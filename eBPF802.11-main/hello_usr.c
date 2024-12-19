#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <MQTTClient.h>
#include "wifi_packet.h"

#define ADDRESS          "demo.thingsboard.io"
#define CLIENTID         "WiFi_Packet_Capture"
#define ATTRIBUTE_TOPIC  "v1/devices/me/attributes"
#define QOS              1
#define TIMEOUT          10000L
#define ACCESS_TOKEN     "LfXxYWivG5xHyMWgxFYp"

// Define maximum buffer size
#define MAX_PAYLOAD_SIZE 4096
#define MAX_ENTRY_SIZE   512

struct key {
    __u8 address[6];
};

struct value {
    __u64 countBeacon;
    __u64 countProbeReq;
    __u64 countProbeRes;
    __u64 countAssocReq;
    __u64 countAssocRes;
    __u64 countAuth;

    __u64 countAck;
    __u64 countRts;
    __u64 countPsPoll;
    __u64 countCts;

    __u64 countData;
    __u64 countQosData;

    __u64 countUnknown;
    char SSID[33];
};

// Function to send MQTT data
void send_data(const char *payload) {
    MQTTClient client;
    MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;

    MQTTClient_create(&client, ADDRESS, CLIENTID, MQTTCLIENT_PERSISTENCE_NONE, NULL);
    conn_opts.username = ACCESS_TOKEN;

    if (MQTTClient_connect(client, &conn_opts) != MQTTCLIENT_SUCCESS) {
        fprintf(stderr, "Failed to connect to MQTT broker\n");
        MQTTClient_destroy(&client);
        return;
    }

    MQTTClient_message pubmsg = MQTTClient_message_initializer;
    pubmsg.payload = (char *)payload;
    pubmsg.payloadlen = (int)strlen(payload);
    pubmsg.qos = QOS;
    pubmsg.retained = 0;

    MQTTClient_deliveryToken token;
    MQTTClient_publishMessage(client, ATTRIBUTE_TOPIC, &pubmsg, &token);
    MQTTClient_waitForCompletion(client, token, TIMEOUT);

    printf("Attributes sent: %s\n", payload);

    MQTTClient_disconnect(client, TIMEOUT);
    MQTTClient_destroy(&client);
}

// Main function
int main() {
    int map_fd = bpf_obj_get("/sys/fs/bpf/xdp_map_count1");
    if (map_fd < 0) {
        perror("bpf_obj_get");
        return 1;
    }

    struct key cur_key = {};
    struct key next_key;
    struct value val;

    while (1) {
        char attributePayload[MAX_PAYLOAD_SIZE];
        char keyData[MAX_PAYLOAD_SIZE];
        int total_len = 0;

        strcpy(keyData, "[");
        total_len += 1; // Account for opening bracket

        memset(&cur_key, 0, sizeof(cur_key));
        if (bpf_map_get_next_key(map_fd, NULL, &next_key) == 0) {
            do {
                if (bpf_map_lookup_elem(map_fd, &next_key, &val) == 0) {
                    char entry[MAX_ENTRY_SIZE];
                    snprintf(entry, sizeof(entry),
                             "{"
                             "\"mac\": \"%02x:%02x:%02x:%02x:%02x:%02x\", "
                             "\"beacon\": %llu, "
                             "\"probeReq\": %llu, "
                             "\"probeRes\": %llu, "
                             "\"assocReq\": %llu, "
                             "\"assocRes\": %llu, "
                             "\"auth\": %llu, "
                             "\"ack\": %llu, "
                             "\"rts\": %llu, "
                             "\"psPoll\": %llu, "
                             "\"cts\": %llu, "
                             "\"data\": %llu, "
                             "\"qosData\": %llu, "
                             "\"others\": %llu, "
                             "\"ssid\": \"%s\""
                             "}",
                             next_key.address[0], next_key.address[1], next_key.address[2],
                             next_key.address[3], next_key.address[4], next_key.address[5],
                             val.countBeacon, val.countProbeReq, val.countProbeRes,
                             val.countAssocReq, val.countAssocRes, val.countAuth,
                             val.countAck, val.countRts, val.countPsPoll,
                             val.countCts, val.countData, val.countQosData,
                             val.countUnknown, val.SSID);

                    int entry_len = strlen(entry);
                    if (total_len + entry_len + 2 >= MAX_PAYLOAD_SIZE) { // +2 for ',' and closing bracket
                        fprintf(stderr, "Payload too large, entry skipped\n");
                        continue;
                    }

                    if (total_len > 1) { // Add a comma if not the first entry
                        strcat(keyData, ",");
                        total_len += 1;
                    }

                    strcat(keyData, entry);
                    total_len += entry_len;
                }
            } while (bpf_map_get_next_key(map_fd, &next_key, &next_key) == 0);
        }

        strcat(keyData, "]");
        snprintf(attributePayload, sizeof(attributePayload),
                 "{ \"key\": { \"key\": %s } }", keyData);

        send_data(attributePayload);

        printf("\n==========================\n");
        sleep(5); // Avoid flooding
    }

    close(map_fd);
    return 0;
}

