#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <MQTTClient.h>
#include "wifi_packet.h"

#define ADDRESS     "demo.thingsboard.io"  
#define CLIENTID    "WiFi_Packet_Capture"
#define TOPIC       "v1/devices/me/telemetry"
#define QOS         1
#define TIMEOUT     10000L
#define ACCESS_TOKEN "W3BZaHIeGE5daOrDqH7p" 

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
    MQTTClient_publishMessage(client, TOPIC, &pubmsg, &token);
    MQTTClient_waitForCompletion(client, token, TIMEOUT);

    printf("Data sent: %s\n", payload);

    MQTTClient_disconnect(client, TIMEOUT);
    MQTTClient_destroy(&client);
}

int main() {
    int map_fd = bpf_obj_get("/sys/fs/bpf/xdp_map_count1");
    if (map_fd < 0) {
        perror("bpf_obj_get");
        return 1;
    }

    struct key cur_key = {};
    struct key next_key;
    struct value val;
    struct value last_val = {0};  // To store the last sent value

    while (1) {
        memset(&cur_key, 0, sizeof(cur_key));
        if (bpf_map_get_next_key(map_fd, NULL, &next_key) == 0) {
            do {
                if (bpf_map_lookup_elem(map_fd, &next_key, &val) == 0) {
                    // Only send data if it has changed since the last time
                    if (memcmp(&val, &last_val, sizeof(struct value)) != 0) {
                        char jsonPayload[512];
                        snprintf(jsonPayload, sizeof(jsonPayload),
                                 "{"
                                 "\"address\": \"%02x:%02x:%02x:%02x:%02x:%02x\", "
                                 "\"countBeacon\": %llu, "
                                 "\"countProbeReq\": %llu, "
                                 "\"countProbeRes\": %llu, "
                                 "\"countAssocReq\": %llu, "
                                 "\"countAssocRes\": %llu, "
                                 "\"countAuth\": %llu, "
                                 "\"countAck\": %llu, "
                                 "\"countRts\": %llu, "
                                 "\"countCts\": %llu, "
                                 "\"countPsPoll\": %llu, "
                                 "\"countData\": %llu, "
                                 "\"countQosData\": %llu, "
                                 "\"countOthers\": %llu, "
                                 "\"SSID\": \"%s\""
                                 "}",
                                 next_key.address[0], next_key.address[1], next_key.address[2],
                                 next_key.address[3], next_key.address[4], next_key.address[5],
                                 val.countBeacon, val.countProbeReq, val.countProbeRes,
                                 val.countAssocReq, val.countAssocRes, val.countAuth,
                                 val.countAck, val.countRts, val.countCts,
                                 val.countPsPoll, val.countData, val.countQosData,
                                 val.countUnknown, val.SSID);

                        // Publish telemetry to ThingBoard
                        send_data(jsonPayload);

                        // Update last_val with the current value
                        memcpy(&last_val, &val, sizeof(struct value));
                    }
                }

            } while (bpf_map_get_next_key(map_fd, &next_key, &next_key) == 0);
        }
        printf("\n==========================\n");
        sleep(5); // Sleep to avoid flooding the terminal
    }

    close(map_fd);
    return 0;
}

