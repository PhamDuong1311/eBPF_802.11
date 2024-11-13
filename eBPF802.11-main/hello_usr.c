#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include "wifi_packet.h"

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
        memset(&cur_key, 0, sizeof(cur_key));
        if (bpf_map_get_next_key(map_fd, NULL, &next_key) == 0) {
            do {
                if (bpf_map_lookup_elem(map_fd, &next_key, &val) == 0) {
                    printf("Address %02x:%02x:%02x:%02x:%02x:%02x\n",
                           next_key.address[0], next_key.address[1], next_key.address[2],
                           next_key.address[3], next_key.address[4], next_key.address[5]);
                    printf("Count Beacon: %llu\n", val.countBeacon);
                    printf("Count Probe Response: %llu\n", val.countProbeRes);
                    printf("Count Probe Request: %llu\n", val.countProbeReq);
                    printf("Count Association Response: %llu\n", val.countAssocRes);
                    printf("Count Association Request: %llu\n", val.countAssocReq);
                    printf("Count Authentication: %llu\n", val.countAuth);
                    
                    printf("Count ACK: %llu\n", val.countAck);
                    printf("Count RTS: %llu\n", val.countRts);
                    printf("Count CTS: %llu\n", val.countCts);
                    printf("Count PS Poll: %llu\n", val.countPsPoll);
                    
                    printf("Count Data: %llu\n", val.countData);
                    printf("Count QoS Data: %llu\n", val.countQosData);
                   
                    printf("Count Unknown: %llu\n", val.countUnknown);
                    printf("SSID is %s \n",val.SSID);
                    printf("--------------------------\n");
                }

            } while (bpf_map_get_next_key(map_fd, &next_key, &next_key) == 0);
        }
        printf("\n==========================\n");
        sleep(1); // Sleep to avoid flooding the terminal
    }

    close(map_fd);
    return 0;
}

