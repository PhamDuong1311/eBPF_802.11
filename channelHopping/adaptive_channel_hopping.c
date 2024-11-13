#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <linux/wireless.h>
#include <pcap.h>
#include <signal.h>
#include <time.h>

#define TOTAL_INTERVAL 3000000       // 3 seconds in microseconds
#define RECALIBRATION_INTERVAL 40     // Recalibrate every 100 seconds

void change_channel(int sock, const char *iface, int channel) {
    struct iwreq wrq;
    memset(&wrq, 0, sizeof(wrq));
    strncpy(wrq.ifr_name, iface, IFNAMSIZ);

    wrq.u.freq.e = 0;
    wrq.u.freq.m = channel;
    if (ioctl(sock, SIOCSIWFREQ, &wrq) == -1) {
        perror("Error setting channel");
    } else {
        printf("Switched to channel %d\n", channel);
    }
}
void packet_handler(u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet) {
    int *packet_count = (int *)user_data;
    (*packet_count)++;
}

int count_packets(const char *iface, int duration) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(iface, BUFSIZ, 1, duration, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", iface, errbuf);
        return -1;
    }

    int packet_count = 0;

    struct pcap_pkthdr header;
    const u_char *packet = pcap_next(handle, &header);

    if (packet == NULL) {
        printf("No packets captured on %s within %d ms\n", iface, duration);
    } else {
        pcap_dispatch(handle, 0, packet_handler, (u_char *)&packet_count);
        printf("Packets captured: %d\n", packet_count);
    }

    pcap_close(handle);
    return packet_count;
}

void channel_hopper(const char *iface) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
        perror("Socket creation failed");
        exit(1);
    }

    int channels[] = {1, 7, 13, 2, 8, 3, 14, 9, 4, 10, 5, 11, 6, 12};
    int num_channels = sizeof(channels) / sizeof(channels[0]);
    int packet_counts[num_channels];
    int dwell_times[num_channels];

    while (1) {
        // recalibrate by counting packets on each channel
        int total_packets = 0;
        for (int i = 0; i < num_channels; ++i) {
            int channel = channels[i];
            change_channel(sock, iface, channel);
            usleep(100000);  // Small delay to switch
            packet_counts[i] = count_packets(iface, 1000);  // Count packets for 1 seconds
            total_packets += packet_counts[i];
            printf("Channel %d: %d packets\n", channel, packet_counts[i]);
        }

        // dwell time for each channel based on packet count
        if (total_packets > 0) {
            for (int i = 0; i < num_channels; ++i) {
                dwell_times[i] = (packet_counts[i] * TOTAL_INTERVAL) / total_packets;
                printf("Channel %d: dwell time %d µs\n", channels[i], dwell_times[i]);
            }
        } else {
            // No packets detected, use equal distribution
            for (int i = 0; i < num_channels; ++i) {
                dwell_times[i] = TOTAL_INTERVAL / num_channels;
            }
        }

        // Execute adaptive channel hopping based on calculated dwell times
        int num_interval = 0;
        while (num_interval < (RECALIBRATION_INTERVAL/(TOTAL_INTERVAL/1000000))) {
        for (int i = 0; i < num_channels; ++i) {
            int channel = channels[i];
            change_channel(sock, iface, channel);
            usleep(dwell_times[i]);
        }
        num_interval++;
        }
    }

    close(sock);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    const char *iface = argv[1];
    channel_hopper(iface);

    return 0;
}
