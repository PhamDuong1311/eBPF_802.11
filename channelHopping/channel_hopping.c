#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <linux/wireless.h>
#include <signal.h>

#define CHANNEL_HOP_DELAY 250000 // 0.25 second in microseconds

void change_channel(int sock, const char *iface, int channel) {
    struct iwreq wrq;
    memset(&wrq, 0, sizeof(wrq));
    strncpy(wrq.ifr_name, iface, IFNAMSIZ);

    wrq.u.freq.e = 0;          // Exponent part for frequency
    wrq.u.freq.m = channel;     // Frequency part (represents the channel here)

    if (ioctl(sock, SIOCSIWFREQ, &wrq) == -1) {
        perror("Error setting channel");
    } else {
        printf("Switched to channel %d\n", channel);
    }
}

void channel_hopper(const char *iface) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
        perror("Socket creation failed");
        exit(1);
    }

    int channels[] = {1, 7, 13, 2, 8, 3, 14, 9, 4, 10, 5, 11, 6, 12}; //Channels interval airodump-ng
    int num_channels = sizeof(channels) / sizeof(channels[0]);
    int channel_index = 0;

    while (1) {
        int current_channel = channels[channel_index % num_channels];
        change_channel(sock, iface, current_channel);
        
        channel_index++;
        usleep(CHANNEL_HOP_DELAY);
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
