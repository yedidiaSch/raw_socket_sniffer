/**
 * @file rawSocket.c
 * @brief Implementation of raw socket lifecycle management.
 */

#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include "rawSocket.h"

// Internal helper to reduce code duplication
static int modify_promisc_mode(int sock_fd, const char *interface_name, int enable) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);

    // 1. Get current flags
    if (ioctl(sock_fd, SIOCGIFFLAGS, &ifr) == -1) {
        perror("[ERROR] Unable to get interface flags");
        return -1;
    }

    // 2. Modify flags
    if (enable) {
        ifr.ifr_flags |= IFF_PROMISC;  // Set bit
    } else {
        ifr.ifr_flags &= ~IFF_PROMISC; // Clear bit
    }

    // 3. Write back flags
    if (ioctl(sock_fd, SIOCSIFFLAGS, &ifr) == -1) {
        perror("[ERROR] Unable to set interface flags");
        return -1;
    }

    return 0;
}

int create_raw_socket(const char *interface_name)
{
    // 1. Create the socket
    // Use ETH_P_ALL to capture all protocols (Ethernet level)
    int sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_fd == -1) {
        perror("[ERROR] Socket creation failed");
        return -1;
    }

    // 2. Get Interface Index
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);

    if (ioctl(sock_fd, SIOCGIFINDEX, &ifr) == -1) {
        perror("[ERROR] Interface not found");
        close(sock_fd);
        return -1;
    }
    int if_index = ifr.ifr_ifindex;

    // 3. Bind Socket to Interface
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = if_index;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(sock_fd, (struct sockaddr *)&sll, sizeof(sll)) == -1) {
        perror("[ERROR] Bind failed");
        close(sock_fd);
        return -1;
    }

    // 4. Enable Promiscuous Mode
    if (modify_promisc_mode(sock_fd, interface_name, 1) == -1) {
        close(sock_fd);
        return -1;
    }

    return sock_fd;
}

void close_raw_socket(int sock_fd, const char *interface_name) {
    if (sock_fd != -1) {
        // Restore interface to normal mode (Disable Promisc)
        printf("[INFO] Disabling promiscuous mode on %s...\n", interface_name);
        modify_promisc_mode(sock_fd, interface_name, 0);
        
        close(sock_fd);
    }
}