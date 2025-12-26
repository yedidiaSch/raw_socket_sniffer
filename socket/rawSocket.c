/**
 * @file rawSocket.c
 * @brief Implementation of raw socket creation and configuration.
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

#include "rawSocket.h"

/**
 * @brief Creates and configures a raw socket.
 * 
 * Steps performed:
 * 1. Create a socket with AF_PACKET, SOCK_RAW, and ETH_P_ALL.
 * 2. Retrieve the interface index using ioctl.
 * 3. Bind the socket to the interface.
 * 4. Enable promiscuous mode on the interface.
 * 
 * @param interface_name Name of the interface to bind to.
 * @return int Socket file descriptor or -1 on error.
 */
int create_raw_socket(const char *interface_name)
{
    // Create the raw socket
    // AF_PACKET: Low level packet interface
    // SOCK_RAW: Raw network protocol access
    // htons(ETH_P_ALL): Capture all protocols (IP, ARP, IPv6, etc.)
    int sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (sock_fd == -1) 
    {
        perror("Socket creation failed");
        return -1;
    }

    // Get the interface index number
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr)); 

    strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);

    if (ioctl(sock_fd, SIOCGIFINDEX, &ifr) == -1) {
        perror("Unable to find interface index");
        close(sock_fd); 
        return -1;
    }

    int if_index = ifr.ifr_ifindex; 

    // Bind the socket to the interface
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));

    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_index;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(sock_fd, (struct sockaddr *)&sll, sizeof(sll)) == -1) {
        perror("Bind failed");
        close(sock_fd);
        return -1;
    }

    // Set interface to Promiscuous mode
    if (ioctl(sock_fd, SIOCGIFFLAGS, &ifr) == -1) {
        perror("Unable to get interface flags");
        close(sock_fd);
        return -1;
    }

    ifr.ifr_flags |= IFF_PROMISC;

    if (ioctl(sock_fd, SIOCSIFFLAGS, &ifr) == -1) {
        perror("Unable to set promiscuous mode");
        close(sock_fd);
        return -1;
    }

    return sock_fd;
}
