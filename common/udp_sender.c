/**
 * @file udp_sender.c
 * @brief Implementation of UDP sender.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "udp_sender.h"

static int sockfd = -1;
static struct sockaddr_in server_addr;

int init_udp_sender(const char* ip, int port) 
{
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("UDP socket creation failed");
        return -1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        return -1;
    }

    return 0;
}

void send_udp_metadata(const PacketMetadata* meta) 
{
    
    if (sockfd < 0){
        return;
    }

    sendto(sockfd, meta, sizeof(PacketMetadata), 0, 
           (const struct sockaddr *)&server_addr, sizeof(server_addr));
}

void close_udp_sender() 
{
    if (sockfd >= 0) {
        close(sockfd);
        sockfd = -1;
    }
}
