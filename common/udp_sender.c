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
#include "Types.h"

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

    // Determine Protocol String
    const char* proto_str = "Other";
    if (meta->ether_type == 0x0806) {
        proto_str = "ARP";
    } else if (meta->ether_type == 0x0800) { // IPv4
        if (meta->l3_protocol == 6) proto_str = "TCP";
        else if (meta->l3_protocol == 17) proto_str = "UDP";
        else if (meta->l3_protocol == 1) proto_str = "ICMP";
        else proto_str = "IPv4";
    } else if (meta->ether_type == 0x86DD) { // IPv6
        if (meta->l3_protocol == 6) proto_str = "TCP";
        else if (meta->l3_protocol == 17) proto_str = "UDP";
        else if (meta->l3_protocol == 58) proto_str = "ICMPv6";
        else proto_str = "IPv6";
    }

    // Format as JSON
    char json_buffer[4096];
    snprintf(json_buffer, sizeof(json_buffer), 
        "{"
        "\"src_mac\": \"%02x:%02x:%02x:%02x:%02x:%02x\","
        "\"dest_mac\": \"%02x:%02x:%02x:%02x:%02x:%02x\","
        "\"src_ip\": \"%s\","
        "\"dest_ip\": \"%s\","
        "\"type\": \"%s\","
        "\"src_port\": %d,"
        "\"dest_port\": %d,"
        "\"size\": %d"
        "}",
        meta->src_mac[0], meta->src_mac[1], meta->src_mac[2], meta->src_mac[3], meta->src_mac[4], meta->src_mac[5],
        meta->dest_mac[0], meta->dest_mac[1], meta->dest_mac[2], meta->dest_mac[3], meta->dest_mac[4], meta->dest_mac[5],
        meta->src_ip,
        meta->dest_ip,
        proto_str,
        meta->src_port,
        meta->dest_port,
        meta->packet_size
    );

    sendto(sockfd, json_buffer, strlen(json_buffer), 0, 
           (const struct sockaddr *)&server_addr, sizeof(server_addr));
}

void close_udp_sender() 
{
    if (sockfd >= 0) {
        close(sockfd);
        sockfd = -1;
    }
}
