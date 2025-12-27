/**
 * @file transportLayer.c
 * @brief Implementation of Transport Layer (TCP/UDP/ICMP) parsing.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include "transportLayer.h"
#include "logger.h"

/**
 * @brief Parses TCP header.
 * 
 * @param buffer Packet buffer.
 * @param size Remaining size.
 */
void parse_tcp(const unsigned char* buffer, int size) {
    // Check if we have enough bytes for the TCP header
    if (size < (int)sizeof(struct tcphdr)) {
        log_message("      [Layer 4 - TCP] Packet too short for TCP header\n");
        return;
    }

    struct tcphdr *tcph = (struct tcphdr *)buffer;

    log_message("      [Layer 4 - TCP] Port: %d -> %d | Flags: [%s%s%s%s]\n", 
           ntohs(tcph->source), 
           ntohs(tcph->dest),
           (tcph->syn ? "SYN " : ""),
           (tcph->ack ? "ACK " : ""),
           (tcph->rst ? "RST " : ""),
           (tcph->fin ? "FIN " : ""));
}

/**
 * @brief Parses UDP header.
 * 
 * @param buffer Packet buffer.
 * @param size Remaining size.
 */
void parse_udp(const unsigned char* buffer, int size) {
    // Check if we have enough bytes for the UDP header
    if (size < (int)sizeof(struct udphdr)) {
        log_message("      [Layer 4 - UDP] Packet too short for UDP header\n");
        return;
    }

    struct udphdr *udph = (struct udphdr *)buffer;

    log_message("      [Layer 4 - UDP] Port: %d -> %d | Len: %d\n", 
           ntohs(udph->source), 
           ntohs(udph->dest),
           ntohs(udph->len));
}

/**
 * @brief Parses ICMP header.
 * 
 * @param buffer Packet buffer.
 * @param size Remaining size.
 */
void parse_icmp(const unsigned char* buffer, int size) {
    if (size < (int)sizeof(struct icmphdr)) {
        log_message("      [Layer 4 - ICMP] Packet too short\n");
        return;
    }

    struct icmphdr *icmph = (struct icmphdr *)buffer;

    log_message("      [Layer 4 - ICMP] Type: %d | Code: %d\n", 
           icmph->type, icmph->code);
}

/**
 * @brief Parses ICMPv6 header.
 * 
 * @param buffer Packet buffer.
 * @param size Remaining size.
 */
void parse_icmpv6(const unsigned char* buffer, int size) {
    if (size < (int)sizeof(struct icmp6_hdr)) {
        log_message("      [Layer 4 - ICMPv6] Packet too short\n");
        return;
    }

    struct icmp6_hdr *icmp6h = (struct icmp6_hdr *)buffer;

    log_message("      [Layer 4 - ICMPv6] Type: %d | Code: %d\n", 
           icmp6h->icmp6_type, icmp6h->icmp6_code);
}
