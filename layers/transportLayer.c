/**
 * @file transportLayer.c
 * @brief Implementation of Transport Layer (TCP/UDP/ICMP) parsing.
 */

#define _GNU_SOURCE
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
 * @param meta Pointer to the metadata struct to fill.
 */
void parse_tcp(const unsigned char* buffer, int size, PacketMetadata* meta) {
    // Check if we have enough bytes for the TCP header
    if (size < (int)sizeof(struct tcphdr)) {
        return;
    }

    struct tcphdr *tcph = (struct tcphdr *)buffer;

    meta->src_port = ntohs(tcph->source);
    meta->dest_port = ntohs(tcph->dest);
    
    // Pack flags into a single byte for simplicity or keep separate
    // Here we just store the raw flags byte (th_flags is uint8_t)
    // Note: struct tcphdr might use bitfields or th_flags depending on system
    // On Linux/GNU, th_flags is standard.
    #ifdef __FAVOR_BSD
    meta->tcp_flags = tcph->th_flags;
    #else
    // Construct flags manually if needed, or cast
    // For standard Linux headers, we can access bitfields but it's messy to pack.
    // Let's just pack the key ones we care about into our uint8_t
    meta->tcp_flags = 0;
    if (tcph->syn) meta->tcp_flags |= 0x02;
    if (tcph->ack) meta->tcp_flags |= 0x10;
    if (tcph->rst) meta->tcp_flags |= 0x04;
    if (tcph->fin) meta->tcp_flags |= 0x01;
    if (tcph->psh) meta->tcp_flags |= 0x08;
    if (tcph->urg) meta->tcp_flags |= 0x20;
    #endif
}

/**
 * @brief Parses UDP header.
 * 
 * @param buffer Packet buffer.
 * @param size Remaining size.
 * @param meta Pointer to the metadata struct to fill.
 */
void parse_udp(const unsigned char* buffer, int size, PacketMetadata* meta) {
    // Check if we have enough bytes for the UDP header
    if (size < (int)sizeof(struct udphdr)) {
        return;
    }

    struct udphdr *udph = (struct udphdr *)buffer;

    meta->src_port = ntohs(udph->source);
    meta->dest_port = ntohs(udph->dest);
}

/**
 * @brief Parses ICMP header.
 * 
 * @param buffer Packet buffer.
 * @param size Remaining size.
 * @param meta Pointer to the metadata struct to fill.
 */
void parse_icmp(const unsigned char* buffer, int size, PacketMetadata* meta) {
    if (size < (int)sizeof(struct icmphdr)) {
        return;
    }

    struct icmphdr *icmph = (struct icmphdr *)buffer;

    meta->icmp_type = icmph->type;
    meta->icmp_code = icmph->code;
}

/**
 * @brief Parses ICMPv6 header.
 * 
 * @param buffer Packet buffer.
 * @param size Remaining size.
 * @param meta Pointer to the metadata struct to fill.
 */
void parse_icmpv6(const unsigned char* buffer, int size, PacketMetadata* meta) {
    if (size < (int)sizeof(struct icmp6_hdr)) {
        return;
    }

    struct icmp6_hdr *icmp6h = (struct icmp6_hdr *)buffer;

    meta->icmp_type = icmp6h->icmp6_type;
    meta->icmp_code = icmp6h->icmp6_code;
}
