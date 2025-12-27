/**
 * @file networkLayer.c
 * @brief Implementation of Network Layer (IPv4/IPv6) parsing.
 */

#define _GNU_SOURCE
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include "networkLayer.h"
#include "logger.h"

/**
 * @brief Parses IPv4 header and prints source/dest IPs.
 * 
 * @param buffer Packet buffer.
 * @param size Remaining size.
 * @param header_len Output for header length.
 * @param meta Pointer to the metadata struct to fill.
 * @return uint8_t Protocol.
 */
uint8_t parse_ip(const unsigned char* buffer, int size, int* header_len, PacketMetadata* meta) {
    // Safety check
    if (size < (int)sizeof(struct iphdr)) return 0;

    struct iphdr *iph = (struct iphdr *)buffer;

    // Fill Metadata
    meta->ip_version = 4;
    inet_ntop(AF_INET, &iph->saddr, meta->src_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET, &iph->daddr, meta->dest_ip, INET6_ADDRSTRLEN);
    meta->l3_protocol = iph->protocol;

    // Calculate the length of the IP header (IHL is in 32-bit words, so multiply by 4)
    *header_len = iph->ihl * 4;

    return iph->protocol;
}

/**
 * @brief Parses IPv6 header and prints source/dest IPs.
 * 
 * @param buffer Packet buffer.
 * @param size Remaining size.
 * @param header_len Output for header length.
 * @param meta Pointer to the metadata struct to fill.
 * @return uint8_t Next Header.
 */
uint8_t parse_ipv6(const unsigned char* buffer, int size, int* header_len, PacketMetadata* meta) {
    // Safety check
    if (size < (int)sizeof(struct ip6_hdr)) return 0;

    struct ip6_hdr *ip6h = (struct ip6_hdr *)buffer;

    // Fill Metadata
    meta->ip_version = 6;
    inet_ntop(AF_INET6, &ip6h->ip6_src, meta->src_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &ip6h->ip6_dst, meta->dest_ip, INET6_ADDRSTRLEN);
    meta->l3_protocol = ip6h->ip6_nxt;

    // IPv6 header is fixed 40 bytes
    *header_len = 40; 

    return ip6h->ip6_nxt;
}

/**
 * @brief Dispatches to IPv4 or IPv6 parser based on version field.
 * 
 * @param buffer Packet buffer.
 * @param size Remaining size.
 * @param header_len Output for header length.
 * @param meta Pointer to the metadata struct to fill.
 * @return uint8_t Protocol.
 */
uint8_t parse_network_layer(const unsigned char* buffer, int size, int* header_len, PacketMetadata* meta) {
    if (size < 1) return 0;

    // Check the Version field (first 4 bits)
    uint8_t version = (*buffer) >> 4;

    if (version == 4) {
        return parse_ip(buffer, size, header_len, meta);
    } else if (version == 6) {
        return parse_ipv6(buffer, size, header_len, meta);
    } else {
        return 0;
    }
}
