/**
 * @file Types.h
 * @brief Common type definitions and constants for the project.
 */

#ifndef TYPES_H
#define TYPES_H

#include <stdint.h>
#include <netinet/in.h>

/**
 * @brief Maximum buffer size for capturing packets.
 * 
 * 65536 bytes is the maximum size of an IP packet (Total Length field is 16 bits).
 */
#define BUFFER_SIZE 65536

/**
 * @brief Structure to hold metadata from all layers.
 */
typedef struct {
    // Layer 2 (Ethernet)
    uint8_t src_mac[6];
    uint8_t dest_mac[6];
    uint16_t ether_type;

    // Layer 3 (Network)
    uint8_t ip_version;       // 4 or 6
    char src_ip[INET6_ADDRSTRLEN];
    char dest_ip[INET6_ADDRSTRLEN];
    uint8_t l3_protocol;      // IP Protocol or IPv6 Next Header

    // Layer 4 (Transport)
    uint16_t src_port;
    uint16_t dest_port;
    uint8_t tcp_flags;        // For TCP
    uint8_t icmp_type;        // For ICMP/ICMPv6
    uint8_t icmp_code;        // For ICMP/ICMPv6
    
    // Metadata
    int packet_size;
} PacketMetadata;

#endif // TYPES_H
