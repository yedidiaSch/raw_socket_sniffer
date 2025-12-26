/**
 * @file packetParser.c
 * @brief Implementation of the central packet parsing logic.
 */

#include <stdio.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include "packetParser.h"
#include "ethernetLayer.h"
#include "networkLayer.h"
#include "transportLayer.h"

/**
 * @brief Processes a captured packet.
 * 
 * Analyzes the packet layer by layer:
 * 1. Ethernet Layer (L2)
 * 2. Network Layer (L3) - IPv4 or IPv6
 * 3. Transport Layer (L4) - TCP, UDP, ICMP, ICMPv6
 * 
 * @param buffer Raw packet data.
 * @param size Size of the packet.
 */
void process_packet(const unsigned char* buffer, int size) {
    
    // 1. Parse Ethernet Layer
    int eth_header_len = 0;
    uint16_t eth_type = parse_ethernet(buffer, size, &eth_header_len);

    const unsigned char* transport_buffer = NULL;
    int transport_remaining_size = 0;
    uint8_t protocol = 0;

    // 2. Check if it's IP or IPv6
    if (eth_type == ETHERTYPE_IP || eth_type == ETHERTYPE_IPV6) {
        
        // Move pointer to Network header
        const unsigned char* network_buffer = buffer + eth_header_len;
        int network_remaining_size = size - eth_header_len;
        int network_header_len = 0;

        // 3. Parse Network Layer (IPv4 or IPv6)
        // The network layer will detect the version internally
        protocol = parse_network_layer(network_buffer, network_remaining_size, &network_header_len);

        // Move pointer to Transport header
        transport_buffer = network_buffer + network_header_len;
        transport_remaining_size = network_remaining_size - network_header_len;

    } 
    
    if(eth_type < 1536) {
        // IEEE 802.3 Length field - Not handled
        printf("\n=== Non-IP Packet (IEEE 802.3 Length: %d) ===\n", eth_type);
        return;
    }
    
    // 4. Dispatch to Transport Layer (Common for both IPv4 and IPv6)
    switch (protocol) {
        case IPPROTO_TCP:
            parse_tcp(transport_buffer, transport_remaining_size);
            break;
        case IPPROTO_UDP:
            parse_udp(transport_buffer, transport_remaining_size);
            break;
        case IPPROTO_ICMP:
            parse_icmp(transport_buffer, transport_remaining_size);
            break;
        case IPPROTO_ICMPV6:
            parse_icmpv6(transport_buffer, transport_remaining_size);
            break;
        default:
            // printf("      [Layer 4] Unknown Protocol: %d\n", protocol);
            break;
    }
}
