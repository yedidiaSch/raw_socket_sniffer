/**
 * @file managedMode.c
 * @brief Implementation of standard network stack parsing.
 */

#include "managedMode.h"
#include "ethernetLayer.h"
#include "networkLayer.h"  
#include "transportLayer.h" 
#include "logger.h" // Added for logging
#include <netinet/in.h>
#include <net/ethernet.h>

void parse_managed_packet(const unsigned char* buffer, int size, PacketMetadata* meta) {
    // --- Layer 2: Ethernet ---
    int eth_header_len = 0;
    
    // parse_ethernet should return the EtherType (e.g., 0x0800 for IP)
    uint16_t eth_type = parse_ethernet(buffer, size, &eth_header_len, meta);

    // Filter out non-IP noise (ARP, STP, etc.) to focus on meaningful traffic
    if (eth_type < 1536) { 
        // 802.3 Frames (Length field instead of Type) are usually not IP
        return; 
    }

    // --- Layer 3: Network (IP / IPv6) ---
    if (eth_type == ETHERTYPE_IP || eth_type == ETHERTYPE_IPV6) {
        const unsigned char* network_buffer = buffer + eth_header_len;
        int network_remaining_size = size - eth_header_len;
        int network_header_len = 0;

        // parse_network_layer should return the L4 Protocol (TCP/UDP/ICMP)
        uint8_t protocol = parse_network_layer(network_buffer, network_remaining_size, &network_header_len, meta);

        // --- Layer 4: Transport (TCP / UDP) ---
        const unsigned char* transport_buffer = network_buffer + network_header_len;
        int transport_remaining_size = network_remaining_size - network_header_len;

        switch (protocol) {
            case IPPROTO_TCP:
                parse_tcp(transport_buffer, transport_remaining_size, meta);
                break;
            case IPPROTO_UDP:
                parse_udp(transport_buffer, transport_remaining_size, meta);
                break;
            case IPPROTO_ICMP:
                parse_icmp(transport_buffer, transport_remaining_size, meta);
                break;
            case IPPROTO_ICMPV6:
                parse_icmpv6(transport_buffer, transport_remaining_size, meta);
                break;
            default:
                // Unknown or unhandled protocol
                break;
        }
    }
}