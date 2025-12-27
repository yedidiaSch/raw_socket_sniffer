/**
 * @file ethernetLayer.c
 * @brief Implementation of Ethernet header parsing.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include "ethernetLayer.h"
#include "utils.h"
#include "logger.h"

/**
 * @brief Parses and prints Ethernet header information.
 * 
 * @param buffer Packet buffer.
 * @param size Packet size.
 * @param header_len Pointer to store the header length.
 * @return uint16_t EtherType.
 */
uint16_t parse_ethernet(const unsigned char* buffer, int size, int* header_len) {
   
    if (size < (int)sizeof(struct ether_header)) {
        return 0; 
    }

    struct ether_header *eth = (struct ether_header *)buffer;
    *header_len = sizeof(struct ether_header);

    // Only print if it's IP (to reduce noise on the screen)
    if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
        log_message("\n=== New IP Packet (Total Size: %d) ===\n", size);
        print_mac_address("   [Layer 2 - Ether] Source", eth->ether_shost);
        print_mac_address("   [Layer 2 - Ether] Dest  ", eth->ether_dhost);
    }

    return ntohs(eth->ether_type);
}
