/**
 * @file ethernetLayer.c
 * @brief Implementation of Ethernet header parsing.
 */

#define _GNU_SOURCE
#include <string.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include "ethernetLayer.h"
#include "logger.h"

/**
 * @brief Parses and prints Ethernet header information.
 * 
 * @param buffer Packet buffer.
 * @param size Packet size.
 * @param header_len Pointer to store the header length.
 * @param meta Pointer to the metadata struct to fill.
 * @return uint16_t EtherType.
 */
uint16_t parse_ethernet(const unsigned char* buffer, int size, int* header_len, PacketMetadata* meta) {
   
    if (size < (int)sizeof(struct ether_header)) {
        return 0; 
    }

    struct ether_header *eth = (struct ether_header *)buffer;
    *header_len = sizeof(struct ether_header);

    // Fill Metadata
    memcpy(meta->src_mac, eth->ether_shost, 6);
    memcpy(meta->dest_mac, eth->ether_dhost, 6);
    meta->ether_type = ntohs(eth->ether_type);

    return meta->ether_type;
}
