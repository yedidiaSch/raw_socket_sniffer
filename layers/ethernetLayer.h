/**
 * @file ethernetLayer.h
 * @brief Layer 2 (Data Link Layer) parsing functions.
 */

#ifndef ETHERNET_LAYER_H
#define ETHERNET_LAYER_H

#include <stdint.h>
#include "Types.h"

/**
 * @brief Parses the Ethernet header.
 * 
 * Extracts MAC addresses and the EtherType into the metadata struct.
 * 
 * @param buffer Pointer to the start of the Ethernet header.
 * @param size Total remaining size of the packet.
 * @param header_len Output parameter to store the size of the Ethernet header.
 * @param meta Pointer to the metadata struct to fill.
 * @return uint16_t The EtherType (in host byte order) indicating the next layer protocol.
 */
uint16_t parse_ethernet(const unsigned char* buffer, int size, int* header_len, PacketMetadata* meta);

#endif // ETHERNET_LAYER_H
