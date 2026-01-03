/**
 * @file managedMode.h
 * @brief Handler for standard Ethernet/IP/TCP traffic.
 *
 * This module is responsible for the standard OSI stack parsing:
 * Layer 2 (Ethernet) -> Layer 3 (IP) -> Layer 4 (TCP/UDP).
 */

#ifndef MANAGEDMODE_H
#define MANAGEDMODE_H

#include "Types.h"

/**
 * @brief Parses a standard Ethernet packet.
 * * Delegates parsing to specific layer handlers (Ethernet, Network, Transport)
 * and populates the metadata structure.
 * * @param buffer Pointer to the raw packet data.
 * @param size Packet size.
 * @param meta Pointer to the metadata structure to fill.
 */
void parse_managed_packet(const unsigned char* buffer, int size, PacketMetadata* meta);

#endif // MANAGEDMODE_H