/**
 * @file networkLayer.h
 * @brief Layer 3 (Network Layer) parsing functions.
 */

#ifndef NETWORK_LAYER_H
#define NETWORK_LAYER_H

#include <stdint.h>
#include "Types.h"

/**
 * @brief Parses an IPv4 header.
 * 
 * @param buffer Pointer to the start of the IP header.
 * @param size Remaining packet size.
 * @param header_len Output parameter for the IP header length.
 * @param meta Pointer to the metadata struct to fill.
 * @return uint8_t The Protocol field (e.g., TCP, UDP).
 */
uint8_t parse_ip(const unsigned char* buffer, int size, int* header_len, PacketMetadata* meta);

/**
 * @brief Parses an IPv6 header.
 * 
 * @param buffer Pointer to the start of the IPv6 header.
 * @param size Remaining packet size.
 * @param header_len Output parameter for the IPv6 header length.
 * @param meta Pointer to the metadata struct to fill.
 * @return uint8_t The Next Header field (Protocol).
 */
uint8_t parse_ipv6(const unsigned char* buffer, int size, int* header_len, PacketMetadata* meta);

/**
 * @brief Generic Network Layer Parser.
 * 
 * Detects the IP version (4 or 6) and calls the appropriate parser.
 * 
 * @param buffer Pointer to the start of the network header.
 * @param size Remaining packet size.
 * @param header_len Output parameter for the header length.
 * @param meta Pointer to the metadata struct to fill.
 * @return uint8_t The Protocol/Next Header field.
 */
uint8_t parse_network_layer(const unsigned char* buffer, int size, int* header_len, PacketMetadata* meta);

#endif // NETWORK_LAYER_H
