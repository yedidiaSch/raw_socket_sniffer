/**
 * @file transportLayer.h
 * @brief Layer 4 (Transport Layer) parsing functions.
 */

#ifndef TRANSPORT_LAYER_H
#define TRANSPORT_LAYER_H

#include "Types.h"

/**
 * @brief Parses a TCP header.
 * 
 * @param buffer Pointer to the start of the TCP header.
 * @param size Remaining packet size.
 * @param meta Pointer to the metadata struct to fill.
 */
void parse_tcp(const unsigned char* buffer, int size, PacketMetadata* meta);

/**
 * @brief Parses a UDP header.
 * 
 * @param buffer Pointer to the start of the UDP header.
 * @param size Remaining packet size.
 * @param meta Pointer to the metadata struct to fill.
 */
void parse_udp(const unsigned char* buffer, int size, PacketMetadata* meta);

/**
 * @brief Parses an ICMP header.
 * 
 * @param buffer Pointer to the start of the ICMP header.
 * @param size Remaining packet size.
 * @param meta Pointer to the metadata struct to fill.
 */
void parse_icmp(const unsigned char* buffer, int size, PacketMetadata* meta);

/**
 * @brief Parses an ICMPv6 header.
 * 
 * @param buffer Pointer to the start of the ICMPv6 header.
 * @param size Remaining packet size.
 * @param meta Pointer to the metadata struct to fill.
 */
void parse_icmpv6(const unsigned char* buffer, int size, PacketMetadata* meta);

#endif // TRANSPORT_LAYER_H
