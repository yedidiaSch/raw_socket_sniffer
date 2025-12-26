/**
 * @file transportLayer.h
 * @brief Layer 4 (Transport Layer) parsing functions.
 */

#ifndef TRANSPORT_LAYER_H
#define TRANSPORT_LAYER_H

/**
 * @brief Parses a TCP header.
 * 
 * Prints ports and flags (SYN, ACK, RST, FIN).
 * 
 * @param buffer Pointer to the start of the TCP header.
 * @param size Remaining packet size.
 */
void parse_tcp(const unsigned char* buffer, int size);

/**
 * @brief Parses a UDP header.
 * 
 * Prints ports and length.
 * 
 * @param buffer Pointer to the start of the UDP header.
 * @param size Remaining packet size.
 */
void parse_udp(const unsigned char* buffer, int size);

/**
 * @brief Parses an ICMP header.
 * 
 * Prints Type and Code.
 * 
 * @param buffer Pointer to the start of the ICMP header.
 * @param size Remaining packet size.
 */
void parse_icmp(const unsigned char* buffer, int size);

/**
 * @brief Parses an ICMPv6 header.
 * 
 * Prints Type and Code.
 * 
 * @param buffer Pointer to the start of the ICMPv6 header.
 * @param size Remaining packet size.
 */
void parse_icmpv6(const unsigned char* buffer, int size);

#endif // TRANSPORT_LAYER_H
