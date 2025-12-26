/**
 * @file packetParser.h
 * @brief Core packet parsing orchestration.
 */

#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

/**
 * @brief Main entry point for parsing a raw packet.
 * 
 * This function orchestrates the parsing process by starting at Layer 2 (Ethernet)
 * and delegating to higher layers (Network, Transport) based on the packet content.
 * 
 * @param buffer Pointer to the raw packet data.
 * @param size Total size of the captured packet in bytes.
 */
void process_packet(const unsigned char* buffer, int size);

#endif // PACKET_PARSER_H
