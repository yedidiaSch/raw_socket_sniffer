/**
 * @file udp_sender.h
 * @brief UDP communication for sending packet metadata.
 */

#ifndef UDP_SENDER_H
#define UDP_SENDER_H

#include "Types.h"

/**
 * @brief Initializes the UDP socket for sending logs.
 * 
 * @param ip Target IP address (e.g., "127.0.0.1").
 * @param port Target port (e.g., 5000).
 * @return int 0 on success, -1 on failure.
 */
int init_udp_sender(const char* ip, int port);

/**
 * @brief Sends the packet metadata struct over UDP.
 * 
 * @param meta Pointer to the metadata struct.
 */
void send_udp_metadata(const PacketMetadata* meta);

/**
 * @brief Closes the UDP socket.
 */
void close_udp_sender();

#endif // UDP_SENDER_H
