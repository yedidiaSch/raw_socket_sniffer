/**
 * @file packetParser.h
 * @brief Main entry point for packet processing.
 *
 * This module acts as a dispatcher. It analyzes the raw packet buffer
 * to determine the mode of operation (Monitor Mode vs Managed Mode)
 * and delegates processing to the appropriate module.
 */

#ifndef PACKETPARSER_H
#define PACKETPARSER_H

/**
 * @brief Sets the operation mode for packet parsing.
 * @param enabled 1 for Monitor Mode, 0 for Managed Mode.
 */
void set_monitor_mode(int enabled);

/**
 * @brief Analyzes a raw packet and dispatches it to the correct handler.
 *
 * If monitor mode is enabled, it calls the Monitor Mode handler.
 * Otherwise, it assumes Ethernet framing (Managed Mode) and calls the Managed Mode handler.
 *
 * @param buffer Pointer to the start of the packet data (Zero-Copy safe).
 * @param size Total size of the received packet in bytes.
 */
void process_packet(const unsigned char* buffer, int size);

#endif // PACKETPARSER_H