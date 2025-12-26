/**
 * @file Types.h
 * @brief Common type definitions and constants for the project.
 */

#ifndef TYPES_H
#define TYPES_H

/**
 * @brief Maximum buffer size for capturing packets.
 * 
 * 65536 bytes is the maximum size of an IP packet (Total Length field is 16 bits).
 */
#define BUFFER_SIZE 65536

/**
 * @brief Name of the network interface to sniff on.
 * 
 * @note Change this value to match your system's interface (e.g., "eth0", "wlan0").
 */
static const char* interface = "wlp2s0";

#endif // TYPES_H
