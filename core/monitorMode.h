/**
 * @file monitorMode.h
 * @brief Handler for 802.11 WiFi packets with Radiotap headers.
 *
 * Handles the extraction of physical layer data (RSSI, Channel) 
 * and parses Management Frames (Beacons) and Data Frames (EAPOL Handshakes).
 */

#ifndef MONITORMODE_H
#define MONITORMODE_H

#include "Types.h"

/**
 * @brief Parses a raw 802.11 packet captured in Monitor Mode.
 * * 1. Skips the Radiotap header.
 * 2. Extracts metadata (Signal strength, Channel).
 * 3. Identifies frame type (Management vs Data).
 * 4. Captures EAPOL Handshakes to a file.
 * * @param buffer Pointer to the raw packet data.
 * @param size Packet size.
 * @param meta Pointer to the metadata structure to fill.
 */
void parse_monitor_packet(const unsigned char* buffer, int size, PacketMetadata* meta);

#endif // MONITORMODE_H