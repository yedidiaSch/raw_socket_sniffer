/**
 * @file packetParser.c
 * @brief Implementation of the packet dispatch logic.
 */

#include <string.h>
#include "packetParser.h"
#include "monitorMode.h"
#include "managedMode.h"
#include "logger.h"
#include "Types.h"

void process_packet(const unsigned char* buffer, int size) {
    PacketMetadata meta;
    memset(&meta, 0, sizeof(PacketMetadata));
    meta.packet_size = size;

    // --- Dispatch Logic ---
    
    /**
     * Heuristic Detection for Monitor Mode (Radiotap Headers):
     * Radiotap headers typically start with version 0x00 at byte 0.
     * We also check for a minimum size to avoid false positives.
     */
    if (size > 4 && buffer[0] == 0x00) {
        // Delegate to the WiFi Monitor Mode specialist
        parse_monitor_packet(buffer, size, &meta);
    } 
    else {
        // Delegate to the Standard Ethernet/IP specialist
        parse_managed_packet(buffer, size, &meta);
    }

    // --- Final Reporting ---
    
    // Log all packets to the dashboard (UDP)
    log_packet(&meta);
}