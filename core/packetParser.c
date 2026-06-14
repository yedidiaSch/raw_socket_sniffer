/**
 * @file packetParser.c
 * @brief Implementation of the packet dispatch logic.
 */

#include <string.h>
#include <netinet/in.h>
#include "packetParser.h"
#include "monitorMode.h"
#include "managedMode.h"
#include "logger.h"
#include "udp_sender.h"
#include "Types.h"

// Flag set by main.c based on interface type
static int g_is_monitor_mode = 0;

void set_monitor_mode(int enabled) {
    g_is_monitor_mode = enabled;
}

void process_packet(const unsigned char* buffer, int size) {
    PacketMetadata meta;
    memset(&meta, 0, sizeof(PacketMetadata));
    meta.packet_size = size;

    // --- Dispatch Logic ---
    
    if (g_is_monitor_mode) {
        // Monitor Mode: Expect Radiotap + 802.11 frames
        parse_monitor_packet(buffer, size, &meta);
    } 
    else {
        // Managed Mode: Standard Ethernet/IP packets
        parse_managed_packet(buffer, size, &meta);
    }

    // --- Feedback-loop guard ---
    // Sniffing an interface that also carries our own dashboard UDP traffic
    // (most obviously loopback) re-captures every emitted metadata packet and
    // amplifies exponentially. Drop those before they hit the logger.
    if (!g_is_monitor_mode && meta.l3_protocol == IPPROTO_UDP &&
        (meta.src_port == DASHBOARD_UDP_PORT || meta.dest_port == DASHBOARD_UDP_PORT)) {
        return;
    }

    // --- Final Reporting ---

    // Log all packets to the dashboard (UDP)
    log_packet(&meta);
}