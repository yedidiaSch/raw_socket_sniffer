/**
 * @file packetParser.c
 * @brief Implementation of the central packet parsing logic with DEBUG LOGS.
 */

#include <string.h>
#include <stdio.h> // For snprintf
#include <net/ethernet.h>
#include <netinet/in.h>
#include "packetParser.h"
#include "ethernetLayer.h"
#include "networkLayer.h"
#include "transportLayer.h"
#include "logger.h"
#include "Types.h"

// Radiotap Present Flags Bitmasks
#define RADIOTAP_PRESENT_TSFT       (1 << 0) // Bit 0
#define RADIOTAP_PRESENT_FLAGS      (1 << 1) // Bit 1
#define RADIOTAP_PRESENT_RATE       (1 << 2) // Bit 2
#define RADIOTAP_PRESENT_CHANNEL    (1 << 3) // Bit 3
#define RADIOTAP_PRESENT_FHSS       (1 << 4) // Bit 4
#define RADIOTAP_PRESENT_DBM_ANTSIGNAL (1 << 5) // Bit 5
#define RADIOTAP_PRESENT_DBM_ANTNOISE  (1 << 6) // Bit 6
#define RADIOTAP_PRESENT_LOCK_QUALITY  (1 << 7) // Bit 7
/**
 * @brief Helper: Convert MHz frequency to Channel number.
 * @param freq Frequency in MHz.
 * @return Channel number.
 */
int mhz_to_channel(int freq) {
    if (freq < 2400 || freq > 6000) return 0;
    if (freq == 2484) return 14;
/**
 * @brief Parses a packet captured in Monitor Mode (802.11 with Radiotap).
 * @param buffer Pointer to the raw packet data.
 * @param size Total size of the packet.
 * @param meta Pointer to the metadata structure to fill.
 */
    if (freq < 2484) return (freq - 2407) / 5;
    return (freq - 5000) / 5;
}
void parseMonitorMode(const unsigned char* buffer, int size, PacketMetadata* meta) {
    // 1. Read header length dynamically (Dynamic Radiotap Length)
    // The second and third bytes contain the length (Little Endian)
    if (size < 4) return;
    uint16_t radiotap_len = *(uint16_t*)(buffer + 2);

    // Protection against unreasonable lengths
    if (radiotap_len >= size || radiotap_len < 10) return;

    // --- Extract physical data (Optional - might shift if header changes, but less critical for now) ---
    // Try to keep existing logic, frequency and signal are likely in the fixed start
    if (radiotap_len >= 30) {
        uint16_t freq = *(uint16_t*)(buffer + 26);
        meta->channel = mhz_to_channel(freq);
        meta->signal_dbm = (int8_t)buffer[30];
    }

    meta->is_monitor_mode = 1;
    memset(meta->ssid, 0, sizeof(meta->ssid));

    // --- Major Fix: Use dynamic length as start point ---
    int offset = radiotap_len; 

    // Check if there is enough payload for the packet itself
    if (offset + 24 >= size) return;

    // --- 2. Extract 802.11 Header Info ---
    uint16_t frame_control = *(uint16_t*)(buffer + offset);
    uint8_t type = (frame_control >> 2) & 0x3;
    uint8_t subtype = (frame_control >> 4) & 0xF;

    // Extract MAC (Located at Offset + 4, 10, 16)
    if (size >= offset + 16) {
        memcpy(meta->dest_mac, buffer + offset + 4, 6);
        memcpy(meta->src_mac, buffer + offset + 10, 6);
    }

    // --- 3. Parse Frame Types ---

    // === MANAGEMENT FRAMES (Type 0) ===
    if (type == 0) {
        int body_offset = offset + 24; 
        char packet_type[15] = "UNKNOWN";
        int is_ssid_frame = 0;

        if (subtype == 8) { // BEACON
            body_offset += 12; 
            strcpy(packet_type, "BEACON");
            is_ssid_frame = 1;
        }
        else if (subtype == 4) { // PROBE REQ
            strcpy(packet_type, "PROBE_REQ");
            is_ssid_frame = 1;
        }
        else if (subtype == 5) { // PROBE RESP
            body_offset += 12;
            strcpy(packet_type, "PROBE_RESP");
            is_ssid_frame = 1;
        }

        if (is_ssid_frame && body_offset < size) {
            while (body_offset + 2 <= size) {
                uint8_t tag_id = buffer[body_offset];
                uint8_t tag_len = buffer[body_offset + 1];
                if (body_offset + 2 + tag_len > size) break;

                if (tag_id == 0) { 
                    int copy_len = (tag_len < 32) ? tag_len : 32;
                    if (copy_len > 0) {
                        memcpy(meta->ssid, buffer + body_offset + 2, copy_len);
                        meta->ssid[copy_len] = '\0';
                    } else {
                        if (subtype == 4) snprintf(meta->ssid, sizeof(meta->ssid), "[BROADCAST]");
                        else snprintf(meta->ssid, sizeof(meta->ssid), "<HIDDEN>");
                    }
                    
                    // Main Log
                    log_message("[%s] [%02X:%02X:%02X:%02X:%02X:%02X] -> '%s' | CH:%d | PWR:%d\n", 
                                packet_type,
                                meta->src_mac[0], meta->src_mac[1], meta->src_mac[2],
                                meta->src_mac[3], meta->src_mac[4], meta->src_mac[5],
                                meta->ssid, meta->channel, meta->signal_dbm);
                    break;
                }
                body_offset += 2 + tag_len;
            }
        }
    }

    // === DATA FRAMES (Type 2) ===
    else if (type == 2) {
        snprintf(meta->ssid, sizeof(meta->ssid), "[Encrypted Data]");

        // --- Full Scanner Method ---
        // Scan the entire packet starting from the new dynamic offset
        int found_handshake = 0;
        
        // Start searching a bit after the Header (say 24 bytes) until the end
        for (int i = offset + 24; i < size - 8; i++) {
            if (buffer[i] == 0xAA && 
                buffer[i+1] == 0xAA &&  
                buffer[i+2] == 0x03 &&
                buffer[i+6] == 0x88 && 
                buffer[i+7] == 0x8E) {
                
                found_handshake = 1;
                break;
            }
        }

        if (found_handshake) {
            snprintf(meta->ssid, sizeof(meta->ssid), "[HANDSHAKE]");
            
            // Victory Log
            log_message("\n[!!!] >>> EAPOL HANDSHAKE CAPTURED! <<<\n");
            log_message("[!!!] From: %02X:%02X:%02X:%02X:%02X:%02X\n",
                        meta->src_mac[0], meta->src_mac[1], meta->src_mac[2],
                        meta->src_mac[3], meta->src_mac[4], meta->src_mac[5]);
        }
    }
}
void process_packet(const unsigned char* buffer, int size) {
    
    log_message("[DEBUG] RAW PACKET: Size=%d | Byte0=0x%02X | Byte1=0x%02X | Byte2=0x%02X\n", 
                size, buffer[0], buffer[1], buffer[2]);
    
PacketMetadata meta;
    memset(&meta, 0, sizeof(PacketMetadata));
    meta.packet_size = size;

    // --- Monitor Mode Detection ---
    if (size > 4 && buffer[0] == 0x00) {
        uint16_t rt_len = *(uint16_t*)(buffer + 2);
        
        // Sanity Check
        if (rt_len > 0 && rt_len < 256 && rt_len <= size) {
            parseMonitorMode(buffer, size, &meta);
            if (meta.is_monitor_mode) {
                log_packet(&meta);
                return;
            }
        }
    }
    // --- Managed Mode (Ethernet) Logic ---
    
    int eth_header_len = 0;
    uint16_t eth_type = parse_ethernet(buffer, size, &eth_header_len, &meta);
    
    // Log for Managed mode (debug purposes only)
    // log_message("[Managed] Processing Ethernet Frame. Type: 0x%04X\n", eth_type);

    const unsigned char* transport_buffer = NULL;
    int transport_remaining_size = 0;
    uint8_t protocol = 0;

    // Handle IP / IPv6
    if (eth_type == ETHERTYPE_IP || eth_type == ETHERTYPE_IPV6) {
        const unsigned char* network_buffer = buffer + eth_header_len;
        int network_remaining_size = size - eth_header_len;
        int network_header_len = 0;

        protocol = parse_network_layer(network_buffer, network_remaining_size, &network_header_len, &meta);

        transport_buffer = network_buffer + network_header_len;
        transport_remaining_size = network_remaining_size - network_header_len;
    } 
    
    // Ignore non-IP packets (like ARP) for deeper analysis to reduce noise
    if(eth_type < 1536) {
        return;
    }
    
    // Parse Transport Layer
    switch (protocol) {
        case IPPROTO_TCP:
            parse_tcp(transport_buffer, transport_remaining_size, &meta);
            break;
        case IPPROTO_UDP:
            parse_udp(transport_buffer, transport_remaining_size, &meta);
            break;
        case IPPROTO_ICMP:
            parse_icmp(transport_buffer, transport_remaining_size, &meta);
            break;
        case IPPROTO_ICMPV6:
            parse_icmpv6(transport_buffer, transport_remaining_size, &meta);
            break;
        default:
            break;
    }

    // Send data to Dashboard via UDP
    log_packet(&meta);
}