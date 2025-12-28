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
    // Lenovo V14 Hardcoded Header Check
    if (size < 38) return; 

    // --- 1. Extract Physical Info (Radiotap) ---
    uint16_t freq = *(uint16_t*)(buffer + 26);
    meta->channel = mhz_to_channel(freq);
    meta->signal_dbm = (int8_t)buffer[30];
    meta->is_monitor_mode = 1;
    memset(meta->ssid, 0, sizeof(meta->ssid));

    int offset = 38; // End of Radiotap Header

    if (offset + 24 >= size) return;

    // --- 2. Extract 802.11 Header Info ---
    uint16_t frame_control = *(uint16_t*)(buffer + offset);
    uint8_t type = (frame_control >> 2) & 0x3;
    uint8_t subtype = (frame_control >> 4) & 0xF;

    // Extract MAC Addresses (Addr1=Dest, Addr2=Source, Addr3=BSSID)
    // Source MAC is usually at offset + 10
    if (size >= offset + 16) {
        memcpy(meta->dest_mac, buffer + offset + 4, 6);
        memcpy(meta->src_mac, buffer + offset + 10, 6);
    }

    // --- 3. Parse Frame Types ---

    // === MANAGEMENT FRAMES (Type 0) ===
    if (type == 0) {
        int body_offset = offset + 24; // Skip MAC Header
        char packet_type[15] = "UNKNOWN";
        int is_ssid_frame = 0;

        // A. BEACON (Subtype 8) or PROBE RESPONSE (Subtype 5)
        // These have 12 bytes of fixed params (Timestamp etc.) before tags
        if (subtype == 8 || subtype == 5) {
            body_offset += 12; 
            strcpy(packet_type, (subtype == 8) ? "BEACON" : "PROBE_RESP");
            is_ssid_frame = 1;
        }
        // B. PROBE REQUEST (Subtype 4)
        // Devices asking "Are you there?". Tags start IMMEDIATELY after MAC.
        else if (subtype == 4) {
            // No fixed params to skip!
            strcpy(packet_type, "PROBE_REQ");
            is_ssid_frame = 1;
        }

        // Parse SSID from Tags
        if (is_ssid_frame && body_offset < size) {
            while (body_offset + 2 <= size) {
                uint8_t tag_id = buffer[body_offset];
                uint8_t tag_len = buffer[body_offset + 1];
                
                if (body_offset + 2 + tag_len > size) break;

                if (tag_id == 0) { // SSID Tag found
                    int copy_len = (tag_len < 32) ? tag_len : 32;
                    
                    if (copy_len > 0) {
                        memcpy(meta->ssid, buffer + body_offset + 2, copy_len);
                        meta->ssid[copy_len] = '\0';
                    } else {
                        // Empty SSID handling
                        if (subtype == 4) snprintf(meta->ssid, sizeof(meta->ssid), "[BROADCAST]");
                        else snprintf(meta->ssid, sizeof(meta->ssid), "<HIDDEN>");
                    }
                    
                    // --- THE MAIN LOG ---
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
    // This shows actual internet traffic (Netflix, YouTube, etc.)
    else if (type == 2) {
        // We can't read the data (encrypted), but we log the activity
        // Logging every single data packet is too much, so we uncomment this only for deep debug
        // log_message("[DATA]    [%02X:%02X:%02X:%02X:%02X:%02X] Size: %d bytes\n",

        
        // ברירת מחדל: סתם מידע מוצפן
        snprintf(meta->ssid, sizeof(meta->ssid), "[Encrypted Data]");

        // --- בדיקת EAPOL (לחיצת יד) ---
        // כותרת 802.11 רגילה היא 24 בתים. אם יש QoS (רוב המכשירים היום), היא 26.
        int header_len = 24;
        if ((subtype & 0x08)) header_len = 26; // Bit 3 דולק = QoS Data

        // בדיקה שיש לנו מספיק מקום לקרוא את כותרת ה-LLC (עוד 8 בתים)
        if (offset + header_len + 8 <= size) {
            unsigned char* llc_header = (unsigned char*)(buffer + offset + header_len);
            
            // חתימת EAPOL:
            // LLC SNAP: AA AA 03 00 00 00
            // EtherType: 88 8E
            if (llc_header[0] == 0xAA && 
                llc_header[1] == 0xAA && 
                llc_header[6] == 0x88 && 
                llc_header[7] == 0x8E) {
                
                // בינגו! תפסנו את המפתחות
                snprintf(meta->ssid, sizeof(meta->ssid), "[HANDSHAKE]");
                
                // נדאג שהדגל הזה יישלח כלוג חשוב
                log_message("[!!!] CAPTURED HANDSHAKE from %02X:%02X:%02X:%02X:%02X:%02X\n",
                    meta->src_mac[0], meta->src_mac[1], meta->src_mac[2],
                    meta->src_mac[3], meta->src_mac[4], meta->src_mac[5]);
            }
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