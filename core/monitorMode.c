/**
 * @file monitorMode.c
 * @brief Implementation of WiFi packet analysis and PCAP dumping.
 */

#include "monitorMode.h"
#include "logger.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

// --- Private Helper Prototypes (Static) ---
static int mhz_to_channel(int freq);
static void save_handshake_to_file(const unsigned char* buffer, int size);
static void write_pcap_global_header(FILE *fp);
static void print_hex_dump(const unsigned char* buffer, int length);


void parse_monitor_packet(const unsigned char* buffer, int size, PacketMetadata* meta) {
    // 1. Validate Radiotap Header Length
    // The length is a 16-bit integer at offset 2 (Little Endian)
    if (size < 4) return;
    uint16_t radiotap_len = *(uint16_t*)(buffer + 2);

    // Sanity checks
    if (radiotap_len >= size || radiotap_len < 10) return;

    // 2. Extract Physical Metadata (Frequency, RSSI)
    // Note: Offsets might vary based on Radiotap fields present, 
    // but usually Freq is at 26 and RSSI (Signal) at 30 for standard drivers.
    if (radiotap_len >= 30) {
        uint16_t freq = *(uint16_t*)(buffer + 26);
        meta->channel = mhz_to_channel(freq);
        meta->signal_dbm = (int8_t)buffer[30];
    }

    meta->is_monitor_mode = 1;
    memset(meta->ssid, 0, sizeof(meta->ssid));

    // Define the start of the 802.11 Frame
    int offset = radiotap_len; 
    if (offset + 24 >= size) return; // Ensure header fits

    // 3. Parse 802.11 Frame Control
    uint16_t frame_control = *(uint16_t*)(buffer + offset);
    uint8_t type = (frame_control >> 2) & 0x3;
    uint8_t subtype = (frame_control >> 4) & 0xF;

    // Extract MAC Addresses (Dest: +4, Src: +10)
    if (size >= offset + 16) {
        memcpy(meta->dest_mac, buffer + offset + 4, 6);
        memcpy(meta->src_mac, buffer + offset + 10, 6);
    }

    // === TYPE 0: MANAGEMENT FRAMES (Beacons / Probes) ===
    if (type == 0) {
        int body_offset = offset + 24; 
        char packet_type[15] = "UNKNOWN";
        int is_ssid_frame = 0;

        if (subtype == 8) { // BEACON
            body_offset += 12; // Skip Timestamp & Beacon Interval
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

        // Parse Tagged Parameters to find SSID (Tag 0)
        if (is_ssid_frame && body_offset < size) {
            while (body_offset + 2 <= size) {
                uint8_t tag_id = buffer[body_offset];
                uint8_t tag_len = buffer[body_offset + 1];
                if (body_offset + 2 + tag_len > size) break;

                if (tag_id == 0) { // SSID Tag
                    int copy_len = (tag_len < 32) ? tag_len : 32;
                    if (copy_len > 0) {
                        memcpy(meta->ssid, buffer + body_offset + 2, copy_len);
                        meta->ssid[copy_len] = '\0';
                    } else {
                        snprintf(meta->ssid, sizeof(meta->ssid), (subtype == 4) ? "[BROADCAST]" : "<HIDDEN>");
                    }
                    
                    // Log relevant WiFi events
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

    // === TYPE 2: DATA FRAMES (Encrypted Traffic) ===
    else if (type == 2) {
        snprintf(meta->ssid, sizeof(meta->ssid), "[Encrypted Data]");
        
        // EAPOL Handshake Detection
        // Looking for the EAPOL signature: 0xAA 0xAA 0x03 ... 0x88 0x8E
        int found_handshake = 0;
        
        // Optimistic scan starting after header
        for (int i = offset + 24; i < size - 8; i++) {
            if (buffer[i] == 0xAA && buffer[i+1] == 0xAA &&  
                buffer[i+2] == 0x03 && buffer[i+6] == 0x88 && buffer[i+7] == 0x8E) {
                found_handshake = 1;
                break;
            }
        }

        if (found_handshake) {
            snprintf(meta->ssid, sizeof(meta->ssid), "[HANDSHAKE]");
            
            log_message("\n[!!!] >>> EAPOL HANDSHAKE CAPTURED! <<<\n");
            log_message("[!!!] Target: %02X:%02X:%02X:%02X:%02X:%02X\n",
                        meta->src_mac[0], meta->src_mac[1], meta->src_mac[2],
                        meta->src_mac[3], meta->src_mac[4], meta->src_mac[5]);

            save_handshake_to_file(buffer, size);
        }
    }
}

// --- Internal Helper Implementation ---

static int mhz_to_channel(int freq) {
    if (freq < 2400 || freq > 6000) return 0;
    if (freq == 2484) return 14;
    if (freq < 2484) return (freq - 2407) / 5;
    return (freq - 5000) / 5;
}

static void write_pcap_global_header(FILE *fp) {
    uint32_t magic_number = 0xa1b2c3d4; // PCAP Magic Number
    uint16_t version_major = 2;
    uint16_t version_minor = 4;
    int32_t  thiszone = 0;
    uint32_t sigfigs = 0;
    uint32_t snaplen = 65535;
    uint32_t network = 127; // DLT_IEEE802_11_RADIO (Radiotap)

    fwrite(&magic_number, 4, 1, fp);
    fwrite(&version_major, 2, 1, fp);
    fwrite(&version_minor, 2, 1, fp);
    fwrite(&thiszone, 4, 1, fp);
    fwrite(&sigfigs, 4, 1, fp);
    fwrite(&snaplen, 4, 1, fp);
    fwrite(&network, 4, 1, fp);
}

static void save_handshake_to_file(const unsigned char* buffer, int size) {
    const char* filename = "captured_handshake.cap";
    FILE *fp = fopen(filename, "ab"); // Append Binary mode
    
    if (!fp) {
        log_message("[ERROR] Could not open file %s for writing\n", filename);
        return;
    }

    // Check if file is empty (needs header)
    fseek(fp, 0, SEEK_END);
    if (ftell(fp) == 0) {
        write_pcap_global_header(fp);
    }

    // Write Packet Header
    uint32_t ts_sec = (uint32_t)time(NULL);
    uint32_t ts_usec = 0; 
    uint32_t incl_len = size;
    uint32_t orig_len = size;

    fwrite(&ts_sec, 4, 1, fp);
    fwrite(&ts_usec, 4, 1, fp);
    fwrite(&incl_len, 4, 1, fp);
    fwrite(&orig_len, 4, 1, fp);

    // Write Packet Data
    fwrite(buffer, 1, size, fp);
    
    fclose(fp);
    log_message("[DISK] Saved EAPOL packet (%d bytes) to %s\n", size, filename);
}

static void print_hex_dump(const unsigned char* buffer, int length) {
    char debug_buf[1024] = "";
    int pos = 0;
    // Limit dump to first 32 bytes to avoid log flooding
    for (int i = 0; i < length && i < 32; i++) { 
        pos += snprintf(debug_buf + pos, sizeof(debug_buf) - pos, "%02X ", buffer[i]);
    }
    log_message("[HEX] %s\n", debug_buf);
}