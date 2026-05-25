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
static void parse_radiotap(const unsigned char* buffer, int radiotap_len,
                           PacketMetadata* meta);


void parse_monitor_packet(const unsigned char* buffer, int size, PacketMetadata* meta) {
    // 1. Validate Radiotap Header Length (LE u16 at offset 2)
    if (size < 8) return;
    uint16_t radiotap_len;
    memcpy(&radiotap_len, buffer + 2, sizeof(radiotap_len));

    // Sanity checks
    if (radiotap_len >= size || radiotap_len < 8) return;

    // 2. Extract Physical Metadata (Frequency, RSSI) via proper Radiotap walk
    parse_radiotap(buffer, radiotap_len, meta);

    meta->is_monitor_mode = 1;
    memset(meta->ssid, 0, sizeof(meta->ssid));

    // Define the start of the 802.11 Frame
    int offset = radiotap_len;
    if (offset + 24 >= size) return; // Ensure header fits

    // 3. Parse 802.11 Frame Control
    uint16_t frame_control;
    memcpy(&frame_control, buffer + offset, sizeof(frame_control));
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
                    // Cap to ssid buffer minus the terminator. memset above
                    // already zeroed the whole buffer, so the explicit NUL is
                    // belt-and-suspenders.
                    size_t max_ssid = sizeof(meta->ssid) - 1;
                    size_t copy_len = (tag_len < max_ssid) ? tag_len : max_ssid;
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

/**
 * Walk the Radiotap header per the spec: read it_present (and any extension
 * present words, signalled by bit 31), then iterate the fields in bit order
 * applying each field's natural alignment relative to the radiotap header
 * start. Extract channel frequency (bit 3) and antenna signal dBm (bit 5).
 *
 * Field table is the subset needed to walk past everything that may appear
 * before bit 5 across common chipsets; trailing fields are listed for
 * completeness so the offset stays consistent if drivers add more.
 */
static void parse_radiotap(const unsigned char* buffer, int radiotap_len,
                           PacketMetadata* meta) {
    static const struct { int bit; int align; int size; } fields[] = {
        { 0, 8, 8},  // TSFT
        { 1, 1, 1},  // FLAGS
        { 2, 1, 1},  // RATE
        { 3, 2, 4},  // CHANNEL (freq + flags)
        { 4, 1, 2},  // FHSS
        { 5, 1, 1},  // DBM_ANTSIGNAL
        { 6, 1, 1},  // DBM_ANTNOISE
        { 7, 2, 2},  // LOCK_QUALITY
        { 8, 2, 2},  // TX_ATTENUATION
        { 9, 2, 2},  // DB_TX_ATTENUATION
        {10, 1, 1},  // DBM_TX_POWER
        {11, 1, 1},  // ANTENNA
        {12, 1, 1},  // DB_ANTSIGNAL
        {13, 1, 1},  // DB_ANTNOISE
        {14, 2, 2},  // RX_FLAGS
        {15, 2, 2},  // TX_FLAGS
        {16, 1, 1},  // RTS_RETRIES
        {17, 1, 1},  // DATA_RETRIES
        {19, 1, 3},  // MCS
        {20, 4, 8},  // AMPDU_STATUS
        {21, 2,12},  // VHT
    };

    if (radiotap_len < 8) return;

    uint32_t present;
    memcpy(&present, buffer + 4, sizeof(present));

    // Skip extension present words (bit 31 = another u32 follows).
    int offset = 8;
    uint32_t cur = present;
    while (cur & (1u << 31)) {
        if (offset + 4 > radiotap_len) return;
        memcpy(&cur, buffer + offset, sizeof(cur));
        offset += 4;
    }

    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        if (!(present & (1u << fields[i].bit))) continue;

        int misalign = offset % fields[i].align;
        if (misalign) offset += fields[i].align - misalign;
        if (offset + fields[i].size > radiotap_len) return;

        if (fields[i].bit == 3) {
            uint16_t freq;
            memcpy(&freq, buffer + offset, sizeof(freq));
            meta->channel = mhz_to_channel(freq);
        } else if (fields[i].bit == 5) {
            meta->signal_dbm = (int8_t)buffer[offset];
        }

        offset += fields[i].size;
    }
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

