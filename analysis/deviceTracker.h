/**
 * @file deviceTracker.h
 * @brief Stateful WiFi device inventory and security analysis.
 *
 * The packet parsers are stateless — each frame is processed and discarded.
 * This module accumulates observations across frames into two bounded tables
 * (access points and client stations), applies a set of detection rules, and
 * emits a human-readable security report plus a structured summary to the
 * dashboard.
 *
 * THREADING: all tracker_observe_* and tracker_tick() calls happen on the
 * capture thread (from the packet parser). tracker_final_report() is called
 * from main() after the capture loop has exited, so there is never concurrent
 * access and no internal locking is required.
 */

#ifndef DEVICE_TRACKER_H
#define DEVICE_TRACKER_H

#include <stdint.h>

// --- Capacity limits (bounded memory, no dynamic growth) ---
#define TRACKER_MAX_APS      512
#define TRACKER_MAX_CLIENTS  1024
#define TRACKER_SSID_LEN     33
#define TRACKER_PROBES_PER_CLIENT 8  // distinct probed SSIDs retained per client
#define TRACKER_KARMA_SSIDS  8       // distinct SSIDs an AP answered, for karma

// --- Per-entity finding flags (bitmask) ---
#define FLAG_OPEN_NETWORK   (1u << 0)  // AP advertises no encryption
#define FLAG_EVIL_TWIN      (1u << 1)  // SSID seen on multiple BSSIDs
#define FLAG_EVIL_TWIN_OUI  (1u << 2)  // ...and the BSSIDs span different vendors
#define FLAG_HIDDEN_SSID    (1u << 3)  // beacon with empty SSID
#define FLAG_MAC_LEAK       (1u << 4)  // client probes a named SSID w/ real MAC
#define FLAG_RANDOMIZED_MAC (1u << 5)  // locally-administered (privacy) MAC
#define FLAG_KARMA          (1u << 6)  // AP probe-responds to many SSIDs
#define FLAG_DEAUTH_SOURCE  (1u << 7)  // station emitted deauth/disassoc frames

// Device category from fingerprinting.
typedef enum {
    DEV_UNKNOWN = 0,
    DEV_ROUTER,
    DEV_PHONE,
    DEV_PRINTER,
    DEV_CAMERA,     // NVR / DVR / IP camera
    DEV_IOT,
    DEV_CAST        // WiFi-Direct / Chromecast / screen-share
} DeviceType;

/** @brief Reset all tables and counters. Call once at startup. */
void tracker_init(void);

/**
 * @brief Record a beacon observation for an access point.
 * @param bssid    6-byte BSSID (transmitter address).
 * @param ssid     NUL-terminated SSID ("" if hidden).
 * @param channel  Channel number (0 if unknown).
 * @param signal   Signal strength in dBm.
 * @param privacy  1 if the Privacy/encryption capability bit is set.
 */
void tracker_observe_beacon(const uint8_t bssid[6], const char* ssid,
                            int channel, int8_t signal, int privacy);

/**
 * @brief Record a probe REQUEST from a client station.
 * @param mac      Client MAC.
 * @param ssid     Requested SSID ("" if broadcast / wildcard).
 * @param signal   Signal strength in dBm.
 */
void tracker_observe_probe_req(const uint8_t mac[6], const char* ssid,
                               int8_t signal);

/**
 * @brief Record a probe RESPONSE from an access point.
 * @param bssid    Responding AP BSSID.
 * @param ssid     SSID carried in the response.
 * @param channel  Channel number.
 * @param signal   Signal strength in dBm.
 */
void tracker_observe_probe_resp(const uint8_t bssid[6], const char* ssid,
                                int channel, int8_t signal);

/**
 * @brief Record a deauthentication / disassociation frame.
 * @param src  Transmitter address.
 */
void tracker_observe_deauth(const uint8_t src[6]);

/**
 * @brief Periodic hook — call frequently from the capture loop. Flushes the
 * report to disk and the dashboard at a fixed interval (cheap no-op between).
 */
void tracker_tick(void);

/** @brief Write the final report (called once at shutdown). */
void tracker_final_report(void);

#endif // DEVICE_TRACKER_H
