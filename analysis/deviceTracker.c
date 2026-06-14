/**
 * @file deviceTracker.c
 * @brief Implementation of the WiFi device inventory + security analysis.
 */

#define _GNU_SOURCE
#include "deviceTracker.h"
#include "logger.h"
#include "udp_sender.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>   // strcasestr
#include <time.h>
#include <ctype.h>

// --- Tunables ---
#define REPORT_FILE        "wifi_security_report.txt"
#define REPORT_INTERVAL_S  10      // how often to flush report + dashboard
#define KARMA_SSID_THRESH  3       // distinct SSIDs answered -> karma suspect
#define DEAUTH_FLOOD_THRESH 20     // deauth frames in one window -> flood alert

// --- Internal entry types ---
typedef struct {
    uint8_t  bssid[6];
    char     ssid[TRACKER_SSID_LEN];
    int      channel;
    int8_t   signal_best;          // strongest (closest to 0) dBm seen
    int8_t   signal_last;
    uint32_t beacons;
    int      privacy;              // 1 = encrypted, 0 = open
    DeviceType type;
    uint16_t flags;
    time_t   first_seen, last_seen;
    // Karma: distinct SSIDs this AP has probe-responded to.
    char     answered[TRACKER_KARMA_SSIDS][TRACKER_SSID_LEN];
    int      answered_count;
    uint32_t deauths;
    int      used;
} ApEntry;

typedef struct {
    uint8_t  mac[6];
    int      randomized;
    char     probed[TRACKER_PROBES_PER_CLIENT][TRACKER_SSID_LEN];
    int      probed_count;
    int8_t   signal_last;
    uint32_t probes;
    DeviceType type;
    uint16_t flags;
    time_t   first_seen, last_seen;
    int      used;
} ClientEntry;

// --- State (capture-thread-local; see header threading note) ---
static ApEntry     aps[TRACKER_MAX_APS];
static ClientEntry clients[TRACKER_MAX_CLIENTS];
static int ap_count = 0;
static int client_count = 0;

static uint32_t total_deauths = 0;
static uint32_t deauth_window = 0;     // reset each report interval
static int deauth_flood_active = 0;

static time_t last_flush = 0;

// ----------------------------------------------------------------------------
// Small helpers
// ----------------------------------------------------------------------------

static int mac_eq(const uint8_t a[6], const uint8_t b[6]) {
    return memcmp(a, b, 6) == 0;
}

// Locally-administered bit (bit 1 of the first octet) => randomized/virtual.
static int is_randomized(const uint8_t mac[6]) {
    return (mac[0] & 0x02) != 0;
}

static int same_oui(const uint8_t a[6], const uint8_t b[6]) {
    return memcmp(a, b, 3) == 0;
}

/**
 * @brief Best-effort vendor name from the OUI. This is a tiny curated table —
 * not a full IEEE registry — so unknown OUIs fall back to the hex prefix.
 */
static const char* oui_vendor(const uint8_t mac[6]) {
    static const struct { uint8_t p[3]; const char* name; } tbl[] = {
        {{0x10,0xB6,0x76}, "HP"},
        {{0x40,0x5E,0xE1}, "Hi-Smart/IoT"},
        {{0x44,0x15,0x24}, "ISP-CPE"},
        {{0xB0,0x1F,0x47}, "ISP-CPE"},
        {{0x9C,0xA3,0xA9}, "IoT/Camera"},
        {{0x00,0x17,0x88}, "Philips Hue"},
        {{0xEC,0xFA,0xBC}, "Espressif/IoT"},
        {{0x18,0xFE,0x34}, "Espressif/IoT"},
    };
    for (size_t i = 0; i < sizeof(tbl)/sizeof(tbl[0]); i++) {
        if (memcmp(mac, tbl[i].p, 3) == 0) return tbl[i].name;
    }
    return NULL;
}

static const char* dev_type_str(DeviceType t) {
    switch (t) {
        case DEV_ROUTER:  return "Router/AP";
        case DEV_PHONE:   return "Phone/Laptop";
        case DEV_PRINTER: return "Printer";
        case DEV_CAMERA:  return "Camera/NVR";
        case DEV_IOT:     return "IoT";
        case DEV_CAST:    return "Cast/Direct";
        default:          return "Unknown";
    }
}

/**
 * @brief Fingerprint a device from its SSID and OUI. Heuristic, order matters
 * (more specific patterns first).
 */
static DeviceType classify_device(const char* ssid, const uint8_t mac[6], int is_ap) {
    if (ssid && ssid[0]) {
        if (strcasestr(ssid, "NVR") || strcasestr(ssid, "DVR") ||
            strcasestr(ssid, "IPC") || strcasestr(ssid, "CAM"))
            return DEV_CAMERA;
        if (strcasestr(ssid, "DeskJet") || strcasestr(ssid, "OfficeJet") ||
            strcasestr(ssid, "ENVY") || strcasestr(ssid, "Canon") ||
            strcasestr(ssid, "EPSON") || strcasestr(ssid, "printer"))
            return DEV_PRINTER;
        if (strncasecmp(ssid, "DIRECT-", 7) == 0)
            return DEV_CAST;
        if (strcasestr(ssid, "Hi-Smart") || strcasestr(ssid, "AEH") ||
            strcasestr(ssid, "Tuya")     || strcasestr(ssid, "Sonoff") ||
            strcasestr(ssid, "Govee")    || strcasestr(ssid, "Tapo") ||
            strcasestr(ssid, "Wyze")     || strcasestr(ssid, "Smart"))
            return DEV_IOT;
    }
    const char* v = oui_vendor(mac);
    if (v) {
        if (strcmp(v, "HP") == 0) return DEV_PRINTER;
        if (strstr(v, "Camera")) return DEV_CAMERA;
        if (strstr(v, "IoT") || strstr(v, "Hue") || strstr(v, "Espressif")) return DEV_IOT;
    }
    return is_ap ? DEV_ROUTER : DEV_PHONE;
}

// Minimal JSON string escaper for SSIDs embedded in dashboard output.
static void json_escape(const char* in, char* out, size_t out_size) {
    size_t o = 0;
    if (out_size == 0) return;
    for (size_t i = 0; in[i] && o + 2 < out_size; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"' || c == '\\') { out[o++] = '\\'; out[o++] = (char)c; }
        else if (c < 0x20) { /* drop control chars */ }
        else out[o++] = (char)c;
    }
    out[o] = '\0';
}

// ----------------------------------------------------------------------------
// Table lookup / insert
// ----------------------------------------------------------------------------

static ApEntry* ap_find_or_add(const uint8_t bssid[6]) {
    for (int i = 0; i < ap_count; i++) {
        if (aps[i].used && mac_eq(aps[i].bssid, bssid)) return &aps[i];
    }
    if (ap_count >= TRACKER_MAX_APS) return NULL; // table full: ignore new APs
    ApEntry* e = &aps[ap_count++];
    memset(e, 0, sizeof(*e));
    memcpy(e->bssid, bssid, 6);
    e->signal_best = -128;
    e->first_seen = time(NULL);
    e->used = 1;
    return e;
}

static ClientEntry* client_find_or_add(const uint8_t mac[6]) {
    for (int i = 0; i < client_count; i++) {
        if (clients[i].used && mac_eq(clients[i].mac, mac)) return &clients[i];
    }
    if (client_count >= TRACKER_MAX_CLIENTS) return NULL;
    ClientEntry* e = &clients[client_count++];
    memset(e, 0, sizeof(*e));
    memcpy(e->mac, mac, 6);
    e->first_seen = time(NULL);
    e->used = 1;
    return e;
}

// Add a probed SSID to a client's set (dedup, bounded).
static void client_add_probe(ClientEntry* c, const char* ssid) {
    if (!ssid[0]) return; // broadcast/wildcard not retained as a named leak
    for (int i = 0; i < c->probed_count; i++) {
        if (strcmp(c->probed[i], ssid) == 0) return;
    }
    if (c->probed_count < TRACKER_PROBES_PER_CLIENT) {
        strncpy(c->probed[c->probed_count], ssid, TRACKER_SSID_LEN - 1);
        c->probed[c->probed_count][TRACKER_SSID_LEN - 1] = '\0';
        c->probed_count++;
    }
}

// ----------------------------------------------------------------------------
// Observation API
// ----------------------------------------------------------------------------

void tracker_observe_beacon(const uint8_t bssid[6], const char* ssid,
                            int channel, int8_t signal, int privacy) {
    ApEntry* e = ap_find_or_add(bssid);
    if (!e) return;

    if (ssid && ssid[0]) {
        strncpy(e->ssid, ssid, TRACKER_SSID_LEN - 1);
        e->ssid[TRACKER_SSID_LEN - 1] = '\0';
    } else {
        e->flags |= FLAG_HIDDEN_SSID;
    }
    if (channel) e->channel = channel;
    if (signal > e->signal_best) e->signal_best = signal;
    e->signal_last = signal;
    e->privacy = privacy;
    if (!privacy) e->flags |= FLAG_OPEN_NETWORK;
    if (is_randomized(bssid)) e->flags |= FLAG_RANDOMIZED_MAC;
    e->type = classify_device(e->ssid, bssid, 1);
    e->beacons++;
    e->last_seen = time(NULL);
}

void tracker_observe_probe_req(const uint8_t mac[6], const char* ssid,
                               int8_t signal) {
    ClientEntry* c = client_find_or_add(mac);
    if (!c) return;

    c->randomized = is_randomized(mac);
    if (c->randomized) c->flags |= FLAG_RANDOMIZED_MAC;

    // Real-MAC probe leak: a globally-administered MAC actively asking for a
    // specific (named) network reveals a saved network and is trackable.
    if (ssid && ssid[0] && !c->randomized) {
        c->flags |= FLAG_MAC_LEAK;
    }
    client_add_probe(c, ssid ? ssid : "");
    c->signal_last = signal;
    c->type = classify_device((ssid && ssid[0]) ? ssid : NULL, mac, 0);
    c->probes++;
    c->last_seen = time(NULL);
}

void tracker_observe_probe_resp(const uint8_t bssid[6], const char* ssid,
                                int channel, int8_t signal) {
    ApEntry* e = ap_find_or_add(bssid);
    if (!e) return;

    if (e->ssid[0] == '\0' && ssid && ssid[0]) {
        strncpy(e->ssid, ssid, TRACKER_SSID_LEN - 1);
        e->ssid[TRACKER_SSID_LEN - 1] = '\0';
    }
    if (channel) e->channel = channel;
    if (signal > e->signal_best) e->signal_best = signal;
    e->signal_last = signal;
    e->last_seen = time(NULL);

    // Karma detection: an AP that answers probes for many different SSIDs is
    // likely impersonating whatever clients ask for.
    if (ssid && ssid[0]) {
        int known = 0;
        for (int i = 0; i < e->answered_count; i++) {
            if (strcmp(e->answered[i], ssid) == 0) { known = 1; break; }
        }
        if (!known && e->answered_count < TRACKER_KARMA_SSIDS) {
            strncpy(e->answered[e->answered_count], ssid, TRACKER_SSID_LEN - 1);
            e->answered[e->answered_count][TRACKER_SSID_LEN - 1] = '\0';
            e->answered_count++;
        }
        if (e->answered_count >= KARMA_SSID_THRESH) e->flags |= FLAG_KARMA;
    }
}

void tracker_observe_deauth(const uint8_t src[6]) {
    total_deauths++;
    deauth_window++;
    ApEntry* e = ap_find_or_add(src);
    if (e) {
        e->deauths++;
        e->flags |= FLAG_DEAUTH_SOURCE;
    }
}

// ----------------------------------------------------------------------------
// Evil-twin pass (computed over the whole table at report time)
// ----------------------------------------------------------------------------

static void recompute_evil_twins(void) {
    for (int i = 0; i < ap_count; i++) {
        if (!aps[i].used || aps[i].ssid[0] == '\0') continue;
        aps[i].flags &= ~(FLAG_EVIL_TWIN | FLAG_EVIL_TWIN_OUI);
    }
    for (int i = 0; i < ap_count; i++) {
        if (!aps[i].used || aps[i].ssid[0] == '\0') continue;
        for (int j = i + 1; j < ap_count; j++) {
            if (!aps[j].used || aps[j].ssid[0] == '\0') continue;
            if (strcmp(aps[i].ssid, aps[j].ssid) != 0) continue;
            // Same SSID on two different BSSIDs.
            aps[i].flags |= FLAG_EVIL_TWIN;
            aps[j].flags |= FLAG_EVIL_TWIN;
            // Different vendor OUI is the stronger rogue-AP signal (legit
            // mesh/extenders almost always share an OUI).
            if (!same_oui(aps[i].bssid, aps[j].bssid)) {
                aps[i].flags |= FLAG_EVIL_TWIN_OUI;
                aps[j].flags |= FLAG_EVIL_TWIN_OUI;
            }
        }
    }
}

// ----------------------------------------------------------------------------
// Report writer
// ----------------------------------------------------------------------------

static void mac_str(const uint8_t m[6], char out[18]) {
    snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             m[0], m[1], m[2], m[3], m[4], m[5]);
}

static void flags_str(uint16_t f, char* out, size_t n) {
    out[0] = '\0';
    #define ADD(s) do { if (out[0]) strncat(out, ",", n - strlen(out) - 1); \
                        strncat(out, s, n - strlen(out) - 1); } while (0)
    if (f & FLAG_OPEN_NETWORK)   ADD("OPEN");
    if (f & FLAG_EVIL_TWIN_OUI)  ADD("EVIL-TWIN!");
    else if (f & FLAG_EVIL_TWIN) ADD("dup-SSID");
    if (f & FLAG_HIDDEN_SSID)    ADD("hidden");
    if (f & FLAG_MAC_LEAK)       ADD("MAC-LEAK");
    if (f & FLAG_RANDOMIZED_MAC) ADD("rand-MAC");
    if (f & FLAG_KARMA)          ADD("KARMA!");
    if (f & FLAG_DEAUTH_SOURCE)  ADD("DEAUTH-SRC!");
    #undef ADD
    if (!out[0]) strncpy(out, "-", n - 1);
}

// Counters filled during the report pass, reused for stdout + dashboard.
typedef struct {
    int open_networks, evil_twins, mac_leaks, karma, deauth_sources, hidden;
} Findings;

static void write_report_file(const Findings* f) {
    FILE* fp = fopen(REPORT_FILE, "w");
    if (!fp) {
        log_message("[ERROR] Could not open %s for writing\n", REPORT_FILE);
        return;
    }

    time_t now = time(NULL);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));

    fprintf(fp, "================ WiFi Security Report ================\n");
    fprintf(fp, "Generated: %s\n", ts);
    fprintf(fp, "APs: %d   Clients: %d   Deauth frames: %u\n",
            ap_count, client_count, total_deauths);
    fprintf(fp, "(Vendor names are best-effort from a small built-in OUI table.)\n\n");

    // --- Access Points ---
    fprintf(fp, "----- ACCESS POINTS -----\n");
    fprintf(fp, "%-17s  %-22s  %-12s  %3s  %-7s  %5s  %6s  %s\n",
            "BSSID", "SSID", "VENDOR", "CH", "SEC", "dBm", "BEACON", "FLAGS");
    for (int i = 0; i < ap_count; i++) {
        if (!aps[i].used) continue;
        char bs[18]; mac_str(aps[i].bssid, bs);
        char fl[96]; flags_str(aps[i].flags, fl, sizeof(fl));
        const char* v = oui_vendor(aps[i].bssid);
        char vbuf[16];
        if (!v) { snprintf(vbuf, sizeof(vbuf), "%02X:%02X:%02X",
                  aps[i].bssid[0], aps[i].bssid[1], aps[i].bssid[2]); v = vbuf; }
        fprintf(fp, "%-17s  %-22s  %-12s  %3d  %-7s  %5d  %6u  %s\n",
                bs,
                aps[i].ssid[0] ? aps[i].ssid : "<hidden>",
                v,
                aps[i].channel,
                aps[i].privacy ? "WPA/enc" : "OPEN",
                aps[i].signal_best,
                aps[i].beacons,
                fl);
    }

    // --- Clients ---
    fprintf(fp, "\n----- CLIENT STATIONS -----\n");
    fprintf(fp, "%-17s  %-12s  %5s  %6s  %s\n",
            "MAC", "TYPE", "dBm", "PROBES", "PROBED-SSIDs / FLAGS");
    for (int i = 0; i < client_count; i++) {
        if (!clients[i].used) continue;
        char ms[18]; mac_str(clients[i].mac, ms);
        char fl[96]; flags_str(clients[i].flags, fl, sizeof(fl));
        fprintf(fp, "%-17s  %-12s  %5d  %6u  ",
                ms, dev_type_str(clients[i].type),
                clients[i].signal_last, clients[i].probes);
        for (int p = 0; p < clients[i].probed_count; p++) {
            fprintf(fp, "%s%s", p ? "," : "", clients[i].probed[p]);
        }
        if (clients[i].probed_count == 0) fprintf(fp, "(broadcast only)");
        fprintf(fp, "  [%s]\n", fl);
    }

    // --- Findings ---
    fprintf(fp, "\n----- SECURITY FINDINGS -----\n");
    int n = 0;
    if (deauth_flood_active)
        fprintf(fp, "%d. [ALERT] Deauthentication flood in progress (%u frames last window).\n", ++n, deauth_window);
    for (int i = 0; i < ap_count; i++) {
        if (!aps[i].used) continue;
        char bs[18]; mac_str(aps[i].bssid, bs);
        if (aps[i].flags & FLAG_EVIL_TWIN_OUI)
            fprintf(fp, "%d. [ALERT] Possible EVIL TWIN: SSID '%s' on %s (different vendor than its twin).\n",
                    ++n, aps[i].ssid, bs);
        if (aps[i].flags & FLAG_KARMA)
            fprintf(fp, "%d. [ALERT] KARMA AP %s answered %d different SSIDs.\n",
                    ++n, bs, aps[i].answered_count);
        if (aps[i].flags & FLAG_DEAUTH_SOURCE)
            fprintf(fp, "%d. [ALERT] %s emitted %u deauth/disassoc frames.\n",
                    ++n, bs, aps[i].deauths);
        if (aps[i].flags & FLAG_OPEN_NETWORK)
            fprintf(fp, "%d. [WARN]  Open (unencrypted) network '%s' on %s.\n",
                    ++n, aps[i].ssid[0] ? aps[i].ssid : "<hidden>", bs);
    }
    for (int i = 0; i < client_count; i++) {
        if (!clients[i].used) continue;
        if (clients[i].flags & FLAG_MAC_LEAK) {
            char ms[18]; mac_str(clients[i].mac, ms);
            fprintf(fp, "%d. [PRIV]  %s (%s) leaks saved networks: ",
                    ++n, ms, dev_type_str(clients[i].type));
            for (int p = 0; p < clients[i].probed_count; p++)
                fprintf(fp, "%s%s", p ? ", " : "", clients[i].probed[p]);
            fprintf(fp, "\n");
        }
    }
    if (n == 0) fprintf(fp, "No notable findings.\n");

    fprintf(fp, "=====================================================\n");
    fclose(fp);

    // mirror counts to caller for stdout/dashboard
    (void)f;
}

static void send_dashboard_summary(const Findings* f) {
    // Compact structured summary the Python listener can route on msg_type.
    char buf[2048];
    int o = snprintf(buf, sizeof(buf),
        "{\"msg_type\":\"security_report\","
        "\"aps\":%d,\"clients\":%d,\"deauth_frames\":%u,"
        "\"open_networks\":%d,\"evil_twins\":%d,\"mac_leaks\":%d,"
        "\"karma\":%d,\"deauth_sources\":%d,\"deauth_flood\":%d,"
        "\"findings\":[",
        ap_count, client_count, total_deauths,
        f->open_networks, f->evil_twins, f->mac_leaks,
        f->karma, f->deauth_sources, deauth_flood_active);

    int first = 1;
    #define EMIT(sev, fmt, ...) do { \
        char line[160], esc[160]; \
        snprintf(line, sizeof(line), fmt, __VA_ARGS__); \
        json_escape(line, esc, sizeof(esc)); \
        int wrote = snprintf(buf + o, sizeof(buf) - o, "%s\"[%s] %s\"", \
                             first ? "" : ",", sev, esc); \
        if (wrote > 0 && (size_t)(o + wrote) < sizeof(buf)) { o += wrote; first = 0; } \
    } while (0)

    if (deauth_flood_active) EMIT("ALERT", "Deauth flood: %u frames/window", deauth_window);
    for (int i = 0; i < ap_count && o < (int)sizeof(buf) - 200; i++) {
        if (!aps[i].used) continue;
        if (aps[i].flags & FLAG_EVIL_TWIN_OUI) EMIT("ALERT", "Evil twin: %s", aps[i].ssid);
        if (aps[i].flags & FLAG_KARMA)         EMIT("ALERT", "Karma AP answered %d SSIDs", aps[i].answered_count);
        if (aps[i].flags & FLAG_OPEN_NETWORK)  EMIT("WARN", "Open network: %s", aps[i].ssid[0] ? aps[i].ssid : "<hidden>");
    }
    for (int i = 0; i < client_count && o < (int)sizeof(buf) - 200; i++) {
        if (clients[i].used && (clients[i].flags & FLAG_MAC_LEAK)) {
            char ms[18]; mac_str(clients[i].mac, ms);
            EMIT("PRIV", "MAC leak from %s", ms);
        }
    }
    #undef EMIT

    if ((size_t)o < sizeof(buf) - 3) {
        o += snprintf(buf + o, sizeof(buf) - o, "]}");
        send_udp_json(buf);
    }
}

static void compute_findings(Findings* f) {
    memset(f, 0, sizeof(*f));
    for (int i = 0; i < ap_count; i++) {
        if (!aps[i].used) continue;
        if (aps[i].flags & FLAG_OPEN_NETWORK)  f->open_networks++;
        if (aps[i].flags & FLAG_EVIL_TWIN_OUI) f->evil_twins++;
        if (aps[i].flags & FLAG_KARMA)         f->karma++;
        if (aps[i].flags & FLAG_DEAUTH_SOURCE) f->deauth_sources++;
        if (aps[i].flags & FLAG_HIDDEN_SSID)   f->hidden++;
    }
    for (int i = 0; i < client_count; i++) {
        if (clients[i].used && (clients[i].flags & FLAG_MAC_LEAK)) f->mac_leaks++;
    }
}

static void generate_report(void) {
    recompute_evil_twins();

    Findings f;
    compute_findings(&f);

    write_report_file(&f);
    send_dashboard_summary(&f);

    // Concise stdout summary through the logger (no per-event spam).
    log_message("[REPORT] APs:%d Clients:%d | open:%d evil-twin:%d karma:%d "
                "mac-leak:%d deauth:%u%s -> %s\n",
                ap_count, client_count, f.open_networks, f.evil_twins, f.karma,
                f.mac_leaks, total_deauths,
                deauth_flood_active ? " [DEAUTH FLOOD!]" : "", REPORT_FILE);
}

// ----------------------------------------------------------------------------
// Lifecycle
// ----------------------------------------------------------------------------

void tracker_init(void) {
    memset(aps, 0, sizeof(aps));
    memset(clients, 0, sizeof(clients));
    ap_count = client_count = 0;
    total_deauths = deauth_window = 0;
    deauth_flood_active = 0;
    last_flush = time(NULL);
}

void tracker_tick(void) {
    time_t now = time(NULL);
    if (now - last_flush < REPORT_INTERVAL_S) return;

    // Evaluate deauth flood over the elapsed window, then reset the counter.
    deauth_flood_active = (deauth_window >= DEAUTH_FLOOD_THRESH);

    generate_report();

    deauth_window = 0;
    last_flush = now;
}

void tracker_final_report(void) {
    deauth_flood_active = (deauth_window >= DEAUTH_FLOOD_THRESH);
    generate_report();
}
