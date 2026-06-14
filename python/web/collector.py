"""
collector.py — framework-agnostic state owner for the web dashboard.

It consumes the same UDP/JSON messages the C sniffer already emits (packet
metadata + the periodic security_report) and maintains all derived state:
access-point and client inventories, per-AP RSSI time series, a rolling packet
stream, threat list, and basic managed-mode stats. snapshot() returns a single
JSON-serialisable view that the server pushes to browsers.

No asyncio / FastAPI imports here on purpose — this is pure logic and is unit
testable by feeding dicts to ingest().
"""

import time
from collections import deque, Counter

# --- Tunables (bound memory; matter for busy / public-area capture) ---
AGING_SECONDS = 120     # drop APs/clients not seen for this long
MAX_RSSI_POINTS = 120   # per-AP RSSI history depth
MAX_STREAM = 200        # rolling live packet rows
MAX_CHARTED_APS = 12    # cap RSSI lines / scatter points to stay readable

# Small OUI table mirroring the C tracker; unknown -> shown as hex prefix.
OUI_VENDORS = {
    "10:B6:76": "HP",
    "40:5E:E1": "Hi-Smart/IoT",
    "44:15:24": "ISP-CPE",
    "B0:1F:47": "ISP-CPE",
    "9C:A3:A9": "IoT/Camera",
    "00:17:88": "Philips Hue",
    "EC:FA:BC": "Espressif/IoT",
    "18:FE:34": "Espressif/IoT",
}


def _vendor(mac):
    if not mac or len(mac) < 8:
        return "?"
    return OUI_VENDORS.get(mac[:8].upper(), mac[:8].upper())


def _randomized(mac):
    """Locally-administered bit (bit 1 of the first octet) => randomized MAC."""
    try:
        return bool(int(mac[0:2], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def _add_flag(entry, flag):
    if flag not in entry["flags"]:
        entry["flags"].append(flag)


class Collector:
    def __init__(self):
        self.aps = {}            # bssid -> dict
        self.clients = {}        # mac   -> dict
        self.rssi_series = {}    # bssid -> deque[(t, dbm)]
        self.stream = deque(maxlen=MAX_STREAM)
        self.threats = []
        self.deauth_flood = False
        self.sec_counts = {}     # authoritative counts from the C security_report

        # Authoritative inventory pushed by the C tracker (Phase 6). When fresh,
        # these replace the packet-derived tables (exact vendor, security, and
        # per-device flags). RSSI history is always packet-derived.
        self.c_aps = None
        self.c_clients = None
        self.c_inventory_ts = 0.0

        # Managed-mode stats
        self.proto_counter = Counter()
        self.talkers = Counter()
        self.total_bytes = 0

        self._pkt_times = deque(maxlen=4000)  # timestamps for pkts/sec

    # ------------------------------------------------------------------ ingest
    def ingest(self, msg):
        if not isinstance(msg, dict):
            return
        if msg.get("msg_type") == "security_report":
            self._ingest_security(msg)
        else:
            self._ingest_packet(msg)

    def _ingest_security(self, m):
        keys = ("aps", "clients", "deauth_frames", "open_networks",
                "evil_twins", "mac_leaks", "karma", "deauth_sources")
        self.sec_counts = {k: m.get(k, 0) for k in keys}
        self.deauth_flood = bool(m.get("deauth_flood"))

        sev_tags = {"[ALERT]": "ALERT", "[WARN]": "WARN", "[PRIV]": "PRIV"}
        threats = []
        for f in m.get("findings", []):
            sev = "INFO"
            for tag, name in sev_tags.items():
                if tag in f:
                    sev = name
                    break
            text = f.split("] ", 1)[-1] if "] " in f else f
            threats.append({"sev": sev, "text": text})
        self.threats = threats

        # Authoritative inventory tables (present only with an enriched C build).
        if isinstance(m.get("ap_inventory"), list) and isinstance(m.get("client_inventory"), list):
            self.c_aps = m["ap_inventory"]
            self.c_clients = m["client_inventory"]
            self.c_inventory_ts = time.time()

    def _ingest_packet(self, p):
        now = time.time()
        self._pkt_times.append(now)
        self.total_bytes += int(p.get("size", 0) or 0)

        ptype = p.get("type")
        is_wifi = (ptype == "802.11")

        # Rolling live stream row (compact; formatted client-side)
        self.stream.appendleft({
            "ts": time.strftime("%H:%M:%S", time.localtime(now)),
            "type": ptype, "subtype": p.get("subtype", ""),
            "src": p.get("src_mac") if is_wifi else (p.get("src_ip") or p.get("src_mac")),
            "dst": p.get("dest_mac") if is_wifi else (p.get("dest_ip") or p.get("dest_mac")),
            "ssid": p.get("ssid", ""), "ch": p.get("channel", 0),
            "rssi": p.get("signal_dbm", 0), "size": p.get("size", 0),
            "sport": p.get("src_port", 0), "dport": p.get("dest_port", 0),
        })

        if is_wifi:
            self._ingest_wifi(p, now)
        else:
            self.proto_counter[ptype or "?"] += 1
            src = p.get("src_ip") or p.get("src_mac")
            if src and src != "N/A":
                self.talkers[src] += 1

    def _ingest_wifi(self, p, now):
        sub = p.get("subtype", "")
        mac = p.get("src_mac", "")
        ssid = p.get("ssid", "")
        ch = int(p.get("channel", 0) or 0)
        dbm = int(p.get("signal_dbm", 0) or 0)
        if not mac:
            return

        # The C side sends display markers; recover the "real" SSID.
        named = ssid if ssid and not ssid.startswith("[") and ssid != "<HIDDEN>" else ""
        hidden = ssid == "<HIDDEN>"

        if sub in ("BEACON", "PROBE_RESP"):
            ap = self.aps.get(mac) or {
                "bssid": mac, "ssid": "", "vendor": _vendor(mac),
                "channel": ch, "security": "?", "beacons": 0,
                "flags": [], "first_seen": now,
            }
            if named:
                ap["ssid"] = named
            elif hidden and not ap["ssid"]:
                _add_flag(ap, "hidden")
            if ch:
                ap["channel"] = ch
            ap["rssi"] = dbm
            if sub == "BEACON":
                ap["beacons"] = ap.get("beacons", 0) + 1
            if _randomized(mac):
                _add_flag(ap, "rand-MAC")
            ap["last_seen"] = now
            self.aps[mac] = ap

            series = self.rssi_series.setdefault(mac, deque(maxlen=MAX_RSSI_POINTS))
            series.append((round(now, 1), dbm))

        elif sub == "PROBE_REQ":
            c = self.clients.get(mac) or {
                "mac": mac, "randomized": _randomized(mac),
                "type": "Phone/Laptop", "probed": [], "rssi": dbm,
                "flags": [], "first_seen": now,
            }
            if named and named not in c["probed"]:
                c["probed"].append(named)
                # Real (non-randomized) MAC asking for a named net = privacy leak
                if not c["randomized"]:
                    _add_flag(c, "MAC-LEAK")
            if c["randomized"]:
                _add_flag(c, "rand-MAC")
            c["rssi"] = dbm
            c["last_seen"] = now
            self.clients[mac] = c

        else:
            # DATA / EAPOL / etc.: just refresh liveness of a known device.
            if mac in self.aps:
                self.aps[mac]["last_seen"] = now
            elif mac in self.clients:
                self.clients[mac]["last_seen"] = now

    # ------------------------------------------------------------- maintenance
    def _age(self, now):
        for table in (self.aps, self.clients):
            for key in [k for k, v in table.items()
                        if now - v.get("last_seen", 0) > AGING_SECONDS]:
                table.pop(key, None)
        for key in [k for k in self.rssi_series if k not in self.aps]:
            self.rssi_series.pop(key, None)

    def _pkts_per_sec(self, now):
        while self._pkt_times and now - self._pkt_times[0] > 5:
            self._pkt_times.popleft()
        return sum(1 for t in self._pkt_times if now - t <= 1)

    # ---------------------------------------------------------------- snapshot
    def snapshot(self):
        now = time.time()
        self._age(now)

        # Prefer the C tracker's authoritative inventory when it is recent;
        # otherwise fall back to the packet-derived tables (older C builds).
        use_c = self.c_aps is not None and (now - self.c_inventory_ts) < 30
        if use_c:
            aps = sorted(self.c_aps, key=lambda a: a.get("rssi", -999), reverse=True)
            clients = sorted(self.c_clients, key=lambda c: c.get("rssi", -999), reverse=True)
        else:
            aps = sorted(self.aps.values(),
                         key=lambda a: a.get("rssi", -999), reverse=True)
            clients = sorted(self.clients.values(),
                             key=lambda c: c.get("rssi", -999), reverse=True)

        top = aps[:MAX_CHARTED_APS]
        series = {}
        for a in top:
            pts = list(self.rssi_series.get(a["bssid"], []))
            if pts:
                series[a["bssid"]] = {"ssid": a.get("ssid") or a["bssid"], "points": pts}
        scatter = [{
            "bssid": a["bssid"], "ssid": a.get("ssid") or "<hidden>",
            "channel": a.get("channel", 0), "rssi": a.get("rssi", 0),
            "security": a.get("security", "?"),
        } for a in top if a.get("channel")]

        kpis = {
            "aps": len(aps),
            "clients": len(clients),
            "threats": len(self.threats),
            "deauth_frames": self.sec_counts.get("deauth_frames", 0),
            "deauth_flood": self.deauth_flood,
            "pkts_per_sec": self._pkts_per_sec(now),
            "total_kb": round(self.total_bytes / 1024, 1),
        }

        return {
            "kpis": kpis,
            "aps": aps,
            "clients": clients,
            "rssi_series": series,
            "channel_scatter": scatter,
            "threats": self.threats,
            "protocols": self.proto_counter.most_common(8),
            "talkers": self.talkers.most_common(8),
            "stream": list(self.stream),
        }
