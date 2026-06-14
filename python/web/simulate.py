#!/usr/bin/env python3
"""
simulate.py — feed the dashboard with synthetic UDP traffic.

Lets you test the web GUI (or the rich TUI) WITHOUT root or a WiFi adapter:
it sends the same JSON messages the C sniffer emits to 127.0.0.1:5005 —
beacons/probes (drive the inventory + RSSI chart) and a periodic
security_report with full aps[]/clients[] + findings (drive the threats panel
and authoritative badges).

Usage:
    # terminal 1
    python server.py
    # terminal 2
    python simulate.py
    # open http://127.0.0.1:8080
"""

import json
import random
import socket
import time

ADDR = ("127.0.0.1", 5005)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# (bssid, ssid, channel, base_rssi, encrypted)
APS = [
    ("44:15:24:4A:B1:E0", "Schwartz", 1, -58, True),
    ("8A:15:24:76:F8:61", "Schwartz", 1, -64, True),   # dup SSID (mesh)
    ("DE:AD:BE:EF:00:11", "Schwartz", 6, -70, True),   # different OUI -> evil twin
    ("B0:1F:47:18:D5:0E", "BeFiber1CA3", 2, -80, True),
    ("40:5E:E1:33:33:33", "FreeCafeWifi", 6, -62, False),  # OPEN
    ("10:B6:76:5B:4B:49", "DIRECT-41-HP DeskJet", 11, -55, True),
    ("9C:A3:A9:44:44:44", "", 9, -75, True),           # hidden / karma
]
CLIENTS = [
    ("CC:47:40:39:96:F1", "schwartz", False),   # real MAC -> leak
    ("5E:B0:23:08:CB:CE", "", True),            # randomized, broadcast
    ("9C:A3:A9:18:67:14", "NVR9ca3a9624ee3", False),
]


def jitter(base):
    return max(-95, min(-30, base + random.randint(-4, 4)))


def send(obj):
    sock.sendto(json.dumps(obj).encode(), ADDR)


def send_packets():
    for bssid, ssid, ch, base, enc in APS:
        send({"type": "802.11", "subtype": "BEACON", "src_mac": bssid,
              "dest_mac": "FF:FF:FF:FF:FF:FF",
              "ssid": ssid if ssid else "<HIDDEN>", "channel": ch,
              "signal_dbm": jitter(base), "size": 300, "is_monitor": 1})
    for mac, ssid, rand in CLIENTS:
        send({"type": "802.11", "subtype": "PROBE_REQ", "src_mac": mac,
              "dest_mac": "FF:FF:FF:FF:FF:FF",
              "ssid": ssid if ssid else "[BROADCAST]", "channel": random.randint(1, 11),
              "signal_dbm": jitter(-72), "size": 120, "is_monitor": 1})


def send_security_report(flood):
    aps = []
    for bssid, ssid, ch, base, enc in APS:
        flags = []
        if not enc:
            flags.append("OPEN")
        if ssid == "Schwartz" and bssid.startswith("DE:AD"):
            flags.append("EVIL-TWIN!")
        elif ssid == "Schwartz":
            flags.append("dup-SSID")
        if not ssid:
            flags += ["hidden", "KARMA!"]
        aps.append({"bssid": bssid, "ssid": ssid,
                    "vendor": "demo", "channel": ch,
                    "security": "ENC" if enc else "OPEN",
                    "rssi": base, "beacons": random.randint(5, 50), "flags": flags})
    clients = []
    for mac, ssid, rand in CLIENTS:
        flags = ["rand-MAC"] if rand else (["MAC-LEAK"] if ssid else [])
        clients.append({"mac": mac, "type": "Phone/Laptop", "rssi": -72,
                        "randomized": rand, "probed": [ssid] if ssid else [],
                        "flags": flags})
    findings = [
        "[ALERT] Possible EVIL TWIN: SSID 'Schwartz' on DE:AD:BE:EF:00:11",
        "[WARN]  Open (unencrypted) network 'FreeCafeWifi'",
        "[PRIV]  CC:47:40:39:96:F1 leaks saved networks: schwartz",
    ]
    if flood:
        findings.insert(0, "[ALERT] Deauthentication flood in progress (37 frames last window).")
    send({"msg_type": "security_report",
          "aps": len(aps), "clients": len(clients),
          "deauth_frames": 37 if flood else 0,
          "open_networks": 1, "evil_twins": 1, "mac_leaks": 1, "karma": 1,
          "deauth_sources": 1 if flood else 0, "deauth_flood": flood,
          "findings": findings,
          "ap_inventory": aps, "client_inventory": clients})


def main():
    print(f"Simulating sniffer traffic -> {ADDR[0]}:{ADDR[1]}  (Ctrl+C to stop)")
    tick = 0
    while True:
        send_packets()
        if tick % 16 == 0:                      # ~every 5s at 0.3s cadence
            send_security_report(flood=(tick % 64 == 0))  # flood pulse occasionally
        tick += 1
        time.sleep(0.3)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nstopped")
