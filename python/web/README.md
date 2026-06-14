# WiFi Analyzer — Web Dashboard

A browser-based dashboard for the C sniffer. It consumes the same UDP/JSON
stream the sniffer already emits and shows live charts, device inventory, and
security findings.

```
C sniffer ──UDP/JSON :5005──▶ FastAPI bridge ──WebSocket──▶ browser
```

## Features
- **Real-time charts** — RSSI-over-time per AP, channel × signal scatter
- **Device inventory** — sortable / filterable Access-Point and Client tables
- **Threats** — evil-twin, open networks, karma, deauth flood, MAC leaks
  (color-coded by severity, driven by the C `security_report`)
- **Live packet stream** and KPI header

## Setup
```bash
cd python/web
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run
Start the sniffer (as root) on your interface, then:
```bash
cd python/web
source .venv/bin/activate
python server.py          # serves http://127.0.0.1:8080
```
Open <http://127.0.0.1:8080>.

To view from another device / phone on your LAN, bind all interfaces
(exposes the dashboard on your network — opt-in):
```bash
uvicorn server:app --host 0.0.0.0 --port 8080
```

## Notes
- Only **one** consumer can bind UDP `5005` at a time — run *either* the rich
  TUI (`python/app.py`) *or* this web dashboard, not both.
- The dashboard process does **not** need root.
- Memory is bounded (entry aging + caps) so it is safe for busy / public-area
  captures.
- Per-AP `security` (open vs encrypted), vendor, and per-device flag badges are
  **authoritative** — the C `security_report` carries the full AP/client tables.
  If an older C build sends only counts, the dashboard falls back to values
  derived from the packet stream. RSSI history (the time chart) is always
  packet-derived.
