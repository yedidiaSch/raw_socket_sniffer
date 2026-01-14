### Network Packet Sniffer & WiFi Diagnostic Tool

![Platform](https://img.shields.io/badge/platform-Linux-green.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

A high-performance, raw socket-based network analyzer written in C for Linux, paired with a real-time Python TUI (Text User Interface) dashboard.

This tool provides deep visibility into network traffic, featuring advanced parsing capabilities for both standard Ethernet/IP traffic and raw 802.11 WiFi frames, including support for variable-length Radiotap headers found in modern drivers.

##  Key Features

###  Wireless Analysis (Monitor Mode)
- **Dynamic Radiotap Parsing:** Robust handling of variable-length Radiotap headers (26/38/50 bytes), ensuring compatibility across various WiFi chipsets.
- **Management Frame Analysis:**
  - Real-time visualization of Beacons and SSIDs.
  - **Probe Request Logging:** Analysis of active scanning behavior by nearby devices.
- ** Protocol Inspection:** Detection and logging of **EAPOL frames** and authentication sequences (Key Exchanges) for security auditing and troubleshooting.
- **Signal Telemetry:** Live RSSI (Signal Strength) monitoring per device.

###  Traffic Analysis (Managed Mode)
- **Full Stack Parsing:** Ethernet II, IP (v4/v6), TCP, and UDP.
- **Network Stats:** Real-time tracking of top talkers, bandwidth usage, and protocol distribution.

###  Performance & Architecture
- **Zero-Copy Capture (MMAP):** Implementation of Linux `PACKET_MMAP` (RX_RING) with `TPACKET_V2` to map kernel buffers directly into user space. This drastically reduces CPU usage and packet drops by eliminating the overhead of copying packets from kernel to user memory (standard `recv()` calls).

###  Dashboard
- **Rich TUI:** A lightweight, non-blocking terminal interface utilizing the `rich` library.
- **Live Stream:** Color-coded packet log for instant protocol identification (Green=Mgmt, Yellow=Control, Red=Auth, Blue=Data).

##  Prerequisites

- **Operating System**: Linux (Kernel with `AF_PACKET` support).
- **Hardware**: WiFi Adapter supporting Monitor Mode (required for 802.11 analysis).
- **System Tools**:
  - `gcc`, `cmake`, `make`
  - `aircrack-ng` suite (specifically `airmon-ng` for interface management).
- **Python**:
  - Python 3.6+
  - `rich` library.

### Installation

1.  **Install System Dependencies:**
    ```bash
    sudo apt update
    sudo apt install build-essential cmake aircrack-ng python3-pip
    ```

2.  **Install Python Libraries:**
    ```bash
    pip install rich
    ```

##  Usage

Use the provided automation script to handle build, interface configuration, and execution.

1.  **Make the script executable:**
    ```bash
    chmod +x build_and_run.sh
    ```

2.  **Run the Tool:**
    ```bash
    ./build_and_run.sh
    ```

### Operation Modes:

* **1) Managed Mode (Standard):**
    * Analyzes traffic on the existing connection.
    * Ideal for debugging TCP/UDP streams and bandwidth monitoring.
    * Preserves internet connectivity.

* **2) Monitor Mode (Advanced Analysis):**
    * Switches the interface to RFMON (Monitor) mode.
    * Enables capture of raw 802.11 management and control frames.
    * **Note:** This mode disconnects the active WiFi session.
    * *Channel Locking:* To analyze specific exchanges (e.g., EAPOL), manual channel locking via `iw` is recommended over the default hopping behavior.

##  Project Structure

```text
Sniffer/
├── src/              # C Backend
│   ├── main.c        # Entry point & socket handling
│   ├── packetParser.c# Protocol decoding logic
│   ├── logger.c      # Thread-safe logging queue
│   ├── udp_sender.c  # IPC (Inter-Process Communication)
│   └── ...
├── include/          # Header definitions
├── python/           # Python Frontend
│   ├── main.py       # Dashboard entry point
│   ├── data_listener.py # UDP receiver & aggregator
│   └── ui_renderer.py   # UI rendering logic
├── build/            # Compilation artifacts
├── build_and_run.sh            # Automation script
└── CMakeLists.txt    # Build configuration
```

## ⚠️ Disclaimer

This tool is designed for educational purposes, network troubleshooting, and security research. The authors are not responsible for any misuse. Ensure you have permission to analyze the network traffic you are capturing.

## License

This project is licensed under the MIT License.
