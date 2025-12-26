# Network Packet Sniffer

A raw socket-based network packet sniffer written in C for Linux. This tool captures network traffic on a specified interface and parses Ethernet, IP, TCP, and UDP headers.

## Features

- **Raw Socket Capture**: Uses `AF_PACKET` sockets to capture traffic at the lowest level.
- **Multi-Layer Parsing**:
  - **Layer 2 (Ethernet)**: MAC addresses and EtherType.
  - **Layer 3 (IP)**: Source/Destination IP addresses and Protocol.
  - **Layer 4 (Transport)**: TCP (Ports, Flags) and UDP (Ports, Length).
- **Modular Design**: Separate modules for each network layer.
- **CMake Build System**: Easy to build and extend.

## Prerequisites

- **OS**: Linux (requires `AF_PACKET` support).
- **Compiler**: GCC or Clang (C11 support).
- **Build System**: CMake (3.10+).
- **Privileges**: Root/Sudo access is required to open raw sockets.

## Build and Run

The project uses CMake. A convenience target `run` is provided to build and execute in one step.

### 1. Build and Run (Recommended)

```bash
mkdir -p build
cd build
cmake ..
sudo make run
```

*Note: `sudo` is usually required for raw socket permissions.*

### 2. Manual Build

```bash
mkdir -p build
cd build
cmake ..
make
```

Then run the executable:
```bash
sudo ./Sniffer
```

## Configuration

The network interface is currently set in `main.c`.
Default: `wlp2s0`

To change it, edit `main.c`:
```c
const char* interface = "eth0"; // Change to your interface
```

## Project Structure

```
Sniffer/
├── main.c              # Entry point and main loop
├── rawSocket.c         # Raw socket creation and configuration
├── packetParser.c      # Central orchestrator for packet parsing
├── ethernetLayer.c     # Layer 2 parsing logic
├── networkLayer.c      # Layer 3 (IP) parsing logic
├── transportLayer.c    # Layer 4 (TCP/UDP) parsing logic
├── utils.c             # Helper functions (e.g., MAC printing)
├── Types.h             # Common type definitions
└── CMakeLists.txt      # Build configuration
```
