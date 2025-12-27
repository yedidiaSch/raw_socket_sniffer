# Network Packet Sniffer

![Platform](https://img.shields.io/badge/platform-Linux-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)

A raw socket-based network packet sniffer written in C for Linux. This tool captures network traffic on a specified interface and parses Ethernet, IP, TCP, and UDP headers.

## Features

- **Raw Socket Capture**: Uses `AF_PACKET` sockets to capture traffic at the lowest level.
- **Multi-Layer Parsing**:
  - **Layer 2 (Data Link)**: Ethernet II (MAC Source/Dest, EtherType).
  - **Layer 3 (Network)**: IPv4 (IP Source/Dest, Protocol).
  - **Layer 4 (Transport)**: TCP (Ports, Flags) & UDP (Ports, Length).
- **Modular Design**: Clean separation of concerns with a dedicated `layers/` directory.
- **Logging**: Integrated logging system for packet details and application status.

## Prerequisites

- **Operating System**: Linux (Kernel with `AF_PACKET` support).
- **Compiler**: GCC or Clang (supporting C11).
- **Build System**: CMake 3.10 or higher.
- **Permissions**: Root/Sudo privileges are required to open raw sockets.

## Build Instructions

The project uses CMake for building.

1.  **Create a build directory:**
    ```bash
    mkdir -p build
    cd build
    ```

2.  **Configure the project:**
    ```bash
    cmake ..
    ```

3.  **Build the executable:**
    ```bash
    make
    ```

## Usage

The application requires the network interface name as a command-line argument.

```bash
sudo ./Sniffer <interface_name>
```

### Examples

Capture packets on the `eth0` interface:
```bash
sudo ./Sniffer eth0
```

Capture packets on the wireless interface (e.g., `wlp2s0`):
```bash
sudo ./Sniffer wlp2s0
```

*Note: You can find your available network interfaces using the `ip link` or `ifconfig` command.*

## Project Structure

```
Sniffer/
├── common/           # Utilities, logging, and type definitions
├── core/             # Central packet parsing orchestration
├── layers/           # Protocol implementations (Ethernet, IP, TCP/UDP)
├── socket/           # Raw socket creation and management
├── main.c            # Application entry point and argument parsing
└── CMakeLists.txt    # Build configuration
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
