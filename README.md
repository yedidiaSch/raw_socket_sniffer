# Network Packet Sniffer

![Platform](https://img.shields.io/badge/platform-Linux-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)

A raw socket-based network packet sniffer written in C for Linux, featuring a real-time Python TUI (Text User Interface) dashboard. This tool captures network traffic on a specified interface, parses Ethernet, IP, TCP, and UDP headers, and visualizes the data live.

## Features

- **Raw Socket Capture**: Uses `AF_PACKET` sockets to capture traffic at the lowest level.
- **Multi-Layer Parsing**:
  - **Layer 2 (Data Link)**: Ethernet II (MAC Source/Dest, EtherType).
  - **Layer 3 (Network)**: IPv4 (IP Source/Dest, Protocol).
  - **Layer 4 (Transport)**: TCP (Ports, Flags) & UDP (Ports, Length).
- **Real-Time Dashboard**: A rich terminal UI written in Python that displays:
  - Live packet table.
  - Traffic statistics (Top Talkers, Protocol Distribution).
  - Total data transfer.
- **Modular Design**: Clean separation of concerns with a dedicated `layers/` directory.

## Prerequisites

- **Operating System**: Linux (Kernel with `AF_PACKET` support).
- **C Environment**:
  - GCC or Clang (supporting C11).
  - CMake 3.10 or higher.
- **Python Environment**:
  - Python 3.6+
  - `rich` library (`pip install rich`)
- **Permissions**: Root/Sudo privileges are required to open raw sockets.

## Build & Run

We provide a convenience script to build the C project and launch the dashboard automatically.

1.  **Install Python Dependencies:**
    ```bash
    pip install rich
    ```

2.  **Run the Application:**
    ```bash
    ./build_and_run.sh <interface_name>
    ```
    *If no interface is provided, it defaults to `wlp2s0`.*

### Example
```bash
./build_and_run.sh eth0
```

This script will:
1.  Compile the C Sniffer using CMake.
2.  Start the C Sniffer in the background (requires sudo).
3.  Launch the Python Dashboard in the foreground.

## Project Structure

```
Sniffer/
├── common/           # Utilities, logging, and type definitions
├── core/             # Central packet parsing orchestration
├── layers/           # Protocol implementations (Ethernet, IP, TCP/UDP)
├── python/           # Python Dashboard source code
│   ├── app.py        # Dashboard entry point
│   ├── data_listener.py # UDP listener for C-to-Python communication
│   └── ui_renderer.py   # Rich TUI layout and rendering
├── socket/           # Raw socket creation and management
├── main.c            # Application entry point and argument parsing
├── build_and_run.sh  # Automation script
└── CMakeLists.txt    # Build configuration
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
