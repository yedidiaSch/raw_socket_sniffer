#!/bin/bash

# Build and Run Script for Sniffer Project (Airmon-ng Version)

# Default interface
BASE_INTERFACE=${1:-wlp2s0}
SNIFFER_PID=""
HOPPER_PID=""  # Initialize variable

# --- Step 1: Ask User for Mode ---
echo "========================================"
echo "Select Operation Mode:"
echo "1) Managed Mode (Normal)"
echo "   - Uses $BASE_INTERFACE"
echo "   - Keeps internet connection."
echo "2) Monitor Mode (Hacker Mode)"
echo "   - Uses airmon-ng to enable Monitor Mode"
echo "   - Kills WiFi connection."
echo "========================================"
read -p "Enter choice [1 or 2]: " MODE_CHOICE

# --- Step 1b: Ask User for Dashboard ---
echo "========================================"
echo "Select Dashboard:"
echo "1) Web Dashboard (browser, live charts) [default]"
echo "2) Terminal TUI (rich)"
echo "========================================"
read -p "Enter choice [1 or 2]: " DASH_CHOICE

# --- Step 2: Build ---
echo "Building Sniffer..."
mkdir -p build && cd build && cmake .. && make
if [ $? -ne 0 ]; then echo "Build failed."; exit 1; fi
cd ..
sudo -v # Refresh sudo

# --- Step 2b: Web Dashboard Environment (one-time venv + deps) ---
if [ "$DASH_CHOICE" != "2" ]; then
    echo "Preparing web dashboard environment..."
    if [ ! -d python/web/.venv ]; then
        python3 -m venv python/web/.venv || { echo "venv creation failed."; exit 1; }
    fi
    python/web/.venv/bin/pip install -q -r python/web/requirements.txt \
        || { echo "Dashboard dependency install failed (offline?)."; exit 1; }
fi

# --- Step 3: Execution Logic ---

if [ "$MODE_CHOICE" == "2" ]; then
    # ==========================================
    # OPTION 2: MONITOR MODE (via Airmon-ng)
    # ==========================================
    echo "[*] Setting up Monitor Mode with airmon-ng..."

    # 1. Kill interfering processes
    sudo airmon-ng check kill > /dev/null 2>&1

    # 2. Start Monitor Mode
    echo "[*] Activating monitor on $BASE_INTERFACE..."
    sudo airmon-ng start $BASE_INTERFACE > /dev/null 2>&1

    # 3. Detect the NEW interface name (e.g., wlan0mon)
    MON_INTERFACE=$(iw dev | grep Interface | awk '{print $2}' | grep "mon" | head -n 1)
    
    # Fallback if detection failed, try adding 'mon' to base
    if [ -z "$MON_INTERFACE" ]; then
        MON_INTERFACE="${BASE_INTERFACE}mon"
    fi

    echo "[V] Monitor Interface Detected: $MON_INTERFACE"

    # Define Cleanup Function
    function cleanup {
        echo ""
        echo "[!] Stopping Monitor Mode..."
        if [ ! -z "$SNIFFER_PID" ]; then sudo kill $SNIFFER_PID 2>/dev/null; fi
        
        # Only kill hopper if it was started
        if [ ! -z "$HOPPER_PID" ]; then sudo kill $HOPPER_PID 2>/dev/null; fi

        # Stop airmon-ng interface
        sudo airmon-ng stop $MON_INTERFACE > /dev/null 2>&1
        
        # Restart Network Manager
        echo "[*] Restarting Network Services..."
        sudo systemctl start NetworkManager
        sudo systemctl start wpa_supplicant 2>/dev/null
        
        if [ -f sniffer.log ]; then sudo chown $USER:$USER sniffer.log; fi
        echo "[V] Internet restored."
    }
    trap cleanup EXIT

    # --- FIXED CHANNEL CONFIGURATION (FOR HANDSHAKE CAPTURE) ---
    #echo "[*] Locking interface to Channel 11..."
    #sudo iw dev $MON_INTERFACE set channel 11

    # --- OLD CHANNEL HOPPER (COMMENTED OUT) ---
    echo "[*] Starting Channel Hopper on $MON_INTERFACE..."
    (
        while true; do
            for channel in {1..13}; do
                sudo iw dev $MON_INTERFACE set channel $channel 2>/dev/null
                sleep 0.1
            done
        done
    ) &
    HOPPER_PID=$!

    # Set interface variable for the sniffer
    CURRENT_INTERFACE=$MON_INTERFACE

else
    # ==========================================
    # OPTION 1: MANAGED MODE
    # ==========================================
    echo "[*] Using Managed Mode on $BASE_INTERFACE..."
    CURRENT_INTERFACE=$BASE_INTERFACE
    
    function cleanup {
        echo "[!] Shutting down..."
        if [ ! -z "$SNIFFER_PID" ]; then sudo kill $SNIFFER_PID 2>/dev/null; fi
        if [ -f sniffer.log ]; then sudo chown $USER:$USER sniffer.log; fi
    }
    trap cleanup EXIT
fi

# --- Step 4: Run Application ---

echo "Starting Sniffer on $CURRENT_INTERFACE..."
echo "Logs -> sniffer.log"

# Run Sniffer with Output Redirection
sudo ./build/Sniffer $CURRENT_INTERFACE > sniffer.log 2>&1 &
SNIFFER_PID=$!

# --- Launch the chosen dashboard (foreground; Ctrl+C triggers cleanup) ---
# Only one consumer can bind UDP 5005, so we run exactly one dashboard.
if [ "$DASH_CHOICE" == "2" ]; then
    echo "Starting Terminal Dashboard (TUI)..."
    python3 python/app.py
else
    DASH_URL="http://127.0.0.1:8080"
    echo "Starting Web Dashboard -> $DASH_URL  (Ctrl+C to stop)"
    # Open the browser shortly after the server comes up.
    ( sleep 2; xdg-open "$DASH_URL" >/dev/null 2>&1 || true ) &
    python/web/.venv/bin/python python/web/server.py
fi