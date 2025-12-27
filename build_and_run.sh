#!/bin/bash

# Build and Run Script for Sniffer Project

# Default interface
INTERFACE=${1:-wlp2s0}

echo "========================================"
echo "Building Sniffer..."
echo "========================================"

# Create build directory if it doesn't exist
mkdir -p build
cd build

# Configure with CMake
cmake ..

# Build the project
make

# Check if build was successful
if [ $? -eq 0 ]; then
    echo "========================================"
    echo "Build Successful!"
    echo "Running Sniffer and Dashboard on interface: $INTERFACE"
    echo "========================================"
    
    # Go back to project root
    cd ..

    # Refresh sudo credentials to avoid password prompt in background
    sudo -v

    # Start Sniffer in background, silencing output
    echo "Starting Sniffer (Background)..."
    sudo ./build/Sniffer $INTERFACE > /dev/null 2>&1 &
    SNIFFER_PID=$!

    # Ensure Sniffer is killed when script exits
    trap "sudo kill $SNIFFER_PID" EXIT

    # Run the Python Dashboard (Foreground)
    echo "Starting Dashboard..."
    python3 python/app.py
else
    echo "Build failed. Aborting."
    exit 1
fi
