#include "rawSocket.h"
#include "mmapSniffer.h" // <--- The new API
#include "packetParser.h"
#include "logger.h"
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>

// Global flag
volatile int keep_running = 1;

void handle_signal(int signal) {
    (void)signal;
    keep_running = 0;
}

int main(int argc, char** argv) {
    // Disable stdout buffering for immediate log output
    setbuf(stdout, NULL);
    
    if (argc != 2) {
        printf("Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    init_logger();
    signal(SIGINT, handle_signal);

    const char* interface = argv[1];
    
    // Detect monitor mode using Kernel IOCTL (Robust)
    int is_monitor = is_interface_monitor_mode(interface);
    set_monitor_mode(is_monitor);
    
    log_message("[INFO] Initializing Sniffer on %s (%s mode)...\n", 
                interface, is_monitor ? "Monitor" : "Managed");

    // 1. Create Socket (Standard)
    int sock_fd = create_raw_socket(interface);
    if (sock_fd == -1) return 1;

    // 2. Setup Zero-Copy Engine
    if (setup_zero_copy_ring(sock_fd) != 0) {
        close_raw_socket(sock_fd, interface);
        return 1;
    }

    // 3. Start The Loop (Blocking)
    start_zero_copy_capture(sock_fd);

    // 4. Cleanup
    cleanup_zero_copy_ring();
    close_raw_socket(sock_fd, interface);
    cleanup_logger();

    printf("Sniffer stopped gracefully.\n");
    return 0;
}