#include "rawSocket.h"
#include "mmapSniffer.h" // <--- The new API
#include "packetParser.h"
#include "logger.h"
#include "deviceTracker.h"
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>

// Global flag. sig_atomic_t is the only type the C standard guarantees can be
// written safely from within a signal handler.
volatile sig_atomic_t keep_running = 1;

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

    // Handle both Ctrl+C (SIGINT) and `kill` (SIGTERM) so the capture loop
    // exits cleanly: promiscuous mode is restored, the ring is unmapped, and
    // the logger thread is joined. sigaction gives reliable, portable
    // semantics (no SysV one-shot reset). SA_RESTART is deliberately omitted
    // so the blocking poll() returns EINTR and the loop can check the flag.
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    const char* interface = argv[1];
    
    // Detect monitor mode using Kernel IOCTL (Robust)
    int is_monitor = is_interface_monitor_mode(interface);
    set_monitor_mode(is_monitor);

    // Stateful WiFi device inventory + security analysis (monitor mode).
    tracker_init();
    
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

    // 4. Final security report (capture loop has exited, so no concurrency).
    //    Logger is still running here so the summary line is delivered.
    if (is_monitor) {
        tracker_final_report();
    }

    // 5. Cleanup
    cleanup_zero_copy_ring();
    close_raw_socket(sock_fd, interface);
    cleanup_logger();

    printf("Sniffer stopped gracefully.\n");
    return 0;
}