/**
 * @file main.c
 * @brief High-performance entry point for the Network Packet Sniffer.
 */

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>     
#include <sys/socket.h>
#include <net/ethernet.h>

#include "rawSocket.h"
#include "packetParser.h"
#include "Types.h"
#include "logger.h"

// Atomic flag for signal handling
volatile sig_atomic_t keep_running = 1;

void handle_signal(int signal) {
    (void)signal;
    keep_running = 0;
}

int main(int argc, char** argv)
{
    // Disable stdout buffering for immediate logs (Debug mode)
    setbuf(stdout, NULL); 
    
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    const char* interface = argv[1];

    // 1. Initialize Subsystems
    init_logger();
    
    // 2. Setup Signal Handling
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = &handle_signal;
    sigaction(SIGINT, &sa, NULL); 
    sigaction(SIGTERM, &sa, NULL);

    log_message("[INFO] Sniffer initializing on interface: %s\n", interface);

    // 3. Create Raw Socket (Enables Promiscuous Mode)
    int sock_fd = create_raw_socket(interface);
    if (sock_fd == -1) {
        log_message("[ERROR] Failed to create raw socket. Are you root?\n");
        cleanup_logger();
        return 1;
    }

    log_message("[INFO] Socket created (FD: %d). Listening...\n", sock_fd);

    unsigned char buffer[BUFFER_SIZE]; 
    ssize_t data_size;

    // 4. Main Capture Loop
    while (keep_running) {
        data_size = recvfrom(sock_fd, buffer, BUFFER_SIZE, 0, NULL, NULL);
        
        if (data_size < 0) {
            continue; // Interrupted system call
        }

        // Sanity Check: Ignore incomplete packets
        if (data_size < (ssize_t)sizeof(struct ether_header)) {
            continue;
        }

        // Process the valid packet
        process_packet(buffer, data_size);
    }

    // 5. Graceful Shutdown & Cleanup
    log_message("[INFO] Shutdown signal received. Cleaning up...\n");
    
    // NEW: Use the smart close function to disable Promiscuous mode
    close_raw_socket(sock_fd, interface);
    
    cleanup_logger();
    
    printf("Sniffer stopped successfully. Interface restored.\n");
    return 0;
}