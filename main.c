/**
 * @file main.c
 * @brief Entry point for the Network Packet Sniffer application.
 *
 * This file contains the main function which initializes the raw socket,
 * sets up signal handling for graceful shutdown, and enters the main
 * packet capture loop.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include "rawSocket.h"
#include "packetParser.h"
#include "Types.h"

/**
 * @brief Global flag to control the main loop execution.
 * 
 * Modified by the signal handler to initiate graceful shutdown.
 */
volatile int keep_running = 1;

/**
 * @brief Signal handler for handling interrupts (e.g., Ctrl+C).
 * 
 * @param signal The signal number received.
 */
void handle_signal(int signal);

/**
 * @brief Main entry point of the application.
 * 
 * Initializes the sniffer, creates a raw socket, and continuously
 * captures and processes packets until a termination signal is received.
 * 
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return int Exit status code (0 for success, 1 for failure).
 */
int main(int argc, char** argv)
{
    (void)argc; // Unused parameter
    (void)argv; // Unused parameter

    printf("Sniffer started on %s\n", interface);

    // Setup signal handling (graceful shutdown)
    signal(SIGINT, handle_signal);
    
    int sock_fd = create_raw_socket(interface);

    // print the sock fd
    printf("Socket FD: %d\n", sock_fd);

    if (sock_fd == -1) 
    {
        return 1;
    }

    // Prepare buffer for incoming packets
    unsigned char buffer[BUFFER_SIZE];
    int data_size;

    printf("Sniffer started on %s. Press Ctrl+C to stop.\n", interface);

    // The Infinite Loop
    while (keep_running) {
        // A. Receive packet (Blocking call - waits for data)
        data_size = recvfrom(sock_fd, buffer, BUFFER_SIZE, 0, NULL, NULL);
        
        if (data_size < 0) {
            perror("Recvfrom error, failed to get packets");
            // Usually we don't exit here, just try again, 
            // unless it's a critical error.
            continue; 
        }
        else {
            // Packet received successfully
            process_packet(buffer, data_size);
        }

        // B. Process packet (Placeholder for next step)
        // Here we will call: process_packet(buffer, data_size);
        printf("Received packet of size: %d bytes\n", data_size);
    }

    // Cleanup
    close(sock_fd);
    printf("Sniffer stopped. Socket closed.\n");

    return 0;
}

/**
 * @brief Handles system signals to ensure graceful shutdown.
 * 
 * Sets the global keep_running flag to 0 when SIGINT is received.
 * 
 * @param signal The signal number caught.
 */
void handle_signal(int signal) {
    if (signal == SIGINT) {
        printf("\nCaught signal, stopping sniffer...\n");
        keep_running = 0;
    }
}
