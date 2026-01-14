/**
 * @file mmapSniffer.h
 * @brief Zero-Copy Packet Capture Engine using Linux PACKET_MMAP.
 *
 * This module abstracts the complexity of Ring Buffers, mmap, and polling.
 * It provides a simple API to initialize and run a high-performance capture loop.
 */

#ifndef MMAP_SNIFFER_H
#define MMAP_SNIFFER_H

/**
 * @brief Allocates the Ring Buffer in Kernel space and maps it to User space.
 * * Performs the setsockopt(PACKET_RX_RING) and mmap() calls.
 * * @param sock_fd The raw socket file descriptor (must be already bound).
 * @return 0 on success, -1 on failure.
 */
int setup_zero_copy_ring(int sock_fd);

/**
 * @brief Starts the main capture loop (Blocking).
 * * Enters an infinite loop (until keep_running is false) that:
 * 1. Polls the socket for new data.
 * 2. Reads packets directly from the mapped memory (Zero Copy).
 * 3. Dispatches them to the packetParser module.
 * * @param sock_fd The raw socket file descriptor.
 */
void start_zero_copy_capture(int sock_fd);

/**
 * @brief Frees resources and unmaps the memory.
 */
void cleanup_zero_copy_ring(void);

int is_interface_monitor_mode(const char* iface_name);

#endif // MMAP_SNIFFER_H