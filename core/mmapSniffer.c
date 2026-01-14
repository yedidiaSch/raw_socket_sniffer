/**
 * @file mmapSniffer.c
 * @brief Implementation of the Zero-Copy engine.
 */

#include "mmapSniffer.h"
#include "packetParser.h" // The dispatcher we created earlier
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <poll.h>
#include <errno.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <net/if.h>

// Global flag from main.c to control the loop
extern volatile int keep_running;

// --- Private Context (Encapsulated) ---
// These variables are static so they are hidden from other files.
static struct {
    char *buffer_start;     // The pointer to the shared memory
    size_t total_size;      // Total size of the ring
    struct tpacket_req req; // Kernel configuration struct
} ring_ctx;


/**
 * @brief Probes the kernel to check if interface creates Radiotap headers.
 * This is robust and doesn't rely on the interface name.
 */
int is_interface_monitor_mode(const char* iface_name) {
    int temp_sock = socket(AF_INET, SOCK_DGRAM, 0); 
    if (temp_sock < 0) return 0; // Fallback

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ - 1);

    
    if (ioctl(temp_sock, SIOCGIFHWADDR, &ifr) == -1) {
        close(temp_sock);
        return 0;
    }

    close(temp_sock);

    // 803 = Radiotap (WIFI Monitor)
    // 1 = Ethernet
    return (ifr.ifr_hwaddr.sa_family == ARPHRD_IEEE80211_RADIOTAP);
}


int setup_zero_copy_ring(int sock_fd) {
    // 0. Set TPACKET_V2 (required for tpacket2_hdr and tp_mac)
    int version = TPACKET_V2;
    if (setsockopt(sock_fd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)) < 0) {
        perror("[ERROR] setsockopt PACKET_VERSION failed");
        return -1;
    }

    // 1. Determine optimal block size (Page Aligned)
    unsigned int block_size = getpagesize(); // Typically 4096 bytes
    unsigned int frame_size = 2048;          // Max packet size + headers
    
    // Ensure block size is large enough to hold frames
    while (block_size < frame_size) {
        block_size <<= 1;
    }

    // 2. Configure Ring Buffer Parameters
    memset(&ring_ctx.req, 0, sizeof(ring_ctx.req));
    ring_ctx.req.tp_block_size = block_size;
    ring_ctx.req.tp_frame_size = frame_size;
    ring_ctx.req.tp_block_nr   = 64; // Number of blocks (Depth of buffer)
    
    // Calculate frame count: (BlockSize * BlockCount) / FrameSize
    ring_ctx.req.tp_frame_nr = (ring_ctx.req.tp_block_size * ring_ctx.req.tp_block_nr) / ring_ctx.req.tp_frame_size;

    // 3. Request the Ring from Kernel
    if (setsockopt(sock_fd, SOL_PACKET, PACKET_RX_RING, &ring_ctx.req, sizeof(ring_ctx.req)) < 0) {
        perror("[ERROR] setsockopt PACKET_RX_RING failed");
        return -1;
    }

    // 4. Map Memory (The "Zero Copy" Step)
    ring_ctx.total_size = ring_ctx.req.tp_block_nr * ring_ctx.req.tp_block_size;
    
    ring_ctx.buffer_start = mmap(NULL, ring_ctx.total_size, 
                                 PROT_READ | PROT_WRITE, MAP_SHARED, sock_fd, 0);

    if (ring_ctx.buffer_start == MAP_FAILED) {
        perror("[ERROR] mmap failed");
        return -1;
    }

    log_message("[INFO] Zero-Copy Ring Initialized. Frames: %d, Total Memory: %lu bytes\n", 
                ring_ctx.req.tp_frame_nr, ring_ctx.total_size);
    
    return 0;
}

void start_zero_copy_capture(int sock_fd) {
    unsigned int frame_idx = 0;
    struct tpacket2_hdr *header;
    struct pollfd pfd;

    // Setup polling
    pfd.fd = sock_fd;
    pfd.events = POLLIN;

    log_message("[INFO] Starting High-Performance Capture Loop...\n");

    while (keep_running) {
        // Compute pointer to the current frame header
        header = (struct tpacket2_hdr *)(ring_ctx.buffer_start + (frame_idx * ring_ctx.req.tp_frame_size));

        // --- POLLING: Wait for the Kernel to give us data ---
        // Check Status Bit: If TP_STATUS_USER (1) is NOT set, the frame belongs to Kernel.
        if ((header->tp_status & TP_STATUS_USER) == 0) {
            // No data ready. Sleep efficiently.
            int ret = poll(&pfd, 1, 100); // 100ms timeout
            if (ret < 0) {
                if (errno == EINTR) continue; // Interrupted by signal (Ctrl+C)
                break; // Real error
            }
            continue;
        }

        // --- PROCESSING: Data is ready in User Space ---
        
        // Safety check for packet loss
        if (header->tp_status & TP_STATUS_LOSING) {
             log_message("[WARN] Ring Buffer Full - Packet Dropped by Kernel\n");
        }
        
        // Get pointer to the actual packet data
        // header->tp_mac is the offset to the MAC header
        unsigned char *packet_ptr = (unsigned char *)header + header->tp_mac;
        
        // Dispatch to our parser (The "Traffic Cop")
        // Note: tp_snaplen is the captured length
        process_packet(packet_ptr, header->tp_snaplen);

        // --- HANDSHAKE: Return Frame to Kernel ---
        header->tp_status = TP_STATUS_KERNEL;
        
        // Advance Ring Pointer
        frame_idx = (frame_idx + 1) % ring_ctx.req.tp_frame_nr;
    }
}

void cleanup_zero_copy_ring(void) {
    if (ring_ctx.buffer_start) {
        munmap(ring_ctx.buffer_start, ring_ctx.total_size);
        ring_ctx.buffer_start = NULL;
        log_message("[INFO] Ring Buffer Unmapped. Memory freed.\n");
    }
}