/**
 * @file rawSocket.h
 * @brief Functions for creating and configuring raw sockets.
 */

#ifndef RAW_SOCKET_H
#define RAW_SOCKET_H

/**
 * @brief Creates a raw socket bound to the specified interface.
 * 
 * This function creates a socket of type SOCK_RAW using the AF_PACKET family,
 * binds it to the specified network interface, and sets the interface to
 * promiscuous mode to capture all traffic.
 * 
 * @param interface_name The name of the network interface (e.g., "eth0", "wlan0").
 * @return int The socket file descriptor on success, or -1 on failure.
 */
int create_raw_socket(const char *interface_name);

#endif // RAW_SOCKET_H
