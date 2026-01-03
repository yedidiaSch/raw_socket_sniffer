#ifndef RAWSOCKET_H
#define RAWSOCKET_H

/**
 * @brief Creates a raw socket and binds it to the specified interface.
 * Enables Promiscuous mode.
 */
int create_raw_socket(const char *interface_name);

/**
 * @brief Closes the socket and disables Promiscuous mode.
 * Crucial for restoring the network interface to its normal state.
 */
void close_raw_socket(int sock_fd, const char *interface_name);

#endif // RAWSOCKET_H