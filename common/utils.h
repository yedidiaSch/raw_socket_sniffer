/**
 * @file utils.h
 * @brief Utility functions for the sniffer application.
 */

#ifndef UTILS_H
#define UTILS_H

/**
 * @brief Prints a MAC address in a human-readable format.
 * 
 * Formats the MAC address as XX:XX:XX:XX:XX:XX.
 * 
 * @param msg A descriptive message to print before the address.
 * @param mac Pointer to the 6-byte MAC address array.
 */
void print_mac_address(const char* msg, unsigned char* mac);

#endif // UTILS_H
