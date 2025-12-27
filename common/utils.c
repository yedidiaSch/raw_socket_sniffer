/**
 * @file utils.c
 * @brief Implementation of utility functions.
 */

#include <stdio.h>
#include "utils.h"
#include "logger.h"

/**
 * @brief Prints a MAC address in standard hex notation.
 * 
 * @param msg Label to print before the MAC address.
 * @param mac Pointer to the 6-byte array containing the MAC address.
 */
void print_mac_address(const char* msg, unsigned char* mac) {
    log_message("%s: %02x:%02x:%02x:%02x:%02x:%02x\n", 
           msg, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
