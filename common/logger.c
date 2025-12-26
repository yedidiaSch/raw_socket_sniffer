/**
 * @file logger.c
 * @brief Implementation of logging functions.
 */

#include <stdio.h>
#include "logger.h"

/**
 * @brief Logs a message to stdout.
 * 
 * @param msg The message string to log.
 */
void log_message(const char* msg) {
    printf("[LOG]: %s\n", msg);
}
