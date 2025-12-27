/**
 * @file logger.h
 * @brief Thread-safe logging utility functions.
 */

#ifndef LOGGER_H
#define LOGGER_H

#include "Types.h"

/**
 * @brief Initializes the logger thread and UDP sender.
 * 
 * Starts a background thread that consumes messages from the log queue
 * and prints them to stdout. Also initializes UDP sender.
 */
void init_logger();

/**
 * @brief Cleans up logger resources and stops the thread.
 * 
 * Waits for the queue to empty before stopping.
 */
void cleanup_logger();

/**
 * @brief Logs a formatted message to the queue (Text logging).
 * 
 * This function is thread-safe and non-blocking.
 * 
 * @param fmt Format string (printf-style).
 * @param ... Arguments for the format string.
 */
void log_message(const char* fmt, ...);

/**
 * @brief Logs a packet metadata struct via UDP.
 * 
 * This function pushes the metadata to a queue (or sends directly if non-blocking).
 * For simplicity and performance, we might send directly or queue it.
 * Given the user request "use it in the logger", we'll queue it to be safe/consistent.
 * 
 * @param meta Pointer to the metadata struct.
 */
void log_packet(const PacketMetadata* meta);

#endif // LOGGER_H
