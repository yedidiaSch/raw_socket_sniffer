/**
 * @file logger.h
 * @brief Thread-safe logging utility functions.
 */

#ifndef LOGGER_H
#define LOGGER_H

/**
 * @brief Initializes the logger thread.
 * 
 * Starts a background thread that consumes messages from the log queue
 * and prints them to stdout.
 */
void init_logger();

/**
 * @brief Cleans up logger resources and stops the thread.
 * 
 * Waits for the queue to empty before stopping.
 */
void cleanup_logger();

/**
 * @brief Logs a formatted message to the queue.
 * 
 * This function is thread-safe and non-blocking (unless queue is full, 
 * though currently implemented as a linked list).
 * 
 * @param fmt Format string (printf-style).
 * @param ... Arguments for the format string.
 */
void log_message(const char* fmt, ...);

#endif // LOGGER_H
