/**
 * @file logger.c
 * @brief Thread-safe logging implementation.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <pthread.h>
#include <time.h>
#include "logger.h"
#include "udp_sender.h"

// --- Queue Structure ---
typedef enum {
    LOG_TYPE_TEXT,
    LOG_TYPE_PACKET
} LogType;

typedef struct LogNode {
    LogType type;
    char* message;          // For standard text messages
    PacketMetadata packet;  // For network packet metadata
    struct LogNode* next;
} LogNode;

static LogNode* head = NULL;
static LogNode* tail = NULL;

// Bound the queue: the capture loop can outpace the logger thread under load,
// so an unbounded queue grows until OOM. New items are dropped when full and
// the dropped count is reported periodically.
#define LOGGER_QUEUE_MAX 10000
static size_t queue_len = 0;
static unsigned long dropped_count = 0;
static time_t last_drop_report = 0;

// --- Synchronization ---
static pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;
static pthread_t logger_thread;
static volatile int logger_running = 0;

/**
 * @brief Main loop of the Logger Thread.
 */
static void* logger_worker(void* arg) {
    (void)arg;
    while (1) {
        pthread_mutex_lock(&queue_mutex);

        // Wait for data or shutdown signal
        while (head == NULL && logger_running) {
            pthread_cond_wait(&queue_cond, &queue_mutex);
        }

        // Exit if shutdown requested and queue is empty
        if (!logger_running && head == NULL) {
            pthread_mutex_unlock(&queue_mutex);
            break;
        }

        // Dequeue an item
        LogNode* node = head;
        head = node->next;
        if (head == NULL) {
            tail = NULL;
        }
        if (queue_len > 0) queue_len--;

        pthread_mutex_unlock(&queue_mutex);

        // Process the message (outside the lock)
        if (node) {
            if (node->type == LOG_TYPE_TEXT) {
                printf("%s", node->message); 
                free(node->message);
            } else if (node->type == LOG_TYPE_PACKET) {
                // Call function from udp_sender.c
                send_udp_metadata(&node->packet);
            }
            free(node);
        }
    }
    return NULL;
}

void init_logger() {
    if (logger_running) return;
    
    // Initialize UDP sender
    init_udp_sender("127.0.0.1", DASHBOARD_UDP_PORT);

    logger_running = 1;
    if (pthread_create(&logger_thread, NULL, logger_worker, NULL) != 0) {
        perror("Failed to create logger thread");
        exit(1);
    }
}

void cleanup_logger() {
    pthread_mutex_lock(&queue_mutex);
    logger_running = 0;
    pthread_cond_signal(&queue_cond);
    pthread_mutex_unlock(&queue_mutex);

    pthread_join(logger_thread, NULL);
    close_udp_sender();
}

void log_message(const char* fmt, ...) {
    if (!logger_running) return;

    va_list args;
    
    // Calculate message size
    va_start(args, fmt);
    int size = vsnprintf(NULL, 0, fmt, args);
    va_end(args);

    if (size < 0) return;

    char* buffer = (char*)malloc(size + 1);
    if (!buffer) return;

    va_start(args, fmt);
    vsnprintf(buffer, size + 1, fmt, args);
    va_end(args);

    // Create new node
    LogNode* node = (LogNode*)malloc(sizeof(LogNode));
    if (!node) {
        free(buffer);
        return;
    }
    node->type = LOG_TYPE_TEXT;
    node->message = buffer;
    node->next = NULL;

    // Add to queue (drop if full)
    pthread_mutex_lock(&queue_mutex);
    if (queue_len >= LOGGER_QUEUE_MAX) {
        dropped_count++;
        time_t now = time(NULL);
        if (now - last_drop_report >= 5) {
            fprintf(stderr, "[WARN] Logger queue full - %lu messages dropped\n", dropped_count);
            dropped_count = 0;
            last_drop_report = now;
        }
        pthread_mutex_unlock(&queue_mutex);
        free(buffer);
        free(node);
        return;
    }
    if (tail) {
        tail->next = node;
        tail = node;
    } else {
        head = tail = node;
    }
    queue_len++;
    pthread_cond_signal(&queue_cond);
    pthread_mutex_unlock(&queue_mutex);
}

void log_packet(const PacketMetadata* meta) {
    if (!logger_running) return;

    LogNode* node = (LogNode*)malloc(sizeof(LogNode));
    if (!node) return;

    node->type = LOG_TYPE_PACKET;
    node->packet = *meta; // Copy data
    node->message = NULL;
    node->next = NULL;

    // Add to queue (drop if full)
    pthread_mutex_lock(&queue_mutex);
    if (queue_len >= LOGGER_QUEUE_MAX) {
        dropped_count++;
        time_t now = time(NULL);
        if (now - last_drop_report >= 5) {
            fprintf(stderr, "[WARN] Logger queue full - %lu messages dropped\n", dropped_count);
            dropped_count = 0;
            last_drop_report = now;
        }
        pthread_mutex_unlock(&queue_mutex);
        free(node);
        return;
    }
    if (tail) {
        tail->next = node;
        tail = node;
    } else {
        head = tail = node;
    }
    queue_len++;
    pthread_cond_signal(&queue_cond);
    pthread_mutex_unlock(&queue_mutex);
}