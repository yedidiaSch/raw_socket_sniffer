/**
 * @file logger.c
 * @brief Implementation of thread-safe logging functions.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <pthread.h>
#include "logger.h"
#include "udp_sender.h"

// --- Queue Structure ---
typedef enum {
    LOG_TYPE_TEXT,
    LOG_TYPE_PACKET
} LogType;

typedef struct LogNode {
    LogType type;
    char* message;          // For text logs
    PacketMetadata packet;  // For packet logs
    struct LogNode* next;
} LogNode;

static LogNode* head = NULL;
static LogNode* tail = NULL;

// --- Synchronization ---
static pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;
static pthread_t logger_thread;
static volatile int logger_running = 0;

/**
 * @brief The main loop for the logger thread.
 */
static void* logger_worker(void* arg) {
    (void)arg;
    while (1) {
        pthread_mutex_lock(&queue_mutex);

        // Wait for data or shutdown signal
        while (head == NULL && logger_running) {
            pthread_cond_wait(&queue_cond, &queue_mutex);
        }

        // If shutdown and empty, exit
        if (!logger_running && head == NULL) {
            pthread_mutex_unlock(&queue_mutex);
            break;
        }

        // Pop message
        LogNode* node = head;
        head = node->next;
        if (head == NULL) {
            tail = NULL;
        }

        pthread_mutex_unlock(&queue_mutex);

        // Process message (IO operation outside lock)
        if (node) {
            if (node->type == LOG_TYPE_TEXT) {
                printf("%s", node->message); 
                free(node->message);
            } else if (node->type == LOG_TYPE_PACKET) {
                send_udp_metadata(&node->packet);
            }
            free(node);
        }
    }
    return NULL;
}

void init_logger() {
    if (logger_running) return;
    
    // Initialize UDP Sender (Hardcoded for now as per request context, or could be args)
    init_udp_sender("127.0.0.1", 5005);

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
    
    // Determine required size
    va_start(args, fmt);
    int size = vsnprintf(NULL, 0, fmt, args);
    va_end(args);

    if (size < 0) return;

    char* buffer = (char*)malloc(size + 1);
    if (!buffer) return;

    va_start(args, fmt);
    vsnprintf(buffer, size + 1, fmt, args);
    va_end(args);

    // Create node
    LogNode* node = (LogNode*)malloc(sizeof(LogNode));
    if (!node) {
        free(buffer);
        return;
    }
    node->type = LOG_TYPE_TEXT;
    node->message = buffer;
    node->next = NULL;

    // Push to queue
    pthread_mutex_lock(&queue_mutex);
    if (tail) {
        tail->next = node;
        tail = node;
    } else {
        head = tail = node;
    }
    pthread_cond_signal(&queue_cond);
    pthread_mutex_unlock(&queue_mutex);
}

void log_packet(const PacketMetadata* meta) {
    if (!logger_running) return;

    LogNode* node = (LogNode*)malloc(sizeof(LogNode));
    if (!node) return;

    node->type = LOG_TYPE_PACKET;
    node->packet = *meta; // Copy struct
    node->message = NULL;
    node->next = NULL;

    // Push to queue
    pthread_mutex_lock(&queue_mutex);
    if (tail) {
        tail->next = node;
        tail = node;
    } else {
        head = tail = node;
    }
    pthread_cond_signal(&queue_cond);
    pthread_mutex_unlock(&queue_mutex);
}
