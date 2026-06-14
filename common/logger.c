/**
 * @file logger.c
 * @brief Thread-safe logging implementation.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include "logger.h"
#include "udp_sender.h"

// --- Queue Structure ---
typedef enum {
    LOG_TYPE_TEXT,
    LOG_TYPE_PACKET
} LogType;

// Maximum length of a single formatted text log line (including terminator).
// Longer lines are truncated rather than heap-allocated, keeping the hot path
// allocation-free.
#define LOG_MSG_MAX 256

// A node carries EITHER a text message OR packet metadata, never both, so a
// union keeps each node compact. The message buffer is inline (no separate
// heap allocation per log call — see the node pool below).
typedef struct LogNode {
    LogType type;
    union {
        char message[LOG_MSG_MAX];
        PacketMetadata packet;
    } data;
    struct LogNode* next;
} LogNode;

static LogNode* head = NULL;
static LogNode* tail = NULL;

// Bound the queue: the capture loop can outpace the logger thread under load,
// so an unbounded queue grows until OOM. New items are dropped when full and
// the dropped count is reported periodically.
#define LOGGER_QUEUE_MAX 10000

// Pre-allocated node pool. Instead of malloc/free per packet (which, at high
// packet rates, dominates the hot path and fragments the heap), all nodes are
// allocated once into this array and recycled through a free list. The free
// list being empty is exactly the "queue full" condition.
static LogNode node_pool[LOGGER_QUEUE_MAX];
static LogNode* free_list = NULL;

static unsigned long dropped_count = 0;
static time_t last_drop_report = 0;

// --- Synchronization ---
static pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;
static pthread_t logger_thread;
static volatile int logger_running = 0;

// --- Pool / queue helpers (all require queue_mutex held by caller) ---

static void pool_init(void) {
    free_list = NULL;
    for (size_t i = 0; i < LOGGER_QUEUE_MAX; i++) {
        node_pool[i].next = free_list;
        free_list = &node_pool[i];
    }
}

static LogNode* pool_pop_free(void) {
    LogNode* n = free_list;
    if (n) free_list = n->next;
    return n;
}

static void pool_push_free(LogNode* n) {
    n->next = free_list;
    free_list = n;
}

static void enqueue_locked(LogNode* node) {
    node->next = NULL;
    if (tail) {
        tail->next = node;
        tail = node;
    } else {
        head = tail = node;
    }
}

static void record_drop_locked(void) {
    dropped_count++;
    time_t now = time(NULL);
    if (now - last_drop_report >= 5) {
        fprintf(stderr, "[WARN] Logger queue full - %lu messages dropped\n", dropped_count);
        dropped_count = 0;
        last_drop_report = now;
    }
}

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

        pthread_mutex_unlock(&queue_mutex);

        // Process the message (outside the lock — printf/sendto may block)
        if (node->type == LOG_TYPE_TEXT) {
            printf("%s", node->data.message);
        } else if (node->type == LOG_TYPE_PACKET) {
            send_udp_metadata(&node->data.packet);
        }

        // Return the node to the pool for reuse.
        pthread_mutex_lock(&queue_mutex);
        pool_push_free(node);
        pthread_mutex_unlock(&queue_mutex);
    }
    return NULL;
}

void init_logger() {
    if (logger_running) return;

    // Initialize UDP sender
    init_udp_sender("127.0.0.1", DASHBOARD_UDP_PORT);

    pool_init();

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

    // Format once into a stack buffer (the previous implementation called
    // vsnprintf twice — once to size, once to fill). Truncation of very long
    // lines is acceptable for log output.
    char buffer[LOG_MSG_MAX];
    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);

    if (n < 0) return;

    pthread_mutex_lock(&queue_mutex);
    LogNode* node = pool_pop_free();
    if (!node) {
        record_drop_locked();
        pthread_mutex_unlock(&queue_mutex);
        return;
    }
    node->type = LOG_TYPE_TEXT;
    memcpy(node->data.message, buffer, sizeof(buffer));
    enqueue_locked(node);
    pthread_cond_signal(&queue_cond);
    pthread_mutex_unlock(&queue_mutex);
}

void log_packet(const PacketMetadata* meta) {
    if (!logger_running) return;

    pthread_mutex_lock(&queue_mutex);
    LogNode* node = pool_pop_free();
    if (!node) {
        record_drop_locked();
        pthread_mutex_unlock(&queue_mutex);
        return;
    }
    node->type = LOG_TYPE_PACKET;
    node->data.packet = *meta; // Copy data
    enqueue_locked(node);
    pthread_cond_signal(&queue_cond);
    pthread_mutex_unlock(&queue_mutex);
}
