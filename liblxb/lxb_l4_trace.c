/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#ifdef HAVE_L4_TRACE
#include <pthread.h>
#include "lxb_l4_trace_event.h"
#endif

// Phase 1: Runtime Control API for L4 Tracing
// This provides CGO-compatible functions for Go runtime control

#ifdef HAVE_L4_TRACE

// Global L4 tracing control (atomic operations via __atomic builtins)
// Runtime enable/disable is via BPF config map (l4_trace_cfg)
static volatile uint8_t l4_trace_enabled = 0;  // Default: disabled until explicitly enabled
static volatile uint8_t l4_trace_sampling_rate = 100; // Default: 100% (no sampling)

// L4 tracing statistics (per-worker aggregation happens in eBPF via BPF_MAP_TYPE_PERCPU_ARRAY)
struct l4_trace_stats {
    uint64_t total_events;      // Total L4 events emitted
    uint64_t sampled_events;    // Events that passed sampling
    uint64_t dropped_events;    // Ring buffer overflows
    uint64_t tcp_events;        // TCP state changes
    uint64_t sctp_events;       // SCTP state changes
    uint64_t udp_events;        // UDP state changes
    uint64_t conn_new;          // New connections
    uint64_t conn_established;  // Established connections
    uint64_t conn_closed;       // Clean closes
    uint64_t conn_timeout;      // Timeout closes
    uint64_t conn_reset;        // RST/ABORT closes
    uint64_t conn_error;        // Error events
};

static struct l4_trace_stats global_stats = {0};
static pthread_mutex_t stats_lock = PTHREAD_MUTEX_INITIALIZER;

// Enable/Disable L4 tracing at runtime
// NOTE: This only updates local C state. Actual eBPF map update happens in Go.
// Returns: 0 on success, -1 on error
int lxb_l4_trace_enable(uint8_t enabled) {
    if (enabled > 1) {
        return -1; // Invalid argument
    }

    __atomic_store_n(&l4_trace_enabled, enabled, __ATOMIC_RELEASE);
    
#ifdef HAVE_PROXY_EXTRA_DEBUG
    printf("[L4Trace] Local state updated: %s (BPF map update happens in Go)\n", enabled ? "ENABLED" : "DISABLED");
#endif
    return 0;
}

// Get current L4 tracing status
// Returns: 1 if enabled, 0 if disabled
uint8_t lxb_l4_trace_is_enabled(void) {
    return __atomic_load_n(&l4_trace_enabled, __ATOMIC_ACQUIRE);
}

// Set sampling rate (0-100 percentage)
// NOTE: This only updates local C state. Actual eBPF map update happens in Go.
// Returns: 0 on success, -1 on invalid rate
int lxb_l4_trace_set_sampling_rate(uint8_t rate) {
    if (rate > 100) {
        return -1;
    }

    __atomic_store_n(&l4_trace_sampling_rate, rate, __ATOMIC_RELEASE);
    
#ifdef HAVE_PROXY_EXTRA_DEBUG
    printf("[L4Trace] Local state updated: sampling=%u%% (BPF map update happens in Go)\n", rate);
#endif
    return 0;
}

// Get current sampling rate
uint8_t lxb_l4_trace_get_sampling_rate(void) {
    return __atomic_load_n(&l4_trace_sampling_rate, __ATOMIC_ACQUIRE);
}

// Update statistics (called by ring consumer or aggregator)
void lxb_l4_trace_update_stats(struct l4_trace_stats *delta) {
    pthread_mutex_lock(&stats_lock);
    
    global_stats.total_events += delta->total_events;
    global_stats.sampled_events += delta->sampled_events;
    global_stats.dropped_events += delta->dropped_events;
    global_stats.tcp_events += delta->tcp_events;
    global_stats.sctp_events += delta->sctp_events;
    global_stats.udp_events += delta->udp_events;
    global_stats.conn_new += delta->conn_new;
    global_stats.conn_established += delta->conn_established;
    global_stats.conn_closed += delta->conn_closed;
    global_stats.conn_timeout += delta->conn_timeout;
    global_stats.conn_reset += delta->conn_reset;
    global_stats.conn_error += delta->conn_error;

    pthread_mutex_unlock(&stats_lock);
}

// Get L4 tracing statistics
struct l4_trace_stats lxb_l4_trace_get_stats(void) {
    struct l4_trace_stats stats;
    pthread_mutex_lock(&stats_lock);
    memcpy(&stats, &global_stats, sizeof(stats));
    pthread_mutex_unlock(&stats_lock);
    return stats;
}

// Reset L4 tracing statistics
void lxb_l4_trace_reset_stats(void) {
    pthread_mutex_lock(&stats_lock);
    memset(&global_stats, 0, sizeof(global_stats));
    pthread_mutex_unlock(&stats_lock);
    printf("[L4Trace] Statistics reset\n");
}

// Phase 2: Ring buffer initialization (Go manages ring buffers via BPF syscalls)
int lxb_l4_trace_ring_init(void) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
    printf("[L4Trace] Ring buffer managed by Go consumer (no C-side init needed)\n");
#endif
    // Phase 2: Ring buffers are created by eBPF loader and accessed via Go
    // This function is kept for API compatibility but is a no-op in current design
    return 0;
}

// Phase 2: Ring buffer cleanup (Go manages cleanup)
void lxb_l4_trace_ring_cleanup(void) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
    printf("[L4Trace] Ring buffer cleanup handled by Go consumer\n");
#endif
    // Phase 2: Ring buffer cleanup happens in Go-side consumer Stop()
}

#else  // !HAVE_L4_TRACE

// Stub implementations when L4 tracing is disabled (build-time optimization)
// These ensure the Go CGO code can always link, even without -DHAVE_L4_TRACE

// Define empty stats struct for stub
struct l4_trace_stats {
    uint64_t total_events;
    uint64_t sampled_events;
    uint64_t dropped_events;
    uint64_t tcp_events;
    uint64_t sctp_events;
    uint64_t udp_events;
    uint64_t conn_new;
    uint64_t conn_established;
    uint64_t conn_closed;
    uint64_t conn_timeout;
    uint64_t conn_reset;
    uint64_t conn_error;
};

int lxb_l4_trace_enable(uint8_t enabled) {
    return -1;  // Always fail when not compiled
}

uint8_t lxb_l4_trace_is_enabled(void) {
    return 0;  // Always disabled
}

int lxb_l4_trace_set_sampling_rate(uint8_t rate) {
    return -1;
}

uint8_t lxb_l4_trace_get_sampling_rate(void) {
    return 0;
}

void lxb_l4_trace_update_stats(struct l4_trace_stats *delta) {
    // No-op
}

struct l4_trace_stats lxb_l4_trace_get_stats(void) {
    struct l4_trace_stats stats = {0};
    return stats;
}

void lxb_l4_trace_reset_stats(void) {
    // No-op
}

int lxb_l4_trace_ring_init(void) {
    return -1;
}

void lxb_l4_trace_ring_cleanup(void) {
    // No-op
}

#endif  // HAVE_L4_TRACE
