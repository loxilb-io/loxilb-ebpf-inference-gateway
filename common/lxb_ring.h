/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */
#ifndef __LXB_RING_H__
#define __LXB_RING_H__

#include <stdint.h>
#include <stdatomic.h>
#include <unistd.h>
#include "lxb_trace_event.h"

// Ring buffer configuration
#define LXB_RING_CAP  8192  // Power of two (for fast modulo via AND mask)
#define LXB_RING_MASK (LXB_RING_CAP - 1)

/**
 * Lock-Free SPSC Ring Buffer (Disruptor Pattern)
 * 
 * Design:
 * - Single Producer (sockproxy worker thread)
 * - Single Consumer (Go goroutine via CGo)
 * - No locks, no CAS, just atomic load/store
 * - Cache-line aligned to prevent false sharing
 * 
 * Memory Layout:
 * - Cache Line 0 (64B): Writer-owned (sockproxy) - w, dropped
 * - Cache Line 1 (64B): Reader-owned (Go) - r
 * - Cache Line 2+: Event storage (8192 × 256B = 2MB)
 * 
 * Total size per ring: ~2MB + 128B overhead
 * For 4 worker threads: ~8MB total
 */
typedef struct __attribute__((aligned(64))) lxb_ring {
  /* Cache Line 0: Writer-owned (prevents false sharing) */
  _Atomic uint32_t w;       // Write index (producer)
  uint32_t cap;             // Capacity (8192)
  _Atomic uint32_t dropped; // Dropped events (ring full, non-critical stat)
  int32_t  eventfd;         // Notification fd (optional, -1 if disabled)
  uint32_t _pad1[12];       // Pad to 64 bytes (cache line)
  
  /* Cache Line 1: Reader-owned (prevents false sharing) */
  _Atomic uint32_t r;       // Read index (consumer)
  uint32_t _pad2[15];       // Pad to 64 bytes (cache line)
  
  /* Cache Line 2+: Event storage (2MB for 8192 events) */
  lxb_trace_event_t ev[LXB_RING_CAP];
} lxb_ring_t;

/**
 * Push event to ring buffer (producer side - sockproxy worker thread)
 * 
 * Performance: ~50ns on modern CPUs (no syscalls, no locks)
 * 
 * Algorithm:
 * 1. Load write index (w) - relaxed
 * 2. Load read index (r) - acquire (ensure reader's writes are visible)
 * 3. Check if full: (w+1) & MASK == r (leave 1 slot for sentinel)
 * 4. Write event to ring slot
 * 5. Advance w with release barrier (publish event)
 * 6. Optional: notify consumer via eventfd
 * 
 * @param rb Ring buffer pointer
 * @param e Event to push (256 bytes)
 * @return 0 on success, -1 if ring full (event dropped)
 */
static inline int lxb_ring_push(lxb_ring_t *rb, const lxb_trace_event_t *e) {
  uint32_t w = atomic_load_explicit(&rb->w, memory_order_relaxed);
  uint32_t r = atomic_load_explicit(&rb->r, memory_order_acquire);

  // Check if ring is full (leave 1 slot for sentinel)
  if (((w + 1) & LXB_RING_MASK) == r) {
    atomic_fetch_add_explicit(&rb->dropped, 1, memory_order_relaxed);
    return -1;  // Ring full, drop event
  }

  // Write event to ring slot (fixed-size copy, compiler will optimize)
  rb->ev[w] = *e;
  
  // Publish event with release barrier (ensures ev[w] write is visible before w update)
  atomic_store_explicit(&rb->w, (w + 1) & LXB_RING_MASK, memory_order_release);

  // Notify consumer (optional, reduces polling latency)
  // Non-blocking write, ignore EAGAIN (consumer will poll anyway)
  if (rb->eventfd >= 0) {
    uint64_t one = 1;
    (void)write(rb->eventfd, &one, sizeof(one));
  }

  return 0;
}

/**
 * Pop event from ring buffer (consumer side - Go via CGo)
 * 
 * Performance: ~30ns on modern CPUs
 * 
 * @param rb Ring buffer pointer
 * @param e Event to populate (256 bytes)
 * @return 1 if event popped, 0 if ring empty
 */
static inline int lxb_ring_pop(lxb_ring_t *rb, lxb_trace_event_t *e) {
  uint32_t r = atomic_load_explicit(&rb->r, memory_order_relaxed);
  uint32_t w = atomic_load_explicit(&rb->w, memory_order_acquire);

  if (r == w) {
    return 0; // Ring empty
  }

  // Read event from ring slot
  *e = rb->ev[r];
  
  // Advance read index with release barrier
  atomic_store_explicit(&rb->r, (r + 1) & LXB_RING_MASK, memory_order_release);

  return 1;
}

/**
 * Get ring utilization (for monitoring)
 * 
 * @param rb Ring buffer pointer
 * @return Number of events currently in ring (0 to LXB_RING_CAP-1)
 */
static inline uint32_t lxb_ring_size(lxb_ring_t *rb) {
  uint32_t w = atomic_load_explicit(&rb->w, memory_order_relaxed);
  uint32_t r = atomic_load_explicit(&rb->r, memory_order_relaxed);
  return (w - r) & LXB_RING_MASK;
}

/**
 * Get dropped event count (for monitoring)
 * 
 * @param rb Ring buffer pointer
 * @return Number of dropped events since initialization
 */
static inline uint32_t lxb_ring_dropped(lxb_ring_t *rb) {
  return atomic_load_explicit(&rb->dropped, memory_order_relaxed);
}

// ============================================================================
// Ring Buffer Management API (implemented in lxb_ring.c)
// ============================================================================

/**
 * Initialize per-thread ring buffers at startup
 * 
 * Creates shared memory files for Go consumer:
 * - /dev/shm/loxilb-trace-ring-<pid>-<worker_id>
 * 
 * LIFECYCLE MANAGEMENT:
 * - Called from proxy_epmap_init() before worker threads spawn
 * - Shared memory owned by loxilb process (0644 permissions for Go reader)
 * - Cleanup handled by lxb_ring_cleanup() on exit (atexit handler)
 * - Crash recovery: stale shm files cleaned by systemd tmpfiles.d rule
 * 
 * MULTI-INSTANCE SUPPORT:
 * - PID in filename ensures per-process isolation
 * - For HA/clustering, add LOXILB_INSTANCE_ID env var:
 *   /dev/shm/loxilb-trace-ring-<instance_id>-<pid>-<worker_id>
 * 
 * @param num_workers Number of sockproxy worker threads (must match PROXY_MAX_THREADS)
 * @return 0 on success, -1 on error
 */
int lxb_ring_init(int num_workers);

/**
 * Check if ring buffers are initialized
 * Used for lazy initialization when tracing is enabled on-demand
 * @return 1 if initialized, 0 if not
 */
int lxb_ring_is_initialized(void);

/**
 * Cleanup all ring buffers (called at exit)
 * 
 * - Unmaps shared memory
 * - Closes eventfds
 * - Unlinks /dev/shm files
 */
void lxb_ring_cleanup(void);

/**
 * Get ring buffer for current worker thread
 * 
 * Thread-local lookup based on worker_id.
 * Must be called after lxb_ring_set_worker_id().
 * 
 * @return Ring buffer pointer, or NULL if not initialized
 */
lxb_ring_t* lxb_ring_get(void);

/**
 * Set worker ID for current thread
 * 
 * Must be called once per worker thread at startup.
 * Used for thread-local ring buffer lookup.
 * 
 * @param worker_id Worker thread ID (0 to num_workers-1)
 */
void lxb_ring_set_worker_id(int worker_id);

// ============================================================================
// Fast RNG for Trace/Span ID Generation
// ============================================================================

/**
 * Generate 64-bit random number (xorshift64* algorithm)
 * 
 * Fast, non-cryptographic PRNG suitable for trace/span IDs.
 * Thread-local state, no syscalls, ~5ns per call.
 * 
 * @return 64-bit random value
 */
uint64_t lxb_gen_trace_id_part(void);

/**
 * Generate 64-bit span ID
 * 
 * @return 64-bit span ID
 */
uint64_t lxb_gen_span_id(void);

/**
 * Generate 128-bit trace ID
 * 
 * @param hi High 64 bits output
 * @param lo Low 64 bits output
 */
void lxb_gen_trace_id(uint64_t *hi, uint64_t *lo);

#endif /* __LXB_RING_H__ */
