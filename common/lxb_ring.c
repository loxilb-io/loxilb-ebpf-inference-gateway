/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */
#include "lxb_ring.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/eventfd.h>
#include <time.h>
#include <pthread.h>

#define MAX_WORKERS 4  // Must match PROXY_MAX_THREADS from sockproxy.c

// Global per-thread ring array
static lxb_ring_t *g_rings[MAX_WORKERS] = {NULL};
static int g_num_workers = 0;
static pthread_t g_worker_tids[MAX_WORKERS] = {0};  // pthread IDs for auto-detection
static __thread int g_worker_id = -1;  // Thread-local worker ID

// Fast RNG state (thread-local)
static __thread uint64_t g_rng_state = 0;

// ============================================================================
// Ring Buffer Management
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
int lxb_ring_init(int num_workers) {
  if (num_workers > MAX_WORKERS) {
    log_error("[LXB_RING] Too many workers: %d (max %d)", num_workers, MAX_WORKERS);
    return -1;
  }

  g_num_workers = num_workers;

  // CRITICAL FIX: Clean up stale ring files from previous instances
  // This prevents SIGBUS crashes when restarting loxilb
  log_info("[LXB_RING] Cleaning up stale ring files for PID %d", getpid());
  for (int i = 0; i < num_workers; i++) {
    char shm_path[256];
    const char *instance_id = getenv("LOXILB_INSTANCE_ID");
    if (instance_id) {
      snprintf(shm_path, sizeof(shm_path), "/loxilb-trace-ring-%s-%d-%d", 
               instance_id, getpid(), i);
    } else {
      snprintf(shm_path, sizeof(shm_path), "/loxilb-trace-ring-%d-%d", getpid(), i);
    }
    // Best-effort cleanup (ignore errors)
    shm_unlink(shm_path);
  }

  for (int i = 0; i < num_workers; i++) {
    // Create shared memory file for this ring
    // Format: /dev/shm/loxilb-trace-ring-<pid>-<worker_id>
    // Alternative for multi-instance: /dev/shm/loxilb-trace-ring-<instance_id>-<pid>-<worker_id>
    char shm_path[256];
    const char *instance_id = getenv("LOXILB_INSTANCE_ID");
    if (instance_id) {
      snprintf(shm_path, sizeof(shm_path), "/loxilb-trace-ring-%s-%d-%d", 
               instance_id, getpid(), i);
    } else {
      snprintf(shm_path, sizeof(shm_path), "/loxilb-trace-ring-%d-%d", getpid(), i);
    }
    
    // Create/open shared memory file (O_CREAT | O_RDWR)
    // Permissions: 0644 (owner RW, group/other R)
    int shm_fd = shm_open(shm_path, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (shm_fd < 0) {
      log_error("[LXB_RING] Failed to create shm %s: %s", shm_path, strerror(errno));
      goto cleanup;
    }

    // Set size to ring buffer struct size
    size_t ring_size = sizeof(lxb_ring_t);
    
    // CRITICAL FIX: Use posix_fallocate to pre-allocate physical memory
    // This prevents SIGBUS when accessing mmap'd memory (avoids sparse file issues)
    // ftruncate alone only sets logical file size, not physical allocation
    int alloc_ret = posix_fallocate(shm_fd, 0, ring_size);
    if (alloc_ret != 0) {
      log_error("[LXB_RING] Failed to allocate shm %s (size=%zu): %s", 
                shm_path, ring_size, strerror(alloc_ret));
      close(shm_fd);
      goto cleanup;
    }
    
    log_debug("[LXB_RING] Allocated %zu bytes for ring %d", ring_size, i);

    // Map shared memory
    void *addr = mmap(NULL, ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (addr == MAP_FAILED) {
      log_error("[LXB_RING] Failed to mmap shm %s: %s", shm_path, strerror(errno));
      close(shm_fd);
      goto cleanup;
    }
    close(shm_fd);  // Can close fd after mmap

    // Initialize ring buffer structure
    lxb_ring_t *rb = (lxb_ring_t *)addr;
    log_debug("[LXB_RING] Zeroing ring %d at addr=%p, size=%zu", i, addr, ring_size);
    memset(rb, 0, ring_size);  // Zero-initialize
    rb->cap = LXB_RING_CAP;
    atomic_store_explicit(&rb->w, 0, memory_order_relaxed);
    atomic_store_explicit(&rb->r, 0, memory_order_relaxed);
    atomic_store_explicit(&rb->dropped, 0, memory_order_relaxed);

    // Create eventfd for notification (optional)
    // EFD_NONBLOCK: non-blocking writes/reads
    // EFD_SEMAPHORE: semaphore-style counter semantics
    rb->eventfd = eventfd(0, EFD_NONBLOCK | EFD_SEMAPHORE);
    if (rb->eventfd < 0) {
      log_warn("[LXB_RING] Failed to create eventfd for ring %d: %s (continuing without notification)",
               i, strerror(errno));
      rb->eventfd = -1;  // Disable eventfd notification
    }

    g_rings[i] = rb;
    
    log_info("[LXB_RING] Initialized ring %d: shm=%s, size=%zu, addr=%p, eventfd=%d",
             i, shm_path, ring_size, addr, rb->eventfd);
  }

  // Register cleanup handler
  atexit(lxb_ring_cleanup);

  log_info("[LXB_RING] All %d rings initialized (pid=%d)", num_workers, getpid());
  return 0;

cleanup:
  // Cleanup on error
  for (int i = 0; i < num_workers; i++) {
    if (g_rings[i]) {
      if (g_rings[i]->eventfd >= 0) {
        close(g_rings[i]->eventfd);
      }
      munmap(g_rings[i], sizeof(lxb_ring_t));
      g_rings[i] = NULL;
    }
    
    // Unlink shared memory file
    char shm_path[256];
    const char *instance_id = getenv("LOXILB_INSTANCE_ID");
    if (instance_id) {
      snprintf(shm_path, sizeof(shm_path), "/loxilb-trace-ring-%s-%d-%d", 
               instance_id, getpid(), i);
    } else {
      snprintf(shm_path, sizeof(shm_path), "/loxilb-trace-ring-%d-%d", getpid(), i);
    }
    shm_unlink(shm_path);
  }
  
  return -1;
}

/**
 * Cleanup all ring buffers (called at exit)
 * 
 * - Unmaps shared memory
 * - Closes eventfds
 * - Unlinks /dev/shm files
 */
void lxb_ring_cleanup(void) {
  log_info("[LXB_RING] Cleaning up %d rings", g_num_workers);

  for (int i = 0; i < g_num_workers; i++) {
    if (g_rings[i]) {
      // Log final stats
      uint32_t dropped = atomic_load_explicit(&g_rings[i]->dropped, memory_order_relaxed);
      uint32_t size = lxb_ring_size(g_rings[i]);
      log_info("[LXB_RING] Ring %d stats: dropped=%u, pending=%u", i, dropped, size);

      // Close eventfd
      if (g_rings[i]->eventfd >= 0) {
        close(g_rings[i]->eventfd);
      }

      // Unmap shared memory
      munmap(g_rings[i], sizeof(lxb_ring_t));
      g_rings[i] = NULL;
    }
    
    // Unlink shared memory file
    char shm_path[256];
    const char *instance_id = getenv("LOXILB_INSTANCE_ID");
    if (instance_id) {
      snprintf(shm_path, sizeof(shm_path), "/loxilb-trace-ring-%s-%d-%d", 
               instance_id, getpid(), i);
    } else {
      snprintf(shm_path, sizeof(shm_path), "/loxilb-trace-ring-%d-%d", getpid(), i);
    }
    shm_unlink(shm_path);
  }

  log_info("[LXB_RING] Cleanup complete");
}

/**
 * Get ring buffer for current worker thread
 * 
 * Thread-local lookup based on worker_id.
 * AUTO-DETECTS worker ID if rings initialized but worker ID not set (lazy init case).
 * 
 * @return Ring buffer pointer, or NULL if not initialized
 */
lxb_ring_t* lxb_ring_get(void) {
  // Fast path: worker ID already set
  if (g_worker_id >= 0 && g_worker_id < g_num_workers) {
    return g_rings[g_worker_id];
  }
  
  // Slow path: rings exist but worker ID not set (lazy initialization case)
  if (g_num_workers > 0 && g_worker_id < 0) {
    pthread_t self = pthread_self();
    for (int i = 0; i < g_num_workers; i++) {
      if (pthread_equal(g_worker_tids[i], self)) {
        log_info("[LXB_RING] Auto-detected worker ID %d for pthread=%lu (lazy init)", i, (unsigned long)self);
        lxb_ring_set_worker_id(i);  // Set it for future calls
        return g_rings[i];
      }
    }
    log_error("[LXB_RING] Failed to auto-detect worker ID for pthread=%lu", (unsigned long)self);
  }
  
  return NULL;  // Worker ID not set or invalid
}

/**
 * Check if ring buffers are initialized
 * Used for lazy initialization when tracing is enabled on-demand
 * @return 1 if initialized, 0 if not
 */
int lxb_ring_is_initialized(void) {
  return (g_num_workers > 0 && g_rings[0] != NULL) ? 1 : 0;
}

/**
 * Set worker ID for current thread
 * 
 * Must be called once per worker thread at startup.
 * Used for thread-local ring buffer lookup.
 * 
 * @param worker_id Worker thread ID (0 to num_workers-1)
 */
void lxb_ring_set_worker_id(int worker_id) {
  // Record pthread ID for this worker (even if rings not initialized yet)
  // This enables lazy initialization to auto-detect worker IDs later
  pthread_t self = pthread_self();
  if (worker_id >= 0 && worker_id < MAX_WORKERS) {
    g_worker_tids[worker_id] = self;
  }
  
  // Silently ignore if rings not initialized (tracing disabled)
  if (g_num_workers == 0) {
    return;
  }
  
  if (worker_id < 0 || worker_id >= g_num_workers) {
    log_error("[LXB_RING] Invalid worker_id %d (max %d)", worker_id, g_num_workers - 1);
    return;
  }
  g_worker_id = worker_id;
  
  // Initialize RNG state for this thread (use worker_id + timestamp for seed)
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  g_rng_state = ((uint64_t)worker_id << 48) | 
                ((uint64_t)ts.tv_sec << 32) | 
                (uint64_t)ts.tv_nsec;
  
  // Ensure seed is non-zero (xorshift64* requirement)
  if (g_rng_state == 0) {
    g_rng_state = 0x123456789abcdef0ULL;
  }
  
  log_debug("[LXB_RING] Worker %d initialized (pthread=%lu, rng_seed=%016llx)", worker_id, (unsigned long)self, g_rng_state);
}

// ============================================================================
// Fast RNG for Trace/Span ID Generation
// ============================================================================

/**
 * xorshift64* - Fast non-cryptographic PRNG
 * 
 * Period: 2^64 - 1
 * Performance: ~5ns per call (2-3 CPU cycles)
 * Quality: Passes BigCrush statistical tests
 * 
 * Algorithm from: Marsaglia, "Xorshift RNGs" (2003)
 * Multiplier from: Vigna, "An experimental exploration of Marsaglia's xorshift generators" (2016)
 */
static inline uint64_t xorshift64star(uint64_t *state) {
  uint64_t x = *state;
  x ^= x >> 12;
  x ^= x << 25;
  x ^= x >> 27;
  *state = x;
  return x * 0x2545F4914F6CDD1DULL;
}

/**
 * Generate 64-bit random number (xorshift64* algorithm)
 * 
 * Fast, non-cryptographic PRNG suitable for trace/span IDs.
 * Thread-local state, no syscalls, ~5ns per call.
 * 
 * @return 64-bit random value
 */
uint64_t lxb_gen_trace_id_part(void) {
  // Auto-initialize if seed is zero (shouldn't happen if lxb_ring_set_worker_id called)
  if (g_rng_state == 0) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    g_rng_state = ((uint64_t)ts.tv_sec << 32) | (uint64_t)ts.tv_nsec;
    if (g_rng_state == 0) {
      g_rng_state = 0x123456789abcdef0ULL;
    }
    log_debug("[LXB_RNG] Auto-initialized g_rng_state=%016llx (worker_id=%d not set)", g_rng_state, g_worker_id);
  }
  
  return xorshift64star(&g_rng_state);
}

/**
 * Generate 64-bit span ID
 * 
 * @return 64-bit span ID
 */
uint64_t lxb_gen_span_id(void) {
  return lxb_gen_trace_id_part();
}

/**
 * Generate 128-bit trace ID
 * 
 * @param hi High 64 bits output
 * @param lo Low 64 bits output
 */
void lxb_gen_trace_id(uint64_t *hi, uint64_t *lo) {
  *hi = lxb_gen_trace_id_part();
  *lo = lxb_gen_trace_id_part();
  log_debug("[LXB_TRACE_ID] Generated: %016llx%016llx (hi=%016llx lo=%016llx)", *hi, *lo, *hi, *lo);
}
