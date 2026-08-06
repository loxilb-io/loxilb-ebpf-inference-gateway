/*
 * Copyright (c) 2022 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* sockproxy_trace.c -- HTTP/HTTPS tracing, catalog management, ring buffer
 * event emission.  Extracted from sockproxy.c sections 3, 22, 23.
 *
 * Compile with -DHAVE_HTTP_TRACE=1 to enable; the stubs in the #else
 * branch are always compiled and satisfy the CGO linkage boundary.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <pthread.h>
#include "uthash.h"               /* MUST precede sockproxy.h */
#include "log.h"
#include "sockproxy_internal.h"   /* includes sockproxy.h    */
#include "sockproxy_trace.h"

// --- Region 1: Trace includes, globals, forward decls ---
#ifdef HAVE_HTTP_TRACE
#include "lxb_ring.h"
#include "lxb_traceparent.h"
#include "lxb_catalog.h"
#include <time.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#ifdef HAVE_MTLS
#include <openssl/ssl.h>
#endif

// Forward declarations for trace functions
uint64_t get_timestamp_ns(void);
void emit_trace_event(proxy_fd_ent_t *pfe, uint8_t event_type, uint32_t duration_us);
static int capture_body_for_tracing(proxy_fd_ent_t *pfe, lxb_trace_event_t *evt);
void *trace_file_cleanup_thread(void *arg);

// Global catalog configuration (mmap'd from shared memory)
lxb_catalog_config_t g_catalog_configs[LXB_MAX_CATALOGS];
lxb_service_catalog_map_t g_service_catalog_map[LXB_MAX_SERVICES];
uint8_t g_catalog_sample_rates[LXB_MAX_CATALOGS];

// Atomic flag to track if catalogs have been successfully loaded
static _Atomic int g_catalogs_loaded = 0;

// Catalog shared memory initialization
static int lxb_catalog_init(void);
static int lxb_catalog_reload(void);

// Lookup catalog ID by service key
uint16_t lxb_lookup_service_catalog(uint32_t xip, uint16_t xport, uint8_t protocol);

// Debug helper to print catalog config
#ifdef HAVE_PROXY_EXTRA_DEBUG
static void log_catalog_config(uint16_t catalog_id, lxb_catalog_config_t *cfg) {
  log_debug("[CATALOG_CONFIG] catalog_id=%d enabled=%d sample_rate=%d%% parser_type=%d path=%s max_body=%u",
            catalog_id, cfg->enabled, cfg->sample_rate, cfg->parser_type,
            cfg->path_prefix[0] ? cfg->path_prefix : "(none)", cfg->max_body_size);
}
#else
#define log_catalog_config(id, cfg) do {} while(0)
#endif
#endif

// --- Region 2: Runtime control (lxb_trace_enable/disable/is_enabled) ---
#ifdef HAVE_HTTP_TRACE
// Atomic flag for dynamic enable/disable (2ns overhead when disabled)
static _Atomic int g_trace_enabled = 0;

// Check if tracing is enabled
int is_tracing_enabled(void) {
  return atomic_load_explicit(&g_trace_enabled, memory_order_relaxed);
}

// CGO Export: Enable tracing dynamically
int lxb_trace_enable(void) {
  // Check if already enabled
  if (atomic_load_explicit(&g_trace_enabled, memory_order_relaxed)) {
    log_info("[HTTP_TRACE] Tracing already enabled");
    return 0;
  }

  // Lazy initialize ring buffers if not already done
  if (!lxb_ring_is_initialized()) {
    log_info("[HTTP_TRACE] Lazy initializing ring buffers for %d workers", PROXY_MAX_THREADS);
    int ret = lxb_ring_init(PROXY_MAX_THREADS);
    if (ret < 0) {
      log_error("[HTTP_TRACE] Failed to initialize trace rings: %d", ret);
      return ret;
    }
    
    // Initialize catalog system for deep inspection
    ret = lxb_catalog_init();
    if (ret < 0) {
      log_error("[HTTP_TRACE] Failed to initialize catalog system: %d", ret);
      // Non-fatal, continue with tracing
    }
    
    log_info("[HTTP_TRACE] Ring buffers initialized successfully");
  }

  atomic_store_explicit(&g_trace_enabled, 1, memory_order_release);
  log_info("[HTTP_TRACE] Tracing enabled");
  return 0;
}

// CGO Export: Disable tracing dynamically
int lxb_trace_disable(void) {
  atomic_store_explicit(&g_trace_enabled, 0, memory_order_release);
  log_info("[HTTP_TRACE] Tracing disabled");
  return 0;
}

// CGO Export: Check if tracing is enabled
int lxb_trace_is_enabled(void) {
  return atomic_load_explicit(&g_trace_enabled, memory_order_relaxed);
}

// CGO Export: Get trace statistics
typedef struct {
  uint64_t total_events;
  uint64_t dropped_events;
  uint32_t ring_utilization[PROXY_MAX_THREADS];
} lxb_trace_stats_t;

lxb_trace_stats_t lxb_trace_get_stats(void) {
  lxb_trace_stats_t stats = {0};
  for (int i = 0; i < PROXY_MAX_THREADS; i++) {
    lxb_ring_t *ring = lxb_ring_get();
    if (ring) {
      stats.total_events += lxb_ring_size(ring);
      stats.dropped_events += lxb_ring_dropped(ring);
      stats.ring_utilization[i] = lxb_ring_size(ring);
    }
  }
  return stats;
}
#else
// Stub implementations when HAVE_HTTP_TRACE is not defined
int lxb_trace_enable(void) {
  return -1;  // Not supported
}

int lxb_trace_disable(void) {
  return -1;  // Not supported
}

int lxb_trace_is_enabled(void) {
  return 0;  // Always disabled
}
#endif

// ============================================================================

// --- Region 3: Catalog management + event emission ---
#ifdef HAVE_HTTP_TRACE
// ============================================================================
// HTTP/HTTPS Tracing: Catalog & Deep Inspection 
// ============================================================================

/**
 * Initialize catalog shared memory
 * Called once on proxy initialization
 */
static int lxb_catalog_init(void) {
  struct stat st;
  
  // Check if shared memory file exists and has correct size
  if (stat("/dev/shm/loxilb-catalog-config", &st) != 0) {
    log_info("[Catalog] Shared memory not found, deep inspection disabled (will retry on first use)");
    // Not fatal - just means no catalogs configured yet
    memset(g_catalog_configs, 0, sizeof(g_catalog_configs));
    memset(g_service_catalog_map, 0, sizeof(g_service_catalog_map));
    memset(g_catalog_sample_rates, 0, sizeof(g_catalog_sample_rates));
    return 0;
  }
  
  size_t expected_size = sizeof(g_catalog_configs) + sizeof(g_service_catalog_map);
  if (st.st_size < expected_size) {
    log_warn("[Catalog] Shared memory size mismatch (expected=%zu, actual=%ld), skipping", 
             expected_size, st.st_size);
    memset(g_catalog_configs, 0, sizeof(g_catalog_configs));
    memset(g_service_catalog_map, 0, sizeof(g_service_catalog_map));
    memset(g_catalog_sample_rates, 0, sizeof(g_catalog_sample_rates));
    return 0;
  }
  
  int fd = open("/dev/shm/loxilb-catalog-config", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    log_error("[Catalog] Failed to open shared memory (errno=%d)", errno);
    return -1;
  }

  // Calculate total size: catalog configs + service map
  size_t total_size = sizeof(g_catalog_configs) + sizeof(g_service_catalog_map);

  // Memory-map entire shared memory (read-only)
  void *addr = mmap(NULL, total_size, PROT_READ, MAP_SHARED, fd, 0);
  close(fd);

  if (addr == MAP_FAILED) {
    log_error("[Catalog] Failed to mmap shared memory (errno=%d)", errno);
    return -1;
  }

  // Copy catalog configs (first 32KB)
  memcpy(g_catalog_configs, addr, sizeof(g_catalog_configs));
  
  // Copy service-to-catalog map (next 4KB)
  void *service_map_addr = (char *)addr + sizeof(g_catalog_configs);
  memcpy(g_service_catalog_map, service_map_addr, sizeof(g_service_catalog_map));
  
  munmap(addr, total_size);

  // Build sample rate cache
  int enabled_count = 0;
  int service_count = 0;
  for (int i = 0; i < LXB_MAX_CATALOGS; i++) {
    g_catalog_sample_rates[i] = g_catalog_configs[i].sample_rate;
    if (g_catalog_configs[i].enabled) {
      enabled_count++;
      log_info("[Catalog] Loaded catalog[%d]: path='%s' sample_rate=%d%% parser=%d",
               g_catalog_configs[i].id,
               g_catalog_configs[i].path_prefix,
               g_catalog_configs[i].sample_rate,
               g_catalog_configs[i].parser_type);
    }
  }

  // Count service mappings
  for (int i = 0; i < LXB_MAX_SERVICES; i++) {
    if (g_service_catalog_map[i].catalog_id > 0) {
      service_count++;
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("[Catalog] Service mapping[%d]: %08x:%04x proto=%d -> catalog_id=%d",
                i, g_service_catalog_map[i].xip, g_service_catalog_map[i].xport,
                g_service_catalog_map[i].protocol, g_service_catalog_map[i].catalog_id);
#endif
    }
  }

  log_info("[Catalog] Initialized %d enabled catalog(s), %d service mapping(s)", enabled_count, service_count);
  
  // Mark catalogs as loaded if we found any enabled catalogs
  if (enabled_count > 0) {
    atomic_store_explicit(&g_catalogs_loaded, 1, memory_order_release);
  }
  
  return 0;
}

/**
 * Reload catalog configuration from shared memory
 * Called lazily when catalogs weren't available at initialization
 * 
 * @return 0 on success, -1 on failure
 */
static int lxb_catalog_reload(void) {
  struct stat st;
  
  // Check if already loaded
  if (atomic_load_explicit(&g_catalogs_loaded, memory_order_acquire)) {
    return 0; // Already loaded
  }
  
  // Check if shared memory file exists now
  if (stat("/dev/shm/loxilb-catalog-config", &st) != 0) {
    return -1; // Still not available
  }
  
  size_t expected_size = sizeof(g_catalog_configs) + sizeof(g_service_catalog_map);
  if (st.st_size < expected_size) {
    log_warn("[Catalog] Reload: Shared memory size mismatch (expected=%zu, actual=%ld)",
             expected_size, st.st_size);
    return -1;
  }
  
  int fd = open("/dev/shm/loxilb-catalog-config", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return -1; // Failed to open
  }
  
  size_t total_size = sizeof(g_catalog_configs) + sizeof(g_service_catalog_map);
  void *addr = mmap(NULL, total_size, PROT_READ, MAP_SHARED, fd, 0);
  close(fd);
  
  if (addr == MAP_FAILED) {
    log_error("[Catalog] Reload: Failed to mmap shared memory (errno=%d)", errno);
    return -1;
  }
  
  // Copy catalog configs and service mappings
  memcpy(g_catalog_configs, addr, sizeof(g_catalog_configs));
  void *service_map_addr = (char *)addr + sizeof(g_catalog_configs);
  memcpy(g_service_catalog_map, service_map_addr, sizeof(g_service_catalog_map));
  munmap(addr, total_size);
  
  // Build sample rate cache and count catalogs
  int enabled_count = 0;
  for (int i = 0; i < LXB_MAX_CATALOGS; i++) {
    g_catalog_sample_rates[i] = g_catalog_configs[i].sample_rate;
    if (g_catalog_configs[i].enabled) {
      enabled_count++;
      log_info("[Catalog] Reloaded catalog[%d]: path='%s' sample_rate=%d%% parser=%d",
               g_catalog_configs[i].id, g_catalog_configs[i].path_prefix,
               g_catalog_configs[i].sample_rate, g_catalog_configs[i].parser_type);
    }
  }
  
  if (enabled_count > 0) {
    atomic_store_explicit(&g_catalogs_loaded, 1, memory_order_release);
    log_info("[Catalog] Successfully reloaded %d catalog(s)", enabled_count);
    return 0;
  }
  
  return -1; // No catalogs found
}

/**
 * Lookup catalog ID by service key (VIP:port:proto)
 * 
 * @param xip Service VIP (network byte order)
 * @param xport Service port (network byte order)
 * @param protocol Protocol (6=TCP, 17=UDP)
 * @return Catalog ID (1-255) or 0 if no match
 */
uint16_t lxb_lookup_service_catalog(uint32_t xip, uint16_t xport, uint8_t protocol) {
  // Try lazy reload if catalogs weren't loaded at init (race condition fix)
  static _Atomic int reload_attempted = 0;
  if (!atomic_load_explicit(&g_catalogs_loaded, memory_order_acquire)) {
    // Only try reload once to avoid repeated mmap overhead
    if (atomic_exchange(&reload_attempted, 1) == 0) {
      lxb_catalog_reload();
    }
  }
  
  // Linear scan (fast for small service counts < 256)
  for (int i = 0; i < LXB_MAX_SERVICES; i++) {
    lxb_service_catalog_map_t *entry = &g_service_catalog_map[i];
    
    if (entry->catalog_id == 0) {
      continue; // Empty slot
    }
    
    if (entry->xip == xip && entry->xport == xport && entry->protocol == protocol) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("[Catalog] Service lookup matched: %08x:%04x proto=%d -> catalog_id=%d",
                xip, xport, protocol, entry->catalog_id);
#endif
      return entry->catalog_id;
    }
  }
  
  return 0; // No match
}

/**
 * Lookup catalog ID by HTTP path
 * Uses prefix matching (longest match wins)
 * 
 * @param path HTTP path (e.g., "/v1/chat/completions")
 * @param path_len Path length
 * @return Catalog ID (1-255) or 0 if no match
 */
uint16_t lxb_lookup_catalog_id(const char *path, size_t path_len) {
  uint16_t matched_id = 0;
  size_t longest_match = 0;

  // Linear scan (fast for small catalog counts < 256)
  for (int i = 1; i < LXB_MAX_CATALOGS; i++) {
    if (!g_catalog_configs[i].enabled) {
      continue;
    }

    const char *prefix = g_catalog_configs[i].path_prefix;
    size_t prefix_len = strnlen(prefix, LXB_MAX_PATH_LEN);

    if (prefix_len == 0 || prefix_len > path_len) {
      continue;
    }

    // Prefix match check
    if (strncmp(path, prefix, prefix_len) == 0) {
      // Longest match wins (more specific catalogs override generic ones)
      if (prefix_len > longest_match) {
        matched_id = g_catalog_configs[i].id;
        longest_match = prefix_len;
      }
    }
  }

#ifdef HAVE_PROXY_EXTRA_DEBUG
  if (matched_id > 0) {
    log_debug("[Catalog] Matched path='%.*s' → catalog_id=%d", 
              (int)path_len, path, matched_id);
  }
#endif

  return matched_id;
}

/**
 * Sampling decision based on catalog configuration
 * Uses fast random number generation for performance
 * 
 * @param catalog_id Catalog ID (1-255)
 * @return 1 if should sample, 0 otherwise
 */
int lxb_should_sample(uint16_t catalog_id) {
  if (catalog_id == 0 || catalog_id >= LXB_MAX_CATALOGS) {
    return 0;  // Invalid catalog ID
  }

  uint8_t rate = g_catalog_sample_rates[catalog_id];
  if (rate == 0) {
    return 0;  // 0% sampling
  }
  if (rate >= 100) {
    return 1;  // 100% sampling
  }

  // Fast random (uses XOR-shift, good enough for sampling)
  static __thread uint32_t seed = 0;
  if (seed == 0) {
    seed = (uint32_t)time(NULL) ^ (uint32_t)pthread_self();
  }
  seed ^= seed << 13;
  seed ^= seed >> 17;
  seed ^= seed << 5;

  return (seed % 100) < rate;
}

/**
 * Capture HTTP body to tmpfs
 * Creates file: /dev/shm/lxb-body-<span_id>.json (shorter for 32-byte event field)
 * 
 * @param trace_id_hi High 64 bits of trace ID (unused, kept for API compat)
 * @param span_id Span ID (used as filename)
 * @param body Body content
 * @param body_len Body length
 * @param catalog_id Catalog ID (for max_body_size limit)
 * @return 0 on success, -1 on error
 */
int lxb_capture_body_to_tmpfs(uint64_t trace_id_hi, uint64_t span_id,
                                const char *body, size_t body_len,
                                uint16_t catalog_id) {
  char path[256];
  
  // Generate unique filename using only span_id (fits in 32-byte event field)
  snprintf(path, sizeof(path), "/dev/shm/lxb-body-%016lx.json", span_id);

#ifdef HAVE_PROXY_EXTRA_DEBUG
  log_debug("[BodyCapture] Writing body: path=%s size=%zu catalog=%d",
            path, body_len, catalog_id);
#endif

  // Get max body size limit from catalog
  uint32_t max_body_size = 16384;  // Default: 16KB
  if (catalog_id > 0 && catalog_id < LXB_MAX_CATALOGS) {
    max_body_size = g_catalog_configs[catalog_id].max_body_size;
  }

  // Truncate if needed
  size_t write_len = (body_len > max_body_size) ? max_body_size : body_len;
  int truncated = (body_len > max_body_size);

  // Open file (O_EXCL prevents collision)
  int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC | O_EXCL | O_CLOEXEC, 0600);
  if (fd < 0) {
    if (errno == EEXIST) {
      // File exists (collision, very rare) - add random suffix
      log_warn("[BodyCapture] File collision: %s (trying with retry)", path);
      snprintf(path, sizeof(path), "/dev/shm/lxb-body-%016lx-%d.json",
               span_id, rand() % 10000);
      fd = open(path, O_CREAT | O_WRONLY | O_TRUNC | O_EXCL | O_CLOEXEC, 0600);
      if (fd < 0) {
        log_error("[BodyCapture] Failed to create file after retry: %s (errno=%d)", 
                  path, errno);
        return -1;
      }
    } else {
      log_error("[BodyCapture] Failed to create file: %s (errno=%d)", path, errno);
      return -1;
    }
  }

  // Write body
  ssize_t written = write(fd, body, write_len);
  close(fd);

  if (written != (ssize_t)write_len) {
    log_error("[BodyCapture] Failed to write body: %s (written=%ld expected=%zu errno=%d)",
              path, written, write_len, errno);
    unlink(path);  // Clean up partial file
    return -1;
  }

#ifdef HAVE_PROXY_EXTRA_DEBUG
  log_debug("[BodyCapture] Success: path=%s written=%zu truncated=%d",
            path, write_len, truncated);
#endif

  return truncated ? 1 : 0;  // Return 1 if truncated
}

// ============================================================================
// HTTP/HTTPS Tracing: Event Emission Helpers 
// ============================================================================

/* get_timestamp_ns moved to sockproxy_metrics.c (always-compiled) so the TTFB
 * histogram resolves it in default builds — see note there. Defining it here too
 * would double-define the symbol when HAVE_HTTP_TRACE is on. */

/**
 * PHASE 1: Hybrid Body Capture for Tracing
 * 
 * Captures HTTP request/response body for protocol-specific deep inspection.
 * Uses hybrid approach: inline storage (280 bytes) + file fallback for large payloads.
 * 
 * Design:
 *   - Fast path (body <= 280 bytes): Inline storage only, zero file I/O
 *   - Slow path (body > 280 bytes): Inline preview + file storage
 *   - Safety guards: 64KB cap, tmpfs space check
 * 
 * @param pfe Connection entry containing cache chain
 * @param evt Event structure to populate with body data
 * @return 0 on success, -1 on error
 */
static int capture_body_for_tracing(proxy_fd_ent_t *pfe, lxb_trace_event_t *evt) {
  if (!pfe->cache_head) {
    evt->body_len = 0;
    evt->body_truncated = 0;
    evt->has_body_file = 0;
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[TRACE_BODY_SKIP] fd=%d: No cache, skipping body capture", pfe->fd);
#endif
    return 0;
  }
  
  // Calculate total body size across cache chain (capped at 64KB for safety)
  size_t total_len = 0;
  struct proxy_cache *cache = pfe->cache_head;
  while (cache && total_len < 65536) {
    total_len += cache->len;
    cache = cache->next;
  }
  
  // ALWAYS copy inline preview (first 280 bytes)
  cache = pfe->cache_head;
  size_t copied = 0;
  while (cache && copied < 280) {
    size_t to_copy = (cache->len < (280 - copied)) ? cache->len : (280 - copied);
    memcpy(evt->body_data + copied, cache->cache, to_copy);
    copied += to_copy;
    cache = cache->next;
  }
  evt->body_len = copied;
  evt->body_truncated = (total_len > 280);
  
#ifdef HAVE_PROXY_EXTRA_DEBUG
  log_debug("[TRACE_BODY_INLINE] fd=%d: Captured %zu bytes inline (total=%zu truncated=%d)",
            pfe->fd, copied, total_len, evt->body_truncated);
#endif
  
  // Set protocol hints (cheap checks for parser dispatch)
  // Note: content_type tracking would require parser modifications, skip for now
  evt->is_json = 0;  // Will be detected by Go parser from Content-Type header
  evt->is_streaming = pfe->is_chunked_response;
  
  // ONLY write file if body > 280 bytes AND size is reasonable
  if (evt->body_truncated && total_len <= 65536) {
    // Safety: Check tmpfs available space (prevent exhaustion)
    struct statvfs vfs;
    if (statvfs("/dev/shm", &vfs) == 0) {
      unsigned long available = vfs.f_bavail * vfs.f_frsize;
      if (available < (10 * 1024 * 1024)) {  // Less than 10MB free
        log_warn("[TRACE] tmpfs low on space (%lu MB), skipping file storage",
                 available / (1024 * 1024));
        evt->body_truncated = 0;  // Force parser to use inline data only
        return 0;
      }
    }
    
    // Generate unique filename: trace_id + span_id + timestamp + thread_id
    char filename[64];
    snprintf(filename, sizeof(filename), 
             "loxilb-trace-%016lx-%016lx-%lu-%d.body",
             pfe->trace_id_hi, pfe->root_span_id, 
             get_timestamp_ns(), gettid());
    
    char full_path[512];
    snprintf(full_path, sizeof(full_path), "/dev/shm/%s", filename);
    
    // Create file with O_CLOEXEC to prevent fd leaks
    int fd = open(full_path, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0600);
    if (fd >= 0) {
      // Write full body from cache chain
      cache = pfe->cache_head;
      size_t total_written = 0;
      while (cache && total_written < 65536) {
        ssize_t written = write(fd, cache->cache, cache->len);
        if (written > 0) {
          total_written += written;
        }
        cache = cache->next;
      }
      close(fd);
      
      // Store RELATIVE filename (Go will prefix with /dev/shm)
      strncpy(evt->body_file_path, filename, sizeof(evt->body_file_path) - 1);
      evt->body_file_path[sizeof(evt->body_file_path) - 1] = '\0';
      evt->has_body_file = 1;
      
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("[TRACE_BODY_FILE] fd=%d: Wrote %zu bytes to %s (inline=%u, truncated=%u)",
                pfe->fd, total_written, full_path, evt->body_len, evt->body_truncated);
#endif
    } else {
      // File creation failed - log and fall back to inline only
      log_warn("[TRACE] Failed to create body file: %s (errno=%d %s)",
               full_path, errno, strerror(errno));
      evt->body_truncated = 0;  // Force parser to use inline data
      evt->has_body_file = 0;
    }
  } else if (total_len > 65536) {
    // Body too large - store inline preview only, mark truncated but no file
    log_debug("[TRACE] Body too large (%zu bytes), storing inline preview only", total_len);
    evt->body_truncated = 1;
    evt->has_body_file = 0;
  }
  
  return 0;
}

/**
 * PHASE 1: TTL-based Trace File Cleanup Thread
 * 
 * Periodically scans /dev/shm for expired trace body files and removes them.
 * Runs every 60 seconds, removes files older than 5 minutes.
 */
void *trace_file_cleanup_thread(void *arg) {
  (void)arg;
  
  while (proxy_struct->run) {
    DIR *dir = opendir("/dev/shm");
    if (!dir) {
      sleep(60);
      continue;
    }
    
    time_t now = time(NULL);
    struct dirent *entry;
    int removed_count = 0;
    
    while ((entry = readdir(dir)) != NULL) {
      // Process both old and new body file patterns
      if (strncmp(entry->d_name, "loxilb-trace-", 13) != 0 &&
          strncmp(entry->d_name, "lxb-body-", 9) != 0) {
        continue;
      }
      
      char path[512];
      snprintf(path, sizeof(path), "/dev/shm/%s", entry->d_name);
      
      struct stat st;
      if (stat(path, &st) == 0) {
        if ((now - st.st_mtime) > TRACE_FILE_TTL_SEC) {
          if (unlink(path) == 0) {
            removed_count++;
#ifdef HAVE_PROXY_EXTRA_DEBUG
            log_debug("[TRACE_CLEANUP] Removed expired file: %s (age=%ld sec)",
                      entry->d_name, now - st.st_mtime);
#endif
          }
        }
      }
    }
    
    closedir(dir);
    
    if (removed_count > 0) {
      log_info("[TRACE_CLEANUP] Removed %d expired trace files", removed_count);
    }
    
    // Sleep for 60 seconds before next cleanup cycle
    sleep(60);
  }
  
  return NULL;
}

/**
 * Emit trace event to ring buffer
 * 
 * @param pfe Connection entry
 * @param event_type Event type (REQ_START, REQ_END, etc.)
 * @param duration_us Duration in microseconds (for *_END events)
 */
void emit_trace_event(proxy_fd_ent_t *pfe, uint8_t event_type, uint32_t duration_us) {
  if (!is_tracing_enabled()) {
    return;
  }
  
#ifdef HAVE_PROXY_EXTRA_DEBUG
  const char *event_names[] = {
    [LXB_EVENT_REQ_START] = "REQ_START",
    [LXB_EVENT_REQ_END] = "REQ_END",
    [LXB_EVENT_UP_START] = "UP_START",
    [LXB_EVENT_UP_END] = "UP_END",
    [LXB_EVENT_TLS_HS] = "TLS_HS",
    [LXB_EVENT_STREAM_MARK] = "STREAM_MARK"
  };
  log_debug("[TRACE_EVENT_EMIT] fd=%d event=%s catalog_id=%d duration=%uus",
            pfe->fd,
            event_type < sizeof(event_names)/sizeof(event_names[0]) ? event_names[event_type] : "UNKNOWN",
            pfe->catalog_id, duration_us);
#endif
  
  lxb_ring_t *ring = lxb_ring_get();
  if (!ring) {
    return;  // Ring not initialized for this thread
  }
  
  // If no traceparent header and this is the first event (REQ_START), generate new trace ID
  // For subsequent events (UP_START, UP_END, etc.), reuse the existing trace_id
  if (!pfe->has_traceparent && event_type == LXB_EVENT_REQ_START) {
    lxb_gen_trace_id(&pfe->trace_id_hi, &pfe->trace_id_lo);
    pfe->parent_span_id = 0;  // No parent (root span)
    pfe->trace_flags = 0x01;  // Sampled by default
    pfe->has_traceparent = 1;  // Mark as having trace context (self-generated)
  }
  
  // Generate or reuse span ID for this event
  uint64_t span_id;
  if (event_type == LXB_EVENT_REQ_START) {
    // Generate new span ID for HTTP request and store as root_span_id for REQ_END
    span_id = lxb_gen_span_id();
    pfe->root_span_id = span_id;
  } else if (event_type == LXB_EVENT_REQ_END) {
    // Reuse span ID from REQ_START (stored in root_span_id)
    span_id = pfe->root_span_id;
  } else if (event_type == LXB_EVENT_UP_START) {
    // Generate new span ID for upstream connection and store for UP_END
    span_id = lxb_gen_span_id();
    pfe->upstream_span_id = span_id;
  } else if (event_type == LXB_EVENT_UP_END) {
    // Reuse span ID from UP_START
    span_id = pfe->upstream_span_id;
  } else {
    // Generate new span ID for other events (TLS_HS, STREAM_MARK, etc.)
    span_id = lxb_gen_span_id();
  }
  
  // Build event
  lxb_trace_event_t evt = {0};
  evt.trace_id_hi = pfe->trace_id_hi;
  evt.trace_id_lo = pfe->trace_id_lo;
  evt.span_id = span_id;
  evt.parent_span_id = (event_type == LXB_EVENT_REQ_START) ? pfe->parent_span_id : pfe->root_span_id;
  evt.timestamp_ns = get_timestamp_ns();
  evt.event_type = event_type;
  evt.flags = 0;
  if (pfe->trace_flags & 0x01) {
    evt.flags |= LXB_FLAG_SAMPLED;
  }
  evt.catalog_id = pfe->catalog_id;  // Use catalog ID from handle_on_message_complete()
  evt.duration_us = duration_us;
  
  // HTTP attributes - use stored values that persist beyond parser lifecycle
  // Use pfe->http_method (stored at request time) instead of pfe->parser.method
  // which may be reset/cleared by the time REQ_END is emitted
  if (pfe->http_method[0] != '\0') {
    strncpy(evt.http_method, pfe->http_method, sizeof(evt.http_method) - 1);
    evt.http_method[sizeof(evt.http_method) - 1] = '\0';
  }
  // Capture HTTP version from parser
  evt.http_major = pfe->parser.http_major;
  evt.http_minor = pfe->parser.http_minor;
  strncpy(evt.http_target, pfe->request_path, sizeof(evt.http_target) - 1);
  strncpy(evt.http_host, pfe->host_url, sizeof(evt.http_host) - 1);
  
  // For REQ_END events, use stored response values (captured when backend responded)
  if (event_type == LXB_EVENT_REQ_END && pfe->odir == 0) {
    // Prefer http_status_code (error codes 502/500/507) if set,
    // otherwise use response_status_code (normal backend responses)
    evt.http_status_code = pfe->http_status_code ? pfe->http_status_code : pfe->response_status_code;
    evt.content_length = pfe->response_content_length;
    
    // PHASE 1: Capture body for deep inspection (hybrid approach)
    // Only capture for REQ_END events on client connections (responses going to client)
    if (pfe->cache_head && pfe->catalog_id > 0) {
      capture_body_for_tracing(pfe, &evt);
#ifdef HAVE_PROXY_EXTRA_DEBUG
      if (evt.has_body_file) {
        log_debug("[TRACE_BODY_CAPTURED] fd=%d: body_len=%u truncated=%u file=%s",
                  pfe->fd, evt.body_len, evt.body_truncated, evt.body_file_path);
      } else if (evt.body_len > 0) {
        log_debug("[TRACE_BODY_INLINE] fd=%d: body_len=%u (inline only)",
                  pfe->fd, evt.body_len);
      }
#endif
    }
    
    // Include body file path if body was captured
    // NOTE: Store full path in event (event field is 256 bytes in modified struct)
    if (pfe->has_body_file && pfe->body_file_path[0] != '\0') {
      evt.has_body_file = 1;
      strncpy(evt.body_file_path, pfe->body_file_path, sizeof(evt.body_file_path) - 1);
      evt.body_file_path[sizeof(evt.body_file_path) - 1] = '\0';
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("[TRACE_REQ_END_BODY] fd=%d: Including body_file_path=%s in REQ_END event",
                pfe->fd, evt.body_file_path);
#endif
    }
  } else if (event_type == LXB_EVENT_REQ_START && pfe->odir == 0) {
    // For REQ_START events (HTTP request), copy the EXISTING body file path
    evt.http_status_code = 0;  // No status code for requests
    evt.content_length = pfe->http_content_length;
    
    // CRITICAL: Use the path from the FIRST body capture (with span_id=0)
    // This file ALREADY EXISTS when the event is emitted. The body will be
    // re-captured with the real span_id later in on_http_message_complete.
    if (pfe->has_body_file && pfe->body_file_path[0] != '\0') {
      evt.has_body_file = 1;
      strncpy(evt.body_file_path, pfe->body_file_path, sizeof(evt.body_file_path) - 1);
      evt.body_file_path[sizeof(evt.body_file_path) - 1] = '\0';
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("[TRACE_REQ_START_BODY] fd=%d: Using captured body_file_path=%s (file exists now)",
                pfe->fd, evt.body_file_path);
#endif
    }
  } else {
    // For other events: prefer http_status_code (error codes 502/500/507) if set,
    // otherwise fall back to parser status (normal backend responses)
    evt.http_status_code = pfe->http_status_code ? pfe->http_status_code : pfe->parser.status_code;
    evt.content_length = pfe->http_content_length;
  }

#ifdef HAVE_PROXY_EXTRA_DEBUG
  log_debug("[TRACE_HTTP_HEADERS] fd=%d event_type=%d | "
            "method='%s' target='%s' host='%s' | "
            "status=%u content_length=%u",
            pfe->fd, event_type,
            evt.http_method, evt.http_target, evt.http_host,
            evt.http_status_code, evt.content_length);
#endif
  
  // Connection attributes (client IP/port)
  // For frontend connections (odir=0), get from socket; for backend (odir=1), use stored values
  if (pfe->odir == 0) {
    struct sockaddr_in peer_addr;
    socklen_t addr_len = sizeof(peer_addr);
    if (getpeername(pfe->fd, (struct sockaddr*)&peer_addr, &addr_len) == 0) {
      evt.client_ip = peer_addr.sin_addr.s_addr;
      evt.client_port = ntohs(peer_addr.sin_port);
      // Store for later use in backend connections
      pfe->client_ip = evt.client_ip;
      pfe->client_port = evt.client_port;
#ifdef HAVE_PROXY_EXTRA_DEBUG
      char client_ip_str[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &peer_addr.sin_addr, client_ip_str, sizeof(client_ip_str));
      log_debug("[TRACE_CLIENT_CONN] fd=%d event_type=%d | "
                "client=%s:%u",
                pfe->fd, event_type,
                client_ip_str, evt.client_port);
#endif
    }
  } else {
    // Backend connection: use stored client IP/port from frontend
    evt.client_ip = pfe->client_ip;
    evt.client_port = pfe->client_port;
#ifdef HAVE_PROXY_EXTRA_DEBUG
    char client_ip_str[INET_ADDRSTRLEN];
    struct in_addr addr = { .s_addr = pfe->client_ip };
    inet_ntop(AF_INET, &addr, client_ip_str, sizeof(client_ip_str));
    log_debug("[TRACE_CLIENT_CONN] fd=%d event_type=%d | "
              "client=%s:%u",
              pfe->fd, event_type,
              client_ip_str, evt.client_port);
#endif
  }
  
  // TLS attributes - detect frontend vs backend SSL
  // Frontend TLS: pfe->odir == 0 && pfe->ssl (HTTPS→HTTP or HTTPS→HTTPS)
  // Backend TLS: pfe->odir == 1 && pfe->ssl (HTTP→HTTPS or HTTPS→HTTPS)
  if (pfe->ssl) {
    evt.tls_version = SSL_version(pfe->ssl);
    const SSL_CIPHER *cipher = SSL_get_current_cipher(pfe->ssl);
    if (cipher) {
      evt.tls_cipher = SSL_CIPHER_get_id(cipher) & 0xFFFF;
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("[TRACE_TLS_ATTRS] fd=%d event_type=%d odir=%d | "
                "tls_version=0x%04x cipher=0x%04x cipher_name='%s'",
                pfe->fd, event_type, pfe->odir,
                evt.tls_version, evt.tls_cipher,
                SSL_CIPHER_get_name(cipher));
#endif
    }
    
    // Set appropriate TLS flag based on connection direction
    if (event_type == LXB_EVENT_TLS_HS) {
      if (pfe->odir == 0) {
        evt.flags |= LXB_FLAG_TLS_FRONTEND;  // Client-side TLS
      } else {
        evt.flags |= LXB_FLAG_TLS_BACKEND;   // Backend-side TLS
      }
    }
  }
  
  // Backend attributes (for upstream events)
  // For backend connections (odir=1), pfe->fd is the backend socket
  // For connection failures (odir=0 but backend_ip set), include attempted backend info
  if (event_type == LXB_EVENT_UP_START || event_type == LXB_EVENT_UP_END) {
    evt.backend_id = pfe->ep_num;
    if (pfe->odir == 1 && pfe->fd > 0) {
      // Use pfe->fd (the backend socket itself), not rfd[0] (which points to frontend)
      struct sockaddr_in backend_addr;
      socklen_t backend_len = sizeof(backend_addr);
      if (getpeername(pfe->fd, (struct sockaddr*)&backend_addr, &backend_len) == 0) {
        evt.backend_ip = backend_addr.sin_addr.s_addr;
        evt.backend_port = ntohs(backend_addr.sin_port);
#ifdef HAVE_PROXY_EXTRA_DEBUG
        char backend_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &backend_addr.sin_addr, backend_ip_str, sizeof(backend_ip_str));
        log_debug("[TRACE_BACKEND_CONN] fd=%d event_type=%d odir=%d | "
                  "backend_id=%u backend=%s:%u",
                  pfe->fd, event_type, pfe->odir,
                  evt.backend_id, backend_ip_str, evt.backend_port);
#endif
      }
    }
  } else if (event_type == LXB_EVENT_REQ_END && pfe->backend_ip != 0) {
    // Connection failure: Include attempted backend info in REQ_END event
    evt.backend_id = pfe->ep_num;
    evt.backend_ip = pfe->backend_ip;
    evt.backend_port = pfe->backend_port;
#ifdef HAVE_PROXY_EXTRA_DEBUG
    char backend_ip_str[INET_ADDRSTRLEN];
    struct in_addr addr = { .s_addr = pfe->backend_ip };
    inet_ntop(AF_INET, &addr, backend_ip_str, sizeof(backend_ip_str));
    log_debug("[TRACE_BACKEND_CONN_FAILED] fd=%d event_type=REQ_END odir=%d | "
              "backend_id=%u attempted_backend=%s:%u (connection failed)",
              pfe->fd, pfe->odir,
              evt.backend_id, backend_ip_str, evt.backend_port);
#endif
  }
  
  // Store request start timestamp for duration calculation
  if (event_type == LXB_EVENT_REQ_START) {
    pfe->req_start_ts = evt.timestamp_ns;
  }
  
  // Session Tracking: Capture session header name and value (for --session-header-name support)
  // This enables session-level tracing for OpenAI/MCP APIs with custom session headers
  if (pfe->session_header_name[0] != '\0') {
    strncpy(evt.session_header_name, pfe->session_header_name, sizeof(evt.session_header_name) - 1);
    evt.session_header_name[sizeof(evt.session_header_name) - 1] = '\0';
  }
  
  if (pfe->has_custom_session_header && pfe->custom_session_header_value[0] != '\0') {
    strncpy(evt.session_header_value, pfe->custom_session_header_value, sizeof(evt.session_header_value) - 1);
    evt.session_header_value[sizeof(evt.session_header_value) - 1] = '\0';
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[TRACE_SESSION] fd=%d event_type=%d | "
              "session_header='%s' session_value='%s'",
              pfe->fd, event_type,
              evt.session_header_name, evt.session_header_value);
#endif
  }
  
  // Conversation ID tracking (for OpenAI/MCP conversation routing)
  if (pfe->has_conv_id && pfe->conversation_id[0] != '\0') {
    strncpy(evt.conversation_id, pfe->conversation_id, sizeof(evt.conversation_id) - 1);
    evt.conversation_id[sizeof(evt.conversation_id) - 1] = '\0';
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[TRACE_CONVERSATION] fd=%d event_type=%d | "
              "conversation_id='%s'",
              pfe->fd, event_type,
              evt.conversation_id);
#endif
  }
  
  // Push to ring buffer
#ifdef HAVE_PROXY_EXTRA_DEBUG
  log_debug("[TRACE_EVENT_PUSH] fd=%d event_type=%d | "
            "Pushing to ring: method='%s' target='%s' host='%s' status=%u "
            "session='%s:%s' conv_id='%s'",
            pfe->fd, event_type,
            evt.http_method, evt.http_target, evt.http_host,
            evt.http_status_code,
            evt.session_header_name, evt.session_header_value, evt.conversation_id);
#endif
  if (lxb_ring_push(ring, &evt) < 0) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[HTTP_TRACE] Ring buffer full, event dropped");
#endif
  }
}
#endif
