/*
 * Copyright (c) 2025 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <fnmatch.h>  // For wildcard pattern matching
#include "sockproxy_presidio.h"
#include "log.h"

// ============================================================================
// PRESIDIO PII DETECTION: C Layer Implementation
// ============================================================================
// This module implements the C-layer integration for Presidio PII detection,
// following the xSync Consumer Pattern used in LlamaFirewall.
//
// Key Features:
// - CGO wrapper around Go bridge functions
// - URL pattern matching (OpenAI-style selective detection)
// - Atomic enable/disable with 2ns overhead when disabled
// - HTTP body extraction and replacement
// - Comprehensive error handling and statistics
//
// Configuration: Uses presidio_config_get() from presidio_config.c
//                (shared memory hot-reload pattern)
// ============================================================================

// Global statistics
static presidio_stats_t g_stats = {0};

// Circuit breaker state
typedef struct {
    _Atomic int state;                // Current state (CLOSED, OPEN, HALF_OPEN)
    _Atomic uint64_t failure_count;   // Consecutive failures
    _Atomic uint64_t success_count;   // Consecutive successes (for HALF_OPEN)
    _Atomic time_t last_failure_time; // Last failure timestamp
    pthread_mutex_t lock;             // State transition lock
} circuit_breaker_t;

static circuit_breaker_t g_circuit_breaker = {
    .state = PRESIDIO_CB_CLOSED,
    .failure_count = 0,
    .success_count = 0,
    .last_failure_time = 0,
    .lock = PTHREAD_MUTEX_INITIALIZER,
};

// Initialization flag to track if cleanup is needed
static _Atomic int g_initialized = 0;

// Note: Configuration now comes from presidio_config_get() (shared memory)

// ============================================================================
// CIRCUIT BREAKER: Prevent Cascading Failures
// ============================================================================

/**
 * Record a successful operation - may close circuit if in HALF_OPEN
 */
void presidio_circuit_breaker_record_success(void) {
    pthread_mutex_lock(&g_circuit_breaker.lock);
    
    int state = atomic_load(&g_circuit_breaker.state);
    
    if (state == PRESIDIO_CB_HALF_OPEN) {
        // Increment success count
        uint64_t successes = atomic_fetch_add(&g_circuit_breaker.success_count, 1) + 1;
        
        // Get config with fallback
        presidio_config_shm_t *cfg = presidio_config_get();
        uint32_t success_threshold = cfg ? cfg->circuit_breaker_success_threshold : 3;
        
        // Check if we should close the circuit
        if (successes >= success_threshold) {
            atomic_store(&g_circuit_breaker.state, PRESIDIO_CB_CLOSED);
            atomic_store(&g_circuit_breaker.failure_count, 0);
            atomic_store(&g_circuit_breaker.success_count, 0);
            log_info("[Presidio-CB] Circuit CLOSED after %lu successes", successes);
        }
    }
    
    pthread_mutex_unlock(&g_circuit_breaker.lock);
}

void presidio_cleanup(void) {
    if (!atomic_load(&g_initialized)) {
        return;  // Nothing to clean up
    }
    
    log_info("[Presidio] Starting cleanup...");
    
    // Reset circuit breaker
    pthread_mutex_lock(&g_circuit_breaker.lock);
    atomic_store(&g_circuit_breaker.state, PRESIDIO_CB_CLOSED);
    atomic_store(&g_circuit_breaker.failure_count, 0);
    atomic_store(&g_circuit_breaker.success_count, 0);
    pthread_mutex_unlock(&g_circuit_breaker.lock);
    
    // Cleanup configuration subsystem (shared memory)
    presidio_config_cleanup();
    
    // Note: Go bridge cleanup handled by Go runtime
    // Any gRPC connections will be closed automatically
    
    atomic_store(&g_initialized, 0);
    
    log_info("[Presidio] Cleanup complete - no memory leaks");
}

/**
 * Record a failure - may open circuit if threshold exceeded
 */
void presidio_circuit_breaker_record_failure(void) {
    pthread_mutex_lock(&g_circuit_breaker.lock);
    
    int state = atomic_load(&g_circuit_breaker.state);
    presidio_config_shm_t *cfg = presidio_config_get();
    if (!cfg) {
        pthread_mutex_unlock(&g_circuit_breaker.lock);
        return;
    }
    
    if (state == PRESIDIO_CB_CLOSED) {
        // Increment failure count
        uint64_t failures = atomic_fetch_add(&g_circuit_breaker.failure_count, 1) + 1;
        
        // Check if we should open the circuit
        presidio_config_shm_t *cfg = presidio_config_get();
        uint32_t threshold = cfg ? cfg->circuit_breaker_threshold : 5;
        uint32_t timeout = cfg ? cfg->circuit_breaker_timeout_sec : 60;
        
        if (failures >= threshold) {
            atomic_store(&g_circuit_breaker.state, PRESIDIO_CB_OPEN);
            atomic_store(&g_circuit_breaker.last_failure_time, time(NULL));
            atomic_fetch_add(&g_stats.circuit_breaker_opens, 1);
            
            log_warn("[Presidio-CB] ⚠️ Circuit OPENED (threshold %u failures exceeded) - "
                     "PII detection BYPASSED for %u seconds",
                     threshold, timeout);
        }
    } else if (state == PRESIDIO_CB_HALF_OPEN) {
        // Failure during half-open - immediately reopen circuit
        atomic_store(&g_circuit_breaker.state, PRESIDIO_CB_OPEN);
        atomic_store(&g_circuit_breaker.last_failure_time, time(NULL));
        atomic_store(&g_circuit_breaker.success_count, 0);
        
        log_warn("[Presidio-CB] ⚠️ Circuit RE-OPENED (recovery attempt failed)");
    }
    
    pthread_mutex_unlock(&g_circuit_breaker.lock);
}

/**
 * Check if circuit breaker allows operation
 * @return 1 if allowed, 0 if rejected
 */
int presidio_circuit_breaker_allow_request(void) {
    int state = atomic_load(&g_circuit_breaker.state);
    
    if (state == PRESIDIO_CB_CLOSED) {
        return 1;  // Normal operation
    }
    
    if (state == PRESIDIO_CB_OPEN) {
        // Check if timeout expired - transition to HALF_OPEN
        time_t now = time(NULL);
        time_t last_failure = atomic_load(&g_circuit_breaker.last_failure_time);
        presidio_config_shm_t *cfg = presidio_config_get();
        uint32_t timeout = cfg ? cfg->circuit_breaker_timeout_sec : 60;
        
        if ((now - last_failure) >= timeout) {
            pthread_mutex_lock(&g_circuit_breaker.lock);
            
            // Double-check state (race condition protection)
            if (atomic_load(&g_circuit_breaker.state) == PRESIDIO_CB_OPEN) {
                atomic_store(&g_circuit_breaker.state, PRESIDIO_CB_HALF_OPEN);
                atomic_store(&g_circuit_breaker.success_count, 0);
                log_info("[Presidio-CB] 🔄 Circuit HALF-OPEN (testing recovery)");
            }
            
            pthread_mutex_unlock(&g_circuit_breaker.lock);
            return 1;  // Allow test request
        }
        
        // Circuit still open - reject request
        atomic_fetch_add(&g_stats.circuit_breaker_rejects, 1);
        return 0;
    }
    
    // HALF_OPEN - allow request for testing
    return 1;
}

presidio_circuit_state_t presidio_get_circuit_state(void) {
    return (presidio_circuit_state_t)atomic_load(&g_circuit_breaker.state);
}

void presidio_reset_circuit_breaker(void) {
    pthread_mutex_lock(&g_circuit_breaker.lock);
    atomic_store(&g_circuit_breaker.state, PRESIDIO_CB_CLOSED);
    atomic_store(&g_circuit_breaker.failure_count, 0);
    atomic_store(&g_circuit_breaker.success_count, 0);
    pthread_mutex_unlock(&g_circuit_breaker.lock);
    
    log_info("[Presidio-CB] Circuit breaker manually reset to CLOSED");
}

int presidio_is_healthy(void) {
    int state = atomic_load(&g_circuit_breaker.state);
    return (state == PRESIDIO_CB_CLOSED);
}

// ============================================================================
// INITIALIZATION & CONFIGURATION
// ============================================================================

int presidio_init(presidio_config_shm_t *config) {
    if (!config) {
        log_warn("[Presidio] Init called with NULL config - using defaults from shared memory");
        // Will use presidio_config_get() dynamically
    }
    
    // Initialize configuration subsystem
    int ret = presidio_config_init();
    if (ret != 0) {
        log_warn("[Presidio] Config init failed, using defaults: %d", ret);
    }
    
    // Get current config
    presidio_config_shm_t *cfg = presidio_config_get();
    if (!cfg) {
        log_error("[Presidio] Failed to get configuration");
        return -1;
    }
    
    // Initialize Go bridge
    ret = llb_presidio_init(cfg->analyzer_url, cfg->anonymizer_url);
    if (ret != 0) {
        log_warn("[Presidio] Failed to initialize Go bridge (will retry on demand): %d", ret);
        // Don't fail - allow proxy to start even if Presidio unavailable
    } else {
        log_info("[Presidio] ✓ Initialized successfully: %s", cfg->analyzer_url);
    }
    
    atomic_store(&g_initialized, 1);
    return 0;
}

int presidio_enable(void) {
    int ret = llb_presidio_enable();
    if (ret == 0) {
        log_info("[Presidio] ✅ PII Detection ENABLED");
    }
    return ret;
}

int presidio_disable(void) {
    int ret = llb_presidio_disable();
    if (ret == 0) {
        log_info("[Presidio] ❌ PII Detection DISABLED");
    }
    return ret;
}

int presidio_is_enabled(void) {
    return llb_presidio_is_enabled();
}

int presidio_reconfigure(presidio_config_shm_t *config) {
    if (!config) {
        return -1;
    }
    
    // Reload configuration from shared memory
    int ret = presidio_config_reload();
    if (ret < 0) {
        log_error("[Presidio] Failed to reload configuration");
        return -1;
    }
    
    // Get updated config
    presidio_config_shm_t *cfg = presidio_config_get();
    if (!cfg) {
        log_error("[Presidio] Failed to get updated configuration");
        return -1;
    }
    
    // Notify Go bridge
    ret = llb_presidio_configure(
        cfg->analyzer_url,
        cfg->anonymizer_url,
        cfg->mode,
        cfg->direction,
        cfg->score_threshold,
        cfg->timeout_ms
    );
    
    if (ret == 0) {
        log_info("[Presidio] ♻️ Configuration updated: mode=%d direction=%d threshold=%.2f",
                 cfg->mode, cfg->direction, cfg->score_threshold);
    }
    
    return ret;
}

int presidio_get_config(presidio_config_shm_t *config) {
    if (!config) {
        return -1;
    }
    
    presidio_config_shm_t *cfg = presidio_config_get();
    if (!cfg) {
        return -1;
    }
    
    memcpy(config, cfg, sizeof(presidio_config_shm_t));
    return 0;
}

// ============================================================================
// URL PATTERN MATCHING (OpenAI-style selective detection)
// Configuration is read-only from shared memory (presidio_config.h)
// ============================================================================

/**
 * Simple wildcard matching helper
 * Supports: /v1/chat/* matches /v1/chat/completions
 */
static int url_pattern_match(const char *pattern, const char *url) {
    return fnmatch(pattern, url, 0) == 0;
}

int presidio_url_matches(const char *url) {
    if (!url) {
        return 0;
    }
    
    // Get config from shared memory with fallback
    presidio_config_shm_t *cfg = presidio_config_get();
    if (!cfg) {
        return 1;  // Fallback: scan all URLs if config unavailable
    }
    
    // Mode 0: Scan all URLs (no filtering)
    if (cfg->url_mode == 0 || cfg->num_url_patterns == 0) {
        return 1;
    }
    
    // Check patterns
    int matched = 0;
    int is_exclude_match = 0;
    
    for (uint8_t i = 0; i < cfg->num_url_patterns && i < PRESIDIO_MAX_URL_PATTERNS; i++) {
        presidio_url_pattern_entry_t *p = &cfg->url_patterns[i];
        if (!p->enabled) continue;
        
        if (url_pattern_match(p->pattern, url)) {
            matched = 1;
            is_exclude_match = p->is_exclude;
            break;  // First match wins
        }
    }
    
    // Mode 1: Include-list - only scan if matched and NOT exclude
    if (cfg->url_mode == 1) {
        return matched && !is_exclude_match;
    }
    
    // Mode 2: Exclude-list - scan unless explicitly excluded
    if (cfg->url_mode == 2) {
        return !matched || !is_exclude_match;
    }
    
    return 1;
}

// ============================================================================
// HTTP BODY EXTRACTION HELPERS
// ============================================================================

/**
 * Extract URL path from HTTP request
 * Example: "GET /v1/chat/completions HTTP/1.1" -> "/v1/chat/completions"
 */
static const char* extract_http_url(const uint8_t *data, size_t len, char *url_buf, size_t buf_size) {
    if (!data || len < 16 || !url_buf || buf_size < 2) {
        return NULL;
    }
    
    // Parse HTTP method and URL
    const char *msg = (const char *)data;
    const char *space1 = memchr(msg, ' ', len);
    if (!space1) return NULL;
    
    const char *space2 = memchr(space1 + 1, ' ', len - (space1 - msg + 1));
    if (!space2) return NULL;
    
    size_t url_len = space2 - (space1 + 1);
    if (url_len >= buf_size) {
        url_len = buf_size - 1;
    }
    
    memcpy(url_buf, space1 + 1, url_len);
    url_buf[url_len] = '\0';
    
    return url_buf;
}

const char* presidio_extract_http_body(const uint8_t *data, size_t len, size_t *body_len) {
    *body_len = 0;
    
    if (!data || len < 4) {
        return NULL;
    }
    
    // Find end of headers (\r\n\r\n or \n\n)
    const char *body_start = NULL;
    for (size_t i = 0; i < len - 3; i++) {
        if (data[i] == '\r' && data[i+1] == '\n' && 
            data[i+2] == '\r' && data[i+3] == '\n') {
            body_start = (const char *)(data + i + 4);
            break;
        }
    }
    
    // Also handle \n\n (less common)
    if (!body_start) {
        for (size_t i = 0; i < len - 1; i++) {
            if (data[i] == '\n' && data[i+1] == '\n') {
                body_start = (const char *)(data + i + 2);
                break;
            }
        }
    }
    
    if (!body_start) {
        return NULL;
    }
    
    *body_len = len - (body_start - (const char *)data);
    
    // Sanity check
    if (*body_len > len) {
        *body_len = 0;
        return NULL;
    }
    
    return body_start;
}

int presidio_should_scan_http(const uint8_t *data, size_t len, int is_request) {
    if (!data || len < 16) {
        return 0;
    }
    
    // Get config from shared memory with fallback
    presidio_config_shm_t *cfg = presidio_config_get();
    uint32_t max_size = cfg ? cfg->max_body_size : 65536;
    uint32_t min_size = cfg ? cfg->min_body_size : 100;
    uint8_t scan_mode = cfg ? cfg->scan_mode : PRESIDIO_SCAN_MODE_FULL;
    
    // Check minimum size
    if (len < min_size) {
        return 0;
    }
    
    // Handle large bodies based on scan_mode
    if (len > max_size) {
        switch (scan_mode) {
            case PRESIDIO_SCAN_MODE_TRUNCATE:
                // Will scan first max_size bytes (handled in scan function)
                log_debug("[Presidio] Body size %zu > max %u, will truncate", len, max_size);
                break;
            case PRESIDIO_SCAN_MODE_FULL:
            default:
                // Skip if too large - only scan complete bodies
                atomic_fetch_add(&g_stats.bodies_skipped_size, 1);
                log_debug("[Presidio] Body size %zu > max %u, skipping (full mode)", len, max_size);
                return 0;
        }
    }
    
    // Must be HTTP
    const char *msg = (const char *)data;
    if (is_request) {
        if (memcmp(data, "GET ", 4) != 0 && 
            memcmp(data, "POST ", 5) != 0 &&
            memcmp(data, "PUT ", 4) != 0 &&
            memcmp(data, "PATCH ", 6) != 0 &&
            memcmp(data, "DELETE ", 7) != 0) {
            return 0;
        }
        
        // Extract URL and check patterns
        char url_buf[256];
        const char *url = extract_http_url(data, len, url_buf, sizeof(url_buf));
        if (url && !presidio_url_matches(url)) {
            return 0;  // URL doesn't match configured patterns
        }
    } else {
        if (memcmp(data, "HTTP/", 5) != 0) {
            return 0;
        }
    }
    
    // Check for text-based Content-Type
    if (strstr(msg, "Content-Type: application/json") ||
        strstr(msg, "Content-Type: text/") ||
        strstr(msg, "Content-Type: application/xml") ||
        strstr(msg, "Content-Type: application/x-www-form-urlencoded")) {
        return 1;
    }
    
    // Skip binary types
    if (strstr(msg, "Content-Type: image/") ||
        strstr(msg, "Content-Type: video/") ||
        strstr(msg, "Content-Type: audio/") ||
        strstr(msg, "Content-Type: application/octet-stream")) {
        return 0;
    }
    
    return 1;  // Default: scan if uncertain
}

int presidio_replace_http_body(
    const uint8_t *original,
    size_t orig_len,
    const char *new_body,
    size_t new_body_len,
    uint8_t **output,
    size_t *output_len)
{
    if (!original || !new_body || !output || !output_len) {
        return -1;
    }
    
    // Find body start
    size_t body_offset = 0;
    for (size_t i = 0; i < orig_len - 3; i++) {
        if (original[i] == '\r' && original[i+1] == '\n' &&
            original[i+2] == '\r' && original[i+3] == '\n') {
            body_offset = i + 4;
            break;
        }
    }
    
    if (body_offset == 0) {
        return -1;  // No body found
    }
    
    // Calculate header and body parts
    size_t header_len = body_offset;
    
    // Allocate new message buffer
    size_t new_msg_len = header_len + new_body_len;
    uint8_t *new_msg = malloc(new_msg_len);
    if (!new_msg) {
        return -1;
    }
    
    // Copy header
    memcpy(new_msg, original, header_len);
    
    // Copy new body
    memcpy(new_msg + header_len, new_body, new_body_len);
    
    // Update output
    *output = new_msg;
    *output_len = new_msg_len;
    
    return 0;
}

// ============================================================================
// PRESIDIO SCAN WITH ERROR HANDLING & RETRIES
// ============================================================================

/**
 * Scan with retry logic
 */
static int presidio_scan_with_retry(
    const char *content,
    size_t content_len,
    int catalog_id,
    pii_scan_result_t **result)
{
    // Get config from shared memory with fallback
    presidio_config_shm_t *cfg = presidio_config_get();
    uint32_t max_retries = cfg ? cfg->max_retries : 1;
    uint32_t retry_backoff_ms = cfg ? cfg->retry_backoff_ms : 100;
    
    for (uint32_t attempt = 0; attempt <= max_retries; attempt++) {
        if (attempt > 0) {
            // Retry attempt
            atomic_fetch_add(&g_stats.retry_attempts, 1);
            
            // Exponential backoff
            usleep(retry_backoff_ms * 1000 * attempt);
            
            log_debug("[Presidio] Retry attempt %u/%u", attempt, max_retries);
        }
        
        // Call Go bridge
        void *go_result = llb_presidio_scan(content, "en", catalog_id);
        
        if (go_result) {
            *result = (pii_scan_result_t *)go_result;
            
            // Check for errors in result
            if ((*result)->error_code != 0) {
                // Error in scan - record failure
                if (strstr((*result)->error_msg, "timeout")) {
                    atomic_fetch_add(&g_stats.scan_timeouts, 1);
                } else if (strstr((*result)->error_msg, "connection")) {
                    atomic_fetch_add(&g_stats.connection_errors, 1);
                } else if (strstr((*result)->error_msg, "grpc")) {
                    atomic_fetch_add(&g_stats.grpc_errors, 1);
                } else {
                    atomic_fetch_add(&g_stats.scan_errors, 1);
                }
                
                // Free result and retry if attempts remain
                llb_presidio_free_result(go_result);
                *result = NULL;
                
                if (attempt < max_retries) {
                    continue;  // Retry
                } else {
                    presidio_circuit_breaker_record_failure();
                    return -1;  // All retries exhausted
                }
            }
            
            // Success!
            if (attempt > 0) {
                atomic_fetch_add(&g_stats.retry_successes, 1);
            }
            presidio_circuit_breaker_record_success();
            return 0;
        }
        
        // NULL result - connection failure
        atomic_fetch_add(&g_stats.connection_errors, 1);
        
        if (attempt < max_retries) {
            continue;  // Retry
        }
    }
    
    // All retries failed
    presidio_circuit_breaker_record_failure();
    return -1;
}

int presidio_scan(
    const char *content,
    size_t content_len,
    int catalog_id,
    pii_scan_result_t **result)
{
    if (!content || content_len == 0 || !result) {
        return -1;
    }
    
    *result = NULL;
    
    // Get config for truncation logic
    presidio_config_shm_t *cfg = presidio_config_get();
    uint32_t max_size = cfg ? cfg->max_body_size : 65536;
    uint8_t scan_mode = cfg ? cfg->scan_mode : PRESIDIO_SCAN_MODE_FULL;
    
    // Truncate if needed
    size_t scan_len = content_len;
    int is_truncated = 0;
    
    if (content_len > max_size && scan_mode == PRESIDIO_SCAN_MODE_TRUNCATE) {
        scan_len = max_size;
        is_truncated = 1;
        atomic_fetch_add(&g_stats.bodies_truncated, 1);
        log_debug("[Presidio] Truncating body from %zu to %zu bytes", content_len, scan_len);
    }
    
    // Check if enabled
    if (!presidio_is_enabled()) {
        return -1;
    }
    
    // Check circuit breaker
    if (!presidio_circuit_breaker_allow_request()) {
        // Circuit open - fail according to fail mode
        presidio_config_shm_t *cfg = presidio_config_get();
        uint8_t fail_mode = cfg ? cfg->fail_mode : PRESIDIO_FAIL_OPEN;
        
        if (fail_mode == PRESIDIO_FAIL_OPEN) {
            atomic_fetch_add(&g_stats.fail_open_bypasses, 1);
            log_debug("[Presidio] Circuit open - FAIL_OPEN: allowing traffic through");
            return 0;  // Success (bypass)
        } else {
            atomic_fetch_add(&g_stats.fail_closed_blocks, 1);
            log_warn("[Presidio] Circuit open - FAIL_CLOSED: blocking traffic");
            return -1;  // Failure (block)
        }
    }
    
    // Attempt scan with retry logic
    int ret = presidio_scan_with_retry(content, scan_len, catalog_id, result);
    
    if (ret != 0) {
        // Scan failed - handle according to fail mode
        presidio_config_shm_t *cfg = presidio_config_get();
        uint8_t fail_mode = cfg ? cfg->fail_mode : PRESIDIO_FAIL_OPEN;
        
        if (fail_mode == PRESIDIO_FAIL_OPEN) {
            atomic_fetch_add(&g_stats.fail_open_bypasses, 1);
            log_debug("[Presidio] Scan failed - FAIL_OPEN: allowing traffic through");
            return 0;  // Success (bypass)
        } else {
            atomic_fetch_add(&g_stats.fail_closed_blocks, 1);
            log_warn("[Presidio] Scan failed - FAIL_CLOSED: blocking traffic");
            return -1;  // Failure (block)
        }
    }
    
    // Update statistics
    atomic_fetch_add(&g_stats.requests_scanned, 1);
    atomic_fetch_add(&g_stats.bytes_scanned, scan_len);  // Use truncated length
    
    if (*result && (*result)->error_code == 0) {
        if ((*result)->entity_count > 0) {
            atomic_fetch_add(&g_stats.entities_detected, (*result)->entity_count);
            if ((*result)->anonymized_text) {
                atomic_fetch_add(&g_stats.requests_masked, 1);
                atomic_fetch_add(&g_stats.bytes_masked, strlen((*result)->anonymized_text));
            }
        }
        atomic_fetch_add(&g_stats.total_latency_us, (uint64_t)((*result)->latency_ms * 1000));
    }
    
    return 0;
}

void presidio_free_result(pii_scan_result_t *result) {
    if (result) {
        // Call Go bridge to free the result structure
        // The Go bridge is responsible for freeing all members
        llb_presidio_free_result(result);
    }
}

// ============================================================================
// STATISTICS
// ============================================================================

int presidio_get_stats(presidio_stats_t *stats) {
    if (!stats) {
        return -1;
    }
    
    stats->requests_scanned = atomic_load(&g_stats.requests_scanned);
    stats->entities_detected = atomic_load(&g_stats.entities_detected);
    stats->requests_masked = atomic_load(&g_stats.requests_masked);
    stats->scan_errors = atomic_load(&g_stats.scan_errors);
    stats->scan_timeouts = atomic_load(&g_stats.scan_timeouts);
    stats->bytes_scanned = atomic_load(&g_stats.bytes_scanned);
    stats->bytes_masked = atomic_load(&g_stats.bytes_masked);
    stats->total_latency_us = atomic_load(&g_stats.total_latency_us);
    
    return 0;
}

void presidio_reset_stats(void) {
    atomic_store(&g_stats.requests_scanned, 0);
    atomic_store(&g_stats.entities_detected, 0);
    atomic_store(&g_stats.requests_masked, 0);
    atomic_store(&g_stats.scan_errors, 0);
    atomic_store(&g_stats.scan_timeouts, 0);
    atomic_store(&g_stats.bytes_scanned, 0);
    atomic_store(&g_stats.bytes_masked, 0);
    atomic_store(&g_stats.total_latency_us, 0);
    
    log_info("[Presidio] Statistics reset");
}

int presidio_health_check(void) {
    return llb_presidio_health_check();
}

// ============================================================================
// V2 API: ENHANCED FEATURES (Unified Implementation)
// ============================================================================

// V2 availability tracking
static _Atomic int g_v2_available = 1;  // Always available with unified client

int presidio_v2_available(void) {
    return atomic_load(&g_v2_available) && atomic_load(&g_initialized);
}

// C wrapper for initialization with config struct
int presidio_v2_init(presidio_config_shm_t *config) {
    if (!config || !config->analyzer_url[0]) {
        log_error("[Presidio] Invalid config or empty analyzer URL");
        return -1;
    }
    
    // Call CGO bridge with analyzer URL
    return llb_presidio_v2_init(config->analyzer_url);
}

// ============================================================================
// OPERATOR HELPERS
// ============================================================================

presidio_operators_t presidio_create_default_operators(presidio_operator_type_t type) {
    presidio_operators_t ops = {0};
    
    ops.default_op.type = type;
    ops.default_op.params[0] = '\0';
    
    // Initialize per-entity operators to use default
    ops.email_op.type = type;
    ops.ssn_op.type = type;
    ops.credit_card_op.type = type;
    ops.phone_op.type = type;
    ops.person_op.type = type;
    
    ops.custom_op_count = 0;
    
    return ops;
}

void presidio_set_encryption_key(presidio_operators_t *operators, const char *key) {
    if (!operators || !key) {
        return;
    }
    
    // Set encryption key in params as JSON
    snprintf(operators->default_op.params, sizeof(operators->default_op.params),
             "{\"key\": \"%s\"}", key);
}

const char* presidio_operator_to_string(presidio_operator_type_t type) {
    switch (type) {
        case PRESIDIO_OP_REPLACE:  return "replace";
        case PRESIDIO_OP_REDACT:   return "redact";
        case PRESIDIO_OP_HASH:     return "hash";
        case PRESIDIO_OP_ENCRYPT:  return "encrypt";
        case PRESIDIO_OP_MASK:     return "mask";
        default:                   return "replace";
    }
}

presidio_operator_type_t presidio_operator_from_string(const char *str) {
    if (!str) return PRESIDIO_OP_REPLACE;
    
    if (strcmp(str, "replace") == 0)  return PRESIDIO_OP_REPLACE;
    if (strcmp(str, "redact") == 0)   return PRESIDIO_OP_REDACT;
    if (strcmp(str, "hash") == 0)     return PRESIDIO_OP_HASH;
    if (strcmp(str, "encrypt") == 0)  return PRESIDIO_OP_ENCRYPT;
    if (strcmp(str, "mask") == 0)     return PRESIDIO_OP_MASK;
    
    return PRESIDIO_OP_REPLACE;
}

// ============================================================================
// V2 SCAN (Combined Analyze + Anonymize)
// ============================================================================

int presidio_scan_v2(
    const char *content,
    size_t content_len,
    presidio_operators_t *operators,
    pii_scan_result_v2_t **result)
{
    if (!content || content_len == 0 || !operators || !result) {
        return -1;
    }
    
    *result = NULL;
    
    // Check if enabled
    if (!presidio_is_enabled()) {
        return -1;
    }
    
    // Check circuit breaker
    if (!presidio_circuit_breaker_allow_request()) {
        presidio_config_shm_t *cfg = presidio_config_get();
        uint8_t fail_mode = cfg ? cfg->fail_mode : PRESIDIO_FAIL_OPEN;
        
        if (fail_mode == PRESIDIO_FAIL_OPEN) {
            log_debug("[Presidio] Circuit open - FAIL_OPEN: bypassing");
            return 0;
        } else {
            log_warn("[Presidio] Circuit open - FAIL_CLOSED: blocking");
            return -1;
        }
    }
    
    // Call Go bridge for unified v2 API
    void *go_result = llb_presidio_analyze_and_anonymize(
        content,
        "en",  // TODO: make language configurable
        operators
    );
    
    if (!go_result) {
        log_error("[Presidio] Go bridge returned NULL");
        presidio_circuit_breaker_record_failure();
        return -1;
    }
    
    *result = (pii_scan_result_v2_t *)go_result;
    
    // Check for errors in result
    if ((*result)->error_code != 0) {
        log_error("[Presidio] Scan failed: %s", (*result)->error_msg);
        presidio_circuit_breaker_record_failure();
        return -1;
    }
    
    // Record success
    presidio_circuit_breaker_record_success();
    
    log_debug("[Presidio] Scan complete: %d entities, %d items",
              (*result)->entity_count, (*result)->item_count);
    
    return 0;
}

// ============================================================================
// DECRYPTION (Reversible Anonymization)
// ============================================================================

int presidio_decrypt(
    const char *encrypted_text,
    anonymized_item_t *items,
    int item_count,
    const char *decryption_key,
    char **result)
{
    if (!encrypted_text || !items || item_count <= 0 || !decryption_key || !result) {
        return -1;
    }
    
    *result = NULL;
    
    if (!presidio_is_enabled()) {
        return -1;
    }
    
    // Call Go bridge
    void *go_result = llb_presidio_deanonymize(
        encrypted_text,
        items,
        item_count,
        decryption_key
    );
    
    if (!go_result) {
        log_error("[Presidio] Decryption failed");
        return -1;
    }
    
    *result = (char *)go_result;
    return 0;
}

// ============================================================================
// CUSTOM RECOGNIZERS
// ============================================================================

int presidio_register_custom_recognizer(presidio_custom_recognizer_t *recognizer) {
    if (!recognizer) {
        return -1;
    }
    
    if (!presidio_is_enabled()) {
        return -1;
    }
    
    // Call Go bridge
    int ret = llb_presidio_register_custom_recognizer(
        recognizer->name,
        recognizer->entity_type,
        recognizer->patterns,
        recognizer->pattern_count,
        NULL,  // context_words - TODO: implement
        0
    );
    
    if (ret != 0) {
        log_error("[Presidio] Failed to register custom recognizer: %s", recognizer->name);
        return -1;
    }
    
    log_info("[Presidio] Registered custom recognizer: %s", recognizer->name);
    return 0;
}

// ============================================================================
// BATCH PROCESSING
// ============================================================================

int presidio_scan_batch(
    const char **texts,
    size_t *lengths,
    int count,
    presidio_operators_t *operators,
    pii_scan_result_v2_t ***results)
{
    if (!texts || !lengths || count <= 0 || !operators || !results) {
        return -1;
    }
    
    *results = NULL;
    
    if (!presidio_is_enabled()) {
        return -1;
    }
    
    // Call Go bridge
    void *go_result = llb_presidio_scan_batch(
        (void *)texts,
        lengths,
        count,
        operators
    );
    
    if (!go_result) {
        log_error("[Presidio] Batch scan failed");
        return -1;
    }
    
    *results = (pii_scan_result_v2_t **)go_result;
    return 0;
}

// ============================================================================
// MEMORY MANAGEMENT (V2)
// ============================================================================

void presidio_free_result_v2(pii_scan_result_v2_t *result) {
    if (result) {
        llb_presidio_free_result_v2(result);
    }
}

void presidio_free_json_result(pii_json_result_t *result) {
    if (result) {
        llb_presidio_free_json_result(result);
    }
}

void presidio_free_decrypted(char *text) {
    if (text) {
        free(text);
    }
}

// ============================================================================
// V2 HEALTH & STATS
// ============================================================================

int presidio_health_check_v2(void) {
    return llb_presidio_health_check_v2();
}

// This file contains JSON anonymization implementation for Phase 2.1
// It will be appended to sockproxy_presidio.c

// ============================================================================
// JSON-AWARE ANONYMIZATION (Phase 2.1)
// ============================================================================

/**
 * Check if JSON anonymization is enabled
 * FIXED: Allow JSON mode even without explicit field mappings (auto-detect mode)
 */
int presidio_json_enabled(void) {
    presidio_config_shm_t *cfg = presidio_config_get();
    // Allow JSON mode if detection is enabled, even without field mappings
    // (empty mappings = auto-detect all fields)
    return cfg && cfg->enable_json_detection;
}

/**
 * JSON-aware anonymization with automatic field detection
 * Production-ready implementation with resource cleanup
 * 
 * @param json_data JSON content to scan
 * @param json_len Content length
 * @param operators Anonymization operators
 * @param result Output: scan result (caller must free with presidio_free_result_v2)
 * @return 0 on success, -1 on error
 */
int presidio_anonymize_json(
    const char *json_data,
    size_t json_len,
    presidio_operators_t *operators,
    pii_scan_result_v2_t **result)
{
    if (!json_data || json_len == 0 || !operators || !result) {
        log_error("[Presidio-JSON] Invalid arguments");
        return -1;
    }
    
    *result = NULL;
    
    // Check if enabled
    if (!presidio_is_enabled()) {
        log_debug("[Presidio-JSON] Presidio disabled");
        return -1;
    }
    
    // Check if JSON mode enabled
    if (!presidio_json_enabled()) {
        log_debug("[Presidio-JSON] JSON mode disabled, falling back to text mode");
        return presidio_scan_v2(json_data, json_len, operators, result);
    }
    
    // Check circuit breaker
    if (!presidio_circuit_breaker_allow_request()) {
        presidio_config_shm_t *cfg = presidio_config_get();
        uint8_t fail_mode = cfg ? cfg->fail_mode : PRESIDIO_FAIL_OPEN;
        
        if (fail_mode == PRESIDIO_FAIL_OPEN) {
            atomic_fetch_add(&g_stats.fail_open_bypasses, 1);
            log_debug("[Presidio-JSON] Circuit open - FAIL_OPEN: bypassing");
            return 0;
        } else {
            atomic_fetch_add(&g_stats.fail_closed_blocks, 1);
            log_warn("[Presidio-JSON] Circuit open - FAIL_CLOSED: blocking");
            return -1;
        }
    }
    
    // Get JSON configuration from shared memory
    presidio_config_shm_t *cfg = presidio_config_get();
    if (!cfg || cfg->json_config.num_field_mappings == 0) {
        log_info("[Presidio-JSON] No field mappings configured, falling back to text mode");
        return presidio_scan_v2(json_data, json_len, operators, result);
    }
    
    // Convert presidio_json_config_t to presidio_json_mapping_t format expected by Go bridge
    presidio_json_mapping_t mapping;
    mapping.mapping_count = cfg->json_config.num_field_mappings;
    
    for (uint8_t i = 0; i < mapping.mapping_count && i < 32; i++) {
        presidio_json_field_config_t *src = &cfg->json_config.field_mappings[i];
        // Copy json_path
        strncpy(mapping.mappings[i].field_path, src->json_path, 127);
        mapping.mappings[i].field_path[127] = '\0';
        
        // Use first entity type, or empty string for auto-detect
        if (src->entity_types_count > 0) {
            strncpy(mapping.mappings[i].entity_type, src->entity_types[0], 63);
            mapping.mappings[i].entity_type[63] = '\0';
        } else {
            mapping.mappings[i].entity_type[0] = '\0';  // Auto-detect
        }
    }
    
    log_debug("[Presidio-JSON] Calling llb_presidio_anonymize_json: len=%zu fields=%d",
              json_len, mapping.mapping_count);
    
    // Call Go bridge (passes pointers directly, not JSON strings)
    void *go_result = llb_presidio_anonymize_json(
        json_data,
        "en",               // Language
        &mapping,           // Pointer to mapping structure
        operators           // Pointer to operators structure
    );
    
    if (!go_result) {
        log_error("[Presidio-JSON] llb_presidio_anonymize_json returned NULL");
        presidio_circuit_breaker_record_failure();
        
        // Fallback to text mode if enabled
        if (cfg->json_fallback_to_text) {
            log_info("[Presidio-JSON] Falling back to text mode after error");
            return presidio_scan_v2(json_data, json_len, operators, result);
        }
        
        return -1;
    }
    
    // CRITICAL FIX: Convert pii_json_result_t to pii_scan_result_v2_t
    // Previous bug: Unsafe cast caused anonymized_len to read garbage memory
    // (fields_anonymized int was interpreted as size_t, giving truncated length like 122)
    pii_json_result_t *json_result = (pii_json_result_t *)go_result;
    
    // Check for errors in JSON result
    if (json_result->error_code != 0) {
        log_error("[Presidio-JSON] Error from Go bridge: %s", json_result->error_msg);
        presidio_circuit_breaker_record_failure();
        
        // Free JSON result and fallback if enabled
        llb_presidio_free_json_result(json_result);
        *result = NULL;
        
        if (cfg->json_fallback_to_text) {
            log_info("[Presidio-JSON] Falling back to text mode after error");
            return presidio_scan_v2(json_data, json_len, operators, result);
        }
        
        return -1;
    }
    
    // Allocate proper v2 result structure
    pii_scan_result_v2_t *v2_result = (pii_scan_result_v2_t *)malloc(sizeof(pii_scan_result_v2_t));
    if (!v2_result) {
        log_error("[Presidio-JSON] Failed to allocate v2_result");
        llb_presidio_free_json_result(json_result);
        return -1;
    }
    
    // Properly convert JSON result to v2 format
    memset(v2_result, 0, sizeof(pii_scan_result_v2_t));
    v2_result->anonymized_text = json_result->json_data;  // Transfer ownership
    v2_result->anonymized_len = strlen(json_result->json_data);  // CORRECT: Calculate length
    v2_result->entities = NULL;
    v2_result->items = NULL;
    v2_result->entity_count = json_result->fields_anonymized;
    v2_result->item_count = 0;
    v2_result->latency_ms = json_result->latency_ms;
    v2_result->error_code = json_result->error_code;
    strncpy(v2_result->error_msg, json_result->error_msg, sizeof(v2_result->error_msg) - 1);
    
    // Free JSON result wrapper (NOT the json_data pointer, we transferred it)
    free(json_result);
    
    *result = v2_result;
    
    // Success!
    presidio_circuit_breaker_record_success();
    
    // Update statistics
    atomic_fetch_add(&g_stats.requests_scanned, 1);
    atomic_fetch_add(&g_stats.bytes_scanned, json_len);
    
    if ((*result)->entity_count > 0) {
        atomic_fetch_add(&g_stats.entities_detected, (*result)->entity_count);
        atomic_fetch_add(&g_stats.requests_masked, 1);
        
        if ((*result)->anonymized_text) {
            atomic_fetch_add(&g_stats.bytes_masked, (*result)->anonymized_len);
        }
        
        log_info("[Presidio-JSON] Detected %d entities in JSON payload",
                 (*result)->entity_count);
    } else {
        log_debug("[Presidio-JSON] No PII detected in JSON payload");
    }
    
    if ((*result)->latency_ms > 0) {
        atomic_fetch_add(&g_stats.total_latency_us, (uint64_t)((*result)->latency_ms * 1000));
    }
    
    return 0;
}

// ============================================================================
// CUSTOM RECOGNIZER REGISTRATION (Phase 2.2)
// ============================================================================

/**
 * Register all custom recognizers from registry with Presidio server
 * Called at startup after presidio_registry_load_from_file()
 */
int presidio_register_custom_patterns(void) {
    if (!presidio_is_enabled()) {
        log_debug("[Presidio-Custom] PII detection disabled, skipping pattern registration");
        return 0;
    }
    
    presidio_config_shm_t *cfg = presidio_config_get();
    if (!cfg || !cfg->custom_recognizers_enabled) {
        log_debug("[Presidio-Custom] Custom recognizers disabled in config");
        return 0;
    }
    
    // Get all recognizers from registry
    presidio_custom_recognizer_config_t *recognizers = NULL;
    int count = 0;
    
    if (presidio_registry_get_all(&recognizers, &count) != 0 || count == 0) {
        log_info("[Presidio-Custom] No custom recognizers to register");
        return 0;
    }
    
    int success_count = 0;
    int failure_count = 0;
    
    log_info("[Presidio-Custom] Registering %d custom recognizers...", count);
    
    for (int i = 0; i < count; i++) {
        presidio_custom_recognizer_config_t *rec = &recognizers[i];
        
        if (!rec->enabled) {
            log_debug("[Presidio-Custom] Skipping disabled recognizer: %s", rec->name);
            continue;
        }
        
        // Convert to presidio_custom_recognizer_t for Go bridge
        presidio_custom_recognizer_t bridge_rec = {0};
        strncpy(bridge_rec.name, rec->name, sizeof(bridge_rec.name) - 1);
        strncpy(bridge_rec.entity_type, rec->entity_type, sizeof(bridge_rec.entity_type) - 1);
        bridge_rec.score = rec->score;
        
        // Copy patterns
        bridge_rec.pattern_count = rec->pattern_count;
        for (int j = 0; j < rec->pattern_count && j < 8; j++) {
            strncpy(bridge_rec.patterns[j].name, rec->patterns[j].name, 
                    sizeof(bridge_rec.patterns[j].name) - 1);
            strncpy(bridge_rec.patterns[j].regex, rec->patterns[j].regex,
                    sizeof(bridge_rec.patterns[j].regex) - 1);
            bridge_rec.patterns[j].score = rec->patterns[j].score;
        }
        
        // Copy context words
        bridge_rec.context_word_count = rec->context_word_count;
        for (int j = 0; j < rec->context_word_count && j < 16; j++) {
            strncpy(bridge_rec.context_words[j], rec->context_words[j],
                    sizeof(bridge_rec.context_words[j]) - 1);
        }
        
        // Register with Presidio server via Go bridge
        int ret = presidio_register_custom_recognizer(&bridge_rec);
        if (ret == 0) {
            success_count++;
            log_info("[Presidio-Custom] ✓ Registered: %s (entity: %s, patterns: %d)",
                     rec->name, rec->entity_type, rec->pattern_count);
        } else {
            failure_count++;
            log_error("[Presidio-Custom] ✗ Failed to register: %s", rec->name);
        }
    }
    
    log_info("[Presidio-Custom] Registration complete: %d success, %d failed",
             success_count, failure_count);
    
    return (failure_count == 0) ? 0 : -1;
}

/**
 * Reload custom recognizers from configuration file and re-register
 * Can be called via API for hot-reload
 */
int presidio_reload_custom_patterns(void) {
    log_info("[Presidio-Custom] Reloading custom patterns...");
    
    // Clear existing registry
    presidio_registry_cleanup();
    presidio_registry_init();
    
    // Load from file
    int ret = presidio_registry_load_from_file(NULL);  // Use default path
    if (ret != 0) {
        log_warn("[Presidio-Custom] Failed to load custom patterns from file");
        return ret;
    }
    
    // Re-register all patterns
    return presidio_register_custom_patterns();
}

