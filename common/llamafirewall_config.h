/*
 * Copyright (c) 2025 LoxiLB Authors
 * SPDX short identifier: BSD-3-Clause
 *
 * LlamaFirewall Configuration: Shared Memory Header
 * Following Presidio pattern for C-Go coordination
 */

#ifndef __LLAMAFIREWALL_CONFIG_H__
#define __LLAMAFIREWALL_CONFIG_H__

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// SHARED MEMORY CONFIGURATION STRUCTURE
// ============================================================================
// This structure is shared between Go (via CGO) and C layer.
// All configuration updates from REST API propagate through shared memory.
//
// Memory Layout: mmap(MAP_SHARED | MAP_ANONYMOUS) for cross-process access
// Thread Safety: Protected by mutexes in Go layer
// Hot-Reload: Supported without process restart
// ============================================================================

typedef struct {
    // Core settings
    uint8_t enabled;              // 0=disabled, 1=enabled
    char server_url[256];         // gRPC server address (e.g., "localhost:50052")
    uint32_t timeout_sec;         // Request timeout (default: 15s)
    uint8_t fail_closed;          // 0=fail-open (allow), 1=fail-closed (block)
    float block_threshold;        // Min confidence score to block (default: 0.9)

    // Circuit breaker settings (prevent cascading failures)
    uint32_t circuit_breaker_threshold;         // Failures before opening (default: 5)
    uint32_t circuit_breaker_timeout_sec;       // Wait before HALF_OPEN (default: 60s)
    uint32_t circuit_breaker_success_threshold; // Successes to close (default: 3)

    // Scanner configuration (which scanners are enabled)
    uint8_t scanner_prompt_guard;     // Prompt injection detection
    uint8_t scanner_code_shield;      // Insecure code detection
    uint8_t scanner_regex;            // Credential regex scanner
    uint8_t scanner_hidden_ascii;     // Hidden ASCII character detection
    uint8_t scanner_agent_alignment;  // Agent alignment detection
    uint8_t scanner_pii_detection;    // PII detection (delegated to Presidio)

    // Performance settings
    uint8_t cache_enabled;        // Response caching
    uint32_t cache_ttl_sec;       // Cache TTL (default: 300s)
    uint32_t connection_pool_size; // gRPC connection pool (default: 10)

    // Version control (for hot-reload detection) - MUST MATCH PRESIDIO PATTERN
    uint64_t config_version;      // Incremented on each update
    uint64_t last_update_ts;      // Unix timestamp (seconds)

    // Reserved for future expansion (maintain ABI compatibility)
    uint8_t _reserved[112];       // Reduced from 128 to account for version fields
} llamafirewall_config_shm_t;

// ============================================================================
// RUNTIME TRACKING STRUCTURE (following Presidio pattern)
// ============================================================================
// This structure tracks the shared memory mapping and version state.
// NOT stored in shared memory - only local to C process.
// ============================================================================

typedef struct {
    int shm_fd;                          // /dev/shm file descriptor
    void *shm_addr;                      // mmap base address
    uint64_t last_reload_version;        // Last seen config_version
    llamafirewall_config_shm_t shm_config; // Local copy of config
} llamafirewall_runtime_config_t;

// ============================================================================
// SHARED MEMORY PATH (following Presidio pattern)
// ============================================================================

#define LLAMAFIREWALL_CONFIG_SHM_PATH "/dev/shm/loxilb_llamafirewall_config"

// ============================================================================
// CONFIGURATION MANAGEMENT FUNCTIONS
// ============================================================================
// These functions manage the shared memory configuration lifecycle.
// Called from both C layer (sockproxy.c) and Go layer (via CGO).
// Following Presidio pattern exactly.
// ============================================================================

/**
 * Initialize shared memory configuration subsystem
 *
 * Opens /dev/shm file and mmaps it for reading.
 * Safe to call multiple times (idempotent).
 * Falls back to defaults if shared memory doesn't exist.
 *
 * @return 0 on success, -1 on error
 */
int llamafirewall_config_init(void);

/**
 * Reload configuration from shared memory (hot-reload)
 *
 * Checks for version changes and reloads config if updated.
 * Called periodically or on-demand to pick up configuration changes.
 * Triggers weak symbol callback if server URL changes.
 *
 * @return 0 on success (reloaded), -1 on error, 1 if no changes
 */
int llamafirewall_config_reload(void);

/**
 * Get pointer to local configuration copy
 *
 * Returns pointer to local copy (NOT direct shared memory pointer).
 * Caller must NOT free this pointer.
 * Call llamafirewall_config_reload() to sync with shared memory.
 *
 * @return Pointer to config local copy
 */
llamafirewall_config_shm_t* llamafirewall_config_get(void);

/**
 * Check if LlamaFirewall is enabled
 *
 * Atomic check of enabled flag from shared memory.
 * Fast path for per-request decision (2ns overhead).
 *
 * @return 1 if enabled, 0 if disabled
 */
int llamafirewall_config_is_enabled(void);

/**
 * Cleanup shared memory resources
 *
 * Unmaps shared memory region.
 * Called at process shutdown.
 */
void llamafirewall_config_cleanup(void);

/**
 * Dump configuration to logs (debugging)
 *
 * Logs current configuration values for diagnostics.
 */
void llamafirewall_config_dump(void);

#ifdef __cplusplus
}
#endif

#endif /* __LLAMAFIREWALL_CONFIG_H__ */
