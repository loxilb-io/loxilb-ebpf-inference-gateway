/*
 * Copyright (c) 2025 LoxiLB Authors
 * SPDX short identifier: BSD-3-Clause
 *
 * LlamaFirewall Configuration: Shared Memory Implementation
 * Following Presidio pattern for C-Go coordination with file-backed /dev/shm
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include "llamafirewall_config.h"
#include "log.h"

// ============================================================================
// LLAMAFIREWALL DYNAMIC CONFIGURATION MANAGEMENT
// Following the same pattern as presidio_config.c
// ============================================================================

// Global runtime configuration
static llamafirewall_runtime_config_t g_llamafirewall_runtime = {
    .shm_fd = -1,
    .shm_addr = NULL,
    .last_reload_version = 0,
};

/**
 * Initialize LlamaFirewall configuration from shared memory
 * Similar to presidio_config_init()
 *
 * @return 0 on success, -1 on error
 */
int llamafirewall_config_init(void) {
    // Open shared memory file (read-only)
    int fd = open(LLAMAFIREWALL_CONFIG_SHM_PATH, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) {
            log_info("[LlamaFirewall-Config] Shared memory not found - using defaults");

            // Initialize with defaults
            memset(&g_llamafirewall_runtime.shm_config, 0, sizeof(llamafirewall_config_shm_t));
            g_llamafirewall_runtime.shm_config.enabled = 0;  // Disabled by default
            strcpy(g_llamafirewall_runtime.shm_config.server_url, "localhost:50052");
            g_llamafirewall_runtime.shm_config.timeout_sec = 15;
            g_llamafirewall_runtime.shm_config.fail_closed = 0;  // Fail-open by default
            g_llamafirewall_runtime.shm_config.block_threshold = 0.9f;
            g_llamafirewall_runtime.shm_config.circuit_breaker_threshold = 5;
            g_llamafirewall_runtime.shm_config.circuit_breaker_timeout_sec = 60;
            g_llamafirewall_runtime.shm_config.circuit_breaker_success_threshold = 3;
            g_llamafirewall_runtime.shm_config.scanner_prompt_guard = 1;
            g_llamafirewall_runtime.shm_config.scanner_code_shield = 1;
            g_llamafirewall_runtime.shm_config.scanner_regex = 1;
            g_llamafirewall_runtime.shm_config.scanner_hidden_ascii = 1;
            g_llamafirewall_runtime.shm_config.scanner_agent_alignment = 0;
            g_llamafirewall_runtime.shm_config.scanner_pii_detection = 0;
            g_llamafirewall_runtime.shm_config.cache_enabled = 1;
            g_llamafirewall_runtime.shm_config.cache_ttl_sec = 300;
            g_llamafirewall_runtime.shm_config.connection_pool_size = 10;
            g_llamafirewall_runtime.shm_config.config_version = 0;
            g_llamafirewall_runtime.shm_config.last_update_ts = 0;

            return 0;  // OK - using defaults
        }

        log_error("[LlamaFirewall-Config] Failed to open shared memory: %s", strerror(errno));
        return -1;
    }

    // Get file size
    struct stat st;
    if (fstat(fd, &st) < 0) {
        log_error("[LlamaFirewall-Config] fstat failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    // Validate size
    size_t expected_size = sizeof(llamafirewall_config_shm_t);
    if (st.st_size != expected_size) {
        log_warn("[LlamaFirewall-Config] Size mismatch: got %ld, expected %zu - using defaults",
                 st.st_size, expected_size);
        close(fd);

        // Initialize with defaults
        memset(&g_llamafirewall_runtime.shm_config, 0, sizeof(llamafirewall_config_shm_t));
        g_llamafirewall_runtime.shm_config.enabled = 0;
        return 0;
    }

    // Map shared memory
    void *addr = mmap(NULL, expected_size, PROT_READ, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        log_error("[LlamaFirewall-Config] mmap failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    // Save mapping info
    g_llamafirewall_runtime.shm_fd = fd;
    g_llamafirewall_runtime.shm_addr = addr;

    // Copy configuration
    memcpy(&g_llamafirewall_runtime.shm_config, addr, sizeof(llamafirewall_config_shm_t));
    g_llamafirewall_runtime.last_reload_version = g_llamafirewall_runtime.shm_config.config_version;

    log_info("[LlamaFirewall-Config] ✓ Loaded from shared memory: version=%lu enabled=%d",
             g_llamafirewall_runtime.shm_config.config_version,
             g_llamafirewall_runtime.shm_config.enabled);

    return 0;
}

/**
 * Reload LlamaFirewall configuration from shared memory (hot-reload)
 * Similar to presidio_config_reload()
 * Called periodically or on-demand to pick up configuration changes
 *
 * @return 0 on success, -1 on error, 1 if no changes
 */
int llamafirewall_config_reload(void) {
    // Check if shared memory is mapped
    if (g_llamafirewall_runtime.shm_fd < 0 || g_llamafirewall_runtime.shm_addr == NULL) {
        // Not initialized yet - try to initialize
        return llamafirewall_config_init();
    }

    // Get file size to detect truncation/changes
    struct stat st;
    if (fstat(g_llamafirewall_runtime.shm_fd, &st) < 0) {
        log_error("[LlamaFirewall-Config] Reload fstat failed: %s", strerror(errno));
        return -1;
    }

    size_t expected_size = sizeof(llamafirewall_config_shm_t);
    if (st.st_size != expected_size) {
        log_warn("[LlamaFirewall-Config] Size changed during reload: %ld vs %zu",
                 st.st_size, expected_size);

        // Remap
        munmap(g_llamafirewall_runtime.shm_addr, expected_size);
        close(g_llamafirewall_runtime.shm_fd);
        g_llamafirewall_runtime.shm_fd = -1;
        g_llamafirewall_runtime.shm_addr = NULL;

        return llamafirewall_config_init();
    }

    // Read version from shared memory
    llamafirewall_config_shm_t *shm_config = (llamafirewall_config_shm_t *)g_llamafirewall_runtime.shm_addr;
    uint64_t current_version = shm_config->config_version;

    // Check if version changed
    if (current_version == g_llamafirewall_runtime.last_reload_version) {
        return 1;  // No changes
    }

    // Check if server URL changed before copying new config
    int url_changed = 0;
    if (strcmp(g_llamafirewall_runtime.shm_config.server_url, shm_config->server_url) != 0) {
        url_changed = 1;
        log_info("[LlamaFirewall-Config] 🔄 Server URL changed: %s → %s",
                 g_llamafirewall_runtime.shm_config.server_url,
                 shm_config->server_url);
    }

    // Copy new configuration
    memcpy(&g_llamafirewall_runtime.shm_config, shm_config, sizeof(llamafirewall_config_shm_t));
    g_llamafirewall_runtime.last_reload_version = current_version;

    log_info("[LlamaFirewall-Config] ♻️ Reloaded configuration: version=%lu enabled=%d",
             current_version,
             g_llamafirewall_runtime.shm_config.enabled);

    // Update Go gRPC client if URL changed (weak symbol - only available in Go binary)
    if (url_changed) {
        // Declare as weak symbol - won't cause link error if not present
        extern int llb_llamafirewall_update_config(const char *server_url) __attribute__((weak));

        if (llb_llamafirewall_update_config != NULL) {
            int ret = llb_llamafirewall_update_config(shm_config->server_url);
            if (ret != 0) {
                log_warn("[LlamaFirewall-Config] Failed to update gRPC client with new URL");
            } else {
                log_info("[LlamaFirewall-Config] ✓ gRPC client updated with new URL: %s",
                         shm_config->server_url);
            }
        } else {
            log_debug("[LlamaFirewall-Config] llb_llamafirewall_update_config not available (weak symbol)");
        }
    }

    return 0;  // Successfully reloaded
}

/**
 * Get pointer to shared memory configuration
 *
 * Returns pointer to local copy of configuration (read-only).
 * Caller must NOT free this pointer.
 *
 * @return Pointer to config, or NULL if not initialized
 */
llamafirewall_config_shm_t* llamafirewall_config_get(void) {
    return &g_llamafirewall_runtime.shm_config;
}

/**
 * Check if LlamaFirewall is enabled
 *
 * Atomic check of enabled flag from local config copy.
 * Fast path for per-request decision (2ns overhead).
 *
 * @return 1 if enabled, 0 if disabled
 */
int llamafirewall_config_is_enabled(void) {
    return g_llamafirewall_runtime.shm_config.enabled;
}

/**
 * Cleanup shared memory resources
 *
 * Unmaps shared memory region and closes file descriptor.
 * Called at process shutdown.
 * Safe to call multiple times (idempotent).
 */
void llamafirewall_config_cleanup(void) {
    if (g_llamafirewall_runtime.shm_addr != NULL) {
        log_info("[LlamaFirewall-Config] Cleaning up shared memory");
        munmap(g_llamafirewall_runtime.shm_addr, sizeof(llamafirewall_config_shm_t));
        g_llamafirewall_runtime.shm_addr = NULL;
    }

    if (g_llamafirewall_runtime.shm_fd >= 0) {
        close(g_llamafirewall_runtime.shm_fd);
        g_llamafirewall_runtime.shm_fd = -1;
    }

    log_info("[LlamaFirewall-Config] ✓ Cleanup complete");
}

/**
 * Dump configuration to logs (debugging)
 *
 * Logs all configuration values for diagnostics.
 */
void llamafirewall_config_dump(void) {
    llamafirewall_config_shm_t *cfg = &g_llamafirewall_runtime.shm_config;

    log_info("[LlamaFirewall-Config] ━━━ Configuration Dump ━━━");
    log_info("  Core Settings:");
    log_info("    enabled:           %d", cfg->enabled);
    log_info("    server_url:        %s", cfg->server_url);
    log_info("    timeout_sec:       %u", cfg->timeout_sec);
    log_info("    fail_closed:       %d", cfg->fail_closed);
    log_info("    block_threshold:   %.2f", cfg->block_threshold);

    log_info("  Circuit Breaker:");
    log_info("    threshold:         %u", cfg->circuit_breaker_threshold);
    log_info("    timeout_sec:       %u", cfg->circuit_breaker_timeout_sec);
    log_info("    success_threshold: %u", cfg->circuit_breaker_success_threshold);

    log_info("  Scanners:");
    log_info("    prompt_guard:      %d", cfg->scanner_prompt_guard);
    log_info("    code_shield:       %d", cfg->scanner_code_shield);
    log_info("    regex:             %d", cfg->scanner_regex);
    log_info("    hidden_ascii:      %d", cfg->scanner_hidden_ascii);
    log_info("    agent_alignment:   %d", cfg->scanner_agent_alignment);
    log_info("    pii_detection:     %d", cfg->scanner_pii_detection);

    log_info("  Performance:");
    log_info("    cache_enabled:     %d", cfg->cache_enabled);
    log_info("    cache_ttl_sec:     %u", cfg->cache_ttl_sec);
    log_info("    connection_pool:   %u", cfg->connection_pool_size);

    log_info("  Version:");
    log_info("    config_version:    %lu", cfg->config_version);
    log_info("    last_update_ts:    %lu", cfg->last_update_ts);
    log_info("[LlamaFirewall-Config] ━━━━━━━━━━━━━━━━━━━━━━━━");
}
