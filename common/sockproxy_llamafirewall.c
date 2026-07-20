/*
 * Copyright (c) 2025 LoxiLB Authors
 * SPDX short identifier: BSD-3-Clause
 *
 * AI Security Scanner: C Layer Implementation
 *
 * This module implements C-layer integration for LlamaFirewall security scanning.
 * Follows Presidio pattern for consistency with existing PII detection.
 *
 * Features:
 * - Prompt injection detection (PromptGuard)
 * - Insecure code detection (CodeShield)
 * - Credential leak detection (Regex)
 * - Hidden character attacks (HiddenASCII)
 * - Agent alignment checking (AgentAlignment)
 * - Lightweight wrapper around Go CGO exports
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>
#include <stdatomic.h>
#include <pthread.h>
#include "sockproxy_llamafirewall.h"
#include "llamafirewall_config.h"

// ============================================================================
// GLOBAL CONFIGURATION
// ============================================================================

// Global configuration (initialized by sockproxy_llamafirewall_init)
static llamafirewall_config_t g_llamafirewall_config = {
    .server_url = LLAMAFIREWALL_DEFAULT_SERVER,
    .enabled = 0,  // Disabled by default (must call init)
    .fail_closed = 0,  // Fail-open by default (allow on error)
    .scanner_mask = LLAMAFIREWALL_DEFAULT_SCANNERS,
    .block_threshold = LLAMAFIREWALL_DEFAULT_THRESHOLD,
};

// Initialization flag
static uint8_t g_initialized = 0;

// ============================================================================
// CIRCUIT BREAKER (following Presidio pattern)
// ============================================================================

// Circuit breaker state
typedef struct {
    _Atomic int state;                // Current state (CLOSED, OPEN, HALF_OPEN)
    _Atomic uint64_t failure_count;   // Consecutive failures
    _Atomic uint64_t success_count;   // Consecutive successes (for HALF_OPEN)
    _Atomic time_t last_failure_time; // Last failure timestamp
    pthread_mutex_t lock;             // State transition lock
} circuit_breaker_t;

static circuit_breaker_t g_circuit_breaker = {
    .state = LLAMAFIREWALL_CB_CLOSED,
    .failure_count = 0,
    .success_count = 0,
    .last_failure_time = 0,
    .lock = PTHREAD_MUTEX_INITIALIZER,
};

// ============================================================================
// STATISTICS (Prometheus metrics, following Presidio pattern)
// ============================================================================

static llamafirewall_stats_t g_stats = {0};

// ============================================================================
// INITIALIZATION
// ============================================================================

/**
 * Initialize LlamaFirewall client with configuration
 *
 * @param server_url Server URL (e.g., "localhost:50052")
 * @return 0 on success, -1 on error
 */
int sockproxy_llamafirewall_init(const char *server_url) {
    printf("[LlamaFirewall-DEBUG] sockproxy_llamafirewall_init called: server_url='%s'\n",
           server_url ? server_url : "(null)");

    if (g_initialized) {
        printf("[LlamaFirewall-DEBUG] Already initialized, returning success\n");
        return 0;  // Already initialized
    }

    // Set server URL
    if (server_url && strlen(server_url) > 0) {
        printf("[LlamaFirewall-DEBUG] Setting server URL to: %s\n", server_url);
        strncpy(g_llamafirewall_config.server_url, server_url,
                sizeof(g_llamafirewall_config.server_url) - 1);
    } else {
        printf("[LlamaFirewall-DEBUG] WARNING: server_url is NULL or empty\n");
    }

    // Call Go bridge initialization
    printf("[LlamaFirewall-DEBUG] Calling llb_llamafirewall_init('%s')...\n",
           g_llamafirewall_config.server_url);
    int ret = llb_llamafirewall_init(g_llamafirewall_config.server_url);
    printf("[LlamaFirewall-DEBUG] llb_llamafirewall_init returned: %d\n", ret);

    if (ret != 0) {
        fprintf(stderr, "[LlamaFirewall] Initialization failed for %s (ret=%d)\n",
                g_llamafirewall_config.server_url, ret);
        return -1;
    }

    // Mark as initialized and enabled
    g_initialized = 1;
    g_llamafirewall_config.enabled = 1;

    printf("[LlamaFirewall] Initialized with server: %s (g_initialized=%d)\n",
           g_llamafirewall_config.server_url, g_initialized);
    return 0;
}

/**
 * Cleanup LlamaFirewall client connection
 *
 * Closes the gRPC connection and resets initialization state.
 * Safe to call multiple times.
 *
 * @return 0 on success, -1 on error
 */
int sockproxy_llamafirewall_cleanup(void) {
    if (!g_initialized) {
        return 0;  // Already cleaned up
    }

    // Call Go bridge cleanup
    int ret = llb_llamafirewall_close();
    if (ret != 0) {
        fprintf(stderr, "[LlamaFirewall] Cleanup failed\n");
        return -1;
    }

    // Mark as not initialized
    g_initialized = 0;
    g_llamafirewall_config.enabled = 0;

    printf("[LlamaFirewall] Cleanup complete\n");
    return 0;
}

// ============================================================================
// SCANNING FUNCTIONS
// ============================================================================

/**
 * Scan API request for security threats
 * Combines method, path, and body into single content string for scanning
 *
 * @param method HTTP method (e.g., "POST", "GET")
 * @param path URL path (e.g., "/api/v1/chat")
 * @param body Request body (can be NULL)
 * @param result Output scan result
 * @return 0 on success, -1 on error
 */
int sockproxy_llamafirewall_scan_request(
    const char *method,
    const char *path,
    const char *body,
    security_scan_result_t *result
) {
    if (!g_llamafirewall_config.enabled) {
        // Not enabled - allow by default
        result->decision = DECISION_ALLOW;
        result->status = STATUS_SUCCESS;
        result->score = 0.0f;
        result->scanner_count = 0;
        result->reason = NULL;
        result->error_msg[0] = '\0';
        return 0;
    }

    // Check circuit breaker before scanning
    if (!llamafirewall_circuit_breaker_allow_request()) {
        // Circuit open - apply fail policy
        if (g_llamafirewall_config.fail_closed) {
            result->decision = DECISION_BLOCK;
            snprintf(result->error_msg, sizeof(result->error_msg),
                    "Circuit breaker open (fail-closed policy)");
            atomic_fetch_add(&g_stats.fail_closed_blocks, 1);
        } else {
            result->decision = DECISION_ALLOW;
            snprintf(result->error_msg, sizeof(result->error_msg),
                    "Circuit breaker open (fail-open policy)");
            atomic_fetch_add(&g_stats.fail_open_bypasses, 1);
        }
        result->status = STATUS_ERROR;
        result->score = 0.0f;
        result->scanner_count = 0;
        result->reason = NULL;
        atomic_fetch_add(&g_stats.circuit_breaker_rejects, 1);
        return 0;  // Not an error - policy applied
    }

    // Combine method, path, and body for scanning
    char content[8192];
    int len = snprintf(content, sizeof(content), "%s %s\n%s",
                      method ? method : "UNKNOWN",
                      path ? path : "/",
                      body ? body : "");

    if (len >= sizeof(content)) {
        // Content too large
        snprintf(result->error_msg, sizeof(result->error_msg),
                "Content too large (%d bytes)", len);
        result->decision = DECISION_ALLOW;  // Fail-open
        result->status = STATUS_ERROR;
        result->score = 0.0f;
        result->scanner_count = 0;
        result->reason = NULL;
        atomic_fetch_add(&g_stats.scan_errors, 1);
        llamafirewall_circuit_breaker_record_failure();
        return -1;
    }

    // Track request
    atomic_fetch_add(&g_stats.requests_scanned, 1);
    atomic_fetch_add(&g_stats.bytes_scanned, (uint64_t)len);

    // Use default scanners: "prompt_guard,regex"
    // PromptGuard catches prompt injection, Regex catches credentials
    const char *scanners = "prompt_guard,regex";

    // Call Go bridge
    int ret = llb_llamafirewall_scan(
        content,
        ROLE_USER,  // User requests are scanned as ROLE_USER
        scanners,
        result
    );

    if (ret != 0) {
        // Scan failed - record failure and apply fail-open/fail-closed policy
        llamafirewall_circuit_breaker_record_failure();
        atomic_fetch_add(&g_stats.scan_errors, 1);

        if (g_llamafirewall_config.fail_closed) {
            result->decision = DECISION_BLOCK;
            snprintf(result->error_msg, sizeof(result->error_msg),
                    "Security scan failed (fail-closed policy)");
            atomic_fetch_add(&g_stats.fail_closed_blocks, 1);
        } else {
            result->decision = DECISION_ALLOW;
            atomic_fetch_add(&g_stats.fail_open_bypasses, 1);
            // error_msg already populated by Go bridge
        }
        return -1;
    }

    // Scan succeeded - record success and track results
    llamafirewall_circuit_breaker_record_success();

    if (result->decision == DECISION_BLOCK) {
        atomic_fetch_add(&g_stats.threats_detected, 1);
        atomic_fetch_add(&g_stats.requests_blocked, 1);
    }

    return 0;
}

/**
 * Scan AI-generated response for security issues
 * Used for scanning assistant responses (e.g., code, instructions)
 *
 * @param content Response content to scan
 * @param result Output scan result
 * @return 0 on success, -1 on error
 */
int sockproxy_llamafirewall_scan_response(
    const char *content,
    security_scan_result_t *result
) {
    if (!g_llamafirewall_config.enabled) {
        result->decision = DECISION_ALLOW;
        result->status = STATUS_SUCCESS;
        result->score = 0.0f;
        result->scanner_count = 0;
        result->reason = NULL;
        result->error_msg[0] = '\0';
        return 0;
    }

    if (!content) {
        result->decision = DECISION_ALLOW;
        result->status = STATUS_SUCCESS;
        result->score = 0.0f;
        result->scanner_count = 0;
        result->reason = NULL;
        result->error_msg[0] = '\0';
        return 0;
    }

    // Check circuit breaker before scanning
    if (!llamafirewall_circuit_breaker_allow_request()) {
        // Circuit open - apply fail policy
        if (g_llamafirewall_config.fail_closed) {
            result->decision = DECISION_BLOCK;
            snprintf(result->error_msg, sizeof(result->error_msg),
                    "Circuit breaker open (fail-closed policy)");
            atomic_fetch_add(&g_stats.fail_closed_blocks, 1);
        } else {
            result->decision = DECISION_ALLOW;
            snprintf(result->error_msg, sizeof(result->error_msg),
                    "Circuit breaker open (fail-open policy)");
            atomic_fetch_add(&g_stats.fail_open_bypasses, 1);
        }
        result->status = STATUS_ERROR;
        result->score = 0.0f;
        result->scanner_count = 0;
        result->reason = NULL;
        atomic_fetch_add(&g_stats.circuit_breaker_rejects, 1);
        return 0;  // Not an error - policy applied
    }

    // Track request
    atomic_fetch_add(&g_stats.requests_scanned, 1);
    atomic_fetch_add(&g_stats.bytes_scanned, (uint64_t)strlen(content));

    // For assistant responses, use CodeShield + Regex
    // CodeShield detects insecure code, Regex catches credential leaks
    const char *scanners = "code_shield,regex";

    // Call Go bridge
    int ret = llb_llamafirewall_scan(
        content,
        ROLE_ASSISTANT,  // Assistant responses scanned as ROLE_ASSISTANT
        scanners,
        result
    );

    if (ret != 0) {
        // Scan failed - record failure and apply fail-open/fail-closed policy
        llamafirewall_circuit_breaker_record_failure();
        atomic_fetch_add(&g_stats.scan_errors, 1);

        if (g_llamafirewall_config.fail_closed) {
            result->decision = DECISION_BLOCK;
            snprintf(result->error_msg, sizeof(result->error_msg),
                    "Response security scan failed (fail-closed policy)");
            atomic_fetch_add(&g_stats.fail_closed_blocks, 1);
        } else {
            result->decision = DECISION_ALLOW;
            atomic_fetch_add(&g_stats.fail_open_bypasses, 1);
        }
        return -1;
    }

    // Scan succeeded - record success and track results
    llamafirewall_circuit_breaker_record_success();

    if (result->decision == DECISION_BLOCK) {
        atomic_fetch_add(&g_stats.threats_detected, 1);
        atomic_fetch_add(&g_stats.requests_blocked, 1);
    }

    return 0;
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Check if request should be blocked based on scan result
 *
 * @param result Scan result from llb_llamafirewall_scan()
 * @return true if should block, false otherwise
 */
bool sockproxy_llamafirewall_should_block(security_scan_result_t *result) {
    if (!result) {
        return false;
    }

    // Check decision
    if (result->decision == DECISION_BLOCK) {
        return true;
    }

    // Check score threshold (if configured)
    if (result->score >= g_llamafirewall_config.block_threshold) {
        return true;
    }

    return false;
}

/**
 * Get human-readable decision string
 *
 * @param decision Decision enum value
 * @return String representation
 */
const char* sockproxy_llamafirewall_decision_str(uint8_t decision) {
    switch (decision) {
        case DECISION_UNSPECIFIED: return "UNSPECIFIED";
        case DECISION_ALLOW: return "ALLOW";
        case DECISION_BLOCK: return "BLOCK";
        case DECISION_HUMAN_IN_THE_LOOP: return "HITL";
        default: return "UNKNOWN";
    }
}

/**
 * Get human-readable scanner type string
 *
 * @param scanner_type Scanner enum value
 * @return String representation
 */
const char* sockproxy_llamafirewall_scanner_str(uint8_t scanner_type) {
    switch (scanner_type) {
        case SCANNER_UNSPECIFIED: return "UNSPECIFIED";
        case SCANNER_PROMPT_GUARD: return "PromptGuard";
        case SCANNER_CODE_SHIELD: return "CodeShield";
        case SCANNER_REGEX: return "Regex";
        case SCANNER_HIDDEN_ASCII: return "HiddenASCII";
        case SCANNER_AGENT_ALIGNMENT: return "AgentAlignment";
        case SCANNER_PII_DETECTION: return "PII";
        default: return "UNKNOWN";
    }
}

/**
 * Free scan result memory
 * Must be called after using result from llb_llamafirewall_scan()
 *
 * @param result Scan result to free
 */
void sockproxy_llamafirewall_free_result(security_scan_result_t *result) {
    if (result) {
        llb_llamafirewall_free_result(result);
    }
}

/**
 * Get global configuration
 *
 * @return Pointer to global configuration (read-only)
 */
llamafirewall_config_t* sockproxy_llamafirewall_get_config(void) {
    return &g_llamafirewall_config;
}

/**
 * Set configuration
 *
 * @param config New configuration to apply
 */
void sockproxy_llamafirewall_set_config(llamafirewall_config_t *config) {
    if (config) {
        memcpy(&g_llamafirewall_config, config, sizeof(llamafirewall_config_t));
    }
}

// ============================================================================
// CIRCUIT BREAKER IMPLEMENTATION (following Presidio pattern)
// ============================================================================

/**
 * Record successful operation - may close circuit if in HALF_OPEN
 */
void llamafirewall_circuit_breaker_record_success(void) {
    pthread_mutex_lock(&g_circuit_breaker.lock);

    int state = atomic_load(&g_circuit_breaker.state);

    if (state == LLAMAFIREWALL_CB_HALF_OPEN) {
        // Increment success count
        uint64_t successes = atomic_fetch_add(&g_circuit_breaker.success_count, 1) + 1;

        // Get config with fallback
        llamafirewall_config_shm_t *cfg = llamafirewall_config_get();
        uint32_t success_threshold = cfg ? cfg->circuit_breaker_success_threshold : 3;

        // Check if we should close the circuit
        if (successes >= success_threshold) {
            atomic_store(&g_circuit_breaker.state, LLAMAFIREWALL_CB_CLOSED);
            atomic_store(&g_circuit_breaker.failure_count, 0);
            atomic_store(&g_circuit_breaker.success_count, 0);
            printf("[LlamaFirewall-CB] Circuit CLOSED after %llu successes\n", (unsigned long long)successes);
        }
    }

    pthread_mutex_unlock(&g_circuit_breaker.lock);
}

/**
 * Record failure - may open circuit if threshold exceeded
 */
void llamafirewall_circuit_breaker_record_failure(void) {
    pthread_mutex_lock(&g_circuit_breaker.lock);

    int state = atomic_load(&g_circuit_breaker.state);
    llamafirewall_config_shm_t *cfg = llamafirewall_config_get();
    if (!cfg) {
        pthread_mutex_unlock(&g_circuit_breaker.lock);
        return;
    }

    if (state == LLAMAFIREWALL_CB_CLOSED) {
        // Increment failure count
        uint64_t failures = atomic_fetch_add(&g_circuit_breaker.failure_count, 1) + 1;

        // Check if we should open the circuit
        uint32_t threshold = cfg->circuit_breaker_threshold;
        uint32_t timeout = cfg->circuit_breaker_timeout_sec;

        if (failures >= threshold) {
            atomic_store(&g_circuit_breaker.state, LLAMAFIREWALL_CB_OPEN);
            atomic_store(&g_circuit_breaker.last_failure_time, time(NULL));
            atomic_fetch_add(&g_stats.circuit_breaker_opens, 1);

            fprintf(stderr, "[LlamaFirewall-CB] ⚠️  Circuit OPENED (threshold %u failures exceeded) - "
                           "scanning BYPASSED for %u seconds\n", threshold, timeout);
        }
    } else if (state == LLAMAFIREWALL_CB_HALF_OPEN) {
        // Failure during half-open - immediately reopen circuit
        atomic_store(&g_circuit_breaker.state, LLAMAFIREWALL_CB_OPEN);
        atomic_store(&g_circuit_breaker.last_failure_time, time(NULL));
        atomic_store(&g_circuit_breaker.success_count, 0);

        fprintf(stderr, "[LlamaFirewall-CB] ⚠️  Circuit RE-OPENED (recovery attempt failed)\n");
    }

    pthread_mutex_unlock(&g_circuit_breaker.lock);
}

/**
 * Check if circuit breaker allows request
 * @return 1 if allowed, 0 if rejected
 */
int llamafirewall_circuit_breaker_allow_request(void) {
    int state = atomic_load(&g_circuit_breaker.state);

    if (state == LLAMAFIREWALL_CB_CLOSED) {
        return 1;  // Normal operation
    }

    if (state == LLAMAFIREWALL_CB_OPEN) {
        // Check if timeout expired - transition to HALF_OPEN
        time_t now = time(NULL);
        time_t last_failure = atomic_load(&g_circuit_breaker.last_failure_time);
        llamafirewall_config_shm_t *cfg = llamafirewall_config_get();
        uint32_t timeout = cfg ? cfg->circuit_breaker_timeout_sec : 60;

        if ((now - last_failure) >= timeout) {
            pthread_mutex_lock(&g_circuit_breaker.lock);

            // Double-check state (race condition protection)
            if (atomic_load(&g_circuit_breaker.state) == LLAMAFIREWALL_CB_OPEN) {
                atomic_store(&g_circuit_breaker.state, LLAMAFIREWALL_CB_HALF_OPEN);
                atomic_store(&g_circuit_breaker.success_count, 0);
                printf("[LlamaFirewall-CB] 🔄 Circuit HALF-OPEN (testing recovery)\n");
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

/**
 * Reset circuit breaker to CLOSED state
 */
void llamafirewall_reset_circuit_breaker(void) {
    pthread_mutex_lock(&g_circuit_breaker.lock);
    atomic_store(&g_circuit_breaker.state, LLAMAFIREWALL_CB_CLOSED);
    atomic_store(&g_circuit_breaker.failure_count, 0);
    atomic_store(&g_circuit_breaker.success_count, 0);
    pthread_mutex_unlock(&g_circuit_breaker.lock);

    printf("[LlamaFirewall-CB] Circuit breaker manually reset to CLOSED\n");
}

/**
 * Get current circuit state
 */
llamafirewall_circuit_state_t llamafirewall_get_circuit_state(void) {
    return (llamafirewall_circuit_state_t)atomic_load(&g_circuit_breaker.state);
}

/**
 * Check if service is healthy (circuit closed)
 */
int llamafirewall_is_healthy(void) {
    int state = atomic_load(&g_circuit_breaker.state);
    return (state == LLAMAFIREWALL_CB_CLOSED);
}

// ============================================================================
// STATISTICS FUNCTIONS
// ============================================================================

/**
 * Get statistics pointer (read-only access)
 */
llamafirewall_stats_t* llamafirewall_get_stats(void) {
    return &g_stats;
}

/**
 * Reset all statistics to zero
 */
void llamafirewall_reset_stats(void) {
    memset(&g_stats, 0, sizeof(llamafirewall_stats_t));
    printf("[LlamaFirewall-Stats] All statistics reset to zero\n");
}
