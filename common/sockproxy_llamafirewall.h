/*
 * Copyright (c) 2025 LoxiLB Authors
 * SPDX short identifier: BSD-3-Clause
 *
 * AI Security Scanner: C Layer Header
 *
 * This header provides C API for LlamaFirewall security scanning integration.
 * Follows Presidio pattern for consistency with existing PII detection.
 *
 * Features:
 * - Prompt injection detection (PromptGuard)
 * - Insecure code detection (CodeShield)
 * - Credential leak detection (Regex)
 * - Hidden character attacks (HiddenASCII)
 * - Agent alignment checking (AgentAlignment)
 * - PII detection (complementary to Presidio)
 */

#ifndef __SOCKPROXY_LLAMAFIREWALL_H__
#define __SOCKPROXY_LLAMAFIREWALL_H__

#ifdef HAVE_LLAMAFIREWALL

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdatomic.h>
#include <pthread.h>

// ============================================================================
// ENUMS (must match proto definitions)
// ============================================================================

// Scanner type enum (matches llamafirewall.proto)
typedef enum {
    SCANNER_UNSPECIFIED = 0,
    SCANNER_PROMPT_GUARD = 1,
    SCANNER_CODE_SHIELD = 2,
    SCANNER_REGEX = 3,
    SCANNER_HIDDEN_ASCII = 4,
    SCANNER_AGENT_ALIGNMENT = 5,
    SCANNER_PII_DETECTION = 6,
} llamafirewall_scanner_type_t;

// Scan decision enum (matches proto)
typedef enum {
    DECISION_UNSPECIFIED = 0,
    DECISION_ALLOW = 1,
    DECISION_BLOCK = 2,
    DECISION_HUMAN_IN_THE_LOOP = 3,
} llamafirewall_decision_t;

// Scan status enum (matches proto)
typedef enum {
    STATUS_UNSPECIFIED = 0,
    STATUS_SUCCESS = 1,
    STATUS_ERROR = 2,
    STATUS_PARTIAL = 3,
} llamafirewall_status_t;

// Role enum (matches proto)
typedef enum {
    ROLE_UNSPECIFIED = 0,
    ROLE_USER = 1,
    ROLE_ASSISTANT = 2,
    ROLE_SYSTEM = 3,
    ROLE_TOOL = 4,
    ROLE_MEMORY = 5,
} llamafirewall_role_t;

// ============================================================================
// DATA STRUCTURES
// ============================================================================

// Security scan result structure (matches CGO definition in ai_security.go)
typedef struct {
    uint8_t decision;        // llamafirewall_decision_t
    char *reason;            // Explanation string (caller must free)
    float score;             // Confidence score (0.0-1.0)
    uint8_t status;          // llamafirewall_status_t
    int scanner_count;       // Number of scanner results
    char error_msg[256];     // Error description
} security_scan_result_t;

// Individual scanner result
typedef struct {
    uint8_t scanner_type;    // llamafirewall_scanner_type_t
    uint8_t decision;        // llamafirewall_decision_t
    char *reason;            // Scanner explanation (caller must free)
    float score;             // Scanner confidence score
    int64_t latency_ms;      // Scanner execution time
} scanner_result_t;

// LlamaFirewall configuration
typedef struct {
    char server_url[256];
    uint8_t enabled;
    uint8_t fail_closed;     // 0=fail open (allow on error), 1=fail closed (block on error)
    uint8_t scanner_mask;    // Bitmask of enabled scanners
    float block_threshold;   // Minimum score to block (0.0-1.0)
} llamafirewall_config_t;

// ============================================================================
// CIRCUIT BREAKER (prevent cascading failures, following Presidio pattern)
// ============================================================================

// Circuit breaker states
typedef enum {
    LLAMAFIREWALL_CB_CLOSED      = 0,  // Normal operation
    LLAMAFIREWALL_CB_OPEN        = 1,  // Circuit open - skip scanning
    LLAMAFIREWALL_CB_HALF_OPEN   = 2,  // Testing if service recovered
} llamafirewall_circuit_state_t;

// ============================================================================
// STATISTICS (Prometheus metrics, following Presidio pattern)
// ============================================================================

typedef struct llamafirewall_stats {
    // Core metrics
    _Atomic uint64_t requests_scanned;
    _Atomic uint64_t threats_detected;
    _Atomic uint64_t requests_blocked;
    _Atomic uint64_t scan_errors;
    _Atomic uint64_t scan_timeouts;
    _Atomic uint64_t bytes_scanned;
    _Atomic uint64_t total_latency_us;

    // Per-scanner metrics
    _Atomic uint64_t prompt_guard_scans;
    _Atomic uint64_t prompt_guard_detections;
    _Atomic uint64_t code_shield_scans;
    _Atomic uint64_t code_shield_detections;
    _Atomic uint64_t regex_scans;
    _Atomic uint64_t regex_detections;

    // Circuit breaker metrics
    _Atomic uint64_t circuit_breaker_opens;   // Times circuit opened
    _Atomic uint64_t circuit_breaker_rejects; // Requests rejected when open
    _Atomic uint64_t fail_open_bypasses;      // Traffic allowed due to FAIL_OPEN
    _Atomic uint64_t fail_closed_blocks;      // Traffic blocked due to FAIL_CLOSED

    // Error breakdown
    _Atomic uint64_t connection_errors;    // gRPC connection failures
    _Atomic uint64_t grpc_errors;          // gRPC protocol errors
    _Atomic uint64_t parse_errors;         // Response parsing errors
    _Atomic uint64_t memory_errors;        // Memory allocation failures
} llamafirewall_stats_t;

// ============================================================================
// CGO FUNCTION DECLARATIONS (implemented in Go: ai_security.go)
// ============================================================================

// Initialize LlamaFirewall client connection
// Returns: 0 on success, -1 on error
extern int llb_llamafirewall_init(const char *server_url);

// Scan content for security threats
// Parameters:
//   content: Text content to scan
//   role: Message role (ROLE_USER, ROLE_ASSISTANT, etc.)
//   scanners: Comma-separated scanner names (e.g., "prompt_guard,regex")
//             Empty string uses default: "prompt_guard,regex"
//   result: Output scan result structure
// Returns: 0 on success, -1 on error
extern int llb_llamafirewall_scan(
    const char *content,
    int role,
    const char *scanners,
    security_scan_result_t *result
);

// Check server health
// Returns: 0 if healthy, -1 on error
extern int llb_llamafirewall_health_check(void);

// Free scan result memory
// Must be called to free reason string allocated by llb_llamafirewall_scan()
extern void llb_llamafirewall_free_result(security_scan_result_t *result);

// Close client connection
// Returns: 0 on success, -1 on error
extern int llb_llamafirewall_close(void);

// ============================================================================
// C HELPER FUNCTIONS (implemented in sockproxy_llamafirewall.c)
// ============================================================================

// Initialize LlamaFirewall client with configuration
int sockproxy_llamafirewall_init(const char *server_url);

// Cleanup LlamaFirewall client connection
int sockproxy_llamafirewall_cleanup(void);

// Scan API request for security threats
// Combines method, path, and body into single content string for scanning
int sockproxy_llamafirewall_scan_request(
    const char *method,
    const char *path,
    const char *body,
    security_scan_result_t *result
);

// Scan AI-generated response for security issues (e.g., code vulnerabilities)
int sockproxy_llamafirewall_scan_response(
    const char *content,
    security_scan_result_t *result
);

// Check if request should be blocked based on scan result
bool sockproxy_llamafirewall_should_block(security_scan_result_t *result);

// Get human-readable decision string
const char* sockproxy_llamafirewall_decision_str(uint8_t decision);

// Get human-readable scanner type string
const char* sockproxy_llamafirewall_scanner_str(uint8_t scanner_type);

// Free scan result memory (wrapper for CGO function)
void sockproxy_llamafirewall_free_result(security_scan_result_t *result);

// Get global configuration
llamafirewall_config_t* sockproxy_llamafirewall_get_config(void);

// Set configuration
void sockproxy_llamafirewall_set_config(llamafirewall_config_t *config);

// ============================================================================
// CIRCUIT BREAKER FUNCTIONS (following Presidio pattern)
// ============================================================================

// Record successful operation (may close circuit if in HALF_OPEN)
void llamafirewall_circuit_breaker_record_success(void);

// Record failed operation (may open circuit if threshold exceeded)
void llamafirewall_circuit_breaker_record_failure(void);

// Check if circuit breaker allows request (0=reject, 1=allow)
int llamafirewall_circuit_breaker_allow_request(void);

// Reset circuit breaker to CLOSED state
void llamafirewall_reset_circuit_breaker(void);

// Get current circuit state
llamafirewall_circuit_state_t llamafirewall_get_circuit_state(void);

// Check if service is healthy (circuit closed)
int llamafirewall_is_healthy(void);

// ============================================================================
// STATISTICS FUNCTIONS
// ============================================================================

// Get statistics pointer (read-only access)
llamafirewall_stats_t* llamafirewall_get_stats(void);

// Reset all statistics to zero
void llamafirewall_reset_stats(void);

// ============================================================================
// CONSTANTS
// ============================================================================

// Default server address
#define LLAMAFIREWALL_DEFAULT_SERVER "localhost:50052"

// Default scanner mask (PromptGuard + Regex)
#define LLAMAFIREWALL_DEFAULT_SCANNERS ((1 << SCANNER_PROMPT_GUARD) | (1 << SCANNER_REGEX))

// Default block threshold
#define LLAMAFIREWALL_DEFAULT_THRESHOLD 0.9f

// Maximum content size (50MB, same as gRPC max message size)
#define LLAMAFIREWALL_MAX_CONTENT_SIZE (50 * 1024 * 1024)

#endif /* HAVE_LLAMAFIREWALL */

#endif /* __SOCKPROXY_LLAMAFIREWALL_H__ */
