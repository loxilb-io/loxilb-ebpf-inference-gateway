/*
 * Copyright (c) 2025 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */

#ifndef __SOCKPROXY_PRESIDIO_H__
#define __SOCKPROXY_PRESIDIO_H__

#include <stdint.h>
#include <stdatomic.h>
#include "presidio_config.h"  // Import shared memory config structures

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// PRESIDIO PII DETECTION: C Layer Integration
// ============================================================================
// This module provides the C-layer integration for Presidio PII detection
// service, following the xSync Consumer Pattern used in LlamaFirewall.
// It acts as a lightweight wrapper around Go CGO exports.
//
// Architecture:
//   sockproxy.c (C) → sockproxy_presidio.c (C) → Go Bridge → Presidio gRPC
//
// Build Flag: HAVE_PII_DETECTION
//
// Configuration: Uses presidio_config_shm_t from presidio_config.h
// ============================================================================

// Circuit breaker states (prevent cascading failures)
typedef enum {
    PRESIDIO_CB_CLOSED      = 0,  // Normal operation
    PRESIDIO_CB_OPEN        = 1,  // Circuit open - skip Presidio calls
    PRESIDIO_CB_HALF_OPEN   = 2,  // Testing if service recovered
} presidio_circuit_state_t;

// PII entity detected (matches proto definition)
typedef struct pii_entity {
    char entity_type[64];  // e.g., "EMAIL_ADDRESS", "CREDIT_CARD"
    int start;             // Start offset in text
    int end;               // End offset in text
    float score;           // Confidence score (0.0-1.0)
} pii_entity_t;

// Scan result returned from Go bridge
typedef struct pii_scan_result {
    char *anonymized_text;   // PII-masked version (caller must free)
    size_t anonymized_len;   // Explicit length (NOT strlen - may contain NUL bytes)
    pii_entity_t *entities;  // Array of detected entities (caller must free)
    int entity_count;        // Number of entities
    double latency_ms;       // Scan latency
    int error_code;          // 0=success, -1=error
    char error_msg[256];     // Error description
} pii_scan_result_t;

// ============================================================================
// V2 ENHANCED TYPES (Unified API)
// ============================================================================

// Anonymization operator types
typedef enum {
    PRESIDIO_OP_REPLACE = 0,  // Replace with <ENTITY_TYPE>
    PRESIDIO_OP_REDACT = 1,   // Replace with [REDACTED]
    PRESIDIO_OP_HASH = 2,     // SHA-256 hash
    PRESIDIO_OP_ENCRYPT = 3,  // AES-256 encryption (reversible)
    PRESIDIO_OP_MASK = 4,     // Partial masking (e.g., ***-**-1234)
} presidio_operator_type_t;

// Operator configuration
typedef struct {
    presidio_operator_type_t type;
    char params[256];  // JSON params: {"key": "secret", "masking_char": "*"}
} presidio_operator_config_t;

// Operators configuration (per entity type)
typedef struct {
    presidio_operator_config_t default_op;      // Default for all entities
    presidio_operator_config_t email_op;        // EMAIL_ADDRESS specific
    presidio_operator_config_t ssn_op;          // US_SSN specific
    presidio_operator_config_t credit_card_op;  // CREDIT_CARD specific
    presidio_operator_config_t phone_op;        // PHONE_NUMBER specific
    presidio_operator_config_t person_op;       // PERSON specific
    
    // Custom entity operators (up to 8)
    presidio_operator_config_t custom_ops[8];
    char custom_entity_types[8][64];
    uint8_t custom_op_count;
} presidio_operators_t;

// Anonymization item metadata (for decryption/tracking)
typedef struct {
    char entity_type[64];     // Entity type (e.g., "EMAIL_ADDRESS")
    int start;                // Position in anonymized text
    int end;                  // End position
    char operator_used[32];   // Which operator was used
    char original_text[256];  // Optional: original value (for reversibility)
} anonymized_item_t;

// Enhanced scan result (v2 API)
typedef struct {
    char *anonymized_text;         // Transformed text (caller must free)
    size_t anonymized_len;         // Explicit length (NOT strlen - may contain NUL bytes)
    pii_entity_t *entities;        // Array of detected entities
    anonymized_item_t *items;      // Anonymization metadata
    int entity_count;              // Number of entities detected
    int item_count;                // Number of anonymized items
    double latency_ms;             // Total latency
    int error_code;                // 0=success, -1=error
    char error_msg[256];           // Error description
} pii_scan_result_v2_t;

// JSON field mapping (field path → entity type) - for Go bridge
typedef struct {
    char field_path[128];   // e.g., "user.email", "messages[].content"
    char entity_type[64];   // e.g., "EMAIL_ADDRESS" or "" for auto-detect
} presidio_json_field_mapping_t;

// JSON field mappings collection - for Go bridge
typedef struct {
    presidio_json_field_mapping_t mappings[32];
    uint8_t mapping_count;
} presidio_json_mapping_t;

// JSON anonymization result
typedef struct {
    char *json_data;           // Anonymized JSON (valid structure, caller must free)
    int fields_anonymized;     // Number of fields modified
    double latency_ms;         // Latency
    int error_code;            // 0=success, -1=error
    char error_msg[256];       // Error description
} pii_json_result_t;

// Regex pattern definition
typedef struct {
    char name[64];
    char regex[256];
    float score;
} presidio_pattern_t;

// Custom recognizer definition
typedef struct {
    char name[64];
    char entity_type[64];
    presidio_pattern_t patterns[8];
    int pattern_count;
    char context_words[16][64];
    int context_word_count;
    float score;
} presidio_custom_recognizer_t;

// Statistics for Prometheus metrics
typedef struct presidio_stats {
    // Core metrics
    _Atomic uint64_t requests_scanned;
    _Atomic uint64_t entities_detected;
    _Atomic uint64_t requests_masked;
    _Atomic uint64_t scan_errors;
    _Atomic uint64_t scan_timeouts;
    _Atomic uint64_t bytes_scanned;
    _Atomic uint64_t bytes_masked;
    _Atomic uint64_t total_latency_us;
    
    // Large body handling
    _Atomic uint64_t bodies_truncated;     // Bodies scanned with truncation
    _Atomic uint64_t bodies_skipped_size;  // Bodies skipped due to size
    
    // Error breakdown for diagnostics
    _Atomic uint64_t connection_errors;    // gRPC connection failures
    _Atomic uint64_t grpc_errors;          // gRPC protocol errors
    _Atomic uint64_t parse_errors;         // Response parsing errors
    _Atomic uint64_t memory_errors;        // Memory allocation failures
    
    // Circuit breaker metrics
    _Atomic uint64_t circuit_breaker_opens;   // Times circuit opened
    _Atomic uint64_t circuit_breaker_rejects; // Requests rejected when open
    _Atomic uint64_t fail_open_bypasses;      // Traffic allowed due to FAIL_OPEN
    _Atomic uint64_t fail_closed_blocks;      // Traffic blocked due to FAIL_CLOSED
    
    // Retry metrics
    _Atomic uint64_t retry_attempts;       // Total retry attempts
    _Atomic uint64_t retry_successes;      // Retries that succeeded
} presidio_stats_t;

// ============================================================================
// EXTERNAL FUNCTIONS: Go CGO Exports
// ============================================================================
// These functions are implemented in Go (pkg/loxinet/pii_detection.go)
// and exported via CGO for C consumption.

// Initialize Presidio client connection
extern int llb_presidio_init(const char *analyzer_url, const char *anonymizer_url);

// Enable/disable PII detection at runtime
extern int llb_presidio_enable(void);
extern int llb_presidio_disable(void);
extern int llb_presidio_is_enabled(void);

// Configure detection parameters
extern int llb_presidio_configure(
    const char *analyzer_url,
    const char *anonymizer_url,
    int mode,
    int direction,
    double threshold,
    unsigned int timeout_ms
);

// Scan text for PII entities
// Returns opaque pointer to pii_scan_result_t (must call free_result after)
extern void* llb_presidio_scan(
    const char *content,
    const char *language,
    int catalog_id
);

// Free scan result memory
extern void llb_presidio_free_result(void *result);

// Get statistics as JSON string (caller must free)
extern char* llb_presidio_get_stats(void);

// Health check
extern int llb_presidio_health_check(void);

// ============================================================================
// V2 CGO EXPORTS (Enhanced Features)
// ============================================================================

// Initialize v2 (uses same unified client)
extern int llb_presidio_v2_init(const char *server_url);

// Combined analyze + anonymize (40% faster)
extern void* llb_presidio_analyze_and_anonymize(
    const char *text,
    const char *language,
    void *operators  // presidio_operators_t*
);

// Decrypt previously encrypted PII
extern void* llb_presidio_deanonymize(
    const char *encrypted_text,
    void *items,      // anonymized_item_t*
    int item_count,
    const char *decryption_key
);

// JSON anonymization (structure-aware)
extern void* llb_presidio_anonymize_json(
    const char *json_data,
    const char *language,
    void *entity_mapping,  // presidio_json_mapping_t*
    void *operators        // presidio_operators_t*
);

// Register custom recognizer (ad-hoc pattern)
extern int llb_presidio_register_custom_recognizer(
    const char *name,
    const char *entity_type,
    void *patterns,           // presidio_pattern_t*
    int pattern_count,
    void *context_words,      // char**
    int context_word_count
);

// Batch processing (streaming)
extern void* llb_presidio_scan_batch(
    void *texts,        // char**
    void *lengths,      // size_t*
    int count,
    void *operators     // presidio_operators_t*
);

// Free v2 result structures
extern void llb_presidio_free_result_v2(void *result);
extern void llb_presidio_free_json_result(void *result);

// Get v2 statistics as JSON
extern char* llb_presidio_get_stats_v2(void);

// Health check v2 service
extern int llb_presidio_health_check_v2(void);

// ============================================================================
// C LAYER API: Public Functions
// 
// NOTE: Configuration is managed via REST API → Shared Memory pattern
//       All config is read-only from shared memory (presidio_config.h)
//       No direct config modification functions in C layer
// ============================================================================

/**
 * Initialize Presidio client with configuration
 * @param config Configuration parameters
 * @return 0 on success, -1 on error
 */
int presidio_init(presidio_config_shm_t *config);

/**
 * Cleanup Presidio client resources
 */
void presidio_cleanup(void);

/**
 * Enable PII detection dynamically
 * @return 0 on success, -1 on error
 */
int presidio_enable(void);

/**
 * Disable PII detection dynamically
 * @return 0 on success, -1 on error
 */
int presidio_disable(void);

/**
 * Check if PII detection is enabled
 * @return 1 if enabled, 0 if disabled
 */
int presidio_is_enabled(void);

/**
 * Update configuration at runtime
 * CRITICAL: Must be called on shutdown to prevent memory leaks
 * - Frees all allocated memory
 * - Closes gRPC connections
 * - Clears statistics
 */
void presidio_cleanup(void);

/**
 * Check if Presidio service is healthy and reachable
 * Uses circuit breaker pattern to prevent cascading failures
 * @return 1 if healthy, 0 if unhealthy/unreachable
 */
int presidio_is_healthy(void);

/**
 * Get current circuit breaker state
 * @return Circuit breaker state (CLOSED, OPEN, HALF_OPEN)
 */
presidio_circuit_state_t presidio_get_circuit_state(void);

/**
 * Manually reset circuit breaker (force close)
 * Useful for operations/debugging
 */
void presidio_reset_circuit_breaker(void);

/**
 * Reconfigure Presidio at runtime (hot-reload)
 * @param config New configuration
 * @return 0 on success, -1 on error
 */
int presidio_reconfigure(presidio_config_shm_t *config);

/**
 * Initialize unified Presidio client (v2 wrapper with config)
 * @param config Presidio configuration
 * @return 0 on success, -1 on error
 */
int presidio_v2_init(presidio_config_shm_t *config);

/**
 * Scan content for PII and optionally mask it
 * @param content Text content to scan
 * @param content_len Length of content
 * @param catalog_id Service catalog ID (0 for default)
 * @param result Output: scan results (caller must call presidio_free_result)
 * @return 0 on success, -1 on error
 */
int presidio_scan(
    const char *content,
    size_t content_len,
    int catalog_id,
    pii_scan_result_t **result
);

/**
 * Free scan result memory
 * @param result Scan result to free
 */
void presidio_free_result(pii_scan_result_t *result);

/**
 * Circuit breaker functions (shared with v2)
 * Note: Prefixed with "presidio_" to avoid conflict with sockproxy's circuit breaker
 */
int presidio_circuit_breaker_allow_request(void);
void presidio_circuit_breaker_record_success(void);
void presidio_circuit_breaker_record_failure(void);

/**
 * Get current configuration
 * @param config Output: current config (from shared memory)
 * @return 0 on success, -1 on error
 */
int presidio_get_config(presidio_config_shm_t *config);

/**
 * Get statistics
 * @param stats Output: current statistics
 * @return 0 on success, -1 on error
 */
int presidio_get_stats(presidio_stats_t *stats);

/**
 * Reset statistics counters
 */
void presidio_reset_stats(void);

/**
 * Health check - verify Presidio service is reachable
 * @return 0 if healthy, -1 if unhealthy
 */
int presidio_health_check(void);

// ============================================================================
// HELPER FUNCTIONS: HTTP Body Extraction
// ============================================================================

/**
 * Check if HTTP message should be scanned for PII
 * @param data HTTP message data
 * @param len Message length
 * @param is_request 1 if request, 0 if response
 * @return 1 if should scan, 0 if skip
 */
int presidio_should_scan_http(const uint8_t *data, size_t len, int is_request);

/**
 * Check if URL matches configured patterns (OpenAI-style URL filtering)
 * Reads configuration from shared memory (presidio_config.h)
 * @param url URL path from HTTP request (e.g., "/v1/chat/completions")
 * @return 1 if should scan, 0 if skip based on URL patterns
 */
int presidio_url_matches(const char *url);

/**
 * Extract HTTP body from message
 * @param data HTTP message data
 * @param len Message length
 * @param body_len Output: body length
 * @return Pointer to body start, or NULL if not found
 */
const char* presidio_extract_http_body(const uint8_t *data, size_t len, size_t *body_len);

/**
 * Replace HTTP body with masked version
 * @param original Original HTTP message
 * @param orig_len Original length
 * @param new_body New body content
 * @param new_body_len New body length
 * @param output Output: new complete message (caller must free)
 * @param output_len Output: new message length
 * @return 0 on success, -1 on error
 */
int presidio_replace_http_body(
    const uint8_t *original,
    size_t orig_len,
    const char *new_body,
    size_t new_body_len,
    uint8_t **output,
    size_t *output_len
);

// ============================================================================
// V2 API: Enhanced C Layer Functions
// ============================================================================

/**
 * Combined analyze + anonymize (v2 - 40% faster than separate calls)
 * @param content Text content to scan and anonymize
 * @param content_len Length of content
 * @param operators Anonymization operators
 * @param result Output: enhanced scan results with metadata
 * @return 0 on success, -1 on error
 */
int presidio_scan_v2(
    const char *content,
    size_t content_len,
    presidio_operators_t *operators,
    pii_scan_result_v2_t **result
);

/**
 * Decrypt previously encrypted PII
 * @param encrypted_text Encrypted text
 * @param items Anonymization metadata
 * @param item_count Number of items
 * @param decryption_key Decryption key
 * @param result Output: decrypted text (caller must free)
 * @return 0 on success, -1 on error
 */
int presidio_decrypt(
    const char *encrypted_text,
    anonymized_item_t *items,
    int item_count,
    const char *decryption_key,
    char **result
);

/**
 * Anonymize JSON while preserving structure
 * Uses shared memory JSON configuration (presidio_config_shm_t)
 * @param json_data JSON string
 * @param json_len JSON length  
 * @param operators Anonymization operators
 * @param result Output: enhanced scan result (v2 format)
 * @return 0 on success, -1 on error
 */
int presidio_anonymize_json(
    const char *json_data,
    size_t json_len,
    presidio_operators_t *operators,
    pii_scan_result_v2_t **result
);

/**
 * Check if JSON anonymization is enabled
 * @return 1 if enabled, 0 otherwise
 */
int presidio_json_enabled(void);

/**
 * Register custom recognizer (ad-hoc pattern)
 * @param recognizer Custom recognizer definition
 * @return 0 on success, -1 on error
 */
int presidio_register_custom_recognizer(presidio_custom_recognizer_t *recognizer);

/**
 * Batch process multiple texts
 * @param texts Array of text pointers
 * @param lengths Array of text lengths
 * @param count Number of texts
 * @param operators Anonymization operators
 * @param results Output: array of results (caller must free)
 * @return 0 on success, -1 on error
 */
int presidio_scan_batch(
    const char **texts,
    size_t *lengths,
    int count,
    presidio_operators_t *operators,
    pii_scan_result_v2_t ***results
);

/**
 * Free v2 scan result
 * @param result Result to free
 */
void presidio_free_result_v2(pii_scan_result_v2_t *result);

/**
 * Free JSON result
 * @param result Result to free
 */
void presidio_free_json_result(pii_json_result_t *result);

/**
 * Free decrypted text
 * @param text Text to free
 */
void presidio_free_decrypted(char *text);

/**
 * Check if v2 API is available
 * @return 1 if available, 0 if not
 */
int presidio_v2_available(void);

/**
 * Health check v2 service
 * @return 0 if healthy, -1 if unhealthy
 */
int presidio_health_check_v2(void);

// ============================================================================
// HELPER FUNCTIONS (V2)
// ============================================================================

/**
 * Create default operators configuration
 * @param type Default operator type
 * @return Operators structure
 */
presidio_operators_t presidio_create_default_operators(presidio_operator_type_t type);

/**
 * Set encryption key for operators
 * @param operators Operators structure
 * @param key Encryption key
 */
void presidio_set_encryption_key(presidio_operators_t *operators, const char *key);

/**
 * Convert operator type to string
 * @param type Operator type
 * @return String representation
 */
const char* presidio_operator_to_string(presidio_operator_type_t type);

/**
 * Convert string to operator type
 * @param str String representation
 * @return Operator type
 */
presidio_operator_type_t presidio_operator_from_string(const char *str);

// ============================================================================
// CUSTOM RECOGNIZER FUNCTIONS (Phase 2.2)
// ============================================================================

/**
 * Register all custom recognizers from registry with Presidio server
 * Called at startup after configuration loading
 * @return 0 on success, -1 on error
 */
int presidio_register_custom_patterns(void);

/**
 * Reload custom recognizers from configuration file and re-register
 * Can be called via API for hot-reload
 * @return 0 on success, -1 on error
 */
int presidio_reload_custom_patterns(void);

#ifdef __cplusplus
}
#endif

#endif /* __SOCKPROXY_PRESIDIO_H__ */
