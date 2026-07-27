/*
 * Copyright (c) 2025 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */

#ifndef __PRESIDIO_CONFIG_H__
#define __PRESIDIO_CONFIG_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// PRESIDIO DYNAMIC CONFIGURATION
// Following the same pattern as lxb_catalog_config for L4/L7 tracing
// Configuration stored in shared memory for dynamic hot-reload
// ============================================================================

#define PRESIDIO_CONFIG_SHM_PATH "/dev/shm/loxilb_presidio_config"
#define PRESIDIO_MAX_URL_PATTERNS 64

// Detection modes
#define PRESIDIO_MODE_DETECT_ONLY   0
#define PRESIDIO_MODE_MASK_IN_PLACE 1
#define PRESIDIO_MODE_REDACT_FULL   2
#define PRESIDIO_MODE_ANONYMIZE     3

// Scan modes for large bodies
#define PRESIDIO_SCAN_MODE_FULL     0  // Skip bodies >max_body_size (scan complete only)
#define PRESIDIO_SCAN_MODE_TRUNCATE 1  // Scan first max_body_size bytes (recommended)

// Direction filters
#define PRESIDIO_DIR_BOTH           0
#define PRESIDIO_DIR_REQUEST_ONLY   1
#define PRESIDIO_DIR_RESPONSE_ONLY  2

// Fail modes
#define PRESIDIO_FAIL_OPEN   0
#define PRESIDIO_FAIL_CLOSED 1

// === JSON Field Mapping (.1) ===
#define PRESIDIO_MAX_JSON_FIELDS 32
#define PRESIDIO_MAX_JSONPATH_LENGTH 128
#define PRESIDIO_MAX_ENTITY_TYPES_PER_FIELD 8

/**
 * JSON Field Configuration Entry (internal config structure)
 * Maps JSONPath expressions to entity types for targeted anonymization
 * Note: Different from presidio_json_field_mapping_t used by Go bridge
 */
typedef struct {
    char json_path[PRESIDIO_MAX_JSONPATH_LENGTH];  // JSONPath: $.messages[*].content
    char entity_types[PRESIDIO_MAX_ENTITY_TYPES_PER_FIELD][32]; // Entity types to detect
    uint8_t entity_types_count;         // Number of entity types
    uint8_t operator_type;              // Override operator (0-4, 255=use default)
    uint8_t priority;                   // 0=low, 1=medium, 2=high
    uint8_t always_scan;                // 1=scan even if no PII detected
    char operator_params[64];           // Custom operator params (JSON string)
    uint8_t _padding[3];                // Alignment
} presidio_json_field_config_t;

/**
 * JSON Configuration (stored in shared memory)
 */
typedef struct {
    presidio_json_field_config_t field_mappings[PRESIDIO_MAX_JSON_FIELDS];
    uint8_t num_field_mappings;         // Number of active mappings
    
    // Excluded JSON paths (fields to skip PII detection)
    char exclude_fields[PRESIDIO_MAX_JSON_FIELDS][PRESIDIO_MAX_JSONPATH_LENGTH];
    uint8_t num_exclude_fields;         // Number of excluded fields
    uint8_t _padding[6];                // Alignment
} presidio_json_config_t;

/**
 * URL Pattern Entry (similar to catalog path_prefix)
 */
typedef struct {
    char pattern[128];     // URL pattern with wildcards: "/v1/chat/*"
    uint8_t enabled;       // 1=active, 0=disabled
    uint8_t is_exclude;    // 1=exclude pattern, 0=include pattern
    uint8_t _padding[2];   // Alignment
} presidio_url_pattern_entry_t;

/**
 * Main Presidio Configuration (stored in shared memory)
 * Similar to lxb_catalog_config_t structure
 */
typedef struct {
    // === Core Settings ===
    uint8_t enabled;                    // Global enable/disable flag
    uint8_t mode;                       // Detection mode (0-3)
    uint8_t direction;                  // Traffic direction (0-2)
    uint8_t fail_mode;                  // Fail-safe behavior (0-1)
    uint8_t scan_mode;                  // Large body handling (0=full, 1=truncate, 2=skip)
    
    // === Thresholds ===
    float score_threshold;              // PII confidence threshold (0.0-1.0)
    uint32_t timeout_ms;                // Per-request timeout
    uint32_t max_body_size;             // Max body to scan (bytes)
    uint32_t min_body_size;             // Min body size worth scanning
    
    // === Endpoints ===
    char analyzer_url[256];             // Analyzer gRPC endpoint
    char anonymizer_url[256];           // Anonymizer gRPC endpoint (optional)
    
    // === URL Pattern Matching ===
    uint8_t url_mode;                   // 0=all, 1=include-list, 2=exclude-list
    uint8_t num_url_patterns;           // Number of active patterns
    uint8_t _padding1[2];               // Alignment
    presidio_url_pattern_entry_t url_patterns[PRESIDIO_MAX_URL_PATTERNS];
    
    // === Circuit Breaker Settings ===
    uint32_t circuit_breaker_threshold;     // Failures before opening
    uint32_t circuit_breaker_timeout_sec;   // Seconds before retry
    uint32_t circuit_breaker_success_threshold; // Successes to close
    
    // === Retry Settings ===
    uint32_t max_retries;               // Max retry attempts
    uint32_t retry_backoff_ms;          // Backoff between retries
    
    // === Version Control (for hot-reload detection) ===
    uint64_t config_version;            // Incremented on each update
    uint64_t last_update_ts;            // Timestamp of last update
    
    // ========================================================================
    // V2 EXTENSIONS 
    // ========================================================================
    
    // === V2 API Control ===
    uint8_t enable_v2;                  // Enable v2 API features
    uint8_t default_operator;           // Default anonymization operator (0-4)
    uint8_t store_metadata;             // Store anonymization metadata for decryption
    uint8_t _padding_v2[1];             // Alignment
    
    // === Encryption Settings ===
    char encryption_key[64];            // Base64-encoded encryption key (AES-256)
    uint32_t encryption_algorithm;      // 0=AES-256-GCM (default), 1=AES-128-GCM
    
    // === JSON Anonymization (.1) ===
    uint8_t enable_json_detection;      // Auto-detect JSON payloads
    uint8_t json_fallback_to_text;      // Fallback to text mode if JSON parsing fails
    uint8_t json_response_scanning;     // Also scan JSON responses
    uint8_t json_preserve_structure;    // Ensure valid JSON output
    
    uint8_t num_json_mappings;          // Number of active JSON field mappings
    uint8_t _padding_json[3];           // Alignment
    
    // === Batch Processing ===
    uint32_t batch_size;                // Items per batch stream (default: 10)
    uint32_t batch_timeout_ms;          // Batch processing timeout
    
    // === Custom Recognizers (.2) ===
    uint8_t num_custom_recognizers;     // Number of registered custom recognizers
    uint8_t custom_recognizers_enabled; // Enable custom recognizer loading
    uint8_t _padding_custom[2];         // Alignment
    // Note: Custom recognizers stored separately (registered at runtime)
    
    // === JSON Field Mappings (.1) ===
    presidio_json_config_t json_config; // JSON anonymization configuration
    
} presidio_config_shm_t;

/**
 * Configuration wrapper with local cache
 * Mirrors the g_catalog_configs pattern
 */
typedef struct {
    presidio_config_shm_t shm_config;   // Current config from shared memory
    uint64_t last_reload_version;       // Last version we loaded
    int shm_fd;                         // Shared memory file descriptor
    void *shm_addr;                     // Mapped memory address
} presidio_runtime_config_t;
// ============================================================================
// CUSTOM RECOGNIZER CONFIGURATION (.2)
// ============================================================================

#define PRESIDIO_MAX_CUSTOM_RECOGNIZERS 100
#define PRESIDIO_MAX_PATTERNS_PER_RECOGNIZER 8
#define PRESIDIO_MAX_CONTEXT_WORDS 16
#define PRESIDIO_MAX_REGEX_LENGTH 512
#define PRESIDIO_CUSTOM_PATTERNS_FILE "/etc/loxilb/presidio_custom_patterns.json"

/**
 * Regex Pattern Definition
 */
typedef struct {
    char name[64];                      // Pattern name
    char regex[PRESIDIO_MAX_REGEX_LENGTH];  // Regex pattern
    float score;                        // Confidence score (0.0-1.0)
} presidio_pattern_config_t;

/**
 * Custom Recognizer Definition (stored in memory)
 */
typedef struct {
    char name[64];                      // Recognizer name (e.g., "EMPLOYEE_ID")
    char entity_type[64];               // Entity type (e.g., "CUSTOM_EMPLOYEE_ID")
    presidio_pattern_config_t patterns[PRESIDIO_MAX_PATTERNS_PER_RECOGNIZER];
    int pattern_count;                  // Number of patterns
    char context_words[PRESIDIO_MAX_CONTEXT_WORDS][64];  // Context hints
    int context_word_count;             // Number of context words
    float score;                        // Default score if not in pattern
    uint8_t enabled;                    // 1=active, 0=disabled
    time_t registered_at;               // Registration timestamp
    char registered_by[64];             // User/process that registered
} presidio_custom_recognizer_config_t;

/**
 * Custom Recognizer Registry (in-memory management)
 */
typedef struct {
    presidio_custom_recognizer_config_t recognizers[PRESIDIO_MAX_CUSTOM_RECOGNIZERS];
    int count;                          // Number of registered recognizers
    pthread_rwlock_t lock;              // Thread-safe access
    time_t last_load_time;              // Last file load timestamp
} presidio_recognizer_registry_t;

// Configuration management functions
int presidio_config_init(void);
int presidio_config_reload(void);
presidio_config_shm_t* presidio_config_get(void);
int presidio_config_is_enabled(void);
void presidio_config_dump(void);
void presidio_config_cleanup(void);

// Custom recognizer registry management (.2)
int presidio_registry_init(void);
void presidio_registry_cleanup(void);
int presidio_registry_add(presidio_custom_recognizer_config_t *recognizer);
int presidio_registry_remove(const char *name);
int presidio_registry_find(const char *name, presidio_custom_recognizer_config_t **out_recognizer);
int presidio_registry_get_all(presidio_custom_recognizer_config_t **recognizers, int *count);
int presidio_registry_load_from_file(const char *filepath);
int presidio_registry_count(void);

// Pattern validation
int presidio_validate_regex(const char *pattern);
int presidio_validate_recognizer(presidio_custom_recognizer_config_t *recognizer);
#ifdef __cplusplus
}
#endif

#endif /* __PRESIDIO_CONFIG_H__ */
