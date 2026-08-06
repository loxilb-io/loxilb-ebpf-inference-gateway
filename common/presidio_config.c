/*
 * Copyright (c) 2025 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
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
#include <pthread.h>
#include <json-c/json.h>
#include "presidio_config.h"
#include "log.h"

// Forward declarations
static int presidio_load_json_config(presidio_config_shm_t *config);

// ============================================================================
// PRESIDIO DYNAMIC CONFIGURATION MANAGEMENT
// Following the same pattern as lxb_catalog_init/lxb_catalog_reload
// ============================================================================

// Global runtime configuration
static presidio_runtime_config_t g_presidio_runtime = {
    .shm_fd = -1,
    .shm_addr = NULL,
    .last_reload_version = 0,
};

/**
 * Initialize Presidio configuration from shared memory
 * Similar to lxb_catalog_init()
 * 
 * @return 0 on success, -1 on error
 */
int presidio_config_init(void) {
    // Open shared memory file (read-only)
    int fd = open(PRESIDIO_CONFIG_SHM_PATH, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) {
            log_info("[Presidio-Config] Shared memory not found - using defaults");
            
            // Initialize with defaults
            memset(&g_presidio_runtime.shm_config, 0, sizeof(presidio_config_shm_t));
            g_presidio_runtime.shm_config.enabled = 0;  // Disabled by default
            g_presidio_runtime.shm_config.mode = PRESIDIO_MODE_MASK_IN_PLACE;
            g_presidio_runtime.shm_config.direction = PRESIDIO_DIR_BOTH;
            g_presidio_runtime.shm_config.fail_mode = PRESIDIO_FAIL_OPEN;
            g_presidio_runtime.shm_config.score_threshold = 0.7;
            g_presidio_runtime.shm_config.timeout_ms = 100;
            g_presidio_runtime.shm_config.max_body_size = 65536;
            g_presidio_runtime.shm_config.min_body_size = 100;
            strcpy(g_presidio_runtime.shm_config.analyzer_url, "localhost:50051");
            g_presidio_runtime.shm_config.circuit_breaker_threshold = 5;
            g_presidio_runtime.shm_config.circuit_breaker_timeout_sec = 60;
            g_presidio_runtime.shm_config.circuit_breaker_success_threshold = 3;
            g_presidio_runtime.shm_config.max_retries = 1;
            g_presidio_runtime.shm_config.retry_backoff_ms = 100;
            g_presidio_runtime.shm_config.enable_json_detection = 1;  // Enable JSON mode by default
            
            return 0;  // OK - using defaults
        }
        
        log_error("[Presidio-Config] Failed to open shared memory: %s", strerror(errno));
        return -1;
    }
    
    // Get file size
    struct stat st;
    if (fstat(fd, &st) < 0) {
        log_error("[Presidio-Config] fstat failed: %s", strerror(errno));
        close(fd);
        return -1;
    }
    
    // Validate size
    size_t expected_size = sizeof(presidio_config_shm_t);
    if (st.st_size != expected_size) {
        log_warn("[Presidio-Config] Size mismatch: got %ld, expected %zu - using defaults",
                 st.st_size, expected_size);
        close(fd);
        
        // Initialize with defaults
        memset(&g_presidio_runtime.shm_config, 0, sizeof(presidio_config_shm_t));
        g_presidio_runtime.shm_config.enabled = 0;
        return 0;
    }
    
    // Map shared memory
    void *addr = mmap(NULL, expected_size, PROT_READ, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        log_error("[Presidio-Config] mmap failed: %s", strerror(errno));
        close(fd);
        return -1;
    }
    
    // Save mapping info
    g_presidio_runtime.shm_fd = fd;
    g_presidio_runtime.shm_addr = addr;
    
    // Copy configuration
    memcpy(&g_presidio_runtime.shm_config, addr, sizeof(presidio_config_shm_t));
    g_presidio_runtime.last_reload_version = g_presidio_runtime.shm_config.config_version;
    
    // Load JSON field mappings if enabled
    if (g_presidio_runtime.shm_config.enable_json_detection) {
        presidio_load_json_config(&g_presidio_runtime.shm_config);
    }
    
    log_info("[Presidio-Config] ✓ Loaded from shared memory: version=%lu enabled=%d",
             g_presidio_runtime.shm_config.config_version,
             g_presidio_runtime.shm_config.enabled);
    
    return 0;
}

/**
 * Reload Presidio configuration from shared memory (hot-reload)
 * Similar to lxb_catalog_reload()
 * Called periodically or on-demand to pick up configuration changes
 * 
 * @return 0 on success, -1 on error, 1 if no changes
 */
int presidio_config_reload(void) {
    // Check if shared memory is mapped
    if (g_presidio_runtime.shm_fd < 0 || g_presidio_runtime.shm_addr == NULL) {
        // Not initialized yet - try to initialize
        return presidio_config_init();
    }
    
    // Get file size to detect truncation/changes
    struct stat st;
    if (fstat(g_presidio_runtime.shm_fd, &st) < 0) {
        log_error("[Presidio-Config] Reload fstat failed: %s", strerror(errno));
        return -1;
    }
    
    size_t expected_size = sizeof(presidio_config_shm_t);
    if (st.st_size != expected_size) {
        log_warn("[Presidio-Config] Size changed during reload: %ld vs %zu",
                 st.st_size, expected_size);
        
        // Remap
        munmap(g_presidio_runtime.shm_addr, expected_size);
        close(g_presidio_runtime.shm_fd);
        g_presidio_runtime.shm_fd = -1;
        g_presidio_runtime.shm_addr = NULL;
        
        return presidio_config_init();
    }
    
    // Read version from shared memory
    presidio_config_shm_t *shm_config = (presidio_config_shm_t *)g_presidio_runtime.shm_addr;
    uint64_t current_version = shm_config->config_version;
    
    // Check if version changed
    if (current_version == g_presidio_runtime.last_reload_version) {
        return 1;  // No changes
    }
    
    // Check if analyzer URL changed before copying new config
    int url_changed = 0;
    if (strcmp(g_presidio_runtime.shm_config.analyzer_url, shm_config->analyzer_url) != 0) {
        url_changed = 1;
        log_info("[Presidio-Config] 🔄 Analyzer URL changed: %s → %s",
                 g_presidio_runtime.shm_config.analyzer_url,
                 shm_config->analyzer_url);
    }
    
    // Copy new configuration
    memcpy(&g_presidio_runtime.shm_config, shm_config, sizeof(presidio_config_shm_t));
    g_presidio_runtime.last_reload_version = current_version;
    
    // Load JSON field mappings if enabled
    if (g_presidio_runtime.shm_config.enable_json_detection) {
        presidio_load_json_config(&g_presidio_runtime.shm_config);
    }
    
    log_info("[Presidio-Config] ♻️ Reloaded configuration: version=%lu enabled=%d mode=%d",
             current_version,
             g_presidio_runtime.shm_config.enabled,
             g_presidio_runtime.shm_config.mode);
    
    // Update Go gRPC client if URL changed (weak symbol - only available in Go binary)
    if (url_changed) {
        // Declare as weak symbol - won't cause link error if not present
        extern int llb_presidio_update_config(const char *analyzer_url) __attribute__((weak));
        
        if (llb_presidio_update_config != NULL) {
            int ret = llb_presidio_update_config(shm_config->analyzer_url);
            if (ret != 0) {
                log_warn("[Presidio-Config] Failed to update gRPC client with new URL");
            }
        }
    }
    
    return 0;
}

/**
 * Get current Presidio configuration
 * Thread-safe read-only access (returns pointer to internal config)
 * 
 * @return Pointer to current configuration, or NULL if not initialized
 */
presidio_config_shm_t* presidio_config_get(void) {
    // Return pointer to the runtime config
    // This is safe because callers only read from it
    if (g_presidio_runtime.shm_fd < 0 && !g_presidio_runtime.shm_config.enabled) {
        return NULL;
    }
    
    return &g_presidio_runtime.shm_config;
}

/**
 * Check if Presidio is enabled
 * Fast atomic check (no locking)
 * 
 * @return 1 if enabled, 0 if disabled
 */
int presidio_config_is_enabled(void) {
    return g_presidio_runtime.shm_config.enabled;
}

/**
 * Cleanup shared memory mapping
 * Called on shutdown
 */
void presidio_config_cleanup(void) {
    if (g_presidio_runtime.shm_addr != NULL) {
        munmap(g_presidio_runtime.shm_addr, sizeof(presidio_config_shm_t));
        g_presidio_runtime.shm_addr = NULL;
    }
    
    if (g_presidio_runtime.shm_fd >= 0) {
        close(g_presidio_runtime.shm_fd);
        g_presidio_runtime.shm_fd = -1;
    }
    
    log_info("[Presidio-Config] Cleanup complete");
}

/**
 * Print current configuration (debug helper)
 */
void presidio_config_dump(void) {
    presidio_config_shm_t *cfg = &g_presidio_runtime.shm_config;
    
    log_info("[Presidio-Config] Current Configuration:");
    log_info("  Version: %lu", cfg->config_version);
    log_info("  Enabled: %d", cfg->enabled);
    log_info("  Mode: %d (0=detect, 1=mask, 2=redact, 3=anonymize)", cfg->mode);
    log_info("  Direction: %d (0=both, 1=request, 2=response)", cfg->direction);
    log_info("  Fail Mode: %d (0=open, 1=closed)", cfg->fail_mode);
    log_info("  Threshold: %.2f", cfg->score_threshold);
    log_info("  Timeout: %u ms", cfg->timeout_ms);
    log_info("  Body Size: %u - %u bytes", cfg->min_body_size, cfg->max_body_size);
    log_info("  Analyzer: %s", cfg->analyzer_url);
    log_info("  URL Mode: %d (0=all, 1=include, 2=exclude)", cfg->url_mode);
    log_info("  URL Patterns: %d configured", cfg->num_url_patterns);
    
    for (int i = 0; i < cfg->num_url_patterns && i < PRESIDIO_MAX_URL_PATTERNS; i++) {
        if (cfg->url_patterns[i].enabled) {
            log_info("    [%d] %s (%s)",
                     i,
                     cfg->url_patterns[i].pattern,
                     cfg->url_patterns[i].is_exclude ? "EXCLUDE" : "INCLUDE");
        }
    }
}

// ============================================================================
// JSON FIELD MAPPINGS LOADER (.1)
// ============================================================================

/**
 * Parse JSON field mappings from file
 * File format: /etc/loxilb/presidio_json_fields.json
 * 
 * Example:
 * {
 *   "fields": [
 *     {
 *       "json_path": "$.messages[*].content",
 *       "entity_types": ["EMAIL_ADDRESS", "PHONE_NUMBER"],
 *       "operator": "replace",
 *       "priority": "high"
 *     }
 *   ]
 * }
 */
static int presidio_parse_json_fields_file(const char *filepath, presidio_json_config_t *config) {
    if (!filepath || !config) {
        return -1;
    }
    
    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        log_debug("[Presidio-JSON] No JSON fields config at %s, using defaults", filepath);
        return 0;  // Not an error - just no config
    }
    
    // Read entire file
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    if (file_size <= 0 || file_size > 1024*1024) {  // Max 1MB
        log_warn("[Presidio-JSON] Config file size invalid: %ld bytes", file_size);
        fclose(fp);
        return -1;
    }
    
    char *json_buf = malloc(file_size + 1);
    if (!json_buf) {
        fclose(fp);
        return -1;
    }
    
    size_t read_size = fread(json_buf, 1, file_size, fp);
    fclose(fp);
    json_buf[read_size] = '\0';
    
    // Parse JSON using json-c library (consistent with custom recognizers parsing)
    log_info("[Presidio-JSON] Parsing JSON fields file: %s (%ld bytes)", filepath, file_size);
    
    struct json_object *root = json_tokener_parse(json_buf);
    if (!root) {
        log_error("[Presidio-JSON] Failed to parse JSON file: %s", filepath);
        free(json_buf);
        return -1;
    }
    
    // Extract "exclude_fields" array (optional)
    struct json_object *exclude_array = NULL;
    if (json_object_object_get_ex(root, "exclude_fields", &exclude_array) &&
        json_object_is_type(exclude_array, json_type_array)) {
        
        int exclude_count = json_object_array_length(exclude_array);
        config->num_exclude_fields = (exclude_count > PRESIDIO_MAX_JSON_FIELDS) ?
                                      PRESIDIO_MAX_JSON_FIELDS : exclude_count;
        
        log_info("[Presidio-JSON] Found %d exclude field pattern(s)", exclude_count);
        
        for (int i = 0; i < config->num_exclude_fields; i++) {
            struct json_object *exclude_obj = json_object_array_get_idx(exclude_array, i);
            if (exclude_obj && json_object_is_type(exclude_obj, json_type_string)) {
                const char *exclude_path = json_object_get_string(exclude_obj);
                strncpy(config->exclude_fields[i], exclude_path, PRESIDIO_MAX_JSONPATH_LENGTH - 1);
                config->exclude_fields[i][PRESIDIO_MAX_JSONPATH_LENGTH - 1] = '\0';
                log_debug("[Presidio-JSON] Exclude field: %s", config->exclude_fields[i]);
            }
        }
    } else {
        config->num_exclude_fields = 0;
        log_debug("[Presidio-JSON] No exclude_fields specified");
    }
    
    // Extract "fields" array
    struct json_object *fields_array = NULL;
    if (!json_object_object_get_ex(root, "fields", &fields_array)) {
        log_error("[Presidio-JSON] Missing 'fields' field in JSON");
        json_object_put(root);
        free(json_buf);
        return -1;
    }
    
    if (!json_object_is_type(fields_array, json_type_array)) {
        log_error("[Presidio-JSON] 'fields' must be an array");
        json_object_put(root);
        free(json_buf);
        return -1;
    }
    
    int array_len = json_object_array_length(fields_array);
    config->num_field_mappings = (array_len > PRESIDIO_MAX_JSON_FIELDS) ? 
                                  PRESIDIO_MAX_JSON_FIELDS : array_len;
    
    log_info("[Presidio-JSON] Found %d field mapping(s) in configuration", array_len);
    
    // Parse each field mapping
    for (int i = 0; i < config->num_field_mappings; i++) {
        struct json_object *field_obj = json_object_array_get_idx(fields_array, i);
        if (!field_obj) continue;
        
        presidio_json_field_config_t *field = &config->field_mappings[i];
        memset(field, 0, sizeof(presidio_json_field_config_t));
        
        // Parse json_path (required)
        struct json_object *path_obj = NULL;
        if (json_object_object_get_ex(field_obj, "json_path", &path_obj)) {
            const char *path = json_object_get_string(path_obj);
            strncpy(field->json_path, path, PRESIDIO_MAX_JSONPATH_LENGTH - 1);
        } else {
            log_warn("[Presidio-JSON] Field %d missing 'json_path', skipping", i);
            continue;
        }
        
        // Parse entity_types array (optional)
        struct json_object *types_array = NULL;
        if (json_object_object_get_ex(field_obj, "entity_types", &types_array) &&
            json_object_is_type(types_array, json_type_array)) {
            
            int types_count = json_object_array_length(types_array);
            field->entity_types_count = (types_count > PRESIDIO_MAX_ENTITY_TYPES_PER_FIELD) ?
                                        PRESIDIO_MAX_ENTITY_TYPES_PER_FIELD : types_count;
            
            for (int j = 0; j < field->entity_types_count; j++) {
                struct json_object *type_obj = json_object_array_get_idx(types_array, j);
                if (type_obj) {
                    const char *type = json_object_get_string(type_obj);
                    strncpy(field->entity_types[j], type, 31);
                    field->entity_types[j][31] = '\0';
                }
            }
        }
        
        // Parse operator (optional, default: replace = 0)
        struct json_object *operator_obj = NULL;
        if (json_object_object_get_ex(field_obj, "operator", &operator_obj)) {
            const char *op = json_object_get_string(operator_obj);
            if (strcmp(op, "replace") == 0) {
                field->operator_type = 0;
            } else if (strcmp(op, "redact") == 0) {
                field->operator_type = 1;
            } else if (strcmp(op, "hash") == 0) {
                field->operator_type = 2;
            } else if (strcmp(op, "encrypt") == 0) {
                field->operator_type = 3;
            } else if (strcmp(op, "mask") == 0) {
                field->operator_type = 4;
            } else {
                field->operator_type = 0;  // Default to replace
            }
        } else {
            field->operator_type = 0;  // Default: PRESIDIO_OP_REPLACE
        }
        
        // Parse priority (optional)
        struct json_object *priority_obj = NULL;
        if (json_object_object_get_ex(field_obj, "priority", &priority_obj)) {
            const char *prio = json_object_get_string(priority_obj);
            if (strcmp(prio, "high") == 0) {
                field->priority = 2;
            } else if (strcmp(prio, "low") == 0) {
                field->priority = 0;
            } else {
                field->priority = 1;  // medium
            }
        } else {
            field->priority = 1;  // default medium
        }
        
        // Parse always_scan (optional, default: false)
        struct json_object *always_scan_obj = NULL;
        if (json_object_object_get_ex(field_obj, "always_scan", &always_scan_obj)) {
            field->always_scan = json_object_get_boolean(always_scan_obj);
        } else {
            field->always_scan = 0;
        }
        
        log_debug("[Presidio-JSON] Loaded field: %s (types: %d, op: %d, priority: %d)",
                  field->json_path, field->entity_types_count, field->operator_type, field->priority);
    }
    
    // Cleanup
    json_object_put(root);
    free(json_buf);
    
    log_info("[Presidio-JSON] ✓ Loaded %u field mapping(s) from %s", 
             config->num_field_mappings, filepath);
    
    return 0;
}

/**
 * Load JSON field mappings configuration
 * Called during presidio_config_init() if enable_json_detection is true
 */
int presidio_load_json_config(presidio_config_shm_t *config) {
    if (!config) {
        return -1;
    }
    
    // Initialize JSON config
    memset(&config->json_config, 0, sizeof(presidio_json_config_t));
    
    // Load from file
    const char *config_file = "/etc/loxilb/presidio_json_fields.json";
    int ret = presidio_parse_json_fields_file(config_file, &config->json_config);
    
    if (ret < 0) {
        log_warn("[Presidio-JSON] Failed to parse JSON fields config");
        return ret;
    }
    
    if (config->json_config.num_field_mappings == 0) {
        log_info("[Presidio-JSON] No field mappings configured, JSON mode will use fallback");
    }
    
    log_info("[Presidio-JSON] ✓ Loaded %u field mapping(s), %u exclude pattern(s)", 
             config->json_config.num_field_mappings,
             config->json_config.num_exclude_fields);
    
    return 0;
}

// ============================================================================
// CUSTOM RECOGNIZER REGISTRY (.2)
// ============================================================================

// Global custom recognizer registry
static presidio_recognizer_registry_t g_recognizer_registry = {
    .count = 0,
    .lock = PTHREAD_RWLOCK_INITIALIZER,
    .last_load_time = 0,
};

/**
 * Initialize custom recognizer registry
 */
int presidio_registry_init(void) {
    pthread_rwlock_wrlock(&g_recognizer_registry.lock);
    
    // Reset registry
    memset(g_recognizer_registry.recognizers, 0, sizeof(g_recognizer_registry.recognizers));
    g_recognizer_registry.count = 0;
    g_recognizer_registry.last_load_time = time(NULL);
    
    pthread_rwlock_unlock(&g_recognizer_registry.lock);
    
    log_info("[Presidio-Registry] ✓ Initialized custom recognizer registry");
    return 0;
}

/**
 * Cleanup custom recognizer registry
 */
void presidio_registry_cleanup(void) {
    pthread_rwlock_wrlock(&g_recognizer_registry.lock);
    
    g_recognizer_registry.count = 0;
    memset(g_recognizer_registry.recognizers, 0, sizeof(g_recognizer_registry.recognizers));
    
    pthread_rwlock_unlock(&g_recognizer_registry.lock);
    
    log_info("[Presidio-Registry] Cleanup complete");
}

/**
 * Validate regex pattern for ReDoS vulnerabilities
 * Simple heuristic checks - not comprehensive but catches common issues
 */
int presidio_validate_regex(const char *pattern) {
    if (!pattern || strlen(pattern) == 0) {
        log_warn("[Presidio-Validate] Empty regex pattern");
        return -1;
    }
    
    size_t len = strlen(pattern);
    if (len > PRESIDIO_MAX_REGEX_LENGTH) {
        log_warn("[Presidio-Validate] Regex too long: %zu > %d", len, PRESIDIO_MAX_REGEX_LENGTH);
        return -1;
    }
    
    // Check for catastrophic backtracking patterns
    // Pattern: (a+)+ or (a*)* or (a+)*
    int nested_quantifiers = 0;
    int paren_depth = 0;
    
    for (size_t i = 0; i < len - 1; i++) {
        if (pattern[i] == '(') {
            paren_depth++;
        } else if (pattern[i] == ')') {
            paren_depth--;
            // Check if followed by quantifier
            if (i + 1 < len && (pattern[i + 1] == '+' || pattern[i + 1] == '*' || pattern[i + 1] == '?')) {
                // Check if group contains quantifiers
                int has_inner_quantifier = 0;
                for (size_t j = i; j > 0 && pattern[j] != '('; j--) {
                    if (pattern[j] == '+' || pattern[j] == '*') {
                        has_inner_quantifier = 1;
                        break;
                    }
                }
                if (has_inner_quantifier) {
                    nested_quantifiers++;
                }
            }
        }
    }
    
    if (nested_quantifiers > 2) {
        log_warn("[Presidio-Validate] Potential ReDoS: nested quantifiers detected (%d)", nested_quantifiers);
        return -1;
    }
    
    // Check for unbalanced parentheses
    if (paren_depth != 0) {
        log_warn("[Presidio-Validate] Unbalanced parentheses in regex");
        return -1;
    }
    
    return 0;
}

/**
 * Validate custom recognizer configuration
 */
int presidio_validate_recognizer(presidio_custom_recognizer_config_t *recognizer) {
    if (!recognizer) {
        return -1;
    }
    
    // Check name
    if (strlen(recognizer->name) == 0) {
        log_warn("[Presidio-Validate] Recognizer name is empty");
        return -1;
    }
    
    // Check entity type
    if (strlen(recognizer->entity_type) == 0) {
        log_warn("[Presidio-Validate] Entity type is empty for recognizer: %s", recognizer->name);
        return -1;
    }
    
    // Check pattern count
    if (recognizer->pattern_count <= 0 || recognizer->pattern_count > PRESIDIO_MAX_PATTERNS_PER_RECOGNIZER) {
        log_warn("[Presidio-Validate] Invalid pattern count: %d (max: %d)",
                 recognizer->pattern_count, PRESIDIO_MAX_PATTERNS_PER_RECOGNIZER);
        return -1;
    }
    
    // Validate each pattern
    for (int i = 0; i < recognizer->pattern_count; i++) {
        if (presidio_validate_regex(recognizer->patterns[i].regex) != 0) {
            log_warn("[Presidio-Validate] Invalid regex in pattern %d of recognizer: %s",
                     i, recognizer->name);
            return -1;
        }
        
        // Check score range
        if (recognizer->patterns[i].score < 0.0 || recognizer->patterns[i].score > 1.0) {
            log_warn("[Presidio-Validate] Invalid score %.2f in pattern %d (must be 0.0-1.0)",
                     recognizer->patterns[i].score, i);
            return -1;
        }
    }
    
    // Check context word count
    if (recognizer->context_word_count > PRESIDIO_MAX_CONTEXT_WORDS) {
        log_warn("[Presidio-Validate] Too many context words: %d (max: %d)",
                 recognizer->context_word_count, PRESIDIO_MAX_CONTEXT_WORDS);
        return -1;
    }
    
    return 0;
}

/**
 * Add custom recognizer to registry
 */
int presidio_registry_add(presidio_custom_recognizer_config_t *recognizer) {
    if (!recognizer) {
        return -1;
    }
    
    // Validate recognizer
    if (presidio_validate_recognizer(recognizer) != 0) {
        log_error("[Presidio-Registry] Validation failed for recognizer: %s", recognizer->name);
        return -1;
    }
    
    pthread_rwlock_wrlock(&g_recognizer_registry.lock);
    
    // Check if already exists
    for (int i = 0; i < g_recognizer_registry.count; i++) {
        if (strcmp(g_recognizer_registry.recognizers[i].name, recognizer->name) == 0) {
            log_info("[Presidio-Registry] Recognizer '%s' already exists, updating", recognizer->name);
            memcpy(&g_recognizer_registry.recognizers[i], recognizer, 
                   sizeof(presidio_custom_recognizer_config_t));
            pthread_rwlock_unlock(&g_recognizer_registry.lock);
            return 0;
        }
    }
    
    // Check capacity
    if (g_recognizer_registry.count >= PRESIDIO_MAX_CUSTOM_RECOGNIZERS) {
        pthread_rwlock_unlock(&g_recognizer_registry.lock);
        log_error("[Presidio-Registry] Registry full: %d/%d", 
                  g_recognizer_registry.count, PRESIDIO_MAX_CUSTOM_RECOGNIZERS);
        return -1;
    }
    
    // Add new recognizer
    memcpy(&g_recognizer_registry.recognizers[g_recognizer_registry.count], 
           recognizer, sizeof(presidio_custom_recognizer_config_t));
    g_recognizer_registry.count++;
    
    pthread_rwlock_unlock(&g_recognizer_registry.lock);
    
    log_info("[Presidio-Registry] ✓ Added recognizer: %s (entity: %s, patterns: %d)",
             recognizer->name, recognizer->entity_type, recognizer->pattern_count);
    
    return 0;
}

/**
 * Remove custom recognizer from registry
 */
int presidio_registry_remove(const char *name) {
    if (!name) {
        return -1;
    }
    
    pthread_rwlock_wrlock(&g_recognizer_registry.lock);
    
    int found = -1;
    for (int i = 0; i < g_recognizer_registry.count; i++) {
        if (strcmp(g_recognizer_registry.recognizers[i].name, name) == 0) {
            found = i;
            break;
        }
    }
    
    if (found < 0) {
        pthread_rwlock_unlock(&g_recognizer_registry.lock);
        log_warn("[Presidio-Registry] Recognizer not found: %s", name);
        return -1;
    }
    
    // Shift remaining recognizers
    for (int i = found; i < g_recognizer_registry.count - 1; i++) {
        memcpy(&g_recognizer_registry.recognizers[i], 
               &g_recognizer_registry.recognizers[i + 1],
               sizeof(presidio_custom_recognizer_config_t));
    }
    
    g_recognizer_registry.count--;
    
    pthread_rwlock_unlock(&g_recognizer_registry.lock);
    
    log_info("[Presidio-Registry] Removed recognizer: %s", name);
    return 0;
}

/**
 * Find custom recognizer by name
 */
int presidio_registry_find(const char *name, presidio_custom_recognizer_config_t **out_recognizer) {
    if (!name || !out_recognizer) {
        return -1;
    }
    
    pthread_rwlock_rdlock(&g_recognizer_registry.lock);
    
    for (int i = 0; i < g_recognizer_registry.count; i++) {
        if (strcmp(g_recognizer_registry.recognizers[i].name, name) == 0) {
            *out_recognizer = &g_recognizer_registry.recognizers[i];
            pthread_rwlock_unlock(&g_recognizer_registry.lock);
            return 0;
        }
    }
    
    pthread_rwlock_unlock(&g_recognizer_registry.lock);
    return -1;
}

/**
 * Get all custom recognizers
 */
int presidio_registry_get_all(presidio_custom_recognizer_config_t **recognizers, int *count) {
    if (!recognizers || !count) {
        return -1;
    }
    
    pthread_rwlock_rdlock(&g_recognizer_registry.lock);
    
    *recognizers = g_recognizer_registry.recognizers;
    *count = g_recognizer_registry.count;
    
    pthread_rwlock_unlock(&g_recognizer_registry.lock);
    
    return 0;
}

/**
 * Get count of registered custom recognizers
 */
int presidio_registry_count(void) {
    pthread_rwlock_rdlock(&g_recognizer_registry.lock);
    int count = g_recognizer_registry.count;
    pthread_rwlock_unlock(&g_recognizer_registry.lock);
    return count;
}

/**
 * Load custom recognizers from JSON configuration file
 * 
 * File format: /etc/loxilb/presidio_custom_patterns.json
 * {
 *   \"custom_recognizers\": [
 *     {
 *       \"name\": \"EMPLOYEE_ID\",
 *       \"entity_type\": \"CUSTOM_EMPLOYEE_ID\",
 *       \"patterns\": [
 *         {\"name\": \"EMP_PATTERN\", \"regex\": \"EMP-[0-9]{6}\", \"score\": 0.9}
 *       ],
 *       \"context_words\": [\"employee\", \"staff\", \"worker\"],
 *       \"enabled\": true
 *     }
 *   ]
 * }
 */
int presidio_registry_load_from_file(const char *filepath) {
    if (!filepath) {
        filepath = PRESIDIO_CUSTOM_PATTERNS_FILE;
    }
    
    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        log_debug("[Presidio-Registry] No custom patterns file at %s", filepath);
        return 0;  // Not an error - just no config
    }
    
    // Read entire file
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    if (file_size <= 0 || file_size > 1048576) {  // Max 1MB
        log_warn("[Presidio-Registry] Invalid file size: %ld bytes", file_size);
        fclose(fp);
        return -1;
    }
    
    char *json_content = malloc(file_size + 1);
    if (!json_content) {
        fclose(fp);
        return -1;
    }
    
    size_t bytes_read = fread(json_content, 1, file_size, fp);
    json_content[bytes_read] = '\0';
    fclose(fp);
    
    // Parse JSON using json-c library
    log_info("[Presidio-Registry] Parsing custom patterns file: %s (%ld bytes)", filepath, file_size);
    
    struct json_object *root = json_tokener_parse(json_content);
    if (!root) {
        log_error("[Presidio-Registry] Failed to parse JSON file: %s", filepath);
        free(json_content);
        return -1;
    }
    
    // Extract "custom_recognizers" array
    struct json_object *recognizers_array = NULL;
    if (!json_object_object_get_ex(root, "custom_recognizers", &recognizers_array)) {
        log_error("[Presidio-Registry] Missing 'custom_recognizers' field in JSON");
        json_object_put(root);
        free(json_content);
        return -1;
    }
    
    if (!json_object_is_type(recognizers_array, json_type_array)) {
        log_error("[Presidio-Registry] 'custom_recognizers' must be an array");
        json_object_put(root);
        free(json_content);
        return -1;
    }
    
    int array_len = json_object_array_length(recognizers_array);
    log_info("[Presidio-Registry] Found %d custom recognizer(s) in configuration", array_len);
    
    int success_count = 0;
    int failure_count = 0;
    
    // Parse each recognizer
    for (int i = 0; i < array_len; i++) {
        struct json_object *rec_obj = json_object_array_get_idx(recognizers_array, i);
        if (!rec_obj) continue;
        
        presidio_custom_recognizer_config_t recognizer = {0};
        recognizer.enabled = 1;  // Default to enabled
        recognizer.score = 0.8;  // Default score
        recognizer.registered_at = time(NULL);
        strncpy(recognizer.registered_by, "config_file", sizeof(recognizer.registered_by) - 1);
        
        // Parse required fields: name, entity_type
        struct json_object *name_obj = NULL;
        if (json_object_object_get_ex(rec_obj, "name", &name_obj)) {
            const char *name = json_object_get_string(name_obj);
            strncpy(recognizer.name, name, sizeof(recognizer.name) - 1);
        } else {
            log_warn("[Presidio-Registry] Recognizer %d missing 'name' field, skipping", i);
            failure_count++;
            continue;
        }
        
        struct json_object *entity_type_obj = NULL;
        if (json_object_object_get_ex(rec_obj, "entity_type", &entity_type_obj)) {
            const char *entity_type = json_object_get_string(entity_type_obj);
            strncpy(recognizer.entity_type, entity_type, sizeof(recognizer.entity_type) - 1);
        } else {
            log_warn("[Presidio-Registry] Recognizer '%s' missing 'entity_type' field, skipping", 
                     recognizer.name);
            failure_count++;
            continue;
        }
        
        // Parse optional fields
        struct json_object *enabled_obj = NULL;
        if (json_object_object_get_ex(rec_obj, "enabled", &enabled_obj)) {
            recognizer.enabled = json_object_get_boolean(enabled_obj);
        }
        
        struct json_object *score_obj = NULL;
        if (json_object_object_get_ex(rec_obj, "score", &score_obj)) {
            recognizer.score = json_object_get_double(score_obj);
        }
        
        // Parse patterns array
        struct json_object *patterns_array = NULL;
        if (json_object_object_get_ex(rec_obj, "patterns", &patterns_array) &&
            json_object_is_type(patterns_array, json_type_array)) {
            
            int pattern_count = json_object_array_length(patterns_array);
            recognizer.pattern_count = (pattern_count > PRESIDIO_MAX_PATTERNS_PER_RECOGNIZER) ?
                                       PRESIDIO_MAX_PATTERNS_PER_RECOGNIZER : pattern_count;
            
            for (int j = 0; j < recognizer.pattern_count; j++) {
                struct json_object *pattern_obj = json_object_array_get_idx(patterns_array, j);
                if (!pattern_obj) continue;
                
                // Parse pattern name
                struct json_object *pattern_name_obj = NULL;
                if (json_object_object_get_ex(pattern_obj, "name", &pattern_name_obj)) {
                    const char *pattern_name = json_object_get_string(pattern_name_obj);
                    strncpy(recognizer.patterns[j].name, pattern_name, 
                            sizeof(recognizer.patterns[j].name) - 1);
                }
                
                // Parse regex (required)
                struct json_object *regex_obj = NULL;
                if (json_object_object_get_ex(pattern_obj, "regex", &regex_obj)) {
                    const char *regex = json_object_get_string(regex_obj);
                    strncpy(recognizer.patterns[j].regex, regex,
                            sizeof(recognizer.patterns[j].regex) - 1);
                } else {
                    log_warn("[Presidio-Registry] Pattern %d of '%s' missing regex, skipping pattern",
                             j, recognizer.name);
                    continue;
                }
                
                // Parse pattern score (optional, defaults to recognizer score)
                struct json_object *pattern_score_obj = NULL;
                if (json_object_object_get_ex(pattern_obj, "score", &pattern_score_obj)) {
                    recognizer.patterns[j].score = json_object_get_double(pattern_score_obj);
                } else {
                    recognizer.patterns[j].score = recognizer.score;
                }
            }
        } else {
            log_warn("[Presidio-Registry] Recognizer '%s' has no patterns, skipping", 
                     recognizer.name);
            failure_count++;
            continue;
        }
        
        // Parse context_words array (optional)
        struct json_object *context_words_array = NULL;
        if (json_object_object_get_ex(rec_obj, "context_words", &context_words_array) &&
            json_object_is_type(context_words_array, json_type_array)) {
            
            int context_count = json_object_array_length(context_words_array);
            recognizer.context_word_count = (context_count > PRESIDIO_MAX_CONTEXT_WORDS) ?
                                            PRESIDIO_MAX_CONTEXT_WORDS : context_count;
            
            for (int j = 0; j < recognizer.context_word_count; j++) {
                struct json_object *word_obj = json_object_array_get_idx(context_words_array, j);
                if (word_obj) {
                    const char *word = json_object_get_string(word_obj);
                    strncpy(recognizer.context_words[j], word,
                            sizeof(recognizer.context_words[j]) - 1);
                }
            }
        }
        
        // Add recognizer to registry
        int ret = presidio_registry_add(&recognizer);
        if (ret == 0) {
            success_count++;
            log_info("[Presidio-Registry] ✓ Loaded: %s (entity: %s, patterns: %d, enabled: %d)",
                     recognizer.name, recognizer.entity_type, 
                     recognizer.pattern_count, recognizer.enabled);
        } else {
            failure_count++;
            log_warn("[Presidio-Registry] ✗ Failed to add: %s", recognizer.name);
        }
    }
    
    // Cleanup
    json_object_put(root);
    free(json_content);
    
    // Update last load time
    g_recognizer_registry.last_load_time = time(NULL);
    
    log_info("[Presidio-Registry] ✓ Parsing complete: %d success, %d failed",
             success_count, failure_count);
    
    return (failure_count == 0) ? 0 : -1;
}

