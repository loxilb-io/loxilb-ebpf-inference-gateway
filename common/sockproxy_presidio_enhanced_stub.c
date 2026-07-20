/*
 * Copyright (c) 2025 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 *
 * PII Detection v2: CGO Bridge Stubs (for C-only builds)
 * 
 * This file provides stub implementations for v2 CGO bridge functions
 * when building C-only binaries (e.g., loxilb_dp_debug) without Go runtime.
 */

#include <stdio.h>
#include <string.h>
#include "log.h"

// ============================================================================
// V2 STUB IMPLEMENTATIONS
// ============================================================================

int llb_presidio_v2_init(const char *server_url) {
    log_warn("[Presidio-v2-Stub] llb_presidio_v2_init called in C-only build - not supported");
    return -1;
}

void* llb_presidio_analyze_and_anonymize(
    const char *text,
    const char *language,
    void *operators
) {
    log_warn("[Presidio-v2-Stub] llb_presidio_analyze_and_anonymize called in C-only build - not supported");
    return NULL;
}

char* llb_presidio_deanonymize(
    const char *encrypted_text,
    void *items,
    int item_count,
    const char *decryption_key
) {
    log_warn("[Presidio-v2-Stub] llb_presidio_deanonymize called in C-only build - not supported");
    return NULL;
}

char* llb_presidio_anonymize_json(
    const char *json_data,
    const char *language,
    void *entity_mapping,
    void *operators
) {
    log_warn("[Presidio-v2-Stub] llb_presidio_anonymize_json called in C-only build - not supported");
    return NULL;
}

int llb_presidio_register_custom_recognizer(
    const char *name,
    const char *entity_type,
    void *patterns,
    int pattern_count,
    void *context_words,
    int context_word_count
) {
    log_warn("[Presidio-v2-Stub] llb_presidio_register_custom_recognizer called in C-only build - not supported");
    return -1;
}

void* llb_presidio_scan_batch(
    void *texts,
    void *lengths,
    int count,
    void *operators
) {
    log_warn("[Presidio-v2-Stub] llb_presidio_scan_batch called in C-only build - not supported");
    return NULL;
}

void llb_presidio_free_result_v2(void *result) {
    // No-op in stub
}

void llb_presidio_free_json_result(char *json_result) {
    // No-op in stub
}

int llb_presidio_health_check_v2(void) {
    return -1;  // Always unhealthy in C-only builds
}

char* llb_presidio_get_stats_v2(void) {
    return NULL;
}
