/*
 * Copyright (c) 2025 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 *
 * PII Detection: CGO Bridge Stubs (for C-only builds)
 * 
 * This file provides stub implementations for CGO bridge functions
 * when building C-only binaries (e.g., loxilb_dp_debug) without Go runtime.
 */

#include <stdio.h>
#include <string.h>
#include "log.h"

// Stub implementations for CGO bridge functions
// These are used when PII detection is enabled but Go bridge is not available

int llb_presidio_init(const char *analyzer_url, const char *anonymizer_url) {
    log_warn("[Presidio-Stub] llb_presidio_init called in C-only build - not supported");
    return -1;
}

int llb_presidio_enable(void) {
    log_warn("[Presidio-Stub] llb_presidio_enable called in C-only build - not supported");
    return -1;
}

int llb_presidio_disable(void) {
    log_warn("[Presidio-Stub] llb_presidio_disable called in C-only build - not supported");
    return 0;
}

int llb_presidio_is_enabled(void) {
    return 0;  // Always disabled in C-only builds
}

int llb_presidio_configure(const char *analyzer_url, const char *anonymizer_url,
                           int mode, int direction, float score_threshold,
                           unsigned int timeout_ms) {
    log_warn("[Presidio-Stub] llb_presidio_configure called in C-only build - not supported");
    return -1;
}

void* llb_presidio_scan(const char *content, const char *language, int catalog_id) {
    log_warn("[Presidio-Stub] llb_presidio_scan called in C-only build - not supported");
    return NULL;
}

void llb_presidio_free_result(void *result) {
    // No-op in stub
}

int llb_presidio_health_check(void) {
    return 0;  // Always unhealthy in C-only builds
}
