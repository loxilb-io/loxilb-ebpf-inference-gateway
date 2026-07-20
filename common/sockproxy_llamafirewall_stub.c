/*
 * Copyright (c) 2025 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 *
 * LlamaFirewall: CGO Bridge Stubs (for C-only builds)
 *
 * This file provides stub implementations for LlamaFirewall CGO bridge functions
 * when building C-only binaries (e.g., loxilb_dp_debug) without Go runtime.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "log.h"
#include "sockproxy_llamafirewall.h"

// ============================================================================
// STUB IMPLEMENTATIONS
// ============================================================================

int llb_llamafirewall_init(const char *server_url) {
    log_warn("[LlamaFirewall-Stub] llb_llamafirewall_init called in C-only build - not supported");
    return -1;
}

int llb_llamafirewall_scan(
    const char *content,
    int role,
    const char *scanners,
    security_scan_result_t *result
) {
    log_warn("[LlamaFirewall-Stub] llb_llamafirewall_scan called in C-only build - not supported");

    // Fill in stub result (allow everything)
    if (result) {
        result->decision = DECISION_ALLOW;
        result->status = STATUS_ERROR;
        result->score = 0.0f;
        result->scanner_count = 0;
        result->reason = NULL;
        snprintf(result->error_msg, sizeof(result->error_msg),
                "LlamaFirewall not available in C-only build");
    }

    return -1;
}

void llb_llamafirewall_free_result(security_scan_result_t *result) {
    // No-op in stub
}

int llb_llamafirewall_health_check(void) {
    return -1;  // Always unhealthy in C-only builds
}

char* llb_llamafirewall_get_stats(void) {
    return NULL;
}

int llb_llamafirewall_close(void) {
    log_warn("[LlamaFirewall-Stub] llb_llamafirewall_close called in C-only build - not supported");
    return 0;  // Return success to avoid breaking cleanup flow
}
