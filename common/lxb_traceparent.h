/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */
#ifndef __LXB_TRACEPARENT_H__
#define __LXB_TRACEPARENT_H__

#include <stdint.h>
#include <string.h>
#include <ctype.h>

/**
 * W3C Trace Context traceparent header parser
 * 
 * Specification: https://www.w3.org/TR/trace-context/#traceparent-header
 * 
 * Format: version-trace_id-parent_id-trace_flags
 * Example: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01
 * 
 * Components:
 * - version: 2-digit hex (currently only "00" supported)
 * - trace_id: 32-digit hex (128-bit)
 * - parent_id: 16-digit hex (64-bit)
 * - trace_flags: 2-digit hex (8-bit, bit 0 = sampled)
 * 
 * Performance: ~100ns for valid header (no allocations, stack-only)
 */

/**
 * Parse W3C traceparent header
 * 
 * @param header Null-terminated traceparent header string
 *               Example: "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
 * @param trace_id_hi Output: high 64 bits of trace_id
 * @param trace_id_lo Output: low 64 bits of trace_id
 * @param parent_span_id Output: parent span ID (64-bit)
 * @param flags Output: trace flags (bit 0 = sampled)
 * @return 0 on success, -1 on parse error
 */
static inline int lxb_parse_traceparent(const char *header,
                                         uint64_t *trace_id_hi,
                                         uint64_t *trace_id_lo,
                                         uint64_t *parent_span_id,
                                         uint8_t *flags) {
  // Minimum valid length: "00-" + 32 hex + "-" + 16 hex + "-" + 2 hex = 55 chars
  // Maximum reasonable length: 128 chars (with extra validation)
  size_t len = strlen(header);
  if (len < 55 || len > 128) {
    return -1;  // Invalid length
  }

  // Parse version (must be "00")
  if (header[0] != '0' || header[1] != '0' || header[2] != '-') {
    return -1;  // Unsupported version or malformed
  }

  const char *p = header + 3;  // Skip "00-"

  // Parse trace_id (32 hex digits = 128 bits)
  // High 64 bits (16 hex digits)
  uint64_t hi = 0;
  for (int i = 0; i < 16; i++) {
    char c = p[i];
    if (!isxdigit(c)) return -1;
    hi = (hi << 4) | (c <= '9' ? c - '0' : (c & 0xdf) - 'A' + 10);
  }
  
  // Low 64 bits (16 hex digits)
  uint64_t lo = 0;
  for (int i = 16; i < 32; i++) {
    char c = p[i];
    if (!isxdigit(c)) return -1;
    lo = (lo << 4) | (c <= '9' ? c - '0' : (c & 0xdf) - 'A' + 10);
  }
  
  // Validate trace_id is not all zeros (per spec)
  if (hi == 0 && lo == 0) {
    return -1;
  }

  if (p[32] != '-') return -1;  // Missing separator
  p += 33;  // Skip trace_id and "-"

  // Parse parent_id (16 hex digits = 64 bits)
  uint64_t parent = 0;
  for (int i = 0; i < 16; i++) {
    char c = p[i];
    if (!isxdigit(c)) return -1;
    parent = (parent << 4) | (c <= '9' ? c - '0' : (c & 0xdf) - 'A' + 10);
  }
  
  // Validate parent_id is not all zeros (per spec)
  if (parent == 0) {
    return -1;
  }

  if (p[16] != '-') return -1;  // Missing separator
  p += 17;  // Skip parent_id and "-"

  // Parse trace_flags (2 hex digits = 8 bits)
  uint8_t flag_byte = 0;
  for (int i = 0; i < 2; i++) {
    char c = p[i];
    if (!isxdigit(c)) return -1;
    flag_byte = (flag_byte << 4) | (c <= '9' ? c - '0' : (c & 0xdf) - 'A' + 10);
  }

  // Success - write outputs
  *trace_id_hi = hi;
  *trace_id_lo = lo;
  *parent_span_id = parent;
  *flags = flag_byte;

  return 0;
}

/**
 * Format trace ID as hex string (for logging/debugging)
 * 
 * @param trace_id_hi High 64 bits of trace_id
 * @param trace_id_lo Low 64 bits of trace_id
 * @param buf Output buffer (must be at least 33 bytes)
 */
static inline void lxb_format_trace_id(uint64_t trace_id_hi, uint64_t trace_id_lo, char *buf) {
  snprintf(buf, 33, "%016llx%016llx", 
           (unsigned long long)trace_id_hi, 
           (unsigned long long)trace_id_lo);
}

/**
 * Format span ID as hex string (for logging/debugging)
 * 
 * @param span_id Span ID (64-bit)
 * @param buf Output buffer (must be at least 17 bytes)
 */
static inline void lxb_format_span_id(uint64_t span_id, char *buf) {
  snprintf(buf, 17, "%016llx", (unsigned long long)span_id);
}

/**
 * Format traceparent header (for propagation to upstream)
 * 
 * @param trace_id_hi High 64 bits of trace_id
 * @param trace_id_lo Low 64 bits of trace_id
 * @param span_id Current span ID (becomes parent_id for child)
 * @param flags Trace flags
 * @param buf Output buffer (must be at least 55 bytes)
 */
static inline void lxb_format_traceparent(uint64_t trace_id_hi, 
                                           uint64_t trace_id_lo,
                                           uint64_t span_id, 
                                           uint8_t flags,
                                           char *buf) {
  snprintf(buf, 56, "00-%016llx%016llx-%016llx-%02x",
           (unsigned long long)trace_id_hi,
           (unsigned long long)trace_id_lo,
           (unsigned long long)span_id,
           flags);
}

/**
 * Check if trace is sampled (bit 0 of flags)
 * 
 * @param flags Trace flags byte
 * @return 1 if sampled, 0 if not sampled
 */
static inline int lxb_trace_is_sampled(uint8_t flags) {
  return flags & 0x01;
}

#endif /* __LXB_TRACEPARENT_H__ */
