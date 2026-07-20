/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */
#ifndef __LXB_CATALOG_H__
#define __LXB_CATALOG_H__

#include <stdint.h>

/**
 * Service Catalog Configuration - Shared Memory Structure
 * 
 * This structure is written by Go control plane and read by C dataplane
 * Memory layout: /dev/shm/loxilb-catalog-config (mmap'd)
 * 
 * Architecture:
 * - Go: Loads YAML catalogs -> Populates shared memory
 * - C:  Reads shared memory -> Makes sampling decisions
 */

#define LXB_MAX_CATALOGS 256
#define LXB_MAX_PATH_LEN 96
#define LXB_MAX_SERVICES 256  // Max services with tracing enabled

/**
 * Service-to-Catalog Mapping Entry
 * Maps a service (VIP:port:proto) to its catalog_id
 * Size: 16 bytes
 */
typedef struct __attribute__((packed)) {
  uint32_t xip;        // Service VIP (network byte order)
  uint16_t xport;      // Service port (network byte order)
  uint8_t  protocol;   // Protocol (6=TCP, 17=UDP)
  uint8_t  _pad;       // Alignment
  uint16_t catalog_id; // Catalog ID (1-255, 0=unused entry)
  uint16_t _reserved;  // Future use
  uint32_t _reserved2; // Future use
} lxb_service_catalog_map_t;

/**
 * Per-catalog configuration for deep inspection
 * Size: 128 bytes (cache-line friendly)
 */
typedef struct __attribute__((packed)) {
  // === Identification ===
  uint16_t id;               // Catalog ID (1-255, 0 reserved for "no catalog")
  uint8_t  enabled;          // Deep inspection enabled (1=yes, 0=no)
  uint8_t  sample_rate;      // 0-100 (percent)
  
  // === Parser Configuration ===
  uint8_t  parser_type;      // 0=generic, 1=openai, 2=mcp, 3=graphql, 4=mock
  uint8_t  redact_pii;       // PII redaction enabled (1=yes, 0=no)
  uint16_t _pad1;            // Alignment padding
  uint32_t max_body_size;    // Max body size to capture (bytes)
  
  // === Path Matching ===
  char     path_prefix[LXB_MAX_PATH_LEN]; // HTTP path prefix (e.g., "/v1/chat/completions")
  
  // === L4 Tracing Configuration (Phase 3) ===
  uint8_t  l4_tracing_enabled;  // L4 connection tracing (1=yes, 0=no)
  uint8_t  l4_sampling_rate;    // L4 sampling rate 0-100 (percent)
  uint8_t  _pad2[2];            // Alignment padding
  
  // === Reserved for Future Use ===
  uint8_t  _reserved[12];
  
} lxb_catalog_config_t;

// Compile-time size check
#ifdef __cplusplus
typedef char __lxb_catalog_config_size_check[sizeof(lxb_catalog_config_t) == 128 ? 1 : -1];
#endif

/**
 * Global Catalog Array (Shared Memory)
 * Total size: 256 * 128 = 32KB (fits in L2 cache)
 */
#ifndef __cplusplus
extern lxb_catalog_config_t g_catalog_configs[LXB_MAX_CATALOGS];
#endif

/**
 * Global Service-to-Catalog Mapping (Shared Memory)
 * Total size: 256 * 16 = 4KB
 */
#ifndef __cplusplus
extern lxb_service_catalog_map_t g_service_catalog_map[LXB_MAX_SERVICES];
#endif

/**
 * Fast Lookup Cache (Separate Array for Hot Path)
 * Stores only sample rates for quick access
 * Size: 256 bytes (fits in L1 cache)
 */
#ifndef __cplusplus
extern uint8_t g_catalog_sample_rates[LXB_MAX_CATALOGS];
#endif

/**
 * Parser Type Enumeration
 */
#define LXB_PARSER_GENERIC  0
#define LXB_PARSER_OPENAI   1
#define LXB_PARSER_MCP      2
#define LXB_PARSER_GRAPHQL  3
#define LXB_PARSER_MOCK     4

/**
 * Helper Functions (implemented in sockproxy.c)
 */

// Lookup catalog ID by service key (VIP:port:proto)
// Returns: catalog_id (1-255) or 0 if no match
uint16_t lxb_lookup_service_catalog(uint32_t xip, uint16_t xport, uint8_t protocol);

// Lookup catalog ID by HTTP path
// Returns: catalog_id (1-255) or 0 if no match
uint16_t lxb_lookup_catalog_id(const char *path, size_t path_len);

// Sampling decision based on catalog config
// Returns: 1 if should sample, 0 otherwise
int lxb_should_sample(uint16_t catalog_id);

// Capture HTTP body to tmpfs
// Returns: 0 on success, -1 on error
int lxb_capture_body_to_tmpfs(uint64_t trace_id_hi, uint64_t span_id,
                                const char *body, size_t body_len,
                                uint16_t catalog_id);

#endif /* __LXB_CATALOG_H__ */
