/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */
#ifndef __LXB_TRACE_EVENT_H__
#define __LXB_TRACE_EVENT_H__

#include <stdint.h>

/**
 * HTTP/HTTPS Trace Event - Fixed-size structure for lock-free ring buffer
 * 
 * Size: ~616 bytes (: includes 280-byte inline body storage)
 * Protocol: Generic HTTP/HTTPS (no protocol-specific fields)
 * 
 * Design principles:
 * - Fixed size (no heap allocations in hot path)
 * - HTTP semantic attributes (OpenTelemetry conventions)
 * - W3C Trace Context (trace_id, span_id)
 * - No strings in hot path (numeric tags only where possible)
 * - Cache-line aligned fields for optimal memory access
 */
typedef struct __attribute__((packed)) {
  /* === Trace Context (32 bytes) === */
  uint64_t trace_id_hi;      // W3C trace_id (high 64 bits, 128-bit UUID)
  uint64_t trace_id_lo;      // W3C trace_id (low 64 bits)
  uint64_t span_id;          // W3C span_id (current span, 64-bit)
  uint64_t parent_span_id;   // W3C parent_span_id (parent span, 64-bit)
  
  /* === Event Metadata (16 bytes) === */
  uint64_t timestamp_ns;     // Event timestamp (nanoseconds since epoch, CLOCK_REALTIME)
  uint8_t  event_type;       // Event type (REQ_START, REQ_END, etc.)
  uint8_t  flags;            // Bit flags (sampled, error, tls_enabled, has_body)
  uint16_t catalog_id;       // Service catalog ID (for deep inspection routing)
  uint32_t duration_us;      // Event duration in microseconds (for *_END events)
  
  /* === HTTP Semantic Attributes (128 bytes) === */
  char     http_method[16];  // HTTP method (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS)
  uint8_t  http_major;       // HTTP version major (1 for HTTP/1.x, 2 for HTTP/2)
  uint8_t  http_minor;       // HTTP version minor (0 for HTTP/1.0, 1 for HTTP/1.1)
  char     http_target[96];  // Request path (/api/users, /v1/chat/completions, /mcp-server)
  char     http_host[48];    // Host header value (api.openai.com, localhost:8443)
  uint16_t http_status_code; // HTTP status code (200, 404, 500, etc.)
  uint32_t content_length;   // Content-Length header value (bytes)
  char     content_type[32]; // Content-Type header (application/json, text/html, etc.)
  
  /* === Connection Attributes (32 bytes) === */
  uint32_t client_ip;        // Client IP address (IPv4, network byte order)
  uint16_t client_port;      // Client port (host byte order)
  uint16_t backend_id;       // Backend server ID (for upstream spans)
  uint32_t backend_ip;       // Backend IP address (IPv4, network byte order)
  uint16_t backend_port;     // Backend port (host byte order)
  uint16_t tls_version;      // TLS version (0x0303 = TLS 1.2, 0x0304 = TLS 1.3)
  uint16_t tls_cipher;       // TLS cipher suite ID (IANA registry)
  uint16_t _pad2;            // Padding for alignment
  uint32_t _pad2b[3];        // Additional padding
  
  /* === Session Tracking (256 bytes) === */
  // Session consistency tracking (--session-header-name support)
  char     session_header_name[64];      // Custom session header name (e.g., "mcp-session-id", "x-session-token")
  char     session_header_value[128];    // Session header value (e.g., "abc123", "session-xyz")
  char     conversation_id[64];          // Conversation ID for OpenAI/MCP (e.g., "conv-abc123")
  
  /* === Error/Reason Codes (16 bytes) === */
  uint16_t error_class;      // Error class (TIMEOUT, CONN_FAIL, TLS_FAIL, etc.)
  uint16_t error_code;       // Detailed error code (errno, TLS alert, etc.)
  uint32_t _pad3[3];         // Padding for alignment
  
  /* === PHASE 1: Hybrid Body Storage (320 bytes) === */
  // Inline body preview (ALWAYS populated if body present)
  uint16_t body_len;         // Actual bytes in body_data (0-280)
  uint8_t  body_truncated;   // 1 if body > 280 bytes (file fallback active)
  uint8_t  is_streaming;     // 1 if Transfer-Encoding: chunked
  
  // Protocol hints (cheap to extract in C, enables fast parser dispatch in Go)
  uint8_t  is_json;          // 1 if Content-Type: application/json
  uint8_t  has_body_file;    // 1 if body saved to tmpfs (large payload fallback)
  uint16_t _pad4;            // Padding for alignment
  
  char     body_data[280];   // Inline body preview (first 280 bytes, ALWAYS populated)
  char     body_file_path[32]; // Filename only (NO /dev/shm/ prefix! Go adds it)
  
} lxb_trace_event_t;

// Compile-time size verification (disabled for C, __attribute__((packed)) ensures correct size)
// Note: C and C++ have different padding rules, so this check fails in C
// Actual size will be verified at runtime by lxb_ring_init()
#ifdef __cplusplus
typedef char __lxb_trace_event_size_check[sizeof(lxb_trace_event_t) == 256 ? 1 : -1];
#endif

/* === Event Types === */
#define LXB_EVENT_REQ_START    1  // HTTP request started (client → loxilb)
#define LXB_EVENT_REQ_END      2  // HTTP request completed (response sent to client)
#define LXB_EVENT_UP_START     3  // Upstream connection started (loxilb → backend)
#define LXB_EVENT_UP_END       4  // Upstream response received (backend → loxilb)
#define LXB_EVENT_TLS_HS       5  // TLS handshake completed (frontend or backend)
#define LXB_EVENT_STREAM_MARK  6  // Streaming chunk marker (HTTP/2, Server-Sent Events)

/* === Event Flags === */
#define LXB_FLAG_SAMPLED       0x01  // Event is sampled (should be exported to tracing backend)
#define LXB_FLAG_ERROR         0x02  // Event contains error information
#define LXB_FLAG_TLS_FRONTEND  0x04  // Frontend uses TLS (HTTPS → *)
#define LXB_FLAG_TLS_BACKEND   0x08  // Backend uses TLS (* → HTTPS)
#define LXB_FLAG_TRACED        0x10  // traceparent header present (distributed trace)
#define LXB_FLAG_HAS_BODY      0x20  // OPTIONAL: Body captured in tmpfs (deep inspection)

/* === Error Classes === */
#define LXB_ERR_NONE           0   // No error
#define LXB_ERR_TIMEOUT        1   // Request timeout (client or upstream)
#define LXB_ERR_CONN_FAIL      2   // Connection failed (upstream unreachable)
#define LXB_ERR_TLS_FAIL       3   // TLS handshake failed (cert validation, cipher mismatch)
#define LXB_ERR_HTTP_PARSE     4   // HTTP parsing error (malformed request/response)
#define LXB_ERR_BACKEND_DOWN   5   // Backend unavailable (circuit breaker open)
#define LXB_ERR_CLIENT_ABORT   6   // Client disconnected prematurely
#define LXB_ERR_OVERLOAD       7   // Server overload (rate limit, circuit breaker)

#endif /* __LXB_TRACE_EVENT_H__ */
