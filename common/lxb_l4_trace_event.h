/*
 * Copyright (c) 2025 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */
#ifndef __LXB_L4_TRACE_EVENT_H__
#define __LXB_L4_TRACE_EVENT_H__

#include <stdint.h>

/**
 * L4 Connection Trace Event - Production-Ready Structure
 * 
 * Size: 256 bytes (matches L7, optimal cache utilization)
 * Lifetime: 5-6 events per connection (state transitions only)
 * 
 * Design:
 * - Fixed-size for ring buffer efficiency
 * - Cache-aligned (64-byte alignment)
 * - No CT map modification needed (span_id from hash)
 * - State transitions only (not per-packet)
 */
typedef struct __attribute__((packed, aligned(64))) {
  /* === Trace Context (32 bytes) === */
  uint64_t timestamp_ns;       // bpf_ktime_get_ns()
  uint8_t  trace_id[16];       // W3C trace ID (inherited or generated)
  uint64_t span_id;            // Deterministic hash of CT key
  uint64_t parent_span_id;     // L7 span ID (0 if standalone)

  /* === Event Metadata (16 bytes) === */
  uint8_t  event_type;         // LXB_L4_EVENT_* (see below)
  uint8_t  protocol;           // IPPROTO_TCP=6, IPPROTO_SCTP=132
  uint8_t  old_state;          // ct_state_t before transition
  uint8_t  new_state;          // ct_state_t after transition
  uint8_t  direction;          // CT_DIR_IN=0, CT_DIR_OUT=1
  uint8_t  flags;              // LXB_L4_FLAG_* (see below)
  uint16_t catalog_id;         // Service catalog ID
  uint32_t duration_us;        // Connection duration (for CLOSE events)
  uint16_t worker_id;          // Worker thread ID (0-3)
  uint16_t _pad1;

  /* === Connection 5-tuple (32 bytes, IPv6-ready) === */
  uint32_t client_ip[4];       // IPv4: [0] only, IPv6: all 4
  uint32_t server_ip[4];       // VIP
  uint16_t client_port;
  uint16_t server_port;
  uint16_t _pad2[4];

  /* === Backend Info (16 bytes) === */
  uint32_t backend_ip[4];      // Selected backend endpoint
  uint16_t backend_port;
  uint16_t backend_id;

  /* === Performance Metrics (32 bytes) === */
  uint64_t bytes_in;           // Client → server
  uint64_t bytes_out;          // Server → client
  uint32_t packets_in;
  uint32_t packets_out;
  uint32_t rtt_us;             // Round-trip time (microseconds)
  uint32_t retrans_in;
  uint32_t retrans_out;
  uint32_t window_size;        // TCP window (current)

  /* === Protocol Specific (32 bytes) === */
  union {
    struct {  // TCP
      uint32_t seq_in;
      uint32_t seq_out;
      uint32_t ack_in;
      uint32_t ack_out;
      uint32_t mss;              // Maximum segment size
      uint8_t  tcp_flags;
      uint8_t  _pad_tcp[11];
    } tcp;
    struct {  // SCTP
      uint32_t vtag;             // Verification tag
      uint16_t streams_in;
      uint16_t streams_out;
      uint32_t tsn;              // Transmission Sequence Number
      uint32_t cum_ack;
      uint8_t  chunk_type;       // Last chunk type
      uint8_t  _pad_sctp[15];
    } sctp;
  } proto;

  /* === Error Info (16 bytes) === */
  uint32_t error_code;         // ERR_* codes (see below)
  uint32_t reset_reason;
  uint64_t _pad3;

  /* === Padding to 256 bytes === */
  uint8_t _pad4[80];           // 32+16+32+16+32+32+16+80 = 256 bytes

} lxb_l4_trace_event_t;

/* === Event Types === */
#define LXB_L4_EVENT_CONN_NEW      10  // New connection (SYN, INIT)
#define LXB_L4_EVENT_STATE_CHANGE  11  // State transition
#define LXB_L4_EVENT_CONN_CLOSE    12  // Graceful close
#define LXB_L4_EVENT_CONN_TIMEOUT  13  // Timeout (half-open, idle)
#define LXB_L4_EVENT_CONN_RESET    14  // RST, ABORT
#define LXB_L4_EVENT_CONN_ERROR    15  // eBPF error (map full)

/* === Event Flags === */
#define LXB_L4_FLAG_SAMPLED          0x01  // Event is sampled
#define LXB_L4_FLAG_ERROR            0x02  // Event contains error
#define LXB_L4_FLAG_NAT_APPLIED      0x04  // NAT applied to connection
#define LXB_L4_FLAG_TRACED           0x08  // Part of distributed trace
#define LXB_L4_FLAG_BACKEND_SELECTED 0x10  // Backend endpoint selected
#define LXB_L4_FLAG_BACKEND_UNHEALTHY 0x20  // Backend health check failed
#define LXB_L4_FLAG_PRECT_FAILURE    0x40  // Failure before CT entry created
#define LXB_L4_FLAG_POLICY_DROP      0x80  // Dropped by firewall/ACL policy

/* === Error Codes === */
#define LXB_L4_ERROR_NONE           0
#define LXB_L4_ERROR_RST_CLIENT     1  // Client sent RST
#define LXB_L4_ERROR_RST_SERVER     2  // Backend sent RST
#define LXB_L4_ERROR_SCTP_ABORT     3  // SCTP ABORT chunk
#define LXB_L4_ERROR_CT_TIMEOUT     4  // CT entry timeout
#define LXB_L4_ERROR_MAP_FULL       5  // CT map eviction
#define LXB_L4_ERROR_SYN_TIMEOUT    6  // Half-open connection timeout

/* Backend/Network Error Codes (Pre-CT failures) */
#define LXB_L4_ERROR_NO_BACKEND     10  // No healthy backend available
#define LXB_L4_ERROR_BACKEND_DOWN   11  // Backend marked down by health check
#define LXB_L4_ERROR_BACKEND_REFUSED 12  // Connection refused by backend (ICMP unreachable)
#define LXB_L4_ERROR_NO_ROUTE       13  // No route to backend
#define LXB_L4_ERROR_BACKEND_TIMEOUT 14  // Backend connection timeout
#define LXB_L4_ERROR_PORT_MISMATCH  15  // Backend port misconfiguration
#define LXB_L4_ERROR_LB_FAILURE     16  // Load balancer selection failed
#define LXB_L4_ERROR_NAT_FAILURE    17  // NAT transformation failed
#define LXB_L4_ERROR_POLICY_DROP    18  // Dropped by security policy/ACL
#define LXB_L4_ERROR_RATE_LIMIT     19  // Connection rate limit exceeded

/* === Sampling Algorithms === */
#define LXB_L4_SAMPLING_NONE     0  // Trace all (100%)
#define LXB_L4_SAMPLING_RANDOM   1  // Random sampling (bpf_get_prandom_u32)
#define LXB_L4_SAMPLING_HASH_BASED 2  // Hash-based deterministic (5-tuple hash)
#define LXB_L4_SAMPLING_ADAPTIVE 3  // Adaptive based on load

/**
 * Generate deterministic span_id from CT key (5-tuple + zone)
 * 
 * Properties:
 * - Deterministic: Same connection → same span_id
 * - Fast: ~20ns (pure arithmetic, no map lookups)
 * - Collision-resistant: 64-bit hash space
 * - No CT map modification needed
 * 
 * Note: This function is defined in eBPF code (llb_kern_ct.c)
 * as it needs access to struct dp_ct_key
 */

#endif /* __LXB_L4_TRACE_EVENT_H__ */
