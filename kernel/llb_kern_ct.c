/*
 *  llb_kern_ct.c: Loxilb kernel eBPF ConnTracking Implementation
 *  Copyright (c) 2022-2025 LoxiLB Authors
 *
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 */

// ============================================================================
// CONNECTION ERROR STATISTICS (always-on, unsampled, trace-INDEPENDENT)
// ============================================================================
// These feed loxilb_l4_error_events_total. Deliberately OUTSIDE HAVE_L4_TRACE:
// error metrics must be exact and present in every build, unlike the sampled,
// compile/runtime-gated L4 trace ring buffer. Error-stat indices into the
// ct_err_stats ARRAY map (llb_kern_cdefs.h) — keep in sync with that map's
// comment and the Go reader DpCtErrorGetStats.
//
// RST is split by direction so alerting can separate benign client resets from
// pathological backend resets: CT_DIR_IN = client sent RST, CT_DIR_OUT = server
// (backend) sent RST — same convention as the CONN_RESET event handling above.
#define CT_ERR_STAT_TCP_RST_CLIENT 0  // TCP RST from client   (CT_TCP_CW, dir IN)
#define CT_ERR_STAT_TCP_RST_SERVER 1  // TCP RST from backend  (CT_TCP_CW, dir OUT)
#define CT_ERR_STAT_TCP_ERR        2  // TCP error (CT_TCP_ERR — proto violation / half-open)
#define CT_ERR_STAT_SCTP_ABORT     3  // SCTP ABORT (CT_SCTP_ABRT)
#define CT_ERR_STAT_SCTP_ERR       4  // SCTP error (CT_SCTP_ERR)

/*
 * Bump a global connection-error counter exactly once per transition INTO an
 * error state. Mirrors dp_update_security_stats(): one ARRAY lookup + atomic
 * add (<0.1us). MUST be called AFTER releasing the CT spinlock — eBPF forbids
 * most helper calls while a bpf_spin_lock is held.
 */
static void __always_inline
dp_update_ct_error_stats(__u32 stat_type, __u64 increment)
{
  __u64 *counter = bpf_map_lookup_elem(&ct_err_stats, &stat_type);
  if (counter) {
    __sync_fetch_and_add(counter, increment);
  }
}

// ============================================================================
// L4 TRACING: Full Implementation
// ============================================================================
#ifdef HAVE_L4_TRACE
// lxb_l4_trace_event.h included in main entry file (llb_kern_entry.c)

// Maps are defined in llb_kern_cdefs.h and registered in loxilb_libdp.c
// Following loxilb design pattern (same as HAVE_DP_SECURITY_RATE_RUNTIME_CONFIG)

// Runtime control via l4_trace_cfg map (modifiable from Go)

/**
 * Generate deterministic span_id directly from xf (5-tuple + zone)
 * 
 * CRITICAL: __noinline for separate stack frame (allows 3 shallow calls vs 2 deep)
 * This function implements a simplified XXH64 hash optimized for eBPF.
 * No CT map modification needed - span_id calculated on-demand.
 * 
 * Collision probability: ~2.7×10^-11 (1 in 37 billion) - negligible
 */
static __noinline uint64_t
lxb_generate_span_id_from_xf(struct xfi *xf) {
  const uint64_t PRIME64_1 = 0x9E3779B185EBCA87ULL;
  const uint64_t PRIME64_2 = 0xC2B2AE3D27D4EB4FULL;
  const uint64_t PRIME64_3 = 0x165667B19E3779F9ULL;
  
  uint64_t h64 = PRIME64_1 + PRIME64_2;
  
  // Hash source IP (handles both IPv4 and IPv6)
  #pragma unroll
  for (int i = 0; i < 4; i++) {
    h64 ^= xf->l34m.saddr[i] * PRIME64_2;
    h64 = ((h64 << 31) | (h64 >> 33)) * PRIME64_1;
  }
  
  // Hash destination IP
  #pragma unroll
  for (int i = 0; i < 4; i++) {
    h64 ^= xf->l34m.daddr[i] * PRIME64_2;
    h64 = ((h64 << 31) | (h64 >> 33)) * PRIME64_1;
  }
  
  // Hash ports and protocol
  uint64_t port_proto = ((uint64_t)xf->l34m.source << 48) |
                        ((uint64_t)xf->l34m.dest << 32) |
                        ((uint64_t)xf->l34m.nw_proto << 16) |
                        xf->pm.zone;
  h64 ^= port_proto * PRIME64_2;
  h64 = ((h64 << 31) | (h64 >> 33)) * PRIME64_1;
  
  // Finalization
  h64 ^= h64 >> 33;
  h64 *= PRIME64_2;
  h64 ^= h64 >> 29;
  h64 *= PRIME64_3;
  h64 ^= h64 >> 32;
  
  return h64 ? h64 : 1;  // Ensure non-zero (0 reserved for invalid)
}

/**
 * L4 Trace Sampling Logic
 * 
 * Implements hash-based consistent per-connection sampling:
 * - CONN_NEW: Hash-based sampling decision (respects sampling_rate)
 * - CONN_CLOSE/RESET/ERROR: Always emitted (100% error detection)
 *   Rationale: Backend failures must be detected regardless of sampling rate.
 *   CONN_CLOSE can be reclassified to CONN_RESET by populate_event().
 * - STATE_CHANGE: Uses cached decision from CONN_NEW
 * - Orphaned STATE_CHANGE: Dropped (partial NAT span from sampling)
 * 
 * Returns: 1 = emit event, 0 = drop event
 * 
 * CRITICAL: __noinline to prevent stack overflow (BPF 512 byte limit)
 */
static __noinline int
lxb_l4_should_sample(struct xfi *xf, uint64_t span_id, uint8_t event_type, 
                     struct dp_l4_trace_config *cfg) {
  // Check if 100% sampling (fast path)
  if (cfg->sampling_rate >= 100) {
    return 1;
  }
  
  // Check if 0% sampling (fast path)
  if (cfg->sampling_rate == 0) {
    return 0;
  }
  
  // Check if we have a cached sampling decision for this span
  // All event types (CONN_NEW, STATE_CHANGE, CONN_CLOSE, etc.) use the same decision
  struct l4_sampling_decision *decision = bpf_map_lookup_elem(&l4_sampling_map, &span_id);
  if (decision) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
    bpf_printk("[L4_TRACE_SAMPLE] span=%016llx cached=%d event=%d", 
               span_id, decision->sampled, event_type);
#endif
    return decision->sampled;
  }
  
  // No cached decision: determine if this is an orphaned event worth emitting
  // CRITICAL: Always emit error/close events (may be orphaned backend failures)
  // CONN_CLOSE can become CONN_RESET after populate_event() reclassifies it
  // Make sampling decision for consistency, but always return 1 for errors
  if (event_type == LXB_L4_EVENT_CONN_ERROR ||
      event_type == LXB_L4_EVENT_CONN_RESET ||
      event_type == LXB_L4_EVENT_CONN_CLOSE) {
    // Make sampling decision for consistency
    uint16_t hash_mod = (span_id & 0xFFFF) % 100;
    uint8_t sampled = (hash_mod < cfg->sampling_rate) ? 1 : 0;
    
    struct l4_sampling_decision new_decision = {
      .sampled = sampled,
      .timestamp_ns = bpf_ktime_get_ns()
    };
    bpf_map_update_elem(&l4_sampling_map, &span_id, &new_decision, BPF_ANY);
    
#ifdef HAVE_PROXY_EXTRA_DEBUG
    bpf_printk("[L4_TRACE_SAMPLE] span=%016llx ERROR always=1 event=%d",
               span_id, event_type);
#endif
    
    return 1;  // Always emit errors regardless of sampling rate
  }
  
  // CONN_NEW: Make normal sampling decision
  if (event_type == LXB_L4_EVENT_CONN_NEW) {
    uint16_t hash_mod = (span_id & 0xFFFF) % 100;
    uint8_t sampled = (hash_mod < cfg->sampling_rate) ? 1 : 0;
    
    // Store decision for future events of this span
    struct l4_sampling_decision new_decision = {
      .sampled = sampled,
      .timestamp_ns = bpf_ktime_get_ns()
    };
    bpf_map_update_elem(&l4_sampling_map, &span_id, &new_decision, BPF_ANY);
    
#ifdef HAVE_PROXY_EXTRA_DEBUG
    bpf_printk("[L4_TRACE_SAMPLE] span=%016llx new=%d rate=%d hash=%d event=%d",
               span_id, sampled, cfg->sampling_rate, hash_mod, event_type);
#endif
    
    return sampled;
  }
  
  // Other event types without cached decision: drop as orphaned
#ifdef HAVE_PROXY_EXTRA_DEBUG
  bpf_printk("[L4_TRACE_SAMPLE] span=%016llx orphaned event=%d (dropped)", 
             span_id, event_type);
#endif
  return 0;
}

/**
 * Helper: Populate event structure (separate __noinline for stack management)
 * BPF limit: max 5 arguments (event, xf, ts, state_and_dir, protocol)
 * Basic fields (span_id, event_type, protocol) must be set by caller before calling this
 */
static __noinline void
lxb_l4_populate_event(lxb_l4_trace_event_t *event,
                      struct xfi *xf,
                      struct dp_ct_tact *ts,
                      uint32_t state_and_dir)
{
  ct_state_t old_state = (state_and_dir >> 16) & 0xFF;
  ct_state_t new_state = (state_and_dir >> 8) & 0xFF;
  ct_dir_t direction = state_and_dir & 0xFF;
  uint8_t protocol = event->protocol;  // Already set by caller
  
  // Fill event structure
  event->timestamp_ns = bpf_ktime_get_ns();
  event->old_state = old_state;
  event->new_state = new_state;
  event->direction = direction;  // Use actual direction from CT
  event->flags = LXB_L4_FLAG_SAMPLED;
  event->catalog_id = 0;  // TODO: Get from xf if available
  event->worker_id = 0;   // TODO: Get from CPU ID
  event->duration_us = 0; // Will be calculated for CLOSE events
  
  // Copy 5-tuple (source = client, dest = server from xf)
  __builtin_memcpy(event->client_ip, xf->l34m.saddr, sizeof(event->client_ip));
  __builtin_memcpy(event->server_ip, xf->l34m.daddr, sizeof(event->server_ip));
  event->client_port = xf->l34m.source;
  event->server_port = xf->l34m.dest;
  
  // Backend info from NAT transformation
  if (ts && ts->ctd.xi.nat_flags & LLB_NAT_DST) {
    __builtin_memcpy(event->backend_ip, ts->ctd.xi.nat_xip, sizeof(event->backend_ip));
    event->backend_port = ts->ctd.xi.nat_xport;
    event->backend_id = ts->ctd.rid;  // Rule ID as backend identifier
    event->flags |= LXB_L4_FLAG_BACKEND_SELECTED;
    event->flags |= LXB_L4_FLAG_NAT_APPLIED;
  } else {
    __builtin_memset(event->backend_ip, 0, sizeof(event->backend_ip));
    event->backend_port = 0;
    event->backend_id = 0;
  }
  
  // Copy byte/packet counters from CT entry
  if (ts) {
    event->bytes_in = ts->ctd.pb.bytes;
    event->packets_in = ts->ctd.pb.packets;
  }
  
  // Error code detection with proper RST direction
  event->error_code = LXB_L4_ERROR_NONE;
  if (protocol == IPPROTO_TCP && new_state == CT_TCP_CW) {
    // RST received - use direction to determine origin
    // CT_DIR_IN = client -> server (client sent RST)
    // CT_DIR_OUT = server -> client (backend sent RST)
    if (direction == CT_DIR_IN) {
      event->error_code = LXB_L4_ERROR_RST_CLIENT;
    } else {
      event->error_code = LXB_L4_ERROR_RST_SERVER;  // Backend RST
    }
    event->event_type = LXB_L4_EVENT_CONN_RESET;
    event->flags |= LXB_L4_FLAG_ERROR;
  } else if (protocol == IPPROTO_TCP && new_state == CT_TCP_ERR) {
    event->error_code = LXB_L4_ERROR_CT_TIMEOUT;  // Generic CT error
    event->flags |= LXB_L4_FLAG_ERROR;
#ifndef HAVE_DP_DPU_SLIM
  } else if (protocol == IPPROTO_SCTP && new_state == CT_SCTP_SHUT) {
    // SCTP graceful shutdown - set event type but NO error code
    // This is normal connection termination, not an error
    event->event_type = LXB_L4_EVENT_CONN_RESET;
    // Do NOT set error_code or LXB_L4_FLAG_ERROR for graceful shutdown
#endif
  }
  
  // Protocol-specific fields
  if (protocol == IPPROTO_TCP && ts) {
    ct_tcp_pinf_t *tcp_state = &ts->ctd.pi.t;
    
    // RTT from 3-way handshake
    event->rtt_us = tcp_state->rtt_us;
    
    // TCP-specific fields (sequence numbers from CT state)
    event->proto.tcp.seq_in = tcp_state->tcp_cts[CT_DIR_IN].seq;
    event->proto.tcp.ack_in = tcp_state->tcp_cts[CT_DIR_IN].pack;
    event->proto.tcp.seq_out = tcp_state->tcp_cts[CT_DIR_OUT].seq;
    event->proto.tcp.ack_out = tcp_state->tcp_cts[CT_DIR_OUT].pack;
    // tcp_flags cannot be set here (would need xf, exceeds BPF arg limit)
    event->proto.tcp.tcp_flags = 0;
    
#ifndef HAVE_DP_DPU_SLIM
  } else if (protocol == IPPROTO_SCTP && ts) {
    ct_sctp_pinf_t *sctp_state = &ts->ctd.pi.s;

    // SCTP-specific fields
    event->proto.sctp.vtag = sctp_state->itag;
    event->proto.sctp.streams_in = 0;   // TODO: Extract from SCTP header
    event->proto.sctp.streams_out = 0;  // TODO: Extract from SCTP header
    event->proto.sctp.chunk_type = 0;   // TODO: Track last chunk type

    // Error detection for SCTP
    if (new_state == CT_SCTP_ABRT) {
      event->error_code = LXB_L4_ERROR_SCTP_ABORT;
      event->event_type = LXB_L4_EVENT_CONN_RESET;
      event->flags |= LXB_L4_FLAG_ERROR;
    } else if (new_state == CT_SCTP_ERR) {
      event->error_code = LXB_L4_ERROR_CT_TIMEOUT;
      event->flags |= LXB_L4_FLAG_ERROR;
    }
#endif
  }
  
  // Reserved fields - zero out
  __builtin_memset(event->_pad4, 0, sizeof(event->_pad4));
}

/**
 * Full Event Emission to Ring Buffer
 * 
 * Split into two __noinline functions for stack management:
 * 1. This function: sampling check + ring buffer allocation
 * 2. lxb_l4_populate_event: event structure population
 * 
 * CRITICAL: Must be noinline to avoid BPF stack overflow (512 byte limit)
 */
static __noinline void
lxb_l4_emit_event(struct xfi *xf,
                  struct dp_ct_tact *ts,
                  uint32_t state_and_dir,  // packed: (old_state << 16) | (new_state << 8) | direction
                  uint8_t protocol)
{
  // Fast path: check if tracing enabled via config map
  __u32 cfg_key = 0;
  struct dp_l4_trace_config *cfg = bpf_map_lookup_elem(&l4_trace_cfg, &cfg_key);
  if (!cfg || !cfg->enabled) {
    return;  // <20ns: single map lookup + branch prediction
  }
  
  // Unpack state for event type determination
  ct_state_t old_state = (state_and_dir >> 16) & 0xFF;
  ct_state_t new_state = (state_and_dir >> 8) & 0xFF;
  
  // Generate span_id from xf (inlined to reduce call depth)
  uint64_t span_id = lxb_generate_span_id_from_xf(xf);
  
  // Determine event type from state transition
  uint8_t event_type = LXB_L4_EVENT_STATE_CHANGE;  // Default
  
  // TCP event type determination
  if (protocol == IPPROTO_TCP) {
    if (old_state == CT_TCP_CLOSED && new_state == CT_TCP_SS) {
      event_type = LXB_L4_EVENT_CONN_NEW;
    } else if (new_state == CT_TCP_EST && old_state != CT_TCP_EST) {
      event_type = LXB_L4_EVENT_CONN_NEW;  // Treat first EST as NEW
    } else if (new_state == CT_TCP_CW || new_state == CT_TCP_FINI || new_state == CT_TCP_FINI2 || new_state == CT_TCP_FINI3) {
      event_type = LXB_L4_EVENT_CONN_CLOSE;
    } else if (new_state == CT_TCP_ERR) {
      event_type = LXB_L4_EVENT_CONN_ERROR;
    }
  }
  // SCTP event type determination handled in protocol-specific section
  
  // Apply sampling decision (pass xf for NAT correlation)
  if (!lxb_l4_should_sample(xf, span_id, event_type, cfg)) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
    bpf_printk("[L4_TRACE_DROP] span=%016llx event_type=%d sampled=0", span_id, event_type);
#endif
    return;
  }
  
  // Reserve space in ring buffer
  lxb_l4_trace_event_t *event = bpf_ringbuf_reserve(&l4_trace_ringbuf,
                                                             sizeof(*event), 0);
  if (!event) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
    bpf_printk("[L4_TRACE_RING_FULL] span=%016llx dropped", span_id);
#endif
    return;  // Ring buffer full, drop event
  }
  
  // Pre-populate basic fields (BPF arg limit = 5)
  event->span_id = span_id;
  event->event_type = event_type;
  event->protocol = protocol;
  
  // Populate event in separate function (reduces combined stack usage)
  lxb_l4_populate_event(event, xf, ts, state_and_dir);
  
#ifdef HAVE_PROXY_EXTRA_DEBUG
  bpf_printk("[L4_TRACE_EMIT] span=%016llx type=%d state=%d->%d proto=%d",
             span_id, event_type, old_state, new_state, protocol);
#endif
  
  // Submit event to ring buffer
  bpf_ringbuf_submit(event, 0);
}

#endif /* HAVE_L4_TRACE */

// ============================================================================
// Existing CT implementation continues below
// ============================================================================

#ifdef HAVE_LEGACY_BPF_MAPS

struct bpf_map_def SEC("maps") ct_ctr = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct dp_ct_ctrtact),
  .max_entries = 1 
};

#else

struct ct_ctr_d {
  __uint(type,        BPF_MAP_TYPE_ARRAY);
  __type(key,         __u32);
  __type(value,       struct dp_ct_ctrtact);
  __uint(max_entries, 1);
} ct_ctr SEC(".maps");

#endif

#define CT_KEY_GEN(k, xf)                    \
do {                                         \
  (k)->daddr[0] = xf->l34m.daddr[0];         \
  (k)->daddr[1] = xf->l34m.daddr[1];         \
  (k)->daddr[2] = xf->l34m.daddr[2];         \
  (k)->daddr[3] = xf->l34m.daddr[3];         \
  (k)->saddr[0] = xf->l34m.saddr[0];         \
  (k)->saddr[1] = xf->l34m.saddr[1];         \
  (k)->saddr[2] = xf->l34m.saddr[2];         \
  (k)->saddr[3] = xf->l34m.saddr[3];         \
  (k)->sport = xf->l34m.source;              \
  (k)->dport = xf->l34m.dest;                \
  (k)->l4proto = xf->l34m.nw_proto;          \
  (k)->zone = xf->pm.zone;                   \
  (k)->v6 = xf->l2m.dl_type == bpf_ntohs(ETH_P_IPV6) ? 1: 0; \
  (k)->ident = xf->tm.tun_decap ? 0 : xf->tm.tunnel_id;      \
  (k)->type = xf->tm.tun_decap ? 0 : xf->tm.tun_type;        \
}while(0)

#define dp_run_ctact_helper(x, a) \
do {                              \
  switch ((a)->ca.act_type) {     \
  case DP_SET_NOP:                \
  case DP_SET_SNAT:               \
  case DP_SET_DNAT:               \
    (a)->ctd.pi.t.tcp_cts[CT_DIR_IN].pseq = (x)->l34m.seq;   \
    (a)->ctd.pi.t.tcp_cts[CT_DIR_IN].pack = (x)->l34m.ack;   \
    break;                        \
  default:                        \
    break;                        \
  }                               \
} while(0)

static int __always_inline
dp_run_ct_helper(struct xfi *xf)
{
  struct dp_ct_key key;
  struct dp_ct_tact *act;

  CT_KEY_GEN(&key, xf);

  act = bpf_map_lookup_elem(&ct_map, &key);
  if (!act) {
    BPF_ERR_PRINTK("[FCH] ct-miss");
    return -1;
  }

  /* We dont do much strict tracking after EST state.
   * But need to maintain minimal ctinfo
   */
  dp_run_ctact_helper(xf, act);
  return 0;
}

static void __always_inline
dp_ct_related_fc_rm(struct dp_ct_key *ctk)
{
  struct dp_fcv4_key key;

  if (ctk->v6 || ctk->ident || ctk->type) {
    return;
  }

  key.daddr      = ctk->daddr4;
  key.saddr      = ctk->saddr4;
  key.sport      = ctk->sport;
  key.dport      = ctk->dport;
  key.l4proto    = ctk->l4proto;
  key.pad        = 0;
  key.in_port    = 0;

  bpf_map_delete_elem(&fc_v4_map, &key);
  return;
}


#ifdef HAVE_DP_EXTCT
#define DP_RUN_CT_HELPER(x)                \
do {                                       \
  if ((x)->l34m.nw_proto == IPPROTO_TCP) { \
    dp_run_ct_helper(x);                   \
  }                                        \
} while(0)
#else
#define DP_RUN_CT_HELPER(x)
#endif

static __u32 __always_inline
dp_ct_get_newctr(__u32 *nid)
{
  __u32 k = 0;
  __u32 v = 0;
  struct dp_ct_ctrtact *ctr;

  ctr = bpf_map_lookup_elem(&ct_ctr, &k);

  if (ctr == NULL) {
    return 0;
  }

  *nid = ctr->start;
  /* FIXME - We can potentially do a percpu array and do away
   *         with the locking here
   */ 
#ifndef HAVE_DP_DPU_SLIM
  bpf_spin_lock(&ctr->lock);
#endif
  v = ctr->counter;
  ctr->counter += 2;
  if (ctr->counter >= ctr->entries) {
    ctr->counter = ctr->start;
  }
#ifndef HAVE_DP_DPU_SLIM
  bpf_spin_unlock(&ctr->lock);
#endif

  return v;
}

static int __always_inline
dp_ct_proto_xfk_init(struct dp_ct_key *key,
                     nxfrm_inf_t *xi,
                     struct dp_ct_key *xkey,
                     nxfrm_inf_t *xxi)
{
  DP_XADDR_CP(xkey->daddr, key->saddr);
  DP_XADDR_CP(xkey->saddr, key->daddr);
  xkey->sport = key->dport; 
  xkey->dport = key->sport;
  xkey->l4proto = key->l4proto;
  xkey->zone = key->zone;
  xkey->v6 = key->v6;
  xkey->ident = key->ident;
  xkey->type = key->type;

  if (xi->dsr) {
    if (xi->nat_flags & LLB_NAT_DST) {
      xxi->nat_flags = LLB_NAT_SRC;
      DP_XADDR_CP(xxi->nat_xip, key->daddr);
      xxi->nat_xport = key->dport;
      xxi->nv6 = xi->nv6;
    }
    xxi->dsr = xi->dsr;
    return 0;
  }

  /* Apply NAT xfrm if needed */
  if (xi->nat_flags & LLB_NAT_DST) {
    xkey->v6 = (__u8)(xi->nv6);
    DP_XADDR_CP(xkey->saddr, xi->nat_xip);
    if (!DP_XADDR_ISZR(xi->nat_rip)) {
      DP_XADDR_CP(xkey->daddr, xi->nat_rip);
      DP_XADDR_CP(xxi->nat_rip, key->saddr);
    }
    if (key->l4proto != IPPROTO_ICMP) {
        if (xi->nat_xport)
          xkey->sport = xi->nat_xport;
        else
          xi->nat_xport = key->dport;
    }

    xxi->nat_flags = LLB_NAT_SRC;
    xxi->nv6 = key->v6;
    DP_XADDR_CP(xxi->nat_xip, key->daddr);
    if (key->l4proto != IPPROTO_ICMP)
      xxi->nat_xport = key->dport;
  }
  if (xi->nat_flags & LLB_NAT_SRC) {
    xkey->v6 = xi->nv6;
    DP_XADDR_CP(xkey->daddr, xi->nat_xip);
    if (!DP_XADDR_ISZR(xi->nat_rip)) {
      DP_XADDR_CP(xkey->saddr, xi->nat_rip);
      DP_XADDR_CP(xxi->nat_rip, key->daddr);
    }
    if (key->l4proto != IPPROTO_ICMP) {
      if (xi->nat_xport)
        xkey->dport = xi->nat_xport;
      else
        xi->nat_xport = key->sport;
    }

    xxi->nat_flags = LLB_NAT_DST;
    xxi->nv6 = key->v6;
    DP_XADDR_CP(xxi->nat_xip, key->saddr);
    if (key->l4proto != IPPROTO_ICMP)
      xxi->nat_xport = key->sport;
  }
  if (xi->nat_flags & LLB_NAT_HDST) {
    DP_XADDR_CP(xkey->saddr, key->saddr);
    DP_XADDR_CP(xkey->daddr, key->daddr);

    if (key->l4proto != IPPROTO_ICMP) {
      if (xi->nat_xport)
        xkey->sport = xi->nat_xport;
      else
        xi->nat_xport = key->dport;
    }

    xxi->nat_flags = LLB_NAT_HSRC;
    xxi->nv6 = key->v6;
    DP_XADDR_SETZR(xxi->nat_xip);
    DP_XADDR_SETZR(xi->nat_xip);
    if (key->l4proto != IPPROTO_ICMP)
      xxi->nat_xport = key->dport;
  }
  if (xi->nat_flags & LLB_NAT_HSRC) {
    DP_XADDR_CP(xkey->saddr, key->saddr);
    DP_XADDR_CP(xkey->daddr, key->daddr);

    if (key->l4proto != IPPROTO_ICMP) {
      if (xi->nat_xport)
        xkey->dport = xi->nat_xport;
      else
        xi->nat_xport = key->sport;
    }

    xxi->nat_flags = LLB_NAT_HDST;
    xxi->nv6 = key->v6;
    DP_XADDR_SETZR(xxi->nat_xip);
    DP_XADDR_SETZR(xi->nat_xip);

    if (key->l4proto != IPPROTO_ICMP)
      xxi->nat_xport = key->sport;
  }

  return 0;  
}

static int __always_inline
dp_ct3_sm(struct dp_ct_dat *tdat,
          struct dp_ct_dat *xtdat,
          ct_dir_t dir)
{
  ct_state_t new_state = tdat->pi.l3i.state;
  switch (tdat->pi.l3i.state) {
  case CT_STATE_NONE:
    if (dir == CT_DIR_IN)  {
      new_state = CT_STATE_REQ;
    } else {
      return -1;
    }
    break;
  case CT_STATE_REQ:
    if (dir == CT_DIR_OUT)  {
      new_state = CT_STATE_REP;
    }
    break;
  case CT_STATE_REP:
    if (dir == CT_DIR_IN)  {
      new_state = CT_STATE_EST;
    } 
    break;
  default:
    break;
  }

  tdat->pi.l3i.state = new_state;

  if (new_state == CT_STATE_EST) {
    return 1;
  }

  return 0;
}

static int __always_inline
dp_ct_tcp_sm(void *ctx, struct xfi *xf, 
             struct dp_ct_tact *atdat,
             struct dp_ct_tact *axtdat,
             ct_dir_t dir)
{
  struct dp_ct_dat *tdat = &atdat->ctd;
  struct dp_ct_dat *xtdat = &axtdat->ctd;
  ct_tcp_pinf_t *ts = &tdat->pi.t;
  ct_tcp_pinf_t *rts = &xtdat->pi.t;
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));
  struct tcphdr *t = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);
  uint8_t tcp_flags = xf->pm.tcp_flags;
  ct_tcp_pinfd_t *td = &ts->tcp_cts[dir];
  ct_tcp_pinfd_t *rtd;
  uint32_t seq;
  uint32_t ack;
  uint32_t nstate = 0;
  /* Read outside the spin-lock section below: no helper calls are allowed
   * while the lock is held */
  int is_gso = dp_skb_is_gso(ctx);
  int defer_ppv2 = 0;

  if (t + 1 > dend) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCT_ERR);
    return -1;
  }

  seq = bpf_ntohl(t->seq);
  ack = bpf_ntohl(t->ack_seq);

#ifndef HAVE_DP_DPU_SLIM
  bpf_spin_lock(&atdat->lock);
#endif

  if (dir == CT_DIR_IN) {
    tdat->pi.t.tcp_cts[0].pseq = t->seq;
    tdat->pi.t.tcp_cts[0].pack = t->ack_seq;
    tdat->pb.bytes += xf->pm.l3_len;
    tdat->pb.packets += 1;
  } else {
    xtdat->pi.t.tcp_cts[0].pseq = t->seq;
    xtdat->pi.t.tcp_cts[0].pack = t->ack_seq;
    xtdat->pb.bytes += xf->pm.l3_len;
    xtdat->pb.packets += 1;
  }

  rtd = &ts->tcp_cts[dir == CT_DIR_IN ? CT_DIR_OUT:CT_DIR_IN];

  if (dir == CT_DIR_IN) {
    if (td->ppv2) {
      xf->pm.oppv2 = 1;
    }
  } else {
    if (td->ppv2) {
      xf->pm.ippv2 = 1;
    }
  }

  if (tcp_flags & LLB_TCP_RST) {
    nstate = CT_TCP_CW;
    goto end;
  }

  switch (ts->state) {
  case CT_TCP_CLOSED:

    if (xf->nm.dsr) {
      nstate = CT_TCP_EST;
      goto end;
    }

    /* If DP starts after TCP was established
     * we need to somehow handle this particular case
     */
    if (tcp_flags & LLB_TCP_ACK)  {
      td->seq = seq;
      if (td->init_acks) {
        if (ack  > rtd->seq + 2) {
          nstate = CT_TCP_ERR;
          goto end;
        }
      }
      td->init_acks++;
      if (td->init_acks >= CT_TCP_INIT_ACK_THRESHOLD &&
          rtd->init_acks >= CT_TCP_INIT_ACK_THRESHOLD) {
        nstate = CT_TCP_EST;
        break;
      }
      nstate = CT_TCP_ERR;
      goto end;
    }
    
    if ((tcp_flags & LLB_TCP_SYN) != LLB_TCP_SYN) {
      nstate = CT_TCP_ERR;
      goto end;
    }

    /* SYN sent with ack 0 */
    if (ack != 0 && dir != CT_DIR_IN) {
      nstate = CT_TCP_ERR;
      goto end;
    }

    td->seq = seq;
    nstate = CT_TCP_SS;
    
#ifdef HAVE_L4_TRACE
    // RTT Calculation: Initialize timestamp tracking on SYN
    ts->syn_ack_time_ns = 0;
    ts->rtt_us = 0;
#endif
    break;
  case CT_TCP_SS:
    if (dir != CT_DIR_OUT) {
      if ((tcp_flags & LLB_TCP_SYN) == LLB_TCP_SYN) {
        td->seq = seq;
        nstate = CT_TCP_SS;
      } else {
        nstate = CT_TCP_ERR;
      }
      goto end;
    }
  
    if ((tcp_flags & (LLB_TCP_SYN|LLB_TCP_ACK)) !=
         (LLB_TCP_SYN|LLB_TCP_ACK)) {
      nstate = CT_TCP_ERR;
      goto end;
    }
  
    if (ack  != rtd->seq + 1) {
      nstate = CT_TCP_ERR;
      goto end;
    }

    td->seq = seq;
    nstate = CT_TCP_SA;
    break;

  case CT_TCP_SA:
    if (dir != CT_DIR_IN) {
      if ((tcp_flags & (LLB_TCP_SYN|LLB_TCP_ACK)) !=
         (LLB_TCP_SYN|LLB_TCP_ACK)) {
        nstate = CT_TCP_ERR;
        goto end;
      }

      if (ack  != rtd->seq + 1) {
        nstate = CT_TCP_ERR;
        goto end;
      }

      nstate = CT_TCP_SA;
      goto end;
    } 

    if ((tcp_flags & LLB_TCP_SYN) == LLB_TCP_SYN) {
      td->seq = seq;
      nstate = CT_TCP_SS;
      goto end;
    }
  
    if ((tcp_flags & LLB_TCP_ACK) != LLB_TCP_ACK) {
      nstate = CT_TCP_ERR;
      goto end;
    }

    if (ack  != rtd->seq + 1) {
      nstate = CT_TCP_ERR;
      goto end;
    }

    td->seq = seq;

#ifdef HAVE_L4_TRACE
    // RTT Calculation: Record SYN-ACK timestamp when transitioning to SYN-ACK state
    // This will be used to calculate RTT when connection is ESTABLISHED
    if (ts->state == CT_TCP_SS && dir == CT_DIR_OUT) {
      // Cannot call bpf_ktime_get_ns() inside spinlock - will be calculated after unlock
      // For now, just mark that we need to record the timestamp
      ts->syn_ack_time_ns = 1; // Placeholder, will be set after unlock
    }
#endif
    
    if (xf->nm.ppv2) {
      nstate = CT_TCP_PEST;
      /* Insert the ppv2 header early, on this handshake ACK: an empty ACK
       * is never a GSO super-packet, so dp_ins_ppv2 runs on the proven
       * single-segment path. The first data packet (e.g. TLS ClientHello,
       * which GRO can turn into a GSO super-packet) then only needs the
       * GSO-safe seq fixup, avoiding the FIXED_GSO stream corruption
       * (issue #1044/#1089). If this packet itself carries piggybacked
       * data and was GRO-merged (is_gso), defer: leave the connection
       * unmarked and drop it, so the retransmit (a single non-GSO MSS
       * segment) gets the header inserted instead.
       */
      if (td->ppv2 == 0) {
        if (!is_gso) {
          xf->pm.ppv2 = 1;
          td->ppv2 = 1;
          rtd->ppv2 = 1;
        } else {
          defer_ppv2 = 1;
        }
      }
    } else {
      nstate = CT_TCP_EST;
    }
    break;

  case CT_TCP_PEST:
    if (tcp_flags & LLB_TCP_FIN) {
      ts->fndir = dir;
      nstate = CT_TCP_FINI;
      td->seq = seq;
    } else {
      nstate = CT_TCP_PEST;
      if (dir == CT_DIR_IN) {
        if (td->ppv2 == 0) {
          if (!is_gso) {
            xf->pm.ppv2 = 1;
            td->ppv2 = 1;
            rtd->ppv2 = 1;
          } else {
            /* GSO super-packet: inline insertion would corrupt the byte
             * stream (28-byte seq hole). Drop without marking so the
             * retransmit carries the header instead.
             */
            defer_ppv2 = 1;
          }
        }
      }
    }
    break;

  case CT_TCP_EST:
    if (tcp_flags & LLB_TCP_FIN) {
      ts->fndir = dir;
      nstate = CT_TCP_FINI;
      td->seq = seq;
    } else {
      nstate = CT_TCP_EST;
    }
    break;

  case CT_TCP_FINI:
    if (ts->fndir != dir) {
      if ((tcp_flags & (LLB_TCP_FIN|LLB_TCP_ACK)) == 
          (LLB_TCP_FIN|LLB_TCP_ACK)) {
        nstate = CT_TCP_FINI3;
        td->seq = seq;
      } else if (tcp_flags & LLB_TCP_ACK) {
        nstate = CT_TCP_FINI2;
        td->seq = seq;
      }
    }
    break;
  case CT_TCP_FINI2:
    if (ts->fndir != dir) {
      if (tcp_flags & LLB_TCP_FIN) {
        nstate = CT_TCP_FINI3;
        td->seq = seq;
      }
    }
    break;

  case CT_TCP_FINI3:
    if (ts->fndir == dir) {
      if (tcp_flags & LLB_TCP_ACK) {
        nstate = CT_TCP_CW;
      }
    }
    break;

  default:
    break;
  }

end:
  {
    // Save old state before updating. Always computed: needed both for the
    // always-on error accounting below and (when compiled) L4 trace emission.
    uint32_t old_state = ts->state;

    ts->state = nstate;
    rts->state = nstate;

    if (nstate != CT_TCP_ERR && dir == CT_DIR_OUT) {
      xtdat->pi.t.tcp_cts[0].seq = seq;
    }

#ifndef HAVE_DP_DPU_SLIM
    bpf_spin_unlock(&atdat->lock);
#endif

    // Always-on, unsampled error accounting (metric logic — trace-independent).
    // Count each transition INTO a reset/error state exactly once. MUST be after
    // the spinlock release (helper calls are illegal under bpf_spin_lock). This
    // DP encodes RST-received as CT_TCP_CW (see the CONN_RESET handling above).
    if (old_state != nstate) {
      if (nstate & CT_TCP_CW) {
        // CT_DIR_IN = client sent RST, CT_DIR_OUT = backend sent RST.
        dp_update_ct_error_stats(dir == CT_DIR_IN ?
                                 CT_ERR_STAT_TCP_RST_CLIENT :
                                 CT_ERR_STAT_TCP_RST_SERVER, 1);
      } else if (nstate & CT_TCP_ERR) {
        /* Count a TCP protocol error only once the connection actually
         * established (or is tearing down). A CT_TCP_ERR out of a pre-established
         * handshake state (CLOSED / SYN-SENT / SYN-ACK) is not a backend or
         * protocol error on real load-balanced traffic — it is what the datapath
         * sees for flows it observed mid-handshake, e.g. short-lived local
         * management/REST connections to loxilb's own API port. Counting those
         * manufactured "L4 errors" (~5 per REST call, all from CLOSED/SYN-SENT)
         * inflated the error signal and could false-fire the error-burst alert.
         * Backend refusals arrive as RST and are accounted above as
         * rst_server/rst_client, not here. */
        if (old_state == CT_TCP_EST || (old_state & CT_TCP_FIN_MASK)) {
        dp_update_ct_error_stats(CT_ERR_STAT_TCP_ERR, 1);
        }
      }
    }

#ifdef HAVE_L4_TRACE
    // RTT Calculation: Must be done AFTER spinlock release
    // eBPF doesn't allow helper function calls while holding locks
    if (old_state == CT_TCP_SA && nstate == CT_TCP_EST) {
      // Record SYN-ACK timestamp when transitioning from SYN-SENT to SYN-ACK
      if (ts->syn_ack_time_ns == 1 && dir == CT_DIR_OUT) {
        __u64 syn_ack_time = bpf_ktime_get_ns();
#ifndef HAVE_DP_DPU_SLIM
        bpf_spin_lock(&atdat->lock);
#endif
        ts->syn_ack_time_ns = syn_ack_time;
#ifndef HAVE_DP_DPU_SLIM
        bpf_spin_unlock(&atdat->lock);
#endif
      }

      // Calculate RTT when ACK received (SYN-ACK → ESTABLISHED)
      __u64 saved_syn_ack_time = ts->syn_ack_time_ns;
      if (saved_syn_ack_time > 1) {  // Valid timestamp (not 0 or 1 placeholder)
        __u64 now_ns = bpf_ktime_get_ns();
        __u64 delta_ns = now_ns - saved_syn_ack_time;
        __u32 rtt_us = (__u32)(delta_ns / 1000);

#ifndef HAVE_DP_DPU_SLIM
        bpf_spin_lock(&atdat->lock);
#endif
        ts->rtt_us = rtt_us;
#ifndef HAVE_DP_DPU_SLIM
        bpf_spin_unlock(&atdat->lock);
#endif
        
#ifdef HAVE_PROXY_EXTRA_DEBUG
        bpf_printk("[L4_TRACE_RTT] TCP RTT calculated: %u us", rtt_us);
#endif
      }
    }
    
    // Emit event to ring buffer (pass xf to avoid stack allocation)
    if (old_state != nstate) {
      uint32_t state_and_dir = ((uint32_t)old_state << 16) | ((uint32_t)nstate << 8) | (uint32_t)dir;
      lxb_l4_emit_event(xf, atdat, state_and_dir, IPPROTO_TCP);
    }
#endif
  }

  if (defer_ppv2) {
    /* The ppv2 header can only be inserted on a non-GSO packet; drop this one
     * (connection left unmarked) and let the retransmit carry it. Our end:
     * block already released atdat->lock (guarded #ifndef HAVE_DP_DPU_SLIM),
     * so no unlock here — avoid a double-unlock.
     */
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
  }

  if (nstate == CT_TCP_EST) {
    return CT_SMR_EST;
  } else if (nstate & CT_TCP_CW) {
    return CT_SMR_CTD;
  } else if (nstate & CT_TCP_ERR) {
    return CT_SMR_ERR;
  } else if (nstate & CT_TCP_FIN_MASK) {
    return CT_SMR_FIN;
  }

  return CT_SMR_INPROG;
}

static int __always_inline
dp_ct_udp_sm(void *ctx, struct xfi *xf,
             struct dp_ct_tact *atdat,
             struct dp_ct_tact *axtdat,
             ct_dir_t dir)
{
  struct dp_ct_dat *tdat = &atdat->ctd;
  struct dp_ct_dat *xtdat = &axtdat->ctd;
  ct_udp_pinf_t *us = &tdat->pi.u;
  ct_udp_pinf_t *xus = &xtdat->pi.u;
  uint32_t nstate = us->state;

  /* Suppress unused variable warning (xus is used later) */
  (void)xus;

  // bpf_spin_lock(&atdat->lock);

  if (dir == CT_DIR_IN) {
    bpf_printk("[CT_UDP_SM] state trace - DIR_IN");
    tdat->pb.bytes += xf->pm.l3_len;
    tdat->pb.packets += 1;
    us->pkts_seen++;
  } else {
    bpf_printk("[CT_UDP_SM] not start state trace - DIR_OUT");
    xtdat->pb.bytes += xf->pm.l3_len;
    xtdat->pb.packets += 1;
    us->rpkts_seen++;
  }

  switch (us->state) {
  case CT_UDP_CNI:
    bpf_printk("[CT_UDP_SM] CT_UDP_CNI state, pkts=%u, rpkts=%u", us->pkts_seen, us->rpkts_seen);
    if (xf->nm.dsr || xf->l2m.ssnid) {
      bpf_printk("[CT_UDP_SM] DSR/SSNID detected - CNI->EST");
      nstate = CT_UDP_EST;
      break;
    }

    if (us->pkts_seen && us->rpkts_seen) {
      bpf_printk("[CT_UDP_SM] Bidirectional traffic - CNI->EST");
      nstate = CT_UDP_EST;
    } else if (us->pkts_seen > CT_UDP_CONN_THRESHOLD) {
      bpf_printk("[CT_UDP_SM] Unidirectional threshold reached - CNI->UEST");
      nstate = CT_UDP_UEST;
    }
    break;

  case CT_UDP_UEST:
    bpf_printk("[CT_UDP_SM] CT_UDP_UEST state, pkts=%u, rpkts=%u", us->pkts_seen, us->rpkts_seen);
    bpf_printk("[CT_UDP_SM] checking packets for EST transition");
    if (us->rpkts_seen || us->pkts_seen > 2*CT_UDP_CONN_THRESHOLD) {
      bpf_printk("[CT_UDP_SM] UEST->EST (bidirectional or high packet count)");
      nstate = CT_UDP_EST;
    }
    break;

  case CT_UDP_EST:
    bpf_printk("[CT_UDP_SM] CT_UDP_EST state");
  if (xf->pm.l4fin) {
    bpf_printk("[CT_UDP_SM] l4fin detected");
    nstate = CT_UDP_FINI;
    us->fndir = dir;
  }
    break;
  case CT_UDP_FINI:
    bpf_printk("[CT_UDP_SM] CT_UDP_FINI state");
    if (xf->pm.l4fin && us->fndir != dir) {
      nstate = CT_UDP_CW;
    }
    break;

  default:
    bpf_printk("[CT_UDP_SM] default state");
    break;
  }

#ifdef HAVE_L4_TRACE
  // Save old state before updating for event emission
  uint32_t old_state = us->state;
#endif

  us->state = nstate;
  xus->state = nstate;

  // bpf_spin_unlock(&atdat->lock);

#ifdef HAVE_L4_TRACE
  // Emit full event to ring buffer (pass xf to avoid stack allocation)
  if (old_state != nstate) {
    uint32_t state_and_dir = ((uint32_t)old_state << 16) | ((uint32_t)nstate << 8) | (uint32_t)dir;
    lxb_l4_emit_event(xf, atdat, state_and_dir, IPPROTO_UDP);
  }
#endif


  /* Note: DCID map operations are now done immediately upon migration detection */

  if (nstate == CT_UDP_UEST) {
    bpf_printk("[CT_UDP_SM] returning CT_SMR_UEST");
    return CT_SMR_UEST;
  } else if (nstate == CT_UDP_EST) {
    bpf_printk("[CT_UDP_SM] returning CT_SMR_EST");
    return CT_SMR_EST;
  } else if (nstate & CT_UDP_CW) {
    bpf_printk("[CT_UDP_SM] returning CT_SMR_CTD");
    return CT_SMR_CTD;
  } else if (nstate & CT_UDP_FIN_MASK) {
    bpf_printk("[CT_UDP_SM] returning CT_SMR_FIN");
    return CT_SMR_FIN;
  } else {
    bpf_printk("[CT_UDP_SM] returning CT_SMR_INPROG");
  }  
  return CT_SMR_INPROG;
}

static int __always_inline
dp_ct_icmp6_sm(void *ctx, struct xfi *xf,
               struct dp_ct_tact *atdat,
               struct dp_ct_tact *axtdat,
               ct_dir_t dir)
{
  struct dp_ct_dat *tdat = &atdat->ctd;
  struct dp_ct_dat *xtdat = &axtdat->ctd;
  ct_icmp_pinf_t *is = &tdat->pi.i;
  ct_icmp_pinf_t *xis = &xtdat->pi.i;
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));
  struct icmp6hdr *i = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);
  uint32_t nstate;
  uint16_t seq;

  if (i + 1 > dend) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCT_ERR);
    return -1;
  }

  /* We fetch the sequence number even if icmp may not be
   * echo type because we can't call another fn holding
   * spinlock
   */
  seq = bpf_ntohs(i->icmp6_dataun.u_echo.sequence);

#ifndef HAVE_DP_DPU_SLIM
  bpf_spin_lock(&atdat->lock);
#endif

  if (dir == CT_DIR_IN) {
    tdat->pb.bytes += xf->pm.l3_len;
    tdat->pb.packets += 1;
  } else {
    xtdat->pb.bytes += xf->pm.l3_len;
    xtdat->pb.packets += 1;
  }

  nstate = is->state;

  switch (i->icmp6_type) {
  case ICMPV6_DEST_UNREACH:
    is->state |= CT_ICMP_DUNR;
    goto end;
  case ICMPV6_TIME_EXCEED:
    is->state |= CT_ICMP_TTL;
    goto end;
  case ICMPV6_ECHO_REPLY:
  case ICMPV6_ECHO_REQUEST:
    /* Further state-machine processing */
    break;
  default:
    is->state |= CT_ICMP_UNK;
    goto end;
  }

  switch (is->state) {
  case CT_ICMP_CLOSED:
    if (xf->nm.dsr) {
      nstate = CT_ICMP_REPS;
      goto end;
    }
    if (i->icmp6_type != ICMPV6_ECHO_REQUEST) {
      is->errs = 1;
      goto end;
    }
    nstate = CT_ICMP_REQS;
    is->lseq = seq;
    break;
  case CT_ICMP_REQS:
    if (i->icmp6_type == ICMPV6_ECHO_REQUEST) {
      is->lseq = seq;
    } else if (i->icmp6_type == ICMPV6_ECHO_REPLY) {
      if (is->lseq != seq) {
        is->errs = 1;
        goto end;
      }
      nstate = CT_ICMP_REPS;
      is->lseq = seq;
    }
    break;
  case CT_ICMP_REPS:
    /* Connection is tracked now */
  default:
    break;
  }

end:
  is->state = nstate;
  xis->state = nstate;

#ifndef HAVE_DP_DPU_SLIM
  bpf_spin_unlock(&atdat->lock);
#endif

  if (nstate == CT_ICMP_REPS)
    return CT_SMR_EST;

  return CT_SMR_INPROG;
}

static int __always_inline
dp_ct_icmp_sm(void *ctx, struct xfi *xf,
              struct dp_ct_tact *atdat,
              struct dp_ct_tact *axtdat,
              ct_dir_t dir)
{
  struct dp_ct_dat *tdat = &atdat->ctd;
  struct dp_ct_dat *xtdat = &axtdat->ctd;
  ct_icmp_pinf_t *is = &tdat->pi.i;
  ct_icmp_pinf_t *xis = &xtdat->pi.i;
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));
  struct icmphdr *i = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);
  uint32_t nstate;
  uint16_t seq;

  if (i + 1 > dend) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCT_ERR);
    return -1;
  }

  /* We fetch the sequence number even if icmp may not be
   * echo type because we can't call another fn holding
   * spinlock
   */
  seq = bpf_ntohs(i->un.echo.sequence);

#ifndef HAVE_DP_DPU_SLIM
  bpf_spin_lock(&atdat->lock);
#endif

  if (dir == CT_DIR_IN) {
    tdat->pb.bytes += xf->pm.l3_len;
    tdat->pb.packets += 1;
  } else {
    xtdat->pb.bytes += xf->pm.l3_len;
    xtdat->pb.packets += 1;
  }

  nstate = is->state;

  switch (i->type) {
  case ICMP_DEST_UNREACH:
    is->state |= CT_ICMP_DUNR;
    goto end;
  case ICMP_TIME_EXCEEDED:
    is->state |= CT_ICMP_TTL;
    goto end;
  case ICMP_REDIRECT:
    is->state |= CT_ICMP_RDR;
    goto end;
  case ICMP_ECHOREPLY:
  case ICMP_ECHO:
    /* Further state-machine processing */
    break;
  default:
    is->state |= CT_ICMP_UNK;
    goto end;
  } 

  switch (is->state) { 
  case CT_ICMP_CLOSED: 
    if (xf->nm.dsr) {
      nstate = CT_ICMP_REPS;
      goto end;
    }

    if (i->type != ICMP_ECHO) { 
      is->errs = 1;
      goto end;
    }
    nstate = CT_ICMP_REQS;
    is->lseq = seq;
    break;
  case CT_ICMP_REQS:
    if (i->type == ICMP_ECHO) {
      is->lseq = seq;
    } else if (i->type == ICMP_ECHOREPLY) {
      if (is->lseq != seq) {
        is->errs = 1;
        goto end;
      }
      nstate = CT_ICMP_REPS;
      is->lseq = seq;
    }
    break;
  case CT_ICMP_REPS:
    /* Connection is tracked now */
  default:
    break;
  }

end:
  is->state = nstate;
  xis->state = nstate;

#ifndef HAVE_DP_DPU_SLIM
  bpf_spin_unlock(&atdat->lock);
#endif

  if (nstate == CT_ICMP_REPS)
    return CT_SMR_EST;

  return CT_SMR_INPROG;
}

#ifndef HAVE_DP_DPU_SLIM
static int __always_inline
dp_ct_sctp_sm(void *ctx, struct xfi *xf,
              struct dp_ct_tact *atdat,
              struct dp_ct_tact *axtdat,
              ct_dir_t dir)
{
  struct dp_ct_dat *tdat = &atdat->ctd;
  struct dp_ct_dat *xtdat = &axtdat->ctd;
  ct_sctp_pinf_t *ss = &tdat->pi.s;
  ct_sctp_pinf_t *xss = &xtdat->pi.s;
  ct_sctp_pinfd_t *pss = &ss->sctp_cts[CT_DIR_IN];
  ct_sctp_pinfd_t *pxss = &ss->sctp_cts[CT_DIR_OUT];
  uint32_t nstate = 0;
  uint32_t npmhh = tdat->pi.npmhh;
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));
  struct sctphdr *s = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);
  struct sctp_dch *c;
  struct sctp_init_ch *ic;
  struct sctp_cookie *ck;
  struct sctp_param  *pm;
  uint16_t poff = 0;
  uint32_t nh = 0;
  int i = 0;

  if (s + 1 > dend) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCT_ERR);
    return -1;
  }

  c = DP_TC_PTR(DP_ADD_PTR(s, sizeof(*s)));
  
  if (c + 1 > dend) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCT_ERR);
    return -1;
  }

  poff = xf->pm.l4_off + sizeof(*s);

  nstate = ss->state;
  bpf_spin_lock(&atdat->lock);

  if (dir == CT_DIR_IN) {
    atdat->ctd.pb.bytes += xf->pm.l3_len;
    atdat->ctd.pb.packets += 1;
  } else {
    axtdat->ctd.pb.bytes += xf->pm.l3_len;
    axtdat->ctd.pb.packets += 1;
  }

  switch (c->type) {
  case SCTP_ERROR:
    nstate = CT_SCTP_ERR;
    goto end;
  case SCTP_SHUT:
    nstate = CT_SCTP_SHUT;
    goto end;
  case SCTP_ABORT:
    nstate = CT_SCTP_ABRT;
    goto end;
  }

  switch (ss->state) {
  case CT_SCTP_CLOSED:
    if (xf->nm.dsr) {
      nstate = CT_SCTP_EST;
      goto end;
    }

    if (dir == CT_DIR_IN && tdat->xi.nat_flags && s->vtag != 0 &&
        (c->type == SCTP_DATA || c->type == SCTP_SACK ||
         c->type == SCTP_HB_REQ || c->type == SCTP_HB_ACK)) {
      nstate = CT_SCTP_EST;
      goto end;
    }

    if (c->type != SCTP_INIT_CHUNK || dir != CT_DIR_IN) {
      nstate = CT_SCTP_ERR;
      goto end;
    }

    ic = DP_TC_PTR(DP_ADD_PTR(c, sizeof(*c)));
    if (ic + 1 > dend) {
      goto end;
    }
    poff += sizeof(*c);

    ss->itag = ic->tag;
    nstate = CT_SCTP_INIT;

    pm = DP_TC_PTR(DP_ADD_PTR(ic, sizeof(*ic)));
    if (pm + 1 > dend) {
      goto add_nph0;
    } 
    poff += sizeof(*ic);

    if (xf->l2m.dl_type != bpf_ntohs(ETH_P_IP) || !tdat->xi.nat_flags) {
      break;
    }

    pss->mh_host[0] = xf->l34m.saddr[0];
    pss->nh = 1;
    pss->odst = xf->l34m.daddr[0];
    pss->osrc = xf->l34m.saddr[0];

    nh = 1;
    for (i = 0; i < LLB_MAX_SCTP_CHUNKS_INIT; i++) {
      uint16_t csz = 0;
      if (poff >= 4096) {
        bpf_spin_unlock(&atdat->lock);
        LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCT_ERR);
        return -1;
      }
      pm = DP_TC_PTR(DP_ADD_PTR(DP_PDATA(ctx), poff));
      dend = DP_TC_PTR(DP_PDATA_END(ctx));
      if (pm + 1 > dend) {
        goto add_nph0;
      }

      if (pm->type == bpf_htons(SCTP_IPV4_ADDR_PARAM)) {
        __be32 *ip = DP_TC_PTR(DP_ADD_PTR(pm, sizeof(*pm)));
        if (ip + 1 > dend) {
          break;
        }
        if (nh <= LLB_MAX_MHOSTS && *ip != pss->osrc) {
          pss->mh_host[nh] = *ip;
          pss->nh++;
          nh++;
        }

        if (!atdat->nat_act.nv6) {
          /* Checksum to be taken care of at a later stage */
          if (nh-1 < LLB_MAX_MHOSTS && atdat->ctd.pi.pmhh[nh-1] != 0) {
            *ip = atdat->ctd.pi.pmhh[nh-1];
          } else if (atdat->ctd.pi.pmhh[0] != 0) {
            *ip = atdat->ctd.pi.pmhh[0];
          } else if (atdat->nat_act.rip[0] != 0) {
            *ip = atdat->nat_act.rip[0];
          }
        }
      }

      csz = bpf_ntohs(pm->len);
      poff += (csz + 3) & ~0x3;
    }

add_nph0:
    if ((pss->nh - 1) < npmhh) {
      int grow;
      int diff = npmhh - pss->nh + 1;

      grow = ((diff)*(sizeof(*pm)+sizeof(__u32)));
      poff = (((struct __sk_buff *)ctx)->len);

      bpf_spin_unlock(&atdat->lock);
      if (dp_pktbuf_expand_tail(ctx, grow + poff) < 0) {
        LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCT_ERR);
        bpf_spin_lock(&atdat->lock);
        break;
      }
      bpf_spin_lock(&atdat->lock);

      pm = DP_TC_PTR(DP_PDATA(ctx));
      dend = DP_TC_PTR(DP_PDATA_END(ctx));
      if (pm + 1 > dend) {
        break;
      }

      for (i = 0; i < diff; i++) {

        if (i >= LLB_MAX_MHOSTS) break;

        /* Keep the verifier happy */
        if (poff > SCTP_MAX_INIT_ACK_SZ) {
          break;
        }

        pm = DP_ADD_PTR(pm, poff);
        if (pm + 1 > dend) {
          break;
        }

        pm->type = bpf_htons(SCTP_IPV4_ADDR_PARAM);
        pm->len = bpf_htons(sizeof(*pm) + sizeof(__u32));

        __be32 *ip = DP_TC_PTR(DP_ADD_PTR(pm, sizeof(*pm)));
        if (ip + 1 > dend) {
          break;
        }

        if (!atdat->nat_act.nv6) {
          /* Checksum to be taken care of at a later stage */
          if (i < LLB_MAX_MHOSTS && atdat->ctd.pi.pmhh[i] != 0) {
            *ip = atdat->ctd.pi.pmhh[i];
          } else if (atdat->ctd.pi.pmhh[0] != 0) {
            *ip = atdat->ctd.pi.pmhh[0];
          } else if (atdat->nat_act.rip[0] != 0) {
            *ip = atdat->nat_act.rip[0];
          }
        }

        poff = sizeof(*pm)+sizeof(__u32);
      }

      s = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);
      if (s + 1 > dend) {
        break;
      }

      c = DP_TC_PTR(DP_ADD_PTR(s, sizeof(*s)));
      if (c + 1 > dend) {
        break;
      }

      poff = bpf_ntohs(c->len) + grow;
      c->len = bpf_htons(poff);
      xf->pm.l3_adj = grow;
    }
    break;
  case CT_SCTP_INIT:

    if (c->type != SCTP_INIT_CHUNK && c->type != SCTP_INIT_CHUNK_ACK) {
      nstate = CT_SCTP_ERR;
      goto end;
    }

    if ((c->type == SCTP_INIT_CHUNK && dir != CT_DIR_IN) ||
        (c->type == SCTP_INIT_CHUNK_ACK && dir != CT_DIR_OUT)) {
      nstate = CT_SCTP_ERR;
      goto end;
    }

    ic = DP_TC_PTR(DP_ADD_PTR(c, sizeof(*c)));
    if (ic + 1 > dend) {
      goto end;
    }
    poff += sizeof(*c);

    if (c->type == SCTP_INIT_CHUNK) {
      ss->itag = ic->tag;
      ss->otag = 0;
      nstate = CT_SCTP_INIT;
    } else {
      if (s->vtag != ss->itag) {
        nstate = CT_SCTP_ERR;
        goto end;
      }

      ss->otag = ic->tag;
      nstate = CT_SCTP_INITA;
    }

    if (xf->l2m.dl_type != bpf_ntohs(ETH_P_IP) || !tdat->xi.nat_flags) {
      break;
    }

    pm = DP_TC_PTR(DP_ADD_PTR(ic, sizeof(*ic)));
    if (pm + 1 > dend) {
      goto add_nph1;
    }
    poff += sizeof(*ic);

    pxss->mh_host[0] = xf->l34m.saddr[0];
    pxss->nh = 1;
    pxss->odst = xf->l34m.daddr[0];
    pxss->osrc = xf->l34m.saddr[0];

    nh = 1;
    for (i = 0; i < LLB_MAX_SCTP_CHUNKS_INIT; i++) {
      uint16_t csz = 0;
      if (poff >= 4096) {
        bpf_spin_unlock(&atdat->lock);
        LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCT_ERR);
        return -1;
      }
      pm = DP_TC_PTR(DP_ADD_PTR(DP_PDATA(ctx), poff));
      dend = DP_TC_PTR(DP_PDATA_END(ctx));
      if (pm + 1 > dend) {
        goto add_nph1;
      }

      if (pm->type == bpf_htons(SCTP_IPV4_ADDR_PARAM)) {
        __be32 *ip = DP_TC_PTR(DP_ADD_PTR(pm, sizeof(*pm)));
        if (ip + 1 > dend) {
          break;
        }

        if (nh <= LLB_MAX_MHOSTS && *ip != pxss->osrc) {
          pxss->mh_host[nh] = *ip;
          pxss->nh++;
          nh++;
        }

        if (!axtdat->nat_act.nv6) {
          /* Checksum to be taken care of a later stage */
          if (nh - 1 < LLB_MAX_MHOSTS && axtdat->ctd.pi.pmhh[nh-1] != 0) {
            *ip = axtdat->ctd.pi.pmhh[nh-1];
          } else if (axtdat->ctd.pi.pmhh[0] != 0) {
            *ip = axtdat->ctd.pi.pmhh[0];
          } else if (axtdat->nat_act.xip[0] != 0) {
            *ip = axtdat->nat_act.xip[0];
          }
        }
      }

      csz = bpf_ntohs(pm->len);
      poff += (csz + 3) & ~0x3;
    }

add_nph1:
    if ((pxss->nh - 1) < npmhh) {
      int grow;
      int diff = npmhh - pxss->nh + 1;

      grow = ((diff)*(sizeof(*pm)+sizeof(__u32)));
      poff = (((struct __sk_buff *)ctx)->len);

      bpf_spin_unlock(&atdat->lock);
      if (dp_pktbuf_expand_tail(ctx, grow + poff) < 0) {
        LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCT_ERR);
        bpf_spin_lock(&atdat->lock);
        break;
      }
      bpf_spin_lock(&atdat->lock);

      pm = DP_TC_PTR(DP_PDATA(ctx));
      dend = DP_TC_PTR(DP_PDATA_END(ctx));
      if (pm + 1 > dend) {
        break;
      }

      for (i = 0; i < diff; i++) {

        if (i >= LLB_MAX_MHOSTS) break;

        /* Keep the verifier happy */
        if (poff > SCTP_MAX_INIT_ACK_SZ) {
          break;
        }

        pm = DP_ADD_PTR(pm, poff);
        if (pm + 1 > dend) {
          break;
        }

        pm->type = bpf_htons(SCTP_IPV4_ADDR_PARAM);
        pm->len = bpf_htons(sizeof(*pm)+sizeof(__u32));

        __be32 *ip = DP_TC_PTR(DP_ADD_PTR(pm, sizeof(*pm)));
        if (ip + 1 > dend) {
          break;
        }

        /* Checksum to be taken care of at a later stage */
        if (i < LLB_MAX_MHOSTS && axtdat->ctd.pi.pmhh[i] != 0) {
          *ip = axtdat->ctd.pi.pmhh[i];
        } else if (axtdat->ctd.pi.pmhh[0] != 0) {
          *ip = axtdat->ctd.pi.pmhh[0];
        } else if (axtdat->nat_act.xip[0] != 0) {
          *ip = axtdat->nat_act.xip[0];
        }

        poff = sizeof(*pm)+sizeof(__u32);
      }

      s = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);
      if (s + 1 > dend) {
        break;
      }

      c = DP_TC_PTR(DP_ADD_PTR(s, sizeof(*s)));
      if (c + 1 > dend) {
        break;
      }

      poff = bpf_ntohs(c->len) + grow;
      c->len = bpf_htons(poff);
      xf->pm.l3_adj = grow;
    }

    if (npmhh > 0) {
      tdat->xi.mhon =  1;
      xtdat->xi.mhon = 1;
    }
    break;
  case CT_SCTP_INITA:

    if ((c->type != SCTP_INIT_CHUNK && dir != CT_DIR_IN) &&
        (c->type != SCTP_COOKIE_ECHO && dir != CT_DIR_IN)) {
      nstate = CT_SCTP_ERR;
      goto end;
    }

    if (c->type == SCTP_INIT_CHUNK) {
      ic = DP_TC_PTR(DP_ADD_PTR(c, sizeof(*c)));
      if (ic + 1 > dend) {
        goto end;
      }

      ss->itag = ic->tag;
      ss->otag = 0;
      nstate = CT_SCTP_INIT;
      goto end;
    }

    ck = DP_TC_PTR(DP_ADD_PTR(c, sizeof(*c)));
    if (ck + 1 > dend) {
      goto end;
    }

    if (ss->otag != s->vtag) {
      nstate = CT_SCTP_ERR;
      goto end;
    }

    ss->cookie = ck->cookie;
    nstate = CT_SCTP_COOKIE;
    break;
  case CT_SCTP_COOKIE:
    if (c->type != SCTP_COOKIE_ACK && dir != CT_DIR_OUT) {
      nstate = CT_SCTP_ERR;
      goto end;
    }

    if (ss->itag != s->vtag) {
      nstate = CT_SCTP_ERR;
      goto end;
    }

    nstate = CT_SCTP_COOKIEA;
    break;
  case CT_SCTP_COOKIEA:
    nstate = CT_SCTP_EST;
    break;
  case CT_SCTP_PRE_EST:
    if (dir != CT_DIR_OUT) {
      nstate = CT_SCTP_EST;
    }
    break;
  case CT_SCTP_EST:
#ifdef HAVE_SCTPMH_HB_MANGLE
    if (pss->nh) {
      int grow;
      poff = (((struct __sk_buff *)ctx)->len);
      if (c->type == SCTP_HB_REQ) {
        grow = sizeof(__u32);
        bpf_spin_unlock(&atdat->lock);
        if (dp_pktbuf_expand_tail(ctx, grow + poff) < 0) {
          LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCT_ERR);
          bpf_spin_lock(&atdat->lock);
          break;
        }

        bpf_spin_lock(&atdat->lock);
        dend = DP_TC_PTR(DP_PDATA_END(ctx));
        s = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);

        if (s + 1 > dend) {
          LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCT_ERR);
          break;
        }

        c = DP_TC_PTR(DP_ADD_PTR(s, sizeof(*s)));

        if (c + 1 > dend) {
          LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCT_ERR);
          break;
        }

        pm = DP_TC_PTR(DP_ADD_PTR(c, sizeof(*c)));
        if (pm + 1 > dend) {
          LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCT_ERR);
          break;
        }

        __u16 pmlen = bpf_ntohs(pm->len);
        if (pmlen > 512) {
          LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCT_ERR);
          break;
        }
        __be32 *ip = DP_ADD_PTR(pm, pmlen);
        if (ip + 1 > dend) {
          LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCT_ERR);
          break;
        }

        *ip = xf->l34m.saddr[0];
        c->len = bpf_htons((bpf_ntohs(c->len) + 4));
        pm->len = bpf_htons((bpf_ntohs(pm->len) + 4));
        xf->pm.l3_adj = grow;
      } else if (c->type == SCTP_HB_ACK) {
        pm = DP_TC_PTR(DP_ADD_PTR(c, sizeof(*c)));
        if (pm + 1 > dend) {
          LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCT_ERR);
          break;
        }
        __u16 pmlen = bpf_ntohs(pm->len);
        if (pmlen > 512) {
          LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCT_ERR);
          break;
        }
        __be32 *ip = DP_ADD_PTR(pm, pmlen-4);
        if (ip + 1 > dend) {
          LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCT_ERR);
          break;
        }
        c->len = bpf_htons((bpf_ntohs(c->len) - 4));
        pm->len = bpf_htons((bpf_ntohs(pm->len) - 4));

        if (dir == CT_DIR_IN) {
          xf->nm.nxip4 = *ip;
        } else {
          if (xf->nm.nrip4) {
            xf->nm.nrip4 = *ip;
          }
        }

        grow = -4;
        bpf_spin_unlock(&atdat->lock);
        if (dp_pktbuf_expand_tail(ctx, grow + poff) < 0) {
          LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCT_ERR);
          bpf_spin_lock(&atdat->lock);
          break;
        }
        bpf_spin_lock(&atdat->lock);

        xf->pm.l3_adj = grow;
      }
    }
#endif
    break;
  case CT_SCTP_ABRT:
    nstate = CT_SCTP_ABRT;
    break;
  case CT_SCTP_SHUT:
    if (c->type != SCTP_SHUT_ACK && dir != CT_DIR_OUT) {
      nstate = CT_SCTP_ERR;
      goto end;
    }
    nstate = CT_SCTP_SHUTA;
    break;
  case CT_SCTP_SHUTA:
    if (c->type != SCTP_SHUT_COMPLETE && dir != CT_DIR_IN) {
      nstate = CT_SCTP_ERR;
      goto end;
    }
    nstate = CT_SCTP_SHUTC;
    break;
  default:
    break;
  }
end:

  if (pss->nh && nstate == CT_SCTP_COOKIE) {
    nstate = CT_SCTP_EST;
  }

  // Save old state BEFORE updating. Always computed: needed for the always-on
  // error accounting below and (when compiled) L4 trace emission.
  uint32_t old_state = ss->state;

  ss->state = nstate;
  xss->state = nstate;

  bpf_spin_unlock(&atdat->lock);

  // Always-on, unsampled error accounting (metric logic — trace-independent).
  // Count each transition INTO an abort/error state exactly once, after unlock.
  if (old_state != nstate) {
    if (nstate & CT_SCTP_ABRT) {
      dp_update_ct_error_stats(CT_ERR_STAT_SCTP_ABORT, 1);
    } else if (nstate & CT_SCTP_ERR) {
      dp_update_ct_error_stats(CT_ERR_STAT_SCTP_ERR, 1);
    }
  }

#ifdef HAVE_L4_TRACE
  // Emit event to ring buffer after unlock (pass xf to avoid stack allocation)
  if (old_state != nstate) {
    uint32_t state_and_dir = ((uint32_t)old_state << 16) | ((uint32_t)nstate << 8) | (uint32_t)dir;
    lxb_l4_emit_event(xf, atdat, state_and_dir, IPPROTO_SCTP);
  }
#endif

  if (nstate == CT_SCTP_EST) {
    return CT_SMR_EST;
  } else if (nstate & CT_SCTP_SHUTC) {
    return CT_SMR_CTD;
  } else if (nstate & CT_SCTP_ERR) {
    return CT_SMR_ERR;
  } else if (nstate & CT_SCTP_FIN_MASK) {
    return CT_SMR_FIN;
  }

  return CT_SMR_INPROG;
}
#endif /* !HAVE_DP_DPU_SLIM - SCTP state machine */

static int __always_inline
dp_ct_sm(void *ctx, struct xfi *xf,
         struct dp_ct_tact *atdat,
         struct dp_ct_tact *axtdat,
         ct_dir_t dir)
{
  int sm_ret = 0;

  switch (xf->l34m.nw_proto) {
  case IPPROTO_TCP:
    sm_ret = dp_ct_tcp_sm(ctx, xf, atdat, axtdat, dir);
    break;
  case IPPROTO_UDP:
    sm_ret = dp_ct_udp_sm(ctx, xf, atdat, axtdat, dir);
    break;
  case IPPROTO_ICMP:
    sm_ret = dp_ct_icmp_sm(ctx, xf, atdat, axtdat, dir);
    break;
#ifndef HAVE_DP_DPU_SLIM
  case IPPROTO_SCTP:
    sm_ret = dp_ct_sctp_sm(ctx, xf, atdat, axtdat, dir);
    break;
#endif
  case IPPROTO_ICMPV6:
    sm_ret = dp_ct_icmp6_sm(ctx, xf, atdat, axtdat, dir);
    break;
  default:
    sm_ret = CT_SMR_UNT;
    break;
  }

  return sm_ret;
}

#define CP_CT_NAT_TACTS(dst, src)  \
  memcpy(&dst->ca, &src->ca, sizeof(struct dp_cmn_act));  \
  memcpy(&dst->ctd, &src->ctd, sizeof(struct dp_ct_dat)); \
  dst->ito =  src->ito; \
  dst->lts =  src->lts; \
  memcpy(&dst->nat_act, &src->nat_act, sizeof(struct dp_nat_act)); \

static int __always_inline
dp_ct_est(struct xfi *xf,
         struct dp_ct_key *key,
         struct dp_ct_key *xkey,
         struct dp_ct_tact *atdat,
         struct dp_ct_tact *axtdat)
{
  struct dp_ct_dat *tdat = &atdat->ctd;
  //struct dp_ct_dat *xtdat = &axtdat->ctd;
  struct dp_ct_tact_scratch *adat, *axdat;
#ifndef HAVE_DP_DPU_SLIM
  ct_sctp_pinf_t *ss;
  ct_sctp_pinf_t *tss;
  int i, j;
#endif
  int k;

  k = 0;
  adat = bpf_map_lookup_elem(&xctk, &k);

  k = 1;
  axdat = bpf_map_lookup_elem(&xctk, &k);

  if (adat == NULL || axdat == NULL || tdat->xi.dsr || tdat->xi.nv6) {
    return 0;
  }

  CP_CT_NAT_TACTS(adat, atdat);
  CP_CT_NAT_TACTS(axdat, axtdat);

#ifndef HAVE_DP_DPU_SLIM
  ss = &adat->ctd.pi.s;
  tss = &atdat->ctd.pi.s;
#endif

  switch (xf->l34m.nw_proto) {
  case IPPROTO_UDP:
    if (xf->l2m.ssnid) {
      if (xf->pm.dir == CT_DIR_IN) {
        adat->ctd.xi.osp = key->sport;
        adat->ctd.xi.odp = key->dport;
        key->sport = xf->l2m.ssnid;
        key->dport = xf->l2m.ssnid;
        adat->ctd.pi.frag = 1;
        bpf_map_update_elem(&ct_map, key, adat, BPF_ANY);
      } else {
        axdat->ctd.xi.osp = xkey->sport;
        axdat->ctd.xi.odp = xkey->dport;
        xkey->sport = xf->l2m.ssnid;
        xkey->dport = xf->l2m.ssnid;
        axdat->ctd.pi.frag = 1;
        bpf_map_update_elem(&ct_map, xkey, axdat, BPF_ANY);
      }
    }
    break;
#ifndef HAVE_DP_DPU_SLIM
  case IPPROTO_SCTP:
    /* Ignore Hearbeats */
    if (xf->pm.goct) return 0;

    if (tdat->xi.mhon && xf->pm.dir == CT_DIR_IN) {
      __be32 primary_src = 0;
      __be32 primary_ep = 0;
      __be32 secondary_ep = 0;
      __be32 mhvip = 0;
      ct_sctp_pinfd_t *pss = &ss->sctp_cts[CT_DIR_IN];
      //ct_sctp_pinfd_t *pxss = &ss->sctp_cts[CT_DIR_OUT];
      ct_sctp_pinfd_t *tpxss = &tss->sctp_cts[CT_DIR_OUT];

      for (i = 0; i < pss->nh && i < LLB_MAX_MHOSTS; i++) {
        if (pss->mh_host[i] == xf->l34m.saddr[0]) {
          primary_ep = tpxss->osrc;
          break;
        }
      }

      if (!primary_ep) {
        break;
      }

      adat->ctd.xi.mhon = 0;
      axdat->ctd.xi.mhon = 0;
      adat->ctd.xi.mhs = 1;
      axdat->ctd.xi.mhs = 1;

      for (i = 1, j = 0; i < pss->nh && i < LLB_MAX_MHOSTS; i++) {
        j = i - 1;
        if (j < LLB_MAX_MHOSTS) {
          if (tdat->pi.pmhh[j] && pss->mh_host[i]) {
            mhvip = tdat->pi.pmhh[j];
            primary_src = pss->mh_host[i];
            if (tpxss->mh_host[i]) {
              secondary_ep = tpxss->mh_host[i];
            } else {
              secondary_ep = primary_ep;
            }

            key->saddr[0] = pss->mh_host[i];
            key->daddr[0] = mhvip;

            adat->ctd.xi.nat_rip[0] = mhvip;
            adat->nat_act.rip[0] = mhvip;
            adat->ctd.xi.nat_xip[0] = secondary_ep;
            adat->nat_act.xip[0] = secondary_ep;

            xkey->daddr[0] = mhvip;
            xkey->saddr[0] = secondary_ep;
            axdat->ctd.xi.nat_xip[0] = mhvip;
            axdat->nat_act.xip[0] = mhvip;

            BPF_DBG_PRINTK("[CTRK] xASSOC %d 0x%x->0x%x", i, key->saddr[0], key->daddr[0]);
            axdat->nat_act.rip[0] = primary_src;
            axdat->ctd.xi.nat_rip[0] = primary_src;
            bpf_map_update_elem(&ct_map, xkey, axdat, BPF_ANY);

            BPF_DBG_PRINTK("[CTRK] ASSOC 0x%x->0x%x",key->saddr[0], key->daddr[0]);
            bpf_map_update_elem(&ct_map, key, adat, BPF_ANY);
          }
        }
      }

      j = i-1;
      i = 0;
      for (;j < LLB_MAX_MHOSTS; j++) {
        if (tdat->pi.pmhh[j] && pss->mh_host[i]) {
          mhvip = tdat->pi.pmhh[j];
          primary_src = pss->mh_host[i];
          if (tpxss->mh_host[i]) {
            secondary_ep = tpxss->mh_host[i];
          } else {
            secondary_ep = primary_ep;
          }

          key->saddr[0] = pss->mh_host[i];
          key->daddr[0] = mhvip;

          adat->ctd.xi.nat_rip[0] = mhvip;
          adat->nat_act.rip[0] = mhvip;
          adat->ctd.xi.nat_xip[0] = secondary_ep;
          adat->nat_act.xip[0] = secondary_ep;

          xkey->daddr[0] = mhvip;
          xkey->saddr[0] = secondary_ep;
          axdat->ctd.xi.nat_xip[0] = mhvip;
          axdat->nat_act.xip[0] = mhvip;

          BPF_DBG_PRINTK("[CTRK] xASSOC %d 0x%x->0x%x", i, key->saddr[0], key->daddr[0]);
          axdat->nat_act.rip[0] = primary_src;
          axdat->ctd.xi.nat_rip[0] = primary_src;
          bpf_map_update_elem(&ct_map, xkey, axdat, BPF_ANY);

          BPF_DBG_PRINTK("[CTRK] ASSOC 0x%x->0x%x",key->saddr[0], key->daddr[0]);
          bpf_map_update_elem(&ct_map, key, adat, BPF_ANY);
        }
      }
    }
    break;
#endif /* !HAVE_DP_DPU_SLIM - SCTP multi-homing */
  default:
    break;
  }
  return 0;
}

static int __always_inline
dp_ct_ctd(struct xfi *xf,
         struct dp_ct_key *key,
         struct dp_ct_key *xkey,
         struct dp_ct_tact *atdat,
         struct dp_ct_tact *axtdat)
{
#ifndef HAVE_DP_DPU_SLIM
  struct dp_ct_dat *tdat = &atdat->ctd;
  struct dp_ct_dat *xtdat = &axtdat->ctd;
  ct_sctp_pinf_t *ss;
  int i,j;

  ss = &atdat->ctd.pi.s;
#endif

  switch (xf->l34m.nw_proto) {
#ifndef HAVE_DP_DPU_SLIM
  case IPPROTO_SCTP:
    if (xf->nm.npmhh) {
      ct_sctp_pinfd_t *pss = &ss->sctp_cts[CT_DIR_IN];
      ct_sctp_pinfd_t *pxss = &ss->sctp_cts[CT_DIR_OUT];

      for (i = 0; i < pss->nh && i < LLB_MAX_MHOSTS; i++) {
        key->saddr[0] = pss->mh_host[i];
        for (j = 0; j < LLB_MAX_MHOSTS; j++) {
          if (tdat->pi.pmhh[j] && pss->mh_host[i]) {
            key->daddr[0] = tdat->pi.pmhh[j];
            xkey->daddr[0] = tdat->pi.pmhh[j];

            bpf_map_delete_elem(&ct_map, key);
            bpf_map_delete_elem(&ct_map, xkey);
          }
        }
        key->daddr[0] = pss->odst;
        bpf_map_delete_elem(&ct_map, key);
      }

      for (i = 0; i < pxss->nh && i < LLB_MAX_MHOSTS; i++) {
        xkey->saddr[0] = pxss->mh_host[i];
        for (j = 0; j < LLB_MAX_MHOSTS; j++) {
          if (xtdat->pi.pmhh[j] && pxss->mh_host[i]) {
            xkey->daddr[0] = xtdat->pi.pmhh[j];
            bpf_map_delete_elem(&ct_map, xkey);
          }
        }
        xkey->daddr[0] = pxss->odst;
        bpf_map_delete_elem(&ct_map, xkey);

      }
    }
    break;
#endif /* !HAVE_DP_DPU_SLIM - SCTP CT delete */
  default:
    break;
  }
  return 0;
}

static int __always_inline
dp_ct_in(void *ctx, struct xfi *xf)
{
  struct dp_ct_key key;
  struct dp_ct_key xkey;
  struct dp_ct_tact_scratch *adat;
  struct dp_ct_tact_scratch *axdat;
  struct dp_ct_tact *atdat;
  struct dp_ct_tact *axtdat;
  nxfrm_inf_t *xi;
  nxfrm_inf_t *xxi;
  ct_dir_t cdir = CT_DIR_IN;
  int smr = CT_SMR_ERR;
  int k;

  k = 0;
  adat = bpf_map_lookup_elem(&xctk, &k);

  k = 1;
  axdat = bpf_map_lookup_elem(&xctk, &k);

  if (adat == NULL || axdat == NULL) {
    return smr;
  }

  xi = &adat->ctd.xi;
  xxi = &axdat->ctd.xi;
 
  /* CT Key */
  DP_XADDR_CP(key.daddr, xf->l34m.daddr);
  DP_XADDR_CP(key.saddr, xf->l34m.saddr);
  key.sport = xf->l34m.source;
  key.dport = xf->l34m.dest;
  key.l4proto = xf->l34m.nw_proto;
  key.zone = xf->pm.zone;
  key.v6 = xf->l2m.dl_type == bpf_ntohs(ETH_P_IPV6) ? 1: 0;
  key.ident = xf->tm.tun_decap ? 0 : xf->tm.tunnel_id;
  key.type = xf->tm.tun_decap ? 0 : xf->tm.tun_type;

  if (key.l4proto != IPPROTO_TCP &&
      key.l4proto != IPPROTO_UDP &&
      key.l4proto != IPPROTO_ICMP &&
      key.l4proto != IPPROTO_SCTP &&
      key.l4proto != IPPROTO_ICMPV6) {
    return 0;
  }

  xi->nat_flags = xf->pm.nf;
  DP_XADDR_CP(xi->nat_xip, xf->nm.nxip);
  DP_XADDR_CP(xi->nat_rip, xf->nm.nrip);
  xi->nat_xport = xf->nm.nxport;
  xi->nv6 = xf->nm.nv6;
  xi->dsr = xf->nm.dsr;

  xxi->nat_flags = 0;
  xxi->nat_xport = 0;
  DP_XADDR_SETZR(xxi->nat_xip);
  DP_XADDR_SETZR(xxi->nat_rip);

  if (xf->pm.nf & (LLB_NAT_DST|LLB_NAT_SRC)) {
    if (DP_XADDR_ISZR(xi->nat_xip)) {
      if (xf->pm.nf == LLB_NAT_DST) {
        xi->nat_flags = LLB_NAT_HDST;
      } else if (xf->pm.nf == LLB_NAT_SRC){
        xi->nat_flags = LLB_NAT_HSRC;
      }
    }
  }

  dp_ct_proto_xfk_init(&key, xi, &xkey, xxi);

  atdat = bpf_map_lookup_elem(&ct_map, &key);
  if (atdat == NULL) {

    /* A TCP SYN|ACK can never open a flow: it is the second leg of a
     * handshake whose opening SYN this datapath has no entry for — either a
     * stale/orphan return packet, or a reply that raced the opening SYN's
     * ct commit (e.g. while the backend's nexthop was still resolving, the
     * punted SYN reaches the backend before the SYN's map inserts are
     * visible to the CPU handling the reply). Creating a fresh ct here is
     * always wrong: the CLOSED-state machine immediately errors the entry,
     * the error teardown also removes the opening flow's reverse key, and
     * the packet falls through to the kernel UNTRANSLATED — the client sees
     * the backend's real address, answers with a RST that is then NAT'd
     * onto the live backend socket, and the flow is wedged until the client
     * gives up. Drop it instead: the backend retransmits the SYN|ACK, and
     * by then the opening SYN's entries are in place so the retransmit is
     * reverse-translated normally. DSR flows are exempt — any first packet
     * may legitimately seed their ct (see CT_TCP_CLOSED handling).
     */
    if (key.l4proto == IPPROTO_TCP && !xf->nm.dsr &&
        (xf->pm.tcp_flags & (LLB_TCP_SYN|LLB_TCP_ACK)) ==
        (LLB_TCP_SYN|LLB_TCP_ACK)) {
      LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCT_ERR);
      dp_update_ct_error_stats(CT_ERR_STAT_TCP_ERR, 1);
      return 0;
    }

    BPF_TRACE_PRINTK("[CTRK] new-ct ent");
    adat->ca.ftrap = 0;
    adat->ca.oaux = 0;
    adat->ca.cidx = dp_ct_get_newctr(&adat->ctd.nid);
    adat->ca.fwrid = xf->pm.fw_rid;
    adat->ca.record = xf->pm.dp_rec;
    memset(&adat->ctd.pi, 0, sizeof(ct_pinf_t));
    if (xi->nat_flags) {
      adat->ca.act_type = xi->nat_flags & (LLB_NAT_DST|LLB_NAT_HDST) ?
                             DP_SET_DNAT: DP_SET_SNAT;
      DP_XADDR_CP(adat->nat_act.xip,  xi->nat_xip);
      DP_XADDR_CP(adat->nat_act.rip, xi->nat_rip);
      adat->nat_act.xport = xi->nat_xport;
      adat->nat_act.doct = 1;
      adat->nat_act.rid = xf->pm.rule_id;
      adat->nat_act.aid = xf->nm.sel_aid;
      adat->nat_act.nv6 = xf->nm.nv6 ? 1:0;
      adat->nat_act.dsr = xf->nm.dsr;
      adat->nat_act.cdis = xf->nm.cdis;
      adat->nat_act.nmh = xf->nm.npmhh;
      adat->nat_act.ppv2 = xf->nm.ppv2;
      /* Persist the rule policer id per-flow so established packets (which
       * never hit nat_map again) keep policing. The reverse direction gets the
       * same id below — the rule policer is bidirectional over one bucket.
       */
      adat->nat_act.polid = xf->qm.rpolid;
      adat->ito = xf->nm.ito;
    } else {
      adat->ito = 0;
      adat->ca.act_type = DP_SET_DO_CT;
    }
    adat->ctd.dir = cdir;

    /* FIXME This is duplicated data */
    adat->ctd.rid = xf->pm.rule_id;
    adat->ctd.aid = xf->nm.sel_aid;
    adat->ctd.smr = CT_SMR_INIT;
    adat->ctd.pi.npmhh = xf->nm.npmhh;
    adat->ctd.pi.pmhh[0] = xf->nm.pmhh[0];
    adat->ctd.pi.pmhh[1] = xf->nm.pmhh[1];
    adat->ctd.pi.pmhh[2] = xf->nm.pmhh[2]; // LLB_MAX_MHOSTS
    adat->ctd.pb.bytes = 0;
    adat->ctd.pb.packets = 0;

    /* Octavia connectionLimit: increment the per-rule live
     * concurrent-connection count on CT-create, SELECTOR-AGNOSTIC. conc_conns lives in the
     * rule-index-keyed nat_ep_map so the teardown path can decrement it by rule id. Only count
     * NAT'd flows (xi->nat_flags) — the same gate the SecurityRate / active_sess dec uses below.
     * This is the SAME live count the connectionLimit gate (dp_do_nat) compares against and the
     * stats active_connections endpoint reads. The (N+1)th SYN is refused BEFORE reaching here
     * (sel=-1 => no NAT => no CT), so it is never counted. */
    if (xi->nat_flags) {
      __u32 cc_key = xf->pm.rule_id;
      struct dp_nat_epacts *ccepa = bpf_map_lookup_elem(&nat_ep_map, &cc_key);
      if (ccepa != NULL) {
#ifndef HAVE_DP_DPU_SLIM
        bpf_spin_lock(&ccepa->lock);
#endif
        ccepa->conc_conns++;
        /* Octavia /stats total_connections ( "++ on CT-create"): cumulative,
         * never decremented, so even a flow that tears down before the next RulesSync tick is
         * still counted. conc_conns (above) is the live gauge; total_conns is the running total. */
        ccepa->total_conns++;
#ifndef HAVE_DP_DPU_SLIM
        bpf_spin_unlock(&ccepa->lock);
#endif
      }
    }

    axdat->ca.ftrap = 0;
    axdat->ca.oaux = 0;
    axdat->ca.cidx = adat->ca.cidx + 1;
    axdat->ca.fwrid = xf->pm.fw_rid;
    axdat->ca.record = xf->pm.dp_rec;
    memset(&axdat->ctd.pi, 0, sizeof(ct_pinf_t));
    if (xxi->nat_flags) { 
      axdat->ca.act_type = xxi->nat_flags & (LLB_NAT_DST|LLB_NAT_HDST) ?
                             DP_SET_DNAT: DP_SET_SNAT;
      DP_XADDR_CP(axdat->nat_act.xip, xxi->nat_xip);
      DP_XADDR_CP(axdat->nat_act.rip, xxi->nat_rip);
      axdat->nat_act.xport = xxi->nat_xport;
      axdat->nat_act.doct = 1;
      axdat->nat_act.rid = xf->pm.rule_id;
      axdat->nat_act.aid = xf->nm.sel_aid;
      axdat->nat_act.nv6 = key.v6 ? 1:0;
      axdat->nat_act.dsr = xf->nm.dsr;
      axdat->nat_act.cdis = xf->nm.cdis;
      axdat->nat_act.nmh = xf->nm.npmhh;
      axdat->nat_act.ppv2 = xf->nm.ppv2;
      /* The rule policer is bidirectional: the reverse direction carries the
       * same polid, so response traffic (arriving on the backend-facing NIC's
       * ingress hook) drains the same bucket as the forward direction. One
       * bucket, one CIR, both directions combined. The explicit write also
       * matters for correctness — adat/axdat are per-CPU scratch reused across
       * packets and this fill is field-by-field (no memset), so an unwritten
       * polid would inherit a stale value from a previously processed flow.
       */
      axdat->nat_act.polid = xf->qm.rpolid;
      axdat->ito = xf->nm.ito;
    } else {
      axdat->ito = 0;
      axdat->ca.act_type = DP_SET_DO_CT;
    }
    axdat->lts = adat->lts;
    axdat->ctd.dir = CT_DIR_OUT;
    axdat->ctd.smr = CT_SMR_INIT;
    axdat->ctd.rid = adat->ctd.rid;
    axdat->ctd.aid = adat->ctd.aid;
    axdat->ctd.nid = adat->ctd.nid;
    axdat->ctd.pi.npmhh = xf->nm.npmhh;
    axdat->ctd.pi.pmhh[0] = xf->nm.pmhh[0];
    axdat->ctd.pi.pmhh[1] = xf->nm.pmhh[1];
    axdat->ctd.pi.pmhh[2] = xf->nm.pmhh[2]; // LLB_MAX_MHOSTS
    axdat->ctd.pb.bytes = 0;
    axdat->ctd.pb.packets = 0;

    axtdat = bpf_map_lookup_elem(&ct_map, &xkey);
    if (axtdat != NULL) {
      LLBS_PPLN_DROPC(xf, LLB_PIPE_CT_ERR);
      return 0;
    }
    bpf_map_update_elem(&ct_map, &xkey, axdat, BPF_ANY);
    bpf_map_update_elem(&ct_map, &key, adat, BPF_ANY);

    atdat = bpf_map_lookup_elem(&ct_map, &key);
    axtdat = bpf_map_lookup_elem(&ct_map, &xkey);
  } else {
    axtdat = bpf_map_lookup_elem(&ct_map, &xkey);
    if (axtdat == NULL) {
      LLBS_PPLN_DROPC(xf, LLB_PIPE_CT_ERR);
      return 0;
    }
  }

  if (atdat != NULL && axtdat != NULL) {
    atdat->lts = bpf_ktime_get_ns();
    axtdat->lts = atdat->lts;
    if (atdat->ctd.dir == CT_DIR_IN) {
      xf->pm.dir = CT_DIR_IN;
      BPF_TRACE_PRINTK("[CTRK] ct in-dir");
      xf->pm.phit |= LLB_DP_CTSI_HIT;
      smr = dp_ct_sm(ctx, xf, atdat, axtdat, CT_DIR_IN);
    } else {
      BPF_TRACE_PRINTK("[CTRK] ct out-dir");
      xf->pm.dir = CT_DIR_OUT;
      xf->pm.phit |= LLB_DP_CTSO_HIT;
      smr = dp_ct_sm(ctx, xf, axtdat, atdat, CT_DIR_OUT);
    }

    BPF_TRACE_PRINTK("[CTRK] ct smr %d", smr);

    if (smr == CT_SMR_EST || smr == CT_SMR_UEST) {
      if (xi->nat_flags) {
        /* One-shot gate: doct starts at 1 (CT creation), cleared here on first EST.
         * Only emit HW offload events on the 1→0 transition to avoid flooding
         * the perf ring on every subsequent packet (critical for UDP which returns
         * CT_SMR_EST on every packet once established). */
        int first_est = atdat->nat_act.doct;
        atdat->nat_act.doct = 0;
        axtdat->nat_act.doct = 0;
        if (atdat->ctd.dir == CT_DIR_IN) {
          dp_ct_est(xf, &key, &xkey, atdat, axtdat);
        } else {
          dp_ct_est(xf, &xkey, &key, axtdat, atdat);
        }
        atdat->ctd.xi.mhon = 0;
        axtdat->ctd.xi.mhon = 0;

        /* Emit HW offload events for BOTH directions (key + xkey) on first EST only.
         * For UDP, EST may fire on DIR_OUT; both DNAT+SNAT need offloading.
         * One-shot: prevents perf ring flooding that kills DOCA worker. */
        if (first_est && !key.v6 &&
            (key.l4proto == IPPROTO_TCP || key.l4proto == IPPROTO_UDP)) {
          struct ll_dp_ct_hwev ev;
          __builtin_memset(&ev, 0, sizeof(ev));
          ev.rcode = LLB_PIPE_RC_HW_UPD;
          ev.rid = atdat->ctd.rid;
          ev.saddr = key.saddr[0];
          ev.daddr = key.daddr[0];
          ev.sport = key.sport;
          ev.dport = key.dport;
          ev.l4proto = key.l4proto;
          bpf_perf_event_output(ctx, &cp_ring,
                                BPF_F_CURRENT_CPU, &ev, sizeof(ev));
          /* Reverse direction so both DNAT+SNAT get offloaded */
          ev.saddr = xkey.saddr[0];
          ev.daddr = xkey.daddr[0];
          ev.sport = xkey.sport;
          ev.dport = xkey.dport;
          bpf_perf_event_output(ctx, &cp_ring,
                                BPF_F_CURRENT_CPU, &ev, sizeof(ev));
        }
      } else {
        /* One-shot gate for non-NAT: act_type transitions from DP_SET_DO_CT to DP_SET_NOP */
        int first_est_nonat = (atdat->ca.act_type != DP_SET_NOP);
        atdat->ca.act_type = DP_SET_NOP;
        axtdat->ca.act_type = DP_SET_NOP;

        /* Emit HW offload event for non-NAT established/uest flows on first EST only. */
        if (first_est_nonat && !key.v6 &&
            (key.l4proto == IPPROTO_TCP || key.l4proto == IPPROTO_UDP)) {
          struct ll_dp_ct_hwev ev;
          __builtin_memset(&ev, 0, sizeof(ev));
          ev.rcode = LLB_PIPE_RC_HW_UPD;
          ev.rid = atdat->ctd.rid;
          ev.saddr = key.saddr[0];
          ev.daddr = key.daddr[0];
          ev.sport = key.sport;
          ev.dport = key.dport;
          ev.l4proto = key.l4proto;
          bpf_perf_event_output(ctx, &cp_ring,
                                BPF_F_CURRENT_CPU, &ev, sizeof(ev));
        }
      }
    } else if (smr == CT_SMR_ERR || smr == CT_SMR_CTD) {
      bpf_map_delete_elem(&ct_map, &xkey);
      bpf_map_delete_elem(&ct_map, &key);
      dp_ct_related_fc_rm(&xkey);
      dp_ct_related_fc_rm(&key); 

      if (atdat->ctd.dir == CT_DIR_IN) {
        dp_ct_ctd(xf, &key, &xkey, atdat, axtdat);
      } else {
        dp_ct_ctd(xf, &xkey, &key, axtdat, atdat);
      }

      if (xi->nat_flags) {
        dp_do_dec_nat_sess(ctx, xf, atdat->ctd.rid, atdat->ctd.aid);

        /* Octavia connectionLimit: decrement the per-rule live
         * concurrent-connection count on CT-teardown, by rule id (atdat->ctd.rid). Pairs with
         * the CT-create increment above. Guarded against underflow so a double-teardown or a
         * pre-existing CT (created before the counter existed) cannot wrap conc_conns. Frees a
         * slot so a previously-refused client can connect. */
        {
          __u32 dc_key = atdat->ctd.rid;
          struct dp_nat_epacts *dcepa = bpf_map_lookup_elem(&nat_ep_map, &dc_key);
          if (dcepa != NULL) {
            /* Octavia /stats cumulative directional bytes: fold this flow's
             * final per-direction byte totals into the rule's running sums at teardown. atdat is
             * the entry being torn down; atdat->ctd.dir says which direction it is, axtdat is its
             * twin. The forward (CT_DIR_IN) CT carries client->VIP request bytes (bytes_in); the
             * reverse (CT_DIR_OUT) carries VIP->client response bytes (bytes_out). NOT a 50/50
             * split. While the flow is live these bytes are surfaced by the live-CT-walk rollup;
             * once it tears down they live here, so the control plane sees no gap and no double
             * count. */
            __u64 fin_bin, fin_bout;
            if (atdat->ctd.dir == CT_DIR_IN) {
              fin_bin = atdat->ctd.pb.bytes;
              fin_bout = axtdat->ctd.pb.bytes;
            } else {
              fin_bin = axtdat->ctd.pb.bytes;
              fin_bout = atdat->ctd.pb.bytes;
            }
#ifndef HAVE_DP_DPU_SLIM
            bpf_spin_lock(&dcepa->lock);
#endif
            if (dcepa->conc_conns > 0) {
              dcepa->conc_conns--;
            }
            dcepa->cum_bytes_in += fin_bin;
            dcepa->cum_bytes_out += fin_bout;
#ifndef HAVE_DP_DPU_SLIM
            bpf_spin_unlock(&dcepa->lock);
#endif
          }
        }
      }
    }
  }

  return smr;
}

