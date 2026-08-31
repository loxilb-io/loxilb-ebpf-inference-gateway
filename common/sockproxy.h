/*
 * Copyright (c) 2024 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */
#ifndef __SOCKPROXY_H__
#define __SOCKPROXY_H__

#include <string.h>  /* strncpy/memset — needed by the static-inline l7_store_header helpers below */
#include <stdint.h>
#include <stdatomic.h>  /* D2 root fix: _Atomic gen stamp on proxy_fd_ent */

#include "llhttp.h"

#define JSMN_STATIC
#include "jsmn.h"

#include "sockproxy_qos.h"  /* Tier-1 byte-shaper config + bucket (proxy_map_ent members) */

// Forward declaration for HTTP/2 support
struct proxy_h2_session;
typedef struct proxy_h2_session proxy_h2_session_t;

// Forward declaration for proxy_arg (defined later, needed for proxy_map_ent)
struct proxy_arg;

// Forward declarations for types from llb_dpapi.h (avoid full include for userspace)
struct llb_sockmap_key;
struct dp_proxy_ct_ent;

#define PROXY_LOCK() pthread_rwlock_wrlock(&proxy_struct->lock)
#define PROXY_RDLOCK() pthread_rwlock_rdlock(&proxy_struct->lock)
#define PROXY_UNLOCK() pthread_rwlock_unlock(&proxy_struct->lock)

#define PROXY_ENT_LOCK(e) pthread_rwlock_wrlock(&e->lock)
#define PROXY_ENT_UNLOCK(e) pthread_rwlock_unlock(&e->lock)
/* D2 root fix (I5 V2): non-blocking acquire — returns 0 on success. Used where a
 * second pfe lock must be taken while already holding a peer pfe lock in a
 * direction that the self-then-peer teardown order can invert (ENT(client)↔
 * ENT(backend) ABBA). A blocking acquire there would close a deadlock cycle; a
 * try-acquire that bails on contention cannot. */
#define PROXY_ENT_TRYLOCK(e) pthread_rwlock_trywrlock(&e->lock)

#define PROXY_ENT_CLOCK(e) pthread_rwlock_wrlock(&e->cache_lock)
#define PROXY_ENT_CUNLOCK(e) pthread_rwlock_unlock(&e->cache_lock)

// ============================================================================
// COMPILE-TIME CONFIGURATION: Buffer Sizes
// ============================================================================
// Override at compile time: make CFLAGS="-DMAX_PREFIX_LEN=1024"
#ifndef MAX_PREFIX_LEN
#define MAX_PREFIX_LEN 512  // LLM prefix extraction buffer (system prompt + user query)
#endif

#ifndef MAX_LORA_LEN
#define MAX_LORA_LEN 128    // LoRA adapter name buffer
#endif

#ifndef MAX_MODEL_LEN
#define MAX_MODEL_LEN 128   // Model name buffer
#endif

#ifndef MAX_HASH_LEN
#define MAX_HASH_LEN 64     // Hash string buffer for multi-modal content
#endif

#ifndef MAX_SALT_LEN
#define MAX_SALT_LEN 64     // Cache isolation salt
#define PD_KV_PARAMS_MAX_LEN 65536  // P/D kv_transfer_params buffer (64KB for real vLLM block_ids)

/* P/D orchestration engine flavor (proxy_epval_t.pd_engine). Values equal
 * the wire kv_engine_type encoding (0=vllm, 1=sglang, 2=trtllm) —
 * the proxy_add stamp goes through pd_engine_from_kv_engine_type()
 * (sockproxy_pd_core.c), these names exist so the orchestration branch reads
 * an orchestration-named constant. Adding an engine = new constant here +
 * mapper/resolver case + (when it diverges) its own dialect ops table. */
#define PD_ENGINE_VLLM   0
#define PD_ENGINE_SGLANG 1
/* TensorRT-LLM disaggregation is sequential ctx-first — a parameterization
 * of the vLLM machine with its own body dialect (sockproxy_pd_trtllm.c:
 * disaggregated_params splice/extract/re-splice + context early exit). */
#define PD_ENGINE_TRTLLM 2

/* SGLang --disaggregation-bootstrap-port default (server_args.py). Applied
 * at proxy_add when the rule leaves pd_bootstrap_port at 0. */
#define PD_SG_BOOTSTRAP_PORT_DFL 8998
#endif

// ============================================================================
// L7 POLICY: generic per-connection header/cookie capture 
// ----------------------------------------------------------------------------
// The l7_policy_evaluate engine (Plan 03/04) needs ANY request header by name
// (and cookies via the captured Cookie header), not just the ~8 named headers
// the handle_header_val cascade retains today. This is a FIXED-CAPACITY store:
// overflow beyond L7_MAX_CAPTURED_HEADERS is dropped (counted), never grown, so
// an attacker cannot inflate the already-large proxy_fd_ent_t (rcvbuf is 1MB)
// via header flooding. Name/value are truncated to the maxes on copy
// (bounded strncpy idiom). Populated on BOTH the H1 (handle_header_val)
// and H2 (proxy_h2_on_header_callback) parse paths for protocol parity.
#ifndef L7_MAX_CAPTURED_HEADERS
#define L7_MAX_CAPTURED_HEADERS 32   // max headers retained per connection (bounded)
#endif
#ifndef L7_HDR_NAME_MAX
#define L7_HDR_NAME_MAX 64           // max stored header-name length (incl NUL)
#endif
#ifndef L7_HDR_VALUE_MAX
#define L7_HDR_VALUE_MAX 256         // max stored header-value length (incl NUL)
#endif
// Octavia: bounded default for timeout_tcp_inspect_ms when unset (0).
// 10s mirrors a conservative HAProxy `timeout http-request` default — long enough not to trip
// legitimate slow clients on the L7_Proxy peer, short enough to bound a slowloris hold. Only
// ever applied when has_l7_policy==1 (the L7 listener); the AI peer is never gated by this.
#ifndef L7_TCP_INSPECT_DEFAULT_MS
#define L7_TCP_INSPECT_DEFAULT_MS 10000
#endif

// ============================================================================
// PROMETHEUS METRICS: Global Stats (Forward Declaration)
// ============================================================================
// Actual definition in sockproxy.c, used by sockproxy_h2.c
typedef struct proxy_global_stats {
    _Atomic uint64_t cache_high_water_triggers;
    _Atomic uint64_t conversation_hits;
    _Atomic uint64_t conversation_misses;
    _Atomic uint64_t h2_total_streams;
    _Atomic uint64_t h2_sessions;
    _Atomic uint64_t chunked_responses;
    _Atomic uint64_t cache_drain_partial;
    _Atomic uint64_t peer_eof_graceful;
    _Atomic uint64_t conversation_ttl_expirations;
    // L7 Metrics: HTTP Response Counters (always compiled, independent of HAVE_HTTP_TRACE)
    _Atomic uint64_t http_responses_total;
    _Atomic uint64_t http_status_2xx;
    _Atomic uint64_t http_status_3xx;
    _Atomic uint64_t http_status_4xx;
    _Atomic uint64_t http_status_5xx;
    // L7 Metrics: TTFB Latency Histogram (C-side buckets)
    // Bucket boundaries: 1ms,5ms,10ms,25ms,50ms,100ms,250ms,500ms,1s,2.5s,5s,10s
    _Atomic uint64_t latency_bucket[12];
    _Atomic uint64_t latency_sum_us;
    _Atomic uint64_t latency_count;
    // P/D Buffer: kv_transfer_params overflow counter
    _Atomic uint64_t pd_kv_params_overflow;
    _Atomic uint64_t pd_fallback_to_normal;  // RES-02: Non-P/D fallback counter
    _Atomic uint64_t pd_cb_flips;            // OBS-03: Circuit breaker state transition count
    _Atomic uint64_t pd_cb_proactive_heal;   // OPEN→HALF_OPEN driven by the 1Hz health pass (no organic traffic)
    // : global total-footprint admission. pd_admission_total_inflight is a
    // GAUGE — incremented once per pfe_alloc (loxilb commits to holding a connection's
    // footprint) and decremented (>0-guarded) once per pfe_recycle, so it is balanced
    // like pfe_pool_live. pd_admission_total_blocked is a COUNTER of accept()s refused
    // by the LLB_PD_MAX_TOTAL_INFLIGHT ingress bound (SYN left in the listen backlog).
    _Atomic uint64_t pd_admission_total_inflight;
    _Atomic uint64_t pd_admission_total_blocked;
    // (KV Tier 1.5 routing diagnostics): per-guard miss counters + fallthrough.
    // Allocated in plan 42-01 (storage only); incremented in plan 42-02 (pd_kv_exact_select guards).
    _Atomic uint64_t pd_kv_t15_miss_mode_off;     // kvExactMode=0 (feature not enabled)
    _Atomic uint64_t pd_kv_t15_miss_warmup;       // warmup grace period suppressing routing
    _Atomic uint64_t pd_kv_t15_miss_text_empty;   // request body text extraction empty
    _Atomic uint64_t pd_kv_t15_miss_model_empty;  // model slug empty / not derivable
    _Atomic uint64_t pd_kv_t15_miss_tokenize;     // tokenizer lookup / tokenization failure
    _Atomic uint64_t pd_kv_t15_miss_hashes;       // block-hash computation produced no hashes
    _Atomic uint64_t pd_kv_t15_miss_no_worker;    // llb_ai_kv_best_worker returned no candidate
    _Atomic uint64_t pd_kv_t15_miss_excluded;     // candidate EP excluded (health / load)
    _Atomic uint64_t pd_kv_t15_miss_shallow;      // best match under the minimum token depth
    // Binding-dataplane contract: gate + typed-bridge miss classes.
    // Same alignment contract as the nine above: C atomic <-> snapshot field
    // (sockproxy_metrics.h) <-> Go CGO mirror + reason label, all in lockstep.
    _Atomic uint64_t pd_kv_t15_miss_not_ready;    // contract word fenced (!eligible) or bridge returned NOT_READY (Go deny set)
    _Atomic uint64_t pd_kv_t15_miss_api_mode;     // request surface excluded by the contract api_mode byte
    _Atomic uint64_t pd_kv_t15_miss_unsupported;  // bridge: excluded feature on a strict rule (request-class, never readiness)
    _Atomic uint64_t pd_kv_t15_miss_runtime_fault;// bridge: profile/renderer/tokenizer/unknown fault on a strict rule
    _Atomic uint64_t pd_kv_t15_fallthrough_total; // Tier 1.5 skipped entirely -> Tier 2 path
    // Failover observability: endpoint-death and failover EVENTS (as detected
    // per connection), distinct from the request-outcome counters in
    // loxilb_ai_pd_requests_total. Zero increments == no failovers happened.
    _Atomic uint64_t pd_prefill_ep_died;        // prefill backend died mid-request (client got 503)
    _Atomic uint64_t pd_decode_ep_died;         // decode EP failure: init-connect failure or zero-byte EOF
    _Atomic uint64_t pd_decode_zero_byte_eof;   // decode EOF with ZERO response bytes relayed (subset of above)
    _Atomic uint64_t pd_connect_failover;       // prefill connect retry against another EP succeeded
    _Atomic uint64_t lb_select_failure_shutdown; // non-P/D: selection/connect failed -> raw shutdown, no HTTP error
    // SGLang P/D dual-dispatch observability (mirrors the failover family above)
    _Atomic uint64_t pd_sg_prefill_abort_decode; // prefill drain-leg failure forced a decode-leg abort
    _Atomic uint64_t pd_sg_decode_close_drain;   // decode-leg failure closed the prefill drain leg
    _Atomic uint64_t pd_sg_room_retry;           // dual dispatch retried as a pair with a fresh room
    _Atomic uint64_t pd_sg_prefill_reject_relay; // prefill 4xx relayed to the client verbatim (origin-computed client error, not an EP fault)
    _Atomic uint64_t pd_sg_oversize_reject;      // streamable body on an SGLang disagg rule refused fail-closed (503, no backend bytes)
    // TRT-LLM sequential-dialect observability
    _Atomic uint64_t pd_trt_ctx_early_exit;      // context response finished the request — decode leg skipped, buffered response relayed
    //: per-stage hot-path µs histograms. One 12-bucket histogram
    // per (stage, outcome) — stage in {TOKENIZE,HASH,CGO,SCAN} (sockproxy_kv_exact.h),
    // outcome in {miss=0, hit=1}. Bucket bounds reuse latency_bucket_bounds_us so the
    // "must match Go CGO bucketBounds" parity comment (below) holds for these too.
    // Off-path accumulation only (atomic_fetch_add, mirror of record_latency_sample);
    // populated by record_kv_stage from the flag-gated stage timers in pd_kv_exact_select.
    // NOTE: dimensions are literal (4 stages × 2 outcomes × 12 buckets) to avoid a
    // sockproxy_kv_exact.h include cycle in this core header; kept in lockstep with the
    // KV_N_STAGES / KV_N_STAGE_OUTCOMES / KV_STAGE_N_BUCKETS enum there (asserted below).
    _Atomic uint64_t kv_stage_buckets[4][2][12];
    _Atomic uint64_t kv_stage_sum_us[4][2];
    _Atomic uint64_t kv_stage_count[4][2];
#ifdef HAVE_PII_DETECTION
    // PII Detection metrics (atomic for thread-safety)
    _Atomic uint64_t pii_requests_scanned;
    _Atomic uint64_t pii_entities_detected;
    _Atomic uint64_t pii_requests_masked;
    _Atomic uint64_t pii_scan_errors;
    _Atomic uint64_t pii_scan_timeouts;
    _Atomic uint64_t pii_bytes_scanned;
    _Atomic uint64_t pii_bytes_masked;
#endif
#ifdef HAVE_LLAMAFIREWALL
    // LlamaFirewall AI Security metrics (atomic for thread-safety)
    _Atomic uint64_t llamafirewall_requests_scanned;
    _Atomic uint64_t llamafirewall_threats_detected;
    _Atomic uint64_t llamafirewall_requests_blocked;
    _Atomic uint64_t llamafirewall_scan_errors;
    _Atomic uint64_t llamafirewall_scan_timeouts;
    _Atomic uint64_t llamafirewall_bytes_scanned;
    _Atomic uint64_t llamafirewall_prompt_guard_detections;
    _Atomic uint64_t llamafirewall_code_shield_detections;
#endif
#ifdef HAVE_MTLS
    // mTLS metrics 
    _Atomic uint64_t mtls_frontend_verify_success;   // Successful client cert verifications
    _Atomic uint64_t mtls_frontend_verify_failures;  // Failed client cert verifications
    _Atomic uint64_t mtls_backend_verify_success;    // Successful backend cert verifications
    _Atomic uint64_t mtls_backend_verify_failures;   // Failed backend cert verifications
    _Atomic uint64_t mtls_rate_limited;              // Connections blocked by mTLS rate limiting
    _Atomic uint64_t mtls_hostname_mismatch;         // CN/SAN validation failures
#endif
} proxy_global_stats_t;

extern proxy_global_stats_t global_stats;

// ============================================================================
// DEEP INSPECTION: Catalog Management API
// ============================================================================
// Set catalog ID for a service (simple direct API, no eBPF complexity)
int proxy_set_service_catalog(uint32_t xip, uint16_t xport, uint8_t protocol, uint16_t catalog_id);


// Define MAX_PROXY_EP early for CHWBL structures
// Synced with LLB_MAX_NXFRMS from llb_dpapi.h
#ifndef MAX_PROXY_EP
#define MAX_PROXY_EP 32
#endif

// bounded backpressured admission — per-EP parked-request FIFO.
// PD_MAX_QUEUE_DEPTH is the COMPILE cap (ring capacity); the RUNTIME bound is
// LLB_PD_QUEUE_DEPTH_PER_EP (<= PD_MAX_QUEUE_DEPTH; 0/unset = feature off).
#ifndef PD_MAX_QUEUE_DEPTH
#define PD_MAX_QUEUE_DEPTH 64
#endif

/* A single parked client. We store (fd, gen) — NOT a pfe pointer — so dequeue
 * re-resolves the pfe and validates pfe->gen == gen (Phase-89 staleness
 * guard): a recycled fd yields a gen mismatch and the entry is dropped safely.
 * enqueue_ns feeds the max-park reap (LLB_PD_MAX_PARK_SEC). */
typedef struct {
  int      fd;          /* parked client fd */
  uint64_t gen;         /* pfe->gen snapshot at enqueue — staleness guard on dequeue */
  uint64_t enqueue_ns;  /* CLOCK_MONOTONIC stamp — for the max-park reap */
} pd_parked_ent_t;

/* One bounded ring per prefill EP. head/tail/count index slot[]; the whole
 * struct is untouched (never scanned/enqueued) when the runtime knob is 0,
 * preserving the default-off byte-identical invariant. */
typedef struct {
  pd_parked_ent_t slot[PD_MAX_QUEUE_DEPTH];
  uint16_t head;   /* dequeue index (oldest) */
  uint16_t tail;   /* enqueue index (next free) */
  uint16_t count;  /* live entries (O(1) depth) */
} pd_parked_fifo_t;

// ============================================================================
// PHASE 1: Dynamic Prefix Hash Configuration Flags
// ============================================================================
#define PREFIX_HAS_LORA          (1 << 0)  // LoRA adapter present
#define PREFIX_HAS_IMAGE         (1 << 1)  // Image content hash present
#define PREFIX_HAS_AUDIO         (1 << 2)  // Audio content hash present
#define PREFIX_HAS_CACHE_SALT    (1 << 3)  // Cache isolation salt present
#define PREFIX_HAS_TOOL_SCHEMAS  (1 << 4)  // Tool definitions hash present
#define PREFIX_HAS_SESSION_CTX   (1 << 5)  // Session context hash (Level 2)
#define PREFIX_HAS_RAG_TEMPLATE  (1 << 6)  // RAG template hash (Level 3)
#define PREFIX_HAS_RAG_DOC_IDS   (1 << 7)  // RAG document IDs hash (Level 3)

/**
 * LLM Prefix Key Structure -: Dynamic Multi-Level Prefix Hashing
 *
 * Supports 3-level tiered prefix boundaries:
 *   Level 1 (Global): System prompt, model, optional multi-modal/LoRA/salt
 *   Level 2 (Session): Session context summary (optional)
 *   Level 3 (RAG): RAG template + document IDs (optional)
 */
typedef struct llm_prefix_key {
  // LEVEL 1: Global Prefix (always included)
  char prefix[MAX_PREFIX_LEN];        // System prompt (normalized)
  char model[MAX_MODEL_LEN];          // Model identifier
  
  // Optional fields (conditionally hashed based on flags)
  uint32_t flags;                     // Bitfield: which optional fields present
  
  char lora_adapter[MAX_LORA_LEN];    // LoRA adapter name
  char image_hash[MAX_HASH_LEN];      // Image content hash (vision models)
  char audio_hash[MAX_HASH_LEN];      // Audio content hash (audio models)
  char cache_salt[MAX_SALT_LEN];      // Cache isolation salt (multi-tenant)
  char tool_schemas_hash[MAX_HASH_LEN]; // Tool definitions hash
  
  // LEVEL 2: Session Context (optional)
  char session_context_hash[MAX_HASH_LEN];  // Summarized conversation history
  
  // LEVEL 3: RAG Context (optional)
  char rag_template_hash[MAX_HASH_LEN];     // RAG template/header
  char rag_doc_ids_hash[MAX_HASH_LEN];      // Sorted document IDs
  
  // Computed Results
  uint64_t hash;   // Final computed hash
  int valid;       // 1 if extraction succeeded, 0 otherwise
  int level;       // Hash level: 1 (global), 2 (session), 3 (RAG)
} llm_prefix_key_t;

#define MAX_CONV_ID_LEN 128

// P1.2: Virtual node in consistent hash ring
typedef struct chwbl_vnode {
  uint64_t hash;        // Hash value for this virtual node
  int ep_idx;           // Physical endpoint index (0 to n_eps-1)
} chwbl_vnode_t;

// P1.2: Consistent hash ring
typedef struct chwbl_ring {
  int replication;      // Virtual nodes per physical endpoint
  int n_vnodes;         // Total virtual nodes (n_eps × replication)
  int n_eps;            // Number of physical endpoints
  chwbl_vnode_t *vnodes; // Sorted array of virtual nodes
  pthread_rwlock_t lock; // Reader-writer lock for concurrent access
} chwbl_ring_t;

// P1.3: Load tracking per endpoint
typedef struct ep_load_tracker {
  _Atomic uint32_t active_conns;  // Current active connections
  _Atomic uint32_t queued_requests; // COMP-07: From vLLM metrics scraper (num_requests_waiting)
  _Atomic uint64_t total_requests; // Total requests routed
  // H-17 (metrics audit): CLOCK_MONOTONIC seconds of the last scraper update
  // for queued_requests (stamped by llb_ai_update_ep_queue_depth; 0 = scraper
  // never reported). Scorers treat entries older than PD_QUEUE_STALE_SEC as
  // unknown instead of trusting a dead EP's last value forever.
  _Atomic uint64_t last_update_ts;
  int ep_available;                 // Endpoint health flag
  // vLLM-advertised KV capacity (cache_config_info num_gpu_blocks),
  // fed by llb_ai_update_ep_capacity (mirrors the queue-depth bridge). Consumed
  // by pd_select_prefill's capacity-weighted bounded-load scorer (the reserved
  // PROXY_SEL_GPU_AWARE weights lit up). 0 = not advertised (clamped to 1 by
  // pd_kv_clamp_capacity before any divide — V5 guard, never divide-by-zero).
  _Atomic uint32_t num_gpu_blocks;
  // swap-space pressure signal for the SWAP_WEIGHT term (0 when the
  // scraper does not advertise it — the SWAP term then contributes nothing).
  _Atomic uint32_t swap_pressure;
} ep_load_tracker_t;

/* Radix trie for cache-aware prefill EP selection (Tier 1) */
typedef struct pd_trie pd_trie_t;

// P1.3: CHWBL configuration
typedef struct chwbl_config {
  int mean_load_factor;      // Max load = average × this factor (default: 125)
  int prefix_char_length;    // Prefix extraction length (unused for now)
  int replication;           // Virtual nodes per endpoint (default: 256)
  ep_load_tracker_t ep_loads[MAX_PROXY_EP];
  
  // PHASE 1: Dynamic Prefix Hash Configuration
  uint32_t prefix_hash_level;    // 1=L1 only (default), 2=L1+L2, 3=L1+L2+L3
  uint32_t prefix_hash_flags;    // Which optional fields to include (0=auto-detect)
  uint8_t enable_cache_salt;     // 1=require cache_salt, 0=optional (default: 0)
} chwbl_config_t;

typedef struct conversation_mapping {
  char conv_id[MAX_CONV_ID_LEN];
  int ep_idx;
  uint64_t created_ts;
  uint64_t last_access_ts;
  uint32_t request_count;
  // Smart validation tracking - per-endpoint version-based caching
  uint64_t cached_metrics_version;  // Endpoint's metrics_version when last validated
  uint8_t validated_healthy;        // 1 = validated healthy at cached_metrics_version, 0 = not validated
  UT_hash_handle hh;
} conversation_mapping_t;

// P/D Session stickiness: pins multi-turn conversations to same (prefill, decode) EP pair
typedef struct pd_session_mapping {
  char     conv_id[MAX_CONV_ID_LEN];  // hash key (conv_id or user_id)
  int      prefill_ep_idx;
  int      decode_ep_idx;
  uint64_t created_ts;
  _Atomic uint64_t last_access_ts;    // atomic for benign rdlock update
  uint32_t request_count;
  UT_hash_handle hh;
} pd_session_mapping_t;

// P2: Draining policy types
typedef enum {
  DRAIN_POLICY_GRACEFUL,   // Never force-close (default) - connections drain naturally
  DRAIN_POLICY_TIMED,      // Force-close after timeout
  DRAIN_POLICY_IMMEDIATE   // Force-close immediately (emergency maintenance)
} drain_policy_t;

// P2: Draining state per endpoint
typedef struct ep_drain_state {
  uint8_t is_draining;           // 1 = draining in progress, 0 = not draining
  time_t drain_start_ts;         // Timestamp when draining started (seconds since epoch)
  uint32_t active_conns_at_start; // Connection count when draining started (for logging)
} ep_drain_state_t;

// P2 Task 2.3: Circuit breaker states
typedef enum {
  CB_STATE_CLOSED,      // Normal operation - allow traffic
  CB_STATE_OPEN,        // Rejecting traffic - too many failures
  CB_STATE_HALF_OPEN    // Testing recovery - limited traffic
} circuit_breaker_state_t;

// P2 Task 2.3: Circuit breaker per endpoint
typedef struct circuit_breaker {
  circuit_breaker_state_t state;   // Current circuit state
  uint32_t failure_count;          // Consecutive failures in CLOSED state
  uint32_t success_count;          // Successes in HALF_OPEN state
  time_t last_failure_ts;          // Timestamp of last failure
  time_t open_ts;                  // When circuit opened (for timeout)
  
  // Configuration
  uint32_t failure_threshold;      // Default: 5 consecutive failures to open
  uint32_t success_threshold;      // Default: 2 successes in HALF_OPEN to close
  uint32_t open_timeout_sec;       // Default: 30 seconds before HALF_OPEN
  uint32_t half_open_max_requests; // Default: 3 test requests in HALF_OPEN
  uint32_t half_open_requests;     // Current request count in HALF_OPEN

  /* Origin-error demotion. failure_count only sees CONNECT-level faults and
   * is reset by every connect success, so an EP that accepts TCP but keeps
   * answering HTTP 5xx never trips the breaker — warm KV affinity then
   * re-pins it indefinitely. This streak is touched ONLY by origin response
   * statuses (5xx increments, <400 resets), so connect successes cannot
   * defeat it; at the threshold the breaker opens through the same trip
   * actions (trie removal, parked drain, selection/affinity skip). */
  uint32_t origin_err_streak;      // Consecutive origin 5xx responses
  /* Set when the breaker OPENED on the origin streak (vs a connect fault).
   * While set, a HALF_OPEN connect success must NOT close the breaker —
   * the EP accepts TCP fine, that is exactly why it tripped; only an origin
   * success (status < 400) closes it. Cleared on that close. Without this,
   * every heal cycle instantly re-closed on the probe's CONNECT success and
   * clients ate another full 5xx streak per cycle, forever. */
  uint8_t  origin_tripped;         // 1 = OPENed by origin streak, not connect
} circuit_breaker_t;

// ============================================================================
// global-AI-controller advisory per-EP instruction word.
//
// One packed _Atomic uint32_t per EP (proxy_epval_t.pd_ctrl_ep[]):
//   bits 31-24 = state (PD_CTRL_ST_*), bits 7-0 = weight [0,100],
//   bits 23-8 reserved (0). packed == 0 => NO instruction => every guard skips.
// State values MUST stay in lockstep with the frozen loxilb.aictrl.v1 EpState
// enum (pkg/aictrl): 1=ACTIVE, 2=DRAINING, 3=DISABLED, 0=none.
// ============================================================================
#ifndef PD_CTRL_ST_NONE
#define PD_CTRL_ST_NONE     0  /* no instruction (zero-init / cleared)          */
#define PD_CTRL_ST_ACTIVE   1  /* serve normally (weight may still scale)      */
#define PD_CTRL_ST_DRAINING 2  /* exclude from NEW-session assignment only     */
#define PD_CTRL_ST_DISABLED 3  /* fold into excluded_mask (all tiers)          */
/* Accessors for the packed word. */
#define PD_CTRL_STATE(p)  (((p) >> 24) & 0xff)
#define PD_CTRL_WEIGHT(p) ((p) & 0xff)
#endif

// ============================================================================
// Proxy Endpoint Statistics & Management
// ============================================================================
typedef struct proxy_epstat {
  uint64_t nrb;  // Number of bytes received
  uint64_t nrp;  // Number of packets received
  uint64_t ntb;  // Number of bytes transmitted
  uint64_t ntp;  // Number of packets transmitted
} proxy_epstat_t;

// Proxy endpoint entry - backend server address
typedef struct proxy_ent {
  uint32_t xip;
  uint16_t xport;
  uint8_t inv;
  uint8_t protocol;
  uint8_t weight;      // P3: Weight for WRR (1-100, 0=default to 1)
  uint8_t pad;         // Explicit alignment pad
  uint16_t nixl_port;  // NIXL side-channel port; 0=use xport
} proxy_ent_t;

/* kv_exact_mode value for the Tier-1.5 single-role decouple
 * seam. Mode 1 (zmq, P/D) semantics are untouched byte-for-byte; value 2 stays
 * reserved for NATS (RESEARCH Pitfall 6) — single-role deliberately takes 3.
 * Twin-defined idempotently in sockproxy_kv_exact.c for the TEST_KV_EXACT
 * single-TU unit build (the PD_CTRL_ST_* precedent). */
#define KV_EXACT_MODE_SINGLE_ROLE 3

/* P/D engine-dialect ops table — full definition in sockproxy_pd.h; the epval
 * only carries the resolved pointer. */
struct pd_dialect_ops;

// Proxy endpoint value - manages endpoint pool for a service
typedef struct proxy_epval {
  char host_url[256];
  uint32_t _id;
  int main_fd;
  int n_eps;
  int ep_sel;
  int select;
  proxy_ent_t eps[MAX_PROXY_EP];
  proxy_epstat_t ep_stats[MAX_PROXY_EP];
  
  // P1.2/P1.3: CHWBL support
  chwbl_ring_t *hash_ring;      // Consistent hash ring (NULL if not CHWBL mode)
  chwbl_config_t *chwbl_config; // CHWBL configuration & load tracking
  
  // P2: Draining support
  ep_drain_state_t drain_state[MAX_PROXY_EP]; // Draining state per endpoint
  drain_policy_t drain_policy;                // Draining policy for this service
  uint32_t drain_timeout_sec;                 // Timeout for timed draining (default: 60)
  
  // P2 Task 2.3: Circuit breaker support
  circuit_breaker_t circuit_breakers[MAX_PROXY_EP]; // Circuit breaker per endpoint
  uint8_t cb_enabled;                               // 1 = enabled, 0 = disabled
  
  // P3: WRR support (Weighted Round-Robin)
  int wrr_current_weights[MAX_PROXY_EP];  // Current weight counters for smooth WRR
  int wrr_gcd;                             // GCD of all endpoint weights
  int wrr_max_weight;                      // Maximum weight value
  uint8_t wrr_initialized;                 // 1 = WRR state initialized, 0 = not
  uint8_t pad_wrr[3];                      // Padding for alignment
  
  // P6: Host + Path Prefix Routing - composite key storage
  char ephash_key[512];  // Composite key: "host|path" or "host" (backward compat)
  
  // Custom header-based session stickiness configuration
  char session_header_name[128];  // e.g., "mcp-session-id", "x-session-token", "authorization"
  uint8_t session_header_enabled;  // 1=enabled, 0=disabled (use IP-based)

  // SSE (Server-Sent Events) streaming configuration per service rule
  uint8_t  sse_mode;                // 1=SSE mode enabled, 0=disabled
  uint32_t max_stream_duration_sec; // Absolute wall-clock cap for streams (0=use hard cap)
  uint32_t backend_keepalive_sec;   // Backend SO_KEEPALIVE+TCP_KEEPIDLE interval (0=disabled)
  uint32_t inactive_timeout_sec;    // Per-rule idle timeout in seconds (0=disabled); suppressed when sse_active=1

  // P/D Disaggregation configuration
  uint8_t  pd_disagg_enabled;       // 1=P/D mode enabled for this service
  uint8_t  ai_gw_mode;             // 1=AI Gateway mode (auto-derived)
  uint8_t  apikey_auth;            // 0=unset, 1=required, 2=declared disabled (per-service policy, NOT derived)
  /* P/D orchestration engine flavor. Stamped at proxy_add FROM the rule's
   * kv_engine_type (0=vllm ⇒ PD_ENGINE_VLLM, 1=sglang ⇒ PD_ENGINE_SGLANG,
   * 2=trtllm ⇒ PD_ENGINE_TRTLLM) so the orchestration branch never reads a
   * KV-named field. vLLM keeps the sequential prefill→decode state machine
   * (TRT-LLM rides it with its own body dialect); SGLang selects the
   * concurrent dual-dispatch machine (bootstrap triple injection, prefill
   * drain leg). */
  uint8_t  pd_engine;
  /* SGLang bootstrap port on every prefill EP; the decode engine rendezvouses
   * with prefill on it. 0 is defaulted to PD_SG_BOOTSTRAP_PORT_DFL at
   * proxy_add, so readers can trust it non-zero when pd_engine==SGLANG. */
  uint16_t pd_bootstrap_port;
  /* Dialect ops table (sockproxy_pd.h), resolved from pd_engine at the same
   * proxy_add sites that stamp it — never NULL once the rule is live, so the
   * request path calls through it without re-deriving the engine. */
  const struct pd_dialect_ops *pd_ops;
  uint8_t  ep_role[MAX_PROXY_EP];  // Per-endpoint role: 0=normal, 1=prefill, 2=decode
  int      n_prefill_eps;          // Count of prefill endpoints
  int      n_decode_eps;           // Count of decode endpoints
  // P/D timeout configuration
  uint32_t pd_prefill_timeout_sec;  // Prefill response timeout (0 = default 30s)
  uint32_t pd_decode_timeout_sec;   /* decode stream timeout (0 = use 120s default) */
  uint32_t pd_idle_cap_sec;         /* generic ESTABLISHED-idle P/D reaper cap
                                       (0 = default max(prefill,decode)+slack) */
  uint32_t pd_decode_idle_cap_sec;  /* backend-idle window before a decode-streaming SSE
                                       conn is gracefully completed with a synthesized [DONE]
                                       (0 = PROXY_PD_DECODE_IDLE_CAP_SEC default ~25s) */

  // P/D Cache-Aware Routing configuration (US-PD801)
  uint16_t pd_kv_params_max;             // Runtime KV params buffer limit (0 = use PD_KV_PARAMS_MAX_LEN)
  uint8_t  pd_cache_aware_mode;        // 0=disabled, 1=enabled (requires pd_disagg_enabled)
  uint8_t  pd_cache_threshold;         // 0-100, default 20
  uint8_t  pd_balance_abs_threshold;   // default 3
  _Atomic uint32_t pd_tier2_rr;       // RR tie-breaker for Tier 2 min-load
  _Atomic uint32_t pd_decode_rr;      // RR tie-breaker for decode EP tie-breaking (P2 fix: TB3/TB4)
  uint32_t pd_session_ttl_sec;         // session TTL in seconds, 0=no expiry
  ep_load_tracker_t pd_ep_loads[MAX_PROXY_EP]; // independent of chwbl_config_t

  /* global-controller advisory influence. Packed per-EP atomic:
   * state bits 31-24 (PD_CTRL_ST_*), weight bits 7-0 [0,100]. Zero-init (this
   * struct is calloc'd at proxy_add — sockproxy_http.c:1891/:2270) == mode 0 ==
   * controller absent == BYTE-IDENTICAL Phase-95 selection (G3). Written ONLY by
   * llb_ai_ctrl_update_ep / llb_ai_ctrl_set_mode (the Go applier's CGO bridge,
   * sockproxy_metrics.c); read lock-free via atomic_load in pd_select_prefill.
   * _Atomic from the first commit (TD-1/TD-2 plain-int race debt must not grow).
   * No pointer swaps, nothing to free — the Phase-89/90/93 UAF class is
   * structurally excluded. KNOWN LIMIT: MAX_PROXY_EP == 32 caps the addressable
   * EP set (per REQUIREMENTS Out of Scope — flagged, NOT fixed this phase). */
  _Atomic uint32_t pd_ctrl_ep[MAX_PROXY_EP];
  _Atomic uint8_t  pd_ctrl_mode;      /* 0 = absent/autonomous (skip ALL controller work) */

  /* bounded backpressured admission. One parked-request FIFO per
   * prefill EP; pd_parked_lock guards ALL per-EP FIFOs (coarse but the enqueue
   * path is off the hot dispatch path — it only runs when every prefill EP is
   * already at the in-flight cap). Initialized alongside pd_session_lock /
   * pd_trie_lock at proxy_add (sockproxy_http.c). When LLB_PD_QUEUE_DEPTH_PER_EP
   * is 0/unset nothing here is ever touched (default-off byte-identical). */
  pd_parked_fifo_t      pd_parked[MAX_PROXY_EP];
  pthread_mutex_t       pd_parked_lock;

  /* per-service radix trie for Tier 1 cache affinity */
  pd_trie_t           *pd_trie;          /* NULL when pd_cache_aware_mode=0 */
  pthread_rwlock_t     pd_trie_lock;     /* Lock order: pd_session_lock BEFORE pd_trie_lock */

  // P/D Session stickiness table (Tier 0 cache-aware routing)
  pd_session_mapping_t *pd_session_map;    // P/D session table (NULL initially)
  pthread_rwlock_t      pd_session_lock;   // separate from conv_lock

  // KV-Cache Exact Routing (Tier 1.5)
  uint8_t  kv_exact_mode;        // 0=off, 1=zmq(P/D), 2=nats(reserved), 3=zmq single-role 
  uint8_t  kv_hash_algo;         // 0=sha256_cbor, 1=xxhash_cbor
  uint16_t kv_zmq_port;          // ZMQ PUB port per EP (default 5557)
  uint32_t kv_block_size;        // Token block size for hashing (default 16)
  uint32_t kv_warmup_sec;        // Seconds to skip Tier 1.5 after subscriber start
  /* A1 finding (verified 2026-07-12): kv_warmup_start has NO
   * production writer — only test_kv_exact.c stamps it (the CGO bridge and Go
   * subscriber never do; dpebpf_linux.go fills kv_warmup_sec only). GUARD_B
   * (sockproxy_kv_exact.c) therefore never fires in production: kvWarmupSec is
   * equally INERT on BOTH the P/D (mode 1) and single-role (mode 3) paths.
 * Deliberately NOT stamped in — stamping now would change shipped
 * vLLM P/D behavior (byte-identical discipline). */
  time_t   kv_warmup_start;      // Timestamp when ZMQ subscriber connected (runtime; never set in production — see A1 note)
  // (SGL-03): per-rule KV engine + SGLang DP rank count.
  // Copied field-for-field at proxy_add_entry alongside the five kv_* fields above.
  uint8_t  kv_engine_type;       // 0=vllm (default), 1=sglang, 2=trtllm
  uint8_t  kv_dp_rank_count;     // SGLang DP ranks (1..8; 0 defaulted to 1 at the CGO fill)
  /* (SGL-04, RESEARCH Pitfall 2): the calling rule's identity for the
   * Tier-1.5 Go selector. Threaded through llb_ai_kv_best_worker so the Go side
   * scores ONLY this rule's inventories — without it two same-model VIPs can
   * cross-match content and return an epIdx valid in the WRONG rule's EP space
   * (the cross-VIP contamination seam). Stamped at proxy_add_entry from
   * arg->_id, which already carries the rule number end-to-end (Open Q1
   * resolved: Go r.ruleNum -> dp_proxy_tacts.ca.cidx -> llb_conv_nat2proxy
   * pval->_id -> here); no new dp-cfg twin is needed. LB rule markers allocate
   * from 1 (rules.go NewMarker(1, ...)), so 0 unambiguously means "no
   * identity" and the Go side keeps today's all-services loop — the seam is
 * independently default-off (kv_weight twin-lockstep precedent). */
  uint32_t kv_svc_id;            // calling rule identity for the Go selector (0 = no identity)

  /* Binding-dataplane contract word:
   *   [ binding_gen:32 | flags:16 | api_mode:8 | eligible:8 ]
   * Written ONLY by proxy_update_kv_exact_contract (single-writer; the Go
   * control plane's fence-first transactions), read once per request with
   * acquire semantics in pd_kv_exact_select before tokenize. Zero means "no
   * contract installed" — the legacy passthrough (binding_gen 0 is reserved,
   * so an installed word is never zero even while fenced). Deliberately NOT
   * copied at proxy_add_entry: an entry rebuild starts legacy/ineligible and
   * the control plane re-installs after ACK; the Go-side per-svc_id deny set
   * fences the strict rule across that window (plan-fix I-14 backstop). */
  _Atomic uint64_t kv_exact_contract;

  UT_hash_handle hh;
} proxy_epval_t;

// Proxy value - contains per-proxy state
typedef struct proxy_val {
  int proxy_mode;
  int main_fd;
  int have_ssl;
  int have_epssl;
  int ppv2;             /* PROXY protocol v2 emission on backend conns (L7 fullproxy) */
  int sched_free;
  void *ssl_ctx;
  void *ssl_epctx;
  uint32_t nfds;
  struct proxy_epval *ephash;
  struct proxy_fd_ent *fdlist;
  conversation_mapping_t *conv_map;  // Conversation tracking (P0.3)
  pthread_rwlock_t conv_lock;        // Lock for conv_map (P0.3)
  
  // Backend protocol capability (prevents client/backend protocol mismatch)
  // 0 = HTTP/1.1 only (default, safest)
  // 1 = HTTP/2 only
  // 2 = Both HTTP/1.1 and HTTP/2 (backend auto-negotiates)
  uint8_t backend_protocol_cap;
} proxy_val_t;

// Proxy map entry - combines key and value
typedef struct proxy_map_ent {
  struct proxy_ent key;
  struct proxy_val val;
  struct proxy_map_ent *next;
  
  // Deep Inspection: Catalog ID for this service (0=disabled, 1-255=catalog ID)
  uint16_t catalog_id;
  
  // Memory management: Track heap-allocated proxy_arg for cleanup
  // - mTLS mode: OpenSSL auto-frees via callback (this is backup)
  // - Non-mTLS HTTPS: Manual free needed to prevent leak
  // - NULL if stack-allocated (old code paths)
  struct proxy_arg *arg_ptr;

  // L7 content-routing policy discriminator (CONTEXT).
  // These live on the per-service proxy_map_ent (the heap struct), NEVER on
  // proxy_arg (the 4096-byte eBPF map value — its _Static_assert stays untouched,
  // ). DECLARED here by Plan (the first reader: l7_route_dispatch reads
  // has_l7_policy and, when set, runs the L7 engine over l7_routes); POPULATED by
  // Plan an earlier cycle's proxy_attach_l7_policy (deep-copies the position-sorted route
  // array, regcomp's each REGEX once, sets has_l7_policy=1).
  //
  // When has_l7_policy == 0 (the default for every AI/model service) the L7
  // dispatch is a pure no-op and the AI path runs byte-for-byte unchanged
  // (Pitfall 5). l7_routes is an opaque pointer here (void *) to keep
  // sockproxy.h free of the l7policy IR dependency; sockproxy_l7policy.c casts it
  // to (const l7_route_t *) before calling l7_policy_evaluate.
  uint8_t has_l7_policy;            // 1 => an L7_POLICY is attached ( discriminator)
  void   *l7_routes;                // ordered l7_route_t[] (opaque here; cast in the engine)
  int     n_l7_routes;              // number of routes in l7_routes

  // (gap-fix): scratch "resolved sub-pool" used by l7_resolve_pool to
  // forward a matched L7 route to a SPECIFIC subset of the service's endpoints
  // (the route's backendRefs[].ep, honoring weights) instead of the whole pool.
  // It is a struct proxy_epval (allocated lazily at first FORWARD on this service)
  // whose eps[]/n_eps are narrowed from the base pool (val.ephash) per FORWARD.
  // The proxy hot path is single-threaded (one proxy_run event-loop thread), and
  // each request fully consumes this scratch (connects to the chosen endpoint)
  // synchronously before the next is routed, so a single reusable buffer is safe
  // (mirrors the existing tepval->ep_sel single-threaded mutation in ep.c). It is
  // an opaque void* here to keep sockproxy.h free of any forward dependency; the
  // engine TU casts it to (proxy_epval_t *). Freed by proxy_detach_l7_policy and
  // when the proxy_map_ent is torn down.
  void   *l7_resolved_pool;         // struct proxy_epval * scratch (opaque here)

  // L7 (Tier-1) byte shaper. Config + runtime bucket live HERE on the heap
  // proxy_map_ent (per-service state), never on proxy_arg (the 4096-byte eBPF
  // map value). qos_cfg.cir_Bps == 0 means the shaper is off and the relay
  // path is byte-for-byte today's behaviour. Meters PLAINTEXT payload bytes;
  // the Tier-0 eBPF policer meters L3 wire bytes — different units, never
  // comparable. qos_up shapes client->backend reads (qos_cfg.dir bit 0);
  // qos_down shapes backend->client reads (bit 1). The buckets are
  // independent: each direction gets its own CIR, they never share tokens.
  struct proxy_qos_cfg    qos_cfg;
  struct proxy_qos_bucket qos_up;
  struct proxy_qos_bucket qos_down;
} proxy_map_ent_t;

// ============================================================================
// SNI-Based Multi-Certificate Support (GLOBAL CERTIFICATE STORE)
// ============================================================================
/**
 * Global SSL certificate entry - independent of loadbalancer rules
 * Multiple loadbalancer rules can share the same certificate by hostname
 * 
 * Design:
 *   - One global hash map: hostname → SSL_CTX
 *   - Loadbalancer rules reference certificates by hostname (not by IP:Port)
 *   - During TLS handshake, SNI callback looks up certificate by requested hostname
 *   - Multiple proxies can share the same certificate (e.g., api.example.com)
 */
typedef struct ssl_cert_entry {
  char hostname[256];          // Hostname (e.g., "api.example.com")
  char cert_path[256];         // Certificate path (e.g., "/opt/loxilb/cert/hostname" or custom path)
  void *ssl_ctx;              // Dedicated SSL context for this hostname (SSL_CTX*)
  int ref_count;              // Reference count (how many proxies use this cert)
  time_t loaded_ts;           // When certificate was loaded
  UT_hash_handle hh;          // uthash handle for global hash table
} ssl_cert_entry_t;

// the certId registry is the canonical management
// handle for TLS material, LAYERED OVER the hostname-keyed SNI store above. The
// SNI callback still SELECTS by hostname at handshake (selection path unchanged,
// ); certId is purely the upload/rotate/delete handle. On register, the
// material is persisted to a managed dir (/etc/loxilb/certs/<certId>/),
// hostnames are auto-derived from the cert SAN/CN, and EACH derived
// hostname is registered into the SNI store via the EXISTING
// proxy_add_sni_certificate (no new SNI loader). The certId is also referenced by
// proxy_arg.backend_*_cert_id for backend re-encryption material.
#define CERTID_MAX_HOSTNAMES 8
// max length of an opaque certId management token.
// proxy_arg references heavy backend TLS material by this short id instead of
// inline path strings (768 bytes reclaimed). 64 fits the token
// format (alphanumeric handle) with NUL terminator headroom. Defined here (ahead
// of cert_id_entry and proxy_arg, both of which embed certId[CERTID_MAX]).
#define CERTID_MAX 64
typedef struct cert_id_entry {
  char certId[CERTID_MAX];                          // opaque management handle (hash key)
  char dir_path[256];                               // managed dir, e.g. /etc/loxilb/certs/<certId>
  char hostnames[CERTID_MAX_HOSTNAMES][256];        // auto-derived SAN/CN hostnames registered in the SNI store
  int  n_hostnames;                                 // count of derived hostnames
  time_t loaded_ts;                                 // last (re)load timestamp
  UT_hash_handle hh;                                // uthash handle for the certId map
} cert_id_entry_t;

typedef enum {
  PROXY_SOCK_LISTEN = 1,
  PROXY_SOCK_ACTIVE,
} proxy_socktype_t;

struct proxy_cache {
  void *cache;
  size_t off;          // CRITICAL: Must be size_t to handle large file transfers (was uint16_t, causing overflow at 64KB!)
  size_t len;
  struct proxy_cache *next;
  uint8_t data[0];
};
typedef struct proxy_cache proxy_cache_t;

// P/D disaggregation orchestration phases
typedef enum {
  PD_PHASE_NONE             = 0,  // Not a P/D request (zero-overhead path)
  PD_PHASE_PREFILL_SENDING  = 1,  // Prefill request being sent to prefill EP
  PD_PHASE_PREFILL_WAITING  = 2,  // Waiting for prefill response
  PD_PHASE_PREFILL_DONE     = 3,  // Prefill response received, ready for decode
  PD_PHASE_DECODE_SENDING   = 4,  // Decode request being sent to decode EP
  PD_PHASE_DECODE_STREAMING = 5,  // Decode response streaming to client
  PD_PHASE_COMPLETE         = 6,  // P/D flow completed
  PD_PHASE_ERROR            = 7,  // P/D flow error
  PD_PHASE_PARKED           = 8   // client parked (all prefill EPs capped),
                                  // EPOLLIN-suspended on a per-EP FIFO, awaiting a freed
                                  // slot (dequeue+resume is not wired yet). NOT connected.
} pd_phase_t;

struct proxy_fd_ent {
  pthread_rwlock_t lock;
  /* D2 root fix (pfe pool + generation). The pfe STRUCT (this shell) is never
   * free()d to the heap once allocated — it is recycled through a grow-only
   * freelist (pfe_alloc/pfe_recycle), so its address is permanently valid and a
   * stale notify dispatch that derefs a recycled pfe is memory-safe. `gen` is
   * bumped on every recycle; proxy_notifier drops any event whose captured gen
   * no longer matches, eliminating the use-after-free class. Only the large
   * embedded buffers (rcvbuf below, pd_* bufs, ssl, pii) are malloc/free'd per
   * connection so steady-state residency tracks live connections, not high-water
   * (B-split: the 1MB rcvbuf is NOT pooled). _Atomic so the recycle-side bump and
   * the dispatch-side read race safely without taking a lock on the read path. */
  _Atomic uint64_t gen;
  /* D2 root fix: freelist link for the pfe pool (sockproxy_conn.c). Dedicated
   * field — NOT the `next` used for ent->val.fdlist linkage — so the pool and the
   * fd-list can never alias, even on early error-teardown paths. Valid only while
   * the shell sits on the freelist. */
  struct proxy_fd_ent *pool_next;
  int used;
  int fd;
  int rfd[MAX_PROXY_EP];
  struct proxy_fd_ent *rfd_ent[MAX_PROXY_EP];
  int n_rfd;
  int mode;
  int ep_num;
  int lsel;
  int protocol;
  int seltype;
  int odir;
  int ssl_err;
  int ktls_enabled;  // kTLS offload active on this socket
  int protocol_version;  // 1 = HTTP/1.1, 2 = HTTP/2
  uint32_t _id;
  proxy_socktype_t stype;
  pthread_rwlock_t cache_lock;
  proxy_cache_t *cache_head;
  uint32_t cache_count;          // Number of cache entries
  size_t cache_total_size;       // Total size of cached data
  int cache_backpressure;        // 1 if reading is paused due to high cache
  int read_paused;               // 1 if EPOLLIN is disabled due to backpressure
  // 1 if the Tier-1 shaper parked this fd (empty bucket). Distinct from
  // cache_backpressure on purpose: the backpressure clear/resume paths must
  // never disengage a QoS park — only the shaper's refill wake clears this.
  int qos_parked;
  // 1 between a QoS resume and the next successful read; lets the first
  // post-park read be accounted as delayed bytes.
  int qos_was_parked;
  // Wall-clock stamp of the last 1Hz health pass that observed this
  // connection QoS-parked (0 = not parked at the last pass). The pass uses
  // it to slide start-anchored duration caps forward by the exact paused
  // span, so shaper-paused time never counts as idle/stream time.
  time_t qos_park_seen_ts;
  // Monotonic ns stamp taken when the shaper parked this fd (0 = not parked).
  // Consumed at resume to accumulate the bucket's park_ns_total observability
  // counter; distinct from qos_park_seen_ts, which is the 1Hz health pass's
  // second-resolution anchor and must stay on its own clock.
  uint64_t qos_park_ns;
  int cache_draining;            // 1 if cache is currently being drained (prevents bypass)
  uint64_t chunk_seq;            // Chunk sequence number for ordering verification

  // Connection-level state for chunked encoding and graceful shutdown
  int is_chunked_response;       // 1 if Transfer-Encoding: chunked detected (persists for connection)
  int peer_eof;                  // 1 if peer closed, waiting for our cache to drain
  time_t eof_timestamp;          // When peer EOF detected (for timeout enforcement)

  struct proxy_fd_ent *next;
  void *head;
  void *ssl;
  void *epv;
  proxy_h2_session_t *h2_session;  // HTTP/2 session context (NULL for HTTP/1.1)
  void *backend_h2_session;        // Backend HTTP/2 session (for backend connections only)
  uint64_t nrb;
  uint64_t nrp;
  uint64_t ntb;
  uint64_t ntp;
  size_t rcv_off;
  size_t parsed_off;  // How much of rcvbuf has been parsed
  int http_pok;
  int http_hok;
  int http_hvok;
  int http_body_complete;
  size_t http_content_length;
  int is_streamable;  // Flag: Content can be streamed (not JSON/form-urlencoded)
  /* F-GPU-4: outstanding request-body bytes of a STREAMED request (early
   * backend connect forwarded the headers before the body finished arriving).
   * While >0, client reads are raw-relayed to rfd[0] — they are BODY, not a
   * new request — and the KA-FIX stale-leg release must not fire (the
   * streamed-forward path resets rcv_off to 0, which otherwise makes
   * mid-body look exactly like a keep-alive request boundary). */
  size_t stream_body_remaining;
  char host_url[256];
  char request_path[256];  // P6: Request URL path ("/v1/users")
  char url_path[512];      // Full URL with query string for query parameter extraction
  int http_path_ok;        // P6: Path extraction flag
  char last_header_name[128];

  // L7 policy generic header/cookie store — bounded fixed
  // capacity; populated by l7_store_header_n() from BOTH the H1 and H2 parse
  // paths; consumed by l7_policy_evaluate (Plan 03/04). Overflow is dropped.
  struct {
    char name[L7_HDR_NAME_MAX];
    char value[L7_HDR_VALUE_MAX];
  } l7_headers[L7_MAX_CAPTURED_HEADERS];
  uint16_t n_l7_headers;        // count of populated l7_headers slots (<= cap)

  // Octavia: header-accumulation deadline anchor (slowloris guard).
  // Set to time(NULL) on the FIRST data byte of the request parsing phase (rfd[0]<=0 and
  // http_hok==0). Enforced ONLY on the L7_Proxy peer (has_l7_policy==1) and ONLY while the
  // request headers are still incomplete: if (now - l7_hdr_accum_start) exceeds the listener's
  // timeout_tcp_inspect_ms deadline (ms, or a bounded default when 0) before \r\n\r\n / the full
  // HEADERS frame arrives, the connection is dropped. Cleared (0) once headers complete so it
  // never bounds body upload. Pure no-op for the AI peer / un-configured listeners.
  time_t l7_hdr_accum_start;    // first-byte ts of the in-progress request headers (0=unset)

  llm_prefix_key_t prefix_key;  // LLM prefix extraction (P0.2)

  // (B1): request-scoped chat-routing signal + raw-body locator for
  // the KV-exact tokenize stage. is_chat=1 marks /v1/chat/completions so
  // pd_kv_exact_select routes tokenization to llb_ai_kv_tokenize_chat (raw body
  // + apply_chat_template) instead of the un-templated single-text path.
  // body_off/body_len pin the raw JSON body's location WITHIN rcvbuf (set at the
  // extract_llm_prefix call site where body_start/body_len are valid), so the
  // kv-exact stage can pass the contiguous raw body to the chat bridge. These are
  // request-scoped fields on proxy_fd_ent — deliberately NOT added to
  // llm_prefix_key_t, which participates in hashing/HA sync (threat).
  uint8_t is_chat;              // 1 = /v1/chat/completions; 0 = completions/other (fail-safe default)
  size_t  body_off;            // offset of the raw JSON body within rcvbuf (0 = unset)
  size_t  body_len;            // length of the raw JSON body within rcvbuf (0 = unset)

  char conversation_id[MAX_CONV_ID_LEN];  // Conversation ID (P0.3)
  int has_conv_id;  // Flag: conversation ID present
  char user_id[128];    // extracted from JSON body "user" field (P/D session key fallback)
  int  has_user_id;     // Flag: user_id present

  // Custom session header storage (generic, flexible)
  char custom_session_header_value[256];  // Extracted header value
  int has_custom_session_header;          // 1=extracted, 0=not present
  char session_header_name[128];          // Configured session header name (from service config)
  
  // Criterion A: Model name from X-Model HTTP request header (fast path)
  // Priority for effective model: x_model_header > prefix_key.model > "" (wildcard)
  char x_model_header[MAX_MODEL_LEN];     // Extracted from X-Model: request header; empty = not present

  // Session learning for backend responses
  int needs_session_learning;             // 1=first request without session header, need to learn from response
  char learned_session_id[256];           // Session ID extracted from backend response
  
  // L7 Metrics (independent of Jaeger tracing)
  uint64_t metric_req_start_ns;
  uint16_t metric_response_status;
  uint8_t  ai_gw_mode;                // 1=AI Gateway connection; copied from the rule at accept
  uint8_t  apikey_auth;               // 0=unset 1=required 2=declared-disabled; copied from the rule at accept
  uint8_t  metric_ai_recorded;       // 1=this request already counted in ai_requests_total (dedup guard)

  // HTTP/HTTPS Trace Context (: Protocol Analyzer)
#ifdef HAVE_HTTP_TRACE
  uint64_t trace_id_hi;                   // W3C trace_id (high 64 bits, 128-bit UUID)
  uint64_t trace_id_lo;                   // W3C trace_id (low 64 bits)
  uint64_t parent_span_id;                // W3C parent_span_id (from traceparent header)
  uint64_t root_span_id;                  // Root span ID (for REQ_START event)
  uint64_t upstream_span_id;              // Upstream span ID (for UP_START/UP_END pairing)
  uint64_t req_start_ts;                  // Request start timestamp (nanoseconds)
  uint8_t  trace_flags;                   // W3C trace flags (bit 0 = sampled)
  uint8_t  has_traceparent;               // 1=traceparent header found, 0=generated
  uint16_t catalog_id;                    // Service catalog ID (for deep inspection)
  uint16_t response_status_code;          // HTTP response status (captured when backend responds)
  uint16_t http_status_code;              // Error status code for trace emission (502/500/507 for error paths)
  uint32_t response_content_length;       // HTTP response Content-Length (captured when backend responds)
  uint32_t client_ip;                     // Original client IP (for backend connections)
  uint16_t client_port;                   // Original client port (for backend connections)
  uint32_t backend_ip;                    // Attempted backend IP (for connection failure traces)
  uint16_t backend_port;                  // Attempted backend port (for connection failure traces)
  uint8_t  has_body_file;                 // 1=body captured to tmpfs, 0=no body
  char     body_file_path[256];           // Path to captured body file (if has_body_file=1)
  char     http_method[16];               // HTTP method (GET/POST/PUT/etc.) stored at request time
#endif
  
  llhttp_t parser;
  llhttp_settings_t settings;
#define SP_SOCK_MSG_LEN (1024 * 1024)  // 1MB - handles file uploads + LLM requests
/* largest JSON body the proxy will BUFFER for body inspection (prefix
 * extraction / KV-exact tokenize). A JSON request above this streams instead:
 * inspection is skipped and routing falls through to Tier-2 (fail-open). The
 * cap MUST sit safely under the 95%-of-SP_SOCK_MSG_LEN overflow guard in
 * sockproxy_http.c (972KB) — before this cap existed, a long-context JSON
 * request (coding-assistant, >~972KB) could never complete in rcvbuf, hit that
 * guard, and had its CONNECTION RESET instead of being served. 3/4 of the
 * buffer leaves 256KB headroom for headers + the final read burst. */
#define SP_JSON_INSPECT_MAX (SP_SOCK_MSG_LEN / 4 * 3)
  /* D2 root fix (B-split): the 1MB receive buffer is heap-allocated per
   * connection (pfe_alloc calloc's it, pfe_recycle frees it) rather than embedded
   * inline, so the pooled pfe shell stays small (~KB) and grow-only residency is
   * bounded. Access syntax (pfe->rcvbuf[i], &pfe->rcvbuf[i]) is unchanged. */
  uint8_t *rcvbuf;
  
  // Session Affinity Fields
  uint32_t sticky_server_id;     // Index of bound backend server
  int is_sticky;                 // 1 if connection is bound to a server
  char session_key[64];          // Session identifier (IP+Port or Content ID)
  time_t session_created;        // When session was created
  int affinity_type;             // Type of affinity (IP-based, content-based, etc.)
  time_t last_activity;         // Last activity timestamp for session timeout
#ifdef HAVE_PII_DETECTION
  // PII Masking Deferred State (prevents parser corruption)
  char *pii_masked_text;         // Temporarily stores masked body text
  size_t pii_masked_len;         // Length of masked text
  int pii_needs_masking;         // 1 = apply masking before forwarding
#endif

  // AI Gateway per-connection state
  char     x_api_key_raw[256];        // Raw value of X-Api-Key request header (extracted by handle_header_val)
  char     tenant_id[64];             // Tenant ID from llb_ai_validate_key decision
  uint8_t  ai_gw_denied;              // 1 = the AI gate refused this request (response already sent,
                                      // socket shut down). Read after llhttp_execute to keep a policy
                                      // denial out of the parse-error fallback, which relays the buffer
                                      // raw to a backend -- the exact path a denial must never take. 

  // SSE (Server-Sent Events) per-connection state 
  uint8_t  sse_mode;                  // SSE mode enabled for this rule: copied from proxy_epval_t at accept
  uint32_t max_stream_duration_sec;   // Max stream duration from rule (0=use hard cap)
  uint32_t backend_keepalive_sec;     // Backend keepalive interval from rule (0=disabled)
  uint32_t inactive_timeout_sec;      // Per-rule idle timeout in seconds (0=disabled); suppressed when sse_active=1
  uint8_t  sse_active;                // 1=SSE stream detected and active (Content-Type: text/event-stream seen)
  time_t   stream_start_ts;           // Wall-clock time when SSE stream was activated (time(NULL))
  time_t   stream_end_ts;             // Wall-clock time when data:[DONE] was received
  uint64_t stream_start_mono_ns;      // CLOCK_MONOTONIC stamp at SSE activation; latency source for
                                      // llb_ai_record_request (wall-clock seconds truncated sub-second
                                      // streams to 0 and NTP steps could skew/negate the delta)
  uint8_t  sse_tail[20];              // Sliding tail buffer for TCP-fragmentation-safe [DONE] scanner
  uint8_t  sse_tail_len;              // Number of valid bytes in sse_tail

  /* Token-accounting response scan state. usage_tail is a sliding window
   * over the LAST bytes of the backend response relayed to this client fd —
   * sized to hold the final SSE usage chunk (or the tail of a non-streamed
   * JSON body) across TCP segment splits. The quota is charged exactly once
   * per response (usage_consumed); all four fields reset with the other
   * per-request captures at the next message begin. proxy_fd_ent is not
   * xSync-serialized, so this growth is HA-safe (pd_last_decode_ts
   * precedent below). */
#define PROXY_USAGE_TAIL_KEEP 1024
  uint8_t  usage_tail[PROXY_USAGE_TAIL_KEEP];
  uint16_t usage_tail_len;            // Number of valid bytes in usage_tail
  uint8_t  usage_consumed;            // 1 = token quota charged for the current response
  int      usage_prompt_toks;         // extracted usage.prompt_tokens (0 = none seen)
  int      usage_complet_toks;        // extracted usage.completion_tokens
  /* Estimate net for responses whose usage object never materializes
   * (chunked/oversize request bodies skip the include_usage inject; an
   * engine may drop the final chunk). usage_est_prompt is sized from the
   * request's messages/prompt bytes at dispatch; usage_sse_events counts
   * relayed "data: {" SSE chunks (~1 completion token per content chunk).
   * Charged with the estimated flag ONLY when extraction misses. */
  uint32_t usage_est_prompt;          // prompt-token estimate from the request body
  uint32_t usage_sse_events;          // relayed SSE data-object chunk count
  /* Pre-admission reservation made at the gate (prompt estimate +
   * declared max_tokens) and its quota-window tag; both echoed to the
   * consume call at settlement, zeroed there and at message begin. An
   * aborted request's claim self-heals at window rollover. */
  uint32_t usage_reserved_toks;       // tokens reserved at admission (0 = none)
  int64_t  usage_res_epoch;           // reservation window tag from the reserve call
  time_t   pd_last_decode_ts;         // wall-clock of the LAST decode backend byte relayed to the
                                      // client. Refreshed per byte during decode streaming so the safety-net
                                      // reaper (sockproxy_health.c) can gate graceful [DONE] synthesis on
                                      // genuine BACKEND-idle (vLLM dropped its [DONE]) instead of
                                      // wall-clock-since-start, which would truncate a slow-but-live stream.
                                      // proxy_fd_ent is not xSync-serialized, so this growth is HA-safe.

  // response-leg HTTP_RESPONSE framing latch. Set on a
  // backend pfe (odir==1) the first time the pd_framing_v2 path lazily inits its
  // HTTP_RESPONSE parser so the init is idempotent and the parser is NOT
  // re-initialized per relayed read (which would discard mid-message state).
  // Append-only growth on proxy_fd_ent (NOT xSync-serialized) — HA-safe per the
  // pd_last_decode_ts precedent above ( Invariant 2).
  uint8_t  resp_parser_inited;        // 1=backend HTTP_RESPONSE parser initialized (pd_framing_v2 path)

  // vLLM Request-ID management 
  char     vllm_request_id[256];     // Generated or client-provided request ID
  uint8_t  has_vllm_request_id;      // 1=from client X-Request-Id header
  uint8_t  request_id_injected;      // 1=already injected into forwarded request

  // P/D Disaggregation orchestration state 
  pd_phase_t pd_phase;               // Current P/D orchestration phase
  uint8_t  is_pd_decode_backend;     // 1=this pfe is a decode backend (not prefill or client)
  // bounded backpressured admission — park bookkeeping. When this
  // client is parked (all prefill EPs capped, FIFO has room), park_ep_idx is the
  // prefill EP whose FIFO it sits on and park_start_ts is the CLOCK_MONOTONIC ns
  // stamp at enqueue (drives the max-park reap). park_ep_idx == -1 (the
  // pooled-pfe default) means "not parked". No parallel struct — reuse the pfe.
  int      park_ep_idx;              // prefill EP index this request is parked behind (-1 = not parked)
  uint64_t park_start_ts;            // CLOCK_MONOTONIC ns at park enqueue (max-park reap)
  int      pd_prefill_ep_idx;        // Selected prefill endpoint index
  int      pd_decode_ep_idx;         // Selected decode endpoint index
  uint8_t *pd_saved_body;            // Heap: original request body for decode phase
  size_t   pd_saved_body_len;        // Length of saved body
  uint8_t *pd_saved_headers;         // Heap: complete request headers (with X-Request-Id etc.)
  size_t   pd_saved_headers_len;     // Length of saved headers (includes \r\n\r\n)
  uint8_t *pd_prefill_resp_buf;      // Heap: buffered prefill response (max 64KB)
  size_t   pd_prefill_resp_len;      // Current length of buffered prefill response
  size_t   pd_prefill_resp_cap;      // Capacity of prefill response buffer
  char     pd_kv_params[PD_KV_PARAMS_MAX_LEN]; // Extracted kv_transfer_params JSON (64KB)
  size_t   pd_kv_params_len;         // Length of kv_transfer_params
  size_t   pd_prefill_body_len;      // Length of rewritten prefill body (for Content-Length update)
  time_t   pd_phase_start_ts;        // Wall-clock timestamp for timeout tracking
  uint64_t pd_prefill_start_ns;      // Monotonic timestamp for prefill latency
  uint64_t pd_decode_start_ns;       // Monotonic timestamp for decode latency
  size_t   pd_decode_content_length; // Content-Length from non-SSE decode response headers
  size_t   pd_decode_bytes_received; // Decode response body bytes received so far
  /* SGLang P/D dual-dispatch state. The CLIENT pfe reuses the
   * DECODE_SENDING/DECODE_STREAMING/COMPLETE pd_phase lifecycle for its decode
   * leg (so every decode-side behavior — SSE latch, [DONE] scanner, stream
   * caps, EOF taxonomy, reapers, xSync — applies unchanged); the prefill leg
   * is a detached DRAIN leg whose state lives on the BACKEND pfe below.
   * Append-only growth on proxy_fd_ent (NOT xSync-serialized) — HA-safe per
   * the resp_parser_inited precedent. Zero-init (pfe_alloc) == off. */
  uint8_t  pd_sg_active;             // CLIENT: SGLang dual dispatch live for this request
  uint64_t pd_sg_room;               // CLIENT: bootstrap room injected into both legs (logs/retry)
  uint8_t  pd_sg_drain;              // BACKEND: this leg is the SGLang prefill drain leg
  uint8_t  pd_sg_drain_done;         // BACKEND: prefill response fully received (message complete)
  uint8_t  pd_sg_drain_handled;      // BACKEND: failure coupling already fired for this leg
  uint8_t  pd_sg_drain_desync;       // BACKEND: a parser feed was skipped (trylock miss) — framing
                                     // untrusted, completion falls back to leg EOF
  uint8_t  pd_sg_drain_fed;          // BACKEND: drain framer consumed at least one chunk (a 4xx
                                     // enters relay mode only when detected on the FIRST chunk —
                                     // earlier chunks were discarded and cannot be re-relayed)
  uint8_t  pd_sg_drain_relay;        // BACKEND: origin 4xx being handed to the client verbatim;
                                     // every further drain chunk is relayed until message end
                                     // (or leg EOF for a close-framed response)
  uint8_t  pd_prefill_retries;       // Prefill mid-request failovers consumed (budget: 1).
                                     // Prefill is side-effect-idempotent and the complete
                                     // request survives in pd_saved_headers/pd_saved_body,
                                     // so ONE re-dispatch against a re-selected EP is safe;
                                     // a second death fails the request (503).
  uint8_t  lb_err_body_sent;         // An HTTP error body already went to this client for
                                     // the current selection/connect failure — the caller's
                                     // raw-shutdown accounting (lb_select_failure_shutdown)
                                     // must then NOT count it as a silent reset.

  /* single-role Tier-1.5 load-accounting bookkeeping.
   * kv_sr_load_held == 1 marks "this client pfe holds ONE active_conns unit on
   * epv->pd_ep_loads[kv_sr_ep_idx]" (stamped by the single-role KV branch in
   * sockproxy_ep.c on a Tier-1.5 hit). The unit is released EXACTLY once —
   * claimed via __atomic_exchange (the Phase-89 pd_free_claim single-owner
   * discipline) by EITHER the backend connect-failure path (sockproxy_ep.c)
   * OR the generic teardown (pd_cleanup, sockproxy_http.c). Without this
   * pairing the unified CHWBL hard-cap and adaptive ε/λ run blind on
   * single-role services (the hot-spot, 99-RESEARCH Pitfall 1).
   * Append-only growth on proxy_fd_ent (NOT xSync-serialized) — HA-safe per
   * the resp_parser_inited precedent above. Zero-init (pfe_alloc) == not held. */
  uint8_t  kv_sr_load_held;          // 1 = single-role KV load unit held 
  int      kv_sr_ep_idx;             // EP index holding the unit (valid iff kv_sr_load_held)

  char     resp_model[MAX_MODEL_LEN]; // Effective model snapshot taken at the keep-alive
                                      // request-reset boundary. The per-request resets clear
                                      // x_model_header and prefix_key BEFORE the backend
                                      // response arrives, so response-phase consumers (SSE
                                      // activation/[DONE] metrics, stream cap/reaper, P/D
                                      // completion records) must read the model here.
};
typedef struct proxy_fd_ent proxy_fd_ent_t;

/* Effective model for response-phase consumers: live request fields first
 * (pre-reset paths), then the resp_model snapshot. Returns "" when no model
 * was supplied at all. */
static inline const char *
proxy_effective_model(const proxy_fd_ent_t *pfe)
{
  if (pfe->x_model_header[0] != '\0') {
    return pfe->x_model_header;
  }
  if (pfe->prefix_key.model[0] != '\0') {
    return pfe->prefix_key.model;
  }
  return pfe->resp_model;
}

/* D2 root fix (pfe pool + generation, B-split) — implemented in sockproxy_conn.c.
 * pfe_alloc(): a zeroed pfe shell from a grow-only freelist (address permanently
 * valid) with a fresh 1MB rcvbuf; gen is preserved across recycles (monotonic).
 * Returns NULL only on OOM. pfe_recycle(): free the shell's per-connection heap
 * buffers, bump gen, return the shell to the freelist — never free() it. */
proxy_fd_ent_t *pfe_alloc(void);
void pfe_recycle(proxy_fd_ent_t *pfe);
#ifdef D2_DEBUG_INJECT
void pfe_pool_selftest(void);   /* validation-only pool+gen invariant proof */
#endif

// ============================================================================
// L7 POLICY: bounded generic header capture helpers 
// ----------------------------------------------------------------------------
// Append a (name, value) pair into the per-connection fixed-capacity store.
// Both the H1 parse path (handle_header_val, sockproxy_http.c) and the H2 parse
// path (proxy_h2_on_header_callback, sockproxy_h2.c) call l7_store_header_n with
// length-delimited buffers (llhttp/nghttp2 do NOT NUL-terminate). The store is
// BOUNDED: once n_l7_headers reaches L7_MAX_CAPTURED_HEADERS the append is a
// no-op (overflow dropped, never grown). Name/value are truncated to
// L7_HDR_NAME_MAX-1 / L7_HDR_VALUE_MAX-1 and always NUL-terminated.
static inline void
l7_store_header_n(struct proxy_fd_ent *pfe,
                  const char *name, size_t namelen,
                  const char *value, size_t valuelen)
{
  size_t nl, vl;

  if (!pfe || !name)
    return;
  if (pfe->n_l7_headers >= L7_MAX_CAPTURED_HEADERS)
    return;  // bounded: overflow dropped 

  nl = (namelen < (size_t)(L7_HDR_NAME_MAX - 1)) ? namelen : (size_t)(L7_HDR_NAME_MAX - 1);
  vl = (value && valuelen < (size_t)(L7_HDR_VALUE_MAX - 1)) ? valuelen
       : (value ? (size_t)(L7_HDR_VALUE_MAX - 1) : 0);

  memcpy(pfe->l7_headers[pfe->n_l7_headers].name, name, nl);
  pfe->l7_headers[pfe->n_l7_headers].name[nl] = '\0';
  if (value && vl)
    memcpy(pfe->l7_headers[pfe->n_l7_headers].value, value, vl);
  pfe->l7_headers[pfe->n_l7_headers].value[vl] = '\0';

  pfe->n_l7_headers++;
}

// Convenience wrapper for NUL-terminated inputs.
static inline void
l7_store_header(struct proxy_fd_ent *pfe, const char *name, const char *value)
{
  if (!name)
    return;
  l7_store_header_n(pfe, name, strlen(name), value, value ? strlen(value) : 0);
}

#define PROXY_MODE_DFL 0
#define PROXY_MODE_ALL 1

#define PROXY_SEL_RR    0
#define PROXY_SEL_HASH  1
#define PROXY_SEL_N2    2
#define PROXY_SEL_STICKY 3       // Session persistence (from persist-sockproxy)
#define PROXY_SEL_CHWBL 4        // P1.2: Consistent Hash with Bounded Loads (from gpu)
#define PROXY_SEL_GPU_AWARE 5    // Part 5: GPU-Aware Load Balancing (catalog-based, from gpu)
#define PROXY_SEL_WRR 6          // P3: Weighted Round-Robin (smooth distribution)
#define PROXY_SEL_WRR_HASH 7     // P3.5: Weighted Consistent Hash + Bounded Loads

// PROXY_SEL_GPU_AWARE scoring weights — the data-path live-load
// terms the capacity-weighted bounded-load scorer consumes in
// pd_select_prefill (pd_capacity_blend_score). These were previously defined
// ONLY under HAVE_DP_GPU_ROUTING (DEFAULT_{QUEUE,SWAP,KV_CACHE}_WEIGHT below)
// and never wired into the prefill selector. They are defined here
// UNCONDITIONALLY so the GPU-aware prefill arm compiles + consumes them even on
// the default (non-HAVE_DP_GPU_ROUTING) build. Values match the DEFAULT_*
// catalog (queue 50 / swap 30 / kv-cache 20) for backward compatibility.
#ifndef DEFAULT_QUEUE_WEIGHT
#define DEFAULT_QUEUE_WEIGHT               50
#endif
#ifndef DEFAULT_SWAP_WEIGHT
#define DEFAULT_SWAP_WEIGHT                30
#endif
#ifndef DEFAULT_KV_CACHE_WEIGHT
#define DEFAULT_KV_CACHE_WEIGHT            20
#endif

// Session affinity types
#define PROXY_AFFINITY_NONE     0
#define PROXY_AFFINITY_IP       1    // Based on client IP
#define PROXY_AFFINITY_CONTENT  2    // Based on content ID
#define PROXY_AFFINITY_COOKIE   3    // Based on HTTP cookie

// SSE hard cap: absolute maximum stream lifetime regardless of max_stream_duration_sec=0
// Prevents fd leaks when [DONE] terminator is missed due to TCP fragmentation
#define PROXY_SSE_HARD_CAP_SEC  86400  // 24 hours

// CERTID_MAX is defined earlier (near cert_id_entry, ~line 530) so both that
// struct and proxy_arg below can embed certId[CERTID_MAX].

struct proxy_arg {
  char host_url[256];
  char path_prefix[256];    // P6: URL path prefix ("/v1/users", optional)
  char model_name[128];     // AI model name for pool selection (e.g. "llama-70b"); empty = wildcard
  uint8_t path_match_mode;  // P6: 0=disabled, 1=prefix, 2=exact
  uint32_t _id;
  int have_ssl;
  int have_epssl;
  int ppv2;             /* PROXY protocol v2 emission on backend conns (L7 fullproxy) */
  int proxy_mode;
  int select;
  int n_eps;
  proxy_ent_t eps[MAX_PROXY_EP];
  int affinity_type;        // Type of session affinity to use
  int session_timeout;      // Session timeout in seconds (0 = no timeout)
  
  // Custom header-based session stickiness configuration
  char session_header_name[128];    // e.g., "mcp-session-id", "x-session-token"
  uint8_t session_header_enabled;   // 1=enabled, 0=use IP-based
  
  // Backend protocol capability (for ALPN configuration)
  // 0 = HTTP/1.1 only (default) - advertise only http/1.1 to clients
  // 1 = HTTP/2 only - advertise only h2 to clients
  // 2 = Both - advertise both h2 and http/1.1 (backend supports both)
  uint8_t backend_protocol_cap;

  // ==========================================================================
  // TLS-hardening scalars ( version pinning / HSTS).
  // All additive + default-off: 0/empty ⇒ today's hardcoded behaviour (-COMPAT,
  // mirroring the precedent below). Enforced only on the L7_Proxy peer
  // (has_l7_policy==1); the AI peer is byte-for-byte unchanged. ALPN reuses the
  // existing backend_protocol_cap enum above — no new field.
  // ==========================================================================

  // TLS protocol-version pinning. Encoded as the OpenSSL proto
  // ordinal (TLS1_2_VERSION=0x0303 → store 0x03; 0 ⇒ today's hardcoded
  // TLS1.2..TLS1.3 range). Octavia tls_versions list collapsed to a min..max range.
  uint8_t tls_version_min;  // 0 ⇒ today's TLS1_2_VERSION floor
  uint8_t tls_version_max;  // 0 ⇒ today's TLS1_3_VERSION ceiling

  // HSTS response injection. Data plane synthesizes
  // "Strict-Transport-Security: max-age=N[; includeSubDomains][; preload]" and
  // injects via the L7-gated header path (nghttp2 on H2).
  uint32_t hsts_max_age;             // 0 ⇒ no HSTS injection (default-off)
  uint8_t  hsts_include_subdomains;  // 0 ⇒ omit "; includeSubDomains"
  uint8_t  hsts_preload;             // 0 ⇒ omit "; preload"
  uint8_t  _pad_tls77[2];            // 8-byte alignment for the following string

  // inline OpenSSL cipher string, passed to BOTH
  // SSL_CTX_set_cipher_list (TLS1.2) and SSL_CTX_set_ciphersuites (TLS1.3).
  // empty ⇒ today's hardcoded cipher lists. Inlined (not id-referenced) because
  // reclaiming the 768 backend-path bytes leaves ample headroom under
  // the 4096 _Static_assert (Open Question 2 RESOLVED — measured).
  char tls_ciphers[256];             // empty ⇒ today's hardcoded ciphers

  // SSE (Server-Sent Events) streaming configuration
  uint8_t  sse_mode;                // 1=SSE mode enabled, 0=disabled
  uint32_t max_stream_duration_sec; // Absolute wall-clock cap for streams (0=use PROXY_SSE_HARD_CAP_SEC)
  uint32_t backend_keepalive_sec;   // Backend SO_KEEPALIVE+TCP_KEEPIDLE interval in seconds (0=disabled)
  uint32_t inactive_timeout_sec;    // Per-rule idle timeout in seconds (0=disabled); suppressed when sse_active=1

  // per-listener member timeouts in MILLISECONDS (Octavia native unit).
  // Additive + default-off: 0 ⇒ preserve today's hardcoded behaviour (zero behaviour change
  // for un-configured L7 listeners;). Enforced only on the L7_Proxy peer (has_l7_policy==1).
  uint32_t timeout_member_connect_ms; // 0 ⇒ 500 (today's sockproxy_conn.c:408 connect-poll literal)
  uint32_t timeout_member_data_ms;    // 0 ⇒ existing client-idle value (member-side relay idle)
  // header-accumulation deadline — max time to await the complete request headers
  // (\r\n\r\n / full HEADERS frame) before evaluating L7 rules (slowloris protection).
  // NOTE (Pitfall 4): NON-REPRESENTABLE on Gateway-API export (Gateway exposes only
  // timeouts.request/backendRequest); a future Gateway controller MUST hard-error, never silent-drop.
  uint32_t timeout_tcp_inspect_ms;    // 0 ⇒ sane bounded default (header-accum deadline)

  // P/D Disaggregation configuration
  uint8_t  pd_disagg_mode;          // 1=P/D mode enabled
  uint8_t  ai_gw_mode;             // 1=AI Gateway mode (auto-derived)
  uint8_t  apikey_auth;            // 0=unset, 1=required, 2=declared disabled (per-service policy, NOT derived)
  // SGLang bootstrap port on prefill EPs (0 ⇒ PD_SG_BOOTSTRAP_PORT_DFL at
  // proxy_add). The nat2proxy hop of the additive chain
  // (dp_proxy_tacts -> proxy_arg -> proxy_add_entry).
  uint16_t pd_bootstrap_port;
  uint8_t  ep_role[MAX_PROXY_EP];  // Per-endpoint role: 0=normal, 1=prefill, 2=decode

  // P/D Cache-Aware Routing configuration (US-PD801)
  uint16_t pd_kv_params_max;            // Runtime KV params buffer limit (0 = use PD_KV_PARAMS_MAX_LEN)
  uint8_t  pd_cache_aware_mode;
  uint8_t  pd_cache_threshold;
  uint8_t  pd_balance_abs_threshold;
  uint8_t  cb_enable;                  // per-endpoint circuit breaker (replaces pad_pd_cache_arg)
  uint32_t pd_session_ttl_sec;

  // KV-Cache Exact Routing configuration 
  uint8_t  kv_exact_mode;        // 0=off, 1=zmq(P/D), 2=nats(reserved), 3=zmq single-role 
  uint8_t  kv_hash_algo;         // 0=sha256_cbor, 1=xxhash_cbor
  uint16_t kv_zmq_port;          // ZMQ PUB port (default 5557)
  uint32_t kv_block_size;        // Token block size (default 16)
  uint32_t kv_warmup_sec;        // Warmup seconds
  // (SGL-03): per-rule KV engine + SGLang DP rank count.
  uint8_t  kv_engine_type;       // 0=vllm (default), 1=sglang, 2=trtllm
  uint8_t  kv_dp_rank_count;     // SGLang DP ranks (1..8; 0 defaulted to 1 at the CGO fill)

  // CHWBL prefix hash level: 0=use default(1), 1=L1 only, 2=L1+L2, 3=L1+L2+L3
  // Populated from dp_proxy_tacts.chwbl_prefix_hash_level during proxy_add_entry
  uint32_t chwbl_prefix_hash_level;

#ifdef HAVE_MTLS
  // ============================================================================
  // mTLS Configuration 
  // ============================================================================
  
  // Frontend mTLS - Client certificate verification
  uint8_t frontend_mtls_mode;       // 0=disabled, 1=optional, 2=required
  char client_ca_path[256];         // Client CA bundle path
  uint8_t require_client_cn;        // 1=require CN pattern match, 0=no
  char client_cn_pattern[256];      // CN pattern (e.g., "*.corp.example.com")
  
  // explicit operator-supplied client-cert CRL path (PEM) loaded
  // into the verify X509_STORE with leaf-only X509_V_FLAG_CRL_CHECK. This is the explicit
  // drop-in for an earlier cycle's convention-derived sibling crl.pem (mtls_derive_crl_path): when set it
  // is preferred; empty ⇒ fall back to the CA-dir-sibling convention (today's behaviour).
  char client_crl_path[256];        // empty ⇒ derive sibling crl.pem from client_ca_path 

  // Backend mTLS - Server cert verification + client cert
  uint8_t backend_verify_cert;      // 1=verify server cert, 0=no (SSL_VERIFY_NONE)

  // backend re-encryption material is referenced by
  // a short certId into the registry, NOT inline path strings.
  // This reclaims the 768 bytes the three backend_*_path[256] strings occupied
  // (Pitfall 3) — the headroom the rest of the phase's scalars need. The registry
  // resolves the certId → managed-dir paths (/etc/loxilb/certs/<certId>/) at
  // backend SSL_CTX build time (proxy_client_ssl_ctx_init). empty ⇒ no backend
  // CA/client-cert (today's behaviour when the paths were empty).
  char backend_ca_cert_id[CERTID_MAX];      // certId of the backend CA bundle (empty ⇒ system default)
  char backend_client_cert_id[CERTID_MAX];  // certId of loxilb's backend client cert+key (empty ⇒ none)

  // Padding for 8-byte alignment (structure size validation)
  uint8_t _pad_mtls[6];
#endif /* HAVE_MTLS */
};
typedef struct proxy_arg proxy_arg_t;

// Ensure structure doesn't exceed eBPF map limits (critical for kernel compatibility)
_Static_assert(sizeof(struct proxy_arg) <= 4096, 
              "proxy_arg_t exceeds eBPF map value size limit");

typedef int (*sockmap_cb_t)(struct llb_sockmap_key *key, int fd, int doadd);
typedef void (*proxy_info_cb_t)(struct dp_proxy_ct_ent *pct);
int proxy_find_ep(uint32_t xip, uint16_t xport, uint8_t protocol,
                  uint32_t *epip, uint16_t *epport, uint8_t *epprotocol);
int proxy_add_entry(struct proxy_ent *new_ent, struct proxy_arg *arg);
int proxy_delete_entry(struct proxy_ent *ent, struct proxy_arg *arg);
int proxy_update_ep_health(struct proxy_ent *key, int ep_index, uint8_t inactive);
int proxy_update_ep_health_by_ip(struct proxy_ent *key, uint32_t ep_ip, uint8_t inactive);

/* Synchronous single-writer setter for the per-entry kv_exact_contract
 * word (pattern: proxy_update_ep_health). Packs
 * [binding_gen:32|flags=0:16|api_mode:8|eligible:8], stores with release
 * ordering and reads the word back into *applied — the caller's ACK is
 * (return == 0 && *applied == the requested word). binding_gen 0 is refused
 * (reserved as "no contract"); there is deliberately NO way to return an
 * entry to the legacy zero word short of entry teardown. */
int proxy_update_kv_exact_contract(struct proxy_ent *key, uint32_t binding_gen,
                                   uint8_t api_mode, uint8_t eligible,
                                   uint64_t *applied);
int proxy_set_drain_policy(struct proxy_ent *key, drain_policy_t policy, uint32_t timeout_sec);
/* Tier-1 byte shaper control. Rates arrive in bits/sec (the policer API's
 * native unit) and are converted to bytes/sec at store time. cir_bps == 0
 * detaches: the stored config is cleared and any live entry stops shaping.
 * Config is stored independently of entry existence, so a policy created
 * before its LB rule converges when the rule appears (proxy_add_entry). */
int proxy_update_qos_config(struct proxy_ent *key, uint64_t cir_bps,
                            uint64_t pir_bps, uint32_t cbs_bytes,
                            uint8_t dir, uint8_t mode);
/* Notifier tick hook: refills active shaper buckets and wakes parked fds
 * whose bucket regained tokens. Internally rate-limited; called from every
 * notify worker's poll loop. */
void proxy_qos_tick(int thread);
int proxy_set_circuit_breaker(struct proxy_ent *key, uint8_t enabled, 
                                uint32_t failure_threshold, uint32_t open_timeout_sec);

#ifdef HAVE_MTLS
// ============================================================================
// mTLS Configuration API 
// ============================================================================

// proxy_config_mtls_frontend - Configure frontend (client-facing) mTLS
// @service_id: Service identifier (proxy_arg_t._id)
// @client_cert_mode: 0=disabled, 1=optional, 2=required
// @client_ca_path: Path to client CA bundle (must exist on filesystem)
// @require_client_cn: Whether to enforce CN pattern matching (0=no, 1=yes)
// @client_cn_pattern: CN pattern for validation (e.g., "*.corp.example.com"), NULL if not needed
//
// Returns: 0 on success, negative error code on failure
int proxy_config_mtls_frontend(uint32_t service_id, uint8_t client_cert_mode,
                                const char *client_ca_path, uint8_t require_client_cn,
                                const char *client_cn_pattern);

// proxy_config_mtls_backend - Configure backend (upstream) mTLS
// @service_id: Service identifier
// @verify_cert: 0=no verification (SSL_VERIFY_NONE), 1=verify (SSL_VERIFY_PEER)
// @backend_ca_path: Path to backend CA bundle (NULL uses system CA store)
// @client_cert_path: Path to loxilb's client certificate (NULL if not needed)
// @client_key_path: Path to loxilb's private key (NULL if not needed)
//
// Returns: 0 on success, negative error code on failure
int proxy_config_mtls_backend(uint32_t service_id, uint8_t verify_cert,
                               const char *backend_ca_path,
                               const char *client_cert_path,
                               const char *client_key_path);

// proxy_clear_mtls_config - Clear mTLS configuration for a service
// @service_id: Service identifier
//
// Returns: 0 on success, negative error code on failure
int proxy_clear_mtls_config(uint32_t service_id);
#endif /* HAVE_MTLS */

// PHASE 1: CHWBL Dynamic Prefix Hash Configuration API
int proxy_set_chwbl_prefix_config(struct proxy_ent *key,
                                    uint32_t level,
                                    uint32_t flags,
                                    uint8_t enable_cache_salt);
void proxy_dump_entry(proxy_info_cb_t);
void proxy_get_entry_stats(uint32_t id, int epid, uint64_t *p, uint64_t *b);
void pfe_ent_accouting(proxy_fd_ent_t *pfe, uint64_t bc, int txdir);
int proxy_main(sockmap_cb_t cb, int ktls_enabled);

// SNI Certificate Management API (Global Certificate Store)
// These manage certificates independently of loadbalancer rules
int proxy_add_sni_certificate(const char *hostname, const char *cert_path);
int proxy_remove_sni_certificate(const char *hostname);
int proxy_list_sni_certificates(void (*callback)(const char *hostname, void *data),
                                void *user_data);
int proxy_list_sni_certificates_with_path(void (*callback)(const char *hostname, const char *cert_path, void *data),
                                          void *user_data);
void *proxy_get_ssl_ctx_for_hostname(const char *hostname);  // Internal: SNI lookup

// ============================================================================
// Internal Functions Used by HTTP/2 Module (sockproxy_h2.c)
// ============================================================================
int proxy_select_ep(proxy_fd_ent_t *pfe, void *inbuf, size_t insz, int *ep);
int proxy_setup_ep_connect(uint32_t epip, uint16_t epport, uint8_t protocol,
                            void *ssl_ctx, void **ssl, proxy_fd_ent_t *pfe,
                            const void *pp2hdr, int pp2len);
/* Build a 28-byte IPv4 PROXY protocol v2 header (args in network byte order). */
int proxy_build_ppv2_v4(uint8_t *buf, size_t bufsz, uint32_t sip, uint16_t sport,
                        uint32_t dip, uint16_t dport);
int is_endpoint_healthy(proxy_epval_t *tepval, int ep_idx);
int find_next_healthy_endpoint(proxy_epval_t *tepval, int start_idx);
int select_healthy_endpoint(proxy_epval_t *tepval, int algorithm_selection);
void circuit_breaker_record_failure(proxy_epval_t *tepval, int ep_index);
void circuit_breaker_record_success(proxy_epval_t *tepval, int ep_index);
void circuit_breaker_record_origin_error(proxy_epval_t *tepval, int ep_index);
void circuit_breaker_record_origin_success(proxy_epval_t *tepval, int ep_index);
int chwbl_ring_lookup(chwbl_ring_t *ring, uint64_t hash);
uint64_t compute_prefix_hash(llm_prefix_key_t *key);
int extract_llm_prefix(const char *json_str, size_t json_len, llm_prefix_key_t *key);
conversation_mapping_t* get_conversation_mapping(proxy_map_ent_t *ent, const char *conv_id);
int store_conversation_endpoint(proxy_map_ent_t *ent, const char *conv_id, int ep_idx);
void strip_port_from_hostname(const char *host_with_port, char *host_only, size_t host_only_size);

// P/D Session stickiness functions (Tier 0 cache-aware routing)
int  pd_session_lookup(proxy_epval_t *tepval, const char *key, int *prefill_ep, int *decode_ep);
void pd_session_store(proxy_epval_t *tepval, const char *key, int prefill_ep, int decode_ep);
void pd_session_evict(proxy_epval_t *tepval);
void pd_session_evict_key(proxy_epval_t *tepval, const char *key);

/* 3-tier P/D selection (sockproxy_pd.c) -- 
 * excluded_mask: bitmask of EP indices to skip (0 = no exclusions).
 * Used by mid-cycle failover to retry with a different prefill EP after TCP
 * connect failure, without waiting for the 60-second health-check cycle.
 * Returns 0 on success (*ep_out set), -1 if no healthy prefill EP, or
 * PD_PREFILL_NO_CAPACITY when ALL healthy prefill EPs are at the
 * in-flight admission cap (LLB_PD_MAX_INFLIGHT_PER_EP) -> caller sheds 429. */
#ifndef PD_PREFILL_NO_CAPACITY
#define PD_PREFILL_NO_CAPACITY (-2)
#endif
/* bounded backpressured admission. When ALL healthy prefill EPs are
 * at the in-flight cap AND a per-EP parked FIFO still has room, pd_select_prefill
 * ENQUEUES the request (hold-don't-drop, vllm-router parity) and returns
 * PD_PREFILL_PARKED instead of shedding a 429. The caller (proxy_setup_ep__ ->
 * setup_proxy_path) then SUSPENDS the client fd (EPOLLIN-pause) and holds it open;
 * it is NOT connected and does NOT charge active_conns. 429 (PD_PREFILL_NO_CAPACITY)
 * fires ONLY on FIFO overflow. Gated by LLB_PD_QUEUE_DEPTH_PER_EP (default-off:
 * unset/0 -> the all-capped branch returns PD_PREFILL_NO_CAPACITY exactly as today). */
#ifndef PD_PREFILL_PARKED
#define PD_PREFILL_PARKED (-3)
#endif
/* setup_proxy_path / proxy_setup_ep__ return contract. They return
 * 0 = wired, -1 = error (caller tears down/closes the fd). PD_SETUP_PARKED is a
 * THIRD outcome: the request was enqueued + the client fd EPOLLIN-suspended and
 * held open — the caller MUST keep the fd (do NOT forward to a backend, do NOT
 * close). Distinct positive sentinel so it never collides with the -1 error path. */
#ifndef PD_SETUP_PARKED
#define PD_SETUP_PARKED (2)
#endif
int pd_select_prefill(proxy_epval_t *tepval, proxy_fd_ent_t *pfe, int *ep_out,
                      uint32_t excluded_mask);
/* bounded-admission FIFO dequeue/reap primitives (sockproxy_pd.c).
 * Pure ring ops on ONE pd_parked_fifo_t — the CALLER must hold tepval->pd_parked_lock.
 * They never touch a pfe, never free, never dispatch (UAF-critical re-drive/teardown
 * stays in the caller, on the pinned owner / via pd_teardown_conn). pop_head/peek_head
 * act on the oldest entry; remove_fd drops a specific (fd[,gen]) entry FIFO-order-safe. */
int pd_parked_pop_head(pd_parked_fifo_t *q, pd_parked_ent_t *out);
int pd_parked_peek_head(const pd_parked_fifo_t *q, pd_parked_ent_t *out);
int pd_parked_remove_fd(pd_parked_fifo_t *q, int want_fd, uint64_t want_gen);
/* runtime max-park bound (env LLB_PD_MAX_PARK_SEC; 0/unset = reap off). */
uint32_t pd_max_park_sec(void);
/* runtime per-EP parked-FIFO depth (env LLB_PD_QUEUE_DEPTH_PER_EP;
 * 0/unset = bounded-admission OFF). The pd_cleanup dequeue hook gates on this. */
uint32_t pd_queue_depth_per_ep(void);
/* : global total in-flight+queued footprint bound (env
 * LLB_PD_MAX_TOTAL_INFLIGHT; 0/unset = ingress backpressure OFF, accept() byte-
 * identical). Mirrors pd_max_park_sec (getenv-once, __atomic-cached). */
uint32_t pd_max_total_inflight(void);
/* : the pure accept-gate decision, factored out so it can be
 * unit-tested in isolation. Returns 1 = ACCEPT (under bound or feature off),
 * 0 = REFUSE (at/over the bound — leave the SYN in the listen backlog). bound==0
 * (feature off) always ACCEPTs. */
int pd_admission_should_accept(uint64_t cur_inflight, uint32_t bound);
int pd_select_decode(proxy_epval_t *tepval, proxy_fd_ent_t *pfe, int *ep_out);
int pd_select_any_healthy(proxy_epval_t *tepval, int *ep_out);

/* Radix trie API (sockproxy_pd_trie.c) -- NOT thread-safe, caller must hold pd_trie_lock */
pd_trie_t *pd_trie_create(void);
void        pd_trie_free(pd_trie_t *t);
int         pd_trie_match(pd_trie_t *t, const char *text, size_t len,
                           int *ep_idx_out, float *match_rate_out);
void        pd_trie_insert(pd_trie_t *t, const char *text, size_t len, int ep_idx);
void        pd_trie_remove_ep(pd_trie_t *t, int ep_idx);
size_t      pd_trie_node_count(pd_trie_t *t);
void        pd_trie_evict_lru(pd_trie_t *t, size_t max_nodes);

// P6: Path-based routing helper (exported for HTTP/2 module)
proxy_epval_t* find_endpoint_lpm(proxy_map_ent_t *ent,
                                  const char *host,
                                  const char *request_path,
                                  const char *model_name);

// Event loop management wrappers (for HTTP/2 backend registration)
int proxy_notify_add_fd(int fd, int type, void *priv);
int proxy_notify_delete_fd(int fd, int evict);


// ============================================================================
// GPU-Aware Routing Configuration (guarded by HAVE_DP_GPU_ROUTING)
// ============================================================================
#ifdef HAVE_DP_GPU_ROUTING

/* GPU-Aware Routing Configuration */

// DEFAULT scoring weights (used when catalog not found - fallback only)
// These match the "default" catalog for backward compatibility.
// NOTE (C2 / ): these are now ALSO defined unconditionally near the
// PROXY_SEL_* block above so the GPU-aware prefill scorer compiles on the
// default build; the #ifndef guards keep both definitions consistent.
#ifndef DEFAULT_QUEUE_WEIGHT
#define DEFAULT_QUEUE_WEIGHT               50
#endif
#ifndef DEFAULT_SWAP_WEIGHT
#define DEFAULT_SWAP_WEIGHT                30
#endif
#ifndef DEFAULT_KV_CACHE_WEIGHT
#define DEFAULT_KV_CACHE_WEIGHT            20
#endif

// DEFAULT overload thresholds (used when catalog not specified)
#define DEFAULT_QUEUE_OVERLOAD_THRESHOLD   10
#define DEFAULT_QUEUE_RECOVERY_THRESHOLD   5
#define DEFAULT_KV_CACHE_OVERLOAD_THRESHOLD 95
#define DEFAULT_KV_CACHE_RECOVERY_THRESHOLD 70
#define DEFAULT_RECOVERY_GRACE_PERIOD_SEC  3

// Note: METRICS_STALENESS_SEC is defined in llb_dpapi.h

#endif /* HAVE_DP_GPU_ROUTING */

// ============================================================================
// PII DETECTION: Presidio Integration (Feature Flag)
// ============================================================================
#ifdef HAVE_PII_DETECTION
#include "sockproxy_presidio.h"

// CGO Export Functions for dynamic control
// Configuration is managed via REST API → Shared Memory (presidio_config.h)
int lxb_presidio_enable(void);
int lxb_presidio_disable(void);
int lxb_presidio_is_enabled(void);
int lxb_presidio_configure_params(const char *analyzer_url, const char *anonymizer_url,
                                   uint8_t mode, uint8_t direction, 
                                   double threshold, uint32_t timeout_ms);
char* lxb_presidio_get_stats_json(void);
void lxb_presidio_free_json(char *json);
#else
// Stub implementations when HAVE_PII_DETECTION not defined
static inline int lxb_presidio_enable(void) { return -1; }
static inline int lxb_presidio_disable(void) { return -1; }
static inline int lxb_presidio_is_enabled(void) { return 0; }
#endif /* HAVE_PII_DETECTION */

// L7 Metrics: Always-available timestamp (implementation at sockproxy.c:6974)
uint64_t get_timestamp_ns(void);

// ============================================================================
// HTTP/HTTPS TRACE FUNCTIONS (shared between sockproxy.c and sockproxy_h2.c)
// ============================================================================
#ifdef HAVE_HTTP_TRACE
int is_tracing_enabled(void);
void emit_trace_event(proxy_fd_ent_t *pfe, uint8_t event_type, uint32_t duration_us);
#endif

#endif
