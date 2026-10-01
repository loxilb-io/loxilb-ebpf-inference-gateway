/*
 * Copyright (c) 2024 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */
#ifndef __SOCKPROXY_METRICS_H__
#define __SOCKPROXY_METRICS_H__

/*
 * sockproxy_metrics.h - Prometheus / observability metrics export interface.
 *
 * This is the CANONICAL C-side definition of proxy_metrics_snapshot_t.
 * ABI SYNC REQUIRED: when modifying this struct also update
 * api/prometheus/sockproxy_metrics.go inline CGO definition.
 * See sockproxy_refactoring_plan.md §3.P7
 */

#include <stddef.h>
#include <stdint.h>

/* =========================================================================
 * proxy_metrics_snapshot_t - snapshot returned to Go CGO on each scrape.
 *
 * FIELD ORDER MUST MATCH api/prometheus/sockproxy_metrics.go CGO block.
 * Add new fields at the END only; never reorder or change field types.
 * ========================================================================= */
typedef struct proxy_metrics_snapshot {
    /* Gauges (point-in-time counts) */
    uint64_t active_connections;
    uint64_t active_ssl_connections;
    uint64_t cache_backpressure_active;
    uint64_t conversation_sessions;
    uint64_t h2_sessions;

    /* Counters (cumulative atomics) */
    uint64_t cache_high_water_events;
    uint64_t conversation_hits;
    uint64_t conversation_misses;
    uint64_t h2_total_streams;
    uint64_t chunked_responses;
    uint64_t cache_drain_partial;
    uint64_t peer_eof_graceful;
    uint64_t conversation_ttl_expired;

    /* L7 Metrics: HTTP Response Counters */
    uint64_t http_responses_total;
    uint64_t http_status_2xx;
    uint64_t http_status_3xx;
    uint64_t http_status_4xx;
    uint64_t http_status_5xx;

    /* L7 Metrics: TTFB Latency Histogram (C-side buckets) */
    uint64_t latency_bucket[12];
    uint64_t latency_sum_us;
    uint64_t latency_count;

    /* Histograms (samples - simplified for) */
    uint64_t cache_size_samples[100]; /* Last 100 connections */
    uint32_t cache_size_sample_count;

    /* CHWBL load imbalance (optional - GPU routing) */
    float chwbl_load_imbalance_ratio;

    /* P/D Buffer: kv_transfer_params overflow counter */
    uint64_t pd_kv_params_overflow;

    /* P/D Production Hardening gauges */
    uint64_t pd_sessions_active;            /* OBS-01: Active P/D sessions */
    uint64_t pd_trie_nodes;                 /* OBS-01: Prefix trie node count */
    uint64_t pd_cb_flips;                   /* OBS-03: Circuit breaker state transitions */
    uint64_t pd_fallback_to_normal;         /* RES-02: Non-P/D fallback count */

    /* KV Tier 1.5 routing diagnostics (per-guard miss + fallthrough). */
    /* Storage allocated in plan 42-01; incremented in plan 42-02. */
    uint64_t pd_kv_t15_miss_mode_off;
    uint64_t pd_kv_t15_miss_warmup;
    uint64_t pd_kv_t15_miss_text_empty;
    uint64_t pd_kv_t15_miss_model_empty;
    uint64_t pd_kv_t15_miss_tokenize;
    uint64_t pd_kv_t15_miss_hashes;
    uint64_t pd_kv_t15_miss_no_worker;
    uint64_t pd_kv_t15_miss_excluded;
    uint64_t pd_kv_t15_miss_shallow;
    /* Contract-gate + typed-bridge miss classes (lockstep with
     * sockproxy.h atomics and the Go CGO mirror). */
    uint64_t pd_kv_t15_miss_not_ready;
    uint64_t pd_kv_t15_miss_api_mode;
    uint64_t pd_kv_t15_miss_unsupported;
    uint64_t pd_kv_t15_miss_runtime_fault;
    uint64_t pd_kv_t15_fallthrough_total;

    /* (OBS-01): CB proactive heal  + per-EP admission layer
 * counters. TAIL-APPEND ONLY — twin-declared in the cgo preamble
     * of api/prometheus/sockproxy_metrics.go; keep BOTH in lockstep, same commit. */
    uint64_t pd_cb_proactive_heal;
    uint64_t pd_admission_shed;
    uint64_t pd_admission_queued;

    /* Failover observability counters. TAIL-APPEND ONLY — twin-declared in
     * the cgo preamble of api/prometheus/sockproxy_metrics.go AND in
     * api/prometheus/proxy_metrics_stub.c; keep ALL THREE in lockstep,
     * same commit. */
    uint64_t pd_prefill_ep_died;
    uint64_t pd_decode_ep_died;
    uint64_t pd_decode_zero_byte_eof;
    uint64_t pd_connect_failover;
    uint64_t lb_select_failure_shutdown;

    /* SGLang P/D dual-dispatch counters. TAIL-APPEND ONLY — twin-declared in
     * the cgo preamble of api/prometheus/sockproxy_metrics.go AND in
     * api/prometheus/proxy_metrics_stub.c; keep ALL THREE in lockstep,
     * same commit. */
    uint64_t pd_sg_prefill_abort_decode;
    uint64_t pd_sg_decode_close_drain;
    uint64_t pd_sg_room_retry;
    uint64_t pd_sg_prefill_reject_relay;
    uint64_t pd_sg_oversize_reject;

    /* TRT-LLM sequential-dialect counters. TAIL-APPEND ONLY — same
     * three-way lockstep contract as the SGLang block above. */
    uint64_t pd_trt_ctx_early_exit;

    /* Relay-cache footprint gauges. The backpressure watermark is per
     * connection (PROXY_CACHE_HIGH_WATER), so nothing reports what the
     * process is holding in aggregate; these do. TAIL-APPEND ONLY — same
     * three-way lockstep contract as the blocks above. */
    uint64_t cache_bytes_total;
    uint64_t cache_bytes_max_conn;
    uint64_t cache_conns_queued;

    /* Same-EP reconnect counters (transient backend connect failure on an
     * affinity-bearing service; see pd_connect_retry_budget in sockproxy.h).
     * TAIL-APPEND ONLY — same three-way lockstep contract as the blocks
     * above. */
    uint64_t pd_connect_retry_same_ep;
    uint64_t pd_connect_retry_same_ep_ok;

    /* Bounded-admission overflow shed (parked FIFO full on every eligible
     * EP -> 429). With LLB_PD_QUEUE_DEPTH_PER_EP > 0 the plain-shed branch
     * is unreachable and this valve is the ONLY shed that can fire, so
     * without this field every overload drop is invisible to /metrics.
     * TAIL-APPEND ONLY — same three-way lockstep contract as the blocks
     * above. */
    uint64_t pd_admission_overflow_shed;

    /* Client connections dropped for not completing their request headers
     * within the listener's deadline (read path and health pass). TAIL-APPEND
     * ONLY — same three-way lockstep contract as the blocks above. */
    uint64_t hdr_deadline_drops;

    /* The process accept valve (LLB_PD_MAX_TOTAL_INFLIGHT): connection
     * contexts held (a gauge, backend legs included; counted only while the
     * bound is set, 0 otherwise), accept()s it held back
     * (a counter), and the bound (0 = unbounded). TAIL-APPEND ONLY — same
     * three-way lockstep contract as the blocks above. */
    uint64_t proxy_context_inflight;
    uint64_t proxy_accept_blocked;
    uint64_t proxy_accept_bound;

    /* Half-close observation (sockproxy_hc.c). The dimensions are the enums
     * of sockproxy_hc_core.h, spelled as numbers because the Go mirror reads
     * them; sockproxy_hc.c holds them to the enums at compile time. Buckets
     * are cumulative, the bounds are hc_fin_bounds_us / hc_prog_bounds_us,
     * and the count includes samples past the last bound. TAIL-APPEND ONLY —
     * same three-way lockstep contract as the blocks above. */
    uint64_t hc_fin_gap_bucket[4][3][15];   /* [entry][stream][bound] */
    uint64_t hc_fin_gap_sum_us[4][3];
    uint64_t hc_fin_gap_count[4][3];
    uint64_t hc_fin_total[7][6];            /* [entry][outcome] */
    uint64_t hc_accel_early_fin;
    uint64_t hc_tls_fin[3][2];              /* [path][early and owed] */
    uint64_t hc_client_reset;
    uint64_t hc_user_agent[13];             /* [family] */
    uint64_t hc_first_gap_bucket[3][15];    /* [stream][bound] */
    uint64_t hc_first_gap_sum_us[3];
    uint64_t hc_first_gap_count[3];
    uint64_t hc_max_gap_bucket[3][15];      /* [stream][bound] */
    uint64_t hc_max_gap_sum_us[3];
    uint64_t hc_max_gap_count[3];
} proxy_metrics_snapshot_t;

/* =========================================================================
 * Public API
 * ========================================================================= */

/*
 * proxy_get_metrics - export a snapshot of all current metrics.
 * Called by Go CGO (api/prometheus/sockproxy_metrics.go).
 */
proxy_metrics_snapshot_t proxy_get_metrics(void);

/*
 * pd_admission_stats_get - read-only accessor for the Phase-93 file-static
 * admission counters in sockproxy_pd.c (OBS-01 export).
 * which==0 -> pd_admission_shed_total, which==1 -> pd_admission_queued_total,
 * which==2 -> pd_admission_overflow_shed_total, any other value -> 0.
 * Called from proxy_get_metrics only.
 */
uint64_t pd_admission_stats_get(int which);

/* =========================================================================
 * Tier-1 byte-shaper (QoS) per-service statistics.
 *
 * FIELD ORDER AND PADDING MUST MATCH the CGO block in
 * api/prometheus/qos_shaper_metrics.go AND the weak stub in
 * api/prometheus/proxy_metrics_stub.c. Three-way lockstep, same commit —
 * tail-append only.
 *
 * Direction-indexed arrays: index 0 = upload (client->backend, QOS_DIR_UPLOAD),
 * index 1 = download (backend->client, QOS_DIR_DOWNLOAD). A direction the
 * config leaves un-shaped reports zeros; its bit is absent from `dir`.
 *
 * Byte units are PLAINTEXT payload bytes (post-decrypt), never the Tier-0
 * eBPF policer's L3 wire bytes — the two must never be summed or compared.
 * ========================================================================= */
#define PROXY_QOS_STAT_MAX 256   /* services reported per proxy_get_qos_stats call */

typedef struct proxy_qos_svc_stat {
    uint32_t xip;              /* service VIP, network byte order (v4) */
    uint16_t xport;            /* service port, HOST byte order */
    uint8_t  protocol;         /* IPPROTO_* */
    uint8_t  dir;              /* QOS_DIR_* bitmask in force */
    uint64_t cir_bps;          /* committed rate, BYTES/sec */
    uint32_t cbs_bytes;        /* effective burst depth */
    uint32_t n_parked[2];      /* gauge: readers parked right now */
    uint32_t pad;
    uint64_t bytes_pass[2];    /* counter: payload bytes granted by the bucket */
    uint64_t bytes_delayed[2]; /* counter: bytes that waited >=1 park/resume */
    uint64_t parks[2];         /* counter: park events */
    uint64_t park_ns[2];       /* counter: summed park->resume wall time (ns) */
    int64_t  tokens[2];        /* gauge: bucket level in bytes */
} proxy_qos_svc_stat_t;

/*
 * proxy_get_qos_stats - fill `out` with one entry per service that currently
 * has the Tier-1 shaper enabled (cir_bps != 0). Returns the number of entries
 * written, capped at `max`; 0 when no service is shaped. Called by Go CGO
 * (api/prometheus/qos_shaper_metrics.go) off the hot path.
 */
int proxy_get_qos_stats(proxy_qos_svc_stat_t *out, int max);

/* =========================================================================
 * AI admission gate (capacity) per-pool statistics.
 *
 * FIELD ORDER AND PADDING MUST MATCH the CGO block in
 * api/prometheus/ai_admission_metrics.go AND the weak stub in
 * api/prometheus/proxy_metrics_stub.c. Three-way lockstep, same commit --
 * tail-append only.
 *
 * One row per model pool of an AI-gateway service, whatever the gate's mode:
 * a pool with the gate off reports mode 0 and zero counts, so a scrape can
 * tell "not enforcing" from "not an AI service". Role index 0 = normal,
 * 1 = prefill, 2 = decode (enum fc_role); reason index follows enum
 * fc_reason. Both counts are pinned by static asserts where the enums are
 * visible.
 * ========================================================================= */
#define PROXY_FC_STAT_MAX 256   /* pools reported per proxy_get_fc_stats call */
#define PROXY_FC_ROLES 3
#define PROXY_FC_REASONS 12     /* enum fc_reason: the decisions array grew with the queue reasons */
#define PROXY_FC_POOL_LEN 64    /* pool key as exported; longer keys are cut */
#define PROXY_FC_QWAIT_BUCKETS 8 /* queue wait histogram buckets (FC_QWAIT_BUCKETS) */
#define PROXY_FC_LIMITS 8        /* configured limits with a source, first block */
#define PROXY_FC_ADAPT_LIMITS 3  /* adaptive, warm-up, TTFT target: FC_LIMITS is the sum */

typedef struct proxy_fc_svc_stat {
    uint32_t xip;                          /* service VIP, network byte order (v4) */
    uint16_t xport;                        /* service port, HOST byte order */
    uint8_t  protocol;                     /* IPPROTO_* */
    uint8_t  mode;                         /* enum fc_mode: 0 off, 1 observe, 2 enforce */
    uint32_t max_outstanding;              /* service ceiling, 0 = unlimited */
    uint32_t ep_cap[PROXY_FC_ROLES];       /* per-endpoint ceiling per role */
    uint32_t inflight;                     /* gauge: service units held */
    uint32_t ep_inflight[PROXY_FC_ROLES];  /* gauge: endpoint units held, summed per role */
    uint64_t decisions[PROXY_FC_REASONS];  /* counter per enum fc_reason */
    char     pool[PROXY_FC_POOL_LEN];      /* pool key ("host|path" or "host"), NUL-terminated */
    /* The bounded queue: same three-way lockstep, offsets pinned below. */
    uint32_t queued;                       /* gauge: requests waiting for a unit */
    uint32_t max_queue_depth;              /* the depth in force, 0 = no waiting */
    uint32_t max_queue_wait_ms;            /* the wait window in force */
    uint32_t pad;
    uint64_t qwait_bucket[PROXY_FC_QWAIT_BUCKETS]; /* histogram: waits in (bound[i-1], bound[i]] ms */
    uint64_t qwait_sum_ms;                 /* histogram: summed wait of every resumed request */
    uint64_t qwait_count;                  /* histogram: resumed requests */
    /* The rule's configuration read-back: same lockstep, offsets pinned below. */
    uint32_t telemetry_stale_ms;           /* scraped queue depth trusted this long */
    uint8_t  src[PROXY_FC_LIMITS];         /* enum fc_src per enum fc_limit: 0 default, 1 env, 2 rule */
    uint32_t pad2;
    /* The adaptive ceiling and the warm-up: same lockstep, offsets pinned below. */
    uint32_t effective_max_outstanding;    /* the service ceiling in force (the adaptive one while adapting) */
    uint32_t warmup_ms;                    /* endpoint warm-up window, 0 = none */
    uint32_t ttft_target_ms;               /* TTFT above this is backpressure, 0 = TTFT unused */
    uint8_t  adaptive;                     /* 1 when the ceiling adapts */
    uint8_t  adapt_state;                  /* enum fc_adapt_state: 0 off, 1 open, 2 tightened, 3 frozen */
    uint8_t  adapt_reason;                 /* enum fc_adapt_reason: 0 none, 1 queued, 2 ttft, 3 clear, 4 stale */
    uint8_t  src_adapt[PROXY_FC_ADAPT_LIMITS]; /* sources of adaptive, warmup_ms, ttft_target_ms */
    uint16_t warming_eps;                  /* gauge: endpoints inside their warm-up window */
    uint64_t adapt_down;                   /* counter: times the adaptive ceiling went down */
    uint64_t adapt_up;                     /* counter: times it went up */
} proxy_fc_svc_stat_t;

/* The Go collector reads this struct through cgo from its own copy of this
 * definition, and its test links a stub with a third: all three pin the
 * same layout, so a field moved in one without the others fails to build
 * instead of shifting every counter after it. */
_Static_assert(sizeof(proxy_fc_svc_stat_t) == 352, "proxy_fc_svc_stat_t size");
_Static_assert(offsetof(proxy_fc_svc_stat_t, decisions) == 40, "decisions offset");
_Static_assert(offsetof(proxy_fc_svc_stat_t, pool) == 136, "pool offset");
_Static_assert(offsetof(proxy_fc_svc_stat_t, queued) == 200, "queued offset");
_Static_assert(offsetof(proxy_fc_svc_stat_t, qwait_bucket) == 216, "qwait_bucket offset");
_Static_assert(offsetof(proxy_fc_svc_stat_t, qwait_count) == 288, "qwait_count offset");
_Static_assert(offsetof(proxy_fc_svc_stat_t, telemetry_stale_ms) == 296, "telemetry_stale_ms offset");
_Static_assert(offsetof(proxy_fc_svc_stat_t, src) == 300, "src offset");
_Static_assert(offsetof(proxy_fc_svc_stat_t, effective_max_outstanding) == 312,
               "effective_max_outstanding offset");
_Static_assert(offsetof(proxy_fc_svc_stat_t, adaptive) == 324, "adaptive offset");
_Static_assert(offsetof(proxy_fc_svc_stat_t, warming_eps) == 330, "warming_eps offset");
_Static_assert(offsetof(proxy_fc_svc_stat_t, adapt_down) == 336, "adapt_down offset");

/*
 * proxy_get_fc_stats - fill `out` with one entry per model pool of every
 * AI-gateway service. Returns the number of entries written, capped at
 * `max`; 0 when no AI service exists. Called by Go CGO
 * (api/prometheus/ai_admission_metrics.go) off the hot path.
 */
int proxy_get_fc_stats(proxy_fc_svc_stat_t *out, int max);

/*
 * proxy_get_fc_anomaly - the process-wide anomaly counter for `kind`
 * (enum fc_anomaly: 0 underflow, 1 unknown_permit); 0 for any other kind.
 */
uint64_t proxy_get_fc_anomaly(int kind);

/*
 * proxy_get_fc_state - the gate state of ONE rule's pool (the service key
 * plus the pool key the rule's host, path prefix and model resolve to),
 * for the configuration read-back. 0 with `out` filled, -1 when no such
 * pool exists. Called by Go CGO off the hot path.
 */
struct proxy_ent;
int proxy_get_fc_state(struct proxy_ent *key, const char *host_url,
                       const char *path_prefix, const char *model_name,
                       proxy_fc_svc_stat_t *out);

/*
 * proxy_get_fc_inflight_total - executing inference requests across every
 * gated pool, for the maintenance drain read-back.
 */
uint64_t proxy_get_fc_inflight_total(void);

/*
 * proxy_fc_drain_set - enter (1) or leave (0) the process-wide drain: while
 * set, new inference requests are refused and every pool's queue is ended.
 * Executing requests finish on their own.
 */
void proxy_fc_drain_set(int on);

/*
 * proxy_set_service_catalog - associate catalog_id with a service entry.
 * Called from Go to enable deep inspection for a specific service.
 */
int proxy_set_service_catalog(uint32_t xip, uint16_t xport, uint8_t protocol,
                               uint16_t catalog_id);

/*
 * record_latency_sample - record one TTFB latency sample into global_stats.
 * Called from proxy_try_epxmit (sockproxy.c / future sockproxy_http.c).
 * Not static: callers in multiple TUs.
 */
void record_latency_sample(uint64_t latency_us);

#ifdef HAVE_DP_GPU_ROUTING
/*
 * pd_kv_overflow_inc - increment the P/D KV-cache parameter overflow counter.
 * Called when KV cache routing parameters exceed available capacity.
 */
void pd_kv_overflow_inc(void);
#endif /* HAVE_DP_GPU_ROUTING */

#endif /* __SOCKPROXY_METRICS_H__ */
