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
 * any other value -> 0. Called from proxy_get_metrics only.
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
