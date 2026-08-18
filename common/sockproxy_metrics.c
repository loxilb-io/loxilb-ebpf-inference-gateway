/*
 * Copyright (c) 2024 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */

/*
 * sockproxy_metrics.c - Prometheus metrics collection and global statistics.
 *
 * Moved from sockproxy.c section 5 (lines ~305-515 in the original monolith).
 * See sockproxy_refactoring_plan.md §6.8 and §3.P7.
 *
 * Contents:
 *   - global_stats authoritative definition
 *   - proxy_set_service_catalog (catalog deep-inspection API)
 *   - proxy_get_metrics (CGO export to Go prometheus scraper)
 *   - record_latency_sample (TTFB histogram helper)
 */

/* Standard library */
#include <stdatomic.h>
#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/* uthash MUST precede sockproxy.h (provides UT_hash_handle, HASH_COUNT) */
#include "uthash.h"

/* Logging */
#include "log.h"

/* Internal shared types */
#include "sockproxy_internal.h"    /* proxy_struct_t, proxy_struct, PROXY_LOCK */
#include "sockproxy_metrics.h"
#include "sockproxy_kv_exact.h"    /* KV_STAGE_* enum + record_kv_stage contract */

/* =========================================================================
 * Internal forward declarations
 * ========================================================================= */

/*
 * cmp_proxy_ent - compare two proxy_ent_t for equality (xip/xport/proto).
 * Defined (non-static) in sockproxy.c; moves to sockproxy_conn.c in.
 * See sockproxy_refactoring_plan.md §6.2
 */
bool cmp_proxy_ent(proxy_ent_t *e1, proxy_ent_t *e2);

/* =========================================================================
 * Global statistics authoritative definition.
 * Declared extern in sockproxy.h so all TUs that include sockproxy.h
 * can write counters via atomic_fetch_add without an additional include.
 * ========================================================================= */
proxy_global_stats_t global_stats = {0};

/* P/D buffer overflow counter increment — called from sockproxy_pd.c */
void pd_kv_overflow_inc(void) {
  atomic_fetch_add(&global_stats.pd_kv_params_overflow, 1);
}

/* =========================================================================
 * Catalog / deep-inspection API
 * ========================================================================= */

/*
 * proxy_set_service_catalog - associate catalog_id with a service entry.
 * Called from Go CGO to arm per-service deep inspection.
 */
int proxy_set_service_catalog(uint32_t xip, uint16_t xport, uint8_t protocol,
                               uint16_t catalog_id) {
  if (!proxy_struct) {
    log_error("[CATALOG] proxy_struct not initialized");
    return -1;
  }

  proxy_ent_t key = {0};
  key.xip = xip;
  key.xport = xport;
  key.protocol = protocol;

  PROXY_LOCK();
  proxy_map_ent_t *node = proxy_struct->head;
  while (node) {
    if (cmp_proxy_ent(&node->key, &key)) {
      node->catalog_id = catalog_id;
      PROXY_UNLOCK();
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("[CATALOG] Set catalog_id=%d for service %08x:%04x proto=%d",
                catalog_id, xip, xport, protocol);
#endif
      return 0;
    }
    node = node->next;
  }
  PROXY_UNLOCK();

  log_error("[CATALOG] Service not found: %08x:%04x proto=%d", xip, xport, protocol);
  return -1;
}

/* =========================================================================
 * Prometheus metrics export
 * ========================================================================= */

/*
 * proxy_get_metrics - return a flat snapshot of all runtime counters and gauges.
 * Called by Go CGO (api/prometheus/sockproxy_metrics.go) on every scrape cycle.
 *
 * ABI contract: field order in proxy_metrics_snapshot_t MUST match the CGO block
 * in sockproxy_metrics.go.  See sockproxy_refactoring_plan.md §3.P7.
 */
proxy_metrics_snapshot_t proxy_get_metrics(void) {
    proxy_metrics_snapshot_t snapshot = {0};

    /* TIER 1 + TIER 2 + TIER 3: Copy atomic counters (lock-free reads) */
    snapshot.cache_high_water_events = atomic_load(&global_stats.cache_high_water_triggers);
    snapshot.conversation_hits = atomic_load(&global_stats.conversation_hits);
    snapshot.conversation_misses = atomic_load(&global_stats.conversation_misses);
    snapshot.h2_total_streams = atomic_load(&global_stats.h2_total_streams);
    snapshot.chunked_responses = atomic_load(&global_stats.chunked_responses);
    snapshot.cache_drain_partial = atomic_load(&global_stats.cache_drain_partial);
    snapshot.peer_eof_graceful = atomic_load(&global_stats.peer_eof_graceful);
    snapshot.conversation_ttl_expired = atomic_load(&global_stats.conversation_ttl_expirations);

    /* L7 Metrics: HTTP Response Counters */
    snapshot.http_responses_total = atomic_load(&global_stats.http_responses_total);
    snapshot.http_status_2xx = atomic_load(&global_stats.http_status_2xx);
    snapshot.http_status_3xx = atomic_load(&global_stats.http_status_3xx);
    snapshot.http_status_4xx = atomic_load(&global_stats.http_status_4xx);
    snapshot.http_status_5xx = atomic_load(&global_stats.http_status_5xx);

    /* L7 Metrics: TTFB Latency Histogram Buckets */
    for (int i = 0; i < 12; i++) {
        snapshot.latency_bucket[i] = atomic_load(&global_stats.latency_bucket[i]);
    }
    snapshot.latency_sum_us = atomic_load(&global_stats.latency_sum_us);
    snapshot.latency_count = atomic_load(&global_stats.latency_count);

    /* GAUGES: Count current runtime state (requires traversal) */
    snapshot.active_connections = 0;
    snapshot.active_ssl_connections = 0;
    snapshot.cache_backpressure_active = 0;
    snapshot.conversation_sessions = 0;
    snapshot.h2_sessions = atomic_load(&global_stats.h2_sessions);

    PROXY_LOCK();
    proxy_map_ent_t *node = proxy_struct->head;
    while (node) {
        proxy_fd_ent_t *pfe = node->val.fdlist;
        while (pfe) {
            snapshot.active_connections++;
            if (pfe->ssl) {
                snapshot.active_ssl_connections++;
            }
            if (pfe->cache_backpressure) {
                snapshot.cache_backpressure_active++;
            }
            pfe = pfe->next;
        }

        /* Count conversation sessions */
        pthread_rwlock_rdlock(&node->val.conv_lock);
        snapshot.conversation_sessions += HASH_COUNT(node->val.conv_map);
        pthread_rwlock_unlock(&node->val.conv_lock);

        /* OBS-01: Count active P/D sessions and trie nodes */
        {
            proxy_epval_t *tepval, *tmp_epval;
            HASH_ITER(hh, node->val.ephash, tepval, tmp_epval) {
                if (tepval->pd_disagg_enabled) {
                    pthread_rwlock_rdlock(&tepval->pd_session_lock);
                    snapshot.pd_sessions_active += HASH_COUNT(tepval->pd_session_map);
                    pthread_rwlock_unlock(&tepval->pd_session_lock);
                    if (tepval->pd_trie) {
                        pthread_rwlock_rdlock(&tepval->pd_trie_lock);
                        snapshot.pd_trie_nodes += pd_trie_node_count(tepval->pd_trie);
                        pthread_rwlock_unlock(&tepval->pd_trie_lock);
                    }
                }
            }
        }

        node = node->next;
    }
    PROXY_UNLOCK();

    /* CHWBL load imbalance (optional - GPU routing) */
    snapshot.chwbl_load_imbalance_ratio = 0.0f;
#ifdef HAVE_DP_GPU_ROUTING
    /* Implementation deferred -- see GPU integration */

    /* P/D Disaggregation counters */
    snapshot.pd_kv_params_overflow = atomic_load(&global_stats.pd_kv_params_overflow);
    snapshot.pd_cb_flips           = atomic_load(&global_stats.pd_cb_flips);
    snapshot.pd_fallback_to_normal = atomic_load(&global_stats.pd_fallback_to_normal);
#endif

    /* P/D Buffer overflow counter */
    snapshot.pd_kv_params_overflow = atomic_load(&global_stats.pd_kv_params_overflow);

    /* P/D Production Hardening counters */
    snapshot.pd_cb_flips = atomic_load(&global_stats.pd_cb_flips);
    snapshot.pd_fallback_to_normal = atomic_load(&global_stats.pd_fallback_to_normal);

    /* Failover observability counters */
    snapshot.pd_prefill_ep_died         = atomic_load(&global_stats.pd_prefill_ep_died);
    snapshot.pd_decode_ep_died          = atomic_load(&global_stats.pd_decode_ep_died);
    snapshot.pd_decode_zero_byte_eof    = atomic_load(&global_stats.pd_decode_zero_byte_eof);
    snapshot.pd_connect_failover        = atomic_load(&global_stats.pd_connect_failover);
    snapshot.lb_select_failure_shutdown = atomic_load(&global_stats.lb_select_failure_shutdown);

    /* SGLang P/D dual-dispatch counters */
    snapshot.pd_sg_prefill_abort_decode = atomic_load(&global_stats.pd_sg_prefill_abort_decode);
    snapshot.pd_sg_decode_close_drain   = atomic_load(&global_stats.pd_sg_decode_close_drain);
    snapshot.pd_sg_room_retry           = atomic_load(&global_stats.pd_sg_room_retry);
    /* P/D session and trie gauges — populated from PROXY_LOCK ephash walk above */

    /* KV Tier 1.5 routing diagnostics — storage only in plan 42-01; */
    /* increments land in plan 42-02 when pd_kv_exact_select guards call atomic_fetch_add. */
    snapshot.pd_kv_t15_miss_mode_off     = atomic_load(&global_stats.pd_kv_t15_miss_mode_off);
    snapshot.pd_kv_t15_miss_warmup       = atomic_load(&global_stats.pd_kv_t15_miss_warmup);
    snapshot.pd_kv_t15_miss_text_empty   = atomic_load(&global_stats.pd_kv_t15_miss_text_empty);
    snapshot.pd_kv_t15_miss_model_empty  = atomic_load(&global_stats.pd_kv_t15_miss_model_empty);
    snapshot.pd_kv_t15_miss_tokenize     = atomic_load(&global_stats.pd_kv_t15_miss_tokenize);
    snapshot.pd_kv_t15_miss_hashes       = atomic_load(&global_stats.pd_kv_t15_miss_hashes);
    snapshot.pd_kv_t15_miss_no_worker    = atomic_load(&global_stats.pd_kv_t15_miss_no_worker);
    snapshot.pd_kv_t15_miss_excluded     = atomic_load(&global_stats.pd_kv_t15_miss_excluded);
    snapshot.pd_kv_t15_fallthrough_total = atomic_load(&global_stats.pd_kv_t15_fallthrough_total);

    /* (OBS-01): CB proactive heal (global_stats) + per-EP
 * admission counters (file-static in sockproxy_pd.c — exported
     * via the pd_admission_stats_get accessor; see sockproxy_metrics.h). */
    snapshot.pd_cb_proactive_heal = atomic_load(&global_stats.pd_cb_proactive_heal);
    snapshot.pd_admission_shed    = pd_admission_stats_get(0);
    snapshot.pd_admission_queued  = pd_admission_stats_get(1);

    return snapshot;
}

/* =========================================================================
 * Queue-depth update (COMP-07)
 * ========================================================================= */

/*
 * llb_ai_update_ep_queue_depth - update per-EP queued_requests from Go vLLM scraper.
 * Iterates proxy_struct to find the service matching (service_ip, service_port)
 * and atomically stores queued_requests for the given ep_index.
 */
void
llb_ai_update_ep_queue_depth(uint32_t service_ip, uint16_t service_port,
                             int ep_index, uint32_t queued_requests)
{
  if (!proxy_struct || ep_index < 0 || ep_index >= MAX_PROXY_EP) return;

  PROXY_LOCK();
  proxy_map_ent_t *node = proxy_struct->head;
  while (node) {
    if (node->key.xip == service_ip && node->key.xport == service_port) {
      proxy_epval_t *tepval = node->val.ephash;
      if (tepval && tepval->pd_disagg_enabled && ep_index < tepval->n_eps) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        atomic_store(&tepval->pd_ep_loads[ep_index].queued_requests, queued_requests);
        /* H-17: stamp freshness so scorers can distrust a value the scraper
         * has stopped refreshing (dead/unreachable EP). */
        atomic_store(&tepval->pd_ep_loads[ep_index].last_update_ts,
                     (uint64_t)ts.tv_sec);
      }
      PROXY_UNLOCK();
      return;
    }
    node = node->next;
  }
  PROXY_UNLOCK();
}

/*
 * llb_ai_update_ep_capacity - update per-EP advertised KV capacity
 * (num_gpu_blocks) from the Go vLLM scraper. Byte-for-byte mirror of
 * llb_ai_update_ep_queue_depth above (PROXY_LOCK + atomic_store, MAX_PROXY_EP
 * bound, pd_disagg + n_eps guard) — the only differences are the field stored
 * (num_gpu_blocks) and the value source. A 0 advertisement is stored as-is and
 * clamped to 1 at read time by pd_kv_clamp_capacity (V5 — never divide-by-zero).
 */
void
llb_ai_update_ep_capacity(uint32_t service_ip, uint16_t service_port,
                          int ep_index, uint32_t num_gpu_blocks)
{
  if (!proxy_struct || ep_index < 0 || ep_index >= MAX_PROXY_EP) return;

  PROXY_LOCK();
  proxy_map_ent_t *node = proxy_struct->head;
  while (node) {
    if (node->key.xip == service_ip && node->key.xport == service_port) {
      proxy_epval_t *tepval = node->val.ephash;
      if (tepval && tepval->pd_disagg_enabled && ep_index < tepval->n_eps) {
        atomic_store(&tepval->pd_ep_loads[ep_index].num_gpu_blocks, num_gpu_blocks);
      }
      PROXY_UNLOCK();
      return;
    }
    node = node->next;
  }
  PROXY_UNLOCK();
}

/*
 * llb_ai_ctrl_update_ep -: store the global-controller advisory
 * packed instruction word for one EP (state bits 31-24, weight bits 7-0 — see
 * PD_CTRL_* in sockproxy.h). Byte-for-byte mirror of llb_ai_update_ep_queue_depth
 * above (PROXY_LOCK + atomic_store, MAX_PROXY_EP bound, pd_disagg + n_eps guard)
 * — the only differences are the field stored (pd_ctrl_ep[ep_index]) and the
 * value source (the Go applier's merged snapshot, validated Go-side in :
 * weight<=100, state in the aictrl.v1 enum). This function and
 * llb_ai_ctrl_set_mode below are the SOLE writers of the pd_ctrl_* fields; the
 * selection path only ever atomic_load's them. No malloc/free/pointer swap —
 * the Phase-89/90/93 UAF class is structurally excluded.
 */
void
llb_ai_ctrl_update_ep(uint32_t service_ip, uint16_t service_port,
                      int ep_index, uint32_t packed)
{
  if (!proxy_struct || ep_index < 0 || ep_index >= MAX_PROXY_EP) return;

  PROXY_LOCK();
  proxy_map_ent_t *node = proxy_struct->head;
  while (node) {
    if (node->key.xip == service_ip && node->key.xport == service_port) {
      proxy_epval_t *tepval = node->val.ephash;
      if (tepval && tepval->pd_disagg_enabled && ep_index < tepval->n_eps) {
        atomic_store(&tepval->pd_ctrl_ep[ep_index], packed);
      }
      PROXY_UNLOCK();
      return;
    }
    node = node->next;
  }
  PROXY_UNLOCK();
}

/*
 * llb_ai_ctrl_set_mode -: store the per-service controller mode
 * ladder scalar (0 = controller absent/autonomous => pd_select_prefill skips ALL
 * controller work, the G3 byte-identical hot path). Byte-for-byte mirror of
 * llb_ai_update_ep_queue_depth above (PROXY_LOCK + atomic_store, pd_disagg
 * guard) — the only differences are the field stored (pd_ctrl_mode, a service-
 * level _Atomic uint8_t, so there is no ep_index parameter/bounds pair) and the
 * value source (the Go applier's mode ladder). Sole writer discipline as
 * llb_ai_ctrl_update_ep.
 */
void
llb_ai_ctrl_set_mode(uint32_t service_ip, uint16_t service_port, uint8_t mode)
{
  if (!proxy_struct) return;

  PROXY_LOCK();
  proxy_map_ent_t *node = proxy_struct->head;
  while (node) {
    if (node->key.xip == service_ip && node->key.xport == service_port) {
      proxy_epval_t *tepval = node->val.ephash;
      if (tepval && tepval->pd_disagg_enabled) {
        atomic_store(&tepval->pd_ctrl_mode, mode);
      }
      PROXY_UNLOCK();
      return;
    }
    node = node->next;
  }
  PROXY_UNLOCK();
}

/* =========================================================================
 * Latency histogram helper
 * ========================================================================= */

/* Bucket upper boundaries in microseconds (must match Go CGO bucketBounds) */
static const uint64_t latency_bucket_bounds_us[12] = {
    1000, 5000, 10000, 25000, 50000, 100000,
    250000, 500000, 1000000, 2500000, 5000000, 10000000
};

/*
 * get_timestamp_ns - current wall-clock time in nanoseconds (CLOCK_REALTIME).
 * Lives here (always-compiled metrics unit) rather than sockproxy_trace.c so the
 * TTFB path resolves it in default builds; the trace subsystem (HAVE_HTTP_TRACE)
 * is optional but the TTFB histogram is a first-class L7 metric.
 */
uint64_t get_timestamp_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/*
 * record_latency_sample - record one TTFB latency data point.
 * Called from proxy_try_epxmit; will move to sockproxy_http.c in.
 * Non-static so sockproxy.c can call it until extraction.
 */
void record_latency_sample(uint64_t latency_us) {
    for (int i = 0; i < 12; i++) {
        if (latency_us <= latency_bucket_bounds_us[i]) {
            atomic_fetch_add(&global_stats.latency_bucket[i], 1);
        }
    }
    atomic_fetch_add(&global_stats.latency_sum_us, latency_us);
    atomic_fetch_add(&global_stats.latency_count, 1);
}

/* =========================================================================
 * Per-stage hot-path histogram
 * ========================================================================= */

/*
 * record_kv_stage - accumulate one per-stage µs timing for (stage, outcome).
 *
 * The C3 routing-overhead breakdown: each of the 4 Tier-1.5 stages
 * (tokenize / CBOR+hash / CGO best_worker / scan) carries its own 12-bucket
 * µs histogram, split by the hit/miss outcome so the per-stage cost can be
 * reported on BOTH the cache-hit and the cache-miss (Tier-2 fallthrough) path.
 *
 * Off-path accumulation ONLY — a fixed-bucket atomic_fetch_add mirror of
 * record_latency_sample with NO synchronous logging (: a fprintf in
 * the timed path would perturb the very latency C3 measures). The bucket bounds
 * reuse latency_bucket_bounds_us[] so the "must match Go CGO bucketBounds"
 * parity note above covers the per-stage histograms too.
 *
 * Bounds-checked: an out-of-range stage or outcome is a silent no-op (V5 — a
 * caller bug must not index past the fixed arrays).
 */
void record_kv_stage(int stage, int is_hit, uint64_t latency_us) {
    if (stage < 0 || stage >= KV_N_STAGES) return;
    int outcome = is_hit ? KV_STAGE_OUTCOME_HIT : KV_STAGE_OUTCOME_MISS;
    if (outcome < 0 || outcome >= KV_N_STAGE_OUTCOMES) return;  /* defensive */
    /* Cumulative (Prometheus le-bucket) form, byte-identical to
     * record_latency_sample: increment EVERY bucket whose bound >= latency. */
    for (int i = 0; i < KV_STAGE_N_BUCKETS; i++) {
        if (latency_us <= latency_bucket_bounds_us[i]) {
            atomic_fetch_add(&global_stats.kv_stage_buckets[stage][outcome][i], 1);
        }
    }
    atomic_fetch_add(&global_stats.kv_stage_sum_us[stage][outcome], latency_us);
    atomic_fetch_add(&global_stats.kv_stage_count[stage][outcome], 1);
}
