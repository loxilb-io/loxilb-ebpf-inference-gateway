/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * loxilb_doca_metrics.c -- SDK-counter-query bridge implementation.
 *
 * Compiled only when HAVE_DOCA=1 (real BF2 hardware build path).
 *
 * Canonical SDK references (per 65-CONTEXT.md <canonical_refs>):
 *   - Local SPEC is the source of truth for signatures / structs / enums:
 *     3rdparty/doca-294/opt/mellanox/doca/include/doca_flow.h
 *     - doca_flow.h:1055 -- struct doca_flow_resource_query layout
 *       (anonymous union exposing counter.total_pkts / counter.total_bytes).
 *     - doca_flow.h:1332 -- doca_flow_shared_resources_query signature
 *       (batched query for the SHARED counter pool).
 *     - doca_flow.h:1895 -- doca_flow_resource_query_entry signature
 *       (per-entry query for NON_SHARED counter pipes).
 *     - doca_flow.h:1984 -- doca_flow_entries_process signature
 *       (port, pipe_queue, timeout, max_processed_entries).
 *   - Online CONCEPT is the source of truth for lifecycle / prose:
 *     https://docs.nvidia.com/doca/archive/2-9-4/...
 *   - Never trust DOCA 2.9.0 Doxygen or DOCA 3.x latest docs as BF2
 *     ground truth (see [[feedback-doca-2-9-4-spec-vs-concept]]).
 *
 * Stage-2 reference samples (validated on bf2-arm DOCA 2.9.4 switchdev):
 *   - 3rdparty/doca-294/.../flow_p65_counter_query/flow_p65_counter_query_sample.c
 *     -- G1/G2/G3 timing harness; per-entry query loop at line 1072-1073.
 *   - 3rdparty/doca-294/.../flow_e2e_l3_routing/flow_e2e_l3_routing_sample.c
 *     -- per-entry query + entries_process flush at lines 643, 657, 662-663.
 *   - 3rdparty/doca-294/.../flow_shared_counter/flow_shared_counter_sample.c
 *     -- batched query pattern at lines 319, 327, 390-418.
 *
 * anti-pattern guard:
 *   - This file MUST NOT call the pipe-cfg miss-counter SETTER
 * ( descope; rc=-22 opcode 0x1800000 on BASIC pipes per
 *     Stage-2 G5/G5b harness in 3rdparty/doca-294/.../flow_p65_counter_query).
 *   - This file MUST NOT call the per-pipe MISS-counter QUERY API
 * ( descope; companion to the disabled precondition).
 *   - This file MUST NOT set `monitor.counter_type =
 * DOCA_FLOW_RESOURCE_TYPE_SHARED` on a BASIC pipe template (
 *     constraint; silicon-rejected in switch,hws,isolated mode).
 *   - DOCA_FLOW_SHARED_RESOURCE_COUNTER is the resource-type ARGUMENT
 *     to doca_flow_shared_resources_query (the pool definition; legal
 *     and required). That argument-vs-template-monitor distinction is
 * the fault line.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdatomic.h>

/* SDK headers -- only this translation unit sees them. The header
 * loxilb_doca_metrics.h stays SDK-free per the opaque-pointer rule. */
#include <doca_flow.h>
#include <doca_log.h>
#include <doca_error.h>

#include "loxilb_doca_metrics.h"

DOCA_LOG_REGISTER(LLB_DOCA_METRICS);

/* ----------------------------------------------------------------
 *  Module state
 * ---------------------------------------------------------------- */

/*
 * LLB_DOCA_MAX_SHARED_COUNTERS bounds the shared-counter ID space we
 * hand out via llb_doca_alloc_shared_counter. Threat (DoS
 * via allocator exhaustion) is mitigated by the hard cap. 
 * has no production callers for SHARED counters today ( narrows
 * BASIC pipes to NON_SHARED), so the cap is forward-proof rather than
 * load-bearing. The Stage-2 G1 sweep harness tops out at N=10000
 * (3rdparty/doca-294/.../flow_p65_counter_query_sample.c MAX_SHARED_IDS
 * = 10001), so 10000 is also the largest empirically-tested working
 * pool size on bf2-arm DOCA 2.9.4.
 */
#define LLB_DOCA_MAX_SHARED_COUNTERS 10000

/*
 * Atomic cursor for shared-counter ID allocation. No mutex by design
 * ( lifecycle keep-simple). On cap-hit we atomically decrement
 * back so the cursor never drifts past LLB_DOCA_MAX_SHARED_COUNTERS.
 */
static _Atomic uint32_t g_next_shared_counter_id = 0;

/*
 * Cached G2 outcome (EGRESS-domain SHARED counter availability).
 *
 * Initialized to 1 because G2 PASS was sustained across Round 3
 * runs 4/5/6 on bf2-arm DOCA 2.9.4 switch,hws,isolated mode per
 * 65-STAGE2-RESULTS.md.
 *
 * The variable is _Atomic int so a future BF3/BF4 silicon variant or
 * SDK rev that changes the G2 outcome can flip it via a future setter
 * without API churn (no setter shipped in v6.0 first release;
 * documented as TODO below).
 */
static _Atomic int g_egress_available = 1;

/* ----------------------------------------------------------------
 *  Section C -- llb_doca_entry_query_v2
 *  Wraps: doca_flow_resource_query_entry
 *  G3 ratified path (p99=540-660ns per 65-STAGE2-RESULTS.md).
 * ---------------------------------------------------------------- */

int llb_doca_entry_query_v2(const void *entry_handle,
                            llb_doca_counter_result_t *out)
{
    if (entry_handle == NULL || out == NULL) {
        return -1;
    }

    /* Cast the opaque handle back to the SDK type. The opaque-pointer
     * rule (loxilb_doca_metrics.h preamble + umbrella header line 21)
     * keeps doca_flow_pipe_entry out of the public header; this is
     * the one site where the cast crosses back. */
    struct doca_flow_pipe_entry *entry =
        (struct doca_flow_pipe_entry *)(uintptr_t)entry_handle;

    struct doca_flow_resource_query qr;
    memset(&qr, 0, sizeof(qr));

    doca_error_t r = doca_flow_resource_query_entry(entry, &qr);
    if (r != DOCA_SUCCESS) {
        DOCA_LOG_DBG("llb_doca_entry_query_v2: doca_flow_resource_query_entry "
                     "failed: %s", doca_error_get_descr(r));
        return -1;
    }

    /* Copy the counter sub-fields. doca_flow_resource_query is a
     * union; the counter members are valid because we requested a
     * counter query (versus an ipsec_sa query). */
    out->total_pkts  = qr.counter.total_pkts;
    out->total_bytes = qr.counter.total_bytes;
    return 0;
}

/* ----------------------------------------------------------------
 *  Section D -- llb_doca_counter_batch_query
 *  Wraps: doca_flow_shared_resources_query
 *  G1 ratified path (p99=0.95-1.01ms at N=10K per 65-STAGE2-RESULTS).
 * FUTURE-PROOF per -- no production pipe references SHARED
 *  counters today; protocol-pipe pools (CT/ACL/NAT) ship in a later
 *  plan and will consume this wrapper.
 * ---------------------------------------------------------------- */

int llb_doca_counter_batch_query(const uint32_t *ids,
                                 llb_doca_counter_result_t *out,
                                 uint32_t n)
{
    if (ids == NULL || out == NULL) {
        return -1;
    }
    if (n == 0) {
        /* No work -- legal no-op. The Stage-2 G1 sweep skips N=0
         * iterations the same way (sample file line 502). */
        return 0;
    }

    /*
     * The SDK signature takes a NON-const uint32_t *res_array even
     * though the IDs are an input (doca_flow.h:1332). Cast through a
     * scratch alias so we honor the const contract at the public
     * API while satisfying the SDK signature.
     */
    uint32_t *ids_nonconst = (uint32_t *)(uintptr_t)ids;

    /*
     * Stack-allocate the SDK results array. The Stage-2 G1 sample
     * heap-allocates (sample file line 507) because it sweeps N up
     * to 10000 inside a long-lived measurement loop; here we expect
     * per-call N << 10000 (Plan 65-03 chunked walker stays under the
 * polling budget of ~5000 entries per tick), so stack is
     * faster and simpler. If a future caller wants N > 1024 we will
     * revisit with a VLA-vs-heap branch.
     */
    if (n > 1024) {
        /* Large-N path: heap-alloc to avoid stack blow-up. */
        struct doca_flow_resource_query *results =
            calloc(n, sizeof(*results));
        if (results == NULL) {
            DOCA_LOG_DBG("llb_doca_counter_batch_query: calloc(%u) failed", n);
            return -1;
        }
        doca_error_t r = doca_flow_shared_resources_query(
            DOCA_FLOW_SHARED_RESOURCE_COUNTER,
            ids_nonconst, results, n);
        if (r != DOCA_SUCCESS) {
            DOCA_LOG_DBG("llb_doca_counter_batch_query: SDK query failed: "
                         "%s", doca_error_get_descr(r));
            free(results);
            return -1;
        }
        for (uint32_t i = 0; i < n; i++) {
            out[i].total_pkts  = results[i].counter.total_pkts;
            out[i].total_bytes = results[i].counter.total_bytes;
        }
        free(results);
        return 0;
    }

    /* Small-N stack path. */
    struct doca_flow_resource_query results[1024];
    memset(results, 0, sizeof(results[0]) * n);

    doca_error_t r = doca_flow_shared_resources_query(
        DOCA_FLOW_SHARED_RESOURCE_COUNTER,
        ids_nonconst, results, n);
    if (r != DOCA_SUCCESS) {
        DOCA_LOG_DBG("llb_doca_counter_batch_query: SDK query failed: %s",
                     doca_error_get_descr(r));
        return -1;
    }

    for (uint32_t i = 0; i < n; i++) {
        out[i].total_pkts  = results[i].counter.total_pkts;
        out[i].total_bytes = results[i].counter.total_bytes;
    }
    return 0;
}

/* ----------------------------------------------------------------
 *  Section E -- llb_doca_entries_process_flush
 *  Wraps: doca_flow_entries_process(port, queue=0, timeout=0, max=0).
 *  RESEARCH Pitfall 9 + flow_e2e_l3_routing_sample.c:657 pattern.
 *  Mandatory precondition before any counter read in a polling
 *  iteration; the chunked walker in Plan 65-03 calls this once per
 *  chunk at the head of its loop.
 * ---------------------------------------------------------------- */

int llb_doca_entries_process_flush(const void *port_handle)
{
    if (port_handle == NULL) {
        return -1;
    }

    struct doca_flow_port *port =
        (struct doca_flow_port *)(uintptr_t)port_handle;

    /*
     * (queue=0, timeout=0, max=0) -- exact shape used in the
     * Stage-2 G1 sweep drain (sample line 515) and the L3 routing
     * sample line 657. timeout=0 means "do not block"; max=0
     * means "process all pending events"; queue=0 because the
     * loxilb DOCA worker pins a single queue (matches sample line 515
     * usage and the L3 routing sample on the worker thread).
     */
    doca_error_t r = doca_flow_entries_process(port, 0, 0, 0);
    if (r != DOCA_SUCCESS) {
        DOCA_LOG_DBG("llb_doca_entries_process_flush: failed: %s",
                     doca_error_get_descr(r));
        return -1;
    }
    return 0;
}

/* ----------------------------------------------------------------
 *  Section F -- shared-counter ID lifecycle
 *  llb_doca_alloc_shared_counter / llb_doca_free_shared_counter
 *
 *  v6.0 first release: monotonic-cursor allocator capped at
 *  LLB_DOCA_MAX_SHARED_COUNTERS. Free is a no-op (lazy recycle pool
 *  is a Plan 65-05 follow-up).
 *
 *  scope_key is accepted for forward-compat (Plan 65-05 may use it
 *  to scope a per-pool pool) but ignored today.
 * ---------------------------------------------------------------- */

int llb_doca_alloc_shared_counter(const char *scope_key, uint32_t *id_out)
{
    /* TODO(P65-followup) -- lazy recycle pool deferred; see Plan 65-05
     * operator runbook. v6.0 first release uses monotonic-cursor only.
     * scope_key is accepted for forward-compat (pool partitioning by
     * subsystem) and intentionally unused today. */
    (void)scope_key;

    if (id_out == NULL) {
        return -1;
    }

    /* Atomic increment-and-bound. If the increment crosses the cap
     * we atomically rewind so the cursor stays at the cap. The +1
     * lets the very first allocation return ID 0 cleanly. */
    uint32_t prev = atomic_fetch_add(&g_next_shared_counter_id, 1);
    if (prev >= LLB_DOCA_MAX_SHARED_COUNTERS) {
        /* Rewind: best-effort -- multiple concurrent callers may
         * each rewind once; the cursor stays bounded above
         * LLB_DOCA_MAX_SHARED_COUNTERS by at most the number of
         * concurrent callers, but never grows unboundedly. */
        atomic_fetch_sub(&g_next_shared_counter_id, 1);
        DOCA_LOG_DBG("llb_doca_alloc_shared_counter: cap reached at %u",
                     LLB_DOCA_MAX_SHARED_COUNTERS);
        return -1;
    }

    *id_out = prev;
    return 0;
}

void llb_doca_free_shared_counter(uint32_t id)
{
    /* No-op in v6.0 first release. Lazy recycle deferred to Plan 65-05
     * follow-up (when a SHARED-counter pool ships). The signature is
     * kept stable so call sites can pair alloc/free idiomatically. */
    (void)id;
}

/* ----------------------------------------------------------------
 *  Section G -- llb_doca_egress_counter_available
 *
 *  Constant `1` for v6.0 first release per 65-STAGE2-RESULTS.md G2
 *  PASS (runs 4/5/6 sustained across Round 3). Future silicon
 *  variants or SDK revs that change the G2 outcome would flip the
 *  stored atomic via a future setter (TODO site below); the
 *  loxilb_doca_egress_counters_available Prometheus gauge in
 *  Plan 65-03 mirrors this constant today.
 * ---------------------------------------------------------------- */

int llb_doca_egress_counter_available(void)
{
    /* TODO(P65-followup) -- when a future BF3/BF4 silicon variant
     * or DOCA SDK rev changes the G2 outcome, add an init-time
     * runtime probe that flips g_egress_available atomically. The
     * accessor stays the same; only the initialization path changes.
     * Today the constant 1 reflects Stage-2 Round 3 ratification. */
    return atomic_load(&g_egress_available);
}
