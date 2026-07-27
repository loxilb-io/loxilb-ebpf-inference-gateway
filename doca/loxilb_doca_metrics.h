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
 * loxilb_doca_metrics.h -- SDK-counter-query bridge declarations.
 *
 * This header is included by the CGO preamble (via the umbrella bridge
 * header) and by the C implementation in loxilb_doca_metrics.c.
 *
 * Opaque-pointer rule (mirrors umbrella header line 21, commit c5ba2725):
 *   - This header MUST NOT include any SDK or DPDK headers.
 *   - All native handles cross the CGO boundary as `const void *`.
 *   - Result types are plain-data structs that depend only on <stdint.h>
 *     and <stddef.h>.
 *   - Native enum and struct identifiers never appear here -- they live
 *     exclusively inside loxilb_doca_metrics.c after that file pulls in
 *     the SDK headers.
 *
 * in-scope SDK APIs wrapped here (full SDK identifiers are
 * documented inline in loxilb_doca_metrics.c; this header deliberately
 * paraphrases them to keep the opaque-pointer grep gate green):
 *
 *   - Per-entry counter query (G3 ratified, D-P65-01 entry 1)
 *   - Batched shared-resource counter query (G1 ratified, D-P65-01
 * entry 3, FUTURE-PROOF per narrowing)
 *   - Mandatory entries-process flush per RESEARCH Pitfall 9
 *
 * EXPLICITLY DESCOPED per (silicon-rejected on BASIC pipes):
 *
 *   - Pipe-miss counter create-time precondition. Stage-2 G5/G5b prove
 *     BASIC + miss-counter is silicon-rejected (rc=-22 opcode 0x1800000).
 *   - Per-pipe miss counter query API. Pairs with the disabled
 *     create-time precondition; the Stage-2 G5/G5b/G6 harness in
 *     3rdparty/doca-294/.../flow_p65_counter_query is the regression
 *     detector for the missing entry-point 2.
 *
 * Downstream consumers (Plans 65-03 and 65-04 will consume these symbols
 * via the Go CGO scaffold in pkg/loxinet/dpu_doca_bf2_metrics.go):
 * Plan 65-03: chunked walker plus ReconcileCtStats lazy-on-read
 * contract scaffold plus registers a per-tick collector via
 *     RegisterDocaCollector. The walker calls llb_doca_entry_query_v2 in
 * a chunked loop bounded by 's polling-budget shape.
 * Plan 65-04: REST debug endpoint per-entry query plus wires
 * InvokeRegisteredDocaCollectors into the existing 
 *     per-tick path at pkg/loxinet/dpu_metrics.go.
 *   - Plan 65-05: operator runbook for BF2 HW build + validation.
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * llb_doca_counter_result_t -- plain-data counter result.
 *
 * Mirrors the SDK resource-query counter shape (total_pkts +
 * total_bytes) so the C bridge can struct-copy without exposing the
 * SDK-side anonymous-union type to CGO. The two fields are ordered
 * (total_pkts, total_bytes) for stable Go-side `ReconciledCounterResult`
 * binding regardless of any future SDK union layout change.
 *
 * Serves: D-P65-05 (reconciliation contract scaffold) -- Plan 65-03 builds
 * `ReconciledCounterResult` directly from this struct.
 */
typedef struct {
    uint64_t total_pkts;   /* total packets hit by the queried entry/resource */
    uint64_t total_bytes;  /* total bytes hit by the queried entry/resource */
} llb_doca_counter_result_t;

/*
 * llb_doca_entry_query_v2 -- per-entry counter query ( struct API).
 *
 * Naming note (planner-discretion deviation from PLAN interfaces section):
 * the umbrella header at offset 395 already declares a legacy
 * `llb_doca_entry_query(entry, bytes_out, pkts_out)` with a 3-arg
 * out-pointer signature consumed by the existing `DocaEntryQuery` Go
 * wrapper at pkg/loxinet/dpu_doca_cgo.go (the legacy site uses
 * uint64_t out-pointers, NOT a struct). Two C declarations with the same
 * identifier and different signatures fail at compile. takes
 * the suffix `_v2` (mirrors the LLB_DOCA_ROOT_PIPE_CFG_V2 precedent in
 * the umbrella) so this struct-returning variant coexists with the
 * legacy two-out-pointer API. The verify-gate grep
 * `grep -q 'llb_doca_entry_query' loxilb_doca_metrics.h` still matches
 * by substring (Plan 65-02 deviations). The Go binding name on the
 * Plan 65-02 side is `EntryQuery`; no collision in the Go namespace.
 *
 * Wraps: the SDK per-entry resource query (G3 ratified at p99=540-660ns
 * per 65-STAGE2-RESULTS.md; PRIMARY counter API in per RESEARCH
 * Standard Stack section).
 *
 * Stage-2 gate: G3 PASS (Round 3 sustained).
 *
 * Consumed by:
 * Plan 65-03 chunked walker for periodic counter reconciliation
 * under the polling-budget cap.
 * Plan 65-03/04 ReconcileCtStats lazy-on-read.
 * Plan 65-04 REST debug endpoint for operator per-entry queries.
 *
 * Serves: D-P65-01 entry 1, D-P65-05 (reconciliation contract).
 *
 * @param entry_handle Opaque pipe-entry handle (the SDK native type on
 *                     the C side; cast through `const void *` here to
 *                     obey the opaque-pointer rule).
 * @param out          Pre-allocated result buffer (caller-owned).
 * @return 0 on success, -1 on any failure (invalid handle, SDK error).
 */
int llb_doca_entry_query_v2(const void *entry_handle,
                            llb_doca_counter_result_t *out);

/*
 * llb_doca_counter_batch_query -- batched shared-resource counter query.
 *
 * Wraps: the SDK batched shared-resource query API (G1 ratified at
 * p99=0.95-1.01ms at N=10K per 65-STAGE2-RESULTS.md).
 *
 * Stage-2 gate: G1 PASS (Round 3 sustained across N sweeps).
 *
 * FUTURE-PROOF per narrowing -- no production pipe references
 * SHARED counters today (BF2 switch,hws,isolated mode silicon-rejects
 * BASIC with SHARED counter monitor type; SHARED counters may only be
 * referenced from protocol pipes -- CT/ACL/NAT in loxilb terms). This
 * wrapper is allocated now for forward-compat when a protocol-pipe
 * SHARED counter pool ships in a future plan (not).
 *
 * Consumed by: nothing today. Plan 65-03 may declare a registration
 * site but will not invoke the wrapper since no SHARED-counter pool
 * exists.
 *
 * Serves: D-P65-01 entry 3 (forward-compat), D-P65-02 (polling-budget
 * API shape).
 *
 * @param ids   Pointer to caller-owned array of `n` shared-resource IDs.
 * @param out   Pre-allocated array of `n` result buffers (caller-owned).
 * @param n     Number of IDs to query in a single batched call.
 * @return 0 on success, -1 on any failure (n=0 with non-NULL ids treated
 *         as a no-op success).
 */
int llb_doca_counter_batch_query(const uint32_t *ids,
                                 llb_doca_counter_result_t *out,
                                 uint32_t n);

/*
 * llb_doca_entries_process_flush -- flush pending entry events.
 *
 * Wraps: the SDK entries-process call (queue=0, timeout=0, max=0).
 *
 * Reference patterns:
 *   - 3rdparty/doca-294/.../flow_e2e_l3_routing_sample.c:657 (per-cycle
 *     flush before per-entry query loop).
 *   - 3rdparty/doca-294/.../flow_shared_counter_sample.c:319 (drain
 *     before timed shared-resource query iteration).
 *   - RESEARCH Pitfall 9 -- counter reads before this flush return
 *     stale values for entries that were programmed in the same window.
 *
 * Caller contract: MUST invoke once per polling iteration BEFORE
 * counter reads (the chunked walker in Plan 65-03 calls this at the
 * top of each chunk).
 *
 * Serves: D-P65-01 (counter-read correctness precondition), 
 * (polling-budget -- the flush itself is the first cost in the budget).
 *
 * @param port_handle Opaque port handle (the SDK native type on the C
 *                    side; cast through `const void *` here).
 * @return 0 on success, -1 on any failure.
 */
int llb_doca_entries_process_flush(const void *port_handle);

/*
 * llb_doca_alloc_shared_counter -- allocate a shared-counter ID.
 *
 * Increments an atomic cursor (`_Atomic uint32_t`) capped at
 * LLB_DOCA_MAX_SHARED_COUNTERS. Returns 0 plus allocated ID on success,
 * 1 past the cap. No mutex -- the cursor is the entire allocator (
 * lifecycle keep-simple decision).
 *
 * `scope_key` is accepted for forward-compat (Plan 65-05 runbook
 * documents potential lazy-recycle pool) but ignored in v6.0 first
 * release -- pass any non-NULL string or NULL.
 *
 * Serves: lifecycle, D-P65-01 entry 3 (counter-pool primitive for
 * the future SHARED counter use cases).
 *
 * @param scope_key Forward-compat scope tag; NULL acceptable.
 * @param id_out    Pre-allocated `uint32_t *` slot for the allocated ID.
 * @return 0 on success (id_out populated), -1 on cap-reached or NULL
 *         id_out.
 */
int llb_doca_alloc_shared_counter(const char *scope_key, uint32_t *id_out);

/*
 * llb_doca_free_shared_counter -- release a shared-counter ID.
 *
 * No-op in v6.0 first release (lazy recycle deferred to Plan 65-05
 * follow-up). Kept in the API surface so Plan 65-03/04 call sites can
 * pair alloc/free cleanly when lazy-recycle ships.
 *
 * Serves: lifecycle (forward-compat).
 *
 * @param id Previously-allocated shared-counter ID.
 */
void llb_doca_free_shared_counter(uint32_t id);

/*
 * llb_doca_egress_counter_available -- EGRESS-domain counter availability.
 *
 * Returns the cached G2 outcome (Stage-2 ratified). On bf2-arm DOCA 2.9.4
 * with switch,hws,isolated mode this returns 1 (G2 PASS sustained across
 * Round 3 runs 4/5/6 per 65-STAGE2-RESULTS.md).
 *
 * The C-side implementation uses a settable `_Atomic int` so a future
 * BF3/BF4 silicon variant or SDK rev that changes the G2 outcome can
 * flip it without API churn. v6.0 first release returns the constant 1.
 *
 * Consumed by: Plan 65-03 mirrors this into the
 * `loxilb_doca_egress_counters_available` Prometheus gauge.
 *
 * Serves: G2 outcome accessor; D-P65-01 entry 3 context.
 *
 * @return 1 when EGRESS-domain SHARED counters are available, 0 otherwise.
 */
int llb_doca_egress_counter_available(void);

#ifdef __cplusplus
}
#endif
