/*
 * Copyright (c) 2022 NetLOX Inc
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
 * loxilb_doca_flow.h -- C bridge API for DOCA 2.9.4 Flow offload.
 *
 * This header is included by the CGO preamble and the standalone C test
 * program.  It must NOT include any DOCA/DPDK headers -- only <stdint.h>.
 * All DOCA opaque types are hidden behind void* handle types.
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

/* ---- Return codes ---- */
#define LLB_DOCA_OK           0
#define LLB_DOCA_ERR_EAL     -1
#define LLB_DOCA_ERR_DEV     -2
#define LLB_DOCA_ERR_FLOW    -3
#define LLB_DOCA_ERR_PORT    -4
#define LLB_DOCA_ERR_PIPE    -5
#define LLB_DOCA_ERR_ENTRY   -6
#define LLB_DOCA_ERR_TIMEOUT -7
#define LLB_DOCA_ERR_PARAM   -8
#define LLB_DOCA_ERR_NOTSUP  -9

/* ---- Opaque handle types (hide DOCA types from CGO) ---- */
typedef void *llb_doca_pipe_handle_t;
typedef void *llb_doca_entry_handle_t;

/* ---- Port limits ---- */
#define LLB_DOCA_MAX_PORTS 32

/* ---- Pipe types ---- */
#define LLB_DOCA_PIPE_BASIC  0

/* ---- Forward action types ---- */
typedef enum {
    LLB_DOCA_FWD_DROP   = 0,
    LLB_DOCA_FWD_PORT   = 1,
    LLB_DOCA_FWD_RSS    = 2,  /* Phase 26 readiness */
    LLB_DOCA_FWD_TARGET = 3,  /* FWD_TARGET (KERNEL, etc.) -- Phase 30 */
} llb_doca_fwd_type_t;

/* ---- Pipe capacity configuration ---- */
typedef struct {
    uint32_t ct_pipe_capacity;      /* default: 8192 (doubled in init to 16384) */
    uint32_t udp_ct_pipe_capacity;  /* default: 8192 (doubled in init to 16384) */
    uint32_t snat_pipe_capacity;    /* default: 2048 */
    uint32_t num_repr;              /* number of VF representors (default: 2) */
} llb_doca_config;

/* ---- Root pipe rebuild configuration (versioned for ABI compat) ----
 *
 * Phase 47 (D-04): bumped to V2 by appending `miss_pipe_override`.
 * V1 callers remain ABI-compatible via zero-initialisation: the new
 * trailing field lands at offset >= sizeof(V1-layout), and the validator
 * accepts both LLB_DOCA_ROOT_PIPE_CFG_V1 and _V2. When version==V2 and
 * miss_pipe_override!=0, the root miss dispatches to the override pipe
 * instead of the default `g_to_kernel_pipe` (fixes Bug #2: FDB pipe
 * orphaning). When version==V2 and miss_pipe_override==0, behaviour
 * collapses to V1 semantics.
 *
 * Phase 52 (D-04): bumped to V3 by appending per-dispatch
 * `port_meta_value[]` array AND a global `match_port_meta` flag at the
 * tail. V1 and V2 callers remain ABI-compatible via zero-initialisation:
 * the new trailing fields land at offset >= sizeof(V2-layout), and the
 * validator accepts LLB_DOCA_ROOT_PIPE_CFG_V1, _V2, AND _V3. When
 * version==V3 AND match_port_meta!=0, the rebuild adds
 * parser_meta.port_meta=UINT32_MAX to the pipe match template AND
 * sets each entry's port_meta from port_meta_value[i] (per-entry
 * exact match dispatch by ingress DPDK port_id).
 */
#define LLB_DOCA_ROOT_PIPE_CFG_V1   1
#define LLB_DOCA_ROOT_PIPE_CFG_V2   2
#define LLB_DOCA_ROOT_PIPE_CFG_V3   3   /* Phase 52: per-port ingress dispatch (D-04) */
#define LLB_DOCA_ROOT_PIPE_MAX_DISPATCH 8

typedef struct {
    uint32_t version;        /* struct version for ABI compat (LLB_DOCA_ROOT_PIPE_CFG_V1 or _V2) */
    uint32_t nr_entries;     /* root pipe capacity (4 for Phase 34) */
    uint32_t num_dispatch;   /* number of l4 dispatch entries */
    struct {
        uint32_t l4_type;              /* DOCA_FLOW_L4_META_TCP or _UDP value (cast from enum) */
        llb_doca_pipe_handle_t target; /* downstream pipe handle */
    } dispatch[LLB_DOCA_ROOT_PIPE_MAX_DISPATCH];
    /* V2: non-NULL overrides default g_to_kernel_pipe miss destination.
     * V1 callers leave this field zero-initialised; behaviour unchanged. */
    llb_doca_pipe_handle_t miss_pipe_override;
    /* V3 (Phase 52 D-04): per-dispatch ingress port_meta exact-match value.
     * 0 = wildcard (V2 behaviour preserved entry-by-entry — uplink port_id is 0
     *               on BF2 standard switchdev, but `match_port_meta=0` keeps
     *               the entire feature opt-out for V2 callers).
     * >0 = exact ingress DPDK port_id match.
     * Only consulted when match_port_meta != 0 AND version >= V3. */
    uint32_t port_meta_value[LLB_DOCA_ROOT_PIPE_MAX_DISPATCH];
    /* V3: when nonzero, the pipe template adds parser_meta.port_meta to its
     * match mask, and per-entry port_meta values become exact-match keys.
     * When zero (default for V1/V2/V3 with no port-dispatch needs), the
     * template stays V2 — port_meta NOT in match mask. */
    uint8_t  match_port_meta;
    uint8_t  _pad_v3[7];   /* alignment / future use; zero-initialised */
} llb_doca_root_pipe_cfg;

/* Defense-in-depth: compile-time assertions that the V2 layout APPENDED
 * miss_pipe_override at the end (Phase 47 D-04). Any silent drift -- e.g.
 * a future editor inserting a field in the middle -- trips the build.
 *
 * Anchor: miss_pipe_override sits strictly after dispatch[] (so V1 wire
 * zero-init of the legacy layout remains binary-compatible), and the
 * trailing field is the last one in the struct (so sizeof == offsetof+sizeof). */
_Static_assert(offsetof(llb_doca_root_pipe_cfg, miss_pipe_override) >=
               offsetof(llb_doca_root_pipe_cfg, dispatch) +
                   LLB_DOCA_ROOT_PIPE_MAX_DISPATCH *
                       sizeof(((llb_doca_root_pipe_cfg *)0)->dispatch[0]),
               "miss_pipe_override must be appended AFTER dispatch[] (V1 zero-init compat)");
_Static_assert(offsetof(llb_doca_root_pipe_cfg, port_meta_value) ==
               offsetof(llb_doca_root_pipe_cfg, miss_pipe_override) +
                   sizeof(((llb_doca_root_pipe_cfg *)0)->miss_pipe_override),
               "Phase 52 (D-04): port_meta_value must be appended directly AFTER "
               "miss_pipe_override (V2 zero-init compat)");
_Static_assert(sizeof(llb_doca_root_pipe_cfg) ==
               offsetof(llb_doca_root_pipe_cfg, _pad_v3) +
                   sizeof(((llb_doca_root_pipe_cfg *)0)->_pad_v3),
               "Phase 52 (D-04): _pad_v3 must be the LAST field "
               "(no trailing insertions without bumping V4)");

/* ---- Init / Shutdown ---- */
int  llb_doca_init(const char *pci_addr, int no_huge, const llb_doca_config *cfg);
void llb_doca_shutdown(void);
int  llb_doca_is_initialized(void);

/* ---- Port info ---- */
int llb_doca_get_port_id(void);
int llb_doca_get_port_mac(uint8_t mac_out[6]);
int llb_doca_get_port_count(void);
int llb_doca_get_port_mac_by_id(uint16_t port_id, uint8_t mac_out[6]);
int llb_doca_get_port_ifindex(uint16_t port_id, unsigned int *ifindex_out);

/* ---- Pipe lifecycle ---- */
llb_doca_pipe_handle_t llb_doca_pipe_create_basic(
    const char *name,
    uint32_t match_dst_ip_mask,   /* 0=wildcard, UINT32_MAX=exact */
    uint16_t match_dst_port_mask, /* 0=wildcard, UINT16_MAX=exact */
    uint32_t match_src_ip_mask,   /* 0=wildcard, UINT32_MAX=exact (SNAT pipes) */
    uint16_t match_src_port_mask, /* 0=wildcard, UINT16_MAX=exact (SNAT pipes) */
    uint8_t  match_proto,         /* IPPROTO_TCP, IPPROTO_UDP, 0=any */
    int fwd_type,                 /* LLB_DOCA_FWD_* */
    uint16_t fwd_port_id,         /* for FWD_PORT */
    uint32_t nr_entries           /* pipe capacity (0 = use default) */
);

int llb_doca_pipe_destroy(llb_doca_pipe_handle_t pipe);

/* ---- Root pipe access ---- */
llb_doca_pipe_handle_t llb_doca_get_root_pipe(void);

/* ---- CT-FWD pipe access (Phase 63-04 D-04, renamed from llb_doca_get_ct_pipe) ---- */
llb_doca_pipe_handle_t llb_doca_get_ct_fwd_pipe(void);

/* Phase 63-06 (TX-2): transitional alias `#define llb_doca_get_ct_pipe
 * llb_doca_get_ct_fwd_pipe` removed. The Go CGO wrapper rename to
 * DocaGetCTFwdPipe (calling C.llb_doca_get_ct_fwd_pipe directly) landed in
 * this plan; the alias is no longer needed. */

/* ---- CT-REV pipe access (Phase 52: per-direction reply pipe, D-01) ---- */
llb_doca_pipe_handle_t llb_doca_get_ct_rev_pipe(void);

/* Phase 63-06 (TX-1): the deliberate HAVE_DOCA=1 CGO link break for
 * DocaGetEgressSteerPipe / docaGetSteerPipeDirect is resolved by deleting
 * both Go wrappers and their callers in pkg/loxinet/dpu_doca_*. The
 * C-side prototype was already removed in Plan 63-04. */

/* ---- TEST-ONLY DIAGNOSTIC: rebuild CT_REV with miss=DROP ----
 * Verifies whether [TCP + port_meta=N/VF] traffic reaches CT_REV_5TUPLE_PIPE.
 * Must call llb_doca_rebuild_root_pipe() from Go after this to re-wire dispatch.
 * REMOVE after diagnosis is complete. ---- */
int llb_doca_ct_rev_test_drop_all(void);

/* ---- UDP CT pipe access (Phase 34, dedicated UDP conntrack pipe) ---- */
llb_doca_pipe_handle_t llb_doca_get_udp_ct_pipe(void);

/* ---- Root pipe rebuild (Phase 34, reusable for Phases 35/37) ---- */
int llb_doca_rebuild_root_pipe(const llb_doca_root_pipe_cfg *cfg);

/* Phase 63-04: EGRESS_STEER_NR_ENTRIES macro deleted along with the
 * EGRESS-domain steer pipe (CONTEXT.md D-04). The Go-side
 * GetEgressSteerCapacity() in pkg/loxinet/dpu_doca_cgo.go is a pure Go
 * constant (returns 1024) — Plan 63-06 will remove that helper and the
 * deferred_offload capacity gate that consumes it. */

/* ---- FDB L2 pipe (Phase 36: MAC-based unicast forwarding) ---- */
#define LLB_DOCA_FDB_PIPE_CAPACITY 4096

llb_doca_pipe_handle_t llb_doca_fdb_pipe_create(uint32_t nr_entries);

llb_doca_entry_handle_t llb_doca_fdb_entry_add(
    llb_doca_pipe_handle_t pipe,
    const uint8_t dst_mac[6],     /* match dst MAC, exact */
    uint16_t fwd_port_id,         /* per-entry FWD_PORT target (DPDK port ID for VF repr) */
    uint32_t aging_sec,           /* per-entry idle timeout (300 = bridge standard) */
    uint64_t user_ctx,            /* opaque ID for aged-entry identification */
    uint32_t timeout_ms           /* max wait for offload callback */
);

llb_doca_pipe_handle_t llb_doca_get_fdb_pipe(void);

/* ---- ACL HW offload (Phase 64: rebuilt from validated flow_acl_basic sample) ----
 *
 * Phase 37 single-pipe signatures and the Phase 63 L4 dispatch stub are RETIRED per Phase 64 D-19
 * (replaced by the lazy DENY+ALLOW pipe pair declared below; 15,360 shared NON_SHARED counter
 * ceiling per D-11; ROOT now dispatches per-L4-proto directly to CT_FWD).
 *
 * New Phase 64 pipeline: ROOT → DENY_PIPE → ALLOW_PIPE → CT_FWD → CT_REV(miss) → EGRESS_DISPATCH.
 * DENY_PIPE drops per-entry; ALLOW_PIPE is a counter-only audit layer (no MAC rewrite — CT owns that).
 * Both pipes are lazy: created on first HwOffload=true rule, destroyed when the last is removed (D-13).
 * Match shape: 5-tuple TRANSPORT with per-entry mask for CIDR support (D-08).
 */

/* Lazy lifecycle: create BOTH g_deny_pipe and g_allow_pipe atomically.
 * Returns LLB_DOCA_OK on success, LLB_DOCA_ERR on any failure (rollback both).
 * Idempotent — second call when both pipes are already up returns LLB_DOCA_OK.
 * ALLOW_PIPE is created FIRST because DENY_PIPE's fwd_miss.next_pipe = g_allow_pipe (D-13). */
int llb_doca_acl_pipes_create(void);

/* Lazy lifecycle: destroy BOTH pipes. Caller MUST first re-dispatch the root pipe
 * AWAY from g_deny_pipe before invoking this (D-13 OPENING→CLOSING sequencing). */
void llb_doca_acl_pipes_destroy(void);

/* Per-rule entry add for the DENY pipe. The pipe must be up — the caller must invoke the
 * lazy-create entry point first or expect NULL. `em` is an opaque pointer to a caller-
 * allocated `struct doca_flow_match` buffer (allocate via llb_doca_acl_match_alloc_ip4).
 * The opaque-pointer type matches the header's no-DOCA-include contract (line 21);
 * the implementation casts back to `struct doca_flow_match *` after including doca_flow.h.
 *
 * Exact-IP values only — DOCA 2.9.4 `doca_flow_pipe_add_entry` is 9-arg and BASIC pipes
 * use the pipe-level template mask set at create time; per-entry masks are NOT supported.
 * D-08 "CIDR via per-entry mask" was infeasible — corrected to exact-IP-only;
 * `validateHwOffloadExpressible` rejects non-/32 source / destination prefixes.
 *
 * When `timeout_ms > 0`, the call blocks on wait_entry_offload(); when `timeout_ms == 0`,
 * the call returns immediately after the DOCA_FLOW_NO_WAIT enqueue and the Go-side
 * debouncer drives doca_flow_entries_process() on its 50ms tick (D-15). Returns entry
 * handle (opaque), NULL on failure. */
llb_doca_entry_handle_t llb_doca_acl_deny_entry_add(
    const void *em,
    uint32_t timeout_ms);

/* Per-rule entry add for the ALLOW pipe. Same semantics as deny_entry_add but installs an
 * FWD_PIPE→g_ct_fwd_pipe action template (counter-only audit; CT owns MAC rewrite). */
llb_doca_entry_handle_t llb_doca_acl_allow_entry_add(
    const void *em,
    uint32_t timeout_ms);

/* Per-rule entry remove by handle. Returns LLB_DOCA_OK on success, LLB_DOCA_ERR on failure. */
int llb_doca_acl_deny_entry_del(llb_doca_entry_handle_t entry);
int llb_doca_acl_allow_entry_del(llb_doca_entry_handle_t entry);

/* Pipe-handle accessors. Return NULL when pipes are not up (D-13 lazy state). */
llb_doca_pipe_handle_t llb_doca_get_deny_pipe(void);
llb_doca_pipe_handle_t llb_doca_get_allow_pipe(void);

/* Match-buffer helpers — Plan 64-04 D-19 ext: the bridge header must stay free of
 * DOCA includes (loxilb_doca_flow.h:21 contract) so Go callers cannot use
 * `C.sizeof_struct_doca_flow_match` directly. These helpers allocate and fill an
 * opaque match buffer from primitive Go-side args, returning a heap pointer the
 * Go caller frees via llb_doca_acl_match_free. All IP fields are network byte
 * order; mask fields are network byte order (CIDR mask); ports are network byte
 * order; mask 0 = wildcard, mask 0xFFFF = exact. Returns NULL on calloc failure. */
void *llb_doca_acl_match_alloc_ip4(
    uint32_t src_ip,        /* network byte order; 0 = wildcard if mask=0 */
    uint32_t src_mask,      /* network byte order CIDR mask */
    uint32_t dst_ip,
    uint32_t dst_mask,
    uint16_t src_port,      /* network byte order; 0 = wildcard if mask=0 */
    uint16_t src_port_mask, /* 0=wildcard, 0xFFFF=exact (D-08) */
    uint16_t dst_port,
    uint16_t dst_port_mask);

/* Companion mask buffer (same shape; caller passes the mask values where the
 * value buffer takes the literal field values). Returned pointer is freed via
 * llb_doca_acl_match_free. */
void *llb_doca_acl_match_alloc_mask_ip4(
    uint32_t src_mask,
    uint32_t dst_mask,
    uint16_t src_port_mask,
    uint16_t dst_port_mask);

/* Free a buffer returned by either llb_doca_acl_match_alloc_ip4 or
 * llb_doca_acl_match_alloc_mask_ip4. Safe to call with NULL. */
void llb_doca_acl_match_free(void *match);

/* ---- Entry CRUD -- BASIC pipe ----
 *
 * Phase 63-06 (D-12): dropped the trailing `out_es_entry` out-param. The paired
 * g_egress_steer entry pattern (Phase 55 P2) is removed entirely — Plan 63-02
 * replaced it with a DEFAULT-domain g_egress_dispatch pipe that installs
 * static per-port FWD_PORT entries at init, and Plan 63-04 deleted
 * g_egress_steer_pipe wholesale. CT entries now drive the downstream dispatch
 * via meta.pkt_meta = target_port_id; no paired install is needed at flow time.
 *
 * REQ-55-INV-01 invariant preserved: the per-direction CT split (g_ct_fwd_pipe
 * forward + g_ct_rev_pipe reply, miss-chained per 63-04 D-04) still flows
 * through this single shared function body.
 */
llb_doca_entry_handle_t llb_doca_entry_add_basic(
    llb_doca_pipe_handle_t pipe,
    uint32_t dst_ip,              /* match dst IP, network byte order (0=don't match) */
    uint16_t dst_port,            /* match dst port, network byte order (0=don't match) */
    uint32_t src_ip,              /* match src IP, network byte order (0=don't match) */
    uint16_t src_port,            /* match src port, network byte order (0=don't match) */
    uint32_t new_dst_ip,          /* DNAT: network byte order, 0=no rewrite */
    uint16_t new_dst_port,        /* DNAT: network byte order, 0=no rewrite */
    uint32_t new_src_ip,          /* SNAT: network byte order, 0=no rewrite */
    uint16_t new_src_port,        /* SNAT: network byte order, 0=no rewrite */
    uint8_t  new_dst_mac[6],      /* DSR: dst MAC rewrite, all-zero=no rewrite */
    uint8_t  new_src_mac[6],      /* src MAC rewrite, all-zero=no rewrite */
    uint32_t timeout_ms,          /* max wait for offload callback */
    uint8_t  match_proto,         /* IPPROTO_TCP or IPPROTO_UDP for port field dispatch */
    uint16_t fwd_port_id,         /* per-entry FWD_PORT target (DPDK port ID for VF repr) */
    uint32_t aging_sec,           /* per-entry idle timeout for DOCA aging (Phase 35) */
    uint64_t user_ctx,            /* opaque ID for aged-entry identification (Phase 35) */
    uint32_t meter_id             /* shared meter ID (LLB_DOCA_METER_NONE = no meter) (Phase 38) */
);

/* ---- Entry remove ---- */
int llb_doca_entry_remove(llb_doca_pipe_handle_t pipe,
                           llb_doca_entry_handle_t entry,
                           uint32_t timeout_ms);

/* ---- Aging infrastructure (Phase 35) ---- */
#define LLB_DOCA_AGED_RING_SIZE 512

typedef struct {
    uint64_t user_ctx;
} llb_doca_aged_entry_t;

int llb_doca_aging_poll(uint64_t quota_time, uint32_t timeout_us, uint32_t max_entries);
int llb_doca_get_aged_entries(uint64_t *out_ctx, int max_out);

/* Plan 64-06: drain DOCA per-pipe-queue NO_WAIT pending buffer. Called from the
 * Go-side ACL debouncer after each batched flushAclPending tick. Required to
 * prevent silent INVALID_VALUE returns from doca_flow_pipe_add_entry once the
 * queue saturates (default ~128 entries on BF2 DOCA 2.9.4 switch,hws). */
int llb_doca_entries_drain(uint32_t timeout_us, uint32_t max_entries);

/* ---- Meter classification pipe (Phase 38: per-service/per-host metering) ---- */
#define LLB_DOCA_METER_PIPE_CAPACITY 256

/* Create meter classification BASIC pipe with FIXED meter_id (no wildcard).
 * BF2 firmware rejects meter_id wildcard in pipe templates.
 * Pipe-per-meter pattern: each policer creates its own pipe with a fixed meter.
 * Match: dst_ip wildcard (per-entry VIP or host).
 * FWD: next pipe (L4 dispatch).  Miss: same next pipe (passthrough). */
llb_doca_pipe_handle_t llb_doca_meter_pipe_create(
    llb_doca_pipe_handle_t miss_target,
    uint32_t meter_id,        /* fixed shared meter ID for ALL entries in this pipe */
    uint32_t nr_entries);

llb_doca_entry_handle_t llb_doca_meter_pipe_entry_add(
    llb_doca_pipe_handle_t pipe,
    uint32_t dst_ip,          /* match dst IP (VIP or host), network byte order; 0=any */
    uint32_t timeout_ms);

/* Get/set the "first" meter pipe (pipeline chain anchor).
 * Additional meter pipes chain: ACL miss → meter_pipe_0 → meter_pipe_1 → ... → dispatch */
llb_doca_pipe_handle_t llb_doca_get_meter_pipe(void);
void llb_doca_set_meter_pipe(llb_doca_pipe_handle_t pipe);

/* ---- Shared meter lifecycle (Phase 38: QoS metering HW offload) ---- */
#define LLB_DOCA_MAX_METERS   64
#define LLB_DOCA_METER_NONE   0xFFFFFFFF

/* Meter stats -- aggregate only (BF2 does not expose per-color via shared resource query) */
struct llb_doca_meter_stats {
    uint64_t total_pkts;
    uint64_t total_bytes;
};

int llb_doca_meter_add(uint32_t meter_id, uint64_t cir_bps, uint64_t cbs, uint64_t ebs);
int llb_doca_meter_del(uint32_t meter_id);
int llb_doca_meter_query(uint32_t meter_id, struct llb_doca_meter_stats *stats);
int llb_doca_entry_update_meter(llb_doca_pipe_handle_t pipe, void *entry_handle, uint32_t meter_id);

/* ---- Entry stats query ---- */
int llb_doca_entry_query(llb_doca_entry_handle_t entry,
                          uint64_t *bytes_out,
                          uint64_t *pkts_out);

/* SPIKE-001 DIAG: dump root-pipe per-entry counters to stderr.
 * Use to verify whether reply traffic reaches the root pipe and which
 * port_meta dispatch entry it hits.  Safe to call from any thread; the
 * cached entry handles are set once during init by llb_doca_rebuild_root_pipe. */
void llb_doca_diag_dump_root_entries(void);

/* Phase 65 — DOCA counter query bridge declarations (Plan 65-02). */
#include "loxilb_doca_metrics.h"
