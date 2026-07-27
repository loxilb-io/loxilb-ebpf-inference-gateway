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
 * loxilb_doca_flow.c -- DOCA 2.9.4 Flow bridge implementation.
 *
 * Wraps DOCA Flow opaque APIs (init, pipe lifecycle, entry CRUD) behind
 * simple C functions with llb_doca_ prefix.  Patterns extracted from
 * hardware-validated VD helpers (doca_verify_flow_common.h, vd2, vd5).
 *
 * This file is compiled ONLY when HAVE_DOCA=1 (real BF2 hardware).
 * For non-DOCA builds, loxilb_doca_flow_stub.c provides no-op stubs.
 */

#include "loxilb_doca_flow.h"

/* Compile-time guard: FWD_PORT must never be 0 (FWD_DROP) */
_Static_assert(LLB_DOCA_FWD_PORT != 0,
    "LLB_DOCA_FWD_PORT must not be 0 (FWD_DROP)");

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <netinet/in.h>
#include <net/if.h>  /* SPIKE-001: if_indextoname for port enumeration dump */

/* DOCA SDK headers */
#include <doca_flow.h>
#include <doca_dpdk.h>
#include <doca_dev.h>
#include <doca_error.h>

/* DPDK headers */
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_flow.h>  /* T4l: rte_flow_isolate for switch-mode port init */

/* ----------------------------------------------------------------
 *  Static globals
 * ---------------------------------------------------------------- */

static struct doca_dev       *g_dev  = NULL;
static struct doca_flow_port *g_ports[LLB_DOCA_MAX_PORTS];
#define g_port g_ports[0]   /* backward-compat alias for existing readers */
static struct doca_flow_port *g_switch_port = NULL;
/* + unified CT pipe architecture (topology-agnostic):
 *   RSS pipe → to_kernel pipe (FWD_TARGET KERNEL)
 *   root_l3l4_dispatch_pipe (BASIC, is_root, L3+L4 classifier, Step 6e)
 * > acl_pipe (BASIC, deny-only firewall, Step 6d4)
 * > [meter_pipe_N,...] (dynamic, per-policer)
 * > l4_dispatch_pipe (BASIC, Step 6d2)
 *           -> CT_5TUPLE_PIPE (BASIC, TRANSPORT, no dir_info, Step 6c)
 *           -> udp_ct_pipe (BASIC, UDP, no dir_info, Step 6d)
 *     -> to_kernel_pipe (root miss: ICMP, GRE, ARP, IPv6)
 * fdb_pipe (BASIC, independent L2, Step 6f — last, non-fatal)
 *
 * Root pipe matches parser_meta.outer_l3_type + outer_l4_type (per-entry).
 * Dispatch: TCP+UDP → ACL (or L4_dispatch if ACL absent, or CT fallback).
 * BF2 limitation: in v4.0 fallback (no ACL/L4_dispatch), both TCP+UDP must
 * dispatch to CT_5TUPLE_PIPE only — udp_ct_pipe cannot receive HW hits when
 * set as a separate next_pipe target from root.
 * No dir_info annotations — unified pipes handle all directions/topologies.
 *
 * The CT pipe replaces the former LB+LPM pipe pair — it handles both NAT
 * (conntrack) entries and non-NAT route entries through a single BASIC pipe.
 * This is a DOCA BASIC pipe used as a conntrack cache — not DOCA's native
 * DOCA_FLOW_PIPE_CT type which has different semantics.
 *
 * llb_doca_pipe_create_basic() creates additional non-root pipes (SNAT, etc.)
 * that are independent of the root/CT chain.
 */
static struct doca_flow_pipe *g_root_pipe      = NULL;
/* SPIKE-001 DIAG: cache the to_kernel pipe's catch-all entry handle.
 * The pipe itself is already in g_to_kernel_pipe; this is the first (only)
 * entry in it.  Used by llb_doca_diag_dump_pipe_misses() to read total
 * to-kernel volume vs each upstream pipe's miss count. */
static struct doca_flow_pipe_entry *g_to_kernel_entry = NULL;
/* miss-chained CT pipe pair.
 * g_ct_fwd_pipe (renamed from g_ct_pipe) handles uplink→VIP DNAT+SNAT.
 * g_ct_rev_pipe handles VIP→uplink reverse SNAT+DNAT, reached via fwd's
 * miss action. Both forward to g_egress_dispatch via template fwd; both
 * miss off-chain into g_to_kernel_pipe (ct_rev only) or g_ct_rev_pipe
 * (ct_fwd). Mirrors the validated sample's lb_fwd → lb_rev → to_kernel
 * pattern (flow_lb_snat_dnat_sample.c:786-799). */
static struct doca_flow_pipe *g_ct_fwd_pipe    = NULL;
static struct doca_flow_pipe *g_ct_rev_pipe    = NULL;  /* origin; rebuilt 63-04 as fwd-miss target */
/* g_egress_steer_pipe deleted wholesale (EGRESS-domain pipe was
 * architecture, proven wrong by validated DOCA samples — see
 * CONTEXT.md + STATE.md SUPERSEDED notice). Replaced by miss-chained
 * BASIC DEFAULT pair (g_ct_fwd_pipe → g_ct_rev_pipe → g_to_kernel_pipe) that
 * forwards to g_egress_dispatch via template fwd. */
/* Plan 02 (per CONTEXT.md): DEFAULT-domain BASIC pipe that
 * matches meta.pkt_meta and forwards to a discovered port via per-entry FWD_PORT.
 * Sample analog: flow_e2e_l3_routing_sample.c:169-242 (create_egress_dispatch_pipe).
 * Declared unconditionally; the former LLB_DOCA_SPIKE_003_META_DISPATCH gate is gone. */
static struct doca_flow_pipe *g_egress_dispatch = NULL;
static struct doca_flow_pipe *g_udp_ct_pipe    = NULL;  /* dedicated UDP CT pipe */
static struct doca_flow_pipe *g_fdb_pipe       = NULL;  /* L2 FDB MAC forwarding pipe */
/* rebuilt-from-validated-sample DENY+ALLOW pipe pair.
 * Lazy lifecycle — both NULL until the first FwRule with HwOffload=true arrives,
 * destroyed when the last HwOffload=true rule is removed. DENY drops per-entry,
 * ALLOW forwards to g_ct_fwd_pipe as a counter-only audit layer (CT owns MAC rewrite). */
static struct doca_flow_pipe *g_deny_pipe       = NULL;  /* ACL deny pipe (lazy) */
static struct doca_flow_pipe *g_allow_pipe      = NULL;  /* ACL allow pipe (lazy) */
static struct doca_flow_pipe *g_meter_pipe      = NULL;  /* meter classification pipe (no NAT) */
static struct doca_flow_pipe *g_l4_dispatch_pipe = NULL; /* vestigial: always NULL post-Phase-64; accessor kept for Go binary compat until Plan 64-03 retires the Go bridge */
static struct doca_flow_pipe *g_rss_pipe       = NULL;
static struct doca_flow_pipe *g_to_kernel_pipe = NULL;
static struct doca_flow_target *g_kernel_target = NULL;
static int g_root_pipe_has_actions = 0;  /* false: root pipe is port_meta dispatcher only */
static int g_ct_pipe_has_actions   = 1;  /* true: unified CT pipe has NAT actions */
static int                    g_num_ports   = 0;
static uint32_t               g_num_repr    = 2;  /* default VF representor count */
/* SPIKE-001: include host-PF representor (pf0hpf) in the probe so we can A/B test
 * port_meta dispatch through a non-VF representor. mlx5 typically assigns
 * port_id=1 to pf0hpf when present, shifting VF reps to port_id=2..N+1.
 * Set to 0 (or revert the devargs string) to restore the original VF-only probe. */
static int                    g_has_pf_rep  = 1;  /* T4q1: re-enabled.
                                                    * T4k temporarily disabled to match
                                                    * sample's single-probe pattern during
                                                    * EOPNOTSUPP bisect; T4m proved actual
                                                    * cause was missing set_dev, not dual-probe.
                                                    * Restoring PF-rep so user can test
                                                    * traffic via pf0hpf instead of pf0vf0. */
static uint16_t               g_dpdk_port_id = 0;
static int                    g_initialized = 0;

/* Configurable pipe capacities (overridden by llb_doca_config in init) */
static uint32_t g_ct_pipe_capacity       = 8192;
static uint32_t g_udp_ct_pipe_capacity   = 8192;  /* default same as TCP */
static uint32_t g_snat_pipe_capacity     = 2048;

/* Entry callback state */
static volatile int g_entry_status = -1;
static int g_meter_capable = 0;  /* set to 1 if shared meter pre-alloc succeeded */

/* Aged-entry ring buffer (producer=callback, consumer=poll drain, same thread) */
static llb_doca_aged_entry_t g_aged_ring[LLB_DOCA_AGED_RING_SIZE];
static uint32_t g_aged_ring_head = 0; /* written by callback */
static uint32_t g_aged_ring_tail = 0; /* read by poll drain */

/* ----------------------------------------------------------------
 *  Monotonic millisecond helper
 * ---------------------------------------------------------------- */
static uint64_t llb_monotonic_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

/* ----------------------------------------------------------------
 *  Entry-status callback (same pattern as VD2/VD5)
 * ---------------------------------------------------------------- */
static void entry_status_cb(struct doca_flow_pipe_entry *entry,
                              uint16_t pipe_queue,
                              enum doca_flow_entry_status status,
                              enum doca_flow_entry_op op,
                              void *user_ctx)
{
    (void)entry; (void)pipe_queue;
    g_entry_status = (int)status;

    /* detect aged entries via op field (NOT status enum) */
    if (op == DOCA_FLOW_ENTRY_OP_AGED && user_ctx) {
        uint32_t h = __atomic_load_n(&g_aged_ring_head, __ATOMIC_RELAXED);
        uint32_t next = (h + 1) % LLB_DOCA_AGED_RING_SIZE;
        if (next != __atomic_load_n(&g_aged_ring_tail, __ATOMIC_ACQUIRE)) {
            g_aged_ring[h].user_ctx = (uint64_t)(uintptr_t)user_ctx;
            __atomic_store_n(&g_aged_ring_head, next, __ATOMIC_RELEASE);
        }
    }
}

/* ----------------------------------------------------------------
 *  Helper: build doca_flow_fwd from LLB_DOCA_FWD_* type
 * ---------------------------------------------------------------- */
static void build_fwd(struct doca_flow_fwd *fwd, int fwd_type,
                       uint16_t fwd_port_id)
{
    memset(fwd, 0, sizeof(*fwd));
    switch (fwd_type) {
    case LLB_DOCA_FWD_PORT:
        fwd->type = DOCA_FLOW_FWD_PORT;
        fwd->port_id = fwd_port_id;
        break;
    case LLB_DOCA_FWD_RSS:
        /* LLB_DOCA_FWD_RSS is only used internally for g_rss_pipe creation
         * which builds its own FWD struct directly (not via build_fwd()).
         * External callers should never reach this case -- drop as safety net. */
        fprintf(stderr, "llb_doca: WARN build_fwd(): LLB_DOCA_FWD_RSS hit unexpectedly\n");
        fwd->type = DOCA_FLOW_FWD_DROP;
        break;
    case LLB_DOCA_FWD_DROP:
    default:
        fwd->type = DOCA_FLOW_FWD_DROP;
        break;
    }
}

/* ----------------------------------------------------------------
 *  Helper: wait for entry callback to fire or timeout
 * ---------------------------------------------------------------- */
static int wait_entry_offload(uint32_t timeout_ms)
{
    uint64_t t0 = llb_monotonic_ms();

    while (g_entry_status < 0) {
        doca_flow_entries_process(g_switch_port, 0, 1000, 32);
        if (llb_monotonic_ms() - t0 > timeout_ms)
            break;
    }

    if (g_entry_status == (int)DOCA_FLOW_ENTRY_STATUS_SUCCESS)
        return LLB_DOCA_OK;

    if (g_entry_status < 0) {
        fprintf(stderr, "llb_doca: entry callback not fired within %u ms\n",
                timeout_ms);
        return LLB_DOCA_ERR_TIMEOUT;
    }

    fprintf(stderr, "llb_doca: entry status %d (expected SUCCESS=%d)\n",
            g_entry_status, (int)DOCA_FLOW_ENTRY_STATUS_SUCCESS);
    return LLB_DOCA_ERR_ENTRY;
}

/* ================================================================
 *  Init / Shutdown
 * ================================================================ */

int llb_doca_init(const char *pci_addr, int no_huge, const llb_doca_config *cfg)
{
    doca_error_t dret;
    int i;

    if (g_initialized)
        return LLB_DOCA_OK;

    if (!pci_addr || !*pci_addr)
        return LLB_DOCA_ERR_PARAM;

    /* Read num_repr from config */
    g_num_repr = (cfg && cfg->num_repr > 0) ? cfg->num_repr : 2;

    /* Apply capacity configuration (0 = use default) */
    if (cfg) {
        if (cfg->ct_pipe_capacity > 0)       g_ct_pipe_capacity       = cfg->ct_pipe_capacity;
        if (cfg->udp_ct_pipe_capacity > 0)   g_udp_ct_pipe_capacity   = cfg->udp_ct_pipe_capacity;
        if (cfg->snat_pipe_capacity > 0)     g_snat_pipe_capacity     = cfg->snat_pipe_capacity;
    }

    /* ---- Step 1: DPDK EAL init (vd_dpdk_init pattern) ---- */
    /* NOTE: --no-signal-handler is NOT supported by DOCA 2.9.4's bundled
     * DPDK (validated on BF2 hardware 2026-03-24).  Omitted to avoid
     * EAL init failure.  Go runtime signal handling coexists with DPDK
     * in --no-huge mode without conflict. */
    char prog[]      = "loxilb-doca";
    char no_huge_f[] = "--no-huge";
    char mem_f[]     = "-m";
    char mem_sz[]    = "256";
    char dev_f[]     = "-a";
    char dummy_pci[] = "pci:00:00.0";

    char *argv_nohuge[] = { prog, no_huge_f, mem_f, mem_sz,
                            dev_f, dummy_pci, NULL };
    char *argv_base[]   = { prog, mem_f, mem_sz,
                            dev_f, dummy_pci, NULL };
    char **argv = no_huge ? argv_nohuge : argv_base;
    int   argc  = no_huge ? 6 : 5;

    if (rte_eal_init(argc, argv) < 0) {
        fprintf(stderr, "llb_doca: rte_eal_init failed\n");
        return LLB_DOCA_ERR_EAL;
    }

    /* ---- Step 2: Open device by PCI + probe DPDK port ---- */
    /* Normalize PCI address to include domain prefix */
    char full_pci[64];
    if (strlen(pci_addr) > 4 && pci_addr[4] == ':')
        snprintf(full_pci, sizeof(full_pci), "%s", pci_addr);
    else
        snprintf(full_pci, sizeof(full_pci), "0000:%s", pci_addr);

    /* Open DOCA device */
    struct doca_devinfo **dev_list = NULL;
    uint32_t nb_devs = 0;
    dret = doca_devinfo_create_list(&dev_list, &nb_devs);
    if (dret != DOCA_SUCCESS || nb_devs == 0) {
        fprintf(stderr, "llb_doca: doca_devinfo_create_list failed: %s\n",
                doca_error_get_descr(dret));
        rte_eal_cleanup();
        return LLB_DOCA_ERR_DEV;
    }

    struct doca_dev *dev = NULL;
    for (uint32_t di = 0; di < nb_devs; di++) {
        char dev_pci[32] = {0};
        doca_devinfo_get_pci_addr_str(dev_list[di], dev_pci);
        if (dev_pci[0] && strcmp(dev_pci, full_pci) == 0) {
            dret = doca_dev_open(dev_list[di], &dev);
            break;
        }
    }
    doca_devinfo_destroy_list(dev_list);

    if (!dev) {
        fprintf(stderr, "llb_doca: device %s not found\n", full_pci);
        rte_eal_cleanup();
        return LLB_DOCA_ERR_DEV;
    }

    /* Probe DPDK port with switch-mode devargs + representor range (PORT-01).
     *
     * SPIKE-001: include the host-PF representor (pf0hpf) so we can A/B test
     * port_meta dispatch through a non-VF rep.
     *
     * Authoritative reference: tools/doca2-verify/vd_basicscale.c:test_r1
     * (VD15.R1) documents that mlx5 vport 65535 = host-PF representor on
     * this DOCA/BF2 combo, and explicitly says:
     *
     *   "Probe pf0hpf representor. DOCA sample pattern: append
     *    ',representor=[65535]' to the switch devargs and call
     *    doca_dpdk_port_probe() on the SAME doca_dev."
     *
     * Iteration history (all on this exact bf2-arm + DOCA 2.9.4):
     *   FAIL  representor=[pf0,vf0-N]       — bare pfN parsed as self-ref
     *   FAIL  representor=[c1pf0,vf0-N]     — controller prefix unsupported
     *   FAIL  representor=[65535,vf0-N]     — mixed magic + vf-range list
     *                                          rejected by mlx5 list parser
     *   PASS  representor=vf0-N             — original loxilb (VFs only)
     *   PASS  representor=[65535]           — pf0hpf only (vd_basicscale)
     *
     * Resolution: TWO sequential probes on the same doca_dev.  The "SAME
     * doca_dev" phrasing in vd_basicscale's comment implicitly assumes a
     * prior probe — that's the documented pattern.
     */
    char devargs[512];
    snprintf(devargs, sizeof(devargs),
        "dv_flow_en=2,fdb_def_rule_en=0,vport_match=1,repr_matching_en=0,"
        "dv_xmeta_en=4,representor=vf0-%u",
        g_num_repr - 1);
    fprintf(stderr, "llb_doca: SPIKE-001 probe-1 (VF reps) devargs = %s\n", devargs);
    dret = doca_dpdk_port_probe(dev, devargs);
    if (dret != DOCA_SUCCESS) {
        fprintf(stderr, "llb_doca: doca_dpdk_port_probe (VF reps) failed: %s\n",
                doca_error_get_descr(dret));
        doca_dev_close(dev);
        rte_eal_cleanup();
        return LLB_DOCA_ERR_DEV;
    }

    if (g_has_pf_rep) {
        /* Second probe on the SAME doca_dev to add the host-PF rep
         * (vd_basicscale.c:test_r1 documented pattern). */
        const char *pf_rep_devargs =
            "dv_flow_en=2,fdb_def_rule_en=0,vport_match=1,repr_matching_en=0,"
            "dv_xmeta_en=4,representor=[65535]";
        fprintf(stderr, "llb_doca: SPIKE-001 probe-2 (host PF rep) devargs = %s\n",
                pf_rep_devargs);
        dret = doca_dpdk_port_probe(dev, pf_rep_devargs);
        if (dret != DOCA_SUCCESS) {
            fprintf(stderr,
                "llb_doca: SPIKE-001 host-PF-rep probe failed (continuing without): %s\n",
                doca_error_get_descr(dret));
            /* Don't fail init — we still have VFs.  The A/B test loses its
             * pf0hpf arm but VF arm still runs. */
            g_has_pf_rep = 0;
        }
    }

    /* T4l: Configure and start ALL DPDK ports (uplink + representors).
     * Previously we only configured/started port 0. EGRESS-domain BASIC pipes on
     * BF2 require every port to have valid TX queue context — they operate at
     * the eswitch crossbar level and need every representor port DPDK-started
     * before doca_flow_init() touches them.
     *
     * Mirrors the sample's dpdk_queues_and_ports_init() which configures ALL
     * ports uniformly with isolated_mode=1 (rte_flow_isolate) before DOCA flow
     * init. Without this, EGRESS pipe creation fails EOPNOTSUPP because the
     * crossbar can't commit egress paths to ports lacking valid TX state. */
    uint16_t total_dpdk_ports = rte_eth_dev_count_avail();
    fprintf(stderr, "llb_doca: T4l configuring %u DPDK ports (was 1)\n",
            total_dpdk_ports);

    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create(
        "LLB_DOCA_MBUF", 1024 * total_dpdk_ports, 256, 0,
        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!mbuf_pool) {
        fprintf(stderr, "llb_doca: mbuf pool create failed\n");
        doca_dev_close(dev);
        rte_eal_cleanup();
        return LLB_DOCA_ERR_PORT;
    }

    for (uint16_t pid = 0; pid < total_dpdk_ports; pid++) {
        struct rte_eth_conf port_conf;
        memset(&port_conf, 0, sizeof(port_conf));

        if (rte_eth_dev_configure(pid, 1, 1, &port_conf) < 0) {
            fprintf(stderr, "llb_doca: T4l rte_eth_dev_configure(port=%u) failed\n", pid);
            doca_dev_close(dev);
            rte_eal_cleanup();
            return LLB_DOCA_ERR_PORT;
        }

        if (rte_eth_rx_queue_setup(pid, 0, 256,
                                    rte_socket_id(), NULL, mbuf_pool) < 0) {
            fprintf(stderr, "llb_doca: T4l rx_queue_setup(port=%u) failed\n", pid);
            doca_dev_close(dev);
            rte_eal_cleanup();
            return LLB_DOCA_ERR_PORT;
        }
        if (rte_eth_tx_queue_setup(pid, 0, 256,
                                    rte_socket_id(), NULL) < 0) {
            fprintf(stderr, "llb_doca: T4l tx_queue_setup(port=%u) failed\n", pid);
            doca_dev_close(dev);
            rte_eal_cleanup();
            return LLB_DOCA_ERR_PORT;
        }

        /* T4l: enable isolated mode (matches sample's port_config.isolated_mode=1).
         * Required for DOCA-managed flow rules — must be called BEFORE dev_start.
         * Without this, mlx5 default-rx-classifier may fight DOCA pipe placement. */
        struct rte_flow_error fl_err;
        memset(&fl_err, 0, sizeof(fl_err));
        if (rte_flow_isolate(pid, 1, &fl_err) != 0) {
            fprintf(stderr, "llb_doca: T4l rte_flow_isolate(port=%u) failed: %s "
                    "(non-fatal — continuing)\n", pid,
                    fl_err.message ? fl_err.message : "(no msg)");
        }

        if (rte_eth_dev_start(pid) < 0) {
            fprintf(stderr, "llb_doca: T4l rte_eth_dev_start(port=%u) failed\n", pid);
            doca_dev_close(dev);
            rte_eal_cleanup();
            return LLB_DOCA_ERR_PORT;
        }

        fprintf(stderr, "llb_doca: T4l DPDK port %u configured + isolated + started\n", pid);
    }

    /* ---- Step 3: DOCA Flow init (vd_flow_init pattern) ---- */
    /* Renamed local to flow_cfg to avoid shadowing input 'cfg' parameter */
    struct doca_flow_cfg *flow_cfg = NULL;
    dret = doca_flow_cfg_create(&flow_cfg);
    if (dret != DOCA_SUCCESS) {
        fprintf(stderr, "llb_doca: doca_flow_cfg_create failed: %s\n",
                doca_error_get_descr(dret));
        doca_dev_close(dev);
        rte_eal_cleanup();
        return LLB_DOCA_ERR_FLOW;
    }

    doca_flow_cfg_set_pipe_queues(flow_cfg, 1);

    /* T4k: add set_default_rss to match sample's init_doca_flow_cb
     * (flow_common.c:88-96). The sample sets default RSS with 1 queue ([0]).
     * queues_array must remain valid until doca_flow_init() runs — same scope
     * is fine. Hypothesis: missing default RSS may interact with EGRESS-domain
     * BASIC pipe creation on BF2 (RSS hash policy default is needed). */
    uint16_t t4k_rss_queues[1] = { 0 };
    struct doca_flow_resource_rss_cfg t4k_rss = {0};
    t4k_rss.nr_queues = 1;
    t4k_rss.queues_array = t4k_rss_queues;
    doca_flow_cfg_set_default_rss(flow_cfg, &t4k_rss);

    /* testbed-portability gap: `isolated` + `hairpinq_num=4` are
     * load-bearing for doca_flow_get_target(DOCA_FLOW_TARGET_KERNEL) on BF2
 * DOCA 2.9.4. stripped them as " diagnostic noise",
     * but the to_kernel pipe's FWD_TARGET(KERNEL) — which is how every
     * unmatched packet reaches the eBPF slow path — returns EOPNOTSUPP
     * without the hairpin-queue backing. The validated samples use FWD_RSS
     * and so never needed this; loxilb's integration always relied on the
     * explicit kernel target. Restored to the proven Spike-003 string. */
    doca_flow_cfg_set_mode_args(flow_cfg, "switch,hws,isolated,hairpinq_num=4");
    doca_flow_cfg_set_cb_entry_process(flow_cfg, entry_status_cb);
    /* Sample-aligned default; was diagnostic value 22 during EGRESS-domain bisect. */
    doca_flow_cfg_set_nr_counters(flow_cfg, 65536);

    /* T4k: skip METER reservation. Sample doesn't reserve METER
     * shared resources. Hypothesis: METER reservation may make EGRESS-domain
 * BASIC pipe creation impossible. meter offload will be disabled
     * in this run — acceptable for diagnostic; CB drops back if needed. */
    g_meter_capable = 0;
    /*
    dret = doca_flow_cfg_set_nr_shared_resource(flow_cfg, 64,
                                                 DOCA_FLOW_SHARED_RESOURCE_METER);
    if (dret != DOCA_SUCCESS) {
        fprintf(stderr, "llb_doca: WARN shared meter pre-alloc failed: %s (non-fatal, meter offload disabled)\n",
                doca_error_get_descr(dret));
        g_meter_capable = 0;
    } else {
        g_meter_capable = 1;
    }
    */

    /* T4e: reserve shared mirror resources required for EGRESS-domain
     * BASIC pipes on BF2/DOCA 2.9.4. Without this, doca_flow_pipe_create rejects
     * EGRESS-domain pipes with DOCA_ERROR_NOT_PERMITTED. Reference: DOCA 2.9.4
     * sample flow_switch_to_wire_sample.c:643 (nr_shared_resources[MIRROR] = 4). */
    dret = doca_flow_cfg_set_nr_shared_resource(flow_cfg, 4,
                                                 DOCA_FLOW_SHARED_RESOURCE_MIRROR);
    if (dret != DOCA_SUCCESS) {
        fprintf(stderr, "llb_doca: WARN shared mirror pre-alloc failed: %s "
                "(EGRESS-domain egress_steer pipe creation will fail)\n",
                doca_error_get_descr(dret));
    }

    dret = doca_flow_init(flow_cfg);
    doca_flow_cfg_destroy(flow_cfg);
    if (dret != DOCA_SUCCESS) {
        fprintf(stderr, "llb_doca: doca_flow_init failed: %s\n",
                doca_error_get_descr(dret));
        doca_dev_close(dev);
        rte_eal_cleanup();
        return LLB_DOCA_ERR_FLOW;
    }

    /* ---- Step 4: Start all flow ports (PF + VF reprs) (PORT-02) ---- */
    /* SPIKE-001: if pf0 representor included, total = uplink + pf0_rep + VF reprs. */
    int total_ports = 1 + (g_has_pf_rep ? 1 : 0) + (int)g_num_repr;
    if (total_ports > LLB_DOCA_MAX_PORTS)
        total_ports = LLB_DOCA_MAX_PORTS;
    /* testbed-portability gap: cap by actual DPDK port count. SPIKE-001
     * probes for `vf0-3` (4 VFs) but smaller testbeds enumerate fewer ports.
     * Without this cap, doca_flow_port_start fails on port_id >= dpdk_avail and
     * the whole init aborts even though the available ports would have worked. */
    {
        int dpdk_avail = (int)rte_eth_dev_count_avail();
        if (total_ports > dpdk_avail) {
            fprintf(stderr,
                    "llb_doca: capping total_ports %d -> %d "
                    "(DPDK enumerated %d; probe asked for more VFs than testbed provides)\n",
                    total_ports, dpdk_avail, dpdk_avail);
            total_ports = dpdk_avail;
        }
    }

    memset(g_ports, 0, sizeof(g_ports));
    for (i = 0; i < total_ports; i++) {
        struct doca_flow_port_cfg *port_cfg = NULL;
        dret = doca_flow_port_cfg_create(&port_cfg);
        if (dret != DOCA_SUCCESS) {
            fprintf(stderr, "llb_doca: port_cfg_create failed for port %d: %s\n",
                    i, doca_error_get_descr(dret));
            goto port_fail;
        }
        /* T4m: set doca_dev for port 0 (proxy), NULL for representors.
         * MIRRORS sample's create_doca_flow_port at flow_common.c:182 — sample
         * passes dev_arr[port_id] where dev_arr[0]=doca_dev, dev_arr[1..N]=NULL.
         * Without set_dev, DOCA can't establish the eswitch ↔ doca_dev binding
         * that EGRESS-domain pipes require to commit egress paths. This is the
         * one API call from the sample's port-init we were missing. */
        doca_flow_port_cfg_set_dev(port_cfg, (i == 0) ? dev : NULL);

        char port_id_str[8];
        snprintf(port_id_str, sizeof(port_id_str), "%u", i);
        doca_flow_port_cfg_set_devargs(port_cfg, port_id_str);

        /* T4l: set operation_state=ACTIVE (matches sample's
         * init_doca_flow_ports_with_op_state at flow_common.c:248). Without
         * explicit ACTIVE state, DOCA may default to a state where EGRESS-domain
         * pipes can't be created. */
        doca_flow_port_cfg_set_operation_state(port_cfg,
                                               DOCA_FLOW_PORT_OPERATION_STATE_ACTIVE);

        dret = doca_flow_port_start(port_cfg, &g_ports[i]);
        doca_flow_port_cfg_destroy(port_cfg);
        if (dret != DOCA_SUCCESS) {
            fprintf(stderr, "llb_doca: port_start failed for port %d: %s\n",
                    i, doca_error_get_descr(dret));
            goto port_fail;
        }
    }
    g_num_ports = total_ports;

    /* SPIKE-001: dump enumerated DPDK ports so we can map port_id → port_meta value
     * before trusting the root pipe's dispatch table. mlx5 typically orders:
     *   port_id=0 uplink, port_id=1 pf0hpf (if probed), port_id=2..N+1 pf0vfX. */
    fprintf(stderr, "llb_doca: SPIKE-001 port enumeration after probe (g_has_pf_rep=%d, g_num_repr=%u, total=%d):\n",
            g_has_pf_rep, g_num_repr, total_ports);
    for (int p = 0; p < total_ports; p++) {
        struct rte_eth_dev_info pinfo;
        memset(&pinfo, 0, sizeof(pinfo));
        if (rte_eth_dev_info_get((uint16_t)p, &pinfo) != 0) {
            fprintf(stderr, "  port_id=%d  rte_eth_dev_info_get failed\n", p);
            continue;
        }
        struct rte_ether_addr mac;
        memset(&mac, 0, sizeof(mac));
        rte_eth_macaddr_get((uint16_t)p, &mac);
        char ifname[64] = "(unknown)";
        if (pinfo.if_index > 0)
            (void)if_indextoname(pinfo.if_index, ifname);
        fprintf(stderr,
            "  port_id=%d  if_index=%u  ifname=%s  mac=%02x:%02x:%02x:%02x:%02x:%02x  driver=%s\n",
            p, pinfo.if_index, ifname,
            mac.addr_bytes[0], mac.addr_bytes[1], mac.addr_bytes[2],
            mac.addr_bytes[3], mac.addr_bytes[4], mac.addr_bytes[5],
            pinfo.driver_name ? pinfo.driver_name : "(null)");
    }

    /* ---- Step 5: Get switch port (FWD-03) ---- */
    g_switch_port = doca_flow_port_switch_get(g_ports[0]);
    if (!g_switch_port) {
        fprintf(stderr, "llb_doca: doca_flow_port_switch_get returned NULL\n");
        goto port_fail;
    }

    /* ---- Step 6: Unified pipe chain (topology-agnostic, no dir_info) ---- */
    /* Bottom-up creation: RSS → to_kernel → CT → root.
     * Root pipe dispatches ALL port_meta values to single unified CT pipe.
     * No dir_info annotations — unified pipes handle all directions. */

    /* 6a: Create RSS pipe (leaf -- created first) */
    {
        struct doca_flow_pipe_cfg *pipe_cfg = NULL;
        dret = doca_flow_pipe_cfg_create(&pipe_cfg, g_switch_port);
        if (dret != DOCA_SUCCESS) {
            fprintf(stderr, "llb_doca: rss pipe_cfg_create failed: %s\n",
                    doca_error_get_descr(dret));
            goto port_fail;
        }

        doca_flow_pipe_cfg_set_name(pipe_cfg, "rss_pipe");
        doca_flow_pipe_cfg_set_is_root(pipe_cfg, false);
        doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
        doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 1);

        /* Match: outer_l3_type = IPV4 */
        struct doca_flow_match rss_match;
        memset(&rss_match, 0, sizeof(rss_match));
        rss_match.parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4;
        doca_flow_pipe_cfg_set_match(pipe_cfg, &rss_match, NULL);

        /* Forward: RSS */
        uint16_t rss_queues[1] = { 0 };
        struct doca_flow_fwd rss_fwd;
        memset(&rss_fwd, 0, sizeof(rss_fwd));
        rss_fwd.type = DOCA_FLOW_FWD_RSS;
        rss_fwd.rss_queues = rss_queues;
        rss_fwd.num_of_queues = 1;
        rss_fwd.rss_outer_flags = DOCA_FLOW_RSS_IPV4 | DOCA_FLOW_RSS_TCP;

        struct doca_flow_pipe *pipe = NULL;
        doca_error_t err = doca_flow_pipe_create(pipe_cfg, &rss_fwd,
                                                  NULL, &pipe);
        doca_flow_pipe_cfg_destroy(pipe_cfg);
        if (err != DOCA_SUCCESS) {
            fprintf(stderr, "llb_doca: rss pipe create failed: %s\n",
                    doca_error_get_descr(err));
            goto port_fail;
        }

        /* Add one catch-all entry */
        struct doca_flow_match rss_entry_match;
        memset(&rss_entry_match, 0, sizeof(rss_entry_match));
        g_entry_status = -1;
        struct doca_flow_pipe_entry *rss_entry = NULL;
        err = doca_flow_pipe_add_entry(0, pipe,
                                        &rss_entry_match, NULL,
                                        NULL, NULL,
                                        DOCA_FLOW_NO_WAIT,
                                        NULL, &rss_entry);
        if (err != DOCA_SUCCESS) {
            fprintf(stderr, "llb_doca: rss pipe entry failed: %s\n",
                    doca_error_get_descr(err));
            goto port_fail;
        }
        if (wait_entry_offload(5000) != LLB_DOCA_OK) {
            fprintf(stderr, "llb_doca: rss pipe entry offload timeout\n");
            goto port_fail;
        }

        g_rss_pipe = pipe;
        fprintf(stderr, "llb_doca: rss pipe created OK\n");
    }

    /* 6a-egress: EGRESS_STEER_PIPE creation block deleted in 63-04.
     * The validated DOCA samples (flow_lb_snat_dnat + flow_e2e_l3_routing) prove
     * the EGRESS-domain pipe with paired-entry pattern is the wrong architecture
     * on BF2 DOCA 2.9.4. Replaced by miss-chained BASIC DEFAULT pair
     * (g_ct_fwd_pipe → g_ct_rev_pipe) that forward to g_egress_dispatch (built
 * just below at step 6b2) via template fwd. See CONTEXT.md +. */

    /* 6b: Create to_kernel pipe (middle) */
    {
        /* Get kernel target handle. Requires `isolated,hairpinq_num=4` in the
         * doca_flow mode_args (set above) — without the hairpin-queue backing
         * DOCA 2.9.4 returns EOPNOTSUPP here. This FWD_TARGET(KERNEL) pipe is
         * how every unmatched packet reaches the eBPF slow path. */
        dret = doca_flow_get_target(DOCA_FLOW_TARGET_KERNEL, &g_kernel_target);
        if (dret != DOCA_SUCCESS) {
            fprintf(stderr, "llb_doca: doca_flow_get_target(KERNEL) failed: %s\n",
                    doca_error_get_descr(dret));
            goto port_fail;
        }

        struct doca_flow_pipe_cfg *pipe_cfg = NULL;
        dret = doca_flow_pipe_cfg_create(&pipe_cfg, g_switch_port);
        if (dret != DOCA_SUCCESS) {
            fprintf(stderr, "llb_doca: to_kernel pipe_cfg_create failed: %s\n",
                    doca_error_get_descr(dret));
            goto port_fail;
        }

        doca_flow_pipe_cfg_set_name(pipe_cfg, "to_kernel_pipe");
        doca_flow_pipe_cfg_set_is_root(pipe_cfg, false);
        doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
        doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 1);

        /* SPIKE-001 DIAG: enable monitor + miss counter so we can see how
         * many packets fall all the way through to to_kernel (vs being eaten
         * earlier by FDB/CT/L4 dispatch). The single catch-all entry already
         * matches every packet, so the entry counter will tell us total
         * to-kernel volume; miss counter will be 0 if all packets match. */
        struct doca_flow_monitor tk_monitor;
        memset(&tk_monitor, 0, sizeof(tk_monitor));
        tk_monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
        doca_flow_pipe_cfg_set_monitor(pipe_cfg, &tk_monitor);
        doca_flow_pipe_cfg_set_miss_counter(pipe_cfg, true);

        /* Match: empty (catch ALL traffic -- ARP, IPv4, IPv6, etc.)
         * Root pipe miss sends non-IPv4 here, so we must not filter by L3 type.
         * LB pipe miss sends unmatched IPv4 here too.  Both need kernel delivery. */
        struct doca_flow_match tk_match;
        memset(&tk_match, 0, sizeof(tk_match));
        doca_flow_pipe_cfg_set_match(pipe_cfg, &tk_match, NULL);

        /* Forward: FWD_TARGET(KERNEL) — the actual kernel sink. The empty
         * catch-all entry below matches every packet, so this fwd (not the
         * miss) is what delivers ARP / ICMP / IPv6 / slow-path IPv4 onto the
         * ingress port's kernel netdev, where the eBPF tc hooks pick it up.
         * Requires the hairpinq_num=4 mode_args (set above); the DOCA 2.9.4
         * reference for this exact form is flow_switch_single_sample.c:195.
         *
         * NOTE: 141c4d3b mis-wired this to FWD_PIPE->g_rss_pipe on the false
         * premise that DOCA 2.9.4 lacks FWD_TARGET(KERNEL). That commit's
         * EOPNOTSUPP was actually the missing hairpinq_num — fixed in 49cfcd7c,
         * which restored the mode_args + get_target() call but missed restoring
         * THIS assignment. g_rss_pipe is not a kernel sink: FWD_RSS goes to DPDK
         * RSS queues, which loxilb's DOCA side never drains for slow path — so
         * packets were black-holed (TO_KERNEL_ENTRY counter incremented but
         * nothing reached the kernel). This completes the 49cfcd7c revert. */
        struct doca_flow_fwd tk_fwd;
        memset(&tk_fwd, 0, sizeof(tk_fwd));
        tk_fwd.type = DOCA_FLOW_FWD_TARGET;
        tk_fwd.target = g_kernel_target;

        /* Miss: FWD_PIPE -> g_rss_pipe. Effectively unreachable (the empty
         * catch-all entry matches everything) but mirrors the sample's
         * fwd_miss -> rss pipe. */
        struct doca_flow_fwd tk_miss;
        memset(&tk_miss, 0, sizeof(tk_miss));
        tk_miss.type = DOCA_FLOW_FWD_PIPE;
        tk_miss.next_pipe = g_rss_pipe;

        struct doca_flow_pipe *pipe = NULL;
        doca_error_t err = doca_flow_pipe_create(pipe_cfg, &tk_fwd,
                                                  &tk_miss, &pipe);
        doca_flow_pipe_cfg_destroy(pipe_cfg);
        if (err != DOCA_SUCCESS) {
            fprintf(stderr, "llb_doca: to_kernel pipe create failed: %s\n",
                    doca_error_get_descr(err));
            goto port_fail;
        }

        /* Add one entry matching L3_META_IPV4 */
        struct doca_flow_match tk_entry_match;
        memset(&tk_entry_match, 0, sizeof(tk_entry_match));
        g_entry_status = -1;
        struct doca_flow_pipe_entry *tk_entry = NULL;
        err = doca_flow_pipe_add_entry(0, pipe,
                                        &tk_entry_match, NULL,
                                        NULL, NULL,
                                        DOCA_FLOW_NO_WAIT,
                                        NULL, &tk_entry);
        if (err != DOCA_SUCCESS) {
            fprintf(stderr, "llb_doca: to_kernel pipe entry failed: %s\n",
                    doca_error_get_descr(err));
            goto port_fail;
        }
        if (wait_entry_offload(5000) != LLB_DOCA_OK) {
            fprintf(stderr, "llb_doca: to_kernel pipe entry offload timeout\n");
            goto port_fail;
        }

        g_to_kernel_pipe = pipe;
        g_to_kernel_entry = tk_entry;  /* SPIKE-001 DIAG: cache for dump */
        fprintf(stderr, "llb_doca: to_kernel pipe created OK "
                "(catch-all, FWD_TARGET KERNEL)\n");
    }

    /* 6b2: Create egress_dispatch pipe ( Plan 02, per CONTEXT.md).
     *
     * Sample analog: flow_e2e_l3_routing_sample.c:169-242 (create_egress_dispatch_pipe).
     *
     * Shape:
     *   - DOCA_FLOW_PIPE_BASIC, DEFAULT domain (no set_dir_info, no set_domain(EGRESS)).
     *   - Match key: meta.pkt_meta CHANGEABLE (UINT32_MAX in mask, 0 in template).
     *   - Template fwd: FWD_PORT with port_id=0xFFFF (wildcard sentinel; per-entry overrides).
     *   - Miss: FWD_PIPE -> g_to_kernel_pipe.
     *   - Entries: N pre-installed FWD_PORT(pid) entries where N = g_num_ports
     *     (uplink + optional PF rep + g_num_repr VF reps).
     *   - Per-entry match value uses NETWORK byte order: em.meta.pkt_meta = htonl(pid).
     *
     * Construction order: must exist BEFORE g_ct_pipe / g_ct_rev_pipe creation
     * because those pipes' template fwd references g_egress_dispatch (under
     * #ifdef LLB_DOCA_SPIKE_003_META_DISPATCH today; rewired unconditionally in 63-04). */
    {
        struct doca_flow_pipe_cfg *pipe_cfg = NULL;
        dret = doca_flow_pipe_cfg_create(&pipe_cfg, g_switch_port);
        if (dret != DOCA_SUCCESS) {
            fprintf(stderr, "llb_doca: egress_dispatch pipe_cfg_create failed: %s\n",
                    doca_error_get_descr(dret));
            goto port_fail;
        }

        doca_flow_pipe_cfg_set_name(pipe_cfg, "EGRESS_DISPATCH_PIPE");
        doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
        doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_DEFAULT);
        doca_flow_pipe_cfg_set_is_root(pipe_cfg, false);
        doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 16);
        /* NOTE: deliberately NO doca_flow_pipe_cfg_set_dir_info() — sample omits it
 * and the EGRESS-domain artifacts proved set_dir_info(BIDIRECTIONAL)
         * silently breaks data plane on BF2 DOCA 2.9.4. */

        /* Match: meta.pkt_meta CHANGEABLE */
        struct doca_flow_match m, mm;
        memset(&m, 0, sizeof(m));
        memset(&mm, 0, sizeof(mm));
        mm.meta.pkt_meta = UINT32_MAX;
        doca_flow_pipe_cfg_set_match(pipe_cfg, &m, &mm);

        /* Template fwd: FWD_PORT with wildcard port_id, overridden per entry.
         * (NOT FWD_CHANGEABLE — sample explicitly uses FWD_PORT(0xFFFF).) */
        struct doca_flow_fwd template_fwd;
        memset(&template_fwd, 0, sizeof(template_fwd));
        template_fwd.type    = DOCA_FLOW_FWD_PORT;
        template_fwd.port_id = 0xFFFF;

        /* Miss: FWD_PIPE -> to_kernel_pipe */
        struct doca_flow_fwd miss_fwd;
        memset(&miss_fwd, 0, sizeof(miss_fwd));
        miss_fwd.type      = DOCA_FLOW_FWD_PIPE;
        miss_fwd.next_pipe = g_to_kernel_pipe;

        struct doca_flow_pipe *pipe = NULL;
        doca_error_t err = doca_flow_pipe_create(pipe_cfg, &template_fwd,
                                                  &miss_fwd, &pipe);
        doca_flow_pipe_cfg_destroy(pipe_cfg);
        if (err != DOCA_SUCCESS || !pipe) {
            fprintf(stderr, "llb_doca: egress_dispatch pipe_create failed: %s\n",
                    doca_error_get_descr(err));
            goto port_fail;
        }
        g_egress_dispatch = pipe;

        /* Install FWD_PORT(pid) entries for every discovered port.
         * g_num_ports was set to (1 + g_has_pf_rep + g_num_repr) at line ~552. */
        for (int pid = 0; pid < g_num_ports; pid++) {
            struct doca_flow_match em;
            struct doca_flow_fwd   ef;
            memset(&em, 0, sizeof(em));
            memset(&ef, 0, sizeof(ef));
            em.meta.pkt_meta = htonl((uint32_t)pid);
            ef.type    = DOCA_FLOW_FWD_PORT;
            ef.port_id = (uint16_t)pid;

            g_entry_status = -1;
            struct doca_flow_pipe_entry *ed_entry = NULL;
            err = doca_flow_pipe_add_entry(0, g_egress_dispatch, &em, NULL,
                                            NULL, &ef, DOCA_FLOW_NO_WAIT,
                                            NULL, &ed_entry);
            if (err != DOCA_SUCCESS) {
                fprintf(stderr,
                        "llb_doca: egress_dispatch FWD_PORT(%d) add failed: %s\n",
                        pid, doca_error_get_descr(err));
                continue;
            }
            if (wait_entry_offload(5000) != LLB_DOCA_OK) {
                fprintf(stderr,
                        "llb_doca: egress_dispatch FWD_PORT(%d) offload timeout\n",
                        pid);
                continue;
            }
            fprintf(stderr,
                    "llb_doca: egress_dispatch FWD_PORT(%d) installed OK\n", pid);
        }

        fprintf(stderr,
                "llb_doca: egress_dispatch pipe created OK "
                "(BASIC DEFAULT, match=meta.pkt_meta, fwd=FWD_PORT(per-entry), "
                "miss->to_kernel, n_entries=%d)\n",
                g_num_ports);
    }

    /* 6c-rev: Create CT REV pipe (miss-chain target for
     * g_ct_fwd_pipe; sample-aligned with flow_lb_snat_dnat_sample.c's lb_rev_pipe).
     *
     * Construction order requirement (PATTERNS.md §"Pipe-chain construction
     * order" / sample lines 786-799): the REVERSE pipe must be created BEFORE
     * the FORWARD pipe because the forward pipe references g_ct_rev_pipe as
     * its miss target in doca_flow_pipe_create's miss_fwd argument.
     *
 * Shape: BASIC DEFAULT, no set_dir_info ( already removed),
     * protocol-agnostic TRANSPORT match handles both TCP+UDP.
     * Capacity: combined 2 * g_ct_pipe_capacity (16384)
     * fwd  template → g_egress_dispatch (per-flow CT entry's pkt_meta NAT
     *                 action drives the downstream FWD_PORT selection)
     * miss          → g_to_kernel_pipe (slow-path fallback for reply traffic
     *                 with no matching rev-CT entry)
     */
    {
        struct doca_flow_pipe_cfg *pipe_cfg = NULL;
        dret = doca_flow_pipe_cfg_create(&pipe_cfg, g_switch_port);
        if (dret != DOCA_SUCCESS) {
            fprintf(stderr, "llb_doca: ct_rev pipe_cfg_create failed: %s\n",
                    doca_error_get_descr(dret));
            goto port_fail;
        }

        doca_flow_pipe_cfg_set_name(pipe_cfg, "CT_REV_5TUPLE_PIPE");
        doca_flow_pipe_cfg_set_is_root(pipe_cfg, false);
        doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
        doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, g_ct_pipe_capacity * 2);
        /* testbed-validation gap: set_dir_info(BIDIRECTIONAL) is
         * load-bearing for the FWD_TARGET(KERNEL) slow-path return on BF2.
         * The "DOCA ground truth reset" retraction was derived from the
         * validated samples — but those samples deliver to kernel via FWD_RSS,
         * never FWD_TARGET(KERNEL), so they never exercised whatever the eswitch
         * needs set_dir_info for. Without it, reply-direction packets reach the
         * to_kernel pipe (counter increments) but FWD_TARGET(KERNEL) silently
         * fails to land them on the ingress port's kernel netdev. Restored to
         * match the proven Spike-003 CT pipe shape. */
        doca_flow_pipe_cfg_set_dir_info(pipe_cfg, DOCA_FLOW_DIRECTION_BIDIRECTIONAL);

        /* Match: protocol-agnostic TRANSPORT (TCP+UDP via per-entry l4_type).
         * Loxilb-specific divergence from sample (PATTERNS.md §"loxilb-specific
         * divergence"): sample uses TCP-only EXT, loxilb uses TRANSPORT so one
         * pipe handles both protocols — no separate UDP CT pipe needed. */
        struct doca_flow_match lb_match;
        memset(&lb_match, 0, sizeof(lb_match));
        lb_match.parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4;
        lb_match.parser_meta.outer_l4_type = UINT32_MAX;             /* per-entry TCP/UDP */
        lb_match.outer.l4_type_ext         = DOCA_FLOW_L4_TYPE_EXT_TRANSPORT;
        lb_match.outer.l3_type             = DOCA_FLOW_L3_TYPE_IP4;
        lb_match.outer.ip4.src_ip          = 0xffffffff;
        lb_match.outer.ip4.dst_ip          = 0xffffffff;
        lb_match.outer.transport.src_port  = 0xffff;
        lb_match.outer.transport.dst_port  = 0xffff;
        doca_flow_pipe_cfg_set_match(pipe_cfg, &lb_match, NULL);

        /* NAT action template: src_ip + dst_ip + src_mac + dst_mac +
         * pkt_meta — all CHANGEABLE. Per-entry NAT action sets concrete values
         * including pkt_meta = htonl(target_port_id) which g_egress_dispatch
         * matches downstream. Mirrors create_lb_pipe() in the validated sample. */
        struct doca_flow_actions lb_actions;
        memset(&lb_actions, 0, sizeof(lb_actions));
        lb_actions.outer.l3_type            = DOCA_FLOW_L3_TYPE_IP4;
        lb_actions.outer.ip4.dst_ip         = UINT32_MAX;
        lb_actions.outer.ip4.src_ip         = UINT32_MAX;
        memset(lb_actions.outer.eth.src_mac, 0xFF, 6);
        memset(lb_actions.outer.eth.dst_mac, 0xFF, 6);
        lb_actions.outer.transport.src_port = UINT16_MAX;
        lb_actions.outer.transport.dst_port = UINT16_MAX;
        lb_actions.meta.pkt_meta            = UINT32_MAX;
        struct doca_flow_actions *lb_acts_arr[1] = { &lb_actions };
        doca_flow_pipe_cfg_set_actions(pipe_cfg, lb_acts_arr, NULL, NULL, 1);

        /* Monitor: per-entry NON_SHARED counter + aging wildcard */
        struct doca_flow_monitor lb_monitor;
        memset(&lb_monitor, 0, sizeof(lb_monitor));
        lb_monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
        lb_monitor.aging_sec    = 0xffffffff;
        doca_flow_pipe_cfg_set_monitor(pipe_cfg, &lb_monitor);
        doca_flow_pipe_cfg_set_miss_counter(pipe_cfg, true);

        /* fwd  template → g_egress_dispatch (pkt_meta drives port selection)
         * miss          → g_to_kernel_pipe (slow-path fallback) */
        struct doca_flow_fwd lb_fwd;
        memset(&lb_fwd, 0, sizeof(lb_fwd));
        lb_fwd.type      = DOCA_FLOW_FWD_PIPE;
        lb_fwd.next_pipe = g_egress_dispatch;

        struct doca_flow_fwd lb_miss;
        memset(&lb_miss, 0, sizeof(lb_miss));
        lb_miss.type      = DOCA_FLOW_FWD_PIPE;
        lb_miss.next_pipe = g_to_kernel_pipe;

        struct doca_flow_pipe *pipe = NULL;
        doca_error_t err = doca_flow_pipe_create(pipe_cfg, &lb_fwd,
                                                  &lb_miss, &pipe);
        doca_flow_pipe_cfg_destroy(pipe_cfg);
        if (err != DOCA_SUCCESS) {
            fprintf(stderr, "llb_doca: CT_REV pipe create failed: %s\n",
                    doca_error_get_descr(err));
            goto port_fail;
        }

        g_ct_rev_pipe = pipe;
        fprintf(stderr, "llb_doca: CT_REV 5-tuple pipe created OK "
                "(BASIC DEFAULT, no set_dir_info, capacity=%u, NAT actions, "
                "fwd=PIPE(egress_dispatch), miss->to_kernel)\n",
                g_ct_pipe_capacity * 2);
    }

    /* 6c-fwd: Create CT FWD pipe (forward direction of the
     * miss-chained pair). Mirrors flow_lb_snat_dnat_sample.c:267-370 create_lb_pipe.
     *
     * Created AFTER g_ct_rev_pipe because its miss target is g_ct_rev_pipe
     * (sample chain rule, lines 786-799).
     *
     * fwd  template → g_egress_dispatch  (forward CT hit → egress_dispatch
     *                                     does the per-port FWD)
     * miss          → g_ct_rev_pipe      (miss-chain: try the reverse pipe
     *                                     before falling all the way through) */
    {
        struct doca_flow_pipe_cfg *pipe_cfg = NULL;
        dret = doca_flow_pipe_cfg_create(&pipe_cfg, g_switch_port);
        if (dret != DOCA_SUCCESS) {
            fprintf(stderr, "llb_doca: ct_fwd pipe_cfg_create failed: %s\n",
                    doca_error_get_descr(dret));
            goto port_fail;
        }

        doca_flow_pipe_cfg_set_name(pipe_cfg, "CT_FWD_5TUPLE_PIPE");
        doca_flow_pipe_cfg_set_is_root(pipe_cfg, false);
        doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
        doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, g_ct_pipe_capacity * 2);
        /* set_dir_info(BIDIRECTIONAL): load-bearing for FWD_TARGET(KERNEL)
         * slow-path return — see the matching comment on CT_REV above. */
        doca_flow_pipe_cfg_set_dir_info(pipe_cfg, DOCA_FLOW_DIRECTION_BIDIRECTIONAL);

        /* Match: identical to ct_rev — protocol-agnostic TRANSPORT 5-tuple. */
        struct doca_flow_match lb_match;
        memset(&lb_match, 0, sizeof(lb_match));
        lb_match.parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4;
        lb_match.parser_meta.outer_l4_type = UINT32_MAX;
        lb_match.outer.l4_type_ext         = DOCA_FLOW_L4_TYPE_EXT_TRANSPORT;
        lb_match.outer.l3_type             = DOCA_FLOW_L3_TYPE_IP4;
        lb_match.outer.ip4.src_ip          = 0xffffffff;
        lb_match.outer.ip4.dst_ip          = 0xffffffff;
        lb_match.outer.transport.src_port  = 0xffff;
        lb_match.outer.transport.dst_port  = 0xffff;
        doca_flow_pipe_cfg_set_match(pipe_cfg, &lb_match, NULL);

        /* NAT action template: identical shape to ct_rev. */
        struct doca_flow_actions lb_actions;
        memset(&lb_actions, 0, sizeof(lb_actions));
        lb_actions.outer.l3_type            = DOCA_FLOW_L3_TYPE_IP4;
        lb_actions.outer.ip4.dst_ip         = UINT32_MAX;
        lb_actions.outer.ip4.src_ip         = UINT32_MAX;
        memset(lb_actions.outer.eth.src_mac, 0xFF, 6);
        memset(lb_actions.outer.eth.dst_mac, 0xFF, 6);
        lb_actions.outer.transport.src_port = UINT16_MAX;
        lb_actions.outer.transport.dst_port = UINT16_MAX;
        lb_actions.meta.pkt_meta            = UINT32_MAX;
        struct doca_flow_actions *lb_acts_arr[1] = { &lb_actions };
        doca_flow_pipe_cfg_set_actions(pipe_cfg, lb_acts_arr, NULL, NULL, 1);

        struct doca_flow_monitor lb_monitor;
        memset(&lb_monitor, 0, sizeof(lb_monitor));
        lb_monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
        lb_monitor.aging_sec    = 0xffffffff;
        doca_flow_pipe_cfg_set_monitor(pipe_cfg, &lb_monitor);
        doca_flow_pipe_cfg_set_miss_counter(pipe_cfg, true);

        /* fwd  template → g_egress_dispatch (forward hit case)
         * miss          → g_ct_rev_pipe     (miss-chain to reverse) */
        struct doca_flow_fwd lb_fwd;
        memset(&lb_fwd, 0, sizeof(lb_fwd));
        lb_fwd.type      = DOCA_FLOW_FWD_PIPE;
        lb_fwd.next_pipe = g_egress_dispatch;

        struct doca_flow_fwd lb_miss;
        memset(&lb_miss, 0, sizeof(lb_miss));
        lb_miss.type      = DOCA_FLOW_FWD_PIPE;
        lb_miss.next_pipe = g_ct_rev_pipe;

        struct doca_flow_pipe *pipe = NULL;
        doca_error_t err = doca_flow_pipe_create(pipe_cfg, &lb_fwd,
                                                  &lb_miss, &pipe);
        doca_flow_pipe_cfg_destroy(pipe_cfg);
        if (err != DOCA_SUCCESS) {
            fprintf(stderr, "llb_doca: CT_FWD pipe create failed: %s\n",
                    doca_error_get_descr(err));
            goto port_fail;
        }

        g_ct_fwd_pipe = pipe;
        fprintf(stderr, "llb_doca: CT_FWD 5-tuple pipe created OK "
                "(BASIC DEFAULT, no set_dir_info, capacity=%u, NAT actions, "
                "fwd=PIPE(egress_dispatch), miss=PIPE(ct_rev))\n",
                g_ct_pipe_capacity * 2);
    }

    /* stub: DOCA pipe creation/entry-update deferred until validated
     * against the new core pipeline (CT pair + egress_dispatch + simplified root).
     * Go-side Capabilities() still advertises this offload; eBPF slow path handles
 * the feature at runtime. Restoration plan: CONTEXT.md. Old body in git
     * history at <pre-Phase-63 commit>.
     *
     * UDP CT pipe specifically: the unified g_ct_fwd_pipe/g_ct_rev_pipe pair built
     * in Plan 63-04 uses protocol-agnostic TRANSPORT match, so it already carries
     * UDP traffic without a dedicated UDP pipe. g_udp_ct_pipe stays declared at
     * line 100 and remains NULL for the lifetime of the process. */
    /* g_udp_ct_pipe stays NULL — UDP traffic flows through unified CT pair */

    /* 6d2-6d4: L4-dispatch + single-pipe ACL init removed by.
     * The post-Phase-63 ROOT pipe dispatches per-L4-proto directly to CT_FWD, with no
     * L4-dispatch hop. ACL is now a lazy DENY+ALLOW pipe pair created on first
 * FwRule with HwOffload=true — see the lifecycle entry point below.
 * Meter pipes remain dynamic per-policer, unchanged by. */
    /* g_l4_dispatch_pipe and g_deny_pipe/g_allow_pipe stay NULL at init time. */

    /* 6e: Create FDB L2 pipe BEFORE root rebuild.
     *
     * The FDB pipe must exist before we build the root so that the root's
 * miss_pipe_override can point at it -- otherwise the FDB pipe
     * would be orphaned (Bug #2: root miss went direct to to_kernel, no
     * packet ever reached the FDB pipe).
     *
     * Independent BASIC pipe matching outer.eth.dst_mac with FWD_PORT action.
     * Miss action: to_kernel (broadcast, multicast, unknown unicast) --
 * set inside llb_doca_fdb_pipe_create, unchanged by.
     *
     * Non-fatal: if FDB pipe creation fails, g_fdb_pipe stays NULL and the
     * root rebuild below falls back to V1 semantics (miss -> to_kernel). */
    g_fdb_pipe = (struct doca_flow_pipe *)llb_doca_fdb_pipe_create(
        LLB_DOCA_FDB_PIPE_CAPACITY);
    if (!g_fdb_pipe) {
        fprintf(stderr, "llb_doca: FDB pipe creation failed (non-fatal, root miss -> to_kernel)\n");
    } else {
        fprintf(stderr, "llb_doca: FDB L2 pipe created, capacity=%u\n",
                LLB_DOCA_FDB_PIPE_CAPACITY);
    }

    /* 6f: Create root BASIC pipe via llb_doca_rebuild_root_pipe().
     *
 * (REVISED — per-ingress-port dispatch restored):
     * The root pipe dispatches by (ingress port_meta, L4 proto). Forward traffic
     * (ingress = uplink p0, port_meta=0) → g_ct_fwd_pipe. Reply traffic (ingress
     * = any representor, port_meta=1..N) → g_ct_rev_pipe directly. This mirrors
 * the proven Spike-003 / per-direction routing.
     *
     * WHY match_port_meta=1 is load-bearing (not just a filter):
     * When the root pipe MATCHES on parser_meta.port_meta, BF2 carries port_meta
     * through the whole pipeline as flow context. The slow-path tail
     * (ct_* miss → to_kernel → FWD_TARGET(KERNEL)) relies on that preserved
     * port_meta so FWD_TARGET(KERNEL) lands the packet on the *ingress port's*
 * kernel netdev. With match_port_meta=0 (the collapsed form),
     * port_meta is never looked at — FWD_TARGET(KERNEL) then defaults every
     * slow-path packet onto port 0's netdev. Forward traffic (ingress p0) works
     * by luck; reply traffic (ingress pf0vf0) is delivered to the wrong netdev
     * and lost. That broke the eBPF reply slow-path AND kernel ping of every
     * non-uplink endpoint. Restoring per-port matching fixes both.
     *
     * The Plan 63-04 miss-chain (g_ct_fwd_pipe miss → g_ct_rev_pipe → to_kernel)
     * is preserved and still used by forward traffic that misses ct_fwd.
     *
     * V3 ABI for `llb_doca_root_pipe_cfg` is PRESERVED — _Static_assert anchors
     * in the header (loxilb_doca_flow.h:127-141) remain unchanged.
     *
     * Non-TCP/non-UDP IPv4 (ICMP, GRE) and non-IPv4 (ARP, IPv6) fall through
 * root pipe miss → FDB pipe ( V2 miss-override) → fdb miss →
     * to_kernel; port_meta is still carried so kernel delivery lands right. */
    {
        llb_doca_root_pipe_cfg root_cfg;
        memset(&root_cfg, 0, sizeof(root_cfg));
        root_cfg.version         = LLB_DOCA_ROOT_PIPE_CFG_V3; /* V3 ABI preserved */
        root_cfg.nr_entries      = 16;                         /* headroom over num_dispatch */
        root_cfg.match_port_meta = 1;                          /* per-ingress-port exact match */

        /* Per-(port_meta, proto) dispatch. port_meta=0 (uplink p0) → forward CT
         * pipe; port_meta=1..N (representors) → reply CT pipe. TCP entries first
         * (critical path), then UDP, truncating UDP if the 8-slot dispatch array
         * would overflow on a many-VF testbed. */
        uint32_t idx = 0;
        for (int p = 0; p < g_num_ports && idx < LLB_DOCA_ROOT_PIPE_MAX_DISPATCH; p++) {
            root_cfg.dispatch[idx].l4_type    = DOCA_FLOW_L4_META_TCP;
            root_cfg.dispatch[idx].target     = (p == 0)
                ? (llb_doca_pipe_handle_t)g_ct_fwd_pipe
                : (llb_doca_pipe_handle_t)g_ct_rev_pipe;
            root_cfg.port_meta_value[idx]     = (uint32_t)p;
            idx++;
        }
        for (int p = 0; p < g_num_ports && idx < LLB_DOCA_ROOT_PIPE_MAX_DISPATCH; p++) {
            root_cfg.dispatch[idx].l4_type    = DOCA_FLOW_L4_META_UDP;
            root_cfg.dispatch[idx].target     = (p == 0)
                ? (llb_doca_pipe_handle_t)g_ct_fwd_pipe
                : (llb_doca_pipe_handle_t)g_ct_rev_pipe;
            root_cfg.port_meta_value[idx]     = (uint32_t)p;
            idx++;
        }
        root_cfg.num_dispatch       = idx;
        /* miss_pipe_override is set for completeness, but note rebuild_root only
         * honors it for V2 callers — a V3 caller's root miss goes straight to
         * g_to_kernel_pipe. That is correct here: ICMP/ARP/non-TCP-UDP fall to
         * to_kernel with port_meta preserved (the pipe template carries it once
         * match_port_meta=1), so kernel delivery still lands on the right netdev. */
        root_cfg.miss_pipe_override = (llb_doca_pipe_handle_t)g_fdb_pipe;

        int rc = llb_doca_rebuild_root_pipe(&root_cfg);
        if (rc != LLB_DOCA_OK) {
            fprintf(stderr, "llb_doca: root pipe rebuild failed: %d\n", rc);
            goto port_fail;
        }
        fprintf(stderr,
            "llb_doca: root pipe rebuilt ( per-port) — %u dispatch entries "
            "(port_meta=0 → g_ct_fwd_pipe; port_meta=1..%d → g_ct_rev_pipe; "
            "miss → to_kernel, port_meta preserved)\n", idx, g_num_ports - 1);
    }

    /* Store in globals */
    g_dev = dev;
    g_dpdk_port_id = 0;  /* T4l: PF/uplink port is always port_id=0 */
    g_initialized = 1;

    return LLB_DOCA_OK;

port_fail:
    /* Cleanup already-started ports in reverse order */
    for (i = g_num_ports > 0 ? g_num_ports - 1 : total_ports - 1; i >= 0; i--) {
        if (g_ports[i]) {
            doca_flow_port_stop(g_ports[i]);
            g_ports[i] = NULL;
        }
    }
    g_num_ports = 0;
    g_switch_port = NULL;
    doca_flow_destroy();
    doca_dev_close(dev);
    rte_eal_cleanup();
    return LLB_DOCA_ERR_PORT;
}

void llb_doca_shutdown(void)
{
    if (!g_initialized)
        return;

    /* Stop ports in reverse order (VF reprs first, PF last) */
    for (int i = g_num_ports - 1; i >= 0; i--) {
        if (g_ports[i]) {
            doca_flow_port_stop(g_ports[i]);
            g_ports[i] = NULL;
        }
    }
    g_num_ports = 0;
    g_switch_port = NULL;
    g_root_pipe = NULL;
    g_ct_fwd_pipe = NULL;   /* renamed from g_ct_pipe */
    g_ct_rev_pipe = NULL;   /* prevent stale handle on re-init (Pitfall 3) */
    /* g_egress_steer_pipe deleted. */
    g_egress_dispatch = NULL;    /* same re-init Pitfall 3 protection */
    g_udp_ct_pipe = NULL;
    g_fdb_pipe = NULL;
    /* lazy DENY+ALLOW pipes — destroy if currently up (idempotent NULL-safe). */
    if (g_deny_pipe) {
        doca_flow_pipe_destroy(g_deny_pipe);
        g_deny_pipe = NULL;
    }
    if (g_allow_pipe) {
        doca_flow_pipe_destroy(g_allow_pipe);
        g_allow_pipe = NULL;
    }
    /* g_l4_dispatch_pipe stays NULL post-Phase-64; nothing to destroy. */
    g_l4_dispatch_pipe = NULL;
    g_rss_pipe = NULL;
    g_to_kernel_pipe = NULL;
    g_kernel_target = NULL;
    g_root_pipe_has_actions = 0;
    g_ct_pipe_has_actions = 0;
    doca_flow_destroy();

    if (g_dev) {
        doca_dev_close(g_dev);
        g_dev = NULL;
    }

    rte_eal_cleanup();
    g_initialized = 0;
}

int llb_doca_is_initialized(void)
{
    return g_initialized;
}

/* ================================================================
 *  Port info
 * ================================================================ */

int llb_doca_get_port_id(void)
{
    if (!g_initialized)
        return LLB_DOCA_ERR_NOTSUP;
    return (int)g_dpdk_port_id;
}

int llb_doca_get_port_mac(uint8_t mac_out[6])
{
    if (!g_initialized || !mac_out)
        return LLB_DOCA_ERR_PARAM;

    struct rte_ether_addr addr;
    int ret = rte_eth_macaddr_get(g_dpdk_port_id, &addr);
    if (ret < 0)
        return LLB_DOCA_ERR_DEV;

    memcpy(mac_out, addr.addr_bytes, 6);
    return LLB_DOCA_OK;
}

int llb_doca_get_port_count(void)
{
    return g_num_ports;
}

int llb_doca_get_port_mac_by_id(uint16_t port_id, uint8_t mac_out[6])
{
    if (port_id >= (uint16_t)g_num_ports)
        return LLB_DOCA_ERR_PARAM;
    if (!mac_out)
        return LLB_DOCA_ERR_PARAM;

    struct rte_ether_addr addr;
    int ret = rte_eth_macaddr_get(port_id, &addr);
    if (ret != 0)
        return LLB_DOCA_ERR_PORT;

    memcpy(mac_out, addr.addr_bytes, 6);
    return LLB_DOCA_OK;
}

int llb_doca_get_port_ifindex(uint16_t port_id, unsigned int *ifindex_out)
{
    if (port_id >= (uint16_t)g_num_ports || !ifindex_out)
        return LLB_DOCA_ERR_PARAM;

    struct rte_eth_dev_info info;
    int ret = rte_eth_dev_info_get(port_id, &info);
    if (ret != 0)
        return LLB_DOCA_ERR_PORT;

    *ifindex_out = info.if_index;
    return LLB_DOCA_OK;
}

/* ================================================================
 *  Pipe lifecycle -- external API for Go-created pipes (SNAT, etc.)
 *
 *  These pipes are independent of the root/CT chain created during
 *  llb_doca_init().  They are non-root, created on g_switch_port,
 *  and have their own actions templates and miss forwarding (DROP).
 * ================================================================ */

llb_doca_pipe_handle_t llb_doca_pipe_create_basic(
    const char *name,
    uint32_t match_dst_ip_mask,
    uint16_t match_dst_port_mask,
    uint32_t match_src_ip_mask,
    uint16_t match_src_port_mask,
    uint8_t  match_proto,
    int fwd_type,
    uint16_t fwd_port_id,
    uint32_t nr_entries)
{
    doca_error_t ret;

    if (!g_initialized || !name)
        return NULL;

    /* Match template */
    struct doca_flow_match match_template;
    memset(&match_template, 0, sizeof(match_template));
    match_template.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
    match_template.outer.ip4.dst_ip = match_dst_ip_mask;
    if (match_src_ip_mask)
        match_template.outer.ip4.src_ip = match_src_ip_mask;

    if (match_proto == IPPROTO_TCP) {
        match_template.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_TCP;
        match_template.outer.tcp.l4_port.dst_port = match_dst_port_mask;
        if (match_src_port_mask)
            match_template.outer.tcp.l4_port.src_port = match_src_port_mask;
    } else if (match_proto == IPPROTO_UDP) {
        match_template.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
        match_template.outer.udp.l4_port.dst_port = match_dst_port_mask;
        if (match_src_port_mask)
            match_template.outer.udp.l4_port.src_port = match_src_port_mask;
    }

    /* Universal actions template: mask ALL rewrite fields so any entry
     * MAY rewrite any subset (0 = no rewrite for that field per entry). */
    struct doca_flow_actions actions_template;
    memset(&actions_template, 0, sizeof(actions_template));
    actions_template.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
    actions_template.outer.ip4.dst_ip = UINT32_MAX;
    actions_template.outer.ip4.src_ip = UINT32_MAX;
    memset(actions_template.outer.eth.src_mac, 0xFF, 6);
    memset(actions_template.outer.eth.dst_mac, 0xFF, 6);
    if (match_proto == IPPROTO_UDP) {
        actions_template.outer.udp.l4_port.src_port = UINT16_MAX;
        actions_template.outer.udp.l4_port.dst_port = UINT16_MAX;
    } else {
        actions_template.outer.tcp.l4_port.src_port = UINT16_MAX;
        actions_template.outer.tcp.l4_port.dst_port = UINT16_MAX;
    }
    struct doca_flow_actions *acts_arr[1] = { &actions_template };

    /* Monitor: enable per-entry counter */
    struct doca_flow_monitor monitor;
    memset(&monitor, 0, sizeof(monitor));
    monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;

    /* Forward */
    struct doca_flow_fwd fwd;
    build_fwd(&fwd, fwd_type, fwd_port_id);

    /* Miss forward: drop */
    struct doca_flow_fwd miss_fwd;
    memset(&miss_fwd, 0, sizeof(miss_fwd));
    miss_fwd.type = DOCA_FLOW_FWD_DROP;

    /* Pipe config -- create on switch port for eSwitch steering (FWD-03) */
    struct doca_flow_pipe_cfg *pipe_cfg = NULL;
    ret = doca_flow_pipe_cfg_create(&pipe_cfg, g_switch_port);
    if (ret != DOCA_SUCCESS) {
        fprintf(stderr, "llb_doca: pipe_cfg_create failed: %s\n",
                doca_error_get_descr(ret));
        return NULL;
    }

    doca_flow_pipe_cfg_set_name(pipe_cfg, name);
    doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
    doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, nr_entries > 0 ? nr_entries : g_ct_pipe_capacity);
    doca_flow_pipe_cfg_set_match(pipe_cfg, &match_template, NULL);
    doca_flow_pipe_cfg_set_actions(pipe_cfg, acts_arr, NULL, NULL, 1);
    doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor);

    struct doca_flow_pipe *pipe = NULL;
    ret = doca_flow_pipe_create(pipe_cfg, &fwd, &miss_fwd, &pipe);
    doca_flow_pipe_cfg_destroy(pipe_cfg);

    if (ret != DOCA_SUCCESS) {
        fprintf(stderr, "llb_doca: pipe_create failed: %s\n",
                doca_error_get_descr(ret));
        return NULL;
    }

    return (llb_doca_pipe_handle_t)pipe;
}

llb_doca_pipe_handle_t llb_doca_get_root_pipe(void)
{
    if (!g_initialized || !g_root_pipe)
        return NULL;
    return (llb_doca_pipe_handle_t)g_root_pipe;
}

llb_doca_pipe_handle_t llb_doca_get_ct_fwd_pipe(void)
{
    if (!g_initialized)
        return NULL;
    return (llb_doca_pipe_handle_t)g_ct_fwd_pipe;
}

llb_doca_pipe_handle_t llb_doca_get_ct_rev_pipe(void)
{
    if (!g_initialized)
        return NULL;
    return (llb_doca_pipe_handle_t)g_ct_rev_pipe;
}

/* llb_doca_get_egress_steer_pipe deleted along with
 * g_egress_steer_pipe. Plan 63-06 owns removing the matching Go-side
 * wrappers DocaGetEgressSteerPipe / docaGetSteerPipeDirect in
 * pkg/loxinet/dpu_doca_cgo.go. Until then the !doca stub
 * (loxilb_doca_flow_stub.c) is unaffected because it never defined this
 * accessor; the doca build's CGO link breaks at the Go callsites until
 * 63-06 lands (documented as a transitional break in 63-04 SUMMARY). */

/* ----------------------------------------------------------------
 *  TEST-ONLY DIAGNOSTIC: llb_doca_ct_rev_test_drop_all
 *
 *  Rebuilds CT_REV_5TUPLE_PIPE with DOCA_FLOW_FWD_DROP as the miss
 *  action (instead of to_kernel_pipe).  After this call, any packet
 *  from a VF representor that reaches the pipe but has no matching
 *  5-tuple entry will be DROPPED rather than sent to the kernel.
 *
 *  HOW TO USE:
 *    1. Call this function.
 *    2. Call llb_doca_rebuild_root_pipe() from Go to re-wire root
 *       dispatch entries to the new pipe handle.
 *    3. Send traffic from a backend VF.  If it disappears (no reply
 *       to client) the pipe IS being visited — root dispatch is OK.
 *       If traffic still reaches the kernel, root dispatch is broken.
 *
 *  REMOVE after diagnosis is complete.
 * ---------------------------------------------------------------- */
int llb_doca_ct_rev_test_drop_all(void)
{
    doca_error_t dret;

    if (!g_initialized || !g_switch_port) {
        fprintf(stderr, "llb_doca_ct_rev_test_drop_all: not initialized\n");
        return LLB_DOCA_ERR_NOTSUP;
    }

    /* Destroy old pipe first (root dispatch entries become stale until
     * caller rebuilds the root pipe). */
    if (g_ct_rev_pipe) {
        doca_flow_pipe_destroy(g_ct_rev_pipe);
        g_ct_rev_pipe = NULL;
        fprintf(stderr, "llb_doca_ct_rev_test_drop_all: old CT_REV pipe destroyed\n");
    }

    /* Re-create CT_REV_5TUPLE_PIPE — identical to init step 6c-rev
     * except miss_fwd = FWD_DROP instead of FWD_PIPE(to_kernel). */
    struct doca_flow_pipe_cfg *pipe_cfg = NULL;
    dret = doca_flow_pipe_cfg_create(&pipe_cfg, g_switch_port);
    if (dret != DOCA_SUCCESS) {
        fprintf(stderr, "llb_doca_ct_rev_test_drop_all: pipe_cfg_create failed: %s\n",
                doca_error_get_descr(dret));
        return LLB_DOCA_ERR_PIPE;
    }

    doca_flow_pipe_cfg_set_name(pipe_cfg, "CT_REV_5TUPLE_PIPE");
    doca_flow_pipe_cfg_set_is_root(pipe_cfg, false);
    doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
    doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, g_ct_pipe_capacity * 2);

    struct doca_flow_match lb_match;
    memset(&lb_match, 0, sizeof(lb_match));
    lb_match.parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4;
    lb_match.parser_meta.outer_l4_type = UINT32_MAX;
    lb_match.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_TRANSPORT;
    lb_match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
    lb_match.outer.ip4.src_ip = 0xffffffff;
    lb_match.outer.ip4.dst_ip = 0xffffffff;
    lb_match.outer.transport.src_port = 0xffff;
    lb_match.outer.transport.dst_port = 0xffff;
    doca_flow_pipe_cfg_set_match(pipe_cfg, &lb_match, NULL);

    struct doca_flow_actions lb_actions;
    memset(&lb_actions, 0, sizeof(lb_actions));
    lb_actions.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
    lb_actions.outer.ip4.dst_ip = UINT32_MAX;
    lb_actions.outer.ip4.src_ip = UINT32_MAX;
    memset(lb_actions.outer.eth.src_mac, 0xFF, 6);
    memset(lb_actions.outer.eth.dst_mac, 0xFF, 6);
    lb_actions.outer.transport.src_port = UINT16_MAX;
    lb_actions.outer.transport.dst_port = UINT16_MAX;
    struct doca_flow_actions *lb_acts_arr[1] = { &lb_actions };
    doca_flow_pipe_cfg_set_actions(pipe_cfg, lb_acts_arr, NULL, NULL, 1);

    struct doca_flow_monitor lb_monitor;
    memset(&lb_monitor, 0, sizeof(lb_monitor));
    lb_monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
    lb_monitor.aging_sec = 0xffffffff;
    doca_flow_pipe_cfg_set_monitor(pipe_cfg, &lb_monitor);
    doca_flow_pipe_cfg_set_miss_counter(pipe_cfg, true);

    /* Per-entry fwd (normal operation when entries exist) */
    struct doca_flow_fwd lb_fwd;
    memset(&lb_fwd, 0, sizeof(lb_fwd));
    lb_fwd.type = DOCA_FLOW_FWD_PORT;
    lb_fwd.port_id = 0xffff;

    /* TEST: miss → DROP (was to_kernel_pipe) */
    struct doca_flow_fwd drop_miss;
    memset(&drop_miss, 0, sizeof(drop_miss));
    drop_miss.type = DOCA_FLOW_FWD_DROP;

    struct doca_flow_pipe *pipe = NULL;
    dret = doca_flow_pipe_create(pipe_cfg, &lb_fwd, &drop_miss, &pipe);
    doca_flow_pipe_cfg_destroy(pipe_cfg);
    if (dret != DOCA_SUCCESS) {
        fprintf(stderr, "llb_doca_ct_rev_test_drop_all: pipe_create failed: %s\n",
                doca_error_get_descr(dret));
        return LLB_DOCA_ERR_PIPE;
    }

    g_ct_rev_pipe = pipe;
    fprintf(stderr,
        "llb_doca_ct_rev_test_drop_all: CT_REV rebuilt with miss=DROP "
        "(capacity=%u) -- rebuilding V3 root pipe now\n",
        g_ct_pipe_capacity * 2);

    /* Re-wire root pipe to the new g_ct_rev_pipe handle via the miss-chain.
     *
 * collapsed root dispatches to a single IPv4 TCP+UDP classifier
     * pointing at g_ct_fwd_pipe. Reply traffic still reaches the newly-rebuilt
     * (miss=DROP) g_ct_rev_pipe via the ct_fwd → ct_rev miss-chain installed in
     * Plan 63-04. Diagnostic intent preserved: a packet from a VF rep that fails
     * to match a 5-tuple entry in ct_fwd will fall to ct_rev (miss-chain), and a
     * miss in ct_rev now DROPs instead of going to_kernel — exactly what the
     * test_drop_all routine wants to verify.
     *
     * V3 ABI preserved; match_port_meta=0; miss_pipe_override=g_fdb_pipe. */
    {
        llb_doca_root_pipe_cfg root_cfg;
        memset(&root_cfg, 0, sizeof(root_cfg));
        root_cfg.version         = LLB_DOCA_ROOT_PIPE_CFG_V3;
        root_cfg.nr_entries      = 4;
        root_cfg.match_port_meta = 0;  /* wildcard ingress */

        /* Entry 0: IPv4/TCP from any ingress port → g_ct_fwd_pipe (miss-chain → CT_REV-DROP). */
        root_cfg.dispatch[0].l4_type = DOCA_FLOW_L4_META_TCP;
        root_cfg.dispatch[0].target  = (llb_doca_pipe_handle_t)g_ct_fwd_pipe;

        /* Entry 1: IPv4/UDP from any ingress port → g_ct_fwd_pipe (same target). */
        root_cfg.dispatch[1].l4_type = DOCA_FLOW_L4_META_UDP;
        root_cfg.dispatch[1].target  = (llb_doca_pipe_handle_t)g_ct_fwd_pipe;

        root_cfg.num_dispatch       = 2;
        root_cfg.miss_pipe_override = (llb_doca_pipe_handle_t)g_fdb_pipe;

        int rrc = llb_doca_rebuild_root_pipe(&root_cfg);
        if (rrc != LLB_DOCA_OK) {
            fprintf(stderr,
                "llb_doca_ct_rev_test_drop_all: root rebuild failed: %d "
                "(CT_REV drop-test active but root NOT re-wired)\n", rrc);
            return LLB_DOCA_ERR_PIPE;
        }
        fprintf(stderr,
            "llb_doca_ct_rev_test_drop_all: root re-wired — "
            "2 dispatch entries (IPv4/TCP + IPv4/UDP → g_ct_fwd_pipe; "
            "miss-chain → g_ct_rev_pipe (miss=DROP); root miss → g_fdb_pipe)\n");
    }

    return LLB_DOCA_OK;
}

llb_doca_pipe_handle_t llb_doca_get_udp_ct_pipe(void)
{
    /* stub: DOCA pipe creation/entry-update deferred until validated
     * against the new core pipeline (CT pair + egress_dispatch + simplified root).
     * Go-side Capabilities() still advertises this offload; eBPF slow path handles
 * the feature at runtime. Restoration plan: CONTEXT.md. Old body in git
     * history at <pre-Phase-63 commit>. */
    return NULL;
}

/* ----------------------------------------------------------------
 * Root pipe rebuild (reusable for Phases 35/37)
 *
 *  Creates a BASIC root pipe with L3+L4 dispatch.  Each dispatch entry
 *  matches outer_l3_type=IPV4 + outer_l4_type=<per-entry> and forwards
 *  to the target pipe via FWD_PIPE.
 *
 *  Entries are added sequentially (DOCA_FLOW_NO_WAIT + wait_entry_offload
 *  per entry) -- NOT batch mode.  g_entry_status is a single volatile int;
 *  batch callbacks overwrite each other, silently masking failures.
 *
 *  Miss action: FWD_PIPE → g_to_kernel_pipe (ICMP, GRE, ARP, IPv6,
 *  fragments all fall here).
 *
 *  Atomic swap: old root pipe is destroyed after new one is installed.
 * ---------------------------------------------------------------- */
int llb_doca_rebuild_root_pipe(const llb_doca_root_pipe_cfg *cfg)
{
    doca_error_t dret;

    if (!cfg)
        return LLB_DOCA_ERR_PARAM;
    /* accept BOTH V1 and V2. V1 callers (e.g. dpu_doca_cgo.go:612
     * ACL-rebuild path) stay operable during Plan 04 Go-side migration; V2 callers
     * may optionally set miss_pipe_override to redirect the root miss away from
     * g_to_kernel_pipe (fixes Bug #2 -- FDB pipe orphaning). */
    if (cfg->version != LLB_DOCA_ROOT_PIPE_CFG_V1 &&
        cfg->version != LLB_DOCA_ROOT_PIPE_CFG_V2 &&
        cfg->version != LLB_DOCA_ROOT_PIPE_CFG_V3)   /* */
        return LLB_DOCA_ERR_PARAM;
    if (cfg->num_dispatch == 0 || cfg->num_dispatch > LLB_DOCA_ROOT_PIPE_MAX_DISPATCH)
        return LLB_DOCA_ERR_PARAM;
    if (!g_switch_port || !g_to_kernel_pipe)
        return LLB_DOCA_ERR_FLOW;

    /* BF2 DOCA only allows ONE root pipe at a time.  Destroy old root
     * BEFORE creating the new one.  Brief traffic gap is unavoidable. */
    if (g_root_pipe) {
        doca_flow_pipe_destroy(g_root_pipe);
        g_root_pipe = NULL;
        fprintf(stderr, "llb_doca: old root pipe destroyed (pre-rebuild)\n");
    }

    /* Create new root pipe */
    struct doca_flow_pipe_cfg *pipe_cfg = NULL;
    dret = doca_flow_pipe_cfg_create(&pipe_cfg, g_switch_port);
    if (dret != DOCA_SUCCESS) {
        fprintf(stderr, "llb_doca: rebuild_root pipe_cfg_create failed: %s\n",
                doca_error_get_descr(dret));
        return LLB_DOCA_ERR_PIPE;
    }

    doca_flow_pipe_cfg_set_name(pipe_cfg, "root_l3l4_dispatch_pipe");
    doca_flow_pipe_cfg_set_is_root(pipe_cfg, true);
    doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
    doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, cfg->nr_entries);

    /* Match template: both L3 and L4 are per-entry (UINT32_MAX wildcards) */
    struct doca_flow_match root_match;
    memset(&root_match, 0, sizeof(root_match));
    root_match.parser_meta.outer_l3_type = UINT32_MAX;
    root_match.parser_meta.outer_l4_type = UINT32_MAX;
    /* V3 callers with match_port_meta!=0 add parser_meta.port_meta
     * to the pipe template. V1/V2 callers and V3 callers with match_port_meta==0
     * keep the V2 template (Pitfall 1: ACL rebuild path stays binary-compatible). */
    if (cfg->version == LLB_DOCA_ROOT_PIPE_CFG_V3 && cfg->match_port_meta != 0) {
        root_match.parser_meta.port_meta = UINT32_MAX;
    }
    doca_flow_pipe_cfg_set_match(pipe_cfg, &root_match, NULL);

    /* SPIKE-001 DIAG: pipe-level monitor was attempted here but BF2 firmware
     * rejects it on root pipes in switch+isolated mode (same restriction as
 * actions — see lesson below). Got "Operation not supported" on
     * doca_flow_pipe_create. Kept only the per-entry monitor passed to
     * doca_flow_pipe_add_entry below; if the firmware also rejects per-entry
     * monitors on root entries, we'll need a shadow-pipe diagnostic instead. */

    /* NO actions -- root pipe is pure L3+L4 classifier ( lesson:
     * eSwitch FDB rejects actions on root pipes in switch,isolated mode) */

    /* FWD: FWD_PIPE to first dispatch target as default */
    struct doca_flow_fwd root_fwd;
    memset(&root_fwd, 0, sizeof(root_fwd));
    root_fwd.type = DOCA_FLOW_FWD_PIPE;
    root_fwd.next_pipe = (struct doca_flow_pipe *)cfg->dispatch[0].target;

    /* Miss: FWD_PIPE → miss_target (default g_to_kernel_pipe; V2 override honored).
     *
 * V2 callers may set cfg->miss_pipe_override to a non-NULL
     * pipe handle to redirect root misses away from to_kernel (e.g. into the
     * FDB L2 pipe). V2 with override==0 collapses to V1 semantics. V1 callers
     * ignore the field entirely.
     *
     * Default chain:      root miss → to_kernel
     * V2 (with FDB):      root miss → fdb_pipe → (fdb miss) → to_kernel
     */
    struct doca_flow_pipe *miss_target = g_to_kernel_pipe;
    if (cfg->version == LLB_DOCA_ROOT_PIPE_CFG_V2 && cfg->miss_pipe_override) {
        miss_target = (struct doca_flow_pipe *)cfg->miss_pipe_override;
    }

    struct doca_flow_fwd root_miss;
    memset(&root_miss, 0, sizeof(root_miss));
    root_miss.type = DOCA_FLOW_FWD_PIPE;
    root_miss.next_pipe = miss_target;

    struct doca_flow_pipe *new_pipe = NULL;
    dret = doca_flow_pipe_create(pipe_cfg, &root_fwd, &root_miss, &new_pipe);
    doca_flow_pipe_cfg_destroy(pipe_cfg);
    if (dret != DOCA_SUCCESS) {
        fprintf(stderr, "llb_doca: rebuild_root pipe create failed: %s\n",
                doca_error_get_descr(dret));
        return LLB_DOCA_ERR_PIPE;
    }

    /* Add dispatch entries sequentially (per-entry FWD_PIPE to target).
     * SPIKE-001 NOTE: per-entry monitors on root-pipe entries silently no-op
     * on this BF2 firmware (entry_add succeeds, query returns Invalid input).
     * Diagnostic counters live on downstream pipes via pipe-miss counters. */
    for (uint32_t i = 0; i < cfg->num_dispatch; i++) {
        struct doca_flow_match entry_match;
        memset(&entry_match, 0, sizeof(entry_match));
        entry_match.parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4;
        entry_match.parser_meta.outer_l4_type = cfg->dispatch[i].l4_type;
        /* V3 callers set per-entry exact ingress port_meta */
        if (cfg->version == LLB_DOCA_ROOT_PIPE_CFG_V3 && cfg->match_port_meta != 0) {
            entry_match.parser_meta.port_meta = cfg->port_meta_value[i];
        }

        struct doca_flow_fwd entry_fwd;
        memset(&entry_fwd, 0, sizeof(entry_fwd));
        entry_fwd.type = DOCA_FLOW_FWD_PIPE;
        entry_fwd.next_pipe = (struct doca_flow_pipe *)cfg->dispatch[i].target;

        g_entry_status = -1;
        struct doca_flow_pipe_entry *entry = NULL;
        dret = doca_flow_pipe_add_entry(0, new_pipe,
                                         &entry_match, NULL,
                                         NULL, &entry_fwd,
                                         DOCA_FLOW_NO_WAIT,
                                         NULL, &entry);
        if (dret != DOCA_SUCCESS) {
            fprintf(stderr, "llb_doca: rebuild_root entry[%u] add failed: %s\n",
                    i, doca_error_get_descr(dret));
            doca_flow_pipe_destroy(new_pipe);
            return LLB_DOCA_ERR_ENTRY;
        }
        if (wait_entry_offload(5000) != LLB_DOCA_OK) {
            fprintf(stderr, "llb_doca: rebuild_root entry[%u] offload timeout\n", i);
            doca_flow_pipe_destroy(new_pipe);
            return LLB_DOCA_ERR_TIMEOUT;
        }
        fprintf(stderr, "llb_doca: rebuild_root entry[%u] l4_type=%u port_meta=%u → pipe=%p OK\n",
                i, cfg->dispatch[i].l4_type,
                (cfg->version == LLB_DOCA_ROOT_PIPE_CFG_V3 ? cfg->port_meta_value[i] : 0u),
                cfg->dispatch[i].target);
    }

    /* Install new root pipe */
    g_root_pipe = new_pipe;
    g_root_pipe_has_actions = 0;  /* root pipe is pure classifier */

    fprintf(stderr, "llb_doca: root L3+L4 BASIC pipe rebuilt OK "
            "(dispatch=%u entries, miss->%s)\n",
            cfg->num_dispatch,
            (miss_target != g_to_kernel_pipe) ? "override_pipe" : "to_kernel");
    return LLB_DOCA_OK;
}

int llb_doca_pipe_destroy(llb_doca_pipe_handle_t pipe)
{
    if (!g_initialized || !pipe)
        return LLB_DOCA_ERR_PARAM;

    doca_flow_pipe_destroy((struct doca_flow_pipe *)pipe);
    return LLB_DOCA_OK;
}

/* ================================================================
 * FDB L2 pipe 
 * ================================================================ */

llb_doca_pipe_handle_t llb_doca_fdb_pipe_create(uint32_t nr_entries)
{
    doca_error_t dret;

    /* Note: g_initialized is NOT checked here because this function is called
     * during llb_doca_init() BEFORE g_initialized is set to 1.
     * g_switch_port and g_to_kernel_pipe are sufficient guards. */
    if (!g_switch_port || !g_to_kernel_pipe) {
        fprintf(stderr, "llb_doca: fdb pipe guard failed: switch=%p to_kernel=%p\n",
                (void *)g_switch_port, (void *)g_to_kernel_pipe);
        return NULL;
    }

    struct doca_flow_pipe_cfg *pipe_cfg = NULL;
    dret = doca_flow_pipe_cfg_create(&pipe_cfg, g_switch_port);
    if (dret != DOCA_SUCCESS) {
        fprintf(stderr, "llb_doca: fdb pipe_cfg_create failed: %s\n",
                doca_error_get_descr(dret));
        return NULL;
    }

    doca_flow_pipe_cfg_set_name(pipe_cfg, "fdb_l2_pipe");
    doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
    doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, nr_entries);

    /* P49-R2: enable per-entry HW counters on the FDB pipe.
     * Without counter_type = NON_SHARED, doca_flow_resource_query_entry()
     * returns {total_pkts=0, total_bytes=0} for every FDB entry.
     * Mirrors the CT/LB/ACL pipes at loxilb_doca_flow.c lines 607, 1022, 1441. */
    struct doca_flow_monitor fdb_pipe_monitor;
    memset(&fdb_pipe_monitor, 0, sizeof(fdb_pipe_monitor));
    fdb_pipe_monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
    dret = doca_flow_pipe_cfg_set_monitor(pipe_cfg, &fdb_pipe_monitor);
    if (dret != DOCA_SUCCESS) {
        fprintf(stderr, "llb_doca: fdb pipe_cfg_set_monitor failed: %s\n",
                doca_error_get_descr(dret));
        doca_flow_pipe_cfg_destroy(pipe_cfg);
        return NULL;
    }
    /* SPIKE-001 DIAG: pipe miss counter on FDB pipe — tells us whether reply
     * traffic enters FDB before reaching root pipe (Hypothesis D). */
    dret = doca_flow_pipe_cfg_set_miss_counter(pipe_cfg, true);
    if (dret != DOCA_SUCCESS) {
        fprintf(stderr, "llb_doca: fdb pipe_cfg_set_miss_counter failed: %s\n",
                doca_error_get_descr(dret));
        doca_flow_pipe_cfg_destroy(pipe_cfg);
        return NULL;
    }

    /* Match template: exact dst_mac match only.
     * No IP fields, no L4 fields, no parser_meta — pure L2 switching. */
    struct doca_flow_match match;
    memset(&match, 0, sizeof(match));
    memset(match.outer.eth.dst_mac, 0xFF, 6);  /* exact match mask for dst MAC */
    doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL);

    /* NO actions template — FDB pipe is pure forwarding, no MAC/IP rewrite.
     * Per-entry FWD_PORT is the only action. */

    /* FWD default: port 0 (overridden per-entry) */
    struct doca_flow_fwd fwd;
    memset(&fwd, 0, sizeof(fwd));
    fwd.type = DOCA_FLOW_FWD_PORT;
    fwd.port_id = 0;

    /* Miss: broadcast, multicast, and unknown unicast → to_kernel pipe.
     * This satisfies L2-02: ARP requests and broadcast reach ARM kernel. */
    struct doca_flow_fwd miss;
    memset(&miss, 0, sizeof(miss));
    miss.type = DOCA_FLOW_FWD_PIPE;
    miss.next_pipe = g_to_kernel_pipe;

    struct doca_flow_pipe *pipe = NULL;
    dret = doca_flow_pipe_create(pipe_cfg, &fwd, &miss, &pipe);
    doca_flow_pipe_cfg_destroy(pipe_cfg);
    if (dret != DOCA_SUCCESS) {
        fprintf(stderr, "llb_doca: fdb pipe create failed: %s\n",
                doca_error_get_descr(dret));
        return NULL;
    }

    return (llb_doca_pipe_handle_t)pipe;
}

llb_doca_entry_handle_t llb_doca_fdb_entry_add(
    llb_doca_pipe_handle_t pipe,
    const uint8_t dst_mac[6],
    uint16_t fwd_port_id,
    uint32_t aging_sec,
    uint64_t user_ctx,
    uint32_t timeout_ms)
{
    doca_error_t dret;

    if (!g_initialized || !pipe || !dst_mac)
        return NULL;

    /* Entry match: exact dst MAC */
    struct doca_flow_match entry_match;
    memset(&entry_match, 0, sizeof(entry_match));
    memcpy(entry_match.outer.eth.dst_mac, dst_mac, 6);

    /* Per-entry FWD to specific port representor */
    struct doca_flow_fwd entry_fwd;
    memset(&entry_fwd, 0, sizeof(entry_fwd));
    entry_fwd.type = DOCA_FLOW_FWD_PORT;
    entry_fwd.port_id = fwd_port_id;

    /* Monitor: aging timeout + user context for aged-entry identification.
 * P49-R2: always set counter_type on the per-entry monitor so the
     * HW reports hw_pkts/hw_bytes. aging_sec is additive (set only when >0). */
    struct doca_flow_monitor monitor;
    memset(&monitor, 0, sizeof(monitor));
    monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
    if (aging_sec > 0) {
        monitor.aging_sec = aging_sec;
    }

    g_entry_status = -1;
    struct doca_flow_pipe_entry *entry = NULL;
    dret = doca_flow_pipe_add_entry(0,
                                     (struct doca_flow_pipe *)pipe,
                                     &entry_match,
                                     NULL,  /* no actions */
                                     &monitor,
                                     &entry_fwd,
                                     DOCA_FLOW_NO_WAIT,
                                     (user_ctx != 0) ? (void *)(uintptr_t)user_ctx : NULL,
                                     &entry);
    if (dret != DOCA_SUCCESS) {
        fprintf(stderr, "llb_doca: fdb entry add failed: %s (mac=%02x:%02x:%02x:%02x:%02x:%02x)\n",
                doca_error_get_descr(dret),
                dst_mac[0], dst_mac[1], dst_mac[2],
                dst_mac[3], dst_mac[4], dst_mac[5]);
        return NULL;
    }

    if (wait_entry_offload(timeout_ms) != LLB_DOCA_OK) {
        fprintf(stderr, "llb_doca: fdb entry offload timeout (mac=%02x:%02x:%02x:%02x:%02x:%02x)\n",
                dst_mac[0], dst_mac[1], dst_mac[2],
                dst_mac[3], dst_mac[4], dst_mac[5]);
        /* Entry may be partially offloaded — attempt removal */
        if (entry)
            doca_flow_pipe_remove_entry(0, DOCA_FLOW_NO_WAIT, entry);
        return NULL;
    }

    fprintf(stderr, "llb_doca: fdb entry added mac=%02x:%02x:%02x:%02x:%02x:%02x port=%u aging=%u\n",
            dst_mac[0], dst_mac[1], dst_mac[2],
            dst_mac[3], dst_mac[4], dst_mac[5],
            fwd_port_id, aging_sec);
    return (llb_doca_entry_handle_t)entry;
}

llb_doca_pipe_handle_t llb_doca_get_fdb_pipe(void)
{
    return (llb_doca_pipe_handle_t)g_fdb_pipe;
}

/* ================================================================
 * ACL HW offload — rebuilt from validated flow_acl_basic sample 
 *
 *  Two-pipe pipeline:
 *      ROOT → DENY_PIPE → ALLOW_PIPE → CT_FWD → CT_REV(miss) → EGRESS_DISPATCH
 *
 *  DENY_PIPE  (BASIC, non-root, BIDIRECTIONAL default):
 *      - per-entry FWD_DROP
 *      - fwd_miss → ALLOW_PIPE
 * 5-tuple TRANSPORT match with per-entry mask (CIDR support)
 * NON_SHARED counter monitor — set BEFORE pipe_create
 *      - sample analog: flow_acl_basic_sample.c:369-424 (create_deny_pipe)
 *
 *  ALLOW_PIPE (BASIC, non-root, BIDIRECTIONAL default):
 *      - per-entry FWD_PIPE → g_ct_fwd_pipe (counter-only audit; CT owns MAC rewrite)
 * fwd_miss → g_ct_fwd_pipe ( transparent passthrough)
 * 5-tuple TRANSPORT match with per-entry mask
 * NO pipe_cfg_set_actions ( explicitly drops sample's MAC rewrite + pkt_meta)
 * NON_SHARED counter monitor 
 * sample analog: flow_acl_basic_sample.c:293-366 (create_allow_pipe, with divergence)
 *
 * Lazy lifecycle: both pipes are NULL until the first FwRule with
 *  HwOffload=true arrives. Plan 64-04 owns the Go-side debouncer that drives
 *  doca_flow_entries_process() on its 50ms tick when DOCA_FLOW_NO_WAIT is used.
 *
 * Anti-pattern guard: BIDIRECTIONAL default (no explicit set_dir_info call),
 *  DEFAULT domain only (no EGRESS-domain steering), no CHANGEABLE forward template.
 *  See `make check-doca-pipeline-contract` for the Makefile-enforced check.
 * ================================================================ */

static doca_error_t llb_doca_create_deny_pipe(uint32_t nr_entries,
                                              struct doca_flow_pipe **out_pipe)
{
    doca_error_t dret;
    struct doca_flow_pipe_cfg *pipe_cfg = NULL;
    struct doca_flow_match    match_tmpl, match_mask;
    struct doca_flow_monitor  monitor;
    struct doca_flow_fwd      fwd_drop, fwd_miss;

    if (!g_switch_port) {
        fprintf(stderr, "llb_doca: DENY_PIPE create guard failed: switch=%p\n",
                (void *)g_switch_port);
        return DOCA_ERROR_INVALID_VALUE;
    }
    if (!g_allow_pipe) {
        /* OPENING order: ALLOW must be alive before DENY because
         * DENY's fwd_miss.next_pipe = g_allow_pipe. */
        fprintf(stderr, "llb_doca: DENY_PIPE create guard failed: g_allow_pipe NULL "
                        "(call ALLOW create first per)\n");
        return DOCA_ERROR_INVALID_VALUE;
    }

    memset(&match_tmpl, 0, sizeof(match_tmpl));
    memset(&match_mask, 0, sizeof(match_mask));
    memset(&monitor,    0, sizeof(monitor));
    memset(&fwd_drop,   0, sizeof(fwd_drop));
    memset(&fwd_miss,   0, sizeof(fwd_miss));
    monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;  /* */

    dret = doca_flow_pipe_cfg_create(&pipe_cfg, g_switch_port);
    if (dret != DOCA_SUCCESS) {
        fprintf(stderr, "llb_doca: DENY_PIPE pipe_cfg_create failed: %s\n",
                doca_error_get_descr(dret));
        return dret;
    }
    doca_flow_pipe_cfg_set_name(pipe_cfg, "DENY_PIPE");
    doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);     /* */
    doca_flow_pipe_cfg_set_is_root(pipe_cfg, false);                 /* */
    doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, nr_entries);
    dret = doca_flow_pipe_cfg_set_miss_counter(pipe_cfg, true);
    if (dret != DOCA_SUCCESS) {
        fprintf(stderr, "llb_doca: DENY_PIPE set_miss_counter failed: %s\n",
                doca_error_get_descr(dret));
        doca_flow_pipe_cfg_destroy(pipe_cfg);
        return dret;
    }

    /* v4 (2026-05-18): EXPLICIT mask, no parser_meta. Empirically locked
     * by standalone sample flow_p64_acl_5tuple bisect (variants v1..v4 on BF2
     * DOCA 2.9.4 switch,hws):
     *   v1 parser_meta + TRANSPORT + NULL mask → FAIL (hw_pkts=0)
     *   v2 L3-only      + EXPL mask           → PASS (hw_pkts=30)
     *   v3 TCP-specific + NULL mask            → FAIL (hw_pkts=0)
     *   v4 TRANSPORT   + EXPL mask            → PASS (hw_pkts=30)  ← this shape
     *
     * The PIPE_BASIC + switch,hws code path on BF2 silently rejects NULL mask;
 * the prior v3 hypothesis ("DOCA derives mask from template UINT*
     * fields") is empirically false. CT_FWD/CT_REV pipes are unaffected
     * because they're PIPE_HASH, which has different mask semantics.
     *
     * parser_meta is intentionally dropped: v4 omits it and still passes; the
     * canonical flow_acl_basic_main.c also omits it for the deny pipe.
     *
     * Mask layout:
     *   l3_type, src_ip, dst_ip   exact (per-entry overrides values)
     *   l4_type_ext = TRANSPORT   exact   (TCP/UDP/SCTP only — matches
     *                                      validateHwOffloadExpressible which
     *                                      already rejects ICMP-specific rules)
     *   transport.src_port = 0    wildcard (clients have ephemeral src_port)
     *   transport.dst_port = MAX  exact   (port-range rules already rejected
     *                                      at the REST layer; min==max only) */
    match_tmpl.outer.l3_type             = DOCA_FLOW_L3_TYPE_IP4;
    match_tmpl.outer.ip4.src_ip          = UINT32_MAX;
    match_tmpl.outer.ip4.dst_ip          = UINT32_MAX;
    match_tmpl.outer.l4_type_ext         = DOCA_FLOW_L4_TYPE_EXT_TRANSPORT;
    match_tmpl.outer.transport.src_port  = UINT16_MAX;
    match_tmpl.outer.transport.dst_port  = UINT16_MAX;

    match_mask.outer.l3_type             = DOCA_FLOW_L3_TYPE_IP4;
    match_mask.outer.ip4.src_ip          = UINT32_MAX;
    match_mask.outer.ip4.dst_ip          = UINT32_MAX;
    match_mask.outer.l4_type_ext         = DOCA_FLOW_L4_TYPE_EXT_TRANSPORT;
    match_mask.outer.transport.src_port  = 0;
    match_mask.outer.transport.dst_port  = UINT16_MAX;

    dret = doca_flow_pipe_cfg_set_match(pipe_cfg, &match_tmpl, &match_mask);
    if (dret != DOCA_SUCCESS) {
        fprintf(stderr, "llb_doca: DENY_PIPE set_match failed: %s\n",
                doca_error_get_descr(dret));
        doca_flow_pipe_cfg_destroy(pipe_cfg);
        return dret;
    }

    /* monitor MUST be set BEFORE pipe_create. The sample's troubleshooting
     * #4 ("counter not defined") is caused by the reverse order. */
    dret = doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor);
    if (dret != DOCA_SUCCESS) {
        fprintf(stderr, "llb_doca: DENY_PIPE set_monitor failed: %s\n",
                doca_error_get_descr(dret));
        doca_flow_pipe_cfg_destroy(pipe_cfg);
        return dret;
    }

    /* per-entry forward action template = DROP; miss → ALLOW_PIPE. */
    fwd_drop.type      = DOCA_FLOW_FWD_DROP;
    fwd_miss.type      = DOCA_FLOW_FWD_PIPE;
    fwd_miss.next_pipe = g_allow_pipe;

    dret = doca_flow_pipe_create(pipe_cfg, &fwd_drop, &fwd_miss, out_pipe);
    doca_flow_pipe_cfg_destroy(pipe_cfg);
    if (dret != DOCA_SUCCESS) {
        fprintf(stderr, "llb_doca: DENY_PIPE create failed: %s\n",
                doca_error_get_descr(dret));
        return dret;
    }
    return DOCA_SUCCESS;
}

static doca_error_t llb_doca_create_allow_pipe(uint32_t nr_entries,
                                               struct doca_flow_pipe **out_pipe)
{
    doca_error_t dret;
    struct doca_flow_pipe_cfg *pipe_cfg = NULL;
    struct doca_flow_match    match_tmpl, match_mask;
    struct doca_flow_monitor  monitor;
    struct doca_flow_fwd      fwd_tmpl, fwd_miss;

    if (!g_switch_port || !g_ct_fwd_pipe) {
        fprintf(stderr, "llb_doca: ALLOW_PIPE create guard failed: switch=%p ct_fwd=%p\n",
                (void *)g_switch_port, (void *)g_ct_fwd_pipe);
        return DOCA_ERROR_INVALID_VALUE;
    }

    memset(&match_tmpl, 0, sizeof(match_tmpl));
    memset(&match_mask, 0, sizeof(match_mask));
    memset(&monitor,    0, sizeof(monitor));
    memset(&fwd_tmpl,   0, sizeof(fwd_tmpl));
    memset(&fwd_miss,   0, sizeof(fwd_miss));
    monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;  /* */

    dret = doca_flow_pipe_cfg_create(&pipe_cfg, g_switch_port);
    if (dret != DOCA_SUCCESS) {
        fprintf(stderr, "llb_doca: ALLOW_PIPE pipe_cfg_create failed: %s\n",
                doca_error_get_descr(dret));
        return dret;
    }
    doca_flow_pipe_cfg_set_name(pipe_cfg, "ALLOW_PIPE");
    doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);     /* */
    doca_flow_pipe_cfg_set_is_root(pipe_cfg, false);                 /* */
    doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, nr_entries);
    dret = doca_flow_pipe_cfg_set_miss_counter(pipe_cfg, true);
    if (dret != DOCA_SUCCESS) {
        fprintf(stderr, "llb_doca: ALLOW_PIPE set_miss_counter failed: %s\n",
                doca_error_get_descr(dret));
        doca_flow_pipe_cfg_destroy(pipe_cfg);
        return dret;
    }

    /* v4: identical match shape as DENY_PIPE — full rationale in the
     * DENY_PIPE comment above (PIPE_BASIC on BF2 DOCA 2.9.4 requires explicit
     * mask; bisect locked v4 shape). Template + mask kept symmetric so DENY
     * and ALLOW share the same per-entry contract; differences live in the
     * forward action (DROP vs FWD_PIPE→CT_FWD). */
    match_tmpl.outer.l3_type             = DOCA_FLOW_L3_TYPE_IP4;
    match_tmpl.outer.ip4.src_ip          = UINT32_MAX;
    match_tmpl.outer.ip4.dst_ip          = UINT32_MAX;
    match_tmpl.outer.l4_type_ext         = DOCA_FLOW_L4_TYPE_EXT_TRANSPORT;
    match_tmpl.outer.transport.src_port  = UINT16_MAX;
    match_tmpl.outer.transport.dst_port  = UINT16_MAX;

    match_mask.outer.l3_type             = DOCA_FLOW_L3_TYPE_IP4;
    match_mask.outer.ip4.src_ip          = UINT32_MAX;
    match_mask.outer.ip4.dst_ip          = UINT32_MAX;
    match_mask.outer.l4_type_ext         = DOCA_FLOW_L4_TYPE_EXT_TRANSPORT;
    match_mask.outer.transport.src_port  = 0;
    match_mask.outer.transport.dst_port  = UINT16_MAX;

    dret = doca_flow_pipe_cfg_set_match(pipe_cfg, &match_tmpl, &match_mask);
    if (dret != DOCA_SUCCESS) {
        fprintf(stderr, "llb_doca: ALLOW_PIPE set_match failed: %s\n",
                doca_error_get_descr(dret));
        doca_flow_pipe_cfg_destroy(pipe_cfg);
        return dret;
    }

    /* explicitly NO pipe_cfg_set_actions — CT_FWD/CT_REV own MAC rewrite + pkt_meta. */

    /* monitor BEFORE pipe_create. */
    dret = doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor);
    if (dret != DOCA_SUCCESS) {
        fprintf(stderr, "llb_doca: ALLOW_PIPE set_monitor failed: %s\n",
                doca_error_get_descr(dret));
        doca_flow_pipe_cfg_destroy(pipe_cfg);
        return dret;
    }

    /* per-entry FWD_PIPE → CT_FWD; miss also → CT_FWD (transparent passthrough). */
    fwd_tmpl.type      = DOCA_FLOW_FWD_PIPE;
    fwd_tmpl.next_pipe = g_ct_fwd_pipe;
    fwd_miss.type      = DOCA_FLOW_FWD_PIPE;
    fwd_miss.next_pipe = g_ct_fwd_pipe;

    dret = doca_flow_pipe_create(pipe_cfg, &fwd_tmpl, &fwd_miss, out_pipe);
    doca_flow_pipe_cfg_destroy(pipe_cfg);
    if (dret != DOCA_SUCCESS) {
        fprintf(stderr, "llb_doca: ALLOW_PIPE create failed: %s\n",
                doca_error_get_descr(dret));
        return dret;
    }
    return DOCA_SUCCESS;
}

int llb_doca_acl_pipes_create(void)
{
    /* Idempotent: a second call when both pipes are already up is a no-op. */
    if (g_deny_pipe != NULL && g_allow_pipe != NULL) {
        return LLB_DOCA_OK;
    }

    /* OPENING order: ALLOW first (DENY's fwd_miss.next_pipe = g_allow_pipe). */
    doca_error_t dret = llb_doca_create_allow_pipe(4096, &g_allow_pipe);
    if (dret != DOCA_SUCCESS) {
        fprintf(stderr, "llb_doca: acl_pipes_create ALLOW failed rc=%d\n", (int)dret);
        g_allow_pipe = NULL;
        return LLB_DOCA_ERR_PIPE;
    }

    dret = llb_doca_create_deny_pipe(4096, &g_deny_pipe);
    if (dret != DOCA_SUCCESS) {
        fprintf(stderr, "llb_doca: acl_pipes_create DENY failed rc=%d (rollback ALLOW)\n",
                (int)dret);
        doca_flow_pipe_destroy(g_allow_pipe);
        g_allow_pipe = NULL;
        g_deny_pipe  = NULL;
        return LLB_DOCA_ERR_PIPE;
    }

    fprintf(stderr, "llb_doca: acl-lifecycle: DENY_PIPE+ALLOW_PIPE created "
                    "(lazy on first HwOffload=true rule)\n");
    return LLB_DOCA_OK;
}

void llb_doca_acl_pipes_destroy(void)
{
    /* CLOSING: caller (Plan 64-04 Go-side) MUST have already re-dispatched
     * the root pipe AWAY from g_deny_pipe before invoking this. */
    if (g_deny_pipe != NULL) {
        doca_flow_pipe_destroy(g_deny_pipe);
        g_deny_pipe = NULL;
    }
    if (g_allow_pipe != NULL) {
        doca_flow_pipe_destroy(g_allow_pipe);
        g_allow_pipe = NULL;
    }
    fprintf(stderr, "llb_doca: acl-lifecycle: DENY_PIPE+ALLOW_PIPE destroyed "
                    "(last HwOffload=true rule removed)\n");
}

llb_doca_entry_handle_t llb_doca_acl_deny_entry_add(
    const void *em,
    uint32_t timeout_ms)
{
    doca_error_t dret;

    if (g_deny_pipe == NULL) {
        fprintf(stderr, "llb_doca: acl_deny_entry_add called before pipes_create\n");
        return NULL;
    }
    if (em == NULL) {
        fprintf(stderr, "llb_doca: acl_deny_entry_add invalid args (em=NULL)\n");
        return NULL;
    }

    /* Header opacity: `em` arrives as `const void *` per the loxilb_doca_flow.h
     * no-DOCA-include contract; cast back to the DOCA type here where doca_flow.h
     * IS included. */
    const struct doca_flow_match *match = (const struct doca_flow_match *)em;

    /* Counter-readback fix (2026-05-17): per-entry monitor + per-entry fwd both
     * passed as NULL to mirror the canonical flow_drop / flow_acl_basic samples
     * (flow_drop_sample.c:194,309 + flow_acl_basic_sample.c:571,602,634).
     * Previously these were non-NULL, which appeared to detach the per-entry
     * counter from the FWD_DROP action: HW DROP fired (tcpdump bisection on
     * p0 in vs pf0vf0 out confirmed packets vanish inside DPU) but
     * doca_flow_resource_query_entry() returned hw_pkts=0 forever. Pipe-level
     * monitor (set at create time with counter_type=NON_SHARED, line 2107) and
 * pipe-default fwd_drop (line 2120) carry the semantics. still met. */
    g_entry_status = -1;
    struct doca_flow_pipe_entry *entry = NULL;
    dret = doca_flow_pipe_add_entry(0,
                                     g_deny_pipe,
                                     (struct doca_flow_match *)match,
                                     NULL,        /* no actions for DENY */
                                     NULL,        /* monitor inherits pipe-level */
                                     NULL,        /* fwd inherits pipe-default DROP */
                                     DOCA_FLOW_NO_WAIT,  /* batched flush */
                                     NULL,        /* user_ctx unused for ACL */
                                     &entry);
    if (dret != DOCA_SUCCESS) {
        fprintf(stderr, "llb_doca: DENY entry add failed rc=%d (%s)\n",
                (int)dret, doca_error_get_descr(dret));
        return NULL;
    }

    if (timeout_ms > 0) {
        if (wait_entry_offload(timeout_ms) != LLB_DOCA_OK) {
            fprintf(stderr, "llb_doca: DENY entry offload timeout (ms=%u) — rollback\n",
                    timeout_ms);
            if (entry) {
                doca_flow_pipe_remove_entry(0, DOCA_FLOW_NO_WAIT, entry);
            }
            return NULL;
        }
    }
    /* timeout_ms == 0: caller (Go-side debouncer per) drives
     * doca_flow_entries_process() on its 50ms tick. */
    return (llb_doca_entry_handle_t)entry;
}

llb_doca_entry_handle_t llb_doca_acl_allow_entry_add(
    const void *em,
    uint32_t timeout_ms)
{
    doca_error_t dret;

    if (g_allow_pipe == NULL) {
        fprintf(stderr, "llb_doca: acl_allow_entry_add called before pipes_create\n");
        return NULL;
    }
    if (em == NULL) {
        fprintf(stderr, "llb_doca: acl_allow_entry_add invalid args (em=NULL)\n");
        return NULL;
    }
    if (g_ct_fwd_pipe == NULL) {
        /* Defence-in-depth: ALLOW's forward target. The pipe-create guard above already
         * checks this, but a separate teardown of g_ct_fwd_pipe between create and
         * entry-add would leave ALLOW with a stale next_pipe. */
        fprintf(stderr, "llb_doca: acl_allow_entry_add g_ct_fwd_pipe NULL\n");
        return NULL;
    }

    /* Header opacity cast — see llb_doca_acl_deny_entry_add. */
    const struct doca_flow_match *match = (const struct doca_flow_match *)em;

    /* Counter-readback fix (2026-05-17): per-entry monitor + per-entry fwd both
     * passed as NULL — pipe-level monitor (line 2194, counter_type=NON_SHARED)
     * and pipe-default fwd_tmpl FWD_PIPE→g_ct_fwd_pipe (line 2208) carry the
     * semantics. Mirrors flow_acl_basic_sample.c:571,602,634 pattern. See
 * llb_doca_acl_deny_entry_add for full RCA. still met. */
    g_entry_status = -1;
    struct doca_flow_pipe_entry *entry = NULL;
    dret = doca_flow_pipe_add_entry(0,
                                     g_allow_pipe,
                                     (struct doca_flow_match *)match,
                                     NULL,        /* no actions for ALLOW — */
                                     NULL,        /* monitor inherits pipe-level */
                                     NULL,        /* fwd inherits pipe-default FWD_PIPE→CT_FWD */
                                     DOCA_FLOW_NO_WAIT,
                                     NULL,
                                     &entry);
    if (dret != DOCA_SUCCESS) {
        fprintf(stderr, "llb_doca: ALLOW entry add failed rc=%d (%s)\n",
                (int)dret, doca_error_get_descr(dret));
        return NULL;
    }

    if (timeout_ms > 0) {
        if (wait_entry_offload(timeout_ms) != LLB_DOCA_OK) {
            fprintf(stderr, "llb_doca: ALLOW entry offload timeout (ms=%u) — rollback\n",
                    timeout_ms);
            if (entry) {
                doca_flow_pipe_remove_entry(0, DOCA_FLOW_NO_WAIT, entry);
            }
            return NULL;
        }
    }
    return (llb_doca_entry_handle_t)entry;
}

int llb_doca_acl_deny_entry_del(llb_doca_entry_handle_t entry)
{
    if (entry == NULL) {
        return LLB_DOCA_ERR_PARAM;
    }
    doca_error_t dret = doca_flow_pipe_remove_entry(0, DOCA_FLOW_NO_WAIT,
                                                    (struct doca_flow_pipe_entry *)entry);
    if (dret != DOCA_SUCCESS) {
        fprintf(stderr, "llb_doca: DENY entry remove failed rc=%d (%s)\n",
                (int)dret, doca_error_get_descr(dret));
        return LLB_DOCA_ERR_ENTRY;
    }
    return LLB_DOCA_OK;
}

int llb_doca_acl_allow_entry_del(llb_doca_entry_handle_t entry)
{
    if (entry == NULL) {
        return LLB_DOCA_ERR_PARAM;
    }
    doca_error_t dret = doca_flow_pipe_remove_entry(0, DOCA_FLOW_NO_WAIT,
                                                    (struct doca_flow_pipe_entry *)entry);
    if (dret != DOCA_SUCCESS) {
        fprintf(stderr, "llb_doca: ALLOW entry remove failed rc=%d (%s)\n",
                (int)dret, doca_error_get_descr(dret));
        return LLB_DOCA_ERR_ENTRY;
    }
    return LLB_DOCA_OK;
}

llb_doca_pipe_handle_t llb_doca_get_deny_pipe(void)
{
    return (llb_doca_pipe_handle_t)g_deny_pipe;
}

llb_doca_pipe_handle_t llb_doca_get_allow_pipe(void)
{
    return (llb_doca_pipe_handle_t)g_allow_pipe;
}

/* Plan 64-04 ext: per-entry match buffer alloc/fill helpers. Keep the
 * bridge header opaque (loxilb_doca_flow.h:21 contract) by exposing only
 * primitive args. The struct doca_flow_match layout is private to this file. */
void *llb_doca_acl_match_alloc_ip4(
    uint32_t src_ip,
    uint32_t src_mask,
    uint32_t dst_ip,
    uint32_t dst_mask,
    uint16_t src_port,
    uint16_t src_port_mask,
    uint16_t dst_port,
    uint16_t dst_port_mask)
{
    (void)src_mask; (void)dst_mask; (void)src_port_mask; (void)dst_port_mask;
    struct doca_flow_match *m = calloc(1, sizeof(*m));
    if (m == NULL) {
        return NULL;
    }
    m->outer.l3_type            = DOCA_FLOW_L3_TYPE_IP4;
    m->outer.ip4.src_ip         = src_ip;
    m->outer.ip4.dst_ip         = dst_ip;
    m->outer.l4_type_ext        = DOCA_FLOW_L4_TYPE_EXT_TRANSPORT;
    m->outer.transport.src_port = src_port;
    m->outer.transport.dst_port = dst_port;
    return m;
}

void *llb_doca_acl_match_alloc_mask_ip4(
    uint32_t src_mask,
    uint32_t dst_mask,
    uint16_t src_port_mask,
    uint16_t dst_port_mask)
{
    struct doca_flow_match *m = calloc(1, sizeof(*m));
    if (m == NULL) {
        return NULL;
    }
    m->outer.l3_type            = DOCA_FLOW_L3_TYPE_IP4;
    m->outer.ip4.src_ip         = src_mask;
    m->outer.ip4.dst_ip         = dst_mask;
    m->outer.l4_type_ext        = DOCA_FLOW_L4_TYPE_EXT_TRANSPORT;
    m->outer.transport.src_port = src_port_mask;
    m->outer.transport.dst_port = dst_port_mask;
    return m;
}

void llb_doca_acl_match_free(void *match)
{
    if (match != NULL) {
        free(match);
    }
}

/* ================================================================
 * Meter classification pipe (: per-service / per-host QoS)
 *
 *  BASIC pipe with NO NAT actions — only match + shared meter + counter.
 *  BF2 firmware accepts meter wildcards when no NAT modify actions exist.
 *  Match: 5-tuple wildcard (TRANSPORT l4_type_ext for port parsing).
 *  FWD: next pipe (L4 dispatch).  Miss: same next pipe (passthrough).
 *  Pipeline: ACL → meter_pipe → L4 dispatch → CT pipe.
 * ================================================================ */

llb_doca_pipe_handle_t llb_doca_meter_pipe_create(
    llb_doca_pipe_handle_t miss_target,
    uint32_t meter_id,
    uint32_t nr_entries)
{
    /* stub: DOCA pipe creation/entry-update deferred until validated
     * against the new core pipeline (CT pair + egress_dispatch + simplified root).
     * Go-side Capabilities() still advertises this offload; eBPF slow path handles
 * the feature at runtime. Restoration plan: CONTEXT.md. Old body in git
     * history at <pre-Phase-63 commit>. */
    (void)miss_target; (void)meter_id; (void)nr_entries;
    return NULL;
}

llb_doca_entry_handle_t llb_doca_meter_pipe_entry_add(
    llb_doca_pipe_handle_t pipe,
    uint32_t dst_ip,
    uint32_t timeout_ms)
{
    /* stub: DOCA pipe creation/entry-update deferred until validated
     * against the new core pipeline (CT pair + egress_dispatch + simplified root).
     * Go-side Capabilities() still advertises this offload; eBPF slow path handles
 * the feature at runtime. Restoration plan: CONTEXT.md. Old body in git
     * history at <pre-Phase-63 commit>. */
    (void)pipe; (void)dst_ip; (void)timeout_ms;
    return NULL;
}

void llb_doca_set_meter_pipe(llb_doca_pipe_handle_t pipe)
{
    g_meter_pipe = (struct doca_flow_pipe *)pipe;
}

llb_doca_pipe_handle_t llb_doca_get_meter_pipe(void)
{
    return (llb_doca_pipe_handle_t)g_meter_pipe;
}

/* ================================================================
 * L4 dispatch pipe — vestigial after.
 *
 * introduced this pipe between ACL and CT for protocol re-classification.
 * rebuilt the root pipe to dispatch per-L4-proto directly to CT_FWD,
 * rendering the L4-dispatch hop unnecessary. retires the
 *  creator function entirely (header decl removed in Task 1; body removed here).
 *
 *  The accessor `llb_doca_get_l4_dispatch_pipe()` is kept to satisfy unresolved
 *  CGO references in pkg/loxinet/dpu_doca_cgo.go (Plan 64-03 will delete those
 *  Go wrappers; until then this returns NULL, matching the prior stub state).
 * ================================================================ */

llb_doca_pipe_handle_t llb_doca_get_l4_dispatch_pipe(void)
{
    /* pipe is never created; always NULL. */
    return (llb_doca_pipe_handle_t)g_l4_dispatch_pipe;
}

/* ================================================================
 *  Entry CRUD
 * ================================================================ */

llb_doca_entry_handle_t llb_doca_entry_add_basic(
    llb_doca_pipe_handle_t pipe,
    uint32_t dst_ip,
    uint16_t dst_port,
    uint32_t src_ip,
    uint16_t src_port,
    uint32_t new_dst_ip,
    uint16_t new_dst_port,
    uint32_t new_src_ip,
    uint16_t new_src_port,
    uint8_t  new_dst_mac[6],
    uint8_t  new_src_mac[6],
    uint32_t timeout_ms,
    uint8_t  match_proto,
    uint16_t fwd_port_id,
    uint32_t aging_sec,
    uint64_t user_ctx,
    uint32_t meter_id)
{
    doca_error_t ret;
    static const uint8_t zero_mac[6] = {0};

    /* out_es_entry out-param dropped along with the
     * paired g_egress_steer entry pattern. CT entries drive downstream
     * dispatch via meta.pkt_meta = target_port_id; g_egress_dispatch
     * (Plan 63-02) handles per-port FWD via pre-installed entries. */

    if (!g_initialized || !pipe)
        return NULL;

    /* Entry match values */
    struct doca_flow_match entry_match;
    memset(&entry_match, 0, sizeof(entry_match));
    entry_match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
    if (dst_ip)
        entry_match.outer.ip4.dst_ip = dst_ip;
    if (src_ip)
        entry_match.outer.ip4.src_ip = src_ip;

    /* Port match fields: CT_FWD and CT_REV pipes both use TRANSPORT
 * (protocol-agnostic) per the 63-04 miss-chain pair. Both pipes
     * carry both TCP+UDP via per-entry l4_type. */
    int use_transport = ((struct doca_flow_pipe *)pipe == g_ct_fwd_pipe ||
                         (struct doca_flow_pipe *)pipe == g_ct_rev_pipe);
    if (use_transport) {
        entry_match.parser_meta.outer_l4_type =
            (match_proto == IPPROTO_UDP) ? DOCA_FLOW_L4_META_UDP : DOCA_FLOW_L4_META_TCP;
        if (dst_port)
            entry_match.outer.transport.dst_port = dst_port;
        if (src_port)
            entry_match.outer.transport.src_port = src_port;
    } else if (match_proto == IPPROTO_UDP) {
        if (dst_port)
            entry_match.outer.udp.l4_port.dst_port = dst_port;
        if (src_port)
            entry_match.outer.udp.l4_port.src_port = src_port;
    } else {
        if (dst_port)
            entry_match.outer.tcp.l4_port.dst_port = dst_port;
        if (src_port)
            entry_match.outer.tcp.l4_port.src_port = src_port;
    }

    /* Entry actions: NAT rewrite (dst IP/port, src IP/port, dst/src MAC) */
    struct doca_flow_actions entry_actions;
    memset(&entry_actions, 0, sizeof(entry_actions));
    entry_actions.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
    if (new_dst_ip)
        entry_actions.outer.ip4.dst_ip = new_dst_ip;
    if (new_src_ip)
        entry_actions.outer.ip4.src_ip = new_src_ip;

    /* Port action fields: match pipe template (TRANSPORT vs protocol-specific) */
    if (use_transport) {
        if (new_dst_port)
            entry_actions.outer.transport.dst_port = new_dst_port;
        if (new_src_port)
            entry_actions.outer.transport.src_port = new_src_port;
    } else if (match_proto == IPPROTO_UDP) {
        if (new_dst_port)
            entry_actions.outer.udp.l4_port.dst_port = new_dst_port;
        if (new_src_port)
            entry_actions.outer.udp.l4_port.src_port = new_src_port;
    } else {
        if (new_dst_port)
            entry_actions.outer.tcp.l4_port.dst_port = new_dst_port;
        if (new_src_port)
            entry_actions.outer.tcp.l4_port.src_port = new_src_port;
    }
    if (new_dst_mac && memcmp(new_dst_mac, zero_mac, 6) != 0)
        memcpy(entry_actions.outer.eth.dst_mac, new_dst_mac, 6);
    if (new_src_mac && memcmp(new_src_mac, zero_mac, 6) != 0)
        memcpy(entry_actions.outer.eth.src_mac, new_src_mac, 6);

    /* (TX-3): encode per-entry pkt_meta from fwd_port_id so
     * g_egress_dispatch (Plan 63-02 DEFAULT-domain BASIC pipe) can match
     * this entry's port via meta.pkt_meta = port_id.
     *
     * Byte order: NETWORK (htonl). Both validated samples set pkt_meta this
     * way on BOTH sides — the egress_dispatch entry match
     * (flow_e2e_l3_routing_sample.c:218 / flow_lb_snat_dnat_sample.c:241,
     * em.meta.pkt_meta = htonl(pid)) AND the per-flow action
     * (…:421/462 / …:466/516, ea.meta.pkt_meta = htonl(PORT_ID)). loxilb's
     * g_egress_dispatch entries already use htonl (line ~878), so this
     * action MUST too: on little-endian BF2, native fwd_port_id>=1 (e.g.
     * 0x00000001) never equals the entry's htonl(1)=0x01000000, so those
     * packets silently miss egress_dispatch and fall through miss→to_kernel.
 * Observed in validation as a stalled forward direction
     * (fwd_port=1) while reply (fwd_port=0, htonl-invariant) worked.
     * (user_ctx is still passed to doca_flow_pipe_add_entry below as the
 * aged-entry identification cookie —.) */
    entry_actions.meta.pkt_meta = htonl((uint32_t)fwd_port_id);

    /* (TX-3): CT entries rely on the template fwd
     * (g_egress_dispatch from Plan 63-02) — no per-entry FWD override
     * needed because the pipe template already carries the correct
     * destination, and pkt_meta-as-action drives the downstream dispatch
     * entry selection. Non-CT pipes (FDB) still use direct FWD_PORT.
     * The former LLB_DOCA_SPIKE_003_META_DISPATCH ifdef gate is gone —
     * both branches were already functionally identical post-63-04. */
    struct doca_flow_fwd entry_fwd;
    memset(&entry_fwd, 0, sizeof(entry_fwd));
    int is_ct_pipe = ((struct doca_flow_pipe *)pipe == g_ct_fwd_pipe ||
                      (struct doca_flow_pipe *)pipe == g_ct_rev_pipe);
    struct doca_flow_fwd *entry_fwd_ptr = &entry_fwd;
    if (is_ct_pipe) {
        entry_fwd_ptr = NULL;  /* template fwd handles it (egress_dispatch) */
    } else {
        entry_fwd.type = DOCA_FLOW_FWD_PORT;
        entry_fwd.port_id = fwd_port_id;
    }

    /* Pipe-aware actions dispatch:
     * - Root pipe: ALWAYS match-only (L3 classifier) → NULL actions
     * - CT pipe: has NAT actions template → pass entry_actions
     *   with IP/port/MAC rewrite values populated above
     * - Other pipes (SNAT via llb_doca_pipe_create_basic): always
     *   have actions templates → pass entry_actions
     *
     * Guard: pipes without actions template MUST pass NULL to avoid
     * DOCA rejection (actions on entry without pipe template is illegal). */
    struct doca_flow_actions *entry_acts_ptr = &entry_actions;
    if ((struct doca_flow_pipe *)pipe == g_root_pipe && !g_root_pipe_has_actions) {
        entry_acts_ptr = NULL;
    }
    /* Unified CT pipe always has actions -- no guard needed.
     * The g_ct_pipe_has_actions check is retained for external pipes. */

    const char *pipe_name =
        ((struct doca_flow_pipe *)pipe == g_ct_fwd_pipe)  ? "CT_FWD" :
        ((struct doca_flow_pipe *)pipe == g_ct_rev_pipe)  ? "CT_REV" :
        ((struct doca_flow_pipe *)pipe == g_udp_ct_pipe)  ? "UDP_CT" :
        ((struct doca_flow_pipe *)pipe == g_root_pipe)    ? "ROOT" : "OTHER";
    fprintf(stderr, "llb_doca: entry_add_basic [%s] pipe=%p match=[%08x:%u→%08x:%u proto=%u] "
            "nat=[dst=%08x:%u src=%08x:%u] mac=[%02x:%02x:%02x:%02x:%02x:%02x→"
            "%02x:%02x:%02x:%02x:%02x:%02x] fwd_port=%u actions=%s\n",
            pipe_name, pipe,
            src_ip, ntohs(src_port), dst_ip, ntohs(dst_port), match_proto,
            new_dst_ip, ntohs(new_dst_port), new_src_ip, ntohs(new_src_port),
            new_src_mac ? new_src_mac[0] : 0, new_src_mac ? new_src_mac[1] : 0,
            new_src_mac ? new_src_mac[2] : 0, new_src_mac ? new_src_mac[3] : 0,
            new_src_mac ? new_src_mac[4] : 0, new_src_mac ? new_src_mac[5] : 0,
            new_dst_mac ? new_dst_mac[0] : 0, new_dst_mac ? new_dst_mac[1] : 0,
            new_dst_mac ? new_dst_mac[2] : 0, new_dst_mac ? new_dst_mac[3] : 0,
            new_dst_mac ? new_dst_mac[4] : 0, new_dst_mac ? new_dst_mac[5] : 0,
            fwd_port_id,
            entry_acts_ptr ? "NAT-rewrite" : "NULL(match-only)");

    /* per-entry aging monitor +: per-entry shared meter */
    struct doca_flow_monitor entry_monitor;
    memset(&entry_monitor, 0, sizeof(entry_monitor));
    entry_monitor.aging_sec = aging_sec;
    /* attach shared meter to this entry if meter_id is valid */
    if (meter_id != LLB_DOCA_METER_NONE && meter_id < LLB_DOCA_MAX_METERS) {
        entry_monitor.meter_type = DOCA_FLOW_RESOURCE_TYPE_SHARED;
        entry_monitor.shared_meter.shared_meter_id = meter_id;
        entry_monitor.shared_meter.meter_init_color = DOCA_FLOW_METER_COLOR_GREEN;
    }

    g_entry_status = -1;
    struct doca_flow_pipe_entry *entry = NULL;
    ret = doca_flow_pipe_add_entry(0, (struct doca_flow_pipe *)pipe,
                                    &entry_match, entry_acts_ptr,
                                    (aging_sec || (meter_id != LLB_DOCA_METER_NONE && meter_id < LLB_DOCA_MAX_METERS)) ? &entry_monitor : NULL,
                                    entry_fwd_ptr,
                                    DOCA_FLOW_NO_WAIT,
                                    (void *)(uintptr_t)user_ctx, &entry);
    if (ret != DOCA_SUCCESS) {
        fprintf(stderr, "llb_doca: pipe_add_entry failed: %s\n",
                doca_error_get_descr(ret));
        return NULL;
    }

    if (wait_entry_offload(timeout_ms) != LLB_DOCA_OK) {
        /* Try to remove the failed entry */
        doca_flow_pipe_remove_entry(0, DOCA_FLOW_NO_WAIT, entry);
        return NULL;
    }

    fprintf(stderr, "llb_doca: entry offloaded OK [%s] entry=%p fwd_port=%u\n",
            pipe_name, (void *)entry, fwd_port_id);

    /* the obsolete `if (out_es_entry) *out_es_entry =
     * NULL;` write is gone with the out-param drop. Per-flow paired
 * g_egress_steer install ( P2) was removed in
     * Plan 63-04; g_egress_dispatch (Plan 63-02) handles per-port FWD
     * via static init-time entries keyed on meta.pkt_meta. */

    return (llb_doca_entry_handle_t)entry;
}

int llb_doca_entry_remove(llb_doca_pipe_handle_t pipe,
                           llb_doca_entry_handle_t entry,
                           uint32_t timeout_ms)
{
    doca_error_t ret;
    (void)pipe;  /* pipe not needed for rm_entry in DOCA 2.9.4 */

    if (!g_initialized || !entry)
        return LLB_DOCA_ERR_PARAM;

    g_entry_status = -1;
    ret = doca_flow_pipe_remove_entry(0, DOCA_FLOW_NO_WAIT,
                                   (struct doca_flow_pipe_entry *)entry);
    if (ret != DOCA_SUCCESS) {
        fprintf(stderr, "llb_doca: pipe_rm_entry failed: %s\n",
                doca_error_get_descr(ret));
        return LLB_DOCA_ERR_ENTRY;
    }

    return wait_entry_offload(timeout_ms);
}

int llb_doca_entry_query(llb_doca_entry_handle_t entry,
                          uint64_t *bytes_out,
                          uint64_t *pkts_out)
{
    if (!g_initialized || !entry)
        return LLB_DOCA_ERR_PARAM;

    struct doca_flow_resource_query query;
    memset(&query, 0, sizeof(query));
    doca_error_t ret = doca_flow_resource_query_entry(
        (struct doca_flow_pipe_entry *)entry, &query);

    if (ret != DOCA_SUCCESS) {
        fprintf(stderr, "llb_doca: query_entry failed: %s\n",
                doca_error_get_descr(ret));
        return LLB_DOCA_ERR_ENTRY;
    }

    if (bytes_out)
        *bytes_out = query.counter.total_bytes;
    if (pkts_out)
        *pkts_out = query.counter.total_pkts;

    fprintf(stderr, "llb_doca: entry_query entry=%p hw_pkts=%lu hw_bytes=%lu\n",
            (void *)entry, (unsigned long)query.counter.total_pkts,
            (unsigned long)query.counter.total_bytes);

    return LLB_DOCA_OK;
}

/* SPIKE-001 DIAG: dump pipe-miss counters for every downstream pipe.
 *
 * Per-entry monitors on root-pipe entries are silently no-ops on this BF2
 * firmware (entry_add OK, query returns Invalid input).  Pipe-miss counters
 * on the *target* pipes work fine: each says "this many packets entered this
 * pipe but matched no entry, so they took the pipe's miss path."
 *
 * CRITICAL — a pipe miss is NOT the same as "fell to the slow path".  The
 * pipeline is a MISS-CHAIN, so a miss on one pipe is just a hop to
 * the next pipe.  The chain is:
 *
 *     root --(port_meta)--> CT_FWD --miss--> CT_REV --miss--> to_kernel
 *       \--miss------------------------------------------------^
 *
 * Therefore the ONLY counter that means "packet was NOT HW-offloaded" is the
 * to_kernel ENTRY counter (its catch-all entry eats everything that arrives,
 * so its FWD_TARGET(KERNEL) — not its miss — is the real slow-path sink).
 *
 * Reading rules (corrected — the previous version mislabeled CT_FWD miss as a
 * fault signal and caused a false "1M-packet loss" alarm during 63-09
 * validation; the counters are internally consistent and the data plane is
 * correct):
 *   - TO_KERNEL_ENTRY hw_pkts  = AUTHORITATIVE slow-path volume. The number to
 *     watch. Fed by root-miss + CT_REV-miss.
 *   - CT_FWD miss = INTERMEDIATE miss-chain hop, NOT a fault. CT_FWD miss
 *     chains into CT_REV; a packet that misses CT_FWD and then matches a
 *     CT_REV entry is still fully HW-offloaded. A large CT_FWD miss with a
 *     small TO_KERNEL_ENTRY is HEALTHY (traffic matched on the reverse pipe).
 *   - CT_REV miss = real slow-path feed (chains straight to to_kernel).
 *   - FDB / UDP_CT / L4_DISPATCH miss = real slow-path feeds (chain to to_kernel).
 *   - TO_KERNEL pipe miss = effectively unreachable (catch-all entry matches all).
 *
 * Open follow-up (testbed): why a non-trivial fraction of port_meta=0 traffic
 * traverses the CT_FWD->CT_REV hop instead of matching CT_FWD directly is an
 * efficiency question, not a correctness one.
 */
static void diag_dump_pipe_miss_one(const char *name, struct doca_flow_pipe *pipe,
                                    const char *miss_chains_to)
{
    if (!pipe) {
        fprintf(stderr, "  %-16s  (pipe NULL)\n", name);
        return;
    }
    struct doca_flow_resource_query q;
    memset(&q, 0, sizeof(q));
    doca_error_t r = doca_flow_resource_query_pipe_miss(pipe, &q);
    if (r != DOCA_SUCCESS) {
        fprintf(stderr, "  %-16s  miss query_failed: %s\n",
                name, doca_error_get_descr(r));
        return;
    }
    fprintf(stderr, "  %-16s  miss_pkts=%lu miss_bytes=%lu  -> miss chains to %s\n",
            name,
            (unsigned long)q.counter.total_pkts,
            (unsigned long)q.counter.total_bytes,
            miss_chains_to);
}

void llb_doca_diag_dump_root_entries(void)
{
    if (!g_initialized) {
        fprintf(stderr, "llb_doca: DIAG_DUMP not initialized\n");
        return;
    }
    fprintf(stderr, "llb_doca: DIAG_DUMP pipe-miss counters:\n");

    /* AUTHORITATIVE slow-path signal FIRST: the to_kernel ENTRY counter is the
     * only number that means "packet was NOT HW-offloaded". Print it up top so
     * an operator reads the real verdict before the intermediate chain counters
     * (which are easy to misread — see the comment block on diag_dump_pipe_miss_one).
     * The catch-all entry matches everything that arrives, so its hw_pkts — not
     * the to_kernel pipe's miss — is the true slow-path volume. */
    if (g_to_kernel_entry) {
        struct doca_flow_resource_query q;
        memset(&q, 0, sizeof(q));
        doca_error_t r = doca_flow_resource_query_entry(g_to_kernel_entry, &q);
        if (r == DOCA_SUCCESS) {
            fprintf(stderr,
                "  %-16s  hw_pkts=%lu hw_bytes=%lu  <== SLOW-PATH TOTAL (packets NOT HW-offloaded)\n",
                "TO_KERNEL_ENTRY",
                (unsigned long)q.counter.total_pkts,
                (unsigned long)q.counter.total_bytes);
        } else {
            fprintf(stderr, "  %-16s  query_failed: %s\n",
                    "TO_KERNEL_ENTRY", doca_error_get_descr(r));
        }
    }

    /* Intermediate miss-chain counters. A miss here is a HOP to the next pipe,
     * not a slow-path drop. CT_FWD miss in particular chains into CT_REV and is
     * NOT a fault signal on its own — see the comment block above. */
    diag_dump_pipe_miss_one("CT_FWD",      g_ct_fwd_pipe,
        "CT_REV (intermediate hop — a CT_FWD miss that matches CT_REV is still HW-offloaded)");
    diag_dump_pipe_miss_one("CT_REV",      g_ct_rev_pipe,      "to_kernel (real slow-path feed)");
    diag_dump_pipe_miss_one("UDP_CT",      g_udp_ct_pipe,      "to_kernel");
    diag_dump_pipe_miss_one("L4_DISPATCH", g_l4_dispatch_pipe, "to_kernel");
    diag_dump_pipe_miss_one("FDB",         g_fdb_pipe,         "to_kernel");
    diag_dump_pipe_miss_one("TO_KERNEL",   g_to_kernel_pipe,
        "rss (effectively unreachable — catch-all entry matches all)");
    /* EGRESS_STEER diag dump removed along with the pipe.
     * Replacement diag (egress_dispatch + ct_fwd/ct_rev miss counters) is
     * carried by the CT_FWD/CT_REV/TO_KERNEL lines already above; the new
     * miss-chain semantics make a per-EGRESS_STEER line meaningless. */

    fprintf(stderr,
        "  interpretation: slow-path volume = TO_KERNEL_ENTRY hw_pkts above. "
        "CT_FWD miss is an intermediate miss-chain hop (CT_FWD->CT_REV->to_kernel) — "
        "a high CT_FWD miss with a low TO_KERNEL_ENTRY is HEALTHY.\n");
}

/* ================================================================
 * Shared meter lifecycle (QoS metering HW offload)
 * ================================================================ */

/* llb_doca_meter_add -- Configure and bind a shared RFC2697 srTCM meter.
 *
 * Three-step lifecycle validated by VD6 pre-spike on BF2:
 *   1. doca_flow_shared_resource_set_cfg() -- set CIR/CBS/EBS, algorithm
 *   2. doca_flow_shared_resources_bind()   -- bind to switch port (allocate HW)
 *
 * meter_id: 0-based (Go layer passes PolH.Mark - 1)
 * cir_bps:  Committed Information Rate in bits/sec (converted to bytes/sec for DOCA)
 * cbs:      Committed Burst Size in bytes
 * ebs:      Excess Burst Size in bytes (srTCM: via .rfc2698.pbs field per VD6.4)
 *
 * Returns: LLB_DOCA_OK or LLB_DOCA_ERR_PARAM.
 */
int llb_doca_meter_add(uint32_t meter_id, uint64_t cir_bps, uint64_t cbs, uint64_t ebs)
{
    /* stub: DOCA pipe creation/entry-update deferred until validated
     * against the new core pipeline (CT pair + egress_dispatch + simplified root).
     * Go-side Capabilities() still advertises this offload; eBPF slow path handles
 * the feature at runtime. Restoration plan: CONTEXT.md. Old body in git
     * history at <pre-Phase-63 commit>. */
    (void)meter_id; (void)cir_bps; (void)cbs; (void)ebs;
    return 0;
}

int llb_doca_meter_del(uint32_t meter_id)
{
    /* stub: DOCA pipe creation/entry-update deferred until validated
     * against the new core pipeline (CT pair + egress_dispatch + simplified root).
     * Go-side Capabilities() still advertises this offload; eBPF slow path handles
 * the feature at runtime. Restoration plan: CONTEXT.md. Old body in git
     * history at <pre-Phase-63 commit>. */
    (void)meter_id;
    return 0;
}

int llb_doca_meter_query(uint32_t meter_id, struct llb_doca_meter_stats *stats)
{
    /* stub: DOCA pipe creation/entry-update deferred until validated
     * against the new core pipeline (CT pair + egress_dispatch + simplified root).
     * Go-side Capabilities() still advertises this offload; eBPF slow path handles
 * the feature at runtime. Restoration plan: CONTEXT.md. Old body in git
     * history at <pre-Phase-63 commit>. */
    (void)meter_id;
    if (stats) memset(stats, 0, sizeof(*stats));
    return 0;
}

/* llb_doca_entry_update_meter -- Update an existing CT entry with a new meter.
 *
 * Requires pipe template to include meter wildcard (0xffffffff) at creation.
 * Confirmed working on BF2 by VD6.6 pre-spike.
 *
 * Returns: LLB_DOCA_OK or error code.
 */
int llb_doca_entry_update_meter(llb_doca_pipe_handle_t pipe, void *entry_handle, uint32_t meter_id)
{
    doca_error_t ret;

    if (!g_initialized || !pipe || !entry_handle)
        return LLB_DOCA_ERR_PARAM;
    if (meter_id >= LLB_DOCA_MAX_METERS && meter_id != LLB_DOCA_METER_NONE)
        return LLB_DOCA_ERR_PARAM;

    struct doca_flow_monitor new_monitor;
    memset(&new_monitor, 0, sizeof(new_monitor));
    if (meter_id != LLB_DOCA_METER_NONE) {
        new_monitor.meter_type = DOCA_FLOW_RESOURCE_TYPE_SHARED;
        new_monitor.shared_meter.shared_meter_id = meter_id;
        new_monitor.shared_meter.meter_init_color = DOCA_FLOW_METER_COLOR_GREEN;
    }

    g_entry_status = -1;
    ret = doca_flow_pipe_update_entry(0,
        (struct doca_flow_pipe *)pipe,
        NULL, &new_monitor, NULL,
        DOCA_FLOW_NO_WAIT,
        (struct doca_flow_pipe_entry *)entry_handle);
    if (ret != DOCA_SUCCESS) {
        fprintf(stderr, "llb_doca: entry_update_meter(%p, meter=%u) failed: %s\n",
                entry_handle, meter_id, doca_error_get_descr(ret));
        return LLB_DOCA_ERR_ENTRY;
    }

    if (wait_entry_offload(5000) != LLB_DOCA_OK) {
        fprintf(stderr, "llb_doca: entry_update_meter(%p, meter=%u) timeout\n",
                entry_handle, meter_id);
        return LLB_DOCA_ERR_TIMEOUT;
    }

    fprintf(stderr, "llb_doca: entry_update_meter(%p, meter=%u) OK\n",
            entry_handle, meter_id);
    return LLB_DOCA_OK;
}

/* ================================================================
 * Aging infrastructure
 * ================================================================ */

/* llb_doca_aging_poll -- Walk HW aging tables and fire callbacks for aged entries.
 *
 * Pattern follows DOCA flow_aging sample: call doca_flow_aging_handle() first
 * to walk HW aging tables, then doca_flow_entries_process() to fire callbacks.
 *
 * Return: 0 on success, negative error code on failure.
 * doca_flow_aging_handle returns: >0 = aged entries found, 0 = none, -1 = full cycle (not error).
 */
int llb_doca_aging_poll(uint64_t quota_time, uint32_t timeout_us, uint32_t max_entries)
{
    int num_aged;
    doca_error_t ret;

    if (!g_initialized || !g_switch_port)
        return LLB_DOCA_ERR_PARAM;

    num_aged = doca_flow_aging_handle(g_switch_port, 0, quota_time, 0);
    while (num_aged > 0) {
        ret = doca_flow_entries_process(g_switch_port, 0, timeout_us, max_entries);
        if (ret != DOCA_SUCCESS)
            return (int)ret;
        num_aged = doca_flow_aging_handle(g_switch_port, 0, quota_time, 0);
    }
    /* num_aged == -1 means full aging cycle complete (not error) */
    /* num_aged == 0 means no aged entries in this call */
    return 0; /* success */
}

/* llb_doca_entries_drain -- Process pending DOCA_FLOW_NO_WAIT entries.
 *
 * Pairs with the Plan 64-04 ACL debouncer which enqueues entries via
 * doca_flow_pipe_add_entry(..., DOCA_FLOW_NO_WAIT, ...) and relies on the
 * caller to drain the per-pipe-queue pending buffer. Without this drain the
 * queue saturates at the DOCA per-queue depth (~128 with set_pipe_queues(1)
 * on BF2 DOCA 2.9.4) and every subsequent add_entry returns INVALID_VALUE.
 *
 * aging implicitly drains the same queue for CT entries via
 * llb_doca_aging_poll's entries_process call; ACL pipes are not aged so they
 * need this explicit drain from the Go-side flushAclPending tick.
 *
 * Return: 0 on success, negative doca_error_t on failure.
 */
int llb_doca_entries_drain(uint32_t timeout_us, uint32_t max_entries)
{
    doca_error_t ret;

    if (!g_initialized || !g_switch_port)
        return LLB_DOCA_ERR_PARAM;

    ret = doca_flow_entries_process(g_switch_port, 0, timeout_us, max_entries);
    if (ret != DOCA_SUCCESS)
        return (int)ret;
    return 0;
}

/* llb_doca_get_aged_entries -- Drain aged entry ring buffer.
 * Returns: number of aged entries drained (0..max_out).
 */
int llb_doca_get_aged_entries(uint64_t *out_ctx, int max_out)
{
    int count = 0;
    uint32_t tail = __atomic_load_n(&g_aged_ring_tail, __ATOMIC_RELAXED);
    while (count < max_out && tail != __atomic_load_n(&g_aged_ring_head, __ATOMIC_ACQUIRE)) {
        out_ctx[count++] = g_aged_ring[tail].user_ctx;
        tail = (tail + 1) % LLB_DOCA_AGED_RING_SIZE;
    }
    __atomic_store_n(&g_aged_ring_tail, tail, __ATOMIC_RELEASE);
    return count;
}
