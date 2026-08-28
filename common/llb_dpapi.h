/*
 *  llb_dpapi.h: LoxiLB DP Application Programming Interface 
 *  Copyright (C) 2022-2025  LoxiLB Authors
 * 
 *  SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-clause) 
 */
#ifndef __LLB_DPAPI_H__
#define __LLB_DPAPI_H__

#define LLB_MGMT_CHANNEL      "llb0"
#define LLB_SECTION_PASS      "xdp_pass"
#define LLB_FP_IMG_DEFAULT    "/opt/loxilb/llb_xdp_main.o"
#define LLB_FP_IMG_BPF        "/opt/loxilb/llb_ebpf_main.o"
#define LLB_FP_IMG_BPF_EGR    "/opt/loxilb/llb_ebpf_emain.o"
#define LLB_SOCK_ADDR_IMG_BPF "/opt/loxilb/llb_kern_sock.o"
#define LLB_SOCK_MAP_IMG_BPF  "/opt/loxilb/llb_kern_sockmap.o"
#define LLB_SOCK_DIR_IMG_BPF  "/opt/loxilb/llb_kern_sockdirect.o"
#define LLB_SOCK_SP_IMG_BPF   "/opt/loxilb/llb_kern_sockstream.o"
#define LLB_DB_MAP_PDIR       "/opt/loxilb/dp/bpf"

#define LLB_MAX_LB_NODES      (2)
#define LLB_MIRR_MAP_ENTRIES  (32)
#define LLB_NH_MAP_ENTRIES    (4*1024)
#define LLB_RTV4_MAP_ENTRIES  (32*1024)
#define LLB_RTV4_PREF_LEN     (48)
#define LLB_CT_MAP_ENTRIES    (256*1024*LLB_MAX_LB_NODES)
#define LLB_ACLV6_MAP_ENTRIES (4*1024)
#define LLB_RTV6_MAP_ENTRIES  (2*1024)
#define LLB_TMAC_MAP_ENTRIES  (2*1024)
#define LLB_DMAC_MAP_ENTRIES  (8*1024)
#define LLB_NATV4_MAP_ENTRIES (4*1024)
#define LLB_NATV4_STAT_MAP_ENTRIES (4*16*1024) /* 16 end-points */
#define LLB_NAT_EP_MAP_ENTRIES (4*1024)
#define LLB_SMAC_MAP_ENTRIES  (LLB_DMAC_MAP_ENTRIES)
#define LLB_FW4_MAP_ENTRIES   (8*1024)
#define LLB_FW6_MAP_ENTRIES   (1024)
#ifdef HAVE_DP_IP_FILTER
#define LLB_IP_FILTER_MAP_ENTRIES (16*1024)
#endif

#ifdef HAVE_DP_SECURITY_RATE_LIMIT
/* Unified Security Rate Limiting (P0-5 SYN Flood + P0-6 Connection Rate)
 *
 * MEMORY OPTIMIZATION: Single map for both features
 * - Replaces separate SYN flood maps (100K × 2 = 200K entries)
 * - Replaces separate connection rate maps (100K × 2 = 200K entries)
 * - Total: 100K entries (per protocol) vs 200K (50% reduction)
 *
 * Memory Savings:
 * - Old: 14.4 MB (4 separate maps)
 * - New:  7.6 MB (2 unified maps)
 * - Savings: 6.8 MB (47% reduction)
 */
#define LLB_SECURITY_RATE_MAP_ENTRIES (100*1024)  /* 100K entries per protocol */
#endif

#define LLB_INTERFACES        (512)
#define LLB_PORT_NO           (LLB_INTERFACES-1)
#define LLB_PORT_PIDX_START   (LLB_PORT_NO - 128)
#define LLB_INTF_MAP_ENTRIES  (6*1024)
#define LLB_FCV4_MAP_ENTRIES  (LLB_CT_MAP_ENTRIES)
#define LLB_PGM_MAP_ENTRIES   (9)
// #define LLB_PGM_MAP_ENTRIES   (8)
#define LLB_FCV4_MAP_ACTS     (DP_SET_TOCP+1)
#define LLB_POL_MAP_ENTRIES   (8*1024)
#define LLB_SESS_MAP_ENTRIES  (20*1024)
#define LLB_PPLAT_MAP_ENTRIES (2048)
#define LLB_PSECS             (8)
#define LLB_MAX_NXFRMS        (32)
#define LLB_CRC32C_ENTRIES    (256)
#define LLB_MAX_MHOSTS        (3)
#define LLB_MAX_SCTP_CHUNKS_INIT (8)
#define LLB_RWR_MAP_ENTRIES   (1024)
#define LLB_SOCK_MAP_SZ       (17*1024)
#define LLB_SOCKID_MAP_SZ     (17*1024)
#define LLB_MAX_HOSTURL_LEN   (256)
#define MAX_MODEL_LEN         (128)  /* AI model name max length (e.g. "llama-70b") */

#ifdef HAVE_DP_GPU_ROUTING
#define MAX_ENDPOINTS         (512)
#define METRICS_STALENESS_SEC (5)
#endif

#define LLB_DP_MASQ_PGM_ID     (7)
#define LLB_DP_SUNP_PGM_ID2    (6)
#define LLB_DP_CRC_PGM_ID2     (5)
#define LLB_DP_CRC_PGM_ID1     (4)
#define LLB_DP_FW_PGM_ID       (3)
#ifdef HAVE_DP_IP_FILTER
#define LLB_DP_IPFILTER_PGM_ID (8)
#endif
#define LLB_DP_CT_PGM_ID       (2)
#define LLB_DP_PKT_SLOW_PGM_ID (1)
#define LLB_DP_PKT_PGM_ID      (0)

#define LLB_NAT_STAT_CID(rid, aid) ((((rid) & 0x7ff) << 5) | (aid & 0x1f))


/* Hard-timeout of 120s for fc dp entry */
#define FC_V4_DPTO            (120000000000)

/* fc cp sweep period of 30m */
#define FC_SWEEP_PERIOD       (1800000000000)
/* Hard-timeout of 15m for fc cp entry */
#define FC_V4_CPTO            ( 900000000000)

/* Hard-timeout of 30m for ct entry */
#define CT_V4_CPTO            (1800000000000)

/* Hard-timeouts for ct xxx entry */
#define CT_TCP_FN_CPTO        (10000000000)
#define CT_SCTP_FN_CPTO       (10000000000)
#define CT_UDP_FN_CPTO        (5000000000)
#define CT_UDP_EST_CPTO       (10000000000)
#define CT_ICMP_EST_CPTO      (20000000000)
#define CT_ICMP_FN_CPTO       (5000000000)
#define CT_MISMATCH_FN_CPTO   (180000000000)

/* FW Mark values */
#define LLB_MARK_NAT          (0x80000000)
#define LLB_MARK_SRC          (0x40000000)
#define LLB_MARK_SNAT_EGR     (0x20000000)

#define DP_XADDR_ISZR(a) ((a)[0] == 0 && \
                          (a)[1] == 0 && \
                          (a)[2] == 0 && \
                          (a)[3] == 0)

#define DP_XADDR_CP(a, b)         \
do {                              \
  (a)[0] = (b)[0];                \
  (a)[1] = (b)[1];                \
  (a)[2] = (b)[2];                \
  (a)[3] = (b)[3];                \
} while (0)

#define DP_XADDR_SETZR(a)         \
do {                              \
  (a)[0] = 0;                     \
  (a)[1] = 0;                     \
  (a)[2] = 0;                     \
  (a)[3] = 0;                     \
} while(0)

enum llb_dp_tid {
  LL_DP_INTF_MAP = 0,
  LL_DP_INTF_STATS_MAP,
  LL_DP_BD_STATS_MAP,
  LL_DP_SMAC_MAP,
  LL_DP_TMAC_MAP,
  LL_DP_CT_MAP,
  LL_DP_RTV4_MAP,
  LL_DP_RTV6_MAP,
  LL_DP_NH_MAP,
  LL_DP_DMAC_MAP,
  LL_DP_TX_INTF_MAP,
  LL_DP_MIRROR_MAP,
  LL_DP_TX_INTF_STATS_MAP,
  LL_DP_TX_BD_STATS_MAP,
  LL_DP_PKT_PERF_RING,
  LL_DP_RTV4_STATS_MAP,
  LL_DP_RTV6_STATS_MAP,
  LL_DP_CT_STATS_MAP,
  LL_DP_TMAC_STATS_MAP,
  LL_DP_FCV4_MAP,
  LL_DP_FCV4_STATS_MAP,
  LL_DP_PGM_MAP,
  LL_DP_POL_MAP,
  LL_DP_NAT_MAP,
  LL_DP_NAT_STATS_MAP,
  LL_DP_SESS4_MAP,
  LL_DP_SESS4_STATS_MAP,
  LL_DP_FW4_MAP,
  LL_DP_FW6_MAP,
  LL_DP_FW_STATS_MAP,
#ifdef HAVE_DP_IP_FILTER
  LL_DP_IP_BLACKLIST_MAP,
  LL_DP_IP_WHITELIST_MAP,
  LL_DP_IP_BLACKLIST6_MAP,
  LL_DP_IP_WHITELIST6_MAP,
#endif
#ifdef HAVE_DP_SECURITY_RATE_LIMIT
  LL_DP_SECURITY_RATE_V4_TRACKING_MAP,
  LL_DP_SECURITY_RATE_V6_TRACKING_MAP,
  LL_DP_SECURITY_RATE_STATS_MAP,
#ifdef HAVE_DP_SECURITY_RATE_RUNTIME_CONFIG
  LL_DP_SECURITY_RATE_CONFIG_MAP,
#endif
#endif
  LL_DP_CRC32C_MAP,
  LL_DP_CTCTR_MAP,
  LL_DP_CPU_MAP,
  LL_DP_LCPU_MAP,
  LL_DP_PPLAT_MAP,
  LL_DP_CP_PERF_RING,
  LL_DP_NAT_EP_MAP,
  LL_DP_SOCK_RWR_MAP,
  LL_DP_SOCK_PROXY_MAP,
#ifdef HAVE_DP_GPU_ROUTING
  LL_DP_ROUTING_MODE_MAP,
  LL_DP_WORKER_GPU_STATS_MAP,
  LL_DP_ENDPOINT_TO_GPU_INDEX_MAP,
  LL_DP_SERVICE_SCORING_CONFIG_MAP,
#endif
#ifdef HAVE_L4_TRACE
  LL_DP_L4_TRACE_CONFIG_MAP,
  LL_DP_L4_TRACE_RINGBUF,
  LL_DP_L4_SAMPLING_MAP,
#endif
  /*
   * Always-on, unsampled connection-error counters (metric-only).
   * Deliberately OUTSIDE HAVE_L4_TRACE: L4 error metrics must be exact and
   * independent of the (compile-gated, runtime-gated, SAMPLED) L4 trace path.
   */
  LL_DP_CT_ERR_STATS_MAP,
  LL_DP_MAX_MAP
};

enum {
  DP_SET_DROP            = 0,
  DP_SET_SNAT            = 1,
  DP_SET_DNAT            = 2,
  DP_SET_NEIGH_L2        = 3,
  DP_SET_ADD_L2VLAN      = 4,
  DP_SET_RM_L2VLAN       = 5,
  DP_SET_TOCP            = 6,
  DP_SET_RM_VXLAN        = 7,
  DP_SET_NEIGH_VXLAN     = 8,
  DP_SET_RT_TUN_NH       = 9,
  DP_SET_L3RT_TUN_NH     = 10,
  DP_SET_IFI             = 11,
  DP_SET_NOP             = 12,
  DP_SET_L3_EN           = 13,
  DP_SET_RT_NHNUM        = 14,
  DP_SET_SESS_FWD_ACT    = 15,
  DP_SET_RDR_PORT        = 16,
  DP_SET_POLICER         = 17,
  DP_SET_DO_POLICER      = 18,
  DP_SET_FCACT           = 19,
  DP_SET_DO_CT           = 20,
  DP_SET_RM_GTP          = 21,
  DP_SET_ADD_GTP         = 22,
  DP_SET_NEIGH_IPIP      = 23,
  DP_SET_RM_IPIP         = 24,
  DP_SET_NACT_SESS       = 25,
  DP_SET_FULLPROXY       = 27,
  DP_SET_RT_NHNUM_DFLT   = 28
};

struct dp_cmn_act {
  __u8 act_type;
  __u8 ftrap;
  __u16 oaux;
  __u32 cidx;
  __u16 fwrid;
  __u16 record;
  __u32 mark;
};

struct dp_rt_l2nh_act {
  __u8 dmac[6];
  __u8 smac[6];
  __u16 bd;  
  __u16 rnh_num;
};

#define DP_MAX_ACTIVE_PATHS (4)

struct dp_rt_nh_act {
  __u16 nh_num[DP_MAX_ACTIVE_PATHS];
  __u16 naps;
  __u16 bd;
  __u32 tid;
  struct dp_rt_l2nh_act l2nh;
};

struct dp_rt_l3tun_act {
  __u32 rip;
  __u32 sip;
  __u32 tid;
  __u32 aux;
};

struct dp_rt_tunnh_act {
  struct dp_rt_l3tun_act l3t;
  struct dp_rt_l2nh_act l2nh;
};

struct dp_rdr_act {
  __u16 oport;
  __u16 fr;
};

struct dp_l2vlan_act {
  __u16 vlan;
  __u16 oport;
};

struct dp_sess_act {
  __u32 sess_id;
};

struct dp_nat_act {
  __u32 xip[4];
  __u32 rip[4];
  __u16 xport;
  __u8 fr;
  __u8 doct;
  __u32 rid;
  __u32 aid;
  __u8 nv6;
  __u8 dsr;
  __u8 cdis;
  __u8 nmh;
  __u8 ppv2;
  /* Rule-attached policer id carried per-flow (from dp_proxy_tacts.polid at CT-create;
   * 0 = none). Occupies former tail padding — struct size is unchanged at 52 bytes,
   * pinned below. Established packets re-arm xf->qm.rpolid from here (dp_pipe_set_nat)
   * so the rule policer fires on every packet, not just the nat_map-lookup ones.
   */
  __u16 polid;
};

/* dp_nat_act rides inside dp_ct_tact (ct_map value) — a silent size change here would
 * skew every CT entry. polid consumed tail padding; the size must not have moved.
 */
_Static_assert(sizeof(struct dp_nat_act) == 52, "dp_nat_act ABI size changed");

#define MIN_DP_POLICER_RATE  (8*1000*1000)  /* 1 MBps = 8 Mbps */

struct dp_pol_stats {
  uint64_t drop_packets;
  uint64_t pass_packets;
};

struct dp_policer_act {
  __u8  trtcm;
  __u8  color_aware;
  __u16 drop_prio; 
  __u32 pad;
  __u32 cbs;
  __u32 ebs;

  /* Internal state data */
  __u32 tok_c;
  __u32 tok_e;
  __u64 toksc_pus;
  __u64 tokse_pus;
  __u64 lastc_uts;
  __u64 laste_uts;
  struct dp_pol_stats ps;
};

#ifdef HAVE_DP_GPU_ROUTING
/* GPU-Aware Load Balancing: Worker Metrics Storage (vLLM 0.9.x) */
struct worker_gpu_stats {
    // TIER 1: Queue Metrics (vLLM Primary - MOST IMPORTANT for LLMs)
    __u32 queued_requests;      // vllm:num_requests_running + vllm:num_requests_waiting
    __u32 swapped_requests;     // Delta from vllm:num_preemptions_total

    // TIER 2: KV Cache (Memory Pressure Indicator)
    __u32 kv_cache_usage_perc;  // vllm:gpu_cache_usage_perc * 100 (0-100 scale)
    __u32 num_gpu_blocks;       // vllm:cache_config_info{num_gpu_blocks} (static config)

    // Hysteresis state for stability
    __u8  is_overloaded;        // Boolean: 1 if overloaded, 0 if healthy
    __u8  _pad1[3];             // Padding for alignment
    __u64 overload_start_ts;    // Timestamp when overload began (seconds)
    __u64 last_update_ts;       // Last metrics update timestamp (seconds)
    
    // Smart validation: Per-endpoint change tracking
    // Increments whenever THIS endpoint's metrics change significantly
    // Used to avoid redundant overload checks for cached conversations
    __u64 metrics_version;      // Increments on each metrics update
};

/* Endpoint to GPU Index Mapping Key */
struct endpoint_to_gpu_key {
    __be32 ip;      // Endpoint IP (network byte order)
    __be16 port;    // Endpoint port (network byte order)
    __u16  _pad;    // Padding for alignment
};

/* Service-level Scoring Configuration (from catalog) */
struct service_scoring_config {
    // Dynamic scoring weights (0-100, must sum to 100)
    __u32 queue_weight;
    __u32 swap_weight;
    __u32 kv_cache_weight;

    // Dynamic overload thresholds
    __u32 queue_overload_threshold;
    __u32 queue_recovery_threshold;
    __u32 kv_cache_overload_threshold;
    __u32 kv_cache_recovery_threshold;

    // Dynamic hysteresis config
    __u64 recovery_grace_period_sec;

    // Metadata for debugging/logging
    __u8 catalog_name[32];  // e.g., "chat-interactive"
    
    // Deep inspection catalog ID (0=disabled, 1-255=catalog ID)
    __u16 catalog_id;
    __u8 _pad[2];           // Alignment padding
};
#endif /* HAVE_DP_GPU_ROUTING */

struct dp_nh_key {
  __u32 nh_num;
};

struct dp_nh_tact {
  struct dp_cmn_act ca; /* Possible actions :
                         * DP_SET_NEIGH_L2
                         */
  union {
    struct dp_rt_l2nh_act rt_l2nh;
    struct dp_rt_tunnh_act rt_tnh;
  };
};

struct dp_rtv6_key {
  struct bpf_lpm_trie_key l;
  union {
    __u32 addr[4]; 
  };
}__attribute__((packed));

struct dp_rtv4_key {
  struct bpf_lpm_trie_key l;
  union {
    __u8  v4k[6];
    __u32 addr; 
  };
}__attribute__((packed));

struct dp_rt_tact {
  struct dp_cmn_act ca; /* Possible actions :
                         *  DP_SET_DROP
                         *  DP_SET_TOCP
                         *  DP_SET_RDR_PORT
                         *  DP_SET_RT_NHNUM
                         *  DP_SET_RT_TUN_NH
                         */
  union {
    struct dp_rdr_act port_act;
    struct dp_rt_nh_act rt_nh;
  };
};

#ifdef HAVE_DP_IP_FILTER
/* IP Filter (Whitelist/Blacklist) structures */
/* BUG FIX v2: Use byte array instead of union for better compatibility
 * The bpf_lpm_trie_key has prefixlen followed by data[] flexible array.
 * We use a fixed-size byte array that can hold both IPv4 (4 bytes) and IPv6 (16 bytes).
 */
struct dp_ip_filter_key {
  __u32 prefixlen;            /* Matches bpf_lpm_trie_key.prefixlen */
  __u8  data[16];             /* IP address bytes: IPv4 uses first 4, IPv6 uses all 16 */
}__attribute__((packed));

/* NOT packed: the kernel updates packets/bytes with 64-bit atomics, which
 * must target naturally-aligned members (clang rejects atomics on packed
 * members). The explicit pad makes the layout identical to the old packed
 * form plus alignment, and the static assert freezes it at 24 bytes. */
struct dp_ip_filter_rule {
  __u8  action;               /* 0 = allow, 1 = drop */
  __u8  zone;                 /* Security zone (0 = all zones) */
  __u16 priority;             /* Rule priority (higher = more important) */
  __u32 pad;                  /* Explicit pad so packets sits at offset 8 */
  __u64 packets;              /* Packet counter (offset 8) */
  __u64 bytes;                /* Byte counter   (offset 16) */
};
_Static_assert(sizeof(struct dp_ip_filter_rule) == 24,
               "dp_ip_filter_rule ABI changed - update Go-side stats offsets");
#endif

struct dp_fcv4_key {
#ifdef HAVE_DP_EXTFC
  __u8  smac[6];
  __u8  dmac[6];
  __u8  in_smac[6];
  __u8  in_dmac[6];
#endif

  __u32 daddr; 
  __u32 saddr; 
  __u16 sport; 
  __u16 dport; 
  __u8  l4proto;
  __u8  pad;
  __u16 in_port;

#ifdef HAVE_DP_EXTFC
  __u8  pad2;
  __u8  in_l4proto;
  __u16 in_sport; 
  __u32 in_daddr; 

  __u32 in_saddr; 
  __u16 in_dport; 
  __u16 bd;
#endif
};

struct dp_fc_tact {
  struct dp_cmn_act ca; /* Possible actions : See below */
  union {
    struct dp_rdr_act port_act;
    struct dp_rt_nh_act nh_act;          /* DP_SET_RM_VXLAN
                                          * DP_SET_RT_TUN_NH
                                          * DP_SET_L3RT_TUN_NH
                                          */
    struct dp_nat_act nat_act;           /* DP_SET_SNAT, DP_SET_DNAT */
    struct dp_rt_l2nh_act nl2;           /* DP_SET_NEIGH_L2 */
    struct dp_rt_tunnh_act ntun;         /* DP_SET_NEIGH_VXLAN,
                                          * DP_SET_NEIGH_IPIP
                                          */
    struct dp_l2vlan_act l2ov;           /* DP_SET_ADD_L2VLAN,
                                          * DP_SET_RM_L2VLAN
                                          */
  };
};

struct dp_fc_tacts {
  struct dp_cmn_act ca;
  __u64 its;
  __u32 zone;
  __u16 pad;
  __u16 pten;
  struct dp_fc_tact fcta[LLB_FCV4_MAP_ACTS];
};

struct dp_dmac_key {
  __u8 dmac[6];
  __u16 bd;
};

struct dp_dmac_tact {
  struct dp_cmn_act ca; /* Possible actions :
                         *  DP_SET_DROP
                         *  DP_SET_RDR_PORT
                         *  DP_SET_ADD_L2VLAN
                         *  DP_SET_RM_L2VLAN
                         */
  union {
    struct dp_l2vlan_act vlan_act;
    struct dp_rdr_act port_act;
  };
};

struct dp_tmac_key {
  __u8 mac[6];
  __u8 tun_type;
  __u8 pad;
  __u32 tunnel_id;
};

struct dp_tmac_tact {
  struct dp_cmn_act ca; /* Possible actions :
                         * DP_SET_DROP 
                         * DP_SET_TMACT_HIT
                         */
  union {
    struct dp_rt_nh_act rt_nh;
  };
};

struct dp_smac_key {
  __u8 smac[6];
  __u16 bd;
};

struct dp_smac_tact {
  struct dp_cmn_act ca; /* Possible actions :
                         * DP_SET_DROP 
                         * DP_SET_TOCP
                         * DP_SET_NOP
                         */
};

struct intf_key {
  __u32 ifindex;
  __u16 ing_vid;
  __u16 pad;
};

struct dp_intf_tact_set_ifi {
  __u16 xdp_ifidx;
  __u16 zone;
  __u16 bd;
  __u16 mirr;
  __u16 polid;
  __u8  pprop;
#define DP_PTEN_ALL   2
#define DP_PTEN_TRAP  1
#define DP_PTEN_DIS   0
  __u8  pten;
  /* Egress-direction policer id (polx_map key; 0 = none). Consumed only by the
   * egress TC image; the ingress image never reads it. Takes the first two bytes
   * of the former r[4] padding — offsets and total size unchanged.
   */
  __u16 e_polid;
  __u8  r[2];
};

struct dp_intf_tact {
  struct dp_cmn_act ca;
  union {
    struct dp_intf_tact_set_ifi set_ifi;
  };
};

struct dp_intf_map {
	struct intf_key key;
  struct dp_intf_tact acts;
};

struct dp_mirr_tact {
  struct dp_cmn_act ca; /* Possible actions :
                         * DP_SET_NEIGH_VXLAN
                         * DP_SET_ADD_L2VLAN
                         * DP_SET_RM_L2VLAN
                         */
  union {
    struct dp_rt_tunnh_act rt_tnh;
    struct dp_l2vlan_act vlan_act;
    struct dp_rdr_act port_act;
  };
};

struct dp_pol_tact {
  struct dp_cmn_act ca; /* Possible actions :
                         * DP_SET_DO_POLICER
                         */
#ifndef HAVE_DP_DPU_SLIM
  struct bpf_spin_lock lock;
#endif
  struct dp_policer_act pol;
};

struct sock_rwr_key {
#define vip4 vip[0]
  __u32 vip[4];
  __u16 port;
  __u16 res;
};

struct sock_rwr_action {
  __u16 rw_port;
  __u16 res;
};

struct dp_pb_stats {
  uint64_t bytes;
  uint64_t packets;
};
typedef struct dp_pb_stats dp_pb_stats_t;

#define DP_ST_LTO  (10000000000ULL)

struct dp_pbc_stats {
  dp_pb_stats_t st;
  uint64_t lts_used;
  int used;
};
typedef struct dp_pbc_stats dp_pbc_stats_t;

/* Connection tracking related defines */
typedef enum {
  CT_DIR_IN = 0,
  CT_DIR_OUT,
  CT_DIR_MAX
} ct_dir_t;

typedef enum {
  CT_STATE_NONE = 0x0,
  CT_STATE_REQ  = 0x1,
  CT_STATE_REP  = 0x2,
  CT_STATE_EST  = 0x4,
  CT_STATE_FIN  = 0x8,
  CT_STATE_DOR  = 0x10
} ct_state_t;

typedef enum {
  CT_FSTATE_NONE = 0x0,
  CT_FSTATE_SEEN = 0x1,
  CT_FSTATE_DOR  = 0x2
} ct_fstate_t;

typedef enum {
  CT_SMR_ERR    = -1,
  CT_SMR_INPROG = 0,
  CT_SMR_EST    = 1,
  CT_SMR_UEST   = 2,
  CT_SMR_FIN    = 3,
  CT_SMR_CTD    = 4,
  CT_SMR_UNT    = 100,
  CT_SMR_INIT   = 200,
} ct_smr_t;

#define CT_TCP_FIN_MASK (CT_TCP_FINI|CT_TCP_FINI2|CT_TCP_FINI3|CT_TCP_CW)
#define CT_TCP_SYNC_MASK (CT_TCP_SS|CT_TCP_SA)

typedef enum {
  CT_TCP_CLOSED = 0x0,
  CT_TCP_SS     = 0x1,
  CT_TCP_SA     = 0x2,
  CT_TCP_EST    = 0x4,
  CT_TCP_FINI   = 0x10,
  CT_TCP_FINI2  = 0x20,
  CT_TCP_FINI3  = 0x40,
  CT_TCP_CW     = 0x80,
  CT_TCP_ERR    = 0x100,
  CT_TCP_PEST   = 0x200,
} ct_tcp_state_t;

typedef struct {
  __u16 hstate;
#define CT_TCP_INIT_ACK_THRESHOLD 3
  __u8 init_acks;
  __u8 ppv2;
  __u32 seq;
  __be32 pack;
  __be32 pseq;
} ct_tcp_pinfd_t;

typedef struct {
  ct_tcp_state_t state;
  ct_dir_t fndir;
  ct_tcp_pinfd_t tcp_cts[CT_DIR_MAX];
#ifdef HAVE_L4_TRACE
  __u64 syn_ack_time_ns;  /* Timestamp for RTT calculation (SYN-ACK received) */
  __u32 rtt_us;           /* Calculated RTT in microseconds */
  __u32 _pad_rtt;         /* Padding for alignment */
#endif
} ct_tcp_pinf_t;


#define CT_UDP_FIN_MASK (CT_UDP_FINI)

typedef enum {
  CT_UDP_CNI    = 0x0,
  CT_UDP_UEST   = 0x1,
  CT_UDP_EST    = 0x2,
  CT_UDP_FINI   = 0x8,
  CT_UDP_CW     = 0x10,
} ct_udp_state_t;

typedef struct {
  __u16 state;
#define CT_UDP_CONN_THRESHOLD 4
  __u16 pkts_seen;
  __u16 rpkts_seen;
   ct_dir_t fndir;
} ct_udp_pinf_t;

typedef enum {
  CT_ICMP_CLOSED= 0x0,
  CT_ICMP_REQS  = 0x1,
  CT_ICMP_REPS  = 0x2,
  CT_ICMP_FINI  = 0x4,
  CT_ICMP_DUNR  = 0x8,
  CT_ICMP_TTL   = 0x10,
  CT_ICMP_RDR   = 0x20,
  CT_ICMP_UNK   = 0x40,
} ct_icmp_state_t;

typedef struct {
  __u32 nh;
  __u32 odst;
  __u32 osrc;
  __be32 mh_host[LLB_MAX_MHOSTS+1];
} ct_sctp_pinfd_t;

#define CT_SCTP_FIN_MASK (CT_SCTP_SHUT|CT_SCTP_SHUTA|CT_SCTP_SHUTC|CT_SCTP_ABRT)
#define CT_SCTP_INIT_MASK (CT_SCTP_INIT|CT_SCTP_INITA|CT_SCTP_COOKIE|CT_SCTP_COOKIEA)

typedef enum {
  CT_SCTP_CLOSED  = 0x0,
  CT_SCTP_INIT    = 0x1,
  CT_SCTP_INITA   = 0x2,
  CT_SCTP_COOKIE  = 0x4,
  CT_SCTP_COOKIEA = 0x10,
  CT_SCTP_PRE_EST = 0x20,
  CT_SCTP_EST     = 0x40,
  CT_SCTP_SHUT    = 0x80,
  CT_SCTP_SHUTA   = 0x100,
  CT_SCTP_SHUTC   = 0x200,
  CT_SCTP_ERR     = 0x400,
  CT_SCTP_ABRT    = 0x800
} ct_sctp_state_t;

typedef struct {
  ct_sctp_state_t state;
  ct_dir_t fndir;
  uint32_t itag;
  uint32_t otag;
  uint32_t cookie;
  ct_sctp_pinfd_t sctp_cts[CT_DIR_MAX];
} ct_sctp_pinf_t;

typedef struct {
  uint8_t state;
  uint8_t errs;
  uint16_t lseq;
} ct_icmp_pinf_t;

typedef struct {
  ct_state_t state;
} ct_l3inf_t;

typedef struct {
  union {
    ct_tcp_pinf_t t;
    ct_udp_pinf_t u;
    ct_icmp_pinf_t i;
    ct_sctp_pinf_t s;
  };
  __u16 frag;
  __u16 npmhh;
  __u32 pmhh[4];
  ct_l3inf_t l3i;
} ct_pinf_t;

#define nat_xip4 nat_xip[0]
#define nat_rip4 nat_rip[0]

struct mf_xfrm_inf {
  /* LLB_NAT_XXX flags */
  uint8_t nat_flags;
  uint8_t inactive;
  uint8_t wprio;
  uint8_t nv6;
  uint8_t dsr;
  uint8_t mhon;
  uint8_t mhs;
  uint8_t ep_role;                  // P/D endpoint role: 0=normal, 1=prefill, 2=decode
  uint32_t nat_xip[4];
  uint32_t nat_rip[4];
  uint16_t nat_xport;
  uint16_t osp;
  uint16_t odp;
  uint16_t nixl_xport;              // NIXL side-channel port; 0=use nat_xport
};
typedef struct mf_xfrm_inf nxfrm_inf_t;

struct dp_ct_dat {
  __u16 rid;
  __u16 aid;
  __u32 nid;
  ct_pinf_t pi;
  ct_dir_t dir;
  ct_smr_t smr;
  nxfrm_inf_t xi;
  dp_pb_stats_t pb;
};

struct dp_ct_tact {
  struct dp_cmn_act ca; /* Possible actions :
                         *  DP_SET_DROP
                         *  DP_SET_TOCP
                         *  DP_SET_NOP
                         *  DP_SET_RDR_PORT
                         *  DP_SET_RT_NHNUM
                         *  DP_SET_SESS_FWD_ACT
                         */
#ifndef HAVE_DP_DPU_SLIM
  struct bpf_spin_lock lock;
#endif
  struct dp_ct_dat ctd;
  __u64 ito;            /* Inactive timeout */
  __u64 lts;            /* Last used timestamp */
  union {
    struct dp_rdr_act port_act;
    struct dp_sess_act pdr_sess_act;
    struct dp_rt_nh_act rt_nh;
    struct dp_nat_act nat_act;
  };
};

/* Scratch version without spinlock for PERCPU maps */
struct dp_ct_tact_scratch {
  struct dp_cmn_act ca;
  __u32 pad_lock;       /* Padding to match dp_ct_tact layout (replaces bpf_spin_lock) */
  struct dp_ct_dat ctd;
  __u64 ito;
  __u64 lts;
  union {
    struct dp_rdr_act port_act;
    struct dp_sess_act pdr_sess_act;
    struct dp_rt_nh_act rt_nh;
    struct dp_nat_act nat_act;
  };
};

struct dp_ct_tact_set {
  uint16_t wp;
  uint16_t fc;
  uint32_t tc;
  struct dp_ct_tact tact;
};

#define CT_MAX_ACT_SET         16 

#define DP_SET_LB_NONE         0
#define DP_SET_LB_WPRIO        1
#define DP_SET_LB_RR           2

struct dp_ct_tacts {
  uint16_t num_acts;
  uint16_t lb_type;
  uint32_t rdata;
  struct dp_ct_tact_set act_set[CT_MAX_ACT_SET];
};
typedef struct dp_ct_tacts dp_ct_tacts_t;

struct dp_ct_key {
  __u32 daddr[4];
  __u32 saddr[4];
  __u16 sport;
  __u16 dport;
  __u16 zone;
  __u8  l4proto;
  __u8  v6;
  __u32 ident;
  __u32 type;
};

struct dp_proxy_ct_ent {
  __u32 rid;
  __u32 aid;
  struct dp_ct_key ct_in;
  struct dp_ct_key ct_out;
  struct dp_pb_stats st_in;
  struct dp_pb_stats st_out;
};

struct dp_fw_tact {
  struct dp_cmn_act ca; /* Possible actions :
                         *  DP_SET_DROP
                         *  DP_SET_TOCP
                         *  DP_SET_NOP
                         *  DP_SET_RDR_PORT
                         *  DP_SET_FW_MARK
                         */
  union {
    struct dp_rdr_act port_act;
    struct dp_nat_act nat_act;
  };
};

struct dp_fwv4_ent {
	struct pdi_key k;
  struct dp_fw_tact fwa;
};

struct dp_fwv6_ent {
	struct pdi6_key k;
  struct dp_fw_tact fwa;
};

struct dp_nat_key {
  __u32 daddr[4];
  __u16 dport;
  __u16 zone;
  __u32 mark;
  __u16 l4proto;
  __u16 v6;
};

#define NAT_LB_SEL_RR   0
#define NAT_LB_SEL_HASH 1
#define NAT_LB_SEL_PRIO 2
#define NAT_LB_SEL_RR_PERSIST 3
#define NAT_LB_SEL_LC 4
#define NAT_LB_SEL_N2 5
#define NAT_LB_SEL_N3 6
#define NAT_LB_SEL_CHWBL 8      /* Consistent Hash with Bounded Loads */
#define NAT_LB_SEL_GPU_AWARE 9  /* GPU-Aware Load Balancing (catalog-based) */
#define NAT_LB_SEL_WRR_HASH 10  /* Weighted Consistent Hash + Bounded Loads */

#define NAT_LB_PERSIST_TIMEOUT (10800000000000ULL)

#define SEC_MODE_NONE 0
#define SEC_MODE_HTTPS 1
#define SEC_MODE_HTTPS_E2E 2

#define NAT_LB_OP_CHKSRC 0x1


struct dp_proxy_tacts {
  struct dp_cmn_act ca;
  uint64_t ito;
  uint64_t pto;
#ifndef HAVE_DP_DPU_SLIM
  struct bpf_spin_lock lock;
#endif
  uint8_t nxfrm;
  uint8_t opflags;
  uint8_t cdis;
  uint8_t npmhh;
  uint16_t sel_hint;
  uint8_t sel_type;
  uint8_t sec_mode;
  uint8_t ppv2;
  uint8_t path_match_mode;  // P6: 0=disabled, 1=prefix, 2=exact
  uint8_t backend_protocol_cap;  // Backend protocol: 0=http1, 1=http2, 2=both
  uint8_t pd_disagg_mode;           // P/D disaggregation: 1=enabled, 0=disabled
  uint8_t ai_gw_mode;              // AI Gateway mode: 1=enabled, 0=disabled (auto-derived from sse_mode/pd_disagg/apikey)
  uint8_t pd_cache_aware_mode;     // P/D cache-aware routing: 0=disabled, 1=enabled
  uint8_t pd_cache_threshold;      // Cache hit % threshold (default 20)
  uint8_t pd_balance_abs_threshold; // Load balance absolute threshold (default 3);
  uint8_t apikey_auth;             // X-Api-Key policy: 0=unset, 1=required (enforce+strip), 2=declared disabled (strip only)
  uint64_t lts;
  uint64_t base_to;
  uint32_t pmhh[LLB_MAX_MHOSTS];
  uint8_t pad2[4];
  struct mf_xfrm_inf nxfrms[LLB_MAX_NXFRMS];
  uint8_t host_url[LLB_MAX_HOSTURL_LEN];
  uint8_t path_prefix[LLB_MAX_HOSTURL_LEN];  // P6: URL path prefix
  uint8_t session_header_name[128];  // Custom session header for stickiness (e.g., "mcp-session-id")
  uint8_t session_header_enabled;    // Enable session learning from backend responses (0=disabled, 1=enabled)
  uint8_t model_name[MAX_MODEL_LEN]; // AI model name for pool selection (e.g. "llama-70b"); empty = wildcard
  uint8_t  pad3a;                    // Explicit padding: align pd_kv_params_max to 2-byte boundary
  uint16_t pd_kv_params_max;         // Runtime KV params buffer limit (0 = use PD_KV_PARAMS_MAX_LEN)
  // SSE (Server-Sent Events) streaming configuration
  uint8_t  sse_mode;                 // SSE mode: 1=enabled, 0=disabled per-rule
  uint8_t  kv_exact_mode;            // KV-cache exact routing: 0=off, 1=zmq 
  uint8_t  kv_hash_algo;             // KV hash algorithm: 0=sha256_cbor, 1=xxhash_cbor 
  uint8_t  chwbl_prefix_hash_level;  // CHWBL prefix hash level: 1=L1, 2=L1+L2, 3=L1+L2+L3 (replaces pad3)
  uint32_t max_stream_duration_sec;  // Max stream duration cap in seconds (0=use PROXY_SSE_HARD_CAP_SEC)
  uint32_t backend_keepalive_sec;    // Backend TCP keepalive interval (0=disabled)
  uint32_t pd_session_ttl_sec;       // P/D session TTL in seconds (0=default 300s)
  uint32_t kv_block_size;            // KV token block size (default 16)
  uint32_t kv_warmup_sec;           // KV warmup seconds before Tier 1.5 activates 
  uint16_t kv_zmq_port;             // KV ZMQ PUB port (default 5557)
  // (SGL-03): per-rule engine + SGLang DP rank count. These two u8s
  // REPLACE the former pad3b(2) explicit padding (chwbl_prefix_hash_level
  // replaces-pad3 idiom) — every offset and the total size are unchanged, so
  // the four _Static_asserts below stay as-is. 0 = vllm default (byte-identical).
  uint8_t  kv_engine_type;          // KV engine: 0=vllm (default), 1=sglang 
  uint8_t  kv_dp_rank_count;        // SGLang DP ranks (1..8; 0 defaulted to 1 at CGO fill)
  // Octavia per-rule connectionLimit ceiling. conn_limit is the configured
  // concurrent-connection ceiling read by the SYN-time gate in dp_do_nat (0 = unlimited / no
  // gate). The LIVE concurrent count it is compared against (conc_conns) lives in dp_nat_epacts
  // (rule-index-keyed nat_ep_map) so the CT-teardown path in llb_kern_ct.c can decrement it by
  // rule id without re-deriving the VIP key — mirroring the proven active_sess[] / SecurityRate
  // concurrent_conns inc/dec primitive (selector-agnostic, fires for round-robin AND LC). This
  // single live count also backs the stats active_connections read. conn_limit(u32) +
  // pad3c(u32) = net +8 bytes here; the struct was already 8-aligned (a bare u32 would be padded
  // to 8 anyway). Bump ALL FOUR _Static_asserts + the Go CGO mirror in the same commit.
  uint32_t conn_limit;             // Configured concurrent-conn ceiling (0 = unlimited)
  // Per-endpoint circuit breaker enable (0=disabled, 1=enabled). Takes the first
  // byte of the former pad3c(4) — offsets and total size unchanged, so the
  // _Static_asserts below stay as-is (same idiom as kv_engine_type/pad3b).
  uint8_t  cb_enable;
  uint8_t  pad3c;                  // Alignment padding (keeps struct 8-byte aligned)
  // SGLang P/D disaggregation bootstrap port on every prefill EP (0 ⇒ SGLang's
  // default 8998, applied at proxy_add). Meaningful only when pd_disagg_mode=1
  // and kv_engine_type=1 (sglang) — the Go control plane rejects every other
  // pairing at config time. Takes the LAST TWO bytes of the former pad3c(3)
  // (cb_enable sits at a 4-aligned+1 offset, so those two bytes are 2-aligned)
  // — offsets and total size unchanged, the _Static_asserts below stay as-is
  // (same idiom as cb_enable/kv_engine_type).
  uint16_t pd_bootstrap_port;
  // Octavia per-listener member timeouts in MILLISECONDS (native unit).
  // Additive + default-off (0 ⇒ preserve today's behaviour). These mirror the proxy_arg
  // *_ms fields (sockproxy.h, added by Plan ) and are copied verbatim into proxy_arg by
  // llb_conv_nat2proxy (loxilb_libdp.c). Enforced only on the L7_Proxy peer (has_l7_policy==1).
  // 3×u32 = +12 bytes; the struct was 8-aligned after pad3c so the first u32 fills the 4-byte
  // slot and the last u32 needs a +4 pad to re-align. Bump ALL FOUR _Static_asserts + (no Go
  // mirror — dpebpf_linux.go reads C.struct_dp_proxy_tacts directly via cgo) in the same commit.
  uint32_t timeout_member_connect_ms; // backend connect-poll deadline (0 ⇒ 500ms default)
  uint32_t timeout_member_data_ms;    // member-side relay idle deadline (0 ⇒ existing idle)
  uint32_t timeout_tcp_inspect_ms;    // header-accumulation deadline (0 ⇒ bounded default)
  // Rule-attached Tier-0 policer id (polx_map key; 0 = no rule policer). Takes the
  // FIRST TWO bytes of the former pad3d(4) — offsets and total size unchanged, so the
  // _Static_asserts below stay as-is (same idiom as cb_enable/kv_engine_type). The NAT
  // datapath (dp_do_nat) copies this into xf->qm.rpolid on rule hit; CT-create persists
  // it per-flow in dp_nat_act.polid so established packets keep policing after the
  // nat_map lookup stops running for the flow.
  uint16_t polid;
  uint16_t pad3d;                     // Remaining padding (keeps struct 8-byte aligned)
  // TLS-hardening scalars ( version/cipher pinning, HSTS, backend
  // certIds). Additive + default-off (0/empty ⇒ today's behaviour, -COMPAT). Copied verbatim
  // into the proxy_arg fields added by llb_conv_nat2proxy. Consumed only on the L7_Proxy
  // peer (has_l7_policy==1); the AI peer is byte-for-byte unchanged. The Go side reads
  // C.struct_dp_proxy_tacts directly via cgo (no separate Go mirror to update).
  // Byte math (non-MTLS region): tls_version_min(1)+tls_version_max(1)+hsts_include_subdomains(1)
  //   +hsts_preload(1)+hsts_max_age(4) = 8 (8-aligned) + tls_ciphers(256) + backend_ca_cert_id(64)
  //   + backend_client_cert_id(64) = +392 bytes. All FOUR _Static_asserts bumped by +392.
  uint8_t  tls_version_min;           // low-byte 0x03xx ordinal; 0 ⇒ TLS1.2 floor
  uint8_t  tls_version_max;           // 0 ⇒ TLS1.3 ceiling
  uint8_t  hsts_include_subdomains;   // 1 ⇒ "; includeSubDomains"
  uint8_t  hsts_preload;              // 1 ⇒ "; preload"
  uint32_t hsts_max_age;              // 0 ⇒ no HSTS injection
  char     tls_ciphers[256];          // inline cipher string; empty ⇒ today's ciphers
  char     backend_ca_cert_id[64];    // backend CA certId; empty ⇒ system default
  char     backend_client_cert_id[64];// backend client certId; empty ⇒ none
#ifdef HAVE_MTLS
  // mTLS frontend configuration (only used for FullProxy rules in userspace; never in eBPF kernel map)
  uint8_t  mtls_frontend_mode;      // 0=disabled, 1=optional, 2=required
  uint8_t  mtls_require_client_cn;  // 1=require CN pattern match
  uint8_t  mtls_pad[6];             // Alignment padding
  char     mtls_client_ca_path[256];
  char     mtls_client_cn_pattern[256];
  // explicit client-cert CRL path → proxy_arg.client_crl_path.
  // Additive/default-off — empty ⇒ sibling-crl convention (+256 bytes; HAVE_MTLS asserts).
  char     mtls_client_crl_path[256];
#endif /* HAVE_MTLS */
};

// ABI guard: explicit padding eliminates all implicit alignment gaps.
// Layout: ca(16)+ito(8)+pto(8)+lock(4)+9×u8(9)+sel_hint(2)+5×u8(5)+pd_disagg_mode(1)+ai_gw_mode(1)
//         +pd_cache_aware_mode(1)+pd_cache_threshold(1)+pd_balance_abs_threshold(1)
//         +apikey_auth(1)+implicit_pad(3)+lts(8)+base_to(8)
//         +pmhh[3](12)+pad2(4)+nxfrms[32](1536)+host_url(256)+path_prefix(256)
//         +session_header_name(128)+session_header_enabled(1)+model_name(128)
//         +pad3a(1)+pd_kv_params_max(2)+sse_mode(1)+kv_exact_mode(1)+kv_hash_algo(1)+chwbl_prefix_hash_level(1)
//         +max_stream_dur(4)+backend_ka(4)+pd_session_ttl(4)
//         +kv_block_size(4)+kv_warmup_sec(4)+kv_zmq_port(2)+kv_engine_type(1)+kv_dp_rank_count(1) = 2424
// (: the two u8 engine fields replaced the former pad3b(2) — size/offsets unchanged)
// +conn_limit(4)+pad3c(4) = +8 (; struct already 8-aligned) = 2432
//         +timeout_member_connect_ms(4)+timeout_member_data_ms(4)+timeout_tcp_inspect_ms(4)+pad3d(4)
// = +16 (; struct already 8-aligned) = 2448
//         +HAVE_MTLS: +mtls_frontend_mode(1)+mtls_require_client_cn(1)+mtls_pad(6)+ca_path(256)+cn_pat(256) = +520 = 2968
// If this assertion fails, update the Go CGO struct in pkg/loxinet/dpebpf_linux.go.
// ABI guard updated for: +kv_block_size(4)+kv_warmup_sec(4)+kv_zmq_port(2)+pad3b(2) = +12 bytes
// Old tail padding (4 bytes after pd_session_ttl_sec) consumed by new fields = net +8 bytes: 2416→2424
// ABI guard updated for: +conn_limit(4)+pad3c(4) = +8 bytes (struct already 8-aligned): 2424→2432.
//   The live conc_conns count lives in dp_nat_epacts (rule-index-keyed), NOT here, so the
//   CT-teardown decrement can reach it by rule id; conn_limit (the ceiling) is read by the gate.
// ABI guard updated for: +timeout_member_connect_ms(4)+timeout_member_data_ms(4)
//   +timeout_tcp_inspect_ms(4)+pad3d(4) = +16 bytes (struct already 8-aligned): 2432→2448.
//   These ms timeouts are copied verbatim into proxy_arg by llb_conv_nat2proxy; no Go mirror to
//   update (dpebpf_linux.go reads C.struct_dp_proxy_tacts directly via cgo).
// ABI guard updated for: +tls_version_min(1)+tls_version_max(1)
//   +hsts_include_subdomains(1)+hsts_preload(1)+hsts_max_age(4)+tls_ciphers(256)
//   +backend_ca_cert_id(64)+backend_client_cert_id(64) = +392 bytes (8-aligned region): all four
//   asserts shift by +392 (2448→2840, 2440→2832, 2968→3360, 2960→3352). These scalars are copied
// verbatim into the proxy_arg fields added by llb_conv_nat2proxy; no Go mirror (cgo direct).
#ifndef HAVE_MTLS
#ifndef HAVE_DP_DPU_SLIM
_Static_assert(sizeof(struct dp_proxy_tacts) == 2840,
              "dp_proxy_tacts ABI changed — update Go CGO struct and this check");
#else
_Static_assert(sizeof(struct dp_proxy_tacts) == 2832,
              "dp_proxy_tacts DPU ABI changed");
#endif
#else /* HAVE_MTLS */
// +mtls_client_crl_path(256) = +256 (HAVE_MTLS only): 3360→3616, 3352→3608.
#ifndef HAVE_DP_DPU_SLIM
_Static_assert(sizeof(struct dp_proxy_tacts) == 3616,
              "dp_proxy_tacts mTLS ABI changed — update Go CGO struct and this check");
#else
_Static_assert(sizeof(struct dp_proxy_tacts) == 3608,
              "dp_proxy_tacts DPU mTLS ABI changed");
#endif
#endif /* HAVE_MTLS */

struct dp_nat_epacts {
  struct dp_cmn_act ca;
#ifndef HAVE_DP_DPU_SLIM
  struct bpf_spin_lock lock;
#endif
  uint16_t active_sess[LLB_MAX_NXFRMS];
  // Octavia per-rule live concurrent-connection count. Incremented on
  // CT-create and decremented on CT-teardown, SELECTOR-AGNOSTIC (unlike active_sess[] which is
  // only maintained in the least-connections branch). Keyed by rule index (nat_ep_map key), so
  // the CT-teardown path can decrement it by rule id. Read by the connectionLimit gate in
  // dp_do_nat and by the stats active_connections endpoint. Keep the Go CGO mirror in sync.
  uint32_t conc_conns;
  // Octavia /stats CUMULATIVE counters. Unlike conc_conns (a live
  // gauge), these are monotonic totals maintained in the datapath so they capture EVERY flow —
  // including short-lived ones that are created and torn down between two control-plane RulesSync
  // ticks (the live-CT-walk rollup misses those). Read per-rule by DpCtStatsRollup via the
  // nat_ep_map; reset on rule reset/delete (loxilb_libdp.c). Keep the Go CGO mirror in sync.
  // total_conns = ++ on CT-create ( "++ on CT-create"); never decremented.
  //   cum_bytes_in  = Σ client->VIP request bytes, summed from the forward CT at CT-teardown.
  //   cum_bytes_out = Σ VIP->client response bytes, summed from the reverse CT at CT-teardown.
  // u32 conc_conns + u32 total_conns keep the struct 8-byte aligned for the two trailing u64s.
  uint32_t total_conns;
  uint64_t cum_bytes_in;
  uint64_t cum_bytes_out;
};

/* This is currently based on ULCL classification scheme */
struct dp_sess4_key {
  __u32 daddr;
  __u32 saddr;
  __u32 teid;
  __u32 r;
};

struct dp_sess_tact {
  struct dp_cmn_act ca;
  uint8_t qfi; 
  uint8_t r1;
  uint16_t r2;
  uint32_t rip;
  uint32_t sip;
  uint32_t teid;
};

struct dp_ct_ctrtact {
  struct dp_cmn_act ca; /* Possible actions :
                         * None (just place holder)
                         */
#ifndef HAVE_DP_DPU_SLIM
  struct bpf_spin_lock lock;
#endif
  __u32 start;
  __u32 counter;
  __u32 entries;
};

struct llb_sockmap_key {
  __be32 dip;
  __be32 sip;
  __be32 dport;
  __be32 sport;
};

struct sock_str_key {
  __u32 xip;
  __u16 xport;
  __u16 res;
};

struct sock_str_val {
  __u32 start;
  __u32 num;
};

struct ll_dp_pmdi {
  __u32 ifindex;
  __u16 dp_inport;
  __u16 dp_oport;
  __u32 rcode;
  __u16 table_id;
  __u16 phit ;
  __u32 pkt_len;
  __u32 resolve_ip;
  uint8_t data[];
}; 

/* HW offload event sent via cp_ring when CT reaches EST with NAT */
struct ll_dp_ct_hwev {
  __u32 rcode;    /* LLB_PIPE_RC_HW_UPD */
  __u32 rid;      /* rule ID from CT */
  __u32 saddr;    /* source IP (network byte order) */
  __u32 daddr;    /* dest IP (network byte order) */
  __u16 sport;    /* source port (network byte order) */
  __u16 dport;    /* dest port (network byte order) */
  __u8  l4proto;  /* IPPROTO_TCP or IPPROTO_UDP */
  __u8  pad[3];
};

struct ll_dp_map_notif {
  int addop;
  char map_name[16];
  int key_len;
  void *key;
  int val_len;
  void *val;
};
typedef struct ll_dp_map_notif ll_dp_map_notif_t;

void goCtHwOffloadHandler(struct ll_dp_ct_hwev *ev);

struct dp_map_ita {
  void *next_key;
  size_t key_sz;
  void *val;
  void *uarg;
};
typedef struct dp_map_ita dp_map_ita_t;

void goMapNotiHandler(struct ll_dp_map_notif *mn);

#define __force __attribute__((force))

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#define memset(dest, c, n) __builtin_memset((dest), (c), (n))
#endif

#define DP_ADD_PTR(x, len) ((void *)(((uint8_t *)((long)x)) + (len)))
#define DP_TC_PTR(x) ((void *)((long)x))
#define DP_DIFF_PTR(x, y) (((uint8_t *)DP_TC_PTR(x)) - ((uint8_t *)DP_TC_PTR(y)))

/* Policer map stats update callback */
typedef void (*dp_pts_cb_t)(uint32_t idx, struct dp_pol_stats *ps);
/* Map stats update callback */
typedef void (*dp_ts_cb_t)(uint32_t idx, uint64_t bc, uint64_t pc);
/* Map stats idx valid check callback */
typedef int (*dp_tiv_cb_t)(int tid, uint32_t idx);
/* Map walker */
typedef int (*dp_map_walker_t)(int tid, void *key, void *arg);

int llb_map2fd(int t);
int llb_fetch_map_stats_cached(int tbl, uint32_t index, int raw, void *bc, void *pc);
void llb_age_map_entries(int tbl);
void llb_trigger_get_proxy_entries(void);
void llb_collect_map_stats(int tbl);
int llb_fetch_pol_map_stats(int tid, uint32_t e, void *ppass, void *pdrop);
void llb_clear_map_stats(int tbl, __u32 idx);
int llb_add_map_elem(int tbl, void *k, void *v);
int llb_del_map_elem_wval(int tbl, void *k, void *v);
int llb_del_map_elem(int tbl, void *k);
void llb_map_loop_and_delete(int tbl, dp_map_walker_t cb, dp_map_ita_t *it);
int llb_dp_link_attach(const char *ifname, const char *psec, int mp_type, int unload);
void llb_unload_kern_all(void);
void llb_xh_lock(void);
void llb_xh_unlock(void);
#endif /* __LLB_DPAPI_H__ */
