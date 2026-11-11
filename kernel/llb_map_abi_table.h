/* SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) */
#ifndef LLB_MAP_ABI_TABLE_H
#define LLB_MAP_ABI_TABLE_H
struct llb_map_geometry { __u32 type, key_size, value_size; };
#define LLB_GEOMETRY(t,k,v) {BPF_MAP_TYPE_##t, sizeof(k), sizeof(v)}
static const struct llb_map_geometry llb_map_geometry[LL_DP_MAX_MAP] = {
  [LL_DP_INTF_MAP] = LLB_GEOMETRY(HASH, struct intf_key, struct dp_intf_tact),
  [LL_DP_SMAC_MAP] = LLB_GEOMETRY(HASH, struct dp_smac_key, struct dp_smac_tact),
  [LL_DP_TMAC_MAP] = LLB_GEOMETRY(HASH, struct dp_tmac_key, struct dp_tmac_tact),
  [LL_DP_DMAC_MAP] = LLB_GEOMETRY(HASH, struct dp_dmac_key, struct dp_dmac_tact),
  [LL_DP_CT_MAP] = LLB_GEOMETRY(HASH, struct dp_ct_key, struct dp_ct_tact),
  [LL_DP_FCV4_MAP] = LLB_GEOMETRY(HASH, struct dp_fcv4_key, struct dp_fc_tacts),
  [LL_DP_NAT_MAP] = LLB_GEOMETRY(HASH, struct dp_nat_key, struct dp_proxy_tacts),
  [LL_DP_NAT_EP_MAP] = LLB_GEOMETRY(ARRAY, __u32, struct dp_nat_epacts),
  [LL_DP_FW4_MAP] = LLB_GEOMETRY(ARRAY, __u32, struct dp_fwv4_ent),
  [LL_DP_FW6_MAP] = LLB_GEOMETRY(ARRAY, __u32, struct dp_fwv6_ent),
  [LL_DP_POL_MAP] = LLB_GEOMETRY(ARRAY, __u32, struct dp_pol_tact),
  [LL_DP_RTV4_MAP] = LLB_GEOMETRY(LPM_TRIE, struct dp_rtv4_key, struct dp_rt_tact),
  [LL_DP_RTV6_MAP] = LLB_GEOMETRY(LPM_TRIE, struct dp_rtv6_key, struct dp_rt_tact),
  [LL_DP_NH_MAP] = LLB_GEOMETRY(ARRAY, __u32, struct dp_nh_tact),
  [LL_DP_TX_INTF_MAP] = LLB_GEOMETRY(DEVMAP, int, int),
  [LL_DP_MIRROR_MAP] = LLB_GEOMETRY(ARRAY, __u32, struct dp_mirr_tact),
  [LL_DP_SESS4_MAP] = LLB_GEOMETRY(HASH, struct dp_sess4_key, struct dp_sess_tact),
#ifndef HAVE_DP_DPU_SLIM
  [LL_DP_CRC32C_MAP] = LLB_GEOMETRY(ARRAY, __u32, __u32),
#endif
  [LL_DP_CTCTR_MAP] = LLB_GEOMETRY(ARRAY, __u32, struct dp_ct_ctrtact),
  [LL_DP_CPU_MAP] = LLB_GEOMETRY(CPUMAP, __u32, __u32),
  [LL_DP_LCPU_MAP] = LLB_GEOMETRY(ARRAY, __u32, __u32),
  [LL_DP_INTF_STATS_MAP] = LLB_GEOMETRY(PERCPU_ARRAY, __u32, struct dp_pb_stats),
  [LL_DP_BD_STATS_MAP] = LLB_GEOMETRY(PERCPU_ARRAY, __u32, struct dp_pb_stats),
  [LL_DP_TMAC_STATS_MAP] = LLB_GEOMETRY(PERCPU_ARRAY, __u32, struct dp_pb_stats),
  [LL_DP_CT_STATS_MAP] = LLB_GEOMETRY(PERCPU_ARRAY, __u32, struct dp_pb_stats),
  [LL_DP_RTV4_STATS_MAP] = LLB_GEOMETRY(PERCPU_ARRAY, __u32, struct dp_pb_stats),
  [LL_DP_RTV6_STATS_MAP] = LLB_GEOMETRY(PERCPU_ARRAY, __u32, struct dp_pb_stats),
  [LL_DP_TX_INTF_STATS_MAP] = LLB_GEOMETRY(PERCPU_ARRAY, __u32, struct dp_pb_stats),
  [LL_DP_TX_BD_STATS_MAP] = LLB_GEOMETRY(PERCPU_ARRAY, __u32, struct dp_pb_stats),
  [LL_DP_FCV4_STATS_MAP] = LLB_GEOMETRY(PERCPU_ARRAY, __u32, struct dp_pb_stats),
  [LL_DP_NAT_STATS_MAP] = LLB_GEOMETRY(PERCPU_ARRAY, __u32, struct dp_pb_stats),
  [LL_DP_SESS4_STATS_MAP] = LLB_GEOMETRY(PERCPU_ARRAY, __u32, struct dp_pb_stats),
  [LL_DP_FW_STATS_MAP] = LLB_GEOMETRY(PERCPU_ARRAY, __u32, struct dp_pb_stats),
  [LL_DP_PPLAT_MAP] = LLB_GEOMETRY(PERCPU_ARRAY, __u32, struct dp_pb_stats),
  [LL_DP_PGM_MAP] = LLB_GEOMETRY(PROG_ARRAY, __u32, __u32),
  [LL_DP_PKT_PERF_RING] = LLB_GEOMETRY(PERF_EVENT_ARRAY, __u32, __u32),
  [LL_DP_CP_PERF_RING] = LLB_GEOMETRY(PERF_EVENT_ARRAY, __u32, __u32),
  [LL_DP_CT_ERR_STATS_MAP] = LLB_GEOMETRY(ARRAY, __u32, __u64),
#ifdef HAVE_DP_IP_FILTER
  [LL_DP_IP_BLACKLIST_MAP] = LLB_GEOMETRY(LPM_TRIE, struct dp_ip_filter_key, struct dp_ip_filter_rule),
  [LL_DP_IP_WHITELIST_MAP] = LLB_GEOMETRY(LPM_TRIE, struct dp_ip_filter_key, struct dp_ip_filter_rule),
  [LL_DP_IP_BLACKLIST6_MAP] = LLB_GEOMETRY(LPM_TRIE, struct dp_ip_filter_key, struct dp_ip_filter_rule),
  [LL_DP_IP_WHITELIST6_MAP] = LLB_GEOMETRY(LPM_TRIE, struct dp_ip_filter_key, struct dp_ip_filter_rule),
#endif
#ifdef HAVE_DP_SECURITY_RATE_LIMIT
  /* The BPF declaration freezes the state at 56 bytes. Userspace iterates
   * these fixed keys; Go reads fixed-width scalar statistics. */
  [LL_DP_SECURITY_RATE_V4_TRACKING_MAP] = LLB_GEOMETRY(LRU_HASH, __u32, __u64[7]),
  [LL_DP_SECURITY_RATE_V6_TRACKING_MAP] = LLB_GEOMETRY(LRU_HASH, struct in6_addr, __u64[7]),
  [LL_DP_SECURITY_RATE_STATS_MAP] = LLB_GEOMETRY(ARRAY, __u32, __u64),
#ifdef HAVE_DP_SECURITY_RATE_RUNTIME_CONFIG
  /* Go's dpSecurityRateConfig is 14 uint32 fields, checked at its callsite;
   * the BPF side also has a 56-byte static assertion. */
  [LL_DP_SECURITY_RATE_CONFIG_MAP] = LLB_GEOMETRY(ARRAY, __u32, __u32[14]),
#endif
#endif
#ifdef HAVE_DP_GPU_ROUTING
  [LL_DP_ROUTING_MODE_MAP] = LLB_GEOMETRY(ARRAY, __u32, __u8),
  [LL_DP_WORKER_GPU_STATS_MAP] = LLB_GEOMETRY(HASH, __u32, struct worker_gpu_stats),
  [LL_DP_ENDPOINT_TO_GPU_INDEX_MAP] = LLB_GEOMETRY(HASH, struct endpoint_to_gpu_key, __u32),
  [LL_DP_SERVICE_SCORING_CONFIG_MAP] = LLB_GEOMETRY(HASH, __u32, struct service_scoring_config),
#endif
#ifdef HAVE_L4_TRACE
  [LL_DP_L4_TRACE_CONFIG_MAP] = LLB_GEOMETRY(ARRAY, __u32, __u32[4]),
  [LL_DP_L4_SAMPLING_MAP] = LLB_GEOMETRY(LRU_HASH, __u64, __u64[2]),
#endif

};
#undef LLB_GEOMETRY
#endif
