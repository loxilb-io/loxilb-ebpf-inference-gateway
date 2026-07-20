/*
 *  llb_kern_ipfilter.c: LoxiLB Kernel eBPF IP Whitelist/Blacklist Implementation
 *  Copyright (c) 2022-2025 LoxiLB Authors
 *
 *  SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 *
 *  P0-7: IP Whitelist/Blacklist - XDP Layer Security Filter
 *
 *  This implements XDP-layer IP filtering for DDoS protection with CIDR support.
 *  Performs early packet filtering at XDP layer before sk_buff allocation.
 *  Target: <1µs overhead per packet at XDP layer.
 *
 *  Two-stage security approach:
 *  - XDP (this file): Broad CIDR-based IP filtering for volumetric attacks
 *  - TC Firewall (llb_kern_fw.c): Fine-grained L4-L7 filtering with stateful tracking
 *
 *  Build-time feature flag: HAVE_DP_IP_FILTER
 *  Enable with: make EXTRA_CFLAGS="-DHAVE_DP_IP_FILTER"
 *
 *  Migration Note: IP filter moved to XDP layer for true early-drop performance.
 *  TC hook8 (tc_packet_func_ipfilter) is now DEPRECATED and bypassed.
 */

#ifdef HAVE_DP_IP_FILTER

/*
 * XDP Layer IP Filter Implementation
 * Simplified design: No zones (all traffic), no NAT check (pre-NAT), direct returns
 */

static int __always_inline
dp_do_ipfilter_v4_xdp(struct xdp_md *ctx, struct xfi *xf)
{
  struct dp_ip_filter_key key;
  struct dp_ip_filter_rule *blacklist_rule = NULL;
  struct dp_ip_filter_rule *whitelist_rule = NULL;

  /* Prepare LPM trie key for longest prefix match */
  memset(&key, 0, sizeof(key));
  key.prefixlen = 32;  /* /32 for exact match, LPM finds longest prefix */
  /* Copy IPv4 address into data byte array preserving network byte order */
  /* CRITICAL: Convert to host byte order first, then extract bytes to match Go pattern */
  /* Go does: ip4 := IP.To4() -> memcpy(data, &ip4[0], 4) which preserves byte order */
  /* We need: network_order -> host_order -> byte_extract to get [10,10,10,1] not [1,10,10,10] */
  __u32 saddr_host = bpf_ntohl(xf->l34m.saddr4);
  key.data[0] = (saddr_host >> 24) & 0xFF;  /* First byte (MSB) */
  key.data[1] = (saddr_host >> 16) & 0xFF;  /* Second byte */
  key.data[2] = (saddr_host >> 8) & 0xFF;   /* Third byte */
  key.data[3] = saddr_host & 0xFF;          /* Fourth byte (LSB) */

  // BPF_DBG_PRINTK("[XDP-IPFILTER] Lookup: src_net=0x%x src_host=0x%x key=[%d.%d.%d.%d] prefixlen=%d\n",
  //                xf->l34m.saddr4, saddr_host, key.data[0], key.data[1], key.data[2], key.data[3], key.prefixlen);

  /* Look up both blacklist and whitelist rules */
  blacklist_rule = bpf_map_lookup_elem(&ip_blacklist_map, &key);
  whitelist_rule = bpf_map_lookup_elem(&ip_whitelist_map, &key);

  /* Priority-based decision: Higher priority wins; whitelist wins ties so a
   * specific allow can override a broad blacklist at equal priority. */
  if (blacklist_rule && whitelist_rule) {
    /* Both rules match - compare priorities (higher value = higher priority) */
    if (whitelist_rule->priority >= blacklist_rule->priority) {
      /* Whitelist has higher-or-equal priority - allow */
      // BPF_DBG_PRINTK("[XDP-IPFILTER] Whitelist WINS (priority %d >= %d)\n",
      //                whitelist_rule->priority, blacklist_rule->priority);
      
      /* Update whitelist statistics */
      __sync_fetch_and_add(&whitelist_rule->packets, 1);
      __sync_fetch_and_add(&whitelist_rule->bytes, xf->pm.l3_len);
      
      if (whitelist_rule->action == 0) {  /* Allow action */
        return XDP_PASS;
      }
    } else {
      /* Blacklist has higher or equal priority - drop */
      // BPF_DBG_PRINTK("[XDP-IPFILTER] Blacklist WINS (priority %d >= %d)\n",
      //                blacklist_rule->priority, whitelist_rule->priority);
      
      /* Update blacklist statistics */
      __sync_fetch_and_add(&blacklist_rule->packets, 1);
      __sync_fetch_and_add(&blacklist_rule->bytes, xf->pm.l3_len);
      
      if (blacklist_rule->action == 1) {  /* Drop action */
        LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_ACT_DROP);
        return XDP_DROP;
      }
    }
  } else if (blacklist_rule) {
    /* Only blacklist matches */
    // BPF_DBG_PRINTK("[XDP-IPFILTER] Blacklist HIT: action=%d zone=%d priority=%d packets=%llu\n",
    //                blacklist_rule->action, blacklist_rule->zone, blacklist_rule->priority, blacklist_rule->packets);
    
    /* Update statistics atomically */
    __sync_fetch_and_add(&blacklist_rule->packets, 1);
    __sync_fetch_and_add(&blacklist_rule->bytes, xf->pm.l3_len);

    if (blacklist_rule->action == 1) {  /* Drop action */
      // BPF_DBG_PRINTK("[XDP-IPFILTER] ✓ Blacklist DROP: src_ip=0x%x action=%d\n",
      //                bpf_ntohl(xf->l34m.saddr4), blacklist_rule->action);
      LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_ACT_DROP);
      return XDP_DROP;  /* Direct drop at XDP layer */
    }
  } else if (whitelist_rule) {
    /* Only whitelist matches */
    /* Update statistics atomically */
    __sync_fetch_and_add(&whitelist_rule->packets, 1);
    __sync_fetch_and_add(&whitelist_rule->bytes, xf->pm.l3_len);

    if (whitelist_rule->action == 0) {  /* Allow action */
      // BPF_DBG_PRINTK("[XDP-IPFILTER] Whitelist ALLOW: src_ip=0x%x\n",
      //                bpf_ntohl(xf->l34m.saddr4));
      return XDP_PASS;  /* Continue to TC layer */
    }
  }

  /* Default: pass to TC layer (implicit allow if no rules match) */
  return XDP_PASS;
}

static int __always_inline
dp_do_ipfilter_v6_xdp(struct xdp_md *ctx, struct xfi *xf)
{
  struct dp_ip_filter_key key;
  struct dp_ip_filter_rule *blacklist_rule = NULL;
  struct dp_ip_filter_rule *whitelist_rule = NULL;

  /* Prepare LPM key for IPv6 */
  memset(&key, 0, sizeof(key));
  key.prefixlen = 128;  /* IPv6 /128 for exact match, LPM finds longest prefix */

  /* Copy IPv6 address into data byte array (already in network byte order) */
  *((__u32 *)&key.data[0]) = xf->l34m.saddr[0];
  *((__u32 *)&key.data[4]) = xf->l34m.saddr[1];
  *((__u32 *)&key.data[8]) = xf->l34m.saddr[2];
  *((__u32 *)&key.data[12]) = xf->l34m.saddr[3];

  /* Look up both blacklist and whitelist rules (IPv6-only tries) */
  blacklist_rule = bpf_map_lookup_elem(&ip_blacklist6_map, &key);
  whitelist_rule = bpf_map_lookup_elem(&ip_whitelist6_map, &key);

  /* Priority-based decision: Higher priority wins; whitelist wins ties so a
   * specific allow can override a broad blacklist at equal priority. */
  if (blacklist_rule && whitelist_rule) {
    /* Both rules match - compare priorities */
    if (whitelist_rule->priority >= blacklist_rule->priority) {
      /* Whitelist has higher-or-equal priority - allow */
      BPF_DBG_PRINTK("[XDP-IPFILTER] IPv6 Whitelist WINS (priority %d >= %d)\n",
                     whitelist_rule->priority, blacklist_rule->priority);
      
      /* Update whitelist statistics */
      __sync_fetch_and_add(&whitelist_rule->packets, 1);
      __sync_fetch_and_add(&whitelist_rule->bytes, xf->pm.l3_len);
      
      if (whitelist_rule->action == 0) {  /* Allow */
        return XDP_PASS;
      }
    } else {
      /* Blacklist has higher or equal priority - drop */
      BPF_DBG_PRINTK("[XDP-IPFILTER] IPv6 Blacklist WINS (priority %d >= %d)\n",
                     blacklist_rule->priority, whitelist_rule->priority);
      
      /* Update blacklist statistics */
      __sync_fetch_and_add(&blacklist_rule->packets, 1);
      __sync_fetch_and_add(&blacklist_rule->bytes, xf->pm.l3_len);
      
      if (blacklist_rule->action == 1) {  /* Drop */
        LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_ACT_DROP);
        return XDP_DROP;
      }
    }
  } else if (blacklist_rule) {
    /* Only blacklist matches */
    /* Update statistics atomically */
    __sync_fetch_and_add(&blacklist_rule->packets, 1);
    __sync_fetch_and_add(&blacklist_rule->bytes, xf->pm.l3_len);

    if (blacklist_rule->action == 1) {  /* Drop */
      BPF_DBG_PRINTK("[XDP-IPFILTER] IPv6 Blacklist DROP\n");
      LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_ACT_DROP);
      return XDP_DROP;
    }
  } else if (whitelist_rule) {
    /* Only whitelist matches */
    /* Update statistics atomically */
    __sync_fetch_and_add(&whitelist_rule->packets, 1);
    __sync_fetch_and_add(&whitelist_rule->bytes, xf->pm.l3_len);

    if (whitelist_rule->action == 0) {  /* Allow */
      BPF_DBG_PRINTK("[XDP-IPFILTER] IPv6 Whitelist ALLOW\n");
      return XDP_PASS;
    }
  }

  /* Default: pass to TC layer */
  return XDP_PASS;
}

/* Main XDP IP filter entry point - called from xdp_packet_func */
static int __always_inline
dp_do_ipfilter_main_xdp(struct xdp_md *ctx, struct xfi *xf)
{
  /* Process based on IP version */
  if (xf->l2m.dl_type == bpf_htons(ETH_P_IP)) {
    return dp_do_ipfilter_v4_xdp(ctx, xf);
  } else if (xf->l2m.dl_type == bpf_htons(ETH_P_IPV6)) {
    return dp_do_ipfilter_v6_xdp(ctx, xf);
  }

  /* Non-IP traffic, pass through */
  return XDP_PASS;
}

#endif /* HAVE_DP_IP_FILTER */