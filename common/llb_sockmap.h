/*
 *  llb_sockmap.h: LoxiLB sockmap definitions 
 *  Copyright (c) 2024-2025 LoxiLB Authors
 * 
 *  SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-clause) 
 */
#ifndef __LLB_SOCKMAP_H__
#define __LLB_SOCKMAP_H__

/* Counters for observing sockmap engagement (sk_skb verdict / sk_msg).
 * The meaning of each index is defined below.
 * Values are cumulative. Because this is PERCPU, per-packet increments do not
 * contend, but readers must sum values across CPUs. */
#define LLB_SOCKMAP_STATS_SZ        8   /* Includes spare slots */
#define SOCKMAP_STAT_REDIRECT_OK    0   /* Peer hit -> issue bpf_sk_redirect_hash (engage) */
#define SOCKMAP_STAT_PEER_MISS      1   /* Eligible, but peer_map miss -> SK_PASS */
#define SOCKMAP_STAT_INELIGIBLE     2   /* Portset mismatch -> SK_PASS */
#define SOCKMAP_STAT_REDIRECT_REQ   3   /* REDIRECT_OK in the request direction (client->backend, vip hit) */
#define SOCKMAP_STAT_REDIRECT_RESP  4   /* REDIRECT_OK in the response direction (backend->client, ep hit) */
/* Bytes handed to bpf_sk_redirect_hash in the response direction.
 * Compared against what the client actually receives, this tells whether a
 * duplicated segment passed through this verdict (counts match) or was produced
 * further down the kernel's send path (client receives more than we redirected). */
#define SOCKMAP_STAT_RESP_BYTES     5

struct sock_proxy_map_d {
  __uint(type,        BPF_MAP_TYPE_SOCKHASH);
  __type(key,         struct llb_sockmap_key);
  __type(value,       int);
  __uint(max_entries, LLB_SOCK_MAP_SZ);
} sock_proxy_map SEC(".maps");

struct sockmap_stats_map_d {
  __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key,         __u32);
  __type(value,       __u64);
  __uint(max_entries, LLB_SOCKMAP_STATS_SZ);
} sockmap_stats SEC(".maps");

/* Increment the counter for the given index by 1. Perform the atomic add only
 * after a standalone NULL check on a single lookup pointer.
 * This follows the same convention as synflood's dp_update_security_stats and
 * avoids the pointer-OR verifier hazard. */
static __always_inline void
sockmap_stat_inc(__u32 idx)
{
  __u64 *c = bpf_map_lookup_elem(&sockmap_stats, &idx);
  if (c) {
    __sync_fetch_and_add(c, 1);
  }
}

static __always_inline void
sockmap_stat_add(__u32 idx, __u64 val)
{
  __u64 *c = bpf_map_lookup_elem(&sockmap_stats, &idx);
  if (c) {
    __sync_fetch_and_add(c, val);
  }
}

struct sockmap_peer_map_d {
  __uint(type,        BPF_MAP_TYPE_HASH);
  __type(key,         struct llb_sockmap_key);
  __type(value,       struct llb_sockmap_key);
  __uint(max_entries, LLB_SOCK_MAP_SZ);
} peer_map SEC(".maps");

struct sockmap_vip_portset_map_d {
  __uint(type,        BPF_MAP_TYPE_HASH);
  __type(key,         __u16);
  __type(value,       __u8);
  __uint(max_entries, LLB_SOCK_VIP_PORTSET_SZ);
} sockmap_vip_portset SEC(".maps");

struct sockmap_ep_portset_map_d {
  __uint(type,        BPF_MAP_TYPE_HASH);
  __type(key,         __u16);
  __type(value,       __u8);
  __uint(max_entries, LLB_SOCK_EP_PORTSET_SZ);
} sockmap_ep_portset SEC(".maps");

#endif
