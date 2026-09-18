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
#define SOCKMAP_STAT_REDIRECT_OK    0   /* bpf_sk_redirect_hash accepted the redirect (engage) */
#define SOCKMAP_STAT_PEER_MISS      1   /* peer_map miss -> SK_PASS. Must stay 0: userspace keeps sock_verdict_map and peer_map in step */
#define SOCKMAP_STAT_INELIGIBLE     2   /* Retired, always 0 for the stream verdict (index kept: tests read counters by index) */
#define SOCKMAP_STAT_REDIRECT_REQ   3   /* REDIRECT_OK in the request direction (client->backend, vip hit) */
#define SOCKMAP_STAT_REDIRECT_RESP  4   /* REDIRECT_OK in the response direction (backend->client, ep hit) */
/* Bytes handed to bpf_sk_redirect_hash in the response direction.
 * Compared against what the client actually receives, this tells whether a
 * duplicated segment passed through this verdict (counts match) or was produced
 * further down the kernel's send path (client receives more than we redirected). */
#define SOCKMAP_STAT_RESP_BYTES     5
/* bpf_sk_redirect_hash refused the redirect: the target is missing from
 * sock_proxy_map or cannot take a redirect, so the verdict returns SK_DROP. The
 * bytes were already ACKed to the sender, so the stream stalls. Must stay 0;
 * REDIRECT_OK, _REQ, _RESP and RESP_BYTES count only accepted redirects. */
#define SOCKMAP_STAT_REDIRECT_DROP  6

/* Two sockhashes, so that only the direction a rule accelerates pays for the
 * sk_skb verdict:
 *   sock_proxy_map   - every eligible socket, keyed by its own tuple. No programs
 *                      are attached; it is the lookup map of bpf_sk_redirect_hash,
 *                      so any socket that can be a redirect target must be here
 *                      (a miss is SK_DROP, and the dropped bytes are already ACKed).
 *   sock_verdict_map - the subset whose ingress direction is accelerated. The
 *                      stream parser and verdict are attached to this map.
 *                      Userspace adds a socket only after its peer_map entry
 *                      is installed and removes it before deleting that entry
 *                      (sockops never adds to it), so the verdict always finds
 *                      a peer and never has to SK_PASS.
 * A socket in response-only mode on the client side, for example, is only in
 * sock_proxy_map: it can receive redirected response bytes, while the requests it
 * receives stay on the plain TCP path instead of the psock ingress queue.
 * The value is __u64 so userspace can look an entry up (the kernel returns the
 * socket cookie only for an 8-byte value). */
struct sock_proxy_map_d {
  __uint(type,        BPF_MAP_TYPE_SOCKHASH);
  __type(key,         struct llb_sockmap_key);
  __type(value,       __u64);
  __uint(max_entries, LLB_SOCK_MAP_SZ);
} sock_proxy_map SEC(".maps");

struct sock_verdict_map_d {
  __uint(type,        BPF_MAP_TYPE_SOCKHASH);
  __type(key,         struct llb_sockmap_key);
  __type(value,       __u64);
  __uint(max_entries, LLB_SOCK_MAP_SZ);
} sock_verdict_map SEC(".maps");

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
  __type(value,       struct llb_sockmap_peer);
  __uint(max_entries, LLB_SOCK_MAP_SZ);
} peer_map SEC(".maps");

struct sockmap_vip_portset_map_d {
  __uint(type,        BPF_MAP_TYPE_HASH);
  __type(key,         struct llb_sockmap_portset_key);
  __type(value,       struct llb_sockmap_portset_val);
  __uint(max_entries, LLB_SOCK_VIP_PORTSET_SZ);
} sockmap_vip_portset SEC(".maps");

struct sockmap_ep_portset_map_d {
  __uint(type,        BPF_MAP_TYPE_HASH);
  __type(key,         struct llb_sockmap_portset_key);
  __type(value,       struct llb_sockmap_portset_val);
  __uint(max_entries, LLB_SOCK_EP_PORTSET_SZ);
} sockmap_ep_portset SEC(".maps");

/* VIP portset lookup for a socket whose local address and port are ip/port:
 * the exact address first, then the wildcard entry of a rule bound to 0.0.0.0.
 * One pointer is live at a time (see the pointer-OR note in the verdict). */
static __always_inline struct llb_sockmap_portset_val *
sockmap_vip_portset_lookup(__be32 ip, __u16 port)
{
  struct llb_sockmap_portset_key pk = { .ip = ip, .port = port, .res = 0 };
  struct llb_sockmap_portset_val *pv;

  pv = bpf_map_lookup_elem(&sockmap_vip_portset, &pk);
  if (pv) {
    return pv;
  }
  pk.ip = 0;
  return bpf_map_lookup_elem(&sockmap_vip_portset, &pk);
}

/* Endpoint portset lookup for a socket whose remote address and port are ip/port. */
static __always_inline struct llb_sockmap_portset_val *
sockmap_ep_portset_lookup(__be32 ip, __u16 port)
{
  struct llb_sockmap_portset_key pk = { .ip = ip, .port = port, .res = 0 };

  return bpf_map_lookup_elem(&sockmap_ep_portset, &pk);
}

#endif
