/* 
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 */
#include <string.h>

#include <linux/stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <sys/socket.h>
#include <stdint.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../common/common_pdi.h"
#include "../common/llb_dpapi.h"
#include "../common/llb_dp_mdi.h"

#ifndef HAVE_SOCKOPS
struct sock_proxy_map2_d {
  __uint(type,        BPF_MAP_TYPE_SOCKHASH);
  __type(key,         struct llb_sockmap_key);
  __type(value,       int);
  __uint(max_entries, LLB_SOCK_MAP_SZ);
} sock_proxy_map2 SEC(".maps");
#else
#define sock_proxy_map2 sock_proxy_map
#include "../common/llb_sockmap.h"
#endif

SEC("sk_skb/stream_parser")
int llb_sock_parser(struct __sk_buff *skb)
{
  return skb->len;
}

SEC("sk_skb/stream_verdict")
int llb_sock_verdict(struct __sk_buff *skb)
{
  /* Normalize ports to the low-half convention, where the net-order port lives
   * in the low 16 bits of the __be32 field.
   * __sk_buff.remote_port is a __u32 "network byte order" field, and the
   * kernel context rewrite applies LSH 16 on little-endian systems, placing
   * the net-order port in the upper 16 bits, just like
   * bpf_sock_ops.remote_port. Therefore it must be normalized with >> 16 to
   * match the sock_proxy_map / peer_map keys populated by sockops/userspace.
   * local_port is stored in the host-order low 16 bits, so convert it to the
   * net-order low 16 bits with bpf_htonl(...) >> 16. */
  struct llb_sockmap_key key = { .dip = skb->remote_ip4,
                                 .sip = skb->local_ip4,
                                 .dport = skb->remote_port >> 16,
                                 .sport = bpf_htonl(skb->local_port) >> 16
                                };
#ifdef HAVE_SOCKOPS
  struct llb_sockmap_key redirect_key;
  struct llb_sockmap_key *peer_key;
  __u16 vip_port;
  __u16 ep_port;
  __u8 eligible = 0;
  __u8 is_request = 0;
  __u8 *vip_enabled;
  __u8 *ep_enabled;
#endif

  if (skb->family != AF_INET) {
    return SK_PASS;
  }

#ifdef HAVE_SOCKOPS
  vip_port = key.sport;
  ep_port = key.dport;
  /* If both portset lookups stay live at the same time, the -O2 compiler can
   * merge the two NULL checks into
   *   r0 = vip_ptr | ep_ptr
   * which triggers the verifier error "pointer |= pointer prohibited".
   * Only look up ep on a vip miss so that at most one pointer is live at a
   * time, while preserving the OR semantics of eligibility. */
  vip_enabled = bpf_map_lookup_elem(&sockmap_vip_portset, &vip_port);
  if (vip_enabled) {
    /* sport is a VIP port -> this is the client/frontend socket, so the
     * ingress data is a request (client->backend). */
    eligible = 1;
    is_request = 1;
  } else {
    ep_enabled = bpf_map_lookup_elem(&sockmap_ep_portset, &ep_port);
    if (ep_enabled) {
      /* dport is an endpoint port -> backend socket, ingress data is a
       * response (backend->client). */
      eligible = 1;
    }
  }

  if (!eligible) {
    sockmap_stat_inc(SOCKMAP_STAT_INELIGIBLE);
    return SK_PASS;
  }

  peer_key = bpf_map_lookup_elem(&peer_map, &key);
  if (!peer_key) {
    sockmap_stat_inc(SOCKMAP_STAT_PEER_MISS);
    BPF_DBG_PRINTK("sockstream: peer miss dport 0x%lx sport 0x%lx", key.dport, key.sport);
    return SK_PASS;
  }

  __builtin_memcpy(&redirect_key, peer_key, sizeof(redirect_key));
#endif

  BPF_DBG_PRINTK("sockstream: dip 0x%lx sip 0x%lx", key.dip, key.sip);
  BPF_DBG_PRINTK("sockstream: dport 0x%lx sport 0x%lx", key.dport, key.sport);

#ifdef HAVE_SOCKOPS
  sockmap_stat_inc(SOCKMAP_STAT_REDIRECT_OK);
  sockmap_stat_inc(is_request ? SOCKMAP_STAT_REDIRECT_REQ : SOCKMAP_STAT_REDIRECT_RESP);
  /* Byte accounting for the response direction only: the client compares what it
   * received against this to locate where a duplicated segment came from. */
  if (!is_request) {
    sockmap_stat_add(SOCKMAP_STAT_RESP_BYTES, skb->len);
  }
  BPF_DBG_PRINTK("sockstream: peer dport 0x%lx sport 0x%lx", redirect_key.dport, redirect_key.sport);
  return bpf_sk_redirect_hash(skb, &sock_proxy_map2, &redirect_key, 0);
#else
  return bpf_sk_redirect_hash(skb, &sock_proxy_map2,  &key, 0);
#endif
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
