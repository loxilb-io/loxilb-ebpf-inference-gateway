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
#include "../common/llb_sockmap.h"

SEC("sk_msg")
int llb_sockmap_dir(struct sk_msg_md *mmd)
{
  struct llb_sockmap_key redirect_key;
  struct llb_sockmap_key *peer_key;
  struct llb_sockmap_portset_val *pv;
  struct llb_sockmap_key key = { .dip = mmd->local_ip4,
                                 .sip = mmd->remote_ip4,
	                                 .dport = bpf_htonl(mmd->local_port) >> 16,
	                                 .sport = mmd->remote_port >> 16,
                               };

  /* This key is the peer's view of the socket (sip/sport are the remote end),
   * which is what the portset lookups below have always been given. Only one
   * portset pointer is live at a time, to avoid the verifier's pointer-OR
   * rejection. */
  pv = sockmap_vip_portset_lookup(key.sip, (__u16)key.sport);
  if (!pv) {
    pv = sockmap_ep_portset_lookup(key.dip, (__u16)key.dport);
  }

  if (!pv) {
    sockmap_stat_inc(SOCKMAP_STAT_INELIGIBLE);
    return SK_PASS;
  }

  peer_key = bpf_map_lookup_elem(&peer_map, &key);
  if (!peer_key) {
    sockmap_stat_inc(SOCKMAP_STAT_PEER_MISS);
    BPF_DBG_PRINTK("sockdir: peer miss sport %lu dport %lu",
                   bpf_ntohs(key.sport), bpf_ntohs(key.dport));
    return SK_PASS;
  }

  __builtin_memcpy(&redirect_key, peer_key, sizeof(redirect_key));

  sockmap_stat_inc(SOCKMAP_STAT_REDIRECT_OK);
  BPF_DBG_PRINTK("sockdir: sport %lu dport %lu", bpf_ntohs(key.sport), bpf_ntohs(key.dport));

  bpf_msg_redirect_hash(mmd, &sock_proxy_map, &redirect_key, BPF_F_INGRESS);

  return SK_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
