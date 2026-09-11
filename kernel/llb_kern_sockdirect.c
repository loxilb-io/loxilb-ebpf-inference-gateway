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
  __u16 vip_port;
  __u16 ep_port;
  __u8 eligible = 0;
  __u8 *vip_enabled;
  __u8 *ep_enabled;
  /* Use the low-half convention. sk_msg_md.remote_port is also a __u32
   * "network byte order" field, so the kernel places the net-order port in the
   * upper 16 bits and it must be normalized with >> 16.
   * (During the earlier unification, removing >> 16 after misreading
   * remote_port as already being in the low 16 bits, together with the missing
   * dport in sk_skb verdict, was the reason sockmap redirect always missed.)
   * local_port is stored in the host-order low 16 bits, so use
   * bpf_htonl(...) >> 16. */
  struct llb_sockmap_key key = { .dip = mmd->local_ip4,
                                 .sip = mmd->remote_ip4,
	                                 .dport = bpf_htonl(mmd->local_port) >> 16,
	                                 .sport = mmd->remote_port >> 16,
                               };

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
    eligible = 1;
  } else {
    ep_enabled = bpf_map_lookup_elem(&sockmap_ep_portset, &ep_port);
    if (ep_enabled) {
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
