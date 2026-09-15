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
#include "../common/llb_sockmap.h"

/* Registers a newly established socket that belongs to a sockmap-enabled rule.
 * Every such socket goes into sock_proxy_map so it can be a redirect target.
 * sock_verdict_map is filled by userspace instead, only once the socket has a
 * peer to redirect to (llb_verdict_map_op): a socket in that map that the
 * verdict has to SK_PASS is exposed to a kernel defect. When SK_PASS data from
 * an earlier strparser read is still unread at the next read,
 * tcp_bpf_strp_read_sock() moves copied_seq past rcv_nxt, and a later small
 * segment never wakes the reader (h2c streams and small request tails stall).
 * Ports follow the low-half convention of llb_sockmap_key. */
SEC("sockops")
int llb_setup_sockmap(struct bpf_sock_ops *bpf_sops)
{
  struct llb_sockmap_portset_val *pv;
  struct llb_sockmap_key key = { .dip = bpf_sops->remote_ip4,
                                 .sip = bpf_sops->local_ip4,
                                 .dport = bpf_sops->remote_port >> 16,
                                 .sport = bpf_htonl(bpf_sops->local_port) >> 16,
                               };

  switch (bpf_sops->op) {
  case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
    /* accepted by a proxy listener: local address and port are the VIP */
    pv = sockmap_vip_portset_lookup(key.sip, (__u16)key.sport);
    break;
  case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
    /* connected by the proxy: remote address and port are the endpoint */
    pv = sockmap_ep_portset_lookup(key.dip, (__u16)key.dport);
    break;
  default:
    return 0;
  }

  if (!pv) {
    return 0;
  }

  bpf_sock_hash_update(bpf_sops, &sock_proxy_map, &key, BPF_NOEXIST);

  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
