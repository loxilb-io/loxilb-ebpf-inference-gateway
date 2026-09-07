/* SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) */
#ifndef __LLB_KERN_UNPARSE_GATE_H__
#define __LLB_KERN_UNPARSE_GATE_H__

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

/*
 * Source NAT is normally deferred to dp_unparse_packet() after the forwarding
 * decision. An ingress PASS/TRAP verdict returns before that function, while
 * an egress PASS still calls it and must not be rewritten twice. Tunnel
 * insertion remains an unconditional early-SNAT case.
 */
static __always_inline int
dp_unparse_needs_early_snat(unsigned int new_tunnel_id,
                            unsigned int pipe_act,
                            unsigned int pass_trap_mask,
                            int is_egr)
{
  return new_tunnel_id != 0 || (!is_egr && (pipe_act & pass_trap_mask));
}

#endif /* __LLB_KERN_UNPARSE_GATE_H__ */
