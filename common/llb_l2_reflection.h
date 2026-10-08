/* SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) */
#ifndef LLB_L2_REFLECTION_H
#define LLB_L2_REFLECTION_H

/* Split horizon for unchanged L2 forwarding. Deliberate routing, NAT,
 * tunnel and VLAN transformations may legitimately use the ingress port. */
static inline int
llb_l2_is_reflection(unsigned int ingress, unsigned int egress,
                     unsigned int ingress_vlan, unsigned int egress_vlan,
                     int local_l3, int rewritten_l3, int tunnel)
{
    return ingress == egress && ingress_vlan == egress_vlan &&
           !local_l3 && !rewritten_l3 && !tunnel;
}
#endif
