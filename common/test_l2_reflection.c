/* SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) */
#include <assert.h>
#include <stdio.h>
#include "llb_l2_reflection.h"

int main(void)
{
    /* Exhaust the exemption combinations for untagged and tagged traffic. */
    for (unsigned int vlan = 0; vlan <= 4095; vlan++) {
        for (int local = 0; local < 2; local++)
            for (int nat = 0; nat < 2; nat++)
                for (int tunnel = 0; tunnel < 2; tunnel++) {
                    int unchanged = !local && !nat && !tunnel;
                    assert(llb_l2_is_reflection(1, 1, vlan, vlan,
                                               local, nat, tunnel) == unchanged);
                    assert(!llb_l2_is_reflection(1, 2, vlan, vlan,
                                                local, nat, tunnel));
                    assert(!llb_l2_is_reflection(1, 1, vlan, vlan ^ 1,
                                                local, nat, tunnel));
                }
    }
    puts("L2 split-horizon and routing/NAT/tunnel/VLAN exemptions: PASS");
    return 0;
}
