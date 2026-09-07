/* SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) */
#include <assert.h>
#include <stdio.h>

#include "llb_kern_unparse_gate.h"

#define PIPE_PASS 0x01u
#define PIPE_TRAP 0x02u
#define PIPE_RDR  0x04u
#define PASS_TRAP_MASK (PIPE_PASS | PIPE_TRAP)

int
main(void)
{
  assert(dp_unparse_needs_early_snat(0, PIPE_PASS, PASS_TRAP_MASK, 0));
  assert(dp_unparse_needs_early_snat(0, PIPE_TRAP, PASS_TRAP_MASK, 0));

  assert(!dp_unparse_needs_early_snat(0, PIPE_RDR, PASS_TRAP_MASK, 0));
  assert(!dp_unparse_needs_early_snat(0, PIPE_PASS, PASS_TRAP_MASK, 1));
  assert(!dp_unparse_needs_early_snat(0, PIPE_TRAP, PASS_TRAP_MASK, 1));
  assert(!dp_unparse_needs_early_snat(0, 0, PASS_TRAP_MASK, 0));

  assert(dp_unparse_needs_early_snat(42, PIPE_RDR, PASS_TRAP_MASK, 0));
  assert(dp_unparse_needs_early_snat(42, PIPE_PASS, PASS_TRAP_MASK, 1));

  puts("ALL PASS (8/8)");
  return 0;
}
