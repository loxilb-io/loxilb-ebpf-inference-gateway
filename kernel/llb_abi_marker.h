/* SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) */
#ifndef LLB_ABI_MARKER_H
#define LLB_ABI_MARKER_H
#include "llb_abi_fingerprint.generated.h"
/* A separate read-only data section has exactly one value: no BTF offset or
 * untrusted kernel-sized copy is needed to read the fingerprint. */
const volatile char llb_abi_fingerprint[]
  __attribute__((section(".rodata.llbabi"), used)) = LLB_ABI_FINGERPRINT;
#endif
