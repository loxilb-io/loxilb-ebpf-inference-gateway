/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2026 LoxiLB Authors
 *
 * sockproxy_hdr_deadline_test.c — the header-completion deadline resolution.
 *
 * Includes ONLY the pure header, so it runs without the proxy object graph:
 *
 *   T1  a configured value is enforced as given.
 *   T2  0 resolves to the product default — it does NOT disable the
 *       deadline. A listener with no deadline is a slowloris target, and
 *       the comment that once promised "0 = disabled" described a switch
 *       the code never had.
 *   T3  the default is the documented 10 s.
 *
 * Build: $(CC) -Wall -Wextra -o test_hdr_deadline sockproxy_hdr_deadline_test.c -I.
 * Run:   ./test_hdr_deadline
 */
#include <stdio.h>

#include "sockproxy_hdr_deadline.h"

static int g_failures = 0;

#define CHECK(cond, msg) do {                                          \
    if (cond) {                                                        \
      printf("  [PASS] %s\n", (msg));                                  \
    } else {                                                           \
      printf("  [FAIL] %s  (%s:%d)\n", (msg), __FILE__, __LINE__);     \
      g_failures++;                                                    \
    }                                                                  \
  } while (0)

int
main(void)
{
  printf("T1 configured value is used as given\n");
  CHECK(sp_hdr_deadline_resolve_ms(1) == 1, "1 ms stays 1 ms");
  CHECK(sp_hdr_deadline_resolve_ms(2500) == 2500, "2500 ms stays 2500 ms");
  CHECK(sp_hdr_deadline_resolve_ms(0xFFFFFFFFu) == 0xFFFFFFFFu,
        "the largest value stays as given");

  printf("T2 zero resolves to the default, never to 'off'\n");
  CHECK(sp_hdr_deadline_resolve_ms(0) != 0,
        "0 does not disable the deadline");
  CHECK(sp_hdr_deadline_resolve_ms(0) == L7_TCP_INSPECT_DEFAULT_MS,
        "0 resolves to L7_TCP_INSPECT_DEFAULT_MS");

  printf("T3 the default is the documented value\n");
  CHECK(L7_TCP_INSPECT_DEFAULT_MS == 10000, "default is 10000 ms");

  if (g_failures) {
    printf("FAIL: %d check(s) failed\n", g_failures);
    return 1;
  }
  puts("PASS: header-completion deadline resolves 0 to the default, never to off");
  return 0;
}
