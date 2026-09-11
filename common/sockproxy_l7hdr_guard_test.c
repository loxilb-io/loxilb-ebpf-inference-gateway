/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2024-2025 LoxiLB Authors
 *
 * sockproxy_l7hdr_guard_test.c — the field guard that stands between a header
 * value and the wire.
 *
 * Includes ONLY the pure header, so it runs without the proxy object graph:
 *
 *   T1  an ordinary field passes (the control -- a guard that refuses
 *       everything would pass every refusal case below and be useless).
 *   T2  CR, LF and CRLF anywhere in a VALUE are refused. This is the
 *       header-injection class: on H1 the receiver reads what follows the
 *       break as a header line of its own, and X-Auth-User is exactly the
 *       field a backend reads to decide who is calling.
 *   T3  the same breaks in a NAME are refused.
 *   T4  an empty or absent name is refused (": value" is a line no parser
 *       agrees on), and a NULL value is refused rather than dereferenced.
 *   T5  an empty value is ALLOWED -- "X-H: \r\n" is a legal header line, and
 *       refusing it would be the guard overreaching into policy.
 *
 * Build: $(CC) -Wall -Wextra -o test_l7hdr_guard sockproxy_l7hdr_guard_test.c -I.
 * Run:   ./test_l7hdr_guard
 */
#include <stdio.h>
#include <string.h>

#include "sockproxy_l7hdr_guard.h"

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
  printf("=== T1: an ordinary field passes (control) ===\n");
  CHECK(l7_hdr_pair_unsafe("X-Auth-User", "alice") == 0,
        "a plain name and value are accepted");
  CHECK(l7_hdr_pair_unsafe("X-Auth-Tenant", "tenant-a/team.7_x") == 0,
        "punctuation that is not a line break is accepted");
  CHECK(l7_hdr_field_has_break("alice") == 0,
        "the predicate itself reports a clean field as clean");

  printf("=== T2: a line break in the VALUE is refused ===\n");
  CHECK(l7_hdr_pair_unsafe("X-Auth-User", "alice\r\nX-Auth-Tenant: admin") != 0,
        "CRLF splicing a second header is refused");
  CHECK(l7_hdr_pair_unsafe("X-Auth-User", "alice\rX") != 0,
        "a bare CR is refused");
  CHECK(l7_hdr_pair_unsafe("X-Auth-User", "alice\nX") != 0,
        "a bare LF is refused");
  CHECK(l7_hdr_pair_unsafe("X-Auth-User", "\r\nX-Auth-Tenant: admin") != 0,
        "a break at the very start is refused");
  CHECK(l7_hdr_pair_unsafe("X-Auth-User", "alice\r\n") != 0,
        "a trailing break -- which would end the field early -- is refused");

  printf("=== T3: a line break in the NAME is refused ===\n");
  CHECK(l7_hdr_pair_unsafe("X-Auth\r\nEvil", "v") != 0,
        "CRLF in the name is refused");
  CHECK(l7_hdr_pair_unsafe("X-Auth\nEvil", "v") != 0,
        "LF in the name is refused");

  printf("=== T4: a field that cannot be written at all is refused ===\n");
  CHECK(l7_hdr_pair_unsafe("", "v") != 0,
        "an empty name is refused (': v' is not a header line)");
  CHECK(l7_hdr_pair_unsafe(NULL, "v") != 0,
        "a NULL name is refused, not dereferenced");
  CHECK(l7_hdr_pair_unsafe("X-H", NULL) != 0,
        "a NULL value is refused, not dereferenced");
  CHECK(l7_hdr_field_has_break(NULL) != 0,
        "the predicate treats an absent field as unsafe");

  printf("=== T5: an empty value stays legal ===\n");
  CHECK(l7_hdr_pair_unsafe("X-H", "") == 0,
        "an empty value is accepted ('X-H: ' is a legal line)");

  printf("\n%s: %d failure(s)\n",
         g_failures ? "FAILED" : "PASSED", g_failures);
  return g_failures ? 1 : 0;
}
