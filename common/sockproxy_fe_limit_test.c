/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2026 LoxiLB Authors
 *
 * sockproxy_fe_limit_test.c — the per-listener client-connection ceiling
 * (connectionLimit on a fullproxy rule, enforced at accept).
 *
 * Includes ONLY the pure header, so it runs without the proxy object graph:
 *
 *   T1  limit 0 is unlimited: nothing is taken, nothing is counted.
 *   T2  exactly `limit` units are granted, the (limit+1)th is refused with
 *       the gauge untouched and the refusal counted.
 *   T3  a release frees one slot; the next take succeeds again.
 *   T4  a release on an empty gauge is a no-op (no wrap to 2^32-1, which
 *       would refuse every connection for the listener's lifetime).
 *   T5  the refusal count is monotonic and reported per refusal.
 *   T6  concurrent takes under a ceiling never exceed it (fetch_add, not
 *       load-compare-store).
 *
 * Build: $(CC) -Wall -Wextra -pthread -o test_fe_limit sockproxy_fe_limit_test.c -I.
 * Run:   ./test_fe_limit
 */
#include <stdio.h>
#include <pthread.h>

#include "sockproxy_fe_limit.h"

static int g_failures = 0;

#define CHECK(cond, msg) do {                                          \
    if (cond) {                                                        \
      printf("  [PASS] %s\n", (msg));                                  \
    } else {                                                           \
      printf("  [FAIL] %s  (%s:%d)\n", (msg), __FILE__, __LINE__);     \
      g_failures++;                                                    \
    }                                                                  \
  } while (0)

static void
t1_unlimited(void)
{
  _Atomic uint32_t conns = 0;
  _Atomic uint64_t refused = 0;
  uint64_t n = 99;

  printf("T1 limit 0 is unlimited\n");
  for (int i = 0; i < 1000; i++) {
    if (fe_limit_take(&conns, 0, &refused, &n) != FE_LIMIT_UNLIMITED) g_failures++;
  }
  CHECK(atomic_load(&conns) == 0, "gauge untouched with no ceiling");
  CHECK(atomic_load(&refused) == 0, "nothing refused with no ceiling");
  CHECK(n == 99, "refused_total not written with no ceiling");
}

static void
t2_ceiling(void)
{
  _Atomic uint32_t conns = 0;
  _Atomic uint64_t refused = 0;
  uint64_t n = 0;
  int taken = 0;

  printf("T2 exactly limit units, then refusal\n");
  for (int i = 0; i < 3; i++) {
    if (fe_limit_take(&conns, 3, &refused, &n) == FE_LIMIT_TAKEN) taken++;
  }
  CHECK(taken == 3, "limit=3 grants three units");
  CHECK(atomic_load(&conns) == 3, "gauge == 3");
  CHECK(fe_limit_take(&conns, 3, &refused, &n) == FE_LIMIT_REFUSED, "fourth is refused");
  CHECK(atomic_load(&conns) == 3, "refusal leaves the gauge at 3");
  CHECK(atomic_load(&refused) == 1 && n == 1, "refusal counted once and reported");
}

static void
t3_release_frees_slot(void)
{
  _Atomic uint32_t conns = 0;
  _Atomic uint64_t refused = 0;

  printf("T3 release frees a slot\n");
  fe_limit_take(&conns, 1, &refused, NULL);
  CHECK(fe_limit_take(&conns, 1, &refused, NULL) == FE_LIMIT_REFUSED, "second refused at limit 1");
  fe_limit_release(&conns);
  CHECK(atomic_load(&conns) == 0, "release -> 0");
  CHECK(fe_limit_take(&conns, 1, &refused, NULL) == FE_LIMIT_TAKEN, "taken again after release");
}

static void
t4_release_on_empty(void)
{
  _Atomic uint32_t conns = 0;
  _Atomic uint64_t refused = 0;

  printf("T4 release on an empty gauge\n");
  fe_limit_release(&conns);
  fe_limit_release(&conns);
  CHECK(atomic_load(&conns) == 0, "stays at 0, never wraps");
  CHECK(fe_limit_take(&conns, 1, &refused, NULL) == FE_LIMIT_TAKEN, "still accepts");
}

static void
t5_refused_monotonic(void)
{
  _Atomic uint32_t conns = 0;
  _Atomic uint64_t refused = 0;
  uint64_t n = 0, last = 0;
  int ok = 1;

  printf("T5 refusal count is monotonic\n");
  fe_limit_take(&conns, 1, &refused, NULL);
  for (int i = 1; i <= 50; i++) {
    fe_limit_take(&conns, 1, &refused, &n);
    if (n != last + 1) ok = 0;
    last = n;
  }
  CHECK(ok && last == 50, "50 refusals reported 1..50");
}

struct t6_arg {
  _Atomic uint32_t *conns;
  _Atomic uint64_t *refused;
  uint32_t limit;
  int rounds;
  int taken;
};

static void *
t6_worker(void *p)
{
  struct t6_arg *a = p;
  for (int i = 0; i < a->rounds; i++) {
    if (fe_limit_take(a->conns, a->limit, a->refused, NULL) == FE_LIMIT_TAKEN)
      a->taken++;
  }
  return NULL;
}

static void
t6_concurrent(void)
{
  _Atomic uint32_t conns = 0;
  _Atomic uint64_t refused = 0;
  pthread_t th[8];
  struct t6_arg args[8];
  int total = 0;

  printf("T6 concurrent takes never exceed the ceiling\n");
  for (int i = 0; i < 8; i++) {
    args[i] = (struct t6_arg){ &conns, &refused, 100, 10000, 0 };
    pthread_create(&th[i], NULL, t6_worker, &args[i]);
  }
  for (int i = 0; i < 8; i++) {
    pthread_join(th[i], NULL);
    total += args[i].taken;
  }
  CHECK(total == 100, "exactly limit units granted across 8 shards");
  CHECK(atomic_load(&conns) == 100, "gauge == limit");
  CHECK(atomic_load(&refused) == 8 * 10000 - 100, "every other attempt counted as refused");
}

int
main(void)
{
  t1_unlimited();
  t2_ceiling();
  t3_release_frees_slot();
  t4_release_on_empty();
  t5_refused_monotonic();
  t6_concurrent();
  if (g_failures) {
    printf("FAILED: %d check(s)\n", g_failures);
    return 1;
  }
  printf("ALL PASS\n");
  return 0;
}
