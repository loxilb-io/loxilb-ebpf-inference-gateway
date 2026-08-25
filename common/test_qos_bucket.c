/*
 * SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-Clause)
 * Copyright (c) 2026 NetLOX Inc
 *
 * test_qos_bucket.c - standalone unit tests for the Tier-1 shaper bucket
 * primitives (sockproxy_qos.h). Covers grant/credit/refill arithmetic, the
 * min-grant park threshold, the refill clamp, and a multi-threaded
 * conservation check: concurrent takers + refiller must never mint tokens.
 *
 * Build/run: make test_qos (see Makefile)
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>

#include "sockproxy_qos.h"

static int n_pass;

#define CHECK(cond) do {                                                  \
  if (!(cond)) {                                                          \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);       \
    exit(1);                                                              \
  }                                                                       \
  n_pass++;                                                               \
} while (0)

static void
test_cbs_derivation(void)
{
  struct proxy_qos_cfg cfg = { 0 };

  cfg.cir_Bps = 10 * 1000 * 1000;       /* 10 MB/s */
  cfg.cbs_bytes = 0;
  CHECK(qos_effective_cbs(&cfg) == 1000 * 1000);   /* 100ms of CIR */

  cfg.cir_Bps = 1000;                   /* tiny rate: floor applies */
  CHECK(qos_effective_cbs(&cfg) == QOS_CBS_MIN_BYTES);

  cfg.cbs_bytes = 4096;                 /* explicit wins */
  CHECK(qos_effective_cbs(&cfg) == 4096);
}

static void
test_take_grant_shapes(void)
{
  struct proxy_qos_cfg cfg = { .cir_Bps = 1000 * 1000, .cbs_bytes = 100000 };
  struct proxy_qos_bucket b;

  memset(&b, 0, sizeof(b));
  qos_bucket_init(&b, &cfg, 0);
  CHECK(atomic_load(&b.tokens) == 100000);

  /* full grant */
  CHECK(qos_bucket_take(&b, 60000) == 60000);
  CHECK(atomic_load(&b.tokens) == 40000);

  /* partial grant >= QOS_MIN_GRANT is honoured */
  CHECK(qos_bucket_take(&b, 60000) == 40000);
  CHECK(atomic_load(&b.tokens) == 0);

  /* empty bucket refuses */
  CHECK(qos_bucket_take(&b, 1) == 0);

  /* tiny partial below MIN_GRANT is refused (caller parks) ... */
  atomic_store(&b.tokens, QOS_MIN_GRANT - 1);
  CHECK(qos_bucket_take(&b, 1000000) == 0);
  CHECK(atomic_load(&b.tokens) == QOS_MIN_GRANT - 1);

  /* ... but a small grant satisfying the FULL want passes (end of buffer) */
  CHECK(qos_bucket_take(&b, 100) == 100);

  /* zero want is a no-op */
  CHECK(qos_bucket_take(&b, 0) == 0);
}

static void
test_credit(void)
{
  struct proxy_qos_cfg cfg = { .cir_Bps = 1000 * 1000, .cbs_bytes = 50000 };
  struct proxy_qos_bucket b;

  memset(&b, 0, sizeof(b));
  qos_bucket_init(&b, &cfg, 0);

  CHECK(qos_bucket_take(&b, 50000) == 50000);
  qos_bucket_credit(&b, 20000);          /* short read: 30000 consumed */
  CHECK(atomic_load(&b.tokens) == 20000);
}

static void
test_refill(void)
{
  struct proxy_qos_cfg cfg = { .cir_Bps = 1000 * 1000, .cbs_bytes = 100000 };
  struct proxy_qos_bucket b;
  uint64_t t0 = 1000000000ULL;

  memset(&b, 0, sizeof(b));
  qos_bucket_init(&b, &cfg, t0);
  atomic_store(&b.tokens, 0);

  /* sub-1ms elapsed: refused */
  CHECK(qos_bucket_refill(&b, cfg.cir_Bps, cfg.cbs_bytes, t0 + 500000) == 0);
  CHECK(atomic_load(&b.tokens) == 0);

  /* 10ms at 1 MB/s => 10000 bytes */
  CHECK(qos_bucket_refill(&b, cfg.cir_Bps, cfg.cbs_bytes, t0 + 10000000) == 1);
  CHECK(atomic_load(&b.tokens) == 10000);

  /* same timestamp again: elapsed 0, no double refill */
  CHECK(qos_bucket_refill(&b, cfg.cir_Bps, cfg.cbs_bytes, t0 + 10000000) == 0);
  CHECK(atomic_load(&b.tokens) == 10000);

  /* long idle refills to cbs, never beyond */
  CHECK(qos_bucket_refill(&b, cfg.cir_Bps, cfg.cbs_bytes,
                          t0 + 10000000 + 3600ULL * 1000000000ULL) == 1);
  CHECK(atomic_load(&b.tokens) == 100000);
}

/* --- conservation under concurrency ------------------------------------- */

#define HAMMER_THREADS 4
#define HAMMER_ITERS   200000

struct hammer_arg {
  struct proxy_qos_bucket *b;
  uint64_t taken;
};

static void *
hammer_taker(void *p)
{
  struct hammer_arg *a = p;
  for (int i = 0; i < HAMMER_ITERS; i++) {
    uint64_t g = qos_bucket_take(a->b, (uint64_t)(i % 8192) + 1);
    a->taken += g;
    if ((i & 0xff) == 0 && g) {
      /* occasional short-read credit of half the grant */
      qos_bucket_credit(a->b, g / 2);
      a->taken -= g / 2;
    }
  }
  return NULL;
}

static void
test_conservation(void)
{
  struct proxy_qos_cfg cfg = { .cir_Bps = 100 * 1000 * 1000, .cbs_bytes = 1000000 };
  struct proxy_qos_bucket b;
  struct hammer_arg args[HAMMER_THREADS];
  pthread_t thr[HAMMER_THREADS];
  uint64_t now = 1;
  uint64_t refilled = 0;

  memset(&b, 0, sizeof(b));
  qos_bucket_init(&b, &cfg, now);

  for (int i = 0; i < HAMMER_THREADS; i++) {
    args[i].b = &b;
    args[i].taken = 0;
    pthread_create(&thr[i], NULL, hammer_taker, &args[i]);
  }

  /* refiller: 2ms steps at 100 MB/s => 200000 bytes per refill */
  for (int i = 0; i < 200; i++) {
    uint64_t before = (uint64_t)atomic_load(&b.tokens);
    now += 2000000ULL;
    if (qos_bucket_refill(&b, cfg.cir_Bps, cfg.cbs_bytes, now)) {
      uint64_t after = (uint64_t)atomic_load(&b.tokens);
      /* upper bound on what this refill can have added (takers ran too, so
       * the true add is <= nominal; the clamp can only shrink) */
      (void)before; (void)after;
      refilled += (cfg.cir_Bps * 2000000ULL) / 1000000000ULL;
    }
  }

  uint64_t total_taken = 0;
  for (int i = 0; i < HAMMER_THREADS; i++) {
    pthread_join(thr[i], NULL);
    total_taken += args[i].taken;
  }

  /* conservation: net grants can never exceed initial burst + all refills */
  CHECK(total_taken <= (uint64_t)cfg.cbs_bytes + refilled);
  /* and the bucket can never end negative below a full outstanding credit */
  CHECK(atomic_load(&b.tokens) >= 0);

  printf("  conservation: taken=%llu budget=%llu\n",
         (unsigned long long)total_taken,
         (unsigned long long)(cfg.cbs_bytes + refilled));
}

int
main(void)
{
  test_cbs_derivation();
  test_take_grant_shapes();
  test_credit();
  test_refill();
  test_conservation();
  printf("test_qos_bucket: %d checks passed\n", n_pass);
  return 0;
}
