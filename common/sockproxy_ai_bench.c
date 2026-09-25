/*
 * Copyright (c) 2026 LoxiLB Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sockproxy_ai_gw.h"
#include "sockproxy_ai_bench.h"

/* The worker identity the relay threads carry (notify.c). The bench thread
 * takes worker 0 so the export attributes its records as a worker's. */
extern __thread int sp_worker_id;

typedef struct {
  uint64_t  iters;
  uint64_t *samples;
  int       rc;
} bench_arg_t;

static uint64_t
now_ns(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int
cmp_u64(const void *a, const void *b)
{
  uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
  return x < y ? -1 : x > y;
}

static void *
bench_thread(void *arg)
{
  bench_arg_t *b = arg;
  char tenant[] = "bench-tenant";
  char model[] = "bench-model";
  char request_id[32 + 1];
  char user[] = "bench-user";
  char key[] = "bench-key";
  char svc[] = "10.0.0.1:2040";
  char none[] = "";

  sp_worker_id = 0;
  memset(request_id, 'a', sizeof(request_id) - 1);
  request_id[sizeof(request_id) - 1] = '\0';

  for (uint64_t i = 0; i < b->iters; i++) {
    uint64_t t0 = now_ns();
    llb_ai_audit_emit_only(tenant, model, 200, 12, 40, 8, none,
                           request_id, user, key, svc, 0, sp_worker_id);
    b->samples[i] = now_ns() - t0;
  }
  return NULL;
}

int
llb_sp_audit_bench(uint64_t iters, llb_sp_audit_bench_t *out)
{
  bench_arg_t b;
  pthread_t tid;
  int rc;

  if (!out || iters == 0)
    return -EINVAL;
  memset(out, 0, sizeof(*out));
  b.iters = iters;
  b.rc = 0;
  b.samples = calloc(iters, sizeof(*b.samples));
  if (!b.samples)
    return -ENOMEM;

  rc = pthread_create(&tid, NULL, bench_thread, &b);
  if (rc != 0) {
    free(b.samples);
    return -rc;
  }
  pthread_join(tid, NULL);

  qsort(b.samples, iters, sizeof(*b.samples), cmp_u64);
  out->iters = iters;
  out->p50_ns = (double)b.samples[(iters * 50) / 100];
  out->p95_ns = (double)b.samples[(iters * 95) / 100 >= iters ? iters - 1 : (iters * 95) / 100];
  out->p99_ns = (double)b.samples[(iters * 99) / 100 >= iters ? iters - 1 : (iters * 99) / 100];
  out->max_ns = (double)b.samples[iters - 1];
  free(b.samples);
  return 0;
}
