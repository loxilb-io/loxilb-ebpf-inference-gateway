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

#ifndef __SOCKPROXY_AI_BENCH_H__
#define __SOCKPROXY_AI_BENCH_H__

#include <stdint.h>

/*
 * Producer-cost harness for the completion export.
 *
 * The cost that matters is the one the relay worker pays: the C call into
 * llb_ai_record_request including the CGO crossing, measured from the C
 * side with the same clock the workers use. A Go-side benchmark proves only
 * the Go half, so this harness runs a worker-shaped thread of its own that
 * calls the real export in a tight loop and reports the distribution.
 *
 * The thread carries a worker identity so the export attributes every
 * record to a producer, exactly as a relay worker would.
 */
typedef struct llb_sp_audit_bench {
  uint64_t iters;      /* calls timed */
  double   p50_ns;
  double   p95_ns;
  double   p99_ns;
  double   max_ns;
} llb_sp_audit_bench_t;

/* Run iters calls on a fresh thread and fill out. Returns 0, or -errno when
 * the thread or the sample buffer could not be created. */
int llb_sp_audit_bench(uint64_t iters, llb_sp_audit_bench_t *out);

#endif /* __SOCKPROXY_AI_BENCH_H__ */
