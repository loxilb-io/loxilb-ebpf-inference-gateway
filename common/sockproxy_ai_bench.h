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
 * Producer-cost harness for the audit trail.
 *
 * The cost that matters is the one the relay worker pays to record a
 * request: the C call, the CGO crossing and the producer's hand-off,
 * measured from the C side with the same clock the workers use. A Go-side
 * benchmark proves only the Go half, so this harness runs a worker-shaped
 * thread of its own that calls the real entry point in a tight loop and
 * reports the distribution.
 *
 * It times llb_ai_audit_emit_only rather than llb_ai_record_request,
 * because the completion export also feeds the Prometheus counters and that
 * work is not the trail's. Timing the export and subtracting an arm with no
 * trail behind it does not separate the two: a difference of medians is not
 * the median of differences, and at the tail the subtraction is of Go
 * garbage collection and scheduler noise that is there either way.
 *
 * The thread carries a worker identity so the trail attributes every record
 * to a producer, exactly as a relay worker would.
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

/*
 * llb_ai_audit_emit_only - write a completed request to the audit trail and
 * nothing else.
 *
 * It takes the arguments of llb_ai_record_request and does the half of it
 * that records: no counters are raised. There is one caller, the harness
 * above, and no reason for another - the datapath wants both halves and
 * calls llb_ai_record_request. It is declared here, beside the harness that
 * needs it, so it is not mistaken for a way to record a request.
 */
extern void llb_ai_audit_emit_only(char *tenant_id, char *model_name, int status_code,
                                   int64_t latency_ms, int prompt_tokens, int complet_tokens,
                                   char *error_code, char *request_id, char *user_id,
                                   char *key_id, char *svc_ident, int is_stream,
                                   int producer_id);

#endif /* __SOCKPROXY_AI_BENCH_H__ */
