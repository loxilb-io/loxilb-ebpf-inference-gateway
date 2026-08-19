/* sockproxy_pd_core.c - machine-agnostic P/D dialect core
 *
 * Target home (as extraction proceeds) for the dispatch-site glue, retry-pend
 * collection, reaper walk, pd counters, JSON splice + Content-Length fixup and
 * the [PD_DECISION]/frame-mismatch instruments shared by every dialect.
 * Skeleton for now: dialect resolution only — the machines still live in
 * sockproxy_http.c behind the ops table.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>
#include <time.h>

#include "uthash.h"
#include "log.h"
#include "sockproxy.h"
#include "sockproxy_pd.h"

/* Wire kv_engine_type → PD_ENGINE_*. Values are equal by construction for
 * the engines the control plane emits today; unknown/future values degrade
 * to the sequential vLLM flavor (the machine with no injection prerequisite)
 * rather than to a dialect whose contract the peer engine cannot speak. */
uint8_t
pd_engine_from_kv_engine_type(uint8_t kv_engine_type)
{
  switch (kv_engine_type) {
  case PD_ENGINE_SGLANG:
    return PD_ENGINE_SGLANG;
  case PD_ENGINE_TRTLLM:
    return PD_ENGINE_TRTLLM;
  case PD_ENGINE_VLLM:
  default:
    return PD_ENGINE_VLLM;
  }
}

const pd_dialect_ops_t *
pd_dialect_resolve(uint8_t pd_engine)
{
  switch (pd_engine) {
  case PD_ENGINE_SGLANG:
    return &pd_dialect_sglang;
  case PD_ENGINE_TRTLLM:
    /* Sequential ctx-first disaggregation — rides the vLLM machine until a
     * dedicated sockproxy_pd_trtllm.c table earns its place. */
    return &pd_dialect_vllm;
  case PD_ENGINE_VLLM:
  default:
    return &pd_dialect_vllm;
  }
}
