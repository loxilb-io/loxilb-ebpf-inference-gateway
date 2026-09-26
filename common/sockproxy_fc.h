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
#ifndef __SOCKPROXY_FC_H__
#define __SOCKPROXY_FC_H__

#include <stdint.h>
#include <stdatomic.h>

/*
 * Capacity admission for AI inference requests: the one place every request
 * path (HTTP/1 buffered, HTTP/1 streamed, HTTP/1 on a kept backend leg,
 * HTTP/2 stream, prefill/decode legs) takes a permit before its first
 * backend byte, and the one place that permit is handed back.
 *
 * Units. A permit holds at most one SERVICE unit (the request or stream
 * itself, counted once however many legs it opens) and at most one
 * ENDPOINT unit per role: normal, prefill, decode. A P/D request therefore
 * holds one service unit and two endpoint units; the service count never
 * doubles for it.
 *
 * Ceilings are compare-and-swap reservations. A load snapshot followed by an
 * unrelated increment is not a bound, so no selector's "least loaded" is
 * trusted: the CAS here is the last word, and a selector's pick that turns
 * out to be over its cap is moved to another eligible endpoint or refused.
 *
 * Modes. `off` takes no atomics at all and the dispatch path is byte for
 * byte what it was. `observe` counts every decision the gate would have
 * taken and admits everything. `enforce` refuses. Zero ceilings mean
 * unlimited at that level; the counters still move so the gauges are true.
 *
 * Release is idempotent: the response-complete site, the keep-alive
 * boundary and the single teardown owner may each call it for the same
 * permit, and only the first one moves a counter. A counter that would go
 * below zero is left at zero and counted as an anomaly: that, not a second
 * release call, is the signal of a unit released that was never taken.
 *
 * This header pulls in nothing from the proxy so the module and its unit
 * test build alone. FC_MAX_EP mirrors MAX_PROXY_EP and is asserted equal
 * where both are visible.
 */

#define FC_MAX_EP 32

enum fc_role {
  FC_ROLE_NORMAL = 0,
  FC_ROLE_PREFILL = 1,
  FC_ROLE_DECODE = 2,
  FC_ROLES = 3,
};

enum fc_mode {
  FC_MODE_OFF = 0,
  FC_MODE_OBSERVE = 1,
  FC_MODE_ENFORCE = 2,
};

typedef struct fc_cfg {
  uint8_t  mode;                 /* enum fc_mode */
  uint32_t max_outstanding;      /* service ceiling on executing units; 0 = unlimited */
  uint32_t ep_cap[FC_ROLES];     /* per-endpoint ceiling per role; 0 = unlimited */
} fc_cfg_t;

/* What the gate decided, one counter each. The names are the wire values of
 * the decisions metric; they are spelled here once. */
enum fc_reason {
  FC_R_ADMITTED = 0,
  FC_R_CAPACITY_SHED,            /* service or endpoint ceiling, enforce */
  FC_R_NO_HEALTHY_CAPACITY,      /* no eligible endpoint at all */
  FC_R_OBSERVE_WOULD_SHED,       /* over a ceiling in observe mode, admitted */
  FC_R_BYPASS_NON_INFERENCE,     /* not an inference request: no capacity unit */
  FC_R_COUNT,
};

enum fc_anomaly {
  FC_A_UNDERFLOW = 0,            /* a release found its counter at zero */
  FC_A_UNKNOWN_PERMIT,           /* an executing permit with no service */
  FC_A_COUNT,
};

/* Per-service (per model pool) admission state. Zero-initialised memory is a
 * valid `off` state, which is what a pool that predates this module looks
 * like; fc_state_init applies the configuration. */
typedef struct fc_state {
  fc_cfg_t cfg;
  _Atomic uint32_t inflight;
  _Atomic uint32_t ep_inflight[FC_MAX_EP][FC_ROLES];
  _Atomic uint64_t decisions[FC_R_COUNT];
} fc_state_t;

enum fc_permit_state {
  FC_P_NONE = 0,                 /* nothing taken */
  FC_P_BYPASS,                   /* gate off or non-inference: nothing to release */
  FC_P_EXECUTING,                /* units held */
  FC_P_RELEASED,                 /* units handed back */
};

typedef struct fc_permit {
  fc_state_t *fc;                /* the service the units were taken from */
  uint8_t state;                 /* enum fc_permit_state */
  uint8_t svc_held;
  int8_t  ep[FC_ROLES];          /* endpoint holding this role's unit, -1 = none */
} fc_permit_t;

typedef enum fc_verdict {
  FC_ADMIT = 0,
  FC_SHED = 1,                   /* over a ceiling: 429 admission_capacity */
  FC_NO_CAPACITY = 2,            /* no eligible endpoint: 503 admission_no_capacity */
} fc_verdict_t;

extern _Atomic uint64_t fc_anomaly_total[FC_A_COUNT];

/* Environment defaults. Rule fields arrive in a later change; until then the
 * process-wide values are the configuration of every pool. */
void fc_cfg_from_env(fc_cfg_t *cfg);
void fc_state_init(fc_state_t *fc);
void fc_state_apply(fc_state_t *fc, const fc_cfg_t *cfg);

static inline int
fc_active(const fc_state_t *fc)
{
  return fc != NULL && fc->cfg.mode != FC_MODE_OFF;
}

void fc_permit_init(fc_permit_t *p);

/* Capacity permits apply to inference requests only: a POST on one of the
 * inference paths. Everything else on an AI service (model listings, health
 * probes, preflight) bypasses capacity, never policy, and is counted under
 * its own reason so an operator can see what the gate let past. The query
 * string is ignored. */
int fc_is_inference_request(int is_post, const char *path);

/* Take the service unit. Returns FC_ADMIT with the permit EXECUTING (or
 * BYPASS when the gate is off), FC_SHED with the permit untouched. Not yet
 * counted as admitted: the endpoint unit is the decision, and the first
 * endpoint unit that lands on the permit counts it, once per request. */
fc_verdict_t fc_service_acquire(fc_state_t *fc, fc_permit_t *p);

/* The same, for a request that is not an inference request. */
void fc_bypass(fc_state_t *fc, fc_permit_t *p);

/* True when the endpoint is at or over its ceiling for the role. A read,
 * for selectors that want to skip capped endpoints early; the CAS in
 * fc_ep_acquire is still the last word. */
int fc_ep_over_cap(const fc_state_t *fc, int ep, int role);

/* Take one endpoint unit for the role. FC_SHED leaves the permit as it was. */
fc_verdict_t fc_ep_acquire(fc_state_t *fc, fc_permit_t *p, int ep, int role);

/* Take one endpoint unit for the role on the preferred endpoint, or on the
 * first eligible endpoint with room when the preferred one is over its cap
 * (bounded to one pass over n_eps). Returns the endpoint taken, or -1 with
 * *verdict set to FC_SHED (eligible endpoints exist, all over cap) or
 * FC_NO_CAPACITY (no eligible endpoint). `eligible` answers health, role and
 * drain state for the caller's pool. */
typedef int (*fc_eligible_fn)(void *ctx, int ep);
int fc_ep_acquire_any(fc_state_t *fc, fc_permit_t *p, int role, int preferred,
                      int n_eps, fc_eligible_fn eligible, void *ctx,
                      fc_verdict_t *verdict);

/* Move the role's unit to another endpoint (a leg re-selected after a dead
 * backend): the new endpoint's unit is taken first, under its cap, and the
 * old one released after. Returns 0, or -1 with nothing changed when the
 * new endpoint has no room, so a retry can never over-admit. */
int fc_permit_move(fc_permit_t *p, int role, int new_ep);

/* Hand back one role's endpoint unit (a leg that ended on its own). */
void fc_release_role(fc_permit_t *p, int role);

/* Hand back everything the permit holds. Idempotent. */
void fc_permit_release(fc_permit_t *p);

void fc_count(fc_state_t *fc, enum fc_reason reason);

static inline uint32_t
fc_inflight(const fc_state_t *fc)
{
  return fc ? atomic_load_explicit(&fc->inflight, memory_order_relaxed) : 0;
}

static inline uint32_t
fc_ep_inflight(const fc_state_t *fc, int ep, int role)
{
  if (!fc || ep < 0 || ep >= FC_MAX_EP || role < 0 || role >= FC_ROLES)
    return 0;
  return atomic_load_explicit(&fc->ep_inflight[ep][role], memory_order_relaxed);
}

/* The ceiling a shed response reports beside the inflight count. */
static inline uint32_t
fc_limit_for(const fc_state_t *fc, int role)
{
  if (!fc)
    return 0;
  if (role < 0 || role >= FC_ROLES)
    return fc->cfg.max_outstanding;
  return fc->cfg.ep_cap[role] ? fc->cfg.ep_cap[role] : fc->cfg.max_outstanding;
}

const char *fc_reason_name(enum fc_reason reason);
const char *fc_anomaly_name(enum fc_anomaly a);
const char *fc_mode_name(uint8_t mode);

#endif /* __SOCKPROXY_FC_H__ */
