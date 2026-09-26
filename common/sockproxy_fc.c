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
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "sockproxy_fc.h"

_Atomic uint64_t fc_anomaly_total[FC_A_COUNT];

static const char *const fc_reason_names[FC_R_COUNT] = {
  [FC_R_ADMITTED] = "admitted",
  [FC_R_CAPACITY_SHED] = "capacity_shed",
  [FC_R_NO_HEALTHY_CAPACITY] = "no_healthy_capacity",
  [FC_R_OBSERVE_WOULD_SHED] = "observe_would_shed",
  [FC_R_BYPASS_NON_INFERENCE] = "bypass_non_inference",
};

static const char *const fc_anomaly_names[FC_A_COUNT] = {
  [FC_A_UNDERFLOW] = "underflow",
  [FC_A_UNKNOWN_PERMIT] = "unknown_permit",
};

const char *
fc_reason_name(enum fc_reason reason)
{
  if ((int)reason < 0 || reason >= FC_R_COUNT)
    return "unknown";
  return fc_reason_names[reason];
}

const char *
fc_anomaly_name(enum fc_anomaly a)
{
  if ((int)a < 0 || a >= FC_A_COUNT)
    return "unknown";
  return fc_anomaly_names[a];
}

const char *
fc_mode_name(uint8_t mode)
{
  switch (mode) {
  case FC_MODE_OFF: return "off";
  case FC_MODE_OBSERVE: return "observe";
  case FC_MODE_ENFORCE: return "enforce";
  }
  return "unknown";
}

/* ---- configuration ------------------------------------------------------ */

static uint32_t
fc_env_u32(const char *name, uint32_t dflt)
{
  const char *e = getenv(name);
  char *end = NULL;
  long n;

  if (!e || !*e)
    return dflt;
  n = strtol(e, &end, 10);
  if (end == e || (end && *end) || n < 0 || n > 1000000)
    return dflt;
  return (uint32_t)n;
}

void
fc_cfg_from_env(fc_cfg_t *cfg)
{
  const char *mode;

  memset(cfg, 0, sizeof(*cfg));
  mode = getenv("LLB_FC_MODE");
  if (mode && !strcasecmp(mode, "enforce"))
    cfg->mode = FC_MODE_ENFORCE;
  else if (mode && !strcasecmp(mode, "observe"))
    cfg->mode = FC_MODE_OBSERVE;
  else
    cfg->mode = FC_MODE_OFF;

  cfg->max_outstanding = fc_env_u32("LLB_FC_MAX_OUTSTANDING", 0);
  cfg->ep_cap[FC_ROLE_NORMAL] = fc_env_u32("LLB_FC_EP_MAX_INFLIGHT", 0);
  /* The prefill ceiling keeps reading the knob the prefill selector already
   * honours, so an operator who set it keeps the same bound under the gate. */
  cfg->ep_cap[FC_ROLE_PREFILL] =
    fc_env_u32("LLB_FC_PREFILL_MAX_INFLIGHT",
               fc_env_u32("LLB_PD_MAX_INFLIGHT_PER_EP", 0));
  cfg->ep_cap[FC_ROLE_DECODE] = fc_env_u32("LLB_FC_DECODE_MAX_INFLIGHT", 0);
}

void
fc_state_apply(fc_state_t *fc, const fc_cfg_t *cfg)
{
  if (!fc || !cfg)
    return;
  fc->cfg = *cfg;
}

void
fc_state_init(fc_state_t *fc)
{
  fc_cfg_t cfg;

  if (!fc)
    return;
  memset(fc, 0, sizeof(*fc));
  fc_cfg_from_env(&cfg);
  fc_state_apply(fc, &cfg);
}

void
fc_permit_init(fc_permit_t *p)
{
  if (!p)
    return;
  p->fc = NULL;
  p->state = FC_P_NONE;
  p->svc_held = 0;
  for (int r = 0; r < FC_ROLES; r++)
    p->ep[r] = -1;
}

void
fc_count(fc_state_t *fc, enum fc_reason reason)
{
  if (!fc || (int)reason < 0 || reason >= FC_R_COUNT)
    return;
  atomic_fetch_add_explicit(&fc->decisions[reason], 1, memory_order_relaxed);
}

/* ---- classification ----------------------------------------------------- */

/* Inference paths, exact after the query string is dropped. A deployment
 * that serves inference on another path gets a configurable table in a
 * later change; until then anything else bypasses capacity and is counted. */
static const char *const fc_inference_paths[] = {
  "/v1/chat/completions",
  "/v1/completions",
  "/v1/embeddings",
  "/v1/rerank",
  "/v1/messages",
  "/v1/responses",
  "/generate",
  "/generate_stream",
  NULL,
};

int
fc_is_inference_request(int is_post, const char *path)
{
  size_t plen;

  if (!is_post || !path || path[0] != '/')
    return 0;
  plen = strcspn(path, "?");
  /* A trailing slash names the same resource. */
  while (plen > 1 && path[plen - 1] == '/')
    plen--;
  for (int i = 0; fc_inference_paths[i]; i++) {
    const char *want = fc_inference_paths[i];
    if (strlen(want) == plen && strncmp(want, path, plen) == 0)
      return 1;
  }
  return 0;
}

/* ---- units ---------------------------------------------------------------- */

/* Reserve one unit under a ceiling. cap == 0 is unlimited: the counter still
 * moves so the gauge is true. Returns 0 on success, -1 when the counter is at
 * or over the ceiling (nothing changed). */
static int
fc_unit_take(_Atomic uint32_t *ctr, uint32_t cap)
{
  uint32_t cur = atomic_load_explicit(ctr, memory_order_relaxed);

  for (;;) {
    if (cap && cur >= cap)
      return -1;
    if (atomic_compare_exchange_weak_explicit(ctr, &cur, cur + 1,
                                              memory_order_acq_rel,
                                              memory_order_relaxed))
      return 0;
    /* cur was reloaded by the failed exchange; try again. */
  }
}

/* Hand one unit back. A counter already at zero is left there and counted:
 * that is a unit released that was never taken, and letting it wrap would
 * turn the ceiling into a permanent admit. */
static void
fc_unit_give(_Atomic uint32_t *ctr)
{
  uint32_t cur = atomic_load_explicit(ctr, memory_order_relaxed);

  for (;;) {
    if (cur == 0) {
      atomic_fetch_add_explicit(&fc_anomaly_total[FC_A_UNDERFLOW], 1,
                                memory_order_relaxed);
      return;
    }
    if (atomic_compare_exchange_weak_explicit(ctr, &cur, cur - 1,
                                              memory_order_acq_rel,
                                              memory_order_relaxed))
      return;
  }
}

void
fc_bypass(fc_state_t *fc, fc_permit_t *p)
{
  fc_permit_init(p);
  p->fc = fc;
  p->state = FC_P_BYPASS;
  if (fc_active(fc))
    fc_count(fc, FC_R_BYPASS_NON_INFERENCE);
}

fc_verdict_t
fc_service_acquire(fc_state_t *fc, fc_permit_t *p)
{
  fc_permit_init(p);
  p->fc = fc;
  if (!fc_active(fc)) {
    p->state = FC_P_BYPASS;
    return FC_ADMIT;
  }
  if (fc_unit_take(&fc->inflight, fc->cfg.max_outstanding) != 0) {
    if (fc->cfg.mode == FC_MODE_ENFORCE) {
      fc_count(fc, FC_R_CAPACITY_SHED);
      p->state = FC_P_NONE;
      return FC_SHED;
    }
    fc_count(fc, FC_R_OBSERVE_WOULD_SHED);
    fc_unit_take(&fc->inflight, 0);
  }
  p->svc_held = 1;
  p->state = FC_P_EXECUTING;
  /* Not yet an admission: the endpoint unit decides. Counted when the
   * first endpoint unit lands on this permit. */
  return FC_ADMIT;
}

int
fc_ep_over_cap(const fc_state_t *fc, int ep, int role)
{
  uint32_t cap;

  if (!fc_active(fc) || fc->cfg.mode != FC_MODE_ENFORCE)
    return 0;
  if (ep < 0 || ep >= FC_MAX_EP || role < 0 || role >= FC_ROLES)
    return 0;
  cap = fc->cfg.ep_cap[role];
  return cap && fc_ep_inflight(fc, ep, role) >= cap;
}

fc_verdict_t
fc_ep_acquire(fc_state_t *fc, fc_permit_t *p, int ep, int role)
{
  if (!p || !fc_active(fc) || p->state != FC_P_EXECUTING)
    return FC_ADMIT;
  if (ep < 0 || ep >= FC_MAX_EP || role < 0 || role >= FC_ROLES)
    return FC_ADMIT;
  if (p->ep[role] == ep)
    return FC_ADMIT;              /* already held for this leg */
  if (fc_unit_take(&fc->ep_inflight[ep][role], fc->cfg.ep_cap[role]) != 0) {
    if (fc->cfg.mode == FC_MODE_ENFORCE) {
      fc_count(fc, FC_R_CAPACITY_SHED);
      return FC_SHED;
    }
    fc_count(fc, FC_R_OBSERVE_WOULD_SHED);
    fc_unit_take(&fc->ep_inflight[ep][role], 0);
  }
  {
    int had_leg = 0;
    for (int r = 0; r < FC_ROLES; r++)
      if (p->ep[r] >= 0)
        had_leg = 1;
    if (p->ep[role] >= 0)
      fc_unit_give(&fc->ep_inflight[(int)p->ep[role]][role]);
    p->ep[role] = (int8_t)ep;
    /* One admitted decision per request: the first leg's unit, not each
     * leg of a request that opens two. */
    if (!had_leg)
      fc_count(fc, FC_R_ADMITTED);
  }
  return FC_ADMIT;
}

int
fc_ep_acquire_any(fc_state_t *fc, fc_permit_t *p, int role, int preferred,
                  int n_eps, fc_eligible_fn eligible, void *ctx,
                  fc_verdict_t *verdict)
{
  int any_eligible = 0;

  if (verdict)
    *verdict = FC_ADMIT;
  if (!p || p->state != FC_P_EXECUTING || !fc_active(fc)) {
    /* Nothing to bound: the caller keeps its own pick. */
    return preferred;
  }
  if (n_eps > FC_MAX_EP)
    n_eps = FC_MAX_EP;

  if (preferred >= 0 && preferred < n_eps && eligible(ctx, preferred)) {
    any_eligible = 1;
    if (fc_ep_acquire(fc, p, preferred, role) == FC_ADMIT)
      return preferred;
  }
  for (int i = 0; i < n_eps; i++) {
    if (i == preferred || !eligible(ctx, i))
      continue;
    any_eligible = 1;
    if (fc_ep_over_cap(fc, i, role))
      continue;
    if (fc_ep_acquire(fc, p, i, role) == FC_ADMIT)
      return i;
  }
  if (verdict)
    *verdict = any_eligible ? FC_SHED : FC_NO_CAPACITY;
  if (!any_eligible)
    fc_count(fc, FC_R_NO_HEALTHY_CAPACITY);
  return -1;
}

int
fc_permit_move(fc_permit_t *p, int role, int new_ep)
{
  fc_state_t *fc;
  int old;

  if (!p || p->state != FC_P_EXECUTING || role < 0 || role >= FC_ROLES)
    return 0;
  fc = p->fc;
  if (!fc_active(fc))
    return 0;
  if (new_ep < 0 || new_ep >= FC_MAX_EP)
    return -1;
  old = p->ep[role];
  if (old == new_ep)
    return 0;
  if (fc_unit_take(&fc->ep_inflight[new_ep][role], fc->cfg.ep_cap[role]) != 0) {
    if (fc->cfg.mode == FC_MODE_ENFORCE) {
      fc_count(fc, FC_R_CAPACITY_SHED);
      return -1;
    }
    fc_count(fc, FC_R_OBSERVE_WOULD_SHED);
    fc_unit_take(&fc->ep_inflight[new_ep][role], 0);
  }
  if (old >= 0)
    fc_unit_give(&fc->ep_inflight[old][role]);
  p->ep[role] = (int8_t)new_ep;
  return 0;
}

void
fc_release_role(fc_permit_t *p, int role)
{
  if (!p || p->state != FC_P_EXECUTING || role < 0 || role >= FC_ROLES)
    return;
  if (p->ep[role] < 0)
    return;
  if (!p->fc) {
    atomic_fetch_add_explicit(&fc_anomaly_total[FC_A_UNKNOWN_PERMIT], 1,
                              memory_order_relaxed);
    p->ep[role] = -1;
    return;
  }
  fc_unit_give(&p->fc->ep_inflight[(int)p->ep[role]][role]);
  p->ep[role] = -1;
}

void
fc_permit_release(fc_permit_t *p)
{
  if (!p)
    return;
  switch (p->state) {
  case FC_P_NONE:
  case FC_P_RELEASED:
    return;
  case FC_P_BYPASS:
    p->state = FC_P_RELEASED;
    return;
  case FC_P_EXECUTING:
    break;
  default:
    p->state = FC_P_RELEASED;
    return;
  }
  for (int r = 0; r < FC_ROLES; r++)
    fc_release_role(p, r);
  if (p->svc_held) {
    if (p->fc)
      fc_unit_give(&p->fc->inflight);
    else
      atomic_fetch_add_explicit(&fc_anomaly_total[FC_A_UNKNOWN_PERMIT], 1,
                                memory_order_relaxed);
    p->svc_held = 0;
  }
  p->state = FC_P_RELEASED;
}
