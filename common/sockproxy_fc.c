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
#include <unistd.h>

#include "sockproxy_fc.h"

_Atomic uint64_t fc_anomaly_total[FC_A_COUNT];

const uint32_t fc_qwait_bounds_ms[FC_QWAIT_BUCKETS] = {
  10, 50, 100, 250, 500, 1000, 2500, 5000,
};

static const char *const fc_reason_names[FC_R_COUNT] = {
  [FC_R_ADMITTED] = "admitted",
  [FC_R_CAPACITY_SHED] = "capacity_shed",
  [FC_R_NO_HEALTHY_CAPACITY] = "no_healthy_capacity",
  [FC_R_OBSERVE_WOULD_SHED] = "observe_would_shed",
  [FC_R_BYPASS_NON_INFERENCE] = "bypass_non_inference",
  [FC_R_QUEUED] = "queued",
  [FC_R_QUEUE_FULL] = "queue_full",
  [FC_R_QUEUE_TIMEOUT] = "queue_timeout",
  [FC_R_CANCELLED] = "cancelled",
  [FC_R_DRAINED] = "drained",
  [FC_R_OBSERVE_WOULD_QUEUE] = "observe_would_queue",
  [FC_R_DRAINING] = "draining",
};

static const char *const fc_anomaly_names[FC_A_COUNT] = {
  [FC_A_UNDERFLOW] = "underflow",
  [FC_A_UNKNOWN_PERMIT] = "unknown_permit",
};

static fc_wake_fn fc_wake_hook;
static _Atomic int fc_drain_flag;

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

/* A numeric knob from the environment: `dflt` when unset or unparseable,
 * and the source marked when the environment gave the value. */
static uint32_t
fc_env_u32(const char *name, uint32_t dflt, uint8_t *src)
{
  const char *e = getenv(name);
  char *end = NULL;
  long n;

  if (!e || !*e)
    return dflt;
  n = strtol(e, &end, 10);
  if (end == e || (end && *end) || n < 0 || n > 100000000)
    return dflt;
  if (src)
    *src = FC_SRC_ENV;
  return (uint32_t)n;
}

void
fc_cfg_from_env(fc_cfg_t *cfg)
{
  const char *mode;

  memset(cfg, 0, sizeof(*cfg));
  mode = getenv("LLB_FC_MODE");
  if (mode && !strcasecmp(mode, "enforce")) {
    cfg->mode = FC_MODE_ENFORCE;
    cfg->src[FC_L_MODE] = FC_SRC_ENV;
  } else if (mode && !strcasecmp(mode, "observe")) {
    cfg->mode = FC_MODE_OBSERVE;
    cfg->src[FC_L_MODE] = FC_SRC_ENV;
  } else {
    cfg->mode = FC_MODE_OFF;
    if (mode && !strcasecmp(mode, "off"))
      cfg->src[FC_L_MODE] = FC_SRC_ENV;
  }

  cfg->max_outstanding = fc_env_u32("LLB_FC_MAX_OUTSTANDING", 0,
                                    &cfg->src[FC_L_MAX_OUTSTANDING]);
  cfg->ep_cap[FC_ROLE_NORMAL] = fc_env_u32("LLB_FC_EP_MAX_INFLIGHT", 0,
                                           &cfg->src[FC_L_EP_NORMAL]);
  /* The prefill ceiling keeps reading the knob the prefill selector already
   * honours, so an operator who set it keeps the same bound under the gate. */
  cfg->ep_cap[FC_ROLE_PREFILL] =
    fc_env_u32("LLB_FC_PREFILL_MAX_INFLIGHT",
               fc_env_u32("LLB_PD_MAX_INFLIGHT_PER_EP", 0,
                          &cfg->src[FC_L_EP_PREFILL]),
               &cfg->src[FC_L_EP_PREFILL]);
  cfg->ep_cap[FC_ROLE_DECODE] = fc_env_u32("LLB_FC_DECODE_MAX_INFLIGHT", 0,
                                           &cfg->src[FC_L_EP_DECODE]);
  cfg->max_queue_depth = fc_env_u32("LLB_FC_MAX_QUEUE_DEPTH", 0,
                                    &cfg->src[FC_L_QUEUE_DEPTH]);
  if (cfg->max_queue_depth > FC_QUEUE_DEPTH_MAX)
    cfg->max_queue_depth = FC_QUEUE_DEPTH_MAX;
  cfg->max_queue_wait_ms = fc_env_u32("LLB_FC_MAX_QUEUE_WAIT_MS", 0,
                                      &cfg->src[FC_L_QUEUE_WAIT]);
  if (cfg->max_queue_wait_ms > FC_QUEUE_WAIT_MS_MAX)
    cfg->max_queue_wait_ms = FC_QUEUE_WAIT_MS_MAX;
  /* A depth with no wait window would park a request forever: the window
   * defaults so the queue is always bounded in time as well as in size. */
  if (cfg->max_queue_depth > 0 && cfg->max_queue_wait_ms == 0)
    cfg->max_queue_wait_ms = 5000;
  cfg->telemetry_stale_ms = fc_env_u32("LLB_FC_TELEMETRY_STALE_MS",
                                       FC_TELEMETRY_STALE_MS_DEFAULT,
                                       &cfg->src[FC_L_TELEMETRY_STALE]);
  if (cfg->telemetry_stale_ms == 0 ||
      cfg->telemetry_stale_ms > FC_TELEMETRY_STALE_MS_MAX) {
    cfg->telemetry_stale_ms = FC_TELEMETRY_STALE_MS_DEFAULT;
    cfg->src[FC_L_TELEMETRY_STALE] = FC_SRC_DEFAULT;
  }
}

static inline void
fc_overlay_u32(uint32_t *val, uint8_t *src, uint32_t declared)
{
  if (declared) {
    *val = declared;
    *src = FC_SRC_RULE;
  }
}

void
fc_cfg_resolve(fc_cfg_t *out, const fc_cfg_t *env, const fc_rule_cfg_t *rule)
{
  *out = *env;
  if (!rule)
    return;
  if (rule->mode >= FC_RULE_MODE_OFF && rule->mode <= FC_RULE_MODE_ENFORCE) {
    out->mode = rule->mode - 1;
    out->src[FC_L_MODE] = FC_SRC_RULE;
  }
  fc_overlay_u32(&out->max_outstanding, &out->src[FC_L_MAX_OUTSTANDING],
                 rule->max_outstanding);
  fc_overlay_u32(&out->ep_cap[FC_ROLE_NORMAL], &out->src[FC_L_EP_NORMAL],
                 rule->ep_cap[FC_ROLE_NORMAL]);
  fc_overlay_u32(&out->ep_cap[FC_ROLE_PREFILL], &out->src[FC_L_EP_PREFILL],
                 rule->ep_cap[FC_ROLE_PREFILL]);
  fc_overlay_u32(&out->ep_cap[FC_ROLE_DECODE], &out->src[FC_L_EP_DECODE],
                 rule->ep_cap[FC_ROLE_DECODE]);
  fc_overlay_u32(&out->max_queue_depth, &out->src[FC_L_QUEUE_DEPTH],
                 rule->max_queue_depth);
  if (out->max_queue_depth > FC_QUEUE_DEPTH_MAX)
    out->max_queue_depth = FC_QUEUE_DEPTH_MAX;
  /* The environment's defaulted window was for the environment's depth:
   * start from its declared wait, or none, before the rule's. */
  if (env->src[FC_L_QUEUE_WAIT] == FC_SRC_DEFAULT)
    out->max_queue_wait_ms = 0;
  fc_overlay_u32(&out->max_queue_wait_ms, &out->src[FC_L_QUEUE_WAIT],
                 rule->max_queue_wait_ms);
  if (out->max_queue_wait_ms > FC_QUEUE_WAIT_MS_MAX)
    out->max_queue_wait_ms = FC_QUEUE_WAIT_MS_MAX;
  if (out->max_queue_depth > 0 && out->max_queue_wait_ms == 0) {
    out->max_queue_wait_ms = 5000;
    out->src[FC_L_QUEUE_WAIT] = FC_SRC_DEFAULT;
  }
  fc_overlay_u32(&out->telemetry_stale_ms, &out->src[FC_L_TELEMETRY_STALE],
                 rule->telemetry_stale_ms);
  if (out->telemetry_stale_ms > FC_TELEMETRY_STALE_MS_MAX)
    out->telemetry_stale_ms = FC_TELEMETRY_STALE_MS_MAX;
}

int
fc_cfg_equal(const fc_cfg_t *a, const fc_cfg_t *b)
{
  if (a->mode != b->mode || a->max_outstanding != b->max_outstanding ||
      a->max_queue_depth != b->max_queue_depth ||
      a->max_queue_wait_ms != b->max_queue_wait_ms ||
      a->telemetry_stale_ms != b->telemetry_stale_ms)
    return 0;
  for (int r = 0; r < FC_ROLES; r++)
    if (a->ep_cap[r] != b->ep_cap[r])
      return 0;
  for (int l = 0; l < FC_LIMITS; l++)
    if (a->src[l] != b->src[l])
      return 0;
  return 1;
}

/* ---- the ring, lock held ------------------------------------------------ */

static inline uint32_t
fc_ring_wrap(const fc_queue_t *q, uint32_t i)
{
  return i >= q->cap ? i - q->cap : i;
}

/* Re-lay the live entries, in order, from slot 0 of `dst` (a fresh buffer,
 * never the ring itself), then adopt it. Runs when the slots are used up by
 * tombstones, or when the depth grows. The slot hints held by waiting
 * permits go stale here; fc_ring_find falls back to a scan for them. */
static void
fc_ring_relayout(fc_queue_t *q, fc_queue_ent_t *dst, uint32_t dst_cap)
{
  uint32_t n = 0;
  uint32_t i = q->head;

  for (uint32_t k = 0; k < q->used; k++) {
    const fc_queue_ent_t *e = &q->ring[i];
    if (e->live && n < dst_cap)
      dst[n++] = *e;
    i = fc_ring_wrap(q, i + 1);
  }
  free(q->ring);
  q->ring = dst;
  q->cap = dst_cap;
  q->head = 0;
  q->tail = n == dst_cap ? 0 : n;
  q->used = n;
  q->count = n;
}

static int
fc_ring_compact(fc_queue_t *q)
{
  fc_queue_ent_t *scratch;

  if (q->cap == 0)
    return -1;
  scratch = calloc(q->cap, sizeof(*scratch));
  if (!scratch)
    return -1;
  fc_ring_relayout(q, scratch, q->cap);
  return 0;
}

static int
fc_ring_grow(fc_queue_t *q, uint32_t want)
{
  fc_queue_ent_t *ring;

  if (want > FC_QUEUE_DEPTH_MAX)
    want = FC_QUEUE_DEPTH_MAX;
  if (want <= q->cap)
    return 0;
  ring = calloc(want, sizeof(*ring));
  if (!ring)
    return -1;
  if (q->ring) {
    fc_ring_relayout(q, ring, want);
  } else {
    q->ring = ring;
    q->cap = want;
    q->head = q->tail = q->used = q->count = 0;
  }
  return 0;
}

void
fc_state_apply(fc_state_t *fc, const fc_cfg_t *cfg)
{
  if (!fc || !cfg)
    return;
  pthread_mutex_lock(&fc->queue.lock);
  fc->cfg = *cfg;
  if (fc->cfg.max_queue_depth > FC_QUEUE_DEPTH_MAX)
    fc->cfg.max_queue_depth = FC_QUEUE_DEPTH_MAX;
  if (fc->cfg.max_queue_wait_ms > FC_QUEUE_WAIT_MS_MAX)
    fc->cfg.max_queue_wait_ms = FC_QUEUE_WAIT_MS_MAX;
  if (fc->cfg.max_queue_depth > 0 && fc->cfg.max_queue_wait_ms == 0)
    fc->cfg.max_queue_wait_ms = 5000;
  if (fc->cfg.telemetry_stale_ms == 0)
    fc->cfg.telemetry_stale_ms = FC_TELEMETRY_STALE_MS_DEFAULT;
  if (!fc->queue.dead && fc->cfg.max_queue_depth > fc->queue.cap)
    (void)fc_ring_grow(&fc->queue, fc->cfg.max_queue_depth);
  pthread_mutex_unlock(&fc->queue.lock);
}

void
fc_state_init(fc_state_t *fc)
{
  fc_cfg_t cfg;

  if (!fc)
    return;
  memset(fc, 0, sizeof(*fc));
  pthread_mutex_init(&fc->queue.lock, NULL);
  fc_cfg_from_env(&cfg);
  fc_state_apply(fc, &cfg);
}

void
fc_state_destroy(fc_state_t *fc)
{
  if (!fc)
    return;
  pthread_mutex_lock(&fc->queue.lock);
  free(fc->queue.ring);
  fc->queue.ring = NULL;
  fc->queue.cap = fc->queue.head = fc->queue.tail = 0;
  fc->queue.used = fc->queue.count = 0;
  fc->queue.dead = 1;
  atomic_store_explicit(&fc->queued, 0, memory_order_relaxed);
  pthread_mutex_unlock(&fc->queue.lock);
}

void
fc_permit_init(fc_permit_t *p)
{
  if (!p)
    return;
  p->fc = NULL;
  p->state = FC_P_NONE;
  p->svc_held = 0;
  p->woken = 0;
  for (int r = 0; r < FC_ROLES; r++)
    p->ep[r] = -1;
  p->q_fd = -1;
  p->q_slot = 0;
  p->q_gen = 0;
  p->q_enqueue_ns = 0;
  p->q_deadline_ns = 0;
}

void
fc_count(fc_state_t *fc, enum fc_reason reason)
{
  if (!fc || (int)reason < 0 || reason >= FC_R_COUNT)
    return;
  atomic_fetch_add_explicit(&fc->decisions[reason], 1, memory_order_relaxed);
}

void
fc_drain_set(int on)
{
  atomic_store_explicit(&fc_drain_flag, on ? 1 : 0, memory_order_release);
}

int
fc_draining(void)
{
  return atomic_load_explicit(&fc_drain_flag, memory_order_acquire);
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

/* The service unit for a request that may (can_queue) or may not wait. */
static fc_verdict_t
fc_service_acquire__(fc_state_t *fc, fc_permit_t *p, int can_queue, int woken)
{
  int over = 0;
  uint64_t enq = woken ? p->q_enqueue_ns : 0;
  uint64_t deadline = woken ? p->q_deadline_ns : 0;

  fc_permit_init(p);
  p->fc = fc;
  /* A woken request keeps the wait it was first given, should it go back. */
  p->q_enqueue_ns = enq;
  p->q_deadline_ns = deadline;
  if (!fc_active(fc)) {
    p->state = FC_P_BYPASS;
    return FC_ADMIT;
  }
  if (fc->cfg.mode == FC_MODE_ENFORCE && fc_draining()) {
    p->state = FC_P_NONE;
    return FC_DRAINING;
  }
  /* A queue with someone in it: a newcomer waits behind them (or, on a
   * path that cannot wait, is refused), whatever the counters say, so a
   * unit freed for the head of the queue is not taken from under it. A
   * woken request IS the head. */
  if (fc->cfg.mode == FC_MODE_ENFORCE && fc_queue_enabled(fc) && !woken &&
      fc_queued(fc) > 0)
    over = 1;
  if (!over && fc_unit_take(&fc->inflight, fc->cfg.max_outstanding) != 0)
    over = 1;
  if (over) {
    if (fc->cfg.mode == FC_MODE_ENFORCE) {
      p->state = FC_P_NONE;
      return can_queue && fc_queue_enabled(fc) ? FC_QUEUE : FC_SHED;
    }
    fc_count(fc, fc->cfg.max_queue_depth > 0 ? FC_R_OBSERVE_WOULD_QUEUE
                                             : FC_R_OBSERVE_WOULD_SHED);
    fc_unit_take(&fc->inflight, 0);
  }
  p->svc_held = 1;
  p->state = FC_P_EXECUTING;
  p->woken = (uint8_t)(woken ? 1 : 0);
  /* Not yet an admission: the endpoint unit decides. Counted when the
   * first endpoint unit lands on this permit. */
  return FC_ADMIT;
}

fc_verdict_t
fc_service_acquire(fc_state_t *fc, fc_permit_t *p)
{
  return fc_service_acquire__(fc, p, 0, 0);
}

fc_verdict_t
fc_service_acquire_h1(fc_state_t *fc, fc_permit_t *p, int woken)
{
  return fc_service_acquire__(fc, p, 1, woken);
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
    if (fc->cfg.mode == FC_MODE_ENFORCE)
      return FC_SHED;
    fc_count(fc, fc->cfg.max_queue_depth > 0 ? FC_R_OBSERVE_WOULD_QUEUE
                                             : FC_R_OBSERVE_WOULD_SHED);
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

static void
fc_permit_release__(fc_permit_t *p, int wake)
{
  fc_state_t *fc;

  if (!p)
    return;
  switch (p->state) {
  case FC_P_NONE:
  case FC_P_RELEASED:
    return;
  case FC_P_BYPASS:
    p->state = FC_P_RELEASED;
    return;
  case FC_P_QUEUED:
    /* The request is gone while it waited: its entry leaves the queue
     * without a wake. The deadline and a drain move the permit out of
     * QUEUED when they take the entry, so a QUEUED permit whose entry is
     * no longer there was popped for its turn: the wake is on its way to a
     * connection that will not use it, and the turn goes to the next
     * waiting request instead of being lost. */
    fc = p->fc;
    if (fc && fc_queue_take(fc, p)) {
      fc_count(fc, FC_R_CANCELLED);
      fc = NULL;
    }
    p->state = FC_P_RELEASED;
    if (fc && wake)
      fc_queue_wake_one(fc);
    return;
  case FC_P_EXECUTING:
    break;
  default:
    p->state = FC_P_RELEASED;
    return;
  }
  for (int r = 0; r < FC_ROLES; r++)
    fc_release_role(p, r);
  fc = p->fc;
  if (p->svc_held) {
    if (fc)
      fc_unit_give(&fc->inflight);
    else
      atomic_fetch_add_explicit(&fc_anomaly_total[FC_A_UNKNOWN_PERMIT], 1,
                                memory_order_relaxed);
    p->svc_held = 0;
  }
  p->state = FC_P_RELEASED;
  /* The unit is back: the oldest waiting request gets its turn. After the
   * state change so a wake that re-enters this permit finds it released. */
  if (fc && wake)
    fc_queue_wake_one(fc);
}

void
fc_permit_release(fc_permit_t *p)
{
  fc_permit_release__(p, 1);
}

void
fc_permit_release_nowake(fc_permit_t *p)
{
  fc_permit_release__(p, 0);
}

/* ---- the queue ------------------------------------------------------------ */

void
fc_set_wake_hook(fc_wake_fn fn)
{
  fc_wake_hook = fn;
}

/* Lock held. Append or prepend one entry; -1 when no slot can be made. */
static int
fc_ring_insert(fc_queue_t *q, const fc_queue_ent_t *e, int front,
               uint32_t *slot_out)
{
  uint32_t slot;

  if (q->cap == 0)
    return -1;
  if (q->used >= q->cap && q->count < q->cap) {
    /* The slots are spent but live entries are fewer than the ring holds:
     * tombstones fill the gap. Re-lay the live entries. */
    (void)fc_ring_compact(q);
  }
  if (q->used >= q->cap && front) {
    /* A woken request going back to the head while newcomers filled the
     * queue: its place is kept, so the ring grows by a slot or more. Only
     * requests that were already counted in the depth come back this way. */
    uint32_t more = q->cap / 8 > 16 ? q->cap / 8 : 16;
    (void)fc_ring_grow(q, q->cap + more);
  }
  if (q->used >= q->cap)
    return -1;
  if (front) {
    uint32_t next;

    slot = q->head == 0 ? q->cap - 1 : q->head - 1;
    q->head = slot;
    /* Back at the head, but behind anyone who went back before it and
     * arrived earlier: several woken requests that lose keep their order. */
    q->ring[slot] = *e;
    q->ring[slot].live = 1;
    for (uint32_t k = 0; k < q->used; k++) {
      next = fc_ring_wrap(q, slot + 1);
      if (q->ring[next].live &&
          q->ring[next].enqueue_ns >= q->ring[slot].enqueue_ns)
        break;
      fc_queue_ent_t t = q->ring[next];
      q->ring[next] = q->ring[slot];
      q->ring[slot] = t;
      slot = next;
    }
  } else {
    slot = q->tail;
    q->tail = fc_ring_wrap(q, q->tail + 1);
  }
  q->ring[slot] = *e;
  q->ring[slot].live = 1;
  q->used++;
  q->count++;
  if (slot_out)
    *slot_out = slot;
  return 0;
}

int
fc_queue_push(fc_state_t *fc, fc_permit_t *p, int fd, uint64_t gen,
              uint64_t now_ns, int front)
{
  fc_queue_ent_t e;
  uint32_t slot = 0;
  uint64_t first_deadline = 0;
  int rc = -1;

  if (!fc || !p || fd < 0)
    return -1;
  /* A woken request going back is still bounded by its first window, and
   * takes its place among the waiters by when it first arrived. */
  if (front && p->q_deadline_ns) {
    now_ns = p->q_enqueue_ns;
    first_deadline = p->q_deadline_ns;
  }
  e.fd = fd;
  e.live = 1;
  e.gen = gen;
  e.enqueue_ns = now_ns;

  /* The permit is QUEUED before the entry is published: a drain or a
   * deadline on another thread that pops the entry the moment the lock is
   * dropped must find a waiting permit, not the one it replaces. */
  fc_permit_init(p);
  p->fc = fc;
  p->state = FC_P_QUEUED;
  p->q_fd = fd;
  p->q_gen = gen;
  p->q_enqueue_ns = now_ns;

  pthread_mutex_lock(&fc->queue.lock);
  e.deadline_ns = first_deadline ? first_deadline
                 : now_ns + (uint64_t)fc->cfg.max_queue_wait_ms * 1000000ULL;
  p->q_deadline_ns = e.deadline_ns;
  if (!fc->queue.dead && fc_queue_enabled(fc) &&
      (front || fc->queue.count < fc->cfg.max_queue_depth))
    rc = fc_ring_insert(&fc->queue, &e, front, &slot);
  if (rc == 0) {
    p->q_slot = slot;
    atomic_store_explicit(&fc->queued, fc->queue.count, memory_order_relaxed);
  }
  pthread_mutex_unlock(&fc->queue.lock);

  if (rc != 0) {
    fc_permit_init(p);
    p->fc = fc;
    fc_count(fc, FC_R_QUEUE_FULL);
    return -1;
  }
  fc_count(fc, FC_R_QUEUED);
  return 0;
}

/* Lock held. Find the live entry for (fd, gen): the slot hint first, then
 * the used span (the hint is stale after a re-layout). Returns the slot
 * or UINT32_MAX. */
static uint32_t
fc_ring_find(const fc_queue_t *q, int fd, uint64_t gen, uint32_t hint)
{
  uint32_t i;

  if (q->cap == 0)
    return UINT32_MAX;
  if (hint < q->cap && q->ring[hint].live && q->ring[hint].fd == fd &&
      q->ring[hint].gen == gen)
    return hint;
  i = q->head;
  for (uint32_t k = 0; k < q->used; k++) {
    const fc_queue_ent_t *e = &q->ring[i];
    if (e->live && e->fd == fd && e->gen == gen)
      return i;
    i = fc_ring_wrap(q, i + 1);
  }
  return UINT32_MAX;
}

int
fc_queue_take(fc_state_t *fc, fc_permit_t *p)
{
  uint32_t slot;
  int taken = 0;

  if (!fc || !p || p->state != FC_P_QUEUED)
    return 0;
  pthread_mutex_lock(&fc->queue.lock);
  slot = fc_ring_find(&fc->queue, p->q_fd, p->q_gen, p->q_slot);
  if (slot != UINT32_MAX) {
    fc->queue.ring[slot].live = 0;
    fc->queue.count--;
    taken = 1;
    /* A tombstone at the head is dead weight: drop it now. */
    while (fc->queue.used > 0 && !fc->queue.ring[fc->queue.head].live) {
      fc->queue.head = fc_ring_wrap(&fc->queue, fc->queue.head + 1);
      fc->queue.used--;
    }
    atomic_store_explicit(&fc->queued, fc->queue.count, memory_order_relaxed);
  }
  pthread_mutex_unlock(&fc->queue.lock);
  return taken;
}

int
fc_queue_holds(fc_state_t *fc, const fc_permit_t *p)
{
  int held;

  if (!fc || !p || p->state != FC_P_QUEUED)
    return 0;
  pthread_mutex_lock(&fc->queue.lock);
  held = fc_ring_find(&fc->queue, p->q_fd, p->q_gen, p->q_slot) != UINT32_MAX;
  pthread_mutex_unlock(&fc->queue.lock);
  return held;
}

/* Lock held. */
static int
fc_ring_pop(fc_queue_t *q, fc_queue_ent_t *out)
{
  while (q->used > 0) {
    fc_queue_ent_t *e = &q->ring[q->head];
    int live = e->live != 0;
    if (live && out)
      *out = *e;
    e->live = 0;
    q->head = fc_ring_wrap(q, q->head + 1);
    q->used--;
    if (live) {
      q->count--;
      return 1;
    }
  }
  return 0;
}

int
fc_queue_pop(fc_state_t *fc, fc_queue_ent_t *out)
{
  int rc;

  if (!fc)
    return 0;
  pthread_mutex_lock(&fc->queue.lock);
  rc = fc_ring_pop(&fc->queue, out);
  atomic_store_explicit(&fc->queued, fc->queue.count, memory_order_relaxed);
  pthread_mutex_unlock(&fc->queue.lock);
  return rc;
}

static void
fc_note_wait(fc_state_t *fc, uint64_t wait_ms)
{
  for (int i = 0; i < FC_QWAIT_BUCKETS; i++) {
    if (wait_ms <= fc_qwait_bounds_ms[i]) {
      atomic_fetch_add_explicit(&fc->qwait_bucket[i], 1, memory_order_relaxed);
      break;
    }
  }
  atomic_fetch_add_explicit(&fc->qwait_sum_ms, wait_ms, memory_order_relaxed);
  atomic_fetch_add_explicit(&fc->qwait_count, 1, memory_order_relaxed);
}

void
fc_queue_resumed(fc_state_t *fc, fc_permit_t *p, uint64_t now_ns)
{
  uint64_t wait_ms = 0;

  if (!p || p->state != FC_P_QUEUED)
    return;
  if (fc && now_ns > p->q_enqueue_ns)
    wait_ms = (now_ns - p->q_enqueue_ns) / 1000000ULL;
  if (fc)
    fc_note_wait(fc, wait_ms);
  p->state = FC_P_NONE;
  p->woken = 1;
}

/* Pop the head and wake its owner. 0 when nobody was popped or the wake
 * could not be delivered. */
static int
fc_queue_wake_head(fc_state_t *fc)
{
  fc_queue_ent_t e;

  if (!fc_queue_pop(fc, &e))
    return 0;
  if (fc_wake_hook(e.fd, e.gen) != 0) {
    /* The owner could not be woken now: the request keeps its place at
     * the head and the next released unit tries again. Its deadline is
     * unchanged, so the wait stays bounded. */
    pthread_mutex_lock(&fc->queue.lock);
    (void)fc_ring_insert(&fc->queue, &e, 1, NULL);
    atomic_store_explicit(&fc->queued, fc->queue.count, memory_order_relaxed);
    pthread_mutex_unlock(&fc->queue.lock);
    return 0;
  }
  return 1;
}

void
fc_queue_wake_one(fc_state_t *fc)
{
  if (!fc || !fc_wake_hook)
    return;
  if (fc_queued(fc) == 0 || !fc_has_room(fc))
    return;
  (void)fc_queue_wake_head(fc);
}

void
fc_queue_wake_room(fc_state_t *fc)
{
  uint32_t n, cap, inflight;

  if (!fc || !fc_wake_hook)
    return;
  n = fc_queued(fc);
  if (n == 0)
    return;
  /* A woken request takes its unit when its worker runs, not now, so the
   * units free at this moment bound how many turns are given; a woken one
   * that still meets a ceiling (an endpoint's) goes back to the head. */
  cap = fc->cfg.max_outstanding;
  if (fc->cfg.mode == FC_MODE_ENFORCE && cap != 0) {
    inflight = fc_inflight(fc);
    if (inflight >= cap)
      return;
    if (cap - inflight < n)
      n = cap - inflight;
  }
  while (n-- > 0) {
    if (!fc_queue_wake_head(fc))
      break;
  }
}

void
fc_queue_drain(fc_state_t *fc, fc_drain_fn fn, void *ctx)
{
  fc_queue_ent_t e;

  if (!fc)
    return;
  while (fc_queue_pop(fc, &e)) {
    if (!fn || fn(ctx, &e))
      fc_count(fc, FC_R_DRAINED);
  }
}

uint32_t
fc_retry_after_s(const fc_state_t *fc)
{
  uint64_t n, sum, mean_ms, s;

  if (!fc)
    return 1;
  n = atomic_load_explicit(&fc->qwait_count, memory_order_relaxed);
  sum = atomic_load_explicit(&fc->qwait_sum_ms, memory_order_relaxed);
  if (n == 0)
    return 1;
  mean_ms = sum / n;
  s = (mean_ms + 999) / 1000;
  if (s < 1)
    s = 1;
  if (s > 30)
    s = 30;
  return (uint32_t)s;
}

uint64_t
fc_queue_memory_bytes(uint32_t depth)
{
  return (uint64_t)depth << 20;
}

uint64_t
fc_node_memory_bytes(void)
{
  long pages = sysconf(_SC_PHYS_PAGES);
  long psize = sysconf(_SC_PAGESIZE);

  if (pages <= 0 || psize <= 0)
    return 0;
  return (uint64_t)pages * (uint64_t)psize;
}
