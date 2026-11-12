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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <sys/timerfd.h>

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
  [FC_R_TENANT_SHARE] = "tenant_share",
  [FC_R_SHED] = "shed",
};

static const char *const fc_band_outcome_names[FC_BO_COUNT] = {
  [FC_BO_ADMITTED] = "admitted",
  [FC_BO_QUEUED] = "queued",
  [FC_BO_SHED] = "shed",
  [FC_BO_EXPIRED] = "expired",
  [FC_BO_CANCELLED] = "cancelled",
};

/* The decision each band outcome splits. */
static const uint8_t fc_band_outcome_reason[FC_BO_COUNT] = {
  [FC_BO_ADMITTED] = FC_R_ADMITTED,
  [FC_BO_QUEUED] = FC_R_QUEUED,
  [FC_BO_SHED] = FC_R_SHED,
  [FC_BO_EXPIRED] = FC_R_QUEUE_TIMEOUT,
  [FC_BO_CANCELLED] = FC_R_CANCELLED,
};

static const char *const fc_anomaly_names[FC_A_COUNT] = {
  [FC_A_UNDERFLOW] = "underflow",
  [FC_A_UNKNOWN_PERMIT] = "unknown_permit",
  [FC_A_TENANT_TABLE_FULL] = "tenant_table_full",
  [FC_A_H2_DENY_HEADERS] = "h2_deny_headers",
  [FC_A_EXPOSE_HEAD_OVERFLOW] = "expose_head_overflow",
};

static const char *const fc_adapt_state_names[FC_AS_COUNT] = {
  [FC_AS_OFF] = "off",
  [FC_AS_OPEN] = "open",
  [FC_AS_TIGHTENED] = "tightened",
  [FC_AS_FROZEN] = "frozen",
};

static const char *const fc_adapt_reason_names[FC_AR_COUNT] = {
  [FC_AR_NONE] = "none",
  [FC_AR_QUEUED] = "queued",
  [FC_AR_TTFT] = "ttft",
  [FC_AR_CLEAR] = "clear",
  [FC_AR_STALE] = "stale",
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
fc_adapt_state_name(uint8_t state)
{
  return state < FC_AS_COUNT ? fc_adapt_state_names[state] : "unknown";
}

const char *
fc_adapt_reason_name(uint8_t reason)
{
  return reason < FC_AR_COUNT ? fc_adapt_reason_names[reason] : "unknown";
}

static uint64_t
fc_clock_monotonic(void)
{
  struct timespec ts;

  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static fc_clock_fn fc_clock = fc_clock_monotonic;

uint64_t
fc_now_ns(void)
{
  return fc_clock();
}

void
fc_set_clock(fc_clock_fn fn)
{
  fc_clock = fn ? fn : fc_clock_monotonic;
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

/* A two-valued switch from the environment: 0 for `v0` (or unset, or any
 * other value), 1 for `v1`; the source is the environment only for a value
 * it names. */
static int
fc_env_choice(const char *name, const char *v0, const char *v1, uint8_t *src)
{
  const char *v = getenv(name);

  if (v && !strcasecmp(v, v1)) {
    *src = FC_SRC_ENV;
    return 1;
  }
  if (v && !strcasecmp(v, v0))
    *src = FC_SRC_ENV;
  return 0;
}

/* Whether any band knob differs from its default. With none set, a pool's
 * bands run the defaults: strict wake, no floor, the shared wait and
 * depth, sheddable refused at the ceiling, FIFO inside a band. */
static uint8_t
fc_cfg_bands(const fc_cfg_t *c)
{
  if (c->wake_policy != FC_WAKE_STRICT || c->shed_queue ||
      c->tenant_wake != FC_TENANT_WAKE_FIFO)
    return 1;
  for (int b = 0; b < FC_BANDS; b++)
    if (c->band_weight[b] || c->band_min_share_pct[b] || c->band_wait_ms[b] ||
        c->band_queue_pct[b])
      return 1;
  return c->critical_reserve_pct != 0;
}

/* The configured switches equal the effective ones until fc_cfg_band_guard
 * judges the combination. */
static void
fc_cfg_band_mirror(fc_cfg_t *c)
{
  c->wake_policy_cfg = c->wake_policy;
  c->shed_queue_cfg = c->shed_queue;
  c->tenant_wake_cfg = c->tenant_wake;
  c->band_fallback = FC_BAND_FB_NONE;
}

void
fc_cfg_from_env(fc_cfg_t *cfg)
{
  const char *mode, *adaptive, *expose;

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
  adaptive = getenv("LLB_FC_ADAPTIVE");
  if (adaptive && !strcasecmp(adaptive, "on")) {
    cfg->adaptive = 1;
    cfg->src[FC_L_ADAPTIVE] = FC_SRC_ENV;
  } else if (adaptive && !strcasecmp(adaptive, "off")) {
    cfg->src[FC_L_ADAPTIVE] = FC_SRC_ENV;
  }
  cfg->warmup_ms = fc_env_u32("LLB_FC_WARMUP_MS", 0, &cfg->src[FC_L_WARMUP]);
  if (cfg->warmup_ms > FC_WARMUP_MS_MAX)
    cfg->warmup_ms = FC_WARMUP_MS_MAX;
  cfg->ttft_target_ms = fc_env_u32("LLB_FC_TTFT_TARGET_MS", 0,
                                   &cfg->src[FC_L_TTFT_TARGET]);
  if (cfg->ttft_target_ms > FC_TTFT_TARGET_MS_MAX)
    cfg->ttft_target_ms = FC_TTFT_TARGET_MS_MAX;
  {
    uint32_t pct = fc_env_u32("LLB_FC_TENANT_MAX_SHARE_PCT", 0,
                              &cfg->src[FC_L_TENANT_SHARE]);
    /* A percentage or nothing: a value past 100 is not a share. */
    if (pct > 100) {
      pct = 0;
      cfg->src[FC_L_TENANT_SHARE] = FC_SRC_DEFAULT;
    }
    cfg->tenant_share_pct = (uint8_t)pct;
  }
  expose = getenv("LLB_FC_EXPOSE_HEADERS");
  if (expose && !strcasecmp(expose, "on")) {
    cfg->expose_headers = 1;
    cfg->src[FC_L_EXPOSE_HEADERS] = FC_SRC_ENV;
  } else if (expose && !strcasecmp(expose, "off")) {
    cfg->src[FC_L_EXPOSE_HEADERS] = FC_SRC_ENV;
  }
  /* The band switches have an environment default; the numeric band knobs
   * are rule-only (0 there means none, which an environment value could not
   * say). */
  cfg->wake_policy = (uint8_t)fc_env_choice("LLB_FC_WAKE_POLICY", "strict",
                                            "weighted", &cfg->src[FC_L_WAKE_POLICY]);
  cfg->shed_queue = (uint8_t)fc_env_choice("LLB_FC_SHED_QUEUE", "off", "on",
                                           &cfg->src[FC_L_SHED_QUEUE]);
  cfg->tenant_wake = (uint8_t)fc_env_choice("LLB_FC_TENANT_WAKE", "fifo", "rr",
                                            &cfg->src[FC_L_TENANT_WAKE]);
  cfg->llmd_headers = (uint8_t)fc_env_choice("LLB_FC_LLMD_HEADERS", "off", "on",
                                             &cfg->src[FC_L_LLMD_HEADERS]);
  cfg->bands = fc_cfg_bands(cfg);
  fc_cfg_band_mirror(cfg);
}

static inline void
fc_overlay_u32(uint32_t *val, uint8_t *src, uint32_t declared)
{
  if (declared) {
    *val = declared;
    *src = FC_SRC_RULE;
  }
}

/* A rule-only triple: the rule's values, its own source when any is set.
 * Values past `max` are held at it (the control plane refuses them). */
static void
fc_band_triple_u8(uint8_t *out, uint8_t *src, const uint8_t *rule, uint8_t max)
{
  int set = 0;

  for (int b = 0; b < FC_BANDS; b++) {
    out[b] = rule[b] > max ? max : rule[b];
    set |= out[b] != 0;
  }
  *src = set ? FC_SRC_RULE : FC_SRC_DEFAULT;
}

static void
fc_cfg_resolve_bands(fc_cfg_t *out, const fc_rule_cfg_t *rule)
{
  int set = 0;

  if (rule->wake_policy == FC_RULE_WAKE_STRICT ||
      rule->wake_policy == FC_RULE_WAKE_WEIGHTED) {
    out->wake_policy = rule->wake_policy == FC_RULE_WAKE_WEIGHTED
                       ? FC_WAKE_WEIGHTED : FC_WAKE_STRICT;
    out->src[FC_L_WAKE_POLICY] = FC_SRC_RULE;
  }
  fc_band_triple_u8(out->band_weight, &out->src[FC_L_BAND_WEIGHTS],
                    rule->band_weight, FC_BAND_WEIGHT_MAX);
  fc_band_triple_u8(out->band_min_share_pct, &out->src[FC_L_BAND_MIN_SHARE],
                    rule->band_min_share_pct, 100);
  /* The reserve is not a floor: it holds units back from the other bands
   * whether or not critical has a waiter. It is kept beside the floors. */
  out->critical_reserve_pct = rule->critical_reserve_pct > 100
                              ? 100 : rule->critical_reserve_pct;
  out->src[FC_L_CRITICAL_RESERVE] = out->critical_reserve_pct ? FC_SRC_RULE
                                                              : FC_SRC_DEFAULT;
  for (int b = 0; b < FC_BANDS; b++) {
    out->band_wait_ms[b] = rule->band_wait_ms[b] > FC_QUEUE_WAIT_MS_MAX
                           ? FC_QUEUE_WAIT_MS_MAX : rule->band_wait_ms[b];
    set |= out->band_wait_ms[b] != 0;
  }
  out->src[FC_L_BAND_WAIT] = set ? FC_SRC_RULE : FC_SRC_DEFAULT;
  fc_band_triple_u8(out->band_queue_pct, &out->src[FC_L_BAND_QUEUE],
                    rule->band_queue_pct, 100);
  if (rule->shed_queue == FC_RULE_SWITCH_OFF || rule->shed_queue == FC_RULE_SWITCH_ON) {
    out->shed_queue = rule->shed_queue == FC_RULE_SWITCH_ON;
    out->src[FC_L_SHED_QUEUE] = FC_SRC_RULE;
  }
  if (rule->tenant_wake == FC_RULE_TENANT_WAKE_FIFO ||
      rule->tenant_wake == FC_RULE_TENANT_WAKE_RR) {
    out->tenant_wake = rule->tenant_wake == FC_RULE_TENANT_WAKE_RR
                       ? FC_TENANT_WAKE_RR : FC_TENANT_WAKE_FIFO;
    out->src[FC_L_TENANT_WAKE] = FC_SRC_RULE;
  }
  if (rule->llmd_headers == FC_RULE_SWITCH_OFF || rule->llmd_headers == FC_RULE_SWITCH_ON) {
    out->llmd_headers = rule->llmd_headers == FC_RULE_SWITCH_ON;
    out->src[FC_L_LLMD_HEADERS] = FC_SRC_RULE;
  }
  out->bands = fc_cfg_bands(out);
  fc_cfg_band_mirror(out);
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
  if (rule->adaptive == FC_RULE_ADAPTIVE_OFF ||
      rule->adaptive == FC_RULE_ADAPTIVE_ON) {
    out->adaptive = rule->adaptive == FC_RULE_ADAPTIVE_ON;
    out->src[FC_L_ADAPTIVE] = FC_SRC_RULE;
  }
  fc_overlay_u32(&out->warmup_ms, &out->src[FC_L_WARMUP], rule->warmup_ms);
  if (out->warmup_ms > FC_WARMUP_MS_MAX)
    out->warmup_ms = FC_WARMUP_MS_MAX;
  fc_overlay_u32(&out->ttft_target_ms, &out->src[FC_L_TTFT_TARGET],
                 rule->ttft_target_ms);
  if (out->ttft_target_ms > FC_TTFT_TARGET_MS_MAX)
    out->ttft_target_ms = FC_TTFT_TARGET_MS_MAX;
  if (rule->tenant_share_pct >= 1 && rule->tenant_share_pct <= 100) {
    out->tenant_share_pct = rule->tenant_share_pct;
    out->src[FC_L_TENANT_SHARE] = FC_SRC_RULE;
  }
  if (rule->expose_headers == FC_RULE_EXPOSE_OFF ||
      rule->expose_headers == FC_RULE_EXPOSE_ON) {
    out->expose_headers = rule->expose_headers == FC_RULE_EXPOSE_ON;
    out->src[FC_L_EXPOSE_HEADERS] = FC_SRC_RULE;
  }
  fc_cfg_resolve_bands(out, rule);
}

uint8_t
fc_cfg_band_guard(fc_cfg_t *c, int gate_bypassed)
{
  fc_cfg_band_mirror(c);
  if (gate_bypassed && c->bands) {
    /* The request direction is carried by the kernel and never reaches
     * the gate: the bands have nothing to order. llmd_headers is not a
     * band knob (it changes no admission decision) and stays. */
    c->wake_policy = FC_WAKE_STRICT;
    c->shed_queue = 0;
    c->tenant_wake = FC_TENANT_WAKE_FIFO;
    memset(c->band_weight, 0, sizeof(c->band_weight));
    memset(c->band_min_share_pct, 0, sizeof(c->band_min_share_pct));
    c->critical_reserve_pct = 0;
    memset(c->band_wait_ms, 0, sizeof(c->band_wait_ms));
    memset(c->band_queue_pct, 0, sizeof(c->band_queue_pct));
    c->band_fallback = FC_BAND_FB_SOCKMAP;
  }
  if (c->wake_policy == FC_WAKE_WEIGHTED) {
    for (int b = 0; b < FC_BANDS; b++) {
      if (c->band_weight[b] == 0) {
        /* A zero weight is strict under another name. */
        c->wake_policy = FC_WAKE_STRICT;
        if (c->band_fallback == FC_BAND_FB_NONE)
          c->band_fallback = FC_BAND_FB_NO_WEIGHTS;
        break;
      }
    }
  }
  if (c->shed_queue && c->max_queue_depth == 0) {
    c->shed_queue = 0;
    if (c->band_fallback == FC_BAND_FB_NONE)
      c->band_fallback = FC_BAND_FB_NO_QUEUE;
  }
  c->bands = fc_cfg_bands(c);
  return c->band_fallback;
}

const char *
fc_band_fallback_name(uint8_t reason)
{
  switch (reason) {
  case FC_BAND_FB_SOCKMAP:    return "sockmap_request";
  case FC_BAND_FB_NO_WEIGHTS: return "zero_weight";
  case FC_BAND_FB_NO_QUEUE:   return "no_queue";
  }
  return "none";
}

const char *
fc_src_name(uint8_t src)
{
  switch (src) {
  case FC_SRC_RULE: return "rule";
  case FC_SRC_ENV:  return "env";
  }
  return "default";
}

int
fc_cfg_equal(const fc_cfg_t *a, const fc_cfg_t *b)
{
  if (a->mode != b->mode || a->max_outstanding != b->max_outstanding ||
      a->max_queue_depth != b->max_queue_depth ||
      a->max_queue_wait_ms != b->max_queue_wait_ms ||
      a->telemetry_stale_ms != b->telemetry_stale_ms ||
      a->adaptive != b->adaptive || a->warmup_ms != b->warmup_ms ||
      a->ttft_target_ms != b->ttft_target_ms ||
      a->tenant_share_pct != b->tenant_share_pct ||
      a->expose_headers != b->expose_headers ||
      a->wake_policy != b->wake_policy || a->shed_queue != b->shed_queue ||
      a->tenant_wake != b->tenant_wake || a->llmd_headers != b->llmd_headers ||
      a->bands != b->bands || a->wake_policy_cfg != b->wake_policy_cfg ||
      a->critical_reserve_pct != b->critical_reserve_pct ||
      a->shed_queue_cfg != b->shed_queue_cfg ||
      a->tenant_wake_cfg != b->tenant_wake_cfg ||
      a->band_fallback != b->band_fallback)
    return 0;
  for (int i = 0; i < FC_BANDS; i++)
    if (a->band_weight[i] != b->band_weight[i] ||
        a->band_min_share_pct[i] != b->band_min_share_pct[i] ||
        a->band_wait_ms[i] != b->band_wait_ms[i] ||
        a->band_queue_pct[i] != b->band_queue_pct[i])
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

/* Whether a band has its own counts: critical and sheddable. Standard is
 * the total less those two, so a request with no class moves nothing new. */
static inline int
fc_band_counted(uint8_t band)
{
  return band == FC_BAND_CRITICAL || band == FC_BAND_SHEDDABLE;
}

/* Lock held. A live entry joins or leaves the ring's per-band count. */
static inline void
fc_ring_band_add(fc_queue_t *q, uint8_t band)
{
  if (fc_band_counted(band))
    q->band_count[band]++;
}

static inline void
fc_ring_band_sub(fc_queue_t *q, uint8_t band)
{
  if (fc_band_counted(band) && q->band_count[band] > 0)
    q->band_count[band]--;
}

/* Lock held. The lock-free mirrors of the queue's counts. */
static void
fc_queue_publish(fc_state_t *fc)
{
  atomic_store_explicit(&fc->queued, fc->queue.count, memory_order_relaxed);
  atomic_store_explicit(&fc->band_queued[FC_BAND_CRITICAL],
                        fc->queue.band_count[FC_BAND_CRITICAL], memory_order_relaxed);
  atomic_store_explicit(&fc->band_queued[FC_BAND_SHEDDABLE],
                        fc->queue.band_count[FC_BAND_SHEDDABLE], memory_order_relaxed);
}

/* Lock held. The earliest deadline among the live entries: kept by every
 * insertion (a min) and every removal (a rescan when the removed deadline
 * was the earliest), so the deadline pass reads one word per pool. */
static void
fc_ring_deadline_add(fc_queue_t *q, uint64_t deadline_ns)
{
  uint64_t cur = atomic_load_explicit(&q->next_deadline_ns, memory_order_relaxed);

  if (deadline_ns && (!cur || deadline_ns < cur))
    atomic_store_explicit(&q->next_deadline_ns, deadline_ns, memory_order_release);
}

static void
fc_ring_deadline_rescan(fc_queue_t *q)
{
  uint64_t min = 0;
  uint32_t i = q->head;

  for (uint32_t k = 0; k < q->used && q->cap; k++) {
    const fc_queue_ent_t *e = &q->ring[i];
    if (e->live && e->deadline_ns && (!min || e->deadline_ns < min))
      min = e->deadline_ns;
    i = fc_ring_wrap(q, i + 1);
  }
  atomic_store_explicit(&q->next_deadline_ns, min, memory_order_release);
}

static void
fc_ring_deadline_gone(fc_queue_t *q, uint64_t deadline_ns)
{
  if (deadline_ns &&
      deadline_ns == atomic_load_explicit(&q->next_deadline_ns, memory_order_relaxed))
    fc_ring_deadline_rescan(q);
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

  memset(q->band_count, 0, sizeof(q->band_count));
  for (uint32_t k = 0; k < q->used; k++) {
    const fc_queue_ent_t *e = &q->ring[i];
    if (e->live && n < dst_cap) {
      dst[n++] = *e;
      fc_ring_band_add(q, e->band);
    }
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
    memset(q->band_count, 0, sizeof(q->band_count));
  }
  return 0;
}

/* Where the adaptive ceiling stands after a configuration change: at the
 * new ceiling when the pool just became adaptive (it starts open and only
 * tightens on evidence) or was open, held under a lowered ceiling, and,
 * when it was tightened, left where it was under a raised one (it climbs
 * back one unit per fresh tick, as it would have under the old one). */
static void
fc_adapt_reset(fc_state_t *fc, const fc_cfg_t *old)
{
  uint32_t ceil = fc->cfg.max_outstanding;
  uint32_t eff = atomic_load_explicit(&fc->eff_max, memory_order_relaxed);

  if (!fc->cfg.adaptive || ceil == 0) {
    atomic_store_explicit(&fc->eff_max, ceil, memory_order_relaxed);
    atomic_store_explicit(&fc->adapt_state, FC_AS_OFF, memory_order_relaxed);
    atomic_store_explicit(&fc->adapt_reason, FC_AR_NONE, memory_order_relaxed);
    return;
  }
  if (!old->adaptive || old->max_outstanding == 0 || eff == 0 || eff > ceil ||
      eff >= old->max_outstanding)
    eff = ceil;
  atomic_store_explicit(&fc->eff_max, eff, memory_order_relaxed);
  atomic_store_explicit(&fc->adapt_state,
                        eff < ceil ? FC_AS_TIGHTENED : FC_AS_OPEN,
                        memory_order_relaxed);
}

static int fc_tenant_table_ensure(fc_state_t *fc);
static uint32_t fc_tenant_slots_clamp(uint32_t n);

void
fc_state_apply(fc_state_t *fc, const fc_cfg_t *cfg)
{
  fc_cfg_t old;

  if (!fc || !cfg)
    return;
  pthread_mutex_lock(&fc->queue.lock);
  old = fc->cfg;
  fc->cfg = *cfg;
  if (fc->cfg.max_queue_depth > FC_QUEUE_DEPTH_MAX)
    fc->cfg.max_queue_depth = FC_QUEUE_DEPTH_MAX;
  if (fc->cfg.max_queue_wait_ms > FC_QUEUE_WAIT_MS_MAX)
    fc->cfg.max_queue_wait_ms = FC_QUEUE_WAIT_MS_MAX;
  if (fc->cfg.max_queue_depth > 0 && fc->cfg.max_queue_wait_ms == 0)
    fc->cfg.max_queue_wait_ms = 5000;
  if (fc->cfg.telemetry_stale_ms == 0)
    fc->cfg.telemetry_stale_ms = FC_TELEMETRY_STALE_MS_DEFAULT;
  if (fc->cfg.warmup_ms > FC_WARMUP_MS_MAX)
    fc->cfg.warmup_ms = FC_WARMUP_MS_MAX;
  if (fc->cfg.ttft_target_ms > FC_TTFT_TARGET_MS_MAX)
    fc->cfg.ttft_target_ms = FC_TTFT_TARGET_MS_MAX;
  if (fc->cfg.tenant_share_pct > 100)
    fc->cfg.tenant_share_pct = 0;
  /* The tenant table comes with the pool's first share. A pool that cannot
   * have one runs without a share, and says so in its read-back. */
  if (fc_share_active(fc) && fc_tenant_table_ensure(fc) != 0) {
    fc->cfg.tenant_share_pct = 0;
    fc->cfg.src[FC_L_TENANT_SHARE] = FC_SRC_DEFAULT;
  }
  /* A window removed ends every warm-up at once. */
  if (fc->cfg.warmup_ms == 0)
    for (int e = 0; e < FC_MAX_EP; e++)
      atomic_store_explicit(&fc->warm_since_ns[e], 0, memory_order_relaxed);
  fc_adapt_reset(fc, &old);
  /* A new policy or new weights start a round of their own, and a new tenant
   * order starts its turns again; waiters keep their places and bands. */
  if (old.wake_policy != fc->cfg.wake_policy ||
      memcmp(old.band_weight, fc->cfg.band_weight, sizeof(old.band_weight)) != 0)
    memset(fc->queue.drr_credit, 0, sizeof(fc->queue.drr_credit));
  if (old.tenant_wake != fc->cfg.tenant_wake)
    memset(fc->queue.rr_next, 0, sizeof(fc->queue.rr_next));
  if (!fc->queue.dead && fc->cfg.max_queue_depth > fc->queue.cap)
    (void)fc_ring_grow(&fc->queue, fc->cfg.max_queue_depth);
  pthread_mutex_unlock(&fc->queue.lock);
}

void
fc_state_init_slots(fc_state_t *fc, uint32_t tenant_slots)
{
  fc_cfg_t cfg;

  if (!fc)
    return;
  memset(fc, 0, sizeof(*fc));
  pthread_mutex_init(&fc->queue.lock, NULL);
  fc->tenant_slots = fc_tenant_slots_clamp(tenant_slots);
  fc_cfg_from_env(&cfg);
  fc_state_apply(fc, &cfg);
}

void
fc_state_init(fc_state_t *fc)
{
  fc_state_init_slots(fc, FC_TENANT_SLOTS);
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
  memset(fc->queue.band_count, 0, sizeof(fc->queue.band_count));
  fc->queue.dead = 1;
  atomic_store_explicit(&fc->queue.next_deadline_ns, 0, memory_order_release);
  fc_queue_publish(fc);
  /* The tenant table goes with the rule, so creating and deleting rules
   * does not grow the process. A request that still holds the pool settles
   * its service unit as before and finds no tenant slot to settle. */
  free(fc->tenants);
  free(fc->tenant_index);
  fc->tenants = NULL;
  fc->tenant_index = NULL;
  fc->tenants_used = 0;
  fc->tenant_free = 0;
  fc->tenant_tombs = 0;
  fc->tenants_runnable_waiting = 0;
  fc->tenant_bound = 0;
  pthread_mutex_unlock(&fc->queue.lock);
}

static void
fc_permit_reset(fc_permit_t *p)
{
  p->fc = NULL;
  p->state = FC_P_NONE;
  p->svc_held = 0;
  p->woken = 0;
  p->band = FC_BAND_STANDARD;
  p->q_parked = 0;
  p->q_ttl_cut = 0;
  p->q_ttl_ms = 0;
  for (int r = 0; r < FC_ROLES; r++)
    p->ep[r] = -1;
  p->q_fd = -1;
  p->q_slot = 0;
  p->q_gen = 0;
  p->q_enqueue_ns = 0;
  p->q_deadline_ns = 0;
  p->q_first_ns = 0;
  p->admit_ns = 0;
  p->tkey = 0;
  p->tslot = -1;
}

static void (*fc_owner_hold)(fc_state_t *fc);
static void (*fc_owner_drop)(fc_state_t *fc);

void
fc_set_owner_hooks(void (*hold)(fc_state_t *fc), void (*drop)(fc_state_t *fc))
{
  fc_owner_hold = hold;
  fc_owner_drop = drop;
}

void
fc_permit_unbind(fc_permit_t *p)
{
  fc_state_t *old;

  if (!p || !fc_owner_drop)
    return;
  /* The queue drain (another thread, under PROXY_LOCK) and the owner's
   * teardown can both unbind one permit: the exchange gives the old state to
   * exactly one of them, so its reference is dropped once. */
  old = __atomic_exchange_n(&p->fc, NULL, __ATOMIC_ACQ_REL);
  if (old)
    fc_owner_drop(old);
}

void
fc_permit_init(fc_permit_t *p)
{
  if (!p)
    return;
  fc_permit_unbind(p);
  fc_permit_reset(p);
}

/* A fresh permit bound to fc. The new state's reference is taken before the
 * old one is given back, so a rebind to the same state never drops its
 * count to zero on the way. Without owner hooks the permit's earlier
 * content is not read (it may be uninitialised). */
static void
fc_permit_bind(fc_permit_t *p, fc_state_t *fc)
{
  fc_state_t *old = fc_owner_drop ? p->fc : NULL;

  if (fc && fc_owner_hold)
    fc_owner_hold(fc);
  fc_permit_reset(p);
  p->fc = fc;
  if (old)
    fc_owner_drop(old);
}

/* ---- tenant share ----------------------------------------------------------- */

uint64_t
fc_tenant_key(const char *tenant_id)
{
  /* FNV-1a: two tenants that collide share one budget, at odds of one in
   * 2^64 per pair. */
  uint64_t h = 0xcbf29ce484222325ULL;

  if (tenant_id)
    for (const unsigned char *c = (const unsigned char *)tenant_id; *c; c++) {
      h ^= *c;
      h *= 0x100000001b3ULL;
    }
  return h;
}

static uint32_t
fc_share_of(uint32_t whole, uint8_t pct)
{
  uint64_t n;

  if (whole == 0)
    return 0;
  n = ((uint64_t)whole * pct + 99) / 100;
  return n ? (uint32_t)n : 1;
}

uint32_t
fc_tenant_svc_bound(const fc_state_t *fc)
{
  if (!fc_share_active(fc))
    return 0;
  return fc_share_of(fc_svc_cap(fc), fc->cfg.tenant_share_pct);
}

uint32_t
fc_tenant_queue_bound(const fc_state_t *fc)
{
  if (!fc_share_active(fc))
    return 0;
  return fc_share_of(fc->cfg.max_queue_depth, fc->cfg.tenant_share_pct);
}

uint32_t
fc_band_queue_bound(const fc_state_t *fc, uint8_t band)
{
  if (!fc)
    return 0;
  band = fc_band_of(band);
  if (!fc->cfg.band_queue_pct[band])
    return 0;
  return fc_share_of(fc->cfg.max_queue_depth, fc->cfg.band_queue_pct[band]);
}

/* Lock held. The live waiters of one band; the standard slot is the rest. */
static uint32_t
fc_band_live(const fc_queue_t *q, uint8_t band)
{
  uint32_t crit = q->band_count[FC_BAND_CRITICAL];
  uint32_t shed = q->band_count[FC_BAND_SHEDDABLE];

  if (fc_band_counted(band))
    return q->band_count[band];
  return q->count > crit + shed ? q->count - crit - shed : 0;
}

uint32_t
fc_tenants_active(fc_state_t *fc)
{
  uint32_t n;

  if (!fc)
    return 0;
  pthread_mutex_lock(&fc->queue.lock);
  n = fc->tenants_used;
  pthread_mutex_unlock(&fc->queue.lock);
  return n;
}

static uint32_t
fc_tenant_slots_clamp(uint32_t n)
{
  if (n < FC_TENANT_SLOTS)
    return FC_TENANT_SLOTS;
  if (n > FC_TENANT_SLOTS_MAX)
    return FC_TENANT_SLOTS_MAX;
  return n;
}

uint32_t
fc_tenant_slots_from_env(void)
{
  return fc_tenant_slots_clamp(fc_env_u32("LLB_FC_TENANT_SLOTS",
                                          FC_TENANT_SLOTS_DEFAULT, NULL));
}

uint32_t
fc_tenant_slots(const fc_state_t *fc)
{
  if (!fc)
    return 0;
  return fc->tenant_slots ? fc->tenant_slots : FC_TENANT_SLOTS;
}

/* The lookup index: a bucket is empty, a tombstone (its slot was freed and
 * a later key's probe run still passes over it), or a slot number plus one. */
#define FC_TIDX_EMPTY 0u
#define FC_TIDX_TOMB  0xffffu

_Static_assert(FC_TENANT_SLOTS_MAX + 1 < FC_TIDX_TOMB, "slot + 1 fits a bucket");

static inline uint32_t
fc_tidx_buckets(const fc_state_t *fc)
{
  return 2 * fc->tenant_slots;
}

static inline uint32_t
fc_tidx_next(const fc_state_t *fc, uint32_t b)
{
  return b + 1 == fc_tidx_buckets(fc) ? 0 : b + 1;
}

/* Where a key's probe run starts. The key is FNV-1a, whose low bits alone
 * spread poorly under a modulo: the high half is folded in first. */
static inline uint32_t
fc_tidx_home(const fc_state_t *fc, uint64_t key)
{
  key ^= key >> 33;
  key *= 0xff51afd7ed558ccdULL;
  key ^= key >> 33;
  return (uint32_t)(key % fc_tidx_buckets(fc));
}

/* Lock held. The table and its index, made on the pool's first share.
 * tenant_slots is not zero from here on. A destroyed pool gets none: a
 * request that resolved the pool before its rule went runs on the service
 * ceiling alone. */
static int
fc_tenant_table_ensure(fc_state_t *fc)
{
  uint32_t n;

  if (fc->tenants)
    return 0;
  if (fc->queue.dead)
    return -1;
  if (fc->tenant_slots == 0)
    fc->tenant_slots = FC_TENANT_SLOTS;
  n = fc->tenant_slots;
  fc->tenants = calloc((size_t)n + 1, sizeof(*fc->tenants));
  fc->tenant_index = calloc(2 * (size_t)n, sizeof(*fc->tenant_index));
  if (!fc->tenants || !fc->tenant_index) {
    free(fc->tenants);
    free(fc->tenant_index);
    fc->tenants = NULL;
    fc->tenant_index = NULL;
    return -1;
  }
  for (uint32_t i = 0; i < n; i++)
    fc->tenants[i].next_free = (uint16_t)(i + 1);
  fc->tenant_free = 0;
  fc->tenants_used = 0;
  fc->tenant_tombs = 0;
  fc->tenants_runnable_waiting = 0;
  fc->tenant_bound = 0;
  return 0;
}

/* Lock held. The bucket holding `key`'s slot, or the bucket count when the
 * key has none; `free_out` is then the bucket a new slot for it goes in.
 * At most tenant_slots of the 2 * tenant_slots buckets hold a slot, so a
 * bucket to take always turns up. */
static uint32_t
fc_tidx_find(const fc_state_t *fc, uint64_t key, uint32_t *free_out)
{
  uint32_t nb = fc_tidx_buckets(fc);
  uint32_t b = fc_tidx_home(fc, key);
  uint32_t free_bkt = nb;

  for (uint32_t k = 0; k < nb; k++) {
    uint16_t v = fc->tenant_index[b];

    if (v == FC_TIDX_EMPTY) {
      if (free_bkt == nb)
        free_bkt = b;
      break;
    }
    if (v == FC_TIDX_TOMB) {
      if (free_bkt == nb)
        free_bkt = b;
    } else if (fc->tenants[v - 1].key == key) {
      return b;
    }
    b = fc_tidx_next(fc, b);
  }
  if (free_out)
    *free_out = free_bkt;
  return nb;
}

/* Lock held. Lay the index out again from the slots in use. The slots stay
 * where they are: permits and queue entries name them by number. */
static void
fc_tidx_relay(fc_state_t *fc)
{
  uint32_t nb = fc_tidx_buckets(fc);

  memset(fc->tenant_index, 0, (size_t)nb * sizeof(*fc->tenant_index));
  fc->tenant_tombs = 0;
  for (uint32_t i = 0; i < fc->tenant_slots; i++) {
    uint32_t b;

    if (!fc->tenants[i].used)
      continue;
    b = fc_tidx_home(fc, fc->tenants[i].key);
    while (fc->tenant_index[b] != FC_TIDX_EMPTY)
      b = fc_tidx_next(fc, b);
    fc->tenant_index[b] = (uint16_t)(i + 1);
  }
}

/* Lock held. Take a freed slot's bucket out of the index. At the end of
 * its probe run the bucket is simply empty again, and so are the tombstones
 * right before it; inside a run it has to stay as a tombstone. Tombstones
 * lengthen every probe that misses, so past a quarter of the buckets the
 * index is laid out again. */
static void
fc_tidx_drop(fc_state_t *fc, uint64_t key)
{
  uint32_t nb = fc_tidx_buckets(fc);
  uint32_t b = fc_tidx_find(fc, key, NULL);

  if (b == nb)
    return;
  if (fc->tenant_index[fc_tidx_next(fc, b)] == FC_TIDX_EMPTY) {
    fc->tenant_index[b] = FC_TIDX_EMPTY;
    for (;;) {
      b = b == 0 ? nb - 1 : b - 1;
      if (fc->tenant_index[b] != FC_TIDX_TOMB)
        break;
      fc->tenant_index[b] = FC_TIDX_EMPTY;
      fc->tenant_tombs--;
    }
    return;
  }
  fc->tenant_index[b] = FC_TIDX_TOMB;
  if (++fc->tenant_tombs > nb / 4)
    fc_tidx_relay(fc);
}

/* Lock held. The tenant's slot, taken when it has none: a free one, or the
 * shared last slot once the table is full (`count` says whether this call
 * is the request's first look, the one the anomaly is counted on). Hand it
 * back with fc_tenant_put when nothing was counted on it. -1 when the pool
 * has no table. */
static int
fc_tenant_get(fc_state_t *fc, uint64_t key, int count)
{
  uint32_t nb, b, free_bkt = 0;
  uint32_t slot;
  fc_tenant_t *t;

  if (fc_tenant_table_ensure(fc) != 0)
    return -1;
  nb = fc_tidx_buckets(fc);
  b = fc_tidx_find(fc, key, &free_bkt);
  if (b != nb)
    return (int)fc->tenant_index[b] - 1;
  slot = fc->tenant_free;
  if (slot >= fc->tenant_slots) {
    slot = fc->tenant_slots;
    if (count)
      atomic_fetch_add_explicit(&fc_anomaly_total[FC_A_TENANT_TABLE_FULL], 1,
                                memory_order_relaxed);
    t = &fc->tenants[slot];
    if (!t->used) {
      t->used = 1;
      t->key = key;
      t->inflight = t->queued = 0;
      t->waiting_runnable = 0;
      fc->tenants_used++;
    }
    return (int)slot;
  }
  t = &fc->tenants[slot];
  fc->tenant_free = t->next_free;
  t->used = 1;
  t->key = key;
  t->inflight = t->queued = 0;
  t->waiting_runnable = 0;
  fc->tenants_used++;
  if (fc->tenant_index[free_bkt] == FC_TIDX_TOMB)
    fc->tenant_tombs--;
  fc->tenant_index[free_bkt] = (uint16_t)(slot + 1);
  return (int)slot;
}

/* Lock held. A slot holding nothing is free again. */
static void
fc_tenant_put(fc_state_t *fc, int slot)
{
  fc_tenant_t *t;

  if (!fc->tenants || slot < 0 || (uint32_t)slot > fc->tenant_slots)
    return;
  t = &fc->tenants[slot];
  if (!t->used || t->inflight != 0 || t->queued != 0)
    return;
  t->used = 0;
  fc->tenants_used--;
  /* The shared slot has no bucket and is never on the free list. */
  if ((uint32_t)slot == fc->tenant_slots)
    return;
  fc_tidx_drop(fc, t->key);
  t->next_free = (uint16_t)fc->tenant_free;
  fc->tenant_free = (uint32_t)slot;
  /* The last named tenant left: whatever tombstones remain mark nothing. */
  if (fc->tenant_tombs &&
      fc->tenants_used == fc->tenants[fc->tenant_slots].used)
    fc_tidx_relay(fc);
}

/* Lock held. Keep the slot's place in the count of tenants that wait and
 * could run, after its inflight or queued count moved. */
static void
fc_tenant_mark(fc_state_t *fc, fc_tenant_t *t)
{
  uint8_t runnable = t->used && t->queued > 0 &&
                     (fc->tenant_bound == 0 || t->inflight < fc->tenant_bound);

  if (runnable == t->waiting_runnable)
    return;
  t->waiting_runnable = runnable;
  if (runnable)
    fc->tenants_runnable_waiting++;
  else
    fc->tenants_runnable_waiting--;
}

/* Lock held. Move one count of the slot down, never below zero. */
static void
fc_tenant_dec(fc_state_t *fc, int slot, int queued)
{
  fc_tenant_t *t;
  uint32_t *ctr;

  if (!fc->tenants || slot < 0 || (uint32_t)slot > fc->tenant_slots ||
      !fc->tenants[slot].used)
    return;
  t = &fc->tenants[slot];
  ctr = queued ? &t->queued : &t->inflight;
  if (*ctr == 0)
    atomic_fetch_add_explicit(&fc_anomaly_total[FC_A_UNDERFLOW], 1,
                              memory_order_relaxed);
  else
    (*ctr)--;
  fc_tenant_mark(fc, t);
  fc_tenant_put(fc, slot);
}

/* Lock held. Whether a queued entry's tenant may take a unit now. */
static inline int
fc_tenant_can_run(const fc_state_t *fc, int slot, uint32_t bound)
{
  return slot < 0 || bound == 0 || !fc->tenants ||
         fc->tenants[slot].inflight < bound;
}

/* Lock held. Whether anybody waiting could take a unit now: a newcomer
 * waits behind them, not behind waiters held back by their own share. The
 * count is kept as the tenants' own counts move; it is taken again over the
 * table only when the bound itself moved (a new share or ceiling, or a step
 * of the adaptive ceiling). */
static int
fc_tenant_waiter_can_run(fc_state_t *fc, uint32_t bound)
{
  if (!fc->tenants)
    return 0;
  if (bound != fc->tenant_bound) {
    fc->tenant_bound = bound;
    fc->tenants_runnable_waiting = 0;
    for (uint32_t i = 0; i <= fc->tenant_slots; i++) {
      fc->tenants[i].waiting_runnable = 0;
      fc_tenant_mark(fc, &fc->tenants[i]);
    }
  }
  return fc->tenants_runnable_waiting > 0;
}

void
fc_count(fc_state_t *fc, enum fc_reason reason)
{
  if (!fc || (int)reason < 0 || reason >= FC_R_COUNT)
    return;
  atomic_fetch_add_explicit(&fc->decisions[reason], 1, memory_order_relaxed);
}

static int
fc_band_outcome_of(enum fc_reason reason)
{
  for (int o = 0; o < FC_BO_COUNT; o++)
    if (fc_band_outcome_reason[o] == reason)
      return o;
  return -1;
}

void
fc_count_band(fc_state_t *fc, enum fc_reason reason, uint8_t band)
{
  int o;

  fc_count(fc, reason);
  if (!fc || !fc_band_counted(band))
    return;
  o = fc_band_outcome_of(reason);
  if (o >= 0)
    atomic_fetch_add_explicit(&fc->band_outcome[band][o], 1, memory_order_relaxed);
}

uint64_t
fc_band_outcome(fc_state_t *fc, uint8_t band, int outcome)
{
  uint64_t total, crit, shed, std, seen;

  if (!fc || outcome < 0 || outcome >= FC_BO_COUNT)
    return 0;
  band = fc_band_of(band);
  if (fc_band_counted(band))
    return atomic_load_explicit(&fc->band_outcome[band][outcome], memory_order_relaxed);
  /* The two counted bands first: each moves with the decision, after it,
   * so read after the decision they are never ahead of it. */
  total = atomic_load_explicit(&fc->decisions[fc_band_outcome_reason[outcome]],
                               memory_order_relaxed);
  crit = atomic_load_explicit(&fc->band_outcome[FC_BAND_CRITICAL][outcome],
                              memory_order_relaxed);
  shed = atomic_load_explicit(&fc->band_outcome[FC_BAND_SHEDDABLE][outcome],
                              memory_order_relaxed);
  std = total > crit + shed ? total - crit - shed : 0;
  /* A critical or sheddable request counted between the loads reads in its
   * band but not yet in the total: the difference can only read low, by
   * the requests in that window, and the next read has them back. A counter
   * must not step back, so a reader returns the larger of this and the
   * last value read; neither is ever above the true count. */
  seen = atomic_load_explicit(&fc->band_std_read[outcome], memory_order_relaxed);
  while (std > seen &&
         !atomic_compare_exchange_weak_explicit(&fc->band_std_read[outcome], &seen,
                                                std, memory_order_relaxed,
                                                memory_order_relaxed))
    ;
  return std > seen ? std : seen;
}

const char *
fc_band_outcome_name(int outcome)
{
  if (outcome < 0 || outcome >= FC_BO_COUNT)
    return "unknown";
  return fc_band_outcome_names[outcome];
}

int
fc_band_may_wait(const fc_state_t *fc, const fc_permit_t *p)
{
  return !fc || !p || fc->cfg.mode != FC_MODE_ENFORCE ||
         p->band != FC_BAND_SHEDDABLE || fc->cfg.shed_queue;
}

fc_verdict_t
fc_band_verdict(const fc_state_t *fc, const fc_permit_t *p, fc_verdict_t v)
{
  if ((v == FC_QUEUE || v == FC_SHED) && !fc_band_may_wait(fc, p))
    return FC_BAND_SHED;
  return v;
}

int
fc_band_triple_fmt(char *out, size_t cap, const uint32_t v[FC_BANDS])
{
  return snprintf(out, cap, "%u:%u:%u", v[fc_band_at_rank(0)],
                  v[fc_band_at_rank(1)], v[fc_band_at_rank(2)]);
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
  fc_permit_bind(p, fc);
  p->state = FC_P_BYPASS;
  if (fc_active(fc))
    fc_count(fc, FC_R_BYPASS_NON_INFERENCE);
}

/* The permit's service unit is counted in its band too (critical and
 * sheddable only). Taken where svc_held is set, given back where it is
 * cleared; the band does not change while the unit is held. */
static inline void
fc_band_unit_take(fc_state_t *fc, const fc_permit_t *p)
{
  if (fc_band_counted(p->band))
    atomic_fetch_add_explicit(&fc->band_inflight[p->band], 1, memory_order_relaxed);
}

static inline void
fc_band_unit_give(fc_state_t *fc, const fc_permit_t *p)
{
  if (fc_band_counted(p->band))
    fc_unit_give(&fc->band_inflight[p->band]);
}

/* Whether the pool follows its waiters by tenant: a tenant share bounds them, or the
 * round-robin wake needs to tell them apart. */
static inline int
fc_tenants_tracked(const fc_state_t *fc)
{
  return fc_share_active(fc) ||
         (fc != NULL && fc->cfg.mode != FC_MODE_OFF &&
          fc->cfg.tenant_wake == FC_TENANT_WAKE_RR);
}

/* Whether the strict wake orders this pool's waiters by band. Weighted
 * keeps one order across bands until it runs its own rounds. */
static inline int
fc_wake_strict(const fc_state_t *fc)
{
  return fc->cfg.wake_policy == FC_WAKE_STRICT;
}

/* ---- floors and the reserve ----------------------------------------------- */

uint32_t
fc_floor_units(uint32_t cap, uint8_t pct)
{
  uint64_t u;

  if (cap == 0 || pct == 0)
    return 0;
  if (pct >= 100)
    return cap;
  u = ((uint64_t)cap * pct + 99) / 100;
  return u >= cap ? cap - 1 : (uint32_t)u;
}

void
fc_floor_claims(const fc_cfg_t *c, uint32_t cap, uint32_t floor[FC_BANDS],
                uint32_t *reserve)
{
  uint32_t left = cap, res = fc_floor_units(cap, c->critical_reserve_pct);
  uint32_t crit = fc_floor_units(cap, c->band_min_share_pct[FC_BAND_CRITICAL]);
  uint32_t claim = res > crit ? res : crit;

  /* Critical first: it holds the larger of its floor and its reserve (each
   * at most the ceiling, so the claim always fits). */
  floor[FC_BAND_CRITICAL] = crit;
  if (reserve)
    *reserve = res;
  left -= claim;
  for (int r = 1; r < FC_BANDS; r++) {
    uint8_t b = fc_band_at_rank(r);
    uint32_t u = fc_floor_units(cap, c->band_min_share_pct[b]);

    floor[b] = u < left ? u : left;
    left -= floor[b];
  }
}

/* The bands as a floor decision sees them: what each holds, what it is owed
 * and whether it has a waiter that could take a unit. */
typedef struct fc_floor_view {
  uint32_t cap;
  uint32_t total;                /* units held, and the ones already promised by a wake */
  uint32_t reserve;              /* units critical is owed whatever it has waiting */
  uint32_t floor[FC_BANDS];      /* units a band is owed while it has a waiter */
  uint32_t claim[FC_BANDS];      /* what a band takes freely: critical's larger of floor and reserve */
  uint32_t in[FC_BANDS];
  uint8_t  wait[FC_BANDS];
} fc_floor_view_t;

/* `pend`: units promised to waiters already woken and not yet taken (a wake
 * loop's own; NULL for none). `wait`: which bands have a waiter that could
 * run, when the caller knows (queue lock held); NULL reads the mirrors. */
static void
fc_floor_view_load(const fc_state_t *fc, fc_floor_view_t *v, uint32_t cap,
                   const uint32_t *pend, const uint8_t *wait)
{
  uint32_t pt = 0, crit, shed, total;

  if (pend)
    pt = pend[0] + pend[1] + pend[2];
  total = atomic_load_explicit(&fc->inflight, memory_order_relaxed);
  crit = atomic_load_explicit(&fc->band_inflight[FC_BAND_CRITICAL], memory_order_relaxed);
  shed = atomic_load_explicit(&fc->band_inflight[FC_BAND_SHEDDABLE], memory_order_relaxed);
  if (pend) {
    crit += pend[FC_BAND_CRITICAL];
    shed += pend[FC_BAND_SHEDDABLE];
  }
  total += pt;
  v->cap = cap;
  v->total = total;
  for (int b = 0; b < FC_BANDS; b++) {
    v->in[b] = fc_band_derive(total, crit, shed, (uint8_t)b);
    v->wait[b] = wait ? wait[b] : fc_band_queued(fc, (uint8_t)b) > 0;
  }
  fc_floor_claims(&fc->cfg, cap, v->floor, &v->reserve);
  for (int b = 0; b < FC_BANDS; b++)
    v->claim[b] = v->floor[b];
  if (v->reserve > v->claim[FC_BAND_CRITICAL])
    v->claim[FC_BAND_CRITICAL] = v->reserve;
}

/* Units the other bands hold back from a request of `band`. A band below
 * what it takes freely (its floor; critical's reserve) takes its own units
 * and yields only the reserve; a band at or above it yields, besides, the
 * floor every other band with a waiter is short of. */
static uint32_t
fc_floor_held_back(const fc_floor_view_t *v, uint8_t band)
{
  int below = v->in[band] < v->claim[band];
  uint32_t held = 0;

  for (int y = 0; y < FC_BANDS; y++) {
    uint32_t rd = 0, fd = 0;

    if (y == band)
      continue;
    if (y == FC_BAND_CRITICAL && v->reserve > v->in[y])
      rd = v->reserve - v->in[y];
    if (!below && v->wait[y] && v->floor[y] > v->in[y])
      fd = v->floor[y] - v->in[y];
    held += rd > fd ? rd : fd;
  }
  return held;
}

static int
fc_floor_may_take(const fc_floor_view_t *v, uint8_t band)
{
  uint32_t held = fc_floor_held_back(v, band);

  return held < v->cap && v->total < v->cap - held;
}

/* The ceiling a request of `band` may fill: 0 is "no unit" (a ceiling of 0
 * elsewhere is unlimited, so the caller checks). Only an enforcing pool with
 * a ceiling and a floor or a reserve holds anything back. */
static int
fc_floors_apply(const fc_state_t *fc, uint32_t cap)
{
  return cap != 0 && fc->cfg.mode == FC_MODE_ENFORCE && fc_floors_on(&fc->cfg);
}

/* Reserve one service unit for a request of `band` under the ceiling,
 * holding back what the floors and the reserve owe the other bands. The
 * floors are read from the band counters and queue mirrors, not one
 * snapshot: a race with another admission can cross a floor by the units
 * in flight in that race and no more. `wait` as in fc_floor_view_load. */
static int
fc_unit_take_band(fc_state_t *fc, uint8_t band, uint32_t cap, const uint8_t *wait)
{
  fc_floor_view_t v;
  uint32_t held;

  if (!fc_floors_apply(fc, cap))
    return fc_unit_take(&fc->inflight, cap);
  fc_floor_view_load(fc, &v, cap, NULL, wait);
  held = fc_floor_held_back(&v, band);
  if (held >= cap)
    return -1;
  return fc_unit_take(&fc->inflight, cap - held);
}

/* Whether a request of `band` is below what its band takes freely: it then
 * does not wait behind the other bands' waiters. */
static int
fc_band_below_claim(const fc_state_t *fc, uint8_t band)
{
  fc_floor_view_t v;
  uint32_t cap = fc_svc_cap(fc);

  if (!fc_floors_apply(fc, cap))
    return 0;
  fc_floor_view_load(fc, &v, cap, NULL, NULL);
  return v.in[band] < v.claim[band];
}

/* Lock held. Which bands hold a waiter whose tenant could take a unit now. */
static void
fc_floor_waiting_runnable(const fc_state_t *fc, uint32_t bound, uint8_t wait[FC_BANDS])
{
  const fc_queue_t *q = &fc->queue;
  uint32_t i = q->head;

  memset(wait, 0, FC_BANDS);
  for (uint32_t k = 0; k < q->used; k++) {
    const fc_queue_ent_t *e = &q->ring[i];

    if (e->live && fc_tenant_can_run(fc, e->tslot, bound))
      wait[fc_band_of(e->band)] = 1;
    i = fc_ring_wrap(q, i + 1);
  }
}

/* Whether a newcomer of `band` waits behind the queue, read from the
 * lock-free mirrors: under strict, behind a waiter of its own band or a
 * higher one; otherwise behind anybody. With every waiter standard both
 * are "anybody waiting", today's test. */
static int
fc_waiters_ahead(const fc_state_t *fc, uint8_t band)
{
  int rank = fc_band_rank(band);

  if (fc_queued(fc) == 0)
    return 0;
  /* Below its floor a band is served before the wake policy's choice: it
   * waits only behind its own band. */
  if (fc_band_below_claim(fc, band))
    return fc_band_queued(fc, band) > 0;
  if (!fc_wake_strict(fc) || rank == FC_BANDS - 1)
    return 1;
  for (int r = 0; r <= rank; r++)
    if (fc_band_queued(fc, fc_band_at_rank(r)) > 0)
      return 1;
  return 0;
}

/* Lock held. Live entries of one band (standard is the rest). */
static uint32_t
fc_ring_band_n(const fc_queue_t *q, uint8_t band)
{
  uint32_t crit = q->band_count[FC_BAND_CRITICAL];
  uint32_t shed = q->band_count[FC_BAND_SHEDDABLE];

  return fc_band_derive(q->count, crit, shed, band);
}

/* Lock held. The same on a pool with a share: a newcomer of `band` waits
 * when a waiter that could take the unit now is ahead of it. The tenant
 * count answers it whenever every waiter is ahead of the newcomer; only a
 * queue that holds both bands ahead of it and bands below it is walked. */
static int
fc_band_waiter_can_run(fc_state_t *fc, uint8_t band, uint32_t bound)
{
  const fc_queue_t *q = &fc->queue;
  int rank = fc_band_rank(band);
  int ahead = 0, below = 0;
  uint32_t i;

  if (!fc_tenant_waiter_can_run(fc, bound))
    return 0;
  if (fc_band_below_claim(fc, band)) {
    i = q->head;
    for (uint32_t k = 0; k < q->used; k++) {
      const fc_queue_ent_t *e = &q->ring[i];
      if (e->live && e->band == band && fc_tenant_can_run(fc, e->tslot, bound))
        return 1;
      i = fc_ring_wrap(q, i + 1);
    }
    return 0;
  }
  if (!fc_wake_strict(fc) || rank == FC_BANDS - 1)
    return 1;
  for (int r = 0; r < FC_BANDS; r++) {
    if (fc_ring_band_n(q, fc_band_at_rank(r)) == 0)
      continue;
    if (r <= rank)
      ahead = 1;
    else
      below = 1;
  }
  if (!ahead)
    return 0;
  if (!below)
    return 1;
  i = q->head;
  for (uint32_t k = 0; k < q->used; k++) {
    const fc_queue_ent_t *e = &q->ring[i];
    if (e->live && fc_band_rank(e->band) <= rank &&
        fc_tenant_can_run(fc, e->tslot, bound))
      return 1;
    i = fc_ring_wrap(q, i + 1);
  }
  return 0;
}

/* The service unit on a pool with a tenant share: the tenant's own count
 * is checked and moved under the queue lock, with the service unit. */
static fc_verdict_t
fc_service_acquire_shared(fc_state_t *fc, fc_permit_t *p, int can_queue,
                          int woken)
{
  int enforce = fc->cfg.mode == FC_MODE_ENFORCE;
  uint32_t bound = fc_tenant_svc_bound(fc);
  fc_verdict_t v = FC_ADMIT;
  int over = 0;
  fc_tenant_t *t;
  int slot;

  pthread_mutex_lock(&fc->queue.lock);
  /* A woken request was looked up, and counted, when it first arrived. */
  slot = fc_tenant_get(fc, p->tkey, !woken);
  t = slot >= 0 ? &fc->tenants[slot] : NULL;
  if (t && bound && t->inflight >= bound) {
    if (enforce) {
      /* At its share: it waits for one of its own units when it may, and
       * everyone else still admits. A sheddable request that may not wait
       * takes the share's refusal: the pool is not at its ceiling. */
      v = can_queue && fc_queue_enabled(fc) && fc_band_may_wait(fc, p)
          ? FC_QUEUE : FC_TENANT_SHARE;
      goto refused;
    }
    fc_count(fc, FC_R_OBSERVE_WOULD_SHED);
    fc_unit_take(&fc->inflight, 0);
    goto admitted;
  }
  /* Waiters come first, but only those that could take the unit: a queue
   * full of tenants held back by their share is no reason to wait, and
   * under strict neither is a queue of lower bands. A woken request IS the
   * head. */
  if (enforce && fc_queue_enabled(fc) && !woken &&
      fc_band_waiter_can_run(fc, p->band, bound))
    over = 1;
  if (!over) {
    uint32_t cap = fc_svc_cap(fc);
    uint8_t wait[FC_BANDS];
    const uint8_t *w = NULL;

    /* Under the lock the waiters that count are the ones that could run. */
    if (fc_floors_apply(fc, cap) && fc_queued(fc) > 0) {
      fc_floor_waiting_runnable(fc, bound, wait);
      w = wait;
    }
    if (fc_unit_take_band(fc, p->band, cap, w) != 0)
      over = 1;
  }
  if (over) {
    if (enforce) {
      v = fc_band_verdict(fc, p, can_queue && fc_queue_enabled(fc) ? FC_QUEUE
                                                                   : FC_SHED);
      goto refused;
    }
    fc_count(fc, fc->cfg.max_queue_depth > 0 ? FC_R_OBSERVE_WOULD_QUEUE
                                             : FC_R_OBSERVE_WOULD_SHED);
    fc_unit_take(&fc->inflight, 0);
  }
admitted:
  if (t) {
    t->inflight++;
    fc_tenant_mark(fc, t);
  }
  pthread_mutex_unlock(&fc->queue.lock);
  p->tslot = (int16_t)slot;
  p->svc_held = 1;
  fc_band_unit_take(fc, p);
  p->state = FC_P_EXECUTING;
  p->woken = (uint8_t)(woken ? 1 : 0);
  return FC_ADMIT;
refused:
  fc_tenant_put(fc, slot);
  pthread_mutex_unlock(&fc->queue.lock);
  p->state = FC_P_NONE;
  return v;
}

/* The service unit for a request that may (can_queue) or may not wait. */
static fc_verdict_t
fc_service_acquire__(fc_state_t *fc, fc_permit_t *p, int can_queue, int woken,
                     uint64_t tkey, uint8_t band)
{
  int over = 0;
  uint64_t enq = woken ? p->q_enqueue_ns : 0;
  uint64_t deadline = woken ? p->q_deadline_ns : 0;
  /* A new request is in no park; a woken one is still in its first. */
  uint8_t parked = woken ? p->q_parked : 0;
  /* ... and its deadline is still the one it was given. */
  uint8_t ttl_cut = woken ? p->q_ttl_cut : 0;

  fc_permit_bind(p, fc);
  p->q_parked = parked;
  p->q_ttl_cut = ttl_cut;
  /* A woken request keeps the wait it was first given, should it go back. */
  p->q_enqueue_ns = enq;
  p->q_deadline_ns = deadline;
  p->tkey = tkey;
  p->band = fc_band_of(band);
  if (!fc_active(fc)) {
    p->state = FC_P_BYPASS;
    return FC_ADMIT;
  }
  if (fc->cfg.mode == FC_MODE_ENFORCE && fc_draining()) {
    p->state = FC_P_NONE;
    return FC_DRAINING;
  }
  if (fc_share_active(fc))
    return fc_service_acquire_shared(fc, p, can_queue, woken);
  /* A queue with someone in it: a newcomer waits behind them (or, on a
   * path that cannot wait, is refused), whatever the counters say, so a
   * unit freed for the head of the queue is not taken from under it. Under
   * strict only a waiter of its own band or a higher one is ahead of it. A
   * woken request IS the head. */
  if (fc->cfg.mode == FC_MODE_ENFORCE && fc_queue_enabled(fc) && !woken &&
      fc_waiters_ahead(fc, p->band))
    over = 1;
  if (!over && fc_unit_take_band(fc, p->band, fc_svc_cap(fc), NULL) != 0)
    over = 1;
  if (over) {
    if (fc->cfg.mode == FC_MODE_ENFORCE) {
      p->state = FC_P_NONE;
      return fc_band_verdict(fc, p, can_queue && fc_queue_enabled(fc) ? FC_QUEUE
                                                                      : FC_SHED);
    }
    fc_count(fc, fc->cfg.max_queue_depth > 0 ? FC_R_OBSERVE_WOULD_QUEUE
                                             : FC_R_OBSERVE_WOULD_SHED);
    fc_unit_take(&fc->inflight, 0);
  }
  p->svc_held = 1;
  fc_band_unit_take(fc, p);
  p->state = FC_P_EXECUTING;
  p->woken = (uint8_t)(woken ? 1 : 0);
  /* Not yet an admission: the endpoint unit decides. Counted when the
   * first endpoint unit lands on this permit. */
  return FC_ADMIT;
}

fc_verdict_t
fc_service_acquire(fc_state_t *fc, fc_permit_t *p)
{
  return fc_service_acquire__(fc, p, 0, 0, fc_tenant_key(NULL), FC_BAND_STANDARD);
}

fc_verdict_t
fc_service_acquire_h1(fc_state_t *fc, fc_permit_t *p, int woken)
{
  return fc_service_acquire__(fc, p, 1, woken, fc_tenant_key(NULL),
                              FC_BAND_STANDARD);
}

fc_verdict_t
fc_service_acquire_tenant(fc_state_t *fc, fc_permit_t *p, uint64_t tkey)
{
  return fc_service_acquire__(fc, p, 0, 0, tkey, FC_BAND_STANDARD);
}

fc_verdict_t
fc_service_acquire_h1_tenant(fc_state_t *fc, fc_permit_t *p, int woken,
                             uint64_t tkey)
{
  return fc_service_acquire__(fc, p, 1, woken, tkey, FC_BAND_STANDARD);
}

fc_verdict_t
fc_service_acquire_band(fc_state_t *fc, fc_permit_t *p, uint64_t tkey,
                        uint8_t band)
{
  return fc_service_acquire__(fc, p, 0, 0, tkey, band);
}

fc_verdict_t
fc_service_acquire_h1_band(fc_state_t *fc, fc_permit_t *p, int woken,
                           uint64_t tkey, uint8_t band)
{
  return fc_service_acquire__(fc, p, 1, woken, tkey, band);
}

int
fc_ep_over_cap(const fc_state_t *fc, int ep, int role)
{
  uint32_t cap;

  if (!fc_active(fc) || fc->cfg.mode != FC_MODE_ENFORCE)
    return 0;
  if (ep < 0 || ep >= FC_MAX_EP || role < 0 || role >= FC_ROLES)
    return 0;
  cap = fc_ep_cap_now(fc, ep, role, 0);
  return cap && fc_ep_inflight(fc, ep, role) >= cap;
}

static void fc_note_wait(fc_state_t *fc, uint64_t wait_ms);

fc_verdict_t
fc_ep_acquire(fc_state_t *fc, fc_permit_t *p, int ep, int role)
{
  if (!p || !fc_active(fc) || p->state != FC_P_EXECUTING)
    return FC_ADMIT;
  if (ep < 0 || ep >= FC_MAX_EP || role < 0 || role >= FC_ROLES)
    return FC_ADMIT;
  if (p->ep[role] == ep)
    return FC_ADMIT;              /* already held for this leg */
  if (fc_unit_take(&fc->ep_inflight[ep][role],
                   fc_ep_cap_now(fc, ep, role, 0)) != 0) {
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
     * leg of a request that opens two. Its time is the dispatch a TTFT
     * sample is measured from, so a wait at the gate is not the engine's. */
    if (!had_leg) {
      fc_count_band(fc, FC_R_ADMITTED, p->band);
      p->admit_ns = fc_now_ns();
      fc_queue_wait_end(fc, p, p->admit_ns);
    }
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
  if (fc_unit_take(&fc->ep_inflight[new_ep][role],
                   fc_ep_cap_now(fc, new_ep, role, 0)) != 0) {
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
     * no longer there was popped for its turn, or evicted. Evicted, it was
     * counted shed and freed no unit: its owed answer is dropped with the
     * connection and nobody is woken. Popped, the wake is on its way to a
     * connection that will not use it, and the turn goes to the next
     * waiting request instead of being lost. */
    fc = p->fc;
    if (fc && fc_queue_take(fc, p)) {
      fc_count_band(fc, FC_R_CANCELLED, p->band);
      fc_queue_wait_end(fc, p, fc_now_ns());
      fc = NULL;
    } else if (fc && fc_queue_evicted_claim(fc, p->q_fd, p->q_gen)) {
      (void)fc_permit_settle(p, FC_P_RELEASED);
      p->q_parked = 0;             /* observed where it was evicted */
      fc = NULL;
    } else if (!fc_permit_settle(p, FC_P_RELEASED)) {
      fc = NULL;                   /* another path ended the wait: no turn to pass on */
    }
    p->state = FC_P_RELEASED;
    if (fc && wake)
      fc_queue_wake_one(fc);
    return;
  case FC_P_EVICTED:
  case FC_P_ENDED:
    /* Decided by the path that ended the wait, which answers it; nothing
     * is held. */
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
  fc = p->fc;
  if (p->svc_held) {
    if (fc) {
      fc_unit_give(&fc->inflight);
      fc_band_unit_give(fc, p);
    } else
      atomic_fetch_add_explicit(&fc_anomaly_total[FC_A_UNKNOWN_PERMIT], 1,
                                memory_order_relaxed);
    p->svc_held = 0;
  }
  /* The tenant's unit, whatever the share is now: a share turned off while
   * the request ran still settles what it counted. Before the wake, so the
   * tenant's own waiter can take the turn. */
  if (p->tslot >= 0 && fc) {
    pthread_mutex_lock(&fc->queue.lock);
    fc_tenant_dec(fc, p->tslot, 0);
    pthread_mutex_unlock(&fc->queue.lock);
  }
  p->tslot = -1;
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
               int ordered, uint32_t *slot_out)
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
    if (ordered) {
      /* A request that arrived before the waiters at the tail (it waited
       * in another queue first) goes in behind the last one that arrived
       * no later than it, as a woken request goes back. */
      q->ring[slot] = *e;
      q->ring[slot].live = 1;
      while (slot != q->head) {
        uint32_t prev = slot == 0 ? q->cap - 1 : slot - 1;

        if (q->ring[prev].live &&
            q->ring[prev].enqueue_ns <= q->ring[slot].enqueue_ns)
          break;
        fc_queue_ent_t t = q->ring[prev];
        q->ring[prev] = q->ring[slot];
        q->ring[slot] = t;
        slot = prev;
      }
    }
  }
  q->ring[slot] = *e;
  q->ring[slot].live = 1;
  q->used++;
  q->count++;
  fc_ring_band_add(q, e->band);
  fc_ring_deadline_add(q, e->deadline_ns);
  if (slot_out)
    *slot_out = slot;
  return 0;
}

/* Lock held. The waiter an arrival of `band` would evict at the queue's
 * depth: the youngest sheddable entry, when the pool lets sheddable wait
 * (fc_shed_queue), the arrival is above sheddable and the evicted list has
 * room for one more answer. UINT32_MAX for none. */
static uint32_t
fc_ring_evict_pick(const fc_state_t *fc, uint8_t band)
{
  const fc_queue_t *q = &fc->queue;
  uint32_t i;

  if (!fc->cfg.shed_queue || fc_band_of(band) == FC_BAND_SHEDDABLE ||
      q->band_count[FC_BAND_SHEDDABLE] == 0 ||
      atomic_load_explicit(&q->n_evicted, memory_order_relaxed) >= FC_EVICT_PENDING ||
      q->used == 0)
    return UINT32_MAX;
  i = fc_ring_wrap(q, q->head + q->used - 1);
  for (uint32_t k = 0; k < q->used; k++) {
    const fc_queue_ent_t *e = &q->ring[i];
    if (e->live && e->band == FC_BAND_SHEDDABLE)
      return i;
    i = i == 0 ? q->cap - 1 : i - 1;
  }
  return UINT32_MAX;
}

/* Lock held. Take the entry at `slot` out as evicted: its place, its band
 * and its tenant's queue count go now, its answer goes on the evicted list
 * (fc_ring_evict_pick checked the room). Returns what was evicted. */
static fc_evicted_t
fc_ring_evict(fc_state_t *fc, uint32_t slot, uint64_t now_ns)
{
  fc_queue_t *q = &fc->queue;
  fc_queue_ent_t *e = &q->ring[slot];
  uint32_t n = atomic_load_explicit(&q->n_evicted, memory_order_relaxed);
  fc_evicted_t gone = { .fd = e->fd, .gen = e->gen, .at_ns = now_ns };

  e->live = 0;
  q->count--;
  fc_ring_band_sub(q, e->band);
  fc_tenant_dec(fc, e->tslot, 1);
  fc_ring_deadline_gone(q, e->deadline_ns);
  while (q->used > 0 && !q->ring[q->head].live) {
    q->head = fc_ring_wrap(q, q->head + 1);
    q->used--;
  }
  q->evicted[n] = gone;
  atomic_store_explicit(&q->n_evicted, n + 1, memory_order_relaxed);
  return gone;
}

/* Lock held. Drop entry `i` of the evicted list, keeping the order. */
static void
fc_evicted_drop(fc_queue_t *q, uint32_t i)
{
  uint32_t n = atomic_load_explicit(&q->n_evicted, memory_order_relaxed);

  for (uint32_t k = i + 1; k < n; k++)
    q->evicted[k - 1] = q->evicted[k];
  atomic_store_explicit(&q->n_evicted, n - 1, memory_order_relaxed);
}

/* Takes (fd, gen)'s entry off the evicted list. With `p`, the permit is
 * swapped QUEUED -> FC_P_EVICTED in the same hold of the queue lock: the
 * pass then decides only a wait whose entry nobody has claimed, and an
 * owner's resume can never fall between the claim and the swap. */
static int
fc_evicted_take(fc_state_t *fc, int fd, uint64_t gen, fc_permit_t *p)
{
  fc_queue_t *q;
  int won = 0;

  if (!fc || fd < 0 || fc_queue_evicted(fc) == 0)
    return 0;
  q = &fc->queue;
  pthread_mutex_lock(&q->lock);
  for (uint32_t i = 0; i < atomic_load_explicit(&q->n_evicted, memory_order_relaxed); i++) {
    if (q->evicted[i].fd == fd && q->evicted[i].gen == gen) {
      fc_evicted_drop(q, i);
      won = p ? fc_permit_settle(p, FC_P_EVICTED) : 1;
      break;
    }
  }
  pthread_mutex_unlock(&q->lock);
  return won;
}

int
fc_queue_evicted_claim(fc_state_t *fc, int fd, uint64_t gen)
{
  return fc_evicted_take(fc, fd, gen, NULL);
}

int
fc_queue_evicted_settle(fc_state_t *fc, fc_permit_t *p, int fd, uint64_t gen)
{
  return p ? fc_evicted_take(fc, fd, gen, p) : 0;
}

uint32_t
fc_queue_evicted_sweep(fc_state_t *fc, uint64_t before_ns,
                       int (*fn)(void *ctx, const fc_queue_ent_t *ent),
                       void *ctx)
{
  fc_evicted_t take[FC_EVICT_PENDING];
  fc_queue_t *q;
  uint32_t n = 0, i, answered = 0;

  if (!fc || fc_queue_evicted(fc) == 0)
    return 0;
  q = &fc->queue;
  /* The entries stay on the list while `fn` decides them: `fn` answers a
   * waiter only by taking its entry and swapping its state in one hold of
   * the queue lock (fc_queue_evicted_settle), so an owner's resume that
   * claimed the entry meanwhile leaves `fn` nothing to take. Only one sweep
   * runs at a time (PROXY_LOCK). */
  pthread_mutex_lock(&q->lock);
  for (i = 0; i < atomic_load_explicit(&q->n_evicted, memory_order_relaxed); i++)
    if (q->evicted[i].at_ns <= before_ns)
      take[n++] = q->evicted[i];
  pthread_mutex_unlock(&q->lock);
  for (i = 0; i < n; i++) {
    fc_queue_ent_t e = { .fd = take[i].fd, .band = FC_BAND_SHEDDABLE,
                         .tslot = -1, .gen = take[i].gen };
    if (fn && fn(ctx, &e))
      answered++;
  }
  /* Decided either way now (answered here, claimed by its owner, or its
   * connection gone): off the list, whatever is still on it. The same
   * eviction only (its time too): a later request on the same connection,
   * evicted meanwhile under the same (fd, gen), stays owed. */
  pthread_mutex_lock(&q->lock);
  for (i = 0; i < n; i++) {
    for (uint32_t k = 0; k < atomic_load_explicit(&q->n_evicted, memory_order_relaxed); k++) {
      if (q->evicted[k].fd == take[i].fd && q->evicted[k].gen == take[i].gen &&
          q->evicted[k].at_ns == take[i].at_ns) {
        fc_evicted_drop(q, k);
        break;
      }
    }
  }
  pthread_mutex_unlock(&q->lock);
  return answered;
}

int
fc_queue_push(fc_state_t *fc, fc_permit_t *p, int fd, uint64_t gen,
              uint64_t now_ns, int front)
{
  fc_queue_ent_t e;
  uint32_t slot = 0;
  uint64_t first_deadline = 0;
  uint64_t tkey;
  uint8_t band;
  int tslot = -1;
  int rc = -1;
  uint32_t evict = UINT32_MAX;
  fc_evicted_t gone = { .fd = -1 };
  uint64_t gone_enq_ns = 0;
  int evicted = 0;
  int band_full = 0;
  uint8_t parked;
  uint8_t ttl_cut;
  uint32_t ttl_ms;
  uint64_t first_ns;
  uint64_t at_ns = now_ns;       /* now, whatever time the entry is given */
  int ordered = 0;

  if (!fc || !p || fd < 0)
    return -1;
  tkey = p->tkey;
  band = p->band;
  /* A request moved here from the P/D prefill park, where it waited first,
   * keeps that wait: it takes its place among the waiters by when it first
   * parked, and its window and its queue-wait sample count from then. Asked
   * of this push only (the bind below clears it). An eviction it causes is
   * decided now, and timed from now. */
  first_ns = p->q_first_ns;
  if (!front && first_ns && first_ns < now_ns) {
    now_ns = first_ns;
    ordered = 1;
  }
  /* The client's TTL is asked of this push only (the bind below clears it);
   * a request going back to its place keeps the deadline it was first given
   * and whose it was. */
  ttl_ms = p->q_ttl_ms;
  ttl_cut = front ? p->q_ttl_cut : 0;
  /* A request going back to its place is still in its first park. */
  parked = front ? p->q_parked : 1;
  /* A woken request going back is still bounded by its first window, and
   * takes its place among the waiters by when it first arrived. */
  if (front && p->q_deadline_ns) {
    now_ns = p->q_enqueue_ns;
    first_deadline = p->q_deadline_ns;
  }
  e.fd = fd;
  e.live = 1;
  e.band = band;
  e.tslot = -1;
  e.gen = gen;
  e.enqueue_ns = now_ns;

  /* The permit is QUEUED before the entry is published: a drain or a
   * deadline on another thread that pops the entry the moment the lock is
   * dropped must find a waiting permit, not the one it replaces. */
  fc_permit_bind(p, fc);
  p->state = FC_P_QUEUED;
  p->q_fd = fd;
  p->q_gen = gen;
  p->q_enqueue_ns = now_ns;
  p->tkey = tkey;
  p->band = band;
  /* Set before the entry is published, like the state: a deadline on
   * another thread may end the park at once. */
  p->q_parked = parked;

  pthread_mutex_lock(&fc->queue.lock);
  if (!first_deadline) {
    /* The band's window, held inside the rule's; a client's TTL (with
     * fc_llmd_headers on) only ever shortens it. */
    uint32_t window_ms = fc_band_wait_ms(fc, band);

    if (fc->cfg.llmd_headers && ttl_ms && ttl_ms < window_ms) {
      window_ms = ttl_ms;
      ttl_cut = 1;
    }
    first_deadline = now_ns + (uint64_t)window_ms * 1000000ULL;
  }
  e.deadline_ns = first_deadline;
  p->q_deadline_ns = e.deadline_ns;
  p->q_ttl_cut = ttl_cut;
  /* A band at its own share of the depth is refused as a full queue: no
   * other band's waiter makes room in it, so nobody is evicted for it. */
  if (!front && !fc->queue.dead && fc_queue_enabled(fc)) {
    uint32_t bound = fc_band_queue_bound(fc, band);

    band_full = bound && fc_band_live(&fc->queue, band) >= bound;
  }
  /* At its depth, a request above sheddable may take the place of a
   * sheddable waiter (fc_shed_queue): one is chosen now, and evicted only
   * once this request is sure to take its place. */
  if (!front && !fc->queue.dead && fc_queue_enabled(fc) &&
      fc->queue.count >= fc->cfg.max_queue_depth &&
      first_deadline > at_ns)        /* one whose window is over takes nobody's place */
    evict = fc_ring_evict_pick(fc, band);
  if (!band_full && !fc->queue.dead && fc_queue_enabled(fc) &&
      (front || fc->queue.count < fc->cfg.max_queue_depth ||
       evict != UINT32_MAX)) {
    if (fc_tenants_tracked(fc)) {
      uint32_t qbound = fc_tenant_queue_bound(fc);
      tslot = fc_tenant_get(fc, tkey, 0);
      /* A request going back to the head already held its place. */
      if (tslot >= 0 && !front && qbound &&
          fc->tenants[tslot].queued >= qbound)
        rc = -2;
      e.tslot = (int16_t)tslot;
    }
    if (rc != -2 && evict != UINT32_MAX) {
      gone_enq_ns = fc->queue.ring[evict].enqueue_ns;
      gone = fc_ring_evict(fc, evict, at_ns);
      evicted = 1;
    }
    if (rc != -2)
      rc = fc_ring_insert(&fc->queue, &e, front, ordered, &slot);
    if (tslot >= 0) {
      if (rc == 0) {
        fc->tenants[tslot].queued++;
        fc_tenant_mark(fc, &fc->tenants[tslot]);
      } else {
        fc_tenant_put(fc, tslot);
      }
    }
  }
  if (rc == 0)
    p->q_slot = slot;
  if (rc == 0 || evicted)
    fc_queue_publish(fc);
  pthread_mutex_unlock(&fc->queue.lock);

  /* The park's deadline is met by the timer: set to it now when it is the
   * earliest pending (a no-op in a process without the timer). */
  if (rc == 0)
    fc_deadline_arm(fc_deadline_global(), e.deadline_ns, at_ns);
  if (evicted) {
    /* Counted where it was decided; answered on its own connection by its
     * owner worker, which claims it on this wake. A wake that cannot be
     * queued leaves it to the 1 Hz pass. */
    fc_count_band(fc, FC_R_SHED, FC_BAND_SHEDDABLE);
    /* Its park ends here (its owner only answers it): observed here. */
    fc_note_wait(fc, at_ns > gone_enq_ns ? (at_ns - gone_enq_ns) / 1000000ULL : 0);
    if (fc_wake_hook)
      (void)fc_wake_hook(gone.fd, gone.gen);
  }
  if (rc != 0) {
    fc_permit_bind(p, fc);
    p->tkey = tkey;
    p->band = band;
    p->q_parked = front ? parked : 0;
    fc_count(fc, rc == -2 ? FC_R_TENANT_SHARE : FC_R_QUEUE_FULL);
    return rc == -2 ? -2 : -1;
  }
  /* A request going back to the head is the same park. */
  if (!front)
    fc_count_band(fc, FC_R_QUEUED, band);
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
  /* The request is decided here, before its entry goes: an owner's resume
   * that finds the entry gone then finds the permit out of QUEUED too. */
  if (slot != UINT32_MAX && fc_permit_settle(p, FC_P_ENDED)) {
    fc->queue.ring[slot].live = 0;
    fc->queue.count--;
    fc_ring_band_sub(&fc->queue, fc->queue.ring[slot].band);
    fc_tenant_dec(fc, fc->queue.ring[slot].tslot, 1);
    fc_ring_deadline_gone(&fc->queue, fc->queue.ring[slot].deadline_ns);
    taken = 1;
    /* A tombstone at the head is dead weight: drop it now. */
    while (fc->queue.used > 0 && !fc->queue.ring[fc->queue.head].live) {
      fc->queue.head = fc_ring_wrap(&fc->queue, fc->queue.head + 1);
      fc->queue.used--;
    }
    fc_queue_publish(fc);
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
      fc_ring_band_sub(q, e->band);
      fc_ring_deadline_gone(q, e->deadline_ns);
      return 1;
    }
  }
  return 0;
}

int
fc_queue_pop(fc_state_t *fc, fc_queue_ent_t *out)
{
  fc_queue_ent_t e;
  int rc;

  if (!fc)
    return 0;
  pthread_mutex_lock(&fc->queue.lock);
  rc = fc_ring_pop(&fc->queue, &e);
  if (rc)
    fc_tenant_dec(fc, e.tslot, 1);
  fc_queue_publish(fc);
  pthread_mutex_unlock(&fc->queue.lock);
  if (rc && out)
    *out = e;
  return rc;
}

/* Lock held. Take the live entry at ring index `at` out of the queue. */
static void
fc_ring_take_at(fc_queue_t *q, uint32_t at, fc_queue_ent_t *out)
{
  fc_queue_ent_t *e = &q->ring[at];

  *out = *e;
  e->live = 0;
  q->count--;
  fc_ring_band_sub(q, e->band);
  fc_ring_deadline_gone(q, e->deadline_ns);
  while (q->used > 0 && !q->ring[q->head].live) {
    q->head = fc_ring_wrap(q, q->head + 1);
    q->used--;
  }
}

/* What a pick spent, so a wake that cannot be delivered gives it back. */
typedef struct fc_pick_undo {
  int      band;                 /* -1: nothing was spent */
  int      credit;               /* a weighted credit */
  int      rr;                   /* the tenant order moved */
  uint32_t rr_before;
  uint32_t rr_after;
} fc_pick_undo_t;

/* The tenant slot an entry belongs to in the round-robin order; an entry
 * with none is one more tenant, last. */
static inline uint32_t
fc_rr_key(const fc_queue_ent_t *e)
{
  return e->tslot < 0 ? 0x7fffffffu : (uint32_t)e->tslot;
}

/* Lock held. The entry of `band` to take out next, among those whose tenant
 * could take a unit now: the oldest (fifo), or the oldest of the next tenant
 * in turn (rr: the lowest tenant slot from the band's cursor round to the
 * first one again; inside one tenant the oldest first). UINT32_MAX for none. */
static uint32_t
fc_ring_pick_in_band(const fc_state_t *fc, uint8_t band, uint32_t bound)
{
  const fc_queue_t *q = &fc->queue;
  uint32_t i = q->head, first = UINT32_MAX, after = UINT32_MAX, wrap = UINT32_MAX;
  uint32_t after_key = 0, wrap_key = 0;
  int rr = fc->cfg.tenant_wake == FC_TENANT_WAKE_RR;

  for (uint32_t k = 0; k < q->used; k++) {
    const fc_queue_ent_t *e = &q->ring[i];

    if (e->live && fc_band_of(e->band) == band &&
        fc_tenant_can_run(fc, e->tslot, bound)) {
      uint32_t key;

      if (!rr)
        return i;
      if (first == UINT32_MAX)
        first = i;
      key = fc_rr_key(e);
      if (key >= q->rr_next[band] && (after == UINT32_MAX || key < after_key)) {
        after = i;
        after_key = key;
      }
      if (wrap == UINT32_MAX || key < wrap_key) {
        wrap = i;
        wrap_key = key;
      }
    }
    i = fc_ring_wrap(q, i + 1);
  }
  return after != UINT32_MAX ? after : wrap;
}

/* Lock held. Deficit round robin over the bands that have an entry that can
 * be taken (cand): the highest band with credit left is served and spends
 * one; when no such band has credit left the round starts again, each band
 * with a candidate getting its weight, a band with none forfeiting its turn.
 * A band with a candidate and a zero weight is given one (the control plane
 * refuses it; the pick never stalls on it). Returns the band, -1 for none. */
static int
fc_drr_pick(fc_state_t *fc, const uint8_t cand[FC_BANDS], fc_pick_undo_t *u)
{
  fc_queue_t *q = &fc->queue;

  for (int pass = 0; pass < 2; pass++) {
    for (int r = 0; r < FC_BANDS; r++) {
      uint8_t b = fc_band_at_rank(r);

      if (cand[b] && q->drr_credit[b] > 0) {
        q->drr_credit[b]--;
        u->credit = 1;
        return b;
      }
    }
    if (pass == 0)
      for (int b = 0; b < FC_BANDS; b++)
        q->drr_credit[b] = cand[b] ? (fc->cfg.band_weight[b] ? fc->cfg.band_weight[b] : 1) : 0;
  }
  return -1;
}

/* Lock held. Take out the entry the wake gives the next unit to; its tenant's
 * queue count is left for the caller to settle once the wake is delivered: an
 * entry put back keeps its slot counted, so the slot is never reused under it.
 *
 * The plain pool (strict, fifo, no floor) takes the oldest entry whose tenant
 * could take a unit now, or under strict with a waiter of a band other than
 * standard the oldest such entry of the highest band that has one. Anything
 * else goes through the bands: the band is chosen first (a band below its
 * floor, then the policy: strict takes the highest, weighted runs its
 * rounds), then the entry inside it (fifo or the tenants in turn). `pend`
 * counts the units this wake loop has already promised. */
static int
fc_ring_pop_banded(fc_state_t *fc, fc_queue_ent_t *out, const uint32_t pend[FC_BANDS],
                   int floors, fc_pick_undo_t *u)
{
  fc_queue_t *q = &fc->queue;
  uint32_t bound = fc_tenant_svc_bound(fc);
  uint8_t wait[FC_BANDS] = {0}, ok[FC_BANDS];
  fc_floor_view_t v;
  int pick = -1;
  uint32_t idx, i = q->head;

  for (uint32_t k = 0; k < q->used; k++) {
    const fc_queue_ent_t *e = &q->ring[i];

    if (e->live && fc_tenant_can_run(fc, e->tslot, bound))
      wait[fc_band_of(e->band)] = 1;
    i = fc_ring_wrap(q, i + 1);
  }
  if (floors)
    fc_floor_view_load(fc, &v, fc_svc_cap(fc), pend, wait);
  for (int b = 0; b < FC_BANDS; b++)
    ok[b] = wait[b] && (!floors || fc_floor_may_take(&v, (uint8_t)b));
  for (int r = 0; r < FC_BANDS && pick < 0 && floors; r++) {
    uint8_t b = fc_band_at_rank(r);

    if (wait[b] && v.in[b] < v.claim[b] && fc_floor_may_take(&v, b))
      pick = b;
  }
  if (pick < 0 && fc_wake_strict(fc)) {
    for (int r = 0; r < FC_BANDS && pick < 0; r++) {
      uint8_t b = fc_band_at_rank(r);

      if (ok[b])
        pick = b;
    }
  } else if (pick < 0) {
    pick = fc_drr_pick(fc, ok, u);
  }
  if (pick < 0)
    return 0;
  idx = fc_ring_pick_in_band(fc, (uint8_t)pick, bound);
  if (idx == UINT32_MAX)
    return 0;
  u->band = pick;
  fc_ring_take_at(q, idx, out);
  if (fc->cfg.tenant_wake == FC_TENANT_WAKE_RR) {
    u->rr = 1;
    u->rr_before = q->rr_next[pick];
    q->rr_next[pick] = fc_rr_key(out) + 1;
    u->rr_after = q->rr_next[pick];
  }
  return 1;
}

static int
fc_ring_pop_runnable(fc_state_t *fc, fc_queue_ent_t *out, const uint32_t pend[FC_BANDS],
                     fc_pick_undo_t *u)
{
  fc_queue_t *q = &fc->queue;
  uint32_t bound = fc_tenant_svc_bound(fc);
  uint32_t i = q->head, best = UINT32_MAX;
  int banded = q->band_count[FC_BAND_CRITICAL] || q->band_count[FC_BAND_SHEDDABLE];
  int best_rank = FC_BANDS;
  int floors = fc_floors_apply(fc, fc_svc_cap(fc));
  fc_queue_ent_t *e;

  u->band = -1;
  u->credit = u->rr = 0;
  if (floors || !fc_wake_strict(fc) || fc->cfg.tenant_wake == FC_TENANT_WAKE_RR)
    return fc_ring_pop_banded(fc, out, pend, floors, u);
  for (uint32_t k = 0; k < q->used; k++) {
    e = &q->ring[i];
    if (e->live && fc_tenant_can_run(fc, e->tslot, bound)) {
      int r = banded ? fc_band_rank(e->band) : 0;

      if (r < best_rank) {
        best = i;
        best_rank = r;
        if (r == 0)
          break;
      }
    }
    i = fc_ring_wrap(q, i + 1);
  }
  if (best == UINT32_MAX)
    return 0;
  fc_ring_take_at(q, best, out);
  return 1;
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

int
fc_queue_resumed(fc_state_t *fc, fc_permit_t *p, uint64_t now_ns)
{
  (void)fc;
  (void)now_ns;
  if (!p || !fc_permit_settle(p, FC_P_NONE))
    return 0;
  /* Not the end of the park: the woken request may go back to its place.
   * Its wait is observed when the park ends (fc_queue_wait_end). */
  p->woken = 1;
  return 1;
}

int
fc_queue_owner_resume(fc_state_t *fc, fc_permit_t *p, uint64_t now_ns)
{
  uint8_t st;

  if (!p)
    return FC_RESUME_NOT_QUEUED;
  st = atomic_load_explicit(&p->state, memory_order_acquire);
  if (st == FC_P_EVICTED || st == FC_P_ENDED)
    return FC_RESUME_DECIDED;
  if (st != FC_P_QUEUED || !fc)
    return FC_RESUME_NOT_QUEUED;
  /* Evicted for a higher band: the answer is the owner's if it takes the
   * entry off the evicted list and swaps the state before the 1 Hz pass
   * does; the pass swaps first only when it has the entry in hand. */
  if (fc_queue_evicted_claim(fc, p->q_fd, p->q_gen)) {
    if (!fc_permit_settle(p, FC_P_NONE))
      return FC_RESUME_DECIDED;
    p->woken = 0;
    p->q_parked = 0;               /* observed where it was evicted */
    return FC_RESUME_EVICTED;
  }
  /* The queue pops an entry before it wakes the connection: an entry still
   * waiting means this resume is not its turn. */
  if (fc_queue_holds(fc, p))
    return FC_RESUME_WAIT;
  /* Popped for its turn, unless a path that ends a wait took it first: then
   * that path swapped the state already and this resume is late. */
  return fc_queue_resumed(fc, p, now_ns) ? FC_RESUME_TURN : FC_RESUME_DECIDED;
}

void
fc_queue_wait_end(fc_state_t *fc, fc_permit_t *p, uint64_t now_ns)
{
  if (!fc || !p || !p->q_parked)
    return;
  p->q_parked = 0;
  fc_note_wait(fc, now_ns > p->q_enqueue_ns ? (now_ns - p->q_enqueue_ns) / 1000000ULL : 0);
}

/* Pop the head and wake its owner. 0 when nobody was popped or the wake
 * could not be delivered. */
static int
fc_queue_wake_head(fc_state_t *fc, uint32_t pend[FC_BANDS])
{
  fc_queue_ent_t e;
  fc_pick_undo_t u;
  int rc;

  pthread_mutex_lock(&fc->queue.lock);
  rc = fc_ring_pop_runnable(fc, &e, pend, &u);
  fc_queue_publish(fc);
  pthread_mutex_unlock(&fc->queue.lock);
  if (!rc)
    return 0;
  if (fc_wake_hook(e.fd, e.gen) != 0) {
    /* The owner could not be woken now: the request keeps its place at
     * the head and the next released unit tries again. Its deadline is
     * unchanged, so the wait stays bounded. */
    pthread_mutex_lock(&fc->queue.lock);
    if (fc_ring_insert(&fc->queue, &e, 1, 0, NULL) != 0)
      fc_tenant_dec(fc, e.tslot, 1);
    else
      fc_deadline_arm(fc_deadline_global(), e.deadline_ns, fc_now_ns());
    /* What the pick spent is given back, if nothing moved it since. */
    if (u.band >= 0) {
      if (u.credit && fc->queue.drr_credit[u.band] < FC_BAND_WEIGHT_MAX + 2)
        fc->queue.drr_credit[u.band]++;
      if (u.rr && fc->queue.rr_next[u.band] == u.rr_after)
        fc->queue.rr_next[u.band] = u.rr_before;
    }
    fc_queue_publish(fc);
    pthread_mutex_unlock(&fc->queue.lock);
    return 0;
  }
  pthread_mutex_lock(&fc->queue.lock);
  fc_tenant_dec(fc, e.tslot, 1);
  pthread_mutex_unlock(&fc->queue.lock);
  pend[fc_band_of(e.band)]++;
  return 1;
}

void
fc_queue_wake_one(fc_state_t *fc)
{
  uint32_t pend[FC_BANDS] = {0};

  if (!fc || !fc_wake_hook)
    return;
  if (fc_queued(fc) == 0 || !fc_has_room(fc))
    return;
  (void)fc_queue_wake_head(fc, pend);
}

void
fc_queue_wake_room(fc_state_t *fc)
{
  uint32_t n, cap, inflight;
  uint32_t pend[FC_BANDS] = {0};

  if (!fc || !fc_wake_hook)
    return;
  n = fc_queued(fc);
  if (n == 0)
    return;
  /* A woken request takes its unit when its worker runs, not now, so the
   * units free at this moment bound how many turns are given; a woken one
   * that still meets a ceiling (an endpoint's) goes back to the head. */
  cap = fc_svc_cap(fc);
  if (fc->cfg.mode == FC_MODE_ENFORCE && cap != 0) {
    inflight = fc_inflight(fc);
    if (inflight >= cap)
      return;
    if (cap - inflight < n)
      n = cap - inflight;
  }
  while (n-- > 0) {
    if (!fc_queue_wake_head(fc, pend))
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
fc_queue_visit(fc_state_t *fc, fc_visit_fn fn, void *ctx)
{
  fc_queue_t *q;
  uint32_t i, n = 0;

  if (!fc || !fn)
    return 0;
  q = &fc->queue;
  pthread_mutex_lock(&q->lock);
  if (q->cap > 0) {
    i = q->head;
    for (uint32_t k = 0; k < q->used; k++) {
      const fc_queue_ent_t *e = &q->ring[i];
      if (e->live) {
        fn(ctx, e);
        n++;
      }
      i = fc_ring_wrap(q, i + 1);
    }
  }
  pthread_mutex_unlock(&q->lock);
  return n;
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

/* ---- adaptive ceiling and warm-up ------------------------------------------ */

uint32_t
fc_ep_cap_now(const fc_state_t *fc, int ep, int role, uint64_t now_ns)
{
  uint32_t cap, floor, win;
  uint64_t since, elapsed_ms;

  if (!fc || role < 0 || role >= FC_ROLES)
    return 0;
  cap = fc->cfg.ep_cap[role];
  win = fc->cfg.warmup_ms;
  if (cap == 0 || win == 0 || ep < 0 || ep >= FC_MAX_EP)
    return cap;
  since = atomic_load_explicit(&fc->warm_since_ns[ep], memory_order_relaxed);
  if (since == 0)
    return cap;
  if (now_ns == 0)
    now_ns = fc_now_ns();
  if (now_ns <= since)
    elapsed_ms = 0;
  else
    elapsed_ms = (now_ns - since) / 1000000ULL;
  if (elapsed_ms >= win)
    return cap;
  floor = cap / 4 ? cap / 4 : 1;
  return floor + (uint32_t)((uint64_t)(cap - floor) * elapsed_ms / win);
}

void
fc_ep_warm_start(fc_state_t *fc, int ep, uint64_t now_ns)
{
  if (!fc || ep < 0 || ep >= FC_MAX_EP || fc->cfg.warmup_ms == 0)
    return;
  if (now_ns == 0)
    now_ns = fc_now_ns();
  atomic_store_explicit(&fc->warm_since_ns[ep], now_ns, memory_order_relaxed);
}

uint32_t
fc_warming_eps(const fc_state_t *fc, uint64_t now_ns)
{
  uint32_t n = 0;
  uint64_t win_ns;

  if (!fc || fc->cfg.warmup_ms == 0)
    return 0;
  win_ns = (uint64_t)fc->cfg.warmup_ms * 1000000ULL;
  for (int e = 0; e < FC_MAX_EP; e++) {
    uint64_t since = atomic_load_explicit(&fc->warm_since_ns[e],
                                          memory_order_relaxed);
    if (since != 0 && (now_ns <= since || now_ns - since < win_ns))
      n++;
  }
  return n;
}

void
fc_ttft_sample(fc_state_t *fc, int ep, uint32_t ms, uint64_t now_ns)
{
  uint32_t old, next;

  if (!fc || ep < 0 || ep >= FC_MAX_EP)
    return;
  if (now_ns == 0)
    now_ns = fc_now_ns();
  old = atomic_load_explicit(&fc->ttft_ewma_ms[ep], memory_order_relaxed);
  /* The first sample, or the first after the estimate went stale, starts
   * it over: an average carried across a silence describes nothing. */
  if (old == 0 || !fc_ttft_fresh(fc, ep, now_ns))
    next = ms ? ms : 1;
  else
    next = (uint32_t)(((uint64_t)old * 7 + ms + 7) / 8);
  atomic_store_explicit(&fc->ttft_ewma_ms[ep], next, memory_order_relaxed);
  atomic_store_explicit(&fc->ttft_ts_ns[ep], now_ns, memory_order_relaxed);
}

void
fc_permit_ttft(fc_permit_t *p)
{
  fc_state_t *fc;
  int ep;
  uint64_t now;

  if (!p || p->state != FC_P_EXECUTING || !p->fc || p->admit_ns == 0)
    return;
  fc = p->fc;
  if (fc->cfg.ttft_target_ms == 0)
    return;
  ep = p->ep[FC_ROLE_DECODE] >= 0 ? p->ep[FC_ROLE_DECODE] : p->ep[FC_ROLE_NORMAL];
  if (ep < 0)
    return;
  now = fc_now_ns();
  if (now <= p->admit_ns)
    return;
  fc_ttft_sample(fc, ep, (uint32_t)((now - p->admit_ns) / 1000000ULL), now);
}

int
fc_ttft_fresh(const fc_state_t *fc, int ep, uint64_t now_ns)
{
  uint64_t ts;

  if (!fc || ep < 0 || ep >= FC_MAX_EP)
    return 0;
  ts = atomic_load_explicit(&fc->ttft_ts_ns[ep], memory_order_relaxed);
  if (ts == 0)
    return 0;
  return now_ns <= ts ||
         now_ns - ts <= (uint64_t)fc->cfg.telemetry_stale_ms * 1000000ULL;
}

int
fc_ttft_over(const fc_state_t *fc, int ep, uint64_t now_ns, int *fresh)
{
  int f;

  if (fresh)
    *fresh = 0;
  if (!fc || fc->cfg.ttft_target_ms == 0)
    return 0;
  f = fc_ttft_fresh(fc, ep, now_ns);
  if (fresh)
    *fresh = f;
  return f && atomic_load_explicit(&fc->ttft_ewma_ms[ep], memory_order_relaxed) >
              fc->cfg.ttft_target_ms;
}

void
fc_adapt_tick(fc_state_t *fc, const fc_signal_t *sig)
{
  uint32_t ceil, eff, floor, next;
  uint8_t reason;

  if (!fc || !sig || !fc->cfg.adaptive || fc->cfg.max_outstanding == 0)
    return;
  ceil = fc->cfg.max_outstanding;
  eff = atomic_load_explicit(&fc->eff_max, memory_order_relaxed);
  if (eff == 0 || eff > ceil)
    eff = ceil;
  floor = ceil / 4 ? ceil / 4 : 1;
  if (!sig->fresh) {
    /* Nothing to go on: hold. A stale signal never widens. */
    atomic_store_explicit(&fc->adapt_state,
                          eff < ceil ? FC_AS_FROZEN : FC_AS_OPEN,
                          memory_order_relaxed);
    if (eff < ceil)
      atomic_store_explicit(&fc->adapt_reason, FC_AR_STALE, memory_order_relaxed);
    return;
  }
  if (sig->queued || sig->ttft_over) {
    reason = sig->queued ? FC_AR_QUEUED : FC_AR_TTFT;
    next = (uint32_t)((uint64_t)eff * 4 / 5);
    if (next < floor)
      next = floor;
    if (next < eff) {
      atomic_store_explicit(&fc->eff_max, next, memory_order_relaxed);
      atomic_fetch_add_explicit(&fc->adapt_moves[0], 1, memory_order_relaxed);
    }
    atomic_store_explicit(&fc->adapt_reason, reason, memory_order_relaxed);
    atomic_store_explicit(&fc->adapt_state,
                          next < ceil ? FC_AS_TIGHTENED : FC_AS_OPEN,
                          memory_order_relaxed);
    return;
  }
  if (eff < ceil) {
    atomic_store_explicit(&fc->eff_max, eff + 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&fc->adapt_moves[1], 1, memory_order_relaxed);
    atomic_store_explicit(&fc->adapt_reason, FC_AR_CLEAR, memory_order_relaxed);
    eff++;
  }
  atomic_store_explicit(&fc->adapt_state,
                        eff < ceil ? FC_AS_TIGHTENED : FC_AS_OPEN,
                        memory_order_relaxed);
  /* The unit given back is a turn for the oldest waiting request. */
  fc_queue_wake_room(fc);
}

/* ---- admission headers on admitted responses ----------------------------- */

int
fc_expose_take(const fc_permit_t *p, fc_expose_t *out)
{
  const fc_state_t *fc;

  if (!p || p->state != FC_P_EXECUTING || !p->fc)
    return 0;
  fc = p->fc;
  if (!fc_active(fc) || !fc->cfg.expose_headers)
    return 0;
  if (out) {
    out->inflight = fc_inflight(fc);
    out->queued = fc_queued(fc);
    out->limit = fc_svc_cap(fc);
  }
  return 1;
}

#define FC_EXPOSE_NAME "x-loxilb-admission-"
#define FC_EXPOSE_NAME_LEN (sizeof(FC_EXPOSE_NAME) - 1)

/* The end of the header block (the offset of its blank line's CRLF), or 0
 * when the buffer does not hold all of it. */
static size_t
fc_h1_head_end(const uint8_t *buf, size_t len)
{
  for (size_t i = 0; i + 3 < len; i++) {
    if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' &&
        buf[i + 3] == '\n')
      return i + 2;
  }
  return 0;
}

size_t
fc_expose_h1(uint8_t *buf, size_t len, size_t cap, const fc_expose_t *v,
             int *res)
{
  char add[3 * 64];
  size_t end, i, n;
  int alen, status;

  if (res)
    *res = FC_EXPOSE_H1_SKIPPED;
  if (!buf || !v || len < 12 || memcmp(buf, "HTTP/1.", 7) != 0 ||
      buf[8] != ' ' || buf[9] < '1' || buf[9] > '5' ||
      buf[10] < '0' || buf[10] > '9' || buf[11] < '0' || buf[11] > '9')
    return len;
  status = (buf[9] - '0') * 100 + (buf[10] - '0') * 10 + (buf[11] - '0');
  if (status < 200) {
    /* An interim response: the final one still follows and carries them. */
    if (res)
      *res = FC_EXPOSE_H1_INTERIM;
    return len;
  }
  end = fc_h1_head_end(buf, len);
  if (end == 0)
    return len;

  /* The values are the gateway's own: a backend's lines of the same names
   * go, so a client never reads two answers. */
  i = 0;
  while (i < end && !(buf[i] == '\r' && buf[i + 1] == '\n'))
    i++;
  i += 2;                                   /* past the status line */
  while (i < end) {
    size_t eol = i;
    while (eol < end && !(buf[eol] == '\r' && buf[eol + 1] == '\n'))
      eol++;
    eol += 2;
    if (eol - i > FC_EXPOSE_NAME_LEN &&
        !strncasecmp((const char *)buf + i, FC_EXPOSE_NAME, FC_EXPOSE_NAME_LEN)) {
      memmove(buf + i, buf + eol, len - eol);
      len -= eol - i;
      end -= eol - i;
      continue;
    }
    i = eol;
  }

  alen = snprintf(add, sizeof(add),
                  "X-Loxilb-Admission-Inflight: %u\r\n"
                  "X-Loxilb-Admission-Queued: %u\r\n"
                  "X-Loxilb-Admission-Limit: %u\r\n",
                  v->inflight, v->queued, v->limit);
  if (alen <= 0 || (size_t)alen >= sizeof(add))
    return len;
  n = (size_t)alen;
  if (len + n > cap)
    return len;
  memmove(buf + end + n, buf + end, len - end);
  memcpy(buf + end, add, n);
  if (res)
    *res = FC_EXPOSE_H1_DONE;
  return len + n;
}

/* ---- queue deadlines ------------------------------------------------------ */

static fc_deadline_t fc_deadline_proc;

fc_deadline_t *
fc_deadline_global(void)
{
  return &fc_deadline_proc;
}

uint64_t
fc_queue_next_deadline(const fc_state_t *fc)
{
  if (!fc)
    return 0;
  return atomic_load_explicit(&fc->queue.next_deadline_ns, memory_order_acquire);
}

uint32_t
fc_queue_expired(fc_state_t *fc, uint64_t now_ns, fc_queue_ent_t *out, uint32_t cap)
{
  fc_queue_t *q;
  uint32_t i, n = 0;

  if (!fc || !out || cap == 0)
    return 0;
  q = &fc->queue;
  pthread_mutex_lock(&q->lock);
  if (q->cap > 0) {
    i = q->head;
    for (uint32_t k = 0; k < q->used && n < cap; k++) {
      const fc_queue_ent_t *e = &q->ring[i];
      if (e->live && e->deadline_ns && e->deadline_ns <= now_ns)
        out[n++] = *e;
      i = fc_ring_wrap(q, i + 1);
    }
  }
  pthread_mutex_unlock(&q->lock);
  return n;
}

int
fc_deadline_init(fc_deadline_t *d)
{
  if (!d)
    return -1;
  atomic_store_explicit(&d->armed_ns, 0, memory_order_relaxed);
  atomic_store_explicit(&d->last_fire_ns, 0, memory_order_relaxed);
  atomic_store_explicit(&d->wakeups, 0, memory_order_relaxed);
  atomic_store_explicit(&d->passes, 0, memory_order_relaxed);
  d->tfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
  return d->tfd > 0 ? 0 : -1;
}

void
fc_deadline_close(fc_deadline_t *d)
{
  if (!d)
    return;
  if (d->tfd > 0)
    close(d->tfd);
  d->tfd = 0;
  atomic_store_explicit(&d->armed_ns, 0, memory_order_relaxed);
}

/* The timer is set to `target`, and set again while another thread lowered
 * armed_ns under this one's call: the last word is the earliest. */
static void
fc_deadline_settime(fc_deadline_t *d, uint64_t target)
{
  for (;;) {
    struct itimerspec its;
    uint64_t cur;

    memset(&its, 0, sizeof(its));
    its.it_value.tv_sec = (time_t)(target / 1000000000ULL);
    its.it_value.tv_nsec = (long)(target % 1000000000ULL);
    (void)timerfd_settime(d->tfd, TFD_TIMER_ABSTIME, &its, NULL);
    cur = atomic_load_explicit(&d->armed_ns, memory_order_acquire);
    if (cur == target || cur == 0)
      return;
    target = cur;
  }
}

void
fc_deadline_arm(fc_deadline_t *d, uint64_t deadline_ns, uint64_t now_ns)
{
  uint64_t cur, target, floor;

  (void)now_ns;
  if (!d || d->tfd <= 0 || deadline_ns == 0)
    return;
  /* Never before the last firing plus the grain: a burst of parks a few
   * microseconds apart is one wake-up, not one each. A deadline already past
   * is set as it is: an absolute time in the past fires at once. */
  floor = atomic_load_explicit(&d->last_fire_ns, memory_order_relaxed);
  floor = floor ? floor + FC_DEADLINE_GRAIN_NS : 0;
  target = deadline_ns > floor ? deadline_ns : floor;
  cur = atomic_load_explicit(&d->armed_ns, memory_order_acquire);
  do {
    if (cur && cur <= target)
      return;                    /* set for an earlier time already */
  } while (!atomic_compare_exchange_weak_explicit(&d->armed_ns, &cur, target,
                                                  memory_order_acq_rel,
                                                  memory_order_acquire));
  fc_deadline_settime(d, target);
}

int
fc_deadline_wait(fc_deadline_t *d, int max_wait_ms)
{
  struct pollfd pfd;
  uint64_t n = 0;
  int rc;

  if (!d || d->tfd <= 0)
    return -1;
  pfd.fd = d->tfd;
  pfd.events = POLLIN;
  pfd.revents = 0;
  rc = poll(&pfd, 1, max_wait_ms);
  if (rc < 0)
    return errno == EINTR ? 0 : -1;
  if (rc == 0)
    return 0;
  if (read(d->tfd, &n, sizeof(n)) != (ssize_t)sizeof(n))
    return 0;                    /* a spurious readiness: nothing fired */
  atomic_fetch_add_explicit(&d->wakeups, 1, memory_order_relaxed);
  return 1;
}

typedef struct fc_deadline_pass_ctx {
  uint64_t now_ns;
  uint64_t earliest;
  fc_expire_fn expire;
  void *ctx;
} fc_deadline_pass_ctx_t;

static void
fc_deadline_visit_pool(void *vctx, fc_state_t *fc)
{
  fc_deadline_pass_ctx_t *c = vctx;
  uint64_t next = fc_queue_next_deadline(fc);

  if (next && next <= c->now_ns) {
    /* This pool's earliest deadline has passed: its queue, and only its
     * queue, is read for the entries past theirs. Bounded batches, in case
     * an expire leaves an entry where it is. */
    fc_queue_ent_t batch[64];
    uint32_t n;
    int rounds = 0;

    do {
      n = fc_queue_expired(fc, c->now_ns, batch, 64);
      for (uint32_t i = 0; i < n; i++)
        if (c->expire)
          c->expire(c->ctx, fc, &batch[i], c->now_ns);
    } while (n == 64 && ++rounds < 16 &&
             fc_queue_next_deadline(fc) &&
             fc_queue_next_deadline(fc) <= c->now_ns);
    next = fc_queue_next_deadline(fc);
    if (next && next <= c->now_ns)
      next = c->now_ns + FC_DEADLINE_GRAIN_NS;   /* left in place: again at the next grain */
  }
  if (next && (!c->earliest || next < c->earliest))
    c->earliest = next;
}

uint64_t
fc_deadline_pass(fc_deadline_t *d, uint64_t now_ns, fc_pools_fn pools,
                 fc_expire_fn expire, void *ctx)
{
  fc_deadline_pass_ctx_t c = { now_ns, 0, expire, ctx };

  if (d) {
    atomic_fetch_add_explicit(&d->passes, 1, memory_order_relaxed);
    atomic_store_explicit(&d->last_fire_ns, now_ns, memory_order_relaxed);
    /* Disarmed before the pools are read: a park that lands during the
     * read arms the timer itself, and the re-arm below is a min with it. */
    atomic_store_explicit(&d->armed_ns, 0, memory_order_release);
  }
  if (pools)
    pools(ctx, fc_deadline_visit_pool, &c);
  if (d && c.earliest)
    fc_deadline_arm(d, c.earliest, now_ns);
  return c.earliest;
}
