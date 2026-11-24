/* SPDX-License-Identifier: (GPL-2.0) */
/*
 * sockproxy_radix_cfg.h - a rule's prefix-affinity arguments applied to its
 * pool, and the one reader of the pool's radix pointer.
 *
 * The arguments ride dp_proxy_tacts -> proxy_arg (llb_conv_nat2proxy) ->
 * the pool: proxy_add_entry calls sp_radix_apply on both create paths and in
 * the refresh block, under the proxy lock (the pool's only writer).
 *
 *   off -> radix    the state is created on, with the rule's threshold and
 *                   balance (0 = the default), and published with a release
 *                   store; until something is learned every request misses
 *   radix -> radix  the values are set for the next decision; the state and
 *                   what it learned are kept
 *   radix -> off    radix_pool_disable: from the next request no lookup, no
 *                   learn; what was learned is purged; the object stays until
 *                   the pool is freed (proxy_pool_finalize), so a reader that
 *                   loaded the pointer always holds a valid object
 *   off -> radix    on an existing object: on again, empty
 * A pool that cannot use radix (P/D, KV-exact, MCP) gets no state.
 *
 * Every reader takes the state through sp_radix_active: one acquire load of
 * the pointer, NULL when there is none or it is off. Nothing here logs; the
 * caller logs the line sp_radix_line gives (no request text exists here).
 */
#ifndef __SOCKPROXY_RADIX_CFG_H__
#define __SOCKPROXY_RADIX_CFG_H__

#include <stdio.h>
#include <string.h>

#include "uthash.h"
#include "sockproxy.h"
#include "sockproxy_radix_route.h"

/* prefix_affinity_mode words (the Go side writes them) */
#define SP_PREFIX_AFFINITY_OFF   0
#define SP_PREFIX_AFFINITY_RADIX 1

enum sp_radix_xition {
  SP_RADIX_NONE = 0,     /* off and stays off */
  SP_RADIX_CREATED,      /* off -> radix, new state */
  SP_RADIX_ENABLED,      /* off -> radix, the pool's earlier state reused */
  SP_RADIX_KEPT,         /* radix -> radix (values set) */
  SP_RADIX_DISABLED,     /* radix -> off */
  SP_RADIX_INELIGIBLE,   /* radix asked on a pool that cannot use it */
  SP_RADIX_NOMEM,        /* radix asked, the state could not be allocated */
};

static inline radix_pool_t *
sp_radix_active(const proxy_epval_t *p)
{
  radix_pool_t *r = p ? __atomic_load_n(&p->radix, __ATOMIC_ACQUIRE) : NULL;

  return radix_pool_is_on(r) ? r : NULL;
}

/* Under the proxy lock. Returns enum sp_radix_xition. */
static inline int
sp_radix_apply(proxy_epval_t *tepval, const proxy_arg_t *arg)
{
  radix_pool_t *r = __atomic_load_n(&tepval->radix, __ATOMIC_RELAXED);
  int want = arg->prefix_affinity_mode == SP_PREFIX_AFFINITY_RADIX;

  if (want && (tepval->pd_disagg_enabled || tepval->kv_exact_mode != 0 ||
               tepval->mcp_stateless)) {
    if (radix_pool_is_on(r))
      radix_pool_disable(r);
    return SP_RADIX_INELIGIBLE;
  }
  if (!want) {
    if (!radix_pool_is_on(r))
      return SP_RADIX_NONE;
    radix_pool_disable(r);
    return SP_RADIX_DISABLED;
  }
  if (!r) {
    radix_route_cfg_t cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.match_pct = arg->prefix_affinity_match_pct;
    cfg.balance_abs = arg->prefix_affinity_balance_abs;
    r = radix_pool_create(&cfg);
    if (!r)
      return SP_RADIX_NOMEM;
    __atomic_store_n(&tepval->radix, r, __ATOMIC_RELEASE);
    return SP_RADIX_CREATED;
  }
  radix_pool_set_cfg(r, arg->prefix_affinity_match_pct, arg->prefix_affinity_balance_abs);
  if (!radix_pool_is_on(r)) {
    radix_pool_enable(r);
    return SP_RADIX_ENABLED;
  }
  return SP_RADIX_KEPT;
}

/* What a pool's radix state was before sp_radix_apply, for its log line. */
typedef struct sp_radix_prev {
  uint8_t  on;
  uint32_t match_pct;
  uint32_t balance_abs;
} sp_radix_prev_t;

static inline sp_radix_prev_t
sp_radix_prev(const proxy_epval_t *tepval)
{
  sp_radix_prev_t pv = { 0, 0, 0 };
  radix_pool_t *r = sp_radix_active(tepval);

  if (r) {
    pv.on = 1;
    pv.match_pct = __atomic_load_n(&r->cfg.match_pct, __ATOMIC_RELAXED);
    pv.balance_abs = __atomic_load_n(&r->cfg.balance_abs, __ATOMIC_RELAXED);
  }
  return pv;
}

/* The info line for a transition (rc of sp_radix_apply), with the values in
 * force; 0 and an empty line when nothing changed. */
static inline size_t
sp_radix_line(char *buf, size_t cap, const proxy_epval_t *tepval,
              const sp_radix_prev_t *pv, int rc)
{
  sp_radix_prev_t now;
  int n = 0;

  if (!buf || !cap)
    return 0;
  buf[0] = '\0';
  if (!tepval || !pv)
    return 0;
  now = sp_radix_prev(tepval);
  switch (rc) {
  case SP_RADIX_CREATED:
  case SP_RADIX_ENABLED:
    n = snprintf(buf, cap, "[RADIX] pool '%s': on (match_pct=%u balance_abs=%u)",
                 tepval->ephash_key, now.match_pct, now.balance_abs);
    break;
  case SP_RADIX_KEPT:
    if (now.match_pct == pv->match_pct && now.balance_abs == pv->balance_abs)
      return 0;                    /* a refresh that changes nothing */
    n = snprintf(buf, cap, "[RADIX] pool '%s': match_pct=%u balance_abs=%u",
                 tepval->ephash_key, now.match_pct, now.balance_abs);
    break;
  case SP_RADIX_DISABLED:
    n = snprintf(buf, cap, "[RADIX] pool '%s': off", tepval->ephash_key);
    break;
  case SP_RADIX_NOMEM:
    n = snprintf(buf, cap, "[RADIX] pool '%s': off (no memory)", tepval->ephash_key);
    break;
  default:
    return 0;                      /* none, ineligible */
  }
  if (n < 0) {
    buf[0] = '\0';
    return 0;
  }
  return (size_t)n < cap ? (size_t)n : cap - 1;
}

#endif /* __SOCKPROXY_RADIX_CFG_H__ */
