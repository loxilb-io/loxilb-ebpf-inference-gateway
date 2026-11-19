/* SPDX-License-Identifier: (GPL-2.0) */
/*
 * sockproxy_radix_route.c - prefix routing decision for one non-P/D pool.
 * Contract, gate order, locking and counters: sockproxy_radix_route.h.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE            /* writer-preferring rwlock kind (glibc) */
#endif
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sockproxy_radix_route.h"

#ifndef PTHREAD_RWLOCK_WRITER_NONRECURSIVE_INITIALIZER_NP
#error "sockproxy_radix_route.c needs the writer-preferring rwlock kind PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP (glibc, _GNU_SOURCE defined before the first system header)"
#endif

#define RR_UNIT RADIX_SCAN_DIGEST     /* lookups compare whole digests */

static uint64_t rr_scan_calls;        /* process-wide, relaxed */

#define RR_INC(p, field) __atomic_fetch_add(&(p)->st.field, 1, __ATOMIC_RELAXED)

static uint64_t rr_mono_ns(void)
{
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts))
    return 0;
  return (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec;
}

uint32_t radix_now(void)
{
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC_COARSE, &ts))
    return 0;
  return (uint32_t)(((uint64_t)ts.tv_sec * 1000u +
                     (uint64_t)ts.tv_nsec / 1000000u) / RADIX_ROUTE_TICK_MS);
}

static int rr_lock_init(pthread_rwlock_t *l)
{
  pthread_rwlockattr_t a;
  int rc;

  if (pthread_rwlockattr_init(&a))
    return -1;
  rc = pthread_rwlockattr_setkind_np(&a, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
  if (!rc)
    rc = pthread_rwlock_init(l, &a);
  pthread_rwlockattr_destroy(&a);
  return rc ? -1 : 0;
}

radix_pool_t *radix_pool_create(const radix_route_cfg_t *cfg)
{
  radix_pool_t *p = calloc(1, sizeof(*p));

  if (!p)
    return NULL;
  if (cfg)
    p->cfg = *cfg;
  if (!p->cfg.match_pct)
    p->cfg.match_pct = RADIX_ROUTE_MATCH_PCT;
  if (!p->cfg.balance_abs)
    p->cfg.balance_abs = RADIX_ROUTE_BALANCE_ABS;
  if (!p->cfg.max_body)
    p->cfg.max_body = RADIX_ROUTE_MAX_BODY;
  if (!p->cfg.scan_cap)
    p->cfg.scan_cap = RADIX_ROUTE_SCAN_CAP;
  if (p->cfg.scan_cap > RADIX_SCAN_CAP_MAX)
    p->cfg.scan_cap = RADIX_SCAN_CAP_MAX;
  p->trie = radix_trie_create(&p->cfg.lim);
  if (!p->trie) {
    free(p);
    return NULL;
  }
  if (rr_lock_init(&p->lock)) {
    radix_trie_free(p->trie);
    free(p);
    return NULL;
  }
  return p;
}

void radix_pool_free(radix_pool_t *p)
{
  if (!p)
    return;
  radix_trie_free(p->trie);
  pthread_rwlock_destroy(&p->lock);
  free(p);
}

/* Ends a decision; counting is the caller's (one reason per request). */
static int rr_end(radix_pool_t *p, radix_route_out_t *out,
                  radix_route_reason_t r)
{
  (void)p;
  out->reason = r;
  return r == RADIX_R_HIT ? out->ep : -1;
}

static void rr_count(radix_pool_t *p, const radix_route_out_t *out)
{
  if (!p || out->reason == RADIX_R_OFF)
    return;
  RR_INC(p, decided[out->reason]);
  if (out->reason == RADIX_R_SCAN_SKIP && (unsigned)out->scan_rc < RADIX_SCAN__COUNT)
    RR_INC(p, scan_skip[out->scan_rc]);
}

static void rr_put_le64(uint8_t b[8], uint64_t v)
{
  for (int i = 0; i < 8; i++)
    b[i] = (uint8_t)(v >> (8 * i));
}

/* Namespace in the header's order; 0 when it does not fit. */
static uint16_t rr_build_ns(uint8_t ns[RADIX_NS_MAX], const radix_route_in_t *in,
                            const radix_scan_res_t *sr)
{
  uint8_t th[8], kh[8];
  size_t off = 0;

  rr_put_le64(th, sr->tools_hash);
  rr_put_le64(kh, sr->tmpl_kwargs_hash);
  if (radix_ns_append(ns, RADIX_NS_MAX, &off, in->model,
                      in->model ? in->model_len : 0) ||
      radix_ns_append(ns, RADIX_NS_MAX, &off, in->salt,
                      in->salt ? in->salt_len : 0) ||
      radix_ns_append(ns, RADIX_NS_MAX, &off, in->tenant,
                      in->tenant ? in->tenant_len : 0) ||
      radix_ns_append(ns, RADIX_NS_MAX, &off, th, sr->has_tools ? 8 : 0) ||
      radix_ns_append(ns, RADIX_NS_MAX, &off, kh, sr->has_tmpl_kwargs ? 8 : 0))
    return 0;
  return (uint16_t)off;
}

static void rr_max(uint64_t *slot, uint64_t v)
{
  uint64_t cur = __atomic_load_n(slot, __ATOMIC_RELAXED);
  while (v > cur &&
         !__atomic_compare_exchange_n(slot, &cur, v, 1, __ATOMIC_RELAXED,
                                      __ATOMIC_RELAXED))
    ;
}

static void rr_scan(radix_pool_t *p, radix_req_t *rq, const radix_route_in_t *in)
{
  radix_scan_res_t sr;
  radix_scan_rc_t rc;
  uint64_t t0 = rr_mono_ns(), dt;

  rc = radix_scan_chat(in->body, in->body_len, p->cfg.max_body, p->cfg.scan_cap,
                       rq->key, sizeof(rq->key), &sr);
  dt = rr_mono_ns() - t0;
  __atomic_fetch_add(&rr_scan_calls, 1, __ATOMIC_RELAXED);
  RR_INC(p, scans);
  __atomic_fetch_add(&p->st.scan_ns_sum, dt, __ATOMIC_RELAXED);
  rr_max(&p->st.scan_ns_max, dt);

  rq->pool = in->pool_id;
  rq->scanned = 1;
  rq->scan_rc = (uint8_t)rc;
  rq->learnable = 0;
  rq->full_mask = 0;
  rq->key_len = 0;
  rq->ns_len = 0;
  rq->stream_bytes = 0;
  if (rc != RADIX_SCAN_OK)
    return;
  rq->key_len = (uint16_t)sr.key_len;
  rq->stream_bytes = (uint32_t)sr.stream_bytes;
  rq->ns_len = rr_build_ns(rq->ns, in, &sr);
}

static int rr_decide(radix_pool_t *p, radix_req_t **rqp,
                     const radix_route_in_t *in, radix_route_out_t *out)
{
  radix_lookup_res_t lr;
  radix_lookup_rc_t lrc;
  radix_route_reason_t gate = RADIX_R_HIT;
  radix_req_t *rq;
  uint32_t eligible, cand, lo = UINT32_MAX, hi = 0, best = UINT32_MAX;
  unsigned n;
  int pick = -1;
  uint64_t w0;

  memset(out, 0, sizeof(*out));
  out->ep = -1;
  out->reason = RADIX_R_OFF;
  if (!p || !in || !rqp)
    return -1;

  if (in->pipelined)
    gate = RADIX_R_PIPELINED;
  else if (in->route_subset)
    gate = RADIX_R_ROUTE_SUBSET;
  else if (in->pinned || in->sticky_select)
    gate = RADIX_R_PINNED;
  else if (!in->ai_gw_mode)
    gate = RADIX_R_AI_GW_OFF;
  else if (!in->fc_active)
    gate = RADIX_R_FC_INACTIVE;
  else if (in->chunked)
    gate = RADIX_R_CHUNKED;
  else if (in->over_inspect)
    gate = RADIX_R_INSPECT_SIZE;
  else if (!in->body || !in->body_len)
    gate = RADIX_R_NO_BODY;
  else if (in->salt_invalid)
    gate = RADIX_R_SALT_INVALID;
  if (gate != RADIX_R_HIT) {
    if (*rqp)
      (*rqp)->learnable = 0;   /* not scanned for this decision: never learns */
    return rr_end(p, out, gate);
  }

  rq = *rqp;
  if (!rq) {
    rq = calloc(1, sizeof(*rq));
    if (!rq)
      return rr_end(p, out, RADIX_R_NOMEM);
    *rqp = rq;
  }
  /* A request driven again (a park's wake) keeps its scan. */
  if (!rq->scanned || rq->pool != in->pool_id)
    rr_scan(p, rq, in);
  out->scan_rc = (radix_scan_rc_t)rq->scan_rc;
  if (rq->scan_rc != RADIX_SCAN_OK)
    return rr_end(p, out, RADIX_R_SCAN_SKIP);
  if (!rq->ns_len)
    return rr_end(p, out, RADIX_R_NS_OVERFLOW);

  rq->learnable = 1;
  rq->full_mask = 0;
  out->stream_bytes = rq->stream_bytes;
  n = in->n_eps < RADIX_MAX_EP ? in->n_eps : RADIX_MAX_EP;
  eligible = in->eligible & (n >= 32 ? UINT32_MAX : ((UINT32_C(1) << n) - 1));

  w0 = rr_mono_ns();
  pthread_rwlock_rdlock(&p->lock);
  rr_max(&p->st.lookup_wait_ns_max, rr_mono_ns() - w0);
  lrc = radix_trie_lookup(p->trie, rq->ns, rq->ns_len, rq->key, rq->key_len,
                          RR_UNIT, eligible, in->now, &lr);
  pthread_rwlock_unlock(&p->lock);

  if (lrc == RADIX_LOOKUP_FALLBACK_WORK_CAP)
    return rr_end(p, out, RADIX_R_WORK_CAP);
  if (lrc != RADIX_LOOKUP_HIT)
    return rr_end(p, out, RADIX_R_MISS);
  if (lr.full && lr.matched_len == rq->key_len)
    rq->full_mask = lr.cand_mask;
  out->cand_mask = lr.cand_mask;

  out->matched_bytes = radix_scan_matched_bytes(lr.matched_len);
  if ((uint64_t)out->matched_bytes * 100u <
      (uint64_t)p->cfg.match_pct * rq->stream_bytes)
    return rr_end(p, out, RADIX_R_BELOW_THRESHOLD);

  for (unsigned i = 0; i < n; i++) {
    uint32_t v;
    if (!(eligible & (UINT32_C(1) << i)))
      continue;
    v = in->inflight ? in->inflight[i] : 0;
    if (v < lo)
      lo = v;
    if (v > hi)
      hi = v;
  }
  if (hi - lo > p->cfg.balance_abs)
    return rr_end(p, out, RADIX_R_SPREAD);

  cand = lr.cand_mask & eligible;
  for (unsigned i = 0; i < n; i++) {
    uint32_t v;
    if (!(cand & (UINT32_C(1) << i)))
      continue;
    v = in->inflight ? in->inflight[i] : 0;
    if (v < best || (v == best && (int)i == in->selector_pick)) {
      best = v;
      pick = (int)i;
    }
  }
  if (pick < 0)
    return rr_end(p, out, RADIX_R_MISS);
  out->ep = pick;
  return rr_end(p, out, RADIX_R_HIT);
}

int radix_route_decide(radix_pool_t *p, radix_req_t **rqp,
                       const radix_route_in_t *in, radix_route_out_t *out)
{
  radix_route_out_t scratch;
  int ep;

  if (!out)
    out = &scratch;
  ep = rr_decide(p, rqp, in, out);
  rr_count(p, out);
  return ep;
}

int radix_route_keepalive(radix_pool_t *p, radix_req_t **rqp,
                          const radix_route_in_t *in, int kept_ep,
                          radix_route_out_t *out)
{
  radix_route_out_t scratch;
  int ep;

  if (!out)
    out = &scratch;
  memset(out, 0, sizeof(*out));
  out->ep = -1;
  out->reason = RADIX_R_OFF;
  if (!p || !in || !rqp || in->gates_unknown || kept_ep < 0 || kept_ep >= RADIX_MAX_EP)
    return 0;                      /* keep, as today: nothing scanned or counted */
  ep = rr_decide(p, rqp, in, out);
  if (ep >= 0 && !(out->cand_mask & (UINT32_C(1) << kept_ep))) {
    RR_INC(p, ka_moved);           /* its reason is counted at the selection */
    return 1;
  }
  rr_count(p, out);
  if (ep >= 0)
    RR_INC(p, kept_leg);
  return 0;
}

void radix_route_note_moved(radix_pool_t *p)
{
  if (p)
    RR_INC(p, admission_moved);
}

static radix_learn_rc_t rr_learn_end(radix_pool_t *p, radix_learn_rc_t rc)
{
  if (p)
    RR_INC(p, learn[rc]);
  return rc;
}

radix_learn_rc_t radix_route_learn(radix_pool_t *p, radix_req_t *rq,
                                   const void *pool_id, int ep,
                                   unsigned status, uint32_t now)
{
  radix_insert_rc_t ir;
  uint32_t bit;
  uint64_t w0;

  if (!p || !rq || !rq->learnable || rq->pool != pool_id)
    return rr_learn_end(p, RADIX_LEARN_NONE);
  if (status < 200)
    return rr_learn_end(p, RADIX_LEARN_INTERIM);
  rq->learnable = 0;                         /* the first final status */
  if (status >= 300)
    return rr_learn_end(p, RADIX_LEARN_REFUSED);
  if (ep < 0 || ep >= RADIX_MAX_EP)
    return rr_learn_end(p, RADIX_LEARN_NONE);
  bit = UINT32_C(1) << ep;
  if (rq->full_mask & bit)
    return rr_learn_end(p, RADIX_LEARN_NOOP);  /* no lock taken */
  w0 = rr_mono_ns();
  pthread_rwlock_wrlock(&p->lock);
  rr_max(&p->st.learn_wait_ns_max, rr_mono_ns() - w0);
  ir = radix_trie_insert(p->trie, rq->ns, rq->ns_len, rq->key, rq->key_len,
                         (unsigned)ep, now);
  if (ir == RADIX_INSERT_OK || ir == RADIX_INSERT_NOOP)
    p->learned_mask |= bit;
  pthread_rwlock_unlock(&p->lock);
  switch (ir) {
  case RADIX_INSERT_OK:        return rr_learn_end(p, RADIX_LEARN_OK);
  case RADIX_INSERT_NOOP:      return rr_learn_end(p, RADIX_LEARN_NOOP);
  case RADIX_INSERT_NOMEM:     return rr_learn_end(p, RADIX_LEARN_NOMEM);
  case RADIX_INSERT_TOO_LARGE: return rr_learn_end(p, RADIX_LEARN_TOO_LARGE);
  default:                     return rr_learn_end(p, RADIX_LEARN_NONE);
  }
}

void radix_req_reset(radix_req_t *rq)
{
  if (!rq)
    return;
  rq->pool = NULL;
  rq->key_len = 0;
  rq->ns_len = 0;
  rq->stream_bytes = 0;
  rq->full_mask = 0;
  rq->scanned = 0;
  rq->scan_rc = 0;
  rq->learnable = 0;
}

void radix_req_free(radix_req_t **rqp)
{
  if (!rqp || !*rqp)
    return;
  free(*rqp);
  *rqp = NULL;
}

/* Exclusive lock held. Walks the trie only for endpoints that may hold
 * entries: learned_mask has every endpoint inserted since its last purge. */
static void rr_purge_locked(radix_pool_t *p, uint32_t mask)
{
  mask &= p->learned_mask;
  for (unsigned ep = 0; mask; ep++, mask >>= 1) {
    if (!(mask & 1u))
      continue;
    radix_trie_purge_ep(p->trie, ep);
    p->learned_mask &= ~(UINT32_C(1) << ep);
    RR_INC(p, purges);
  }
}

void radix_pool_purge_ep(radix_pool_t *p, unsigned ep)
{
  if (!p || ep >= RADIX_MAX_EP)
    return;
  pthread_rwlock_wrlock(&p->lock);
  rr_purge_locked(p, UINT32_C(1) << ep);
  pthread_rwlock_unlock(&p->lock);
}

void radix_pool_purge_mask(radix_pool_t *p, uint32_t mask)
{
  if (!p || !mask)
    return;
  pthread_rwlock_wrlock(&p->lock);
  rr_purge_locked(p, mask);
  pthread_rwlock_unlock(&p->lock);
}

uint32_t radix_refresh_purge_mask(const radix_ep_ident_t old_eps[RADIX_MAX_EP],
                                  const radix_ep_ident_t new_eps[RADIX_MAX_EP],
                                  unsigned new_n)
{
  uint32_t m = 0;

  for (unsigned i = 0; i < RADIX_MAX_EP; i++) {
    const radix_ep_ident_t *o = &old_eps[i], *c = &new_eps[i];
    if (i >= new_n || o->xip != c->xip || o->xport != c->xport ||
        o->protocol != c->protocol || (!o->inv && c->inv))
      m |= UINT32_C(1) << i;
  }
  return m;
}

static const char *const rr_reason_names[RADIX_R__COUNT] = {
  [RADIX_R_HIT]             = "hit",
  [RADIX_R_OFF]             = "off",
  [RADIX_R_PIPELINED]       = "pipelined",
  [RADIX_R_ROUTE_SUBSET]    = "route_subset",
  [RADIX_R_PINNED]          = "pinned",
  [RADIX_R_AI_GW_OFF]       = "ai_gw_off",
  [RADIX_R_FC_INACTIVE]     = "fc_inactive",
  [RADIX_R_CHUNKED]         = "chunked",
  [RADIX_R_INSPECT_SIZE]    = "inspect_size",
  [RADIX_R_NO_BODY]         = "no_body",
  [RADIX_R_SALT_INVALID]    = "salt_invalid",
  [RADIX_R_NOMEM]           = "nomem",
  [RADIX_R_SCAN_SKIP]       = "scan_skip",
  [RADIX_R_NS_OVERFLOW]     = "ns_overflow",
  [RADIX_R_MISS]            = "miss",
  [RADIX_R_WORK_CAP]        = "work_cap",
  [RADIX_R_BELOW_THRESHOLD] = "below_threshold",
  [RADIX_R_SPREAD]          = "spread",
};

static const char *const rr_learn_names[RADIX_LEARN__COUNT] = {
  [RADIX_LEARN_OK]        = "ok",
  [RADIX_LEARN_NOOP]      = "noop",
  [RADIX_LEARN_NOMEM]     = "nomem",
  [RADIX_LEARN_TOO_LARGE] = "too_large",
  [RADIX_LEARN_REFUSED]   = "refused",
  [RADIX_LEARN_INTERIM]   = "interim",
  [RADIX_LEARN_NONE]      = "none",
};

const char *radix_route_reason_name(radix_route_reason_t r)
{
  return (unsigned)r < RADIX_R__COUNT ? rr_reason_names[r] : "unknown";
}

const char *radix_learn_rc_name(radix_learn_rc_t r)
{
  return (unsigned)r < RADIX_LEARN__COUNT ? rr_learn_names[r] : "unknown";
}

/* Append " name=count" when count is non-zero and the pair fits whole. */
static void rr_pair(char *buf, size_t cap, size_t *len, int *full,
                    const char *pfx, const char *name, uint64_t v)
{
  char pair[96];
  int n;

  if (*full || !v)
    return;
  n = snprintf(pair, sizeof(pair), "%s%s%s=%llu", *len ? " " : "", pfx, name,
               (unsigned long long)v);
  if (n < 0 || (size_t)n >= sizeof(pair) || *len + (size_t)n >= cap) {
    *full = 1;
    return;
  }
  memcpy(buf + *len, pair, (size_t)n + 1);
  *len += (size_t)n;
}

#define RR_LD(x) __atomic_load_n(&(x), __ATOMIC_RELAXED)

size_t radix_pool_stats_format(radix_pool_t *p, char *buf, size_t cap)
{
  size_t len = 0;
  int full = 0;

  if (!buf || !cap)
    return 0;
  buf[0] = '\0';
  if (!p)
    return 0;
  for (int r = 0; r < RADIX_R__COUNT; r++)
    rr_pair(buf, cap, &len, &full, "", rr_reason_names[r], RR_LD(p->st.decided[r]));
  for (int r = 0; r < RADIX_SCAN__COUNT; r++)
    rr_pair(buf, cap, &len, &full, "scan.", radix_scan_rc_name((radix_scan_rc_t)r),
            RR_LD(p->st.scan_skip[r]));
  for (int r = 0; r < RADIX_LEARN__COUNT; r++)
    rr_pair(buf, cap, &len, &full, "learn.", rr_learn_names[r], RR_LD(p->st.learn[r]));
  rr_pair(buf, cap, &len, &full, "", "moved", RR_LD(p->st.admission_moved));
  rr_pair(buf, cap, &len, &full, "", "purges", RR_LD(p->st.purges));
  rr_pair(buf, cap, &len, &full, "", "scans", RR_LD(p->st.scans));
  rr_pair(buf, cap, &len, &full, "", "scan_us_max", RR_LD(p->st.scan_ns_max) / 1000u);
  rr_pair(buf, cap, &len, &full, "", "scan_us_sum", RR_LD(p->st.scan_ns_sum) / 1000u);
  rr_pair(buf, cap, &len, &full, "", "lookup_wait_us_max",
          RR_LD(p->st.lookup_wait_ns_max) / 1000u);
  rr_pair(buf, cap, &len, &full, "", "learn_wait_us_max",
          RR_LD(p->st.learn_wait_ns_max) / 1000u);
  rr_pair(buf, cap, &len, &full, "", "kept_leg", RR_LD(p->st.kept_leg));
  rr_pair(buf, cap, &len, &full, "", "ka_moved", RR_LD(p->st.ka_moved));
  return len;
}

int radix_pool_stats_due(radix_pool_t *p, uint64_t now_ms, uint64_t period_ms)
{
  uint64_t last, next;

  if (!p)
    return 0;
  next = now_ms ? now_ms : 1;      /* 0 means "never printed" */
  last = __atomic_load_n(&p->stats_last_ms, __ATOMIC_RELAXED);
  if (last && now_ms - last < period_ms)
    return 0;
  return __atomic_compare_exchange_n(&p->stats_last_ms, &last, next, 0,
                                     __ATOMIC_RELAXED, __ATOMIC_RELAXED);
}

size_t radix_pool_stats_take(radix_pool_t *p, uint64_t now_ms, uint64_t period_ms,
                             char *buf, size_t cap)
{
  uint64_t sig = 1469598103934665603ull;     /* FNV-1a over the line */
  size_t len;

  if (!buf || !cap || !p)
    return 0;
  /* Not due yet: return before formatting. A plain read, no claim: the
   * slot is claimed below, only for a line that is printed. */
  {
    uint64_t last = __atomic_load_n(&p->stats_last_ms, __ATOMIC_RELAXED);
    if (last && now_ms - last < period_ms)
      return 0;
  }
  len = radix_pool_stats_format(p, buf, cap);
  if (!len)
    return 0;
  for (size_t i = 0; i < len; i++)
    sig = (sig ^ (uint8_t)buf[i]) * 1099511628211ull;
  if (sig == __atomic_load_n(&p->stats_last_sig, __ATOMIC_RELAXED))
    return 0;                                /* unchanged since the last line */
  if (!radix_pool_stats_due(p, now_ms, period_ms))
    return 0;
  __atomic_store_n(&p->stats_last_sig, sig, __ATOMIC_RELAXED);
  return len;
}

uint64_t radix_route_scan_calls(void)
{
  return __atomic_load_n(&rr_scan_calls, __ATOMIC_RELAXED);
}
