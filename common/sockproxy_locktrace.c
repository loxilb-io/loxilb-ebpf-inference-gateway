/*
 * Copyright (c) 2024 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */
/* Global proxy lock accounting by call site; see sockproxy_locktrace.h. */
#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "log.h"
#include "sockproxy_locktrace.h"

#define LT_MAX_SITES   128
#define LT_MAX_DEPTH   8
#define LT_REPORT_NS   1000000000ULL

int proxy_lock_trace_state = -1;

typedef struct lt_site {
  const char *func;               /* NULL until the slot is published */
  int line;
  int wr;
  _Atomic uint64_t n;
  _Atomic uint64_t wait_ns;
  _Atomic uint64_t wait_max_ns;   /* since start */
  _Atomic uint64_t hold_ns;
  _Atomic uint64_t hold_max_ns;   /* since start */
  _Atomic uint64_t iv_wait_max_ns;   /* since the last report, reset by it */
  _Atomic uint64_t iv_hold_max_ns;
  _Atomic uint64_t hist[PROXY_LOCK_TRACE_BUCKETS];
  /* the reporter's view at the last report; only the reporter touches these */
  uint64_t rep_n, rep_wait_ns, rep_hold_ns, rep_hist[PROXY_LOCK_TRACE_BUCKETS];
} lt_site_t;

typedef struct lt_held {
  lt_site_t *site;
  uint64_t t_acq;
} lt_held_t;

static lt_site_t lt_sites[LT_MAX_SITES];
static _Atomic int lt_n_sites;
static pthread_mutex_t lt_insert_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t lt_report_mtx = PTHREAD_MUTEX_INITIALIZER;
static _Atomic uint64_t lt_last_report_ns;
static _Atomic uint64_t lt_dropped;     /* holds deeper than the per-thread stack */

static __thread lt_held_t lt_held[LT_MAX_DEPTH];
static __thread int lt_depth;

int
proxy_lock_trace_init(void)
{
  const char *e = getenv("LLB_PROXY_LOCK_TRACE");
  int s = (e && *e && *e != '0') ? 1 : 0;
  __atomic_store_n(&proxy_lock_trace_state, s, __ATOMIC_RELAXED);
  return s;
}

static inline uint64_t
lt_now(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

int
proxy_lock_trace_bucket(uint64_t hold_ns)
{
  static const uint64_t edge[PROXY_LOCK_TRACE_BUCKETS - 1] = {
    10000ULL, 100000ULL, 1000000ULL, 10000000ULL, 100000000ULL
  };
  int b;
  for (b = 0; b < PROXY_LOCK_TRACE_BUCKETS - 1; b++) {
    if (hold_ns <= edge[b]) {
      return b;
    }
  }
  return PROXY_LOCK_TRACE_BUCKETS - 1;
}

static inline void
lt_max(_Atomic uint64_t *m, uint64_t v)
{
  uint64_t cur = atomic_load_explicit(m, memory_order_relaxed);
  while (v > cur &&
         !atomic_compare_exchange_weak_explicit(m, &cur, v, memory_order_relaxed,
                                                memory_order_relaxed)) {
  }
}

/* The site for (func, line): a lock-free scan of the published slots, and a
 * serialised insert the first time a site is seen. `func` is the function's
 * own __func__ array, so pointer equality identifies the function. */
static lt_site_t *
lt_site(const char *func, int line, int wr)
{
  int n = atomic_load_explicit(&lt_n_sites, memory_order_acquire);
  int i;

  for (i = 0; i < n; i++) {
    if (lt_sites[i].func == func && lt_sites[i].line == line) {
      return &lt_sites[i];
    }
  }

  pthread_mutex_lock(&lt_insert_mtx);
  n = atomic_load_explicit(&lt_n_sites, memory_order_acquire);
  for (i = 0; i < n; i++) {
    if (lt_sites[i].func == func && lt_sites[i].line == line) {
      pthread_mutex_unlock(&lt_insert_mtx);
      return &lt_sites[i];
    }
  }
  if (n >= LT_MAX_SITES) {
    pthread_mutex_unlock(&lt_insert_mtx);
    return NULL;
  }
  lt_sites[n].line = line;
  lt_sites[n].wr = wr;
  lt_sites[n].func = func;
  atomic_store_explicit(&lt_n_sites, n + 1, memory_order_release);
  pthread_mutex_unlock(&lt_insert_mtx);
  return &lt_sites[n];
}

void
proxy_lock_trace_acquire(pthread_rwlock_t *l, int wr, const char *func, int line)
{
  lt_site_t *s = lt_site(func, line, wr);
  uint64_t t0 = lt_now();
  uint64_t t1;

  if (wr) {
    pthread_rwlock_wrlock(l);
  } else {
    pthread_rwlock_rdlock(l);
  }
  t1 = lt_now();

  if (s) {
    uint64_t wait = t1 - t0;
    atomic_fetch_add_explicit(&s->wait_ns, wait, memory_order_relaxed);
    lt_max(&s->wait_max_ns, wait);
    lt_max(&s->iv_wait_max_ns, wait);
  }
  if (lt_depth < LT_MAX_DEPTH) {
    lt_held[lt_depth].site = s;
    lt_held[lt_depth].t_acq = t1;
  } else {
    atomic_fetch_add_explicit(&lt_dropped, 1, memory_order_relaxed);
  }
  lt_depth++;
}

void
proxy_lock_trace_release(pthread_rwlock_t *l)
{
  uint64_t now = lt_now();
  lt_site_t *s = NULL;
  uint64_t t_acq = 0;

  if (lt_depth > 0) {
    lt_depth--;
    if (lt_depth < LT_MAX_DEPTH) {
      s = lt_held[lt_depth].site;
      t_acq = lt_held[lt_depth].t_acq;
    }
  }

  pthread_rwlock_unlock(l);

  if (s) {
    uint64_t hold = now - t_acq;
    atomic_fetch_add_explicit(&s->n, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&s->hold_ns, hold, memory_order_relaxed);
    atomic_fetch_add_explicit(&s->hist[proxy_lock_trace_bucket(hold)], 1,
                              memory_order_relaxed);
    lt_max(&s->hold_max_ns, hold);
    lt_max(&s->iv_hold_max_ns, hold);
  }

  proxy_lock_trace_report(0);
}

int
proxy_lock_trace_sites(proxy_lock_site_stat_t *out, int max)
{
  int n = atomic_load_explicit(&lt_n_sites, memory_order_acquire);
  int i, b;

  for (i = 0; i < n && i < max; i++) {
    lt_site_t *s = &lt_sites[i];
    out[i].func = s->func;
    out[i].line = s->line;
    out[i].wr = s->wr;
    out[i].n = atomic_load_explicit(&s->n, memory_order_relaxed);
    out[i].wait_ns = atomic_load_explicit(&s->wait_ns, memory_order_relaxed);
    out[i].wait_max_ns = atomic_load_explicit(&s->wait_max_ns, memory_order_relaxed);
    out[i].hold_ns = atomic_load_explicit(&s->hold_ns, memory_order_relaxed);
    out[i].hold_max_ns = atomic_load_explicit(&s->hold_max_ns, memory_order_relaxed);
    for (b = 0; b < PROXY_LOCK_TRACE_BUCKETS; b++) {
      out[i].hist[b] = atomic_load_explicit(&s->hist[b], memory_order_relaxed);
    }
  }
  return n;
}

/* One thread per interval is elected by the compare-and-swap on the report
 * stamp; the mutex only keeps a slow reporter from overlapping the next. */
int
proxy_lock_trace_report(int force)
{
  uint64_t now = lt_now();
  uint64_t last = atomic_load_explicit(&lt_last_report_ns, memory_order_relaxed);
  uint64_t interval, wr_busy = 0, wait_total = 0;
  int n, i, b, active = 0;

  if (last == 0) {
    atomic_compare_exchange_strong(&lt_last_report_ns, &last, now);
    if (!force) {
      return 0;
    }
    last = now;
  } else if (!force && now - last < LT_REPORT_NS) {
    return 0;
  }
  if (!atomic_compare_exchange_strong(&lt_last_report_ns, &last, now)) {
    return 0;
  }
  if (pthread_mutex_trylock(&lt_report_mtx)) {
    return 0;
  }
  interval = now > last ? now - last : 1;

  n = atomic_load_explicit(&lt_n_sites, memory_order_acquire);
  for (i = 0; i < n; i++) {
    lt_site_t *s = &lt_sites[i];
    uint64_t cn = atomic_load_explicit(&s->n, memory_order_relaxed);
    uint64_t cw = atomic_load_explicit(&s->wait_ns, memory_order_relaxed);
    uint64_t ch = atomic_load_explicit(&s->hold_ns, memory_order_relaxed);
    uint64_t dn = cn - s->rep_n, dw = cw - s->rep_wait_ns, dh = ch - s->rep_hold_ns;
    uint64_t wmax = atomic_exchange_explicit(&s->iv_wait_max_ns, 0, memory_order_relaxed);
    uint64_t hmax = atomic_exchange_explicit(&s->iv_hold_max_ns, 0, memory_order_relaxed);
    uint64_t dhist[PROXY_LOCK_TRACE_BUCKETS];

    for (b = 0; b < PROXY_LOCK_TRACE_BUCKETS; b++) {
      uint64_t c = atomic_load_explicit(&s->hist[b], memory_order_relaxed);
      dhist[b] = c - s->rep_hist[b];
      s->rep_hist[b] = c;
    }
    s->rep_n = cn;
    s->rep_wait_ns = cw;
    s->rep_hold_ns = ch;
    if (dn == 0) {
      continue;
    }
    active++;
    wait_total += dw;
    if (s->wr) {
      wr_busy += dh;
    }
    log_error("[PROXY-LOCK] site=%s:%d %s n=%llu wait_avg_us=%.1f wait_max_us=%.1f "
              "hold_avg_us=%.1f hold_max_us=%.1f hold_ms=%.1f "
              "h=%llu/%llu/%llu/%llu/%llu/%llu",
              s->func, s->line, s->wr ? "wr" : "rd",
              (unsigned long long)dn,
              (double)dw / dn / 1000.0, (double)wmax / 1000.0,
              (double)dh / dn / 1000.0, (double)hmax / 1000.0,
              (double)dh / 1000000.0,
              (unsigned long long)dhist[0], (unsigned long long)dhist[1],
              (unsigned long long)dhist[2], (unsigned long long)dhist[3],
              (unsigned long long)dhist[4], (unsigned long long)dhist[5]);
  }
  if (active) {
    log_error("[PROXY-LOCK] t=%llu.%03llu ms=%llu wr_busy_ms=%.1f wr_busy_pct=%.1f "
              "wait_ms=%.1f sites=%d dropped=%llu",
              (unsigned long long)(now / 1000000000ULL),
              (unsigned long long)((now / 1000000ULL) % 1000ULL),
              (unsigned long long)(interval / 1000000ULL),
              (double)wr_busy / 1000000.0,
              interval >= 1000000ULL ? 100.0 * (double)wr_busy / (double)interval : 0.0,
              (double)wait_total / 1000000.0, active,
              (unsigned long long)atomic_load_explicit(&lt_dropped, memory_order_relaxed));
  }
  pthread_mutex_unlock(&lt_report_mtx);
  return active;
}
