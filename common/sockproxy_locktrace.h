/*
 * Copyright (c) 2024 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */
#ifndef __SOCKPROXY_LOCKTRACE_H__
#define __SOCKPROXY_LOCKTRACE_H__

#include <pthread.h>
#include <stdint.h>

/* Global proxy lock accounting, by call site, behind LLB_PROXY_LOCK_TRACE=1.
 *
 * PROXY_LOCK / PROXY_RDLOCK / PROXY_UNLOCK expand to the two inline helpers
 * at the bottom. With the variable unset they are the bare rwlock calls
 * behind one relaxed load. With it set, every acquire records how long the
 * caller waited for the lock and every release how long the caller held
 * it, both attributed to the acquiring site (function and line), and once a
 * second the thread that happens to release the lock writes one summary
 * line and one line per site that was active in the interval:
 *
 *   [PROXY-LOCK] t=<s> ms=<interval> wr_busy_ms=<sum of write holds>
 *                wr_busy_pct=<share of the interval> wait_ms=<sum of waits>
 *                sites=<n>
 *   [PROXY-LOCK] site=<func>:<line> <wr|rd> n=<acquires>
 *                wait_avg_us=<> wait_max_us=<> hold_avg_us=<> hold_max_us=<>
 *                hold_ms=<sum> h=<hold histogram: <=10us/<=100us/<=1ms/<=10ms/<=100ms/more>
 *
 * Holds are tracked per thread on a small stack, so a lock taken in one
 * function and released in another, or a nested read lock, is attributed
 * to the site that took it. A release the tracker did not see acquired
 * (a lock taken through the pthread call directly) just unlocks. */

#define PROXY_LOCK_TRACE_BUCKETS 6

typedef struct proxy_lock_site_stat {
  const char *func;
  int line;
  int wr;
  uint64_t n;            /* acquires                       */
  uint64_t wait_ns;      /* time spent waiting to acquire  */
  uint64_t wait_max_ns;
  uint64_t hold_ns;      /* time spent holding             */
  uint64_t hold_max_ns;
  uint64_t hist[PROXY_LOCK_TRACE_BUCKETS];
} proxy_lock_site_stat_t;

extern int proxy_lock_trace_state;   /* -1 not yet read, 0 off, 1 on */

int  proxy_lock_trace_init(void);
void proxy_lock_trace_acquire(pthread_rwlock_t *l, int wr, const char *func, int line);
void proxy_lock_trace_release(pthread_rwlock_t *l);

/* Histogram bucket of one hold time. */
int  proxy_lock_trace_bucket(uint64_t hold_ns);
/* Cumulative per-site stats since start; returns the number of sites known. */
int  proxy_lock_trace_sites(proxy_lock_site_stat_t *out, int max);
/* Write the interval report now if at least one site was active since the
 * previous report (force ignores the 1 s cadence); returns sites reported. */
int  proxy_lock_trace_report(int force);

static inline int
proxy_lock_trace_enabled(void)
{
  int s = __atomic_load_n(&proxy_lock_trace_state, __ATOMIC_RELAXED);
  return s < 0 ? proxy_lock_trace_init() : s;
}

static inline void
proxy_lock_take(pthread_rwlock_t *l, int wr, const char *func, int line)
{
  if (__builtin_expect(proxy_lock_trace_enabled(), 0)) {
    proxy_lock_trace_acquire(l, wr, func, line);
    return;
  }
  if (wr) {
    pthread_rwlock_wrlock(l);
  } else {
    pthread_rwlock_rdlock(l);
  }
}

static inline void
proxy_lock_drop(pthread_rwlock_t *l)
{
  if (__builtin_expect(proxy_lock_trace_enabled(), 0)) {
    proxy_lock_trace_release(l);
    return;
  }
  pthread_rwlock_unlock(l);
}

#endif /* __SOCKPROXY_LOCKTRACE_H__ */
