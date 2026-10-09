/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2026 LoxiLB Authors
 *
 * sockproxy_fe_limit.h — the per-listener client-connection ceiling.
 *
 * A load-balancer rule's connectionLimit is enforced for NAT rules by the
 * datapath at SYN time (nat_map conn_limit against nat_ep_map.conc_conns,
 * which NAT conntrack maintains). A fullproxy rule never enters nat_map and
 * its flows have no NAT conntrack, so that gate can never see it: the
 * listener is the one place that knows how many client connections it
 * holds, and it enforces the ceiling at accept with the gauge below.
 *
 * The gauge is one unit per accepted client leg, taken with a single
 * fetch_add so concurrent accept shards cannot both slip under the ceiling,
 * and released exactly once when the leg is torn down. The unit is taken
 * whether or not a ceiling is configured: the gauge is also what a fullproxy
 * rule reports as activeConnections (a NAT rule has conntrack for that, a
 * proxied flow has nothing else), so a rule without a limit must still
 * count. A limit of 0 is "unlimited": nothing is ever refused.
 *
 * Deliberately free of project includes so a unit can exercise it without
 * the proxy object graph.
 */
#ifndef __SOCKPROXY_FE_LIMIT_H__
#define __SOCKPROXY_FE_LIMIT_H__

#include <stdint.h>
#include <stdatomic.h>

/* Outcome of fe_limit_take(). */
enum fe_limit_rc {
  FE_LIMIT_TAKEN     = 1,  /* a unit is held: accept, release it at teardown */
  FE_LIMIT_REFUSED   = 2,  /* at the ceiling: nothing held, refuse */
};

/* Take one unit of a listener's gauge; refuse it only when a ceiling is
 * configured (limit > 0) and already reached. On FE_LIMIT_REFUSED the gauge
 * is unchanged and *refused_total, when given, holds the refusal count after
 * this one. */
static inline enum fe_limit_rc
fe_limit_take(_Atomic uint32_t *conns, uint32_t limit,
              _Atomic uint64_t *refused, uint64_t *refused_total)
{
  uint32_t prev;

  prev = atomic_fetch_add_explicit(conns, 1, memory_order_relaxed);
  if (limit == 0 || prev < limit) {
    return FE_LIMIT_TAKEN;
  }
  atomic_fetch_sub_explicit(conns, 1, memory_order_relaxed);
  if (refused) {
    uint64_t n = atomic_fetch_add_explicit(refused, 1, memory_order_relaxed) + 1;
    if (refused_total) {
      *refused_total = n;
    }
  }
  return FE_LIMIT_REFUSED;
}

/* Hand back one unit. Guarded against going below zero so a release that
 * reaches a gauge reset underneath it (a listener torn down and recreated)
 * cannot wrap it to a ceiling that refuses everything. */
static inline void
fe_limit_release(_Atomic uint32_t *conns)
{
  if (atomic_load_explicit(conns, memory_order_relaxed) > 0) {
    atomic_fetch_sub_explicit(conns, 1, memory_order_relaxed);
  }
}

#endif /* __SOCKPROXY_FE_LIMIT_H__ */
