/* Legacy P/D load reservations. Routing hints are NOT ownership tokens.
 * A token is zero (unowned) or ep+1; claim it before returning the unit.
 * Same-client lifecycle changes run on its pinned owner worker. */
#ifndef SOCKPROXY_PD_RESERVATION_H
#define SOCKPROXY_PD_RESERVATION_H
#include <stdint.h>
#include <stdatomic.h>
#include <limits.h>
#ifndef PD_LOAD_WAKE
#if defined(TEST_PD_CACHE_AWARE)
#define PD_LOAD_WAKE(t, e) ((void)0)
#else
void pd_wake_parked_one(proxy_epval_t *tepval, int ep);
#define PD_LOAD_WAKE(t, e) pd_wake_parked_one((t), (e))
#endif
#endif

static inline int
pd_load_try_reserve(proxy_epval_t *t, int ep, uint32_t cap)
{
  if (!t || ep < 0 || ep >= t->n_eps) return 0;
  uint32_t cur = atomic_load(&t->pd_ep_loads[ep].active_conns);
  while (cur != UINT32_MAX && (cap == 0 || cur < cap)) {
    if (atomic_compare_exchange_weak(&t->pd_ep_loads[ep].active_conns,
                                    &cur, cur + 1)) {
#if !defined(TEST_PD_CACHE_AWARE)
      log_debug("[PD_RESERVATION] pool=%u ep=%d take=%u cap=%u",
                (unsigned)t->_id, ep, cur + 1, cap);
#endif
      return 1;
    }
  }
  return 0;
}

static inline void
pd_load_put(proxy_epval_t *t, int ep)
{
  if (!t || ep < 0 || ep >= t->n_eps) return;
  uint32_t cur = atomic_load(&t->pd_ep_loads[ep].active_conns);
  while (cur > 0) {
    if (atomic_compare_exchange_weak(&t->pd_ep_loads[ep].active_conns,
                                    &cur, cur - 1)) {
#if !defined(TEST_PD_CACHE_AWARE)
      log_debug("[PD_RESERVATION] pool=%u ep=%d return=%u",
                (unsigned)t->_id, ep, cur - 1);
#endif
      if (t->ep_role[ep] == 1) PD_LOAD_WAKE(t, ep);
      return;
    }
  }
}

/* The caller already owns the new reservation. Exchange publishes it before
 * releasing the old one; rollback/cleanup can never return a routing hint. */
static inline void
pd_load_commit(proxy_epval_t *t, uint32_t *token, int ep)
{
  uint32_t old = __atomic_exchange_n(token, (uint32_t)ep + 1, __ATOMIC_ACQ_REL);
  if (old) pd_load_put(t, (int)old - 1);
}

static inline void
pd_load_release(proxy_epval_t *t, uint32_t *token)
{
  uint32_t old = __atomic_exchange_n(token, 0, __ATOMIC_ACQ_REL);
  if (old) pd_load_put(t, (int)old - 1);
}
#endif
