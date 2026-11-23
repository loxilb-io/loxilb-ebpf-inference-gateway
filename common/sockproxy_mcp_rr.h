/* Copyright (c) 2026 LoxiLB Authors. SPDX-License-Identifier: BSD-3-Clause */
#ifndef SOCKPROXY_MCP_RR_H
#define SOCKPROXY_MCP_RR_H
#include <stdint.h>
#include <stdatomic.h>
#include <time.h>
/* Pick the ticket-th eligible original endpoint. Unsigned wrap is defined;
 * the bitmap includes health and route membership before this pure operation. */
static inline int sp_mcp_rr_index(uint32_t eligible, uint64_t ticket)
{
  unsigned count=0;
  for (unsigned i=0;i<32;i++) if (eligible & (UINT32_C(1)<<i)) count++;
  if (!count) return -1;
  unsigned ordinal=(unsigned)(ticket % count);
  for (unsigned i=0;i<32;i++) if (eligible & (UINT32_C(1)<<i)) {
    if (!ordinal--) return (int)i;
  }
  return -1;
}
/* Smooth WRR state belongs to the listener/base pool, never route config
 * allocations. Its guard is never reset by policy replacement. */
typedef struct sp_mcp_selector_state {
  _Atomic unsigned busy;
  uint32_t eligible;
  uint8_t weights[32];
  int64_t current[32];
} sp_mcp_selector_state;
static inline int sp_mcp_wrr_index(sp_mcp_selector_state *state,
                                  uint32_t eligible, const uint8_t weights[32])
{
  unsigned expected;
  do { expected=0; } while (!atomic_compare_exchange_weak_explicit(
      &state->busy,&expected,1,memory_order_acquire,memory_order_relaxed));
  int changed=state->eligible!=eligible;
  for (unsigned i=0;i<32;i++) {
    uint8_t w=(eligible & (UINT32_C(1)<<i)) ? (weights[i] ? weights[i] : 1) : 0;
    if (state->weights[i]!=w) changed=1;
  }
  if (changed) {
    state->eligible=eligible;
    for (unsigned i=0;i<32;i++) {
      state->weights[i]=(eligible & (UINT32_C(1)<<i)) ? (weights[i] ? weights[i] : 1) : 0;
      state->current[i]=0;
    }
  }
  int selected=-1;
  int64_t total=0, largest=INT64_MIN;
  for (unsigned i=0;i<32;i++) if (state->weights[i]) {
    total+=state->weights[i];
    state->current[i]+=state->weights[i];
    if (state->current[i]>largest) { largest=state->current[i]; selected=(int)i; }
  }
  if (selected>=0) state->current[selected]-=total;
  atomic_store_explicit(&state->busy,0,memory_order_release);
  return selected;
}
#endif /* SOCKPROXY_MCP_RR_H */

/* Included a second time by selector TUs after sockproxy types are complete. */
#ifdef SP_MCP_PROXY_SELECTOR
#include "sockproxy_health.h" /* synchronized CB snapshot/probe APIs */
/* Caller holds the global read lock; configuration writers remain excluded. Eligibility must not reserve a HALF_OPEN
 * probe on every scanned endpoint; only the final dispatch reserves one. */
static inline int sp_mcp_candidate_locked(proxy_epval_t *pool, int ep)
{
  if (ep<0 || ep>=pool->n_eps || ep>=MAX_PROXY_EP || pool->eps[ep].inv) return 0;
  return circuit_breaker_candidate(pool,ep);
}
static inline int sp_mcp_candidate(proxy_epval_t *pool, int ep)
{
  PROXY_RDLOCK();
  int eligible=sp_mcp_candidate_locked(pool,ep);
  PROXY_UNLOCK();
  return eligible;
}
static inline int sp_mcp_reserve_probe(proxy_epval_t *pool, int ep)
{
  PROXY_RDLOCK();
  int healthy=is_endpoint_healthy(pool,ep);
  PROXY_UNLOCK();
  return healthy;
}
/* A FORWARD route restricts the request to its members (l7_route_pool):
 * MCP's routes and every other pool's alike. */
static inline int sp_route_allows(const proxy_fd_ent_t *pfe, int ep)
{
  return !pfe || !pfe->mcp_route_active ||
         (ep >= 0 && ep < MAX_PROXY_EP && (pfe->mcp_route_mask & (UINT32_C(1) << ep)));
}
/* A route subset on a pool other than MCP's: selected by
 * sp_mcp_request_select, outside the pool's own selection modes. */
static inline int sp_route_subset(const proxy_fd_ent_t *pfe, const proxy_epval_t *pool)
{
  return pfe && pfe->mcp_route_active && pool && !pool->mcp_stateless;
}
/* Prefix routing (sockproxy_radix_route.h), both protocols: the endpoints of
 * the first n a request may be routed to by radix, and each one's in-flight
 * count into inflight[]. Eligible: in the request's route, not drained, a
 * normal role, a breaker candidate (read without taking a half-open probe;
 * is_endpoint_healthy would spend one per endpoint). */
static inline uint32_t sp_radix_eligible(const proxy_fd_ent_t *pfe, proxy_epval_t *pool,
                                         int n, uint32_t *inflight)
{
  uint32_t eligible = 0;
  for (int i = 0; i < n; i++) {
    inflight[i] = fc_ep_inflight(&pool->fc, i, FC_ROLE_NORMAL);
    if (sp_route_allows(pfe, i) && pool->eps[i].inv == 0 && pool->ep_role[i] == 0 &&
        circuit_breaker_candidate(pool, i))
      eligible |= UINT32_C(1) << i;
  }
  return eligible;
}
typedef struct sp_mcp_fc_scope {
  proxy_epval_t *pool;
  proxy_fd_ent_t *request;
} sp_mcp_fc_scope;
static inline int sp_mcp_fc_eligible(void *opaque, int ep)
{
  sp_mcp_fc_scope *scope=opaque;
  if (ep<0 || ep>=MAX_PROXY_EP) return 0;
  if (scope->request->mcp_route_active &&
      !(scope->request->mcp_route_mask & (UINT32_C(1)<<ep))) return 0;
  return sp_mcp_candidate(scope->pool,ep);
}
static inline int sp_mcp_request_select(proxy_epval_t *pool, proxy_fd_ent_t *pfe)
{
  uint32_t eligible=0;
  uint8_t weights[32]={0}, first=0;
  PROXY_RDLOCK();
  int weighted=pool->select==PROXY_SEL_WRR;
  for (int i=0;i<pool->n_eps && i<MAX_PROXY_EP;i++)
    if ((!pfe->mcp_route_active || (pfe->mcp_route_mask & (UINT32_C(1)<<i))) &&
        sp_mcp_candidate_locked(pool,i)) {
      eligible |= UINT32_C(1)<<i;
      weights[i]=pfe->mcp_route_active && pfe->mcp_route_weights[i] ?
          pfe->mcp_route_weights[i] : pool->eps[i].weight;
      if (!weights[i]) weights[i]=1;
      if (first && first!=weights[i] && pfe->mcp_route_active) weighted=1;
      if (!first) first=weights[i];
    }
  sp_mcp_selector_state *state=pfe->mcp_route_active ?
      pfe->mcp_selector_state : &pool->mcp_selector;
  uint64_t ticket=pfe->mcp_route_active ? pfe->mcp_route_ticket :
    atomic_fetch_add_explicit(&pool->mcp_rr_ticket,1,memory_order_relaxed);
  PROXY_UNLOCK(); /* Never nest global read lock and the guarded WRR state. */
  if (weighted) {
    if (!state) return -1;
    return sp_mcp_wrr_index(state,eligible,weights);
  }
  return sp_mcp_rr_index(eligible,ticket);
}
#undef SP_MCP_PROXY_SELECTOR
#endif
