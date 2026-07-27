/*
 * Copyright (c) 2024 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */
#ifndef __SOCKPROXY_LB_H__
#define __SOCKPROXY_LB_H__

#include "sockproxy.h"

/*
 * sockproxy_lb.h - Load Balancing Algorithm declarations.
 *
 * Consumers: sockproxy.c (callers of wrr_select_endpoint, chwbl_*),
 * sockproxy_ep.c.
 *
 * See sockproxy_refactoring_plan.md §6.7
 *
 * NOTE: sockproxy_lb.c is the SOLE owner of XXH_IMPLEMENTATION.
 *       All other files that use xxhash must NOT define XXH_IMPLEMENTATION.
 */

/* =========================================================================
 * WRR (Weighted Round-Robin) -- always compiled
 * ========================================================================= */

/* Initialise WRR state for an endpoint group (called on proxy_add_entry) */
void wrr_init_state(proxy_epval_t *epv);

/* Select the next endpoint using smooth WRR. Returns ep index or -1. */
int  wrr_select_endpoint(proxy_epval_t *epv);

/* =========================================================================
 * CHWBL (Consistent Hash WRR-Balanced Load) + WRR_HASH
 * Only compiled when HAVE_DP_GPU_ROUTING is defined.
 * ========================================================================= */
#ifdef HAVE_DP_GPU_ROUTING

/* Build the consistent hash ring with replication factor */
int  chwbl_build_ring(proxy_epval_t *epv, int replication);

/* Build the weighted hash ring (WRR_HASH variant) */
int  chwbl_build_weighted_ring(proxy_epval_t *epv);

/* Look up the ring for a given hash value; returns endpoint index */
int  chwbl_ring_lookup(chwbl_ring_t *ring, uint64_t hash);

/* Destroy and free a hash ring */
void chwbl_destroy_ring(chwbl_ring_t *ring);

/* Select endpoint using CHWBL with health-aware probing.
 * skip_load_balance=1: skip bounded-load overflow for strict prefix_hash routing
 *                       (KV cache locality; only health failover applies). */
int  chwbl_select_endpoint(chwbl_ring_t *ring, chwbl_config_t *config,
                            uint64_t hash, proxy_epval_t *tepval,
                            int *selected_ep, int skip_load_balance);

/* Select endpoint using WRR_HASH (weighted consistent hashing).
 * skip_load_balance=1: same strict-hash semantics as chwbl_select_endpoint. */
int  wrr_hash_select_endpoint(chwbl_ring_t *ring, chwbl_config_t *config,
                               uint64_t hash, proxy_epval_t *tepval,
                               int *selected_ep, int skip_load_balance);

/* Decrement load counter when a connection closes */
void chwbl_dec_load(chwbl_config_t *config, int ep_idx);

/* Validate load counters; returns non-zero if drift detected */
int  chwbl_validate_load_counters(proxy_epval_t *tepval);

#endif /* HAVE_DP_GPU_ROUTING */

#endif /* __SOCKPROXY_LB_H__ */
