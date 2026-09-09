/*
 * Copyright (c) 2024 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */

/*
 * sockproxy_lb.c -- Load Balancing Algorithms (WRR and CHWBL).
 *
 * Extracted from sockproxy.c per sockproxy_refactoring_plan.md §6.7
 *
 * This file is the SOLE owner of XXH_IMPLEMENTATION (see plan §3.P4).
 * All other files that use xxhash must include "xxhash.h" WITHOUT defining
 * XXH_IMPLEMENTATION -- the symbol bodies come from this translation unit.
 *
 * Functions extracted:
 *   WRR (always compiled):
 *     wrr_gcd, wrr_calculate_gcd_weights, wrr_find_max_weight  (static, internal)
 *     wrr_init_state            -- extern (called from proxy_add_entry)
 *     wrr_select_endpoint       -- extern
 *     wrr_recalculate_state     -- static (unused, bookkeeping only)
 *
 *   CHWBL (guarded by HAVE_DP_GPU_ROUTING):
 *     compare_vnodes            -- static (internal qsort comparator)
 *     chwbl_build_ring          -- extern
 *     chwbl_build_weighted_ring -- extern
 *     chwbl_ring_lookup         -- extern (already non-static)
 *     chwbl_destroy_ring        -- extern
 *     chwbl_select_endpoint     -- extern
 *     wrr_hash_select_endpoint  -- extern
 *     chwbl_dec_load            -- extern
 *     chwbl_validate_load_counters -- extern
 *
 * Include order MUST be:
 *   uthash.h  ->  log.h  ->  (llb_dpapi.h prereqs) ->  llb_dpapi.h
 *   ->  sockproxy_internal.h  ->  sockproxy_lb.h
 */

/* --- XXH_IMPLEMENTATION ownership (see plan §3.P4) --- */
#define XXH_STATIC_LINKING_ONLY
#define XXH_IMPLEMENTATION
/* XXH_IMPLEMENTATION is defined ONLY in sockproxy_lb.c -- sockproxy_refactoring_plan.md §3.P4 */

#include "uthash.h"
#include "log.h"
/* System headers required before llb_dpapi.h */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <bpf.h>
#include "common_pdi.h"
#include "llb_dpapi.h"
#include "sockproxy_internal.h"
#include "sockproxy_lb.h"
#include "sockproxy_json.h"   /* compute_prefix_hash -- used by WRR_HASH path */
#include "xxhash.h"           /* after XXH_IMPLEMENTATION define above */


// ============================================================================
// P3: Weighted Round-Robin (WRR) Implementation
// ============================================================================

// P3: Calculate GCD (Greatest Common Divisor) using Euclidean algorithm
static int
wrr_gcd(int a, int b)
{
  while (b != 0) {
    int temp = b;
    b = a % b;
    a = temp;
  }
  return a;
}

// P3: Calculate GCD for all endpoint weights
static int
wrr_calculate_gcd_weights(proxy_epval_t *epv)
{
  int result;
  int weight;
  
  if (!epv || epv->n_eps == 0) {
    return 1;
  }

  // Start with first endpoint's weight
  result = epv->eps[0].weight ? epv->eps[0].weight : 1;
  
  // Calculate GCD with all other endpoints
  for (int i = 1; i < epv->n_eps; i++) {
    weight = epv->eps[i].weight ? epv->eps[i].weight : 1;
    result = wrr_gcd(result, weight);
  }

  return result ? result : 1;
}

// P3: Find maximum weight among all endpoints
static int
wrr_find_max_weight(proxy_epval_t *epv)
{
  int max_weight = 0;
  
  if (!epv) {
    return 1;
  }
  
  for (int i = 0; i < epv->n_eps; i++) {
    int weight = epv->eps[i].weight ? epv->eps[i].weight : 1;
    if (weight > max_weight) {
      max_weight = weight;
    }
  }
  
  return max_weight ? max_weight : 1;
}

// P3: Initialize WRR state for smooth weighted round-robin
void
wrr_init_state(proxy_epval_t *epv)
{
  if (!epv) {
    return;
  }

  // Set default weights if not specified (0 → 1)
  for (int i = 0; i < epv->n_eps; i++) {
    if (epv->eps[i].weight == 0) {
      epv->eps[i].weight = 1;  // Default weight
    }
    epv->wrr_current_weights[i] = 0;  // Start at 0 for smooth distribution
  }

  epv->wrr_gcd = wrr_calculate_gcd_weights(epv);
  epv->wrr_max_weight = wrr_find_max_weight(epv);
  epv->wrr_initialized = 1;

  log_info("P3: WRR initialized - n_eps=%d, gcd=%d, max_weight=%d",
           epv->n_eps, epv->wrr_gcd, epv->wrr_max_weight);

  for (int i = 0; i < epv->n_eps; i++) {
    log_debug("P3: EP%d weight=%d (IP=%s:%u)",
              i, epv->eps[i].weight,
              inet_ntoa(*(struct in_addr *)&epv->eps[i].xip),
              ntohs(epv->eps[i].xport));
  }
}

// P3: Smooth WRR selection algorithm (NGINX-style)
// This algorithm ensures smooth distribution without traffic bursts
// Example: weights [5,1,1] → EP0,EP0,EP1,EP0,EP2,EP0,EP0 (smooth)
//          NOT: EP0,EP0,EP0,EP0,EP0,EP1,EP2 (bursty)
int
wrr_select_endpoint(proxy_epval_t *epv)
{
  int total_weight = 0;
  int selected = -1;
  int max_current_weight = INT_MIN;

  if (!epv || !epv->wrr_initialized) {
    log_error("P3: WRR not initialized");
    return -1;
  }

  // Step 1: Find endpoint with highest current weight
  // Also accumulate total weight and increase current weights
  for (int i = 0; i < epv->n_eps; i++) {
    // P2 INTEGRATION: Skip inactive endpoints (health check)
    if (epv->eps[i].inv) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("P3: Skipping EP%d (inactive)", i);
#endif
      continue;
    }

    // P2 Task 2.3 INTEGRATION: Skip circuit breaker OPEN endpoints
    if (epv->cb_enabled &&
        epv->circuit_breakers[i].state == CB_STATE_OPEN) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("P3: Skipping EP%d (circuit breaker OPEN)", i);
#endif
      continue;
    }

    // Increase current weight by original weight (smooth distribution)
    epv->wrr_current_weights[i] += epv->eps[i].weight;
    total_weight += epv->eps[i].weight;

    // Track endpoint with maximum current weight
    if (epv->wrr_current_weights[i] > max_current_weight) {
      max_current_weight = epv->wrr_current_weights[i];
      selected = i;
    }
  }

  if (selected < 0 || total_weight == 0) {
    log_error("P3: No available endpoints for WRR (all inactive)");
    return -1;
  }

  // Step 2: Decrease selected endpoint's current weight by total
  // This ensures smooth distribution over time
  epv->wrr_current_weights[selected] -= total_weight;

#ifdef HAVE_PROXY_EXTRA_DEBUG
  log_debug("P3: WRR selected EP%d (weight=%d, curr_before=%d, curr_after=%d, total=%d)",
            selected, epv->eps[selected].weight, max_current_weight,
            epv->wrr_current_weights[selected], total_weight);
#endif

  return selected;
}

// P3: Recalculate WRR state when endpoints change (health updates, weight changes)
static void __attribute__((unused))
wrr_recalculate_state(proxy_epval_t *epv)
{
  if (!epv || !epv->wrr_initialized) {
    return;
  }

  epv->wrr_gcd = wrr_calculate_gcd_weights(epv);
  epv->wrr_max_weight = wrr_find_max_weight(epv);

  // Reset current weights to ensure fair distribution
  for (int i = 0; i < epv->n_eps; i++) {
    epv->wrr_current_weights[i] = 0;
  }

  log_info("P3: WRR state recalculated - gcd=%d, max_weight=%d",
           epv->wrr_gcd, epv->wrr_max_weight);
}

#ifdef HAVE_DP_GPU_ROUTING
// P1.2: Compare function for qsort (sort vnodes by hash)
static int compare_vnodes(const void *a, const void *b)
{
  const chwbl_vnode_t *va = (const chwbl_vnode_t *)a;
  const chwbl_vnode_t *vb = (const chwbl_vnode_t *)b;
  
  if (va->hash < vb->hash) return -1;
  if (va->hash > vb->hash) return 1;
  return 0;
}

static chwbl_ring_t *
chwbl_alloc_ring(int n_eps, int n_vnodes, int replication)
{
  chwbl_ring_t *ring;

  if (n_eps <= 0 || n_eps > MAX_PROXY_EP || n_vnodes <= 0 ||
      (size_t)n_vnodes > SIZE_MAX / sizeof(chwbl_vnode_t))
    return NULL;

  ring = calloc(1, sizeof(*ring));
  if (!ring)
    return NULL;
  ring->vnodes = calloc((size_t)n_vnodes, sizeof(*ring->vnodes));
  if (!ring->vnodes) {
    free(ring);
    return NULL;
  }
  ring->n_eps = n_eps;
  ring->n_vnodes = n_vnodes;
  ring->replication = replication;
  pthread_rwlock_init(&ring->lock, NULL);
  return ring;
}

chwbl_ring_t *
chwbl_create_ring(const proxy_epval_t *epv, int replication)
{
  char vnode_key[128];
  chwbl_ring_t *ring;
  size_t total;
  int idx = 0;

  if (!epv || epv->n_eps <= 0 || epv->n_eps > MAX_PROXY_EP ||
      replication <= 0 || (size_t)epv->n_eps > SIZE_MAX / (size_t)replication)
    return NULL;
  total = (size_t)epv->n_eps * (size_t)replication;
  if (total > INT32_MAX)
    return NULL;
  ring = chwbl_alloc_ring(epv->n_eps, (int)total, replication);
  if (!ring)
    return NULL;

  for (int i = 0; i < epv->n_eps; i++) {
    for (int j = 0; j < replication; j++) {
      snprintf(vnode_key, sizeof(vnode_key), "%u:%u#%d",
               epv->eps[i].xip, epv->eps[i].xport, j);
      ring->vnodes[idx].hash = XXH64(vnode_key, strlen(vnode_key),
                                     0xDEADBEEF + (i * 7919));
      ring->vnodes[idx++].ep_idx = i;
    }
  }
  qsort(ring->vnodes, ring->n_vnodes, sizeof(*ring->vnodes), compare_vnodes);
  return ring;
}

int chwbl_build_ring(proxy_epval_t *epv, int replication)
{
  chwbl_ring_t *candidate = chwbl_create_ring(epv, replication);
  if (!candidate)
    return -1;
  epv->hash_ring = candidate;
  return 0;
}

/* Weighted ring geometry uses an exact total budget. Every active positive-
 * weight endpoint first receives one vnode; the remainder is distributed by
 * largest remainder with endpoint order as the deterministic tie breaker. */
chwbl_ring_t *
chwbl_create_weighted_ring(const proxy_epval_t *epv, int budget)
{
  uint64_t total_weight = 0;
  uint64_t remainder[MAX_PROXY_EP] = {0};
  int allocation[MAX_PROXY_EP] = {0};
  int positive = 0, allocated = 0, idx = 0;
  char vnode_key[128];
  chwbl_ring_t *ring;

  if (!epv || epv->n_eps <= 0 || epv->n_eps > MAX_PROXY_EP || budget <= 0)
    return NULL;
  for (int i = 0; i < epv->n_eps; i++) {
    if (epv->eps[i].inv == 0 && epv->eps[i].weight > 0) {
      positive++;
      total_weight += (uint64_t)epv->eps[i].weight;
    }
  }
  if (positive == 0 || budget < positive || total_weight == 0)
    return NULL;

  int distributable = budget - positive;
  for (int i = 0; i < epv->n_eps; i++) {
    if (epv->eps[i].inv != 0 || epv->eps[i].weight <= 0)
      continue;
    uint64_t product = (uint64_t)distributable * (uint64_t)epv->eps[i].weight;
    allocation[i] = 1 + (int)(product / total_weight);
    remainder[i] = product % total_weight;
    allocated += allocation[i];
  }
  while (allocated < budget) {
    int best = -1;
    for (int i = 0; i < epv->n_eps; i++) {
      if (epv->eps[i].inv != 0 || epv->eps[i].weight <= 0)
        continue;
      if (best < 0 || remainder[i] > remainder[best])
        best = i;
    }
    if (best < 0)
      return NULL;
    allocation[best]++;
    remainder[best] = 0;
    allocated++;
  }

  ring = chwbl_alloc_ring(epv->n_eps, budget, budget);
  if (!ring)
    return NULL;
  for (int i = 0; i < epv->n_eps; i++) {
    for (int j = 0; j < allocation[i]; j++) {
      snprintf(vnode_key, sizeof(vnode_key), "%u:%u#%d",
               epv->eps[i].xip, epv->eps[i].xport, j);
      ring->vnodes[idx].hash = XXH64(vnode_key, strlen(vnode_key),
                                     0xDEADBEEF + (i * 7919));
      ring->vnodes[idx++].ep_idx = i;
    }
  }
  qsort(ring->vnodes, ring->n_vnodes, sizeof(*ring->vnodes), compare_vnodes);
  return ring;
}

int chwbl_build_weighted_ring(proxy_epval_t *epv)
{
  int budget = epv && epv->chwbl_config ? epv->chwbl_config->replication : 0;
  chwbl_ring_t *candidate = chwbl_create_weighted_ring(epv, budget);
  if (!candidate)
    return -1;
  epv->hash_ring = candidate;
  return 0;
}

int
chwbl_prepare_runtime(proxy_epval_t *candidate, const proxy_arg_t *arg,
                      const proxy_epval_t *previous)
{
  chwbl_config_t *config;

  if (!candidate || !arg)
    return -1;
  candidate->hash_ring = NULL;
  candidate->chwbl_config = NULL;
  if (candidate->select != PROXY_SEL_CHWBL &&
      candidate->select != PROXY_SEL_WRR_HASH)
    return 0;
  if (candidate->n_eps <= 0 || candidate->n_eps > MAX_PROXY_EP)
    return -1;

  config = calloc(1, sizeof(*config));
  if (!config)
    return -1;
  config->prefix_hash_level = arg->chwbl_prefix_hash_level ?
                              arg->chwbl_prefix_hash_level : 1;
  config->prefix_hash_flags = arg->chwbl_prefix_hash_flags;
  config->mean_load_factor = arg->chwbl_mean_load_factor ?
                             arg->chwbl_mean_load_factor : 175;
  config->replication = arg->chwbl_replication ? arg->chwbl_replication : 256;
  config->enable_cache_salt = arg->chwbl_enable_cache_salt ? 1 : 0;
  uint32_t level_mask = 0x1f;
  if (config->prefix_hash_level >= 2)
    level_mask |= PREFIX_HAS_SESSION_CTX;
  if (config->prefix_hash_level >= 3)
    level_mask |= PREFIX_HAS_RAG_TEMPLATE | PREFIX_HAS_RAG_DOC_IDS;
  if (config->prefix_hash_level < 1 || config->prefix_hash_level > 3 ||
      config->mean_load_factor < 100 || config->mean_load_factor > 300 ||
      config->replication < 1 || config->replication > 1024 ||
      (config->prefix_hash_flags && (config->prefix_hash_flags & ~level_mask)) ||
      (config->enable_cache_salt && config->prefix_hash_flags &&
       !(config->prefix_hash_flags & PREFIX_HAS_CACHE_SALT))) {
    free(config);
    return -1;
  }

  for (int i = 0; i < candidate->n_eps; i++) {
    uint32_t active = 0, requests = 0;
    if (previous && previous->chwbl_config) {
      for (int j = 0; j < previous->n_eps; j++) {
        if (candidate->eps[i].xip == previous->eps[j].xip &&
            candidate->eps[i].xport == previous->eps[j].xport) {
          active = atomic_load(&previous->chwbl_config->ep_loads[j].active_conns);
          requests = atomic_load(&previous->chwbl_config->ep_loads[j].total_requests);
          break;
        }
      }
    }
    atomic_init(&config->ep_loads[i].active_conns, active);
    atomic_init(&config->ep_loads[i].total_requests, requests);
    config->ep_loads[i].last_update_ts = time(NULL);
    config->ep_loads[i].ep_available = candidate->eps[i].inv == 0;
  }
  candidate->chwbl_config = config;
  candidate->hash_ring = candidate->select == PROXY_SEL_CHWBL ?
      chwbl_create_ring(candidate, config->replication) :
      chwbl_create_weighted_ring(candidate, config->replication);
  if (!candidate->hash_ring) {
    free(config);
    candidate->chwbl_config = NULL;
    return -1;
  }
  return 0;
}

void
chwbl_release_runtime(proxy_epval_t *epv)
{
  if (!epv)
    return;
  if (epv->hash_ring)
    chwbl_destroy_ring(epv->hash_ring);
  free(epv->chwbl_config);
  epv->hash_ring = NULL;
  epv->chwbl_config = NULL;
}

// P1.2: Lookup endpoint in hash ring (clockwise search)
int chwbl_ring_lookup(chwbl_ring_t *ring, uint64_t hash)
{
  int left = 0;
  int right = ring->n_vnodes - 1;
  int mid;
  
  if (!ring || ring->n_vnodes == 0) {
    return -1;
  }
  
  // Binary search for first vnode with hash >= target
  while (left < right) {
    mid = left + (right - left) / 2;
    
    if (ring->vnodes[mid].hash < hash) {
      left = mid + 1;
    } else {
      right = mid;
    }
  }
  
  // If hash is larger than all vnodes, wrap around to first
  if (left >= ring->n_vnodes) {
    left = 0;
  }
  
  return ring->vnodes[left].ep_idx;
}

// P1.2: Destroy hash ring
void chwbl_destroy_ring(chwbl_ring_t *ring)
{
  if (!ring) return;
  
  pthread_rwlock_wrlock(&ring->lock);
  
  if (ring->vnodes) {
    free(ring->vnodes);
    ring->vnodes = NULL;
  }
  
  pthread_rwlock_unlock(&ring->lock);
  pthread_rwlock_destroy(&ring->lock);
  
  free(ring);
}

// P1.3: CHWBL endpoint selection with load bounds
// Returns: selected endpoint index on success, -1 on failure
int chwbl_select_endpoint(chwbl_ring_t *ring, chwbl_config_t *config,
                                   uint64_t hash, proxy_epval_t *tepval,
                                   int *selected_ep, int skip_load_balance)
{
  (void)skip_load_balance;
  if (!ring || !config || !tepval || !selected_ep) {
    return -1;
  }
  
  // 1. Lookup in hash ring
  pthread_rwlock_rdlock(&ring->lock);
  int initial_ep = chwbl_ring_lookup(ring, hash);
  pthread_rwlock_unlock(&ring->lock);
  
  if (initial_ep < 0 || initial_ep >= tepval->n_eps) {
    log_error("CHWBL: Invalid endpoint %d from ring lookup", initial_ep);
    return -1;
  }
  
  // 2. Check health
  if (!is_endpoint_healthy(tepval, initial_ep)) {
    log_debug("CHWBL: Initial EP%d unhealthy, finding alternative", initial_ep);
    initial_ep = find_next_healthy_endpoint(tepval, initial_ep);
    if (initial_ep < 0) {
      log_error("CHWBL: No healthy endpoints available");
      return -1;
    }
  }
  
  // 3. Check the FUTURE load (including this request). Hashed traffic never
  // bypasses the configured bounded-load policy.
  uint32_t max_load = UINT32_MAX;  // default: no spillover
  uint32_t current_load = atomic_load(&config->ep_loads[initial_ep].active_conns);
  int sel = initial_ep;

  {
    uint32_t total_load = 0;
    for (int i = 0; i < tepval->n_eps; i++) {
      total_load += atomic_load(&config->ep_loads[i].active_conns);
    }
    
    // Calculate max_load with proper bounded-load semantics
    // Formula: max_load = ceil((total_load / n_eps) * load_factor)
    // load_factor = mean_load_factor / 100 (e.g., 175 → 1.75x average)
    //
    // Key insight: We should compare against FUTURE state (after adding this connection)
    // to prevent race conditions and ensure smooth distribution.
    //
    // Example scenarios:
    //   2 EPs, total=0: avg=0, max=max(1, 2) = 2 (allow some initial imbalance)
    //   2 EPs, total=2: avg=1, max=ceil(1*1.75) = 2 (allow 25% imbalance)
    //   2 EPs, total=4: avg=2, max=ceil(2*1.75) = 3 (allow 3 on one EP)
    uint64_t future_total = (uint64_t)total_load + 1;
    uint64_t denominator = (uint64_t)tepval->n_eps * 100;
    max_load = (uint32_t)((future_total * config->mean_load_factor + denominator - 1) /
                          denominator);
    if (max_load < 1)
      max_load = 1;
    
    if ((uint64_t)current_load + 1 > max_load) {
      log_debug("CHWBL: EP%d at max load (%u/%u), probing alternatives",
                initial_ep, current_load, max_load);
      
      // 4. Probe next vnode (power of 2 choices)
      pthread_rwlock_rdlock(&ring->lock);
      int probe_ep = chwbl_ring_lookup(ring, hash + 1);
      pthread_rwlock_unlock(&ring->lock);
      
      if (probe_ep >= 0 && probe_ep < tepval->n_eps &&
          is_endpoint_healthy(tepval, probe_ep) &&
          atomic_load(&config->ep_loads[probe_ep].active_conns) < max_load) {
        sel = probe_ep;
        log_debug("CHWBL: Probe found EP%d with load %u", sel,
                  atomic_load(&config->ep_loads[sel].active_conns));
      } else {
        // 5. Fallback: least loaded endpoint
        uint32_t min_load = UINT32_MAX;
        sel = -1;
        for (int i = 0; i < tepval->n_eps; i++) {
          if (is_endpoint_healthy(tepval, i)) {
            uint32_t load = atomic_load(&config->ep_loads[i].active_conns);
            if (load < min_load) {
              min_load = load;
              sel = i;
            }
          }
        }
        
        if (sel < 0) {
          log_error("CHWBL: All endpoints overloaded or unhealthy");
          return -1;
        }
        log_debug("CHWBL: Fallback to least loaded EP%d (load=%u)", sel, min_load);
      }
    }
  }
  
  // 6. Increment load counter
  atomic_fetch_add(&config->ep_loads[sel].active_conns, 1);
  
  log_info("P1.3: CHWBL selected EP%d for hash 0x%016lx (load=%u/%u)", 
           sel, hash, current_load + 1, max_load);
  
  *selected_ep = sel;
  return 0;
}

// P3.5: WRR_HASH endpoint selection - Weighted Consistent Hash + Bounded Loads
// Combines weighted vnode allocation (for heterogeneous capacity) with load tracking
// This function reuses CHWBL's load tracking infrastructure but uses weighted ring
// Returns: 0 on success with selected_ep populated, -1 on failure
int wrr_hash_select_endpoint(chwbl_ring_t *ring, chwbl_config_t *config,
                                     uint64_t hash, proxy_epval_t *tepval,
                                     int *selected_ep, int skip_load_balance)
{
  (void)skip_load_balance;
  if (!ring || !config || !tepval || !selected_ep) {
    log_error("WRR_HASH: Invalid arguments (NULL pointer)");
    return -1;
  }
  
  // 1. Lookup in weighted hash ring (finds endpoint based on hash)
  pthread_rwlock_rdlock(&ring->lock);
  int initial_ep = chwbl_ring_lookup(ring, hash);
  
#ifdef HAVE_PROXY_EXTRA_DEBUG
  // Debug: Show which vnode was selected
  int vnode_idx = -1;
  for (int i = 0; i < ring->n_vnodes; i++) {
    if (ring->vnodes[i].hash >= hash) {
      vnode_idx = i;
      break;
    }
  }
  if (vnode_idx == -1) vnode_idx = 0;  // Wrapped around
  
  log_debug("WRR_HASH: Hash 0x%016lx → vnode[%d] (vhash=0x%016lx, EP%d)", 
            hash, vnode_idx, ring->vnodes[vnode_idx].hash, ring->vnodes[vnode_idx].ep_idx);
#endif
  
  pthread_rwlock_unlock(&ring->lock);
  
  if (initial_ep < 0 || initial_ep >= tepval->n_eps) {
    log_error("WRR_HASH: Invalid endpoint %d from ring lookup", initial_ep);
    return -1;
  }
  
  // 2. Check endpoint health (P2 integration)
  if (!is_endpoint_healthy(tepval, initial_ep)) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("WRR_HASH: Initial EP%d unhealthy, finding alternative", initial_ep);
#endif
    initial_ep = find_next_healthy_endpoint(tepval, initial_ep);
    if (initial_ep < 0) {
      log_error("WRR_HASH: No healthy endpoints available");
      return -1;
    }
  }
  
  // 3. Check the future load. Content hashes are not exempt from bounds.
  uint32_t max_load = UINT32_MAX;  // default: no spillover
  uint32_t current_load = atomic_load(&config->ep_loads[initial_ep].active_conns);
  int sel = initial_ep;

  {
    uint32_t total_load = 0;
    for (int i = 0; i < tepval->n_eps; i++) {
      total_load += atomic_load(&config->ep_loads[i].active_conns);
    }
    
    uint64_t future_total = (uint64_t)total_load + 1;
    uint64_t denominator = (uint64_t)tepval->n_eps * 100;
    max_load = (uint32_t)((future_total * config->mean_load_factor + denominator - 1) /
                          denominator);
    if (max_load < 1)
      max_load = 1;
    
    // 4. If initial endpoint is overloaded, probe alternative
    if ((uint64_t)current_load + 1 > max_load) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("WRR_HASH: EP%d at max load (%u/%u), probing alternatives",
                initial_ep, current_load, max_load);
#endif
      
      // Power of 2 choices: probe next vnode in hash ring
      pthread_rwlock_rdlock(&ring->lock);
      int probe_ep = chwbl_ring_lookup(ring, hash + 1);
      pthread_rwlock_unlock(&ring->lock);
      
      if (probe_ep >= 0 && probe_ep < tepval->n_eps &&
          is_endpoint_healthy(tepval, probe_ep) &&
          atomic_load(&config->ep_loads[probe_ep].active_conns) < max_load) {
        sel = probe_ep;
#ifdef HAVE_PROXY_EXTRA_DEBUG
        log_debug("WRR_HASH: Probe found EP%d with load %u", sel,
                  atomic_load(&config->ep_loads[sel].active_conns));
#endif
      } else {
        // 5. Fallback: Select least loaded endpoint (maintains availability)
        uint32_t min_load = UINT32_MAX;
        sel = -1;
        for (int i = 0; i < tepval->n_eps; i++) {
          if (is_endpoint_healthy(tepval, i)) {
            uint32_t load = atomic_load(&config->ep_loads[i].active_conns);
            if (load < min_load) {
              min_load = load;
              sel = i;
            }
          }
        }
        
        if (sel < 0) {
          log_error("WRR_HASH: All endpoints overloaded or unhealthy");
          return -1;
        }
#ifdef HAVE_PROXY_EXTRA_DEBUG
        log_debug("WRR_HASH: Fallback to least loaded EP%d (load=%u)", sel, min_load);
#endif
      }
    }
  }
  
  // 6. Increment load counter (atomic operation)
  atomic_fetch_add(&config->ep_loads[sel].active_conns, 1);

#ifdef HAVE_PROXY_EXTRA_DEBUG
  uint32_t selected_load_before = atomic_load(&config->ep_loads[sel].active_conns) - 1;
  log_info("P3.5: WRR_HASH selected EP%d (weight=%d) for hash 0x%016lx (load=%u→%u, max=%u)", 
           sel, tepval->eps[sel].weight, hash, selected_load_before, selected_load_before + 1, max_load);
#endif
  
  *selected_ep = sel;
  return 0;
}

// P1.3: Update load tracking (decrement) - called when connection closes
// PRODUCTION SAFEGUARDS: Prevent underflow, log anomalies, validate state
void chwbl_dec_load(chwbl_config_t *config, int ep_idx)
{
  if (!config) {
    log_error("CHWBL: dec_load called with NULL config");
    return;
  }
  
  if (ep_idx < 0 || ep_idx >= MAX_PROXY_EP) {
    log_error("CHWBL: dec_load called with invalid ep_idx=%d", ep_idx);
    return;
  }
  
  uint32_t current = atomic_load(&config->ep_loads[ep_idx].active_conns);
  
  if (current > 0) {
    atomic_fetch_sub(&config->ep_loads[ep_idx].active_conns, 1);
    log_debug("CHWBL: Decremented load for EP%d: %u -> %u", ep_idx, current, current - 1);
  } else {
    // PRODUCTION WARNING: Load counter underflow attempt detected
    log_error("CHWBL: Attempted to decrement load for EP%d but counter is already 0 (underflow protection)", ep_idx);
    
    // In production, this indicates:
    // 1. Double-decrement bug
    // 2. Missing increment
    // 3. Incorrect connection lifecycle tracking
    // This log helps diagnose load tracking inconsistencies
  }
  
  config->ep_loads[ep_idx].last_update_ts = time(NULL);
}

int
chwbl_select_runtime(proxy_epval_t *epv, uint64_t hash, int *selected_ep)
{
  int rc = -1;
  if (!epv)
    return -1;
  pthread_rwlock_rdlock(&epv->chwbl_state_lock);
  if (epv->select == PROXY_SEL_CHWBL)
    rc = chwbl_select_endpoint(epv->hash_ring, epv->chwbl_config, hash,
                               epv, selected_ep, 0);
  else if (epv->select == PROXY_SEL_WRR_HASH)
    rc = wrr_hash_select_endpoint(epv->hash_ring, epv->chwbl_config, hash,
                                  epv, selected_ep, 0);
  pthread_rwlock_unlock(&epv->chwbl_state_lock);
  return rc;
}

int
chwbl_apply_hash_policy(const chwbl_config_t *config, llm_prefix_key_t *key)
{
  uint32_t level_mask = 0x1f;
  if (!config || !key)
    return -1;
  /* Salt admission is independent of prefix extraction. Otherwise a malformed
   * salt or a required-but-missing salt could bypass the local 400 by taking
   * the ordinary no-prefix fallback path. */
  if (key->cache_salt_invalid)
    return -2;
  if (config->enable_cache_salt && !(key->flags & PREFIX_HAS_CACHE_SALT))
    return -2;
  if (!key->valid)
    return -1;
  if (config->prefix_hash_level >= 2)
    level_mask |= PREFIX_HAS_SESSION_CTX;
  if (config->prefix_hash_level >= 3)
    level_mask |= PREFIX_HAS_RAG_TEMPLATE | PREFIX_HAS_RAG_DOC_IDS;
  key->level = config->prefix_hash_level;
  key->flags &= config->prefix_hash_flags ? config->prefix_hash_flags : level_mask;
  return 0;
}

int
chwbl_hash_and_select_runtime(proxy_epval_t *epv, llm_prefix_key_t *key,
                              int *selected_ep)
{
  int rc;
  if (!epv)
    return -1;
  pthread_rwlock_rdlock(&epv->chwbl_state_lock);
  rc = chwbl_apply_hash_policy(epv->chwbl_config, key);
  if (rc == 0) {
    key->hash = compute_prefix_hash(key);
    if (epv->select == PROXY_SEL_CHWBL)
      rc = chwbl_select_endpoint(epv->hash_ring, epv->chwbl_config, key->hash,
                                 epv, selected_ep, 0);
    else if (epv->select == PROXY_SEL_WRR_HASH)
      rc = wrr_hash_select_endpoint(epv->hash_ring, epv->chwbl_config, key->hash,
                                    epv, selected_ep, 0);
    else
      rc = -1;
  }
  pthread_rwlock_unlock(&epv->chwbl_state_lock);
  return rc;
}

void
chwbl_dec_runtime(proxy_epval_t *epv, int ep_idx)
{
  if (!epv)
    return;
  pthread_rwlock_rdlock(&epv->chwbl_state_lock);
  if ((epv->select == PROXY_SEL_CHWBL || epv->select == PROXY_SEL_WRR_HASH) &&
      epv->chwbl_config)
    chwbl_dec_load(epv->chwbl_config, ep_idx);
  pthread_rwlock_unlock(&epv->chwbl_state_lock);
}

void
chwbl_inc_runtime(proxy_epval_t *epv, int ep_idx)
{
  if (!epv || ep_idx < 0 || ep_idx >= MAX_PROXY_EP)
    return;
  pthread_rwlock_rdlock(&epv->chwbl_state_lock);
  if ((epv->select == PROXY_SEL_CHWBL || epv->select == PROXY_SEL_WRR_HASH) &&
      epv->chwbl_config)
    atomic_fetch_add(&epv->chwbl_config->ep_loads[ep_idx].active_conns, 1);
  pthread_rwlock_unlock(&epv->chwbl_state_lock);
}

// P1.3: PRODUCTION: Validate CHWBL load counter consistency
// Call this periodically to detect and log load tracking drift
// Returns: 0 if consistent, -1 if drift detected
int chwbl_validate_load_counters(proxy_epval_t *tepval)
{
  if (!tepval || !tepval->chwbl_config) {
    return 0;  // Not using CHWBL, skip validation
  }
  
  if (tepval->select != PROXY_SEL_CHWBL) {
    return 0;  // Not using CHWBL mode
  }
  
  int drift_detected = 0;
  uint32_t total_tracked_load = 0;
  
  for (int i = 0; i < tepval->n_eps && i < MAX_PROXY_EP; i++) {
    uint32_t load = atomic_load(&tepval->chwbl_config->ep_loads[i].active_conns);
    total_tracked_load += load;
    
    // Log warning if any endpoint has suspiciously high load
    // (could indicate missing decrements)
    if (load > 10000) {  // Threshold for production monitoring
      log_error("CHWBL: EP%d has abnormally high load counter: %u (possible leak)", i, load);
      drift_detected = -1;
    }
  }
  
  // Log total tracked load for monitoring
  if (total_tracked_load > 0) {
    log_debug("CHWBL: Total tracked load across all endpoints: %u", total_tracked_load);
  }
  
  return drift_detected;
}
#endif /* HAVE_DP_GPU_ROUTING */
