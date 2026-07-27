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

// P1.2: Build consistent hash ring with virtual nodes
int chwbl_build_ring(proxy_epval_t *epv, int replication)
{
  int i, j, idx;
  char vnode_key[128];
  
  if (!epv || epv->n_eps <= 0) {
    log_error("Invalid arguments for hash ring build");
    return -1;
  }
  
  // Allocate ring structure
  epv->hash_ring = calloc(1, sizeof(chwbl_ring_t));
  if (!epv->hash_ring) {
    log_error("Failed to allocate hash ring");
    return -1;
  }
  
  epv->hash_ring->replication = replication;
  epv->hash_ring->n_eps = epv->n_eps;
  epv->hash_ring->n_vnodes = epv->n_eps * replication;
  pthread_rwlock_init(&epv->hash_ring->lock, NULL);
  
  // Allocate virtual nodes array
  epv->hash_ring->vnodes = calloc(epv->hash_ring->n_vnodes, 
                                   sizeof(chwbl_vnode_t));
  if (!epv->hash_ring->vnodes) {
    log_error("Failed to allocate vnodes");
    free(epv->hash_ring);
    epv->hash_ring = NULL;
    return -1;
  }
  
  // Create virtual nodes for each physical endpoint
  idx = 0;
  for (i = 0; i < epv->n_eps; i++) {
    for (j = 0; j < replication; j++) {
      // Generate unique key for each virtual node
      // Format: "endpoint_IP:port#replica_number"
      snprintf(vnode_key, sizeof(vnode_key), "%u:%u#%d",
               epv->eps[i].xip, epv->eps[i].xport, j);
      
      // FIX #2: Add random seed to break sequential IP clustering
      // Use prime number (7919) to ensure good distribution
      epv->hash_ring->vnodes[idx].hash = XXH64(vnode_key, strlen(vnode_key), 
                                                0xDEADBEEF + (i * 7919));
      epv->hash_ring->vnodes[idx].ep_idx = i;
      idx++;
    }
  }
  
  // Sort virtual nodes by hash value for binary search
  qsort(epv->hash_ring->vnodes, epv->hash_ring->n_vnodes,
        sizeof(chwbl_vnode_t), compare_vnodes);  
  
  return 0;
}

// P3.5: Build weighted consistent hash ring with weight-proportional virtual nodes
// This allocates vnodes proportionally to endpoint weights for heterogeneous server capacity
// Example: weights [50, 30, 20] with 256 total vnodes → [128, 77, 51] vnodes per endpoint
int chwbl_build_weighted_ring(proxy_epval_t *epv)
{
  int i, j, idx;
  char vnode_key[128];
  const int TOTAL_VNODES = 256;  // Global constant for all hash ring modes
  
  if (!epv || epv->n_eps <= 0) {
    log_error("WRR_HASH: Invalid arguments for weighted hash ring build");
    return -1;
  }
  
  // Allocate ring structure
  epv->hash_ring = calloc(1, sizeof(chwbl_ring_t));
  if (!epv->hash_ring) {
    log_error("WRR_HASH: Failed to allocate hash ring");
    return -1;
  }
  
  epv->hash_ring->n_eps = epv->n_eps;
  pthread_rwlock_init(&epv->hash_ring->lock, NULL);
  
  // Calculate total weight (sum of all endpoint weights)
  int total_weight = 0;
  for (i = 0; i < epv->n_eps; i++) {
    int weight = epv->eps[i].weight ? epv->eps[i].weight : 1;  // Default weight = 1
    total_weight += weight;
  }
  
  if (total_weight == 0) {
    log_error("WRR_HASH: Total weight is zero, using equal distribution");
    total_weight = epv->n_eps;  // Fallback to equal weights
  }
  
  // Allocate vnodes array (max TOTAL_VNODES)
  epv->hash_ring->vnodes = calloc(TOTAL_VNODES, sizeof(chwbl_vnode_t));
  if (!epv->hash_ring->vnodes) {
    log_error("WRR_HASH: Failed to allocate vnodes");
    free(epv->hash_ring);
    epv->hash_ring = NULL;
    return -1;
  }
  
  // Allocate vnodes proportionally to weights
  idx = 0;
  int vnodes_allocated[MAX_PROXY_EP] = {0};  // Track allocation per endpoint
  
  for (i = 0; i < epv->n_eps && idx < TOTAL_VNODES; i++) {
    int weight = epv->eps[i].weight ? epv->eps[i].weight : 1;
    
    // Calculate proportional vnodes: (TOTAL_VNODES * weight) / total_weight
    int num_vnodes = (TOTAL_VNODES * weight) / total_weight;
    
    // Ensure at least 1 vnode per active endpoint (for availability)
    if (num_vnodes == 0 && epv->eps[i].inv == 0) {
      num_vnodes = 1;
    }
    
    vnodes_allocated[i] = num_vnodes;
    
    // Generate virtual nodes for this endpoint
    for (j = 0; j < num_vnodes && idx < TOTAL_VNODES; j++) {
      // Generate unique key for each virtual node
      // Format: "endpoint_IP:port#replica_number"
      snprintf(vnode_key, sizeof(vnode_key), "%u:%u#%d",
               epv->eps[i].xip, epv->eps[i].xport, j);
      
      // Use XXH64 with seed to generate hash (same as CHWBL)
      // Add prime number (7919) to break sequential IP clustering
      epv->hash_ring->vnodes[idx].hash = XXH64(vnode_key, strlen(vnode_key), 
                                                0xDEADBEEF + (i * 7919));
      epv->hash_ring->vnodes[idx].ep_idx = i;
      idx++;
    }
  }
  
  // Handle rounding errors: distribute remaining vnodes to endpoints with highest weights
  int remaining = TOTAL_VNODES - idx;
  if (remaining > 0) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("WRR_HASH: Distributing %d remaining vnodes due to rounding", remaining);
#endif
    for (i = 0; i < epv->n_eps && remaining > 0 && idx < TOTAL_VNODES; i++) {
      // Skip inactive endpoints
      if (epv->eps[i].inv != 0) continue;
      
      // Add one more vnode
      snprintf(vnode_key, sizeof(vnode_key), "%u:%u#extra_%d",
               epv->eps[i].xip, epv->eps[i].xport, remaining);
      epv->hash_ring->vnodes[idx].hash = XXH64(vnode_key, strlen(vnode_key), 
                                                0xDEADBEEF + (i * 7919) + remaining);
      epv->hash_ring->vnodes[idx].ep_idx = i;
      idx++;
      remaining--;
      vnodes_allocated[i]++;
    }
  }
  
  epv->hash_ring->n_vnodes = idx;
  epv->hash_ring->replication = idx;  // Store actual total for consistency
  
  // Sort virtual nodes by hash value for binary search
  qsort(epv->hash_ring->vnodes, epv->hash_ring->n_vnodes,
        sizeof(chwbl_vnode_t), compare_vnodes);
#ifdef HAVE_PROXY_EXTRA_DEBUG
  // Log vnode allocation for debugging
  log_info("WRR_HASH: Built weighted ring with %d vnodes for %d endpoints",
           epv->hash_ring->n_vnodes, epv->n_eps);
  for (i = 0; i < epv->n_eps; i++) {
    log_debug("WRR_HASH:   EP%d (weight=%d): %d vnodes (%.1f%%)",
              i, epv->eps[i].weight ? epv->eps[i].weight : 1,
              vnodes_allocated[i],
              (100.0 * vnodes_allocated[i]) / epv->hash_ring->n_vnodes);
  }
  
  // Log first/last few vnodes to see distribution
  log_debug("WRR_HASH: First 5 vnodes:");
  for (i = 0; i < 5 && i < epv->hash_ring->n_vnodes; i++) {
    log_debug("  [%d]: hash=0x%016lx → EP%d", i, 
              epv->hash_ring->vnodes[i].hash, epv->hash_ring->vnodes[i].ep_idx);
  }
  log_debug("WRR_HASH: Last 5 vnodes:");
  for (i = epv->hash_ring->n_vnodes - 5; i < epv->hash_ring->n_vnodes && i >= 0; i++) {
    log_debug("  [%d]: hash=0x%016lx → EP%d", i, 
              epv->hash_ring->vnodes[i].hash, epv->hash_ring->vnodes[i].ep_idx);
  }
#endif
  
  return 0;
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
  
  // 3. Check load bounds with proper rounding to avoid premature spillover
  //    SKIP when skip_load_balance=1: content-based prefix_hash routing for KV cache
  //    locality must not be overridden by bounded load — let the backend queue handle
  //    concurrency. Only health-based failover applies in strict hash mode.
  uint32_t max_load = UINT32_MAX;  // default: no spillover
  uint32_t current_load = atomic_load(&config->ep_loads[initial_ep].active_conns);
  int sel = initial_ep;

  if (!skip_load_balance) {
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
    uint32_t avg_load = (tepval->n_eps > 0) ? (total_load / tepval->n_eps) : 0;
    
    // Calculate max with ceiling: ceil(avg * factor) = (avg * factor + 99) / 100
    max_load = (avg_load * config->mean_load_factor + 99) / 100;
    
    // Minimum bound: Allow at least 1 connection, or n_eps connections total
    // This prevents spurious spillover at low load (e.g., first connection)
    uint32_t min_bound = (total_load < tepval->n_eps) ? tepval->n_eps : 1;
    if (max_load < min_bound) {
      max_load = min_bound;
    }
    
    if (current_load >= max_load) {
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
  
  // 3. Check load bounds (same formula as CHWBL for consistency)
  //    SKIP when skip_load_balance=1: strict prefix_hash routing must not be
  //    overridden by bounded load for KV cache locality in LLM serving.
  uint32_t max_load = UINT32_MAX;  // default: no spillover
  uint32_t current_load = atomic_load(&config->ep_loads[initial_ep].active_conns);
  int sel = initial_ep;

  if (!skip_load_balance) {
    uint32_t total_load = 0;
    for (int i = 0; i < tepval->n_eps; i++) {
      total_load += atomic_load(&config->ep_loads[i].active_conns);
    }
    
    // Calculate max_load with ceiling: ceil(avg * factor) = (avg * factor + 99) / 100
    // load_factor = mean_load_factor / 100 (default: 175 → 1.75x average)
    uint32_t avg_load = (tepval->n_eps > 0) ? (total_load / tepval->n_eps) : 0;
    max_load = (avg_load * config->mean_load_factor + 99) / 100;
    
    // Minimum bound: Allow at least 1 connection, or n_eps connections total
    uint32_t min_bound = (total_load < tepval->n_eps) ? tepval->n_eps : 1;
    if (max_load < min_bound) {
      max_load = min_bound;
    }
    
    // 4. If initial endpoint is overloaded, probe alternative
    if (current_load >= max_load) {
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
