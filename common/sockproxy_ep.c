/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */
/*
 * sockproxy_ep.c -- Endpoint selection, session affinity, conversation mapping
 * Extracted from sockproxy.c Phase 4a refactoring.
 * Functions: session_key_hash, lookup/store/get conversation_endpoint,
 *            strip_port_from_hostname, proxy_setup_ep__,
 *            proxy_conversation_cleanup_thread, proxy_run
 */
#define _GNU_SOURCE
#define HAVE_PROXY_EXTRA_DEBUG
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "log.h"
#include "uthash.h"
#include "notify.h"
#include "sockproxy.h"
#include "sockproxy_internal.h"
#include "sockproxy_metrics.h"
#include "sockproxy_cache.h"    /* cmp_proxy_ent */
#include "sockproxy_conn.h"     /* proxy_setup_ep_connect */
#include "sockproxy_routing.h"  /* find_endpoint_lpm */
#include "sockproxy_l7policy.h" /* Phase 75: l7_route_dispatch (L7 content routing) */
#include "sockproxy_lb.h"       /* wrr_select_endpoint, chwbl_select_endpoint, chwbl_dec_load */
#include "sockproxy_health.h"   /* is_endpoint_healthy, circuit_breaker_record_failure/success */
#include "sockproxy_kv_exact.h" /* Phase 99: pd_kv_exact_select (single-role Tier-1.5 branch) */
#include "sockproxy_ep.h"       /* own header */

#define XXH_STATIC_LINKING_ONLY
/* XXH_IMPLEMENTATION is defined ONLY in sockproxy_lb.c -- see sockproxy_refactoring_plan.md P4 */
#include "xxhash.h"
#include <assert.h>
/* AI GW CGO bridge: normal-mode session-stickiness hit counter (declared in sockproxy_ai_gw.h) */
extern void llb_ai_normal_session_hit(char *model_name);
/* P/D disaggregation: pd_select_prefill, pd_select_decode, pd_session_store,
 * pd_session_evict, pd_trie_evict_lru are declared in sockproxy.h */

/* =========================================================================
 * Phase 70 — sockproxy HA state-sync emit helper (conversation_mapping_t).
 *
 * Mirrors the pd_session_build_event helper in sockproxy_pd.c but for
 * conversation_mapping_t (synced state #2 — PRD table). All emit call
 * sites live AFTER pthread_rwlock_unlock(&ent->val.conv_lock) — never
 * nested inside the wrlock. Service-key resolution walks proxy_struct
 * under PROXY_RDLOCK (Pri-1); safe because conv_lock (Pri-3) has been
 * released by then.
 *
 * Returns 1 on emit-ready, 0 on resolution miss (caller MUST not emit).
 * ========================================================================= */
static int
conv_build_sync_event(proxy_sync_event_t *ev,
                      const proxy_map_ent_t *ent,
                      int kind,
                      const char *conv_id,
                      int ep_idx,
                      uint64_t created_ts, uint64_t last_access_ts,
                      uint32_t request_count)
{
  uint32_t xip;

  if (!ev || !ent || !conv_id || conv_id[0] == '\0')
    return 0;

  memset(ev, 0, sizeof(*ev));
  ev->kind           = kind;
  ev->prefill_ep_idx = -1;
  ev->decode_ep_idx  = -1;
  ev->ep_idx         = ep_idx;
  ev->created_ts     = created_ts;
  ev->last_access_ts = last_access_ts;
  ev->request_count  = request_count;

  strncpy(ev->conv_id, conv_id, sizeof(ev->conv_id) - 1);
  ev->conv_id[sizeof(ev->conv_id) - 1] = '\0';

  /* No further locking needed: caller passes ent by-pointer; ent's lifetime
   * is bounded by proxy_struct itself which we are not removing. */
  xip = ent->key.xip;
  snprintf(ev->service_key, sizeof(ev->service_key), "%u.%u.%u.%u:%u:%u",
           (xip >> 24) & 0xFF, (xip >> 16) & 0xFF,
           (xip >> 8) & 0xFF,  xip & 0xFF,
           (unsigned)ent->key.xport,
           (unsigned)ent->key.protocol);
  return 1;
}

// Session hash and server selection
uint32_t
session_key_hash(const char *session_key)
{
  uint32_t hash = 5381;
  for (int i = 0; session_key[i]; i++) {
    hash = ((hash << 5) + hash) + session_key[i];
  }
  return hash;
}

/* proxy_setup_ep_connect moved to sockproxy_conn.c (Phase 3) */

// P0.3: Find existing conversation mapping
static int __attribute__((unused))
lookup_conversation_endpoint(proxy_map_ent_t *ent, 
                              const char *conv_id,
                              int *ep_idx)
{
  conversation_mapping_t *mapping = NULL;
  time_t now = time(NULL);
  int found = 0;
  
  if (!conv_id || conv_id[0] == '\0') {
    return -1;
  }
  
  // CRITICAL-2 FIX: Use WRITE lock since we modify mapping fields
  pthread_rwlock_wrlock(&ent->val.conv_lock);
  HASH_FIND_STR(ent->val.conv_map, conv_id, mapping);

  if (mapping) {
    *ep_idx = mapping->ep_idx;
    mapping->last_access_ts = now;        // Safe under WRITE lock
    mapping->request_count++;             // Safe under WRITE lock
    found = 1;

    // METRICS: Track conversation hit (TIER 1, Metric #2)
    atomic_fetch_add(&global_stats.conversation_hits, 1);
  } else {
    // METRICS: Track conversation miss (TIER 1, Metric #2)
    atomic_fetch_add(&global_stats.conversation_misses, 1);
  }

  pthread_rwlock_unlock(&ent->val.conv_lock);
  return found ? 0 : -1;
}

// P0.3: Get conversation mapping with full metadata (for smart validation)
conversation_mapping_t*
get_conversation_mapping(proxy_map_ent_t *ent, const char *conv_id)
{
  conversation_mapping_t *mapping = NULL;
  
  if (!conv_id || conv_id[0] == '\0') {
    return NULL;
  }
  
  pthread_rwlock_rdlock(&ent->val.conv_lock);
  HASH_FIND_STR(ent->val.conv_map, conv_id, mapping);
  pthread_rwlock_unlock(&ent->val.conv_lock);
  
  return mapping;
}

// P0.3: Update conversation validation state (after GPU check)
static void __attribute__((unused))
update_conversation_validation(proxy_map_ent_t *ent,
                                const char *conv_id,
                                uint64_t metrics_version,
                                uint8_t is_healthy)
{
  conversation_mapping_t *mapping = NULL;
  
  if (!conv_id || conv_id[0] == '\0') {
    return;
  }
  
  pthread_rwlock_wrlock(&ent->val.conv_lock);
  HASH_FIND_STR(ent->val.conv_map, conv_id, mapping);
  
  if (mapping) {
    mapping->cached_metrics_version = metrics_version;
    mapping->validated_healthy = is_healthy;
    mapping->last_access_ts = time(NULL);
  }
  
  pthread_rwlock_unlock(&ent->val.conv_lock);
}

// P0.3: Store new conversation mapping
int 
store_conversation_endpoint(proxy_map_ent_t *ent,
                            const char *conv_id,
                            int ep_idx)
{
  conversation_mapping_t *mapping;
  conversation_mapping_t *existing = NULL;
  time_t now = time(NULL);
  
  if (!conv_id || conv_id[0] == '\0') {
    return -1;
  }
  
  pthread_rwlock_wrlock(&ent->val.conv_lock);
  
  // CRITICAL FIX: Check if mapping already exists (prevents memory leak on duplicate)
  HASH_FIND_STR(ent->val.conv_map, conv_id, existing);
  
  if (existing) {
    /* Phase 70 — capture state under wrlock for emit-after-unlock. */
    uint64_t emit_created_ts    = existing->created_ts;
    uint64_t emit_last_access   = existing->last_access_ts;
    uint32_t emit_request_count = existing->request_count;

    // Update existing mapping instead of creating duplicate
    existing->ep_idx = ep_idx;
    existing->last_access_ts = now;
    existing->request_count++;
    existing->cached_metrics_version = 0;  // Reset validation state
    existing->validated_healthy = 0;
    /* re-capture incremented value for emit */
    emit_request_count = existing->request_count;
    emit_last_access   = existing->last_access_ts;

    pthread_rwlock_unlock(&ent->val.conv_lock);
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[CONV_UPDATE] Updated existing mapping '%s' → endpoint[%d] (request_count=%u)",
              conv_id, ep_idx, existing->request_count);
#endif
    /* Phase 70 EMIT SITE #1 (sockproxy_ep.c) [PHASE_70_EMIT_EP_001] — conversation UPDATE.
     * Emit-after-unlock: conv_lock released by the line above. */
    {
      proxy_sync_event_t _ev70;
      if (conv_build_sync_event(&_ev70, ent, SYNC_CONV_UPDATE, conv_id, ep_idx,
                                emit_created_ts, emit_last_access, emit_request_count))
        llb_sockproxy_emit_sync_event(&_ev70);
    }
    return 0;
  }

  // Create new mapping
  mapping = calloc(1, sizeof(*mapping));
  if (!mapping) {
    pthread_rwlock_unlock(&ent->val.conv_lock);
    return -1;
  }

  strncpy(mapping->conv_id, conv_id, sizeof(mapping->conv_id)-1);
  mapping->conv_id[sizeof(mapping->conv_id)-1] = '\0';
  mapping->ep_idx = ep_idx;
  mapping->created_ts = now;
  mapping->last_access_ts = now;
  mapping->request_count = 1;

  // Initialize smart validation state
  mapping->cached_metrics_version = 0;  // Will be set on first validation
  mapping->validated_healthy = 0;       // Not yet validated

  HASH_ADD_STR(ent->val.conv_map, conv_id, mapping);
  /* Phase 70 — capture state under wrlock for emit-after-unlock. */
  {
    uint64_t emit_created_ts    = mapping->created_ts;
    uint64_t emit_last_access   = mapping->last_access_ts;
    uint32_t emit_request_count = mapping->request_count;
    int      emit_ep_idx        = mapping->ep_idx;
    pthread_rwlock_unlock(&ent->val.conv_lock);

#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[CONV_NEW] Created new mapping '%s' → endpoint[%d]", conv_id, ep_idx);
#endif

    /* Phase 70 EMIT SITE #2 (sockproxy_ep.c) [PHASE_70_EMIT_EP_002] — conversation CREATE.
     * Emit-after-unlock: conv_lock released by the line above. */
    {
      proxy_sync_event_t _ev70;
      if (conv_build_sync_event(&_ev70, ent, SYNC_CONV_CREATE, conv_id, emit_ep_idx,
                                emit_created_ts, emit_last_access, emit_request_count))
        llb_sockproxy_emit_sync_event(&_ev70);
    }
  }

  return 0;
}

// Helper function to strip port from hostname for endpoint lookup
// Example: "example.com:9090" → "example.com"
//          "example.com" → "example.com" (unchanged)
//          "[2001:db8::1]:8080" → "[2001:db8::1]" (IPv6)
void
strip_port_from_hostname(const char *host_with_port, char *host_only, size_t host_only_size)
{
  if (!host_with_port || !host_only || host_only_size == 0) return;
  
  // Find the last colon (IPv6 addresses may have multiple colons)
  const char *port_start = strrchr(host_with_port, ':');
  
  if (port_start) {
    // Check if this is an IPv6 address (contains ']' after last ':')
    const char *bracket = strchr(port_start, ']');
    if (bracket) {
      // IPv6 with port: [2001:db8::1]:8080 - keep everything including bracket
      size_t len = bracket - host_with_port + 1;
      if (len < host_only_size) {
        strncpy(host_only, host_with_port, len);
        host_only[len] = '\0';
      } else {
        strncpy(host_only, host_with_port, host_only_size - 1);
        host_only[host_only_size - 1] = '\0';
      }
    } else {
      // Regular hostname with port - strip the :port part
      size_t len = port_start - host_with_port;
      if (len < host_only_size) {
        strncpy(host_only, host_with_port, len);
        host_only[len] = '\0';
      } else {
        strncpy(host_only, host_with_port, host_only_size - 1);
        host_only[host_only_size - 1] = '\0';
      }
    }
  } else {
    // No port - copy as-is
    strncpy(host_only, host_with_port, host_only_size - 1);
    host_only[host_only_size - 1] = '\0';
  }
}

int
proxy_setup_ep__(uint32_t xip, uint16_t xport, uint8_t protocol,
                 const char *host_str,
                 const char *request_path,  // P6: NEW PARAMETER for path-based routing
                 const char *conv_id,  // P0.3: NEW PARAMETER for conversation ID
                 uint64_t prefix_hash, // P1.3: NEW PARAMETER for CHWBL routing
                 const char *custom_session_header,  // NEW: Custom session header value
                 proxy_ep_sel_t *ep_sel,
                 proxy_epval_t **epv, int *seltype, uint32_t *rid,
                 void *ssl_ctx, void **ssl, uint32_t client_ip,
                 proxy_fd_ent_t *pfe)  // NEW: For tracing context
{
  int sel = 0;
  uint32_t epip;
  uint16_t epport;
  uint8_t epprotocol;
  proxy_ent_t ent = { 0 };
  struct proxy_epval *tepval;
  proxy_map_ent_t *node = proxy_struct->head;
  proxy_map_ent_t *found_ent = NULL;  // Track found entry for catalog_id
  (void)found_ent;  // Suppress unused warning

#ifdef HAVE_HTTP_TRACE
#ifdef HAVE_PROXY_EXTRA_DEBUG
  log_debug("[CATALOG_ENTRY] proxy_setup_ep__ called: xip=%08x xport=%04x pfe=%p", xip, xport, pfe);
#endif
#endif

  ent.xip = xip;
  ent.xport = xport;
  ent.protocol = protocol;
  
#ifdef HAVE_HTTP_TRACE
  // Note: catalog_id will be loaded after finding the proxy entry
#endif

  while (node) {   
    if (cmp_proxy_ent(&node->key, &ent)) {
      found_ent = node;  // Save for catalog_id lookup
#ifdef HAVE_HTTP_TRACE
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("[CATALOG_MATCH] Found proxy entry: xip=%08x xport=%04x proxy_mode=%d", 
                xip, xport, node->val.proxy_mode);
#endif
#endif
      if (node->val.proxy_mode == PROXY_MODE_DFL) {
#ifdef HAVE_HTTP_TRACE
#ifdef HAVE_PROXY_EXTRA_DEBUG
        log_debug("[CATALOG_DFLMODE] Entering PROXY_MODE_DFL block, host_str=%s request_path=%s", 
                  host_str ? host_str : "(null)", request_path ? request_path : "(null)");
#endif
#endif
        if (host_str == NULL) {
          tepval = node->val.ephash;
        } else {
          // Strip port from hostname before lookup (e.g., "example.com:9090" → "example.com")
          char host_only[256];
          strip_port_from_hostname(host_str, host_only, sizeof(host_only));

          // US-202 Criterion A: Determine effective model name with priority:
          //   1. X-Model HTTP header (fast path — set during header parsing)
          //   2. JSON body "model" field (set by extract_llm_prefix during body parsing)
          //   3. "" (empty string — wildcard, backward compatible)
          // Criterion C: same effective_model is the value that llb_ai_validate_key
          // (US-006 CGO bridge) would receive for AllowedModels checking.
          const char *effective_model = "";
          if (pfe && pfe->x_model_header[0] != '\0') {
            effective_model = pfe->x_model_header;       // Priority 1: X-Model header
          } else if (pfe && pfe->prefix_key.model[0] != '\0') {
            effective_model = pfe->prefix_key.model;     // Priority 2: JSON body "model"
          }

          // Phase 75 (D-10): L7 content-routing discriminator + dispatch — the H1
          // seam. Runs AFTER the AI-GW auth/QUOTA gate (handle_on_message_complete,
          // sockproxy_http.c:4532-4593, untouched) and BEFORE the AI model
          // selection. When no L7_POLICY is attached (has_l7_policy==0, the default
          // for every AI service) l7_route_dispatch is a PURE NO-OP returning
          // L7_DISPATCH_FALLTHROUGH, so the model path below runs byte-for-byte
          // unchanged (D-04 / Pitfall 5). The SAME shared helper is invoked at the
          // H2 seam (sockproxy_h2.c) — parity (T-75-12).
          if (node && node->has_l7_policy) {
            proxy_epval_t *l7_tepval = NULL;
            int l7_rc = l7_route_dispatch(pfe, node, &l7_tepval);
            if (l7_rc == L7_DISPATCH_TERMINATED) {
              // REJECT / REDIRECT / no-match already emitted on the client fd.
              return -1;
            } else if (l7_rc == L7_DISPATCH_FORWARD) {
              // FORWARD: a plain pool was resolved; re-enter the existing intra-pool
              // EP-select below WITHOUT touching the AI model engine (D-03).
              tepval = l7_tepval;
              if (!tepval) {
                // FORWARD with no usable pool -> no-route (mirror the AI 503 idiom).
                if (pfe) {
                  const char *l7_no_pool_resp =
                      "HTTP/1.1 503 Service Unavailable\r\n"
                      "Content-Type: application/json\r\n"
                      "Connection: close\r\n"
                      "\r\n"
                      "{\"error\":\"no_route\","
                      "\"detail\":\"L7 FORWARD resolved no backend pool\"}\r\n";
                  send(pfe->fd, l7_no_pool_resp, strlen(l7_no_pool_resp),
                       MSG_DONTWAIT | MSG_NOSIGNAL);
                }
                return -1;
              }
              goto l7_have_tepval;
            }
            // L7_DISPATCH_FALLTHROUGH (defensive: dispatch is itself a no-op when
            // has_l7_policy==0) — fall through to the unchanged AI/LPM path.
          }

          // US-202 Criterion B: find_endpoint_lpm tries model-specific pool first, then
          // wildcard pool (empty model_name).  Returns NULL only when both lookups fail.
          tepval = find_endpoint_lpm(node, host_only, request_path, effective_model);

          if (!tepval) {
            // 503 when a model was specified but no pool (specific or wildcard) was found
            if (pfe && effective_model[0] != '\0') {
              char response_buf[512];
              snprintf(response_buf, sizeof(response_buf),
                       "HTTP/1.1 503 Service Unavailable\r\n"
                       "Content-Type: application/json\r\n"
                       "Connection: close\r\n"
                       "\r\n"
                       "{\"error\":\"model_unavailable\",\"model\":\"%s\","
                       "\"detail\":\"no backend pool for this model\"}\r\n",
                       effective_model);
              send(pfe->fd, response_buf, strlen(response_buf),
                   MSG_DONTWAIT | MSG_NOSIGNAL);
              log_info("[MODEL_ROUTING] 503 sent for model='%s' on fd=%d",
                       effective_model, pfe->fd);
              return -1;
            }
            // PB-4 FIX: When find_endpoint_lpm returns NULL (no path prefix matched,
            // no hostname-only rule, no empty-hostname rule), send 503 instead of
            // falling back to an arbitrary first hash entry.  A NULL return from
            // find_endpoint_lpm means the request path genuinely has no matching rule.
            if (pfe) {
              const char *no_route_resp =
                  "HTTP/1.1 503 Service Unavailable\r\n"
                  "Content-Type: application/json\r\n"
                  "Connection: close\r\n"
                  "\r\n"
                  "{\"error\":\"no_route\","
                  "\"detail\":\"no routing rule matched the request path\"}\r\n";
              send(pfe->fd, no_route_resp, strlen(no_route_resp),
                   MSG_DONTWAIT | MSG_NOSIGNAL);
              log_info("[PROXY_NO_ROUTE] 503 sent: no prefix match for path='%s' on fd=%d",
                       request_path ? request_path : "", pfe->fd);
              return -1;
            }
            // Non-HTTP path (raw TCP, no pfe): keep backward-compat fallback
            tepval = node->val.ephash;
            if (!tepval) {
              /* Production fix: all rules deleted for this VIP:port but listener
               * kept open.  Return HTTP 503 so callers get a clean error instead
               * of a silent connection-reset. */
              if (pfe) {
                const char *no_rule_resp =
                    "HTTP/1.1 503 Service Unavailable\r\n"
                    "Content-Type: application/json\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                    "{\"error\":\"no_rules\","
                    "\"detail\":\"all routing rules have been removed for this service\"}\r\n";
                send(pfe->fd, no_rule_resp, strlen(no_rule_resp),
                     MSG_DONTWAIT | MSG_NOSIGNAL);
                log_info("[PROXY_NO_RULES] 503 sent on fd=%d (empty ephash)", pfe->fd);
              } else {
                log_error("Default endpoint (ephash) is NULL!");
              }
            }
          }
        }

      l7_have_tepval:  // Phase 75: L7 FORWARD jumps here with a resolved plain pool
        if (tepval == NULL) {
#ifdef HAVE_HTTP_TRACE
#ifdef HAVE_PROXY_EXTRA_DEBUG
          log_debug("[CATALOG_NOTEPVAL] tepval is NULL, breaking early");
#endif
#endif
          break;
        }
        
        // Endpoint selection based on algorithm
        int algorithm_selection = -1;
        
#ifdef HAVE_DP_GPU_ROUTING
        // Check selection algorithm
        switch (tepval->select) {
          case PROXY_SEL_CHWBL:
            {              
              uint64_t routing_hash = 0;
              
              // Determine routing hash from available sources
              // PRIMARY: prefix_hash (model+prompt content) for KV cache locality
              // FALLBACK: conv_id for session stickiness (multi-turn conversations)
              // LAST: round-robin
              if (prefix_hash != 0) {
                // Use content-based prefix hash (model name + prompt prefix)
                routing_hash = prefix_hash;
              } else if (conv_id && conv_id[0] != '\0') {
                // Fallback: use conversation ID for session stickiness
                routing_hash = XXH64(conv_id, strlen(conv_id), 0);
              } else {
                // Last resort: round-robin
                routing_hash = XXH64(&tepval->ep_sel, sizeof(tepval->ep_sel), 0);
                tepval->ep_sel++;
              }
              
              if (tepval->hash_ring && tepval->chwbl_config) {
                if (chwbl_select_endpoint(tepval->hash_ring, tepval->chwbl_config,
                                           routing_hash, tepval, &algorithm_selection,
                                           (prefix_hash != 0) ? 1 : 0) < 0) {
                  log_error("P1.3: CHWBL selection failed, falling back to round-robin");
                  algorithm_selection = -1;
                } 
              } else {
                log_debug("P2: CHWBL not configured, using round-robin fallback");
                algorithm_selection = -1;
              }
            }
            break;
          
          case PROXY_SEL_GPU_AWARE:
            if (prefix_hash != 0) {
              algorithm_selection = (int)(prefix_hash % (uint64_t)tepval->n_eps);
            } else if (conv_id && conv_id[0] != '\0') {
              uint64_t hash = XXH64(conv_id, strlen(conv_id), 0);
              algorithm_selection = (int)(hash % (uint64_t)tepval->n_eps);
            } else {
              algorithm_selection = -1;
            }
            break;
          
          case PROXY_SEL_WRR:  // P3: Weighted Round-Robin
            algorithm_selection = wrr_select_endpoint(tepval);
            if (algorithm_selection < 0) {
              log_error("P3: WRR selection failed, falling back to round-robin");
              algorithm_selection = -1;
            }
#ifdef HAVE_PROXY_EXTRA_DEBUG
            else {
              log_info("P3: WRR selected EP%d (weight=%d)",
                       algorithm_selection, tepval->eps[algorithm_selection].weight);
            }
#endif
            break;
          
          case PROXY_SEL_WRR_HASH:  // P3.5: Weighted Consistent Hash + Bounded Loads
            {
              uint64_t routing_hash = 0;
              
              // Determine routing hash from available sources (same priority as CHWBL)
              // PRIMARY: prefix_hash (model+prompt content) for KV cache locality
              if (prefix_hash != 0) {
                routing_hash = prefix_hash;
              } else if (conv_id && conv_id[0] != '\0') {
                // Fallback to conversation ID for session stickiness
                routing_hash = XXH64(conv_id, strlen(conv_id), 0);
              } else {
                // Last resort: round-robin
                routing_hash = XXH64(&tepval->ep_sel, sizeof(tepval->ep_sel), 0);
                tepval->ep_sel++;
              }
              
              int wrr_hash_ep = -1;
              if (wrr_hash_select_endpoint(tepval->hash_ring, tepval->chwbl_config,
                                           routing_hash, tepval, &wrr_hash_ep,
                                           (prefix_hash != 0) ? 1 : 0) == 0) {
                algorithm_selection = wrr_hash_ep;
#ifdef HAVE_PROXY_EXTRA_DEBUG
                log_info("P3.5: WRR_HASH selected EP%d (weight=%d, hash=0x%016lx)",
                         wrr_hash_ep, tepval->eps[wrr_hash_ep].weight, routing_hash);
#endif
              } else {
                log_error("P3.5: WRR_HASH selection failed, falling back to round-robin");
              }
            }
            break;
            
          default:
            // Will use round-robin below
            algorithm_selection = -1;
            break;
        }
#else
        // P3: WRR support (without HAVE_DP_GPU_ROUTING flag)
        if (tepval->select == PROXY_SEL_WRR) {
          algorithm_selection = wrr_select_endpoint(tepval);
          if (algorithm_selection < 0) {
            log_error("P3: WRR selection failed, falling back to round-robin");
            algorithm_selection = -1;
          }
#ifdef HAVE_PROXY_EXTRA_DEBUG
          else {
            log_info("P3: WRR selected EP%d (weight=%d)",
                     algorithm_selection, tepval->eps[algorithm_selection].weight);
          }
#endif
        }
#endif /* HAVE_DP_GPU_ROUTING */

        /* US-PD804: 3-tier P/D selection (replaces first-healthy stub) */
        if (tepval->pd_disagg_enabled && tepval->n_prefill_eps > 0 && tepval->n_decode_eps > 0) {
          int pd_prefill = -1, pd_decode = -1;

          /* KV-T15 / D-05.3: seed the exclusion mask with health/CB state so the
           * Tier-1.5 Go argmax (llb_ai_kv_best_worker) SKIPS down/CB-open EPs and
           * returns the genuine 2nd-best-overlap prefill — the FR-2 contract
           * ("excluded winner falls to 2nd-best PREFILL EP, not Tier-2 RR").
           * Previously first-attempt selection passed 0 and inv/CB were only
           * checked POST-argmax (GUARD_G -> miss -> Tier-2 RR), so a down winner
           * could never fall to the 2nd-best-overlap EP. The mask is also honored
           * by tiers 0/1/2 (session/trie/min-load), where skipping unhealthy EPs
           * is already the semantic. */
          uint32_t pd_excl = 0;
          for (int pe = 0; pe < tepval->n_eps && pe < 32; pe++) {
            if (tepval->eps[pe].inv ||
                tepval->circuit_breakers[pe].state == CB_STATE_OPEN) {
              pd_excl |= (1u << (unsigned)pe);
            }
          }

          /* Phase 93: capture the prefill rc so the in-flight-cap "no capacity"
           * verdict (PD_PREFILL_NO_CAPACITY) sheds a retriable 429 instead of
           * falling to any-healthy/normal mode (which would BYPASS the cap). This
           * shed happens BEFORE the active_conns increment below, so a shed never
           * perturbs the load counters. */
          int pf_rc = pd_select_prefill(tepval, pfe, &pd_prefill, pd_excl);
          /* Phase 93-04: bounded backpressured admission. PARKED means the request
           * was already ENQUEUED onto a per-EP FIFO inside pd_select_prefill (it
           * held + stamped park_start_ts there). Do NOT connect, do NOT 429, do NOT
           * active_conns++. Propagate PD_SETUP_PARKED so setup_proxy_path SUSPENDS
           * the client fd (EPOLLIN-pause) and holds it open; the caller keeps the fd.
           * Checked BEFORE the NO_CAPACITY 429 fork (NO_CAPACITY is now overflow-only). */
          if (pf_rc == PD_PREFILL_PARKED) {
            /* The enqueue + park_start_ts stamp already happened in the selector;
             * mark epv so a later teardown (93-05 max-park reap) can find the EP. */
            if (pfe && !pfe->epv) pfe->epv = tepval;
            return PD_SETUP_PARKED;
          }
          if (pf_rc == PD_PREFILL_NO_CAPACITY) {
            if (pfe) {
              const char *pd_429_resp =
                "HTTP/1.1 429 Too Many Requests\r\n"
                "Content-Type: application/json\r\n"
                "Retry-After: 1\r\n"
                "Connection: close\r\n"
                "\r\n"
                "{\"error\":\"pd_overloaded\","
                "\"detail\":\"all prefill endpoints at in-flight capacity\"}\r\n";
              send(pfe->fd, pd_429_resp, strlen(pd_429_resp),
                   MSG_DONTWAIT | MSG_NOSIGNAL);
            }
            return -1;
          }
          if (pf_rc != 0 ||
              pd_select_decode(tepval, pfe, &pd_decode) != 0) {
            /* RES-02: Fallback to any healthy EP in normal (non-P/D) mode */
            int fallback_ep = -1;
            if (pd_select_any_healthy(tepval, &fallback_ep) == 0) {
              if (pfe) pfe->pd_phase = PD_PHASE_NONE;
              atomic_fetch_add(&global_stats.pd_fallback_to_normal, 1);
              log_info("P/D fallback: all prefill/decode EPs unhealthy, using EP[%d] in normal mode",
                       fallback_ep);
              algorithm_selection = fallback_ep;
              goto pd_fallback_normal;
            }
            /* No healthy EPs at all — return 503 */
            log_error("US-PD804: P/D selection failed — no healthy prefill or decode");
            if (pfe) {
              const char *pd_503_resp =
                "HTTP/1.1 503 Service Unavailable\r\n"
                "Content-Type: application/json\r\n"
                "Connection: close\r\n"
                "\r\n"
                "{\"error\":\"pd_pool_unavailable\","
                "\"detail\":\"no healthy prefill or decode endpoint\"}\r\n";
              send(pfe->fd, pd_503_resp, strlen(pd_503_resp),
                   MSG_DONTWAIT | MSG_NOSIGNAL);
            }
            return -1;
          }

          /* INTG-06: Increment active_conns for selected EPs */
          atomic_fetch_add(&tepval->pd_ep_loads[pd_prefill].active_conns, 1);
          atomic_fetch_add(&tepval->pd_ep_loads[pd_decode].active_conns, 1);

          algorithm_selection = pd_prefill;
          if (pfe) {
            pfe->pd_prefill_ep_idx = pd_prefill;
            pfe->pd_decode_ep_idx = pd_decode;
            /* Bug1-fix: set epv now so pd_cleanup() can decrement active_conns
             * if the prefill TCP connect fails before epv is set at line ~9102 */
            if (!pfe->epv) pfe->epv = tepval;
          }

          /* INTG-04: Store session AFTER both EPs known.
           * Priority: user_id first, then client-provided conv_id (skip auto-generated). */
          if (pfe) {
            const char *session_key = NULL;
            if (pfe->has_user_id && pfe->user_id[0] != '\0')
              session_key = pfe->user_id;
            if (pfe->has_conv_id && pfe->conversation_id[0] != '\0' &&
                strncmp(pfe->conversation_id, "auto-", 5) != 0)
              session_key = pfe->conversation_id;
            if (session_key)
              pd_session_store(tepval, session_key, pd_prefill, pd_decode);
          }

          log_info("US-PD804: P/D EP selected — prefill=EP%d decode=EP%d", pd_prefill, pd_decode);
        } else if (tepval->kv_exact_mode == KV_EXACT_MODE_SINGLE_ROLE && pfe) {
          /* Phase 99 (D-09/D-10): single-role Tier-1.5 KV-exact selection — the
           * SIBLING of the P/D block above, structurally parallel and textually
           * independent (at kv_exact_mode == 1 this branch is provably never
           * entered; the P/D path stays byte-identical). A role-less service
           * reaches pd_kv_exact_select with the same health/CB exclusion mask
           * the P/D ladder builds; inside pd_kv_exact_select the candidate mask
           * admits ALL non-excluded EPs at this mode (ep_role[] is all-zero on
           * single-role services).
           *   HIT  -> route to the KV winner + hold one active_conns unit.
           *           Unified CHWBL hard-cap and adaptive ε/λ key on
           *           pd_ep_loads[].active_conns — without this accounting the
           *           blend runs blind (the 81-09 hot-spot, RESEARCH Pitfall 1).
           *   MISS -> algorithm_selection is left untouched, so the rule's own
           *           configured selector (CHWBL/adaptive/RR — already run in
           *           the select switch above) is the natural fallback ladder.
           *           No Tier-0/1/2 duplication, no 429/503/park (P/D-only). */
          uint32_t sr_excl = 0;
          for (int pe = 0; pe < tepval->n_eps && pe < 32; pe++) {
            if (tepval->eps[pe].inv ||
                tepval->circuit_breakers[pe].state == CB_STATE_OPEN) {
              sr_excl |= (1u << (unsigned)pe);
            }
          }
          int kv_sr_ep = -1;
          if (pd_kv_exact_select(tepval, pfe, &kv_sr_ep, sr_excl) == 0 &&
              kv_sr_ep >= 0 && kv_sr_ep < tepval->n_eps) {
            /* Load accounting on hit (Pitfall 1): increment now; the paired
             * decrement is claimed EXACTLY once via __atomic_exchange on
             * kv_sr_load_held (pd_free_claim single-owner shape) — either by
             * the backend connect-failure path below or by pd_cleanup() at
             * generic teardown (sockproxy_http.c). */
            /* Phase 99 load-signal fix (release-before-acquire): a REUSED
             * keep-alive connection can still hold the PRIOR request's
             * single-role unit here — that request's response has completed (the
             * client could not have sent THIS request otherwise). Release it
             * before acquiring this request's unit; without this the prior unit
             * would leak (and kv_sr_ep_idx would be overwritten) now that the
             * unit is preserved across the keep-alive request-forward boundary
             * (see the matching !kv_sr_load_held guard in sockproxy_http.c). The
             * two changes together make the unit span the backend generation, so
             * the adaptive/CHWBL selector once again sees real concurrency
             * instead of a near-zero load signal (the single-role sibling of the
             * 81-09 blind-blend hot-spot). __atomic_exchange keeps single-owner
             * discipline vs the connect-failure / teardown claimants. */
            if (__atomic_exchange_n(&pfe->kv_sr_load_held, 0, __ATOMIC_ACQ_REL)) {
              int prev_sr_ep = pfe->kv_sr_ep_idx;
              if (prev_sr_ep >= 0 && prev_sr_ep < tepval->n_eps) {
                uint32_t prev_cur =
                    atomic_load(&tepval->pd_ep_loads[prev_sr_ep].active_conns);
                if (prev_cur > 0)
                  atomic_fetch_sub(&tepval->pd_ep_loads[prev_sr_ep].active_conns, 1);
              }
            }
            atomic_fetch_add(&tepval->pd_ep_loads[kv_sr_ep].active_conns, 1);
            algorithm_selection = kv_sr_ep;
            pfe->kv_sr_load_held = 1;
            pfe->kv_sr_ep_idx = kv_sr_ep;
            /* Bug1-fix idiom (P/D block above): set epv now so pd_cleanup()
             * can decrement even if the backend TCP connect fails before epv
             * is normally set. */
            if (!pfe->epv) pfe->epv = tepval;
            log_info("[KV_SR] fd=%d single-role Tier-1.5 HIT -> EP%d",
                     pfe->fd, kv_sr_ep);
          }
        }

pd_fallback_normal:
        // If algorithm didn't select an endpoint, use round-robin
        if (algorithm_selection < 0) {
          int attempts = 0;
          int found_active = 0;
          sel = -1;
          
          for (attempts = 0; attempts < tepval->n_eps; attempts++) {
            int candidate = (tepval->ep_sel + attempts) % tepval->n_eps;
            if (candidate >= MAX_PROXY_EP) break;
            
            if (tepval->eps[candidate].inv == 0) {  // Check if active
              sel = candidate;
              found_active = 1;
              tepval->ep_sel = candidate + 1;  // Update for next round-robin
              break;
            }
          }
          
          if (!found_active) {
            log_error("proxy_find_ep: All endpoints inactive for service %s:%u",
                      inet_ntoa(*(struct in_addr *)(&xip)), ntohs(xport));
            return -1;  // No active endpoints available
          }
        } else {
          // Use algorithm-selected endpoint
          sel = algorithm_selection;
        }

        epip = tepval->eps[sel].xip;
        epport = tepval->eps[sel].xport;
        epprotocol = tepval->eps[sel].protocol;
        
        ep_sel->ep_cfds[0].ep_cfd = proxy_setup_ep_connect(epip, epport, (uint8_t)epprotocol,
                                                           ssl_ctx, ssl, pfe);
        if (ep_sel->ep_cfds[0].ep_cfd < 0) {
          // P2 Task 2.3: Record connection failure for circuit breaker
          circuit_breaker_record_failure(tepval, sel);
          
#ifdef HAVE_HTTP_TRACE
          // Store backend info for trace even when connection fails
          // This ensures REQ_END events include backend details for 502 errors
          if (pfe) {
            pfe->backend_ip = epip;
            pfe->backend_port = ntohs(epport);  // Convert to host byte order
            pfe->ep_num = sel;
          }
#endif
          
#ifdef HAVE_DP_GPU_ROUTING
          // CRITICAL FIX: Decrement CHWBL/WRR_HASH load counter on connection failure
          // Without this, failed connections leak load forever!
          if ((tepval->select == PROXY_SEL_CHWBL || tepval->select == PROXY_SEL_WRR_HASH) && tepval->chwbl_config) {
            chwbl_dec_load(tepval->chwbl_config, sel);
            log_debug("CHWBL/WRR_HASH: Decremented load for EP%d after connection failure", sel);
          }
#endif /* HAVE_DP_GPU_ROUTING */

          /* Phase 99 (D-09/D-10): single-role KV load — release the held
           * active_conns unit immediately on backend connect failure (failed
           * connections must not leak load forever — the chwbl_dec_load idiom
           * above). __atomic_exchange claims kv_sr_load_held so pd_cleanup()
           * at the later teardown can never double-decrement (single-owner). */
          if (pfe &&
              __atomic_exchange_n(&pfe->kv_sr_load_held, 0, __ATOMIC_ACQ_REL)) {
            int sr_fail_ep = pfe->kv_sr_ep_idx;
            if (sr_fail_ep >= 0 && sr_fail_ep < tepval->n_eps) {
              /* Bug3-fix shape: guard against uint32_t underflow */
              uint32_t cur_sr =
                  atomic_load(&tepval->pd_ep_loads[sr_fail_ep].active_conns);
              if (cur_sr > 0)
                atomic_fetch_sub(&tepval->pd_ep_loads[sr_fail_ep].active_conns, 1);
              log_debug("[KV_SR] fd=%d released load for EP%d after connection failure",
                        pfe->fd, sr_fail_ep);
            }
            pfe->kv_sr_ep_idx = -1;
          }

          /* US-PD804 Option-B: P/D mid-cycle failover.
           * The health-check cycle runs every 60 s, so when a prefill EP is
           * stopped (e.g. docker stop) its inv flag is not set yet.  Rather
           * than returning an error immediately, try every remaining healthy
           * prefill EP while recording TCP failures in the circuit breaker.
           * A 503 is sent only when all prefill EPs are exhausted. */
          if (tepval->pd_disagg_enabled && pfe) {
            /* Undo active_conns for the original failed EP pair so the
             * counters remain consistent regardless of retry outcome. */
            int fc_orig_decode = pfe->pd_decode_ep_idx;
            {
              uint32_t cur_sel = atomic_load(&tepval->pd_ep_loads[sel].active_conns);
              if (cur_sel > 0)
                atomic_fetch_sub(&tepval->pd_ep_loads[sel].active_conns, 1);
            }
            if (fc_orig_decode >= 0 && fc_orig_decode < MAX_PROXY_EP) {
              uint32_t cur_odc = atomic_load(&tepval->pd_ep_loads[fc_orig_decode].active_conns);
              if (cur_odc > 0)
                atomic_fetch_sub(&tepval->pd_ep_loads[fc_orig_decode].active_conns, 1);
            }

            uint32_t pd_excluded = 1u << (unsigned)sel;  /* exclude original EP */

            for (int pd_retry = 0; pd_retry < tepval->n_prefill_eps; pd_retry++) {
              int fc_prefill = -1, fc_decode = -1;
              /* Reset decode hint so pd_select_prefill/pd_select_decode pick
               * a fresh pair unconstrained by the now-evicted session. */
              pfe->pd_decode_ep_idx = -1;
              if (pd_select_prefill(tepval, pfe, &fc_prefill, pd_excluded) != 0)
                break;  /* no more healthy prefill candidates */
              if (pd_select_decode(tepval, pfe, &fc_decode) != 0)
                break;  /* no decode EP available */

              atomic_fetch_add(&tepval->pd_ep_loads[fc_prefill].active_conns, 1);
              atomic_fetch_add(&tepval->pd_ep_loads[fc_decode].active_conns, 1);

              int fc_fd = proxy_setup_ep_connect(
                  tepval->eps[fc_prefill].xip,
                  tepval->eps[fc_prefill].xport,
                  tepval->eps[fc_prefill].protocol,
                  ssl_ctx, ssl, pfe);
              if (fc_fd >= 0) {
                /* Retry succeeded — update tracking state */
                pfe->pd_prefill_ep_idx = fc_prefill;
                pfe->pd_decode_ep_idx  = fc_decode;
                /* Re-pin session to healthy EP pair */
                { const char *sk = NULL;
                  if (pfe->has_user_id && pfe->user_id[0] != '\0') sk = pfe->user_id;
                  if (pfe->has_conv_id && pfe->conversation_id[0] != '\0' &&
                      strncmp(pfe->conversation_id, "auto-", 5) != 0) sk = pfe->conversation_id;
                  if (sk) pd_session_store(tepval, sk, fc_prefill, fc_decode); }
                ep_sel->ep_cfds[0].ep_cfd = fc_fd;
                sel = fc_prefill;
                log_info("US-PD804: P/D mid-cycle failover → prefill=EP%d decode=EP%d (attempt %d)",
                         fc_prefill, fc_decode, pd_retry + 1);
                goto pd_failover_ok;
              }
              /* This candidate also unreachable — clean up and try next */
              {
                uint32_t cur_fcp = atomic_load(&tepval->pd_ep_loads[fc_prefill].active_conns);
                if (cur_fcp > 0)
                  atomic_fetch_sub(&tepval->pd_ep_loads[fc_prefill].active_conns, 1);
              }
              {
                uint32_t cur_fcd = atomic_load(&tepval->pd_ep_loads[fc_decode].active_conns);
                if (cur_fcd > 0)
                  atomic_fetch_sub(&tepval->pd_ep_loads[fc_decode].active_conns, 1);
              }
              circuit_breaker_record_failure(tepval, fc_prefill);
              pd_excluded |= 1u << (unsigned)fc_prefill;
            }

            /* All prefill EPs exhausted — respond with 503 */
            log_error("US-PD804: P/D mid-cycle failover exhausted all prefill EPs — 503");
            { const char *pd_503 =
                "HTTP/1.1 503 Service Unavailable\r\n"
                "Content-Type: application/json\r\n"
                "Connection: close\r\n"
                "\r\n"
                "{\"error\":\"pd_pool_unavailable\","
                "\"detail\":\"all prefill endpoints unreachable\"}\r\n";
              send(pfe->fd, pd_503, strlen(pd_503), MSG_DONTWAIT | MSG_NOSIGNAL); }
            /* Clear EP indices so pd_cleanup() skips double-decrement */
            pfe->pd_prefill_ep_idx = -1;
            pfe->pd_decode_ep_idx  = -1;
          }

          return -1;
        }

pd_failover_ok: /* mid-cycle failover succeeded; sel == winning prefill EP */
        // P2 Task 2.3: Record connection success for circuit breaker
        circuit_breaker_record_success(tepval, sel);

        *seltype = 0;
        *rid = tepval->_id;
        *epv = tepval;
        ep_sel->ep_cfds[0].ep_num = sel;
        ep_sel->n_eps = 1;

#ifdef HAVE_HTTP_TRACE
        // CRITICAL FIX: Set catalog_id in PROXY_MODE_DFL path
        // Previously only set in PROXY_MODE_ALL path, causing catalog_id=0 for DFL mode
        if (pfe && found_ent && found_ent->catalog_id > 0) {
          pfe->catalog_id = found_ent->catalog_id;
#ifdef HAVE_PROXY_EXTRA_DEBUG
          log_debug("[CATALOG_ASSIGNED_DFL] Set pfe->catalog_id=%d from proxy entry (PROXY_MODE_DFL path)",
                    pfe->catalog_id);
#endif
        }
#ifdef HAVE_PROXY_EXTRA_DEBUG
        else {
          log_debug("[CATALOG_SKIP_DFL] Not setting catalog_id: pfe=%p found_ent=%p catalog_id=%d",
                    pfe, found_ent, found_ent ? found_ent->catalog_id : 0);
        }
#endif
#endif

        return 0;
      } else if (node->val.proxy_mode == PROXY_MODE_ALL) {
        int ep = 0;
        tepval = node->val.ephash;
        if (tepval == NULL) break;

        /* Do not support for this mode */
        assert(ssl_ctx == NULL);

        // Session stickiness with custom header support
        // PROXY_SEL_STICKY: IP-based fallback for first request (backward compatible)
        // PROXY_SEL_RR: Round-robin fallback for first request (better load balancing)
        // FR-10 (Phase 76): also enter when an L7 HTTP_COOKIE route is active, so
        // the stateless cookie read-back pin runs regardless of the base select
        // mode; on a cookie miss the existing RR/IP fallback below selects the
        // backend (the cookie pin is purely additive — D-03 miss->rehash).
        if (tepval->select == PROXY_SEL_STICKY ||
            (tepval->select == PROXY_SEL_RR && tepval->session_header_enabled) ||
            (node->has_l7_policy && pfe && l7_cookie_persist_active(pfe, node))) {
          char session_key[256];  // Increased size for long header values
          int selected_ep = -1;
          int using_learned_session = 0;
          int cookie_pinned = 0;   // FR-10: 1 if a valid LB cookie pinned selected_ep

          /* FR-10 (Phase 76, D-02/D-03/D-05): STATELESS HTTP_COOKIE read-back pin.
           * When the matched L7 route enables cookie_persist and the request
           * carries a valid LB cookie, re-derive + constant-time-match the token
           * against the LIVE member set and PIN selected_ep to that member — the
           * existing connect loop below honours selected_ep. On a forged/stale
           * token (or no cookie) l7_cookie_node_match returns L7_COOKIE_MISS and
           * we fall through to the normal hash/RR selection (D-03: NEVER an
           * arbitrary backend). Nothing is read from / written to proxy_fd_ent
           * state (D-02) — the cookie value IS the binding, so this works
           * identically on an HA peer that never saw the original request. */
          if (node->has_l7_policy && pfe &&
              l7_cookie_persist_active(pfe, node)) {
            char presented[LB_COOKIE_TOKEN_MAX];
            if (l7_cookie_read_presented(pfe, presented, sizeof(presented)) == 0) {
              int cep = l7_cookie_node_match(node, tepval, presented);
              if (cep != L7_COOKIE_MISS && cep >= 0 && cep < tepval->n_eps &&
                  tepval->eps[cep].inv == 0 && is_endpoint_healthy(tepval, cep)) {
                selected_ep = cep;
                cookie_pinned = 1;
                log_info("[COOKIE_PIN] valid LB cookie -> ep[%d] (PROXY_AFFINITY_COOKIE)",
                         cep);
              } else {
                log_info("[COOKIE_MISS] no live-member match for presented cookie -> rehash");
              }
            }
          }

          // PRIORITY 0: Check if we have a learned session binding (highest priority)
          if (tepval->session_header_enabled && 
              custom_session_header && 
              custom_session_header[0] != '\0') {
            
            // Build conversation ID to lookup
            // CRITICAL FIX: Validate combined length to prevent truncation
            size_t total_len = strlen("custom__") + strlen(tepval->session_header_name) + 
                               strlen(custom_session_header) + 1;
            if (total_len >= MAX_CONV_ID_LEN) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
              log_warn("[CONV_OVERFLOW] Session header too long (%zu bytes), truncating to %d",
                       total_len, MAX_CONV_ID_LEN);
#endif
            }
            snprintf(session_key, sizeof(session_key), "custom_%s_%s", 
                     tepval->session_header_name,
                     custom_session_header);
            
            // Try to lookup learned session binding
            if (lookup_conversation_endpoint(node, session_key, &selected_ep) == 0) {
              // CRITICAL FIX: Validate learned endpoint before using
              if (selected_ep >= 0 && selected_ep < tepval->n_eps) {
                // Check if endpoint is still active/healthy
                if (tepval->eps[selected_ep].inv == 0 && 
                    is_endpoint_healthy(tepval, selected_ep)) {
                  // Valid and healthy - use learned binding
                  using_learned_session = 1;
                  /* Record normal-mode session hit metric (mirrors P/D Tier-0 hit) */
                  if (pfe) {
                    const char *sh_model = "";
                    if (pfe->x_model_header[0] != '\0') sh_model = pfe->x_model_header;
                    else if (pfe->prefix_key.model[0] != '\0') sh_model = pfe->prefix_key.model;
                    llb_ai_normal_session_hit((char *)sh_model);
                  }
                  log_info("[NS_STICKY_HIT] key='%s' → ep[%d] (session binding used, metric recorded)",
                           session_key, selected_ep);
                } else {
                  // CRITICAL FIX: Endpoint failed/inactive - DELETE stale mapping to force re-learning
                  // This prevents repeatedly trying failed endpoints and allows learning new healthy endpoint
                  log_warn("[NS_STICKY_STALE] key='%s' → ep[%d] inv=%d unhealthy; deleting stale mapping",
                           session_key, selected_ep, tepval->eps[selected_ep].inv);
                  pthread_rwlock_wrlock(&node->val.conv_lock);
                  conversation_mapping_t *stale_mapping = NULL;
                  HASH_FIND_STR(node->val.conv_map, session_key, stale_mapping);
                  /* Phase 70 — capture state under wrlock for emit-after-unlock. */
                  int      emit_stale_present = 0;
                  uint64_t emit_stale_created_ts = 0;
                  int      emit_stale_ep_idx = -1;
                  if (stale_mapping) {
                    emit_stale_present = 1;
                    emit_stale_created_ts = stale_mapping->created_ts;
                    emit_stale_ep_idx = stale_mapping->ep_idx;
                    HASH_DEL(node->val.conv_map, stale_mapping);
                    free(stale_mapping);
                  }
                  pthread_rwlock_unlock(&node->val.conv_lock);
                  /* Phase 70 EMIT SITE #3 (sockproxy_ep.c) [PHASE_70_EMIT_EP_003] — stale-mapping DELETE.
                   * Emit-after-unlock: conv_lock released by the line above. */
                  if (emit_stale_present) {
                    proxy_sync_event_t _ev70;
                    if (conv_build_sync_event(&_ev70, node, SYNC_CONV_DELETE, session_key,
                                              emit_stale_ep_idx, emit_stale_created_ts,
                                              (uint64_t)time(NULL), 0))
                      llb_sockproxy_emit_sync_event(&_ev70);
                  }
                  // Fall through to normal selection and re-learning
                }
              } else {
                // CRITICAL FIX: Out of bounds - DELETE invalid mapping
                pthread_rwlock_wrlock(&node->val.conv_lock);
                conversation_mapping_t *invalid_mapping = NULL;
                HASH_FIND_STR(node->val.conv_map, session_key, invalid_mapping);
                /* Phase 70 — capture state under wrlock for emit-after-unlock. */
                int      emit_inv_present = 0;
                uint64_t emit_inv_created_ts = 0;
                int      emit_inv_ep_idx = -1;
                if (invalid_mapping) {
                  emit_inv_present = 1;
                  emit_inv_created_ts = invalid_mapping->created_ts;
                  emit_inv_ep_idx = invalid_mapping->ep_idx;
                  HASH_DEL(node->val.conv_map, invalid_mapping);
                  free(invalid_mapping);
                  log_error("[CONV_DELETE_INVALID] Deleted invalid mapping '%s' → ep[%d] (out of bounds, n_eps=%d)",
                            session_key, selected_ep, tepval->n_eps);
                }
                pthread_rwlock_unlock(&node->val.conv_lock);
                /* Phase 70 EMIT SITE #4 (sockproxy_ep.c) [PHASE_70_EMIT_EP_004] — invalid-mapping DELETE. */
                if (emit_inv_present) {
                  proxy_sync_event_t _ev70;
                  if (conv_build_sync_event(&_ev70, node, SYNC_CONV_DELETE, session_key,
                                            emit_inv_ep_idx, emit_inv_created_ts,
                                            (uint64_t)time(NULL), 0))
                    llb_sockproxy_emit_sync_event(&_ev70);
                }
              }
            } else {
              log_info("[NS_STICKY_MISS] key='%s' not found in conv_map (Turn 1 or mapping expired)",
                       session_key);
            }
          }
          
          // PRIORITY 1: If no learned session, try hash-based custom header stickiness
          // FR-10: a valid LB cookie pin (cookie_pinned) takes precedence over the
          // hash/RR fallbacks — selected_ep is already set to the pinned member.
          if (!cookie_pinned && !using_learned_session &&
              tepval->session_header_enabled &&
              custom_session_header &&
              custom_session_header[0] != '\0') {
            
            // Use custom header value for session key
            snprintf(session_key, sizeof(session_key), "custom_%s_%s", 
                     tepval->session_header_name,  // Include header name for uniqueness
                     custom_session_header);
            
            uint32_t hash = session_key_hash(session_key);
            selected_ep = hash % tepval->n_eps;
            
#ifdef HAVE_PROXY_EXTRA_DEBUG
            log_info("[STICKY_CUSTOM] Header '%s'='%s' → hash=%u → endpoint[%d]",
                     tepval->session_header_name, custom_session_header, 
                     hash, selected_ep);
#endif
          }
          // PRIORITY 2: Fallback strategy depends on selection mode
          else if (!cookie_pinned && !using_learned_session) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
            log_info("[FALLBACK] No custom header, tepval->select=%d (RR=%d, STICKY=%d)",
                     tepval->select, PROXY_SEL_RR, PROXY_SEL_STICKY);
#endif
            if (tepval->select == PROXY_SEL_RR) {
              // Round-robin for new sessions (better load balancing with session learning)
              selected_ep = tepval->ep_sel;
              tepval->ep_sel = (tepval->ep_sel + 1) % tepval->n_eps;
              
              snprintf(session_key, sizeof(session_key), "new_session_rr");
              
#ifdef HAVE_PROXY_EXTRA_DEBUG
              log_info("[RR_NEW] New session without header → round-robin endpoint[%d]",
                       selected_ep);
#endif
            } else {
              // PROXY_SEL_STICKY: IP-based for backward compatibility
              snprintf(session_key, sizeof(session_key), "ip_%s", 
                       inet_ntoa(*(struct in_addr *)(&client_ip)));
              
              uint32_t hash = session_key_hash(session_key);
              selected_ep = hash % tepval->n_eps;
              
#ifdef HAVE_PROXY_EXTRA_DEBUG
              log_info("[STICKY_IP] Client IP '%s' → hash=%u → endpoint[%d]",
                       inet_ntoa(*(struct in_addr *)(&client_ip)), 
                       hash, selected_ep);
#endif
            }
          }
          
          // P2 Health: Find active endpoint starting from hashed position and retry on connect failure
          int attempts = 0;
          int found_active = 0;
          (void)found_active;  // May be used in future health check logic
          int connect_success = 0;
          
          for (attempts = 0; attempts < tepval->n_eps; attempts++) {
            int candidate = (selected_ep + attempts) % tepval->n_eps;
            
            // Skip inactive endpoints (health check marked them down)
            if (tepval->eps[candidate].inv != 0) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
              log_debug("[STICKY_RETRY] Skipping inactive endpoint[%d]", candidate);
#endif
              continue;
            }
            
            // Try to connect to this endpoint
            epip = tepval->eps[candidate].xip;
            epport = tepval->eps[candidate].xport;
            epprotocol = tepval->eps[candidate].protocol;
            
#ifdef HAVE_PROXY_EXTRA_DEBUG
            log_info("[STICKY_TRY] Attempting endpoint[%d]: %s:%u (session_key='%s', attempt=%d/%d)",
                     candidate, 
                     inet_ntoa(*(struct in_addr *)(&epip)), 
                     ntohs(epport),
                     session_key,
                     attempts + 1,
                     tepval->n_eps);
#endif
            
            ep_sel->ep_cfds[0].ep_cfd = proxy_setup_ep_connect(epip, epport, (uint8_t)epprotocol, 
                                                               NULL, NULL, pfe);
            
            if (ep_sel->ep_cfds[0].ep_cfd > 0) {
              // Connection successful!
              selected_ep = candidate;
              found_active = 1;
              connect_success = 1;
              
#ifdef HAVE_PROXY_EXTRA_DEBUG
              log_info("[STICKY_SUCCESS] Connected to endpoint[%d]: %s:%u",
                       selected_ep, 
                       inet_ntoa(*(struct in_addr *)(&epip)), 
                       ntohs(epport));
#endif
              
              // P2 Task 2.3: Record connection success
              circuit_breaker_record_success(tepval, selected_ep);
              break;
            } else {
              // Connection failed - try next endpoint
              log_warn("[STICKY_FAIL] Connection failed to endpoint[%d] %s:%u, trying next...",
                       candidate,
                       inet_ntoa(*(struct in_addr *)(&epip)), 
                       ntohs(epport));
              
              // P2 Task 2.3: Record connection failure
              circuit_breaker_record_failure(tepval, candidate);
              
#ifdef HAVE_HTTP_TRACE
              // Store last attempted backend for tracing (will be used if all attempts fail)
              if (pfe) {
                pfe->backend_ip = epip;
                pfe->backend_port = ntohs(epport);  // Convert to host byte order
                pfe->ep_num = candidate;
              }
#endif
            }
          }
          
          if (!connect_success) {
            log_error("[STICKY] All endpoints failed for session (tried %d endpoints)", attempts);
            if (pfe) {
              const char *err_503 =
                  "HTTP/1.1 503 Service Unavailable\r\n"
                  "Content-Type: application/json\r\n"
                  "Connection: close\r\n"
                  "\r\n"
                  "{\"error\":\"service_unavailable\","
                  "\"detail\":\"all backend endpoints unreachable\"}\r\n";
              send(pfe->fd, err_503, strlen(err_503), MSG_DONTWAIT | MSG_NOSIGNAL);
            }
            return -1;
          }
          
          // Setup successful connection
          ep_sel->ep_cfds[0].ep_num = selected_ep;
          sel = 1;

          // AI GW immediate session binding: store custom_session_header → ep NOW.
          // Normal (non-P/D) mode: vLLM backends do NOT return session IDs in their
          // responses, so the normal "learn from backend response" path never fires.
          // By storing here (on request, after a successful TCP connect) we guarantee
          // that Turn 2 of the same conversation hits PRIORITY 0 (learned binding)
          // instead of falling back to PRIORITY 1 (hash re-computation).
          if (tepval->session_header_enabled && !using_learned_session &&
              custom_session_header && custom_session_header[0] != '\0') {
            char imm_key[256];
            snprintf(imm_key, sizeof(imm_key), "custom_%s_%s",
                     tepval->session_header_name, custom_session_header);
            if (store_conversation_endpoint(node, imm_key, selected_ep) == 0) {
              log_info("[NS_STICKY_STORE] stored '%s' → ep[%d]", imm_key, selected_ep);
            } else {
              log_warn("[NS_STICKY_STORE] FAILED to store '%s' → ep[%d] (calloc/lock failed?)", imm_key, selected_ep);
            }
          }

          // Session Learning: Store parameters in ep_sel to pass back to caller
          // Caller will mark CLIENT connection, which will be copied to BACKEND connection
          // CRITICAL FIX: Enable re-learning when previous learned endpoint failed (using_learned_session=0)
          // This allows sessions to be re-bound to healthy endpoints after failures
          // Conditions: (1) session_header_enabled, (2) not using valid learned session
          if (tepval->session_header_enabled && !using_learned_session) {
            // Store flag in ep_sel - caller will check this and set up learning
            ep_sel->ep_cfds[0].needs_learning = 1;
            strncpy(ep_sel->session_header_name, tepval->session_header_name, 
                    sizeof(ep_sel->session_header_name) - 1);
            ep_sel->session_header_name[sizeof(ep_sel->session_header_name) - 1] = '\0';
#ifdef HAVE_PROXY_EXTRA_DEBUG
            log_debug("[SESSION_LEARN_PENDING] Backend will learn '%s' → ep[%d] (relearn=%s)",
                      tepval->session_header_name, selected_ep,
                      custom_session_header ? "yes" : "no");
#endif
          }
        } else {
          // Original logic - connect to all ACTIVE endpoints (skip inactive)
          for (ep = 0; ep < tepval->n_eps; ep++) {
            // P2 Health: Skip inactive endpoints
            if (tepval->eps[ep].inv != 0) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
              log_debug("proxy_find_ep: Skipping inactive endpoint[%d] %s:%u",
                        ep, inet_ntoa(*(struct in_addr *)(&tepval->eps[ep].xip)), 
                        ntohs(tepval->eps[ep].xport));
#endif
              continue;
            }
            
            epip = tepval->eps[ep].xip;
            epport = tepval->eps[ep].xport;
            epprotocol = tepval->eps[ep].protocol;
            ep_sel->ep_cfds[sel].ep_cfd = proxy_setup_ep_connect(epip, epport, (uint8_t)epprotocol, 
                                                                 NULL, NULL, pfe);
            if (ep_sel->ep_cfds[sel].ep_cfd > 0) {
              ep_sel->ep_cfds[sel].ep_num = sel;
              sel++;
            } else {
#ifdef HAVE_HTTP_TRACE
              // Store last attempted backend for tracing
              if (pfe) {
                pfe->backend_ip = epip;
                pfe->backend_port = ntohs(epport);  // Convert to host byte order
                pfe->ep_num = ep;
              }
#endif
            }
          }
        }

        *rid = tepval->_id;
        *epv = tepval;
#ifdef HAVE_HTTP_TRACE
#ifdef HAVE_PROXY_EXTRA_DEBUG

#endif
#endif
        if (!sel && pfe) {
          const char *err_503 =
              "HTTP/1.1 503 Service Unavailable\r\n"
              "Content-Type: application/json\r\n"
              "Connection: close\r\n"
              "\r\n"
              "{\"error\":\"service_unavailable\","
              "\"detail\":\"all backend endpoints unreachable\"}\r\n";
          send(pfe->fd, err_503, strlen(err_503), MSG_DONTWAIT | MSG_NOSIGNAL);
        }
        if (sel) {
          ep_sel->n_eps = sel;
          *seltype = tepval->select;
          
#ifdef HAVE_HTTP_TRACE
#ifdef HAVE_PROXY_EXTRA_DEBUG
          log_debug("[CATALOG_CHECK] Before catalog assignment: sel=%d pfe=%p found_ent=%p", 
                    sel, pfe, found_ent);
          if (found_ent) {
            log_debug("[CATALOG_CHECK] found_ent->catalog_id=%d xip=%08x xport=%04x", 
                      found_ent->catalog_id, found_ent->key.xip, found_ent->key.xport);
          }
#endif
          // Load catalog_id from proxy_map_ent (simple, no eBPF complexity)
          if (pfe && found_ent) {
            pfe->catalog_id = found_ent->catalog_id;
#ifdef HAVE_PROXY_EXTRA_DEBUG
            log_debug("[CATALOG] pfe->catalog_id SET to %d for service %08x:%04x", 
                      pfe->catalog_id, xip, xport);
#endif
          } else {
#ifdef HAVE_PROXY_EXTRA_DEBUG
            log_debug("[CATALOG_WARNING] NOT setting catalog_id: pfe=%p found_ent=%p", pfe, found_ent);
#endif
          }
#endif
          
          return 0;
        }
#ifdef HAVE_HTTP_TRACE
#ifdef HAVE_PROXY_EXTRA_DEBUG

#endif
#endif
        return -1;
      }
    }
    node = node->next;
  }

#ifdef HAVE_HTTP_TRACE
#ifdef HAVE_PROXY_EXTRA_DEBUG
  log_debug("[CATALOG_NOMATCH] No matching proxy entry found (xip=%08x xport=%04x)", xip, xport);
#endif
#endif
  return -1;
}

/* proxy_sock_init moved to sockproxy_conn.c (Phase 3) */

/* proxy_drain_checker_thread moved to sockproxy_health.c (Phase 2) */

// Conversation mapping cleanup thread - removes stale/expired mappings
void *
proxy_conversation_cleanup_thread(void *arg)
{
  time_t now;
  uint32_t total_removed;
  
  while (proxy_struct->run) {
    // Cleanup every CONVERSATION_CLEANUP_INTERVAL seconds
    sleep(CONVERSATION_CLEANUP_INTERVAL);
    
    now = time(NULL);
    total_removed = 0;
    
    /* Phase 70.1 — CR-04 / D-04 two-pass gather-then-evict for P/D-enabled
     * ephash entries. Closes the recursive-rwlock UB documented in
     * .planning/phases/70-sockproxy-ha-sync/70-REVIEW.md (CR-04).
     *
     * Lock hierarchy: sockproxy_internal.h:89-100 declares Pri-1 (proxy_struct->lock)
     * is the lowest-priority lock that any thread may hold. pd_session_evict()
     * internally re-acquires Pri-1 (rdlock) via pd_session_resolve_service_key().
     * POSIX rwlock recursion is undefined behaviour — so we MUST release
     * PROXY_LOCK() before calling pd_session_evict().
     *
     * Safety of victim pointer stability across PROXY_UNLOCK() is the
     * load-bearing property — RESEARCH Pitfall 8 / Assumption A2. All HASH_DEL
     * of node->val.ephash must be performed under PROXY_LOCK() so that the
     * cleanup thread is the only writer between gather and the post-unlock
     * evict loop. Audit grep:
     *   grep -n "HASH_DEL.*ephash\|free.*proxy_epval_t" loxilb-ebpf/common/sockproxy*.c
     * The result must show every site is reached only under PROXY_LOCK() by
     * its caller (today: proxy_delete_entry() in sockproxy_conn.c). When you
     * add a new ephash mutator, you MUST verify this invariant — otherwise
     * the two-pass refactor below is UAF-vulnerable. */
    #define PROXY_PD_EVICT_GATHER_N 64
    proxy_epval_t *victims_stack[PROXY_PD_EVICT_GATHER_N];
    proxy_epval_t **victims = victims_stack;
    size_t n_v = 0, cap_v = PROXY_PD_EVICT_GATHER_N;

    PROXY_LOCK();

    proxy_map_ent_t *node = proxy_struct->head;
    while (node) {
      uint32_t node_removed = 0;

      /* conv_map two-pass block — scoped so its local `victims[]` struct
       * array does NOT shadow the outer P/D gather `victims` pointer below
       * (Pri-3 sibling pattern, predates D-04). */
      {
        conversation_mapping_t *mapping, *tmp;
        /* Phase 70 — Landmine L-6 batch list for emit-after-unlock. Bounded
         * to 256 victims per pass; further evictions land in the next 30s tick. */
        #define CONV_CLEANUP_EMIT_BATCH 256
        struct {
          char     conv_id[MAX_CONV_ID_LEN];
          int      ep_idx;
          uint64_t created_ts;
        } victims[CONV_CLEANUP_EMIT_BATCH];
        uint32_t n_victims = 0;

        pthread_rwlock_wrlock(&node->val.conv_lock);

        HASH_ITER(hh, node->val.conv_map, mapping, tmp) {
          // Remove mappings that haven't been accessed within TTL
          if (now - mapping->last_access_ts > CONVERSATION_MAPPING_TTL) {
            /* Phase 70 — capture victim for emit-after-unlock. */
            if (n_victims < CONV_CLEANUP_EMIT_BATCH) {
              strncpy(victims[n_victims].conv_id, mapping->conv_id, MAX_CONV_ID_LEN - 1);
              victims[n_victims].conv_id[MAX_CONV_ID_LEN - 1] = '\0';
              victims[n_victims].ep_idx = mapping->ep_idx;
              victims[n_victims].created_ts = mapping->created_ts;
              n_victims++;
            }
            HASH_DEL(node->val.conv_map, mapping);
#ifdef HAVE_PROXY_EXTRA_DEBUG
            log_debug("[CONV_EXPIRE] Removed stale mapping '%s' → ep[%d] (last_access=%ld seconds ago, requests=%u)",
                      mapping->conv_id, mapping->ep_idx,
                      now - mapping->last_access_ts, mapping->request_count);
#endif
            free(mapping);
            node_removed++;

            // METRICS: Track conversation TTL expirations (TIER 3, Metric #13)
            atomic_fetch_add(&global_stats.conversation_ttl_expirations, 1);
          }
        }

        pthread_rwlock_unlock(&node->val.conv_lock);
        total_removed += node_removed;

        /* Phase 70 EMIT SITE #5 (sockproxy_ep.c) [PHASE_70_EMIT_EP_005] — cleanup-thread bulk DELETE.
         * Emit-after-unlock: conv_lock released above. Landmine L-6 compliant. */
        for (uint32_t i = 0; i < n_victims; i++) {
          proxy_sync_event_t _ev70;
          if (conv_build_sync_event(&_ev70, node, SYNC_CONV_DELETE, victims[i].conv_id,
                                    victims[i].ep_idx, victims[i].created_ts,
                                    (uint64_t)now, 0))
            llb_sockproxy_emit_sync_event(&_ev70);
        }
        #undef CONV_CLEANUP_EMIT_BATCH
      }

      /* P/D Session stickiness: GATHER P/D-enabled tepvals here (under
       * PROXY_LOCK Pri-1 wrlock). pd_session_evict() is called AFTER the
       * PROXY_UNLOCK() below to avoid recursive Pri-1 rdlock via
       * pd_session_resolve_service_key. See block-header comment for the
       * full lock-hierarchy rationale (CR-04 / D-04). */
      {
        proxy_epval_t *tepval, *tv_tmp;
        HASH_ITER(hh, node->val.ephash, tepval, tv_tmp) {
          if (tepval->pd_disagg_enabled) {
            if (n_v == cap_v) {
              cap_v *= 2;
              if (victims == victims_stack) {
                proxy_epval_t **heap = malloc(cap_v * sizeof *heap);
                if (!heap) {
                  /* Allocation failure: skip this tepval; the next 30s tick
                   * will retry. Do NOT abort the cleanup pass — best-effort
                   * eviction is preferable to dropping the whole tick. */
                  log_warn("[CONV_CLEANUP] gather array malloc failed at n_v=%zu cap_v=%zu — skipping spill",
                           n_v, cap_v);
                  cap_v = n_v;  /* stop trying to spill this tick */
                  goto skip_pd_gather;
                }
                memcpy(heap, victims_stack, n_v * sizeof *heap);
                victims = heap;
              } else {
                proxy_epval_t **heap = realloc(victims, cap_v * sizeof *heap);
                if (!heap) {
                  log_warn("[CONV_CLEANUP] gather array realloc failed at n_v=%zu cap_v=%zu — skipping spill",
                           n_v, cap_v);
                  cap_v = n_v;
                  goto skip_pd_gather;
                }
                victims = heap;
              }
            }
            victims[n_v++] = tepval;
          }
          skip_pd_gather:
          /* Phase 8: trie LRU eviction safety net. STAYS inline under PROXY_LOCK
           * — pd_trie_lock (Pri-5) does NOT recurse into proxy_struct->lock,
           * so the Pri-1 → Pri-5 hierarchy is preserved (RESEARCH Pitfall 11). */
          if (tepval->pd_trie) {
            pthread_rwlock_wrlock(&tepval->pd_trie_lock);
            pd_trie_evict_lru(tepval->pd_trie, 8192);
            pthread_rwlock_unlock(&tepval->pd_trie_lock);
          }
        }
      }

      node = node->next;
    }

    PROXY_UNLOCK();

    /* Pri-1 fully released — pd_session_evict() can safely re-acquire Pri-1
     * rdlock via pd_session_resolve_service_key(). Pri-1 alone is never a
     * hierarchy violation per sockproxy_internal.h:89-100. The gathered
     * tepval pointers remain stable because all ephash mutators take
     * PROXY_LOCK() (RESEARCH Assumption A2 / Pitfall 8). */
    for (size_t i = 0; i < n_v; i++) {
      pd_session_evict(victims[i]);
    }
    if (victims != victims_stack) free(victims);
    #undef PROXY_PD_EVICT_GATHER_N

    if (total_removed > 0) {
      log_info("[CONV_CLEANUP] Removed %u expired conversation mappings (TTL=%d seconds)",
               total_removed, CONVERSATION_MAPPING_TTL);
    }
  }
  
  return NULL;
}

void *
proxy_run(void *arg)
{
  // Start notification system for socket events (this blocks)
  notify_start(proxy_struct->ns);
  return NULL;
}

/* proxy_find_ep moved to sockproxy_conn.c (Phase 3) */
/* alpn_select_callback moved to sockproxy_ssl.c (Phase 3) */

/* proxy_free_fd_ctx, proxy_try_free_fd_ctx, proxy_delete_entry__ moved to sockproxy_conn.c (Phase 3) */
/* SSL context management moved to sockproxy_ssl.c (Phase 3) */
/* WRR algorithms moved to sockproxy_lb.c (Phase 2) */

/* US-PD801: Old P/D RR/WRR selection functions (pd_rr_select_from_role,
 * pd_wrr_select_from_role, pd_select_worker_pair) have been deleted.
 * Phase 4 will implement pd_select_prefill/pd_select_decode with 3-tier logic.
 */

