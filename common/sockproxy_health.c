/*
 * Copyright (c) 2022 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * sockproxy_health.c - Universal endpoint health management, circuit breaker,
 *                      and drain management for LoxiLB proxy.
 *
 * Extracted from sockproxy.c as of the refactoring plan.
 * Contains:
 *   - proxy_drain_checker_thread (background drain thread)
 *   - Drain management: count_active_connections_to_endpoint,
 *     force_close_endpoint_connections, cleanup_endpoint_sessions,
 *     check_draining_endpoints
 *   - Circuit breaker: circuit_breaker_init, circuit_breaker_should_skip,
 *     circuit_breaker_record_failure, circuit_breaker_record_success
 *   - Universal health: is_endpoint_healthy, find_next_healthy_endpoint,
 *     select_healthy_endpoint
 */

#include "uthash.h"
#include "log.h"
#include <linux/types.h>
#include <stdatomic.h>
#include <bpf.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "common_pdi.h"
#include "llb_dpapi.h"
#include "sockproxy_internal.h"
#include "circuit_breaker_heal.h"  /* 93-02 (D1): shared proactive-heal predicate (also unit-tested) */
#include "sockproxy_health.h"
#include "sockproxy_ai_gw.h"
#include "notify.h"
/* pure two-leg teardown helper shared with the unit TU.
 * Included AFTER the headers that define `struct proxy_fd_ent` and
 * notify_delete_ent so the helper's pfe* signature resolves here. */
#include "sockproxy_pd_leak.h"

/* Forward declaration for internal use (defined later in this file) */
static void check_draining_endpoints(void);

/* (conc=128 single-owner teardown) — replaces the
 * `pd_teardown_legs(pfe, notify_delete_ent_adapter, ns) + proxy_release_fd_ctx(pfe,1)`
 * pair at all four reaper sites below.
 *
 * Root cause it fixes (gdb-confirmed live): pd_teardown_legs() called
 * notify_delete_ent() per leg, which ALWAYS invokes cbs.pdestroy ->
 * proxy_pdestroy(). Inside the reaper (holding PROXY_LOCK) that re-acquired
 * PROXY_LOCK and ran proxy_release_rfd_ctx() -> proxy_release_fd_ctx(client)
 * once per backend leg — plus the reaper's own release at the end. Those N+1
 * releases of the same client pfe double-freed a non-idempotent buffer, the
 * next free aborted with "corrupted size vs. prev_size", the SIGABRT was
 * swallowed on the C thread, and the reaper never released PROXY_LOCK -> every
 * serving worker wedged (post_smoke=000, no restart).
 *
 * Single-owner contract here: deregister each fd WITHOUT pdestroy
 * (notify_deregister_ent), then release+free each backend leg exactly once and
 * the client exactly once. proxy_release_fd_ctx(reset=1) unlinks the pfe from
 * ent->val.fdlist and closes its fd; proxy_try_free_fd_ctx owns the node free
 * (used==1 here). Backends are inserted head-ward of the client in fdlist, so
 * freeing them is pfe_next-safe (they sit behind the reaper's cursor). Does NOT
 * re-acquire PROXY_LOCK, so it is safe to call while the reaper holds it.
 *
 * r2 (gdb-confirmed live wedge under decode-slowdown teardown churn):
 * the single-owner free above is NOT actually single-owner. notify_deregister_ent
 * only clears the notifier's earr[fd] entry; the matching free was done here
 * UNCONDITIONALLY, ignoring its return. But a notify worker can win the earr
 * clear first: notify_run -> notify_delete_ent__(fd) clears earr[fd] (passing
 * its own ent->fd>0 guard), commits to cbs.pdestroy=proxy_pdestroy(pfe), then
 * BLOCKS on the PROXY_LOCK the reaper holds. Our notify_deregister_ent then
 * returns -ENOENT (entry already cleared) yet we still freed the pfe -> when the
 * reaper releases PROXY_LOCK the worker's proxy_pdestroy frees the SAME pfe again
 * -> double-free -> glibc abort() -> SIGABRT swallowed on the C thread (Go
 * runtime badsignal) -> PROXY_LOCK never released -> total serving wedge
 * (aborts=0, restarts=0, both VIPs 000). earr[fd] IS the ownership token: free a
 * leg here ONLY if our notify_deregister_ent returned 0 (we cleared it first). On
 * -ENOENT the worker owns proxy_pdestroy()+free for that fd — skip our free. We
 * still detach the cross-references first so the worker's proxy_release_rfd_ctx
 * cannot cascade back into the client. */
static void
pd_teardown_conn(proxy_fd_ent_t *client)
{
  if (client == NULL) {
    return;
  }

  for (int i = 0; i < client->n_rfd && i < MAX_PROXY_EP; i++) {
    proxy_fd_ent_t *be = client->rfd_ent[i];
    int be_fd = client->rfd[i];

    /* own the free only if WE cleared earr[be_fd] (deregister==0); on -ENOENT a
     * notify worker already claimed it and owns proxy_pdestroy(be)+free. */
    int be_owned = 1;
    if (be_fd > 0) {
      be_owned = (notify_deregister_ent(proxy_struct->ns, be_fd) == 0);
    }
    client->rfd[i] = -1;

    if (be != NULL) {
      /* detach the client<->backend cross-references both ways first (always
       * safe under PROXY_LOCK; lets a racing worker's proxy_release_rfd_ctx(be)
       * not cascade into this client) */
      for (int j = 0; j < be->n_rfd && j < MAX_PROXY_EP; j++) {
        if (be->rfd_ent[j] == client) {
          be->rfd_ent[j] = NULL;
        }
      }
      be->n_rfd = 0;
      client->rfd_ent[i] = NULL;

      if (be_owned) {
        proxy_release_fd_ctx(be, 1);   /* reset: unlink fdlist + close be->fd */
        proxy_try_free_fd_ctx(be);     /* used-- -> free (single owner) */
      }
      /* else: notify worker owns proxy_pdestroy(be)+free (blocked on our
       * PROXY_LOCK); freeing here too would double-free. */
    }
  }
  client->n_rfd = 0;

  int client_owned = 1;
  if (client->fd > 0) {
    client_owned = (notify_deregister_ent(proxy_struct->ns, client->fd) == 0);
  }
  if (client_owned) {
    proxy_release_fd_ctx(client, 1);   /* reset: unlink fdlist + close client->fd */
    proxy_try_free_fd_ctx(client);     /* used-- -> free (single owner) */
  }
  /* else: a notify worker owns the client's proxy_pdestroy()+free — skip. */
}

/* prefill-timeout default with an env override (LLB_PD_PREFILL_TIMEOUT_SEC).
 * Unset/invalid => 30s (the production default, behaviour-identical). The override
 * exists so the prefill-timeout reaper — the path that drives pd_teardown_conn,
 * i.e. the conc=128 corruption fix — can be exercised DETERMINISTICALLY under load in
 * validation (e.g. =3 so saturated prefills time out and the reaper fires every tick),
 * instead of relying on prefill stochastically exceeding 30s. Cached (getenv once). */
static uint32_t
pd_prefill_timeout_default(void)
{
  static uint32_t cached = 0;  /* 0 = not yet resolved */
  uint32_t v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
  if (v != 0) {
    return v;
  }
  v = 30;
  const char *e = getenv("LLB_PD_PREFILL_TIMEOUT_SEC");
  if (e && *e) {
    long n = strtol(e, NULL, 10);
    if (n > 0 && n < 100000) {
      v = (uint32_t)n;
    }
  }
  __atomic_store_n(&cached, v, __ATOMIC_RELEASE);
  return v;
}

// P2: Periodic draining check thread
void *
proxy_drain_checker_thread(void *arg)
{
 
  while (1) {
    /* Tick at 1Hz.: timeoutMemberData is enforced inside
     * check_draining_endpoints' per-rule idle pass, and 76-04 documented the deadline as
     * "rounded UP to whole seconds because this pass ticks once per second". The loop previously
     * slept 5s, so a sub-5s member stall (e.g. the gate's 3s slow backend with a 1500ms→2s deadline)
     * completed BEFORE the next pass and was never cut. All work here is wall-clock-threshold based
     * (drain timeout, SSE max-duration cap, PD prefill timeout, per-rule idle deadline — each an
     * `elapsed >= threshold` against time(NULL)), so a finer 1Hz cadence only makes those deadlines
     * fire more promptly; it never changes WHICH connections are eligible. This realises the
     * documented 1-second granularity the timeoutMemberData feature was specified against. */
    sleep(1);
    check_draining_endpoints();

    /* (AC-4): bounded-footprint soak observability. Every ~10s emit a
     * single line carrying the pfe-pool high-water gauges + the global admission
     * gauge/blocked counter so soak_footprint.sh can sample pfe_pool_live (and the
     * accept-gate activity) from `docker logs` alongside RSS. Observability-only:
     * a plain read of leaf-mutex statics + relaxed atomics — it changes NO relay /
     * accept behavior.
     *
     * 93-06 (default-off): gated on the total-inflight bound being enabled
     * (LLB_PD_MAX_TOTAL_INFLIGHT > 0). With the knob unset the health thread takes
     * NO extra pfe_pool_lock and emits nothing ⇒ byte-identical to pre-93-06. The
     * soak harness sets the bound to observe pfe_pool_live / accept-gate activity. */
    if (pd_max_total_inflight() != 0) {
      static unsigned int fp_tick;
      if ((++fp_tick % 10u) == 0u) {
        unsigned long live = 0, total = 0;
        pfe_pool_snapshot(&live, &total);
        log_info("[PD_FOOTPRINT] pfe_pool_live=%lu pfe_pool_total=%lu "
                 "admission_inflight=%lu admission_blocked=%lu",
                 live, total,
                 (unsigned long)atomic_load_explicit(
                     &global_stats.pd_admission_total_inflight, memory_order_relaxed),
                 (unsigned long)atomic_load_explicit(
                     &global_stats.pd_admission_total_blocked, memory_order_relaxed));
      }
    }
  }

  return NULL;
}


// P2: Helper function - Count active connections to specific endpoint
uint32_t
count_active_connections_to_endpoint(proxy_map_ent_t *ent, int ep_index)
{
  proxy_fd_ent_t *fd_ent;
  uint32_t count = 0;
  
  if (!ent) return 0;
  
  fd_ent = ent->val.fdlist;
  while (fd_ent) {
    // Check if this connection is to the specified endpoint
    // Only count established remote connections (rfd[*] > 0)
    if (fd_ent->ep_num == ep_index && fd_ent->n_rfd > 0) {
      for (int i = 0; i < fd_ent->n_rfd; i++) {
        if (fd_ent->rfd[i] > 0) {
          count++;
          break; // Count this fd_ent only once
        }
      }
    }
    fd_ent = fd_ent->next;
  }
  
  return count;
}

// P2: Helper function - Force-close all connections to specified endpoint
//
// I5 fix (2026-06-24): this used to tear down each leg via
// notify_delete_ent(..., evict=0), which invokes cbs.pdestroy -> proxy_pdestroy()
// -> PROXY_LOCK(). But BOTH callers already hold PROXY_LOCK:
// check_draining_endpoints (the TIMED drain-timeout path) and proxy_update_ep_health
// (the DRAIN_POLICY_IMMEDIATE path). proxy_struct->lock is a non-recursive
// pthread_rwlock_t, so the re-acquire self-deadlocks; and pdestroy(client) + the
// trailing proxy_release_fd_ctx(client,1) double-release the client (N+1). This is
// the EXACT wedge class Phase-90 fixed for the P/D reaper (see notify.c:417-431,
// which names this very path) — force_close was simply never converted. Latent only
// because the KV campaigns never administratively drain endpoints mid-run.
//
// Fix: tear down via pd_teardown_conn (the Phase-90 single-owner primitive) — it
// deregisters each fd WITHOUT pdestroy (no PROXY_LOCK re-entry) and owns the free
// exactly once, so it is safe under PROXY_LOCK. pd_teardown_conn frees the matched
// pfe AND its cross-referenced peer legs and unlinks them from ent->val.fdlist, so
// the cursor must NOT be advanced across a freed node — re-scan from the live head
// after each teardown. SSE-suppressed connections are skipped without triggering a
// restart, so the loop terminates (each restart removes >=1 matchable connection).
// Note: a backend pfe can carry ep_num==ep_index (sockproxy_http.c:5065, h2:2898),
// so a matched fd_ent may be either a client or a backend; pd_teardown_conn tears
// down the whole connection pair from either entry point and the head re-scan then
// skips the freed partner.
void
force_close_endpoint_connections(proxy_map_ent_t *ent, int ep_index)
{
  proxy_fd_ent_t *fd_ent;
  uint32_t closed_count = 0;

  if (!ent) return;

restart:
  for (fd_ent = ent->val.fdlist; fd_ent != NULL; fd_ent = fd_ent->next) {
    // Check if this connection is to the specified endpoint
    if (fd_ent->ep_num != ep_index) {
      continue;
    }

    /* C-2: SSE eviction suppression — do not force-close an active SSE stream
     * when the backend endpoint is being drained.  The max-duration enforcer
     * in check_draining_endpoints handles stream lifetime limits. */
    if (fd_ent->sse_active == 1 && fd_ent->stream_end_ts == 0) {
      log_info("[SSE_EVICT_SUPPRESS] fd=%d: active SSE stream, deferring force-close",
               fd_ent->fd);
      continue;
    }

    /* Single-owner teardown (no pdestroy, no PROXY_LOCK re-entry). Frees fd_ent
     * and its peer legs and unlinks them from fdlist, so re-scan from the head. */
    pd_teardown_conn(fd_ent);
    closed_count++;
    goto restart;
  }

  if (closed_count > 0) {
    log_info("[DRAIN] ep[%d]: force-closed %u connection(s)", ep_index, closed_count);
  }
}

// P2: Proactive session cleanup - Remove all conversation mappings for inactive endpoint
// This prevents memory waste and re-learning overhead when endpoints go down
uint32_t
cleanup_endpoint_sessions(proxy_map_ent_t *ent, int ep_index)
{
  conversation_mapping_t *mapping, *tmp;
  uint32_t removed = 0;
  
  if (!ent || ep_index < 0) {
    return 0;
  }
  
  pthread_rwlock_wrlock(&ent->val.conv_lock);
  
  HASH_ITER(hh, ent->val.conv_map, mapping, tmp) {
    if (mapping->ep_idx == ep_index) {
      HASH_DEL(ent->val.conv_map, mapping);
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("[CONV_EP_DOWN] Removed stale session mapping '%s' → ep[%d] (proactive cleanup)",
                mapping->conv_id, ep_index);
#endif
      free(mapping);
      removed++;
    }
  }
  
  pthread_rwlock_unlock(&ent->val.conv_lock);
  
  if (removed > 0) {
    log_info("[CONV_EP_DOWN] Proactively removed %u stale session mappings for endpoint[%d]",
             removed, ep_index);
  }
  
  return removed;
}

// P2: Check draining endpoints and force-close if timeout exceeded
// Called periodically (every 5 seconds) by proxy_run() thread
static void
check_draining_endpoints(void)
{
  proxy_map_ent_t *node;
  proxy_epval_t *tepval, *tmp_epval;
  time_t now = time(NULL);
  
  PROXY_LOCK();
  
  node = proxy_struct->head;
  while (node) {
    HASH_ITER(hh, node->val.ephash, tepval, tmp_epval) {
      // Check each endpoint for draining state
      for (int ep_idx = 0; ep_idx < tepval->n_eps; ep_idx++) {
        if (tepval->drain_state[ep_idx].is_draining) {
          time_t elapsed = now - tepval->drain_state[ep_idx].drain_start_ts;
          
          if (elapsed >= tepval->drain_timeout_sec) {
            // Timeout exceeded - force-close connections
            uint32_t active_conns = count_active_connections_to_endpoint(node, ep_idx);
            
            if (active_conns > 0) {
              force_close_endpoint_connections(node, ep_idx);
            }
            
            // Mark draining complete
            tepval->drain_state[ep_idx].is_draining = 0;

          }
        }

        /* 93-02 (D1): proactive circuit-breaker recovery in the 1 Hz health pass.
         *
         * The P/D selection path reads circuit_breakers[].state RAW (== CB_STATE_OPEN
         * -> skip) at every tier (sockproxy_pd.c:934/978/1010/1029/1055/1106/1121/1239,
         * sockproxy_ep.c:647) and NEVER calls circuit_breaker_should_skip() — the only
         * site that performs the OPEN->HALF_OPEN timeout transition (this file, :794-802).
         * So a prefill EP whose breaker latched OPEN during its restart is skipped by the
         * P/D path PERMANENTLY, regardless of open_timeout_sec or traffic; recovery
         * (circuit_breaker_record_success) needs a successful relay that can never happen
         * because the EP is never selected. RR self-heals (it routes via
         * is_endpoint_healthy->should_skip); KV/PD does not. See 93-CONTEXT.md T1 map.
         *
         * Fix: drive OPEN->HALF_OPEN here, off the relay/teardown path, after the same
         * open_timeout_sec the should_skip path uses. This makes state != CB_STATE_OPEN,
         * so the tiers stop skipping the EP — it (inv=0, 0 conns => least-loaded) is picked
         * again and the next GENUINE relay success closes the breaker. Safety: a still-down
         * EP keeps inv=1 (Go control-plane health) and is skipped by the tiers regardless
         * of CB state (sockproxy_pd.c:1118); an up-but-failing EP fails the half-open
         * request -> record_failure -> clean re-OPEN (no oscillation, no synthetic probe
         * under PROXY_LOCK). Mirrors the transition at :797-799 exactly. */
        if (tepval->cb_enabled) {
          circuit_breaker_t *cb = &tepval->circuit_breakers[ep_idx];
          time_t open_for = now - cb->open_ts;  /* captured before the transition for the log */
          if (circuit_breaker_proactive_heal(cb, now)) {
            atomic_fetch_add(&global_stats.pd_cb_flips, 1);          /* OBS-03: OPEN->HALF_OPEN */
            atomic_fetch_add(&global_stats.pd_cb_proactive_heal, 1); /* 93-02: health-pass heal */
            log_info("[CB heal] ep[%d] OPEN->HALF_OPEN driven by 1Hz health pass "
                     "(open %lds >= %us) — EP re-enters rotation, next relay success closes it",
                     ep_idx, (long)open_for, cb->open_timeout_sec);
          }
        }
      }
    }
    node = node->next;
  }

  /* C-3: SSE max-duration enforcement — walk all live client connections and
   * force-terminate SSE streams that have exceeded their configured cap.
   *
   * effective_cap = min(max_stream_duration_sec, PROXY_SSE_HARD_CAP_SEC) when
   * max_stream_duration_sec > 0, else PROXY_SSE_HARD_CAP_SEC (24 h hard cap). */
  {
    static const char sse_dur_err[] =
        "data: {\"error\":\"max_stream_duration_exceeded\"}\n\n";

    proxy_map_ent_t *sse_node = proxy_struct->head;
    while (sse_node) {
      proxy_fd_ent_t *pfe = sse_node->val.fdlist;
      while (pfe) {
        proxy_fd_ent_t *pfe_next = pfe->next;

        if (pfe->sse_active == 1 && pfe->stream_end_ts == 0 &&
            pfe->stream_start_ts > 0) {
          time_t elapsed = now - pfe->stream_start_ts;
          time_t cap = (time_t)PROXY_SSE_HARD_CAP_SEC;
          if (pfe->max_stream_duration_sec > 0 &&
              (time_t)pfe->max_stream_duration_sec < cap) {
            cap = (time_t)pfe->max_stream_duration_sec;
          }

          if (elapsed >= cap) {
            log_info("[SSE_CAP] fd=%d: elapsed=%lds >= cap=%lds, terminating stream",
                     pfe->fd, (long)elapsed, (long)cap);
            /* Deliver an error SSE event before shutdown so the client can react. */
            if (pfe->fd > 0) {
              send(pfe->fd, sse_dur_err, sizeof(sse_dur_err) - 1, MSG_NOSIGNAL);
            }
            /* Decrement the active-streams gauge BEFORE clearing sse_active.
             * PROXY_LOCK() is held throughout check_draining_endpoints, so the
             * call is safe without copying the model field (idempotent CAS inside).
             * Model must resolve exactly as llb_ai_stream_start did — ending
             * with a bare x_model_header leaks the per-model gauge whenever
             * the model came from the request body or the reset-boundary
             * snapshot. */
            llb_ai_stream_end("", (char *)proxy_effective_model(pfe));
            pfe->stream_end_ts = now;
            pfe->sse_active = 0;  /* Reset so eviction suppression no longer blocks cleanup */
            /* Terminate both directions; the epoll loop will clean up. */
            if (pfe->fd > 0) {
              shutdown(pfe->fd, SHUT_RDWR);
            }
          }
        }

        pfe = pfe_next;
      }
      sse_node = sse_node->next;
    }
  }

  /* C-4: Per-rule idle timeout enforcement — terminate connections that have been
   * idle (no data received) for longer than the rule's inactiveTimeOut setting.
   * Suppressed when sse_active=1 so active SSE streams are not killed by idle
 * timeout (the whole point of sse_mode suppression in).
   * Only enforced when inactive_timeout_sec > 0; setting is sourced from the
   * dat->ito field of dp_proxy_tacts via llb_conv_nat2proxy. */
  {
    proxy_map_ent_t *ito_node = proxy_struct->head;
    while (ito_node) {
      /* (Open-Q1/): timeoutMemberData is enforced HERE, aliased onto the
       * existing per-rule idle deadline (this is THE single chosen member-side relay-idle site —
       * the run loop's one idle-disconnect pass, semantics match A5). When the listener has an
       * L7_POLICY attached (has_l7_policy==1) and a non-zero timeout_member_data_ms is configured,
       * the L7 listener's member-side idle deadline (milliseconds) governs and TIGHTENS/overrides
       * the seconds-granularity inactive_timeout_sec for its connections; the deadline is rounded
       * UP to whole seconds (this pass ticks once per second, so sub-second ms cannot be honoured
       * finer than 1s here — documented). For the AI peer / un-configured listeners (has_l7_policy
 * ==0 or timeout_member_data_ms==0) behaviour is byte-for-byte unchanged. */
      uint32_t l7_data_to_s = 0;
      if (ito_node->has_l7_policy && ito_node->arg_ptr &&
          ito_node->arg_ptr->timeout_member_data_ms > 0) {
        /* ms → seconds, rounded up so a sub-second deadline still expires after one tick */
        l7_data_to_s = (ito_node->arg_ptr->timeout_member_data_ms + 999) / 1000;
      }
      proxy_fd_ent_t *pfe = ito_node->val.fdlist;
      while (pfe) {
        proxy_fd_ent_t *pfe_next = pfe->next;

        /* L7 member-data deadline overrides the per-rule idle deadline when configured. */
        uint32_t idle_to_s = (l7_data_to_s > 0) ? l7_data_to_s : pfe->inactive_timeout_sec;

        /* for the L7 timeoutMemberData deadline use >= so a deadline rounded UP to N whole
         * seconds fires AT the Nth 1Hz tick (e.g. 1500ms→2s fires at the 2s pass, landing inside the
         * gate's configured-ms window), rather than only after N+1 seconds. The legacy per-rule
         * inactive_timeout_sec path keeps its original strict > semantics (behaviour-preserving). */
        time_t idle_elapsed = now - pfe->last_activity;
        int idle_expired = (l7_data_to_s > 0)
                               ? (idle_elapsed >= (time_t)idle_to_s)
                               : (idle_elapsed > (time_t)idle_to_s);

        if (idle_to_s > 0 &&
            pfe->sse_active == 0 &&         /* do not kill active SSE streams */
            pfe->last_activity > 0 &&
            idle_expired) {
          log_info("[IDLE_TIMEOUT] fd=%d: idle=%lds >= timeout=%us%s, closing connection",
                   pfe->fd, (long)(now - pfe->last_activity), idle_to_s,
                   (l7_data_to_s > 0) ? " (L7 timeoutMemberData)" : "");
          if (pfe->fd > 0) {
            shutdown(pfe->fd, SHUT_RDWR);
          }
        }

        pfe = pfe_next;
      }
      ito_node = ito_node->next;
    }
  }

  /* P/D prefill timeout enforcement — walk all client connections and
   * detect prefill phases that have exceeded their timeout.  Default is 30s
   * (typical prefill completes in 50-500ms). */
  {
    static const char pd_timeout_resp[] =
        "HTTP/1.1 504 Gateway Timeout\r\n"
        "Content-Type: application/json\r\n"
        "Connection: close\r\n"
        "\r\n"
        "{\"error\":\"pd_prefill_timeout\"}";

    proxy_map_ent_t *pd_node = proxy_struct->head;
    while (pd_node) {
      proxy_fd_ent_t *pfe = pd_node->val.fdlist;
      while (pfe) {
        proxy_fd_ent_t *pfe_next = pfe->next;

        if (pfe->pd_phase >= PD_PHASE_PREFILL_SENDING &&
            pfe->pd_phase <= PD_PHASE_PREFILL_DONE &&
            pfe->pd_phase_start_ts > 0) {
          time_t elapsed = now - pfe->pd_phase_start_ts;
          uint32_t timeout = pd_prefill_timeout_default(); /* 30s, env-overridable */
          if (pfe->epv) {
            proxy_epval_t *epv = (proxy_epval_t *)pfe->epv;
            if (epv->pd_prefill_timeout_sec > 0) {
              timeout = epv->pd_prefill_timeout_sec;
            }
          }

          if (elapsed >= (time_t)timeout) {
            log_error("P/D prefill timeout — fd=%d elapsed=%lds >= timeout=%us",
                      pfe->fd, (long)elapsed, timeout);
            /* Record P/D timeout metrics before cleanup */
            {
              char *pd_tmo_model = "";
              if (pfe->x_model_header[0] != '\0') {
                pd_tmo_model = pfe->x_model_header;
              } else if (pfe->prefix_key.model[0] != '\0') {
                pd_tmo_model = pfe->prefix_key.model;
              }
              int64_t t_prefill_ms = 0;
              if (pfe->pd_prefill_start_ns > 0) {
                struct timespec _pdts;
                clock_gettime(CLOCK_MONOTONIC, &_pdts);
                uint64_t t_now = (uint64_t)_pdts.tv_sec * 1000000000ULL +
                                 (uint64_t)_pdts.tv_nsec;
                t_prefill_ms = (int64_t)((t_now - pfe->pd_prefill_start_ns) /
                                          1000000ULL);
              }
              int t_kv = (pfe->pd_kv_params_len > 0) ? 1 : 0;
              log_info(" llb_ai_pd_record (prefill timeout): model=%s prefill=%lldms kv=%d",
                       pd_tmo_model, (long long)t_prefill_ms, t_kv);
              llb_ai_pd_record(pd_tmo_model, t_prefill_ms, 0, t_kv, 1);
            }
            if (pfe->fd > 0) {
              send(pfe->fd, pd_timeout_resp, sizeof(pd_timeout_resp) - 1,
                   MSG_DONTWAIT | MSG_NOSIGNAL);
            }
            /* single-owner teardown (see pd_teardown_conn). Mark ERROR,
             * then deregister+close+free each backend leg and the client exactly
             * once. We hold PROXY_LOCK and pd_teardown_conn does NOT re-acquire it
             * (the Phase-87 pd_teardown_legs route did, via notify_del->pdestroy,
             * and double-freed the client per leg -> conc=128 corruption+wedge).
             * Iteration uses pfe_next and backends sit head-ward, so the frees are
             * pfe_next-safe. */
            pfe->pd_phase = PD_PHASE_ERROR;
            pd_teardown_conn(pfe);
          }
        }

        pfe = pfe_next;
      }
      pd_node = pd_node->next;
    }
  }

  /* (AC-5b): MAX-PARK REAP. A bounded-admission PARKED conn is
   * PD_PHASE_PARKED — INVISIBLE to the prefill-timeout scan above (which gates on
   * PD_PHASE_PREFILL_SENDING..PREFILL_DONE). Without this pass a conn that never gets
   * a slot-free dequeue would leak its fd + 1 MB rcvbuf until the client gives up.
   * This pass drops any parked conn older than LLB_PD_MAX_PARK_SEC, bounding the
   * worst-case park wait to O(max_park) instead of O(prefill_timeout). It funnels
   * through the SAME single-owner pd_teardown_conn as the other reapers (no
   * proxy_pdestroy, no PROXY_LOCK re-entry) with pfe_next-safe iteration (Shared
   * Pattern C). Default-off: pd_max_park_sec()==0 (and the queue feature off) ⇒ the
   * whole pass is skipped ⇒ byte-identical. Kept MINIMAL (max-park-only) so it does
   * not materially grow the O(n)-under-lock scan (Open Q3 — D2 sharding deferred). */
  {
    uint32_t max_park = pd_max_park_sec();
    /* Gate behind BOTH the queue feature AND a non-zero reap bound, so a deploy that
     * sets the FIFO depth but not the reap bound still bounds parked lifetime: if the
     * queue is on but LLB_PD_MAX_PARK_SEC is unset, default the reap to the prefill
     * timeout (the parked conn cannot outlive what an in-flight prefill would). */
    if (pd_queue_depth_per_ep() > 0) {
      if (max_park == 0) {
        max_park = pd_prefill_timeout_default();  /* sane fallback < typical client timeout */
      }
      static const char pd_park_timeout_resp[] =
          "HTTP/1.1 504 Gateway Timeout\r\n"
          "Content-Type: application/json\r\n"
          "Connection: close\r\n"
          "\r\n"
          "{\"error\":\"pd_admission_park_timeout\"}";

      struct timespec _mpts;
      clock_gettime(CLOCK_MONOTONIC, &_mpts);
      uint64_t mp_now_ns = (uint64_t)_mpts.tv_sec * 1000000000ULL + (uint64_t)_mpts.tv_nsec;
      uint64_t max_park_ns = (uint64_t)max_park * 1000000000ULL;

      proxy_map_ent_t *mp_node = proxy_struct->head;
      while (mp_node) {
        proxy_fd_ent_t *pfe = mp_node->val.fdlist;
        while (pfe) {
          proxy_fd_ent_t *pfe_next = pfe->next;  /* capture BEFORE teardown frees pfe */

          if (pfe->pd_phase == PD_PHASE_PARKED &&
              pfe->park_start_ts > 0 &&
              mp_now_ns >= pfe->park_start_ts &&
              (mp_now_ns - pfe->park_start_ts) >= max_park_ns) {

            log_error("[PD_ADMISSION] max-park reap — fd=%d parked %llums >= %us "
                      "(ep=%d) — 504 + teardown", pfe->fd,
                      (unsigned long long)((mp_now_ns - pfe->park_start_ts) / 1000000ULL),
                      max_park, pfe->park_ep_idx);

            /* Remove this conn from its EP's parked FIFO (it never dispatched). Under
             * pd_parked_lock; pd_parked_remove_fd is FIFO-order-safe. The fd may have
             * already been popped by a dequeue whose wake then failed — remove_fd then
             * simply returns "not found", which is fine. */
            if (pfe->epv && pfe->park_ep_idx >= 0) {
              proxy_epval_t *pev = (proxy_epval_t *)pfe->epv;
              if (pfe->park_ep_idx < pev->n_eps) {
                pthread_mutex_lock(&pev->pd_parked_lock);
                pd_parked_remove_fd(&pev->pd_parked[pfe->park_ep_idx], pfe->fd,
                                    atomic_load_explicit(&pfe->gen, memory_order_relaxed));
                pthread_mutex_unlock(&pev->pd_parked_lock);
              }
            }

            if (pfe->fd > 0) {
              send(pfe->fd, pd_park_timeout_resp, sizeof(pd_park_timeout_resp) - 1,
                   MSG_DONTWAIT | MSG_NOSIGNAL);
            }
            pfe->park_ep_idx   = -1;
            pfe->park_start_ts = 0;
            /* Single-owner teardown (see pd_teardown_conn): does NOT re-acquire
             * PROXY_LOCK, does NOT proxy_pdestroy. pfe_next captured above, so the
             * free is pfe_next-safe. A parked conn has NO backend leg (never
             * connected), so pd_teardown_conn just deregisters+closes+frees the
             * client exactly once. */
            pfe->pd_phase = PD_PHASE_ERROR;
            pd_teardown_conn(pfe);
          }

          pfe = pfe_next;
        }
        mp_node = mp_node->next;
      }
    }
  }

  /* (RESOLVED): graceful [DONE]-synthesis safety-net — the real
   * deliverable. Diagnosis: vLLM's P/D-disagg path FINISHES generation but omits
   * the closing "data: [DONE]" SSE chunk for ~2.5% of streams under concurrency
   * (loxilb's :1198 scanner completes 100% of TERMINATED streams — exonerated).
   * Such a stream sits in PD_PHASE_DECODE_STREAMING with sse_active==1 and its
 * backend leg silent forever, eventually hit by the 502 / 504
   * backstops below — both of which inject a malformed HTTP status line into a
   * body the client already saw "200 OK" for.
   *
 * This sweep runs FIRST (before) and, when the BACKEND leg has been
   * idle past PROXY_PD_DECODE_IDLE_CAP_SEC (gated on pd_last_decode_ts, refreshed
   * per relayed byte in sockproxy_http.c — NOT wall-clock-since-start, so a
   * slow-but-live stream is never truncated), synthesizes the protocol-correct
   * "data: [DONE]\n\n" terminator and completes the flow exactly as the :1198
   * SSE_DONE path would have: stream-end gauge, P/D metrics, COMPLETE, then the
   * same single-owner pd_teardown_conn as the other reapers.
   * Converts a forever-hang into a clean completion. */
  {
    static const char pd_graceful_done[] = "data: [DONE]\n\n";

    proxy_map_ent_t *pd_node = proxy_struct->head;
    while (pd_node) {
      proxy_fd_ent_t *pfe = pd_node->val.fdlist;
      while (pfe) {
        proxy_fd_ent_t *pfe_next = pfe->next;

        uint32_t decode_idle_cap = PROXY_PD_DECODE_IDLE_CAP_SEC;
        if (pfe->epv) {
          proxy_epval_t *epv = (proxy_epval_t *)pfe->epv;
          if (epv->pd_decode_idle_cap_sec > 0) {
            decode_idle_cap = epv->pd_decode_idle_cap_sec;
          }
        }

        if (pd_should_graceful_complete(
                pfe->pd_phase == PD_PHASE_DECODE_STREAMING,
                pfe->sse_active, pfe->stream_end_ts, pfe->pd_last_decode_ts,
                now, decode_idle_cap)) {
          log_info("[PD_GRACEFUL_DONE] fd=%d backend-idle=%lds >= cap=%us — "
                   "synthesizing data: [DONE] (vLLM dropped terminator)",
                   pfe->fd, (long)(now - pfe->pd_last_decode_ts), decode_idle_cap);

          const char *gc_model = proxy_effective_model(pfe);

          /* 1) Send the synthesized SSE terminator BEFORE any teardown. */
          if (pfe->fd > 0) {
            send(pfe->fd, pd_graceful_done, sizeof(pd_graceful_done) - 1,
                 MSG_DONTWAIT | MSG_NOSIGNAL);
          }

          /* 2) End the active-streams gauge (balances llb_ai_stream_start at
           * SSE activation), then reset sse_active so eviction-suppression no
           * longer blocks cleanup — mirrors the [SSE_CAP] path. */
          llb_ai_stream_end("", (char *)gc_model);
          pfe->stream_end_ts = now;
          pfe->sse_active = 0;

          /* 3) Record P/D metrics, mirroring the :1255 SSE_DONE success path. */
          {
            struct timespec _pdts;
            clock_gettime(CLOCK_MONOTONIC, &_pdts);
            uint64_t pd_now_ns = (uint64_t)_pdts.tv_sec * 1000000000ULL +
                                 (uint64_t)_pdts.tv_nsec;
            int64_t prefill_ms = 0, decode_ms = 0;
            if (pfe->pd_prefill_start_ns > 0 && pfe->pd_decode_start_ns > 0) {
              prefill_ms = (int64_t)((pfe->pd_decode_start_ns -
                                      pfe->pd_prefill_start_ns) / 1000000ULL);
            }
            if (pfe->pd_decode_start_ns > 0) {
              decode_ms = (int64_t)((pd_now_ns - pfe->pd_decode_start_ns) /
                                    1000000ULL);
            }
            int pd_kv = (pfe->pd_kv_params_len > 0) ? 1 : 0;
            llb_ai_pd_record((char *)gc_model, prefill_ms, decode_ms, pd_kv, 0);
          }

          /* 4) Mark COMPLETE and tear down with the same leak-proof sequence as
 * (held under PROXY_LOCK; pfe_next-safe). */
          pfe->pd_phase = PD_PHASE_COMPLETE;
          pd_teardown_conn(pfe);
        }

        pfe = pfe_next;
      }
      pd_node = pd_node->next;
    }
  }

  /* P/D decode stream timeout enforcement — walk all client connections
   * and detect decode streaming phases that have exceeded their timeout.
   * Default is 120s. When a decode EP crashes mid-stream, this prevents the
   * client from hanging until the 300s SO_RCVTIMEO fires. */
  {
    static const char pd_decode_timeout_resp[] =
        "HTTP/1.1 502 Bad Gateway\r\n"
        "Content-Type: application/json\r\n"
        "Connection: close\r\n"
        "\r\n"
        "{\"error\":\"pd_decode_stream_timeout\"}";

    proxy_map_ent_t *pd_node = proxy_struct->head;
    while (pd_node) {
      proxy_fd_ent_t *pfe = pd_node->val.fdlist;
      while (pfe) {
        proxy_fd_ent_t *pfe_next = pfe->next;

        if (pfe->pd_phase == PD_PHASE_DECODE_STREAMING &&
            pfe->pd_phase_start_ts > 0) {
          /* Idle-based, NOT duration-based (F-GPU-6): pd_last_decode_ts is
           * refreshed on every relayed decode byte (sockproxy_http.c [DONE]
           * scanner), so an ACTIVE stream keeps pushing this deadline out no
           * matter how long the generation runs. Measuring from
           * pd_phase_start_ts truncated every legitimate >120s generation
           * mid-stream (8192-token SSE died at exactly 120s with no [DONE],
           * no finish_reason). Only a decode backend that has gone SILENT for
           * the full timeout — the EP-crash hang this sweep exists for —
           * still trips it. */
          time_t basis = pfe->pd_phase_start_ts;
          if (pfe->pd_last_decode_ts > basis) {
            basis = pfe->pd_last_decode_ts;
          }
          time_t elapsed = now - basis;
          uint32_t timeout = 120; /* default 120s decode-stream SILENCE */
          if (pfe->epv) {
            proxy_epval_t *epv = (proxy_epval_t *)pfe->epv;
            if (epv->pd_decode_timeout_sec > 0) {
              timeout = epv->pd_decode_timeout_sec;
            }
          }
          if (elapsed >= (time_t)timeout) {
            log_error("ERR-01: P/D decode stream timeout — fd=%d idle=%lds",
                      pfe->fd, (long)elapsed);
            if (pfe->fd > 0) {
              send(pfe->fd, pd_decode_timeout_resp,
                   sizeof(pd_decode_timeout_resp) - 1,
                   MSG_DONTWAIT | MSG_NOSIGNAL);
            }
            /* real two-leg teardown (see above). */
            pfe->pd_phase = PD_PHASE_ERROR;
            pd_teardown_conn(pfe);
          }
        }

        pfe = pfe_next;
      }
      pd_node = pd_node->next;
    }
  }

  /* generic ESTABLISHED-but-idle P/D reaper — defense in depth.
 * The and sweeps only cover PREFILL_SENDING..PREFILL_DONE and
   * DECODE_STREAMING respectively; a pfe stuck in DECODE_SENDING (or any P/D
   * phase that wedged without advancing) would still leak ESTABLISHED-idle legs.
   * This sweep closes ANY pfe whose pd_phase is an in-flight P/D phase
   * (PREFILL_SENDING..DECODE_STREAMING, i.e. != NONE and not yet COMPLETE/ERROR)
   * whose pd_phase_start_ts has exceeded a conservative cap. Cap is an epv field
   * (pd_idle_cap_sec); when unset it defaults to max(prefill,decode)+slack. Same
   * saved-pfe_next iteration + the same single-owner pd_teardown_conn
   * (no full client-destroy path → no PROXY_LOCK re-entry). */
  {
    static const char pd_idle_resp[] =
        "HTTP/1.1 504 Gateway Timeout\r\n"
        "Content-Type: application/json\r\n"
        "Connection: close\r\n"
        "\r\n"
        "{\"error\":\"pd_idle_timeout\"}";

    proxy_map_ent_t *pd_node = proxy_struct->head;
    while (pd_node) {
      proxy_fd_ent_t *pfe = pd_node->val.fdlist;
      while (pfe) {
        proxy_fd_ent_t *pfe_next = pfe->next;

        if (pfe->pd_phase >= PD_PHASE_PREFILL_SENDING &&
            pfe->pd_phase <= PD_PHASE_DECODE_STREAMING &&
            pfe->pd_phase_start_ts > 0) {
          /* Conservative cap: epv override, else max(prefill,decode)+slack. */
          uint32_t prefill_to = 30;  /* mirrors default */
          uint32_t decode_to = 120;  /* mirrors default */
          uint32_t idle_cap = 0;
          if (pfe->epv) {
            proxy_epval_t *epv = (proxy_epval_t *)pfe->epv;
            if (epv->pd_prefill_timeout_sec > 0) {
              prefill_to = epv->pd_prefill_timeout_sec;
            }
            if (epv->pd_decode_timeout_sec > 0) {
              decode_to = epv->pd_decode_timeout_sec;
            }
            if (epv->pd_idle_cap_sec > 0) {
              idle_cap = epv->pd_idle_cap_sec;
            }
          }
          if (idle_cap == 0) {
            uint32_t base = (prefill_to > decode_to) ? prefill_to : decode_to;
            idle_cap = base + 60; /* +60s slack beyond the specific reapers */
          }

          /* Same activity basis as ERR-01 (F-GPU-6): an actively-relaying
           * DECODE_STREAMING flow must not be reaped on total duration —
           * without this the +60s slack only bought a stream 180s before
           * this sweep killed what ERR-01 spared. */
          time_t basis = pfe->pd_phase_start_ts;
          if (pfe->pd_phase == PD_PHASE_DECODE_STREAMING &&
              pfe->pd_last_decode_ts > basis) {
            basis = pfe->pd_last_decode_ts;
          }
          time_t elapsed = now - basis;
          if (elapsed >= (time_t)idle_cap) {
            log_error("generic P/D idle reaper — fd=%d pd_phase=%d "
                      "elapsed=%lds >= cap=%us",
                      pfe->fd, (int)pfe->pd_phase, (long)elapsed, idle_cap);
            if (pfe->fd > 0) {
              send(pfe->fd, pd_idle_resp, sizeof(pd_idle_resp) - 1,
                   MSG_DONTWAIT | MSG_NOSIGNAL);
            }
            pfe->pd_phase = PD_PHASE_ERROR;
            pd_teardown_conn(pfe);
          }
        }

        pfe = pfe_next;
      }
      pd_node = pd_node->next;
    }
  }

  PROXY_UNLOCK();
}


// P2 Task 2.3: Initialize circuit breaker for an endpoint
void
circuit_breaker_init(circuit_breaker_t *cb)
{
  if (!cb) return;
  
  memset(cb, 0, sizeof(*cb));
  cb->state = CB_STATE_CLOSED;
  cb->failure_threshold = 5;      // Default: 5 consecutive failures
  cb->success_threshold = 1;       // Default: 1 success in HALF_OPEN to close
  cb->open_timeout_sec = 30;       // Default: 30 seconds
  cb->half_open_max_requests = 3;  // Default: 3 test requests in HALF_OPEN
}

// P2 Task 2.3: Check if circuit breaker should skip this endpoint
// Returns: 1 = skip endpoint, 0 = allow traffic
int
circuit_breaker_should_skip(proxy_epval_t *tepval, int ep_index)
{
  circuit_breaker_t *cb;
  time_t now = time(NULL);
  
  if (!tepval || !tepval->cb_enabled || ep_index >= MAX_PROXY_EP) {
    return 0;  // Circuit breaker disabled or invalid index
  }
  
  cb = &tepval->circuit_breakers[ep_index];
  
  switch (cb->state) {
  case CB_STATE_CLOSED:
    // Normal operation - allow traffic
    return 0;
    
  case CB_STATE_OPEN:
    // Check if timeout expired → transition to HALF_OPEN
    if (now - cb->open_ts >= cb->open_timeout_sec) {
      cb->state = CB_STATE_HALF_OPEN;
      cb->half_open_requests = 0;
      cb->success_count = 0;
      atomic_fetch_add(&global_stats.pd_cb_flips, 1);  /* OBS-03: OPEN→HALF_OPEN */
      return 0;  // Allow testing in HALF_OPEN
    }
    // Still within timeout - reject traffic
    return 1;
    
  case CB_STATE_HALF_OPEN:
    // Limited testing - allow only N requests
    if (cb->half_open_requests >= cb->half_open_max_requests) {
      return 1;  // Already testing, skip additional requests
    }
    cb->half_open_requests++;
    return 0;
  }
  
  return 0;
}

// P2 Task 2.3: Record connection failure for circuit breaker
void
circuit_breaker_record_failure(proxy_epval_t *tepval, int ep_index)
{
  circuit_breaker_t *cb;
  time_t now = time(NULL);
  
  if (!tepval || !tepval->cb_enabled || ep_index >= MAX_PROXY_EP) {
    return;
  }
  
  cb = &tepval->circuit_breakers[ep_index];
  cb->last_failure_ts = now;
  
  switch (cb->state) {
  case CB_STATE_CLOSED:
    cb->failure_count++;
    
    if (cb->failure_count >= cb->failure_threshold) {
      // Threshold exceeded - open circuit
      cb->state = CB_STATE_OPEN;
      cb->open_ts = now;
      atomic_fetch_add(&global_stats.pd_cb_flips, 1);  /* OBS-03: CLOSED→OPEN */
      log_info("Circuit breaker CLOSED → OPEN - ep[%d], %u failures",
               ep_index, cb->failure_count);
      /* remove tripped EP from trie */
      if (tepval->pd_trie) {
        pthread_rwlock_wrlock(&tepval->pd_trie_lock);
        pd_trie_remove_ep(tepval->pd_trie, ep_index);
        pthread_rwlock_unlock(&tepval->pd_trie_lock);
      }
    }
    break;
    
  case CB_STATE_HALF_OPEN:
    // Failure in HALF_OPEN → back to OPEN
    cb->state = CB_STATE_OPEN;
    cb->open_ts = now;
    cb->failure_count = cb->failure_threshold;  // Reset to threshold
    atomic_fetch_add(&global_stats.pd_cb_flips, 1);  /* OBS-03: HALF_OPEN→OPEN */
    log_info("Circuit breaker HALF_OPEN → OPEN - ep[%d], recovery failed",
             ep_index);
    /* remove tripped EP from trie */
    if (tepval->pd_trie) {
      pthread_rwlock_wrlock(&tepval->pd_trie_lock);
      pd_trie_remove_ep(tepval->pd_trie, ep_index);
      pthread_rwlock_unlock(&tepval->pd_trie_lock);
    }
    break;
    
  case CB_STATE_OPEN:
    // Already open - no action needed
    break;
  }
}

// P2 Task 2.3: Record connection success for circuit breaker
void
circuit_breaker_record_success(proxy_epval_t *tepval, int ep_index)
{
  circuit_breaker_t *cb;
  
  if (!tepval || !tepval->cb_enabled || ep_index >= MAX_PROXY_EP) {
    return;
  }
  
  cb = &tepval->circuit_breakers[ep_index];
  
  switch (cb->state) {
  case CB_STATE_CLOSED:
    // Reset failure count on success
    cb->failure_count = 0;
    break;
    
  case CB_STATE_HALF_OPEN:
    cb->success_count++;
    
    if (cb->success_count >= cb->success_threshold) {
      // Enough successes - close circuit
      cb->state = CB_STATE_CLOSED;
      cb->failure_count = 0;
      atomic_fetch_add(&global_stats.pd_cb_flips, 1);  /* OBS-03: HALF_OPEN→CLOSED */
      /* 93-02 (D1): complete the recovery observability triad. The OPEN→HALF_OPEN
       * heal ([CB heal], sockproxy_health.c) and CLOSED→OPEN trip already log; this
       * makes the CLOSE observable too, so a full self-heal cycle is visible in the
       * docker logs without inferring it from the absence of misses (per
       * [[validation-harness-pitfalls]] — the live test must self-confirm). */
      log_info("[CB heal] ep[%d] HALF_OPEN->CLOSED on relay success — fully back in rotation",
               ep_index);
    }
    break;
    
  case CB_STATE_OPEN:
    // Success in OPEN state shouldn't happen, but log it
    break;
  }
}

// ============================================================================
// P2: Universal Endpoint Health Management
// These functions provide health-aware endpoint selection for ALL algorithms
// ============================================================================

// P2: Universal endpoint health checking - works for ALL selection algorithms
// Returns: 1 if endpoint is healthy, 0 if unhealthy
int is_endpoint_healthy(proxy_epval_t *tepval, int ep_idx)
{
  if (!tepval || ep_idx < 0 || ep_idx >= tepval->n_eps) {
    return 0;
  }
  
  // Primary health check: inv flag (0 = active, 1 = inactive)
  if (tepval->eps[ep_idx].inv != 0) {
    return 0;
  }
  
  // Circuit breaker check (integrated into universal health system)
  if (circuit_breaker_should_skip(tepval, ep_idx)) {
    return 0;
  }
  
  // Future: Additional checks can be added here:
  // - Connection limits  
  // - Response time thresholds
  // - Custom health predicates
  // - Rate limiting
  // - Geographic constraints
  
  return 1;  // Healthy
}

// P2: Universal healthy endpoint finder - works for ALL selection algorithms  
// Finds the next healthy endpoint starting from a given position
// Returns: endpoint index if found, -1 if no healthy endpoint available
int find_next_healthy_endpoint(proxy_epval_t *tepval, int start_idx)
{
  if (!tepval || tepval->n_eps == 0) {
    return -1;
  }
  
  // Try each endpoint starting from start_idx
  for (int i = 0; i < tepval->n_eps; i++) {
    int ep_idx = (start_idx + i) % tepval->n_eps;
    
    if (is_endpoint_healthy(tepval, ep_idx)) {
      return ep_idx;
    }
  }
  
  log_error("P2: No healthy endpoints available (checked all %d endpoints)", tepval->n_eps);
  return -1;
}

// P2: Universal endpoint selection wrapper
// Validates algorithm selection result and provides health-aware fallback
// This ensures ALL selection algorithms automatically get health awareness
int select_healthy_endpoint(proxy_epval_t *tepval, int algorithm_selection)
{
  
  if (!tepval) {
    log_error("P2: select_healthy_endpoint: tepval is NULL!");
    return -1;
  }
  
  // Validate n_eps is sane
  if (tepval->n_eps <= 0 || tepval->n_eps > MAX_PROXY_EP) {
    log_error("P2: Invalid n_eps=%d (must be 1-%d)", tepval->n_eps, MAX_PROXY_EP);
    return -1;
  }
  
  // If algorithm provided valid selection, check if it's healthy
  if (algorithm_selection >= 0 && algorithm_selection < tepval->n_eps) {
    if (is_endpoint_healthy(tepval, algorithm_selection)) {
      return algorithm_selection;
    }
  }
  
  int result = find_next_healthy_endpoint(tepval, 0);

  // Final bounds check (defense in depth)
  if (result >= 0 && result >= tepval->n_eps) {
    log_error("P2: find_next_healthy_endpoint returned out-of-bounds ep=%d (n_eps=%d)",
              result, tepval->n_eps);
    return -1;
  }
  
  return result;
}
