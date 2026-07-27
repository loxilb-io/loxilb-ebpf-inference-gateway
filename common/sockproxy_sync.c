/* SPDX-License-Identifier: GPL-2.0
 *
 * sockproxy_sync.c — HA state-sync receiver.
 * SPEC.md req: A4, A5, A7.
 *
 * Implements:
 *  - proxy_sync_apply_session_entry(): the wire-level RPC handler invoked
 *    from Go (via CGO) for each remote-pushed SockproxySessionEntry. The
 *    health-gate (is_endpoint_healthy) is the LAST step before wrlock
 *    acquire (SPEC A5 + RESEARCH §5). First-writer-wins by created_ts
 *    implements SPEC A6 conflict resolution.
 *  - sockproxy_snapshot_pd_sessions(): rdlock-memcpy-unlock iterator used
 *    by the sender side of GetSockproxySnapshot to dump per-service P/D
 *    sessions without holding the wrlock for the entire transfer
 *    (RESEARCH §3 Pattern C).
 *
 * Lock-discipline invariant (sockproxy_internal.h:89-100):
 *   Pri-3 conv_lock < Pri-4 pd_session_lock < Pri-5 pd_trie_lock.
 * Emit (llb_sockproxy_emit_sync_event) ONLY after the protecting rwlock
 * has been released — never nested. The receiver itself NEVER emits; it
 * only INSTALLS state coming from a peer (no event loop here).
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>
#include <time.h>

#include "uthash.h"
#include "log.h"
#include "sockproxy.h"
#include "sockproxy_internal.h"

/* Forward declaration; real signature reuses sockproxy_health.c. */
extern int is_endpoint_healthy(proxy_epval_t *tepval, int ep_idx);

/* Outcome codes returned to Go-side coordinator for conflict-resolution
 * metric labelling (sockproxy_sync.go updates the conflict counter). */
#define SYNC_APPLY_INSTALLED      0  /* installed or replaced local; remote_won */
#define SYNC_APPLY_LOCAL_KEPT     1  /* local.created_ts strictly older — kept */
#define SYNC_APPLY_TIE_LOCAL_KEPT 2  /* local.created_ts == remote — kept (SPEC A6) */
#define SYNC_APPLY_HEALTH_REJECT  3  /* receiver-side ep unhealthy (SPEC A5) */
#define SYNC_APPLY_ERROR         -1  /* malformed input, service not found, etc. */

/* proxy_lookup_service: resolve "xip:xport:proto" service key → proxy_map_ent_t.
 *
 * The string form is "<dotted-ip>:<port-dec>:<proto-num>" (e.g. "10.10.10.1:8080:6").
 * This helper walks proxy_struct->head under PROXY_RDLOCK. Returns NULL on miss.
 * Lock priority Pri-1 — held briefly; emit must NOT be called while this lock
 * is held (Landmine L-7).
 *
 * NB: a stronger implementation would index by service_key in a hashmap, but
 * only invokes this on the receive path (RPC traffic, not packet
 * traffic), so linear walk over a typical-handful service list is fine.
 */
static proxy_map_ent_t *
proxy_lookup_service_by_key(const char *service_key)
{
  proxy_map_ent_t *node;
  char tmp[64];
  uint32_t xip;
  unsigned int xport_u, proto_u;
  unsigned int b0, b1, b2, b3;

  if (!service_key || service_key[0] == '\0')
    return NULL;

  /* Parse "a.b.c.d:port:proto" — strict, no whitespace tolerated. */
  if (sscanf(service_key, "%u.%u.%u.%u:%u:%u",
             &b0, &b1, &b2, &b3, &xport_u, &proto_u) != 6)
    return NULL;
  if (b0 > 255 || b1 > 255 || b2 > 255 || b3 > 255 ||
      xport_u > 0xFFFF || proto_u > 0xFF)
    return NULL;
  xip = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;

  /* PROXY_RDLOCK is the macro the sockproxy.c head walks use; defined in
   * sockproxy.c. We avoid pulling that macro here to keep the test build
   * link-free of the production singleton — fall back to direct rwlock. */
  pthread_rwlock_rdlock(&proxy_struct->lock);
  node = proxy_struct->head;
  while (node) {
    if (node->key.xip == xip &&
        node->key.xport == (uint16_t)xport_u &&
        node->key.protocol == (uint8_t)proto_u) {
      pthread_rwlock_unlock(&proxy_struct->lock);
      /* Stringify "tmp" only to silence unused-variable warning; the lookup
       * by parsed (xip, xport, proto) is the authoritative result. */
      (void)snprintf(tmp, sizeof(tmp), "%u.%u.%u.%u", b0, b1, b2, b3);
      return node;
    }
    node = node->next;
  }
  pthread_rwlock_unlock(&proxy_struct->lock);
  return NULL;
}

/* Pick the P/D-enabled proxy_epval_t for the service. only syncs
 * P/D-enabled or session-stickiness-enabled services; non-P/D services have
 * no per-EP session table to sync. */
static proxy_epval_t *
pick_tepval_for_sync(proxy_map_ent_t *ent)
{
  proxy_epval_t *tepval = NULL, *tv_tmp;

  if (!ent)
    return NULL;

  HASH_ITER(hh, ent->val.ephash, tepval, tv_tmp) {
    if (tepval->pd_disagg_enabled ||
        tepval->n_eps > 0)
      return tepval;
  }
  return NULL;
}

/*
 * apply_conv_sync_entry — install one remote conversation_mapping entry into
 * ent->val.conv_map ( synced state #2). The pd_session apply below
 * targets pd_session_map; this targets conv_map. Disambiguation between the
 * two synced tables is by field convention — ev->ep_idx >= 0 with
 * prefill/decode == -1 means a conversation_mapping row — exactly as
 * xsync.proto documents, because the Go ApplyOne() collapses the wire kind to
 * SESSION_UPDATE/DELETE and so kind alone cannot distinguish them.
 *
 * Lock: conv_lock (Pri-3) taken alone. proxy_struct->lock (Pri-1) was already
 * released inside proxy_lookup_service_by_key, so no ordering violation.
 *
 * SPEC A6 first-writer-wins by created_ts; DELETE removes unconditionally so a
 * stale local mapping cannot outlive a remote tombstone.
 */
static int
apply_conv_sync_entry(proxy_map_ent_t *ent, proxy_epval_t *tepval,
                      const proxy_sync_event_t *ev)
{
  conversation_mapping_t *m = NULL;
  int outcome = SYNC_APPLY_ERROR;
  int is_delete = (ev->kind == SYNC_SESSION_DELETE || ev->kind == SYNC_CONV_DELETE);

  /* HEALTH GATE (SPEC A5) — installs only; a DELETE must always apply. */
  if (!is_delete && ev->ep_idx >= 0 && !is_endpoint_healthy(tepval, ev->ep_idx))
    return SYNC_APPLY_HEALTH_REJECT;

  pthread_rwlock_wrlock(&ent->val.conv_lock);

  HASH_FIND_STR(ent->val.conv_map, ev->conv_id, m);

  if (is_delete) {
    if (m) {
      HASH_DEL(ent->val.conv_map, m);
      free(m);
    }
    outcome = SYNC_APPLY_INSTALLED;
    goto unlock_and_done;
  }

  if (!m) {
    /* No local entry → install remote. */
    m = calloc(1, sizeof(*m));
    if (!m) {
      outcome = SYNC_APPLY_ERROR;
      goto unlock_and_done;
    }
    strncpy(m->conv_id, ev->conv_id, MAX_CONV_ID_LEN - 1);
    m->conv_id[MAX_CONV_ID_LEN - 1] = '\0';
    m->ep_idx         = ev->ep_idx;
    m->created_ts     = ev->created_ts;
    m->last_access_ts = ev->last_access_ts;
    m->request_count  = ev->request_count;
    HASH_ADD_STR(ent->val.conv_map, conv_id, m);
    outcome = SYNC_APPLY_INSTALLED;
    log_info("[XSYNC_CONV_APPLY] INSTALLED conv_id='%s' ep_idx=%d svc=%s",
             ev->conv_id, ev->ep_idx, ev->service_key);
    goto unlock_and_done;
  }

  /* Local entry exists → SPEC A6 first-writer-wins by created_ts. */
  if (m->created_ts == ev->created_ts) {
    outcome = SYNC_APPLY_TIE_LOCAL_KEPT;
    goto unlock_and_done;
  }
  if (m->created_ts < ev->created_ts) {
    outcome = SYNC_APPLY_LOCAL_KEPT;
    goto unlock_and_done;
  }
  /* m->created_ts > ev->created_ts → remote is older, remote wins. */
  m->ep_idx         = ev->ep_idx;
  m->created_ts     = ev->created_ts;
  m->last_access_ts = ev->last_access_ts;
  m->request_count  = ev->request_count;
  outcome = SYNC_APPLY_INSTALLED;

unlock_and_done:
  pthread_rwlock_unlock(&ent->val.conv_lock);
  return outcome;
}

/*
 * proxy_sync_apply_session_entry — install one remote SockproxySessionEntry.
 *
 * Step 0: input validation (ev pointer, conv_id non-empty).
 * Step 1: resolve service_key → proxy_map_ent_t.
 * Step 2: resolve proxy_epval_t inside the entry.
 * Step 3 (HEALTH GATE — SPEC A5, RESEARCH §5): for every ep_idx that the
 *        event references AND that is in-range, call is_endpoint_healthy().
 *        If ANY referenced EP is locally unhealthy, increment health-reject
 *        counter (Go-side, via outcome=SYNC_APPLY_HEALTH_REJECT) and return.
 *        This is the LAST step BEFORE wrlock acquire so the lock isn't held
 *        on a probable-reject path AND the EP health can't flip during the
 *        wait window.
 * Step 4: acquire pd_session_lock (Pri-4) — Pri-5 pd_trie_lock is NOT taken
 *        here (the sync path doesn't touch the trie; the trie is rebuilt
 *        lazily from session traffic). Lock order preserved.
 * Step 5: first-writer-wins by ev->created_ts (SPEC A6):
 *           - no local entry          → insert remote (SYNC_APPLY_INSTALLED)
 *           - local.created_ts >  ev  → replace local with remote (SYNC_APPLY_INSTALLED)
 *           - local.created_ts <  ev  → keep local (SYNC_APPLY_LOCAL_KEPT)
 *           - local.created_ts == ev  → keep local (SYNC_APPLY_TIE_LOCAL_KEPT)
 *         For the DELETE kind (ev->kind == SYNC_SESSION_DELETE), the local
 *         entry is removed unconditionally if present.
 * Step 6: release wrlock.
 *
 * Returns one of the SYNC_APPLY_* outcome codes for Go-side metric labelling.
 */
int
proxy_sync_apply_session_entry(const proxy_sync_event_t *ev)
{
  proxy_map_ent_t *ent;
  proxy_epval_t   *tepval;
  pd_session_mapping_t *m = NULL;
  int               outcome = SYNC_APPLY_ERROR;

  if (!ev || ev->conv_id[0] == '\0' || ev->service_key[0] == '\0')
    return SYNC_APPLY_ERROR;

  ent = proxy_lookup_service_by_key(ev->service_key);
  if (!ent)
    return SYNC_APPLY_ERROR;

  tepval = pick_tepval_for_sync(ent);
  if (!tepval)
    return SYNC_APPLY_ERROR;

  /* route conversation_mapping rows (ep_idx set, prefill/decode
   * == -1) to ent->val.conv_map; pd_session rows (prefill/decode set, ep_idx
   * == -1) fall through to the pd_session_map path below. Without this the
   * receiver dropped every conversation entry into pd_session_map and left
   * conv_map empty, so X-Conversation-Id stickiness never survived failover. */
  if (ev->ep_idx >= 0 && ev->prefill_ep_idx < 0 && ev->decode_ep_idx < 0)
    return apply_conv_sync_entry(ent, tepval, ev);

  /* HEALTH GATE — SPEC A5. LAST step before wrlock acquire. */
  if (ev->prefill_ep_idx >= 0 &&
      !is_endpoint_healthy(tepval, ev->prefill_ep_idx))
    return SYNC_APPLY_HEALTH_REJECT;
  if (ev->decode_ep_idx >= 0 &&
      !is_endpoint_healthy(tepval, ev->decode_ep_idx))
    return SYNC_APPLY_HEALTH_REJECT;
  if (ev->ep_idx >= 0 &&
      !is_endpoint_healthy(tepval, ev->ep_idx))
    return SYNC_APPLY_HEALTH_REJECT;

  pthread_rwlock_wrlock(&tepval->pd_session_lock);

  HASH_FIND_STR(tepval->pd_session_map, ev->conv_id, m);

  if (ev->kind == SYNC_SESSION_DELETE) {
    if (m) {
      HASH_DEL(tepval->pd_session_map, m);
      free(m);
    }
    outcome = SYNC_APPLY_INSTALLED;
    goto unlock_and_done;
  }

  if (!m) {
    /* No local entry → install remote. */
    m = calloc(1, sizeof(*m));
    if (!m) {
      outcome = SYNC_APPLY_ERROR;
      goto unlock_and_done;
    }
    strncpy(m->conv_id, ev->conv_id, MAX_CONV_ID_LEN - 1);
    m->conv_id[MAX_CONV_ID_LEN - 1] = '\0';
    m->prefill_ep_idx = ev->prefill_ep_idx;
    m->decode_ep_idx  = ev->decode_ep_idx;
    m->created_ts     = ev->created_ts;
    atomic_store(&m->last_access_ts, ev->last_access_ts);
    m->request_count  = ev->request_count;
    HASH_ADD_STR(tepval->pd_session_map, conv_id, m);
    outcome = SYNC_APPLY_INSTALLED;
    goto unlock_and_done;
  }

  /* Local entry exists → SPEC A6 first-writer-wins by created_ts. */
  if (m->created_ts == ev->created_ts) {
    outcome = SYNC_APPLY_TIE_LOCAL_KEPT;
    goto unlock_and_done;
  }
  if (m->created_ts < ev->created_ts) {
    outcome = SYNC_APPLY_LOCAL_KEPT;
    goto unlock_and_done;
  }
  /* m->created_ts > ev->created_ts → remote is older, remote wins. */
  m->prefill_ep_idx = ev->prefill_ep_idx;
  m->decode_ep_idx  = ev->decode_ep_idx;
  m->created_ts     = ev->created_ts;
  atomic_store(&m->last_access_ts, ev->last_access_ts);
  m->request_count  = ev->request_count;
  outcome = SYNC_APPLY_INSTALLED;

unlock_and_done:
  pthread_rwlock_unlock(&tepval->pd_session_lock);
  return outcome;
}

/*
 * sockproxy_snapshot_pd_sessions — dump all P/D sessions for one tepval.
 *
 * Caller-owned out_array: on success, *out_array is a calloc()'d buffer
 * the caller MUST free(). Holds rdlock briefly during memcpy; safe even
 * for large session tables (~80μs per 1K entries).
 *
 * Returns 0 on success, -1 on input error or allocation failure.
 */
int
sockproxy_snapshot_pd_sessions(proxy_epval_t *tepval,
                               pd_session_mapping_t **out_array,
                               uint32_t *out_count)
{
  pd_session_mapping_t *iter, *tmp;
  uint32_t              count;
  uint32_t              i = 0;

  if (!tepval || !out_array || !out_count)
    return -1;

  *out_array = NULL;
  *out_count = 0;

  pthread_rwlock_rdlock(&tepval->pd_session_lock);

  count = HASH_COUNT(tepval->pd_session_map);
  if (count == 0) {
    pthread_rwlock_unlock(&tepval->pd_session_lock);
    return 0;
  }

  *out_array = calloc(count, sizeof(pd_session_mapping_t));
  if (!*out_array) {
    pthread_rwlock_unlock(&tepval->pd_session_lock);
    return -1;
  }

  HASH_ITER(hh, tepval->pd_session_map, iter, tmp) {
    if (i >= count) break;  /* defensive — table mutated under rdlock would be a bug */
    memcpy(&(*out_array)[i], iter, sizeof(pd_session_mapping_t));
    /* hh field is meaningless in the copy; receiver must not use it. */
    memset(&(*out_array)[i].hh, 0, sizeof((*out_array)[i].hh));
    i++;
  }

  pthread_rwlock_unlock(&tepval->pd_session_lock);
  *out_count = i;
  return 0;
}

/*
 * sockproxy_snapshot_conv_sessions — dump all X-Conversation-Id mappings for
 * one proxy_map_ent's conv_map under rdlock (mirrors sockproxy_snapshot_pd_sessions).
 *
 * Caller-owned out_array: on success, *out_array is a calloc()'d buffer the
 * caller MUST free(). Holds conv_lock rdlock briefly during memcpy.
 *
 * Returns 0 on success, -1 on input error or allocation failure.
 */
int
sockproxy_snapshot_conv_sessions(proxy_map_ent_t *ent,
                                 conversation_mapping_t **out_array,
                                 uint32_t *out_count)
{
  conversation_mapping_t *iter, *tmp;
  uint32_t                count;
  uint32_t                i = 0;

  if (!ent || !out_array || !out_count)
    return -1;

  *out_array = NULL;
  *out_count = 0;

  pthread_rwlock_rdlock(&ent->val.conv_lock);

  count = HASH_COUNT(ent->val.conv_map);
  if (count == 0) {
    pthread_rwlock_unlock(&ent->val.conv_lock);
    return 0;
  }

  *out_array = calloc(count, sizeof(conversation_mapping_t));
  if (!*out_array) {
    pthread_rwlock_unlock(&ent->val.conv_lock);
    return -1;
  }

  HASH_ITER(hh, ent->val.conv_map, iter, tmp) {
    if (i >= count) break;
    memcpy(&(*out_array)[i], iter, sizeof(conversation_mapping_t));
    memset(&(*out_array)[i].hh, 0, sizeof((*out_array)[i].hh));
    i++;
  }

  pthread_rwlock_unlock(&ent->val.conv_lock);
  *out_count = i;
  return 0;
}

/*
 * sockproxy_snapshot_all_sessions — walk every service in proxy_struct->head
 * and collect all conv_map and pd_session_map entries into a flat
 * proxy_sync_event_t array suitable for SockproxySessionBulkGet pagination.
 *
 * On success *out_events is a calloc()'d array of *out_count entries — the
 * caller must free() it.  Each conv entry has kind=SYNC_CONV_CREATE and
 * ep_idx set; each P/D entry has kind=SYNC_SESSION_CREATE and
 * prefill_ep_idx / decode_ep_idx set.  service_key is populated from the
 * service's (xip, xport, protocol) triple.
 *
 * This is the cold-start BulkGet back-end (-L). It intentionally
 * snapshots under per-map rdlocks (not a global freeze) to keep latency
 * bounded; the receiver already applies first-writer-wins conflict
 * resolution (SPEC A6), so a small race window is acceptable.
 *
 * Returns 0 on success, -1 on fatal allocation failure.
 */
int
sockproxy_snapshot_all_sessions(proxy_sync_event_t **out_events,
                                uint32_t            *out_count)
{
  proxy_map_ent_t         *node;
  proxy_epval_t           *tepval, *tv_tmp;
  conversation_mapping_t  *conv_arr  = NULL;
  pd_session_mapping_t    *pd_arr    = NULL;
  uint32_t                 conv_n    = 0, pd_n = 0;
  uint32_t                 total     = 0, cap = 256, used = 0;
  proxy_sync_event_t      *evs;
  char                     svckey[64];
  uint32_t                 i;

  if (!out_events || !out_count)
    return -1;

  *out_events = NULL;
  *out_count  = 0;

  evs = calloc(cap, sizeof(proxy_sync_event_t));
  if (!evs)
    return -1;

  /* First pass: tally total entries so we can realloc once if needed. */
  pthread_rwlock_rdlock(&proxy_struct->lock);
  node = proxy_struct->head;
  while (node) {
    total += HASH_COUNT(node->val.conv_map);
    HASH_ITER(hh, node->val.ephash, tepval, tv_tmp) {
      total += HASH_COUNT(tepval->pd_session_map);
    }
    node = node->next;
  }
  pthread_rwlock_unlock(&proxy_struct->lock);

  if (total == 0) {
    free(evs);
    return 0;
  }
  if (total > cap) {
    proxy_sync_event_t *tmp2 = realloc(evs, total * sizeof(proxy_sync_event_t));
    if (!tmp2) { free(evs); return -1; }
    evs = tmp2;
    cap = total;
  }

  /* Second pass: snapshot under per-map locks. */
  pthread_rwlock_rdlock(&proxy_struct->lock);
  node = proxy_struct->head;
  while (node) {
    /* Build service_key string "a.b.c.d:port:proto". */
    uint32_t xip  = node->key.xip;
    snprintf(svckey, sizeof(svckey), "%u.%u.%u.%u:%u:%u",
             (xip >> 24) & 0xFF, (xip >> 16) & 0xFF,
             (xip >> 8)  & 0xFF,  xip        & 0xFF,
             (unsigned)node->key.xport,
             (unsigned)node->key.protocol);

    /* conv_map entries */
    conv_arr = NULL; conv_n = 0;
    sockproxy_snapshot_conv_sessions(node, &conv_arr, &conv_n);
    for (i = 0; i < conv_n && used < cap; i++, used++) {
      proxy_sync_event_t *ev = &evs[used];
      ev->kind           = SYNC_CONV_CREATE;
      strncpy(ev->service_key, svckey, sizeof(ev->service_key) - 1);
      strncpy(ev->conv_id,     conv_arr[i].conv_id, MAX_CONV_ID_LEN - 1);
      ev->ep_idx         = conv_arr[i].ep_idx;
      ev->prefill_ep_idx = -1;
      ev->decode_ep_idx  = -1;
      ev->created_ts     = conv_arr[i].created_ts;
      ev->last_access_ts = conv_arr[i].last_access_ts;
      ev->request_count  = conv_arr[i].request_count;
    }
    free(conv_arr); conv_arr = NULL;

    /* pd_session_map entries */
    HASH_ITER(hh, node->val.ephash, tepval, tv_tmp) {
      pd_arr = NULL; pd_n = 0;
      sockproxy_snapshot_pd_sessions(tepval, &pd_arr, &pd_n);
      for (i = 0; i < pd_n && used < cap; i++, used++) {
        proxy_sync_event_t *ev = &evs[used];
        ev->kind           = SYNC_SESSION_CREATE;
        strncpy(ev->service_key, svckey, sizeof(ev->service_key) - 1);
        strncpy(ev->conv_id,     pd_arr[i].conv_id, MAX_CONV_ID_LEN - 1);
        ev->ep_idx         = -1;
        ev->prefill_ep_idx = pd_arr[i].prefill_ep_idx;
        ev->decode_ep_idx  = pd_arr[i].decode_ep_idx;
        ev->created_ts     = pd_arr[i].created_ts;
        ev->last_access_ts = (uint64_t)atomic_load(&pd_arr[i].last_access_ts);
        ev->request_count  = pd_arr[i].request_count;
      }
      free(pd_arr); pd_arr = NULL;
    }

    node = node->next;
  }
  pthread_rwlock_unlock(&proxy_struct->lock);

  *out_events = evs;
  *out_count  = used;
  return 0;
}
