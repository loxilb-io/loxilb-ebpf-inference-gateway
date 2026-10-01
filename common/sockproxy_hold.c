/*
 * Copyright (c) 2026 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 *
 * sockproxy_hold.c - holding a client that half-closed after its request.
 *
 * A client that writes its request and then shuts down its write side is
 * saying "that was my last request", not "forget the answer". Without a hold
 * the proxy cuts such a client at its FIN (or 50 ms later on a connection
 * whose response direction the kernel carries), and the answer is lost.
 *
 * A hold keeps the client's write side open until the answer is out. It is
 * taken only where the proxy can tell an answer is owed and can see every
 * byte of it: plaintext, the kernel never given a direction of the
 * connection, and the rule's mode set to hold with the process-wide switch
 * allowing it. Everything else keeps today's behaviour, byte for byte.
 *
 * Lifecycle
 *   begin    the EOF handling reads the FIN of a client that owes an answer
 *            (sp_hold_eof): read side shut, fd disarmed for reads.
 *   settle   after a write to the client that leaves its relay cache empty
 *            (the relay's direct send, the cache drain), close once nothing
 *            is owed, or once the leg carrying the answer has ended.
 *   expire   the 1 Hz health pass closes a hold with no progress towards the
 *            client for the bound (an idle bound, not a total one).
 *   release  an operator can close every held connection at the next pass.
 *   end      the connection's shell is recycled: the hold is counted, by the
 *            first reason recorded.
 *
 * Every close is a SHUT_RDWR, so the connection goes through the normal
 * teardown and gives back what it holds (capacity units included).
 */
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <time.h>

/* uthash precedes sockproxy.h (UT_hash_handle) */
#include "uthash.h"
#include "log.h"
#include "sockproxy_internal.h"
#include "sockproxy_metrics.h"
#include "sockproxy_hc_core.h"
#include "sockproxy_hold_core.h"
#include "sockproxy_hold.h"

/* Process-wide settings, written by the control plane. A new hold needs the
 * switch on; turning it off stops new holds and leaves the held ones to finish
 * (the release action is what ends those). */
static _Atomic uint32_t hold_allowed = 1;
static _Atomic uint32_t hold_cap_sec = SP_HOLD_CAP_DEFAULT_SEC;
static _Atomic uint32_t hold_release_req;

static struct {
  _Atomic uint64_t held;                        /* gauge: holds open now */
  _Atomic uint64_t oldest_ms;                   /* gauge: age of the oldest, at the last pass */
  _Atomic uint64_t begun;
  _Atomic uint64_t ended[SP_HOLD_END_MAX];      /* by the reason recorded */
  _Atomic uint64_t expired[2][HC_STREAM_MAX];   /* [answer had begun][stream] */
  _Atomic uint64_t refused_residue;             /* would hold, a pipelined request was arriving */
  _Atomic uint64_t reentry;                     /* the EOF handling ran again on a held client */
  _Atomic uint64_t empty_out;                   /* a held client woke for OUT with nothing to send */
  _Atomic uint64_t accel_skipped;               /* pairing skipped: the client had already sent FIN */
} hold_stats;

static inline void
hold_inc(_Atomic uint64_t *c)
{
  atomic_fetch_add_explicit(c, 1, memory_order_relaxed);
}

static uint64_t
hold_now_ns(void)
{
  struct timespec ts;

  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static int
hold_owed(proxy_fd_ent_t *c)
{
  return atomic_load_explicit(&c->cresp_forwarded, memory_order_relaxed) >
         atomic_load_explicit(&c->cresp_completed, memory_order_relaxed);
}

/* Records why the hold ended; the first reason wins. Returns 1 if this call
 * recorded it. */
static int
hold_record_end(proxy_fd_ent_t *c, enum sp_hold_end e)
{
  uint8_t none = SP_HOLD_END_NONE;

  return atomic_compare_exchange_strong_explicit(&c->hold_end, &none, (uint8_t)e,
                                                 memory_order_relaxed,
                                                 memory_order_relaxed);
}

int
sp_eof_held(const proxy_fd_ent_t *pfe)
{
  return pfe && pfe->odir == 0 && pfe->eof_hold;
}

int
sp_notify_arm(void *ns, int fd, notify_type_t type, proxy_fd_ent_t *pfe, uint64_t gen)
{
  if (sp_eof_held(pfe)) {
    type = (notify_type_t)sp_hold_arm_type(type, 1);
    if (!type) {
      return notify_disarm_ent(ns, fd);
    }
  }
  /* The one direct arming call: the source invariant check allows it here
   * and nowhere else. */
  return notify_add_ent(ns, fd, type, pfe, gen);
}

/* ---- begin ---------------------------------------------------------------- */

int
sp_hold_eof(proxy_fd_ent_t *pfe)
{
  struct sp_hold_in in;
  proxy_fd_ent_t *be;
  proxy_epval_t *epv;
  uint64_t now;

  if (!pfe || pfe->odir != 0) {
    return 0;
  }
  memset(&in, 0, sizeof(in));
  be = pfe->n_rfd > 0 ? pfe->rfd_ent[0] : NULL;
  epv = (proxy_epval_t *)pfe->epv;
  in.is_client = 1;
  in.held = pfe->eof_hold;
  in.owed = hold_owed(pfe);
  in.has_leg = be && be->fd > 0;
  in.accel = atomic_load_explicit(&pfe->hc_accel, memory_order_relaxed) != 0;
  in.is_tls = pfe->ssl != NULL;
  in.mode_hold = epv && epv->hold_mode == SP_HOLD_MODE_HOLD;
  in.allowed = atomic_load_explicit(&hold_allowed, memory_order_relaxed) != 0;
  in.leg_peer_eof = be && be->peer_eof;
  in.pending = pfe->rcv_off != 0 || pfe->stream_body_remaining != 0;

  switch (sp_hold_decide(&in)) {
  case SP_HOLD_REENTRY:
    /* The fd is disarmed for reads while held and the dispatch drops them,
     * so this should not happen: a count above zero is a read path the two
     * did not cover. */
    hold_inc(&hold_stats.reentry);
    return 1;
  case SP_HOLD_REFUSE_RESIDUE:
    hold_inc(&hold_stats.refused_residue);
    return 0;
  case SP_HOLD_NO:
    return 0;
  case SP_HOLD_YES:
    break;
  }

  now = hold_now_ns();
  PROXY_ENT_LOCK(pfe);
  pfe->eof_hold = 1;
  pfe->hold_start_ns = now;
  /* An answer already under way when the FIN came (the client half-closed
   * after the first bytes) is progress from the start. */
  pfe->hold_answer_began = pfe->cresp_answer_open;
  pfe->hold_progress_ns = 0;
  /* With nothing left in the backend's cache the request has reached the
   * backend already; otherwise the cache drain says when it does. */
  atomic_store_explicit(&pfe->hold_handoff_ns,
                        (be->cache_head == NULL && !be->cache_draining) ? now : 0,
                        memory_order_relaxed);
  /* We will not read from this client again; its write side stays open for
   * the answer. Armed for OUT only while something is waiting to be written. */
  shutdown(pfe->fd, SHUT_RD);
  sp_notify_arm(proxy_struct->ns, pfe->fd,
                NOTI_TYPE_IN | NOTI_TYPE_HUP | (pfe->cache_head ? NOTI_TYPE_OUT : 0),
                pfe, pfe->gen);
  PROXY_ENT_UNLOCK(pfe);

  hold_inc(&hold_stats.begun);
  hold_inc(&hold_stats.held);
  log_debug("[HOLD] fd=%d: client half-closed with an answer owed "
            "(forwarded=%u completed=%u); keeping its write side open",
            pfe->fd,
            atomic_load_explicit(&pfe->cresp_forwarded, memory_order_relaxed),
            atomic_load_explicit(&pfe->cresp_completed, memory_order_relaxed));
  return 1;
}

/* ---- the answer ------------------------------------------------------------ */

void
sp_hold_answer_began(proxy_fd_ent_t *c)
{
  c->cresp_answer_open = 1;
  if (c->eof_hold) {
    c->hold_answer_began = 1;
  }
}

void
sp_hold_answer_ended(proxy_fd_ent_t *c)
{
  c->cresp_answer_open = 0;
}

void
sp_hold_progress(proxy_fd_ent_t *dst)
{
  /* Interim responses (100 Continue, 103) are not progress: only writes once
   * an answer has begun count. */
  if (sp_eof_held(dst) && dst->hold_answer_began) {
    dst->hold_progress_ns = hold_now_ns();
  }
}

void
sp_hold_handoff(proxy_fd_ent_t *be)
{
  proxy_fd_ent_t *c;

  /* The backend's cache has just emptied: whatever of the request it held
   * has gone to the backend. Called with the backend entry locked; a client's
   * teardown takes that lock to unlink, so the link is stable here. */
  if (!be || be->odir != 1 || be->n_rfd <= 0) {
    return;
  }
  c = be->rfd_ent[0];
  if (sp_eof_held(c)) {
    atomic_store_explicit(&c->hold_handoff_ns, hold_now_ns(), memory_order_relaxed);
  }
}

void
sp_hold_leg_ended(proxy_fd_ent_t *c)
{
  /* Recorded whether or not the client is held yet: a leg that ended
   * mid-answer before the FIN was read still means nothing more will come.
   * It describes the current leg: attaching another clears it. */
  if (c && c->odir == 0) {
    atomic_store_explicit(&c->hold_leg_ended, 1, memory_order_relaxed);
  }
}

void
sp_hold_leg_attached(proxy_fd_ent_t *c)
{
  if (c && c->odir == 0) {
    atomic_store_explicit(&c->hold_leg_ended, 0, memory_order_relaxed);
  }
}

/* ---- settle ---------------------------------------------------------------- */

int
sp_hold_settle(proxy_fd_ent_t *c)
{
  enum sp_hold_end e;

  if (!sp_eof_held(c)) {
    return 0;
  }
  e = sp_hold_settle_decide(c->cache_head == NULL && !c->cache_draining, hold_owed(c),
                            atomic_load_explicit(&c->hold_leg_ended, memory_order_relaxed));
  if (e == SP_HOLD_END_NONE) {
    return 0;
  }
  hold_record_end(c, e);
  log_debug("[HOLD] fd=%d: %s, closing", c->fd,
            e == SP_HOLD_END_ANSWERED ? "answer delivered" : "answer's leg ended first");
  return 1;
}

/* ---- the client goes away -------------------------------------------------- */

void
sp_hold_peer_error(proxy_fd_ent_t *c, int err)
{
  /* A held client is in CLOSE_WAIT (its FIN is in), so a reset it sends is
   * reported as EPIPE, not ECONNRESET. Only while no reason is recorded: once
   * the proxy decided to close and shut the write side, its own later writes
   * fail with EPIPE too, and those are not the client's. */
  if (err == EPIPE && sp_eof_held(c)) {
    hold_record_end(c, SP_HOLD_END_RESET);
  }
}

void
sp_hold_out_wake(proxy_fd_ent_t *c)
{
  if (sp_eof_held(c) && c->cache_head == NULL) {
    hold_inc(&hold_stats.empty_out);
  }
}

void
sp_hold_retire(proxy_fd_ent_t *pfe)
{
  enum sp_hold_end e;

  if (!pfe || !pfe->eof_hold) {
    return;
  }
  e = sp_hold_end_at_release(
      (enum sp_hold_end)atomic_load_explicit(&pfe->hold_end, memory_order_relaxed),
      hold_owed(pfe), atomic_load_explicit(&pfe->hold_leg_ended, memory_order_relaxed));
  hold_inc(&hold_stats.ended[e < SP_HOLD_END_MAX ? e : SP_HOLD_END_OTHER]);
  if (atomic_load_explicit(&hold_stats.held, memory_order_relaxed) > 0) {
    atomic_fetch_sub_explicit(&hold_stats.held, 1, memory_order_relaxed);
  }
  pfe->eof_hold = 0;
}

/* ---- the 1 Hz pass --------------------------------------------------------- */

int
sp_hold_sweep_due(void)
{
  return atomic_load_explicit(&hold_stats.held, memory_order_relaxed) > 0 ||
         atomic_load_explicit(&hold_release_req, memory_order_relaxed) != 0;
}

static void
hold_close(proxy_fd_ent_t *c)
{
  /* One load of the leg pointer, as the deferred-close pass does: a worker's
   * teardown clears it holding no lock this pass shares. */
  proxy_fd_ent_t *leg0 = __atomic_load_n(&c->rfd_ent[0], __ATOMIC_ACQUIRE);

  if (c->fd > 0) {
    shutdown(c->fd, SHUT_RDWR);
  }
  if (c->n_rfd > 0 && leg0 && leg0->fd > 0) {
    shutdown(leg0->fd, SHUT_RDWR);
  }
}

void
sp_hold_sweep(void)
{
  proxy_map_ent_t *node;
  proxy_fd_ent_t *pfe;
  uint64_t now = hold_now_ns();
  uint64_t cap = (uint64_t)atomic_load_explicit(&hold_cap_sec, memory_order_relaxed) *
                 1000000000ull;
  uint64_t oldest = 0;
  int release = atomic_exchange_explicit(&hold_release_req, 0, memory_order_relaxed) != 0;

  /* Called with PROXY_LOCK held. */
  for (node = proxy_struct->head; node; node = node->next) {
    for (pfe = node->val.fdlist; pfe; pfe = pfe->next) {
      if (!sp_eof_held(pfe)) {
        continue;
      }
      if (release) {
        if (hold_record_end(pfe, SP_HOLD_END_RELEASED)) {
          log_info("[HOLD] fd=%d: released by the operator, closing", pfe->fd);
          hold_close(pfe);
        }
        continue;
      }
      if (sp_hold_expired(now, pfe->hold_start_ns,
                          atomic_load_explicit(&pfe->hold_handoff_ns, memory_order_relaxed),
                          pfe->hold_progress_ns, cap)) {
        if (hold_record_end(pfe, SP_HOLD_END_EXPIRED)) {
          int st = pfe->hc_stream < HC_STREAM_MAX ? pfe->hc_stream : HC_STREAM_UNKNOWN;

          hold_inc(&hold_stats.expired[pfe->hold_answer_began ? 1 : 0][st]);
          log_info("[HOLD] fd=%d: no progress towards the client for %u s (answer %s), "
                   "closing", pfe->fd, (unsigned)(cap / 1000000000ull),
                   pfe->hold_answer_began ? "started" : "not started");
          hold_close(pfe);
        }
        continue;
      }
      if (now > pfe->hold_start_ns && now - pfe->hold_start_ns > oldest) {
        oldest = now - pfe->hold_start_ns;
      }
    }
  }
  atomic_store_explicit(&hold_stats.oldest_ms, oldest / 1000000ull, memory_order_relaxed);
}

/* ---- pairing -------------------------------------------------------------- */

int
sp_hold_pairing_allowed(proxy_fd_ent_t *client, proxy_epval_t *epv)
{
  struct tcp_info ti;
  socklen_t len = sizeof(ti);

  /* Only where a hold could be taken: elsewhere the pairing keeps today's
   * behaviour. */
  if (!client || client->fd <= 0 || !epv || epv->hold_mode != SP_HOLD_MODE_HOLD ||
      !atomic_load_explicit(&hold_allowed, memory_order_relaxed)) {
    return 1;
  }
  memset(&ti, 0, sizeof(ti));
  if (getsockopt(client->fd, IPPROTO_TCP, TCP_INFO, &ti, &len) != 0) {
    return 1;
  }
  if (ti.tcpi_state == TCP_ESTABLISHED) {
    return 1;
  }
  /* The client has sent its FIN (CLOSE_WAIT): installing the pair now would
   * take the connection out of the hold's reach, and the kernel would carry
   * an answer to a client the proxy can no longer follow. */
  hold_inc(&hold_stats.accel_skipped);
  log_debug("[HOLD] client fd=%d already sent its FIN (tcp state %u): not pairing",
            client->fd, (unsigned)ti.tcpi_state);
  return 0;
}

/* ---- control and export ---------------------------------------------------- */

void
proxy_update_halfclose_config(int allow, uint32_t cap_sec)
{
  if (cap_sec < SP_HOLD_CAP_MIN_SEC) {
    cap_sec = SP_HOLD_CAP_MIN_SEC;
  } else if (cap_sec > SP_HOLD_CAP_MAX_SEC) {
    cap_sec = SP_HOLD_CAP_MAX_SEC;
  }
  atomic_store_explicit(&hold_allowed, allow ? 1 : 0, memory_order_relaxed);
  atomic_store_explicit(&hold_cap_sec, cap_sec, memory_order_relaxed);
  log_info("[HOLD] half-close holds %s, bound %u s", allow ? "allowed" : "blocked", cap_sec);
}

void
proxy_halfclose_release(void)
{
  atomic_store_explicit(&hold_release_req, 1, memory_order_relaxed);
  log_info("[HOLD] release requested: held connections close at the next pass");
}

#define HOLD_COPY(dst, src, n)                                             \
  do {                                                                     \
    const _Atomic uint64_t *s_ = (const _Atomic uint64_t *)(src);          \
    uint64_t *d_ = (uint64_t *)(dst);                                      \
    for (size_t i_ = 0; i_ < (n); i_++) {                                  \
      d_[i_] = atomic_load_explicit(&s_[i_], memory_order_relaxed);        \
    }                                                                      \
  } while (0)

void
sp_hold_metrics_fill(proxy_metrics_snapshot_t *s)
{
  s->hold_held = atomic_load_explicit(&hold_stats.held, memory_order_relaxed);
  s->hold_oldest_ms = atomic_load_explicit(&hold_stats.oldest_ms, memory_order_relaxed);
  s->hold_begun = atomic_load_explicit(&hold_stats.begun, memory_order_relaxed);
  HOLD_COPY(s->hold_ended, hold_stats.ended, SP_HOLD_END_MAX);
  HOLD_COPY(s->hold_expired, hold_stats.expired, 2 * HC_STREAM_MAX);
  s->hold_refused_residue =
      atomic_load_explicit(&hold_stats.refused_residue, memory_order_relaxed);
  s->hold_reentry = atomic_load_explicit(&hold_stats.reentry, memory_order_relaxed);
  s->hold_empty_out = atomic_load_explicit(&hold_stats.empty_out, memory_order_relaxed);
  s->hold_accel_skipped =
      atomic_load_explicit(&hold_stats.accel_skipped, memory_order_relaxed);
  s->hold_allowed = atomic_load_explicit(&hold_allowed, memory_order_relaxed);
  s->hold_cap_sec = atomic_load_explicit(&hold_cap_sec, memory_order_relaxed);
}

_Static_assert(sizeof(((proxy_metrics_snapshot_t *)0)->hold_ended) ==
               sizeof(uint64_t) * SP_HOLD_END_MAX, "hold_ended");
_Static_assert(sizeof(((proxy_metrics_snapshot_t *)0)->hold_expired) ==
               sizeof(uint64_t) * 2 * HC_STREAM_MAX, "hold_expired");
