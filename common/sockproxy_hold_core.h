/*
 * Copyright (c) 2026 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */
#ifndef __SOCKPROXY_HOLD_CORE_H__
#define __SOCKPROXY_HOLD_CORE_H__

/*
 * Holding a half-closed client: the pure half.
 *
 * The decisions, with no connection entry, lock or clock in sight, so the
 * unit test (test_hold_core.c) can pin them. The stateful half and the hooks are in
 * sockproxy_hold.c.
 */

#include <stdint.h>

#include "notify.h"

/* The idle bound on a hold, process-wide: no progress towards the client for
 * this long ends it. The control plane sets it within these limits. */
#define SP_HOLD_CAP_DEFAULT_SEC 240
#define SP_HOLD_CAP_MIN_SEC     1
#define SP_HOLD_CAP_MAX_SEC     3600

/* A rule's half-close mode, as the control plane hands it over. Unset falls
 * back to the process default, which is off until a default can be set. */
enum sp_hold_mode {
  SP_HOLD_MODE_UNSET = 0,
  SP_HOLD_MODE_OFF,
  SP_HOLD_MODE_HOLD,        /* hold a client that half-closed after its request */
  SP_HOLD_MODE_MAX
};

/* Why a hold ended. The first reason recorded wins; a hold that ends with
 * none recorded is classified when its connection is released. */
enum sp_hold_end {
  SP_HOLD_END_NONE = 0,
  SP_HOLD_END_ANSWERED,      /* the owed answer went out in full */
  SP_HOLD_END_BACKEND_FIRST, /* the leg carrying the answer ended before it did */
  SP_HOLD_END_EXPIRED,       /* no progress towards the client for the bound */
  SP_HOLD_END_RELEASED,      /* an operator released the held connections */
  SP_HOLD_END_RESET,         /* the client reset while held: it was a cancel */
  SP_HOLD_END_OTHER,         /* torn down for some other reason */
  SP_HOLD_END_MAX
};

/* What the EOF handling knows about a client the moment it reads its FIN. */
struct sp_hold_in {
  uint8_t is_client;        /* odir == 0 */
  uint8_t held;             /* already held on EOF */
  uint8_t owed;             /* requests framed > responses framed to completion */
  uint8_t has_leg;          /* n_rfd > 0 && rfd_ent[0] && rfd_ent[0]->fd > 0 */
  uint8_t accel;            /* either history bit: the kernel was given a direction */
  uint8_t is_tls;           /* pfe->ssl, kTLS included */
  uint8_t mode_hold;        /* the rule's mode in force is hold */
  uint8_t allowed;          /* the process-wide switch allows new holds */
  uint8_t leg_peer_eof;     /* the backend leg is already closing behind a drain */
  uint8_t pending;          /* rcv_off != 0 || stream_body_remaining != 0 */
};

enum sp_hold_verdict {
  SP_HOLD_NO = 0,           /* not ours: the EOF handling goes on as today */
  SP_HOLD_YES,              /* hold it */
  SP_HOLD_REENTRY,          /* already held: the EOF came round again */
  SP_HOLD_REFUSE_RESIDUE,   /* would hold, but a pipelined request is still arriving */
};

/* The gate. TLS (kTLS too) and any history of a kernel-carried direction keep
 * today's behaviour: over TLS a half-close is almost always a close, and with
 * a direction in the kernel the owed count is not to be trusted. A pipelined
 * remainder is refused and counted rather than held, until its frequency says
 * whether to drop the condition. */
static inline enum sp_hold_verdict
sp_hold_decide(const struct sp_hold_in *in)
{
  if (!in->is_client) {
    return SP_HOLD_NO;
  }
  if (in->held) {
    return SP_HOLD_REENTRY;
  }
  if (!in->owed || !in->has_leg || in->accel || in->is_tls || !in->mode_hold ||
      !in->allowed || in->leg_peer_eof) {
    return SP_HOLD_NO;
  }
  if (in->pending) {
    return SP_HOLD_REFUSE_RESIDUE;
  }
  return SP_HOLD_YES;
}

/* Whether a held client can be closed now. Only once its relay cache is
 * empty: the bytes ahead of the end are still on their way otherwise. Then
 * either nothing is owed any more, or the leg that carried the answer has
 * ended and nothing more can come. */
static inline enum sp_hold_end
sp_hold_settle_decide(int cache_empty, int owed, int leg_ended)
{
  if (!cache_empty) {
    return SP_HOLD_END_NONE;
  }
  if (!owed) {
    return SP_HOLD_END_ANSWERED;
  }
  if (leg_ended) {
    return SP_HOLD_END_BACKEND_FIRST;
  }
  return SP_HOLD_END_NONE;
}

/* Whether the leg carrying the answer has ended, from the mark its end left:
 * the number of requests the client had framed by then, plus one (0: none).
 * A request framed since went to a leg that has not ended, so the mark is
 * then stale - no place that attaches a leg has to clear it. */
static inline int
sp_hold_leg_ended_now(uint32_t mark, uint32_t framed)
{
  return mark != 0 && mark == framed + 1;
}

/* The reason a hold ended, at release: the one recorded, else what the
 * counters say happened (a backend close with nothing left to drain releases
 * the client without passing a settle point). */
static inline enum sp_hold_end
sp_hold_end_at_release(enum sp_hold_end recorded, int owed, int leg_ended)
{
  if (recorded != SP_HOLD_END_NONE) {
    return recorded;
  }
  if (!owed) {
    return SP_HOLD_END_ANSWERED;
  }
  if (leg_ended) {
    return SP_HOLD_END_BACKEND_FIRST;
  }
  return SP_HOLD_END_OTHER;
}

/* The bound is on idleness towards the client, not on total time: a hold
 * expires when nothing has been written to the client for cap_ns since the
 * later of the request reaching the backend and the last successful write.
 * Until the request is known to have reached the backend, the clock starts at
 * the hold itself, so a hold whose request never leaves is still bounded.
 * A hold whose start reads 0 has not been seen to begin: never expired, or a
 * reader that caught it being set up would count its age from 0. */
static inline int
sp_hold_expired(uint64_t now_ns, uint64_t start_ns, uint64_t handoff_ns,
                uint64_t progress_ns, uint64_t cap_ns)
{
  uint64_t base = handoff_ns ? handoff_ns : start_ns;

  if (!start_ns) {
    return 0;
  }
  if (progress_ns > base) {
    base = progress_ns;
  }
  return now_ns > base && now_ns - base >= cap_ns;
}

/* The poll events a held client may be armed for: never the read events (IN,
 * and HUP, which asks for RDHUP) - its read side is at EOF and both report
 * level-triggered. 0 means disarm. */
static inline uint32_t
sp_hold_arm_type(uint32_t type, int held)
{
  if (held) {
    type &= ~(uint32_t)(NOTI_TYPE_IN | NOTI_TYPE_HUP);
  }
  return type;
}

/* The events a held client is dispatched for: never the reads (IN, RDHUP).
 * Arming it for OUT alone is not enough to keep it from being read: the
 * notifier core reports every OUT as IN as well, and a read would only meet
 * its EOF again. A reset or a full close still arrives as HUP or ERROR. */
static inline uint32_t
sp_hold_dispatch_type(uint32_t type, int held)
{
  if (held) {
    type &= ~(uint32_t)(NOTI_TYPE_IN | NOTI_TYPE_RDHUP);
  }
  return type;
}

#endif /* __SOCKPROXY_HOLD_CORE_H__ */
