/*
 * SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-Clause)
 * Copyright (c) 2026 NetLOX Inc
 *
 * sockproxy_qos.h - L7 (Tier-1) byte shaper primitives for the sockproxy
 * fullproxy relay.
 *
 * A per-service token bucket meters PLAINTEXT payload bytes (post-SSL_read /
 * post-kTLS-decrypt) as they pass proxy_sock_read(). This is a different unit
 * from the eBPF (Tier-0) policer, which meters L3 wire bytes: the two differ
 * by TLS + TCP/IP framing overhead and must never be summed or compared.
 *
 * Concurrency contract: take/credit run on any of the notify worker threads
 * (inside the relay burst loop); refill runs from the notifier tick. All state
 * transitions are lock-free atomics — no mutex may sit on the relay hot path.
 * The parked-fd ring is the only locked structure, and it is touched solely
 * when a connection is throttled (off the hot path by definition).
 */

#ifndef __SOCKPROXY_QOS_H__
#define __SOCKPROXY_QOS_H__

#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>
#include <string.h>
#include <time.h>

/* Direction bits for qos_cfg.dir */
#define QOS_DIR_UPLOAD    0x1   /* client -> backend (request payload) */
#define QOS_DIR_DOWNLOAD  0x2   /* backend -> client (response payload) */

/* qos_cfg.mode */
#define QOS_MODE_OFF      0
#define QOS_MODE_SHAPE    1     /* pace: park the reader, resume on refill */
#define QOS_MODE_POLICE   2     /* reserved: drop instead of pace */

/* Below this many available bytes a grant is refused outright (the reader is
 * parked) instead of dribbling tiny reads through recv(); a grant smaller than
 * the caller's remaining want is still honoured at end-of-buffer. */
#define QOS_MIN_GRANT     2048

/* Default burst depth when no CBS is configured: 100ms worth of CIR, floored
 * so a single MTU-sized read can always proceed. */
#define QOS_CBS_MIN_BYTES 16384

/* Per-service shaper configuration (control-plane owned, applied under
 * PROXY_LOCK; readers see a consistent snapshot because updates re-init the
 * bucket before flipping cir_Bps, the enable gate). */
struct proxy_qos_cfg {
  uint64_t cir_Bps;      /* committed rate in BYTES/sec; 0 => shaper off */
  uint64_t pir_Bps;      /* peak rate in BYTES/sec; 0 => single-rate */
  uint32_t cbs_bytes;    /* burst depth in bytes; 0 => derived from CIR */
  uint8_t  dir;          /* QOS_DIR_* bitmask */
  uint8_t  mode;         /* QOS_MODE_* */
};

/* One parked (throttled) connection awaiting a refill wake. gen is the pfe
 * generation captured at park time — resume is gen-validated so a recycled
 * fd slot can never be woken by a stale park entry. */
struct qos_parked_fd {
  int      fd;
  int      owner_thr;
  uint64_t gen;
};

#define QOS_MAX_PARKED 256

/* Runtime bucket. Lives on the heap proxy_map_ent, NEVER on proxy_arg (the
 * 4096-byte eBPF map value). */
struct proxy_qos_bucket {
  _Atomic int64_t  tokens;         /* available bytes; may transiently exceed cbs by one refill quantum */
  _Atomic uint64_t last_refill_ns; /* CAS-claimed by the single active refiller per tick */

  /* observability counters */
  _Atomic uint64_t bytes_pass;
  _Atomic uint64_t bytes_delayed;  /* bytes that waited for >=1 park/resume cycle */
  _Atomic uint64_t parks;

  /* throttled connections waiting on refill (locked; off the hot path) */
  pthread_mutex_t park_lock;
  int n_parked;
  struct qos_parked_fd parked[QOS_MAX_PARKED];
};

static inline uint32_t
qos_effective_cbs(const struct proxy_qos_cfg *cfg)
{
  if (cfg->cbs_bytes) {
    return cfg->cbs_bytes;
  }
  uint64_t derived = cfg->cir_Bps / 10;   /* 100ms of CIR */
  if (derived < QOS_CBS_MIN_BYTES) {
    derived = QOS_CBS_MIN_BYTES;
  }
  if (derived > UINT32_MAX) {
    derived = UINT32_MAX;
  }
  return (uint32_t)derived;
}

static inline void
qos_bucket_init(struct proxy_qos_bucket *b, const struct proxy_qos_cfg *cfg,
                uint64_t now_ns)
{
  atomic_store(&b->tokens, (int64_t)qos_effective_cbs(cfg));
  atomic_store(&b->last_refill_ns, now_ns);
}

/* Grant up to `want` bytes. Returns 0 when the caller must park. Partial
 * grants below QOS_MIN_GRANT are refused unless they satisfy the full want
 * (end-of-buffer reads stay cheap; everything else parks and batches). */
static inline uint64_t
qos_bucket_take(struct proxy_qos_bucket *b, uint64_t want)
{
  if (want == 0) {
    return 0;
  }
  int64_t cur = atomic_load_explicit(&b->tokens, memory_order_relaxed);
  for (;;) {
    if (cur <= 0) {
      return 0;
    }
    uint64_t grant = ((uint64_t)cur < want) ? (uint64_t)cur : want;
    if (grant < want && grant < QOS_MIN_GRANT) {
      return 0;
    }
    if (atomic_compare_exchange_weak_explicit(&b->tokens, &cur,
                                              cur - (int64_t)grant,
                                              memory_order_acq_rel,
                                              memory_order_relaxed)) {
      return grant;
    }
    /* cur reloaded by the failed CAS; retry */
  }
}

/* Return unused tokens (short read: granted > actually consumed). The clamp
 * to cbs is applied by the next refill; a transient overshoot here is bounded
 * by one grant and harmless. */
static inline void
qos_bucket_credit(struct proxy_qos_bucket *b, uint64_t unused_bytes)
{
  if (unused_bytes) {
    atomic_fetch_add_explicit(&b->tokens, (int64_t)unused_bytes,
                              memory_order_relaxed);
  }
}

/* Refill by elapsed wall time at rate_Bps, clamped to cbs. Exactly one caller
 * wins the CAS on last_refill_ns per quantum; losers no-op, so concurrent
 * ticks from several workers never double-refill. Returns 1 when tokens were
 * added (the caller should sweep this bucket's parked fds). */
static inline int
qos_bucket_refill(struct proxy_qos_bucket *b, uint64_t rate_Bps,
                  uint32_t cbs, uint64_t now_ns)
{
  uint64_t last = atomic_load_explicit(&b->last_refill_ns, memory_order_relaxed);
  if (now_ns <= last) {
    return 0;
  }
  uint64_t elapsed = now_ns - last;
  /* refuse sub-1ms refills: keeps the add above integer-truncation noise and
   * bounds the CAS traffic under many workers */
  if (elapsed < 1000000ULL) {
    return 0;
  }
  if (!atomic_compare_exchange_strong_explicit(&b->last_refill_ns, &last, now_ns,
                                               memory_order_acq_rel,
                                               memory_order_relaxed)) {
    return 0;   /* another worker owns this quantum */
  }
  /* cap the catch-up: an idle bucket refills to cbs, never beyond */
  uint64_t add = (rate_Bps * elapsed) / 1000000000ULL;
  if (add == 0) {
    return 0;
  }
  int64_t cur = atomic_fetch_add_explicit(&b->tokens, (int64_t)add,
                                          memory_order_acq_rel) + (int64_t)add;
  /* clamp via CAS, not a plain store: a store could resurrect tokens a
   * concurrent take consumed between the add and the clamp */
  while (cur > (int64_t)cbs) {
    if (atomic_compare_exchange_weak_explicit(&b->tokens, &cur, (int64_t)cbs,
                                              memory_order_acq_rel,
                                              memory_order_relaxed)) {
      break;
    }
  }
  return 1;
}

/* Idle-accounting guard arithmetic: slide a start-anchored wall-clock cap
 * (SSE stream start, P/D phase start) forward by the span a connection spent
 * QoS-parked, so shaper-paused time is excluded from the cap. Unarmed
 * anchors (<=0) pass through untouched, and a slide can never push the
 * anchor past `now` (a stale park stamp must not make elapsed go negative
 * and disarm the cap forever). */
static inline time_t
qos_slide_anchor(time_t anchor, time_t span, time_t now)
{
  if (anchor <= 0 || span <= 0) {
    return anchor;
  }
  anchor += span;
  if (anchor > now) {
    anchor = now;
  }
  return anchor;
}

#endif /* __SOCKPROXY_QOS_H__ */
