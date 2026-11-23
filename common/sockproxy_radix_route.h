/* SPDX-License-Identifier: (GPL-2.0) */
/*
 * sockproxy_radix_route.h - prefix routing decision for one non-P/D pool.
 *
 * Self-contained: does not include sockproxy.h. The caller (the HTTP/1.1
 * selection in sockproxy_ep.c) gathers plain inputs from the request and the
 * pool; this module owns the per-pool trie, its lock and counters, and the
 * per-request digest key. It writes no log and keeps no request text: the
 * request keeps digests and the namespace only.
 *
 * Decision, after the existing selector, session overlay and round-robin
 * fallback have chosen (selector_pick), and before the admission gate. The
 * first reason that applies, in this order, ends the decision; every reason
 * but HIT means "keep the existing selector's pick":
 *   OFF            the pool has no radix state (p == NULL; not counted)
 *   PIPELINED      HTTP/1.1 pipelining: the request began while an answer
 *                  to an earlier request on the connection was still owed.
 *                  The per-connection state then cannot tell the two apart:
 *                  the request is not scanned, and neither it nor the
 *                  earlier one learns (the earlier one's pending learn was
 *                  reset when this one began)
 *   ROUTE_SUBSET   the request is on an L7 route subset
 *   PINNED         a forced pin or the session overlay chose, or the pool's
 *                  selector is persistence (sticky): an operator's explicit
 *                  choice that radix never overrides
 *   AI_GW_OFF      the pool is not in ai_gw_mode
 *   FC_INACTIVE    flow control is off for the pool (no in-flight counter)
 *   CHUNKED        chunked request body (not buffered for inspection)
 *   INSPECT_SIZE   body above the H1 inspection limit (streamed)
 *   NO_BODY        no buffered body located
 *   SALT_INVALID   cache_salt present but invalid
 *   NOT_CHAT       the request is not a chat completion (sp_is_chat_path)
 *   NOMEM          the per-request state could not be allocated
 *   SCAN_SKIP      radix_scan_chat() skipped (its reason counted apart)
 *   NS_OVERFLOW    the namespace does not fit RADIX_NS_MAX
 *   MISS           no eligible endpoint has seen a prefix of the key
 *   WORK_CAP       the lookup reached its work cap
 *   BELOW_THRESHOLD matched_bytes * 100 < match_pct * stream_bytes
 *   SPREAD         the chosen candidate's in-flight minus the lowest in-flight
 *                  over eligible endpoints > balance_abs
 *   HIT            out->ep is the radix pick
 * No request reaches the scanner before NOMEM, so a request stopped by an
 * earlier reason costs no parsing and no allocation.
 *
 * Candidate choice on HIT: among the lookup's candidates, the lowest
 * in-flight count; on a tie the selector's pick if it is among them, else the
 * lowest endpoint index.
 *
 * Namespace, in this order, each field radix_ns_append-encoded (absent =
 * length 0): effective model, cache salt, authenticated tenant, tools hash,
 * chat_template_kwargs hash (the two hashes as 8 bytes little-endian when
 * present). The order is fixed once learned state exists.
 *
 * Learning: a request is learnable only when its scan returned
 * RADIX_SCAN_OK in this pool (HIT, MISS, WORK_CAP, BELOW_THRESHOLD, SPREAD).
 * radix_route_learn() is called with each response status of the request:
 * an interim 1xx changes nothing; the first final status consumes the
 * request, and only a 2xx learns. When the lookup had already matched the
 * whole key with the final endpoint among its candidates, nothing is
 * inserted and no lock is taken (NOOP). Otherwise the learn takes the
 * exclusive lock, waiting for the readers inside; a learn is never skipped.
 *
 * Locking (radix_pool_t.lock): a writer-preferring rwlock
 * (PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP), so a waiting learn or
 * purge is not held off by readers that keep arriving.
 *   shared     radix_route_decide (lookup only), radix_pool_stats_format
 *   exclusive  radix_route_learn, radix_pool_purge_* (blocking wrlock)
 *   none       radix_pool_create / radix_pool_free (no other user)
 * Rules for every caller:
 *   - a leaf: nothing else is acquired while it is held;
 *   - never taken twice by one thread, not even two shared holds: with a
 *     writer waiting, a nested rdlock waits behind it and deadlocks;
 *   - no I/O, admission wait or other blocking call while it is held.
 * A build whose C library lacks the writer-preferring kind fails (#error in
 * sockproxy_radix_route.c) instead of falling back.
 *
 * HTTP/1.1 keep-alive (radix_route_keepalive): a kept-alive connection keeps
 * its backend leg for the next request unless the same request, sent on a
 * new connection, would get a radix HIT whose candidates do not include the
 * kept endpoint. Every other outcome keeps the leg: no radix state, a gate
 * that cannot be evaluated where the leg is decided (gates_unknown), a scan
 * skip, a miss, the threshold or the spread guard. The request is scanned
 * once; the selection that follows a release reuses the key. Each request
 * counts one decision reason: a kept leg counts it here (plus kept_leg when
 * the kept endpoint is a candidate of a HIT), a released leg counts ka_moved
 * here and its reason at the selection.
 *
 * Counters live in the pool (relaxed atomics) and are never exported.
 */
#ifndef __SOCKPROXY_RADIX_ROUTE_H__
#define __SOCKPROXY_RADIX_ROUTE_H__

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "sockproxy_radix.h"
#include "sockproxy_radix_scan.h"

#define RADIX_ROUTE_SCAN_CAP      8192u  /* key-stream cap */
#define RADIX_ROUTE_KEY_CAP       RADIX_SCAN_KEY_CAP(RADIX_SCAN_CAP_MAX)
#define RADIX_ROUTE_MATCH_PCT     20u    /* 0 -> this; minimum 1 */
#define RADIX_ROUTE_BALANCE_ABS   3u
#define RADIX_ROUTE_MAX_BODY      (768u * 1024u) /* until the S4g decision */
#define RADIX_ROUTE_TICK_MS       100u

typedef enum radix_route_reason {
  RADIX_R_HIT = 0,
  RADIX_R_OFF,
  RADIX_R_PIPELINED,
  RADIX_R_ROUTE_SUBSET,
  RADIX_R_PINNED,
  RADIX_R_AI_GW_OFF,
  RADIX_R_FC_INACTIVE,
  RADIX_R_CHUNKED,
  RADIX_R_INSPECT_SIZE,
  RADIX_R_NO_BODY,
  RADIX_R_SALT_INVALID,
  RADIX_R_NOMEM,
  RADIX_R_SCAN_SKIP,
  RADIX_R_NS_OVERFLOW,
  RADIX_R_MISS,
  RADIX_R_WORK_CAP,
  RADIX_R_BELOW_THRESHOLD,
  RADIX_R_SPREAD,
  RADIX_R_NOT_CHAT,      /* after SPREAD: the earlier indices are unchanged */
  RADIX_R__COUNT
} radix_route_reason_t;

typedef enum radix_learn_rc {
  RADIX_LEARN_OK = 0,
  RADIX_LEARN_NOOP,       /* already held the whole key: nothing inserted */
  RADIX_LEARN_NOMEM,      /* insert failed to allocate: trie unchanged */
  RADIX_LEARN_TOO_LARGE,  /* the key cannot fit the byte cap */
  RADIX_LEARN_REFUSED,    /* first final status not 2xx: consumed, not learned */
  RADIX_LEARN_INTERIM,    /* 1xx: not consumed */
  RADIX_LEARN_NONE,       /* not learnable, already consumed, other pool, bad ep */
  RADIX_LEARN__COUNT
} radix_learn_rc_t;

typedef struct radix_route_cfg {
  uint32_t       match_pct;    /* 0 -> RADIX_ROUTE_MATCH_PCT */
  uint32_t       balance_abs;  /* 0 -> RADIX_ROUTE_BALANCE_ABS */
  size_t         max_body;     /* scanner body-length ceiling; 0 -> RADIX_ROUTE_MAX_BODY */
  size_t         scan_cap;     /* 0 -> RADIX_ROUTE_SCAN_CAP; at most RADIX_SCAN_CAP_MAX */
  radix_limits_t lim;          /* trie limits; zeros are the trie defaults */
} radix_route_cfg_t;

typedef struct radix_route_stats {
  uint64_t decided[RADIX_R__COUNT];
  uint64_t scan_skip[RADIX_SCAN__COUNT]; /* SCAN_SKIP by scanner result */
  uint64_t learn[RADIX_LEARN__COUNT];
  uint64_t admission_moved;              /* a HIT the admission gate moved */
  uint64_t purges;                       /* endpoint purges performed */
  uint64_t scans;
  uint64_t scan_ns_sum;
  uint64_t scan_ns_max;
  uint64_t lookup_wait_ns_max;           /* longest wait for the shared lock */
  uint64_t learn_wait_ns_max;            /* longest wait for the exclusive lock
                                            in a learn */
  uint64_t kept_leg;                     /* keep-alive: kept endpoint among the
                                            candidates of a HIT */
  uint64_t ka_moved;                     /* keep-alive: leg released for radix */
} radix_route_stats_t;

typedef struct radix_pool {
  radix_trie_t        *trie;
  pthread_rwlock_t     lock;
  radix_route_cfg_t    cfg;          /* resolved (no zeros left) */
  uint32_t             learned_mask; /* endpoints inserted since their last purge;
                                        written only under the exclusive lock (a
                                        NOOP learn does not touch it) */
  radix_route_stats_t  st;
  uint64_t             stats_last_ms;
  uint64_t             stats_last_sig; /* signature of the last line taken */
} radix_pool_t;

typedef struct radix_req {
  const void *pool;          /* pool the scan and decision belong to */
  uint8_t     key[RADIX_ROUTE_KEY_CAP];
  uint8_t     ns[RADIX_NS_MAX];
  uint16_t    key_len;
  uint16_t    ns_len;
  uint32_t    stream_bytes;
  uint32_t    full_mask;     /* candidates when the whole key matched */
  uint8_t     scanned;       /* scan_rc is this request's */
  uint8_t     scan_rc;       /* radix_scan_rc_t */
  uint8_t     learnable;
} radix_req_t;

typedef struct radix_route_in {
  const void     *pool_id;      /* identity of the pool (the caller's object) */
  const char     *body;
  size_t          body_len;     /* 0: no buffered body */
  uint8_t         pipelined;    /* began under an answer still owed to an
                                   earlier request on the connection */
  uint8_t         route_subset;
  uint8_t         pinned;
  uint8_t         sticky_select; /* the pool's selector is persistence (sticky) */
  uint8_t         ai_gw_mode;
  uint8_t         fc_active;
  uint8_t         chunked;
  uint8_t         over_inspect;
  uint8_t         salt_invalid;
  const char     *model;  size_t model_len;
  const char     *salt;   size_t salt_len;   /* NULL/0: absent */
  const char     *tenant; size_t tenant_len; /* NULL/0: absent */
  uint32_t        eligible;     /* bit i: endpoint i passes route, health, CB, drain */
  const uint32_t *inflight;     /* in-flight per endpoint, n_eps entries */
  unsigned        n_eps;        /* at most RADIX_MAX_EP */
  int             selector_pick;
  uint32_t        now;          /* radix_now() */
  uint8_t         gates_unknown; /* keep-alive site: a gate selection applies
                                    cannot be evaluated there */
  uint8_t         not_chat;     /* the request is not a chat completion
                                   (sp_is_chat_path) */
  uint8_t        *decided;      /* the caller's per-request decided mark:
                                   NULL counts every call; else the decision
                                   is counted only while *decided is 0, which
                                   it then sets. The caller clears it when it
                                   reuses the request state. */
} radix_route_in_t;

typedef struct radix_route_out {
  radix_route_reason_t reason;
  radix_scan_rc_t      scan_rc;       /* valid when the request was scanned */
  int                  ep;            /* radix pick on HIT, else -1 */
  uint32_t             cand_mask;     /* lookup candidates (eligible), when it hit */
  size_t               matched_bytes; /* key-stream bytes of the match */
  size_t               stream_bytes;
} radix_route_out_t;

/* Endpoint identity for the refresh-block purge. */
typedef struct radix_ep_ident {
  uint32_t xip;
  uint16_t xport;
  uint8_t  protocol;
  uint8_t  inv;
} radix_ep_ident_t;

/* Coarse time in RADIX_ROUTE_TICK_MS ticks of CLOCK_MONOTONIC_COARSE. */
uint32_t radix_now(void);

/* NULL when an allocation fails (nothing leaked). */
radix_pool_t *radix_pool_create(const radix_route_cfg_t *cfg);
void radix_pool_free(radix_pool_t *p);

/* Returns out->ep on HIT, -1 otherwise. *rqp is allocated on the first
 * request that passes every gate before the scan; it stays NULL otherwise. */
int radix_route_decide(radix_pool_t *p, radix_req_t **rqp,
                       const radix_route_in_t *in, radix_route_out_t *out);

/* Keep-alive site: 1 when the kept leg (on kept_ep) must be released and the
 * request selected again, 0 to keep it. See the keep-alive rule above. */
int radix_route_keepalive(radix_pool_t *p, radix_req_t **rqp,
                          const radix_route_in_t *in, int kept_ep,
                          radix_route_out_t *out);

/* The admission gate moved a HIT to another endpoint (counted only). */
void radix_route_note_moved(radix_pool_t *p);

/* Called with every response status the request's client receives. */
radix_learn_rc_t radix_route_learn(radix_pool_t *p, radix_req_t *rq,
                                   const void *pool_id, int ep,
                                   unsigned status, uint32_t now);

/* Message begin of the connection's next request: nothing carries over. */
void radix_req_reset(radix_req_t *rq);
/* Connection recycle or release. NULL and *rqp NULL are accepted. */
void radix_req_free(radix_req_t **rqp);

/* Remove endpoints from the trie (exclusive lock, blocking). */
void radix_pool_purge_ep(radix_pool_t *p, unsigned ep);
void radix_pool_purge_mask(radix_pool_t *p, uint32_t mask);

/* Slots to purge when a pool refresh replaces its endpoint array: every slot
 * whose address changed (all RADIX_MAX_EP slots compared), every slot below
 * new_n whose inv went 0 -> 1, and every slot at or beyond new_n. */
uint32_t radix_refresh_purge_mask(const radix_ep_ident_t old_eps[RADIX_MAX_EP],
                                  const radix_ep_ident_t new_eps[RADIX_MAX_EP],
                                  unsigned new_n);

/* The non-zero counters as space-separated "name=count" pairs, names only:
 *   <reason>=n          radix_route_reason_name(), e.g. "hit=3 miss=1"
 *   scan.<result>=n     radix_scan_rc_name() of a SCAN_SKIP, e.g. "scan.short=2"
 *   learn.<result>=n    radix_learn_rc_name(), e.g. "learn.ok=4"
 *   moved=n purges=n scans=n scan_us_max=n scan_us_sum=n
 *   lookup_wait_us_max=n learn_wait_us_max=n   lock waits, microseconds
 *   kept_leg=n ka_moved=n                     keep-alive outcomes
 * Reason names are the enum suffixes in lower case ("route_subset",
 * "below_threshold"); learn names likewise ("ok", "too_large"). Truncated
 * at a pair boundary when cap is short; returns the length written. */
size_t radix_pool_stats_format(radix_pool_t *p, char *buf, size_t cap);
/* 1 at most once per period_ms per pool (claims the slot), else 0. */
int radix_pool_stats_due(radix_pool_t *p, uint64_t now_ms, uint64_t period_ms);
/* The counters line for the log: its length when the period is due and the
 * line differs from the last one taken, else 0 (nothing to print). */
size_t radix_pool_stats_take(radix_pool_t *p, uint64_t now_ms, uint64_t period_ms,
                             char *buf, size_t cap);

const char *radix_route_reason_name(radix_route_reason_t r);
const char *radix_learn_rc_name(radix_learn_rc_t r);

/* Process-wide number of radix_scan_chat() calls made by this module. */
uint64_t radix_route_scan_calls(void);

#endif /* __SOCKPROXY_RADIX_ROUTE_H__ */
