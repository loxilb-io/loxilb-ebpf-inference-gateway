/*
 * Copyright (c) 2026 LoxiLB Authors
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
#ifndef __SOCKPROXY_FC_H__
#define __SOCKPROXY_FC_H__

#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>

/*
 * Capacity admission for AI inference requests: the one place every request
 * path (HTTP/1 buffered, HTTP/1 streamed, HTTP/1 on a kept backend leg,
 * HTTP/2 stream, prefill/decode legs) takes a permit before its first
 * backend byte, and the one place that permit is handed back.
 *
 * Units. A permit holds at most one SERVICE unit (the request or stream
 * itself, counted once however many legs it opens) and at most one
 * ENDPOINT unit per role: normal, prefill, decode. A P/D request therefore
 * holds one service unit and two endpoint units; the service count never
 * doubles for it.
 *
 * Ceilings are compare-and-swap reservations. A load snapshot followed by an
 * unrelated increment is not a bound, so no selector's "least loaded" is
 * trusted: the CAS here is the last word, and a selector's pick that turns
 * out to be over its cap is moved to another eligible endpoint or refused.
 *
 * Queue. With a queue depth configured, an HTTP/1 request that finds no
 * room waits instead of being refused: its connection is parked (reads
 * paused, the request held in its buffer) and its fd and generation sit in
 * a per-pool FIFO. Every released service unit pops exactly one entry and
 * wakes that connection's owner worker, which re-runs the gate. A newcomer
 * never jumps a non-empty queue, and a woken request that loses the race
 * for its unit goes back to the HEAD, so the order is kept. Each entry
 * carries an absolute deadline; the proxy's 1 Hz health pass ends expired
 * ones. Exactly one terminal action per entry: the pop, the cancellation
 * (the client went away while parked), the deadline and the drain all take
 * the entry out under the queue lock, and whichever gets it owns what
 * happens to the connection. HTTP/2 streams never queue: over a ceiling is
 * a refusal on the stream.
 *
 * Modes. `off` takes no atomics at all and the dispatch path is byte for
 * byte what it was. `observe` counts every decision the gate would have
 * taken and admits everything. `enforce` refuses or queues. Zero ceilings
 * mean unlimited at that level; the counters still move so the gauges are
 * true.
 *
 * Release is idempotent: the response-complete site, the keep-alive
 * boundary and the single teardown owner may each call it for the same
 * permit, and only the first one moves a counter. A counter that would go
 * below zero is left at zero and counted as an anomaly: that, not a second
 * release call, is the signal of a unit released that was never taken.
 *
 * This header pulls in nothing from the proxy so the module and its unit
 * tests build alone. FC_MAX_EP mirrors MAX_PROXY_EP and is asserted equal
 * where both are visible. Decisions are counted by the caller that takes
 * the terminal action (a refusal written, an entry queued or refused for a
 * full queue), never inside an acquire: an acquire that fails may still
 * end in a wait, and a wait is not a shed.
 */

#define FC_MAX_EP 32

/* The largest queue depth a rule may declare. What scales with the depth is
 * not the ring (32 bytes an entry) but the parked client connections, each
 * holding a receive buffer of about a megabyte while it waits. */
#define FC_QUEUE_DEPTH_MAX 65536u

/* The longest wait window a rule may declare, and the ceiling on the
 * environment default: an hour. */
#define FC_QUEUE_WAIT_MS_MAX 3600000u

enum fc_role {
  FC_ROLE_NORMAL = 0,
  FC_ROLE_PREFILL = 1,
  FC_ROLE_DECODE = 2,
  FC_ROLES = 3,
};

enum fc_mode {
  FC_MODE_OFF = 0,
  FC_MODE_OBSERVE = 1,
  FC_MODE_ENFORCE = 2,
};

/* Where a value in force came from, per limit, for the read-back. */
enum fc_src {
  FC_SRC_DEFAULT = 0,            /* the product default */
  FC_SRC_ENV = 1,                /* the process environment (LLB_FC_*) */
  FC_SRC_RULE = 2,               /* the rule's own declaration */
};

enum fc_limit {
  FC_L_MODE = 0,
  FC_L_MAX_OUTSTANDING,
  FC_L_EP_NORMAL,
  FC_L_EP_PREFILL,
  FC_L_EP_DECODE,
  FC_L_QUEUE_DEPTH,
  FC_L_QUEUE_WAIT,
  FC_L_TELEMETRY_STALE,
  FC_LIMITS,
};

/* How long an endpoint's scraped queue depth is trusted without a refresh
 * (three default scrape intervals). */
#define FC_TELEMETRY_STALE_MS_DEFAULT 30000u
#define FC_TELEMETRY_STALE_MS_MAX     3600000u

typedef struct fc_cfg {
  uint8_t  mode;                 /* enum fc_mode */
  uint8_t  src[FC_LIMITS];       /* enum fc_src per enum fc_limit */
  uint32_t max_outstanding;      /* service ceiling on executing units; 0 = unlimited */
  uint32_t ep_cap[FC_ROLES];     /* per-endpoint ceiling per role; 0 = unlimited */
  uint32_t max_queue_depth;      /* requests that may wait for a unit; 0 = no waiting */
  uint32_t max_queue_wait_ms;    /* longest wait before a queued request is ended */
  uint32_t telemetry_stale_ms;   /* scraped queue depth older than this is not trusted */
} fc_cfg_t;

/* A rule's declarations, as the control plane sends them. 0 on any field
 * inherits the environment; the mode is shifted by one so a rule can say
 * "off" under an enforcing environment. */
enum fc_rule_mode {
  FC_RULE_MODE_INHERIT = 0,
  FC_RULE_MODE_OFF = 1,
  FC_RULE_MODE_OBSERVE = 2,
  FC_RULE_MODE_ENFORCE = 3,
};

typedef struct fc_rule_cfg {
  uint8_t  mode;                 /* enum fc_rule_mode */
  uint32_t max_outstanding;
  uint32_t ep_cap[FC_ROLES];
  uint32_t max_queue_depth;
  uint32_t max_queue_wait_ms;
  uint32_t telemetry_stale_ms;
} fc_rule_cfg_t;

/* What the gate decided, one counter each. The names are the wire values of
 * the decisions metric; they are spelled here once. Append only. */
enum fc_reason {
  FC_R_ADMITTED = 0,
  FC_R_CAPACITY_SHED,            /* service or endpoint ceiling, enforce, no wait possible */
  FC_R_NO_HEALTHY_CAPACITY,      /* no eligible endpoint at all */
  FC_R_OBSERVE_WOULD_SHED,       /* over a ceiling in observe mode, admitted */
  FC_R_BYPASS_NON_INFERENCE,     /* not an inference request: no capacity unit */
  FC_R_QUEUED,                   /* parked to wait for a unit */
  FC_R_QUEUE_FULL,               /* over a ceiling with the queue at its depth: refused */
  FC_R_QUEUE_TIMEOUT,            /* waited the whole wait window: ended */
  FC_R_CANCELLED,                /* the client went away while it waited */
  FC_R_DRAINED,                  /* the pool or the process stopped taking work while it waited */
  FC_R_OBSERVE_WOULD_QUEUE,      /* over a ceiling in observe mode with a queue depth, admitted */
  FC_R_DRAINING,                 /* refused: the process is draining for maintenance */
  FC_R_COUNT,
};

enum fc_anomaly {
  FC_A_UNDERFLOW = 0,            /* a release found its counter at zero */
  FC_A_UNKNOWN_PERMIT,           /* an executing permit with no service */
  FC_A_COUNT,
};

/* Queue wait histogram: bucket i counts waits in (bound[i-1], bound[i]]
 * milliseconds; a wait above the last bound lands in the count and the sum
 * only (the +Inf bucket of the exported histogram). */
#define FC_QWAIT_BUCKETS 8
extern const uint32_t fc_qwait_bounds_ms[FC_QWAIT_BUCKETS];

/* One waiting request: the parked client's fd and the connection generation
 * captured when it was parked, so a recycled fd is never woken for a
 * request that is gone. `live` is cleared in place when the entry is taken
 * out of turn (cancelled, expired, drained), and a pop skips it. */
typedef struct fc_queue_ent {
  int      fd;
  uint32_t live;
  uint64_t gen;
  uint64_t enqueue_ns;
  uint64_t deadline_ns;
} fc_queue_ent_t;

/* Per-pool FIFO of waiting requests. The ring is allocated when a depth is
 * configured and grown when the depth grows; it is never shrunk while
 * entries wait (a smaller depth bounds new pushes only). `used` counts the
 * slots between head and tail, tombstones included; `count` the live ones. */
typedef struct fc_queue {
  fc_queue_ent_t *ring;
  uint32_t cap;
  uint32_t head;
  uint32_t tail;
  uint32_t used;
  uint32_t count;
  uint32_t dead;                 /* the pool's rule is gone: nothing may wait here again */
  pthread_mutex_t lock;
} fc_queue_t;

/* Per-service (per model pool) admission state. Zero-initialised memory is a
 * valid `off` state, which is what a pool that predates this module looks
 * like; fc_state_init applies the configuration. */
typedef struct fc_state {
  fc_cfg_t cfg;
  _Atomic uint32_t inflight;
  _Atomic uint32_t queued;                       /* live queue entries, mirrored for lock-free reads */
  _Atomic uint32_t ep_inflight[FC_MAX_EP][FC_ROLES];
  _Atomic uint64_t decisions[FC_R_COUNT];
  _Atomic uint64_t qwait_bucket[FC_QWAIT_BUCKETS];
  _Atomic uint64_t qwait_sum_ms;
  _Atomic uint64_t qwait_count;
  fc_queue_t queue;
} fc_state_t;

enum fc_permit_state {
  FC_P_NONE = 0,                 /* nothing taken */
  FC_P_BYPASS,                   /* gate off or non-inference: nothing to release */
  FC_P_EXECUTING,                /* units held */
  FC_P_RELEASED,                 /* units handed back */
  FC_P_QUEUED,                   /* waiting in the pool's queue, nothing held */
};

typedef struct fc_permit {
  fc_state_t *fc;                /* the service the units were taken from */
  uint8_t state;                 /* enum fc_permit_state */
  uint8_t svc_held;
  uint8_t woken;                 /* popped from the queue: may not be made to queue again behind newcomers */
  int8_t  ep[FC_ROLES];          /* endpoint holding this role's unit, -1 = none */
  int      q_fd;                 /* the queue entry this permit sits in, while QUEUED */
  uint32_t q_slot;
  uint64_t q_gen;
  uint64_t q_enqueue_ns;
  uint64_t q_deadline_ns;
} fc_permit_t;

typedef enum fc_verdict {
  FC_ADMIT = 0,
  FC_SHED = 1,                   /* over a ceiling: 429 admission_capacity */
  FC_NO_CAPACITY = 2,            /* no eligible endpoint: 503 admission_no_capacity */
  FC_QUEUE = 3,                  /* over a ceiling with a queue: the caller parks the request */
  FC_DRAINING = 4,               /* the process is draining: 503 gateway_draining */
} fc_verdict_t;

extern _Atomic uint64_t fc_anomaly_total[FC_A_COUNT];

/* Environment defaults. A rule's own values, when non-zero, replace them
 * pool by pool (fc_state_apply); the environment stays the process default. */
void fc_cfg_from_env(fc_cfg_t *cfg);
/* The configuration a rule runs on: `env` with each non-zero declaration of
 * `rule` in its place, the queue depth held at its ceiling and a depth
 * given a wait window, and the source of every value recorded. */
void fc_cfg_resolve(fc_cfg_t *out, const fc_cfg_t *env, const fc_rule_cfg_t *rule);
/* Whether two configurations differ in any value or source. */
int fc_cfg_equal(const fc_cfg_t *a, const fc_cfg_t *b);
void fc_state_init(fc_state_t *fc);
/* Apply a configuration to a live pool. The queue ring grows to the new
 * depth when needed; entries already waiting are kept in order. */
void fc_state_apply(fc_state_t *fc, const fc_cfg_t *cfg);
/* Free the queue ring and mark the pool dead, so a request still holding
 * the pool can never park on it again. The queue must have been drained
 * first. The lock is kept: the pool's memory outlives its rule, and a
 * worker that resolved the pool before the delete may still take it. */
void fc_state_destroy(fc_state_t *fc);

static inline int
fc_active(const fc_state_t *fc)
{
  return fc != NULL && fc->cfg.mode != FC_MODE_OFF;
}

/* Whether requests may wait on this pool: enforce mode with a depth. */
static inline int
fc_queue_enabled(const fc_state_t *fc)
{
  return fc != NULL && fc->cfg.mode == FC_MODE_ENFORCE &&
         fc->cfg.max_queue_depth > 0 && fc->queue.cap > 0;
}

/* Whether the service ceiling has a unit free. A read: the CAS in the gate
 * is still the last word. */
static inline int
fc_has_room(const fc_state_t *fc)
{
  uint32_t cap;

  if (!fc)
    return 0;
  cap = fc->cfg.max_outstanding;
  return cap == 0 ||
         atomic_load_explicit(&fc->inflight, memory_order_relaxed) < cap;
}

void fc_permit_init(fc_permit_t *p);

/* Capacity permits apply to inference requests only: a POST on one of the
 * inference paths. Everything else on an AI service (model listings, health
 * probes, preflight) bypasses capacity, never policy, and is counted under
 * its own reason so an operator can see what the gate let past. The query
 * string is ignored. */
int fc_is_inference_request(int is_post, const char *path);

/* Take the service unit. Returns FC_ADMIT with the permit EXECUTING (or
 * BYPASS when the gate is off), FC_SHED with the permit untouched, or
 * FC_DRAINING while the process drains. Not yet counted as admitted: the
 * endpoint unit is the decision, and the first endpoint unit that lands on
 * the permit counts it, once per request. A refusal is not counted here
 * either: the caller counts what it does with it. With a queue configured,
 * a non-empty queue refuses newcomers so nobody overtakes a waiting request. */
fc_verdict_t fc_service_acquire(fc_state_t *fc, fc_permit_t *p);

/* The same for a request that may wait: FC_QUEUE instead of FC_SHED when
 * the pool has a queue. `woken` is a request popped from that queue: it
 * takes its unit ahead of newcomers. */
fc_verdict_t fc_service_acquire_h1(fc_state_t *fc, fc_permit_t *p, int woken);

/* The same, for a request that is not an inference request. */
void fc_bypass(fc_state_t *fc, fc_permit_t *p);

/* True when the endpoint is at or over its ceiling for the role. A read,
 * for selectors that want to skip capped endpoints early; the CAS in
 * fc_ep_acquire is still the last word. */
int fc_ep_over_cap(const fc_state_t *fc, int ep, int role);

/* Take one endpoint unit for the role. FC_SHED leaves the permit as it was. */
fc_verdict_t fc_ep_acquire(fc_state_t *fc, fc_permit_t *p, int ep, int role);

/* Take one endpoint unit for the role on the preferred endpoint, or on the
 * first eligible endpoint with room when the preferred one is over its cap
 * (bounded to one pass over n_eps). Returns the endpoint taken, or -1 with
 * *verdict set to FC_SHED (eligible endpoints exist, all over cap) or
 * FC_NO_CAPACITY (no eligible endpoint). `eligible` answers health, role and
 * drain state for the caller's pool. */
typedef int (*fc_eligible_fn)(void *ctx, int ep);
int fc_ep_acquire_any(fc_state_t *fc, fc_permit_t *p, int role, int preferred,
                      int n_eps, fc_eligible_fn eligible, void *ctx,
                      fc_verdict_t *verdict);

/* Move the role's unit to another endpoint (a leg re-selected after a dead
 * backend): the new endpoint's unit is taken first, under its cap, and the
 * old one released after. Returns 0, or -1 with nothing changed when the
 * new endpoint has no room, so a retry can never over-admit. */
int fc_permit_move(fc_permit_t *p, int role, int new_ep);

/* Hand back one role's endpoint unit (a leg that ended on its own). */
void fc_release_role(fc_permit_t *p, int role);

/* Hand back everything the permit holds. Idempotent. A released service
 * unit pops one waiting request and wakes it through the hook below. A
 * QUEUED permit released this way is a cancellation: the entry is taken
 * out and counted, and nothing is woken. When its entry had already been
 * popped, the turn it was given is passed to the next waiting request, so a
 * client that leaves between its wake and its resume costs nobody a turn. */
void fc_permit_release(fc_permit_t *p);

/* The same, without waking anyone: for a request that goes back to wait
 * for the same ceiling it just failed, where a wake would only hand the
 * turn to a request that fails it too. */
void fc_permit_release_nowake(fc_permit_t *p);

void fc_count(fc_state_t *fc, enum fc_reason reason);

/* ---- the queue ------------------------------------------------------------ */

/* Park a request: push its fd and generation with an absolute deadline
 * `now_ns + max_queue_wait_ms`. `front` puts it at the head (a woken request
 * that lost its unit keeps its place, even when newcomers filled the queue
 * to its depth meanwhile: its own entry left the queue only for the turn);
 * such a request keeps the arrival time and deadline it was first parked
 * with, and settles behind any request back at the head that arrived before
 * it, so going back neither extends its wait nor reorders the waiters.
 * The permit is QUEUED before its entry can be seen by any other thread.
 * Returns 0 with the permit QUEUED and the decision counted, -1 when the
 * queue is at its depth or the pool is dead (counted as queue_full, the
 * permit reset). */
int fc_queue_push(fc_state_t *fc, fc_permit_t *p, int fd, uint64_t gen,
                  uint64_t now_ns, int front);

/* Take the permit's own entry out of the queue, wherever it sits. Returns 1
 * when the entry was still live (the caller now owns the terminal action),
 * 0 when a pop, a cancellation, the deadline or a drain got there first. Not
 * counted here: the caller says why. */
int fc_queue_take(fc_state_t *fc, fc_permit_t *p);

/* Pop the oldest live entry. Returns 1 and fills *out, 0 when nothing waits. */
int fc_queue_pop(fc_state_t *fc, fc_queue_ent_t *out);

/* Whether the permit's entry is still waiting in the queue. A resume for a
 * permit whose entry was never popped did not come from its turn. */
int fc_queue_holds(fc_state_t *fc, const fc_permit_t *p);

/* The woken request is back at its gate: the wait is recorded, the permit
 * leaves the QUEUED state and is marked woken. */
void fc_queue_resumed(fc_state_t *fc, fc_permit_t *p, uint64_t now_ns);

/* Wake a popped entry on its connection's owner. Installed by the proxy;
 * returns 0 when the wake was delivered, non-zero when it could not be (the
 * entry then goes back to the head of the queue). */
typedef int (*fc_wake_fn)(int fd, uint64_t gen);
void fc_set_wake_hook(fc_wake_fn fn);

/* Pop one waiting request and wake it, when the service ceiling has a unit
 * free. Called for every released service unit, and once a second for every
 * pool with waiting requests so a turn that was lost on the way (a wake that
 * could not be delivered, a woken connection that is gone) is given again.
 * Harmless on an empty queue. */
void fc_queue_wake_one(fc_state_t *fc);
/* After a configuration change: wake, in order, the waiters the new limits
 * let through: all of them when the pool no longer enforces, else one per
 * free service unit. */
void fc_queue_wake_room(fc_state_t *fc);

/* Take every waiting request out, oldest first, and hand each to `fn`,
 * which returns non-zero when it ended a request (counted as drained) and
 * zero for an entry whose connection had already moved on. */
typedef int (*fc_drain_fn)(void *ctx, const fc_queue_ent_t *ent);
void fc_queue_drain(fc_state_t *fc, fc_drain_fn fn, void *ctx);

/* Process-wide drain for maintenance: while set, the gate refuses new
 * inference requests with FC_DRAINING and pools drain their queues. */
void fc_drain_set(int on);
int fc_draining(void);

/* Retry-After for a refusal on a pool that queues: the mean observed wait
 * rounded up to whole seconds, at least 1 and at most 30. */
uint32_t fc_retry_after_s(const fc_state_t *fc);

/* What a depth costs while it is full: one parked client per entry, each
 * holding about a megabyte. Used by the rule apply to warn an operator whose
 * depth could park more than half of the node's memory. */
uint64_t fc_queue_memory_bytes(uint32_t depth);
uint64_t fc_node_memory_bytes(void);

static inline uint32_t
fc_inflight(const fc_state_t *fc)
{
  return fc ? atomic_load_explicit(&fc->inflight, memory_order_relaxed) : 0;
}

static inline uint32_t
fc_queued(const fc_state_t *fc)
{
  return fc ? atomic_load_explicit(&fc->queued, memory_order_relaxed) : 0;
}

static inline uint32_t
fc_ep_inflight(const fc_state_t *fc, int ep, int role)
{
  if (!fc || ep < 0 || ep >= FC_MAX_EP || role < 0 || role >= FC_ROLES)
    return 0;
  return atomic_load_explicit(&fc->ep_inflight[ep][role], memory_order_relaxed);
}

/* The ceiling a shed response reports beside the inflight count. */
static inline uint32_t
fc_limit_for(const fc_state_t *fc, int role)
{
  if (!fc)
    return 0;
  if (role < 0 || role >= FC_ROLES)
    return fc->cfg.max_outstanding;
  return fc->cfg.ep_cap[role] ? fc->cfg.ep_cap[role] : fc->cfg.max_outstanding;
}

const char *fc_reason_name(enum fc_reason reason);
const char *fc_anomaly_name(enum fc_anomaly a);
const char *fc_mode_name(uint8_t mode);

#endif /* __SOCKPROXY_FC_H__ */
