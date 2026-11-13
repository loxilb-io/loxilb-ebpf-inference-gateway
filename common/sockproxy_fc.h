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

#include <stddef.h>
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
 * Tenant share. With a share set, a tenant (the credential-resolved tenant
 * id; no id is one pseudo-tenant) holds at most that share of the service
 * ceiling and of the queue depth. Over it, a request waits for one of its
 * own tenant's units, or is refused with its own reason while every other
 * tenant still admits. Waiting tenants that cannot run are no reason for
 * anyone else to wait: a newcomer waits behind the queue only when a waiter
 * could take the unit, and a released unit wakes the oldest waiter that can.
 * The counts sit in a bounded table under the queue lock, taken on the
 * admission path only while a share is set.
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
  FC_L_ADAPTIVE,
  FC_L_WARMUP,
  FC_L_TTFT_TARGET,
  FC_L_TENANT_SHARE,
  FC_L_EXPOSE_HEADERS,
  /* Priority bands. */
  FC_L_WAKE_POLICY,
  FC_L_BAND_WEIGHTS,
  FC_L_BAND_MIN_SHARE,
  FC_L_CRITICAL_RESERVE,
  FC_L_BAND_WAIT,
  FC_L_BAND_QUEUE,
  FC_L_SHED_QUEUE,
  FC_L_TENANT_WAKE,
  FC_L_LLMD_HEADERS,
  FC_LIMITS,
};
#define FC_BAND_LIMITS (FC_LIMITS - FC_L_WAKE_POLICY)

/* Which waiting band a freed unit wakes. */
enum fc_wake_policy {
  FC_WAKE_STRICT = 0,            /* the highest band with a runnable waiter */
  FC_WAKE_WEIGHTED = 1,          /* deficit round robin by band_weight */
};

/* Which tenant's entry a wake takes inside one band. */
enum fc_tenant_wake {
  FC_TENANT_WAKE_FIFO = 0,       /* the oldest runnable entry */
  FC_TENANT_WAKE_RR = 1,         /* rotate across the tenants with a runnable entry */
};

/* Why a pool runs band settings other than the ones it was configured with
 * (fc_cfg_band_guard): a combination the control plane refuses when a rule
 * declares it, reached by inheriting the environment (or by a restore
 * replay), runs on the defaults instead. */
enum fc_band_fallback {
  FC_BAND_FB_NONE = 0,
  FC_BAND_FB_SOCKMAP = 1,        /* sockMapMode request/both without an AI gateway: every band knob at its default */
  FC_BAND_FB_NO_WEIGHTS = 2,     /* weighted with a zero weight: strict */
  FC_BAND_FB_NO_QUEUE = 3,       /* shed queue on with no queue depth: off */
};

/* A band's weight under weighted wake is 1..62 and a round, the sum, at
 * most 64; a band's TTL at most the queue's own window bound. */
#define FC_BAND_WEIGHT_MAX 62u
#define FC_BAND_ROUND_MAX  64u

/* How long an endpoint's scraped queue depth is trusted without a refresh
 * (three default scrape intervals). */
#define FC_TELEMETRY_STALE_MS_DEFAULT 30000u
#define FC_TELEMETRY_STALE_MS_MAX     3600000u

/* The longest warm-up window and TTFT target a rule may declare: an hour. */
#define FC_WARMUP_MS_MAX              3600000u
#define FC_TTFT_TARGET_MS_MAX         3600000u

/* Tenants a pool tracks by name for the tenant share. Tenants past these are
 * held together to one share in a last, shared slot (counted as an anomaly):
 * the table stays bounded whatever the credentials in use. The size is fixed
 * when the pool is created, because permits and queue entries hold slot
 * numbers: FC_TENANT_SLOTS is the smallest table and what fc_state_init
 * gives; the gateway creates its pools with LLB_FC_TENANT_SLOTS
 * (fc_tenant_slots_from_env). */
#define FC_TENANT_SLOTS 64
#define FC_TENANT_SLOTS_DEFAULT 256
#define FC_TENANT_SLOTS_MAX 4096

/* Priority bands. A band is the request's class constant as the admission
 * gate resolved it (AI_GW_CLASS_*: 0 standard, 1 critical, 2 sheddable), so
 * a zeroed permit or entry is standard: a request with no class (MCP,
 * keyless, a pool with no class configured) is standard and FIFO. Band
 * order is by rank, not by number: critical first, then standard, then
 * sheddable. The per-band counts below are kept for critical and sheddable
 * only; standard is the total less those two, so a request with no class
 * moves no counter it did not move before. */
#define FC_BANDS 3
#define FC_BAND_STANDARD  0
#define FC_BAND_CRITICAL  1
#define FC_BAND_SHEDDABLE 2

typedef struct fc_cfg {
  uint8_t  mode;                 /* enum fc_mode */
  uint8_t  src[FC_LIMITS];       /* enum fc_src per enum fc_limit */
  uint32_t max_outstanding;      /* service ceiling on executing units; 0 = unlimited */
  uint32_t ep_cap[FC_ROLES];     /* per-endpoint ceiling per role; 0 = unlimited */
  uint32_t max_queue_depth;      /* requests that may wait for a unit; 0 = no waiting */
  uint32_t max_queue_wait_ms;    /* longest wait before a queued request is ended */
  uint32_t telemetry_stale_ms;   /* scraped queue depth older than this is not trusted */
  uint8_t  adaptive;             /* 1: the service ceiling tightens under backpressure */
  uint32_t warmup_ms;            /* an endpoint back in service ramps to its ceiling over this; 0 = at once */
  uint32_t ttft_target_ms;       /* an endpoint's TTFT above this is backpressure; 0 = TTFT unused */
  uint8_t  tenant_share_pct;     /* most of the ceiling and of the queue one tenant may hold; 0 or 100 = no share */
  uint8_t  expose_headers;       /* 1: an admitted response carries the admission headers */
  /* Priority bands. Every triple is indexed by band (FC_BAND_*). */
  uint8_t  wake_policy;          /* enum fc_wake_policy */
  uint8_t  band_weight[FC_BANDS];        /* weighted wake: 1..62 each, 0 = not set */
  uint8_t  band_min_share_pct[FC_BANDS]; /* floor, % of the ceiling in force: a guarantee under contention, binding only while the band has a waiter */
  uint8_t  critical_reserve_pct; /* % of the ceiling in force that no other band may take, even while critical is idle */
  /* A band's wait window is a cap inside the rule's window (max_queue_wait_ms), never above it; 0 = the rule's window. */
  uint32_t band_wait_ms[FC_BANDS];
  /* A band's queue share bounds that band's own occupancy of max_queue_depth, a ceiling and not a reservation: what a
   * band does not use stays open to every other band, and the queue as a whole never holds more than max_queue_depth;
   * 0 = the shared depth. */
  uint8_t  band_queue_pct[FC_BANDS];
  uint8_t  shed_queue;           /* 1: a sheddable request at the ceiling waits in its band instead of 429 */
  uint8_t  tenant_wake;          /* enum fc_tenant_wake */
  uint8_t  llmd_headers;         /* 1: refusals carry x-llm-d-request-dropped-reason; x-llm-d-inference-ttl shortens a wait */
  uint8_t  bands;                /* derived: 1 when a band knob differs from its default (wake, weights, floors, waits, shares, shed queue, rr) */
  /* The switches as configured (rule, else environment), before
   * fc_cfg_band_guard; the fields above are what the gate runs. */
  uint8_t  wake_policy_cfg;
  uint8_t  shed_queue_cfg;
  uint8_t  tenant_wake_cfg;
  uint8_t  band_fallback;        /* enum fc_band_fallback */
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

/* The same shift for the adaptive switch. */
enum fc_rule_adaptive {
  FC_RULE_ADAPTIVE_INHERIT = 0,
  FC_RULE_ADAPTIVE_OFF = 1,
  FC_RULE_ADAPTIVE_ON = 2,
};

/* And for the admission headers on admitted responses. */
enum fc_rule_expose {
  FC_RULE_EXPOSE_INHERIT = 0,
  FC_RULE_EXPOSE_OFF = 1,
  FC_RULE_EXPOSE_ON = 2,
};

/* The band switches, the same shift: 0 inherits. */
enum fc_rule_wake {
  FC_RULE_WAKE_INHERIT = 0,
  FC_RULE_WAKE_STRICT = 1,
  FC_RULE_WAKE_WEIGHTED = 2,
};

enum fc_rule_tenant_wake {
  FC_RULE_TENANT_WAKE_INHERIT = 0,
  FC_RULE_TENANT_WAKE_FIFO = 1,
  FC_RULE_TENANT_WAKE_RR = 2,
};

/* An on/off switch (shed queue, llm-d headers). */
enum fc_rule_switch {
  FC_RULE_SWITCH_INHERIT = 0,
  FC_RULE_SWITCH_OFF = 1,
  FC_RULE_SWITCH_ON = 2,
};

typedef struct fc_rule_cfg {
  uint8_t  mode;                 /* enum fc_rule_mode */
  uint32_t max_outstanding;
  uint32_t ep_cap[FC_ROLES];
  uint32_t max_queue_depth;
  uint32_t max_queue_wait_ms;
  uint32_t telemetry_stale_ms;
  uint8_t  adaptive;             /* enum fc_rule_adaptive */
  uint32_t warmup_ms;
  uint32_t ttft_target_ms;
  uint8_t  tenant_share_pct;     /* 1..100; 0 inherits */
  uint8_t  expose_headers;       /* enum fc_rule_expose */
  /* Priority bands. The switches inherit the environment at 0; the numeric
   * knobs are the rule's own (no environment value: 0 is "none"). Triples
   * are indexed by band (FC_BAND_*). */
  uint8_t  wake_policy;          /* enum fc_rule_wake */
  uint8_t  band_weight[FC_BANDS];
  uint8_t  band_min_share_pct[FC_BANDS];
  uint8_t  critical_reserve_pct; /* the reservation: units no other band may take; not a floor */
  uint32_t band_wait_ms[FC_BANDS];
  uint8_t  band_queue_pct[FC_BANDS];
  uint8_t  shed_queue;           /* enum fc_rule_switch */
  uint8_t  tenant_wake;          /* enum fc_rule_tenant_wake */
  uint8_t  llmd_headers;         /* enum fc_rule_switch */
} fc_rule_cfg_t;

/* The adaptive ceiling's state, for the read-back and the metrics. */
enum fc_adapt_state {
  FC_AS_OFF = 0,                 /* not adaptive, or no service ceiling to tighten */
  FC_AS_OPEN,                    /* at the configured ceiling */
  FC_AS_TIGHTENED,               /* below it, following fresh signals */
  FC_AS_FROZEN,                  /* below it, signals stale: held where it is */
  FC_AS_COUNT,
};

/* Why the adaptive ceiling last moved, or why it holds. */
enum fc_adapt_reason {
  FC_AR_NONE = 0,
  FC_AR_QUEUED,                  /* an endpoint reported waiting requests */
  FC_AR_TTFT,                    /* an endpoint's TTFT is above the target */
  FC_AR_CLEAR,                   /* fresh signals, no backpressure: widened */
  FC_AR_STALE,                   /* no fresh signal: held */
  FC_AR_COUNT,
};

/* What the 1 Hz pass saw across a pool's endpoints. */
typedef struct fc_signal {
  uint8_t fresh;                 /* at least one endpoint reported within the telemetry window */
  uint8_t queued;                /* a fresh endpoint has requests waiting */
  uint8_t ttft_over;             /* a fresh endpoint's TTFT is above the target */
} fc_signal_t;

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
  FC_R_TENANT_SHARE,             /* refused: the tenant holds its share of the ceiling or of the queue */
  FC_R_SHED,                     /* refused or evicted by band policy: a sheddable request that may not wait */
  FC_R_COUNT,
};

/* How a request of a band ended, or that it waited: the per-band split of
 * five decisions (enum fc_reason), counted where those are counted.
 * admitted, shed, expired and cancelled are terminal, one per request;
 * queued is counted once per park (a woken request that goes back to its
 * place is the same park). Kept for critical and sheddable; standard is the
 * decision less those two, so a request with no class moves no counter it
 * did not move before. */
enum fc_band_outcome {
  FC_BO_ADMITTED = 0,            /* took a unit (FC_R_ADMITTED) */
  FC_BO_QUEUED,                  /* parked (FC_R_QUEUED) */
  FC_BO_SHED,                    /* refused or evicted by band policy, 429 admission_shed (FC_R_SHED) */
  FC_BO_EXPIRED,                 /* its wait window ended, 504 (FC_R_QUEUE_TIMEOUT) */
  FC_BO_CANCELLED,               /* its client left while it waited (FC_R_CANCELLED) */
  FC_BO_COUNT,
};

enum fc_anomaly {
  FC_A_UNDERFLOW = 0,            /* a release found its counter at zero */
  FC_A_UNKNOWN_PERMIT,           /* an executing permit with no service */
  FC_A_TENANT_TABLE_FULL,        /* a tenant past the table was put in the shared slot */
  FC_A_H2_DENY_HEADERS,          /* an HTTP/2 refusal had more headers than its frame holds: not sent */
  FC_A_EXPOSE_HEAD_OVERFLOW,     /* an HTTP/1.1 response head came split and longer than the
                                  * assembly bound: sent as it came, without the admission headers */
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
 * out of turn (cancelled, expired, drained), and a pop skips it. `tslot` is
 * the tenant slot whose queue count the entry holds, -1 for none. */
typedef struct fc_queue_ent {
  int      fd;
  uint8_t  live;
  uint8_t  band;                 /* FC_BAND_*: the request's class when it parked */
  int16_t  tslot;
  uint64_t gen;
  uint64_t enqueue_ns;
  uint64_t deadline_ns;
} fc_queue_ent_t;

/* A waiter evicted from the queue (fc_shed_queue) whose answer is still
 * owed: the 429 is written by its connection's owner worker, which claims
 * the entry on its resume (fc_queue_evicted_claim); the 1 Hz pass answers
 * one whose wake was lost. The list is bounded: while it is full nobody is
 * evicted and the arrival is refused as a full queue. */
#define FC_EVICT_PENDING 16

typedef struct fc_evicted {
  int      fd;
  uint64_t gen;
  uint64_t at_ns;                /* when it was evicted */
} fc_evicted_t;

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
  uint32_t band_count[FC_BANDS]; /* live entries per band; the standard slot is never written */
  /* Weighted wake: the credits each band has left in the round in progress (spent one per wake,
   * set again from the weights when no band that has a runnable waiter has any left, and reset
   * when the policy or the weights change). Round-robin tenant wake: the tenant slot a band's
   * next turn starts from, one past the slot it served last. Both under the lock. */
  uint32_t drr_credit[FC_BANDS];
  uint32_t rr_next[FC_BANDS];
  uint32_t dead;                 /* the pool's rule is gone: nothing may wait here again */
  fc_evicted_t evicted[FC_EVICT_PENDING]; /* evicted waiters owed their answer, oldest first */
  _Atomic uint32_t n_evicted;    /* written under the lock, read without it */
  /* The earliest deadline among the live entries, 0 while none waits:
   * written under the lock by every insertion and removal, read without it
   * by the deadline pass, which enters a pool's queue only once this has
   * passed (fc_deadline_pass). */
  _Atomic uint64_t next_deadline_ns;
  pthread_mutex_t lock;
} fc_queue_t;

/* One tenant's hold on a pool: the service units it executes on and the
 * queue entries it waits in. A slot is free again when both are zero.
 * `waiting_runnable` is set while the tenant has a queue entry and room
 * under its share (counted in fc_state_t.tenants_runnable_waiting);
 * `next_free` links the free slots. */
typedef struct fc_tenant {
  uint64_t key;
  uint32_t inflight;
  uint32_t queued;
  uint8_t  used;
  uint8_t  waiting_runnable;
  uint16_t next_free;
} fc_tenant_t;

/* Slot numbers travel as int16_t (permit, queue entry) and the lookup index
 * holds slot + 1 in a uint16_t beside two reserved values. */
_Static_assert(sizeof(fc_tenant_t) == 24, "fc_tenant_t size");
_Static_assert(sizeof(fc_queue_ent_t) == 32, "fc_queue_ent_t size");
_Static_assert(FC_TENANT_SLOTS_MAX < INT16_MAX, "tenant slot fits int16_t");
_Static_assert(FC_TENANT_SLOTS <= FC_TENANT_SLOTS_DEFAULT &&
               FC_TENANT_SLOTS_DEFAULT <= FC_TENANT_SLOTS_MAX,
               "tenant slot bounds");

/* Per-service (per model pool) admission state. Zero-initialised memory is a
 * valid `off` state, which is what a pool that predates this module looks
 * like; fc_state_init applies the configuration. */
typedef struct fc_state {
  fc_cfg_t cfg;
  _Atomic uint32_t inflight;
  _Atomic uint32_t queued;                       /* live queue entries, mirrored for lock-free reads */
  /* Per band (critical and sheddable; the standard slot is never written):
   * service units held, and live queue entries mirrored like `queued`. */
  _Atomic uint32_t band_inflight[FC_BANDS];
  _Atomic uint32_t band_queued[FC_BANDS];
  /* Per band and outcome (critical and sheddable; the standard row is
   * never written, fc_band_outcome derives it). */
  _Atomic uint64_t band_outcome[FC_BANDS][FC_BO_COUNT];
  /* The standard count of each outcome last read: a derived count never
   * steps back (fc_band_outcome). */
  _Atomic uint64_t band_std_read[FC_BO_COUNT];
  _Atomic uint32_t ep_inflight[FC_MAX_EP][FC_ROLES];
  _Atomic uint64_t decisions[FC_R_COUNT];
  _Atomic uint64_t qwait_bucket[FC_QWAIT_BUCKETS];
  _Atomic uint64_t qwait_sum_ms;
  _Atomic uint64_t qwait_count;
  /* When this service last logged a neutralised client-supplied engine
   * priority (ai_gw_native_priority_note): one line per service, rate-limited. */
  _Atomic uint64_t native_prio_note_ns;
  fc_queue_t queue;
  /* The adaptive ceiling in force while cfg.adaptive is set; otherwise
   * unused (the configured ceiling is). Moved by fc_adapt_tick only. */
  _Atomic uint32_t eff_max;
  _Atomic uint8_t adapt_state;   /* enum fc_adapt_state */
  _Atomic uint8_t adapt_reason;  /* enum fc_adapt_reason */
  _Atomic uint64_t adapt_moves[2]; /* times the ceiling went down, up */
  /* Per endpoint: when its warm-up began (0 = warm), and its TTFT
   * estimate with the time of the last sample. */
  _Atomic uint64_t warm_since_ns[FC_MAX_EP];
  _Atomic uint32_t ttft_ewma_ms[FC_MAX_EP];
  _Atomic uint64_t ttft_ts_ns[FC_MAX_EP];
  /* The tenant share: `tenant_slots` slots by tenant key and one more,
   * shared by tenants past the table. Under queue.lock, which every path
   * that moves a queue entry already holds; taken on the admission path only
   * while a share is set. The table is allocated when the pool first runs
   * with a share and freed by fc_state_destroy; a release that arrives
   * after that finds no table. Slots never move while they are held;
   * `tenant_index` finds a slot by key (open addressing, 2 * tenant_slots
   * buckets) and is the only part that is ever re-laid. */
  fc_tenant_t *tenants;
  uint16_t *tenant_index;
  uint32_t tenant_slots;         /* fixed at fc_state_init; 0 reads as FC_TENANT_SLOTS */
  uint32_t tenants_used;
  uint32_t tenant_free;          /* head of the free slots, tenant_slots = none */
  uint32_t tenant_tombs;         /* index buckets left behind by freed slots */
  /* Tenants with a queue entry and room under `tenant_bound`, the per-tenant
   * unit bound the count was last taken with. */
  uint32_t tenants_runnable_waiting;
  uint32_t tenant_bound;
} fc_state_t;

enum fc_permit_state {
  FC_P_NONE = 0,                 /* nothing taken */
  FC_P_BYPASS,                   /* gate off or non-inference: nothing to release */
  FC_P_EXECUTING,                /* units held */
  FC_P_RELEASED,                 /* units handed back */
  FC_P_QUEUED,                   /* waiting in the pool's queue, nothing held */
  FC_P_EVICTED,                  /* evicted, and the 1 Hz pass decided its answer */
  FC_P_ENDED,                    /* the wait was ended by the deadline, a drain or a cancel */
};

/* A waiting request leaves FC_P_QUEUED exactly once, by one compare-and-swap
 * on the state it already has: its owner's resume (to FC_P_NONE: its turn,
 * or its eviction claimed by the owner) or one of the paths that end a wait
 * from elsewhere (FC_P_EVICTED, FC_P_ENDED). Whoever swaps decides what
 * happens to the request; the other does nothing, so no request is answered
 * twice, and an owner's resume that comes after another path decided is
 * dropped. */

typedef struct fc_permit {
  fc_state_t *fc;                /* the service the units were taken from */
  _Atomic uint8_t state;         /* enum fc_permit_state; leaves QUEUED by fc_permit_settle */
  uint8_t svc_held;
  uint8_t woken;                 /* popped from the queue: may not be made to queue again behind newcomers */
  uint8_t band;                  /* FC_BAND_*: set at the service acquire, kept while queued */
  uint8_t q_parked;              /* in a park whose wait is not yet observed (fc_queue_wait_end) */
  uint8_t q_ttl_cut;             /* the park's deadline is the client's x-llm-d-inference-ttl, not a window of the rule's */
  uint32_t q_ttl_ms;             /* the client's TTL for the next fc_queue_push, 0 = none; read only with llmd_headers on */
  int8_t  ep[FC_ROLES];          /* endpoint holding this role's unit, -1 = none */
  int      q_fd;                 /* the queue entry this permit sits in, while QUEUED */
  uint32_t q_slot;
  uint64_t q_gen;
  uint64_t q_enqueue_ns;
  uint64_t q_deadline_ns;
  uint64_t q_first_ns;           /* when a request moved here from the P/D prefill park first parked, for the next fc_queue_push; 0 = none; cleared by the bind */
  uint64_t admit_ns;             /* fc_now_ns() when the first endpoint unit landed: dispatch */
  uint64_t tkey;                 /* the tenant the request is admitted as */
  int16_t  tslot;                /* tenant slot whose inflight count this permit holds, -1 = none */
} fc_permit_t;

/* QUEUED -> `to`, once: 1 when this caller made the transition (and so
 * decides the request), 0 when the permit had already left QUEUED. */
static inline int
fc_permit_settle(fc_permit_t *p, uint8_t to)
{
  uint8_t from = FC_P_QUEUED;

  return atomic_compare_exchange_strong_explicit(&p->state, &from, to,
                                                 memory_order_acq_rel,
                                                 memory_order_acquire);
}

typedef enum fc_verdict {
  FC_ADMIT = 0,
  FC_SHED = 1,                   /* over a ceiling: 429 admission_capacity */
  FC_NO_CAPACITY = 2,            /* no eligible endpoint: 503 admission_no_capacity */
  FC_QUEUE = 3,                  /* over a ceiling with a queue: the caller parks the request */
  FC_DRAINING = 4,               /* the process is draining: 503 gateway_draining */
  FC_TENANT_SHARE = 5,           /* the tenant holds its share: 429 admission_tenant_share */
  FC_BAND_SHED = 6,              /* a sheddable request that may not wait: 429 admission_shed */
} fc_verdict_t;

extern _Atomic uint64_t fc_anomaly_total[FC_A_COUNT];

/* Environment defaults. A rule's own values, when non-zero, replace them
 * pool by pool (fc_state_apply); the environment stays the process default. */
void fc_cfg_from_env(fc_cfg_t *cfg);
/* The configuration a rule runs on: `env` with each non-zero declaration of
 * `rule` in its place, the queue depth held at its ceiling and a depth
 * given a wait window, and the source of every value recorded. */
void fc_cfg_resolve(fc_cfg_t *out, const fc_cfg_t *env, const fc_rule_cfg_t *rule);
/* Holds a resolved configuration to what the control plane accepts from a
 * declaring rule: a pool whose request direction bypasses the gate
 * (`gate_bypassed`: sockMapMode request or both, not an AI-gateway service)
 * runs every band knob at its default; weighted with a zero weight runs
 * strict; a shed queue with no queue depth runs off. The configured
 * switches are kept beside the effective ones and the first reason in
 * band_fallback. Returns band_fallback. */
uint8_t fc_cfg_band_guard(fc_cfg_t *cfg, int gate_bypassed);
const char *fc_band_fallback_name(uint8_t reason);
/* enum fc_src as the read-back spells it: rule, env, default. */
const char *fc_src_name(uint8_t src);
/* Whether two configurations differ in any value or source. */
int fc_cfg_equal(const fc_cfg_t *a, const fc_cfg_t *b);
void fc_state_init(fc_state_t *fc);
/* The same with the tenant table sized: `tenant_slots` held to
 * FC_TENANT_SLOTS..FC_TENANT_SLOTS_MAX. */
void fc_state_init_slots(fc_state_t *fc, uint32_t tenant_slots);
/* LLB_FC_TENANT_SLOTS held to the same range; FC_TENANT_SLOTS_DEFAULT when
 * unset or not a number. Process-wide: there is no per-rule value. */
uint32_t fc_tenant_slots_from_env(void);
/* Apply a configuration to a live pool. The queue ring grows to the new
 * depth when needed; entries already waiting are kept in order. */
void fc_state_apply(fc_state_t *fc, const fc_cfg_t *cfg);
/* Free the queue ring and the tenant table and mark the pool dead, so a
 * request still holding the pool can never park on it again. The queue
 * must have been drained first. The lock is kept: the pool's memory
 * outlives its rule, and a worker that resolved the pool before the delete
 * may still take it. */
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

/* The service ceiling in force: the adaptive one while the pool adapts,
 * else the configured one. 0 is unlimited, and an unlimited pool has
 * nothing to tighten. */
static inline uint32_t
fc_svc_cap(const fc_state_t *fc)
{
  if (fc->cfg.adaptive && fc->cfg.max_outstanding)
    return atomic_load_explicit(&fc->eff_max, memory_order_relaxed);
  return fc->cfg.max_outstanding;
}

/* An endpoint's ceiling for the role at `now_ns`: the configured one, or,
 * while the endpoint warms up, a ramp from a quarter of it (at least one)
 * to all of it across the warm-up window. An unlimited role is not ramped. */
uint32_t fc_ep_cap_now(const fc_state_t *fc, int ep, int role, uint64_t now_ns);

/* Whether the service ceiling has a unit free. A read: the CAS in the gate
 * is still the last word. */
static inline int
fc_has_room(const fc_state_t *fc)
{
  uint32_t cap;

  if (!fc)
    return 0;
  cap = fc_svc_cap(fc);
  return cap == 0 ||
         atomic_load_explicit(&fc->inflight, memory_order_relaxed) < cap;
}

void fc_permit_init(fc_permit_t *p);
/* The owner's reference for each permit that points at a state: taken when a
 * permit is bound to it, given back when the permit is unbound (the sockproxy
 * counts its pool this way; a released permit stays bound, it is read after
 * its release). Set once at start. While set, a permit must start from
 * zeroed memory: a bind reads the state the permit pointed at before. */
void fc_set_owner_hooks(void (*hold)(fc_state_t *fc), void (*drop)(fc_state_t *fc));
/* Unbind the permit from its state without touching its units: what the
 * permit's owner runs before the permit's memory goes or is reused. */
void fc_permit_unbind(fc_permit_t *p);

/* ---- tenant share ----------------------------------------------------------- */

/* A tenant's key: a 64-bit hash of the credential-resolved tenant id. No id
 * (a keyless request, or a credential with no tenant) is one pseudo-tenant. */
uint64_t fc_tenant_key(const char *tenant_id);

/* Whether the pool holds tenants to a share. */
static inline int
fc_share_active(const fc_state_t *fc)
{
  return fc != NULL && fc->cfg.mode != FC_MODE_OFF &&
         fc->cfg.tenant_share_pct > 0 && fc->cfg.tenant_share_pct < 100;
}

/* The executing units one tenant may hold: its share of the ceiling in
 * force, rounded up, at least one. 0 (no bound) when the pool has no share or
 * no ceiling. */
uint32_t fc_tenant_svc_bound(const fc_state_t *fc);
/* The same for queue entries, as a share of the queue depth. */
uint32_t fc_tenant_queue_bound(const fc_state_t *fc);
/* Tenants holding a unit or a queue entry on the pool now. */
uint32_t fc_tenants_active(fc_state_t *fc);
/* Tenants the pool tracks by name: the table size in force. */
uint32_t fc_tenant_slots(const fc_state_t *fc);

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

/* The same two, for a request admitted as tenant `tkey`. On a pool with a
 * share, a tenant at its share of the ceiling waits (when it may, within its
 * share of the queue) or is refused with FC_TENANT_SHARE while other tenants
 * still admit, and a newcomer waits behind the queue only when someone in it
 * can run. The two above are the pseudo-tenant. */
fc_verdict_t fc_service_acquire_tenant(fc_state_t *fc, fc_permit_t *p,
                                       uint64_t tkey);
fc_verdict_t fc_service_acquire_h1_tenant(fc_state_t *fc, fc_permit_t *p,
                                          int woken, uint64_t tkey);

/* The same two, for a request of band `band` (FC_BAND_*; anything else is
 * standard). The two above are band standard. */
fc_verdict_t fc_service_acquire_band(fc_state_t *fc, fc_permit_t *p,
                                     uint64_t tkey, uint8_t band);
fc_verdict_t fc_service_acquire_h1_band(fc_state_t *fc, fc_permit_t *p,
                                        int woken, uint64_t tkey, uint8_t band);

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

/* fc_count for one of the five decisions a band outcome splits (admitted,
 * queued, shed, queue_timeout, cancelled), with the request's band: the
 * decision is counted, and so is the band's outcome when the band is
 * critical or sheddable. Any other reason is fc_count. */
void fc_count_band(fc_state_t *fc, enum fc_reason reason, uint8_t band);

/* A band's count of an outcome (enum fc_band_outcome). Standard is the
 * decision less critical and sheddable, held at zero, and never below the
 * value it last read. */
uint64_t fc_band_outcome(fc_state_t *fc, uint8_t band, int outcome);
const char *fc_band_outcome_name(int outcome);

/* Whether a request of the permit's band may wait in this pool's queue: a
 * sheddable request only with fc_shed_queue on. Enforce mode only; anything
 * else may. */
int fc_band_may_wait(const fc_state_t *fc, const fc_permit_t *p);

/* ---- floors and the reserve ------------------------------------------------
 * A floor (fc_band_min_share_pct) is a guarantee under contention, not a
 * reservation: it binds only while its band has a waiter, so with no demand
 * in a band the other bands take every unit. The reserve
 * (fc_critical_reserve_pct) is the one true reservation: units no other band
 * may take even while critical is idle. Both are a share of the ceiling in
 * force, in units fc_floor_units.
 *
 * The rule the code implements: when a unit frees, the highest-ranked band
 * that is below its floor and has a runnable waiter takes it; when no band
 * is below its floor, the wake policy chooses. A request of a band at or
 * above its own floor takes a unit only if the units left after it still
 * cover what every other band with a waiter is short of its floor, and what
 * critical is short of its reserve. */

/* Whether the pool runs a floor or the reserve. */
static inline int
fc_floors_on(const fc_cfg_t *c)
{
  return (c->band_min_share_pct[0] | c->band_min_share_pct[1] |
          c->band_min_share_pct[2] | c->critical_reserve_pct) != 0;
}

/* A share of a ceiling in whole units, rounded in the band's favour (up) but
 * never to the whole ceiling for a share under 100: 0 without a ceiling or
 * a share. */
uint32_t fc_floor_units(uint32_t cap, uint8_t pct);

/* The floors and the reserve of a configuration against a ceiling, in units
 * as the gate enforces them: the three together never exceed the ceiling
 * (rounding is clamped in rank order, critical first), and critical holds
 * the larger of its floor and its reserve. floor[] is indexed by band. */
void fc_floor_claims(const fc_cfg_t *c, uint32_t cap, uint32_t floor[FC_BANDS],
                     uint32_t *reserve);

/* The band's say over a capacity verdict: a sheddable request that would
 * wait (FC_QUEUE) or that met a ceiling (FC_SHED) and may not wait is shed,
 * FC_BAND_SHED. Every other verdict is returned as it is. */
fc_verdict_t fc_band_verdict(const fc_state_t *fc, const fc_permit_t *p,
                             fc_verdict_t v);

/* A band triple as operators write it, critical:standard:sheddable, from
 * values indexed by band. Returns what snprintf returns. */
int fc_band_triple_fmt(char *out, size_t cap, const uint32_t v[FC_BANDS]);

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
 * permit reset), -2 when the permit's tenant holds its share of the queue
 * (counted as tenant_share, the permit reset). A first park is counted
 * queued; a request going back to the head is the same park and is not
 * counted again.
 *
 * Eviction (fc_shed_queue on): a request above sheddable that finds the
 * queue at its depth takes the place of the youngest sheddable waiter. The
 * evicted waiter is counted shed, kept on the evicted list until its answer
 * is claimed, and its connection's owner is woken through the wake hook to
 * write 429 admission_shed (fc_queue_evicted_claim). */
int fc_queue_push(fc_state_t *fc, fc_permit_t *p, int fd, uint64_t gen,
                  uint64_t now_ns, int front);

/* Claim the answer owed to an evicted waiter (fd, gen): 1 when it was on
 * the evicted list, now taken off it (the caller writes the 429), 0 when it
 * was not evicted or another path has claimed it. */
int fc_queue_evicted_claim(fc_state_t *fc, int fd, uint64_t gen);

/* The pass's decision on an evicted waiter: (fd, gen)'s entry is taken off
 * the evicted list and `p` swapped QUEUED -> FC_P_EVICTED in one hold of
 * the queue lock. 1 when the pass now answers it. 0 when the entry is gone
 * (its owner claimed it: the owner answers, and a later request on the same
 * connection, parked under the same (fd, gen), is not this wait) or the
 * permit had already left QUEUED. */
int fc_queue_evicted_settle(fc_state_t *fc, fc_permit_t *p, int fd, uint64_t gen);

/* Evicted waiters whose answer is still owed. A read. */
static inline uint32_t
fc_queue_evicted(const fc_state_t *fc)
{
  return fc ? atomic_load_explicit(&fc->queue.n_evicted, memory_order_relaxed) : 0;
}

/* Every waiter evicted at or before `before_ns` is handed to `fn` (the
 * entry's fd and gen, band sheddable) outside the queue lock, and taken off
 * the evicted list after `fn` returned. `fn` decides the request with
 * fc_queue_evicted_settle and answers it only when that returns 1, so a
 * late resume of the owner that claims the entry meanwhile and a pass that
 * answers it are never both: whoever takes the entry decides. For the 1 Hz pass
 * (a wake that was lost or came late) and the drain of a pool (UINT64_MAX:
 * all). Returns the number `fn` answered (returned nonzero for). */
uint32_t fc_queue_evicted_sweep(fc_state_t *fc, uint64_t before_ns,
                                int (*fn)(void *ctx, const fc_queue_ent_t *ent),
                                void *ctx);

/* Take the permit's own entry out of the queue, wherever it sits: under the
 * queue lock the permit is moved QUEUED -> FC_P_ENDED and only then its entry
 * removed. Returns 1 when it was (the caller now owns the terminal action),
 * 0 when a pop, a cancellation, the deadline, a drain or the owner got there
 * first. Not counted here: the caller says why. */
int fc_queue_take(fc_state_t *fc, fc_permit_t *p);

/* Pop the oldest live entry. Returns 1 and fills *out, 0 when nothing waits. */
int fc_queue_pop(fc_state_t *fc, fc_queue_ent_t *out);

/* Whether the permit's entry is still waiting in the queue. A resume for a
 * permit whose entry was never popped did not come from its turn. */
int fc_queue_holds(fc_state_t *fc, const fc_permit_t *p);

/* The woken request is back at its gate: the permit leaves QUEUED (to
 * FC_P_NONE, by fc_permit_settle) and is marked woken. Returns 1 when it did,
 * 0 when another path had already decided the request. */
int fc_queue_resumed(fc_state_t *fc, fc_permit_t *p, uint64_t now_ns);

/* What the owner's resume of a parked connection is, for a request in the
 * capacity queue (pd_resume_parked). */
enum fc_resume {
  FC_RESUME_NOT_QUEUED = 0,      /* not in the capacity queue: some other park */
  FC_RESUME_WAIT,                /* still waiting: not its turn, stays parked */
  FC_RESUME_TURN,                /* its turn: woken, back to its gate */
  FC_RESUME_EVICTED,             /* evicted, the answer is the owner's: 429 admission_shed */
  FC_RESUME_DECIDED,             /* another path decided it first: do nothing */
};

/* The owner's half of the one transition out of QUEUED: claims an eviction
 * owed to it, leaves a request still waiting where it is, takes its turn, or
 * finds that the 1 Hz pass, the deadline or a drain decided first. */
int fc_queue_owner_resume(fc_state_t *fc, fc_permit_t *p, uint64_t now_ns);
/* A park ends: the queue-wait histogram takes its whole wait, from the first
 * park, once (admitted, expired, cancelled; an evicted waiter is observed
 * where it is evicted). A woken request that goes back to its place is the
 * same park and is not observed in between. No-op for a permit not in a
 * park. */
void fc_queue_wait_end(fc_state_t *fc, fc_permit_t *p, uint64_t now_ns);

/* Wake a popped entry on its connection's owner. Installed by the proxy;
 * returns 0 when the wake was delivered, non-zero when it could not be (the
 * entry then goes back to the head of the queue). */
typedef int (*fc_wake_fn)(int fd, uint64_t gen);
void fc_set_wake_hook(fc_wake_fn fn);

/* Pop one waiting request and wake it, when the service ceiling has a unit
 * free. On a pool with a share, the oldest waiter whose tenant is under its
 * share: one that could not run is passed over and keeps its place. Called for every released service unit, and once a second for every
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

/* Hand every waiting entry to `fn`, oldest first, with the queue lock held;
 * nothing is taken out and the order is kept. Returns the number of entries
 * visited. `fn` runs under the lock, so a write it makes to its waiter's
 * connection is ordered before that waiter's pop: it must not call back into
 * this queue. */
typedef void (*fc_visit_fn)(void *ctx, const fc_queue_ent_t *ent);
uint32_t fc_queue_visit(fc_state_t *fc, fc_visit_fn fn, void *ctx);

/* ---- queue deadlines ------------------------------------------------------
 * A configured wait window is the enforced window. A waiting request's
 * deadline is met by a timer armed to the earliest pending deadline across
 * the pools (FC_DEADLINE_GRAIN_NS granularity), re-armed on every park and
 * after every pass; with no waiter anywhere it is not armed and the pass
 * does not run. The pass reads one atomic per pool (fc_queue_next_deadline)
 * and enters only the queues whose earliest deadline has passed, where it
 * copies the entries past theirs (fc_queue_expired) and hands each to the
 * expire function, which ends the request through the CAS settle
 * (fc_queue_take) exactly as before: nothing here walks a connection list. */

/* The earliest deadline among a pool's waiting entries, 0 for none. */
uint64_t fc_queue_next_deadline(const fc_state_t *fc);

/* Copy, oldest first, the live entries whose deadline is at or before
 * now_ns, up to cap; nothing is taken out (the expire path takes its entry
 * through fc_queue_take, which may find it gone to its turn or its
 * cancellation first). Returns how many were copied. */
uint32_t fc_queue_expired(fc_state_t *fc, uint64_t now_ns,
                          fc_queue_ent_t *out, uint32_t cap);

#define FC_DEADLINE_GRAIN_NS 25000000ULL   /* the timer fires at most every 25 ms */

typedef struct fc_deadline {
  int tfd;                       /* the timerfd; <= 0: no timer (nothing arms, nothing fires) */
  _Atomic uint64_t armed_ns;     /* the absolute time the timer is set for, 0 = disarmed */
  _Atomic uint64_t last_fire_ns; /* when it last fired, 0 = never */
  _Atomic uint64_t wakeups;      /* times it fired */
  _Atomic uint64_t passes;       /* times the pass ran */
} fc_deadline_t;

/* The process's timer; fc_deadline_init opens its timerfd (proxy_main, before
 * any worker thread exists: the drain checker reads tfd on every pass). Until then (every unit that does not test the timer) arming is a
 * no-op. */
fc_deadline_t *fc_deadline_global(void);
int  fc_deadline_init(fc_deadline_t *d);
void fc_deadline_close(fc_deadline_t *d);

/* A deadline came into existence (a park, a woken request going back): the
 * timer is set to it when it is earlier than what it is set for, never
 * earlier than the last firing plus the grain. */
void fc_deadline_arm(fc_deadline_t *d, uint64_t deadline_ns, uint64_t now_ns);

/* Block until the timer fires (1) or for at most max_wait_ms (0; -1 = no
 * bound) or fails (-1). The timer is one-shot: fc_deadline_pass re-arms it. */
int  fc_deadline_wait(fc_deadline_t *d, int max_wait_ms);

/* The pools: `pools` calls `visit` for every pool; `expire` is handed each
 * entry whose deadline has passed, with the pool it waits in. The pass
 * re-arms the timer to the earliest deadline left across the pools (the
 * grain after now at the earliest) and returns it, 0 for none. */
typedef void (*fc_pool_visit_fn)(void *vctx, fc_state_t *fc);
typedef void (*fc_pools_fn)(void *ctx, fc_pool_visit_fn visit, void *vctx);
typedef void (*fc_expire_fn)(void *ctx, fc_state_t *fc, const fc_queue_ent_t *ent,
                             uint64_t now_ns);
uint64_t fc_deadline_pass(fc_deadline_t *d, uint64_t now_ns, fc_pools_fn pools,
                          fc_expire_fn expire, void *ctx);

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

/* A class constant as a band: anything out of range is standard. */
static inline uint8_t
fc_band_of(int cls)
{
  return (cls == FC_BAND_CRITICAL || cls == FC_BAND_SHEDDABLE) ? (uint8_t)cls
                                                              : FC_BAND_STANDARD;
}

/* The bands by rank, highest first: the order the strict wake serves them
 * in, and the order every band triple is written in, at the API and in the
 * log (critical:standard:sheddable). The one mapping between a position and
 * a band; fc_band_rank is its inverse. */
static inline uint8_t
fc_band_at_rank(int rank)
{
  static const uint8_t by_rank[FC_BANDS] = {
    FC_BAND_CRITICAL, FC_BAND_STANDARD, FC_BAND_SHEDDABLE,
  };

  return rank >= 0 && rank < FC_BANDS ? by_rank[rank] : FC_BAND_STANDARD;
}

/* Order between bands: 0 is served first. */
static inline int
fc_band_rank(uint8_t band)
{
  band = fc_band_of(band);
  for (int r = 0; r < FC_BANDS; r++)
    if (fc_band_at_rank(r) == band)
      return r;
  return FC_BANDS - 1;
}

/* Service units held, and requests waiting, in one band. Standard is the
 * total less the two counted bands; the reads are not one snapshot, so it
 * is clamped at zero. */
static inline uint32_t
fc_band_derive(uint32_t total, uint32_t crit, uint32_t shed, uint8_t band)
{
  if (band == FC_BAND_CRITICAL)
    return crit;
  if (band == FC_BAND_SHEDDABLE)
    return shed;
  return total > crit + shed ? total - crit - shed : 0;
}

static inline uint32_t
fc_band_inflight(const fc_state_t *fc, uint8_t band)
{
  if (!fc)
    return 0;
  return fc_band_derive(
      atomic_load_explicit(&fc->inflight, memory_order_relaxed),
      atomic_load_explicit(&fc->band_inflight[FC_BAND_CRITICAL], memory_order_relaxed),
      atomic_load_explicit(&fc->band_inflight[FC_BAND_SHEDDABLE], memory_order_relaxed),
      fc_band_of(band));
}

static inline uint32_t
fc_band_queued(const fc_state_t *fc, uint8_t band)
{
  if (!fc)
    return 0;
  return fc_band_derive(
      atomic_load_explicit(&fc->queued, memory_order_relaxed),
      atomic_load_explicit(&fc->band_queued[FC_BAND_CRITICAL], memory_order_relaxed),
      atomic_load_explicit(&fc->band_queued[FC_BAND_SHEDDABLE], memory_order_relaxed),
      fc_band_of(band));
}

static inline uint32_t
fc_ep_inflight(const fc_state_t *fc, int ep, int role)
{
  if (!fc || ep < 0 || ep >= FC_MAX_EP || role < 0 || role >= FC_ROLES)
    return 0;
  return atomic_load_explicit(&fc->ep_inflight[ep][role], memory_order_relaxed);
}

/* A band's wait window in force: its own, held inside the rule's window
 * (max_queue_wait_ms), else the rule's. */
static inline uint32_t
fc_band_wait_ms(const fc_state_t *fc, uint8_t band)
{
  uint32_t own;

  if (!fc)
    return 0;
  band = fc_band_of(band);
  own = fc->cfg.band_wait_ms[band];
  return own && own < fc->cfg.max_queue_wait_ms ? own : fc->cfg.max_queue_wait_ms;
}

/* The most live waiters a band may hold: its share of max_queue_depth
 * (rounded up, at least one); 0 = no bound of its own. */
uint32_t fc_band_queue_bound(const fc_state_t *fc, uint8_t band);

/* The ceiling a shed response reports beside the inflight count. */
static inline uint32_t
fc_limit_for(const fc_state_t *fc, int role)
{
  if (!fc)
    return 0;
  if (role < 0 || role >= FC_ROLES)
    return fc_svc_cap(fc);
  return fc->cfg.ep_cap[role] ? fc->cfg.ep_cap[role] : fc_svc_cap(fc);
}

/* ---- adaptive ceiling and warm-up ------------------------------------------ */

/* One step of the adaptive ceiling, once a second per pool. Backpressure
 * on a fresh signal takes the ceiling to four fifths (never below a quarter
 * of the configured one, and never below one); a fresh signal without
 * backpressure gives one unit back, up to the configured ceiling, and wakes
 * the waiters that now fit; no fresh signal holds it where it is. Only a
 * fresh signal ever raises it. */
void fc_adapt_tick(fc_state_t *fc, const fc_signal_t *sig);

/* A time-to-first-token sample for an endpoint: folded into its estimate
 * (an exponential average weighting the new sample one eighth). */
void fc_ttft_sample(fc_state_t *fc, int ep, uint32_t ms, uint64_t now_ns);

/* A streamed response's first data event for the request holding `p`:
 * its time from admission is one TTFT sample for the endpoint holding the
 * request's unit (the decode endpoint of a disaggregated request). A no-op
 * unless the permit is executing and its pool has a TTFT target. */
void fc_permit_ttft(fc_permit_t *p);

/* Whether the endpoint has a TTFT sample within the telemetry window. */
int fc_ttft_fresh(const fc_state_t *fc, int ep, uint64_t now_ns);

/* Whether the endpoint's TTFT estimate is fresh at `now_ns` and above the
 * pool's target. False when no target is set or no fresh sample exists. */
int fc_ttft_over(const fc_state_t *fc, int ep, uint64_t now_ns, int *fresh);

/* The endpoint came back into service (a breaker closed, it was added or
 * re-enabled): its ceilings ramp up over the warm-up window. A no-op when
 * the pool has no warm-up window. */
void fc_ep_warm_start(fc_state_t *fc, int ep, uint64_t now_ns);

/* Endpoints still inside their warm-up window at `now_ns`. */
uint32_t fc_warming_eps(const fc_state_t *fc, uint64_t now_ns);

/* The module's clock for warm-up and freshness: CLOCK_MONOTONIC in
 * nanoseconds, so a wall-clock step never ends or extends a window. Tests
 * replace it. */
uint64_t fc_now_ns(void);
typedef uint64_t (*fc_clock_fn)(void);
void fc_set_clock(fc_clock_fn fn);

/* ---- admission headers on admitted responses ------------------------------ */

/* What an admitted response reports: the pool's executing units and waiting
 * requests as its head goes out, and the service ceiling in force (0 is
 * none), the same three a refusal carries. */
typedef struct fc_expose {
  uint32_t inflight;
  uint32_t queued;
  uint32_t limit;
} fc_expose_t;

/* Whether the request holding `p` reports them on its response: it holds
 * its units on a pool that exposes them. Fills `out` with the values now. */
int fc_expose_take(const fc_permit_t *p, fc_expose_t *out);

enum fc_expose_h1 {
  FC_EXPOSE_H1_DONE = 0,         /* the head now carries them */
  FC_EXPOSE_H1_INTERIM,          /* a 1xx: the final response carries them */
  FC_EXPOSE_H1_SKIPPED,          /* not a whole response head, or no room */
};

/* Put the three headers into the HTTP/1.x response head at the start of
 * `buf` (`len` bytes, `cap` room), in place of any the backend sent. Only a
 * final response whose whole head is in the buffer is touched; what follows
 * the head (a body, chunks, an event stream) is moved, never read. Returns
 * the new length; `res` says which of the three happened. */
size_t fc_expose_h1(uint8_t *buf, size_t len, size_t cap, const fc_expose_t *v,
                    int *res);

const char *fc_adapt_state_name(uint8_t state);
const char *fc_adapt_reason_name(uint8_t reason);

const char *fc_reason_name(enum fc_reason reason);
const char *fc_anomaly_name(enum fc_anomaly a);
const char *fc_mode_name(uint8_t mode);

#endif /* __SOCKPROXY_FC_H__ */
