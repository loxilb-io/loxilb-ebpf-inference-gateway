/* test_pd_admission.c - Unit tests for the P/D bounded backpressured admission layer.
 * Standalone ASan test binary that COMPILES the production selector (sockproxy_pd.c)
 * directly, mirroring the test_pd_cache_aware.c mock harness, so the cap+enqueue
 * decision (pd_select_prefill's all-capped branch) is exercised end-to-end.
 *
 * Build: gcc -Wall -Wextra -fsanitize=address -o test_pd_admission \
 *        test_pd_admission.c -I. -DTEST_PD_ADMISSION -lpthread
 *
 * Cases:
 *   - smoke: mocked active_conns inc/dec (the scaffold invariant)
 *   - default-off: env UNSET -> all-capped returns PD_PREFILL_NO_CAPACITY
 *   - enqueue when all-capped (depth < bound) -> PARKED, NOT 429,
 *     the chosen EP's parked FIFO count increments
 *   - 429 ONLY when the per-EP FIFO is also full (overflow valve)
 *   - AC-5a/b: dequeue + max-park reap
 *
 * The TU is ASan-clean and wired into the `test_pd` aggregate gate.
 *
 * IMPORTANT: sockproxy_pd.c's env resolvers (pd_max_inflight_per_ep,
 * pd_queue_depth_per_ep) cache getenv-once. This binary therefore SETs both env
 * vars BEFORE the first pd_select_prefill call and uses the SAME values for every
 * case; (env-unset) runs in a forked child so its caching is isolated.
 */

#define _GNU_SOURCE
/* Reuse the cache_aware unit-test build guards in sockproxy_pd.c / sockproxy_pd_trie.c
 * (skip sockproxy.h, no proxy_struct singleton, no-op sync emit). TEST_PD_ADMISSION
 * stays defined too (Makefile -D) for this TU's own identity/comments. */
#ifndef TEST_PD_CACHE_AWARE
#define TEST_PD_CACHE_AWARE 1
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>
#include <limits.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>

/* ===== Constants (from sockproxy.h) ===== */
#define MAX_PROXY_EP      32
#define MAX_PREFIX_LEN    512
#define MAX_MODEL_LEN     128
#define MAX_CONV_ID_LEN   128
#define MAX_LORA_LEN      128
#define MAX_HASH_LEN      64
#define MAX_SALT_LEN      64

/* Circuit breaker states */
#define CB_STATE_CLOSED    0
#define CB_STATE_OPEN      1
#define CB_STATE_HALF_OPEN 2

/* C2 capacity-aware symbols referenced by pd_select_prefill's Tier-2
 * scorer — only needed for sockproxy_pd.c to compile here (never exercised). */
#ifndef PROXY_SEL_GPU_AWARE
#define PROXY_SEL_GPU_AWARE      4
#define DEFAULT_QUEUE_WEIGHT     1
#define DEFAULT_KV_CACHE_WEIGHT  1
#define DEFAULT_SWAP_WEIGHT      1
#endif

/* admission verdict + parked-FIFO mock (mirrors sockproxy.h). */
#ifndef PD_PREFILL_NO_CAPACITY
#define PD_PREFILL_NO_CAPACITY (-2)
#endif
#ifndef PD_PREFILL_PARKED
#define PD_PREFILL_PARKED (-3)
#endif
#ifndef PD_MAX_QUEUE_DEPTH
#define PD_MAX_QUEUE_DEPTH 64
#endif
typedef struct {
  int      fd;
  uint64_t gen;
  uint64_t enqueue_ns;
} pd_parked_ent_t;
typedef struct {
  pd_parked_ent_t slot[PD_MAX_QUEUE_DEPTH];
  uint16_t head, tail, count;
} pd_parked_fifo_t;

/* ===== uthash (vendored in same directory) ===== */
#include "uthash.h"

/* ===== Struct stubs (mirror test_pd_cache_aware.c) ===== */

typedef struct {
  uint32_t xip;
  uint16_t xport;
  uint8_t  inv;        /* 0=active, non-zero=inactive */
  uint8_t  protocol;
  uint8_t  weight;
  uint8_t  pad;
  uint16_t nixl_port;
} proxy_ent_t;

typedef struct {
  uint8_t state;  /* CB_STATE_CLOSED, CB_STATE_OPEN, CB_STATE_HALF_OPEN */
} circuit_breaker_t;

typedef struct {
  _Atomic uint32_t active_conns;
  _Atomic uint32_t queued_requests;
  _Atomic uint64_t total_requests;
  uint64_t last_update_ts;
  int ep_available;
  _Atomic uint32_t num_gpu_blocks;
  _Atomic uint32_t swap_pressure;
} ep_load_tracker_t;

typedef struct llm_prefix_key {
  char prefix[MAX_PREFIX_LEN];
  char model[MAX_MODEL_LEN];
  uint32_t flags;
  char lora_adapter[MAX_LORA_LEN];
  char image_hash[MAX_HASH_LEN];
  char audio_hash[MAX_HASH_LEN];
  char cache_salt[MAX_SALT_LEN];
  char tool_schemas_hash[MAX_HASH_LEN];
  char session_context_hash[MAX_HASH_LEN];
  char rag_template_hash[MAX_HASH_LEN];
  char rag_doc_ids_hash[MAX_HASH_LEN];
  uint64_t hash;
  int valid;
  int level;
} llm_prefix_key_t;

typedef struct pd_trie pd_trie_t;

typedef struct pd_session_mapping {
  char     conv_id[MAX_CONV_ID_LEN];
  int      prefill_ep_idx;
  int      decode_ep_idx;
  uint64_t created_ts;
  _Atomic uint64_t last_access_ts;
  uint32_t request_count;
  UT_hash_handle hh;
} pd_session_mapping_t;

typedef struct proxy_epval {
  int n_eps;
  int ep_sel;
  int select;
  proxy_ent_t eps[MAX_PROXY_EP];

  circuit_breaker_t circuit_breakers[MAX_PROXY_EP];
  uint8_t cb_enabled;

  uint8_t  pd_disagg_enabled;
  uint8_t  ai_gw_mode;
  uint8_t  ep_role[MAX_PROXY_EP];
  int      n_prefill_eps;
  int      n_decode_eps;

  uint8_t  pd_cache_aware_mode;
  uint8_t  pd_cache_threshold;
  uint8_t  pd_balance_abs_threshold;
  uint8_t  kv_exact_mode;
  _Atomic uint32_t pd_tier2_rr;
  _Atomic uint32_t pd_decode_rr;
  uint32_t pd_session_ttl_sec;
  ep_load_tracker_t pd_ep_loads[MAX_PROXY_EP];

  /* controller advisory mirror (sockproxy.h) — the #included
   * sockproxy_pd.c reads these in pd_select_prefill. memset-0 init == mode 0 ==
   * byte-identical selection (G3), so every existing case is untouched. */
  _Atomic uint32_t pd_ctrl_ep[MAX_PROXY_EP];
  _Atomic uint8_t  pd_ctrl_mode;

  /* bounded backpressured admission — per-EP parked FIFO */
  pd_parked_fifo_t  pd_parked[MAX_PROXY_EP];
  pthread_mutex_t   pd_parked_lock;

  pd_trie_t           *pd_trie;
  pthread_rwlock_t     pd_trie_lock;

  pd_session_mapping_t *pd_session_map;
  pthread_rwlock_t      pd_session_lock;

  UT_hash_handle hh;
} proxy_epval_t;

typedef struct proxy_fd_ent {
  int      fd;
  _Atomic uint64_t gen;                   /* pfe pool generation (parked staleness guard) */
  char conversation_id[MAX_CONV_ID_LEN];
  int has_conv_id;
  char user_id[128];
  int  has_user_id;
  llm_prefix_key_t prefix_key;
  char     x_model_header[MAX_MODEL_LEN];
  int      pd_decode_ep_idx;
  int      park_ep_idx;                   /* parked-behind prefill EP (-1 = not parked) */
  uint64_t park_start_ts;                 /* CLOCK_MONOTONIC ns at park enqueue */
} proxy_fd_ent_t;

/* ===== Log stubs ===== */
#define log_error(fmt, ...) fprintf(stderr, "ERROR: " fmt "\n", ##__VA_ARGS__)
#define log_warn(fmt, ...) fprintf(stderr, "WARN: " fmt "\n", ##__VA_ARGS__)
#define log_debug(fmt, ...) ((void)0)
#define log_info(fmt, ...)  ((void)0)

/* ===== sync-event stubs (sockproxy_pd.c references these) ===== */
typedef enum {
    SYNC_SESSION_CREATE = 0,
    SYNC_SESSION_UPDATE = 1,
    SYNC_SESSION_DELETE = 2,
    SYNC_CONV_CREATE    = 3,
    SYNC_CONV_UPDATE    = 4,
    SYNC_CONV_DELETE    = 5,
} proxy_sync_event_kind_t;

typedef struct proxy_sync_event {
    int      kind;
    char     service_key[64];
    char     conv_id[MAX_CONV_ID_LEN];
    int      prefill_ep_idx;
    int      decode_ep_idx;
    int      ep_idx;
    uint64_t created_ts;
    uint64_t last_access_ts;
    uint32_t request_count;
} proxy_sync_event_t;

static inline void llb_sockproxy_emit_sync_event(const proxy_sync_event_t *ev) {
    (void)ev;
}

/* ===== global_stats stub ===== */
typedef struct proxy_global_stats {
    _Atomic uint64_t pd_kv_t15_fallthrough_total;
    _Atomic uint64_t conversation_ttl_expirations;
    /* : mirror the production gauge+counter so pd_max_total_inflight /
     * pd_admission_should_accept compile against the included sockproxy_pd.c and the
     * counter-balance test can exercise the alloc/recycle inc/dec pattern. */
    _Atomic uint64_t pd_admission_total_inflight;
    _Atomic uint64_t pd_admission_total_blocked;
} proxy_global_stats_t;
static proxy_global_stats_t global_stats;

/* pd_kv_exact_select stub (Tier 1.5 — gated by kv_exact_mode==1, never set here) */
struct proxy_epval; struct proxy_fd_ent;
static inline int pd_kv_exact_select(struct proxy_epval *tepval,
                                     struct proxy_fd_ent *pfe,
                                     int *ep_out, uint32_t excluded_mask) {
    (void)tepval; (void)pfe; (void)ep_out; (void)excluded_mask;
    return -1;
}

/* C2 capacity-aware scorer helpers (Tier-2 GPU_AWARE branch — never taken here) */
uint64_t pd_kv_clamp_capacity(uint32_t capacity) { return capacity ? capacity : 1ULL; }
uint64_t pd_capacity_blend_score(uint32_t a, uint32_t q, uint32_t s,
                                 uint64_t ci, uint64_t tc, int n,
                                 uint32_t qw, uint32_t kw, uint32_t sw) {
  (void)a; (void)q; (void)s; (void)ci; (void)tc; (void)n; (void)qw; (void)kw; (void)sw;
  return 0;
}

/* ===== Include implementations ===== */
/* Trie must be included BEFORE sockproxy_pd.c (defines pd_trie_t type) */
#include "sockproxy_pd_trie.c"
#include "sockproxy_pd.c"

/* ===== Test framework ===== */
static int g_failures;

#define CHECK(cond, msg)                                                      \
  do {                                                                        \
    if (!(cond)) { printf("  [FAIL] %s\n", (msg)); g_failures++; }            \
    else         { printf("  [PASS] %s\n", (msg)); }                          \
  } while (0)

/* ===== Helpers ===== */

/* Build an all-prefill epval with n_prefill prefill EPs and 1 decode EP. Roles:
 * [0..n_prefill-1] = prefill (1), [n_prefill] = decode (2). All healthy, CB closed. */
static void init_admission_epval(proxy_epval_t *ev, int n_prefill) {
  memset(ev, 0, sizeof(*ev));
  ev->n_eps = n_prefill + 1;
  ev->pd_disagg_enabled = 1;
  ev->pd_cache_aware_mode = 0;     /* keep selection on the min-load tiers, not the trie */
  ev->cb_enabled = 1;
  ev->pd_session_ttl_sec = 0;
  pthread_rwlock_init(&ev->pd_session_lock, NULL);
  pthread_rwlock_init(&ev->pd_trie_lock, NULL);
  pthread_mutex_init(&ev->pd_parked_lock, NULL);
  ev->pd_trie = NULL;
  ev->pd_session_map = NULL;
  for (int i = 0; i < n_prefill; i++) {
    ev->ep_role[i] = 1;            /* prefill */
    ev->circuit_breakers[i].state = CB_STATE_CLOSED;
  }
  ev->ep_role[n_prefill] = 2;      /* decode */
  ev->circuit_breakers[n_prefill].state = CB_STATE_CLOSED;
  ev->n_prefill_eps = n_prefill;
  ev->n_decode_eps = 1;
}

static void cleanup_admission_epval(proxy_epval_t *ev) {
  pthread_rwlock_destroy(&ev->pd_session_lock);
  pthread_rwlock_destroy(&ev->pd_trie_lock);
  pthread_mutex_destroy(&ev->pd_parked_lock);
}

static void init_admission_pfe(proxy_fd_ent_t *pfe, int fd) {
  memset(pfe, 0, sizeof(*pfe));
  pfe->fd = fd;
  pfe->pd_decode_ep_idx = -1;
  pfe->park_ep_idx = -1;            /* "not parked" sentinel (matches pfe_alloc) */
  atomic_store(&pfe->gen, 1ULL);
}

/* ===== smoke ( scaffold) ===== */
static void test_active_conns_inc_dec(void) {
  ep_load_tracker_t ep;
  atomic_store(&ep.active_conns, 0u);
  atomic_store(&ep.queued_requests, 0u);
  atomic_fetch_add(&ep.active_conns, 1u);
  atomic_fetch_add(&ep.active_conns, 1u);
  CHECK(atomic_load(&ep.active_conns) == 2u, "active_conns increments on dispatch");
  atomic_fetch_sub(&ep.active_conns, 1u);
  CHECK(atomic_load(&ep.active_conns) == 1u, "active_conns decrements on slot-free");
  atomic_fetch_sub(&ep.active_conns, 1u);
  CHECK(atomic_load(&ep.active_conns) == 0u, "active_conns returns to 0 (no underflow)");
  CHECK(atomic_load(&ep.queued_requests) == 0u, "queued_requests starts empty (FIFO scaffold)");
}

/* Drive all prefill EPs to the in-flight cap so the next selection hits the
 * all-capped branch. cap is the value passed to LLB_PD_MAX_INFLIGHT_PER_EP. */
static void saturate_prefill(proxy_epval_t *ev, int n_prefill, uint32_t cap) {
  for (int i = 0; i < n_prefill; i++)
    atomic_store(&ev->pd_ep_loads[i].active_conns, cap);
}

/* ===== : default-off (env UNSET) -> all-capped sheds, NEVER parks ===== *
 * Runs in a forked child so this process's getenv-once cache (which the SET
 * cases below need) is not poisoned by the unset state. */
static void test_ac1_default_off_child(void) {
  /* Child: env explicitly UNSET. cap set so the all-capped branch is reached. */
  unsetenv("LLB_PD_QUEUE_DEPTH_PER_EP");
  setenv("LLB_PD_MAX_INFLIGHT_PER_EP", "2", 1);
  proxy_epval_t ev; proxy_fd_ent_t pfe;
  init_admission_epval(&ev, 2);
  init_admission_pfe(&pfe, 100);
  saturate_prefill(&ev, 2, 2);
  int ep = -123;
  int rc = pd_select_prefill(&ev, &pfe, &ep, 0);
  int ok = (rc == PD_PREFILL_NO_CAPACITY)
        && (ev.pd_parked[0].count == 0) && (ev.pd_parked[1].count == 0)
        && (pfe.park_ep_idx == -1);
  cleanup_admission_epval(&ev);
  _exit(ok ? 0 : 1);
}

static void test_ac1_default_off(void) {
  pid_t pid = fork();
  if (pid == 0) {
    test_ac1_default_off_child();   /* never returns */
  }
  int st = 1;
  if (pid > 0) waitpid(pid, &st, 0);
  CHECK(pid > 0 && WIFEXITED(st) && WEXITSTATUS(st) == 0,
        "AC-1: env-UNSET all-capped returns PD_PREFILL_NO_CAPACITY (sheds, never parks)");
}

/* ===== : all-capped + FIFO has room -> PARKED (not 429), count++ ===== */
static void test_ac2_enqueue_not_shed(proxy_epval_t *ev) {
  /* env: cap=2, depth=2. All 2 prefill EPs saturated. */
  proxy_fd_ent_t pfe;
  init_admission_pfe(&pfe, 200);
  saturate_prefill(ev, 2, 2);

  int ep = -123;
  int rc = pd_select_prefill(ev, &pfe, &ep, 0);
  CHECK(rc == PD_PREFILL_PARKED, ": all-capped + FIFO room returns PD_PREFILL_PARKED (not 429)");
  CHECK(ep >= 0 && ep < 2, ": parked EP index exposed (a prefill EP)");
  /* exactly one of the two prefill FIFOs took the entry */
  uint32_t total = ev->pd_parked[0].count + ev->pd_parked[1].count;
  CHECK(total == 1u, ": chosen EP's parked FIFO count incremented (held, not shed)");
  CHECK(ep >= 0 && ev->pd_parked[ep].count == 1u, ": the increment landed on the exposed EP");
  CHECK(pfe.park_ep_idx == ep, ": pfe->park_ep_idx records the parked EP");
  CHECK(pfe.park_start_ts != 0, ": pfe->park_start_ts stamped at enqueue");
  CHECK(ev->pd_parked[ep].slot[0].fd == 200, ": parked entry carries the client fd");
  CHECK(ev->pd_parked[ep].slot[0].gen == 1u, ": parked entry carries the pfe gen (staleness guard)");

  /* active_conns invariant: parking charges NO EP (charged<=>dispatched). */
  CHECK(atomic_load(&ev->pd_ep_loads[0].active_conns) == 2u,
        "AC-2: parking leaves prefill EP0 active_conns unchanged");
  CHECK(atomic_load(&ev->pd_ep_loads[1].active_conns) == 2u,
        "AC-2: parking leaves prefill EP1 active_conns unchanged");
}

/* ===== : all-capped + every FIFO at bound -> overflow 429 ===== */
static void test_ac3_overflow_shed(proxy_epval_t *ev) {
  /* depth bound = 2. Fill BOTH prefill FIFOs to the bound. */
  for (int e = 0; e < 2; e++) {
    pd_parked_fifo_t *q = &ev->pd_parked[e];
    q->head = q->tail = q->count = 0;
    for (int k = 0; k < 2; k++) {       /* bound = 2 */
      q->slot[q->tail].fd = 9000 + e * 10 + k;
      q->slot[q->tail].gen = 1u;
      q->slot[q->tail].enqueue_ns = 1u;
      q->tail = (uint16_t)((q->tail + 1) % PD_MAX_QUEUE_DEPTH);
      q->count++;
    }
  }
  saturate_prefill(ev, 2, 2);

  proxy_fd_ent_t pfe;
  init_admission_pfe(&pfe, 300);
  int ep = -123;
  int rc = pd_select_prefill(ev, &pfe, &ep, 0);
  CHECK(rc == PD_PREFILL_NO_CAPACITY,
        "AC-3: all-capped + every FIFO full returns PD_PREFILL_NO_CAPACITY (overflow 429)");
  CHECK(ev->pd_parked[0].count == 2u && ev->pd_parked[1].count == 2u,
        "AC-3: FIFOs unchanged on overflow (no enqueue past the bound)");
  CHECK(pfe.park_ep_idx == -1, ": overflow request is NOT parked (park_ep_idx stays -1)");
}

/* ===== AC-5a: enqueue -> slot-free dequeue -> entry removed (FIFO pop, gen-guard) =====
 *
 * The production dequeue-on-slot-free hook (sockproxy_http.c pd_cleanup) and the
 * owner-worker re-drive (pd_resume_parked) live in TUs not compiled here (they need
 * sockproxy_http/notify). This case exercises the FIFO-level contract those paths
 * depend on, against the SAME production primitives (pd_parked_pop_head /
 * pd_parked_remove_fd) the hook calls: (1) park N -> the chosen EP's FIFO holds them
 * oldest-first; (2) a slot-free pops the OLDEST (FIFO order), decrementing count
 * exactly once (single-owner, no double-pop); (3) the popped entry carries the (fd,gen)
 * the resume path gen-validates; (4) a STALE entry (gen mismatch vs the live pfe) is
 * dropped by the gen-guard, never re-dispatched. ASan-clean throughout. */
static void test_ac5a_dequeue_on_free(proxy_epval_t *ev) {
  /* Park three distinct clients behind the saturated prefill EPs. */
  saturate_prefill(ev, 2, 2);
  int parked_eps[3], parked_fds[3] = { 410, 411, 412 };
  uint64_t parked_gens[3] = { 1u, 1u, 1u };
  for (int k = 0; k < 3; k++) {
    proxy_fd_ent_t pfe;
    init_admission_pfe(&pfe, parked_fds[k]);
    int ep = -123;
    int rc = pd_select_prefill(ev, &pfe, &ep, 0);
    CHECK(rc == PD_PREFILL_PARKED, "AC-5a: client parked behind a capped prefill EP");
    parked_eps[k] = ep;
    parked_gens[k] = atomic_load(&pfe.gen);
  }

  /* Pick the EP that took the FIRST parked client and simulate a slot-free dequeue
   * (exactly what pd_cleanup's hook does: pop the FIFO head under pd_parked_lock). */
  int e = parked_eps[0];
  uint32_t before = ev->pd_parked[e].count;
  CHECK(before >= 1u, "AC-5a: target prefill EP has a parked head to dequeue");

  pd_parked_ent_t popped = { 0 };
  pthread_mutex_lock(&ev->pd_parked_lock);
  int have = pd_parked_pop_head(&ev->pd_parked[e], &popped);
  pthread_mutex_unlock(&ev->pd_parked_lock);

  CHECK(have == 1, "AC-5a: slot-free pops the parked FIFO head");
  CHECK(ev->pd_parked[e].count == before - 1u,
        "AC-5a: FIFO count decremented exactly once (single-owner, no double-pop)");
  CHECK(popped.fd == parked_fds[0],
        "AC-5a: popped the OLDEST parked entry (FIFO order)");
  CHECK(popped.gen == parked_gens[0],
        "AC-5a: popped entry carries the (fd,gen) the resume path gen-validates");

  /* gen-guard: a popped entry whose gen no longer matches the live pfe (slot recycled)
   * must be treated as STALE and dropped — never re-dispatched. We model the resume
   * gen-check here (pd_resume_parked compares popped.gen against the live pfe->gen). */
  uint64_t live_gen_recycled = popped.gen + 1;   /* the slot was recycled since enqueue */
  int stale_dropped = (popped.gen != live_gen_recycled);
  CHECK(stale_dropped, "AC-5a: gen mismatch (recycled fd) is detected -> stale entry dropped");

  /* Empty-FIFO pop is a safe no-op (the hook's guard for an already-drained EP). */
  pd_parked_fifo_t empty = { 0 };
  pd_parked_ent_t none = { 0 };
  CHECK(pd_parked_pop_head(&empty, &none) == 0,
        "AC-5a: pop on an empty FIFO is a safe no-op (no underflow)");
}

/* ===== AC-5b: max-park reap — an aged parked entry is removed; a younger one stays ===
 *
 * The reap pass (sockproxy_health.c) tears the aged conn down via the single-owner
 * pd_teardown_conn (not compiled here) but FIRST removes it from its EP FIFO via
 * pd_parked_remove_fd under pd_parked_lock. This case exercises that removal contract
 * + the age decision (env LLB_PD_MAX_PARK_SEC via pd_max_park_sec): an entry older than
 * max-park is removed (FIFO count drops, FIFO-order of survivors preserved, ASan-clean);
 * a younger entry is left in place (not reaped early); double-remove is a safe no-op. */
static void test_ac5b_max_park_reap(void) {
  /* Build a single EP FIFO with two entries: one AGED, one YOUNG. enqueue_ns is the
   * monotonic stamp the reap compares against now - max_park_ns. */
  pd_parked_fifo_t q = { 0 };
  uint64_t now_ns = 1000ULL * 1000000000ULL;            /* arbitrary monotonic 'now' */
  uint32_t max_park = pd_max_park_sec();                 /* env LLB_PD_MAX_PARK_SEC */
  if (max_park == 0) max_park = 5;                        /* unit default if env unset */
  uint64_t max_park_ns = (uint64_t)max_park * 1000000000ULL;

  /* aged: enqueued (max_park + 2)s ago -> past the bound. young: 0s ago -> within. */
  uint64_t aged_ns  = now_ns - (max_park_ns + 2ULL * 1000000000ULL);
  uint64_t young_ns = now_ns;

  q.slot[q.tail].fd = 510; q.slot[q.tail].gen = 7u; q.slot[q.tail].enqueue_ns = aged_ns;
  q.tail = (uint16_t)((q.tail + 1) % PD_MAX_QUEUE_DEPTH); q.count++;
  q.slot[q.tail].fd = 511; q.slot[q.tail].gen = 7u; q.slot[q.tail].enqueue_ns = young_ns;
  q.tail = (uint16_t)((q.tail + 1) % PD_MAX_QUEUE_DEPTH); q.count++;

  CHECK(q.count == 2u, "AC-5b: two parked entries enqueued (one aged, one young)");

  /* Reap decision on the head (oldest): aged -> reap. Mirror the health.c age test. */
  pd_parked_ent_t head = { 0 };
  CHECK(pd_parked_peek_head(&q, &head) == 1, "AC-5b: peek head returns the oldest entry");
  int head_aged = (now_ns >= head.enqueue_ns) &&
                  ((now_ns - head.enqueue_ns) >= max_park_ns);
  CHECK(head_aged, "AC-5b: head entry is older than LLB_PD_MAX_PARK_SEC (reapable)");

  /* The reap removes the aged entry (by fd+gen) — pd_parked_remove_fd, FIFO-safe. */
  int removed = pd_parked_remove_fd(&q, 510, 7u);
  CHECK(removed == 1, "AC-5b: aged parked entry removed from its EP FIFO");
  CHECK(q.count == 1u, "AC-5b: FIFO count decremented (only the aged entry reaped)");

  /* The younger entry must survive and remain reachable as the new head. */
  pd_parked_ent_t survivor = { 0 };
  CHECK(pd_parked_peek_head(&q, &survivor) == 1, "AC-5b: survivor still in FIFO");
  CHECK(survivor.fd == 511,
        "AC-5b: younger entry left in place (not reaped early), FIFO order preserved");
  int young_aged = (now_ns >= survivor.enqueue_ns) &&
                   ((now_ns - survivor.enqueue_ns) >= max_park_ns);
  CHECK(!young_aged, "AC-5b: younger entry is NOT past max-park (would not be reaped)");

  /* Double-remove (e.g. a dequeue already popped it, then the reap also tries) is a
   * safe no-op — no double-free / underflow (the single-owner teardown invariant). */
  int removed_again = pd_parked_remove_fd(&q, 510, 7u);
  CHECK(removed_again == 0, "AC-5b: re-removing an already-reaped entry is a safe no-op");
  CHECK(q.count == 1u, "AC-5b: count unchanged on the no-op re-remove (no underflow)");
}

/* =====  : global total-footprint bound + accept backpressure ===== */

/* Mirror the production pfe_alloc/pfe_recycle gauge mutation (sockproxy_conn.c) so
 * the inc/dec balance + the >0 underflow guard are exercised without compiling the
 * whole connection layer. inc once per checkout, dec (>0-guarded) once per free. */
static void admission_gauge_alloc(void) {
  atomic_fetch_add_explicit(&global_stats.pd_admission_total_inflight, 1,
                            memory_order_relaxed);
}
static void admission_gauge_recycle(void) {
  if (atomic_load_explicit(&global_stats.pd_admission_total_inflight,
                           memory_order_relaxed) > 0)
    atomic_fetch_sub_explicit(&global_stats.pd_admission_total_inflight, 1,
                              memory_order_relaxed);
}

/* : the global gauge increments on a pfe_alloc-equivalent, decrements on a
 * pfe_recycle-equivalent, is balanced (returns to baseline), and NEVER underflows
 * (a dec below 0 is a guarded no-op). */
static void test_ac4_gauge_balanced(void) {
  atomic_store(&global_stats.pd_admission_total_inflight, 0ull);

  admission_gauge_alloc();
  admission_gauge_alloc();
  admission_gauge_alloc();
  CHECK(atomic_load(&global_stats.pd_admission_total_inflight) == 3ull,
        "AC-4: gauge increments on each pfe_alloc-equivalent (3 checkouts)");

  admission_gauge_recycle();
  admission_gauge_recycle();
  admission_gauge_recycle();
  CHECK(atomic_load(&global_stats.pd_admission_total_inflight) == 0ull,
        "AC-4: gauge returns to baseline after alloc+free (balanced like active_conns)");

  /* Extra free past zero must NOT underflow (guarded no-op, mirrors pfe_pool_live). */
  admission_gauge_recycle();
  admission_gauge_recycle();
  CHECK(atomic_load(&global_stats.pd_admission_total_inflight) == 0ull,
        "AC-4: gauge never underflows below 0 (>0-guarded dec)");
}

/* : pd_admission_should_accept — the pure accept-gate decision.
 *  - bound==0 (feature off): ALWAYS accept (byte-identical accept path).
 *  - under the bound: accept.
 *  - at / over the bound: refuse (SYN stays in the listen backlog). */
static void test_ac4_gate_decision(void) {
  CHECK(pd_admission_should_accept(0, 0) == 1,
        "AC-4: bound=0 (unset) always ACCEPTs — byte-identical when feature off");
  CHECK(pd_admission_should_accept(1000000, 0) == 1,
        "AC-4: bound=0 ACCEPTs even at huge in-flight (feature off = no gate)");
  CHECK(pd_admission_should_accept(0, 8) == 1,
        "AC-4: 0 in-flight under bound=8 -> ACCEPT");
  CHECK(pd_admission_should_accept(7, 8) == 1,
        "AC-4: 7 in-flight under bound=8 -> ACCEPT (strictly-under)");
  CHECK(pd_admission_should_accept(8, 8) == 0,
        "AC-4: at the bound (8>=8) -> REFUSE (leave SYN in listen backlog)");
  CHECK(pd_admission_should_accept(9, 8) == 0,
        "AC-4: over the bound (9>=8) -> REFUSE");
}

/* : pd_max_total_inflight env resolver — forked so the parent's getenv-once
 * cache (already resolved for cap/depth/max-park) is not poisoned. */
static void test_ac4_resolver_unset_child(void) {
  unsetenv("LLB_PD_MAX_TOTAL_INFLIGHT");
  _exit(pd_max_total_inflight() == 0 ? 0 : 1);   /* unset == DISABLED (0) */
}
static void test_ac4_resolver_set_child(void) {
  setenv("LLB_PD_MAX_TOTAL_INFLIGHT", "256", 1);
  uint32_t v = pd_max_total_inflight();
  /* cached: a second read must agree, and reject a later mutation. */
  setenv("LLB_PD_MAX_TOTAL_INFLIGHT", "999", 1);
  _exit((v == 256 && pd_max_total_inflight() == 256) ? 0 : 1);
}
static void run_forked(void (*child)(void), const char *msg) {
  pid_t pid = fork();
  if (pid == 0) child();           /* never returns */
  int st = 1;
  if (pid > 0) waitpid(pid, &st, 0);
  CHECK(pid > 0 && WIFEXITED(st) && WEXITSTATUS(st) == 0, msg);
}

int main(void) {
  printf("=== /05/06 admission-layer unit tests (test_pd_admission) ===\n");

  /* smoke + first ( forks; the parent's getenv cache is still pristine). */
  test_active_conns_inc_dec();
  test_ac1_default_off();

  /* Now SET the env vars (cap=2, depth=2, max-park=5s) for the SET cases. The
   * getenv-once caches resolve on the first call below and hold for all of them.
   * depth=2 keeps 's overflow-at-bound=2 valid; AC-5a parks 2 clients (one per
   * EP) so both fit within the bound. */
  setenv("LLB_PD_MAX_INFLIGHT_PER_EP", "2", 1);
  setenv("LLB_PD_QUEUE_DEPTH_PER_EP", "2", 1);
  setenv("LLB_PD_MAX_PARK_SEC", "5", 1);

  {
    proxy_epval_t ev;
    init_admission_epval(&ev, 2);
    test_ac2_enqueue_not_shed(&ev);
    cleanup_admission_epval(&ev);
  }
  {
    proxy_epval_t ev;
    init_admission_epval(&ev, 2);
    test_ac3_overflow_shed(&ev);
    cleanup_admission_epval(&ev);
  }
  {
    /* AC-5a: enqueue -> slot-free dequeue (FIFO pop + gen-guard). */
    proxy_epval_t ev;
    init_admission_epval(&ev, 2);
    test_ac5a_dequeue_on_free(&ev);
    cleanup_admission_epval(&ev);
  }
  /* AC-5b: max-park reap (FIFO removal by age + survivor preservation). */
  test_ac5b_max_park_reap();

  /*  : global total-footprint bound + accept backpressure decision.
   * The pure gate + gauge tests are env-independent; the resolver tests fork so
   * the getenv-once cache (this process already resolved cap/depth/max-park) is
   * never poisoned by the SET/UNSET probes. */
  test_ac4_gauge_balanced();
  test_ac4_gate_decision();
  run_forked(test_ac4_resolver_unset_child,
             "AC-4: LLB_PD_MAX_TOTAL_INFLIGHT unset -> pd_max_total_inflight()==0 (DISABLED)");
  run_forked(test_ac4_resolver_set_child,
             "AC-4: LLB_PD_MAX_TOTAL_INFLIGHT=256 -> resolver caches 256 (ignores later mutation)");

  if (g_failures) {
    printf("test_pd_admission: FAIL (%d)\n", g_failures);
    return 1;
  }
  printf("test_pd_admission: PASS\n");
  return 0;
}
