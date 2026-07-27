/* test_pd_ctrl.c - Unit tests for the global-AI-controller
 * advisory influence plumbing in the P/D prefill selector.
 * Standalone ASan test binary that COMPILES the production selector
 * (sockproxy_pd.c) directly, mirroring the test_pd_admission.c mock harness,
 * so the mode guard, the DISABLED/DRAINING fold-ins and the Tier-2 weight
 * scaling are exercised end-to-end against the REAL tier stack.
 *
 * Build: gcc -Wall -Wextra -fsanitize=address -o test_pd_ctrl \
 *        test_pd_ctrl.c -I. -DTEST_PD_CTRL -lpthread
 *
 * Cases:
 *   - TC-1  G3 identity: pd_ctrl_mode==0 + all pd_ctrl_ep[] zero -> the FULL
 *           selection SEQUENCE over 1000 calls is byte-identical (memcmp) to a
 *           pre-96 COMP-07 Tier-2 reference (min conns+queued, RR advance ONLY
 *           on genuine tie — the shipped Phase-95 contract)          -> SNAP-03/G3
 *   - TC-2  DISABLED: mode=1, EP2 packed (DISABLED<<24)|100 -> EP2 receives
 *           ZERO selections over 1000 calls; the others absorb them  -> SNAP-03
 *   - TC-3  DRAINING: mode=1, EP1 DRAINING -> EP1 excluded from NEW-session
 *           assignment; clearing the packed word (write 0) restores
 *           selections (the advisory vanishes with the snapshot)     -> SNAP-03
 *   - TC-4  weight: mode=1, EP0 weight=50 others 100 on the GPU_AWARE Tier-2
 *           blend (REAL pd_capacity_blend_score via sockproxy_kv_exact.h) ->
 *           EP0's selection share over 5000 closed-loop calls falls below
 *           0.75x its mode-0 share (deterministic, no RNG)           -> SNAP-03
 *   - TC-5  G4 non-resurrection: EP3 locally ineligible (CB_STATE_OPEN, and
 *           separately excluded_mask) while the packed word says
 *           ACTIVE|weight=100 -> EP3 receives ZERO selections (the applier's
 *           word can never resurrect a locally-excluded EP)          -> SNAP-04/G4
 *   - TC-6  mode-0 packed-nonzero: pd_ctrl_ep[] nonzero BUT mode=0 -> sequence
 *           still identical to the TC-1 reference (the MODE guard, not the
 *           array, is the gate)                                      -> SNAP-03/G3
 *
 * The TU is ASan-clean and wired into the `test_pd` aggregate gate (9th unit).
 *
 * IMPORTANT: sockproxy_pd.c's env resolvers (pd_max_inflight_per_ep,
 * pd_queue_depth_per_ep, pd_kv_loadguard_on, ...) cache getenv-once. EVERY
 * case here wants them DISABLED (the default), so main() unsetenv()s the lot
 * BEFORE the first pd_select_prefill call and no case ever sets them — no
 * fork isolation is required (unlike test_pd_admission.c's AC-1, there is no
 * env mutation between cases to isolate). */

#define _GNU_SOURCE
/* Reuse the cache_aware unit-test build guards in sockproxy_pd.c /
 * sockproxy_pd_trie.c (skip sockproxy.h, no proxy_struct singleton, no-op
 * sync emit). TEST_PD_CTRL stays defined too (Makefile -D) for this TU's own
 * identity/comments. */
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

/* C2 capacity-aware (81-07) symbols referenced by pd_select_prefill's Tier-2
 * scorer. TC-4 EXERCISES the GPU_AWARE branch, so unlike test_pd_admission.c
 * the blend math must be REAL — pd_kv_clamp_capacity/pd_capacity_blend_score
 * come from sockproxy_kv_exact.h below (the production static inlines), and
 * only the selector-arm constant + weights are mirrored here. */
#ifndef PROXY_SEL_GPU_AWARE
#define PROXY_SEL_GPU_AWARE      4
#define DEFAULT_QUEUE_WEIGHT     50
#define DEFAULT_KV_CACHE_WEIGHT  20
#define DEFAULT_SWAP_WEIGHT      30
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

/* ===== Real C2 blend math (production static inlines) =====
 * pd_kv_clamp_capacity + pd_capacity_blend_score + pd_capacity_weighted_cap.
 * Included so TC-4's weight assertion runs the SAME arithmetic the data path
 * runs (a mirrored stub could drift and green-wash the weight influence). */
#include "sockproxy_kv_exact.h"

/* ===== uthash (vendored in same directory) ===== */
#include "uthash.h"

/* ===== Struct stubs (mirror test_pd_admission.c) ===== */

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

  /* the fields under test — controller advisory mirror
   * (sockproxy.h). memset-0 init == mode 0 == byte-identical selection (G3). */
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
  _Atomic uint64_t gen;
  char conversation_id[MAX_CONV_ID_LEN];
  int has_conv_id;
  char user_id[128];
  int  has_user_id;
  llm_prefix_key_t prefix_key;
  char     x_model_header[MAX_MODEL_LEN];
  int      pd_decode_ep_idx;
  int      park_ep_idx;
  uint64_t park_start_ts;
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
    _Atomic uint64_t pd_admission_total_inflight;
    _Atomic uint64_t pd_admission_total_blocked;
} proxy_global_stats_t;
static proxy_global_stats_t global_stats;

/* pd_kv_exact_select stub (Tier 1.5 — gated by kv_exact_mode==1, never set
 * here). NON-static: sockproxy_kv_exact.h (included above for the real blend
 * math) declares the extern prototype, so a static definition would clash. */
int pd_kv_exact_select(struct proxy_epval *tepval,
                       struct proxy_fd_ent *pfe,
                       int *ep_out, uint32_t excluded_mask) {
    (void)tepval; (void)pfe; (void)ep_out; (void)excluded_mask;
    return -1;
}

/* record_kv_stage is declared by sockproxy_kv_exact.h; sockproxy_pd.c never
 * calls it, but provide a no-op so the TU links standalone if it ever does. */
void record_kv_stage(int stage, int is_hit, uint64_t latency_us) {
    (void)stage; (void)is_hit; (void)latency_us;
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

/* Build an epval with n_prefill prefill EPs and 1 decode EP. Roles:
 * [0..n_prefill-1] = prefill (1), [n_prefill] = decode (2). All healthy, CB
 * closed, all pd_ctrl_* ZERO (the production calloc-at-proxy_add state). */
static void init_ctrl_epval(proxy_epval_t *ev, int n_prefill) {
  memset(ev, 0, sizeof(*ev));
  ev->n_eps = n_prefill + 1;
  ev->pd_disagg_enabled = 1;
  ev->pd_cache_aware_mode = 0;     /* keep selection on the Tier-2 min-load path */
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

static void cleanup_ctrl_epval(proxy_epval_t *ev) {
  pthread_rwlock_destroy(&ev->pd_session_lock);
  pthread_rwlock_destroy(&ev->pd_trie_lock);
  pthread_mutex_destroy(&ev->pd_parked_lock);
}

static void init_ctrl_pfe(proxy_fd_ent_t *pfe, int fd) {
  memset(pfe, 0, sizeof(*pfe));
  pfe->fd = fd;
  pfe->pd_decode_ep_idx = -1;
  pfe->park_ep_idx = -1;
  atomic_store(&pfe->gen, 1ULL);
}

/* Pack a controller instruction word: state bits 31-24, weight bits 7-0
 * (PD_CTRL_STATE/PD_CTRL_WEIGHT accessors from sockproxy_pd.c's idempotent
 * define block — lockstep with the frozen aictrl.v1 EpState enum). */
static uint32_t ctrl_pack(uint32_t state, uint32_t weight) {
  return (state << 24) | (weight & 0xffu);
}

/* The TC-1/TC-6 mixed-load fixture: 4 prefill EPs, static loads chosen so the
 * COMP-07 score (conns+queued) is {2,1,4,1} -> EP1 and EP3 tie at the minimum
 * and the RR tie-breaker must alternate between them (exercises both the
 * composite score and the genuine-tie-only RR advance, Bug5 contract). */
static void seed_mixed_loads(proxy_epval_t *ev) {
  atomic_store(&ev->pd_ep_loads[0].active_conns, 2u);
  atomic_store(&ev->pd_ep_loads[0].queued_requests, 0u);
  atomic_store(&ev->pd_ep_loads[1].active_conns, 0u);
  atomic_store(&ev->pd_ep_loads[1].queued_requests, 1u);
  atomic_store(&ev->pd_ep_loads[2].active_conns, 4u);
  atomic_store(&ev->pd_ep_loads[2].queued_requests, 0u);
  atomic_store(&ev->pd_ep_loads[3].active_conns, 1u);
  atomic_store(&ev->pd_ep_loads[3].queued_requests, 0u);
}

/* ===== Pre-96 COMP-07 Tier-2 reference selector (the G3 baseline) =====
 *
 * A from-the-contract reimplementation of the SHIPPED Phase-95 Tier-2 path
 * for a P/D service with cache-aware/kv-exact/session tiers all inactive:
 *   - eligibility: role==prefill, !inv, !excluded, CB not OPEN
 *   - score      : active_conns + queued_requests (COMP-07)
 *   - winner     : min score; ties collected in index order; RR counter
 *                  advances ONLY on a genuine tie (Bug5) and indexes the
 *                  candidate array modulo its length.
 * This encodes the PRE-96 selection semantics independently of the new
 * controller code — if the mode-0 production sequence diverges from this
 * reference, G3 is broken (that is exactly what TC-1/TC-6 machine-check). */
static uint32_t ref_rr;

static int ref_tier2_select(const proxy_epval_t *ev, uint32_t excluded_mask) {
  uint64_t best = UINT64_MAX;
  int cand[MAX_PROXY_EP], nc = 0;
  for (int i = 0; i < ev->n_eps; i++) {
    if (ev->ep_role[i] != 1 || ev->eps[i].inv) continue;
    if (excluded_mask & (1u << (unsigned)i)) continue;
    if (ev->cb_enabled &&
        ev->circuit_breakers[i].state == CB_STATE_OPEN) continue;
    uint64_t score = (uint64_t)atomic_load(&ev->pd_ep_loads[i].active_conns) +
                     (uint64_t)atomic_load(&ev->pd_ep_loads[i].queued_requests);
    if (score < best) { best = score; cand[0] = i; nc = 1; }
    else if (score == best) { cand[nc++] = i; }
  }
  if (nc <= 0) return -1;
  uint32_t rr = (nc > 1) ? ref_rr++ : 0;
  return cand[rr % (uint32_t)nc];
}

#define SEQ_LEN 1000

/* Run pd_select_prefill SEQ_LEN times against ev, recording the selection
 * sequence into seq[]. Asserts rc==0 on every call (returns 0 on any rc!=0). */
static int record_sequence(proxy_epval_t *ev, int *seq, int n) {
  proxy_fd_ent_t pfe;
  for (int k = 0; k < n; k++) {
    init_ctrl_pfe(&pfe, 100 + k);
    int ep = -1;
    if (pd_select_prefill(ev, &pfe, &ep, 0) != 0) return 0;
    seq[k] = ep;
  }
  return 1;
}

/* ===== TC-1: G3 identity at mode 0 / zeroed array ===== */
static int tc1_seq[SEQ_LEN];   /* kept for TC-6's cross-check */
static int tc1_ref[SEQ_LEN];

static void test_tc1_g3_identity(void) {
  printf("TC-1: G3 identity — mode 0, pd_ctrl_ep[] all-zero\n");
  proxy_epval_t ev;
  init_ctrl_epval(&ev, 4);
  seed_mixed_loads(&ev);

  CHECK(record_sequence(&ev, tc1_seq, SEQ_LEN),
        "TC-1: 1000 selections all returned rc==0");

  /* Reference sequence with its own RR counter starting at the same zero-init. */
  ref_rr = 0;
  for (int k = 0; k < SEQ_LEN; k++) tc1_ref[k] = ref_tier2_select(&ev, 0);

  CHECK(memcmp(tc1_seq, tc1_ref, sizeof(tc1_seq)) == 0,
        "TC-1 (G3): mode-0 sequence memcmp-IDENTICAL to the pre-96 COMP-07 reference");

  /* Sanity: the fixture really exercises the RR tie (both EP1 and EP3 appear). */
  int saw1 = 0, saw3 = 0;
  for (int k = 0; k < SEQ_LEN; k++) {
    if (tc1_seq[k] == 1) saw1++;
    if (tc1_seq[k] == 3) saw3++;
  }
  CHECK(saw1 > 0 && saw3 > 0 && saw1 + saw3 == SEQ_LEN,
        "TC-1: fixture exercised the genuine-tie RR path (EP1+EP3 only)");
  cleanup_ctrl_epval(&ev);
}

/* ===== TC-2: DISABLED folds into excluded_mask ===== */
static void test_tc2_disabled(void) {
  printf("TC-2: DISABLED — mode 1, EP2 (DISABLED<<24)|100\n");
  proxy_epval_t ev;
  init_ctrl_epval(&ev, 4);   /* equal (zero) loads -> 4-way tie -> RR cycles */
  atomic_store(&ev.pd_ctrl_mode, 1);
  atomic_store(&ev.pd_ctrl_ep[2], ctrl_pack(PD_CTRL_ST_DISABLED, 100));

  int seq[SEQ_LEN];
  CHECK(record_sequence(&ev, seq, SEQ_LEN),
        "TC-2: 1000 selections all returned rc==0 (3 EPs still serve)");
  int count[5] = {0};
  for (int k = 0; k < SEQ_LEN; k++) count[seq[k]]++;
  CHECK(count[2] == 0, "TC-2: DISABLED EP2 received ZERO selections");
  CHECK(count[0] > 0 && count[1] > 0 && count[3] > 0,
        "TC-2: EP0/EP1/EP3 absorbed EP2's share (all selected)");
  CHECK(count[0] + count[1] + count[3] == SEQ_LEN,
        "TC-2: every selection landed on a non-DISABLED prefill EP");
  cleanup_ctrl_epval(&ev);
}

/* ===== TC-3: DRAINING excludes NEW assignment; clearing restores ===== */
static void test_tc3_draining(void) {
  printf("TC-3: DRAINING — mode 1, EP1 DRAINING then cleared\n");
  proxy_epval_t ev;
  init_ctrl_epval(&ev, 4);
  atomic_store(&ev.pd_ctrl_mode, 1);
  atomic_store(&ev.pd_ctrl_ep[1], ctrl_pack(PD_CTRL_ST_DRAINING, 100));

  int seq[SEQ_LEN];
  CHECK(record_sequence(&ev, seq, SEQ_LEN),
        "TC-3: 1000 selections all returned rc==0 while EP1 drains");
  int drain_count[5] = {0};
  for (int k = 0; k < SEQ_LEN; k++) drain_count[seq[k]]++;
  CHECK(drain_count[1] == 0,
        "TC-3: DRAINING EP1 excluded from NEW-session assignment (zero selections)");
  CHECK(drain_count[0] > 0 && drain_count[2] > 0 && drain_count[3] > 0,
        "TC-3: the non-draining EPs kept serving");

  /* Clear the advisory (the applier writes 0) -> eligibility restored. */
  atomic_store(&ev.pd_ctrl_ep[1], 0u);
  int seq2[300];
  CHECK(record_sequence(&ev, seq2, 300),
        "TC-3: 300 post-clear selections all returned rc==0");
  int back = 0;
  for (int k = 0; k < 300; k++) if (seq2[k] == 1) back++;
  CHECK(back > 0,
        "TC-3: clearing the packed word restored EP1 (advisory vanishes with snapshot)");
  cleanup_ctrl_epval(&ev);
}

/* ===== TC-4: weight scales effective capacity in the Tier-2 blend ===== */

/* Closed-loop selection: after each pick, increment the winner's active_conns
 * (a held dispatch). Under the capacity-normalised blend the steady-state
 * share of each EP tracks its EFFECTIVE capacity — so halving EP0's weight
 * must measurably depress its share. Deterministic (no RNG). */
static void run_closed_loop(proxy_epval_t *ev, int n, int *count) {
  proxy_fd_ent_t pfe;
  for (int k = 0; k < n; k++) {
    init_ctrl_pfe(&pfe, 5000 + k);
    int ep = -1;
    if (pd_select_prefill(ev, &pfe, &ep, 0) != 0) return;
    count[ep]++;
    atomic_fetch_add(&ev->pd_ep_loads[ep].active_conns, 1u);
  }
}

static void test_tc4_weight(void) {
  printf("TC-4: weight — GPU_AWARE Tier-2, EP0 weight=50 vs mode-0 share\n");
  enum { N = 5000 };

  /* Phase A: mode 0 baseline — equal capacities, equal shares. */
  proxy_epval_t ev;
  init_ctrl_epval(&ev, 4);
  ev.ep_sel = PROXY_SEL_GPU_AWARE;
  for (int i = 0; i < 4; i++)
    atomic_store(&ev.pd_ep_loads[i].num_gpu_blocks, 1000u);
  int base[5] = {0};
  run_closed_loop(&ev, N, base);
  cleanup_ctrl_epval(&ev);
  CHECK(base[0] + base[1] + base[2] + base[3] == N,
        "TC-4: mode-0 closed loop completed 5000 selections");

  /* Phase B: mode 1, EP0 ACTIVE|weight=50, others ACTIVE|100. */
  init_ctrl_epval(&ev, 4);
  ev.ep_sel = PROXY_SEL_GPU_AWARE;
  for (int i = 0; i < 4; i++)
    atomic_store(&ev.pd_ep_loads[i].num_gpu_blocks, 1000u);
  atomic_store(&ev.pd_ctrl_mode, 1);
  atomic_store(&ev.pd_ctrl_ep[0], ctrl_pack(PD_CTRL_ST_ACTIVE, 50));
  for (int i = 1; i < 4; i++)
    atomic_store(&ev.pd_ctrl_ep[i], ctrl_pack(PD_CTRL_ST_ACTIVE, 100));
  int wcount[5] = {0};
  run_closed_loop(&ev, N, wcount);
  cleanup_ctrl_epval(&ev);
  CHECK(wcount[0] + wcount[1] + wcount[2] + wcount[3] == N,
        "TC-4: weighted closed loop completed 5000 selections");
  CHECK(wcount[0] > 0,
        "TC-4: weight=50 EP0 still serves (weight scales, never removes — V5)");
  /* Share assertion: EP0's weighted share < 0.75 x its mode-0 share.
   * Integer cross-multiply (no floats): wcount0 * 4 < 3 * base0. */
  CHECK((uint64_t)wcount[0] * 4ULL < (uint64_t)base[0] * 3ULL,
        "TC-4: EP0 share at weight=50 fell below 0.75x its mode-0 share");
}

/* ===== TC-5: G4 non-resurrection ===== */
static void test_tc5_g4_non_resurrection(void) {
  printf("TC-5: G4 — locally-ineligible EP3 + ACTIVE|100 snapshot\n");

  /* Sub-case A: local circuit breaker OPEN (exactly the production per-tier
   * CB_STATE_OPEN check) while the applier's word says ACTIVE|weight=100. */
  proxy_epval_t ev;
  init_ctrl_epval(&ev, 4);
  ev.circuit_breakers[3].state = CB_STATE_OPEN;   /* local exclusion */
  atomic_store(&ev.pd_ctrl_mode, 1);
  atomic_store(&ev.pd_ctrl_ep[3], ctrl_pack(PD_CTRL_ST_ACTIVE, 100));

  int seq[SEQ_LEN];
  CHECK(record_sequence(&ev, seq, SEQ_LEN),
        "TC-5a: 1000 selections all returned rc==0 (3 healthy EPs serve)");
  int cb_hits = 0;
  for (int k = 0; k < SEQ_LEN; k++) if (seq[k] == 3) cb_hits++;
  CHECK(cb_hits == 0,
        "TC-5a (G4): CB-open EP3 received ZERO selections despite ACTIVE|100 snapshot");
  cleanup_ctrl_epval(&ev);

  /* Sub-case B: local exclusion via excluded_mask (the caller-side exclusion
   * every tier honors) — the fold-in ORs INTO the mask, never clears it. */
  init_ctrl_epval(&ev, 4);
  atomic_store(&ev.pd_ctrl_mode, 1);
  atomic_store(&ev.pd_ctrl_ep[3], ctrl_pack(PD_CTRL_ST_ACTIVE, 100));
  proxy_fd_ent_t pfe;
  int excl_hits = 0;
  for (int k = 0; k < SEQ_LEN; k++) {
    init_ctrl_pfe(&pfe, 9000 + k);
    int ep = -1;
    if (pd_select_prefill(&ev, &pfe, &ep, (1u << 3)) != 0) { excl_hits = -1; break; }
    if (ep == 3) excl_hits++;
  }
  CHECK(excl_hits == 0,
        "TC-5b (G4): excluded_mask EP3 received ZERO selections despite ACTIVE|100 snapshot");
  cleanup_ctrl_epval(&ev);
}

/* ===== TC-6: mode 0 + packed-nonzero array is inert ===== */
static void test_tc6_mode0_packed_nonzero(void) {
  printf("TC-6: mode-0 gate — pd_ctrl_ep[] nonzero but mode stays 0\n");
  proxy_epval_t ev;
  init_ctrl_epval(&ev, 4);
  seed_mixed_loads(&ev);
  /* Poison the array with words that WOULD change selection at mode 1:
   * DISABLE the min-score EP1, DRAIN EP3, half-weight EP0. mode stays 0. */
  atomic_store(&ev.pd_ctrl_ep[0], ctrl_pack(PD_CTRL_ST_ACTIVE, 50));
  atomic_store(&ev.pd_ctrl_ep[1], ctrl_pack(PD_CTRL_ST_DISABLED, 100));
  atomic_store(&ev.pd_ctrl_ep[3], ctrl_pack(PD_CTRL_ST_DRAINING, 100));

  int seq[SEQ_LEN];
  CHECK(record_sequence(&ev, seq, SEQ_LEN),
        "TC-6: 1000 selections all returned rc==0");
  CHECK(memcmp(seq, tc1_seq, sizeof(seq)) == 0,
        "TC-6 (G3): sequence memcmp-IDENTICAL to TC-1 — the MODE guard, not the array, is the gate");
  cleanup_ctrl_epval(&ev);
}

int main(void) {
  /* getenv-once hygiene: every resolver must cache its DISABLED default before
   * any pd_select_prefill call (see header note — no per-case env mutation). */
  unsetenv("LLB_PD_MAX_INFLIGHT_PER_EP");
  unsetenv("LLB_PD_QUEUE_DEPTH_PER_EP");
  unsetenv("LLB_PD_MAX_PARK_SEC");
  unsetenv("LLB_PD_MAX_TOTAL_INFLIGHT");
  unsetenv("LLB_KV_LOADGUARD");

  printf("=== test_pd_ctrl: controller advisory influence (G3/G4) ===\n");
  test_tc1_g3_identity();
  test_tc2_disabled();
  test_tc3_draining();
  test_tc4_weight();
  test_tc5_g4_non_resurrection();
  test_tc6_mode0_packed_nonzero();

  if (g_failures) {
    printf("test_pd_ctrl: FAIL (%d)\n", g_failures);
    return 1;
  }
  printf("test_pd_ctrl: PASS\n");
  return 0;
}
