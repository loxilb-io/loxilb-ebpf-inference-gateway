/* SPDX-License-Identifier: (GPL-2.0) */
/* test_radix_route.c - the prefix routing decision of a non-P/D pool
 * (sockproxy_radix_route.c, with the trie and the scanner it calls; all
 * three included directly, they are self-contained).
 *
 * Exit criteria of step 4 proven at this level (case name prefix):
 *   e1   radix off: no scan, no allocation; gates before the scan stop a
 *        request without scanning or allocating
 *   e3   route subset and pins win and are not scanned; an endpoint outside
 *        the eligible mask (route, health, circuit breaker, drain) is never
 *        picked, the lookup walks back to an eligible shallower match
 *   e4   one case per fallback reason, each counted under its own name
 *   e5   learning: once, on the first final 2xx; none on 4xx/5xx or without
 *        a reply; 1xx does not consume; the final endpoint is the one
 *        learned; keep-alive requests independent; only scanned requests
 *        learn; whole-key match learns with no lock; a learn waits for a
 *        reader and then succeeds
 *   e7   purge of an endpoint, relearn after it returns, refresh purge mask,
 *        purge completes while readers run back to back
 *   e10  lookups, learns and purges concurrently on one pool (TSan build);
 *        a reply for another pool generation changes nothing
 *   ka   HTTP/1.1 keep-alive: keep the leg unless a full HIT excludes the
 *        kept endpoint; one decision per request; one scan per request
 *   d2   per-request state: reset and free leave nothing allocated (LSan)
 *   d4b  a body above 8,192 JSON tokens is routed
 *   misc counters line (names and counts only), rate limit, lock-wait
 *        maxima (lookup and learn), time source,
 *        allocation failure in create
 *
 * Build: make test_radix_route test_radix_route_tsan
 */
/* The module needs the writer-preferring rwlock kind, declared by glibc
 * only with _GNU_SOURCE; it is included below after system headers. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "sockproxy_radix.c"
#include "sockproxy_radix_scan.c"

/* ---- allocation wrappers, active only inside sockproxy_radix_route.c ---- */

static long fa_live;
static long fa_calls;
static long fa_fail_at = -1;
static pthread_mutex_t fa_mu = PTHREAD_MUTEX_INITIALIZER;

static int fa_should_fail(void)
{
  long idx = fa_calls++;
  if (fa_fail_at >= 0 && idx == fa_fail_at) {
    fa_fail_at = -1;
    return 1;
  }
  return 0;
}

static __attribute__((unused)) void *fa_malloc(size_t n)
{
  void *p = NULL;
  pthread_mutex_lock(&fa_mu);
  if (!fa_should_fail()) {
    p = malloc(n);
    if (p)
      fa_live++;
  }
  pthread_mutex_unlock(&fa_mu);
  return p;
}

static __attribute__((unused)) void *fa_calloc(size_t n, size_t sz)
{
  void *p = NULL;
  pthread_mutex_lock(&fa_mu);
  if (!fa_should_fail()) {
    p = calloc(n, sz);
    if (p)
      fa_live++;
  }
  pthread_mutex_unlock(&fa_mu);
  return p;
}

static __attribute__((unused)) void fa_free(void *p)
{
  if (!p)
    return;
  pthread_mutex_lock(&fa_mu);
  fa_live--;
  pthread_mutex_unlock(&fa_mu);
  free(p);
}

#define malloc(n) fa_malloc(n)
#define calloc(n, sz) fa_calloc(n, sz)
#define free(p) fa_free(p)
#include "sockproxy_radix_route.c"
#undef malloc
#undef calloc
#undef free

/* ---- reporting ---- */

static int g_fail;
static int g_case_fail;
static const char *g_case;

#define CHECK(c) do {                                                   \
    if (!(c)) {                                                         \
      g_fail++;                                                         \
      if (g_case_fail++ < 6)                                            \
        printf("    check failed: %s (line %d)\n", #c, __LINE__);       \
    }                                                                   \
  } while (0)

static void case_begin(const char *name)
{
  g_case = name;
  g_case_fail = 0;
}

static void case_end(void)
{
  printf("[%s] %s%s\n", g_case_fail ? "FAIL" : "PASS", g_case,
         g_case_fail > 6 ? " (more failures not shown)" : "");
}

/* ---- request bodies ---- */

#define BODY_CAP (256 * 1024)

/* {"model":"m","messages":[{"role":"system","content":S},{"role":"user","content":U}]}
 * with S = sys_len copies of sys_ch and U = user_len copies of user_ch. The
 * key stream is (3 + sys_len) + (3 + user_len) bytes. */
static size_t body2(char *b, char sys_ch, size_t sys_len, char user_ch,
                    size_t user_len)
{
  size_t n = 0;
  n += (size_t)sprintf(b + n, "{\"model\":\"m\",\"messages\":[{\"role\":\"system\",\"content\":\"");
  memset(b + n, sys_ch, sys_len); n += sys_len;
  n += (size_t)sprintf(b + n, "\"},{\"role\":\"user\",\"content\":\"");
  memset(b + n, user_ch, user_len); n += user_len;
  n += (size_t)sprintf(b + n, "\"}]}");
  return n;
}

static size_t body_raw(char *b, const char *s)
{
  size_t n = strlen(s);
  memcpy(b, s, n);
  return n;
}

/* count alternating user/assistant messages "hi": 5 JSON tokens each. */
static size_t body_many(char *b, unsigned count)
{
  size_t n = 0;
  n += (size_t)sprintf(b + n, "{\"model\":\"m\",\"messages\":[");
  for (unsigned i = 0; i < count; i++)
    n += (size_t)sprintf(b + n, "%s{\"role\":\"%s\",\"content\":\"hi\"}",
                         i ? "," : "", (i & 1) ? "assistant" : "user");
  n += (size_t)sprintf(b + n, "]}");
  return n;
}

/* ---- decision inputs ---- */

static uint32_t g_inflight[RADIX_MAX_EP];

static void in_base(radix_route_in_t *in, const void *pool_id,
                    const char *body, size_t len)
{
  memset(in, 0, sizeof(*in));
  in->pool_id = pool_id;
  in->body = body;
  in->body_len = len;
  in->ai_gw_mode = 1;
  in->fc_active = 1;
  in->model = "m";
  in->model_len = 1;
  in->eligible = 0x7;
  in->inflight = g_inflight;
  in->n_eps = 3;
  in->selector_pick = 1;
  in->now = 1;
}

static radix_pool_t *pool_new(void)
{
  radix_route_cfg_t cfg;
  memset(&cfg, 0, sizeof(cfg));
  memset(g_inflight, 0, sizeof(g_inflight));
  return radix_pool_create(&cfg);
}

static uint64_t decided(radix_pool_t *p, radix_route_reason_t r)
{
  return p ? __atomic_load_n(&p->st.decided[r], __ATOMIC_RELAXED) : 0;
}

/* One request: decide, then the reply status from endpoint ep, then the
 * message-begin reset of the next request. Returns the learn result. */
static radix_learn_rc_t request(radix_pool_t *p, radix_req_t **rq,
                                const char *body, size_t len, int ep,
                                unsigned status, radix_route_out_t *out)
{
  radix_route_in_t in;
  radix_route_out_t o;
  radix_learn_rc_t lr;
  in_base(&in, p, body, len);
  radix_route_decide(p, rq, &in, out ? out : &o);
  lr = radix_route_learn(p, *rq, p, ep, status, 2);
  radix_req_reset(*rq);
  return lr;
}

static int decide_body(radix_pool_t *p, radix_req_t **rq, const char *body,
                       size_t len, uint32_t eligible, radix_route_out_t *out)
{
  radix_route_in_t in;
  in_base(&in, p, body, len);
  in.eligible = eligible;
  return radix_route_decide(p, rq, &in, out);
}

/* ======================================================================== */
/* E1                                                                        */

static void e1_off_no_scan_no_alloc(void)
{
  char *b = malloc(BODY_CAP);
  radix_req_t *rq = NULL;
  radix_route_in_t in;
  radix_route_out_t out;
  uint64_t s0 = radix_route_scan_calls();
  long c0 = fa_calls;

  case_begin("e1_off_no_scan_no_alloc");
  in_base(&in, NULL, b, body2(b, 'x', 600, 'a', 300));
  CHECK(radix_route_decide(NULL, &rq, &in, &out) == -1);
  CHECK(out.reason == RADIX_R_OFF && out.ep == -1);
  CHECK(rq == NULL);
  CHECK(radix_route_scan_calls() == s0);
  CHECK(fa_calls == c0);
  CHECK(radix_route_learn(NULL, rq, NULL, 0, 200, 1) == RADIX_LEARN_NONE);
  case_end();
  free(b);
}

static void e1_gates_before_scan(void)
{
  struct { const char *name; radix_route_reason_t r; } g[] = {
    { "route_subset", RADIX_R_ROUTE_SUBSET }, { "pinned", RADIX_R_PINNED },
    { "ai_gw_off", RADIX_R_AI_GW_OFF }, { "fc_inactive", RADIX_R_FC_INACTIVE },
    { "chunked", RADIX_R_CHUNKED }, { "inspect_size", RADIX_R_INSPECT_SIZE },
    { "no_body", RADIX_R_NO_BODY }, { "salt_invalid", RADIX_R_SALT_INVALID },
  };
  char *b = malloc(BODY_CAP);
  size_t len = body2(b, 'x', 600, 'a', 300);
  radix_pool_t *p = pool_new();

  case_begin("e1_gates_before_scan (also e3 route subset / pin, e4 gate reasons)");
  CHECK(p != NULL);
  for (unsigned i = 0; p && i < sizeof(g) / sizeof(g[0]); i++) {
    radix_req_t *rq = NULL;
    radix_route_in_t in;
    radix_route_out_t out;
    uint64_t s0 = radix_route_scan_calls();
    long c0 = fa_calls;
    in_base(&in, p, b, len);
    switch (g[i].r) {
    case RADIX_R_ROUTE_SUBSET: in.route_subset = 1; break;
    case RADIX_R_PINNED:       in.pinned = 1; break;
    case RADIX_R_AI_GW_OFF:    in.ai_gw_mode = 0; break;
    case RADIX_R_FC_INACTIVE:  in.fc_active = 0; break;
    case RADIX_R_CHUNKED:      in.chunked = 1; in.body_len = 0; break;
    case RADIX_R_INSPECT_SIZE: in.over_inspect = 1; in.body_len = 0; break;
    case RADIX_R_NO_BODY:      in.body_len = 0; break;
    case RADIX_R_SALT_INVALID: in.salt_invalid = 1; break;
    default: break;
    }
    CHECK(radix_route_decide(p, &rq, &in, &out) == -1);
    if (out.reason != g[i].r)
      printf("    gate %s: reason %d\n", g[i].name, (int)out.reason);
    CHECK(out.reason == g[i].r);
    CHECK(out.ep == -1);
    CHECK(rq == NULL);                         /* no allocation */
    CHECK(fa_calls == c0);
    CHECK(radix_route_scan_calls() == s0);     /* no scan */
    CHECK(decided(p, g[i].r) == 1);
  }
  radix_pool_free(p);
  case_end();
  free(b);
}

/* ======================================================================== */
/* E3                                                                        */

static void e3_pinned_not_learnable(void)
{
  char *b = malloc(BODY_CAP);
  size_t len = body2(b, 'x', 600, 'a', 300);
  radix_pool_t *p = pool_new();
  radix_req_t *rq = NULL;
  radix_route_in_t in;
  radix_route_out_t out;

  case_begin("e3_pinned_not_learnable");
  /* an earlier request on the connection allocated the state */
  CHECK(request(p, &rq, b, len, 0, 404, &out) == RADIX_LEARN_REFUSED);
  CHECK(rq != NULL);
  in_base(&in, p, b, len);
  in.pinned = 1;
  CHECK(radix_route_decide(p, &rq, &in, &out) == -1);
  CHECK(out.reason == RADIX_R_PINNED);
  CHECK(radix_route_learn(p, rq, p, 0, 200, 2) == RADIX_LEARN_NONE);
  radix_req_reset(rq);
  CHECK(decide_body(p, &rq, b, len, 0x7, &out) == -1);
  CHECK(out.reason == RADIX_R_MISS);           /* nothing was learned */
  radix_req_free(&rq);
  radix_pool_free(p);
  case_end();
  free(b);
}

static void e3_sticky_is_pinned(void)
{
  char *a = malloc(BODY_CAP);
  size_t la = body2(a, 'x', 600, 'a', 300);
  radix_pool_t *p = pool_new();
  radix_req_t *rq = NULL;
  radix_route_in_t in;
  radix_route_out_t out;
  uint64_t s0;

  case_begin("e3_sticky_is_pinned (a persistence selector is never overridden: PINNED, not scanned)");
  CHECK(request(p, &rq, a, la, 0, 200, NULL) == RADIX_LEARN_OK); /* learned on ep0 */
  radix_req_reset(rq);
  s0 = radix_route_scan_calls();
  in_base(&in, p, a, la);
  in.sticky_select = 1;
  in.selector_pick = 2;                                    /* the sticky pick */
  CHECK(radix_route_decide(p, &rq, &in, &out) == -1);      /* keep the sticky pick */
  CHECK(out.reason == RADIX_R_PINNED);
  CHECK(radix_route_scan_calls() == s0);
  CHECK(decided(p, RADIX_R_PINNED) == 1);
  CHECK(radix_route_learn(p, rq, p, 2, 200, 3) == RADIX_LEARN_NONE); /* pinned: no learn */
  radix_req_reset(rq);
  in.gates_unknown = 1;                                    /* the keep-alive site: kept */
  CHECK(radix_route_keepalive(p, &rq, &in, 2, &out) == 0);
  CHECK(radix_route_scan_calls() == s0);
  radix_req_free(&rq);
  radix_pool_free(p);
  case_end();
  free(a);
}

/* Health, circuit breaker, drain and route mask all reach the decision as a
 * cleared bit of the eligible mask (the caller builds it); the mapping of
 * each rule to the bit is checked end to end by the scenario. */
static void e3_ineligible_never_picked(void)
{
  char *a1 = malloc(BODY_CAP), *a2 = malloc(BODY_CAP);
  size_t l1 = body2(a1, 'x', 600, 'a', 300);  /* 3 blocks */
  size_t l2 = body2(a2, 'x', 600, 'c', 10);   /* 2 blocks, a prefix of a1's key */
  radix_pool_t *p = pool_new();
  radix_req_t *rq = NULL;
  radix_route_out_t out;

  case_begin("e3_ineligible_never_picked");
  CHECK(request(p, &rq, a1, l1, 0, 200, NULL) == RADIX_LEARN_OK);
  CHECK(request(p, &rq, a2, l2, 2, 200, NULL) == RADIX_LEARN_OK);
  CHECK(decide_body(p, &rq, a1, l1, 0x7, &out) == 0);
  CHECK(out.reason == RADIX_R_HIT && out.matched_bytes == 768);
  radix_req_reset(rq);
  CHECK(decide_body(p, &rq, a1, l1, 0x6, &out) == 2);   /* ep0 out: walk back */
  CHECK(out.reason == RADIX_R_HIT && out.matched_bytes == 512);
  radix_req_reset(rq);
  CHECK(decide_body(p, &rq, a1, l1, 0x2, &out) == -1);  /* ep0, ep2 out */
  CHECK(out.reason == RADIX_R_MISS);
  radix_req_free(&rq);
  radix_pool_free(p);
  case_end();
  free(a1); free(a2);
}

/* ======================================================================== */
/* E4                                                                        */

/* Learned: a = system 600 'x' + user 300 'a' (stream 906, 3 blocks) on ep0.
 * Probe b = same system + user n 'b': common stream 605 bytes = 2 full
 * blocks, so matched_bytes 512; stream 606 + n. n = 1954 -> 2560, exactly
 * 20 %; n = 1955 -> 2561, below. */
static void e4_threshold(void)
{
  char *a = malloc(BODY_CAP), *bb = malloc(BODY_CAP);
  size_t la = body2(a, 'x', 600, 'a', 300);
  radix_pool_t *p = pool_new();
  radix_req_t *rq = NULL;
  radix_route_out_t out;

  case_begin("e4_threshold (default 20 %, exact boundary)");
  CHECK(request(p, &rq, a, la, 0, 200, NULL) == RADIX_LEARN_OK);
  CHECK(decide_body(p, &rq, bb, body2(bb, 'x', 600, 'b', 1954), 0x7, &out) == 0);
  CHECK(out.reason == RADIX_R_HIT);
  CHECK(out.matched_bytes == 512 && out.stream_bytes == 2560);
  radix_req_reset(rq);
  CHECK(decide_body(p, &rq, bb, body2(bb, 'x', 600, 'b', 1955), 0x7, &out) == -1);
  CHECK(out.reason == RADIX_R_BELOW_THRESHOLD);
  CHECK(out.matched_bytes == 512 && out.stream_bytes == 2561);
  CHECK(decided(p, RADIX_R_BELOW_THRESHOLD) == 1);
  radix_req_free(&rq);
  radix_pool_free(p);
  case_end();
  free(a); free(bb);
}

static void e4_spread_and_tiebreak(void)
{
  char *a = malloc(BODY_CAP);
  size_t la = body2(a, 'x', 600, 'a', 300);
  radix_pool_t *p = pool_new();
  radix_req_t *rq = NULL;
  radix_route_in_t in;
  radix_route_out_t out;

  case_begin("e4_spread_and_tiebreak (balance 3: pick - min over eligible)");
  CHECK(request(p, &rq, a, la, 0, 200, NULL) == RADIX_LEARN_OK);

  in_base(&in, p, a, la);
  g_inflight[0] = 4; g_inflight[1] = 0; g_inflight[2] = 0;
  CHECK(radix_route_decide(p, &rq, &in, &out) == -1);   /* pick - min = 4 */
  CHECK(out.reason == RADIX_R_SPREAD);
  radix_req_reset(rq);
  g_inflight[0] = 3;
  CHECK(radix_route_decide(p, &rq, &in, &out) == 0);    /* pick - min = 3 */
  CHECK(out.reason == RADIX_R_HIT);
  radix_req_reset(rq);
  g_inflight[0] = 0; g_inflight[2] = 9;
  in.eligible = 0x3;                       /* ep2 ineligible */
  CHECK(radix_route_decide(p, &rq, &in, &out) == 0);
  CHECK(out.reason == RADIX_R_HIT);
  radix_req_reset(rq);
  memset(g_inflight, 0, sizeof(g_inflight));

  /* the same key learned on ep0 and ep1 */
  CHECK(request(p, &rq, a, la, 1, 200, NULL) == RADIX_LEARN_OK);
  in_base(&in, p, a, la);
  g_inflight[0] = 2; g_inflight[1] = 1;
  CHECK(radix_route_decide(p, &rq, &in, &out) == 1);    /* lower in-flight */
  radix_req_reset(rq);
  g_inflight[0] = 1; g_inflight[1] = 1;
  in.selector_pick = 1;
  CHECK(radix_route_decide(p, &rq, &in, &out) == 1);    /* tie: selector's pick */
  radix_req_reset(rq);
  in.selector_pick = 2;
  CHECK(radix_route_decide(p, &rq, &in, &out) == 0);    /* tie: lowest index */
  radix_req_free(&rq);
  radix_pool_free(p);
  memset(g_inflight, 0, sizeof(g_inflight));
  case_end();
  free(a);
}

/* The cases that tell the guard rules apart (rule B: fall back only when the
 * chosen candidate sits more than balance_abs above the least-loaded
 * eligible endpoint; the spread of the other endpoints does not count). */
static void e4_rule_b(void)
{
  char *a = malloc(BODY_CAP);
  size_t la = body2(a, 'x', 600, 'a', 300);
  radix_pool_t *p = pool_new();
  radix_req_t *rq = NULL;
  radix_route_in_t in;
  radix_route_out_t out;

  case_begin("e4_rule_b (max - min > abs with pick - min <= abs: HIT)");
  CHECK(request(p, &rq, a, la, 0, 200, NULL) == RADIX_LEARN_OK);   /* on ep0 */
  in_base(&in, p, a, la);
  g_inflight[0] = 0; g_inflight[1] = 0; g_inflight[2] = 4;
  CHECK(radix_route_decide(p, &rq, &in, &out) == 0);    /* max - min 4, pick - min 0 */
  CHECK(out.reason == RADIX_R_HIT);
  radix_req_reset(rq);
  g_inflight[0] = 3; g_inflight[1] = 0; g_inflight[2] = 20;
  CHECK(radix_route_decide(p, &rq, &in, &out) == 0);    /* pick - min == abs */
  CHECK(out.reason == RADIX_R_HIT);
  radix_req_reset(rq);
  g_inflight[0] = 4; g_inflight[1] = 0; g_inflight[2] = 4;
  CHECK(radix_route_decide(p, &rq, &in, &out) == -1);   /* pick - min > abs */
  CHECK(out.reason == RADIX_R_SPREAD);
  radix_req_reset(rq);
  g_inflight[0] = 4; g_inflight[1] = 4; g_inflight[2] = 0;
  in.eligible = 0x3;                       /* min over eligible only: 4 */
  CHECK(radix_route_decide(p, &rq, &in, &out) == 0);
  CHECK(out.reason == RADIX_R_HIT);
  radix_req_reset(rq);
  CHECK(decided(p, RADIX_R_HIT) == 3 && decided(p, RADIX_R_SPREAD) == 1);
  memset(g_inflight, 0, sizeof(g_inflight));

  /* a candidate that is not eligible never becomes the pick: learned on
   * ep0 and ep2, ep2 ineligible and idle */
  CHECK(request(p, &rq, a, la, 2, 200, NULL) == RADIX_LEARN_OK);
  in_base(&in, p, a, la);
  in.eligible = 0x3;
  g_inflight[0] = 4; g_inflight[1] = 0; g_inflight[2] = 0;
  CHECK(radix_route_decide(p, &rq, &in, &out) == -1);   /* ep0: 4 - 0 */
  CHECK(out.reason == RADIX_R_SPREAD && !(out.cand_mask & 0x4));
  radix_req_reset(rq);
  g_inflight[0] = 3;
  CHECK(radix_route_decide(p, &rq, &in, &out) == 0);    /* ep0, never ep2 */
  CHECK(out.reason == RADIX_R_HIT && !(out.cand_mask & 0x4));
  radix_req_free(&rq);
  radix_pool_free(p);
  memset(g_inflight, 0, sizeof(g_inflight));
  case_end();
  free(a);
}

static void e4_scan_skips(void)
{
  struct { const char *body; radix_scan_rc_t rc; } s[] = {
    { "{", RADIX_SKIP_MALFORMED },
    { "{\"model\":\"m\",\"messages\":[{\"role\":\"user\",\"content\":\"short\"}]}",
      RADIX_SKIP_SHORT },
    { "{\"model\":\"m\",\"messages\":[{\"role\":\"user\",\"content\":"
      "[{\"type\":\"image_url\",\"image_url\":{\"url\":\"x\"}}]}]}",
      RADIX_SKIP_NON_TEXT_PART },
    { "{\"model\":\"m\",\"chat_template\":\"t\",\"messages\":"
      "[{\"role\":\"user\",\"content\":\"hello\"}]}", RADIX_SKIP_TEMPLATE_OVERRIDE },
  };
  char *b = malloc(BODY_CAP);
  radix_pool_t *p = pool_new();

  case_begin("e4_scan_skips (each scanner result counted apart)");
  for (unsigned i = 0; i < sizeof(s) / sizeof(s[0]); i++) {
    radix_req_t *rq = NULL;
    radix_route_out_t out;
    size_t len = body_raw(b, s[i].body);
    CHECK(decide_body(p, &rq, b, len, 0x7, &out) == -1);
    CHECK(out.reason == RADIX_R_SCAN_SKIP && out.scan_rc == s[i].rc);
    CHECK(p && __atomic_load_n(&p->st.scan_skip[s[i].rc], __ATOMIC_RELAXED) == 1);
    CHECK(radix_route_learn(p, rq, p, 0, 200, 2) == RADIX_LEARN_NONE);
    radix_req_free(&rq);
  }
  CHECK(decided(p, RADIX_R_SCAN_SKIP) == 4);
  radix_pool_free(p);

  /* the body-length ceiling (S4g) is the scanner's max_body */
  {
    radix_route_cfg_t cfg;
    radix_req_t *rq = NULL;
    radix_route_out_t out;
    memset(&cfg, 0, sizeof(cfg));
    cfg.max_body = 1000;
    p = radix_pool_create(&cfg);
    CHECK(decide_body(p, &rq, b, body2(b, 'x', 600, 'a', 400), 0x7, &out) == -1);
    CHECK(out.reason == RADIX_R_SCAN_SKIP &&
          out.scan_rc == RADIX_SKIP_BODY_TOO_LARGE);
    radix_req_free(&rq);
    radix_pool_free(p);
  }
  case_end();
  free(b);
}

static void e4_miss_workcap_ns_nomem(void)
{
  char *b = malloc(BODY_CAP), *t = malloc(1024);
  size_t len = body2(b, 'x', 600, 'a', 300);
  radix_pool_t *p = pool_new();
  radix_req_t *rq = NULL;
  radix_route_in_t in;
  radix_route_out_t out;
  radix_route_cfg_t cfg;
  long live0;

  case_begin("e4_miss_workcap_ns_nomem");
  CHECK(decide_body(p, &rq, b, len, 0x7, &out) == -1);
  CHECK(out.reason == RADIX_R_MISS);
  radix_req_free(&rq);

  /* namespace over RADIX_NS_MAX (a tenant longer than any real one) */
  memset(t, 't', 600);
  in_base(&in, p, b, len);
  in.tenant = t;
  in.tenant_len = 600;
  CHECK(radix_route_decide(p, &rq, &in, &out) == -1);
  CHECK(out.reason == RADIX_R_NS_OVERFLOW);
  CHECK(radix_route_learn(p, rq, p, 0, 200, 2) == RADIX_LEARN_NONE);
  radix_req_free(&rq);

  /* allocation of the per-request state fails */
  live0 = fa_live;
  fa_calls = 0;
  fa_fail_at = 0;
  CHECK(decide_body(p, &rq, b, len, 0x7, &out) == -1);
  CHECK(out.reason == RADIX_R_NOMEM && rq == NULL);
  CHECK(fa_live == live0);
  fa_fail_at = -1;
  CHECK(decided(p, RADIX_R_NOMEM) == 1);
  radix_pool_free(p);

  /* lookup work cap */
  memset(&cfg, 0, sizeof(cfg));
  cfg.lim.lookup_work_cap = 1;
  p = radix_pool_create(&cfg);
  CHECK(request(p, &rq, b, len, 0, 200, NULL) == RADIX_LEARN_OK);
  CHECK(decide_body(p, &rq, b, len, 0x7, &out) == -1);
  CHECK(out.reason == RADIX_R_WORK_CAP);
  CHECK(decided(p, RADIX_R_WORK_CAP) == 1);
  radix_req_free(&rq);
  radix_pool_free(p);
  case_end();
  free(b); free(t);
}

/* ======================================================================== */
/* E5                                                                        */

static void e5_once_on_2xx(void)
{
  char *b = malloc(BODY_CAP);
  size_t len = body2(b, 'x', 600, 'a', 300);
  radix_pool_t *p = pool_new();
  radix_req_t *rq = NULL;
  radix_route_out_t out;

  case_begin("e5_once_on_2xx");
  CHECK(decide_body(p, &rq, b, len, 0x7, &out) == -1);
  CHECK(radix_route_learn(p, rq, p, 0, 200, 2) == RADIX_LEARN_OK);
  CHECK(radix_route_learn(p, rq, p, 0, 200, 2) == RADIX_LEARN_NONE);
  CHECK(radix_route_learn(p, rq, p, 1, 201, 2) == RADIX_LEARN_NONE);
  radix_req_reset(rq);
  CHECK(decide_body(p, &rq, b, len, 0x7, &out) == 0);
  CHECK(decide_body(p, &rq, b, len, 0x6, &out) == -1); /* only ep0 learned */
  CHECK(p && __atomic_load_n(&p->st.learn[RADIX_LEARN_OK], __ATOMIC_RELAXED) == 1);
  radix_req_free(&rq);
  radix_pool_free(p);
  case_end();
  free(b);
}

static void e5_no_learn_on_error_or_no_reply(void)
{
  unsigned st[] = { 400, 404, 429, 500, 503 };
  char *b = malloc(BODY_CAP);
  size_t len = body2(b, 'x', 600, 'a', 300);
  radix_pool_t *p = pool_new();
  radix_req_t *rq = NULL;
  radix_route_out_t out;

  case_begin("e5_no_learn_on_error_or_no_reply");
  for (unsigned i = 0; i < sizeof(st) / sizeof(st[0]); i++) {
    CHECK(decide_body(p, &rq, b, len, 0x7, &out) == -1);
    CHECK(out.reason == RADIX_R_MISS);
    CHECK(radix_route_learn(p, rq, p, 0, st[i], 2) == RADIX_LEARN_REFUSED);
    CHECK(radix_route_learn(p, rq, p, 0, 200, 2) == RADIX_LEARN_NONE);
    radix_req_reset(rq);
  }
  /* connection failure: no reply ever reaches the latch, the next request
   * on the connection resets */
  CHECK(decide_body(p, &rq, b, len, 0x7, &out) == -1);
  radix_req_reset(rq);
  CHECK(radix_route_learn(p, rq, p, 0, 200, 2) == RADIX_LEARN_NONE);
  CHECK(decide_body(p, &rq, b, len, 0x7, &out) == -1);
  CHECK(out.reason == RADIX_R_MISS);
  CHECK(p && __atomic_load_n(&p->st.learn[RADIX_LEARN_REFUSED], __ATOMIC_RELAXED) == 5);
  radix_req_free(&rq);
  radix_pool_free(p);
  case_end();
  free(b);
}

static void e5_interim_then_200(void)
{
  char *b = malloc(BODY_CAP);
  size_t len = body2(b, 'x', 600, 'a', 300);
  radix_pool_t *p = pool_new();
  radix_req_t *rq = NULL;
  radix_route_out_t out;

  case_begin("e5_interim_then_200 (100 Continue / 103 do not consume)");
  CHECK(decide_body(p, &rq, b, len, 0x7, &out) == -1);
  CHECK(radix_route_learn(p, rq, p, 0, 100, 2) == RADIX_LEARN_INTERIM);
  CHECK(radix_route_learn(p, rq, p, 0, 103, 2) == RADIX_LEARN_INTERIM);
  CHECK(radix_route_learn(p, rq, p, 0, 200, 2) == RADIX_LEARN_OK);
  radix_req_free(&rq);
  radix_pool_free(p);
  case_end();
  free(b);
}

static void e5_final_endpoint(void)
{
  char *b = malloc(BODY_CAP);
  size_t len = body2(b, 'x', 600, 'a', 300);
  radix_pool_t *p = pool_new();
  radix_req_t *rq = NULL;
  radix_route_out_t out;

  case_begin("e5_final_endpoint (retry / admission move)");
  CHECK(request(p, &rq, b, len, 0, 200, NULL) == RADIX_LEARN_OK);
  CHECK(decide_body(p, &rq, b, len, 0x7, &out) == 0);   /* radix picks ep0 */
  radix_route_note_moved(p);                             /* admission: ep0 -> ep2 */
  CHECK(radix_route_learn(p, rq, p, 2, 200, 3) == RADIX_LEARN_OK);
  radix_req_reset(rq);
  CHECK(decide_body(p, &rq, b, len, 0x4, &out) == 2);   /* learned on ep2 */
  CHECK(p && __atomic_load_n(&p->st.admission_moved, __ATOMIC_RELAXED) == 1);
  radix_req_free(&rq);
  radix_pool_free(p);
  case_end();
  free(b);
}

static void e5_keepalive_independent(void)
{
  char *a = malloc(BODY_CAP), *c = malloc(BODY_CAP);
  size_t la = body2(a, 'x', 600, 'a', 300);
  size_t lc = body2(c, 'y', 600, 'a', 300);
  radix_pool_t *p = pool_new();
  radix_req_t *rq = NULL;
  radix_route_out_t out;

  case_begin("e5_keepalive_independent");
  CHECK(decide_body(p, &rq, a, la, 0x7, &out) == -1);   /* request 1, no reply */
  radix_req_reset(rq);                                   /* request 2 begins */
  CHECK(decide_body(p, &rq, c, lc, 0x7, &out) == -1);
  CHECK(radix_route_learn(p, rq, p, 1, 200, 2) == RADIX_LEARN_OK);
  radix_req_reset(rq);
  CHECK(decide_body(p, &rq, a, la, 0x7, &out) == -1);   /* request 1's key: none */
  CHECK(out.reason == RADIX_R_MISS);
  radix_req_reset(rq);
  CHECK(decide_body(p, &rq, c, lc, 0x7, &out) == 1);
  radix_req_free(&rq);
  radix_pool_free(p);
  case_end();
  free(a); free(c);
}

static void e5_learnable_outcomes(void)
{
  char *a = malloc(BODY_CAP), *bb = malloc(BODY_CAP);
  size_t la = body2(a, 'x', 600, 'a', 300);
  size_t lb = body2(bb, 'x', 600, 'b', 1955);
  radix_pool_t *p = pool_new();
  radix_req_t *rq = NULL;
  radix_route_in_t in;
  radix_route_out_t out;

  case_begin("e5_learnable_outcomes (miss, below threshold, spread)");
  CHECK(request(p, &rq, a, la, 0, 200, &out) == RADIX_LEARN_OK);  /* MISS */
  CHECK(out.reason == RADIX_R_MISS);
  CHECK(request(p, &rq, bb, lb, 1, 200, &out) == RADIX_LEARN_OK); /* BELOW */
  CHECK(out.reason == RADIX_R_BELOW_THRESHOLD);
  in_base(&in, p, a, la);
  g_inflight[0] = 4;                       /* the candidate ep0 */
  CHECK(radix_route_decide(p, &rq, &in, &out) == -1);
  CHECK(out.reason == RADIX_R_SPREAD);
  CHECK(radix_route_learn(p, rq, p, 2, 200, 2) == RADIX_LEARN_OK);
  memset(g_inflight, 0, sizeof(g_inflight));
  radix_req_free(&rq);
  radix_pool_free(p);
  case_end();
  free(a); free(bb);
}

typedef struct {
  radix_pool_t *p;
  radix_req_t *rq;
  int ep;
  radix_learn_rc_t rc;
  int done;
} learn_job_t;

static void *learn_job(void *v)
{
  learn_job_t *j = v;
  j->rc = radix_route_learn(j->p, j->rq, j->p, j->ep, 200, 3);
  __atomic_store_n(&j->done, 1, __ATOMIC_RELEASE);
  return NULL;
}

static void e5_whole_key_no_lock(void)
{
  char *a = malloc(BODY_CAP), *c = malloc(BODY_CAP);
  size_t la = body2(a, 'x', 600, 'a', 300);
  size_t lc = body2(c, 'y', 600, 'a', 300);
  radix_pool_t *p = pool_new();
  radix_req_t *rq = NULL;
  radix_route_out_t out;
  learn_job_t job;
  pthread_t th;
  struct timespec ts = { 0, 100 * 1000 * 1000 };

  case_begin("e5_whole_key_no_lock (NOOP without the lock; a learn waits for a reader, then succeeds)");
  CHECK(request(p, &rq, a, la, 0, 200, NULL) == RADIX_LEARN_OK);
  CHECK(decide_body(p, &rq, a, la, 0x7, &out) == 0);
  CHECK(pthread_rwlock_rdlock(&p->lock) == 0);          /* a reader holds it */
  CHECK(radix_route_learn(p, rq, p, 0, 200, 3) == RADIX_LEARN_NOOP);
  pthread_rwlock_unlock(&p->lock);
  radix_req_reset(rq);
  CHECK(decide_body(p, &rq, c, lc, 0x7, &out) == -1 && out.reason == RADIX_R_MISS);
  CHECK(pthread_rwlock_rdlock(&p->lock) == 0);          /* a reader holds it again */
  job = (learn_job_t){ .p = p, .rq = rq, .ep = 1, .rc = RADIX_LEARN__COUNT };
  pthread_create(&th, NULL, learn_job, &job);
  nanosleep(&ts, NULL);
  CHECK(!__atomic_load_n(&job.done, __ATOMIC_ACQUIRE));  /* the learn waits */
  pthread_rwlock_unlock(&p->lock);
  pthread_join(th, NULL);
  CHECK(job.rc == RADIX_LEARN_OK);                      /* then succeeds */
  CHECK(radix_route_learn(p, rq, p, 1, 200, 3) == RADIX_LEARN_NONE); /* consumed */
  radix_req_reset(rq);
  CHECK(decide_body(p, &rq, c, lc, 0x7, &out) == 1);     /* learned on ep1 */
  CHECK(__atomic_load_n(&p->st.learn[RADIX_LEARN_OK], __ATOMIC_RELAXED) == 2);
  CHECK(__atomic_load_n(&p->st.learn[RADIX_LEARN_NOOP], __ATOMIC_RELAXED) == 1);
  radix_req_free(&rq);
  radix_pool_free(p);
  case_end();
  free(a); free(c);
}

/* ======================================================================== */
/* E7                                                                        */

static void e7_purge_and_relearn(void)
{
  char *a = malloc(BODY_CAP), *c = malloc(BODY_CAP);
  size_t la = body2(a, 'x', 600, 'a', 300);
  size_t lc = body2(c, 'y', 600, 'a', 300);
  radix_pool_t *p = pool_new();
  radix_req_t *rq = NULL;
  radix_route_out_t out;

  case_begin("e7_purge_and_relearn");
  CHECK(request(p, &rq, a, la, 0, 200, NULL) == RADIX_LEARN_OK);
  CHECK(request(p, &rq, c, lc, 1, 200, NULL) == RADIX_LEARN_OK);
  radix_pool_purge_ep(p, 0);                       /* inactive or breaker trip */
  CHECK(decide_body(p, &rq, a, la, 0x7, &out) == -1 && out.reason == RADIX_R_MISS);
  radix_req_reset(rq);
  CHECK(decide_body(p, &rq, c, lc, 0x7, &out) == 1);  /* ep1 untouched */
  radix_req_reset(rq);
  CHECK(request(p, &rq, a, la, 0, 200, NULL) == RADIX_LEARN_OK);  /* back */
  CHECK(decide_body(p, &rq, a, la, 0x7, &out) == 0);
  radix_req_reset(rq);
  radix_pool_purge_mask(p, 0x3);
  CHECK(decide_body(p, &rq, a, la, 0x7, &out) == -1);
  radix_req_reset(rq);
  CHECK(decide_body(p, &rq, c, lc, 0x7, &out) == -1);
  CHECK(p && __atomic_load_n(&p->st.purges, __ATOMIC_RELAXED) >= 3);
  radix_req_free(&rq);
  radix_pool_free(p);
  case_end();
  free(a); free(c);
}

static uint32_t learned_mask_of(radix_pool_t *p)
{
  uint32_t m;
  pthread_rwlock_rdlock(&p->lock);
  m = p->learned_mask;
  pthread_rwlock_unlock(&p->lock);
  return m;
}

static void e7_learned_mask(void)
{
  char *a = malloc(BODY_CAP);
  size_t la = body2(a, 'x', 600, 'a', 300);
  radix_pool_t *p = pool_new();
  radix_req_t *rq = NULL;
  radix_route_out_t out;
  uint64_t purges;

  case_begin("e7_learned_mask (purge clears the bit, relearn sets it, NOOP leaves it)");
  CHECK(learned_mask_of(p) == 0);
  CHECK(request(p, &rq, a, la, 0, 200, NULL) == RADIX_LEARN_OK);
  CHECK(learned_mask_of(p) == 0x1);
  radix_pool_purge_ep(p, 0);
  CHECK(learned_mask_of(p) == 0);
  purges = __atomic_load_n(&p->st.purges, __ATOMIC_RELAXED);
  CHECK(purges == 1);
  radix_pool_purge_ep(p, 0);                       /* nothing left: no walk */
  radix_pool_purge_mask(p, ~UINT32_C(0));
  CHECK(__atomic_load_n(&p->st.purges, __ATOMIC_RELAXED) == purges);
  CHECK(request(p, &rq, a, la, 0, 200, NULL) == RADIX_LEARN_OK);  /* relearn */
  CHECK(learned_mask_of(p) == 0x1);
  CHECK(decide_body(p, &rq, a, la, 0x7, &out) == 0);
  CHECK(pthread_rwlock_rdlock(&p->lock) == 0);     /* NOOP needs no lock */
  CHECK(radix_route_learn(p, rq, p, 0, 200, 3) == RADIX_LEARN_NOOP);
  CHECK(p->learned_mask == 0x1);
  pthread_rwlock_unlock(&p->lock);
  radix_req_free(&rq);
  radix_pool_free(p);
  case_end();
  free(a);
}

#define PR_READERS 4

static radix_pool_t *pr_pool;
static const char *pr_body;
static size_t pr_len;
static int pr_stop;
static long pr_lookups;

static void *pr_reader(void *v)
{
  radix_req_t *rq = NULL;
  radix_route_out_t out;
  (void)v;
  /* the request keeps its scan: each iteration is one lookup under the
   * shared lock, back to back */
  while (!__atomic_load_n(&pr_stop, __ATOMIC_ACQUIRE)) {
    decide_body(pr_pool, &rq, pr_body, pr_len, 0x7, &out);
    __atomic_fetch_add(&pr_lookups, 1, __ATOMIC_RELAXED);
  }
  radix_req_free(&rq);
  return NULL;
}

static void e7_purge_under_readers(void)
{
  char *a = malloc(BODY_CAP);
  size_t la = body2(a, 'x', 600, 'a', 300);
  radix_req_t *rq = NULL;
  radix_route_out_t out;
  pthread_t th[PR_READERS];
  struct timespec ts = { 0, 20 * 1000 * 1000 };
  uint64_t t0, dt;
  long before;

  case_begin("e7_purge_under_readers (purge completes while readers run back to back)");
  pr_pool = pool_new();
  pr_body = a;
  pr_len = la;
  pr_stop = 0;
  pr_lookups = 0;
  CHECK(request(pr_pool, &rq, a, la, 0, 200, NULL) == RADIX_LEARN_OK);
  for (int i = 0; i < PR_READERS; i++)
    pthread_create(&th[i], NULL, pr_reader, NULL);
  nanosleep(&ts, NULL);
  before = __atomic_load_n(&pr_lookups, __ATOMIC_RELAXED);
  t0 = rr_mono_ns();
  radix_pool_purge_ep(pr_pool, 0);
  dt = rr_mono_ns() - t0;
  nanosleep(&ts, NULL);
  CHECK(__atomic_load_n(&pr_lookups, __ATOMIC_RELAXED) > before); /* readers kept going */
  __atomic_store_n(&pr_stop, 1, __ATOMIC_RELEASE);
  for (int i = 0; i < PR_READERS; i++)
    pthread_join(th[i], NULL);
  CHECK(before > 0);
  CHECK(dt < 1000u * 1000 * 1000);                /* completes (bound: 1 s) */
  printf("    purge under %d readers: %llu us\n", PR_READERS,
         (unsigned long long)(dt / 1000));
  CHECK(decide_body(pr_pool, &rq, a, la, 0x7, &out) == -1 && out.reason == RADIX_R_MISS);
  radix_req_free(&rq);
  radix_pool_free(pr_pool);
  case_end();
  free(a);
}

static void e7_refresh_purge_mask(void)
{
  radix_ep_ident_t o[RADIX_MAX_EP], n[RADIX_MAX_EP];
  const uint32_t beyond3 = ~UINT32_C(0x7);

  case_begin("e7_refresh_purge_mask (address, inv 0->1, at or beyond n_eps)");
  memset(o, 0, sizeof(o));
  for (unsigned i = 0; i < 3; i++) {
    o[i].xip = 0x0a000001u + i;
    o[i].xport = 8000;
    o[i].protocol = 6;
  }
  memcpy(n, o, sizeof(n));
  CHECK(radix_refresh_purge_mask(o, n, 3) == beyond3);          /* unchanged */
  n[1].xip = 0x0a0000ffu;                                       /* address */
  CHECK(radix_refresh_purge_mask(o, n, 3) == (beyond3 | 0x2));
  memcpy(n, o, sizeof(n));
  n[0].xport = 8001;                                            /* port */
  CHECK(radix_refresh_purge_mask(o, n, 3) == (beyond3 | 0x1));
  memcpy(n, o, sizeof(n));
  n[2].inv = 1;                                                 /* inv 0 -> 1 */
  CHECK(radix_refresh_purge_mask(o, n, 3) == (beyond3 | 0x4));
  o[0].inv = 1;
  memcpy(n, o, sizeof(n));
  n[0].inv = 0;                                                 /* inv 1 -> 0 */
  CHECK(radix_refresh_purge_mask(o, n, 3) == beyond3);
  memcpy(n, o, sizeof(n));
  CHECK(radix_refresh_purge_mask(o, n, 2) == ~UINT32_C(0x3));   /* shrink */
  case_end();
}

/* ======================================================================== */
/* E10                                                                       */

/* ======================================================================== */
/* KA: keep-alive leg decision                                               */

static int ka(radix_pool_t *p, radix_req_t **rq, const char *body, size_t len,
              int kept, radix_route_out_t *out)
{
  radix_route_in_t in;
  in_base(&in, p, body, len);
  return radix_route_keepalive(p, rq, &in, kept, out);
}

static uint64_t st_of(radix_pool_t *p, const uint64_t *f)
{
  (void)p;
  return __atomic_load_n(f, __ATOMIC_RELAXED);
}

static void ka_keep_when_kept_is_candidate(void)
{
  char *a = malloc(BODY_CAP);
  size_t la = body2(a, 'x', 600, 'a', 300);
  radix_pool_t *p = pool_new();
  radix_req_t *rq = NULL;
  radix_route_out_t out;

  case_begin("ka_keep_when_kept_is_candidate (HIT includes the kept endpoint: keep, kept_leg)");
  CHECK(request(p, &rq, a, la, 0, 200, NULL) == RADIX_LEARN_OK);
  CHECK(ka(p, &rq, a, la, 0, &out) == 0);
  CHECK(out.reason == RADIX_R_HIT && (out.cand_mask & 0x1));
  CHECK(st_of(p, &p->st.kept_leg) == 1 && st_of(p, &p->st.ka_moved) == 0);
  CHECK(decided(p, RADIX_R_HIT) == 1);                     /* the request's one decision */
  CHECK(radix_route_learn(p, rq, p, 0, 200, 3) == RADIX_LEARN_NOOP); /* scanned: learns */
  radix_req_free(&rq);
  radix_pool_free(p);
  case_end();
  free(a);
}

static void ka_release_when_kept_not_candidate(void)
{
  char *a = malloc(BODY_CAP);
  size_t la = body2(a, 'x', 600, 'a', 300);
  radix_pool_t *p = pool_new();
  radix_req_t *rq = NULL;
  radix_route_out_t out;
  uint64_t s0;

  case_begin("ka_release_when_kept_not_candidate (HIT elsewhere: release; selection reuses the scan)");
  CHECK(request(p, &rq, a, la, 0, 200, NULL) == RADIX_LEARN_OK);
  s0 = radix_route_scan_calls();
  CHECK(ka(p, &rq, a, la, 2, &out) == 1);                  /* kept leg on ep2 */
  CHECK(out.reason == RADIX_R_HIT && out.cand_mask == 0x1);
  CHECK(st_of(p, &p->st.ka_moved) == 1 && st_of(p, &p->st.kept_leg) == 0);
  CHECK(decided(p, RADIX_R_HIT) == 0);                     /* counted at the selection */
  CHECK(decide_body(p, &rq, a, la, 0x7, &out) == 0);       /* the selection that follows */
  CHECK(radix_route_scan_calls() == s0 + 1);               /* one scan for the request */
  CHECK(decided(p, RADIX_R_HIT) == 1);
  radix_req_free(&rq);
  radix_pool_free(p);
  case_end();
  free(a);
}

static void ka_keep_on_guards(void)
{
  char *a = malloc(BODY_CAP), *bb = malloc(BODY_CAP);
  size_t la = body2(a, 'x', 600, 'a', 300);
  size_t lb = body2(bb, 'x', 600, 'b', 1955);              /* 512 / 2561: below 20 % */
  radix_pool_t *p = pool_new();
  radix_req_t *rq = NULL;
  radix_route_in_t in;
  radix_route_out_t out;

  case_begin("ka_keep_on_guards (below threshold, spread, miss: keep, reason counted)");
  CHECK(request(p, &rq, a, la, 0, 200, NULL) == RADIX_LEARN_OK);
  CHECK(ka(p, &rq, bb, lb, 2, &out) == 0);
  CHECK(out.reason == RADIX_R_BELOW_THRESHOLD);
  radix_req_reset(rq);
  in_base(&in, p, a, la);
  g_inflight[0] = 4;                                       /* the candidate ep0 */
  CHECK(radix_route_keepalive(p, &rq, &in, 2, &out) == 0);
  CHECK(out.reason == RADIX_R_SPREAD);
  memset(g_inflight, 0, sizeof(g_inflight));
  radix_req_reset(rq);
  bb[60] = 'Q';                                             /* another system prompt: miss */
  CHECK(ka(p, &rq, bb, lb, 2, &out) == 0);
  CHECK(out.reason == RADIX_R_MISS);
  CHECK(radix_route_learn(p, rq, p, 2, 200, 3) == RADIX_LEARN_OK); /* kept leg learns */
  CHECK(decided(p, RADIX_R_BELOW_THRESHOLD) == 1 && decided(p, RADIX_R_SPREAD) == 1);
  CHECK(st_of(p, &p->st.ka_moved) == 0 && st_of(p, &p->st.kept_leg) == 0);
  radix_req_free(&rq);
  radix_pool_free(p);
  case_end();
  free(a); free(bb);
}

/* Rule B at the keep-alive leg: an idle candidate is a HIT although another
 * endpoint is busy, so a kept leg off the candidates is released. */
static void ka_rule_b_hit_releases(void)
{
  char *a = malloc(BODY_CAP);
  size_t la = body2(a, 'x', 600, 'a', 300);
  radix_pool_t *p = pool_new();
  radix_req_t *rq = NULL;
  radix_route_in_t in;
  radix_route_out_t out;

  case_begin("ka_rule_b_hit_releases (max - min > abs, pick - min <= abs: release)");
  CHECK(request(p, &rq, a, la, 0, 200, NULL) == RADIX_LEARN_OK);
  in_base(&in, p, a, la);
  g_inflight[0] = 0; g_inflight[1] = 0; g_inflight[2] = 4;
  CHECK(radix_route_keepalive(p, &rq, &in, 2, &out) == 1);
  CHECK(out.reason == RADIX_R_HIT && out.cand_mask == 0x1);
  CHECK(st_of(p, &p->st.ka_moved) == 1 && decided(p, RADIX_R_SPREAD) == 0);
  memset(g_inflight, 0, sizeof(g_inflight));
  radix_req_free(&rq);
  radix_pool_free(p);
  case_end();
  free(a);
}

static void ka_keep_gate_unknown_or_off(void)
{
  char *a = malloc(BODY_CAP);
  size_t la = body2(a, 'x', 600, 'a', 300);
  radix_pool_t *p = pool_new();
  radix_req_t *rq = NULL;
  radix_route_in_t in;
  radix_route_out_t out;
  uint64_t s0;
  long c0;

  case_begin("ka_keep_gate_unknown_or_off (gate unknown, no radix state: keep, no scan)");
  CHECK(request(p, &rq, a, la, 0, 200, NULL) == RADIX_LEARN_OK);
  radix_req_reset(rq);
  s0 = radix_route_scan_calls();
  in_base(&in, p, a, la);
  in.gates_unknown = 1;
  CHECK(radix_route_keepalive(p, &rq, &in, 2, &out) == 0);
  CHECK(radix_route_scan_calls() == s0);
  CHECK(st_of(p, &p->st.ka_moved) == 0 && st_of(p, &p->st.kept_leg) == 0);
  CHECK(decided(p, RADIX_R_HIT) == 0 && decided(p, RADIX_R_MISS) == 1); /* the teaching request only */
  CHECK(radix_route_learn(p, rq, p, 2, 200, 3) == RADIX_LEARN_NONE);    /* not scanned */
  radix_req_free(&rq);
  c0 = fa_calls;
  in_base(&in, NULL, a, la);
  CHECK(radix_route_keepalive(NULL, &rq, &in, 2, &out) == 0);
  CHECK(rq == NULL && fa_calls == c0 && radix_route_scan_calls() == s0);
  radix_pool_free(p);
  case_end();
  free(a);
}

static void e5_pipelined_not_scanned(void)
{
  char *a = malloc(BODY_CAP);
  size_t la = body2(a, 'x', 600, 'a', 300);
  radix_pool_t *p = pool_new();
  radix_req_t *rq = NULL;
  radix_route_in_t in;
  radix_route_out_t out;
  uint64_t s0;

  case_begin("e5_pipelined_not_scanned (a request begun under an owed answer: PIPELINED first, not scanned, nothing learned; keep-alive keeps the leg)");
  CHECK(request(p, &rq, a, la, 0, 200, NULL) == RADIX_LEARN_OK);  /* learned on ep0 */
  /* request N scanned and learnable, then N+1 begins under N's owed answer:
   * the reset at its message begin drops N's pending learn */
  radix_req_reset(rq);
  CHECK(decide_body(p, &rq, a, la, 0x7, &out) == 0 && out.reason == RADIX_R_HIT);
  radix_req_reset(rq);
  CHECK(radix_route_learn(p, rq, p, 0, 200, 3) == RADIX_LEARN_NONE);
  /* N+1 at selection: PIPELINED before every other gate, no scan */
  radix_req_reset(rq);
  s0 = radix_route_scan_calls();
  in_base(&in, p, a, la);
  in.pipelined = 1;
  in.route_subset = 1;
  CHECK(radix_route_decide(p, &rq, &in, &out) == -1);
  CHECK(out.reason == RADIX_R_PIPELINED);
  CHECK(radix_route_scan_calls() == s0);
  CHECK(decided(p, RADIX_R_PIPELINED) == 1 && decided(p, RADIX_R_ROUTE_SUBSET) == 0);
  CHECK(radix_route_learn(p, rq, p, 0, 200, 3) == RADIX_LEARN_NONE);
  /* N+1 at the keep-alive site, kept leg on ep2 (unpipelined it would be a
   * HIT on ep0 that releases the leg): kept, one PIPELINED, no scan */
  radix_req_reset(rq);
  in_base(&in, p, a, la);
  in.pipelined = 1;
  CHECK(radix_route_keepalive(p, &rq, &in, 2, &out) == 0);
  CHECK(out.reason == RADIX_R_PIPELINED);
  CHECK(radix_route_scan_calls() == s0);
  CHECK(st_of(p, &p->st.ka_moved) == 0 && st_of(p, &p->st.kept_leg) == 0);
  CHECK(decided(p, RADIX_R_PIPELINED) == 2);
  CHECK(radix_route_learn(p, rq, p, 2, 200, 4) == RADIX_LEARN_NONE);
  /* the same request unpipelined does move: the gate is what kept it */
  radix_req_reset(rq);
  in.pipelined = 0;
  CHECK(radix_route_keepalive(p, &rq, &in, 2, &out) == 1);
  radix_req_free(&rq);
  radix_pool_free(p);
  case_end();
  free(a);
}

static void misc_stats_take(void)
{
  char *a = malloc(BODY_CAP), line[1024];
  size_t la = body2(a, 'x', 600, 'a', 300);
  radix_pool_t *p = pool_new();
  radix_req_t *rq = NULL;

  case_begin("misc_stats_take (due and changed only; keep-alive counters in the line)");
  CHECK(radix_pool_stats_take(p, 1000, 5000, line, sizeof(line)) == 0); /* nothing counted */
  CHECK(request(p, &rq, a, la, 0, 200, NULL) == RADIX_LEARN_OK);
  CHECK(radix_pool_stats_take(p, 2000, 5000, line, sizeof(line)) > 0);
  CHECK(strstr(line, "miss=1") != NULL);
  CHECK(radix_pool_stats_take(p, 3000, 5000, line, sizeof(line)) == 0); /* not due */
  CHECK(radix_pool_stats_take(p, 8000, 5000, line, sizeof(line)) == 0); /* due, unchanged */
  {
    radix_route_out_t out;
    radix_route_in_t in;
    in_base(&in, p, a, la);
    CHECK(radix_route_keepalive(p, &rq, &in, 2, &out) == 1);
  }
  CHECK(radix_pool_stats_take(p, 14000, 5000, line, sizeof(line)) > 0);
  CHECK(strstr(line, "ka_moved=1") != NULL);
  radix_req_free(&rq);
  radix_pool_free(p);
  case_end();
  free(a);
}

static void e10_other_generation(void)
{
  char *a = malloc(BODY_CAP);
  size_t la = body2(a, 'x', 600, 'a', 300);
  radix_pool_t *p_old = pool_new(), *p_new = pool_new();
  radix_req_t *rq = NULL;
  radix_route_out_t out;

  case_begin("e10_other_generation (late reply learns nowhere new)");
  CHECK(decide_body(p_old, &rq, a, la, 0x7, &out) == -1 && out.reason == RADIX_R_MISS);
  /* the connection's pool hold now names a newer pool object */
  CHECK(radix_route_learn(p_new, rq, p_new, 0, 200, 2) == RADIX_LEARN_NONE);
  radix_req_reset(rq);
  CHECK(decide_body(p_new, &rq, a, la, 0x7, &out) == -1 && out.reason == RADIX_R_MISS);
  radix_req_free(&rq);
  radix_pool_free(p_old);
  radix_pool_free(p_new);
  case_end();
  free(a);
}

#define RACE_THREADS 6
#define RACE_ITERS   3000

static radix_pool_t *race_pool;
static volatile int race_go;
static int race_bad;

static void *race_worker(void *arg)
{
  long id = (long)arg;
  char *b = malloc(BODY_CAP);
  radix_req_t *rq = NULL;
  uint64_t s = (uint64_t)id * 0x9E3779B97F4A7C15ull + 1;

  while (!__atomic_load_n(&race_go, __ATOMIC_ACQUIRE))
    ;
  for (int i = 0; i < RACE_ITERS; i++) {
    radix_route_in_t in;
    radix_route_out_t out;
    uint32_t inflight[RADIX_MAX_EP] = { 0 };
    s ^= s << 13; s ^= s >> 7; s ^= s << 17;
    size_t len = body2(b, (char)('a' + (s % 8)), 300 + (s >> 8) % 600,
                       (char)('a' + (s >> 20) % 4), 100 + (s >> 24) % 400);
    in_base(&in, race_pool, b, len);
    in.inflight = inflight;
    in.n_eps = 8;
    in.eligible = (uint32_t)(0xFF & ~(1u << (s >> 32) % 8));
    in.now = (uint32_t)i;
    int ep = radix_route_decide(race_pool, &rq, &in, &out);
    if (ep >= 0 && !(in.eligible & (1u << ep)))
      __atomic_fetch_add(&race_bad, 1, __ATOMIC_RELAXED);
    if (id == 0 && i % 50 == 0)
      radix_pool_purge_ep(race_pool, (unsigned)(s >> 40) % 8);
    else
      (void)radix_route_learn(race_pool, rq, race_pool,
                              ep >= 0 ? ep : (int)((s >> 44) % 8), 200, (uint32_t)i);
    radix_req_reset(rq);
  }
  radix_req_free(&rq);
  free(b);
  return NULL;
}

static void e10_race(void)
{
  pthread_t th[RACE_THREADS];
  radix_stats_t ts;

  case_begin("e10_race (decide / learn / purge on one pool; TSan build)");
  race_pool = pool_new();
  race_bad = 0;
  race_go = 0;
  for (long i = 0; i < RACE_THREADS; i++)
    pthread_create(&th[i], NULL, race_worker, (void *)i);
  __atomic_store_n(&race_go, 1, __ATOMIC_RELEASE);
  for (int i = 0; i < RACE_THREADS; i++)
    pthread_join(th[i], NULL);
  CHECK(race_bad == 0);
  CHECK(race_pool && race_pool->trie != NULL);
  if (race_pool && race_pool->trie) {
    radix_trie_stats(race_pool->trie, &ts);
    CHECK(ts.nodes > 1);
  }
  CHECK(race_pool && __atomic_load_n(&race_pool->st.decided[RADIX_R_HIT],
                                     __ATOMIC_RELAXED) > 0);
  radix_pool_free(race_pool);
  case_end();
}

/* ======================================================================== */
/* D-2, D-4b, counters, time, create                                         */

static void d2_req_lifecycle(void)
{
  char *a = malloc(BODY_CAP);
  size_t la = body2(a, 'x', 600, 'a', 300);
  radix_pool_t *p = pool_new();
  radix_req_t *rq = NULL, *first;
  radix_route_out_t out;
  long live0 = fa_live;

  case_begin("d2_req_lifecycle (reset, reuse, free; nothing left allocated)");
  CHECK(decide_body(p, &rq, a, la, 0x7, &out) == -1);
  CHECK(rq != NULL);
  CHECK(fa_live == live0 + 1);
  first = rq;
  radix_req_reset(rq);
  radix_req_reset(rq);
  CHECK(decide_body(p, &rq, a, la, 0x7, &out) == -1);
  CHECK(rq == first);                                    /* reused, not re-allocated */
  CHECK(fa_live == live0 + 1);
  radix_req_free(&rq);
  CHECK(rq == NULL);
  CHECK(fa_live == live0);
  radix_req_free(&rq);
  radix_req_free(NULL);
  radix_req_reset(NULL);
  radix_pool_free(p);
  radix_pool_free(NULL);
  case_end();
  free(a);
}

static void d4b_many_tokens(void)
{
  char *b = malloc(BODY_CAP);
  size_t len = body_many(b, 2000);     /* about 10,000 JSON tokens */
  radix_pool_t *p = pool_new();
  radix_req_t *rq = NULL;
  radix_route_out_t out;

  case_begin("d4b_many_tokens (above 8,192 JSON tokens is routed)");
  CHECK(len < RADIX_ROUTE_MAX_BODY);
  CHECK(request(p, &rq, b, len, 1, 200, &out) == RADIX_LEARN_OK);
  CHECK(out.reason == RADIX_R_MISS && out.scan_rc == RADIX_SCAN_OK);
  CHECK(decide_body(p, &rq, b, len, 0x7, &out) == 1);
  CHECK(out.reason == RADIX_R_HIT && out.matched_bytes == out.stream_bytes / 256 * 256);
  radix_req_free(&rq);
  radix_pool_free(p);
  case_end();
  free(b);
}

static void misc_stats_line(void)
{
  static const char marker[] = "MARKERQ7Z";
  char *b = malloc(BODY_CAP), line[1024];
  size_t n = 0;
  radix_pool_t *p = pool_new();
  radix_req_t *rq = NULL;
  radix_route_out_t out;
  int names_ok = 1;

  case_begin("misc_stats_line (names and counts only, rate limit)");
  n += (size_t)sprintf(b, "{\"model\":\"m\",\"messages\":[{\"role\":\"user\",\"content\":\"");
  for (int i = 0; i < 40; i++)
    n += (size_t)sprintf(b + n, "%s ", marker);
  n += (size_t)sprintf(b + n, "\"}]}");
  CHECK(request(p, &rq, b, n, 0, 200, NULL) == RADIX_LEARN_OK);
  CHECK(decide_body(p, &rq, b, n, 0x7, &out) == 0);
  radix_req_reset(rq);
  CHECK(decide_body(p, &rq, b, body_raw(b, "{\"model\":\"m\",\"messages\":[{\"role\":"
                    "\"user\",\"content\":\"MARKERQ7Z\"}]}"), 0x7, &out) == -1);
  CHECK(radix_pool_stats_format(p, line, sizeof(line)) > 0);
  CHECK(strstr(line, "hit=1") != NULL);
  CHECK(strstr(line, "miss=1") != NULL);
  CHECK(strstr(line, "scan.short=1") != NULL);
  CHECK(strstr(line, "learn.ok=1") != NULL);
  CHECK(strstr(line, "scans=3") != NULL);
  CHECK(strstr(line, "scan_us_sum=") != NULL);    /* scan time total, for the cost measurement */
  CHECK(strstr(line, marker) == NULL);
  CHECK(strstr(line, "=0") == NULL);                 /* non-zero only */
  for (int r = 0; r < RADIX_R__COUNT; r++) {
    const char *nm = radix_route_reason_name((radix_route_reason_t)r);
    if (!nm || !nm[0] || !strcmp(nm, "?"))
      names_ok = 0;
    for (int q = 0; q < r; q++)
      if (nm && !strcmp(nm, radix_route_reason_name((radix_route_reason_t)q)))
        names_ok = 0;
  }
  for (int r = 0; r < RADIX_LEARN__COUNT; r++) {
    const char *nm = radix_learn_rc_name((radix_learn_rc_t)r);
    if (!nm || !nm[0] || !strcmp(nm, "?"))
      names_ok = 0;
  }
  CHECK(names_ok);
  CHECK(!strcmp(radix_route_reason_name(RADIX_R_BELOW_THRESHOLD), "below_threshold"));
  CHECK(!strcmp(radix_learn_rc_name(RADIX_LEARN_TOO_LARGE), "too_large"));
  CHECK(radix_pool_stats_due(p, 1000, 60000) == 1);
  CHECK(radix_pool_stats_due(p, 2000, 60000) == 0);
  CHECK(radix_pool_stats_due(p, 61000, 60000) == 1);
  CHECK(radix_pool_stats_due(NULL, 61000, 60000) == 0);
  radix_req_free(&rq);
  radix_pool_free(p);
  case_end();
  free(b);
}

typedef struct {
  radix_pool_t *p;
  const char *body;
  size_t len;
  int ep;
  int done;
} decide_job_t;

static void *decide_job(void *v)
{
  decide_job_t *j = v;
  radix_req_t *rq = NULL;
  radix_route_out_t out;
  j->ep = decide_body(j->p, &rq, j->body, j->len, 0x7, &out);
  radix_req_free(&rq);
  __atomic_store_n(&j->done, 1, __ATOMIC_RELEASE);
  return NULL;
}

static void misc_lock_wait_counters(void)
{
  char *a = malloc(BODY_CAP), *c = malloc(BODY_CAP), line[1024];
  size_t la = body2(a, 'x', 600, 'a', 300);
  size_t lc = body2(c, 'y', 600, 'a', 300);
  radix_pool_t *p = pool_new();
  radix_req_t *rq = NULL;
  radix_route_out_t out;
  decide_job_t dj;
  learn_job_t lj;
  pthread_t th;
  struct timespec ts = { 0, 60 * 1000 * 1000 };
  const char *f;

  case_begin("misc_lock_wait_counters (lookup and learn wait maxima, in the counters line)");
  CHECK(request(p, &rq, a, la, 0, 200, NULL) == RADIX_LEARN_OK);
  CHECK(__atomic_load_n(&p->st.lookup_wait_ns_max, __ATOMIC_RELAXED) < 50u * 1000 * 1000);
  /* a lookup waits for a writer */
  CHECK(pthread_rwlock_wrlock(&p->lock) == 0);
  dj = (decide_job_t){ .p = p, .body = a, .len = la, .ep = -2 };
  pthread_create(&th, NULL, decide_job, &dj);
  nanosleep(&ts, NULL);
  CHECK(!__atomic_load_n(&dj.done, __ATOMIC_ACQUIRE));
  pthread_rwlock_unlock(&p->lock);
  pthread_join(th, NULL);
  CHECK(dj.ep == 0);
  CHECK(__atomic_load_n(&p->st.lookup_wait_ns_max, __ATOMIC_RELAXED) >= 50u * 1000 * 1000);
  /* a learn waits for a reader */
  CHECK(decide_body(p, &rq, c, lc, 0x7, &out) == -1 && out.reason == RADIX_R_MISS);
  CHECK(__atomic_load_n(&p->st.learn_wait_ns_max, __ATOMIC_RELAXED) < 50u * 1000 * 1000);
  CHECK(pthread_rwlock_rdlock(&p->lock) == 0);
  lj = (learn_job_t){ .p = p, .rq = rq, .ep = 1, .rc = RADIX_LEARN__COUNT };
  pthread_create(&th, NULL, learn_job, &lj);
  nanosleep(&ts, NULL);
  pthread_rwlock_unlock(&p->lock);
  pthread_join(th, NULL);
  CHECK(lj.rc == RADIX_LEARN_OK);
  CHECK(__atomic_load_n(&p->st.learn_wait_ns_max, __ATOMIC_RELAXED) >= 50u * 1000 * 1000);
  /* both in the counters line, in microseconds */
  CHECK(radix_pool_stats_format(p, line, sizeof(line)) > 0);
  f = strstr(line, "lookup_wait_us_max=");
  CHECK(f && strtoull(f + strlen("lookup_wait_us_max="), NULL, 10) >= 50000);
  f = strstr(line, "learn_wait_us_max=");
  CHECK(f && strtoull(f + strlen("learn_wait_us_max="), NULL, 10) >= 50000);
  radix_req_free(&rq);
  radix_pool_free(p);
  case_end();
  free(a); free(c);
}

static void misc_time_and_create(void)
{
  uint32_t t0, t1;
  struct timespec ts = { 0, 350 * 1000 * 1000 };
  long live0 = fa_live;
  int done = 0;

  case_begin("misc_time_and_create (100 ms ticks; create under allocation failure)");
  t0 = radix_now();
  nanosleep(&ts, NULL);
  t1 = radix_now();
  CHECK(t1 >= t0 + 2 && t1 <= t0 + 6);
  for (long k = 0; k < 16 && !done; k++) {
    radix_route_cfg_t cfg;
    radix_pool_t *p;
    memset(&cfg, 0, sizeof(cfg));
    fa_calls = 0;
    fa_fail_at = k;
    p = radix_pool_create(&cfg);
    if (!p) {
      CHECK(fa_live == live0);
      continue;
    }
    done = fa_fail_at >= 0;     /* no injected failure left: all succeeded */
    fa_fail_at = -1;
    CHECK(p->trie != NULL);
    CHECK(p->cfg.match_pct == RADIX_ROUTE_MATCH_PCT);
    CHECK(p->cfg.max_body == RADIX_ROUTE_MAX_BODY);
    CHECK(p->cfg.scan_cap == RADIX_ROUTE_SCAN_CAP);
    radix_pool_free(p);
    CHECK(fa_live == live0);
  }
  CHECK(done);
  case_end();
}

int main(void)
{
  e1_off_no_scan_no_alloc();
  e1_gates_before_scan();
  e3_pinned_not_learnable();
  e3_ineligible_never_picked();
  e3_sticky_is_pinned();
  e5_pipelined_not_scanned();
  e4_threshold();
  e4_spread_and_tiebreak();
  e4_rule_b();
  e4_scan_skips();
  e4_miss_workcap_ns_nomem();
  e5_once_on_2xx();
  e5_no_learn_on_error_or_no_reply();
  e5_interim_then_200();
  e5_final_endpoint();
  e5_keepalive_independent();
  e5_learnable_outcomes();
  e5_whole_key_no_lock();
  e7_purge_and_relearn();
  e7_learned_mask();
  e7_purge_under_readers();
  e7_refresh_purge_mask();
  ka_keep_when_kept_is_candidate();
  ka_release_when_kept_not_candidate();
  ka_keep_on_guards();
  ka_rule_b_hit_releases();
  ka_keep_gate_unknown_or_off();
  misc_stats_take();
  e10_other_generation();
  e10_race();
  d2_req_lifecycle();
  d4b_many_tokens();
  misc_stats_line();
  misc_lock_wait_counters();
  misc_time_and_create();
  CHECK(fa_live == 0);
  printf("test_radix_route: %s (%d failed checks)\n", g_fail ? "FAIL" : "PASS", g_fail);
  return g_fail ? 1 : 0;
}
