/* SPDX-License-Identifier: (GPL-2.0) */
/* test_radix_cfg.c - a rule's prefix-affinity arguments, from the eBPF map
 * value to the pool's radix state (ASan + UBSan + LeakSanitizer).
 *
 * The three arguments ride dp_proxy_tacts (llb_dpapi.h, the NAT map value
 * the Go control plane fills through cgo) -> proxy_arg (llb_conv_nat2proxy)
 * -> the pool (sp_radix_apply, sockproxy_radix_cfg.h, called by both create
 * paths and the refresh block of proxy_add_entry; test_radix_cfg_wiring.py
 * holds those call sites and the conversion's copies).
 *
 * Pinned here:
 *   layout  the three bytes sit in the padding after apikey_auth (53, 54, 55;
 *           49-51 in the DPU-slim shape), lts stays at 56, the struct size is
 *           unchanged; in proxy_arg they take epp_pad, epp_timeout_ms stays;
 *           mode words 0 off, 1 radix (the Go side writes them)
 *   zeros   an all-zero argument block (a Gateway that does not know the
 *           fields) creates no radix state
 *   xition  off -> radix creates the state, on, with the rule's threshold and
 *           balance (0 = default); a retune keeps the object and what was
 *           learned; radix -> off keeps the object, off and empty, and
 *           sp_radix_active gives NULL; radix again reuses the object; a pool
 *           that cannot use radix (P/D, KV-exact, MCP) gets none
 *   free    the object is freed once, with the pool (LeakSanitizer)
 *   log     one info line per real change, with the values in force (after
 *           the default and the clamp); a refresh that changes neither the
 *           mode nor a value logs nothing; "off (no memory)" kept
 *   zero    0 resolves to the default for both values, on create and retune
 *
 * Build: make test_radix_cfg
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>
#include <netdb.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netinet/in.h>

#include <linux/bpf.h>
#include "bpf.h"
#include "libbpf.h"
#include "uthash.h"
#include "pdi.h"
#include "llb_dpapi.h"
#include "sockproxy.h"
#include "sockproxy_radix.c"
#include "sockproxy_radix_scan.c"
#include "sockproxy_radix_route.c"
#include "sockproxy_radix_cfg.h"

/* ---- layout (OD-1: offsets 53-55 after apikey_auth, lts at 56) ---- */

#define TACTS dp_proxy_tacts
_Static_assert(sizeof(((struct TACTS *)0)->prefix_affinity_mode) == 1, "mode is a byte");
_Static_assert(sizeof(((struct TACTS *)0)->prefix_affinity_match_pct) == 1, "match_pct is a byte");
_Static_assert(sizeof(((struct TACTS *)0)->prefix_affinity_balance_abs) == 1, "balance_abs is a byte");
#ifndef HAVE_DP_DPU_SLIM
_Static_assert(offsetof(struct TACTS, apikey_auth) == 52, "apikey_auth at 52");
_Static_assert(offsetof(struct TACTS, prefix_affinity_mode) == 53, "mode at 53");
_Static_assert(offsetof(struct TACTS, prefix_affinity_match_pct) == 54, "match_pct at 54");
_Static_assert(offsetof(struct TACTS, prefix_affinity_balance_abs) == 55, "balance_abs at 55");
#else
_Static_assert(offsetof(struct TACTS, apikey_auth) == 48, "apikey_auth at 48 (DPU slim)");
_Static_assert(offsetof(struct TACTS, prefix_affinity_mode) == 49, "mode at 49 (DPU slim)");
_Static_assert(offsetof(struct TACTS, prefix_affinity_match_pct) == 50, "match_pct at 50 (DPU slim)");
_Static_assert(offsetof(struct TACTS, prefix_affinity_balance_abs) == 51, "balance_abs at 51 (DPU slim)");
#endif
_Static_assert(offsetof(struct TACTS, lts) == 56, "lts stays at 56");
#if !defined(HAVE_DP_DPU_SLIM) && !defined(HAVE_MTLS)
_Static_assert(sizeof(struct TACTS) == 3008, "dp_proxy_tacts size unchanged");
#elif !defined(HAVE_DP_DPU_SLIM)
_Static_assert(sizeof(struct TACTS) == 4040, "dp_proxy_tacts size unchanged (mTLS)");
#endif

/* proxy_arg: the three bytes take epp_pad; the deadline after them stays */
_Static_assert(offsetof(struct proxy_arg, prefix_affinity_mode) == offsetof(struct proxy_arg, epp_mode) + 1,
               "proxy_arg mode right after epp_mode");
_Static_assert(offsetof(struct proxy_arg, prefix_affinity_match_pct) == offsetof(struct proxy_arg, epp_mode) + 2,
               "proxy_arg match_pct");
_Static_assert(offsetof(struct proxy_arg, prefix_affinity_balance_abs) == offsetof(struct proxy_arg, epp_mode) + 3,
               "proxy_arg balance_abs");
/* epp_mode sits at an odd offset: after the three bytes come two bytes of
 * alignment padding, then the u32 deadline, as on native a6f5cc6 (epp_mode
 * 1714, epp_timeout_ms 1720 in the build of this test). */
_Static_assert(offsetof(struct proxy_arg, epp_timeout_ms) == offsetof(struct proxy_arg, epp_mode) + 6,
               "proxy_arg epp_timeout_ms stays where it was (epp_mode, three bytes, two of padding)");
_Static_assert(sizeof(struct proxy_arg) <= 4096, "proxy_arg must fit its map value");

/* the words the Go side writes */
_Static_assert(SP_PREFIX_AFFINITY_OFF == 0 && SP_PREFIX_AFFINITY_RADIX == 1,
               "prefix_affinity_mode words drifted from the Go mirror");

static int fails;
#define CHECK(c) do { if (!(c)) { fails++; printf("    check failed: %s (line %d)\n", #c, __LINE__); } } while (0)

static size_t body(char *b, char c)
{
  size_t n = (size_t)sprintf(b, "{\"model\":\"m\",\"messages\":[{\"role\":\"system\",\"content\":\"");
  memset(b + n, c, 900); n += 900;
  n += (size_t)sprintf(b + n, "\"}]}");
  return n;
}

/* One request through the pool's active radix state: decide, then a 200
 * from ep. Returns the decision's endpoint. */
static int use(proxy_epval_t *pool, radix_req_t **rq, const char *b, size_t len, int ep)
{
  radix_pool_t *r = sp_radix_active(pool);
  radix_route_in_t in;
  radix_route_out_t out;
  int pick;

  if (!r)
    return -2;
  memset(&in, 0, sizeof(in));
  in.pool_id = pool; in.ai_gw_mode = 1; in.fc_active = 1; in.model = "m"; in.model_len = 1;
  in.body = b; in.body_len = len; in.eligible = 0x7; in.n_eps = 3; in.selector_pick = 0;
  pick = radix_route_decide(r, rq, &in, &out);
  (void)radix_route_learn(r, *rq, pool, ep, 200, 1);
  radix_req_reset(*rq);
  return pick;
}

static void arg_set(proxy_arg_t *arg, uint8_t mode, uint8_t pct, uint8_t bal)
{
  memset(arg, 0, sizeof(*arg));
  arg->prefix_affinity_mode = mode;
  arg->prefix_affinity_match_pct = pct;
  arg->prefix_affinity_balance_abs = bal;
}

static void t_zero_args_no_state(void)
{
  proxy_epval_t *pool = calloc(1, sizeof(*pool));
  proxy_arg_t arg;

  printf("Test: an all-zero argument block creates no radix state\n");
  memset(&arg, 0, sizeof(arg));
  sp_radix_apply(pool, &arg);
  CHECK(pool->radix == NULL);
  CHECK(sp_radix_active(pool) == NULL);
  sp_radix_apply(pool, &arg);                    /* a refresh: still none */
  CHECK(pool->radix == NULL);
  free(pool);
}

static void t_transitions(void)
{
  proxy_epval_t *pool = calloc(1, sizeof(*pool));
  proxy_arg_t arg;
  radix_req_t *rq = NULL;
  radix_pool_t *obj;
  char *b = malloc(4096);
  size_t len = body(b, 'x');

  printf("Test: off -> radix -> retune -> off -> radix on one pool\n");
  /* off -> radix, defaults */
  arg_set(&arg, SP_PREFIX_AFFINITY_RADIX, 0, 0);
  CHECK(sp_radix_apply(pool, &arg) == SP_RADIX_CREATED);
  obj = pool->radix;
  CHECK(obj != NULL && sp_radix_active(pool) == obj);
  CHECK(obj && obj->cfg.match_pct == RADIX_ROUTE_MATCH_PCT && obj->cfg.balance_abs == RADIX_ROUTE_BALANCE_ABS);
  CHECK(use(pool, &rq, b, len, 1) == -1);        /* miss, learned on ep1 */
  CHECK(use(pool, &rq, b, len, 1) == 1);         /* hit */

  /* retune: same object, values in force, learned state kept */
  arg_set(&arg, SP_PREFIX_AFFINITY_RADIX, 55, 7);
  CHECK(sp_radix_apply(pool, &arg) == SP_RADIX_KEPT);
  CHECK(pool->radix == obj && sp_radix_active(pool) == obj);
  CHECK(obj->cfg.match_pct == 55 && obj->cfg.balance_abs == 7);
  CHECK(use(pool, &rq, b, len, 1) == 1);

  /* radix -> off: same object, off, nothing learned left, not active */
  arg_set(&arg, SP_PREFIX_AFFINITY_OFF, 55, 7);
  CHECK(sp_radix_apply(pool, &arg) == SP_RADIX_DISABLED);
  CHECK(pool->radix == obj);
  CHECK(!radix_pool_is_on(obj) && obj->learned_mask == 0);
  CHECK(sp_radix_active(pool) == NULL);
  CHECK(use(pool, &rq, b, len, 1) == -2);
  CHECK(sp_radix_apply(pool, &arg) == SP_RADIX_NONE);     /* off again: nothing */

  /* radix again: the same object, on, empty, the rule's values */
  arg_set(&arg, SP_PREFIX_AFFINITY_RADIX, 30, 2);
  CHECK(sp_radix_apply(pool, &arg) == SP_RADIX_ENABLED);
  CHECK(pool->radix == obj && sp_radix_active(pool) == obj);
  CHECK(obj->cfg.match_pct == 30 && obj->cfg.balance_abs == 2);
  CHECK(use(pool, &rq, b, len, 2) == -1);        /* empty: miss, learned on ep2 */
  CHECK(use(pool, &rq, b, len, 2) == 2);

  /* the pool goes: its finalizer frees the object once (proxy_pool_finalize) */
  radix_req_free(&rq);
  radix_pool_free(pool->radix);
  pool->radix = NULL;
  free(b);
  free(pool);
}

static void t_ineligible_pools(void)
{
  proxy_arg_t arg;

  printf("Test: P/D, KV-exact and MCP pools get no radix state\n");
  arg_set(&arg, SP_PREFIX_AFFINITY_RADIX, 0, 0);
  for (int k = 0; k < 3; k++) {
    proxy_epval_t *pool = calloc(1, sizeof(*pool));
    if (k == 0) pool->pd_disagg_enabled = 1;
    if (k == 1) pool->kv_exact_mode = 3;
    if (k == 2) pool->mcp_stateless = 1;
    CHECK(sp_radix_apply(pool, &arg) == SP_RADIX_INELIGIBLE);
    CHECK(pool->radix == NULL && sp_radix_active(pool) == NULL);
    free(pool);
  }
}

static void t_values_clamped(void)
{
  proxy_epval_t *pool = calloc(1, sizeof(*pool));
  proxy_arg_t arg;

  printf("Test: a threshold above 100 is held at 100\n");
  arg_set(&arg, SP_PREFIX_AFFINITY_RADIX, 250, 255);
  CHECK(sp_radix_apply(pool, &arg) == SP_RADIX_CREATED);
  CHECK(pool->radix && pool->radix->cfg.match_pct == 100);
  CHECK(pool->radix && pool->radix->cfg.balance_abs == 255);
  radix_pool_free(pool->radix);
  free(pool);
}

/* The transition and its info line, as proxy_add_entry logs it. */
static int step(proxy_epval_t *pool, uint8_t mode, uint8_t pct, uint8_t bal,
                char *line, size_t cap)
{
  proxy_arg_t arg;
  sp_radix_prev_t pv = sp_radix_prev(pool);
  int rc;

  arg_set(&arg, mode, pct, bal);
  rc = sp_radix_apply(pool, &arg);
  sp_radix_line(line, cap, pool, &pv, rc);
  return rc;
}

static void t_log_lines(void)
{
  proxy_epval_t *pool = calloc(1, sizeof(*pool));
  char line[256];

  printf("Test: one info line per real change, with the values in force; unchanged logs nothing\n");
  snprintf(pool->ephash_key, sizeof(pool->ephash_key), "%s", "api.example|/v1");
  /* off stays off: nothing */
  CHECK(step(pool, SP_PREFIX_AFFINITY_OFF, 0, 0, line, sizeof(line)) == SP_RADIX_NONE);
  CHECK(line[0] == '\0');
  /* off -> radix, defaults resolved */
  CHECK(step(pool, SP_PREFIX_AFFINITY_RADIX, 0, 0, line, sizeof(line)) == SP_RADIX_CREATED);
  CHECK(!strcmp(line, "[RADIX] pool 'api.example|/v1': on (match_pct=20 balance_abs=3)"));
  /* the same again (a refresh): nothing */
  CHECK(step(pool, SP_PREFIX_AFFINITY_RADIX, 0, 0, line, sizeof(line)) == SP_RADIX_KEPT);
  CHECK(line[0] == '\0');
  /* 20 and 3 written out are the same values: nothing */
  CHECK(step(pool, SP_PREFIX_AFFINITY_RADIX, 20, 3, line, sizeof(line)) == SP_RADIX_KEPT);
  CHECK(line[0] == '\0');
  /* a retune: the values in force, the threshold held at 100 */
  CHECK(step(pool, SP_PREFIX_AFFINITY_RADIX, 200, 9, line, sizeof(line)) == SP_RADIX_KEPT);
  CHECK(!strcmp(line, "[RADIX] pool 'api.example|/v1': match_pct=100 balance_abs=9"));
  /* only the balance changes */
  CHECK(step(pool, SP_PREFIX_AFFINITY_RADIX, 100, 4, line, sizeof(line)) == SP_RADIX_KEPT);
  CHECK(!strcmp(line, "[RADIX] pool 'api.example|/v1': match_pct=100 balance_abs=4"));
  /* 0 resets both to the defaults */
  CHECK(step(pool, SP_PREFIX_AFFINITY_RADIX, 0, 0, line, sizeof(line)) == SP_RADIX_KEPT);
  CHECK(!strcmp(line, "[RADIX] pool 'api.example|/v1': match_pct=20 balance_abs=3"));
  CHECK(pool->radix->cfg.match_pct == 20 && pool->radix->cfg.balance_abs == 3);
  /* radix -> off, off again */
  CHECK(step(pool, SP_PREFIX_AFFINITY_OFF, 0, 0, line, sizeof(line)) == SP_RADIX_DISABLED);
  CHECK(!strcmp(line, "[RADIX] pool 'api.example|/v1': off"));
  CHECK(step(pool, SP_PREFIX_AFFINITY_OFF, 50, 5, line, sizeof(line)) == SP_RADIX_NONE);
  CHECK(line[0] == '\0');
  /* on again on the kept object */
  CHECK(step(pool, SP_PREFIX_AFFINITY_RADIX, 40, 0, line, sizeof(line)) == SP_RADIX_ENABLED);
  CHECK(!strcmp(line, "[RADIX] pool 'api.example|/v1': on (match_pct=40 balance_abs=3)"));
  /* allocation failure keeps today's line; an ineligible pool logs nothing */
  {
    sp_radix_prev_t pv = { 0, 0, 0 };
    sp_radix_line(line, sizeof(line), pool, &pv, SP_RADIX_NOMEM);
    CHECK(!strcmp(line, "[RADIX] pool 'api.example|/v1': off (no memory)"));
    sp_radix_line(line, sizeof(line), pool, &pv, SP_RADIX_INELIGIBLE);
    CHECK(line[0] == '\0');
  }
  radix_pool_free(pool->radix);
  free(pool);
}

static void t_zero_is_default(void)
{
  proxy_epval_t *pool = calloc(1, sizeof(*pool));
  proxy_arg_t arg;

  printf("Test: 0 resolves to the default for both values, on create and on a retune\n");
  arg_set(&arg, SP_PREFIX_AFFINITY_RADIX, 0, 0);
  CHECK(sp_radix_apply(pool, &arg) == SP_RADIX_CREATED);
  CHECK(pool->radix->cfg.match_pct == RADIX_ROUTE_MATCH_PCT);
  CHECK(pool->radix->cfg.balance_abs == RADIX_ROUTE_BALANCE_ABS);
  arg_set(&arg, SP_PREFIX_AFFINITY_RADIX, 70, 8);
  CHECK(sp_radix_apply(pool, &arg) == SP_RADIX_KEPT);
  arg_set(&arg, SP_PREFIX_AFFINITY_RADIX, 0, 8);
  CHECK(sp_radix_apply(pool, &arg) == SP_RADIX_KEPT);
  CHECK(pool->radix->cfg.match_pct == RADIX_ROUTE_MATCH_PCT && pool->radix->cfg.balance_abs == 8);
  arg_set(&arg, SP_PREFIX_AFFINITY_RADIX, 70, 0);
  CHECK(sp_radix_apply(pool, &arg) == SP_RADIX_KEPT);
  CHECK(pool->radix->cfg.match_pct == 70 && pool->radix->cfg.balance_abs == RADIX_ROUTE_BALANCE_ABS);
  /* the clamp on a retune too */
  arg_set(&arg, SP_PREFIX_AFFINITY_RADIX, 101, 0);
  CHECK(sp_radix_apply(pool, &arg) == SP_RADIX_KEPT);
  CHECK(pool->radix->cfg.match_pct == 100);
  radix_pool_free(pool->radix);
  free(pool);
}

int main(void)
{
  t_zero_args_no_state();
  t_transitions();
  t_ineligible_pools();
  t_values_clamped();
  t_log_lines();
  t_zero_is_default();
  printf("test_radix_cfg: %s (%d failed checks)\n", fails ? "FAIL" : "PASS", fails);
  return fails ? 1 : 0;
}
