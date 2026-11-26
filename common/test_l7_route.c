/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_l7_route.c - where an L7 FORWARD sends a request, and what it holds.
 *
 *   - a FORWARD that names members of the pool gets the listener's own pool,
 *     with those members marked on the request: no copy of the pool exists,
 *     so nothing is shared between two requests and nothing outlives the
 *     policy;
 *   - a FORWARD that names none gets the pool as it selects; one that names
 *     only members the pool does not have gets none;
 *   - the selection over a route follows the pool's health as it is NOW, and
 *     the route's weights;
 *   - a policy replaced and detached while requests are dispatched on the
 *     listener, and while they read the route's cookie marker and run the
 *     header filters (which read the listener's trusted ranges, rewritten
 *     with the policy): no request reads a freed route or a range being
 *     rewritten (ASan, TSan).
 *
 * Build (wired into `make test_l7route`): links the policy translation unit
 * and stubs what it calls out to, as test_l7origin does.
 */

#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "uthash.h"
#include "sockproxy_internal.h"
#include "sockproxy_l7policy.h"
#include "sockproxy_pool.h"
#include "sockproxy_qsbr.h"

static int checks, failures;

#define CHECK(cond, ...) do {                                        \
    checks++;                                                        \
    if (cond) {                                                      \
      printf("ok %d - ", checks); printf(__VA_ARGS__); printf("\n"); \
    } else {                                                         \
      failures++;                                                    \
      printf("FAIL %d - ", checks); printf(__VA_ARGS__);             \
      printf("   (%s:%d)\n", __FILE__, __LINE__);                    \
    }                                                                \
  } while (0)

/* ---- what the translation units call out to ----------------------------- */

proxy_struct_t *proxy_struct;
int proxy_lock_trace_state = 0;

void circuit_breaker_lock(void) {}
void circuit_breaker_unlock(void) {}
void log_log(int level, const char *file, int line, const char *fmt, ...)
{
  (void)level; (void)file; (void)line; (void)fmt;
}
int proxy_lock_trace_init(void) { return 0; }
void proxy_lock_trace_acquire(pthread_rwlock_t *l, int wr, const char *f, int n)
{ (void)l; (void)wr; (void)f; (void)n; }
void proxy_lock_trace_release(pthread_rwlock_t *l) { (void)l; }
int proxy_h2_send_l7_synthetic(proxy_fd_ent_t *pfe, int status_code,
                               const char *location, const char *body)
{ (void)pfe; (void)status_code; (void)location; (void)body; return 0; }
/* The records of the H1 answers (sockproxy_http.c); the H2 stub above
 * answers every request in these tests. */
int proxy_note_local_answer(proxy_fd_ent_t *pfe, uint16_t status)
{ (void)pfe; (void)status; return 0; }
int proxy_note_local_refusal(proxy_fd_ent_t *pfe, uint16_t status)
{ (void)pfe; (void)status; return 0; }
void proxy_record_local_deny(proxy_fd_ent_t *pfe, int stage, int status,
                             const char *code)
{ (void)pfe; (void)stage; (void)status; (void)code; }
void proxy_record_local_completion(proxy_fd_ent_t *pfe, uint16_t status)
{ (void)pfe; (void)status; }
int extract_cookie_by_name(const char *headers, const char *name,
                           char *value, size_t value_size)
{ (void)headers; (void)name; (void)value; (void)value_size; return -1; }
int extract_query_param_value(const char *url, const char *name,
                              char *value, size_t value_size)
{ (void)url; (void)name; (void)value; (void)value_size; return -1; }
void strip_port_from_hostname(const char *host_with_port, char *host_only,
                              size_t host_only_size)
{
  if (host_only && host_only_size)
    snprintf(host_only, host_only_size, "%s", host_with_port ? host_with_port : "");
}
bool cmp_proxy_ent(proxy_ent_t *e1, proxy_ent_t *e2)
{
  return e1->xip == e2->xip && e1->xport == e2->xport &&
         e1->protocol == e2->protocol;
}

/* The selector's view of health (sockproxy_health.c): a member is up when
 * the pool says so, and the circuit breaker is closed in this test. */
int is_endpoint_healthy(proxy_epval_t *tepval, int ep_idx)
{
  return tepval && ep_idx >= 0 && ep_idx < tepval->n_eps && tepval->eps[ep_idx].inv == 0;
}
int circuit_breaker_candidate(proxy_epval_t *tepval, int ep_idx)
{
  (void)tepval; (void)ep_idx;
  return 1;
}

#define SP_MCP_PROXY_SELECTOR
#include "sockproxy_mcp_rr.h"

/* ---- a listener with one pool of three members -------------------------- */

static proxy_struct_t ps;
static proxy_map_ent_t ent;
static proxy_epval_t *pool;

static void
listener_init(void)
{
  memset(&ps, 0, sizeof(ps));
  memset(&ent, 0, sizeof(ent));
  pthread_rwlock_init(&ps.lock, NULL);
  ent.key.xip = 0x0a000001; ent.key.xport = 100; ent.key.protocol = 6;
  ps.head = &ent;
  proxy_struct = &ps;
  pool = sp_pool_alloc();
  snprintf(pool->ephash_key, sizeof(pool->ephash_key), "r.example");
  pool->n_eps = 3;
  pool->select = PROXY_SEL_RR;
  if (sp_pool_link(&ent, pool) != 0)
    abort();
}

/* The listener's pool goes the product's way: out of the table, freed after
 * the grace period (no reader is registered, so it is over at once). */
static void
listener_fini(void)
{
  proxy_detach_l7_policy(&ent.key);
  if (sp_pool_unlink(&ent, pool) != 0)
    abort();
  for (int i = 0; i < 16 && sp_qsbr_pending(); i++)
    sp_qsbr_run_ready();
}

/* A route matching the path prefix, forwarding to members refs[] (weights w[]). */
static void
route_fwd(l7_route_t *r, int position, const char *prefix, int n, const int *refs, const int *w)
{
  memset(r, 0, sizeof(*r));
  r->position = position;
  r->n_sets = 1;
  r->sets[0].n_conds = 1;
  r->sets[0].conds[0].field = L7F_PATH;
  r->sets[0].conds[0].op = L7OP_PREFIX;
  snprintf(r->sets[0].conds[0].value, sizeof(r->sets[0].conds[0].value), "%s", prefix);
  r->action.kind = L7A_FORWARD;
  r->action.u.fwd.n_refs = (uint8_t)n;
  for (int i = 0; i < n; i++) {
    r->action.u.fwd.refs[i].ep = (uint32_t)refs[i];
    r->action.u.fwd.refs[i].weight = (uint8_t)(w ? w[i] : 0);
  }
}

static int
dispatch(proxy_fd_ent_t *pfe, const char *path, proxy_epval_t **out)
{
  memset(pfe, 0, sizeof(*pfe));
  snprintf(pfe->request_path, sizeof(pfe->request_path), "%s", path);
  *out = (proxy_epval_t *)0x1;
  return l7_route_dispatch(pfe, &ent, out);
}

static void
test_route_marks_the_pool(void)
{
  static const int sub[] = { 1, 2 }, none[] = { 7 };
  l7_route_t r[3];
  proxy_fd_ent_t pfe;
  proxy_epval_t *out;
  uint64_t live0, live1;

  listener_init();
  route_fwd(&r[0], 1, "/sub", 2, sub, NULL);
  route_fwd(&r[1], 2, "/none", 1, none, NULL);
  route_fwd(&r[2], 3, "/", 0, NULL, NULL);
  CHECK(proxy_attach_l7_policy(&ent.key, r, 3) == 0, "a three-route policy attaches");
  sp_pool_counts(&live0, NULL);

  CHECK(dispatch(&pfe, "/sub/x", &out) == L7_DISPATCH_FORWARD && out == pool,
        "a FORWARD naming members gets the listener's own pool");
  CHECK(pfe.mcp_route_active == 1 && pfe.mcp_route_mask == 0x6,
        "with those members, and only those, marked on the request (mask %#x)",
        pfe.mcp_route_mask);
  CHECK(pfe.mcp_selector_state == &ent.mcp_l7_selector[0],
        "and the route's own cursor on the listener");

  CHECK(dispatch(&pfe, "/other", &out) == L7_DISPATCH_FORWARD && out == pool &&
        pfe.mcp_route_active == 0,
        "a FORWARD naming no member gets the pool as it selects");
  CHECK(dispatch(&pfe, "/none", &out) == L7_DISPATCH_FORWARD && out == NULL,
        "a FORWARD naming only members the pool lacks gets no pool");

  sp_pool_counts(&live1, NULL);
  CHECK(live1 == live0 && sp_pool_refs(pool) == 1,
        "no pool was made for a route, and none holds the listener's");
  CHECK(proxy_detach_l7_policy(&ent.key) == 0 && sp_pool_refs(pool) == 1,
        "detaching the policy leaves nothing to free");
  listener_fini();
}

static int
select_over(proxy_fd_ent_t *pfe, const char *path, int n, int count[3])
{
  proxy_epval_t *out;
  int bad = 0;

  memset(count, 0, 3 * sizeof(int));
  for (int i = 0; i < n; i++) {
    if (dispatch(pfe, path, &out) != L7_DISPATCH_FORWARD || out != pool)
      return -1;
    int ep = sp_mcp_request_select(pool, pfe);
    if (ep < 0 || ep > 2)
      bad++;
    else
      count[ep]++;
  }
  return bad;
}

static void
test_selection_follows_the_pool(void)
{
  static const int sub[] = { 1, 2 }, w[] = { 3, 1 };
  l7_route_t r[2];
  proxy_fd_ent_t pfe;
  int c[3];

  listener_init();
  route_fwd(&r[0], 1, "/rr", 2, sub, NULL);
  route_fwd(&r[1], 2, "/w", 2, sub, w);
  CHECK(proxy_attach_l7_policy(&ent.key, r, 2) == 0, "a two-route policy attaches");

  CHECK(select_over(&pfe, "/rr", 100, c) == 0 && c[0] == 0 && c[1] == 50 && c[2] == 50,
        "round-robin over the route's members only (%d/%d/%d)", c[0], c[1], c[2]);
  pool->eps[2].inv = 1;     /* the health check marks a member down */
  CHECK(select_over(&pfe, "/rr", 100, c) == 0 && c[0] == 0 && c[1] == 100 && c[2] == 0,
        "a member marked down after the attach is not selected (%d/%d/%d)", c[0], c[1], c[2]);
  pool->eps[1].inv = 1;
  {
    proxy_epval_t *out;
    dispatch(&pfe, "/rr", &out);
    CHECK(sp_mcp_request_select(pool, &pfe) < 0,
          "no member of the route up: nothing is selected, not a member outside it");
  }
  pool->eps[1].inv = pool->eps[2].inv = 0;

  CHECK(select_over(&pfe, "/w", 400, c) == 0 && c[0] == 0 && c[1] == 300 && c[2] == 100,
        "the route's weights 3:1 (%d/%d/%d)", c[0], c[1], c[2]);
  listener_fini();
}

/* ---- a policy replaced under the dispatch -------------------------------- */

static _Atomic int stop;

static void
emit_none(void *ctx, int op, const char *name, const char *value)
{
  (void)ctx; (void)op; (void)name; (void)value;
}

static void *
dispatcher(void *arg)
{
  proxy_fd_ent_t pfe;
  proxy_epval_t *out;
  long *n = arg, cookies = 0;

  while (!atomic_load(&stop)) {
    int rc = dispatch(&pfe, "/sub/x", &out);
    /* The policy may change between the two reads: the marker is read for
     * the sanitizers, its value is either. */
    cookies += l7_cookie_persist_active(&pfe, &ent);
    {
      l7_hop_list_t hops;
      char origin[L7_HOP_TEXT_MAX];
      uint8_t skipped = 0;
      l7_origin_scope_t scope = { &hops, origin, sizeof(origin), &skipped };

      memset(&hops, 0, sizeof(hops));
      l7_hop_list_from_xff("10.9.9.9, 10.1.2.3", &hops);
      l7_apply_req_filters(&pfe, &ent, &scope, "10.1.2.3", 80, "http", emit_none, NULL);
    }
    if (rc == L7_DISPATCH_FORWARD && out == pool && pfe.mcp_route_mask == 0x6)
      n[0]++;
    else if (rc == L7_DISPATCH_FALLTHROUGH)
      n[1]++;
    else
      n[2]++;
  }
  n[3] = cookies;
  return NULL;
}

static void
test_replace_under_dispatch(void)
{
  static const int sub[] = { 1, 2 };
  l7_route_t r[8];
  pthread_t t[2];
  long n[2][4] = { { 0 } };

  listener_init();
  for (int i = 0; i < 8; i++)
    route_fwd(&r[i], i, i == 7 ? "/sub" : "/never", 2, sub, NULL);
  r[7].cookie_persist = 1;
  for (int i = 0; i < 2; i++)
    pthread_create(&t[i], NULL, dispatcher, n[i]);
  for (int k = 0; k < 4000; k++) {
    l7_trusted_range_t tr[2] = { { 0x0a010000u, 16 }, { 0x0a090000u, 16 } };

    proxy_attach_l7_policy(&ent.key, r, 8);
    proxy_attach_l7_trusted_ranges(&ent.key, tr, 1 + (k & 1));
    if (k % 3 == 0)
      proxy_detach_l7_policy(&ent.key);
  }
  atomic_store(&stop, 1);
  for (int i = 0; i < 2; i++)
    pthread_join(t[i], NULL);
  CHECK(n[0][2] + n[1][2] == 0 && n[0][0] + n[1][0] > 0,
        "4000 replaces (trusted ranges rewritten with each) and 1334 detaches under two "
        "dispatching threads: every "
        "decision is the policy's or no policy's (%ld forwards, %ld no policy)",
        n[0][0] + n[1][0], n[0][1] + n[1][1]);
  CHECK(n[0][3] + n[1][3] > 0, "and the route's cookie marker was read %ld times with it on",
        n[0][3] + n[1][3]);
  listener_fini();
}

/* A route whose one condition is on the HOST, forwarding to members refs[]. */
static void
route_host(l7_route_t *r, int position, l7_op_t op, const char *value,
           int n, const int *refs)
{
  route_fwd(r, position, "/", n, refs, NULL);
  r->sets[0].conds[0].field = L7F_HOST;
  r->sets[0].conds[0].op = op;
  snprintf(r->sets[0].conds[0].value, sizeof(r->sets[0].conds[0].value), "%s", value);
}

static int
dispatch_host(proxy_fd_ent_t *pfe, const char *host, proxy_epval_t **out)
{
  memset(pfe, 0, sizeof(*pfe));
  snprintf(pfe->request_path, sizeof(pfe->request_path), "/");
  snprintf(pfe->host_url, sizeof(pfe->host_url), "%s", host);
  *out = (proxy_epval_t *)0x1;
  return l7_route_dispatch(pfe, &ent, out);
}

/* HOST conditions compare without regard to case, as host routing does: the
 * value of EQUAL/PREFIX/SUFFIX/CONTAINS and the request host are both folded,
 * and a HOST REGEX matches either case while its pattern keeps its own. */
static void
test_host_conditions_ignore_case(void)
{
  static const int m0[] = { 0 }, m1[] = { 1 }, m01[] = { 0, 1 }, m2[] = { 2 };
  l7_route_t r[4];
  proxy_fd_ent_t pfe;
  proxy_epval_t *out;

  listener_init();
  route_host(&r[0], 1, L7OP_EQUAL, "API.Example.com", 1, m0);
  route_host(&r[1], 2, L7OP_REGEX, "^[A-Z]+\\.Re\\.Example$", 1, m1);
  route_host(&r[2], 3, L7OP_SUFFIX, ".Suffix.Example", 2, m01);
  route_fwd(&r[3], 4, "/", 1, m2, NULL);
  CHECK(proxy_attach_l7_policy(&ent.key, r, 4) == 0, "a four-route HOST policy attaches");

  CHECK(dispatch_host(&pfe, "api.example.com", &out) == L7_DISPATCH_FORWARD &&
        pfe.mcp_route_mask == 0x1, "EQUAL matches a lower-case host");
  CHECK(dispatch_host(&pfe, "API.EXAMPLE.COM", &out) == L7_DISPATCH_FORWARD &&
        pfe.mcp_route_mask == 0x1, "EQUAL matches an upper-case host");
  CHECK(dispatch_host(&pfe, "SVC.re.Example", &out) == L7_DISPATCH_FORWARD &&
        pfe.mcp_route_mask == 0x2, "a HOST REGEX written in upper case matches any case");
  CHECK(dispatch_host(&pfe, "x.SUFFIX.example", &out) == L7_DISPATCH_FORWARD &&
        pfe.mcp_route_mask == 0x3, "SUFFIX compares without case");
  CHECK(dispatch_host(&pfe, "api.example.org", &out) == L7_DISPATCH_FORWARD &&
        pfe.mcp_route_mask == 0x4, "another host falls to the catch-all route");

  CHECK(proxy_detach_l7_policy(&ent.key) == 0, "the HOST policy detaches");
  listener_fini();
}

int
main(void)
{
  setvbuf(stdout, NULL, _IONBF, 0);
  sp_pool_init(NULL);
  test_route_marks_the_pool();
  test_host_conditions_ignore_case();
  test_selection_follows_the_pool();
  test_replace_under_dispatch();
  {
    uint64_t live;
    sp_pool_counts(&live, NULL);
    CHECK(live == 0, "every pool of the test is freed");
  }
  printf("%d checks, %d failures\n", checks, failures);
  return failures ? 1 : 0;
}
