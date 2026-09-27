/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_l7origin.c - what a listener puts on the wire, and what it attributes.
 *
 * The rule itself is pinned by test_l7trust. This unit pins the request path
 * built on it: the header ops actually emitted, the origin recorded on the
 * request, and the entry point an operator's configuration arrives through.
 *
 *   - a listener told nothing about what sits in front of it REPLACES the
 *     inbound chain with the socket peer, which is what every listener did
 *     before trusted ranges existed and must stay byte-for-byte that;
 *   - a listener told which ranges its own upstreams occupy EXTENDS the chain
 *     with the peer instead, so the backend still sees what the upstream
 *     recorded, and attributes the request to the right-most hop that is not
 *     ours;
 *   - the chain is read per REQUEST, so a second request on a keep-alive
 *     connection is not attributed to the first request's origin;
 *   - the port and the scheme are still replaced, so a client cannot spoof
 *     them whatever the listener trusts;
 *   - ranges attach to the listener they name and nowhere else, more of them
 *     than a listener holds is refused, and they are dropped when the policy
 *     they ride is detached;
 *   - attaching ranges and attaching a policy do not disturb each other, in
 *     either order, which is what lets the two halves of this land separately.
 *
 * Build (wired into `make test_l7or`): links the policy translation unit and
 * stubs what it calls out to.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>

#include "uthash.h"
#include "sockproxy_internal.h"
#include "sockproxy_l7policy.h"

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

/* ---- what the translation unit calls out to ---------------------------- */

proxy_struct_t *proxy_struct;
int proxy_lock_trace_state = 0;      /* tracing off: the lock path stays plain */

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

/* ---- capturing the emitted header ops ---------------------------------- */

typedef struct {
  int  op;
  char name[128];
  char value[1024];
} emitted_t;

static emitted_t ops[16];
static int n_ops;

static void
capture(void *ctx, int op, const char *name, const char *value)
{
  (void)ctx;
  if (n_ops >= (int)(sizeof(ops) / sizeof(ops[0])))
    return;
  ops[n_ops].op = op;
  snprintf(ops[n_ops].name, sizeof(ops[n_ops].name), "%s", name ? name : "");
  snprintf(ops[n_ops].value, sizeof(ops[n_ops].value), "%s", value ? value : "");
  n_ops++;
}

/* The op emitted for `name`, or NULL. */
static const emitted_t *
emitted(const char *name)
{
  int i;
  for (i = 0; i < n_ops; i++) {
    if (strcasecmp(ops[i].name, name) == 0)
      return &ops[i];
  }
  return NULL;
}

/* Run the applier over a fresh request carrying `chain`. */
static void
apply_with_chain(proxy_fd_ent_t *pfe, proxy_map_ent_t *ent,
                 const char *chain, const char *peer)
{
  memset(pfe, 0, sizeof(*pfe));
  if (chain)
    l7_store_header(pfe, "X-Forwarded-For", chain);
  n_ops = 0;
  l7_apply_req_filters(pfe, ent, peer, 8080, "https", capture, NULL);
}

static uint8_t
ranges_of(l7_trusted_range_t *out, const char **cidrs, uint8_t n)
{
  uint8_t i;
  for (i = 0; i < n; i++) {
    if (l7_trust_parse_cidr(cidrs[i], &out[i]) != 0)
      return 0;
  }
  return n;
}

/* ---- the wire ---------------------------------------------------------- */

static void
test_edge_listener(void)
{
  proxy_fd_ent_t pfe;
  proxy_map_ent_t ent;
  const emitted_t *e;

  memset(&ent, 0, sizeof(ent));   /* no trusted ranges: a listener at the edge */

  /* A client sends a chain of its own invention. It is not evidence. */
  apply_with_chain(&pfe, &ent, "1.2.3.4, 10.0.0.9", "203.0.113.5");
  e = emitted("X-Forwarded-For");
  CHECK(e && e->op == L7HDR_SET && strcmp(e->value, "203.0.113.5") == 0,
        "told no ranges, the chain is REPLACED by the peer");
  CHECK(strcmp(pfe.l7_origin_ip, "203.0.113.5") == 0 && pfe.l7_trusted_hops == 0,
        "and the peer is what the request is attributed to");

  /* The port and the scheme are the listener's own facts either way. */
  e = emitted("X-Forwarded-Port");
  CHECK(e && e->op == L7HDR_SET && strcmp(e->value, "8080") == 0,
        "the listener port is replaced");
  e = emitted("X-Forwarded-Proto");
  CHECK(e && e->op == L7HDR_SET && strcmp(e->value, "https") == 0,
        "the scheme is replaced");

  /* No chain at all: the same, which is the case that must not change. */
  apply_with_chain(&pfe, &ent, NULL, "203.0.113.5");
  e = emitted("X-Forwarded-For");
  CHECK(e && e->op == L7HDR_SET && strcmp(e->value, "203.0.113.5") == 0,
        "with no chain at all the peer is set, exactly as before");
}

static void
test_trusting_listener(void)
{
  static const char *cidrs[] = { "10.0.0.0/8" };
  proxy_fd_ent_t pfe;
  proxy_map_ent_t ent;
  const emitted_t *e;

  memset(&ent, 0, sizeof(ent));
  ent.l7_n_trusted_ranges = ranges_of(ent.l7_trusted_ranges, cidrs, 1);
  CHECK(ent.l7_n_trusted_ranges == 1, "the listener has its range");

  /* One of our load balancers in front. It recorded the client it saw and did
   * NOT record itself, so the chain holds one hop and none of it is ours: the
   * hop count is 0 even though we are behind a proxy. */
  apply_with_chain(&pfe, &ent, "203.0.113.5", "10.0.0.7");
  e = emitted("X-Forwarded-For");
  CHECK(e && e->op == L7HDR_SET &&
        strcmp(e->value, "203.0.113.5, 10.0.0.7") == 0,
        "told its ranges, the chain is EXTENDED with the peer");
  CHECK(strcmp(pfe.l7_origin_ip, "203.0.113.5") == 0 && pfe.l7_trusted_hops == 0,
        "and the client the upstream recorded is what is attributed");

  /* TWO of ours in front: the inner one appended the outer one, so now the
   * chain really does end in a hop of ours and the walk steps past it. */
  apply_with_chain(&pfe, &ent, "203.0.113.5, 10.0.0.6", "10.0.0.7");
  CHECK(strcmp(pfe.l7_origin_ip, "203.0.113.5") == 0 && pfe.l7_trusted_hops == 1,
        "with two of ours in front, the hop between them is stepped past");

  /* Forgeries the client prepended are carried on - the backend is entitled to
   * see what arrived - but they do not change the attribution. */
  apply_with_chain(&pfe, &ent, "9.9.9.9, 203.0.113.5", "10.0.0.7");
  e = emitted("X-Forwarded-For");
  CHECK(e && strcmp(e->value, "9.9.9.9, 203.0.113.5, 10.0.0.7") == 0,
        "what arrived is carried on");
  CHECK(strcmp(pfe.l7_origin_ip, "203.0.113.5") == 0 && pfe.l7_trusted_hops == 0,
        "and the forgery to its left is not attributed");

  /* A direct connection to this listener: no chain, so the peer. */
  apply_with_chain(&pfe, &ent, NULL, "203.0.113.5");
  e = emitted("X-Forwarded-For");
  CHECK(e && strcmp(e->value, "203.0.113.5") == 0,
        "a direct connection sends just the peer");
  CHECK(strcmp(pfe.l7_origin_ip, "203.0.113.5") == 0 && pfe.l7_trusted_hops == 0,
        "and nothing was stepped past, which is how it is told from a chain");

  /* A chain entirely of ours resolves back to the peer - and the hop count is
   * what distinguishes that from the direct connection just above. */
  apply_with_chain(&pfe, &ent, "10.0.0.6", "10.0.0.7");
  CHECK(strcmp(pfe.l7_origin_ip, "10.0.0.7") == 0 && pfe.l7_trusted_hops == 1,
        "a chain entirely of ours resolves to the peer, with the hops counted");
}

/* The chain belongs to the request, not the connection. The header store the
 * policy engine reads is per-connection and never reset, so reading the chain
 * from it would answer a keep-alive connection's second request with its
 * first request's chain. */
static void
test_per_request(void)
{
  static const char *cidrs[] = { "10.0.0.0/8" };
  proxy_fd_ent_t pfe;
  proxy_map_ent_t ent;
  const emitted_t *e;

  memset(&ent, 0, sizeof(ent));
  ent.l7_n_trusted_ranges = ranges_of(ent.l7_trusted_ranges, cidrs, 1);

  memset(&pfe, 0, sizeof(pfe));
  l7_store_header(&pfe, "X-Forwarded-For", "203.0.113.5");
  n_ops = 0;
  l7_apply_req_filters(&pfe, &ent, "10.0.0.7", 8080, "https", capture, NULL);
  CHECK(strcmp(pfe.l7_origin_ip, "203.0.113.5") == 0,
        "the first request on a connection is attributed to its own chain");

  /* The keep-alive boundary runs exactly this pair. The request is only
   * FORWARDED at that point, so the origin has to survive into its response
   * phase while the live fields are cleared for the next request. */
  l7_origin_snapshot(&pfe);
  l7_origin_reset(&pfe);
  CHECK(pfe.l7_inbound_chain[0] == '\0' && pfe.l7_origin_ip[0] == '\0' &&
        pfe.l7_trusted_hops == 0 && pfe.n_l7_headers > 0,
        "the boundary clears the request's chain and origin, not the connection's store");
  CHECK(strcmp(proxy_origin_ip(&pfe), "203.0.113.5") == 0,
        "and the forwarded request's origin is still readable after it");

  l7_store_header(&pfe, "X-Forwarded-For", "198.51.100.9");
  n_ops = 0;
  l7_apply_req_filters(&pfe, &ent, "10.0.0.7", 8080, "https", capture, NULL);
  CHECK(strcmp(pfe.l7_origin_ip, "198.51.100.9") == 0 && pfe.l7_trusted_hops == 0,
        "the second request is attributed to ITS chain, not the first's");
  e = emitted("X-Forwarded-For");
  CHECK(e && strcmp(e->value, "198.51.100.9, 10.0.0.7") == 0,
        "and what it forwards is its own chain too");

  /* A request that arrives with no chain after one that did must not inherit. */
  l7_origin_reset(&pfe);
  n_ops = 0;
  l7_apply_req_filters(&pfe, &ent, "10.0.0.7", 8080, "https", capture, NULL);
  CHECK(strcmp(pfe.l7_origin_ip, "10.0.0.7") == 0 && pfe.l7_trusted_hops == 0,
        "a request with no chain of its own does not inherit the previous one");
}

/* Several chain header lines are one list in arrival order. */
static void
test_several_chain_lines(void)
{
  static const char *cidrs[] = { "10.0.0.0/8" };
  proxy_fd_ent_t pfe;
  proxy_map_ent_t ent;
  const emitted_t *e;

  memset(&ent, 0, sizeof(ent));
  ent.l7_n_trusted_ranges = ranges_of(ent.l7_trusted_ranges, cidrs, 1);

  memset(&pfe, 0, sizeof(pfe));
  l7_store_header(&pfe, "X-Forwarded-For", "9.9.9.9");
  l7_store_header(&pfe, "x-forwarded-for", "203.0.113.5");   /* case-insensitive */
  n_ops = 0;
  l7_apply_req_filters(&pfe, &ent, "10.0.0.7", 8080, "https", capture, NULL);
  e = emitted("X-Forwarded-For");
  CHECK(e && strcmp(e->value, "9.9.9.9, 203.0.113.5, 10.0.0.7") == 0,
        "several chain lines are one list, in the order they arrived");
  CHECK(strcmp(pfe.l7_origin_ip, "203.0.113.5") == 0,
        "so the right-most of them is what the walk reaches first");
}

/* ---- the entry point configuration arrives through --------------------- */

static proxy_struct_t ps;
static proxy_map_ent_t ent_a, ent_b;

static void
listeners_init(void)
{
  memset(&ps, 0, sizeof(ps));
  memset(&ent_a, 0, sizeof(ent_a));
  memset(&ent_b, 0, sizeof(ent_b));
  pthread_rwlock_init(&ps.lock, NULL);
  ent_a.key.xip = 0x0a000001; ent_a.key.xport = 100; ent_a.key.protocol = 6;
  ent_b.key.xip = 0x0a000002; ent_b.key.xport = 200; ent_b.key.protocol = 6;
  ent_a.next = &ent_b;
  ps.head = &ent_a;
  proxy_struct = &ps;
}

static void
test_attach_ranges(void)
{
  static const char *cidrs[] = { "10.0.0.0/8", "192.168.1.0/24" };
  l7_trusted_range_t r[L7_MAX_TRUSTED_RANGES];
  uint8_t n;

  listeners_init();
  n = ranges_of(r, cidrs, 2);
  CHECK(n == 2, "the range set parses");

  CHECK(proxy_attach_l7_trusted_ranges(&ent_a.key, r, 2) == 0 &&
        ent_a.l7_n_trusted_ranges == 2,
        "ranges attach to the listener they name");
  CHECK(ent_b.l7_n_trusted_ranges == 0,
        "and to no other listener");

  /* The stored ranges are the masked ones, so nothing parses on the request
   * path and one range has one spelling. */
  CHECK(ent_a.l7_trusted_ranges[0].addr == inet_addr("10.0.0.0") &&
        ent_a.l7_trusted_ranges[0].prefix_len == 8,
        "and they are stored parsed and masked");

  /* Replace, rather than accumulate. */
  CHECK(proxy_attach_l7_trusted_ranges(&ent_a.key, r, 1) == 0 &&
        ent_a.l7_n_trusted_ranges == 1,
        "a second attach REPLACES the set rather than adding to it");

  /* Clearing returns the listener to edge behaviour. */
  CHECK(proxy_attach_l7_trusted_ranges(&ent_a.key, NULL, 0) == 0 &&
        ent_a.l7_n_trusted_ranges == 0,
        "attaching none returns the listener to the edge behaviour");

  /* Refusals. */
  {
    proxy_ent_t nosuch = { 0 };
    nosuch.xip = 0x0a0000ff; nosuch.xport = 999; nosuch.protocol = 6;
    CHECK(proxy_attach_l7_trusted_ranges(&nosuch, r, 1) < 0,
          "a listener that does not exist is refused");
  }
  CHECK(proxy_attach_l7_trusted_ranges(&ent_a.key, r,
                                       L7_MAX_TRUSTED_RANGES + 1) < 0 &&
        ent_a.l7_n_trusted_ranges == 0,
        "more ranges than a listener holds is refused, and changes nothing");
  CHECK(proxy_attach_l7_trusted_ranges(&ent_a.key, NULL, 2) < 0,
        "a count with no ranges behind it is refused");
  CHECK(proxy_attach_l7_trusted_ranges(NULL, r, 1) < 0,
        "no listener is refused");
}

/* The ranges ride the policy: detaching it drops them, but attaching a policy
 * does not disturb ranges already recorded. That independence is what lets the
 * fork half and the gateway half land in either order. */
static void
test_ranges_and_policy(void)
{
  static const char *cidrs[] = { "10.0.0.0/8" };
  l7_trusted_range_t r[1];
  l7_route_t route;

  listeners_init();
  ranges_of(r, cidrs, 1);
  memset(&route, 0, sizeof(route));
  route.position = 1;

  CHECK(proxy_attach_l7_trusted_ranges(&ent_a.key, r, 1) == 0 &&
        ent_a.l7_n_trusted_ranges == 1, "ranges attach first");
  CHECK(proxy_attach_l7_policy(&ent_a.key, &route, 1) == 0 &&
        ent_a.has_l7_policy == 1 && ent_a.l7_n_trusted_ranges == 1,
        "a policy attached afterwards leaves the ranges alone");
  CHECK(proxy_attach_l7_policy(&ent_a.key, &route, 1) == 0 &&
        ent_a.l7_n_trusted_ranges == 1,
        "and so does replacing that policy");

  CHECK(proxy_detach_l7_policy(&ent_a.key) == 0 &&
        ent_a.has_l7_policy == 0 && ent_a.l7_n_trusted_ranges == 0,
        "detaching the policy drops the ranges with it");

  /* The other order. */
  listeners_init();
  CHECK(proxy_attach_l7_policy(&ent_a.key, &route, 1) == 0 &&
        proxy_attach_l7_trusted_ranges(&ent_a.key, r, 1) == 0 &&
        ent_a.has_l7_policy == 1 && ent_a.l7_n_trusted_ranges == 1,
        "the other order works too, which is what lets the two halves land apart");
  proxy_detach_l7_policy(&ent_a.key);
}

/* The origin has to be readable on both sides of the reset boundary, because
 * the request is reported in its response phase - after the boundary has run.
 * This is the trap proxy_request_id_snapshot exists for, and the same one. */
static void
test_snapshot_across_the_boundary(void)
{
  static const char *cidrs[] = { "10.0.0.0/8" };
  proxy_fd_ent_t pfe;
  proxy_map_ent_t ent;

  memset(&ent, 0, sizeof(ent));
  ent.l7_n_trusted_ranges = ranges_of(ent.l7_trusted_ranges, cidrs, 1);

  /* Two of ours in front, so the hop count is non-zero and has to survive with
   * the address - they are only meaningful as a pair. */
  apply_with_chain(&pfe, &ent, "203.0.113.5, 10.0.0.6", "10.0.0.7");
  CHECK(strcmp(proxy_origin_ip(&pfe), "203.0.113.5") == 0 &&
        proxy_origin_trusted_hops(&pfe) == 1,
        "before the boundary the live answer is read");

  l7_origin_snapshot(&pfe);
  l7_origin_reset(&pfe);
  CHECK(strcmp(proxy_origin_ip(&pfe), "203.0.113.5") == 0 &&
        proxy_origin_trusted_hops(&pfe) == 1,
        "after it the same answer is read, address and hop count together");

  /* The next request on the connection takes over the live fields, and the
   * reader must then answer with ITS origin, not the snapshot behind it. */
  l7_store_header(&pfe, "X-Forwarded-For", "198.51.100.9");
  n_ops = 0;
  l7_apply_req_filters(&pfe, &ent, "10.0.0.7", 8080, "https", capture, NULL);
  CHECK(strcmp(proxy_origin_ip(&pfe), "198.51.100.9") == 0 &&
        proxy_origin_trusted_hops(&pfe) == 0,
        "once the next request derives its own, that is what is read");

  /* Nothing derived at all reads as empty, which is NOT the same as the peer:
   * a request whose headers were never spliced decided nothing. */
  memset(&pfe, 0, sizeof(pfe));
  CHECK(proxy_origin_ip(&pfe)[0] == '\0',
        "a request that derived nothing reads empty, not as the peer");
}

int
main(void)
{
  test_edge_listener();
  test_trusting_listener();
  test_per_request();
  test_several_chain_lines();
  test_snapshot_across_the_boundary();
  test_attach_ranges();
  test_ranges_and_policy();
  printf("=== results: %d/%d passed ===\n", checks - failures, checks);
  return failures ? 1 : 0;
}
