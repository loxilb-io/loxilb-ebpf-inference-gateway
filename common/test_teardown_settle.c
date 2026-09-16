/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_teardown_settle.c - a rule delete must not strand a tenant's claim.
 *
 * proxy_pdestroy() guarded all three of its settle blocks with
 * `!is_listener` while the listener branch freed every connection on the rule
 * outright, so a teardown that took the rule's main fd handed back nothing:
 * the HTTP/1.1 reservation, the missing-usage report and every in-flight
 * HTTP/2 stream's claim were dropped on the floor. The endpoint pools do go
 * away with the rule - but the token bucket is per-tenant and outlives it, so
 * the claim is not released, it is STRANDED, until the quota epoch rolls.
 *
 * A focused unit is the only shape available here: the branch cannot be
 * induced from a black-box topology. A rule delete deliberately keeps
 * the listener open (sockproxy_conn.c, "Production fix: ... keep the TCP
 * listener socket open", and proxy_delete_entry__ never returns main_fd), so
 * the listener branch is reached only by an error/HUP on the listening socket
 * itself or by shutdown. Neither is drivable from the harness.
 *
 * THE ORACLE IS SELF-VERIFYING. Each case is scored twice: once against the
 * shipped rule, and once against `prefix_owes_settle` below - the pre-fix rule
 * kept verbatim. A case only counts if it PASSES the shipped rule and FAILS
 * the pre-fix one. A test that cannot go red proves nothing, so the red twin
 * is not a separate build here; it is an assertion.
 *
 * Build (wired into `make test_teardown`):
 *   gcc -Wall -Wextra -Werror -o test_teardown_settle test_teardown_settle.c -I.
 */

#include <stdio.h>
#include <string.h>

#include "sockproxy_teardown_settle.h"

static int failures = 0;
static int checks   = 0;

/*
 * The PRE-FIX rule, kept verbatim: every settle block in proxy_pdestroy was
 * guarded by `!is_listener`, so a listener teardown settled nothing at all.
 */
static int
prefix_owes_settle(int shape, const teardown_conn_t *c)
{
  if (shape == TEARDOWN_LISTENER)
    return 0;                      /* <- the defect */
  return teardown_conn_owes_settle(shape, c);
}

/*
 * Score one case against both rules.
 *
 * `want` is what the shipped rule must answer. `twin_sees` says whether this
 * case is one the pre-fix rule got WRONG - i.e. whether it is load-bearing.
 * Cases marked load-bearing must actually disagree with the pre-fix rule, or
 * the case is vacuous and is reported as a failure in its own right.
 */
static void
check(const char *name, int shape, const teardown_conn_t *c, int want,
      int twin_sees)
{
  int got  = teardown_conn_owes_settle(shape, c);
  int twin = prefix_owes_settle(shape, c);

  checks++;
  if (got != want) {
    printf("  [FAIL] %s: shipped rule got %d want %d\n", name, got, want);
    failures++;
    return;
  }
  if (twin_sees && twin == want) {
    printf("  [FAIL] %s: VACUOUS - the pre-fix rule answers %d too, so this "
           "case cannot detect the defect\n", name, twin);
    failures++;
    return;
  }
  if (!twin_sees && twin != want) {
    printf("  [FAIL] %s: case claims the pre-fix rule agrees, but it answers "
           "%d want %d\n", name, twin, want);
    failures++;
    return;
  }
  printf("  [ok]   %s (shipped=%d pre-fix=%d%s)\n", name, got, twin,
         twin_sees ? ", red-twin sees it" : "");
}

int
main(void)
{
  /* An HTTP/1.1 client that was admitted, holds an unspent claim, and died
   * before burning any of it. */
  teardown_conn_t h1_claim = {
      .odir = 0, .ai_gw_mode = 1, .usage_reserved_toks = 1030,
      .usage_consumed = 0, .has_tenant = 1, .has_h2_session = 0,
      .metric_ai_recorded = 0, .metric_response_status = 0,
  };

  /* An HTTP/2 client connection with streams still in flight. */
  teardown_conn_t h2_inflight = {
      .odir = 0, .ai_gw_mode = 1, .usage_reserved_toks = 0,
      .usage_consumed = 0, .has_tenant = 1, .has_h2_session = 1,
      .metric_ai_recorded = 0, .metric_response_status = 0,
  };

  /* A connection whose last 2xx response carried no readable usage object. */
  teardown_conn_t umiss = {
      .odir = 0, .ai_gw_mode = 1, .usage_reserved_toks = 0,
      .usage_consumed = 0, .has_tenant = 1, .has_h2_session = 0,
      .metric_ai_recorded = 1, .metric_response_status = 200,
  };

  /* Nothing owed: the claim was already settled by the stream's own close. */
  teardown_conn_t settled = {
      .odir = 0, .ai_gw_mode = 1, .usage_reserved_toks = 1030,
      .usage_consumed = 1, .has_tenant = 1, .has_h2_session = 0,
      .metric_ai_recorded = 0, .metric_response_status = 200,
  };

  /* A backend leg holds no admission claim of its own. */
  teardown_conn_t backend = {
      .odir = 1, .ai_gw_mode = 1, .usage_reserved_toks = 0,
      .usage_consumed = 0, .has_tenant = 1, .has_h2_session = 0,
      .metric_ai_recorded = 1, .metric_response_status = 200,
  };

  /* Admitted without a tenant: there is no per-tenant bucket to hand back to. */
  teardown_conn_t no_tenant = {
      .odir = 0, .ai_gw_mode = 1, .usage_reserved_toks = 1030,
      .usage_consumed = 0, .has_tenant = 0, .has_h2_session = 0,
      .metric_ai_recorded = 0, .metric_response_status = 0,
  };

  printf("teardown: the shape decides the walk set, not the settle\n");

  printf("\n TEARDOWN_CONN - the shape that always worked:\n");
  check("h1 unspent claim",        TEARDOWN_CONN, &h1_claim,    1, 0);
  check("h2 streams in flight",    TEARDOWN_CONN, &h2_inflight, 1, 0);
  check("2xx with no usage object",TEARDOWN_CONN, &umiss,       1, 0);
  check("already settled",         TEARDOWN_CONN, &settled,     0, 0);
  check("backend leg",             TEARDOWN_CONN, &backend,     0, 0);
  check("admitted with no tenant", TEARDOWN_CONN, &no_tenant,   0, 0);

  printf("\n TEARDOWN_LISTENER - the same connections, rule going away:\n");
  check("h1 unspent claim",        TEARDOWN_LISTENER, &h1_claim,    1, 1);
  check("h2 streams in flight",    TEARDOWN_LISTENER, &h2_inflight, 1, 1);
  check("2xx with no usage object",TEARDOWN_LISTENER, &umiss,       1, 1);
  /* These three owe nothing in EITHER shape, so the pre-fix rule happens to
   * agree. Kept so the suite says where the rules genuinely coincide rather
   * than only where they differ. */
  check("already settled",         TEARDOWN_LISTENER, &settled,     0, 0);
  check("backend leg",             TEARDOWN_LISTENER, &backend,     0, 0);
  check("admitted with no tenant", TEARDOWN_LISTENER, &no_tenant,   0, 0);

  printf("\n the walk set is the shape's ONLY business:\n");
  checks++;
  if (teardown_walks_peer_conns(TEARDOWN_CONN) != 0) {
    printf("  [FAIL] a connection teardown must walk only itself\n");
    failures++;
  } else {
    printf("  [ok]   a connection teardown walks only itself\n");
  }
  checks++;
  if (teardown_walks_peer_conns(TEARDOWN_LISTENER) != 1) {
    printf("  [FAIL] a listener teardown must walk the rule's connections\n");
    failures++;
  } else {
    printf("  [ok]   a listener teardown walks the rule's connections\n");
  }

  printf("\n%s: %d checks, %d failure(s)\n",
         failures ? "FAILED" : "PASSED", checks, failures);
  return failures ? 1 : 0;
}
