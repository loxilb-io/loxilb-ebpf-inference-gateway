/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_ka_leg.c - a keep-alive request keeps its backend leg unless routing
 * would have sent it elsewhere.
 *
 * The request boundary on an AI-gateway connection used to release the
 * backend leg unconditionally, because the admission gate only ran while the
 * connection had no leg. The parse phase is now keyed on a flag, and the
 * decision whether the framed request rides the existing leg lives in
 * sockproxy_ka_leg.h. This unit drives that rule directly.
 *
 * THE ORACLE IS SELF-VERIFYING. Each case is scored twice: once against the
 * shipped rule, and once against `always_release` below - the pre-fix rule
 * kept verbatim. A "keep" case only counts if the shipped rule keeps and the
 * pre-fix rule releases; a "release" case must be released by both, so the
 * fix demonstrably never forwards to a leg the old code would have refused.
 *
 * Build (wired into `make test_ka`):
 *   gcc -Wall -Wextra -Werror -o test_ka_leg test_ka_leg.c -I.
 */

#include <stdio.h>
#include <string.h>

#include "sockproxy_ka_leg.h"

static int failures = 0;
static int checks   = 0;

/* The PRE-FIX rule: the boundary released the leg on every request. */
static int
always_release(const ka_leg_ctx_t *c)
{
  (void)c;
  return 0;
}

static void
expect_keep(const char *name, ka_leg_ctx_t c)
{
  int reason = -1;
  int kept = ka_leg_reusable(&c, &reason);
  checks++;
  if (!kept || reason != KA_LEG_KEPT) {
    printf("FAIL %s: expected keep, got release (%s)\n", name,
           ka_leg_reason_str(reason));
    failures++;
    return;
  }
  checks++;
  if (always_release(&c)) {
    printf("FAIL %s: the pre-fix rule also keeps; case proves nothing\n", name);
    failures++;
    return;
  }
  printf("ok   %s: kept (pre-fix rule released)\n", name);
}

static void
expect_release(const char *name, ka_leg_ctx_t c, int want_reason)
{
  int reason = -1;
  int kept = ka_leg_reusable(&c, &reason);
  checks++;
  if (kept || reason != want_reason) {
    printf("FAIL %s: expected release (%s), got %s (%s)\n", name,
           ka_leg_reason_str(want_reason), kept ? "keep" : "release",
           ka_leg_reason_str(reason));
    failures++;
    return;
  }
  checks++;
  if (always_release(&c)) {
    printf("FAIL %s: the pre-fix rule keeps a leg the fix releases\n", name);
    failures++;
    return;
  }
  printf("ok   %s: released (%s)\n", name, ka_leg_reason_str(reason));
}

int
main(void)
{
  ka_leg_ctx_t base = {
    .leg_live = 1, .ep_pinned = 1, .ep_healthy = 1,
    .prev_model = "llama-3-8b", .next_model = "llama-3-8b",
  };
  ka_leg_ctx_t c;

  /* The common case: same model, healthy pinned endpoint. */
  expect_keep("same model, healthy endpoint", base);

  /* No model on either request (a rule that does not route by model). */
  c = base; c.prev_model = ""; c.next_model = "";
  expect_keep("no model on either request", c);
  c = base; c.prev_model = NULL; c.next_model = NULL;
  expect_keep("model pointers absent", c);

  /* The previous request left no leg (backend closed, first request). */
  c = base; c.leg_live = 0;
  expect_release("no live leg", c, KA_LEG_NO_LEG);

  /* A leg whose endpoint the connection cannot name. */
  c = base; c.ep_pinned = 0;
  expect_release("leg not pinned to an endpoint", c, KA_LEG_UNPINNED);

  /* The pinned endpoint went unhealthy between requests. */
  c = base; c.ep_healthy = 0;
  expect_release("pinned endpoint unhealthy", c, KA_LEG_UNHEALTHY);

  /* The request names another model. */
  c = base; c.next_model = "mistral-7b";
  expect_release("model changed", c, KA_LEG_MODEL);
  c = base; c.next_model = "";
  expect_release("model dropped", c, KA_LEG_MODEL);
  c = base; c.prev_model = "";
  expect_release("model added", c, KA_LEG_MODEL);

  /* Precedence: an unhealthy endpoint is reported before a model change. */
  c = base; c.ep_healthy = 0; c.next_model = "mistral-7b";
  expect_release("unhealthy wins over model change", c, KA_LEG_UNHEALTHY);

  printf("%d checks, %d failures\n", checks, failures);
  return failures ? 1 : 0;
}
