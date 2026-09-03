/* test_pd_ns_overlay.c - Unit tests for the session-header / IP-persist
 * stickiness overlay resolution (sockproxy_ns_overlay.h) and its G-1 P/D
 * gate: on a P/D-disaggregated rule the converged learned-binding overlay
 * must NOT repoint the ladder's prefill selection (which carries the paired
 * active_conns accounting and the phase machine's pd_prefill_ep_idx), while
 * on a converged rule the overlay must keep working unchanged.
 *
 * G-1 (UNIFIED-ENGINE-ROUTING-ANALYSIS): the pd_fallback_normal overlay had
 * no P/D gate, so a stale learned binding could override a P/D prefill
 * choice and desync the connect target from the load accounting. The live
 * probe missed it because a single-prefill pair makes the learned value
 * equal the sole choice; the repro below uses two prefill endpoints so the
 * stale binding names a DIFFERENT endpoint than this request's ladder pick.
 *
 * Build: gcc -Wall -Wextra -ffunction-sections -fdata-sections \
 *   -Wl,--gc-sections -o test_pd_ns_overlay test_pd_ns_overlay.c -I.
 */

#define _GNU_SOURCE
#include <stdio.h>

#include "sockproxy_ns_overlay.h"

static int failures = 0;

#define CHECK(cond, name) do {                          \
    if (cond) {                                         \
      printf("PASS: %s\n", name);                       \
    } else {                                            \
      printf("FAIL: %s\n", name);                       \
      failures++;                                       \
    }                                                   \
  } while (0)

int
main(void)
{
  ns_overlay_kind_t k;
  int out;

  /* ---- G-1 repro: P/D rule, stale learned binding names a different EP ----
   * Ladder chose prefill EP1 (algo_in=1); active_conns already incremented on
   * EP1 + its decode; pfe->pd_prefill_ep_idx=1. A learned session-header
   * binding from an earlier request points at EP0 and is healthy. The overlay
   * must NOT override — connecting to EP0 while the accounting tracks EP1 is
   * the desync. This is the assertion that is RED without the P/D gate. */
  {
    ns_overlay_in_t in = {
      .pd_disagg_enabled = 1,
      .session_header_enabled = 1,
      .header_present = 1,
      .learned_ep = 0, .learned_ok = 1,   /* stale binding -> EP0, healthy */
      .hash_ep = -1, .hash_ok = 0,
      .sel_sticky = 0,
      .ip_ep = -1, .ip_ok = 0,
    };
    out = ns_overlay_resolve(1 /* ladder chose EP1 */, &in, &k);
    CHECK(out == 1, "P/D: stale learned binding does NOT override the ladder prefill (EP1)");
    CHECK(k == NS_OVERLAY_PD_SKIP, "P/D: overlay reports PD_SKIP, not a learned hit");
  }

  /* Same P/D rule, learned binding happens to equal the ladder pick (the
   * single-prefill topology that hid the bug live): still a skip, still EP0. */
  {
    ns_overlay_in_t in = {
      .pd_disagg_enabled = 1, .session_header_enabled = 1, .header_present = 1,
      .learned_ep = 0, .learned_ok = 1,
      .hash_ep = -1, .hash_ok = 0, .sel_sticky = 0, .ip_ep = -1, .ip_ok = 0,
    };
    out = ns_overlay_resolve(0, &in, &k);
    CHECK(out == 0 && k == NS_OVERLAY_PD_SKIP,
          "P/D: single-prefill coincidence still resolves via the gate, not the overlay");
  }

  /* P/D rule with NO learned binding yet: still skipped (no hash pin either),
   * ladder selection untouched. */
  {
    ns_overlay_in_t in = {
      .pd_disagg_enabled = 1, .session_header_enabled = 1, .header_present = 1,
      .learned_ep = -1, .learned_ok = 0,
      .hash_ep = 2, .hash_ok = 1, .sel_sticky = 0, .ip_ep = -1, .ip_ok = 0,
    };
    out = ns_overlay_resolve(1, &in, &k);
    CHECK(out == 1 && k == NS_OVERLAY_PD_SKIP,
          "P/D: header hash does not pin either (gate covers PRIORITY 1)");
  }

  /* ---- G1-B regression: converged rule, overlay must still work ---- */

  /* PRIORITY 0: learned binding overrides the algorithmic/RR choice. */
  {
    ns_overlay_in_t in = {
      .pd_disagg_enabled = 0, .session_header_enabled = 1, .header_present = 1,
      .learned_ep = 3, .learned_ok = 1,
      .hash_ep = 1, .hash_ok = 1, .sel_sticky = 0, .ip_ep = -1, .ip_ok = 0,
    };
    out = ns_overlay_resolve(2 /* algo chose EP2 */, &in, &k);
    CHECK(out == 3 && k == NS_OVERLAY_LEARNED,
          "converged: learned binding overrides the algorithmic choice (PRIORITY 0)");
  }

  /* PRIORITY 1: no learned binding, no prior algo pick -> header hash pins. */
  {
    ns_overlay_in_t in = {
      .pd_disagg_enabled = 0, .session_header_enabled = 1, .header_present = 1,
      .learned_ep = -1, .learned_ok = 0,
      .hash_ep = 1, .hash_ok = 1, .sel_sticky = 0, .ip_ep = -1, .ip_ok = 0,
    };
    out = ns_overlay_resolve(-1, &in, &k);
    CHECK(out == 1 && k == NS_OVERLAY_HASH,
          "converged: header hash pins when nothing learned and no prior pick (PRIORITY 1)");
  }

  /* PRIORITY 1 must NOT override an existing algorithmic pick (learned miss,
   * algo already >= 0). */
  {
    ns_overlay_in_t in = {
      .pd_disagg_enabled = 0, .session_header_enabled = 1, .header_present = 1,
      .learned_ep = -1, .learned_ok = 0,
      .hash_ep = 1, .hash_ok = 1, .sel_sticky = 0, .ip_ep = -1, .ip_ok = 0,
    };
    out = ns_overlay_resolve(2, &in, &k);
    CHECK(out == 2 && k == NS_OVERLAY_NONE,
          "converged: header hash does not override an existing pick");
  }

  /* PRIORITY 2: no session header, RR_PERSIST, no prior pick -> IP hash. */
  {
    ns_overlay_in_t in = {
      .pd_disagg_enabled = 0, .session_header_enabled = 0, .header_present = 0,
      .learned_ep = -1, .learned_ok = 0, .hash_ep = -1, .hash_ok = 0,
      .sel_sticky = 1, .ip_ep = 4, .ip_ok = 1,
    };
    out = ns_overlay_resolve(-1, &in, &k);
    CHECK(out == 4 && k == NS_OVERLAY_IP,
          "converged: IP persistence pins when RR_PERSIST and no prior pick (PRIORITY 2)");
  }

  /* PRIORITY 2 must NOT fire on a P/D rule even with RR_PERSIST + no pick. */
  {
    ns_overlay_in_t in = {
      .pd_disagg_enabled = 1, .session_header_enabled = 0, .header_present = 0,
      .learned_ep = -1, .learned_ok = 0, .hash_ep = -1, .hash_ok = 0,
      .sel_sticky = 1, .ip_ep = 4, .ip_ok = 1,
    };
    out = ns_overlay_resolve(-1, &in, &k);
    CHECK(out == -1 && k == NS_OVERLAY_PD_SKIP,
          "P/D: IP persistence is gated off too (PRIORITY 2)");
  }

  /* Nothing configured: passthrough. */
  {
    ns_overlay_in_t in = {0};
    out = ns_overlay_resolve(2, &in, &k);
    CHECK(out == 2 && k == NS_OVERLAY_NONE, "converged: no stickiness configured -> passthrough");
  }

  /* ---- learn-store gate (ns_overlay_should_learn) ---- */
  CHECK(ns_overlay_should_learn(0, 1, 0) == 1,
        "learn: converged + header + not-already-learned -> persist");
  CHECK(ns_overlay_should_learn(0, 1, 1) == 0,
        "learn: a learned binding already won -> do not re-persist");
  CHECK(ns_overlay_should_learn(1, 1, 0) == 0,
        "learn: P/D rule never writes the converged binding map (G-1 gate)");
  CHECK(ns_overlay_should_learn(0, 0, 0) == 0,
        "learn: no session header -> nothing to persist");

  if (failures) {
    printf("test_pd_ns_overlay: %d FAILURE(S)\n", failures);
    return 1;
  }
  printf("test_pd_ns_overlay: ALL PASS\n");
  return 0;
}
