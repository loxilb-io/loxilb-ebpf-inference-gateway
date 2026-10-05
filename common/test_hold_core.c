/*
 * Copyright (c) 2026 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 *
 * test_hold_core.c - the pure half of holding a half-closed client
 * (sockproxy_hold_core.h): the gate, when a hold settles, when the answer's
 * leg counts as ended, how its end is classified at release, the idle bound
 * and the events a held client may be armed and dispatched for.
 *
 * Build (wired into `make test_hold`):
 *   gcc -Wall -Wextra -Werror -o test_hold_core test_hold_core.c -I.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "sockproxy_hold_core.h"

#define SEC 1000000000ull

/* A client that should be held: everything the gate asks for is there. */
static struct sp_hold_in
holdable(void)
{
  struct sp_hold_in in;

  memset(&in, 0, sizeof(in));
  in.is_client = 1;
  in.owed = 1;
  in.has_leg = 1;
  in.mode_hold = 1;
  in.allowed = 1;
  return in;
}

static void
test_decide(void)
{
  struct sp_hold_in in = holdable();

  assert(sp_hold_decide(&in) == SP_HOLD_YES);

  /* Each condition on its own keeps today's behaviour. */
  in = holdable(); in.is_client = 0;    assert(sp_hold_decide(&in) == SP_HOLD_NO);
  in = holdable(); in.owed = 0;         assert(sp_hold_decide(&in) == SP_HOLD_NO);
  in = holdable(); in.has_leg = 0;      assert(sp_hold_decide(&in) == SP_HOLD_NO);
  in = holdable(); in.accel = 1;        assert(sp_hold_decide(&in) == SP_HOLD_NO);
  in = holdable(); in.is_tls = 1;       assert(sp_hold_decide(&in) == SP_HOLD_NO);
  in = holdable(); in.mode_hold = 0;    assert(sp_hold_decide(&in) == SP_HOLD_NO);
  in = holdable(); in.allowed = 0;      assert(sp_hold_decide(&in) == SP_HOLD_NO);
  in = holdable(); in.leg_peer_eof = 1; assert(sp_hold_decide(&in) == SP_HOLD_NO);

  /* A pipelined request still arriving is refused, and only where a hold
   * would otherwise be taken: it is counted as a hold not taken. */
  in = holdable(); in.pending = 1;
  assert(sp_hold_decide(&in) == SP_HOLD_REFUSE_RESIDUE);
  in.mode_hold = 0;
  assert(sp_hold_decide(&in) == SP_HOLD_NO);

  /* Already held wins over everything else: the EOF came round again, and
   * the caller must keep the connection whatever the rest now says. */
  in = holdable(); in.held = 1;
  assert(sp_hold_decide(&in) == SP_HOLD_REENTRY);
  in.owed = 0; in.allowed = 0; in.pending = 1;
  assert(sp_hold_decide(&in) == SP_HOLD_REENTRY);

  /* But never for a backend. */
  in.is_client = 0;
  assert(sp_hold_decide(&in) == SP_HOLD_NO);
  printf("  gate: ok\n");
}

static void
test_mode_in_force(void)
{
  /* A rule that leaves its mode unset gets the process default. */
  assert(sp_hold_mode_in_force(SP_HOLD_MODE_UNSET, SP_HOLD_MODE_OFF) == SP_HOLD_MODE_OFF);
  assert(sp_hold_mode_in_force(SP_HOLD_MODE_UNSET, SP_HOLD_MODE_HOLD) == SP_HOLD_MODE_HOLD);

  /* Its own value wins either way: the default never turns an explicit off
   * into a hold, nor a hold off. */
  assert(sp_hold_mode_in_force(SP_HOLD_MODE_OFF, SP_HOLD_MODE_HOLD) == SP_HOLD_MODE_OFF);
  assert(sp_hold_mode_in_force(SP_HOLD_MODE_HOLD, SP_HOLD_MODE_OFF) == SP_HOLD_MODE_HOLD);
  assert(sp_hold_mode_in_force(SP_HOLD_MODE_HOLD, SP_HOLD_MODE_HOLD) == SP_HOLD_MODE_HOLD);

  /* A default that is not hold is off, unset included. */
  assert(sp_hold_mode_in_force(SP_HOLD_MODE_UNSET, SP_HOLD_MODE_UNSET) == SP_HOLD_MODE_OFF);
  assert(sp_hold_mode_in_force(SP_HOLD_MODE_UNSET, SP_HOLD_MODE_MAX) == SP_HOLD_MODE_OFF);

  /* A rule byte the control plane never sends holds nothing, whatever the
   * default. */
  assert(sp_hold_mode_in_force(SP_HOLD_MODE_MAX, SP_HOLD_MODE_HOLD) == SP_HOLD_MODE_OFF);
  assert(sp_hold_mode_in_force(0xff, SP_HOLD_MODE_HOLD) == SP_HOLD_MODE_OFF);
  printf("  mode in force: ok\n");
}

static void
test_settle(void)
{
  /* Nothing closes while the cache still holds bytes ahead of the end. */
  assert(sp_hold_settle_decide(0, 0, 0) == SP_HOLD_END_NONE);
  assert(sp_hold_settle_decide(0, 0, 1) == SP_HOLD_END_NONE);
  assert(sp_hold_settle_decide(0, 1, 1) == SP_HOLD_END_NONE);

  /* Cache empty: answered once nothing is owed, whether or not the leg has
   * gone; the leg having gone with the answer still owed is a backend-first. */
  assert(sp_hold_settle_decide(1, 0, 0) == SP_HOLD_END_ANSWERED);
  assert(sp_hold_settle_decide(1, 0, 1) == SP_HOLD_END_ANSWERED);
  assert(sp_hold_settle_decide(1, 1, 1) == SP_HOLD_END_BACKEND_FIRST);

  /* Still owed, the leg still there: keep waiting. */
  assert(sp_hold_settle_decide(1, 1, 0) == SP_HOLD_END_NONE);
  printf("  settle: ok\n");
}

static void
test_leg_ended(void)
{
  /* No mark: no leg has ended. */
  assert(!sp_hold_leg_ended_now(0, 0));
  assert(!sp_hold_leg_ended_now(0, 3));

  /* A leg ended after three requests were framed: it speaks for those. */
  assert(sp_hold_leg_ended_now(3 + 1, 3));

  /* The next request went to another leg, which has not ended: the mark is
   * stale without anything clearing it. */
  assert(!sp_hold_leg_ended_now(3 + 1, 4));
  assert(!sp_hold_leg_ended_now(3 + 1, 5));
  printf("  leg ended: ok\n");
}

static void
test_end_at_release(void)
{
  enum sp_hold_end e;

  /* A recorded reason stands, whatever the counters say by then. */
  for (e = SP_HOLD_END_ANSWERED; e < SP_HOLD_END_MAX; e = (enum sp_hold_end)(e + 1)) {
    assert(sp_hold_end_at_release(e, 1, 0) == e);
    assert(sp_hold_end_at_release(e, 0, 1) == e);
  }

  /* None recorded: the counters classify it, as a settle would have. */
  assert(sp_hold_end_at_release(SP_HOLD_END_NONE, 0, 0) == SP_HOLD_END_ANSWERED);
  assert(sp_hold_end_at_release(SP_HOLD_END_NONE, 0, 1) == SP_HOLD_END_ANSWERED);
  assert(sp_hold_end_at_release(SP_HOLD_END_NONE, 1, 1) == SP_HOLD_END_BACKEND_FIRST);
  assert(sp_hold_end_at_release(SP_HOLD_END_NONE, 1, 0) == SP_HOLD_END_OTHER);

  /* Never NONE: every hold is counted under some reason. */
  assert(sp_hold_end_at_release(SP_HOLD_END_NONE, 1, 0) != SP_HOLD_END_NONE);

  /* The metrics export carries one cell per reason, NONE included. */
  assert(SP_HOLD_END_MAX == 7);
  printf("  end at release: ok\n");
}

static void
test_expired(void)
{
  const uint64_t cap = 240 * SEC;
  const uint64_t t0 = 1000 * SEC;

  /* Before the request is known to have reached the backend, the clock
   * starts at the hold. */
  assert(!sp_hold_expired(t0 + cap - 1, t0, 0, 0, cap));
  assert(sp_hold_expired(t0 + cap, t0, 0, 0, cap));

  /* Once it has, the clock starts there instead. */
  assert(!sp_hold_expired(t0 + cap, t0, t0 + 10 * SEC, 0, cap));
  assert(sp_hold_expired(t0 + 10 * SEC + cap, t0, t0 + 10 * SEC, 0, cap));

  /* A write to the client restarts it: an idle bound, not a total one. */
  assert(!sp_hold_expired(t0 + 3 * cap, t0, t0 + 10 * SEC, t0 + 3 * cap - SEC, cap));
  assert(sp_hold_expired(t0 + 4 * cap, t0, t0 + 10 * SEC, t0 + 3 * cap - SEC, cap));

  /* Progress older than the handoff does not move the clock back. */
  assert(sp_hold_expired(t0 + 10 * SEC + cap, t0, t0 + 10 * SEC, t0 + SEC, cap));

  /* A clock reading behind the base is never expired. */
  assert(!sp_hold_expired(t0 - SEC, t0, 0, 0, cap));
  assert(!sp_hold_expired(t0, t0, t0 + SEC, 0, cap));

  /* A hold not yet seen to begin is never expired, however late the clock:
   * its age would otherwise be counted from 0. */
  assert(!sp_hold_expired(t0 + 4 * cap, 0, 0, 0, cap));
  assert(!sp_hold_expired(t0 + 4 * cap, 0, t0, 0, cap));
  assert(!sp_hold_expired(t0 + 4 * cap, 0, 0, t0, cap));

  /* The bound's limits. */
  assert(sp_hold_expired(t0 + SP_HOLD_CAP_MIN_SEC * SEC, t0, 0, 0,
                         SP_HOLD_CAP_MIN_SEC * SEC));
  assert(!sp_hold_expired(t0 + SP_HOLD_CAP_MAX_SEC * SEC - 1, t0, 0, 0,
                          SP_HOLD_CAP_MAX_SEC * SEC));
  assert(SP_HOLD_CAP_MIN_SEC <= SP_HOLD_CAP_DEFAULT_SEC &&
         SP_HOLD_CAP_DEFAULT_SEC <= SP_HOLD_CAP_MAX_SEC);
  printf("  idle bound: ok\n");
}

static void
test_arm_type(void)
{
  const uint32_t all = NOTI_TYPE_IN | NOTI_TYPE_HUP | NOTI_TYPE_OUT;

  /* Not held: armed exactly as asked. */
  assert(sp_hold_arm_type(all, 0) == all);
  assert(sp_hold_arm_type(NOTI_TYPE_IN | NOTI_TYPE_HUP, 0) == (NOTI_TYPE_IN | NOTI_TYPE_HUP));
  assert(sp_hold_arm_type(0, 0) == 0);

  /* Held: the read events go, OUT stays; with nothing left it is a disarm. */
  assert(sp_hold_arm_type(all, 1) == NOTI_TYPE_OUT);
  assert(sp_hold_arm_type(NOTI_TYPE_OUT, 1) == NOTI_TYPE_OUT);
  assert(sp_hold_arm_type(NOTI_TYPE_IN | NOTI_TYPE_HUP, 1) == 0);
  assert(sp_hold_arm_type(NOTI_TYPE_IN, 1) == 0);
  assert(sp_hold_arm_type(NOTI_TYPE_HUP, 1) == 0);
  printf("  arming: ok\n");
}

static void
test_dispatch_type(void)
{
  const uint32_t out_as_in = NOTI_TYPE_OUT | NOTI_TYPE_IN; /* how the core reports OUT */

  /* Not held: dispatched as reported. */
  assert(sp_hold_dispatch_type(out_as_in, 0) == out_as_in);
  assert(sp_hold_dispatch_type(NOTI_TYPE_RDHUP, 0) == NOTI_TYPE_RDHUP);

  /* Held: a wake-up to write is a write, never a read. */
  assert(sp_hold_dispatch_type(out_as_in, 1) == NOTI_TYPE_OUT);
  assert(sp_hold_dispatch_type(NOTI_TYPE_IN | NOTI_TYPE_RDHUP, 1) == 0);

  /* A reset or a full close still reaches it. */
  assert(sp_hold_dispatch_type(NOTI_TYPE_IN | NOTI_TYPE_HUP, 1) == NOTI_TYPE_HUP);
  assert(sp_hold_dispatch_type(NOTI_TYPE_IN | NOTI_TYPE_ERROR, 1) == NOTI_TYPE_ERROR);
  printf("  dispatch: ok\n");
}

int
main(void)
{
  printf("test_hold_core:\n");
  test_decide();
  test_mode_in_force();
  test_settle();
  test_leg_ended();
  test_end_at_release();
  test_expired();
  test_arm_type();
  test_dispatch_type();
  printf("test_hold_core: all passed\n");
  return 0;
}
