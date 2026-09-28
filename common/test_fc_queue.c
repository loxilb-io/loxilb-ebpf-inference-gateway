/*
 * Copyright (c) 2026 LoxiLB Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * The bounded service queue of the capacity gate, driven alone: the order
 * requests leave in, the depth, what happens to an entry that is cancelled,
 * expired or drained while another path races for it, what a released unit
 * wakes, and what a woken request that lost its unit does. The clock is a
 * parameter, so a deadline race is played out instruction by instruction.
 *
 * Build: make test_fc_queue (also run by `make test_fc`).
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sockproxy_fc.h"

#define MS(n) ((uint64_t)(n) * 1000000ULL)

static void
reset_anomalies(void)
{
  for (int i = 0; i < FC_A_COUNT; i++)
    atomic_store(&fc_anomaly_total[i], 0);
}

static uint64_t
decisions(const fc_state_t *fc, enum fc_reason r)
{
  return atomic_load(&fc->decisions[r]);
}

static void
pool_with(fc_state_t *fc, uint8_t mode, uint32_t max_out, uint32_t depth,
          uint32_t wait_ms)
{
  fc_cfg_t cfg = {0};

  memset(fc, 0, sizeof(*fc));
  pthread_mutex_init(&fc->queue.lock, NULL);
  cfg.mode = mode;
  cfg.max_outstanding = max_out;
  cfg.max_queue_depth = depth;
  cfg.max_queue_wait_ms = wait_ms;
  fc_state_apply(fc, &cfg);
}

/* The wake hook records what was popped, in order, and can refuse. */
static int woken_fd[256];
static uint64_t woken_gen[256];
static int woken_n;
static int wake_refuse;

static int
record_wake(int fd, uint64_t gen)
{
  if (wake_refuse)
    return -1;
  assert(woken_n < 256);
  woken_fd[woken_n] = fd;
  woken_gen[woken_n] = gen;
  woken_n++;
  return 0;
}

static void
reset_wakes(void)
{
  woken_n = 0;
  wake_refuse = 0;
}

/* Take a service unit the way the HTTP/1 site does: admit, or park. */
static fc_verdict_t
h1_gate(fc_state_t *fc, fc_permit_t *p, int fd, uint64_t gen, uint64_t now,
        int woken)
{
  fc_verdict_t v = fc_service_acquire_h1(fc, p, woken);

  if (v == FC_ADMIT) {
    if (p->state == FC_P_EXECUTING)
      assert(fc_ep_acquire(fc, p, 0, FC_ROLE_NORMAL) == FC_ADMIT);
    return v;
  }
  if (v == FC_QUEUE) {
    if (fc_queue_push(fc, p, fd, gen, now, woken) == 0)
      return FC_QUEUE;
    /* The push counted queue_full: that is the decision, not a shed. */
    return FC_SHED;
  }
  if (v == FC_SHED)
    fc_count(fc, FC_R_CAPACITY_SHED);
  return v;
}

/* ---- order and depth --------------------------------------------------------- */

static void
test_fifo_order_and_depth(void)
{
  fc_state_t fc;
  fc_permit_t exec[2], wait[4], extra;
  uint64_t now = MS(1000);

  pool_with(&fc, FC_MODE_ENFORCE, 2, 3, 5000);
  reset_anomalies();
  reset_wakes();
  assert(fc_queue_enabled(&fc));
  assert(fc.queue.cap == 3);

  /* Two execute, three wait, the fourth is refused: the queue is at depth. */
  for (int i = 0; i < 2; i++)
    assert(h1_gate(&fc, &exec[i], 10 + i, 1, now, 0) == FC_ADMIT);
  for (int i = 0; i < 3; i++)
    assert(h1_gate(&fc, &wait[i], 20 + i, 1, now + i, 0) == FC_QUEUE);
  assert(fc_queued(&fc) == 3);
  assert(h1_gate(&fc, &wait[3], 23, 1, now, 0) == FC_SHED);
  assert(decisions(&fc, FC_R_QUEUED) == 3);
  assert(decisions(&fc, FC_R_QUEUE_FULL) == 1);
  assert(decisions(&fc, FC_R_CAPACITY_SHED) == 0);
  assert(wait[3].state == FC_P_NONE);
  assert(wait[0].q_deadline_ns == now + MS(5000));

  /* A release pops exactly one, the oldest, and wakes it. */
  fc_permit_release(&exec[0]);
  assert(woken_n == 1);
  assert(woken_fd[0] == 20 && woken_gen[0] == 1);
  assert(fc_queued(&fc) == 2);
  assert(fc_inflight(&fc) == 1);

  /* A newcomer does not overtake the two still waiting: it queues behind
   * them even though a unit is free. */
  assert(h1_gate(&fc, &extra, 30, 1, now, 0) == FC_QUEUE);
  assert(fc_queued(&fc) == 3);

  /* The woken request takes the free unit ahead of the newcomer. */
  fc_queue_resumed(&fc, &wait[0], now + MS(40));
  assert(wait[0].state == FC_P_NONE && wait[0].woken);
  assert(h1_gate(&fc, &wait[0], 20, 1, now, 1) == FC_ADMIT);
  assert(fc_inflight(&fc) == 2);
  assert(atomic_load(&fc.qwait_count) == 1);
  assert(atomic_load(&fc.qwait_sum_ms) == 40);
  assert(atomic_load(&fc.qwait_bucket[1]) == 1);   /* 40 ms: (10, 50] */

  /* Releases keep popping in order: 21, 22, then the newcomer. */
  fc_permit_release(&exec[1]);
  fc_permit_release(&wait[0]);
  assert(woken_n == 3);
  assert(woken_fd[1] == 21 && woken_fd[2] == 22);
  fc_queue_resumed(&fc, &wait[1], now + MS(100));
  fc_queue_resumed(&fc, &wait[2], now + MS(100));
  assert(h1_gate(&fc, &wait[1], 21, 1, now, 1) == FC_ADMIT);
  assert(h1_gate(&fc, &wait[2], 22, 1, now, 1) == FC_ADMIT);
  fc_permit_release(&wait[1]);
  assert(woken_n == 4 && woken_fd[3] == 30);
  fc_queue_resumed(&fc, &extra, now + MS(200));
  assert(h1_gate(&fc, &extra, 30, 1, now, 1) == FC_ADMIT);
  fc_permit_release(&wait[2]);
  fc_permit_release(&extra);
  assert(fc_inflight(&fc) == 0);
  assert(fc_queued(&fc) == 0);
  assert(atomic_load(&fc_anomaly_total[FC_A_UNDERFLOW]) == 0);
  fc_state_destroy(&fc);
  printf("  order: three waited, woken oldest first, a newcomer never overtook\n");
}

/* ---- a woken request that lost its unit keeps its place ---------------------- */

static void
test_woken_loser_returns_to_the_head(void)
{
  fc_state_t fc;
  fc_permit_t a, b, c, thief;
  uint64_t now = MS(1);

  pool_with(&fc, FC_MODE_ENFORCE, 1, 4, 1000);
  reset_wakes();
  assert(h1_gate(&fc, &a, 1, 7, now, 0) == FC_ADMIT);
  assert(h1_gate(&fc, &b, 2, 7, now, 0) == FC_QUEUE);
  assert(h1_gate(&fc, &c, 3, 7, now, 0) == FC_QUEUE);

  fc_permit_release(&a);
  assert(woken_n == 1 && woken_fd[0] == 2);
  /* Between the pop and the resume another executing request ends and a
   * woken one from elsewhere takes the unit (a woken request bypasses the
   * queue rule). fd 2 then finds no unit. */
  fc_queue_resumed(&fc, &b, now);
  assert(h1_gate(&fc, &thief, 9, 7, now, 1) == FC_ADMIT);
  assert(h1_gate(&fc, &b, 2, 7, now, 1) == FC_QUEUE);
  assert(b.state == FC_P_QUEUED);
  /* It is back at the HEAD, ahead of fd 3. */
  fc_permit_release(&thief);
  assert(woken_n == 2 && woken_fd[1] == 2);
  fc_queue_resumed(&fc, &b, now);
  assert(h1_gate(&fc, &b, 2, 7, now, 1) == FC_ADMIT);
  fc_permit_release(&b);
  assert(woken_n == 3 && woken_fd[2] == 3);
  fc_queue_resumed(&fc, &c, now);
  assert(h1_gate(&fc, &c, 3, 7, now, 1) == FC_ADMIT);
  fc_permit_release(&c);
  assert(fc_queued(&fc) == 0);
  fc_state_destroy(&fc);
  printf("  head: a woken request that lost the race went back to the front\n");
}

/* A request woken and sent back to wait is still bounded by the window it
 * was first given: going back must not restart its clock, or a pool whose
 * head keeps losing at an endpoint ceiling would hold it past the wait. */
static void
test_woken_loser_keeps_its_deadline(void)
{
  fc_state_t fc;
  fc_permit_t a, b, thief;
  uint64_t t0 = MS(1), later = MS(900);

  pool_with(&fc, FC_MODE_ENFORCE, 1, 4, 1000);
  reset_wakes();
  assert(h1_gate(&fc, &a, 1, 7, t0, 0) == FC_ADMIT);
  assert(h1_gate(&fc, &b, 2, 7, t0, 0) == FC_QUEUE);
  assert(b.q_deadline_ns == t0 + MS(1000));

  fc_permit_release(&a);
  assert(woken_n == 1 && woken_fd[0] == 2);
  fc_queue_resumed(&fc, &b, later);
  assert(h1_gate(&fc, &thief, 9, 7, later, 1) == FC_ADMIT);
  assert(h1_gate(&fc, &b, 2, 7, later, 1) == FC_QUEUE);
  assert(b.q_enqueue_ns == t0);
  assert(b.q_deadline_ns == t0 + MS(1000));

  assert(fc_queue_take(&fc, &b));
  fc_permit_release(&thief);
  fc_state_destroy(&fc);
  printf("  head: a woken request sent back keeps its first deadline\n");
}

/* Several woken requests that all lose go back in the order they arrived,
 * not in the order they happened to come back. */
static void
test_woken_losers_keep_arrival_order(void)
{
  fc_state_t fc;
  fc_cfg_t cfg;
  fc_permit_t a, w1, w2, w3, t1, t2;

  pool_with(&fc, FC_MODE_ENFORCE, 1, 4, 1000);
  reset_wakes();
  assert(h1_gate(&fc, &a, 1, 1, MS(1), 0) == FC_ADMIT);
  assert(h1_gate(&fc, &w1, 2, 1, MS(2), 0) == FC_QUEUE);
  assert(h1_gate(&fc, &w2, 3, 1, MS(3), 0) == FC_QUEUE);
  assert(h1_gate(&fc, &w3, 4, 1, MS(4), 0) == FC_QUEUE);

  cfg = fc.cfg;
  cfg.max_outstanding = 3;                        /* two turns given at once */
  fc_state_apply(&fc, &cfg);
  fc_queue_wake_room(&fc);
  assert(woken_n == 2 && woken_fd[0] == 2 && woken_fd[1] == 3);
  fc_queue_resumed(&fc, &w1, MS(5));
  fc_queue_resumed(&fc, &w2, MS(5));
  /* Both units are taken before either woken request runs; each goes back,
   * the first-woken first. */
  assert(h1_gate(&fc, &t1, 8, 1, MS(5), 1) == FC_ADMIT);
  assert(h1_gate(&fc, &t2, 9, 1, MS(5), 1) == FC_ADMIT);
  assert(h1_gate(&fc, &w1, 2, 1, MS(6), 1) == FC_QUEUE);
  assert(h1_gate(&fc, &w2, 3, 1, MS(6), 1) == FC_QUEUE);
  assert(fc_queued(&fc) == 3);

  reset_wakes();
  fc_permit_release(&t1);
  fc_queue_resumed(&fc, &w1, MS(7));
  fc_permit_release(&t2);
  assert(woken_n == 2 && woken_fd[0] == 2 && woken_fd[1] == 3);
  fc_queue_resumed(&fc, &w2, MS(7));
  assert(fc_queue_take(&fc, &w3));
  fc_permit_release(&a);
  fc_state_destroy(&fc);
  printf("  head: woken requests sent back keep their arrival order\n");
}

/* ---- exactly one terminal action per entry --------------------------------- */

static void
test_cancel_deadline_and_pop_are_exclusive(void)
{
  fc_state_t fc;
  fc_permit_t a, w1, w2, w3;
  uint64_t now = MS(10);

  pool_with(&fc, FC_MODE_ENFORCE, 1, 8, 100);
  reset_wakes();
  assert(h1_gate(&fc, &a, 1, 1, now, 0) == FC_ADMIT);
  assert(h1_gate(&fc, &w1, 2, 1, now, 0) == FC_QUEUE);
  assert(h1_gate(&fc, &w2, 3, 1, now, 0) == FC_QUEUE);
  assert(h1_gate(&fc, &w3, 4, 1, now, 0) == FC_QUEUE);
  assert(fc_queued(&fc) == 3);

  /* The client behind w1 goes away: releasing a QUEUED permit is the
   * cancellation, counted once, and it is never woken later. */
  fc_permit_release(&w1);
  assert(decisions(&fc, FC_R_CANCELLED) == 1);
  assert(fc_queued(&fc) == 2);
  fc_permit_release(&w1);                       /* idempotent */
  assert(decisions(&fc, FC_R_CANCELLED) == 1);

  /* The reaper finds w2 past its deadline and takes it: the pop that a
   * release triggers right after skips it and wakes w3 instead. */
  assert(w2.q_deadline_ns == now + MS(100));
  assert(fc_queue_take(&fc, &w2) == 1);
  fc_count(&fc, FC_R_QUEUE_TIMEOUT);
  assert(fc_queued(&fc) == 1);
  fc_permit_release(&a);
  assert(woken_n == 1 && woken_fd[0] == 4);
  /* And the reaper racing for w3 after that pop gets nothing. */
  assert(fc_queue_take(&fc, &w3) == 0);
  fc_queue_resumed(&fc, &w3, now + MS(50));
  /* The expired entry's own teardown finds nothing to cancel either. */
  w2.state = FC_P_QUEUED;
  assert(fc_queue_take(&fc, &w2) == 0);
  fc_permit_release(&w2);
  assert(decisions(&fc, FC_R_CANCELLED) == 1);
  assert(decisions(&fc, FC_R_QUEUE_TIMEOUT) == 1);
  assert(woken_n == 1);
  fc_state_destroy(&fc);
  printf("  exclusive: cancel, deadline and pop each took an entry exactly once\n");
}

/* ---- a wake that cannot be delivered keeps the entry at the head ------------- */

static void
test_undeliverable_wake_keeps_the_place(void)
{
  fc_state_t fc;
  fc_permit_t a, w1, w2;
  uint64_t now = MS(3);

  pool_with(&fc, FC_MODE_ENFORCE, 1, 4, 1000);
  reset_wakes();
  assert(h1_gate(&fc, &a, 1, 1, now, 0) == FC_ADMIT);
  assert(h1_gate(&fc, &w1, 2, 1, now, 0) == FC_QUEUE);
  assert(h1_gate(&fc, &w2, 3, 1, now + 1, 0) == FC_QUEUE);
  wake_refuse = 1;
  fc_permit_release(&a);
  assert(woken_n == 0);
  assert(fc_queued(&fc) == 2);
  wake_refuse = 0;
  /* The next released unit wakes the same oldest entry, with its original
   * deadline. */
  assert(h1_gate(&fc, &a, 9, 1, now, 1) == FC_ADMIT);
  fc_permit_release(&a);
  assert(woken_n == 1 && woken_fd[0] == 2);
  fc_queue_resumed(&fc, &w1, now);
  assert(w1.q_deadline_ns == now + MS(1000));
  /* Its slot hint is stale after the re-insert; cancelling still finds it. */
  assert(h1_gate(&fc, &w1, 2, 1, now, 1) == FC_ADMIT);
  fc_permit_release(&w1);
  assert(woken_n == 2 && woken_fd[1] == 3);
  fc_queue_resumed(&fc, &w2, now);
  w2.state = FC_P_QUEUED;
  assert(fc_queue_take(&fc, &w2) == 0);
  fc_state_destroy(&fc);
  printf("  wake: an undeliverable wake left the entry at the head\n");
}

/* ---- the depth can change while requests wait ------------------------------ */

static void
test_resize_keeps_waiting_entries(void)
{
  fc_state_t fc;
  fc_permit_t a, w[6];
  fc_cfg_t cfg;
  uint64_t now = MS(5);

  pool_with(&fc, FC_MODE_ENFORCE, 1, 2, 1000);
  reset_wakes();
  assert(h1_gate(&fc, &a, 1, 1, now, 0) == FC_ADMIT);
  assert(h1_gate(&fc, &w[0], 10, 1, now, 0) == FC_QUEUE);
  assert(h1_gate(&fc, &w[1], 11, 1, now, 0) == FC_QUEUE);
  assert(h1_gate(&fc, &w[2], 12, 1, now, 0) == FC_SHED);

  /* Grow: the ring is re-laid, the two keep their order, a third fits. */
  cfg = fc.cfg;
  cfg.max_queue_depth = 4;
  fc_state_apply(&fc, &cfg);
  assert(fc.queue.cap == 4 && fc_queued(&fc) == 2);
  assert(h1_gate(&fc, &w[2], 12, 1, now, 0) == FC_QUEUE);
  assert(h1_gate(&fc, &w[3], 13, 1, now, 0) == FC_QUEUE);
  assert(h1_gate(&fc, &w[4], 14, 1, now, 0) == FC_SHED);
  /* The stale slot hint of w[0] still cancels the right entry. */
  fc_permit_release(&w[0]);
  assert(decisions(&fc, FC_R_CANCELLED) == 1);
  assert(fc_queued(&fc) == 3);

  /* Shrink below the live count: nothing is dropped, new pushes wait for
   * the count to fall under the new depth. */
  cfg.max_queue_depth = 1;
  fc_state_apply(&fc, &cfg);
  assert(fc.queue.cap == 4 && fc_queued(&fc) == 3);
  assert(h1_gate(&fc, &w[4], 14, 1, now, 0) == FC_SHED);
  fc_permit_release(&a);
  assert(woken_n == 1 && woken_fd[0] == 11);
  fc_queue_resumed(&fc, &w[1], now);
  assert(h1_gate(&fc, &w[1], 11, 1, now, 1) == FC_ADMIT);
  fc_permit_release(&w[1]);
  assert(woken_n == 2 && woken_fd[1] == 12);
  fc_queue_resumed(&fc, &w[2], now);
  assert(h1_gate(&fc, &w[2], 12, 1, now, 1) == FC_ADMIT);
  fc_permit_release(&w[2]);
  assert(woken_n == 3 && woken_fd[2] == 13);
  fc_queue_resumed(&fc, &w[3], now);
  assert(h1_gate(&fc, &w[3], 13, 1, now, 1) == FC_ADMIT);
  assert(fc_queued(&fc) == 0);
  /* Depth 0 turns waiting off: over the ceiling is a refusal again. */
  cfg.max_queue_depth = 0;
  fc_state_apply(&fc, &cfg);
  assert(!fc_queue_enabled(&fc));
  assert(h1_gate(&fc, &w[5], 15, 1, now, 0) == FC_SHED);
  fc_permit_release(&w[3]);
  fc_state_destroy(&fc);
  printf("  resize: grow kept the order, shrink dropped nothing, zero turned waiting off\n");
}

/* ---- tombstones do not eat the ring ---------------------------------------- */

static void
test_tombstones_are_reclaimed(void)
{
  fc_state_t fc;
  fc_permit_t a, w[8];
  uint64_t now = MS(9);

  pool_with(&fc, FC_MODE_ENFORCE, 1, 3, 1000);
  reset_wakes();
  assert(h1_gate(&fc, &a, 1, 1, now, 0) == FC_ADMIT);
  /* Fill, cancel the middle one, fill the gap: the slots are used up by
   * a tombstone, the insert re-lays the ring instead of refusing. */
  for (int round = 0; round < 4; round++) {
    assert(h1_gate(&fc, &w[0], 100 + round, 1, now, 0) == FC_QUEUE);
    assert(h1_gate(&fc, &w[1], 200 + round, 1, now, 0) == FC_QUEUE);
    assert(h1_gate(&fc, &w[2], 300 + round, 1, now, 0) == FC_QUEUE);
    fc_permit_release(&w[1]);
    fc_permit_release(&w[0]);
    assert(fc_queued(&fc) == 1);
    assert(h1_gate(&fc, &w[3], 400 + round, 1, now, 0) == FC_QUEUE);
    assert(h1_gate(&fc, &w[4], 500 + round, 1, now, 0) == FC_QUEUE);
    assert(fc_queued(&fc) == 3);
    fc_permit_release(&w[2]);
    fc_permit_release(&w[3]);
    fc_permit_release(&w[4]);
    assert(fc_queued(&fc) == 0);
  }
  assert(decisions(&fc, FC_R_QUEUE_FULL) == 0);
  fc_permit_release(&a);
  fc_state_destroy(&fc);
  printf("  tombstones: cancelled slots were reclaimed, nothing refused\n");
}

/* ---- drain and maintenance --------------------------------------------------- */

static int drained_fd[8];
static int drained_n;
static int drained_skip_fd = -1;

/* Ends every entry but `drained_skip_fd`, whose connection has moved on. */
static int
note_drained(void *ctx, const fc_queue_ent_t *e)
{
  (void)ctx;
  if (e->fd == drained_skip_fd)
    return 0;
  drained_fd[drained_n++] = e->fd;
  return 1;
}

static void
test_drain_and_draining_flag(void)
{
  fc_state_t fc;
  fc_permit_t a, w1, w2, late, h2;
  uint64_t now = MS(2);

  pool_with(&fc, FC_MODE_ENFORCE, 1, 4, 1000);
  reset_wakes();
  drained_n = 0;
  assert(h1_gate(&fc, &a, 1, 1, now, 0) == FC_ADMIT);
  assert(h1_gate(&fc, &w1, 2, 1, now, 0) == FC_QUEUE);
  assert(h1_gate(&fc, &w2, 3, 1, now, 0) == FC_QUEUE);

  fc_drain_set(1);
  assert(fc_draining());
  /* New requests, HTTP/1 or HTTP/2, are refused while draining. */
  assert(fc_service_acquire_h1(&fc, &late, 0) == FC_DRAINING);
  assert(fc_service_acquire(&fc, &h2) == FC_DRAINING);
  /* The pool drains oldest first, each counted, none woken. */
  fc_queue_drain(&fc, note_drained, NULL);
  assert(drained_n == 2 && drained_fd[0] == 2 && drained_fd[1] == 3);
  assert(decisions(&fc, FC_R_DRAINED) == 2);
  assert(fc_queued(&fc) == 0);
  assert(woken_n == 0);
  /* Their teardowns find nothing to cancel. */
  fc_permit_release(&w1);
  fc_permit_release(&w2);
  assert(decisions(&fc, FC_R_CANCELLED) == 0);
  /* The executing request finishes normally. */
  fc_permit_release(&a);
  assert(fc_inflight(&fc) == 0);
  fc_drain_set(0);
  assert(fc_service_acquire_h1(&fc, &late, 0) == FC_ADMIT);
  fc_permit_release(&late);
  fc_state_destroy(&fc);
  printf("  drain: waiting requests drained in order, newcomers refused while draining\n");
}

/* An entry whose connection moved on before the drain reached it is not a
 * drained request: only the entries the callback ended are counted. */
static void
test_drain_counts_what_it_ended(void)
{
  fc_state_t fc;
  fc_permit_t a, w1, w2, w3;
  uint64_t now = MS(2);

  pool_with(&fc, FC_MODE_ENFORCE, 1, 4, 1000);
  reset_wakes();
  drained_n = 0;
  drained_skip_fd = 3;
  assert(h1_gate(&fc, &a, 1, 1, now, 0) == FC_ADMIT);
  assert(h1_gate(&fc, &w1, 2, 1, now, 0) == FC_QUEUE);
  assert(h1_gate(&fc, &w2, 3, 1, now, 0) == FC_QUEUE);
  assert(h1_gate(&fc, &w3, 4, 1, now, 0) == FC_QUEUE);
  fc_queue_drain(&fc, note_drained, NULL);
  assert(drained_n == 2 && drained_fd[0] == 2 && drained_fd[1] == 4);
  assert(decisions(&fc, FC_R_DRAINED) == 2);
  assert(fc_queued(&fc) == 0);
  drained_skip_fd = -1;
  fc_permit_release(&a);
  fc_state_destroy(&fc);
  printf("  drain: an entry whose connection had moved on was not counted drained\n");
}

/* ---- turns are never lost ---------------------------------------------------- */

/* The woken request's client leaves between the wake and the resume: its
 * teardown finds its entry already popped. The turn it was given goes to
 * the next waiting request, or the pool would idle with requests waiting. */
static void
test_a_lost_turn_is_passed_on(void)
{
  fc_state_t fc;
  fc_permit_t a, w1, w2;
  uint64_t now = MS(6);

  pool_with(&fc, FC_MODE_ENFORCE, 1, 4, 1000);
  reset_wakes();
  assert(h1_gate(&fc, &a, 1, 1, now, 0) == FC_ADMIT);
  assert(h1_gate(&fc, &w1, 2, 1, now, 0) == FC_QUEUE);
  assert(h1_gate(&fc, &w2, 3, 1, now, 0) == FC_QUEUE);
  fc_permit_release(&a);
  assert(woken_n == 1 && woken_fd[0] == 2);
  assert(fc_queue_holds(&fc, &w1) == 0);          /* popped for its turn */
  assert(fc_queue_holds(&fc, &w2) == 1);
  fc_permit_release(&w1);                         /* gone before its resume */
  assert(woken_n == 2 && woken_fd[1] == 3);
  assert(decisions(&fc, FC_R_CANCELLED) == 0);    /* its entry was not taken */
  fc_queue_resumed(&fc, &w2, now);
  assert(h1_gate(&fc, &w2, 3, 1, now, 1) == FC_ADMIT);
  fc_permit_release(&w2);
  assert(fc_inflight(&fc) == 0 && fc_queued(&fc) == 0);
  fc_state_destroy(&fc);
  printf("  turns: a woken client that left passed its turn to the next waiter\n");
}

/* A wake is a turn only when the ceiling has a unit free. The periodic
 * kick calls fc_queue_wake_one for every pool with waiting requests, so it
 * must not pop anyone while the pool is full, and must give the turn again
 * once a wake was lost with a unit free. */
static void
test_a_wake_needs_room(void)
{
  fc_state_t fc;
  fc_permit_t a, w1;
  uint64_t now = MS(7);

  pool_with(&fc, FC_MODE_ENFORCE, 1, 4, 1000);
  reset_wakes();
  assert(h1_gate(&fc, &a, 1, 1, now, 0) == FC_ADMIT);
  assert(h1_gate(&fc, &w1, 2, 1, now, 0) == FC_QUEUE);
  fc_queue_wake_one(&fc);                         /* full: nobody is popped */
  assert(woken_n == 0 && fc_queued(&fc) == 1);
  wake_refuse = 1;
  fc_permit_release(&a);                          /* the wake is lost */
  assert(woken_n == 0 && fc_queued(&fc) == 1 && fc_inflight(&fc) == 0);
  wake_refuse = 0;
  fc_queue_wake_one(&fc);                         /* the kick gives it again */
  assert(woken_n == 1 && woken_fd[0] == 2);
  fc_queue_resumed(&fc, &w1, now);
  assert(h1_gate(&fc, &w1, 2, 1, now, 1) == FC_ADMIT);
  fc_permit_release(&w1);
  fc_state_destroy(&fc);
  printf("  turns: no wake while full; a lost wake was given again once there was room\n");
}

/* A rule replace that frees units wakes that many waiters, in order, at
 * once rather than one per periodic kick; one that stops enforcing wakes
 * every waiter, since the gate now lets each of them through. */
static void
test_reconfigure_wakes_what_fits(void)
{
  fc_state_t fc;
  fc_cfg_t cfg;
  fc_permit_t a, w1, w2, w3;
  uint64_t now = MS(9);

  pool_with(&fc, FC_MODE_ENFORCE, 1, 4, 1000);
  reset_wakes();
  assert(h1_gate(&fc, &a, 1, 1, now, 0) == FC_ADMIT);
  assert(h1_gate(&fc, &w1, 2, 1, now, 0) == FC_QUEUE);
  assert(h1_gate(&fc, &w2, 3, 1, now, 0) == FC_QUEUE);
  assert(h1_gate(&fc, &w3, 4, 1, now, 0) == FC_QUEUE);
  fc_queue_wake_room(&fc);                        /* unchanged: nothing fits */
  assert(woken_n == 0 && fc_queued(&fc) == 3);

  cfg = fc.cfg;
  cfg.max_outstanding = 3;                        /* two more units */
  fc_state_apply(&fc, &cfg);
  fc_queue_wake_room(&fc);
  assert(woken_n == 2 && woken_fd[0] == 2 && woken_fd[1] == 3);
  assert(fc_queued(&fc) == 1);

  cfg.mode = FC_MODE_OBSERVE;                     /* no longer enforcing */
  fc_state_apply(&fc, &cfg);
  fc_queue_wake_room(&fc);
  assert(woken_n == 3 && woken_fd[2] == 4 && fc_queued(&fc) == 0);

  fc_queue_resumed(&fc, &w1, now);
  fc_queue_resumed(&fc, &w2, now);
  fc_queue_resumed(&fc, &w3, now);
  fc_permit_release(&w1);
  fc_permit_release(&w2);
  fc_permit_release(&w3);
  fc_permit_release(&a);
  fc_state_destroy(&fc);
  printf("  reconfigure: freed units woke that many waiters in order; observe woke the rest\n");
}

/* A request that goes back to wait hands its unit back without waking
 * anyone: the next waiter would meet the same ceiling. */
static void
test_release_nowake(void)
{
  fc_state_t fc;
  fc_permit_t a, w1;
  uint64_t now = MS(8);

  pool_with(&fc, FC_MODE_ENFORCE, 1, 4, 1000);
  reset_wakes();
  assert(h1_gate(&fc, &a, 1, 1, now, 0) == FC_ADMIT);
  assert(h1_gate(&fc, &w1, 2, 1, now, 0) == FC_QUEUE);
  fc_permit_release_nowake(&a);
  assert(woken_n == 0 && fc_inflight(&fc) == 0 && fc_queued(&fc) == 1);
  assert(a.state == FC_P_RELEASED);
  fc_permit_release_nowake(&a);                   /* idempotent */
  assert(atomic_load(&fc_anomaly_total[FC_A_UNDERFLOW]) == 0);
  fc_queue_wake_one(&fc);
  assert(woken_n == 1 && woken_fd[0] == 2);
  fc_queue_resumed(&fc, &w1, now);
  assert(h1_gate(&fc, &w1, 2, 1, now, 1) == FC_ADMIT);
  fc_permit_release(&w1);
  fc_state_destroy(&fc);
  printf("  nowake: a unit handed back without a wake woke nobody\n");
}

/* The woken request that lost its unit goes back to the head even when
 * newcomers filled the queue to its depth meanwhile: its entry left the
 * queue only for its turn. */
static void
test_front_push_is_not_refused_at_depth(void)
{
  fc_state_t fc;
  fc_permit_t a, w1, w2, n1, thief;
  uint64_t now = MS(11);

  pool_with(&fc, FC_MODE_ENFORCE, 1, 2, 1000);
  reset_wakes();
  assert(h1_gate(&fc, &a, 1, 1, now, 0) == FC_ADMIT);
  assert(h1_gate(&fc, &w1, 2, 1, now, 0) == FC_QUEUE);
  assert(h1_gate(&fc, &w2, 3, 1, now, 0) == FC_QUEUE);
  fc_permit_release(&a);
  assert(woken_n == 1 && woken_fd[0] == 2);
  assert(h1_gate(&fc, &n1, 4, 1, now, 0) == FC_QUEUE);   /* back at depth */
  assert(fc_queued(&fc) == 2);
  fc_queue_resumed(&fc, &w1, now);
  assert(h1_gate(&fc, &thief, 9, 1, now, 1) == FC_ADMIT);
  assert(h1_gate(&fc, &w1, 2, 1, now, 1) == FC_QUEUE);   /* not refused */
  assert(fc_queued(&fc) == 3);
  assert(decisions(&fc, FC_R_QUEUE_FULL) == 0);
  fc_permit_release(&thief);
  assert(woken_n == 2 && woken_fd[1] == 2);              /* still the head */
  /* Its turn taken, the queue is back at its depth, which still binds
   * newcomers. */
  assert(fc_queued(&fc) == 2);
  assert(h1_gate(&fc, &thief, 9, 1, now, 0) == FC_SHED);
  assert(decisions(&fc, FC_R_QUEUE_FULL) == 1);
  fc_queue_resumed(&fc, &w1, now);
  assert(h1_gate(&fc, &w1, 2, 1, now, 1) == FC_ADMIT);
  fc_permit_release(&w1);
  assert(woken_n == 3 && woken_fd[2] == 3);
  fc_queue_resumed(&fc, &w2, now);
  assert(h1_gate(&fc, &w2, 3, 1, now, 1) == FC_ADMIT);
  fc_permit_release(&w2);
  assert(woken_n == 4 && woken_fd[3] == 4);
  fc_queue_resumed(&fc, &n1, now);
  assert(h1_gate(&fc, &n1, 4, 1, now, 1) == FC_ADMIT);
  fc_permit_release(&n1);
  assert(fc_queued(&fc) == 0 && fc_inflight(&fc) == 0);
  fc_state_destroy(&fc);
  printf("  head: a woken loser went back to the head past a full queue\n");
}

/* A pool whose rule is gone: a worker that resolved it before the delete
 * may still reach it. Nothing parks on it again, the lock stays usable, and
 * a later apply does not bring the ring back. */
static void
test_a_dead_pool_takes_no_waiter(void)
{
  fc_state_t fc;
  fc_permit_t a, w;
  fc_cfg_t cfg;
  uint64_t now = MS(12);

  pool_with(&fc, FC_MODE_ENFORCE, 1, 4, 1000);
  reset_wakes();
  assert(h1_gate(&fc, &a, 1, 1, now, 0) == FC_ADMIT);
  fc_state_destroy(&fc);
  assert(!fc_queue_enabled(&fc));
  assert(fc_queue_push(&fc, &w, 2, 1, now, 0) == -1);
  assert(w.state == FC_P_NONE);
  assert(fc_queue_push(&fc, &w, 2, 1, now, 1) == -1);   /* nor at the head */
  cfg = fc.cfg;
  fc_state_apply(&fc, &cfg);
  assert(fc.queue.cap == 0 && !fc_queue_enabled(&fc));
  fc_permit_release(&a);
  assert(woken_n == 0);
  printf("  dead: a destroyed pool refused every push and stayed ringless\n");
}

/* A push publishes a permit that is already QUEUED: a drain on another
 * thread that pops the entry the moment it appears must find it waiting. */
#define STRESS_N 200000
static fc_permit_t stress_permit[STRESS_N];
static fc_state_t stress_fc;
static _Atomic int stress_done;
static _Atomic long stress_seen_not_queued;
static _Atomic long stress_drained;

static int
stress_note(void *ctx, const fc_queue_ent_t *e)
{
  (void)ctx;
  if (__atomic_load_n(&stress_permit[e->fd].state, __ATOMIC_RELAXED) != FC_P_QUEUED)
    atomic_fetch_add(&stress_seen_not_queued, 1);
  atomic_fetch_add(&stress_drained, 1);
  return 1;
}

static void *
stress_drainer(void *arg)
{
  (void)arg;
  while (!atomic_load(&stress_done) || fc_queued(&stress_fc) > 0)
    fc_queue_drain(&stress_fc, stress_note, NULL);
  return NULL;
}

static void
test_push_publishes_a_queued_permit(void)
{
  pthread_t t;
  long pushed = 0;

  pool_with(&stress_fc, FC_MODE_ENFORCE, 1, FC_QUEUE_DEPTH_MAX, 1000);
  atomic_store(&stress_done, 0);
  assert(pthread_create(&t, NULL, stress_drainer, NULL) == 0);
  for (int i = 0; i < STRESS_N; i++)
    if (fc_queue_push(&stress_fc, &stress_permit[i], i, 1, MS(1), 0) == 0)
      pushed++;
  atomic_store(&stress_done, 1);
  pthread_join(t, NULL);
  assert(atomic_load(&stress_drained) == pushed);
  assert(atomic_load(&stress_seen_not_queued) == 0);
  fc_state_destroy(&stress_fc);
  printf("  publish: %ld entries drained concurrently, every permit already QUEUED\n", pushed);
}

/* ---- HTTP/2 never waits; observe counts what it would have done ------------- */

static void
test_h2_sheds_and_observe_counts(void)
{
  fc_state_t fc;
  fc_permit_t a, s, w, o;
  uint64_t now = MS(4);

  pool_with(&fc, FC_MODE_ENFORCE, 1, 4, 1000);
  reset_wakes();
  assert(h1_gate(&fc, &a, 1, 1, now, 0) == FC_ADMIT);
  /* The stream site: over the ceiling is a refusal, never FC_QUEUE. */
  assert(fc_service_acquire(&fc, &s) == FC_SHED);
  assert(s.state == FC_P_NONE);
  /* With someone waiting it is refused even when a unit is free: the wait
   * is honoured over the stream. */
  assert(h1_gate(&fc, &w, 2, 1, now, 0) == FC_QUEUE);
  atomic_store(&fc.inflight, 0);
  assert(fc_service_acquire(&fc, &s) == FC_SHED);
  atomic_store(&fc.inflight, 1);
  /* Once the release has popped the last waiter the queue is empty, and a
   * stream arriving before the woken request resumes takes the unit; the
   * woken request goes back to the head and gets the stream's unit next. */
  fc_permit_release(&a);
  assert(woken_n == 1 && woken_fd[0] == 2);
  assert(fc_service_acquire(&fc, &s) == FC_ADMIT);
  fc_queue_resumed(&fc, &w, now);
  assert(h1_gate(&fc, &w, 2, 1, now, 1) == FC_QUEUE);
  fc_permit_release(&s);
  assert(woken_n == 2 && woken_fd[1] == 2);
  fc_queue_resumed(&fc, &w, now);
  assert(h1_gate(&fc, &w, 2, 1, now, 1) == FC_ADMIT);
  fc_permit_release(&w);
  fc_state_destroy(&fc);

  /* Observe: over the ceiling with a depth is admitted and counted as a
   * would-have-queued; the queue itself is never used. */
  pool_with(&fc, FC_MODE_OBSERVE, 1, 4, 1000);
  assert(!fc_queue_enabled(&fc));
  assert(h1_gate(&fc, &a, 1, 1, now, 0) == FC_ADMIT);
  assert(h1_gate(&fc, &o, 2, 1, now, 0) == FC_ADMIT);
  assert(fc_inflight(&fc) == 2);
  assert(decisions(&fc, FC_R_OBSERVE_WOULD_QUEUE) == 1);
  assert(decisions(&fc, FC_R_OBSERVE_WOULD_SHED) == 0);
  assert(fc_queued(&fc) == 0);
  fc_permit_release(&a);
  fc_permit_release(&o);
  fc_state_destroy(&fc);
  printf("  h2/observe: a stream never waited; observe counted a would-have-queued\n");
}

/* ---- the environment and the sizing arithmetic ------------------------------- */

static void
test_env_and_sizing(void)
{
  fc_cfg_t cfg;
  fc_state_t fc;

  setenv("LLB_FC_MODE", "enforce", 1);
  setenv("LLB_FC_MAX_OUTSTANDING", "8", 1);
  setenv("LLB_FC_MAX_QUEUE_DEPTH", "70000", 1);
  unsetenv("LLB_FC_MAX_QUEUE_WAIT_MS");
  fc_cfg_from_env(&cfg);
  assert(cfg.mode == FC_MODE_ENFORCE);
  assert(cfg.max_queue_depth == FC_QUEUE_DEPTH_MAX);   /* bounded */
  assert(cfg.max_queue_wait_ms == 5000);               /* a depth always has a window */
  setenv("LLB_FC_MAX_QUEUE_WAIT_MS", "99999999", 1);
  fc_cfg_from_env(&cfg);
  assert(cfg.max_queue_wait_ms == FC_QUEUE_WAIT_MS_MAX); /* an hour at most */
  setenv("LLB_FC_MAX_QUEUE_DEPTH", "16", 1);
  setenv("LLB_FC_MAX_QUEUE_WAIT_MS", "250", 1);
  fc_state_init(&fc);
  assert(fc.cfg.max_queue_depth == 16 && fc.cfg.max_queue_wait_ms == 250);
  assert(fc.queue.cap == 16);
  fc_state_destroy(&fc);
  unsetenv("LLB_FC_MODE");
  unsetenv("LLB_FC_MAX_OUTSTANDING");
  unsetenv("LLB_FC_MAX_QUEUE_DEPTH");
  unsetenv("LLB_FC_MAX_QUEUE_WAIT_MS");

  assert(fc_queue_memory_bytes(65536) == (65536ULL << 20));
  assert(fc_queue_memory_bytes(0) == 0);
  assert(fc_node_memory_bytes() > 0);

  /* Retry-After follows the mean wait, rounded up, within [1, 30]. */
  pool_with(&fc, FC_MODE_ENFORCE, 1, 4, 1000);
  assert(fc_retry_after_s(&fc) == 1);
  atomic_store(&fc.qwait_count, 4);
  atomic_store(&fc.qwait_sum_ms, 4 * 2400);
  assert(fc_retry_after_s(&fc) == 3);
  atomic_store(&fc.qwait_sum_ms, 4 * 90000);
  assert(fc_retry_after_s(&fc) == 30);
  fc_state_destroy(&fc);
  printf("  env/sizing: depth bounded, wait defaulted, memory and Retry-After arithmetic\n");
}

int
main(void)
{
  fc_set_wake_hook(record_wake);
  test_fifo_order_and_depth();
  test_woken_loser_returns_to_the_head();
  test_woken_loser_keeps_its_deadline();
  test_woken_losers_keep_arrival_order();
  test_cancel_deadline_and_pop_are_exclusive();
  test_undeliverable_wake_keeps_the_place();
  test_resize_keeps_waiting_entries();
  test_tombstones_are_reclaimed();
  test_drain_and_draining_flag();
  test_drain_counts_what_it_ended();
  test_a_lost_turn_is_passed_on();
  test_a_wake_needs_room();
  test_reconfigure_wakes_what_fits();
  test_release_nowake();
  test_front_push_is_not_refused_at_depth();
  test_a_dead_pool_takes_no_waiter();
  test_push_publishes_a_queued_permit();
  test_h2_sheds_and_observe_counts();
  test_env_and_sizing();
  printf("test_fc_queue: all passed\n");
  return 0;
}
