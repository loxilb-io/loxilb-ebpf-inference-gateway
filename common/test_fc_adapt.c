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
 * The adaptive service ceiling and the endpoint warm-up of the capacity
 * gate, driven alone: where each setting comes from, how the ceiling moves
 * tick by tick on fresh signals and holds on stale ones, what a TTFT
 * estimate is, how an endpoint's ceiling ramps back after it returns, and
 * that the gate's reservations follow the ceilings in force. The clock is
 * replaced, so every window is played out exactly.
 *
 * Build: make test_fc_adapt (also run by `make test_fc`).
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sockproxy_fc.h"

#define MS(n) ((uint64_t)(n) * 1000000ULL)

static uint64_t now;

static uint64_t
test_clock(void)
{
  return now;
}

static int wakes;

static int
count_wake(int fd, uint64_t gen)
{
  (void)fd;
  (void)gen;
  wakes++;
  return 0;
}

static void
pool_with(fc_state_t *fc, const fc_cfg_t *cfg)
{
  memset(fc, 0, sizeof(*fc));
  pthread_mutex_init(&fc->queue.lock, NULL);
  fc_state_apply(fc, cfg);
}

static uint32_t
eff(const fc_state_t *fc)
{
  return fc_svc_cap(fc);
}

static uint8_t
state(const fc_state_t *fc)
{
  return atomic_load(&fc->adapt_state);
}

static uint8_t
reason(const fc_state_t *fc)
{
  return atomic_load(&fc->adapt_reason);
}

static void
tick(fc_state_t *fc, int fresh, int queued, int ttft_over)
{
  fc_signal_t sig = { .fresh = (uint8_t)fresh, .queued = (uint8_t)queued,
                      .ttft_over = (uint8_t)ttft_over };
  fc_adapt_tick(fc, &sig);
}

static void
clear_env(void)
{
  unsetenv("LLB_FC_MODE");
  unsetenv("LLB_FC_MAX_OUTSTANDING");
  unsetenv("LLB_FC_ADAPTIVE");
  unsetenv("LLB_FC_WARMUP_MS");
  unsetenv("LLB_FC_TTFT_TARGET_MS");
}

static void
test_settings_resolve_with_sources(void)
{
  fc_cfg_t env, out, other;
  fc_rule_cfg_t rule;

  clear_env();
  fc_cfg_from_env(&env);
  assert(env.adaptive == 0 && env.src[FC_L_ADAPTIVE] == FC_SRC_DEFAULT);
  assert(env.warmup_ms == 0 && env.src[FC_L_WARMUP] == FC_SRC_DEFAULT);
  assert(env.ttft_target_ms == 0 && env.src[FC_L_TTFT_TARGET] == FC_SRC_DEFAULT);

  setenv("LLB_FC_ADAPTIVE", "on", 1);
  setenv("LLB_FC_WARMUP_MS", "20000", 1);
  setenv("LLB_FC_TTFT_TARGET_MS", "3600001", 1);
  fc_cfg_from_env(&env);
  assert(env.adaptive == 1 && env.src[FC_L_ADAPTIVE] == FC_SRC_ENV);
  assert(env.warmup_ms == 20000 && env.src[FC_L_WARMUP] == FC_SRC_ENV);
  /* Over the ceiling: held at it. */
  assert(env.ttft_target_ms == FC_TTFT_TARGET_MS_MAX &&
         env.src[FC_L_TTFT_TARGET] == FC_SRC_ENV);

  /* Nothing declared: the environment's values, sources kept. */
  memset(&rule, 0, sizeof(rule));
  fc_cfg_resolve(&out, &env, &rule);
  assert(memcmp(&out, &env, sizeof(out)) == 0);

  /* A rule turns adaptation off under an environment that has it on, and
   * sets its own window and target. */
  rule.adaptive = FC_RULE_ADAPTIVE_OFF;
  rule.warmup_ms = 5000;
  rule.ttft_target_ms = 800;
  fc_cfg_resolve(&out, &env, &rule);
  assert(out.adaptive == 0 && out.src[FC_L_ADAPTIVE] == FC_SRC_RULE);
  assert(out.warmup_ms == 5000 && out.src[FC_L_WARMUP] == FC_SRC_RULE);
  assert(out.ttft_target_ms == 800 && out.src[FC_L_TTFT_TARGET] == FC_SRC_RULE);

  /* An undefined switch value inherits. */
  rule.adaptive = 7;
  fc_cfg_resolve(&out, &env, &rule);
  assert(out.adaptive == 1 && out.src[FC_L_ADAPTIVE] == FC_SRC_ENV);

  setenv("LLB_FC_ADAPTIVE", "off", 1);
  fc_cfg_from_env(&env);
  assert(env.adaptive == 0 && env.src[FC_L_ADAPTIVE] == FC_SRC_ENV);
  memset(&rule, 0, sizeof(rule));
  rule.adaptive = FC_RULE_ADAPTIVE_ON;
  fc_cfg_resolve(&out, &env, &rule);
  assert(out.adaptive == 1 && out.src[FC_L_ADAPTIVE] == FC_SRC_RULE);

  /* Each of the three is a change. */
  other = out;
  other.adaptive = 0;
  assert(!fc_cfg_equal(&out, &other));
  other = out;
  other.warmup_ms = 1;
  assert(!fc_cfg_equal(&out, &other));
  other = out;
  other.ttft_target_ms = 1;
  assert(!fc_cfg_equal(&out, &other));
  other = out;
  assert(out.src[FC_L_TTFT_TARGET] == FC_SRC_ENV);
  other.src[FC_L_TTFT_TARGET] = FC_SRC_DEFAULT;
  assert(!fc_cfg_equal(&out, &other));
  assert(fc_cfg_equal(&out, &out));
  clear_env();
  printf("  settings: each declaration replaces the environment, with its source\n");
}

static void
test_ceiling_tightens_holds_and_recovers(void)
{
  fc_state_t fc;
  fc_cfg_t cfg = { .mode = FC_MODE_ENFORCE, .max_outstanding = 20,
                   .adaptive = 1, .telemetry_stale_ms = 30000 };
  const uint32_t down[] = { 16, 12, 9, 7, 5, 5 };

  pool_with(&fc, &cfg);
  assert(eff(&fc) == 20 && state(&fc) == FC_AS_OPEN);

  /* Fresh backpressure: four fifths per tick, never under a quarter. */
  for (unsigned i = 0; i < sizeof(down) / sizeof(down[0]); i++) {
    tick(&fc, 1, 1, 0);
    assert(eff(&fc) == down[i]);
    assert(state(&fc) == FC_AS_TIGHTENED && reason(&fc) == FC_AR_QUEUED);
  }
  assert(atomic_load(&fc.adapt_moves[0]) == 5);

  /* Stale: held, however long, and said so. */
  for (int i = 0; i < 10; i++) {
    tick(&fc, 0, 0, 0);
    assert(eff(&fc) == 5);
  }
  assert(state(&fc) == FC_AS_FROZEN && reason(&fc) == FC_AR_STALE);
  /* Stale with a stale backpressure bit set is still only held. */
  tick(&fc, 0, 1, 1);
  assert(eff(&fc) == 5 && state(&fc) == FC_AS_FROZEN);

  /* Fresh and clear: one unit back per tick, up to the ceiling. */
  for (uint32_t want = 6; want <= 20; want++) {
    tick(&fc, 1, 0, 0);
    assert(eff(&fc) == want);
    assert(reason(&fc) == FC_AR_CLEAR);
  }
  assert(state(&fc) == FC_AS_OPEN);
  tick(&fc, 1, 0, 0);
  assert(eff(&fc) == 20 && atomic_load(&fc.adapt_moves[1]) == 15);

  /* TTFT over the target is backpressure too. */
  tick(&fc, 1, 0, 1);
  assert(eff(&fc) == 16 && reason(&fc) == FC_AR_TTFT);

  /* The service reservation follows the ceiling in force. */
  {
    fc_permit_t p[20];
    int admitted = 0;

    for (int i = 0; i < 20; i++)
      if (fc_service_acquire(&fc, &p[i]) == FC_ADMIT)
        admitted++;
    assert(admitted == 16);
    assert(!fc_has_room(&fc));
    assert(fc_limit_for(&fc, -1) == 16);
    for (int i = 0; i < 16; i++)
      fc_permit_release(&p[i]);
  }

  /* A small ceiling never goes to zero. */
  cfg.max_outstanding = 3;
  pool_with(&fc, &cfg);
  for (int i = 0; i < 5; i++)
    tick(&fc, 1, 1, 0);
  assert(eff(&fc) == 1);
  printf("  adaptive: tightens on fresh backpressure, holds on stale, gives back one per clear tick\n");
}

static void
test_reconfiguration(void)
{
  fc_state_t fc;
  fc_cfg_t cfg = { .mode = FC_MODE_ENFORCE, .max_outstanding = 20,
                   .adaptive = 1, .telemetry_stale_ms = 30000 };

  pool_with(&fc, &cfg);
  tick(&fc, 1, 1, 0);
  tick(&fc, 1, 1, 0);
  assert(eff(&fc) == 12);

  /* A raised ceiling does not undo the evidence: the pool climbs back. */
  cfg.max_outstanding = 40;
  fc_state_apply(&fc, &cfg);
  assert(eff(&fc) == 12 && state(&fc) == FC_AS_TIGHTENED);

  /* A lowered ceiling holds it. */
  cfg.max_outstanding = 10;
  fc_state_apply(&fc, &cfg);
  assert(eff(&fc) == 10);

  /* An open pool follows a raised ceiling at once. */
  cfg.max_outstanding = 10;
  pool_with(&fc, &cfg);
  cfg.max_outstanding = 30;
  fc_state_apply(&fc, &cfg);
  assert(eff(&fc) == 30 && state(&fc) == FC_AS_OPEN);

  /* Adaptation turned off: the configured ceiling, at once. */
  tick(&fc, 1, 1, 0);
  assert(eff(&fc) == 24);
  cfg.adaptive = 0;
  fc_state_apply(&fc, &cfg);
  assert(eff(&fc) == 30 && state(&fc) == FC_AS_OFF);
  /* And a tick of a pool that does not adapt moves nothing. */
  tick(&fc, 1, 1, 0);
  assert(eff(&fc) == 30);

  /* No ceiling: nothing to tighten. */
  cfg.adaptive = 1;
  cfg.max_outstanding = 0;
  fc_state_apply(&fc, &cfg);
  tick(&fc, 1, 1, 0);
  assert(eff(&fc) == 0 && state(&fc) == FC_AS_OFF);
  printf("  adaptive: a replace clamps a lowered ceiling, keeps the evidence under a raised one\n");
}

static void
test_widening_wakes_the_waiters_that_fit(void)
{
  fc_state_t fc;
  fc_cfg_t cfg = { .mode = FC_MODE_ENFORCE, .max_outstanding = 10,
                   .adaptive = 1, .max_queue_depth = 8,
                   .max_queue_wait_ms = 60000, .telemetry_stale_ms = 30000 };
  fc_permit_t run[10], wait[3];
  int held = 0;

  pool_with(&fc, &cfg);
  fc_set_wake_hook(count_wake);
  tick(&fc, 1, 1, 0);                       /* 10 -> 8 */
  assert(eff(&fc) == 8);
  for (int i = 0; i < 10; i++)
    if (fc_service_acquire_h1(&fc, &run[i], 0) == FC_ADMIT)
      held++;
  assert(held == 8);
  for (int i = 0; i < 3; i++) {
    assert(fc_service_acquire_h1(&fc, &wait[i], 0) == FC_QUEUE);
    assert(fc_queue_push(&fc, &wait[i], 100 + i, 1, MS(1), 0) == 0);
  }
  wakes = 0;
  tick(&fc, 0, 0, 0);                       /* stale: nobody */
  assert(wakes == 0);
  tick(&fc, 1, 0, 0);                       /* one unit back: one waiter */
  assert(eff(&fc) == 9 && wakes == 1);
  for (int i = 0; i < 8; i++)
    fc_permit_release_nowake(&run[i]);
  fc_set_wake_hook(NULL);
  printf("  adaptive: a unit given back wakes one waiter; a stale tick wakes none\n");
}

static void
test_ttft_estimate(void)
{
  fc_state_t fc;
  fc_cfg_t cfg = { .mode = FC_MODE_ENFORCE, .max_outstanding = 8,
                   .ttft_target_ms = 500, .telemetry_stale_ms = 10000 };
  int fresh;

  pool_with(&fc, &cfg);
  now = MS(1000);
  assert(!fc_ttft_over(&fc, 0, now, &fresh) && !fresh);
  fc_ttft_sample(&fc, 0, 400, now);
  assert(atomic_load(&fc.ttft_ewma_ms[0]) == 400);
  assert(!fc_ttft_over(&fc, 0, now, &fresh) && fresh);
  /* One slow sample moves the estimate an eighth of the way. */
  fc_ttft_sample(&fc, 0, 1200, now);
  assert(atomic_load(&fc.ttft_ewma_ms[0]) == 500);
  assert(!fc_ttft_over(&fc, 0, now, NULL));
  fc_ttft_sample(&fc, 0, 1200, now);
  assert(atomic_load(&fc.ttft_ewma_ms[0]) == 588);
  assert(fc_ttft_over(&fc, 0, now, &fresh) && fresh);
  /* Past the telemetry window the estimate is not evidence. */
  assert(!fc_ttft_over(&fc, 0, now + MS(10001), &fresh) && !fresh);
  /* The next sample after a silence starts the estimate over. */
  fc_ttft_sample(&fc, 0, 100, now + MS(20000));
  assert(atomic_load(&fc.ttft_ewma_ms[0]) == 100);
  /* Without a target TTFT is never backpressure. */
  cfg.ttft_target_ms = 0;
  fc_state_apply(&fc, &cfg);
  fc_ttft_sample(&fc, 1, 99999, now);
  assert(!fc_ttft_over(&fc, 1, now, &fresh) && !fresh);
  printf("  ttft: an eighth-weighted estimate, evidence only while fresh and a target is set\n");
}

static void
test_warm_up_ramp(void)
{
  fc_state_t fc;
  fc_cfg_t cfg = { .mode = FC_MODE_ENFORCE, .ep_cap = { 8, 0, 3 },
                   .warmup_ms = 1000, .telemetry_stale_ms = 30000 };
  fc_permit_t p[8];
  int got = 0;

  fc_set_clock(test_clock);
  pool_with(&fc, &cfg);
  now = MS(5000);
  assert(fc_ep_cap_now(&fc, 0, FC_ROLE_NORMAL, 0) == 8);   /* warm */
  fc_ep_warm_start(&fc, 0, 0);
  assert(fc_warming_eps(&fc, now) == 1);
  assert(fc_ep_cap_now(&fc, 0, FC_ROLE_NORMAL, 0) == 2);   /* a quarter */
  assert(fc_ep_cap_now(&fc, 0, FC_ROLE_DECODE, 0) == 1);   /* at least one */
  assert(fc_ep_cap_now(&fc, 0, FC_ROLE_PREFILL, 0) == 0);  /* unlimited stays */
  assert(fc_ep_cap_now(&fc, 1, FC_ROLE_NORMAL, 0) == 8);   /* others untouched */

  /* The reservation follows the ramp: two now, not eight. */
  for (int i = 0; i < 8; i++) {
    assert(fc_service_acquire(&fc, &p[i]) == FC_ADMIT);
    if (fc_ep_acquire(&fc, &p[i], 0, FC_ROLE_NORMAL) == FC_ADMIT)
      got++;
  }
  assert(got == 2);
  assert(fc_ep_over_cap(&fc, 0, FC_ROLE_NORMAL));

  now = MS(5500);
  assert(fc_ep_cap_now(&fc, 0, FC_ROLE_NORMAL, 0) == 5);   /* halfway */
  assert(!fc_ep_over_cap(&fc, 0, FC_ROLE_NORMAL));
  now = MS(6000);
  assert(fc_ep_cap_now(&fc, 0, FC_ROLE_NORMAL, 0) == 8);   /* done */
  assert(fc_warming_eps(&fc, now) == 0);
  for (int i = 0; i < 8; i++)
    fc_permit_release(&p[i]);

  /* No window: a return is at full ceiling at once. */
  cfg.warmup_ms = 0;
  fc_state_apply(&fc, &cfg);
  fc_ep_warm_start(&fc, 2, 0);
  assert(fc_ep_cap_now(&fc, 2, FC_ROLE_NORMAL, 0) == 8);
  /* A window removed ends a warm-up in progress. */
  cfg.warmup_ms = 1000;
  fc_state_apply(&fc, &cfg);
  fc_ep_warm_start(&fc, 3, 0);
  assert(fc_ep_cap_now(&fc, 3, FC_ROLE_NORMAL, 0) == 2);
  cfg.warmup_ms = 0;
  fc_state_apply(&fc, &cfg);
  assert(fc_ep_cap_now(&fc, 3, FC_ROLE_NORMAL, 0) == 8);
  fc_set_clock(NULL);
  printf("  warm-up: an endpoint back in service ramps from a quarter to its ceiling\n");
}

static void
test_ttft_is_measured_from_admission(void)
{
  fc_state_t fc;
  fc_cfg_t cfg = { .mode = FC_MODE_ENFORCE, .max_outstanding = 1,
                   .ttft_target_ms = 500, .max_queue_depth = 4,
                   .max_queue_wait_ms = 60000, .telemetry_stale_ms = 30000 };
  fc_permit_t a, b;

  fc_set_clock(test_clock);
  pool_with(&fc, &cfg);
  now = MS(1000);
  /* b arrives while a holds the only unit, waits 4 s at the gate, then is
   * admitted: its engine answered 300 ms after that, not 4.3 s after it
   * arrived. */
  assert(fc_service_acquire_h1(&fc, &a, 0) == FC_ADMIT);
  assert(fc_ep_acquire(&fc, &a, 0, FC_ROLE_NORMAL) == FC_ADMIT);
  assert(a.admit_ns == MS(1000));
  assert(fc_service_acquire_h1(&fc, &b, 0) == FC_QUEUE);
  assert(fc_queue_push(&fc, &b, 7, 1, MS(1000), 0) == 0);
  now = MS(5000);
  fc_permit_release_nowake(&a);
  {
    fc_queue_ent_t e;

    assert(fc_queue_pop(&fc, &e) == 1 && e.fd == 7);
  }
  fc_queue_resumed(&fc, &b, MS(5000));
  assert(fc_service_acquire_h1(&fc, &b, 1) == FC_ADMIT);
  assert(b.q_enqueue_ns == MS(1000));
  assert(fc_ep_acquire(&fc, &b, 1, FC_ROLE_NORMAL) == FC_ADMIT);
  now = MS(5300);
  fc_permit_ttft(&b);
  assert(atomic_load(&fc.ttft_ewma_ms[1]) == 300);
  fc_permit_release(&b);

  /* A disaggregated request is credited to its decode endpoint, from the
   * admission of its first (prefill) leg. */
  now = MS(6000);
  assert(fc_service_acquire(&fc, &a) == FC_ADMIT);
  assert(fc_ep_acquire(&fc, &a, 2, FC_ROLE_PREFILL) == FC_ADMIT);
  now = MS(6400);
  assert(fc_ep_acquire(&fc, &a, 3, FC_ROLE_DECODE) == FC_ADMIT);
  now = MS(6900);
  fc_permit_ttft(&a);
  assert(atomic_load(&fc.ttft_ewma_ms[3]) == 900);
  assert(atomic_load(&fc.ttft_ewma_ms[2]) == 0);
  fc_permit_release(&a);

  /* Without a target nothing is sampled; a released permit samples nothing. */
  cfg.ttft_target_ms = 0;
  fc_state_apply(&fc, &cfg);
  assert(fc_service_acquire(&fc, &a) == FC_ADMIT);
  assert(fc_ep_acquire(&fc, &a, 4, FC_ROLE_NORMAL) == FC_ADMIT);
  now = MS(7000);
  fc_permit_ttft(&a);
  assert(atomic_load(&fc.ttft_ts_ns[4]) == 0);
  fc_permit_release(&a);
  fc_permit_ttft(&a);
  assert(atomic_load(&fc.ttft_ts_ns[4]) == 0);
  fc_set_clock(NULL);
  printf("  ttft: measured from admission, credited to the decode endpoint, only with a target\n");
}

int
main(void)
{
  test_settings_resolve_with_sources();
  test_ceiling_tightens_holds_and_recovers();
  test_reconfiguration();
  test_widening_wakes_the_waiters_that_fit();
  test_ttft_estimate();
  test_warm_up_ramp();
  test_ttft_is_measured_from_admission();
  printf("test_fc_adapt: all passed\n");
  return 0;
}
