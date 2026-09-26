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

/* The capacity gate's contract, exercised without the proxy: ceilings hold
 * under contention, units come back exactly once, two legs of one request
 * count one service unit, a moved leg never over-admits, observe mode
 * admits and counts, off mode touches nothing. */

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sockproxy_fc.h"

static void
reset_anomalies(void)
{
  for (int i = 0; i < FC_A_COUNT; i++)
    atomic_store(&fc_anomaly_total[i], 0);
}

static uint64_t
anomalies(enum fc_anomaly a)
{
  return atomic_load(&fc_anomaly_total[a]);
}

static uint64_t
decisions(const fc_state_t *fc, enum fc_reason r)
{
  return atomic_load(&fc->decisions[r]);
}

static void
state_with(fc_state_t *fc, uint8_t mode, uint32_t max_out,
           uint32_t cap_normal, uint32_t cap_prefill, uint32_t cap_decode)
{
  fc_cfg_t cfg = {0};

  memset(fc, 0, sizeof(*fc));
  cfg.mode = mode;
  cfg.max_outstanding = max_out;
  cfg.ep_cap[FC_ROLE_NORMAL] = cap_normal;
  cfg.ep_cap[FC_ROLE_PREFILL] = cap_prefill;
  cfg.ep_cap[FC_ROLE_DECODE] = cap_decode;
  fc_state_apply(fc, &cfg);
}

/* ---- ceilings under contention -------------------------------------------- */

#define WORKERS 8
#define ROUNDS 2000

typedef struct {
  fc_state_t *fc;
  int ep;
  uint32_t max_seen_svc;
  uint32_t max_seen_ep;
  uint32_t admitted;
  uint32_t shed;
} worker_t;

static void *
hammer(void *arg)
{
  worker_t *w = arg;

  for (int i = 0; i < ROUNDS; i++) {
    fc_permit_t p;
    if (fc_service_acquire(w->fc, &p) != FC_ADMIT) {
      w->shed++;
      continue;
    }
    if (fc_ep_acquire(w->fc, &p, w->ep, FC_ROLE_NORMAL) != FC_ADMIT) {
      w->shed++;
      fc_permit_release(&p);
      continue;
    }
    uint32_t s = fc_inflight(w->fc);
    uint32_t e = fc_ep_inflight(w->fc, w->ep, FC_ROLE_NORMAL);
    if (s > w->max_seen_svc) w->max_seen_svc = s;
    if (e > w->max_seen_ep) w->max_seen_ep = e;
    w->admitted++;
    fc_permit_release(&p);
  }
  return NULL;
}

static void
test_ceilings_hold_under_contention(void)
{
  fc_state_t fc;
  pthread_t th[WORKERS];
  worker_t w[WORKERS];
  uint32_t max_svc = 0, max_ep = 0, admitted = 0, shed = 0;

  /* Service ceiling 5 across eight workers, endpoint ceiling 3 on one EP. */
  state_with(&fc, FC_MODE_ENFORCE, 5, 3, 0, 0);
  reset_anomalies();
  for (int i = 0; i < WORKERS; i++) {
    memset(&w[i], 0, sizeof(w[i]));
    w[i].fc = &fc;
    w[i].ep = 0;
    assert(pthread_create(&th[i], NULL, hammer, &w[i]) == 0);
  }
  for (int i = 0; i < WORKERS; i++) {
    pthread_join(th[i], NULL);
    if (w[i].max_seen_svc > max_svc) max_svc = w[i].max_seen_svc;
    if (w[i].max_seen_ep > max_ep) max_ep = w[i].max_seen_ep;
    admitted += w[i].admitted;
    shed += w[i].shed;
  }
  assert(max_svc <= 5);
  assert(max_ep <= 3);
  assert(admitted > 0);
  assert(fc_inflight(&fc) == 0);
  assert(fc_ep_inflight(&fc, 0, FC_ROLE_NORMAL) == 0);
  assert(decisions(&fc, FC_R_ADMITTED) == admitted);
  assert(decisions(&fc, FC_R_CAPACITY_SHED) == shed);
  assert(anomalies(FC_A_UNDERFLOW) == 0);
  printf("  contention: %u admitted, %u shed, max service %u/5, max endpoint %u/3\n",
         admitted, shed, max_svc, max_ep);
}

/* ---- exactly-once release --------------------------------------------------- */

static void
test_release_is_idempotent_and_underflow_is_counted(void)
{
  fc_state_t fc;
  fc_permit_t p;

  state_with(&fc, FC_MODE_ENFORCE, 4, 2, 0, 0);
  reset_anomalies();

  assert(fc_service_acquire(&fc, &p) == FC_ADMIT);
  assert(fc_ep_acquire(&fc, &p, 1, FC_ROLE_NORMAL) == FC_ADMIT);
  assert(fc_inflight(&fc) == 1);
  assert(fc_ep_inflight(&fc, 1, FC_ROLE_NORMAL) == 1);

  /* Three release sites may all run for one request; only the first moves
   * a counter and none of them is an anomaly. */
  fc_permit_release(&p);
  fc_permit_release(&p);
  fc_permit_release(&p);
  assert(fc_inflight(&fc) == 0);
  assert(fc_ep_inflight(&fc, 1, FC_ROLE_NORMAL) == 0);
  assert(p.state == FC_P_RELEASED);
  assert(anomalies(FC_A_UNDERFLOW) == 0);

  /* A unit released that was never taken: the counter stays at zero and
   * the event is counted, never wrapped into a permanent admit. */
  assert(fc_service_acquire(&fc, &p) == FC_ADMIT);
  assert(fc_ep_acquire(&fc, &p, 1, FC_ROLE_NORMAL) == FC_ADMIT);
  atomic_store(&fc.inflight, 0);
  atomic_store(&fc.ep_inflight[1][FC_ROLE_NORMAL], 0);
  fc_permit_release(&p);
  assert(fc_inflight(&fc) == 0);
  assert(fc_ep_inflight(&fc, 1, FC_ROLE_NORMAL) == 0);
  assert(anomalies(FC_A_UNDERFLOW) == 2);

  /* A permit that never acquired releases nothing and reports nothing. */
  fc_permit_init(&p);
  fc_permit_release(&p);
  assert(anomalies(FC_A_UNDERFLOW) == 2);
  assert(anomalies(FC_A_UNKNOWN_PERMIT) == 0);
}

/* ---- dual legs, one service unit --------------------------------------------- */

static void
test_two_role_legs_count_one_service_unit(void)
{
  fc_state_t fc;
  fc_permit_t p;

  state_with(&fc, FC_MODE_ENFORCE, 8, 0, 1, 1);
  reset_anomalies();

  assert(fc_service_acquire(&fc, &p) == FC_ADMIT);
  assert(fc_ep_acquire(&fc, &p, 0, FC_ROLE_PREFILL) == FC_ADMIT);
  assert(fc_ep_acquire(&fc, &p, 3, FC_ROLE_DECODE) == FC_ADMIT);
  assert(fc_inflight(&fc) == 1);
  assert(fc_ep_inflight(&fc, 0, FC_ROLE_PREFILL) == 1);
  assert(fc_ep_inflight(&fc, 3, FC_ROLE_DECODE) == 1);

  /* A second request finds both role ceilings (1) taken but the service
   * has room: it is refused on the endpoint, and the refusal leaves its
   * own service unit to be handed back by the caller. */
  fc_permit_t q;
  assert(fc_service_acquire(&fc, &q) == FC_ADMIT);
  assert(fc_inflight(&fc) == 2);
  assert(fc_ep_acquire(&fc, &q, 0, FC_ROLE_PREFILL) == FC_SHED);
  fc_permit_release(&q);
  assert(fc_inflight(&fc) == 1);

  /* The decode leg ends on its own; the request is still executing. */
  fc_release_role(&p, FC_ROLE_DECODE);
  assert(fc_ep_inflight(&fc, 3, FC_ROLE_DECODE) == 0);
  assert(fc_inflight(&fc) == 1);
  assert(p.state == FC_P_EXECUTING);

  fc_permit_release(&p);
  assert(fc_inflight(&fc) == 0);
  assert(fc_ep_inflight(&fc, 0, FC_ROLE_PREFILL) == 0);
  assert(anomalies(FC_A_UNDERFLOW) == 0);
}

/* ---- a moved leg never over-admits ------------------------------------------ */

static void
test_move_takes_the_new_endpoint_first(void)
{
  fc_state_t fc;
  fc_permit_t p, other;

  state_with(&fc, FC_MODE_ENFORCE, 8, 0, 1, 0);
  reset_anomalies();

  assert(fc_service_acquire(&fc, &other) == FC_ADMIT);
  assert(fc_ep_acquire(&fc, &other, 1, FC_ROLE_PREFILL) == FC_ADMIT);

  assert(fc_service_acquire(&fc, &p) == FC_ADMIT);
  assert(fc_ep_acquire(&fc, &p, 0, FC_ROLE_PREFILL) == FC_ADMIT);

  /* Endpoint 1 is full: the move is refused and endpoint 0 is still held. */
  assert(fc_permit_move(&p, FC_ROLE_PREFILL, 1) == -1);
  assert(p.ep[FC_ROLE_PREFILL] == 0);
  assert(fc_ep_inflight(&fc, 0, FC_ROLE_PREFILL) == 1);
  assert(fc_ep_inflight(&fc, 1, FC_ROLE_PREFILL) == 1);

  /* Endpoint 2 has room: the unit moves, endpoint 0 is released. */
  assert(fc_permit_move(&p, FC_ROLE_PREFILL, 2) == 0);
  assert(p.ep[FC_ROLE_PREFILL] == 2);
  assert(fc_ep_inflight(&fc, 0, FC_ROLE_PREFILL) == 0);
  assert(fc_ep_inflight(&fc, 2, FC_ROLE_PREFILL) == 1);

  fc_permit_release(&p);
  fc_permit_release(&other);
  assert(fc_inflight(&fc) == 0);
  assert(anomalies(FC_A_UNDERFLOW) == 0);
}

/* ---- selection cannot override admission ----------------------------------- */

typedef struct {
  int n;
  int eligible[FC_MAX_EP];
} pool_t;

static int
pool_eligible(void *ctx, int ep)
{
  pool_t *pool = ctx;
  return ep >= 0 && ep < pool->n && pool->eligible[ep];
}

static void
test_acquire_any_spills_to_an_endpoint_with_room(void)
{
  fc_state_t fc;
  fc_permit_t held[2], p;
  pool_t pool = { .n = 3, .eligible = { 1, 1, 1 } };
  fc_verdict_t v;

  state_with(&fc, FC_MODE_ENFORCE, 16, 1, 0, 0);
  reset_anomalies();

  /* Endpoints 0 and 1 are full. The selector's pick (0) is over its cap, so
   * the unit lands on 2, the only eligible endpoint with room. */
  for (int i = 0; i < 2; i++) {
    assert(fc_service_acquire(&fc, &held[i]) == FC_ADMIT);
    assert(fc_ep_acquire(&fc, &held[i], i, FC_ROLE_NORMAL) == FC_ADMIT);
  }
  assert(fc_service_acquire(&fc, &p) == FC_ADMIT);
  assert(fc_ep_acquire_any(&fc, &p, FC_ROLE_NORMAL, 0, pool.n,
                           pool_eligible, &pool, &v) == 2);
  assert(v == FC_ADMIT);
  assert(p.ep[FC_ROLE_NORMAL] == 2);
  fc_permit_release(&p);

  /* Every eligible endpoint is full: shed, not "least loaded". */
  pool.eligible[2] = 0;
  assert(fc_service_acquire(&fc, &p) == FC_ADMIT);
  assert(fc_ep_acquire_any(&fc, &p, FC_ROLE_NORMAL, 0, pool.n,
                           pool_eligible, &pool, &v) == -1);
  assert(v == FC_SHED);
  assert(p.ep[FC_ROLE_NORMAL] == -1);
  fc_permit_release(&p);

  /* No eligible endpoint at all is a different answer. */
  pool.eligible[0] = pool.eligible[1] = 0;
  assert(fc_service_acquire(&fc, &p) == FC_ADMIT);
  assert(fc_ep_acquire_any(&fc, &p, FC_ROLE_NORMAL, 0, pool.n,
                           pool_eligible, &pool, &v) == -1);
  assert(v == FC_NO_CAPACITY);
  assert(decisions(&fc, FC_R_NO_HEALTHY_CAPACITY) == 1);
  fc_permit_release(&p);

  fc_permit_release(&held[0]);
  fc_permit_release(&held[1]);
  assert(fc_inflight(&fc) == 0);
  assert(anomalies(FC_A_UNDERFLOW) == 0);
}

/* ---- observe admits and counts, off touches nothing ------------------------- */

static void
test_observe_admits_over_the_ceiling_and_counts_it(void)
{
  fc_state_t fc;
  fc_permit_t p[3];

  state_with(&fc, FC_MODE_OBSERVE, 2, 1, 0, 0);
  for (int i = 0; i < 3; i++) {
    assert(fc_service_acquire(&fc, &p[i]) == FC_ADMIT);
    assert(fc_ep_acquire(&fc, &p[i], 0, FC_ROLE_NORMAL) == FC_ADMIT);
    assert(p[i].state == FC_P_EXECUTING);
  }
  assert(fc_inflight(&fc) == 3);
  assert(fc_ep_inflight(&fc, 0, FC_ROLE_NORMAL) == 3);
  assert(decisions(&fc, FC_R_ADMITTED) == 3);
  /* One service overshoot and two endpoint overshoots would have shed. */
  assert(decisions(&fc, FC_R_OBSERVE_WOULD_SHED) == 3);
  assert(decisions(&fc, FC_R_CAPACITY_SHED) == 0);
  assert(fc_ep_over_cap(&fc, 0, FC_ROLE_NORMAL) == 0);   /* never excludes in observe */
  for (int i = 0; i < 3; i++)
    fc_permit_release(&p[i]);
  assert(fc_inflight(&fc) == 0);
}

static void
test_off_bypasses_without_touching_a_counter(void)
{
  fc_state_t fc;
  fc_permit_t p;

  state_with(&fc, FC_MODE_OFF, 1, 1, 1, 1);
  assert(!fc_active(&fc));
  assert(fc_service_acquire(&fc, &p) == FC_ADMIT);
  assert(p.state == FC_P_BYPASS);
  assert(fc_ep_acquire(&fc, &p, 0, FC_ROLE_NORMAL) == FC_ADMIT);
  assert(fc_inflight(&fc) == 0);
  assert(fc_ep_inflight(&fc, 0, FC_ROLE_NORMAL) == 0);
  for (int r = 0; r < FC_R_COUNT; r++)
    assert(decisions(&fc, r) == 0);
  fc_permit_release(&p);
  assert(p.state == FC_P_RELEASED);
  assert(fc_inflight(&fc) == 0);

  /* Unlimited ceilings under enforce still keep the gauges true. */
  state_with(&fc, FC_MODE_ENFORCE, 0, 0, 0, 0);
  assert(fc_service_acquire(&fc, &p) == FC_ADMIT);
  assert(fc_ep_acquire(&fc, &p, 5, FC_ROLE_NORMAL) == FC_ADMIT);
  assert(fc_inflight(&fc) == 1);
  assert(fc_ep_inflight(&fc, 5, FC_ROLE_NORMAL) == 1);
  fc_permit_release(&p);
  assert(fc_inflight(&fc) == 0);
}

/* ---- a non-inference request holds no unit ----------------------------------- */

static void
test_non_inference_requests_bypass_and_are_counted(void)
{
  fc_state_t fc;
  fc_permit_t p;

  assert(fc_is_inference_request(1, "/v1/chat/completions"));
  assert(fc_is_inference_request(1, "/v1/chat/completions?stream=true"));
  assert(fc_is_inference_request(1, "/v1/completions/"));
  assert(fc_is_inference_request(1, "/v1/embeddings"));
  assert(fc_is_inference_request(1, "/v1/messages"));
  assert(fc_is_inference_request(1, "/v1/responses"));
  assert(fc_is_inference_request(1, "/generate"));
  assert(!fc_is_inference_request(0, "/v1/chat/completions"));   /* GET */
  assert(!fc_is_inference_request(1, "/v1/models"));
  assert(!fc_is_inference_request(1, "/health"));
  assert(!fc_is_inference_request(1, "/v1/chat/completionsx"));
  assert(!fc_is_inference_request(1, ""));
  assert(!fc_is_inference_request(1, NULL));

  state_with(&fc, FC_MODE_ENFORCE, 1, 1, 0, 0);
  fc_bypass(&fc, &p);
  assert(p.state == FC_P_BYPASS);
  assert(fc_inflight(&fc) == 0);
  assert(decisions(&fc, FC_R_BYPASS_NON_INFERENCE) == 1);
  fc_permit_release(&p);
  assert(fc_inflight(&fc) == 0);
}

/* ---- configuration from the environment ------------------------------------ */

static void
test_env_defaults(void)
{
  fc_cfg_t cfg;

  unsetenv("LLB_FC_MODE");
  unsetenv("LLB_FC_MAX_OUTSTANDING");
  unsetenv("LLB_FC_EP_MAX_INFLIGHT");
  unsetenv("LLB_FC_PREFILL_MAX_INFLIGHT");
  unsetenv("LLB_FC_DECODE_MAX_INFLIGHT");
  unsetenv("LLB_PD_MAX_INFLIGHT_PER_EP");
  fc_cfg_from_env(&cfg);
  assert(cfg.mode == FC_MODE_OFF);
  assert(cfg.max_outstanding == 0);

  setenv("LLB_FC_MODE", "Enforce", 1);
  setenv("LLB_FC_MAX_OUTSTANDING", "64", 1);
  setenv("LLB_FC_EP_MAX_INFLIGHT", "8", 1);
  setenv("LLB_PD_MAX_INFLIGHT_PER_EP", "4", 1);
  fc_cfg_from_env(&cfg);
  assert(cfg.mode == FC_MODE_ENFORCE);
  assert(cfg.max_outstanding == 64);
  assert(cfg.ep_cap[FC_ROLE_NORMAL] == 8);
  assert(cfg.ep_cap[FC_ROLE_PREFILL] == 4);    /* inherited from the selector's knob */
  assert(cfg.ep_cap[FC_ROLE_DECODE] == 0);

  setenv("LLB_FC_PREFILL_MAX_INFLIGHT", "2", 1);
  setenv("LLB_FC_MODE", "observe", 1);
  setenv("LLB_FC_MAX_OUTSTANDING", "junk", 1);
  fc_cfg_from_env(&cfg);
  assert(cfg.mode == FC_MODE_OBSERVE);
  assert(cfg.max_outstanding == 0);            /* unparseable reads as unset */
  assert(cfg.ep_cap[FC_ROLE_PREFILL] == 2);    /* the explicit knob wins */

  setenv("LLB_FC_MODE", "yes", 1);
  fc_cfg_from_env(&cfg);
  assert(cfg.mode == FC_MODE_OFF);             /* an unknown mode never enforces by accident */
}

int
main(void)
{
  test_ceilings_hold_under_contention();
  test_release_is_idempotent_and_underflow_is_counted();
  test_two_role_legs_count_one_service_unit();
  test_move_takes_the_new_endpoint_first();
  test_acquire_any_spills_to_an_endpoint_with_room();
  test_observe_admits_over_the_ceiling_and_counts_it();
  test_off_bypasses_without_touching_a_counter();
  test_non_inference_requests_bypass_and_are_counted();
  test_env_defaults();
  printf("test_fc_gate: all passed\n");
  return 0;
}
