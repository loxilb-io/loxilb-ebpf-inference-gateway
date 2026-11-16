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
 * A P/D request that meets a full role ceiling waits at the capacity gate
 * instead of being refused 429 admission_capacity. The legacy prefill count
 * can pass a request whose role ceiling is still full: another request holds
 * the unit and is not counted yet, or the legacy cap is above the ceiling.
 *
 * Driven with the production gate (sp_fc_h1_gate_pd_roles, sp_fc_h1_gate_role
 * and sp_fc_h1_refuse, taken from sockproxy_http.c by the Makefile into
 * test_pd_role_wait.gen.c) and the real sockproxy_fc.c; the connection is a
 * stand-in holding only what those functions read. Checked:
 *   - a full prefill ceiling: the request waits, holds no unit, nothing is
 *     answered or counted as a refusal; the release that frees the unit
 *     wakes it, and it then takes both role units;
 *   - a decode ceiling full after the prefill unit was granted: the prefill
 *     unit goes back while it waits;
 *   - a request moved from the P/D prefill park keeps its first park time:
 *     its deadline and its queue-wait sample count from then, and it takes
 *     its place ahead of a waiter that arrived after it; an eviction it
 *     causes is decided and timed now, and one whose window is over evicts
 *     nobody;
 *   - a pool that does not queue still refuses, as before.
 *
 * Build: make test_pd_role_wait (ASan + UBSan; also run by `make test_fc`).
 */

#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "sockproxy_fc.h"
#include "sockproxy_llmd.h"
#include "sockproxy_obj_hint.h"
#include "sockproxy_corr.h"

#define MS(n) ((uint64_t)(n) * 1000000ULL)

/* ---- the connection, as far as the gate reads it --------------------------- */

typedef struct proxy_fd_ent {
  int fd;
  int odir;
  void *h2_session;
  _Atomic uint64_t gen;
  fc_permit_t fc;
  sp_ttl_hint_t ttl_hint;
  uint8_t adm_class_set, adm_class, adm_objective_denied, adm_hint_not_applied;
  uint8_t auth_src, adm_priority;
  char tenant_id[32], auth_key_id[32], auth_user_id[32], l7_peer_ip[32];
  char auth_net_identity[32], adm_objective[32];
  sp_corr_cap_t http_corr;
} proxy_fd_ent_t;

typedef struct proxy_epval {
  fc_state_t fc;
} proxy_epval_t;

#define SP_FC_H1_REFUSED (-1)
#define SP_FC_H1_QUEUED  (-2)
#define SP_FC_H1_KEPT    (-3)

/* ---- what the gate calls besides the pool ----------------------------------- */

static uint64_t clock_ns;
static uint64_t qos_now_ns(void) { return clock_ns; }
#define log_debug(...) ((void)0)

static int sent, sent_status, denies;
static char sent_code[48];

static int
sp_h1_refusal_keeps_connection(proxy_fd_ent_t *pfe)
{
  (void)pfe;
  return 0;
}

static void
proxy_pfe_svc_ident(proxy_fd_ent_t *pfe, char *out, size_t n)
{
  (void)pfe;
  snprintf(out, n, "svc");
}

static int
sp_h1_send_capacity_deny(proxy_fd_ent_t *pfe, int status, const char *code,
                         const char *msg, uint32_t inflight, uint32_t queued,
                         uint32_t limit, uint32_t retry_after, int keep,
                         const char *cls, uint32_t band_wait_ms,
                         const char *dropped_reason)
{
  (void)pfe; (void)msg; (void)inflight; (void)queued; (void)limit;
  (void)retry_after; (void)keep; (void)cls; (void)band_wait_ms;
  (void)dropped_reason;
  sent++;
  sent_status = status;
  snprintf(sent_code, sizeof(sent_code), "%s", code);
  return 0;
}

/* The refusal's correlation (sockproxy_http.c): not under test here. */
static ai_corr_t *proxy_refusal_corr(const proxy_fd_ent_t *pfe) { (void)pfe; return NULL; }
#undef AI_GW_CLASS_INFO
#define AI_GW_CLASS_INFO(a, b, c, d) 0

/* The refusal's deny record: counted, with its status and code. */
static void
ai_gw_record_capacity_deny(const char *request_id, int producer_id,
                           const char *svc_ident, const char *model,
                           const char *tenant_id, const char *key_id,
                           const char *user_id, int http_status,
                           const char *error_code,
                           const char *client_ip, const char *origin_ip,
                           int trusted_hops, int auth_src,
                           const char *net_identity,
                           int priority, int class_info,
                           const char *objective, const ai_corr_t *corr)
{
  (void)corr;
  (void)request_id; (void)producer_id; (void)svc_ident; (void)model;
  (void)tenant_id; (void)key_id; (void)user_id; (void)client_ip;
  (void)origin_ip; (void)trusted_hops; (void)auth_src; (void)net_identity;
  (void)priority; (void)class_info; (void)objective;
  assert(http_status == sent_status && !strcmp(error_code, sent_code));
  denies++;
}

static const char *proxy_request_id(proxy_fd_ent_t *p) { (void)p; return "rid"; }
static int notify_worker_id(void) { return 0; }
static const char *proxy_effective_model(proxy_fd_ent_t *p) { (void)p; return "m"; }
static const char *proxy_origin_ip(proxy_fd_ent_t *p) { return p->l7_peer_ip; }
static int proxy_origin_trusted_hops(proxy_fd_ent_t *p) { (void)p; return 0; }
static void cresp_note_local_answer(proxy_fd_ent_t *p) { (void)p; }
static void sp_h1_kept_request_reset(proxy_fd_ent_t *p) { (void)p; }

#include "test_pd_role_wait.gen.c"

/* ---- fixtures ------------------------------------------------------------- */

static int woken_fd = -1, woken_n;

static int
note_wake(int fd, uint64_t gen)
{
  (void)gen;
  woken_fd = fd;
  woken_n++;
  return 0;
}

/* One pool: service ceiling `svc`, per-endpoint role ceilings, a queue of
 * `depth` with a 5 s window. */
static int shed_queue;

static void
pool(proxy_epval_t *ev, uint32_t svc, uint32_t prefill, uint32_t decode,
     uint32_t depth)
{
  fc_cfg_t cfg = {0};

  memset(ev, 0, sizeof(*ev));
  pthread_mutex_init(&ev->fc.queue.lock, NULL);
  cfg.mode = FC_MODE_ENFORCE;
  cfg.max_outstanding = svc;
  cfg.ep_cap[FC_ROLE_PREFILL] = prefill;
  cfg.ep_cap[FC_ROLE_DECODE] = decode;
  cfg.max_queue_depth = depth;
  cfg.max_queue_wait_ms = 5000;
  cfg.wake_policy = FC_WAKE_STRICT;
  cfg.shed_queue = shed_queue;
  fc_state_apply(&ev->fc, &cfg);
  /* The pool reads the same clock the gate pushes with. */
  fc_set_clock(qos_now_ns);
  fc_set_wake_hook(note_wake);
  woken_fd = -1;
  woken_n = 0;
  sent = denies = 0;
}

static void
conn(proxy_fd_ent_t *c, int fd)
{
  memset(c, 0, sizeof(*c));
  c->fd = fd;
  atomic_store(&c->gen, 1);
  fc_permit_init(&c->fc);
}

/* The service unit, as sp_fc_h1_gate_service takes it. */
static fc_verdict_t
service_band(proxy_epval_t *ev, proxy_fd_ent_t *c, int woken, uint8_t band)
{
  return fc_service_acquire_h1_band(&ev->fc, &c->fc, woken,
                                    fc_tenant_key(NULL), band);
}

static fc_verdict_t
service(proxy_epval_t *ev, proxy_fd_ent_t *c, int woken)
{
  return service_band(ev, c, woken, FC_BAND_STANDARD);
}

static uint64_t
dec(const fc_state_t *fc, enum fc_reason r)
{
  return atomic_load(&fc->decisions[r]);
}

/* A P/D request that holds the prefill unit on endpoint 0 and the decode
 * unit on endpoint 1. */
static void
running(proxy_epval_t *ev, proxy_fd_ent_t *a)
{
  assert(service(ev, a, 0) == FC_ADMIT);
  assert(sp_fc_h1_gate_pd_roles(a, ev, 0, 1) == 0);
  assert(a->fc.ep[FC_ROLE_PREFILL] == 0 && a->fc.ep[FC_ROLE_DECODE] == 1);
}

/* ---- the prefill ceiling full: wait, then both units ------------------------ */

static void
test_prefill_full_waits(void)
{
  proxy_epval_t ev;
  proxy_fd_ent_t a, b;

  pool(&ev, 2, 1, 2, 4);
  conn(&a, 10);
  conn(&b, 11);
  clock_ns = MS(3000);
  running(&ev, &a);

  /* B passed the legacy count after its prefill park (started at 1 s) and
   * meets the prefill ceiling A holds. */
  assert(service(&ev, &b, 0) == FC_ADMIT);
  b.fc.q_first_ns = MS(1000);
  uint64_t shed0 = dec(&ev.fc, FC_R_CAPACITY_SHED);
  assert(sp_fc_h1_gate_pd_roles(&b, &ev, 0, 1) == SP_FC_H1_QUEUED);
  assert(b.fc.state == FC_P_QUEUED);
  assert(b.fc.svc_held == 0);
  assert(b.fc.ep[FC_ROLE_PREFILL] == -1 && b.fc.ep[FC_ROLE_DECODE] == -1);
  assert(fc_inflight(&ev.fc) == 1);
  assert(fc_ep_inflight(&ev.fc, 0, FC_ROLE_PREFILL) == 1);
  assert(sent == 0 && denies == 0);
  assert(dec(&ev.fc, FC_R_CAPACITY_SHED) == shed0);
  /* Its wait counts from the first park: place, deadline, sample. */
  assert(b.fc.q_enqueue_ns == MS(1000));
  assert(b.fc.q_deadline_ns == MS(1000) + MS(5000));
  assert(b.fc.q_first_ns == 0);
  assert(fc_queued(&ev.fc) == 1);

  /* A ends: its release wakes B. */
  clock_ns = MS(4000);
  fc_permit_release(&a.fc);
  assert(woken_n == 1 && woken_fd == b.fd);
  assert(fc_queue_owner_resume(&ev.fc, &b.fc, clock_ns) == FC_RESUME_TURN);
  /* The dispatch driven again: the service gate, then both roles. The one
   * queue-wait sample is taken at the first role unit (the admission),
   * counted from the first park. */
  assert(service(&ev, &b, 1) == FC_ADMIT);
  assert(sp_fc_h1_gate_pd_roles(&b, &ev, 0, 1) == 0);
  assert(atomic_load(&ev.fc.qwait_count) == 1);
  assert(atomic_load(&ev.fc.qwait_sum_ms) == 3000);
  assert(b.fc.ep[FC_ROLE_PREFILL] == 0 && b.fc.ep[FC_ROLE_DECODE] == 1);
  assert(fc_ep_inflight(&ev.fc, 0, FC_ROLE_PREFILL) == 1);
  assert(sent == 0 && denies == 0);
  fc_permit_release(&b.fc);
  assert(fc_inflight(&ev.fc) == 0);
  assert(fc_ep_inflight(&ev.fc, 0, FC_ROLE_PREFILL) == 0);
  assert(fc_ep_inflight(&ev.fc, 1, FC_ROLE_DECODE) == 0);
  fc_state_destroy(&ev.fc);
}

/* ---- the decode ceiling full after the prefill unit was granted -------------- */

static void
test_decode_full_holds_nothing(void)
{
  proxy_epval_t ev;
  proxy_fd_ent_t a, b;

  pool(&ev, 2, 2, 1, 4);
  conn(&a, 20);
  conn(&b, 21);
  clock_ns = MS(1000);
  running(&ev, &a);

  assert(service(&ev, &b, 0) == FC_ADMIT);
  assert(sp_fc_h1_gate_pd_roles(&b, &ev, 0, 1) == SP_FC_H1_QUEUED);
  assert(b.fc.ep[FC_ROLE_PREFILL] == -1 && b.fc.ep[FC_ROLE_DECODE] == -1);
  assert(fc_ep_inflight(&ev.fc, 0, FC_ROLE_PREFILL) == 1);   /* A's only */
  assert(fc_ep_inflight(&ev.fc, 1, FC_ROLE_DECODE) == 1);
  assert(fc_inflight(&ev.fc) == 1);
  /* No first park: the wait starts now. */
  assert(b.fc.q_enqueue_ns == MS(1000));
  assert(sent == 0);

  fc_permit_release(&a.fc);
  assert(woken_fd == b.fd);
  assert(fc_queue_owner_resume(&ev.fc, &b.fc, clock_ns) == FC_RESUME_TURN);
  assert(service(&ev, &b, 1) == FC_ADMIT);
  assert(sp_fc_h1_gate_pd_roles(&b, &ev, 0, 1) == 0);
  fc_permit_release(&b.fc);
  assert(fc_inflight(&ev.fc) == 0);
  fc_state_destroy(&ev.fc);
}

/* ---- the first park decides the place among the waiters --------------------- */

static void
test_first_park_keeps_its_place(void)
{
  proxy_epval_t ev;
  proxy_fd_ent_t a, y, z, w;

  pool(&ev, 4, 1, 4, 4);
  conn(&a, 30);
  conn(&y, 31);
  conn(&z, 32);
  conn(&w, 33);
  clock_ns = MS(1000);
  running(&ev, &a);
  /* Each holds its service unit before anyone waits: Z and W as requests
   * resumed from the prefill park hold theirs (taken on their first pass). */
  assert(service(&ev, &y, 0) == FC_ADMIT);
  assert(service(&ev, &z, 0) == FC_ADMIT);
  assert(service(&ev, &w, 0) == FC_ADMIT);

  /* Y meets the prefill ceiling at 2 s, never parked before. */
  clock_ns = MS(2000);
  assert(sp_fc_h1_gate_pd_roles(&y, &ev, 0, 1) == SP_FC_H1_QUEUED);
  /* Z meets it at 3 s, after a prefill park that began at 1 s: it goes in
   * ahead of Y. */
  clock_ns = MS(3000);
  z.fc.q_first_ns = MS(1000);
  assert(sp_fc_h1_gate_pd_roles(&z, &ev, 0, 1) == SP_FC_H1_QUEUED);
  assert(z.fc.q_enqueue_ns == MS(1000));
  /* A first park "later" than now is not a first park: W waits from now,
   * behind both. */
  w.fc.q_first_ns = MS(9000);
  assert(sp_fc_h1_gate_pd_roles(&w, &ev, 0, 1) == SP_FC_H1_QUEUED);
  assert(w.fc.q_enqueue_ns == MS(3000));
  assert(fc_queued(&ev.fc) == 3);

  /* Each release wakes the earliest arrival. */
  fc_permit_release(&a.fc);
  assert(woken_fd == z.fd);
  assert(fc_queue_owner_resume(&ev.fc, &z.fc, clock_ns) == FC_RESUME_TURN);
  assert(service(&ev, &z, 1) == FC_ADMIT);
  assert(sp_fc_h1_gate_pd_roles(&z, &ev, 0, 1) == 0);
  fc_permit_release(&z.fc);
  assert(woken_fd == y.fd);
  assert(fc_queue_owner_resume(&ev.fc, &y.fc, clock_ns) == FC_RESUME_TURN);
  assert(service(&ev, &y, 1) == FC_ADMIT);
  assert(sp_fc_h1_gate_pd_roles(&y, &ev, 0, 1) == 0);
  fc_permit_release(&y.fc);
  assert(woken_fd == w.fd);
  assert(fc_queue_owner_resume(&ev.fc, &w.fc, clock_ns) == FC_RESUME_TURN);
  assert(service(&ev, &w, 1) == FC_ADMIT);
  assert(sp_fc_h1_gate_pd_roles(&w, &ev, 0, 1) == 0);
  fc_permit_release(&w.fc);
  assert(fc_inflight(&ev.fc) == 0 && fc_queued(&ev.fc) == 0);
  fc_state_destroy(&ev.fc);
}

/* ---- what a moved request does to the others is decided now ------------------ */

static void
test_first_park_evicts_now(void)
{
  proxy_epval_t ev;
  proxy_fd_ent_t a, s, z, x;

  shed_queue = 1;                /* sheddable waits, and may be evicted */
  pool(&ev, 4, 1, 4, 1);
  shed_queue = 0;
  conn(&a, 50);
  conn(&s, 51);
  conn(&z, 52);
  conn(&x, 53);
  clock_ns = MS(8000);
  running(&ev, &a);
  assert(service_band(&ev, &s, 0, FC_BAND_SHEDDABLE) == FC_ADMIT);
  assert(service(&ev, &z, 0) == FC_ADMIT);
  assert(service(&ev, &x, 0) == FC_ADMIT);
  /* A sheddable request waits from 8 s; the queue (depth 1) is full. */
  assert(sp_fc_h1_gate_pd_roles(&s, &ev, 0, 1) == SP_FC_H1_QUEUED);

  /* X first parked at 1 s: its 5 s window is over, so it takes nobody's
   * place; the full queue refuses it. */
  clock_ns = MS(10000);
  x.fc.q_first_ns = MS(1000);
  assert(sp_fc_h1_gate_pd_roles(&x, &ev, 0, 1) == SP_FC_H1_REFUSED);
  assert(sent == 1 && sent_status == 429);
  assert(s.fc.state == FC_P_QUEUED && fc_queue_evicted(&ev.fc) == 0);
  /* X's refusal handed its service unit back and woke S; S meets the
   * prefill ceiling again and goes back to the head, its wait unchanged. */
  assert(woken_fd == s.fd);
  assert(fc_queue_owner_resume(&ev.fc, &s.fc, clock_ns) == FC_RESUME_TURN);
  assert(service_band(&ev, &s, 1, FC_BAND_SHEDDABLE) == FC_ADMIT);
  assert(sp_fc_h1_gate_pd_roles(&s, &ev, 0, 1) == SP_FC_H1_QUEUED);
  assert(s.fc.q_enqueue_ns == MS(8000) && fc_queued(&ev.fc) == 1);

  /* Z first parked at 9 s, in its window: it evicts the sheddable waiter
   * now. The eviction is timed at 10 s (the owner's grace runs from it)
   * and the evicted wait is 2 s, not the 1 s a backdated clock gives. */
  z.fc.q_first_ns = MS(9000);
  uint64_t sum0 = atomic_load(&ev.fc.qwait_sum_ms);
  assert(sp_fc_h1_gate_pd_roles(&z, &ev, 0, 1) == SP_FC_H1_QUEUED);
  assert(z.fc.q_enqueue_ns == MS(9000));
  assert(fc_queue_evicted(&ev.fc) == 1);
  assert(ev.fc.queue.evicted[0].at_ns == MS(10000));
  assert(atomic_load(&ev.fc.qwait_sum_ms) - sum0 == 2000);
  (void)fc_queue_owner_resume(&ev.fc, &s.fc, clock_ns);

  fc_permit_release(&a.fc);
  assert(woken_fd == z.fd);
  assert(fc_queue_owner_resume(&ev.fc, &z.fc, clock_ns) == FC_RESUME_TURN);
  assert(service(&ev, &z, 1) == FC_ADMIT);
  assert(sp_fc_h1_gate_pd_roles(&z, &ev, 0, 1) == 0);
  fc_permit_release(&z.fc);
  fc_permit_release(&s.fc);
  fc_permit_release(&x.fc);
  assert(fc_inflight(&ev.fc) == 0);
  fc_state_destroy(&ev.fc);
}

/* ---- a pool that does not queue refuses, as before --------------------------- */

static void
test_no_queue_refuses(void)
{
  proxy_epval_t ev;
  proxy_fd_ent_t a, b;

  pool(&ev, 2, 1, 2, 0);
  conn(&a, 40);
  conn(&b, 41);
  clock_ns = MS(1000);
  running(&ev, &a);

  assert(service(&ev, &b, 0) == FC_ADMIT);
  assert(sp_fc_h1_gate_pd_roles(&b, &ev, 0, 1) == SP_FC_H1_REFUSED);
  assert(sent == 1 && sent_status == 429 && !strcmp(sent_code, "admission_capacity"));
  assert(denies == 1);
  assert(b.fc.svc_held == 0 && fc_inflight(&ev.fc) == 1);
  fc_permit_release(&a.fc);
  assert(fc_inflight(&ev.fc) == 0);
  fc_state_destroy(&ev.fc);
}

int
main(void)
{
  test_prefill_full_waits();
  test_decode_full_holds_nothing();
  test_first_park_keeps_its_place();
  test_first_park_evicts_now();
  test_no_queue_refuses();
  printf("test_pd_role_wait: all passed\n");
  return 0;
}
