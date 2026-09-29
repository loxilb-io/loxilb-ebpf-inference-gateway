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
 * The tenant share of the capacity gate, driven alone: the bounds a share
 * gives, a tenant held to its share of the executing units and of the queue
 * while other tenants still admit, a waiting tenant that cannot run never
 * holding up one that can (neither at the gate nor at the wake), every exit
 * handing its tenant's count back, the keyless pseudo-tenant, the bounded
 * tenant table, and a pool without a share left exactly as it was.
 *
 * Build: make test_fc_tenant (also run by `make test_fc`).
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sockproxy_fc.h"

#define MS(n) ((uint64_t)(n) * 1000000ULL)

static uint64_t
decisions(const fc_state_t *fc, enum fc_reason r)
{
  return atomic_load(&fc->decisions[r]);
}

static void
pool_share(fc_state_t *fc, uint8_t mode, uint32_t max_out, uint32_t depth,
           uint8_t pct)
{
  fc_cfg_t cfg = {0};

  memset(fc, 0, sizeof(*fc));
  pthread_mutex_init(&fc->queue.lock, NULL);
  cfg.mode = mode;
  cfg.max_outstanding = max_out;
  cfg.max_queue_depth = depth;
  cfg.max_queue_wait_ms = depth ? 5000 : 0;
  cfg.tenant_share_pct = pct;
  fc_state_apply(fc, &cfg);
}

static int woken_fd[256];
static int woken_n;

static int
record_wake(int fd, uint64_t gen)
{
  (void)gen;
  assert(woken_n < 256);
  woken_fd[woken_n++] = fd;
  return 0;
}

static uint64_t KA, KB, KC;

/* The HTTP/1 site: admit (and take the endpoint unit), or park, or refuse. */
static fc_verdict_t
gate(fc_state_t *fc, fc_permit_t *p, uint64_t tkey, int fd, int woken)
{
  fc_verdict_t v = fc_service_acquire_h1_tenant(fc, p, woken, tkey);
  int rc;

  if (v == FC_ADMIT) {
    if (p->state == FC_P_EXECUTING)
      assert(fc_ep_acquire(fc, p, 0, FC_ROLE_NORMAL) == FC_ADMIT);
    return v;
  }
  if (v == FC_QUEUE) {
    rc = fc_queue_push(fc, p, fd, 1, MS(1000) + (uint64_t)fd, woken);
    if (rc == 0)
      return FC_QUEUE;
    return rc == -2 ? FC_TENANT_SHARE : FC_SHED;
  }
  if (v == FC_TENANT_SHARE)
    fc_count(fc, FC_R_TENANT_SHARE);
  return v;
}

/* ---- bounds ------------------------------------------------------------------ */

static void
test_bounds(void)
{
  fc_state_t fc;

  pool_share(&fc, FC_MODE_ENFORCE, 10, 10, 30);
  assert(fc_share_active(&fc));
  assert(fc_tenant_svc_bound(&fc) == 3);
  assert(fc_tenant_queue_bound(&fc) == 3);
  fc_state_destroy(&fc);

  /* Rounded up, never below one. */
  pool_share(&fc, FC_MODE_ENFORCE, 3, 1, 10);
  assert(fc_tenant_svc_bound(&fc) == 1);
  assert(fc_tenant_queue_bound(&fc) == 1);
  fc_state_destroy(&fc);

  /* An unlimited service has no share of it to give. */
  pool_share(&fc, FC_MODE_ENFORCE, 0, 0, 50);
  assert(fc_tenant_svc_bound(&fc) == 0);
  assert(fc_tenant_queue_bound(&fc) == 0);
  fc_state_destroy(&fc);

  /* 0 and 100 are no share at all. */
  pool_share(&fc, FC_MODE_ENFORCE, 10, 10, 100);
  assert(!fc_share_active(&fc));
  fc_state_destroy(&fc);
  pool_share(&fc, FC_MODE_ENFORCE, 10, 10, 0);
  assert(!fc_share_active(&fc));
  fc_state_destroy(&fc);

  /* The share follows the adaptive ceiling in force, not the configured one. */
  pool_share(&fc, FC_MODE_ENFORCE, 10, 0, 50);
  fc.cfg.adaptive = 1;
  atomic_store(&fc.eff_max, 4);
  assert(fc_tenant_svc_bound(&fc) == 2);
  fc_state_destroy(&fc);
  printf("  bounds: rounded up to at least one, inert when unlimited, off at 0/100, adaptive-aware\n");
}

static void
test_config_resolves(void)
{
  fc_cfg_t env, out, other;
  fc_rule_cfg_t rule = {0};

  setenv("LLB_FC_TENANT_MAX_SHARE_PCT", "40", 1);
  fc_cfg_from_env(&env);
  assert(env.tenant_share_pct == 40 && env.src[FC_L_TENANT_SHARE] == FC_SRC_ENV);
  setenv("LLB_FC_TENANT_MAX_SHARE_PCT", "101", 1);
  fc_cfg_from_env(&env);
  assert(env.tenant_share_pct == 0 && env.src[FC_L_TENANT_SHARE] == FC_SRC_DEFAULT);
  unsetenv("LLB_FC_TENANT_MAX_SHARE_PCT");
  fc_cfg_from_env(&env);
  assert(env.tenant_share_pct == 0);

  rule.tenant_share_pct = 25;
  fc_cfg_resolve(&out, &env, &rule);
  assert(out.tenant_share_pct == 25 && out.src[FC_L_TENANT_SHARE] == FC_SRC_RULE);
  rule.tenant_share_pct = 100;                  /* a rule may say "no share" */
  fc_cfg_resolve(&other, &env, &rule);
  assert(other.tenant_share_pct == 100);
  assert(!fc_cfg_equal(&out, &other));
  rule.tenant_share_pct = 0;                    /* inherit */
  fc_cfg_resolve(&other, &env, &rule);
  assert(other.src[FC_L_TENANT_SHARE] == FC_SRC_DEFAULT);
  printf("  config: env and rule resolve with their source; a change is a change\n");
}

/* ---- the share ----------------------------------------------------------------- */

/* The plan's case: A floods, B still gets in. */
static void
test_a_flood_leaves_room_for_b(void)
{
  fc_state_t fc;
  fc_permit_t a[4], b[3], c;

  pool_share(&fc, FC_MODE_ENFORCE, 4, 0, 50);
  woken_n = 0;
  assert(gate(&fc, &a[0], KA, 1, 0) == FC_ADMIT);
  assert(gate(&fc, &a[1], KA, 2, 0) == FC_ADMIT);
  assert(gate(&fc, &a[2], KA, 3, 0) == FC_TENANT_SHARE);   /* A at its share */
  assert(gate(&fc, &a[3], KA, 4, 0) == FC_TENANT_SHARE);
  assert(decisions(&fc, FC_R_TENANT_SHARE) == 2);
  assert(fc_inflight(&fc) == 2);
  assert(gate(&fc, &b[0], KB, 5, 0) == FC_ADMIT);          /* B is not held */
  assert(gate(&fc, &b[1], KB, 6, 0) == FC_ADMIT);
  assert(gate(&fc, &b[2], KB, 7, 0) == FC_TENANT_SHARE);
  assert(fc_tenants_active(&fc) == 2);
  /* The service is full: a third tenant meets the service ceiling. */
  assert(gate(&fc, &c, KC, 8, 0) == FC_SHED);
  /* A unit A hands back is A's again. */
  fc_permit_release(&a[0]);
  assert(gate(&fc, &a[2], KA, 3, 0) == FC_ADMIT);
  fc_permit_release(&a[1]);
  fc_permit_release(&a[2]);
  fc_permit_release(&b[0]);
  fc_permit_release(&b[1]);
  assert(fc_inflight(&fc) == 0);
  assert(fc_tenants_active(&fc) == 0);                     /* evicted at zero */
  fc_state_destroy(&fc);
  printf("  share: A flooded to its share and was refused; B still admitted\n");
}

/* A tenant holds at most its share of the queue too, and a waiting tenant
 * that cannot run does not make an under-share newcomer wait behind it. */
static void
test_queue_share_and_no_hol_at_the_gate(void)
{
  fc_state_t fc;
  fc_permit_t a[4], b, c;

  /* ceiling 2, depth 4, 50%: one unit and two queue slots per tenant */
  pool_share(&fc, FC_MODE_ENFORCE, 2, 4, 50);
  woken_n = 0;
  fc_set_wake_hook(record_wake);
  assert(gate(&fc, &a[0], KA, 1, 0) == FC_ADMIT);
  assert(gate(&fc, &a[1], KA, 2, 0) == FC_QUEUE);
  assert(gate(&fc, &a[2], KA, 3, 0) == FC_QUEUE);
  assert(gate(&fc, &a[3], KA, 4, 0) == FC_TENANT_SHARE);   /* A's queue share */
  assert(decisions(&fc, FC_R_TENANT_SHARE) == 1);
  assert(decisions(&fc, FC_R_QUEUE_FULL) == 0);
  assert(fc_queued(&fc) == 2);
  /* Every waiter is A, and A is at its share: B takes the free unit. */
  assert(gate(&fc, &b, KB, 5, 0) == FC_ADMIT);
  assert(fc_inflight(&fc) == 2);
  /* The service is now full: C waits. */
  assert(gate(&fc, &c, KC, 6, 0) == FC_QUEUE);
  assert(fc_queued(&fc) == 3);
  fc_set_wake_hook(NULL);
  fc_permit_release(&b);
  fc_permit_release(&a[0]);
  fc_permit_release(&a[1]);                   /* cancelled while waiting */
  fc_permit_release(&a[2]);
  fc_permit_release(&c);
  assert(fc_queued(&fc) == 0 && fc_inflight(&fc) == 0);
  assert(fc_tenants_active(&fc) == 0);
  fc_state_destroy(&fc);
  printf("  queue: A held to its queue share; B not held behind A's waiters\n");
}

/* The wake skips a waiter whose tenant is at its share: the unit goes to
 * the first waiter that can run, and the skipped ones keep their order. */
static void
test_wake_skips_an_over_share_head(void)
{
  fc_state_t fc;
  fc_permit_t a0, a1, a2, b, c;

  pool_share(&fc, FC_MODE_ENFORCE, 2, 4, 50);
  woken_n = 0;
  fc_set_wake_hook(record_wake);
  assert(gate(&fc, &a0, KA, 1, 0) == FC_ADMIT);
  assert(gate(&fc, &a1, KA, 2, 0) == FC_QUEUE);
  assert(gate(&fc, &a2, KA, 3, 0) == FC_QUEUE);
  assert(gate(&fc, &b, KB, 5, 0) == FC_ADMIT);
  assert(gate(&fc, &c, KC, 6, 0) == FC_QUEUE);
  /* B finishes: A (at its share) heads the queue, C is behind it. */
  fc_permit_release(&b);
  assert(woken_n == 1 && woken_fd[0] == 6);
  assert(fc_queued(&fc) == 2);
  fc_queue_resumed(&fc, &c, MS(2000));
  assert(gate(&fc, &c, KC, 6, 1) == FC_ADMIT);
  /* A's own unit comes back: now A's head waiter is the one that can run. */
  fc_permit_release(&a0);
  assert(woken_n == 2 && woken_fd[1] == 2);
  fc_queue_resumed(&fc, &a1, MS(2000));
  assert(gate(&fc, &a1, KA, 2, 1) == FC_ADMIT);
  /* A is at its share again; nothing wakes for it while C holds a unit. */
  assert(fc_queued(&fc) == 1);
  fc_queue_wake_one(&fc);
  assert(woken_n == 2);
  fc_permit_release(&c);                        /* a unit, but A is at share */
  assert(woken_n == 2 && fc_queued(&fc) == 1);
  fc_permit_release(&a1);
  assert(woken_n == 3 && woken_fd[2] == 3);
  fc_queue_resumed(&fc, &a2, MS(2000));
  assert(gate(&fc, &a2, KA, 3, 1) == FC_ADMIT);
  fc_permit_release(&a2);
  fc_set_wake_hook(NULL);
  assert(fc_inflight(&fc) == 0 && fc_queued(&fc) == 0);
  assert(fc_tenants_active(&fc) == 0);
  fc_state_destroy(&fc);
  printf("  wake: an over-share head was skipped; the unit went to the next that could run\n");
}

/* Every way out of the queue hands the tenant's queue slot back: the
 * deadline's take, a drain, and a cancellation. */
static int
drain_all(void *ctx, const fc_queue_ent_t *e)
{
  (void)ctx;
  (void)e;
  return 1;
}

static void
test_every_exit_gives_the_slot_back(void)
{
  fc_state_t fc;
  fc_permit_t a0, a1, a2, b0, b1;

  pool_share(&fc, FC_MODE_ENFORCE, 2, 4, 50);
  woken_n = 0;
  assert(gate(&fc, &a0, KA, 1, 0) == FC_ADMIT);
  assert(gate(&fc, &b0, KB, 2, 0) == FC_ADMIT);
  assert(gate(&fc, &a1, KA, 3, 0) == FC_QUEUE);
  assert(gate(&fc, &a2, KA, 4, 0) == FC_QUEUE);
  assert(gate(&fc, &b1, KB, 5, 0) == FC_QUEUE);
  /* The deadline takes a1: A has one queue slot free again. */
  assert(fc_queue_take(&fc, &a1) == 1);
  fc_permit_init(&a1);
  assert(gate(&fc, &a1, KA, 6, 0) == FC_QUEUE);
  /* A cancellation. */
  fc_permit_release(&a2);
  assert(decisions(&fc, FC_R_CANCELLED) == 1);
  /* A drain takes the rest. */
  fc_queue_drain(&fc, drain_all, NULL);
  assert(fc_queued(&fc) == 0);
  fc_permit_init(&a1);
  fc_permit_init(&b1);
  fc_permit_release(&a0);
  fc_permit_release(&b0);
  assert(fc_tenants_active(&fc) == 0);
  assert(atomic_load(&fc_anomaly_total[FC_A_UNDERFLOW]) == 0);
  fc_state_destroy(&fc);
  printf("  exits: deadline, cancel and drain each gave the tenant's slot back\n");
}

/* Requests with no tenant are one pseudo-tenant, held to one share. */
static void
test_keyless_is_one_tenant(void)
{
  fc_state_t fc;
  fc_permit_t k[3], b;
  uint64_t none = fc_tenant_key("");

  assert(fc_tenant_key(NULL) == none);
  assert(none != KA && KA != KB);
  pool_share(&fc, FC_MODE_ENFORCE, 4, 0, 50);
  assert(gate(&fc, &k[0], none, 1, 0) == FC_ADMIT);
  assert(gate(&fc, &k[1], none, 2, 0) == FC_ADMIT);
  assert(gate(&fc, &k[2], none, 3, 0) == FC_TENANT_SHARE);
  /* The legacy entry points are the pseudo-tenant too. */
  assert(fc_service_acquire(&fc, &b) == FC_TENANT_SHARE);
  assert(gate(&fc, &b, KB, 4, 0) == FC_ADMIT);
  fc_permit_release(&k[0]);
  fc_permit_release(&k[1]);
  fc_permit_release(&b);
  assert(fc_tenants_active(&fc) == 0);
  fc_state_destroy(&fc);
  printf("  keyless: no tenant id is one pseudo-tenant under the same share\n");
}

/* The table is bounded: tenants past it share one overflow budget. */
static void
test_table_full_shares_the_overflow(void)
{
  fc_state_t fc;
  fc_permit_t p[FC_TENANT_SLOTS + 3];
  char id[32];
  uint64_t before = atomic_load(&fc_anomaly_total[FC_A_TENANT_TABLE_FULL]);
  int n = FC_TENANT_SLOTS + 3;

  /* ceiling 1000 at 1%: ten units per tenant */
  pool_share(&fc, FC_MODE_ENFORCE, 1000, 0, 1);
  assert(fc_tenant_svc_bound(&fc) == 10);
  for (int i = 0; i < n; i++) {
    snprintf(id, sizeof(id), "tenant-%d", i);
    assert(gate(&fc, &p[i], fc_tenant_key(id), i + 1, 0) == FC_ADMIT);
  }
  assert(fc_tenants_active(&fc) == FC_TENANT_SLOTS + 1);
  assert(atomic_load(&fc_anomaly_total[FC_A_TENANT_TABLE_FULL]) == before + 3);
  for (int i = 0; i < n; i++)
    fc_permit_release(&p[i]);
  assert(fc_tenants_active(&fc) == 0 && fc_inflight(&fc) == 0);
  /* Freed slots are taken again by new tenants. */
  assert(gate(&fc, &p[0], KC, 1, 0) == FC_ADMIT);
  assert(fc_tenants_active(&fc) == 1);
  fc_permit_release(&p[0]);
  fc_state_destroy(&fc);
  printf("  table: %d tenants past the table shared the overflow slot, counted\n", 3);
}

/* Observe mode admits over-share requests and counts what it would do. */
static void
test_observe_counts_and_admits(void)
{
  fc_state_t fc;
  fc_permit_t a[3];

  pool_share(&fc, FC_MODE_OBSERVE, 4, 0, 50);
  for (int i = 0; i < 3; i++)
    assert(gate(&fc, &a[i], KA, i + 1, 0) == FC_ADMIT);
  assert(decisions(&fc, FC_R_OBSERVE_WOULD_SHED) == 1);
  assert(decisions(&fc, FC_R_TENANT_SHARE) == 0);
  for (int i = 0; i < 3; i++)
    fc_permit_release(&a[i]);
  assert(fc_tenants_active(&fc) == 0);
  fc_state_destroy(&fc);
  printf("  observe: over share admitted and counted as would-shed\n");
}

/* A pool without a share keeps no tenant state and keeps strict FIFO. */
static void
test_no_share_is_unchanged(void)
{
  fc_state_t fc;
  fc_permit_t a[3], b;

  pool_share(&fc, FC_MODE_ENFORCE, 2, 4, 0);
  assert(gate(&fc, &a[0], KA, 1, 0) == FC_ADMIT);
  assert(gate(&fc, &a[1], KA, 2, 0) == FC_ADMIT);
  assert(gate(&fc, &a[2], KA, 3, 0) == FC_QUEUE);
  assert(gate(&fc, &b, KB, 4, 0) == FC_QUEUE);            /* strict FIFO */
  assert(fc_tenants_active(&fc) == 0);
  assert(a[0].tslot < 0);
  fc_permit_release(&a[0]);
  fc_permit_release(&a[1]);
  fc_permit_release(&a[2]);
  fc_permit_release(&b);
  fc_state_destroy(&fc);
  printf("  off: no share, no tenant state, strict FIFO as before\n");
}

/* A share turned off while tenants hold units: their counts still come back. */
static void
test_share_turned_off_under_load(void)
{
  fc_state_t fc;
  fc_permit_t a;
  fc_cfg_t cfg;

  pool_share(&fc, FC_MODE_ENFORCE, 4, 0, 50);
  assert(gate(&fc, &a, KA, 1, 0) == FC_ADMIT);
  assert(fc_tenants_active(&fc) == 1);
  cfg = fc.cfg;
  cfg.tenant_share_pct = 0;
  fc_state_apply(&fc, &cfg);
  fc_permit_release(&a);
  assert(fc_tenants_active(&fc) == 0);
  assert(atomic_load(&fc_anomaly_total[FC_A_UNDERFLOW]) == 0);
  fc_state_destroy(&fc);
  printf("  reconfigure: a share turned off under load still settled its tenants\n");
}

int
main(void)
{
  KA = fc_tenant_key("tenant-a");
  KB = fc_tenant_key("tenant-b");
  KC = fc_tenant_key("tenant-c");
  printf("fc tenant share:\n");
  test_bounds();
  test_config_resolves();
  test_a_flood_leaves_room_for_b();
  test_queue_share_and_no_hol_at_the_gate();
  test_wake_skips_an_over_share_head();
  test_every_exit_gives_the_slot_back();
  test_keyless_is_one_tenant();
  test_table_full_shares_the_overflow();
  test_observe_counts_and_admits();
  test_no_share_is_unchanged();
  test_share_turned_off_under_load();
  printf("OK\n");
  return 0;
}
