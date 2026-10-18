/* SPDX-License-Identifier: BSD-3-Clause
 * Link the real selector, HTTP cleanup/wake, SGLang drain and trie TUs.
 * Structs and enums are the production headers; only scheduler/metric/KV
 * service boundaries are fixture edges. No production .c slicing or inclusion. */
#define _GNU_SOURCE
#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include "uthash.h"
#include "log.h"
#include "sockproxy_internal.h"
#include "sockproxy_pd.h"
#include "sockproxy_pd_reservation.h"

proxy_global_stats_t global_stats;
static proxy_struct_t instance;
proxy_struct_t *proxy_struct = &instance;
static proxy_fd_ent_t *registry[512], *clients[16];
static int woken[256], nwoken;
void llb_ai_pd_session_hit(char *m)
{
  (void)m;
}
void llb_ai_pd_tier_selected(char *m, int tier)
{
  (void)m;
  (void)tier;
}
void llb_sockproxy_emit_sync_event(const proxy_sync_event_t *event)
{
  (void)event;
}
int pd_kv_exact_select(proxy_epval_t *t, proxy_fd_ent_t *p, int *ep, uint32_t excluded)
{
  (void)t;
  (void)p;
  (void)ep;
  (void)excluded;
  assert(0);
  return -1; /* KV-exact is disabled in this reservation fixture. */
}
int notify_owner_thr(void *ctx, int fd)
{
  (void)ctx;
  (void)fd;
  return 0;
}
void *notify_priv_of_fd(void *ctx, int fd, uint64_t *gen)
{
  (void)ctx;
  if (fd < 0 || fd >= 512 || !registry[fd])
    return NULL;
  *gen = atomic_load(&registry[fd]->gen);
  return registry[fd];
}
int notify_wake_worker_gen(void *ctx, int worker, int fd, uint64_t gen)
{
  (void)ctx;
  assert(worker == 0 && registry[fd]);
  assert(atomic_load(&registry[fd]->gen) == gen && nwoken < 256);
  woken[nwoken++] = fd;
  return 0;
}
static void init_admission_epval(proxy_epval_t *t, int n)
{
  memset(t, 0, sizeof(*t));
  t->n_eps = n + 1;
  t->pd_disagg_enabled = t->cb_enabled = 1;
  pthread_rwlock_init(&t->pd_session_lock, NULL);
  pthread_rwlock_init(&t->pd_trie_lock, NULL);
  pthread_mutex_init(&t->pd_parked_lock, NULL);
  for (int i = 0; i < n; i++) {
    t->ep_role[i] = 1;
    t->circuit_breakers[i].state = CB_STATE_CLOSED;
  }
  t->ep_role[n] = 2;
  t->circuit_breakers[n].state = CB_STATE_CLOSED;
  t->n_prefill_eps = n;
  t->n_decode_eps = 1;
}
static void cleanup_admission_epval(proxy_epval_t *t)
{
  pthread_rwlock_destroy(&t->pd_session_lock);
  pthread_rwlock_destroy(&t->pd_trie_lock);
  pthread_mutex_destroy(&t->pd_parked_lock);
}
static void init_admission_pfe(proxy_fd_ent_t *p, int fd)
{
  memset(p, 0, sizeof(*p));
  p->fd = fd;
  p->pd_prefill_ep_idx = p->pd_decode_ep_idx = p->park_ep_idx = -1;
  atomic_store(&p->gen, 1);
  assert(fd >= 0 && fd < 512);
  registry[fd] = p;
}
static void cleanup_connections(void)
{
  for (int i = 0; i < 16; i++)
    if (clients[i]) {
      pd_cleanup(clients[i]);
      registry[clients[i]->fd] = NULL;
      free(clients[i]);
      clients[i] = NULL;
    }
}
static pthread_barrier_t before, held;
static proxy_epval_t ev;
static int legacy, selected[16], codes[16];
static void *race(void *arg)
{
  long id = (long)arg;
  proxy_fd_ent_t *p = clients[id];
  init_admission_pfe(p, 100 + (int)id);
  p->epv = &ev;
  pthread_barrier_wait(&before);
#ifdef I18_BASELINE
  codes[id] = pd_select_prefill(&ev, p, &selected[id], 0);
#else
  codes[id] = legacy ? pd_select_prefill(&ev, p, &selected[id], 0)
                     : pd_reserve_prefill(&ev, p, &selected[id], 0, 0);
#endif
  if (!legacy && codes[id] == 0)
    pd_load_commit(&ev, &p->pd_prefill_load_token, selected[id]);
  pthread_barrier_wait(&held);
  if (legacy && codes[id] == 0)
    atomic_fetch_add(&ev.pd_ep_loads[selected[id]].active_conns, 1);
  return NULL;
}
static void concurrent(int n)
{
  for (int i = 0; i < n; i++) {
    assert(!clients[i]);
    clients[i] = calloc(1, sizeof(*clients[i]));
    assert(clients[i]);
  }
  pthread_t threads[16];
  pthread_barrier_init(&before, NULL, n);
  pthread_barrier_init(&held, NULL, n);
  for (long i = 0; i < n; i++)
    assert(!pthread_create(&threads[i], NULL, race, (void *)i));
  for (int i = 0; i < n; i++)
    assert(!pthread_join(threads[i], NULL));
  pthread_barrier_destroy(&before);
  pthread_barrier_destroy(&held);
}
#ifndef I18_BASELINE
static void clean(proxy_epval_t *t)
{
  pd_session_mapping_t *s, *tmp;
  HASH_ITER(hh, t->pd_session_map, s, tmp)
  {
    HASH_DEL(t->pd_session_map, s);
    free(s);
  }
  cleanup_admission_epval(t);
}
static void capacity(void)
{
  setenv("LLB_PD_MAX_INFLIGHT_PER_EP", "1", 1);
  setenv("LLB_PD_QUEUE_DEPTH_PER_EP", "2", 1);
  for (int round = 0; round < 64; round++) {
    init_admission_epval(&ev, 2);
    concurrent(16);
    int admitted = 0;
    for (int i = 0; i < 16; i++) {
      if (codes[i] == 0)
        admitted++;
      else
        assert(codes[i] == PD_PREFILL_NO_CAPACITY);
    }
    assert(admitted == 2);
    assert(atomic_load(&ev.pd_ep_loads[0].active_conns) == 1);
    assert(atomic_load(&ev.pd_ep_loads[1].active_conns) == 1);
    for (int i = 0; i < 16; i++)
      if (codes[i] == 0)
        pd_cleanup(clients[i]);
    cleanup_connections();
    assert(!atomic_load(&ev.pd_ep_loads[0].active_conns));
    assert(!atomic_load(&ev.pd_ep_loads[1].active_conns));
    assert(!ev.pd_parked[0].count && !ev.pd_parked[1].count);
    clean(&ev);
  }
  puts("PASS 64 x16 concurrent reservations: two cap1 EPs, exactly2 admitted, no retry "
       "parking, rollback0");
  init_admission_epval(&ev, 2);
  proxy_fd_ent_t p;
  init_admission_pfe(&p, 50);
  int ep = -1;
  pd_session_store(&ev, "pinned", 0, 2);
  p.has_conv_id = 1;
  strcpy(p.conversation_id, "pinned");
  assert(!pd_reserve_prefill(&ev, &p, &ep, 0, 0) && ep == 0);
  uint32_t a = 0;
  pd_load_commit(&ev, &a, ep);
  assert(!pd_reserve_prefill(&ev, &p, &ep, 0, 0) && ep == 1);
  uint32_t b = 0;
  pd_load_commit(&ev, &b, ep);
  assert(pd_reserve_prefill(&ev, &p, &ep, 0, 0) == PD_PREFILL_NO_CAPACITY);
  pd_load_release(&ev, &a);
  pd_load_release(&ev, &a);
  assert(atomic_load(&ev.pd_ep_loads[1].active_conns) == 1);
  pd_load_release(&ev, &b);
  clean(&ev);
  puts("PASS session cap spill, exhausted capacity, duplicate rollback never steals "
       "another request unit");
  init_admission_epval(&ev, 2);
  init_admission_pfe(&p, 55);
  for (int state = 0; state < 3; state++) {
    ev.eps[0].inv = state == 0;
    ev.circuit_breakers[0].state = state == 1 ? CB_STATE_OPEN : CB_STATE_CLOSED;
    atomic_store(&ev.pd_ctrl_mode, state == 2 ? 1 : 0);
    atomic_store(&ev.pd_ctrl_ep[0], (uint32_t)PD_CTRL_ST_DISABLED << 24);
    assert(!pd_reserve_prefill(&ev, &p, &ep, 0, 0) && ep == 1);
    pd_load_put(&ev, ep);
    assert(!atomic_load(&ev.pd_ep_loads[0].active_conns));
  }
  clean(&ev);
  puts("PASS reservation preserves health/CB/controller exclusion");
}
static void ownership(void)
{
  init_admission_epval(&ev, 2);
  uint32_t p = 0, d = 0;
  assert(pd_load_try_reserve(&ev, 0, 1));
  pd_load_commit(&ev, &p, 0);
  assert(pd_load_try_reserve(&ev, 2, 0));
  pd_load_commit(&ev, &d, 2);
  /* A failed replacement is temporary: original pair remains owned. */
  assert(pd_load_try_reserve(&ev, 1, 1));
  uint32_t candidate = 2;
  pd_load_release(&ev, &candidate);
  pd_load_release(&ev, &candidate);
  assert(atomic_load(&ev.pd_ep_loads[0].active_conns) == 1 &&
         !atomic_load(&ev.pd_ep_loads[1].active_conns));
  /* Commit a replacement once, then client cancellation + repeated cleanup. */
  assert(pd_load_try_reserve(&ev, 1, 1));
  pd_load_commit(&ev, &p, 1);
  assert(!atomic_load(&ev.pd_ep_loads[0].active_conns) &&
         atomic_load(&ev.pd_ep_loads[1].active_conns) == 1);
  pd_load_release(&ev, &p);
  pd_load_release(&ev, &d);
  pd_load_release(&ev, &p);
  pd_load_release(&ev, &d);
  for (int i = 0; i < 3; i++)
    assert(!atomic_load(&ev.pd_ep_loads[i].active_conns));
  /* A decode hint, with no owned token, must not release someone else's D. */
  assert(pd_load_try_reserve(&ev, 2, 0));
  pd_load_release(&ev, &d);
  assert(atomic_load(&ev.pd_ep_loads[2].active_conns) == 1);
  pd_load_put(&ev, 2);
  atomic_store(&ev.pd_ep_loads[0].active_conns, UINT32_MAX);
  assert(!pd_load_try_reserve(&ev, 0, 0));
  atomic_store(&ev.pd_ep_loads[0].active_conns, 0);
  clean(&ev);
  puts("PASS failed replacement rollback, retry ownership transfer, cancel/duplicate "
       "cleanup, unowned decode hint, overflow guard");
}
static void queues(void)
{
  init_admission_epval(&ev, 1);
  proxy_fd_ent_t h, p[3];
  int ep = -1;
  init_admission_pfe(&h, 10);
  assert(!pd_reserve_prefill(&ev, &h, &ep, 0, 1));
  uint32_t token = 0;
  pd_load_commit(&ev, &token, ep);
  for (int i = 0; i < 3; i++) {
    init_admission_pfe(&p[i], 20 + i);
    int rc = pd_reserve_prefill(&ev, &p[i], &ep, 0, 1);
    assert(rc == (i < 2 ? PD_PREFILL_PARKED : PD_PREFILL_NO_CAPACITY));
  }
  assert(ev.pd_parked[0].count == 2 &&
         atomic_load(&ev.pd_ep_loads[0].active_conns) == 1);
  int prev = nwoken;
  pd_load_release(&ev, &token);
  assert(nwoken == prev + 1 && woken[prev] == 20);
  /* Owner re-drives the oldest parked request; no unit existed while parked. */
  assert(!pd_reserve_prefill(&ev, &p[0], &ep, 0, 0));
  pd_load_commit(&ev, &token, ep);
  pd_load_release(&ev, &token);
  assert(nwoken == prev + 2 && woken[prev + 1] == 21);
  assert(!ev.pd_parked[0].count && !atomic_load(&ev.pd_ep_loads[0].active_conns));
  /* Actual production FIFO expiry math, including generation metadata. */
  uint64_t gen = atomic_load(&p[1].gen);
  ev.pd_parked[0].slot[0] = (pd_parked_ent_t){.fd = 21, .gen = gen, .enqueue_ns = 1};
  ev.pd_parked[0].head = 0;
  ev.pd_parked[0].tail = 1;
  ev.pd_parked[0].count = 1;
  pd_parked_ent_t expired = {0};
  assert(pd_parked_peek_head(&ev.pd_parked[0], &expired));
  assert(expired.enqueue_ns == 1 && expired.fd == 21 && expired.gen == gen);
  assert(!pd_parked_remove_fd(&ev.pd_parked[0], 21, gen + 1));
  assert(pd_parked_remove_fd(&ev.pd_parked[0], 21, gen));
  assert(!pd_parked_remove_fd(&ev.pd_parked[0], 21, gen) && !ev.pd_parked[0].count);
  clean(&ev);
  puts("PASS bounded FIFO/overflow, unreserved park, slot-free wake/owner re-drive, "
       "production FIFO generation/remove primitives");
}
static void real_cleanup(void)
{
  proxy_fd_ent_t *p = calloc(1, sizeof(*p));
  assert(p);
  init_admission_epval(&ev, 2);
  init_admission_pfe(p, 66);
  p->epv = &ev;
  assert(pd_load_try_reserve(&ev, 0, 1));
  pd_load_commit(&ev, &p->pd_prefill_load_token, 0);
  assert(pd_load_try_reserve(&ev, 2, 0));
  pd_load_commit(&ev, &p->pd_decode_load_token, 2);
  assert(pd_load_try_reserve(&ev, 2, 0)); /* another client's Decode unit */
  p->pd_decode_ep_idx = 2;
  p->pd_phase = PD_PHASE_DECODE_STREAMING;
  p->pd_saved_body = malloc(16);
  assert(p->pd_saved_body);
  pd_cleanup(p);
  assert(!p->pd_saved_body && !p->pd_prefill_load_token && !p->pd_decode_load_token);
  assert(!atomic_load(&ev.pd_ep_loads[0].active_conns));
  assert(atomic_load(&ev.pd_ep_loads[2].active_conns) == 1);
  p->pd_decode_ep_idx = 2;
  pd_cleanup(p);
  assert(atomic_load(&ev.pd_ep_loads[2].active_conns) == 1);
  pd_load_put(&ev, 2);
  clean(&ev);
  registry[66] = NULL;
  free(p);
  puts("PASS real HTTP cleanup: owned P/D release, saved-body free, duplicate cleanup "
       "and unowned Decode hint");
}
static void uncapped(void)
{
  setenv("LLB_PD_MAX_INFLIGHT_PER_EP", "0", 1);
  setenv("LLB_PD_QUEUE_DEPTH_PER_EP", "0", 1);
  init_admission_epval(&ev, 1);
  concurrent(16);
  for (int i = 0; i < 16; i++)
    assert(codes[i] == 0);
  assert(atomic_load(&ev.pd_ep_loads[0].active_conns) == 16);
  for (int i = 0; i < 16; i++)
    pd_cleanup(clients[i]);
  cleanup_connections();
  assert(!atomic_load(&ev.pd_ep_loads[0].active_conns));
  clean(&ev);
  puts("PASS cap0 compatibility:16 simultaneous reservations, balanced teardown");
}
#endif
#ifndef I18_BASELINE
static void overflow_edge(void)
{
  setenv("LLB_PD_MAX_INFLIGHT_PER_EP", "0", 1);
  setenv("LLB_PD_QUEUE_DEPTH_PER_EP", "0", 1);
  proxy_epval_t t;
  proxy_fd_ent_t p;
  int ep = -1;
  init_admission_epval(&t, 1);
  init_admission_pfe(&p, 60);
  atomic_store(&t.pd_ep_loads[0].active_conns, UINT32_MAX);
  puts("CONTROL cap0 overflow boundary must terminate without wrapping");
  fflush(stdout);
  alarm(2);
  assert(pd_reserve_prefill(&t, &p, &ep, 0, 0) == PD_PREFILL_NO_CAPACITY);
  alarm(0);
  assert(atomic_load(&t.pd_ep_loads[0].active_conns) == UINT32_MAX);
  clean(&t);
  puts("PASS cap0 saturated-counter boundary terminates without wrap/loop");
}
static void drain_edge(void)
{
  setenv("LLB_PD_MAX_INFLIGHT_PER_EP", "1", 1);
  setenv("LLB_PD_QUEUE_DEPTH_PER_EP", "0", 1);
  proxy_epval_t t;
  proxy_fd_ent_t p;
  int ep = -1;
  init_admission_epval(&t, 1);
  init_admission_pfe(&p, 61);
  pd_session_store(&t, "drain-pinned", 0, 1);
  p.has_conv_id = 1;
  strcpy(p.conversation_id, "drain-pinned");
  atomic_store(&t.pd_ctrl_mode, 1);
  atomic_store(&t.pd_ctrl_ep[0], (uint32_t)PD_CTRL_ST_DRAINING << 24);
  assert(!pd_reserve_prefill(&t, &p, &ep, 0, 0) && ep == 0);
  puts("CONTROL pinned draining owner at cap must reject without looping/fallback "
       "bypass");
  fflush(stdout);
  alarm(2);
  assert(pd_reserve_prefill(&t, &p, &ep, 0, 0) == PD_PREFILL_NO_CAPACITY);
  alarm(0);
  assert(atomic_load(&t.pd_ep_loads[0].active_conns) == 1);
  pd_load_put(&t, 0);
  clean(&t);
  puts("PASS draining pinned session respects cap and terminates without normal-mode "
       "fallback");
}
#endif
int main(int argc, char **argv)
{
  log_set_level(LOG_ERROR);
  pthread_rwlock_init(&instance.lock, NULL);
  instance.ns = &instance;
#ifndef I18_BASELINE
  if (argc > 1 && !strcmp(argv[1], "--overflow-edge-only")) {
    overflow_edge();
    return 0;
  }
  if (argc > 1 && !strcmp(argv[1], "--drain-edge-only")) {
    drain_edge();
    return 0;
  }
#endif
  if (argc > 1 && !strcmp(argv[1], "--legacy-red")) {
    legacy = 1;
    setenv("LLB_PD_MAX_INFLIGHT_PER_EP", "1", 1);
    setenv("LLB_PD_QUEUE_DEPTH_PER_EP", "0", 1);
    init_admission_epval(&ev, 1);
    concurrent(2);
    unsigned units = atomic_load(&ev.pd_ep_loads[0].active_conns);
    printf("%s old select/check then increment: cap1 held=%u\n",
           units > 1 ? "RED" : "UNQUALIFIED", units);
    cleanup_connections();
    return units > 1 ? 2 : 3;
  }
#ifndef I18_BASELINE
  for (int edge = 0; edge < 2; edge++) {
    pid_t e = fork();
    assert(e >= 0);
    if (!e) {
      if (edge)
        drain_edge();
      else
        overflow_edge();
      fflush(stdout);
      _exit(0);
    }
    int st;
    assert(waitpid(e, &st, 0) == e && WIFEXITED(st) && WEXITSTATUS(st) == 0);
  }
  pid_t child = fork();
  assert(child >= 0);
  if (child == 0) {
    uncapped();
    fflush(stdout);
    _exit(0);
  }
  int status;
  assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
         WEXITSTATUS(status) == 0);
  capacity();
  ownership();
  queues();
  real_cleanup();
  return 0;
#else
  return 3;
#endif
}
