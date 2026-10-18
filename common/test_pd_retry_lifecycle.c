/* SPDX-License-Identifier: BSD-3-Clause
 * Real vLLM/SGLang retry, selector, rewriter and HTTP cleanup TUs.
 * Only dial/allocation/registration/metrics boundaries are controlled here.
 * No copied production function bodies, substitute structs or enum values. */
#define _GNU_SOURCE
#include "uthash.h"
#include "log.h"
#include "notify.h"
#include <errno.h>
#include "sockproxy_internal.h"
#include "sockproxy_pd.h"
#include "sockproxy_pd_reservation.h"
#include <assert.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

proxy_global_stats_t global_stats;
static proxy_struct_t instance;
proxy_struct_t *proxy_struct = &instance;
static proxy_epval_t *pool;
static proxy_fd_ent_t *old_decode;
static proxy_fd_ent_t *shells[16];
static int nshells, sockets[32], socket_ep[16], nsockets, registrations, deletions;
static int fail_all_p, fail_first_p, fail_decode, fail_shell_at, p_dials, shell_calls;
static int allocation_armed, allocation_at, allocation_calls, write_failure;
static int no_decode, all_p_full;
static int initiate_mode, d_dials, d_order[4], cancel_at, first_d_fails;

void *__real_malloc(size_t size);
void *__real_calloc(size_t n, size_t size);
ssize_t __real_write(int fd, const void *data, size_t size);
static int allocation_fails(void)
{
  return allocation_armed && ++allocation_calls == allocation_at;
}
void *__wrap_malloc(size_t size)
{
  return allocation_fails() ? NULL : __real_malloc(size);
}
void *__wrap_calloc(size_t n, size_t size)
{
  return allocation_fails() ? NULL : __real_calloc(n, size);
}
ssize_t __wrap_write(int fd, const void *data, size_t size)
{
  if (write_failure) {
    for (int i = 0; i < nsockets; i += 2) {
      if (fd == sockets[i] && pool->ep_role[socket_ep[i / 2]] == write_failure) {
        errno = EPIPE;
        return -1;
      }
    }
  }
  return __real_write(fd, data, size);
}
int proxy_setup_ep_connect(uint32_t ip, uint16_t port, uint8_t protocol, void *ssl_ctx,
                           void **ssl, proxy_fd_ent_t *client, const void *pp2,
                           int pp2len)
{
  (void)port;
  if (old_decode) {
    assert(!old_decode->n_rfd && !old_decode->rfd_ent[0]);
    for (int i = 0; i < MAX_PROXY_EP; i++)
      assert(client->rfd_ent[i] != old_decode);
  }
  assert(protocol == IPPROTO_TCP && !ssl_ctx && !ssl && !pp2 && !pp2len);
  int ep = -1;
  for (int i = 0; i < pool->n_eps; i++)
    if (pool->eps[i].xip == ip)
      ep = i;
  assert(ep >= 0);
  if (pool->ep_role[ep] == 1) {
    p_dials++;
    assert(ep != 0 && atomic_load(&pool->pd_ep_loads[ep].active_conns) == 1);
    if (fail_all_p || (fail_first_p && p_dials == 1))
      return -1;
  } else {
    if (initiate_mode) {
      assert(d_dials < 4);
      d_order[d_dials++] = ep;
      /* The old owned unit remains while the alternate is private. */
      if (d_dials == 2) {
        assert(ep == 4);
        assert(atomic_load(&pool->pd_ep_loads[3].active_conns) ==
               1u + (client->pd_decode_load_token == 4));
        assert(atomic_load(&pool->pd_ep_loads[4].active_conns) == 1);
      }
      if (cancel_at == d_dials) pd_cleanup(client);
    }
    if (fail_decode || (initiate_mode && first_d_fails && d_dials == 1)) return -1;
  }
  int pair[2];
  assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, pair));
  assert(nsockets + 2 <= 32);
  socket_ep[nsockets / 2] = ep;
  sockets[nsockets++] = pair[0];
  sockets[nsockets++] = pair[1];
  return pair[0];
}
proxy_fd_ent_t *pfe_alloc(void)
{
  if (++shell_calls == fail_shell_at)
    return NULL;
  proxy_fd_ent_t *p = calloc(1, sizeof(*p));
  if (!p)
    return NULL;
  assert(nshells < 16);
  shells[nshells++] = p;
  atomic_store(&p->gen, 1);
  pthread_rwlock_init(&p->lock, NULL);
  return p;
}
int __wrap_proxy_fdlist_link(proxy_map_ent_t *head, proxy_fd_ent_t *p, const char *what)
{
  assert(head && p && what);
  return 0; /* Registration handoff, not a second gateway fd registry. */
}
void __wrap_pd_resp_parser_init(proxy_fd_ent_t *p)
{
  assert(p); /* Response framing is covered by the production HTTP TU gates. */
}
int __wrap_handle_on_message_complete(llhttp_t *parser)
{
  (void)parser;
  assert(0); /* This fixture dispatches; it does not invent a backend answer. */
  return 0;
}
int notify_add_ent_pinned(void *ctx, int fd, notify_type_t type, void *priv,
                          uint64_t gen, int pin_fd)
{
  (void)ctx;
  (void)type;
  assert(fd > 0 && priv && gen && pin_fd > 0);
  registrations++;
  return 0;
}
int notify_delete_ent(void *ctx, int fd, int evict)
{
  (void)ctx;
  assert(fd > 0 && !evict);
  deletions++;
  return 0; /* Leave the fixture client alive to inspect real abort bytes. */
}
int notify_owner_thr(void *ctx, int fd)
{
  (void)ctx;
  (void)fd;
  assert(0);
  return -1;
}
void *notify_priv_of_fd(void *ctx, int fd, uint64_t *gen)
{
  (void)ctx;
  (void)fd;
  (void)gen;
  assert(0);
  return NULL;
}
int notify_wake_worker_gen(void *ctx, int worker, int fd, uint64_t gen)
{
  (void)ctx;
  (void)worker;
  (void)fd;
  (void)gen;
  assert(0);
  return -1; /* Queue is off; the separate real-notifier fixture covers wake. */
}
int proxy_build_ppv2_v4(uint8_t *b, size_t n, uint32_t s, uint16_t sp, uint32_t d,
                        uint16_t dp)
{
  (void)b;
  (void)n;
  (void)s;
  (void)sp;
  (void)d;
  (void)dp;
  assert(0);
  return -1;
}
void circuit_breaker_record_failure(proxy_epval_t *t, int ep)
{
  t->circuit_breakers[ep].state = CB_STATE_OPEN;
}
void circuit_breaker_record_origin_error(proxy_epval_t *t, int ep)
{
  (void)t;
  (void)ep;
  assert(0); /* All injected failures are transport or allocation failures. */
}
void pd_kv_overflow_inc(void)
{
  assert(0); /* Fixture transfer parameters fit the production capacity. */
}
void circuit_breaker_record_origin_success(proxy_epval_t *t, int ep)
{
  assert(t && ep >= 0);
}
void llb_ai_pd_record(char *m, int64_t p, int64_t d, int kv, int error)
{
  (void)m;
  (void)p;
  (void)d;
  (void)kv;
  (void)error;
}
void llb_ai_pd_session_hit(char *m)
{
  (void)m;
}
void llb_ai_pd_tier_selected(char *m, int tier)
{
  (void)m;
  (void)tier;
}
void llb_sockproxy_emit_sync_event(const proxy_sync_event_t *e)
{
  (void)e;
}
int pd_kv_exact_select(proxy_epval_t *t, proxy_fd_ent_t *p, int *ep, uint32_t mask)
{
  (void)t;
  (void)p;
  (void)ep;
  (void)mask;
  assert(0);
  return -1;
}

static void reset_pool(void)
{
  pool = calloc(1, sizeof(*pool));
  assert(pool);
  pool->n_eps = 5;
  pool->n_prefill_eps = 3;
  pool->n_decode_eps = 2;
  pool->pd_disagg_enabled = pool->cb_enabled = 1;
  pool->pd_bootstrap_port = 8998;
  pthread_rwlock_init(&pool->pd_session_lock, NULL);
  pthread_rwlock_init(&pool->pd_trie_lock, NULL);
  pthread_mutex_init(&pool->pd_parked_lock, NULL);
  for (int i = 0; i < 5; i++) {
    pool->eps[i].xip = htonl(0xc0000201u + (unsigned)i);
    pool->eps[i].xport = htons(8000);
    pool->eps[i].nixl_port = htons(5600);
    pool->ep_role[i] = i < 3 ? 1 : 2;
    pool->circuit_breakers[i].state = CB_STATE_CLOSED;
  }
  old_decode = NULL;
  nshells = nsockets = registrations = deletions = p_dials = shell_calls = 0;
}
static void run_case(int sg, int owns_decode, int invalid_body, int nth_alloc,
                     int expect_success)
{
  reset_pool();
  pool->pd_engine = sg ? PD_ENGINE_SGLANG : PD_ENGINE_VLLM;
  if (no_decode) {
    pool->circuit_breakers[3].state = CB_STATE_OPEN;
    pool->circuit_breakers[4].state = CB_STATE_OPEN;
  }
  if (all_p_full) {
    atomic_store(&pool->pd_ep_loads[1].active_conns, 1);
    atomic_store(&pool->pd_ep_loads[2].active_conns, 1);
  }
  proxy_fd_ent_t *c = calloc(1, sizeof(*c));
  proxy_map_ent_t *head = calloc(1, sizeof(*head));
  assert(c && head);
  int client[2];
  assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, client));
  c->fd = client[0];
  c->head = head;
  c->epv = pool;
  c->pd_prefill_ep_idx = 0;
  c->pd_prefill_load_token = 1;
  c->pd_decode_ep_idx = 3;
  c->pd_decode_load_token = owns_decode ? 4 : 0;
  c->park_ep_idx = -1;
  c->pd_sg_active = sg;
  c->pd_sg_room = sg ? 12345 : 0;
  c->pd_phase = sg ? PD_PHASE_DECODE_SENDING : PD_PHASE_PREFILL_WAITING;
  atomic_store(&pool->pd_ep_loads[0].active_conns, 1);
  atomic_store(&pool->pd_ep_loads[3].active_conns, 1 + owns_decode);
  int old_wire[2] = {-1, -1};
  if (sg) {
    old_decode = calloc(1, sizeof(*old_decode));
    assert(old_decode && !socketpair(AF_UNIX, SOCK_STREAM, 0, old_wire));
    pthread_rwlock_init(&old_decode->lock, NULL);
    old_decode->fd = old_wire[0];
    old_decode->is_pd_decode_backend = 1;
    old_decode->rfd_ent[0] = c;
    old_decode->rfd[0] = c->fd;
    old_decode->n_rfd = 1;
    c->rfd_ent[0] = old_decode;
    c->rfd[0] = old_wire[0];
    c->n_rfd = 1;
  }
  const char *json = invalid_body ? "{"
                                  : "{\"model\":\"fixture\",\"messages\":[{\"role\":"
                                    "\"user\",\"content\":\"retry\"}],"
                                    "\"max_tokens\":32,\"stream\":true}";
  const char *header = "POST /v1/chat/completions HTTP/1.1\r\nHost: fixture\r\n"
                       "Content-Length: 0\r\n\r\n";
  uint8_t *body = (uint8_t *)strdup(json);
  uint8_t *hdrs = (uint8_t *)strdup(header);
  c->pd_saved_body = (uint8_t *)strdup(json);
  c->pd_saved_body_len = strlen(json);
  c->pd_saved_headers = (uint8_t *)strdup(header);
  c->pd_saved_headers_len = strlen(header);
  assert(body && hdrs && c->pd_saved_body && c->pd_saved_headers);
  allocation_calls = 0;
  allocation_at = nth_alloc;
  allocation_armed = 1;
  if (sg)
    pd_sg_retry_pair(c, 0, hdrs, strlen(header), body, strlen(json));
  else
    pd_retry_prefill(c, 0, hdrs, strlen(header), body, strlen(json));
  allocation_armed = 0;
  if (expect_success >= 0)
    assert((c->pd_phase != PD_PHASE_ERROR) == expect_success);
  if (c->pd_phase == PD_PHASE_ERROR) {
    char response[1024] = {0};
    assert(recv(client[1], response, sizeof(response) - 1, MSG_DONTWAIT) > 0);
    assert(strstr(response, sg ? "502 Bad Gateway" : "503 Service Unavailable"));
    assert(!c->pd_prefill_load_token && !c->pd_decode_load_token);
  } else {
    assert(c->pd_prefill_load_token && registrations == (sg ? 2 : 1));
    if (sg) {
      assert(c->pd_decode_load_token && c->pd_sg_room != 12345);
      assert(atomic_load(&pool->pd_ep_loads[3].active_conns) == 1);
    } else {
      assert(c->pd_decode_load_token == (owns_decode ? 4u : 0u));
    }
  }
  if (sg) {
    char byte;
    assert(!old_decode->n_rfd && !old_decode->rfd_ent[0]);
    assert(recv(old_wire[1], &byte, 1, MSG_DONTWAIT) == 0);
  }
  int calls = allocation_calls;
  pd_cleanup(c);
  pd_cleanup(c); /* Repeated caller teardown must never steal another D unit. */
  for (int i = 0; i < 5; i++)
    assert(atomic_load(&pool->pd_ep_loads[i].active_conns) ==
           (unsigned)(i == 3 || (all_p_full && (i == 1 || i == 2))));
  assert(!c->pd_prefill_load_token && !c->pd_decode_load_token);
  for (int i = 0; i < nsockets; i++)
    close(sockets[i]);
  close(client[0]);
  close(client[1]);
  for (int i = 0; i < nshells; i++) {
    pthread_rwlock_destroy(&shells[i]->lock);
    free(shells[i]);
  }
  pthread_rwlock_destroy(&pool->pd_session_lock);
  pthread_rwlock_destroy(&pool->pd_trie_lock);
  pthread_mutex_destroy(&pool->pd_parked_lock);
  if (old_decode) {
    close(old_wire[0]);
    close(old_wire[1]);
    pthread_rwlock_destroy(&old_decode->lock);
    free(old_decode);
  }
  free(pool);
  free(head);
  free(c);
  allocation_calls = calls;
}
/* Actual sequential Decode entry: keep all production selection, buffer
 * rewriting, ownership and cleanup paths. Inject only external boundaries. */
static void run_decode_case(int owned, int mode, int nth_alloc)
{
  reset_pool();
  pool->pd_engine = PD_ENGINE_VLLM;
  initiate_mode = 1; d_dials = 0;
  first_d_fails = mode != 1 && mode != 8;
  fail_decode = mode == 2;
  cancel_at = mode == 3 ? 1 : mode == 4 ? 2 : 0;
  if (mode == 5) pool->eps[4].inv = 1;
  if (mode == 6) pool->circuit_breakers[4].state = CB_STATE_OPEN;
  if (mode == 7) atomic_store(&pool->pd_ep_loads[4].active_conns, UINT32_MAX);
  if (mode == 8) pool->eps[3].inv = 1;
  /* A third healthy Decode must not extend the two-connect budget. */
  if (mode == 2) {
    pool->n_eps = 6; pool->ep_role[5] = 2;
    pool->eps[5].xip = htonl(0xc0000206u);
    atomic_store(&pool->pd_ep_loads[5].active_conns, 10);
  }
  proxy_fd_ent_t *c = calloc(1, sizeof(*c));
  proxy_map_ent_t *head = calloc(1, sizeof(*head));
  int client[2]; assert(c && head && !socketpair(AF_UNIX, SOCK_STREAM, 0, client));
  c->fd = client[0]; atomic_store(&c->gen, 42);
  c->head = head; c->epv = pool; c->park_ep_idx = -1;
  c->pd_prefill_ep_idx = 0; c->pd_prefill_load_token = 1;
  c->pd_decode_ep_idx = 3; c->pd_decode_load_token = owned ? 4 : 0;
  c->pd_phase = PD_PHASE_PREFILL_DONE;
  atomic_store(&pool->pd_ep_loads[0].active_conns, 1);
  atomic_store(&pool->pd_ep_loads[3].active_conns, 1 + owned);
  const char *body = "{\"model\":\"fixture\",\"messages\":[{\"role\":\"user\",\"content\":\"retry\"}],\"max_tokens\":32,\"stream\":true}";
  const char *headers = "POST /v1/chat/completions HTTP/1.1\r\nHost: fixture\r\nX-Request-ID: stable-retry-id\r\nContent-Length: 0\r\n\r\n";
  const char *prefill = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"kv_transfer_params\":{\"remote_engine_id\":\"fixture-kv\"}}";
  c->pd_saved_body = (uint8_t *)strdup(body); c->pd_saved_body_len = strlen(body);
  c->pd_saved_headers = (uint8_t *)strdup(headers); c->pd_saved_headers_len = strlen(headers);
  c->pd_prefill_resp_buf = (uint8_t *)strdup(prefill); c->pd_prefill_resp_len = strlen(prefill);
  if (mode >= 9) {
    if (mode == 9) c->pd_phase = PD_PHASE_DECODE_SENDING;
    if (mode == 10) c->pd_phase = PD_PHASE_DECODE_STREAMING;
    if (mode == 11) c->pd_decode_bytes_received = 1;
    if (mode == 12) c->pd_last_decode_ts = 1;
    if (mode == 13) c->reap_resp = 1;
    if (mode == 14) c->pd_decode_content_length = 1;
  }
  allocation_calls = 0; allocation_at = nth_alloc; allocation_armed = 1;
  int result = pd_initiate_decode(c);
  allocation_armed = 0;
  int allocations = allocation_calls;
  if (mode >= 9) {
    assert(result < 0 && !d_dials && c->pd_saved_body && c->pd_prefill_resp_buf);
  } else if (!nth_alloc && !fail_shell_at && !write_failure) {
    if (mode == 0 || mode == 1 || mode == 8) {
      assert(!result && registrations == 1 && !p_dials);
      int selected = mode == 1 ? 3 : 4;
      assert(c->pd_decode_load_token == (unsigned)selected + 1);
      assert(c->pd_decode_ep_idx == selected && c->pd_prefill_load_token == 1);
      assert(d_dials == (mode == 0 ? 2 : 1));
      assert(d_order[0] == (mode == 8 ? 4 : 3));
      char wire[8192] = {0};
      assert(recv(sockets[1], wire, sizeof(wire)-1, MSG_DONTWAIT) > 0);
      assert(strstr(wire, "stable-retry-id") && strstr(wire, "fixture-kv"));
    } else {
      assert(result < 0 && !registrations);
      assert(d_dials == (mode == 2 || mode == 4 ? 2 : 1));
    }
  }
  pd_cleanup(c); pd_cleanup(c);
  assert(!c->pd_prefill_load_token && !c->pd_decode_load_token);
  for (int i = 0; i < pool->n_eps; i++) {
    unsigned expected = i == 3 ? 1 : mode == 7 && i == 4 ? UINT32_MAX : mode == 2 && i == 5 ? 10 : 0;
    assert(atomic_load(&pool->pd_ep_loads[i].active_conns) == expected);
  }
  for (int i = 0; i < nsockets; i++) close(sockets[i]);
  for (int i = 0; i < nshells; i++) {pthread_rwlock_destroy(&shells[i]->lock); free(shells[i]);}
  close(client[0]); close(client[1]);
  pthread_rwlock_destroy(&pool->pd_session_lock);
  pthread_rwlock_destroy(&pool->pd_trie_lock);
  pthread_mutex_destroy(&pool->pd_parked_lock);
  free(c); free(head); free(pool);
  initiate_mode = first_d_fails = cancel_at = fail_decode = 0;
  allocation_calls = allocations;
}
int main(void)
{
  setenv("LLB_PD_MAX_INFLIGHT_PER_EP", "1", 1);
  setenv("LLB_PD_QUEUE_DEPTH_PER_EP", "0", 1);
  log_set_level(LOG_ERROR);
  pthread_rwlock_init(&instance.lock, NULL);
  for (int sg = 0; sg <= 1; sg++) {
    for (int owned = 0; owned <= 1; owned++) {
      run_case(sg, owned, 0, 0, 1);
      int allocations = allocation_calls;
      assert(allocations >= 3);
      for (int nth = 1; nth <= allocations; nth++)
        run_case(sg, owned, 0, nth, -1);
      fail_first_p = 1;
      run_case(sg, owned, 0, 0, 1);
      assert(p_dials == 2);
      fail_first_p = 0;
      fail_all_p = 1;
      run_case(sg, owned, 0, 0, 0);
      fail_all_p = 0;
      all_p_full = 1;
      run_case(sg, owned, 0, 0, 0);
      all_p_full = 0;
      if (sg) {
        fail_decode = 1;
        run_case(sg, owned, 0, 0, 0);
        fail_decode = 0;
        no_decode = 1;
        run_case(sg, owned, 0, 0, 0);
        no_decode = 0;
      }
      run_case(sg, owned, 1, 0, 0);
      for (int nth = 1; nth <= (sg ? 2 : 1); nth++) {
        fail_shell_at = nth;
        run_case(sg, owned, 0, 0, 0);
      }
      fail_shell_at = 0;
      for (int role = 1; role <= (sg ? 2 : 1); role++) {
        write_failure = role;
        run_case(sg, owned, 0, 0, 1);
      }
      write_failure = 0;
    }
  }
  for (int owned = 0; owned <= 1; owned++) {
    run_decode_case(owned, 0, 0);
    int allocations = allocation_calls;
    for (int nth = 1; nth <= allocations; nth++) run_decode_case(owned, 0, nth);
    for (int mode = 1; mode <= 14; mode++) run_decode_case(owned, mode, 0);
    fail_shell_at = 1; run_decode_case(owned, 0, 0); fail_shell_at = 0;
    write_failure = 2; run_decode_case(owned, 0, 0); write_failure = 0;
  }
  pthread_rwlock_destroy(&instance.lock);
  puts("real retry TUs: commit, alternate dial, all-P/decode failure, invalid JSON, "
       "allocation matrix, shell and write failures, duplicate cleanup, "
       "owned/unowned Decode conservation: PASS");
  return 0;
}
