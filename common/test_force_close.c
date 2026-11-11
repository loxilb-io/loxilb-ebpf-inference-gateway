/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_force_close.c - an endpoint's force-close (sockproxy_health.c) frees
 * HTTP/1.1 pairs inline and hands every HTTP/2 entry to its own worker.
 *
 * force_close_endpoint_connections runs under PROXY_LOCK on the health
 * thread. An HTTP/2 client's session is walked by its worker with no lock
 * held, so no entry of an HTTP/2 connection may be freed from there: it is
 * shut down instead, and its worker's hangup runs the full teardown. Drives
 * the REAL force_close_endpoint_connections / pd_teardown_conn over a
 * connection list holding:
 *   c2/l2  an HTTP/2 client and its HTTP/2 leg to the endpoint
 *   c1/l1  an HTTP/1.1 pair to the endpoint
 *   c3/l3  a connection that switched to HTTP/2 after an HTTP/1.1 request,
 *          its HTTP/1.1 leg still on the endpoint
 *   w      an HTTP/1.1 client a worker already claimed (deregister -ENOENT)
 * and checks what was freed, what was shut down, and that the scan ends.
 * The twins in wp8/twins-h2leg.sh remove each guard and must turn this red.
 *
 * The reaper-fallback shape (an HTTP/2 client with no leg left, handed to
 * pd_teardown_conn itself) is driven directly.
 *
 * Build: make test_forceclose (ASan + UBSan).
 */
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "uthash.h"
#include "sockproxy.h"
#include "sockproxy_internal.h"
#include "sockproxy_h2.h"
#include "sockproxy_health.h"

/* The teardown under test is file-static: compiled in here. */
#include "sockproxy_health.c"

static int checks, failures;

#define CHECK(cond, ...) do {                                        \
    checks++;                                                        \
    if (cond) {                                                      \
      printf("ok %d - ", checks); printf(__VA_ARGS__); printf("\n"); \
    } else {                                                         \
      failures++;                                                    \
      printf("FAIL %d - ", checks); printf(__VA_ARGS__);             \
      printf("  (%s:%d)\n", __FILE__, __LINE__);                     \
    }                                                                \
  } while (0)

static proxy_struct_t pstruct;
proxy_struct_t *proxy_struct = &pstruct;
proxy_global_stats_t global_stats;

/* The teardown primitives the force-close calls, recorded. A reset release
 * unlinks the entry from its rule's list, as the real one does. */
static int w_fd = -1, w_deregs;
static proxy_fd_ent_t *released[16], *freed[16];
static int n_released, n_freed;

int
notify_deregister_ent(void *ns, int fd)
{
  (void)ns;
  if (fd == w_fd) {
    w_deregs++;
    return -ENOENT;   /* a worker cleared it first and owns the teardown */
  }
  return 0;
}

void
proxy_release_fd_ctx(proxy_fd_ent_t *e, int reset)
{
  released[n_released++] = e;
  if (reset && e->head) {
    proxy_fd_ent_t **pp = &((proxy_map_ent_t *)e->head)->val.fdlist;
    while (*pp && *pp != e)
      pp = &(*pp)->next;
    if (*pp)
      *pp = e->next;
  }
}

void
proxy_try_free_fd_ctx(proxy_fd_ent_t *e)
{
  freed[n_freed++] = e;
}

/* The reaper's hand-off: the owner is found and woken, unless a case says
 * otherwise. */
static int owner_rc = 3, wake_rc;

int
notify_owner_thr(void *ctx, int fd)
{
  (void)ctx; (void)fd;
  return owner_rc;
}

int
notify_wake_worker(void *ctx, int thr, int fd)
{
  (void)ctx; (void)thr; (void)fd;
  return wake_rc;
}

/* The causes recorded for an HTTP/2 client's end line, as called. */
static struct { proxy_fd_ent_t *pfe; int reason; const proxy_fd_ent_t *leg; } marks[64];
static int n_marks;

void
proxy_h2_client_end_mark(proxy_fd_ent_t *pfe, int reason, int err,
                         const proxy_fd_ent_t *leg)
{
  (void)err;
  if (n_marks == (int)(sizeof(marks) / sizeof(marks[0])))
    return;
  marks[n_marks].pfe = pfe;
  marks[n_marks].reason = reason;
  marks[n_marks].leg = leg;
  n_marks++;
}

void
proxy_h2_client_end_log(proxy_fd_ent_t *pfe)
{
  (void)pfe;
}

/* The active-streams gauge, as ended. An inline free skips proxy_pdestroy,
 * whose settle would end a stream still open, so the teardown ends it. */
static int n_stream_ends;

int
llb_ai_stream_end(char *tenant_id, char *model_name)
{
  (void)tenant_id; (void)model_name;
  n_stream_ends++;
  return 0;
}

/* The reaper's fallback asks whether an answer is in progress; none is
 * here, so it writes its status text as before. */
int
sp_answer_started(proxy_fd_ent_t *pfe)
{
  (void)pfe;
  return 0;
}

/* 1 when e was marked with reason and leg. */
static int
marked(proxy_fd_ent_t *e, int reason, const proxy_fd_ent_t *leg)
{
  for (int i = 0; i < n_marks; i++)
    if (marks[i].pfe == e && marks[i].reason == reason && marks[i].leg == leg)
      return 1;
  return 0;
}

static int
marked_any(proxy_fd_ent_t *e)
{
  for (int i = 0; i < n_marks; i++)
    if (marks[i].pfe == e)
      return 1;
  return 0;
}

static int
was(proxy_fd_ent_t **set, int n, proxy_fd_ent_t *e)
{
  for (int i = 0; i < n; i++)
    if (set[i] == e)
      return 1;
  return 0;
}

static int
linked(proxy_map_ent_t *ent, proxy_fd_ent_t *e)
{
  for (proxy_fd_ent_t *p = ent->val.fdlist; p; p = p->next)
    if (p == e)
      return 1;
  return 0;
}

/* 1 when the far end of e's socketpair reads EOF: e was shut down. */
static int peer[64];
static int
shut(proxy_fd_ent_t *e)
{
  char b;
  return recv(peer[e->fd], &b, 1, MSG_DONTWAIT) == 0;
}

static void
mk(proxy_map_ent_t *ent, proxy_fd_ent_t *e, int odir, int ep)
{
  int sv[2];

  assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0 && sv[0] < 64);
  memset(e, 0, sizeof(*e));
  e->fd = sv[0];
  peer[sv[0]] = sv[1];
  e->odir = odir;
  e->ep_num = ep;
  e->head = ent;
  e->next = ent->val.fdlist;
  ent->val.fdlist = e;
}

static void
pair(proxy_fd_ent_t *c, proxy_fd_ent_t *l, int slot)
{
  c->rfd_ent[slot] = l;
  c->rfd[slot] = l->fd;
  c->n_rfd = slot + 1;
  l->rfd_ent[0] = c;
  l->rfd[0] = c->fd;
  l->n_rfd = 1;
}

static void
spin(int sig)
{
  (void)sig;
  printf("FAIL 0 - the force-close scan did not end (livelock)\n");
  _exit(1);
}

int
main(void)
{
  proxy_map_ent_t ent;
  proxy_fd_ent_t c2, l2, c1, l1, c3, l3, w, wl;
  proxy_h2_session_t h2a, h2b;
  backend_h2_session_t bs;
  const int EP = 1;

  setvbuf(stdout, NULL, _IONBF, 0);
  memset(&ent, 0, sizeof(ent));
  memset(&h2a, 0, sizeof(h2a));
  memset(&h2b, 0, sizeof(h2b));
  memset(&bs, 0, sizeof(bs));

  mk(&ent, &c2, 0, EP);  c2.h2_session = &h2a;   /* its last stream went to EP */
  mk(&ent, &l2, 1, EP);  l2.backend_h2_session = &bs;
  pair(&c2, &l2, 0);
  mk(&ent, &c1, 0, EP);
  mk(&ent, &l1, 1, -1);
  pair(&c1, &l1, 0);
  mk(&ent, &c3, 0, 0);   c3.h2_session = &h2b;   /* switched; not on EP itself */
  mk(&ent, &l3, 1, EP);
  pair(&c3, &l3, 0);
  mk(&ent, &w, 0, EP);
  mk(&ent, &wl, 1, -1);
  pair(&w, &wl, 0);
  w_fd = w.fd;

  signal(SIGALRM, spin);
  alarm(5);
  force_close_endpoint_connections(&ent, EP);
  alarm(0);
  CHECK(1, "the scan ends");

  CHECK(!was(released, n_released, &c2) && linked(&ent, &c2) && !shut(&c2),
        "the HTTP/2 client is neither freed nor shut down: it goes on over its other legs");
  CHECK(!was(released, n_released, &l2) && linked(&ent, &l2) && shut(&l2),
        "its leg to the endpoint is shut down, not freed: its worker ends it");
  CHECK(was(freed, n_freed, &c1) && was(freed, n_freed, &l1) &&
        !linked(&ent, &c1) && !linked(&ent, &l1),
        "the HTTP/1.1 pair is freed inline, as before");
  CHECK(!was(released, n_released, &c3) && !was(released, n_released, &l3) && shut(&l3),
        "the switched connection's HTTP/1.1 leg is handed to its worker");
  CHECK(!shut(&c3) && linked(&ent, &c3),
        "and its HTTP/2 client is not touched from here");
  /* The worker that ends a handed-off client sees only the hangup, which
   * reads as the client leaving: the cause is recorded before it. */
  CHECK(marked(&c3, SP_H2_END_TEARDOWN, &l3),
        "the switched client's end is recorded as the teardown, through its leg");
  CHECK(!marked_any(&c2),
        "the HTTP/2 client that goes on records no end");
  /* Passed, not retried in place: once per scan (here the first pass and the
   * rescan after c1's free), never the endless retry of the same entry. */
  CHECK(w_deregs >= 1 && w_deregs <= 2 && !was(freed, n_freed, &w) && linked(&ent, &w),
        "a client a worker already claimed is passed, at most once per scan (%d tries)", w_deregs);

  /* A reaper that reaches an open stream (ERR-01, the idle reaper) frees the
   * client inline: its stream ends there, once. A client a worker already
   * claimed is ended by that worker's settle; a pair torn down through its
   * leg ends the client's stream in the leg loop. */
  {
    proxy_map_ent_t ent4;
    proxy_fd_ent_t sc, sl, wc, wcl, lc, ll;

    memset(&ent4, 0, sizeof(ent4));
    mk(&ent4, &sc, 0, EP);
    mk(&ent4, &sl, 1, -1);
    pair(&sc, &sl, 0);
    mk(&ent4, &wc, 0, EP);
    mk(&ent4, &wcl, 1, -1);
    pair(&wc, &wcl, 0);
    mk(&ent4, &lc, 0, -1);
    mk(&ent4, &ll, 1, EP);
    pair(&lc, &ll, 0);
    sc.sse_active = wc.sse_active = lc.sse_active = 1;
    w_fd = wc.fd;
    n_stream_ends = 0;
    CHECK(pd_teardown_conn(&sc) == 1 && n_stream_ends == 1 && !sc.sse_active,
          "a client with an open stream, freed inline, ends its stream once");
    CHECK(pd_teardown_conn(&wc) == 0 && n_stream_ends == 1 && wc.sse_active,
          "a client a worker already claimed keeps it for that worker's settle");
    CHECK(pd_teardown_conn(&ll) == 1 && n_stream_ends == 2 && !lc.sse_active,
          "a pair torn down through its leg ends the client's stream once");
    w_fd = -1;
  }

  /* The reaper's fallback (its owner could not be woken) hands a client to
   * pd_teardown_conn itself; an HTTP/2 client with no leg left has no peer
   * to recognise it by. */
  {
    proxy_map_ent_t ent2;
    proxy_fd_ent_t lone;
    proxy_h2_session_t h2c;

    memset(&ent2, 0, sizeof(ent2));
    memset(&h2c, 0, sizeof(h2c));
    mk(&ent2, &lone, 0, EP);
    lone.h2_session = &h2c;
    n_released = n_freed = 0;
    CHECK(pd_teardown_conn(&lone) == 0 && n_released == 0 && shut(&lone) && linked(&ent2, &lone),
          "an HTTP/2 client with no leg, reaped, is shut down for its worker, not freed");
    CHECK(marked(&lone, SP_H2_END_TEARDOWN, NULL),
          "and its end is recorded as the teardown before the hangup");
  }

  /* The reaper hands an unanswered request to the connection's owner, which
   * finishes it and sees only its own hangup: the cause is recorded before
   * the hand-off, or the end line would name the wrong actor. */
  {
    proxy_map_ent_t ent3;
    proxy_fd_ent_t rc;
    proxy_h2_session_t h2r;

    memset(&ent3, 0, sizeof(ent3));
    memset(&h2r, 0, sizeof(h2r));
    mk(&ent3, &rc, 0, EP);
    rc.h2_session = &h2r;
    pstruct.ns = &pstruct;              /* any non-NULL notifier */
    n_marks = 0;
    pd_reap_respond(&rc, SP_REAP_PD_PARK_TIMEOUT);
    pstruct.ns = NULL;
    CHECK(rc.reap_resp == SP_REAP_PD_PARK_TIMEOUT && marked(&rc, SP_H2_END_REAPER, NULL),
          "a reaped client handed to its owner is recorded as the reaper's end");
    CHECK(atomic_load(&global_stats.reap_fallback) == 0,
          "and the hand-off is not counted as a fallback");
  }

  /* A client whose owner cannot be handed the end (the wake fails, or no
   * owner) is ended from here, and each such end is counted. */
  {
    proxy_map_ent_t ent5;
    proxy_fd_ent_t fa, fb;

    memset(&ent5, 0, sizeof(ent5));
    mk(&ent5, &fa, 0, EP);
    mk(&ent5, &fb, 0, EP);
    pstruct.ns = &pstruct;
    n_freed = 0;
    wake_rc = -1;
    pd_reap_respond(&fa, SP_REAP_PD_IDLE_TIMEOUT);
    wake_rc = 0;
    owner_rc = -1;
    pd_reap_respond(&fb, SP_REAP_SSE_CAP);
    owner_rc = 3;
    pstruct.ns = NULL;
    CHECK(fa.reap_resp == SP_REAP_NONE && was(freed, n_freed, &fa) &&
          fb.reap_resp == SP_REAP_NONE && !was(freed, n_freed, &fb),
          "a failed wake and a missing owner are ended from the health thread");
    CHECK(atomic_load(&global_stats.reap_fallback) == 2,
          "and both are counted (%llu)",
          (unsigned long long)atomic_load(&global_stats.reap_fallback));
  }

  /* What that fallback writes for a refusal: the plain text, which names its
   * stage, and nothing of the request, whatever the request holds: no
   * request ID, no admission header, no wait. An ending that is not a
   * refusal is written as it is, with no stage. */
  {
    static const char want_q[] =
      "HTTP/1.1 504 Gateway Timeout\r\n"
      "X-Loxilb-Refusal-Stage: queue\r\n"
      "Content-Type: application/json\r\n"
      "Content-Length: 35\r\n"
      "Retry-After: 1\r\n"
      "Connection: close\r\n"
      "\r\n"
      "{\"error\":\"admission_queue_timeout\"}";
    static const uint8_t fc_kinds[] = { SP_REAP_FC_QUEUE_TIMEOUT, SP_REAP_FC_DRAINED,
                                        SP_REAP_FC_SHED, SP_REAP_FC_TTL };
    static const char *const fc_codes[] = { "admission_queue_timeout", "admission_drained",
                                            "admission_shed", "admission_ttl_expired" };
    proxy_map_ent_t ent6;
    proxy_fd_ent_t q, pk, idle, fcq[4];
    char got[1024];
    ssize_t n;
    size_t i;

    memset(&ent6, 0, sizeof(ent6));
    mk(&ent6, &q, 0, EP);
    mk(&ent6, &pk, 0, EP);
    mk(&ent6, &idle, 0, EP);
    /* Every request here has an ID of its own, and the queue ending says it
     * was classed and has waited: none of it may reach the wire. */
    snprintf(q.vllm_request_id, sizeof(q.vllm_request_id), "rid-reap-1");
    snprintf(q.resp_request_id, sizeof(q.resp_request_id), "rid-reap-previous");
    q.adm_class_set = 1;
    q.fc.q_enqueue_ns = 1;
    snprintf(pk.vllm_request_id, sizeof(pk.vllm_request_id), "rid-reap-2");
    snprintf(idle.vllm_request_id, sizeof(idle.vllm_request_id), "rid-reap-3");
    pstruct.ns = &pstruct;
    owner_rc = -1;

    pd_reap_respond(&q, SP_REAP_FC_QUEUE_TIMEOUT);
    n = recv(peer[q.fd], got, sizeof(got) - 1, MSG_DONTWAIT);
    got[n > 0 ? n : 0] = '\0';
    CHECK(n == (ssize_t)sizeof(want_q) - 1 && !strcmp(got, want_q),
          "a queue timeout ended from the health thread: its plain text, byte for byte (%zd bytes)", n);
    CHECK(!strstr(got, "X-Request-Id") && !strstr(got, "rid-reap") &&
          !strstr(got, "X-Loxilb-Admission-") && !strstr(got, "queued_ms"),
          "with the stage and nothing of the request: no ID, no admission header, no wait");

    for (i = 0; i < sizeof(fc_kinds); i++) {
      char want_body[64];

      mk(&ent6, &fcq[i], 0, EP);
      snprintf(fcq[i].vllm_request_id, sizeof(fcq[i].vllm_request_id), "rid-reap-fc-%zu", i);
      snprintf(want_body, sizeof(want_body), "\r\n\r\n{\"error\":\"%s\"}", fc_codes[i]);
      pd_reap_respond(&fcq[i], fc_kinds[i]);
      n = recv(peer[fcq[i].fd], got, sizeof(got) - 1, MSG_DONTWAIT);
      got[n > 0 ? n : 0] = '\0';
      CHECK(n > 0 && strstr(got, "\r\nX-Loxilb-Refusal-Stage: queue\r\n") &&
            strstr(got, want_body) && !strstr(got, "X-Request-Id") &&
            !strstr(got, "X-Loxilb-Admission-"),
            "%s from the health thread: stage queue only", fc_codes[i]);
    }

    pd_reap_respond(&pk, SP_REAP_PD_PARK_TIMEOUT);
    n = recv(peer[pk.fd], got, sizeof(got) - 1, MSG_DONTWAIT);
    got[n > 0 ? n : 0] = '\0';
    CHECK(n > 0 && strstr(got, "\r\nX-Loxilb-Refusal-Stage: queue\r\n") &&
          !strstr(got, "X-Request-Id") &&
          strstr(got, "\r\n\r\n{\"error\":\"pd_admission_park_timeout\"}"),
          "a P/D park timeout from the health thread: stage queue, no request ID");

    pd_reap_respond(&idle, SP_REAP_PD_IDLE_TIMEOUT);
    n = recv(peer[idle.fd], got, sizeof(got) - 1, MSG_DONTWAIT);
    got[n > 0 ? n : 0] = '\0';
    CHECK(n > 0 && strstr(got, "{\"error\":\"pd_idle_timeout\"}") &&
          !strstr(got, "X-Loxilb-Refusal-") && !strstr(got, "X-Request-Id"),
          "a P/D idle timeout is not a refusal: no stage, no request ID");

    owner_rc = 3;
    pstruct.ns = NULL;
  }

  printf("%d checks, %d failures\n", checks, failures);
  return failures ? 1 : 0;
}
