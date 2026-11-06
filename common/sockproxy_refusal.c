/* SPDX-License-Identifier: BSD-3-Clause
 * Native P/D body/preparation refusals: bounded, owner-worker output.
 * A timeout or fatal I/O error closes without pretending the reply completed.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <openssl/ssl.h>
#include "uthash.h"
#include "log.h"
#include "notify.h"
#include "sockproxy_internal.h"
#include "sockproxy_hold.h"
#include "sockproxy_refusal.h"

/* Handles, never borrowed pfe pointers. Teardown/reuse invalidates the
 * registration generation. Only the owner tick removes/frees these nodes. */
typedef struct reply_watch {
  int fd;
  uint64_t gen;
  struct reply_watch *next;
} reply_watch_t;
static _Thread_local reply_watch_t *reply_watches;

static uint64_t
reply_now_ns(void)
{
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec;
}

static int
reply_fail(proxy_fd_ent_t *pfe, const char *reason)
{
  log_warn("[PD_REFUSAL_SEND_FAILED] fd=%d reason=%s accepted=%u required=%u",
           pfe->fd, reason, pfe->pd_reply.off, pfe->pd_reply.len);
  pfe->pd_reply.active = 0;
  return -1;
}

/* Discard upload tails without waiting or monopolizing the owner. A finite
 * byte budget per readiness event also bounds work for continuously readable
 * malicious uploads. The owner tick closes a slow tail after 200 ms. */
static int
reply_drain(proxy_fd_ent_t *pfe)
{
  sp_pd_reply_t *r = &pfe->pd_reply;
  r->wait = NOTI_TYPE_IN;
  uint8_t buffer[8192];
  for (int i = 0; i < 16 && r->drain_remaining; i++) {
    size_t want = r->drain_remaining < sizeof(buffer) ?
                  r->drain_remaining : sizeof(buffer);
    ssize_t n = pfe->ssl ? SSL_read(pfe->ssl, buffer, (int)want) :
                         recv(pfe->fd, buffer, want, MSG_DONTWAIT);
    if (n > 0) {
      r->drain_remaining -= (size_t)n;
      continue;
    }
    if (n < 0) {
      if (pfe->ssl) {
        int error = SSL_get_error(pfe->ssl, (int)n);
        if (error == SSL_ERROR_WANT_READ ||
            (error == SSL_ERROR_SYSCALL && errno == EINTR))
          return 1;
      } else if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
        return 1;
      }
    }
    log_debug("[PD_REFUSAL_DRAIN_DONE] fd=%d reason=input_end remaining=%zu",
              pfe->fd, r->drain_remaining);
    r->active = 0; /* EOF or terminal input error: output already completed */
    return 0;
  }
  if (r->drain_remaining)
    return 1;
  log_debug("[PD_REFUSAL_DRAIN_DONE] fd=%d reason=byte_cap", pfe->fd);
  r->active = 0;
  return 0;
}

/* 16 attempts bounds per-event work even with pathological one-byte writes.
 * A positive partial SSL write advances; a WANT retry uses identical args. */
static int
reply_flush(proxy_fd_ent_t *pfe)
{
  sp_pd_reply_t *r = &pfe->pd_reply;
  if (r->draining)
    return reply_drain(pfe);
  if (reply_now_ns() >= r->deadline_ns)
    return reply_fail(pfe, "timeout");
  for (int i = 0; i < 16 && r->off < r->len; i++) {
    size_t remaining = r->len - r->off;
    ssize_t n;
    r->wait = NOTI_TYPE_OUT;
    if (pfe->ssl) {
      n = SSL_write(pfe->ssl, r->bytes + r->off, (int)remaining);
      if (n <= 0) {
        int error = SSL_get_error(pfe->ssl, (int)n);
        if (error == SSL_ERROR_WANT_READ)
          r->wait = NOTI_TYPE_IN;
        else if (error != SSL_ERROR_WANT_WRITE &&
                 !(error == SSL_ERROR_SYSCALL && errno == EINTR))
          return reply_fail(pfe, "tls_write");
        return 1;
      }
    } else {
      n = send(pfe->fd, r->bytes + r->off, remaining,
               MSG_DONTWAIT | MSG_NOSIGNAL);
      if (n <= 0) {
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
          return 1;
        return reply_fail(pfe, "socket_write");
      }
    }
    if ((size_t)n > remaining)
      return reply_fail(pfe, "invalid_write_count");
    r->off += (uint16_t)n;
  }
  if (r->off != r->len)
    return 1;

  /* Only this full-completion path half-closes successfully. A TLS close
   * alert on an already-buffered request is best effort, never waited for. */
  log_debug("[PD_REFUSAL_FLUSHED] fd=%d accepted=%u required=%u",
            pfe->fd, r->off, r->len);
  if (!r->drain_remaining && pfe->ssl)
    (void)SSL_shutdown(pfe->ssl);
  (void)shutdown(pfe->fd, SHUT_WR);
  if (r->drain_remaining) {
    r->draining = 1;
    r->deadline_ns = reply_now_ns() + SP_PD_REPLY_TIMEOUT_NS;
    return reply_drain(pfe);
  }
  r->active = 0;
  return 0;
}

int
sp_pd_send_refusal(proxy_fd_ent_t *pfe, int stage, uint16_t status,
                    const char *code, const void *response, size_t len,
                    size_t drain_remaining)
{
  sp_pd_reply_t *r = &pfe->pd_reply;
  if (r->active)
    return 1; /* terminal: never replace TLS retry bytes or record twice */
  proxy_note_local_refusal(pfe, status);
  proxy_record_local_deny(pfe, stage, status, code);
  pfe->lb_err_body_sent = 1;
  if (!response || !len || len > sizeof(r->bytes))
    return reply_fail(pfe, "response_size");
  /* Preserve the shared sender's begun-answer invariant. This is a fresh
   * pre-connect refusal, never a second status line inside an older answer. */
  if (sp_answer_is_status_line(response, len) && sp_answer_started(pfe)) {
    sp_end_started_answer(pfe, response, len);
    return -1;
  }
  memcpy(r->bytes, response, len);
  r->len = (uint16_t)len;
  r->off = 0;
  r->draining = 0;
  r->active = 1;
  r->deadline_ns = reply_now_ns() + SP_PD_REPLY_TIMEOUT_NS;
  /* A positive unread-body hint enables linger. Do not close exactly at
   * Content-Length: curl may still be sending TLS records/close_notify after
   * those bytes while consuming the early response. EOF, 4 MiB or the timer
   * ends the discard state; no subsequent request is parsed or forwarded. */
  r->drain_remaining = drain_remaining ? 4 * 1024 * 1024 : 0;
  int rc = reply_flush(pfe);
  if (rc != 1)
    return rc;
  if (!proxy_struct || !proxy_struct->ns || notify_worker_id() < 0)
    return reply_fail(pfe, "no_owner");
  reply_watch_t *watch = malloc(sizeof(*watch));
  if (!watch)
    return reply_fail(pfe, "watch_alloc");
  *watch = (reply_watch_t){ .fd = pfe->fd, .gen = pfe->gen,
                          .next = reply_watches };
  reply_watches = watch;
  pfe->read_paused = 1;
  /* No RDHUP subscription: a peer FIN must not cancel its owed response or
   * spin on a paused upload. Fatal HUP/ERR is always reported by epoll. */
  if (sp_notify_arm(proxy_struct->ns, pfe->fd, r->wait, pfe, pfe->gen) != 0) {
    reply_watches = watch->next;
    free(watch);
    return reply_fail(pfe, "arm");
  }
  return 1;
}

void
sp_pd_refusal_event(proxy_fd_ent_t *pfe, int type)
{
  if (!pfe->pd_reply.active || !(type & pfe->pd_reply.wait))
    return;
  int rc = reply_flush(pfe);
  if (rc == 1 && sp_notify_arm(proxy_struct->ns, pfe->fd,
                               pfe->pd_reply.wait, pfe, pfe->gen) == 0)
    return;
  if (rc == 1)
    (void)reply_fail(pfe, "rearm");
  /* Owner callback, no proxy/entry locks held. No pfe access after delete. */
  notify_delete_ent(proxy_struct->ns, pfe->fd, 0);
}

void
sp_pd_refusal_tick(void)
{
  if (!reply_watches)
    return;
  uint64_t now = reply_now_ns();
  reply_watch_t **link = &reply_watches;
  while (*link) {
    reply_watch_t *watch = *link;
    uint64_t gen = 0;
    proxy_fd_ent_t *pfe = notify_priv_of_fd(proxy_struct->ns, watch->fd, &gen);
    int live = pfe && gen == watch->gen && pfe->gen == gen &&
               pfe->fd == watch->fd && pfe->pd_reply.active;
    if (live && now < pfe->pd_reply.deadline_ns) {
      link = &watch->next;
      continue;
    }
    /* Unlink BEFORE teardown: its callbacks may enqueue another refusal. */
    *link = watch->next;
    free(watch);
    if (live) {
      if (pfe->pd_reply.draining) {
        log_debug("[PD_REFUSAL_DRAIN_DONE] fd=%d reason=timeout remaining=%zu",
                  pfe->fd, pfe->pd_reply.drain_remaining);
        pfe->pd_reply.active = 0;
      } else {
        (void)reply_fail(pfe, "timeout");
      }
      notify_delete_ent(proxy_struct->ns, pfe->fd, 0);
    }
  }
}
