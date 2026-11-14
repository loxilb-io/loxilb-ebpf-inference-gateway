/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 *
 * Endpoint Picker (EPP) side table and completion wake — see sockproxy_epp.h.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>
#include <time.h>

#include "log.h"
#include "uthash.h"
#include "notify.h"
#include "sockproxy.h"
#include "sockproxy_internal.h"
#include "sockproxy_epp.h"
#include "sockproxy_refusal_mark.h"

struct epp_pending {
  uint64_t sid;
  int      fd;
  uint64_t gen;
  uint64_t at_ns;
  struct epp_result r;      /* the pointer fields own heap copies */
  UT_hash_handle hh;
};

static pthread_mutex_t epp_lock = PTHREAD_MUTEX_INITIALIZER;
static epp_pending_t *epp_table;
static int epp_n;

uint64_t
epp_now_ns(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static char *
epp_dup(const char *s, int n)
{
  char *d;
  if (!s || n <= 0) return NULL;
  d = malloc((size_t)n + 1);
  if (!d) return NULL;
  memcpy(d, s, (size_t)n);
  d[n] = '\0';
  return d;
}

static void
epp_result_free_bufs(struct epp_result *r)
{
  free((void *)r->imm_body);
  free((void *)r->hdr_set);
  free((void *)r->hdr_del);
  free((void *)r->new_body);
  r->imm_body = r->hdr_set = r->hdr_del = r->new_body = NULL;
}

int
proxy_epp_complete(void *ns, int fd, uint64_t gen, uint64_t sid,
                   const struct epp_result *r)
{
  epp_pending_t *p;
  uint64_t reg_gen = 0;
  int owner;

  if (!ns || fd <= 0 || sid == 0 || !r) return -1;
  /* The fd must still be the registration the submit saw: a recycled slot
   * (gen bumped) or a closed fd has nobody waiting for this decision. */
  if (!notify_priv_of_fd(ns, fd, &reg_gen) || reg_gen != gen) {
    log_debug("[EPP] complete sid=%llu fd=%d gen=%llu: slot gone (reg gen %llu) - dropped",
              (unsigned long long)sid, fd, (unsigned long long)gen,
              (unsigned long long)reg_gen);
    return -2;
  }
  p = calloc(1, sizeof(*p));
  if (!p) return -1;
  p->sid = sid;
  p->fd = fd;
  p->gen = gen;
  p->at_ns = epp_now_ns();
  p->r.status = r->status;
  p->r.ncands = r->ncands < 0 ? 0 : (r->ncands > EPP_MAX_CANDS ? EPP_MAX_CANDS : r->ncands);
  for (int i = 0; i < p->r.ncands; i++) {
    strncpy(p->r.cands[i], r->cands[i], EPP_CAND_LEN - 1);
    p->r.cands[i][EPP_CAND_LEN - 1] = '\0';
  }
  p->r.imm_code = r->imm_code;
  p->r.imm_body = epp_dup(r->imm_body, r->imm_body_len);
  p->r.imm_body_len = p->r.imm_body ? r->imm_body_len : 0;
  p->r.hdr_set = epp_dup(r->hdr_set, r->hdr_set_len);
  p->r.hdr_set_len = p->r.hdr_set ? r->hdr_set_len : 0;
  p->r.hdr_del = epp_dup(r->hdr_del, r->hdr_del_len);
  p->r.hdr_del_len = p->r.hdr_del ? r->hdr_del_len : 0;
  p->r.new_body = epp_dup(r->new_body, r->new_body_len);
  p->r.new_body_len = p->r.new_body ? r->new_body_len : 0;

  pthread_mutex_lock(&epp_lock);
  {
    epp_pending_t *old = NULL;
    HASH_FIND(hh, epp_table, &sid, sizeof(sid), old);
    if (old) {  /* a second completion for one stream: the last one wins */
      HASH_DEL(epp_table, old);
      epp_n--;
      epp_result_free_bufs(&old->r);
      free(old);
    }
    HASH_ADD(hh, epp_table, sid, sizeof(sid), p);
    epp_n++;
  }
  pthread_mutex_unlock(&epp_lock);

  owner = notify_owner_thr(ns, fd);
  if (owner < 0 || notify_wake_worker(ns, owner, fd) != 0) {
    log_warn("[EPP] complete sid=%llu fd=%d: owner worker %d could not be woken; "
             "the reaper collects it", (unsigned long long)sid, fd, owner);
    return -3;
  }
  return 0;
}

int
proxy_epp_evict(void *ns, int fd, uint64_t gen, uint64_t sid, int code)
{
  proxy_fd_ent_t *pfe;
  uint64_t reg_gen = 0;
  int rc = -2;

  if (!ns || fd <= 0 || sid == 0) return -1;
  PROXY_LOCK();
  pfe = (proxy_fd_ent_t *)notify_priv_of_fd(ns, fd, &reg_gen);
  if (pfe && pfe->fd == fd && reg_gen == gen && pfe->epp_sid == sid &&
      pfe->pd_phase != PD_PHASE_ERROR && !pfe->epp_reported) {
    /* The EPP ended the stream with its answer: nothing more goes to it. */
    pfe->epp_reported = 1;
    pfe->pd_phase = PD_PHASE_ERROR;   /* out of every reaper pass */
    log_info("[EPP] fd=%d sid=%llu evicted by the EPP (%d) %s", fd,
             (unsigned long long)sid, code,
             pfe->epp_hdrs_reported ? "mid-response: cutting the relay"
                                    : "before the response: answering 429");
    sp_reap_request(pfe, pfe->epp_hdrs_reported ? SP_REAP_EPP_EVICT_CUT
                                                : SP_REAP_EPP_EVICT_429);
    rc = 0;
  }
  PROXY_UNLOCK();
  return rc;
}

epp_pending_t *
epp_pending_take(uint64_t sid, int fd, uint64_t gen)
{
  epp_pending_t *p = NULL;

  if (sid == 0) return NULL;
  pthread_mutex_lock(&epp_lock);
  HASH_FIND(hh, epp_table, &sid, sizeof(sid), p);
  if (p) {
    HASH_DEL(epp_table, p);
    epp_n--;
  }
  pthread_mutex_unlock(&epp_lock);
  if (p && (p->fd != fd || p->gen != gen)) {
    log_warn("[EPP] take sid=%llu: entry is for fd=%d gen=%llu, caller fd=%d gen=%llu - dropped",
             (unsigned long long)sid, p->fd, (unsigned long long)p->gen, fd,
             (unsigned long long)gen);
    epp_pending_free(p);
    return NULL;
  }
  return p;
}

const struct epp_result *
epp_pending_result(const epp_pending_t *p)
{
  return p ? &p->r : NULL;
}

void
epp_pending_free(epp_pending_t *p)
{
  if (!p) return;
  epp_result_free_bufs(&p->r);
  free(p);
}

void
epp_pending_drop(uint64_t sid)
{
  epp_pending_t *p = NULL;

  if (sid == 0) return;
  pthread_mutex_lock(&epp_lock);
  HASH_FIND(hh, epp_table, &sid, sizeof(sid), p);
  if (p) {
    HASH_DEL(epp_table, p);
    epp_n--;
  }
  pthread_mutex_unlock(&epp_lock);
  epp_pending_free(p);
}

int
epp_pending_count(void)
{
  int n;
  pthread_mutex_lock(&epp_lock);
  n = epp_n;
  pthread_mutex_unlock(&epp_lock);
  return n;
}

int
epp_pending_reap(uint64_t max_age_ns)
{
  epp_pending_t *p, *tmp;
  uint64_t now = epp_now_ns();
  int freed = 0;

  pthread_mutex_lock(&epp_lock);
  HASH_ITER(hh, epp_table, p, tmp) {
    if (now - p->at_ns >= max_age_ns) {
      HASH_DEL(epp_table, p);
      epp_n--;
      epp_result_free_bufs(&p->r);
      free(p);
      freed++;
    }
  }
  pthread_mutex_unlock(&epp_lock);
  if (freed)
    log_warn("[EPP] reaped %d orphaned decision(s)", freed);
  return freed;
}

static const char *
epp_reason(int status)
{
  switch (status) {
  case 400: return "Bad Request";
  case 403: return "Forbidden";
  case 404: return "Not Found";
  case 413: return "Payload Too Large";
  case 429: return "Too Many Requests";
  case 500: return "Internal Server Error";
  case 502: return "Bad Gateway";
  case 503: return "Service Unavailable";
  case 504: return "Gateway Timeout";
  default:  return "Error";
  }
}

void
epp_send_error(proxy_fd_ent_t *pfe, int status, const char *code, const char *detail)
{
  char body[512];
  char resp[1024];
  int blen, n;

  blen = snprintf(body, sizeof(body), "{\"error\":\"%s\",\"detail\":\"%s\"}\r\n",
                  code, detail ? detail : "");
  if (blen < 0 || blen >= (int)sizeof(body)) blen = 0;
  n = snprintf(resp, sizeof(resp),
               "HTTP/1.1 %d %s\r\n"
               "Content-Type: application/json\r\n"
               "Content-Length: %d\r\n"
               "Connection: close\r\n"
               "\r\n%s", status, epp_reason(status), blen, blen ? body : "");
  if (n > 0 && n < (int)sizeof(resp)) {
    pfe->lb_err_body_sent = 1;
    if (sp_send_local_outage(pfe, (uint16_t)status, resp, (size_t)n) != 0)
      log_error("[EPP] fd=%d failed to send %d %s", pfe->fd, status, code);
  }
  log_info("[EPP] fd=%d answered %d %s: %s", pfe->fd, status, code, detail ? detail : "");
}

/* Whether a "name: value\r\n" line of an EPP header set is the request-ID
 * header (the whole name, any case). */
static int
epp_hdr_is_request_id(const char *line, size_t len)
{
  static const char name[] = SP_REFUSAL_RID_HDR;

  return len > sizeof(name) - 1 && line[sizeof(name) - 1] == ':' &&
         strncasecmp(line, name, sizeof(name) - 1) == 0;
}

/* The Endpoint Picker's immediate answer, relayed with its own headers and
 * body. Like every answer the gateway writes it names the request by the
 * request's own ID, once (sockproxy_refusal_mark.h): when the request has
 * one that can be echoed, an X-Request-Id the EPP set is left out and the
 * request's line is written here, whatever the answer's length; when it has
 * none, the EPP's headers go out as they are. */
void
epp_send_immediate(proxy_fd_ent_t *pfe, const struct epp_result *r)
{
  const char *rid = SP_REFUSAL_LIVE_RID(pfe);
  int own = sp_refusal_rid_ok(rid);
  int hlen = r->hdr_set && r->hdr_set_len > 0 ? r->hdr_set_len : 0;
  int blen = r->imm_body && r->imm_body_len > 0 ? r->imm_body_len : 0;
  size_t cap = 256 + SP_REFUSAL_MARK_MAX + (size_t)hlen + (size_t)blen;
  char *resp = malloc(cap);
  int n, m, off = 0;

  if (!resp) return;
  n = snprintf(resp, cap, "HTTP/1.1 %d %s\r\n", r->imm_code, epp_reason(r->imm_code));
  if (own && n > 0 && (size_t)n < cap) {
    m = snprintf(resp + n, cap - (size_t)n, SP_REFUSAL_RID_HDR ": %s\r\n", rid);
    n = m > 0 && (size_t)m < cap - (size_t)n ? n + m : -1;
  }
  while (n > 0 && off < hlen) {
    const char *line = r->hdr_set + off;
    const char *eol = memchr(line, '\n', (size_t)(hlen - off));
    size_t len = eol ? (size_t)(eol - line) + 1 : (size_t)(hlen - off);

    off += (int)len;
    if (own && epp_hdr_is_request_id(line, len))
      continue;
    if ((size_t)n + len >= cap) {
      n = -1;
      break;
    }
    memcpy(resp + n, line, len);
    n += (int)len;
  }
  if (n > 0) {
    m = snprintf(resp + n, cap - (size_t)n,
                 "Content-Length: %d\r\nConnection: close\r\n\r\n", blen);
    n = m > 0 && (size_t)m < cap - (size_t)n ? n + m : -1;
  }
  if (n > 0 && (size_t)n + (size_t)blen < cap) {
    if (blen > 0) {
      memcpy(resp + n, r->imm_body, (size_t)blen);
      n += blen;
    }
    resp[n] = '\0';
    pfe->lb_err_body_sent = 1;
    /* An outage answer, as sp_send_local_outage records and sends one; the
     * request's ID is already in the head built above. */
    proxy_record_local_completion(pfe, (uint16_t)r->imm_code);
    if (proxy_send_local_response(pfe, resp, (size_t)n) != 0)
      log_error("[EPP] fd=%d failed to send the EPP's %d", pfe->fd, r->imm_code);
  }
  free(resp);
  log_info("[EPP] fd=%d sid=%llu EPP immediate response %d relayed", pfe->fd,
           (unsigned long long)pfe->epp_sid, r->imm_code);
}

void
epp_request_end(proxy_fd_ent_t *pfe)
{
  if (!pfe) return;
  free(pfe->epp_resp_head);
  pfe->epp_resp_head = NULL;
  pfe->epp_resp_head_len = 0;
  if (pfe->epp_sid == 0) return;
  if (!pfe->epp_reported) {
    pfe->epp_reported = 1;
    llb_epp_resp_event(pfe->epp_sid, EPP_EV_ABORT, 0, NULL, 0, NULL, 0);
    log_debug("[EPP] fd=%d sid=%llu abort reported", pfe->fd, (unsigned long long)pfe->epp_sid);
  }
  epp_pending_drop(pfe->epp_sid);
  pfe->epp_sid = 0;
  pfe->epp_decided = 0;
  /* The pin belongs to the request that just ended. The next request on
   * this kept connection starts unpinned, so a submit refused before a
   * stream id exists (FailOpen) still reaches the P/D ladder's rewrite. */
  pfe->epp_pinned = 0;
  pfe->epp_deadline_ns = 0;
  pfe->epp_hdrs_reported = 0;
  pfe->epp_served[0] = '\0';
}

void
epp_resp_head_feed(proxy_fd_ent_t *pfe, const void *msg, size_t len)
{
  size_t room, n;

  if (!pfe || pfe->epp_sid == 0 || pfe->epp_hdrs_reported || len == 0) return;
  if (!pfe->epp_resp_head) {
    pfe->epp_resp_head = malloc(EPP_RESP_HEAD_MAX);
    if (!pfe->epp_resp_head) return;
    pfe->epp_resp_head_len = 0;
  }
  room = EPP_RESP_HEAD_MAX - pfe->epp_resp_head_len;
  n = len < room ? len : room;
  memcpy(pfe->epp_resp_head + pfe->epp_resp_head_len, msg, n);
  pfe->epp_resp_head_len += (uint16_t)n;
}

void
epp_report_resp_headers(proxy_fd_ent_t *pfe, int status)
{
  const uint8_t *head = NULL;
  size_t head_len = 0;

  if (!pfe || pfe->epp_sid == 0 || pfe->epp_hdrs_reported || pfe->epp_reported) return;
  pfe->epp_hdrs_reported = 1;
  if (pfe->epp_resp_head) {
    const uint8_t *end = memmem(pfe->epp_resp_head, pfe->epp_resp_head_len, "\r\n\r\n", 4);
    head = pfe->epp_resp_head;
    head_len = end ? (size_t)(end - head) + 2 : pfe->epp_resp_head_len;
  }
  llb_epp_resp_event(pfe->epp_sid, EPP_EV_RESP_HEADERS, status,
                     (char *)head, (int)head_len,
                     pfe->epp_served, (int)strlen(pfe->epp_served));
  log_debug("[EPP] fd=%d sid=%llu response headers reported: %d, served %s (%zu head bytes)",
            pfe->fd, (unsigned long long)pfe->epp_sid, status, pfe->epp_served, head_len);
  free(pfe->epp_resp_head);
  pfe->epp_resp_head = NULL;
  pfe->epp_resp_head_len = 0;
}

void
epp_report_resp_eos(proxy_fd_ent_t *pfe)
{
  if (!pfe || pfe->epp_sid == 0 || pfe->epp_reported) return;
  if (!pfe->epp_hdrs_reported) {
    /* A response that ended before its headers were seen complete
     * (unframed, cut short): report what there is first, in order. */
    epp_report_resp_headers(pfe, pfe->metric_response_status);
  }
  pfe->epp_reported = 1;
  llb_epp_resp_event(pfe->epp_sid, EPP_EV_RESP_EOS, 0, NULL, 0, NULL, 0);
  log_debug("[EPP] fd=%d sid=%llu end of stream reported", pfe->fd, (unsigned long long)pfe->epp_sid);
}
