/*
 * Copyright (c) 2026 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 *
 * sockproxy_hc.c - half-close observation: the stateful half.
 *
 * Two questions are measured here, both before anything is changed to answer
 * them.
 *
 * What a client's FIN looks like. A client that half-closes after its request
 * sends the FIN right behind the last request segment; a client that cancels
 * sends it after at least a time to first token. The time from the request's
 * completion to the FIN separates the two, and it is sampled once per FIN, at
 * the first place the proxy sees it: the read path's EOF, or an RDHUP while
 * the client's reads are paused. A FIN seen again later (the EOF branch runs
 * twice for one FIN, and a held client meets its EOF again when its reads
 * resume) is not counted again, or the held ones would land late, among the
 * cancels. The sample is taken only where the counters it needs are right: no
 * TLS, and the kernel never given a direction of the connection. Outside that
 * the FIN is counted by reason, and the TLS exits are counted by how they end.
 *
 * How a response makes progress towards the client. Per response, the time
 * from handing the request to the backend to the first successful write to
 * the client, and the longest time between two writes. A response is done
 * when its framer saw it end and the client's relay cache is empty, not when
 * it was framed: the framer reads bytes before the socket takes them, and a
 * client that stops reading leaves its longest gap in the cache drain.
 *
 * Observation only. Nothing here changes what is relayed or when a connection
 * closes, and nothing asserts: an assert in a worker ends the whole data plane.
 */
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

/* uthash precedes sockproxy.h (UT_hash_handle) */
#include "uthash.h"
#include "log.h"
#include "sockproxy_internal.h"
#include "sockproxy_metrics.h"
#include "sockproxy_hc.h"

_Static_assert(HC_SSL_ERR_SSL == SSL_ERROR_SSL, "HC_SSL_ERR_SSL");
_Static_assert(HC_SSL_ERR_SYSCALL == SSL_ERROR_SYSCALL, "HC_SSL_ERR_SYSCALL");

/* Each family counts a connection once. */
#define HC_COUNTED_TLS   0x1
#define HC_COUNTED_RESET 0x2

#define HC_FIN_B  (HC_FIN_NB - 1)
#define HC_PROG_B (HC_PROG_NB - 1)

static struct {
  _Atomic uint64_t fin_gap_bucket[HC_ENTRY_SAMPLED][HC_STREAM_MAX][HC_FIN_B];
  _Atomic uint64_t fin_gap_sum_us[HC_ENTRY_SAMPLED][HC_STREAM_MAX];
  _Atomic uint64_t fin_gap_count[HC_ENTRY_SAMPLED][HC_STREAM_MAX];
  _Atomic uint64_t fin_total[HC_ENTRY_MAX][HC_OUT_MAX];
  _Atomic uint64_t accel_early_fin;
  _Atomic uint64_t tls_fin[HC_TLS_MAX][2];
  _Atomic uint64_t client_reset;
  _Atomic uint64_t ua[HC_UA_MAX];
  _Atomic uint64_t first_gap_bucket[HC_STREAM_MAX][HC_PROG_B];
  _Atomic uint64_t first_gap_sum_us[HC_STREAM_MAX];
  _Atomic uint64_t first_gap_count[HC_STREAM_MAX];
  _Atomic uint64_t max_gap_bucket[HC_STREAM_MAX][HC_PROG_B];
  _Atomic uint64_t max_gap_sum_us[HC_STREAM_MAX];
  _Atomic uint64_t max_gap_count[HC_STREAM_MAX];
} hc_stats;

/* The snapshot spells the dimensions as numbers (it is mirrored in Go); these
 * hold them to the enums. */
#define HC_DIM(field, n) \
  _Static_assert(sizeof(((proxy_metrics_snapshot_t *)0)->field) == \
                 sizeof(uint64_t) * (n), #field)
HC_DIM(hc_fin_gap_bucket, HC_ENTRY_SAMPLED * HC_STREAM_MAX * HC_FIN_B);
HC_DIM(hc_fin_gap_sum_us, HC_ENTRY_SAMPLED * HC_STREAM_MAX);
HC_DIM(hc_fin_gap_count, HC_ENTRY_SAMPLED * HC_STREAM_MAX);
HC_DIM(hc_fin_total, HC_ENTRY_MAX * HC_OUT_MAX);
HC_DIM(hc_tls_fin, HC_TLS_MAX * 2);
HC_DIM(hc_user_agent, HC_UA_MAX);
HC_DIM(hc_first_gap_bucket, HC_STREAM_MAX * HC_PROG_B);
HC_DIM(hc_first_gap_sum_us, HC_STREAM_MAX);
HC_DIM(hc_first_gap_count, HC_STREAM_MAX);
HC_DIM(hc_max_gap_bucket, HC_STREAM_MAX * HC_PROG_B);
HC_DIM(hc_max_gap_sum_us, HC_STREAM_MAX);
HC_DIM(hc_max_gap_count, HC_STREAM_MAX);
#undef HC_DIM

static inline void
hc_inc(_Atomic uint64_t *c)
{
  atomic_fetch_add_explicit(c, 1, memory_order_relaxed);
}

static void
hc_observe(_Atomic uint64_t *bucket, _Atomic uint64_t *sum, _Atomic uint64_t *count,
           const uint64_t *bounds, int nb, uint64_t v_us)
{
  int i;

  for (i = hc_cum_first(bounds, nb, v_us); i < nb - 1; i++) {
    hc_inc(&bucket[i]);
  }
  atomic_fetch_add_explicit(sum, v_us, memory_order_relaxed);
  hc_inc(count);
}

/* Monotonic: these are durations, and the wall clock can step. */
static uint64_t
hc_now_ns(void)
{
  struct timespec ts;

  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static int
hc_owed(proxy_fd_ent_t *c)
{
  return atomic_load_explicit(&c->cresp_forwarded, memory_order_relaxed) >
         atomic_load_explicit(&c->cresp_completed, memory_order_relaxed);
}

static enum hc_stream
hc_stream_of(const proxy_fd_ent_t *c)
{
  return c->hc_stream < HC_STREAM_MAX ? (enum hc_stream)c->hc_stream : HC_STREAM_UNKNOWN;
}

static int
hc_is_client(const proxy_fd_ent_t *c)
{
  return c && c->odir == 0;
}

void
hc_note_accel(proxy_fd_ent_t *client, uint8_t bits)
{
  if (hc_is_client(client)) {
    atomic_fetch_or_explicit(&client->hc_accel, bits, memory_order_relaxed);
  }
}

/* ---- request framer ------------------------------------------------------ */

void
hc_req_begin(proxy_fd_ent_t *c)
{
  c->hc_ua_name = 0;
  c->hc_ua_capture = 0;
  c->hc_ua_seen = 0;
  c->hc_ua_len = 0;
  c->hc_stream = HC_STREAM_UNKNOWN;
}

void
hc_req_header_field(proxy_fd_ent_t *c, const char *at, size_t len)
{
  c->hc_ua_name = (int8_t)hc_ua_name_step(c->hc_ua_name, at, len);
}

void
hc_req_header_field_done(proxy_fd_ent_t *c)
{
  /* The first User-Agent wins; a repeated one is not read. */
  c->hc_ua_capture = c->hc_ua_name == HC_UA_NAME_LEN && !c->hc_ua_seen;
  if (c->hc_ua_capture) {
    c->hc_ua_len = 0;
  }
}

void
hc_req_header_value(proxy_fd_ent_t *c, const char *at, size_t len)
{
  size_t room;

  if (!c->hc_ua_capture) {
    return;
  }
  room = sizeof(c->hc_ua_buf) - c->hc_ua_len;
  if (len > room) {
    len = room;
  }
  memcpy(c->hc_ua_buf + c->hc_ua_len, at, len);
  c->hc_ua_len = (uint8_t)(c->hc_ua_len + len);
}

void
hc_req_header_value_done(proxy_fd_ent_t *c)
{
  if (c->hc_ua_capture) {
    c->hc_ua_seen = 1;
    c->hc_ua_capture = 0;
  }
  c->hc_ua_name = 0;               /* the next header's name starts afresh */
}

void
hc_req_headers_done(proxy_fd_ent_t *c)
{
  c->hc_ua = c->hc_ua_seen ? (uint8_t)hc_ua_classify(c->hc_ua_buf, c->hc_ua_len)
                           : (uint8_t)HC_UA_NONE;
}

void
hc_req_done(proxy_fd_ent_t *c)
{
  c->hc_req_done_ns = hc_now_ns();
  atomic_store_explicit(&c->hc_handoff_pending, 1, memory_order_relaxed);
}

void
hc_note_stream(proxy_fd_ent_t *c, int stream)
{
  if (hc_is_client(c)) {
    c->hc_stream = stream > 0 ? HC_STREAM_YES : stream == 0 ? HC_STREAM_NO : HC_STREAM_UNKNOWN;
  }
}

void
hc_note_park(proxy_fd_ent_t *c, enum hc_entry kind)
{
  if (hc_is_client(c)) {
    c->hc_park = (uint8_t)kind;
  }
}

/* ---- the FIN -------------------------------------------------------------- */

void
hc_fin_seen(proxy_fd_ent_t *c, enum hc_entry entry, int partial)
{
  uint64_t now;
  uint8_t accel;
  enum hc_outcome out;
  int sampled_entry;

  if (!hc_is_client(c) || c->hc_fin_ns != 0 || entry >= HC_ENTRY_MAX) {
    return;
  }
  now = hc_now_ns();
  c->hc_fin_ns = now;

  /* A FIN met while reads were paused mid-request comes before the request
   * is complete: the gap would be negative, so it is counted, not sampled. */
  sampled_entry = entry < HC_ENTRY_SAMPLED;
  accel = atomic_load_explicit(&c->hc_accel, memory_order_relaxed);
  out = hc_classify(c->ssl != NULL, accel, partial || !sampled_entry, sampled_entry,
                    hc_owed(c));
  hc_inc(&hc_stats.fin_total[entry][out]);

  /* The response direction went to the kernel and the request direction did
   * not: the request framer still saw every request, so the gap is good, but
   * the response counters are not. An early FIN here is a half-close that
   * came after the response pair was installed, or raced its installation:
   * no userspace count can tell what is still owed to it. */
  if (sampled_entry && out == HC_OUT_ACCEL && accel == HC_ACCEL_RESP &&
      hc_is_early(c->hc_req_done_ns, now)) {
    hc_inc(&hc_stats.accel_early_fin);
  }

  if (sampled_entry && out == HC_OUT_OWED && c->hc_req_done_ns != 0 &&
      now >= c->hc_req_done_ns) {
    enum hc_stream st = hc_stream_of(c);

    hc_observe(hc_stats.fin_gap_bucket[entry][st], &hc_stats.fin_gap_sum_us[entry][st],
               &hc_stats.fin_gap_count[entry][st], hc_fin_bounds_us, HC_FIN_NB,
               (now - c->hc_req_done_ns) / 1000);
    hc_inc(&hc_stats.ua[c->hc_ua < HC_UA_MAX ? c->hc_ua : HC_UA_OTHER]);
  }
}

enum hc_entry
hc_paused_entry(proxy_fd_ent_t *c)
{
  int j;

  if (c->pd_phase == PD_PHASE_PARKED) {
    if (c->hc_park == HC_ENTRY_SETUP_PARK || c->hc_park == HC_ENTRY_FC_PARK) {
      return (enum hc_entry)c->hc_park;
    }
    return HC_ENTRY_OTHER_PAUSE;
  }
  if (c->qos_parked) {
    return HC_ENTRY_QOS;
  }
  for (j = 0; j < c->n_rfd && j < MAX_PROXY_EP; j++) {
    if (c->rfd_ent[j] && c->rfd_ent[j]->cache_backpressure) {
      return HC_ENTRY_BACKPRESSURE;
    }
  }
  return HC_ENTRY_OTHER_PAUSE;
}

void
hc_tls_fin_seen(proxy_fd_ent_t *c, enum hc_tls_path path)
{
  int early_owed;

  if (!hc_is_client(c) || path >= HC_TLS_MAX) {
    return;
  }
  hc_fin_seen(c, HC_ENTRY_EOF, 0);          /* no-op if the FIN was seen before */
  if (c->hc_counted & HC_COUNTED_TLS) {
    return;
  }
  c->hc_counted |= HC_COUNTED_TLS;
  early_owed = hc_is_early(c->hc_req_done_ns, c->hc_fin_ns) && hc_owed(c);
  hc_inc(&hc_stats.tls_fin[path][early_owed]);
}

void
hc_tls_read_failed(proxy_fd_ent_t *c, int ssl_err, int rval, int err_no)
{
  unsigned long e;
  int reason_eof = 0, path;

  if (!hc_is_client(c)) {
    return;
  }
  e = ERR_peek_error();                     /* peek: the caller's log pops it */
#ifdef SSL_R_UNEXPECTED_EOF_WHILE_READING
  reason_eof = e != 0 && ERR_GET_LIB(e) == ERR_LIB_SSL &&
               ERR_GET_REASON(e) == SSL_R_UNEXPECTED_EOF_WHILE_READING;
#endif
  path = hc_tls_eof_path(ssl_err, rval, e == 0, reason_eof);
  if (path >= 0) {
    hc_tls_fin_seen(c, (enum hc_tls_path)path);
  } else if (rval < 0 && err_no == ECONNRESET) {
    hc_client_reset_seen(c);
  }
}

void
hc_client_reset_seen(proxy_fd_ent_t *c)
{
  if (!hc_is_client(c) || (c->hc_counted & HC_COUNTED_RESET)) {
    return;
  }
  c->hc_counted |= HC_COUNTED_RESET;
  hc_inc(&hc_stats.client_reset);
}

/* A reset that arrived while nothing was reading (reads paused or disarmed)
 * is only visible as the socket's pending error when the connection is torn
 * down. Reading it clears it, so the value read is returned for the caller
 * to hand on (the half-close hold reads EPIPE from it); 0 when not read. */
int
hc_client_reset_check(proxy_fd_ent_t *c)
{
  int err = 0;
  socklen_t len = sizeof(err);

  if (!hc_is_client(c) || c->stype != PROXY_SOCK_ACTIVE || c->fd <= 0 ||
      (c->hc_counted & HC_COUNTED_RESET)) {
    return 0;
  }
  if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0) {
    return 0;
  }
  if (err == ECONNRESET) {
    hc_client_reset_seen(c);
  }
  return err;
}

/* ---- response progress ---------------------------------------------------- */

void
hc_resp_headers(proxy_fd_ent_t *c)
{
  c->hc_resp_active = 1;
}

void
hc_resp_done(proxy_fd_ent_t *c)
{
  /* Atomic: a response the backend ends by closing is completed on the
   * backend's worker without the client's lock. */
  if (hc_is_client(c)) {
    atomic_store_explicit(&c->hc_deliver_pending, 1, memory_order_relaxed);
  }
}

void
hc_prog_write(proxy_fd_ent_t *dst)
{
  uint64_t now;

  if (!dst) {
    return;
  }
  if (dst->odir != 0) {
    /* A write towards a backend: the first one after a request was framed is
     * where it was handed over. The client entry is not locked here; the two
     * fields are atomic for that, and the client is found through the leg's
     * link without a generation check, so a shell recycled under it can take
     * a stamp meant for another connection. That costs one wrong sample here.
     * Nothing may decide from this stamp: a hold bound that needs the handoff
     * time must take its own, under the client's lock. */
    proxy_fd_ent_t *c = dst->n_rfd > 0 ? dst->rfd_ent[0] : NULL;

    if (hc_is_client(c) &&
        atomic_exchange_explicit(&c->hc_handoff_pending, 0, memory_order_relaxed)) {
      atomic_store_explicit(&c->hc_handoff_ns, hc_now_ns(), memory_order_relaxed);
    }
    return;
  }

  /* A write towards the client counts once an answer is under way (the
   * framer does not report interim responses), so a 100 Continue alone is not
   * progress. */
  if (!dst->hc_resp_active) {
    return;
  }
  now = hc_now_ns();
  if (dst->hc_first_write_ns == 0) {
    dst->hc_first_write_ns = now;
    dst->hc_resp_handoff_ns =
        atomic_exchange_explicit(&dst->hc_handoff_ns, 0, memory_order_relaxed);
  } else if (now - dst->hc_last_write_ns > dst->hc_max_gap_ns) {
    dst->hc_max_gap_ns = now - dst->hc_last_write_ns;
  }
  dst->hc_last_write_ns = now;
}

void
hc_prog_settled(proxy_fd_ent_t *c)
{
  if (!hc_is_client(c) || c->cache_head != NULL ||
      !atomic_load_explicit(&c->hc_deliver_pending, memory_order_relaxed)) {
    return;
  }
  /* Unpaired plaintext connections only, the population a hold bound is for:
   * with a direction in the kernel the request framer misses requests (so the
   * handoff is stale) or the response framer misses responses. */
  if (c->hc_first_write_ns != 0 && c->ssl == NULL &&
      atomic_load_explicit(&c->hc_accel, memory_order_relaxed) == 0) {
    enum hc_stream st = hc_stream_of(c);

    if (c->hc_resp_handoff_ns != 0 && c->hc_first_write_ns >= c->hc_resp_handoff_ns) {
      hc_observe(hc_stats.first_gap_bucket[st], &hc_stats.first_gap_sum_us[st],
                 &hc_stats.first_gap_count[st], hc_prog_bounds_us, HC_PROG_NB,
                 (c->hc_first_write_ns - c->hc_resp_handoff_ns) / 1000);
    }
    hc_observe(hc_stats.max_gap_bucket[st], &hc_stats.max_gap_sum_us[st],
               &hc_stats.max_gap_count[st], hc_prog_bounds_us, HC_PROG_NB,
               c->hc_max_gap_ns / 1000);
  }
  c->hc_resp_active = 0;
  atomic_store_explicit(&c->hc_deliver_pending, 0, memory_order_relaxed);
  c->hc_resp_handoff_ns = 0;
  c->hc_first_write_ns = 0;
  c->hc_last_write_ns = 0;
  c->hc_max_gap_ns = 0;
}

/* ---- export --------------------------------------------------------------- */

#define HC_COPY(dst, src, n)                                               \
  do {                                                                     \
    const _Atomic uint64_t *s_ = (const _Atomic uint64_t *)(src);          \
    uint64_t *d_ = (uint64_t *)(dst);                                      \
    for (size_t i_ = 0; i_ < (n); i_++) {                                  \
      d_[i_] = atomic_load_explicit(&s_[i_], memory_order_relaxed);        \
    }                                                                      \
  } while (0)

#define HC_N(a) (sizeof(a) / sizeof(uint64_t))

void
hc_metrics_fill(proxy_metrics_snapshot_t *s)
{
  HC_COPY(s->hc_fin_gap_bucket, hc_stats.fin_gap_bucket, HC_N(s->hc_fin_gap_bucket));
  HC_COPY(s->hc_fin_gap_sum_us, hc_stats.fin_gap_sum_us, HC_N(s->hc_fin_gap_sum_us));
  HC_COPY(s->hc_fin_gap_count, hc_stats.fin_gap_count, HC_N(s->hc_fin_gap_count));
  HC_COPY(s->hc_fin_total, hc_stats.fin_total, HC_N(s->hc_fin_total));
  s->hc_accel_early_fin = atomic_load_explicit(&hc_stats.accel_early_fin, memory_order_relaxed);
  HC_COPY(s->hc_tls_fin, hc_stats.tls_fin, HC_N(s->hc_tls_fin));
  s->hc_client_reset = atomic_load_explicit(&hc_stats.client_reset, memory_order_relaxed);
  HC_COPY(s->hc_user_agent, hc_stats.ua, HC_N(s->hc_user_agent));
  HC_COPY(s->hc_first_gap_bucket, hc_stats.first_gap_bucket, HC_N(s->hc_first_gap_bucket));
  HC_COPY(s->hc_first_gap_sum_us, hc_stats.first_gap_sum_us, HC_N(s->hc_first_gap_sum_us));
  HC_COPY(s->hc_first_gap_count, hc_stats.first_gap_count, HC_N(s->hc_first_gap_count));
  HC_COPY(s->hc_max_gap_bucket, hc_stats.max_gap_bucket, HC_N(s->hc_max_gap_bucket));
  HC_COPY(s->hc_max_gap_sum_us, hc_stats.max_gap_sum_us, HC_N(s->hc_max_gap_sum_us));
  HC_COPY(s->hc_max_gap_count, hc_stats.max_gap_count, HC_N(s->hc_max_gap_count));
}
