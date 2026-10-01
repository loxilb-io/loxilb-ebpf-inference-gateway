/*
 * Copyright (c) 2026 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */
#ifndef __SOCKPROXY_HC_CORE_H__
#define __SOCKPROXY_HC_CORE_H__

/*
 * Half-close observation: the pure half.
 *
 * Nothing here touches a connection entry or a lock, so it builds on its own
 * and the unit test (test_hc_metrics.c) exercises it without the proxy. The
 * stateful half, and the hooks the proxy calls, are in sockproxy_hc.c.
 *
 * Everything this feeds is observation only: no caller decides anything from
 * these values.
 */

#include <stddef.h>
#include <stdint.h>

/* Where a client's FIN was first seen. The first four can carry a sample: the
 * request they hold is complete, so the time from its completion to the FIN
 * means something. The paused-read ones cannot: the request was still being
 * read when the FIN arrived, so the gap would be negative. */
enum hc_entry {
  HC_ENTRY_EOF = 0,        /* the read path met the EOF */
  HC_ENTRY_CONNECT_WAIT,   /* RDHUP while the backend connect was in flight */
  HC_ENTRY_SETUP_PARK,     /* RDHUP while parked at setup (queue / admission) */
  HC_ENTRY_FC_PARK,        /* RDHUP while a keep-alive request waited in the queue */
  HC_ENTRY_QOS,            /* RDHUP while the byte shaper held the reads */
  HC_ENTRY_BACKPRESSURE,   /* RDHUP while a full relay cache held the reads */
  HC_ENTRY_OTHER_PAUSE,    /* RDHUP while reads were paused for another reason */
  HC_ENTRY_MAX
};
#define HC_ENTRY_SAMPLED 4 /* entries below this index can carry a gap sample */

/* What the first sight of a FIN was, for the counter. */
enum hc_outcome {
  HC_OUT_OWED = 0,  /* in the gate and an answer is owed: the case under study */
  HC_OUT_IDLE,      /* in the gate, nothing owed: an ordinary close */
  HC_OUT_PARTIAL,   /* in the gate, the FIN came before the request was complete
                     * (or reads were paused mid-request): count only */
  HC_OUT_RESIDUE,   /* in the gate, an answer is owed and the next request was
                     * still arriving: a pipeline's remainder. Count only; a hold
                     * would refuse it */
  HC_OUT_TLS,       /* outside the gate: a TLS connection */
  HC_OUT_ACCEL,     /* outside the gate: the kernel carried bytes on this connection */
  HC_OUT_MAX
};

/* The request's "stream" field, where the proxy read the body. Plain FullProxy
 * rules never parse the body, so unknown there does not mean non-streaming. */
enum hc_stream {
  HC_STREAM_UNKNOWN = 0,
  HC_STREAM_YES,
  HC_STREAM_NO,
  HC_STREAM_MAX
};

/* How a TLS client's FIN arrived. */
enum hc_tls_path {
  HC_TLS_KTLS = 0,         /* kTLS: the FIN comes up the plaintext EOF path */
  HC_TLS_CLOSE_NOTIFY,     /* SSL_ERROR_ZERO_RETURN */
  HC_TLS_UNEXPECTED_EOF,   /* a FIN with no close_notify */
  HC_TLS_MAX
};

/* User-Agent families, bounded so the label cannot grow with traffic. */
enum hc_ua {
  HC_UA_NONE = 0,          /* no User-Agent header at all */
  HC_UA_CURL,
  HC_UA_PY_REQUESTS,
  HC_UA_PY_HTTPX,
  HC_UA_PY_AIOHTTP,
  HC_UA_PY_URLLIB,
  HC_UA_OPENAI_PY,
  HC_UA_OPENAI_NODE,
  HC_UA_GO,
  HC_UA_NODE,
  HC_UA_JAVA,
  HC_UA_BROWSER,
  HC_UA_OTHER,
  HC_UA_MAX
};

/* A FIN within this long after the request completed is an "early FIN": a
 * half-close's FIN follows the last request segment at packetisation distance,
 * a cancel comes after at least a time to first token. */
#define HC_EARLY_FIN_US (100ull * 1000)

/* FIN gap buckets (upper bounds, microseconds). The last bucket is +Inf. */
#define HC_FIN_NB 16
static const uint64_t hc_fin_bounds_us[HC_FIN_NB - 1] = {
  1000, 2000, 5000, 10000, 20000, 50000, 100000, 200000, 500000,
  1000000, 2000000, 5000000, 10000000, 30000000, 60000000,
};

/* Response progress buckets (upper bounds, microseconds), longer than any
 * bound a hold could be given, so its tail does not pile up in +Inf. */
#define HC_PROG_NB 16
static const uint64_t hc_prog_bounds_us[HC_PROG_NB - 1] = {
  10000, 50000, 100000, 250000, 500000, 1000000, 2000000, 5000000,
  10000000, 30000000, 60000000, 120000000, 300000000, 600000000, 1800000000,
};

static inline int
hc_bucket(const uint64_t *bounds, int nb, uint64_t v)
{
  int i;

  for (i = 0; i < nb - 1; i++) {
    if (v <= bounds[i]) {
      return i;
    }
  }
  return nb - 1;
}

static inline int
hc_fin_bucket(uint64_t gap_us)
{
  return hc_bucket(hc_fin_bounds_us, HC_FIN_NB, gap_us);
}

static inline int
hc_prog_bucket(uint64_t gap_us)
{
  return hc_bucket(hc_prog_bounds_us, HC_PROG_NB, gap_us);
}

/* The storage is cumulative, as Prometheus reads it: a sample counts in every
 * bucket whose bound it does not exceed, and in none when it is past the last
 * bound (the +Inf bucket is the total count). This is the first index a
 * sample counts in; the caller counts it there and in every later one. */
static inline int
hc_cum_first(const uint64_t *bounds, int nb, uint64_t v)
{
  return hc_bucket(bounds, nb, v);
}

/* How a failed TLS read on a client ended, from what OpenSSL reported. A FIN
 * without close_notify is SSL_ERROR_SSL with the unexpected-EOF reason on
 * OpenSSL 3, and SSL_ERROR_SYSCALL with a zero return and an empty error
 * queue on 1.1.1. Anything else is a real TLS failure and not a FIN, so it
 * returns -1 and nothing is counted. The caller reads the queue with
 * ERR_peek_error before anything pops it. */
#define HC_SSL_ERR_SSL     1   /* SSL_ERROR_SSL */
#define HC_SSL_ERR_SYSCALL 5   /* SSL_ERROR_SYSCALL */

static inline int
hc_tls_eof_path(int ssl_err, int rval, int queue_empty, int reason_unexpected_eof)
{
  if (ssl_err == HC_SSL_ERR_SSL && reason_unexpected_eof) {
    return HC_TLS_UNEXPECTED_EOF;
  }
  if (ssl_err == HC_SSL_ERR_SYSCALL && rval == 0 && queue_empty) {
    return HC_TLS_UNEXPECTED_EOF;
  }
  return -1;
}

/* Is the FIN early (and was an answer owed)? A gap is only meaningful when a
 * request was framed before the FIN. */
static inline int
hc_is_early(uint64_t req_done_ns, uint64_t fin_ns)
{
  return req_done_ns != 0 && fin_ns >= req_done_ns &&
         (fin_ns - req_done_ns) / 1000 <= HC_EARLY_FIN_US;
}

/* The accel history bits on the client: set where a verdict entry is added,
 * never cleared. "The kernel may have carried bytes in that direction." */
#define HC_ACCEL_REQ  0x1
#define HC_ACCEL_RESP 0x2

/* The gate the samples are taken under: no TLS, and the kernel never carried a
 * byte on the connection. Outside it the counters the samples need are not
 * trustworthy (an accelerated direction is invisible to the framers).
 *
 * partial: the request the FIN arrived behind was not complete. Where the
 * count of owed answers is known at that moment (owed_known), a partial
 * request behind an owed answer is a pipeline's remainder, not a truncated
 * request. Where reads were paused mid-request it is not known: the paused
 * request may itself be the one the answer is owed for. */
static inline enum hc_outcome
hc_classify(int is_tls, uint8_t accel, int partial, int owed_known, int owed)
{
  if (is_tls) {
    return HC_OUT_TLS;
  }
  if (accel) {
    return HC_OUT_ACCEL;
  }
  if (partial) {
    return owed_known && owed ? HC_OUT_RESIDUE : HC_OUT_PARTIAL;
  }
  return owed ? HC_OUT_OWED : HC_OUT_IDLE;
}

/* Case-insensitive prefix test over a value that is not NUL-terminated. */
static inline int
hc_has_prefix(const char *s, size_t len, const char *p)
{
  size_t i;

  for (i = 0; p[i]; i++) {
    char c;

    if (i >= len) {
      return 0;
    }
    c = s[i];
    if (c >= 'A' && c <= 'Z') {
      c = (char)(c - 'A' + 'a');
    }
    if (c != p[i]) {
      return 0;
    }
  }
  return 1;
}

static inline int
hc_contains(const char *s, size_t len, const char *p)
{
  size_t i;

  for (i = 0; i < len; i++) {
    if (hc_has_prefix(s + i, len - i, p)) {
      return 1;
    }
  }
  return 0;
}

/* Classifies the first bytes of a User-Agent value. Order matters where one
 * library builds on another: the OpenAI SDKs ride on httpx and node-fetch, so
 * they are tested first. len == 0 is a header that was present but empty. */
static inline enum hc_ua
hc_ua_classify(const char *ua, size_t len)
{
  if (!ua || len == 0) {
    return HC_UA_OTHER;
  }
  if (hc_has_prefix(ua, len, "openai/python")) {
    return HC_UA_OPENAI_PY;
  }
  if (hc_has_prefix(ua, len, "openai/js") || hc_has_prefix(ua, len, "openai/node")) {
    return HC_UA_OPENAI_NODE;
  }
  if (hc_has_prefix(ua, len, "curl/")) {
    return HC_UA_CURL;
  }
  if (hc_has_prefix(ua, len, "python-requests/")) {
    return HC_UA_PY_REQUESTS;
  }
  if (hc_has_prefix(ua, len, "python-httpx/")) {
    return HC_UA_PY_HTTPX;
  }
  if (hc_contains(ua, len, "aiohttp/")) {
    return HC_UA_PY_AIOHTTP;
  }
  if (hc_has_prefix(ua, len, "python-urllib")) {
    return HC_UA_PY_URLLIB;
  }
  if (hc_has_prefix(ua, len, "go-http-client/")) {
    return HC_UA_GO;
  }
  if (hc_has_prefix(ua, len, "node") || hc_has_prefix(ua, len, "undici") ||
      hc_has_prefix(ua, len, "axios/")) {
    return HC_UA_NODE;
  }
  if (hc_has_prefix(ua, len, "java/") || hc_has_prefix(ua, len, "apache-httpclient/") ||
      hc_has_prefix(ua, len, "okhttp/")) {
    return HC_UA_JAVA;
  }
  if (hc_has_prefix(ua, len, "mozilla/")) {
    return HC_UA_BROWSER;
  }
  return HC_UA_OTHER;
}

/* Incremental, case-insensitive match of a header name against "user-agent".
 * State is the number of characters matched so far; -1 means no match. The
 * name can arrive in pieces, so the caller keeps the state between calls. */
#define HC_UA_NAME "user-agent"
#define HC_UA_NAME_LEN 10

static inline int
hc_ua_name_step(int state, const char *at, size_t len)
{
  size_t i;

  if (state < 0) {
    return -1;
  }
  for (i = 0; i < len; i++) {
    char c = at[i];

    if (state >= HC_UA_NAME_LEN) {
      return -1;
    }
    if (c >= 'A' && c <= 'Z') {
      c = (char)(c - 'A' + 'a');
    }
    if (c != HC_UA_NAME[state]) {
      return -1;
    }
    state++;
  }
  return state;
}

#endif /* __SOCKPROXY_HC_CORE_H__ */
