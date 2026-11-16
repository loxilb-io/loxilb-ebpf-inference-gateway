/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_h2_corr.c - each HTTP/2 stream's traceparent and x-client-session-id
 * are its own (WP-D).
 *
 * Several streams of one connection are parsed by the product's header
 * callback (sockproxy_h2.c, built with ASan) before any of them is
 * forwarded, so a capture kept anywhere but on the stream would give one
 * stream another's values. Three streams are sent in one batch:
 *   stream 1  a valid traceparent and a valid session value;
 *   stream 3  neither header;
 *   stream 5  another trace twice (two fields: void) and its own session;
 * then stream 7 sends a valid traceparent and, in its trailers, another one:
 * a trailer is not a request header, so it is neither the value nor a
 * duplicate. Each stream's capture is read where the product keeps it, and
 * then each stream is refused at admission: the request the gate is handed
 * carries that stream's correlation and no other's.
 *
 * Build: make test_h2_corr (ASan + UBSan, the gateway object included).
 */
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_h2_fixture.h"

#define T1 "4bf92f3577b34da6a3ce929d0e0e4736"
#define P1 "00f067aa0ba902b7"
#define T2 "0af7651916cd43dd8448eb211c80319c"
#define P2 "b7ad6b7169203331"
#define S1 "loxigpt.app:sess_01-A"
#define S5 "sess-five"

#define NV(n, v) { (uint8_t *)(n), (uint8_t *)(v), sizeof(n) - 1, sizeof(v) - 1, 0 }

/* What the gate was handed, per stream. */
static struct { int seen; int null; ai_corr_t corr; } at_gate[H2FX_MAX_STREAMS];

static void
admit_deny(const ai_gw_req_ctx_t *req, ai_gw_admit_result_t *res)
{
  int32_t id = (int32_t)strtol(req->request_id, NULL, 10);

  at_gate[id / 2].seen++;
  at_gate[id / 2].null = req->corr == NULL;
  if (req->corr)
    at_gate[id / 2].corr = *req->corr;
  res->verdict = AI_GW_ADMIT_DENY;
  res->http_status = 401;
  res->stage = AI_GW_STAGE_AUTH;
  snprintf(res->error_code, sizeof(res->error_code), "invalid_api_key");
  snprintf(res->error_msg, sizeof(res->error_msg), "the key is not known");
}

static const char *
rec(const ai_corr_t *c)
{
  static char out[4][256];
  static int k;
  char *o = out[k++ & 3];
  snprintf(o, 256, "%s|%s|%s", c->trace_id[0] ? c->trace_id : "-",
           c->parent_span_id[0] ? c->parent_span_id : "-",
           c->session_id[0] ? c->session_id : "-");
  return o;
}

static int32_t
submit(const nghttp2_nv *extra, size_t n_extra, nghttp2_data_provider *prd)
{
  nghttp2_nv nv[16] = {
    NV(":method", "POST"), NV(":path", "/v1/chat/completions"),
    NV(":scheme", "http"), NV(":authority", "all.example"),
    NV("x-model", "m1"),
  };
  size_t n = 5;
  assert(n + n_extra <= 16);
  for (size_t i = 0; i < n_extra; i++)
    nv[n++] = extra[i];
  int32_t id = nghttp2_submit_request(h2fx_cl, NULL, nv, n, prd, NULL);
  assert(id > 0 && id / 2 < H2FX_MAX_STREAMS);
  return id;
}

/* Stream 7's body: two bytes, then trailers carrying another traceparent. */
static ssize_t
body_then_trailers(nghttp2_session *s, int32_t id, uint8_t *buf, size_t len,
                   uint32_t *flags, nghttp2_data_source *src, void *ud)
{
  static const nghttp2_nv tr[] = { NV("traceparent", "00-" T2 "-" P2 "-01") };
  (void)src; (void)ud;
  assert(len >= 2);
  memcpy(buf, "{}", 2);
  *flags |= NGHTTP2_DATA_FLAG_EOF | NGHTTP2_DATA_FLAG_NO_END_STREAM;
  assert(nghttp2_submit_trailer(s, id, tr, 1) == 0);
  return 2;
}

static void
refuse(int32_t id)
{
  proxy_h2_stream_t *st = h2fx_stream(id);
  CHECK(st != NULL, "stream %d is open before its forward", id);
  if (!st)
    return;
  snprintf(st->request_id, sizeof(st->request_id), "%d", id);
  (void)proxy_h2_forward_to_backend(h2fx_pfe, st);
  h2fx_deliver();
  CHECK(h2fx_status[id / 2] == 401, "stream %d is refused (got %d)", id,
        h2fx_status[id / 2]);
}

int
main(void)
{
  static const nghttp2_nv s1[] = {
    NV("traceparent", "00-" T1 "-" P1 "-01"), NV("x-client-session-id", S1),
  };
  static const nghttp2_nv s3[] = { NV("accept", "*/*") };
  static const nghttp2_nv s5[] = {
    NV("traceparent", "00-" T2 "-" P2 "-01"), NV("x-client-session-id", S5),
    NV("traceparent", "00-" T2 "-" P2 "-01"),
  };
  static const nghttp2_nv s7[] = { NV("traceparent", "00-" T1 "-" P2 "-01") };
  nghttp2_data_provider prd = { .read_callback = body_then_trailers };
  int32_t a, b, c, d;

  h2fx_init();
  (void)h2fx_pool("all.example", 0);
  h2fx_admit = admit_deny;

  /* One batch: all three are parsed before any is forwarded. */
  a = submit(s1, 2, NULL);
  b = submit(s3, 1, NULL);
  c = submit(s5, 3, NULL);
  h2fx_to_gateway();

  proxy_h2_stream_t *sa = h2fx_stream(a), *sb = h2fx_stream(b), *sc = h2fx_stream(c);
  CHECK(sa && sb && sc && sa->headers_complete && sb->headers_complete &&
        sc->headers_complete, "streams %d, %d, %d are parsed together", a, b, c);
  if (sa && sb && sc) {
    CHECK(strcmp(rec(&sa->corr.rec), T1 "|" P1 "|" S1) == 0,
          "stream %d: its own trace and session (got %s)", a, rec(&sa->corr.rec));
    CHECK(strcmp(rec(&sb->corr.rec), "-|-|-") == 0,
          "stream %d sent neither: nothing, not stream %d's (got %s)", b, a,
          rec(&sb->corr.rec));
    CHECK(strcmp(rec(&sc->corr.rec), "-|-|" S5) == 0,
          "stream %d: a duplicate traceparent voids the trace, its session is kept "
          "(got %s)", c, rec(&sc->corr.rec));
  }

  /* Refused in order: each gate call is handed its own stream's values. */
  refuse(a);
  refuse(b);
  refuse(c);
  CHECK(at_gate[a / 2].seen == 1 && !at_gate[a / 2].null &&
        strcmp(rec(&at_gate[a / 2].corr), T1 "|" P1 "|" S1) == 0,
        "the gate saw stream %d's correlation (got %s)", a, rec(&at_gate[a / 2].corr));
  CHECK(at_gate[b / 2].seen == 1 && !at_gate[b / 2].null &&
        strcmp(rec(&at_gate[b / 2].corr), "-|-|-") == 0,
        "the gate saw none on stream %d (got %s)", b, rec(&at_gate[b / 2].corr));
  CHECK(at_gate[c / 2].seen == 1 && !at_gate[c / 2].null &&
        strcmp(rec(&at_gate[c / 2].corr), "-|-|" S5) == 0,
        "the gate saw stream %d's own session and no trace (got %s)", c,
        rec(&at_gate[c / 2].corr));

  /* A stream after them on the same connection, with trailers. */
  d = submit(s7, 1, &prd);
  h2fx_to_gateway();
  proxy_h2_stream_t *sd = h2fx_stream(d);
  CHECK(sd && sd->data_complete, "stream %d ended after its trailers", d);
  if (sd)
    CHECK(strcmp(rec(&sd->corr.rec), T1 "|" P2 "|-") == 0,
          "stream %d: the trailer's traceparent is neither its value nor a "
          "duplicate (got %s)", d, rec(&sd->corr.rec));
  refuse(d);
  CHECK(at_gate[d / 2].seen == 1 &&
        strcmp(rec(&at_gate[d / 2].corr), T1 "|" P2 "|-") == 0,
        "the gate saw stream %d's header value (got %s)", d,
        rec(&at_gate[d / 2].corr));

  h2fx_fini();
  return h2fx_result();
}
