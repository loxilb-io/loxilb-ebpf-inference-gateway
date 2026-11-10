/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_h2_resp_mark.c - a backend's X-Loxilb-Refusal-* never reaches an
 * HTTP/2 client.
 *
 * X-Loxilb-Refusal-Stage says the gateway refused a request before any
 * backend saw it (sockproxy_refusal_mark.h). A response a backend sent is
 * not that, so the family is removed from every response head the gateway
 * relays, interim and final, on every service: no admission setting, permit
 * or api_key_auth is needed for it. The rest of the head is relayed as it
 * came, the backend's own X-Request-Id included.
 *
 * This drives the REAL response relay (proxy_h2_handle_backend_data and the
 * backend session's callbacks) over the shared HTTP/2 fixture
 * (test_h2_fixture.h): a plain pool with nothing configured, a request
 * forwarded to a fake backend, and the backend answering with an interim
 * 103 and a final 429 that both carry the family.
 *
 * Build: make test_h2rmark (ASan + UBSan, the gateway object included).
 */
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "test_h2_fixture.h"

#define NV(n, v) { (uint8_t *)(n), (uint8_t *)(v), sizeof(n) - 1, sizeof(v) - 1, NGHTTP2_NV_FLAG_NONE }

int
main(void)
{
  proxy_epval_t *pool;
  const char *v;
  int32_t s1;
  nghttp2_nv interim[] = {
    NV(":status", "103"),
    NV("link", "</style.css>; rel=preload"),
    NV("x-loxilb-refusal-stage", "route"),
  };
  nghttp2_nv final[] = {
    NV(":status", "429"),
    NV("content-length", "0"),
    NV("x-loxilb-refusal-stage", "capacity"),
    NV("x-backend", "b1"),
    NV("x-loxilb-refusal-anything", "1"),
    NV("x-request-id", "be-7"),
    NV("retry-after", "3"),
  };

  h2fx_init();
  pool = h2fx_pool("all.example", 1);
  h2fx_lpm = pool;

  s1 = h2fx_submit("m1", NULL, 0);
  CHECK(h2fx_gw_read() == 0, "the request is read and forwarded");
  CHECK(h2fx_connect_calls == 1 && h2fx_be[0].streams == 1 && h2fx_be[0].end_stream,
        "the backend got it (connects %d, streams %d)", h2fx_connect_calls,
        h2fx_be[0].streams);
  if (h2fx_be[0].streams != 1)
    return h2fx_result();

  /* The interim head. */
  assert(nghttp2_submit_headers(h2fx_be[0].srv, NGHTTP2_FLAG_NONE, h2fx_be[0].stream,
                                NULL, interim, sizeof(interim) / sizeof(interim[0]),
                                NULL) == 0);
  CHECK(h2fx_be_send(0) == 0, "the backend's 103 reaches the gateway");
  v = h2fx_header(s1, "link");
  CHECK(v != NULL, "the interim head is relayed (link: %s)", v ? v : "none");
  v = h2fx_header(s1, "x-loxilb-refusal-stage");
  CHECK(v == NULL, "without the backend's x-loxilb-refusal-stage (got %s)", v ? v : "none");

  /* The final head: a backend's own 429, dressed as a refusal of ours. */
  assert(nghttp2_submit_response(h2fx_be[0].srv, h2fx_be[0].stream, final,
                                 sizeof(final) / sizeof(final[0]), NULL) == 0);
  CHECK(h2fx_be_send(0) == 0, "the backend's 429 reaches the gateway");
  CHECK(h2fx_status[s1 / 2] == 429, "the client gets the backend's status (got %d)",
        h2fx_status[s1 / 2]);
  v = h2fx_header(s1, "x-loxilb-refusal-stage");
  CHECK(v == NULL, "with no x-loxilb-refusal-stage (got %s)", v ? v : "none");
  v = h2fx_header(s1, "x-loxilb-refusal-anything");
  CHECK(v == NULL, "nor any other field of the family (got %s)", v ? v : "none");
  v = h2fx_header(s1, "x-backend");
  CHECK(v && !strcmp(v, "b1"), "the rest of the head is the backend's (x-backend: %s)",
        v ? v : "none");
  v = h2fx_header(s1, "x-request-id");
  CHECK(v && !strcmp(v, "be-7"), "its x-request-id included (got %s)", v ? v : "none");
  v = h2fx_header(s1, "retry-after");
  CHECK(v && !strcmp(v, "3"), "and its retry-after (got %s)", v ? v : "none");

  h2fx_fini();
  return h2fx_result();
}
