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
 * The same relay then carries the class headers of an admitted response:
 * X-Loxilb-Admission-Objective-Requested is there when the request named an
 * objective it may not use, with what it named, and absent when it did not;
 * a backend's own header of that name is dropped either way.
 *
 * Build: make test_h2rmark (ASan + UBSan, the gateway object included).
 */
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "test_h2_fixture.h"

#define NV(n, v) { (uint8_t *)(n), (uint8_t *)(v), sizeof(n) - 1, sizeof(v) - 1, NGHTTP2_NV_FLAG_NONE }

/* The admission gate's answer for the class cases: admitted, and the
 * objective the request named was denied or not. */
static int the_denied;
static const char *the_requested;

static void
admit(const ai_gw_req_ctx_t *req, ai_gw_admit_result_t *res)
{
  (void)req;
  res->verdict = AI_GW_ADMIT_ALLOW;
  snprintf(res->tenant_id, sizeof(res->tenant_id), "t1");
  res->priority_class = AI_GW_CLASS_STANDARD;
  res->objective_denied = the_denied ? 1 : 0;
  /* Set even when not denied: the gateway must not read it then. */
  snprintf(res->objective_requested, sizeof(res->objective_requested), "%s",
           the_requested ? the_requested : "");
}

/* One admitted request relayed to the backend, which answers 200 with its
 * own copies of the class headers. Returns the client's stream. */
static int32_t
class_exchange(int denied, const char *requested, int streams_before)
{
  nghttp2_nv ok[] = {
    NV(":status", "200"),
    NV("content-length", "0"),
    NV("x-loxilb-admission-objective-requested", "forged"),
    NV("x-loxilb-admission-class", "critical"),
    NV("x-backend", "b1"),
  };
  int32_t id;

  the_denied = denied;
  the_requested = requested;
  id = h2fx_submit("m1", NULL, 0);
  CHECK(h2fx_gw_read() == 0 && h2fx_be[0].streams == streams_before + 1,
        "the request is admitted and forwarded (backend streams %d)", h2fx_be[0].streams);
  if (h2fx_be[0].streams != streams_before + 1)
    return id;
  assert(nghttp2_submit_response(h2fx_be[0].srv, h2fx_be[0].stream, ok,
                                 sizeof(ok) / sizeof(ok[0]), NULL) == 0);
  CHECK(h2fx_be_send(0) == 0 && h2fx_status[id / 2] == 200,
        "the backend's 200 reaches the client (got %d)", h2fx_status[id / 2]);
  return id;
}

int
main(void)
{
  proxy_epval_t *pool;
  const char *v;
  int32_t s1, s2;
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

  /* The class headers on the same relay: classes on, a rule that exposes
   * its admission headers, a request the gate admits. */
  /* An admitted request completes, and its completion is recorded: the two
   * stand-ins of that record abort for every test that did not say this. */
  h2fx_allow_completion = 1;
  h2fx_admit = admit;
  h2fx_class_on = 1;
  pool->ai_gw_mode = 1;
  pool->fc.cfg.expose_headers = 1;

  s2 = class_exchange(1, "premium", 1);
  v = h2fx_header(s2, "x-loxilb-admission-class");
  CHECK(v && !strcmp(v, "standard"), "denied: the class is the gateway's (got %s)", v ? v : "none");
  v = h2fx_header(s2, "x-loxilb-admission-objective-requested");
  CHECK(v && !strcmp(v, "premium"),
        "denied: the head says what the request asked for, not the backend's value (got %s)",
        v ? v : "none");
  v = h2fx_header(s2, "x-loxilb-admission-objective");
  CHECK(v == NULL, "and no applied objective, there being none (got %s)", v ? v : "none");
  v = h2fx_header(s2, "x-backend");
  CHECK(v && !strcmp(v, "b1"), "the rest of the head is the backend's");

  s2 = class_exchange(0, "premium", 2);
  v = h2fx_header(s2, "x-loxilb-admission-objective-requested");
  CHECK(v == NULL, "not denied: the header is absent, the backend's copy included (got %s)",
        v ? v : "none");
  v = h2fx_header(s2, "x-loxilb-admission-class");
  CHECK(v && !strcmp(v, "standard"), "the class is still there (got %s)", v ? v : "none");

  s2 = class_exchange(1, "(oversize)", 3);
  v = h2fx_header(s2, "x-loxilb-admission-objective-requested");
  CHECK(v && !strcmp(v, "(oversize)"), "an oversize hint is reported as the capture kept it (got %s)",
        v ? v : "none");

  s2 = class_exchange(1, "pre mium", 4);
  v = h2fx_header(s2, "x-loxilb-admission-objective-requested");
  CHECK(v == NULL, "a hint that is not header text is not written (got %s)", v ? v : "none");

  /* Classes off: the stage did not run, nothing is exposed or dropped. */
  h2fx_class_on = 0;
  s2 = class_exchange(1, "premium", 5);
  v = h2fx_header(s2, "x-loxilb-admission-objective-requested");
  CHECK(v && !strcmp(v, "forged"),
        "with no class stage the backend's header passes as its other headers do (got %s)",
        v ? v : "none");

  CHECK(h2fx_completion_requests == 5 && h2fx_completion_usage_missing == 5,
        "each of the five admitted requests left one completion record through the fixture (%d, usage missing %d)",
        h2fx_completion_requests, h2fx_completion_usage_missing);

  h2fx_fini();
  return h2fx_result();
}
