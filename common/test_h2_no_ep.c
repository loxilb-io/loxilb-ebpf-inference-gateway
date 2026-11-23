/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_h2_no_ep.c - an HTTP/2 stream whose rule has no endpoints is
 * answered, by the status the rule asks for.
 *
 * A host|path rule may be installed with no endpoints (sockproxy_no_ep.h).
 * The stream its pool takes used to get nothing: proxy_h2_forward_to_backend
 * logged "Invalid n_eps=0" and returned without an answer, and the stream
 * stayed open until the client gave up. Now the gateway answers it, right
 * after the pool is found and before any gate or selector:
 *   - no_ep_status 503 (the default): 503 no_healthy_backend;
 *   - no_ep_status 500: 500 no_backend.
 * Each answer reaches the client, ends and frees the stream, names no stage
 * (an outage, not a refusal), and no case reaches a backend connect.
 *
 * This drives the REAL proxy_h2_forward_to_backend over a REAL gateway
 * session (the shared HTTP/2 fixture, test_h2_fixture.h).
 *
 * Build: make test_h2noep (ASan + UBSan, the gateway object included).
 */
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_h2_fixture.h"
#include "sockproxy_no_ep.h"

static void
answered(proxy_epval_t *pool, uint8_t no_ep_status, int want_status,
         const char *want_error, const char *what)
{
  proxy_h2_stream_t *st;
  const char *b;
  int32_t id;
  int rc;

  pool->no_ep_status = no_ep_status;
  id = h2fx_submit("", NULL, 0);
  h2fx_to_gateway();
  st = h2fx_stream(id);
  CHECK(st && st->headers_complete && st->data_complete && !st->response_sent,
        "%s: the request is complete on stream %d", what, id);
  if (!st)
    return;
  rc = proxy_h2_forward_to_backend(h2fx_pfe, st);
  h2fx_deliver();
  b = h2fx_body(id);
  CHECK(rc == 0, "%s: answered by the gateway itself (rc %d)", what, rc);
  CHECK(h2fx_status[id / 2] == want_status, "%s: the client got %d (got %d)",
        what, want_status, h2fx_status[id / 2]);
  CHECK(b && strstr(b, want_error), "%s: the body names %s (got %s)",
        what, want_error, b ? b : "none");
  CHECK(b && strstr(b, sp_no_ep_answer(no_ep_status).detail),
        "%s: the body says why (got %s)", what, b ? b : "none");
  CHECK(h2fx_header(id, "x-loxilb-refusal-stage") == NULL,
        "%s: an outage names no stage", what);
  CHECK(h2fx_stream(id) == NULL, "%s: the answer ended the stream and freed it", what);
}

int
main(void)
{
  proxy_epval_t *pool;

  h2fx_init();
  pool = h2fx_pool("shop.example.com|/down|", 0);
  h2fx_lpm = pool;

  answered(pool, SP_NO_EP_STATUS_503, 503, "\"no_healthy_backend\"",
           "no endpoints, the default answer");
  answered(pool, SP_NO_EP_STATUS_500, 500, "\"no_backend\"",
           "no endpoints, the rule asks for 500");
  /* A value this build does not know answers as the default. */
  answered(pool, 7, 503, "\"no_healthy_backend\"", "no endpoints, an unknown status");

  CHECK(h2fx_lpm_calls == 3, "one lookup a stream (got %d)", h2fx_lpm_calls);
  CHECK(h2fx_connect_calls == 0, "no case reached a backend connect");

  /* The HTTP/1.1 text of the same answers. */
  {
    char buf[256];
    int n = sp_no_ep_h1_text(SP_NO_EP_STATUS_503, buf, sizeof(buf));

    CHECK(n > 0 && !strncmp(buf, "HTTP/1.1 503 Service Unavailable\r\n", 34) &&
          strstr(buf, "Connection: close\r\n") &&
          strstr(buf, "\r\n\r\n{\"error\":\"no_healthy_backend\",\"detail\":\"the rule has no endpoints\"}\r\n"),
          "HTTP/1.1 503 text (got %s)", n > 0 ? buf : "none");
    n = sp_no_ep_h1_text(SP_NO_EP_STATUS_500, buf, sizeof(buf));
    CHECK(n > 0 && !strncmp(buf, "HTTP/1.1 500 Internal Server Error\r\n", 36) &&
          strstr(buf, "{\"error\":\"no_backend\",\"detail\":\"the rule has no usable backend\"}\r\n"),
          "HTTP/1.1 500 text (got %s)", n > 0 ? buf : "none");
    CHECK(sp_no_ep_h1_text(SP_NO_EP_STATUS_503, buf, 32) == -1,
          "a text that does not fit is not cut short");
  }

  h2fx_fini();
  return h2fx_result();
}
