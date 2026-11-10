/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_h2_deny_free.c - nothing reads an HTTP/2 stream after an answer that
 * may have freed it.
 *
 * When the client has sent all of its request, an answer from the gateway
 * (a deny, an L7 reject) ends the stream on both sides as soon as nghttp2
 * writes it, and nghttp2's close callback frees the stream before the send
 * returns. proxy_h2_forward_to_backend used to log the stream's id (and, for
 * a model with no pool, the model name held in the stream) after such an
 * answer: a heap-use-after-free, seen live under ASan when a listener was
 * deleted while its streams were being dispatched.
 *
 * This drives the REAL proxy_h2_forward_to_backend over a REAL gateway
 * session (proxy_setup_h2_session: the product's callbacks, sending on a
 * socketpair), with the request parsed by those callbacks, for the four
 * answers it gives itself:
 *   - a model with no pool: 503 model_unavailable;
 *   - an admission refusal: 401;
 *   - an L7 reject: 403;
 *   - a capacity refusal: 429 (sp_fc_h2_shed, which also records the
 *     refusal and releases the stream's permit: it used to do both AFTER
 *     the answer, a write into the freed stream);
 *   - a CHWBL pool refusing the request's cache_salt: 400 (it used to send
 *     nothing and leave the stream open);
 *   - a sheddable request at the ceiling: 429 admission_shed with every
 *     admission header, the class and its band wait included (the frame
 *     builder used to keep three of the five and drop the rest unsaid).
 * And the walk over the ready streams (proxy_h2_handle_client_data): a
 * forward's send can end and free ANOTHER stream whose answer was waiting
 * for the client's window; the walk must not hold that stream.
 * Every refusal names the stage that refused (x-loxilb-refusal-stage) and
 * echoes the request's ID (x-request-id) when the stream has one that can
 * be a field value (sockproxy_refusal_mark.h); the 503 of a draining
 * gateway says in its body when to come back, as the HTTP/1.1 answer does.
 * Each case checks the answer reached the client AND that the stream was
 * freed (otherwise the case could not catch a read of it). The gateway code
 * is built with ASan here (sockproxy_h2_asan.o), so a read after the free
 * aborts the test; putting any one site's old code back turns it red.
 *
 * The connection is the shared HTTP/2 fixture (test_h2_fixture.h); no case
 * may reach a backend connect.
 *
 * Build: make test_h2deny (ASan + UBSan, the gateway object included).
 */
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_h2_fixture.h"
#include "sockproxy_qsbr.h"
#include "sockproxy_l7policy.h"
#include "sockproxy_fc.h"
#include "sockproxy_llmd.h"

/* What the cases set for the product's seams (the fixture's hooks). */
enum { CASE_NO_POOL, CASE_ADMIT_DENY, CASE_L7_REJECT, CASE_CAPACITY, CASE_BAD_SALT,
       CASE_SHED_CLASS };
static int the_case;
static proxy_epval_t *lpm_pool;   /* what the lookup finds, CASE_CAPACITY */
/* The request ID the stream has when it is answered (the fixture's
 * ai_gw_mint_request_id writes none); NULL leaves the stream without one. */
static const char *the_rid;

static void
admit(const ai_gw_req_ctx_t *req, ai_gw_admit_result_t *res)
{
  (void)req;
  if (the_case == CASE_ADMIT_DENY) {
    res->verdict = AI_GW_ADMIT_DENY;
    res->http_status = 401;
    res->stage = AI_GW_STAGE_AUTH;
    snprintf(res->error_code, sizeof(res->error_code), "invalid_api_key");
    snprintf(res->error_msg, sizeof(res->error_msg), "the key is not known");
  } else if (the_case == CASE_CAPACITY || the_case == CASE_SHED_CLASS) {
    res->verdict = AI_GW_ADMIT_ALLOW;
    snprintf(res->tenant_id, sizeof(res->tenant_id), "t1");
    if (the_case == CASE_SHED_CLASS)
      res->priority_class = AI_GW_CLASS_SHEDDABLE;
  } else {
    res->verdict = AI_GW_ADMIT_UNMETERED;
  }
}

static int
l7_reject(proxy_fd_ent_t *pfe, proxy_map_ent_t *ent, proxy_epval_t **tepval_out)
{
  (void)ent; (void)tepval_out;
  /* The product's reject, l7_send_reject on an HTTP/2 connection. */
  if (proxy_h2_send_l7_synthetic(pfe, 403, NULL, NULL) != 0)
    return L7_DISPATCH_FALLTHROUGH;
  return L7_DISPATCH_TERMINATED;
}

/* An L7 FORWARD route none of whose members can take the request: the
 * product's dispatch leaves the route on the connection (mcp_route_active
 * and an empty member mask here), and the endpoint choice then finds no
 * one. That is an outage, not a refusal. */
static int
l7_forward_all_down(proxy_fd_ent_t *pfe, proxy_map_ent_t *ent, proxy_epval_t **tepval_out)
{
  /* The route has no cookie persistence, which this fixture does not model
   * (test_h2_fixture_links.c): the listener's policy flag is what the
   * forward path asks before it looks for one, so it is down from here to
   * the end of this dispatch; the case raises it again for its next stream. */
  ent->has_l7_policy = 0;
  pfe->mcp_route_active = 1;
  pfe->mcp_route_mask = 0;
  *tepval_out = lpm_pool;
  return L7_DISPATCH_FORWARD;
}

/* The CHWBL selector refusing the request's cache_salt (CASE_BAD_SALT). */
static int
chwbl_refuse(proxy_epval_t *tepval, llm_prefix_key_t *key, int *ep_idx)
{
  (void)tepval; (void)key; (void)ep_idx;
  if (the_case != CASE_BAD_SALT) {
    puts("chwbl_hash_and_select_runtime reached outside CASE_BAD_SALT");
    abort();
  }
  return -2;
}

/* CASE_NO_POOL: the listener's pool is gone (deleted under the streams). */
static void
set_case(int which)
{
  the_case = which;
  h2fx_lpm = which == CASE_CAPACITY || which == CASE_BAD_SALT || which == CASE_SHED_CLASS ?
             lpm_pool : NULL;
}

static ssize_t
small_body(nghttp2_session *s, int32_t id, uint8_t *buf, size_t len,
           uint32_t *flags, nghttp2_data_source *src, void *u)
{
  (void)s; (void)id; (void)src; (void)u;
  assert(len >= 2);
  memcpy(buf, "{}", 2);
  *flags |= NGHTTP2_DATA_FLAG_EOF;
  return 2;
}

static int32_t last_id;

/* The stream's response record (test_h2_fixture_links.c keeps what the
 * product noted): every answer here is the gateway's own, so it takes the
 * class count once and never a TTFB sample. */
extern int h2fx_notes, h2fx_note_status, h2fx_note_ttfb;

static void
run(int which, int want_status, const char *what)
{
  int32_t id;
  proxy_h2_stream_t *st;
  int rc;
  int notes_before = h2fx_notes;

  set_case(which);
  id = h2fx_submit("m-gone", NULL, 0);
  last_id = id;
  h2fx_to_gateway();
  st = h2fx_stream(id);
  CHECK(st && st->headers_complete && st->data_complete && !st->response_sent,
        "%s: the request is complete on stream %d", what, id);
  if (!st)
    return;
  if (the_rid)
    snprintf(st->request_id, sizeof(st->request_id), "%s", the_rid);
  rc = proxy_h2_forward_to_backend(h2fx_pfe, st);
  h2fx_deliver();
  CHECK(rc == 0, "%s: answered by the gateway itself (rc %d)", what, rc);
  CHECK(h2fx_status[id / 2] == want_status, "%s: the client got %d (got %d)",
        what, want_status, h2fx_status[id / 2]);
  CHECK(h2fx_notes == notes_before + 1 && h2fx_note_status == want_status &&
        h2fx_note_ttfb == 0,
        "%s: the answer took the class count once, status %d, no TTFB sample "
        "(notes +%d, status %d, ttfb %d)",
        what, want_status, h2fx_notes - notes_before, h2fx_note_status,
        h2fx_note_ttfb);
  CHECK(h2fx_stream(id) == NULL,
        "%s: the answer ended the stream and freed it (the case can see a read after the free)",
        what);
}

/* What the last answer says of itself: its stage (want_stage NULL: an
 * answer that names none must carry no field of the family) and the request
 * ID (want_rid NULL: the field must be absent). The two are independent. */
static void
mark_is(const char *what, const char *want_stage, const char *want_rid)
{
  const char *v = h2fx_header(last_id, "x-loxilb-refusal-stage");

  if (want_stage)
    CHECK(v && !strcmp(v, want_stage), "%s: the refusal names its stage, %s (got %s)",
          what, want_stage, v ? v : "none");
  else
    CHECK(v == NULL, "%s: no stage on it (got %s)", what, v ? v : "none");
  v = h2fx_header(last_id, "x-request-id");
  if (want_rid)
    CHECK(v && !strcmp(v, want_rid), "%s: and echoes the request's ID whole (got %zu bytes)",
          what, v ? strlen(v) : (size_t)0);
  else
    CHECK(v == NULL, "%s: and no request ID (got %s)", what, v ? v : "none");
}

int
main(void)
{
  proxy_epval_t *pool;
  char rid255[256];

  memset(rid255, 'r', 255);
  rid255[255] = '\0';

  h2fx_init();
  h2fx_admit = admit;
  h2fx_l7 = l7_reject;
  h2fx_chwbl = chwbl_refuse;

  /* No pool on the listener (deleted under its streams): no admission, the
   * model has no pool, 503. The model name the log prints is the stream's. */
  the_rid = "rid-h2-1";
  run(CASE_NO_POOL, 503, "no pool for the model");
  CHECK(h2fx_admit_calls == 0 && h2fx_lpm_calls == 1, "no admission without a pool, one lookup");
  mark_is("no pool for the model", "route", "rid-h2-1");
  /* A stream with no ID yet carries the stage alone; an ID that cannot be a
   * header value (a blank at its end) is left out, never cut. */
  the_rid = NULL;
  run(CASE_NO_POOL, 503, "no pool, no request ID");
  mark_is("no pool, no request ID", "route", NULL);
  the_rid = "rid-with-a-blank ";
  run(CASE_NO_POOL, 503, "no pool, an ID that is not a field value");
  mark_is("no pool, an ID that is not a field value", "route", NULL);
  the_rid = NULL;

  /* Forwarding one stream sends whatever is queued for the others: a stream
   * whose answer was waiting for the client's window ends, and is freed,
   * inside that send. The walk over the ready streams must not hold it.
   * Stream A opens with its body still to come; stream B is complete and
   * answered, the body of its answer held by a client window of 0. Then one
   * read brings B's window and the end of A's body: forwarding A flushes B
   * and frees it while the walk is on A. */
  {
    nghttp2_settings_entry zero = { NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 0 };
    nghttp2_settings_entry open = { NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 65535 };
    nghttp2_nv req[] = {
      { (uint8_t *)":method", (uint8_t *)"POST", 7, 4, 0 },
      { (uint8_t *)":path", (uint8_t *)"/v1/chat/completions", 5, 20, 0 },
      { (uint8_t *)":scheme", (uint8_t *)"http", 7, 4, 0 },
      { (uint8_t *)":authority", (uint8_t *)"all.example", 10, 11, 0 },
      { (uint8_t *)"x-model", (uint8_t *)"m-gone", 7, 6, 0 },
    };
    nghttp2_data_provider body = { .read_callback = small_body };
    proxy_h2_stream_t *sa, *sb;
    int32_t a, b;

    set_case(CASE_NO_POOL);
    assert(nghttp2_submit_settings(h2fx_cl, NGHTTP2_FLAG_NONE, &zero, 1) == 0);
    h2fx_to_gateway();
    a = nghttp2_submit_headers(h2fx_cl, NGHTTP2_FLAG_NONE, -1, NULL, req, 5, NULL);
    b = nghttp2_submit_request(h2fx_cl, NULL, req, 5, NULL, NULL);
    assert(a > 0 && b > a);
    CHECK(h2fx_gw_read() == 0, "A's headers and B's request are read");
    sa = h2fx_stream(a);
    sb = h2fx_stream(b);
    CHECK(sa && !sa->data_complete && sb && sb->response_sent && h2fx_status[b / 2] == 503,
          "B is answered (503) and still open, its body held by the window; A waits for its body");
    assert(nghttp2_submit_window_update(h2fx_cl, NGHTTP2_FLAG_NONE, b, 65535) == 0);
    assert(nghttp2_submit_data(h2fx_cl, NGHTTP2_FLAG_END_STREAM, a, &body) == 0);
    CHECK(h2fx_gw_read() == 0, "one read: B's window and the end of A's body");
    CHECK(h2fx_stream(b) == NULL,
          "forwarding A sent B's answer to its end and freed B, which the walk did not touch");
    CHECK(h2fx_status[a / 2] == 503, "A is answered too (got %d)", h2fx_status[a / 2]);
    assert(nghttp2_submit_settings(h2fx_cl, NGHTTP2_FLAG_NONE, &open, 1) == 0);
    h2fx_to_gateway();
    CHECK(h2fx_stream(a) == NULL, "and once the window opens, A's answer ends it");
  }

  /* The listener has its pool; admission refuses. */
  pool = h2fx_pool("all.example", 0);
  (void)pool;
  the_rid = rid255;
  run(CASE_ADMIT_DENY, 401, "admission refusal");
  CHECK(h2fx_admit_calls == 1, "admission ran once");
  mark_is("admission refusal (a 255-byte ID)", "auth", rid255);
  the_rid = "rid-h2-2";

  /* An L7 policy rejects (the flag l7_policy_on reads). */
  h2fx_ent.has_l7_policy = 1;
  run(CASE_L7_REJECT, 403, "L7 reject");
  CHECK(h2fx_l7_calls == 1, "the L7 dispatch ran once");
  mark_is("L7 reject", "route", "rid-h2-2");
  h2fx_ent.has_l7_policy = 0;

  /* An AI pool with a ceiling of one, held by another request: the stream
   * is refused at the service level (it never held a unit). What this case
   * catches is the refusal reading or releasing through the freed stream;
   * the counts below only show the other request's unit is untouched. */
  {
    fc_cfg_t cfg = { 0 };
    fc_permit_t other = { 0 };

    lpm_pool = sp_pool_alloc();
    assert(lpm_pool);
    snprintf(lpm_pool->ephash_key, sizeof(lpm_pool->ephash_key), "all.example|m-gone");
    lpm_pool->ai_gw_mode = 1;
    lpm_pool->n_eps = 1;
    pthread_mutex_init(&lpm_pool->fc.queue.lock, NULL);
    cfg.mode = FC_MODE_ENFORCE;
    cfg.max_outstanding = 1;
    fc_state_apply(&lpm_pool->fc, &cfg);
    assert(fc_service_acquire(&lpm_pool->fc, &other) == FC_ADMIT);
    run(CASE_CAPACITY, 429, "capacity refusal");
    mark_is("capacity refusal", "capacity", "rid-h2-2");
    CHECK(h2fx_header(last_id, SP_LLMD_REASON_HDR) == NULL,
          "no llm-d reason on a rule that does not speak the convention");
    CHECK(fc_inflight(&lpm_pool->fc) == 1,
          "only the other request's unit is in flight (inflight %u)",
          fc_inflight(&lpm_pool->fc));

    /* With classes on, a sheddable request at the same ceiling: every
     * admission header reaches the client, the class and its band wait
     * after the three counts. */
    {
      char want_wait[16];
      const char *v;

      /* The rule speaks the llm-d convention here, so the frame is at its
       * fullest: the six admission headers and the two of the mark. */
      h2fx_class_on = 1;
      lpm_pool->fc.cfg.llmd_headers = 1;
      snprintf(want_wait, sizeof(want_wait), "%u",
               fc_band_wait_ms(&lpm_pool->fc, FC_BAND_SHEDDABLE));
      run(CASE_SHED_CLASS, 429, "sheddable at the ceiling");
      h2fx_class_on = 0;
      lpm_pool->fc.cfg.llmd_headers = 0;
      mark_is("sheddable at the ceiling", "capacity", "rid-h2-2");
      v = h2fx_header(last_id, SP_LLMD_REASON_HDR);
      CHECK(v && !strcmp(v, "rejected-saturated"),
            "all eight of the frame's extras arrive: the llm-d reason too (got %s)",
            v ? v : "none");
      v = h2fx_header(last_id, "x-loxilb-admission-inflight");
      CHECK(v && !strcmp(v, "1"), "the refusal names the units in flight (got %s)", v ? v : "none");
      v = h2fx_header(last_id, "x-loxilb-admission-limit");
      CHECK(v && !strcmp(v, "1"), "and the ceiling (got %s)", v ? v : "none");
      v = h2fx_header(last_id, "x-loxilb-admission-queued");
      CHECK(v != NULL, "and the queue (got %s)", v ? v : "none");
      v = h2fx_header(last_id, "x-loxilb-admission-class");
      CHECK(v && !strcmp(v, "sheddable"), "and the request's class (got %s)", v ? v : "none");
      v = h2fx_header(last_id, "x-loxilb-admission-band-wait-ms");
      CHECK(v && !strcmp(v, want_wait), "and its band's wait, %s ms (got %s)", want_wait,
            v ? v : "none");
      CHECK(fc_inflight(&lpm_pool->fc) == 1, "the refused stream took no unit");
    }
    /* A draining gateway: the 503's body says when to come back, as the
     * HTTP/1.1 answer does. */
    fc_drain_set(1);
    run(CASE_CAPACITY, 503, "draining");
    fc_drain_set(0);
    mark_is("draining", "capacity", "rid-h2-2");
    {
      const char *b = h2fx_body(last_id);
      const char *v = h2fx_header(last_id, "retry-after");

      CHECK(b && !strcmp(b, "{\"error\":\"gateway_draining\",\"message\":\"the gateway is "
                            "draining for maintenance\",\"retry_after\":5}\r\n"),
            "the 503 body carries retry_after next to error and message (got %s)", b ? b : "none");
      CHECK(v && !strcmp(v, "5"), "and it equals the retry-after header (got %s)", v ? v : "none");
    }
    fc_permit_release(&other);
    CHECK(fc_inflight(&lpm_pool->fc) == 0, "and none after it ends");
    fc_permit_unbind(&other);
  }

  /* A CHWBL pool refuses the request's cache_salt: the client gets its 400
   * on the stream. It used to get nothing: the answer went through the L7
   * responder, which answers only during an L7 dispatch, and the stream was
   * left open. */
  lpm_pool->select = PROXY_SEL_CHWBL;
  run(CASE_BAD_SALT, 400, "invalid cache_salt");
  mark_is("invalid cache_salt", "framing", "rid-h2-2");
  CHECK(fc_inflight(&lpm_pool->fc) == 0, "and the refused request holds no unit");
  lpm_pool->select = 0;

  /* An outage (no member of the route can take the request) is answered
   * through the same frame with no stage: it carries the stream's own
   * request ID all the same, and nothing when the stream has none. The ID
   * does not depend on a stage. */
  {
    static const char *const rids[] = { "rid-h2-outage", NULL };

    h2fx_l7 = l7_forward_all_down;
    for (size_t i = 0; i < 2; i++) {
      const char *what = rids[i] ? "outage, the stream has an ID" : "outage, the stream has no ID";
      proxy_h2_stream_t *st;
      const char *b;
      int32_t id;
      int rc;

      set_case(CASE_NO_POOL);
      h2fx_ent.has_l7_policy = 1;
      id = h2fx_submit("m-gone", NULL, 0);
      last_id = id;
      h2fx_to_gateway();
      st = h2fx_stream(id);
      CHECK(st && st->data_complete && !st->response_sent, "%s: the request is complete", what);
      if (!st)
        continue;
      st->request_id[0] = '\0';
      if (rids[i])
        snprintf(st->request_id, sizeof(st->request_id), "%s", rids[i]);
      rc = proxy_h2_forward_to_backend(h2fx_pfe, st);
      h2fx_deliver();
      b = h2fx_body(id);
      CHECK(rc == 0 && h2fx_status[id / 2] == 503 && b && strstr(b, "\"no_healthy_backend\""),
            "%s: answered 503 no_healthy_backend by the gateway (rc %d, status %d, body %s)",
            what, rc, h2fx_status[id / 2], b ? b : "none");
      mark_is(what, NULL, rids[i]);
    }
    h2fx_pfe->mcp_route_active = 0;
    h2fx_l7 = l7_reject;
    h2fx_ent.has_l7_policy = 0;
    CHECK(fc_inflight(&lpm_pool->fc) == 0, "and the outage holds no unit");
  }

  CHECK(h2fx_connect_calls == 0, "no case reached a backend connect");

  /* Teardown, so the leak check reads only the code under test. */
  fc_state_destroy(&lpm_pool->fc);
  sp_pool_discard(lpm_pool);
  h2fx_fini();
  return h2fx_result();
}
