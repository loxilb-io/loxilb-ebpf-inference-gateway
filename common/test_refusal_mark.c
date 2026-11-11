/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_refusal_mark.c - the refusal mark (sockproxy_refusal_mark.h): the
 * stage a gateway-written refusal names, the request ID it echoes, and the
 * removal of a backend's headers of that family from a relayed head.
 *
 *   - the stage names are the audit record's wire names, value for value,
 *     and a stage with no name yields no mark;
 *   - a request ID is echoed whole or not at all: 255 bytes fit beside the
 *     longest stage, a line break or a control byte leaves it out;
 *   - the ID an answer echoes is the request's live field and nothing else:
 *     with the live field empty there is no X-Request-Id, whatever the audit
 *     key's snapshot holds, and the ID does not depend on a stage;
 *   - a mark is whole or absent: a buffer one byte short gets nothing;
 *   - a finished response takes the mark after its status line with every
 *     other byte in place, and the real HTTP_RESPONSE framer reads the same
 *     status and the same body from it at every cut of the read;
 *   - the family strip takes X-Loxilb-Refusal-* out of a response head in
 *     any letter case, leaves every other header (the admission family
 *     included) and every body byte where they were, and does nothing to a
 *     head that is not whole.
 *
 * Build: make test_refmark (ASan + UBSan).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "llhttp.h"
#include "sockproxy_stream_fallback.h"
#include "sockproxy_refusal_mark.h"

#define log_error(...) ((void)0)
#include "sockproxy_l7hdr_guard.h"
#include "sockproxy_h1_hdr.h"

static int checks, failures;
#define CHECK(cond, ...) do { \
    checks++; \
    if (!(cond)) { failures++; printf("FAIL %d - ", checks); printf(__VA_ARGS__); printf("\n"); } \
  } while (0)

/* ---- the framer's view of a response ------------------------------------ */

typedef struct {
  unsigned complete;
  size_t body_len;
  char body[1024];
} seen_t;

static int on_body(llhttp_t *p, const char *at, size_t n)
{
  seen_t *s = p->data;

  if (s->body_len + n < sizeof(s->body)) {
    memcpy(s->body + s->body_len, at, n);
    s->body_len += n;
  }
  return 0;
}

static int on_complete(llhttp_t *p)
{
  ((seen_t *)p->data)->complete++;
  return 0;
}

/* Parse `wire` cut in two at `split`; with `eof`, the body ends at the close
 * (a response with no Content-Length). Returns the status, -1 on an error. */
static int parse(const char *wire, size_t len, size_t split, int eof, seen_t *s)
{
  llhttp_t p;
  llhttp_settings_t st;

  memset(s, 0, sizeof(*s));
  llhttp_settings_init(&st);
  st.on_body = on_body;
  st.on_message_complete = on_complete;
  llhttp_init(&p, HTTP_RESPONSE, &st);
  p.data = s;
  if (llhttp_execute(&p, wire, split) != HPE_OK)
    return -1;
  if (llhttp_execute(&p, wire + split, len - split) != HPE_OK)
    return -1;
  if (eof && llhttp_finish(&p) != HPE_OK)
    return -1;
  return (int)p.status_code;
}

/* ---- the texts the gateway sends as they are ------------------------------
 * Copies of the whole-text refusals, so the splice is run over the shapes it
 * meets: with and without Content-Length, a header after the blank-line
 * neighbour, a text/plain body. `eof`: the body ends at the close. */
static const struct {
  const char *name;
  const char *text;
  const char *stage;
  int status;
  int eof;
} texts[] = {
  { "model_required_early", SP_MODEL_REQUIRED_EARLY_RESPONSE, "framing", 400, 0 },
  { "bad_request",
    "HTTP/1.1 400 Bad Request\r\n"
    "Content-Type: application/json\r\n"
    "Connection: close\r\n"
    "\r\n"
    "{\"error\":\"bad_request\",\"message\":\"unparseable or "
    "ambiguously framed request refused before admission\"}\r\n", "framing", 400, 1 },
  { "llamafirewall_block",
    "HTTP/1.1 403 Forbidden\r\n"
    "Content-Type: application/json\r\n"
    "Connection: close\r\n"
    "X-LlamaFirewall-Decision: BLOCK\r\n"
    "\r\n"
    "{\"error\":\"Request blocked by LlamaFirewall\",\"reason\":\"Security threat detected\"}\r\n",
    "security", 403, 1 },
  { "no_route",
    "HTTP/1.1 503 Service Unavailable\r\n"
    "Content-Type: application/json\r\n"
    "Connection: close\r\n"
    "\r\n"
    "{\"error\":\"no_route\",\"detail\":\"no routing rule matched the request path\"}\r\n", "route", 503, 1 },
  { "pd_overloaded",
    "HTTP/1.1 429 Too Many Requests\r\n"
    "Content-Type: application/json\r\n"
    "Retry-After: 1\r\n"
    "Connection: close\r\n"
    "\r\n"
    "{\"error\":\"pd_overloaded\",\"detail\":\"all prefill endpoints at in-flight capacity\"}\r\n", "capacity", 429, 1 },
  { "pd_admission_park_timeout (the stage is on the text; the ID is added)",
    "HTTP/1.1 504 Gateway Timeout\r\n"
    "X-Loxilb-Refusal-Stage: queue\r\n"
    "Content-Type: application/json\r\n"
    "Connection: close\r\n"
    "\r\n"
    "{\"error\":\"pd_admission_park_timeout\"}", NULL, 504, 1 },
  { "no_route on a listener kept after its last rule (sockproxy_ep.c: the stage is on the text; the ID is added)",
    "HTTP/1.1 503 Service Unavailable\r\n"
    "X-Loxilb-Refusal-Stage: route\r\n"
    "Content-Type: application/json\r\n"
    "Connection: close\r\n"
    "\r\n"
    "{\"error\":\"no_route\","
    "\"detail\":\"no rule on this listener (kept open after its last rule was deleted)\"}\r\n", NULL, 503, 1 },
  { "an outage (no stage anywhere; the ID alone is added)",
    "HTTP/1.1 503 Service Unavailable\r\n"
    "Content-Type: application/json\r\n"
    "Connection: close\r\n"
    "\r\n"
    "{\"error\":\"service_unavailable\"}\r\n", NULL, 503, 1 },
  { "admission_queue_timeout fallback (the stage is on the text; the ID is added)",
    "HTTP/1.1 504 Gateway Timeout\r\n"
    "X-Loxilb-Refusal-Stage: queue\r\n"
    "Content-Type: application/json\r\n"
    "Content-Length: 35\r\n"
    "Retry-After: 1\r\n"
    "Connection: close\r\n"
    "\r\n"
    "{\"error\":\"admission_queue_timeout\"}", NULL, 504, 0 },
};

static void test_stage_names(void)
{
  /* aiDenyStage (pkg/loxinet/ai_gateway_audit.go), value for value. */
  static const char *const want[] = { NULL, "auth", "conflict", "ratelimit", "reserve",
                                      "capacity", "objective", "route", "framing",
                                      "security" };

  for (int i = 0; i < 10; i++) {
    const char *got = sp_refusal_stage_name(i);

    CHECK((got == NULL) == (want[i] == NULL) && (!got || !strcmp(got, want[i])),
          "stage %d is named %s (got %s)", i, want[i] ? want[i] : "(none)", got ? got : "(none)");
    CHECK(!got || strlen(got) <= SP_REFUSAL_STAGE_MAX, "stage %d fits the mark's room", i);
  }
  CHECK(sp_refusal_stage_name(10) == NULL && sp_refusal_stage_name(-1) == NULL &&
        sp_refusal_stage_name(255) == NULL, "a stage outside the table has no name");
  CHECK(strlen(SP_REFUSAL_STAGE_QUEUE) <= SP_REFUSAL_STAGE_MAX, "queue fits the mark's room");
}

static void test_rid(void)
{
  char id[SP_REFUSAL_RID_MAX + 2];

  CHECK(!sp_refusal_rid_ok(NULL) && !sp_refusal_rid_ok(""), "no ID: nothing to echo");
  CHECK(sp_refusal_rid_ok("a") && sp_refusal_rid_ok("9f1c2b7e4d5a4c0e8b3f6a7d1e2c3b4a"),
        "a plain ID is echoed");
  CHECK(sp_refusal_rid_ok("req 1\tx") && sp_refusal_rid_ok("r\xc3\xa9q"),
        "an inner blank and bytes above 0x7f are field content");
  CHECK(!sp_refusal_rid_ok("a\r\nX-Loxilb-Refusal-Stage: capacity") &&
        !sp_refusal_rid_ok("a\nb") && !sp_refusal_rid_ok("a\rb"),
        "an ID with a line break is not echoed");
  CHECK(!sp_refusal_rid_ok("a\x01" "b") && !sp_refusal_rid_ok("a\x7f"), "nor one with a control byte");
  CHECK(!sp_refusal_rid_ok(" a") && !sp_refusal_rid_ok("a ") && !sp_refusal_rid_ok("\ta") &&
        !sp_refusal_rid_ok("a\t"), "nor one with a blank at either end");
  memset(id, 'x', sizeof(id));
  id[SP_REFUSAL_RID_MAX] = '\0';
  CHECK(sp_refusal_rid_ok(id), "%d bytes: the longest ID a request can have", SP_REFUSAL_RID_MAX);
  id[SP_REFUSAL_RID_MAX] = 'x';
  id[SP_REFUSAL_RID_MAX + 1] = '\0';
  CHECK(!sp_refusal_rid_ok(id), "one byte more is left out, not cut");
}

static void test_mark(void)
{
  char mark[SP_REFUSAL_MARK_MAX + 1], id[SP_REFUSAL_RID_MAX + 1], small[64];
  char longest_stage[SP_REFUSAL_STAGE_MAX + 1];
  int n;

  n = sp_refusal_mark_h1(mark, sizeof(mark), "capacity", "req-1");
  CHECK(n > 0 && !strcmp(mark, "X-Loxilb-Refusal-Stage: capacity\r\nX-Request-Id: req-1\r\n") &&
        (size_t)n == strlen(mark), "stage and ID: two lines, the stage first");
  n = sp_refusal_mark_h1(mark, sizeof(mark), "route", "");
  CHECK(n > 0 && !strcmp(mark, "X-Loxilb-Refusal-Stage: route\r\n"), "no ID: the stage alone");
  n = sp_refusal_mark_h1(mark, sizeof(mark), "route", "a\r\nInjected: 1");
  CHECK(n > 0 && !strcmp(mark, "X-Loxilb-Refusal-Stage: route\r\n"),
        "an ID that is not one header value: the stage alone, no injected line");
  n = sp_refusal_mark_h1(mark, sizeof(mark), NULL, "req-1");
  CHECK(n > 0 && !strcmp(mark, "X-Request-Id: req-1\r\n"), "no stage: the ID alone");
  n = sp_refusal_mark_h1(mark, sizeof(mark), NULL, NULL);
  CHECK(n == 0 && mark[0] == '\0', "neither: nothing, and that is not an error");

  /* The room the senders give: the longest stage with the longest ID. */
  memset(id, 'r', SP_REFUSAL_RID_MAX);
  id[SP_REFUSAL_RID_MAX] = '\0';
  memset(longest_stage, 's', SP_REFUSAL_STAGE_MAX);
  longest_stage[SP_REFUSAL_STAGE_MAX] = '\0';
  n = sp_refusal_mark_h1(mark, sizeof(mark), longest_stage, id);
  CHECK(n == (int)SP_REFUSAL_MARK_MAX && strstr(mark, id) != NULL,
        "the longest stage and a %d-byte ID fill SP_REFUSAL_MARK_MAX exactly (%d of %zu)",
        SP_REFUSAL_RID_MAX, n, (size_t)SP_REFUSAL_MARK_MAX);
  n = sp_refusal_mark_h1(mark, sizeof(mark) - 1, longest_stage, id);
  CHECK(n == -1 && mark[0] == '\0', "one byte short: no mark at all, never a cut one");

  /* A mark is whole or absent at every size. */
  for (size_t cap = 1; cap <= sizeof(small); cap++) {
    memset(small, '#', sizeof(small));
    n = sp_refusal_mark_h1(small, cap, "capacity", "req-1");
    if (n < 0)
      CHECK(small[0] == '\0', "cap %zu: refused and emptied", cap);
    else
      CHECK((size_t)n < cap && !strcmp(small, "X-Loxilb-Refusal-Stage: capacity\r\nX-Request-Id: req-1\r\n"),
            "cap %zu: whole", cap);
  }
  n = sp_refusal_mark_h1(small, 0, "capacity", "req-1");
  CHECK(n == -1, "no buffer: refused");
  CHECK(sp_refusal_mark_h1(NULL, 16, "capacity", "req-1") == -1, "NULL buffer: refused");
}

/* The ID an HTTP/1.1 answer echoes: the connection's live field, read
 * through SP_REFUSAL_LIVE_RID as every sender reads it. The second field
 * stands for the audit key's snapshot (resp_request_id), which on a
 * keep-alive connection can still hold the previous request's ID. */
static void test_live_rid(void)
{
  struct { char vllm_request_id[256]; char resp_request_id[256]; } c;
  static const char answer[] =
    "HTTP/1.1 400 Bad Request\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
  char mark[SP_REFUSAL_MARK_MAX + 1], out[512 + SP_REFUSAL_MARK_MAX];
  size_t n;

  memset(&c, 0, sizeof(c));
  snprintf(c.vllm_request_id, sizeof(c.vllm_request_id), "req-this");
  snprintf(c.resp_request_id, sizeof(c.resp_request_id), "req-previous");
  CHECK(sp_refusal_mark_h1(mark, sizeof(mark), "framing", SP_REFUSAL_LIVE_RID(&c)) > 0 &&
        !strcmp(mark, "X-Loxilb-Refusal-Stage: framing\r\nX-Request-Id: req-this\r\n"),
        "a refusal echoes the request's own ID");
  CHECK(sp_refusal_mark_h1(mark, sizeof(mark), NULL, SP_REFUSAL_LIVE_RID(&c)) > 0 &&
        !strcmp(mark, "X-Request-Id: req-this\r\n"),
        "an answer that names no stage (an outage, a refusal after dispatch) echoes it all the same");
  n = sp_refusal_mark_splice(out, sizeof(out), answer, sizeof(answer) - 1, NULL, SP_REFUSAL_LIVE_RID(&c));
  CHECK(n == sizeof(answer) - 1 + strlen("X-Request-Id: req-this\r\n") &&
        strstr(out, "HTTP/1.1 400 Bad Request\r\nX-Request-Id: req-this\r\nContent-Length: 2\r\n") == out &&
        !strstr(out, SP_REFUSAL_HDR_PREFIX),
        "spliced into a finished answer: the ID after the status line, no stage");

  /* The request has no ID of its own (refused before one was read, or
   * answered after it was forwarded): nothing is echoed, and least of all
   * what the snapshot still holds. */
  c.vllm_request_id[0] = '\0';
  CHECK(sp_refusal_mark_h1(mark, sizeof(mark), "framing", SP_REFUSAL_LIVE_RID(&c)) > 0 &&
        !strcmp(mark, "X-Loxilb-Refusal-Stage: framing\r\n"),
        "no live ID: the stage alone, never the snapshot's ID");
  CHECK(sp_refusal_mark_h1(mark, sizeof(mark), NULL, SP_REFUSAL_LIVE_RID(&c)) == 0 && mark[0] == '\0',
        "no live ID and no stage: no header at all");
  CHECK(sp_refusal_mark_splice(out, sizeof(out), answer, sizeof(answer) - 1, NULL,
                               SP_REFUSAL_LIVE_RID(&c)) == 0,
        "and the finished answer goes out as it was built");
}

static void test_splice(void)
{
  char out[1024 + SP_REFUSAL_MARK_MAX], want_mark[SP_REFUSAL_MARK_MAX + 1];
  seen_t plain, marked;

  for (size_t t = 0; t < sizeof(texts) / sizeof(texts[0]); t++) {
    const char *text = texts[t].text;
    size_t len = strlen(text);
    const char *eol = strstr(text, "\r\n");
    size_t head = (size_t)(eol - text) + 2;
    int m = sp_refusal_mark_h1(want_mark, sizeof(want_mark), texts[t].stage, "req-7f3a");
    size_t n = sp_refusal_mark_splice(out, sizeof(out), text, len, texts[t].stage, "req-7f3a");

    CHECK(m > 0 && n == len + (size_t)m && out[n] == '\0',
          "%s: the response grows by its mark and nothing else", texts[t].name);
    CHECK(!memcmp(out, text, head) && !memcmp(out + head, want_mark, (size_t)m) &&
          !memcmp(out + head + m, text + head, len - head),
          "%s: the mark sits after the status line, every other byte in place", texts[t].name);
    CHECK(strstr(out, "\r\nX-Request-Id: req-7f3a\r\n") != NULL, "%s: the request is named", texts[t].name);
    {
      const char *first = strstr(out, "X-Loxilb-Refusal-Stage: ");
      int staged = texts[t].stage || strstr(text, "X-Loxilb-Refusal-Stage: ");

      if (staged)
        CHECK(first && !strstr(first + 1, "X-Loxilb-Refusal-Stage: "),
              "%s: the stage is named once", texts[t].name);
      else
        CHECK(!first && !strstr(out, SP_REFUSAL_HDR_PREFIX),
              "%s: no stage is added to an answer that names none", texts[t].name);
    }
    /* The framer reads the same response from it, at every cut. */
    CHECK(parse(text, len, len, texts[t].eof, &plain) == texts[t].status && plain.complete == 1,
          "%s: the text itself is a whole %d", texts[t].name, texts[t].status);
    for (size_t split = 0; split <= n; split++) {
      int st = parse(out, n, split, texts[t].eof, &marked);

      if (st != texts[t].status || marked.complete != 1 || marked.body_len != plain.body_len ||
          memcmp(marked.body, plain.body, plain.body_len)) {
        CHECK(0, "%s cut at %zu: status %d, complete %u, body %zu bytes (want %d, 1, %zu)",
              texts[t].name, split, st, marked.complete, marked.body_len, texts[t].status,
              plain.body_len);
        break;
      }
    }
    checks++;

    /* Room: one byte short of the marked response and its NUL is refused,
     * and the buffer is the caller's to ignore. */
    CHECK(sp_refusal_mark_splice(out, n + 1, text, len, texts[t].stage, "req-7f3a") == n,
          "%s: fits a buffer of its length and a NUL", texts[t].name);
    CHECK(sp_refusal_mark_splice(out, n, text, len, texts[t].stage, "req-7f3a") == 0,
          "%s: one byte short, the caller sends the text as it is", texts[t].name);
  }

  {
    static const char ok[] = "HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n{}";

    CHECK(sp_refusal_mark_splice(out, sizeof(out), ok, sizeof(ok) - 1, NULL, NULL) == 0,
          "nothing to add: the text as it is");
    CHECK(sp_refusal_mark_splice(out, sizeof(out), ok, sizeof(ok) - 1, NULL, "a\rb") == 0,
          "an ID that cannot be echoed and no stage: the text as it is");
    CHECK(sp_refusal_mark_splice(out, sizeof(out), "data: {\"error\":\"client_stalled\"}\n\n", 34,
                                 "queue", "r") == 0,
          "an event inside an answer is not a response: untouched");
    CHECK(sp_refusal_mark_splice(out, sizeof(out), "HTTP/1.1 503 Service Unavailable", 32,
                                 "route", "r") == 0,
          "a status line with no end: untouched");
    CHECK(sp_refusal_mark_splice(out, sizeof(out), NULL, 64, "route", "r") == 0 &&
          sp_refusal_mark_splice(NULL, 64, ok, sizeof(ok) - 1, "route", "r") == 0 &&
          sp_refusal_mark_splice(out, sizeof(out), ok, 4, "route", "r") == 0,
          "no text, no buffer, a text too short to be a response: untouched");
  }
}

static void test_strip(void)
{
  static const char body[] =
    "X-Loxilb-Refusal-Stage: capacity\r\n\r\n{\"error\":{\"message\":\"backend says no\"}}";
  char buf[1024], want[1024];
  uint8_t *end;
  size_t len;
  seen_t s;

  /* A backend's 429 that imitates a gateway refusal. */
  len = (size_t)snprintf(buf, sizeof(buf),
      "HTTP/1.1 429 Too Many Requests\r\n"
      "X-Loxilb-Refusal-Stage: capacity\r\n"
      "Content-Type: application/json\r\n"
      "x-loxilb-refusal-stage: queue\r\n"
      "X-LOXILB-REFUSAL-ANYTHING: 1\r\n"
      "X-Loxilb-Admission-Inflight: 999\r\n"
      "X-Loxilb-Refusal: not-of-the-family\r\n"
      "X-Request-Id: backend-echo\r\n"
      "Content-Length: %zu\r\n"
      "X-Loxilb-Refusal-Stage: route\r\n"
      "\r\n%s", sizeof(body) - 1, body);
  end = l7h1_strip_header_prefix((uint8_t *)buf, &len, SP_REFUSAL_HDR_PREFIX);
  buf[len] = '\0';
  CHECK(end != NULL, "the head keeps its end");
  snprintf(want, sizeof(want),
      "HTTP/1.1 429 Too Many Requests\r\n"
      "Content-Type: application/json\r\n"
      "X-Loxilb-Admission-Inflight: 999\r\n"
      "X-Loxilb-Refusal: not-of-the-family\r\n"
      "X-Request-Id: backend-echo\r\n"
      "Content-Length: %zu\r\n"
      "\r\n%s", sizeof(body) - 1, body);
  CHECK(!strcmp(buf, want),
      "every line of the family is gone in any letter case, first, middle and last; "
      "the other headers and the body, which holds the same text, are where they were");
  CHECK(parse(buf, len, len, 0, &s) == 429 && s.complete == 1 && s.body_len == sizeof(body) - 1 &&
        !memcmp(s.body, body, s.body_len), "and the framer reads the same 429 and the same body");

  /* Nothing of the family: not a byte moves. */
  len = (size_t)snprintf(buf, sizeof(buf),
      "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Loxilb-Admission-Limit: 4\r\n\r\n{}");
  {
    char before[128];
    size_t blen = len;

    memcpy(before, buf, len);
    end = l7h1_strip_header_prefix((uint8_t *)buf, &len, SP_REFUSAL_HDR_PREFIX);
    CHECK(end != NULL && len == blen && !memcmp(before, buf, len), "a head without the family is untouched");
  }

  /* A head that is not whole is left as it is (the relay never hands one
   * over: sp_resp_strip_refusal_mark acts only on a read the response
   * framer marked as a whole header block). */
  len = (size_t)snprintf(buf, sizeof(buf),
      "HTTP/1.1 429 Too Many Requests\r\nX-Loxilb-Refusal-Stage: capacity\r\nContent-Le");
  {
    size_t blen = len;

    end = l7h1_strip_header_prefix((uint8_t *)buf, &len, SP_REFUSAL_HDR_PREFIX);
    CHECK(end == NULL && len == blen, "a split head: nothing is removed");
  }

  /* HTTP/2 field names. */
  CHECK(sp_refusal_hdr_is_mark((const uint8_t *)"x-loxilb-refusal-stage", 22) &&
        sp_refusal_hdr_is_mark((const uint8_t *)"X-Loxilb-Refusal-Other", 22),
        "an HTTP/2 field of the family, in any letter case");
  CHECK(!sp_refusal_hdr_is_mark((const uint8_t *)"x-loxilb-refusal-", 17) &&
        !sp_refusal_hdr_is_mark((const uint8_t *)"x-loxilb-refusal", 16) &&
        !sp_refusal_hdr_is_mark((const uint8_t *)"x-loxilb-admission-limit", 24) &&
        !sp_refusal_hdr_is_mark((const uint8_t *)"x-request-id", 12) &&
        !sp_refusal_hdr_is_mark(NULL, 22),
        "the bare prefix, the admission family and x-request-id are not of it");
}

int main(void)
{
  test_stage_names();
  test_rid();
  test_mark();
  test_live_rid();
  test_splice();
  test_strip();
  if (failures) {
    printf("refusal mark: %d of %d checks FAILED\n", failures, checks);
    return 1;
  }
  printf("refusal mark: %d checks PASS (stage names, request-ID echo, live ID only, whole-or-absent mark, "
         "splice at every cut, family strip)\n", checks);
  return 0;
}
