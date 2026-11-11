/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-Clause) */
/*
 * test_obj_hint.c - the objective a request asks for by header, the class
 * headers of an admitted response, and the one edit made to a backend's
 * response head.
 *
 *   make test_objhint
 *
 * The capture is driven by the real request framer over reads cut where a
 * socket cuts them. The response cases run the real response framer with
 * the per-read answer the gateway keeps (sockproxy_creq_block.h) and the
 * header edit it then makes (sockproxy_h1_hdr.h). Every buffer that is
 * edited is a heap buffer of the exact size the edit may use, so the
 * sanitizers see a byte written outside it.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "llhttp.h"
#include "sockproxy_creq_block.h"
#include "sockproxy_obj_hint.h"

#define log_error(...) ((void)0)
#include "sockproxy_l7hdr_guard.h"
#include "sockproxy_h1_hdr.h"

static int failures = 0;
static int checks   = 0;

#define CHECK(cond, ...) do { \
    checks++; \
    if (!(cond)) { failures++; printf("  FAIL "); printf(__VA_ARGS__); printf("\n"); } \
    else { printf("  ok   "); printf(__VA_ARGS__); printf("\n"); } \
  } while (0)

/* ---- a client connection as the proxy keeps it: the header name last
 * seen, and the hint ---- */
typedef struct creq {
  llhttp_t parser;
  char last_name[128];
  sp_obj_hint_t hint;
} creq_t;

static llhttp_settings_t req_settings;

static int
req_on_field(llhttp_t *p, const char *at, size_t len)
{
  creq_t *c = p->data;

  if (len < sizeof(c->last_name)) {
    memcpy(c->last_name, at, len);
    c->last_name[len] = '\0';
  }
  sp_obj_hint_name(&c->hint);
  return 0;
}

static int
req_on_value(llhttp_t *p, const char *at, size_t len)
{
  creq_t *c = p->data;

  sp_obj_hint_val(&c->hint, sp_obj_hint_which(c->last_name, strlen(c->last_name)),
                  at, len);
  return 0;
}

static void
creq_init(creq_t *c)
{
  llhttp_settings_init(&req_settings);
  req_settings.on_header_field = req_on_field;
  req_settings.on_header_value = req_on_value;
  llhttp_init(&c->parser, HTTP_REQUEST, &req_settings);
  c->parser.data = c;
  c->last_name[0] = '\0';
  sp_obj_hint_reset(&c->hint);
}

/* Feed one read from a heap copy of its exact size. */
static void
creq_read(creq_t *c, const char *bytes, size_t len)
{
  char *copy = malloc(len ? len : 1);

  memcpy(copy, bytes, len);
  (void)llhttp_execute(&c->parser, copy, len);
  free(copy);
}

/* The hint a request leaves, the request fed whole and then cut at `cut`
 * (0 = whole only). Returns the name captured on the last run. */
static const char *
hint_of(creq_t *c, const char *req, size_t cut)
{
  size_t len = strlen(req);

  creq_init(c);
  if (cut == 0 || cut >= len) {
    creq_read(c, req, len);
  } else {
    creq_read(c, req, cut);
    creq_read(c, req + cut, len - cut);
  }
  return c->hint.name;
}

#define REQ_HEAD "POST /v1/chat/completions HTTP/1.1\r\nHost: a\r\n"
#define REQ_TAIL "Content-Length: 2\r\n\r\n{}"

static void
test_capture(void)
{
  creq_t c;
  const char *r;
  size_t at;
  char big[512];

  printf("== the objective header\n");

  r = REQ_HEAD "x-llm-d-inference-objective: realtime\r\n" REQ_TAIL;
  CHECK(!strcmp(hint_of(&c, r, 0), "realtime"), "the canonical name is captured");

  r = REQ_HEAD "X-Gateway-Inference-Objective: batch\r\n" REQ_TAIL;
  CHECK(!strcmp(hint_of(&c, r, 0), "batch"), "the deprecated name is captured, in any case");

  r = REQ_HEAD "x-llm-d-inference-objective: new\r\nx-gateway-inference-objective: old\r\n" REQ_TAIL;
  CHECK(!strcmp(hint_of(&c, r, 0), "new"), "the new name wins when it comes first");
  r = REQ_HEAD "x-gateway-inference-objective: old\r\nx-llm-d-inference-objective: new\r\n" REQ_TAIL;
  CHECK(!strcmp(hint_of(&c, r, 0), "new"), "the new name wins when it comes second");
  r = REQ_HEAD "x-gateway-inference-objective: old\r\nx-llm-d-inference-objective: new\r\n"
      "x-gateway-inference-objective: older\r\n" REQ_TAIL;
  CHECK(!strcmp(hint_of(&c, r, 0), "new"), "a deprecated header after the new one changes nothing");

  r = REQ_HEAD "x-llm-d-inference-objective: first\r\nx-llm-d-inference-objective: second\r\n" REQ_TAIL;
  CHECK(!strcmp(hint_of(&c, r, 0), "second"), "one name repeated: the last value");

  r = REQ_HEAD "x-llm-d-inference-objective-id: realtime\r\n" REQ_TAIL;
  CHECK(hint_of(&c, r, 0)[0] == '\0', "a longer name that begins with the header's is not a hint");
  r = REQ_HEAD "x-llm-d-inference-objectiv: realtime\r\n" REQ_TAIL;
  CHECK(hint_of(&c, r, 0)[0] == '\0', "a shorter name is not a hint");
  r = REQ_HEAD "x-llm-d-inference-fairness-id: t1\r\n" REQ_TAIL;
  CHECK(hint_of(&c, r, 0)[0] == '\0', "the fairness header is not a hint");
  r = REQ_HEAD REQ_TAIL;
  CHECK(hint_of(&c, r, 0)[0] == '\0', "no header, no hint");

  /* A read boundary at every position inside the value. */
  r = REQ_HEAD "x-llm-d-inference-objective: realtime-tier-one\r\n" REQ_TAIL;
  {
    const char *v = strstr(r, "realtime-tier-one");
    int bad = 0;

    for (at = (size_t)(v - r); at <= (size_t)(v - r) + strlen("realtime-tier-one"); at++)
      if (strcmp(hint_of(&c, r, at), "realtime-tier-one"))
        bad++;
    CHECK(bad == 0, "a value cut by a read boundary anywhere is captured whole (%d cuts wrong)", bad);
  }

  /* 63 bytes fit; 64 do not, and are not kept as a shorter name. */
  memset(big, 'o', sizeof(big));
  snprintf(big, sizeof(big), REQ_HEAD "x-llm-d-inference-objective: %.63s\r\n" REQ_TAIL,
           "ooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo");
  CHECK(strlen(hint_of(&c, big, 0)) == 63, "a name of 63 bytes is captured whole");
  snprintf(big, sizeof(big), REQ_HEAD "x-llm-d-inference-objective: %.64s\r\n" REQ_TAIL,
           "ooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo");
  CHECK(!strcmp(hint_of(&c, big, 0), SP_OBJ_OVERSIZE), "a name of 64 bytes reads as a name no objective has");
  {
    const char *v = strstr(big, ": ooo") + 2;

    CHECK(!strcmp(hint_of(&c, big, (size_t)(v - big) + 40), SP_OBJ_OVERSIZE),
          "the same when a read boundary falls inside it");
  }
  snprintf(big, sizeof(big), REQ_HEAD "x-llm-d-inference-objective: %.64s\r\n"
           "x-llm-d-inference-objective: small\r\n" REQ_TAIL,
           "ooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo");
  CHECK(!strcmp(hint_of(&c, big, 0), "small"), "an oversize value does not stick to the next header");
}

/* ---- the class headers on a response head ---- */

/* Run the splice on a heap buffer whose capacity is exactly `cap`. */
static size_t
expose(const char *resp, size_t len, size_t cap, const char *objective,
       uint8_t cls, const char *requested, int *res, char **out)
{
  uint8_t *buf = malloc(cap);
  size_t n;

  memcpy(buf, resp, len);
  n = sp_class_expose_h1(buf, len, cap, objective, cls, requested, res);
  *out = malloc(n + 1);
  memcpy(*out, buf, n);
  (*out)[n] = '\0';
  free(buf);
  return n;
}

static void
test_expose(void)
{
  const char *resp, *body;
  char *out;
  size_t n, len;
  int res;

  printf("== the class headers\n");

  resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 17\r\n\r\n"
         "{\"a\":\"\\r\\n\\r\\nX\"}\r\n\r\n";
  len = strlen(resp);
  body = strstr(resp, "\r\n\r\n") + 4;
  n = expose(resp, len, len + 128, "batch", 2, NULL, &res, &out);
  CHECK(res == SP_CLASS_H1_DONE, "a whole head takes the headers");
  CHECK(strstr(out, "\r\nX-Loxilb-Admission-Objective: batch\r\n") &&
        strstr(out, "\r\nX-Loxilb-Admission-Class: sheddable\r\n\r\n"),
        "the objective and the class are on the head");
  CHECK(n > len && !memcmp(out + n - strlen(body), body, strlen(body)),
        "the body is byte for byte what the backend sent");
  CHECK(!memcmp(out, resp, (size_t)(body - 2 - resp)), "the backend's own head lines are unchanged");
  free(out);

  n = expose(resp, len, len + 128, "", 0, NULL, &res, &out);
  CHECK(res == SP_CLASS_H1_DONE && strstr(out, "X-Loxilb-Admission-Class: standard\r\n") &&
        !strstr(out, "Admission-Objective"), "no hint applied: the class alone");
  free(out);
  n = expose(resp, len, len + 128, "tier:priority", 1, NULL, &res, &out);
  CHECK(strstr(out, "X-Loxilb-Admission-Objective: tier:priority\r\n") &&
        strstr(out, "X-Loxilb-Admission-Class: critical\r\n"), "a tier hint is named as tier:<value>");
  free(out);
  n = expose(resp, len, len + 128, "bad\r\nInjected: 1", 1, NULL, &res, &out);
  CHECK(!strstr(out, "Injected") && strstr(out, "X-Loxilb-Admission-Class: critical\r\n"),
        "an objective name that is not header text is not written");
  free(out);

  /* Exactly enough room, and one byte short. */
  {
    size_t need = strlen("X-Loxilb-Admission-Objective: batch\r\nX-Loxilb-Admission-Class: sheddable\r\n");

    n = expose(resp, len, len + need, "batch", 2, NULL, &res, &out);
    CHECK(res == SP_CLASS_H1_DONE && n == len + need, "exactly enough room is enough");
    free(out);
    n = expose(resp, len, len + need - 1, "batch", 2, NULL, &res, &out);
    CHECK(res == SP_CLASS_H1_SKIPPED && n == len && !memcmp(out, resp, len),
          "one byte short: nothing is written and nothing changes");
    free(out);
  }

  /* A backend's own lines of the two names go; its other admission lines stay. */
  resp = "HTTP/1.1 200 OK\r\nx-loxilb-admission-class: critical\r\n"
         "X-Loxilb-Admission-Objective: stolen\r\nX-Loxilb-Admission-Inflight: 3\r\n"
         "X-Loxilb-Admission-Classic: keep\r\nContent-Length: 0\r\n\r\n";
  len = strlen(resp);
  n = expose(resp, len, len + 128, "", 2, NULL, &res, &out);
  CHECK(res == SP_CLASS_H1_DONE && !strstr(out, "critical") && !strstr(out, "stolen"),
        "the backend's own class and objective lines are removed");
  CHECK(strstr(out, "X-Loxilb-Admission-Inflight: 3\r\n") && strstr(out, "X-Loxilb-Admission-Classic: keep\r\n"),
        "other lines stay, a longer name that begins the same included");
  free(out);

  resp = "HTTP/1.1 100 Continue\r\n\r\n";
  len = strlen(resp);
  n = expose(resp, len, len + 128, "batch", 2, NULL, &res, &out);
  CHECK(res == SP_CLASS_H1_INTERIM && n == len, "an interim head is left for the final one");
  free(out);

  resp = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n";
  len = strlen(resp);
  n = expose(resp, len, len + 128, "batch", 2, NULL, &res, &out);
  CHECK(res == SP_CLASS_H1_SKIPPED && n == len, "a head that is not whole in the read is left");
  free(out);

  resp = "data: {\"x\":1}\r\n\r\nHTTP/1.1 200 OK\r\n\r\n";
  len = strlen(resp);
  n = expose(resp, len, len + 128, "batch", 2, NULL, &res, &out);
  CHECK(res == SP_CLASS_H1_SKIPPED && n == len && !memcmp(out, resp, len),
        "bytes that do not begin with a status line are left");
  free(out);
}

/* ---- what a request asked for and did not get ---- */
static void
test_requested(void)
{
  static const char L_OBJ[] = "X-Loxilb-Admission-Objective: batch\r\n";
  static const char L_CLASS[] = "X-Loxilb-Admission-Class: sheddable\r\n";
  static const char L_REQ[] = "X-Loxilb-Admission-Objective-Requested: premium\r\n";
  const char *resp;
  char *out, big[512], name63[64];
  creq_t c;
  size_t n, len;
  int res;

  printf("== the objective a request asked for and may not use\n");

  resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
  len = strlen(resp);

  /* Denied, and the request fell to a default objective: all three, the
   * new line last. */
  n = expose(resp, len, len + 256, "batch", 2, "premium", &res, &out);
  CHECK(res == SP_CLASS_H1_DONE && strstr(out, L_OBJ) && strstr(out, L_CLASS) &&
        strstr(out, "\r\nX-Loxilb-Admission-Objective-Requested: premium\r\n\r\n{}"),
        "denied: the hint the client sent is on the head, after the applied objective and the class");
  CHECK(n == len + strlen(L_OBJ) + strlen(L_CLASS) + strlen(L_REQ), "and nothing else was added");
  free(out);

  /* Denied with no default: the applied objective is absent, the requested
   * one is not. */
  n = expose(resp, len, len + 256, "", 0, "premium", &res, &out);
  CHECK(res == SP_CLASS_H1_DONE && !strstr(out, "X-Loxilb-Admission-Objective: ") &&
        strstr(out, "X-Loxilb-Admission-Class: standard\r\n" "X-Loxilb-Admission-Objective-Requested: premium\r\n"),
        "denied with no default objective: the class and what was asked for");
  free(out);

  /* Not denied: the caller passes no hint, or an empty one. */
  n = expose(resp, len, len + 256, "batch", 2, NULL, &res, &out);
  CHECK(res == SP_CLASS_H1_DONE && !strstr(out, "Objective-Requested") && strstr(out, L_OBJ),
        "not denied: the header is absent");
  free(out);
  n = expose(resp, len, len + 256, "batch", 2, "", &res, &out);
  CHECK(res == SP_CLASS_H1_DONE && !strstr(out, "Objective-Requested"),
        "an empty hint writes no header");
  free(out);

  /* A tier that was asked for by the body and denied. */
  n = expose(resp, len, len + 256, "", 0, "tier:priority", &res, &out);
  CHECK(strstr(out, "X-Loxilb-Admission-Objective-Requested: tier:priority\r\n"),
        "a denied body tier is named as tier:<value>");
  free(out);

  /* A value that is not header text is not written; the pair still is. */
  n = expose(resp, len, len + 256, "batch", 2, "pre mium", &res, &out);
  CHECK(res == SP_CLASS_H1_DONE && !strstr(out, "Objective-Requested") && strstr(out, L_CLASS),
        "a hint with a space in it is not written, the class headers are");
  free(out);
  n = expose(resp, len, len + 256, "batch", 2, "x\r\nInjected: 1", &res, &out);
  CHECK(!strstr(out, "Injected") && !strstr(out, "Objective-Requested"),
        "nor one with a line break in it");
  free(out);

  /* An oversize hint, captured by the real request framer, is what the
   * capture made of it. */
  snprintf(big, sizeof(big), REQ_HEAD "x-llm-d-inference-objective: %.64s\r\n" REQ_TAIL,
           "ooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo");
  n = expose(resp, len, len + 256, "", 0, hint_of(&c, big, 0), &res, &out);
  CHECK(strstr(out, "X-Loxilb-Admission-Objective-Requested: " SP_OBJ_OVERSIZE "\r\n"),
        "an oversize hint is reported as " SP_OBJ_OVERSIZE);
  free(out);

  /* The longest values there can be: 63 bytes each. */
  memset(name63, 'n', 63);
  name63[63] = '\0';
  n = expose(resp, len, len + 512, name63, 1, name63, &res, &out);
  CHECK(res == SP_CLASS_H1_DONE && n == len + 30 + 63 + 2 + strlen("X-Loxilb-Admission-Class: critical\r\n") + 40 + 63 + 2,
        "two names of 63 bytes are written whole (%zu bytes added)", n - len);
  free(out);

  /* All of it or none: exactly enough room, and one byte short. */
  {
    size_t need = strlen(L_OBJ) + strlen(L_CLASS) + strlen(L_REQ);

    n = expose(resp, len, len + need, "batch", 2, "premium", &res, &out);
    CHECK(res == SP_CLASS_H1_DONE && n == len + need, "exactly enough room for the three lines is enough");
    free(out);
    n = expose(resp, len, len + need - 1, "batch", 2, "premium", &res, &out);
    CHECK(res == SP_CLASS_H1_SKIPPED && n == len && !memcmp(out, resp, len),
          "one byte short: none of the three is written and nothing changes");
    free(out);
  }

  /* A backend's own line of that name never reaches the client. */
  resp = "HTTP/1.1 200 OK\r\nX-Loxilb-Admission-Objective-Requested: forged\r\n"
         "x-loxilb-admission-objective-requested: forged2\r\n"
         "X-Loxilb-Admission-Objective-Requested-By: keep\r\nContent-Length: 0\r\n\r\n";
  len = strlen(resp);
  n = expose(resp, len, len + 256, "", 0, NULL, &res, &out);
  CHECK(res == SP_CLASS_H1_DONE && !strstr(out, "forged"),
        "not denied: the backend's lines of that name are removed, in any case");
  CHECK(strstr(out, "X-Loxilb-Admission-Objective-Requested-By: keep\r\n"),
        "a longer name that begins the same stays");
  free(out);
  n = expose(resp, len, len + 256, "", 0, "premium", &res, &out);
  CHECK(!strstr(out, "forged") &&
        strstr(out, "X-Loxilb-Admission-Objective-Requested: premium\r\n\r\n"),
        "denied: the backend's lines go and the gateway's is the only one");
  free(out);

  /* An interim head and a head that is not whole take nothing, as before. */
  resp = "HTTP/1.1 103 Early Hints\r\n\r\n";
  len = strlen(resp);
  n = expose(resp, len, len + 256, "batch", 2, "premium", &res, &out);
  CHECK(res == SP_CLASS_H1_INTERIM && n == len, "an interim head is left for the final one");
  free(out);
  resp = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n";
  len = strlen(resp);
  n = expose(resp, len, len + 256, "batch", 2, "premium", &res, &out);
  CHECK(res == SP_CLASS_H1_SKIPPED && n == len, "a head that is not whole in the read is left");
  free(out);
}

/* ---- a backend's response head: where a read stands, and the strip ---- */
typedef struct cresp {
  llhttp_t parser;
  creq_block_t blk;
} cresp_t;

static llhttp_settings_t resp_settings;

static int resp_on_begin(llhttp_t *p)     { creq_block_msg_begin(&((cresp_t *)p->data)->blk); return 0; }
static int resp_on_hdrs_done(llhttp_t *p) { creq_block_hdrs_done(&((cresp_t *)p->data)->blk); return 0; }
static int resp_on_done(llhttp_t *p)      { creq_block_msg_done(&((cresp_t *)p->data)->blk); return 0; }

static void
cresp_init(cresp_t *c)
{
  llhttp_settings_init(&resp_settings);
  resp_settings.on_message_begin = resp_on_begin;
  resp_settings.on_headers_complete = resp_on_hdrs_done;
  resp_settings.on_message_complete = resp_on_done;
  llhttp_init(&c->parser, HTTP_RESPONSE, &resp_settings);
  c->parser.data = c;
  creq_block_reset(&c->blk);
}

/* One backend read as the gateway handles it: framed, then stripped of
 * X-Api-Key when the framer marked it. `fixed` = the gateway's rule;
 * 0 = the rule it had (any read that holds a blank line). Returns a heap
 * copy of what goes to the client. */
static char *
cresp_read(cresp_t *c, const char *bytes, int fixed, int *marked)
{
  size_t len = strlen(bytes), cur = len;
  uint8_t *buf = malloc(len ? len : 1);
  enum llhttp_errno e;
  char *out;

  memcpy(buf, bytes, len);
  creq_block_read_begin(&c->blk);
  e = llhttp_execute(&c->parser, (const char *)buf, len);
  creq_block_read_end(&c->blk, e == HPE_OK || e == HPE_PAUSED);
  if (marked) *marked = c->blk.hdr_block;
  if (fixed ? c->blk.hdr_block : (len >= 4 && memmem(buf, len, "\r\n\r\n", 4) != NULL)) {
    if (!l7h1_strip_header(buf, &cur, "X-Api-Key"))
      cur = len;
  }
  out = malloc(cur + 1);
  memcpy(out, buf, cur);
  out[cur] = '\0';
  free(buf);
  return out;
}

static void
test_response_strip(void)
{
  cresp_t c;
  char *out;
  int marked;
  const char *head, *body, *rest;

  printf("== a backend's X-Api-Key in its response\n");

  head = "HTTP/1.1 200 OK\r\nX-Api-Key: sk-backend\r\nX-Auth-Tenant: t9\r\nContent-Length: 34\r\n\r\n";
  body = "line one\r\n\r\nX-Api-Key: in-the-body";
  cresp_init(&c);
  out = cresp_read(&c, head, 1, &marked);
  CHECK(marked && !strstr(out, "sk-backend"), "the header is removed from a head whole in its read");
  CHECK(strstr(out, "X-Auth-Tenant: t9\r\n") && strstr(out, "Content-Length: 34\r\n\r\n"),
        "X-Auth-* and every other line of the head stay");
  free(out);
  out = cresp_read(&c, body, 1, &marked);
  CHECK(!marked && !strcmp(out, body), "a body read holding a blank line and such a line is untouched");
  free(out);
  /* The rule the gateway had edits that same body read. */
  {
    cresp_t old;
    char *o;

    cresp_init(&old);
    o = cresp_read(&old, head, 0, NULL);
    free(o);
    o = cresp_read(&old, "a: b\r\nX-Api-Key: in-the-body\r\n\r\nrest of the 34 bytes.", 0, NULL);
    CHECK(!strstr(o, "in-the-body"), "red twin: the blank-line rule removes a body line");
    free(o);
    cresp_init(&old);
    o = cresp_read(&old, head, 1, NULL);
    free(o);
    o = cresp_read(&old, "a: b\r\nX-Api-Key: in-the-body\r\n\r\nrest of the 34 bytes.", 1, &marked);
    CHECK(!marked && strstr(o, "in-the-body"), "the framed rule leaves that body line");
    free(o);
  }

  /* The next response on the kept connection is a head again. */
  cresp_init(&c);
  out = cresp_read(&c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", 1, &marked);
  CHECK(marked, "a whole response in one read is marked");
  free(out);
  out = cresp_read(&c, "HTTP/1.1 200 OK\r\nx-api-key: second\r\nContent-Length: 2\r\n\r\nok", 1, &marked);
  CHECK(marked && !strstr(out, "second"), "the next response's head is stripped too, in any case of the name");
  free(out);

  /* A streamed answer: only its head. */
  cresp_init(&c);
  out = cresp_read(&c, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nX-Api-Key: k\r\n"
                       "Transfer-Encoding: chunked\r\n\r\n", 1, &marked);
  CHECK(marked && !strstr(out, "X-Api-Key"), "a streamed answer's head is stripped");
  free(out);
  rest = "1c\r\ndata: X-Api-Key: v\r\n\r\nmore\r\n\r\n";
  out = cresp_read(&c, rest, 1, &marked);
  CHECK(!marked && !strcmp(out, rest), "its events are untouched, blank lines and all");
  free(out);

  /* A head split across two reads is left as it is. */
  cresp_init(&c);
  out = cresp_read(&c, "HTTP/1.1 200 OK\r\nX-Api-Key: split\r\n", 1, &marked);
  CHECK(!marked && strstr(out, "split"), "the first part of a split head is not marked");
  free(out);
  out = cresp_read(&c, "Content-Length: 0\r\n\r\n", 1, &marked);
  CHECK(!marked, "nor is the part that ends it");
  free(out);
  out = cresp_read(&c, "HTTP/1.1 204 No Content\r\nX-Api-Key: after\r\n\r\n", 1, &marked);
  CHECK(marked && !strstr(out, "after"), "the response after it is framed again");
  free(out);
}

int
main(void)
{
  test_capture();
  test_expose();
  test_requested();
  test_response_strip();
  printf("\n%d checks, %d failed\n", checks, failures);
  return failures ? 1 : 0;
}
