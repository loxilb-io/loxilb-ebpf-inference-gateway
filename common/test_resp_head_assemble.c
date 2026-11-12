/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-Clause) */
/*
 * test_resp_head_assemble.c - an admitted HTTP/1.1 response whose head the
 * backend sent in more than one read gets the admission headers and the
 * class headers all the same (sockproxy_resp_head.h).
 *
 *   make test_resphead
 *
 * The relay's step is called as the relay calls it: one read at a time,
 * each in a heap buffer of exactly the size the edit may use, what it says
 * to send appended to what the client has received so far. The reference
 * for every cut is the same response given in one read, which never enters
 * the buffer and is the path that existed before: a client must not be
 * able to tell from the bytes it reads where the backend's writes ended.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sockproxy_resp_head.h"

#define log_error(...) ((void)0)
#include "sockproxy_l7hdr_guard.h"
#include "sockproxy_h1_hdr.h"

/* The relay's strip of a backend's X-Loxilb-Refusal-*, as proxy_resp_head_strip
 * makes it on a head that was put together. */
static size_t
strip_refusal(uint8_t *buf, size_t len)
{
  size_t cur = len;

  if (!l7h1_strip_header_prefix(buf, &cur, "X-Loxilb-Refusal-"))
    return len;
  return cur;
}

static int failures = 0;
static int checks   = 0;

#define CHECK(cond, ...) do { \
    checks++; \
    if (!(cond)) { failures++; printf("  FAIL "); printf(__VA_ARGS__); printf("\n"); } \
  } while (0)
#define SAY(...) do { printf("  ok   "); printf(__VA_ARGS__); printf("\n"); } while (0)

/* ---- the client connection, as far as the relay's step sees it ---- */
typedef struct conn {
  sp_resp_head_t head;
  uint8_t fc_pending, class_pending;
  int fc_x;
  fc_expose_t fc_v;
  const char *objective;
  uint8_t klass;
  const char *requested;
  /* what the client has received, in order */
  uint8_t *out;
  size_t out_len, out_cap;
  /* bookkeeping the cases look at */
  int emits, emit_fail, over, over_logs, held_reads, errs;
  size_t max_held;
} conn_t;

static void
conn_arm(conn_t *c)
{
  c->fc_pending = 1;
  c->class_pending = 1;
  c->fc_x = 1;
  c->fc_v.inflight = 3;
  c->fc_v.queued = 1;
  c->fc_v.limit = 8;
  c->objective = "gold";
  c->klass = 1;
  c->requested = NULL;
}

static void
conn_init(conn_t *c)
{
  memset(c, 0, sizeof(*c));
  conn_arm(c);
}

static void
conn_free(conn_t *c)
{
  sp_resp_head_free(&c->head);
  free(c->out);
  c->out = NULL;
  c->out_len = c->out_cap = 0;
}

static void
out_add(conn_t *c, const uint8_t *b, size_t n)
{
  if (c->out_len + n > c->out_cap) {
    c->out_cap = (c->out_len + n) * 2 + 64;
    c->out = realloc(c->out, c->out_cap);
    if (!c->out) abort();
  }
  if (n) memcpy(c->out + c->out_len, b, n);
  c->out_len += n;
}

static int
emit(void *ctx, const uint8_t *b, size_t n)
{
  conn_t *c = ctx;

  if (c->emit_fail)
    return -1;
  c->emits++;
  out_add(c, b, n);
  return 0;
}

/* One read from the backend, as proxy_try_epxmit treats it at its seam. */
static enum sp_resp_head_res
feed(conn_t *c, const uint8_t *b, size_t n)
{
  size_t cap = n + SP_RESP_HEAD_ROOM, len = n, off = 0;
  uint8_t *msg = malloc(cap ? cap : 1);
  enum sp_resp_head_res r = SP_RESP_HEAD_NOT_HEAD;
  sp_resp_expose_t x = {
    .fc_pending = &c->fc_pending, .class_pending = &c->class_pending,
    .fc_x = c->fc_x, .fc_v = &c->fc_v, .objective = c->objective,
    .priority_class = c->klass, .requested = c->requested,
    .strip = strip_refusal,
  };

  if (!msg) abort();
  if (n) memcpy(msg, b, n);
  if (c->fc_pending || c->class_pending || c->head.len > 0) {
    if (c->head.len == 0 && !c->class_pending && !c->fc_x) {
      len = sp_resp_expose_apply(&x, msg, len, cap, NULL);
    } else {
      r = sp_resp_head_relay(&c->head, &x, msg, &len, cap, &off, emit, c, NULL);
      if (r == SP_RESP_HEAD_ERR) {
        c->errs++;
        free(msg);
        return r;
      }
      if (r == SP_RESP_HEAD_OVER) {
        c->over++;
        c->over_logs += sp_resp_head_over(&c->head);
      }
      if (r == SP_RESP_HEAD_HELD)
        c->held_reads++;
    }
  }
  if (c->head.len > c->max_held)
    c->max_held = c->head.len;
  out_add(c, msg + off, len);
  free(msg);
  return r;
}

static void
feed_str(conn_t *c, const char *s)
{
  (void)feed(c, (const uint8_t *)s, strlen(s));
}

/* The whole of `resp` in reads cut at each of the n offsets in cuts[]. */
static void
feed_cut(conn_t *c, const char *resp, size_t rlen, const size_t *cuts, int n)
{
  size_t at = 0;

  for (int i = 0; i < n; i++) {
    (void)feed(c, (const uint8_t *)resp + at, cuts[i] - at);
    at = cuts[i];
  }
  (void)feed(c, (const uint8_t *)resp + at, rlen - at);
}

static int
has(const conn_t *c, const char *needle)
{
  return memmem(c->out, c->out_len, needle, strlen(needle)) != NULL;
}

static int
count(const conn_t *c, const char *needle)
{
  int k = 0;
  size_t nl = strlen(needle);
  const uint8_t *p = c->out, *end = c->out + c->out_len;

  while (p && (size_t)(end - p) >= nl && (p = memmem(p, (size_t)(end - p), needle, nl))) {
    k++;
    p += nl;
  }
  return k;
}

static int
same(const conn_t *a, const conn_t *b)
{
  return a->out_len == b->out_len && memcmp(a->out, b->out, a->out_len) == 0;
}

static uint64_t
over_total(void)
{
  return atomic_load(&fc_anomaly_total[FC_A_EXPOSE_HEAD_OVERFLOW]);
}

#define HEAD_PLAIN \
  "HTTP/1.1 200 OK\r\n" \
  "Content-Type: application/json\r\n" \
  "Content-Length: 17\r\n" \
  "X-Backend: a\r\n" \
  "\r\n"
#define BODY_PLAIN "{\"id\":\"cmpl-1\"}\r\n"

#define HEAD_SPOOF \
  "HTTP/1.1 200 OK\r\n" \
  "X-Loxilb-Admission-Inflight: 999\r\n" \
  "Content-Type: text/event-stream\r\n" \
  "x-loxilb-admission-class: critical\r\n" \
  "X-Loxilb-Admission-Objective: stolen\r\n" \
  "X-Loxilb-Admission-Objective-Requested: forged\r\n" \
  "Transfer-Encoding: chunked\r\n" \
  "X-Loxilb-Admission-Limit: 1\r\n" \
  "\r\n"
#define BODY_SSE "6\r\ndata: \r\n0\r\n\r\n"

/* ---- every cut of a response reads like the response in one read ---- */
static void
test_every_cut(const char *name, const char *resp)
{
  size_t rlen = strlen(resp), hlen = sp_resp_head_whole((const uint8_t *)resp, rlen);
  conn_t ref;
  int bad = 0, bad2 = 0, held_ok = 1;

  conn_init(&ref);
  feed_str(&ref, resp);
  CHECK(ref.emits == 0 && ref.held_reads == 0 && ref.head.buf == NULL,
        "%s: one read never enters the buffer", name);
  CHECK(has(&ref, "X-Loxilb-Admission-Inflight: 3\r\n") &&
        has(&ref, "X-Loxilb-Admission-Class: critical\r\n") &&
        has(&ref, "X-Loxilb-Admission-Objective: gold\r\n"),
        "%s: one read carries the gateway's lines", name);

  /* one cut, at every offset */
  for (size_t cut = 1; cut < rlen; cut++) {
    conn_t c;

    conn_init(&c);
    feed_cut(&c, resp, rlen, &cut, 1);
    if (!same(&c, &ref)) {
      if (!bad) printf("  FAIL %s: cut at %zu differs from one read\n", name, cut);
      bad++;
    }
    if (c.fc_pending || c.class_pending || c.head.buf || c.head.len)
      held_ok = 0;
    if (cut < hlen && c.held_reads != 1)
      held_ok = 0;
    conn_free(&c);
  }
  checks++;
  if (bad) failures++;
  CHECK(held_ok, "%s: a cut inside the head is kept once, nothing is left kept or owed", name);

  /* two cuts, at every pair of offsets */
  for (size_t c1 = 1; c1 < rlen; c1++) {
    for (size_t c2 = c1 + 1; c2 < rlen; c2++) {
      size_t cuts[2] = { c1, c2 };
      conn_t c;

      conn_init(&c);
      feed_cut(&c, resp, rlen, cuts, 2);
      if (!same(&c, &ref)) {
        if (!bad2) printf("  FAIL %s: cuts at %zu,%zu differ from one read\n", name, c1, c2);
        bad2++;
      }
      conn_free(&c);
    }
  }
  checks++;
  if (bad2) failures++;

  /* one byte a read */
  {
    conn_t c;

    conn_init(&c);
    for (size_t i = 0; i < rlen; i++)
      (void)feed(&c, (const uint8_t *)resp + i, 1);
    CHECK(same(&c, &ref), "%s: one byte a read reads like one read", name);
    CHECK(c.emits == 1, "%s: one byte a read: the head left once (%d)", name, c.emits);
    CHECK(c.max_held <= hlen && c.head.buf == NULL,
          "%s: one byte a read: never more kept than the head (%zu <= %zu), freed after",
          name, c.max_held, hlen);
    conn_free(&c);
  }
  if (!bad && !bad2)
    SAY("%s: %zu single cuts and %zu pairs read like one read", name, rlen - 1,
        (rlen - 1) * (rlen - 2) / 2);
  conn_free(&ref);
}

/* ---- the cuts the package names, each on its own ---- */
static void
test_named_cuts(void)
{
  static const char resp[] = HEAD_PLAIN BODY_PLAIN;
  size_t rlen = sizeof(resp) - 1;
  size_t hlen = sizeof(HEAD_PLAIN) - 1;
  const char *p;
  struct { const char *what; size_t at; } cuts[6];
  int n = 0;
  conn_t ref;

  cuts[n].what = "after the first byte"; cuts[n++].at = 1;
  p = strstr(resp, "\r\nContent-Type");
  cuts[n].what = "between CR and LF of the status line"; cuts[n++].at = (size_t)(p - resp) + 1;
  p = strstr(resp, "Content-Length");
  cuts[n].what = "inside a header name"; cuts[n++].at = (size_t)(p - resp) + 7;
  cuts[n].what = "inside the blank line (CRLF CR | LF)"; cuts[n++].at = hlen - 1;
  cuts[n].what = "between the last header and the blank line"; cuts[n++].at = hlen - 2;
  cuts[n].what = "inside the status code"; cuts[n++].at = 10;

  conn_init(&ref);
  feed_str(&ref, resp);
  for (int i = 0; i < n; i++) {
    conn_t c;

    conn_init(&c);
    (void)feed(&c, (const uint8_t *)resp, cuts[i].at);
    CHECK(c.out_len == 0 && c.head.len == cuts[i].at && c.fc_pending && c.class_pending,
          "%s: nothing sent yet, %zu bytes kept, both still owed", cuts[i].what, cuts[i].at);
    (void)feed(&c, (const uint8_t *)resp + cuts[i].at, rlen - cuts[i].at);
    CHECK(same(&c, &ref), "%s: reads like one read", cuts[i].what);
    CHECK(count(&c, "X-Loxilb-Admission-Inflight: 3\r\n") == 1 &&
          count(&c, "X-Loxilb-Admission-Class: critical\r\n") == 1 &&
          c.out_len >= 17 &&
          memcmp(c.out + c.out_len - 17, BODY_PLAIN, 17) == 0,
          "%s: the lines once, the body as sent", cuts[i].what);
    CHECK(!c.fc_pending && !c.class_pending && c.head.buf == NULL,
          "%s: nothing owed, nothing kept", cuts[i].what);
    conn_free(&c);
  }
  SAY("the named cuts: first byte, inside CRLF, inside a name, inside the blank line");
  conn_free(&ref);
}

/* ---- a backend's own lines on a split head are replaced ---- */
static void
test_spoof_split(void)
{
  static const char resp[] = HEAD_SPOOF BODY_SSE;
  size_t rlen = sizeof(resp) - 1;
  int bad = 0;

  for (size_t cut = 1; cut < sizeof(HEAD_SPOOF) - 1; cut++) {
    conn_t c;

    conn_init(&c);
    c.requested = "platinum";
    feed_cut(&c, resp, rlen, &cut, 1);
    if (has(&c, "999") || has(&c, "stolen") || has(&c, "forged") ||
        has(&c, "Admission-Limit: 1\r\n") ||
        count(&c, "-Inflight: 3\r\n") != 1 || count(&c, "-Limit: 8\r\n") != 1 ||
        count(&c, "X-Loxilb-Admission-Class: critical\r\n") != 1 ||
        count(&c, "x-loxilb-admission-class") != 0 ||
        count(&c, "X-Loxilb-Admission-Objective: gold\r\n") != 1 ||
        count(&c, "X-Loxilb-Admission-Objective-Requested: platinum\r\n") != 1 ||
        !has(&c, "Content-Type: text/event-stream\r\n") ||
        !has(&c, "Transfer-Encoding: chunked\r\n") ||
        c.out_len < sizeof(BODY_SSE) - 1 ||
        memcmp(c.out + c.out_len - (sizeof(BODY_SSE) - 1), BODY_SSE, sizeof(BODY_SSE) - 1)) {
      if (!bad) printf("  FAIL spoof: cut at %zu\n", cut);
      bad++;
    }
    conn_free(&c);
  }
  CHECK(!bad, "a split head's own admission lines are replaced at every cut");
  if (!bad)
    SAY("backend lines of the admission family on a split head: replaced, the chunks as sent");
}

/* ---- a backend's X-Loxilb-Refusal-* on a split head does not pass ---- */
static void
test_refusal_split(void)
{
  static const char clean[] =
    "HTTP/1.1 429 Too Many Requests\r\n"
    "Content-Type: application/json\r\n"
    "Content-Length: 2\r\n"
    "\r\n{}";
  static const char resp[] =
    "HTTP/1.1 429 Too Many Requests\r\n"
    "X-Loxilb-Refusal-Stage: capacity\r\n"
    "Content-Type: application/json\r\n"
    "x-loxilb-refusal-dispatch: none\r\n"
    "Content-Length: 2\r\n"
    "\r\n{}";
  static const char i_resp[] =
    "HTTP/1.1 103 Early Hints\r\nX-Loxilb-Refusal-Stage: queue\r\nLink: </a>\r\n\r\n";
  size_t rlen = sizeof(resp) - 1, hlen = sp_resp_head_whole((const uint8_t *)resp, rlen);
  conn_t ref, c;
  int bad = 0;

  /* what the client reads when the backend sends no such line */
  conn_init(&ref);
  feed_str(&ref, clean);
  for (size_t cut = 1; cut < hlen; cut++) {
    conn_init(&c);
    feed_cut(&c, resp, rlen, &cut, 1);
    if (!same(&c, &ref) || has(&c, "efusal")) {
      if (!bad) printf("  FAIL refusal: cut at %zu\n", cut);
      bad++;
    }
    conn_free(&c);
  }
  CHECK(!bad, "a split head's X-Loxilb-Refusal-* lines are gone at every cut inside the head");

  /* an interim head that came split loses them too, and stays an interim head */
  conn_init(&c);
  (void)feed(&c, (const uint8_t *)i_resp, 30);
  (void)feed(&c, (const uint8_t *)i_resp + 30, sizeof(i_resp) - 1 - 30);
  CHECK(!has(&c, "efusal") && has(&c, "HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n") &&
        c.fc_pending && c.class_pending && !has(&c, "Admission"),
        "a split interim head loses them, gets no admission lines, and the final head is still owed");
  conn_free(&c);
  if (!bad)
    SAY("backend X-Loxilb-Refusal-* on a head that came split: removed when it is put together");
  conn_free(&ref);
}

/* ---- interim heads ---- */
static void
test_interim(void)
{
  static const char i100[] = "HTTP/1.1 100 Continue\r\n\r\n";
  static const char i103[] = "HTTP/1.1 103 Early Hints\r\nLink: </a>; rel=preload\r\n\r\n";
  static const char fin[] = HEAD_PLAIN BODY_PLAIN;
  char all[512];
  size_t alen;
  conn_t ref, c;
  int bad = 0;

  alen = (size_t)snprintf(all, sizeof(all), "%s%s%s", i100, i103, fin);

  /* each in a read of its own: the path that existed */
  conn_init(&ref);
  feed_str(&ref, i100);
  CHECK(ref.out_len == sizeof(i100) - 1 && ref.fc_pending && ref.class_pending &&
        ref.head.len == 0, "a whole 100 goes at once and both stay owed");
  feed_str(&ref, i103);
  feed_str(&ref, fin);
  CHECK(count(&ref, "X-Loxilb-Admission-Inflight") == 1 &&
        count(&ref, "X-Loxilb-Admission-Class") == 1 &&
        memcmp(ref.out, i100, sizeof(i100) - 1) == 0 &&
        memcmp(ref.out + sizeof(i100) - 1, i103, sizeof(i103) - 1) == 0,
        "interim heads untouched, the final head carries the lines once");

  /* all three in one read: the final head still gets them */
  conn_init(&c);
  (void)feed(&c, (const uint8_t *)all, alen);
  CHECK(same(&c, &ref), "100 + 103 + final in one read reads the same");
  conn_free(&c);

  /* every cut of the three */
  for (size_t cut = 1; cut < alen; cut++) {
    conn_init(&c);
    feed_cut(&c, all, alen, &cut, 1);
    if (!same(&c, &ref) || c.fc_pending || c.class_pending || c.head.buf) {
      if (!bad) printf("  FAIL interim: cut at %zu\n", cut);
      bad++;
    }
    conn_free(&c);
  }
  CHECK(!bad, "every cut of 100 + 103 + final reads the same");

  /* a 100 that is whole leaves before the final head is */
  conn_init(&c);
  feed_str(&c, "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Le");
  CHECK(c.out_len == sizeof(i100) - 1 && memcmp(c.out, i100, c.out_len) == 0 &&
        c.head.len == 27 && c.fc_pending,
        "a whole 100 leaves while the start of the final head is kept");
  feed_str(&c, "ngth: 0\r\n\r\n");
  CHECK(has(&c, "X-Loxilb-Admission-Inflight: 3\r\n") && c.head.buf == NULL,
        "... and the final head then carries the lines");
  conn_free(&c);

  /* a 100 that came split is kept until whole, then passed, still owed */
  conn_init(&c);
  feed_str(&c, "HTTP/1.1 100 Cont");
  CHECK(c.out_len == 0 && c.head.len == 17, "the start of a 100 is kept");
  feed_str(&c, "inue\r\n\r\n");
  CHECK(c.out_len == sizeof(i100) - 1 && memcmp(c.out, i100, c.out_len) == 0 &&
        c.fc_pending && c.class_pending && c.head.buf == NULL && c.emits == 1,
        "... passed on whole, as sent, and the final head is still owed");
  feed_str(&c, fin);
  CHECK(count(&c, "X-Loxilb-Admission-Class: critical\r\n") == 1,
        "... which then carries the lines");
  conn_free(&c);
  SAY("1xx then final: in reads of their own, in one read, at every cut");
  conn_free(&ref);
}

/* ---- two responses on one kept connection ---- */
static void
test_keepalive(void)
{
  static const char r1[] = HEAD_PLAIN BODY_PLAIN;
  static const char r2[] =
    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Backend: b\r\n\r\nok";
  conn_t ref, c;
  int bad = 0;

  conn_init(&ref);
  feed_str(&ref, r1);
  conn_arm(&ref);                 /* the next request passed the gate */
  ref.fc_v.inflight = 5;
  ref.objective = "";
  ref.klass = 2;
  feed_str(&ref, r2);
  CHECK(count(&ref, "X-Loxilb-Admission-Inflight: 3\r\n") == 1 &&
        count(&ref, "X-Loxilb-Admission-Inflight: 5\r\n") == 1 &&
        count(&ref, "X-Loxilb-Admission-Class: sheddable\r\n") == 1,
        "two responses in a read each: each head its own values");

  for (size_t c1 = 1; c1 < sizeof(r1) - 1; c1++) {
    for (size_t c2 = 1; c2 < sizeof(r2) - 1; c2 += 3) {
      conn_init(&c);
      feed_cut(&c, r1, sizeof(r1) - 1, &c1, 1);
      if (c.head.buf || c.fc_pending || c.class_pending)
        bad++;
      conn_arm(&c);
      c.fc_v.inflight = 5;
      c.objective = "";
      c.klass = 2;
      feed_cut(&c, r2, sizeof(r2) - 1, &c2, 1);
      if (!same(&c, &ref) || c.head.buf || c.fc_pending || c.class_pending) {
        if (!bad) printf("  FAIL keep-alive: cuts at %zu / %zu\n", c1, c2);
        bad++;
      }
      conn_free(&c);
    }
  }
  CHECK(!bad, "two split heads back to back: each put together on its own");
  if (!bad)
    SAY("keep-alive: nothing of the first head is kept into the second");
  conn_free(&ref);
}

/* ---- longer than the bound ---- */
static char *
big_head(size_t total, size_t *out_len)
{
  /* a head of exactly `total` bytes, blank line included */
  static const char pre[] = "HTTP/1.1 200 OK\r\nX-Pad: ";
  char *h = malloc(total + 1);
  size_t i = sizeof(pre) - 1;

  if (!h) abort();
  memcpy(h, pre, i);
  while (i < total - 4) h[i++] = 'a';
  memcpy(h + i, "\r\n\r\n", 4);
  h[total] = '\0';
  *out_len = total;
  return h;
}

static void
test_over(void)
{
  size_t hlen;
  char *h;
  conn_t c;
  uint64_t before;

  /* exactly the bound, split: put together */
  h = big_head(SP_RESP_HEAD_ASSEMBLE_MAX, &hlen);
  conn_init(&c);
  before = over_total();
  {
    size_t cut = hlen / 2;
    feed_cut(&c, h, hlen, &cut, 1);
  }
  CHECK(has(&c, "X-Loxilb-Admission-Inflight: 3\r\n") && c.over == 0 &&
        over_total() == before && c.max_held <= SP_RESP_HEAD_ASSEMBLE_MAX,
        "a split head of exactly the bound is put together (%zu kept at most)", c.max_held);
  conn_free(&c);
  /* ... one byte a read as well: the buffer is written to its last byte */
  conn_init(&c);
  for (size_t i = 0; i < hlen; i++)
    (void)feed(&c, (const uint8_t *)h + i, 1);
  CHECK(has(&c, "X-Loxilb-Admission-Class: critical\r\n") && c.over == 0,
        "... also one byte a read");
  conn_free(&c);
  free(h);

  /* one byte more, split: as it came, counted, logged once */
  h = big_head(SP_RESP_HEAD_ASSEMBLE_MAX + 1, &hlen);
  conn_init(&c);
  before = over_total();
  {
    size_t cut = 100;
    feed_cut(&c, h, hlen, &cut, 1);
  }
  CHECK(c.out_len == hlen && memcmp(c.out, h, hlen) == 0,
        "a split head one byte over the bound leaves as it came");
  CHECK(c.over == 1 && over_total() == before + 1 && c.over_logs == 1,
        "... counted once, logged once");
  CHECK(!c.fc_pending && !c.class_pending && c.head.buf == NULL,
        "... nothing owed, nothing kept");
  /* the same again on the same connection: counted, not logged */
  conn_arm(&c);
  {
    size_t cut = 5000;
    feed_cut(&c, h, hlen, &cut, 1);
  }
  CHECK(c.over == 2 && over_total() == before + 2 && c.over_logs == 1 &&
        c.out_len == 2 * hlen && memcmp(c.out + hlen, h, hlen) == 0,
        "a second one on the connection: counted again, no second log line");
  conn_free(&c);

  /* one byte over, one byte a read */
  conn_init(&c);
  before = over_total();
  for (size_t i = 0; i < hlen; i++)
    (void)feed(&c, (const uint8_t *)h + i, 1);
  CHECK(c.out_len == hlen && memcmp(c.out, h, hlen) == 0 && c.over == 1 &&
        over_total() == before + 1 && c.max_held == SP_RESP_HEAD_ASSEMBLE_MAX,
        "one byte a read: as it came, never more kept than the bound (%zu)", c.max_held);
  conn_free(&c);

  /* a first read already longer than the bound with no blank line */
  free(h);
  h = big_head(SP_RESP_HEAD_ASSEMBLE_MAX + 3, &hlen);
  conn_init(&c);
  before = over_total();
  (void)feed(&c, (const uint8_t *)h, hlen - 2);
  CHECK(c.out_len == hlen - 2 && c.head.buf == NULL && c.over == 1 &&
        over_total() == before + 1 && !c.fc_pending,
        "a first read longer than the bound without its blank line is not kept");
  (void)feed(&c, (const uint8_t *)h + hlen - 2, 2);
  CHECK(c.out_len == hlen && memcmp(c.out, h, hlen) == 0, "... and the rest follows as sent");
  conn_free(&c);
  free(h);

  /* a head longer than the bound that is whole in one read was never
   * bound by it */
  h = big_head(3 * SP_RESP_HEAD_ASSEMBLE_MAX, &hlen);
  conn_init(&c);
  before = over_total();
  (void)feed(&c, (const uint8_t *)h, hlen);
  CHECK(has(&c, "X-Loxilb-Admission-Inflight: 3\r\n") && c.over == 0 &&
        over_total() == before && c.head.buf == NULL,
        "a 48 KiB head whole in one read carries the lines as it always did");
  conn_free(&c);
  free(h);
  SAY("the bound: at it, one over, a first read over it, whole in one read");
}

/* ---- what is not a response head is not kept ---- */
static void
test_not_head(void)
{
  static const char *const bodies[] = {
    "data: {\"x\":1}\n\n", "H", "HTTP", "HTTP/2 200\r\n", "HTTP/1.1 600 X\r\n",
    "HTTP/1.1 2x0 OK\r\n", "HTTP/1.1200 OK\r\n", "\r\n\r\n", "hello",
  };
  conn_t c;

  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++) {
    const char *b = bodies[i];
    int keep = (!strcmp(b, "H") || !strcmp(b, "HTTP"));

    conn_init(&c);
    feed_str(&c, b);
    if (keep) {
      CHECK(c.out_len == 0 && c.head.len == strlen(b) && c.fc_pending,
            "\"%s\" can still become a status line: kept", b);
      /* ... and when it does not, it leaves as it came, in order */
      feed_str(&c, "ello world");
      CHECK(c.out_len == strlen(b) + 10 && memcmp(c.out, b, strlen(b)) == 0 &&
            memcmp(c.out + strlen(b), "ello world", 10) == 0 &&
            !c.fc_pending && !c.class_pending && c.head.buf == NULL,
            "\"%s\" + what is no status line: both as sent, nothing owed", b);
    } else {
      CHECK(c.out_len == strlen(b) && memcmp(c.out, b, c.out_len) == 0 &&
            c.head.buf == NULL && !c.fc_pending && !c.class_pending,
            "what cannot be a status line is sent as it came (%zu bytes)", strlen(b));
    }
    conn_free(&c);
  }

  /* nothing owed and nothing kept: the step is not called at all */
  conn_init(&c);
  c.fc_pending = c.class_pending = 0;
  feed_str(&c, "HTTP/1.1 200 OK\r\nConte");
  CHECK(c.out_len == 22 && c.head.buf == NULL, "nothing owed: a split head is not kept");
  conn_free(&c);

  /* owed but no permit to report and no class: the flag goes, nothing kept */
  conn_init(&c);
  c.class_pending = 0;
  c.fc_x = 0;
  feed_str(&c, "HTTP/1.1 200 OK\r\nConte");
  CHECK(c.out_len == 22 && c.head.buf == NULL && !c.fc_pending,
        "no values to write: a split head is not kept, the flag is cleared");
  conn_free(&c);

  /* class only (no permit to report): kept, the class lines alone */
  conn_init(&c);
  c.fc_x = 0;
  feed_str(&c, "HTTP/1.1 200 OK\r\nConte");
  feed_str(&c, "nt-Length: 0\r\n\r\n");
  CHECK(has(&c, "X-Loxilb-Admission-Class: critical\r\n") &&
        !has(&c, "X-Loxilb-Admission-Inflight") && !c.fc_pending && !c.class_pending,
        "class headers alone on a split head when no permit reports");
  conn_free(&c);
  SAY("what is no status line, and a head nothing is owed to, are not kept");
}

/* ---- the kept head cannot leave: the caller closes ---- */
static void
test_emit_fail(void)
{
  conn_t c;

  conn_init(&c);
  feed_str(&c, "HTTP/1.1 200 OK\r\nConte");
  c.emit_fail = 1;
  CHECK(feed(&c, (const uint8_t *)"nt-Length: 0\r\n\r\n", 16) == SP_RESP_HEAD_ERR &&
        c.errs == 1 && c.head.buf == NULL && c.head.len == 0,
        "a kept head that cannot be queued: the caller is told, nothing stays kept");
  conn_free(&c);
  SAY("emit failure is reported and leaves nothing allocated");
}

/* ---- a head whose values changed while it was coming in ---- */
static void
test_values_at_completion(void)
{
  conn_t c;

  conn_init(&c);
  feed_str(&c, "HTTP/1.1 200 OK\r\nConte");
  c.fc_v.inflight = 7;            /* the pool moved before the head was whole */
  c.fc_v.queued = 4;
  feed_str(&c, "nt-Length: 0\r\n\r\n");
  CHECK(has(&c, "X-Loxilb-Admission-Inflight: 7\r\n") &&
        has(&c, "X-Loxilb-Admission-Queued: 4\r\n"),
        "the values are those of the read that completed the head");
  conn_free(&c);
  SAY("values are read when the head is whole");
}

int
main(void)
{
  printf("test_resp_head_assemble\n");
  test_every_cut("plain", HEAD_PLAIN BODY_PLAIN);
  test_every_cut("spoofed event stream", HEAD_SPOOF BODY_SSE);
  test_named_cuts();
  test_spoof_split();
  test_refusal_split();
  test_interim();
  test_keepalive();
  test_over();
  test_not_head();
  test_emit_fail();
  test_values_at_completion();
  printf("%d checks, %d failed\n", checks, failures);
  return failures ? 1 : 0;
}
