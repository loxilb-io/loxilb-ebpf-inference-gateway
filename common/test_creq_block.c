/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_creq_block.c - a request's header block is edited once, and a body
 * read is never edited.
 *
 * The relay path used to treat any client read that held a blank line as a
 * header block: it stripped "header" lines from it and spliced the forwarded
 * identity in. A body may hold a blank line (JSON written with CRLF line
 * ends, the last chunk of a chunked body, any text), so body bytes were
 * removed and a header line was written into them. The relay path now asks
 * the request framer where the read stands (sockproxy_creq_block.h), strips
 * only a read that opens a request, and injects nothing.
 *
 * This unit drives the real llhttp request framer over reads cut the way a
 * socket cuts them, and applies the same header edits the gateway applies
 * (sockproxy_h1_hdr.h), each read in a heap buffer of its exact size so the
 * address sanitizer sees any step outside it.
 *
 * THE ORACLE IS SELF-VERIFYING. A body case counts only when the shipped
 * rule leaves the read byte for byte AND `prefix_relay` below -- the pre-fix
 * rule kept verbatim -- changes it.
 *
 * Build: `make test_creq` (this file with -Wall -Wextra -Werror, the
 * vendored framer without; address and undefined-behaviour sanitizers on).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "llhttp.h"
#include "sockproxy_creq_block.h"

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

/* ---- one client connection: the framer and the per-read answer ---- */
typedef struct conn {
  llhttp_t parser;
  creq_block_t blk;
} conn_t;

static llhttp_settings_t settings;

static int on_begin(llhttp_t *p)     { creq_block_msg_begin(&((conn_t *)p->data)->blk); return 0; }
static int on_hdrs_done(llhttp_t *p) { creq_block_hdrs_done(&((conn_t *)p->data)->blk); return 0; }
static int on_done(llhttp_t *p)      { creq_block_msg_done(&((conn_t *)p->data)->blk); return 0; }

static void
conn_init(conn_t *c)
{
  llhttp_settings_init(&settings);
  settings.on_message_begin = on_begin;
  settings.on_headers_complete = on_hdrs_done;
  settings.on_message_complete = on_done;
  llhttp_init(&c->parser, HTTP_REQUEST, &settings);
  c->parser.data = c;
  creq_block_reset(&c->blk);
}

/* The gateway's creq_feed, step for step. */
static void
feed(conn_t *c, const char *rd, size_t len)
{
  enum llhttp_errno e;

  creq_block_read_begin(&c->blk);
  if (llhttp_get_errno(&c->parser) == HPE_PAUSED_UPGRADE) {
    creq_block_read_end(&c->blk, 0);
    return;
  }
  e = llhttp_execute(&c->parser, rd, len);
  if (e == HPE_PAUSED_UPGRADE) {
    creq_block_read_end(&c->blk, 1);
    return;
  }
  if (e != HPE_OK && e != HPE_PAUSED) {
    llhttp_init(&c->parser, HTTP_REQUEST, &settings);
    c->parser.data = c;
    creq_block_read_end(&c->blk, 0);
    return;
  }
  creq_block_read_end(&c->blk, 1);
}

/* sp_h1_switched's part on the request framer, asked before each client
 * read: the framer holds an upgrade request, and the backend answered it
 * with a 101 (switched, from now on) or with something else (resumed). */
static int
next_read(conn_t *c, int answered_101)
{
  if (llhttp_get_errno(&c->parser) != HPE_PAUSED_UPGRADE)
    return 0;
  if (!answered_101)
    llhttp_resume_after_upgrade(&c->parser);
  return answered_101;
}

/* A read in a heap buffer with `room` spare bytes behind it. */
static uint8_t *
heap_read(const char *rd, size_t len, size_t room)
{
  uint8_t *b = malloc(len + room);
  if (!b) { perror("malloc"); exit(2); }
  memcpy(b, rd, len);
  return b;
}

/* The shipped relay rule: strip only, and only a read that opens a request. */
static uint8_t *
shipped_relay(conn_t *c, const char *rd, size_t *len)
{
  uint8_t *b;

  feed(c, rd, *len);
  b = heap_read(rd, *len, 0);
  if (c->blk.hdr_block) {
    size_t cur = *len;
    if (l7h1_strip_header(b, &cur, "X-Api-Key") &&
        l7h1_strip_header_prefix(b, &cur, "X-Auth-"))
      *len = cur;
  }
  return b;
}

/* The PRE-FIX relay rule, verbatim in what it decides: a blank line anywhere
 * makes the read a header block; strip, then splice the identity unless the
 * read itself names a chunked body. */
#define PREFIX_ROOM 64
static uint8_t *
prefix_relay(const char *rd, size_t *len)
{
  uint8_t *b = heap_read(rd, *len, PREFIX_ROOM);
  size_t cur = *len;

  if (*len < 4 || !memmem(b, *len, "\r\n\r\n", 4))
    return b;
  if (!l7h1_strip_header(b, &cur, "X-Api-Key") ||
      !l7h1_strip_header_prefix(b, &cur, "X-Auth-"))
    return b;
  if (!memmem(b, cur < 2048 ? cur : 2048, "Transfer-Encoding: chunked", 26))
    (void)l7h1_splice_header(b, &cur, *len + PREFIX_ROOM, "X-Auth-Tenant", "t-1");
  *len = cur;
  return b;
}

static int
same(const uint8_t *a, size_t alen, const char *b, size_t blen)
{
  return alen == blen && memcmp(a, b, blen) == 0;
}

#define HEAD_CL(n) \
  "POST /v1/chat/completions HTTP/1.1\r\nHost: a\r\nX-Auth-Tenant: spoof\r\n" \
  "X-Api-Key: sk-client\r\nX-Authority: keep\r\nContent-Length: " n "\r\n\r\n"
#define HEAD_CL_CLEAN(n) \
  "POST /v1/chat/completions HTTP/1.1\r\nHost: a\r\nX-Authority: keep\r\nContent-Length: " n "\r\n\r\n"
/* 62 bytes: a blank CRLF line, and lines that look like the stripped headers */
#define BODY "line one\r\nX-Auth-Canary: 1\r\nX-Api-Key: in-body\r\n\r\nafter blank\r\n"
#define BODY_LEN "62"

/* a body-only read: the shipped rule must leave it, the pre-fix rule must not */
static void
body_read_case(const char *name, const char *before, const char *rd)
{
  conn_t c;
  size_t len = strlen(rd), plen = strlen(rd);
  uint8_t *got, *old;

  conn_init(&c);
  if (before)
    feed(&c, before, strlen(before));
  got = shipped_relay(&c, rd, &len);
  old = prefix_relay(rd, &plen);
  CHECK(c.blk.hdr_block == 0, "%s: the read is not a header block", name);
  CHECK(same(got, len, rd, strlen(rd)), "%s: relayed byte for byte", name);
  CHECK(!same(old, plen, rd, strlen(rd)), "%s: the pre-fix rule changed it (the case proves something)", name);
  free(got);
  free(old);
}

static void
test_header_helpers(void)
{
  char req[] = HEAD_CL(BODY_LEN) BODY;
  size_t len = strlen(req), room = 64;
  uint8_t *b = heap_read(req, len, room);

  printf("header edits stay inside the header block\n");
  CHECK(l7h1_strip_header(b, &len, "x-api-key") != NULL, "strip by name, any letter case");
  CHECK(!memmem(b, len, "sk-client", 9), "the header line is gone");
  CHECK(memmem(b, len, "X-Api-Key: in-body", 18) != NULL, "the body line of the same name stays");
  CHECK(l7h1_strip_header_prefix(b, &len, "X-Auth-") != NULL, "strip a family");
  CHECK(!memmem(b, len, "spoof", 5), "the family's header line is gone");
  CHECK(memmem(b, len, "X-Authority: keep", 17) != NULL, "a name that only starts like the family stays");
  CHECK(memmem(b, len, "X-Auth-Canary: 1", 16) != NULL, "the body line of the family stays");
  CHECK(len == strlen(HEAD_CL_CLEAN(BODY_LEN) BODY) &&
        memcmp(b, HEAD_CL_CLEAN(BODY_LEN) BODY, len) == 0, "what is left is the request without the two lines");
  CHECK(l7h1_splice_header(b, &len, len + room, "X-Auth-Tenant", "t-1") == 0, "splice with room");
  {
    const uint8_t *h = memmem(b, len, "X-Auth-Tenant: t-1\r\n\r\n", 22);
    const uint8_t *body = memmem(b, len, BODY, strlen(BODY));
    CHECK(h && body && h + 22 == body, "the line is the last of the header block, the body follows whole");
  }
  CHECK(l7h1_splice_header(b, &len, len, "X-Auth-User", "u") == -1, "splice with no room is refused");
  CHECK(l7h1_splice_header(b, &len, len + room, "X-Auth-User", "u\r\nX-Evil: 1") == -1, "a value with a line break is refused");
  free(b);
  {
    char nob[] = "no blank line here\r\nX-Api-Key: x\r\n";
    size_t n = strlen(nob);
    uint8_t *q = heap_read(nob, n, 0);
    CHECK(l7h1_strip_header(q, &n, "X-Api-Key") == NULL && n == strlen(nob), "no header terminator: nothing is touched");
    free(q);
  }
}

static void
test_request_start(void)
{
  conn_t c;
  size_t len;
  uint8_t *got;

  printf("a read that opens a request is stripped, once\n");
  conn_init(&c);
  len = strlen(HEAD_CL(BODY_LEN) BODY);
  got = shipped_relay(&c, HEAD_CL(BODY_LEN) BODY, &len);
  CHECK(c.blk.hdr_block == 1, "header block and body in one read: a header block");
  CHECK(same(got, len, HEAD_CL_CLEAN(BODY_LEN) BODY, strlen(HEAD_CL_CLEAN(BODY_LEN) BODY)),
        "its two header lines are gone and the body is whole");
  free(got);

  /* the next request of the same connection, its body in a read of its own */
  len = strlen(HEAD_CL(BODY_LEN));
  got = shipped_relay(&c, HEAD_CL(BODY_LEN), &len);
  CHECK(c.blk.hdr_block == 1, "second request, header block alone: a header block");
  CHECK(same(got, len, HEAD_CL_CLEAN(BODY_LEN), strlen(HEAD_CL_CLEAN(BODY_LEN))), "stripped");
  free(got);
  len = strlen(BODY);
  got = shipped_relay(&c, BODY, &len);
  CHECK(c.blk.hdr_block == 0, "its body: not a header block");
  CHECK(same(got, len, BODY, strlen(BODY)), "relayed byte for byte");
  free(got);

  /* two requests in one read: the first header block is the read's */
  conn_init(&c);
  feed(&c, "GET /a HTTP/1.1\r\nHost: a\r\n\r\nGET /b HTTP/1.1\r\nHost: a\r\n\r\n", 54);
  CHECK(c.blk.hdr_block == 1, "two requests in one read: the read opens a request");
  /* a read that begins in a body and ends in the next request's header block */
  conn_init(&c);
  feed(&c, HEAD_CL("4") "ab", strlen(HEAD_CL("4") "ab"));
  feed(&c, "cdGET /b HTTP/1.1\r\nHost: a\r\n\r\n", 30);
  CHECK(c.blk.hdr_block == 0, "a read that begins inside a body is never a header block, whatever follows");
}

static void
test_body_reads(void)
{
  printf("a body read is relayed byte for byte\n");
  body_read_case("Content-Length body with a blank line", HEAD_CL(BODY_LEN), BODY);
  body_read_case("the rest of a body", HEAD_CL(BODY_LEN) "line one\r\n", "X-Auth-Canary: 1\r\nX-Api-Key: in-body\r\n\r\nafter blank\r\n");
  body_read_case("the last chunk of a chunked body",
                 "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n", "0\r\n\r\n");
  body_read_case("chunk data with a blank line",
                 "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n", "3e\r\n" BODY "\r\n");
  body_read_case("the rest of a header block cut in two",
                 "POST / HTTP/1.1\r\nHost: a\r\n", "X-Auth-Tenant: spoof\r\nContent-Length: 0\r\n\r\n");
  body_read_case("bytes that are no request", NULL, "not a request\r\nX-Auth-Canary: 1\r\n\r\ntail\r\n");
}

static void
test_recovers_after_garbage(void)
{
  conn_t c;

  printf("the framer starts over after bytes it refused\n");
  conn_init(&c);
  feed(&c, "not a request\r\n\r\n", 17);
  CHECK(c.blk.hdr_block == 0 && c.blk.open == 0, "refused bytes: no header block, nothing open");
  feed(&c, "GET / HTTP/1.1\r\nHost: a\r\n\r\n", 27);
  CHECK(c.blk.hdr_block == 1, "the next read, a request: a header block");
}

/* every way a socket can cut one request in two, and one byte at a time */
static void
test_every_cut(void)
{
  const char *req = HEAD_CL(BODY_LEN) BODY;
  const char *body = BODY;
  size_t n = strlen(req), head = n - strlen(body), k, bad_body = 0, bad_count = 0, i;

  printf("every cut of a request\n");
  for (k = 1; k < n; k++) {
    conn_t c;
    size_t l1 = k, l2 = n - k, flagged = 0;
    uint8_t *a, *b, *all;

    conn_init(&c);
    a = shipped_relay(&c, req, &l1);
    flagged += c.blk.hdr_block;
    b = shipped_relay(&c, req + k, &l2);
    flagged += c.blk.hdr_block;
    all = malloc(l1 + l2);
    memcpy(all, a, l1);
    memcpy(all + l1, b, l2);
    /* the body is the last strlen(body) bytes, whatever the header lost */
    if (l1 + l2 < strlen(body) || memcmp(all + l1 + l2 - strlen(body), body, strlen(body)) != 0)
      bad_body++;
    if (flagged > 1 || (flagged == 1 && k < head))
      bad_count++;
    if (k >= head && !same(a, l1, HEAD_CL_CLEAN(BODY_LEN) BODY, l1))
      bad_count++;                 /* header block whole in the first read: it must be the stripped one */
    free(a); free(b); free(all);
  }
  CHECK(bad_body == 0, "%zu cuts: the body reaches the backend whole in every one", n - 1);
  CHECK(bad_count == 0, "at most one read is a header block, and only one that holds the whole block");
  {
    conn_t c;
    size_t flagged = 0;
    conn_init(&c);
    for (i = 0; i < n; i++) {
      feed(&c, req + i, 1);
      flagged += c.blk.hdr_block;
    }
    CHECK(flagged == 0 && c.blk.open == 0, "one byte a read: no read is a header block, and the request ends");
  }
}

#define WSREQ "GET /ws HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
#define KEYREQ "GET /next HTTP/1.1\r\nHost: a\r\nX-Api-Key: sk-client\r\n\r\n"

static void
feed_str(conn_t *c, const char *rd)
{
  feed(c, rd, strlen(rd));
}

static void
test_upgrade(void)
{
  conn_t c;

  printf("an upgrade request, then the other protocol or HTTP again:\n");
  conn_init(&c);
  CHECK(!next_read(&c, 0), "a fresh connection has not switched");
  feed_str(&c, WSREQ);
  CHECK(c.blk.hdr_block == 1, "the upgrade request's read is a header block");
  CHECK(next_read(&c, 1), "answered with a 101: the connection has switched");
  feed_str(&c, KEYREQ);
  CHECK(c.blk.hdr_block == 0,
        "a read after the 101 is not a header block, though it reads like a request");
  CHECK(next_read(&c, 1), "and the connection stays switched");

  conn_init(&c);
  feed_str(&c, WSREQ);
  CHECK(!next_read(&c, 0), "answered otherwise: the connection has not switched");
  feed_str(&c, KEYREQ);
  CHECK(c.blk.hdr_block == 1,
        "the next request is a header block again, so its strips still run");

  conn_init(&c);
  feed_str(&c, "GET / HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\n\r\n");
  CHECK(llhttp_get_errno(&c.parser) == HPE_OK,
        "Connection: Upgrade without an Upgrade header: an ordinary request");
  conn_init(&c);
  feed_str(&c, "GET / HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\n"
               "Connection: keep-alive, upgrade\r\n\r\n");
  CHECK(llhttp_get_errno(&c.parser) == HPE_PAUSED_UPGRADE,
        "upgrade among the Connection tokens, in any case: an upgrade request");
  conn_init(&c);
  feed_str(&c, "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 19\r\n\r\n"
               "Connection: Upgrade");
  CHECK(llhttp_get_errno(&c.parser) == HPE_OK,
        "a body that says Connection: Upgrade: no upgrade");
}

int
main(void)
{
  test_header_helpers();
  test_request_start();
  test_body_reads();
  test_recovers_after_garbage();
  test_every_cut();
  test_upgrade();
  printf("%d checks, %d failed\n", checks, failures);
  return failures ? 1 : 0;
}
