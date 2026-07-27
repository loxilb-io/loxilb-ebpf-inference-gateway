/* test_resp_framing.c - (REQ-REG / contract §5): adversarial
 * HTTP-response message-framing regression units for the M1 response-leg parser.
 *
 * These lock the property the three hand-rolled memmem detectors (the SSE/chunked
 * scanners replaced in M1, 90-04) NEVER had: an HTTP_RESPONSE llhttp parser fed
 * adversarially-fragmented responses fires EXACTLY ONE on_message_complete per
 * message — no double-fire, no miss — regardless of where the TCP read boundaries
 * land. This is the falsifiable proof the new parser path is fragmentation-immune,
 * the regression lock M1's cutover (90-04) and the deletion (90-06) must keep
 * GREEN.
 *
 * Case 5 is the LOAD-BEARING proof for Pitfall #3: a keep-alive socket that goes
 * SILENT mid-body (no Content-Length satisfied, no last-chunk, no close) does NOT
 * complete — llhttp will not frame it — so the graceful-[DONE] reaper
 * (b327c044) is STILL required. The assertion is completions == 0.
 *
 * The units drive the REAL llhttp parser (the same one the production response leg
 * uses) — they do NOT re-implement chunked/CL decode. We assert llhttp's own
 * callbacks. HTTP_RESPONSE (NOT HTTP_BOTH) is used so 1xx/204/304 framing rules
 * apply (RESEARCH anti-pattern).
 *
 * Build: gcc -Wall -Wextra -fsanitize=address -o test_resp_framing \
 *        test_resp_framing.c llhttp.c httpapi.c http.c -I.
 *
 * Idiom mirrors test_pd_complete.c: assert(cond && "msg") per case, per-case
 * static functions, main() runs all cases + prints "ALL PASS (test_resp_framing)"
 * + returns 0 on success / assert-aborts on failure. -fsanitize=address catches
 * any over-read llhttp or the harness introduces.
 */
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "llhttp.h"

/* Per-test counters carried through settings.uarg (and mirrored on parser->data
 * by llhttp_init, which copies settings->uarg into parser->data). */
struct fctx {
  int headers_complete;
  int body_bytes;
  int message_complete;
};

static int
cb_headers_complete(llhttp_t *p)
{
  struct fctx *c = (struct fctx *)p->data;
  c->headers_complete++;
  return 0;
}

static int
cb_body(llhttp_t *p, const char *at, size_t length)
{
  struct fctx *c = (struct fctx *)p->data;
  (void)at;
  c->body_bytes += (int)length;
  return 0;
}

static int
cb_message_complete(llhttp_t *p)
{
  struct fctx *c = (struct fctx *)p->data;
  c->message_complete++;
  return 0;
}

/* Initialise a fresh HTTP_RESPONSE parser wired to fctx. */
static void
parser_init(llhttp_t *p, llhttp_settings_t *s, struct fctx *c)
{
  memset(c, 0, sizeof(*c));
  llhttp_settings_init(s);
  s->on_headers_complete = cb_headers_complete;
  s->on_body = cb_body;
  s->on_message_complete = cb_message_complete;
  s->uarg = c;
  llhttp_init(p, HTTP_RESPONSE, s);
  p->data = c; /* llhttp_init copies settings->uarg into parser->data, but pin it
                * explicitly so the callbacks above can rely on p->data. */
}

/* Feed one fragment; assert llhttp accepted it (HPE_OK) unless told otherwise. */
static llhttp_errno_t
feed(llhttp_t *p, const char *seg, size_t len)
{
  return llhttp_execute(p, seg, len);
}

/* ---- Case 1: response header block split at EVERY byte boundary ----
 * For every split point i in 1..len-1, feed the header block as two
 * llhttp_execute calls (bytes [0,i) then [i,len)). Headers must parse identically
 * regardless of where the read boundary falls: exactly one on_headers_complete,
 * exactly one on_message_complete (the response is a complete CL:0 message). */
static void
test_header_split_every_byte(void)
{
  const char *resp =
      "HTTP/1.1 200 OK\r\n"
      "Server: loxilb\r\n"
      "Content-Length: 0\r\n"
      "\r\n";
  size_t len = strlen(resp);

  for (size_t i = 1; i < len; i++) {
    llhttp_t p;
    llhttp_settings_t s;
    struct fctx c;
    parser_init(&p, &s, &c);

    assert(feed(&p, resp, i) == HPE_OK &&
           "first fragment of header block must parse cleanly");
    assert(feed(&p, resp + i, len - i) == HPE_OK &&
           "second fragment of header block must parse cleanly");

    assert(c.headers_complete == 1 &&
           "exactly one on_headers_complete regardless of split point");
    assert(c.message_complete == 1 &&
           "exactly one on_message_complete for the CL:0 response");
  }
  printf("  [PASS] header block split at every byte -> 1 headers + 1 complete\n");
}

/* ---- Case 2: chunked size-line split mid "1a\r\n" ----
 * Split the response inside the chunk-size line so the size token straddles two
 * reads. The full 26-byte ("1a") chunk body must still be delivered to on_body
 * and exactly one on_message_complete must fire. */
static void
test_chunked_size_line_split(void)
{
  /* 0x1a = 26 bytes of body. */
  const char *head =
      "HTTP/1.1 200 OK\r\n"
      "Transfer-Encoding: chunked\r\n"
      "\r\n";
  /* chunk-size line "1a\r\n" deliberately split as "1" | "a\r\n" */
  const char *size_a = "1";
  const char *size_b = "a\r\n";
  const char *chunk_body = "abcdefghijklmnopqrstuvwxyz\r\n"; /* 26 bytes + CRLF */
  const char *last_chunk = "0\r\n\r\n";

  llhttp_t p;
  llhttp_settings_t s;
  struct fctx c;
  parser_init(&p, &s, &c);

  assert(feed(&p, head, strlen(head)) == HPE_OK && "headers parse");
  assert(feed(&p, size_a, strlen(size_a)) == HPE_OK &&
         "first half of chunk-size line parses (no completion yet)");
  assert(c.message_complete == 0 && "no completion mid chunk-size line");
  assert(feed(&p, size_b, strlen(size_b)) == HPE_OK &&
         "second half of chunk-size line parses");
  assert(feed(&p, chunk_body, strlen(chunk_body)) == HPE_OK && "chunk body parses");
  assert(feed(&p, last_chunk, strlen(last_chunk)) == HPE_OK && "last-chunk parses");

  assert(c.body_bytes == 26 &&
         "full 26-byte chunk body delivered despite the split size line");
  assert(c.message_complete == 1 &&
         "exactly one on_message_complete after the split-size chunked body");
  printf("  [PASS] chunked size-line split mid-token -> full body + 1 complete\n");
}

/* ---- Case 3: trailer-only final read ("0\r\n\r\n") ----
 * The last llhttp_execute carries ONLY the terminating last-chunk + trailers,
 * separate from the chunk body read. Exactly one on_message_complete. */
static void
test_trailer_only_final_read(void)
{
  const char *head =
      "HTTP/1.1 200 OK\r\n"
      "Transfer-Encoding: chunked\r\n"
      "\r\n";
  const char *chunk = "5\r\nhello\r\n";      /* one 5-byte chunk */
  const char *terminator = "0\r\n\r\n";       /* last-chunk in its OWN read */

  llhttp_t p;
  llhttp_settings_t s;
  struct fctx c;
  parser_init(&p, &s, &c);

  assert(feed(&p, head, strlen(head)) == HPE_OK && "headers parse");
  assert(feed(&p, chunk, strlen(chunk)) == HPE_OK && "chunk body parses");
  assert(c.message_complete == 0 &&
         "no completion before the last-chunk terminator arrives");
  assert(feed(&p, terminator, strlen(terminator)) == HPE_OK &&
         "trailer-only final read parses");

  assert(c.body_bytes == 5 && "5-byte chunk body delivered");
  assert(c.message_complete == 1 &&
         "exactly one on_message_complete on the trailer-only final read");
  printf("  [PASS] trailer-only final read (0\\r\\n\\r\\n) -> 1 complete\n");
}

/* ---- Case 4: Content-Length satisfied vs over-read ----
 * Deliver the body in 1-byte llhttp_execute calls up to Content-Length. The
 * completion must fire EXACTLY at CL — not before, not twice. Then a trailing
 * PIPELINED response is delivered: it must begin a NEW message and must NOT
 * double-complete the first one. */
static void
test_cl_satisfied_no_double_complete(void)
{
  const char *head =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 5\r\n"
      "\r\n";
  const char *body = "hello"; /* exactly CL=5 */

  llhttp_t p;
  llhttp_settings_t s;
  struct fctx c;
  parser_init(&p, &s, &c);

  assert(feed(&p, head, strlen(head)) == HPE_OK && "headers parse");

  /* feed body one byte at a time; completion must fire exactly on the 5th byte */
  for (size_t i = 0; i < 5; i++) {
    assert(feed(&p, body + i, 1) == HPE_OK && "1-byte body fragment parses");
    if (i < 4)
      assert(c.message_complete == 0 &&
             "must NOT complete before Content-Length is satisfied");
  }
  assert(c.message_complete == 1 &&
         "exactly one on_message_complete the instant Content-Length is met");
  assert(c.body_bytes == 5 && "all 5 body bytes delivered, none over-read");

  /* A trailing pipelined response: it must start a SECOND message, never
   * re-complete the first. After it fully arrives, completions == 2 (the second
   * message completed once) — proving no double-fire on the first. */
  const char *pipelined =
      "HTTP/1.1 204 No Content\r\n"
      "\r\n";
  assert(feed(&p, pipelined, strlen(pipelined)) == HPE_OK &&
         "pipelined 204 response parses on the same parser");
  assert(c.message_complete == 2 &&
         "pipelined response completes exactly once more (no double-complete of "
         "the first message)");
  printf("  [PASS] CL satisfied -> 1 complete at CL; pipelined -> +1, no double\n");
}

/* ---- Case 5 (THE reaper proof, Pitfall #3): no-terminator keep-alive silence ----
 * A keep-alive response whose body is SHORT of Content-Length, with no close and
 * no last-chunk: llhttp will NOT frame it. on_message_complete MUST NOT fire.
 * This is the load-bearing proof that the framing parser ALONE cannot detect a
 * silent stalled stream — so the graceful-[DONE] decode-idle reaper
 * (b327c044) is STILL required. The assertion is completions == 0.
 *
 * llhttp_finish() is deliberately NOT called: on a keep-alive socket the proxy
 * never sees EOF, so the parser is left mid-body exactly as the real stalled-leg
 * case leaves it. */
static void
test_no_terminator_keepalive_silence(void)
{
  const char *head =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 100\r\n" /* promises 100 bytes ... */
      "\r\n";
  const char *partial_body = "only-ten!!"; /* ... but only 10 ever arrive */

  llhttp_t p;
  llhttp_settings_t s;
  struct fctx c;
  parser_init(&p, &s, &c);

  assert(feed(&p, head, strlen(head)) == HPE_OK && "headers parse");
  assert(c.headers_complete == 1 && "headers completed (CL announced)");
  assert(feed(&p, partial_body, strlen(partial_body)) == HPE_OK &&
         "partial body bytes parse (still waiting for the rest)");

  /* The socket then goes silent forever — no more reads, no EOF, no close. */
  assert(c.message_complete == 0 &&
         "no-terminator keep-alive silence MUST NOT complete -- the framing "
         "parser cannot frame a silent stalled stream; the graceful-[DONE] "
         "reaper is STILL required (Pitfall #3)");
  printf("  [PASS] no-terminator keep-alive silence -> 0 completions "
         "(reaper still required)\n");
}

int
main(void)
{
  printf("test_resp_framing: adversarial HTTP-response framing "
         "(HTTP_RESPONSE llhttp)\n");
  test_header_split_every_byte();
  test_chunked_size_line_split();
  test_trailer_only_final_read();
  test_cl_satisfied_no_double_complete();
  test_no_terminator_keepalive_silence();
  printf("ALL PASS (test_resp_framing)\n");
  return 0;
}
