#!/usr/bin/env python3
"""The correlation capture (WP-D) on the HTTP/1.1 parser callbacks, and where
HTTP/2 calls it.

Part 1, source invariants (read from the source, as test_convhdr does):
  - handle_header_val keeps a value's bytes for a correlation field, as it
    does for Content-Type (otherwise value_complete has nothing to read);
  - every per-request reset of the header state also resets the capture,
    so request N+1 on a kept connection does not inherit request N's, and
    does so AFTER request N's last readers in the same function (its owed
    completion and its release settle), so request N's records keep N's
    values (tightened in step B: step A accepted a reset anywhere near the
    header-state reset, which is before those readers);
  - the HTTP/2 request-header callback hands every field to the capture,
    exactly once, beside the x-conversation-id read.
Part 2, behaviour: the production span callbacks (sp_h1_header_span ..
sp_h1_header_value_complete) are cut from sockproxy_http.c and driven by the
bundled llhttp at every two-piece split of the request and bytewise, so a
value split across reads is captured whole.

The capture's contract is the one test_corr_capture.c states.
"""
from pathlib import Path
import os
import re
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parent
source = (root / "sockproxy_http.c").read_text()
h2 = (root / "sockproxy_h2.c").read_text()
header = (root / "sockproxy.h").read_text()

failed = 0


def check(ok, what):
    global failed
    print(("PASS: " if ok else "FAIL: ") + what)
    if not ok:
        failed += 1


def body_of(text, signature):
    """The body of the C function whose definition starts with signature."""
    start = text.find(signature)
    if start < 0:
        return ""
    brace = text.index("{", start)
    depth = 0
    for i in range(brace, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[brace:i + 1]
    return ""


# ── part 1: source invariants ────────────────────────────────────────────────
val = body_of(source, "handle_header_val(llhttp_t *parser")
span_guards = [m.group(1) for m in re.finditer(r"if \(([^;{]*)\)\s*\n\s*sp_h1_header_span\(pfe, at, length\);", val)]
check(any("http_corr_field" in g for g in span_guards),
      "handle_header_val keeps the value's bytes when the field is a correlation field "
      "(guards seen: %s)" % (span_guards or "none"))

resets = [m.start() for m in re.finditer(r"pfe->http_content_type_count = 0;", source)]
begin = body_of(source, "handle_on_message_begin(llhttp_t* parser)")
order = []
for mark in ("pfe->http_content_type_count = 0;", "pfe->http_corr_field = 0;",
             "llb_ai_token_quota_consume(", "proxy_ai_record_completion(pfe);",
             "sp_corr_reset(&pfe->http_corr);"):
    order.append(begin.find(mark))
ct, field, release, completion, reset = order
check(len(resets) == 1 and resets[0] == source.find(begin) + ct and
      min(order) >= 0 and begin.count("sp_corr_reset(&pfe->http_corr);") == 1 and
      reset > release and reset > completion and abs(field - ct) < 200,
      "the per-request reset (%d site) clears the field state with the header "
      "state and the capture once, after request N's release and completion "
      "(offsets %s)" % (len(resets), order))

# The HTTP/1.1 admission context is built before the request's ID is minted:
# it takes the live capture of the request in hand (none on a pipelined
# read), never the key-following choice, which could still name an earlier
# request's hand-over snapshot at that moment.
adm = body_of(source, "sp_h1_admit_req_from_headers(const proxy_fd_ent_t *pfe")
check("req->corr = pfe->http_pipelined ? NULL : &pfe->http_corr.rec;" in adm and
      "proxy_request_corr" not in adm,
      "the HTTP/1.1 admission context takes the live capture of the request in hand")

h2cb = ""
for m in re.finditer(r'HEADER_MATCHES\("x-conversation-id"\)', h2):
    fn = h2.rfind("\nstatic int", 0, m.start())
    h2cb = h2[fn:m.start() + 4000]
    break
calls = len(re.findall(r"sp_corr_value\(&stream->corr,\s*sp_corr_field\(", h2))
check(calls == 1 and "sp_corr_value(&stream->corr" in h2cb,
      "the HTTP/2 request-header callback hands each field to the capture, once "
      "(calls in sockproxy_h2.c: %d)" % calls)

# ── part 2: the HTTP/1.1 callbacks, every split ──────────────────────────────
start = header.index("enum {\n  SP_H1_MEDIA_JSON")
media_enum = header[start:header.index("};", start) + 2]
start = source.index("static void\nsp_h1_header_span(")
callbacks = source[start:source.index("\nint\nhandle_header_name(", start)]

prefix = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "llhttp.h"
#include "sockproxy_corr.h"
typedef struct {
  char *rcvbuf;
  int odir, http_hdrs_done;
  size_t http_header_start, http_header_len, rcv_off;
  uint8_t http_content_type_field, http_body_media, http_content_type_count;
  uint8_t http_corr_field;
  sp_corr_cap_t http_corr;
} proxy_fd_ent_t;
'''
suffix = r'''
/* The gating handle_header_name / handle_header_val apply before they call
 * the span helper: trailers are not request headers, and a value's bytes are
 * kept only for a field something reads. */
static int begin(llhttp_t *parser)
{
  llhttp_settings_t *settings = parser->settings;
  proxy_fd_ent_t *p = settings->uarg;
  p->http_hdrs_done = p->http_header_len = 0;
  p->http_content_type_field = p->http_body_media = p->http_content_type_count = 0;
  p->http_corr_field = 0;
  sp_corr_reset(&p->http_corr);
  return 0;
}
static int field(llhttp_t *parser, const char *at, size_t len)
{
  llhttp_settings_t *settings = parser->settings;
  proxy_fd_ent_t *p = settings->uarg;
  if (parser->flags & F_TRAILING) return 0;
  if (!p->http_hdrs_done) sp_h1_header_span(p, at, len);
  return 0;
}
static int value(llhttp_t *parser, const char *at, size_t len)
{
  llhttp_settings_t *settings = parser->settings;
  proxy_fd_ent_t *p = settings->uarg;
  if (parser->flags & F_TRAILING) return 0;
  if (!p->http_hdrs_done && (p->http_content_type_field || p->http_corr_field))
    sp_h1_header_span(p, at, len);
  return 0;
}
static int headers(llhttp_t *parser)
{
  llhttp_settings_t *settings = parser->settings;
  proxy_fd_ent_t *p = settings->uarg;
  p->http_hdrs_done = 1;
  return 0;
}
static const char *rec(const proxy_fd_ent_t *p)
{
  static char out[256];
  ai_corr_t r;
  memset(&r, 0x5a, sizeof(r));
  sp_corr_export(&p->http_corr, &r);
  snprintf(out, sizeof(out), "%s|%s|%s",
           r.trace_id[0] ? r.trace_id : "-", r.parent_span_id[0] ? r.parent_span_id : "-",
           r.session_id[0] ? r.session_id : "-");
  return out;
}
static int fails;
static char seq_got[8][256];
static int seq_n;
static int done(llhttp_t *parser)
{
  llhttp_settings_t *settings = parser->settings;
  proxy_fd_ent_t *p = settings->uarg;
  if (seq_n < 8) snprintf(seq_got[seq_n], sizeof(seq_got[0]), "%s", rec(p));
  seq_n++;
  return 0;
}
/* Requests 1..n on one kept connection, each record read as its request
 * completes: at every two-piece split of the whole and bytewise. */
static void seq(const char *what, const char *wire, int n, const char *const *want)
{
  size_t len = strlen(wire);
  char buf[8192];
  assert(len < sizeof(buf));
  memcpy(buf, wire, len);
  llhttp_settings_t settings;
  llhttp_settings_init(&settings);
  settings.on_message_begin = begin;
  settings.on_header_field = field;
  settings.on_header_field_complete = sp_h1_header_field_complete;
  settings.on_header_value = value;
  settings.on_header_value_complete = sp_h1_header_value_complete;
  settings.on_headers_complete = headers;
  settings.on_message_complete = done;
  proxy_fd_ent_t p;
  memset(&p, 0, sizeof(p));
  p.rcvbuf = buf; p.rcv_off = len;
  settings.uarg = &p;
  llhttp_t parser;
  int bad = 0;
  for (size_t split = 0; split <= len + 1 && !bad; split++) {
    seq_n = 0;
    llhttp_init(&parser, HTTP_REQUEST, &settings);
    if (split <= len) {
      assert(llhttp_execute(&parser, buf, split) == HPE_OK);
      assert(llhttp_execute(&parser, buf + split, len - split) == HPE_OK);
    } else {
      for (size_t i = 0; i < len; i++)
        assert(llhttp_execute(&parser, buf + i, 1) == HPE_OK);
    }
    for (int i = 0; i < n && !bad; i++)
      if (seq_n != n || strcmp(seq_got[i], want[i]) != 0) {
        printf("FAIL: %s, %s: request %d of %d got '%s', want '%s'\n", what,
               split <= len ? "split" : "bytewise", i + 1, seq_n,
               seq_n > i ? seq_got[i] : "(none)", want[i]);
        bad = 1;
      }
  }
  if (!bad) printf("PASS: %s\n", what);
  fails += bad;
}
static void test(const char *what, const char *hdrs, const char *tail, const char *want, int media)
{
  char wire[8192];
  size_t len = (size_t)snprintf(wire, sizeof(wire),
      "POST / HTTP/1.1\r\nHost: test\r\n%s%s", hdrs, tail);
  assert(len < sizeof(wire));
  llhttp_settings_t settings;
  llhttp_settings_init(&settings);
  settings.on_message_begin = begin;
  settings.on_header_field = field;
  settings.on_header_field_complete = sp_h1_header_field_complete;
  settings.on_header_value = value;
  settings.on_header_value_complete = sp_h1_header_value_complete;
  settings.on_headers_complete = headers;
  proxy_fd_ent_t p;
  memset(&p, 0, sizeof(p));
  p.rcvbuf = wire; p.rcv_off = len;
  settings.uarg = &p;
  llhttp_t parser;
  int bad = 0;
  for (size_t split = 0; split <= len && !bad; split++) {
    llhttp_init(&parser, HTTP_REQUEST, &settings);
    assert(llhttp_execute(&parser, wire, split) == HPE_OK);
    assert(llhttp_execute(&parser, wire + split, len - split) == HPE_OK);
    if (strcmp(rec(&p), want) != 0 || p.http_body_media != media) {
      printf("FAIL: %s, split at %zu: got '%s' media %d, want '%s' media %d\n",
             what, split, rec(&p), p.http_body_media, want, media);
      bad = 1;
    }
  }
  /* A kept connection: the same request three times on one parser, bytewise. */
  llhttp_init(&parser, HTTP_REQUEST, &settings);
  for (int n = 0; n < 3 && !bad; n++) {
    for (size_t i = 0; i < len; i++)
      assert(llhttp_execute(&parser, wire + i, 1) == HPE_OK);
    if (strcmp(rec(&p), want) != 0) {
      printf("FAIL: %s, request %d of 3 on one connection, bytewise: got '%s', want '%s'\n",
             what, n + 1, rec(&p), want);
      bad = 1;
    }
  }
  if (!bad) printf("PASS: %s\n", what);
  fails += bad;
}
#define T  "4bf92f3577b34da6a3ce929d0e0e4736"
#define P  "00f067aa0ba902b7"
#define TP "00-" T "-" P "-01"
#define S  "loxigpt.app:sess_01-A"
#define CL "Content-Length: 2\r\n\r\n{}"
int main(void)
{
  test("both valid", "traceparent: " TP "\r\nX-Client-Session-Id: " S "\r\n", CL,
       T "|" P "|" S, 0);
  test("neither sent", "Accept: */*\r\n", CL, "-|-|-", 0);
  test("whitespace around the values", "traceparent:  \t" TP " \t\r\nX-Client-Session-Id:\t" S "  \r\n", CL,
       T "|" P "|" S, 0);
  test("Content-Type between them still decides the body's media",
       "traceparent: " TP "\r\nContent-Type: application/json\r\nX-Client-Session-Id: " S "\r\n", CL,
       T "|" P "|" S, SP_H1_MEDIA_JSON);
  test("duplicate traceparent, two spellings: trace absent, session kept",
       "traceparent: " TP "\r\nX-Client-Session-Id: " S "\r\nTraceParent: " TP "\r\n", CL,
       "-|-|" S, 0);
  test("duplicate session: session absent, trace kept",
       "X-Client-Session-Id: " S "\r\ntraceparent: " TP "\r\nx-client-session-id: other\r\n", CL,
       T "|" P "|-", 0);
  test("a duplicate session line that is empty still voids it",
       "X-Client-Session-Id: " S "\r\nX-Client-Session-Id:\r\ntraceparent: " TP "\r\n", CL,
       T "|" P "|-", 0);
  test("comma-joined traceparent: trace absent, session kept",
       "traceparent: " TP "," TP "\r\nX-Client-Session-Id: " S "\r\n", CL, "-|-|" S, 0);
  test("invalid traceparent (version ff): trace absent, session kept",
       "traceparent: ff-" T "-" P "-01\r\nX-Client-Session-Id: " S "\r\n", CL, "-|-|" S, 0);
  test("X-Session-IDx and X-Client-Session-Idx are not the session header",
       "X-Session-IDx: " S "\r\nX-Client-Session-Idx: " S "\r\ntraceparent: " TP "\r\n", CL,
       T "|" P "|-", 0);
  test("a traceparent in the trailers is not a request header (no duplicate)",
       "traceparent: " TP "\r\nX-Client-Session-Id: " S "\r\nTransfer-Encoding: chunked\r\n",
       "\r\n2\r\n{}\r\n0\r\ntraceparent: 00-" T "-00f067aa0ba902b8-01\r\n\r\n",
       T "|" P "|" S, 0);
  char big[4096];
  snprintf(big, sizeof(big), "X-Pad: %01900d\r\ntraceparent: " TP "\r\n", 0);
  test("a value well past the first read", big, CL, T "|" P "|-", 0);
  /* Rule 3 (the WP-G class): request N+1 on a kept connection never carries
   * request N's values, and one header line after a reset is one line. */
  static const char *const ka_want[] = {
    (T "|" P "|" S), "-|-|-", (T "|00f067aa0ba902b9|other-session"), ("-|-|" S),
  };
  seq("keep-alive: both, then neither, then other values, then a session alone",
      "POST / HTTP/1.1\r\nHost: t\r\ntraceparent: " TP "\r\nX-Client-Session-Id: " S "\r\n" CL
      "POST / HTTP/1.1\r\nHost: t\r\n" CL
      "POST / HTTP/1.1\r\nHost: t\r\ntraceparent: 00-" T "-00f067aa0ba902b9-01\r\n"
      "X-Client-Session-Id: other-session\r\n" CL
      "POST / HTTP/1.1\r\nHost: t\r\nX-Client-Session-Id: " S "\r\n" CL,
      4, ka_want);
  if (fails) { printf("%d case(s) FAILED\n", fails); return 1; }
  puts("correlation capture on the HTTP/1.1 callbacks: every split, bytewise keep-alive PASS");
  return 0;
}
'''

with tempfile.TemporaryDirectory() as folder:
    folder = Path(folder)
    unit = folder / "test.c"
    binary = folder / "test"
    unit.write_text(prefix + media_enum + callbacks + suffix)
    cc = subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra",
                         "-Werror", "-Wno-unused-parameter", "-fsanitize=address,undefined",
                         "-I", str(root), str(unit), str(root / "llhttp.c"),
                         str(root / "httpapi.c"), str(root / "http.c"), "-o", str(binary)])
    if cc.returncode != 0:
        check(False, "the HTTP/1.1 harness compiles against the cut callbacks and sockproxy_corr.h")
    else:
        run = subprocess.run([str(binary)])
        check(run.returncode == 0, "the HTTP/1.1 cases")

if failed:
    print("test_corr_h1: %d part(s) FAILED" % failed)
    sys.exit(1)
print("test_corr_h1: source invariants and the HTTP/1.1 callbacks PASS")
