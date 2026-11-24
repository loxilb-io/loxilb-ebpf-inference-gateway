#!/usr/bin/env python3
"""X-Forwarded-Proto and X-Forwarded-Host reach the backend on an HTTPS
request, upgrade requests included, and nothing else changes what the
function does (inject_forwarded_headers, sockproxy_http.c, run from the
source).

What the function may not do is as much a part of this:
- a body that contains "Connection: Upgrade" or "Transfer-Encoding: chunked"
  does not change it;
- it looks only inside the bytes it was given: the receive buffer is not
  NUL-terminated at them, and past them may lie an earlier request's bytes,
  as on a keep-alive connection whose second request is shorter than its
  first;
- binary bytes (a WebSocket frame) and a plain-HTTP request are left as they
  came."""
from pathlib import Path
import os, subprocess, sys, tempfile
root = Path(__file__).resolve().parent
http = (root / 'sockproxy_http.c').read_text()
if os.environ.get('FWD_TEST_HTTP'):
    http = Path(os.environ['FWD_TEST_HTTP']).read_text()

def body(src, start):
    i = src.index(start)
    return src[i:src.index('\n}\n', i) + 3]

helper = 'static const uint8_t *\nsp_mem_casefind('
fns = (body(http, helper) if helper in http else '') + \
      body(http, 'static ssize_t\ninject_forwarded_headers(')

prefix = r'''
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#define log_error(...) ((void)0)
#define log_trace(...) ((void)0)
#define log_debug(...) ((void)0)
'''

test = r'''
#define SZ 8192
static int bad;
static uint8_t buf[SZ];

static void show(const uint8_t *p, size_t n)
{
  for (size_t i = 0; i < n; i++)
    p[i] == '\r' ? fputs("\\r", stdout) : p[i] == '\n' ? fputs("\\n", stdout) :
    (p[i] < 32 || p[i] > 126) ? printf("\\x%02x", p[i]) : putchar(p[i]);
}

/* The receive buffer as a connection leaves it: zero past what was ever
 * written, the bytes of an earlier request (stale) where it reached, and the
 * read being handled (in, n bytes) at the start. */
static void run(const char *what, int ssl, const char *host, const char *in, size_t n,
                const char *stale, size_t bufsize, ssize_t want_len, const char *want)
{
  ssize_t got;

  memset(buf, 0, sizeof(buf));
  if (stale)
    memcpy(buf, stale, strlen(stale));
  memcpy(buf, in, n);
  got = inject_forwarded_headers(buf, n, bufsize, ssl, host);
  if (got == want_len && (got < 0 || !memcmp(buf, want, (size_t)got))) {
    printf("PASS %s\n", what);
    return;
  }
  bad++;
  printf("FAIL %s\n  got  (%zd): ", what, got);
  if (got > 0 && (size_t)got <= sizeof(buf))
    show(buf, (size_t)got);
  printf("\n  want (%zd): ", want_len);
  if (want_len > 0)
    show((const uint8_t *)want, (size_t)want_len);
  putchar('\n');
}
#define RUN(what, ssl, host, in, stale, want) \
  run(what, ssl, host, in, sizeof(in) - 1, stale, SZ, sizeof(want) - 1, want)

#define XF   "X-Forwarded-Proto: https\r\nX-Forwarded-Host: a.example.com\r\n"
#define HOST "Host: a.example.com\r\n"
#define WS(conn) "GET /cluster-api/exec HTTP/1.1\r\n" HOST "Upgrade: websocket\r\n" \
                 "Connection: " conn "\r\nSec-WebSocket-Key: dGhlIHNhbXBsZQ==\r\n" \
                 "Sec-WebSocket-Version: 13\r\n"
#define UPB  "{\"prompt\":\"Connection: Upgrade\"}"
#define CHB  "{\"prompt\":\"Transfer-Encoding: chunked\"}"
#define ST(len) "Content-Type: application/json\r\nContent-Length: " len "\r\n"

int main(void)
{
  setvbuf(stdout, NULL, _IONBF, 0);
  RUN("a GET: both headers go in before the blank line", 1, "a.example.com",
      "GET / HTTP/1.1\r\n" HOST "\r\n", NULL,
      "GET / HTTP/1.1\r\n" HOST XF "\r\n");
  RUN("a WebSocket handshake with Connection: Upgrade gets them too", 1, "a.example.com",
      WS("Upgrade") "\r\n", NULL, WS("Upgrade") XF "\r\n");
  RUN("Connection: upgrade, in lower case", 1, "a.example.com",
      WS("upgrade") "\r\n", NULL, WS("upgrade") XF "\r\n");
  RUN("Connection: keep-alive, Upgrade", 1, "a.example.com",
      WS("keep-alive, Upgrade") "\r\n", NULL, WS("keep-alive, Upgrade") XF "\r\n");
  RUN("Connection: Upgrade with no Upgrade header: an ordinary request", 1, "a.example.com",
      "GET / HTTP/1.1\r\n" HOST "Connection: Upgrade\r\n\r\n", NULL,
      "GET / HTTP/1.1\r\n" HOST "Connection: Upgrade\r\n" XF "\r\n");
  RUN("a body that says Connection: Upgrade: the request is forwarded, the body unchanged", 1,
      "a.example.com", "POST /v1/completions HTTP/1.1\r\n" HOST ST("32") "\r\n" UPB, NULL,
      "POST /v1/completions HTTP/1.1\r\n" HOST ST("32") XF "\r\n" UPB);
  RUN("a body that says Transfer-Encoding: chunked does not make the request chunked", 1,
      "a.example.com", "POST /v1/completions HTTP/1.1\r\n" HOST ST("39") "\r\n" CHB, NULL,
      "POST /v1/completions HTTP/1.1\r\n" HOST ST("39") XF "\r\n" CHB);
  RUN("a chunked request is left as it came (the splice would move the chunks)", 1,
      "a.example.com", "POST /up HTTP/1.1\r\n" HOST "Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n", NULL,
      "POST /up HTTP/1.1\r\n" HOST "Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n");
  RUN("chunked in another case: left as it came", 1, "a.example.com",
      "PUT /up HTTP/1.1\r\n" HOST "transfer-encoding: CHUNKED\r\n\r\n", NULL,
      "PUT /up HTTP/1.1\r\n" HOST "transfer-encoding: CHUNKED\r\n\r\n");
  RUN("a header block not yet whole: unchanged, though an earlier request's blank line follows it",
      1, "a.example.com", "GET /x HTTP/1.1\r\n" HOST,
      "GET /an/earlier/request/with/a/longer/path HTTP/1.1\r\n" HOST "\r\n",
      "GET /x HTTP/1.1\r\n" HOST);
  RUN("an earlier chunked request's header past the read does not stop the injection", 1,
      "a.example.com", "GET /y HTTP/1.1\r\n" HOST "\r\n",
      "POST /an/earlier/request/padded/past/the/read/ HTTP/1.1\r\n" HOST
      "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
      "GET /y HTTP/1.1\r\n" HOST XF "\r\n");
  RUN("a WebSocket frame (binary): unchanged", 1, "a.example.com",
      "\x81\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58", NULL,
      "\x81\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58");
  RUN("plain HTTP: nothing is injected, a handshake neither", 0, "a.example.com",
      WS("Upgrade") "\r\n", NULL, WS("Upgrade") "\r\n");
  RUN("no Host: X-Forwarded-Proto alone", 1, NULL,
      "GET / HTTP/1.1\r\n\r\n", NULL,
      "GET / HTTP/1.1\r\nX-Forwarded-Proto: https\r\n\r\n");
  {
    static const char in[] = "GET / HTTP/1.1\r\n" HOST "\r\n";
    run("no room for the headers: an error, as before", 1, "a.example.com",
        in, sizeof(in) - 1, NULL, sizeof(in) + 4, -1, NULL);
  }
  printf(bad ? "FAILED (%d)\n" : "test_forwarded_inject: ok\n", bad);
  return bad != 0;
}
'''
with tempfile.TemporaryDirectory() as d:
    src = Path(d) / 'test.c'
    src.write_text(prefix + fns + test)
    cc = os.environ.get('CC', 'cc')
    subprocess.run([cc, '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                    '-Wno-unused-parameter', '-fsanitize=address,undefined', '-I', str(root),
                    '-o', str(Path(d) / 't'), str(src)], check=True)
    sys.exit(subprocess.run([str(Path(d) / 't')]).returncode)
