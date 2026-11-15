#!/usr/bin/env python3
"""A backend's X-Api-Key does not reach the client on the final head when
interim heads precede it in the same read, on a service that declares
api_key_auth (sp_resp_strip_api_key, sockproxy_http.c, run from the source
against the real header helpers and the real policy predicate).

X-Api-Key is the gateway's credential header on such a service: a key a
backend echoes or mints is removed from its response head. A backend may
answer "100 Continue" (or 102, 103) and the final head in one write; the key
is then on the second head of the read, and it must be removed there as it
is when the final head comes alone. The function reads heads only while they
are interim ones: nothing behind a final head is looked at (a body may contain
anything), nothing behind a 101 is (another protocol), a final head that is
not whole in this read is left as it came, a read the framer did not mark is
not touched, and a service that made no api_key_auth declaration owns the
header, which passes."""
from pathlib import Path
import os, subprocess, sys, tempfile
root = Path(__file__).resolve().parent
http = (root / 'sockproxy_http.c').read_text()
if os.environ.get('STRIP_TEST_HTTP'):
    http = Path(os.environ['STRIP_TEST_HTTP']).read_text()
sec = (root / 'sockproxy_ai_security.c').read_text()

def body(src, start):
    i = src.index(start)
    return src[i:src.index('\n}\n', i) + 3]

fn = body(http, 'static size_t\nsp_resp_strip_api_key(')
pred = body(sec, 'int\nai_security_should_strip_api_key(')

prefix = r'''
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define log_error(...) ((void)0)
#include "sockproxy_l7hdr_guard.h"
#include "sockproxy_h1_hdr.h"
typedef struct { int unused; } proxy_map_ent_t;
typedef struct { uint8_t apikey_auth; } proxy_epval_t;
typedef struct { struct { int hdr_block; } cresp_blk; void *head; } proxy_fd_ent_t;
static proxy_map_ent_t the_rule;
static proxy_epval_t the_pool;
static proxy_epval_t *sp_pool_first(proxy_map_ent_t *n) { return n == &the_rule ? &the_pool : NULL; }
int ai_security_should_strip_api_key(uint8_t policy);
'''

test = r'''
static int bad;
static void run(const char *what, int policy, int marked, const char *in, const char *want)
{
  uint8_t buf[4096];
  proxy_fd_ent_t c = { .cresp_blk = { .hdr_block = marked }, .head = &the_rule };
  size_t n = strlen(in), got;

  the_pool.apikey_auth = (uint8_t)policy;
  memset(buf, 0xee, sizeof(buf));
  memcpy(buf, in, n);
  got = sp_resp_strip_api_key(&c, buf, n);
  if (got == strlen(want) && !memcmp(buf, want, got) && c.cresp_blk.hdr_block == 0) {
    printf("PASS %s\n", what);
  } else {
    bad++;
    printf("FAIL %s (mark after: %d)\n  got  (%zu): ", what, c.cresp_blk.hdr_block, got);
    for (size_t i = 0; i < got && i < sizeof(buf); i++)
      buf[i] == '\r' ? fputs("\\r", stdout) : buf[i] == '\n' ? fputs("\\n", stdout) : putchar(buf[i]);
    printf("\n  want (%zu): ", strlen(want));
    for (const char *p = want; *p; p++)
      *p == '\r' ? fputs("\\r", stdout) : *p == '\n' ? fputs("\\n", stdout) : putchar(*p);
    putchar('\n');
  }
}
#define C100 "HTTP/1.1 100 Continue\r\n\r\n"
#define KEY  "X-Api-Key: lxb_backend_minted\r\n"
#define H200 "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
#define TAIL "Content-Length: 44\r\n\r\n"
#define BODY "{\"note\":\"X-Api-Key: in\\r\\n\\r\\nthe body\"}"
#define REQ  2   /* any declared api_key_auth: 1 required, 2 declared disabled */
int main(void)
{
  run("the final head alone: the key is removed, the body is not read", REQ, 1,
      H200 KEY TAIL BODY, H200 TAIL BODY);
  run("100 Continue and the final head in one read: the key is removed from the final head", REQ, 1,
      C100 H200 KEY TAIL BODY, C100 H200 TAIL BODY);
  run("the key on the interim head and on the final head: removed from both", REQ, 1,
      "HTTP/1.1 100 Continue\r\n" KEY "\r\n" H200 KEY TAIL BODY, C100 H200 TAIL BODY);
  run("two interim heads (100, 103 with the key) and the final head: removed from each", REQ, 1,
      C100 "HTTP/1.1 103 Early Hints\r\nLink: </a>; rel=preload\r\n" KEY "\r\n" H200 KEY TAIL BODY,
      C100 "HTTP/1.1 103 Early Hints\r\nLink: </a>; rel=preload\r\n\r\n" H200 TAIL BODY);
  run("required (1) as well as declared disabled (2): removed behind the interim head", 1, 1,
      C100 H200 KEY TAIL BODY, C100 H200 TAIL BODY);
  run("an interim head alone: as it came", REQ, 1, C100, C100);
  run("an interim head and a final head that is not whole: the part is left as it came", REQ, 1,
      C100 H200 KEY "Content-Len", C100 H200 KEY "Content-Len");
  run("101 with the key on its own head: removed there, and nothing after it is touched", REQ, 1,
      "HTTP/1.1 101 Switching Protocols\r\n" KEY "Upgrade: x\r\n\r\n" KEY "raw\r\n\r\n",
      "HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\n\r\n" KEY "raw\r\n\r\n");
  run("a final head, then a body that looks like a head: the body is not touched", REQ, 1,
      H200 "Content-Length: 60\r\n\r\n" H200 KEY "\r\n" "tail",
      H200 "Content-Length: 60\r\n\r\n" H200 KEY "\r\n" "tail");
  run("101 Switching Protocols: what follows it is not HTTP and is not touched", REQ, 1,
      "HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\n\r\n" H200 KEY "\r\n",
      "HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\n\r\n" H200 KEY "\r\n");
  run("an interim head, then bytes that are not a response head: not touched", REQ, 1,
      C100 "GARBAGE\r\n" KEY "\r\n", C100 "GARBAGE\r\n" KEY "\r\n");
  run("an interim head, then fewer bytes than a status line: as they came", REQ, 1,
      C100 "HTTP/1", C100 "HTTP/1");
  run("a 1xx status with a non-digit: not an interim head, nothing after it is touched", REQ, 1,
      "HTTP/1.1 1x0 Odd\r\n\r\n" H200 KEY TAIL, "HTTP/1.1 1x0 Odd\r\n\r\n" H200 KEY TAIL);
  run("a read the framer did not mark: not touched", REQ, 0,
      C100 H200 KEY TAIL BODY, C100 H200 KEY TAIL BODY);
  run("a service with no api_key_auth declaration owns the header: it passes, behind an interim head too", 0, 1,
      C100 H200 KEY TAIL BODY, C100 H200 KEY TAIL BODY);
  printf(bad ? "FAILED (%d)\n" : "test_resp_strip_api_key_interim: ok\n", bad);
  return bad != 0;
}
'''
with tempfile.TemporaryDirectory() as d:
    src = Path(d) / 'test.c'
    src.write_text(prefix + pred + fn + test)
    cc = os.environ.get('CC', 'cc')
    subprocess.run([cc, '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                    '-Wno-unused-parameter', '-fsanitize=address,undefined', '-fno-sanitize-recover=undefined', '-I', str(root),
                    '-o', str(Path(d) / 't'), str(src)], check=True)
    sys.exit(subprocess.run([str(Path(d) / 't')]).returncode)
