#!/usr/bin/env python3
"""A backend's X-Loxilb-Refusal-* does not reach the client on the final head
when interim heads precede it in the same read (sp_resp_strip_refusal_mark,
sockproxy_http.c, run from the source against the real header helpers).

The relay hands that function every read the response framer marked as the
start of a response. A backend may answer "100 Continue" (or 102, 103) and
the final head in one write; the family is then on the second head of the
read, and it must be removed there as it is when the final head comes alone.
What the function may not do is as much a part of this: it reads heads only
while they are interim ones, so nothing behind a final head is looked at
(a body may contain anything), nothing behind a 101 is (the bytes after it
are another protocol), a final head that is not whole in this read is left
as it came (the documented split-head residual), and a read the framer did
not mark is not touched at all."""
from pathlib import Path
import os, subprocess, sys, tempfile
root = Path(__file__).resolve().parent
http = (root / 'sockproxy_http.c').read_text()
if os.environ.get('STRIP_TEST_HTTP'):
    http = Path(os.environ['STRIP_TEST_HTTP']).read_text()

def body(src, start):
    i = src.index(start)
    return src[i:src.index('\n}\n', i) + 3]

fn = body(http, 'static size_t\nsp_resp_strip_refusal_mark(')

prefix = r'''
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define log_error(...) ((void)0)
#include "sockproxy_l7hdr_guard.h"
#include "sockproxy_h1_hdr.h"
#include "sockproxy_refusal_mark.h"
typedef struct { struct { int hdr_block; } cresp_blk; } proxy_fd_ent_t;
'''

test = r'''
static int bad;
static void run(const char *what, int marked, const char *in, const char *want)
{
  uint8_t buf[4096];
  proxy_fd_ent_t c = { .cresp_blk = { .hdr_block = marked } };
  size_t n = strlen(in), got;

  memset(buf, 0xee, sizeof(buf));
  memcpy(buf, in, n);
  got = sp_resp_strip_refusal_mark(&c, buf, n);
  if (got == strlen(want) && !memcmp(buf, want, got)) {
    printf("PASS %s\n", what);
  } else {
    bad++;
    printf("FAIL %s\n  got  (%zu): ", what, got);
    for (size_t i = 0; i < got && i < sizeof(buf); i++)
      buf[i] == '\r' ? fputs("\\r", stdout) : buf[i] == '\n' ? fputs("\\n", stdout) : putchar(buf[i]);
    printf("\n  want (%zu): ", strlen(want));
    for (const char *p = want; *p; p++)
      *p == '\r' ? fputs("\\r", stdout) : *p == '\n' ? fputs("\\n", stdout) : putchar(*p);
    putchar('\n');
  }
}
#define C100 "HTTP/1.1 100 Continue\r\n\r\n"
#define FAM  "X-Loxilb-Refusal-Stage: capacity\r\nx-loxilb-refusal-other: 1\r\n"
#define H200 "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
#define TAIL "Content-Length: 61\r\n\r\n"
#define BODY "{\"note\":\"X-Loxilb-Refusal-Stage: capacity\\r\\n\\r\\nHTTP/1.1 200 OK\"}"
int main(void)
{
  run("the final head alone: the family is removed, the body is not read", 1,
      H200 FAM TAIL BODY, H200 TAIL BODY);
  run("100 Continue and the final head in one read: the family is removed from the final head", 1,
      C100 H200 FAM TAIL BODY, C100 H200 TAIL BODY);
  run("the family on the interim head and on the final head: removed from both", 1,
      "HTTP/1.1 100 Continue\r\n" FAM "\r\n" H200 FAM TAIL BODY, C100 H200 TAIL BODY);
  run("two interim heads (100, 103 with the family) and the final head: removed from each", 1,
      C100 "HTTP/1.1 103 Early Hints\r\nLink: </a>; rel=preload\r\n" FAM "\r\n" H200 FAM TAIL BODY,
      C100 "HTTP/1.1 103 Early Hints\r\nLink: </a>; rel=preload\r\n\r\n" H200 TAIL BODY);
  run("an interim head alone: as it came", 1, C100, C100);
  run("an interim head and a final head that is not whole: the part is left as it came", 1,
      C100 H200 FAM "Content-Len", C100 H200 FAM "Content-Len");
  /* An interim head and the final head in two reads. The framer marks the
   * second read when it begins at the final head's first byte and holds all
   * of it: it is then a head alone, cleaned as always. */
  run("two reads, the second the whole final head (marked by the framer): the family is removed", 1,
      H200 FAM TAIL BODY, H200 TAIL BODY);
  /* The final head cut across reads: its first part came behind the interim
   * head and was left (above); the read that brings the rest does not begin
   * at a head, the framer does not mark it, and it is not touched. A final
   * head that is not whole in one read is the split-head residual: cleaned
   * only where the relay puts the head together (sockproxy_resp_head.h). */
  run("two reads, the second the rest of a cut final head (not marked): not touched, the residual", 0,
      "gth: 61\r\n" FAM "\r\n" BODY, "gth: 61\r\n" FAM "\r\n" BODY);
  run("101 with the family on its own head: removed there, and nothing after it is touched", 1,
      "HTTP/1.1 101 Switching Protocols\r\n" FAM "Upgrade: x\r\n\r\n" FAM "raw\r\n\r\n",
      "HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\n\r\n" FAM "raw\r\n\r\n");
  run("a final head, then a body that looks like a head: the body is not touched", 1,
      H200 "Content-Length: 70\r\n\r\n" H200 FAM "\r\n" "tail",
      H200 "Content-Length: 70\r\n\r\n" H200 FAM "\r\n" "tail");
  run("101 Switching Protocols: what follows it is not HTTP and is not touched", 1,
      "HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\n\r\n" H200 FAM "\r\n",
      "HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\n\r\n" H200 FAM "\r\n");
  run("an interim head, then bytes that are not a response head: not touched", 1,
      C100 "GARBAGE\r\n" FAM "\r\n", C100 "GARBAGE\r\n" FAM "\r\n");
  run("a read the framer did not mark: not touched", 0,
      C100 H200 FAM TAIL BODY, C100 H200 FAM TAIL BODY);
  printf(bad ? "FAILED (%d)\n" : "test_resp_strip_interim: ok\n", bad);
  return bad != 0;
}
'''
with tempfile.TemporaryDirectory() as d:
    src = Path(d) / 'test.c'
    src.write_text(prefix + fn + test)
    cc = os.environ.get('CC', 'cc')
    subprocess.run([cc, '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                    '-Wno-unused-parameter', '-fsanitize=address,undefined', '-I', str(root),
                    '-o', str(Path(d) / 't'), str(src)], check=True)
    sys.exit(subprocess.run([str(Path(d) / 't')]).returncode)
