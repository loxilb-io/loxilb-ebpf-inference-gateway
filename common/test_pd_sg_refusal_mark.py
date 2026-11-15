#!/usr/bin/env python3
"""The SGLang oversize refusal carries the refusal mark (pd_sg_oversize_reject,
sockproxy_pd_sglang.c, run from the source against stubs).

503 pd_sg_oversize_unroutable is refused by the gateway before any backend
byte moves and recorded at stage `framing`. Like every refusal the gateway
writes, the answer names that stage and the request's own ID after its status
line (sockproxy_refusal_mark.h); everything else of the text, the body above
all, is what it was. One refusal note, one deny record at framing, one write."""
from pathlib import Path
import os, subprocess, sys, tempfile
root = Path(__file__).resolve().parent
sg = (root / 'sockproxy_pd_sglang.c').read_text()
if os.environ.get('SG_TEST_SOURCE'):
    sg = Path(os.environ['SG_TEST_SOURCE']).read_text()
i = sg.index('void\npd_sg_oversize_reject(')
fn = sg[i:sg.index('\n}\n', i) + 3]

prefix = r'''
#define _GNU_SOURCE
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "sockproxy_refusal_mark.h"
#define log_error(...) ((void)0)
#define AI_GW_STAGE_FRAMING 8
typedef struct proxy_fd_ent {
  int fd; size_t http_content_length; char vllm_request_id[256]; uint8_t http_pipelined;
} proxy_fd_ent_t;
static struct { _Atomic uint64_t pd_sg_oversize_reject; } global_stats;
static int notes, denies, deny_stage, deny_status, writes, shuts;
static char deny_code[64], wire[2048];
static size_t wire_len;
static int proxy_note_local_refusal(proxy_fd_ent_t *p, uint16_t s) { (void)p; (void)s; notes++; return 1; }
static void proxy_record_local_deny(proxy_fd_ent_t *p, int stage, int status, const char *code) {
  (void)p; denies++; deny_stage = stage; deny_status = status;
  snprintf(deny_code, sizeof(deny_code), "%s", code);
}
static ssize_t sp_raw_status_write(proxy_fd_ent_t *p, const void *buf, size_t len, int flags) {
  (void)p; (void)flags; writes++;
  if (wire_len + len < sizeof(wire)) { memcpy(wire + wire_len, buf, len); wire_len += len; }
  return (ssize_t)len;
}
static int test_shutdown(void) { shuts++; return 0; }
#define shutdown(fd, how) test_shutdown()
'''

test = r'''
#define STATUS "HTTP/1.1 503 Service Unavailable\r\n"
#define REST   "Content-Type: application/json\r\nConnection: close\r\n\r\n" \
  "{\"error\":\"pd_sg_oversize_unroutable\",\"detail\":\"request body exceeds the gateway inspection window for prefill/decode dual dispatch\"}"
static int bad;
static int pipelined_next;   /* the next run(): a second request is already in the buffer */
static void run(const char *what, const char *rid, const char *echo)
{
  proxy_fd_ent_t p = { .fd = 7, .http_content_length = 900000, .http_pipelined = (uint8_t)pipelined_next };
  char want[2048];
  int n;

  pipelined_next = 0;
  notes = denies = deny_stage = deny_status = writes = shuts = 0; wire_len = 0; deny_code[0] = 0;
  if (rid) snprintf(p.vllm_request_id, sizeof(p.vllm_request_id), "%s", rid);
  n = snprintf(want, sizeof(want), STATUS "X-Loxilb-Refusal-Stage: framing\r\n");
  if (echo) n += snprintf(want + n, sizeof(want) - (size_t)n, "X-Request-Id: %s\r\n", echo);
  n += snprintf(want + n, sizeof(want) - (size_t)n, "%s", REST);
  pd_sg_oversize_reject(&p);
  if (wire_len == (size_t)n && !memcmp(wire, want, wire_len) && writes == 1) {
    printf("PASS %s: the text with its stage%s after the status line, the rest byte-identical\n",
           what, echo ? " and the request's ID" : " alone");
  } else {
    bad++;
    printf("FAIL %s: %d write(s), %zu bytes, wanted one of %d; the head sent:\n", what, writes, wire_len, n);
    wire[wire_len] = 0;
    char *e = strstr(wire, "\r\n\r\n"); if (e) *e = 0;
    printf("  %s\n", wire);
  }
  if (notes == 1 && denies == 1 && deny_stage == AI_GW_STAGE_FRAMING && deny_status == 503 &&
      !strcmp(deny_code, "pd_sg_oversize_unroutable") && shuts == 1 &&
      atomic_load(&global_stats.pd_sg_oversize_reject) >= 1) {
    printf("PASS %s: one refusal note, one deny record at framing, counted, the socket shut\n", what);
  } else {
    bad++;
    printf("FAIL %s: notes %d denies %d stage %d status %d code %s shuts %d\n", what, notes, denies,
           deny_stage, deny_status, deny_code, shuts);
  }
}
int main(void)
{
  char id255[256];
  memset(id255, 'r', 255); id255[255] = 0;
  run("an ID", "req-7f3a", "req-7f3a");
  run("a 255-byte ID", id255, id255);
  run("no ID", NULL, NULL);
  run("an ID that cannot be a header value", "bad\x01id", NULL);
  pipelined_next = 1;
  run("a second request in the buffer, the live ID is that request's", "req-next-9c1d", NULL);
  run("the P/D routing ID (endpoint addresses)",
      "___prefill_addr_10.0.0.11:8000___decode_addr_10.0.0.12:8000_0123456789abcdef0123456789abcdef", NULL);
  printf(bad ? "FAILED (%d)\n" : "test_pd_sg_refusal_mark: ok\n", bad);
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
