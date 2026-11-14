#!/usr/bin/env python3
"""An Endpoint Picker's immediate answer carries exactly one X-Request-Id.

epp_send_immediate writes the EPP's own header set into the answer the
client gets. Every answer the gateway writes names the request by its own
ID (sockproxy_refusal_mark.h), so an EPP that sets x-request-id on its
immediate response left the client with two lines, possibly two values.
The request's own ID is the one that stays; the EPP's line is kept only
when the request has none that can be echoed. An answer too long for the
outage sender's splice is covered as well.

The production epp_send_immediate and sp_send_local_outage run against
stubs; the client's bytes are what proxy_send_local_response is handed."""
from pathlib import Path
import os, subprocess, tempfile
root = Path(__file__).resolve().parent
epp = (root / 'sockproxy_epp.c').read_text()
http = (root / 'sockproxy_http.c').read_text()
if os.environ.get('EPP_TEST_EPP'):
    epp = Path(os.environ['EPP_TEST_EPP']).read_text()
if os.environ.get('EPP_TEST_HTTP'):
    http = Path(os.environ['EPP_TEST_HTTP']).read_text()

def body(src, start):
    i = src.index(start)
    return src[i:src.index('\n}\n', i) + 3]

a = epp.index('static const char *\nepp_reason(')
b = epp.index('\n}\n', epp.index('\nvoid\nepp_send_immediate(')) + 3
m0 = http.index('#define SP_LOCAL_REFUSAL_MAX')
outage = http[m0:http.index('\n', m0) + 1] + body(http, 'int\nsp_send_local_outage(')

prefix = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "sockproxy_refusal_mark.h"
typedef struct proxy_fd_ent {
  int fd; unsigned long long epp_sid; int lb_err_body_sent;
  char vllm_request_id[300];
} proxy_fd_ent_t;
struct epp_result {
  int imm_code;
  const char *imm_body; int imm_body_len;
  const char *hdr_set;  int hdr_set_len;
};
#define log_error(...) ((void)0)
#define log_info(...) ((void)0)
static char wire[8192]; static size_t wire_len; static int completions;
static void proxy_record_local_completion(proxy_fd_ent_t *p, uint16_t s){(void)p;(void)s;completions++;}
static int proxy_send_local_response(proxy_fd_ent_t *p, const void *buf, size_t n){
  (void)p; assert(n < sizeof(wire)); memcpy(wire, buf, n); wire[n] = 0; wire_len = n; return 0;
}
int sp_send_local_outage(proxy_fd_ent_t *pfe, uint16_t status, const void *buf, size_t len);
'''
suffix = r'''
static int fails;
/* The X-Request-Id lines of the head on the wire: how many, and the last value. */
static int rid_lines(char *val, size_t cap)
{
  char *end = strstr(wire, "\r\n\r\n"), *p = wire;
  int n = 0;
  val[0] = 0;
  assert(end);
  while (p < end) {
    char *eol = strstr(p, "\r\n");
    if (!strncasecmp(p, "x-request-id:", 13)) {
      const char *v = p + 13;
      while (*v == ' ') v++;
      snprintf(val, cap, "%.*s", (int)(eol - v), v);
      n++;
    }
    p = eol + 2;
  }
  return n;
}
static void one(const char *what, const char *live, const char *hdrs, int blen, const char *want)
{
  proxy_fd_ent_t p = { .fd = 7 };
  struct epp_result r = { .imm_code = 429 };
  char *bodybuf = malloc((size_t)blen + 1), val[300];
  int n;
  memset(bodybuf, 'b', (size_t)blen); bodybuf[blen] = 0;
  snprintf(p.vllm_request_id, sizeof(p.vllm_request_id), "%s", live);
  r.imm_body = bodybuf; r.imm_body_len = blen;
  r.hdr_set = hdrs; r.hdr_set_len = (int)strlen(hdrs);
  wire_len = 0; wire[0] = 0;
  epp_send_immediate(&p, &r);
  assert(wire_len > 0 && !strncmp(wire, "HTTP/1.1 429 Too Many Requests\r\n", 32));
  n = rid_lines(val, sizeof(val));
  {
    /* the body and its length are the EPP's, whatever happened to the head */
    char cl[48]; const char *b = strstr(wire, "\r\n\r\n") + 4;
    snprintf(cl, sizeof(cl), "\r\nContent-Length: %d\r\n", blen);
    assert(strstr(wire, cl) && (int)strlen(b) == blen && !memcmp(b, bodybuf, (size_t)blen));
  }
  if (want[0] == 0 ? n != 0 : (n != 1 || strcmp(val, want))) {
    printf("FAIL %s: %d X-Request-Id line(s), last '%s'; want %s'%s'\n", what, n, val,
           want[0] ? "one, " : "none ", want);
    fails++;
  } else {
    printf("ok   %s: %d line(s) '%s'\n", what, n, val);
  }
  free(bodybuf);
}
int main(void)
{
  one("the EPP names its own ID, the request has one", "req-own", "retry-after: 3\r\nx-request-id: epp-id\r\n", 20, "req-own");
  one("the same in another case of the name", "req-own", "X-Request-ID: epp-id\r\nretry-after: 3\r\n", 20, "req-own");
  one("the EPP names it twice", "req-own", "x-request-id: a\r\nx-other: 1\r\nx-request-id: b\r\n", 20, "req-own");
  one("the EPP names none", "req-own", "retry-after: 3\r\n", 20, "req-own");
  one("no header set at all", "req-own", "", 20, "req-own");
  one("an answer longer than the outage sender's splice room", "req-own", "x-request-id: epp-id\r\n", 2000, "req-own");
  one("a long answer, the EPP names none", "req-own", "retry-after: 3\r\n", 2000, "req-own");
  one("the request has no ID: the EPP's stays", "", "x-request-id: epp-id\r\n", 20, "epp-id");
  one("the request's ID cannot be a header value: the EPP's stays", "a\rb", "x-request-id: epp-id\r\n", 20, "epp-id");
  one("neither has one", "", "retry-after: 3\r\n", 20, "");
  {
    /* a name that only starts like it is another header and is kept */
    proxy_fd_ent_t p = { .fd = 7 };
    struct epp_result r = { .imm_code = 429, .hdr_set = "x-request-id-source: epp\r\n", .hdr_set_len = 26 };
    strcpy(p.vllm_request_id, "req-own");
    epp_send_immediate(&p, &r);
    if (!strstr(wire, "\r\nx-request-id-source: epp\r\n")) { puts("FAIL a longer name was dropped"); fails++; }
    else puts("ok   a header whose name only starts with x-request-id is kept");
  }
  assert(completions == 11);
  if (fails) { printf("EPP immediate answer: %d case(s) FAILED\n", fails); return 1; }
  puts("EPP immediate answer: exactly one X-Request-Id, the request's own when it has one PASS");
  return 0;
}
'''
with tempfile.TemporaryDirectory() as td:
    p = Path(td); (p / 'test.c').write_text(prefix + epp[a:b] + outage + suffix)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror', '-I', str(root),
                    '-o', str(p / 'test'), str(p / 'test.c')], check=True)
    subprocess.run([str(p / 'test')], check=True)
