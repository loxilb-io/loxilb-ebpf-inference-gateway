#!/usr/bin/env python3
"""Run the production senders and the reaper's finish against a client whose
answer has begun, and against one whose answer has not (the twin): a status
line goes out only in the second case; in the first the answer is ended
in-band (a stream) or by the close, and the reaper's own SSE events and the
synthesised [DONE] still finish a stream."""
from pathlib import Path
import os, subprocess, tempfile
root = Path(__file__).resolve().parent
http = (root / 'sockproxy_http.c').read_text()
health = (root / 'sockproxy_health.c').read_text()
if os.environ.get('ANSWER_TEST_HTTP'):
    http = Path(os.environ['ANSWER_TEST_HTTP']).read_text()
if os.environ.get('ANSWER_TEST_HEALTH'):
    health = Path(os.environ['ANSWER_TEST_HEALTH']).read_text()

a = http.index('int\nproxy_send_local_response(proxy_fd_ent_t *pfe')
b = http.index('/* ---- responses the gateway writes itself', a)
senders = http[a:b]
t0 = health.index('typedef struct sp_reap_text {')
t1 = health.index('\n};\n', health.index('[SP_REAP_SSE_STALL]', t0)) + 4
r0 = health.index('static void\npd_reap_respond(')
r1 = health.index('\nvoid\nsp_reap_request(', r0)
c0 = health.index('static int\nsp_reap_client_chunked(')
c1 = health.index('\n}\n', c0) + 3
b0 = health.index('static size_t\nsp_reap_body_frame(')
b1 = health.index('\n}\n', b0) + 3
f0 = health.index('void\nsp_reap_finish(proxy_fd_ent_t *pfe)')
f1 = health.index('\n}\n', f0) + 3
reaper = health[t0:t1] + health[c0:c1] + health[b0:b1] + health[r0:r1] + health[f0:f1]

common = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include "sockproxy_answer.h"
#define F_CHUNKED (1 << 3)
#define MSG_DONTWAIT 0x40
#define MSG_NOSIGNAL 0x4000
#define SHUT_RDWR 2
typedef struct proxy_fd_ent proxy_fd_ent_t;
struct proxy_fd_ent {
  int fd; void *ssl; _Atomic uint8_t cresp_in_msg, cresp_answer_open;
  struct { uint8_t is_sse; } cresp_sse; struct { uint16_t flags; } cresp_parser;
  uint8_t reap_resp, read_paused, is_chunked_response; int n_rfd; proxy_fd_ent_t *rfd_ent[2];
};
static char wrote[1024]; static size_t wrote_len; static int writes, shuts, last_flags;
static void reset(void) { wrote_len = 0; writes = shuts = 0; last_flags = -1; }
static void take(const void *b, size_t n) { memcpy(wrote + wrote_len, b, n); wrote_len += n; writes++; }
static int has(const char *s) { return memmem(wrote, wrote_len, s, strlen(s)) != NULL; }
#define log_warn(...) ((void)0)
#define log_error(...) ((void)0)
#define log_debug(...) ((void)0)
#define log_info(...) ((void)0)
'''

senders_prefix = common + r'''
static int SSL_write(void *s, const void *b, int n) { (void)s; take(b, (size_t)n); last_flags = -2; return n; }
static int SSL_shutdown(void *s) { (void)s; return 1; }
static ssize_t send(int fd, const void *b, size_t n, int flags) { (void)fd; take(b, n); last_flags = flags; return (ssize_t)n; }
static int shutdown(int fd, int how) { (void)fd; (void)how; shuts++; return 0; }
#define SP_LOCAL_SEND_RETRY_MAX 4
static int proxy_send_local_once(void *a, const uint8_t *b, size_t n, int *retry) { (void)a; (void)b; (void)n; (void)retry; return 0; }
typedef int (*once_fn)(void *, const uint8_t *, size_t, int *);
static int sp_send_all_bounded(once_fn f, proxy_fd_ent_t *p, const void *b, size_t n, int m) { (void)f; (void)p; (void)m; take(b, n); return 0; }
static int sp_send_all_bounded_then_shutdown(once_fn f, int (*sh)(void *), proxy_fd_ent_t *p, const void *b, size_t n, int m) { (void)f; (void)m; take(b, n); sh(p); return 0; }
int sp_answer_started(proxy_fd_ent_t *pfe);
void sp_end_started_answer(proxy_fd_ent_t *pfe, const void *buf, size_t len);
'''
senders_main = r'''
static const char st[] = "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n{\"error\":\"pd_decode_stream_timeout\"}";
static proxy_fd_ent_t client(int in_msg, int open, int sse, int chunked, int tls) {
  proxy_fd_ent_t p; memset(&p, 0, sizeof(p)); p.fd = 7; p.ssl = tls ? (void *)&p : NULL;
  atomic_store(&p.cresp_in_msg, in_msg); atomic_store(&p.cresp_answer_open, open);
  p.cresp_sse.is_sse = sse; p.cresp_parser.flags = chunked ? F_CHUNKED : 0; return p;
}
int main(void) {
  proxy_fd_ent_t p;
  /* twin: no answer has begun, the status line goes out, whole */
  p = client(0, 0, 0, 0, 0); reset();
  assert(proxy_send_local_response(&p, st, sizeof(st) - 1) == 0);
  assert(writes == 1 && wrote_len == sizeof(st) - 1 && has("HTTP/1.1 502") && shuts == 0);
  p = client(0, 0, 0, 0, 0); reset();
  assert(proxy_send_local_response_and_shutdown(&p, st, sizeof(st) - 1) == 0);
  assert(has("HTTP/1.1 502") && shuts == 1);
  /* a stream whose headers went out: the in-band end, chunk-framed, then the close */
  p = client(1, 1, 1, 1, 0); reset();
  assert(proxy_send_local_response(&p, st, sizeof(st) - 1) == -1);
  assert(!has("HTTP/") && has("data: {\"error\":\"pd_decode_stream_timeout\"}\n\n") && has("\r\n0\r\n\r\n"));
  assert(shuts == 1);
  p = client(1, 1, 1, 0, 1); reset();
  assert(proxy_send_local_response_and_shutdown(&p, st, sizeof(st) - 1) == -1);
  assert(!has("HTTP/") && has("data: {\"error\":") && !has("\r\n0\r\n") && last_flags == -2 && shuts == 1);
  /* any other answer that has begun: nothing written, the close ends it */
  p = client(1, 1, 0, 0, 0); reset();
  assert(proxy_send_local_response(&p, st, sizeof(st) - 1) == -1);
  assert(wrote_len == 0 && shuts == 1);
  /* begun inside its header block (the status line split across reads):
   * no event either, it would land among the headers */
  p = client(1, 0, 1, 0, 0); reset();
  assert(proxy_send_local_response(&p, st, sizeof(st) - 1) == -1);
  assert(wrote_len == 0 && shuts == 1);
  /* bytes inside the answer are not a status line: they go out */
  p = client(1, 1, 1, 0, 0); reset();
  assert(proxy_send_local_response(&p, "data: [DONE]\n\n", 14) == 0);
  assert(has("data: [DONE]") && shuts == 0);
  /* the raw write: twin, TLS, begun */
  p = client(0, 0, 0, 0, 0); reset();
  assert(sp_raw_status_write(&p, st, sizeof(st) - 1, MSG_DONTWAIT | MSG_NOSIGNAL) == (ssize_t)(sizeof(st) - 1));
  assert(has("HTTP/1.1 502") && last_flags == (MSG_DONTWAIT | MSG_NOSIGNAL));
  p = client(0, 0, 0, 0, 1); reset();
  sp_raw_status_write(&p, st, sizeof(st) - 1, MSG_NOSIGNAL);
  assert(has("HTTP/1.1 502") && last_flags == -2);
  p = client(1, 1, 1, 0, 0); reset();
  assert(sp_raw_status_write(&p, st, sizeof(st) - 1, MSG_NOSIGNAL) == -1);
  assert(!has("HTTP/") && has("data: {\"error\":\"pd_decode_stream_timeout\"}") && shuts == 1);
  puts("senders: a status line goes out only before an answer begins; a begun stream ends in-band, anything else by the close PASS");
  return 0;
}
'''

reaper_prefix = common + r'''
enum { SP_REAP_NONE = 0, SP_REAP_SSE_CAP, SP_REAP_PD_PREFILL_TIMEOUT, SP_REAP_PD_DECODE_TIMEOUT,
  SP_REAP_PD_PARK_TIMEOUT, SP_REAP_PD_GRACEFUL_DONE, SP_REAP_PD_STREAM_TIMEOUT, SP_REAP_PD_IDLE_TIMEOUT,
  SP_REAP_FC_QUEUE_TIMEOUT, SP_REAP_FC_DRAINED, SP_REAP_EPP_TIMEOUT, SP_REAP_EPP_EVICT_429,
  SP_REAP_EPP_EVICT_CUT, SP_REAP_SSE_STALL, SP_REAP_FC_SHED,
  SP_REAP_FC_TTL, SP_REAP_KINDS };
static struct { void *ns; } proxy_struct_v = { (void *)1 }, *proxy_struct = &proxy_struct_v;
static struct { _Atomic unsigned long long reap_fallback; } global_stats;
static int owner = 1, ended, teardowns, recorded;
static int notify_owner_thr(void *ns, int fd) { (void)ns; (void)fd; return owner; }
static int notify_wake_worker(void *ns, int o, int fd) { (void)ns; (void)o; (void)fd; return -1; }
static void proxy_h2_client_end_mark(proxy_fd_ent_t *p, int a, int b, void *c) { (void)p; (void)a; (void)b; (void)c; }
#define SP_H2_END_REAPER 0
static void pd_teardown_conn(proxy_fd_ent_t *p) { (void)p; teardowns++; }
#define PROXY_LOCK() ((void)0)
#define PROXY_UNLOCK() ((void)0)
static ssize_t send(int fd, const void *b, size_t n, int flags) { (void)fd; (void)flags; take(b, n); return (ssize_t)n; }
static int shutdown(int fd, int how) { (void)fd; (void)how; shuts++; return 0; }
static size_t sp_reap_fc_format(proxy_fd_ent_t *p, uint8_t k, int keep, char *o, size_t c) { (void)p; (void)k; (void)keep; (void)o; (void)c; return 0; }
/* The plain texts go out as they are: the request ID the owner worker adds to a refusal is test_refusal_mark.c's. */
static size_t sp_reap_refusal_wire(proxy_fd_ent_t *p, uint8_t k, char *o, size_t c) { (void)p; (void)k; (void)o; (void)c; return 0; }
static void sp_reap_record(proxy_fd_ent_t *p, uint8_t k) { (void)p; (void)k; recorded++; }
static int proxy_send_local_response_and_shutdown(proxy_fd_ent_t *p, const void *b, size_t n) { (void)p; take(b, n); shuts++; return 0; }
int sp_answer_started(proxy_fd_ent_t *p) { return atomic_load(&p->cresp_in_msg) || atomic_load(&p->cresp_answer_open); }
void sp_end_started_answer(proxy_fd_ent_t *p, const void *b, size_t n) { (void)p; (void)b; (void)n; ended++; shuts++; }
'''
reaper_main = r'''
static proxy_fd_ent_t client(int begun) {
  proxy_fd_ent_t p; memset(&p, 0, sizeof(p)); p.fd = 9;
  atomic_store(&p.cresp_in_msg, begun); atomic_store(&p.cresp_answer_open, begun); p.cresp_sse.is_sse = begun; return p;
}
int main(void) {
  for (int k = 1; k < SP_REAP_KINDS; k++) {
    const sp_reap_text_t *t = &sp_reap_texts[k];
    proxy_fd_ent_t p;
    /* twin: before an answer begins, every kind writes its text */
    p = client(0); reset(); ended = 0; p.reap_resp = (uint8_t)k;
    sp_reap_finish(&p);
    assert(wrote_len == t->len && !memcmp(wrote, t->text, t->len) && ended == 0);
    /* begun: a whole response is never written into it; the reaper's SSE
     * events and the synthesised [DONE] still finish the stream in-band */
    p = client(1); reset(); ended = 0; p.reap_resp = (uint8_t)k;
    sp_reap_finish(&p);
    if (t->body) {
      assert(ended == 0 && wrote_len == t->len && !sp_answer_is_status_line(wrote, wrote_len));
    } else {
      assert(ended == 1 && wrote_len == 0);
    }
    /* the health thread's fallback (no owner to hand it to) */
    owner = -1;
    p = client(1); reset(); pd_reap_respond(&p, (uint8_t)k);
    assert(t->body ? (wrote_len == t->len) : (wrote_len == 0));
    assert(!has("HTTP/"));
    p = client(0); reset(); pd_reap_respond(&p, (uint8_t)k);
    assert(wrote_len == t->len);
    owner = 1;
  }
  puts("reaper: every kind writes its status line only before an answer begins; once begun it finishes a stream in-band or closes, on the owner worker and in the fallback PASS");
  return 0;
}
'''

def run(name, src):
    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        (p / 'test.c').write_text(src)
        cc = os.environ.get('CC', 'cc')
        subprocess.run([cc, '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                        '-Wno-missing-field-initializers',
                        '-I', str(root), '-o', str(p / name), str(p / 'test.c')], check=True)
        subprocess.run([str(p / name)], check=True)

run('senders', senders_prefix + senders + senders_main)
run('reaper', reaper_prefix + reaper + reaper_main)
