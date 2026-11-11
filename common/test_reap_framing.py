#!/usr/bin/env python3
"""Run the reaper's production writers against P/D-shaped clients: the bytes a
body kind (the synthesised [DONE], the SSE cap and stall events) is written as
follow the answer the client is being sent, never a backend leg. A chunked
answer gets a chunk-framed event and the 0-chunk, and the real HTTP_RESPONSE
framer, fed the answer's head, a content chunk and those bytes, ends the
message with [DONE] as its last decoded event: the client's read ends cleanly.
The legs are laid out as P/D lays them out (prefill in slot 0, gone or not
chunked; decode in slot 1, chunked), so a decision read off slot 0 fails here.
The twin is a client whose answer is not chunked while a leg is: the text goes
out as it is."""
from pathlib import Path
import os, subprocess, tempfile
root = Path(__file__).resolve().parent
health = (root / 'sockproxy_health.c').read_text()
if os.environ.get('ANSWER_TEST_HEALTH'):
    health = Path(os.environ['ANSWER_TEST_HEALTH']).read_text()

t0 = health.index('typedef struct sp_reap_text {')
t1 = health.index('\n};\n', health.index('[SP_REAP_SSE_STALL]', t0)) + 4
c0 = health.index('static int\nsp_reap_client_chunked(')
c1 = health.index('\n}\n', c0) + 3
b0 = health.index('static size_t\nsp_reap_body_frame(')
b1 = health.index('\n}\n', b0) + 3
r0 = health.index('static void\npd_reap_respond(')
r1 = health.index('\nvoid\nsp_reap_request(', r0)
f0 = health.index('void\nsp_reap_finish(proxy_fd_ent_t *pfe)')
f1 = health.index('\n}\n', f0) + 3
reaper = health[t0:t1] + health[c0:c1] + health[b0:b1] + health[r0:r1] + health[f0:f1]

prefix = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include "llhttp.h"
#define MSG_DONTWAIT 0x40
#define MSG_NOSIGNAL 0x4000
#define SHUT_RDWR 2
#define log_warn(...) ((void)0)
#define log_error(...) ((void)0)
#define log_debug(...) ((void)0)
typedef struct proxy_fd_ent proxy_fd_ent_t;
struct proxy_fd_ent {
  int fd; void *ssl; _Atomic uint8_t cresp_in_msg, cresp_answer_open;
  llhttp_t cresp_parser;
  uint8_t reap_resp, read_paused, is_chunked_response; int n_rfd; proxy_fd_ent_t *rfd_ent[2];
};
enum { SP_REAP_NONE = 0, SP_REAP_SSE_CAP, SP_REAP_PD_PREFILL_TIMEOUT, SP_REAP_PD_DECODE_TIMEOUT,
  SP_REAP_PD_PARK_TIMEOUT, SP_REAP_PD_GRACEFUL_DONE, SP_REAP_PD_STREAM_TIMEOUT, SP_REAP_PD_IDLE_TIMEOUT,
  SP_REAP_FC_QUEUE_TIMEOUT, SP_REAP_FC_DRAINED, SP_REAP_EPP_TIMEOUT, SP_REAP_EPP_EVICT_429, SP_REAP_EPP_EVICT_CUT, SP_REAP_SSE_STALL, SP_REAP_FC_SHED,
  SP_REAP_FC_TTL, SP_REAP_KINDS };
static char wrote[1024]; static size_t wrote_len;
static void take(const void *b, size_t n) { memcpy(wrote + wrote_len, b, n); wrote_len += n; }
static struct { void *ns; } proxy_struct_v = { (void *)1 }, *proxy_struct = &proxy_struct_v;
static int owner = 1;
static int notify_owner_thr(void *ns, int fd) { (void)ns; (void)fd; return owner; }
static int notify_wake_worker(void *ns, int o, int fd) { (void)ns; (void)o; (void)fd; return -1; }
static void proxy_h2_client_end_mark(proxy_fd_ent_t *p, int a, int b, void *c) { (void)p; (void)a; (void)b; (void)c; }
#define SP_H2_END_REAPER 0
static void pd_teardown_conn(proxy_fd_ent_t *p) { (void)p; }
static struct { _Atomic unsigned long long reap_fallback; } global_stats;
#define PROXY_LOCK() ((void)0)
#define PROXY_UNLOCK() ((void)0)
static ssize_t send(int fd, const void *b, size_t n, int flags) { (void)fd; (void)flags; take(b, n); return (ssize_t)n; }
static int shutdown(int fd, int how) { (void)fd; (void)how; return 0; }
static size_t sp_reap_fc_format(proxy_fd_ent_t *p, uint8_t k, int keep, char *o, size_t c) { (void)p; (void)k; (void)keep; (void)o; (void)c; return 0; }
/* The plain texts go out as they are: the request ID the owner worker adds to a refusal is test_refusal_mark.c's. */
static size_t sp_reap_refusal_wire(proxy_fd_ent_t *p, uint8_t k, char *o, size_t c) { (void)p; (void)k; (void)o; (void)c; return 0; }
static void sp_reap_record(proxy_fd_ent_t *p, uint8_t k) { (void)p; (void)k; }
static int proxy_send_local_response_and_shutdown(proxy_fd_ent_t *p, const void *b, size_t n) { (void)p; take(b, n); return 0; }
static int sp_answer_started(proxy_fd_ent_t *p) { return atomic_load(&p->cresp_in_msg) || atomic_load(&p->cresp_answer_open); }
static void sp_end_started_answer(proxy_fd_ent_t *p, const void *b, size_t n) { (void)p; (void)b; (void)n; }
'''

main = r'''
/* The client's view: the answer's head and one content chunk relayed from the
 * decode engine, then what the reaper wrote. */
static const char head_chunked[] =
  "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n";
static const char head_eof[] =
  "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n";
static const char chunk1[] = "f\r\ndata: {\"a\":1}\n\n\r\n";
static const char event1[] = "data: {\"a\":1}\n\n";

static llhttp_settings_t cs;
typedef struct { char body[1024]; size_t n; int done; } dec_t;
static int on_body(llhttp_t *p, const char *at, size_t n) { dec_t *d = p->data; memcpy(d->body + d->n, at, n); d->n += n; return 0; }
static int on_done(llhttp_t *p) { ((dec_t *)p->data)->done++; return 0; }

/* A client inside its answer: the real framer has read the head (and, chunked,
 * one chunk), so its parser flags are the client's framing. */
static void client(proxy_fd_ent_t *c, int chunked, dec_t *d) {
  memset(c, 0, sizeof(*c)); memset(d, 0, sizeof(*d)); c->fd = 9;
  llhttp_settings_init(&cs); cs.on_body = on_body; cs.on_message_complete = on_done;
  llhttp_init(&c->cresp_parser, HTTP_RESPONSE, &cs); c->cresp_parser.data = d;
  const char *h = chunked ? head_chunked : head_eof;
  assert(llhttp_execute(&c->cresp_parser, h, strlen(h)) == HPE_OK);
  if (chunked) assert(llhttp_execute(&c->cresp_parser, chunk1, strlen(chunk1)) == HPE_OK);
  else assert(llhttp_execute(&c->cresp_parser, event1, strlen(event1)) == HPE_OK);
  atomic_store(&c->cresp_in_msg, 1); atomic_store(&c->cresp_answer_open, 1);
}
/* P/D legs: prefill in slot 0 (unlinked, or kept alive and not chunked),
 * decode in slot 1 with a chunked response. */
static proxy_fd_ent_t prefill, decode;
static void pd_legs(proxy_fd_ent_t *c, int prefill_gone) {
  memset(&prefill, 0, sizeof(prefill)); memset(&decode, 0, sizeof(decode));
  decode.is_chunked_response = 1;
  c->rfd_ent[0] = prefill_gone ? NULL : &prefill; c->rfd_ent[1] = &decode;
  c->n_rfd = prefill_gone ? 1 : 2;
}
static void finish(proxy_fd_ent_t *c, int k) {
  wrote_len = 0;
  if (owner >= 0) { c->reap_resp = (uint8_t)k; sp_reap_finish(c); }
  else pd_reap_respond(c, (uint8_t)k);
}

int main(void) {
  static const int body_kinds[] = { SP_REAP_PD_GRACEFUL_DONE, SP_REAP_SSE_CAP, SP_REAP_SSE_STALL };
  for (int path = 0; path < 2; path++) {            /* owner worker, health-thread fallback */
    owner = path == 0 ? 1 : -1;
    for (int gone = 0; gone < 2; gone++) {
      for (unsigned i = 0; i < sizeof(body_kinds) / sizeof(body_kinds[0]); i++) {
        int k = body_kinds[i];
        const sp_reap_text_t *t = &sp_reap_texts[k];
        proxy_fd_ent_t c; dec_t d;
        /* chunked answer: the event is the last chunk, then the 0-chunk; the
         * framer decodes it and ends the message */
        client(&c, 1, &d); pd_legs(&c, gone);
        finish(&c, k);
        char want[256];
        int wn = snprintf(want, sizeof(want), "%zx\r\n%s\r\n0\r\n\r\n", t->len, t->text);
        assert(wrote_len == (size_t)wn && !memcmp(wrote, want, wrote_len));
        assert(llhttp_execute(&c.cresp_parser, wrote, wrote_len) == HPE_OK);
        assert(d.done == 1);
        assert(d.n >= t->len && !memcmp(d.body + d.n - t->len, t->text, t->len));
        /* twin: the answer is not chunked though a leg is: the text as it is */
        client(&c, 0, &d); pd_legs(&c, gone);
        finish(&c, k);
        assert(wrote_len == t->len && !memcmp(wrote, t->text, t->len));
      }
    }
  }
  /* The flag the old decision read: a non-P/D client whose only leg is
   * chunked, but whose answer has ended (a kept connection between answers),
   * gets no frame: there is no chunked answer to frame into. */
  {
    proxy_fd_ent_t c; dec_t d; owner = 1;
    client(&c, 1, &d); pd_legs(&c, 1);
    atomic_store(&c.cresp_answer_open, 0);
    finish(&c, SP_REAP_PD_GRACEFUL_DONE);
    assert(wrote_len == sp_reap_texts[SP_REAP_PD_GRACEFUL_DONE].len);
  }
  puts("reaper framing: a body kind into a chunked answer is chunk-framed with the 0-chunk and ends the client's message, whatever the P/D legs hold; a non-chunked answer gets the text as it is; on the owner worker and in the fallback PASS");
  return 0;
}
'''

with tempfile.TemporaryDirectory() as td:
    p = Path(td)
    (p / 'test.c').write_text(prefix + reaper + main)
    cc = os.environ.get('CC', 'cc')
    subprocess.run([cc, '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                    '-Wno-unused-parameter', '-Wno-missing-field-initializers',
                    '-fsanitize=address,undefined',
                    '-I', str(root), '-o', str(p / 'framing'), str(p / 'test.c'),
                    str(root / 'llhttp.c'), str(root / 'http.c'), str(root / 'httpapi.c')],
                   check=True)
    subprocess.run([str(p / 'framing')], check=True)
