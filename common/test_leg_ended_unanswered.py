#!/usr/bin/env python3
"""A backend leg that goes away under the whole HTTP/1.1 request it was to
answer, before any answer, on an AI-gateway rule that is not P/D: the client
gets the 502 a refused connect gives it, once, and the request is recorded by
proxy_send_backend_unreachable_forwarded (completed, 502, named by the ID the
request was forwarded under), as the TLS leg's failure is.
Without it the client got the bare close (F-18).

Nothing is sent, and the teardown's rule decides the record, when:
  - the connection's answers go by the kernel (no status is seen, the answer
    may be out);
  - the rule is P/D, or a P/D request is in flight (the P/D paths answer
    with their own status), or the client is HTTP/2 (its streams are
    answered in proxy_h2_backend_leg_end);
  - the leg is an SGLang drain leg, whose bytes never reach the client;
  - no whole request reached the gate, an answer already began, a status or
    a record already accounts for the request, or a reaper or stall named
    the end;
  - the rule is not AI-gateway, or the client has no socket.
A TLS client is also told the stream ended (SSL_shutdown).

The production function runs against stubs; proxy_pdestroy is checked to
call it with nothing held, before it takes PROXY_LOCK."""
from pathlib import Path
import os, re, subprocess, sys, tempfile
root = Path(__file__).resolve().parent
http = (root / 'sockproxy_http.c').read_text()
if os.environ.get('LEG_TEST_HTTP'):
    http = Path(os.environ['LEG_TEST_HTTP']).read_text()

def body(src, start):
    i = src.index(start)
    return src[i:src.index('\n}\n', i) + 3]

fn = body(http, 'static void\nproxy_backend_leg_ended_unanswered(')
pd = body(http, 'void\nproxy_pdestroy(')
call = pd.find('  proxy_backend_leg_ended_unanswered(pfe);\n')
lock = pd.find('  PROXY_LOCK();\n')
assert call >= 0, 'proxy_pdestroy no longer answers an HTTP/1.1 leg ending before any answer'
assert lock >= 0 and call < lock, 'proxy_pdestroy answers the leg after taking PROXY_LOCK'
assert pd.find('  proxy_h2_backend_leg_end(pfe);\n') < call, \
    'proxy_pdestroy answers the HTTP/1.1 leg before the HTTP/2 leg end'

prefix = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define INET_ADDRSTRLEN 16
#define PD_PHASE_NONE 0
typedef struct proxy_fd_ent {
  int odir, fd, n_rfd, pd_phase;
  uint8_t pd_sg_drain, ai_gw_mode, pd_rule, resp_kernel, metric_ai_recorded, end_cause;
  uint16_t metric_response_status;
  uint64_t metric_req_start_ns;
  void *h2_session, *ssl;
  int started, locked;
  struct proxy_fd_ent *rfd_ent[2];
} proxy_fd_ent_t;
static int sent, shut, named, locks;
#define PROXY_ENT_LOCK(p) do { assert(!(p)->locked); (p)->locked = 1; locks++; } while (0)
#define PROXY_ENT_UNLOCK(p) do { assert((p)->locked); (p)->locked = 0; } while (0)
#define log_error(...) ((void)0)
static int sp_answer_started(proxy_fd_ent_t *p) { return p->started; }
static void proxy_backend_leg_name(proxy_fd_ent_t *l, proxy_fd_ent_t *c, char *o, size_t n) {
  (void)l; (void)c; snprintf(o, n, "10.0.0.2:8000"); named++;
}
/* The product's sender for a request already forwarded, as
 * test_backend_failure_audit.py runs it: the 502 is written with the ID the
 * request was forwarded under, the status latched and the request recorded
 * completed. Called with the client's lock held. */
static int proxy_send_backend_unreachable_forwarded(proxy_fd_ent_t *p, const char *d) {
  (void)d; assert(p->locked); assert(p->odir == 0);
  sent++; p->metric_response_status = 502; p->metric_ai_recorded = 1; return 0;
}
static void cresp_note_local_answer(proxy_fd_ent_t *p) { p->started = 1; }
static int SSL_shutdown(void *s) { (void)s; shut++; return 0; }
'''
test = r'''
static proxy_fd_ent_t cl, leg;
static void reset(void) {
  memset(&cl, 0, sizeof(cl)); memset(&leg, 0, sizeof(leg));
  cl.odir = 0; cl.fd = 7; cl.ai_gw_mode = 1; cl.metric_req_start_ns = 100;
  leg.odir = 1; leg.fd = 8; leg.n_rfd = 1; leg.rfd_ent[0] = &cl;
  sent = shut = named = locks = 0;
}
#define NONE(what, setup) do { reset(); setup; proxy_backend_leg_ended_unanswered(&leg); \
  printf("  %-44s -> %d 502(s)\n", what, sent); if (sent != 0) bad = 1; } while (0)
int main(void) {
  int bad = 0;
  reset();
  proxy_backend_leg_ended_unanswered(&leg);
  printf("  %-44s -> %d 502(s), status %d, recorded %d\n", "not P/D, the leg ends before any answer",
         sent, cl.metric_response_status, cl.metric_ai_recorded);
  if (sent != 1 || cl.metric_response_status != 502 || !cl.metric_ai_recorded || !cl.started ||
      shut != 0 || cl.locked || named != 1) bad = 1;
  proxy_backend_leg_ended_unanswered(&leg);   /* a second end owes nothing */
  printf("  %-44s -> %d 502(s)\n", "the same leg's end seen again", sent);
  if (sent != 1) bad = 1;
  reset(); cl.ssl = (void *)1;
  proxy_backend_leg_ended_unanswered(&leg);
  printf("  %-44s -> %d 502(s), %d TLS shutdown\n", "a TLS client", sent, shut);
  if (sent != 1 || shut != 1) bad = 1;
  NONE("answers by the kernel", cl.resp_kernel = 1);
  NONE("P/D rule", cl.pd_rule = 1);
  NONE("P/D request in flight", cl.pd_phase = 2);
  NONE("HTTP/2 client", cl.h2_session = (void *)1);
  NONE("SGLang drain leg", leg.pd_sg_drain = 1);
  NONE("no whole request", cl.metric_req_start_ns = 0);
  NONE("answer begun", cl.started = 1);
  NONE("a status already sent", cl.metric_response_status = 200);
  NONE("already recorded", cl.metric_ai_recorded = 1);
  NONE("a reaper named the end", cl.end_cause = 6);
  NONE("not AI gateway", cl.ai_gw_mode = 0);
  NONE("client has no socket", cl.fd = -1);
  NONE("client leg unlinked", leg.n_rfd = 0);
  NONE("called on a client entry", leg.odir = 0);
  printf(bad ? "FAILED\n" : "test_leg_ended_unanswered: ok\n");
  return bad;
}
'''
with tempfile.TemporaryDirectory() as d:
    src = Path(d) / 'test.c'
    src.write_text(prefix + fn + test)
    cc = os.environ.get('CC', 'cc')
    subprocess.run([cc, '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                    '-Wno-unused-parameter', '-fsanitize=address,undefined',
                    '-o', str(Path(d) / 't'), str(src)], check=True)
    r = subprocess.run([str(Path(d) / 't')])
    sys.exit(r.returncode)
