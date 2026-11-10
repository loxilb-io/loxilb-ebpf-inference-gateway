#!/usr/bin/env python3
"""Every reaper that ends an answer the client was already receiving leaves
exactly one request record (loxilb_ai_requests_total) with the status the
client received, 200, and how it ended (error_code, sockproxy_end_cause.h):
"" for the sweep's clean end (completed), the reaper's code for a cut
(aborted). A client that leaves with its answer open is client_abort; one
whose answer ended whole is "". A P/D client that leaves before any answer
(the prefill, or the decode leg's first byte still to come) is
client_abort_before_answer with status 0, none having been sent, and its P/D
lifecycle record is aborted (9): the two families stay 1:1. So is a P/D
request whose client left at the gate, queued or parked, on a kept
connection whatever phase the request before left. The rule's listener going
before any answer is listener_closed with status 0, the request record alone
on a P/D rule too (F-17: nothing in the product tears a listener down with
requests on it today, test_teardown_settle.c). A whole request on a rule that is
not P/D gets the request record alone (no lifecycle family pairs with it):
client_abort_before_answer when the client left, listener_closed when the
listener went, backend_died (cause engine) when the leg its answer was to
come on ended, status 0 each.

The production reaper writers run on the owner worker (sp_reap_finish and
sp_reap_record, sockproxy_health.c) with the production request recorders
(sockproxy_http.c), against a client whose 200 has gone out and whose record
is still owed (it waits for the [DONE] scanner or the usage object). Then the
connection ends the way that reaper kind ends it:
  - a teardown kind goes through pd_teardown_conn, which frees the client
    inline: proxy_pdestroy, and the record a teardown owes, never run there;
  - a shutdown kind (the SSE duration cap, the stalled client) is cleaned up
    by the event loop: proxy_pdestroy collects what the connection owes by
    the shared rule (sockproxy_teardown_settle.h) and writes it.
Both models are tied to the source below. The twin is the same reaper before
any answer began: its own status, once."""
from pathlib import Path
import os, re, subprocess, sys, tempfile
root = Path(__file__).resolve().parent
health = (root / 'sockproxy_health.c').read_text()
http = (root / 'sockproxy_http.c').read_text()
if os.environ.get('REAP_TEST_HEALTH'):
    health = Path(os.environ['REAP_TEST_HEALTH']).read_text()
if os.environ.get('REAP_TEST_HTTP'):
    http = Path(os.environ['REAP_TEST_HTTP']).read_text()

def body(src, start):
    i = src.index(start)
    return src[i:src.index('\n}\n', i) + 3]

# The teardown each kind gets is the model's only assumption; check it.
td = body(health, 'static int\npd_teardown_conn(')
assert 'proxy_try_free_fd_ctx(client);' in td, 'pd_teardown_conn no longer frees the client inline'
for rec in ('proxy_collect_conn_settles', 'llb_ai_record_request', 'proxy_ai_record_completion',
            'proxy_record_'):
    assert rec not in td, 'pd_teardown_conn now records (%s): update this model' % rec
pd = body(http, 'static void\nproxy_collect_conn_settles(')
assert 'u->owes_record  = teardown_owes_completion(&v);' in pd
assert re.search(r'if \(\(teardown_owes_completion\(&v\) \|\| teardown_owes_abort_record\(&v\) \|\|', pd), \
    'the teardown no longer collects a request its client left before any answer'
assert re.search(r'if \(teardown_owes_abort_record\(&v\) && sp_end_recorded_before_answer\(u->end\)\) \{\s*u->owes_record = 1;\s*\}', pd), \
    'the record of a request ended before any answer is no longer owed: update this model'
assert re.search(r'if \(u->owes_record && sp_end_client_left\(u->end\) &&\s*\(pd_reap_error_phase\(pfe->pd_phase\) >= 0 \|\|\s*'
                 r'\(u->end == SP_END_CLIENT_NO_ANSWER && pfe->pd_rule\)\)\) \{'
                 r'[\s\S]*?9 /\*aborted\*/\);\s*pfe->pd_phase = PD_PHASE_ERROR;', pd), \
    'the P/D client leaving records aborted (9) differently: update this model'
assert not re.search(r'u->end == SP_END_LISTENER_CLOSED[^{]*\{[\s\S]*?sp_pd_record\(', pd), \
    'the listener going now writes a P/D lifecycle record: update this model'
assert re.search(r'if \(u->owes_record\) \{\s*llb_ai_record_request\([^;]*\(char \*\)sp_end_code\(u->end\),', http), \
    'proxy_pdestroy no longer writes the record a teardown owes, with its end'
# The event loop's teardown reads the end as below (the model's teardown).
tde = re.search(r'u->end = (sp_end_cause_at_teardown\(\s*pfe->end_cause, shape == TEARDOWN_LISTENER,\s*'
                r'!pfe->h2_session &&\s*atomic_load_explicit\(&pfe->cresp_answer_open, memory_order_relaxed\),\s*'
                r'teardown_owes_abort_record\(&v\)\));', pd)
assert tde, 'the teardown reads the end differently: update this model'
# The view reads the gateway-ended holds by these values (stubbed below).
hcore = (root / 'sockproxy_hold_core.h').read_text()
hend = re.search(r'enum sp_hold_end \{([^}]*)\}', hcore).group(1)
hnames = [m.group(1) for m in re.finditer(r'(SP_HOLD_END_[A-Z_]+)', hend)]
assert hnames.index('SP_HOLD_END_EXPIRED') == 3 and hnames.index('SP_HOLD_END_RELEASED') == 4 \
    and 'SP_HOLD_END_NONE = 0' in hend, 'enum sp_hold_end moved: update the stub values'
# The passes name the shutdown kinds' cuts before handing them off.
for kind, cause in (('SP_REAP_SSE_CAP', 'SP_END_DURATION_CAP'), ('SP_REAP_SSE_STALL', 'SP_END_CLIENT_STALL')):
    i = health.index('pd_reap_respond(pfe, %s);' % kind)
    assert 'pfe->end_cause = %s;' % cause in health[i - 1500:i], kind

t0 = health.index('typedef struct sp_reap_text {')
t1 = health.index('\n};\n', health.index('[SP_REAP_SSE_STALL]', t0)) + 4
reaper = (health[t0:t1] + body(health, 'static int\nsp_reap_client_chunked(')
          + body(health, 'static size_t\nsp_reap_body_frame(')
          + body(health, 'static int\nsp_reap_end(')
          + body(health, 'static void\nsp_reap_record(')
          + body(health, 'void\nsp_reap_finish(proxy_fd_ent_t *pfe)'))
# Compile the named recorders independently of unrelated neighboring helpers.
pdleak = (root / 'sockproxy_pd_leak.h').read_text()
recorders = (body(pdleak, 'static inline int\npd_reap_error_phase(')
             + body(http, 'static int\nproxy_owes_completion(')
             + body(http, 'static void\nproxy_ai_record_completion_(')
             + body(http, 'static void\nproxy_ai_record_completion(')
             + body(http, 'void\nproxy_record_reaped_answer(')
             + body(http, 'void\nproxy_record_local_completion(')
             + body(http, 'static void\nproxy_teardown_view('))

prefix = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include "llhttp.h"
#include "sockproxy_teardown_settle.h"
#include "sockproxy_end_cause.h"
#define log_warn(...) ((void)0)
#define log_error(...) ((void)0)
#define log_debug(...) ((void)0)
#define PROXY_LOCK() ((void)0)
#define PROXY_UNLOCK() ((void)0)
#define AI_GW_STAGE_CAPACITY 3
#define AI_GW_CLASS_INFO(a,b,c,d) 0
enum { SP_HOLD_END_NONE = 0, SP_HOLD_END_EXPIRED = 3, SP_HOLD_END_RELEASED = 4 };
typedef struct proxy_fd_ent proxy_fd_ent_t;
struct proxy_fd_ent {
  int fd, odir, ai_gw_mode, metric_ai_recorded, metric_response_status, noted, fc;
  int usage_reserved_toks, usage_consumed, usage_prompt_toks, usage_complet_toks;
  int auth_src, adm_priority, adm_class_set, adm_class, adm_objective_denied, adm_hint_not_applied, pd_phase;
  uint8_t pd_rule, resp_kernel; _Atomic uint8_t hold_end;
  void *h2_session; uint8_t sse_active, reap_resp, end_cause; time_t stream_start_ts;
  _Atomic uint8_t cresp_in_msg, cresp_answer_open; llhttp_t cresp_parser;
  uint64_t metric_req_start_ns;
  char tenant_id[32], auth_user_id[32], auth_key_id[32], l7_peer_ip[32];
  char auth_net_identity[32], adm_objective[32], request_id[32], model[32];
};
enum { SP_REAP_NONE = 0, SP_REAP_SSE_CAP, SP_REAP_PD_PREFILL_TIMEOUT, SP_REAP_PD_DECODE_TIMEOUT,
  SP_REAP_PD_PARK_TIMEOUT, SP_REAP_PD_GRACEFUL_DONE, SP_REAP_PD_STREAM_TIMEOUT, SP_REAP_PD_IDLE_TIMEOUT,
  SP_REAP_FC_QUEUE_TIMEOUT, SP_REAP_FC_DRAINED, SP_REAP_EPP_TIMEOUT, SP_REAP_EPP_EVICT_429, SP_REAP_EPP_EVICT_CUT, SP_REAP_SSE_STALL, SP_REAP_FC_SHED,
  SP_REAP_FC_TTL, SP_REAP_KINDS };
static int records, record_status, record_stream, freed_inline, pd_aborted;
static char record_code[64];
static void capture(int status, int stream, const char *code) {
  records++; record_status = status; record_stream = stream; snprintf(record_code, sizeof(record_code), "%s", code); }
#define llb_ai_record_request(t,m,st,lat,ti,to,a,b,c,r,u,k,svc,stream,worker,peer,origin,hops,auth,net,prio,cls,obj) \
 ((void)(t),(void)(m),(void)(lat),(void)(ti),(void)(to),(void)(r),(void)(u),(void)(k),(void)(svc),(void)(worker), \
  (void)(peer),(void)(origin),(void)(hops),(void)(auth),(void)(net),(void)(prio),(void)(cls),(void)(obj),capture(st,stream,c))
static uint64_t get_timestamp_ns(void) { return 2000000; }
static const char *proxy_effective_model(proxy_fd_ent_t *p) { return p->model; }
static const char *proxy_request_id(proxy_fd_ent_t *p) { return p->request_id; }
static const char *proxy_origin_ip(proxy_fd_ent_t *p) { return p->l7_peer_ip; }
static int proxy_origin_trusted_hops(proxy_fd_ent_t *p) { (void)p; return 0; }
static int notify_worker_id(void) { return 2; }
static void proxy_pfe_svc_ident(proxy_fd_ent_t *p, char *s, size_t n) { (void)p; snprintf(s, n, "svc"); }
static void fc_permit_release(int *p) { *p = 0; }
/* The response record's latch, as the product keeps it: once per request,
 * client leg only, and it sets the status. */
static int proxy_note_local_answer(proxy_fd_ent_t *p, uint16_t s) {
  if (p->odir || p->noted) return 0;
  p->noted = 1; p->metric_response_status = s; return 1;
}
static int proxy_note_local_refusal(proxy_fd_ent_t *p, uint16_t s) {
  int n = proxy_note_local_answer(p, s); if (n) p->metric_ai_recorded = 1; return n;
}
static void proxy_record_local_deny(proxy_fd_ent_t *p, int st, int s, const char *c) { (void)p; (void)st; (void)s; (void)c; }
static size_t sp_reap_fc_format(proxy_fd_ent_t *p, uint8_t k, int keep, char *o, size_t c) { (void)p; (void)k; (void)keep; (void)o; (void)c; return 0; }
/* The plain texts go out as they are: the request ID the owner worker adds to a refusal is test_refusal_mark.c's. */
static size_t sp_reap_refusal_wire(proxy_fd_ent_t *p, uint8_t k, char *o, size_t c) { (void)p; (void)k; (void)o; (void)c; return 0; }
static int sp_answer_started(proxy_fd_ent_t *p) { return atomic_load(&p->cresp_in_msg) || atomic_load(&p->cresp_answer_open); }
static void sp_end_started_answer(proxy_fd_ent_t *p, const void *b, size_t n) { (void)p; (void)b; (void)n; }
static int proxy_send_local_response_and_shutdown(proxy_fd_ent_t *p, const void *b, size_t n) { (void)p; (void)b; (void)n; return 0; }
/* Frees the client inline: proxy_pdestroy never runs for it (checked above). */
static int pd_teardown_conn(proxy_fd_ent_t *p) { (void)p; freed_inline++; return 1; }
'''

main = r'''
static const char *kname(int k) {
  switch (k) {
  case SP_REAP_PD_GRACEFUL_DONE: return "graceful-[DONE] sweep";
  case SP_REAP_PD_STREAM_TIMEOUT: return "stream-silence (ERR-01)";
  case SP_REAP_PD_IDLE_TIMEOUT: return "generic idle reaper";
  case SP_REAP_SSE_CAP: return "duration cap";
  case SP_REAP_SSE_STALL: return "stalled client";
  case SP_REAP_NONE: return "the client leaving";
  default: return "?";
  }
}
static llhttp_settings_t cs;
static proxy_fd_ent_t client(int answered) {
  proxy_fd_ent_t c;
  memset(&c, 0, sizeof(c));
  c.fd = 9; c.ai_gw_mode = 1; c.fc = 1; c.metric_req_start_ns = 1000000;
  strcpy(c.tenant_id, "tenant-a"); strcpy(c.model, "model-a"); strcpy(c.request_id, "req-a");
  llhttp_settings_init(&cs);
  llhttp_init(&c.cresp_parser, HTTP_RESPONSE, &cs);
  if (answered) {
    /* the 200 went out; the record waits for the [DONE] scanner */
    static const char h[] = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n";
    assert(llhttp_execute(&c.cresp_parser, h, strlen(h)) == HPE_OK);
    c.noted = 1; c.metric_response_status = 200;
    atomic_store(&c.cresp_in_msg, 1); atomic_store(&c.cresp_answer_open, 1);
    c.stream_start_ts = 100;
  }
  return c;
}
/* The event loop's proxy_pdestroy: it settles what the connection owes, with
 * the end it reads (as the source reads it, checked above). */
static void event_loop_teardown_(proxy_fd_ent_t *c, int shape) {
  teardown_conn_t v;
  int owes, end;
  proxy_teardown_view(c, &v);
  if (!teardown_conn_owes_settle(shape, &v) ||
      !(teardown_owes_completion(&v) || teardown_owes_abort_record(&v)))
    return;
  owes = teardown_owes_completion(&v);
  end = sp_end_cause_at_teardown(c->end_cause, shape == TEARDOWN_LISTENER,
                                 !c->h2_session && atomic_load(&c->cresp_answer_open),
                                 teardown_owes_abort_record(&v));
  if (teardown_owes_abort_record(&v) && sp_end_recorded_before_answer(end)) owes = 1;
  c->metric_ai_recorded = 1;
  if (owes && sp_end_client_left(end) &&
      (pd_reap_error_phase(c->pd_phase) >= 0 || (end == SP_END_CLIENT_NO_ANSWER && c->pd_rule))) {
    pd_aborted++; c->pd_phase = 7;   /* aborted (9), then ERROR */
  }
  if (owes) capture(c->metric_response_status, 0, sp_end_code(end));
}
static void event_loop_teardown(proxy_fd_ent_t *c) { event_loop_teardown_(c, TEARDOWN_CONN); }
/* The reaper's hand-off on the owner worker, then the end of the connection.
 * SP_REAP_NONE: no reaper, the client leaves. */
static void reap(proxy_fd_ent_t *c, int k) {
  records = 0; freed_inline = 0; record_code[0] = 0; pd_aborted = 0;
  c->sse_active = 0;   /* every body kind's reaper ends the stream gauge first */
  if (k == SP_REAP_SSE_CAP) c->end_cause = SP_END_DURATION_CAP;    /* the pass names the cut */
  if (k == SP_REAP_SSE_STALL) c->end_cause = SP_END_CLIENT_STALL;
  if (k == SP_REAP_NONE) { event_loop_teardown(c); return; }
  c->reap_resp = (uint8_t)k;
  sp_reap_finish(c);
  if (!sp_reap_texts[k].teardown) {
    event_loop_teardown(c);   /* a shutdown: the event loop settles what is owed */
  } else {
    assert(freed_inline == 1);
  }
}
int main(void) {
  static const struct { int k; const char *code; } kinds[] = {
    { SP_REAP_PD_GRACEFUL_DONE, "" },
    { SP_REAP_PD_STREAM_TIMEOUT, "pd_decode_stream_timeout" },
    { SP_REAP_PD_IDLE_TIMEOUT, "pd_idle_timeout" },
    { SP_REAP_SSE_CAP, "max_stream_duration_exceeded" },
    { SP_REAP_SSE_STALL, "client_stall" },
    { SP_REAP_NONE, "client_abort" },
  };
  int bad = 0;
  for (unsigned i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) {
    int k = kinds[i].k;
    proxy_fd_ent_t c = client(1);
    reap(&c, k);
    if (records)
      printf("  after a 200: %-24s -> %d request record(s), status %d, error_code \"%s\" (%s)\n", kname(k),
             records, record_status, record_code, record_code[0] ? "aborted" : "completed");
    else
      printf("  after a 200: %-24s -> no request record\n", kname(k));
    if (records != 1 || record_status != 200 || strcmp(record_code, kinds[i].code) != 0) bad = 1;
  }
  /* The client leaves after its answer ended whole (the record still waited
   * for a usage object): completed, no end. */
  {
    proxy_fd_ent_t c = client(1);
    atomic_store(&c.cresp_in_msg, 0); atomic_store(&c.cresp_answer_open, 0);
    reap(&c, SP_REAP_NONE);
    printf("  answer whole, then the client leaves -> %d request record(s), status %d, error_code \"%s\"\n",
           records, record_status, record_code);
    if (records != 1 || record_status != 200 || record_code[0]) bad = 1;
  }
  /* The twins: the same reapers before any answer began write their own
   * status, once (the SSE kinds have no answer to end there). */
  {
    static const struct { int k, status; } twin[] = {
      { SP_REAP_PD_STREAM_TIMEOUT, 502 }, { SP_REAP_PD_IDLE_TIMEOUT, 504 },
    };
    for (unsigned i = 0; i < sizeof(twin) / sizeof(twin[0]); i++) {
      proxy_fd_ent_t c = client(0);
      reap(&c, twin[i].k);
      printf("  no answer yet: %-23s -> %d request record(s), status %d, error_code \"%s\"\n",
             kname(twin[i].k), records, record_status, record_code);
      if (records != 1 || record_status != twin[i].status || record_code[0]) bad = 1;
    }
  }
  /* A P/D client that leaves: before any answer (the prefill, the decode
   * leg's first byte still to come) its request record is status 0,
   * client_abort_before_answer, and its lifecycle record aborted (9); with
   * its answer open, client_abort and 9. One of each. A listener going before
   * any answer: listener_closed, status 0, and no lifecycle record. A
   * whole request on a rule that is not P/D, its client gone before any
   * answer: the request record alone, status 0, client_abort_before_answer;
   * listener_closed when the listener goes; nothing after the gateway ended
   * its hold; the
   * leg its answer was to come on ending (end named backend_died by the
   * leg's teardown): backend_died, status 0. A P/D rule's request at the
   * gate, queued or parked: both records, at any phase a kept connection
   * carries; one already recorded (a park timeout's 504): neither again. */
  {
    static const struct { const char *what; int pd_rule, pd_phase, answered, hold_end, end_cause, rec, shape, records, status, pd9; const char *code; } left[] = {
      { "P/D prefill, the client leaves", 1, 2, 0, 0, 0, 0, TEARDOWN_CONN, 1, 0, 1, "client_abort_before_answer" },
      { "P/D decode sent, no byte yet", 1, 4, 0, 0, 0, 0, TEARDOWN_CONN, 1, 0, 1, "client_abort_before_answer" },
      { "P/D answer open, the client leaves", 1, 5, 1, 0, 0, 0, TEARDOWN_CONN, 1, 200, 1, "client_abort" },
      { "P/D prefill, the listener goes", 1, 2, 0, 0, 0, 0, TEARDOWN_LISTENER, 1, 0, 0, "listener_closed" },
      { "P/D at the gate, the client leaves", 1, 0, 0, 0, 0, 0, TEARDOWN_CONN, 1, 0, 1, "client_abort_before_answer" },
      { "P/D parked, the client leaves", 1, 8, 0, 0, 0, 0, TEARDOWN_CONN, 1, 0, 1, "client_abort_before_answer" },
      { "P/D kept conn (old COMPLETE), leaves", 1, 6, 0, 0, 0, 0, TEARDOWN_CONN, 1, 0, 1, "client_abort_before_answer" },
      { "P/D kept conn (old ERROR), leaves", 1, 7, 0, 0, 0, 0, TEARDOWN_CONN, 1, 0, 1, "client_abort_before_answer" },
      { "P/D parked, the listener goes", 1, 8, 0, 0, 0, 0, TEARDOWN_LISTENER, 1, 0, 0, "listener_closed" },
      { "P/D answer open, the listener goes", 1, 5, 1, 0, 0, 0, TEARDOWN_LISTENER, 1, 200, 0, "listener_closed" },
      { "P/D park timeout recorded (504)", 1, 7, 0, 0, 0, 1, TEARDOWN_CONN, 0, 0, 0, "" },
      { "not P/D, the client leaves", 0, 0, 0, 0, 0, 0, TEARDOWN_CONN, 1, 0, 0, "client_abort_before_answer" },
      { "not P/D, answer open, client leaves", 0, 0, 1, 0, 0, 0, TEARDOWN_CONN, 1, 200, 0, "client_abort" },
      { "not P/D, the listener goes", 0, 0, 0, 0, 0, 0, TEARDOWN_LISTENER, 1, 0, 0, "listener_closed" },
      { "not P/D, hold expired", 0, 0, 0, SP_HOLD_END_EXPIRED, 0, 0, TEARDOWN_CONN, 0, 0, 0, "" },
      { "not P/D, hold released", 0, 0, 0, SP_HOLD_END_RELEASED, 0, 0, TEARDOWN_CONN, 0, 0, 0, "" },
      { "not P/D, the leg died before answer", 0, 0, 0, 0, SP_END_BACKEND_DIED, 0, TEARDOWN_CONN, 1, 0, 0, "backend_died" },
      { "not P/D, leg died, the listener goes", 0, 0, 0, 0, SP_END_BACKEND_DIED, 0, TEARDOWN_LISTENER, 1, 0, 0, "backend_died" },
    };
    for (unsigned i = 0; i < sizeof(left) / sizeof(left[0]); i++) {
      proxy_fd_ent_t c = client(left[i].answered);
      c.pd_rule = (uint8_t)left[i].pd_rule;
      c.pd_phase = left[i].pd_phase;
      c.end_cause = (uint8_t)left[i].end_cause;
      if (left[i].rec) { c.metric_ai_recorded = 1; c.noted = 1; c.metric_response_status = 504; }
      atomic_store(&c.hold_end, (uint8_t)left[i].hold_end);
      records = 0; record_status = 0; record_code[0] = 0; pd_aborted = 0;
      event_loop_teardown_(&c, left[i].shape);
      event_loop_teardown_(&c, left[i].shape);   /* a second walk owes nothing */
      printf("  %-36s -> %d request record(s), status %d, error_code \"%s\"; %d aborted (9)\n",
             left[i].what, records, record_status, record_code, pd_aborted);
      if (records != left[i].records || pd_aborted != left[i].pd9 ||
          (records && (record_status != left[i].status || strcmp(record_code, left[i].code) != 0)))
        bad = 1;
    }
  }
  /* A connection with no whole request (idle, or one still being read) owes
   * nothing, on any rule. */
  {
    proxy_fd_ent_t c = client(0);
    c.metric_req_start_ns = 0;
    records = 0; pd_aborted = 0;
    event_loop_teardown(&c);
    printf("  not P/D, no whole request, client leaves -> %d request record(s)\n", records);
    if (records != 0 || pd_aborted != 0) bad = 1;
  }
  /* A connection whose answers go by the kernel (sockmap response pairing):
   * no status reaches userspace, so an answered request reads as status 0.
   * Whether the client or the leg goes, nothing is recorded, as its answers
   * are not. */
  {
    static const int ends[] = { 0, SP_END_BACKEND_DIED };
    for (unsigned i = 0; i < sizeof(ends) / sizeof(ends[0]); i++) {
      proxy_fd_ent_t c = client(0);
      c.resp_kernel = 1;
      c.end_cause = (uint8_t)ends[i];
      records = 0; pd_aborted = 0;
      event_loop_teardown(&c);
      printf("  not P/D, answers by the kernel, %s -> %d request record(s)\n",
             ends[i] ? "leg ends" : "client leaves", records);
      if (records != 0 || pd_aborted != 0) bad = 1;
    }
  }
  /* The teardown's reading, case by case: a recorded end wins, an open answer
   * is the client leaving (the gateway when the whole listener goes), a
   * request the abort rule owes before any answer the client leaving before
   * it (the gateway when the listener goes), a whole one has no end. */
  if (sp_end_cause_at_teardown(SP_END_CLIENT_STALL, 0, 0, 0) != SP_END_CLIENT_STALL ||
      sp_end_cause_at_teardown(SP_END_BACKEND_DIED, 1, 1, 0) != SP_END_BACKEND_DIED ||
      sp_end_cause_at_teardown(SP_END_NONE, 0, 1, 0) != SP_END_CLIENT_GONE ||
      sp_end_cause_at_teardown(SP_END_NONE, 1, 1, 0) != SP_END_LISTENER_CLOSED ||
      sp_end_cause_at_teardown(SP_END_NONE, 1, 0, 0) != SP_END_NONE ||
      sp_end_cause_at_teardown(SP_END_NONE, 0, 0, 1) != SP_END_CLIENT_NO_ANSWER ||
      sp_end_cause_at_teardown(SP_END_NONE, 1, 0, 1) != SP_END_LISTENER_CLOSED ||
      !sp_end_recorded_before_answer(SP_END_LISTENER_CLOSED) ||
      sp_end_cause_at_teardown(SP_END_CAUSES, 0, 0, 0) != SP_END_NONE ||
      !sp_end_client_left(SP_END_CLIENT_NO_ANSWER) || !sp_end_client_left(SP_END_CLIENT_GONE) ||
      sp_end_client_left(SP_END_CLIENT_STALL) ||
      strcmp(sp_end_code(SP_END_LISTENER_CLOSED), "listener_closed") != 0 ||
      strcmp(sp_end_code(SP_END_CLIENT_NO_ANSWER), "client_abort_before_answer") != 0 ||
      strcmp(sp_end_codes[SP_END_CLIENT_NO_ANSWER].cause, "client") != 0 ||
      sp_end_code(SP_END_CAUSES)[0] != 0) {
    puts("FAIL: sp_end_cause_at_teardown / sp_end_code"); bad = 1;
  }
  if (bad) { puts("FAIL: a reaped answer has no request record, more than one, or the wrong end"); return 1; }
  puts("reaped answers: every reaper after a 200 leaves one request record, 200, named by its end (the sweep's clean end completed, a cut aborted); before an answer, its own status, once; a P/D client leaving at any stage (gate, queue, park included), one request record and one aborted (9); the listener going before any answer, listener_closed (status 0) and no lifecycle record; off P/D, before any answer, one request record (status 0): the client leaving, the listener going or the engine ending it PASS");
  return 0;
}
'''

with tempfile.TemporaryDirectory() as tdir:
    p = Path(tdir)
    (p / 'test.c').write_text(prefix + recorders + reaper + main)
    cc = os.environ.get('CC', 'cc')
    subprocess.run([cc, '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                    '-Wno-unused-parameter', '-Wno-missing-field-initializers',
                    '-fsanitize=address,undefined',
                    '-I', str(root), '-o', str(p / 'rec'), str(p / 'test.c'),
                    str(root / 'llhttp.c'), str(root / 'http.c'), str(root / 'httpapi.c')],
                   check=True)
    sys.exit(subprocess.run([str(p / 'rec')]).returncode)
