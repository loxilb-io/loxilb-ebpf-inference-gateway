/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_h2_radix.c - non-P/D prefix routing on HTTP/2 streams.
 *
 * Drives the REAL HTTP/2 forward and response relay (sockproxy_h2.c, ASan)
 * over the shared fixture (test_h2_fixture.h) with a real radix pool state
 * (sockproxy_radix_route.c, the trie and the scanner):
 *   off   a pool without radix state routes exactly as before: no
 *         eligibility read, no per-stream state, nothing counted;
 *   E2/5  a chat request routed by the selector learns its prefix on the
 *         2xx of the endpoint it reached; the next request with the prefix
 *         goes there (HIT), the selector's pick notwithstanding; a non-2xx
 *         learns nothing;
 *   E1/7  a request that is not a chat completion (NOT_CHAT), a body that
 *         is not JSON (NO_BODY), a HEADERS-only request (NO_BODY), a body
 *         above the inspection limit (INSPECT_SIZE), a pool not in AI
 *         gateway mode (AI_GW_OFF): the selector's pick, no per-stream
 *         state allocated;
 *   E3    a stream carrying x-conversation-id is pinned: never scanned;
 *   E6    on a bounded-load pool the stream mapping's unit sits on the
 *         radix endpoint while the stream is open, and every unit is back
 *         to zero after it, never below;
 *   B     a stream forwarded a second time (its first forward failed after
 *         the decision) is counted once;
 *   E10   the per-stream state is freed with the stream: normal end, a
 *         client reset before the answer, teardown with a stream open
 *         (LeakSanitizer at exit).
 * The predicate sp_is_chat_path is checked on its own first.
 *
 * Build: make test_h2radix (ASan + UBSan, the gateway object included).
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_h2_fixture.h"
#include "sockproxy_fc.h"
#include "sockproxy_lb.h"
#include "sockproxy_json.h"
#include "sockproxy_radix_route.h"

#define NV(n, v) { (uint8_t *)(n), (uint8_t *)(v), sizeof(n) - 1, sizeof(v) - 1, NGHTTP2_NV_FLAG_NONE }
#define CHAT "/v1/chat/completions"
#define JSON "application/json"

/* ---- working fakes for the paths these cases take (the fixture's
 * stand-ins are weak) ---- */

/* The breaker: every endpoint a candidate; the calls are counted. */
static int cb_calls;
int
circuit_breaker_candidate(proxy_epval_t *pool, int ep)
{
  (void)pool; (void)ep;
  cb_calls++;
  return 1;
}

/* The capacity gate's eligibility: every endpoint. */
int sp_fc_normal_eligible(void *ctx, int ep) { (void)ctx; (void)ep; return 1; }

/* The JSON pre-scan: the request names model "m" and no cache_salt. */
void sp_json_scan_init(sp_json_scan_t *scan) { memset(scan, 0, sizeof(*scan)); }
int
sp_json_scan_feed(sp_json_scan_t *scan, const char *data, size_t len)
{
  (void)data; (void)len;
  snprintf(scan->model, sizeof(scan->model), "m");
  scan->model_seen = scan->model_ready = 1;
  return 0;
}
int sp_json_scan_finish(sp_json_scan_t *scan) { (void)scan; return 0; }

/* The conversation table: empty, stores counted. */
static int conv_lookups, conv_stores;
conversation_mapping_t *
get_conversation_mapping(proxy_map_ent_t *ent, const char *conv_id, const proxy_epval_t *pool)
{
  (void)ent; (void)conv_id; (void)pool;
  conv_lookups++;
  return NULL;
}
int
store_conversation_endpoint(proxy_map_ent_t *ent, const char *conv_id, int ep_idx,
                            const proxy_epval_t *pool)
{
  (void)ent; (void)conv_id; (void)ep_idx; (void)pool;
  conv_stores++;
  return 0;
}

/* Bounded-load units per endpoint, and the lowest any ever reached. */
static int units[MAX_PROXY_EP], units_min;
void
chwbl_inc_runtime(proxy_epval_t *epv, int ep_idx)
{
  (void)epv;
  units[ep_idx]++;
}
void
chwbl_dec_runtime(proxy_epval_t *epv, int ep_idx)
{
  (void)epv;
  if (--units[ep_idx] < units_min)
    units_min = units[ep_idx];
}
int
extract_llm_prefix_scanned(const char *body, size_t len, const sp_json_scan_t *scan,
                           llm_prefix_key_t *pk)
{
  (void)body; (void)len; (void)scan; (void)pk;
  return -1;    /* no CHWBL prefix: the hook below picks */
}
uint64_t compute_prefix_hash(llm_prefix_key_t *pk) { (void)pk; return 0; }

/* The CHWBL selector: the endpoint the test names, its unit taken the way
 * the real selector takes it. */
static int chwbl_pick;
static int
chwbl(proxy_epval_t *epv, llm_prefix_key_t *key, int *ep)
{
  (void)key;
  *ep = chwbl_pick;
  chwbl_inc_runtime(epv, chwbl_pick);
  return 0;
}

/* ---- helpers ---- */

#define BODY_CAP (900 * 1024)
static char body[BODY_CAP];

/* {"model":"m","messages":[{"role":"system","content":S},{"role":"user","content":U}]} */
static size_t
chat_body(char sys_ch, size_t sys_len, char user_ch, size_t user_len)
{
  size_t n = 0;
  n += (size_t)sprintf(body + n, "{\"model\":\"m\",\"messages\":[{\"role\":\"system\",\"content\":\"");
  memset(body + n, sys_ch, sys_len); n += sys_len;
  n += (size_t)sprintf(body + n, "\"},{\"role\":\"user\",\"content\":\"");
  memset(body + n, user_ch, user_len); n += user_len;
  n += (size_t)sprintf(body + n, "\"}]}");
  return n;
}

static proxy_epval_t *
pool_new(const char *key, int n, int ai_gw, int with_radix)
{
  proxy_epval_t *p = h2fx_pool(key, n);
  fc_cfg_t cfg = { 0 };

  p->ai_gw_mode = ai_gw ? 1 : 0;
  pthread_mutex_init(&p->fc.queue.lock, NULL);
  cfg.mode = FC_MODE_OBSERVE;
  fc_state_apply(&p->fc, &cfg);
  if (with_radix)
    p->radix = radix_pool_create(NULL);
  return p;
}

/* A reason's count in the pool's counters line. */
static unsigned long
cnt(proxy_epval_t *p, const char *name)
{
  char line[1024], pat[64];
  const char *at;
  size_t nl;

  if (!p->radix)
    return 0;
  radix_pool_stats_format(p->radix, line, sizeof(line));
  nl = (size_t)snprintf(pat, sizeof(pat), "%s=", name);
  for (at = line; (at = strstr(at, pat)); at += nl)
    if (at == line || at[-1] == ' ')
      return strtoul(at + nl, NULL, 10);
  return 0;
}

/* The endpoint client stream id was forwarded to, and its backend. */
static int
routed(int32_t id, int *be)
{
  for (int i = 0; i < h2fx_n_be; i++) {
    stream_mapping_t *m = h2fx_mapping(i, id);
    if (m) {
      if (be)
        *be = i;
      return m->ep_idx;
    }
  }
  return -1;
}

/* Backend be answers client stream id with status (no body). */
static void
answer(int be, int32_t id, const char *status)
{
  nghttp2_nv nv[] = { { (uint8_t *)":status", (uint8_t *)status, 7, 3, 0 },
                      NV("content-length", "0") };
  stream_mapping_t *m = h2fx_mapping(be, id);

  assert(m);
  assert(nghttp2_submit_response(h2fx_be[be].srv, m->backend_stream_id, nv, 2, NULL) == 0);
  (void)h2fx_be_send(be);
}

/* One request forwarded: its endpoint (-1 when it was not forwarded). */
static int
send_one(const char *path, const char *ctype, const char *conv, size_t len,
         int32_t *idp, int *bep)
{
  int32_t id = h2fx_submit_req(path, ctype, conv, "m", (const uint8_t *)body, len);
  int ep, rc = 0;

  /* a body above the stream window takes several reads (window updates) */
  for (int i = 0; i < 64 && !rc; i++) {
    rc = h2fx_gw_read();
    if (routed(id, NULL) >= 0 || h2fx_status[id / 2] || !h2fx_stream(id))
      break;
  }
  CHECK(rc == 0, "stream %d is read", id);
  ep = routed(id, bep);
  if (idp)
    *idp = id;
  return ep;
}

/* ---- the predicate ---- */

static void
chat_predicate(void)
{
  CHECK(sp_is_chat_path("/v1/chat/completions") == 1, "chat path");
  CHECK(sp_is_chat_path("/v1/chat/completions?x=1") == 1, "chat path with a query");
  CHECK(sp_is_chat_path("/v1/chat/completions/") == 0, "a trailing slash is not it");
  CHECK(sp_is_chat_path("/v1/chat/completionsX") == 0, "a longer path is not it");
  CHECK(sp_is_chat_path("/v1/completions") == 0, "completions is not chat");
  CHECK(sp_is_chat_path("/V1/chat/completions") == 0, "the match is exact");
  CHECK(sp_is_chat_path("") == 0, "an empty path is not chat");
}

/* ---- off: no radix state on the pool ---- */

static void
off_unchanged(void)
{
  proxy_epval_t *p = pool_new("off", 3, 1, 0);
  int32_t id[3];
  int ep[3], be[3], c0 = cb_calls;
  size_t len = chat_body('x', 600, 'a', 300);

  h2fx_lpm = p;
  for (int i = 0; i < 3; i++) {
    ep[i] = send_one(CHAT, JSON, NULL, len, &id[i], &be[i]);
    CHECK(ep[i] >= 0, "off: stream %d forwarded to ep %d", id[i], ep[i]);
    CHECK(h2fx_stream(id[i]) && h2fx_stream(id[i])->radix_req == NULL,
          "off: no per-stream radix state");
  }
  CHECK(ep[1] == (ep[0] + 1) % 3 && ep[2] == (ep[0] + 2) % 3,
        "off: the round robin's order (%d %d %d)", ep[0], ep[1], ep[2]);
  CHECK(cb_calls == c0, "off: no eligibility read (breaker calls %d)", cb_calls - c0);
  for (int i = 0; i < 3; i++)
    if (ep[i] >= 0)
      answer(be[i], id[i], "200");
  CHECK(h2fx_status[id[0] / 2] == 200 && h2fx_status[id[2] / 2] == 200, "off: answered");
}

/* ---- on ---- */

static void
on_learn_and_hit(proxy_epval_t *p)
{
  size_t len = chat_body('x', 600, 'a', 300);
  int32_t id1, id2, id3;
  int be1, be2, be3, ep1, ep2, ep3;
  unsigned long miss0 = cnt(p, "miss"), hit0 = cnt(p, "hit"), ok0 = cnt(p, "learn.ok");

  ep1 = send_one(CHAT, JSON, NULL, len, &id1, &be1);
  CHECK(ep1 >= 0, "E2: the first request goes to the selector's pick (ep %d)", ep1);
  CHECK(cnt(p, "miss") == miss0 + 1, "E2: counted a miss (%lu)", cnt(p, "miss") - miss0);
  CHECK(h2fx_stream(id1) && h2fx_stream(id1)->radix_req != NULL,
        "E10: the open stream holds its radix state");
  if (ep1 < 0)
    return;
  answer(be1, id1, "200");
  CHECK(cnt(p, "learn.ok") == ok0 + 1, "E5: learned on the 2xx (%lu)", cnt(p, "learn.ok") - ok0);

  /* the same prefix, a different question: radix over the round robin */
  len = chat_body('x', 600, 'b', 280);
  ep2 = send_one(CHAT, JSON, NULL, len, &id2, &be2);
  CHECK(ep2 == ep1, "E2: the next request with the prefix goes to ep %d (got %d)", ep1, ep2);
  CHECK(cnt(p, "hit") == hit0 + 1, "E2: counted a hit (%lu)", cnt(p, "hit") - hit0);
  if (ep2 >= 0)
    answer(be2, id2, "200");

  /* a non-2xx learns nothing */
  ok0 = cnt(p, "learn.ok");
  miss0 = cnt(p, "miss");
  len = chat_body('y', 600, 'a', 300);
  ep3 = send_one(CHAT, JSON, NULL, len, &id3, &be3);
  if (ep3 >= 0)
    answer(be3, id3, "500");
  CHECK(cnt(p, "learn.ok") == ok0, "E5: a 500 learns nothing");
  ep3 = send_one(CHAT, JSON, NULL, len, &id3, &be3);
  CHECK(cnt(p, "miss") == miss0 + 2, "E5: the prefix still misses (%lu)", cnt(p, "miss") - miss0);
  if (ep3 >= 0)
    answer(be3, id3, "200");
}

/* The selector's pick, no state: one gated request. */
static void
gated(proxy_epval_t *p, const char *what, const char *reason, const char *path,
      const char *ctype, const char *conv, size_t len)
{
  unsigned long r0 = cnt(p, reason), s0 = radix_route_scan_calls();
  int32_t id;
  int be, ep = send_one(path, ctype, conv, len, &id, &be);

  CHECK(ep >= 0, "%s: forwarded to the selector's pick (ep %d)", what, ep);
  CHECK(cnt(p, reason) == r0 + 1, "%s: counted %s (%lu)", what, reason, cnt(p, reason) - r0);
  CHECK(radix_route_scan_calls() == s0, "%s: not scanned", what);
  CHECK(h2fx_stream(id) && h2fx_stream(id)->radix_req == NULL,
        "%s: no per-stream radix state", what);
  if (ep >= 0)
    answer(be, id, "200");
}

static void
on_gates(proxy_epval_t *p)
{
  size_t len = chat_body('z', 600, 'a', 300);

  gated(p, "NOT_CHAT", "not_chat", "/v1/completions", JSON, NULL, len);
  gated(p, "NOT_CHAT, a longer chat-like path", "not_chat", "/v1/chat/completions/x",
        JSON, NULL, len);
  gated(p, "non-JSON media", "no_body", CHAT, "text/plain", NULL, len);
  gated(p, "HEADERS-only (E8)", "no_body", CHAT, JSON, NULL, 0);
  gated(p, "conversation pin (E3)", "pinned", CHAT, JSON, "conv-1", len);
  CHECK(conv_lookups > 0, "E3: the conversation table was read");
  memset(body, ' ', BODY_CAP);
  len = chat_body('z', 600, 'a', 800 * 1024);
  gated(p, "body above 768 KiB", "inspect_size", CHAT, JSON, NULL, len);
}

static void
on_ai_gw_off(void)
{
  proxy_epval_t *p = pool_new("on-aigw-off", 2, 0, 1);

  h2fx_lpm = p;
  gated(p, "pool not in AI gateway mode", "ai_gw_off", CHAT, JSON, NULL,
        chat_body('w', 600, 'a', 300));
  radix_pool_free(p->radix);
  p->radix = NULL;
}

/* B: the first forward fails after the decision without an answer (the
 * stream mapping cannot be allocated); the next read forwards the stream
 * again: one decision counted. */
static void
on_reforward_counted_once(void)
{
  proxy_epval_t *p = pool_new("on-reforward", 2, 1, 1);
  size_t len = chat_body('v', 600, 'a', 300);
  unsigned long m0;
  int32_t id;
  int be, ep;

  h2fx_lpm = p;
  m0 = cnt(p, "miss");
  id = h2fx_submit_req(CHAT, JSON, NULL, "m", (const uint8_t *)body, len);
  h2fx_fail_calloc_size = sizeof(stream_mapping_t);
  CHECK(h2fx_gw_read() == 0, "B: the request is read; its mapping is not allocated");
  CHECK(h2fx_calloc_failed == 1 && routed(id, NULL) < 0 && !h2fx_status[id / 2],
        "B: not forwarded the first time, and not answered");
  assert(nghttp2_submit_ping(h2fx_cl, NGHTTP2_FLAG_NONE, NULL) == 0);
  CHECK(h2fx_gw_read() == 0, "B: the next read forwards it again");
  ep = routed(id, &be);
  CHECK(ep >= 0, "B: forwarded the second time (ep %d)", ep);
  CHECK(h2fx_stream(id) && h2fx_stream(id)->radix_decided == 1, "B: the stream is marked decided");
  CHECK(cnt(p, "miss") == m0 + 1, "B: one decision counted (%lu)", cnt(p, "miss") - m0);
  if (ep >= 0)
    answer(be, id, "200");
  radix_pool_free(p->radix);
  p->radix = NULL;
}

/* E6: the bounded-load unit follows the radix endpoint. */
static void
on_units(void)
{
  static chwbl_config_t cfg;
  proxy_epval_t *p = pool_new("on-chwbl", 3, 1, 1);
  size_t len = chat_body('u', 600, 'a', 300);
  int32_t id;
  int be, ep;

  p->select = PROXY_SEL_CHWBL;
  p->chwbl_config = &cfg;
  h2fx_chwbl = chwbl;
  h2fx_lpm = p;
  chwbl_pick = 2;                       /* learned on ep2 */
  ep = send_one(CHAT, JSON, NULL, len, &id, &be);
  CHECK(ep == 2, "E6: the selector's pick on a miss (ep %d)", ep);
  if (ep >= 0)
    answer(be, id, "200");
  CHECK(units[0] == 0 && units[1] == 0 && units[2] == 0, "E6: no unit held after the stream");
  chwbl_pick = 0;                       /* the selector now says ep0 */
  len = chat_body('u', 600, 'b', 280);
  ep = send_one(CHAT, JSON, NULL, len, &id, &be);
  CHECK(ep == 2, "E6: radix moves the stream to ep2 (got %d)", ep);
  CHECK(units[2] == 1 && units[0] == 0,
        "E6: the stream's unit sits on the radix endpoint while it is open (ep0 %d, ep2 %d)",
        units[0], units[2]);
  if (ep >= 0)
    answer(be, id, "200");
  CHECK(units[0] == 0 && units[1] == 0 && units[2] == 0 && units_min == 0,
        "E6: every unit back to zero after it, never below (min %d)", units_min);
  h2fx_chwbl = NULL;
  radix_pool_free(p->radix);
  p->radix = NULL;
}

/* E10: a client reset before the answer, and a stream still open at
 * teardown: LeakSanitizer reads what is left at exit. */
static void
on_lifetime(void)
{
  size_t len = chat_body('t', 600, 'a', 300);
  int32_t id;
  int ep = send_one(CHAT, JSON, NULL, len, &id, NULL);

  CHECK(ep >= 0 && h2fx_stream(id) && h2fx_stream(id)->radix_req != NULL,
        "E10: the stream holds its state before the reset");
  assert(nghttp2_submit_rst_stream(h2fx_cl, NGHTTP2_FLAG_NONE, id, NGHTTP2_CANCEL) == 0);
  h2fx_to_gateway();
  CHECK(h2fx_stream(id) == NULL, "E10: the reset freed the stream");
  ep = send_one(CHAT, JSON, NULL, chat_body('t', 600, 'c', 300), &id, NULL);
  CHECK(ep >= 0 && h2fx_stream(id) && h2fx_stream(id)->radix_req != NULL,
        "E10: a stream left open for the teardown holds its state");
}

int
main(void)
{
  proxy_epval_t *on;
  radix_pool_t *on_radix;

  h2fx_init();
  h2fx_allow_completion = 1;     /* admitted answers are relayed */
  h2fx_be_body_count = 1;        /* the 800 KiB body reaches a backend */
  chat_predicate();
  off_unchanged();

  on = pool_new("on", 3, 1, 1);
  on_radix = on->radix;
  h2fx_lpm = on;
  on_learn_and_hit(on);
  on_gates(on);
  on_ai_gw_off();
  on_reforward_counted_once();
  on_units();
  h2fx_lpm = on;
  on_lifetime();

  h2fx_fini();
  radix_pool_free(on_radix);
  return h2fx_result();
}
