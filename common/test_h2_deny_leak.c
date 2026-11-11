/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_h2_deny_leak.c - the HTTP/2 answers the gateway writes itself, and the
 * strip of a backend's X-Loxilb-Refusal-*, hold nothing per stream.
 *
 * cicd/ai-jwtauth H2-LIFE-003 watches the gateway's data segment while one
 * connection is refused stream after stream. It moves in 64 kB steps and
 * bounds megabyte-scale growth only. This unit asks the same question where
 * it can be answered exactly: ONE gateway connection (the shared fixture,
 * test_h2_fixture.h, the product's sockproxy_h2.c built with ASan) is driven
 * through five paths, cycle after cycle:
 *
 *   SHED8        429 capacity refusal at its fullest: the six admission
 *                fields of the caller plus the two of the mark
 *                (x-loxilb-refusal-stage, x-request-id) - the eight-field
 *                list of h2_send_deny_frame; the client reads the body.
 *   SHED8_RESET  the same refusal, the client's stream window at 0 so the
 *                deny body stays queued at the gateway, and the client
 *                resets the stream: the body context is freed by the
 *                stream's close, never by its read callback.
 *   AUTH         401 from the admission gate with a 255-byte request ID
 *                echoed whole; the body is read.
 *   AUTH_RESET   the path H2-LIFE-003 drives: 401, body held, reset.
 *   RELAY        a request forwarded to a backend that answers 103 and 429,
 *                both carrying x-loxilb-refusal-*: the family is dropped
 *                from each head (proxy_h2_drop_resp_refusal_mark).
 *
 * Verdict, two halves:
 *   - LeakSanitizer at exit: nothing the paths allocated is left without an
 *     owner (ASAN_OPTIONS=detect_leaks=1; a report makes the exit code
 *     non-zero).
 *   - the live heap (ASan's own count of allocated bytes) is read at the end
 *     of every cycle. After a warm-up it must be THE SAME NUMBER at the end
 *     of every later cycle: state that stays reachable and grows with the
 *     stream count is not a leak LeakSanitizer can see, and this is. (Past
 *     stream ID 65535 the number may differ by nghttp2's own map bucket
 *     lists and by nothing else: see NGH2_MAP_LIST_BYTES.)
 * Every stream is also checked for what it is supposed to be: the answer was
 * written (the response note), the body was held when it should be, and the
 * stream is gone afterwards. The streams the fixture's client keeps headers
 * for (the first 63) are checked field by field.
 *
 * usage: test_h2_deny_leak [cycles (10000)] [warm-up cycles (500)]
 *                          [mask of paths (31)] [heap profile (0)]
 *                          [unbounded fake backend (0)] [reset every Nth cycle (6)]
 *
 * The two reset paths are paced under nghttp2's stream-reset rate limit (see
 * reset_pace), and that pacing is nearly all of the run time. By default
 * they run in every 6th cycle only: 10000 cycles are then about 33000
 * streams on the one connection (30000 through the three paths that are
 * read, 1666 through each reset path), which crosses stream ID 65535, in
 * under two minutes on two CPUs. The full run, every path in every cycle,
 * 50000 streams, about 13 minutes:
 *
 *   make test_h2dleak H2DLEAK_ARGS="10000 500 31 0 0 1"
 *
 * Build: make test_h2dleak (ASan + UBSan + LeakSanitizer, the gateway object
 * included). H2DLEAK_ARGS passes the arguments above.
 */
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* ASan's count of the bytes the program holds (sanitizer/allocator_interface.h;
 * declared here so the unit builds where that header is not installed). */
size_t __sanitizer_get_current_allocated_bytes(void);
void __sanitizer_print_memory_profile(size_t top_percent, size_t max_number_of_contexts);

#include "test_h2_fixture.h"
#include "sockproxy_qsbr.h"
#include "sockproxy_l7policy.h"
#include "sockproxy_fc.h"
#include "sockproxy_llmd.h"

enum { K_SHED8, K_SHED8_RESET, K_AUTH, K_AUTH_RESET, K_RELAY, K_N };
static const char *const kname[K_N] = { "SHED8", "SHED8_RESET", "AUTH", "AUTH_RESET", "RELAY" };

static int the_kind;
static proxy_epval_t *plain_pool, *shed_pool;
static char rid255[256];

extern int h2fx_notes, h2fx_note_status, h2fx_note_ttfb;

static long done[K_N], bad[K_N], shown;
static long cyc;
static int32_t top_id;    /* the last stream the client opened */

/* What libnghttp2 itself keeps, and why the verdict has two regimes.
 * Its stream map (1.43: 256 buckets, FNV-1a over the four bytes of the
 * stream ID) gives a bucket that ever holds two streams at once a skip list
 * of its own, 64 + 528 bytes, and keeps that list for the life of the
 * session. The gateway's session holds about a hundred streams at a time
 * (the closed ones nghttp2 retains up to the advertised limit). While every
 * ID is below 65536 no two of them share a bucket and the heap is exactly
 * flat; above it buckets start to collide, and each first collision adds
 * 592 bytes once, 256 times at most. That is the library's bounded
 * bookkeeping in ANY session that lives past 32768 streams; it does not
 * depend on what the gateway answers. So: below 65536 the heap must be the
 * same number at the end of every cycle; above, it may differ from that
 * number only by whole bucket lists, never fewer than before. */
#define NGH2_MAP_LIST_BYTES 592
#define NGH2_MAP_BUCKETS 256
#define NGH2_FLAT_ID_MAX 65535
static int be_limited;
static int no_be_limit;   /* diagnostic: leave the fake backend unbounded */

#define EXPECT(cond, ...) do {                                           \
    if (!(cond)) {                                                       \
      bad[the_kind]++;                                                   \
      if (shown++ < 25) {                                                \
        printf("  unexpected, cycle %ld %s: ", cyc, kname[the_kind]);    \
        printf(__VA_ARGS__); printf("  (line %d)\n", __LINE__);          \
      }                                                                  \
    }                                                                    \
  } while (0)

static void
admit(const ai_gw_req_ctx_t *req, ai_gw_admit_result_t *res)
{
  (void)req;
  if (the_kind == K_AUTH || the_kind == K_AUTH_RESET) {
    res->verdict = AI_GW_ADMIT_DENY;
    res->http_status = 401;
    res->stage = AI_GW_STAGE_AUTH;
    snprintf(res->error_code, sizeof(res->error_code), "invalid_api_key");
    snprintf(res->error_msg, sizeof(res->error_msg), "the key is not known");
  } else if (the_kind == K_SHED8 || the_kind == K_SHED8_RESET) {
    res->verdict = AI_GW_ADMIT_ALLOW;
    snprintf(res->tenant_id, sizeof(res->tenant_id), "t1");
    res->priority_class = AI_GW_CLASS_SHEDDABLE;
  } else {
    res->verdict = AI_GW_ADMIT_UNMETERED;
  }
}

#define NV(n, v) { (uint8_t *)(n), (uint8_t *)(v), sizeof(n) - 1, sizeof(v) - 1, NGHTTP2_NV_FLAG_NONE }

/* A complete request (END_STREAM on HEADERS) naming its own request ID.
 * Not h2fx_submit: that one stops at the 64 streams the fixture records. */
static int32_t
submit(const char *rid)
{
  nghttp2_nv req[] = {
    NV(":method", "POST"),
    NV(":path", "/v1/chat/completions"),
    NV(":scheme", "http"),
    NV(":authority", "all.example"),
    NV("x-model", "m1"),
    { (uint8_t *)"x-request-id", (uint8_t *)rid, 12, strlen(rid), NGHTTP2_NV_FLAG_NONE },
  };
  int32_t id = nghttp2_submit_request(h2fx_cl, NULL, req, 6, NULL, NULL);

  assert(id > 0);
  top_id = id;
  return id;
}

/* The client's stream window: 0 holds a deny body at the gateway. */
static void
window(uint32_t w)
{
  static uint32_t cur = 65535;
  nghttp2_settings_entry e = { NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, w };

  if (cur == w)
    return;
  assert(nghttp2_submit_settings(h2fx_cl, NGHTTP2_FLAG_NONE, &e, 1) == 0);
  h2fx_to_gateway();
  cur = w;
}

/* nghttp2 lets a peer reset 1000 streams at once and 33 a second after that
 * (its answer to rapid reset); past it the gateway's session says GOAWAY and
 * the connection is over. One connection is the subject here, so the resets
 * are paced under that rate once the burst is nearly spent. */
#define RESET_BURST 800
#define RESET_PER_SEC 25.0
static long n_resets;

static double
now_s(void)
{
  struct timespec ts;

  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void
reset_pace(void)
{
  static double t0;
  double due;

  if (n_resets++ == 0)
    t0 = now_s();
  if (n_resets <= RESET_BURST)
    return;
  due = t0 + (double)(n_resets - RESET_BURST) / RESET_PER_SEC;
  while (now_s() < due)
    usleep(2000);
}

static int
recorded(int32_t id)
{
  return id / 2 < H2FX_MAX_STREAMS;
}

static void
refusal(int kind)
{
  int reset = kind == K_SHED8_RESET || kind == K_AUTH_RESET;
  int shed = kind == K_SHED8 || kind == K_SHED8_RESET;
  int want = shed ? 429 : 401;
  const char *rid = shed ? "rid-leak-shed" : rid255;
  int notes0 = h2fx_notes;
  proxy_h2_stream_t *st;
  int32_t id;
  int rc;

  the_kind = kind;
  h2fx_lpm = shed ? shed_pool : NULL;
  h2fx_class_on = shed;
  window(reset ? 0 : 65535);
  id = submit(rid);
  rc = h2fx_gw_read();
  EXPECT(rc == 0, "the read returned %d", rc);
  EXPECT(h2fx_notes == notes0 + 1 && h2fx_note_status == want && h2fx_note_ttfb == 0,
         "one answer of the gateway's own, %d (notes +%d, status %d)", want,
         h2fx_notes - notes0, h2fx_note_status);
  if (reset) {
    st = h2fx_stream(id);
    EXPECT(st && st->response_sent && st->deny_body_ctx,
           "the answered stream is open with its body still queued (stream %s, ctx %s)",
           st ? "there" : "gone", st && st->deny_body_ctx ? "held" : "none");
    if (recorded(id))
      EXPECT(h2fx_status[id / 2] == want && h2fx_body(id)[0] == '\0',
             "the client has the head and no body (status %d, body '%s')",
             h2fx_status[id / 2], h2fx_body(id));
    reset_pace();
    assert(nghttp2_submit_rst_stream(h2fx_cl, NGHTTP2_FLAG_NONE, id, NGHTTP2_CANCEL) == 0);
    rc = h2fx_gw_read();
    EXPECT(rc == 0, "the read of the reset returned %d", rc);
  } else if (recorded(id)) {
    EXPECT(h2fx_status[id / 2] == want && h2fx_body(id)[0] == '{',
           "the client has the head and the body (status %d, body '%s')",
           h2fx_status[id / 2], h2fx_body(id));
  }
  EXPECT(h2fx_stream(id) == NULL, "the stream is gone");
  if (recorded(id)) {
    const char *v = h2fx_header(id, "x-loxilb-refusal-stage");

    EXPECT(v && !strcmp(v, shed ? "capacity" : "auth"), "stage %s", v ? v : "none");
    v = h2fx_header(id, "x-request-id");
    EXPECT(v && !strcmp(v, rid), "the request's own ID, whole (%zu bytes)", v ? strlen(v) : (size_t)0);
    if (shed) {
      static const char *const six[] = {
        "x-loxilb-admission-inflight", "x-loxilb-admission-queued", "x-loxilb-admission-limit",
        "x-loxilb-admission-class", "x-loxilb-admission-band-wait-ms", SP_LLMD_REASON_HDR,
      };
      for (size_t i = 0; i < 6; i++)
        EXPECT(h2fx_header(id, six[i]) != NULL, "field %s of the eight", six[i]);
    }
  }
  done[kind]++;
}

static void
relay(void)
{
  nghttp2_nv interim[] = {
    NV(":status", "103"),
    NV("link", "</style.css>; rel=preload"),
    NV("x-loxilb-refusal-stage", "route"),
  };
  nghttp2_nv final[] = {
    NV(":status", "429"),
    NV("content-length", "0"),
    NV("x-loxilb-refusal-stage", "capacity"),
    NV("x-backend", "b1"),
    NV("x-loxilb-refusal-anything", "1"),
    NV("x-request-id", "be-7"),
    NV("retry-after", "3"),
  };
  int streams0 = h2fx_n_be ? h2fx_be[0].streams : 0;
  int notes0 = h2fx_notes;
  int32_t id;
  int rc;

  the_kind = K_RELAY;
  h2fx_lpm = plain_pool;
  h2fx_class_on = 0;
  window(65535);
  id = submit("rid-leak-relay");
  rc = h2fx_gw_read();
  EXPECT(rc == 0 && h2fx_n_be == 1 && h2fx_be[0].streams == streams0 + 1 && h2fx_be[0].end_stream,
         "forwarded to the one backend (rc %d, backends %d, streams %d)", rc, h2fx_n_be,
         h2fx_n_be ? h2fx_be[0].streams : -1);
  if (h2fx_n_be != 1 || h2fx_be[0].streams != streams0 + 1) {
    done[K_RELAY]++;
    return;
  }
  EXPECT(h2fx_mapping(0, id) != NULL, "the stream has its mapping on the leg");
  if (!be_limited && !no_be_limit) {
    /* The fake backend is an nghttp2 server session, and one that names no
     * stream limit keeps every closed stream (its priority tree) for the
     * life of the connection: the fixture's memory, not the gateway's. A
     * limit bounds what it keeps, as the gateway's own session is bounded
     * by the limit it advertises. */
    nghttp2_settings_entry lim = { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 };

    assert(nghttp2_submit_settings(h2fx_be[0].srv, NGHTTP2_FLAG_NONE, &lim, 1) == 0);
    be_limited = 1;
  }
  assert(nghttp2_submit_headers(h2fx_be[0].srv, NGHTTP2_FLAG_NONE, h2fx_be[0].stream, NULL,
                                interim, sizeof(interim) / sizeof(interim[0]), NULL) == 0);
  rc = h2fx_be_send(0);
  EXPECT(rc == 0, "the 103 is relayed (rc %d)", rc);
  if (recorded(id)) {
    EXPECT(h2fx_header(id, "link") != NULL, "the interim head arrived");
    EXPECT(h2fx_header(id, "x-loxilb-refusal-stage") == NULL, "without the family");
  }
  assert(nghttp2_submit_response(h2fx_be[0].srv, h2fx_be[0].stream, final,
                                 sizeof(final) / sizeof(final[0]), NULL) == 0);
  rc = h2fx_be_send(0);
  EXPECT(rc == 0, "the 429 is relayed (rc %d)", rc);
  EXPECT(h2fx_notes == notes0 + 1 && h2fx_note_status == 429,
         "the stream's response is noted once, the backend's 429 (notes +%d, status %d)",
         h2fx_notes - notes0, h2fx_note_status);
  if (recorded(id)) {
    const char *v = h2fx_header(id, "x-request-id");

    EXPECT(h2fx_status[id / 2] == 429, "the backend's status (%d)", h2fx_status[id / 2]);
    EXPECT(h2fx_header(id, "x-loxilb-refusal-stage") == NULL &&
           h2fx_header(id, "x-loxilb-refusal-anything") == NULL, "no field of the family");
    EXPECT(v && !strcmp(v, "be-7"), "the backend's own x-request-id (%s)", v ? v : "none");
    EXPECT(h2fx_header(id, "x-backend") != NULL, "the rest of the head");
  }
  EXPECT(h2fx_stream(id) == NULL, "the stream is gone");
  EXPECT(h2fx_mapping(0, id) == NULL, "and its mapping");
  done[K_RELAY]++;
}

int
main(int argc, char **argv)
{
  long cycles = argc > 1 ? atol(argv[1]) : 10000;
  long warm = argc > 2 ? atol(argv[2]) : 500;
  int profile = argc > 4 ? atoi(argv[4]) : 0;              /* diagnostic: who holds the heap */
  no_be_limit = argc > 5 ? atoi(argv[5]) : 0;
  int mask = argc > 3 ? atoi(argv[3]) : (1 << K_N) - 1;   /* diagnostic: a subset of the paths */
  long reset_every = argc > 6 ? atol(argv[6]) : 6;        /* the reset paths run in every Nth cycle */
  long want[K_N], streams = 0, flat_streams = 0, late_streams = 0;
  size_t base = 0, hi = 0, last = 0;
  long moved = 0, first_moved = -1, flat_samples = 0;
  long late_samples = 0, late_bad = 0, first_late_bad = -1, steps = 0, last_step = -1;
  fc_cfg_t cfg = { 0 };
  fc_permit_t other = { 0 };
  long total = 0, total_bad = 0;

  assert(cycles > warm && warm > 0 && reset_every > 0);
  memset(rid255, 'r', 255);

  h2fx_init();
  h2fx_admit = admit;
  plain_pool = h2fx_pool("all.example", 1);

  /* An AI pool with a ceiling of one, held by another request for the whole
   * run, on a rule that speaks the llm-d convention: every sheddable request
   * is refused with the frame at its fullest. */
  shed_pool = sp_pool_alloc();
  assert(shed_pool);
  snprintf(shed_pool->ephash_key, sizeof(shed_pool->ephash_key), "all.example|m1");
  shed_pool->ai_gw_mode = 1;
  shed_pool->n_eps = 1;
  pthread_mutex_init(&shed_pool->fc.queue.lock, NULL);
  cfg.mode = FC_MODE_ENFORCE;
  cfg.max_outstanding = 1;
  fc_state_apply(&shed_pool->fc, &cfg);
  shed_pool->fc.cfg.llmd_headers = 1;
  assert(fc_service_acquire(&shed_pool->fc, &other) == FC_ADMIT);

  for (int k = 0; k < K_N; k++) {
    int reset = k == K_SHED8_RESET || k == K_AUTH_RESET;

    want[k] = !(mask & (1 << k)) ? 0 : reset ? cycles / reset_every : cycles;
  }
  printf("# %ld cycles (the reset paths in every cycle that is a multiple of %ld), warm-up %ld "
         "cycles; live heap at the end of a cycle:\n", cycles, reset_every, warm);
  for (cyc = 1; cyc <= cycles; cyc++) {
    size_t now;
    long in_cycle = 0;

    for (int k = 0; k < K_N; k++) {
      if (!(mask & (1 << k)))
        continue;
      if ((k == K_SHED8_RESET || k == K_AUTH_RESET) && cyc % reset_every)
        continue;
      in_cycle++;
      if (k == K_RELAY)
        relay();
      else
        refusal(k);
    }

    /* The client's own pending frames (a WINDOW_UPDATE it owes for the
     * bodies it read) are the test's memory: sent before the heap is read. */
    h2fx_to_gateway();
    streams += in_cycle;
    now = __sanitizer_get_current_allocated_bytes();
    if (profile && (cyc == warm || cyc == cycles)) {
      fflush(stdout);
      fprintf(stderr, "### live heap profile at cycle %ld\n", cyc);
      __sanitizer_print_memory_profile(100, 25);
    }
    if (cyc == warm) {
      base = hi = now;
    } else if (cyc > warm && top_id <= NGH2_FLAT_ID_MAX) {
      flat_samples++;
      flat_streams += in_cycle;
      if (now != base) {
        moved++;
        if (first_moved < 0)
          first_moved = cyc;
      }
    } else if (cyc > warm) {
      long d = (long)now - (long)base;

      late_samples++;
      late_streams += in_cycle;
      if (d < 0 || d % NGH2_MAP_LIST_BYTES || d / NGH2_MAP_LIST_BYTES > NGH2_MAP_BUCKETS ||
          now < hi) {
        late_bad++;
        if (first_late_bad < 0)
          first_late_bad = cyc;
      }
      if (now > hi) {
        hi = now;
        steps++;
        last_step = cyc;
      }
    }
    last = now;
    if (cyc == 1 || cyc == 10 || cyc == 100 || cyc == warm || cyc % 500 == 0 || cyc == cycles)
      printf("#   cycle %6ld (%7ld streams): %zu bytes\n", cyc, streams, now);
  }

  for (int k = 0; k < K_N; k++) {
    total += done[k];
    total_bad += bad[k];
    CHECK(done[k] == want[k] && bad[k] == 0, "%s: %ld streams, %ld unexpected observations",
          kname[k], done[k], bad[k]);
  }
  CHECK(total_bad == 0, "%ld streams on one connection (the last is stream %d), every one as declared",
        total, top_id);
  CHECK(!(mask & (1 << K_RELAY)) || (h2fx_connect_calls == 1 && h2fx_be[0].streams == cycles),
        "one backend connection carried every relayed stream (connects %d, streams %d)",
        h2fx_connect_calls, h2fx_be[0].streams);
  CHECK(fc_inflight(&shed_pool->fc) == 1, "no refused stream took a unit (inflight %u)",
        fc_inflight(&shed_pool->fc));
  CHECK(flat_samples > 0 && moved == 0,
        "stream IDs up to %d: the live heap is the same number, %zu bytes, at the end of each "
        "of the %ld cycles after the warm-up (%ld streams); %ld samples differ, the first at "
        "cycle %ld", NGH2_FLAT_ID_MAX, base, flat_samples, flat_streams, moved,
        first_moved);
  CHECK(late_bad == 0,
        "stream IDs above it, %ld cycles (%ld streams): the heap differs from that number only "
        "by whole nghttp2 map bucket lists, never fewer than before: +%ld bytes = %ld lists of "
        "%d (at most %d), the last added at cycle %ld; %ld samples are anything else, the first "
        "at cycle %ld", late_samples, late_streams, (long)hi - (long)base,
        ((long)hi - (long)base) / NGH2_MAP_LIST_BYTES, NGH2_MAP_LIST_BYTES, NGH2_MAP_BUCKETS,
        last_step, late_bad, first_late_bad);
  (void)steps;
  (void)last;

  fc_permit_release(&other);
  fc_permit_unbind(&other);
  fc_state_destroy(&shed_pool->fc);
  sp_pool_discard(shed_pool);
  h2fx_fini();
  return h2fx_result();
}
