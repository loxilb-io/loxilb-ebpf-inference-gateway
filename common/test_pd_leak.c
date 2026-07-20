/* test_pd_leak.c - Unit tests for the Phase 87 P/D streaming-completion
 * connection-leak fix (FIX-1/2/3/4), against the PURE helpers in
 * sockproxy_pd_leak.h.
 *
 * Standalone test binary: NO sockproxy.c / proxy-machinery dependencies.
 * Build: gcc -Wall -Wextra -fsanitize=address -o test_pd_leak \
 *        test_pd_leak.c -I. -DTEST_PD_LEAK
 *
 * Idiom: mirrors test_pd_rewriter — assert() per case, "ALL PASS" print at the
 * end, exit 0 on success / nonzero on failure. The fake-struct + stub include
 * pattern follows the test_pd_cache_aware.c precedent.
 *
 * Coverage:
 *   - FIX-2 (prefill, chunked / no Content-Length)  → detector returns nonzero
 *   - FIX-2 negative (partial chunked, no terminator) → detector returns 0
 *   - FIX-4 (chunked non-SSE decode response)        → detector returns nonzero
 *   - SSE [DONE] done-marker                         → detector returns nonzero
 *   - FIX-1/3 (phase timeout → two-leg teardown)     → all fds == -1, every fd
 *                                                       deregistered, no leak
 */

#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>

/* ----- Stub close(): the helper calls close() on fd ints. We must NOT close
 * real fds in the unit. Redirect close() to a recording stub via macro BEFORE
 * including the unit under test, so pd_teardown_legs() links against the stub.
 * sockproxy_pd_leak.h includes <unistd.h>; our macro overrides the symbol it
 * sees at the call sites within the header (textual inclusion order matters). */
static int g_stub_close_calls[64];
static int g_stub_close_n = 0;
static int
stub_close(int fd)
{
  if (g_stub_close_n < (int)(sizeof(g_stub_close_calls) / sizeof(g_stub_close_calls[0]))) {
    g_stub_close_calls[g_stub_close_n++] = fd;
  }
  return 0;
}
#define close(fd) stub_close(fd)

/* ----- Fake proxy_fd_ent (the test-supplied minimal struct; the
 * SOCKPROXY_PD_LEAK_FAKE_ENT guard tells the header to use OUR struct). ----- */
#define SOCKPROXY_PD_LEAK_FAKE_ENT
struct proxy_fd_ent {
  int fd;
  int rfd[8];
  int n_rfd;
};

#include "sockproxy_pd_leak.h"

/* ----- Fake notifier: records every fd it was asked to deregister, so a test
 * can prove the teardown deregisters all three legs (client + 2 backend). ----- */
static int g_notify_del_fds[64];
static int g_notify_del_n = 0;
static int
fake_notify_del(void *ns, int fd, int arg)
{
  (void)ns;
  (void)arg;
  if (g_notify_del_n < (int)(sizeof(g_notify_del_fds) / sizeof(g_notify_del_fds[0]))) {
    g_notify_del_fds[g_notify_del_n++] = fd;
  }
  return 0;
}

static int
notify_recorded(int fd)
{
  for (int i = 0; i < g_notify_del_n; i++) {
    if (g_notify_del_fds[i] == fd) {
      return 1;
    }
  }
  return 0;
}

/* PREFILL_WAITING: the P/D phase Bug 1 wedges forever when a chunked / CL-less
 * prefill response is not detected as complete. The detector flipping nonzero is
 * exactly what lets the prefill gate leave PREFILL_WAITING. Named here so the
 * harness self-documents the state it guards. */
#define PREFILL_WAITING_GUARD "pd_detect_http_msg_end gates exit from PREFILL_WAITING"

/* ---------- FIX-2: chunked prefill WITHOUT Content-Length completes ---------- */
static void
test_fix2_chunked_prefill_complete(void)
{
  /* A prefill response framed with Transfer-Encoding: chunked and NO
   * Content-Length, terminated by the last-chunk "0\r\n\r\n". Bug 1 today leaves
   * pr_complete=0 (CL-only gate) → permanent PREFILL_WAITING. The detector must
   * see the terminator → nonzero → flips pr_complete. */
  static const char resp[] =
      "HTTP/1.1 200 OK\r\n"
      "Content-Type: application/json\r\n"
      "Transfer-Encoding: chunked\r\n"
      "\r\n"
      "1a\r\n{\"id\":\"x\",\"object\":\"y\"}\r\n"
      "0\r\n\r\n";
  int r = pd_detect_http_msg_end((const uint8_t *)resp, sizeof(resp) - 1);
  assert(r != 0 && "FIX-2: chunked prefill with 0\\r\\n\\r\\n must complete (no permanent "
                   PREFILL_WAITING_GUARD ")");
  printf("  [PASS] FIX-2  chunked prefill (no Content-Length) -> complete\n");
}

/* ---------- FIX-2 negative: partial chunked prefill stays WAITING ---------- */
static void
test_fix2_partial_chunked_incomplete(void)
{
  /* Same response WITHOUT the terminating "0\r\n\r\n" — a fragment that has only
   * arrived partway. The detector MUST return 0 so the gate stays WAITING and
   * does not prematurely complete (and forward a truncated prefill). */
  static const char resp[] =
      "HTTP/1.1 200 OK\r\n"
      "Transfer-Encoding: chunked\r\n"
      "\r\n"
      "1a\r\n{\"id\":\"x\",\"object\":\"y\"}\r\n";
  int r = pd_detect_http_msg_end((const uint8_t *)resp, sizeof(resp) - 1);
  assert(r == 0 && "FIX-2 negative: partial chunked (no terminator) must NOT complete");
  printf("  [PASS] FIX-2  partial chunked (no terminator) -> stays WAITING\n");
}

/* ---------- FIX-4: chunked non-SSE decode response completes ---------- */
static void
test_fix4_chunked_decode_complete(void)
{
  /* The non-SSE decode completion gate (http.c:1296-1297) is CL-only today, so a
   * chunked decode response never reaches PD_PHASE_COMPLETE. The detector seeing
   * "0\r\n\r\n" is what FIX-4 uses to complete it. */
  static const char resp[] =
      "HTTP/1.1 200 OK\r\n"
      "Transfer-Encoding: chunked\r\n"
      "\r\n"
      "2c\r\n{\"choices\":[{\"text\":\"hello world\"}]}\r\n"
      "0\r\n\r\n";
  int r = pd_detect_http_msg_end((const uint8_t *)resp, sizeof(resp) - 1);
  assert(r != 0 && "FIX-4: chunked decode with 0\\r\\n\\r\\n must reach PD_PHASE_COMPLETE");
  printf("  [PASS] FIX-4  chunked decode (no Content-Length) -> complete\n");
}

/* ---------- detector: SSE [DONE] marker also completes ---------- */
static void
test_sse_done_marker_complete(void)
{
  static const char resp1[] = "event: x\ndata: {\"a\":1}\n\ndata: [DONE]\n\n";
  static const char resp2[] = "data:{\"a\":1}\n\ndata:[DONE]\n\n";
  assert(pd_detect_http_msg_end((const uint8_t *)resp1, sizeof(resp1) - 1) != 0 &&
         "SSE 'data: [DONE]' must complete");
  assert(pd_detect_http_msg_end((const uint8_t *)resp2, sizeof(resp2) - 1) != 0 &&
         "SSE 'data:[DONE]' must complete");
  printf("  [PASS] SSE    [DONE] done-marker (both spacings) -> complete\n");
}

/* ---------- detector: bounded scan / robustness ---------- */
static void
test_detector_bounds(void)
{
  /* NULL / zero-length → not complete (no read). */
  assert(pd_detect_http_msg_end(NULL, 0) == 0);
  assert(pd_detect_http_msg_end((const uint8_t *)"0\r\n\r\n", 0) == 0);
  /* len shorter than the terminator must NOT spuriously match. The detector is
   * bounded by len only — ASan would flag any over-read here. */
  assert(pd_detect_http_msg_end((const uint8_t *)"0\r\n\r", 4) == 0);
  /* A buffer whose terminator sits past `len` must NOT match (bounded). */
  static const char buf[] = "abc0\r\n\r\n";
  assert(pd_detect_http_msg_end((const uint8_t *)buf, 3) == 0); /* only "abc" visible */
  assert(pd_detect_http_msg_end((const uint8_t *)buf, sizeof(buf) - 1) != 0);
  printf("  [PASS] BOUND  detector honors len, no over-read (ASan-clean)\n");
}

/* ---------- FIX-1/3: phase-timeout two-leg teardown closes every fd ---------- */
static void
test_fix1_3_teardown_closes_all_legs(void)
{
  /* Use REAL fds (from /dev/null dups) so the stub close() / -1 zeroing operate
   * on plausible positive fds; the stub does not actually close them, but we dup
   * real ones to keep the values realistic and avoid magic numbers. */
  int c  = open("/dev/null", O_RDONLY);
  int r0 = open("/dev/null", O_RDONLY);
  int r1 = open("/dev/null", O_RDONLY);
  assert(c > 0 && r0 > 0 && r1 > 0);

  struct proxy_fd_ent ent;
  memset(&ent, 0, sizeof(ent));
  ent.fd = c;
  ent.n_rfd = 2;
  ent.rfd[0] = r0;
  ent.rfd[1] = r1;

  g_notify_del_n = 0;
  g_stub_close_n = 0;

  int closed = pd_teardown_legs(&ent, fake_notify_del, NULL);

  /* All three legs closed and zeroed to -1 (no leaked fds). */
  assert(closed == 3 && "teardown must close client + 2 backend legs");
  assert(ent.fd == -1 && "client fd must be zeroed to -1");
  assert(ent.rfd[0] == -1 && "backend leg 0 must be zeroed to -1");
  assert(ent.rfd[1] == -1 && "backend leg 1 must be zeroed to -1");

  /* Every leg was deregistered from the notifier (proves no notifier leak). */
  assert(notify_recorded(c)  && "client fd must be deregistered");
  assert(notify_recorded(r0) && "backend leg 0 must be deregistered");
  assert(notify_recorded(r1) && "backend leg 1 must be deregistered");
  assert(g_notify_del_n == 3 && "exactly 3 deregistrations");

  /* And close() was invoked on each (via the stub). */
  assert(g_stub_close_n == 3 && "exactly 3 closes");

  /* Idempotency: a second teardown of the already-torn-down ent is a no-op
   * (all fds already -1) — proves the reaper can't double-close. */
  g_notify_del_n = 0;
  g_stub_close_n = 0;
  int closed2 = pd_teardown_legs(&ent, fake_notify_del, NULL);
  assert(closed2 == 0 && "re-teardown of a torn-down ent closes nothing (idempotent)");
  assert(g_notify_del_n == 0 && g_stub_close_n == 0);

  printf("  [PASS] FIX-1/3 two-leg teardown: fds -> -1, all deregistered, idempotent\n");

  /* Genuinely release the real fds we dup'd (NOT via the stubbed close()). */
#undef close
  close(c);
  close(r0);
  close(r1);
}

int
main(void)
{
  printf("== test_pd_leak: Phase 87 P/D streaming-leak helpers ==\n");
  test_fix2_chunked_prefill_complete();
  test_fix2_partial_chunked_incomplete();
  test_fix4_chunked_decode_complete();
  test_sse_done_marker_complete();
  test_detector_bounds();
  test_fix1_3_teardown_closes_all_legs();
  printf("== test_pd_leak: ALL PASS ==\n");
  return 0;
}
