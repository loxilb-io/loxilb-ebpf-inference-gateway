/* test_pd_complete.c - Unit tests for the T3 load-path stall fix
 * (: streaming-completion stall when sse_active never flips under TCP
 * fragmentation). Exercises the PURE windowed detector pd_scan_msg_end_window()
 * in sockproxy_pd_leak.h.
 *
 * Build: gcc -Wall -Wextra -fsanitize=address -o test_pd_complete \
 *        test_pd_complete.c -I. -DTEST_PD_COMPLETE
 *
 * Idiom mirrors test_pd_leak.c: assert() per case, "ALL PASS" at the end, exit 0
 * on success / nonzero (assert abort) on failure.
 *
 * The regression these guard: scanned only the CURRENT packet,
 * so a message-end terminator split across two reads was missed. On the
 * sse_active==0 path (fragmented Content-Type under load) that is the
 * ONLY decode completion detector, so the missed terminator stranded the decode
 * leg forever (~50% of high-rate points at conc=64 were watchdog-reaped).
 * pd_scan_msg_end_window() keeps a sliding tail so the straddling terminator is
 * detected on the read that completes it. Each split-terminator case also asserts
 * the OLD single-packet pd_detect_http_msg_end() would have MISSED it, pinning
 * the window as the thing that fixes the bug.
 */
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* The header defines pd_teardown_legs() as a static inline that dereferences
 * struct proxy_fd_ent, so the TU must supply a complete struct (we don't call it
 * here — pd_scan_msg_end_window/pd_detect_http_msg_end take no struct). Mirrors
 * the test_pd_leak.c / test_pd_cache_aware.c fake-ent precedent. */
#define SOCKPROXY_PD_LEAK_FAKE_ENT
struct proxy_fd_ent {
  int fd;
  int rfd[8];
  int n_rfd;
};

#include "sockproxy_pd_leak.h"

/* A per-"connection" sliding-tail fixture, mirroring the proxy_fd_ent.sse_tail /
 * .sse_tail_len fields the production call site rides on. Zero-initialised =
 * the fresh-connection state (tail_len == 0). */
struct tail_state {
  uint8_t tail[PD_MSG_END_TAIL_KEEP];
  uint8_t tail_len;
};

static int
scan(struct tail_state *ts, const char *pkt)
{
  return pd_scan_msg_end_window(ts->tail, &ts->tail_len,
                                (const uint8_t *)pkt, strlen(pkt));
}

/* ---- Case 1: terminator wholly inside one packet still completes ---- */
static void
test_done_whole_packet(void)
{
  struct tail_state ts = {{0}, 0};
  assert(scan(&ts, "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n") == 0);
  assert(scan(&ts, "data: [DONE]\n\n") != 0 &&
         "whole-packet data: [DONE] must complete");
  printf("  [PASS] whole-packet data: [DONE] -> complete\n");
}

/* ---- Case 2 (THE regression): [DONE] split across two reads ---- */
static void
test_done_split_across_reads(void)
{
  struct tail_state ts = {{0}, 0};

  /* The single-packet detector sees nothing in packet 1 ... */
  assert(pd_detect_http_msg_end((const uint8_t *)"id: 1\ndata: [DO", 14) == 0);
  assert(scan(&ts, "id: 1\ndata: [DO") == 0 &&
         "partial terminator must NOT complete");

  /* ... and STILL nothing in packet 2 ALONE (this is what missed)... */
  assert(pd_detect_http_msg_end((const uint8_t *)"NE]\n\n", 5) == 0);

  /* ... but the windowed scan, carrying the tail from packet 1, completes. */
  assert(scan(&ts, "NE]\n\n") != 0 &&
         "split data: [DONE] across two reads must complete via the sliding tail");
  printf("  [PASS] split data: [DONE] across two reads -> complete (sliding tail)\n");
}

/* ---- Case 3: chunked last-chunk "0\r\n\r\n" split across two reads ---- */
static void
test_chunked_terminator_split(void)
{
  struct tail_state ts = {{0}, 0};

  assert(pd_detect_http_msg_end((const uint8_t *)"5\r\nhello\r\n0\r", 12) == 0);
  assert(scan(&ts, "5\r\nhello\r\n0\r") == 0 &&
         "partial chunk terminator must NOT complete");

  assert(pd_detect_http_msg_end((const uint8_t *)"\n\r\n", 3) == 0);
  assert(scan(&ts, "\n\r\n") != 0 &&
         "split chunked 0\\r\\n\\r\\n must complete via the sliding tail");
  printf("  [PASS] split chunked 0\\r\\n\\r\\n across two reads -> complete\n");
}

/* ---- Case 4: a long stream of data with NO terminator never false-completes ---- */
static void
test_no_terminator_no_completion(void)
{
  struct tail_state ts = {{0}, 0};
  for (int i = 0; i < 50; i++) {
    assert(scan(&ts, "data: {\"choices\":[{\"delta\":{\"content\":\"tok\"}}]}\n\n") == 0 &&
           "data chunks without a terminator must never complete");
  }
  printf("  [PASS] 50 data chunks, no terminator -> no false completion\n");
}

/* ---- Case 5: the Bug-A scenario end to end (sse_active never set) ----
 * Read 1 = status line + a header that is NOT "Content-Type: text/event-stream"
 * (so the :1157 sniff would never flip sse_active), the body arrives in
 * fragments, and the [DONE] terminator straddles the final two reads. The
 * windowed detector — the only completion path on the sse_active==0 branch —
 * must still complete. */
static void
test_bug_a_fragmented_no_content_type(void)
{
  struct tail_state ts = {{0}, 0};

  /* read 1: status line + chunked header; Content-Type fragmented to a later seg */
  assert(scan(&ts, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n") == 0);
  /* read 2: rest of headers — Content-Type lands here, AFTER the sniff window */
  assert(scan(&ts, "Content-Type: text/event-stream\r\n\r\n") == 0);
  /* reads 3..N: streamed tokens */
  assert(scan(&ts, "data: {\"delta\":\"a\"}\n\n") == 0);
  assert(scan(&ts, "data: {\"delta\":\"b\"}\n\n") == 0);
  /* final terminator split across the last two reads */
  assert(scan(&ts, "data: [DON") == 0);
  assert(scan(&ts, "E]\n\n") != 0 &&
         "completion must fire on the sse_active==0 path even with a "
         "fragmented Content-Type and a split terminator");
  printf("  [PASS] Bug-A fragmented Content-Type + split [DONE] -> complete\n");
}

/* --- (RESOLVED) graceful-[DONE] safety-net predicate ----
 * pd_should_graceful_complete() decides whether a decode-streaming SSE connection
 * whose backend leg went silent (vLLM dropped its closing "data: [DONE]") should
 * be force-completed with a synthesized terminator. The load-bearing property is
 * that the decision is gated on the LAST-BACKEND-BYTE timestamp, NOT
 * wall-clock-since-start — so a slow-but-still-streaming response is never
 * truncated. The helper does not even take a stream-start argument, which is the
 * structural guarantee. */

/* A synthetic "now"; absolute value is irrelevant, only deltas matter. */
#define NOW ((time_t)1000000)
#define CAP 25u

/* ---- Case 6: backend idle past the cap -> reap (graceful complete) ---- */
static void
test_graceful_idle_reaped(void)
{
  /* decode streaming, sse active, not yet terminated, last byte 30s ago, cap 25s */
  assert(pd_should_graceful_complete(1, 1, 0, NOW - 30, NOW, CAP) != 0 &&
         "30s backend-idle (> 25s cap) must reap");
  /* exact boundary: now - last == cap -> reap (>=) */
  assert(pd_should_graceful_complete(1, 1, 0, NOW - (time_t)CAP, NOW, CAP) != 0 &&
         "idle exactly at cap must reap (>=)");
  printf("  [PASS] backend-idle past cap -> graceful complete\n");
}

/* ---- Case 7 (THE truncation guard): slow-but-streaming is NOT reaped ----
 * A long-running generation that emitted a token 5s ago must survive, even though
 * the stream started long ago — proven by the helper carrying no start time at
 * all and gating purely on last_decode_ts. */
static void
test_graceful_slow_stream_not_reaped(void)
{
  assert(pd_should_graceful_complete(1, 1, 0, NOW - 5, NOW, CAP) == 0 &&
         "a stream that relayed a byte 5s ago must NOT be reaped");
  /* just under the boundary */
  assert(pd_should_graceful_complete(1, 1, 0, NOW - ((time_t)CAP - 1), NOW, CAP) == 0 &&
         "idle one second under cap must NOT reap");
  printf("  [PASS] slow-but-streaming (recent backend byte) -> not reaped\n");
}

/* ---- Case 8: all the guards individually suppress the reap ---- */
static void
test_graceful_guards(void)
{
  /* not in decode-streaming phase */
  assert(pd_should_graceful_complete(0, 1, 0, NOW - 30, NOW, CAP) == 0 &&
         "non-decode-streaming phase must not reap");
  /* not an SSE stream (would inject [DONE] into a non-SSE body) */
  assert(pd_should_graceful_complete(1, 0, 0, NOW - 30, NOW, CAP) == 0 &&
         "non-SSE stream must not get a synthesized [DONE]");
  /* the real [DONE] already arrived (stream_end_ts set) */
  assert(pd_should_graceful_complete(1, 1, NOW - 1, NOW - 30, NOW, CAP) == 0 &&
         "already-terminated stream must not be re-completed");
  /* no backend byte ever relayed -> no meaningful idle clock */
  assert(pd_should_graceful_complete(1, 1, 0, 0, NOW, CAP) == 0 &&
         "last_decode_ts==0 must not reap");
  /* safety-net disabled */
  assert(pd_should_graceful_complete(1, 1, 0, NOW - 30, NOW, 0u) == 0 &&
         "cap==0 disables the safety-net");
  printf("  [PASS] guards (phase/sse/terminated/no-byte/disabled) all suppress\n");
}

/* ---- Case 9: pd_http_resp_status — the origin-feed status glance ----
 * The vLLM sequential machine swallows the prefill response (a 5xx degrades
 * to decode-recompute), so the breaker's origin-error feed reads the status
 * straight off the accumulated response buffer with this parser. Malformed /
 * truncated / non-HTTP buffers must yield 0 ("status unknown" — fed as
 * NEITHER error nor success), never a fabricated code. */
static void
test_http_resp_status(void)
{
  static const char ok200[]  = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
  static const char err500[] = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
  static const char err503[] = "HTTP/1.0 503 Service Unavailable\r\n\r\n";
  static const char cli400[] = "HTTP/1.1 400 Bad Request\r\n\r\n";

  assert(pd_http_resp_status((const uint8_t *)ok200, sizeof(ok200) - 1) == 200);
  assert(pd_http_resp_status((const uint8_t *)err500, sizeof(err500) - 1) == 500);
  assert(pd_http_resp_status((const uint8_t *)err503, sizeof(err503) - 1) == 503);
  assert(pd_http_resp_status((const uint8_t *)cli400, sizeof(cli400) - 1) == 400);

  /* status line truncated mid-code: too short to trust */
  assert(pd_http_resp_status((const uint8_t *)"HTTP/1.1 50", 11) == 0 &&
         "truncated status line must be status-unknown");
  /* not an HTTP response at all (e.g. a raw JSON error body) */
  assert(pd_http_resp_status((const uint8_t *)"{\"error\":1}", 11) == 0 &&
         "non-HTTP buffer must be status-unknown");
  /* non-digit where the code belongs */
  assert(pd_http_resp_status((const uint8_t *)"HTTP/1.1 OK 200\r\n", 17) == 0 &&
         "non-numeric code must be status-unknown");
  /* out-of-range 3-digit code */
  assert(pd_http_resp_status((const uint8_t *)"HTTP/1.1 999 Nope\r\n", 19) == 0 &&
         "out-of-range code must be status-unknown");
  /* NULL / empty */
  assert(pd_http_resp_status(NULL, 64) == 0);
  assert(pd_http_resp_status((const uint8_t *)"", 0) == 0);
  printf("  [PASS] pd_http_resp_status: codes parsed, malformed -> unknown\n");
}

int
main(void)
{
  printf("test_pd_complete: load-path (windowed completion + graceful [DONE])\n");
  test_done_whole_packet();
  test_done_split_across_reads();
  test_chunked_terminator_split();
  test_no_terminator_no_completion();
  test_bug_a_fragmented_no_content_type();
  test_graceful_idle_reaped();
  test_graceful_slow_stream_not_reaped();
  test_graceful_guards();
  test_http_resp_status();
  printf("ALL PASS (test_pd_complete)\n");
  return 0;
}
