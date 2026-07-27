/* sockproxy_pd_leak.h - Pure, unit-testable primitives for the 
 * P/D streaming-completion connection-leak fix.
 *
 * This header factors the two testable primitives the fixes depend on
 * into PURE, self-contained `static inline` functions that carry NO dependency
 * on the global proxy machinery, so a unit TU (test_pd_leak.c) can include them
 * directly the way test_pd_rewriter includes sockproxy_pd.c, while the shipped
 * code in sockproxy_http.c / sockproxy_health.c includes the SAME helpers (no
 * copy, no drift).
 *
 *   (1) pd_detect_http_msg_end(buf, len)
 *         Fragmentation-safe HTTP message-end detector. Returns nonzero when the
 *         already-accumulated buffer contains a complete HTTP message end:
 *           - the chunked transfer-coding last-chunk terminator "0\r\n\r\n", OR
 *           - an SSE "[DONE]" done-marker (the in-tree PROXY_SSE_DONE_STR1/2
 *             semantics).
 * (prefill, sockproxy_http.c:~1099) and (non-SSE decode,
 *         sockproxy_http.c:~1296) call this beside the existing Content-Length
 *         check so chunked / CL-less responses still complete.
 *
 *         V5 Input Validation: the scan is bounded by the caller-supplied `len`
 *         ONLY — it NEVER reads past buf+len. Callers pass the FULL accumulated
 *         heap buffer (pd_prefill_resp_buf / the decode resp buffer) plus its
 *         current length; because the buffer is accumulated, a single bounded
 *         memmem over the whole buffer is correct and is the simplest correct
 *         generalization of the C-5 sliding-window scanner.
 *
 *   (2) pd_teardown_legs(pfe, notify_del, ns)
 *         Encodes the safe two-leg teardown SEQUENCE from
 *         force_close_endpoint_connections() (sockproxy_health.c:133-150):
 *         deregister + close + zero each backend rfd[], then the client fd.
 * the Wave 1 reaper sites ( in
 *         sockproxy_health.c) call this helper and then SEPARATELY invoke the
 *         production fd-context release (the proxy_release_*fd_ctx machinery).
 *
 *         The production fd-context release is INTENTIONALLY NOT called here: it
 *         already re-enters pd_cleanup() (sockproxy_conn.c:758), so folding it
 *         into this helper would create the pd_cleanup re-entrancy / double-free
 *         hazard (RESEARCH Pitfall 1). Keeping it out also gives this helper zero
 *         dependency on the proxy machinery, which is what makes it unit-testable.
 *
 * Build: header-only. Production includes it after sockproxy_proto.h (so the
 * real `struct proxy_fd_ent` is visible). The unit TU defines
 * SOCKPROXY_PD_LEAK_FAKE_ENT before including, supplying its own fake struct
 * (the test_pd_cache_aware.c stub-struct precedent).
 */
#ifndef SOCKPROXY_PD_LEAK_H
#define SOCKPROXY_PD_LEAK_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE   /* memmem() */
#endif

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>     /* time_t */
#include <unistd.h>   /* close() */

#ifdef __cplusplus
extern "C" {
#endif

/* When the test TU defines SOCKPROXY_PD_LEAK_FAKE_ENT it supplies its own
 * `struct proxy_fd_ent { int fd; int rfd[...]; int n_rfd; };` BEFORE including
 * this header. Otherwise we rely on the real struct from sockproxy_proto.h,
 * which production TUs include ahead of this header; a forward declaration keeps
 * the pointer-typed signature valid even if only the forward decl is visible. */
#ifndef SOCKPROXY_PD_LEAK_FAKE_ENT
struct proxy_fd_ent;
#endif

/* The chunked transfer-coding last-chunk terminator: a zero-length chunk
 * ("0\r\n") followed by the trailing CRLF that closes the message. */
#define PD_CHUNKED_LAST_CHUNK     "0\r\n\r\n"
#define PD_CHUNKED_LAST_CHUNK_LEN 5

/* SSE "[DONE]" done-markers — mirrors PROXY_SSE_DONE_STR1/2 in sockproxy_http.c.
 * We accept either spacing variant a vLLM/OpenAI-style SSE stream emits. */
#define PD_SSE_DONE_STR1          "data:[DONE]"
#define PD_SSE_DONE_STR2          "data: [DONE]"

/*
 * pd_detect_http_msg_end - return nonzero iff [buf, buf+len) contains a complete
 * HTTP message end (chunked last-chunk terminator OR an SSE [DONE] marker).
 *
 * The scan is bounded strictly by `len`; memmem never reads past buf+len. A NULL
 * buffer or len shorter than the shortest terminator yields 0 (not complete).
 */
static inline int
pd_detect_http_msg_end(const uint8_t *buf, size_t len)
{
  if (buf == NULL || len == 0) {
    return 0;
  }

  /* Chunked transfer-coding: the last-chunk "0\r\n\r\n" terminator. Bounded by
   * `len` only (V5: never trust / scan beyond the supplied length). */
  if (len >= PD_CHUNKED_LAST_CHUNK_LEN &&
      memmem(buf, len, PD_CHUNKED_LAST_CHUNK, PD_CHUNKED_LAST_CHUNK_LEN) != NULL) {
    return 1;
  }

  /* SSE done-marker: "data:[DONE]" / "data: [DONE]" (token form, spacing-tolerant).
   * Same bounded scan over the accumulated buffer. */
  {
    size_t done1_len = sizeof(PD_SSE_DONE_STR1) - 1;
    size_t done2_len = sizeof(PD_SSE_DONE_STR2) - 1;
    if (len >= done1_len &&
        memmem(buf, len, PD_SSE_DONE_STR1, done1_len) != NULL) {
      return 1;
    }
    if (len >= done2_len &&
        memmem(buf, len, PD_SSE_DONE_STR2, done2_len) != NULL) {
      return 1;
    }
  }

  return 0;
}

/* PD_MSG_END_TAIL_KEEP - bytes of trailing context carried between successive
 * reads so a message-end terminator that straddles two TCP segments is still
 * detected. Must be >= the longest terminator pd_detect_http_msg_end matches:
 *   strlen("data: [DONE]") = 12, strlen("0\r\n\r\n") = 5.
 * 20 matches the in-tree PROXY_SSE_TAIL_KEEP (sockproxy_http.c) and the
 * proxy_fd_ent.sse_tail[20] field this rides on, with headroom for the SSE
 * done-line's trailing "\n\n". */
#define PD_MSG_END_TAIL_KEEP 20

/*
 * pd_scan_msg_end_window - fragmentation-safe HTTP message-end detector.
 *
 * pd_detect_http_msg_end() sees only ONE packet, so a terminator split across two
 * reads (e.g. "...data: [DO" | "NE]\n\n") is missed. This wrapper keeps a sliding
 * tail of the last PD_MSG_END_TAIL_KEEP bytes in caller-owned state (`tail` /
 * `*tail_len` — e.g. proxy_fd_ent.sse_tail / .sse_tail_len) and scans BOTH the
 * overlap window (old tail + new data tail) AND the full current packet, so a
 * terminator is detected wherever it lands:
 *   - straddling the read boundary  -> caught by the overlap window;
 *   - wholly inside this packet      -> caught by the full-packet scan (the
 *     window can be shorter than the packet when len > PD_MSG_END_TAIL_KEEP).
 *
 * Caller-state contract: `tail` points to a buffer of >= PD_MSG_END_TAIL_KEEP
 * bytes; `*tail_len` is 0 on the first call for a connection and is maintained
 * here thereafter. Either pointer may be NULL, degrading to a single-packet scan
 * (correct, just not fragmentation-safe). Bounded strictly by `len`; never reads
 * past msg+len. Returns nonzero iff a complete HTTP message end is present.
 *
 * T3: on the sse_active==0 stall path this is the ONLY decode
 * completion detector, and a split terminator under load is exactly what stranded
 * the decode leg with the single-packet scan.
 */
static inline int
pd_scan_msg_end_window(uint8_t *tail, uint8_t *tail_len,
                       const uint8_t *msg, size_t len)
{
  if (msg == NULL || len == 0) {
    return 0;
  }

  uint8_t window[PD_MSG_END_TAIL_KEEP * 2];
  uint8_t old_len = (tail != NULL && tail_len != NULL &&
                     *tail_len <= PD_MSG_END_TAIL_KEEP) ? *tail_len : 0;
  uint8_t new_len = (len < PD_MSG_END_TAIL_KEEP) ? (uint8_t)len
                                                 : PD_MSG_END_TAIL_KEEP;

  if (old_len > 0) {
    memcpy(window, tail, old_len);
  }
  memcpy(window + old_len, msg + (len - new_len), new_len);
  size_t window_len = (size_t)old_len + new_len;

  /* Advance the sliding tail to the end of the current packet. */
  if (tail != NULL && tail_len != NULL) {
    memcpy(tail, msg + (len - new_len), new_len);
    *tail_len = new_len;
  }

  if (pd_detect_http_msg_end(window, window_len)) {
    return 1;
  }
  if (pd_detect_http_msg_end(msg, len)) {
    return 1;
  }
  return 0;
}

/* PROXY_PD_DECODE_IDLE_CAP_SEC - default backend-idle window (seconds) after which
 * a decode-streaming SSE connection whose backend leg has gone silent is reaped
 * with a SYNTHESIZED graceful "data: [DONE]\n\n" terminator instead of hanging.
 *
 * (RESOLVED): vLLM's P/D-disagg path FINISHES generation but omits the
 * closing "data: [DONE]" SSE chunk for ~2.5% of streams under concurrency (loxilb
 * exonerated — its :1198 scanner completes 100% of TERMINATED streams). Without a
 * terminator the decode leg never reaches PD_PHASE_COMPLETE and the client hangs
 * until a wall-clock backstop ( 502 @120s / 504 @180s) injects a
 * malformed HTTP status line into a live SSE body. This safety-net converts that
 * forever-hang into a protocol-correct completion.
 *
 * Chosen ~25s: a healthy decode stream emits a token every few hundred ms, so 25s
 * of TOTAL backend silence strongly implies generation is over. Gated on the
 * LAST-BACKEND-BYTE timestamp (pd_last_decode_ts), NOT wall-clock-since-start, so a
 * legitimately slow-but-still-streaming response is never truncated. */
#ifndef PROXY_PD_DECODE_IDLE_CAP_SEC
#define PROXY_PD_DECODE_IDLE_CAP_SEC 25
#endif

/*
 * pd_should_graceful_complete - decide whether a P/D decode-streaming connection
 * should be force-completed with a synthesized SSE [DONE] terminator.
 *
 * Pure predicate (no proxy machinery) so the reaper's decision is unit-testable.
 * Returns nonzero IFF ALL hold:
 *   - is_decode_streaming : pd_phase == PD_PHASE_DECODE_STREAMING (the only phase
 *     where the client has already received "200 OK" + SSE chunks, making a
 *     synthesized "data: [DONE]" the protocol-correct termination);
 *   - sse_active          : this is a live SSE stream (not a non-SSE JSON body —
 *     injecting "data: [DONE]" into a non-SSE body would be garbage);
 *   - stream_end_ts == 0  : the real [DONE] has not already been seen;
 *   - last_decode_ts  > 0 : at least one backend byte was relayed (we have a
 *     meaningful idle clock to measure against);
 *   - idle_cap_sec    > 0 : the safety-net is enabled;
 *   - (now - last_decode_ts) >= idle_cap_sec : the BACKEND leg has been silent
 *     past the cap. Measuring from last_decode_ts (refreshed per relayed byte),
 *     NOT from stream_start_ts, is what guarantees a still-streaming response is
 *     not truncated.
 */
static inline int
pd_should_graceful_complete(int is_decode_streaming, int sse_active,
                            time_t stream_end_ts, time_t last_decode_ts,
                            time_t now, uint32_t idle_cap_sec)
{
  if (!is_decode_streaming) {
    return 0;
  }
  if (!sse_active) {
    return 0;
  }
  if (stream_end_ts != 0) {
    return 0;
  }
  if (last_decode_ts <= 0) {
    return 0;
  }
  if (idle_cap_sec == 0) {
    return 0;
  }
  return (now - last_decode_ts) >= (time_t)idle_cap_sec;
}

/*
 * pd_teardown_legs - safe two-leg teardown of a P/D connection.
 *
 * Encodes the close SEQUENCE from force_close_endpoint_connections()
 * (sockproxy_health.c:133-150) WITHOUT calling the production fd-context
 * release machinery:
 *   - for each backend leg pfe->rfd[i] (i < pfe->n_rfd) that is > 0:
 *       notify_del(ns, rfd[i], 0); close(rfd[i]); rfd[i] = -1;
 *   - then if the client fd pfe->fd > 0:
 *       notify_del(ns, pfe->fd, 0); close(pfe->fd); pfe->fd = -1;
 *
 * `notify_del` is the notifier-deregister callback (production passes a thunk
 * over notify_delete_ent; the unit TU passes a recording fake). It may be NULL,
 * in which case deregistration is skipped (close still happens). The caller —
 * the Wave 1 reaper — is responsible for invoking the production fd-context
 * release (pfe, 1) AFTER this helper returns (kept out here to avoid the
 * pd_cleanup re-entrancy hazard; see header banner).
 *
 * Returns the number of fds closed (backend legs + client), for assertions.
 */
static inline int
pd_teardown_legs(struct proxy_fd_ent *pfe,
                 int (*notify_del)(void *ns, int fd, int arg),
                 void *ns)
{
  int closed = 0;

  if (pfe == NULL) {
    return 0;
  }

  for (int i = 0; i < pfe->n_rfd; i++) {
    if (pfe->rfd[i] > 0) {
      if (notify_del != NULL) {
        notify_del(ns, pfe->rfd[i], 0);
      }
      close(pfe->rfd[i]);
      pfe->rfd[i] = -1;
      closed++;
    }
  }

  if (pfe->fd > 0) {
    if (notify_del != NULL) {
      notify_del(ns, pfe->fd, 0);
    }
    close(pfe->fd);
    pfe->fd = -1;
    closed++;
  }

  return closed;
}

#ifdef __cplusplus
}
#endif

#endif /* SOCKPROXY_PD_LEAK_H */
