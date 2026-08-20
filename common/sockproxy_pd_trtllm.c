/* sockproxy_pd_trtllm.c - TensorRT-LLM P/D disaggregation dialect
 *
 * Dialect: TRT-LLM sequential context-first disaggregation — the vLLM
 *   machine SHAPE (prefill probe → buffered response → decode re-dispatch,
 *   sockproxy_pd_vllm.c) with a different body dialect, so this table rides
 *   the sequential machine and overrides only the request rewrite. The
 *   body-surgery functions (pd_trt_prepare_prefill_body /
 *   pd_trt_extract_disagg_params / pd_trt_prepare_decode_body) live in
 *   sockproxy_pd.c; the machine selects them by epval->pd_engine.
 * Contract validated against: TensorRT-LLM 1.3.0rc24 (disaggregated_params
 *   splice, context_only/generation_only request_type, extra="forbid" on
 *   unknown fields, engine-forced context token cap — hence NO max_tokens
 *   rewrite on the prefill leg).
 * Known caps: shares the 64KB pd_kv_params buffer for the extracted
 *   disaggregated_params span (encoded_opaque_state measures KiB-scale;
 *   overflow degrades to decode-side recompute, never a request failure).
 * Early exit: a context response whose finish_reason is neither "length"
 *   nor "not_finished" already finished the request in the context step —
 *   the buffered response is relayed to the client and the decode leg
 *   skipped entirely (better than the reference proxy, which drops the
 *   content). Counted in global_stats.pd_trt_ctx_early_exit.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>

#include "uthash.h"
#include "log.h"
#include "notify.h"
#include "picohttpparser.h"
#include "llhttp.h"
#include "sockproxy_ai_gw.h"
#include "sockproxy.h"
#include "sockproxy_pd.h"
#include "sockproxy_internal.h"

/* Best-effort client write — the pd_sg 4xx relay-verbatim idiom (bounded,
 * small responses; the context response is a one-step completion). */
static void
pd_trt_client_write(proxy_fd_ent_t *client_pfe, const uint8_t *buf,
                    size_t len)
{
  if (!client_pfe || client_pfe->fd <= 0 || !buf || len == 0) return;
  if (client_pfe->ssl) {
    SSL_write(client_pfe->ssl, buf, (int)len);
  } else {
    send(client_pfe->fd, buf, len, MSG_DONTWAIT | MSG_NOSIGNAL);
  }
}

/* Relay the buffered context response to the client and complete the P/D
 * flow without a decode leg. A client that asked for streaming gets a
 * minimal one-chunk SSE re-frame of the response body + [DONE]; everyone
 * else (and any chunked/headerless corner) gets the buffered response
 * verbatim. Runs on the prefill leg's worker with no proxy locks held
 * (same context as the decode-init error sends at the call sites). */
void
pd_trt_early_exit_relay(struct proxy_fd_ent *client_pfe,
                        const uint8_t *resp, size_t resp_len,
                        int stream_requested)
{
  const uint8_t *he = NULL, *body = NULL;
  size_t hdr_len = 0, body_len = 0;
  int chunked = 0, sse_framed = 0;

  if (!client_pfe || !resp || resp_len == 0) return;

  atomic_fetch_add(&global_stats.pd_trt_ctx_early_exit, 1);

  he = memmem(resp, resp_len, "\r\n\r\n", 4);
  if (he) {
    hdr_len = (size_t)(he + 4 - resp);
    body = resp + hdr_len;
    body_len = resp_len - hdr_len;
    if (memmem(resp, hdr_len, "Transfer-Encoding: chunked", 26) ||
        memmem(resp, hdr_len, "transfer-encoding: chunked", 26)) {
      /* SSE re-framing would need de-chunking; the verbatim relay below is
       * still a complete, valid HTTP response. */
      chunked = 1;
    }
  }

  if (stream_requested && !chunked && body && body_len > 0) {
    static const char sse_hdr[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/event-stream\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: close\r\n"
        "\r\n"
        "data: ";
    static const char sse_tail[] = "\n\ndata: [DONE]\n\n";
    size_t out_len = (sizeof(sse_hdr) - 1) + body_len + (sizeof(sse_tail) - 1);
    uint8_t *out = malloc(out_len);
    if (out) {
      uint8_t *w = out;
      memcpy(w, sse_hdr, sizeof(sse_hdr) - 1);
      w += sizeof(sse_hdr) - 1;
      memcpy(w, body, body_len);
      w += body_len;
      memcpy(w, sse_tail, sizeof(sse_tail) - 1);
      pd_trt_client_write(client_pfe, out, out_len);
      free(out);
      sse_framed = 1;
    }
  }
  if (!sse_framed) {
    if (stream_requested) {
      log_warn("trt early exit: streaming client served the buffered "
               "context response verbatim (chunked=%d client_fd=%d)",
               chunked, client_pfe->fd);
    }
    pd_trt_client_write(client_pfe, resp, resp_len);
  }

  /* Success record with a zero-length decode leg; kv=0 — no transfer
   * params moved, the context step served the whole request. */
  {
    const char *model = proxy_effective_model(client_pfe);
    int64_t prefill_ms = 0;
    if (client_pfe->pd_prefill_start_ns > 0) {
      struct timespec _ts;
      clock_gettime(CLOCK_MONOTONIC, &_ts);
      uint64_t now_ns = (uint64_t)_ts.tv_sec * 1000000000ULL +
                        (uint64_t)_ts.tv_nsec;
      prefill_ms = (int64_t)((now_ns - client_pfe->pd_prefill_start_ns) /
                             1000000ULL);
    }
    llb_ai_pd_record((char *)model, prefill_ms, 0, 0, 0);
  }

  log_info("[PD_TRT_EARLY_EXIT] context response finished the request — "
           "relayed %zuB (stream=%d sse_framed=%d) client_fd=%d",
           resp_len, stream_requested, sse_framed, client_pfe->fd);

  client_pfe->pd_phase = PD_PHASE_COMPLETE;
  pd_cleanup(client_pfe);
}

/* --- Dialect ops --------------------------------------------------------- */

/* TRT-LLM context-leg rewrite via the shared sequential preparation:
 * stream→false + disaggregated_params splice, NO max_tokens rewrite. */
static int
pd_trt_prepare_request(struct proxy_fd_ent *pfe, struct proxy_epval *epval,
                       size_t hdr_len, const uint8_t *body, size_t body_len)
{
  return pd_seq_prepare_request(pfe, epval, hdr_len, body, body_len,
                                pd_trt_prepare_prefill_body);
}

const pd_dialect_ops_t pd_dialect_trtllm = {
  .name = "trtllm",
  .prepare_request = pd_trt_prepare_request,
  .dispatch = pd_vllm_dispatch,   /* sequential-machine forward, shared */
  .on_prefill_response = NULL,
  .on_leg_error = NULL,
  .collect_retry = NULL,
  .reap = NULL,
};
