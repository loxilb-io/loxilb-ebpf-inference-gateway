/* sockproxy_pd_core.c - machine-agnostic P/D dialect core
 *
 * Engine-neutral services shared by every dialect: dialect resolution
 * (pd_engine → ops table), Content-Length fixup, and the
 * [PD_DECISION]/frame-mismatch instruments. The per-engine machines live in
 * sockproxy_pd_vllm.c (sequential) and sockproxy_pd_sglang.c (dual
 * dispatch); the HTTP engine reaches them only through the pd_dialect_ops
 * pointer cached on the epval (see sockproxy_pd.h).
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <openssl/ssl.h>

#include "uthash.h"
#include "log.h"
#include "picohttpparser.h"
#include "llhttp.h"
#include "sockproxy.h"
#include "sockproxy_pd.h"
#include "sockproxy_json.h"
#include "sockproxy_ai_admit.h"
#include "sockproxy_internal.h"
#include "sockproxy_hc.h"

static pthread_once_t pd_body_limit_once = PTHREAD_ONCE_INIT;
static size_t pd_body_limit = SP_JSON_INSPECT_MAX;

static void
pd_read_body_limit(void)
{
  const char *value = getenv("LLB_PD_MAX_BODY_BYTES");
  char *end;
  unsigned long long limit;

  if (value && *value) {
    errno = 0;
    limit = strtoull(value, &end, 10);
    if (value[0] < '0' || value[0] > '9' || *end || errno ||
        limit == 0 || limit > SP_JSON_INSPECT_MAX) {
      log_error("Invalid LLB_PD_MAX_BODY_BYTES='%s'; using %u bytes",
                value, (unsigned)SP_JSON_INSPECT_MAX);
    } else {
      pd_body_limit = (size_t)limit;
    }
  }
  log_info("Native P/D request body limit: %zu bytes (LLB_PD_MAX_BODY_BYTES)",
           pd_body_limit);
}

size_t
pd_max_request_body_bytes(void)
{
  pthread_once(&pd_body_limit_once, pd_read_body_limit);
  return pd_body_limit;
}


int
pd_check_request_body(proxy_fd_ent_t *pfe)
{
  const char *error = NULL;
  const char *detail = NULL;
  uint16_t status = 413;
  size_t limit = pd_max_request_body_bytes();
  size_t content_length = pfe->http_pipelined ? pfe->http_first_content_length :
                                              pfe->http_content_length;
  uint8_t media = pfe->http_pipelined ? pfe->http_first_body_media : pfe->http_body_media;
  uint8_t chunked = pfe->http_pipelined ? pfe->http_first_chunked : pfe->json_guard_chunked;
  const uint8_t *head_end = memmem(pfe->rcvbuf, pfe->rcv_off, "\r\n\r\n", 4);
  size_t body_len = head_end ? pfe->rcv_off - (size_t)(head_end + 4 - pfe->rcvbuf) : 0;
  /* The receive buffer may also contain a pipelined request. Only the
   * current message's declared body belongs to this byte limit. */
  if (!chunked && body_len > content_length)
    body_len = content_length;

  if (pfe->http_pipelined) {
    status = 400;
    error = "pd_pipelining_unsupported";
    detail = "send one P/D request at a time on a keep-alive connection";
  } else if ((content_length || chunked) &&
      !(media & SP_H1_MEDIA_JSON)) {
    status = 415;
    error = "pd_body_unsupported_media";
    detail = "native prefill/decode requires an application/json request body";
  } else if (content_length > limit || body_len > limit) {
    error = "pd_body_too_large";
    detail = "request body exceeds the native prefill/decode byte limit";
  } else if (pfe->is_streamable || chunked) {
    error = "pd_body_unbufferable";
    detail = "native prefill/decode requires a complete buffered Content-Length body";
  } else if (content_length && body_len == content_length &&
             !pd_body_is_object(head_end + 4, body_len)) {
    status = 400;
    error = "invalid_json_body";
    detail = "native prefill/decode requires a JSON object";
  }
  if (error) {
    char body[320];
    int body_len_out = snprintf(body, sizeof(body),
        "{\"error\":\"%s\",\"detail\":\"%s\",\"max_body_bytes\":%zu}\r\n",
        error, detail, limit);
    char response[512];
    int len = snprintf(response, sizeof(response),
        "HTTP/1.1 %u %s\r\n"
        "Content-Type: application/json\r\nContent-Length: %d\r\n"
        "Connection: close\r\n\r\n%s",
        status, status == 415 ? "Unsupported Media Type" :
                status == 400 ? "Bad Request" : "Payload Too Large",
        body_len_out, body);
    size_t unread = content_length > body_len ? content_length - body_len :
                    chunked && !pfe->http_pok ? 4 * 1024 * 1024 : 0;
    fc_permit_release(&pfe->fc);
    sp_pd_send_refusal(pfe, AI_GW_STAGE_FRAMING, status, error,
                        response, (size_t)len, unread);
    return -1;
  }
  return 0;
}

int
pd_prepare_failed(proxy_fd_ent_t *pfe)
{
  static const char body[] =
      "{\"error\":\"pd_prepare_failed\","
      "\"detail\":\"native prefill/decode request preparation failed\"}\r\n";
  char response[512];
  int len = snprintf(response, sizeof(response),
      "HTTP/1.1 500 Internal Server Error\r\n"
      "Content-Type: application/json\r\nContent-Length: %zu\r\n"
      "Connection: close\r\n\r\n%s", sizeof(body) - 1, body);
  pd_cleanup(pfe);
  fc_permit_release(&pfe->fc);
  pfe->pd_phase = PD_PHASE_ERROR;
  sp_pd_send_refusal(pfe, AI_GW_STAGE_FRAMING, 500, "pd_prepare_failed",
                      response, (size_t)len, 0);
  pfe->lb_err_body_sent = 1;
  return -1;
}

void
pd_request_usage_prepare(proxy_fd_ent_t *pfe, proxy_epval_t *epval)
{
  if (!epval || !epval->ai_gw_mode || epval->mcp_stateless ||
      pfe->odir != 0 || pfe->is_streamable || pfe->json_guard_chunked ||
      pfe->http_pipelined ||
      pfe->http_content_length == 0)
    return;
  uint8_t *head = memmem(pfe->rcvbuf, pfe->rcv_off, "\r\n\r\n", 4);
  if (!head)
    return;
  size_t hdr_len = (size_t)(head + 4 - pfe->rcvbuf);
  size_t body_len = pfe->http_content_length;
  if (pfe->rcv_off - hdr_len < body_len)
    return;
  char *body = (char *)pfe->rcvbuf + hdr_len;
  hc_note_stream(pfe, json_stream_flag(body, body_len));
  size_t new_len = body_len;
  int injected = inject_include_usage(body, body_len, SP_SOCK_MSG_LEN - hdr_len, &new_len);
  pfe->usage_est_prompt = (uint32_t)estimate_prompt_tokens(body, new_len);
  if (injected == 0) {
    pfe->rcv_off = hdr_len + new_len;
    pd_update_content_length(pfe->rcvbuf, &pfe->rcv_off, SP_SOCK_MSG_LEN, new_len);
    pfe->http_content_length = new_len;
    pfe_rcv_note(pfe);
  }
}

int
pd_prepare_before_connect(proxy_fd_ent_t *pfe, proxy_epval_t *epval)
{
  if (pfe->pd_sg_active && pfe->pd_saved_body) {
    uint8_t *head = memmem(pfe->rcvbuf, pfe->rcv_off, "\r\n\r\n", 4);
    if (!head)
      return pd_prepare_failed(pfe);
    size_t hdr_len = (size_t)(head + 4 - pfe->rcvbuf);
    if (pfe->pd_saved_body_len > SP_SOCK_MSG_LEN - hdr_len)
      return pd_prepare_failed(pfe);
    memcpy(pfe->rcvbuf + hdr_len, pfe->pd_saved_body, pfe->pd_saved_body_len);
    pfe->http_content_length = pfe->pd_saved_body_len;
    pfe->rcv_off = hdr_len + pfe->pd_saved_body_len;
    pd_update_content_length(pfe->rcvbuf, &pfe->rcv_off,
                             SP_SOCK_MSG_LEN, pfe->pd_saved_body_len);
    pd_free_claim(&pfe->pd_saved_body);
    pfe->pd_saved_body_len = 0;
    pfe->pd_sg_active = 0;
  }
  pd_request_usage_prepare(pfe, epval);
  uint8_t *head = memmem(pfe->rcvbuf, pfe->rcv_off, "\r\n\r\n", 4);
  if (!head || !epval->pd_ops || !epval->pd_ops->prepare_request)
    return pd_prepare_failed(pfe);
  size_t hdr_len = (size_t)(head + 4 - pfe->rcvbuf);
  if (!pfe->http_content_length || pfe->rcv_off - hdr_len < pfe->http_content_length)
    return pd_prepare_failed(pfe);
  int rc = epval->pd_ops->prepare_request(pfe, epval, hdr_len,
                  pfe->rcvbuf + hdr_len, pfe->http_content_length);
  if (rc < 0)
    return rc;
  if (pfe->pd_phase != PD_PHASE_PREFILL_SENDING && !pfe->pd_sg_active)
    return pd_prepare_failed(pfe);
  return 0;
}

/* Wire kv_engine_type → PD_ENGINE_*. Values are equal by construction for
 * the engines the control plane emits today (both sides generate from the
 * same manifest — sockproxy_pd_ids.h). An unknown/future value is STRICT:
 * it maps to PD_ENGINE_INVALID, never silently to vLLM — applying another
 * engine's dialect to a peer that cannot speak it is a wire-corruption
 * class, and gateway-side admission already refuses unknown engines, so
 * this path is the last-line fail-closed, not a working degrade. */
uint8_t
pd_engine_from_kv_engine_type(uint8_t kv_engine_type)
{
  switch (kv_engine_type) {
  case PD_ENGINE_VLLM:
    return PD_ENGINE_VLLM;
  case PD_ENGINE_SGLANG:
    return PD_ENGINE_SGLANG;
  case PD_ENGINE_TRTLLM:
    return PD_ENGINE_TRTLLM;
  default:
    return PD_ENGINE_INVALID;
  }
}

/* Resolve an engine's dialect ops table. Unknown values — including
 * PD_ENGINE_INVALID from the mapper above — resolve to NULL: the callers
 * treat a NULL table as "P/D orchestration must not activate" (plain L7
 * forwarding still works via the pd_dialect_plain fallback in
 * proxy_usage_ops). */
const pd_dialect_ops_t *
pd_dialect_resolve(uint8_t pd_engine)
{
  switch (pd_engine) {
  case PD_ENGINE_VLLM:
    return &pd_dialect_vllm;
  case PD_ENGINE_SGLANG:
    return &pd_dialect_sglang;
  case PD_ENGINE_TRTLLM:
    /* Sequential ctx-first disaggregation: own context-splice rewrite,
     * everything else riding the vLLM machine (sockproxy_pd_trtllm.c). */
    return &pd_dialect_trtllm;
  default:
    return NULL;
  }
}

/* Shared OpenAI-convention usage extractor. Every supported engine reports
 * token usage the same way (verified live across llama.cpp, vLLM P/D,
 * SGLang P/D and TensorRT-LLM: usage rides the final pre-[DONE] SSE chunk
 * under stream_options.include_usage, or the body object non-streaming, and
 * the client-visible/decode stream always carries prompt_tokens), so all
 * dialect profiles bind this one parser. */
int
pd_usage_extract_openai(struct proxy_fd_ent *pfe, const uint8_t *buf,
                        size_t len, int *prompt_tokens, int *completion_tokens)
{
  (void)pfe;
  return extract_usage_tokens((const char *)buf, len, prompt_tokens,
                              completion_tokens);
}

/* Plain-LB profile: AI-gateway rules with no engine dialect (no
 * kv_engine_type) still account tokens; every P/D orchestration op stays
 * NULL. */
const pd_dialect_ops_t pd_dialect_plain = {
  .name = "plain",
  .extract_usage = pd_usage_extract_openai,
};

/* Update Content-Length header in HTTP request buffer.
 * Searches for "Content-Length:" header and replaces the value with new_body_len.
 * Uses memmem() + memmove() pattern (same as PII masking).
 * Returns 0 on success, -1 on error. */
int
pd_update_content_length(uint8_t *buf, size_t *buf_len, size_t buf_capacity,
                         size_t new_body_len)
{
  uint8_t *headers_end = memmem(buf, *buf_len, "\r\n\r\n", 4);
  if (!headers_end) return -1;

  size_t headers_size = (size_t)(headers_end + 4 - buf);

  char *cl_start = memmem(buf, headers_size, "Content-Length:", 15);
  if (!cl_start) {
    cl_start = memmem(buf, headers_size, "content-length:", 15);
  }
  if (!cl_start) return -1;

  char *value_start = cl_start + 15;
  while (value_start < (char *)headers_end && *value_start == ' ') value_start++;
  char *value_end = value_start;
  while (value_end < (char *)headers_end && *value_end >= '0' && *value_end <= '9') value_end++;

  char new_val[32];
  int new_val_len = snprintf(new_val, sizeof(new_val), "%zu", new_body_len);
  int old_val_len = (int)(value_end - value_start);
  int shift = new_val_len - old_val_len;

  if ((ssize_t)*buf_len + shift > (ssize_t)buf_capacity) {
    return -1;
  }

  if (shift != 0) {
    size_t tail = *buf_len - (size_t)(value_end - (char *)buf);
    memmove(value_end + shift, value_end, tail);
  }
  memcpy(value_start, new_val, new_val_len);
  *buf_len = (size_t)((ssize_t)*buf_len + shift);
  return 0;
}

/* ---------------------------------------------------------------------------
 * [FRAME_MISMATCH] framing-consistency instrument
 *
 * LOG-ONLY. Emits one [FRAME_MISMATCH] line at each request-forward site to
 * discriminate framing-corruption candidates:
 *   1. truncated/over-long forward  → decl_cl != body_bytes, deterministic
 *   2. CL-rewrite mismatch          → diverges only at the decode rewrite site
 *   3. buffer/locking race          → mismatch correlates with tid (worker)
 *
 * Fields:
 *   fd, method (parser-owned), decl_cl = pfe->http_content_length,
 *   hdr_len via memmem("\r\n\r\n") bounded by rcv_off, body_bytes =
 *   rcv_off - hdr_len, mismatch = (decl_cl > 0 && body_bytes != decl_cl),
 *   rcv_off, tid = pthread_self(), site=.
 *
 * memmem is bounded by *cur_len (never reads past the buffered
 * span). This is a diagnostic build aid; it does NOT alter forward behavior.
 * --------------------------------------------------------------------------- */
void
pd_frame_mismatch_log(proxy_fd_ent_t *pfe, const uint8_t *buf, size_t cur_len,
                      size_t declared_cl, const char *site)
{
  const uint8_t *he = memmem(buf, cur_len, "\r\n\r\n", 4);
  size_t hdr_len   = he ? (size_t)(he + 4 - buf) : 0;
  size_t body_bytes = (cur_len > hdr_len) ? cur_len - hdr_len : 0;
  int mismatch = (declared_cl > 0 && body_bytes != declared_cl);
  log_debug("[FRAME_MISMATCH] fd=%d method=%s decl_cl=%zu hdr_len=%zu body=%zu "
           "rcv_off=%zu mismatch=%d tid=%lu site=%s",
           pfe->fd,
           llhttp_method_name(llhttp_get_method(&pfe->parser)),
           declared_cl, hdr_len, body_bytes, cur_len, mismatch,
           (unsigned long)pthread_self(), site);
}
