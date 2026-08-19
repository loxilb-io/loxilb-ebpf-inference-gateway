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

#include "uthash.h"
#include "log.h"
#include "picohttpparser.h"
#include "llhttp.h"
#include "sockproxy.h"
#include "sockproxy_pd.h"

/* Wire kv_engine_type → PD_ENGINE_*. Values are equal by construction for
 * the engines the control plane emits today; unknown/future values degrade
 * to the sequential vLLM flavor (the machine with no injection prerequisite)
 * rather than to a dialect whose contract the peer engine cannot speak. */
uint8_t
pd_engine_from_kv_engine_type(uint8_t kv_engine_type)
{
  switch (kv_engine_type) {
  case PD_ENGINE_SGLANG:
    return PD_ENGINE_SGLANG;
  case PD_ENGINE_TRTLLM:
    return PD_ENGINE_TRTLLM;
  case PD_ENGINE_VLLM:
  default:
    return PD_ENGINE_VLLM;
  }
}

const pd_dialect_ops_t *
pd_dialect_resolve(uint8_t pd_engine)
{
  switch (pd_engine) {
  case PD_ENGINE_SGLANG:
    return &pd_dialect_sglang;
  case PD_ENGINE_TRTLLM:
    /* Sequential ctx-first disaggregation — rides the vLLM machine until a
     * dedicated sockproxy_pd_trtllm.c table earns its place. */
    return &pd_dialect_vllm;
  case PD_ENGINE_VLLM:
  default:
    return &pd_dialect_vllm;
  }
}

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
  log_info("[FRAME_MISMATCH] fd=%d method=%s decl_cl=%zu hdr_len=%zu body=%zu "
           "rcv_off=%zu mismatch=%d tid=%lu site=%s",
           pfe->fd,
           llhttp_method_name(llhttp_get_method(&pfe->parser)),
           declared_cl, hdr_len, body_bytes, cur_len, mismatch,
           (unsigned long)pthread_self(), site);
}
