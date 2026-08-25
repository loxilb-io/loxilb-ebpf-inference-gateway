/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 *
 * sockproxy_http.c — HTTP/HTTPS proxy core: header injection, endpoint transmit,
 * session management, HTTP parsing callbacks, P/D disaggregation, multiplexor,
 * per-fd I/O helpers, and the listen/active data path handlers.
 *
 * Extracted from sockproxy.c — see sockproxy_refactoring_plan.md.
 */
#define _GNU_SOURCE
#define HAVE_PROXY_EXTRA_DEBUG
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <assert.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <linux/tls.h>
#include <linux/tcp.h>
#include <fcntl.h>
#include <poll.h>
#include <limits.h>
#include <stdbool.h>
#include <dirent.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "log.h"
#include "notify.h"
#include "uthash.h"
#include "picohttpparser.h"
#include "llhttp.h"
#include "lxb_ring.h"
#include <bpf.h>
#include "common_pdi.h"
#include "llb_dpapi.h"
#include "sockproxy_ai_gw.h"
#include "sockproxy.h"
#include "sockproxy_pd.h"       /* P/D engine-dialect ops table */
#include "sockproxy_l7policy.h" /* l7_apply_req_filters + L7HDR_* ops */
#include "sockproxy_internal.h"
#include "sockproxy_metrics.h"
#include "sockproxy_routing.h"
#include "sockproxy_json.h"
#include "sockproxy_trace.h"
#ifdef HAVE_HTTP_TRACE
#include "lxb_catalog.h"
#include "lxb_traceparent.h"
#endif
#include "sockproxy_cache.h"
#include "sockproxy_lb.h"
#include "sockproxy_health.h"
#include "sockproxy_ssl.h"
#include "sockproxy_conn.h"
#include "sockproxy_ep.h"
#include "sockproxy_ktls.h"
#include "sockproxy_h2.h"
/* pure HTTP-message-end detector (chunked "0\r\n\r\n" /
 * SSE "[DONE]") shared with the unit TU. Included AFTER sockproxy.h so the real
 * `struct proxy_fd_ent` is in scope (the helper takes a proxy_fd_ent* in
 * pd_teardown_legs; pd_detect_http_msg_end here is buffer-only). */
#include "sockproxy_pd_leak.h"

#ifdef HAVE_MTLS
#include "sockproxy_mtls.h"
#endif

#define XXH_STATIC_LINKING_ONLY
#include "xxhash.h"

/* P/D body-rewrite + dual-dispatch helper declarations live in
 * sockproxy_pd.h (included above) next to the dialect ops table. */

/* AI Gateway CGO bridge */
extern void llb_ai_normal_session_hit(char *model_name);

/* PII Detection (: Dynamic Configuration) */
#ifdef HAVE_PII_DETECTION
#include <fnmatch.h>
#include "presidio_config.h"
#include "sockproxy_presidio.h"

/* PII initialization state (shared via sockproxy_http.h extern decls) */
_Atomic int g_presidio_initialized = 0;
int presidio_is_initialized(void) { return atomic_load(&g_presidio_initialized); }
void presidio_set_initialized(int initialized) { atomic_store(&g_presidio_initialized, initialized); }
#endif

/* LlamaFirewall AI Security Scanner */
#ifdef HAVE_LLAMAFIREWALL
#include "sockproxy_llamafirewall.h"
#include "llamafirewall_config.h"

/* LlamaFirewall initialization state (shared via sockproxy_http.h extern decls) */
_Atomic int g_llamafirewall_initialized = 0;
int llamafirewall_is_initialized(void) { return atomic_load(&g_llamafirewall_initialized); }
void llamafirewall_set_initialized(int initialized) { atomic_store(&g_llamafirewall_initialized, initialized); }
#endif

/* Private constants (not in header — internal to this TU only) */
#define PROXY_NUM_BURST_RX          1024
#define PROXY_MAX_CACHE_ENTRIES     200
#define PROXY_MAX_CACHE_SIZE        (16 * 1024 * 1024)  /* 16MB per connection */
/* commented-out earlier limit: #define PROXY_MAX_CACHE_ENTRIES 50 */
/* commented-out earlier limit: #define PROXY_MAX_CACHE_SIZE (512*1024) */

#include "sockproxy_http.h"  /* own header — after all deps; provides PROXY_SESSION_* */

/* Portable strnstr (needed by inject_forwarded_headers and url-matching) */
static const char *strnstr_portable(const char *haystack, const char *needle, size_t len) {
    size_t needle_len = strlen(needle);
    if (needle_len == 0) return haystack;
    if (len < needle_len) return NULL;
    for (size_t i = 0; i <= len - needle_len; i++) {
        if (strncmp(&haystack[i], needle, needle_len) == 0)
            return &haystack[i];
    }
    return NULL;
}

/* ---------------------------------------------------------------------------
 * pd_framing_v2 runtime feature-flag (REQ-R2 /, migration scaffold)
 *
 * Mirrors the kv_hash_debug_on() idiom (sockproxy_kv_exact.c:182-204) verbatim
 * in shape: a once-cached, atomic-init latch reading getenv("LLB_PD_FRAMING_V2")
 * exactly once, so the gate is read per-connection at zero hot-path cost.
 *
 * 0/unset  → byte-identical legacy behavior (the flag is a migration scaffold,
 *            NOT a behavior change — M1/M2 gate on it in later plans).
 * "1"      → the v2 (parser-owned) request/response framing path (wired later).
 *
 * Default MUST be OFF. As of this gate is DEFINED ONLY — it is not
 * consulted anywhere yet. Per Invariant 2 any future per-message framing
 * state goes on proxy_fd_ent (NOT on proxy_sync_event_t / llm_prefix_key_t),
 * which is not xSync-serialized (sockproxy.h pd_last_decode_ts precedent).
 * --------------------------------------------------------------------------- */
static _Atomic int llb_pd_framing_v2_initialized = 0;
static int llb_pd_framing_v2 = 0;

int
pd_framing_v2_on(void)
{
  int init = atomic_load_explicit(&llb_pd_framing_v2_initialized,
                                  memory_order_acquire);
  if (init) return llb_pd_framing_v2;
  const char *v = getenv("LLB_PD_FRAMING_V2");
  int on = (v && v[0] == '1' && v[1] == '\0') ? 1 : 0;
  llb_pd_framing_v2 = on;
  atomic_store_explicit(&llb_pd_framing_v2_initialized, 1,
                        memory_order_release);
  return on;
}

/* Test hook: force the pd_framing_v2 gate without setenv/unsetenv races in unit
 * tests (test_resp_framing.c) and the mismatched-flag HA variant. */
void
pd_framing_v2_test_set(int on)
{
  llb_pd_framing_v2 = on ? 1 : 0;
  atomic_store_explicit(&llb_pd_framing_v2_initialized, 1,
                        memory_order_release);
}

/* [FRAME_MISMATCH] instrument + pd_update_content_length moved to
 * sockproxy_pd_core.c; pd_initiate_decode / pd_retry_prefill (the vLLM
 * sequential machine) moved to sockproxy_pd_vllm.c — see sockproxy_pd.h. */

/* Internal forward declarations (file-scope only) */
/* SGLang machine entry points declared in sockproxy_pd.h. */
/* pd_cleanup declared in sockproxy_internal.h */
/* response-leg HTTP_RESPONSE parser path (pd_framing_v2).
 * Defined after handle_on_message_complete; forward-declared here for the
 * proxy_try_epxmit feed site (odir==1) which precedes the definitions. */
static int handle_resp_headers_complete(llhttp_t *parser);
static int handle_resp_body(llhttp_t *parser, const char *at, size_t length);
static int handle_resp_message_complete(llhttp_t *parser);

/**
 * Inject X-Forwarded-* headers into HTTP request before forwarding to backend
 *
 * Adds protocol awareness headers so backend knows original client protocol/host.
 * Required for HTTPS→HTTP proxying to prevent mixed content issues.
 *
 * Headers injected:
 * - X-Forwarded-Proto: https  (tells backend original protocol)
 * - X-Forwarded-Host: domain  (tells backend original hostname)
 *
 * @param buf     Buffer containing HTTP request (modified in-place)
 * @param buflen  Current length of data in buffer
 * @param bufsize Maximum buffer size (SP_SOCK_MSG_LEN)
 * @param is_ssl  1 if client connection is HTTPS, 0 if HTTP
 * @param host    Original Host header value (or NULL)
 * @return New length of buffer after injection, or -1 on error
 */
static ssize_t
inject_forwarded_headers(uint8_t *buf, size_t buflen, size_t bufsize,
                         int is_ssl, const char *host)
{
  // P7: Validate this is HTTP text data, not binary (check for HTTP method)
  if (buflen < 4 || (memcmp(buf, "GET ", 4) != 0 && 
                      memcmp(buf, "POST", 4) != 0 && 
                      memcmp(buf, "PUT ", 4) != 0 &&
                      memcmp(buf, "DELE", 4) != 0 &&
                      memcmp(buf, "HEAD", 4) != 0 &&
                      memcmp(buf, "PATC", 4) != 0)) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[BINARY_SKIP] Skipping header injection for non-HTTP data (first 4 bytes: %02x %02x %02x %02x)",
              buflen >= 4 ? buf[0] : 0, buflen >= 4 ? buf[1] : 0, 
              buflen >= 4 ? buf[2] : 0, buflen >= 4 ? buf[3] : 0);
#endif
    return buflen;  // Return unchanged - this is binary data
  }

  // P7: Skip injection for WebSocket upgrade requests (binary handshake data)
  if (strcasestr((char *)buf, "Connection: Upgrade") != NULL) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[WS_SKIP] Skipping header injection for WebSocket upgrade request");
#endif
    return 0;
  }
  char *headers_end;
  size_t header_insert_len = 0;
  char inject_buf[512];

  // Only inject if client connection was HTTPS
  if (!is_ssl) {
    return buflen;  // No modification needed for HTTP→HTTP
  }

  // Find end of headers (\r\n\r\n marker)
  headers_end = strstr((char *)buf, "\r\n\r\n");
  if (!headers_end) {
    // Malformed HTTP request - no header end marker
    log_trace("inject_forwarded_headers: No header end marker found");
    return buflen;  // Return unchanged
  }

  // SAFETY: Skip modification if Transfer-Encoding: chunked is present
  // (Rare for requests, but possible with POST/PUT uploads)
  // NOTE: This is for REQUEST chunking only. Response chunking is detected elsewhere.
  if (strcasestr((char *)buf, "Transfer-Encoding: chunked") != NULL) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[FORWARDED_INJECT_SKIP] Skipping header injection for chunked request "
              "(would corrupt chunk boundaries)");
#endif
    return buflen;  // Skip injection to preserve chunk integrity
  }

  // Build headers to inject (before final \r\n\r\n)
  snprintf(inject_buf, sizeof(inject_buf),
           "X-Forwarded-Proto: https\r\n"
           "%s%s%s",
           host ? "X-Forwarded-Host: " : "",
           host ? host : "",
           host ? "\r\n" : "");

  header_insert_len = strlen(inject_buf);

  // Check buffer space
  if (buflen + header_insert_len > bufsize) {
    log_error("inject_forwarded_headers: Buffer overflow - need %zu bytes, have %zu",
              buflen + header_insert_len, bufsize);
    return -1;
  }

  // Calculate insertion point (AFTER first \r\n, before second \r\n of \r\n\r\n)
  // headers_end points to first \r of \r\n\r\n, we want to insert after the \n
  char *insert_point = headers_end + 2;  // Skip first \r\n
  size_t insert_offset = insert_point - (char *)buf;
  size_t tail_len = buflen - insert_offset;  // Length of "\r\n" + body

  // Move tail (insert_point onwards) to make space
  memmove(insert_point + header_insert_len, insert_point, tail_len);

  // Insert new headers
  memcpy(insert_point, inject_buf, header_insert_len);

  #ifdef HAVE_PROXY_EXTRA_DEBUG
  log_debug("inject_forwarded_headers: Injected %zu bytes at offset %zu (X-Forwarded-Proto: https%s%s)",
            header_insert_len, insert_offset,
            host ? ", X-Forwarded-Host: " : "",
            host ? host : "");
  #endif

  // Debug: Show headers after injection (first 200 bytes)
  #ifdef HAVE_PROXY_EXTRA_DEBUG
  {
    char preview[256];
    size_t preview_len = (buflen + header_insert_len) < 200 ? (buflen + header_insert_len) : 200;
    memcpy(preview, buf, preview_len);
    preview[preview_len] = '\0';
    // Replace non-printable chars for logging
    for (size_t i = 0; i < preview_len; i++) {
      if (preview[i] == '\r') preview[i] = '\\';
      else if (preview[i] == '\n') preview[i] = 'n';
      else if (preview[i] < 32 || preview[i] > 126) preview[i] = '.';
    }
    log_debug("   Request after injection: %s", preview);
  }
  #endif

  return buflen + header_insert_len;
}

/**
 * Generate a vLLM-compatible request ID (UUID v4) for AI Gateway requests.
 * For non-P/D mode: produces 32-char hex UUID.
 * For P/D mode: produces ___prefill_addr_<ep>___decode_addr_<ep>_<uuid32>.
 *
 * Uses xorshift64* PRNG from lxb_ring (non-crypto, uniqueness only).
 *
 * @param pfe        Per-connection state (stores generated ID)
 * @param prefill_ep Prefill endpoint address (NULL for non-P/D mode)
 * @param decode_ep  Decode endpoint address (NULL for non-P/D mode)
 */
static void
generate_vllm_request_id(proxy_fd_ent_t *pfe,
                         const char *prefill_ep,
                         const char *decode_ep)
{
  uint64_t hi, lo;

  /* Reuse xorshift64* PRNG from lxb_ring (non-crypto, uniqueness only) */
  hi = lxb_gen_trace_id_part();
  lo = lxb_gen_trace_id_part();

  /* Set UUID v4 version bits (version=4 in bits 12-15 of hi) */
  hi = (hi & ~((uint64_t)0xF << 12)) | ((uint64_t)0x4 << 12);
  /* Set variant bits (variant=10xx in bits 62-63 of lo) */
  lo = (lo & ~((uint64_t)0x3 << 62)) | ((uint64_t)0x2 << 62);

  char uuid_buf[33];
  snprintf(uuid_buf, sizeof(uuid_buf), "%016llx%016llx",
           (unsigned long long)hi, (unsigned long long)lo);

  if (prefill_ep && decode_ep) {
    snprintf(pfe->vllm_request_id, sizeof(pfe->vllm_request_id),
             "___prefill_addr_%s___decode_addr_%s_%s",
             prefill_ep, decode_ep, uuid_buf);
  } else {
    strncpy(pfe->vllm_request_id, uuid_buf, sizeof(pfe->vllm_request_id) - 1);
    pfe->vllm_request_id[sizeof(pfe->vllm_request_id) - 1] = '\0';
  }

  /* Auto-generated ID: clear has_vllm_request_id so inject gate fires */
  pfe->has_vllm_request_id = 0;
  pfe->request_id_injected = 0;
}

/**
 * Inject X-Request-Id header into HTTP request before forwarding.
 * Uses strip-then-inject pattern to prevent duplicate headers.
 *
 * @param msg      Buffer containing HTTP request (modified in-place)
 * @param len      Current length of data in buffer (updated on success)
 * @param bufsize  Maximum buffer capacity
 * @param req_id   Request ID string to inject
 * @return 0 on success, -1 on error (buffer too small, no headers found, etc.)
 */
static int
inject_request_id_header(void *msg, size_t *len, size_t bufsize,
                         const char *req_id)
{
  char inject_buf[512];
  size_t inject_len;
  uint8_t *headers_end;
  uint8_t *insert_point;
  size_t tail_len;
  uint8_t *existing;

  if (!req_id || req_id[0] == '\0')
    return -1;

  /* Build injection string */
  inject_len = (size_t)snprintf(inject_buf, sizeof(inject_buf),
                                "X-Request-Id: %s\r\n", req_id);
  if (inject_len >= sizeof(inject_buf))
    return -1;

  /* Find header-body separator */
  headers_end = memmem(msg, *len, "\r\n\r\n", 4);
  if (!headers_end)
    return -1;

  /* Strip existing X-Request-Id if present (prevent duplicates) */
  existing = memmem(msg, (size_t)(headers_end - (uint8_t *)msg + 4),
                    "X-Request-Id:", 13);
  if (!existing) {
    /* Try lowercase variation */
    existing = memmem(msg, (size_t)(headers_end - (uint8_t *)msg + 4),
                      "x-request-id:", 13);
  }
  if (existing) {
    /* Find end of this header line */
    uint8_t *line_end = memmem(existing,
                               *len - (size_t)(existing - (uint8_t *)msg),
                               "\r\n", 2);
    if (line_end) {
      line_end += 2; /* Skip \r\n */
      size_t remove_len = (size_t)(line_end - existing);
      memmove(existing, line_end,
              *len - (size_t)(line_end - (uint8_t *)msg));
      *len -= remove_len;
      /* Re-find headers_end after removal */
      headers_end = memmem(msg, *len, "\r\n\r\n", 4);
      if (!headers_end)
        return -1;
    }
  }

  /* Check buffer capacity */
  if (*len + inject_len >= bufsize)
    return -1;

  /* Insert point: after last header \r\n, before final \r\n */
  insert_point = headers_end + 2;
  tail_len = *len - (size_t)(insert_point - (uint8_t *)msg);

  /* Shift body data to make room */
  memmove(insert_point + inject_len, insert_point, tail_len);

  /* Insert header */
  memcpy(insert_point, inject_buf, inject_len);

  *len += inject_len;
  return 0;
}

/* ===========================================================================
 * (CONTEXT) — NEW L7-gated H1 request-header
 * injection. SEPARATE from inject_forwarded_headers() above, which is left
 * BYTE-FOR-BYTE UNTOUCHED (it runs ungated on the shared/AI path). This
 * NEW path runs ONLY when node->has_l7_policy and mirrors the legacy
 * \r\n\r\n splice SHAPE while sharing the op-selection + validation with the H2
 * path via the single l7_apply_req_filters() in sockproxy_l7policy.c (Pitfall 1).
 *
 * SET    = strip any existing header of that name + append the new value.
 * ADD    = append the header value (duplicates allowed — HTTP list semantics).
 * REMOVE = strip every header of that name.
 * The X-Forwarded-* trio is emitted by the applier as SET (always overwrite).
 * =========================================================================== */

/* Strip EVERY occurrence of header `name` (case-insensitive) from the request
 * header block in [msg, *len). Returns the (possibly shrunk) header terminator,
 * or NULL if the \r\n\r\n terminator is lost. Bounded to the header block only. */
static uint8_t *
l7h1_strip_header(uint8_t *msg, size_t *len, const char *name)
{
  uint8_t *headers_end = memmem(msg, *len, "\r\n\r\n", 4);
  size_t name_len = strlen(name);
  if (!headers_end || name_len == 0)
    return headers_end;

  /* Walk header lines from the first CRLF after the request-line. */
  uint8_t *line = memmem(msg, (size_t)(headers_end - msg), "\r\n", 2);
  while (line && line < headers_end) {
    uint8_t *hdr = line + 2;                 /* start of the next header line */
    if (hdr >= headers_end)
      break;
    /* Match "<name>:" case-insensitively at the start of this header line. */
    if ((size_t)(headers_end - hdr) > name_len &&
        strncasecmp((const char *)hdr, name, name_len) == 0 &&
        hdr[name_len] == ':') {
      uint8_t *line_end = memmem(hdr, (size_t)(*len - (size_t)(hdr - msg)),
                                 "\r\n", 2);
      if (!line_end)
        break;
      line_end += 2;                         /* include the trailing CRLF */
      size_t remove_len = (size_t)(line_end - hdr);
      memmove(hdr, line_end, *len - (size_t)(line_end - msg));
      *len -= remove_len;
      headers_end = memmem(msg, *len, "\r\n\r\n", 4);
      if (!headers_end)
        return NULL;
      /* Re-scan from the same `line` (hdr now holds the following header). */
      continue;
    }
    line = memmem(hdr, (size_t)(headers_end - hdr), "\r\n", 2);
  }
  return headers_end;
}

/* Splice one "<name>: <value>\r\n" line before the final \r\n\r\n. */
static int
l7h1_splice_header(uint8_t *msg, size_t *len, size_t bufsize,
                   const char *name, const char *value)
{
  char inject_buf[L7_HDR_NAME_MAX + L7_HDR_VALUE_MAX + 8];
  int n = snprintf(inject_buf, sizeof(inject_buf), "%s: %s\r\n", name, value);
  if (n <= 0 || (size_t)n >= sizeof(inject_buf))
    return -1;
  size_t inject_len = (size_t)n;

  uint8_t *headers_end = memmem(msg, *len, "\r\n\r\n", 4);
  if (!headers_end)
    return -1;
  if (*len + inject_len >= bufsize)
    return -1;

  uint8_t *insert_point = headers_end + 2;   /* after last header CRLF */
  size_t tail_len = *len - (size_t)(insert_point - msg);
  memmove(insert_point + inject_len, insert_point, tail_len);
  memcpy(insert_point, inject_buf, inject_len);
  *len += inject_len;
  return 0;
}

/* Emit-callback context for the H1 path: the mutable request buffer. */
typedef struct {
  uint8_t *msg;
  size_t  *len;
  size_t   bufsize;
} l7h1_emit_ctx_t;

/* l7_hdr_emit_fn for H1: translate one SET/ADD/REMOVE op into buffer splices. */
static void
l7h1_emit(void *vctx, int op, const char *name, const char *value)
{
  l7h1_emit_ctx_t *c = (l7h1_emit_ctx_t *)vctx;
  switch (op) {
  case L7HDR_SET:
    /* Overwrite: strip any existing, then splice the new value. */
    if (!l7h1_strip_header(c->msg, c->len, name))
      return;
    (void)l7h1_splice_header(c->msg, c->len, c->bufsize, name, value);
    break;
  case L7HDR_ADD:
    (void)l7h1_splice_header(c->msg, c->len, c->bufsize, name, value);
    break;
  case L7HDR_REMOVE:
    (void)l7h1_strip_header(c->msg, c->len, name);
    break;
  default:
    break;
  }
}

/*
 * l7_inject_req_headers_h1 — apply the request-header op set to an H1
 * request buffer in place. Caller MUST have already gated on node->has_l7_policy.
 * Returns the new buffer length, or the unchanged length on a non-HTTP/chunked
 * buffer (the splice would corrupt binary/chunked bodies — mirrors the legacy
 * guards). `fd` is the client socket (for the real TCP peer IP).
 */
static size_t
l7_inject_req_headers_h1(proxy_fd_ent_t *pfe, proxy_map_ent_t *node,
                         uint8_t *buf, size_t buflen, size_t bufsize, int fd)
{
  /* Only mutate well-formed HTTP request text with a complete header block. */
  if (buflen < 4 || (memcmp(buf, "GET ", 4) != 0 &&
                     memcmp(buf, "POST", 4) != 0 &&
                     memcmp(buf, "PUT ", 4) != 0 &&
                     memcmp(buf, "DELE", 4) != 0 &&
                     memcmp(buf, "HEAD", 4) != 0 &&
                     memcmp(buf, "PATC", 4) != 0))
    return buflen;
  if (!memmem(buf, buflen, "\r\n\r\n", 4))
    return buflen;
  /* Chunked request bodies: a header splice shifts the body and would corrupt
   * chunk boundaries — skip (same invariant as inject_forwarded_headers). */
  {
    size_t scan = (buflen < 2048) ? buflen : 2048;
    if (memmem(buf, scan, "Transfer-Encoding: chunked", 26) ||
        memmem(buf, scan, "transfer-encoding: chunked", 26))
      return buflen;
  }

  /* Real TCP peer IP: the client socket peer, NOT any client-supplied XFF. */
  char xff_ip[INET6_ADDRSTRLEN] = {0};
  struct sockaddr_in peer;
  socklen_t plen = sizeof(peer);
  if (getpeername(fd, (struct sockaddr *)&peer, &plen) == 0 &&
      peer.sin_family == AF_INET) {
    inet_ntop(AF_INET, &peer.sin_addr, xff_ip, sizeof(xff_ip));
  }

  uint16_t listener_port = ntohs(node->key.xport);
  const char *xfproto = (pfe->ssl != NULL || pfe->ktls_enabled) ? "https" : "http";

  size_t cur = buflen;
  l7h1_emit_ctx_t ctx = { buf, &cur, bufsize };
  l7_apply_req_filters(pfe, node,
                       xff_ip[0] ? xff_ip : NULL, listener_port, xfproto,
                       l7h1_emit, &ctx);
  return cur;
}

/*
 * (CONTEXT) — H1 RESPONSE-side Set-Cookie
 * injection for stateless HTTP_COOKIE persistence. Splices a fixed-name
 * Set-Cookie carrying the opaque keyed-HMAC token of the BACKEND THIS REQUEST WAS
 * SENT TO into the response header block (before the final \r\n\r\n), mirroring
 * the legacy rewrite_location_header shape. The token IS the binding (
 * nothing stored on proxy_fd_ent), so the client presents it on the next request
 * and read-back pins to the same backend (session dispatch, sockproxy_ep.c).
 *
 * Attributes: Path=/; HttpOnly always; Secure iff the listener is HTTPS;
 * SameSite unset. Idempotent — re-minting the same token on every response is
 * harmless (same backend ⇒ same value), so no per-connection "already sent" state
 * is needed (keeps pure).
 *
 *   client      — the CLIENT proxy_fd_ent (odir==0); its head is the L7 service,
 *                 its epv/ep_num identify the backend chosen for this request.
 *   is_ssl      — 1 if the client connection is HTTPS (drives the Secure attr).
 * Returns the new buffer length, unchanged on a non-injectable/chunked response.
 */
static size_t
l7_inject_set_cookie_h1(proxy_fd_ent_t *client, uint8_t *buf, size_t buflen,
                        size_t bufsize, int is_ssl)
{
  proxy_map_ent_t *node;
  proxy_epval_t *tepval;
  char token[LB_COOKIE_TOKEN_MAX];
  char cookie_line[L7_HDR_VALUE_MAX];
  int ep_idx, n;

  if (!client)
    return buflen;
  node = (proxy_map_ent_t *)client->head;
  if (!node || !node->has_l7_policy)
    return buflen;
  /* Only on HTTP_COOKIE listeners (the matched route's cookie_persist marker). */
  if (!l7_cookie_persist_active(client, node))
    return buflen;

  tepval = (proxy_epval_t *)client->epv;
  ep_idx = client->ep_num;
  if (!tepval || ep_idx < 0 || ep_idx >= tepval->n_eps)
    return buflen;

  /* Response must be HTTP text with a complete header block (skip chunked/binary —
   * the caller already gates on !is_chunked_response, but re-check the marker). */
  if (buflen < 12 || memcmp(buf, "HTTP/", 5) != 0)
    return buflen;
  if (!memmem(buf, buflen, "\r\n\r\n", 4))
    return buflen;

  /* Mint the token for the backend this request was routed to ( opaque). */
  if (l7_cookie_node_token_for_ep(node, tepval, ep_idx, token, sizeof(token)) <= 0)
    return buflen;

  /* Set-Cookie: <name>=<token>; Path=/; HttpOnly[; Secure]. */
  n = snprintf(cookie_line, sizeof(cookie_line),
               "%s=%s; Path=/; HttpOnly%s",
               LB_COOKIE_NAME, token, is_ssl ? "; Secure" : "");
  if (n <= 0 || (size_t)n >= sizeof(cookie_line))
    return buflen;

  {
    size_t cur = buflen;
    if (l7h1_splice_header(buf, &cur, bufsize, "Set-Cookie", cookie_line) != 0)
      return buflen;          /* no room / lost terminator — leave response intact */
    return cur;
  }
}

/*
 * (RFC 6797) — H1 RESPONSE-side HSTS injection.
 * Synthesizes "Strict-Transport-Security: max-age=N[; includeSubDomains]
 * [; preload]" from the proxy_arg HSTS scalars (added ) and splices it onto
 * the backend→client response header block via the SAME response-side seam as the
 * Set-Cookie injector (l7h1_splice_header), NOT the request-egress
 * l7_inject_req_headers_h1 (Pitfall 1: HSTS is a RESPONSE header).
 *
 * Triple gate: inject ONLY when
 *   have_ssl (HTTPS/TLS-terminating listener) && has_l7_policy && hsts_max_age>0.
 * On a plain-HTTP listener (have_ssl==0) HSTS is meaningless (browsers ignore it
 * over plaintext) — skip + log once and leave the response byte-for-byte intact.
 * has_l7_policy==0 (AI / un-configured) is a pure no-op. The value is
 * server-synthesized, but still passes l7_hdr_value_valid (defence in depth).
 *
 * Idempotent: HSTS is a fixed single-value header; the splice strips any existing
 * Strict-Transport-Security first, so re-emitting on a retry never duplicates.
 *
 *   client — the CLIENT proxy_fd_ent (odir==0); its head is the L7 service node.
 * Returns the new buffer length, unchanged on a non-injectable response or when
 * any gate is unmet.
 */
static size_t
l7_inject_hsts_h1(proxy_fd_ent_t *client, uint8_t *buf, size_t buflen,
                  size_t bufsize)
{
  proxy_map_ent_t *node;
  char hsts_val[L7_HDR_VALUE_MAX];
  size_t vlen;

  if (!client)
    return buflen;
  node = (proxy_map_ent_t *)client->head;
  if (!node || !node->has_l7_policy)
    return buflen;                       /* AI / un-configured — no-op. */
  if (!node->arg_ptr || node->arg_ptr->hsts_max_age == 0)
    return buflen;                       /* HSTS not configured (default-off). */

  /* HTTPS/TLS-terminating listeners ONLY (RFC 6797). On plain-HTTP
   * skip + log — emitting HSTS over plaintext is meaningless (browsers ignore). */
  if (!node->val.have_ssl) {
    log_debug("[HSTS] skip: plain-HTTP listener (have_ssl=0), "
              "HSTS not injected (RFC 6797)");
    return buflen;
  }

  /* Response must be HTTP text with a complete header block. */
  if (buflen < 12 || memcmp(buf, "HTTP/", 5) != 0)
    return buflen;
  if (!memmem(buf, buflen, "\r\n\r\n", 4))
    return buflen;

  /* Synthesize the value via the shared protocol-neutral builder (Task-2 parity). */
  vlen = l7_hsts_synthesize(node->arg_ptr->hsts_max_age,
                            node->arg_ptr->hsts_include_subdomains,
                            node->arg_ptr->hsts_preload,
                            hsts_val, sizeof(hsts_val));
  if (vlen == 0 || !l7_hdr_value_valid(hsts_val))
    return buflen;                       /* no-injection / failed guard — intact. */

  {
    size_t cur = buflen;
    /* Idempotent: strip any prior STS line, then splice exactly one. */
    (void)l7h1_strip_header(buf, &cur, "Strict-Transport-Security");
    if (l7h1_splice_header(buf, &cur, bufsize,
                           "Strict-Transport-Security", hsts_val) != 0)
      return buflen;                     /* no room — leave response intact. */
    return cur;
  }
}

/**
 * Rewrite Location header in HTTP response from http:// to https://
 *
 * Required for HTTPS→HTTP proxying to prevent protocol downgrade attacks.
 * Browser expects HTTPS URLs in responses when original request was HTTPS.
 *
 * Handles:
 * - Location: http://domain/path → Location: https://domain/path
 * - Case-insensitive header matching
 * - Multiple occurrences (though rare)
 *
 * @param buf     Buffer containing HTTP response (modified in-place)
 * @param buflen  Current length of data in buffer
 * @param bufsize Maximum buffer size
 * @param is_ssl  1 if client connection is HTTPS, 0 if HTTP
 * @return New length of buffer after rewriting, or -1 on error
 */
static ssize_t
rewrite_location_header(uint8_t *buf, size_t buflen, size_t bufsize, int is_ssl)
{
  char *headers_end;
  char *location_start;
  char *http_start;
  ssize_t new_len = buflen;

  // Only rewrite if client connection is HTTPS
  if (!is_ssl) {
    return buflen;  // No modification needed
  }

  // Find end of headers
  headers_end = strstr((char *)buf, "\r\n\r\n");
  if (!headers_end) {
    return buflen;  // Not a complete HTTP response yet
  }

  // CRITICAL FIX: DO NOT rewrite chunked responses!
  // Modifying chunked content changes the data length without updating chunk size headers
  // This causes ERR_INVALID_CHUNKED_ENCODING because chunk boundaries become misaligned
  // Format: SIZE\r\nDATA\r\n - if DATA length changes, SIZE becomes wrong
  if (strcasestr((char *)buf, "Transfer-Encoding: chunked") != NULL) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[LOCATION_REWRITE_SKIP] Skipping Location rewrite for chunked response "
              "(would corrupt chunk boundaries)");
#endif
    return buflen;  // Skip rewrite to preserve chunk integrity
  }

  // Search for "Location:" header (case-insensitive)
  location_start = (char *)buf;
  while (location_start < headers_end) {
    // Find "Location:" (case-insensitive)
    char *line_start = location_start;
    char *line_end = strstr(line_start, "\r\n");
    if (!line_end || line_end > headers_end) break;

    // Check if this line starts with "Location:"
    if ((line_end - line_start) >= 10 &&
        strncasecmp(line_start, "Location:", 9) == 0) {

      // Find "http://" in the value part
      http_start = strstr(line_start + 9, "http://");
      if (http_start && http_start < line_end) {
        // Found "Location: http://" - rewrite to "https://"

        // Check buffer space (we're adding 1 byte: 's')
        if (buflen + 1 > bufsize) {
          log_error("rewrite_location_header: Buffer overflow");
          return -1;
        }

        // Calculate positions
        size_t offset_to_http = http_start - (char *)buf;
        size_t tail_len = buflen - offset_to_http - 4;  // After "http"

        // Move tail to make space for 's'
        memmove(buf + offset_to_http + 5, buf + offset_to_http + 4, tail_len);

        // Insert 's' to make "https"
        buf[offset_to_http + 4] = 's';
        new_len = buflen + 1;

        // Extract rewritten URL for logging (up to 100 chars)
        char rewritten_url[128];
        size_t url_len = line_end - http_start;
        if (url_len > 120) url_len = 120;
        memcpy(rewritten_url, http_start, url_len);
        rewritten_url[url_len] = '\0';

        log_debug("rewrite_location_header: Rewrote Location: %s", rewritten_url);

        // Continue searching for more Location headers (rare but possible)
        location_start = line_end + 2;
        buflen = new_len;  // Update for next iteration
        continue;
      }
    }

    location_start = line_end + 2;
  }

  return new_len;
}

/* Slide the token-accounting tail window: keep the last
 * PROXY_USAGE_TAIL_KEEP bytes of the response stream. Unlike the [DONE]
 * scanner's replace-tail, partial segments ACCUMULATE so a usage object
 * split across small SSE segments survives intact in the window. */
static void
proxy_usage_tail_update(proxy_fd_ent_t *pfe, const uint8_t *msg, size_t len)
{
  if (len >= PROXY_USAGE_TAIL_KEEP) {
    memcpy(pfe->usage_tail, msg + len - PROXY_USAGE_TAIL_KEEP,
           PROXY_USAGE_TAIL_KEEP);
    pfe->usage_tail_len = PROXY_USAGE_TAIL_KEEP;
    return;
  }
  if ((size_t)pfe->usage_tail_len + len > PROXY_USAGE_TAIL_KEEP) {
    size_t shift = (size_t)pfe->usage_tail_len + len - PROXY_USAGE_TAIL_KEEP;
    memmove(pfe->usage_tail, pfe->usage_tail + shift,
            pfe->usage_tail_len - shift);
    pfe->usage_tail_len = (uint16_t)(pfe->usage_tail_len - shift);
  }
  memcpy(pfe->usage_tail + pfe->usage_tail_len, msg, len);
  pfe->usage_tail_len = (uint16_t)(pfe->usage_tail_len + len);
}

/* Dialect ops for token accounting on the response path. P/D rules carry
 * their engine dialect on the epval; plain AI-gateway rules (no
 * kv_engine_type) fall back to the plain-LB profile. */
static const pd_dialect_ops_t *
proxy_usage_ops(proxy_fd_ent_t *pfe)
{
  proxy_epval_t *epv = (proxy_epval_t *)pfe->epv;
  if (epv && epv->pd_ops)
    return epv->pd_ops;
  return &pd_dialect_plain;
}

int
proxy_try_epxmit(proxy_fd_ent_t *ent, void *msg, size_t len, int sel)
{
  int n;
  proxy_fd_ent_t *rfd_ent = NULL;

#ifdef HAVE_PII_DETECTION
  // CRITICAL FIX: Apply deferred PII masking NOW (before forwarding)
  // We deferred the masking in handle_on_message_complete() to avoid corrupting
  // the llhttp parser's internal pointers. Now that parsing is complete and we're
  // about to forward the data, it's safe to apply the masking.
  if (ent->pii_needs_masking && ent->pii_masked_text && ent->pii_masked_len > 0) {
    // Find body start by searching for "\r\n\r\n" (end of headers)
    const char *body_start = NULL;
    size_t body_len = 0;
    
    for (size_t i = 0; i < len - 3; i++) {
      if (((char *)msg)[i] == '\r' && ((char *)msg)[i+1] == '\n' &&
          ((char *)msg)[i+2] == '\r' && ((char *)msg)[i+3] == '\n') {
        body_start = (const char *)msg + i + 4;
        body_len = len - (i + 4);
        break;
      }
    }
    
    if (body_start && body_len > 0) {
      size_t headers_size = body_start - (const char *)msg;
      
      // CRITICAL: We're working with ent->rcvbuf directly through msg pointer
      // msg points to ent->rcvbuf, so modifications here affect the source buffer
      char *buffer = (char *)msg;
      size_t buffer_capacity = SP_SOCK_MSG_LEN;
      
      // Update Content-Length header to match masked body size
      char *cl_start = memmem(buffer, headers_size, "Content-Length:", 15);
      if (cl_start) {
        char *value_start = cl_start + 15;
        while (value_start < body_start && *value_start == ' ') value_start++;
        char *value_end = value_start;
        while (value_end < body_start && *value_end >= '0' && *value_end <= '9') value_end++;
        
        char new_value[32];
        int new_value_len = snprintf(new_value, sizeof(new_value), "%zu", ent->pii_masked_len);
        int old_value_len = value_end - value_start;
        int shift = new_value_len - old_value_len;
        
        if (shift == 0) {
          // Same length - simple overwrite
          memcpy(value_start, new_value, new_value_len);
        } else {
          // Different length - need to shift body
          size_t bytes_after_value = len - (value_end - buffer);
          size_t new_total_size = len + shift;
          
          if (new_total_size > buffer_capacity) {
            log_error("[PII_CL_OVERFLOW] fd=%d: new_total_size=%zu > capacity=%zu",
                      ent->fd, new_total_size, buffer_capacity);
            goto skip_deferred_masking;
          }
          
          // Shift everything after the old value
          memmove(value_end + shift, value_end, bytes_after_value);
          memcpy(value_start, new_value, new_value_len);
          
          // Update pointers and length
          body_start += shift;
          len += shift;
          headers_size += shift;
          
#ifdef HAVE_PROXY_EXTRA_DEBUG
          log_debug("[PII_CL_SHIFT] fd=%d: Shifted buffer by %d bytes (CL: %.*s→%s)",
                    ent->fd, shift, old_value_len, value_start - shift, new_value);
#endif
        }
      }
      
      // Copy masked body over original body
      // Check if there's enough space in the buffer for the masked body
      size_t new_total_size = headers_size + ent->pii_masked_len;
      if (new_total_size <= buffer_capacity) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
        // Show original body before masking (first 200 chars)
        char before_preview[201];
        size_t before_len = body_len > 200 ? 200 : body_len;
        memcpy(before_preview, body_start, before_len);
        before_preview[before_len] = '\0';
        log_debug("[PII_BEFORE_APPLY] fd=%d: Original (first 200): %s", 
                 ent->fd, before_preview);
#endif
        
        memcpy((void *)body_start, ent->pii_masked_text, ent->pii_masked_len);
        
        // Update message length to reflect new body size
        len = headers_size + ent->pii_masked_len;
        
        // Update rcv_off in the source buffer
        ent->rcv_off = len;
        
#ifdef HAVE_PROXY_EXTRA_DEBUG
        // Show masked body after application (first 200 chars)
        char after_preview[201];
        size_t after_len = ent->pii_masked_len > 200 ? 200 : ent->pii_masked_len;
        memcpy(after_preview, body_start, after_len);
        after_preview[after_len] = '\0';
        log_debug("[PII_AFTER_APPLY] fd=%d: Masked (first 200): %s", 
                 ent->fd, after_preview);
#endif
        
        log_info("[PII_APPLIED] fd=%d: Applied deferred masking (%zu→%zu bytes)", 
                 ent->fd, body_len, ent->pii_masked_len);
      } else {
        log_error("[PII_OVERFLOW] fd=%d: Masked text total size (%zu) > buffer capacity (%zu), skipping",
                 ent->fd, new_total_size, buffer_capacity);
      }
    }

skip_deferred_masking:
    
    // Free the temporary storage
    free(ent->pii_masked_text);
    ent->pii_masked_text = NULL;
    ent->pii_masked_len = 0;
    ent->pii_needs_masking = 0;
  }
#endif

  if (ent->rfd_ent[sel]) {
    rfd_ent = ent->rfd_ent[sel];
  }

  if (rfd_ent) {
    PROXY_ENT_LOCK(rfd_ent);

    // DEFENSIVE: Check if peer connection is being torn down (EOF deferred)
    // Avoid processing data on connections marked for closure
    if (rfd_ent->peer_eof) {
      log_trace("[PEER_EOF_SKIP] fd=%d: Peer marked for EOF, skipping processing", rfd_ent->fd);
      PROXY_ENT_UNLOCK(rfd_ent);
      return 0;  // Skip processing but don't error
    }

    /* the member has now sent response data (ent->odir==1 ⇒ this is the
     * backend→client direction). DISARM the timeoutMemberData idle deadline on the client-side entry
     * by clearing its last_activity anchor (which the H1/H2 headers-complete sites set to start the
     * "waiting for member" clock). Without this, a fast-responding member's keepalive/h2c connection
     * keeps last_activity pinned at request time and the 1Hz idle pass (sockproxy_health.c) would
     * shut down a perfectly healthy idle connection ~timeout_member_data seconds later — which broke
     * cookie-affinity reads on the :2020 listener (the connection was cut mid-keepalive). Only clears
 * the -armed anchor on a non-sticky connection; sticky sessions manage last_activity
     * themselves (is_sticky path), so leave those untouched. */
    if (ent->odir == 1 && rfd_ent && !rfd_ent->is_sticky && rfd_ent->last_activity != 0) {
      rfd_ent->last_activity = 0;
    }

    /* response-leg HTTP_RESPONSE parser feed, gated on
     * pd_framing_v2. This runs IN PARALLEL to (BEFORE) the three legacy memmem
     * detectors below (:1085-1355) — NOT replacing them in this plan. With the
     * flag OFF this is a pure no-op and behavior is byte-identical to today.
     *
     * Feed only the NEW response bytes (msg/len for THIS read) to the backend
     * pfe's HTTP_RESPONSE parser; llhttp retains incremental state across reads,
     * so each chunk is fed exactly once (no parsed_off accumulation needed on the
     * response leg — unlike the request leg which re-parses pfe->rcvbuf). The
     * bytes are relayed to the client UNCHANGED by the existing forward path; the
     * parser only OBSERVES framing and fires handle_resp_message_complete once
     * per response message (the single completion consumer).
     *
 * conc=128 UAF fix: the parser feed WRITES mutable parser
     * state into the backend pfe struct itself (ent->parser / ent->settings) —
     * a per-read write the legacy memmem detectors NEVER did (they only read the
     * local `msg` bytes and write the client pfe `rfd_ent` under its lock; they
     * never mutate `ent`). proxy_try_epxmit is entered WITHOUT ent's own lock
     * held (the burst/multiplexor caller drops PROXY_ENT_LOCK(pfe) before the
     * forward — :7414), so a lock-free llhttp_execute(&ent->parser,...) here
     * races proxy_pdestroy/proxy_release_rfd_ctx freeing this very `ent` struct
     * on the CLIENT-fd worker (the cross-worker teardown the Phase-89 banner
     * documents: client fd and backend rfd shard to different notify workers;
     * pd_free_claim closed only the P/D *buffer* double-free, not a write into
     * the freed *pfe struct*). The scribble into the recycled chunk surfaces as
     * glibc `malloc(): mismatching next->prev_size` on the next pd_initiate_decode
     * malloc — conc=128-only because it needs the teardown sweep to interleave
     * with an in-flight backend read on another worker.
     *
     * Fix: take ent's OWN write lock around the parser-state mutation — the SAME
     * lock proxy_pdestroy (:3462) and proxy_release_rfd_ctx (:3418) hold before
     * proxy_try_free_fd_ctx/proxy_release_fd_ctx free the struct — so the feed
     * and the free are mutually exclusive. Lock order is client(rfd_ent) →
     * backend(ent), matching teardown's PROXY_ENT_LOCK(client) →
     * proxy_release_rfd_ctx→PROXY_ENT_LOCK(backend) order, so no ABBA. Flag OFF:
     * this whole block is skipped, byte-identical to today (no extra lock taken).
     * rwlock is non-recursive; ent is NOT already locked on this path (only
     * rfd_ent is, :1016), so the nested acquire cannot self-deadlock.
     *
 * conc=128 UAF fix-2 (Pitfall #2 — prefill-leg skip): the
     * guard below ALSO skips the M1 framer feed on the INTERNAL prefill leg
     * (client pfe still in PD_PHASE_PREFILL_WAITING). The prefill response is
     * NEVER client-facing — it is buffered into rfd_ent->pd_prefill_resp_buf
 * and parsed for kv_params by the block just below (:1211-1259),
     * then DROPPED; the client only ever sees the decode-leg response. Framing
     * the prefill response here fires handle_resp_message_complete /
     * client-stream completion on a response the client never receives, which
 * races the pd_initiate_decode rewire+teardown (the path UNLOCKs
     * rfd_ent at :1260 and tears the prefill backend down) — the conc=128
     * corruptor that survived fix-1. Discriminator = rfd_ent->pd_phase ==
 * PD_PHASE_PREFILL_WAITING, matching the intercept at:1211 EXACTLY
 * so the framer is skipped on precisely the responses swallows (no
     * gap, no overlap). Non-P/D and decode-leg responses (the only
     * client-facing bytes) are framed as before. Flag OFF: whole block skipped,
     * byte-identical. */
    if (ent->odir == 1 && pd_framing_v2_on() && len > 0 &&
        !ent->pd_sg_drain &&  /* SGLang drain leg: never client-facing — same
                               * hazard class as the PREFILL_WAITING skip below;
                               * it runs its OWN framer (pd_sg_drain_consume). */
        !(rfd_ent && rfd_ent->pd_phase == PD_PHASE_PREFILL_WAITING)) {
      /* D2 root fix (I5 V2 — close the dormant ENT(client)↔ENT(backend) ABBA).
       * We reach here holding the CLIENT lock (rfd_ent, taken at the relay scope
       * ~:1016) and must take the BACKEND lock (ent) → order client→backend. But
       * teardown is self-then-peer: proxy_pdestroy on a BACKEND pfe takes
       * backend(ent) then proxy_release_rfd_ctx→client(peer) → order
       * backend→client. A blocking acquire here would therefore close a deadlock
       * cycle. Use a NON-BLOCKING acquire and skip this read's framer feed on
       * contention — safe because the M1 framer is OBSERVE-only (the legacy
       * detectors own completion; relay is unaffected either way). This makes the
       * fix independent of any global pfe-lock order, as Candidate B requires.
       * NOTE: before pd_framing_v2 is promoted to the load-bearing completion
       * path, replace this skip with a canonical-address-ordered double-lock so
       * no framer feed is ever dropped. */
      if (PROXY_ENT_TRYLOCK(ent) == 0) {
        pd_resp_parser_init(ent);   /* idempotent; HTTP_RESPONSE, not HTTP_BOTH */
        enum llhttp_errno rerr = llhttp_execute(&ent->parser, (const char *)msg, len);
        if (rerr != HPE_OK && rerr != HPE_PAUSED) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
          log_debug("[RESP_FRAMING] fd=%d llhttp_execute err=%d (%s) — relay unaffected",
                    ent->fd, rerr, llhttp_errno_name(rerr));
#endif
          /* Framing error is OBSERVE-only in M1: the legacy detectors still own
           * completion (flag is a parallel scaffold). Do NOT drop the relay. */
        }
        PROXY_ENT_UNLOCK(ent);
      }
#ifdef HAVE_PROXY_EXTRA_DEBUG
      else {
        log_debug("[RESP_FRAMING] fd=%d backend lock contended — skipping framer feed (ABBA-safe)",
                  ent->fd);
      }
#endif
    }

    // CRITICAL FIX: Detect chunked encoding ONCE per connection, not per packet
    // Only check if not already marked as chunked (avoids redundant detection)
    // This prevents header manipulation from corrupting binary chunk data on subsequent packets
    // P7 FIX: Mark chunked on SOURCE (backend) connection, not target (client)
    // This way it only affects response processing, not request processing
    if (ent->odir == 1 && !ent->is_chunked_response && len > 30) {
      // Use memmem() for binary-safe search (safer than strcasestr on binary data)
      // Only search first 2KB of headers to avoid scanning chunk data
      size_t search_len = (len < 2048) ? len : 2048;
      if (memmem(msg, search_len, "Transfer-Encoding: chunked", 26) != NULL ||
          memmem(msg, search_len, "transfer-encoding: chunked", 26) != NULL) {

        // P7 FIX: Save flag to BACKEND connection (ent), not client (rfd_ent)
        // This prevents Location header rewriting in responses without affecting
        // X-Forwarded-* injection in requests
        ent->is_chunked_response = 1;

        // METRICS: Track chunked responses (TIER 2, Metric #9)
        atomic_fetch_add(&global_stats.chunked_responses, 1);

#ifdef HAVE_PROXY_EXTRA_DEBUG
        log_debug("[CHUNKED_DETECTED] backend fd=%d: Marked BACKEND as chunked, "
                  "response header rewriting disabled (request injection unaffected)", ent->fd);
#endif
      }
    }

#ifdef HAVE_HTTP_TRACE
    // Parse HTTP response status and Content-Length for tracing (ONCE per connection)
    // Only parse from backend connections (odir=1) when we haven't captured status yet
    if (ent->odir == 1 && rfd_ent && rfd_ent->odir == 0 && 
        rfd_ent->response_status_code == 0 && len > 16) {
      
      const char *buf = (const char *)msg;
      size_t header_search_len = (len < 2048) ? len : 2048;  // Only search first 2KB
      
      // Check for HTTP response status line: "HTTP/1.1 200 OK\r\n"
      if (memcmp(buf, "HTTP/1.", 7) == 0 && len > 12) {
        // Extract status code (3 digits after "HTTP/1.x ")
        const char *status_start = buf + 9;  // Skip "HTTP/1.x "
        if (status_start + 3 <= buf + len) {
          rfd_ent->response_status_code = (status_start[0] - '0') * 100 +
                                          (status_start[1] - '0') * 10 +
                                          (status_start[2] - '0');
#ifdef HAVE_PROXY_EXTRA_DEBUG
          log_debug("[RESPONSE_STATUS_CAPTURED] frontend_fd=%d backend_fd=%d status=%u",
                    rfd_ent->fd, ent->fd, rfd_ent->response_status_code);
#endif
        }
        
        // Find Content-Length header (case-insensitive)
        const char *content_length_pos = memmem(buf, header_search_len, "Content-Length:", 15);
        if (!content_length_pos) {
          content_length_pos = memmem(buf, header_search_len, "content-length:", 15);
        }
        
        if (content_length_pos && content_length_pos + 15 < buf + len) {
          // Skip "Content-Length:" and whitespace
          const char *value_start = content_length_pos + 15;
          while (*value_start == ' ' && value_start < buf + len) value_start++;
          
          // Parse integer value
          rfd_ent->response_content_length = 0;
          while (*value_start >= '0' && *value_start <= '9' && value_start < buf + len) {
            rfd_ent->response_content_length = (rfd_ent->response_content_length * 10) + (*value_start - '0');
            value_start++;
          }
#ifdef HAVE_PROXY_EXTRA_DEBUG
          log_debug("[RESPONSE_LENGTH_CAPTURED] frontend_fd=%d content_length=%u",
                    rfd_ent->fd, rfd_ent->response_content_length);
#endif
        }
      }
    }
#endif

    // L7 METRICS: Parse HTTP response status (independent of Jaeger tracing)
    if (ent->odir == 1 && rfd_ent && rfd_ent->odir == 0 &&
        rfd_ent->metric_response_status == 0 && len > 16) {
      const char *buf = (const char *)msg;
      if (memcmp(buf, "HTTP/1.", 7) == 0 && len > 12) {
        const char *status_start = buf + 9;
        if (status_start + 3 <= buf + len &&
            status_start[0] >= '1' && status_start[0] <= '5' &&
            status_start[1] >= '0' && status_start[1] <= '9' &&
            status_start[2] >= '0' && status_start[2] <= '9') {
          uint16_t status = (status_start[0] - '0') * 100 +
                            (status_start[1] - '0') * 10 +
                            (status_start[2] - '0');
          rfd_ent->metric_response_status = status;
          // Count by status class (skip 1xx interim responses)
          atomic_fetch_add(&global_stats.http_responses_total, 1);
          if (status >= 200 && status < 300) {
            atomic_fetch_add(&global_stats.http_status_2xx, 1);
          } else if (status >= 300 && status < 400) {
            atomic_fetch_add(&global_stats.http_status_3xx, 1);
          } else if (status >= 400 && status < 500) {
            atomic_fetch_add(&global_stats.http_status_4xx, 1);
          } else if (status >= 500 && status < 600) {
            atomic_fetch_add(&global_stats.http_status_5xx, 1);
          }
          // TTFB latency — recorded unconditionally (see request-start capture in
          // handle_on_message_complete); the histogram is a first-class L7 metric,
          // not gated behind the optional HAVE_HTTP_TRACE trace subsystem.
          if (rfd_ent->metric_req_start_ns > 0) {
            uint64_t latency_us = (get_timestamp_ns() - rfd_ent->metric_req_start_ns) / 1000;
            record_latency_sample(latency_us);
          }
          // Origin-error breaker feed for plain (non-P/D) relay: an endpoint
          // that accepts TCP but keeps answering 5xx never trips the
          // connect-level breaker, and prefix affinity keeps re-selecting it.
          // P/D flows are excluded — their dialect handlers feed the breaker
          // with leg-accurate EP indexes. The endpoint handle lives on the
          // CLIENT entry (the backend entry keeps epv/ep_num unset by design
          // for load accounting). 4xx neither extends nor resets the streak:
          // engines answer 4xx/5xx to client-fault bodies, and only a
          // consecutive-5xx streak should demote.
          if (rfd_ent->pd_phase == PD_PHASE_NONE &&
              rfd_ent->epv && rfd_ent->ep_num >= 0) {
            proxy_epval_t *repval = (proxy_epval_t *)rfd_ent->epv;
            if (status >= 500) {
              circuit_breaker_record_origin_error(repval, rfd_ent->ep_num);
            } else if (status < 400) {
              circuit_breaker_record_origin_success(repval, rfd_ent->ep_num);
            }
          }
        }
      }
    }

    /* P/D prefill response buffering — when client is in PREFILL_WAITING,
     * buffer the backend response instead of forwarding to client.
     * The prefill response is small (max_tokens=1) and will be parsed for kv_params. */
    if (ent->odir == 1) {
      log_info("[PD_EPXMIT] odir=1 rfd_ent=%p pd_phase=%d len=%zu",
               rfd_ent, rfd_ent ? rfd_ent->pd_phase : -1, len);
    }

    /* SGLang P/D drain leg: frame + discard the prefill response, fire the
     * failure coupling on an error status. Never relayed to the client —
     * with ONE exception: an origin-computed 4xx (pre-decode) enters relay
     * mode and IS handed over verbatim, replacing the old 502 mask. */
    if (ent->odir == 1 && ent->pd_sg_drain && rfd_ent != NULL) {
      pd_sg_drain_consume(ent, rfd_ent, msg, len);
      PROXY_ENT_UNLOCK(rfd_ent);
      return 0;
    }

    if (ent->odir == 1 && rfd_ent != NULL && rfd_ent->pd_phase == PD_PHASE_PREFILL_WAITING) {
      if (rfd_ent->pd_prefill_resp_buf && rfd_ent->pd_prefill_resp_cap > 0) {
        size_t remain = rfd_ent->pd_prefill_resp_cap - rfd_ent->pd_prefill_resp_len;
        size_t copy_len = (len < remain) ? len : remain;
        if (copy_len > 0) {
          memcpy(rfd_ent->pd_prefill_resp_buf + rfd_ent->pd_prefill_resp_len,
                 msg, copy_len);
          rfd_ent->pd_prefill_resp_len += copy_len;
        }
        if (copy_len < len) {
          log_warn("Prefill response buffer full (%zu/%zu), truncating",
                   rfd_ent->pd_prefill_resp_len, rfd_ent->pd_prefill_resp_cap);
        }

        /* Check if prefill HTTP response is complete (headers + Content-Length body) */
        uint8_t *pr_hdr_end = memmem(rfd_ent->pd_prefill_resp_buf,
                                      rfd_ent->pd_prefill_resp_len,
                                      "\r\n\r\n", 4);
        if (pr_hdr_end) {
          size_t pr_hdr_len = (size_t)(pr_hdr_end + 4 - rfd_ent->pd_prefill_resp_buf);
          uint8_t *pr_cl = memmem(rfd_ent->pd_prefill_resp_buf, pr_hdr_len,
                                   "Content-Length: ", 16);
          if (!pr_cl) {
            pr_cl = memmem(rfd_ent->pd_prefill_resp_buf, pr_hdr_len,
                            "content-length: ", 16);
          }
          int pr_complete = 0;
          if (pr_cl) {
            size_t pr_content_len = (size_t)atol((char *)(pr_cl + 16));
            if (rfd_ent->pd_prefill_resp_len >= pr_hdr_len + pr_content_len) {
              pr_complete = 1;
            } else if (pr_hdr_len + pr_content_len > rfd_ent->pd_prefill_resp_cap) {
              /* (long-context wedge): the declared prefill response can
               * NEVER fit the buffer, so the >= completion check above could
               * never fire and the flow sat in PREFILL_WAITING until the client
               * timed out — NO response at all (live-proven at 64KB cap:
               * resp<=32KB fine, resp>=64KB total wedge). A prefill response
               * this large is off the P/D contract (prefill is max_tokens=1;
               * kv_transfer_params JSON is small) — but the proxy must FAIL
               * OPEN, not hang: force completion once the header block is in.
               * pd_extract_kv_params on the truncated body then degrades
               * exactly like the existing overflow path ("decode will recompute
               * prefill"). Late-arriving prefill bytes are DISCARDED by the
               * decode-phase guard below so they can't interleave into the
               * client's decode stream. */
              log_warn("Prefill response (hdr %zu + CL %zu) exceeds buffer cap %zu"
                       " — forcing completion, decode will recompute prefill"
                       " (client_fd=%d)",
                       pr_hdr_len, pr_content_len, rfd_ent->pd_prefill_resp_cap,
                       rfd_ent->fd);
              pr_complete = 1;
            }
          } else if (pd_detect_http_msg_end(rfd_ent->pd_prefill_resp_buf,
                                            rfd_ent->pd_prefill_resp_len)) {
            /* chunked / CL-less prefill response. With no
             * Content-Length header the response is chunked (or
             * connection-delimited); the prefill leg used to stay in
             * PREFILL_WAITING forever (the 9/10 stuck-prefill-legs root cause).
             * Detect the chunked last-chunk terminator "0\r\n\r\n" over the FULL
             * accumulated buffer (bounded by pd_prefill_resp_len; the 64KB
             * pd_prefill_resp_cap guard above caps that length). This is the
             * success path only — no client error here; the error sends live in
 * the reapers. */
            pr_complete = 1;
          }
          if (pr_complete) {
            log_info("Prefill response complete — client_fd=%d "
                     "resp_len=%zu", rfd_ent->fd, rfd_ent->pd_prefill_resp_len);
            rfd_ent->pd_phase = PD_PHASE_PREFILL_DONE;
            PROXY_ENT_UNLOCK(rfd_ent);

            /* Initiate decode phase */
            if (pd_initiate_decode(rfd_ent) < 0) {
              log_error("Failed to initiate decode — client_fd=%d",
                        rfd_ent->fd);
              atomic_fetch_add(&global_stats.pd_decode_ep_died, 1);
              /* P5-fix: Send 503 (not 502) — decode endpoint unreachable means
               * the P/D backend pool is unavailable, not a proxy protocol error. */
              static const char pd_dec_err[] =
                  "HTTP/1.1 503 Service Unavailable\r\n"
                  "Content-Type: application/json\r\n"
                  "Connection: close\r\n\r\n"
                  "{\"error\":\"pd_pool_unavailable\",\"detail\":\"decode endpoint unreachable\"}";
              if (rfd_ent->fd > 0) {
                /* Use SSL_write when client connection is TLS to avoid
                 * sending plaintext over an encrypted channel (T9 fix). */
                if (rfd_ent->ssl) {
                  SSL_write(rfd_ent->ssl, pd_dec_err, sizeof(pd_dec_err) - 1);
                } else {
                  send(rfd_ent->fd, pd_dec_err, sizeof(pd_dec_err) - 1,
                       MSG_DONTWAIT | MSG_NOSIGNAL);
                }
              }
              /* Record the decode failure (errorPhase=2) — this call site sent
               * the 503 but never recorded it, so decode-init failures on THIS
               * path were invisible to loxilb_ai_pd_requests_total (found by
               * the LC-6.1 failover leg; the :5937 call site already records). */
              {
                const char *pd_dec_model = proxy_effective_model(rfd_ent);
                int d_kv = (rfd_ent->pd_kv_params_len > 0) ? 1 : 0;
                llb_ai_pd_record((char *)pd_dec_model, 0, 0, d_kv, 2);
              }
              rfd_ent->pd_phase = PD_PHASE_ERROR;
              pd_cleanup(rfd_ent);
            }
            return 0;
          }
        }
      }
      PROXY_ENT_UNLOCK(rfd_ent);
      return 0; /* Don't forward prefill response to client */
    }

    /* (second half): once the decode phase is live, any bytes still
     * arriving on the PREFILL leg (client rfd slot 0; decode legs start at
     * slot 1) have no legitimate destination — they are the tail of an
     * over-cap prefill response whose completion was forced above. Forwarding
     * them would interleave prefill garbage into the client's decode stream.
     * Discard them. In the contract-conformant flow the prefill backend is
     * idle after its (small, complete) response, so this branch never fires. */
    if (ent->odir == 1 && rfd_ent != NULL &&
        (rfd_ent->pd_phase == PD_PHASE_DECODE_SENDING ||
         rfd_ent->pd_phase == PD_PHASE_DECODE_STREAMING) &&
        rfd_ent->n_rfd > 1 && ent->fd == rfd_ent->rfd[0]) {
      log_debug("[PD_LATE_PREFILL_DISCARD] client_fd=%d prefill_fd=%d len=%zu",
                rfd_ent->fd, ent->fd, len);
      /* Latent lock-leak fix: this early-return previously kept the client
       * pfe write-lock taken at the relay scope above — any later lock
       * attempt on this pfe (relay, teardown) would wedge. Never fired in
       * conformant vLLM flows (prefill idle after its response); made
       * load-bearing by the SGLang drain path landing beside it. */
      PROXY_ENT_UNLOCK(rfd_ent);
      return 0;
    }

    /* C-1: SSE stream activation — detect "Content-Type: text/event-stream" in the
     * first backend response packet and flip sse_active on the client-side pfe.
     * Only triggered when the LB rule has sse_mode=1 and the stream is not yet live. */
    if (ent->odir == 1 && rfd_ent->sse_mode == 1 &&
        !rfd_ent->sse_active && len > 16) {
      size_t sse_search_len = (len < 2048) ? len : 2048;
      if (memmem(msg, sse_search_len, "Content-Type: text/event-stream", 31) != NULL ||
          memmem(msg, sse_search_len, "content-type: text/event-stream", 31) != NULL) {
        rfd_ent->sse_active = 1;
        rfd_ent->stream_start_ts = time(NULL);
        {
          struct timespec _sse_ts;
          clock_gettime(CLOCK_MONOTONIC, &_sse_ts);
          rfd_ent->stream_start_mono_ns = (uint64_t)_sse_ts.tv_sec * 1000000000ULL +
                                          (uint64_t)_sse_ts.tv_nsec;
        }
        /* Effective model: X-Model header > JSON body model > reset-boundary
         * snapshot > "" */
        const char *sse_model = proxy_effective_model(rfd_ent);
        llb_ai_stream_start("", (char *)sse_model);
        log_info("[SSE_ACTIVATED] client_fd=%d backend_fd=%d model=%s",
                 rfd_ent->fd, ent->fd, sse_model);

        /* P/D decode streaming transition — decode EP is now streaming */
        if (rfd_ent->pd_phase == PD_PHASE_DECODE_SENDING) {
          rfd_ent->pd_phase = PD_PHASE_DECODE_STREAMING;
          rfd_ent->pd_phase_start_ts = time(NULL); /* reset for decode stream timeout */
          /* arm the backend-idle clock for the graceful-[DONE] safety-net
           * reaper. This read carried the activation bytes, so "now" is the last
           * backend activity. Refreshed per byte in the [DONE] scanner below. */
          rfd_ent->pd_last_decode_ts = time(NULL);
          log_info("Decode streaming started — client_fd=%d backend_fd=%d",
                   rfd_ent->fd, ent->fd);
        }
      }
    }

    /* Token accounting: maintain the response tail window and, for
     * non-streamed JSON bodies, charge the tenant quota as soon as the
     * usage object completes in the window (headers and body usually share
     * one segment, but a split body keeps retrying here per segment). SSE
     * responses charge at the [DONE] terminator below, where the final
     * chunk — the usage carrier under stream_options.include_usage — is
     * already in this same window. result stays NULL on the consume call:
     * a completed response is never interrupted; an exceeded quota denies
     * the NEXT request at the rate-limit gate. */
    if (ent->odir == 1 && rfd_ent && rfd_ent->odir == 0 &&
        rfd_ent->ai_gw_mode && !rfd_ent->usage_consumed && len > 0) {
      proxy_usage_tail_update(rfd_ent, (const uint8_t *)msg, len);
      if (!rfd_ent->sse_active && rfd_ent->metric_response_status != 0) {
        const pd_dialect_ops_t *uops = proxy_usage_ops(rfd_ent);
        int up = 0, uc = 0;
        if (uops->extract_usage &&
            uops->extract_usage(rfd_ent, rfd_ent->usage_tail,
                                rfd_ent->usage_tail_len, &up, &uc) == 0) {
          rfd_ent->usage_prompt_toks = up;
          rfd_ent->usage_complet_toks = uc;
          llb_ai_token_quota_consume((char *)rfd_ent->tenant_id,
                                     (char *)proxy_effective_model(rfd_ent),
                                     up, uc, 0,
                                     (int)rfd_ent->usage_reserved_toks,
                                     rfd_ent->usage_res_epoch, NULL);
          /* Settled: the admission claim is spent. Zero it so no later
           * consume on this connection can release it a second time. */
          rfd_ent->usage_reserved_toks = 0;
          rfd_ent->usage_res_epoch = 0;
          rfd_ent->usage_consumed = 1;
          log_info("[AI_TOKENS] client_fd=%d prompt=%d completion=%d (non-stream)",
                   rfd_ent->fd, up, uc);
        }
      }
    }

    /* Record non-SSE AI-Gateway responses into loxilb_ai_requests_total.
     * The SSE path records at its [DONE] terminator; a plain-JSON response —
     * the common error shape (OpenAI-compatible backends return errors as JSON
     * even for streaming requests), and non-streamed 200s — never reaches it, so
     * the AI request/error-ratio metrics were otherwise blind to it. Once this
     * backend packet carries a complete response header block ("\r\n\r\n") and
     * the SSE sniff above did NOT activate a stream, record the request exactly
     * once. metric_ai_recorded guards against the [DONE] path (which also sets
     * it) and against re-firing on later packets of the same response; status +
     * TTFB latency were captured by the L7-metrics block above. Token counts
     * come from the accounting block above when the body carried usage in
     * this same segment (0 when it arrives later — the quota still charges,
     * only this metric misses the counts). */
    if (ent->odir == 1 && rfd_ent && rfd_ent->odir == 0 &&
        rfd_ent->ai_gw_mode && !rfd_ent->metric_ai_recorded &&
        !rfd_ent->sse_active && rfd_ent->metric_response_status != 0 &&
        memmem(msg, len, "\r\n\r\n", 4) != NULL) {
      int64_t ai_ns_lat_ms = 0;
      if (rfd_ent->metric_req_start_ns > 0) {
        ai_ns_lat_ms = (int64_t)((get_timestamp_ns() -
                                  rfd_ent->metric_req_start_ns) / 1000000ULL);
      }
      const char *ai_ns_model = proxy_effective_model(rfd_ent);
      llb_ai_record_request((char *)rfd_ent->tenant_id, (char *)ai_ns_model,
                            (int)rfd_ent->metric_response_status, ai_ns_lat_ms,
                            rfd_ent->usage_prompt_toks,
                            rfd_ent->usage_complet_toks, 0, 0, "");
      rfd_ent->metric_ai_recorded = 1;
      log_info("[AI_NONSSE_RECORDED] client_fd=%d backend_fd=%d model=%s status=%u",
               rfd_ent->fd, ent->fd, ai_ns_model,
               (unsigned)rfd_ent->metric_response_status);
    }

    /* C-5: data:[DONE]\n\n scanner — TCP-fragmentation-safe detection of the
     * OpenAI SSE stream terminator using a 20-byte sliding tail buffer.
     *
     * On each chunk, sse_tail holds the last PROXY_SSE_TAIL_LEN bytes of the
     * previous chunk. We concatenate tail+new_tail into a window and search
     * that window, guaranteeing detection even when the terminator spans two
     * consecutive TCP segments. */
#define PROXY_SSE_DONE_STR1  "data:[DONE]\n\n"
#define PROXY_SSE_DONE_LEN1  13   /* strlen("data:[DONE]\n\n") */
#define PROXY_SSE_DONE_STR2  "data: [DONE]\n\n"
#define PROXY_SSE_DONE_LEN2  14   /* strlen("data: [DONE]\n\n") */
#define PROXY_SSE_TAIL_KEEP  20   /* must be >= max(DONE_LEN1, DONE_LEN2) = 14 */

    if (ent->odir == 1 && rfd_ent->sse_active == 1 &&
        rfd_ent->stream_end_ts == 0 && len > 0) {
      /* refresh the backend-idle clock on every relayed decode byte.
       * The graceful-[DONE] safety-net reaper (sockproxy_health.c) measures idle
       * from THIS timestamp, so a stream that is still producing tokens — however
       * slowly — keeps pushing its reap deadline out and is never truncated; only a
       * stream whose backend has gone genuinely silent (vLLM dropped its [DONE])
       * crosses the cap. */
      rfd_ent->pd_last_decode_ts = time(NULL);

      /* Estimate net: count relayed SSE data-object chunks ("data:" whose
       * value opens with '{' — [DONE] never matches). At the OpenAI
       * streaming convention of one content delta per chunk this
       * approximates completion tokens; used only when the final usage
       * object never materializes. A "data:" split across two TCP
       * segments undercounts by one — acceptable for a backstop. */
      {
        const uint8_t *ev_p = (const uint8_t *)msg;
        size_t ev_left = len;
        const uint8_t *ev_hit;
        while ((ev_hit = memmem(ev_p, ev_left, "data:", 5)) != NULL) {
          const uint8_t *ev_v = ev_hit + 5;
          const uint8_t *ev_end = (const uint8_t *)msg + len;
          while (ev_v < ev_end && (*ev_v == ' ' || *ev_v == '\t'))
            ev_v++;
          if (ev_v < ev_end && *ev_v == '{')
            rfd_ent->usage_sse_events++;
          ev_left -= (size_t)(ev_hit + 5 - ev_p);
          ev_p = ev_hit + 5;
        }
      }

      uint8_t window[PROXY_SSE_TAIL_KEEP * 2];
      uint8_t old_len = rfd_ent->sse_tail_len;
      uint8_t new_len = (len < PROXY_SSE_TAIL_KEEP) ? (uint8_t)len
                                                     : PROXY_SSE_TAIL_KEEP;

      /* Build overlap window from previous tail and new data tail. */
      memcpy(window, rfd_ent->sse_tail, old_len);
      memcpy(window + old_len,
             (const uint8_t *)msg + (len - new_len),
             new_len);
      size_t window_len = (size_t)old_len + new_len;

      /* Advance sliding tail to new data. */
      rfd_ent->sse_tail_len = new_len;
      memcpy(rfd_ent->sse_tail,
             (const uint8_t *)msg + (len - new_len),
             new_len);

      if (memmem(window, window_len, PROXY_SSE_DONE_STR1, PROXY_SSE_DONE_LEN1) ||
          memmem(window, window_len, PROXY_SSE_DONE_STR2, PROXY_SSE_DONE_LEN2) ||
          memmem(msg,    len,        PROXY_SSE_DONE_STR1, PROXY_SSE_DONE_LEN1) ||
          memmem(msg,    len,        PROXY_SSE_DONE_STR2, PROXY_SSE_DONE_LEN2)) {
        /* Step 1: Record stream end timestamp */
        rfd_ent->stream_end_ts = time(NULL);
        /* Step 2: Compute latency from the CLOCK_MONOTONIC activation stamp.
         * Clamped to >= 1 ms: the Go side treats latency_ms <= 0 as "unknown"
         * and skips the histogram Observe, which would silently drop every
         * sub-millisecond completion. */
        int64_t latency_ms = 1;
        {
          struct timespec _sse_ts;
          clock_gettime(CLOCK_MONOTONIC, &_sse_ts);
          uint64_t _sse_now_ns = (uint64_t)_sse_ts.tv_sec * 1000000000ULL +
                                 (uint64_t)_sse_ts.tv_nsec;
          if (rfd_ent->stream_start_mono_ns > 0 &&
              _sse_now_ns > rfd_ent->stream_start_mono_ns) {
            int64_t _sse_delta_ms =
                (int64_t)((_sse_now_ns - rfd_ent->stream_start_mono_ns) / 1000000ULL);
            if (_sse_delta_ms > latency_ms) {
              latency_ms = _sse_delta_ms;
            }
          }
        }

        const char *sse_model = proxy_effective_model(rfd_ent);
        const char *sse_tenant = rfd_ent->tenant_id;

        /* Step 3: Record token consumption. The final pre-[DONE] chunk —
         * the usage carrier when the client requested
         * stream_options.include_usage — sits in the usage tail window
         * maintained on the relay path above; extract through the engine
         * dialect and charge the tenant quota. Counts stay 0 when the
         * client omitted the flag (no usage chunk to read).
         * Pass NULL for result — the current response is complete and
         * must NOT be interrupted; an exceeded quota denies the NEXT
         * request at the rate-limit gate. */
        int sse_tok_p = rfd_ent->usage_prompt_toks;
        int sse_tok_c = rfd_ent->usage_complet_toks;
        int sse_estimated = 0;
        if (!rfd_ent->usage_consumed) {
          const pd_dialect_ops_t *sse_uops = proxy_usage_ops(rfd_ent);
          if (sse_uops->extract_usage &&
              sse_uops->extract_usage(rfd_ent, rfd_ent->usage_tail,
                                      rfd_ent->usage_tail_len,
                                      &sse_tok_p, &sse_tok_c) == 0) {
            rfd_ent->usage_prompt_toks = sse_tok_p;
            rfd_ent->usage_complet_toks = sse_tok_c;
            log_info("[AI_TOKENS] client_fd=%d prompt=%d completion=%d (stream)",
                     rfd_ent->fd, sse_tok_p, sse_tok_c);
          } else {
            /* No usage object despite the request-side include_usage
             * inject (chunked/oversize body skipped it, or the engine
             * dropped the final chunk) — fall back to the estimate net so
             * the stream is not free. */
            sse_tok_p = (int)rfd_ent->usage_est_prompt;
            sse_tok_c = (int)rfd_ent->usage_sse_events;
            sse_estimated = (sse_tok_p + sse_tok_c) > 0;
            rfd_ent->usage_prompt_toks = sse_tok_p;
            rfd_ent->usage_complet_toks = sse_tok_c;
            log_info("[AI_TOKENS] client_fd=%d no usage in final chunk — "
                     "estimated prompt=%d completion=%d",
                     rfd_ent->fd, sse_tok_p, sse_tok_c);
          }
          rfd_ent->usage_consumed = 1;
        }
        llb_ai_token_quota_consume((char *)sse_tenant, (char *)sse_model,
                                   sse_tok_p, sse_tok_c, sse_estimated,
                                   (int)rfd_ent->usage_reserved_toks,
                                   rfd_ent->usage_res_epoch, NULL);
        /* Settled: zero the claim so a spurious second [DONE] or a later
         * non-stream consume on this connection cannot double-release. */
        rfd_ent->usage_reserved_toks = 0;
        rfd_ent->usage_res_epoch = 0;
        /* Step 4: End SSE stream gauge */
        llb_ai_stream_end("", (char *)sse_model);
        /* Step 5: Record request metrics. Status comes from the backend
         * response status line captured by the L7-metrics block above; an
         * active SSE stream implies the headers were seen, but fall back to
         * 200 defensively if the capture missed. */
        int sse_status = rfd_ent->metric_response_status > 0
                             ? (int)rfd_ent->metric_response_status
                             : 200;
        llb_ai_record_request((char *)sse_tenant, (char *)sse_model, sse_status,
                              latency_ms, sse_tok_p, sse_tok_c, 0, 0, "");
        rfd_ent->metric_ai_recorded = 1;   // mark counted so the non-SSE recorder below won't double-count
        log_info("[SSE_DONE] client_fd=%d backend_fd=%d model=%s latency_ms=%lld",
                 rfd_ent->fd, ent->fd, sse_model, (long long)latency_ms);
        /* Step 6: Reset sse_active AFTER llb_ai_stream_end (idempotent)
 * to signal stream lifecycle complete */
        rfd_ent->sse_active = 0;

        /* P/D flow complete — decode stream finished */
        if (rfd_ent->pd_phase == PD_PHASE_DECODE_STREAMING) {
          rfd_ent->pd_phase = PD_PHASE_COMPLETE;
          /* Record P/D metrics before cleanup clears timestamps */
          {
            struct timespec _pdts;
            clock_gettime(CLOCK_MONOTONIC, &_pdts);
            uint64_t pd_now_ns = (uint64_t)_pdts.tv_sec * 1000000000ULL +
                                 (uint64_t)_pdts.tv_nsec;
            int64_t prefill_ms = 0, decode_ms = 0;
            if (rfd_ent->pd_prefill_start_ns > 0 &&
                rfd_ent->pd_decode_start_ns > 0) {
              prefill_ms = (int64_t)((rfd_ent->pd_decode_start_ns -
                                      rfd_ent->pd_prefill_start_ns) / 1000000ULL);
            }
            if (rfd_ent->pd_decode_start_ns > 0) {
              decode_ms = (int64_t)((pd_now_ns -
                                     rfd_ent->pd_decode_start_ns) / 1000000ULL);
            }
            int pd_kv = (rfd_ent->pd_kv_params_len > 0) ? 1 : 0;
            llb_ai_pd_record((char *)sse_model, prefill_ms, decode_ms, pd_kv, 0);
          }
          log_info("P/D flow complete — client_fd=%d backend_fd=%d",
                   rfd_ent->fd, ent->fd);
          pd_cleanup(rfd_ent);
        }
      }
    }

    /* Non-SSE decode completion — detect via Content-Length tracking.
     * The [DONE] scanner above handles streaming (SSE) decode responses.
     * For non-streaming decode (stream=false), the backend returns a complete
     * JSON response with Content-Length.  HTTP keep-alive means the EOF path
     * never fires, so we track body bytes here and call llb_ai_pd_record once
     * the full body has been forwarded to the client. */
    if (ent->odir == 1 &&
        rfd_ent->pd_phase == PD_PHASE_DECODE_SENDING &&
        !rfd_ent->sse_active) {
      if (len > 0) {
        /* Universal decode-activity stamp: (a) the zero-byte
         * discriminator at the decode-EOF site (pd_last_decode_ts == 0 ⇒ the
         * decode leg died before ONE response byte was relayed), and (b)
         * extends the idle-based reaper basis (F-GPU-6) to non-SSE decode
         * responses — the SSE path stamps in the [DONE] scanner. */
        rfd_ent->pd_last_decode_ts = time(NULL);
      }
      if (rfd_ent->pd_decode_content_length == 0 && len > 16) {
        /* First packet — extract Content-Length and count body bytes */
        const uint8_t *cl_pos = memmem(msg, len < 2048 ? len : 2048,
                                       "Content-Length: ", 16);
        if (!cl_pos) {
          cl_pos = memmem(msg, len < 2048 ? len : 2048,
                          "content-length: ", 16);
        }
        if (cl_pos) {
          rfd_ent->pd_decode_content_length = (size_t)atol((const char *)cl_pos + 16);
          const uint8_t *hdr_end = memmem(msg, len, "\r\n\r\n", 4);
          if (hdr_end) {
            size_t hdr_len = (size_t)(hdr_end + 4 - (const uint8_t *)msg);
            rfd_ent->pd_decode_bytes_received +=
                (len > hdr_len) ? (len - hdr_len) : 0;
          }
        }
      } else if (rfd_ent->pd_decode_content_length > 0) {
        rfd_ent->pd_decode_bytes_received += len;
      }

      /* + T3: chunked / CL-less non-SSE decode
       * completion. When the decode response has no Content-Length (chunked
       * transfer-coding), the Content-Length tracking above never fires.
       *
 * T3 (the high-concurrency stall): this !sse_active branch is ALSO
       * the only completion detector when sse_active never flipped — the
       * fragmented-"Content-Type" stall. Under load the response header block can
       * split across reads, so the single-read sniff at :1157 misses
       * "Content-Type: text/event-stream" -> sse_active stays 0 -> pd_phase stays
       * PD_PHASE_DECODE_SENDING -> control reaches HERE, not the :1198 SSE
 * scanner. originally scanned only the CURRENT packet, so a terminator
       * ("data: [DONE]\n\n" or the chunked "0\r\n\r\n") split across two TCP
       * segments was missed -> the decode leg stalled forever and was eventually
       * watchdog-reaped (~50% of high-rate points at conc=64).
       *
       * pd_scan_msg_end_window() keeps a sliding tail (riding the otherwise-idle
       * sse_tail — idle precisely because sse_active==0 on this branch, so there
       * is no contention with the :1198 scanner, which is gated on sse_active==1
       * and mutually exclusive with this branch — the two never double-fire /
       * double-free). Completion is thereby decoupled from sse_active; sse_active
       * remains the metrics/gauge signal only. */
      int pd_decode_chunked_done =
          (rfd_ent->pd_decode_content_length == 0) &&
          pd_scan_msg_end_window(rfd_ent->sse_tail, &rfd_ent->sse_tail_len,
                                 (const uint8_t *)msg, len);

      if (pd_decode_chunked_done ||
          (rfd_ent->pd_decode_content_length > 0 &&
           rfd_ent->pd_decode_bytes_received >= rfd_ent->pd_decode_content_length)) {
        /* Non-SSE decode response fully received — record P/D metrics */
        struct timespec _pdts;
        clock_gettime(CLOCK_MONOTONIC, &_pdts);
        uint64_t pd_now_ns = (uint64_t)_pdts.tv_sec * 1000000000ULL +
                             (uint64_t)_pdts.tv_nsec;
        int64_t prefill_ms = 0, decode_ms = 0;
        if (rfd_ent->pd_prefill_start_ns > 0 &&
            rfd_ent->pd_decode_start_ns > 0) {
          prefill_ms = (int64_t)((rfd_ent->pd_decode_start_ns -
                                  rfd_ent->pd_prefill_start_ns) / 1000000ULL);
        }
        if (rfd_ent->pd_decode_start_ns > 0) {
          decode_ms = (int64_t)((pd_now_ns -
                                 rfd_ent->pd_decode_start_ns) / 1000000ULL);
        }
        int pd_kv = (rfd_ent->pd_kv_params_len > 0) ? 1 : 0;
        const char *ns_model = proxy_effective_model(rfd_ent);
        llb_ai_pd_record((char *)ns_model, prefill_ms, decode_ms, pd_kv, 0);
        rfd_ent->pd_phase = PD_PHASE_COMPLETE;
        pd_cleanup(rfd_ent);
      }
    }

    // Rewrite Location header in HTTP responses (backend→client) when client is HTTPS
    // SKIP for chunked responses to prevent buffer corruption from scanning binary chunk data
    // Only apply when forwarding FROM backend (ent->odir=1) TO client (rfd_ent->odir=0)
    // P7 FIX: Check chunked flag on SOURCE (backend/ent), not target (client/rfd_ent)

    if (!ent->is_chunked_response && ent->odir == 1 && rfd_ent->odir == 0) {

      ssize_t new_len = rewrite_location_header((uint8_t *)msg, len, SP_SOCK_MSG_LEN,
                                                 rfd_ent->ssl != NULL);
      if (new_len < 0) {
        log_error("Failed to rewrite Location header for fd=%d->%d", ent->fd, rfd_ent->fd);
        PROXY_ENT_UNLOCK(rfd_ent);
        return -1;
      }
      if (new_len != len) {
        log_debug("[REWRITE_MODIFIED] fd=%d: Changed len from %zu to %zd", rfd_ent->fd, len, new_len);
      }
      len = new_len;

      /* NEW L7-gated stateless HTTP_COOKIE
       * Set-Cookie injection on the backend→client response. Mints the opaque
       * keyed-HMAC token of the backend THIS request was routed to (rfd_ent->epv
       * / ep_num) and splices a fixed-name Set-Cookie (Path=/; HttpOnly; Secure
       * iff HTTPS). Pure no-op unless the matched route's cookie_persist is set
       * (l7_cookie_persist_active gates inside) — AI peer / non-cookie listeners
 * are byte-for-byte unchanged. Nothing stored on proxy_fd_ent
 * the token IS the binding, so affinity survives HA failover. */
      len = l7_inject_set_cookie_h1(rfd_ent, (uint8_t *)msg, len, SP_SOCK_MSG_LEN,
                                    rfd_ent->ssl != NULL);

      /* (RFC 6797): HSTS response injection on the
       * SAME backend→client response seam. Synthesizes Strict-Transport-Security
       * from the proxy_arg HSTS scalars and splices it, gated strictly on
       * have_ssl && has_l7_policy && hsts_max_age>0 (the gate lives inside
       * l7_inject_hsts_h1). Pure no-op for plain-HTTP / AI / un-configured
 * listeners — byte-for-byte unchanged. */
      len = l7_inject_hsts_h1(rfd_ent, (uint8_t *)msg, len, SP_SOCK_MSG_LEN);
    }

    rfd_ent->chunk_seq++;  // Increment sequence for each transmission attempt
    // CRITICAL FIX: Enforce strict FIFO ordering to prevent race condition
    // If cache has ANY data OR is currently being drained, MUST add to cache
    // This prevents out-of-order delivery when:
    // 1. Backend sends chunks rapidly (chunked encoding)
    // 2. Socket becomes ready mid-cache-drain
    // 3. Direct send bypasses cache while old chunks still queued
    // 4. RACE: proxy_xmit_cache() unlocks → new data arrives → direct send
    // Result: Client receives chunks out of order → gzip decode failure
    if (rfd_ent->cache_head != NULL || rfd_ent->cache_draining) {
      // Cache is non-empty or draining - enforce FIFO ordering
      if (proxy_add_xmitcache(rfd_ent, msg, len) < 0) {
        log_error("[CACHE_FULL] fd=%d: Cannot add %zu bytes, closing connection",
                  rfd_ent->fd, len);
        PROXY_ENT_UNLOCK(rfd_ent);
        return -1;
      }

      // Try to drain cache (includes data we just added)
      proxy_xmit_cache(rfd_ent);

      PROXY_ENT_UNLOCK(rfd_ent);
      return 0;
    }

    // Cache is empty - safe to attempt direct send
    n = proxy_xmit_cache(rfd_ent);  // Double-check cache is truly empty
    if (n < 0) {
      // Cache drain failed (socket not ready), add data to cache
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("🔄 [CACHE_ENQUEUE] fd=%d: Socket not ready, caching %zu bytes | "
                "current cache: count=%u, size=%.2f MB, backpressure=%d",
                rfd_ent->fd, len, rfd_ent->cache_count,
                rfd_ent->cache_total_size / (1024.0 * 1024.0),
                rfd_ent->cache_backpressure);
#endif

      if (proxy_add_xmitcache(rfd_ent, msg, len) < 0) {
        // proxy_add_xmitcache() only returns -1 for:
        // 1. Cache entry count limit (PROXY_MAX_CACHE_ENTRIES)
        // 2. Cache MAX size limit (PROXY_MAX_CACHE_SIZE = 16MB)
        // HIGH_WATER (12MB) does NOT return -1, so this is true overflow!
        log_error("[TRY_EPXMIT_OVERFLOW] fd=%d: Cache add failed (TRUE OVERFLOW), "
                  "dropping %zu bytes and CLOSING CONNECTION", rfd_ent->fd, len);
        
#ifdef HAVE_HTTP_TRACE
        // CRITICAL: Emit REQ_END for cache overflow before closing
        if (rfd_ent->odir == 0 && rfd_ent->root_span_id != 0 && is_tracing_enabled()) {
          uint64_t duration_us = 0;
          if (rfd_ent->req_start_ts > 0) {
            uint64_t now = get_timestamp_ns();
            duration_us = (now - rfd_ent->req_start_ts) / 1000;
          }
          
          // Set HTTP 507 Insufficient Storage for cache overflow
          rfd_ent->http_status_code = 507;
          
          log_info("[TRACE_ERROR] fd=%d: Emitting REQ_END with status 507 (cache overflow) duration=%luμs trace=%016lx%016lx",
                   rfd_ent->fd, duration_us, rfd_ent->trace_id_hi, rfd_ent->trace_id_lo);
          
          emit_trace_event(rfd_ent, LXB_EVENT_REQ_END, duration_us);
          rfd_ent->root_span_id = 0;
        }
#endif
        
        PROXY_ENT_UNLOCK(rfd_ent);
        return -1;  // Signal connection should be closed
      }
      // Data cached for later retry
      PROXY_ENT_UNLOCK(rfd_ent);
      return 0;
    }

    // Cache drained successfully, try direct send
    if (!rfd_ent->ssl || rfd_ent->ktls_enabled) {
      // Use raw socket I/O for plaintext or kTLS-offloaded connections
      n = send(ent->rfd[sel], msg, len, MSG_DONTWAIT|MSG_NOSIGNAL);

      #ifdef HAVE_PROXY_EXTRA_DEBUG
     if (n <= 0) {
        int send_errno = errno;
        log_error("[XMIT] send(fd=%d, len=%zu) failed: n=%d, errno=%d (%s), ktls=%d",
                 ent->rfd[sel], len, n, send_errno, strerror(send_errno), rfd_ent->ktls_enabled);
      }
      #endif
    } else {
      n = SSL_write(rfd_ent->ssl, msg, len);
      if (n <= 0) {
        int ssl_err = SSL_get_error(rfd_ent->ssl, n);
#ifdef HAVE_PROXY_EXTRA_DEBUG
        log_warn("ssl-write-fail fd=%d: err=%d (%s)", rfd_ent->fd, ssl_err,
                 ssl_err == SSL_ERROR_WANT_WRITE ? "WANT_WRITE" :
                 ssl_err == SSL_ERROR_WANT_READ ? "WANT_READ" : "ERROR");
#endif
        if (ssl_err == SSL_ERROR_SSL || ssl_err == SSL_ERROR_SYSCALL) {
          unsigned long err_code = ERR_get_error();
          char err_buf[256];
          ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
          log_error("   OpenSSL error details: %s (code=0x%lx)", err_buf, err_code);
        }
      }
      if (n <= 0) {
        int ssl_err;
        ssl_err = SSL_get_error(rfd_ent->ssl, n);
        
        switch (ssl_err) {
          case SSL_ERROR_WANT_WRITE:
            // CRITICAL: SSL has buffered data internally, we MUST retry with same buffer
            // We cannot cache because SSL might have partial data in its internal buffers
            log_trace("ssl-retry fd=%d", rfd_ent->fd);
            if (!sel) {
              // For sel=0 (primary path), we MUST cache to retry later
              // But this might cause issues if SSL has internal state
              if (proxy_add_xmitcache(rfd_ent, msg, len) < 0) {
                log_error("SSL cache full, closing connection (fd=%d)", rfd_ent->fd);
                
#ifdef HAVE_HTTP_TRACE
                // Emit REQ_END for SSL cache overflow
                if (rfd_ent->odir == 0 && rfd_ent->root_span_id != 0 && is_tracing_enabled()) {
                  uint64_t duration_us = 0;
                  if (rfd_ent->req_start_ts > 0) {
                    uint64_t now = get_timestamp_ns();
                    duration_us = (now - rfd_ent->req_start_ts) / 1000;
                  }
                  rfd_ent->http_status_code = 507;
                  log_info("[TRACE_ERROR] fd=%d: Emitting REQ_END with status 507 (SSL cache full) duration=%luμs",
                           rfd_ent->fd, duration_us);
                  emit_trace_event(rfd_ent, LXB_EVENT_REQ_END, duration_us);
                  rfd_ent->root_span_id = 0;
                }
#endif
                
                PROXY_ENT_UNLOCK(rfd_ent);
                return -1;
              }

              // CRITICAL FIX: Immediately try to drain cache after adding data
              // This matches the pattern at line 1105 where we always call proxy_xmit_cache()
              // after caching. Without this, data sits in cache until EPOLLOUT fires,
              // causing delays and potential client timeouts.
              proxy_xmit_cache(rfd_ent);
            }

            // Note: notify_add_ent and EPOLLOUT registration now handled by proxy_xmit_cache()
            // if the drain hits WANT_WRITE again. No need to duplicate here.
            PROXY_ENT_UNLOCK(rfd_ent);
            return 0;
          case SSL_ERROR_WANT_READ:
            if (!sel) {
              if (proxy_add_xmitcache(rfd_ent, msg, len) < 0) {
                log_error("SSL cache full, closing connection (fd=%d)", rfd_ent->fd);
                
#ifdef HAVE_HTTP_TRACE
                // Emit REQ_END for SSL cache overflow (WANT_READ path)
                if (rfd_ent->odir == 0 && rfd_ent->root_span_id != 0 && is_tracing_enabled()) {
                  uint64_t duration_us = 0;
                  if (rfd_ent->req_start_ts > 0) {
                    uint64_t now = get_timestamp_ns();
                    duration_us = (now - rfd_ent->req_start_ts) / 1000;
                  }
                  rfd_ent->http_status_code = 507;
                  log_info("[TRACE_ERROR] fd=%d: Emitting REQ_END with status 507 (SSL cache full) duration=%luμs",
                           rfd_ent->fd, duration_us);
                  emit_trace_event(rfd_ent, LXB_EVENT_REQ_END, duration_us);
                  rfd_ent->root_span_id = 0;
                }
#endif
                
                PROXY_ENT_UNLOCK(rfd_ent);
                return -1;
              }

              // CRITICAL FIX: Immediately try to drain cache after adding data
              // This matches the pattern at line 1105. Without this, data sits in cache
              // until EPOLLIN fires (for renegotiation), causing unnecessary delays.
              // proxy_xmit_cache() will handle EPOLLIN registration if needed.
              proxy_xmit_cache(rfd_ent);
            }

            // Note: EPOLLIN registration now handled by proxy_xmit_cache() if drain
            // hits WANT_READ again. No need to duplicate here.
            PROXY_ENT_UNLOCK(rfd_ent);
            return 0;
          case SSL_ERROR_SSL:
          case SSL_ERROR_SYSCALL:
            log_error("ssl-error fd=%d: %s", rfd_ent->fd, ERR_error_string(ERR_get_error(), NULL));
          default:
#ifdef HAVE_HTTP_TRACE
            // CRITICAL: Emit REQ_END for SSL errors before closing connection
            // This ensures traces show up in Jaeger for SSL failure scenarios
            if (rfd_ent->odir == 0 && rfd_ent->root_span_id != 0 && is_tracing_enabled()) {
              uint64_t duration_us = 0;
              if (rfd_ent->req_start_ts > 0) {
                uint64_t now = get_timestamp_ns();
                duration_us = (now - rfd_ent->req_start_ts) / 1000;
              }
              
              // Set HTTP 500 Internal Server Error for SSL failures
              rfd_ent->http_status_code = 500;
              
              log_info("[TRACE_ERROR] fd=%d: Emitting REQ_END with status 500 (SSL error) duration=%luμs trace=%016lx%016lx",
                       rfd_ent->fd, duration_us, rfd_ent->trace_id_hi, rfd_ent->trace_id_lo);
              
              emit_trace_event(rfd_ent, LXB_EVENT_REQ_END, duration_us);
              rfd_ent->root_span_id = 0;  // Prevent duplicate emission
            }
#endif
            
            if (ssl_err != SSL_ERROR_SSL && ssl_err != SSL_ERROR_SYSCALL) {
              SSL_shutdown(rfd_ent->ssl);
            } else {
              rfd_ent->ssl_err = 1;
            }
            if (rfd_ent->odir) {
              shutdown(ent->fd, SHUT_RDWR);
            } else {
              shutdown(rfd_ent->fd, SHUT_RDWR);
            }
            PROXY_ENT_UNLOCK(rfd_ent);
            return -1;
        }
      }
    }
    if (n != len) {
      if (n > 0) {
        pfe_ent_accouting(rfd_ent, n, 1);
        if (!sel) {
          if (proxy_add_xmitcache(rfd_ent, (uint8_t *)(msg) + n, len - n) < 0) {
            log_error("Partial write cache full, closing connection (fd=%d)", rfd_ent->fd);
            PROXY_ENT_UNLOCK(rfd_ent);
            return -1;
          }
        }
        PROXY_ENT_UNLOCK(rfd_ent);
        return 0;
      } else /*if (n <= 0)*/ {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
          if (!sel) {
            if (proxy_add_xmitcache(rfd_ent, msg, len) < 0) {
              log_error("Send retry cache full, closing connection (fd=%d)", rfd_ent->fd);
              PROXY_ENT_UNLOCK(rfd_ent);
              return -1;
            }
          }
          PROXY_ENT_UNLOCK(rfd_ent);
          return 0;
        }
        PROXY_ENT_UNLOCK(rfd_ent);
        return -1;
      }
    }

    pfe_ent_accouting(rfd_ent, n, 1);
    PROXY_ENT_UNLOCK(rfd_ent);
  }

  return 0;
}

/* proxy_skmap_key_from_fd moved to sockproxy_conn.c */
/* socket utils (setnb, setnodelay, set_opts, server_setup, ssl_connect) moved to sockproxy_conn.c */

/* Session hash, conversation mapping, endpoint selection (proxy_setup_ep__),
 * proxy_conversation_cleanup_thread, proxy_run moved to sockproxy_ep.c */

/* Tier-1 shaper (defined with its control plane further down) */
static void qos_apply_stored_cfg(proxy_map_ent_t *ent);
static void qos_service_teardown(proxy_ent_t *key);
static int qos_park_reader(proxy_map_ent_t *ent, proxy_fd_ent_t *pfe, int fd);
static int qos_resume_reader(int fd, proxy_fd_ent_t *pfe);

int
proxy_add_entry(proxy_ent_t *new_ent, proxy_arg_t *arg)
{
  int lsd;
  void *ssl_ctx = NULL;
  void *ssl_epctx = NULL;
  proxy_map_ent_t *node;
  proxy_epval_t *tepval;
  proxy_map_ent_t *ent = proxy_struct->head;
  proxy_fd_ent_t *fd_ctx;

  PROXY_LOCK();

  while (ent) {
    if (cmp_proxy_ent(&ent->key, new_ent)) {
      /* a shaper config stored before this add (or surviving a rule
       * re-create) attaches here; no-op when none is stored */
      qos_apply_stored_cfg(ent);

      // P6: Build composite key (host|path|model) or shorter form for backward compat
      char ephash_key[512];
      build_ephash_key(ephash_key, sizeof(ephash_key),
                       arg->host_url,           // "api.example.com"
                       arg->path_prefix,        // "/v1/users" or "" for backward compat
                       arg->model_name);        // "llama-70b" or "" for wildcard pool

      HASH_FIND_STR(ent->val.ephash, ephash_key, tepval);
      if (tepval != NULL) {
        /* Refresh the existing pool in place instead of returning -EEXIST.
         * Returning -EEXIST froze the userspace L7 pool after first creation,
         * so health-monitor endpoint up/down and member add/remove never
         * reached sockproxy -- the fullproxy NAT add does `goto out` before the
         * eBPF map update (loxilb_libdp.c), making proxy_add_entry the ONLY
         * carrier of these updates. Our eps[] is aid-indexed (slot == rule
         * endpoint index), so copying the fresh eps[] also refreshes each
         * endpoint's inv (health) flag consumed by proxy_setup_ep__ selection.
         * Only membership/health state is touched; the P/D trie, per-EP loads,
         * chwbl_config, session maps and locks are intentionally preserved
         * across the update (adapted from loxilb-ebpf upstream facdb93). */
        tepval->n_eps = arg->n_eps;
        tepval->_id = arg->_id;
        tepval->select = arg->select;
        memcpy(tepval->eps, arg->eps, sizeof(arg->eps));
        if (tepval->pd_disagg_enabled) {
          tepval->n_prefill_eps = 0;
          tepval->n_decode_eps = 0;
          for (int i = 0; i < arg->n_eps && i < MAX_PROXY_EP; i++) {
            tepval->ep_role[i] = arg->ep_role[i];
            if (arg->ep_role[i] == 1) tepval->n_prefill_eps++;
            if (arg->ep_role[i] == 2) tepval->n_decode_eps++;
          }
        }
        PROXY_UNLOCK();
        log_info("sockproxy : %s:%u (%s) updated",
                 inet_ntoa(*(struct in_addr *)&new_ent->xip),
                 ntohs(new_ent->xport), ephash_key);
        return 0;
      } else {
        tepval = calloc(1, sizeof(*tepval));
        assert(tepval);
        tepval->n_eps = arg->n_eps;
        tepval->_id = arg->_id;
        tepval->select = arg->select;
        strncpy(tepval->host_url, arg->host_url, sizeof(tepval->host_url) - 1);
        memcpy(tepval->eps, arg->eps, sizeof(arg->eps));
        
        // P6: Store composite key for hash table
        strncpy(tepval->ephash_key, ephash_key, sizeof(tepval->ephash_key) - 1);
        tepval->ephash_key[sizeof(tepval->ephash_key) - 1] = '\0';
        
        // Store custom header configuration
        if (arg->session_header_enabled && arg->session_header_name[0] != '\0') {
          tepval->session_header_enabled = 1;
          strncpy(tepval->session_header_name, arg->session_header_name,
                  sizeof(tepval->session_header_name) - 1);
          tepval->session_header_name[sizeof(tepval->session_header_name) - 1] = '\0';

#ifdef HAVE_PROXY_EXTRA_DEBUG
          log_info("[PROXY_ADD] Custom header stickiness enabled: header='%s' for service %s:%u",
                   tepval->session_header_name,
                   inet_ntoa(*(struct in_addr *)&new_ent->xip),
                   ntohs(new_ent->xport));
#endif
        } else {
          tepval->session_header_enabled = 0;
          tepval->session_header_name[0] = '\0';
        }

        // SSE streaming configuration 
        tepval->sse_mode = arg->sse_mode;
        tepval->max_stream_duration_sec = arg->max_stream_duration_sec;
        tepval->backend_keepalive_sec = arg->backend_keepalive_sec;
        tepval->inactive_timeout_sec = arg->inactive_timeout_sec;

        // P/D disaggregation configuration
        tepval->pd_disagg_enabled = arg->pd_disagg_mode;
        tepval->ai_gw_mode = arg->ai_gw_mode;
        log_info("[PD_CONFIG] proxy_add: pd_disagg=%d ai_gw=%d n_eps=%d",
                 arg->pd_disagg_mode, arg->ai_gw_mode, arg->n_eps);
        if (arg->pd_disagg_mode) {
          tepval->n_prefill_eps = 0;
          tepval->n_decode_eps = 0;
          for (int i = 0; i < arg->n_eps; i++) {
            tepval->ep_role[i] = arg->ep_role[i];
            if (arg->ep_role[i] == 1) tepval->n_prefill_eps++;
            if (arg->ep_role[i] == 2) tepval->n_decode_eps++;
          }

        }

        /* P/D orchestration flavor + SGLang bootstrap port. pd_engine is
         * mapped FROM kv_engine_type (N-way, ready for engines beyond
         * vllm/sglang) so the orchestration branch never reads a KV-named
         * field; the dialect ops pointer is resolved once here so the
         * request path never re-derives the engine; the port default lands
         * here so every reader can trust it non-zero (pd_cache_threshold
         * defaulting idiom). */
        tepval->pd_engine = pd_engine_from_kv_engine_type(arg->kv_engine_type);
        tepval->pd_ops = pd_dialect_resolve(tepval->pd_engine);
        tepval->pd_bootstrap_port = arg->pd_bootstrap_port ?
                                    arg->pd_bootstrap_port : PD_SG_BOOTSTRAP_PORT_DFL;

        // US-PD801: P/D Cache-Aware Routing configuration
        tepval->pd_kv_params_max = arg->pd_kv_params_max;
        tepval->pd_cache_aware_mode = arg->pd_cache_aware_mode;
        tepval->pd_cache_threshold = arg->pd_cache_threshold ? arg->pd_cache_threshold : 20;
        tepval->pd_balance_abs_threshold = arg->pd_balance_abs_threshold ? arg->pd_balance_abs_threshold : 3;
        tepval->pd_session_ttl_sec = arg->pd_session_ttl_sec;

        /* Per-endpoint circuit breaker (opt-in per rule). Initialize each
         * breaker when enabling — a zero-initialized breaker would trip OPEN
         * on the first recorded failure (failure_threshold 0). */
        tepval->cb_enabled = arg->cb_enable;
        if (tepval->cb_enabled) {
          for (int cb_i = 0; cb_i < tepval->n_eps && cb_i < MAX_PROXY_EP; cb_i++)
            circuit_breaker_init(&tepval->circuit_breakers[cb_i]);
        }

        // KV-Cache Exact Routing (: gap closure)
        tepval->kv_exact_mode = arg->kv_exact_mode;
        tepval->kv_hash_algo  = arg->kv_hash_algo;
        tepval->kv_zmq_port   = arg->kv_zmq_port;
        tepval->kv_block_size = arg->kv_block_size;
        tepval->kv_warmup_sec = arg->kv_warmup_sec;
        // (SGL-03): engine + DP rank count ride the same copy block.
        tepval->kv_engine_type = arg->kv_engine_type;
        tepval->kv_dp_rank_count = arg->kv_dp_rank_count;
        /* (SGL-04): the calling rule's identity for the Tier-1.5 Go
         * selector — arg->_id already carries the rule number end-to-end
         * (ca.cidx via llb_conv_nat2proxy), so the stamp just mirrors it into
         * the kv config block. 0 == no identity ⇒ Go keeps the legacy loop. */
        tepval->kv_svc_id = arg->_id;

        tepval->pd_session_map = NULL;
        pthread_rwlock_init(&tepval->pd_session_lock, NULL);
        /* bounded backpressured admission — per-EP parked FIFO lock.
         * Mirror placement with the other P/D locks; FIFOs are zero-init by the
         * tepval calloc, untouched when LLB_PD_QUEUE_DEPTH_PER_EP is 0 (default-off). */
        pthread_mutex_init(&tepval->pd_parked_lock, NULL);
        /* allocate radix trie for Tier 1 cache affinity */
        if (tepval->pd_cache_aware_mode) {
          tepval->pd_trie = pd_trie_create();
          pthread_rwlock_init(&tepval->pd_trie_lock, NULL);
        } else {
          tepval->pd_trie = NULL;
        }
#ifndef HAVE_LLM_SYSTEM_PROMPT_HASH
        if (tepval->pd_cache_aware_mode) {
            log_error("pd_cache_aware_mode=1 requires HAVE_LLM_SYSTEM_PROMPT_HASH build flag; degrading to mode=0");
            tepval->pd_cache_aware_mode = 0;
        }
#endif

        // P2: Initialize draining fields
        tepval->drain_policy = DRAIN_POLICY_GRACEFUL;  // Default: graceful draining
        tepval->drain_timeout_sec = 60;                // Default: 60 seconds
        memset(tepval->drain_state, 0, sizeof(tepval->drain_state));

#ifdef HAVE_DP_GPU_ROUTING
        // P1.2/P1.3: Initialize CHWBL structures if using CHWBL selection
        if (tepval->select == PROXY_SEL_CHWBL) {
          // Allocate and initialize CHWBL config
          tepval->chwbl_config = calloc(1, sizeof(chwbl_config_t));
          if (tepval->chwbl_config) {
            tepval->chwbl_config->mean_load_factor = 175;  // Default: 175% of average
            tepval->chwbl_config->replication = 256;       // Default: 256 virtual nodes
            tepval->chwbl_config->prefix_char_length = 0;  // Unused for now
            
            // PHASE 1: Initialize prefix hash configuration
            tepval->chwbl_config->prefix_hash_level = (arg && arg->chwbl_prefix_hash_level > 0) ? arg->chwbl_prefix_hash_level : 1;  // From config or default L1
            tepval->chwbl_config->prefix_hash_flags = 0;   // Default: auto-detect
            tepval->chwbl_config->enable_cache_salt = 0;   // Default: optional
            
            // Initialize load trackers for all endpoints
            for (int i = 0; i < tepval->n_eps; i++) {
              atomic_init(&tepval->chwbl_config->ep_loads[i].active_conns, 0);
              atomic_init(&tepval->chwbl_config->ep_loads[i].total_requests, 0);
              tepval->chwbl_config->ep_loads[i].last_update_ts = time(NULL);
              tepval->chwbl_config->ep_loads[i].ep_available = (tepval->eps[i].inv == 0) ? 1 : 0;
            }
            
            // Build consistent hash ring
            if (chwbl_build_ring(tepval, 256) < 0) {
              log_error("CHWBL: Failed to build hash ring for rule %u", tepval->_id);
              free(tepval->chwbl_config);
              tepval->chwbl_config = NULL;
              tepval->hash_ring = NULL;
            } else {
              log_info("CHWBL: Initialized for rule %u with %d endpoints, 256 vnodes each",
                       tepval->_id, tepval->n_eps);
            }
          } else {
            log_error("CHWBL: Failed to allocate config for rule %u", tepval->_id);
            tepval->hash_ring = NULL;
          }
        }
#endif /* HAVE_DP_GPU_ROUTING */
        
        // P3: Initialize WRR if selection mode is WRR
        if (tepval->select == PROXY_SEL_WRR) {
          wrr_init_state(tepval);
#ifdef HAVE_PROXY_EXTRA_DEBUG
          log_info("P3: WRR initialized for %s with %d endpoints",
                   arg->host_url[0] ? arg->host_url : "default",
                   tepval->n_eps);
          
          // Log endpoint weights for verification
          for (int i = 0; i < tepval->n_eps; i++) {
            log_info("P3:   EP%d: %s:%u weight=%d",
                     i, inet_ntoa(*(struct in_addr *)&tepval->eps[i].xip),
                     ntohs(tepval->eps[i].xport), tepval->eps[i].weight);
          }
#endif
        }
        
#ifdef HAVE_DP_GPU_ROUTING
        // P3.5: Initialize WRR_HASH if selection mode is WRR_HASH
        if (tepval->select == PROXY_SEL_WRR_HASH) {
          // Allocate CHWBL config for load tracking
          tepval->chwbl_config = calloc(1, sizeof(chwbl_config_t));
          if (tepval->chwbl_config) {
            tepval->chwbl_config->mean_load_factor = 175;  // 1.75x average (same as CHWBL)
            tepval->chwbl_config->replication = 256;       // Total vnodes (weighted allocation)
            tepval->chwbl_config->prefix_hash_level = (arg && arg->chwbl_prefix_hash_level > 0) ? arg->chwbl_prefix_hash_level : 1;  // From config or default L1
            
            // Initialize load trackers for all endpoints
            for (int i = 0; i < tepval->n_eps; i++) {
              atomic_init(&tepval->chwbl_config->ep_loads[i].active_conns, 0);
              atomic_init(&tepval->chwbl_config->ep_loads[i].total_requests, 0);
              tepval->chwbl_config->ep_loads[i].last_update_ts = time(NULL);
              tepval->chwbl_config->ep_loads[i].ep_available = (tepval->eps[i].inv == 0) ? 1 : 0;
            }
            
            // Build weighted consistent hash ring
            if (chwbl_build_weighted_ring(tepval) < 0) {
              log_error("WRR_HASH: Failed to build weighted hash ring for rule %u", tepval->_id);
              free(tepval->chwbl_config);
              tepval->chwbl_config = NULL;
              tepval->hash_ring = NULL;
            } else {
#ifdef HAVE_PROXY_EXTRA_DEBUG
              log_info("WRR_HASH: Initialized for rule %u with %d endpoints (weighted vnodes)",
                       tepval->_id, tepval->n_eps);
              // Log endpoint weights and vnode allocation
              for (int i = 0; i < tepval->n_eps; i++) {
                log_info("P3.5:   EP%d: %s:%u weight=%d",
                         i, inet_ntoa(*(struct in_addr *)&tepval->eps[i].xip),
                         ntohs(tepval->eps[i].xport), tepval->eps[i].weight);
              }
#endif
            }
          } else {
            log_error("WRR_HASH: Failed to allocate config for rule %u", tepval->_id);
            tepval->hash_ring = NULL;
          }
        }
#endif /* HAVE_DP_GPU_ROUTING */
        
        // P6: Use stored key for hash table insertion
        HASH_ADD_KEYPTR(hh, ent->val.ephash,
                        tepval->ephash_key, strlen(tepval->ephash_key),
                        tepval);
        
        PROXY_UNLOCK();
        return 0;
      }
    }
    ent = ent->next;
  }

  node = calloc(1, sizeof(*node));
  if (node == NULL) {
    PROXY_UNLOCK();
    return -ENOMEM;
  }

  memcpy(&node->key, new_ent, sizeof(proxy_ent_t));
  node->val.main_fd = -1;
  node->val.have_ssl = arg->have_ssl;
  node->val.ppv2 = arg->ppv2;   /* L7 fullproxy PROXY protocol v2 emission (mandatory when set) */
  
  // Store proxy_arg pointer for later cleanup if heap-allocated
  // This enables proper memory management for both mTLS and non-mTLS cases
  node->arg_ptr = arg;
  
#ifdef HAVE_HTTP_TRACE
  // Lookup catalog_id for this service from shared memory mapping (non-critical)
  // Initialize to 0 (no tracing) in case lookup fails
  node->catalog_id = 0;
  uint16_t catalog_result = lxb_lookup_service_catalog(node->key.xip, node->key.xport, node->key.protocol);
  if (catalog_result > 0) {
    node->catalog_id = catalog_result;
    log_debug("[CATALOG] Proxy entry created with catalog_id=%d for service %08x:%04x proto=%d",
              catalog_result, node->key.xip, node->key.xport, node->key.protocol);
  }
#endif

  if (arg->have_ssl) {
    // thread the rule's proxy_arg so version/cipher
    // pinning is applied to the frontend listener SSL_CTX. arg is byte-for-byte
    // today's behaviour when the TLS-pinning fields are unset (-COMPAT).
    ssl_ctx = proxy_server_ssl_ctx_init(arg);
    assert(ssl_ctx);
    
    if (proxy_ssl_cfg_opts(ssl_ctx,
          strcmp(arg->host_url, "") ? arg->host_url : NULL, 0)) {
      log_error("[LB Rule] Failed to load SSL certificates for hostname: '%s'",
                strcmp(arg->host_url, "") ? arg->host_url : "(default)");
      PROXY_UNLOCK();
      return -EINVAL;
    }

    // Check if certificate exists in global store
    if (strcmp(arg->host_url, "") != 0) {
      ssl_cert_entry_t *cert_entry = NULL;
      pthread_rwlock_rdlock(&proxy_struct->global_cert_lock);
      HASH_FIND_STR(proxy_struct->global_cert_map, arg->host_url, cert_entry);
      pthread_rwlock_unlock(&proxy_struct->global_cert_lock);
    }

    // Register SNI callback for dynamic certificate selection (GLOBAL STORE)
    SSL_CTX_set_tlsext_servername_callback((SSL_CTX *)ssl_ctx, sni_servername_callback);
    SSL_CTX_set_tlsext_servername_arg((SSL_CTX *)ssl_ctx, NULL);  // Not used - callback uses global store
    
#ifdef HAVE_MTLS
    // Configure frontend mTLS (client certificate verification)
    if (arg->frontend_mtls_mode > 0) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("[mTLS] Frontend mTLS enabled in proxy_add_entry");
      log_debug("[mTLS]   mode=%d (1=Optional, 2=Required)", arg->frontend_mtls_mode);
      log_debug("[mTLS]   client_ca_path=%s", arg->client_ca_path[0] ? arg->client_ca_path : "(none)");
      log_debug("[mTLS]   require_client_cn=%d, pattern=%s",
                arg->require_client_cn, arg->client_cn_pattern[0] ? arg->client_cn_pattern : "(none)");
      log_debug("[mTLS]   host_url=%s", strcmp(arg->host_url, "") ? arg->host_url : "(default)");
#endif
      if (mtls_configure_frontend((SSL_CTX *)ssl_ctx, arg) != 0) {
        log_error("[mTLS] Failed to configure frontend mTLS for %s",
                  strcmp(arg->host_url, "") ? arg->host_url : "(default)");
        SSL_CTX_free(ssl_ctx);
        ssl_ctx = NULL;
        PROXY_UNLOCK();
        return -EINVAL;
      }
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("[mTLS] Frontend mTLS configured successfully for %s",
                strcmp(arg->host_url, "") ? arg->host_url : "(default)");
      log_debug("[mTLS] Stored proxy_arg=%p in SSL_CTX=%p with index=%d", 
                (void*)arg, (void*)ssl_ctx, g_ssl_ctx_proxy_arg_index);
#endif
    }
#endif
  }

  if (arg->have_epssl) {
    ssl_epctx = proxy_client_ssl_ctx_init(arg);
    assert(ssl_epctx);
    if (proxy_ssl_cfg_opts(ssl_epctx, NULL, 0)) {
      if (ssl_ctx) {
        SSL_CTX_free(ssl_ctx);
        ssl_ctx = NULL;
      }
      PROXY_UNLOCK();
      return -EINVAL;
    }
    
#ifdef HAVE_MTLS
    // Backend mTLS is now integrated into proxy_client_ssl_ctx_init 
    // No additional configuration needed here - kept for backward compatibility check
    // backend material referenced by certId.
    if (arg->backend_verify_cert || arg->backend_client_cert_id[0] != '\0') {
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("[mTLS] Backend mTLS configured via proxy_client_ssl_ctx_init ");
      log_debug("[mTLS]   verify_server_cert=%d, client_cert_id present=%s",
                arg->backend_verify_cert,
                arg->backend_client_cert_id[0] ? "yes" : "no");
#else
      log_debug("[mTLS] Backend mTLS configured via proxy_client_ssl_ctx_init");
#endif
    }
#endif
  }

  lsd = proxy_sock_init(node->key.xip, node->key.xport, node->key.protocol);
  if (lsd <= 0) {
    log_error("sockproxy : %s:%u sock-init failed",
        inet_ntoa(*(struct in_addr *)&node->key.xip), ntohs(node->key.xport));
    if (ssl_epctx) {
      SSL_CTX_free(ssl_epctx);
      ssl_epctx = NULL;
    }
    if (ssl_ctx) {
      SSL_CTX_free(ssl_ctx);
      ssl_ctx = NULL;
    }
    PROXY_UNLOCK();
    return -1; 
  }

  node->val.main_fd = lsd;
  node->val.ssl_ctx = ssl_ctx;
  node->val.ssl_epctx = ssl_epctx;
  node->val.proxy_mode = arg->proxy_mode;
  
  // Initialize backend protocol capability (default: HTTP/1.1 only for safety)
  node->val.backend_protocol_cap = arg->backend_protocol_cap;
  
  // Configure ALPN callback with backend protocol capability
  if (ssl_ctx) {
    SSL_CTX_set_alpn_select_cb(ssl_ctx, alpn_select_callback, &node->val.backend_protocol_cap);
    const char *proto_str = (node->val.backend_protocol_cap == 0) ? "http/1.1 only" :
                            (node->val.backend_protocol_cap == 1) ? "h2 only" : "h2+http/1.1";
    log_info("[ALPN] Configured for backend capability: %s", proto_str);
  }

  // P0.3: Initialize conversation tracking
  node->val.conv_map = NULL;
  pthread_rwlock_init(&node->val.conv_lock, NULL);

  // Note: SNI certificates now stored globally - no per-proxy cert_map needed
  
  fd_ctx = pfe_alloc();   /* D2 root fix: pooled pfe shell + heap rcvbuf */
  assert(fd_ctx);

  node->val.fdlist = fd_ctx;
  node->val.nfds++;
  fd_ctx->head = node;
  fd_ctx->stype = PROXY_SOCK_LISTEN;
  fd_ctx->fd = lsd;
  fd_ctx->seltype = arg->select;
  
  // Configure session affinity
  if (arg->affinity_type > PROXY_AFFINITY_NONE) {
    fd_ctx->seltype = PROXY_SEL_STICKY;  // Enable sticky selection
  } 
  if (notify_add_ent(proxy_struct->ns, lsd, NOTI_TYPE_IN|NOTI_TYPE_HUP, fd_ctx, fd_ctx->gen)) {
    log_error("sockproxy : %s:%u notify failed",
        inet_ntoa(*(struct in_addr *)&node->key.xip), ntohs(node->key.xport));
    PROXY_UNLOCK();
    close(lsd);
    if (node->val.ssl_ctx) {
      SSL_CTX_free(node->val.ssl_ctx);
      node->val.ssl_ctx = NULL;
    }
    return -1; 
  }
  fd_ctx->used++;

  tepval = calloc(1, sizeof(*tepval));
  assert(tepval);
  tepval->n_eps = arg->n_eps;
  tepval->_id = arg->_id;
  tepval->select = arg->select;
  strncpy(tepval->host_url, arg->host_url, sizeof(tepval->host_url) - 1);
  tepval->host_url[sizeof(tepval->host_url) - 1] = '\0';
  memcpy(tepval->eps, arg->eps, sizeof(arg->eps));
  
  // P6: Build composite key based on path_prefix and model_name configuration
  char ephash_key[512];
  build_ephash_key(ephash_key, sizeof(ephash_key),
                   arg->host_url,           // "api.example.com"
                   arg->path_prefix,        // "/v1/users" or "" for backward compat
                   arg->model_name);        // "llama-70b" or "" for wildcard pool

  // P6: Store composite key in tepval for hash table
  strncpy(tepval->ephash_key, ephash_key, sizeof(tepval->ephash_key) - 1);
  tepval->ephash_key[sizeof(tepval->ephash_key) - 1] = '\0';
  
  // Store custom header configuration
  if (arg->session_header_enabled && arg->session_header_name[0] != '\0') {
    tepval->session_header_enabled = 1;
    strncpy(tepval->session_header_name, arg->session_header_name,
            sizeof(tepval->session_header_name) - 1);
    tepval->session_header_name[sizeof(tepval->session_header_name) - 1] = '\0';

#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_info("[PROXY_ADD] Custom header stickiness enabled: header='%s' for service %s:%u",
             tepval->session_header_name,
             inet_ntoa(*(struct in_addr *)&new_ent->xip),
             ntohs(new_ent->xport));
#endif
  } else {
    tepval->session_header_enabled = 0;
    tepval->session_header_name[0] = '\0';
  }

  // SSE streaming configuration 
  tepval->sse_mode = arg->sse_mode;
  tepval->max_stream_duration_sec = arg->max_stream_duration_sec;
  tepval->backend_keepalive_sec = arg->backend_keepalive_sec;
  tepval->inactive_timeout_sec = arg->inactive_timeout_sec;

  // P/D disaggregation configuration (new entry path)
  tepval->pd_disagg_enabled = arg->pd_disagg_mode;
  tepval->ai_gw_mode = arg->ai_gw_mode;
  log_info("[PD_CONFIG] proxy_add(new): pd_disagg=%d ai_gw=%d n_eps=%d sse=%d",
           arg->pd_disagg_mode, arg->ai_gw_mode, arg->n_eps, arg->sse_mode);
  if (arg->pd_disagg_mode) {
    tepval->n_prefill_eps = 0;
    tepval->n_decode_eps = 0;
    for (int i = 0; i < arg->n_eps; i++) {
      tepval->ep_role[i] = arg->ep_role[i];
      if (arg->ep_role[i] == 1) tepval->n_prefill_eps++;
      if (arg->ep_role[i] == 2) tepval->n_decode_eps++;
    }
    log_info("[PD_CONFIG] EP roles: n_prefill=%d n_decode=%d",
             tepval->n_prefill_eps, tepval->n_decode_eps);

  }

  /* P/D orchestration flavor + SGLang bootstrap port — mirrors the
   * update-existing-tepval branch above (pd_cache_threshold defaulting
   * idiom for the port). */
  tepval->pd_engine = pd_engine_from_kv_engine_type(arg->kv_engine_type);
  tepval->pd_ops = pd_dialect_resolve(tepval->pd_engine);
  tepval->pd_bootstrap_port = arg->pd_bootstrap_port ?
                              arg->pd_bootstrap_port : PD_SG_BOOTSTRAP_PORT_DFL;

  // US-PD801: P/D Cache-Aware Routing configuration
  tepval->pd_kv_params_max = arg->pd_kv_params_max;
  tepval->pd_cache_aware_mode = arg->pd_cache_aware_mode;
  tepval->pd_cache_threshold = arg->pd_cache_threshold ? arg->pd_cache_threshold : 20;
  tepval->pd_balance_abs_threshold = arg->pd_balance_abs_threshold ? arg->pd_balance_abs_threshold : 3;
  tepval->pd_session_ttl_sec = arg->pd_session_ttl_sec;

  /* Per-endpoint circuit breaker (opt-in per rule). Initialize each breaker
   * when enabling — a zero-initialized breaker would trip OPEN on the first
   * recorded failure (failure_threshold 0). */
  tepval->cb_enabled = arg->cb_enable;
  if (tepval->cb_enabled) {
    for (int cb_i = 0; cb_i < tepval->n_eps && cb_i < MAX_PROXY_EP; cb_i++)
      circuit_breaker_init(&tepval->circuit_breakers[cb_i]);
  }

  // KV-Cache Exact Routing (Tier 1.5) — propagate five kv_* fields on
  // the new-tepval path. Mirrors the update-existing-tepval branch at L1384-1388.
  // Without these copies, tepval->kv_exact_mode stays 0, pd_select_prefill's
  // `if (kv_exact_mode == 1)` gate never fires, and Tier 1.5 routing is silently
  // bypassed for every service created via this branch (see 42-03-DIAGNOSIS.md).
  tepval->kv_exact_mode = arg->kv_exact_mode;
  tepval->kv_hash_algo  = arg->kv_hash_algo;
  tepval->kv_zmq_port   = arg->kv_zmq_port;
  tepval->kv_block_size = arg->kv_block_size;
  tepval->kv_warmup_sec = arg->kv_warmup_sec;
  // (SGL-03): engine + DP rank count ride the same copy block.
  tepval->kv_engine_type = arg->kv_engine_type;
  tepval->kv_dp_rank_count = arg->kv_dp_rank_count;
  /* (SGL-04): the calling rule's identity for the Tier-1.5 Go
   * selector — arg->_id already carries the rule number end-to-end (ca.cidx
   * via llb_conv_nat2proxy), so the stamp just mirrors it into the kv config
   * block. 0 == no identity ⇒ Go keeps the legacy all-services loop. */
  tepval->kv_svc_id = arg->_id;
  log_info("[KV_CONFIG] proxy_add(new): kv_exact_mode=%d kv_hash_algo=%d kv_zmq_port=%u kv_block_size=%u kv_warmup_sec=%u kv_engine_type=%u kv_dp_rank_count=%u kv_svc_id=%u",
           tepval->kv_exact_mode, tepval->kv_hash_algo, tepval->kv_zmq_port,
           tepval->kv_block_size, tepval->kv_warmup_sec,
           tepval->kv_engine_type, tepval->kv_dp_rank_count, tepval->kv_svc_id);

  tepval->pd_session_map = NULL;
  pthread_rwlock_init(&tepval->pd_session_lock, NULL);
  /* bounded backpressured admission — per-EP parked FIFO lock. */
  pthread_mutex_init(&tepval->pd_parked_lock, NULL);
  /* allocate radix trie for Tier 1 cache affinity */
  if (tepval->pd_cache_aware_mode) {
    tepval->pd_trie = pd_trie_create();
    pthread_rwlock_init(&tepval->pd_trie_lock, NULL);
  } else {
    tepval->pd_trie = NULL;
  }
#ifndef HAVE_LLM_SYSTEM_PROMPT_HASH
  if (tepval->pd_cache_aware_mode) {
      log_error("pd_cache_aware_mode=1 requires HAVE_LLM_SYSTEM_PROMPT_HASH build flag; degrading to mode=0");
      tepval->pd_cache_aware_mode = 0;
  }
#endif

  // P2: Initialize draining fields
  tepval->drain_policy = DRAIN_POLICY_GRACEFUL;  // Default: graceful draining
  tepval->drain_timeout_sec = 60;                // Default: 60 seconds
  memset(tepval->drain_state, 0, sizeof(tepval->drain_state));

#ifdef HAVE_DP_GPU_ROUTING
  // P1.2/P1.3: Initialize CHWBL structures if using CHWBL selection
  if (tepval->select == PROXY_SEL_CHWBL) {
    // Allocate and initialize CHWBL config
    tepval->chwbl_config = calloc(1, sizeof(chwbl_config_t));
    if (tepval->chwbl_config) {
      tepval->chwbl_config->mean_load_factor = 175;  // Default: 175% of average
      tepval->chwbl_config->replication = 256;       // Default: 256 virtual nodes
      tepval->chwbl_config->prefix_char_length = 0;  // Unused for now
      
      // PHASE 1: Initialize prefix hash configuration
      tepval->chwbl_config->prefix_hash_level = (arg && arg->chwbl_prefix_hash_level > 0) ? arg->chwbl_prefix_hash_level : 1;  // From config or default L1
      tepval->chwbl_config->prefix_hash_flags = 0;   // Default: auto-detect
      tepval->chwbl_config->enable_cache_salt = 0;   // Default: optional
      
      // Initialize load trackers for all endpoints
      for (int i = 0; i < tepval->n_eps; i++) {
        atomic_init(&tepval->chwbl_config->ep_loads[i].active_conns, 0);
        atomic_init(&tepval->chwbl_config->ep_loads[i].total_requests, 0);
        tepval->chwbl_config->ep_loads[i].last_update_ts = time(NULL);
        tepval->chwbl_config->ep_loads[i].ep_available = (tepval->eps[i].inv == 0) ? 1 : 0;
      }
      
      // Build consistent hash ring
      if (chwbl_build_ring(tepval, 256) < 0) {
        log_error("CHWBL: Failed to build hash ring for rule %u", tepval->_id);
        free(tepval->chwbl_config);
        tepval->chwbl_config = NULL;
        tepval->hash_ring = NULL;
      } else {
        log_info("CHWBL: Initialized for rule %u with %d endpoints, 256 vnodes each",
                 tepval->_id, tepval->n_eps);
      }
    } else {
      log_error("CHWBL: Failed to allocate config for rule %u", tepval->_id);
      tepval->hash_ring = NULL;
    }
  }
#endif /* HAVE_DP_GPU_ROUTING */
  
  // P3: Initialize WRR if selection mode is WRR
  if (tepval->select == PROXY_SEL_WRR) {
    wrr_init_state(tepval);
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_info("P3: WRR initialized for rule %u (%s) with %d endpoints",
             tepval->_id,
             arg->host_url[0] ? arg->host_url : "default",
             tepval->n_eps);
    
    // Log endpoint weights for verification
    for (int i = 0; i < tepval->n_eps; i++) {
      log_info("P3:   EP%d: %s:%u weight=%d",
               i, inet_ntoa(*(struct in_addr *)&tepval->eps[i].xip),
               ntohs(tepval->eps[i].xport), tepval->eps[i].weight);
    }
#endif
  }
  
#ifdef HAVE_DP_GPU_ROUTING
  // P3.5: Initialize WRR_HASH if selection mode is WRR_HASH (second location)
  if (tepval->select == PROXY_SEL_WRR_HASH) {
    // Allocate CHWBL config for load tracking
    tepval->chwbl_config = calloc(1, sizeof(chwbl_config_t));
    if (tepval->chwbl_config) {
      tepval->chwbl_config->mean_load_factor = 175;  // 1.75x average (same as CHWBL)
      tepval->chwbl_config->replication = 256;       // Total vnodes (weighted allocation)
      tepval->chwbl_config->prefix_hash_level = (arg && arg->chwbl_prefix_hash_level > 0) ? arg->chwbl_prefix_hash_level : 1;  // From config or default L1
      
      // Initialize load trackers for all endpoints
      for (int i = 0; i < tepval->n_eps; i++) {
        atomic_init(&tepval->chwbl_config->ep_loads[i].active_conns, 0);
        atomic_init(&tepval->chwbl_config->ep_loads[i].total_requests, 0);
        tepval->chwbl_config->ep_loads[i].last_update_ts = time(NULL);
        tepval->chwbl_config->ep_loads[i].ep_available = (tepval->eps[i].inv == 0) ? 1 : 0;
      }
      
      // Build weighted consistent hash ring
      if (chwbl_build_weighted_ring(tepval) < 0) {
        log_error("WRR_HASH: Failed to build weighted hash ring for rule %u", tepval->_id);
        free(tepval->chwbl_config);
        tepval->chwbl_config = NULL;
        tepval->hash_ring = NULL;
      } else {
#ifdef HAVE_PROXY_EXTRA_DEBUG
        log_info("WRR_HASH: Initialized for rule %u with %d endpoints (weighted vnodes)",
                 tepval->_id, tepval->n_eps);
        // Log endpoint weights and vnode allocation
        for (int i = 0; i < tepval->n_eps; i++) {
          log_info("P3.5:   EP%d: %s:%u weight=%d",
                   i, inet_ntoa(*(struct in_addr *)&tepval->eps[i].xip),
                   ntohs(tepval->eps[i].xport), tepval->eps[i].weight);
        }
#endif
      }
    } else {
      log_error("WRR_HASH: Failed to allocate config for rule %u", tepval->_id);
      tepval->hash_ring = NULL;
    }
  }
#endif /* HAVE_DP_GPU_ROUTING */
  
  // P6: Use stored key for hash table insertion
  HASH_ADD_KEYPTR(hh, node->val.ephash,
                  tepval->ephash_key, strlen(tepval->ephash_key),
                  tepval);

  /* new service: attach any shaper config stored ahead of rule creation */
  qos_apply_stored_cfg(node);

  node->next = proxy_struct->head;
  proxy_struct->head = node;

  HASH_FIND_STR(node->val.ephash, ephash_key, tepval);
  if (tepval == NULL) {
    assert(0);
  }

  PROXY_UNLOCK();
  
  return 0;
}

int
proxy_delete_entry(proxy_ent_t *ent, proxy_arg_t *arg)
{
  int ret = 0, fd = 0;
  void *ssl_ctx = NULL;
  void *ssl_epctx = NULL;

  PROXY_LOCK();

  /* Release the shaper state for this service before teardown: drop the
   * stored config (a later rule on the same VIP:port must not inherit it —
   * a surviving policer association is re-driven by the policer ticker) and
   * wake any parked readers so their connections tear down promptly instead
   * of hanging HUP-armed until a client timeout. */
  qos_service_teardown(ent);

  ret = proxy_delete_entry__(ent, arg, &fd, &ssl_ctx, &ssl_epctx);
  PROXY_UNLOCK();

  if (fd > 0) {
    notify_delete_ent(proxy_struct->ns, fd, 0);
    close(fd);
  }

  return ret;
}
/* Drain management moved to sockproxy_health.c */

/* pd_parked_drain_ep — pop EVERY parked-admission entry for ep_index and wake
 * each owner worker to re-drive selection. The slot-free dequeue (pd_cleanup)
 * pops only ONE parked head per dying in-flight conn, so a FIFO deeper than
 * the dying-conn count stranded the remainder until the max-park reap 503'd
 * them. Called on the transitions that make the EP ineligible for selection
 * (health inv-flip, circuit-breaker OPEN): every woken conn re-drives
 * selection on its own owner worker (gen-validated in pd_resume_parked; a
 * recycled fd is dropped, an already-resumed conn is a no-op) and selection
 * excludes this EP, so the queue fails over instead of timing out. Entries
 * are popped under pd_parked_lock, wakes issued after, mirroring the
 * slot-free dequeue pattern. Empty FIFO (feature off included) = no-op. */
void
pd_parked_drain_ep(proxy_epval_t *tepval, int ep_index, const char *why)
{
  pd_parked_ent_t drained[PD_MAX_QUEUE_DEPTH];
  uint32_t n_drained = 0;

  if (!tepval || ep_index < 0 || ep_index >= tepval->n_eps ||
      !proxy_struct || !proxy_struct->ns) {
    return;
  }

  pthread_mutex_lock(&tepval->pd_parked_lock);
  while (n_drained < PD_MAX_QUEUE_DEPTH &&
         pd_parked_pop_head(&tepval->pd_parked[ep_index],
                            &drained[n_drained])) {
    n_drained++;
  }
  pthread_mutex_unlock(&tepval->pd_parked_lock);

  for (uint32_t di = 0; di < n_drained; di++) {
    if (drained[di].fd <= 0) continue;
    int owner = notify_owner_thr(proxy_struct->ns, drained[di].fd);
    int wrc = (owner >= 0)
        ? notify_wake_worker(proxy_struct->ns, owner, drained[di].fd)
        : -1;
    if (wrc != 0) {
      log_warn("[PD_ADMISSION] %s drain: wake failed (rc=%d) for parked "
               "fd=%d (owner=%d) — relying on max-park reap",
               why, wrc, drained[di].fd, owner);
    }
  }
  if (n_drained > 0) {
    log_info("[PD_ADMISSION] %s drain: ep=%d released %u parked conn(s) "
             "for re-selection", why, ep_index, n_drained);
  }
}

// P2 Task 1.3: Lightweight endpoint health update with graceful draining
//
// This function ONLY updates the inactive flag without full rule reconfiguration
// providing a 100x performance improvement (50-100ms → <1ms) over full rule sync.
//
// CONNECTION DRAINING BEHAVIOR:
// 
// When marking endpoint INACTIVE (inactive=1):
//   * NEW connections: Will NOT select this endpoint (inv=1, ep_available=0)
//   * EXISTING connections: Continue using established file descriptors (graceful draining)
//   * Draining time: Depends on connection lifetime and natural termination
//   * No connections are force-closed - they drain naturally as clients disconnect
//
// When marking endpoint ACTIVE (inactive=0):
//   * NEW connections: Immediately available for selection (inv=0, ep_available=1)
//   * EXISTING connections: Unaffected (continue normally)
//
// This provides zero-downtime health updates with automatic graceful draining.
// For controlled draining with timeouts, use the draining policy features (Task 2.2).
//
// Updates performed (only 2 bytes changed):
//   1. tepval->eps[ep_index].inv = inactive (1 byte)
//   2. tepval->chwbl_config->ep_loads[ep_index].ep_available = !inactive (1 byte)
//
// No hash ring rebuild, no socket operations, no connection termination.
int
proxy_update_ep_health(proxy_ent_t *key, int ep_index, uint8_t inactive)
{
  proxy_map_ent_t *ent;
  proxy_epval_t *tepval, *tmp_epval;
  time_t now = time(NULL);
  
  if (!key || ep_index < 0) {
    log_error("P2: proxy_update_ep_health - invalid parameters");
    return -EINVAL;
  }

  PROXY_LOCK();
  
  // Find existing proxy entry
  ent = proxy_struct->head;
  while (ent) {
    if (cmp_proxy_ent(&ent->key, key)) {
      // Entry found - update endpoint health
      HASH_ITER(hh, ent->val.ephash, tepval, tmp_epval) {
        // Validate endpoint index
        if (ep_index >= tepval->n_eps) {
          PROXY_UNLOCK();
          log_error("P2: proxy_update_ep_health - invalid ep_index %d (max: %d)", 
                    ep_index, tepval->n_eps);
          return -EINVAL;
        }

        // Update ONLY the inactive flag
        uint8_t old_state = tepval->eps[ep_index].inv;
        tepval->eps[ep_index].inv = inactive;

        // P2: Proactive session cleanup when endpoint becomes inactive
        if (inactive && old_state == 0) {
          // CRITICAL: Remove all stale session mappings for this endpoint
          // This prevents memory waste and avoids re-learning overhead on every request
          uint32_t cleaned = cleanup_endpoint_sessions(ent, ep_index);
          if (cleaned > 0) {
            log_info("[EP_HEALTH] Endpoint[%d] marked inactive, cleaned %u session mappings",
                     ep_index, cleaned);
          }

          /* remove dead EP from trie to prevent stale Tier 1 matches */
          if (tepval->pd_trie) {
            pthread_rwlock_wrlock(&tepval->pd_trie_lock);
            pd_trie_remove_ep(tepval->pd_trie, ep_index);
            pthread_rwlock_unlock(&tepval->pd_trie_lock);
          }

          /* Release every client parked on the now-dead EP for
           * re-selection (see pd_parked_drain_ep). */
          pd_parked_drain_ep(tepval, ep_index, "ep-down");
        }

        // P2: Handle draining based on policy
        if (inactive && old_state == 0) {
          
          if (tepval->drain_policy == DRAIN_POLICY_TIMED) {
            // Count current active connections
            uint32_t active_conns = count_active_connections_to_endpoint(ent, ep_index);
            
            tepval->drain_state[ep_index].is_draining = 1;
            tepval->drain_state[ep_index].drain_start_ts = now;
            tepval->drain_state[ep_index].active_conns_at_start = active_conns;
          } else if (tepval->drain_policy == DRAIN_POLICY_IMMEDIATE) {
            // Force-close immediately
            force_close_endpoint_connections(ent, ep_index);
          } 
        } else if (!inactive && old_state == 1) {
          // Transitioning from inactive → active (cancel draining)
          if (tepval->drain_state[ep_index].is_draining) {
            tepval->drain_state[ep_index].is_draining = 0;
          }
        }

        log_info("EP health updated - %s:%u ep[%d] %u→%u",
                  inet_ntoa(*(struct in_addr *)&tepval->eps[ep_index].xip),
                  ntohs(tepval->eps[ep_index].xport),
                  ep_index, old_state, inactive);

        PROXY_UNLOCK();
        
        // Note: Existing connections continue (graceful draining by default)
        // - NEW connections: Will skip this endpoint if inactive=1
        // - EXISTING connections: Continue using established sockets
        // - Timed policy: Will force-close after drain_timeout_sec
        // - Immediate policy: Connections closed immediately
        
        return 0;
      }
      
      PROXY_UNLOCK();
      log_error("P2: proxy_update_ep_health - no ephash entry found");
      return -ENOENT;
    }
    ent = ent->next;
  }

  PROXY_UNLOCK();
  log_error("P2: proxy_update_ep_health - entry not found for %s:%u",
            inet_ntoa(*(struct in_addr *)&key->xip), ntohs(key->xport));
  return -ENOENT;
}

// P2 GPU-Aware: Update endpoint health by IP address lookup
// This is a helper for GPU-aware load balancing where we have endpoint IP but not index
// Returns: 0 on success, -1 on error
int
proxy_update_ep_health_by_ip(proxy_ent_t *key, uint32_t ep_ip, uint8_t inactive)
{
  proxy_map_ent_t *ent;
  proxy_epval_t *tepval, *tmp_epval;
  int ep_index = -1;
  
  if (!key) {
    log_error("proxy_update_ep_health_by_ip - invalid key");
    return -EINVAL;
  }

  log_info("proxy_update_ep_health_by_ip called - svc=%s:%u ep=%s inactive=%u",
           inet_ntoa(*(struct in_addr *)&key->xip), ntohs(key->xport),
           inet_ntoa(*(struct in_addr *)&ep_ip), inactive);

  PROXY_LOCK();
  
  // Find existing proxy entry
  ent = proxy_struct->head;
  while (ent) {
    if (cmp_proxy_ent(&ent->key, key)) {
      // Entry found - find endpoint by IP
      HASH_ITER(hh, ent->val.ephash, tepval, tmp_epval) {
        // Search for matching endpoint IP
        for (int i = 0; i < tepval->n_eps; i++) {
          if (tepval->eps[i].xip == ep_ip) {
            ep_index = i;
            break;
          }
        }
        
        if (ep_index < 0) {
          PROXY_UNLOCK();
          log_error("Endpoint IP %s not found in service %s:%u",
                    inet_ntoa(*(struct in_addr *)&ep_ip),
                    inet_ntoa(*(struct in_addr *)&key->xip), 
                    ntohs(key->xport));
          return -ENOENT;
        }
        
        PROXY_UNLOCK();
        
        // Reuse existing health update function
        return proxy_update_ep_health(key, ep_index, inactive);
      }
      
      PROXY_UNLOCK();
      log_error("No ephash entry found");
      return -ENOENT;
    }
    ent = ent->next;
  }

  PROXY_UNLOCK();
  log_error("Proxy entry not found for %s:%u",
            inet_ntoa(*(struct in_addr *)&key->xip), ntohs(key->xport));
  return -ENOENT;
}

/* ==========================================================================
 * Tier-1 (L7) byte shaper — control plane + refill/wake engine.
 *
 * The bucket itself and the burst-loop enforcement live on the relay hot
 * path (handle_client_data); everything here is control/slow path. Config is
 * stored in a small key-indexed table so a policer attached BEFORE its LB
 * rule exists converges when proxy_add_entry later creates the entry, and so
 * a rule re-create keeps its shaper without a control-plane round trip.
 *
 * Locking: the store and all cfg mutation are under PROXY_LOCK (write); the
 * tick walks entries under PROXY_RDLOCK. Bucket state is atomics-only.
 * ========================================================================== */

#define QOS_CFG_STORE_MAX   512
#define QOS_TICK_QUANTUM_NS 5000000ULL   /* refill/wake sweep every 5ms */

struct qos_cfg_slot {
  proxy_ent_t key;
  struct proxy_qos_cfg cfg;
  int valid;
};

static struct qos_cfg_slot qos_cfg_store[QOS_CFG_STORE_MAX]; /* PROXY_LOCK */
static _Atomic uint64_t qos_last_tick_ns;

static uint64_t
qos_now_ns(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* PROXY_LOCK held. Returns the slot for key; allocates a free one when
 * alloc != 0. NULL when absent (or the store is full). */
static struct qos_cfg_slot *
qos_store_find(proxy_ent_t *key, int alloc)
{
  struct qos_cfg_slot *free_slot = NULL;
  for (int i = 0; i < QOS_CFG_STORE_MAX; i++) {
    if (qos_cfg_store[i].valid) {
      if (cmp_proxy_ent(&qos_cfg_store[i].key, key)) {
        return &qos_cfg_store[i];
      }
    } else if (!free_slot) {
      free_slot = &qos_cfg_store[i];
    }
  }
  if (alloc && free_slot) {
    memset(free_slot, 0, sizeof(*free_slot));
    memcpy(&free_slot->key, key, sizeof(*key));
    return free_slot;
  }
  return NULL;
}

/* PROXY_LOCK held. Wake every parked fd on the bucket — used when shaping is
 * disabled (a parked fd would otherwise stay HUP-armed forever) and on rate
 * changes. Wakes route to each fd's owner worker; resume is gen-validated so
 * stale entries are harmless. */
static void
qos_wake_all_parked(struct proxy_qos_bucket *b)
{
  struct qos_parked_fd wake[QOS_MAX_PARKED];
  int n;

  pthread_mutex_lock(&b->park_lock);
  n = b->n_parked;
  if (n > 0) {
    memcpy(wake, b->parked, (size_t)n * sizeof(wake[0]));
    b->n_parked = 0;
  }
  pthread_mutex_unlock(&b->park_lock);

  for (int i = 0; i < n; i++) {
    notify_wake_worker(proxy_struct->ns, wake[i].owner_thr, wake[i].fd);
  }
}

/* PROXY_LOCK held. Applies cfg to a live entry. Enabling (or a rate change)
 * re-inits the bucket to a full burst; disabling releases parked readers. */
static void
qos_apply_cfg(proxy_map_ent_t *ent, const struct proxy_qos_cfg *cfg)
{
  int was_on = ent->qos_cfg.cir_Bps != 0;
  int now_on = cfg->cir_Bps != 0;

  if (!was_on && now_on) {
    pthread_mutex_init(&ent->qos_up.park_lock, NULL);
    ent->qos_up.n_parked = 0;
  }

  ent->qos_cfg = *cfg;

  if (now_on) {
    qos_bucket_init(&ent->qos_up, cfg, qos_now_ns());
    log_info("qos: shaper on %s:%u cir=%luB/s cbs=%uB dir=0x%x mode=%d",
             inet_ntoa(*(struct in_addr *)&ent->key.xip), ntohs(ent->key.xport),
             (unsigned long)cfg->cir_Bps, qos_effective_cbs(cfg),
             cfg->dir, cfg->mode);
  }
  if (was_on) {
    /* rate change or disable: parked readers re-evaluate against the new
     * config on their owner workers */
    qos_wake_all_parked(&ent->qos_up);
    if (!now_on) {
      log_info("qos: shaper off %s:%u",
               inet_ntoa(*(struct in_addr *)&ent->key.xip), ntohs(ent->key.xport));
    }
  }
}

/* Called from proxy_add_entry (PROXY_LOCK held) for both the create and the
 * in-place refresh path: a stored config survives rule re-creation. */
static void
qos_apply_stored_cfg(proxy_map_ent_t *ent)
{
  struct qos_cfg_slot *slot = qos_store_find(&ent->key, 0);
  if (slot && slot->cfg.cir_Bps && !ent->qos_cfg.cir_Bps) {
    qos_apply_cfg(ent, &slot->cfg);
  }
}

/* Called from proxy_delete_entry (PROXY_LOCK held): drop the stored config
 * for the service and release its parked readers so teardown never leaves a
 * connection HUP-armed with no wake source. */
static void
qos_service_teardown(proxy_ent_t *key)
{
  struct qos_cfg_slot *slot = qos_store_find(key, 0);
  if (slot) {
    slot->valid = 0;
  }
  for (proxy_map_ent_t *ent = proxy_struct->head; ent; ent = ent->next) {
    if (cmp_proxy_ent(&ent->key, key)) {
      if (ent->qos_cfg.cir_Bps) {
        qos_wake_all_parked(&ent->qos_up);
      }
      break;
    }
  }
}

int
proxy_update_qos_config(struct proxy_ent *key, uint64_t cir_bps,
                        uint64_t pir_bps, uint32_t cbs_bytes,
                        uint8_t dir, uint8_t mode)
{
  proxy_map_ent_t *ent;
  struct proxy_qos_cfg cfg = { 0 };

  if (!key) {
    return -EINVAL;
  }

  /* rates arrive in bits/sec (policer API unit); the shaper meters bytes */
  cfg.cir_Bps = cir_bps / 8;
  cfg.pir_Bps = pir_bps / 8;   /* reserved: single-rate shaping for now */
  cfg.cbs_bytes = cbs_bytes;
  cfg.dir = dir ? dir : QOS_DIR_UPLOAD;
  cfg.mode = mode ? mode : QOS_MODE_SHAPE;

  if (cfg.mode != QOS_MODE_SHAPE && cfg.cir_Bps) {
    log_error("qos: mode %d unsupported (shape only)", cfg.mode);
    return -EOPNOTSUPP;
  }

  PROXY_LOCK();

  if (cfg.cir_Bps == 0) {
    struct qos_cfg_slot *slot = qos_store_find(key, 0);
    if (slot) {
      slot->valid = 0;
    }
  } else {
    struct qos_cfg_slot *slot = qos_store_find(key, 1);
    if (!slot) {
      PROXY_UNLOCK();
      log_error("qos: config store full (%d services)", QOS_CFG_STORE_MAX);
      return -ENOSPC;
    }
    slot->cfg = cfg;
    slot->valid = 1;
  }

  for (ent = proxy_struct->head; ent; ent = ent->next) {
    if (cmp_proxy_ent(&ent->key, key)) {
      qos_apply_cfg(ent, &cfg);
      break;
    }
  }

  PROXY_UNLOCK();
  return 0;
}

/* Park the reading side of fd on the entry's bucket. Returns 0 on success;
 * -1 when the ring is full, in which case the caller lets the read proceed
 * unshaped for this burst (availability over precision — a full ring means
 * hundreds of throttled conns already queued). */
static int
qos_park_reader(proxy_map_ent_t *ent, proxy_fd_ent_t *pfe, int fd)
{
  struct proxy_qos_bucket *b = &ent->qos_up;
  int owner = notify_owner_thr(proxy_struct->ns, fd);

  pthread_mutex_lock(&b->park_lock);
  if (b->n_parked >= QOS_MAX_PARKED) {
    pthread_mutex_unlock(&b->park_lock);
    return -1;
  }
  b->parked[b->n_parked].fd = fd;
  b->parked[b->n_parked].gen =
      atomic_load_explicit(&pfe->gen, memory_order_acquire);
  b->parked[b->n_parked].owner_thr = owner;
  b->n_parked++;
  pthread_mutex_unlock(&b->park_lock);

  /* flags BEFORE the poll-mask change so a racing event observes the park */
  pfe->qos_parked = 1;
  pfe->qos_was_parked = 1;
  pfe->read_paused = 1;
  atomic_fetch_add_explicit(&b->parks, 1, memory_order_relaxed);
  notify_add_ent(proxy_struct->ns, fd, NOTI_TYPE_HUP, pfe, pfe->gen);
  return 0;
}

/* Resume half of the park/resume pair — invoked on the fd's OWNER worker via
 * the notify wake path (see pd_resume_parked, which dispatches here first).
 * Re-arms EPOLLIN; the pending payload is still unread in the socket buffer,
 * so level-triggered poll re-drives handle_client_data naturally. Returns 1
 * when the fd was a QoS park (caller stops), 0 otherwise. */
static int
qos_resume_reader(int fd, proxy_fd_ent_t *pfe)
{
  if (!pfe->qos_parked) {
    return 0;
  }
  pfe->qos_parked = 0;
  pfe->read_paused = 0;
  notify_add_ent(proxy_struct->ns, fd, NOTI_TYPE_IN | NOTI_TYPE_HUP, pfe, pfe->gen);
  return 1;
}

/* Notifier tick: refill every active bucket and wake parked readers when
 * tokens returned. Runs opportunistically from EVERY worker's poll loop (not
 * only the timeout branch — under sustained event load poll never times out,
 * and parked fds must not starve); the CAS on qos_last_tick_ns elects one
 * refiller per quantum, so the common case is a single atomic load. */
void
proxy_qos_tick(int thread)
{
  (void)thread;
  proxy_map_ent_t *ent;

  if (!proxy_struct) {
    return;
  }

  uint64_t now = qos_now_ns();
  uint64_t last = atomic_load_explicit(&qos_last_tick_ns, memory_order_relaxed);
  if (now - last < QOS_TICK_QUANTUM_NS) {
    return;
  }
  if (!atomic_compare_exchange_strong_explicit(&qos_last_tick_ns, &last, now,
                                               memory_order_acq_rel,
                                               memory_order_relaxed)) {
    return;
  }

  PROXY_RDLOCK();
  for (ent = proxy_struct->head; ent; ent = ent->next) {
    if (ent->qos_cfg.cir_Bps == 0) {
      continue;
    }
    struct proxy_qos_bucket *b = &ent->qos_up;
    qos_bucket_refill(b, ent->qos_cfg.cir_Bps,
                      qos_effective_cbs(&ent->qos_cfg), now);
    if (atomic_load_explicit(&b->tokens, memory_order_relaxed) > 0) {
      qos_wake_all_parked(b);
    }
  }
  PROXY_UNLOCK();
}

// P2: Configure draining policy for a proxy service
// This sets the draining behavior when endpoints are marked inactive
// policy: 0=GRACEFUL, 1=TIMED, 2=IMMEDIATE
int
proxy_set_drain_policy(proxy_ent_t *key, unsigned int policy, uint32_t timeout_sec)
{
  proxy_map_ent_t *ent;
  proxy_epval_t *tepval, *tmp_epval;
  
  if (!key) {
    log_error("P2: proxy_set_drain_policy - invalid key");
    return -EINVAL;
  }
  
  if (policy > DRAIN_POLICY_IMMEDIATE) {
    log_error("P2: proxy_set_drain_policy - invalid policy %d", policy);
    return -EINVAL;
  }

  PROXY_LOCK();
  
  // Find existing proxy entry
  ent = proxy_struct->head;
  while (ent) {
    if (cmp_proxy_ent(&ent->key, key)) {
      // Entry found - update draining policy
      HASH_ITER(hh, ent->val.ephash, tepval, tmp_epval) {
        tepval->drain_policy = (drain_policy_t)policy;
        tepval->drain_timeout_sec = timeout_sec > 0 ? timeout_sec : 60; // Default 60s
        
        log_info("P2: Drain policy updated - service %s:%u, policy=%d, timeout=%us",
                 inet_ntoa(*(struct in_addr *)&key->xip), ntohs(key->xport),
                 policy, tepval->drain_timeout_sec);
        
        PROXY_UNLOCK();
        return 0;
      }
      
      PROXY_UNLOCK();
      log_error("P2: proxy_set_drain_policy - no ephash entry found");
      return -ENOENT;
    }
    ent = ent->next;
  }

  PROXY_UNLOCK();
  log_error("P2: proxy_set_drain_policy - entry not found for %s:%u",
            inet_ntoa(*(struct in_addr *)&key->xip), ntohs(key->xport));
  return -ENOENT;
}

// PHASE 1: Configure CHWBL dynamic prefix hash settings
int
proxy_set_chwbl_prefix_config(proxy_ent_t *key,
                                uint32_t level,
                                uint32_t flags,
                                uint8_t enable_cache_salt)
{
  proxy_map_ent_t *ent;
  proxy_epval_t *tepval, *tmp_epval;
  
  if (!key) {
    log_error("proxy_set_chwbl_prefix_config: NULL key");
    return -EINVAL;
  }
  
  // Validate level
  if (level < 1 || level > 3) {
    log_error("proxy_set_chwbl_prefix_config: Invalid level=%u (must be 1-3)", level);
    return -EINVAL;
  }
  
  // PHASE 2: Warn about Level 2 cache fragmentation
  if (level == 2) {
    log_warn("proxy_set_chwbl_prefix_config: Level 2 enabled for service %s:%u - "
             "cache will be per-session (lower global hit rate expected)",
             inet_ntoa(*(struct in_addr *)(&key->xip)), ntohs(key->xport));
  }
  
  // PHASE 3: Warn about Level 3 cache fragmentation
  if (level == 3) {
    log_warn("proxy_set_chwbl_prefix_config: Level 3 enabled for service %s:%u - "
             "cache will be per-RAG-context (specialized for document-specific workloads)",
             inet_ntoa(*(struct in_addr *)(&key->xip)), ntohs(key->xport));
  }
  
  PROXY_LOCK();
  
  // Find proxy entry
  ent = proxy_struct->head;
  while (ent) {
    if (cmp_proxy_ent(&ent->key, key)) {
      // Entry found - update all ephash entries
      HASH_ITER(hh, ent->val.ephash, tepval, tmp_epval) {
        // Check if CHWBL or WRR_HASH is enabled
        if (tepval->select != PROXY_SEL_CHWBL && tepval->select != PROXY_SEL_WRR_HASH) {
          PROXY_UNLOCK();
          log_warn("proxy_set_chwbl_prefix_config: CHWBL/WRR_HASH not enabled (select=%d)", tepval->select);
          return -EINVAL;
        }
        
        // Check if CHWBL config exists
        if (!tepval->chwbl_config) {
          PROXY_UNLOCK();
          log_error("proxy_set_chwbl_prefix_config: chwbl_config is NULL");
          return -ENOENT;
        }
        
        // Update configuration
        tepval->chwbl_config->prefix_hash_level = level;
        tepval->chwbl_config->prefix_hash_flags = flags;
        tepval->chwbl_config->enable_cache_salt = enable_cache_salt;
        
        log_info("CHWBL prefix config updated: service=%s:%u, level=%u, flags=0x%x, cache_salt=%u",
                 inet_ntoa(*(struct in_addr *)(&key->xip)), ntohs(key->xport),
                 level, flags, enable_cache_salt);
        
        PROXY_UNLOCK();
        return 0;
      }
      
      PROXY_UNLOCK();
      log_error("proxy_set_chwbl_prefix_config: No ephash entry found");
      return -ENOENT;
    }
    ent = ent->next;
  }
  
  PROXY_UNLOCK();
  log_error("proxy_set_chwbl_prefix_config: Service not found");
  return -ENOENT;
}
/* Circuit breaker moved to sockproxy_health.c */

// P2 Task 2.3: Configure circuit breaker for a proxy service
// enabled: 1=enabled, 0=disabled
// failure_threshold: Number of consecutive failures before opening (0=use default 5)
// open_timeout_sec: Timeout before HALF_OPEN (0=use default 30)
int
proxy_set_circuit_breaker(proxy_ent_t *key, uint8_t enabled, 
                          uint32_t failure_threshold, uint32_t open_timeout_sec)
{
  proxy_map_ent_t *ent;
  proxy_epval_t *tepval, *tmp_epval;
  
  if (!key) {
    log_error("proxy_set_circuit_breaker - invalid key");
    return -EINVAL;
  }

  PROXY_LOCK();
  
  // Find existing proxy entry
  ent = proxy_struct->head;
  while (ent) {
    if (cmp_proxy_ent(&ent->key, key)) {
      // Entry found - update circuit breaker config
      HASH_ITER(hh, ent->val.ephash, tepval, tmp_epval) {
        tepval->cb_enabled = enabled;
        
        if (enabled) {
          // Initialize circuit breakers for all endpoints
          for (int i = 0; i < tepval->n_eps; i++) {
            circuit_breaker_init(&tepval->circuit_breakers[i]);
            
            // Apply custom thresholds if provided
            if (failure_threshold > 0) {
              tepval->circuit_breakers[i].failure_threshold = failure_threshold;
            }
            if (open_timeout_sec > 0) {
              tepval->circuit_breakers[i].open_timeout_sec = open_timeout_sec;
            }
          }
        } 
        
        PROXY_UNLOCK();
        return 0;
      }
      
      PROXY_UNLOCK();
      return -ENOENT;
    }
    ent = ent->next;
  }

  PROXY_UNLOCK();
  log_error("proxy_set_circuit_breaker - entry not found for %s:%u",
            inet_ntoa(*(struct in_addr *)&key->xip), ntohs(key->xport));
  return -ENOENT;
}

static int
proxy_ct_from_fd(int fd, struct dp_ct_key *ctk, int odir)
{
  struct sockaddr_in sin_addr;
  struct sockaddr_in sin_addr2;
  socklen_t sin_len;
  socklen_t optsize = sizeof(int);
  int protocol;

  if (getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &protocol, &optsize)) {
    return -1;
  }

  ctk->l4proto = (uint8_t)protocol;

  sin_len = sizeof(struct sockaddr);
  if (getsockname(fd, (struct sockaddr*)&sin_addr, &sin_len)) {
    return -1;
  }

  if (getpeername(fd, (struct sockaddr*)&sin_addr2, &sin_len)) {
    return -1;
  }

  if (odir) {
    ctk->saddr[0] = sin_addr.sin_addr.s_addr;
    ctk->sport = sin_addr.sin_port;
    ctk->daddr[0]= sin_addr2.sin_addr.s_addr;
    ctk->dport = sin_addr2.sin_port;
  } else {
    ctk->saddr[0] = sin_addr2.sin_addr.s_addr;
    ctk->sport = sin_addr2.sin_port;
    ctk->daddr[0]= sin_addr.sin_addr.s_addr;
    ctk->dport = sin_addr.sin_port;
  }

  return 0;
}

static void
proxy_ct_dump(const char *str, struct dp_ct_key *ctk)
{
  char ab1[INET6_ADDRSTRLEN];
  char ab2[INET6_ADDRSTRLEN];

  inet_ntop(AF_INET, (struct in_addr *)&ctk->daddr[0], ab1, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, (struct in_addr *)&ctk->saddr[0], ab2, INET_ADDRSTRLEN);
#ifdef HAVE_PROXY_EXTRA_DEBUG
  log_debug("%s %s:%u -> %s:%u:%d", str,
            ab1, ntohs(ctk->dport), ab2, ntohs(ctk->sport), ctk->l4proto);
#endif
}

void
proxy_dump_entry(proxy_info_cb_t cb)
{
  proxy_map_ent_t *node;
  proxy_fd_ent_t *fd_ent;
  struct dp_proxy_ct_ent pct;
  int i = 0;
  int j = 0;

  PROXY_LOCK();
  node = proxy_struct->head;
  while (node) {
    fd_ent = node->val.fdlist;
    while (fd_ent) {
      if (fd_ent->odir == 0) {
        memset(&pct, 0, sizeof(pct));
        pct.rid = fd_ent->_id;
        if (!proxy_ct_from_fd(fd_ent->fd, &pct.ct_in, 0)) {
          pct.st_in.bytes = fd_ent->ntb;
          pct.st_in.bytes += fd_ent->nrb;
          pct.st_in.packets = fd_ent->ntp;
          pct.st_in.packets += fd_ent->nrp;

          if (!cb) proxy_ct_dump("dir", &pct.ct_in);
          /* CRASH FIX: this metrics dump must NOT dereference the rfd_ent[]
           * cross-pointers. fd_ent->rfd_ent[j] points to a sibling fd_ent, and
           * the P/D data path publishes those slots UNLOCKED — pd_initiate_decode()
           * does `rfd_ent[slot]=X; n_rfd++` with no PROXY_LOCK and no memory
           * barrier. Although this collector holds PROXY_LOCK, it can observe the
           * incremented n_rfd before the rfd_ent[slot] store is visible and read a
           * stale/freed slot, so `rfd_ent[j]->ntb` was a use-after-free that took
           * `signal arrived during cgo execution` and crashed the whole data plane
           * under load (the Prometheus conntrack collector runs every 10s). This is
           * a best-effort metrics reader, so it now reports only the reverse leg's
           * CT direction (derived from the rfd[] fd, an int — safe to read torn)
           * with zeroed reverse-direction byte/packet stats. n_rfd is snapshotted
           * once and bounded by MAX_PROXY_EP to also guard against a racy over-count. */
          int n_rfd_snap = fd_ent->n_rfd;
          if (n_rfd_snap > MAX_PROXY_EP) n_rfd_snap = MAX_PROXY_EP;
          for (j = 0; j < n_rfd_snap; j++) {
            memset(&pct.st_out, 0, sizeof(pct.st_out));
            if (!proxy_ct_from_fd(fd_ent->rfd[j], &pct.ct_out, 1)) {
              if (!cb) proxy_ct_dump("rdir", &pct.ct_out);
              if (cb) {
                cb(&pct);
              }
            }
          }
        }
      }
      fd_ent = fd_ent->next;
    }
    node = node->next;
    i++;
  }
  PROXY_UNLOCK();
}

void
proxy_get_entry_stats(uint32_t id, int epid, uint64_t *p, uint64_t *b)
{
  proxy_map_ent_t *node;
  proxy_epval_t *epv;
  int i = 0;

  *p = 0;
  *b = 0;

  PROXY_LOCK();
  node = proxy_struct->head;
  while (node) {
    for (epv = node->val.ephash; epv; epv = epv->hh.next) {
      // CRITICAL FIX: Match rule ID before returning stats
      if (epv->_id == id && epid >= 0 && epid < MAX_PROXY_EP) {
        *b = epv->ep_stats[epid].ntb;
        *p = epv->ep_stats[epid].ntp;
        PROXY_UNLOCK();
        return;
      }
    }
    node = node->next;
    i++;
  }
  PROXY_UNLOCK();
}

int
proxy_selftests()
{
  proxy_ent_t key = { 0 };
  proxy_arg_t *arg = NULL;
  proxy_ent_t key2 = { 0 };
  int n = 0;
  
  // Use heap allocation for consistency with production code
  arg = calloc(1, sizeof(proxy_arg_t));
  if (!arg) {
    log_error("[TEST] Failed to allocate proxy_arg");
    return -ENOMEM;
  }

  key.xip = inet_addr("172.17.0.2");
  key.xport = htons(22222);

  arg->eps[0].xip = inet_addr("127.0.0.1");
  arg->eps[0].xport = htons(33333);
  arg->n_eps = 1;
  proxy_add_entry(&key, arg);

  key2.xip = inet_addr("127.0.0.2");
  key2.xport = htons(22222);
  proxy_add_entry(&key2, arg);
  proxy_dump_entry(NULL);

  // Note: arg is freed automatically by proxy_delete_entry cleanup
  proxy_delete_entry(&key2, arg);
  proxy_dump_entry(NULL);

  while(0) {
    sleep(1);
    n++;
    if (n > 10) {
      // Note: arg will be freed automatically by proxy_delete_entry cleanup
      proxy_delete_entry(&key, arg);
    }
  }
  
  // arg is already freed by proxy_delete_entry - no manual cleanup needed

  return 0;
}

void
proxy_reset_fd_list(proxy_map_ent_t *ent, void *match_pfe)
{
  proxy_fd_ent_t *fd_ent;
  proxy_fd_ent_t *pfd_ent = NULL;

  if (!ent) return;

  fd_ent = ent->val.fdlist;

  if (match_pfe == NULL) {
    while (fd_ent) {
      fd_ent->head = NULL;
      fd_ent = fd_ent->next;
      ent->val.nfds--;
    }
    ent->val.fdlist = NULL;
  } else {
    while (fd_ent) {
      if (fd_ent == match_pfe) {
        if (pfd_ent) {
          pfd_ent->next = fd_ent->next;
        } else {
          ent->val.fdlist = fd_ent->next;
        }
        ent->val.nfds--;
        break;
      }
      pfd_ent = fd_ent;
      fd_ent = fd_ent->next;
    }
  }
}

static void __attribute__((unused))
cleanup_failed_ssl_connection(proxy_fd_ent_t *pfe)
{
  if (pfe->ssl) {
    if (!pfe->ssl_err) {
      SSL_shutdown(pfe->ssl);
    }
    SSL_free(pfe->ssl);
    pfe->ssl = NULL;
    log_trace("SSL context cleaned up for fd=%d", pfe->fd);
  }
  
  // Force cache cleanup on SSL failures
  proxy_destroy_xmitcache(pfe);
  
  // Reset sticky session on SSL errors to prevent stale bindings
  if (pfe->is_sticky) {
    log_info("STICKY-SESSION: Resetting session due to SSL error - fd=%d, key='%s'", 
             pfe->fd, pfe->session_key);
    pfe->is_sticky = 0;
    pfe->sticky_server_id = -1;
    pfe->session_key[0] = '\0';
    pfe->session_created = 0;
    pfe->last_activity = 0;
  }
}

/* Reset P/D orchestration state and free heap buffers.
 * Called on connection close, error, and P/D flow completion. */
void
pd_cleanup(proxy_fd_ent_t *fd_ent)
{
  /* RES-03: Log pd_phase on teardown for debugging disconnects */
  if (fd_ent->pd_phase != PD_PHASE_NONE) {
    log_info("pd_cleanup: fd=%d pd_phase=%d prefill_ep=%d decode_ep=%d",
             fd_ent->fd, fd_ent->pd_phase,
             fd_ent->pd_prefill_ep_idx, fd_ent->pd_decode_ep_idx);
  }

  /* SGLang dual dispatch: the request is over (completion, error, or
   * keep-alive boundary) — a still-open prefill drain leg has no further
   * purpose. shutdown() it so a keep-alive prefill server can't hold the
   * leg (and its pfe) hostage; its own teardown detaches benignly.
   * Janitorial close — the decode-failure coupling counter is ticked by the
   * decode-death paths, not here. */
  if (fd_ent->pd_sg_active) {
    pd_sg_close_drain(fd_ent, 0);
  }

  /* atomic single-owner free — see pd_free_claim banner. The historic
   * if(p){free;p=NULL;} double-freed when this ran concurrently for the same pfe on
   * the client-fd and backend-fd worker threads (conc=128 permanent wedge). */
  pd_free_claim(&fd_ent->pd_saved_body);
  fd_ent->pd_saved_body_len = 0;

  pd_free_claim(&fd_ent->pd_saved_headers);
  fd_ent->pd_saved_headers_len = 0;

  pd_free_claim(&fd_ent->pd_prefill_resp_buf);
  fd_ent->pd_prefill_resp_len = 0;
  fd_ent->pd_prefill_resp_cap = 0;

  /* INTG-06: Decrement active_conns for P/D EPs at teardown */
  if (fd_ent->epv) {
    proxy_epval_t *teardown_epval = (proxy_epval_t *)fd_ent->epv;
    if (fd_ent->pd_prefill_ep_idx >= 0 &&
        fd_ent->pd_prefill_ep_idx < teardown_epval->n_eps) {
      /* Bug3-fix (US-H201): guard against uint32_t underflow on double-cleanup */
      uint32_t cur_pre = atomic_load(&teardown_epval->pd_ep_loads[fd_ent->pd_prefill_ep_idx].active_conns);
      if (cur_pre > 0)
        atomic_fetch_sub(&teardown_epval->pd_ep_loads[fd_ent->pd_prefill_ep_idx].active_conns, 1);

      /* (R1) DEQUEUE-ON-SLOT-FREE: a prefill slot on EP `e` just freed.
       * If the bounded-admission FIFO is enabled and EP `e` has a parked head, pop the
       * OLDEST entry and WAKE ITS OWNER WORKER to re-drive it (pd_resume_parked). We do
       * NOT re-dispatch here: pd_cleanup may run on the decode-complete backend worker
       * (pinned to THIS conn's owner) OR the client-close worker — neither is guaranteed
       * to be the PARKED conn's owner. Re-dispatching off-owner is the rejected R3
       * cross-thread UAF; routing to notify_owner_thr(parked_fd) + notify_wake_worker
       * keeps the re-drive on the parked fd's own worker (Landmine 1). The popped entry's
       * (fd,gen) is gen-validated at resume time (pd_resume_parked) — a recycled fd is
       * dropped. Default-off: pd_queue_depth_per_ep()==0 ⇒ the FIFO is never touched ⇒
       * byte-identical to pre-. No buffer free here, so pd_free_claim is untouched
       * (Landmine 2). */
      if (cur_pre > 0 && pd_queue_depth_per_ep() > 0) {
        int e = fd_ent->pd_prefill_ep_idx;
        pd_parked_ent_t popped = { 0 };
        int have = 0;
        pthread_mutex_lock(&teardown_epval->pd_parked_lock);
        have = pd_parked_pop_head(&teardown_epval->pd_parked[e], &popped);
        pthread_mutex_unlock(&teardown_epval->pd_parked_lock);
        if (have && popped.fd > 0) {
          int owner = notify_owner_thr(proxy_struct->ns, popped.fd);
          if (owner >= 0) {
            int wrc = notify_wake_worker(proxy_struct->ns, owner, popped.fd);
            if (wrc == 0) {
              log_info("[PD_ADMISSION] dequeue: slot freed on prefill ep=%d -> waking "
                       "owner worker %d for parked fd=%d (gen=%lu)",
                       e, owner, popped.fd, (unsigned long)popped.gen);
            } else {
              /* wake failed (ring full / bad owner) — the entry is already popped;
               * the conn stays parked and the max-park reap will eventually drop it.
               * No leak of the FIFO slot (it was popped); the conn's fd/rcvbuf are
               * still bounded by LLB_PD_MAX_PARK_SEC. */
              log_warn("[PD_ADMISSION] dequeue: wake failed (rc=%d) for parked fd=%d "
                       "(owner=%d) — relying on max-park reap", wrc, popped.fd, owner);
            }
          }
        }
      }
    }
    if (fd_ent->pd_decode_ep_idx >= 0 &&
        fd_ent->pd_decode_ep_idx < teardown_epval->n_eps) {
      /* Bug3-fix (US-H201): guard against uint32_t underflow on double-cleanup */
      uint32_t cur_dec = atomic_load(&teardown_epval->pd_ep_loads[fd_ent->pd_decode_ep_idx].active_conns);
      
      if (cur_dec > 0)
        atomic_fetch_sub(&teardown_epval->pd_ep_loads[fd_ent->pd_decode_ep_idx].active_conns, 1);
    }
  }

  /* single-role Tier-1.5 load release — the generic-
   * teardown half of the paired decrement (increment lives in the single-role
   * KV branch in sockproxy_ep.c; the other claimant is the backend connect-
   * failure path there). __atomic_exchange claims kv_sr_load_held so
   * concurrent pd_cleanup runs (client-fd vs backend-fd worker — the Phase-89
   * pd_free_claim race class) or an earlier connect-fail release can never
   * double-decrement (single-owner discipline). Zero-init/mode-1 connections
   * never set the flag, so this block is byte-identical no-op for P/D. */
  if (fd_ent->epv &&
      __atomic_exchange_n(&fd_ent->kv_sr_load_held, 0, __ATOMIC_ACQ_REL)) {
    proxy_epval_t *sr_epval = (proxy_epval_t *)fd_ent->epv;
    if (fd_ent->kv_sr_ep_idx >= 0 && fd_ent->kv_sr_ep_idx < sr_epval->n_eps) {
      /* Bug3-fix shape: guard against uint32_t underflow on double-cleanup */
      uint32_t cur_sr =
          atomic_load(&sr_epval->pd_ep_loads[fd_ent->kv_sr_ep_idx].active_conns);
      if (cur_sr > 0)
        atomic_fetch_sub(&sr_epval->pd_ep_loads[fd_ent->kv_sr_ep_idx].active_conns, 1);
    }
    fd_ent->kv_sr_ep_idx = -1;
  }

  fd_ent->pd_phase = PD_PHASE_NONE;
  fd_ent->pd_prefill_ep_idx = -1;
  fd_ent->pd_decode_ep_idx = -1;
  fd_ent->pd_kv_params[0] = '\0';
  fd_ent->pd_kv_params_len = 0;
  fd_ent->pd_prefill_body_len = 0;
  fd_ent->pd_phase_start_ts = 0;
  fd_ent->pd_prefill_start_ns = 0;
  fd_ent->pd_decode_start_ns = 0;
  fd_ent->pd_decode_content_length = 0;
  fd_ent->pd_decode_bytes_received = 0;
  fd_ent->pd_prefill_retries = 0;
  fd_ent->pd_sg_active = 0;
  fd_ent->pd_sg_room = 0;
}

/* proxy_release_fd_ctx moved to sockproxy_conn.c */

static void
proxy_release_rfd_ctx(proxy_fd_ent_t *pfe)
{
  proxy_fd_ent_t *fd_ent;
  int n = 0;

  for (int i = 0; n < pfe->n_rfd && i < MAX_PROXY_EP; i++) {
    fd_ent = pfe->rfd_ent[i];
    if (fd_ent) {
      PROXY_ENT_LOCK(fd_ent);
      log_trace("sockproxy rfd %d release", fd_ent->fd);
      proxy_release_fd_ctx(fd_ent, 0);
      notify_delete_ent(proxy_struct->ns, fd_ent->fd, 1);
      pfe->rfd_ent[i] = NULL;
      if (!pfe->odir) {
        for (int j = 0; j < fd_ent->n_rfd; j++) {
          fd_ent->rfd_ent[j] = NULL;
        }
        fd_ent->n_rfd = 0;
      } else {
        for (int j = 0; j < fd_ent->n_rfd; j++) {
          if (fd_ent->rfd_ent[j] == pfe) {
            fd_ent->rfd_ent[j] = NULL;
            fd_ent->n_rfd--;
          }
        }
      }
      PROXY_ENT_UNLOCK(fd_ent);
      n++;
    }
    pfe->rfd[i] = -1;
  }
  pfe->n_rfd = 0;
}

void
proxy_pdestroy(void *priv)
{
  proxy_map_ent_t *ent;
  proxy_fd_ent_t *pfe = priv;
  proxy_fd_ent_t *fd_ent;
  int is_listener = 0;

  /* Prefill mid-request failover work is COLLECTED under PROXY_LOCK below and
   * EXECUTED after the final PROXY_UNLOCK (pd_retry_prefill / pd_sg_retry_pair
   * re-take the non-recursive lock to register the replacement leg(s)).
   * sg selects the flavor: 0 = vLLM prefill-only re-dispatch, 1 = SGLang
   * pair retry with a fresh room. */
  struct {
    proxy_fd_ent_t *cpfe;
    int dead_idx;
    int sg;
    uint8_t *hdrs; size_t hdrs_len;
    uint8_t *body; size_t body_len;
  } pd_retry_pend[MAX_PROXY_EP];
  int n_pd_retry_pend = 0;

  assert(pfe);

  // Log sticky session cleanup
  if (pfe->is_sticky && pfe->session_key[0] != '\0') {
    log_info("STICKY-SESSION: Cleaning up sticky session - fd=%d, key='%s', server=%d, created=%ld", 
             pfe->fd, pfe->session_key, pfe->sticky_server_id, pfe->session_created);
  }

  PROXY_LOCK();
  if (pfe) {
    PROXY_ENT_LOCK(pfe);
    ent = pfe->head;
    if (!ent) {
      assert(0);
      PROXY_ENT_UNLOCK(pfe);
      proxy_try_free_fd_ctx(pfe);
      PROXY_UNLOCK();
      return;
    }

    if (pfe->fd == ent->val.main_fd) {
      is_listener = 1;
      fd_ent = ent->val.fdlist;
      while (fd_ent) {
        if (fd_ent->odir == 0) {
          proxy_release_rfd_ctx(fd_ent);
          if (fd_ent->fd != ent->val.main_fd) {
            proxy_release_fd_ctx(fd_ent, 0);
          }
        }
        fd_ent = fd_ent->next;
      }
    }

    /* P/D prefill connection failure — when a backend fd (odir==1)
     * is being destroyed while its client is waiting for a prefill response,
     * send 502 {"error":"pd_prefill_failed"} to the client before cleanup. */
    if (!is_listener && pfe->odir == 1) {
      for (int pd_i = 0; pd_i < pfe->n_rfd && pd_i < MAX_PROXY_EP; pd_i++) {
        proxy_fd_ent_t *client_pfe = pfe->rfd_ent[pd_i];
        if (client_pfe &&
            client_pfe->pd_phase >= PD_PHASE_PREFILL_SENDING &&
            client_pfe->pd_phase <= PD_PHASE_PREFILL_DONE) {
          log_error("Prefill backend died — client_fd=%d backend_fd=%d "
                    "phase=%d", client_pfe->fd, pfe->fd, client_pfe->pd_phase);
          atomic_fetch_add(&global_stats.pd_prefill_ep_died, 1);

          /* Prefill mid-request failover: the complete request survives in
           * pd_saved_headers/pd_saved_body and prefill is idempotent, so
           * defer ONE re-dispatch against a re-selected EP instead of
           * failing the client. Buffers are heap-COPIED here (under
           * PROXY_LOCK) so the decode phase keeps the originals. TLS backend
           * legs are excluded for parity with the decode leg (which connects
           * plaintext). */
          int pd_deferred = 0;
          if ((client_pfe->pd_phase == PD_PHASE_PREFILL_SENDING ||
               client_pfe->pd_phase == PD_PHASE_PREFILL_WAITING) &&
              client_pfe->pd_prefill_retries == 0 &&
              client_pfe->epv && !pfe->ssl &&
              client_pfe->pd_saved_headers &&
              client_pfe->pd_saved_headers_len > 0 &&
              client_pfe->pd_saved_body &&
              client_pfe->pd_saved_body_len > 0 &&
              n_pd_retry_pend < MAX_PROXY_EP) {
            uint8_t *rh = malloc(client_pfe->pd_saved_headers_len);
            uint8_t *rb = rh ? malloc(client_pfe->pd_saved_body_len) : NULL;
            if (rh && rb) {
              memcpy(rh, client_pfe->pd_saved_headers,
                     client_pfe->pd_saved_headers_len);
              memcpy(rb, client_pfe->pd_saved_body,
                     client_pfe->pd_saved_body_len);
              client_pfe->pd_prefill_retries = 1;
              /* Detach both directions so this leg's teardown below cannot
               * cascade-close the client (US-H202 idiom). */
              for (int j = 0; j < MAX_PROXY_EP; j++) {
                if (client_pfe->rfd_ent[j] == pfe) {
                  client_pfe->rfd_ent[j] = NULL;
                  client_pfe->rfd[j] = -1;
                  if (client_pfe->n_rfd > 0) client_pfe->n_rfd--;
                  break;
                }
              }
              pd_retry_pend[n_pd_retry_pend].cpfe = client_pfe;
              pd_retry_pend[n_pd_retry_pend].dead_idx =
                  client_pfe->pd_prefill_ep_idx;
              pd_retry_pend[n_pd_retry_pend].sg = 0;
              pd_retry_pend[n_pd_retry_pend].hdrs = rh;
              pd_retry_pend[n_pd_retry_pend].hdrs_len =
                  client_pfe->pd_saved_headers_len;
              pd_retry_pend[n_pd_retry_pend].body = rb;
              pd_retry_pend[n_pd_retry_pend].body_len =
                  client_pfe->pd_saved_body_len;
              n_pd_retry_pend++;
              pfe->rfd_ent[pd_i] = NULL;
              pfe->n_rfd--;
              pd_deferred = 1;
            } else {
              free(rh);
              free(rb);
            }
          }

          if (!pd_deferred) {
            /* P5-fix: 503 (not 502) — prefill backend connection drop means
             * the P/D backend pool is unavailable, not a proxy protocol
             * error. */
            static const char pd_prefill_err[] =
                "HTTP/1.1 503 Service Unavailable\r\n"
                "Content-Type: application/json\r\n"
                "Connection: close\r\n"
                "\r\n"
                "{\"error\":\"pd_pool_unavailable\",\"detail\":\"prefill backend connection dropped\"}";
            /* Record the failed lifecycle so prefill-death 503s are visible
             * in the P/D request metrics (previously logs-only). */
            {
              const char *pd_model = proxy_effective_model(client_pfe);
              int pd_kv = (client_pfe->pd_kv_params_len > 0) ? 1 : 0;
              llb_ai_pd_record((char *)pd_model, 0, 0, pd_kv,
                               1 /*prefill error*/);
            }
            if (client_pfe->fd > 0) {
              send(client_pfe->fd, pd_prefill_err, sizeof(pd_prefill_err) - 1,
                   MSG_DONTWAIT | MSG_NOSIGNAL);
            }
            pd_cleanup(client_pfe);
            client_pfe->pd_phase = PD_PHASE_ERROR;
          }
        }
      }

      /* P/D backend EOF during decode phase.
       * Two scenarios when a backend (odir==1) closes while client is in decode:
       * 1. PREFILL backend EOF: normal — prefill completed, detach without cascading
       * 2. DECODE backend EOF: non-streaming decode complete — record metrics
       *
       * We distinguish by attempting to detach this backend from the client's
       * rfd_ent[]. If found and removed, this was a prefill backend (detach only).
       * If NOT found in client's rfd_ent[] or if it IS the active backend,
       * this is the decode backend closing (completion). */
      for (int pd_i = 0; pd_i < pfe->n_rfd && pd_i < MAX_PROXY_EP; pd_i++) {
        proxy_fd_ent_t *client_pfe = pfe->rfd_ent[pd_i];
        if (!client_pfe) continue;

        /* US-H202: Decode backend closing after P/D already completed (pd_cleanup
         * set pd_phase=NONE via SSE [DONE] or non-streaming completion).
         * Just detach without closing the still-alive keep-alive client. */
        if ((pfe->is_pd_decode_backend || pfe->pd_sg_drain) &&
            client_pfe->pd_phase == PD_PHASE_NONE) {
          for (int j = 0; j < client_pfe->n_rfd; j++) {
            if (client_pfe->rfd_ent[j] == pfe) {
              client_pfe->rfd_ent[j] = NULL;
              client_pfe->n_rfd--;
              break;
            }
          }
          pfe->rfd_ent[pd_i] = NULL;
          pfe->n_rfd--;
          log_info("[US-H202] Decode backend fd=%d detaching from keep-alive client fd=%d "
                   "(pd_phase=NONE, P/D already complete)",
                   pfe->fd, client_pfe->fd);
          continue;
        }

        if (client_pfe->pd_phase < PD_PHASE_DECODE_SENDING ||
            client_pfe->pd_phase > PD_PHASE_DECODE_STREAMING) continue;

        /* SGLang drain-leg death coupling (pd_router.rs:731 semantics):
         * the prefill leg dying BEFORE its response completed, with ZERO
         * decode bytes relayed, means the rendezvous cannot succeed — the
         * decode engine would sit in WaitingForInput until its 300s
         * disaggregation timeout. Abort the pair now (502; the client-fd
         * shutdown cascade closes the decode leg, whose engine aborts on
         * disconnect in ~4-8s). If decode already produced client-visible
         * bytes (fully radix-cached prompt), let it finish — count only.
         * Either way fall through to the detach loop below so this dying
         * leg cannot cascade-close the client a second time. */
        /* A drain leg in 4xx relay mode dying before message-complete is a
         * CLOSE-FRAMED origin response: EOF is its terminator, not a
         * failure. The client already holds the relayed bytes — finalize
         * (abort-shaped teardown, no synthetic 502 on top of them). */
        if (pfe->pd_sg_drain && pfe->pd_sg_drain_relay &&
            !pfe->pd_sg_drain_done) {
          pfe->pd_sg_drain_done = 1;
          pd_sg_relay_finalize(client_pfe);
        } else
        if (pfe->pd_sg_drain && !pfe->pd_sg_drain_handled &&
            !pfe->pd_sg_drain_done) {
          pfe->pd_sg_drain_handled = 1;
          if (pd_sg_decode_untouched(client_pfe)) {
            /* SGLang pair retry: the ORIGINAL request survives on the client
             * pfe (pd_saved_headers + the pristine pre-injection
             * pd_saved_body) and no client-visible byte has flowed, so defer
             * ONE retry-as-pair — fresh pair, fresh room, both legs
             * restarted — instead of failing the client. Same deferral,
             * buffer-copy, budget and TLS-exclusion contract as the vLLM
             * enqueue above; budget is SHARED (pd_prefill_retries). */
            int sg_deferred = 0;
            if (client_pfe->pd_phase == PD_PHASE_DECODE_SENDING &&
                client_pfe->pd_prefill_retries == 0 &&
                client_pfe->epv && !pfe->ssl &&
                client_pfe->pd_saved_headers &&
                client_pfe->pd_saved_headers_len > 0 &&
                client_pfe->pd_saved_body &&
                client_pfe->pd_saved_body_len > 0 &&
                n_pd_retry_pend < MAX_PROXY_EP) {
              uint8_t *rh = malloc(client_pfe->pd_saved_headers_len);
              uint8_t *rb = rh ? malloc(client_pfe->pd_saved_body_len) : NULL;
              if (rh && rb) {
                memcpy(rh, client_pfe->pd_saved_headers,
                       client_pfe->pd_saved_headers_len);
                memcpy(rb, client_pfe->pd_saved_body,
                       client_pfe->pd_saved_body_len);
                client_pfe->pd_prefill_retries = 1;
                /* Detach both directions so this leg's teardown below cannot
                 * cascade-close the client (US-H202 idiom). */
                for (int j = 0; j < MAX_PROXY_EP; j++) {
                  if (client_pfe->rfd_ent[j] == pfe) {
                    client_pfe->rfd_ent[j] = NULL;
                    client_pfe->rfd[j] = -1;
                    if (client_pfe->n_rfd > 0) client_pfe->n_rfd--;
                    break;
                  }
                }
                pd_retry_pend[n_pd_retry_pend].cpfe = client_pfe;
                pd_retry_pend[n_pd_retry_pend].dead_idx =
                    client_pfe->pd_prefill_ep_idx;
                pd_retry_pend[n_pd_retry_pend].sg = 1;
                pd_retry_pend[n_pd_retry_pend].hdrs = rh;
                pd_retry_pend[n_pd_retry_pend].hdrs_len =
                    client_pfe->pd_saved_headers_len;
                pd_retry_pend[n_pd_retry_pend].body = rb;
                pd_retry_pend[n_pd_retry_pend].body_len =
                    client_pfe->pd_saved_body_len;
                n_pd_retry_pend++;
                pfe->rfd_ent[pd_i] = NULL;
                pfe->n_rfd--;
                sg_deferred = 1;
                log_info("[PD_SG] drain leg died before prefill completed — "
                         "pair retry deferred (client_fd=%d drain_fd=%d "
                         "room=%llu)", client_pfe->fd, pfe->fd,
                         (unsigned long long)client_pfe->pd_sg_room);
              } else {
                free(rh);
                free(rb);
              }
            }
            if (sg_deferred) {
              /* Already fully detached — the decode-death taxonomy below
               * must not misread the dying DRAIN leg as a zero-byte decode
               * EOF against the retried client. */
              continue;
            }
            log_error("[PD_SG] drain leg died before prefill completed — "
                      "aborting pair (client_fd=%d drain_fd=%d)",
                      client_pfe->fd, pfe->fd);
            pd_sg_abort_pair(client_pfe, "drain leg death", 0 /*transport*/);
          } else {
            atomic_fetch_add(&global_stats.pd_prefill_ep_died, 1);
            log_warn("[PD_SG] drain leg died after decode bytes relayed — "
                     "letting decode finish (client_fd=%d drain_fd=%d)",
                     client_pfe->fd, pfe->fd);
          }
        }

        /* Check if this backend (pfe) is still in the client's rfd_ent[].
         * If found, it's a stale link (prefill backend) — detach it.
         * The decode backend was added AFTER prefill; if this pfe is the
         * prefill backend, the client also has the decode backend at a
         * different slot. */
        int is_prefill_backend = 0;
        for (int j = 0; j < client_pfe->n_rfd; j++) {
          if (client_pfe->rfd_ent[j] == pfe) {
            /* Use is_pd_decode_backend flag for reliable prefill/decode
             * backend identification instead of has_other_backend heuristic.
             * The heuristic failed when both pfe slots were still populated at
             * EOF time, misidentifying the decode backend as a prefill backend. */
            if (!pfe->is_pd_decode_backend) {
              is_prefill_backend = 1;
              client_pfe->rfd_ent[j] = NULL;
              log_info("Prefill backend EOF during decode — detaching "
                       "client_fd=%d backend_fd=%d phase=%d",
                       client_pfe->fd, pfe->fd, client_pfe->pd_phase);
            }
            break;
          }
        }

        if (is_prefill_backend) {
          /* Detach client from this backend so proxy_release_rfd_ctx skips it */
          pfe->rfd_ent[pd_i] = NULL;
          pfe->n_rfd--;
        } else if (client_pfe->pd_phase == PD_PHASE_DECODE_SENDING &&
                   client_pfe->pd_last_decode_ts == 0 &&
                   client_pfe->pd_decode_content_length == 0 &&
                   client_pfe->pd_decode_bytes_received == 0) {
          /* decode backend EOF before ONE response byte was relayed —
           * the async-connect-failure signature of a dead decode EP. This was
           * unconditionally treated as "non-streaming decode complete": phase
           * → COMPLETE, llb_ai_pd_record(status 0), while the client received
           * ZERO bytes — failover-invisible and metric-corrupting. Send a
           * real 502 and record errorPhase=2 (decode_error) instead. */
          static const char pd_decode_err[] =
              "HTTP/1.1 502 Bad Gateway\r\n"
              "Content-Type: application/json\r\n"
              "Connection: close\r\n"
              "\r\n"
              "{\"error\":\"pd_decode_backend_died\","
              "\"detail\":\"decode backend closed before any response bytes\"}";
          log_error("decode backend EOF with ZERO response bytes — "
                    "client_fd=%d decode_fd=%d (502 sent, decode_error recorded)",
                    client_pfe->fd, pfe->fd);
          atomic_fetch_add(&global_stats.pd_decode_ep_died, 1);
          atomic_fetch_add(&global_stats.pd_decode_zero_byte_eof, 1);
          if (client_pfe->fd > 0) {
            send(client_pfe->fd, pd_decode_err, sizeof(pd_decode_err) - 1,
                 MSG_DONTWAIT | MSG_NOSIGNAL);
          }
          {
            const char *pd_model = proxy_effective_model(client_pfe);
            int pd_kv = (client_pfe->pd_kv_params_len > 0) ? 1 : 0;
            llb_ai_pd_record((char *)pd_model, 0, 0, pd_kv, 2 /*decode_error*/);
          }
          /* SGLang: decode-leg death must not orphan the prefill drain leg */
          pd_sg_close_drain(client_pfe, 1);
          client_pfe->pd_phase = PD_PHASE_ERROR;
          pd_cleanup(client_pfe);
        } else if (client_pfe->pd_phase == PD_PHASE_DECODE_SENDING) {
          /* Decode backend EOF — non-streaming decode complete */
          client_pfe->pd_phase = PD_PHASE_COMPLETE;
          log_info("Non-streaming decode complete (decode backend EOF) — "
                   "client_fd=%d decode_fd=%d",
                   client_pfe->fd, pfe->fd);
          {
            const char *pd_model = proxy_effective_model(client_pfe);
            struct timespec _pdts;
            clock_gettime(CLOCK_MONOTONIC, &_pdts);
            uint64_t pd_now_ns = (uint64_t)_pdts.tv_sec * 1000000000ULL +
                                 (uint64_t)_pdts.tv_nsec;
            int64_t prefill_ms = 0, decode_ms = 0;
            if (client_pfe->pd_prefill_start_ns > 0 &&
                client_pfe->pd_decode_start_ns > 0) {
              prefill_ms = (int64_t)((client_pfe->pd_decode_start_ns -
                                      client_pfe->pd_prefill_start_ns) / 1000000ULL);
            }
            if (client_pfe->pd_decode_start_ns > 0) {
              decode_ms = (int64_t)((pd_now_ns -
                                     client_pfe->pd_decode_start_ns) / 1000000ULL);
            }
            int pd_kv = (client_pfe->pd_kv_params_len > 0) ? 1 : 0;
            log_info(" llb_ai_pd_record (non-SSE complete): model=%s prefill=%lldms decode=%lldms kv=%d",
                     pd_model, (long long)prefill_ms, (long long)decode_ms, pd_kv);
            llb_ai_pd_record((char *)pd_model, prefill_ms, decode_ms, pd_kv, 0);
          }
          pd_cleanup(client_pfe);
        } else if (client_pfe->pd_phase == PD_PHASE_DECODE_STREAMING &&
                   pfe->is_pd_decode_backend) {
          /* Decode backend EOF mid-stream. A completed stream leaves
           * DECODE_STREAMING via the SSE [DONE] scanner before its backend
           * closes (pd_phase NONE ⇒ the detach branch above), so reaching
           * here means the stream was CUT with no terminator. Completion
           * stays with the reaper paths (graceful-[DONE] synthesizes the
           * terminator after the idle cap), but the EP death itself must be
           * visible to the failover counters — without this tick a
           * mid-stream decode crash is recorded as a clean success. */
          log_error("decode backend EOF mid-stream — client_fd=%d "
                    "decode_fd=%d (stream cut before [DONE]; reaper will "
                    "complete the client)",
                    client_pfe->fd, pfe->fd);
          atomic_fetch_add(&global_stats.pd_decode_ep_died, 1);
          /* SGLang: decode-leg death must not orphan the prefill drain leg */
          pd_sg_close_drain(client_pfe, 1);
        }
        /* DECODE_STREAMING completion (non-cut) handled by SSE [DONE] scanner */
      }
    }

    if (!is_listener) {
      proxy_release_rfd_ctx(pfe);
    }
    proxy_release_fd_ctx(pfe, 1);
    PROXY_ENT_UNLOCK(pfe);
    proxy_try_free_fd_ctx(pfe);

    if (is_listener) {
      ent->val.sched_free = 1;
    }

    if (ent->val.sched_free && ent->val.fdlist == NULL) {
      log_info("sockproxy: %s:%u ent freed",
              inet_ntoa(*(struct in_addr *)&ent->key.xip),
              ntohs(ent->key.xport));
      if (ent->val.ssl_ctx)
        SSL_CTX_free(ent->val.ssl_ctx);
      if (ent->val.ssl_epctx)
        SSL_CTX_free(ent->val.ssl_epctx);
      free(ent);
    }
  }
  PROXY_UNLOCK();

  /* Deferred prefill mid-request failovers (collected above under
   * PROXY_LOCK). Same-thread with the dying leg's teardown — the client pfe
   * cannot be concurrently torn down (Option-A worker pinning). */
  for (int ri = 0; ri < n_pd_retry_pend; ri++) {
    if (pd_retry_pend[ri].sg) {
      pd_sg_retry_pair(pd_retry_pend[ri].cpfe, pd_retry_pend[ri].dead_idx,
                       pd_retry_pend[ri].hdrs, pd_retry_pend[ri].hdrs_len,
                       pd_retry_pend[ri].body, pd_retry_pend[ri].body_len);
    } else {
      pd_retry_prefill(pd_retry_pend[ri].cpfe, pd_retry_pend[ri].dead_idx,
                       pd_retry_pend[ri].hdrs, pd_retry_pend[ri].hdrs_len,
                       pd_retry_pend[ri].body, pd_retry_pend[ri].body_len);
    }
  }
}

static void
proxy_destroy_eps(int sfd, proxy_ep_sel_t *ep_sel)
{
  int i = 0;
  for (i = 0; i < ep_sel->n_eps; i++) {
    if (ep_sel->ep_cfds[i].ep_cfd > 0) {
      ep_sel->ep_cfds[i].ep_cfd = -1;
      ep_sel->ep_cfds[i].ep_num = -1;
    }
  }
}

#define PROXY_SEL_EP_DROP  -1
#define PROXY_SEL_EP_BC    1
#define PROXY_SEL_EP_UC    0

// Session key generation functions
static void
generate_ip_session_key(int fd, char *session_key, size_t key_size)
{
  struct sockaddr_in client_addr;
  socklen_t addr_len = sizeof(client_addr);
  
  if (getpeername(fd, (struct sockaddr*)&client_addr, &addr_len) == 0) {
    snprintf(session_key, key_size, "ip_%s", 
            inet_ntoa(client_addr.sin_addr));
  } else {
    snprintf(session_key, key_size, "ip_unknown_%d", fd);
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_warn("STICKY-SESSION: Failed to get peer info for fd=%d, using fallback key '%s'", fd, session_key);
#endif
  }
}

static int
extract_content_session_key(const char *http_data, size_t data_len, 
                           char *session_key, size_t key_size)
{
  const char *url_start __attribute__((unused)) = NULL;
  const char *url_end __attribute__((unused)) = NULL;
  char method[16] = {0};
  char url[256] = {0};
  
  
  // Parse first line: "METHOD /path HTTP/1.1"
  if (sscanf(http_data, "%15s %255s", method, url) != 2) {
    return -1;
  }  
  
  // Extract content ID from common patterns:
  // POST /upload/file123 -> content_file123
  // GET /download/file456 -> content_file456
  // PUT /content/abc789 -> content_abc789
  
  if (strstr(url, "/upload/") || strstr(url, "/download/") || strstr(url, "/content/")) {
    const char *content_id = strrchr(url, '/');
    if (content_id && strlen(content_id) > 1) {
      snprintf(session_key, key_size, "content_%s", content_id + 1);
      return 0;
    }
  }
  
  // Fallback: use full URL as session key
  snprintf(session_key, key_size, "url_%s", url);
  return 0;
}

// Legacy function - kept for backward compatibility
// New code should use extract_cookie_by_name() with explicit cookie name
static int
extract_cookie_session_key(const char *http_data, size_t data_len,
                          char *session_key, size_t key_size)
{
  const char *cookie_header = strstr(http_data, "Cookie:");
  if (!cookie_header) {
    return -1;
  }  
  
  // Look for JSESSIONID or similar
  const char *session_start = strstr(cookie_header, "JSESSIONID=");
  if (!session_start) {
    session_start = strstr(cookie_header, "sessionid=");
  }
  
  if (session_start) {
    session_start = strchr(session_start, '=') + 1;
    const char *session_end = strpbrk(session_start, ";\r\n ");
    
    size_t session_len = session_end ? (session_end - session_start) : strlen(session_start);
    if (session_len > 0 && session_len < key_size - 8) {
      snprintf(session_key, key_size, "cookie_%.*s", (int)session_len, session_start);
      return 0;
    }
  }
  
  return -1;
}

// NEW: Configurable cookie parser - extract specific cookie by name
// Supports all standard cookie formats used by web frameworks
// Example: extract_cookie_by_name("Cookie: JSESSIONID=abc; theme=dark", "JSESSIONID", value, 64)
// Result: value = "abc" (only the cookie value, other cookies ignored)
// external linkage so sockproxy_l7policy.c reuses this proven
// parser for the L7 COOKIE compare op (RESEARCH §Don't Hand-Roll); prototype in
// sockproxy_l7policy.h. The `static` qualifier was dropped in lock-step.
int
extract_cookie_by_name(const char *headers, const char *cookie_name,
                       char *value, size_t value_size)
{
  if (!headers || !cookie_name || !value || value_size == 0) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[COOKIE_EXTRACT_INVALID] Invalid parameters: headers=%p cookie_name=%p value=%p size=%zu",
              headers, cookie_name, value, value_size);
#endif
    return -1;
  }

  const char *cookie_header = strstr(headers, "Cookie:");
  if (!cookie_header) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[COOKIE_EXTRACT_NOHDR] No Cookie header found in request");
#endif
    return -1;
  }

  // Build search pattern: "cookie_name="
  char search_pattern[256];
  snprintf(search_pattern, sizeof(search_pattern), "%s=", cookie_name);
  
  const char *cookie_start = strstr(cookie_header, search_pattern);
  if (!cookie_start) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[COOKIE_EXTRACT_NOTFOUND] Cookie '%s' not found in Cookie header",
              cookie_name);
#endif
    return -1;
  }

  // Skip past "cookie_name="
  const char *value_start = cookie_start + strlen(search_pattern);
  
  // Find end of cookie value (semicolon, CR, LF, or space)
  const char *value_end = strpbrk(value_start, ";\r\n ");
  
  size_t cookie_len = value_end ? (value_end - value_start) : strlen(value_start);
  
  if (cookie_len == 0) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[COOKIE_EXTRACT_EMPTY] Cookie '%s' has empty value", cookie_name);
#endif
    return -1;
  }
  
  if (cookie_len >= value_size) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_warn("[COOKIE_EXTRACT_TOOLONG] Cookie '%s' value too long (%zu bytes, max %zu), truncating",
             cookie_name, cookie_len, value_size - 1);
#endif
    cookie_len = value_size - 1;
  }

  strncpy(value, value_start, cookie_len);
  value[cookie_len] = '\0';

#ifdef HAVE_PROXY_EXTRA_DEBUG
  log_debug("[COOKIE_EXTRACT_SUCCESS] Extracted cookie '%s'='%s' (%zu bytes)",
            cookie_name, value, cookie_len);
#endif

  return 0;
}

// NEW: URL query parameter parser - extract parameter value from URL
// Supports both ? and & delimiters, handles URL encoding
// Example: extract_query_param_value("/api/data?sessionid=abc123&foo=bar", "sessionid", value, 64)
// Result: value = "abc123"
// external linkage so sockproxy_l7policy.c reuses this proven
// parser for the L7 QUERY compare op (RESEARCH §Don't Hand-Roll); prototype in
// sockproxy_l7policy.h. The `static` qualifier was dropped in lock-step.
int
extract_query_param_value(const char *url, const char *param_name,
                          char *value, size_t value_size)
{
  if (!url || !param_name || !value || value_size == 0) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[QUERY_EXTRACT_INVALID] Invalid parameters: url=%p param_name=%p value=%p size=%zu",
              url, param_name, value, value_size);
#endif
    return -1;
  }

  // Find start of query string
  const char *query_start = strchr(url, '?');
  if (!query_start) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[QUERY_EXTRACT_NOQUERY] No query string in URL: %s", url);
#endif
    return -1;
  }

  // Build search pattern: "param_name="
  char search_pattern[256];
  snprintf(search_pattern, sizeof(search_pattern), "%s=", param_name);
  
  // Search for parameter in query string
  // Handle both ?param=val and &param=val cases
  const char *param_start = strstr(query_start, search_pattern);
  if (!param_start) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[QUERY_EXTRACT_NOTFOUND] Query parameter '%s' not found in URL: %s",
              param_name, url);
#endif
    return -1;
  }

  // Validate that this is a complete parameter match (not substring)
  // Check if preceded by ? or &
  if (param_start != query_start + 1) {  // Not immediately after ?
    const char *prev_char = param_start - 1;
    if (*prev_char != '&') {
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("[QUERY_EXTRACT_SUBSTRING] Parameter '%s' is substring match, not complete parameter",
                param_name);
#endif
      return -1;
    }
  }

  // Skip past "param_name="
  const char *value_start = param_start + strlen(search_pattern);
  
  // Find end of parameter value (&, #, space, or end of string)
  const char *value_end = strpbrk(value_start, "& #\r\n");
  
  size_t param_len = value_end ? (value_end - value_start) : strlen(value_start);
  
  if (param_len == 0) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[QUERY_EXTRACT_EMPTY] Query parameter '%s' has empty value", param_name);
#endif
    return -1;
  }
  
  if (param_len >= value_size) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_warn("[QUERY_EXTRACT_TOOLONG] Query parameter '%s' value too long (%zu bytes, max %zu), truncating",
             param_name, param_len, value_size - 1);
#endif
    param_len = value_size - 1;
  }

  // Copy and URL-decode value (simple decoder - handles %20, %2F, etc.)
  size_t out_idx = 0;
  for (size_t i = 0; i < param_len && out_idx < value_size - 1; i++) {
    if (value_start[i] == '%' && i + 2 < param_len) {
      // URL-encoded character: %XX
      char hex[3] = {value_start[i+1], value_start[i+2], '\0'};
      char *endptr;
      long decoded = strtol(hex, &endptr, 16);
      if (endptr == hex + 2) {
        value[out_idx++] = (char)decoded;
        i += 2;  // Skip the two hex digits
        continue;
      }
    } else if (value_start[i] == '+') {
      // URL-encoded space
      value[out_idx++] = ' ';
      continue;
    }
    value[out_idx++] = value_start[i];
  }
  value[out_idx] = '\0';

#ifdef HAVE_PROXY_EXTRA_DEBUG
  log_debug("[QUERY_EXTRACT_SUCCESS] Extracted query parameter '%s'='%s' (%zu bytes)",
            param_name, value, out_idx);
#endif

  return 0;
}

// NEW: HTTP Basic Auth username extractor - decode Authorization header
// Decodes Base64 and extracts username (before colon)
// Example: Authorization: Basic dXNlcjpwYXNz (user:pass encoded)
// Result: value = "user"
static int
extract_basic_auth_username(const char *headers, char *username, size_t username_size)
{
  if (!headers || !username || username_size == 0) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[BASICAUTH_EXTRACT_INVALID] Invalid parameters: headers=%p username=%p size=%zu",
              headers, username, username_size);
#endif
    return -1;
  }

  const char *auth_header = strstr(headers, "Authorization: Basic ");
  const char *encoded_start = NULL;
  
  if (auth_header) {
    // Full header format: "Authorization: Basic dXNlcjpwYXNz"
    encoded_start = auth_header + 21;  // Skip "Authorization: Basic "
  } else {
    // Header value only format: "Basic dXNlcjpwYXNz"
    const char *basic_prefix = strstr(headers, "Basic ");
    if (!basic_prefix) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("[BASICAUTH_EXTRACT_NOHDR] No 'Basic ' prefix found in auth header");
#endif
      return -1;
    }
    encoded_start = basic_prefix + 6;  // Skip "Basic "
  }
  
  // Find end of Base64 string (CR, LF, or space)
  const char *encoded_end = strpbrk(encoded_start, "\r\n ");
  size_t encoded_len = encoded_end ? (encoded_end - encoded_start) : strlen(encoded_start);
  
  if (encoded_len == 0 || encoded_len > 1024) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[BASICAUTH_EXTRACT_INVLEN] Invalid Base64 length: %zu", encoded_len);
#endif
    return -1;
  }

  // Simple Base64 decoder (sufficient for Basic Auth)
  static const char base64_chars[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  
  char decoded[512];
  size_t decoded_idx = 0;
  
  for (size_t i = 0; i < encoded_len && decoded_idx < sizeof(decoded) - 1; ) {
    unsigned char sextet[4] = {0};
    int valid_count = 0;
    
    // Decode 4 Base64 chars → 3 bytes
    for (int j = 0; j < 4 && i < encoded_len; j++) {
      if (encoded_start[i] == '=') {
        i++;
        break;  // Padding
      }
      
      const char *pos = strchr(base64_chars, encoded_start[i]);
      if (!pos) {
        i++;
        j--;  // Don't count this as a valid position
        continue;  // Skip invalid chars
      }
      
      sextet[j] = (unsigned char)(pos - base64_chars);
      valid_count++;
      i++;
    }
    
    if (valid_count >= 2) {
      decoded[decoded_idx++] = (sextet[0] << 2) | (sextet[1] >> 4);
    }
    if (valid_count >= 3) {
      decoded[decoded_idx++] = ((sextet[1] & 0xF) << 4) | (sextet[2] >> 2);
    }
    if (valid_count >= 4) {
      decoded[decoded_idx++] = ((sextet[2] & 0x3) << 6) | sextet[3];
    }
  }
  decoded[decoded_idx] = '\0';

  if (decoded_idx == 0) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[BASICAUTH_EXTRACT_DECFAIL] Base64 decoding failed");
#endif
    return -1;
  }

  // Extract username (before colon)
  // Decoded format: "username:password"
  const char *colon = strchr(decoded, ':');
  size_t user_len = colon ? (colon - decoded) : decoded_idx;
  
  if (user_len == 0) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[BASICAUTH_EXTRACT_NOUSER] No username found in decoded auth");
#endif
    return -1;
  }
  
  if (user_len >= username_size) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_warn("[BASICAUTH_EXTRACT_TOOLONG] Username too long (%zu bytes, max %zu), truncating",
             user_len, username_size - 1);
#endif
    user_len = username_size - 1;
  }

  strncpy(username, decoded, user_len);
  username[user_len] = '\0';

#ifdef HAVE_PROXY_EXTRA_DEBUG
  log_debug("[BASICAUTH_EXTRACT_SUCCESS] Extracted username='%s' (%zu bytes)",
            username, user_len);
#endif

  return 0;
}

static int
get_server_for_session(const char *session_key, int num_servers)
{
  if (num_servers <= 0) {
    log_error("STICKY-SESSION: Invalid server count: %d", num_servers);
    return 0;
  }
  
  // Use consistent hashing to always select the same server for a session
  uint32_t hash = session_key_hash(session_key);
  int server_id = hash % num_servers;
  
  if (server_id < 0 || server_id >= num_servers) {
    log_error("STICKY-SESSION: Invalid server_id calculation: %d (max: %d)", server_id, num_servers-1);
    return 0;
  }
  
  return server_id;
}

// Session timeout and cleanup functions
void
cleanup_expired_sessions(void)
{
  proxy_map_ent_t *node;
  proxy_fd_ent_t *fd_ent;
  time_t now = time(NULL);
  int cleaned_count = 0;

  PROXY_LOCK();
  
  node = proxy_struct->head;
  while (node) {
    fd_ent = node->val.fdlist;
    while (fd_ent) {
      if (fd_ent->is_sticky && 
          (now - fd_ent->last_activity) > PROXY_SESSION_TIMEOUT) {
        
        log_info("STICKY-SESSION: Expiring session - fd=%d, key='%s', server=%d, idle=%ld seconds", 
                 fd_ent->fd, fd_ent->session_key, fd_ent->sticky_server_id, 
                 now - fd_ent->last_activity);
        
#ifdef HAVE_DP_GPU_ROUTING
        // PRODUCTION FIX: Decrement CHWBL/WRR_HASH load for expired sessions to prevent ghost load accumulation
        if (fd_ent->epv && fd_ent->ep_num >= 0) {
          proxy_epval_t *epv = (proxy_epval_t *)fd_ent->epv;
          if ((epv->select == PROXY_SEL_CHWBL || epv->select == PROXY_SEL_WRR_HASH) && epv->chwbl_config) {
            chwbl_dec_load(epv->chwbl_config, fd_ent->ep_num);
            log_debug("CHWBL/WRR_HASH: Decremented load for expired session on EP%d", fd_ent->ep_num);
          }
        }
#endif /* HAVE_DP_GPU_ROUTING */
        
        // Reset sticky session
        fd_ent->is_sticky = 0;
        fd_ent->sticky_server_id = -1;
        fd_ent->session_key[0] = '\0';
        fd_ent->session_created = 0;
        fd_ent->last_activity = 0;
        cleaned_count++;
      }
      fd_ent = fd_ent->next;
    }
    node = node->next;
  }
  
  proxy_struct->last_session_cleanup = now;
  PROXY_UNLOCK();
  
  if (cleaned_count > 0) {
    log_info("STICKY-SESSION: Cleaned up %d expired sessions", cleaned_count);
  }
}

static void __attribute__((unused))
update_session_activity(proxy_fd_ent_t *pfe)
{
  if (pfe->is_sticky) {
    pfe->last_activity = time(NULL);
  }
}

// Sticky session selection logic
static int __attribute__((unused))
proxy_select_ep_sticky(proxy_fd_ent_t *pfe, void *inbuf, size_t insz, int *ep)
{
  // If already sticky to a server, always use it
  if (pfe->is_sticky && pfe->sticky_server_id < pfe->n_rfd) {
    *ep = pfe->sticky_server_id;
    return PROXY_SEL_EP_UC;
  }    
  
  // For new connections, determine session key and server
  char session_key[64] = {0};
  int server_id = -1;
  
  // Try different session key extraction methods
  if (pfe->affinity_type == PROXY_AFFINITY_CONTENT && inbuf && insz > 0) {
    if (extract_content_session_key((const char*)inbuf, insz, session_key, sizeof(session_key)) == 0) {
      server_id = get_server_for_session(session_key, pfe->n_rfd);
      log_info("STICKY-SESSION: CONTENT affinity SUCCESS - key='%s' -> server=%d", session_key, server_id);
    } 
  } else if (pfe->affinity_type == PROXY_AFFINITY_COOKIE && inbuf && insz > 0) {
    if (extract_cookie_session_key((const char*)inbuf, insz, session_key, sizeof(session_key)) == 0) {
      server_id = get_server_for_session(session_key, pfe->n_rfd);
      log_info("STICKY-SESSION: COOKIE affinity SUCCESS - key='%s' -> server=%d", session_key, server_id);
    } 
  }
  
  // Fallback to IP-based affinity
  if (server_id < 0) {
    generate_ip_session_key(pfe->fd, session_key, sizeof(session_key));
    server_id = get_server_for_session(session_key, pfe->n_rfd);
    pfe->affinity_type = PROXY_AFFINITY_IP;
    log_info("STICKY-SESSION: IP affinity APPLIED - key='%s' -> server=%d", session_key, server_id);
  }
  
  // Bind this connection to the selected server
  pfe->sticky_server_id = server_id;
  pfe->is_sticky = 1;
  pfe->session_created = time(NULL);
  pfe->last_activity = time(NULL);
  strncpy(pfe->session_key, session_key, sizeof(pfe->session_key) - 1);
  
  *ep = server_id;  
  
  log_info("STICKY-SESSION: NEW BINDING CREATED - fd=%d, key='%s', server=%d, affinity_type=%d", 
           pfe->fd, session_key, server_id, pfe->affinity_type);
  
  return PROXY_SEL_EP_UC;
}

int
proxy_select_ep(proxy_fd_ent_t *pfe, void *inbuf, size_t insz, int *ep)
{
  *ep = 0;

  log_trace("proxy_select_ep: fd=%d, seltype=%d, n_rfd=%d", pfe->fd, pfe->seltype, pfe->n_rfd);

  /* Bug-B fix (request-scoped egress) — see
   * .planning/phases/89-kv-exact-production-hardening/BUGB-FIX-DESIGN.md.
   *
   * In a P/D flow the client pfe links TWO NON-interchangeable backends: the prefill
   * backend at rfd[0] (receives the client request) and the decode backend at rfd[1]
   * (receives the decode request via a SEPARATE direct write() at pd_initiate_decode,
   * then streams the response back). The generic round-robin below is built for
   * EQUIVALENT multi-backend L4 fanout — round-robining a client request's chunks
   * across the [prefill, decode] pair sends bytes to the decode socket, which already
   * consumed its own request's Content-Length, so the surplus parses as a malformed
   * request → backend 400 "Invalid HTTP request received." (cross-request body
   * contamination on reused keep-alive connections; persists because the keep-alive
   * boundary reset never clears rfd[]/n_rfd).
   *
   * Fix: a client→backend request must go ENTIRELY to the prefill backend — never the
   * decode slot. When a decode backend is linked, force egress to the first non-decode
   * (== prefill) slot and skip the round-robin. SAFE for all callers: proxy_select_ep
   * is reached ONLY from proxy_multiplexor (the client request relay); the decode
   * request egress (direct write) and the backend→client response relay never pass
   * through here. Non-P/D connections (no decode backend) are unaffected — they fall
   * through to the unchanged selector below. */
  if (pfe->n_rfd > 1) {
    int has_decode = 0, prefill_slot = -1;
    for (int i = 0; i < pfe->n_rfd && i < MAX_PROXY_EP; i++) {
      if (pfe->rfd_ent[i] && pfe->rfd_ent[i]->is_pd_decode_backend) {
        has_decode = 1;
      } else if (prefill_slot < 0) {
        prefill_slot = i;   /* first non-decode slot == the prefill backend */
      }
    }
    if (has_decode && prefill_slot >= 0) {
      *ep = prefill_slot;
      log_trace("[BUGB-FIX] P/D egress fd=%d -> prefill slot=%d (skip decode round-robin)",
                pfe->fd, prefill_slot);
      return PROXY_SEL_EP_UC;
    }
  }

  switch (pfe->seltype) {
  // case PROXY_SEL_STICKY:
  //   return proxy_select_ep_sticky(pfe, inbuf, insz, ep);
  case PROXY_SEL_N2:
  default:
    if (pfe->n_rfd > 1) {
      *ep = pfe->lsel % pfe->n_rfd;
      pfe->lsel++;
      log_trace("Round-robin selection: fd=%d -> server=%d (lsel=%d)", pfe->fd, *ep, pfe->lsel-1);
    } else {
      log_trace("Single server selection: fd=%d -> server=%d", pfe->fd, *ep);
    }
    break;
  }

  return PROXY_SEL_EP_UC;
}

static int
proxy_multiplexor(proxy_fd_ent_t *pfe, void *inbuf, size_t insz)
{
  int epret;
  int ep = 0;

  epret = proxy_select_ep(pfe, inbuf, insz,  &ep);
  if (epret == PROXY_SEL_EP_DROP) {
      return -1;
  } else if (epret == PROXY_SEL_EP_BC) {
    for (int i = 0; i < pfe->n_rfd; i++) {
      proxy_try_epxmit(pfe, inbuf, insz, i);
    }
  } else {
    proxy_try_epxmit(pfe, inbuf, insz, ep);
  }
  return 0;
}

static int
proxy_sock_read(proxy_fd_ent_t *pfe, int fd, void *buf, size_t len)
{
  int ret;
  if (!pfe->ssl || pfe->ktls_enabled) {
    // Use raw socket I/O for plaintext or kTLS-offloaded connections
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[SOCK_READ] fd=%d: Using recv() (ssl=%p, ktls=%d)", fd, pfe->ssl, pfe->ktls_enabled);
#endif
    ret = recv(fd, buf, len, MSG_DONTWAIT);
    return ret;
  } else {
    // Use OpenSSL for userspace TLS
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[SOCK_READ] fd=%d: Using SSL_read() (ssl=%p, ktls=%d)", fd, pfe->ssl, pfe->ktls_enabled);
#endif
    ret = SSL_read(pfe->ssl, buf, len);
    if (ret > 0) {
      // Show first 100 bytes of decrypted data for debugging
      char preview[128];
      int preview_len = ret < 100 ? ret : 100;
      memcpy(preview, buf, preview_len);
      preview[preview_len] = '\0';
      // Replace non-printable chars with '.'
      for (int i = 0; i < preview_len; i++) {
        if (preview[i] < 32 || preview[i] > 126) preview[i] = '.';
      }
    }
    return ret;
  }
}

static int
proxy_sock_read_err(proxy_fd_ent_t *pfe, int rval)
{
#if defined(HAVE_PROXY_EXTRA_DEBUG) && defined(HAVE_HTTP_TRACE)
  log_debug("[SOCK_READ_ERR_ENTRY] fd=%d odir=%d rval=%d | ssl=%p ktls=%d root_span=%016lx",
            pfe->fd, pfe->odir, rval, pfe->ssl, pfe->ktls_enabled, pfe->root_span_id);
#elif defined(HAVE_PROXY_EXTRA_DEBUG)
  log_debug("[SOCK_READ_ERR_ENTRY] fd=%d odir=%d rval=%d | ssl=%p ktls=%d",
            pfe->fd, pfe->odir, rval, pfe->ssl, pfe->ktls_enabled);
#endif

  if (!pfe->ssl || pfe->ktls_enabled) {
    // Plaintext or kTLS path
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[PLAINTEXT_PATH] fd=%d odir=%d | Taking plaintext/kTLS path (ssl=%p ktls=%d)",
              pfe->fd, pfe->odir, pfe->ssl, pfe->ktls_enabled);
#endif
    if (rval <= 0) {
      if (rval == 0) {
        // Clean EOF - peer closed connection
        // CRITICAL FIX: Implement graceful shutdown to prevent data loss

#ifdef HAVE_HTTP_TRACE
        // Emit trace events based on connection direction
        if (is_tracing_enabled()) {
          uint64_t duration_us = 0;
          if (pfe->req_start_ts > 0) {
            uint64_t now = get_timestamp_ns();
            duration_us = (now - pfe->req_start_ts) / 1000;
          }
          
#ifdef HAVE_PROXY_EXTRA_DEBUG
          log_debug("[TRACE_EOF_CHECK] fd=%d odir=%d root_span=%016lx tracing_enabled=%d | "
                    "Will check if REQ_END or UP_END should be emitted",
                    pfe->fd, pfe->odir, pfe->root_span_id, is_tracing_enabled());
#endif
          
          if (pfe->odir == 1) {
            // Backend connection (odir=1) - emit UP_END
#ifdef HAVE_PROXY_EXTRA_DEBUG
            log_debug("[TRACE_EVENT_UP_END] fd=%d odir=%d | "
                      "trace_id=%016lx%016lx parent_span=%016lx root_span=%016lx | "
                      "timestamp=%lu duration_us=%lu flags=0x%02x | "
                      "bytes_rx=%lu packets_rx=%lu",
                      pfe->fd, pfe->odir,
                      pfe->trace_id_hi, pfe->trace_id_lo, pfe->parent_span_id, pfe->root_span_id,
                      get_timestamp_ns(), duration_us, pfe->trace_flags,
                      pfe->nrb, pfe->nrp);
#endif
            emit_trace_event(pfe, LXB_EVENT_UP_END, duration_us);
          } else if (pfe->odir == 0) {
            // Frontend connection (odir=0)
#ifdef HAVE_PROXY_EXTRA_DEBUG
            log_debug("[TRACE_FRONTEND_EOF] fd=%d odir=%d root_span=%016lx | "
                      "Frontend EOF detected, checking root_span_id condition",
                      pfe->fd, pfe->odir, pfe->root_span_id);
#endif
            if (pfe->root_span_id != 0) {
              // Only emit REQ_END if we have a valid root_span_id (means REQ_START was emitted)
#ifdef HAVE_PROXY_EXTRA_DEBUG
              log_debug("[TRACE_EVENT_REQ_END] fd=%d odir=%d | "
                        "trace_id=%016lx%016lx parent_span=%016lx root_span=%016lx | "
                        "timestamp=%lu duration_us=%lu flags=0x%02x",
                        pfe->fd, pfe->odir,
                        pfe->trace_id_hi, pfe->trace_id_lo, pfe->parent_span_id, pfe->root_span_id,
                        get_timestamp_ns(), duration_us, pfe->trace_flags);
#endif
              emit_trace_event(pfe, LXB_EVENT_REQ_END, duration_us);
              // Clear root_span_id to prevent duplicate emission
              pfe->root_span_id = 0;
            } else {
#ifdef HAVE_PROXY_EXTRA_DEBUG
              log_debug("[TRACE_SKIP_REQ_END] fd=%d odir=%d | "
                        "Skipping REQ_END because root_span_id=0 (no REQ_START was emitted)",
                        pfe->fd, pfe->odir);
#endif
            }
          }
        }
#endif

        // Check if peer connection still has data to send
        if (pfe->n_rfd > 0 && pfe->rfd_ent[0]) {
          proxy_fd_ent_t *peer_pfe = pfe->rfd_ent[0];

          // Check if peer has pending cached data
          if (peer_pfe->cache_count > 0) {
            // DEFER CLOSE: Peer still has data to send
            peer_pfe->peer_eof = 1;
            peer_pfe->eof_timestamp = time(NULL);

            // METRICS: Track graceful close with cache drain (TIER 3, Metric #12)
            atomic_fetch_add(&global_stats.peer_eof_graceful, 1);

            log_info("[EOF_DEFERRED] fd=%d closed, but peer fd=%d has cache_count=%u (%.2f MB) - "
                     "Deferring shutdown until peer cache drains",
                     pfe->fd, peer_pfe->fd,
                     peer_pfe->cache_count, peer_pfe->cache_total_size / (1024.0 * 1024.0));

            // Shutdown READ side only (we won't receive more data)
            // Keep WRITE side open for peer to drain cache
            shutdown(pfe->fd, SHUT_RD);

            // Return 1 to keep connection tracked (not -1 which removes from epoll)
            return 1;
          } else {
            // Peer cache is empty, safe to close immediately
            // Log BEFORE accessing peer_pfe fields (defensive programming)
            int peer_fd = peer_pfe->fd;
            log_info("[EOF_IMMEDIATE] fd=%d closed, peer fd=%d cache empty - Closing this side",
                     pfe->fd, peer_fd);
            shutdown(pfe->fd, SHUT_RDWR);
            return -1;
          }
        } else {
          // No peer connection, close immediately
          log_info("[EOF] fd=%d (odir=%d): Peer closed connection (clean EOF), cache_count=%u, cache_size=%.2f MB",
                   pfe->fd, pfe->odir,
                   pfe->cache_count, pfe->cache_total_size / (1024.0 * 1024.0));
          shutdown(pfe->fd, SHUT_RDWR);
          return -1;
        }
      }
      
      // kTLS-specific: EIO can occur in several scenarios:
      // 1. TLS session ends normally (client sent FIN)
      // 2. Client closed connection (normal shutdown)
      // 3. Trying to read when no data available (spurious read)
      //
      // IMPORTANT: For request-response protocols, EIO after sending request
      // is often NORMAL - the client waits for response and has no more data to send.
      // We should NOT treat this as fatal if we haven't received backend response yet.
      if (pfe->ktls_enabled && errno == EIO) {
        // Check if we're waiting for backend response
        if (pfe->rfd[0] > 0 && pfe->rcv_off == 0) {
          // We've forwarded request and reset buffer - waiting for backend response
          // EIO here is NORMAL - client has no more data to send
          return 1;  // Return "would block" to prevent connection close
        } else {
          // Actual connection close
          shutdown(pfe->fd, SHUT_RDWR);
          return -1;
        }
      }
      
      if (errno != EWOULDBLOCK && errno != EAGAIN) {
        log_info("recv() error on fd=%d: rval=%d, errno=%d (%s)",
                 pfe->fd, rval, errno, strerror(errno));
        shutdown(pfe->fd, SHUT_RDWR);
        return -1;
      }
      log_trace("recv() would block on fd=%d (rval=%d, errno=%d)",
                pfe->fd, rval, errno);
      return 1;
    }
    return 0;
  } else {
    // SSL path (non-kTLS)
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[SSL_PATH] fd=%d odir=%d rval=%d | Taking SSL error handling path",
              pfe->fd, pfe->odir, rval);
#endif
    
    if (rval > 0) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("[SSL_RVAL_POSITIVE] fd=%d odir=%d rval=%d | Returning 0 (success)",
                pfe->fd, pfe->odir, rval);
#endif
      return 0;
    }
    
    int ssl_error = SSL_get_error(pfe->ssl, rval);
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[SSL_GET_ERROR] fd=%d odir=%d rval=%d ssl_error=%d | "
              "SSL_ERROR_NONE=%d SSL_ERROR_ZERO_RETURN=%d SSL_ERROR_WANT_READ=%d SSL_ERROR_WANT_WRITE=%d SSL_ERROR_SYSCALL=%d SSL_ERROR_SSL=%d",
              pfe->fd, pfe->odir, rval, ssl_error,
              SSL_ERROR_NONE, SSL_ERROR_ZERO_RETURN, SSL_ERROR_WANT_READ,
              SSL_ERROR_WANT_WRITE, SSL_ERROR_SYSCALL, SSL_ERROR_SSL);
#endif
    
    switch (ssl_error) {
      case SSL_ERROR_NONE:
#ifdef HAVE_PROXY_EXTRA_DEBUG
        log_debug("[SSL_ERROR_NONE] fd=%d odir=%d | No error, returning 0",
                  pfe->fd, pfe->odir);
#endif
        return 0;
      case SSL_ERROR_SSL:
      case SSL_ERROR_SYSCALL:
#ifdef HAVE_PROXY_EXTRA_DEBUG
        log_debug("[SSL_ERROR_SYSCALL] fd=%d odir=%d ssl_error=%d | SSL or syscall error, shutting down",
                  pfe->fd, pfe->odir, ssl_error);
#endif
        log_trace("ssl-syscall-failed %s",
          ERR_error_string(ERR_get_error(), NULL));
        
#ifdef HAVE_HTTP_TRACE
        // Emit REQ_END trace event for SSL errors when rval==0 (EOF) on frontend
        if (rval == 0 && is_tracing_enabled() && pfe->odir == 0 && pfe->root_span_id != 0) {
          uint64_t duration_us = 0;
          if (pfe->req_start_ts > 0) {
            uint64_t now = get_timestamp_ns();
            duration_us = (now - pfe->req_start_ts) / 1000;
          }
          
#ifdef HAVE_PROXY_EXTRA_DEBUG
          log_debug("[TRACE_EVENT_REQ_END_SSL_ERROR] fd=%d odir=%d | "
                    "Emitting REQ_END for SSL error (ssl_error=%d) | "
                    "trace_id=%016llx%016llx root_span=%016llx duration=%lluus",
                    pfe->fd, pfe->odir, ssl_error,
                    pfe->trace_id_hi, pfe->trace_id_lo,
                    pfe->root_span_id, duration_us);
#endif
          
          emit_trace_event(pfe, 2, duration_us);
        }
#endif
        
        pfe->ssl_err = 1;
        shutdown(pfe->fd, SHUT_RDWR);
        return -1;
      case SSL_ERROR_WANT_READ:
#ifdef HAVE_PROXY_EXTRA_DEBUG
        log_debug("[SSL_ERROR_WANT_READ] fd=%d odir=%d | SSL wants more data, returning 1",
                  pfe->fd, pfe->odir);
#endif
        log_trace("ssl-want-rd %s",
          ERR_error_string(ERR_get_error(), NULL));
        return 1;
      case SSL_ERROR_WANT_WRITE:
#ifdef HAVE_PROXY_EXTRA_DEBUG
        log_debug("[SSL_ERROR_WANT_WRITE] fd=%d odir=%d | SSL wants to write, returning 1",
                  pfe->fd, pfe->odir);
#endif
        log_trace("ssl-want-wr %s",
          ERR_error_string(ERR_get_error(), NULL));
        notify_add_ent(proxy_struct->ns, pfe->fd,
              NOTI_TYPE_IN|NOTI_TYPE_HUP|NOTI_TYPE_OUT, pfe, pfe->gen);
        return 1;
      case SSL_ERROR_ZERO_RETURN:
      default:
#ifdef HAVE_PROXY_EXTRA_DEBUG
        log_debug("[SSL_ERROR_ZERO_RETURN_OR_DEFAULT] fd=%d odir=%d ssl_error=%d | "
                  "SSL connection closed or unknown error, should emit trace events",
                  pfe->fd, pfe->odir, ssl_error);
#endif
        // SSL connection closed gracefully (ZERO_RETURN) or error
        log_trace("ssl-err %s",
          ERR_error_string(ERR_get_error(), NULL));

#ifdef HAVE_HTTP_TRACE
        // Emit trace events for SSL connections
        if (is_tracing_enabled()) {
          uint64_t duration_us = 0;
          if (pfe->req_start_ts > 0) {
            uint64_t now = get_timestamp_ns();
            duration_us = (now - pfe->req_start_ts) / 1000;
          }
          
#ifdef HAVE_PROXY_EXTRA_DEBUG
          log_debug("[TRACE_SSL_EOF_CHECK] fd=%d odir=%d root_span=%016lx | "
                    "SSL connection closed, checking trace emission",
                    pfe->fd, pfe->odir, pfe->root_span_id);
#endif
          
          if (pfe->odir == 1) {
            // Backend connection (odir=1) - emit UP_END
#ifdef HAVE_PROXY_EXTRA_DEBUG
            log_debug("[TRACE_EVENT_UP_END_SSL] fd=%d odir=%d | "
                      "trace_id=%016lx%016lx root_span=%016lx | "
                      "timestamp=%lu duration_us=%lu",
                      pfe->fd, pfe->odir,
                      pfe->trace_id_hi, pfe->trace_id_lo, pfe->root_span_id,
                      get_timestamp_ns(), duration_us);
#endif
            emit_trace_event(pfe, LXB_EVENT_UP_END, duration_us);
          } else if (pfe->odir == 0 && pfe->root_span_id != 0) {
            // Frontend connection (odir=0) - emit REQ_END
            // Only emit once by checking and clearing root_span_id
#ifdef HAVE_PROXY_EXTRA_DEBUG
            log_debug("[TRACE_EVENT_REQ_END_SSL] fd=%d odir=%d | "
                      "trace_id=%016lx%016lx root_span=%016lx | "
                      "timestamp=%lu duration_us=%lu",
                      pfe->fd, pfe->odir,
                      pfe->trace_id_hi, pfe->trace_id_lo, pfe->root_span_id,
                      get_timestamp_ns(), duration_us);
#endif
            emit_trace_event(pfe, LXB_EVENT_REQ_END, duration_us);
            // Clear root_span_id to prevent duplicate emission
            pfe->root_span_id = 0;
          }
        }
#endif

        // CRITICAL FIX: Implement graceful shutdown for SSL path too
        if (pfe->n_rfd > 0 && pfe->rfd_ent[0]) {
          proxy_fd_ent_t *peer_pfe = pfe->rfd_ent[0];

          // Check if peer has pending cached data
          if (peer_pfe->cache_count > 0) {
            // DEFER CLOSE: Peer still has data to send
            peer_pfe->peer_eof = 1;
            peer_pfe->eof_timestamp = time(NULL);

            // METRICS: Track graceful close with cache drain (TIER 3, Metric #12)
            atomic_fetch_add(&global_stats.peer_eof_graceful, 1);

            log_info("[SSL_EOF_DEFERRED] fd=%d SSL closed, but peer fd=%d has cache_count=%u (%.2f MB) - "
                     "Deferring shutdown until peer cache drains",
                     pfe->fd, peer_pfe->fd,
                     peer_pfe->cache_count, peer_pfe->cache_total_size / (1024.0 * 1024.0));

            // Shutdown SSL and READ side only
            SSL_shutdown(pfe->ssl);
            shutdown(pfe->fd, SHUT_RD);

            // Return 1 to keep connection tracked
            return 1;
          }
        }

        // No peer or peer cache empty, close immediately
        SSL_shutdown(pfe->ssl);
        shutdown(pfe->fd, SHUT_RDWR);
        return -1;
    }
  }

  /* Not reached */
  return -1;
}

/* HTTP/HTTPS Tracing catalog + emit functions moved to sockproxy_trace.c */


static int
proxy_ssl_accept(void *ssl, int fd)
{
  struct pollfd pfds = { 0 };
  int n_try = 0;
  int sel_rc;
  int ssl_rc;

  pfds.fd = fd;

  for (n_try = 0; n_try < 10; n_try++) {
    if ((ssl_rc = SSL_accept(ssl)) > 0) {
      // TLS handshake completed successfully

      // Log negotiated TLS version and cipher
      int tls_version = SSL_version(ssl);
      const char *version_str __attribute__((unused)) = SSL_get_version(ssl);
      const char *cipher_str __attribute__((unused)) = SSL_get_cipher_name(ssl);

      // Try kTLS for TLS 1.2, skip for TLS 1.3
      if (tls_version == TLS1_2_VERSION) {
        // Try to enable kernel TLS offload
        int ktls_ret __attribute__((unused)) = ktls_try_offload(ssl, fd, 0 /* server side */);
      }

#ifdef HAVE_HTTP_TRACE
      // Emit TLS handshake event (frontend)
      // Note: We don't have pfe here, will emit in first data callback
#endif

      return 0;
    }

    if (ssl_rc == 0) {
      return -1;
    }

    sel_rc = 0;
    switch (SSL_get_error(ssl, ssl_rc)) {
      case SSL_ERROR_WANT_READ:
        log_trace("ssl-accept want-read %s",
          ERR_error_string(ERR_get_error(), NULL));
        pfds.events = POLLIN;
        sel_rc = poll(&pfds, 1, 100);
        break;
      case SSL_ERROR_WANT_WRITE:
        log_trace("ssl-accept want-write %s",
          ERR_error_string(ERR_get_error(), NULL));
        pfds.events = POLLOUT;
        sel_rc = poll(&pfds, 1, 100);
        break;
      default:
        log_error("ssl-accept failed %s",
          ERR_error_string(ERR_get_error(), NULL));
        SSL_shutdown(ssl);
        return -1;
    }
    if (sel_rc < 0) {
      return -1;
    }
  }

  return -1;
}

#ifdef HAVE_MTLS
/**
 * mtls_validate_client_cn - Validate client certificate CN against configured pattern
 * @ssl: SSL connection object
 * @pfe: Proxy FD entry with service configuration
 * @tepval: Service endpoint configuration (unused - kept for API compatibility)
 *
 * Validates that the client certificate CN matches the configured pattern.
 * Called after proxy path is set up and we know which service this connection is for.
 * Returns 0 on success (CN valid), -1 on validation failure.
 *
 * Implementation: Uses mtls_match_cn_pattern() from sockproxy_mtls.c which provides
 * fnmatch-based wildcard support (*.example.com). CN pattern is retrieved from SSL_CTX
 * ex_data where it was stored during proxy_add_entry().
 */
static int
mtls_validate_client_cn(SSL *ssl, proxy_fd_ent_t *pfe, proxy_epval_t *tepval)
{
  X509 *peer_cert = NULL;
  SSL_CTX *ssl_ctx = NULL;
  proxy_arg_t *arg = NULL;
  
  (void)tepval;  // Unused parameter - kept for API compatibility
  
  if (!ssl || !pfe) {
    return 0;  // No validation needed
  }

  // Get peer certificate
  peer_cert = SSL_get_peer_certificate(ssl);
  if (!peer_cert) {
    // No certificate - mode enforcement already happened in SSL_accept via mtls_configure_frontend
    log_debug("[mTLS] No client certificate presented for fd=%d", pfe->fd);
    return 0;
  }

  // Get SSL_CTX to retrieve mTLS configuration
  ssl_ctx = SSL_get_SSL_CTX(ssl);
  if (!ssl_ctx) {
    log_error("[mTLS] REJECT fd=%d: Cannot get SSL_CTX", pfe->fd);
    X509_free(peer_cert);
    return -1;
  }

  // Retrieve proxy_arg_t from SSL_CTX ex_data (stored during proxy_add_entry)
  // Note: g_ssl_ctx_proxy_arg_index is defined/initialized in sockproxy_mtls.c
  log_debug("[mTLS] Retrieving config for fd=%d: ssl=%p ctx=%p index=%d", 
            pfe->fd, (void*)ssl, (void*)ssl_ctx, g_ssl_ctx_proxy_arg_index);
  
  arg = SSL_CTX_get_ex_data(ssl_ctx, g_ssl_ctx_proxy_arg_index);
  
  log_debug("[mTLS] Retrieved proxy_arg=%p for fd=%d", (void*)arg, pfe->fd);
  
  if (!arg) {
    // No mTLS config stored - accept connection
    log_debug("[mTLS] No mTLS config in SSL_CTX for fd=%d, accepting", pfe->fd);
    X509_free(peer_cert);
    return 0;
  }

  log_debug("[mTLS] Retrieved config for fd=%d: require_client_cn=%d pattern='%s'",
            pfe->fd, arg->require_client_cn, arg->client_cn_pattern);

  // Check if CN pattern matching is required
  if (!arg->require_client_cn || arg->client_cn_pattern[0] == '\0') {
    // CN pattern matching not required
    log_debug("[mTLS] CN pattern matching not required for fd=%d", pfe->fd);
    X509_free(peer_cert);
    return 0;
  }

  // Validate CN against pattern using sockproxy_mtls.c function
  if (!mtls_match_cn_pattern(peer_cert, arg->client_cn_pattern)) {
    char cn_buf[256] = {0};
    X509_NAME *subject = X509_get_subject_name(peer_cert);
    if (subject) {
      X509_NAME_get_text_by_NID(subject, NID_commonName, cn_buf, sizeof(cn_buf));
    }
    log_error("[mTLS] REJECT fd=%d: CN='%s' does not match pattern='%s'",
              pfe->fd, cn_buf, arg->client_cn_pattern);
    X509_free(peer_cert);
    atomic_fetch_add(&global_stats.mtls_frontend_verify_failures, 1);
    return -1;
  }

  // CN matches pattern - accept connection
  log_info("[mTLS] CN pattern validated successfully for fd=%d", pfe->fd);
  X509_free(peer_cert);
  atomic_fetch_add(&global_stats.mtls_frontend_verify_success, 1);
  return 0;
}
#endif /* HAVE_MTLS */

static int
setup_proxy_path(smap_key_t *key, smap_key_t *rkey, proxy_fd_ent_t *pfe, const char *flt_url)
{
  proxy_ep_sel_t ep_sel = { 0 };
  // int j, n_eps = 0, seltype = 0;   // TODO: Change Me. Current default select type is 0 (PROXY_SEL_RR)
  int j, n_eps = 0, seltype = PROXY_SEL_STICKY;   
  int epprotocol, protocol;
  uint32_t rid = 0;
  proxy_fd_ent_t *npfe1 = pfe;
  proxy_fd_ent_t *npfe2 = NULL;
  proxy_epval_t *tepval = NULL;
  proxy_map_ent_t *ent;
  void *ssl = NULL;
  int retry = 0;

  ent = pfe->head;
  assert(ent);
  
  log_debug("[SETUP_PROXY_PATH] fd=%d: Called with prefix_hash=0x%lx, conv_id=%s, seltype=%d",
            pfe->fd, pfe->prefix_key.hash, 
            pfe->has_conv_id ? pfe->conversation_id : "(none)",
            pfe->seltype);

  if (proxy_skmap_key_from_fd(pfe->fd, key, &protocol)) {
    log_error("skmap key from fd failed");
    return -1;
  }

  memset(&ep_sel, 0, sizeof(ep_sel));
  
  // NEW: Pass custom session header value (if extracted).
  // Fallback priority: X-Conversation-Id/custom header → JSON "user" field.
  // This enables per-conversation stickiness for normal (non-P/D) AI GW mode
  // even when the client uses the OpenAI "user" field instead of a header.
  const char *custom_header = NULL;
  if (pfe->has_custom_session_header && pfe->custom_session_header_value[0] != '\0') {
    custom_header = pfe->custom_session_header_value;
  } else if (pfe->has_user_id && pfe->user_id[0] != '\0') {
    /* JSON "user" field: use as session key when no explicit session header */
    custom_header = pfe->user_id;
  }

  log_info("[NS_SETUP_PATH] fd=%d session_hdr='%s' has_custom=%d custom_val='%s' has_user=%d user='%s'",
           pfe->fd, pfe->session_header_name[0] ? pfe->session_header_name : "(none)",
           pfe->has_custom_session_header,
           pfe->has_custom_session_header ? pfe->custom_session_header_value : "",
           pfe->has_user_id, pfe->has_user_id ? pfe->user_id : "");
  
  /* PROXY protocol v2 (L7 fullproxy, mandatory when enabled on the rule): build the
   * 28-byte v4 header once from the client socket's addresses. key->dip/dport = the
   * real client (getpeername), key->sip/sport = the VIP the client dialed
   * (getsockname). It is sent as the first bytes of each backend connection by
   * proxy_setup_ep_connect(), before any client payload and before backend TLS. */
  uint8_t pp2buf[28];
  int pp2len = 0;
  if (ent->val.ppv2 && protocol == IPPROTO_TCP) {
    pp2len = proxy_build_ppv2_v4(pp2buf, sizeof(pp2buf),
                                 key->dip, (uint16_t)(key->dport >> 16),   /* src = client */
                                 key->sip, (uint16_t)(key->sport >> 16));  /* dst = VIP */
  }

  int psep_rc = proxy_setup_ep__(key->sip, key->sport >> 16, (uint8_t)(protocol),
                       flt_url,
                       pfe->http_path_ok ? pfe->request_path : "/",  // P6: Pass request path
                       pfe->has_conv_id ? pfe->conversation_id : NULL,  // P0.3: Pass conversation ID
                       pfe->prefix_key.hash,  // P1.3: Pass prefix hash for CHWBL
                       custom_header,  // NEW: Pass custom session header value
                       &ep_sel, &tepval, &seltype, &rid, ent->val.ssl_epctx, &ssl, key->dip, pfe,
                       (pp2len ? pp2buf : NULL), pp2len);
  /* bounded backpressured admission. The request was enqueued onto a
   * per-EP parked FIFO inside proxy_setup_ep__/pd_select_prefill. SUSPEND the client
   * fd (EPOLLIN-pause, HUP-only — the exact form at the backpressure pause site) and
   * hold it open. Do NOT proxy_destroy_eps, do NOT shutdown. The caller translates
   * PD_SETUP_PARKED into "keep fd, do NOT forward to backend, do NOT close". The
   * dequeue+resume (re-arm EPOLLIN + re-drive) is not wired yet. */
  if (psep_rc == PD_SETUP_PARKED) {
    if (!pfe->read_paused) {
      pfe->read_paused = 1;
      notify_add_ent(proxy_struct->ns, pfe->fd, NOTI_TYPE_HUP, pfe, pfe->gen);
    }
    pfe->pd_phase = PD_PHASE_PARKED;
    log_info("[PD_ADMISSION] fd=%d SUSPENDED (parked ep=%d) — EPOLLIN-paused, held open",
             pfe->fd, pfe->park_ep_idx);
    return PD_SETUP_PARKED;
  }
  if (psep_rc) {
    proxy_log_always("no endpoint", key);
    
#ifdef HAVE_HTTP_TRACE
    // CRITICAL: Emit REQ_END with error status before closing connection
    // This ensures traces show up in Jaeger for backend failure scenarios
    if (pfe->root_span_id != 0 && is_tracing_enabled()) {
      uint64_t duration_us = 0;
      if (pfe->req_start_ts > 0) {
        uint64_t now = get_timestamp_ns();
        duration_us = (now - pfe->req_start_ts) / 1000;
      }
      
      // Set HTTP 502 Bad Gateway status for backend connection failure
      pfe->http_status_code = 502;
      
      log_info("[TRACE_ERROR] fd=%d: Emitting REQ_END with status 502 (backend unavailable) duration=%luμs trace=%016lx%016lx",
               pfe->fd, duration_us, pfe->trace_id_hi, pfe->trace_id_lo);
      
      emit_trace_event(pfe, LXB_EVENT_REQ_END, duration_us);
      
      // Clear root_span_id to prevent duplicate REQ_END emission during cleanup
      pfe->root_span_id = 0;
    }
#endif
    
    /* Selection/connect failed. Every rule-matched failure path now emits an
     * HTTP error body first (P/D 429/503, generalized connect-retry 502,
     * all-down 503) and marks lb_err_body_sent — so this counter now ticks
     * ONLY for a genuinely silent raw reset (no-rule paths, or a new failure
     * path that forgot its error body). Nonzero == contract gap. */
    if (!pfe->lb_err_body_sent) {
      atomic_fetch_add(&global_stats.lb_select_failure_shutdown, 1);
    }
    pfe->lb_err_body_sent = 0;
    proxy_destroy_eps(pfe->fd, &ep_sel);
    shutdown(pfe->fd, SHUT_RDWR);
    return -1;
  }

  n_eps = ep_sel.n_eps;
  
  // Session Learning: If proxy_setup_ep__ marked connection for learning, set up npfe1
  if (ep_sel.n_eps > 0 && ep_sel.ep_cfds[0].needs_learning) {
    npfe1->needs_session_learning = 1;
    strncpy(npfe1->session_header_name, ep_sel.session_header_name, 
            sizeof(npfe1->session_header_name) - 1);
    npfe1->session_header_name[sizeof(npfe1->session_header_name) - 1] = '\0';
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[SESSION_LEARN_SETUP_CLIENT] Client fd=%d marked for learning '%s'",
              npfe1->fd, npfe1->session_header_name);
#endif
  }

  for (j = 0; j < n_eps; j++) {
    int ep_cfd = ep_sel.ep_cfds[j].ep_cfd;
    int ep_num = ep_sel.ep_cfds[j].ep_num;
    if (ep_cfd < 0) {
      assert(0);
    }

    if (proxy_skmap_key_from_fd(ep_cfd, rkey, &epprotocol)) {
      log_error("skmap key from ep_cfd failed");
      proxy_destroy_eps(pfe->fd, &ep_sel);
      if (ssl) {
        SSL_shutdown(ssl);
      }
      
#ifdef HAVE_DP_GPU_ROUTING
      // CRITICAL FIX: Decrement CHWBL/WRR_HASH load on skmap key extraction failure
      // Connection was established but failed to get socket metadata
      if (tepval && ep_num >= 0) {
        if ((tepval->select == PROXY_SEL_CHWBL || tepval->select == PROXY_SEL_WRR_HASH) && tepval->chwbl_config) {
          chwbl_dec_load(tepval->chwbl_config, ep_num);
          log_debug("CHWBL/WRR_HASH: Decremented load for EP%d after skmap key extraction failure", ep_num);
        }
      }
#endif /* HAVE_DP_GPU_ROUTING */
      
      shutdown(pfe->fd, SHUT_RDWR);
      return -1;
    }

    proxy_log("connected", rkey);

    // Sockmap offload configuration:
    // - HTTP→HTTP (plaintext): Sockmap enabled (zero-copy kernel forwarding)
    // - HTTPS→HTTP (TLS termination): Sockmap disabled (kTLS only)
    // - HTTPS→HTTPS (TLS transit): Sockmap disabled (kTLS only)
    // - HTTP→HTTPS (TLS origination): Sockmap disabled
    //
    // Rationale: Only HTTP→HTTP is supported for simplicity and reliability.
    // kTLS provides sufficient performance for HTTPS scenarios without sockmap complexity.
    
    int sockmap_eligible = 0;
    int ktls_client_enabled __attribute__((unused)) = 0;
    int ktls_backend_enabled __attribute__((unused)) = 0;

    if (protocol == IPPROTO_TCP && epprotocol == IPPROTO_TCP) {
      // Case 1: HTTP→HTTP (plaintext only) - SOCKMAP ENABLED
      if (!pfe->ssl && !ssl) {
        sockmap_eligible = 1;
      }
      // Case 2: HTTPS→HTTP (TLS termination) - SOCKMAP DISABLED, kTLS ONLY
      else if (pfe->ssl && !ssl && g_ktls_cfg.enabled) {
        // Try to enable kTLS on client side for hardware-accelerated decryption
        if (ktls_try_offload(pfe->ssl, pfe->fd, 0 /* server side */) == 0) {
          ktls_client_enabled = 1;
          pfe->ktls_enabled = 1;
        } else if (ktls_is_active(pfe->fd)) {
          ktls_client_enabled = 1;
          pfe->ktls_enabled = 1;
        } 
      }
      // Case 3: HTTPS→HTTPS (TLS transit) - SOCKMAP DISABLED, kTLS ONLY
      else if (pfe->ssl && ssl && g_ktls_cfg.enabled) {
        // Try to enable kTLS on client side
        if (ktls_try_offload(pfe->ssl, pfe->fd, 0 /* server side */) == 0) {
          ktls_client_enabled = 1;
          pfe->ktls_enabled = 1;
        } else if (ktls_is_active(pfe->fd)) {
          ktls_client_enabled = 1;
          pfe->ktls_enabled = 1;
        }

        // Try to enable kTLS on backend side
        if (ktls_try_offload(ssl, ep_cfd, 1 /* client side */) == 0) {
          ktls_backend_enabled = 1;
        } else if (ktls_is_active(ep_cfd)) {
          ktls_backend_enabled = 1;
        }
      }

      // Register to sockmap ONLY for HTTP→HTTP plaintext
      if (sockmap_eligible && proxy_struct->sockmap_cb) {
        int ret1 = proxy_struct->sockmap_cb(rkey, pfe->fd, 1);
        int ret2 = proxy_struct->sockmap_cb(key, ep_cfd, 1);
        if (ret1 != 0 || ret2 != 0) {
          log_error("Sockmap: Registration failed! client_ret=%d, backend_ret=%d", ret1, ret2);
        }
      }
    }

    npfe2 = pfe_alloc();   /* D2 root fix: pooled pfe shell */
    assert(npfe2);
    npfe2->stype = PROXY_SOCK_ACTIVE;
    npfe2->fd = ep_cfd;
    npfe2->rfd[0] = npfe1->fd;
    npfe2->rfd_ent[0] = npfe1;
    npfe2->seltype = seltype;
    npfe2->ep_num = -1;  // P1.3: Backend FD should NOT decrement load (only client FD decrements)
    npfe2->pd_decode_ep_idx = -1;
    npfe2->odir = 1;
    npfe2->_id = rid;
    npfe2->epv = NULL;  // P1.3: Backend FD should NOT have epv reference
    npfe2->n_rfd++;
    
#ifdef HAVE_HTTP_TRACE
    // CRITICAL: Copy trace context AND client connection info from frontend to backend
    // This ensures UP_END and backend TLS_HS events have the correct trace_id and client_ip
    npfe2->trace_id_hi = npfe1->trace_id_hi;
    npfe2->trace_id_lo = npfe1->trace_id_lo;
    npfe2->parent_span_id = npfe1->parent_span_id;
    npfe2->root_span_id = npfe1->root_span_id;
    npfe2->trace_flags = npfe1->trace_flags;
    npfe2->has_traceparent = npfe1->has_traceparent;
    npfe2->req_start_ts = npfe1->req_start_ts;
    npfe2->client_ip = npfe1->client_ip;      // Copy original client IP
    npfe2->client_port = npfe1->client_port;  // Copy original client port
#ifdef HAVE_PROXY_EXTRA_DEBUG
    char client_ip_str[INET_ADDRSTRLEN];
    struct in_addr addr = { .s_addr = npfe1->client_ip };
    inet_ntop(AF_INET, &addr, client_ip_str, sizeof(client_ip_str));
    log_debug("[TRACE_CONTEXT_COPY] Backend fd=%d inherited trace_id=%016lx%016lx client=%s:%u from frontend fd=%d",
              npfe2->fd, npfe2->trace_id_hi, npfe2->trace_id_lo, client_ip_str, npfe1->client_port, npfe1->fd);
#endif
    
    // Emit UP_START event (upstream connection established)
    // NOTE: Must be emitted AFTER trace context is copied so root_span_id is set correctly
    if (is_tracing_enabled()) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("[TRACE_EVENT_UP_START] fd=%d odir=%d | "
                "trace_id=%016lx%016lx parent_span=%016lx root_span=%016lx | "
                "timestamp=%lu flags=0x%02x",
                npfe2->fd, npfe2->odir,
                npfe2->trace_id_hi, npfe2->trace_id_lo, npfe2->parent_span_id, npfe2->root_span_id,
                get_timestamp_ns(), npfe2->trace_flags);
#endif
      emit_trace_event(npfe2, LXB_EVENT_UP_START, 0);
    }
#endif
    
    // Session Learning: Copy learning parameters from client to backend connection
    if (npfe1->needs_session_learning) {
      npfe2->needs_session_learning = 1;
      npfe2->ep_num = ep_num;  // Store endpoint number for learning (from loop variable)
      strncpy(npfe2->session_header_name, npfe1->session_header_name, 
              sizeof(npfe2->session_header_name) - 1);
      npfe2->session_header_name[sizeof(npfe2->session_header_name) - 1] = '\0';
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("[SESSION_LEARN_SETUP] Backend fd=%d will learn '%s' → ep[%d]",
                ep_cfd, npfe2->session_header_name, npfe2->ep_num);
#endif
    }
    npfe2->head = ent;
    npfe2->ssl = ssl;

    // Check if kTLS was enabled on backend connection
    if (ssl && ktls_is_active(ep_cfd)) {
      npfe2->ktls_enabled = 1;
    } else {
      npfe2->ktls_enabled = 0;
    }
    
    // Initialize cache tracking for backend connection
    npfe2->cache_count = 0;
    npfe2->cache_total_size = 0;
    npfe2->cache_backpressure = 0;
    npfe2->read_paused = 0;
    npfe2->qos_parked = 0;    /* pfe shells are pool-recycled, never re-zeroed */
    npfe2->qos_was_parked = 0;

    PROXY_LOCK();
    npfe2->next = ent->val.fdlist;
    ent->val.fdlist = npfe2;
    ent->val.nfds++;
    PROXY_UNLOCK();

    npfe1->_id = rid;
    npfe1->ep_num = ep_num;  // P1.3: Store endpoint number for load decrement
    npfe1->epv = tepval;     // P1.3: Store epv pointer for CHWBL config access
    npfe1->rfd[npfe1->n_rfd] = ep_cfd;
    npfe1->rfd_ent[npfe1->n_rfd] = npfe2;
    npfe1->n_rfd++;

    for (retry = 0; retry < PROXY_MAPFD_RETRIES; retry++) {
      /* Option A: pin the backend fd to the CLIENT fd's (npfe1) notify
       * worker so both legs of this connection serialize on one thread (prevents
       * the cross-thread pfe use-after-free wedge). Not P/D-specific — covers
       * every proxied connection's client+backend pair. */
      if (notify_add_ent_pinned(proxy_struct->ns, ep_cfd,
          NOTI_TYPE_IN|NOTI_TYPE_HUP, npfe2, npfe2->gen, npfe1->fd) == 0)  {
        break;
      }
      ep_cfd = get_mapped_proxy_fd(ep_cfd, 0);
      npfe2->fd = ep_cfd;
      if (npfe2->ssl) {
        SSL_set_fd(npfe2->ssl, ep_cfd);
      }
    }
    npfe2->used++;

    if (retry >= PROXY_MAPFD_RETRIES) {
      proxy_destroy_eps(pfe->fd, &ep_sel);
      proxy_release_fd_ctx(npfe2, 0);
      if (npfe2->ssl) {
        SSL_shutdown(npfe2->ssl);
        SSL_free(npfe2->ssl);
        npfe2->ssl = NULL;
      }
      pfe_recycle(npfe2);   /* D2 root fix: pool the shell (frees rcvbuf, bumps gen) */
      
#ifdef HAVE_DP_GPU_ROUTING
      // CRITICAL FIX: Decrement CHWBL/WRR_HASH load on notify_add_ent failure
      // Connection was established but failed to register with notification system
      if (npfe1->epv && npfe1->ep_num >= 0) {
        proxy_epval_t *epv = (proxy_epval_t *)npfe1->epv;
        if ((epv->select == PROXY_SEL_CHWBL || epv->select == PROXY_SEL_WRR_HASH) && epv->chwbl_config) {
          chwbl_dec_load(epv->chwbl_config, npfe1->ep_num);
          log_debug("CHWBL/WRR_HASH: Decremented load for EP%d after notify registration failure", npfe1->ep_num);
        }
      }
#endif /* HAVE_DP_GPU_ROUTING */
      
      shutdown(pfe->fd, SHUT_RDWR);
      log_error("failed to add epcfd %d", ep_cfd);
      return -1;
    }
  }

#ifdef HAVE_MTLS
  // Validate client certificate CN now that we know which service this is for
  if (pfe->ssl && tepval) {
    if (mtls_validate_client_cn((SSL *)pfe->ssl, pfe, tepval) != 0) {
      log_info("[mTLS] Client certificate validation failed for fd=%d", pfe->fd);
      proxy_destroy_eps(pfe->fd, &ep_sel);
      shutdown(pfe->fd, SHUT_RDWR);
      return -1;
    }
  }
#endif

  return 0;
}

int
handle_on_message_begin(llhttp_t* parser)
{
  llhttp_settings_t *settings = parser->settings;
  proxy_fd_ent_t *pfe;

  pfe = settings->uarg;
  assert(pfe);

  /* A new request head on the client leg: clear the per-request header
   * captures so a keep-alive request cannot inherit the previous request's
   * credentials or model hint — handle_header_val only overwrites these when
   * the header is present, so without this reset a keyless request N+1 on a
   * reused connection would be validated with request N's key. */
  if (pfe->odir == 0) {
    pfe->x_api_key_raw[0] = '\0';
    pfe->x_model_header[0] = '\0';
    /* Token-accounting state is per-response: without this reset, request
     * N+1 on a reused connection would inherit request N's consumed flag
     * (never charging again) or its stale counts. */
    pfe->usage_tail_len = 0;
    pfe->usage_consumed = 0;
    pfe->usage_prompt_toks = 0;
    pfe->usage_complet_toks = 0;
    pfe->usage_est_prompt = 0;
    pfe->usage_sse_events = 0;
    pfe->usage_reserved_toks = 0;
    pfe->usage_res_epoch = 0;
  }
  return 0;
}

int
handle_on_message_complete(llhttp_t* parser)
{
  llhttp_settings_t *settings = parser->settings;
  proxy_fd_ent_t *pfe;

  pfe = settings->uarg;
  assert(pfe);

  pfe->http_pok = 1;
  pfe->http_body_complete = 1;
  // L7 Metrics: capture request start timestamp for TTFB. Kept independent of
  // HAVE_HTTP_TRACE — the metric_* fields and record_latency_sample() are always
  // compiled (see sockproxy.h "L7 Metrics (independent of Jaeger tracing)"), so
  // the TTFB histogram must record in default builds like the status counters do.
  if (pfe->odir == 0) {
    pfe->metric_req_start_ns = get_timestamp_ns();
    pfe->metric_response_status = 0;
    pfe->metric_ai_recorded = 0;   // re-arm per request (keep-alive connection reuse)
  }

  // AI Gateway: Enforce X-Api-Key validation and per-key / per-tenant RPS limits.
  // Applied only to inbound client requests (odir==0) on AI Gateway connections
  // (i.e., when ai_gw_mode==1, set by SSEMode or PDDisaggMode on the service rule).
  if (pfe->odir == 0 && pfe->head) {
    proxy_map_ent_t *hent = (proxy_map_ent_t *)pfe->head;
    if (hent->val.ephash && hent->val.ephash->ai_gw_mode) {
      ai_gw_decision_t ai_dec = {0};
      char body_model[MAX_MODEL_LEN] = {0};
      const char *gate_body = NULL;
      size_t gate_body_len = 0;

      /* allowed_models must bind to the model the backend will actually
       * serve, which is the one in the JSON body — an X-Model header that
       * differs from the body is at best a stale hint and at worst a spoof.
       * The message is complete here, so the body is present in rcvbuf;
       * parse it and fall back to the header only when the body carries no
       * model field. The located body also feeds the pre-admission token
       * reservation below. */
      if (pfe->http_content_length > 0 && pfe->rcv_off > 4) {
        for (size_t i = 0; i + 3 < pfe->rcv_off; i++) {
          if (pfe->rcvbuf[i] == '\r' && pfe->rcvbuf[i+1] == '\n' &&
              pfe->rcvbuf[i+2] == '\r' && pfe->rcvbuf[i+3] == '\n') {
            gate_body = (const char *)(pfe->rcvbuf + i + 4);
            gate_body_len = pfe->rcv_off - (i + 4);
            break;
          }
        }
        if (gate_body && gate_body_len > 0) {
          extract_model_field(gate_body, gate_body_len, body_model, sizeof(body_model));
        }
      }
      char *model = body_model[0] ? body_model
                  : (pfe->prefix_key.model[0] ? pfe->prefix_key.model
                  : (pfe->x_model_header[0] ? pfe->x_model_header : ""));

      /* Step 1: validate X-Api-Key → 401 (missing/invalid) or 403 (model denied) */
      int ai_rc = llb_ai_validate_key(pfe->x_api_key_raw, model, &ai_dec);
      if (ai_rc != 0) {
        if (ai_dec.decision == 2) {
          static const char resp_403[] =
            "HTTP/1.1 403 Forbidden\r\n"
            "Content-Type: application/json\r\n"
            "Connection: close\r\n"
            "\r\n"
            "{\"error\":\"model_not_allowed\","
            "\"message\":\"Model not permitted for this API key\"}\r\n";
          send(pfe->fd, resp_403, sizeof(resp_403) - 1, 0);
        } else {
          static const char resp_401[] =
            "HTTP/1.1 401 Unauthorized\r\n"
            "Content-Type: application/json\r\n"
            "Connection: close\r\n"
            "\r\n"
            "{\"error\":\"invalid_api_key\","
            "\"message\":\"Missing or invalid X-Api-Key header\"}\r\n";
          send(pfe->fd, resp_401, sizeof(resp_401) - 1, 0);
        }
        shutdown(pfe->fd, SHUT_RDWR);
        log_info("[AIGateway] fd=%d rejected: decision=%d key=%.8s...",
                 pfe->fd, ai_dec.decision, pfe->x_api_key_raw);
        return;
      }

      /* Persist tenant_id for SSE token accounting and metrics */
      strncpy(pfe->tenant_id, ai_dec.tenant_id, sizeof(pfe->tenant_id) - 1);
      pfe->tenant_id[sizeof(pfe->tenant_id) - 1] = '\0';

      /* Step 2: per-key then per-tenant RPS check → 429. The body-bound
       * model rides along so the token-quota stage can consult the
       * tenant|model bucket next to the tenant aggregate. */
      ai_gw_decision_t rl_dec = {0};
      int rl_rc = llb_ai_ratelimit_check(ai_dec.key_id, ai_dec.tenant_id, model, &rl_dec);
      if (rl_rc != 0) {
        char resp_429[320];
        int n = snprintf(resp_429, sizeof(resp_429),
          "HTTP/1.1 429 Too Many Requests\r\n"
          "Content-Type: application/json\r\n"
          "Retry-After: %d\r\n"
          "Connection: close\r\n"
          "\r\n"
          "{\"error\":\"rate_limit_exceeded\",\"retry_after\":%d}\r\n",
          rl_dec.retry_after, rl_dec.retry_after);
        if (n > 0 && n < (int)sizeof(resp_429))
          send(pfe->fd, resp_429, (size_t)n, 0);
        shutdown(pfe->fd, SHUT_RDWR);
        log_info("[AIGateway] fd=%d rate-limited: key=%s tenant=%s error=%s retry=%d",
                 pfe->fd, ai_dec.key_id, ai_dec.tenant_id,
                 rl_dec.error_code, rl_dec.retry_after);
        return;
      }

      /* Step 3: pre-admission token reservation → 429 BEFORE dispatch.
       * Claim the request's worst case (prompt estimated from the body's
       * messages/prompt extent + its declared max_tokens ceiling) against
       * the tenant quota now, while denial costs one cheap response — not
       * a backend prefill whose tokens the latch only bills afterwards.
       * The claim and its window tag ride the pfe to the consume call,
       * which credits the ceiling back and charges the real usage. */
      if (gate_body && gate_body_len > 0) {
        int resv_prompt = estimate_prompt_tokens(gate_body, gate_body_len);
        int resv_max = extract_max_tokens(gate_body, gate_body_len);
        if (resv_prompt > 0 || resv_max > 0) {
          ai_gw_decision_t rs_dec = {0};
          int64_t rs_epoch = 0;
          if (llb_ai_token_quota_reserve(ai_dec.tenant_id, model,
                                         resv_prompt, resv_max,
                                         &rs_epoch, &rs_dec) != 0) {
            char resp_429r[320];
            int rn = snprintf(resp_429r, sizeof(resp_429r),
              "HTTP/1.1 429 Too Many Requests\r\n"
              "Content-Type: application/json\r\n"
              "Retry-After: %d\r\n"
              "Connection: close\r\n"
              "\r\n"
              "{\"error\":\"%s\",\"retry_after\":%d}\r\n",
              rs_dec.retry_after, rs_dec.error_code, rs_dec.retry_after);
            if (rn > 0 && rn < (int)sizeof(resp_429r))
              send(pfe->fd, resp_429r, (size_t)rn, 0);
            shutdown(pfe->fd, SHUT_RDWR);
            log_info("[AIGateway] fd=%d pre-admission denied: tenant=%s "
                     "want=%d+%d error=%s retry=%d",
                     pfe->fd, ai_dec.tenant_id, resv_prompt, resv_max,
                     rs_dec.error_code, rs_dec.retry_after);
            return;
          }
          if (rs_epoch != 0) {
            pfe->usage_reserved_toks = (uint32_t)(resv_prompt + resv_max);
            pfe->usage_res_epoch = rs_epoch;
          }
        }
      }
    }
  }

#ifdef HAVE_PII_DETECTION
  // Perform PII scanning and store masked result for deferred application
  // SAFE: We scan and store the result, but DON'T modify rcvbuf until proxy_try_epxmit()
  presidio_config_shm_t *pii_cfg = presidio_config_get();
  if (pii_cfg && pii_cfg->enabled && pfe->http_content_length > 0 && pfe->rcv_off > 0) {
    if (pfe->http_content_length >= pii_cfg->min_body_size &&
        pfe->http_content_length <= pii_cfg->max_body_size) {
      
      // Find body start
      const char *body_start = NULL;
      size_t body_len = 0;
      for (size_t i = 0; i < pfe->rcv_off - 3; i++) {
        if (pfe->rcvbuf[i] == '\r' && pfe->rcvbuf[i+1] == '\n' &&
            pfe->rcvbuf[i+2] == '\r' && pfe->rcvbuf[i+3] == '\n') {
          body_start = (const char *)(pfe->rcvbuf + i + 4);
          body_len = pfe->rcv_off - (i + 4);
          break;
        }
      }
      
      if (body_start && body_len > 0) {
        // Check URL patterns
        int should_scan = 1;
        if (pii_cfg->num_url_patterns > 0 && pfe->request_path[0] != '\0') {
          should_scan = 0;
          for (int i = 0; i < pii_cfg->num_url_patterns; i++) {
            if (fnmatch(pii_cfg->url_patterns[i].pattern, pfe->request_path, FNM_PATHNAME) == 0) {
              should_scan = !pii_cfg->url_patterns[i].is_exclude;
              break;
            }
          }
        }
        
        if (should_scan && presidio_is_initialized()) {
          // Check if content is JSON (Content-Type detection)
          int is_json = 0;
          const char *headers = (const char *)pfe->rcvbuf;
          size_t headers_len = body_start - headers;
          
          if (headers_len > 20 && headers_len < 8192) {
            // Search for Content-Type: application/json (case-insensitive)
            const char *ct_pos = strnstr_portable(headers, "Content-Type:", headers_len);
            if (!ct_pos) {
              ct_pos = strnstr_portable(headers, "content-type:", headers_len);
            }
            if (ct_pos) {
              const char *line_end = strnstr_portable(ct_pos, "\r\n", headers_len - (ct_pos - headers));
              if (line_end) {
                size_t ct_line_len = line_end - ct_pos;
                if (strnstr_portable(ct_pos, "application/json", ct_line_len)) {
                  is_json = 1;
                  log_debug("[PII_JSON] JSON Content-Type detected");
                }
              }
            }
          }
          
          // Scan with Presidio (JSON-aware or text mode)
          presidio_operators_t ops = {0};
          ops.default_op.type = PRESIDIO_OP_REPLACE;
          strncpy(ops.default_op.params, "{\"new_value\":\"***PII***\"}", 
                  sizeof(ops.default_op.params) - 1);
          
          // Set entity-specific operators (required for structured anonymization)
          ops.email_op.type = PRESIDIO_OP_REPLACE;
          strncpy(ops.email_op.params, "{\"new_value\":\"***PII***\"}", 
                  sizeof(ops.email_op.params) - 1);
          
          ops.ssn_op.type = PRESIDIO_OP_REPLACE;
          strncpy(ops.ssn_op.params, "{\"new_value\":\"***PII***\"}", 
                  sizeof(ops.ssn_op.params) - 1);
          
          ops.credit_card_op.type = PRESIDIO_OP_REPLACE;
          strncpy(ops.credit_card_op.params, "{\"new_value\":\"***PII***\"}", 
                  sizeof(ops.credit_card_op.params) - 1);
          
          ops.phone_op.type = PRESIDIO_OP_REPLACE;
          strncpy(ops.phone_op.params, "{\"new_value\":\"***PII***\"}", 
                  sizeof(ops.phone_op.params) - 1);
          
          ops.person_op.type = PRESIDIO_OP_REPLACE;
          strncpy(ops.person_op.params, "{\"new_value\":\"***PII***\"}", 
                  sizeof(ops.person_op.params) - 1);
          
          pii_scan_result_v2_t *scan_result_v2 = NULL;
          int scan_rc;
          
          if (is_json && presidio_json_enabled()) {
            // JSON-aware anonymization
            log_debug("[PII_JSON] Using JSON mode for request");
            scan_rc = presidio_anonymize_json(body_start, body_len, &ops, &scan_result_v2);
          } else {
            // Text-based anonymization (existing)
            scan_rc = presidio_scan_v2(body_start, body_len, &ops, &scan_result_v2);
          }
          
          if (scan_rc == 0 && scan_result_v2 && scan_result_v2->anonymized_text && 
              scan_result_v2->anonymized_len > 0) {
            
            log_info("[PII_DETECTED] fd=%d path=%s entities=%d",
                    pfe->fd, pfe->request_path, scan_result_v2->entity_count);
            
#ifdef HAVE_PROXY_EXTRA_DEBUG
            // Show original body preview (first 200 chars)
            char orig_preview[201];
            size_t orig_preview_len = body_len > 200 ? 200 : body_len;
            memcpy(orig_preview, body_start, orig_preview_len);
            orig_preview[orig_preview_len] = '\0';
            log_debug("[PII_ORIGINAL] fd=%d: Original body (first 200): %s",
                     pfe->fd, orig_preview);
            
            // Show masked body preview (first 200 chars)
            char masked_preview[201];
            size_t masked_preview_len = scan_result_v2->anonymized_len > 200 ? 200 : scan_result_v2->anonymized_len;
            memcpy(masked_preview, scan_result_v2->anonymized_text, masked_preview_len);
            masked_preview[masked_preview_len] = '\0';
            log_debug("[PII_MASKED] fd=%d: Masked body (first 200): %s",
                     pfe->fd, masked_preview);
#endif
            
            // Store masked text for deferred application
            if (pii_cfg->mode != PRESIDIO_MODE_DETECT_ONLY) {
              pfe->pii_masked_text = malloc(scan_result_v2->anonymized_len + 1);
              if (pfe->pii_masked_text) {
                memcpy(pfe->pii_masked_text, scan_result_v2->anonymized_text, 
                       scan_result_v2->anonymized_len);
                pfe->pii_masked_text[scan_result_v2->anonymized_len] = '\0';
                pfe->pii_masked_len = scan_result_v2->anonymized_len;
                pfe->pii_needs_masking = 1;
                
                log_info("[PII_DEFERRED] fd=%d: Stored masked text %zu→%zu bytes",
                        pfe->fd, body_len, pfe->pii_masked_len);
              }
            }
          }
          
          if (scan_result_v2) {
            presidio_free_result_v2(scan_result_v2);
          }
        }
      }
    }
  }
#endif

#ifdef HAVE_LLAMAFIREWALL
  // LlamaFirewall AI Security Scanning - AFTER Presidio PII masking
  // Purpose: Scan for security threats (injection attacks, jailbreaks) in PII-safe content
  // Architecture: Presidio masks PII → LlamaFirewall blocks attacks → Backend processes safe content

  // DEBUG: Log scanning entry conditions
  int lf_initialized = llamafirewall_is_initialized();
  log_debug("[LlamaFirewall-DEBUG] Scan check: fd=%d initialized=%d content_len=%d rcv_off=%d",
            pfe->fd, lf_initialized, pfe->http_content_length, pfe->rcv_off);

  if (lf_initialized && pfe->http_content_length > 0 && pfe->rcv_off > 0) {
    // Determine which content to scan: PII-masked (preferred) or original
    const char *scan_content = NULL;
    size_t scan_len = 0;
    int scanning_masked_content = 0;

    // Priority 1: Use Presidio-masked content if available
    if (pfe->pii_needs_masking && pfe->pii_masked_text && pfe->pii_masked_len > 0) {
      scan_content = pfe->pii_masked_text;
      scan_len = pfe->pii_masked_len;
      scanning_masked_content = 1;
      log_debug("[LlamaFirewall] Scanning PII-masked content (%zu bytes)", scan_len);
    } else {
      // Priority 2: Fall back to original content if no PII masking occurred
      const char *body_start = NULL;
      size_t body_len = 0;
      for (size_t i = 0; i < pfe->rcv_off - 3; i++) {
        if (pfe->rcvbuf[i] == '\r' && pfe->rcvbuf[i+1] == '\n' &&
            pfe->rcvbuf[i+2] == '\r' && pfe->rcvbuf[i+3] == '\n') {
          body_start = (const char *)&pfe->rcvbuf[i + 4];
          body_len = pfe->rcv_off - (i + 4);
          break;
        }
      }

      if (body_start && body_len > 0) {
        scan_content = body_start;
        scan_len = body_len;
        log_debug("[LlamaFirewall] Scanning original content (%zu bytes, no PII detected)", scan_len);
      }
    }

    if (scan_content && scan_len > 0) {
      // Scan for security threats
      security_scan_result_t scan_result = {0};

      // Use request_path (HTTP path) and HTTP method from parser
      uint8_t http_method = llhttp_get_method(&pfe->parser);
      const char *method = llhttp_method_name(http_method);
      const char *path = pfe->request_path[0] != '\0' ? pfe->request_path : "/";

      int scan_rc = sockproxy_llamafirewall_scan_request(method, path, scan_content, &scan_result);

      if (scan_rc == 0) {
        if (sockproxy_llamafirewall_should_block(&scan_result)) {
          log_info("[LlamaFirewall] BLOCKED: fd=%d path=%s decision=%s score=%.2f masked=%d reason=%s",
                  pfe->fd, path, sockproxy_llamafirewall_decision_str(scan_result.decision),
                  scan_result.score, scanning_masked_content,
                  scan_result.reason ? scan_result.reason : "N/A");

          // Send 403 Forbidden response and close connection
          const char *block_response =
            "HTTP/1.1 403 Forbidden\r\n"
            "Content-Type: application/json\r\n"
            "Connection: close\r\n"
            "X-LlamaFirewall-Decision: BLOCK\r\n"
            "\r\n"
            "{\"error\":\"Request blocked by LlamaFirewall\",\"reason\":\"Security threat detected\"}\r\n";

          size_t response_len = strlen(block_response);
          ssize_t sent = send(pfe->fd, block_response, response_len, 0);

          if (sent > 0) {
            log_info("[LlamaFirewall] Sent 403 response: fd=%d sent=%zd bytes", pfe->fd, sent);
          } else {
            log_error("[LlamaFirewall] Failed to send 403 response: fd=%d error=%s",
                     pfe->fd, strerror(errno));
          }

          // Close the connection immediately
          shutdown(pfe->fd, SHUT_RDWR);

          // Free allocated memory before returning
          sockproxy_llamafirewall_free_result(&scan_result);
          return;  // Don't process this request further
        } else {
          log_debug("[LlamaFirewall] ALLOWED: fd=%d path=%s score=%.2f masked=%d",
                   pfe->fd, path, scan_result.score, scanning_masked_content);
        }
      } else {
        log_debug("[LlamaFirewall] Scan error: fd=%d path=%s error=%s",
                 pfe->fd, path, scan_result.error_msg);
      }

      // Free allocated memory
      sockproxy_llamafirewall_free_result(&scan_result);
    }
  }
#endif

#ifdef HAVE_HTTP_TRACE
  // CRITICAL: Only perform deep inspection if tracing is dynamically enabled
  // This check prevents performance overhead when tracing is disabled via API
  // (curl -X POST http://localhost:11111/netlox/v1/config/trace/enable)
  // CRITICAL FIX: Declare catalog_id OUTSIDE if block (needed for defer_req_start logic)
  uint16_t catalog_id = 0;
  if (is_tracing_enabled()) {
    // Look up catalog_id from proxy entry BEFORE emitting REQ_START
    // This ensures body capture can be triggered if catalog matches
    catalog_id = pfe->catalog_id;
    
    // If catalog_id not set yet, try to get it from proxy entry now
    if (catalog_id == 0 && pfe->request_path[0] != '\0' && pfe->head != NULL) {
      proxy_map_ent_t *ent = (proxy_map_ent_t *)pfe->head;
      if (ent->catalog_id > 0) {
        catalog_id = ent->catalog_id;
        pfe->catalog_id = catalog_id;
#ifdef HAVE_PROXY_EXTRA_DEBUG
        log_debug("[CATALOG_EARLY_SET] Set pfe->catalog_id=%d from proxy entry before REQ_START", catalog_id);
#endif
      }
    }

    // Step 2: Sampling decision
    int should_sample = 0;
    int body_captured = 0;
    if (catalog_id > 0) {
      should_sample = lxb_should_sample(catalog_id);
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("[HTTP_TRACE] Sampling decision: catalog_id=%d should_sample=%d sample_rate=%d%%",
                catalog_id, should_sample, g_catalog_sample_rates[catalog_id]);
#endif

      // Step 3: Body capture (if sampled and body exists in rcvbuf)
      if (should_sample && pfe->http_content_length > 0 && pfe->rcv_off > 0) {
        // Find body start by searching for "\r\n\r\n" (end of headers)
        const char *body_start = NULL;
        size_t body_len = 0;
        
        for (size_t i = 0; i < pfe->rcv_off - 3; i++) {
          if (pfe->rcvbuf[i] == '\r' && pfe->rcvbuf[i+1] == '\n' &&
              pfe->rcvbuf[i+2] == '\r' && pfe->rcvbuf[i+3] == '\n') {
            body_start = (const char *)(pfe->rcvbuf + i + 4);
            body_len = pfe->rcv_off - (i + 4);
            break;
          }
        }
      
        if (body_start && body_len > 0) {
          // Generate root_span_id BEFORE body capture to avoid filename collision
          // (Multiple concurrent requests would all use 0000000000000000 otherwise)
          if (pfe->root_span_id == 0) {
            pfe->root_span_id = lxb_gen_span_id();
          }
          
          char filename[32];
          snprintf(filename, sizeof(filename), "lxb-body-%016lx.json", pfe->root_span_id);
          
          int result = lxb_capture_body_to_tmpfs(
            pfe->trace_id_hi,
            pfe->root_span_id,
            body_start,
            body_len,
            catalog_id
          );
          
          if (result >= 0) {
            strncpy(pfe->body_file_path, filename, sizeof(pfe->body_file_path) - 1);
            pfe->body_file_path[sizeof(pfe->body_file_path) - 1] = '\0';
            pfe->has_body_file = 1;
            body_captured = 1;
          }
          
#ifdef HAVE_PROXY_EXTRA_DEBUG
          log_debug("[HTTP_TRACE] Body captured from rcvbuf: path=/dev/shm/%s size=%zu result=%d",
                    filename, body_len, result);
#endif
        }
      }  // End of should_sample && content_length check
      
#ifdef HAVE_PROXY_EXTRA_DEBUG
      // Debug log to show the sampling/capture decision
      log_debug("[TRACE_EVENT_REQ_START] fd=%d odir=%d | "
                "catalog_id=%d sampled=%d body_captured=%d | "
                "proxy_mode=%s ssl=%p ktls=%d",
                pfe->fd, pfe->odir, catalog_id, should_sample, body_captured,
                pfe->ssl ? (pfe->ktls_enabled ? "HTTPS(kTLS)" : "HTTPS") : "HTTP",
                pfe->ssl, pfe->ktls_enabled);
#endif
    }  // End of catalog_id > 0 check
  }  // End of is_tracing_enabled() check

  // Emit REQ_START event (HTTP request headers complete)
  // Body capture happens best-effort from cache before this point
  emit_trace_event(pfe, LXB_EVENT_REQ_START, 0);
#endif

  /* P/D prefill completion detection (backend response complete, odir==1).
   * Body rewriting for client requests (odir==0) is handled AFTER setup_proxy_path()
   * in proxy_try_read() because pfe->epv is not yet set at this point. */
  if (pfe->odir == 1 && pfe->rfd_ent[0]) {
      proxy_fd_ent_t *client_pfe = pfe->rfd_ent[0];
      if (client_pfe->pd_phase == PD_PHASE_PREFILL_WAITING) {
        client_pfe->pd_phase = PD_PHASE_PREFILL_DONE;
        log_info("Prefill complete — client_fd=%d backend_fd=%d "
                 "resp_len=%zu",
                 client_pfe->fd, pfe->fd, client_pfe->pd_prefill_resp_len);

        /* Trigger decode phase — connect to decode EP and send request */
        if (pd_initiate_decode(client_pfe) < 0) {
          log_error("Failed to initiate decode — client_fd=%d",
                    client_pfe->fd);
          atomic_fetch_add(&global_stats.pd_decode_ep_died, 1);
          /* Record P/D decode failure metrics before cleanup */
          {
            const char *pd_dec_model = proxy_effective_model(client_pfe);
            int64_t d_prefill_ms = 0;
            if (client_pfe->pd_prefill_start_ns > 0 &&
                client_pfe->pd_decode_start_ns > 0) {
              d_prefill_ms = (int64_t)((client_pfe->pd_decode_start_ns -
                                        client_pfe->pd_prefill_start_ns) /
                                        1000000ULL);
            } else if (client_pfe->pd_prefill_start_ns > 0) {
              struct timespec _pdts;
              clock_gettime(CLOCK_MONOTONIC, &_pdts);
              uint64_t d_now = (uint64_t)_pdts.tv_sec * 1000000000ULL +
                               (uint64_t)_pdts.tv_nsec;
              d_prefill_ms = (int64_t)((d_now - client_pfe->pd_prefill_start_ns) /
                                        1000000ULL);
            }
            int d_kv = (client_pfe->pd_kv_params_len > 0) ? 1 : 0;
            log_info(" llb_ai_pd_record (decode error): model=%s prefill=%lldms kv=%d",
                     pd_dec_model, (long long)d_prefill_ms, d_kv);
            llb_ai_pd_record((char *)pd_dec_model, d_prefill_ms, 0, d_kv, 2);
          }
          /* P5-fix: 503 (not 502) — decode response processing failure means
           * the P/D backend pool is unavailable, not a proxy protocol error. */
          {
            static const char pd_decode_err[] =
                "HTTP/1.1 503 Service Unavailable\r\n"
                "Content-Type: application/json\r\n"
                "Connection: close\r\n"
                "\r\n"
                "{\"error\":\"pd_pool_unavailable\",\"detail\":\"decode response processing failed\"}";
            if (client_pfe->fd > 0) {
              /* Use SSL_write when client connection is TLS to avoid
               * sending plaintext over an encrypted channel (T9 fix). */
              if (client_pfe->ssl) {
                SSL_write(client_pfe->ssl, pd_decode_err, sizeof(pd_decode_err) - 1);
              } else {
                send(client_pfe->fd, pd_decode_err, sizeof(pd_decode_err) - 1,
                     MSG_DONTWAIT | MSG_NOSIGNAL);
              }
            }
          }
          client_pfe->pd_phase = PD_PHASE_ERROR;
          pd_cleanup(client_pfe);
        }
      }

    }

#ifdef HAVE_PROXY_EXTRA_DEBUG
	log_debug("http completed %p!\n", settings->uarg);
#endif
	return 0;
}

/* ---------------------------------------------------------------------------
 * response-leg HTTP_RESPONSE parser path (pd_framing_v2).
 *
 * The three callbacks below + pd_resp_parser_init() are the ONE framer that
 * replaces the three hand-rolled memmem detectors (sockproxy_http.c:1085-1355)
 * on the backend (decode/prefill) response leg. They run BEHIND pd_framing_v2:
 * with the flag OFF none of this is consulted and the legacy detectors own
 * completion byte-for-byte ( deletion is , gated on the live oracle).
 *
 * Registered on a BACKEND pfe (odir==1) initialized with HTTP_RESPONSE (NOT
 * HTTP_BOTH) so 1xx/204/304/HEAD framing rules key off parser->type correctly
 * (RESEARCH anti-pattern). The parser is fed only the NEW response bytes as they
 * arrive (llhttp retains its own incremental state across llhttp_execute calls);
 * relay to the client is UNCHANGED — these callbacks only OBSERVE framing.
 * --------------------------------------------------------------------------- */

/* on_headers_complete seam — the fragmentation-immune replacement for the
 * single-read "Content-Type: text/event-stream" memmem sniff at :1157 (the
 * Bug-A response-splitting source). OBSERVE-only here; the SSE-gauge
 * side effects stay on the legacy detectors until . */
static int
handle_resp_headers_complete(llhttp_t *parser)
{
  llhttp_settings_t *settings = parser->settings;
  proxy_fd_ent_t *pfe = settings ? settings->uarg : NULL;
  if (!pfe) {
    return 0;
  }
  pfe->http_hok = 1;
#ifdef HAVE_PROXY_EXTRA_DEBUG
  log_debug("[RESP_FRAMING] fd=%d headers complete (HTTP_RESPONSE parser)", pfe->fd);
#endif
  return 0;
}

/* on_body seam — [DONE] is ORDINARY body data under the parser path (no longer a
 * completion gate; case demoted per). OBSERVE-only; relay is unchanged. */
static int
handle_resp_body(llhttp_t *parser, const char *at, size_t length)
{
  llhttp_settings_t *settings = parser->settings;
  proxy_fd_ent_t *pfe = settings ? settings->uarg : NULL;
  (void)at;
  (void)length;
  if (!pfe) {
    return 0;
  }
  return 0;
}

/* on_message_complete — the ONE completion consumer on the response leg. Fires
 * exactly once per response message (chunked last-chunk / CL satisfied /
 * conn-close), proven fragmentation-immune by test_resp_framing.c cases 1-4.
 *
 * Reaper interlock (Pitfall #3): set stream_end_ts on the CLIENT pfe
 * so the sockproxy_health.c:451 graceful-[DONE] reaper short-circuits
 * (pd_should_graceful_complete returns 0 when stream_end_ts != 0,
 * sockproxy_pd_leak.h:240) — the framed case must NOT also be reaped (no
 * double-completion). The reaper STAYS unchanged; it nets the no-terminator
 * keep-alive-silent case llhttp cannot frame (test_resp_framing.c case 5).
 *
 * Teardown discipline (Pitfall #4, — the conc=128 cross-thread pfe
 * UAF): this callback is a teardown TRIGGER only. It does NOT free the pfe — a
 * relay may still be in flight on another notify worker. The existing two-leg
 * teardown machinery (pd_cleanup / proxy_release_fd_ctx) owns the free, on the
 * notify worker both legs are pinned to ( notify_add_ent_pinned, already
 * landed at :4980). Do NOT pre-fold any additional pinning here — only the live
 * oracle ( trapdoor) may demand it. */
static int
handle_resp_message_complete(llhttp_t *parser)
{
  llhttp_settings_t *settings = parser->settings;
  proxy_fd_ent_t *pfe = settings ? settings->uarg : NULL;
  if (!pfe) {
    return 0;
  }
  pfe->http_pok = 1;
  pfe->http_body_complete = 1;

  /* Reaper interlock: latch stream_end_ts on the CLIENT pfe (rfd_ent[0]) — the
   * entry the reaper iterates and gates on (it carries pd_phase /
   * sse_active / stream_end_ts). Only latch when not already set so we never
   * stomp a real [DONE] timestamp the legacy SSE scanner recorded. */
  if (pfe->odir == 1 && pfe->n_rfd > 0 && pfe->rfd_ent[0]) {
    proxy_fd_ent_t *client_pfe = pfe->rfd_ent[0];
    if (client_pfe->stream_end_ts == 0) {
      client_pfe->stream_end_ts = time(NULL);
    }
  }
#ifdef HAVE_PROXY_EXTRA_DEBUG
  log_debug("[RESP_FRAMING] fd=%d message complete (single completion consumer)",
            pfe->fd);
#endif
  return 0;
}

/* Lazily (idempotently) initialize a backend pfe's HTTP_RESPONSE parser + the
 * three response callbacks the first time the pd_framing_v2 path sees response
 * bytes for it. Mirrors the request-leg init shape (:6118-6125) but uses
 * HTTP_RESPONSE, NOT HTTP_BOTH. Idempotent via resp_parser_inited so we never
 * re-init mid-message (which would discard llhttp's incremental state). */
void
pd_resp_parser_init(proxy_fd_ent_t *pfe)
{
  if (!pfe || pfe->resp_parser_inited) {
    return;
  }
  llhttp_settings_init(&pfe->settings);
  pfe->settings.on_headers_complete = handle_resp_headers_complete;
  pfe->settings.on_body            = handle_resp_body;
  pfe->settings.on_message_complete = handle_resp_message_complete;
  pfe->settings.uarg               = pfe;
  llhttp_init(&pfe->parser, HTTP_RESPONSE, &pfe->settings);
  pfe->resp_parser_inited = 1;
}

int
handle_header_name(llhttp_t *parser, const char *at, size_t length)
{
  char str[256];
  llhttp_settings_t *settings = parser->settings;
  proxy_fd_ent_t *pfe;

  pfe = settings->uarg;
  assert(pfe);

  if (length >= sizeof(str)-1) {
    return 0;
  }
  strncpy(str, at, length);
  str[length] = '\0';

#ifdef HAVE_PROXY_EXTRA_DEBUG
  // Debug log for header name parsing
  log_debug("[HTTP_HEADER] fd=%d odir=%d header_name='%s' (len=%zu)",
            pfe->fd, pfe->odir, str, length);
#endif

  // Store header name for later value matching
  if (length < sizeof(pfe->last_header_name)) {
    strncpy(pfe->last_header_name, at, length);
    pfe->last_header_name[length] = '\0';
  }

  if (strncasecmp("Host", str, length) == 0) {
    pfe->http_hok = 1;
  }

	return 0;
}

int
handle_header_val(llhttp_t *parser, const char *at, size_t length)
{
  llhttp_settings_t *settings = parser->settings;
  proxy_fd_ent_t *pfe;

  pfe = settings->uarg;
  assert(pfe);

#ifdef HAVE_PROXY_EXTRA_DEBUG
  // Debug log for header value parsing
  char value_preview[128];
  size_t preview_len = (length < sizeof(value_preview) - 1) ? length : sizeof(value_preview) - 1;
  strncpy(value_preview, at, preview_len);
  value_preview[preview_len] = '\0';
  log_debug("[HTTP_HEADER] fd=%d odir=%d header_value='%s: %s' (len=%zu)",
            pfe->fd, pfe->odir, pfe->last_header_name, value_preview, length);
#endif

  // P0.3: Check for conversation/session ID headers (multiple formats supported)
  // X-Conversation-ID: Standard conversation tracking
  // X-Request-Id: Common in OpenAI API and many LLM frameworks
  // X-Session-ID: Alternative session tracking
  // X-Trace-ID: Distributed tracing ID (can be used for affinity)
  if (!strncasecmp("X-Conversation-ID", pfe->last_header_name, 17) ||
      !strncasecmp("X-Request-Id", pfe->last_header_name, 12) ||
      !strncasecmp("X-Session-ID", pfe->last_header_name, 12) ||
      !strncasecmp("X-Trace-ID", pfe->last_header_name, 10)) {
    if (length < sizeof(pfe->conversation_id)) {
      strncpy(pfe->conversation_id, at, length);
      pfe->conversation_id[length] = '\0';
      pfe->has_conv_id = 1;
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("P0.3: Extracted conversation ID from header '%s': %s",
                pfe->last_header_name, pfe->conversation_id);
#endif
    }
  }

  /* Also store X-Request-Id in vllm_request_id for P/D propagation */
  if (!strncasecmp("X-Request-Id", pfe->last_header_name, 12)) {
    size_t copy_len = length < sizeof(pfe->vllm_request_id) - 1
                    ? length : sizeof(pfe->vllm_request_id) - 1;
    memcpy(pfe->vllm_request_id, at, copy_len);
    pfe->vllm_request_id[copy_len] = '\0';
    pfe->has_vllm_request_id = 1;
  }

  // Generic custom session header extraction with PREFIX ROUTING
  // Supports multiple session affinity methods:
  //   1. Regular header: "X-Session-ID" → extracts full header value
  //   2. Cookie: "cookie:JSESSIONID" → extracts specific cookie value
  //   3. Query param: "query:sessionid" → extracts from URL query string
  //   4. Basic Auth: "basic-auth" → extracts username from Authorization header
  
  if (pfe->session_header_name[0] != '\0') {
    
    // ROUTE 1: Cookie-specific extraction (cookie:NAME)
    if (strncmp(pfe->session_header_name, "cookie:", 7) == 0) {
      // Only process Cookie header
      if (!strncasecmp("Cookie", pfe->last_header_name, 6)) {
        const char *cookie_name = pfe->session_header_name + 7;  // Skip "cookie:"
        
        // Build full Cookie header string for parsing
        char cookie_header[2048];
        snprintf(cookie_header, sizeof(cookie_header), "Cookie: %.*s", (int)length, at);
        
        char cookie_value[256];
        if (extract_cookie_by_name(cookie_header, cookie_name, 
                                   cookie_value, sizeof(cookie_value)) == 0) {
          // Successfully extracted cookie value
          strncpy(pfe->custom_session_header_value, cookie_value, 
                  sizeof(pfe->custom_session_header_value) - 1);
          pfe->custom_session_header_value[sizeof(pfe->custom_session_header_value) - 1] = '\0';
          pfe->has_custom_session_header = 1;
          
#ifdef HAVE_PROXY_EXTRA_DEBUG
          log_debug("[SESSION_COOKIE] fd=%d: Extracted cookie '%s'='%s' for session affinity",
                   pfe->fd, cookie_name, cookie_value);
#endif
        }
      }
    }
    
    // ROUTE 2: Query parameter extraction (query:NAME)
    else if (strncmp(pfe->session_header_name, "query:", 6) == 0) {
      // Extract from URL in request line (stored during http_on_url callback)
      if (pfe->url_path[0] != '\0') {
        const char *param_name = pfe->session_header_name + 6;  // Skip "query:"
        
        char param_value[256];
        if (extract_query_param_value(pfe->url_path, param_name,
                                      param_value, sizeof(param_value)) == 0) {
          strncpy(pfe->custom_session_header_value, param_value,
                  sizeof(pfe->custom_session_header_value) - 1);
          pfe->custom_session_header_value[sizeof(pfe->custom_session_header_value) - 1] = '\0';
          pfe->has_custom_session_header = 1;
          
#ifdef HAVE_PROXY_EXTRA_DEBUG
          log_debug("[SESSION_QUERY] fd=%d: Extracted query param '%s'='%s' from URL '%s'",
                   pfe->fd, param_name, param_value, pfe->url_path);
#endif
        }
      }
    }
    
    // ROUTE 3: HTTP Basic Auth username extraction (basic-auth)
    else if (strcmp(pfe->session_header_name, "basic-auth") == 0) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("[BASICAUTH_ROUTE] fd=%d: Checking header '%s' against 'Authorization'",
               pfe->fd, pfe->last_header_name);
#endif
      // Only process Authorization header
      if (!strncasecmp("Authorization", pfe->last_header_name, 13)) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
        log_debug("[BASICAUTH_MATCH] fd=%d: Authorization header matched, value length=%zu",
                 pfe->fd, length);
#endif
        // 'at' points to header value: "Basic dXNlcm5hbWU6cGFzc3dvcmQ="
        // Pass it directly to extraction function
        char auth_value[2048];
        if (length < sizeof(auth_value)) {
          strncpy(auth_value, at, length);
          auth_value[length] = '\0';
          
#ifdef HAVE_PROXY_EXTRA_DEBUG
          log_debug("[BASICAUTH_BEFORE_EXTRACT] fd=%d: auth_value='%s'",
                   pfe->fd, auth_value);
#endif
          
          char username[256];
          int extract_result = extract_basic_auth_username(auth_value, username, sizeof(username));
          
#ifdef HAVE_PROXY_EXTRA_DEBUG
          log_debug("[BASICAUTH_AFTER_EXTRACT] fd=%d: extract_result=%d",
                   pfe->fd, extract_result);
#endif
          
          if (extract_result == 0) {
            strncpy(pfe->custom_session_header_value, username,
                    sizeof(pfe->custom_session_header_value) - 1);
            pfe->custom_session_header_value[sizeof(pfe->custom_session_header_value) - 1] = '\0';
            pfe->has_custom_session_header = 1;
            
#ifdef HAVE_PROXY_EXTRA_DEBUG
            log_debug("[SESSION_BASICAUTH] fd=%d: Extracted username='%s' from Basic Auth",
                     pfe->fd, username);
#endif
          }
        }
      }
    }
    
    // ROUTE 4: Regular header extraction (default behavior - backward compatible)
    else {
      size_t header_name_len = strlen(pfe->session_header_name);
      
      // Case-insensitive comparison with configured header name
      if (header_name_len == strlen(pfe->last_header_name) &&
          !strncasecmp(pfe->session_header_name, 
                      pfe->last_header_name, 
                      header_name_len)) {
        
        // Match found! Extract full header value (original behavior)
        if (length > 0 && length < sizeof(pfe->custom_session_header_value)) {
          strncpy(pfe->custom_session_header_value, at, length);
          pfe->custom_session_header_value[length] = '\0';
          pfe->has_custom_session_header = 1;
          
#ifdef HAVE_PROXY_EXTRA_DEBUG
          log_debug("[SESSION_HEADER] fd=%d: Extracted header '%s'='%.*s' for session affinity",
                   pfe->fd, pfe->session_header_name, (int)length, at);
#endif
        }
      }
    }
  }

  // Check if this is Content-Length header
  if (!strncasecmp("Content-Length", pfe->last_header_name, 14)) {
    char len_str[32];
    if (length < sizeof(len_str) - 1) {
      strncpy(len_str, at, length);
      len_str[length] = '\0';
      pfe->http_content_length = strtoull(len_str, NULL, 10);
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("Content-Length: %zu\n", pfe->http_content_length);
#endif
    }
  }

  // Criterion A: Extract X-Model header for model-based endpoint pool selection
  // Priority: X-Model header (fast path) > JSON body "model" field > "" (wildcard)
  if (!strncasecmp("X-Model", pfe->last_header_name, 7)) {
    if (length > 0 && length < sizeof(pfe->x_model_header)) {
      strncpy(pfe->x_model_header, at, length);
      pfe->x_model_header[length] = '\0';
    }
  }

  // AI Gateway: Extract X-Api-Key header for data-plane enforcement 
  if (!strncasecmp("X-Api-Key", pfe->last_header_name, 9)) {
    if (length > 0 && length < sizeof(pfe->x_api_key_raw)) {
      strncpy(pfe->x_api_key_raw, at, length);
      pfe->x_api_key_raw[length] = '\0';
    }
  }

  // FIXED: Properly match Host header using last_header_name instead of flawed http_hok/http_hvok logic
  // This prevents capturing wrong header values (e.g., User-Agent) as the hostname
  if (!strncasecmp("Host", pfe->last_header_name, 4)) {
    if (length < sizeof(pfe->host_url)) {
      strncpy(pfe->host_url, at, length);
      pfe->host_url[length] = '\0';
      pfe->http_hvok = 1;  // Mark that we have the host value
    }
  }

#ifdef HAVE_HTTP_TRACE
  // Parse W3C Trace Context traceparent header (: Protocol Analyzer)
  // Format: 00-<trace_id>-<parent_id>-<flags>
  // Example: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01
  if (!strncasecmp("traceparent", pfe->last_header_name, 11)) {
    if (is_tracing_enabled()) {
      char header_buf[128];
      if (length < sizeof(header_buf) - 1) {
        strncpy(header_buf, at, length);
        header_buf[length] = '\0';
        
        // Parse traceparent header
        uint8_t flags = 0;
        int ret = lxb_parse_traceparent(header_buf,
                                        &pfe->trace_id_hi,
                                        &pfe->trace_id_lo,
                                        &pfe->parent_span_id,
                                        &flags);
        if (ret == 0) {
          pfe->trace_flags = flags;
          pfe->has_traceparent = 1;
#ifdef HAVE_PROXY_EXTRA_DEBUG
          log_debug("[HTTP_TRACE] Parsed traceparent: trace_id=%016lx%016lx parent=%016lx flags=%02x",
                   pfe->trace_id_hi, pfe->trace_id_lo, pfe->parent_span_id, flags);
#endif
        } else {
#ifdef HAVE_PROXY_EXTRA_DEBUG
          log_debug("[HTTP_TRACE] Failed to parse traceparent header: %s", header_buf);
#endif
        }
      }
    }
  }
#endif

#ifdef HAVE_PROXY_EXTRA_DEBUG
	// Show actual header value (first 50 chars) instead of always showing host_url
	char debug_val[64];
	size_t copy_len = (length < 50) ? length : 50;
	strncpy(debug_val, at, copy_len);
	debug_val[copy_len] = '\0';
	log_debug("Header val rcvd %s: %s%s!", pfe->last_header_name, debug_val,
	         (length > 50) ? "..." : "");
#endif

  // append EVERY parsed header into the bounded generic L7
  // store so l7_policy_evaluate (Plan 03/04) can match arbitrary HEADER/COOKIE
  // conditions, not just the ~8 named headers special-cased above. The named
  // cascade is left untouched (the AI path + existing CICD depend on it);
  // re-storing those names here is harmless. `at`/`length` are NOT NUL-terminated
  // (llhttp), and pfe->last_header_name IS NUL-terminated (set in handle_header_field),
  // so use the length-aware helper. The store is bounded (overflow dropped).
  l7_store_header_n(pfe, pfe->last_header_name, strlen(pfe->last_header_name),
                    at, length);

	return 0;
}

int
handle_url(llhttp_t *parser, const char *at, size_t length)
{
  llhttp_settings_t *settings = parser->settings;
  proxy_fd_ent_t *pfe;

  pfe = settings->uarg;
  assert(pfe);

  // Store full URL with query string (for query parameter extraction)
  if (length < sizeof(pfe->url_path)) {
    strncpy(pfe->url_path, at, length);
    pfe->url_path[length] = '\0';
  }

  // Store request path (pattern matches handle_header_val for Host)
  if (length < sizeof(pfe->request_path)) {
    strncpy(pfe->request_path, at, length);
    pfe->request_path[length] = '\0';
    pfe->http_path_ok = 1;  // Mark that we have the path

    // Store HTTP method for trace events (method is reliably available here)
    // This must be done during URL parsing before parser state is cleared
    // Note: Always call llhttp_method_name() rather than checking parser->method first,
    // as some methods (like DELETE) may have timing issues where parser->method appears
    // as 0 during the check but becomes valid immediately after
#ifdef HAVE_HTTP_TRACE
    const char *method_str = llhttp_method_name(parser->method);
    if (method_str && method_str[0] != '\0') {
      strncpy(pfe->http_method, method_str, sizeof(pfe->http_method) - 1);
      pfe->http_method[sizeof(pfe->http_method) - 1] = '\0';
      log_debug("[METHOD_STORE] fd=%d method_str='%s' stored='%s'",
                pfe->fd, method_str, pfe->http_method);
    } else {
      log_debug("[METHOD_STORE_SKIP] fd=%d method_str=%p (null or empty)",
                pfe->fd, method_str);
    }

#ifdef HAVE_PROXY_EXTRA_DEBUG
    // Enhanced debug log with method information
    log_debug("[HTTP_REQUEST] fd=%d odir=%d method=%s path='%s'",
              pfe->fd, pfe->odir, pfe->http_method, pfe->request_path);
#endif
#endif
  }

  return 0;
}
/* JSON functions (jsoneq, json_extract_string, compute_*_hash, extract_llm_prefix, compute_prefix_hash) moved to sockproxy_json.c */


/* CHWBL ring algorithms moved to sockproxy_lb.c */

/* Universal health mgmt moved to sockproxy_health.c */

/*
 * handle_new_connection - Accept and initialize new client connections
 * 
 * Extracted from proxy_notifier to improve debuggability.
 * Handles: accept(), SSL handshake, ALPN negotiation, HTTP/2 setup,
 * session initialization, and registration with notification system.
 * 
 * @param fd: Listen socket file descriptor
 * @param pfe: Proxy file descriptor entry for listen socket
 * @param ent: Proxy map entry containing config (SSL context, etc.)
 * @param key: Sockmap key (output parameter)
 * @param rkey: Reverse sockmap key (output parameter)
 * @param ep_sel: Endpoint selection data (output parameter)
 * 
 * Returns: 0 on success (connection accepted), -1 to restart, 1 to continue loop
 */
int
handle_new_connection(int fd, proxy_fd_ent_t *pfe, proxy_map_ent_t *ent,
                      struct llb_sockmap_key *key, struct llb_sockmap_key *rkey,
                      proxy_ep_sel_t *ep_sel)
{
  int new_sd;
  int protocol;
  int retry;
  proxy_fd_ent_t *npfe1 = NULL;
  SSL *ssl = NULL;

  /* : global total-footprint ingress backpressure (knob
   * LLB_PD_MAX_TOTAL_INFLIGHT). BEFORE accept(), if the bound is enabled
   * (pd_max_total_inflight() > 0, i.e. LLB_PD_MAX_TOTAL_INFLIGHT set) and the
   * global in-flight gauge has reached it, REFUSE this accept() — return WITHOUT
   * calling accept() so the SYN stays in the listen(fd,32) backlog and the kernel
   * applies natural TCP backpressure. This is the XDP-safest primitive under
   * --net=host: it touches NO established-conn epoll/XDP state and does NOT delete
   * the listener from the pollset (a busy spin while over the bound is bounded by
   * the gauge draining via pfe_recycle on the next teardown). With the bound unset
   * (== 0) pd_admission_should_accept() always returns 1 ⇒ this whole block is a
   * no-op ⇒ the accept path is byte-identical to today. */
  {
    uint32_t total_bound = pd_max_total_inflight();
    if (total_bound > 0) {
      uint64_t cur = atomic_load_explicit(
          &global_stats.pd_admission_total_inflight, memory_order_relaxed);
      if (!pd_admission_should_accept(cur, total_bound)) {
        uint64_t blk = atomic_fetch_add_explicit(
            &global_stats.pd_admission_total_blocked, 1, memory_order_relaxed) + 1;
        /* Rate-limit the log so a sustained flood does not spam: every 1024th. */
        if ((blk & 1023u) == 1u) {
          log_info("[PD_ADMISSION] accept gated: total_inflight=%lu >= bound=%u "
                   "(blocked_total=%lu) — SYN held in listen backlog",
                   (unsigned long)cur, total_bound, (unsigned long)blk);
        }
        return 1; // Continue the event loop; SYN stays queued in the backlog.
      }
    }
  }

  // Accept new connection. accept4(SOCK_CLOEXEC) rather than accept(): accepted
  // fds do NOT inherit the listener's close-on-exec flag, so a plain accept()
  // leaks every live client connection into any helper loxilb forks, holding
  // those connections open past their proxy session.
  new_sd = accept4(fd, NULL, NULL, SOCK_CLOEXEC);

  if (new_sd < 0) {
    if (errno != EWOULDBLOCK) {
      log_error("accept failed\n");
    }
    return 1; // Continue processing other events
  }

  new_sd = get_mapped_proxy_fd(new_sd, 1);

  if (proxy_skmap_key_from_fd(new_sd, key, &protocol)) {
    log_error("skmap key from fd failed");
    if (ssl) {
      SSL_shutdown(ssl);
      SSL_free(ssl);
    }
    close(new_sd);
    return 1; // Continue
  }

  proxy_sock_set_opts(new_sd, protocol);

  // SSL handshake if configured
  if (ent->val.ssl_ctx) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[SSL_HANDSHAKE_START] fd=%d: ssl_ctx=%p, starting SSL_accept", new_sd, ent->val.ssl_ctx);
#endif
    ssl = SSL_new(ent->val.ssl_ctx);
    assert(ssl);
    SSL_set_fd(ssl, new_sd);
    if (proxy_ssl_accept(ssl, new_sd) < 0) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("[SSL_HANDSHAKE_FAIL] fd=%d: SSL_accept failed", new_sd);
#endif
      SSL_free(ssl);
      close(new_sd);
      ssl = NULL;
      return 1; // Continue
    }
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[SSL_HANDSHAKE_OK] fd=%d: SSL_accept succeeded, ssl=%p", new_sd, ssl);
#endif
    
    // Note: Frontend TLS_HS event will be emitted later when we have pfe context
    // (after npfe1 is fully initialized below)
  } else {
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[NO_SSL] fd=%d: No ssl_ctx configured (plaintext connection)", new_sd);
#endif
  }

  proxy_log("new accept()", key);
  log_trace("newfd = %d", new_sd);

  // Allocate and initialize new proxy entry
  npfe1 = pfe_alloc();   /* D2 root fix: pooled pfe shell */
  assert(npfe1);
  
  npfe1->stype = PROXY_SOCK_ACTIVE;
  npfe1->fd = new_sd;
  npfe1->seltype = pfe->seltype;
  npfe1->ep_num = -1;
  npfe1->pd_decode_ep_idx  = -1;  // Must be -1 so pd_select_decode falls through to min-load
  npfe1->pd_prefill_ep_idx = -1;  // Bug4-fix: prevent spurious active_conns decrement on early cleanup
  npfe1->head = ent;
  npfe1->ssl = ssl;
  npfe1->odir = 0;  // Client-facing connection

  // Check if kTLS was enabled during SSL_accept
  if (ssl && ktls_is_active(new_sd)) {
    npfe1->ktls_enabled = 1;
  } else {
    npfe1->ktls_enabled = 0;
  }
  
#ifdef HAVE_HTTP_TRACE
  // Emit frontend TLS handshake event (for HTTPS→* proxy modes)
  if (ssl && is_tracing_enabled()) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[TRACE_EVENT_TLS_HS_FRONTEND] fd=%d odir=%d | "
              "trace_id=%016lx%016lx parent_span=%016lx root_span=%016lx | "
              "timestamp=%lu flags=0x%02x (TLS_FRONTEND will be set) | "
              "client_ssl=YES ktls=%d proxy_mode=HTTPS→*",
              npfe1->fd, npfe1->odir,
              npfe1->trace_id_hi, npfe1->trace_id_lo, npfe1->parent_span_id, npfe1->root_span_id,
              get_timestamp_ns(), npfe1->trace_flags,
              npfe1->ktls_enabled);
#endif
    emit_trace_event(npfe1, LXB_EVENT_TLS_HS, 0);
  }
#endif
  
  // Check ALPN and initialize HTTP/2 session if negotiated
  if (ssl) {
    const unsigned char *alpn_proto = NULL;
    unsigned int alpn_len = 0;
    SSL_get0_alpn_selected(ssl, &alpn_proto, &alpn_len);
    
    if (alpn_proto && alpn_len > 0) {
      char alpn_str[32] = {0};
      snprintf(alpn_str, sizeof(alpn_str), "%.*s", (int)alpn_len, alpn_proto);
      
      // Check for HTTP/2
      if (alpn_len == 2 && memcmp(alpn_proto, "h2", 2) == 0) {
        if (proxy_check_and_setup_h2(npfe1) != 0) {
          npfe1->protocol_version = 1;
        } 
      } else if (alpn_len == 8 && memcmp(alpn_proto, "http/1.1", 8) == 0) {
        npfe1->protocol_version = 1;
      } else {
        npfe1->protocol_version = 1;
      }
    } else {
      npfe1->protocol_version = 1;
    }
  } else {
    // No SSL - must be HTTP/1.1
    npfe1->protocol_version = 1;
  }
  
  // Initialize session affinity fields
  npfe1->sticky_server_id = -1;
  npfe1->is_sticky = 0;
  npfe1->session_key[0] = '\0';
  npfe1->session_created = 0;
  npfe1->last_activity = 0;
  npfe1->affinity_type = PROXY_AFFINITY_NONE;
  
  // Initialize custom session header fields
  npfe1->custom_session_header_value[0] = '\0';
  npfe1->has_custom_session_header = 0;
  npfe1->session_header_name[0] = '\0';
  
  // Link to service entry and copy session header config
  npfe1->head = ent;
  if (ent && ent->val.ephash && ent->val.ephash->session_header_enabled) {
    strncpy(npfe1->session_header_name, ent->val.ephash->session_header_name,
            sizeof(npfe1->session_header_name) - 1);
    npfe1->session_header_name[sizeof(npfe1->session_header_name) - 1] = '\0';
    log_info("[NS_CONN_INIT] fd=%d session_header_name='%s' (sticky enabled)",
             new_sd, npfe1->session_header_name);
  } else {
    log_info("[NS_CONN_INIT] fd=%d no session header (ent=%p ephash=%p enabled=%d)",
             new_sd, (void*)ent, ent ? (void*)ent->val.ephash : NULL,
             (ent && ent->val.ephash) ? ent->val.ephash->session_header_enabled : 0);
  }

  // Copy SSE rule configuration to per-connection state (A-7)
  npfe1->sse_mode = 0;
  npfe1->ai_gw_mode = 0;           // AI-gateway connection marker (drives request accounting)
  npfe1->metric_ai_recorded = 0;   // per-request request-accounting dedup guard
  npfe1->max_stream_duration_sec = 0;
  npfe1->backend_keepalive_sec = 0;
  npfe1->inactive_timeout_sec = 0;
  npfe1->sse_active = 0;
  npfe1->stream_start_ts = 0;
  npfe1->stream_end_ts = 0;
  memset(npfe1->sse_tail, 0, sizeof(npfe1->sse_tail));
  npfe1->sse_tail_len = 0;
  if (ent && ent->val.ephash) {
    npfe1->sse_mode = ent->val.ephash->sse_mode;
    npfe1->ai_gw_mode = ent->val.ephash->ai_gw_mode;
    npfe1->max_stream_duration_sec = ent->val.ephash->max_stream_duration_sec;
    npfe1->backend_keepalive_sec = ent->val.ephash->backend_keepalive_sec;
    npfe1->inactive_timeout_sec = ent->val.ephash->inactive_timeout_sec;
  }

  // Initialize vLLM request ID state for new connection
  npfe1->vllm_request_id[0] = '\0';
  npfe1->has_vllm_request_id = 0;
  npfe1->request_id_injected = 0;

  /* C-7: Frontend socket keepalive — override TCP_KEEPIDLE on the client-facing
   * socket so that aggressive cloud NAT tables on the client side also stay alive.
   * SO_KEEPALIVE is already enabled by proxy_sock_set_opts() above.
   * Failure is non-fatal: log and continue. */
  if (npfe1->backend_keepalive_sec > 0 && protocol == IPPROTO_TCP) {
    int kv = (int)npfe1->backend_keepalive_sec;
    if (setsockopt(new_sd, IPPROTO_TCP, TCP_KEEPIDLE, &kv, sizeof(kv)) != 0) {
      log_warn("[SSE] setsockopt(TCP_KEEPIDLE) on frontend fd=%d failed: %s",
               new_sd, strerror(errno));
    }
  }

  // Initialize cache tracking
  npfe1->cache_count = 0;
  npfe1->cache_total_size = 0;
  npfe1->cache_backpressure = 0;
  npfe1->read_paused = 0;
  npfe1->qos_parked = 0;      /* pfe shells are pool-recycled, never re-zeroed */
  npfe1->qos_was_parked = 0;

  // Initialize HTTP parser
  llhttp_settings_init(&npfe1->settings);
  npfe1->settings.on_message_begin = handle_on_message_begin;
  npfe1->settings.on_message_complete = handle_on_message_complete;
  npfe1->settings.on_header_field = handle_header_name;
  npfe1->settings.on_header_value = handle_header_val;
  npfe1->settings.on_url = handle_url;
  npfe1->settings.uarg = npfe1;
  llhttp_init(&npfe1->parser, HTTP_BOTH, &npfe1->settings);
  
#ifdef HAVE_PROXY_EXTRA_DEBUG
  log_debug("[HTTP_PARSER_INIT] fd=%d: Parser initialized, ready for HTTP data", new_sd);
#endif

  // Register with notification system (with retry for fd mapping)
  for (retry = 0; retry < PROXY_MAPFD_RETRIES; retry++) {
    if (notify_add_ent(proxy_struct->ns, new_sd,
            NOTI_TYPE_IN|NOTI_TYPE_HUP, npfe1, npfe1->gen) == 0)  {
      break;
    }
    new_sd = get_mapped_proxy_fd(new_sd, 0);
    npfe1->fd = new_sd;
    if (npfe1->ssl) {
      SSL_set_fd(npfe1->ssl, new_sd);
    }
  }
  npfe1->used++;

  if (retry >= PROXY_MAPFD_RETRIES) {
    proxy_destroy_eps(new_sd, ep_sel);
    proxy_release_fd_ctx(npfe1, 0);
    pfe_recycle(npfe1);   /* D2 root fix: pool the shell (frees rcvbuf, bumps gen) */
    log_error("failed to add new_sd %d", new_sd);
    return 1; // Continue
  }

  // Setup backend path for certain protocols
  if (pfe->seltype == PROXY_SEL_N2 || protocol == IPPROTO_SCTP) {
    /* N2/SCTP is NOT a P/D path, so PD_SETUP_PARKED never arises here.
     * Capture rc defensively and treat any non-zero (parked included, though it
     * cannot occur) as a setup failure — these protocols have no parked-resume. */
    int sp_rc = setup_proxy_path(key, rkey, npfe1, NULL);
    if (sp_rc) {
      log_error("proxy setup failed %d - proto %d(sel %d)", fd, protocol, pfe->seltype);
      return -1; // Restart
    }
  }

  // Add to connection list
  PROXY_LOCK();
  npfe1->next = ent->val.fdlist;
  ent->val.fdlist = npfe1;
  ent->val.nfds++;
  PROXY_UNLOCK();

  return 0; // Success
}

/* (R1): pd_setup_and_forward return contract — the dispatch+forward
 * sequence (setup_proxy_path + P/D body-rewrite + backend forward) factored out of
 * handle_client_data so the bounded-admission RESUME path (pd_resume_parked) re-drives
 * the EXACT same code as a fresh dispatch (charged<=>dispatched holds; no divergent
 * second copy). */
#define SP_FWD_DONE      0   /* forwarded — caller breaks the read loop */
#define SP_FWD_RESTART  (-1) /* error — caller returns -1 (restart/close) */
#define SP_FWD_PARKED    2   /* held/suspended — caller keeps fd, does NOT forward/close */
#define SP_FWD_NOBACKEND 1   /* setup ok but rfd[0]<=0 — caller falls through (no forward) */

static int pd_setup_and_forward(int fd, proxy_fd_ent_t *pfe,
                                struct llb_sockmap_key *key,
                                struct llb_sockmap_key *rkey,
                                const char *phurl);

/* (R1): dispatch + forward, factored verbatim out of handle_client_data
 * (was the inline `Setup backend connection` + `NOW forward accumulated data` block).
 * Used by BOTH the fresh-dispatch site and the bounded-admission resume so the two
 * paths can never diverge. Returns SP_FWD_PARKED / SP_FWD_RESTART / SP_FWD_DONE /
 * SP_FWD_NOBACKEND (see the #defines above). */
static int
pd_setup_and_forward(int fd, proxy_fd_ent_t *pfe,
                     struct llb_sockmap_key *key,
                     struct llb_sockmap_key *rkey,
                     const char *phurl)
{
  // Setup backend connection
  {
    int sp_rc = setup_proxy_path(key, rkey, pfe, phurl);
    /* parked = held/suspended. Keep the fd, do NOT forward
     * to a backend (there is none yet), do NOT close. resumes it. */
    if (sp_rc == PD_SETUP_PARKED) return SP_FWD_PARKED;
    if (sp_rc) {
      return SP_FWD_RESTART; // Restart
    }
  }

  // NOW forward accumulated data to backend
  if (pfe->rfd[0] > 0) {  // Backend connected successfully

    /* AI-gateway token accounting: force stream_options.include_usage=true
     * into streaming request bodies BEFORE any dialect rewrite, so the
     * backend's final SSE chunk carries the usage object the response path
     * charges from. A client that omits the flag would otherwise stream
     * tokens invisible to the per-tenant quota. Placement covers every
     * plane from one site: the plain relay forwards the patched body, the
     * sequential P/D machines save it for the decode leg (their prefill
     * rewrites strip stream_options again), and the sglang dual dispatch
     * inherits it on both legs — exactly what a reference router forwards
     * when the client itself sets the flag. Chunked or partially
     * accumulated bodies are left untouched (not contiguous/complete
     * here); non-streaming requests carry usage without the flag. */
    if (pfe->epv && pfe->odir == 0 && pfe->rcv_off > 4 && !pfe->is_streamable &&
        ((proxy_epval_t *)pfe->epv)->ai_gw_mode) {
      size_t ug_scan = pfe->rcv_off < 2048 ? pfe->rcv_off : 2048;
      if (memmem(pfe->rcvbuf, ug_scan, "Transfer-Encoding: chunked", 26) == NULL &&
          memmem(pfe->rcvbuf, ug_scan, "transfer-encoding: chunked", 26) == NULL) {
        char *ug_body = NULL;
        size_t ug_body_len = 0, ug_hdr_len = 0;
        for (size_t i = 0; i + 3 < pfe->rcv_off; i++) {
          if (pfe->rcvbuf[i] == '\r' && pfe->rcvbuf[i+1] == '\n' &&
              pfe->rcvbuf[i+2] == '\r' && pfe->rcvbuf[i+3] == '\n') {
            ug_hdr_len = i + 4;
            ug_body = (char *)pfe->rcvbuf + ug_hdr_len;
            ug_body_len = pfe->rcv_off - ug_hdr_len;
            break;
          }
        }
        if (ug_body && ug_body_len > 0 && pfe->http_content_length > 0 &&
            ug_body_len >= (size_t)pfe->http_content_length) {
          size_t ug_new_len = ug_body_len;
          if (inject_include_usage(ug_body, ug_body_len,
                                   SP_SOCK_MSG_LEN - ug_hdr_len,
                                   &ug_new_len) == 0) {
            pfe->rcv_off = ug_hdr_len + ug_new_len;
            pd_update_content_length(pfe->rcvbuf, &pfe->rcv_off,
                                     SP_SOCK_MSG_LEN, ug_new_len);
            log_info("[AI_USAGE_INJECT] fd=%d body %zu -> %zu bytes",
                     pfe->fd, ug_body_len, ug_new_len);
          }
          /* Size the prompt-estimate net while the body is at hand — only
           * ever charged (flagged estimated) when the response's usage
           * object fails to materialize. */
          pfe->usage_est_prompt =
              (uint32_t)estimate_prompt_tokens(ug_body, ug_new_len);
        }
      }
    }

    /* P/D disaggregation body rewriting.
     * Moved here from handle_on_message_complete because pfe->epv
     * is only set after setup_proxy_path() runs (line above).
     * When P/D mode is active: save original body, rewrite for prefill,
     * set phase to PREFILL_SENDING. */
    if (pfe->epv) {
      proxy_epval_t *pd_tepval = (proxy_epval_t *)pfe->epv;
      if (pd_tepval->pd_disagg_enabled && pfe->odir == 0 &&
          pfe->pd_phase == PD_PHASE_NONE) {
        /* Client request complete — begin P/D orchestration */
        const uint8_t *pd_body_start = NULL;
        size_t pd_body_len = 0;
        size_t pd_hdr_len = 0;

        /* Find body in rcvbuf */
        for (size_t i = 0; i + 3 < pfe->rcv_off; i++) {
          if (pfe->rcvbuf[i] == '\r' && pfe->rcvbuf[i+1] == '\n' &&
              pfe->rcvbuf[i+2] == '\r' && pfe->rcvbuf[i+3] == '\n') {
            pd_hdr_len = i + 4;
            pd_body_start = pfe->rcvbuf + pd_hdr_len;
            pd_body_len = pfe->rcv_off - pd_hdr_len;
            break;
          }
        }

        /* Engine-dialect body preparation (ops table): the vllm machine
         * saves the body and rewrites the prefill probe; the sglang machine
         * injects the bootstrap triple. A negative return means the dialect
         * terminated the request fail-closed (error response already sent)
         * — restart the fd. */
        if (pd_body_start && pd_body_len > 0 &&
            pd_tepval->pd_ops->prepare_request(pfe, pd_tepval, pd_hdr_len,
                                               pd_body_start,
                                               pd_body_len) < 0) {
          return SP_FWD_RESTART;
        }
      }
    }

    // CRITICAL FIX: Detect chunked requests BEFORE calling inject_forwarded_headers()
    // Prevents binary data corruption from scanning chunk data as text
    int is_chunked_request = 0;
    if (pfe->rcv_off > 30) {
      size_t search_len = (pfe->rcv_off < 2048) ? pfe->rcv_off : 2048;
      if (memmem(pfe->rcvbuf, search_len, "Transfer-Encoding: chunked", 26) != NULL ||
          memmem(pfe->rcvbuf, search_len, "transfer-encoding: chunked", 26) != NULL) {
        is_chunked_request = 1;
#ifdef HAVE_PROXY_EXTRA_DEBUG
        log_debug("[CHUNKED_REQUEST_DETECTED] fd=%d: Chunked request detected, "
                  "skipping inject_forwarded_headers() to prevent corruption", fd);
#endif
      }
    }

    // Inject X-Forwarded-Proto headers before forwarding to backend
    // SKIP for chunked requests to prevent buffer corruption
    ssize_t new_len = pfe->rcv_off;  // Default: no modification

#ifdef HAVE_PROXY_EXTRA_DEBUG
    // CRITICAL: Detect if connection is HTTPS (check both SSL and kTLS)
    int is_https = (pfe->ssl != NULL) || pfe->ktls_enabled;
    log_debug("[HEADER_INJECT] fd=%d: is_chunked=%d, is_https=%d (ssl=%p, ktls=%d), rcv_off=%zu",
              fd, is_chunked_request, is_https, pfe->ssl, pfe->ktls_enabled, pfe->rcv_off);
#endif
    if (!is_chunked_request) {
      new_len = inject_forwarded_headers(pfe->rcvbuf, pfe->rcv_off, SP_SOCK_MSG_LEN,
                                         pfe->ssl != NULL,
                                         pfe->http_hvok ? pfe->host_url : NULL);
      if (new_len < 0) {
        log_error("Failed to inject X-Forwarded-Proto headers for fd=%d", fd);
        return SP_FWD_RESTART; // Restart
      }
    } else {
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("[HEADER_INJECT_PREVENTED] fd=%d: Skipped inject_forwarded_headers() "
                "for chunked request (prevents binary data corruption)", fd);
#endif
    }
    pfe->rcv_off = new_len;

    /* NEW L7-gated request-header
     * injection — ALWAYS-overwrite X-Forwarded-For (real TCP peer IP) +
     * X-Forwarded-Port/Proto + insertHeaders SET/ADD/REMOVE. Gated on
 * node->has_l7_policy: a pure no-op for the AI peer /
     * un-configured listeners (has_l7_policy==0), so that path is
 * byte-for-byte unchanged. Runs AFTER the legacy
 * inject_forwarded_headers (untouched). */
    {
      proxy_map_ent_t *l7node = (proxy_map_ent_t *)pfe->head;
      if (l7node && l7node->has_l7_policy) {
        pfe->rcv_off = l7_inject_req_headers_h1(pfe, l7node, pfe->rcvbuf,
                                                pfe->rcv_off, SP_SOCK_MSG_LEN, fd);
      }
    }

    /* P/D request-ID override — generate with prefill/decode addresses
 * so vllm-router can route correctly. Must happen BEFORE normal path. */
    if (pfe->pd_phase == PD_PHASE_PREFILL_SENDING && pfe->epv) {
      proxy_epval_t *pd_epval = (proxy_epval_t *)pfe->epv;
      int p_idx = pfe->pd_prefill_ep_idx;
      int d_idx = pfe->pd_decode_ep_idx;
      if (p_idx >= 0 && d_idx >= 0 &&
          p_idx < pd_epval->n_eps && d_idx < pd_epval->n_eps) {
        char p_addr[64], d_addr[64];
        struct in_addr p_in = { .s_addr = pd_epval->eps[p_idx].xip };
        struct in_addr d_in = { .s_addr = pd_epval->eps[d_idx].xip };
        /* Use NIXL side-channel port if configured, else fall back to HTTP port */
        uint16_t p_port = pd_epval->eps[p_idx].nixl_port ?
                          ntohs(pd_epval->eps[p_idx].nixl_port) :
                          ntohs(pd_epval->eps[p_idx].xport);
        uint16_t d_port = pd_epval->eps[d_idx].nixl_port ?
                          ntohs(pd_epval->eps[d_idx].nixl_port) :
                          ntohs(pd_epval->eps[d_idx].xport);
        snprintf(p_addr, sizeof(p_addr), "%s:%u",
                 inet_ntoa(p_in), p_port);
        snprintf(d_addr, sizeof(d_addr), "%s:%u",
                 inet_ntoa(d_in), d_port);
        /* Override: generate P/D-aware request ID with endpoint addresses */
        pfe->vllm_request_id[0] = '\0';
        pfe->request_id_injected = 0;
        generate_vllm_request_id(pfe, p_addr, d_addr);

        /* Update Content-Length for rewritten prefill body */
        pd_update_content_length(pfe->rcvbuf, &pfe->rcv_off,
                                 SP_SOCK_MSG_LEN, pfe->pd_prefill_body_len);
        /* R2 [FRAME_MISMATCH] instrument (log-only): rewritten prefill CL site.
         * decl_cl uses the rewritten body len so candidate-2
         * (CL-rewrite divergence) is distinguishable from the
         * parser-owned CL logged at the forward site below. */
        pd_frame_mismatch_log(pfe, pfe->rcvbuf, pfe->rcv_off,
                              pfe->pd_prefill_body_len,
                              "cl_rewrite_prefill");
      }
    } else {
      /* Auto-generate vLLM request ID if absent (AI Gateway mode only).
       * Must happen after setup_proxy_path (which sets epv) and after
       * inject_forwarded_headers, but before proxy_multiplexor forwards data. */
      if (pfe->epv) {
        proxy_epval_t *tepval = (proxy_epval_t *)pfe->epv;
        if (tepval->ai_gw_mode && pfe->vllm_request_id[0] == '\0') {
          generate_vllm_request_id(pfe, NULL, NULL);
        }
      }
    }

    /* Inject X-Request-Id header if auto-generated.
     * Skip injection when client provided the header (has_vllm_request_id=1). */
    if (pfe->vllm_request_id[0] != '\0' &&
        !pfe->has_vllm_request_id && !pfe->request_id_injected) {
      size_t inject_len = pfe->rcv_off;
      int rc_inj = inject_request_id_header(pfe->rcvbuf, &inject_len,
                                            SP_SOCK_MSG_LEN,
                                            pfe->vllm_request_id);
      if (rc_inj == 0) {
        pfe->rcv_off = inject_len;
        pfe->request_id_injected = 1;
      }
    }

    /* Save complete headers (with X-Request-Id) for decode phase (vLLM) or
     * for the pair-retry re-injection (SGLang dual dispatch) */
    if ((pfe->pd_phase == PD_PHASE_PREFILL_SENDING || pfe->pd_sg_active) &&
        !pfe->pd_saved_headers) {
      uint8_t *hdr_end = memmem(pfe->rcvbuf, pfe->rcv_off, "\r\n\r\n", 4);
      if (hdr_end) {
        size_t hdr_len = (size_t)(hdr_end + 4 - pfe->rcvbuf);
        pfe->pd_saved_headers = malloc(hdr_len);
        if (pfe->pd_saved_headers) {
          memcpy(pfe->pd_saved_headers, pfe->rcvbuf, hdr_len);
          pfe->pd_saved_headers_len = hdr_len;
        }
      }
    }

    PROXY_ENT_LOCK(pfe);
    pfe_ent_accouting(pfe, pfe->rcv_off, 0);
    PROXY_ENT_UNLOCK(pfe);

    /* [PD_DECISION] R3 hang-RCA instrument (LOG-ONLY, 2026-06-26). Emits ONE line per
     * forwarded request recording the P/D-vs-plain routing decision and the exact fields
     * that discriminate the two hang mechanisms found in the timeout=260 discriminator:
     *   M-i  is_streamable (>64KB body) → JSON body-scan bypass → P/D skipped → PLAIN
     *   M-ii keep-alive re-entry / stale ep/rfd → 2nd req mis-routed PLAIN
     * decision=PLAIN with disagg=1 is the bug signature (request that SHOULD be P/D but
     * fell to the un-reaped plain path). Correlate reqid with the client x-request-id to
     * map the 13–17 hung requests onto these decisions. Unconditional log_info so the
     * evidence is present regardless of HAVE_PROXY_EXTRA_DEBUG. */
    {
      int pd_dis = (pfe->epv &&
                    ((proxy_epval_t *)pfe->epv)->pd_disagg_enabled) ? 1 : 0;
      log_info("[PD_DECISION] fd=%d reqid=%s has_reqid=%d cl=%zu streamable=%d "
               "disagg=%d odir=%d pd_phase=%d n_rfd=%d ep_num=%d decision=%s",
               pfe->fd,
               pfe->vllm_request_id[0] ? pfe->vllm_request_id : "-",
               pfe->has_vllm_request_id, pfe->http_content_length,
               pfe->is_streamable, pd_dis, pfe->odir, (int)pfe->pd_phase,
               pfe->n_rfd, pfe->ep_num,
               pfe->pd_phase == PD_PHASE_PREFILL_SENDING ? "PD_PREFILL" :
               (pfe->pd_sg_active && pfe->pd_phase == PD_PHASE_NONE) ?
                   "PD_SG_DUAL" : "PLAIN");
    }

    /* P/D-aware forwarding — dialect dispatch, or normal multiplexor. The
     * dialect states below are only reachable after the prepare step ran
     * under a live epval, so the cached ops pointer is always present. */
    /* A streamable request skipped body buffering, so bootstrap injection is
     * impossible. On an SGLang-dialect disagg rule a bootstrap-less PLAIN
     * relay is never servable (disaggregation-mode engines reject or park
     * it), so refuse it fail-closed before any backend bytes move. vLLM
     * dialect rules keep their fail-open PLAIN degradation — a standalone
     * relay is served there. */
    if (pfe->epv && pfe->is_streamable &&
        !pfe->pd_sg_active && pfe->pd_phase == PD_PHASE_NONE &&
        ((proxy_epval_t *)pfe->epv)->pd_disagg_enabled &&
        ((proxy_epval_t *)pfe->epv)->pd_engine == PD_ENGINE_SGLANG) {
      pd_sg_oversize_reject(pfe);
    } else if (pfe->epv &&
        (pfe->pd_phase == PD_PHASE_PREFILL_SENDING ||
         (pfe->pd_sg_active && pfe->pd_phase == PD_PHASE_NONE))) {
      ((proxy_epval_t *)pfe->epv)->pd_ops->dispatch(pfe);
    } else {
      /* R2 [FRAME_MISMATCH] instrument (log-only): generic multiplexor forward
       * site — declared (parser-owned) CL vs actual relayed body. */
      pd_frame_mismatch_log(pfe, pfe->rcvbuf, pfe->rcv_off,
                            pfe->http_content_length, "multiplexor");
      if (proxy_multiplexor(pfe, pfe->rcvbuf, pfe->rcv_off)) {
        return SP_FWD_RESTART; // Restart
      }
    }

    /* F-GPU-4: a STREAMED request (early-backend-connect) reaches this reset
     * with only its headers (+ any first-segment body fragment) forwarded —
     * http_pok==0 because llhttp never saw message-complete. The reset below
     * erases every marker of that in-flight body, so without this tracker the
     * next read (a) trips the KA-FIX stale-leg release (rcv_off==0 looks like
     * a request boundary), and (b) re-enters the parse phase, where body bytes
     * become garbage "requests" sprayed across Tier-2 backends (live signature:
     * backend 400 "Invalid HTTP request received" / json_invalid, one fresh
     * backend conn per 64KB chunk). Record the outstanding body byte count;
     * the read path relays exactly that many bytes before parsing again. */
    pfe->stream_body_remaining = 0;
    if (pfe->is_streamable && !pfe->http_pok && pfe->http_content_length > 0) {
      uint8_t *sb_hdr_end = memmem(pfe->rcvbuf, pfe->rcv_off, "\r\n\r\n", 4);
      size_t sb_hdr_len = sb_hdr_end ? (size_t)(sb_hdr_end + 4 - pfe->rcvbuf)
                                     : pfe->rcv_off;
      size_t sb_body_fwd = pfe->rcv_off > sb_hdr_len ?
                           pfe->rcv_off - sb_hdr_len : 0;
      if (pfe->http_content_length > sb_body_fwd) {
        pfe->stream_body_remaining = pfe->http_content_length - sb_body_fwd;
        log_info("[STREAM_BODY_TRACK] fd=%d streamed request: %zu of %zu body "
                 "bytes forwarded with headers, %zu outstanding — relay mode "
                 "until drained", pfe->fd, sb_body_fwd,
                 pfe->http_content_length, pfe->stream_body_remaining);
      }
    }

    // Reset buffer and parser for next request (HTTP keep-alive)
    pfe->rcv_off = 0;
    pfe->parsed_off = 0;
    pfe->http_pok = 0;
    pfe->http_hok = 0;
    pfe->http_hvok = 0;
    pfe->http_body_complete = 0;
    pfe->http_content_length = 0;
    pfe->is_streamable = 0;

    /* Snapshot the effective model BEFORE the model sources are cleared below:
     * the backend response has not arrived yet, and its consumers (SSE
     * activation/[DONE] metrics, stream cap/reaper, P/D completion records)
     * resolve the model via proxy_effective_model() → resp_model. */
    if (pfe->x_model_header[0] != '\0') {
      strncpy(pfe->resp_model, pfe->x_model_header, sizeof(pfe->resp_model) - 1);
    } else {
      strncpy(pfe->resp_model, pfe->prefix_key.model, sizeof(pfe->resp_model) - 1);
    }
    pfe->resp_model[sizeof(pfe->resp_model) - 1] = '\0';

    memset(&pfe->prefix_key, 0, sizeof(pfe->prefix_key));  // P0.2: Reset prefix
    pfe->has_conv_id = 0;  // P0.3: Reset conversation ID flag
    memset(pfe->conversation_id, 0, sizeof(pfe->conversation_id));  // P0.3: Clear conversation ID

    // Reset custom session header for next request on same connection
    // Each request must extract its own session header independently
    pfe->custom_session_header_value[0] = '\0';
    pfe->has_custom_session_header = 0;
    pfe->x_model_header[0] = '\0';  // Reset X-Model header for next request

    // Reset vLLM request ID for next request on keep-alive connection
    pfe->vllm_request_id[0] = '\0';
    pfe->has_vllm_request_id = 0;
    pfe->request_id_injected = 0;

    // TRUNCATION FIX: reset per-request SSE/streaming state at the keep-alive
    // boundary. The resets above clear HTTP-parse + (below) P/D-orchestration state, but
    // NOTHING clears the SSE stream fields — neither this boundary nor pd_cleanup(). So on
    // a REUSED keep-alive connection request N+1 inherited request N's sse_active=1 and
    // stream_end_ts!=0 (and a stale sse_tail). That made the SSE-activation block
    // (~:1335, gated on !sse_active) AND the data:[DONE] scanner (~:1380, gated on
    // stream_end_ts==0) BOTH skip for N+1 → its decode stream never advanced to
    // DECODE_STREAMING and its [DONE] terminator was never detected → loxilb never
    // completed the response → client truncation (ClientPayloadError / ServerDisconnected).
    // Discriminator-proven keep-alive-only (FRESH=0%, REUSE=13-22%) with the decode EP calm
    // (0 aborts, peak 12 conc) — i.e. NOT decode pressure/topology, a pure state-reset miss.
    // These fields belong to request N's (now-finished) response stream; N+1's response has
    // not begun (we just forwarded N+1's prefill), so the reset is unconditional and safe.
    if (pfe->sse_active || pfe->stream_end_ts != 0 || pfe->sse_tail_len) {
      log_info("[KA_SSE_RESET] fd=%d clearing stale stream state before next keep-alive "
               "request (sse_active=%d stream_end_ts=%ld sse_tail_len=%d)",
               pfe->fd, pfe->sse_active, (long)pfe->stream_end_ts, pfe->sse_tail_len);
    }
    pfe->sse_active = 0;
    pfe->stream_start_ts = 0;
    pfe->stream_end_ts = 0;
    pfe->sse_tail_len = 0;
    pfe->pd_last_decode_ts = 0;

    // Reset P/D state ONLY when not in active P/D flow.
    // During P/D, the prefill phase sets pd_phase=PREFILL_WAITING
    // and we must preserve it until the decode phase completes.
    // load-signal fix: ALSO preserve an in-flight single-role KV load
    // unit (kv_sr_load_held). This keep-alive reset runs right AFTER forwarding
    // the request, BEFORE the backend generates. pd_cleanup() here releases the
    // single-role active_conns unit — so previously the unit lived only for the
    // sub-millisecond forward window and the adaptive/CHWBL selector saw a
    // near-zero load signal (proven live: a 20s in-flight HIT contributed 0 to
    // the selector's totalLoad), collapsing to a single-EP hot-spot. Like P/D
    // state, the unit must survive this boundary and span the generation; it is
    // released at the NEXT request's selection (prior response provably done —
    // release-before-acquire in sockproxy_ep.c) or at connection teardown
    // (proxy_release_fd_ctx -> pd_cleanup). P/D is unaffected: kv_sr_load_held
    // is 0 on every P/D connection.
    if ((pfe->pd_phase == PD_PHASE_NONE ||
         pfe->pd_phase == PD_PHASE_ERROR) &&
        !pfe->kv_sr_load_held) {
      pd_cleanup(pfe);
      pfe->pd_phase = PD_PHASE_NONE;
    }

    llhttp_init(&pfe->parser, HTTP_BOTH, &pfe->settings);

    // CRITICAL FIX: Break read loop after forwarding request to backend
    // We must wait for backend response, not continue reading from client
    // The client has sent its full request and is waiting for response
    // Continuing to read would cause EIO on kTLS sockets
    return SP_FWD_DONE;
  }

  return SP_FWD_NOBACKEND;  /* setup ok but backend not connected */
}

/* (R1): RESUME a parked client fd — runs ON THE PARKED FD'S OWNER WORKER
 * (registered as notify_cbs.resume; the slot-freeing thread only enqueued the fd +
 * woke this worker). All pfe mutation/dispatch therefore stays on the owner thread =
 * the Phase-89/90 cross-thread UAF invariant.
 *
 * Resumability (design §9 verify-before-build #1 — CONFIRMED): no extra park-time
 * state was needed. setup_proxy_path() itself rebuilds `key` from the fd via
 * proxy_skmap_key_from_fd(pfe->fd,...); `rkey` is unused on the P/D path; `flt_url`
 * is recoverable as pfe->host_url (gated by pfe->http_hvok). The full request bytes
 * are still buffered in pfe->rcvbuf (the request was fully read+parsed BEFORE the
 * park; park only set read_paused + HUP-only + pd_phase=PARKED and returned, never
 * resetting rcv_off). So resume RE-DRIVES (does not re-read).
 *
 * Steps: resolve the pfe (gen-validated via the notifier's captured gen), confirm it
 * is still PARKED, un-pause + re-arm EPOLLIN|HUP capturing the CURRENT gen, clear the
 * park markers + pd_phase, then re-drive pd_setup_and_forward — the SAME dispatch path
 * a fresh request takes. If it parks again (still capped) that's fine; if it errors,
 * close cleanly. */
void
pd_resume_parked(int fd)
{
  if (fd <= 0 || !proxy_struct || !proxy_struct->ns) {
    return;
  }

  uint64_t reg_gen = 0;
  proxy_fd_ent_t *pfe = (proxy_fd_ent_t *)notify_priv_of_fd(proxy_struct->ns, fd, &reg_gen);
  if (!pfe) {
    /* fd no longer registered (closed/recycled since wake was queued) — drop. */
    return;
  }

  /* Staleness guards (Phase-89): the slot must still be THIS fd and THIS generation,
   * and still in the PARKED state we enqueued. A recycle (gen bump / fd mismatch) or
   * a state change means the parked identity is gone — drop the resume safely. */
  if (pfe->fd != fd) {
    return;
  }
  if (atomic_load_explicit(&pfe->gen, memory_order_acquire) != reg_gen) {
    log_warn("[PD_ADMISSION] resume fd=%d: gen mismatch (slot recycled) — drop", fd);
    return;
  }

  /* Tier-1 shaper wake rides the same owner-worker resume path. A QoS park
   * never consumed the pending payload, so re-arming EPOLLIN is the whole
   * resume — level-triggered poll re-drives handle_client_data with a
   * refilled bucket. Handled before the P/D-park gate below (a QoS-parked
   * fd is not in PD_PHASE_PARKED). */
  if (qos_resume_reader(fd, pfe)) {
    return;
  }

  if (pfe->pd_phase != PD_PHASE_PARKED) {
    /* Already resumed/reaped/torn down by another edge — idempotent no-op. */
    return;
  }

  /* Un-pause + re-arm EPOLLIN|HUP, capturing the CURRENT gen (gen-guard preserved). */
  pfe->read_paused = 0;
  notify_add_ent(proxy_struct->ns, pfe->fd, NOTI_TYPE_IN | NOTI_TYPE_HUP, pfe, pfe->gen);

  /* Clear park markers; the conn re-enters dispatch as a fresh request. pd_phase back
   * to NONE so pd_setup_and_forward's P/D entry block (gated on PD_PHASE_NONE) runs. */
  pfe->park_ep_idx   = -1;
  pfe->park_start_ts = 0;
  pfe->pd_phase      = PD_PHASE_NONE;

  /* Reconstruct the dispatch from the pfe alone (see Resumability note). */
  struct llb_sockmap_key key = { 0 };
  struct llb_sockmap_key rkey = { 0 };
  const char *phurl = pfe->http_hvok ? pfe->host_url : NULL;

  log_info("[PD_ADMISSION] fd=%d RESUME (owner worker) — re-driving dispatch", fd);

  int fwd_rc = pd_setup_and_forward(fd, pfe, &key, &rkey, phurl);
  if (fwd_rc == SP_FWD_PARKED) {
    /* Still all-capped — re-parked (held again). Nothing more to do; the next
     * slot-free will wake us again. */
    return;
  }
  if (fwd_rc == SP_FWD_RESTART) {
    /* Real error on re-dispatch — close cleanly via the standard path (deregister +
     * single-owner free). Mirrors the caller's `return -1 // Restart` semantics. */
    log_error("[PD_ADMISSION] fd=%d resume re-dispatch failed — closing", fd);
    notify_delete_ent(proxy_struct->ns, fd, 0);  /* evict=0 => cascades proxy_pdestroy (single owner) */
    return;
  }
  /* SP_FWD_DONE / SP_FWD_NOBACKEND: dispatched (or setup ok, awaiting backend) —
   * normal relay proceeds on this owner worker. */
}

/*
 * handle_client_data - Process data from active client connections
 *
 * Extracted from proxy_notifier to improve debuggability.
 * Handles: burst read loop, backpressure checks, HTTP/2 detection,
 * HTTP/1.1 parsing, LLM prefix extraction, routing, and data forwarding.
 *
 * @param fd: Client socket file descriptor
 * @param pfe: Proxy file descriptor entry for client
 * @param key: Sockmap key (for routing)
 * @param rkey: Reverse sockmap key (for routing)
 *
 * Returns: 0 on success, -1 to restart
 */
int
handle_client_data(int fd, proxy_fd_ent_t *pfe,
                   struct llb_sockmap_key *key, struct llb_sockmap_key *rkey)
{
  int j;

  // CRITICAL: Bidirectional backpressure check (inter-event check)
  // This runs BEFORE starting a new burst loop to prevent reading when destination is full
  int has_backpressure = 0;

  // Check all connected endpoints - if ANY has backpressure, pause reading
  // This works for both upload and download:
  // - Upload: client (pfe, odir=0) reads, backend (rfd_ent, odir=1) buffers → check rfd_ent cache
  // - Download: backend (pfe, odir=1) reads, client (rfd_ent, odir=0) buffers → check rfd_ent cache

  for (j = 0; j < pfe->n_rfd; j++) {
    if (pfe->rfd_ent[j]) {
      // SAFETY: Clear backpressure if cache is actually empty (prevents stuck state)
      // A QoS park is NOT backpressure: clearing read_paused here would
      // disengage the shaper — only the shaper's refill wake may do that.
      if (pfe->rfd_ent[j]->cache_backpressure && pfe->rfd_ent[j]->cache_total_size == 0 &&
          !pfe->rfd_ent[j]->qos_parked) {
        pfe->rfd_ent[j]->cache_backpressure = 0;
        pfe->rfd_ent[j]->read_paused = 0;
#ifdef HAVE_PROXY_EXTRA_DEBUG
        log_warn("⚠️  [INTER_EVENT_STUCK] fd=%d: Cleared stuck backpressure flag "
                 "(cache was empty but flag was set)", pfe->rfd_ent[j]->fd);
#endif
      }

      // If the destination has backpressure, stop reading from source
      if (pfe->rfd_ent[j]->cache_backpressure) {
        has_backpressure = 1;
        break;
      }
    }
  }

  // Skip reading if destination is under backpressure
  if (has_backpressure) {
    // CRITICAL FIX: Disable EPOLLIN to prevent infinite event loop
    // Without this, epoll keeps firing because the EPOLLIN event is never consumed
    if (!pfe->read_paused) {
      pfe->read_paused = 1;
      notify_add_ent(proxy_struct->ns, fd, NOTI_TYPE_HUP, pfe, pfe->gen);
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_warn("[BACKPRESSURE_PAUSE_READ] fd=%d (odir=%d): DISABLED EPOLLIN due to destination backpressure | "
               "This will BLOCK data flow until cache drains below %.2f MB",
               fd, pfe->odir, PROXY_CACHE_LOW_WATER / (1024.0 * 1024.0));
#endif
    } else {
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("[ALREADY_PAUSED] fd=%d (odir=%d): Read already paused, skipping event",
                fd, pfe->odir);
#endif
    }
    return 0; // Success (handled by pausing)
  } else {
    // Re-enable reads if they were paused — unless the pause belongs to the
    // Tier-1 shaper: a QoS park is released only by the refill wake.
    if (pfe->read_paused && !pfe->qos_parked) {
      pfe->read_paused = 0;
      notify_add_ent(proxy_struct->ns, fd, NOTI_TYPE_IN|NOTI_TYPE_HUP, pfe, pfe->gen);
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_warn("[BACKPRESSURE_RESUME_READ] fd=%d (odir=%d): RE-ENABLED EPOLLIN after backpressure cleared",
               fd, pfe->odir);
#endif
    }
  }

  // 🔍 DEBUG: Log start of burst loop
  log_trace("burst-start fd=%d odir=%d", fd, pfe->odir);

  /* Tier-1 byte shaper: resolve the service's bucket once per burst.
   * Client->backend reads only; an H2 connection is never shaped (a
   * connection-level pause head-of-line-blocks every stream on it). The
   * token check sits INSIDE the burst loop and clamps the read length —
   * one readiness event can otherwise drain up to 1024 x 1MB unshaped. */
  proxy_map_ent_t *qos_ent = NULL;
  if (pfe->odir == 0 && pfe->head && !pfe->h2_session) {
    proxy_map_ent_t *qhent = (proxy_map_ent_t *)pfe->head;
    if (qhent->qos_cfg.cir_Bps && (qhent->qos_cfg.dir & QOS_DIR_UPLOAD)) {
      qos_ent = qhent;
    }
  }

  for (j = 0; j < PROXY_NUM_BURST_RX; j++) {
    int sret;
    size_t rd_want = SP_SOCK_MSG_LEN - pfe->rcv_off;
    uint64_t qos_grant = 0;

    if (qos_ent && rd_want > 0) {
      qos_grant = qos_bucket_take(&qos_ent->qos_up, rd_want);
      if (qos_grant == 0) {
        if (qos_park_reader(qos_ent, pfe, fd) == 0) {
          /* parked: the pending payload stays in the socket buffer; the
           * refill wake re-arms EPOLLIN and this loop re-runs */
          goto burst_break;
        }
        /* park ring full — pass unshaped this burst rather than stall */
        qos_grant = rd_want;
      }
      rd_want = (size_t)qos_grant;
    }

    int rc = proxy_sock_read(pfe, fd, pfe->rcvbuf + pfe->rcv_off, rd_want);
    int saved_errno = errno;  // Save errno immediately after recv()

    if (qos_ent) {
      if (rc > 0) {
        if ((uint64_t)rc < qos_grant) {
          /* short read: return the unread part of the grant */
          qos_bucket_credit(&qos_ent->qos_up, qos_grant - (uint64_t)rc);
        }
        atomic_fetch_add_explicit(&qos_ent->qos_up.bytes_pass, (uint64_t)rc,
                                  memory_order_relaxed);
        if (pfe->qos_was_parked) {
          pfe->qos_was_parked = 0;
          atomic_fetch_add_explicit(&qos_ent->qos_up.bytes_delayed, (uint64_t)rc,
                                    memory_order_relaxed);
        }
      } else if (qos_grant) {
        /* nothing read (EAGAIN/EOF/error): the whole grant goes back */
        qos_bucket_credit(&qos_ent->qos_up, qos_grant);
      }
    }
    
    // Log only errors and EOF for debugging
#ifdef HAVE_PROXY_EXTRA_DEBUG
    if (rc == 0) {
      log_info("🔌 [EOF_READ] fd=%d (odir=%d): Connection closed by peer (EOF)",
               fd, pfe->odir);
    } else if (rc < 0 && saved_errno != EAGAIN && saved_errno != EWOULDBLOCK) {
      log_debug("⚠️  [READ_ERROR] fd=%d (odir=%d): Read error %d (%s)",
                fd, pfe->odir, saved_errno, strerror(saved_errno));
    }
#endif

    /* [PD_STUCK] R3 hang-RCA instrument (LOG-ONLY, 2026-06-26). When the CLIENT side (odir==0)
     * hits EOF — i.e. the client gave up (request-timeout) — dump this connection's P/D state.
     * A hung request appears here with its stuck pd_phase: pd_phase=0(NONE) ⇒ it was on the
     * un-reaped PLAIN path (the confirmed root cause); pd_phase=4(DECODE_SENDING) ⇒ decode-handoff
     * stall; pd_phase_start_ts/n_rfd/ep_num expose why no reaper gate matched. Correlate reqid with
     * the client x-request-id. Unconditional so evidence survives any build-flag config. */
    if (rc == 0 && pfe->odir == 0) {
      log_info("[PD_STUCK] fd=%d reqid=%s pd_phase=%d n_rfd=%d ep_num=%d sse_active=%d "
               "pd_phase_start_ts=%ld disagg=%d",
               fd, pfe->vllm_request_id[0] ? pfe->vllm_request_id : "-",
               (int)pfe->pd_phase, pfe->n_rfd, pfe->ep_num, pfe->sse_active,
               (long)pfe->pd_phase_start_ts,
               (pfe->epv && ((proxy_epval_t *)pfe->epv)->pd_disagg_enabled) ? 1 : 0);
    }

    // CRITICAL FIX: Handle EAGAIN/EWOULDBLOCK properly (not an error, just no more data)
    if (rc <= 0 && (saved_errno == EAGAIN || saved_errno == EWOULDBLOCK)) {
      // No more data available - this is NORMAL for non-blocking sockets
      // Break out of read loop and wait for next NOTI_TYPE_IN event
      log_trace("📭 [NO_MORE_DATA] fd=%d (odir=%d): No more data available (EAGAIN/EWOULDBLOCK), exiting burst loop",
                fd, pfe->odir);
      break;
    }
    
    errno = saved_errno;  // Restore errno before error checking
    
#ifdef HAVE_PROXY_EXTRA_DEBUG
    if (rc <= 0) {
      log_debug("[BEFORE_SOCK_READ_ERR] fd=%d odir=%d rc=%d | About to call proxy_sock_read_err()",
                fd, pfe->odir, rc);
    }
#endif
    
    if ((sret = proxy_sock_read_err(pfe, rc))) {
      // CRITICAL FIX: Break out of burst read loop when EOF is deferred
      // If proxy_sock_read_err returns 1 (keep alive), it means peer has cached data
      // We should NOT continue reading (rc=0 will loop forever)
      // Instead, break out and return to epoll - peer will trigger EPOLLOUT when cache drains
      break;
    }
    
    if (!pfe->odir) {  // Client → Proxy direction (odir=0)
      const char *phurl = "";

      // Week 3: Check if this is HTTP/2 connection
      if (pfe->h2_session && pfe->h2_session->h2_enabled) {
        pfe->rcv_off += rc;

        /* (H2 parity with the H1 path below): header-accumulation deadline.
         * On the L7_Proxy peer only (has_l7_policy==1), anchor at the first client byte and drop
         * the connection if the HEADERS frame has not completed within timeout_tcp_inspect_ms
         * (or the bounded default). The anchor is cleared in proxy_h2_on_frame_recv_callback once
 * END_HEADERS arrives. No-op for the AI peer / un-configured listeners. */
        {
          proxy_map_ent_t *h2ent = (proxy_map_ent_t *)pfe->head;
          if (h2ent && h2ent->has_l7_policy) {
            if (pfe->l7_hdr_accum_start == 0) {
              pfe->l7_hdr_accum_start = time(NULL);
            } else {
              uint32_t inspect_ms = (h2ent->arg_ptr && h2ent->arg_ptr->timeout_tcp_inspect_ms > 0)
                                    ? h2ent->arg_ptr->timeout_tcp_inspect_ms
                                    : L7_TCP_INSPECT_DEFAULT_MS;
              uint32_t inspect_s = (inspect_ms + 999) / 1000;
              if ((time(NULL) - pfe->l7_hdr_accum_start) > (time_t)inspect_s) {
                log_info("[TCP_INSPECT] fd=%d (h2): header-accumulation deadline %ums exceeded "
                         "(slowloris guard) — dropping connection", fd, inspect_ms);
                return -1;
              }
            }
          }
        }

        if (proxy_h2_handle_client_data(pfe) < 0) {
          log_error("[HTTP/2] fd=%d: Failed to handle client data", fd);
          return -1; // Restart
        }
        pfe->rcv_off = 0;

        // HTTP/2 handler manages its own state, skip HTTP/1.1 parsing
        continue;
      }

      /* F-GPU-4: outstanding body of a STREAMED request — these bytes are BODY,
       * not a new request. Relay them raw to the already-connected backend leg;
       * do NOT let the KA-FIX below release that leg (rcv_off==0 here is the
       * streamed-forward reset, not a request boundary) and do NOT re-enter the
       * parser (which would turn body bytes into garbage Tier-2 "requests").
       * Bytes past the declared Content-Length in the same read are the next
       * pipelined request: shift them to the buffer head and fall through. */
      if (pfe->stream_body_remaining > 0 && rc > 0) {
        if (pfe->rfd[0] <= 0) {
          /* backend leg died mid-body: the request is unrecoverable (its
           * framing lives on that leg) — drop the connection cleanly. */
          log_error("[STREAM_BODY_TRACK] fd=%d backend leg gone with %zu body "
                    "bytes outstanding — closing", pfe->fd,
                    pfe->stream_body_remaining);
          return -1;
        }
        size_t sb_take = ((size_t)rc <= pfe->stream_body_remaining) ?
                         (size_t)rc : pfe->stream_body_remaining;
        PROXY_ENT_LOCK(pfe);
        pfe_ent_accouting(pfe, sb_take, 0);
        PROXY_ENT_UNLOCK(pfe);
        if (proxy_multiplexor(pfe, pfe->rcvbuf, sb_take)) {
          log_error("[STREAM_BODY_TRACK] fd=%d relay of %zu body bytes failed",
                    pfe->fd, sb_take);
          return -1;
        }
        pfe->stream_body_remaining -= sb_take;
        if (pfe->stream_body_remaining == 0) {
          log_info("[STREAM_BODY_TRACK] fd=%d streamed body fully relayed",
                   pfe->fd);
        }
        if ((size_t)rc > sb_take) {
          memmove(pfe->rcvbuf, pfe->rcvbuf + sb_take, (size_t)rc - sb_take);
          rc = (int)((size_t)rc - sb_take);
          /* fall through: remaining bytes start the next request (parse) */
        } else {
          continue;   /* body chunk fully consumed — next burst read */
        }
      }

      /* KA-FIX : release the stale backend leg of a COMPLETED P/D request
       * before parsing the next keep-alive request. rfd[]/n_rfd are cleared ONLY by
       * proxy_release_rfd_ctx (via proxy_pdestroy = full close); pd_cleanup() leaves
       * them set. Without this, request N+1 on a reused connection sees rfd[0]>0,
       * SKIPS the rfd[0]<=0 parse phase below, and is mis-framed (cl=0) -> headers-only
       * PLAIN forward -> backend waits for a body that never comes -> client hang.
       * (RCA : REUSE ~22% hangs vs FRESH 0%.) pd_phase==NONE (set by pd_cleanup at
       * decode-completion, sockproxy_http.c:1468/1556) + n_rfd>0 + disagg uniquely marks
       * a completed P/D request with a stale leg; rcv_off==0 confines this to a request
       * boundary (mid-body relay has rcv_off>0; mid-P/D has pd_phase!=NONE) and
       * stream_body_remaining==0 above excludes the streamed-forward mid-body reset
       * (F-GPU-4). Runs on the
       * client fd's worker holding no lock; proxy_release_rfd_ctx locks only each backend.
       * After release rfd[0]==-1 so this SAME read falls into the parse branch and reframes
       * cleanly. No race with the Phase-89-pinned decode path: req N+1 only arrives after
       * req N's response fully drained, so pd_phase already went COMPLETE->NONE. */
      /* AI-gateway arm of the same boundary release: on an ai_gw_mode
       * connection EVERY keep-alive request must re-enter the parse phase, or
       * the auth/RPS/model gate (and the future TPM charge) runs only on
       * request #1 of the connection and a client that holds one connection
       * open bypasses enforcement entirely. Same boundary guards as the P/D
       * arm (rcv_off==0 request boundary; streamed-forward mid-body excluded
       * above), plus sse_active==0 so an in-flight streamed response is never
       * torn down by an early (pipelined) next request. Cost: the backend leg
       * is re-established per request — which also re-runs endpoint selection,
       * so a long-lived client connection no longer pins every request to the
       * EP chosen for request #1. Like the P/D arm, this assumes the client
       * does not pipeline request N+1 before N's response drains. */
      int ai_gw_boundary = 0;
      if (pfe->head) {
        proxy_map_ent_t *ka_hent = (proxy_map_ent_t *)pfe->head;
        if (ka_hent->val.ephash && ka_hent->val.ephash->ai_gw_mode &&
            pfe->sse_active == 0)
          ai_gw_boundary = 1;
      }
      if (pfe->rcv_off == 0 && pfe->n_rfd > 0 &&
          pfe->pd_phase == PD_PHASE_NONE &&
          ((pfe->epv && ((proxy_epval_t *)pfe->epv)->pd_disagg_enabled) ||
           ai_gw_boundary)) {
        log_info("[KA_FIX] fd=%d releasing stale backend leg before next keep-alive "
                 "request (n_rfd=%d rfd0=%d ai_gw=%d) — reframe/gate re-arm",
                 pfe->fd, pfe->n_rfd, pfe->rfd[0], ai_gw_boundary);
        proxy_release_rfd_ctx(pfe);
      }

      if (pfe->rfd[0] <= 0) {  // No backend connection yet - PARSING PHASE
#ifdef HAVE_PROXY_EXTRA_DEBUG
        log_debug("[FIRST_DATA] fd=%d: First data received (rfd[0]=%d), rc=%zd, ssl=%p, ktls_enabled=%d",
                  fd, pfe->rfd[0], rc, pfe->ssl, pfe->ktls_enabled);
#endif
        // Accumulate data in buffer
        pfe->rcv_off += rc;

        /* header-accumulation deadline (slowloris guard). On the L7_Proxy
         * peer ONLY (has_l7_policy==1), bound the total time spent accumulating the request headers
         * before they complete. Anchor the deadline at the first byte of the in-progress request,
         * then drop the connection if the configured timeout_tcp_inspect_ms (or the bounded default
         * when 0) elapses before http_hok flips. For the AI peer / un-configured listeners
 * (has_l7_policy==0) this is a pure no-op (byte-for-byte unchanged). The H1
         * \r\n\r\n terminator is reflected by pfe->http_hok after llhttp_execute below; we evaluate
         * the deadline here, before re-parsing, using the anchor set on the previous (partial) read. */
        {
          proxy_map_ent_t *hent = (proxy_map_ent_t *)pfe->head;
          if (hent && hent->has_l7_policy) {
            if (pfe->l7_hdr_accum_start == 0) {
              pfe->l7_hdr_accum_start = time(NULL);  /* anchor at first partial-header byte */
            } else if (pfe->http_hok == 0) {
              uint32_t inspect_ms = (hent->arg_ptr && hent->arg_ptr->timeout_tcp_inspect_ms > 0)
                                    ? hent->arg_ptr->timeout_tcp_inspect_ms
                                    : L7_TCP_INSPECT_DEFAULT_MS;
              uint32_t inspect_s = (inspect_ms + 999) / 1000;  /* round up to whole seconds */
              if ((time(NULL) - pfe->l7_hdr_accum_start) > (time_t)inspect_s) {
                log_info("[TCP_INSPECT] fd=%d: header-accumulation deadline %ums exceeded "
                         "(slowloris guard) — dropping connection", fd, inspect_ms);
                return -1;  /* restart/teardown — partial headers dropped at the deadline */
              }
            }
          }
        }

        // P6 FIX: Detect HTTP/2 prior knowledge (plaintext HTTP/2)
        // HTTP/2 connection preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" (24 bytes)
        if (pfe->rcv_off >= 24 && !pfe->h2_session) {
          const char *preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
          if (memcmp(pfe->rcvbuf, preface, 24) == 0) {                  
            // Initialize HTTP/2 session
            if (proxy_check_and_setup_h2(pfe) == 0) {
              // Session created successfully - let HTTP/2 handler take over
              // The data (including preface) will be consumed by nghttp2
              continue;
            } else {
              log_error("[HTTP/2] Failed to initialize HTTP/2 session for plaintext connection");
              return -1; // Restart
            }
          }
        }

        // DEBUG: Show first 200 bytes of accumulated data
        if (pfe->rcv_off > 0) {
          char data_preview[256];
          size_t preview_len = pfe->rcv_off < 200 ? pfe->rcv_off : 200;
          memcpy(data_preview, pfe->rcvbuf, preview_len);
          data_preview[preview_len] = '\0';
          // Replace non-printable with '.'
          for (size_t i = 0; i < preview_len; i++) {
            if (data_preview[i] < 32 || data_preview[i] > 126) data_preview[i] = '.';
          }
        }
        
        // Reset flags before parsing
        pfe->http_pok = 0;
        pfe->http_hok = 0;
        pfe->http_hvok = 0;
        pfe->http_body_complete = 0;
        pfe->is_streamable = 0;
        
        // Parse only the NEW data (incremental parsing)
        size_t to_parse = pfe->rcv_off - pfe->parsed_off;
        
#ifdef HAVE_PROXY_EXTRA_DEBUG
        // Show first 200 bytes of data being parsed
        char parse_preview[256];
        size_t preview_len = to_parse < 200 ? to_parse : 200;
        memcpy(parse_preview, (char *)pfe->rcvbuf + pfe->parsed_off, preview_len);
        parse_preview[preview_len] = '\0';
        // Replace non-printable with '.'
        for (size_t i = 0; i < preview_len; i++) {
          if (parse_preview[i] < 32 || parse_preview[i] > 126) parse_preview[i] = '.';
        }
        log_debug("[PARSE_DATA] fd=%d: Parsing %zu bytes starting at offset %zu: %.200s",
                  fd, to_parse, pfe->parsed_off, parse_preview);
#endif
        
        enum llhttp_errno err = llhttp_execute(&pfe->parser,
                                (char *)pfe->rcvbuf + pfe->parsed_off, to_parse);
        
        // Update how much we've parsed
        pfe->parsed_off = pfe->rcv_off;
        
        if (err == HPE_OK) {
          /* headers complete — clear the accumulation anchor so the tcp_inspect
           * deadline never bounds the body-upload phase (it guards header accumulation only). */
          if (pfe->http_hok) {
            pfe->l7_hdr_accum_start = 0;
            /* arm the member-data idle baseline. The request is now fully received and
             * about to be relayed to the member, so the timeoutMemberData deadline must start counting
             * "time waiting for the member to send data". The idle pass (sockproxy_health.c) only
             * evaluates when last_activity>0, but last_activity was historically set ONLY for sticky
             * sessions — so a plain L7 FORWARD never armed the deadline and a slow/blackhole member ran
 * the full backend delay. Stamp it here, gated on the SAME condition the idle pass
             * uses (has_l7_policy + timeout_member_data_ms>0), so it is a pure no-op for the AI peer /
 * un-configured listeners. A response that arrives inside the window completes
             * normally before the idle pass ticks; a member that stalls is cut at the configured ms. */
            {
              proxy_map_ent_t *l7ent = (proxy_map_ent_t *)pfe->head;
              if (l7ent && l7ent->has_l7_policy && l7ent->arg_ptr &&
                  l7ent->arg_ptr->timeout_member_data_ms > 0 && pfe->last_activity == 0) {
                pfe->last_activity = time(NULL);
              }
            }
          }
          // CRITICAL FIX: Early backend connection for uploads with Content-Length
          // Establish backend connection after parsing headers, don't wait for full body
          // This enables streaming and prevents buffer overflow for ANY sized upload (64KB+)
          //
          // Why 64KB threshold:
          // - Most small API requests (<64KB) complete in first packet → no streaming needed
          // - File uploads (>64KB) benefit from streaming → prevents buffer overflow
          // - Conservative threshold ensures we catch 250KB uploads (customer case)

          // DEBUG: Always log upload detection for diagnosis (use log_error to ensure visibility)
          if (pfe->http_hok) {
            log_error("[UPLOAD_DEBUG] fd=%d: pok=%d hok=%d hvok=%d Content-Length=%zu threshold=%d",
                     fd, pfe->http_pok, pfe->http_hok, pfe->http_hvok,
                     pfe->http_content_length, (64 * 1024));
          }
          
          // CRITICAL FIX: Early backend connection for LARGE CONTENT (streaming mode)
          // 
          // STRATEGY: Whitelist types that need body inspection, stream everything else
          // - application/json: MUST buffer fully (intelligent routing inspects body)
          // - application/x-www-form-urlencoded: MUST buffer fully (form data routing)
          // - Everything else: SAFE to stream (no body-based routing logic)
          // 
          // This includes: multipart/form-data, text/html, text/plain, text/css, 
          //                application/octet-stream, image/*, video/*, application/pdf, etc.
          // 
          // Detection: Check if Content-Type is one of the types that needs buffering
          int needs_body_inspection = 0;
          if (pfe->http_hok && pfe->rcv_off >= 100) {
            size_t search_len = (pfe->rcv_off < 2048) ? pfe->rcv_off : 2048;
            // Only these types require full body buffering for routing logic
            if (memmem(pfe->rcvbuf, search_len, "application/json", 16) != NULL ||
                memmem(pfe->rcvbuf, search_len, "application/x-www-form-urlencoded", 33) != NULL) {
              needs_body_inspection = 1;
            }
          }

          // a JSON body larger than SP_JSON_INSPECT_MAX can NEVER finish
          // buffering — rcvbuf is SP_SOCK_MSG_LEN and the partial-request path
          // below hard-fails ("return -1", connection reset) at 95% fill. Before
          // this cap, a long-context request above ~972KB (coding-assistant
          // window dumps) was therefore KILLED, not served. Above the cap we
          // stream it like any other large upload: body inspection (prefix
          // extraction / KV-exact tokenize) is skipped and routing falls
          // through to Tier-2 — fail-open, same degradation contract as every
          // other KV miss path. Requires Content-Length (chunked TE has none;
          // those already skip inspection via the content_length==0 gate).
          if (needs_body_inspection &&
              pfe->http_content_length > SP_JSON_INSPECT_MAX) {
            log_info("[JSON_STREAM_FALLBACK] fd=%d: JSON Content-Length=%zu > "
                     "inspect cap %d - streaming, body inspection skipped "
                     "(Tier-2 fail-open)",
                     fd, pfe->http_content_length, SP_JSON_INSPECT_MAX);
            needs_body_inspection = 0;
          }

          int is_streamable = !needs_body_inspection;
          
          if (pfe->http_hok && is_streamable && pfe->http_content_length > (64 * 1024)) {
            log_error("🚀 [EARLY_BACKEND_CONNECT] fd=%d: LARGE CONTENT detected (Content-Length=%zu bytes, %.2f KB) - "
                     "Streaming mode enabled (not application/json or form-urlencoded, no body inspection needed)",
                     fd, pfe->http_content_length, pfe->http_content_length / 1024.0);
            
            // Mark body as "complete" to trigger backend connection
            // Even though full body hasn't arrived yet, we have enough info to route
            pfe->http_body_complete = 1;
            
            // Mark as streamable to skip JSON body parsing below
            pfe->is_streamable = 1;
            
            // Fall through to backend setup code below
            // Remaining body will be streamed via proxy_multiplexor in burst loop
          }
          
          // Backend setup conditions:
          // 1. STREAMING MODE: hok=1 + early body_complete=1 (for large non-JSON content)
          // 2. BUFFERING MODE: pok=1 + body_complete=1 (for JSON/form data needing body inspection)
          if ((pfe->http_hok && pfe->http_body_complete && pfe->is_streamable) ||
              (pfe->http_pok && pfe->http_body_complete && !pfe->is_streamable)) {
            // Now we have the complete HTTP request (or early trigger for large streamable content)
            
            // P0.2: Extract LLM prefix from JSON body
            // SKIP for streamable content - only inspect JSON/form data
            if (!pfe->is_streamable && pfe->http_content_length > 0 && pfe->rcv_off > 0) {
              // Find start of body (after headers)
              // The parser has consumed headers, body starts at current parse position
              // For llhttp, we need to find body start by looking for "\r\n\r\n"
              const char *body_start = NULL;
              size_t body_len = 0;
              
              // Search for end of headers marker
              for (size_t search_idx = 0; search_idx < pfe->rcv_off - 3; search_idx++) {
                if (pfe->rcvbuf[search_idx] == '\r' &&
                    pfe->rcvbuf[search_idx + 1] == '\n' &&
                    pfe->rcvbuf[search_idx + 2] == '\r' &&
                    pfe->rcvbuf[search_idx + 3] == '\n') {
                  body_start = (const char *)(pfe->rcvbuf + search_idx + 4);
                  body_len = pfe->rcv_off - (search_idx + 4);
                  break;
                }
              }
              
              log_debug("[BODY_SEARCH] fd=%d: body_start=%p, body_len=%zu", fd, body_start, body_len);
              
              if (body_start && body_len > 0) {
#ifdef HAVE_HTTP_TRACE
                // CRITICAL FIX: Capture body for deep inspection BEFORE protocol-specific parsing
                // This ensures MCP, GraphQL, and other non-OpenAI protocols get body capture
                // SKIP if body was already captured at REQ_START to prevent duplicate files
                if (pfe->catalog_id > 0 && is_tracing_enabled() && !pfe->has_body_file) {
                    int should_sample = lxb_should_sample(pfe->catalog_id);
                    if (should_sample && pfe->root_span_id != 0) {
                      char body_path[256];
                      char filename[32];
                      // Use only root_span_id for shorter filename (fits in 32 bytes)
                      snprintf(filename, sizeof(filename), "lxb-body-%016lx.json", pfe->root_span_id);
                      snprintf(body_path, sizeof(body_path), "/dev/shm/%s", filename);
                      
                      int result = lxb_capture_body_to_tmpfs(
                        pfe->trace_id_hi,
                        pfe->root_span_id,
                        (const char *)body_start,
                        body_len,
                        pfe->catalog_id
                      );
                      
                      if (result >= 0) {
                        // Store ONLY filename (Go will prepend /dev/shm/)
                        strncpy(pfe->body_file_path, filename, sizeof(pfe->body_file_path) - 1);
                        pfe->body_file_path[sizeof(pfe->body_file_path) - 1] = '\0';
                        pfe->has_body_file = 1;
                      }
                      
#ifdef HAVE_PROXY_EXTRA_DEBUG
                      log_debug("[HTTP_TRACE] Body captured: catalog_id=%d size=%zu result=%d path=%s",
                                pfe->catalog_id, body_len, result, body_path);
#endif
                    }
                }
#endif
                
                // (B1): chat-routing signal + raw-body locator for
                // the KV-exact tokenize stage. body_start points INTO pfe->rcvbuf
                // (== rcvbuf + header_end + 4), so we pin the body as an
                // (offset,len) pair within rcvbuf; pd_kv_exact_select rebuilds the
                // pointer as (char *)pfe->rcvbuf + pfe->body_off. Set BEFORE the
                // backend setup / pd_kv_exact_select path runs.
                // is_chat: exact match on the parsed request path. Default 0
                // (completions/other) is fail-safe to the existing single-text
                // tokenize path (threat). Reuse the parsed pfe->request_path
                // (set by the on_url parser callback) rather than re-scanning rcvbuf.
                pfe->is_chat = 0;
                if (pfe->request_path[0] != '\0' &&
                    strncmp(pfe->request_path, "/v1/chat/completions", 20) == 0 &&
                    (pfe->request_path[20] == '\0' || pfe->request_path[20] == '?')) {
                  pfe->is_chat = 1;
                }
                pfe->body_off = (size_t)(body_start - (const char *)pfe->rcvbuf);
                pfe->body_len = body_len;
                log_debug("[KV_CHAT_DETECT] fd=%d path=%s is_chat=%u body_off=%zu body_len=%zu",
                          fd, pfe->request_path, pfe->is_chat, pfe->body_off, pfe->body_len);

                // Try to extract LLM prefix from JSON (OpenAI-specific, optional)
                log_debug("[PREFIX_EXTRACT_ATTEMPT] fd=%d: Trying to extract prefix from JSON body_len=%zu",
                          fd, body_len);
                if (extract_llm_prefix(body_start, body_len, &pfe->prefix_key) == 0) {
                  
                  // P1.1: Compute hash for CHWBL routing using xxHash
                  uint64_t prefix_hash = compute_prefix_hash(&pfe->prefix_key);
                  pfe->prefix_key.hash = prefix_hash;
                  log_debug("[PREFIX_EXTRACTED] fd=%d: prefix_hash=0x%lx, model=%s, prefix=%s", 
                            fd, prefix_hash, pfe->prefix_key.model, pfe->prefix_key.prefix);
                  
                  // P0.3: Generate conversation ID if not provided by client
                  if (!pfe->has_conv_id && pfe->prefix_key.valid) {
                    // FIX #1 CORRECTED: Salt by prefix hash, not fd
                    // This ensures same user gets same conversation ID across turns
                    // but different users with similar queries get different IDs
                    uint64_t user_salt = XXH64(pfe->prefix_key.prefix, 
                                                strlen(pfe->prefix_key.prefix), 
                                                0xCAFEBABE);
                    snprintf(pfe->conversation_id, sizeof(pfe->conversation_id),
                             "auto-%016lx-%08lx", prefix_hash, (unsigned long)(user_salt & 0xFFFFFFFF));
                    pfe->has_conv_id = 1;
                  }
                } else {
                  log_debug("[PREFIX_EXTRACT_FAILED] fd=%d: Extraction failed (returned non-zero)", fd);
                }

                // P/D Session stickiness: extract "user" field from JSON body.
                // Note: pfe->epv is not yet set (assigned in setup_proxy_path),
                // so we extract unconditionally. Harmless for non-P/D services.
                if (extract_user_id((const char *)body_start, body_len,
                                    pfe->user_id, sizeof(pfe->user_id)) == 0) {
                  pfe->has_user_id = 1;
                }
              } else {
                log_debug("[NO_BODY_DATA] fd=%d: body_start=%p, body_len=%zu - cannot extract prefix",
                          fd, body_start, body_len);
              }
            } else {
              log_debug("[NO_CONTENT_LENGTH] fd=%d: http_content_length=%zu, rcv_off=%zu - skipping prefix extraction",
                        fd, pfe->http_content_length, pfe->rcv_off);
            }
            
            if (pfe->http_hvok) {
              phurl = pfe->host_url;
            } else {
              phurl = NULL;
            }

#ifdef HAVE_DP_GPU_ROUTING
            /* PRODUCTION FIX: HTTP keep-alive double-increment guard.
             * When a client reuses a TCP connection for a second request,
             * pfe->ep_num still holds the endpoint selected for the PREVIOUS
             * request.  setup_proxy_path() calls chwbl_select_endpoint() which
             * increments active_conns AGAIN for the new request without ever
             * decrementing the old one — because ep_num gets overwritten and
             * proxy_release_fd_ctx() only decrements the final ep_num.
             * Fix: decrement the stale counter before the new selection. */
            if (pfe->ep_num >= 0 && pfe->epv) {
              proxy_epval_t *old_epv = (proxy_epval_t *)pfe->epv;
              if ((old_epv->select == PROXY_SEL_CHWBL ||
                   old_epv->select == PROXY_SEL_WRR_HASH) &&
                  old_epv->chwbl_config) {
                chwbl_dec_load(old_epv->chwbl_config, pfe->ep_num);
#ifdef HAVE_PROXY_EXTRA_DEBUG
                log_debug("[CHWBL_KEEPALIVE_DEC] fd=%d ep=%d: decremented stale"
                          " active_conns before keep-alive re-select",
                          fd, pfe->ep_num);
#endif
              }
              pfe->ep_num = -1;
              pfe->epv    = NULL;
            }
#endif

            // Setup backend connection + forward.: the dispatch+forward
            // sequence is factored into pd_setup_and_forward() so the bounded-admission
            // RESUME path (pd_resume_parked) re-drives the EXACT same code as a fresh
            // dispatch. PARKED => held/suspended (keep fd, no forward, no close — 
            // resumes via the owner-worker wake). DONE => forwarded (break the loop).
            {
              int fwd_rc = pd_setup_and_forward(fd, pfe, key, rkey, phurl);
              if (fwd_rc == SP_FWD_PARKED)  return 0;   /* held — parked admission */
              if (fwd_rc == SP_FWD_RESTART) return -1;  /* error — restart/close */
              if (fwd_rc == SP_FWD_DONE)    break;      /* forwarded — wait for backend */
              /* SP_FWD_NOBACKEND: setup ok but rfd[0]<=0 — fall through to `continue`. */
            }
          } else {
            // Partial request - check buffer overflow
            // Threshold at 95% to allow some headroom for final chunks
            // With 1MB buffer, this gives 972KB usable space before overflow protection
            // Early backend connection (at 512KB) should prevent reaching this threshold
            if (pfe->rcv_off >= (SP_SOCK_MSG_LEN * 95 / 100)) {
              log_error("⚠️  BUFFER OVERFLOW: Request too large (%zu/%d bytes, 95%% full) - "
                       "Content-Length header missing or upload exceeds buffer capacity! fd=%d", 
                       pfe->rcv_off, SP_SOCK_MSG_LEN, fd);
              log_error("   Parse state: pok=%d hok=%d body_complete=%d content_len=%zu",
                       pfe->http_pok, pfe->http_hok, pfe->http_body_complete, pfe->http_content_length);
              log_error("   Parsed: %zu bytes, Content-Length: %zu, Body complete: %d",
                       pfe->parsed_off, pfe->http_content_length, pfe->http_body_complete);
              return -1; // Restart
            }
          }
          // Continue reading more data in next iteration
          continue;
          
        } else {
          // Parse error
          pfe->rcv_off = 0;
          pfe->parsed_off = 0;
          pfe->http_pok = 0;
          pfe->http_hok = 0;
          pfe->http_hvok = 0;
          pfe->http_body_complete = 0;
          pfe->http_content_length = 0;
          memset(&pfe->prefix_key, 0, sizeof(pfe->prefix_key));  // P0.2: Reset prefix
          pfe->has_conv_id = 0;  // P0.3: Reset conversation ID flag
          memset(pfe->conversation_id, 0, sizeof(pfe->conversation_id));  // P0.3: Clear conversation ID

          // Reset custom session header on parse error
          pfe->custom_session_header_value[0] = '\0';
          pfe->has_custom_session_header = 0;

          // Reset vLLM request ID on parse error
          pfe->vllm_request_id[0] = '\0';
          pfe->has_vllm_request_id = 0;
          pfe->request_id_injected = 0;

          // TRUNCATION FIX: also clear stale SSE/streaming state on the parse-error reset
          // path (same omission as the success-path keep-alive reset above).
          pfe->sse_active = 0;
          pfe->stream_start_ts = 0;
          pfe->stream_end_ts = 0;
          pfe->sse_tail_len = 0;
          pfe->pd_last_decode_ts = 0;

          // Reset P/D state on parse error
          pd_cleanup(pfe);
          pfe->pd_phase = PD_PHASE_NONE;

          llhttp_init(&pfe->parser, HTTP_BOTH, &pfe->settings);
          phurl = NULL;
        }

        {
          int sp_rc = setup_proxy_path(key, rkey, pfe, phurl);
          /* parked = held/suspended. Keep the fd, do NOT forward, do
           * NOT close. dequeues+resumes when a prefill slot frees. */
          if (sp_rc == PD_SETUP_PARKED) return 0;
          if (sp_rc) {
            return -1; // Restart
          }
        }
      }
    } else {
      // Backend → Proxy direction (odir=1) - response forwarding
      // CRITICAL FIX: Check if this is HTTP/2 backend response
      // For HTTP/2 transit mode, backend responses must go through nghttp2 processing
      // Backend pfe (odir=1) doesn't have h2_session - check client pfe instead
      proxy_fd_ent_t *client_pfe = (pfe->odir == 1 && pfe->n_rfd > 0) ? pfe->rfd_ent[0] : NULL;
      if (client_pfe && client_pfe->h2_session && client_pfe->h2_session->h2_enabled) {
        // HTTP/2 backend response path - use nghttp2 to process frames              
        // Accumulate data in buffer for nghttp2 processing
        pfe->rcv_off += rc;
        
        // Process HTTP/2 frames from backend and forward to client
        if (proxy_h2_handle_backend_data(pfe) < 0) {
          log_error("[HTTP/2 Backend] fd=%d: Failed to handle backend response", fd);
          return -1; // Restart
        }
        
        // Reset buffer after processing (nghttp2 consumed all data)
        pfe->rcv_off = 0;
        
        // HTTP/2 handler manages state, skip HTTP/1.1 forwarding below
        continue;
      }
      
      // HTTP/1.1 backend response - parse headers for session learning
      if (rc > 0) {
        char preview[512];
        int preview_len = rc < 400 ? rc : 400;
        memcpy(preview, pfe->rcvbuf, preview_len);
        preview[preview_len] = '\0';
        
        // DIAGNOSTIC: Check if this looks like HTTP headers
        if (pfe->rcv_off == 0 && rc > 10 && 
            memcmp(pfe->rcvbuf, "HTTP/", 5) == 0) {
          // This is the start of an HTTP response - log headers
          char *header_end = strstr((char *)pfe->rcvbuf, "\r\n\r\n");
          if (header_end) {
            size_t header_len = (header_end + 4) - (char *)pfe->rcvbuf;
            char headers[2048];
            size_t copy_len = header_len < sizeof(headers) - 1 ? header_len : sizeof(headers) - 1;
            memcpy(headers, pfe->rcvbuf, copy_len);
            headers[copy_len] = '\0';
            
            // Session Learning: Extract session header from backend response
            // Only attempt if: (1) needs_session_learning flag set, (2) session_header_name configured
            if (pfe->needs_session_learning && pfe->session_header_name[0] != '\0') {
              // Parse response headers line by line to find session header
              char *line_start = strchr(headers, '\n');  // Skip HTTP status line
              if (line_start) {
                line_start++;  // Move past newline
                while (line_start && line_start < headers + copy_len) {
                  char *line_end = strstr(line_start, "\r\n");
                  if (!line_end || line_end == line_start) break;  // End of headers
                  
                  // Check if this line contains our session header
                  char *colon = strchr(line_start, ':');
                  if (colon && colon < line_end) {
                    size_t header_name_len = colon - line_start;
                    size_t session_name_len = strlen(pfe->session_header_name);
                    
                    // Case-insensitive header name comparison
                    if (header_name_len == session_name_len && 
                        strncasecmp(line_start, pfe->session_header_name, header_name_len) == 0) {
                      // Found session header! Extract value
                      char *value_start = colon + 1;
                      while (value_start < line_end && (*value_start == ' ' || *value_start == '\t')) {
                        value_start++;  // Skip whitespace
                      }
                      
                      size_t value_len = line_end - value_start;
                      if (value_len > 0 && value_len < sizeof(pfe->learned_session_id) - 1) {
                        // Store learned session ID
                        memcpy(pfe->learned_session_id, value_start, value_len);
                        pfe->learned_session_id[value_len] = '\0';
                        
                        // Get service entry and store binding in conversation map
                        proxy_map_ent_t *ent = (proxy_map_ent_t *)pfe->head;
                        if (ent && pfe->ep_num >= 0) {
                          // Create conversation ID from header name + value
                          char conv_id[MAX_CONV_ID_LEN];
                          // CRITICAL FIX: Validate combined length before storing
                          size_t total_len = strlen("custom__") + strlen(pfe->session_header_name) + 
                                             strlen(pfe->learned_session_id) + 1;
                          if (total_len >= MAX_CONV_ID_LEN) {
                            log_warn("[SESSION_LEARN_OVERFLOW] Session ID too long (%zu bytes), truncating to %d",
                                     total_len, MAX_CONV_ID_LEN);
                          }
                          snprintf(conv_id, sizeof(conv_id), "custom_%s_%s", 
                                   pfe->session_header_name, pfe->learned_session_id);
                          
                          // Store mapping: session_id → endpoint_index
                          if (store_conversation_endpoint(ent, conv_id, pfe->ep_num) == 0) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
                            log_info("[SESSION_LEARNED] Backend returned '%s: %s' → bound to endpoint[%d]",
                                     pfe->session_header_name, pfe->learned_session_id, pfe->ep_num);
#endif
                          }
                        }
                        
                        pfe->needs_session_learning = 0;  // Learning complete
                      }
                      break;  // Found and processed session header
                    }
                  }
                  
                  line_start = line_end + 2;  // Move to next line
                }
              }
              
              // If we didn't find session header in response, that's OK (backward compat)
              // Just clear the learning flag and continue with IP-based routing
              if (pfe->needs_session_learning) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
                log_debug("[SESSION_LEARN_SKIP] Backend response missing '%s' header, continuing with IP-based routing",
                          pfe->session_header_name);
#endif
                pfe->needs_session_learning = 0;
              }
            }
            
            // Check for Content-Length or Transfer-Encoding
            if (strstr(headers, "Content-Length:")) {
              log_trace("http-content-length fd=%d", fd);
            }
            if (strstr(headers, "Transfer-Encoding: chunked")) {
              log_trace("http-chunked fd=%d", fd);
            }
            if (strstr(headers, "Content-Encoding: gzip")) {
              log_trace("http-gzip fd=%d", fd);
            }
          }
        }
        
        // Log as hex to see chunk framing clearly
        for (int i = 0; i < preview_len && i < 200; i += 16) {
          char hex_line[80];
          char ascii_line[20] __attribute__((unused));  // P6: Mark unused to suppress warning
          int line_len = (preview_len - i) < 16 ? (preview_len - i) : 16;
          
          for (int j = 0; j < line_len; j++) {
            sprintf(hex_line + j*3, "%02x ", (unsigned char)pfe->rcvbuf[i+j]);
            ascii_line[j] = (pfe->rcvbuf[i+j] >= 32 && pfe->rcvbuf[i+j] < 127) ? 
                             pfe->rcvbuf[i+j] : '.';
          }
          ascii_line[line_len] = '\0';
        }
      }
    }

    // Normal forwarding (backend already connected OR backend→client)
    if (pfe->rfd[0] > 0) {
      // CRITICAL FIX: Inject X-Forwarded-Proto headers for Keep-Alive requests
      // When backend already exists (Keep-Alive), we bypass HTTP parsing above,
      // but we MUST still inject headers for EVERY request on client→backend path.
      // Only inject for client→backend (odir=0), not backend→client (odir=1)
      if (!pfe->odir && pfe->ssl) {
        // P7 FIX: Only inject headers if this packet contains COMPLETE headers
        // Check for header end marker (\r\n\r\n) in current packet
        char *headers_end_check = memmem(pfe->rcvbuf, rc, "\r\n\r\n", 4);
        int should_inject = (headers_end_check != NULL);
        
        // P7 FIX: If body is present, skip injection to prevent corruption
        // Body data in same packet as headers means Content-Length mismatch risk
        if (should_inject && headers_end_check) {
          size_t header_len = (headers_end_check + 4) - (char*)pfe->rcvbuf;
          size_t body_in_packet = rc - header_len;
          
          // If there's substantial body data (>10 bytes), this is likely a complete
          // POST request with JSON body - DON'T inject to avoid corrupting body
          if (body_in_packet > 10) {
            should_inject = 0;
#ifdef HAVE_PROXY_EXTRA_DEBUG
            log_debug("[INJECT_SKIP_BODY] fd=%d: Packet contains %zu bytes of body, "
                      "skipping injection to prevent corruption", fd, body_in_packet);
#endif
          }
        }

        // CRITICAL FIX: Detect chunked requests BEFORE calling inject_forwarded_headers()
        int is_chunked_keepalive = 0;
        if (should_inject && rc > 30) {
          size_t search_len = (rc < 2048) ? rc : 2048;
          if (memmem(pfe->rcvbuf, search_len, "Transfer-Encoding: chunked", 26) != NULL ||
              memmem(pfe->rcvbuf, search_len, "transfer-encoding: chunked", 26) != NULL) {
            is_chunked_keepalive = 1;
            should_inject = 0;
#ifdef HAVE_PROXY_EXTRA_DEBUG
            log_debug("[CHUNKED_KEEPALIVE_DETECTED] fd=%d: Chunked Keep-Alive request detected, "
                      "skipping inject_forwarded_headers() to prevent corruption", fd);
#endif
          }
        }

        // This is a client HTTPS connection sending data to backend
        // Inject X-Forwarded-Proto: https header before forwarding
        // SKIP for chunked requests or requests with body data to prevent corruption
        ssize_t new_len = rc;  // Default: no modification
        if (should_inject && !is_chunked_keepalive) {
          new_len = inject_forwarded_headers(pfe->rcvbuf, rc, SP_SOCK_MSG_LEN,
                                             1,  // is_ssl=1 (client is HTTPS)
                                             pfe->http_hvok ? pfe->host_url : NULL);
          if (new_len < 0) {
            log_error("[KEEPALIVE_INJECT_FAIL] fd=%d: Failed to inject X-Forwarded-Proto on Keep-Alive request", fd);
            return -1; // Restart
          }
#ifdef HAVE_PROXY_EXTRA_DEBUG
          if (new_len != rc) {
            log_debug("🔧 [KEEPALIVE_INJECT] fd=%d: Injected X-Forwarded-Proto on Keep-Alive request (%zd bytes)",
                      fd, new_len);
          }
#endif
        } else if (!should_inject) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
          log_trace("[INJECT_SKIP] fd=%d: Skipping injection (no complete headers or body present)", fd);
#endif
        }
        rc = new_len;  // Update length (may be unchanged for chunked)
      }

      /* NEW L7-gated request-header injection on
       * the keep-alive/burst egress too (H1 parity with the first-data path above).
 * Gated on has_l7_policy — no-op for the AI peer / un-configured
 * listeners. Legacy inject_forwarded_headers (above) stays untouched. */
      {
        proxy_map_ent_t *l7node = (proxy_map_ent_t *)pfe->head;
        if (l7node && l7node->has_l7_policy) {
          rc = (ssize_t)l7_inject_req_headers_h1(pfe, l7node, pfe->rcvbuf,
                                                 (size_t)rc, SP_SOCK_MSG_LEN, fd);
        }
      }

      PROXY_ENT_LOCK(pfe);
      pfe_ent_accouting(pfe, rc, 0);
      PROXY_ENT_UNLOCK(pfe);

      if (proxy_multiplexor(pfe, pfe->rcvbuf, rc)) {
        log_error("[BURST_MULTIPLEXOR_FAIL] fd=%d: proxy_multiplexor failed, closing connection", fd);
        return -1; // Restart
      }

      // CRITICAL: Check backpressure AFTER forwarding each packet in burst
      // If destination cache just crossed high water mark, stop reading immediately
      // This prevents cache overflow during high-throughput bursts
      for (int k = 0; k < pfe->n_rfd; k++) {
        if (pfe->rfd_ent[k] && pfe->rfd_ent[k]->cache_backpressure) {
          goto burst_break;
        }
      }
    }
  }

burst_break:
  // 🔍 DEBUG: Log burst loop exit
  log_trace("burst-end fd=%d", fd);
  
  return 0; // Success
}
