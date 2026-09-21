/*
 * Copyright (c) 2025 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 *
 * HTTP/2 Support for LoxiLB sockproxy
 * 
 * This module implements HTTP/2 protocol support using nghttp2 library,
 * enabling multiplexed streams, header compression, and better performance
 * for modern AI/LLM workloads.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdatomic.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>   /* sockaddr_in / AF_INET ( real-peer-IP for XFF) */
#include <arpa/inet.h>    /* inet_ntop / ntohs ( X-Forwarded-* construction) */
#include <openssl/ssl.h>
#include <openssl/err.h>  /* ERR_get_error / ERR_error_string (TLS error logging) */

#include "sockproxy_h2.h"
#include "sockproxy.h"
#include "sockproxy_ai_security.h"
#include "sockproxy_ai_admit.h"   /* the shared H1/H2 admission gate */
#include "sockproxy_ai_gw.h"      /* settle-path ladder calls */
#include "sockproxy_pd.h"         /* dialect ops for usage extraction */
#include "sockproxy_json.h"
#include "sockproxy_lb.h"
#include "sockproxy_l7policy.h" /* l7_route_dispatch (L7 content routing) */
#include "sockproxy_l7hdr_guard.h" /* same field guard as the H1 splice */
#include "notify.h"
#include "log.h"

// HTTP/HTTPS Tracing Support (: Error Trace Emission)
#ifdef HAVE_HTTP_TRACE
#include "lxb_ring.h"
#include "lxb_trace_event.h"
#ifdef HAVE_HTTP_TRACE
#include "sockproxy_trace.h"
#endif

// Forward declarations for trace functions (defined in sockproxy.c)
extern uint64_t get_timestamp_ns(void);
extern void emit_trace_event(proxy_fd_ent_t *pfe, uint8_t event_type, uint32_t duration_us);
extern int is_tracing_enabled(void);
#endif

// ============================================================================
// HTTP/2 BACKPRESSURE WATERMARKS (same pattern as HTTP/1.1)
// ============================================================================
// Design rationale:
//   - HTTP/1.1 uses 12MB HIGH / 4MB LOW for single stream
//   - HTTP/2 supports 100 concurrent streams (per SETTINGS_MAX_CONCURRENT_STREAMS)
//   - Scale limits accordingly: 50MB HIGH / 10MB LOW for multi-stream session
//   - Prevents OOM kills on AI/LLM workloads (100MB+ responses × 100 streams)
//
// Protection mechanism (identical to HTTP/1.1 cache-based backpressure):
//   1. total_response_buffer_size tracks all pending data_copy allocations
//   2. HIGH water (50MB) triggers backpressure → nghttp2 pauses backend reads
//   3. LOW water (10MB) releases backpressure → nghttp2 resumes backend reads
//   4. Client drains data naturally → total_response_buffer_size decreases
//
// Memory accounting:
//   - Each data_copy malloc(len) adds to total_response_buffer_size
//   - Each free(data_copy) subtracts from total_response_buffer_size
//   - Same pattern as HTTP/1.1's cache_total_size tracking
//
#define H2_SESSION_HIGH_WATER (50 * 1024 * 1024)  // 50MB - apply backpressure
#define H2_SESSION_LOW_WATER  (10 * 1024 * 1024)  // 10MB - resume reading

// ============================================================================
// PROMETHEUS METRICS - External global stats from sockproxy.c
// ============================================================================
// Declaration moved to sockproxy.h to avoid duplication

// ============================================================================
// Forward Declarations - External functions from sockproxy.c
// ============================================================================
int proxy_select_ep(proxy_fd_ent_t *pfe, void *inbuf, size_t insz, int *ep);
int proxy_setup_ep_connect(uint32_t epip, uint16_t epport, uint8_t protocol,
                            void *ssl_ctx, void **ssl, proxy_fd_ent_t *pfe,
                            const void *pp2hdr, int pp2len);
int is_endpoint_healthy(proxy_epval_t *tepval, int ep_idx);
int find_next_healthy_endpoint(proxy_epval_t *tepval, int start_idx);
int select_healthy_endpoint(proxy_epval_t *tepval, int algorithm_selection);
void circuit_breaker_record_failure(proxy_epval_t *tepval, int ep_index);
void circuit_breaker_record_success(proxy_epval_t *tepval, int ep_index);
#ifdef HAVE_DP_GPU_ROUTING
int chwbl_ring_lookup(chwbl_ring_t *ring, uint64_t hash);
uint64_t compute_prefix_hash(llm_prefix_key_t *key);
int extract_llm_prefix(const char *json_str, size_t json_len, llm_prefix_key_t *key);
#endif
conversation_mapping_t* get_conversation_mapping(proxy_map_ent_t *ent, const char *conv_id,
                                                 const proxy_epval_t *epv);
int store_conversation_endpoint(proxy_map_ent_t *ent, const char *conv_id, int ep_idx,
                                const proxy_epval_t *epv);

// ============================================================================
// Stream Management Helpers
// ============================================================================

/**
 * Find stream by ID in session's hash table
 */
static proxy_h2_stream_t*
find_stream(proxy_h2_session_t *session, int32_t stream_id)
{
  proxy_h2_stream_t *stream = NULL;
  
  if (!session || !session->streams) {
    return NULL;
  }
  
  HASH_FIND_INT(session->streams, &stream_id, stream);
  return stream;
}

/**
 * Create new stream and add to session
 */
static proxy_h2_stream_t*
create_stream(proxy_h2_session_t *session, int32_t stream_id)
{
  proxy_h2_stream_t *stream;
  
  if (!session) {
    log_error("[HTTP/2] create_stream: NULL session");
    return NULL;
  }
  
  // ============================================================================
  // STREAM BACKPRESSURE: Enforce max_concurrent_streams limit
  // Prevents DoS attacks from malicious/buggy clients ignoring SETTINGS
  // ============================================================================
  if (session->active_stream_count >= session->max_concurrent_streams) {
    log_error("[HTTP/2] Max concurrent streams (%d) reached, rejecting stream %d",
              session->max_concurrent_streams, stream_id);
    
    // Send RST_STREAM to client to reject the stream
    nghttp2_submit_rst_stream(session->session, NGHTTP2_FLAG_NONE,
                               stream_id, NGHTTP2_REFUSED_STREAM);
    nghttp2_session_send(session->session);
    
    return NULL;
  }
  
  // Allocate stream
  stream = calloc(1, sizeof(proxy_h2_stream_t));
  if (!stream) {
    log_error("[HTTP/2] Failed to allocate stream %d", stream_id);
    return NULL;
  }
  
  // Initialize fields
  stream->stream_id = stream_id;
  stream->state = H2_STREAM_IDLE;
  stream->backend_ep_idx = -1;
  stream->created_ts = time(NULL);
  stream->last_activity_ts = stream->created_ts;
  
  // Add to hash table
  HASH_ADD_INT(session->streams, stream_id, stream);
  session->active_stream_count++;

  // METRICS: Track HTTP/2 stream creation (TIER 1, Metric #4)
  atomic_fetch_add(&global_stats.h2_total_streams, 1);

  return stream;
}

/* ==========================================================================
 * AI settle twins — the H1 parser charges token usage at body-complete /
 * SSE [DONE] and releases orphaned admission claims at teardown
 * (sockproxy_http.c). HTTP/2 responses flow through the backend-session
 * callbacks instead, so the same three obligations live here, per stream:
 * a response-tail window for usage extraction, a settle at backend stream
 * close, and a claim release when a stream dies before it settled.
 * ========================================================================== */

/* Release a stream's pending AI-deny response body, if any. The stream owns
 * the buffer nghttp2 reads asynchronously (see proxy_h2_send_ai_deny), so this
 * is the one place it is freed — covering both the normal drain and a client
 * that resets the denied stream before the read callback reaches EOF. */
static void proxy_h2_free_deny_body(proxy_h2_stream_t *stream);
static void h2_resp_relay_free(proxy_h2_session_t *client_session,
                               h2_resp_relay_t *r);

/* Sliding response-tail window: the usage object rides the final bytes of
 * a JSON body or the final SSE chunk (stream_options.include_usage). */
static void
proxy_h2_stream_tail_update(proxy_h2_stream_t *stream,
                            const uint8_t *data, size_t len)
{
  size_t keep = sizeof(stream->usage_tail);

  if (len >= keep) {
    memcpy(stream->usage_tail, data + (len - keep), keep);
    stream->usage_tail_len = (uint16_t)keep;
    return;
  }
  if ((size_t)stream->usage_tail_len + len > keep) {
    size_t drop = (size_t)stream->usage_tail_len + len - keep;
    memmove(stream->usage_tail, stream->usage_tail + drop,
            stream->usage_tail_len - drop);
    stream->usage_tail_len -= (uint16_t)drop;
  }
  memcpy(stream->usage_tail + stream->usage_tail_len, data, len);
  stream->usage_tail_len += (uint16_t)len;
}

/* Extract prompt/completion tokens from a stream's response-tail window using
 * the STREAM's resolved-pool dialect. Pure C (no control-plane entry), so it
 * is safe under PROXY_LOCK — the teardown collector relies on that. The pool
 * pointer is read here, never after the lock is dropped: a concurrent rule
 * delete can free it the instant the lock is released.
 *
 * Returns 1 when a dialect actually read a usage object, 0 when none was
 * readable. The distinction is NOT recoverable from *up/*uc: a usage object
 * reporting zero tokens and no usage object at all both leave them 0, and
 * only the latter is the accounting hole loxilb_ai_tokens_missing_total
 * reports. This is the H2 equivalent of H1's usage_consumed flag. */
static int
proxy_h2_stream_extract_usage(proxy_fd_ent_t *pfe, proxy_h2_stream_t *stream,
                              int *up, int *uc)
{
  *up = 0;
  *uc = 0;
  if (!pfe || !stream || stream->usage_tail_len == 0)
    return 0;
  /* Same dialect resolution as the H1 proxy_usage_ops: P/D rules carry
   * their engine dialect on the epval; plain AI-gateway rules fall back
   * to the plain-LB profile. The pool is the STREAM's resolved pool —
   * pfe->epv is connection-scoped and holds whichever pool the LATEST
   * stream resolved, which on a multi-model connection is not this one. */
  proxy_epval_t *epv = stream->route_epv
                           ? (proxy_epval_t *)stream->route_epv
                           : (proxy_epval_t *)pfe->epv;
  const pd_dialect_ops_t *uops =
    (epv && epv->pd_ops) ? epv->pd_ops : &pd_dialect_plain;
  if (uops->extract_usage)
    return uops->extract_usage(pfe, stream->usage_tail,
                               stream->usage_tail_len, up, uc) == 0;
  return 0;
}

/* Settle an admitted stream: extract usage from the tail window, charge the
 * ladder (releasing the admission claim in the same call) and record the
 * request. result stays NULL on the consume call — a completed response is
 * never interrupted; an exceeded quota denies the NEXT request at the gate. */
static void
proxy_h2_settle_stream(proxy_h2_session_t *session, proxy_h2_stream_t *stream)
{
  proxy_fd_ent_t *pfe = session ? (proxy_fd_ent_t *)session->pfe : NULL;
  int up = 0, uc = 0;

  if (!stream || !(stream->ai_admitted || stream->ai_unmetered) ||
      stream->usage_consumed)
    return;
  stream->usage_consumed = 1;

  int usage_read = proxy_h2_stream_extract_usage(pfe, stream, &up, &uc);

  llb_ai_token_quota_consume(stream->tenant_id, stream->effective_model,
                             stream->auth_user_id, stream->auth_key_id,
                             stream->svc_ident, up, uc, 0,
                             (int)stream->usage_reserved_toks,
                             stream->usage_res_epoch, NULL);
  stream->usage_reserved_toks = 0;
  stream->usage_res_epoch = 0;

  int64_t latency_ms = 0;
  if (stream->admit_mono_ns) {
    uint64_t now = get_timestamp_ns();
    if (now > stream->admit_mono_ns)
      latency_ms = (int64_t)((now - stream->admit_mono_ns) / 1000000ULL);
  }
  /* A request record is emitted ONLY when the response actually progressed,
   * which here means a backend :status was captured for this stream. A
   * stream torn down before that — a client RST_STREAM mid-flight, a backend
   * that died before answering — releases its reservation and is charged
   * whatever arrived, but it never completed a response and must not be
   * counted as one.
   *
   * This is the same rule its three siblings already keep, and it is the
   * reason none of them carries a status fallback: the H1 non-SSE recorder
   * is gated on `metric_response_status != 0`, the H1 SSE recorder only runs
   * once headers have been seen, and the connection-teardown sweep over
   * these very streams emits its record under `if (e->status > 0)`. A
   * fabricated 200 here would add a phantom served request to
   * loxilb_ai_requests_total{outcome="completed"} and pull the served-latency
   * histogram toward the abort interval — precisely the distortion the
   * denial recorder keeps out of that histogram by design. */
  int status = stream->metric_response_status;
  if (status > 0) {
    llb_ai_record_request(stream->tenant_id, stream->effective_model, status,
                          latency_ms, up, uc, 0, 0, "");

    /* The same accounting hole the H1 paths report: this response was recorded
     * as completed and no dialect read a usage object out of it, so it was
     * charged nothing and — without this — reported nothing either. Gated on a
     * 2xx (see proxy_status_is_2xx). Inside the status guard for the same
     * reason the sweep keeps it there: a stream with no backend status never
     * completed a response, so it is a release, not an accounting hole.
     * Charges nothing, by decision and not by omission — the same settled
     * answer the H1 reporters carry. */
    if (!usage_read && proxy_status_is_2xx(status)) {
      /* H2_STREAM_CLOSE rather than RESPONSE_COMPLETE: destroy_stream runs the
       * same close for a response that finished and for one aborted after its
       * 2xx headers, and nghttp2's error code is not plumbed this far, so the
       * boundary is all this site can honestly claim. */
      llb_ai_record_usage_missing(stream->tenant_id, stream->effective_model,
                                  LLB_AI_UMISS_H2_STREAM_CLOSE);
      log_debug("[AI_TOKENS][HTTP/2] stream=%d response completed with no usage "
               "object tenant=%s model=%s reason=%s (reported, not charged)",
               stream->stream_id, stream->tenant_id, stream->effective_model,
               LLB_AI_UMISS_H2_STREAM_CLOSE);
    }
  }

  /* status=0 names the release-only settle explicitly, so the log says which
   * of the two shapes ran instead of leaving it to be inferred from a 200
   * that no backend ever sent. */
  log_debug("[AI_TOKENS][HTTP/2] stream=%d prompt=%d completion=%d status=%d",
           stream->stream_id, up, uc, status);
}

/* Collect the connection's un-settled admitted/keyless streams for a deferred
 * settle at teardown (see the header contract on h2_inflight_settle_t). Usage
 * is extracted here — under the caller's PROXY_LOCK, because the stream's pool
 * is only guaranteed alive while the lock is held — and the identity is copied
 * out so the caller can emit the control-plane charge/record after unlocking.
 * Each collected stream is marked settled so a later close cannot double it. */
int
proxy_h2_collect_inflight_settles(proxy_fd_ent_t *pfe,
                                   h2_inflight_settle_t **out)
{
  proxy_h2_session_t *sess = pfe ? pfe->h2_session : NULL;
  proxy_h2_stream_t *stream, *tmp;
  h2_inflight_settle_t *list;
  int cap, n = 0;

  *out = NULL;
  if (!sess || sess->active_stream_count <= 0)
    return 0;

  cap = sess->active_stream_count;
  list = calloc((size_t)cap, sizeof(*list));
  if (!list) {
    /* Never silently drop: the reservations these streams hold will strand
     * until the quota window rolls, which the operator should be able to see. */
    log_error("[AI_TOKENS][HTTP/2] teardown settle: OOM for %d stream(s) — "
              "their reservations will self-heal only at window roll", cap);
    return 0;
  }

  HASH_ITER(hh, sess->streams, stream, tmp) {
    int up = 0, uc = 0;
    h2_inflight_settle_t *e;

    if (!(stream->ai_admitted || stream->ai_unmetered) ||
        stream->usage_consumed)
      continue;
    if (n >= cap)   /* active_stream_count is authoritative; guard regardless */
      break;
    stream->usage_consumed = 1;

    int usage_read = proxy_h2_stream_extract_usage(pfe, stream, &up, &uc);

    e = &list[n++];
    /* Reported by the caller after PROXY_LOCK drops, like the charge: the
     * recorder crosses into the control plane. 2xx-gated here rather than at
     * the emit, so the decision is made once, beside the extraction it
     * depends on. */
    e->usage_missing = !usage_read &&
                       proxy_status_is_2xx(stream->metric_response_status);
    snprintf(e->tenant, sizeof(e->tenant), "%s", stream->tenant_id);
    snprintf(e->model, sizeof(e->model), "%s", stream->effective_model);
    snprintf(e->user, sizeof(e->user), "%s", stream->auth_user_id);
    snprintf(e->key, sizeof(e->key), "%s", stream->auth_key_id);
    snprintf(e->svc_ident, sizeof(e->svc_ident), "%s", stream->svc_ident);
    e->prompt_toks = up;
    e->complet_toks = uc;
    e->reserved_toks = (int)stream->usage_reserved_toks;
    e->res_epoch = stream->usage_res_epoch;
    e->status = stream->metric_response_status > 0
                    ? stream->metric_response_status : 0;
    e->latency_ms = 0;
    if (stream->admit_mono_ns) {
      uint64_t now = get_timestamp_ns();
      if (now > stream->admit_mono_ns)
        e->latency_ms = (int64_t)((now - stream->admit_mono_ns) / 1000000ULL);
    }
    stream->usage_reserved_toks = 0;
    stream->usage_res_epoch = 0;
  }

  if (n == 0) {
    free(list);
    return 0;
  }
  *out = list;
  return n;
}

/* Release a stream's memory and unlink it from the session. Pure C — no
 * control-plane entry — so it is safe with PROXY_LOCK held. Settling is the
 * CALLER's business: destroy_stream() settles first (nghttp2's stream-close
 * path), while the teardown path in proxy_h2_cleanup_session() must NOT,
 * because proxy_pdestroy has already collected those settles for deferred
 * emission and the charge call would re-enter the non-recursive lock. */
static void
h2_stream_free(proxy_h2_session_t *session, proxy_h2_stream_t *stream)
{
  if (!session || !stream) {
    return;
  }

  /* Release the AI-deny response body if the stream still owns one (a client
   * reset before nghttp2 drained it never reached the read callback's EOF). */
  proxy_h2_free_deny_body(stream);

  /* Release the backend response relay (queued chunks, stored trailers)
   * and return its unsent bytes to the session budget. nghttp2 runs the
   * relay provider only for open streams, so nothing reads it after this
   * point: the stream close callback runs once nghttp2 has detached the
   * DATA item, and proxy_h2_cleanup_session frees streams right before
   * deleting the session. */
  h2_resp_relay_free(session, &stream->resp);

  // Free data buffer if allocated
  if (stream->data_buf) {
    free(stream->data_buf);
    stream->data_buf = NULL;
  }

  // Free prefix_key if allocated
  if (stream->prefix_key) {
    free(stream->prefix_key);
    stream->prefix_key = NULL;
  }

  // Free request headers if allocated (pattern from backend response headers cleanup)
  if (stream->request_headers) {
    for (size_t i = 0; i < stream->request_headers_count; i++) {
      free((void *)stream->request_headers[i].name);
      free((void *)stream->request_headers[i].value);
    }
    free(stream->request_headers);
    stream->request_headers = NULL;
  }

  // Remove from hash table
  HASH_DEL(session->streams, stream);
  session->active_stream_count--;

  // Free stream structure
  free(stream);
}

/**
 * Destroy stream and remove from session
 */
static void
destroy_stream(proxy_h2_session_t *session, proxy_h2_stream_t *stream)
{
  if (!session || !stream) {
    return;
  }

  /* AI settle on teardown: the CLIENT stream is the settle unit and this
   * is the one close that always fires for it. The backend-side stream
   * close (proxy_h2_backend_on_stream_close_callback) also settles, but it
   * races the client close — nghttp2 destroys the client stream as soon as
   * the client's END_STREAM is acknowledged, which for a complete exchange
   * beats the backend close, and once find_stream() can no longer reach the
   * client stream the backend-side settle silently no-ops. Settling here
   * makes metering happen exactly once (usage_consumed guards the double)
   * for every admitted OR keyless stream, no matter which close wins:
   *   - a completed response has its usage in the tail window → charged;
   *   - a genuine abort has whatever arrived (usually nothing) charged and,
   *     for admitted streams, the admission reservation released — the same
   *     hand-back the previous abort-only block did, now never skipped. */
  proxy_h2_settle_stream(session, stream);

  h2_stream_free(session, stream);
}

/**
 * Append data to stream buffer (reallocate if needed)
 */
static int
append_stream_data(proxy_h2_stream_t *stream, const uint8_t *data, size_t len)
{
  if (!stream || !data || len == 0) {
    return -1;
  }
  
  // Check if reallocation needed
  size_t required = stream->data_len + len;
  if (required > stream->data_capacity) {
    // Grow buffer (double size or fit required, whichever is larger)
    size_t new_capacity = stream->data_capacity * 2;
    if (new_capacity < required) {
      new_capacity = required;
    }
    
    // Limit maximum buffer size to prevent memory exhaustion
    #define MAX_STREAM_DATA_SIZE (16 * 1024 * 1024)  // 16MB per stream
    if (new_capacity > MAX_STREAM_DATA_SIZE) {
      log_error("[HTTP/2] Stream %d buffer overflow (requested %zu bytes, max %d)",
                stream->stream_id, new_capacity, MAX_STREAM_DATA_SIZE);
      return -1;
    }
    
    uint8_t *new_buf = realloc(stream->data_buf, new_capacity);
    if (!new_buf) {
      log_error("[HTTP/2] Failed to reallocate stream %d buffer (%zu bytes)",
                stream->stream_id, new_capacity);
      return -1;
    }
    
    stream->data_buf = new_buf;
    stream->data_capacity = new_capacity;
  }
  
  // Append data
  memcpy(stream->data_buf + stream->data_len, data, len);
  stream->data_len += len;
  stream->last_activity_ts = time(NULL);
  
  return 0;
}

// ============================================================================
// nghttp2 Callbacks
// ============================================================================

/**
 * Called when a complete frame is received
 */
int
proxy_h2_on_frame_recv_callback(nghttp2_session *session,
                                 const nghttp2_frame *frame,
                                 void *user_data)
{
  proxy_fd_ent_t *pfe = (proxy_fd_ent_t *)user_data;
  
  if (!pfe || !pfe->h2_session) {
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  
  proxy_h2_session_t *h2_sess = pfe->h2_session;
  
  h2_sess->frames_recv++;
  
  switch (frame->hd.type) {
  case NGHTTP2_HEADERS:
    if (frame->hd.flags & NGHTTP2_FLAG_END_HEADERS) {
      proxy_h2_stream_t *stream = find_stream(h2_sess, frame->hd.stream_id);
      if (stream) {
        stream->headers_complete = 1;
        stream->state = H2_STREAM_OPEN;
      }
      /* (H2 parity): a complete HEADERS frame arrived — clear the connection-level
       * header-accumulation anchor so the tcp_inspect deadline (checked in the H2 client-data
       * branch of proxy_run) no longer fires once real request headers have been received. */
      pfe->l7_hdr_accum_start = 0;
      /* (H2 parity): arm the member-data idle baseline now that the request HEADERS are
       * complete and the request is about to be relayed to the member. Mirrors the H1 site in
       * sockproxy_http.c: the idle pass (sockproxy_health.c) only evaluates when last_activity>0, but
       * last_activity was historically set ONLY for sticky sessions, so a plain L7 FORWARD never armed
       * the timeoutMemberData deadline and a slow/blackhole member ran the full backend delay. Gated on
 * the SAME condition the idle pass uses (has_l7_policy + timeout_member_data_ms>0) so it is
 * a pure no-op for the AI peer / un-configured listeners. */
      {
        proxy_map_ent_t *l7ent = (proxy_map_ent_t *)pfe->head;
        if (l7ent && l7ent->has_l7_policy && l7ent->arg_ptr &&
            l7ent->arg_ptr->timeout_member_data_ms > 0 && pfe->last_activity == 0) {
          pfe->last_activity = time(NULL);
        }
      }
    }
    
    if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
      proxy_h2_stream_t *stream = find_stream(h2_sess, frame->hd.stream_id);
      if (stream) {
        stream->data_complete = 1;
        stream->state = H2_STREAM_HALF_CLOSED;
      }
    }
    break;
    
  case NGHTTP2_DATA:
    if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
      proxy_h2_stream_t *stream = find_stream(h2_sess, frame->hd.stream_id);
      if (stream) {
        stream->data_complete = 1;
        stream->state = H2_STREAM_HALF_CLOSED;
      }
    }
    break;
    
  case NGHTTP2_SETTINGS:
    break;
    
  case NGHTTP2_GOAWAY:
    log_warn("[HTTP/2] GOAWAY received: last_stream=%d, error=0x%x",
             frame->goaway.last_stream_id, frame->goaway.error_code);
    h2_sess->goaway_recv = 1;
    break;
    
  default:
    break;
  }
  
  return 0;
}

/**
 * Called when a header name-value pair is received
 */
int
proxy_h2_on_header_callback(nghttp2_session *session,
                             const nghttp2_frame *frame,
                             const uint8_t *name, size_t namelen,
                             const uint8_t *value, size_t valuelen,
                             uint8_t flags,
                             void *user_data)
{
  proxy_fd_ent_t *pfe = (proxy_fd_ent_t *)user_data;
  
  if (!pfe || !pfe->h2_session) {
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  
  proxy_h2_session_t *h2_sess = pfe->h2_session;
  
  // Only process HEADERS frames for request headers
  if (frame->hd.type != NGHTTP2_HEADERS) {
    return 0;
  }
  
  // Find or create stream
  proxy_h2_stream_t *stream = find_stream(h2_sess, frame->hd.stream_id);
  if (!stream) {
    stream = create_stream(h2_sess, frame->hd.stream_id);
    if (!stream) {
      log_error("[HTTP/2] Failed to create stream %d", frame->hd.stream_id);
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }
  
  // Parse header (store important ones for backward compatibility and quick access)
  #define HEADER_MATCHES(hdr) (namelen == strlen(hdr) && memcmp(name, hdr, namelen) == 0)

  if (HEADER_MATCHES(":method")) {
    snprintf(stream->method, sizeof(stream->method), "%.*s", (int)valuelen, value);
  } else if (HEADER_MATCHES(":path")) {
    snprintf(stream->path, sizeof(stream->path), "%.*s", (int)valuelen, value);
  } else if (HEADER_MATCHES(":authority")) {
    snprintf(stream->authority, sizeof(stream->authority), "%.*s", (int)valuelen, value);
  } else if (HEADER_MATCHES("content-type")) {
    snprintf(stream->content_type, sizeof(stream->content_type), "%.*s", (int)valuelen, value);
  } else if (HEADER_MATCHES("x-conversation-id")) {
    snprintf(stream->conversation_id, sizeof(stream->conversation_id), "%.*s", (int)valuelen, value);
    stream->has_conv_id = 1;
  } else if (HEADER_MATCHES("x-api-key")) {
    /* Credentials are stream state, never connection state: concurrent H2
     * streams may carry different tenants.  An oversized value is cleared so
     * a required policy treats it exactly like a missing credential. */
    ai_security_copy_api_key(stream->x_api_key_raw,
                             sizeof(stream->x_api_key_raw), value, valuelen);
  } else if (HEADER_MATCHES("authorization")) {
    /* The JWT arm's credential, stream state for the same reason as the
     * API key above. nghttp2 delivers the HPACK-decoded value whole, so no
     * fragment reassembly is needed here — but the H1 oversize contract is
     * kept: a value beyond the cap is dropped and flagged, so the JWT arm
     * refuses it as an invalid token instead of validating a prefix. */
    if (valuelen < sizeof(stream->bearer_raw)) {
      memcpy(stream->bearer_raw, value, valuelen);
      stream->bearer_raw[valuelen] = '\0';
      stream->bearer_oversize = 0;
    } else {
      stream->bearer_raw[0] = '\0';
      stream->bearer_oversize = 1;
    }
  } else if (HEADER_MATCHES("x-model")) {
    snprintf(stream->x_model_header, sizeof(stream->x_model_header),
             "%.*s", (int)valuelen, value);
  }

  // append into the bounded generic L7 header/cookie store on
  // the per-connection pfe — H1/H2 PARITY with handle_header_val. This
  // is the SAME store l7_policy_evaluate (Plan 03/04) reads, so HTTP/2 requests
  // match arbitrary HEADER/COOKIE conditions exactly like HTTP/1.1. nghttp2's
  // name/value are length-delimited (not NUL-terminated), so use the _n helper;
  // the store is bounded (overflow dropped). Distinct from stream->request_headers
  // below (that is the per-stream forward buffer; this is the per-connection
  // match-operand store consumed by the L7 engine).
  l7_store_header_n(pfe, (const char *)name, namelen,
                    (const char *)value, valuelen);

  // ============================================================================
  // GENERIC HEADER STORAGE: Store ALL headers for protocol transparency (gRPC)
  // Pattern mirrors backend response header collection (line 618-706)
  // ============================================================================

  // Allocate header storage if needed
  if (!stream->request_headers) {
    stream->request_headers_capacity = 16;  // Initial capacity
    stream->request_headers = calloc(stream->request_headers_capacity, sizeof(nghttp2_nv));
    if (!stream->request_headers) {
      log_error("[HTTP/2] Stream %d: Failed to allocate request header storage", frame->hd.stream_id);
      return NGHTTP2_ERR_NOMEM;
    }
    stream->request_headers_count = 0;
  }

  // Grow storage if needed
  if (stream->request_headers_count >= stream->request_headers_capacity) {
    size_t new_capacity = stream->request_headers_capacity * 2;
    nghttp2_nv *new_headers = realloc(stream->request_headers,
                                       new_capacity * sizeof(nghttp2_nv));
    if (!new_headers) {
      log_error("[HTTP/2] Stream %d: Failed to grow request header storage", frame->hd.stream_id);
      return NGHTTP2_ERR_NOMEM;
    }
    stream->request_headers = new_headers;
    stream->request_headers_capacity = new_capacity;
  }

  // Store header (copy name and value since nghttp2 may reuse buffers)
  nghttp2_nv *nv = &stream->request_headers[stream->request_headers_count];

  // Allocate and copy name
  nv->name = malloc(namelen);
  if (!nv->name) {
    return NGHTTP2_ERR_NOMEM;
  }
  memcpy(nv->name, name, namelen);
  nv->namelen = namelen;

  // Allocate and copy value
  nv->value = malloc(valuelen);
  if (!nv->value) {
    free((void *)nv->name);
    return NGHTTP2_ERR_NOMEM;
  }
  memcpy(nv->value, value, valuelen);
  nv->valuelen = valuelen;
  nv->flags = NGHTTP2_NV_FLAG_NONE;
  stream->request_headers_count++;
  
  return 0;
}

/**
 * Called when DATA chunk is received
 */
int
proxy_h2_on_data_chunk_recv_callback(nghttp2_session *session,
                                      uint8_t flags,
                                      int32_t stream_id,
                                      const uint8_t *data,
                                      size_t len,
                                      void *user_data)
{
  proxy_fd_ent_t *pfe = (proxy_fd_ent_t *)user_data;
  
  if (!pfe || !pfe->h2_session) {
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  
  proxy_h2_session_t *h2_sess = pfe->h2_session;
  
  // Find stream
  proxy_h2_stream_t *stream = find_stream(h2_sess, stream_id);
  if (!stream) {
    log_error("[HTTP/2] DATA chunk for non-existent stream %d", stream_id);
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  
  // Append data to stream buffer
  if (append_stream_data(stream, data, len) < 0) {
    log_error("[HTTP/2] Failed to append data to stream %d", stream_id);
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  
  h2_sess->data_recv += len;
  
  return 0;
}

/**
 * Called when stream is closed
 */
int
proxy_h2_on_stream_close_callback(nghttp2_session *session,
                                   int32_t stream_id,
                                   uint32_t error_code,
                                   void *user_data)
{
  proxy_fd_ent_t *pfe = (proxy_fd_ent_t *)user_data;
  
  if (!pfe || !pfe->h2_session) {
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  
  proxy_h2_session_t *h2_sess = pfe->h2_session;  
  
  // Find and destroy stream
  proxy_h2_stream_t *stream = find_stream(h2_sess, stream_id);
  if (stream) {
    stream->state = H2_STREAM_CLOSED;
    destroy_stream(h2_sess, stream);
  }
  
  return 0;
}

/**
 * Called when nghttp2 wants to send data
 */
ssize_t
proxy_h2_send_callback(nghttp2_session *session,
                        const uint8_t *data, size_t length,
                        int flags,
                        void *user_data)
{
  proxy_fd_ent_t *pfe = (proxy_fd_ent_t *)user_data;
  ssize_t rv;
  
  if (!pfe) {
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  
  if (pfe->ssl) {
    // Send via SSL
    rv = SSL_write(pfe->ssl, data, length);
    if (rv <= 0) {
      int ssl_err = SSL_get_error(pfe->ssl, rv);
      if (ssl_err == SSL_ERROR_WANT_WRITE || ssl_err == SSL_ERROR_WANT_READ) {
        return NGHTTP2_ERR_WOULDBLOCK;
      }
      
      // Handle streaming errors gracefully (critical for gRPC)
      if (ssl_err == SSL_ERROR_ZERO_RETURN) {
        // Peer closed connection cleanly during stream
        log_debug("[HTTP/2] SSL connection closed by peer during stream (fd=%d)", pfe->fd);
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
      
      if (ssl_err == SSL_ERROR_SYSCALL) {
        // Socket error - log errno for diagnosis
        if (errno == EPIPE || errno == ECONNRESET) {
          log_debug("[HTTP/2] SSL connection reset during stream (fd=%d, errno=%d: %s)", 
                    pfe->fd, errno, strerror(errno));
        } else {
          log_error("[HTTP/2] SSL_write SYSCALL error (fd=%d, errno=%d: %s)", 
                    pfe->fd, errno, strerror(errno));
        }
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
      
      log_error("[HTTP/2] SSL_write failed: %d (fd=%d)", ssl_err, pfe->fd);
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  } else {
    // Send via plain TCP
    rv = send(pfe->fd, data, length, MSG_NOSIGNAL);
    if (rv < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return NGHTTP2_ERR_WOULDBLOCK;
      }
      log_error("[HTTP/2] send failed: %s", strerror(errno));
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }
  
  if (pfe->h2_session) {
    pfe->h2_session->frames_sent++;
    pfe->h2_session->data_sent += rv;
  }

  // Update statistics counters (transmit direction)
  pfe_ent_accouting(pfe, rv, 1);

  return rv;
}

/**
 * Called when nghttp2 wants to receive data
 */
ssize_t
proxy_h2_recv_callback(nghttp2_session *session,
                        uint8_t *buf, size_t length,
                        int flags,
                        void *user_data)
{
  proxy_fd_ent_t *pfe = (proxy_fd_ent_t *)user_data;
  ssize_t rv;
  
  if (!pfe) {
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  
  if (pfe->ssl) {
    rv = SSL_read(pfe->ssl, buf, length);
    if (rv <= 0) {
      int ssl_err = SSL_get_error(pfe->ssl, rv);
      if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
        return NGHTTP2_ERR_WOULDBLOCK;
      }
      
      // Handle streaming errors gracefully (critical for gRPC)
      if (ssl_err == SSL_ERROR_ZERO_RETURN) {
        // Peer closed connection cleanly during stream
        log_debug("[HTTP/2] SSL connection closed by peer during receive (fd=%d)", pfe->fd);
        return 0;  // Return 0 to signal EOF to nghttp2
      }
      
      if (ssl_err == SSL_ERROR_SYSCALL) {
        // Socket error - log errno for diagnosis
        if (rv == 0) {
          // EOF without close_notify (common in gRPC)
          log_debug("[HTTP/2] SSL connection closed abruptly (fd=%d)", pfe->fd);
          return 0;  // Return 0 to signal EOF
        }
        if (errno == EPIPE || errno == ECONNRESET) {
          log_debug("[HTTP/2] SSL connection reset during receive (fd=%d, errno=%d: %s)", 
                    pfe->fd, errno, strerror(errno));
        } else {
          log_error("[HTTP/2] SSL_read SYSCALL error (fd=%d, errno=%d: %s)", 
                    pfe->fd, errno, strerror(errno));
        }
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
      
      log_error("[HTTP/2] SSL_read failed: %d (fd=%d)", ssl_err, pfe->fd);
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  } else {
    rv = recv(pfe->fd, buf, length, 0);
    if (rv < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return NGHTTP2_ERR_WOULDBLOCK;
      }
      log_error("[HTTP/2] recv failed: %s", strerror(errno));
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }

  if (rv == 0) {
    return NGHTTP2_ERR_EOF;
  }

  return rv;
}

// ============================================================================
// Backend HTTP/2 Session Management (Transit Mode)
// ============================================================================

/* ==========================================================================
 * Backend -> client response relay (h2_resp_relay_t, sockproxy_h2.h)
 *
 * One data provider per client stream drains a chunk queue filled by the
 * backend DATA callback. The provider is submitted once with END_STREAM,
 * resumed as chunks arrive, and defers while the queue is empty. Once the
 * backend's END_STREAM has been seen and the queue is drained it sets EOF,
 * which ends the stream, or EOF with NO_END_STREAM plus
 * nghttp2_submit_trailer when the backend sent trailers.
 *
 * Why not one nghttp2_submit_data per chunk (the previous design): nghttp2
 * keeps one DATA item per stream and refuses a second with
 * NGHTTP2_ERR_DATA_EXIST until the first reaches EOF, so a chunk that
 * arrived while the client's window was closed failed the callback. Its
 * END_STREAM also never reached the client, because every provider ended
 * at EOF without END_STREAM and an empty END_STREAM DATA frame was never
 * relayed. Trailers submitted with nghttp2_submit_headers could go out
 * before still-pending DATA, since nghttp2 sends HEADERS ahead of DATA.
 * ========================================================================== */

static void
h2_resp_nv_free(nghttp2_nv *nv, size_t count)
{
  if (!nv) {
    return;
  }
  for (size_t i = 0; i < count; i++) {
    free(nv[i].name);
    free(nv[i].value);
  }
  free(nv);
}

/* Free the collected header fields of the HEADERS frame just handled. The
 * header callback appends to this array, so it must be emptied after each
 * frame, or the next frame (a final response after a 1xx, or the trailers)
 * would be relayed with the previous frame's fields prepended. */
static void
h2_mapping_clear_resp_headers(stream_mapping_t *mapping)
{
  if (!mapping->response_headers) {
    return;
  }
  for (size_t i = 0; i < mapping->response_headers_count; i++) {
    free(mapping->response_headers[i].name);
    free(mapping->response_headers[i].value);
  }
  mapping->response_headers_count = 0;
}

static void
h2_resp_account_release(proxy_h2_session_t *client_session, size_t n)
{
  if (client_session->total_response_buffer_size > n) {
    client_session->total_response_buffer_size -= n;
  } else {
    client_session->total_response_buffer_size = 0;
  }
}

/* Release consumed bytes from the session budget and, at the LOW water
 * mark, lift backpressure (same logic as HTTP/1.1's
 * proxy_check_release_backpressure). The backend stream feeding this client
 * stream is looked up by id rather than kept as a pointer, so a backend
 * session torn down in the meantime is never touched. */
static void
h2_resp_release(proxy_h2_session_t *client_session, int32_t client_stream_id,
                size_t n)
{
  h2_resp_account_release(client_session, n);

  if (!client_session->backpressure_active ||
      client_session->total_response_buffer_size > H2_SESSION_LOW_WATER) {
    return;
  }

  client_session->backpressure_active = 0;
  log_warn("🟢 HTTP/2 session LOW water mark reached (size=%zu/%d MB), RELEASING BACKPRESSURE",
           client_session->total_response_buffer_size, H2_SESSION_LOW_WATER/(1024*1024));

  backend_h2_session_t *backend_session, *btmp;
  HASH_ITER(hh, client_session->backend_sessions, backend_session, btmp) {
    stream_mapping_t *mapping = NULL;
    HASH_FIND_INT(backend_session->stream_map, &client_stream_id, mapping);
    if (!mapping || !backend_session->session) {
      continue;
    }
    int rv = nghttp2_session_resume_data(backend_session->session,
                                         mapping->backend_stream_id);
    if (rv == 0) {
      log_debug("✓ Resumed backend stream %d after backpressure release",
                mapping->backend_stream_id);
    } else {
      log_warn("Failed to resume backend stream %d: %s",
               mapping->backend_stream_id, nghttp2_strerror(rv));
    }
    break;
  }
}

/* Drop everything a relay holds and hand its unsent bytes back to the
 * session budget. Idempotent; safe on a zeroed relay. Called when the client
 * stream is freed, which is the only point after which nghttp2 can no longer
 * run the provider. */
static void
h2_resp_relay_free(proxy_h2_session_t *client_session, h2_resp_relay_t *r)
{
  h2_resp_chunk_t *c = r->head;
  while (c) {
    h2_resp_chunk_t *next = c->next;
    free(c);
    c = next;
  }
  r->head = NULL;
  r->tail = NULL;
  if (client_session && r->queued_bytes) {
    h2_resp_account_release(client_session, r->queued_bytes);
    /* No backend resume here: this runs on stream close or session
     * teardown, and the next chunk callback re-checks the watermark. */
    if (client_session->backpressure_active &&
        client_session->total_response_buffer_size <= H2_SESSION_LOW_WATER) {
      client_session->backpressure_active = 0;
    }
  }
  r->queued_bytes = 0;
  h2_resp_nv_free(r->trailers, r->trailers_count);
  r->trailers = NULL;
  r->trailers_count = 0;
  r->trailers_capacity = 0;
  r->trailer_pending = 0;
  r->data_provider_active = 0;
}

/* Reset the client stream once; the stream close that follows frees the
 * relay. */
static void
h2_resp_relay_reset(proxy_h2_session_t *client_session,
                    proxy_h2_stream_t *stream, uint32_t error_code)
{
  if (stream->resp.reset_submitted || stream->resp.eos_sent) {
    return;
  }
  nghttp2_submit_rst_stream(client_session->session, NGHTTP2_FLAG_NONE,
                            stream->stream_id, error_code);
  stream->resp.reset_submitted = 1;
}

/**
 * Data provider read callback for the backend -> client response body.
 */
static ssize_t
h2_resp_relay_read_callback(nghttp2_session *session, int32_t stream_id,
                            uint8_t *buf, size_t length, uint32_t *data_flags,
                            nghttp2_data_source *source, void *user_data)
{
  proxy_fd_ent_t *pfe = (proxy_fd_ent_t *)user_data;
  proxy_h2_session_t *client_session = pfe ? pfe->h2_session : NULL;
  proxy_h2_stream_t *stream =
    client_session ? find_stream(client_session, stream_id) : NULL;

  (void)source;

  if (!stream) {
    /* nghttp2 reads only open streams and the relay is freed with the
     * stream, so the two stream tables disagree. Reset the stream rather
     * than end it as if the body were complete. */
    log_error("[HTTP/2] stream %d: response relay has no stream", stream_id);
    return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
  }

  h2_resp_relay_t *r = &stream->resp;
  size_t copied = 0;

  while (copied < length && r->head) {
    h2_resp_chunk_t *c = r->head;
    size_t avail = c->len - c->off;
    size_t n = (avail < length - copied) ? avail : length - copied;

    memcpy(buf + copied, c->data + c->off, n);
    c->off += n;
    copied += n;
    if (c->off == c->len) {
      r->head = c->next;
      if (!r->head) {
        r->tail = NULL;
      }
      free(c);
    }
  }

  if (copied > 0) {
    r->queued_bytes -= copied;
    h2_resp_release(client_session, stream_id, copied);
  }

  if (r->head) {
    return (ssize_t)copied;          // more queued than this frame can carry
  }
  if (!r->eos_pending) {
    /* Queue drained, body not finished: wait for the next backend chunk,
     * which resumes this provider. */
    return copied ? (ssize_t)copied : NGHTTP2_ERR_DEFERRED;
  }

  /* Backend END_STREAM seen and everything relayed. The provider was
   * submitted with END_STREAM, so EOF alone ends the stream. */
  *data_flags |= NGHTTP2_DATA_FLAG_EOF;
  r->data_provider_active = 0;
  r->eos_sent = 1;

  if (r->trailer_pending) {
    /* Trailers must follow the last DATA: end the provider without
     * END_STREAM and submit them from inside this callback, as nghttp2
     * documents. nghttp2 copies the fields, so free ours now. */
    *data_flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
    int rv = nghttp2_submit_trailer(session, stream_id, r->trailers,
                                    r->trailers_count);
    h2_resp_nv_free(r->trailers, r->trailers_count);
    r->trailers = NULL;
    r->trailers_count = 0;
    r->trailers_capacity = 0;
    r->trailer_pending = 0;
    if (rv != 0) {
      log_error("[HTTP/2] stream %d: nghttp2_submit_trailer failed: %s",
                stream_id, nghttp2_strerror(rv));
      /* Without its trailers the stream can never end cleanly; this return
       * makes nghttp2 reset it. */
      r->reset_submitted = 1;
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
  }

  return (ssize_t)copied;
}

/* Make the provider run: submit it once, or resume it if it is deferred.
 * Returns 0, or a fatal nghttp2 error for the caller to propagate. */
static int
h2_resp_relay_kick(proxy_h2_session_t *client_session, proxy_h2_stream_t *stream)
{
  h2_resp_relay_t *r = &stream->resp;
  int rv;

  if (r->eos_sent || r->reset_submitted) {
    return 0;
  }

  if (r->data_provider_active) {
    rv = nghttp2_session_resume_data(client_session->session, stream->stream_id);
    /* NGHTTP2_ERR_INVALID_ARGUMENT only means the provider is not deferred
     * by us: it is still queued, or waiting for the client's window, and
     * will read the new chunk when it runs. */
    return nghttp2_is_fatal(rv) ? rv : 0;
  }

  nghttp2_data_provider data_prd;
  data_prd.source.ptr = NULL;        // the callback looks the stream up by id
  data_prd.read_callback = h2_resp_relay_read_callback;

  rv = nghttp2_submit_data(client_session->session, NGHTTP2_FLAG_END_STREAM,
                           stream->stream_id, &data_prd);
  if (rv != 0) {
    log_error("[HTTP/2] stream %d: nghttp2_submit_data failed: %s",
              stream->stream_id, nghttp2_strerror(rv));
    if (nghttp2_is_fatal(rv)) {
      return rv;
    }
    h2_resp_relay_reset(client_session, stream, NGHTTP2_INTERNAL_ERROR);
    return 0;
  }
  r->data_provider_active = 1;
  return 0;
}

/**
 * Backend header callback - collect headers from backend response
 * This is CRITICAL because nghttp2_session_mem_recv doesn't populate frame->headers.nva
 *
 * IMPORTANT: When using nghttp2_session_mem_recv(), the frame->headers.nva array
 * is NOT populated in the frame_recv callback. Instead, headers MUST be collected
 * in the header callback and stored for later use when forwarding to client.
 */
static int
proxy_h2_backend_on_header_callback(nghttp2_session *session,
                                      const nghttp2_frame *frame,
                                      const uint8_t *name, size_t namelen,
                                      const uint8_t *value, size_t valuelen,
                                      uint8_t flags,
                                      void *user_data)
{
  backend_h2_session_t *backend_session = (backend_h2_session_t *)user_data;

  if (!backend_session) {
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  // Only collect headers for HEADERS frames
  if (frame->hd.type != NGHTTP2_HEADERS) {
    return 0;
  }

  // Find stream mapping to store headers
  stream_mapping_t *mapping = NULL;
  stream_mapping_t *tmp;
  HASH_ITER(hh, backend_session->stream_map, mapping, tmp) {
    if (mapping->backend_stream_id == frame->hd.stream_id) {
      break;
    }
  }

  if (!mapping) {
    log_warn("[HTTP/2 Backend] ep[%d]: Header for unknown stream %d",
             backend_session->ep_idx, frame->hd.stream_id);
    return 0;
  }

  /* AI settle: capture the backend :status for the request record — the
   * same role the H1 response status-line capture plays. */
  if (namelen == 7 && memcmp(name, ":status", 7) == 0 &&
      backend_session->client_session) {
    proxy_h2_stream_t *ai_stream =
      find_stream(backend_session->client_session, mapping->client_stream_id);
    if (ai_stream && (ai_stream->ai_admitted || ai_stream->ai_unmetered) &&
        valuelen > 0 && valuelen < 4) {
      char st[4] = {0};
      memcpy(st, value, valuelen);
      ai_stream->metric_response_status = atoi(st);
    }
  }

  // Allocate header storage if needed
  if (!mapping->response_headers) {
    mapping->response_headers_capacity = 16;  // Initial capacity
    mapping->response_headers = calloc(mapping->response_headers_capacity, sizeof(nghttp2_nv));
    if (!mapping->response_headers) {
      log_error("[HTTP/2 Backend] ep[%d]: Failed to allocate header storage",
                backend_session->ep_idx);
      return NGHTTP2_ERR_NOMEM;
    }
    mapping->response_headers_count = 0;
  }

  // Grow storage if needed
  if (mapping->response_headers_count >= mapping->response_headers_capacity) {
    size_t new_capacity = mapping->response_headers_capacity * 2;
    nghttp2_nv *new_headers = realloc(mapping->response_headers,
                                       new_capacity * sizeof(nghttp2_nv));
    if (!new_headers) {
      log_error("[HTTP/2 Backend] ep[%d]: Failed to grow header storage",
                backend_session->ep_idx);
      return NGHTTP2_ERR_NOMEM;
    }
    mapping->response_headers = new_headers;
    mapping->response_headers_capacity = new_capacity;
  }

  // Store header (copy name and value since nghttp2 may reuse buffers)
  nghttp2_nv *nv = &mapping->response_headers[mapping->response_headers_count];

  // Allocate and copy name
  nv->name = malloc(namelen);
  if (!nv->name) {
    return NGHTTP2_ERR_NOMEM;
  }
  memcpy(nv->name, name, namelen);
  nv->namelen = namelen;

  // Allocate and copy value
  nv->value = malloc(valuelen);
  if (!nv->value) {
    free((void *)nv->name);
    return NGHTTP2_ERR_NOMEM;
  }
  memcpy(nv->value, value, valuelen);
  nv->valuelen = valuelen;

  nv->flags = NGHTTP2_NV_FLAG_NONE;

  mapping->response_headers_count++;

  return 0;
}

/**
 * Backend frame receive callback
 * Forwards HTTP/2 frames from backend to client
 */
static int
proxy_h2_backend_on_frame_recv_callback(nghttp2_session *session,
                                         const nghttp2_frame *frame,
                                         void *user_data)
{
  backend_h2_session_t *backend_session = (backend_h2_session_t *)user_data;
  
  if (!backend_session || !backend_session->client_session) {
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  
  proxy_h2_session_t *client_session = backend_session->client_session;
  
  backend_session->frames_recv++;
  
  // Find stream mapping (backend_stream_id → client_stream_id)
  stream_mapping_t *mapping = NULL;
  stream_mapping_t *tmp;
  HASH_ITER(hh, backend_session->stream_map, mapping, tmp) {
    if (mapping->backend_stream_id == frame->hd.stream_id) {
      break;
    }
  }
  
  if (!mapping) {
    return 0;
  }
  
  int32_t client_stream_id = mapping->client_stream_id;
  
  // Forward frame to client based on type
  switch (frame->hd.type) {
  case NGHTTP2_HEADERS: {
    // ============================================================================
    // CRITICAL FIX: Use collected headers from header callback, NOT frame->headers.nva
    // ============================================================================
    // When using nghttp2_session_mem_recv(), frame->headers.nva is NOT populated.
    // Headers are only available during the header callback execution.
    // We MUST use the headers collected in mapping->response_headers.
    //
    // A backend (client-mode) session reports only the first HEADERS as
    // NGHTTP2_HCAT_RESPONSE; a later 1xx, the final response and the
    // trailers all arrive as NGHTTP2_HCAT_HEADERS. So classify by :status
    // and by whether the final response has already been relayed. nghttp2's
    // HTTP messaging checks (on by default) reject any other sequence before
    // this callback runs.
    size_t nhdrs = mapping->response_headers ? mapping->response_headers_count : 0;
    int end_stream = (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0;
    proxy_h2_stream_t *cstream = find_stream(client_session, client_stream_id);
    const nghttp2_nv *status_nv = NULL;
    int rv;

    for (size_t i = 0; i < nhdrs; i++) {
      if (mapping->response_headers[i].namelen == 7 &&
          memcmp(mapping->response_headers[i].name, ":status", 7) == 0) {
        status_nv = &mapping->response_headers[i];
        break;
      }
    }

    if (!cstream) {
      /* The client reset the stream: nothing to relay to. */
      log_debug("[HTTP/2 Backend] ep[%d]: HEADERS for closed client stream %d dropped",
                backend_session->ep_idx, client_stream_id);
      h2_mapping_clear_resp_headers(mapping);
      break;
    }

    h2_resp_relay_t *relay = &cstream->resp;

    if (!status_nv && relay->final_headers_sent) {
      /* Trailers. Not submitted here: nghttp2 sends HEADERS ahead of any
       * DATA still pending for the client, so they could overtake the body.
       * Hand the fields to the relay, which submits them after the last
       * DATA. Trailers always carry END_STREAM (nghttp2 enforces it); an
       * empty trailer block just ends the body. */
      if (!end_stream) {
        log_warn("[HTTP/2 Backend] ep[%d]: trailers without END_STREAM on stream %d",
                 backend_session->ep_idx, frame->hd.stream_id);
      }
      if (nhdrs > 0 && !relay->eos_sent && !relay->reset_submitted) {
        h2_resp_nv_free(relay->trailers, relay->trailers_count);
        relay->trailers = mapping->response_headers;
        relay->trailers_count = mapping->response_headers_count;
        relay->trailers_capacity = mapping->response_headers_capacity;
        relay->trailer_pending = 1;
        mapping->response_headers = NULL;
        mapping->response_headers_count = 0;
        mapping->response_headers_capacity = 0;
      }
      h2_mapping_clear_resp_headers(mapping);
      relay->eos_pending = 1;
      rv = h2_resp_relay_kick(client_session, cstream);
      if (rv != 0) {
        return rv;
      }
      nghttp2_session_send(client_session->session);
      break;
    }

    if (!status_nv || relay->final_headers_sent) {
      log_error("[HTTP/2 Backend] ep[%d]: unexpected HEADERS on stream %d "
                "(fields=%zu status=%s final_sent=%d)",
                backend_session->ep_idx, frame->hd.stream_id, nhdrs,
                status_nv ? "yes" : "no", relay->final_headers_sent);
      h2_mapping_clear_resp_headers(mapping);
      h2_resp_relay_reset(client_session, cstream, NGHTTP2_PROTOCOL_ERROR);
      nghttp2_session_send(client_session->session);
      break;
    }

    if (status_nv->valuelen == 3 && status_nv->value[0] == '1') {
      /* Non-final (1xx, e.g. 100 Continue, 103 Early Hints): relay as is.
       * The final response follows, so the stream stays open and the
       * response header injection below waits for it. */
      rv = nghttp2_submit_headers(client_session->session, NGHTTP2_FLAG_NONE,
                                  client_stream_id, NULL,
                                  mapping->response_headers,
                                  mapping->response_headers_count, NULL);
      if (rv != 0) {
        log_error("[HTTP/2 Backend] ep[%d]: nghttp2_submit_headers (1xx) failed: %s",
                  backend_session->ep_idx, nghttp2_strerror(rv));
      }
      h2_mapping_clear_resp_headers(mapping);
      nghttp2_session_send(client_session->session);
      break;
    }

    /* Final response. */

    // on the L7_Proxy peer only ( gate),
    // inject a stateless HTTP_COOKIE Set-Cookie into the relayed HEADERS frame
    // BEFORE submit — via the NON-TERMINAL seam proven by an earlier cycle's test_pd C-unit.
    // We append to the SAME mapping->response_headers[] the relay submits below
    // and touch no frame flag, so the backend's END_STREAM bit (computed just
    // below from frame->hd.flags) and the body DATA frames are unaffected
    // (parity with the H1 \r\n\r\n splice). nghttp2_nv only — never raw bytes
    // (75-LEARNINGS §🟠.2 / defect 097c8dba). has_l7_policy==0 (AI/transit) is
    // byte-for-byte unchanged. Pure no-op unless the matched route's
    // cookie_persist is set. Nothing stored on proxy_fd_ent: the token IS
    // the binding, so affinity survives HA failover.
    if (client_session->pfe) {
      proxy_fd_ent_t *client_pfe = (proxy_fd_ent_t *)client_session->pfe;
      proxy_map_ent_t *node = (proxy_map_ent_t *)client_pfe->head;
      if (node && node->has_l7_policy &&
          l7_cookie_persist_active(client_pfe, node)) {
        /* The pool must be the one THIS backend session belongs to —
         * client_pfe->epv is connection-scoped and a concurrent stream
         * routed through another pool may have overwritten it. */
        proxy_epval_t *tepval = (proxy_epval_t *)backend_session->epv;
        int ep_idx = backend_session->ep_idx;   /* the backend this stream uses */
        char token[LB_COOKIE_TOKEN_MAX];
        if (tepval && ep_idx >= 0 && ep_idx < tepval->n_eps &&
            l7_cookie_node_token_for_ep(node, tepval, ep_idx, token,
                                        sizeof(token)) > 0) {
          /* Build "<name>=<token>; Path=/; HttpOnly[; Secure]". HTTPS iff
           * the client connection is TLS. nghttp2 deep-copies on submit; the
           * relay's per-mapping cleanup frees the injected nv uniformly. */
          int is_ssl = (client_pfe->ssl != NULL || client_pfe->ktls_enabled);
          char cookie_val[L7_HDR_VALUE_MAX];
          int cn = snprintf(cookie_val, sizeof(cookie_val),
                            "%s=%s; Path=/; HttpOnly%s",
                            LB_COOKIE_NAME, token, is_ssl ? "; Secure" : "");
          if (cn > 0 && (size_t)cn < sizeof(cookie_val)) {
            nghttp2_nv sc = {
              .name = (uint8_t *)"set-cookie",
              .value = (uint8_t *)cookie_val,
              .namelen = 10,
              .valuelen = (size_t)cn,
              .flags = NGHTTP2_NV_FLAG_NONE,
            };
            proxy_h2_inject_resp_headers(mapping, &sc, 1);
          }
        }
      }
    }

    // (RFC 6797): HSTS response injection on the H2
    // leg. Build the SAME synthesized Strict-Transport-Security value as the H1
    // seam (l7_hsts_synthesize — one synthesizer, two emit seams) into
    // an nghttp2_nv with the LOWERCASE name "strict-transport-security" (HTTP/2
    // header rule) and inject it via the NON-TERMINAL proxy_h2_inject_resp_headers
    // (Plan ) — appends into mapping->response_headers[] BEFORE the submit
    // below, so END_STREAM and the body DATA frames are untouched. NEVER raw \r\n
    // on an H2 socket (defect 097c8dba) and NEVER nghttp2_submit_response(...NULL)
    // (terminal). SAME triple gate as H1: have_ssl && has_l7_policy &&
    // hsts_max_age>0. has_l7_policy==0 (AI/transit) is byte-for-byte
    // unchanged; a plain-HTTP listener (have_ssl==0) skips + logs (RFC 6797).
    if (client_session->pfe) {
      proxy_fd_ent_t *client_pfe = (proxy_fd_ent_t *)client_session->pfe;
      proxy_map_ent_t *node = (proxy_map_ent_t *)client_pfe->head;
      if (node && node->has_l7_policy &&
          node->arg_ptr && node->arg_ptr->hsts_max_age > 0) {
        if (!node->val.have_ssl) {
          log_debug("[HSTS][H2] skip: plain-HTTP listener (have_ssl=0), "
                    "HSTS not injected (RFC 6797)");
        } else {
          char hsts_val[L7_HDR_VALUE_MAX];
          size_t hvlen = l7_hsts_synthesize(node->arg_ptr->hsts_max_age,
                                            node->arg_ptr->hsts_include_subdomains,
                                            node->arg_ptr->hsts_preload,
                                            hsts_val, sizeof(hsts_val));
          if (hvlen > 0 && l7_hdr_value_valid(hsts_val)) {
            nghttp2_nv hsts = {
              .name = (uint8_t *)"strict-transport-security",
              .value = (uint8_t *)hsts_val,
              .namelen = 25,
              .valuelen = hvlen,
              .flags = NGHTTP2_NV_FLAG_NONE,
            };
            proxy_h2_inject_resp_headers(mapping, &hsts, 1);
          }
        }
      }
    }

    // Forward collected headers to client, preserving END_STREAM from the
    // backend: a response without a body (204, HEAD, a gRPC trailers-only
    // response) ends here. A body is relayed by the response relay, and
    // trailers are handled above.
    uint8_t flags = end_stream ? NGHTTP2_FLAG_END_STREAM : NGHTTP2_FLAG_NONE;

    rv = nghttp2_submit_headers(client_session->session,
                                flags,  // Preserve END_STREAM from backend
                                client_stream_id,
                                NULL,  // No priority
                                mapping->response_headers,      // Use COLLECTED headers
                                mapping->response_headers_count, // Use COLLECTED count
                                NULL);  // No stream user data

    h2_mapping_clear_resp_headers(mapping);

    if (rv != 0) {
      log_error("[HTTP/2 Backend] ep[%d]: nghttp2_submit_headers failed: %s",
                backend_session->ep_idx, nghttp2_strerror(rv));
      h2_resp_relay_reset(client_session, cstream, NGHTTP2_INTERNAL_ERROR);
    } else {
      relay->final_headers_sent = 1;
      if (end_stream) {
        relay->eos_pending = 1;
        relay->eos_sent = 1;
      }
    }

    // Trigger immediate send to client
    nghttp2_session_send(client_session->session);

    break;
  }
  
  case NGHTTP2_DATA:
    // DATA payload is queued by the data_chunk callback. END_STREAM arrives
    // here, including on an empty DATA frame, which never reaches the chunk
    // callback: mark the body complete and let the relay end the stream
    // once the queue drains (submitting an empty provider if no chunk ever
    // came).
    if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
      proxy_h2_stream_t *cstream = find_stream(client_session, client_stream_id);
      if (cstream && !cstream->resp.eos_sent && !cstream->resp.reset_submitted) {
        cstream->resp.eos_pending = 1;
        int rv = h2_resp_relay_kick(client_session, cstream);
        if (rv != 0) {
          return rv;
        }
        nghttp2_session_send(client_session->session);
      }
    }
    break;
    
  case NGHTTP2_RST_STREAM: {
    // Forward stream reset to client
    proxy_h2_stream_t *cstream = find_stream(client_session, client_stream_id);
    if (cstream) {
      cstream->resp.reset_submitted = 1;
    }
    nghttp2_submit_rst_stream(client_session->session, NGHTTP2_FLAG_NONE,
                               client_stream_id, frame->rst_stream.error_code);
    break;
  }
    
  case NGHTTP2_GOAWAY:
    log_warn("[HTTP/2 Backend] ep[%d]: GOAWAY received: last_stream=%d, error=0x%x",
             backend_session->ep_idx, frame->goaway.last_stream_id, frame->goaway.error_code);
    backend_session->goaway_received = 1;
    break;
    
  default:
    break;
  }
  
  return 0;
}

/**
 * Backend data chunk receive callback
 * Forwards DATA frames from backend to client
 */
static int
proxy_h2_backend_on_data_chunk_recv_callback(nghttp2_session *session,
                                               uint8_t flags,
                                               int32_t stream_id,
                                               const uint8_t *data,
                                               size_t len,
                                               void *user_data)
{
  backend_h2_session_t *backend_session = (backend_h2_session_t *)user_data;
  
  if (!backend_session || !backend_session->client_session) {
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  
  proxy_h2_session_t *client_session = backend_session->client_session;
  
  // Find stream mapping
  stream_mapping_t *mapping = NULL;
  stream_mapping_t *tmp;
  HASH_ITER(hh, backend_session->stream_map, mapping, tmp) {
    if (mapping->backend_stream_id == stream_id) {
      break;
    }
  }
  
  if (!mapping) {
    log_warn("[HTTP/2 Backend] ep[%d]: DATA chunk for unknown stream %d",
             backend_session->ep_idx, stream_id);
    return 0;
  }
  
  int32_t client_stream_id = mapping->client_stream_id;

  proxy_h2_stream_t *cstream = find_stream(client_session, client_stream_id);

  (void)flags;  // END_STREAM is seen in the frame recv callback, not here

  /* AI settle: maintain the response-tail window for admitted streams —
   * the usage object rides the final bytes (JSON body or final SSE chunk),
   * exactly what the H1 proxy_usage_tail_update keeps. */
  if (len > 0 && cstream &&
      (cstream->ai_admitted || cstream->ai_unmetered) &&
      !cstream->usage_consumed)
    proxy_h2_stream_tail_update(cstream, data, len);

  if (!cstream) {
    /* The client reset the stream: nothing to relay to. Drop the chunk
     * instead of failing the whole connection. */
    log_debug("[HTTP/2 Backend] ep[%d]: DATA for closed client stream %d dropped",
              backend_session->ep_idx, client_stream_id);
    return 0;
  }

  h2_resp_relay_t *relay = &cstream->resp;
  if (len == 0 || relay->eos_sent || relay->reset_submitted) {
    return 0;
  }

  // ============================================================================
  // HTTP/2 BACKPRESSURE: Apply watermark-based flow control (same as HTTP/1.1)
  // ============================================================================
  // Pattern: Identical to HTTP/1.1's cache limit check at sockproxy.c:302
  //
  // Why this works:
  //   - nghttp2 protocol-level flow control (64KB window) already running
  //   - BUT proxy buffers data AFTER nghttp2 receives it (double buffering)
  //   - Must apply SESSION-LEVEL limit on the relay queues
  //   - Return NGHTTP2_ERR_PAUSE to stop backend reads (nghttp2 API contract)
  //
  // nghttp2 does not deliver a chunk again after NGHTTP2_ERR_PAUSE (it
  // counts it as consumed), so the chunk is still queued below; the
  // overshoot is bounded by one frame.
  int pause = 0;
  if (client_session->total_response_buffer_size + len > H2_SESSION_HIGH_WATER) {
    if (!client_session->backpressure_active) {
      client_session->backpressure_active = 1;
      log_warn("🔴 HTTP/2 session HIGH water mark reached (size=%zu/%d MB), APPLYING BACKPRESSURE",
               client_session->total_response_buffer_size, H2_SESSION_HIGH_WATER/(1024*1024));
    }
    pause = 1;
  }

  // Copy data to avoid lifetime issues (nghttp2 might reuse the buffer)
  h2_resp_chunk_t *chunk = malloc(sizeof(*chunk) + len);
  if (!chunk) {
    log_error("[HTTP/2 Backend] ep[%d]: Failed to allocate memory for DATA forwarding",
              backend_session->ep_idx);
    return NGHTTP2_ERR_NOMEM;
  }
  chunk->next = NULL;
  chunk->len = len;
  chunk->off = 0;
  memcpy(chunk->data, data, len);
  if (relay->tail) {
    relay->tail->next = chunk;
  } else {
    relay->head = chunk;
  }
  relay->tail = chunk;
  relay->queued_bytes += len;

  // Track allocation (same pattern as HTTP/1.1 cache accounting); released
  // as the relay provider hands bytes to nghttp2, or when the stream is freed
  client_session->total_response_buffer_size += len;
  
  // Diagnostic: Warn if buffer is unusually large (shouldn't happen with backpressure)
  // Same pattern as HTTP/1.1's cache diagnostic at sockproxy.c:308-311
  if (client_session->total_response_buffer_size > H2_SESSION_HIGH_WATER * 0.8 &&
      client_session->total_response_buffer_size < H2_SESSION_HIGH_WATER) {
    log_warn("⚠️  HTTP/2 session buffer above 80%% HIGH water (size=%.2f MB, backpressure=%d)",
             client_session->total_response_buffer_size / (1024.0 * 1024.0),
             client_session->backpressure_active);
  }

  int rv = h2_resp_relay_kick(client_session, cstream);
  if (rv != 0) {
    return rv;
  }

  // Send DATA frame to client immediately (same pattern as HEADERS forwarding).
  // This may end and free the client stream; do not touch cstream after it.
  nghttp2_session_send(client_session->session);

  return pause ? NGHTTP2_ERR_PAUSE : 0;
}

/**
 * Backend stream close callback
 */
static int
proxy_h2_backend_on_stream_close_callback(nghttp2_session *session,
                                            int32_t stream_id,
                                            uint32_t error_code,
                                            void *user_data)
{
  backend_h2_session_t *backend_session = (backend_h2_session_t *)user_data;

  if (!backend_session) {
    return 0;
  }

  // Remove stream mapping and free allocated headers
  stream_mapping_t *mapping = NULL;
  stream_mapping_t *tmp;
  HASH_ITER(hh, backend_session->stream_map, mapping, tmp) {
    if (mapping->backend_stream_id == stream_id) {
      /* AI settle twin: the backend closed the response stream, so the
       * tail window holds the final bytes. Charge usage, release the
       * admission claim, record the request — H1 does this at body
       * complete / SSE [DONE]; a backend-side abort still settles here
       * with whatever arrived (settle also covers the claim release). */
      if (backend_session->client_session) {
        proxy_h2_stream_t *ai_stream =
          find_stream(backend_session->client_session,
                      mapping->client_stream_id);
        if (ai_stream)
          proxy_h2_settle_stream(backend_session->client_session, ai_stream);

        /* The response relay lives on the client stream and outlives this
         * mapping: a normal close comes right after the backend's
         * END_STREAM, while the relay may still be waiting for the
         * client's window. A close WITHOUT END_STREAM (a reset nghttp2
         * raised itself, a GOAWAY refusal) leaves nothing that would ever
         * end the client stream, so reset it. Submit only: the send runs
         * from the caller (this callback can fire inside the backend send
         * of proxy_h2_forward_to_backend while the client streams are
         * being iterated, and a send here could free one of them). */
        if (ai_stream && !ai_stream->resp.eos_pending &&
            backend_session->client_session->session) {
          h2_resp_relay_reset(backend_session->client_session, ai_stream,
                              error_code != NGHTTP2_NO_ERROR ?
                              error_code : NGHTTP2_INTERNAL_ERROR);
        }
      }
      HASH_DEL(backend_session->stream_map, mapping);

      // Free allocated header storage
      if (mapping->response_headers) {
        for (size_t i = 0; i < mapping->response_headers_count; i++) {
          free((void *)mapping->response_headers[i].name);
          free((void *)mapping->response_headers[i].value);
        }
        free(mapping->response_headers);
      }

      // Free data source if allocated
      if (mapping->data_source) {
        free(mapping->data_source);
      }

      free(mapping);
      break;
    }
  }

  return 0;
}

/**
 * Create or get backend HTTP/2 session for endpoint
 */
backend_h2_session_t *
proxy_h2_get_backend_session(proxy_h2_session_t *client_session,
                               proxy_fd_ent_t *pfe,
                               int slot,
                               int ep_idx,
                               void *epv,
                               int backend_fd,
                               void *ssl)
{
  backend_h2_session_t *backend_session = NULL;
  nghttp2_session_callbacks *callbacks = NULL;
  int rv;

  if (!client_session || !pfe || slot < 0 || ep_idx < 0 || backend_fd <= 0) {
    log_error("[HTTP/2 Backend] Invalid parameters for backend session creation");
    return NULL;
  }

  /* Sessions are keyed by the per-connection SLOT, never by ep_idx: two
   * model pools on one rule both contain an endpoint 0, and a stream of
   * pool B must not be submitted into pool A's session because the
   * indexes happen to match. The slot was allocated against (epv, ep_idx)
   * by the forwarder, so a hit here is a same-pool, same-endpoint reuse. */
  HASH_FIND_INT(client_session->backend_sessions, &slot, backend_session);
  if (backend_session) {
    return backend_session;
  }

  // Create new backend session
  backend_session = calloc(1, sizeof(backend_h2_session_t));
  if (!backend_session) {
    log_error("[HTTP/2 Backend] ep[%d]: Failed to allocate backend session", ep_idx);
    return NULL;
  }

  backend_session->backend_fd = backend_fd;
  backend_session->slot = slot;
  backend_session->ep_idx = ep_idx;
  backend_session->epv = epv;
  backend_session->client_session = client_session;
  backend_session->ssl = ssl;
  backend_session->connected = 1;
  pthread_mutex_init(&backend_session->send_lock, NULL);
  
  // Create nghttp2 callbacks for backend
  rv = nghttp2_session_callbacks_new(&callbacks);
  if (rv != 0) {
    log_error("[HTTP/2 Backend] ep[%d]: nghttp2_session_callbacks_new failed: %s",
              ep_idx, nghttp2_strerror(rv));
    free(backend_session);
    return NULL;
  }
  
  // Set backend-specific callbacks
  nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, 
                                                        proxy_h2_backend_on_frame_recv_callback);
  nghttp2_session_callbacks_set_on_header_callback(callbacks,
                                                    proxy_h2_backend_on_header_callback);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks,
                                                             proxy_h2_backend_on_data_chunk_recv_callback);
  nghttp2_session_callbacks_set_on_stream_close_callback(callbacks,
                                                          proxy_h2_backend_on_stream_close_callback);
  
  // Create backend session in CLIENT mode (we connect to backend as HTTP/2 client)
  rv = nghttp2_session_client_new(&backend_session->session, callbacks, backend_session);
  nghttp2_session_callbacks_del(callbacks);
  
  if (rv != 0) {
    log_error("[HTTP/2 Backend] ep[%d]: nghttp2_session_client_new failed: %s",
              ep_idx, nghttp2_strerror(rv));
    pthread_mutex_destroy(&backend_session->send_lock);
    free(backend_session);
    return NULL;
  }
  
  // Submit client connection preface (required for HTTP/2)
  nghttp2_submit_settings(backend_session->session, NGHTTP2_FLAG_NONE, NULL, 0);
  
  // Send initial frames to backend
  pthread_mutex_lock(&backend_session->send_lock);

  if (ssl) {
    // Send via SSL
    ssize_t sent;
    const uint8_t *send_data;
    while ((sent = nghttp2_session_mem_send(backend_session->session, &send_data)) > 0) {
      SSL_write(ssl, send_data, sent);
      // Note: Statistics are accounted at socket layer (SSL_write), not here
    }
  } else {
    // Send via plain TCP
    ssize_t sent;
    const uint8_t *send_data;
    while ((sent = nghttp2_session_mem_send(backend_session->session, &send_data)) > 0) {
      send(backend_fd, send_data, sent, 0);
      // Note: Statistics are accounted at socket layer (send), not here
    }
  }
  
  pthread_mutex_unlock(&backend_session->send_lock);
  
  // Add to client session's backend sessions hash
  HASH_ADD_INT(client_session->backend_sessions, slot, backend_session);
  
  return backend_session;
}

// ============================================================================
// Backend Send Buffer Management (Bug Fix for WANT_WRITE/WANT_READ retry)
// Mirrors HTTP/1.1 cache mechanism (sockproxy.c:286-788)
// ============================================================================

/**
 * Add data to backend send buffer
 * Called when SSL_write/send returns WANT_WRITE or WANT_READ
 * Mirrors proxy_add_xmitcache() from sockproxy.c:286-354
 */
int
proxy_h2_backend_add_send_buffer(backend_h2_session_t *backend_session,
                                  const uint8_t *data, size_t len)
{
  backend_send_buffer_t *new_buf;

  if (!backend_session || !data || len == 0) {
    return -1;
  }

  // Allocate buffer entry + data (single allocation for efficiency)
  new_buf = calloc(1, sizeof(backend_send_buffer_t) + len);
  if (!new_buf) {
    log_error("[HTTP/2 Backend] ep[%d]: Failed to allocate send buffer (%zu bytes)",
              backend_session->ep_idx, len);
    return -1;
  }

  // Setup buffer (data follows structure in memory)
  new_buf->data = (uint8_t *)(new_buf + 1);
  memcpy(new_buf->data, data, len);
  new_buf->total_len = len;
  new_buf->sent_len = 0;
  new_buf->pending = 1;
  new_buf->next = NULL;

  // Add to tail of linked list (FIFO order)
  pthread_mutex_lock(&backend_session->send_lock);

  if (backend_session->send_buffer_tail) {
    backend_session->send_buffer_tail->next = new_buf;
    backend_session->send_buffer_tail = new_buf;
  } else {
    backend_session->send_buffer_head = new_buf;
    backend_session->send_buffer_tail = new_buf;
  }

  backend_session->send_buffer_total_size += len;

  pthread_mutex_unlock(&backend_session->send_lock);

  log_debug("[HTTP/2 Backend] ep[%d]: Buffered %zu bytes (total buffered: %zu bytes)",
            backend_session->ep_idx, len, backend_session->send_buffer_total_size);

  return 0;
}

/**
 * Drain backend send buffer (retry pending sends)
 * Called on EPOLLOUT events or after adding to buffer
 * Mirrors proxy_xmit_cache() from sockproxy.c:501-788
 */
int
proxy_h2_backend_drain_send_buffer(backend_h2_session_t *backend_session)
{
  backend_send_buffer_t *curr, *tmp;
  int n;

  if (!backend_session) {
    return -1;
  }

  pthread_mutex_lock(&backend_session->send_lock);

  // Set draining flag to prevent race conditions
  backend_session->send_buffer_draining = 1;

  curr = backend_session->send_buffer_head;
  if (!curr) {
    // Buffer empty
    backend_session->send_buffer_draining = 0;
    pthread_mutex_unlock(&backend_session->send_lock);
    return 0;
  }

  // Drain buffers in FIFO order
  while (curr) {
    size_t remaining = curr->total_len - curr->sent_len;
    uint8_t *send_ptr = curr->data + curr->sent_len;

    if (backend_session->ssl) {
      // SSL/TLS send
      n = SSL_write(backend_session->ssl, send_ptr, remaining);
      if (n <= 0) {
        int ssl_err = SSL_get_error(backend_session->ssl, n);

        switch (ssl_err) {
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_READ:
          // Socket not ready - keep buffer and wait for next EPOLLOUT
          log_debug("[HTTP/2 Backend] ep[%d]: Drain paused (SSL %s), waiting for EPOLLOUT",
                    backend_session->ep_idx,
                    ssl_err == SSL_ERROR_WANT_WRITE ? "WANT_WRITE" : "WANT_READ");
          backend_session->send_buffer_draining = 0;
          pthread_mutex_unlock(&backend_session->send_lock);
          return 0;  // Not an error - just need to retry later

        case SSL_ERROR_SYSCALL:
        case SSL_ERROR_SSL:
        default:
          // Fatal SSL error
          log_error("[HTTP/2 Backend] ep[%d]: SSL_write failed during buffer drain: %s",
                    backend_session->ep_idx, ERR_error_string(ERR_get_error(), NULL));
          
#ifdef HAVE_HTTP_TRACE
          // CRITICAL: Emit REQ_END for backend SSL errors
          // HTTP/2 uses multiplexed streams, so emit trace for the client connection
          if (backend_session->client_session && backend_session->client_session->pfe) {
            proxy_fd_ent_t *client_pfe = backend_session->client_session->pfe;
            if (client_pfe->odir == 0 && client_pfe->root_span_id != 0 && is_tracing_enabled()) {
              uint64_t duration_us = 0;
              if (client_pfe->req_start_ts > 0) {
                uint64_t now = get_timestamp_ns();
                duration_us = (now - client_pfe->req_start_ts) / 1000;
              }
              
              // Set HTTP 500 Internal Server Error for backend SSL failures
              client_pfe->http_status_code = 500;
              
              log_info("[TRACE_ERROR_H2] fd=%d: Emitting REQ_END with status 500 (backend SSL error) duration=%luμs",
                       client_pfe->fd, duration_us);
              
              emit_trace_event(client_pfe, LXB_EVENT_REQ_END, duration_us);
              client_pfe->root_span_id = 0;
            }
          }
#endif
          
          backend_session->send_buffer_draining = 0;
          pthread_mutex_unlock(&backend_session->send_lock);
          return -1;
        }
      }
    } else {
      // Plaintext send
      n = send(backend_session->backend_fd, send_ptr, remaining, MSG_DONTWAIT | MSG_NOSIGNAL);
      if (n <= 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          // Socket not ready - keep buffer and wait for next EPOLLOUT
          log_debug("[HTTP/2 Backend] ep[%d]: Drain paused (EAGAIN), waiting for EPOLLOUT",
                    backend_session->ep_idx);
          backend_session->send_buffer_draining = 0;
          pthread_mutex_unlock(&backend_session->send_lock);
          return 0;  // Not an error - just need to retry later
        }

        // Fatal socket error
        log_error("[HTTP/2 Backend] ep[%d]: send() failed during buffer drain: %s",
                  backend_session->ep_idx, strerror(errno));
        
#ifdef HAVE_HTTP_TRACE
        // CRITICAL: Emit REQ_END for backend send errors
        if (backend_session->client_session && backend_session->client_session->pfe) {
          proxy_fd_ent_t *client_pfe = backend_session->client_session->pfe;
          if (client_pfe->odir == 0 && client_pfe->root_span_id != 0 && is_tracing_enabled()) {
            uint64_t duration_us = 0;
            if (client_pfe->req_start_ts > 0) {
              uint64_t now = get_timestamp_ns();
              duration_us = (now - client_pfe->req_start_ts) / 1000;
            }
            
            // Set HTTP 500 Internal Server Error for backend send failures
            client_pfe->http_status_code = 500;
            
            log_info("[TRACE_ERROR_H2] fd=%d: Emitting REQ_END with status 500 (backend send error) duration=%luμs",
                     client_pfe->fd, duration_us);
            
            emit_trace_event(client_pfe, LXB_EVENT_REQ_END, duration_us);
            client_pfe->root_span_id = 0;
          }
        }
#endif
        
        backend_session->send_buffer_draining = 0;
        pthread_mutex_unlock(&backend_session->send_lock);
        return -1;
      }
    }

    // Update sent progress
    curr->sent_len += n;
    backend_session->frames_sent++;  // Statistics

    // Check if this buffer is fully sent
    if (curr->sent_len >= curr->total_len) {
      // Buffer complete - remove from list and free
      tmp = curr;
      curr = curr->next;
      backend_session->send_buffer_head = curr;

      if (!curr) {
        backend_session->send_buffer_tail = NULL;  // List now empty
      }

      backend_session->send_buffer_total_size -= tmp->total_len;
      free(tmp);

      log_debug("[HTTP/2 Backend] ep[%d]: Buffer entry drained (remaining buffers: %zu bytes)",
                backend_session->ep_idx, backend_session->send_buffer_total_size);
    } else {
      // Partial send - update offset and continue
      log_debug("[HTTP/2 Backend] ep[%d]: Partial send %d/%zu bytes",
                backend_session->ep_idx, n, remaining);
      continue;
    }
  }

  // All buffers drained successfully
  backend_session->send_buffer_draining = 0;
  pthread_mutex_unlock(&backend_session->send_lock);

  log_debug("[HTTP/2 Backend] ep[%d]: All send buffers drained successfully",
            backend_session->ep_idx);

  return 0;
}

/**
 * Destroy all send buffers
 * Called during backend session cleanup
 */
void
proxy_h2_backend_destroy_send_buffer(backend_h2_session_t *backend_session)
{
  backend_send_buffer_t *curr, *tmp;

  if (!backend_session) {
    return;
  }

  pthread_mutex_lock(&backend_session->send_lock);

  curr = backend_session->send_buffer_head;
  while (curr) {
    tmp = curr->next;
    free(curr);
    curr = tmp;
  }

  backend_session->send_buffer_head = NULL;
  backend_session->send_buffer_tail = NULL;
  backend_session->send_buffer_total_size = 0;
  backend_session->send_buffer_draining = 0;

  pthread_mutex_unlock(&backend_session->send_lock);
}

/**
 * Handle backend EPOLLOUT event
 * Called from event loop when backend fd becomes writable
 */
int
proxy_h2_handle_backend_writable(proxy_fd_ent_t *pfe)
{
  backend_h2_session_t *backend_session;

  if (!pfe || !pfe->backend_h2_session) {
    log_error("[HTTP/2 Backend] Invalid pfe or no backend session for EPOLLOUT");
    return -1;
  }

  backend_session = pfe->backend_h2_session;

  // Drain pending send buffers
  if (backend_session->send_buffer_head) {
    log_debug("[HTTP/2 Backend] ep[%d]: EPOLLOUT triggered, draining send buffer",
              backend_session->ep_idx);

    if (proxy_h2_backend_drain_send_buffer(backend_session) < 0) {
      log_error("[HTTP/2 Backend] ep[%d]: Failed to drain send buffer on EPOLLOUT",
                backend_session->ep_idx);
      return -1;
    }

    // If buffer now empty, remove EPOLLOUT from event monitoring
    if (!backend_session->send_buffer_head) {
      log_debug("[HTTP/2 Backend] ep[%d]: Send buffer empty, removing EPOLLOUT monitoring",
                backend_session->ep_idx);
      proxy_notify_add_fd(backend_session->backend_fd, NOTI_TYPE_IN | NOTI_TYPE_HUP, pfe);
    }
  }

  return 0;
}

/**
 * Destroy backend HTTP/2 session
 */
void
proxy_h2_backend_session_destroy(backend_h2_session_t *backend_session)
{
  if (!backend_session) {
    return;
  }

  // ============================================================================
  // BUG FIX: Cleanup send buffers before destroying session
  // ============================================================================
  proxy_h2_backend_destroy_send_buffer(backend_session);

  // Delete all stream mappings and free allocated headers
  stream_mapping_t *mapping, *tmp;
  HASH_ITER(hh, backend_session->stream_map, mapping, tmp) {
    HASH_DEL(backend_session->stream_map, mapping);

    // Free allocated header storage
    if (mapping->response_headers) {
      for (size_t i = 0; i < mapping->response_headers_count; i++) {
        free((void *)mapping->response_headers[i].name);
        free((void *)mapping->response_headers[i].value);
      }
      free(mapping->response_headers);
    }

    free(mapping);
  }

  // Delete nghttp2 session
  if (backend_session->session) {
    nghttp2_session_del(backend_session->session);
    backend_session->session = NULL;
  }

  /* The fd is NOT closed here. It belongs to the backend proxy_fd_ent_t that
   * was created around it, exactly as an HTTP/1.1 backend leg does: that pfe
   * is deregistered by proxy_release_rfd_ctx and closed by its own
   * proxy_release_fd_ctx(.., 1). Closing it here as well would hand the same
   * descriptor number back to the kernel twice — the second close landing on
   * whatever connection has since been handed that number. The two creation
   * failure paths in proxy_h2_forward_to_backend are the only places where no
   * pfe ever took ownership, and each closes the fd itself. */
  pthread_mutex_destroy(&backend_session->send_lock);
  free(backend_session);
}

/**
 * Send pending frames to client
 */
int
proxy_h2_client_send(proxy_h2_session_t *client_session)
{
  int rv;
  
  if (!client_session || !client_session->session) {
    return -1;
  }
  
  rv = nghttp2_session_send(client_session->session);
  if (rv != 0) {
    // ⚠️ CRITICAL FIX for gRPC streaming: Handle client disconnection gracefully
    // Same logic as proxy_h2_handle_client_data - if client disconnected during
    // backend→client response forwarding, don't propagate fatal error
    if (rv == NGHTTP2_ERR_CALLBACK_FAILURE) {
      // Client disconnected while sending backend response
      log_debug("[HTTP/2] Client disconnected during backend response send, cleaning up gracefully");
      client_session->goaway_recv = 1;  // Mark for cleanup
      return 0;  // Success - let event loop clean up
    }
    
    log_error("[HTTP/2] nghttp2_session_send failed: %s", nghttp2_strerror(rv));
    return -1;
  }
  
  return 0;
}

// ============================================================================
// Session Management
// ============================================================================

/**
 * Initialize HTTP/2 session after ALPN negotiation
 */
int
proxy_setup_h2_session(proxy_fd_ent_t *pfe, int is_client)
{
  nghttp2_session_callbacks *callbacks;
  int rv;
  
  if (!pfe) {
    return -1;
  }
    
  // Allocate session context
  pfe->h2_session = calloc(1, sizeof(proxy_h2_session_t));
  if (!pfe->h2_session) {
    log_error("[HTTP/2] Failed to allocate session");
    return -1;
  }

  pfe->h2_session->pfe = pfe;  // Back pointer for statistics
  pfe->h2_session->is_client = is_client;
  pfe->h2_session->h2_enabled = 1;
  pfe->h2_session->max_concurrent_streams = 100;  // Default
  pfe->h2_session->created_ts = time(NULL);

  // METRICS: Track HTTP/2 session creation (TIER 1, Metric #4)
  atomic_fetch_add(&global_stats.h2_sessions, 1);
  pfe->protocol_version = 2;  // HTTP/2
  
  // Initialize backpressure tracking (same pattern as HTTP/1.1 cache)
  pfe->h2_session->total_response_buffer_size = 0;
  pfe->h2_session->backpressure_active = 0;
  
  // Create callbacks
  rv = nghttp2_session_callbacks_new(&callbacks);
  if (rv != 0) {
    log_error("[HTTP/2] nghttp2_session_callbacks_new failed: %s",
              nghttp2_strerror(rv));
    free(pfe->h2_session);
    pfe->h2_session = NULL;
    return -1;
  }
  
  // Set callbacks
  nghttp2_session_callbacks_set_send_callback(callbacks, proxy_h2_send_callback);
  nghttp2_session_callbacks_set_recv_callback(callbacks, proxy_h2_recv_callback);
  nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, proxy_h2_on_frame_recv_callback);
  nghttp2_session_callbacks_set_on_header_callback(callbacks, proxy_h2_on_header_callback);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, proxy_h2_on_data_chunk_recv_callback);
  nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, proxy_h2_on_stream_close_callback);
  
  // Create session
  if (is_client) {
    rv = nghttp2_session_client_new(&pfe->h2_session->session, callbacks, pfe);
  } else {
    rv = nghttp2_session_server_new(&pfe->h2_session->session, callbacks, pfe);
  }
  
  nghttp2_session_callbacks_del(callbacks);
  
  if (rv != 0) {
    log_error("[HTTP/2] nghttp2_session_new failed: %s", nghttp2_strerror(rv));
    free(pfe->h2_session);
    pfe->h2_session = NULL;
    return -1;
  }
  
  // Configure session settings
  nghttp2_settings_entry iv[3] = {
    {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100},  // Limit concurrent streams
    {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 65535},   // 64KB window
    {NGHTTP2_SETTINGS_ENABLE_PUSH, 0}                // Disable server push
  };
  
  rv = nghttp2_submit_settings(pfe->h2_session->session, NGHTTP2_FLAG_NONE, iv, 3);
  if (rv != 0) {
    log_error("[HTTP/2] nghttp2_submit_settings failed: %s", nghttp2_strerror(rv));
    nghttp2_session_del(pfe->h2_session->session);
    free(pfe->h2_session);
    pfe->h2_session = NULL;
    return -1;
  }
  
  // Send initial SETTINGS frame
  rv = nghttp2_session_send(pfe->h2_session->session);
  if (rv != 0) {
    log_error("[HTTP/2] nghttp2_session_send failed: %s", nghttp2_strerror(rv));
    nghttp2_session_del(pfe->h2_session->session);
    free(pfe->h2_session);
    pfe->h2_session = NULL;
    return -1;
  }
  return 0;
}

/**
 * Detect HTTP/2 from ALPN and initialize session
 */
int
proxy_check_and_setup_h2(proxy_fd_ent_t *pfe)
{
  if (!pfe) {
    return -1;
  }
  
  // P6 FIX: Support both HTTPS (via ALPN) and plaintext HTTP/2 (prior knowledge)
  if (pfe->ssl) {
    // HTTPS path: Check ALPN protocol negotiation
    const unsigned char *alpn_proto;
    unsigned int alpn_len;
    SSL_get0_alpn_selected(pfe->ssl, &alpn_proto, &alpn_len);
    
    if (alpn_len == 2 && memcmp(alpn_proto, "h2", 2) == 0) {
      return proxy_setup_h2_session(pfe, 0);  // Server mode
    } else if (alpn_len == 8 && memcmp(alpn_proto, "http/1.1", 8) == 0) {
      pfe->protocol_version = 1;
      return -1;  // HTTP/1.1
    } else if (alpn_len == 0) {
      pfe->protocol_version = 1;
      return -1;  // HTTP/1.1 fallback
    } else {
      pfe->protocol_version = 1;
      return -1;
    }
  } else {
    // Plaintext HTTP/2 path (h2c - HTTP/2 Cleartext)
    // Caller has already detected HTTP/2 connection preface
    return proxy_setup_h2_session(pfe, 0);  // Server mode
  }
}

/*
 * proxy_h2_inject_resp_headers — NON-TERMINAL response
 * header injector. See sockproxy_h2.h for the full contract.
 *
 * The genuinely net-new C primitive of (76-RESEARCH Pitfall 2 /
 * 76-PATTERNS "No Analog Found" / A4). It appends `extra` headers into the
 * per-stream collected response-header set that the backend->client relay
 * (proxy_h2_backend_on_frame_recv_callback, the HEADERS case) submits to the
 * client via nghttp2_submit_headers(). It deliberately does NOT submit anything
 * itself and does NOT touch any frame flag — the relay forwards the *backend's*
 * END_STREAM bit, so the backend DATA frames (the body) keep flowing. Contrast
 * proxy_h2_send_l7_synthetic() below, which is TERMINAL (NULL data provider =>
 * END_STREAM, no body) and is the wrong tool for "200 + injected header + body".
 *
 * Names/values are deep-copied (malloc+memcpy) so the existing per-mapping
 * cleanup loops free them uniformly; mapping->data_source (the request DATA
 * provider) is never touched, so the body stays attached.
 */
int
proxy_h2_inject_resp_headers(stream_mapping_t *mapping,
                             const nghttp2_nv *extra, size_t nextra)
{
  if (!mapping)
    return -1;
  if (!extra || nextra == 0)
    return 0; /* nothing to do — a valid no-op */

  /* Allocate the collection array if the relay has not started it yet. This
   * mirrors proxy_h2_backend_on_header_callback's lazy-alloc so the injector is
   * safe to call before or after the backend header callback has run. */
  if (!mapping->response_headers) {
    mapping->response_headers_capacity = 16;
    mapping->response_headers =
        calloc(mapping->response_headers_capacity, sizeof(nghttp2_nv));
    if (!mapping->response_headers) {
      mapping->response_headers_capacity = 0;
      return -1;
    }
    mapping->response_headers_count = 0;
  }

  int injected = 0;
  for (size_t i = 0; i < nextra; i++) {
    /* Skip malformed entries defensively (no name, or a NUL/CR/LF in the name
     * would be an h2 protocol violation). Value may legitimately be empty. */
    if (!extra[i].name || extra[i].namelen == 0)
      continue;

    /* Grow storage if at capacity (doubling, same idiom as the backend
     * collection path). On a grow failure we stop but keep what we appended —
     * the relay still emits a valid, non-terminal frame. */
    if (mapping->response_headers_count >= mapping->response_headers_capacity) {
      size_t new_cap = mapping->response_headers_capacity
                           ? mapping->response_headers_capacity * 2
                           : 16;
      nghttp2_nv *grown = realloc(mapping->response_headers,
                                  new_cap * sizeof(nghttp2_nv));
      if (!grown)
        break;
      mapping->response_headers = grown;
      mapping->response_headers_capacity = new_cap;
    }

    nghttp2_nv *nv = &mapping->response_headers[mapping->response_headers_count];

    nv->name = malloc(extra[i].namelen);
    if (!nv->name)
      break;
    memcpy(nv->name, extra[i].name, extra[i].namelen);
    nv->namelen = extra[i].namelen;

    if (extra[i].valuelen > 0) {
      nv->value = malloc(extra[i].valuelen);
      if (!nv->value) {
        free(nv->name);
        break;
      }
      memcpy(nv->value, extra[i].value, extra[i].valuelen);
    } else {
      /* Empty value: allocate 1 byte so the cleanup free() is always paired
       * with a malloc and never a static/borrowed pointer. */
      nv->value = malloc(1);
      if (!nv->value) {
        free(nv->name);
        break;
      }
    }
    nv->valuelen = extra[i].valuelen;

    /* Force NONE: never propagate a caller flag that could alter framing. The
     * relay owns END_STREAM (from the backend). */
    nv->flags = NGHTTP2_NV_FLAG_NONE;

    mapping->response_headers_count++;
    injected++;
  }

  return injected;
}

/*
 * proxy_h2_send_l7_synthetic — see sockproxy_l7policy.h for the full contract.
 *
 * Emit a synthetic terminal L7 response (REJECT or REDIRECT) on the ACTIVE h2
 * stream via nghttp2 framing. l7_send_reject/l7_send_redirect (sockproxy_l7policy.c)
 * write raw "HTTP/1.1 ..." bytes + shutdown() on pfe->fd; that is correct for H1
 * but is an HTTP/2 protocol violation on an h2 socket — the client's framing layer
 * sees garbage and aborts the whole connection (curl returns 000). This is the
 * H1/H2 parity fix: on an active h2 session we answer the specific stream
 * with a HEADERS-only response (END_STREAM via NULL data provider) and leave the
 * connection open (h2 multiplexes — only this stream closes). The body is omitted
 * on h2: the gate (and Octavia) assert only the status code and, for REDIRECT, the
 * Location header — both carried in the HEADERS frame.
 *
 * Returns 0 when handled on h2 (caller must NOT also do the H1 raw send); -1 when
 * pfe is not on an active h2 session (caller falls back to the H1 raw path).
 */
int
proxy_h2_send_l7_synthetic(proxy_fd_ent_t *pfe, int status_code,
                           const char *location, const char *body)
{
  (void)body;  /* body intentionally omitted on h2 — status/Location suffice */

  if (!pfe || !pfe->h2_session || !pfe->h2_session->h2_enabled ||
      !pfe->h2_session->session)
    return -1;  /* not an active HTTP/2 session — caller uses the H1 raw path */

  int32_t sid = pfe->h2_session->l7_active_stream_id;
  if (sid <= 0)
    return -1;  /* no stream under dispatch to answer — fall back to H1 raw */

  char status_str[8];
  snprintf(status_str, sizeof(status_str), "%d", status_code);

  /* HEADERS-only: :status (always), location (REDIRECT only), content-length: 0.
   * Positional nghttp2_nv init mirrors the 503 responder below (line ~2337). */
  nghttp2_nv hdrs[3];
  size_t nvlen = 0;
  hdrs[nvlen].name = (uint8_t *)":status";
  hdrs[nvlen].value = (uint8_t *)status_str;
  hdrs[nvlen].namelen = 7;
  hdrs[nvlen].valuelen = strlen(status_str);
  hdrs[nvlen].flags = NGHTTP2_NV_FLAG_NONE;
  nvlen++;
  if (location && location[0]) {
    hdrs[nvlen].name = (uint8_t *)"location";
    hdrs[nvlen].value = (uint8_t *)location;
    hdrs[nvlen].namelen = 8;
    hdrs[nvlen].valuelen = strlen(location);
    hdrs[nvlen].flags = NGHTTP2_NV_FLAG_NONE;
    nvlen++;
  }
  hdrs[nvlen].name = (uint8_t *)"content-length";
  hdrs[nvlen].value = (uint8_t *)"0";
  hdrs[nvlen].namelen = 14;
  hdrs[nvlen].valuelen = 1;
  hdrs[nvlen].flags = NGHTTP2_NV_FLAG_NONE;
  nvlen++;

  /* NULL data provider => END_STREAM is set on the HEADERS frame (no body). */
  int rv = nghttp2_submit_response(pfe->h2_session->session, sid,
                                   hdrs, nvlen, NULL);
  if (rv != 0) {
    log_error("[HTTP/2] L7 synthetic submit failed (stream %d status %d): %s",
              sid, status_code, nghttp2_strerror(rv));
    return 0;  /* it IS an h2 stream — do NOT fall back to raw HTTP/1.1 bytes */
  }
  nghttp2_session_send(pfe->h2_session->session);

  log_debug("[HTTP/2] L7 synthetic %d emitted on stream %d (location=%s)",
            status_code, sid, (location && location[0]) ? location : "-");
  return 0;
}

/*
 * proxy_h2_send_ai_deny — terminal AI-gate refusal on ONE stream.
 *
 * The L7 synthetic above answers policy REJECT/REDIRECTs and carries only
 * :status/location; a gate denial owes the client the FULL H1 response
 * contract: the status, the Retry-After hint on the rate arms, and the
 * machine-readable JSON error body — the error code is how a client (and
 * the cicd oracle) tells WHICH arm refused, e.g. missing_token (the JWT
 * arm decided) vs invalid_api_key. Body shapes mirror the H1 responder
 * byte-for-byte: {"error","retry_after"} when retry_body, else
 * {"error","message"}. HEADERS + DATA(END_STREAM); the connection stays
 * open — h2 multiplexes, only this stream ends.
 */
typedef struct {
  uint8_t *data;
  size_t len;
  size_t offset;
} h2_deny_body_ctx_t;

static void
proxy_h2_free_deny_body(proxy_h2_stream_t *stream)
{
  h2_deny_body_ctx_t *ctx;

  if (!stream || !stream->deny_body_ctx)
    return;
  ctx = (h2_deny_body_ctx_t *)stream->deny_body_ctx;
  free(ctx->data);
  free(ctx);
  stream->deny_body_ctx = NULL;
}

static ssize_t
proxy_h2_deny_body_read_callback(nghttp2_session *session, int32_t stream_id,
                                 uint8_t *buf, size_t length,
                                 uint32_t *data_flags,
                                 nghttp2_data_source *source, void *user_data)
{
  h2_deny_body_ctx_t *ctx = (h2_deny_body_ctx_t *)source->ptr;
  size_t remaining = ctx->len - ctx->offset;
  size_t to_copy = (remaining < length) ? remaining : length;

  (void)session; (void)stream_id; (void)user_data;
  if (to_copy > 0) {
    memcpy(buf, ctx->data + ctx->offset, to_copy);
    ctx->offset += to_copy;
  }
  /* Signal EOF at end-of-body but do NOT free here: the STREAM owns the ctx
   * and destroy_stream frees it. Freeing on EOF would leak whenever the client
   * resets the stream before this callback drains the body (the callback then
   * never runs), and would risk a double free against destroy_stream. */
  if (ctx->offset >= ctx->len)
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
  return (ssize_t)to_copy;
}

static int
proxy_h2_send_ai_deny(proxy_fd_ent_t *pfe, proxy_h2_stream_t *stream,
                      int status_code, int retry_after, int retry_body,
                      const char *error_code, const char *error_msg)
{
  if (!pfe || !stream || !pfe->h2_session || !pfe->h2_session->session)
    return -1;

  int32_t stream_id = stream->stream_id;

  char status_str[8];
  char retry_str[16];
  char clen_str[16];
  char body[512];
  int blen;

  snprintf(status_str, sizeof(status_str), "%d", status_code);
  if (!error_code || !error_code[0])
    error_code = "denied";
  if (retry_body) {
    blen = snprintf(body, sizeof(body),
                    "{\"error\":\"%s\",\"retry_after\":%d}\r\n",
                    error_code, retry_after);
  } else {
    blen = snprintf(body, sizeof(body),
                    "{\"error\":\"%s\",\"message\":\"%s\"}\r\n",
                    error_code, error_msg ? error_msg : "");
  }
  if (blen < 0 || blen >= (int)sizeof(body))
    blen = 0;

  /* The body must outlive this frame: nghttp2 pulls it from the read
   * callback asynchronously. On allocation failure the refusal still
   * stands, just body-less — denying is the part that may not fail. */
  h2_deny_body_ctx_t *ctx = NULL;
  if (blen > 0) {
    ctx = calloc(1, sizeof(*ctx));
    if (ctx) {
      ctx->data = malloc((size_t)blen);
      if (!ctx->data) {
        free(ctx);
        ctx = NULL;
      } else {
        memcpy(ctx->data, body, (size_t)blen);
        ctx->len = (size_t)blen;
      }
    }
  }

  /* The stream owns the body from here: destroy_stream frees it even if the
   * client resets the stream before nghttp2 drains it. A denied stream sends
   * exactly one response, so this never overwrites a live ctx. */
  stream->deny_body_ctx = ctx;

  snprintf(clen_str, sizeof(clen_str), "%d", ctx ? blen : 0);

  nghttp2_nv hdrs[4];
  size_t nvlen = 0;
  hdrs[nvlen].name = (uint8_t *)":status";
  hdrs[nvlen].value = (uint8_t *)status_str;
  hdrs[nvlen].namelen = 7;
  hdrs[nvlen].valuelen = strlen(status_str);
  hdrs[nvlen].flags = NGHTTP2_NV_FLAG_NONE;
  nvlen++;
  hdrs[nvlen].name = (uint8_t *)"content-type";
  hdrs[nvlen].value = (uint8_t *)"application/json";
  hdrs[nvlen].namelen = 12;
  hdrs[nvlen].valuelen = 16;
  hdrs[nvlen].flags = NGHTTP2_NV_FLAG_NONE;
  nvlen++;
  if (retry_after > 0) {
    snprintf(retry_str, sizeof(retry_str), "%d", retry_after);
    hdrs[nvlen].name = (uint8_t *)"retry-after";
    hdrs[nvlen].value = (uint8_t *)retry_str;
    hdrs[nvlen].namelen = 11;
    hdrs[nvlen].valuelen = strlen(retry_str);
    hdrs[nvlen].flags = NGHTTP2_NV_FLAG_NONE;
    nvlen++;
  }
  hdrs[nvlen].name = (uint8_t *)"content-length";
  hdrs[nvlen].value = (uint8_t *)clen_str;
  hdrs[nvlen].namelen = 14;
  hdrs[nvlen].valuelen = strlen(clen_str);
  hdrs[nvlen].flags = NGHTTP2_NV_FLAG_NONE;
  nvlen++;

  nghttp2_data_provider data_prd;
  nghttp2_data_provider *prd = NULL;
  if (ctx) {
    data_prd.source.ptr = ctx;
    data_prd.read_callback = proxy_h2_deny_body_read_callback;
    prd = &data_prd;
  }

  int rv = nghttp2_submit_response(pfe->h2_session->session, stream_id,
                                   hdrs, nvlen, prd);
  if (rv != 0) {
    log_error("[AIGateway][HTTP/2] deny submit failed (stream %d status %d): %s",
              stream_id, status_code, nghttp2_strerror(rv));
    /* nghttp2 never took the data provider, so free the body now (clears the
     * stream's pointer so destroy_stream does not double free). */
    proxy_h2_free_deny_body(stream);
    /* Still an h2 stream: refuse it outright rather than leaving it open. */
    nghttp2_submit_rst_stream(pfe->h2_session->session, NGHTTP2_FLAG_NONE,
                              stream_id, NGHTTP2_INTERNAL_ERROR);
  }
  nghttp2_session_send(pfe->h2_session->session);
  return 0;
}

/**
 * Cleanup HTTP/2 session and all streams
 *
 * Teardown-only, and it never enters the control plane — see the contract on
 * the streams below. Call it from proxy_pdestroy for the client pfe while the
 * backend links are still intact, i.e. BEFORE proxy_release_rfd_ctx.
 */
void
proxy_h2_cleanup_session(proxy_fd_ent_t *pfe)
{
  if (!pfe || !pfe->h2_session) {
    return;
  }

  proxy_h2_session_t *h2_sess = pfe->h2_session;

  /* Streams go FIRST, and without settling. Two reasons, both load-bearing:
   *   - The settle charges the control plane, which re-enters the
   *     non-recursive PROXY_LOCK this runs under. proxy_pdestroy has already
   *     collected these streams' settles for emission after it unlocks.
   *   - Emptying the stream hash now makes the backend-side close callback
   *     harmless: it settles whatever find_stream() hands back, and with the
   *     hash empty that is NULL. So a callback fired from any
   *     nghttp2_session_del below cannot reach a freed stream or the
   *     control plane. */
  proxy_h2_stream_t *stream, *tmp;
  HASH_ITER(hh, h2_sess->streams, stream, tmp) {
    h2_stream_free(h2_sess, stream);
  }

  // Destroy all backend sessions
  backend_h2_session_t *backend_session, *backend_tmp;
  HASH_ITER(hh, h2_sess->backend_sessions, backend_session, backend_tmp) {
    HASH_DEL(h2_sess->backend_sessions, backend_session);
    /* Drop the owning backend pfe's view of this session before freeing it.
     * That pfe outlives this call — proxy_release_rfd_ctx only MARKS it for
     * eviction, so its own teardown (and any EPOLLOUT that beats the evict)
     * runs afterwards and would otherwise read freed memory through
     * pfe->backend_h2_session. */
    if (backend_session->slot >= 0 && backend_session->slot < MAX_PROXY_EP) {
      proxy_fd_ent_t *bpfe = pfe->rfd_ent[backend_session->slot];
      if (bpfe && bpfe->backend_h2_session == backend_session) {
        bpfe->backend_h2_session = NULL;
      }
    }
    proxy_h2_backend_session_destroy(backend_session);
  }

  // Delete nghttp2 session
  if (h2_sess->session) {
    nghttp2_session_del(h2_sess->session);
    h2_sess->session = NULL;
  }

  // Free session structure
  free(h2_sess);
  pfe->h2_session = NULL;
  pfe->protocol_version = 1;  // Reset to HTTP/1.1
}

// ============================================================================
// Data Handling
// ============================================================================

/**
 * Handle incoming HTTP/2 data from client
 */
int
proxy_h2_handle_client_data(proxy_fd_ent_t *pfe)
{
  int rv;
  
  if (!pfe || !pfe->h2_session) {
    return -1;
  }
  
  // ✅ FIX: Use nghttp2_session_mem_recv() instead of nghttp2_session_recv()
  // This reads from pfe->rcvbuf (already filled by event loop) instead of
  // trying to read from socket again (which would block/fail in non-blocking mode)
  if (pfe->rcv_off > 0) {

    ssize_t consumed = nghttp2_session_mem_recv(pfe->h2_session->session,
                                                 pfe->rcvbuf, pfe->rcv_off);
    if (consumed < 0) {
      log_error("[HTTP/2] nghttp2_session_mem_recv failed: %s",
                nghttp2_strerror((int)consumed));
      return -1;
    }
  }
  
  // Check if we have complete requests to forward
  proxy_h2_stream_t *stream, *tmp;
  int total_streams = 0;
  int ready_streams = 0;
  HASH_ITER(hh, pfe->h2_session->streams, stream, tmp) {
    total_streams++;

    if (stream->headers_complete && stream->data_complete && !stream->response_sent) {
      ready_streams++;
      
      rv = proxy_h2_forward_to_backend(pfe, stream);
      if (rv == 0) {
        // Mark as forwarded to prevent duplicate forwarding
        stream->response_sent = 1;
      } else {
        log_error("[HTTP/2] ✗ Failed to forward stream %d to backend", stream->stream_id);
      }
    }
  }
  
  // Send any pending frames to client
  // ⚠️ CRITICAL FIX for gRPC streaming: Handle client disconnection gracefully
  // In gRPC bidirectional streaming, client may disconnect while proxy is processing
  // requests. If send fails with callback error (EPIPE/ECONNRESET), we should:
  //   1. NOT propagate error up (prevents session cleanup loop)
  //   2. Mark session as dead (prevents future sends)
  //   3. Return success (allows event loop to clean up naturally)
  rv = nghttp2_session_send(pfe->h2_session->session);
  if (rv < 0) {
    // Check if this is a client disconnection (callback failure from EPIPE/ECONNRESET)
    if (rv == NGHTTP2_ERR_CALLBACK_FAILURE) {
      // Client disconnected during send - this is NORMAL for gRPC streaming
      // Mark session as terminated but don't fail catastrophically
      log_debug("[HTTP/2] Client disconnected during send (fd=%d), cleaning up gracefully", pfe->fd);
      pfe->h2_session->goaway_recv = 1;  // Mark session for cleanup
      
      // Return success - let event loop handle cleanup via HUP/error detection
      // This prevents infinite error loops and allows proper fd cleanup
      return 0;  // Changed from -1
    }
    
    // Other errors (non-disconnection) are still fatal
    log_error("[HTTP/2] nghttp2_session_send failed: %s (fd=%d)", 
              nghttp2_strerror(rv), pfe->fd);
    return -1;
  }
  
  return 0;
}

/* Called with send_lock held once the retry buffer is not empty: moves every
 * further frame nghttp2 has queued into the buffer, behind the ones already
 * there, arms EPOLLOUT and tries a drain. Releases send_lock. Returns 0, or -1
 * if a frame could not be buffered. */
static int
h2_backend_queue_rest(backend_h2_session_t *backend_session, proxy_fd_ent_t *backend_pfe,
                      int backend_fd)
{
  ssize_t sent;
  const uint8_t *send_data;

  while ((sent = nghttp2_session_mem_send(backend_session->session, &send_data)) > 0) {
    pthread_mutex_unlock(&backend_session->send_lock);
    if (proxy_h2_backend_add_send_buffer(backend_session, send_data, sent) < 0) {
      log_error("[HTTP/2 Backend] ep[%d]: Failed to buffer %zd bytes for retry",
                backend_session->ep_idx, sent);
      return -1;
    }
    pthread_mutex_lock(&backend_session->send_lock);
  }
  pthread_mutex_unlock(&backend_session->send_lock);

  if (backend_pfe) {
    proxy_notify_add_fd(backend_fd, NOTI_TYPE_IN|NOTI_TYPE_OUT|NOTI_TYPE_HUP, backend_pfe);
  }
  proxy_h2_backend_drain_send_buffer(backend_session);
  return 0;
}

/* Write every frame the backend session has queued: requests, and also the
 * WINDOW_UPDATE, SETTINGS ACK and RST_STREAM frames nghttp2 queues while it
 * receives. Frames the socket cannot take now are buffered and retried on
 * EPOLLOUT. Returns 0, or -1 on a write error. */
static int
h2_backend_flush(backend_h2_session_t *backend_session, proxy_fd_ent_t *backend_pfe,
                 int backend_fd)
{
  // ============================================================================
  // BUG FIX: Send frames to backend with WANT_WRITE/WANT_READ retry support
  // Mirrors HTTP/1.1 pattern from sockproxy.c:286-354 (proxy_add_xmitcache)
  // ============================================================================
  pthread_mutex_lock(&backend_session->send_lock);

  if (backend_session->send_buffer_head) {
    /* Earlier frames still wait in the retry buffer. Writing new ones directly
     * would put them on the wire ahead of those, so queue behind them. */
    return h2_backend_queue_rest(backend_session, backend_pfe, backend_fd);
  }

  if (backend_session->ssl) {
    // Send via SSL with retry buffering
    ssize_t sent;
    const uint8_t *send_data;
    while ((sent = nghttp2_session_mem_send(backend_session->session, &send_data)) > 0) {
      int rv = SSL_write(backend_session->ssl, send_data, sent);
      if (rv <= 0) {
        int ssl_err = SSL_get_error(backend_session->ssl, rv);
        if (ssl_err == SSL_ERROR_WANT_WRITE || ssl_err == SSL_ERROR_WANT_READ) {
          // ✅ BUG FIX: Buffer unsent data for retry instead of dropping
          pthread_mutex_unlock(&backend_session->send_lock);

          if (proxy_h2_backend_add_send_buffer(backend_session, send_data, sent) < 0) {
            log_error("[HTTP/2 Backend] ep[%d]: Failed to buffer %zd bytes for retry",
                      backend_session->ep_idx, sent);
            return -1;
          }

          if (backend_pfe) {
            // Register EPOLLOUT for retry when socket becomes writable
            proxy_notify_add_fd(backend_fd, NOTI_TYPE_IN|NOTI_TYPE_OUT|NOTI_TYPE_HUP, backend_pfe);
          }

          // ✅ BUG FIX: Immediately try to drain buffer (mirrors HTTP/1.1 Bug #3 fix)
          // This prevents data starvation when socket becomes ready quickly
          proxy_h2_backend_drain_send_buffer(backend_session);

          log_debug("[HTTP/2 Backend] ep[%d]: Buffered %zd bytes due to WANT_WRITE/WANT_READ, total_buffered=%zu",
                    backend_session->ep_idx, sent, backend_session->send_buffer_total_size);
          return 0;  // Not a fatal error - will retry on EPOLLOUT
        }
        if (ssl_err == SSL_ERROR_SYSCALL) {
          log_error("[HTTP/2 Backend] ep[%d]: SSL_write SYSCALL error (errno=%d: %s)",
                    backend_session->ep_idx, errno, strerror(errno));
        } else {
          log_error("[HTTP/2 Backend] ep[%d]: SSL_write failed: %d",
                    backend_session->ep_idx, ssl_err);
        }
        pthread_mutex_unlock(&backend_session->send_lock);
        return -1;
      }
      backend_session->frames_sent++;
      // Note: Statistics are accounted at socket layer (SSL_write), not here
    }
  } else {
    // Send via plain TCP with retry buffering
    ssize_t sent;
    const uint8_t *send_data;
    while ((sent = nghttp2_session_mem_send(backend_session->session, &send_data)) > 0) {
      ssize_t rv = send(backend_fd, send_data, sent, 0);
      if (rv >= 0 && rv < sent) {
        /* Partial write: keep the rest of the frame, in order, for EPOLLOUT. */
        pthread_mutex_unlock(&backend_session->send_lock);
        if (proxy_h2_backend_add_send_buffer(backend_session, send_data + rv, sent - rv) < 0) {
          return -1;
        }
        pthread_mutex_lock(&backend_session->send_lock);
        return h2_backend_queue_rest(backend_session, backend_pfe, backend_fd);
      }
      if (rv < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          // ✅ BUG FIX: Buffer unsent data for retry instead of dropping
          pthread_mutex_unlock(&backend_session->send_lock);

          if (proxy_h2_backend_add_send_buffer(backend_session, send_data, sent) < 0) {
            log_error("[HTTP/2 Backend] ep[%d]: Failed to buffer %zd bytes for retry",
                      backend_session->ep_idx, sent);
            return -1;
          }

          if (backend_pfe) {
            // Register EPOLLOUT for retry when socket becomes writable
            proxy_notify_add_fd(backend_fd, NOTI_TYPE_IN|NOTI_TYPE_OUT|NOTI_TYPE_HUP, backend_pfe);
          }

          // ✅ BUG FIX: Immediately try to drain buffer (mirrors HTTP/1.1 Bug #3 fix)
          proxy_h2_backend_drain_send_buffer(backend_session);

          log_debug("[HTTP/2 Backend] ep[%d]: Buffered %zd bytes due to EAGAIN/EWOULDBLOCK, total_buffered=%zu",
                    backend_session->ep_idx, sent, backend_session->send_buffer_total_size);
          return 0;  // Not a fatal error - will retry on EPOLLOUT
        }
        log_error("[HTTP/2 Backend] ep[%d]: send() failed (errno=%d: %s)",
                  backend_session->ep_idx, errno, strerror(errno));
        pthread_mutex_unlock(&backend_session->send_lock);
        return -1;
      }
      backend_session->frames_sent++;
      // Note: Statistics are accounted at socket layer (send), not here
    }
  }

  pthread_mutex_unlock(&backend_session->send_lock);
  return 0;
}

/**
 * Handle incoming HTTP/2 data from backend
 * This function processes responses from the backend HTTP/2 server
 */
int
proxy_h2_handle_backend_data(proxy_fd_ent_t *pfe)
{
  int rv;
  proxy_fd_ent_t *client_pfe = NULL;
  backend_h2_session_t *backend_session = NULL;
  
  if (!pfe) {
    return -1;
  }
  
  // CRITICAL FIX: pfe here is the BACKEND connection (odir=1)
  // We need to find the CLIENT pfe that owns this backend connection
  // The client pfe has the h2_session with backend_sessions hash
  
  // Backend pfe (odir=1) stores client pfe in pfe->rfd_ent[0]
  if (pfe->odir == 1 && pfe->n_rfd > 0 && pfe->rfd_ent[0]) {
    client_pfe = pfe->rfd_ent[0];  // Get client pfe
  } else {
    log_error("[HTTP/2 Backend] fd=%d: Backend pfe has no client connection (odir=%d, n_rfd=%d)",
              pfe->fd, pfe->odir, pfe->n_rfd);
    return -1;
  }
  
  // Verify client has HTTP/2 session
  if (!client_pfe->h2_session || !client_pfe->h2_session->h2_enabled) {
    log_error("[HTTP/2 Backend] fd=%d: Client pfe has no HTTP/2 session", pfe->fd);
    return -1;
  }
  
  // Now find which backend_session matches this backend FD
  backend_h2_session_t *tmp;
  HASH_ITER(hh, client_pfe->h2_session->backend_sessions, backend_session, tmp) {
    if (backend_session->backend_fd == pfe->fd) {
      // Found the matching backend session!
      break;
    }
  }
  
  if (!backend_session || backend_session->backend_fd != pfe->fd) {
    log_error("[HTTP/2 Backend] fd=%d: No backend session found in client's hash table", pfe->fd);
    return -1;
  }
  
  // Now process backend response data (already read into pfe->rcvbuf by event loop)
  pthread_mutex_lock(&backend_session->send_lock);
  
  // Feed data to nghttp2 for parsing (data already in pfe->rcvbuf from event loop)
  ssize_t consumed = nghttp2_session_mem_recv(backend_session->session,
                                                pfe->rcvbuf, pfe->rcv_off);
  if (consumed < 0) {
    log_error("[HTTP/2 Backend] ep[%d]: nghttp2_session_mem_recv failed: %s",
              backend_session->ep_idx, nghttp2_strerror(consumed));
    pthread_mutex_unlock(&backend_session->send_lock);
    return -1;
  }

  // Note: Statistics are accounted at socket layer (recv/SSL_read), not here
  // to avoid double-counting the same data
  
  pthread_mutex_unlock(&backend_session->send_lock);

  /* Receiving queues frames for the backend too, most importantly the
   * WINDOW_UPDATE that reopens the backend's flow-control window. Nothing else
   * sends them until the next request is forwarded, so without this flush a
   * response larger than the initial 64KB window stalls. */
  if (h2_backend_flush(backend_session, pfe, pfe->fd) < 0) {
    return -1;
  }
  
  // Send any pending frames to client (responses from backend)
  rv = proxy_h2_client_send(client_pfe->h2_session);
  if (rv < 0) {
    log_error("[HTTP/2 Backend] ep[%d]: Failed to send responses to client",
              backend_session->ep_idx);
    return -1;
  }
  
  return 0;
}

// ============================================================================
// Data Provider Callback for Request Body Forwarding
// ============================================================================

/**
 * Data source for buffered request body
 * Used when forwarding client request data to backend
 */
typedef struct {
  uint8_t *data;      // Buffered request body
  size_t len;         // Total length
  size_t offset;      // Current read position
} h2_data_source_t;

/**
 * nghttp2 data read callback for forwarding buffered request body
 *
 * Called by nghttp2 when it needs to send DATA frames to backend.
 * For gRPC and POST requests, this provides the request body data.
 *
 * @return Number of bytes copied, or NGHTTP2_ERR_* on error
 */
static ssize_t
proxy_h2_data_read_callback(nghttp2_session *session, int32_t stream_id,
                            uint8_t *buf, size_t length, uint32_t *data_flags,
                            nghttp2_data_source *source, void *user_data)
{
  h2_data_source_t *src = (h2_data_source_t *)source->ptr;

  if (!src || !src->data) {
    log_error("[HTTP/2] data_read_callback: NULL data source for stream %d", stream_id);
    return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
  }

  // Calculate remaining data
  size_t remaining = src->len - src->offset;
  size_t to_copy = (remaining < length) ? remaining : length;

  // Copy data to nghttp2 buffer
  memcpy(buf, src->data + src->offset, to_copy);
  src->offset += to_copy;

  // Mark EOF if all data has been sent
  if (src->offset >= src->len) {
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
  } 

  return to_copy;
}

// ============================================================================
// H2 request-header injection (parity w/ H1)
// ============================================================================
/*
 * The H2 request HEADERS frame the proxy sends to the backend is built from an
 * nghttp2_nv (stream->request_headers). augments that array, on the
 * L7_Proxy peer only (has_l7_policy gated by the caller), via the SAME shared
 * op-selection/validation as H1 — l7_apply_req_filters() in sockproxy_l7policy.c
 * — so there is exactly ONE source of truth (Pitfall 1; never reimplement).
 *
 * H2 NEVER writes raw \r\n header bytes (75-LEARNINGS §🟠.2; defect 097c8dba):
 * every injected header is an nghttp2_nv the submit path HPACK-encodes. The
 * emit callback (a) drops any existing nv of a SET/REMOVE name from the forward
 * set and (b) appends SET/ADD names. The new nv name/value buffers are owned by
 * the staging struct and live until the nghttp2_submit_request copies them.
 */
#define L7_H2_MAX_INJECT (3 /* X-Forwarded-* */ + L7_MAX_HDR_FILTERS)

typedef struct {
  nghttp2_nv *out;              /* growable forward set (orig − removed + added)  */
  size_t      n_out;            /* current count in `out`                         */
  size_t      cap_out;          /* capacity of `out`                              */
  char       *owned[L7_H2_MAX_INJECT * 2]; /* malloc'd name/value bufs to free    */
  size_t      n_owned;
  int         oom;              /* sticky allocation-failure flag                 */
} l7h2_emit_ctx_t;

/* Lower-case ASCII compare of an nv name (length-delimited) against a C string
 * (HTTP/2 header names are lower-case; match case-insensitively to be safe). */
static int
l7h2_nv_name_eq(const nghttp2_nv *nv, const char *name)
{
  size_t nl = strlen(name);
  if (nv->namelen != nl)
    return 0;
  return strncasecmp((const char *)nv->name, name, nl) == 0;
}

/* Drop every nv whose name matches `name` from the forward set (in place). */
static void
l7h2_drop_name(l7h2_emit_ctx_t *c, const char *name)
{
  size_t r = 0, w = 0;
  for (r = 0; r < c->n_out; r++) {
    if (l7h2_nv_name_eq(&c->out[r], name))
      continue;                 /* skip (drop) this header */
    if (w != r)
      c->out[w] = c->out[r];
    w++;
  }
  c->n_out = w;
}

/* Append a new nv (deep-copied name/value owned by ctx) to the forward set. */
static void
l7h2_append(l7h2_emit_ctx_t *c, const char *name, const char *value)
{
  if (c->oom || c->n_out >= c->cap_out || c->n_owned + 2 > (size_t)(L7_H2_MAX_INJECT * 2))
    return;
  /*
   * H2 carries fields as HPACK pairs rather than CRLF-delimited lines, so a
   * line break here is not the framing break it is on H1. It is still a field
   * no HTTP/2 peer is required to accept, and the two paths are meant to make
   * the same decision about the same header set -- so refuse it on the same
   * terms rather than leaving the answer to whatever the encoder happens to
   * do with it.
   */
  if (l7_hdr_pair_unsafe(name, value))
    return;
  size_t nl = strlen(name), vl = strlen(value);
  char *ncopy = malloc(nl + 1);
  char *vcopy = malloc(vl + 1);
  if (!ncopy || !vcopy) {
    free(ncopy);
    free(vcopy);
    c->oom = 1;
    return;
  }
  memcpy(ncopy, name, nl + 1);
  memcpy(vcopy, value, vl + 1);
  c->owned[c->n_owned++] = ncopy;
  c->owned[c->n_owned++] = vcopy;
  c->out[c->n_out].name = (uint8_t *)ncopy;
  c->out[c->n_out].value = (uint8_t *)vcopy;
  c->out[c->n_out].namelen = nl;
  c->out[c->n_out].valuelen = vl;
  c->out[c->n_out].flags = NGHTTP2_NV_FLAG_NONE;
  c->n_out++;
}

/* l7_hdr_emit_fn for H2: translate one SET/ADD/REMOVE op into nv-array edits. */
static void
l7h2_emit(void *vctx, int op, const char *name, const char *value)
{
  l7h2_emit_ctx_t *c = (l7h2_emit_ctx_t *)vctx;
  switch (op) {
  case L7HDR_SET:
    l7h2_drop_name(c, name);    /* overwrite: remove existing, then add */
    l7h2_append(c, name, value);
    break;
  case L7HDR_ADD:
    l7h2_append(c, name, value);
    break;
  case L7HDR_REMOVE:
    l7h2_drop_name(c, name);
    break;
  default:
    break;
  }
}

/*
 * proxy_h2_build_l7_req_headers — produce the -augmented request nv array
 * for the backend HEADERS frame. Caller MUST have gated on ent->has_l7_policy.
 * On success returns a malloc'd nv array (*out_nv / *out_n) and fills *ctx_out
 * with the owned name/value buffers to free AFTER nghttp2_submit_request copies
 * them. Returns -1 (and leaves *out_nv NULL) on OOM — caller submits the
 * original unmodified headers. `fd` is the client socket (real peer IP).
 */
static int
proxy_h2_build_l7_req_headers(proxy_fd_ent_t *pfe, proxy_map_ent_t *ent,
                              const nghttp2_nv *orig, size_t n_orig, int fd,
                              nghttp2_nv **out_nv, size_t *out_n,
                              l7h2_emit_ctx_t *ctx_out)
{
  size_t cap = n_orig + L7_H2_MAX_INJECT;
  nghttp2_nv *buf = calloc(cap, sizeof(nghttp2_nv));
  if (!buf)
    return -1;

  /* Start from a shallow copy of the original nv set (names/values still point
   * into stream->request_headers — those are NOT freed by us; only the appended
   * copies are owned). */
  memcpy(buf, orig, n_orig * sizeof(nghttp2_nv));

  memset(ctx_out, 0, sizeof(*ctx_out));
  ctx_out->out = buf;
  ctx_out->n_out = n_orig;
  ctx_out->cap_out = cap;

  /* Real TCP peer IP for XFF — the client socket peer, not any client XFF. */
  char xff_ip[INET6_ADDRSTRLEN] = {0};
  struct sockaddr_in peer;
  socklen_t plen = sizeof(peer);
  if (getpeername(fd, (struct sockaddr *)&peer, &plen) == 0 &&
      peer.sin_family == AF_INET) {
    inet_ntop(AF_INET, &peer.sin_addr, xff_ip, sizeof(xff_ip));
  }

  uint16_t listener_port = ntohs(ent->key.xport);
  const char *xfproto = (pfe->ssl != NULL || pfe->ktls_enabled) ? "https" : "http";

  l7_apply_req_filters(pfe, ent,
                       xff_ip[0] ? xff_ip : NULL, listener_port, xfproto,
                       l7h2_emit, ctx_out);

  if (ctx_out->oom) {
    /* partial — free the owned copies and fall back to the original headers */
    for (size_t i = 0; i < ctx_out->n_owned; i++)
      free(ctx_out->owned[i]);
    free(buf);
    return -1;
  }

  *out_nv = buf;
  *out_n = ctx_out->n_out;
  return 0;
}

/* Free the staging buffers after nghttp2_submit_request has copied the nv data. */
static void
proxy_h2_free_l7_req_headers(nghttp2_nv *nv, l7h2_emit_ctx_t *ctx)
{
  for (size_t i = 0; i < ctx->n_owned; i++)
    free(ctx->owned[i]);
  free(nv);
}

// ============================================================================
// Helper Functions - Week 3 Implementation
// ============================================================================

/**
 * Forward HTTP/2 stream to backend
 * Week 3: Full implementation with endpoint selection integration
 * Integrates with: CHWBL routing, GPU-aware routing, conversation tracking, health checks
 */
int
proxy_h2_forward_to_backend(proxy_fd_ent_t *pfe, proxy_h2_stream_t *stream)
{
  proxy_map_ent_t *ent;
  proxy_epval_t *tepval;
  int ep_idx = -1;
  int backend_fd = -1;
  
  if (!pfe || !stream || !pfe->head) {
    log_error("[HTTP/2] Invalid parameters for forward_to_backend");
    return -1;
  }
  
  ent = (proxy_map_ent_t *)pfe->head;

  /* Mandatory security admission is the first service-dependent decision on
   * this stream.  It MUST precede L7 dispatch, model lookup, all Tier 0/1/1.5/2
   * selectors, conversation/CHWBL fallback and backend connection creation.
   * HTTP/1 performs the same validation from llhttp's message-complete
   * callback; HTTP/2 bypasses llhttp and therefore needs this stream gate.
   *
   * ONE gate, shared with the H1 parser: ai_gw_admit() owns arm dispatch on
   * the declared mode, JWT verification, the body-first effective model and
   * its conflict rule, the rate/quota ladder and the pre-admission token
   * reservation. The previous H2-only gate consulted the API-key arm no
   * matter what the service declared, so the two protocol paths could
   * disagree about the declared authentication mode of the same service.
   * This caller owns only the refusal framing and the stream wiring. */
  char body_model[MAX_MODEL_LEN] = {0};
  if (stream->data_buf && stream->data_len > 0)
    extract_model_field((const char *)stream->data_buf, stream->data_len,
                        body_model, sizeof(body_model));

  if (ent->val.ephash) {
    /* The service identity feeds the QoS ladder (rule-scope defaults and
     * the keyless per-VIP bucket) — an AI-gateway concern. Withhold it on
     * non-AI rules so a plain H2 service with an undeclared policy never
     * pays a per-request ladder probe it paid nothing for before (H1 runs
     * its whole gate only on ai_gw_mode connections). */
    char adm_svc_ident[64] = "";
    if (ent->val.ephash->ai_gw_mode)
      ai_gw_svc_ident(ent->key.xip, ent->key.xport,
                      adm_svc_ident, sizeof(adm_svc_ident));

    ai_gw_req_ctx_t adm_req = {
      .api_key = stream->x_api_key_raw,
      .bearer = stream->bearer_raw,
      .bearer_oversize = stream->bearer_oversize,
      .jwt_profile = ent->val.ephash->jwt_auth_profile,
      .body = (const char *)stream->data_buf,
      .body_len = stream->data_len,
      .prefix_model = body_model,
      .hdr_model = stream->x_model_header,
      .auth_mode = ent->val.ephash->apikey_auth,
      .svc_ident = adm_svc_ident,
    };
    ai_gw_admit_result_t adm;
    ai_gw_admit(&adm_req, &adm);

    if (adm.verdict == AI_GW_ADMIT_UNMETERED) {
      /* Served, but neither authenticated nor attributable to a tenant —
       * report it exactly as the H1 gate does, and only for AI-gateway
       * rules (H1 runs its gate only on ai_gw_mode connections). */
      if (ent->val.ephash->ai_gw_mode) {
        char um_vip[INET6_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &ent->key.xip, um_vip, sizeof(um_vip));
        llb_ai_record_unmetered(um_vip);
        /* Keyless still settles: the response's usage charges the per-VIP
         * shared bucket keyed by svc_ident (tenant stays ""), the same
         * exact-usage/deny-next contract the H1 relay applies — its settle
         * gate is ai_gw_mode, not "admitted with an identity". Without
         * this a service with only keyless traffic can never trip its own
         * vip_shared_tpm on HTTP/2 while tripping it fine on HTTP/1. */
        stream->ai_unmetered = 1;
        snprintf(stream->svc_ident, sizeof(stream->svc_ident), "%s",
                 adm_svc_ident);
        stream->admit_mono_ns = get_timestamp_ns();
      }
    } else if (adm.verdict == AI_GW_ADMIT_DENY) {
      /* Terminal response on THIS stream; the multiplexed connection
       * stays alive. Return success so the caller marks the stream
       * response_sent and never redispatches. */
      proxy_h2_send_ai_deny(pfe, stream,
                            adm.http_status, adm.retry_after,
                            adm.retry_body, adm.error_code, adm.error_msg);
      log_info("[AIGateway][HTTP/2] stream=%d rejected before routing: "
               "status=%d stage=%d error=%s key=%s tenant=%s",
               stream->stream_id, adm.http_status, adm.stage,
               adm.error_code, adm.key_id, adm.tenant_id);
      return 0;
    } else {
      /* Admitted. Persist the identity, the gate's model resolution, the
       * token reservation and the upstream-hygiene switches on the STREAM
       * — the settle/abort paths and the dispatch-time strip/inject read
       * them there, per stream, never from connection state. */
      stream->ai_admitted = 1;
      snprintf(stream->tenant_id, sizeof(stream->tenant_id), "%s",
               adm.tenant_id);
      snprintf(stream->auth_user_id, sizeof(stream->auth_user_id), "%s",
               adm.user_id);
      snprintf(stream->auth_key_id, sizeof(stream->auth_key_id), "%s",
               adm.key_id);
      snprintf(stream->effective_model, sizeof(stream->effective_model), "%s",
               adm.effective_model);
      snprintf(stream->svc_ident, sizeof(stream->svc_ident), "%s",
               adm_svc_ident);
      stream->auth_strip_authz =
        (adm.auth_flags & AI_GW_AUTHF_STRIP_AUTHZ) ? 1 : 0;
      stream->auth_fwd_identity =
        (adm.auth_flags & AI_GW_AUTHF_FWD_IDENTITY) ? 1 : 0;
      stream->auth_jwt_capable =
        (ent->val.ephash->apikey_auth == 3 ||
         ent->val.ephash->apikey_auth == 4) ? 1 : 0;
      if (adm.res_epoch != 0) {
        stream->usage_reserved_toks = adm.reserved_toks;
        stream->usage_res_epoch = adm.res_epoch;
      }
      stream->admit_mono_ns = get_timestamp_ns();
    }
  }
  
  // ✅ FIX: Use stream->authority for HTTP/2 endpoint lookup (not pfe->host_url)
  // In HTTP/2, hostname comes from :authority pseudo-header stored in stream->authority
  // In HTTP/1.1, hostname comes from Host header stored in pfe->host_url
  const char *lookup_host_raw = stream->authority[0] ? stream->authority : "";
  
  // Strip port from :authority before lookup (e.g., "example.com:9090" → "example.com")
  char lookup_host[256];
  strip_port_from_hostname(lookup_host_raw, lookup_host, sizeof(lookup_host));
  
  // P6: Extract path (already available in stream->path, line 331)
  const char *request_path = stream->path[0] ? stream->path : "/";

  // Model for endpoint selection, H1 parity (sockproxy_ep.c Criterion B/C):
  // the gate's resolution wins on enforcing services; non-enforcing services
  // keep the legacy header-first derivation. Derived HERE, before the L7
  // block, so the goto into h2_have_tepval below can never skip it.
  const char *lookup_model = "";
  if (stream->effective_model[0])
    lookup_model = stream->effective_model;
  else if (stream->x_model_header[0])
    lookup_model = stream->x_model_header;
  else if (body_model[0])
    lookup_model = body_model;

  /* Keyless streams settle and are recorded too; give those calls the
   * H1-parity model label (the derived one — non-enforcing services get
   * no gate-resolved model on purpose). Written AFTER the derivation
   * above, so routing semantics are untouched. */
  if (stream->ai_unmetered && !stream->effective_model[0] && lookup_model[0])
    snprintf(stream->effective_model, sizeof(stream->effective_model), "%s",
             lookup_model);
  
  // L7 content-routing discriminator + dispatch — the H2 seam.
  // IDENTICAL shared helper to the H1 seam (sockproxy_ep.c) so the two paths
  // cannot drift (the dominant H1/H2 parity landmine). Runs AFTER the
  // AI-GW gate (untouched) and BEFORE the AI model selection below; a pure no-op
  // when no L7_POLICY is attached (has_l7_policy==0), leaving the AI path
  // byte-for-byte unchanged (Pitfall 5).
  //
  // The engine is pfe-only, but in HTTP/2 the per-request authority/path/method
  // live on the stream — so mirror them into pfe BEFORE dispatch (the contract
  // from -SUMMARY). The generic HEADER/COOKIE store (pfe->l7_headers) is
  // already H2-populated by Plan an earlier cycle's proxy_h2_on_header_callback.
  if (ent && ent->has_l7_policy) {
    proxy_epval_t *l7_tepval = NULL;
    int l7_rc;

    // Mirror the active stream's request operands into pfe (bounded copies).
    if (stream->authority[0]) {
      strncpy(pfe->host_url, stream->authority, sizeof(pfe->host_url) - 1);
      pfe->host_url[sizeof(pfe->host_url) - 1] = '\0';
    }
    strncpy(pfe->request_path, request_path, sizeof(pfe->request_path) - 1);
    pfe->request_path[sizeof(pfe->request_path) - 1] = '\0';
    // url_path carries the full path+query for the QUERY field extractor.
    strncpy(pfe->url_path, request_path, sizeof(pfe->url_path) - 1);
    pfe->url_path[sizeof(pfe->url_path) - 1] = '\0';
#ifdef HAVE_HTTP_TRACE
    /* pfe->http_method only exists under HAVE_HTTP_TRACE (sockproxy.h). Mirror
     * the H2 stream method into it for L7F_METHOD parity with H1 only when the
     * field is compiled in. */
    if (stream->method[0]) {
      strncpy(pfe->http_method, stream->method, sizeof(pfe->http_method) - 1);
      pfe->http_method[sizeof(pfe->http_method) - 1] = '\0';
    }
#endif

    // tell the synthetic responder (proxy_h2_send_l7_synthetic, invoked
    // from l7_send_reject/redirect inside dispatch) which stream a REJECT/REDIRECT
    // must answer — l7_send_* carry only `pfe`, not the stream.
    pfe->h2_session->l7_active_stream_id = stream->stream_id;

    l7_rc = l7_route_dispatch(pfe, ent, &l7_tepval);

    // diagnostic ( H1/H2 parity): make the H2 L7 decision visible
    // in loxilbdp.log so a FORWARD-with-no-pool vs a no-match-REJECT is debuggable.
    log_debug("[HTTP/2][L7] stream=%d host='%s' path='%s' rc=%d tepval=%p",
              stream->stream_id, pfe->host_url, pfe->request_path,
              l7_rc, (void *)l7_tepval);

    pfe->h2_session->l7_active_stream_id = 0;  // clear after dispatch

    if (l7_rc == L7_DISPATCH_TERMINATED) {
      // REJECT / REDIRECT / no-match: the terminal response was framed on THIS
      // h2 stream by proxy_h2_send_l7_synthetic (END_STREAM). Return 0 so the
      // caller marks stream->response_sent=1 — otherwise the next data event would
      // re-dispatch and double-submit on a closed stream.
      return 0;
    } else if (l7_rc == L7_DISPATCH_FORWARD) {
      // FORWARD: a plain pool was resolved; re-enter the existing intra-pool
      // EP-select WITHOUT touching the AI model engine. A NULL pool falls
      // into the existing 502 no-endpoint block below (we still skip the AI LPM).
      tepval = l7_tepval;
      goto h2_have_tepval;
    }
    // L7_DISPATCH_FALLTHROUGH: no L7 policy — fall through to the AI/LPM path.
  }

  // Model-aware endpoint selection: find_endpoint_lpm itself tries the
  // model-specific pool first and falls back to the wildcard, so a
  // model-keyed rule — the normal AI shape — finally resolves on HTTP/2
  // (the old hardwired "" could only ever hit rules stored without a model).
  tepval = find_endpoint_lpm(ent, lookup_host, request_path, lookup_model);

h2_have_tepval:
  if (!tepval) {
    log_error("[HTTP/2] No endpoint found for host=%s path=%s",
              lookup_host, request_path);
    
#ifdef HAVE_HTTP_TRACE
    // CRITICAL: Emit REQ_END for no endpoints available (HTTP 502 Bad Gateway)
    if (pfe->odir == 0 && pfe->root_span_id != 0 && is_tracing_enabled()) {
      uint64_t duration_us = 0;
      if (pfe->req_start_ts > 0) {
        uint64_t now = get_timestamp_ns();
        duration_us = (now - pfe->req_start_ts) / 1000;
      }
      
      // Set HTTP 502 Bad Gateway for no endpoints
      pfe->http_status_code = 502;
      
      log_info("[TRACE_ERROR_H2] fd=%d: Emitting REQ_END with status 502 (no endpoints) duration=%luμs stream_id=%d",
               pfe->fd, duration_us, stream->stream_id);
      
      emit_trace_event(pfe, LXB_EVENT_REQ_END, duration_us);
      pfe->root_span_id = 0;
    }
#endif
    
    /* H1 parity (sockproxy_ep.c Criterion B): a request that NAMED a model
     * for which no pool exists gets a clean 503, not a bare RST — the
     * client can tell "model unavailable" from a transport failure. */
    if (lookup_model[0] && pfe && pfe->h2_session && pfe->h2_session->session) {
      proxy_h2_send_ai_deny(pfe, stream, 503, 0, 0,
                            "model_unavailable",
                            "no backend pool for this model");
      log_info("[MODEL_ROUTING][HTTP/2] 503 sent for model='%s' stream=%d",
               lookup_model, stream->stream_id);
      return 0;
    }

    // Send RST_STREAM to client - no backends available
    if (pfe && pfe->h2_session && pfe->h2_session->session) {
      nghttp2_submit_rst_stream(pfe->h2_session->session, NGHTTP2_FLAG_NONE,
                                stream->stream_id, NGHTTP2_REFUSED_STREAM);
      nghttp2_session_send(pfe->h2_session->session);
    }

    return -1;
  }
  
  // ============================================================================
  // ENDPOINT SELECTION LOGIC (integrates existing routing algorithms)
  // ============================================================================
  
#ifdef HAVE_DP_GPU_ROUTING
  // ============================================================================
  // CHWBL PHASE 1: Extract LLM prefix from JSON request body
  // Mirrors HTTP/1.1 implementation in sockproxy.c:7000-7020
  // ============================================================================
  if ((tepval->select == PROXY_SEL_CHWBL ||
       tepval->select == PROXY_SEL_WRR_HASH) &&
      stream->data_len > 0 && 
      stream->data_buf &&
      stream->prefix_key == NULL) {  // Only extract once per stream
    
    // Check if content-type is application/json (case-insensitive)
    int is_json = 0;
    if (stream->content_type[0] != '\0') {
      is_json = (strncasecmp(stream->content_type, "application/json", 16) == 0);
    }
    
    if (is_json) {
      // Allocate prefix key structure
      llm_prefix_key_t *prefix_key = calloc(1, sizeof(llm_prefix_key_t));
      if (prefix_key) {
        // Extract prefix fields from JSON body
        if (extract_llm_prefix((char *)stream->data_buf, stream->data_len, prefix_key) == 0) {
          // Compute hash for CHWBL routing
          prefix_key->hash = compute_prefix_hash(prefix_key);
          stream->prefix_key = prefix_key;  // Store for routing
          
#ifdef HAVE_PROXY_EXTRA_DEBUG
          log_debug("[HTTP/2 CHWBL] stream %d: Extracted prefix (level=%d, flags=0x%x, hash=0x%lx)",
                    stream->stream_id, prefix_key->level, prefix_key->flags, prefix_key->hash);
#endif
        } else {
          /* Retain the parsed salt status even when no routing prefix was
           * found. The shared policy must still reject a malformed or
           * required-but-missing cache_salt instead of silently falling back. */
          stream->prefix_key = prefix_key;
#ifdef HAVE_PROXY_EXTRA_DEBUG
          log_debug("[HTTP/2 CHWBL] stream %d: Prefix extraction failed, falling back to round-robin",
                    stream->stream_id);
#endif
        }
      } else {
        log_error("[HTTP/2 CHWBL] stream %d: Failed to allocate prefix_key", stream->stream_id);
      }
    }
  }
#endif  // HAVE_DP_GPU_ROUTING
  
  // STATELESS HTTP_COOKIE read-back pin — H2
  // parity with the H1 sockproxy_ep.c pin. When the matched L7 route enables
  // cookie_persist and the request carries a valid LB cookie (read from the
  // H1/H2-parity pfe->l7_headers store, populated in Plan 02), re-derive +
  // constant-time-match the token against the LIVE member set and PIN ep_idx to
  // that member. On a forged/stale token (or no cookie) l7_cookie_node_match
  // returns L7_COOKIE_MISS and ep_idx stays -1 so the normal selection below runs
  // (: never an arbitrary backend). Nothing read/written on proxy_fd_ent
  // works identically on an HA peer that never saw the original request.
  if (ent && ent->has_l7_policy && l7_cookie_persist_active(pfe, ent)) {
    char presented[LB_COOKIE_TOKEN_MAX];
    if (l7_cookie_read_presented(pfe, presented, sizeof(presented)) == 0) {
      int cep = l7_cookie_node_match(ent, tepval, presented);
      if (cep != L7_COOKIE_MISS && cep >= 0 && cep < tepval->n_eps &&
          is_endpoint_healthy(tepval, cep)) {
        ep_idx = cep;
        log_debug("[HTTP/2][COOKIE_PIN] stream %d: valid LB cookie -> ep[%d] (PROXY_AFFINITY_COOKIE)",
                 stream->stream_id, cep);
      } else {
        log_debug("[HTTP/2][COOKIE_MISS] stream %d: no live-member match -> rehash",
                 stream->stream_id);
      }
    }
  }

  // P0.3: Check conversation tracking first (sticky routing)
  if (ep_idx < 0 && stream->has_conv_id && stream->conversation_id[0] != '\0') {
    /* tepval is the pool THIS stream resolved to. A row stored by the other
     * model's pool on this VIP must not answer here: it would both hand us an
     * index chosen for a different endpoint list and suppress the store of our
     * own binding just below. */
    conversation_mapping_t *conv_map =
        get_conversation_mapping(ent, stream->conversation_id, tepval);
    if (conv_map) {
      ep_idx = conv_map->ep_idx;
      
      // Validate endpoint is still healthy
      if (is_endpoint_healthy(tepval, ep_idx)) {
        // Update conversation access time
        conv_map->last_access_ts = time(NULL);
        conv_map->request_count++;
      } else {
        ep_idx = -1;  // Force reselection
      }
    }
  }
  
#ifdef HAVE_DP_GPU_ROUTING
  // CHWBL/WRR_HASH share the same configured hash identity and bounded-load selector.
  if (ep_idx < 0 &&
      (tepval->select == PROXY_SEL_CHWBL || tepval->select == PROXY_SEL_WRR_HASH)) {
    llm_prefix_key_t empty_prefix = {0};
    llm_prefix_key_t *prefix_key = stream->prefix_key ?
        (llm_prefix_key_t *)stream->prefix_key : &empty_prefix;
    int policy_rc = chwbl_hash_and_select_runtime(tepval, prefix_key, &ep_idx);
    if (policy_rc == -2) {
      proxy_h2_send_l7_synthetic(pfe, 400, NULL, NULL);
      return -1;
    }
    if (policy_rc != 0)
      ep_idx = -1;
  }
  
  // P5: GPU-Aware routing (if enabled and no CHWBL match)
  if (ep_idx < 0 && pfe->seltype == PROXY_SEL_GPU_AWARE) {
    // GPU-aware routing would go here (uses catalog-based scoring)
    // For now, fall through to health-based selection
    log_debug("[HTTP/2] stream %d: GPU-aware routing not yet implemented for HTTP/2", stream->stream_id);
  }
#endif  // HAVE_DP_GPU_ROUTING
  
  // Fallback: Use existing endpoint selection (round-robin, hash, etc.)
  if (ep_idx < 0) {
    // TODO (HTTP/2 Transit Mode): Replace with direct HTTP/2 routing logic
    // Currently falls through to round-robin selection
    // See IMPL_PHASE1_HTTP2_TRANSIT_MODES_IMPLEMENTATION_DESIGN.md Section 3.3
    
    if (tepval->n_eps <= 0) {
      log_error("[HTTP/2] stream %d: Invalid n_eps=%d", stream->stream_id, tepval->n_eps);
      return -1;
    }
    
    // Simple round-robin fallback for now
    static int rr_counter = 0;
    int counter_val = rr_counter++;
    ep_idx = (counter_val % tepval->n_eps);
  }
  ep_idx = select_healthy_endpoint(tepval, ep_idx);
  if (ep_idx < 0) {
    log_error("[HTTP/2] stream %d: No healthy endpoint available", stream->stream_id);
    
#ifdef HAVE_HTTP_TRACE
    // CRITICAL: Emit REQ_END for no healthy endpoints (HTTP 502 Bad Gateway)
    if (pfe->odir == 0 && pfe->root_span_id != 0 && is_tracing_enabled()) {
      uint64_t duration_us = 0;
      if (pfe->req_start_ts > 0) {
        uint64_t now = get_timestamp_ns();
        duration_us = (now - pfe->req_start_ts) / 1000;
      }
      
      // Set HTTP 502 Bad Gateway for unhealthy endpoints
      pfe->http_status_code = 502;
      
      log_info("[TRACE_ERROR_H2] fd=%d: Emitting REQ_END with status 502 (no healthy endpoints) duration=%luμs stream_id=%d",
               pfe->fd, duration_us, stream->stream_id);
      
      emit_trace_event(pfe, LXB_EVENT_REQ_END, duration_us);
      pfe->root_span_id = 0;
    }
#endif
    
    // Send RST_STREAM to client - no backends available
    int32_t failed_stream_id = stream ? stream->stream_id : -1;
    if (pfe && pfe->h2_session && pfe->h2_session->session && failed_stream_id > 0) {
      nghttp2_submit_rst_stream(pfe->h2_session->session, NGHTTP2_FLAG_NONE,
                                failed_stream_id, NGHTTP2_REFUSED_STREAM);
      nghttp2_session_send(pfe->h2_session->session);
    }
    
    return -1;
  }
  
  if (ep_idx >= tepval->n_eps) {
    log_error("[HTTP/2] stream %d: ep_idx=%d >= n_eps=%d (invalid endpoint index)",
              stream->stream_id, ep_idx, tepval->n_eps);
    
    // Send RST_STREAM to client - internal error
    int32_t failed_stream_id = stream ? stream->stream_id : -1;
    if (pfe && pfe->h2_session && pfe->h2_session->session && failed_stream_id > 0) {
      nghttp2_submit_rst_stream(pfe->h2_session->session, NGHTTP2_FLAG_NONE,
                                failed_stream_id, NGHTTP2_INTERNAL_ERROR);
      nghttp2_session_send(pfe->h2_session->session);
    }
    
    return -1;
  }

  // ============================================================================
  // CRITICAL: Set endpoint context for statistics accounting
  // HTTP/2 forwards per-stream, so we set the client pfe's endpoint info
  // to track stats for the selected backend endpoint. These two fields are
  // connection-scoped last-write state kept for the byte accounting only —
  // no per-stream decision may read them back (the settle dialect reads
  // stream->route_epv, the cookie path reads the backend session's epv).
  // ============================================================================
  pfe->epv = tepval;
  pfe->ep_num = ep_idx;
  stream->route_epv = tepval;

  // Store conversation mapping if this is first request
  if (stream->has_conv_id && stream->conversation_id[0] != '\0') {
    if (!get_conversation_mapping(ent, stream->conversation_id, tepval)) {
      if (store_conversation_endpoint(ent, stream->conversation_id, ep_idx,
                                      tepval) == 0) {
        log_debug("[HTTP/2] stream %d: Stored conversation mapping: %s → ep[%d]",
                  stream->stream_id, stream->conversation_id, ep_idx);
      }
    }
  }

  // ============================================================================
  // BACKEND CONNECTION & FORWARDING
  // ============================================================================

  // Backend SSL connection handle (for end-to-end HTTPS mode)
  void *backend_ssl = NULL;

  /* Backend-connection identity is (pool, endpoint-in-pool), NEVER the
   * endpoint index alone: with model-keyed rules one connection carries
   * streams of several pools and every pool's eps[] starts at 0, so an
   * index-keyed cache hands pool B's stream the connection dialed for
   * pool A. rfd[]/rfd_ent[] therefore hold SLOTS: reuse requires the
   * registered backend pfe to match BOTH the pool (epv) and the
   * pool-relative endpoint index; a miss allocates the first free slot. */
  int slot = -1;
  for (int i = 0; i < pfe->n_rfd && i < MAX_PROXY_EP; i++) {
    proxy_fd_ent_t *bpfe = pfe->rfd_ent[i];
    if (bpfe && bpfe->epv == (void *)tepval && bpfe->ep_num == ep_idx &&
        pfe->rfd[i] > 0) {
      slot = i;
      backend_fd = pfe->rfd[i];
      break;
    }
  }
  if (slot < 0) {
    for (int i = 0; i < MAX_PROXY_EP; i++) {
      if (pfe->rfd_ent[i] == NULL) {
        slot = i;
        break;
      }
    }
    if (slot < 0) {
      log_error("[HTTP/2] stream %d: no free backend slot (all %d in use)",
                stream->stream_id, MAX_PROXY_EP);
      if (pfe->h2_session && pfe->h2_session->session) {
        nghttp2_submit_rst_stream(pfe->h2_session->session, NGHTTP2_FLAG_NONE,
                                  stream->stream_id, NGHTTP2_REFUSED_STREAM);
        nghttp2_session_send(pfe->h2_session->session);
      }
      return -1;
    }
  }

  if (backend_fd <= 0) {
    if (!tepval) {
      log_error("[HTTP/2] CRITICAL: tepval is NULL!");
      return -1;
    }
    
    if (ep_idx < 0 || ep_idx >= tepval->n_eps) {
      log_error("[HTTP/2] CRITICAL: ep_idx=%d out of bounds (n_eps=%d)",
                ep_idx, tepval->n_eps);
      return -1;
    }
    
    // Access endpoint configuration
    uint32_t ep_ip = tepval->eps[ep_idx].xip;
    uint16_t ep_port = tepval->eps[ep_idx].xport;
    uint8_t ep_proto = tepval->eps[ep_idx].protocol;
    
    // Use proxy_setup_ep_connect to create backend connection
    extern int proxy_setup_ep_connect(uint32_t epip, uint16_t epport, uint8_t protocol,
                                       void *ssl_ctx, void **ssl, proxy_fd_ent_t *pfe,
                                       const void *pp2hdr, int pp2len);

    /* PROXY protocol v2 (L7 fullproxy, HTTP/2 backend path): emit the client's
     * real 4-tuple ahead of the backend stream when the rule enables ppv2. The
     * client fd (pfe->fd) yields client via getpeername and the dialed VIP via
     * getsockname — the same tuple setup_proxy_path derives from the sockmap key. */
    uint8_t pp2buf[28];
    int pp2len = 0;
    if (ent->val.ppv2 && ep_proto == IPPROTO_TCP) {
      struct sockaddr_in cli, vip;
      socklen_t cl = sizeof(cli), vl = sizeof(vip);
      if (getpeername(pfe->fd, (struct sockaddr *)&cli, &cl) == 0 &&
          getsockname(pfe->fd, (struct sockaddr *)&vip, &vl) == 0 &&
          cli.sin_family == AF_INET && vip.sin_family == AF_INET) {
        pp2len = proxy_build_ppv2_v4(pp2buf, sizeof(pp2buf),
                                     cli.sin_addr.s_addr, cli.sin_port,   /* src = client */
                                     vip.sin_addr.s_addr, vip.sin_port);  /* dst = VIP */
      }
    }

    // CRITICAL FIX: For end-to-end HTTPS mode, we need to establish SSL to backend
    // Client → LoxiLB: HTTPS (TLS)
    // LoxiLB → Backend: HTTPS (TLS) - for tcp:e2ehttps mode
    //
    // We must provide a valid pointer to store the SSL handle, not NULL!
    
    backend_fd = proxy_setup_ep_connect(ep_ip, ep_port, ep_proto,
                                         ent->val.ssl_epctx,  // SSL context for backend
                                         ent->val.ssl_epctx ? &backend_ssl : NULL,  // Store SSL handle
                                         pfe,  // Pass pfe for trace events
                                         (pp2len ? pp2buf : NULL), pp2len);  // L7 fullproxy PPv2
    
    if (backend_fd <= 0) {
      log_error("[HTTP/2] stream %d: Failed to connect to backend ep[%d]", stream->stream_id, ep_idx);
      
#ifdef HAVE_HTTP_TRACE
      // CRITICAL: Emit REQ_END for backend connection failure (HTTP 502 Bad Gateway)
      if (pfe->odir == 0 && pfe->root_span_id != 0 && is_tracing_enabled()) {
        uint64_t duration_us = 0;
        if (pfe->req_start_ts > 0) {
          uint64_t now = get_timestamp_ns();
          duration_us = (now - pfe->req_start_ts) / 1000;
        }
        
        // Set HTTP 502 Bad Gateway for backend connection failure
        pfe->http_status_code = 502;
        
        log_info("[TRACE_ERROR_H2] fd=%d: Emitting REQ_END with status 502 (backend connect failed) duration=%luμs stream_id=%d",
                 pfe->fd, duration_us, stream->stream_id);
        
        emit_trace_event(pfe, LXB_EVENT_REQ_END, duration_us);
        pfe->root_span_id = 0;
      }
#endif
      
      // P2 Task 2.3: Record circuit breaker failure
      if (tepval) {
        circuit_breaker_record_failure(tepval, ep_idx);
      }
      
      // ============================================================================
      // Send 503 Service Unavailable to client (better UX than RST_STREAM)
      // Client receives proper HTTP status code instead of protocol error
      // ============================================================================
      
      int32_t failed_stream_id = stream ? stream->stream_id : -1;
      
      if (pfe && pfe->h2_session && pfe->h2_session->session && failed_stream_id > 0) {
        // Send HTTP/2 headers with 503 status + END_STREAM flag (no body needed)
        nghttp2_nv hdrs[] = {
          {(uint8_t *)":status", (uint8_t *)"503", 7, 3, NGHTTP2_NV_FLAG_NONE},
          {(uint8_t *)"content-length", (uint8_t *)"0", 14, 1, NGHTTP2_NV_FLAG_NONE},
        };
        
        nghttp2_submit_response(pfe->h2_session->session, failed_stream_id,
                                hdrs, 2, NULL);  // NULL data provider = no body
        
        nghttp2_session_send(pfe->h2_session->session);
      }
      
      return -1;
    }
    
    pfe->rfd[slot] = backend_fd;
    pfe->n_rfd = (slot + 1 > pfe->n_rfd) ? slot + 1 : pfe->n_rfd;

    // P2 Task 2.3: Record circuit breaker success
    circuit_breaker_record_success(tepval, ep_idx);
  }
  
  // ============================================================================
  // HTTP/2 TRANSIT MODE: Forward request to backend via HTTP/2
  // ============================================================================
  
  // Get or create backend HTTP/2 session
  // Pass backend_ssl (actual SSL connection) not ssl_epctx (SSL context)
  backend_h2_session_t *backend_session = proxy_h2_get_backend_session(
    pfe->h2_session, pfe, slot, ep_idx, tepval, backend_fd, backend_ssl);
  
  if (!backend_session) {
    log_error("[HTTP/2] stream %d: Failed to create backend HTTP/2 session for ep[%d]",
              stream->stream_id, ep_idx);
    
    // Send error to client
    if (pfe->h2_session && pfe->h2_session->session) {
      nghttp2_submit_rst_stream(pfe->h2_session->session, NGHTTP2_FLAG_NONE,
                                 stream->stream_id, NGHTTP2_INTERNAL_ERROR);
      nghttp2_session_send(pfe->h2_session->session);
    }
    
    return -1;
  }
  
  // ============================================================================
  // CRITICAL FIX: Register backend fd with event loop for HTTP/2 responses
  // This is the missing piece that prevented backend responses from being handled
  // ============================================================================
  // Pattern follows HTTP/1.1 implementation in sockproxy.c:3500-3600
  //
  // Why this is needed:
  //   1. Backend connection is established (backend_fd valid)
  //   2. Request is sent to backend (nghttp2_submit_request)
  //   3. Backend responds → data sits in TCP buffer
  //   4. WITHOUT notify_add_ent: Event loop NEVER calls proxy_h2_handle_backend_data()
  //   5. WITH notify_add_ent: Event loop detects NOTI_TYPE_IN → calls proxy_notifier()
  //                           → proxy_notifier() sees backend pfe → processes response
  //
  // Only register if this is a NEW backend connection (not reused)
  if (pfe->rfd_ent[slot] == NULL) {
    // Create proxy_fd_ent_t for backend connection
    proxy_fd_ent_t *backend_pfe = pfe_alloc();   /* D2 root fix: pooled pfe shell */
    if (!backend_pfe) {
      log_error("[HTTP/2] stream %d: Failed to allocate backend pfe for fd=%d",
                stream->stream_id, backend_fd);
      /* No pfe ever took the fd, so this path owns the close — and the
       * session, already in the reuse hash, must go with it or a later slot
       * probe submits streams into a closed descriptor. */
      HASH_DEL(pfe->h2_session->backend_sessions, backend_session);
      proxy_h2_backend_session_destroy(backend_session);
      close(backend_fd);
      return -1;
    }
    
    // Setup backend pfe metadata (same pattern as HTTP/1.1)
    backend_pfe->fd = backend_fd;
    backend_pfe->ssl = backend_ssl;
    backend_pfe->odir = 1;                    // Backend direction (outbound from proxy)
    backend_pfe->head = ent;                  // Link to proxy_map_ent_t
    backend_pfe->protocol_version = 2;        // HTTP/2
    backend_pfe->ep_num = ep_idx;             // Endpoint index INSIDE its pool —
    backend_pfe->epv = tepval;                // with epv this pair IS the slot's
                                              // reuse identity (see slot search)
    backend_pfe->stype = PROXY_SOCK_ACTIVE;   // Active connection
    backend_pfe->used = 1;                    // Mark as in use
    backend_pfe->backend_h2_session = backend_session;  // For event handler lookup
    
    // Link backend pfe to client pfe (bidirectional)
    pfe->rfd_ent[slot] = backend_pfe;
    backend_pfe->rfd_ent[0] = pfe;            // Back-link to client pfe
    backend_pfe->n_rfd = 1;

    /* Link the leg into the rule's connection list like every other leg, and
     * do it before the fd is registered: registration publishes the shell to
     * its worker, which may tear the leg down at once, and a teardown must
     * find the node it unlinks. Linked legs are also what the health passes
     * and the metrics walkers see. */
    proxy_conn_list_add(ent, backend_pfe, "HTTP/2 backend");

    // ✅ CRITICAL: Register with event loop - enables backend response handling
    /* Pinned to the CLIENT fd's notify worker: every handler touching the
     * client's h2_session (proxy_h2_handle_backend_data walks its hashes with
     * no client lock held) then serializes with proxy_pdestroy freeing that
     * session — the same single-worker guarantee the HTTP/1.1 backend path
     * has relied on since the conc=128 wedge fix. */
    if (proxy_notify_add_fd_pinned(backend_fd, NOTI_TYPE_IN|NOTI_TYPE_HUP,
                                   backend_pfe, pfe->fd) != 0) {
      log_error("[HTTP/2] stream %d: Failed to register backend fd=%d with event loop",
                stream->stream_id, backend_fd);
      proxy_conn_list_del(ent, backend_pfe);   /* nothing was published: take it off the list */
      pfe->rfd_ent[slot] = NULL;
      pfe->rfd[slot] = -1;         /* the fd closes below; a stale positive here
                                    * would satisfy the reuse probe forever */
      pfe_recycle(backend_pfe);      /* pool the shell (frees rcvbuf, bumps gen) */
      /* The registration failed, so nothing will ever evict this fd and the
       * recycled shell no longer owns it: close it here. The session was
       * created around that fd and is already in the reuse hash, so it must
       * leave NOW or a later slot probe adopts a dead (possibly
       * kernel-recycled) descriptor number. */
      HASH_DEL(pfe->h2_session->backend_sessions, backend_session);
      proxy_h2_backend_session_destroy(backend_session);
      close(backend_fd);
      return -1;
    }
  }
  
  // ============================================================================
  // GENERIC HEADER FORWARDING: Use all collected headers for protocol transparency
  // This enables gRPC, WebSocket over HTTP/2, and any custom HTTP/2 protocols
  // ============================================================================

  // Verify we have headers to forward (should always be true after on_header_callback)
  if (!stream->request_headers || stream->request_headers_count == 0) {
    log_error("[HTTP/2] stream %d: No request headers collected for forwarding", stream->stream_id);
    return -1;
  }


  // Use the stored headers directly (already in nghttp2_nv format)
  // This includes ALL headers: pseudo-headers (:method, :path, etc.) + regular headers (te, grpc-*, etc.)
  nghttp2_nv *headers = stream->request_headers;
  size_t nheaders = stream->request_headers_count;

  /* on the L7_Proxy peer (has_l7_policy)
   * build an AUGMENTED nv array — always-overwrite X-Forwarded-For (real TCP peer
   * IP) + X-Forwarded-Port/Proto + insertHeaders SET/ADD/REMOVE — via the SAME
   * shared l7_apply_req_filters() the H1 path uses (Pitfall 1 parity; nghttp2_nv
   * only, never raw \r\n bytes). No-op for the AI peer (has_l7_policy==0): the
 * original headers are submitted byte-for-byte unchanged. */
  nghttp2_nv *l7_headers_nv = NULL;
  l7h2_emit_ctx_t l7_hdr_ctx;
  int l7_hdr_built = 0;
  if (ent && ent->has_l7_policy) {
    size_t l7_n = 0;
    if (proxy_h2_build_l7_req_headers(pfe, ent, headers, nheaders, pfe->fd,
                                      &l7_headers_nv, &l7_n, &l7_hdr_ctx) == 0) {
      headers = l7_headers_nv;
      nheaders = l7_n;
      l7_hdr_built = 1;
    }
    /* On build failure (OOM) headers/nheaders stay the originals — fail-open to
     * the unmodified request rather than dropping it. */
  }

  /* Upstream hygiene AFTER optional L7 mutation (so a header rule cannot
   * re-add a stripped credential) and BEFORE nghttp2_submit_request: the
   * gateway credential strip, plus — parity with the H1 splice — the
   * client X-Auth-* spoof strip, the consumed-Authorization strip and the
   * verified-identity injection on JWT-capable rules. Allocation failure
   * fails closed for services that claimed a credential namespace;
   * forwarding the secret is never an acceptable fallback. */
  nghttp2_nv *security_headers_nv = NULL;
  int security_headers_built = 0;
  uint8_t security_policy = ent->val.ephash ? ent->val.ephash->apikey_auth : 0;
  int hygiene_jwt = stream->ai_admitted && stream->auth_jwt_capable;
  if (ai_security_should_strip_api_key(security_policy) || hygiene_jwt) {
    size_t hygiene_cap = nheaders + 2;   /* + injected X-Auth-Tenant/User */
    security_headers_nv = calloc(hygiene_cap, sizeof(*security_headers_nv));
    if (!security_headers_nv) {
      if (l7_hdr_built)
        proxy_h2_free_l7_req_headers(l7_headers_nv, &l7_hdr_ctx);
      log_error("[AIGateway][HTTP/2] cannot allocate credential-safe header set");
      return -1;
    }
    nheaders = ai_security_h2_upstream_hygiene(
        headers, nheaders, security_headers_nv, hygiene_cap,
        security_policy, hygiene_jwt,
        stream->auth_strip_authz, stream->auth_fwd_identity,
        stream->tenant_id, stream->auth_user_id);
    headers = security_headers_nv;
    security_headers_built = 1;
  }

  // Prepare data provider for request body (if present)
  nghttp2_data_provider data_prd;
  nghttp2_data_provider *data_prd_ptr = NULL;
  h2_data_source_t *data_src = NULL;

  if (stream->data_len > 0 && stream->data_buf) {
    // Allocate data source wrapper (will be freed when stream closes)
    data_src = malloc(sizeof(h2_data_source_t));
    if (!data_src) {
      log_error("[HTTP/2] stream %d: Failed to allocate data source", stream->stream_id);
      free(security_headers_nv);
      if (l7_hdr_built)
        proxy_h2_free_l7_req_headers(l7_headers_nv, &l7_hdr_ctx);
      return -1;
    }

    data_src->data = stream->data_buf;
    data_src->len = stream->data_len;
    data_src->offset = 0;

    data_prd.source.ptr = data_src;
    data_prd.read_callback = proxy_h2_data_read_callback;
    data_prd_ptr = &data_prd;
  }
  
  // Submit request to backend
  pthread_mutex_lock(&backend_session->send_lock);
  
  int32_t backend_stream_id = nghttp2_submit_request(
    backend_session->session,
    NULL,  // No priority
    headers,
    nheaders,
    data_prd_ptr,
    NULL   // No stream user data
  );

  pthread_mutex_unlock(&backend_session->send_lock);

  /* nghttp2_submit_request has copied the nv name/value bytes into its own
   * HPACK buffers, so the staging copies + array can be freed now. */
  if (l7_hdr_built) {
    proxy_h2_free_l7_req_headers(l7_headers_nv, &l7_hdr_ctx);
    l7_headers_nv = NULL;
    l7_hdr_built = 0;
  }
  if (security_headers_built) {
    free(security_headers_nv);
    security_headers_nv = NULL;
    security_headers_built = 0;
  }

  if (backend_stream_id < 0) {
    log_error("[HTTP/2] stream %d: nghttp2_submit_request failed: %s",
              stream->stream_id, nghttp2_strerror(backend_stream_id));
    
    // P2 Task 2.3: Record circuit breaker failure
    circuit_breaker_record_failure(tepval, ep_idx);
    
    // Send error to client
    if (pfe->h2_session && pfe->h2_session->session) {
      nghttp2_submit_rst_stream(pfe->h2_session->session, NGHTTP2_FLAG_NONE,
                                 stream->stream_id, NGHTTP2_INTERNAL_ERROR);
      nghttp2_session_send(pfe->h2_session->session);
    }
    
    return -1;
  }
  
  // Create stream mapping (client_stream_id → backend_stream_id)
  stream_mapping_t *mapping = calloc(1, sizeof(stream_mapping_t));
  if (!mapping) {
    log_error("[HTTP/2] stream %d: Failed to allocate stream mapping", stream->stream_id);
    return -1;
  }
  
  mapping->client_stream_id = stream->stream_id;
  mapping->backend_stream_id = backend_stream_id;
  mapping->ep_idx = ep_idx;
  mapping->created_ts = time(NULL);
  mapping->data_source = data_src;  // Store for cleanup (NULL if no request body)

  HASH_ADD_INT(backend_session->stream_map, client_stream_id, mapping);
  
#ifdef HAVE_DP_GPU_ROUTING
  // Update endpoint load (CRITICAL-4 FIX: Use atomic operations)
  if (tepval->chwbl_config) {
    atomic_fetch_add(&tepval->chwbl_config->ep_loads[ep_idx].active_conns, 1);
  }
#endif
  
  if (h2_backend_flush(backend_session, pfe->rfd_ent[slot], backend_fd) < 0) {
    return -1;
  }
  
  // P2 Task 2.3: Record circuit breaker success
  circuit_breaker_record_success(tepval, ep_idx);
  
  // CRITICAL-1 FIX: Free prefix_key after successful forwarding
  if (stream->prefix_key) {
    free(stream->prefix_key);
    stream->prefix_key = NULL;
  }
  
  return 0;
}

/**
 * Extract HTTP/2 header value from stream
 * TODO: Implement proper header storage in Week 2
 */
int
proxy_h2_get_header(proxy_h2_stream_t *stream, const char *header_name,
                    char *value_buf, size_t value_size)
{
  if (!stream || !header_name || !value_buf) {
    return -1;
  }
  
  // For now, only support headers we store in stream struct
  if (strcmp(header_name, ":method") == 0) {
    snprintf(value_buf, value_size, "%s", stream->method);
    return 0;
  } else if (strcmp(header_name, ":path") == 0) {
    snprintf(value_buf, value_size, "%s", stream->path);
    return 0;
  } else if (strcmp(header_name, ":authority") == 0) {
    snprintf(value_buf, value_size, "%s", stream->authority);
    return 0;
  } else if (strcmp(header_name, "content-type") == 0) {
    snprintf(value_buf, value_size, "%s", stream->content_type);
    return 0;
  } else if (strcmp(header_name, "x-conversation-id") == 0) {
    if (stream->has_conv_id) {
      snprintf(value_buf, value_size, "%s", stream->conversation_id);
      return 0;
    }
  }
  
  return -1;  // Header not found
}
