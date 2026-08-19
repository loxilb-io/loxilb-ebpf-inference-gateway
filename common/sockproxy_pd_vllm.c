/* sockproxy_pd_vllm.c - vLLM SEQUENTIAL P/D disaggregation machine
 *
 * Dialect: vLLM sequential P/D (KV-connector-agnostic — we relay
 *   kv_transfer_params, never move KV ourselves).
 * Contract validated against: vLLM v0.17.0 (kv_transfer_params shape,
 *   do_remote_decode/do_remote_prefill, remote_block_ids relay).
 * Known caps: 64KB kv_transfer_params buffer (PD_KV_PARAMS_MAX_LEN;
 *   pd_kv_params_max trims it per rule at runtime) — overflow degrades to
 *   decode-side prefill recompute, never a request failure.
 * Machine shape: prefill probe rewrite (max_tokens=1, stream=false)
 *   → prefill send (leg slot 0) → response parse + kv_transfer_params
 *   extract → decode request rebuild + re-dispatch (leg slot 1)
 *   → mid-request prefill retry on a dead prefill leg.
 * Last re-validated: 2026-08 full long-context GPU suite green
 *   (56/56 incl. the G1/G1b/G2/G3 gates).
 *
 * TensorRT-LLM note: its disaggregation is sequential ctx-first — a
 * parameterization of THIS machine (see the dialect resolver). A dedicated
 * sockproxy_pd_trtllm.c only appears once its contract diverges.
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

/* Rewrite the prefill address inside a P/D request-id receipt
 * (___prefill_addr_<ep>___decode_addr_<ep>_<uuid>) within an HTTP header
 * block. buf/len describe the full request; the search is bounded to the
 * header region. Returns 0 when a rewrite happened, -1 otherwise. */
static int
pd_receipt_rewrite(uint8_t *buf, size_t *len, size_t cap, const char *n_addr)
{
  uint8_t *he = memmem(buf, *len, "\r\n\r\n", 4);
  size_t hdr_len = he ? (size_t)(he + 4 - buf) : 0;
  char *tag = hdr_len ? memmem(buf, hdr_len, "___prefill_addr_", 16) : NULL;
  char *a_start = tag ? tag + 16 : NULL;
  char *a_end = a_start ? memmem(a_start, (size_t)((char *)buf + hdr_len - a_start),
                                 "___decode_addr_", 15) : NULL;
  if (!a_start || !a_end) return -1;

  int n_len = (int)strlen(n_addr);
  int o_len = (int)(a_end - a_start);
  int shift = n_len - o_len;
  if (n_len <= 0 || *len + (size_t)(shift > 0 ? shift : 0) > cap) return -1;
  if (shift != 0) {
    memmove(a_end + shift, a_end, *len - (size_t)(a_end - (char *)buf));
    *len = (size_t)((ssize_t)*len + shift);
  }
  memcpy(a_start, n_addr, (size_t)n_len);
  return 0;
}

/* Initiate decode phase after prefill completes.
 * Creates a new backend connection to the decode EP, builds the decode request
 * (original body + kv_params), and sends it. The decode response will flow to
 * the client via normal proxy path (including SSE streaming). */
int
pd_initiate_decode(proxy_fd_ent_t *client_pfe)
{
  proxy_epval_t *tepval;
  int d_idx;
  uint32_t epip;
  uint16_t epport;
  int ep_cfd;
  int ret = -1;
  uint8_t *decode_body = NULL;
  uint8_t *decode_req = NULL;

  if (!client_pfe || !client_pfe->epv) return -1;

  tepval = (proxy_epval_t *)client_pfe->epv;
  d_idx = client_pfe->pd_decode_ep_idx;

  if (d_idx < 0 || d_idx >= tepval->n_eps) {
    log_error("Invalid decode EP index %d", d_idx);
    return -1;
  }

  /* the decode EP was picked at ADMISSION but is only connected NOW,
   * after prefill completed — a seconds-wide window under long-context
   * prefill during which the EP can die. Until this check, only index
   * bounds were re-validated, so a decode node dying during prefill meant a
   * connect to a known-dead EP (sync 503, or async zero-byte EOF =).
   * Re-check inv/CB and re-select via pd_select_decode (min-load among
   * healthy decode EPs — the admission scorer) with the stale hint cleared.
   * On re-selection, MOVE the admission-time active_conns unit so
   * pd_cleanup's decrement of the final pd_decode_ep_idx stays balanced.
   * Runs BEFORE the buffer claims below, so the -1 path (no healthy decode
   * EP) leaves saved body/headers for the caller's 503+cleanup. */
  if (tepval->eps[d_idx].inv ||
      (tepval->cb_enabled &&
       tepval->circuit_breakers[d_idx].state == CB_STATE_OPEN)) {
    int stale_idx = d_idx;
    int re_idx = -1;
    client_pfe->pd_decode_ep_idx = -1;  /* clear hint: force fresh min-load pick */
    if (pd_select_decode(tepval, client_pfe, &re_idx) == 0) {
      log_error("decode EP%d went unhealthy during prefill — "
                "re-selected healthy decode EP%d (client_fd=%d)",
                stale_idx, re_idx, client_pfe->fd);
      uint32_t cur_stale =
          atomic_load(&tepval->pd_ep_loads[stale_idx].active_conns);
      if (cur_stale > 0)
        atomic_fetch_sub(&tepval->pd_ep_loads[stale_idx].active_conns, 1);
      atomic_fetch_add(&tepval->pd_ep_loads[re_idx].active_conns, 1);
      d_idx = re_idx;  /* pd_select_decode already stored it in the pfe */
    } else {
      client_pfe->pd_decode_ep_idx = stale_idx;  /* restore for cleanup/logs */
      log_error("decode EP%d unhealthy after prefill and NO healthy "
                "replacement — failing decode init (client_fd=%d)",
                stale_idx, client_pfe->fd);
      return -1;
    }
  }

  /* (conc=128 UAF fix): pd_initiate_decode runs on the PREFILL worker
   * and reads three heap buffers (pd_prefill_resp_buf / pd_saved_body /
   * pd_saved_headers) off the shared client pfe, while pd_cleanup() can free the
   * SAME buffers concurrently on the CLIENT-fd worker on client-close (see the
 * pd_free_claim banner for the cross-worker sharding). closed the
   * free-vs-free double-free; this surviving use-vs-free read freed memory and
   * corrupted the heap under load. Atomically CLAIM the buffers into locals so
   * THIS function becomes their single owner — a racing pd_cleanup() then
   * observes NULL for these fields and frees nothing. Lock-free, matching
   * pd_free_claim(). All three locals are freed at the single `out:` exit. */
  size_t l_prefill_len = client_pfe->pd_prefill_resp_len;
  uint8_t *l_prefill = __atomic_exchange_n(&client_pfe->pd_prefill_resp_buf,
                                           NULL, __ATOMIC_ACQ_REL);
  if (!l_prefill) l_prefill_len = 0; else client_pfe->pd_prefill_resp_len = 0;

  size_t l_body_len = client_pfe->pd_saved_body_len;
  uint8_t *l_body = __atomic_exchange_n(&client_pfe->pd_saved_body,
                                        NULL, __ATOMIC_ACQ_REL);
  if (!l_body) l_body_len = 0; else client_pfe->pd_saved_body_len = 0;

  size_t l_headers_len = client_pfe->pd_saved_headers_len;
  uint8_t *l_headers = __atomic_exchange_n(&client_pfe->pd_saved_headers,
                                           NULL, __ATOMIC_ACQ_REL);
  if (!l_headers) l_headers_len = 0; else client_pfe->pd_saved_headers_len = 0;

  /* 1. Extract kv_params from prefill response */
  /* Determine effective KV params capacity: runtime config or compile-time max */
  size_t kv_capacity = sizeof(client_pfe->pd_kv_params);
  proxy_epval_t *kv_epv = (proxy_epval_t *)client_pfe->epv;
  if (kv_epv && kv_epv->pd_kv_params_max > 0 &&
      kv_epv->pd_kv_params_max < kv_capacity) {
      kv_capacity = kv_epv->pd_kv_params_max;
  }
  int kv_ret = pd_extract_kv_params(l_prefill,
                       l_prefill_len,
                       client_pfe->pd_kv_params,
                       &client_pfe->pd_kv_params_len,
                       kv_capacity);
  if (kv_ret == -EMSGSIZE) {
    log_error("kv_transfer_params overflow (%zu bytes) — decode will recompute prefill",
              l_prefill_len);
    /* Graceful degradation: pd_kv_params_len already set to 0 */
  } else if (kv_ret == -ENOENT) {
    log_debug("kv_transfer_params not found in prefill response — decode will recompute");
    /* Normal for non-NIXL vLLM — proceed without KV params */
  } else if (kv_ret == -EINVAL) {
    log_error("pd_extract_kv_params: invalid arguments (should not happen)");
  }

  /* 2. Build decode request body with kv_transfer_params injection */
  size_t decode_body_cap = l_body_len + 8192;
  decode_body = malloc(decode_body_cap);
  if (!decode_body) {
    log_error("malloc failed for decode_body");
    goto out;
  }

  size_t decode_body_len = 0;
  if (pd_prepare_decode_body(l_body,
                             l_body_len,
                             client_pfe->pd_kv_params,
                             client_pfe->pd_kv_params_len,
                             decode_body, &decode_body_len,
                             decode_body_cap) != 0) {
    log_error("pd_prepare_decode_body failed");
    goto out;
  }

  /* 3. Build complete decode HTTP request: saved headers + updated CL + decode body */
  size_t decode_req_cap = l_headers_len + decode_body_len + 256;
  decode_req = malloc(decode_req_cap);
  if (!decode_req) {
    log_error("malloc failed for decode_req");
    goto out;
  }

  /* Copy saved headers (includes \r\n\r\n) and append decode body */
  memcpy(decode_req, l_headers, l_headers_len);
  memcpy(decode_req + l_headers_len, decode_body, decode_body_len);
  size_t decode_req_len = l_headers_len + decode_body_len;

  /* Update Content-Length for decode body */
  pd_update_content_length(decode_req, &decode_req_len, decode_req_cap, decode_body_len);
  /* R2 [FRAME_MISMATCH] instrument (log-only): decode-request reconstruction CL-rewrite
   * site. decl_cl uses the rewritten decode body len so candidate-2
   * (CL-rewrite mismatch on the decode leg) is distinguishable from the
   * prefill paths. cur_len = the reconstructed request length. */
  pd_frame_mismatch_log(client_pfe, decode_req, decode_req_len, decode_body_len,
                        "cl_rewrite_decode");

  /* 4. Connect to decode EP */
  epip = tepval->eps[d_idx].xip;
  epport = tepval->eps[d_idx].xport;

  /* PROXY protocol v2 (L7 fullproxy, P/D decode leg): prepend the client 4-tuple
   * when the rule enables ppv2, consistent with the prefill/HTTP1/HTTP2 backend
   * legs. Derived from the client fd (getpeername=client, getsockname=VIP). */
  uint8_t dpp2buf[28];
  int dpp2len = 0;
  {
    proxy_map_ent_t *dent = (proxy_map_ent_t *)client_pfe->head;
    if (dent && dent->val.ppv2) {
      struct sockaddr_in cli, vip;
      socklen_t cl = sizeof(cli), vl = sizeof(vip);
      if (getpeername(client_pfe->fd, (struct sockaddr *)&cli, &cl) == 0 &&
          getsockname(client_pfe->fd, (struct sockaddr *)&vip, &vl) == 0 &&
          cli.sin_family == AF_INET && vip.sin_family == AF_INET) {
        dpp2len = proxy_build_ppv2_v4(dpp2buf, sizeof(dpp2buf),
                                      cli.sin_addr.s_addr, cli.sin_port,   /* src = client */
                                      vip.sin_addr.s_addr, vip.sin_port);  /* dst = VIP */
      }
    }
  }
  ep_cfd = proxy_setup_ep_connect(epip, epport, IPPROTO_TCP, NULL, NULL, client_pfe,
                                  (dpp2len ? dpp2buf : NULL), dpp2len);
  if (ep_cfd < 0) {
    log_error("Failed to connect to decode EP%d", d_idx);
    goto out;
  }

  /* 5. Create backend pfe for decode connection */
  proxy_fd_ent_t *decode_pfe = pfe_alloc();   /* D2 root fix: pooled pfe shell */
  if (!decode_pfe) {
    log_error("calloc failed for decode_pfe");
    close(ep_cfd);
    goto out;
  }

  decode_pfe->stype = PROXY_SOCK_ACTIVE;
  decode_pfe->pd_decode_ep_idx = -1;
  decode_pfe->fd = ep_cfd;
  decode_pfe->rfd[0] = client_pfe->fd;
  decode_pfe->rfd_ent[0] = client_pfe;
  decode_pfe->seltype = client_pfe->seltype;
  decode_pfe->ep_num = -1;
  decode_pfe->odir = 1;
  decode_pfe->is_pd_decode_backend = 1; /* identify as decode backend for EOF handler */
  decode_pfe->n_rfd = 1;
  decode_pfe->head = client_pfe->head;

  /* Copy SSE configuration from client for decode streaming */
  decode_pfe->sse_mode = client_pfe->sse_mode;
  decode_pfe->max_stream_duration_sec = client_pfe->max_stream_duration_sec;
  decode_pfe->backend_keepalive_sec = client_pfe->backend_keepalive_sec;

  /* Initialize HTTP parser for decode response.
   *
 * under pd_framing_v2, the decode backend response leg is
   * framed by an HTTP_RESPONSE parser (NOT HTTP_BOTH — 1xx/204/304/HEAD framing
   * keys off parser->type) with the three response callbacks. The pd_framing_v2
   * path lazily (re)inits this same parser as HTTP_RESPONSE on the first response
   * read in proxy_try_epxmit (pd_resp_parser_init), so the flag-ON behavior is
   * consistent regardless of which site ran first.
   *
   * With the flag OFF we keep the legacy HTTP_BOTH + handle_on_message_complete
   * init (the decode pfe's on_message_complete already drives prefill->decode
   * orchestration at handle_on_message_complete:odir==1) so behavior is
   * byte-identical to today. */
  if (pd_framing_v2_on()) {
    pd_resp_parser_init(decode_pfe);   /* HTTP_RESPONSE + resp callbacks (M1) */
  } else {
    llhttp_init(&decode_pfe->parser, HTTP_BOTH, &decode_pfe->settings);
    decode_pfe->settings.on_message_complete = handle_on_message_complete;
    decode_pfe->settings.uarg = decode_pfe;
  }

  /* Link decode backend to client pfe (use slot 1 to keep prefill in slot 0) */
  if (client_pfe->n_rfd < MAX_PROXY_EP) {
    int slot = client_pfe->n_rfd;
    client_pfe->rfd[slot] = ep_cfd;
    client_pfe->rfd_ent[slot] = decode_pfe;
    client_pfe->n_rfd++;
  }

  /* Set phase BEFORE notify_add_ent to eliminate race condition.
   * On a fast localhost backend the decode response can arrive and be
   * processed by the event loop before pd_phase is updated, causing the
   * completion check (phase == PD_PHASE_DECODE_SENDING) to miss and
   * llb_ai_pd_record to never be called. Set unconditionally here. */
  client_pfe->pd_phase = PD_PHASE_DECODE_SENDING;
  {
    struct timespec _ts;
    clock_gettime(CLOCK_MONOTONIC, &_ts);
    client_pfe->pd_decode_start_ns =
        (uint64_t)_ts.tv_sec * 1000000000ULL + (uint64_t)_ts.tv_nsec;
  }

  /* Register with event loop */
  proxy_map_ent_t *ent = (proxy_map_ent_t *)client_pfe->head;
  if (ent) {
    PROXY_LOCK();
    decode_pfe->next = ent->val.fdlist;
    ent->val.fdlist = decode_pfe;
    ent->val.nfds++;
    PROXY_UNLOCK();

    /* Option A: pin the decode backend fd to the CLIENT fd's notify
     * worker so this connection's relay (proxy_notifier) and teardown
     * (proxy_pdestroy) serialize on one thread — prevents the cross-thread pfe
     * use-after-free that wedged loxilb under load. */
    notify_add_ent_pinned(proxy_struct->ns, ep_cfd,
                          NOTI_TYPE_IN|NOTI_TYPE_HUP, decode_pfe, decode_pfe->gen,
                          client_pfe->fd);
  }

  /* 6. Send decode request to decode EP */
  {
    size_t sent = 0;
    while (sent < decode_req_len) {
      ssize_t n = write(ep_cfd, decode_req + sent, decode_req_len - sent);
      if (n <= 0) {
        if (errno == EINTR || errno == EAGAIN) continue;
        log_error("Failed to send decode request: %s", strerror(errno));
        goto out;
      }
      sent += (size_t)n;
    }
  }

  log_info("Decode request sent — client_fd=%d decode_fd=%d decode_ep=%d "
           "body_len=%zu",
           client_pfe->fd, ep_cfd, d_idx, decode_body_len);

  ret = 0;

out:
  /* Single-owner free ( conc=128 UAF fix): release the prefill/body/
   * headers buffers we atomically claimed at entry plus the locally-owned decode
   * scratch buffers. A racing pd_cleanup() saw NULL for the claimed fields and
   * freed nothing, so there is no double free; every error/success path lands
   * here exactly once. free(NULL) is a no-op for the un-allocated scratch. */
  free(decode_body);
  free(decode_req);
  free(l_prefill);
  free(l_body);
  free(l_headers);
  return ret;
}

/* P/D prefill mid-request failover.
 *
 * When the prefill backend dies while the request is still in
 * PREFILL_SENDING/PREFILL_WAITING, the COMPLETE original request survives on
 * the client pfe (pd_saved_headers + pd_saved_body) and prefill is
 * side-effect-idempotent (max_tokens=1 KV-warm), so the request is re-driven
 * ONCE against a freshly selected healthy prefill EP instead of surfacing a
 * 503. Runs AFTER proxy_pdestroy drops PROXY_LOCK (registering the
 * replacement leg re-takes it, and the lock is not recursive). This is safe
 * against client teardown because every backend fd is pinned to its client
 * fd's notify worker (the Option-A pinning in setup_proxy_path), so the dying
 * prefill leg's proxy_pdestroy and any client-side relay/close serialize on
 * this same thread.
 *
 * hdrs/body are heap COPIES taken under PROXY_LOCK and owned (always freed)
 * here — the originals stay on the client pfe for the decode phase, and the
 * cross-thread reaper can never see a half-donated buffer.
 *
 * On any failure this function completes the legacy contract itself: 503 to
 * the client, prefill_error recorded, pd state cleaned, client closed. */
void
pd_retry_prefill(proxy_fd_ent_t *client_pfe, int dead_idx,
                 uint8_t *hdrs, size_t hdrs_len,
                 uint8_t *body, size_t body_len)
{
  proxy_epval_t *tepval;
  uint8_t *prefill_buf = NULL;
  uint8_t *req = NULL;
  size_t req_len = 0;
  int new_idx = -1;
  int ep_cfd = -1;

  if (!client_pfe || !client_pfe->epv) goto fail;
  tepval = (proxy_epval_t *)client_pfe->epv;

  if (client_pfe->pd_phase != PD_PHASE_PREFILL_SENDING &&
      client_pfe->pd_phase != PD_PHASE_PREFILL_WAITING) goto fail;

  {
    uint32_t excluded = 0;
    int saved_decode = client_pfe->pd_decode_ep_idx;
    if (dead_idx >= 0 && dead_idx < 32) excluded |= 1u << (unsigned)dead_idx;

    for (int attempt = 0; attempt < tepval->n_prefill_eps; attempt++) {
      int cand = -1;
      int rc = pd_select_prefill(tepval, client_pfe, &cand, excluded);
      /* A Tier-0 session hit inside pd_select_prefill may overwrite the
       * decode hint; the decode EP for THIS request was already chosen at
       * admission and its selection must stand — always restore it. */
      client_pfe->pd_decode_ep_idx = saved_decode;
      if (rc != 0 || cand < 0)
        break;  /* no healthy candidates (park/shed count as none mid-request) */

      /* PROXY protocol v2 parity with the admission-time prefill leg. */
      uint8_t pp2buf[28];
      int pp2len = 0;
      {
        proxy_map_ent_t *hent = (proxy_map_ent_t *)client_pfe->head;
        if (hent && hent->val.ppv2) {
          struct sockaddr_in cli, vip;
          socklen_t cl = sizeof(cli), vl = sizeof(vip);
          if (getpeername(client_pfe->fd, (struct sockaddr *)&cli, &cl) == 0 &&
              getsockname(client_pfe->fd, (struct sockaddr *)&vip, &vl) == 0 &&
              cli.sin_family == AF_INET && vip.sin_family == AF_INET) {
            pp2len = proxy_build_ppv2_v4(pp2buf, sizeof(pp2buf),
                                         cli.sin_addr.s_addr, cli.sin_port,
                                         vip.sin_addr.s_addr, vip.sin_port);
          }
        }
      }
      ep_cfd = proxy_setup_ep_connect(tepval->eps[cand].xip,
                                      tepval->eps[cand].xport,
                                      IPPROTO_TCP, NULL, NULL, client_pfe,
                                      (pp2len ? pp2buf : NULL), pp2len);
      if (ep_cfd >= 0) { new_idx = cand; break; }
      /* Sync connect failure — condemn and try the next candidate. */
      circuit_breaker_record_failure(tepval, cand);
      if (cand >= 0 && cand < 32) excluded |= 1u << (unsigned)cand;
    }

    if (ep_cfd < 0 || new_idx < 0) goto fail;

    /* Rebuild the prefill request exactly as at admission: deterministic
     * max_tokens=1/stream=false rewrite of the ORIGINAL body under the
     * ORIGINAL headers (same X-Request-Id), with Content-Length re-fitted. */
    size_t prefill_cap = body_len + 4096;
    size_t prefill_len = 0;
    prefill_buf = malloc(prefill_cap);
    if (!prefill_buf ||
        pd_prepare_prefill_body(body, body_len, prefill_buf, &prefill_len,
                                prefill_cap) != 0) {
      log_error("prefill failover: body rewrite failed (client_fd=%d)",
                client_pfe->fd);
      close(ep_cfd);
      goto fail;
    }
    size_t req_cap = hdrs_len + prefill_len + 256;
    req = malloc(req_cap);
    if (!req) { close(ep_cfd); goto fail; }
    memcpy(req, hdrs, hdrs_len);
    memcpy(req + hdrs_len, prefill_buf, prefill_len);
    req_len = hdrs_len + prefill_len;
    pd_update_content_length(req, &req_len, req_cap, prefill_len);

    /* The request-id receipt (___prefill_addr_<ep>___decode_addr_<ep>_<uuid>)
     * was stamped at admission and names the DEAD prefill EP. Point it at the
     * replacement (same nixl_port-else-xport formatting as admission) in BOTH
     * the retried prefill request and the SAVED headers — the decode request
     * is rebuilt from the saved headers and the client-visible response id
     * echoes it, so a prefill-only rewrite would still report the dead node
     * as the request's prefill server. uuid tail + decode addr stay,
     * preserving trace continuity. */
    {
      char n_addr[64];
      struct in_addr n_in = { .s_addr = tepval->eps[new_idx].xip };
      uint16_t n_port = tepval->eps[new_idx].nixl_port ?
                        ntohs(tepval->eps[new_idx].nixl_port) :
                        ntohs(tepval->eps[new_idx].xport);
      snprintf(n_addr, sizeof(n_addr), "%s:%u", inet_ntoa(n_in), n_port);
      pd_receipt_rewrite(req, &req_len, req_cap, n_addr);

      size_t sh_cap = hdrs_len + 80;
      uint8_t *sh = malloc(sh_cap);
      if (sh) {
        memcpy(sh, hdrs, hdrs_len);
        size_t sh_len = hdrs_len;
        if (pd_receipt_rewrite(sh, &sh_len, sh_cap, n_addr) == 0) {
          /* Single-owner swap (pd_free_claim discipline): a racing cleanup
           * claims-or-sees-NULL and never double-frees. */
          uint8_t *old_sh = __atomic_exchange_n(&client_pfe->pd_saved_headers,
                                                NULL, __ATOMIC_ACQ_REL);
          free(old_sh);
          client_pfe->pd_saved_headers_len = sh_len;
          __atomic_store_n(&client_pfe->pd_saved_headers, sh, __ATOMIC_RELEASE);
        } else {
          free(sh);
        }
      }
    }

    proxy_fd_ent_t *bpfe = pfe_alloc();
    if (!bpfe) { close(ep_cfd); goto fail; }
    bpfe->stype = PROXY_SOCK_ACTIVE;
    bpfe->pd_decode_ep_idx = -1;
    bpfe->fd = ep_cfd;
    bpfe->rfd[0] = client_pfe->fd;
    bpfe->rfd_ent[0] = client_pfe;
    bpfe->seltype = client_pfe->seltype;
    bpfe->ep_num = -1;
    bpfe->odir = 1;
    bpfe->n_rfd = 1;
    bpfe->head = client_pfe->head;
    bpfe->sse_mode = client_pfe->sse_mode;
    bpfe->max_stream_duration_sec = client_pfe->max_stream_duration_sec;
    bpfe->backend_keepalive_sec = client_pfe->backend_keepalive_sec;
    /* Same framer setup as the decode leg: legacy HTTP_BOTH +
     * handle_on_message_complete (the odir==1 PREFILL_WAITING branch drives
     * completion), lazily re-inited as HTTP_RESPONSE under pd_framing_v2. */
    if (pd_framing_v2_on()) {
      pd_resp_parser_init(bpfe);
    } else {
      llhttp_init(&bpfe->parser, HTTP_BOTH, &bpfe->settings);
      bpfe->settings.on_message_complete = handle_on_message_complete;
      bpfe->settings.uarg = bpfe;
    }

    /* Move the admission active_conns unit dead -> replacement so
     * pd_cleanup's decrement of the final pd_prefill_ep_idx stays balanced. */
    if (dead_idx >= 0 && dead_idx < tepval->n_eps) {
      uint32_t cur = atomic_load(&tepval->pd_ep_loads[dead_idx].active_conns);
      if (cur > 0)
        atomic_fetch_sub(&tepval->pd_ep_loads[dead_idx].active_conns, 1);
    }
    atomic_fetch_add(&tepval->pd_ep_loads[new_idx].active_conns, 1);
    client_pfe->pd_prefill_ep_idx = new_idx;

    /* Link the replacement leg (the dead leg's slot was detached in
     * proxy_pdestroy) and restart the prefill state machine. Any partial
     * response from the dead EP is dropped by resetting the resp length. */
    if (client_pfe->n_rfd < MAX_PROXY_EP) {
      int slot = client_pfe->n_rfd;
      client_pfe->rfd[slot] = ep_cfd;
      client_pfe->rfd_ent[slot] = bpfe;
      client_pfe->n_rfd++;
    }
    client_pfe->pd_prefill_resp_len = 0;
    client_pfe->pd_phase = PD_PHASE_PREFILL_WAITING;
    client_pfe->pd_phase_start_ts = time(NULL);
    {
      struct timespec _ts;
      clock_gettime(CLOCK_MONOTONIC, &_ts);
      client_pfe->pd_prefill_start_ns =
          (uint64_t)_ts.tv_sec * 1000000000ULL + (uint64_t)_ts.tv_nsec;
    }

    {
      proxy_map_ent_t *hent = (proxy_map_ent_t *)client_pfe->head;
      if (hent) {
        PROXY_LOCK();
        bpfe->next = hent->val.fdlist;
        hent->val.fdlist = bpfe;
        hent->val.nfds++;
        PROXY_UNLOCK();
        /* Option-A pinning: relay + teardown for the new leg serialize on the
         * client fd's worker, like every other backend leg. */
        notify_add_ent_pinned(proxy_struct->ns, ep_cfd,
                              NOTI_TYPE_IN|NOTI_TYPE_HUP, bpfe, bpfe->gen,
                              client_pfe->fd);
      }
    }

    {
      size_t sent = 0;
      while (sent < req_len) {
        ssize_t n = write(ep_cfd, req + sent, req_len - sent);
        if (n <= 0) {
          if (errno == EINTR || errno == EAGAIN) continue;
          /* The registered leg will error out and its proxy_pdestroy runs the
           * exhausted-budget 503 path (pd_prefill_retries already consumed). */
          log_error("prefill failover: send to EP%d failed: %s",
                    new_idx, strerror(errno));
          goto done;
        }
        sent += (size_t)n;
      }
    }

    /* Re-pin the session to the healthy pair (admission failover parity). */
    {
      const char *sk = NULL;
      if (client_pfe->has_user_id && client_pfe->user_id[0] != '\0')
        sk = client_pfe->user_id;
      if (client_pfe->has_conv_id && client_pfe->conversation_id[0] != '\0' &&
          strncmp(client_pfe->conversation_id, "auto-", 5) != 0)
        sk = client_pfe->conversation_id;
      if (sk) pd_session_store(tepval, sk, new_idx, saved_decode);
    }

    atomic_fetch_add(&global_stats.pd_connect_failover, 1);
    log_info("prefill mid-request failover: EP%d died -> EP%d "
             "(client_fd=%d req=%zuB)",
             dead_idx, new_idx, client_pfe->fd, req_len);
  }
  goto done;

fail:
  if (client_pfe) {
    static const char pd_prefill_err[] =
        "HTTP/1.1 503 Service Unavailable\r\n"
        "Content-Type: application/json\r\n"
        "Connection: close\r\n"
        "\r\n"
        "{\"error\":\"pd_pool_unavailable\",\"detail\":\"prefill backend connection dropped\"}";
    log_error("prefill failover exhausted — 503 to client_fd=%d (dead EP%d)",
              client_pfe->fd, dead_idx);
    {
      const char *pd_model = proxy_effective_model(client_pfe);
      int pd_kv = (client_pfe->pd_kv_params_len > 0) ? 1 : 0;
      llb_ai_pd_record((char *)pd_model, 0, 0, pd_kv, 1 /*prefill error*/);
    }
    if (client_pfe->fd > 0) {
      if (client_pfe->ssl) {
        SSL_write(client_pfe->ssl, pd_prefill_err, sizeof(pd_prefill_err) - 1);
      } else {
        send(client_pfe->fd, pd_prefill_err, sizeof(pd_prefill_err) - 1,
             MSG_DONTWAIT | MSG_NOSIGNAL);
      }
    }
    pd_cleanup(client_pfe);
    client_pfe->pd_phase = PD_PHASE_ERROR;
    /* The client was detached from the dying leg before the retry, so its
     * teardown no longer cascades — close it explicitly. */
    notify_delete_ent(proxy_struct->ns, client_pfe->fd, 0);
  }

done:
  free(prefill_buf);
  free(req);
  free(hdrs);
  free(body);
}

/* --- Dialect ops --------------------------------------------------------- */

/* vLLM sequential machine: save the original body for the decode phase and
 * rewrite the request into the prefill probe (max_tokens=1, stream=false,
 * +kv_transfer_params). Failures log and fall back to plain forwarding of
 * the untouched request (returns 0 — never fails the client here). */
static int
pd_vllm_prepare_request(struct proxy_fd_ent *pfe, struct proxy_epval *epval,
                        size_t hdr_len, const uint8_t *body, size_t body_len)
{
  (void)epval;
  /* 1. Save original body for decode phase */
  pfe->pd_saved_body = malloc(body_len);
  if (pfe->pd_saved_body) {
    memcpy(pfe->pd_saved_body, body, body_len);
    pfe->pd_saved_body_len = body_len;

    /* 2. Rewrite body for prefill: max_tokens=1, stream=false,
     *    +kv_transfer_params */
    uint8_t *prefill_buf = malloc(body_len + 4096);
    if (prefill_buf) {
      size_t prefill_body_len = 0;
      if (pd_prepare_prefill_body(body, body_len,
                                  prefill_buf, &prefill_body_len,
                                  body_len + 4096) == 0) {
        /* Replace body in rcvbuf */
        memcpy(pfe->rcvbuf + hdr_len, prefill_buf, prefill_body_len);
        pfe->rcv_off = hdr_len + prefill_body_len;
        pfe->pd_prefill_body_len = prefill_body_len;

        /* 3. Allocate prefill response buffer (64KB cap) */
        pfe->pd_prefill_resp_cap = 64 * 1024;
        pfe->pd_prefill_resp_buf = malloc(pfe->pd_prefill_resp_cap);
        if (pfe->pd_prefill_resp_buf) {
          pfe->pd_prefill_resp_len = 0;

          /* 4. Set phase and timestamps */
          pfe->pd_phase = PD_PHASE_PREFILL_SENDING;
          pfe->pd_phase_start_ts = time(NULL);
          {
            struct timespec _ts;
            clock_gettime(CLOCK_MONOTONIC, &_ts);
            pfe->pd_prefill_start_ns =
                (uint64_t)_ts.tv_sec * 1000000000ULL +
                (uint64_t)_ts.tv_nsec;
          }

          log_info("P/D entry — fd=%d prefill_ep=%d "
                   "decode_ep=%d orig_body=%zu prefill_body=%zu",
                   pfe->fd, pfe->pd_prefill_ep_idx,
                   pfe->pd_decode_ep_idx,
                   body_len, prefill_body_len);
        } else {
          log_error("malloc failed for prefill_resp_buf");
          pd_free_claim(&pfe->pd_saved_body);  /* race-safe */
        }
      } else {
        log_error("pd_prepare_prefill_body failed");
        pd_free_claim(&pfe->pd_saved_body);  /* race-safe */
      }
      free(prefill_buf);
    } else {
      log_error("malloc failed for prefill_buf");
      pd_free_claim(&pfe->pd_saved_body);  /* race-safe */
    }
  } else {
    log_error("malloc failed for pd_saved_body (%zu)", body_len);
  }
  return 0;
}

/* vLLM forward: prefill leg only (EP 0, set in proxy_setup_ep__), then the
 * sequential machine waits for the prefill response. */
static int
pd_vllm_dispatch(struct proxy_fd_ent *pfe)
{
  /* frame instrument (log-only): prefill forward site — declared
   * (parser-owned) CL vs actual relayed body bytes. */
  pd_frame_mismatch_log(pfe, pfe->rcvbuf, pfe->rcv_off,
                        pfe->http_content_length, "prefill_xmit");
  proxy_try_epxmit(pfe, pfe->rcvbuf, pfe->rcv_off, 0);
  pfe->pd_phase = PD_PHASE_PREFILL_WAITING;
  log_info("Prefill request sent — fd=%d phase→PREFILL_WAITING", pfe->fd);
  return 0;
}

const pd_dialect_ops_t pd_dialect_vllm = {
  .name = "vllm",
  .needs_full_body = 1,
  .max_inspect_body = 64 * 1024,
  .prepare_request = pd_vllm_prepare_request,
  .dispatch = pd_vllm_dispatch,
  .on_prefill_response = NULL,
  .on_leg_error = NULL,
  .collect_retry = NULL,
  .reap = NULL,
};
