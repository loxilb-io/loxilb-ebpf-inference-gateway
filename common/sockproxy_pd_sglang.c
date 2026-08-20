/* sockproxy_pd_sglang.c - SGLang DUAL-DISPATCH P/D disaggregation machine
 *
 * Dialect: SGLang concurrent P/D (bootstrap rendezvous — we inject the
 *   triple and relay, the engines move KV themselves).
 * Contract validated against: sglang-router 0.3.2 / SGLang v0.5.9
 *   (bootstrap triple field names bootstrap_host/bootstrap_port/
 *   bootstrap_room, room range [0, 2^63-1], 300s
 *   SGLANG_DISAGGREGATION_BOOTSTRAP_TIMEOUT).
 * Machine shape: bootstrap triple injection (room RNG via getrandom)
 *   → pd_sg_dual_dispatch (same payload down BOTH legs: admission-time
 *   prefill connection becomes the detached DRAIN leg, fresh decode leg
 *   is the client-facing one) → drain-leg framing + failure coupling
 *   → pair retry with a FRESH room on drain-leg transport death.
 * Last re-validated: 2026-08 mock scenario 27/27 + GPU suites
 *   (27/27 single-shot, 540/540 sustained).
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

/* ==========================================================================
 * SGLang P/D dual dispatch
 * --------------------------------------------------------------------------
 * SGLang disaggregation is architecturally unlike the sequential vLLM
 * machine (sockproxy_pd_vllm.c): the SAME bootstrap-injected request goes to
 * the prefill AND decode EPs CONCURRENTLY, the engines rendezvous on
 * (bootstrap_host, port, room) at prefill's bootstrap server, and the client
 * response comes exclusively from the decode leg. Prefill's response is
 * drained and discarded — a proxy that waits for it before contacting decode
 * deadlocks (prefill returns only after decode joined the room;
 * SGLANG_DISAGGREGATION_BOOTSTRAP_TIMEOUT=300s).
 *
 * State model: the CLIENT pfe reuses the DECODE_SENDING/DECODE_STREAMING
 * lifecycle from the moment of dispatch (every decode-side behavior — SSE
 * latch, [DONE] scanner, caps, EOF taxonomy, reapers — applies unchanged);
 * pd_sg_active marks the flavor. The prefill leg (client rfd slot 0, the
 * admission-time connection) becomes a detached DRAIN leg: pd_sg_drain=1 on
 * its backend pfe, its bytes are framed (status + message end) and discarded,
 * never relayed.
 *
 * Failure coupling (mirrors sgl-model-gateway pd_router.rs):
 *   - drain leg fails (5xx / transport death) with ZERO decode bytes relayed
 *     -> abort the decode leg (its engine sits in WaitingForInput until the
 *     300s timeout otherwise; on disconnect it aborts in ~4-8s), 502 client.
 *   - decode leg fails -> close the drain leg too (don't orphan it).
 *   - client disconnect -> the existing rfd cascade tears down both legs.
 * ========================================================================== */

/* llhttp message-complete callback for the drain leg: latch completion on the
 * BACKEND pfe. All consequences (metrics, proactive close, detach) are run by
 * the read-path caller, which owns the locks. */
static int
pd_sg_drain_on_msg_complete(llhttp_t *parser)
{
  llhttp_settings_t *settings = parser->settings;
  proxy_fd_ent_t *drain_pfe = settings ? settings->uarg : NULL;
  if (drain_pfe) {
    drain_pfe->pd_sg_drain_done = 1;
  }
  return 0;
}

/* Dedicated HTTP_RESPONSE framer for the drain leg. NOT pd_resp_parser_init:
 * the M1 resp callbacks drive client-stream completion, and the drain leg's
 * response must never touch client-facing state (the exact hazard the
 * PREFILL_WAITING framer-skip in the relay path documents). */
static void
pd_sg_drain_parser_init(proxy_fd_ent_t *drain_pfe)
{
  llhttp_settings_init(&drain_pfe->settings);
  drain_pfe->settings.on_message_complete = pd_sg_drain_on_msg_complete;
  drain_pfe->settings.uarg = drain_pfe;
  llhttp_init(&drain_pfe->parser, HTTP_RESPONSE, &drain_pfe->settings);
}

/* Close the prefill drain leg of an SGLang dual dispatch, if one is still
 * attached to this client. shutdown() only — the leg's own HUP/teardown path
 * (same pinned worker) detaches and frees it. count_close ticks the
 * decode-failure coupling counter; janitorial closes pass 0. */
void
pd_sg_close_drain(proxy_fd_ent_t *client_pfe, int count_close)
{
  if (!client_pfe->pd_sg_active) return;
  for (int j = 0; j < MAX_PROXY_EP; j++) {
    proxy_fd_ent_t *leg = client_pfe->rfd_ent[j];
    if (leg && leg->pd_sg_drain && !leg->pd_sg_drain_handled) {
      leg->pd_sg_drain_handled = 1;
      if (count_close) {
        atomic_fetch_add(&global_stats.pd_sg_decode_close_drain, 1);
      }
      log_info("[PD_SG] closing prefill drain leg fd=%d (client_fd=%d%s)",
               leg->fd, client_pfe->fd,
               count_close ? ", decode-failure coupling" : "");
      if (leg->fd > 0) {
        shutdown(leg->fd, SHUT_RDWR);
      }
    }
  }
}

/* Prefill drain-leg failure with zero decode bytes relayed: abort the pair.
 * 502 to the client, decode leg closed via the client-fd cascade, lifecycle
 * recorded as a prefill error. Terminal — drain-leg TRANSPORT death gets one
 * pd_sg_retry_pair attempt first (the proxy_pdestroy enqueue); an error
 * STATUS from prefill aborts directly (a 4xx/5xx the origin computed is not
 * a gateway-retryable fault). origin_status carries that status (0 for
 * transport death): a 4xx is an origin-computed CLIENT error, so it must not
 * tick the EP-death failover counter — that family means "backend died", and
 * a burst of oversize prompts would otherwise read as a dying prefill EP.
 * Caller holds the CLIENT pfe lock. */
void
pd_sg_abort_pair(proxy_fd_ent_t *client_pfe, const char *reason,
                 unsigned origin_status)
{
  static const char pd_sg_err[] =
      "HTTP/1.1 502 Bad Gateway\r\n"
      "Content-Type: application/json\r\n"
      "Connection: close\r\n"
      "\r\n"
      "{\"error\":\"pd_sg_prefill_failed\",\"detail\":\"prefill leg failed before decode produced output\"}";

  atomic_fetch_add(&global_stats.pd_sg_prefill_abort_decode, 1);
  if (origin_status < 400 || origin_status >= 500) {
    atomic_fetch_add(&global_stats.pd_prefill_ep_died, 1);
  }
  /* An origin-computed 5xx from the prefill feeds its breaker's origin
   * streak — the demotion that stops warm affinity from re-pinning an
   * endpoint that accepts TCP but keeps erroring. Transport deaths
   * (origin_status 0) stay with the connect-level breaker feed; decode-leg
   * 5xx are deliberately NOT attributed here (a decode KV-transfer error
   * routinely blames its prefill peer — demoting the decode would demote
   * the wrong endpoint). */
  if (origin_status >= 500 && client_pfe->epv &&
      client_pfe->pd_prefill_ep_idx >= 0) {
    circuit_breaker_record_origin_error((proxy_epval_t *)client_pfe->epv,
                                        client_pfe->pd_prefill_ep_idx);
  }
  log_error("[PD_SG] aborting pair (%s) — client_fd=%d room=%llu "
            "prefill_ep=%d decode_ep=%d",
            reason, client_pfe->fd,
            (unsigned long long)client_pfe->pd_sg_room,
            client_pfe->pd_prefill_ep_idx, client_pfe->pd_decode_ep_idx);
  {
    const char *pd_model = proxy_effective_model(client_pfe);
    llb_ai_pd_record((char *)pd_model, 0, 0, 0, 1 /*prefill error*/);
  }
  if (client_pfe->fd > 0) {
    if (client_pfe->ssl) {
      SSL_write(client_pfe->ssl, pd_sg_err, sizeof(pd_sg_err) - 1);
    } else {
      send(client_pfe->fd, pd_sg_err, sizeof(pd_sg_err) - 1,
           MSG_DONTWAIT | MSG_NOSIGNAL);
    }
  }
  client_pfe->pd_phase = PD_PHASE_ERROR;
  pd_cleanup(client_pfe);
  client_pfe->pd_phase = PD_PHASE_ERROR;  /* pd_cleanup resets to NONE */
  /* Shut the client down: its teardown cascade releases BOTH backend legs on
   * this same pinned worker (the decode engine aborts on disconnect). */
  if (client_pfe->fd > 0) {
    shutdown(client_pfe->fd, SHUT_RDWR);
  }
}

/* Refuse a request that cannot be dual-dispatched on an SGLang disagg rule:
 * a streamable body was never buffered, so bootstrap injection is
 * impossible, and disaggregation-mode engines cannot serve a bootstrap-less
 * relay — they either 400 it with a message blaming the CLIENT for the
 * gateway's routing choice, or (engines without that validation) park it
 * until their rendezvous timeout. Fail closed before any backend bytes
 * move: honest gateway attribution, counted, fast. The client is mid-upload
 * of a body we will not drain — Connection: close + shutdown, the teardown
 * cascade releases any already-connected backend leg untouched. */
void
pd_sg_oversize_reject(proxy_fd_ent_t *client_pfe)
{
  static const char pd_sg_503[] =
      "HTTP/1.1 503 Service Unavailable\r\n"
      "Content-Type: application/json\r\n"
      "Connection: close\r\n"
      "\r\n"
      "{\"error\":\"pd_sg_oversize_unroutable\",\"detail\":\"request body exceeds the gateway inspection window for prefill/decode dual dispatch\"}";

  atomic_fetch_add(&global_stats.pd_sg_oversize_reject, 1);
  log_error("[PD_SG] streamable request on a disagg rule — fail-closed 503 "
            "(client_fd=%d cl=%zu)",
            client_pfe->fd, client_pfe->http_content_length);
  if (client_pfe->fd > 0) {
    if (client_pfe->ssl) {
      SSL_write(client_pfe->ssl, pd_sg_503, sizeof(pd_sg_503) - 1);
    } else {
      send(client_pfe->fd, pd_sg_503, sizeof(pd_sg_503) - 1,
           MSG_DONTWAIT | MSG_NOSIGNAL);
    }
  }
  if (client_pfe->fd > 0) {
    shutdown(client_pfe->fd, SHUT_RDWR);
  }
}

/* Zero decode bytes relayed so far? (The decode-zero-byte-EOF predicate.) */
int
pd_sg_decode_untouched(const proxy_fd_ent_t *client_pfe)
{
  return client_pfe->pd_last_decode_ts == 0 &&
         client_pfe->pd_decode_content_length == 0 &&
         client_pfe->pd_decode_bytes_received == 0;
}

/* Relay one chunk of the prefill's 4xx response to the client. The bodies
 * are tiny (an engine validation error), but the response routinely spans
 * two writes — HTTP servers flush headers and body separately — so this is
 * called once per drain chunk while relay mode is on. */
static void
pd_sg_relay_bytes(proxy_fd_ent_t *client_pfe, uint8_t *msg, size_t len)
{
  if (client_pfe->fd <= 0 || len == 0) return;
  if (client_pfe->ssl) {
    SSL_write(client_pfe->ssl, msg, len);
  } else {
    send(client_pfe->fd, msg, len, MSG_DONTWAIT | MSG_NOSIGNAL);
  }
}

/* The relayed 4xx is complete (message end, or leg EOF for a close-framed
 * response): tear the pair down exactly like the abort path, minus the
 * synthetic 502 — the client already holds the origin's own response.
 * Caller holds the CLIENT pfe lock. */
void
pd_sg_relay_finalize(proxy_fd_ent_t *client_pfe)
{
  client_pfe->pd_phase = PD_PHASE_ERROR;
  pd_cleanup(client_pfe);
  client_pfe->pd_phase = PD_PHASE_ERROR;  /* pd_cleanup resets to NONE */
  /* Shut the client down: its teardown cascade releases BOTH backend legs on
   * this same pinned worker (the decode engine aborts on disconnect). */
  if (client_pfe->fd > 0) {
    shutdown(client_pfe->fd, SHUT_RDWR);
  }
}

/* Consume bytes arriving on the drain leg: frame them (status + message end),
 * fire the failure coupling on a 4xx/5xx prefill status, discard everything.
 * Caller (proxy_try_epxmit) holds the CLIENT pfe lock; ent's own parser state
 * is mutated under a non-blocking self-lock (the M1 framer-feed discipline —
 * on contention the feed is skipped and completion falls back to leg EOF). */
void
pd_sg_drain_consume(proxy_fd_ent_t *ent, proxy_fd_ent_t *client_pfe,
                    uint8_t *msg, size_t len)
{
  int had_done = ent->pd_sg_drain_done;
  int first_feed = !ent->pd_sg_drain_fed;

  if (!ent->pd_sg_drain_desync && len > 0) {
    ent->pd_sg_drain_fed = 1;
    if (PROXY_ENT_TRYLOCK(ent) == 0) {
      llhttp_errno_t perr = llhttp_execute(&ent->parser, (char *)msg, len);
      if (perr != HPE_OK && perr != HPE_PAUSED) {
        /* Unparseable prefill response — framing is gone; EOF becomes the
         * only completion signal. Not a failure by itself. */
        ent->pd_sg_drain_desync = 1;
      }
      PROXY_ENT_UNLOCK(ent);
    } else {
      ent->pd_sg_drain_desync = 1;
    }
  }

  /* Fail-fast on a prefill error status — no need to wait for message end
   * (pd_router.rs shapes the abort off the prefill status the same way).
   * Deliberately NOT gated on pd_sg_drain_done: when the whole error
   * response arrives in ONE read, llhttp fires message-complete inside the
   * llhttp_execute above, so drain_done is ALREADY set by the time this
   * check runs — the original !drain_done gate then misclassified a
   * complete 4xx/5xx as a successful drain (decode left to park until its
   * own rendezvous timeout; the CICD prefill-500 leg caught this as a
   * read-coalescing race). An error status couples the failure whether the
   * response is mid-flight or complete. */
  /* Relay mode: an origin-computed 4xx is being handed to the client
   * verbatim — keep relaying every drain chunk until the message completes
   * (a close-framed response finalizes at leg EOF instead, in the death
   * handler). */
  if (ent->pd_sg_drain_relay) {
    pd_sg_relay_bytes(client_pfe, msg, len);
    if (ent->pd_sg_drain_done) {
      pd_sg_relay_finalize(client_pfe);
    }
    return;
  }

  if (!ent->pd_sg_drain_handled && ent->parser.status_code >= 400) {
    ent->pd_sg_drain_handled = 1;
    if (pd_sg_decode_untouched(client_pfe)) {
      /* A prefill 4xx is an origin-computed, deterministic CLIENT error
       * (malformed body, prompt over the context window) that every prefill
       * EP would repeat. Masking it as a gateway 502 mislabels a client
       * fault as a server fault — upstream retry logic replays a request
       * that can never succeed — and buries the origin's diagnostic body
       * (token counts, validation detail). The decode leg relays ITS 4xx
       * verbatim, so without this the client-visible contract for the same
       * mistake depended on which leg's error won the race. Enter relay
       * mode instead — only when the status arrived on the FIRST fed chunk
       * (earlier chunks were discarded, so a later detection has no
       * verbatim prefix to hand over) and framing is trusted. Fragmented
       * status lines, desynced legs and all 5xx keep the abort contract. */
      if (ent->parser.status_code < 500 && first_feed &&
          !ent->pd_sg_drain_desync) {
        ent->pd_sg_drain_relay = 1;
        atomic_fetch_add(&global_stats.pd_sg_prefill_reject_relay, 1);
        log_warn("[PD_SG] prefill status %u — relaying origin reject "
                 "verbatim, aborting decode leg (client_fd=%d drain_fd=%d "
                 "room=%llu)",
                 ent->parser.status_code, client_pfe->fd, ent->fd,
                 (unsigned long long)client_pfe->pd_sg_room);
        {
          const char *pd_model = proxy_effective_model(client_pfe);
          llb_ai_pd_record((char *)pd_model, 0, 0, 0, 1 /*prefill error*/);
        }
        pd_sg_relay_bytes(client_pfe, msg, len);
        if (ent->pd_sg_drain_done) {
          pd_sg_relay_finalize(client_pfe);
        }
        return;
      }
      log_error("[PD_SG] prefill status %u — aborting decode leg "
                "(client_fd=%d drain_fd=%d)",
                ent->parser.status_code, client_pfe->fd, ent->fd);
      pd_sg_abort_pair(client_pfe, "prefill error status",
                       ent->parser.status_code);
    } else {
      /* Decode already produced client-visible output (fully radix-cached
       * prompt) — let it finish; log + count only. A 4xx here is an
       * origin-computed client error, not a backend death — keep the
       * EP-death failover counter for 5xx/transport. */
      if (ent->parser.status_code >= 500) {
        atomic_fetch_add(&global_stats.pd_prefill_ep_died, 1);
        if (client_pfe->epv && client_pfe->pd_prefill_ep_idx >= 0) {
          circuit_breaker_record_origin_error(
              (proxy_epval_t *)client_pfe->epv,
              client_pfe->pd_prefill_ep_idx);
        }
      }
      log_warn("[PD_SG] prefill status %u AFTER decode bytes relayed — "
               "letting decode finish (client_fd=%d)",
               ent->parser.status_code, client_pfe->fd);
      if (ent->fd > 0) shutdown(ent->fd, SHUT_RDWR);
    }
    return;
  }

  if (!had_done && ent->pd_sg_drain_done) {
    /* Prefill response complete: stamp "prefill latency" = drain completion
     * time (compute + KV transfer — the operationally interesting number).
     * The shared decode-completion record sites compute
     * prefill_ms = decode_start_ns - prefill_start_ns, so BACKDATE
     * prefill_start_ns to make that subtraction yield the drain latency. */
    struct timespec _ts;
    clock_gettime(CLOCK_MONOTONIC, &_ts);
    uint64_t now_ns = (uint64_t)_ts.tv_sec * 1000000000ULL +
                      (uint64_t)_ts.tv_nsec;
    uint64_t drain_ns = (client_pfe->pd_prefill_start_ns > 0 &&
                         now_ns > client_pfe->pd_prefill_start_ns)
                        ? now_ns - client_pfe->pd_prefill_start_ns : 0;
    if (client_pfe->pd_decode_start_ns > drain_ns) {
      client_pfe->pd_prefill_start_ns =
          client_pfe->pd_decode_start_ns - drain_ns;
    }
    ent->pd_sg_drain_handled = 1;
    /* A clean prefill response resets the origin-error streak (4xx are
     * client faults — neither error nor success for the demotion count). */
    if (ent->parser.status_code > 0 && ent->parser.status_code < 400 &&
        client_pfe->epv && client_pfe->pd_prefill_ep_idx >= 0) {
      circuit_breaker_record_origin_success(
          (proxy_epval_t *)client_pfe->epv, client_pfe->pd_prefill_ep_idx);
    }
    log_info("[PD_SG] prefill drain complete — client_fd=%d drain_fd=%d "
             "status=%u drain_ms=%llu room=%llu",
             client_pfe->fd, ent->fd, ent->parser.status_code,
             (unsigned long long)(drain_ns / 1000000ULL),
             (unsigned long long)client_pfe->pd_sg_room);
    /* Proactively close the leg (keep-alive servers hold it open forever
     * otherwise); its teardown detaches benignly — the client sits in a
     * DECODE_* phase, the stale-prefill-detach branch handles it. */
    if (ent->fd > 0) {
      shutdown(ent->fd, SHUT_RDWR);
    }
  }
}

/* Dual dispatch at request-complete: mark the admission-time prefill leg as
 * the drain leg, bring up the decode leg, send the SAME bootstrap-injected
 * request (already in client rcvbuf) down both, and enter the decode
 * lifecycle. Returns 0 on success; on failure the 503 + record + cleanup are
 * done here and -1 is returned (caller just resets its parse state). */
static int
pd_sg_dual_dispatch(proxy_fd_ent_t *client_pfe)
{
  proxy_epval_t *tepval;
  proxy_fd_ent_t *drain_pfe;
  int d_idx;
  int ep_cfd = -1;

  if (!client_pfe || !client_pfe->epv) return -1;
  tepval = (proxy_epval_t *)client_pfe->epv;
  d_idx = client_pfe->pd_decode_ep_idx;

  if (d_idx < 0 || d_idx >= tepval->n_eps ||
      client_pfe->n_rfd < 1 || client_pfe->rfd[0] <= 0 ||
      !client_pfe->rfd_ent[0]) {
    log_error("[PD_SG] dual dispatch preconditions failed — client_fd=%d "
              "decode_ep=%d n_rfd=%d", client_pfe->fd, d_idx,
              client_pfe->n_rfd);
    goto fail;
  }

  /* 1. The admission-time prefill connection (slot 0) becomes the drain leg. */
  drain_pfe = client_pfe->rfd_ent[0];
  pd_sg_drain_parser_init(drain_pfe);
  drain_pfe->pd_sg_drain = 1;

  /* 2. Decode leg — connect + backend pfe, the pd_initiate_decode shape
   * (selection happened at admission moments ago; inv/CB re-validation is the
   * long-prefill-window concern of the vLLM path, not this one). */
  {
    uint8_t dpp2buf[28];
    int dpp2len = 0;
    proxy_map_ent_t *dent = (proxy_map_ent_t *)client_pfe->head;
    if (dent && dent->val.ppv2) {
      struct sockaddr_in cli, vip;
      socklen_t cl = sizeof(cli), vl = sizeof(vip);
      if (getpeername(client_pfe->fd, (struct sockaddr *)&cli, &cl) == 0 &&
          getsockname(client_pfe->fd, (struct sockaddr *)&vip, &vl) == 0 &&
          cli.sin_family == AF_INET && vip.sin_family == AF_INET) {
        dpp2len = proxy_build_ppv2_v4(dpp2buf, sizeof(dpp2buf),
                                      cli.sin_addr.s_addr, cli.sin_port,
                                      vip.sin_addr.s_addr, vip.sin_port);
      }
    }
    ep_cfd = proxy_setup_ep_connect(tepval->eps[d_idx].xip,
                                    tepval->eps[d_idx].xport,
                                    IPPROTO_TCP, NULL, NULL, client_pfe,
                                    (dpp2len ? dpp2buf : NULL), dpp2len);
  }
  if (ep_cfd < 0) {
    log_error("[PD_SG] decode EP%d connect failed (client_fd=%d)",
              d_idx, client_pfe->fd);
    atomic_fetch_add(&global_stats.pd_decode_ep_died, 1);
    goto fail;
  }

  {
    proxy_fd_ent_t *decode_pfe = pfe_alloc();
    if (!decode_pfe) {
      close(ep_cfd);
      goto fail;
    }
    decode_pfe->stype = PROXY_SOCK_ACTIVE;
    decode_pfe->pd_decode_ep_idx = -1;
    decode_pfe->fd = ep_cfd;
    decode_pfe->rfd[0] = client_pfe->fd;
    decode_pfe->rfd_ent[0] = client_pfe;
    decode_pfe->seltype = client_pfe->seltype;
    decode_pfe->ep_num = -1;
    decode_pfe->odir = 1;
    decode_pfe->is_pd_decode_backend = 1;
    decode_pfe->n_rfd = 1;
    decode_pfe->head = client_pfe->head;
    decode_pfe->sse_mode = client_pfe->sse_mode;
    decode_pfe->max_stream_duration_sec = client_pfe->max_stream_duration_sec;
    decode_pfe->backend_keepalive_sec = client_pfe->backend_keepalive_sec;
    if (pd_framing_v2_on()) {
      pd_resp_parser_init(decode_pfe);
    } else {
      llhttp_init(&decode_pfe->parser, HTTP_BOTH, &decode_pfe->settings);
      decode_pfe->settings.on_message_complete = handle_on_message_complete;
      decode_pfe->settings.uarg = decode_pfe;
    }

    if (client_pfe->n_rfd < MAX_PROXY_EP) {
      int slot = client_pfe->n_rfd;
      client_pfe->rfd[slot] = ep_cfd;
      client_pfe->rfd_ent[slot] = decode_pfe;
      client_pfe->n_rfd++;
    }

    {
      proxy_map_ent_t *ent = (proxy_map_ent_t *)client_pfe->head;
      if (ent) {
        PROXY_LOCK();
        decode_pfe->next = ent->val.fdlist;
        ent->val.fdlist = decode_pfe;
        ent->val.nfds++;
        PROXY_UNLOCK();
        notify_add_ent_pinned(proxy_struct->ns, ep_cfd,
                              NOTI_TYPE_IN|NOTI_TYPE_HUP, decode_pfe,
                              decode_pfe->gen, client_pfe->fd);
      }
    }
  }

  /* 3. Send the identical payload down both legs. Prefill first via the
   * regular transmit path (handles backend SSL/caching); decode via the
   * plaintext write the vLLM decode leg established as precedent. A prefill
   * send failure surfaces as the drain leg's HUP -> failure coupling. */
  proxy_try_epxmit(client_pfe, client_pfe->rcvbuf, client_pfe->rcv_off, 0);
  {
    size_t sent = 0;
    while (sent < client_pfe->rcv_off) {
      ssize_t n = write(ep_cfd, client_pfe->rcvbuf + sent,
                        client_pfe->rcv_off - sent);
      if (n <= 0) {
        if (errno == EINTR || errno == EAGAIN) continue;
        log_error("[PD_SG] decode send failed: %s", strerror(errno));
        atomic_fetch_add(&global_stats.pd_decode_ep_died, 1);
        goto fail;
      }
      sent += (size_t)n;
    }
  }

  /* 4. Enter the decode lifecycle — every decode-side mechanism (SSE latch,
   * [DONE], caps, EOF taxonomy, reapers) now applies unchanged. */
  client_pfe->pd_phase = PD_PHASE_DECODE_SENDING;
  client_pfe->pd_phase_start_ts = time(NULL);
  {
    struct timespec _ts;
    clock_gettime(CLOCK_MONOTONIC, &_ts);
    client_pfe->pd_decode_start_ns =
        (uint64_t)_ts.tv_sec * 1000000000ULL + (uint64_t)_ts.tv_nsec;
  }

  log_info("[PD_SG] dual dispatch — client_fd=%d prefill_ep=%d(fd=%d) "
           "decode_ep=%d(fd=%d) room=%llu req=%zuB",
           client_pfe->fd, client_pfe->pd_prefill_ep_idx,
           client_pfe->rfd[0], d_idx, ep_cfd,
           (unsigned long long)client_pfe->pd_sg_room, client_pfe->rcv_off);
  return 0;

fail:
  {
    static const char pd_sg_dispatch_err[] =
        "HTTP/1.1 503 Service Unavailable\r\n"
        "Content-Type: application/json\r\n"
        "Connection: close\r\n"
        "\r\n"
        "{\"error\":\"pd_pool_unavailable\",\"detail\":\"sglang dual dispatch failed\"}";
    const char *pd_model = proxy_effective_model(client_pfe);
    llb_ai_pd_record((char *)pd_model, 0, 0, 0, 2 /*decode error*/);
    if (client_pfe->fd > 0) {
      if (client_pfe->ssl) {
        SSL_write(client_pfe->ssl, pd_sg_dispatch_err,
                  sizeof(pd_sg_dispatch_err) - 1);
      } else {
        send(client_pfe->fd, pd_sg_dispatch_err,
             sizeof(pd_sg_dispatch_err) - 1, MSG_DONTWAIT | MSG_NOSIGNAL);
      }
    }
    client_pfe->pd_phase = PD_PHASE_ERROR;
    pd_cleanup(client_pfe);
    client_pfe->pd_phase = PD_PHASE_ERROR;
    if (client_pfe->fd > 0) {
      shutdown(client_pfe->fd, SHUT_RDWR);
    }
  }
  return -1;
}

/* SGLang P/D pair retry.
 *
 * The unit of retry is the PAIR: when the prefill drain leg dies before its
 * response completed and ZERO decode bytes have been relayed, the rendezvous
 * is unrecoverable in the OLD room (the decode engine sits in WaitingForInput
 * against a bootstrap server that will never see prefill arrive). A retry
 * therefore means: fresh pair selection, a FRESH room ID, re-injection of the
 * bootstrap triple into the ORIGINAL saved body, and BOTH legs restarted.
 * Budget rides pd_prefill_retries (1, same as the vLLM prefill failover) and
 * is consumed at the proxy_pdestroy enqueue site.
 *
 * Deferred-execution contract is pd_retry_prefill's, verbatim: runs AFTER
 * proxy_pdestroy drops PROXY_LOCK (leg registration re-takes it), safe
 * against concurrent client teardown via the Option-A worker pinning (both
 * old legs, both new legs, and the client serialize on the client fd's
 * worker). hdrs/body are heap COPIES taken under PROXY_LOCK and owned
 * (always freed) here — the originals stay on the client pfe.
 *
 * On any failure the abort contract runs via pd_sg_abort_pair (502, prefill
 * error recorded, pair torn down through the client-fd cascade). */
void
pd_sg_retry_pair(proxy_fd_ent_t *client_pfe, int dead_idx,
                 uint8_t *hdrs, size_t hdrs_len,
                 uint8_t *body, size_t body_len)
{
  proxy_epval_t *tepval;
  uint8_t *inj = NULL;
  uint8_t *req = NULL;
  size_t inj_len = 0;
  size_t req_len = 0;
  uint64_t new_room = 0;
  uint64_t old_room = 0;
  int old_d_idx = -1;
  int p_idx = -1, d_idx = -1;
  int p_cfd = -1, d_cfd = -1;

  if (!client_pfe || !client_pfe->epv) goto fail;
  tepval = (proxy_epval_t *)client_pfe->epv;
  old_room = client_pfe->pd_sg_room;
  old_d_idx = client_pfe->pd_decode_ep_idx;

  if (!client_pfe->pd_sg_active ||
      client_pfe->pd_phase != PD_PHASE_DECODE_SENDING ||
      !pd_sg_decode_untouched(client_pfe)) goto fail;

  /* 1. Close + detach the surviving OLD decode leg — its room is dead.
   * BOTH directions are unlinked BEFORE shutdown so the leg's own teardown
   * (same pinned worker, after we return) finds no client and can neither
   * cascade-close it nor misread the fresh attempt as a zero-byte decode
   * death. The engine aborts the orphaned in-room request on disconnect. */
  for (int j = 0; j < MAX_PROXY_EP; j++) {
    proxy_fd_ent_t *leg = client_pfe->rfd_ent[j];
    if (leg && leg->is_pd_decode_backend) {
      PROXY_ENT_LOCK(leg);
      for (int k = 0; k < MAX_PROXY_EP; k++) {
        if (leg->rfd_ent[k] == client_pfe) {
          leg->rfd_ent[k] = NULL;
          leg->rfd[k] = -1;
          if (leg->n_rfd > 0) leg->n_rfd--;
        }
      }
      PROXY_ENT_UNLOCK(leg);
      client_pfe->rfd_ent[j] = NULL;
      client_pfe->rfd[j] = -1;
      if (client_pfe->n_rfd > 0) client_pfe->n_rfd--;
      log_info("[PD_SG] pair retry: closing old decode leg fd=%d "
               "(client_fd=%d old_room=%llu)", leg->fd, client_pfe->fd,
               (unsigned long long)old_room);
      if (leg->fd > 0) {
        shutdown(leg->fd, SHUT_RDWR);
      }
    }
  }

  /* 2. Fresh PAIR selection. Prefill first, dead EP excluded, with the
   * sync-connect condemn-and-continue loop of the vLLM failover; the decode
   * hint is restored across pd_select_prefill (its Tier-0 session hit may
   * overwrite it) and then deliberately CLEARED for a fresh min-load decode
   * pick — new pair selection, not a patched-up old one. */
  {
    uint32_t excluded = 0;
    int saved_decode = client_pfe->pd_decode_ep_idx;
    if (dead_idx >= 0 && dead_idx < 32) excluded |= 1u << (unsigned)dead_idx;

    for (int attempt = 0; attempt < tepval->n_prefill_eps; attempt++) {
      int cand = -1;
      int rc = pd_select_prefill(tepval, client_pfe, &cand, excluded);
      client_pfe->pd_decode_ep_idx = saved_decode;
      if (rc != 0 || cand < 0)
        break;  /* no healthy candidates (park/shed count as none mid-request) */

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
      p_cfd = proxy_setup_ep_connect(tepval->eps[cand].xip,
                                     tepval->eps[cand].xport,
                                     IPPROTO_TCP, NULL, NULL, client_pfe,
                                     (pp2len ? pp2buf : NULL), pp2len);
      if (p_cfd >= 0) { p_idx = cand; break; }
      circuit_breaker_record_failure(tepval, cand);
      if (cand >= 0 && cand < 32) excluded |= 1u << (unsigned)cand;
    }
    if (p_cfd < 0 || p_idx < 0) goto fail;

    client_pfe->pd_decode_ep_idx = -1;  /* clear hint: force fresh min-load pick */
    if (pd_select_decode(tepval, client_pfe, &d_idx) != 0 || d_idx < 0) {
      client_pfe->pd_decode_ep_idx = saved_decode;  /* restore for cleanup/logs */
      close(p_cfd);
      p_cfd = -1;
      goto fail;
    }
  }

  /* 3. Decode connect (single attempt, pd_initiate_decode posture). */
  {
    uint8_t dpp2buf[28];
    int dpp2len = 0;
    proxy_map_ent_t *dent = (proxy_map_ent_t *)client_pfe->head;
    if (dent && dent->val.ppv2) {
      struct sockaddr_in cli, vip;
      socklen_t cl = sizeof(cli), vl = sizeof(vip);
      if (getpeername(client_pfe->fd, (struct sockaddr *)&cli, &cl) == 0 &&
          getsockname(client_pfe->fd, (struct sockaddr *)&vip, &vl) == 0 &&
          cli.sin_family == AF_INET && vip.sin_family == AF_INET) {
        dpp2len = proxy_build_ppv2_v4(dpp2buf, sizeof(dpp2buf),
                                      cli.sin_addr.s_addr, cli.sin_port,
                                      vip.sin_addr.s_addr, vip.sin_port);
      }
    }
    d_cfd = proxy_setup_ep_connect(tepval->eps[d_idx].xip,
                                   tepval->eps[d_idx].xport,
                                   IPPROTO_TCP, NULL, NULL, client_pfe,
                                   (dpp2len ? dpp2buf : NULL), dpp2len);
  }
  if (d_cfd < 0) {
    circuit_breaker_record_failure(tepval, d_idx);
    close(p_cfd);
    p_cfd = -1;
    goto fail;
  }

  /* 4. Fresh room + re-injection into the ORIGINAL body under the ORIGINAL
   * headers (same X-Request-Id), Content-Length re-fitted. The saved body is
   * pristine pre-injection by construction (the admission-site contract). */
  {
    char sg_host[INET6_ADDRSTRLEN + 2];
    struct in_addr sg_pin = { .s_addr = tepval->eps[p_idx].xip };
    inet_ntop(AF_INET, &sg_pin, sg_host, sizeof(sg_host));

    if (pd_sg_room_id(&new_room) != 0 ||
        (inj = malloc(body_len + 512)) == NULL ||
        pd_sg_inject_bootstrap(body, body_len, inj, &inj_len, body_len + 512,
                               sg_host, tepval->pd_bootstrap_port,
                               new_room) != 0) {
      log_error("[PD_SG] pair retry: bootstrap re-injection failed "
                "(client_fd=%d)", client_pfe->fd);
      close(p_cfd);
      close(d_cfd);
      p_cfd = d_cfd = -1;
      goto fail;
    }
    size_t req_cap = hdrs_len + inj_len + 256;
    req = malloc(req_cap);
    if (!req) {
      close(p_cfd);
      close(d_cfd);
      p_cfd = d_cfd = -1;
      goto fail;
    }
    memcpy(req, hdrs, hdrs_len);
    memcpy(req + hdrs_len, inj, inj_len);
    req_len = hdrs_len + inj_len;
    pd_update_content_length(req, &req_len, req_cap, inj_len);
  }

  /* 5. Move the admission active_conns units dead->replacement (both roles)
   * so pd_cleanup's decrement of the FINAL indexes stays balanced. */
  if (dead_idx >= 0 && dead_idx < tepval->n_eps) {
    uint32_t cur = atomic_load(&tepval->pd_ep_loads[dead_idx].active_conns);
    if (cur > 0)
      atomic_fetch_sub(&tepval->pd_ep_loads[dead_idx].active_conns, 1);
  }
  atomic_fetch_add(&tepval->pd_ep_loads[p_idx].active_conns, 1);
  if (d_idx != old_d_idx) {
    if (old_d_idx >= 0 && old_d_idx < tepval->n_eps) {
      uint32_t cur = atomic_load(&tepval->pd_ep_loads[old_d_idx].active_conns);
      if (cur > 0)
        atomic_fetch_sub(&tepval->pd_ep_loads[old_d_idx].active_conns, 1);
    }
    atomic_fetch_add(&tepval->pd_ep_loads[d_idx].active_conns, 1);
  }
  client_pfe->pd_prefill_ep_idx = p_idx;
  client_pfe->pd_decode_ep_idx = d_idx;

  /* 6. Bring up BOTH replacement legs — fresh drain pfe (dedicated
   * HTTP_RESPONSE framer, never client-facing) + fresh decode pfe (the
   * pd_sg_dual_dispatch shapes), each pinned to the client fd's worker. */
  {
    proxy_map_ent_t *hent = (proxy_map_ent_t *)client_pfe->head;
    proxy_fd_ent_t *drain_pfe = pfe_alloc();
    proxy_fd_ent_t *decode_pfe = drain_pfe ? pfe_alloc() : NULL;
    if (!drain_pfe || !decode_pfe || !hent) {
      /* Alloc failure BEFORE any registration: close both fds and abort.
       * (Both shells are allocated up front so a half-registered pair can
       * never exist; an unregistered shell is an accepted OOM-path loss —
       * the pool is grow-only.) */
      close(p_cfd);
      close(d_cfd);
      p_cfd = d_cfd = -1;
      goto fail;
    }

    drain_pfe->stype = PROXY_SOCK_ACTIVE;
    drain_pfe->pd_decode_ep_idx = -1;
    drain_pfe->fd = p_cfd;
    drain_pfe->rfd[0] = client_pfe->fd;
    drain_pfe->rfd_ent[0] = client_pfe;
    drain_pfe->seltype = client_pfe->seltype;
    drain_pfe->ep_num = -1;
    drain_pfe->odir = 1;
    drain_pfe->n_rfd = 1;
    drain_pfe->head = client_pfe->head;
    drain_pfe->sse_mode = client_pfe->sse_mode;
    drain_pfe->max_stream_duration_sec = client_pfe->max_stream_duration_sec;
    drain_pfe->backend_keepalive_sec = client_pfe->backend_keepalive_sec;
    pd_sg_drain_parser_init(drain_pfe);
    drain_pfe->pd_sg_drain = 1;

    decode_pfe->stype = PROXY_SOCK_ACTIVE;
    decode_pfe->pd_decode_ep_idx = -1;
    decode_pfe->fd = d_cfd;
    decode_pfe->rfd[0] = client_pfe->fd;
    decode_pfe->rfd_ent[0] = client_pfe;
    decode_pfe->seltype = client_pfe->seltype;
    decode_pfe->ep_num = -1;
    decode_pfe->odir = 1;
    decode_pfe->is_pd_decode_backend = 1;
    decode_pfe->n_rfd = 1;
    decode_pfe->head = client_pfe->head;
    decode_pfe->sse_mode = client_pfe->sse_mode;
    decode_pfe->max_stream_duration_sec = client_pfe->max_stream_duration_sec;
    decode_pfe->backend_keepalive_sec = client_pfe->backend_keepalive_sec;
    if (pd_framing_v2_on()) {
      pd_resp_parser_init(decode_pfe);
    } else {
      llhttp_init(&decode_pfe->parser, HTTP_BOTH, &decode_pfe->settings);
      decode_pfe->settings.on_message_complete = handle_on_message_complete;
      decode_pfe->settings.uarg = decode_pfe;
    }

    /* Link into the client's rfd slots (first free slot — the old legs left
     * holes at 0/1) and register both legs. */
    for (int j = 0; j < MAX_PROXY_EP; j++) {
      if (!client_pfe->rfd_ent[j]) {
        client_pfe->rfd[j] = p_cfd;
        client_pfe->rfd_ent[j] = drain_pfe;
        client_pfe->n_rfd++;
        break;
      }
    }
    for (int j = 0; j < MAX_PROXY_EP; j++) {
      if (!client_pfe->rfd_ent[j]) {
        client_pfe->rfd[j] = d_cfd;
        client_pfe->rfd_ent[j] = decode_pfe;
        client_pfe->n_rfd++;
        break;
      }
    }

    PROXY_LOCK();
    drain_pfe->next = hent->val.fdlist;
    hent->val.fdlist = drain_pfe;
    hent->val.nfds++;
    decode_pfe->next = hent->val.fdlist;
    hent->val.fdlist = decode_pfe;
    hent->val.nfds++;
    PROXY_UNLOCK();
    notify_add_ent_pinned(proxy_struct->ns, p_cfd,
                          NOTI_TYPE_IN|NOTI_TYPE_HUP, drain_pfe,
                          drain_pfe->gen, client_pfe->fd);
    notify_add_ent_pinned(proxy_struct->ns, d_cfd,
                          NOTI_TYPE_IN|NOTI_TYPE_HUP, decode_pfe,
                          decode_pfe->gen, client_pfe->fd);
  }

  /* 7. Restart the pair state: same DECODE_SENDING lifecycle, fresh reaper
   * window, fresh latency stamps, the NEW room recorded for logs/coupling. */
  client_pfe->pd_sg_room = new_room;
  client_pfe->pd_phase = PD_PHASE_DECODE_SENDING;
  client_pfe->pd_phase_start_ts = time(NULL);
  {
    struct timespec _ts;
    clock_gettime(CLOCK_MONOTONIC, &_ts);
    uint64_t now_ns = (uint64_t)_ts.tv_sec * 1000000000ULL +
                      (uint64_t)_ts.tv_nsec;
    client_pfe->pd_prefill_start_ns = now_ns;
    client_pfe->pd_decode_start_ns = now_ns;
  }

  /* 8. Same payload down both legs (fresh plaintext connects — TLS backend
   * legs were excluded at the enqueue gate, vLLM parity). A send failure
   * surfaces as that leg's HUP: the drain leg's death re-enters the
   * exhausted-budget abort, the decode leg's death the zero-byte 502. */
  {
    size_t sent = 0;
    while (sent < req_len) {
      ssize_t n = write(p_cfd, req + sent, req_len - sent);
      if (n <= 0) {
        if (errno == EINTR || errno == EAGAIN) continue;
        log_error("[PD_SG] pair retry: prefill send to EP%d failed: %s",
                  p_idx, strerror(errno));
        goto counted;
      }
      sent += (size_t)n;
    }
    sent = 0;
    while (sent < req_len) {
      ssize_t n = write(d_cfd, req + sent, req_len - sent);
      if (n <= 0) {
        if (errno == EINTR || errno == EAGAIN) continue;
        log_error("[PD_SG] pair retry: decode send to EP%d failed: %s",
                  d_idx, strerror(errno));
        goto counted;
      }
      sent += (size_t)n;
    }
  }

counted:
  /* 9. Re-pin the session to the healthy pair (vLLM failover parity). */
  {
    const char *sk = NULL;
    if (client_pfe->has_user_id && client_pfe->user_id[0] != '\0')
      sk = client_pfe->user_id;
    if (client_pfe->has_conv_id && client_pfe->conversation_id[0] != '\0' &&
        strncmp(client_pfe->conversation_id, "auto-", 5) != 0)
      sk = client_pfe->conversation_id;
    if (sk) pd_session_store(tepval, sk, p_idx, d_idx);
  }

  atomic_fetch_add(&global_stats.pd_sg_room_retry, 1);
  atomic_fetch_add(&global_stats.pd_connect_failover, 1);
  log_info("[PD_SG] pair retry — client_fd=%d prefill EP%d died -> "
           "pair(EP%d,EP%d) room %llu -> %llu req=%zuB",
           client_pfe->fd, dead_idx, p_idx, d_idx,
           (unsigned long long)old_room, (unsigned long long)new_room,
           req_len);
  goto done;

fail:
  if (client_pfe) {
    log_error("[PD_SG] pair retry exhausted — aborting (client_fd=%d "
              "dead EP%d)", client_pfe->fd, dead_idx);
    pd_sg_abort_pair(client_pfe, "pair retry failed", 0 /*transport*/);
  }

done:
  free(inj);
  free(req);
  free(hdrs);
  free(body);
}

/* --- Dialect ops --------------------------------------------------------- */

/* SGLang dual-dispatch preparation: inject the bootstrap triple (prefill EP
 * host, bootstrap port, fresh room) into the body — the SAME rewritten body
 * goes to BOTH legs at the dispatch site. The ORIGINAL body is saved for a
 * pair-retry re-injection with a fresh room. Injection failure fails CLOSED
 * (503, returns <0): a bootstrap-less request against a prefill-mode SGLang
 * server parks at the engine until its 300s disaggregation timeout. */
static int
pd_sg_prepare_request(struct proxy_fd_ent *pfe, struct proxy_epval *epval,
                      size_t hdr_len, const uint8_t *body, size_t body_len)
{
  uint64_t sg_room = 0;
  uint8_t *sg_buf = NULL;
  size_t sg_len = 0;
  char sg_host[INET6_ADDRSTRLEN + 2];
  int sg_pidx = pfe->pd_prefill_ep_idx;

  /* A streamed request was never fully buffered, so the body handed in here
   * is a truncated fragment — bootstrap injection is impossible by
   * construction. Refuse honestly as OVERSIZE: the generic prep-failure
   * below misattributes it to pool health ("pd_pool_unavailable"), and the
   * paths that skip preparation entirely relay it PLAIN, drawing an engine
   * 400 that blames the client — or a park on engines that skip the
   * bootstrap validation. */
  if (pfe->is_streamable || body_len < pfe->http_content_length) {
    pd_sg_oversize_reject(pfe);
    return -1;
  }

  if (sg_pidx >= 0 && sg_pidx < epval->n_eps &&
      pd_sg_room_id(&sg_room) == 0 &&
      (sg_buf = malloc(body_len + 512)) != NULL) {
    struct in_addr sg_pin = { .s_addr = epval->eps[sg_pidx].xip };
    inet_ntop(AF_INET, &sg_pin, sg_host, sizeof(sg_host));
    if (pd_sg_inject_bootstrap(body, body_len,
                               sg_buf, &sg_len, body_len + 512,
                               sg_host, epval->pd_bootstrap_port,
                               sg_room) == 0 &&
        hdr_len + sg_len < SP_SOCK_MSG_LEN) {
      pfe->pd_saved_body = malloc(body_len);
      if (pfe->pd_saved_body) {
        memcpy(pfe->pd_saved_body, body, body_len);
        pfe->pd_saved_body_len = body_len;
      }
      memcpy(pfe->rcvbuf + hdr_len, sg_buf, sg_len);
      pfe->rcv_off = hdr_len + sg_len;
      pfe->pd_prefill_body_len = sg_len;
      pd_update_content_length(pfe->rcvbuf, &pfe->rcv_off,
                               SP_SOCK_MSG_LEN, sg_len);
      pfe->pd_sg_active = 1;
      pfe->pd_sg_room = sg_room;
      pfe->pd_phase_start_ts = time(NULL);
      {
        struct timespec _ts;
        clock_gettime(CLOCK_MONOTONIC, &_ts);
        pfe->pd_prefill_start_ns =
            (uint64_t)_ts.tv_sec * 1000000000ULL +
            (uint64_t)_ts.tv_nsec;
      }
      log_info("[PD_SG] entry — fd=%d prefill_ep=%d decode_ep=%d "
               "bootstrap=%s:%u room=%llu orig_body=%zu inj_body=%zu",
               pfe->fd, sg_pidx, pfe->pd_decode_ep_idx, sg_host,
               epval->pd_bootstrap_port,
               (unsigned long long)sg_room, body_len, sg_len);
    }
  }
  free(sg_buf);

  if (!pfe->pd_sg_active) {
    static const char pd_sg_prep_err[] =
        "HTTP/1.1 503 Service Unavailable\r\n"
        "Content-Type: application/json\r\n"
        "Connection: close\r\n"
        "\r\n"
        "{\"error\":\"pd_pool_unavailable\",\"detail\":\"sglang bootstrap injection failed\"}";
    log_error("[PD_SG] bootstrap prep failed — fd=%d prefill_ep=%d "
              "(failing closed)", pfe->fd, sg_pidx);
    if (pfe->ssl) {
      SSL_write(pfe->ssl, pd_sg_prep_err, sizeof(pd_sg_prep_err) - 1);
    } else {
      send(pfe->fd, pd_sg_prep_err, sizeof(pd_sg_prep_err) - 1,
           MSG_DONTWAIT | MSG_NOSIGNAL);
    }
    pd_free_claim(&pfe->pd_saved_body);
    pfe->pd_saved_body_len = 0;
    shutdown(pfe->fd, SHUT_RDWR);
    return -1;
  }
  return 0;
}

/* SGLang forward: same injected payload down BOTH legs — the admission-time
 * prefill connection (slot 0, now the drain leg) and a fresh decode leg.
 * Enters the decode lifecycle directly. On failure the 503 + record +
 * cleanup already happened inside pd_sg_dual_dispatch. */
static int
pd_sg_dispatch(struct proxy_fd_ent *pfe)
{
  if (pd_sg_dual_dispatch(pfe) < 0) {
    pfe->pd_sg_active = 0;
    return -1;
  }
  return 0;
}

const pd_dialect_ops_t pd_dialect_sglang = {
  .name = "sglang",
  .prepare_request = pd_sg_prepare_request,
  .dispatch = pd_sg_dispatch,
  .on_prefill_response = NULL,
  .on_leg_error = NULL,
  .collect_retry = NULL,
  .reap = NULL,
};
