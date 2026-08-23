/* sockproxy_pd.h - P/D disaggregation engine-dialect ops table
 *
 * Each LLM framework speaks a different P/D orchestration dialect:
 *   vLLM    — SEQUENTIAL machine: kv_transfer_params append → prefill send →
 *             response parse/extract → decode re-dispatch → prefill retry.
 *   SGLang  — DUAL-DISPATCH machine: bootstrap triple injection (room RNG),
 *             simultaneous prefill(drain)/decode legs, pair-retry,
 *             rendezvous-wedge reaper.
 *   TRT-LLM — the SEQUENTIAL machine with a different body dialect:
 *             disaggregated_params splice (context_only) → buffered context
 *             response → params re-splice (generation_only) or early exit
 *             when the context step already finished the request.
 * The HTTP engine selects an ops pointer once per rule (proxy_add, from
 * pd_engine) and caches it on the epval; request-lifecycle events then call
 * through the table and never ask which engine they are speaking to.
 *
 * The machines live in sockproxy_pd_vllm.c / sockproxy_pd_sglang.c /
 * sockproxy_pd_trtllm.c, which each define their pd_dialect_ops table;
 * engine-neutral dispatch glue is in sockproxy_pd_core.c. A slot may be
 * NULL when the dialect has no use for that lifecycle event. TRT-LLM rides
 * the vLLM sequential machine (sockproxy_pd_vllm.c), which selects the
 * dialect's body-surgery functions by epval->pd_engine.
 */

#ifndef __SOCKPROXY_PD_H__
#define __SOCKPROXY_PD_H__

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

struct proxy_fd_ent;   /* sockproxy.h */
struct proxy_epval;    /* sockproxy.h */

typedef struct pd_dialect_ops {
  const char *name;              /* "vllm" | "sglang" | "trtllm" */

  /* Body rewrite before dispatch, called with the located request body
   * (hdr_len/body point into pfe->rcvbuf). vllm: save original +
   * kv_transfer_params prefill rewrite. sglang: bootstrap triple injection.
   * Returns 0 to continue forwarding, <0 when the request was terminated
   * (fail-closed 503 already sent) and the caller must restart the fd. */
  int (*prepare_request)(struct proxy_fd_ent *pfe, struct proxy_epval *epval,
                         size_t hdr_len, const uint8_t *body, size_t body_len);

  /* Forward the prepared request. vllm: prefill leg only, phase →
   * PREFILL_WAITING. sglang: pd_sg_dual_dispatch (failure 503 handled
   * inside). Returns 0 on success, <0 on dispatch failure. */
  int (*dispatch)(struct proxy_fd_ent *pfe);

  /* Prefill-leg response bytes. vllm: parse, extract kv_transfer_params,
   * build + send the decode request. sglang: drain + status-check only. */
  int (*on_prefill_response)(struct proxy_fd_ent *pfe,
                             const uint8_t *buf, size_t len);

  /* Failure coupling + retry eligibility (HTTP status vs transport error). */
  int (*on_leg_error)(struct proxy_fd_ent *pfe, int leg, int err);

  /* proxy_pdestroy deferred-retry collection (prefill-retry vs pair-retry). */
  int (*collect_retry)(struct proxy_fd_ent *pfe);

  /* Timeout semantics (30s prefill timeout vs rendezvous wedge 504). */
  int (*reap)(struct proxy_fd_ent *pfe, time_t now);

  /* Token accounting: scan RESPONSE bytes (the relay path's sliding tail
   * window) for the engine's usage report and return prompt/completion
   * token counts. Every supported engine follows the OpenAI convention —
   * usage rides the final pre-[DONE] SSE chunk under
   * stream_options.include_usage, or the body object non-streaming — so all
   * dialects currently bind the shared parser; the op stays per-dialect so
   * a divergent engine can override without touching the relay path.
   * Returns 0 when at least one count was extracted. */
  int (*extract_usage)(struct proxy_fd_ent *pfe, const uint8_t *buf,
                       size_t len, int *prompt_tokens, int *completion_tokens);
} pd_dialect_ops_t;

/* Dialect instances. Defined next to their machines (sockproxy_http.c until
 * extraction moves them into their sockproxy_pd_<engine>.c homes). */
extern const pd_dialect_ops_t pd_dialect_vllm;
extern const pd_dialect_ops_t pd_dialect_sglang;
extern const pd_dialect_ops_t pd_dialect_trtllm;

/* Plain-LB profile for AI-gateway rules that never resolve an engine
 * dialect (no kv_engine_type — e.g. a converged llama.cpp fleet). Only
 * extract_usage is populated; the P/D orchestration ops stay NULL. */
extern const pd_dialect_ops_t pd_dialect_plain;

/* Shared OpenAI-convention usage extractor bound by all dialect profiles
 * (sockproxy_pd_core.c). */
int pd_usage_extract_openai(struct proxy_fd_ent *pfe, const uint8_t *buf,
                            size_t len, int *prompt_tokens,
                            int *completion_tokens);

/* Wire kv_engine_type → PD_ENGINE_* (sockproxy.h). Unknown values degrade
 * to PD_ENGINE_VLLM. */
uint8_t pd_engine_from_kv_engine_type(uint8_t kv_engine_type);

/* PD_ENGINE_* (sockproxy.h) → ops table. Never returns NULL. */
const pd_dialect_ops_t *pd_dialect_resolve(uint8_t pd_engine);

/* --- Shared body-rewrite helpers (sockproxy_pd.c) ------------------------ */

int pd_prepare_prefill_body(const uint8_t *orig_body, size_t orig_body_len,
                            uint8_t *out_buf, size_t *out_len,
                            size_t out_capacity);
int pd_extract_kv_params(const uint8_t *resp_buf, size_t resp_len,
                         char *kv_out, size_t *kv_out_len, size_t kv_capacity);
int pd_prepare_decode_body(const uint8_t *orig_body, size_t orig_body_len,
                           const char *kv_params, size_t kv_params_len,
                           uint8_t *out_buf, size_t *out_len,
                           size_t out_capacity);
int pd_sg_room_id(uint64_t *room_out);
int pd_sg_inject_bootstrap(const uint8_t *orig_body, size_t orig_body_len,
                           uint8_t *out_buf, size_t *out_len,
                           size_t out_capacity, const char *bootstrap_host,
                           uint16_t bootstrap_port, uint64_t bootstrap_room);

/* TRT-LLM sequential-dialect body surgery (sockproxy_pd.c). The _id
 * variant takes a deterministic disagg_request_id for the unit vectors;
 * production draws a fresh int63 per context dispatch. */
int pd_trt_prepare_prefill_body(const uint8_t *orig_body,
                                size_t orig_body_len, uint8_t *out_buf,
                                size_t *out_len, size_t out_capacity);
int pd_trt_prepare_prefill_body_id(const uint8_t *orig_body,
                                   size_t orig_body_len, uint8_t *out_buf,
                                   size_t *out_len, size_t out_capacity,
                                   uint64_t disagg_id);
int pd_trt_extract_disagg_params(const uint8_t *resp_buf, size_t resp_len,
                                 char *dp_out, size_t *dp_out_len,
                                 size_t dp_capacity);
int pd_trt_prepare_decode_body(const uint8_t *orig_body,
                               size_t orig_body_len, const char *dp,
                               size_t dp_len, uint8_t *out_buf,
                               size_t *out_len, size_t out_capacity);
int pd_trt_ctx_early_exit_check(const uint8_t *resp_buf, size_t resp_len);
int pd_trt_stream_requested(const uint8_t *body, size_t body_len);

/* --- Machine-agnostic helpers (sockproxy_pd_core.c) ---------------------- */

/* Update Content-Length header in an HTTP request buffer (memmem+memmove).
 * Returns 0 on success, -1 on error. */
int pd_update_content_length(uint8_t *buf, size_t *buf_len,
                             size_t buf_capacity, size_t new_body_len);

/* [FRAME_MISMATCH] log-only forward-site instrument. */
void pd_frame_mismatch_log(struct proxy_fd_ent *pfe, const uint8_t *buf,
                           size_t cur_len, size_t declared_cl,
                           const char *site);

/* (conc-wedge RCA): race-safe single-owner free of a P/D heap buffer.
 *
 * A P/D connection spans TWO fds — the client fd and the backend
 * (prefill/decode) rfd — which notify.c shards to DIFFERENT worker threads
 * (`tslot = fd % n_thrs`). So pd_cleanup() can run for the SAME client pfe
 * on two threads at once: the decode-completion path (proxy_try_epxmit ->
 * pd_cleanup(rfd_ent), on the backend fd's worker) racing the client-close
 * path (proxy_release_fd_ctx -> pd_cleanup, on the client fd's worker). The
 * historic `if (p) { free(p); p = NULL; }` is a check-then-act race: both
 * threads see p != NULL, both free the SAME pointer before either NULLs it
 * -> double free -> glibc heap-corruption abort. Under conc=128 this
 * reproduced in ~55s and PERMANENTLY wedged loxilb: the aborting thread dies
 * holding the malloc arena lock, so every other worker blocks in
 * free()/malloc() on that arena futex and no thread services new connections
 * (both VIPs -> 000, no self-heal). Live-confirmed by gdb: 3 workers stuck
 * in pd_cleanup->_int_free->futex on the arena, 1 in __libc_message->abort.
 *
 * __atomic_exchange makes exactly ONE caller win the pointer (and free it);
 * the loser observes NULL and skips. Lock-free, no lock-ordering risk. */
static inline void
pd_free_claim(uint8_t **pp)
{
  uint8_t *p = __atomic_exchange_n(pp, NULL, __ATOMIC_ACQ_REL);
  if (p) {
    free(p);
  }
}

/* --- vLLM sequential machine (sockproxy_pd_vllm.c) -----------------------
 * Shared by the TRT-LLM dialect, which parameterizes the body-surgery
 * sites (rewriter selection by epval->pd_engine inside the machine). */

/* Prefill-body rewriter signature shared by the sequential machine's
 * dialects (pd_prepare_prefill_body / pd_trt_prepare_prefill_body). */
typedef int (*pd_body_rewrite_t)(const uint8_t *orig_body,
                                 size_t orig_body_len, uint8_t *out_buf,
                                 size_t *out_len, size_t out_capacity);

/* Sequential-machine request preparation: save the original body, rewrite
 * it via the dialect's prefill rewriter, arm the response buffer and the
 * phase/timestamps. Never fails the client (falls back to plain
 * forwarding of the untouched request). */
int pd_seq_prepare_request(struct proxy_fd_ent *pfe,
                           struct proxy_epval *epval, size_t hdr_len,
                           const uint8_t *body, size_t body_len,
                           pd_body_rewrite_t rewrite);

/* Sequential-machine forward: prefill leg only, phase → PREFILL_WAITING.
 * Shared verbatim by the vLLM and TRT-LLM dialect tables. */
int pd_vllm_dispatch(struct proxy_fd_ent *pfe);

/* Initiate the decode phase after prefill completes. */
int pd_initiate_decode(struct proxy_fd_ent *client_pfe);

/* Mid-request prefill failover (deferred from proxy_pdestroy; owns and frees
 * hdrs/body). */
void pd_retry_prefill(struct proxy_fd_ent *client_pfe, int dead_idx,
                      uint8_t *hdrs, size_t hdrs_len,
                      uint8_t *body, size_t body_len);

/* --- TRT-LLM dialect glue (sockproxy_pd_trtllm.c) ------------------------ */

/* Early exit: the buffered context response already finished the request —
 * relay it to the client (verbatim, or one-chunk SSE re-frame when the
 * client asked for streaming), record metrics and complete the P/D flow
 * without a decode leg. Counted in global_stats.pd_trt_ctx_early_exit. */
void pd_trt_early_exit_relay(struct proxy_fd_ent *client_pfe,
                             const uint8_t *resp, size_t resp_len,
                             int stream_requested);

/* --- SGLang dual-dispatch machine (sockproxy_pd_sglang.c) ----------------
 * Entry points the HTTP engine's relay/teardown glue calls into: drain-leg
 * byte consumption, failure coupling, and the deferred pair retry. */

/* Consume + discard drain-leg bytes; fire failure coupling on 4xx/5xx. */
void pd_sg_drain_consume(struct proxy_fd_ent *ent,
                         struct proxy_fd_ent *client_pfe,
                         uint8_t *msg, size_t len);

/* Close a still-attached prefill drain leg (count_close ticks the
 * decode-failure coupling counter; janitorial closes pass 0). */
void pd_sg_close_drain(struct proxy_fd_ent *client_pfe, int count_close);

/* Abort the pair: 502 to the client, both legs torn down, prefill error
 * recorded. */
void pd_sg_abort_pair(struct proxy_fd_ent *client_pfe, const char *reason,
                      unsigned origin_status);
void pd_sg_relay_finalize(struct proxy_fd_ent *client_pfe);
void pd_sg_oversize_reject(struct proxy_fd_ent *client_pfe);

/* Zero decode bytes relayed so far? (The decode-zero-byte-EOF predicate.) */
int pd_sg_decode_untouched(const struct proxy_fd_ent *client_pfe);

/* Pair retry with a fresh room (deferred from proxy_pdestroy; owns and frees
 * hdrs/body). */
void pd_sg_retry_pair(struct proxy_fd_ent *client_pfe, int dead_idx,
                      uint8_t *hdrs, size_t hdrs_len,
                      uint8_t *body, size_t body_len);

/* --- HTTP-engine services consumed by the dialect machines ----------------
 * Defined in sockproxy_http.c; the machines call back into the engine for
 * relay, response framing and the legacy message-complete orchestration. */

struct llhttp__internal_s;  /* llhttp.h: llhttp_t */

int  proxy_try_epxmit(struct proxy_fd_ent *ent, void *msg, size_t len,
                      int sel);
int  handle_on_message_complete(struct llhttp__internal_s *parser);
void pd_resp_parser_init(struct proxy_fd_ent *pfe);
int  pd_framing_v2_on(void);

#endif /* __SOCKPROXY_PD_H__ */
