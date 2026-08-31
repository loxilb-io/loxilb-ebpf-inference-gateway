/*
 * Copyright (c) 2025 LoxiLB Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __SOCKPROXY_AI_GW_H__
#define __SOCKPROXY_AI_GW_H__

#include <stdint.h>

/*
 * AI Gateway decision structure.
 *
 * Populated by llb_ai_validate_key (Go CGO export in ai_gateway_dp.go).
 * The struct layout must stay in sync with the CGO preamble in that file.
 *
 * decision values:
 *   0  – allow the request to proceed
 *   1  – deny with 401 (missing / disabled / expired API key)
 *   2  – deny with 403 (model not in key's AllowedModels list)
 *   3  – deny with 429 (rate limit exceeded; retry_after set in seconds)
 *   4  – deny with 503 (policy store unavailable: the service's api_key_auth
 *        policy requires a key and the store cannot answer. Deliberately NOT
 *        a 401 -- a client must be able to tell "your key is wrong" from "the
 *        gateway cannot tell right now", because only the second is worth
 *        retrying.)
 */
typedef struct {
    int  decision;
    int  retry_after;
    char tenant_id[128];
    char model_name[128];
    char key_id[64];
    char error_code[64];
} ai_gw_decision_t;

/*
 * llb_ai_validate_key – validate the X-API-Key HTTP header.
 *
 * Parameters:
 *   raw_key    value from the X-API-Key header (NUL-terminated C string)
 *   model_name model name parsed from the request body; pass "" if absent
 *   result     output structure filled on both allow and deny paths
 *
 * Returns:
 *    0  request is allowed; result->decision == 0
 *   -1  request must be rejected; inspect result->decision for HTTP status
 */
extern int llb_ai_validate_key(char *raw_key, char *model_name, ai_gw_decision_t *result);

/*
 * llb_ai_ratelimit_check – enforce per-key and per-tenant RPS limits.
 *
 * The check is performed in two stages: first the per-key bucket is consulted,
 * then the per-tenant shared bucket. Either stage can deny the request.
 *
 * Parameters:
 *   key_id    the validated API key's key_id string
 *   tenant_id the validated API key's tenant_id string
 *   model     the request's body-bound model name (may be empty); selects the
 *             tenant|model token bucket for the token-quota stage
 *   result    output structure; on denial, decision is set to 3 (429),
 *             retry_after is set in seconds, and error_code is populated
 *
 * Returns:
 *    0  request is within rate limits; proceed
 *   -1  request is rate-limited; inspect result->decision and result->retry_after
 */
extern int llb_ai_ratelimit_check(char *key_id, char *tenant_id, char *model,
                                  ai_gw_decision_t *result);

/*
 * llb_ai_ratelimit_update – synchronously refresh in-memory rate-limit buckets.
 *
 * Call this from the control plane whenever the operator changes the rate-limit
 * configuration so that the data plane applies the new limits immediately.
 *
 * Parameters:
 *   key_id    API key's key_id; pass "" to skip key update
 *   tenant_id tenant ID; pass "" to skip tenant update
 *   rps       new rate in requests per second (0 removes the limit)
 *   burst     new burst size; if <= 0 defaults to rps
 *
 * Returns 0 on success.
 */
extern int llb_ai_ratelimit_update(char *key_id, char *tenant_id, int rps, int burst);

/*
 * llb_ai_record_request – record a completed AI Gateway request for Prometheus metrics.
 *
 * C sockproxy calls this once on response completion (or on SSE stream open/close
 * events). The Go implementation sanitises label values and increments the
 * appropriate promauto counters and gauges.
 *
 * Parameters:
 *   tenant_id:      tenant identifier from the validated API key (NUL-terminated)
 *   model_name:     effective model name (X-Model header > JSON body > "")
 *   status_code:    HTTP response status code (200, 401, 403, 429, 500, …)
 *   latency_ms:     request latency in milliseconds; 0 when unknown
 *   prompt_tokens:  token count from the request body; 0 when absent
 *   complet_tokens: token count from the response body; 0 when absent
 *   stream_start:   1 when opening an SSE stream, 0 otherwise
 *   stream_end:     1 when closing an SSE stream, 0 otherwise
 *   error_code:     for 429 responses, the specific denial reason from
 *                   ai_gw_decision_t ("rate_limit_exceeded", "tenant_quota_exceeded",
 *                   "token_quota_exceeded"); pass "" for non-429 responses
 *
 * Returns void.
 */
extern void llb_ai_record_request(char *tenant_id, char *model_name, int status_code,
                                  int64_t latency_ms, int prompt_tokens, int complet_tokens,
                                  int stream_start, int stream_end, char *error_code);

/*
 * llb_ai_stream_start – record the opening of an SSE stream.
 *
 * Call once when the Content-Type: text/event-stream response header is
 * observed. Increments the loxilb_ai_active_streams Prometheus gauge and the
 * per-model in-flight counter in the Go layer.
 *
 * Parameters:
 *   tenant_id  validated tenant identifier (NUL-terminated)
 *   model_name effective model name (NUL-terminated)
 *
 * Returns 0 on success.
 */
extern int llb_ai_stream_start(char *tenant_id, char *model_name);

/*
 * llb_ai_stream_end – record the closing of an SSE stream.
 *
 * Call once when data:[DONE]\n\n is observed or the stream is terminated.
 * Decrements the loxilb_ai_active_streams Prometheus gauge with an
 * idempotency guard that prevents the gauge going below zero.
 *
 * Parameters:
 *   tenant_id  validated tenant identifier (NUL-terminated)
 *   model_name effective model name (NUL-terminated)
 *
 * Returns 0 when the gauge was decremented; 1 when the call was spurious
 * (stream_end called more times than stream_start for the given model).
 */
extern int llb_ai_stream_end(char *tenant_id, char *model_name);

/*
 * llb_ai_token_quota_consume – record token usage after a completed response.
 *
 * C sockproxy calls this after an SSE stream completes (data:[DONE]\n\n) or
 * after a full non-streaming response is received. Token counts are extracted
 * by the existing jsmn parser from the final SSE usage chunk or the response
 * body.
 *
 * If both prompt_tokens and complet_tokens are 0 (absent usage chunk), the
 * loxilb_ai_tokens_missing_total counter is incremented and the quota is NOT
 * charged (best-effort accounting mode, B-2). Operators should set
 * stream_options:{include_usage:true} on OpenAI-compatible clients to enable
 * accurate per-request accounting.
 *
 * If quota is exceeded after consumption the tenant's exceeded flag is set;
 * the NEXT request's llb_ai_ratelimit_check will return decision=3 (HTTP 429).
 * The current response is already complete and is NOT interrupted.
 *
 * Parameters:
 *   tenant_id      tenant identifier from the validated API key (NUL-terminated)
 *   model_name     effective model name (NUL-terminated; pass "" if unknown)
 *   prompt_tokens  token count from the request body; 0 when absent
 *   complet_tokens token count from the response body; 0 when absent
 *   estimated      1 when the counts come from the estimate net (request-size
 *                  prompt estimate + SSE chunk count) rather than an extracted
 *                  usage object; feeds the estimated-tokens split metric
 *   reserved_toks  the admission-time reservation made for this request by
 *                  llb_ai_token_quota_reserve (prompt estimate + max_tokens);
 *                  released here and replaced by the real charge. Pass 0 when
 *                  no reservation was made. Must be passed even when both
 *                  token counts are 0 — an uncounted response still has to
 *                  give its claim back.
 *   res_epoch      the reservation's window tag returned by
 *                  llb_ai_token_quota_reserve; the release is skipped when
 *                  the window has already rolled over (the rollover wiped the
 *                  claim). Pass 0 when no reservation was made.
 *   result         output structure; decision may be set to 3 when quota exceeded
 *
 * Returns:
 *    0  quota not exceeded (or no quota configured)
 *   -1  quota exceeded; result->decision == 3 and result->retry_after is set
 */
extern int llb_ai_token_quota_consume(char *tenant_id, char *model_name,
                                      int prompt_tokens, int complet_tokens,
                                      int estimated, int reserved_toks,
                                      int64_t res_epoch,
                                      ai_gw_decision_t *result);

/*
 * llb_ai_token_quota_reserve – pre-admission token reservation.
 *
 * Called at the AI gate (message-complete, after the key and RPS checks
 * pass) with the request's worst-case token spend: the prompt estimated
 * from the body's messages/prompt byte extent plus the declared
 * max_tokens/max_completion_tokens ceiling. When the tenant's remaining
 * per-minute quota cannot cover it, the request is denied 429 BEFORE it is
 * dispatched to a backend — no GPU prefill is burned on a request whose
 * quota is already spoken for.
 *
 * On admission the caller must stash the reserved amount and *res_epoch on
 * the connection and echo both to llb_ai_token_quota_consume at response
 * completion, which credits the pessimistic claim back and charges the real
 * usage. A reservation orphaned by an aborted request self-heals at the
 * next window rollover (bounded at one 60-second window).
 *
 * A denial does NOT latch the tenant's exceeded flag: it is sized to this
 * request, and a smaller request may still be admitted in the same window.
 *
 * Parameters:
 *   tenant_id   tenant identifier from the validated API key (NUL-terminated)
 *   model_name  effective model name (NUL-terminated; pass "" if unknown)
 *   prompt_est  prompt-token estimate from the request body; 0 when unknown
 *   max_tokens  declared completion ceiling from the request body; 0 when
 *               the client did not declare one (only the prompt estimate is
 *               then reserved — an undeclared ceiling cannot be guessed)
 *   res_epoch   output: the reservation's window tag to echo at settlement;
 *               0 when nothing was reserved (no quota configured)
 *   result      output structure; on denial decision=3, retry_after set and
 *               error_code = "token_quota_would_exceed" (distinct from the
 *               post-hoc "token_quota_exceeded" latch denial)
 *
 * Returns:
 *    0  admitted (or no quota configured); *res_epoch tags the reservation
 *   -1  denied; respond 429 and do NOT dispatch
 */
extern int llb_ai_token_quota_reserve(char *tenant_id, char *model_name,
                                      int prompt_est, int max_tokens,
                                      int64_t *res_epoch,
                                      ai_gw_decision_t *result);

/*
 * llb_ai_pd_record – record a P/D disaggregation lifecycle event.
 *
 * C sockproxy calls this at P/D completion (success or error) to record
 * prefill/decode latencies and kv_params status for Prometheus metrics.
 *
 * Parameters:
 *   model_name         effective model name (NUL-terminated)
 *   prefill_latency_ms prefill phase duration in milliseconds; 0 when unknown
 *   decode_latency_ms  decode phase TTFT in milliseconds; 0 when unknown
 *   kv_params_found    1 when kv_transfer_params found, 0 otherwise
 *   error_phase        0=success, 1=prefill_timeout, 2=decode_error
 *
 * Returns void.
 */
extern void llb_ai_pd_record(char *model_name, int64_t prefill_latency_ms,
                              int64_t decode_latency_ms, int kv_params_found,
                              int error_phase);

/*
 * llb_ai_pd_session_hit – record a P/D session-stickiness cache hit.
 *
 * C sockproxy calls this when Tier-0 session lookup succeeds, meaning a
 * returning user is pinned to the same prefill/decode EP pair.
 *
 * Parameters:
 *   model_name  effective model name (NUL-terminated)
 */
extern void llb_ai_pd_session_hit(char *model_name);

/*
 * llb_ai_normal_session_hit – record a normal-mode session-stickiness cache hit.
 *
 * C sockproxy calls this when PRIORITY 0 (learned conv_map lookup) succeeds
 * in PROXY_SEL_STICKY mode, meaning a returning conversation is pinned to the
 * same backend EP (per-conversation stickiness for non-P/D AI GW rules).
 *
 * Parameters:
 *   model_name  effective model name (NUL-terminated)
 */
extern void llb_ai_normal_session_hit(char *model_name);

/*
 * llb_ai_record_unmetered – record an AI request admitted without a credential.
 *
 * C sockproxy calls this from the AI gate when a connection has ai_gw_mode=1
 * but the service's apikey_auth policy is 0, so no X-Api-Key was validated and
 * no tenant was established. The request is served; this only makes the
 * absence of metering visible to the operator who chose it.
 *
 * Parameters:
 *   vip  service VIP the request arrived on (NUL-terminated)
 */
extern void llb_ai_record_unmetered(char *vip);

/**
 * llb_ai_pd_record_ep – record per-endpoint P/D latency for Prometheus histogram.
 * New export — does NOT replace llb_ai_pd_record.
 *
 * Parameters:
 *   model_name         effective model name (NUL-terminated)
 *   prefill_latency_ms prefill phase duration in milliseconds; 0 when unknown
 *   decode_latency_ms  decode phase TTFT in milliseconds; 0 when unknown
 *   kv_params_found    1 when kv_transfer_params found, 0 otherwise
 *   error_phase        0=success, 1=prefill_timeout, 2=decode_error
 *   prefill_ep_ip      prefill endpoint IP (network byte order uint32)
 *   decode_ep_ip       decode endpoint IP (network byte order uint32)
 */
extern void llb_ai_pd_record_ep(char *model_name, int64_t prefill_latency_ms,
                                int64_t decode_latency_ms, int kv_params_found,
                                int error_phase, uint32_t prefill_ep_ip,
                                uint32_t decode_ep_ip);

/**
 * llb_ai_update_ep_queue_depth – update per-EP queue depth from vLLM scraper.
 *
 * Parameters:
 *   service_ip   service VIP (identifies which proxy_epval_t)
 *   service_port service port
 *   ep_index     endpoint index within the service
 *   queued_requests number of requests waiting in vLLM queue
 */
extern void llb_ai_update_ep_queue_depth(uint32_t service_ip, uint16_t service_port,
                                         int ep_index, uint32_t queued_requests);

/**
 * llb_ai_update_ep_capacity – update per-EP advertised KV capacity
 * (vLLM cache_config_info num_gpu_blocks) from the Go vLLM scraper. Mirrors
 * llb_ai_update_ep_queue_depth exactly (PROXY_LOCK + atomic_store, MAX_PROXY_EP
 * bound, pd_disagg + n_eps guard) so pd_select_prefill's capacity-weighted
 * bounded-load scorer can read live per-EP capacity. A 0 advertisement is
 * stored as-is and clamped to 1 at read time (V5 — never divide-by-zero).
 *
 * Parameters:
 *   service_ip     service VIP (identifies which proxy_epval_t)
 *   service_port   service port
 *   ep_index       endpoint index within the service
 *   num_gpu_blocks vLLM-advertised KV blocks (capacity); 0 = not advertised
 */
extern void llb_ai_update_ep_capacity(uint32_t service_ip, uint16_t service_port,
                                      int ep_index, uint32_t num_gpu_blocks);

/**
 * llb_ai_ctrl_update_ep –: store the global-AI-controller
 * advisory packed instruction word for one EP. Mirrors
 * llb_ai_update_ep_queue_depth exactly (PROXY_LOCK + atomic_store, MAX_PROXY_EP
 * bound, pd_disagg + n_eps guard). Sole writer (with llb_ai_ctrl_set_mode) of
 * proxy_epval_t.pd_ctrl_ep[] — the selection path reads lock-free.
 *
 * Parameters:
 *   service_ip   service VIP (identifies which proxy_epval_t)
 *   service_port service port
 *   ep_index     endpoint index within the service
 *   packed       instruction word: state bits 31-24 (PD_CTRL_ST_*, lockstep
 *                with the frozen aictrl.v1 EpState enum), weight bits 7-0
 *                [0,100]. 0 = no instruction (every selector guard skips).
 */
extern void llb_ai_ctrl_update_ep(uint32_t service_ip, uint16_t service_port,
                                  int ep_index, uint32_t packed);

/**
 * llb_ai_ctrl_set_mode –: store the per-service controller mode
 * scalar. 0 = controller absent/autonomous — pd_select_prefill performs ZERO
 * controller work (the G3 byte-identical hot path). Mirrors
 * llb_ai_update_ep_queue_depth exactly minus the ep_index pair (pd_ctrl_mode is
 * service-level).
 *
 * Parameters:
 *   service_ip   service VIP (identifies which proxy_epval_t)
 *   service_port service port
 *   mode         0 = absent/autonomous; non-zero = controller instructions live
 */
extern void llb_ai_ctrl_set_mode(uint32_t service_ip, uint16_t service_port,
                                 uint8_t mode);

/* KV-Cache Exact Routing CGO exports */

/* Typed bridge return codes: LLB_KV_TOK_ERR_* live in
 * sockproxy_kv_exact.h (the tokenize call sites and the GUARD_E counter
 * classification also compile in the TEST_KV_EXACT unit build, which never
 * sees this header). Included here so every consumer of these externs has
 * the code vocabulary in scope. */
#include "sockproxy_kv_exact.h"

/*
 * llb_ai_kv_tokenize — tokenize a prompt using a HuggingFace tokenizer.
 *
 * Parameters:
 *   text        prompt text to tokenize (NUL-terminated)
 *   model_name  model name for tokenizer lookup (NUL-terminated)
 *   out_ids     output array for token IDs
 *   max_ids     maximum number of token IDs to return
 *   svc_id      calling rule identity (proxy_epval.kv_svc_id; 0 = legacy)
 *   binding_gen contract generation from the kv_exact_contract word loaded
 *               by THIS request (0 = legacy/no contract). Rides the CGO call
 *               so Go resolves exactly one immutable binding snapshot — late
 *               in-flight requests are correct-by-snapshot across a fence.
 *
 * Returns: number of token IDs written to out_ids, or a negative
 *   LLB_KV_TOK_ERR_* code.
 */
extern int llb_ai_kv_tokenize(char *text, char *model_name,
                               uint32_t *out_ids, int max_ids,
                               uint32_t svc_id, uint32_t binding_gen);

/*
 * llb_ai_kv_tokenize_chat — tokenize a /v1/chat/completions request to vLLM
 * apply_chat_template parity.
 *
 * Unlike llb_ai_kv_tokenize (which takes a single pre-extracted prompt string),
 * this takes the RAW chat request body (the full JSON carrying messages[]) and
 * the model name. The Go side parses messages in order, renders
 * the model's chat template (ChatML/Qwen2.5 + default-system injection + the
 * generation prompt), and Encodes with WithEncodeSpecialTokens — so the token
 * ids and therefore the 16-token KV block boundaries match vLLM exactly.
 *
 * Parameters:
 *   raw_body    raw chat request JSON body (NUL-terminated; contains messages[])
 *   model_name  model name for tokenizer + template lookup (NUL-terminated)
 *   out_ids     output array for token IDs
 *   max_ids     maximum number of token IDs to return
 *
 *   svc_id / binding_gen — as in llb_ai_kv_tokenize above.
 *
 * Returns: number of token IDs written to out_ids, or a negative
 *   LLB_KV_TOK_ERR_* code (no messages / no known chat template / tokenize
 *   fail / typed strict-path faults). On ANY negative return the C caller
 *   MUST fall back and NOT route the request through KV-exact (a mis-hashed
 *   prefix would route to the wrong worker).
 */
extern int llb_ai_kv_tokenize_chat(char *raw_body, char *model_name,
                                    uint32_t *out_ids, int max_ids,
                                    uint32_t svc_id, uint32_t binding_gen);

/*
 * llb_ai_kv_best_worker — find the prefill EP with maximum KV block overlap.
 *
 * Parameters:
 *   block_hashes   array of block hash bytes (n_hashes * hash_size bytes)
 *   hash_size      bytes per hash (32 for sha256, 16 for xxhash128)
 *   n_hashes       number of block hashes
 *   model_name     model name for service lookup (NUL-terminated)
 *   prefill_mask   bitmask of absolute EP indices that have ep_role==prefill
 *                  (bit i set iff ep_role[i]==1; MAX_PROXY_EP=32 so uint32_t
 *                  has exact 1:1 coverage of bits 0..31)
 *   excluded_mask  bitmask of EPs already excluded upstream (e.g., dead
 *                  endpoints); these are skipped before scoring
 *   ep_load        per-EP live in-flight load (active_conns) indexed by the
 *                  ABSOLUTE epIdx 0..n_ep_slots-1 (same index space as
 * prefill_mask/excluded_mask bits). (Option B): this
 *                  is loxilb's OWN balancer-tracked load from
 *                  tepval->pd_ep_loads[i].active_conns — NOT the dead vLLM
 *                  workerMetrics scraper. NULL = legacy no-load behavior
 *                  (selector degenerates to pure overlap-argmax).
 *   ep_cap         per-EP advertised capacity (num_gpu_blocks) indexed by the
 *                  same absolute epIdx. 0/NULL = capacity unknown; the Go side
 *                  clamps to [1,MAX] before any divide (kvClampCapacity).
 * ep_weight: per-EP controller weight [0,100] indexed by
 *                  the same absolute epIdx, sourced from the pd_ctrl_ep[]
 *                  atomics (packed==0 mapped to 100 == no instruction). NULL
 *                  when pd_ctrl_mode==0 (controller absent) — the Go side then
 *                  treats every weight as 100, the byte-identical G3 path.
 *                  Applied to capacity BEFORE kvClampCapacity so weight=0 +
 *                  ACTIVE degrades to the smallest positive share, never zero.
 *   n_ep_slots     number of valid entries in ep_load[]/ep_cap[]/ep_weight[]
 *                  (0..32). The Go side bounds-checks every epIdx against this
 *                  length.
 * svc_id (SGL-04): the calling rule's identity
 *                  (tepval->kv_svc_id == the Go-side rule number, kvServices
 *                  key). Non-zero ⇒ the Go selector scores ONLY that rule's
 *                  inventories (closes the cross-VIP contamination seam,
 *                  RESEARCH Pitfall 2). 0 ⇒ "no identity" — the Go side keeps
 *                  today's all-services loop VERBATIM (legacy/uninitialized
 *                  structs behave as before; independently default-off, the
 *                  Phase-96 kv_weight nil-guard precedent). Twin-lockstep
 *                  discipline: this prototype, the Go //export signature
 *                  (ai_kv_subscriber.go) and the C call site
 *                  (sockproxy_kv_exact.c) change in the SAME commit.
 * kv_exact_mode (§9 relief default): the calling rule's
 *                  tepval->kv_exact_mode. The Go side uses ONLY the
 *                  single-role predicate (== KV_EXACT_MODE_SINGLE_ROLE 3) to
 *                  gate the Phase-95 fleet-wide pressure-relief pass by
 *                  default (LOXILB_KV_SPILL_RELIEF unset ⇒ relief ON for
 *                  single-role, OFF for P/D — the Phase-95 substrate verdict
 *                  preserved; explicit env on/off overrides globally). A hot
 *                  single-cached prefix yields a SINGLETON positive-overlap
 *                  candidate set whose self-cap (1+ε)·L ≥ L can never spill —
 * relief is the only unpin mechanism ( §9 evidence:
 *                  goodput 0.22→0.95 at rate 1.0). 0 (legacy/uninitialized)
 *                  ⇒ not single-role ⇒ byte-identical pre-99 behavior.
 *                  Twin-lockstep discipline: this prototype, the Go //export
 *                  signature and the C call site change in the SAME commit.
 *   out_score      output: number of matching blocks for the best EP
 *
 * Returns: absolute EP index (0-based) with max overlap, or -1 on error/no match.
 */
extern int llb_ai_kv_best_worker(uint8_t *block_hashes, int hash_size,
                                  int n_hashes, char *model_name,
                                  uint32_t prefill_mask, uint32_t excluded_mask,
                                  const uint32_t *ep_load, const uint32_t *ep_cap,
                                  const uint32_t *ep_weight,
                                  int n_ep_slots, uint32_t kv_svc_id,
                                  uint32_t kv_exact_mode,
                                  int *out_score);

#endif /* __SOCKPROXY_AI_GW_H__ */
