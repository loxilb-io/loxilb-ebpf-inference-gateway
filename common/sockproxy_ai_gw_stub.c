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

/*
 * sockproxy_ai_gw_stub.c — AI Gateway CGO bridge stubs for C-only builds.
 *
 * The real implementations of llb_ai_validate_key, llb_ai_ratelimit_check,
 * llb_ai_ratelimit_update, llb_ai_record_request, llb_ai_stream_start,
 * llb_ai_stream_end, llb_ai_token_quota_consume and llb_ai_pd_record
 * live in pkg/loxinet/ai_gateway_dp.go and are only
 * available when the binary is linked with the Go CGO runtime.
 *
 * This stub is linked into C-only debug binaries (loxilb_dp_debug) so that
 * sockproxy.c compiles and links without the Go runtime.  All stubs are
 * intentional no-ops that return "allow" (0) so the data path is transparent
 * during C-only debugging sessions.
 */

#include <stdint.h>
#include "sockproxy_ai_gw.h"

int
llb_ai_validate_key(char *raw_key, char *model_name, ai_gw_decision_t *result)
{
    (void)raw_key;
    (void)model_name;
    if (result) {
        result->decision = 0;  /* allow */
    }
    return 0;
}

int
llb_ai_ratelimit_check(char *key_id, char *tenant_id, char *model,
                       ai_gw_decision_t *result)
{
    (void)key_id;
    (void)tenant_id;
    (void)model;
    (void)result;
    return 0;  /* allow */
}

int
llb_ai_ratelimit_update(char *key_id, char *tenant_id, int rps, int burst)
{
    (void)key_id;
    (void)tenant_id;
    (void)rps;
    (void)burst;
    return 0;
}

void
llb_ai_record_request(char *tenant_id, char *model_name, int status_code,
                      int64_t latency_ms, int prompt_tokens, int complet_tokens,
                      int stream_start, int stream_end, char *error_code)
{
    (void)tenant_id;
    (void)model_name;
    (void)status_code;
    (void)latency_ms;
    (void)prompt_tokens;
    (void)complet_tokens;
    (void)stream_start;
    (void)stream_end;
    (void)error_code;
}

int
llb_ai_stream_start(char *tenant_id, char *model_name)
{
    (void)tenant_id;
    (void)model_name;
    return 0;
}

int
llb_ai_stream_end(char *tenant_id, char *model_name)
{
    (void)tenant_id;
    (void)model_name;
    return 0;
}

int
llb_ai_token_quota_consume(char *tenant_id, char *model_name,
                           int prompt_tokens, int complet_tokens,
                           int estimated, int reserved_toks,
                           int64_t res_epoch, ai_gw_decision_t *result)
{
    (void)tenant_id;
    (void)model_name;
    (void)prompt_tokens;
    (void)complet_tokens;
    (void)estimated;
    (void)reserved_toks;
    (void)res_epoch;
    (void)result;
    return 0;  /* allow — no quota enforcement in C-only debug builds */
}

int
llb_ai_token_quota_reserve(char *tenant_id, char *model_name,
                           int prompt_est, int max_tokens,
                           int64_t *res_epoch, ai_gw_decision_t *result)
{
    (void)tenant_id;
    (void)model_name;
    (void)prompt_est;
    (void)max_tokens;
    (void)result;
    if (res_epoch)
        *res_epoch = 0;
    return 0;  /* allow — no quota enforcement in C-only debug builds */
}

void
llb_ai_pd_record(char *model_name, int64_t prefill_latency_ms,
                  int64_t decode_latency_ms, int kv_params_found,
                  int error_phase)
{
    (void)model_name;
    (void)prefill_latency_ms;
    (void)decode_latency_ms;
    (void)kv_params_found;
    (void)error_phase;
}

void
llb_ai_pd_session_hit(char *model_name)
{
    (void)model_name;
}

void
llb_ai_normal_session_hit(char *model_name)
{
    (void)model_name;
}

/* llb_ai_update_ep_queue_depth is defined in sockproxy_metrics.c (C-side),
 * not a CGO export, so no stub needed here. */

/* Per-EP P/D latency recording stub */

void
llb_ai_pd_record_ep(char *model_name, int64_t prefill_latency_ms,
                    int64_t decode_latency_ms, int kv_params_found,
                    int error_phase, uint32_t prefill_ep_ip,
                    uint32_t decode_ep_ip)
{
    (void)model_name;
    (void)prefill_latency_ms;
    (void)decode_latency_ms;
    (void)kv_params_found;
    (void)error_phase;
    (void)prefill_ep_ip;
    (void)decode_ep_ip;
}

/* KV-Cache Exact Routing stubs */

int
llb_ai_kv_tokenize(char *text, char *model_name,
                    uint32_t *out_ids, int max_ids)
{
    (void)text;
    (void)model_name;
    (void)out_ids;
    (void)max_ids;
    return -1;  /* no tokenizer in C-only builds */
}

int
llb_ai_kv_tokenize_chat(char *raw_body, char *model_name,
                         uint32_t *out_ids, int max_ids)
{
    (void)raw_body;
    (void)model_name;
    (void)out_ids;
    (void)max_ids;
    return -1;  /* no tokenizer/chat-template in C-only builds */
}

int
llb_ai_kv_best_worker(uint8_t *block_hashes, int hash_size,
                       int n_hashes, char *model_name,
                       uint32_t prefill_mask, uint32_t excluded_mask,
                       const uint32_t *ep_load, const uint32_t *ep_cap,
                       const uint32_t *ep_weight,
                       int n_ep_slots, uint32_t kv_svc_id,
                       uint32_t kv_exact_mode, int *out_score)
{
    (void)block_hashes;
    (void)hash_size;
    (void)n_hashes;
    (void)model_name;
    (void)prefill_mask;
    (void)excluded_mask;
    (void)ep_load;       /* per-EP load (active_conns) */
    (void)ep_cap;        /* per-EP cap (num_gpu_blocks) */
    (void)ep_weight;     /* per-EP controller weight (pd_ctrl_ep) */
    (void)n_ep_slots;
    (void)kv_svc_id;     /* calling rule identity (SGL-04) */
    (void)kv_exact_mode; /* §9: single-role relief default gate */
    (void)out_score;
    return -1;  /* no KV inventory in C-only builds */
}

/* Sockproxy HA state-sync emit stub.
 *
 * The real implementation lives in pkg/loxinet/sockproxy_sync.go (CGO //export)
 * and pushes the event onto a 10K-buffered Go channel with drop-oldest. In
 * C-only debug builds (loxilb_dp_debug) there is no Go runtime, so we no-op
 * — the data path stays transparent and sockproxy_pd.c / sockproxy_ep.c link
 * against this symbol cleanly. Forward-declare the typedef shape to avoid
 * pulling sockproxy_internal.h here. */
struct proxy_sync_event;
void
llb_sockproxy_emit_sync_event(const struct proxy_sync_event *ev)
{
    (void)ev;
}
