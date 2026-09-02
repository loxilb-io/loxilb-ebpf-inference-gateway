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
 * Every stub is defined __attribute__((weak)) and the object is archived
 * into libloxilbdp.a, so the archive is self-contained for ANY consumer:
 * the gateway's Go CGO exports (strong) always win, while C-only debug
 * binaries (loxilb_dp_debug) and cgo consumers that do not link pkg/loxinet
 * (the REST handler package's test binary) resolve against these no-ops
 * instead of failing to link.  All stubs intentionally return "allow" (0)
 * so the data path is transparent wherever they end up bound.
 *
 * Weak linkage must never become a SILENT enforcement bypass: if a binary
 * that was supposed to carry the Go exports ever runs on these stubs (a
 * build regression would previously have failed the link outright), the
 * first invocation of each stub logs an error. A correctly linked gateway
 * never executes them, so production stays quiet; a binary that does run
 * them says so loudly instead of silently allowing every request.
 */

#include <stdint.h>
#include "log.h"
#include "sockproxy_ai_gw.h"

#define AI_GW_STUB_TRIPWIRE(fn_flag)                                        \
    do {                                                                    \
        static int fn_flag;                                                 \
        if (!fn_flag) {                                                     \
            fn_flag = 1;                                                    \
            log_error("ai-gw: weak stub %s invoked - Go bridge exports "    \
                      "not linked (no-op enforcement)", __func__);          \
        }                                                                   \
    } while (0)

__attribute__((weak)) int
llb_ai_validate_key(char *raw_key, char *model_name, ai_gw_decision_t *result)
{
    AI_GW_STUB_TRIPWIRE(warned);
    (void)raw_key;
    (void)model_name;
    if (result) {
        result->decision = 0;  /* allow */
    }
    return 0;
}

__attribute__((weak)) int
llb_ai_ratelimit_check(char *key_id, char *tenant_id, char *model,
                       ai_gw_decision_t *result)
{
    AI_GW_STUB_TRIPWIRE(warned);
    (void)key_id;
    (void)tenant_id;
    (void)model;
    (void)result;
    return 0;  /* allow */
}

__attribute__((weak)) int
llb_ai_ratelimit_update(char *key_id, char *tenant_id, int rps, int burst)
{
    AI_GW_STUB_TRIPWIRE(warned);
    (void)key_id;
    (void)tenant_id;
    (void)rps;
    (void)burst;
    return 0;
}

__attribute__((weak)) void
llb_ai_record_request(char *tenant_id, char *model_name, int status_code,
                      int64_t latency_ms, int prompt_tokens, int complet_tokens,
                      int stream_start, int stream_end, char *error_code)
{
    AI_GW_STUB_TRIPWIRE(warned);
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

__attribute__((weak)) int
llb_ai_stream_start(char *tenant_id, char *model_name)
{
    AI_GW_STUB_TRIPWIRE(warned);
    (void)tenant_id;
    (void)model_name;
    return 0;
}

__attribute__((weak)) int
llb_ai_stream_end(char *tenant_id, char *model_name)
{
    AI_GW_STUB_TRIPWIRE(warned);
    (void)tenant_id;
    (void)model_name;
    return 0;
}

__attribute__((weak)) int
llb_ai_token_quota_consume(char *tenant_id, char *model_name,
                           int prompt_tokens, int complet_tokens,
                           int estimated, int reserved_toks,
                           int64_t res_epoch, ai_gw_decision_t *result)
{
    AI_GW_STUB_TRIPWIRE(warned);
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

__attribute__((weak)) int
llb_ai_token_quota_reserve(char *tenant_id, char *model_name,
                           int prompt_est, int max_tokens,
                           int64_t *res_epoch, ai_gw_decision_t *result)
{
    AI_GW_STUB_TRIPWIRE(warned);
    (void)tenant_id;
    (void)model_name;
    (void)prompt_est;
    (void)max_tokens;
    (void)result;
    if (res_epoch)
        *res_epoch = 0;
    return 0;  /* allow — no quota enforcement in C-only debug builds */
}

__attribute__((weak)) void
llb_ai_pd_record(char *model_name, int64_t prefill_latency_ms,
                  int64_t decode_latency_ms, int kv_params_found,
                  int error_phase)
{
    AI_GW_STUB_TRIPWIRE(warned);
    (void)model_name;
    (void)prefill_latency_ms;
    (void)decode_latency_ms;
    (void)kv_params_found;
    (void)error_phase;
}

__attribute__((weak)) void
llb_ai_pd_session_hit(char *model_name)
{
    AI_GW_STUB_TRIPWIRE(warned);
    (void)model_name;
}

__attribute__((weak)) void
llb_ai_normal_session_hit(char *model_name)
{
    AI_GW_STUB_TRIPWIRE(warned);
    (void)model_name;
}

__attribute__((weak)) void
llb_ai_record_unmetered(char *vip)
{
    AI_GW_STUB_TRIPWIRE(warned);
    (void)vip;
}

/* llb_ai_update_ep_queue_depth is defined in sockproxy_metrics.c (C-side),
 * not a CGO export, so no stub needed here. */

/* Per-EP P/D latency recording stub */

__attribute__((weak)) void
llb_ai_pd_record_ep(char *model_name, int64_t prefill_latency_ms,
                    int64_t decode_latency_ms, int kv_params_found,
                    int error_phase, uint32_t prefill_ep_ip,
                    uint32_t decode_ep_ip)
{
    AI_GW_STUB_TRIPWIRE(warned);
    (void)model_name;
    (void)prefill_latency_ms;
    (void)decode_latency_ms;
    (void)kv_params_found;
    (void)error_phase;
    (void)prefill_ep_ip;
    (void)decode_ep_ip;
}

/* KV-Cache Exact Routing stubs */

__attribute__((weak)) int
llb_ai_kv_tokenize(char *text, char *model_name,
                    uint32_t *out_ids, int max_ids,
                    uint32_t svc_id, uint32_t binding_gen)
{
    AI_GW_STUB_TRIPWIRE(warned);
    (void)text;
    (void)model_name;
    (void)out_ids;
    (void)max_ids;
    (void)svc_id;
    (void)binding_gen;
    return -1;  /* no tokenizer in C-only builds */
}

__attribute__((weak)) int
llb_ai_kv_tokenize_chat(char *raw_body, char *model_name,
                         uint32_t *out_ids, int max_ids,
                         uint32_t svc_id, uint32_t binding_gen)
{
    AI_GW_STUB_TRIPWIRE(warned);
    (void)raw_body;
    (void)model_name;
    (void)out_ids;
    (void)max_ids;
    (void)svc_id;
    (void)binding_gen;
    return -1;  /* no tokenizer/chat-template in C-only builds */
}

__attribute__((weak)) int
llb_ai_kv_best_worker(uint8_t *block_hashes, int hash_size,
                       int n_hashes, char *model_name,
                       uint32_t prefill_mask, uint32_t excluded_mask,
                       const uint32_t *ep_load, const uint32_t *ep_cap,
                       const uint32_t *ep_weight,
                       int n_ep_slots, uint32_t kv_svc_id,
                       uint32_t kv_exact_mode, int *out_score)
{
    AI_GW_STUB_TRIPWIRE(warned);
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
__attribute__((weak)) void
llb_sockproxy_emit_sync_event(const struct proxy_sync_event *ev)
{
    AI_GW_STUB_TRIPWIRE(warned);
    (void)ev;
}
