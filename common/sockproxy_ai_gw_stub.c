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
 * llb_ai_ratelimit_update, llb_ai_record_request, llb_ai_record_deny,
 * llb_ai_stream_start, llb_ai_stream_end, llb_ai_token_quota_consume and
 * llb_ai_pd_record
 * llb_ai_pd_record_extra
 * live in pkg/loxinet/ai_gateway_dp.go, llb_ai_audit_emit_only lives in
 * pkg/loxinet/ai_gateway_bench.go, and all of them are only
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
#include <string.h>
#include "log.h"
#include "sockproxy_ai_gw.h"
#include "sockproxy_ai_bench.h"
#include "sockproxy_epp.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <stdatomic.h>

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
llb_ai_validate_bearer(char *bearer, char *model_name, char *profile_name,
                       int bearer_flags, ai_gw_decision_t *result)
{
    AI_GW_STUB_TRIPWIRE(warned);
    (void)bearer;
    (void)model_name;
    (void)profile_name;
    (void)bearer_flags;
    if (result) {
        result->decision = 0;  /* allow */
    }
    return 0;
}

__attribute__((weak)) int
llb_ai_ratelimit_check(char *key_id, char *tenant_id,
                       char *user_id, char *svc_ident,
                       char *model, ai_gw_decision_t *result)
{
    AI_GW_STUB_TRIPWIRE(warned);
    (void)key_id;
    (void)tenant_id;
    (void)user_id;
    (void)svc_ident;
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
                      int stream_start, int stream_end, char *error_code,
                      char *request_id, char *user_id, char *key_id,
                      char *svc_ident, int is_stream, int producer_id,
                      char *client_ip, char *origin_ip, int trusted_hops,
                      int auth_src, char *net_identity,
                      int priority, int class_info, char *objective)
{
    AI_GW_STUB_TRIPWIRE(warned);
    (void)auth_src;
    (void)net_identity;
    (void)priority;
    (void)class_info;
    (void)objective;
    (void)tenant_id;
    (void)model_name;
    (void)status_code;
    (void)latency_ms;
    (void)prompt_tokens;
    (void)complet_tokens;
    (void)stream_start;
    (void)stream_end;
    (void)error_code;
    (void)request_id;
    (void)user_id;
    (void)key_id;
    (void)svc_ident;
    (void)is_stream;
    (void)producer_id;
    (void)client_ip;
    (void)origin_ip;
    (void)trusted_hops;
}

__attribute__((weak)) void
llb_ai_audit_emit_only(char *tenant_id, char *model_name, int status_code,
                       int64_t latency_ms, int prompt_tokens, int complet_tokens,
                       char *error_code, char *request_id, char *user_id,
                       char *key_id, char *svc_ident, int is_stream,
                       int producer_id)
{
    AI_GW_STUB_TRIPWIRE(warned);
    (void)tenant_id;
    (void)model_name;
    (void)status_code;
    (void)latency_ms;
    (void)prompt_tokens;
    (void)complet_tokens;
    (void)error_code;
    (void)request_id;
    (void)user_id;
    (void)key_id;
    (void)svc_ident;
    (void)is_stream;
    (void)producer_id;
}

__attribute__((weak)) void
llb_ai_record_deny(char *request_id, int producer_id,
                   char *svc_ident, char *model_name,
                   char *tenant_id, char *key_id, char *user_id,
                   int stage, int http_status, char *error_code,
                   char *client_ip, char *origin_ip, int trusted_hops,
                   int auth_src, char *net_identity,
                   int priority, int class_info, char *objective)
{
    AI_GW_STUB_TRIPWIRE(warned);
    (void)auth_src;
    (void)net_identity;
    (void)priority;
    (void)class_info;
    (void)objective;
    (void)request_id;
    (void)producer_id;
    (void)svc_ident;
    (void)model_name;
    (void)tenant_id;
    (void)key_id;
    (void)user_id;
    (void)stage;
    (void)http_status;
    (void)client_ip;
    (void)origin_ip;
    (void)trusted_hops;
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
                           char *user_id, char *key_id, char *svc_ident,
                           int prompt_tokens, int complet_tokens,
                           int estimated, int reserved_toks,
                           int64_t res_epoch, char *request_id,
                           int producer_id, int auth_src, char *net_identity,
                           ai_gw_decision_t *result)
{
    AI_GW_STUB_TRIPWIRE(warned);
    (void)auth_src;
    (void)net_identity;
    (void)tenant_id;
    (void)model_name;
    (void)user_id;
    (void)key_id;
    (void)svc_ident;
    (void)prompt_tokens;
    (void)complet_tokens;
    (void)estimated;
    (void)reserved_toks;
    (void)res_epoch;
    (void)request_id;
    (void)producer_id;
    (void)result;
    return 0;  /* allow — no quota enforcement in C-only debug builds */
}

__attribute__((weak)) void
llb_ai_token_quota_release(char *tenant_id, char *model_name,
                           char *user_id, char *key_id, char *svc_ident,
                           int reserved_toks, int64_t res_epoch)
{
    AI_GW_STUB_TRIPWIRE(warned);
    (void)tenant_id; (void)model_name; (void)user_id; (void)key_id;
    (void)svc_ident; (void)reserved_toks; (void)res_epoch;
}

__attribute__((weak)) int
llb_ai_token_quota_reserve(char *tenant_id, char *model_name,
                           char *user_id, char *key_id, char *svc_ident,
                           int prompt_est, int max_tokens,
                           int default_tokens,
                           int64_t *res_epoch, int *granted,
                           ai_gw_decision_t *result)
{
    AI_GW_STUB_TRIPWIRE(warned);
    (void)tenant_id;
    (void)model_name;
    (void)user_id;
    (void)key_id;
    (void)svc_ident;
    (void)prompt_est;
    (void)max_tokens;
    (void)default_tokens;
    (void)result;
    if (res_epoch)
        *res_epoch = 0;
    if (granted)
        *granted = 0;
    return 0;  /* allow — no quota enforcement in C-only debug builds */
}

__attribute__((weak)) int
llb_ai_netid_resolve(char *client_ip, int in_ifindex,
                     char *svc_ident, char *model, ai_gw_netid_t *out)
{
    AI_GW_STUB_TRIPWIRE(warned);
    (void)client_ip;
    (void)in_ifindex;
    (void)svc_ident;
    (void)model;
    if (out)
        out->matched = 0;
    return 0;  /* no binding: the request is decided as if none existed */
}

__attribute__((weak)) int
llb_ai_class_resolve(char *tenant, char *key_id, char *binding, char *profile,
                     char *svc_ident, char *objective_hint, int tier_hint,
                     ai_gw_class_t *out)
{
    AI_GW_STUB_TRIPWIRE(warned);
    (void)tenant;
    (void)key_id;
    (void)binding;
    (void)profile;
    (void)svc_ident;
    (void)objective_hint;
    (void)tier_hint;
    if (out)
        memset(out, 0, sizeof(*out));
    return 0;  /* nothing configured: standard */
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
llb_ai_pd_record_extra(char *model_name, int64_t decode_ttft_us,
                       int fallback_reason)
{
    AI_GW_STUB_TRIPWIRE(warned);
    (void)model_name;
    (void)decode_ttft_us;
    (void)fallback_reason;
}

__attribute__((weak)) void
llb_ai_pd_session_hit(char *model_name)
{
    AI_GW_STUB_TRIPWIRE(warned);
    (void)model_name;
}

__attribute__((weak)) void
llb_ai_pd_tier_selected(char *model_name, int tier)
{
    AI_GW_STUB_TRIPWIRE(warned);
    (void)model_name;
    (void)tier;
}

__attribute__((weak)) void
llb_ai_pd_decode_selected(char *model_name, int path, int kv_fill)
{
    AI_GW_STUB_TRIPWIRE(warned);
    (void)model_name;
    (void)path;
    (void)kv_fill;
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

__attribute__((weak)) void
llb_ai_record_stream_early_close(char *svc_ident)
{
    AI_GW_STUB_TRIPWIRE(warned);
    (void)svc_ident;
}

__attribute__((weak)) void
llb_ai_record_usage_missing(char *tenant_id, char *model_name, char *reason)
{
    AI_GW_STUB_TRIPWIRE(warned);
    (void)tenant_id;
    (void)model_name;
    (void)reason;
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

/* ---- Endpoint Picker (EPP) stubs ------------------------------------------
 * Without the Go bridge a submit is refused (sid 0), so an EPP rule takes
 * its failure mode at once. For C-level tests of the park/resume path the
 * stub can instead play a fixed EPP: with LLB_EPP_STUB_CANDS set to an
 * "ip:port,ip:port" list it accepts the request and, after
 * LLB_EPP_STUB_DELAY_MS (default 50), hands those candidates back through
 * proxy_epp_complete from a detached thread - the shape the Go side has. */
struct epp_stub_job {
  void *ns; int fd; uint64_t gen; uint64_t sid; unsigned delay_ms;
};

static void *
epp_stub_complete(void *arg)
{
  struct epp_stub_job *j = arg;
  struct epp_result r;
  const char *cands = getenv("LLB_EPP_STUB_CANDS");
  const char *mode = getenv("LLB_EPP_STUB_MODE");
  int n = 0;

  usleep(j->delay_ms * 1000);
  memset(&r, 0, sizeof(r));
  if (mode && !strcmp(mode, "error")) {
    r.status = EPP_RES_ERROR;
  } else if (mode && !strcmp(mode, "immediate")) {
    r.status = EPP_RES_IMMEDIATE;
    r.imm_code = 429;
    r.imm_body = "{\"error\":\"stub_shed\"}";
    r.imm_body_len = (int)strlen(r.imm_body);
  } else {
    char *dup = cands ? strdup(cands) : NULL;
    char *save = NULL;
    char *tok = dup ? strtok_r(dup, ",", &save) : NULL;
    r.status = EPP_RES_OK;
    while (tok && n < EPP_MAX_CANDS) {
      strncpy(r.cands[n], tok, EPP_CAND_LEN - 1);
      n++;
      tok = strtok_r(NULL, ",", &save);
    }
    r.ncands = n;
    free(dup);
  }
  proxy_epp_complete(j->ns, j->fd, j->gen, j->sid, &r);
  free(j);
  return NULL;
}

__attribute__((weak)) uint64_t
llb_epp_submit(uint32_t svc_id, void *ns, int fd, uint64_t gen,
               char *req_hdrs, int req_hdrs_len,
               char *body, int body_len,
               char *subset, int subset_len)
{
  static _Atomic uint64_t next_sid = 1;
  const char *cands = getenv("LLB_EPP_STUB_CANDS");
  const char *delay = getenv("LLB_EPP_STUB_DELAY_MS");
  struct epp_stub_job *j;
  pthread_t th;
  pthread_attr_t attr;

  (void)svc_id; (void)req_hdrs; (void)req_hdrs_len; (void)body; (void)body_len;
  (void)subset; (void)subset_len;
  if (!cands || !*cands) {
    AI_GW_STUB_TRIPWIRE(warned);
    return 0;
  }
  j = calloc(1, sizeof(*j));
  if (!j) return 0;
  j->ns = ns; j->fd = fd; j->gen = gen;
  j->sid = atomic_fetch_add(&next_sid, 1);
  j->delay_ms = delay ? (unsigned)atoi(delay) : 50;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  if (pthread_create(&th, &attr, epp_stub_complete, j) != 0) {
    pthread_attr_destroy(&attr);
    free(j);
    return 0;
  }
  pthread_attr_destroy(&attr);
  return j->sid;
}

__attribute__((weak)) void
llb_epp_resp_event(uint64_t sid, int kind, int http_status,
                   char *resp_hdrs, int resp_hdrs_len,
                   char *served, int served_len)
{
  (void)sid; (void)kind; (void)http_status; (void)resp_hdrs; (void)resp_hdrs_len;
  (void)served; (void)served_len;
}

__attribute__((weak)) void
llb_epp_metric_outcome(char *outcome)
{
  (void)outcome;
}

__attribute__((weak)) void
llb_epp_metric_rejected(char *reason)
{
  (void)reason;
}
