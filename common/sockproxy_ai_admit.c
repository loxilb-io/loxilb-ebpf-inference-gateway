/*
 * Copyright (c) 2026 LoxiLB Authors
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
 * The AI gateway admission gate, extracted verbatim from the H1 parser's
 * handle_on_message_complete (see sockproxy_http.c for the call site and
 * the response emission). One gate, N protocol callers — the HTTP/2 hole
 * existed precisely because the gate was inlined in the H1 parser, so a
 * second inlined copy was never an option.
 *
 * Stage order (first refusal wins):
 *   1. credential + model authorization (401/403/503)  — a request with no
 *      usable credential learns nothing else about the service.
 *   2. body/header model conflict (400)                — decided after the
 *      credential so an unauthenticated probe still reads as 401, before
 *      rate/quota so an ill-formed request never consumes budget.
 *   3. RPS / token-quota latch (429, 503 on store loss)
 *   4. pre-admission token reservation (429)
 */

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "xxhash.h"
#include "uthash.h"
#include "log.h"
#include "sockproxy_internal.h"
#include "sockproxy_ai_admit.h"
#include "sockproxy_json.h"

/* The header mirrors MAX_MODEL_LEN rather than including the proxy-internal
 * world; hold the mirror to the original. */
_Static_assert(AI_GW_MODEL_LEN == MAX_MODEL_LEN,
               "AI_GW_MODEL_LEN must mirror MAX_MODEL_LEN");

static void
set_deny(ai_gw_admit_result_t *res, ai_gw_admit_stage_t stage, int status,
         int retry_after, int retry_body, const char *code, const char *msg)
{
  res->verdict = AI_GW_ADMIT_DENY;
  res->stage = stage;
  res->http_status = status;
  res->retry_after = retry_after;
  res->retry_body = retry_body;
  snprintf(res->error_code, sizeof(res->error_code), "%s", code);
  snprintf(res->error_msg, sizeof(res->error_msg), "%s", msg);
}

int
ai_gw_admit(const ai_gw_req_ctx_t *req, ai_gw_admit_result_t *res)
{
  memset(res, 0, sizeof(*res));

  const char *api_key = req->api_key ? req->api_key : "";
  const char *prefix_model = req->prefix_model ? req->prefix_model : "";
  const char *hdr_model = req->hdr_model ? req->hdr_model : "";

  /* Skip enforcement only for the two DECLARED non-enforcing values.
   * 1 enforces, and so does anything out of range: a wire value this code
   * does not recognise is a corrupted policy, and a corrupted policy that
   * admits keyless traffic fails open on exactly the services an operator
   * tried to protect. */
  if (req->auth_mode == 0 || req->auth_mode == 2) {
    res->verdict = AI_GW_ADMIT_UNMETERED;
    return 0;
  }

  /* allowed_models must bind to the model the backend will actually serve,
   * which is the one in the JSON body — an X-Model header that differs
   * from the body is at best a stale hint and at worst a spoof. The body
   * is complete by the time the gate runs, so parse it here and fall back
   * to the earlier prefix extraction, then the header, only when the body
   * carries no model field. */
  char body_model[AI_GW_MODEL_LEN] = {0};
  if (req->body && req->body_len > 0) {
    extract_model_field(req->body, req->body_len, body_model, sizeof(body_model));
  }
  const char *body_bound = body_model[0] ? body_model : prefix_model;
  const char *model = body_bound[0] ? body_bound : hdr_model;

  /* Stage 1: validate the credential → 401 (missing/invalid), 403 (model
   * denied), 503 (store cannot answer). The store outage is deliberately
   * NOT a 401: a client that retries a 503 is behaving correctly; a client
   * that retries a 401 is replaying a credential that will never work.
   *
   * Arm dispatch: mode 1 is the API-key arm and mode 3 the JWT arm.
   * Mode 4 (apikey-or-jwt) picks by which credential is PRESENT, API key
   * winning: a present X-Api-Key decides alone and its refusal is final —
   * falling back to the JWT arm after a failed key would let a caller
   * probe one credential per request behind a single 401. With no key the
   * Bearer arm decides (its missing-token 401 covers the neither-present
   * case). Unknown wire values keep the old fail-closed posture and
   * enforce the API-key arm — a JWT-only client is denied there, never
   * admitted unchecked. Identities are never merged across arms. */
  const char *bearer = req->bearer ? req->bearer : "";
  const char *jwt_profile = req->jwt_profile ? req->jwt_profile : "";
  int jwt_arm = (req->auth_mode == 3) ||
                (req->auth_mode == 4 && api_key[0] == '\0');

  ai_gw_decision_t key_dec = {0};
  int ai_rc;
  if (jwt_arm) {
    int bearer_flags = req->bearer_oversize ? AI_GW_BEARERF_OVERSIZE : 0;
    ai_rc = llb_ai_validate_bearer((char *)bearer, (char *)model,
                                   (char *)jwt_profile, bearer_flags,
                                   &key_dec);
  } else {
    ai_rc = llb_ai_validate_key((char *)api_key, (char *)model, &key_dec);
  }
  if (ai_rc != 0) {
    /* The Go arm names its refusal (invalid_token/token_expired/…); fall
     * back to the arm-appropriate legacy code when it did not. */
    const char *deny_code = key_dec.error_code[0] ? key_dec.error_code
                          : (jwt_arm ? "invalid_token" : "invalid_api_key");
    if (key_dec.decision == 4) {
      set_deny(res, AI_GW_STAGE_AUTH, 503, 5, 0,
               key_dec.error_code[0] ? key_dec.error_code
                                     : "policy_store_unavailable",
               "Credential policy store is unavailable; request refused");
    } else if (key_dec.decision == 2) {
      set_deny(res, AI_GW_STAGE_AUTH, 403, 0, 0, "model_not_allowed",
               jwt_arm ? "Model not permitted for this token"
                       : "Model not permitted for this API key");
    } else {
      set_deny(res, AI_GW_STAGE_AUTH, 401, 0, 0, deny_code,
               jwt_arm ? "Missing or invalid bearer token"
                       : "Missing or invalid X-Api-Key header");
    }
    return -1;
  }

  /* Stage 2: on enforcing services a body/header model disagreement is a
   * hard 400, never a silent steer. Before this check existed the auth
   * stage bound allowed_models to the body model while endpoint selection
   * derived its own model header-first — so a key authorized only for
   * model A could reach model B's pool by naming A in the body and B in
   * X-Model. Both present and equal is fine; either alone is fine. */
  if (body_bound[0] && hdr_model[0] && strcmp(body_bound, hdr_model) != 0) {
    set_deny(res, AI_GW_STAGE_CONFLICT, 400, 0, 0, "model_conflict",
             "JSON body model and X-Model header disagree");
    /* The identity is real (the credential validated) — carry it so the
     * caller can log and count the denial against the right tenant. */
    snprintf(res->tenant_id, sizeof(res->tenant_id), "%s", key_dec.tenant_id);
    snprintf(res->key_id, sizeof(res->key_id), "%s", key_dec.key_id);
    return -1;
  }

  snprintf(res->tenant_id, sizeof(res->tenant_id), "%s", key_dec.tenant_id);
  snprintf(res->key_id, sizeof(res->key_id), "%s", key_dec.key_id);
  snprintf(res->user_id, sizeof(res->user_id), "%s", key_dec.user_id);
  res->auth_flags = key_dec.auth_flags;
  snprintf(res->effective_model, sizeof(res->effective_model), "%s", model);

  /* Stage 3: per-key then per-tenant RPS check → 429. The body-bound model
   * rides along so the token-quota stage can consult the tenant|model
   * bucket next to the tenant aggregate. Three shapes arrive on the deny
   * path: the request-rate limit, the token-quota debt latch, and (as
   * decision 4) the stage's own keyed-identity-with-no-store invariant
   * guard — the last is the gateway's outage and carries 503, never a 429
   * that reads as "slow down". */
  ai_gw_decision_t rl_dec = {0};
  int rl_rc = llb_ai_ratelimit_check(key_dec.key_id, key_dec.tenant_id,
                                     (char *)model, &rl_dec);
  if (rl_rc != 0) {
    const char *rl_err =
      rl_dec.error_code[0] ? rl_dec.error_code : "rate_limit_exceeded";
    set_deny(res, AI_GW_STAGE_RATELIMIT,
             rl_dec.decision == 4 ? 503 : 429,
             rl_dec.retry_after, 1, rl_err, "");
    return -1;
  }

  /* Stage 4: pre-admission token reservation → 429 BEFORE dispatch. Claim
   * the request's worst case (prompt estimate + declared max_tokens
   * ceiling) against the tenant quota now, while denial costs one cheap
   * response — not a backend prefill whose tokens the latch only bills
   * afterwards. The claim and its window tag ride back to the caller for
   * the settle call. */
  if (req->body && req->body_len > 0) {
    int resv_prompt = estimate_prompt_tokens(req->body, req->body_len);
    int resv_max = extract_max_tokens(req->body, req->body_len);
    if (resv_prompt > 0 || resv_max > 0) {
      ai_gw_decision_t rs_dec = {0};
      int64_t rs_epoch = 0;
      if (llb_ai_token_quota_reserve(key_dec.tenant_id, (char *)model,
                                     resv_prompt, resv_max,
                                     &rs_epoch, &rs_dec) != 0) {
        set_deny(res, AI_GW_STAGE_RESERVE, 429, rs_dec.retry_after, 1,
                 rs_dec.error_code, "");
        /* Log parity: the inlined gate reported what it asked for. */
        res->reserved_toks = (uint32_t)(resv_prompt + resv_max);
        return -1;
      }
      if (rs_epoch != 0) {
        res->reserved_toks = (uint32_t)(resv_prompt + resv_max);
        res->res_epoch = rs_epoch;
      }
    }
  }

  res->verdict = AI_GW_ADMIT_ALLOW;
  return 0;
}
