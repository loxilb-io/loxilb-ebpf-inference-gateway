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

#ifndef __SOCKPROXY_AI_ADMIT_H__
#define __SOCKPROXY_AI_ADMIT_H__

#include <stddef.h>
#include <stdint.h>

#include "sockproxy_ai_gw.h"

/* Mirrors MAX_MODEL_LEN (sockproxy.h); asserted equal in the .c so the two
 * cannot drift apart silently. Kept separate so this header does not pull
 * in the whole proxy-internal world. */
#define AI_GW_MODEL_LEN 128

/*
 * ai_gw_admit() — the AI gateway admission gate, extracted from the H1
 * parser so HTTP/1 and HTTP/2 run the SAME policy through one entry point
 * instead of each protocol growing its own inlined (and inevitably
 * diverging) copy. It is a pure decision function: it never touches a
 * socket and never writes a response — the caller owns emission, because
 * H1 answers with a raw response buffer and H2 must answer with
 * HEADERS+RST_STREAM.
 *
 * It also owns the effective-model resolution: ONE body-first resolution,
 * handed back for BOTH authorization (inside) and routing (the caller
 * stores it where endpoint selection reads it). On enforcing services a
 * request whose JSON body model and X-Model header disagree is denied 400
 * model_conflict — a disagreement is a broken client or a spoof attempt,
 * and silently picking one hides it. Non-enforcing services keep their
 * legacy behavior: the gate is skipped and routing derives the model as it
 * always has.
 */

/* What the caller should do with the request. */
typedef enum {
  AI_GW_ADMIT_ALLOW = 0,       /* admitted: identity/model/reservation out-fields valid */
  AI_GW_ADMIT_UNMETERED = 1,   /* service policy does not enforce: skip the gate,
                                * count the request unmetered, change nothing else */
  AI_GW_ADMIT_DENY = 2,        /* refuse: http_status/error_code/log fields valid */
} ai_gw_admit_verdict_t;

/* Which stage produced a deny — for logging parity with the inlined gate. */
typedef enum {
  AI_GW_STAGE_NONE = 0,
  AI_GW_STAGE_AUTH,            /* credential/model validation (401/403/503) */
  AI_GW_STAGE_CONFLICT,        /* body/header model disagreement (400) */
  AI_GW_STAGE_RATELIMIT,       /* RPS / quota-latch check (429/503) */
  AI_GW_STAGE_RESERVE,         /* pre-admission token reservation (429) */
} ai_gw_admit_stage_t;

/* Request view handed to the gate. All pointers are borrowed; strings are
 * NUL-terminated. body may be NULL when the request carried none. */
typedef struct ai_gw_req_ctx {
  const char *api_key;       /* captured X-Api-Key value ("" when absent) */
  const char *bearer;        /* captured Authorization Bearer token, scheme
                              * stripped ("" when absent) */
  int         bearer_oversize; /* 1 = capture exceeded its cap; token dropped */
  const char *jwt_profile;   /* rule jwt_auth_profile ("" when none) */
  const char *body;          /* request body bytes, or NULL */
  size_t      body_len;
  const char *prefix_model;  /* body model captured earlier by prefix extraction ("") */
  const char *hdr_model;     /* X-Model header value ("") */
  int         auth_mode;     /* rule api_key_auth wire value (0 unset / 1 apikey
                              * required / 2 disabled / 3 jwt / 4 apikey-or-jwt;
                              * anything else enforces the API-key arm, fail-closed) */
} ai_gw_req_ctx_t;

typedef struct ai_gw_admit_result {
  ai_gw_admit_verdict_t verdict;
  ai_gw_admit_stage_t   stage;

  /* DENY: what the caller's response must carry. retry_body selects the
   * {"error","retry_after"} body shape (rate/reserve arms); otherwise the
   * {"error","message"} shape is used. These mirror the exact wire bodies
   * the inlined gate produced. */
  int  http_status;
  int  retry_after;
  int  retry_body;
  char error_code[64];
  char error_msg[128];

  /* ALLOW: the single body-first model resolution (may be "" when the
   * request named no model anywhere), and the validated identity. user_id
   * is filled by the JWT arm only (API keys do not map to users today);
   * auth_flags carries the deciding arm's upstream-hygiene switches
   * (AI_GW_AUTHF_* in sockproxy_ai_gw.h). */
  char effective_model[AI_GW_MODEL_LEN];
  char tenant_id[128];
  char key_id[64];
  char user_id[128];
  int  auth_flags;

  /* ALLOW: pre-admission token reservation to ride the connection to its
   * settle call. Zero epoch = nothing reserved. */
  uint32_t reserved_toks;
  int64_t  res_epoch;
} ai_gw_admit_result_t;

int ai_gw_admit(const ai_gw_req_ctx_t *req, ai_gw_admit_result_t *res);

#endif /* __SOCKPROXY_AI_ADMIT_H__ */
