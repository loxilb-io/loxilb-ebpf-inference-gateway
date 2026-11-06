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
 *
 * Network identity. On a service with a network-identity binding
 * (netid_bound) the source of the request can decide its tenant. The table,
 * one row per case:
 *
 *   # | service        | credential | binding of the source | result
 *   1 | non-enforcing  | any        | none                  | UNMETERED, as before
 *   2 | non-enforcing  | any        | any                   | ALLOW as the binding's
 *     |                |            |                       | tenant (network path)
 *   3 | enforcing      | present    | none                  | the credential decides
 *   4 | enforcing      | present    | advisory              | the credential decides;
 *     |                |            |                       | net_identity is set
 *   5 | enforcing      | present    | strict                | tenant differs: 403
 *     |                |            |                       | network_tenant_mismatch;
 *     |                |            |                       | equal: the model must
 *     |                |            |                       | also be in the binding's
 *     |                |            |                       | allowlist
 *   6 | enforcing      | absent     | credential: network   | ALLOW as the binding's
 *     |                |            |                       | tenant (network path)
 *   7 | enforcing      | absent     | anything else         | 401, as before
 *
 * The network path runs the same stages as a credential does, in this
 * order: model conflict (400), the binding's model allowlist (403), rate
 * and quota (429), reservation (429). A request that presents a credential
 * is always decided by that credential: a refused credential never falls
 * back to the binding. A resolver that cannot answer is "no binding" - it
 * never admits by network and never refuses a valid credential - except on a
 * service that asked to fail closed (AI_GW_NETID_FAIL_CLOSED), where every
 * request the resolver would have decided is refused with 503
 * netid_unavailable until it answers again.
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
  AI_GW_STAGE_CAPACITY,        /* service/endpoint capacity, after policy (429/503) */
  AI_GW_STAGE_OBJECTIVE,       /* the objective a request named is not its to use (403, strict rules) */
  /* The three below refuse outside ai_gw_admit, before any backend is chosen,
   * and report through ai_gw_record_local_deny. Appended: a recorded value
   * never moves. */
  AI_GW_STAGE_ROUTE,           /* no pool for the named model, no rule matched (503) */
  AI_GW_STAGE_FRAMING,         /* the request cannot be admitted as framed (400/413) */
  AI_GW_STAGE_SECURITY,        /* a content-security scanner blocked the request (403) */
} ai_gw_admit_stage_t;

/* How the tenant was decided. BEARER is set once a bearer token has
 * validated, so a refusal made after that names it too; a token that did
 * not validate decided nothing and leaves CREDENTIAL. */
#define AI_GW_AUTH_SRC_CREDENTIAL 0   /* an API key, or nothing */
#define AI_GW_AUTH_SRC_NETWORK    1   /* a network-identity binding of the source */
#define AI_GW_AUTH_SRC_BEARER     2   /* a validated bearer token */

/* Request view handed to the gate. All pointers are borrowed; strings are
 * NUL-terminated. body may be NULL when the request carried none. */
typedef struct ai_gw_req_ctx {
  const char *api_key;       /* captured X-Api-Key value ("" when absent) */
  const char *bearer;        /* RAW Authorization header value, scheme tag
                              * included ("" when absent); the gate strips
                              * the Bearer prefix itself after reassembly */
  int         bearer_oversize; /* 1 = capture exceeded its cap; token dropped */
  const char *jwt_profile;   /* rule jwt_auth_profile ("" when none) */
  const char *body;          /* request body bytes, or NULL */
  size_t      body_len;
  const char *parsed_body_model; /* non-NULL when the transport scanned metadata */
  int         model_parse_result;
  const char *prefix_model;  /* body model captured earlier by prefix extraction ("") */
  const char *hdr_model;     /* X-Model header value ("") */
  int         auth_mode;     /* rule api_key_auth wire value (0 unset / 1 apikey
                              * required / 2 disabled / 3 jwt / 4 apikey-or-jwt;
                              * anything else enforces the API-key arm, fail-closed) */
  const char *svc_ident;     /* service identity "VIP:port" ("" when unknown);
                              * selects the rule-scope QoS defaults row, and on
                              * non-enforcing services the opt-in per-VIP shared
                              * bucket (the only ladder arm keyless traffic has) */

  /* Streamed dispatch: the request body is NOT complete when the gate runs.
   * body/body_len then hold only the bounded routing prefix (or nothing,
   * for a body the proxy never inspects), so the gate must not parse it as
   * a whole document: the model comes from prefix_model/hdr_model, and the
   * prompt-token reservation is sized from declared_content_length (bytes
   * still to arrive, at the same 4-bytes-per-token bias the complete-body
   * estimate uses) when that is larger than what the prefix shows. A zero
   * declared_content_length with prefix_only set reserves nothing from
   * bytes: the caller has no prompt to size (a non-JSON upload), or is
   * about to refuse the request itself and must not leave a claim behind. */
  int         prefix_only;
  size_t      declared_content_length;

  /* Default reservation: completion tokens to claim for a request whose
   * body declares no max_tokens, as the rule resolved it (0 = off, the
   * prompt estimate alone is claimed). A declared ceiling is never
   * replaced, and nothing is written into the forwarded body.
   *
   * Several rules can share a listener and the request's rule is the one
   * its model routes to, which the gate itself decides. So the caller hands
   * a lookup: default_tokens_of(default_tokens_arg, model) is asked once,
   * at the reservation, with the model the request will be routed by, and
   * answers that rule's value (0 = off, or no rule). It reads rule
   * configuration only. With no lookup, default_tokens is the value. */
  int         default_tokens;
  int       (*default_tokens_of)(void *arg, const char *model);
  void       *default_tokens_arg;

  /* Network identity. netid_bound is the service's switch, from
   * ai_gw_netid_bound(svc_ident): 0 means no binding can match this service
   * and the gate neither resolves one nor reads the body for it;
   * AI_GW_NETID_FAIL_CLOSED beside AI_GW_NETID_BOUND refuses the request
   * with 503 when the resolver cannot answer. It needs svc_ident; with none
   * the gate treats it as 0. in_ifindex is the
   * interface the connection arrived on, cached by the caller (0 = not
   * read); with client_ip below it is what a binding matches on. */
  int         netid_bound;
  int         in_ifindex;

  /* Correlation, filled by the caller before the gate: the request ID that
   * the refusal, the completion and the settle records of this request all
   * carry (minted, or adopted from the client, before admission so a
   * refused request has one too), and the relay worker deciding it
   * (notify_worker_id(); -1 when the caller is not a worker). The gate
   * hands both to the refusal record; it decides nothing on them. */
  const char *request_id;
  int         producer_id;

  /* Where the request came from, filled by the caller beside the correlation
   * above and handed straight to the refusal record; the gate decides
   * nothing on them. client_ip is the socket peer and is always known.
   * origin_ip is normally "" here and that is not an omission: the gate runs
   * BEFORE the header splice that derives an origin, so a refused request
   * usually has no attribution beyond its peer, and "" says exactly that
   * rather than claiming the peer. trusted_hops pairs with origin_ip. */
  const char *client_ip;
  const char *origin_ip;
  int         trusted_hops;

  /* The class of the request. class_on is ai_gw_class_on() as the caller
   * read it: 0 means no class is configured anywhere, the stage is skipped
   * and neither the hint header nor the body's service_tier is looked at.
   * objective_hint is the objective name the request's header asks for
   * ("" or NULL when it carries none). objective_strict is the rule's
   * ai_objective_strict: a request that names an objective it may not use
   * is refused 403 instead of falling to its default. Several rules can
   * share a listener, so the knob is the routed rule's, like the default
   * reservation: objective_strict_of(default_tokens_arg, model), when set,
   * is asked with the model the gate resolved and stands in for the plain
   * value. */
  int         class_on;
  const char *objective_hint;
  int         objective_strict;
  int       (*objective_strict_of)(void *arg, const char *model);
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
   * settle call. Zero epoch = nothing reserved. reserved_toks is what the
   * quota GRANTED, which is what settlement gives back: with a default
   * reservation it can be less than what was asked, and
   * reservation_clamped then says so. */
  uint32_t reserved_toks;
  int64_t  res_epoch;
  uint8_t  reservation_clamped;

  /* Network identity, valid on ALLOW and on a refusal made after the
   * binding was resolved. auth_src says what decided the tenant
   * (AI_GW_AUTH_SRC_*). net_identity names the binding that matched the
   * source ("" = none): on the network path it is the one that admitted
   * the request, beside a credential it is the one checked against it or
   * merely noted (advisory). net_forward_identity is that binding's
   * forward_identity switch, carried for the caller; the gate decides
   * nothing on it. */
  uint8_t  auth_src;
  uint8_t  net_forward_identity;
  char     net_identity[64];

  /* The class stage's answer; all zero when the stage did not run.
   * tier_consumed: the body's service_tier was read as a hint; the caller
   * overwrites the value at [tier_off, tier_off + tier_len) of the body it
   * passed with null before it forwards the request. hint_not_applied: the
   * body was not whole in the buffer and no header hint was given, so a
   * body hint, if there was one, could not be read. */
  int32_t  priority;
  uint8_t  priority_class;     /* AI_GW_CLASS_* */
  uint8_t  objective_denied;
  uint8_t  tier_consumed;
  uint8_t  hint_not_applied;
  /* class_ran: the class stage ran for this request; what the refusal
   * record says about its class. */
  uint8_t  class_ran;
  uint32_t tier_off;
  uint32_t tier_len;
  char     objective[64];
} ai_gw_admit_result_t;

int ai_gw_admit(const ai_gw_req_ctx_t *req, ai_gw_admit_result_t *res);

/* Record a refusal the gateway made outside ai_gw_admit's verdict frame, at
 * `stage`: capacity once the pool is known (AI_GW_STAGE_CAPACITY), routing
 * (AI_GW_STAGE_ROUTE), framing (AI_GW_STAGE_FRAMING) or a content-security
 * block (AI_GW_STAGE_SECURITY). The same record
 * export as the gate's own refusals, so every refusal is counted in one
 * place whichever stage made it. */
void ai_gw_record_local_deny(int stage, const char *request_id, int producer_id,
                             const char *svc_ident, const char *model,
                             const char *tenant_id, const char *key_id,
                             const char *user_id, int http_status,
                             const char *error_code,
                             const char *client_ip, const char *origin_ip,
                             int trusted_hops, int auth_src,
                             const char *net_identity,
                             int priority, int class_info,
                             const char *objective);

/* Record a refusal the capacity gate made AFTER ai_gw_admit admitted the
 * request on policy. The policy arms refuse through ai_gw_admit's own
 * verdict frame; capacity refuses at the dispatch site, once the pool and
 * its ceilings are known, so it reports through this second frame with the
 * identity the policy gate resolved, auth_src and net_identity included.
 * Both frames land on the same record export, so every refusal the gateway
 * makes is on the trail. */
void ai_gw_record_capacity_deny(const char *request_id, int producer_id,
                                const char *svc_ident, const char *model,
                                const char *tenant_id, const char *key_id,
                                const char *user_id, int http_status,
                                const char *error_code,
                                const char *client_ip, const char *origin_ip,
                                int trusted_hops, int auth_src,
                                const char *net_identity,
                                int priority, int class_info,
                                const char *objective);

/* Write a fresh request ID into buf: 32 lowercase hex digits shaped as a
 * UUID v4, from a per-thread generator that needs neither the trace ring
 * nor a trace-enabled build (the ring's generator returns zero in the
 * default build, which would hand every request the same ID). buf is
 * always NUL-terminated; len must cover AI_GW_REQUEST_ID_HEX + 1. */
#define AI_GW_REQUEST_ID_HEX 32
void ai_gw_mint_request_id(char *buf, size_t len);

/* Format the service identity the QoS ladder keys rule-scope state on:
 * "VIP:port" from the rule key's network-order IPv4 address and port —
 * the same derivation llb_ai_record_unmetered has always used for its
 * vip label, plus the listener port. buf is always NUL-terminated; a
 * zero-length buf is left untouched. */
void ai_gw_svc_ident(uint32_t xip_be, uint16_t xport_be, char *buf, size_t len);

/* The services that have a network-identity binding, as the control plane
 * last published them: what callers put in ai_gw_req_ctx_t.netid_bound.
 *
 * ai_gw_netid_bound_set replaces the whole set. svc_idents holds n service
 * identities ("VIP:port") and flags, when not NULL, one byte for each:
 * AI_GW_NETID_FAIL_CLOSED marks a service that refuses a request the
 * resolver could not answer for, AI_GW_NETID_FWD one that has a binding
 * which forwards identity upstream. all carries the same bits for every
 * service: AI_GW_NETID_BOUND marks every service bound (a binding that
 * names no service), with AI_GW_NETID_FAIL_CLOSED every one fails closed
 * and with AI_GW_NETID_FWD every one forwards. More than
 * AI_GW_NETID_SVC_MAX services also reads as all: the set may answer bound,
 * fail-closed or forwarding for a service that did not ask (the resolver
 * then finds no binding), never the reverse. Safe against concurrent
 * readers; writers are serialized.
 *
 * ai_gw_netid_bound is the request-path read: lock-free, wait-free against
 * a writer, one hash and a probe of a table kept at most a quarter full,
 * and one atomic load while no binding exists anywhere. It returns 0 or
 * AI_GW_NETID_BOUND, with AI_GW_NETID_FAIL_CLOSED and AI_GW_NETID_FWD when
 * the service has them.
 *
 * ai_gw_netid_fwd_any says whether any service forwards identity at all:
 * the one load the upstream-header path pays before it builds a service
 * identity to ask about.
 *
 * ai_gw_netid_ifmatch is set while at least one binding matches on an
 * ingress interface. Only then is a connection's ingress interface read. */
#define AI_GW_NETID_SVC_MAX      1024
#define AI_GW_NETID_BOUND        0x1
#define AI_GW_NETID_FAIL_CLOSED  0x2
#define AI_GW_NETID_FWD          0x4
void ai_gw_netid_bound_set(const char *const *svc_idents, const uint8_t *flags,
                           int n, int all);
int  ai_gw_netid_bound(const char *svc_ident);
int  ai_gw_netid_fwd_any(void);

/* Whether any class is configured: an objective, a tenant or key with a
 * class field, a binding or JWT profile that lowers its requests. The
 * control plane sets it; the request path reads it once per request. While
 * it is 0 a request is handled exactly as before classes existed. */
void ai_gw_class_on_set(int on);
int  ai_gw_class_on(void);
void ai_gw_netid_ifmatch_set(int on);
int  ai_gw_netid_ifmatch(void);

#endif /* __SOCKPROXY_AI_ADMIT_H__ */
