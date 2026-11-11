/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Identity-forwarding ABI unit: proves ai_gw_admit() transports the
 * request's full identity — user, key, service — into every ladder call,
 * and that keyless traffic probes the per-VIP shared bucket exactly when
 * the service identity is known.
 *
 * These are the arms the Go-side ladder keeps dormant when a data plane
 * pre-dates the ABI: a regression that quietly drops one of these
 * parameters re-opens the "user limits configured but never enforced"
 * hole without failing any Go test, because the Go corpus exercises the
 * internal functions below the CGO boundary. This unit pins the C side
 * of that boundary.
 *
 * Standalone: compiles sockproxy_ai_admit.c into the binary and stubs
 * both the Go exports and the JSON helpers, so it needs no proxy object
 * graph and no link library.
 */

#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "sockproxy_ai_admit.h"

/* ---- JSON helper stubs (sockproxy_json.h) ------------------------------- */

static int extract_model_calls;

int
extract_model_field(const char *body, size_t len, char *out, size_t cap)
{
  (void)len;
  extract_model_calls++;
  if (body && cap > 3) {
    strcpy(out, "m1");
    return 0;
  }
  return -1;
}

int
estimate_prompt_tokens(const char *body, size_t len)
{
  (void)body;
  (void)len;
  return 7;
}

/* What the body declares as its completion ceiling; 0 = none. */
static int max_tokens_stub = 32;

int
extract_max_tokens(const char *body, size_t len)
{
  (void)body;
  (void)len;
  return max_tokens_stub;
}

/* ---- Go-export stubs recording what the gate handed them ---------------- */

static int validate_key_calls;
static int validate_bearer_calls;
/* Forced outcome of the API-key arm: 0 = validate, otherwise the decision
 * the arm refuses with (2 = model refused for a known tenant). */
static int validate_key_decision;
static const char *validate_key_tenant = "tenant-1";
/* The same for the JWT arm. */
static int validate_bearer_decision;
static struct {
  int  calls;
  char request_id[64];
  int  producer_id;
  char svc[64];
  char model[128];
  char tenant[128];
  char key[64];
  char user[128];
  int  stage;
  int  http_status;
  char error_code[64];
  char client_ip[46];
  char origin_ip[46];
  int  trusted_hops;
  int  auth_src;
  char net_identity[64];
  int  priority;
  int  class_info;
  char objective[64];
} deny_stub;

static struct {
  int  calls;
  char key[64];
  char tenant[128];
  char user[128];
  char svc[64];
  char model[128];
  int  rc;        /* forced return */
  int  decision;  /* forced decision on deny */
} rl_stub;

static struct {
  int  calls;
  char tenant[128];
  char model[128];
  char user[128];
  char key[64];
  char svc[64];
  int  prompt_est;
  int  max_tokens;
  int  default_tokens;
  int  rc;          /* forced return */
  int  shrink;      /* tokens the quota takes off the default it was asked */
} rs_stub;

int
llb_ai_validate_key(char *raw_key, char *model, ai_gw_decision_t *result)
{
  validate_key_calls++;
  (void)model;
  /* The real validator refuses a missing key with the 401 shape. */
  if (raw_key[0] == '\0') {
    result->decision = 1;
    strcpy(result->error_code, "invalid_api_key");
    return -1;
  }
  strcpy(result->key_id, "key-1");
  strcpy(result->tenant_id, validate_key_tenant);
  if (validate_key_decision != 0) {
    /* The credential validated and named its tenant; the refusal is the
     * arm's decision (a model this key may not use). */
    result->decision = validate_key_decision;
    return -1;
  }
  /* API keys map to no user today: user_id stays "". */
  return 0;
}

void
llb_ai_record_deny(char *request_id, int producer_id,
                   char *svc_ident, char *model_name,
                   char *tenant_id, char *key_id, char *user_id,
                   int stage, int http_status, char *error_code,
                   char *client_ip, char *origin_ip, int trusted_hops,
                   int auth_src, char *net_identity,
                   int priority, int class_info, char *objective)
{
  deny_stub.calls++;
  deny_stub.priority = priority;
  deny_stub.class_info = class_info;
  snprintf(deny_stub.objective, sizeof(deny_stub.objective), "%s", objective);
  deny_stub.auth_src = auth_src;
  snprintf(deny_stub.net_identity, sizeof(deny_stub.net_identity), "%s",
           net_identity);
  snprintf(deny_stub.request_id, sizeof(deny_stub.request_id), "%s", request_id);
  deny_stub.producer_id = producer_id;
  snprintf(deny_stub.svc, sizeof(deny_stub.svc), "%s", svc_ident);
  snprintf(deny_stub.model, sizeof(deny_stub.model), "%s", model_name);
  snprintf(deny_stub.tenant, sizeof(deny_stub.tenant), "%s", tenant_id);
  snprintf(deny_stub.key, sizeof(deny_stub.key), "%s", key_id);
  snprintf(deny_stub.user, sizeof(deny_stub.user), "%s", user_id);
  deny_stub.stage = stage;
  deny_stub.http_status = http_status;
  snprintf(deny_stub.error_code, sizeof(deny_stub.error_code), "%s", error_code);
  snprintf(deny_stub.client_ip, sizeof(deny_stub.client_ip), "%s", client_ip);
  snprintf(deny_stub.origin_ip, sizeof(deny_stub.origin_ip), "%s", origin_ip);
  deny_stub.trusted_hops = trusted_hops;
}

int
llb_ai_validate_bearer(char *bearer, char *model_name, char *profile_name,
                       int bearer_flags, ai_gw_decision_t *result)
{
  validate_bearer_calls++;
  (void)model_name;
  (void)profile_name;
  (void)bearer_flags;
  /* The real validator refuses a missing token with the 401 shape. */
  if (bearer[0] == '\0') {
    result->decision = 1;
    strcpy(result->error_code, "invalid_token");
    return -1;
  }
  assert(strcmp(bearer, "tok") == 0); /* gate strips the Bearer tag itself */
  strcpy(result->tenant_id, "tenant-1");
  strcpy(result->user_id, "alice");
  if (validate_bearer_decision != 0) {
    /* The token validated and named its tenant; the refusal is the arm's
     * decision (a model its roles do not cover). */
    result->decision = validate_bearer_decision;
    return -1;
  }
  /* The JWT arm mints no key_id. */
  return 0;
}

int
llb_ai_ratelimit_check(char *key_id, char *tenant_id,
                       char *user_id, char *svc_ident,
                       char *model, ai_gw_decision_t *result)
{
  rl_stub.calls++;
  snprintf(rl_stub.key, sizeof(rl_stub.key), "%s", key_id);
  snprintf(rl_stub.tenant, sizeof(rl_stub.tenant), "%s", tenant_id);
  snprintf(rl_stub.user, sizeof(rl_stub.user), "%s", user_id);
  snprintf(rl_stub.svc, sizeof(rl_stub.svc), "%s", svc_ident);
  snprintf(rl_stub.model, sizeof(rl_stub.model), "%s", model);
  if (rl_stub.rc != 0) {
    result->decision = rl_stub.decision;
    result->retry_after = 2;
    strcpy(result->error_code, "rate_limit_exceeded");
  }
  return rl_stub.rc;
}

int
llb_ai_token_quota_reserve(char *tenant_id, char *model_name,
                           char *user_id, char *key_id, char *svc_ident,
                           int prompt_est, int max_tokens,
                           int default_tokens,
                           int64_t *res_epoch, int *granted,
                           ai_gw_decision_t *result)
{
  rs_stub.calls++;
  snprintf(rs_stub.tenant, sizeof(rs_stub.tenant), "%s", tenant_id);
  snprintf(rs_stub.model, sizeof(rs_stub.model), "%s", model_name);
  snprintf(rs_stub.user, sizeof(rs_stub.user), "%s", user_id);
  snprintf(rs_stub.key, sizeof(rs_stub.key), "%s", key_id);
  snprintf(rs_stub.svc, sizeof(rs_stub.svc), "%s", svc_ident);
  rs_stub.prompt_est = prompt_est;
  rs_stub.max_tokens = max_tokens;
  rs_stub.default_tokens = default_tokens;
  if (rs_stub.rc != 0) {
    result->decision = 3;
    result->retry_after = 5;
    strcpy(result->error_code, "token_quota_would_exceed");
    return rs_stub.rc;
  }
  *res_epoch = 77;
  *granted = prompt_est + max_tokens + default_tokens - rs_stub.shrink;
  return 0;
}

/* The network-identity resolver: what it was asked, and the binding it
 * answers with (out.matched == 0 = no binding; rc != 0 = it could not
 * answer). */
static struct {
  int  calls;
  char client_ip[46];
  int  in_ifindex;
  char svc[64];
  char model[128];
  int  rc;
  ai_gw_netid_t out;
} nid_stub;

int
llb_ai_netid_resolve(char *client_ip, int in_ifindex, char *svc_ident,
                     char *model, ai_gw_netid_t *out)
{
  nid_stub.calls++;
  snprintf(nid_stub.client_ip, sizeof(nid_stub.client_ip), "%s", client_ip);
  nid_stub.in_ifindex = in_ifindex;
  snprintf(nid_stub.svc, sizeof(nid_stub.svc), "%s", svc_ident);
  snprintf(nid_stub.model, sizeof(nid_stub.model), "%s", model);
  /* The gate hands over zeroed memory: a resolver that writes nothing
   * answers "no binding". */
  assert(out->matched == 0 && out->tenant_id[0] == '\0');
  *out = nid_stub.out;
  return nid_stub.rc;
}

/* A binding of the test source, as the resolver would answer it. */
static void
nid_bind(const char *tenant, int strict, int credential_network)
{
  memset(&nid_stub.out, 0, sizeof(nid_stub.out));
  nid_stub.out.matched = 1;
  nid_stub.out.enforce = strict;
  nid_stub.out.credential_network = credential_network;
  nid_stub.out.model_ok = 1;
  snprintf(nid_stub.out.tenant_id, sizeof(nid_stub.out.tenant_id), "%s", tenant);
  strcpy(nid_stub.out.binding, "line-1");
}

/* ---- class resolver double, and the body's tier ------------------------- */

static struct {
  int  calls;
  char tenant[128];
  char key[64];
  char binding[64];
  char profile[64];
  char svc[64];
  char hint[128];
  int  tier;
  int  rc;
  ai_gw_class_t out;
} cls_stub;

int
llb_ai_class_resolve(char *tenant, char *key_id, char *binding, char *profile,
                     char *svc_ident, char *objective_hint, int tier_hint,
                     ai_gw_class_t *out)
{
  cls_stub.calls++;
  snprintf(cls_stub.tenant, sizeof(cls_stub.tenant), "%s", tenant);
  snprintf(cls_stub.key, sizeof(cls_stub.key), "%s", key_id);
  snprintf(cls_stub.binding, sizeof(cls_stub.binding), "%s", binding);
  snprintf(cls_stub.profile, sizeof(cls_stub.profile), "%s", profile);
  snprintf(cls_stub.svc, sizeof(cls_stub.svc), "%s", svc_ident);
  snprintf(cls_stub.hint, sizeof(cls_stub.hint), "%s", objective_hint);
  cls_stub.tier = tier_hint;
  assert(out->priority == 0 && out->objective[0] == '\0');
  *out = cls_stub.out;
  return cls_stub.rc;
}

static struct {
  int    calls;
  int    tier;
  size_t off, vlen;
} tier_stub;

int
extract_service_tier(const char *body, size_t len, size_t *off, size_t *vlen)
{
  (void)body;
  (void)len;
  tier_stub.calls++;
  *off = tier_stub.tier ? tier_stub.off : 0;
  *vlen = tier_stub.tier ? tier_stub.vlen : 0;
  return tier_stub.tier;
}

static void
reset_stubs(void)
{
  memset(&nid_stub, 0, sizeof(nid_stub));
  memset(&cls_stub, 0, sizeof(cls_stub));
  memset(&tier_stub, 0, sizeof(tier_stub));
  validate_key_calls = 0;
  validate_bearer_calls = 0;
  validate_key_decision = 0;
  validate_bearer_decision = 0;
  extract_model_calls = 0;
  memset(&deny_stub, 0, sizeof(deny_stub));
  memset(&rl_stub, 0, sizeof(rl_stub));
  memset(&rs_stub, 0, sizeof(rs_stub));
  max_tokens_stub = 32;
}

/* ---- cases --------------------------------------------------------------- */

static const char body[] = "{\"model\":\"m1\",\"max_tokens\":32}";

static void
test_jwt_arm_forwards_user_and_service(void)
{
  ai_gw_req_ctx_t req = {
    .bearer = "Bearer tok",
    .jwt_profile = "kc",
    .body = body,
    .body_len = sizeof(body) - 1,
    .auth_mode = 3,
    .svc_ident = "10.0.0.1:2040",
  };
  ai_gw_admit_result_t res;

  reset_stubs();
  assert(ai_gw_admit(&req, &res) == 0);
  assert(res.verdict == AI_GW_ADMIT_ALLOW);
  assert(validate_bearer_calls == 1 && validate_key_calls == 0);

  assert(rl_stub.calls == 1);
  assert(strcmp(rl_stub.key, "") == 0);          /* JWT arm mints no key */
  assert(strcmp(rl_stub.tenant, "tenant-1") == 0);
  assert(strcmp(rl_stub.user, "alice") == 0);
  assert(strcmp(rl_stub.svc, "10.0.0.1:2040") == 0);
  assert(strcmp(rl_stub.model, "m1") == 0);

  assert(rs_stub.calls == 1);
  assert(strcmp(rs_stub.user, "alice") == 0);
  assert(strcmp(rs_stub.key, "") == 0);
  assert(strcmp(rs_stub.svc, "10.0.0.1:2040") == 0);
  assert(rs_stub.prompt_est == 7 && rs_stub.max_tokens == 32);
  assert(res.res_epoch == 77 && res.reserved_toks == 39);
  assert(strcmp(res.user_id, "alice") == 0);
  /* A validated token is what decided the tenant, and the result says so. */
  assert(res.auth_src == AI_GW_AUTH_SRC_BEARER);
}

/* What a bearer token leaves on the records: a validated one is named as
 * the source on the admission and on any refusal after it; one that did not
 * validate decided nothing; an API key never reads as a bearer token. */
static void
test_bearer_is_named_as_the_source(void)
{
  ai_gw_req_ctx_t req = {
    .bearer = "Bearer tok",
    .jwt_profile = "kc",
    .body = body,
    .body_len = sizeof(body) - 1,
    .auth_mode = 3,
    .svc_ident = "10.0.0.1:2040",
  };
  ai_gw_admit_result_t res;

  /* Refused by a later stage: the refusal's record names the token. */
  reset_stubs();
  rl_stub.rc = -1;
  rl_stub.decision = 3;
  assert(ai_gw_admit(&req, &res) == -1);
  assert(res.stage == AI_GW_STAGE_RATELIMIT);
  assert(deny_stub.calls == 1 && deny_stub.auth_src == AI_GW_AUTH_SRC_BEARER);
  assert(strcmp(deny_stub.tenant, "tenant-1") == 0);
  assert(deny_stub.net_identity[0] == '\0');

  /* Refused by the token's own model allowlist: the token validated and
   * named its tenant, and the refusal's record names it. */
  reset_stubs();
  validate_bearer_decision = 2;
  assert(ai_gw_admit(&req, &res) == -1);
  assert(res.http_status == 403);
  assert(strcmp(res.error_code, "model_not_allowed") == 0);
  assert(deny_stub.calls == 1 && deny_stub.auth_src == AI_GW_AUTH_SRC_BEARER);
  assert(strcmp(deny_stub.tenant, "tenant-1") == 0);

  /* No token: nothing validated, nothing is claimed. */
  reset_stubs();
  req.bearer = "";
  assert(ai_gw_admit(&req, &res) == -1);
  assert(res.http_status == 401);
  assert(deny_stub.calls == 1 && deny_stub.auth_src == AI_GW_AUTH_SRC_CREDENTIAL);
  assert(res.auth_src == AI_GW_AUTH_SRC_CREDENTIAL);

  /* An API key is not a bearer token. */
  reset_stubs();
  req.bearer = "";
  req.api_key = "k";
  req.auth_mode = 1;
  assert(ai_gw_admit(&req, &res) == 0);
  assert(res.verdict == AI_GW_ADMIT_ALLOW);
  assert(res.auth_src == AI_GW_AUTH_SRC_CREDENTIAL);
}

static void
test_apikey_arm_forwards_key_and_service(void)
{
  ai_gw_req_ctx_t req = {
    .api_key = "sk-abc",
    .body = body,
    .body_len = sizeof(body) - 1,
    .auth_mode = 1,
    .svc_ident = "10.0.0.1:2040",
  };
  ai_gw_admit_result_t res;

  reset_stubs();
  assert(ai_gw_admit(&req, &res) == 0);
  assert(res.verdict == AI_GW_ADMIT_ALLOW);
  assert(validate_key_calls == 1 && validate_bearer_calls == 0);

  assert(rl_stub.calls == 1);
  assert(strcmp(rl_stub.key, "key-1") == 0);
  assert(strcmp(rl_stub.user, "") == 0);         /* keys map to no user */
  assert(strcmp(rl_stub.svc, "10.0.0.1:2040") == 0);

  assert(rs_stub.calls == 1);
  assert(strcmp(rs_stub.key, "key-1") == 0);
  assert(strcmp(rs_stub.user, "") == 0);
  assert(strcmp(rs_stub.svc, "10.0.0.1:2040") == 0);
}

static void
test_keyless_probes_shared_bucket_only_with_ident(void)
{
  ai_gw_req_ctx_t req = {
    .auth_mode = 0,
    .svc_ident = "10.0.0.1:2040",
  };
  ai_gw_admit_result_t res;

  /* With a service identity: exactly one ladder probe, fully-empty
   * identity, service carried — the Go-side keyless contract. */
  reset_stubs();
  assert(ai_gw_admit(&req, &res) == 0);
  assert(res.verdict == AI_GW_ADMIT_UNMETERED);
  assert(rl_stub.calls == 1);
  assert(rl_stub.key[0] == '\0' && rl_stub.tenant[0] == '\0' &&
         rl_stub.user[0] == '\0');
  assert(strcmp(rl_stub.svc, "10.0.0.1:2040") == 0);
  assert(validate_key_calls == 0 && validate_bearer_calls == 0);
  assert(rs_stub.calls == 0); /* keyless traffic reserves nothing */

  /* Shared-bucket denial refuses the request with the rate shape. */
  reset_stubs();
  rl_stub.rc = -1;
  rl_stub.decision = 3;
  assert(ai_gw_admit(&req, &res) == -1);
  assert(res.verdict == AI_GW_ADMIT_DENY);
  assert(res.http_status == 429);
  assert(res.retry_body == 1);
  assert(strcmp(res.error_code, "rate_limit_exceeded") == 0);

  /* No service identity: no probe at all — exact legacy behaviour. */
  reset_stubs();
  req.svc_ident = NULL;
  assert(ai_gw_admit(&req, &res) == 0);
  assert(res.verdict == AI_GW_ADMIT_UNMETERED);
  assert(rl_stub.calls == 0);

  /* Mode 2 (declared disabled) keeps the same probe contract. */
  reset_stubs();
  req.auth_mode = 2;
  req.svc_ident = "10.0.0.1:2040";
  assert(ai_gw_admit(&req, &res) == 0);
  assert(res.verdict == AI_GW_ADMIT_UNMETERED);
  assert(rl_stub.calls == 1);
  assert(strcmp(rl_stub.svc, "10.0.0.1:2040") == 0);
}

/* ---- streamed dispatch: the gate on a bounded prefix ---------------------- */

/* A streamed request hands the gate only its routing prefix. The model must
 * come from the prefix extraction the caller already did (a whole-document
 * parse of a truncated body is meaningless), and the claim must be sized
 * from the declared length: the prefix shows the first bytes of the
 * messages array, the length shows all of them. */
static void
test_prefix_only_sizes_reservation_from_declared_length(void)
{
  static const char prefix[] = "{\"model\":\"m1\",\"messages\":[{\"role\":\"u";
  ai_gw_req_ctx_t req = {
    .api_key = "sk-abc",
    .body = prefix,
    .body_len = sizeof(prefix) - 1,
    .prefix_model = "m1",
    .auth_mode = 1,
    .svc_ident = "10.0.0.1:2040",
    .prefix_only = 1,
    .declared_content_length = 40000,
  };
  ai_gw_admit_result_t res;

  reset_stubs();
  assert(ai_gw_admit(&req, &res) == 0);
  assert(res.verdict == AI_GW_ADMIT_ALLOW);
  assert(extract_model_calls == 0);              /* prefix is not a document */
  assert(strcmp(res.effective_model, "m1") == 0);
  assert(rl_stub.calls == 1 && strcmp(rl_stub.model, "m1") == 0);
  assert(rs_stub.calls == 1);
  assert(rs_stub.prompt_est == 10000);           /* 40000 bytes / 4 */
  assert(rs_stub.max_tokens == 32);              /* still read from the prefix */
  assert(res.reserved_toks == 10032 && res.res_epoch == 77);

  /* The larger of the two estimates wins: a declared length smaller than
   * what the prefix already implies does not shrink the claim. */
  reset_stubs();
  req.declared_content_length = 8;               /* 2 tokens < the stub's 7 */
  assert(ai_gw_admit(&req, &res) == 0);
  assert(rs_stub.calls == 1 && rs_stub.prompt_est == 7);
}

/* ---- default reservation -------------------------------------------------- */

static ai_gw_req_ctx_t
default_resv_req(int default_tokens)
{
  ai_gw_req_ctx_t req = {
    .api_key = "sk-abc",
    .body = body,
    .body_len = sizeof(body) - 1,
    .auth_mode = 1,
    .svc_ident = "10.0.0.1:2040",
    .default_tokens = default_tokens,
  };
  return req;
}

/* The knob off: a request without a ceiling claims its prompt estimate and
 * nothing else, and the quota is not told about a default. */
static void
test_default_reservation_off_claims_the_prompt_alone(void)
{
  ai_gw_req_ctx_t req = default_resv_req(0);
  ai_gw_admit_result_t res;

  reset_stubs();
  max_tokens_stub = 0;
  assert(ai_gw_admit(&req, &res) == 0);
  assert(res.verdict == AI_GW_ADMIT_ALLOW);
  assert(rs_stub.calls == 1);
  assert(rs_stub.prompt_est == 7 && rs_stub.max_tokens == 0);
  assert(rs_stub.default_tokens == 0);
  assert(res.reserved_toks == 7 && res.res_epoch == 77);
  assert(res.reservation_clamped == 0);
}

/* The knob on and no ceiling declared: the default is asked for beside the
 * prompt estimate, and what the quota granted is what settlement will give
 * back. */
static void
test_default_reservation_stands_in_for_an_absent_ceiling(void)
{
  ai_gw_req_ctx_t req = default_resv_req(512);
  ai_gw_admit_result_t res;

  reset_stubs();
  max_tokens_stub = 0;
  assert(ai_gw_admit(&req, &res) == 0);
  assert(res.verdict == AI_GW_ADMIT_ALLOW);
  assert(rs_stub.calls == 1);
  assert(rs_stub.prompt_est == 7 && rs_stub.max_tokens == 0);
  assert(rs_stub.default_tokens == 512);
  assert(res.reserved_toks == 519 && res.res_epoch == 77);
  assert(res.reservation_clamped == 0);
}

/* A declared ceiling is never replaced: the default is not passed at all. */
static void
test_default_reservation_leaves_a_declared_ceiling_alone(void)
{
  ai_gw_req_ctx_t req = default_resv_req(512);
  ai_gw_admit_result_t res;

  reset_stubs();
  assert(ai_gw_admit(&req, &res) == 0);
  assert(rs_stub.calls == 1);
  assert(rs_stub.max_tokens == 32 && rs_stub.default_tokens == 0);
  assert(res.reserved_toks == 39);
  assert(res.reservation_clamped == 0);
}

/* The rule a request routes to is the one whose default counts, and the
 * gate is what decides the model it routes by: the caller's lookup is asked
 * once, at the reservation, with that model. */
static struct {
  int   calls;
  char  model[128];
  void *arg;
  int   answer;
} dt_stub;

static int
dt_lookup(void *arg, const char *model)
{
  dt_stub.calls++;
  dt_stub.arg = arg;
  snprintf(dt_stub.model, sizeof(dt_stub.model), "%s", model);
  return dt_stub.answer;
}

/* Several rules share a listener: the strict knob is the routed rule's,
 * asked with the model the gate resolved, and stands in for the plain
 * value in both directions. */
static struct { int calls; int answer; void *arg; char model[64]; } so_stub;
static int
so_lookup(void *arg, const char *model)
{
  so_stub.calls++;
  so_stub.arg = arg;
  snprintf(so_stub.model, sizeof(so_stub.model), "%s", model);
  return so_stub.answer;
}

static void test_objective_strict_is_the_routed_rules(void);

static void
test_default_reservation_is_the_routed_rules(void)
{
  ai_gw_req_ctx_t req = default_resv_req(64);   /* the plain value: not used */
  ai_gw_admit_result_t res;
  int cookie;

  req.default_tokens_of = dt_lookup;
  req.default_tokens_arg = &cookie;

  /* asked with the model the gate resolved (the body's), and its answer is
   * what the quota is asked for */
  reset_stubs();
  memset(&dt_stub, 0, sizeof(dt_stub));
  dt_stub.answer = 300;
  max_tokens_stub = 0;
  assert(ai_gw_admit(&req, &res) == 0);
  assert(res.verdict == AI_GW_ADMIT_ALLOW);
  assert(dt_stub.calls == 1 && dt_stub.arg == &cookie);
  assert(strcmp(dt_stub.model, "m1") == 0);
  assert(strcmp(dt_stub.model, res.effective_model) == 0);
  assert(rs_stub.default_tokens == 300);
  assert(res.reserved_toks == 307);

  /* the routed rule has it off: nothing stands in, whatever the plain
   * value says */
  reset_stubs();
  memset(&dt_stub, 0, sizeof(dt_stub));
  max_tokens_stub = 0;
  assert(ai_gw_admit(&req, &res) == 0);
  assert(dt_stub.calls == 1);
  assert(rs_stub.default_tokens == 0 && res.reserved_toks == 7);

  /* a declared ceiling: the rule is not asked at all */
  reset_stubs();
  memset(&dt_stub, 0, sizeof(dt_stub));
  dt_stub.answer = 300;
  assert(ai_gw_admit(&req, &res) == 0);
  assert(dt_stub.calls == 0);
  assert(rs_stub.max_tokens == 32 && rs_stub.default_tokens == 0);

  /* a request refused before the reservation never asks */
  reset_stubs();
  memset(&dt_stub, 0, sizeof(dt_stub));
  dt_stub.answer = 300;
  max_tokens_stub = 0;
  rl_stub.rc = 1;
  assert(ai_gw_admit(&req, &res) != 0);
  assert(res.verdict == AI_GW_ADMIT_DENY && res.stage == AI_GW_STAGE_RATELIMIT);
  assert(dt_stub.calls == 0);
}

/* The quota shrank the default: the request is admitted all the same, the
 * granted total rides to settlement (not the asked one), and the result
 * says the claim was clamped. Shrunk to nothing is still an admission, on
 * the prompt estimate alone. */
static void
test_clamped_default_is_admitted_with_what_was_granted(void)
{
  ai_gw_req_ctx_t req = default_resv_req(512);
  ai_gw_admit_result_t res;

  reset_stubs();
  max_tokens_stub = 0;
  rs_stub.shrink = 412;
  assert(ai_gw_admit(&req, &res) == 0);
  assert(res.verdict == AI_GW_ADMIT_ALLOW);
  assert(res.reserved_toks == 107 && res.res_epoch == 77);
  assert(res.reservation_clamped == 1);

  reset_stubs();
  max_tokens_stub = 0;
  rs_stub.shrink = 512;
  assert(ai_gw_admit(&req, &res) == 0);
  assert(res.verdict == AI_GW_ADMIT_ALLOW);
  assert(res.reserved_toks == 7 && res.res_epoch == 77);
  assert(res.reservation_clamped == 1);
}

/* A refusal is the firm part's: the record names the prompt estimate, and
 * the default that was asked beside it is not in the figure. */
static void
test_reserve_refusal_reports_the_firm_claim(void)
{
  ai_gw_req_ctx_t req = default_resv_req(512);
  ai_gw_admit_result_t res;

  reset_stubs();
  max_tokens_stub = 0;
  rs_stub.rc = -1;
  assert(ai_gw_admit(&req, &res) == -1);
  assert(res.verdict == AI_GW_ADMIT_DENY);
  assert(res.stage == AI_GW_STAGE_RESERVE);
  assert(res.http_status == 429 && res.retry_after == 5);
  assert(strcmp(res.error_code, "token_quota_would_exceed") == 0);
  assert(rs_stub.default_tokens == 512);
  assert(res.reserved_toks == 7);
  assert(res.res_epoch == 0 && res.reservation_clamped == 0);
}

/* A streamed body shows the gate a prefix: a ceiling it does not show is a
 * ceiling the gate cannot read, and the default covers it like an absent
 * one, beside the claim sized from the declared length. */
static void
test_default_reservation_covers_a_streamed_body(void)
{
  static const char prefix[] = "{\"model\":\"m1\",\"messages\":[{\"role\":\"u";
  ai_gw_req_ctx_t req = {
    .api_key = "sk-abc",
    .body = prefix,
    .body_len = sizeof(prefix) - 1,
    .prefix_model = "m1",
    .auth_mode = 1,
    .svc_ident = "10.0.0.1:2040",
    .prefix_only = 1,
    .declared_content_length = 40000,
    .default_tokens = 512,
  };
  ai_gw_admit_result_t res;

  reset_stubs();
  max_tokens_stub = 0;
  assert(ai_gw_admit(&req, &res) == 0);
  assert(rs_stub.prompt_est == 10000 && rs_stub.default_tokens == 512);
  assert(res.reserved_toks == 10512);
}

/* No body and no declared length: the credential and rate ladder still
 * run, the model falls back to the header, and NOTHING is reserved. This
 * is the shape of a non-JSON upload (no prompt to size) and of the caller
 * that is about to refuse an unresolvable request itself. */
static void
test_prefix_only_without_length_reserves_nothing(void)
{
  ai_gw_req_ctx_t req = {
    .api_key = "sk-abc",
    .hdr_model = "m-hdr",
    .auth_mode = 1,
    .svc_ident = "10.0.0.1:2040",
    .prefix_only = 1,
  };
  ai_gw_admit_result_t res;

  reset_stubs();
  assert(ai_gw_admit(&req, &res) == 0);
  assert(res.verdict == AI_GW_ADMIT_ALLOW);
  assert(validate_key_calls == 1);
  assert(rl_stub.calls == 1 && strcmp(rl_stub.model, "m-hdr") == 0);
  assert(rs_stub.calls == 0);
  assert(res.reserved_toks == 0 && res.res_epoch == 0);
  assert(strcmp(res.effective_model, "m-hdr") == 0);

  /* No model anywhere is still admitted with an empty resolution: the
   * caller decides what an unresolvable model means for its framing. */
  reset_stubs();
  req.hdr_model = "";
  assert(ai_gw_admit(&req, &res) == 0);
  assert(res.verdict == AI_GW_ADMIT_ALLOW);
  assert(res.effective_model[0] == '\0');
  assert(rs_stub.calls == 0);

  /* A default reservation does not turn "nothing to size" into a claim. */
  reset_stubs();
  max_tokens_stub = 0;
  req.default_tokens = 512;
  assert(ai_gw_admit(&req, &res) == 0);
  assert(rs_stub.calls == 0);
  assert(res.reserved_toks == 0 && res.res_epoch == 0);
}

/* A streamed request with no credential is refused on the credential
 * stage exactly like a buffered one, and refusal reserves nothing. */
static void
test_prefix_only_missing_credential_is_refused(void)
{
  static const char prefix[] = "{\"model\":\"m1\",\"messages\":[";
  ai_gw_req_ctx_t req = {
    .api_key = "",
    .body = prefix,
    .body_len = sizeof(prefix) - 1,
    .prefix_model = "m1",
    .auth_mode = 1,
    .svc_ident = "10.0.0.1:2040",
    .prefix_only = 1,
    .declared_content_length = 900000,
  };
  ai_gw_admit_result_t res;

  reset_stubs();
  assert(ai_gw_admit(&req, &res) == -1);
  assert(res.verdict == AI_GW_ADMIT_DENY);
  assert(res.stage == AI_GW_STAGE_AUTH);
  assert(res.http_status == 401);
  assert(strcmp(res.error_code, "invalid_api_key") == 0);
  assert(rl_stub.calls == 0 && rs_stub.calls == 0);
}

static void
test_svc_ident_format(void)
{
  char buf[64];
  struct in_addr a;

  assert(inet_pton(AF_INET, "10.10.10.254", &a) == 1);
  ai_gw_svc_ident(a.s_addr, htons(2040), buf, sizeof(buf));
  assert(strcmp(buf, "10.10.10.254:2040") == 0);

  /* Too-small buffer truncates but stays NUL-terminated. */
  char tiny[8];
  ai_gw_svc_ident(a.s_addr, htons(2040), tiny, sizeof(tiny));
  assert(tiny[sizeof(tiny) - 1] == '\0');
  assert(strncmp(tiny, "10.10.1", 7) == 0);
}

/* ---- refusal records and the request ID ---------------------------------- */

static void
test_allow_records_no_refusal(void)
{
  ai_gw_req_ctx_t req = {
    .api_key = "k",
    .body = body,
    .body_len = sizeof(body) - 1,
    .auth_mode = 1,
    .svc_ident = "10.0.0.1:2040",
    .request_id = "req-allow",
    .producer_id = 2,
  };
  ai_gw_admit_result_t res;

  reset_stubs();
  assert(ai_gw_admit(&req, &res) == 0);
  assert(res.verdict == AI_GW_ADMIT_ALLOW);
  assert(deny_stub.calls == 0);
}

static void
test_missing_credential_refusal_is_recorded_with_its_key(void)
{
  ai_gw_req_ctx_t req = {
    .api_key = "",
    .body = body,
    .body_len = sizeof(body) - 1,
    .auth_mode = 1,
    .svc_ident = "10.0.0.1:2040",
    .request_id = "req-401",
    .producer_id = 3,
    /* The gate runs before the header splice, so a refused request has its
     * peer but no derived origin — and "" says so rather than claiming the
     * peer, which is the distinction the hop count exists to keep. */
    .client_ip = "203.0.113.5",
    .origin_ip = "",
    .trusted_hops = 0,
  };
  ai_gw_admit_result_t res;

  reset_stubs();
  assert(ai_gw_admit(&req, &res) == -1);
  assert(res.verdict == AI_GW_ADMIT_DENY);
  assert(deny_stub.calls == 1);
  assert(strcmp(deny_stub.request_id, "req-401") == 0);
  /* The refusal carries where the request came from, through the same one
   * verdict frame every deny arm returns through. */
  assert(strcmp(deny_stub.client_ip, "203.0.113.5") == 0);
  assert(deny_stub.origin_ip[0] == '\0');
  assert(deny_stub.trusted_hops == 0);
  assert(deny_stub.producer_id == 3);
  assert(strcmp(deny_stub.svc, "10.0.0.1:2040") == 0);
  assert(strcmp(deny_stub.model, "m1") == 0);   /* named before refusing */
  assert(deny_stub.stage == AI_GW_STAGE_AUTH);
  assert(deny_stub.http_status == 401);
  assert(strcmp(deny_stub.error_code, "invalid_api_key") == 0);
  /* Refused before any identity resolved: nothing is invented. */
  assert(deny_stub.tenant[0] == '\0' && deny_stub.key[0] == '\0');
}

static void
test_model_refusal_keeps_the_tenant_it_validated(void)
{
  ai_gw_req_ctx_t req = {
    .api_key = "k",
    .body = body,
    .body_len = sizeof(body) - 1,
    .auth_mode = 1,
    .svc_ident = "10.0.0.1:2040",
    .request_id = "req-403",
    .producer_id = 1,
  };
  ai_gw_admit_result_t res;

  reset_stubs();
  validate_key_decision = 2;
  assert(ai_gw_admit(&req, &res) == -1);
  assert(res.verdict == AI_GW_ADMIT_DENY);
  assert(res.http_status == 403);
  assert(strcmp(res.error_code, "model_not_allowed") == 0);
  /* The credential validated: the refusal names who was refused. */
  assert(strcmp(res.tenant_id, "tenant-1") == 0);
  assert(strcmp(res.key_id, "key-1") == 0);
  assert(deny_stub.calls == 1);
  assert(strcmp(deny_stub.tenant, "tenant-1") == 0);
  assert(strcmp(deny_stub.key, "key-1") == 0);
  assert(deny_stub.http_status == 403);
  assert(strcmp(deny_stub.request_id, "req-403") == 0);
}

static void
test_rate_limit_refusal_is_recorded_after_identity(void)
{
  ai_gw_req_ctx_t req = {
    .api_key = "k",
    .body = body,
    .body_len = sizeof(body) - 1,
    .auth_mode = 1,
    .svc_ident = "10.0.0.1:2040",
    .request_id = "req-429",
    .producer_id = 0,
    /* This one arrived through two hops of ours, and the walk resolved it to
     * a client the chain named rather than to the peer. */
    .client_ip = "198.51.100.9",
    .origin_ip = "203.0.113.5",
    .trusted_hops = 2,
  };
  ai_gw_admit_result_t res;

  reset_stubs();
  rl_stub.rc = -1;
  rl_stub.decision = 3;
  assert(ai_gw_admit(&req, &res) == -1);
  assert(deny_stub.calls == 1);
  assert(deny_stub.stage == AI_GW_STAGE_RATELIMIT);
  assert(deny_stub.http_status == 429);
  assert(strcmp(deny_stub.tenant, "tenant-1") == 0);
  assert(strcmp(deny_stub.error_code, "rate_limit_exceeded") == 0);
  /* A different arm, the same attribution: it rides the verdict frame, so
   * an arm added to the decision cannot refuse a request unattributed. */
  assert(strcmp(deny_stub.client_ip, "198.51.100.9") == 0);
  assert(strcmp(deny_stub.origin_ip, "203.0.113.5") == 0);
  assert(deny_stub.trusted_hops == 2);
  assert(deny_stub.producer_id == 0);
  /* No binding was asked for: the record says a credential decided and
   * names none. */
  assert(deny_stub.auth_src == AI_GW_AUTH_SRC_CREDENTIAL);
  assert(deny_stub.net_identity[0] == '\0');
}

static void
test_keyless_bucket_refusal_is_recorded(void)
{
  ai_gw_req_ctx_t req = {
    .auth_mode = 0,
    .svc_ident = "10.0.0.1:2040",
    .request_id = "req-keyless",
    .producer_id = 1,
  };
  ai_gw_admit_result_t res;

  reset_stubs();
  rl_stub.rc = -1;
  rl_stub.decision = 3;
  assert(ai_gw_admit(&req, &res) == -1);
  assert(deny_stub.calls == 1);
  assert(deny_stub.stage == AI_GW_STAGE_RATELIMIT);
  assert(strcmp(deny_stub.request_id, "req-keyless") == 0);
  assert(deny_stub.tenant[0] == '\0');
}

static int
is_hex_lower(const char *s, size_t n)
{
  for (size_t i = 0; i < n; i++) {
    char c = s[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
      return 0;
  }
  return 1;
}

static void
test_minted_request_ids_are_unique_and_uuid_shaped(void)
{
  char a[AI_GW_REQUEST_ID_HEX + 1];
  char b[AI_GW_REQUEST_ID_HEX + 1];
  char c[8];

  ai_gw_mint_request_id(a, sizeof(a));
  ai_gw_mint_request_id(b, sizeof(b));
  assert(strlen(a) == AI_GW_REQUEST_ID_HEX);
  assert(strlen(b) == AI_GW_REQUEST_ID_HEX);
  assert(is_hex_lower(a, AI_GW_REQUEST_ID_HEX));
  assert(strcmp(a, b) != 0);
  /* Never the all-zero ID a zeroed generator would produce. */
  assert(strcmp(a, "00000000000040008000000000000000") != 0);
  /* UUID v4 shape: version nibble and variant nibble. */
  assert(a[12] == '4');
  assert(a[16] == '8' || a[16] == '9' || a[16] == 'a' || a[16] == 'b');
  /* A short buffer is truncated and still terminated. */
  ai_gw_mint_request_id(c, sizeof(c));
  assert(strlen(c) == sizeof(c) - 1);
}

/* ---- network identity: one case per row of the decision table ----------- */

#define NET_SVC "10.0.0.1:2040"
#define NET_SRC "10.20.0.7"

/* Row 1: a non-enforcing service, no binding of the source. Whether the
 * service has bindings for other sources or none at all, the request is the
 * keyless one it always was. */
static void
test_net_row1_no_binding_is_the_keyless_request(void)
{
  ai_gw_req_ctx_t req = {
    .body = body,
    .body_len = sizeof(body) - 1,
    .hdr_model = "m2",            /* disagrees with the body: not checked here */
    .auth_mode = 0,
    .svc_ident = NET_SVC,
    .client_ip = NET_SRC,
  };
  ai_gw_admit_result_t unbound, bound;

  /* The service has no binding: the resolver is not called and the body is
   * not read. */
  reset_stubs();
  assert(ai_gw_admit(&req, &unbound) == 0);
  assert(unbound.verdict == AI_GW_ADMIT_UNMETERED);
  assert(nid_stub.calls == 0 && extract_model_calls == 0);
  assert(rl_stub.calls == 1 && rl_stub.tenant[0] == '\0');
  assert(rs_stub.calls == 0);

  /* The service has bindings, none for this source: asked once, and the
   * result is the same in every field. */
  req.netid_bound = 1;
  req.in_ifindex = 7;
  reset_stubs();
  assert(ai_gw_admit(&req, &bound) == 0);
  assert(nid_stub.calls == 1);
  assert(strcmp(nid_stub.client_ip, NET_SRC) == 0 && nid_stub.in_ifindex == 7);
  assert(strcmp(nid_stub.svc, NET_SVC) == 0 && strcmp(nid_stub.model, "m1") == 0);
  assert(memcmp(&unbound, &bound, sizeof(bound)) == 0);
  assert(rl_stub.calls == 1 && rl_stub.tenant[0] == '\0');
  assert(rs_stub.calls == 0 && deny_stub.calls == 0);

  /* The same for both declared non-enforcing values. */
  req.auth_mode = 2;
  reset_stubs();
  assert(ai_gw_admit(&req, &bound) == 0);
  assert(memcmp(&unbound, &bound, sizeof(bound)) == 0);

  /* No service identity: nothing can be bound, nothing is asked. */
  req.svc_ident = "";
  reset_stubs();
  assert(ai_gw_admit(&req, &bound) == 0);
  assert(bound.verdict == AI_GW_ADMIT_UNMETERED);
  assert(nid_stub.calls == 0 && rl_stub.calls == 0);
}

/* Row 2: a non-enforcing service and a binding of the source, advisory or
 * strict: admitted as the binding's tenant through the metered stages. */
static void
test_net_row2_binding_admits_as_its_tenant(void)
{
  ai_gw_req_ctx_t req = {
    .body = body,
    .body_len = sizeof(body) - 1,
    .auth_mode = 0,
    .svc_ident = NET_SVC,
    .client_ip = NET_SRC,
    .netid_bound = 1,
  };
  ai_gw_admit_result_t res;

  for (int strict = 0; strict <= 1; strict++) {
    reset_stubs();
    nid_bind("line-1-tenant", strict, 0);
    nid_stub.out.forward_identity = strict;
    assert(ai_gw_admit(&req, &res) == 0);
    assert(res.verdict == AI_GW_ADMIT_ALLOW);
    assert(res.auth_src == AI_GW_AUTH_SRC_NETWORK);
    assert(strcmp(res.net_identity, "line-1") == 0);
    assert(res.net_forward_identity == strict);
    assert(strcmp(res.tenant_id, "line-1-tenant") == 0);
    assert(res.key_id[0] == '\0' && res.user_id[0] == '\0');
    assert(res.auth_flags == 0);
    /* The model is resolved and handed back for routing, as on an
     * enforcing service. */
    assert(strcmp(res.effective_model, "m1") == 0);
    assert(validate_key_calls == 0 && validate_bearer_calls == 0);
    assert(nid_stub.calls == 1);

    /* Rate and quota are asked for the tenant, with no key and no user. */
    assert(rl_stub.calls == 1);
    assert(strcmp(rl_stub.tenant, "line-1-tenant") == 0);
    assert(rl_stub.key[0] == '\0' && rl_stub.user[0] == '\0');
    assert(strcmp(rl_stub.svc, NET_SVC) == 0 && strcmp(rl_stub.model, "m1") == 0);
    assert(rs_stub.calls == 1);
    assert(strcmp(rs_stub.tenant, "line-1-tenant") == 0);
    assert(rs_stub.key[0] == '\0' && rs_stub.user[0] == '\0');
    assert(rs_stub.prompt_est == 7 && rs_stub.max_tokens == 32);
    assert(res.res_epoch == 77 && res.reserved_toks == 39);
    assert(deny_stub.calls == 0);
  }

  /* A key the client sends to a non-enforcing service decides nothing, as
   * before: the binding still names the tenant. */
  req.api_key = "sk-abc";
  reset_stubs();
  nid_bind("line-1-tenant", 0, 0);
  assert(ai_gw_admit(&req, &res) == 0);
  assert(res.verdict == AI_GW_ADMIT_ALLOW && res.auth_src == AI_GW_AUTH_SRC_NETWORK);
  assert(validate_key_calls == 0);
}

/* Row 2, the stages in order: conflict 400, the binding's allowlist 403,
 * rate 429 / 503, reservation 429. Each refusal names the tenant and is
 * recorded once. */
static void
test_net_row2_stages_refuse_in_order(void)
{
  ai_gw_req_ctx_t req = {
    .body = body,
    .body_len = sizeof(body) - 1,
    .hdr_model = "m2",
    .auth_mode = 0,
    .svc_ident = NET_SVC,
    .client_ip = NET_SRC,
    .netid_bound = 1,
    .request_id = "req-net",
  };
  ai_gw_admit_result_t res;

  /* Conflict first, even where the allowlist would refuse too: a keyless
   * service that steered silently on a header now answers 400 for a bound
   * source. */
  reset_stubs();
  nid_bind("line-1-tenant", 0, 0);
  nid_stub.out.model_ok = 0;
  assert(ai_gw_admit(&req, &res) == -1);
  assert(res.verdict == AI_GW_ADMIT_DENY && res.http_status == 400);
  assert(res.stage == AI_GW_STAGE_CONFLICT);
  assert(strcmp(res.error_code, "model_conflict") == 0);
  assert(strcmp(res.tenant_id, "line-1-tenant") == 0);
  assert(res.auth_src == AI_GW_AUTH_SRC_NETWORK);
  assert(strcmp(res.net_identity, "line-1") == 0);
  assert(rl_stub.calls == 0 && rs_stub.calls == 0);
  assert(deny_stub.calls == 1 && deny_stub.http_status == 400);
  assert(strcmp(deny_stub.tenant, "line-1-tenant") == 0);
  assert(strcmp(deny_stub.model, "m1") == 0);
  /* The record says the network decided the tenant, and by which binding. */
  assert(deny_stub.auth_src == AI_GW_AUTH_SRC_NETWORK);
  assert(strcmp(deny_stub.net_identity, "line-1") == 0);

  /* The allowlist, before any budget is touched. */
  req.hdr_model = "";
  reset_stubs();
  nid_bind("line-1-tenant", 0, 0);
  nid_stub.out.model_ok = 0;
  assert(ai_gw_admit(&req, &res) == -1);
  assert(res.http_status == 403 && res.stage == AI_GW_STAGE_AUTH);
  assert(strcmp(res.error_code, "model_not_allowed") == 0);
  assert(strcmp(res.tenant_id, "line-1-tenant") == 0);
  assert(rl_stub.calls == 0 && rs_stub.calls == 0);
  assert(deny_stub.calls == 1 && deny_stub.key[0] == '\0');

  /* Rate. */
  reset_stubs();
  nid_bind("line-1-tenant", 0, 0);
  rl_stub.rc = -1;
  rl_stub.decision = 3;
  assert(ai_gw_admit(&req, &res) == -1);
  assert(res.http_status == 429 && res.stage == AI_GW_STAGE_RATELIMIT);
  assert(res.retry_body == 1 && res.retry_after == 2);
  assert(strcmp(res.tenant_id, "line-1-tenant") == 0);
  assert(rs_stub.calls == 0 && deny_stub.calls == 1);

  /* The stage's store-loss guard is the gateway's outage, not "slow down". */
  reset_stubs();
  nid_bind("line-1-tenant", 0, 0);
  rl_stub.rc = -1;
  rl_stub.decision = 4;
  assert(ai_gw_admit(&req, &res) == -1);
  assert(res.http_status == 503);

  /* Reservation. */
  reset_stubs();
  nid_bind("line-1-tenant", 0, 0);
  rs_stub.rc = -1;
  assert(ai_gw_admit(&req, &res) == -1);
  assert(res.http_status == 429 && res.stage == AI_GW_STAGE_RESERVE);
  assert(strcmp(res.error_code, "token_quota_would_exceed") == 0);
  assert(res.reserved_toks == 39);
  assert(deny_stub.calls == 1);
  assert(strcmp(deny_stub.tenant, "line-1-tenant") == 0);
  assert(deny_stub.auth_src == AI_GW_AUTH_SRC_NETWORK);
  assert(strcmp(deny_stub.net_identity, "line-1") == 0);
}

/* Row 3: an enforcing service, a credential, no binding of the source: the
 * credential decides, with or without bindings on the service. */
static void
test_net_row3_credential_without_binding_is_unchanged(void)
{
  ai_gw_req_ctx_t req = {
    .api_key = "sk-abc",
    .body = body,
    .body_len = sizeof(body) - 1,
    .auth_mode = 1,
    .svc_ident = NET_SVC,
    .client_ip = NET_SRC,
  };
  ai_gw_admit_result_t unbound, bound;

  reset_stubs();
  assert(ai_gw_admit(&req, &unbound) == 0);
  assert(unbound.verdict == AI_GW_ADMIT_ALLOW);
  assert(nid_stub.calls == 0);

  req.netid_bound = 1;
  reset_stubs();
  assert(ai_gw_admit(&req, &bound) == 0);
  assert(nid_stub.calls == 1);
  assert(memcmp(&unbound, &bound, sizeof(bound)) == 0);
  assert(bound.auth_src == AI_GW_AUTH_SRC_CREDENTIAL && bound.net_identity[0] == '\0');
  assert(strcmp(rl_stub.key, "key-1") == 0 && strcmp(rl_stub.tenant, "tenant-1") == 0);
}

/* Row 4: a credential and an advisory binding: the credential decides and
 * the binding is noted, whatever tenant or allowlist it has. */
static void
test_net_row4_advisory_binding_is_noted_only(void)
{
  ai_gw_req_ctx_t req = {
    .api_key = "sk-abc",
    .body = body,
    .body_len = sizeof(body) - 1,
    .auth_mode = 1,
    .svc_ident = NET_SVC,
    .client_ip = NET_SRC,
    .netid_bound = 1,
  };
  ai_gw_admit_result_t res;

  reset_stubs();
  nid_bind("another-tenant", 0, 1);
  nid_stub.out.model_ok = 0;
  assert(ai_gw_admit(&req, &res) == 0);
  assert(res.verdict == AI_GW_ADMIT_ALLOW);
  assert(res.auth_src == AI_GW_AUTH_SRC_CREDENTIAL);
  assert(strcmp(res.net_identity, "line-1") == 0);
  assert(strcmp(res.tenant_id, "tenant-1") == 0 && strcmp(res.key_id, "key-1") == 0);
  assert(validate_key_calls == 1 && nid_stub.calls == 1);
  assert(strcmp(rl_stub.tenant, "tenant-1") == 0 && strcmp(rl_stub.key, "key-1") == 0);
  assert(strcmp(rs_stub.tenant, "tenant-1") == 0);
  assert(deny_stub.calls == 0);
}

/* Row 5: a credential and a strict binding. Another tenant's credential is
 * refused 403; the binding's own tenant passes, and then the binding's
 * allowlist counts beside the credential's. */
static void
test_net_row5_strict_binding_holds_the_credential(void)
{
  ai_gw_req_ctx_t req = {
    .api_key = "sk-abc",
    .body = body,
    .body_len = sizeof(body) - 1,
    .auth_mode = 1,
    .svc_ident = NET_SVC,
    .client_ip = NET_SRC,
    .netid_bound = 1,
    .request_id = "req-strict",
  };
  ai_gw_admit_result_t res;

  /* Tenant differs. */
  reset_stubs();
  nid_bind("another-tenant", 1, 0);
  assert(ai_gw_admit(&req, &res) == -1);
  assert(res.verdict == AI_GW_ADMIT_DENY && res.http_status == 403);
  assert(res.stage == AI_GW_STAGE_AUTH);
  assert(strcmp(res.error_code, "network_tenant_mismatch") == 0);
  /* Attributed to the credential that was presented, with the binding it
   * was held to. */
  assert(strcmp(res.tenant_id, "tenant-1") == 0 && strcmp(res.key_id, "key-1") == 0);
  assert(strcmp(res.net_identity, "line-1") == 0);
  assert(res.auth_src == AI_GW_AUTH_SRC_CREDENTIAL);
  assert(rl_stub.calls == 0 && rs_stub.calls == 0);
  assert(deny_stub.calls == 1);
  assert(strcmp(deny_stub.error_code, "network_tenant_mismatch") == 0);
  assert(strcmp(deny_stub.tenant, "tenant-1") == 0 && strcmp(deny_stub.key, "key-1") == 0);
  /* On the record: the credential's tenant, decided by the credential, and
   * the binding that refused it. */
  assert(deny_stub.auth_src == AI_GW_AUTH_SRC_CREDENTIAL);
  assert(strcmp(deny_stub.net_identity, "line-1") == 0);

  /* Tenant equal, model in both allowlists. */
  reset_stubs();
  nid_bind("tenant-1", 1, 0);
  assert(ai_gw_admit(&req, &res) == 0);
  assert(res.verdict == AI_GW_ADMIT_ALLOW);
  assert(res.auth_src == AI_GW_AUTH_SRC_CREDENTIAL);
  assert(strcmp(res.net_identity, "line-1") == 0);
  assert(strcmp(rl_stub.key, "key-1") == 0);
  assert(rs_stub.calls == 1);

  /* Tenant equal, model outside the binding's allowlist. */
  reset_stubs();
  nid_bind("tenant-1", 1, 0);
  nid_stub.out.model_ok = 0;
  assert(ai_gw_admit(&req, &res) == -1);
  assert(res.http_status == 403);
  assert(strcmp(res.error_code, "model_not_allowed") == 0);
  assert(strcmp(res.tenant_id, "tenant-1") == 0);
  assert(rl_stub.calls == 0 && deny_stub.calls == 1);
  assert(strcmp(deny_stub.net_identity, "line-1") == 0);

  /* Tenant equal, model outside the credential's own allowlist: the
   * credential's refusal, before the binding is looked at. */
  reset_stubs();
  nid_bind("tenant-1", 1, 0);
  validate_key_decision = 2;
  assert(ai_gw_admit(&req, &res) == -1);
  assert(res.http_status == 403);
  assert(strcmp(res.error_code, "model_not_allowed") == 0);
  assert(nid_stub.calls == 0);

  /* The JWT arm is held the same way. */
  req.api_key = "";
  req.bearer = "Bearer tok";
  req.auth_mode = 3;
  reset_stubs();
  nid_bind("another-tenant", 1, 0);
  assert(ai_gw_admit(&req, &res) == -1);
  assert(strcmp(res.error_code, "network_tenant_mismatch") == 0);
  assert(strcmp(res.user_id, "alice") == 0);
  /* The token validated before the binding refused it. */
  assert(deny_stub.auth_src == AI_GW_AUTH_SRC_BEARER);
  assert(strcmp(deny_stub.net_identity, "line-1") == 0);
}

/* Row 6: an enforcing service, no credential, and a binding that stands in
 * for one: admitted as the binding's tenant, on every enforcing mode. */
static void
test_net_row6_credential_network_admits_without_a_credential(void)
{
  ai_gw_req_ctx_t req = {
    .body = body,
    .body_len = sizeof(body) - 1,
    .svc_ident = NET_SVC,
    .client_ip = NET_SRC,
    .netid_bound = 1,
  };
  ai_gw_admit_result_t res;
  /* 9 is no declared mode: it enforces the API-key arm, fail-closed. */
  static const int modes[] = { 1, 3, 4, 9 };

  for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
    req.auth_mode = modes[i];
    reset_stubs();
    nid_bind("line-1-tenant", 1, 1);
    assert(ai_gw_admit(&req, &res) == 0);
    assert(res.verdict == AI_GW_ADMIT_ALLOW);
    assert(res.auth_src == AI_GW_AUTH_SRC_NETWORK);
    assert(strcmp(res.tenant_id, "line-1-tenant") == 0);
    assert(res.key_id[0] == '\0' && res.user_id[0] == '\0');
    assert(strcmp(res.effective_model, "m1") == 0);
    assert(validate_key_calls == 0 && validate_bearer_calls == 0);
    assert(nid_stub.calls == 1);
    assert(rl_stub.calls == 1 && strcmp(rl_stub.tenant, "line-1-tenant") == 0);
    assert(rs_stub.calls == 1 && deny_stub.calls == 0);
  }

  /* An Authorization value that is not a bearer token (the session-affinity
   * extractor's Basic) is not a credential here, as on the JWT arm. */
  req.auth_mode = 3;
  req.bearer = "Basic dXNlcjpwdw==";
  reset_stubs();
  nid_bind("line-1-tenant", 1, 1);
  assert(ai_gw_admit(&req, &res) == 0);
  assert(res.auth_src == AI_GW_AUTH_SRC_NETWORK);

  /* The same stages as row 2: the conflict rule and the allowlist apply. */
  req.bearer = "";
  req.hdr_model = "m2";
  reset_stubs();
  nid_bind("line-1-tenant", 1, 1);
  assert(ai_gw_admit(&req, &res) == -1);
  assert(res.http_status == 400 && strcmp(res.error_code, "model_conflict") == 0);
  req.hdr_model = "";
  reset_stubs();
  nid_bind("line-1-tenant", 1, 1);
  nid_stub.out.model_ok = 0;
  assert(ai_gw_admit(&req, &res) == -1);
  assert(res.http_status == 403 && strcmp(res.error_code, "model_not_allowed") == 0);
}

/* Row 7: an enforcing service, no credential, and anything short of a
 * credential-bearing binding: the missing-credential 401, as before. */
static void
test_net_row7_no_credential_otherwise_is_401(void)
{
  ai_gw_req_ctx_t req = {
    .body = body,
    .body_len = sizeof(body) - 1,
    .auth_mode = 1,
    .svc_ident = NET_SVC,
    .client_ip = NET_SRC,
    .request_id = "req-401-net",
  };
  ai_gw_admit_result_t unbound, res;

  reset_stubs();
  assert(ai_gw_admit(&req, &unbound) == -1);
  assert(unbound.http_status == 401 && nid_stub.calls == 0);

  /* No binding of the source. */
  req.netid_bound = 1;
  reset_stubs();
  assert(ai_gw_admit(&req, &res) == -1);
  assert(nid_stub.calls == 1);
  assert(memcmp(&unbound, &res, sizeof(res)) == 0);
  assert(deny_stub.calls == 1 && deny_stub.http_status == 401);
  assert(deny_stub.tenant[0] == '\0');

  /* A binding that does not stand in for a credential, advisory or strict:
   * still 401, and the tenant it names is not put on the refusal. */
  for (int strict = 0; strict <= 1; strict++) {
    reset_stubs();
    nid_bind("line-1-tenant", strict, 0);
    assert(ai_gw_admit(&req, &res) == -1);
    assert(res.http_status == 401);
    assert(strcmp(res.error_code, "invalid_api_key") == 0);
    assert(res.tenant_id[0] == '\0' && res.auth_src == AI_GW_AUTH_SRC_CREDENTIAL);
    assert(nid_stub.calls == 1 && validate_key_calls == 1);
    assert(rl_stub.calls == 0 && rs_stub.calls == 0);
  }
}

/* A request that presents a credential is decided by that credential. A
 * refused one never falls back to a credential-bearing binding, and a
 * presented one is never replaced by it. */
static void
test_net_presented_credential_never_falls_back(void)
{
  ai_gw_req_ctx_t req = {
    .api_key = "sk-abc",
    .body = body,
    .body_len = sizeof(body) - 1,
    .auth_mode = 1,
    .svc_ident = NET_SVC,
    .client_ip = NET_SRC,
    .netid_bound = 1,
  };
  ai_gw_admit_result_t res;

  /* A key the store refuses (the 401 shape, decision 1). */
  reset_stubs();
  nid_bind("line-1-tenant", 0, 1);
  validate_key_decision = 1;
  assert(ai_gw_admit(&req, &res) == -1);
  assert(res.http_status == 401);
  assert(nid_stub.calls == 0);            /* not even asked */
  assert(rl_stub.calls == 0 && rs_stub.calls == 0);

  /* The policy store cannot answer: 503, not an admission by network. */
  reset_stubs();
  nid_bind("line-1-tenant", 0, 1);
  validate_key_decision = 4;
  assert(ai_gw_admit(&req, &res) == -1);
  assert(res.http_status == 503 && nid_stub.calls == 0);

  /* A valid key from a credential-bearing advisory binding's source: the
   * key's tenant, not the binding's. */
  reset_stubs();
  nid_bind("line-1-tenant", 0, 1);
  assert(ai_gw_admit(&req, &res) == 0);
  assert(strcmp(res.tenant_id, "tenant-1") == 0);
  assert(res.auth_src == AI_GW_AUTH_SRC_CREDENTIAL);

  /* A bearer token on an API-key service is a presented credential too:
   * the key arm answers its missing key. */
  req.api_key = "";
  req.bearer = "Bearer tok";
  reset_stubs();
  nid_bind("line-1-tenant", 0, 1);
  assert(ai_gw_admit(&req, &res) == -1);
  assert(res.http_status == 401 && nid_stub.calls == 0);

  /* A token dropped for its size was presented. */
  req.bearer = "";
  req.bearer_oversize = 1;
  req.auth_mode = 3;
  reset_stubs();
  nid_bind("line-1-tenant", 0, 1);
  assert(ai_gw_admit(&req, &res) == -1);
  assert(res.http_status == 401 && nid_stub.calls == 0);
  assert(validate_bearer_calls == 1);
}

/* A resolver that cannot answer, or answers something that is not a clean
 * match, is "no binding": it never admits, and never refuses what was
 * admitted without it. */
static void
test_net_resolver_failure_is_no_binding(void)
{
  ai_gw_req_ctx_t req = {
    .body = body,
    .body_len = sizeof(body) - 1,
    .svc_ident = NET_SVC,
    .client_ip = NET_SRC,
    .netid_bound = 1,
  };
  ai_gw_admit_result_t res;

  for (int shape = 0; shape < 3; shape++) {
    /* 0: the call fails with a full match written; 1: it succeeds with the
     * match flag clear; 2: a match that names no tenant. */
    for (int mode = 0; mode <= 1; mode++) {
      req.auth_mode = mode;
      req.api_key = "";
      reset_stubs();
      nid_bind("line-1-tenant", 1, 1);
      if (shape == 0)
        nid_stub.rc = -1;
      else if (shape == 1)
        nid_stub.out.matched = 0;
      else
        nid_stub.out.tenant_id[0] = '\0';

      if (mode == 0) {
        assert(ai_gw_admit(&req, &res) == 0);
        assert(res.verdict == AI_GW_ADMIT_UNMETERED);
        assert(res.tenant_id[0] == '\0' && res.net_identity[0] == '\0');
        assert(res.effective_model[0] == '\0');
        assert(rs_stub.calls == 0);
      } else {
        assert(ai_gw_admit(&req, &res) == -1);
        assert(res.http_status == 401);
        assert(res.tenant_id[0] == '\0' && res.net_identity[0] == '\0');
        assert(rl_stub.calls == 0 && rs_stub.calls == 0);

        /* With a valid key the failure changes nothing either: a strict
         * binding that could not be read does not refuse the credential. */
        req.api_key = "sk-abc";
        reset_stubs();
        nid_bind("another-tenant", 1, 0);
        nid_stub.rc = shape == 0 ? -1 : 0;
        if (shape == 1)
          nid_stub.out.matched = 0;
        else if (shape == 2)
          nid_stub.out.tenant_id[0] = '\0';
        assert(ai_gw_admit(&req, &res) == 0);
        assert(res.verdict == AI_GW_ADMIT_ALLOW);
        assert(strcmp(res.tenant_id, "tenant-1") == 0 && res.net_identity[0] == '\0');
      }
    }
  }

  /* A resolver that fills its strings to the last byte cannot run the gate
   * off the end of them. */
  req.auth_mode = 0;
  req.api_key = "";
  reset_stubs();
  nid_bind("x", 0, 0);
  memset(nid_stub.out.tenant_id, 'T', sizeof(nid_stub.out.tenant_id));
  memset(nid_stub.out.binding, 'B', sizeof(nid_stub.out.binding));
  assert(ai_gw_admit(&req, &res) == 0);
  assert(strlen(res.tenant_id) == sizeof(res.tenant_id) - 1);
  assert(strlen(res.net_identity) == sizeof(res.net_identity) - 1);
}

/* A service that asked to fail closed refuses, with 503, every request the
 * resolver would have decided while it cannot answer. Nothing else moves:
 * an answer, match or not, is decided as on any other service, and a
 * credential's own refusal still comes first. */
static void
test_net_resolver_failure_fails_closed_where_asked(void)
{
  ai_gw_req_ctx_t req = {
    .body = body,
    .body_len = sizeof(body) - 1,
    .svc_ident = NET_SVC,
    .client_ip = NET_SRC,
    .netid_bound = AI_GW_NETID_BOUND | AI_GW_NETID_FAIL_CLOSED,
  };
  ai_gw_admit_result_t res;

  for (int shape = 0; shape < 2; shape++) {
    /* 0: the call fails; 1: a match that names no tenant. */
    for (int mode = 0; mode <= 1; mode++) {
      /* No credential: a non-enforcing service, then an enforcing one. */
      req.auth_mode = mode;
      req.api_key = "";
      reset_stubs();
      nid_bind("line-1-tenant", 1, 1);
      if (shape == 0)
        nid_stub.rc = -1;
      else
        nid_stub.out.tenant_id[0] = '\0';
      assert(ai_gw_admit(&req, &res) == -1);
      assert(res.verdict == AI_GW_ADMIT_DENY && res.stage == AI_GW_STAGE_AUTH);
      assert(res.http_status == 503 && res.retry_after == 5);
      assert(strcmp(res.error_code, "netid_unavailable") == 0);
      assert(res.tenant_id[0] == '\0' && res.net_identity[0] == '\0');
      assert(res.auth_src == AI_GW_AUTH_SRC_CREDENTIAL);
      assert(nid_stub.calls == 1 && validate_key_calls == 0);
      assert(rl_stub.calls == 0 && rs_stub.calls == 0);
      assert(deny_stub.calls == 1 && deny_stub.http_status == 503);
      assert(strcmp(deny_stub.error_code, "netid_unavailable") == 0);
      /* The resolver did not answer: the record names no binding. */
      assert(deny_stub.net_identity[0] == '\0');
      assert(deny_stub.auth_src == AI_GW_AUTH_SRC_CREDENTIAL);
    }

    /* A valid key: refused as well, and the refusal names the key's
     * tenant. The resolver is asked once. */
    req.auth_mode = 1;
    req.api_key = "sk-abc";
    reset_stubs();
    nid_bind("tenant-1", 1, 0);
    if (shape == 0)
      nid_stub.rc = -1;
    else
      nid_stub.out.tenant_id[0] = '\0';
    assert(ai_gw_admit(&req, &res) == -1);
    assert(res.http_status == 503);
    assert(strcmp(res.error_code, "netid_unavailable") == 0);
    assert(strcmp(res.tenant_id, "tenant-1") == 0);
    assert(nid_stub.calls == 1);
    assert(rl_stub.calls == 0 && rs_stub.calls == 0);

    /* An invalid key is refused by its validator first, as on any service:
     * the resolver is not reached. */
    reset_stubs();
    validate_key_decision = 1;
    nid_stub.rc = -1;
    assert(ai_gw_admit(&req, &res) == -1);
    assert(res.http_status == 401);
    assert(nid_stub.calls == 0);
  }

  /* The resolver answers: no binding is no binding, and a binding is a
   * binding. The flag changes neither. */
  req.auth_mode = 0;
  req.api_key = "";
  reset_stubs();
  assert(ai_gw_admit(&req, &res) == 0);
  assert(res.verdict == AI_GW_ADMIT_UNMETERED);
  req.auth_mode = 1;
  reset_stubs();
  assert(ai_gw_admit(&req, &res) == -1);
  assert(res.http_status == 401);
  req.api_key = "sk-abc";
  reset_stubs();
  assert(ai_gw_admit(&req, &res) == 0);
  assert(res.verdict == AI_GW_ADMIT_ALLOW && res.net_identity[0] == '\0');
  req.auth_mode = 0;
  req.api_key = "";
  reset_stubs();
  nid_bind("line-1-tenant", 0, 0);
  assert(ai_gw_admit(&req, &res) == 0);
  assert(res.verdict == AI_GW_ADMIT_ALLOW);
  assert(strcmp(res.tenant_id, "line-1-tenant") == 0);
}

/* The capacity gate refuses after the policy gate admitted, through its own
 * frame: the record carries what the policy gate resolved, the binding
 * included, and a NULL binding reads as none. */
static void
test_capacity_deny_carries_the_binding(void)
{
  reset_stubs();
  ai_gw_record_capacity_deny("req-cap", 3, NET_SVC, "m1", "line-1-tenant",
                             "", "", 429, "admission_capacity", NET_SRC, "",
                             0, AI_GW_AUTH_SRC_NETWORK, "line-1", -1,
                             AI_GW_CLASSF_SET | AI_GW_CLASS_SHEDDABLE, "tier:flex");
  assert(deny_stub.calls == 1 && deny_stub.stage == AI_GW_STAGE_CAPACITY);
  assert(deny_stub.http_status == 429);
  assert(strcmp(deny_stub.tenant, "line-1-tenant") == 0);
  assert(deny_stub.auth_src == AI_GW_AUTH_SRC_NETWORK);
  assert(strcmp(deny_stub.net_identity, "line-1") == 0);
  /* the class the request was admitted with, as its completion would say */
  assert(deny_stub.priority == -1 &&
         deny_stub.class_info == (AI_GW_CLASSF_SET | AI_GW_CLASS_SHEDDABLE) &&
         strcmp(deny_stub.objective, "tier:flex") == 0);

  reset_stubs();
  ai_gw_record_capacity_deny("req-cap", 3, NET_SVC, "m1", "tenant-1", "key-1",
                             "", 503, "admission_no_capacity", NET_SRC, "",
                             0, AI_GW_AUTH_SRC_CREDENTIAL, NULL, 0, 0, NULL);
  assert(deny_stub.calls == 1 && deny_stub.auth_src == AI_GW_AUTH_SRC_CREDENTIAL);
  assert(deny_stub.net_identity[0] == '\0');
  assert(deny_stub.class_info == 0 && deny_stub.objective[0] == '\0');
}

/* A streamed body: the gate has only the prefix, and the network path
 * sizes its claim from the declared length as the credential path does. */
static void
test_net_streamed_body_is_gated_on_the_prefix(void)
{
  ai_gw_req_ctx_t req = {
    .prefix_model = "m9",
    .prefix_only = 1,
    .declared_content_length = 4000,
    .auth_mode = 0,
    .svc_ident = NET_SVC,
    .client_ip = NET_SRC,
    .netid_bound = 1,
  };
  ai_gw_admit_result_t res;

  reset_stubs();
  nid_bind("line-1-tenant", 0, 0);
  assert(ai_gw_admit(&req, &res) == 0);
  assert(res.verdict == AI_GW_ADMIT_ALLOW);
  assert(extract_model_calls == 0);
  assert(strcmp(nid_stub.model, "m9") == 0);
  assert(strcmp(res.effective_model, "m9") == 0);
  assert(rs_stub.calls == 1 && rs_stub.prompt_est == 1000);
}

/* The set of bound services: what callers put in netid_bound. */
static void
test_netid_bound_set(void)
{
  static char names[AI_GW_NETID_SVC_MAX + 1][24];
  static const char *ptrs[AI_GW_NETID_SVC_MAX + 1];
  const char *two[] = { "10.0.0.1:2040", "10.0.0.2:8080" };
  const char *junk[] = { NULL, "", "10.0.0.3:1" };

  /* Nothing published: nothing is bound. */
  assert(ai_gw_netid_bound("10.0.0.1:2040") == 0);
  assert(ai_gw_netid_bound("") == 0 && ai_gw_netid_bound(NULL) == 0);

  ai_gw_netid_bound_set(two, NULL, 2, 0);
  assert(ai_gw_netid_bound("10.0.0.1:2040") == 1);
  assert(ai_gw_netid_bound("10.0.0.2:8080") == 1);
  assert(ai_gw_netid_bound("10.0.0.1:2041") == 0);
  assert(ai_gw_netid_bound("10.0.0.1") == 0);
  assert(ai_gw_netid_bound("") == 0);

  /* A replacement is the whole set, not an addition. */
  ai_gw_netid_bound_set(two + 1, NULL, 1, 0);
  assert(ai_gw_netid_bound("10.0.0.1:2040") == 0);
  assert(ai_gw_netid_bound("10.0.0.2:8080") == 1);

  /* Empty names are skipped. */
  ai_gw_netid_bound_set(junk, NULL, 3, 0);
  assert(ai_gw_netid_bound("10.0.0.3:1") == 1);
  assert(ai_gw_netid_bound("10.0.0.2:8080") == 0);

  /* A binding that names no service binds every service that has an
   * identity. */
  ai_gw_netid_bound_set(NULL, NULL, 0, 1);
  assert(ai_gw_netid_bound("192.0.2.9:1") == 1);
  assert(ai_gw_netid_bound("") == 0);

  /* The full set, every member found. */
  for (int i = 0; i <= AI_GW_NETID_SVC_MAX; i++) {
    snprintf(names[i], sizeof(names[i]), "10.%d.%d.1:%d", i / 256, i % 256,
             1000 + i);
    ptrs[i] = names[i];
  }
  ai_gw_netid_bound_set(ptrs, NULL, AI_GW_NETID_SVC_MAX, 0);
  for (int i = 0; i < AI_GW_NETID_SVC_MAX; i++)
    assert(ai_gw_netid_bound(names[i]) == 1);
  assert(ai_gw_netid_bound(names[AI_GW_NETID_SVC_MAX]) == 0);

  /* One more than it holds: no service may be missed, so all are bound. */
  ai_gw_netid_bound_set(ptrs, NULL, AI_GW_NETID_SVC_MAX + 1, 0);
  assert(ai_gw_netid_bound(names[AI_GW_NETID_SVC_MAX]) == 1);
  assert(ai_gw_netid_bound("192.0.2.9:1") == 1);

  /* And back to nothing. */
  ai_gw_netid_bound_set(NULL, NULL, 0, 0);
  assert(ai_gw_netid_bound("10.0.0.1:2040") == 0);
  assert(ai_gw_netid_bound(names[0]) == 0);
}

/* A service can ask to fail closed: the flag travels with its entry. */
static void
test_netid_bound_set_carries_fail_closed(void)
{
  static char names[AI_GW_NETID_SVC_MAX + 2][24];
  static const char *ptrs[AI_GW_NETID_SVC_MAX + 2];
  static uint8_t fl[AI_GW_NETID_SVC_MAX + 2];
  const char *three[] = { "10.0.0.1:2040", "10.0.0.2:8080", "10.0.0.2:8080" };
  const uint8_t one_closed[] = { AI_GW_NETID_FAIL_CLOSED, 0, 0 };
  const uint8_t dup_closed[] = { 0, 0, AI_GW_NETID_FAIL_CLOSED };
  const int both = AI_GW_NETID_BOUND | AI_GW_NETID_FAIL_CLOSED;

  ai_gw_netid_bound_set(three, one_closed, 2, 0);
  assert(ai_gw_netid_bound("10.0.0.1:2040") == both);
  assert(ai_gw_netid_bound("10.0.0.2:8080") == AI_GW_NETID_BOUND);
  assert(ai_gw_netid_bound("10.0.0.3:1") == 0);

  /* A service named twice fails closed when either entry asks. */
  ai_gw_netid_bound_set(three, dup_closed, 3, 0);
  assert(ai_gw_netid_bound("10.0.0.1:2040") == AI_GW_NETID_BOUND);
  assert(ai_gw_netid_bound("10.0.0.2:8080") == both);

  /* The next set carries no flag: none is left behind, in either table. */
  ai_gw_netid_bound_set(three, NULL, 2, 0);
  assert(ai_gw_netid_bound("10.0.0.1:2040") == AI_GW_NETID_BOUND);
  assert(ai_gw_netid_bound("10.0.0.2:8080") == AI_GW_NETID_BOUND);
  ai_gw_netid_bound_set(three, NULL, 2, 0);
  assert(ai_gw_netid_bound("10.0.0.2:8080") == AI_GW_NETID_BOUND);

  /* Every service bound, one of them closed: that one only. */
  ai_gw_netid_bound_set(three, one_closed, 2, AI_GW_NETID_BOUND);
  assert(ai_gw_netid_bound("10.0.0.1:2040") == both);
  assert(ai_gw_netid_bound("10.0.0.2:8080") == AI_GW_NETID_BOUND);
  assert(ai_gw_netid_bound("192.0.2.9:1") == AI_GW_NETID_BOUND);

  /* Every service bound and closed. */
  ai_gw_netid_bound_set(NULL, NULL, 0, both);
  assert(ai_gw_netid_bound("192.0.2.9:1") == both);
  assert(ai_gw_netid_bound("") == 0);

  /* The closed flag alone binds nothing. */
  ai_gw_netid_bound_set(NULL, NULL, 0, AI_GW_NETID_FAIL_CLOSED);
  assert(ai_gw_netid_bound("192.0.2.9:1") == 0);

  /* Past capacity. The services that fit keep their own flag; one that did
   * not fit and is open leaves the others open ... */
  for (int i = 0; i < AI_GW_NETID_SVC_MAX + 2; i++) {
    snprintf(names[i], sizeof(names[i]), "10.%d.%d.1:%d", i / 256, i % 256,
             1000 + i);
    ptrs[i] = names[i];
    fl[i] = 0;
  }
  fl[5] = AI_GW_NETID_FAIL_CLOSED;
  ai_gw_netid_bound_set(ptrs, fl, AI_GW_NETID_SVC_MAX + 1, 0);
  assert(ai_gw_netid_bound(names[5]) == both);
  assert(ai_gw_netid_bound(names[6]) == AI_GW_NETID_BOUND);
  assert(ai_gw_netid_bound(names[AI_GW_NETID_SVC_MAX]) == AI_GW_NETID_BOUND);
  assert(ai_gw_netid_bound("192.0.2.9:1") == AI_GW_NETID_BOUND);
  /* ... and one that did not fit and is closed closes every service: it
   * cannot be told from the others any more. */
  fl[AI_GW_NETID_SVC_MAX + 1] = AI_GW_NETID_FAIL_CLOSED;
  ai_gw_netid_bound_set(ptrs, fl, AI_GW_NETID_SVC_MAX + 2, 0);
  assert(ai_gw_netid_bound(names[6]) == both);
  assert(ai_gw_netid_bound("192.0.2.9:1") == both);

  ai_gw_netid_bound_set(NULL, NULL, 0, 0);
  assert(ai_gw_netid_bound(names[5]) == 0);
}

/* A service can have a binding that forwards identity: the flag travels
 * with its entry as the fail-closed one does, the two are independent, and
 * one load answers "does any service forward at all". */
static void
test_netid_bound_set_carries_forward(void)
{
  static char names[AI_GW_NETID_SVC_MAX + 2][24];
  static const char *ptrs[AI_GW_NETID_SVC_MAX + 2];
  static uint8_t fl[AI_GW_NETID_SVC_MAX + 2];
  const char *three[] = { "10.0.0.1:2040", "10.0.0.2:8080", "10.0.0.3:9000" };
  const uint8_t mixed[] = { AI_GW_NETID_FWD, AI_GW_NETID_FAIL_CLOSED,
                            AI_GW_NETID_FWD | AI_GW_NETID_FAIL_CLOSED };
  const int b = AI_GW_NETID_BOUND;

  assert(ai_gw_netid_fwd_any() == 0);
  ai_gw_netid_bound_set(three, mixed, 3, 0);
  assert(ai_gw_netid_fwd_any() == 1);
  assert(ai_gw_netid_bound("10.0.0.1:2040") == (b | AI_GW_NETID_FWD));
  assert(ai_gw_netid_bound("10.0.0.2:8080") == (b | AI_GW_NETID_FAIL_CLOSED));
  assert(ai_gw_netid_bound("10.0.0.3:9000") ==
         (b | AI_GW_NETID_FWD | AI_GW_NETID_FAIL_CLOSED));
  assert(ai_gw_netid_bound("10.0.0.4:1") == 0);

  /* The next set carries no flag: none is left behind. */
  ai_gw_netid_bound_set(three, NULL, 3, 0);
  assert(ai_gw_netid_fwd_any() == 0);
  assert(ai_gw_netid_bound("10.0.0.1:2040") == b);

  /* Every service bound, one of them forwarding: that one only. */
  ai_gw_netid_bound_set(three, mixed, 1, AI_GW_NETID_BOUND);
  assert(ai_gw_netid_fwd_any() == 1);
  assert(ai_gw_netid_bound("10.0.0.1:2040") == (b | AI_GW_NETID_FWD));
  assert(ai_gw_netid_bound("192.0.2.9:1") == b);

  /* Every service forwards; one also fails closed. */
  ai_gw_netid_bound_set(three + 1, mixed + 1, 1,
                        AI_GW_NETID_BOUND | AI_GW_NETID_FWD);
  assert(ai_gw_netid_bound("192.0.2.9:1") == (b | AI_GW_NETID_FWD));
  assert(ai_gw_netid_bound("10.0.0.2:8080") ==
         (b | AI_GW_NETID_FWD | AI_GW_NETID_FAIL_CLOSED));

  /* The forward flag alone binds nothing. */
  ai_gw_netid_bound_set(NULL, NULL, 0, AI_GW_NETID_FWD);
  assert(ai_gw_netid_bound("192.0.2.9:1") == 0);
  assert(ai_gw_netid_fwd_any() == 0);

  /* Past capacity, a forwarding service that did not fit makes every
   * service forward: a client-sent identity header must not reach it. */
  for (int i = 0; i < AI_GW_NETID_SVC_MAX + 2; i++) {
    snprintf(names[i], sizeof(names[i]), "10.%d.%d.1:%d", i / 256, i % 256,
             1000 + i);
    ptrs[i] = names[i];
    fl[i] = 0;
  }
  ai_gw_netid_bound_set(ptrs, fl, AI_GW_NETID_SVC_MAX + 1, 0);
  assert(ai_gw_netid_bound("192.0.2.9:1") == b);
  fl[AI_GW_NETID_SVC_MAX + 1] = AI_GW_NETID_FWD;
  ai_gw_netid_bound_set(ptrs, fl, AI_GW_NETID_SVC_MAX + 2, 0);
  assert(ai_gw_netid_bound(names[6]) == (b | AI_GW_NETID_FWD));
  assert(ai_gw_netid_bound("192.0.2.9:1") == (b | AI_GW_NETID_FWD));

  ai_gw_netid_bound_set(NULL, NULL, 0, 0);
  assert(ai_gw_netid_bound(names[6]) == 0 && ai_gw_netid_fwd_any() == 0);
}

/* The interface-match switch: off until the control plane says a binding
 * matches on an interface, and any non-zero value is "on". */
static void
test_netid_ifmatch_switch(void)
{
  assert(ai_gw_netid_ifmatch() == 0);
  ai_gw_netid_ifmatch_set(1);
  assert(ai_gw_netid_ifmatch() == 1);
  ai_gw_netid_ifmatch_set(7);
  assert(ai_gw_netid_ifmatch() == 1);
  ai_gw_netid_ifmatch_set(0);
  assert(ai_gw_netid_ifmatch() == 0);
}

/* A service that also carries the forward flag is bound like any other:
 * the gate reads the bound bit, not the word. */
static void
test_net_forward_flag_does_not_change_the_decision(void)
{
  ai_gw_req_ctx_t req = {
    .body = body,
    .body_len = sizeof(body) - 1,
    .auth_mode = 0,
    .svc_ident = "10.0.0.1:2040",
    .netid_bound = AI_GW_NETID_BOUND | AI_GW_NETID_FWD,
    .client_ip = NET_SRC,
    .in_ifindex = 12,
  };
  ai_gw_admit_result_t res;

  reset_stubs();
  nid_bind("line-1-tenant", 0, 0);
  nid_stub.out.forward_identity = 1;
  assert(ai_gw_admit(&req, &res) == 0);
  assert(res.verdict == AI_GW_ADMIT_ALLOW);
  assert(nid_stub.calls == 1 && nid_stub.in_ifindex == 12);
  assert(res.auth_src == AI_GW_AUTH_SRC_NETWORK);
  assert(res.net_forward_identity == 1);
  assert(strcmp(res.tenant_id, "line-1-tenant") == 0);

  /* The forward flag without the bound bit asks nothing. */
  req.netid_bound = AI_GW_NETID_FWD;
  reset_stubs();
  nid_bind("line-1-tenant", 0, 0);
  assert(ai_gw_admit(&req, &res) == 0);
  assert(res.verdict == AI_GW_ADMIT_UNMETERED);
  assert(nid_stub.calls == 0 && res.net_forward_identity == 0);
}

/* The set is replaced whole while requests read it. A service in every
 * published set must read as bound through every replacement, and one in
 * none of them never: a reader may not see half of a replacement. */
static _Atomic int netid_race_stop;

static void *
netid_race_writer(void *arg)
{
  static char a[AI_GW_NETID_SVC_MAX / 2][24], b[AI_GW_NETID_SVC_MAX / 2][24];
  static const char *pa[AI_GW_NETID_SVC_MAX / 2], *pb[8];
  (void)arg;

  /* Two sets of different sizes and different members, sharing one. */
  for (int i = 0; i < AI_GW_NETID_SVC_MAX / 2; i++) {
    snprintf(a[i], sizeof(a[i]), "10.1.%d.1:%d", i % 250, 2000 + i);
    pa[i] = a[i];
  }
  for (int i = 0; i < 8; i++) {
    snprintf(b[i], sizeof(b[i]), "10.2.%d.1:%d", i, 3000 + i);
    pb[i] = b[i];
  }
  static uint8_t fa[AI_GW_NETID_SVC_MAX / 2], fb[8];
  pa[17] = "192.0.2.1:443";
  pb[3] = "192.0.2.1:443";
  pa[400] = "192.0.2.2:443";
  pb[6] = "192.0.2.2:443";
  fa[400] = AI_GW_NETID_FAIL_CLOSED;
  fb[6] = AI_GW_NETID_FAIL_CLOSED;
  for (int n = 0; n < 20000; n++) {
    ai_gw_netid_bound_set(pa, fa, AI_GW_NETID_SVC_MAX / 2, 0);
    ai_gw_netid_bound_set(pb, fb, 8, 0);
  }
  atomic_store(&netid_race_stop, 1);
  return NULL;
}

static void *
netid_race_reader(void *arg)
{
  long reads = 0;
  (void)arg;
  while (!atomic_load(&netid_race_stop)) {
    assert(ai_gw_netid_bound("192.0.2.1:443") == AI_GW_NETID_BOUND);
    assert(ai_gw_netid_bound("192.0.2.2:443") ==
           (AI_GW_NETID_BOUND | AI_GW_NETID_FAIL_CLOSED));
    assert(ai_gw_netid_bound("198.51.100.1:1") == 0);
    reads++;
  }
  return (void *)reads;
}

static void
test_netid_bound_set_is_replaced_under_readers(void)
{
  const char *first[] = { "192.0.2.1:443", "192.0.2.2:443" };
  const uint8_t first_fl[] = { 0, AI_GW_NETID_FAIL_CLOSED };
  pthread_t w, r[3];
  void *reads;

  ai_gw_netid_bound_set(first, first_fl, 2, 0);
  atomic_store(&netid_race_stop, 0);
  for (int i = 0; i < 3; i++)
    assert(pthread_create(&r[i], NULL, netid_race_reader, NULL) == 0);
  assert(pthread_create(&w, NULL, netid_race_writer, NULL) == 0);
  pthread_join(w, NULL);
  for (int i = 0; i < 3; i++) {
    pthread_join(r[i], &reads);
    assert((long)reads > 0);
  }
  ai_gw_netid_bound_set(NULL, NULL, 0, 0);
  assert(ai_gw_netid_bound("192.0.2.1:443") == 0);
}

/* ---- the class stage ----------------------------------------------------- */

static ai_gw_req_ctx_t
class_key_req(void)
{
  ai_gw_req_ctx_t req = {
    .api_key = "lxb_k",
    .body = body,
    .body_len = sizeof(body) - 1,
    .auth_mode = 1,
    .svc_ident = "10.0.0.1:2040",
    .class_on = 1,
  };
  return req;
}

static void
test_objective_strict_is_the_routed_rules(void)
{
  ai_gw_req_ctx_t req = class_key_req();
  ai_gw_admit_result_t res;
  int cookie;

  req.objective_hint = "not-mine";
  req.objective_strict_of = so_lookup;
  req.default_tokens_arg = &cookie;

  /* the routed rule is strict, the plain value is not: refused */
  req.objective_strict = 0;
  reset_stubs();
  memset(&so_stub, 0, sizeof(so_stub));
  so_stub.answer = 1;
  cls_stub.out.objective_denied = 1;
  assert(ai_gw_admit(&req, &res) != 0);
  assert(res.verdict == AI_GW_ADMIT_DENY && res.stage == AI_GW_STAGE_OBJECTIVE);
  assert(so_stub.calls == 1 && so_stub.arg == &cookie);
  assert(strcmp(so_stub.model, res.effective_model) == 0 && so_stub.model[0]);
  assert(rl_stub.calls == 0);

  /* the routed rule is not strict, the plain value is: served on the default */
  req.objective_strict = 1;
  reset_stubs();
  memset(&so_stub, 0, sizeof(so_stub));
  so_stub.answer = 0;
  cls_stub.out.objective_denied = 1;
  assert(ai_gw_admit(&req, &res) == 0);
  assert(res.verdict == AI_GW_ADMIT_ALLOW && res.objective_denied == 1);
  assert(so_stub.calls == 1);

  /* an objective that is allowed never asks the rule */
  reset_stubs();
  memset(&so_stub, 0, sizeof(so_stub));
  so_stub.answer = 1;
  assert(ai_gw_admit(&req, &res) == 0);
  assert(res.verdict == AI_GW_ADMIT_ALLOW && so_stub.calls == 0);
}

/* With no class configured the gate asks nothing and reads nothing: the
 * request is decided exactly as before the stage existed. */
static void
test_class_off_asks_nothing(void)
{
  ai_gw_req_ctx_t req = class_key_req();
  ai_gw_admit_result_t res;

  req.class_on = 0;
  req.objective_hint = "realtime";
  req.objective_strict = 1;
  reset_stubs();
  tier_stub.tier = AI_TIER_FLEX;
  cls_stub.out.objective_denied = 1;   /* would refuse, were it asked */
  assert(ai_gw_admit(&req, &res) == 0);
  assert(res.verdict == AI_GW_ADMIT_ALLOW);
  assert(cls_stub.calls == 0 && tier_stub.calls == 0);
  assert(res.priority == 0 && res.priority_class == AI_GW_CLASS_STANDARD);
  assert(res.objective[0] == '\0' && !res.objective_denied);
  assert(!res.tier_consumed && !res.hint_not_applied);
  assert(rl_stub.calls == 1 && rs_stub.calls == 1);
}

/* A keyless request on a service that asks for no credential has no tenant:
 * no class is resolved for it. */
static void
test_class_needs_a_tenant(void)
{
  ai_gw_req_ctx_t req = {
    .body = body,
    .body_len = sizeof(body) - 1,
    .auth_mode = 0,
    .svc_ident = "10.0.0.1:2040",
    .class_on = 1,
    .objective_hint = "realtime",
  };
  ai_gw_admit_result_t res;

  reset_stubs();
  tier_stub.tier = AI_TIER_FLEX;
  (void)ai_gw_admit(&req, &res);
  assert(res.verdict != AI_GW_ADMIT_DENY);
  assert(cls_stub.calls == 0 && tier_stub.calls == 0);
  assert(!res.tier_consumed);
}

static void
test_class_key_arm(void)
{
  ai_gw_req_ctx_t req = class_key_req();
  ai_gw_admit_result_t res;

  req.objective_hint = "realtime";
  reset_stubs();
  cls_stub.out.priority = 10;
  cls_stub.out.priority_class = AI_GW_CLASS_CRITICAL;
  strcpy(cls_stub.out.objective, "realtime");
  assert(ai_gw_admit(&req, &res) == 0);
  assert(res.verdict == AI_GW_ADMIT_ALLOW);
  assert(cls_stub.calls == 1);
  assert(strcmp(cls_stub.tenant, "tenant-1") == 0 && strcmp(cls_stub.key, "key-1") == 0);
  assert(cls_stub.binding[0] == '\0' && cls_stub.profile[0] == '\0');
  assert(strcmp(cls_stub.svc, "10.0.0.1:2040") == 0);
  assert(strcmp(cls_stub.hint, "realtime") == 0 && cls_stub.tier == AI_TIER_NONE);
  assert(res.priority == 10 && res.priority_class == AI_GW_CLASS_CRITICAL);
  assert(strcmp(res.objective, "realtime") == 0 && !res.objective_denied);
  assert(!res.tier_consumed && !res.hint_not_applied);
  /* The class is decided before rate and reservation, which still run. */
  assert(rl_stub.calls == 1 && rs_stub.calls == 1);

  /* No header at all is an empty hint, not a NULL the resolver must guard. */
  req.objective_hint = NULL;
  reset_stubs();
  assert(ai_gw_admit(&req, &res) == 0);
  assert(cls_stub.calls == 1 && cls_stub.hint[0] == '\0');
  assert(res.priority_class == AI_GW_CLASS_STANDARD && !res.hint_not_applied);

  /* A class number the gate does not know is not passed on. */
  reset_stubs();
  cls_stub.out.priority_class = 9;
  assert(ai_gw_admit(&req, &res) == 0);
  assert(res.priority_class == AI_GW_CLASS_STANDARD);

  /* An objective with no terminator is cut, not read past. */
  reset_stubs();
  memset(cls_stub.out.objective, 'x', sizeof(cls_stub.out.objective));
  assert(ai_gw_admit(&req, &res) == 0);
  assert(strlen(res.objective) == sizeof(res.objective) - 1);
}

static void
test_class_bearer_arm_names_its_profile(void)
{
  ai_gw_req_ctx_t req = {
    .bearer = "Bearer tok",
    .jwt_profile = "kc",
    .body = body,
    .body_len = sizeof(body) - 1,
    .auth_mode = 3,
    .svc_ident = "10.0.0.1:2040",
    .class_on = 1,
  };
  ai_gw_admit_result_t res;

  reset_stubs();
  assert(ai_gw_admit(&req, &res) == 0);
  assert(res.verdict == AI_GW_ADMIT_ALLOW);
  assert(cls_stub.calls == 1);
  assert(strcmp(cls_stub.profile, "kc") == 0);
  assert(strcmp(cls_stub.tenant, "tenant-1") == 0 && cls_stub.key[0] == '\0');

  /* A key on a key-or-token service was not verified by the profile. */
  req.bearer = NULL;
  req.api_key = "lxb_k";
  req.auth_mode = 4;
  reset_stubs();
  assert(ai_gw_admit(&req, &res) == 0);
  assert(cls_stub.calls == 1 && cls_stub.profile[0] == '\0');
  assert(strcmp(cls_stub.key, "key-1") == 0);
}

static void
test_class_network_arm_names_its_binding(void)
{
  ai_gw_req_ctx_t req = {
    .body = body,
    .body_len = sizeof(body) - 1,
    .auth_mode = 0,
    .svc_ident = NET_SVC,
    .client_ip = NET_SRC,
    .netid_bound = 1,
    .class_on = 1,
  };
  ai_gw_admit_result_t res;

  reset_stubs();
  nid_bind("line-1-tenant", 0, 0);
  cls_stub.out.priority = -1;
  cls_stub.out.priority_class = AI_GW_CLASS_SHEDDABLE;
  assert(ai_gw_admit(&req, &res) == 0);
  assert(res.verdict == AI_GW_ADMIT_ALLOW);
  assert(cls_stub.calls == 1);
  assert(strcmp(cls_stub.tenant, "line-1-tenant") == 0);
  assert(strcmp(cls_stub.binding, "line-1") == 0);
  assert(cls_stub.key[0] == '\0' && cls_stub.profile[0] == '\0');
  assert(res.priority == -1 && res.priority_class == AI_GW_CLASS_SHEDDABLE);
}

/* A request that names an objective it may not use is admitted at its
 * default, with the fact on the result; on a strict rule it is refused 403
 * before the rate limit and the reservation are asked. */
static void
test_class_denied_falls_through_unless_strict(void)
{
  ai_gw_req_ctx_t req = class_key_req();
  ai_gw_admit_result_t res;

  req.objective_hint = "not-mine";
  reset_stubs();
  cls_stub.out.objective_denied = 1;
  cls_stub.out.priority = -5;
  cls_stub.out.priority_class = AI_GW_CLASS_SHEDDABLE;
  strcpy(cls_stub.out.objective, "batch");
  assert(ai_gw_admit(&req, &res) == 0);
  assert(res.verdict == AI_GW_ADMIT_ALLOW);
  assert(res.objective_denied == 1);
  assert(res.priority == -5 && strcmp(res.objective, "batch") == 0);
  assert(rl_stub.calls == 1 && rs_stub.calls == 1 && deny_stub.calls == 0);
  /* and the answer keeps what was asked for, for the response head */
  assert(strcmp(res.objective_requested, "not-mine") == 0);

  /* a denied body tier, with no header: named as the resolver names it */
  req.objective_hint = "";
  reset_stubs();
  cls_stub.out.objective_denied = 1;
  tier_stub.tier = AI_TIER_PRIORITY;
  tier_stub.off = 3;
  tier_stub.vlen = 10;
  assert(ai_gw_admit(&req, &res) == 0 && res.objective_denied == 1);
  assert(strcmp(res.objective_requested, "tier:priority") == 0);

  /* the header wins over the tier, as it does in the resolver */
  req.objective_hint = "not-mine";
  reset_stubs();
  cls_stub.out.objective_denied = 1;
  tier_stub.tier = AI_TIER_FAST;
  tier_stub.off = 3;
  tier_stub.vlen = 6;
  assert(ai_gw_admit(&req, &res) == 0 && res.objective_denied == 1);
  assert(strcmp(res.objective_requested, "not-mine") == 0);

  /* not denied: nothing is kept, whatever was asked */
  reset_stubs();
  strcpy(cls_stub.out.objective, "not-mine");
  assert(ai_gw_admit(&req, &res) == 0 && !res.objective_denied);
  assert(res.objective_requested[0] == '\0');

  req.objective_strict = 1;
  reset_stubs();
  cls_stub.out.objective_denied = 1;
  tier_stub.tier = AI_TIER_FLEX;
  tier_stub.off = 3;
  tier_stub.vlen = 6;
  assert(ai_gw_admit(&req, &res) != 0);
  assert(res.verdict == AI_GW_ADMIT_DENY);
  assert(res.stage == AI_GW_STAGE_OBJECTIVE && res.http_status == 403);
  assert(strcmp(res.error_code, "objective_not_allowed") == 0);
  assert(res.error_msg[0] != '\0' && res.retry_after == 0 && res.retry_body == 0);
  assert(strcmp(res.tenant_id, "tenant-1") == 0 && strcmp(res.key_id, "key-1") == 0);
  assert(rl_stub.calls == 0 && rs_stub.calls == 0);   /* nothing charged */
  assert(deny_stub.calls == 1);                       /* and it is recorded */
  assert(!res.tier_consumed);                         /* nothing is forwarded */

  /* Strict refuses a denied objective only. */
  reset_stubs();
  assert(ai_gw_admit(&req, &res) == 0);
  assert(res.verdict == AI_GW_ADMIT_ALLOW);
}

/* A refusal's record carries the class the request had, so the records of
 * one request agree: an objective refusal and a refusal after the class
 * stage say what class it was; one made before the stage ran says none. */
static void
test_class_on_the_refusal_record(void)
{
  ai_gw_req_ctx_t req = class_key_req();
  ai_gw_admit_result_t res;

  /* the objective refusal itself */
  req.objective_hint = "not-mine";
  req.objective_strict = 1;
  reset_stubs();
  cls_stub.out.objective_denied = 1;
  cls_stub.out.priority = -5;
  cls_stub.out.priority_class = AI_GW_CLASS_SHEDDABLE;
  strcpy(cls_stub.out.objective, "batch");
  assert(ai_gw_admit(&req, &res) != 0 && res.stage == AI_GW_STAGE_OBJECTIVE);
  assert(deny_stub.calls == 1);
  assert(deny_stub.class_info == (AI_GW_CLASSF_SET | AI_GW_CLASS_SHEDDABLE |
                                  AI_GW_CLASSF_DENIED));
  assert(deny_stub.priority == -5 && strcmp(deny_stub.objective, "batch") == 0);

  /* a refusal after the class stage: the rate limit */
  req.objective_hint = NULL;
  req.objective_strict = 0;
  reset_stubs();
  cls_stub.out.priority = 10;
  cls_stub.out.priority_class = AI_GW_CLASS_CRITICAL;
  strcpy(cls_stub.out.objective, "realtime");
  rl_stub.rc = -1;
  rl_stub.decision = 3;
  assert(ai_gw_admit(&req, &res) != 0 && res.stage == AI_GW_STAGE_RATELIMIT);
  assert(deny_stub.calls == 1);
  assert(deny_stub.class_info == (AI_GW_CLASSF_SET | AI_GW_CLASS_CRITICAL));
  assert(deny_stub.priority == 10 && strcmp(deny_stub.objective, "realtime") == 0);

  /* a refusal before the stage ran: no class */
  req.api_key = "";
  reset_stubs();
  cls_stub.out.priority = 10;
  cls_stub.out.priority_class = AI_GW_CLASS_CRITICAL;
  assert(ai_gw_admit(&req, &res) != 0 && res.stage == AI_GW_STAGE_AUTH);
  assert(deny_stub.calls == 1 && cls_stub.calls == 0);
  assert(deny_stub.class_info == 0 && deny_stub.priority == 0 &&
         deny_stub.objective[0] == '\0');
}

/* A tier the gateway read is handed back to be nulled, with where it is,
 * whether the tier or a header decided. A value that is no tier is not. */
static void
test_class_tier_is_consumed_whoever_decided(void)
{
  ai_gw_req_ctx_t req = class_key_req();
  ai_gw_admit_result_t res;

  reset_stubs();
  tier_stub.tier = AI_TIER_PRIORITY;
  tier_stub.off = 17;
  tier_stub.vlen = 10;
  assert(ai_gw_admit(&req, &res) == 0);
  assert(tier_stub.calls == 1 && cls_stub.tier == AI_TIER_PRIORITY);
  assert(res.tier_consumed == 1 && res.tier_off == 17 && res.tier_len == 10);
  assert(!res.hint_not_applied);

  req.objective_hint = "realtime";
  reset_stubs();
  tier_stub.tier = AI_TIER_FLEX;
  tier_stub.off = 5;
  tier_stub.vlen = 6;
  assert(ai_gw_admit(&req, &res) == 0);
  assert(strcmp(cls_stub.hint, "realtime") == 0 && cls_stub.tier == AI_TIER_FLEX);
  assert(res.tier_consumed == 1 && res.tier_off == 5 && res.tier_len == 6);

  reset_stubs();
  assert(ai_gw_admit(&req, &res) == 0);
  assert(tier_stub.calls == 1 && !res.tier_consumed && res.tier_len == 0);
}

/* A body that is not whole in the buffer is not searched for a tier. With
 * no header hint either, the result says a body hint could not be read. */
static void
test_class_streamed_body(void)
{
  ai_gw_req_ctx_t req = {
    .api_key = "lxb_k",
    .prefix_model = "m9",
    .prefix_only = 1,
    .declared_content_length = 4000,
    .auth_mode = 1,
    .svc_ident = "10.0.0.1:2040",
    .class_on = 1,
  };
  ai_gw_admit_result_t res;

  reset_stubs();
  tier_stub.tier = AI_TIER_FLEX;
  assert(ai_gw_admit(&req, &res) == 0);
  assert(res.verdict == AI_GW_ADMIT_ALLOW);
  assert(tier_stub.calls == 0 && cls_stub.calls == 1 && cls_stub.tier == AI_TIER_NONE);
  assert(res.hint_not_applied == 1 && !res.tier_consumed);

  req.objective_hint = "realtime";
  reset_stubs();
  tier_stub.tier = AI_TIER_FLEX;
  assert(ai_gw_admit(&req, &res) == 0);
  assert(tier_stub.calls == 0 && strcmp(cls_stub.hint, "realtime") == 0);
  assert(!res.hint_not_applied && !res.tier_consumed);
}

/* A streamed request hands the gate the part of its body that has arrived.
 * A service_tier in that part is not read and not marked for nulling: the
 * rest of the body is not in the buffer, and what is relayed must be what
 * the client sent. */
static void
test_class_streamed_prefix_is_not_read(void)
{
  static const char prefix[] = "{\"service_tier\":\"flex\",\"model\":\"m9\",\"messages\":[";
  ai_gw_req_ctx_t req = {
    .api_key = "lxb_k",
    .body = prefix,
    .body_len = sizeof(prefix) - 1,
    .prefix_model = "m9",
    .prefix_only = 1,
    .declared_content_length = 4000,
    .auth_mode = 1,
    .svc_ident = "10.0.0.1:2040",
    .class_on = 1,
  };
  ai_gw_admit_result_t res;

  reset_stubs();
  tier_stub.tier = AI_TIER_FLEX;
  assert(ai_gw_admit(&req, &res) == 0);
  assert(res.verdict == AI_GW_ADMIT_ALLOW);
  assert(tier_stub.calls == 0 && cls_stub.calls == 1 && cls_stub.tier == AI_TIER_NONE);
  assert(res.hint_not_applied == 1 && !res.tier_consumed && res.tier_len == 0);
}

/* A credential that validates and names no tenant has nothing a class
 * could be looked up by: the resolver is not asked. */
static void
test_class_key_without_a_tenant(void)
{
  ai_gw_req_ctx_t req = class_key_req();
  ai_gw_admit_result_t res;

  req.objective_hint = "realtime";
  req.objective_strict = 1;
  reset_stubs();
  validate_key_tenant = "";
  tier_stub.tier = AI_TIER_FLEX;
  cls_stub.out.objective_denied = 1;   /* would refuse, were it asked */
  (void)ai_gw_admit(&req, &res);
  validate_key_tenant = "tenant-1";
  assert(cls_stub.calls == 0 && tier_stub.calls == 0);
  assert(!res.tier_consumed && !res.objective_denied);
  assert(res.stage != AI_GW_STAGE_OBJECTIVE);
}

/* A resolver that cannot answer leaves the request standard and admitted,
 * strict rule or not: a class is not a condition of admission. */
static void
test_class_resolver_failure_is_standard(void)
{
  ai_gw_req_ctx_t req = class_key_req();
  ai_gw_admit_result_t res;

  req.objective_hint = "realtime";
  req.objective_strict = 1;
  reset_stubs();
  cls_stub.rc = -1;
  cls_stub.out.priority = 10;
  cls_stub.out.priority_class = AI_GW_CLASS_CRITICAL;
  cls_stub.out.objective_denied = 1;
  strcpy(cls_stub.out.objective, "realtime");
  assert(ai_gw_admit(&req, &res) == 0);
  assert(res.verdict == AI_GW_ADMIT_ALLOW);
  assert(res.priority == 0 && res.priority_class == AI_GW_CLASS_STANDARD);
  assert(res.objective[0] == '\0' && !res.objective_denied);
  assert(rl_stub.calls == 1 && rs_stub.calls == 1);
}

static void
test_class_on_switch(void)
{
  assert(ai_gw_class_on() == 0);
  ai_gw_class_on_set(1);
  assert(ai_gw_class_on() == 1);
  ai_gw_class_on_set(7);
  assert(ai_gw_class_on() == 1);
  ai_gw_class_on_set(0);
  assert(ai_gw_class_on() == 0);
}

/* ---- every refusal is recorded once, at its stage ----------------------
 *
 * The gateway counts every refusal it makes in one place, the deny record:
 * the gate's arms through ai_gw_admit's verdict frame, and the refusals made
 * outside it (capacity, route, framing) through ai_gw_record_local_deny. The
 * five arms below exist only in C; each answers once and is recorded once,
 * with the stage, status and code its client got. */

static void
expect_one_deny(int stage, int status, const char *code)
{
  assert(deny_stub.calls == 1);
  assert(deny_stub.stage == stage);
  assert(deny_stub.http_status == status);
  assert(strcmp(deny_stub.error_code, code) == 0);
}

static void
test_c_only_refusals_are_recorded_once_at_their_stage(void)
{
  ai_gw_admit_result_t res;

  /* netid_unavailable: a fail-closed binding whose lookup failed */
  {
    ai_gw_req_ctx_t req = {
      .api_key = "",
      .body = body,
      .body_len = sizeof(body) - 1,
      .svc_ident = NET_SVC,
      .client_ip = NET_SRC,
      .netid_bound = AI_GW_NETID_BOUND | AI_GW_NETID_FAIL_CLOSED,
    };
    reset_stubs();
    nid_bind("line-1-tenant", 1, 1);
    nid_stub.rc = -1;
    assert(ai_gw_admit(&req, &res) == -1);
    expect_one_deny(AI_GW_STAGE_AUTH, 503, "netid_unavailable");
  }

  /* objective_not_allowed: a strict rule and an objective not the tenant's */
  {
    ai_gw_req_ctx_t req = class_key_req();
    req.objective_hint = "not-mine";
    req.objective_strict = 1;
    reset_stubs();
    cls_stub.out.objective_denied = 1;
    assert(ai_gw_admit(&req, &res) != 0);
    expect_one_deny(AI_GW_STAGE_OBJECTIVE, 403, "objective_not_allowed");
  }

  /* model_conflict and the binding's model_not_allowed: a bound source */
  {
    ai_gw_req_ctx_t req = {
      .body = body,
      .body_len = sizeof(body) - 1,
      .hdr_model = "m2",
      .auth_mode = 0,
      .svc_ident = NET_SVC,
      .client_ip = NET_SRC,
      .netid_bound = 1,
    };
    reset_stubs();
    nid_bind("line-1-tenant", 0, 0);
    assert(ai_gw_admit(&req, &res) == -1);
    expect_one_deny(AI_GW_STAGE_CONFLICT, 400, "model_conflict");

    req.hdr_model = "";
    reset_stubs();
    nid_bind("line-1-tenant", 0, 0);
    nid_stub.out.model_ok = 0;
    assert(ai_gw_admit(&req, &res) == -1);
    expect_one_deny(AI_GW_STAGE_AUTH, 403, "model_not_allowed");
  }

  /* network_tenant_mismatch: an enforcing binding, a key of another tenant */
  {
    ai_gw_req_ctx_t req = {
      .api_key = "sk-abc",
      .body = body,
      .body_len = sizeof(body) - 1,
      .auth_mode = 1,
      .svc_ident = NET_SVC,
      .client_ip = NET_SRC,
      .netid_bound = 1,
    };
    reset_stubs();
    nid_bind("another-tenant", 1, 0);
    assert(ai_gw_admit(&req, &res) == -1);
    expect_one_deny(AI_GW_STAGE_AUTH, 403, "network_tenant_mismatch");
  }
}

static void
test_local_refusals_are_recorded_at_their_stage(void)
{
  /* Route: no pool for the named model; no rule matched (no model). */
  reset_stubs();
  ai_gw_record_local_deny(AI_GW_STAGE_ROUTE, "req-route", 2, NET_SVC, "m9",
                          "", "", "", 503, "model_unavailable", NET_SRC, "",
                          0, AI_GW_AUTH_SRC_CREDENTIAL, "", 0, 0, "");
  expect_one_deny(AI_GW_STAGE_ROUTE, 503, "model_unavailable");
  assert(strcmp(deny_stub.model, "m9") == 0);
  assert(strcmp(deny_stub.request_id, "req-route") == 0 && deny_stub.producer_id == 2);

  reset_stubs();
  ai_gw_record_local_deny(AI_GW_STAGE_ROUTE, "req-nr", 2, NET_SVC, NULL,
                          NULL, NULL, NULL, 503, "no_route", NET_SRC, NULL,
                          0, AI_GW_AUTH_SRC_CREDENTIAL, NULL, 0, 0, NULL);
  expect_one_deny(AI_GW_STAGE_ROUTE, 503, "no_route");
  assert(deny_stub.model[0] == '\0' && deny_stub.tenant[0] == '\0');

  /* Framing: an admitted identity is carried as the gate resolved it. */
  reset_stubs();
  ai_gw_record_local_deny(AI_GW_STAGE_FRAMING, "req-413", 1, NET_SVC, "m1",
                          "tenant-1", "key-1", "", 413,
                          "request_body_too_large", NET_SRC, "", 0,
                          AI_GW_AUTH_SRC_CREDENTIAL, "", 0, 0, "");
  expect_one_deny(AI_GW_STAGE_FRAMING, 413, "request_body_too_large");
  assert(strcmp(deny_stub.tenant, "tenant-1") == 0 && strcmp(deny_stub.key, "key-1") == 0);

  /* Capacity: the capacity helper is the same record at CAPACITY. */
  reset_stubs();
  ai_gw_record_capacity_deny("req-pd", 1, NET_SVC, "m1", "tenant-1", "key-1",
                             "", 429, "pd_overloaded", NET_SRC, "", 0,
                             AI_GW_AUTH_SRC_CREDENTIAL, "", 0, 0, "");
  expect_one_deny(AI_GW_STAGE_CAPACITY, 429, "pd_overloaded");

  /* The values the Go side names a stage by: appended, none moved. */
  assert(AI_GW_STAGE_NONE == 0 && AI_GW_STAGE_AUTH == 1 &&
         AI_GW_STAGE_CONFLICT == 2 && AI_GW_STAGE_RATELIMIT == 3 &&
         AI_GW_STAGE_RESERVE == 4 && AI_GW_STAGE_CAPACITY == 5 &&
         AI_GW_STAGE_OBJECTIVE == 6 && AI_GW_STAGE_ROUTE == 7 &&
         AI_GW_STAGE_FRAMING == 8 && AI_GW_STAGE_SECURITY == 9);
}

int
main(void)
{
  test_jwt_arm_forwards_user_and_service();
  test_bearer_is_named_as_the_source();
  test_apikey_arm_forwards_key_and_service();
  test_keyless_probes_shared_bucket_only_with_ident();
  test_prefix_only_sizes_reservation_from_declared_length();
  test_default_reservation_off_claims_the_prompt_alone();
  test_default_reservation_stands_in_for_an_absent_ceiling();
  test_default_reservation_leaves_a_declared_ceiling_alone();
  test_default_reservation_is_the_routed_rules();
  test_clamped_default_is_admitted_with_what_was_granted();
  test_reserve_refusal_reports_the_firm_claim();
  test_default_reservation_covers_a_streamed_body();
  test_prefix_only_without_length_reserves_nothing();
  test_prefix_only_missing_credential_is_refused();
  test_svc_ident_format();
  test_allow_records_no_refusal();
  test_missing_credential_refusal_is_recorded_with_its_key();
  test_model_refusal_keeps_the_tenant_it_validated();
  test_rate_limit_refusal_is_recorded_after_identity();
  test_keyless_bucket_refusal_is_recorded();
  test_minted_request_ids_are_unique_and_uuid_shaped();
  test_net_row1_no_binding_is_the_keyless_request();
  test_net_row2_binding_admits_as_its_tenant();
  test_net_row2_stages_refuse_in_order();
  test_net_row3_credential_without_binding_is_unchanged();
  test_net_row4_advisory_binding_is_noted_only();
  test_net_row5_strict_binding_holds_the_credential();
  test_net_row6_credential_network_admits_without_a_credential();
  test_net_row7_no_credential_otherwise_is_401();
  test_net_presented_credential_never_falls_back();
  test_net_resolver_failure_is_no_binding();
  test_net_resolver_failure_fails_closed_where_asked();
  test_capacity_deny_carries_the_binding();
  test_net_streamed_body_is_gated_on_the_prefix();
  test_netid_bound_set();
  test_netid_bound_set_carries_fail_closed();
  test_netid_bound_set_carries_forward();
  test_netid_ifmatch_switch();
  test_net_forward_flag_does_not_change_the_decision();
  test_netid_bound_set_is_replaced_under_readers();
  test_class_off_asks_nothing();
  test_objective_strict_is_the_routed_rules();
  test_class_needs_a_tenant();
  test_class_key_arm();
  test_class_bearer_arm_names_its_profile();
  test_class_network_arm_names_its_binding();
  test_class_denied_falls_through_unless_strict();
  test_class_tier_is_consumed_whoever_decided();
  test_class_on_the_refusal_record();
  test_class_streamed_body();
  test_class_streamed_prefix_is_not_read();
  test_class_key_without_a_tenant();
  test_class_resolver_failure_is_standard();
  test_class_on_switch();
  test_c_only_refusals_are_recorded_once_at_their_stage();
  test_local_refusals_are_recorded_at_their_stage();
  puts("PASS: refusals: each C-only gate arm and each local refusal (route, "
       "framing, capacity) is recorded once with its stage, status and code; "
       "stage values pinned");
  puts("PASS: class stage: off asks nothing, every arm hands its identity over, "
       "a denied objective refuses only on a strict rule and before any charge, "
       "a tier that was read is handed back to be nulled");
  puts("PASS: network identity: one case per decision-table row, the conflict "
       "rule on the network path, a presented credential never falls back, "
       "a resolver failure is no binding");
  puts("PASS: identity-forwarding ABI transports user/key/service through the gate, "
       "and a streamed prefix is gated on headers + declared length");
  return 0;
}
