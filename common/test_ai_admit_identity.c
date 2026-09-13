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
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "sockproxy_ai_admit.h"

/* ---- JSON helper stubs (sockproxy_json.h) ------------------------------- */

int
extract_model_field(const char *body, size_t len, char *out, size_t cap)
{
  (void)len;
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

int
extract_max_tokens(const char *body, size_t len)
{
  (void)body;
  (void)len;
  return 32;
}

/* ---- Go-export stubs recording what the gate handed them ---------------- */

static int validate_key_calls;
static int validate_bearer_calls;

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
} rs_stub;

int
llb_ai_validate_key(char *raw_key, char *model, ai_gw_decision_t *result)
{
  validate_key_calls++;
  (void)raw_key;
  (void)model;
  strcpy(result->key_id, "key-1");
  strcpy(result->tenant_id, "tenant-1");
  /* API keys map to no user today: user_id stays "". */
  return 0;
}

int
llb_ai_validate_bearer(char *bearer, char *model_name, char *profile_name,
                       int bearer_flags, ai_gw_decision_t *result)
{
  validate_bearer_calls++;
  (void)model_name;
  (void)profile_name;
  (void)bearer_flags;
  assert(strcmp(bearer, "tok") == 0); /* gate strips the Bearer tag itself */
  strcpy(result->tenant_id, "tenant-1");
  strcpy(result->user_id, "alice");
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
                           int64_t *res_epoch, ai_gw_decision_t *result)
{
  rs_stub.calls++;
  snprintf(rs_stub.tenant, sizeof(rs_stub.tenant), "%s", tenant_id);
  snprintf(rs_stub.model, sizeof(rs_stub.model), "%s", model_name);
  snprintf(rs_stub.user, sizeof(rs_stub.user), "%s", user_id);
  snprintf(rs_stub.key, sizeof(rs_stub.key), "%s", key_id);
  snprintf(rs_stub.svc, sizeof(rs_stub.svc), "%s", svc_ident);
  rs_stub.prompt_est = prompt_est;
  rs_stub.max_tokens = max_tokens;
  (void)result;
  *res_epoch = 77;
  return 0;
}

static void
reset_stubs(void)
{
  validate_key_calls = 0;
  validate_bearer_calls = 0;
  memset(&rl_stub, 0, sizeof(rl_stub));
  memset(&rs_stub, 0, sizeof(rs_stub));
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

int
main(void)
{
  test_jwt_arm_forwards_user_and_service();
  test_apikey_arm_forwards_key_and_service();
  test_keyless_probes_shared_bucket_only_with_ident();
  test_svc_ident_format();
  puts("PASS: identity-forwarding ABI transports user/key/service through the gate");
  return 0;
}
