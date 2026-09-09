/* SPDX-License-Identifier: GPL-2.0 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "sockproxy_ai_security.h"

static int validate_calls;
static int rate_calls;
static int validate_rc;
static int validate_decision;
static int rate_rc;
static int rate_decision;

int
llb_ai_validate_key(char *raw_key, char *model, ai_gw_decision_t *result)
{
  validate_calls++;
  (void)raw_key;
  (void)model;
  result->decision = validate_decision;
  strcpy(result->key_id, "key-1");
  strcpy(result->tenant_id, "tenant-1");
  return validate_rc;
}

int
llb_ai_ratelimit_check(char *key_id, char *tenant_id, char *model,
                       ai_gw_decision_t *result)
{
  rate_calls++;
  assert(strcmp(key_id, "key-1") == 0);
  assert(strcmp(tenant_id, "tenant-1") == 0);
  (void)model;
  result->decision = rate_decision;
  return rate_rc;
}

static void
reset_stubs(void)
{
  validate_calls = 0;
  rate_calls = 0;
  validate_rc = 0;
  validate_decision = 0;
  rate_rc = 0;
  rate_decision = 0;
}

static void
test_admission_matrix(void)
{
  ai_gw_decision_t result;

  reset_stubs();
  assert(ai_security_admit(0, "", "model-a", &result) == 0);
  assert(validate_calls == 0 && rate_calls == 0);

  reset_stubs();
  assert(ai_security_admit(2, "client-owned", "model-a", &result) == 0);
  assert(validate_calls == 0 && rate_calls == 0);

  reset_stubs();
  validate_rc = -1;
  validate_decision = 1;
  assert(ai_security_admit(1, "", "model-a", &result) == 401);
  assert(validate_calls == 1 && rate_calls == 0);

  reset_stubs();
  validate_rc = -1;
  validate_decision = 2;
  assert(ai_security_admit(1, "key", "model-b", &result) == 403);

  reset_stubs();
  validate_rc = -1;
  validate_decision = 4;
  assert(ai_security_admit(1, "key", "model-a", &result) == 503);

  reset_stubs();
  rate_rc = -1;
  rate_decision = 3;
  assert(ai_security_admit(1, "key", "model-a", &result) == 429);
  assert(validate_calls == 1 && rate_calls == 1);

  reset_stubs();
  assert(ai_security_admit(1, "key", "model-a", &result) == 0);
  assert(validate_calls == 1 && rate_calls == 1);

  reset_stubs();
  validate_rc = -1;
  validate_decision = 1;
  assert(ai_security_admit(99, "", "model-a", &result) == 401);
  assert(validate_calls == 1); /* unknown policy fails closed */
}

static void
test_bounded_copy(void)
{
  char dst[256];
  char fit[255];
  char overflow[256];

  memset(fit, 'a', sizeof(fit));
  memset(overflow, 'b', sizeof(overflow));
  assert(ai_security_copy_api_key(dst, sizeof(dst),
                                  (const uint8_t *)fit, sizeof(fit)) == 0);
  assert(strlen(dst) == 255);
  assert(ai_security_copy_api_key(dst, sizeof(dst),
                                  (const uint8_t *)overflow,
                                  sizeof(overflow)) == -1);
  assert(dst[0] == '\0'); /* oversize becomes a missing-key denial */
}

static nghttp2_nv
nv(char *name, char *value)
{
  nghttp2_nv item = {
    .name = (uint8_t *)name,
    .value = (uint8_t *)value,
    .namelen = strlen(name),
    .valuelen = strlen(value),
    .flags = NGHTTP2_NV_FLAG_NONE,
  };
  return item;
}

static void
test_header_filter(void)
{
  nghttp2_nv input[] = {
    nv(":method", "POST"),
    nv("x-api-key", "secret"),
    nv("content-type", "application/json"),
  };
  nghttp2_nv output[3];
  const struct {
    uint8_t policy;
    size_t want;
  } cases[] = {
    {0, 3}, /* undeclared: backend-owned credential passes through */
    {1, 2}, /* required: gateway credential is consumed and stripped */
    {2, 2}, /* declared disabled: namespace is still reserved */
    {99, 2}, /* unknown: fail closed and do not forward credential bytes */
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    assert(ai_security_should_strip_api_key(cases[i].policy) ==
           (cases[i].policy != 0));
    assert(ai_security_filter_h2_headers(input, 3, output, 3,
                                         cases[i].policy) == cases[i].want);
    assert(strncmp((char *)output[0].name, ":method",
                   output[0].namelen) == 0);
    if (cases[i].want == 2)
      assert(strncmp((char *)output[1].name, "content-type",
                     output[1].namelen) == 0);
    else {
      assert(strncmp((char *)output[1].name, "x-api-key",
                     output[1].namelen) == 0);
      assert(output[1].valuelen == sizeof("secret") - 1);
      assert(memcmp(output[1].value, "secret", sizeof("secret") - 1) == 0);
    }
  }
}

int
main(void)
{
  test_admission_matrix();
  test_bounded_copy();
  test_header_filter();
  puts("PASS: AI security admission and policy-owned credential handling");
  return 0;
}
