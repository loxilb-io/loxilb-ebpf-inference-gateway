/* SPDX-License-Identifier: GPL-2.0 */

/*
 * HTTP/2 credential-handling unit. Admission itself lives in ai_gw_admit
 * (covered by test_ai_admit_identity); this unit pins the header-hygiene
 * half: the bounded credential copy, the X-Api-Key namespace rules, and
 * the upstream hygiene (client X-Auth-* strip, consumed-Authorization
 * strip, verified-identity injection).
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "sockproxy_ai_security.h"

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

static int
has_header(const nghttp2_nv *set, size_t n, const char *name,
           const char *value /* NULL = any */)
{
  for (size_t i = 0; i < n; i++) {
    if (set[i].namelen == strlen(name) &&
        strncasecmp((const char *)set[i].name, name, set[i].namelen) == 0) {
      if (!value)
        return 1;
      return set[i].valuelen == strlen(value) &&
             memcmp(set[i].value, value, set[i].valuelen) == 0;
    }
  }
  return 0;
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

static void
test_upstream_hygiene(void)
{
  nghttp2_nv input[] = {
    nv(":method", "POST"),
    nv("authorization", "Bearer tok"),
    nv("x-auth-tenant", "spoofed-t"),
    nv("x-auth-user", "spoofed-u"),
    nv("content-type", "application/json"),
  };
  nghttp2_nv output[7];
  size_t n;

  /* JWT-capable + strip_authz + forward_identity: client X-Auth-* gone,
   * Authorization gone, VERIFIED identity injected. */
  n = ai_security_h2_upstream_hygiene(input, 5, output, 7,
                                      3 /* jwt */, 1, 1, 1,
                                      "tenant-1", "alice");
  assert(n == 4); /* :method + content-type + 2 injected */
  assert(!has_header(output, n, "authorization", NULL));
  assert(has_header(output, n, "x-auth-tenant", "tenant-1"));
  assert(has_header(output, n, "x-auth-user", "alice"));
  assert(!has_header(output, n, "x-auth-tenant", "spoofed-t"));
  assert(!has_header(output, n, "x-auth-user", "spoofed-u"));

  /* Passthrough profile (strip_authz=0): Authorization rides through, the
   * spoofed X-Auth-* still never does. */
  n = ai_security_h2_upstream_hygiene(input, 5, output, 7,
                                      3, 1, 0, 0, "", "");
  assert(n == 3);
  assert(has_header(output, n, "authorization", "Bearer tok"));
  assert(!has_header(output, n, "x-auth-tenant", NULL));
  assert(!has_header(output, n, "x-auth-user", NULL));

  /* Not JWT-capable (plain API-key service): none of the JWT hygiene runs —
   * exact legacy behaviour, headers untouched apart from the key strip. */
  n = ai_security_h2_upstream_hygiene(input, 5, output, 7,
                                      1, 0, 0, 0, NULL, NULL);
  assert(n == 5);
  assert(has_header(output, n, "authorization", "Bearer tok"));
  assert(has_header(output, n, "x-auth-tenant", "spoofed-t"));

  /* forward_identity with no user: only the tenant is injected. */
  n = ai_security_h2_upstream_hygiene(input, 5, output, 7,
                                      3, 1, 1, 1, "tenant-1", "");
  assert(n == 3);
  assert(has_header(output, n, "x-auth-tenant", "tenant-1"));
  assert(!has_header(output, n, "x-auth-user", NULL));

  /* Injection respects the output cap: no room, no write past the end. */
  nghttp2_nv tight[2];
  n = ai_security_h2_upstream_hygiene(input, 5, tight, 2,
                                      3, 1, 1, 1, "tenant-1", "alice");
  assert(n == 2);
}

int
main(void)
{
  test_bounded_copy();
  test_header_filter();
  test_upstream_hygiene();
  puts("PASS: AI credential handling and upstream header hygiene");
  return 0;
}
