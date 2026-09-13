/*
 * Copyright (c) 2025 LoxiLB Authors
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include <string.h>
#include <strings.h>

#include "sockproxy_ai_security.h"

/* ai_security_admit is gone: the HTTP/2 stream gate calls ai_gw_admit()
 * (sockproxy_ai_admit.c), the same admission gate the HTTP/1 parser runs.
 * The H2-only arm it implemented ran the API-key check no matter what the
 * service declared, which admitted a valid API key on a jwt-only service. */

int
ai_security_copy_api_key(char *dst, size_t cap,
                         const uint8_t *value, size_t value_len)
{
  if (!dst || cap == 0)
    return -1;

  dst[0] = '\0';
  if (!value || value_len == 0)
    return 0;
  if (value_len >= cap)
    return -1;

  memcpy(dst, value, value_len);
  dst[value_len] = '\0';
  return 0;
}

int
ai_security_should_strip_api_key(uint8_t policy)
{
  return policy != 0;
}

static int
nv_name_is(const nghttp2_nv *nv, const char *name, size_t namelen)
{
  return nv->namelen == namelen &&
         strncasecmp((const char *)nv->name, name, namelen) == 0;
}

size_t
ai_security_h2_upstream_hygiene(const nghttp2_nv *input, size_t input_len,
                                nghttp2_nv *output, size_t output_cap,
                                uint8_t policy, int jwt_capable,
                                int strip_authz, int fwd_identity,
                                const char *tenant, const char *user)
{
  size_t written = 0;
  int strip_key = ai_security_should_strip_api_key(policy);

  if (!input || !output)
    return 0;

  for (size_t i = 0; i < input_len; i++) {
    const nghttp2_nv *nv = &input[i];
    if (strip_key && nv_name_is(nv, "x-api-key", sizeof("x-api-key") - 1))
      continue;
    /* Client-sent X-Auth-* carries gateway-verified identity upstream, so
     * a client copy is a spoof whether or not this request's profile
     * forwards identity — stripped ALWAYS on JWT-capable rules, exactly
     * like the H1 splice (sockproxy_http.c). */
    if (jwt_capable &&
        (nv_name_is(nv, "x-auth-tenant", sizeof("x-auth-tenant") - 1) ||
         nv_name_is(nv, "x-auth-user", sizeof("x-auth-user") - 1)))
      continue;
    /* Authorization is stripped only when the JWT arm decided this request
     * and the profile did not opt into passthrough: the gateway consumed
     * that credential, and replaying an access token hands every backend
     * operator a bearer credential they never needed. */
    if (jwt_capable && strip_authz &&
        nv_name_is(nv, "authorization", sizeof("authorization") - 1))
      continue;
    if (written >= output_cap)
      break;
    output[written++] = *nv;
  }

  /* Inject the VERIFIED identity (forward_identity profiles). The values
   * point at caller-owned storage — the stream's identity fields — which
   * outlives the submit; nghttp2 copies at submit time. */
  if (jwt_capable && fwd_identity && tenant && tenant[0]) {
    if (written < output_cap) {
      output[written].name = (uint8_t *)"x-auth-tenant";
      output[written].value = (uint8_t *)tenant;
      output[written].namelen = sizeof("x-auth-tenant") - 1;
      output[written].valuelen = strlen(tenant);
      output[written].flags = NGHTTP2_NV_FLAG_NONE;
      written++;
    }
    if (user && user[0] && written < output_cap) {
      output[written].name = (uint8_t *)"x-auth-user";
      output[written].value = (uint8_t *)user;
      output[written].namelen = sizeof("x-auth-user") - 1;
      output[written].valuelen = strlen(user);
      output[written].flags = NGHTTP2_NV_FLAG_NONE;
      written++;
    }
  }

  return written;
}

size_t
ai_security_filter_h2_headers(const nghttp2_nv *input, size_t input_len,
                              nghttp2_nv *output, size_t output_cap,
                              uint8_t policy)
{
  /* Legacy shape: the credential strip alone, no JWT hygiene. */
  return ai_security_h2_upstream_hygiene(input, input_len, output, output_cap,
                                         policy, 0, 0, 0, NULL, NULL);
}
