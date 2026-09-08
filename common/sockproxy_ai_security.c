/*
 * Copyright (c) 2025 LoxiLB Authors
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include <string.h>
#include <strings.h>

#include "sockproxy_ai_security.h"

static int
ai_security_status(const ai_gw_decision_t *result, int default_status)
{
  if (!result)
    return default_status;

  switch (result->decision) {
  case 2:
    return 403;
  case 3:
    return 429;
  case 4:
    return 503;
  case 1:
    return 401;
  default:
    return default_status;
  }
}

int
ai_security_admit(uint8_t policy, char *raw_key, char *model,
                  ai_gw_decision_t *result)
{
  ai_gw_decision_t local = {0};
  ai_gw_decision_t rate = {0};

  if (!result)
    result = &local;
  memset(result, 0, sizeof(*result));

  /* Only the two declared non-enforcing values bypass authentication.
   * Unknown wire values fail closed. */
  if (policy == 0 || policy == 2)
    return 0;

  if (llb_ai_validate_key(raw_key ? raw_key : "", model ? model : "", result) != 0)
    return ai_security_status(result, 401);

  if (llb_ai_ratelimit_check(result->key_id, result->tenant_id,
                             model ? model : "", &rate) != 0) {
    *result = rate;
    return ai_security_status(result, 429);
  }

  return 0;
}

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

size_t
ai_security_filter_h2_headers(const nghttp2_nv *input, size_t input_len,
                              nghttp2_nv *output, size_t output_cap,
                              uint8_t policy, uint8_t ai_gw_mode)
{
  size_t written = 0;
  int strip = (ai_gw_mode != 0 || policy != 0);

  if (!input || !output)
    return 0;

  for (size_t i = 0; i < input_len; i++) {
    const nghttp2_nv *nv = &input[i];
    int is_api_key = nv->namelen == sizeof("x-api-key") - 1 &&
                     strncasecmp((const char *)nv->name, "x-api-key",
                                 sizeof("x-api-key") - 1) == 0;
    if (strip && is_api_key)
      continue;
    if (written >= output_cap)
      break;
    output[written++] = *nv;
  }

  return written;
}
