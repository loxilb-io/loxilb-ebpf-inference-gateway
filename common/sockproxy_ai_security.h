/*
 * Copyright (c) 2025 LoxiLB Authors
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef __SOCKPROXY_AI_SECURITY_H__
#define __SOCKPROXY_AI_SECURITY_H__

#include <nghttp2/nghttp2.h>
#include <stddef.h>
#include <stdint.h>

#include "sockproxy_ai_gw.h"

/*
 * Protocol-neutral API-key and request-rate admission.
 *
 * policy uses the data-plane wire values:
 *   0 = undeclared, 1 = required, 2 = explicitly disabled.
 * Unknown non-zero values fail closed and therefore enforce.
 *
 * Returns 0 when the request may enter routing.  Otherwise returns the HTTP
 * status that the protocol adapter must send (401/403/429/503).  result is
 * populated by the underlying policy callbacks on both allow and deny paths.
 */
int ai_security_admit(uint8_t policy, char *raw_key, char *model,
                      ai_gw_decision_t *result);

/* Copy one length-delimited HTTP/2 value into a bounded C credential buffer. */
int ai_security_copy_api_key(char *dst, size_t cap,
                             const uint8_t *value, size_t value_len);

/*
 * Whether the service claimed the gateway X-Api-Key namespace.
 *
 * Wire value 0 is the compatibility state: no declaration, so a backend-owned
 * header must pass through unchanged. Every non-zero value is a declaration;
 * unknown values strip as the safe fallback even though admission fails them.
 */
int ai_security_should_strip_api_key(uint8_t policy);

/*
 * Remove X-Api-Key from an HTTP/2 name/value array when the service has
 * claimed the gateway credential namespace.  The output is a shallow copy;
 * nghttp2_submit_request copies the bytes before either source array is freed.
 */
size_t ai_security_filter_h2_headers(const nghttp2_nv *input, size_t input_len,
                                     nghttp2_nv *output, size_t output_cap,
                                     uint8_t policy);

#endif /* __SOCKPROXY_AI_SECURITY_H__ */
