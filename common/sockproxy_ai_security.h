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

/* Admission lives in ai_gw_admit (sockproxy_ai_admit.h) — ONE gate for both
 * protocol parsers. This header keeps the HTTP/2 header-hygiene helpers. */

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
 * Full upstream header hygiene for one admitted HTTP/2 stream, the parity
 * twin of the H1 splice block (sockproxy_http.c):
 *   - X-Api-Key stripped when the service claimed the namespace (policy!=0);
 *   - on JWT-capable rules (jwt_capable), CLIENT-sent X-Auth-Tenant/User are
 *     stripped ALWAYS (verified-identity spoof), and Authorization is
 *     stripped when the deciding profile said so (strip_authz);
 *   - when the profile forwards identity (fwd_identity), the VERIFIED
 *     tenant/user are appended as X-Auth-Tenant/X-Auth-User. The injected
 *     values point at CALLER-owned storage (the stream identity fields);
 *     nghttp2_submit_request copies the bytes before they can go stale.
 * The output is a shallow copy; size output_cap for input_len + 2.
 */
size_t ai_security_h2_upstream_hygiene(const nghttp2_nv *input, size_t input_len,
                                       nghttp2_nv *output, size_t output_cap,
                                       uint8_t policy, int jwt_capable,
                                       int strip_authz, int fwd_identity,
                                       const char *tenant, const char *user);

/*
 * Remove X-Api-Key from an HTTP/2 name/value array when the service has
 * claimed the gateway credential namespace.  The output is a shallow copy;
 * nghttp2_submit_request copies the bytes before either source array is freed.
 * (Thin wrapper over the hygiene filter above with the JWT arms off.)
 */
size_t ai_security_filter_h2_headers(const nghttp2_nv *input, size_t input_len,
                                     nghttp2_nv *output, size_t output_cap,
                                     uint8_t policy);

#endif /* __SOCKPROXY_AI_SECURITY_H__ */
