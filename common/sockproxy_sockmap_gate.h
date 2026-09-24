/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-clause)
 *
 * Copyright (c) 2024-2025 LoxiLB Authors
 *
 * sockproxy_sockmap_gate.h — which directions of a connection the service's
 * data plane owns, and therefore cannot hand to the kernel.
 *
 * Sockmap acceleration replaces the userspace relay for a direction: from the
 * moment a direction is paired, userspace neither sees nor rewrites its bytes.
 * A declaration that puts per-request or per-response work on the relay owns
 * that direction, and the pairing must leave it alone. The declarations are
 * not symmetric:
 *
 *   an attached L7 policy    both — insertHeaders and X-Forwarded-* rewrite
 *                            every request; HTTP_COOKIE persistence injects
 *                            Set-Cookie into responses
 *   sse_mode, pd_disagg      both — admission re-runs at every keep-alive
 *                            request, and each request is recorded from its
 *                            response
 *   AI-gateway mode          request — every request re-enters the parser for
 *                            the admission gate; what it reads from responses
 *                            (usage, stream end) is accounting, and the control
 *                            plane accepts losing it on a service whose only
 *                            declaration is a credential (it warns once)
 *   a declared apikey_auth   request — the credential verdict and the
 *                            X-Api-Key strip happen before dispatch, on every
 *                            request; nothing in it touches a response byte
 *
 * So a service that declares api_key_auth and nothing else keeps its request
 * direction on the relay, where the credential is checked on every request of
 * a keep-alive connection, and hands the response direction — where the bytes
 * of an inference are — to the kernel. That is the selective offload the
 * response-only mode exists for.
 *
 * Pure header: plain integers in, plain integers out, no proxy object graph,
 * so test_sockmap_gate.c runs it without a link library.
 */
#ifndef __SOCKPROXY_SOCKMAP_GATE_H__
#define __SOCKPROXY_SOCKMAP_GATE_H__

#include <stdint.h>

/* The rule facts the gate reads, as the proxy carries them per endpoint. */
typedef struct sockmap_gate_in {
  uint8_t has_l7_policy;   /* an L7 policy is attached to the rule */
  uint8_t sse_mode;        /* streaming accounting per request/response */
  uint8_t pd_disagg_mode;  /* prefill/decode disaggregation */
  uint8_t ai_gw_mode;      /* AI-gateway admission on every request */
  uint8_t strips_api_key;  /* ai_security_should_strip_api_key(apikey_auth) */
} sockmap_gate_in_t;

/* Which directions the service owns: own_req for client->backend bytes,
 * own_resp for backend->client bytes. */
static inline void
sockmap_gate_owned_dirs(const sockmap_gate_in_t *in, int *own_req, int *own_resp)
{
  int both = in->has_l7_policy || in->sse_mode || in->pd_disagg_mode;

  *own_req = both || in->ai_gw_mode || in->strips_api_key;
  *own_resp = both;
}

/* The mode a connection may still be paired with, given the directions its
 * service owns. mode is the rule's sockmap_en: 0=off, 1=both, 2=request,
 * 3=response. An owned direction is taken away and the rest is kept: a rule
 * asking for both on a service that owns only requests pairs its responses,
 * which is what the control plane would have accepted for it. 0 means the
 * connection stays on the userspace relay in both directions. */
static inline uint8_t
sockmap_gate_reduce(uint8_t mode, int own_req, int own_resp)
{
  int req = (mode == 1 || mode == 2) && !own_req;
  int resp = (mode == 1 || mode == 3) && !own_resp;

  if (req && resp) {
    return 1;
  }
  if (req) {
    return 2;
  }
  if (resp) {
    return 3;
  }
  return 0;
}

#endif /* __SOCKPROXY_SOCKMAP_GATE_H__ */
