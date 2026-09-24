/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-clause)
 *
 * Copyright (c) 2024-2025 LoxiLB Authors
 *
 * test_sockmap_gate.c — the per-direction sockmap gate.
 *
 * Includes ONLY the pure header, so it runs without the proxy object graph:
 *
 *   T1  a service that declares nothing owns nothing: every mode pairs as asked
 *       (the control -- a gate that took every direction away would pass every
 *       case below and prove nothing).
 *   T2  a declared credential owns the request direction and not the response
 *       one, for the strip alone and for the strip together with AI-gateway
 *       mode (which the credential arms): "response" pairs, "request" and
 *       "both" do not pair the request direction.
 *   T3  streaming, disaggregation and an attached L7 policy own both
 *       directions, alone and combined with a credential: nothing pairs.
 *   T4  the reduction keeps what the service does not own: "both" on a
 *       request-owning service pairs responses only, and an owned direction
 *       asked for on its own leaves the connection on the relay.
 *
 * Build: $(CC) -Wall -Wextra -o test_sockmap_gate test_sockmap_gate.c -I.
 * Run:   ./test_sockmap_gate
 */
#include <stdio.h>
#include <string.h>

#include "sockproxy_sockmap_gate.h"

static int g_failures = 0;

#define CHECK(cond, msg) do {                                          \
    if (cond) {                                                        \
      printf("  [PASS] %s\n", (msg));                                  \
    } else {                                                           \
      printf("  [FAIL] %s  (%s:%d)\n", (msg), __FILE__, __LINE__);     \
      g_failures++;                                                    \
    }                                                                  \
  } while (0)

#define MODE_OFF  0
#define MODE_BOTH 1
#define MODE_REQ  2
#define MODE_RESP 3

static uint8_t
reduce(const sockmap_gate_in_t *in, uint8_t mode)
{
  int own_req, own_resp;

  sockmap_gate_owned_dirs(in, &own_req, &own_resp);
  return sockmap_gate_reduce(mode, own_req, own_resp);
}

int
main(void)
{
  sockmap_gate_in_t none = { 0 };
  sockmap_gate_in_t strip = { 0 };
  sockmap_gate_in_t cred = { 0 };
  sockmap_gate_in_t sse = { 0 };
  sockmap_gate_in_t pd = { 0 };
  sockmap_gate_in_t l7 = { 0 };
  sockmap_gate_in_t cred_sse = { 0 };
  sockmap_gate_in_t cred_l7 = { 0 };
  int own_req, own_resp;

  strip.strips_api_key = 1;                  /* an explicit "disabled": strip only */
  cred.strips_api_key = 1;                   /* required / jwt / apikey-or-jwt: */
  cred.ai_gw_mode = 1;                       /*   the strip plus admission     */
  sse.sse_mode = 1;
  sse.ai_gw_mode = 1;
  pd.pd_disagg_mode = 1;
  pd.ai_gw_mode = 1;
  l7.has_l7_policy = 1;
  cred_sse = cred;
  cred_sse.sse_mode = 1;
  cred_l7 = cred;
  cred_l7.has_l7_policy = 1;

  printf("T1: no declaration owns nothing\n");
  sockmap_gate_owned_dirs(&none, &own_req, &own_resp);
  CHECK(!own_req && !own_resp, "neither direction owned");
  CHECK(reduce(&none, MODE_BOTH) == MODE_BOTH, "both pairs as asked");
  CHECK(reduce(&none, MODE_REQ) == MODE_REQ, "request pairs as asked");
  CHECK(reduce(&none, MODE_RESP) == MODE_RESP, "response pairs as asked");
  CHECK(reduce(&none, MODE_OFF) == MODE_OFF, "off stays off");

  printf("T2: a credential owns the request direction only\n");
  sockmap_gate_owned_dirs(&strip, &own_req, &own_resp);
  CHECK(own_req && !own_resp, "strip alone: request owned, response free");
  sockmap_gate_owned_dirs(&cred, &own_req, &own_resp);
  CHECK(own_req && !own_resp, "strip + admission: request owned, response free");
  CHECK(reduce(&cred, MODE_RESP) == MODE_RESP, "response pairs on a credential service");
  CHECK(reduce(&cred, MODE_REQ) == MODE_OFF, "request alone does not pair");
  CHECK(reduce(&strip, MODE_RESP) == MODE_RESP, "response pairs on a strip-only service");

  printf("T3: streaming, disaggregation and an L7 policy own both directions\n");
  sockmap_gate_owned_dirs(&sse, &own_req, &own_resp);
  CHECK(own_req && own_resp, "sse_mode owns both");
  sockmap_gate_owned_dirs(&pd, &own_req, &own_resp);
  CHECK(own_req && own_resp, "pd_disagg owns both");
  sockmap_gate_owned_dirs(&l7, &own_req, &own_resp);
  CHECK(own_req && own_resp, "an L7 policy owns both");
  CHECK(reduce(&sse, MODE_RESP) == MODE_OFF, "sse_mode: response does not pair");
  CHECK(reduce(&cred_sse, MODE_RESP) == MODE_OFF, "credential + sse_mode: response does not pair");
  CHECK(reduce(&cred_l7, MODE_RESP) == MODE_OFF, "credential + L7 policy: response does not pair");
  CHECK(reduce(&l7, MODE_BOTH) == MODE_OFF, "L7 policy: nothing pairs");

  printf("T4: the reduction keeps the direction the service does not own\n");
  CHECK(reduce(&cred, MODE_BOTH) == MODE_RESP, "both on a credential service pairs responses only");
  CHECK(reduce(&strip, MODE_BOTH) == MODE_RESP, "both on a strip-only service pairs responses only");
  CHECK(sockmap_gate_reduce(MODE_BOTH, 0, 1) == MODE_REQ, "a response-owning service keeps the request direction");
  CHECK(sockmap_gate_reduce(MODE_RESP, 0, 1) == MODE_OFF, "an owned direction asked for alone stays on the relay");

  if (g_failures) {
    printf("FAILED: %d check(s)\n", g_failures);
    return 1;
  }
  printf("OK\n");
  return 0;
}
