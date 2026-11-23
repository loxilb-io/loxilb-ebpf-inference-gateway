/*
 * Copyright (c) 2026 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 *
 * sockproxy_no_ep.h - the answer of a rule that has no endpoints.
 *
 * A host|path rule may be installed with no endpoints. A request that the
 * rule's pool takes is then answered here and goes nowhere else: it is not
 * handed to a shorter prefix, and no selector runs over an empty pool. The
 * rule says which answer (dp_proxy_tacts.no_ep_status, copied into the
 * pool):
 *
 *   SP_NO_EP_STATUS_503  503 no_healthy_backend  (the default)
 *   SP_NO_EP_STATUS_500  500 no_backend
 *
 * 503 keeps the code of the pool whose endpoints are all down: a client that
 * backs off on it, and an alert keyed on it, need nothing new. The detail
 * tells the two apart. 500 is for a rule whose backend the control plane
 * knows to be invalid. Neither is a refusal: no stage, recorded as the
 * request's completion with the status written (sp_send_local_outage,
 * h2_send_local_outage).
 */
#ifndef SOCKPROXY_NO_EP_H
#define SOCKPROXY_NO_EP_H

#include <stdint.h>
#include <stdio.h>

#define SP_NO_EP_STATUS_503 0
#define SP_NO_EP_STATUS_500 1

typedef struct sp_no_ep_answer {
  int status;
  const char *error;
  const char *detail;
} sp_no_ep_answer_t;

/* The answer for a rule's no_ep_status. A value this build does not know
 * answers as the default. */
static inline sp_no_ep_answer_t
sp_no_ep_answer(uint8_t no_ep_status)
{
  if (no_ep_status == SP_NO_EP_STATUS_500)
    return (sp_no_ep_answer_t){ 500, "no_backend",
                                "the rule has no usable backend" };
  return (sp_no_ep_answer_t){ 503, "no_healthy_backend",
                              "the rule has no endpoints" };
}

/* The HTTP/1.1 text of that answer, closing the connection as every outage
 * answer does. Returns its length, or -1 when it does not fit cap. */
static inline int
sp_no_ep_h1_text(uint8_t no_ep_status, char *buf, size_t cap)
{
  sp_no_ep_answer_t a = sp_no_ep_answer(no_ep_status);
  int n = snprintf(buf, cap,
                   "HTTP/1.1 %d %s\r\n"
                   "Content-Type: application/json\r\n"
                   "Connection: close\r\n"
                   "\r\n"
                   "{\"error\":\"%s\",\"detail\":\"%s\"}\r\n",
                   a.status,
                   a.status == 500 ? "Internal Server Error" : "Service Unavailable",
                   a.error, a.detail);

  if (n < 0 || (size_t)n >= cap)
    return -1;
  return n;
}

#endif /* SOCKPROXY_NO_EP_H */
