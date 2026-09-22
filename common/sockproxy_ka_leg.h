/*
 * sockproxy_ka_leg.h - whether a keep-alive request may ride the backend leg
 * its predecessor used.
 *
 * On an AI-gateway connection every request has to pass the admission gate
 * (credential, rate, model, quota). The gate runs inside the request parser,
 * and the parser used to run only while the connection had no backend leg,
 * so the request boundary released the leg to force the parse. That made the
 * reconnect a by-product of the gate, at one ephemeral port per request:
 * TIME-WAIT toward the backends grew by the request rate, and at a few
 * thousand requests a second the port range ran out and the backends
 * answered with resets. The parse phase is now keyed on an explicit flag, so
 * the gate re-runs while the leg stays up, and THIS rule decides whether the
 * framed request may use that leg or must select an endpoint afresh.
 *
 * Keep the leg unless routing would have taken the request elsewhere:
 *   - there is no live leg (nothing to keep);
 *   - the leg is not pinned to a known endpoint (health cannot be judged);
 *   - the pinned endpoint is no longer healthy (health probe, circuit breaker);
 *   - the request names a different model than the one the leg was selected
 *     for (a model-routed pool may serve it from another endpoint).
 * A rule change already takes every connection on the rule down with the
 * listener, and a backend that closes its side ends the leg by itself, so
 * neither needs a case here.
 *
 * Header-only and free of sockproxy.h on purpose, so the rule can be
 * exercised standalone (test_ka_leg.c) - the same shape as
 * sockproxy_teardown_settle.h.
 */
#ifndef __SOCKPROXY_KA_LEG_H__
#define __SOCKPROXY_KA_LEG_H__

#include <string.h>

/* Why a leg was released; KA_LEG_KEPT when it was not. */
#define KA_LEG_KEPT        0
#define KA_LEG_NO_LEG      1   /* rfd[0] <= 0: the previous request left none */
#define KA_LEG_UNPINNED    2   /* no endpoint index/pool on the connection */
#define KA_LEG_UNHEALTHY   3   /* the pinned endpoint failed its health check */
#define KA_LEG_MODEL       4   /* this request names a different model */

/*
 * A connection reduced to what decides reuse. Mirrors the proxy_fd_ent_t
 * fields the decision reads, and nothing else, so the rule can be driven
 * without constructing a pfe.
 */
typedef struct {
  int leg_live;             /* rfd[0] > 0 && rfd_ent[0] != NULL */
  int ep_pinned;            /* epv != NULL && ep_num >= 0 */
  int ep_healthy;           /* is_endpoint_healthy(epv, ep_num) */
  const char *prev_model;   /* model the leg was selected for (resp_model) */
  const char *next_model;   /* this request's effective model */
} ka_leg_ctx_t;

static inline int
ka_leg_model_differs(const char *prev, const char *next)
{
  const char *p = prev ? prev : "";
  const char *n = next ? next : "";
  return strcmp(p, n) != 0;
}

/* Returns 1 when the framed request may be forwarded on the existing leg,
 * 0 when the leg must be released and an endpoint selected afresh. *reason
 * names the case (KA_LEG_*). */
static inline int
ka_leg_reusable(const ka_leg_ctx_t *c, int *reason)
{
  int why = KA_LEG_KEPT;

  if (!c->leg_live) {
    why = KA_LEG_NO_LEG;
  } else if (!c->ep_pinned) {
    why = KA_LEG_UNPINNED;
  } else if (!c->ep_healthy) {
    why = KA_LEG_UNHEALTHY;
  } else if (ka_leg_model_differs(c->prev_model, c->next_model)) {
    why = KA_LEG_MODEL;
  }
  if (reason) {
    *reason = why;
  }
  return why == KA_LEG_KEPT;
}

static inline const char *
ka_leg_reason_str(int reason)
{
  switch (reason) {
  case KA_LEG_KEPT:      return "kept";
  case KA_LEG_NO_LEG:    return "no-leg";
  case KA_LEG_UNPINNED:  return "unpinned";
  case KA_LEG_UNHEALTHY: return "ep-unhealthy";
  case KA_LEG_MODEL:     return "model-changed";
  default:               return "?";
  }
}

#endif /* __SOCKPROXY_KA_LEG_H__ */
