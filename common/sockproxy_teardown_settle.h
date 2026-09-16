/*
 * sockproxy_teardown_settle.h - which connections a teardown owes a settle.
 *
 * proxy_pdestroy() runs in two shapes. One connection can go away on its own,
 * or the rule's main fd can go away and take every connection on the rule with
 * it. The shape decides WHICH connections the teardown must walk. It does not
 * decide whether a walked connection settles.
 *
 * That distinction used to be lost. Every settle block in proxy_pdestroy - the
 * HTTP/1.1 reservation release, the missing-usage report and the HTTP/2
 * in-flight collect - was guarded by `!is_listener`, while the listener branch
 * freed each connection outright. The in-code justification was that "a rule
 * delete is taking the pools with it regardless", and for the pools that is
 * true. It is not true for the claim: the endpoint pools are per-rule, but the
 * token bucket is per-TENANT and outlives the rule. Freeing a connection
 * without handing its claim back therefore withdraws headroom from every other
 * service still serving that tenant, for up to a full quota epoch, for requests
 * that burned nothing - precisely the harm the reservation release exists to
 * prevent, in its own words.
 *
 * So the rule is: a connection holding an unspent claim owes that claim back in
 * BOTH shapes. Answering otherwise for the listener shape is the defect this
 * header exists to prevent.
 *
 * Header-only and free of sockproxy.h on purpose, so the rule can be exercised
 * standalone (test_teardown_settle.c) rather than needing the whole proxy
 * object graph - the same reason sockproxy_ep_health.h is shaped this way.
 */
#ifndef __SOCKPROXY_TEARDOWN_SETTLE_H__
#define __SOCKPROXY_TEARDOWN_SETTLE_H__

#include <stdint.h>

/* The two shapes proxy_pdestroy runs in. */
#define TEARDOWN_CONN     0   /* this connection alone is going away */
#define TEARDOWN_LISTENER 1   /* the rule's main fd is going away, and every
                               * connection on the rule goes with it */

/*
 * A connection reduced to what decides settlement. Mirrors the proxy_fd_ent_t
 * fields the three collection blocks read, and nothing else, so the rule can be
 * driven without constructing a pfe.
 */
typedef struct {
  int odir;                    /* 0 = client, 1 = backend */
  int ai_gw_mode;
  int usage_reserved_toks;     /* the unspent admission claim */
  int usage_consumed;
  int has_tenant;              /* tenant_id[0] != '\0' */
  int has_h2_session;
  int metric_ai_recorded;
  int metric_response_status;
} teardown_conn_t;

/* 2xx, matching proxy_status_is_2xx. Restated rather than included so this
 * header stays free of the proxy object graph. */
static inline int
teardown_status_is_2xx(int status)
{
  return status >= 200 && status < 300;
}

/*
 * An admission-time reservation this connection never settled. Node-local and
 * epoch-tagged, so it self-heals when the window rolls - but until then it
 * counts against the tenant's headroom and can deny admissions for a request
 * that died before it burned anything.
 */
static inline int
teardown_owes_resv_rel(const teardown_conn_t *c)
{
  return c && c->ai_gw_mode && c->usage_reserved_toks &&
         !c->usage_consumed && c->has_tenant;
}

/*
 * The connection's last response completed with no readable usage object. The
 * per-request boundary reports that for every response a request N+1 follows;
 * the last one is followed by nothing, so without this the common
 * single-request shape would never report at all.
 */
static inline int
teardown_owes_usage_missing(const teardown_conn_t *c)
{
  return c && c->odir == 0 && c->ai_gw_mode && c->metric_ai_recorded &&
         !c->usage_consumed &&
         teardown_status_is_2xx(c->metric_response_status);
}

/*
 * An HTTP/2 client connection can carry many admitted or keyless streams that
 * never reached their own close. On an abrupt teardown nghttp2 never runs each
 * stream's close callback, so those streams never released their reservation
 * nor recorded their request.
 */
static inline int
teardown_owes_h2_collect(const teardown_conn_t *c)
{
  return c && c->odir == 0 && c->has_h2_session;
}

/*
 * Does a teardown of this shape walk connections other than the pfe itself?
 *
 * This is the ONLY question the shape is allowed to answer.
 */
static inline int
teardown_walks_peer_conns(int shape)
{
  return shape == TEARDOWN_LISTENER;
}

/*
 * THE RULE. Does this walked connection owe a deferred settle?
 *
 * `shape` is accepted and deliberately ignored. It is in the signature so that
 * a caller reaching for "...but not when the rule is going away" has to delete
 * this call to get it, rather than adding a guard beside it. Returning 0 here
 * for TEARDOWN_LISTENER is the defect this header prevents; see the file
 * header for why
 * the pools argument does not carry over to the claim.
 */
static inline int
teardown_conn_owes_settle(int shape, const teardown_conn_t *c)
{
  (void)shape;   /* the shape decides the walk set, never the settle */
  return teardown_owes_resv_rel(c) || teardown_owes_usage_missing(c) ||
         teardown_owes_h2_collect(c);
}

#endif /* __SOCKPROXY_TEARDOWN_SETTLE_H__ */
