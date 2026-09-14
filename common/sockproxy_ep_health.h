/*
 * sockproxy_ep_health.h - which endpoint a health signal is about.
 *
 * A service with model-keyed rules holds several proxy_epval_t pools in
 * ent->val.ephash, and each pool numbers its own eps[] from 0. An endpoint
 * index is therefore meaningful only inside the pool that produced it, while
 * an endpoint ADDRESS names the same backend in every pool that carries it.
 *
 * The health path used to resolve a caller's index against whichever pool
 * hashed first: the loop body returned during its first iteration. On a
 * multi-pool service that marked a healthy backend down - and ran the session
 * sweep, the trie removal and the parked-client drain against it - while the
 * endpoint that had actually failed kept taking new connections. An in-range
 * index naming a live endpoint is indistinguishable from a correct one, so
 * nothing downstream could catch it.
 *
 * This is the same identity rule the conversation table follows
 * (sockproxy_conv_pool.h): name the pool, or key on something that does not
 * need one. Health keys on the address.
 *
 * Header-only and free of sockproxy.h on purpose, so the rule can be
 * exercised standalone (test_ep_health_pool.c) rather than needing the whole
 * proxy object graph.
 */
#ifndef __SOCKPROXY_EP_HEALTH_H__
#define __SOCKPROXY_EP_HEALTH_H__

#include <stdint.h>

/* Match any port on the address. A host-level signal - a GPU node turning red
 * - is about the host, so it applies to every listener on it. */
#define EP_HEALTH_ANY_PORT 0

/*
 * Is this endpoint the one the health signal is about?
 *
 * Address first, because that is what names the same backend across pools.
 * Port is compared only when the caller supplied one: a per-backend probe
 * knows the port and must not mark a sibling listener on the same host down,
 * while a host-level signal passes EP_HEALTH_ANY_PORT and means all of them.
 *
 * Both arguments are in the byte order the endpoint stores, so no conversion
 * happens here and callers cannot half-convert.
 */
static inline int
ep_health_addr_matches(uint32_t ep_xip, uint16_t ep_xport,
                       uint32_t want_ip, uint16_t want_port)
{
  if (ep_xip != want_ip)
    return 0;
  if (want_port == EP_HEALTH_ANY_PORT)
    return 1;
  return ep_xport == want_port;
}

/*
 * May a bare endpoint index be resolved on a service holding `n_pools` pools?
 *
 * Only when there is nothing to resolve. With one pool the index is
 * unambiguous. With more, it names a position in a list the caller never
 * identified, and picking one pool is a guess whose losing side marks the
 * wrong backend down. With none there is no endpoint at all.
 *
 * Fail closed: the caller is expected to fall back to the address-keyed
 * update, or to a full rule sync, either of which converges.
 */
static inline int
ep_health_index_is_resolvable(unsigned int n_pools)
{
  return n_pools == 1;
}

#endif /* __SOCKPROXY_EP_HEALTH_H__ */
