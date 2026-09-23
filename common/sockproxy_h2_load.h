/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Bounded-load accounting for HTTP/2 stream mappings.
 *
 * The CHWBL and WRR_HASH selectors keep one `active_conns` unit per unit of
 * work they routed, and use the sum to decide whether a hashed endpoint may
 * take one more. On HTTP/1.1 that unit is the connection: the selector takes
 * it when it picks the endpoint and proxy_release_fd_ctx hands it back when
 * the connection closes. HTTP/2 multiplexes many requests over one
 * connection, so there the unit is the STREAM MAPPING (client stream ->
 * backend stream): taken when the mapping is created, released when the
 * mapping is freed, and never by the connection. A connection that held units
 * per stream must therefore not release a connection unit at teardown — that
 * is what conn_holds_load_unit() answers.
 *
 * Pure header: only the selector runtime entry points, so the contract test
 * links it against sockproxy_lb.c alone.
 */
#ifndef __SOCKPROXY_H2_LOAD_H__
#define __SOCKPROXY_H2_LOAD_H__

#include "sockproxy.h"
#include "sockproxy_lb.h"

/* Whether this pool keeps bounded-load units at all. Mirrors the condition
 * chwbl_inc_runtime / chwbl_dec_runtime apply, so a unit is recorded as held
 * exactly when one was really taken. */
static inline int
h2_load_units_active(const proxy_epval_t *epv)
{
  return epv &&
         (epv->select == PROXY_SEL_CHWBL || epv->select == PROXY_SEL_WRR_HASH) &&
         epv->chwbl_config != NULL;
}

/* Take one unit on (pool, endpoint) for a stream mapping. Returns 1 when the
 * mapping now holds a unit and must release it, 0 when the pool does not keep
 * units (nothing to release later). */
static inline int
h2_load_unit_take(proxy_epval_t *epv, int ep_idx)
{
  if (!h2_load_units_active(epv) || ep_idx < 0 || ep_idx >= MAX_PROXY_EP)
    return 0;
  chwbl_inc_runtime(epv, ep_idx);
  return 1;
}

/* Release the unit a mapping holds, exactly once: `held` is cleared on the
 * first call so a second release (backend stream close followed by session
 * teardown, or the reverse) is a no-op instead of an underflow. */
static inline void
h2_load_unit_release(proxy_epval_t *epv, int ep_idx, int *held)
{
  if (!held || !*held)
    return;
  *held = 0;
  chwbl_dec_runtime(epv, ep_idx);
}

/* Does this connection hold a bounded-load unit of its own? True for an
 * HTTP/1.1 leg that routed (the selector counted the connection); false for
 * any HTTP/2 leg, whose units live on its stream mappings. The teardown
 * release in proxy_release_fd_ctx is gated on this. */
static inline int
conn_holds_load_unit(const proxy_fd_ent_t *pfe)
{
  return pfe && pfe->epv && pfe->ep_num >= 0 && !pfe->load_units_per_stream;
}

#endif /* __SOCKPROXY_H2_LOAD_H__ */
