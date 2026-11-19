/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */
#ifndef __SOCKPROXY_EP_H__
#define __SOCKPROXY_EP_H__

#include "sockproxy.h"

/* Conversation mapping lifecycle constants */
#define CONVERSATION_MAPPING_TTL       3600  /* 1 hour TTL for learned session mappings */
#define CONVERSATION_CLEANUP_INTERVAL  300   /* Cleanup every 5 minutes */

struct radix_route_in;

/* Non-P/D prefix routing inputs of a request for a pool, gathered the same
 * way for the selection and for the HTTP/1.1 keep-alive leg decision:
 * eligible endpoints (route, health, breaker, drain), in-flight counts,
 * gates and namespace fields. At the keep-alive site (at_keepalive) a gate
 * that selection would apply but that cannot be evaluated there sets
 * gates_unknown. inflight must hold MAX_PROXY_EP entries. */
void sp_radix_gather(proxy_fd_ent_t *pfe, proxy_epval_t *pool,
                     const proxy_map_ent_t *node, int selector_pick, int pinned,
                     int at_keepalive, struct radix_route_in *in,
                     uint32_t *inflight);

/* HTTP/1.1 keep-alive: 1 when the kept backend leg must be released so that
 * the request is selected again (a radix HIT excludes the kept endpoint). */
int sp_radix_keepalive_moves(proxy_fd_ent_t *pfe, const proxy_map_ent_t *node);

/* Session key hash (also used by sockproxy_http.c) */
uint32_t session_key_hash(const char *session_key);

/* Conversation mapping API.
 *
 * `epv` names the pool the endpoint index belongs to and is REQUIRED: an
 * index is meaningless outside its own pool's eps[] (sockproxy_conv_pool.h).
 * get_ returns NULL when the stored mapping belongs to another pool, so the
 * caller re-selects instead of routing to another model's backend. */
conversation_mapping_t *get_conversation_mapping(proxy_map_ent_t *ent,
                                                  const char *conv_id,
                                                  const proxy_epval_t *epv);
int store_conversation_endpoint(proxy_map_ent_t *ent,
                                const char *conv_id,
                                int ep_idx,
                                const proxy_epval_t *epv);

/* Strip port from hostname helper -- e.g. "host:9090" -> "host" */
void strip_port_from_hostname(const char *host_with_port,
                               char *host_only,
                               size_t host_only_size);

/* Endpoint selection mega-function (all LB algorithm branches) */
int proxy_setup_ep__(uint32_t xip, uint16_t xport, uint8_t protocol,
                     const char *host_str,
                     const char *request_path,
                     const char *conv_id,
                     uint64_t prefix_hash,
                     const char *custom_session_header,
                     proxy_ep_sel_t *ep_sel,
                     proxy_epval_t **epv, int *seltype, uint32_t *rid,
                     void *ssl_ctx, void **ssl, uint32_t client_ip,
                     proxy_fd_ent_t *pfe,
                     const void *pp2hdr, int pp2len);

int proxy_setup_mcp_retry(proxy_fd_ent_t *pfe, proxy_ep_sel_t *out,
                          proxy_epval_t **epv, uint32_t *rid,
                          const void *pp2hdr, int pp2len);

/* Conversation mapping cleanup background thread */
void *proxy_conversation_cleanup_thread(void *arg);

/* Notification dispatch run loop (spawned by proxy_main) */
void *proxy_run(void *arg);

#endif /* __SOCKPROXY_EP_H__ */
