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

/* Session key hash (also used by sockproxy_http.c) */
uint32_t session_key_hash(const char *session_key);

/* Conversation mapping API */
conversation_mapping_t *get_conversation_mapping(proxy_map_ent_t *ent,
                                                  const char *conv_id);
int store_conversation_endpoint(proxy_map_ent_t *ent,
                                const char *conv_id,
                                int ep_idx);

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
                     proxy_fd_ent_t *pfe);

/* Conversation mapping cleanup background thread */
void *proxy_conversation_cleanup_thread(void *arg);

/* Notification dispatch run loop (spawned by proxy_main) */
void *proxy_run(void *arg);

#endif /* __SOCKPROXY_EP_H__ */
