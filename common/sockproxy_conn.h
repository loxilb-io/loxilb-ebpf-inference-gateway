/*
 * Copyright (c) 2022 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __SOCKPROXY_CONN_H__
#define __SOCKPROXY_CONN_H__

#include "sockproxy.h"

/* FD mapping */
int get_mapped_proxy_fd(int fd, int check_slot);

/* FD key extraction (sockmap) */
int proxy_skmap_key_from_fd(int fd, smap_key_t *skmap_key, int *protocol);

/* Socket setup utilities */
void proxy_sock_set_opts(int fd, uint8_t protocol);

/* Endpoint connection setup */
int proxy_setup_ep_connect(uint32_t epip, uint16_t epport, uint8_t protocol,
                           void *ssl_ctx, void **ssl, proxy_fd_ent_t *pfe,
                           const void *pp2hdr, int pp2len);

/* Listening socket initialization */
int proxy_sock_init(uint32_t IP, uint16_t port, uint8_t protocol);

/* Endpoint lookup */
int proxy_find_ep(uint32_t xip, uint16_t xport, uint8_t protocol,
                  uint32_t *epip, uint16_t *epport, uint8_t *epprotocol);

/* FD context management */
void proxy_try_free_fd_ctx(proxy_fd_ent_t *pfe);
int proxy_delete_entry__(proxy_ent_t *ent, proxy_arg_t *arg, int *mfd,
                         void **ssl_ctx, void **ssl_epctx);

#endif /* __SOCKPROXY_CONN_H__ */
