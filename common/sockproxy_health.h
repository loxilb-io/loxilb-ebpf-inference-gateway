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

#ifndef __SOCKPROXY_HEALTH_H__
#define __SOCKPROXY_HEALTH_H__

#include "sockproxy.h"

/* -------------------------------------------------------------------------
 * Universal endpoint health management
 * ------------------------------------------------------------------------- */

/* Returns 1 if endpoint ep_idx is healthy, 0 otherwise */
int is_endpoint_healthy(proxy_epval_t *tepval, int ep_idx);

/* Returns the next healthy endpoint index starting from start_idx, or -1 */
int find_next_healthy_endpoint(proxy_epval_t *tepval, int start_idx);

/* Select a healthy endpoint using the given algorithm; returns ep index or -1 */
int select_healthy_endpoint(proxy_epval_t *tepval, int algorithm_selection);

/* -------------------------------------------------------------------------
 * Circuit breaker
 * ------------------------------------------------------------------------- */

/* Initialize circuit breaker state for an endpoint */
void circuit_breaker_init(circuit_breaker_t *cb);

/* Returns 1 if the circuit breaker says to skip this endpoint, 0 otherwise */
int circuit_breaker_should_skip(proxy_epval_t *tepval, int ep_index);

/* Record a connection failure for the circuit breaker */
void circuit_breaker_record_failure(proxy_epval_t *tepval, int ep_index);
void circuit_breaker_record_origin_error(proxy_epval_t *tepval, int ep_index);
void circuit_breaker_record_origin_success(proxy_epval_t *tepval, int ep_index);

/* Record a connection success for the circuit breaker */
void circuit_breaker_record_success(proxy_epval_t *tepval, int ep_index);

/* -------------------------------------------------------------------------
 * Drain management helpers (also called from sockproxy.c proxy_update_ep_health)
 * ------------------------------------------------------------------------- */

/* Count active connections to a specific endpoint index */
uint32_t count_active_connections_to_endpoint(proxy_map_ent_t *ent, int ep_index);

/* Force-close all connections to a specific endpoint */
void force_close_endpoint_connections(proxy_map_ent_t *ent, int ep_index);

/* Remove all conversation/session mappings for an inactive endpoint */
uint32_t cleanup_endpoint_sessions(proxy_map_ent_t *ent, int ep_index);

/* -------------------------------------------------------------------------
 * Background drain checker thread
 * ------------------------------------------------------------------------- */

/* Background thread: periodically checks draining endpoints */
void *proxy_drain_checker_thread(void *arg);

#endif /* __SOCKPROXY_HEALTH_H__ */
