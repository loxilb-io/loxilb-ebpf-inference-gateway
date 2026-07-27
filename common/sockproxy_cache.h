/*
 * Copyright (c) 2024 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */
#ifndef __SOCKPROXY_CACHE_H__
#define __SOCKPROXY_CACHE_H__

#include "sockproxy.h"

/*
 * sockproxy_cache.h - Xmit cache, backpressure, and logging helpers.
 *
 * This header is included by sockproxy.c and any future module that needs
 * to drain or account xmit data for a proxy_fd_ent_t.
 *
 * See sockproxy_refactoring_plan.md §6.1
 */

/* Per-connection byte accounting (TX / RX stats) */
void pfe_ent_accouting(proxy_fd_ent_t *pfe, uint64_t bc, int txdir);

/*
 * cmp_proxy_ent: temporary home until sockproxy_conn.c is created in.
 * See sockproxy_refactoring_plan.md §6.2 -- will move to sockproxy_conn.h.
 */
bool cmp_proxy_ent(proxy_ent_t *e1, proxy_ent_t *e2);

/* Add a data buffer to the xmit cache */
int  proxy_add_xmitcache(proxy_fd_ent_t *ent, uint8_t *cache, size_t len);

/* Free all cached entries for connection ent */
void proxy_destroy_xmitcache(proxy_fd_ent_t *ent);

/* Drain the xmit cache for connection ent (sends buffered data) */
int  proxy_xmit_cache(proxy_fd_ent_t *ent);

/* Check and release backpressure once cache drains below LOW_WATER */
void proxy_check_release_backpressure(proxy_fd_ent_t *ent);

/*
 * Cache backpressure thresholds.
 * Originally defined in sockproxy.c; moved here in so that
 * sockproxy_cache.c and any future consumer can reference them via this header.
 *
 * ADAPTIVE BACKPRESSURE: Different thresholds for chunked vs non-chunked.
 * Chunked encoding (text/JS/CSS): Lower threshold to prevent SSL timeout.
 * Binary transfers (images/videos): Higher threshold for performance.
 */
#define PROXY_CACHE_HIGH_WATER_CHUNKED (768 * 1024)       /* 768KB for chunked */
#define PROXY_CACHE_LOW_WATER_CHUNKED  (384 * 1024)       /* 384KB resume */
#define PROXY_CACHE_HIGH_WATER         (12 * 1024 * 1024) /* 12MB binary */
#define PROXY_CACHE_LOW_WATER          (4 * 1024 * 1024)  /* 4MB resume */

#endif /* __SOCKPROXY_CACHE_H__ */
