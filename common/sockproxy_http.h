/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 *
 * sockproxy_http.h — Public interface for sockproxy_http.c.
 * Only declares symbols NOT already covered by sockproxy.h / sockproxy_internal.h.
 * Extracted from sockproxy.c — see sockproxy_refactoring_plan.md.
 */
#ifndef __SOCKPROXY_HTTP_H__
#define __SOCKPROXY_HTTP_H__

#include "sockproxy.h"     /* proxy_fd_ent_t, proxy_map_ent_t, etc. */
#include "sockproxy_ep.h"  /* proxy_ep_sel_t */

/* -------------------------------------------------------------------------
 * Session / cache configuration constants
 * PROXY_SESSION_CLEANUP_INTERVAL is used by proxy_notifier (sockproxy.c),
 * so it must be visible outside of sockproxy_http.c.
 * ------------------------------------------------------------------------- */
#define PROXY_SESSION_TIMEOUT           300   /* 5 minutes in seconds */
#define PROXY_SESSION_CLEANUP_INTERVAL   60   /* Cleanup every 60 seconds */

/* -------------------------------------------------------------------------
 * PII / LlamaFirewall initialization state
 * Defined in sockproxy_http.c; used from sockproxy.c (proxy_notifier/proxy_main)
 * ------------------------------------------------------------------------- */
#ifdef HAVE_PII_DETECTION
extern _Atomic int g_presidio_initialized;
int presidio_is_initialized(void);
void presidio_set_initialized(int initialized);
#endif

#ifdef HAVE_LLAMAFIREWALL
extern _Atomic int g_llamafirewall_initialized;
int llamafirewall_is_initialized(void);
void llamafirewall_set_initialized(int initialized);
#endif

/* -------------------------------------------------------------------------
 * Event-loop path helpers — called from proxy_notifier in sockproxy.c
 * (all other proxy_* CGO functions are already declared in sockproxy.h)
 * ------------------------------------------------------------------------- */

/* Endpoint transmit — send buffered data to selected endpoint */
int proxy_try_epxmit(proxy_fd_ent_t *ent, void *msg, size_t len, int sel);

/* FD lifecycle — destroy per-fd private state (used as notify pdestroy cb) */
void proxy_pdestroy(void *priv);

/* Session housekeeping — expire idle sessions (called from proxy_notifier) */
void cleanup_expired_sessions(void);

/* Accept-path handler — called from proxy_notifier for NOTI_TYPE_IN on listeners */
int handle_new_connection(int fd, proxy_fd_ent_t *pfe, proxy_map_ent_t *ent,
                          struct llb_sockmap_key *key, struct llb_sockmap_key *rkey,
                          proxy_ep_sel_t *ep_sel);

/* Data-path handler — called from proxy_notifier for NOTI_TYPE_IN on active FDs */
int handle_client_data(int fd, proxy_fd_ent_t *pfe,
                       struct llb_sockmap_key *key, struct llb_sockmap_key *rkey);

/* -------------------------------------------------------------------------
 * pd_framing_v2 runtime feature-flag (REQ-R2)
 * pd_framing_v2_test_set — force the LLB_PD_FRAMING_V2 gate without
 * setenv/unsetenv races in unit tests (test_resp_framing.c) and the
 * mismatched-flag HA variant. Mirrors kv_hash_debug_test_set.
 * ------------------------------------------------------------------------- */
void pd_framing_v2_test_set(int on);

#endif /* __SOCKPROXY_HTTP_H__ */

