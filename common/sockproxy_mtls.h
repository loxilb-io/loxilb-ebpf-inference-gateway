/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */

#ifndef __SOCKPROXY_MTLS_H__
#define __SOCKPROXY_MTLS_H__

#ifdef HAVE_MTLS

#include <openssl/ssl.h>
#include "sockproxy.h"

/**
 * mtls_configure_frontend - Configure frontend (client-facing) mTLS
 * @ctx: SSL_CTX for frontend connections
 * @arg: Proxy configuration with mTLS settings
 * 
 * Configures client certificate verification based on proxy_arg_t settings.
 * Modes:
 *   0 (disabled): No client cert verification
 *   1 (optional): Accept connections with or without client cert
 *   2 (required): Reject connections without valid client cert
 * 
 * Returns: 0 on success, negative error code on failure
 */
int mtls_configure_frontend(SSL_CTX *ctx, proxy_arg_t *arg);

/**
 * mtls_configure_backend - Configure backend (upstream) mTLS
 * @ctx: SSL_CTX for backend connections
 * @arg: Proxy configuration with mTLS settings
 * 
 * Configures:
 *   - Backend server certificate verification (if backend_verify_cert=1)
 *   - Client certificate presentation to backend (if paths specified)
 * 
 * Returns: 0 on success, negative error code on failure
 */
int mtls_configure_backend(SSL_CTX *ctx, proxy_arg_t *arg);

/**
 * mtls_match_cn_pattern - Match certificate CN against pattern
 * @cert: X509 certificate
 * @pattern: Pattern to match (supports wildcards like "*.example.com")
 * 
 * Returns: 1 if matches, 0 if not
 */
int mtls_match_cn_pattern(X509 *cert, const char *pattern);

/**
 * g_ssl_ctx_proxy_arg_index - OpenSSL ex_data index for proxy_arg_t storage
 * Used by both sockproxy_mtls.c and sockproxy.c to store/retrieve mTLS config
 */
extern int g_ssl_ctx_proxy_arg_index;

/**
 * mtls_ssl_conn_state_t - Per-SSL-connection mTLS configuration snapshot.
 *
 * This struct is allocated in sni_servername_callback() as an OWNED copy of the
 * mTLS fields from proxy_arg_t that mtls_client_verify_callback() needs.
 *
 * Motivation: the SNI callback calls SSL_set_SSL_CTX() to swap in a per-hostname
 * SSL_CTX. That new SSL_CTX has no proxy_arg stored in its ex_data (it was stored
 * on the original SSL_CTX). To survive the SSL_CTX switch AND survive concurrent
 * rule deletion (which frees proxy_arg), we copy the needed fields into a small
 * heap-allocated struct that is owned by the SSL connection. It is freed
 * automatically by OpenSSL when SSL_free() is called via the cleanup callback
 * registered for g_ssl_proxy_arg_index.
 *
 * Lifecycle:
 *   alloc:  sni_servername_callback()    — once per TLS handshake
 *   free:   mtls_ssl_conn_state_cleanup() — called by SSL_free()
 */
typedef struct {
    uint8_t require_client_cn;       /* copy of proxy_arg_t::require_client_cn  */
    char    client_cn_pattern[256];  /* copy of proxy_arg_t::client_cn_pattern  */
} mtls_ssl_conn_state_t;

/**
 * g_ssl_proxy_arg_index - OpenSSL SSL-level ex_data index for
 *                         mtls_ssl_conn_state_t storage.
 *
 * Stores a per-connection OWNED snapshot (mtls_ssl_conn_state_t) that is
 * allocated in sni_servername_callback() and freed automatically by the
 * mtls_ssl_conn_state_cleanup() callback when the SSL connection is destroyed.
 *
 * This is the production-safe replacement for storing the raw proxy_arg_t*,
 * which would be a use-after-free hazard when the rule is deleted while a
 * TLS handshake is still in progress.
 */
extern int g_ssl_proxy_arg_index;

#endif /* HAVE_MTLS */

#endif /* __SOCKPROXY_MTLS_H__ */
