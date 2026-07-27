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

#ifndef __SOCKPROXY_SSL_H__
#define __SOCKPROXY_SSL_H__

#include "sockproxy.h"
#include <openssl/ssl.h>

/* SSL path / size constants */
#define PROXY_SSL_FNAME_SZ 128
#define PROXY_SSL_CERT_DIR "/opt/loxilb/cert"
#define PROXY_SSL_CA_DIR   "/etc/ssl/certs"

/* managed dir for certId-referenced TLS material.
 * Each certId lives under PROXY_SSL_CERTID_DIR/<certId>/ holding the PEM material
 * persisted by the Go REST handler (77-07): server.crt + server.key for frontend
 * certs; ca.crt + client.crt + client.key for backend re-encryption. The
 * Go handler owns dir creation with restrictive perms (0700 dir / 0600 keys,
 *); the C side only reads. */
#define PROXY_SSL_CERTID_DIR "/etc/loxilb/certs"

/* SSL context initialization / configuration */
/* @arg drives version-range + cipher pinning; pass NULL
 * for the legacy default-CTX path (today's hardcoded TLS1.2..1.3 + ciphers). */
SSL_CTX *proxy_server_ssl_ctx_init(const proxy_arg_t *arg);
int proxy_ssl_cfg_opts(SSL_CTX *ctx, const char *site_path, int mtls_en);
SSL_CTX *proxy_client_ssl_ctx_init(proxy_arg_t *arg);

/* TLS callbacks (used as function pointer arguments in proxy_add_entry) */
int alpn_select_callback(SSL *ssl,
                          const unsigned char **out,
                          unsigned char *outlen,
                          const unsigned char *in,
                          unsigned int inlen,
                          void *arg);
int sni_servername_callback(SSL *ssl, int *ad, void *arg);

/* Hostname-based SSL context lookup (returns void* to avoid SSL_CTX exposure) */
void *proxy_get_ssl_ctx_for_hostname(const char *hostname);

/* SNI certificate management */
int proxy_add_sni_certificate(const char *hostname, const char *cert_path);
int proxy_remove_sni_certificate(const char *hostname);
int proxy_list_sni_certificates(void (*callback)(const char *hostname, void *data),
                                void *user_data);
int proxy_list_sni_certificates_with_path(void (*callback)(const char *hostname,
                                                            const char *cert_path,
                                                            void *data),
                                           void *user_data);

/* =========================================================================
 * (..13): certId registry — management handle layered
 * OVER the hostname-keyed SNI store. The CGO layer (77-07) drives these after
 * persisting the inline-PEM upload to PROXY_SSL_CERTID_DIR/<certId>/. Selection
 * at handshake stays by hostname (the SNI callback is unchanged); certId is
 * purely the upload/rotate/delete handle.
 * ========================================================================= */

/* proxy_register_cert - Register a certId. Loads server.crt/server.key from the
 * managed dir, auto-derives the hostname(s) from the leaf cert SAN-DNS (CN
 * fallback), and registers EACH derived hostname into the SNI store via
 * the existing proxy_add_sni_certificate (no new loader).
 * @certId: opaque management handle (<= CERTID_MAX-1 chars)
 * Returns: number of hostnames registered (>=1) on success, negative errno on failure. */
int proxy_register_cert(const char *certId);

/* proxy_rotate_cert - Atomic zero-downtime rotation. Loads a fresh
 * SSL_CTX from the (already-updated) managed dir and swaps it into each SNI store
 * entry under the global_cert_lock write-lock; in-flight connections keep the old
 * SSL_CTX until they close (the old ctx is freed only after the swap).
 * Returns: 0 on success, negative errno on failure. */
int proxy_rotate_cert(const char *certId);

/* proxy_delete_cert - Remove a certId: unregister its derived hostnames from the
 * SNI store and free the registry entry (scoped — touches only this certId).
 * Returns: 0 on success, negative errno on failure. */
int proxy_delete_cert(const char *certId);

/* proxy_certid_resolve_backend -: resolve a backend certId into
 * the managed-dir CA / client-cert / client-key paths for the backend SSL_CTX
 * builder. Writes ca.crt / client.crt / client.key under
 * PROXY_SSL_CERTID_DIR/<certId>/ into the caller buffers (each >= 512 bytes).
 * A path is left empty ("") when its file is absent. certId == NULL/empty ⇒ all
 * outputs empty (today's "no backend material" behaviour).
 * Returns: 0 on success (even when files absent), negative errno on bad args. */
int proxy_certid_resolve_backend(const char *certId,
                                 char *ca_path_out,
                                 char *client_cert_path_out,
                                 char *client_key_path_out,
                                 size_t out_sz);

#endif /* __SOCKPROXY_SSL_H__ */
