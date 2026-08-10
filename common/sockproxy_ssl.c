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

/*
 * sockproxy_ssl.c - SSL/TLS context management, SNI certificate CRUD,
 *                   and ALPN/SNI callbacks for LoxiLB proxy.
 *
 * Extracted from sockproxy.c as of the refactoring plan.
 * Contains:
 *   - alpn_select_callback (ALPN protocol selection during TLS handshake)
 *   - sni_servername_callback (SNI certificate selection callback)
 *   - proxy_server_ssl_ctx_init / proxy_ssl_cfg_opts
 *   - proxy_client_ssl_ctx_init
 *   - proxy_load_ssl_ctx_for_host
 *   - SNI certificate management: proxy_add_sni_certificate,
 *     proxy_remove_sni_certificate, proxy_list_sni_certificates
 *   - proxy_get_ssl_ctx_for_hostname
 */

#include "uthash.h"
#include "log.h"
#include <linux/types.h>
#include <stdatomic.h>
#include <bpf.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "common_pdi.h"
#include "llb_dpapi.h"
#include "sockproxy_internal.h"
#include "sockproxy_ssl.h"
#ifdef HAVE_MTLS
#include "sockproxy_mtls.h"
#endif /* HAVE_MTLS */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <sys/stat.h>


/**
 * ALPN selection callback (server mode)
 * Called by OpenSSL during TLS handshake to select application protocol
 * 
 * HTTP/2 TRANSIT MODE - FULLY IMPLEMENTED ✅
 * ========================================
 * Implementation Status (as of 2025-11-26):
 *   ✅ HTTP/2 client connection handling (nghttp2 server mode)
 *   ✅ HTTP/2 backend connection handling (nghttp2 client mode)
 *   ✅ HTTP/2 request forwarding (client → backend)
 *   ✅ HTTP/2 response forwarding (backend → client)
 *   ✅ Stream multiplexing and mapping
 *   ✅ Event loop integration for backend responses
 *   ✅ All critical bug fixes applied
 * 
 * Protocol Selection Strategy:
 *   Respects backend_protocol_cap configuration:
 *   - backend_protocol_cap == 0: HTTP/1.1 only (force HTTP/1.1)
 *   - backend_protocol_cap == 1: HTTP/2 (h2) only (force HTTP/2)
 *   - backend_protocol_cap == 2: HTTP/2 preferred, HTTP/1.1 fallback (default)
 * 
 * See: HTTP2_TRANSIT_MODE_CRITICAL_FIXES.md for implementation details
 */
int
alpn_select_callback(SSL *ssl,
                      const unsigned char **out,
                      unsigned char *outlen,
                      const unsigned char *in,
                      unsigned int inlen,
                      void *arg)
{
  (void)ssl;  // Unused parameter
  
  // Extract backend protocol capability from arg (passed from SSL_CTX_set_alpn_select_cb)
  uint8_t *backend_cap_ptr = (uint8_t *)arg;
  uint8_t backend_cap = backend_cap_ptr ? *backend_cap_ptr : 2;  // Default: h2+http/1.1
  
  // backend_protocol_cap == 0: HTTP/1.1 only
  if (backend_cap == 0) {
    if (SSL_select_next_proto((unsigned char **)out, outlen,
                               (const unsigned char *)"\x08http/1.1", 9,
                               in, inlen) == OPENSSL_NPN_NEGOTIATED) {
      return SSL_TLSEXT_ERR_OK;
    }
    // Client doesn't support HTTP/1.1 - force it anyway (shouldn't happen)
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_warn("[ALPN] Backend is http/1.1 only, but client doesn't advertise it - forcing HTTP/1.1");
#endif
    *out = (const unsigned char *)"http/1.1";
    *outlen = 8;
    return SSL_TLSEXT_ERR_OK;
  }
  
  // backend_protocol_cap == 1: HTTP/2 only
  if (backend_cap == 1) {
    if (SSL_select_next_proto((unsigned char **)out, outlen,
                               (const unsigned char *)"\x02h2", 3,
                               in, inlen) == OPENSSL_NPN_NEGOTIATED) {
      return SSL_TLSEXT_ERR_OK;
    }
    // Client doesn't support HTTP/2 - fail negotiation
    log_error("[ALPN] Backend is h2 only, but client doesn't support it - negotiation failed");
    return SSL_TLSEXT_ERR_ALERT_FATAL;
  }
  
  // backend_protocol_cap == 2 (or default): HTTP/2 preferred, HTTP/1.1 fallback
  // Try HTTP/2 first (preferred protocol for modern clients)
  if (SSL_select_next_proto((unsigned char **)out, outlen,
                             (const unsigned char *)"\x02h2", 3,
                             in, inlen) == OPENSSL_NPN_NEGOTIATED) {
    return SSL_TLSEXT_ERR_OK;
  }
  
  // Fallback to HTTP/1.1 if client doesn't support HTTP/2
  if (SSL_select_next_proto((unsigned char **)out, outlen,
                             (const unsigned char *)"\x08http/1.1", 9,
                             in, inlen) == OPENSSL_NPN_NEGOTIATED) {
    return SSL_TLSEXT_ERR_OK;
  }
  
  // No common protocol - default to HTTP/1.1 for maximum compatibility
#ifdef HAVE_PROXY_EXTRA_DEBUG
  log_warn("[ALPN] No common protocol (client sent %u bytes), defaulting to HTTP/1.1", inlen);
#endif
  *out = (const unsigned char *)"http/1.1";
  *outlen = 8;
  return SSL_TLSEXT_ERR_OK;
}


// Default cipher strings (preserved verbatim from the historical hardcoded
// behaviour). Used as the fallback when a L7 rule does NOT pin
// arg->tls_ciphers, so the AI peer (has_l7_policy==0) and un-configured L7
// listeners keep byte-for-byte identical TLS (-COMPAT).
static const char *proxy_default_tls13_ciphers =
  "TLS_AES_256_GCM_SHA384:"           // Strongest (256-bit)
  "TLS_CHACHA20_POLY1305_SHA256:"     // Best for mobile/ARM
  "TLS_AES_128_GCM_SHA256";           // Fastest (128-bit)
static const char *proxy_default_tls12_ciphers =
  "ECDHE-RSA-AES256-GCM-SHA384:"      // Strong (256-bit)
  "ECDHE-ECDSA-AES256-GCM-SHA384:"    // Strong (ECDSA)
  "ECDHE-RSA-AES128-GCM-SHA256:"      // Fast (128-bit, allows kTLS if enabled)
  "ECDHE-ECDSA-AES128-GCM-SHA256:"    // Fast (ECDSA)
  "ECDHE-RSA-CHACHA20-POLY1305:"      // Mobile-optimized
  "ECDHE-ECDSA-CHACHA20-POLY1305";    // Mobile-optimized (ECDSA)

/**
 * proxy_tls_proto_from_ordinal - map a proxy_arg low-byte version ordinal to the
 * OpenSSL TLS*_VERSION constant. TLS versions are 0x03xx, so the stored low byte
 * (TLS1_0=0x01 .. TLS1_3=0x04) reconstitutes as (0x03 << 8 | ordinal):
 *   0x01 → 0x0301 (TLS1.0), 0x02 → 0x0302 (TLS1.1),
 *   0x03 → 0x0303 (TLS1.2), 0x04 → 0x0304 (TLS1.3).
 * Returns 0 for a 0/unknown ordinal so callers keep their hardcoded default.
 */
static int
proxy_tls_proto_from_ordinal(uint8_t ord)
{
  if (ord == 0)
    return 0;                       // unset ⇒ caller keeps today's literal
  return (0x03 << 8) | ord;         // 0x03xx family
}

/**
 * proxy_apply_tls_version_cipher -: pin TLS version range
 * + cipher strings on @ctx from @arg when the L7 rule sets them; otherwise apply
 * today's hardcoded TLS1.2..TLS1.3 + default cipher lists. Shared by the frontend
 * (proxy_server_ssl_ctx_init) and backend (proxy_client_ssl_ctx_init) builders so
 * both legs are pinned identically.
 *
 * @arg may be NULL (frontend default-CTX path / proxy_load_ssl_ctx_for_host) — in
 * which case the hardcoded defaults are applied, preserving legacy behaviour.
 * No allowlist pre-validation: an empty cipher intersection is rejected by the
 * existing `!= 1` failure path (faithful Octavia semantics).
 *
 * Returns 0 on success, -1 on failure (caller frees the ctx).
 */
static int
proxy_apply_tls_version_cipher(SSL_CTX *ctx, const proxy_arg_t *arg)
{
  int vmin = arg ? proxy_tls_proto_from_ordinal(arg->tls_version_min) : 0;
  int vmax = arg ? proxy_tls_proto_from_ordinal(arg->tls_version_max) : 0;

  // pin min/max version when the rule sets them; else today's
  // TLS1.2..TLS1.3 range (0 ⇒ literal default).
  SSL_CTX_set_min_proto_version(ctx, vmin ? vmin : TLS1_2_VERSION);
  SSL_CTX_set_max_proto_version(ctx, vmax ? vmax : TLS1_3_VERSION);

  // when arg->tls_ciphers is set, pass it to BOTH the TLS1.3
  // ciphersuites and the TLS1.2 cipher_list; else keep the hardcoded defaults.
  // Pinning BOTH on every leg. No allowlist — the `!= 1` reject below
  // is the no-overlap rejection (faithful Octavia).
  const char *cfg_ciphers = (arg && arg->tls_ciphers[0] != '\0')
                              ? arg->tls_ciphers : NULL;
  const char *tls13_ciphers = cfg_ciphers ? cfg_ciphers : proxy_default_tls13_ciphers;
  const char *tls12_ciphers = cfg_ciphers ? cfg_ciphers : proxy_default_tls12_ciphers;

  if (SSL_CTX_set_ciphersuites(ctx, tls13_ciphers) != 1) {
    log_error("[SSL] Failed to set TLS 1.3 cipher suites%s",
              cfg_ciphers ? " (configured)" : "");
    return -1;
  }
  if (SSL_CTX_set_cipher_list(ctx, tls12_ciphers) != 1) {
    log_error("[SSL] Failed to set TLS 1.2 cipher list%s",
              cfg_ciphers ? " (configured)" : "");
    return -1;
  }
  return 0;
}

SSL_CTX *
proxy_server_ssl_ctx_init(const proxy_arg_t *arg)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
      log_error("sockproxy: ssl-ctx creation failed");
      return NULL;
    }

    // version-range + cipher pinning from the L7 rule when
    // set; falls back to today's TLS1.2..TLS1.3 + hardcoded ciphers when arg is
    // NULL or the fields are unset (AI peer / un-configured listener unchanged).
    if (proxy_apply_tls_version_cipher(ctx, arg) != 0) {
      SSL_CTX_free(ctx);
      return NULL;
    }

    // Enable kTLS support in OpenSSL context (actual usage controlled by --ktlssupport flag)
    // OpenSSL will attempt kTLS if: runtime flag enabled + TLS 1.2 + AES-GCM + kernel support
    // For TLS 1.3, OpenSSL uses userspace crypto (kTLS not supported by kernel yet)
    SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS);

    // Security hardening
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);  // Prevent CRIME attack
    SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
    SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION);  // Incompatible with kTLS

    // Session resumption (works for both TLS 1.2 and 1.3)
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_timeout(ctx, 300);  // 5 minutes

    // Disable TLS 1.3 early data (0-RTT) for safety
    // Early data is vulnerable to replay attacks, not safe for POST requests
    SSL_CTX_set_max_early_data(ctx, 0);

   
    // ALPN callback will be configured per-proxy with backend-specific protocol capability
    // (moved to proxy_add_entry where we know backend capabilities)

    return ctx;
}

int
proxy_ssl_cfg_opts(SSL_CTX *ctx, const char *site_path, int mtls_en)
{
  char fpath[512] = {0};
  /* If site_path is an absolute path (starts with '/'), use it directly as the
   * certificate directory without prepending PROXY_SSL_CERT_DIR.  This handles
   * the case where the REST API caller passes a full path such as
   * "/opt/loxilb/cert/11.11.11.254" instead of just the hostname "11.11.11.254".
   */
  int site_is_abs = (site_path && site_path[0] == '/');

  if (mtls_en) {
    if (site_is_abs)
      snprintf(fpath, sizeof(fpath), "%s", site_path);
    else
      snprintf(fpath, sizeof(fpath), "%s/%s", PROXY_SSL_CERT_DIR, site_path?:"");
    if (SSL_CTX_load_verify_locations(ctx, NULL, fpath) <= 0) {
      log_error("Unable to set verify locations %s",
        ERR_error_string(ERR_get_error(), NULL));
      return -EINVAL;
    }
  }

  if (site_is_abs)
    snprintf(fpath, sizeof(fpath), "%s/%s", site_path, "server.crt");
  else
    snprintf(fpath, sizeof(fpath), "%s/%s/%s", PROXY_SSL_CERT_DIR, site_path?:"", "server.crt");
  if (site_path && !access(fpath, F_OK)) {
    // Use certificate_chain_file to load full chain (leaf + intermediate CAs)
    // This ensures intermediate certificates are sent to clients during TLS handshake
    if (SSL_CTX_use_certificate_chain_file(ctx, fpath) <= 0) {
      log_error("sockproxy: cert chain (%s) load failed - %s", fpath,
                ERR_error_string(ERR_get_error(), NULL));
      return -EINVAL;
    }
    if (site_is_abs)
      snprintf(fpath, sizeof(fpath), "%s/%s", site_path, "server.key");
    else
      snprintf(fpath, sizeof(fpath), "%s/%s/%s", PROXY_SSL_CERT_DIR, site_path, "server.key");
    if (SSL_CTX_use_PrivateKey_file(ctx, fpath, SSL_FILETYPE_PEM) <= 0 ) {
      log_error("sockproxy: privkey (%s) load failed - %s", fpath,
                ERR_error_string(ERR_get_error(), NULL));
      return -EINVAL;
    }
  } else {
    sprintf(fpath, "%s/%s", PROXY_SSL_CERT_DIR, "server.crt");
    // Use certificate_chain_file to load full chain (leaf + intermediate CAs)
    // This ensures intermediate certificates are sent to clients during TLS handshake
    if (SSL_CTX_use_certificate_chain_file(ctx, fpath) <= 0) {
      log_error("sockproxy: cert chain (%s) load failed - %s", fpath,
                ERR_error_string(ERR_get_error(), NULL));
      return -EINVAL;
    }
    sprintf(fpath, "%s/%s", PROXY_SSL_CERT_DIR, "server.key");
    if (SSL_CTX_use_PrivateKey_file(ctx, fpath, SSL_FILETYPE_PEM) <= 0 ) {
      log_error("sockproxy: privkey (%s) load failed - %s", fpath,
                ERR_error_string(ERR_get_error(), NULL));
      return -EINVAL;
    }
  }

  if (!SSL_CTX_check_private_key(ctx)) {
    log_error("sockproxy: privkey mismatch with public certificate");
    return -EINVAL;
  }
  if (mtls_en) {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT|
      SSL_VERIFY_CLIENT_ONCE, 0);
  }

#if 0
  if (!SSL_CTX_set_options(ctx, SSL_OP_IGNORE_UNEXPECTED_EOF)) {
    log_error("sockproxy: SSL_OP_IGNORE_UNEXPECTED_EOF failed");
    return -EINVAL;
  }
#endif

  // CRITICAL: Enable both partial writes and moving write buffer for non-blocking sockets
  // SSL_MODE_ENABLE_PARTIAL_WRITE: Allows SSL_write to return partial byte counts (required!)
  // SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER: Allows buffer pointer to change between retries (for cache)
  // Both flags together allow proper cache-based retry logic that works with all browsers
  if (!SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER)) {
    log_error("sockproxy: SSL_MODE flags failed");
    return -EINVAL;
  }

  return 0;
}

/**
 * proxy_client_ssl_ctx_init - Initialize client-side SSL context with mTLS support
 * @arg: Proxy configuration (includes backend mTLS settings), NULL for default config
 * 
 * Creates SSL_CTX for backend (upstream) connections with:
 * - TLS 1.2/1.3 support
 * - Strong cipher suites
 * - ALPN for HTTP/2
 * - Optional backend server certificate verification (mTLS)
 * - Optional client certificate for backend authentication (mTLS)
 * 
 * Returns: SSL_CTX pointer on success, NULL on failure
 */
SSL_CTX *
proxy_client_ssl_ctx_init(proxy_arg_t *arg)
{
  const SSL_METHOD *method;
  SSL_CTX *ctx;

  method = TLS_client_method();
  ctx = SSL_CTX_new(method);
  if (!ctx) {
    log_error("sockproxy: ssl-ctx creation failed");
    return NULL;
  }

  // pin the SAME version range + cipher strings on the backend
  // (re-encryption) leg as the frontend listener, driven from arg when set; else
  // today's TLS1.2..TLS1.3 + hardcoded ciphers. arg is non-NULL here (the caller
  // always passes the rule's proxy_arg), so an L7 rule pins both legs.
  if (proxy_apply_tls_version_cipher(ctx, arg) != 0) {
    SSL_CTX_free(ctx);
    return NULL;
  }

  // Enable kTLS (conditional on TLS 1.2)
  SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS);

  // Security hardening
  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
  SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
  SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION);
  
  // Configure ALPN for HTTP/2 support (client mode - to backend).
  // gate the advertised list on the pool's backend_protocol_cap.
  // loxilb has NO h2→h1 backend downgrade engine, so h2 must NEVER be advertised
  // to an h1-only pool (an h2 client + h1-only pool would otherwise yield an empty
  // body — RESEARCH Pitfall 2). The cap is mapped from Octavia alpn_protocols in
  // the control plane (the design); here the data plane HONORS it:
  //   cap==0 → http/1.1 only   cap==1 → h2 only   cap==2 → h2 + http/1.1
  // arg==NULL ⇒ legacy unconditional h2+http/1.1 (AI peer byte-for-byte unchanged).
  static const unsigned char alpn_both[]  = "\x02h2\x08http/1.1";
  static const unsigned char alpn_h2[]    = "\x02h2";
  static const unsigned char alpn_h1[]    = "\x08http/1.1";
  const unsigned char *alpn_protos = alpn_both;
  unsigned int alpn_protos_len = sizeof(alpn_both) - 1;
  if (arg != NULL) {
    if (arg->backend_protocol_cap == 0) {        // http/1.1-only pool: never offer h2
      alpn_protos = alpn_h1;
      alpn_protos_len = sizeof(alpn_h1) - 1;
    } else if (arg->backend_protocol_cap == 1) { // h2-only pool
      alpn_protos = alpn_h2;
      alpn_protos_len = sizeof(alpn_h2) - 1;
    }
    // cap==2 (or any other value): keep h2 + http/1.1 (today's default)
  }
  if (SSL_CTX_set_alpn_protos(ctx, alpn_protos, alpn_protos_len) != 0) {
    log_error("[sockproxy] Failed to set ALPN protocols for client SSL context");
  }

#ifdef HAVE_MTLS
  // ============================================================================
  // Backend mTLS Integration
  // ============================================================================
  if (arg != NULL) {
    // Configure backend mTLS (server cert verification + client cert).
    // the backend material is referenced by certId;
    // mtls_configure_backend resolves the certId → managed-dir paths.
    if (arg->backend_verify_cert || arg->backend_client_cert_id[0] != '\0') {
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("[mTLS] Backend mTLS enabled in proxy_client_ssl_ctx_init");
      log_debug("[mTLS]   verify_server_cert=%d", arg->backend_verify_cert);
      log_debug("[mTLS]   backend_ca_cert_id=%s", arg->backend_ca_cert_id[0] ? arg->backend_ca_cert_id : "(system CA)");
      log_debug("[mTLS]   backend_client_cert_id=%s", arg->backend_client_cert_id[0] ? arg->backend_client_cert_id : "(none)");
#endif
      if (mtls_configure_backend(ctx, arg) != 0) {
        log_error("[mTLS] Failed to configure backend mTLS in proxy_client_ssl_ctx_init");
        SSL_CTX_free(ctx);
        return NULL;
      }
      log_info("[mTLS] Backend mTLS configured successfully in proxy_client_ssl_ctx_init");
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("[mTLS] SSL_CTX backend verify mode: %d", SSL_CTX_get_verify_mode(ctx));
#endif
    }
  }
#endif /* HAVE_MTLS */

  return ctx;
}/**
 * SNI (Server Name Indication) callback for dynamic certificate selection (GLOBAL STORE)
 *
 * Called by OpenSSL during TLS handshake when client sends SNI extension.
 * Looks up certificate in GLOBAL certificate store (shared by all proxies).
 *
 * @param ssl    OpenSSL SSL connection object
 * @param ad     Alert descriptor (unused)
 * @param arg    User-defined argument (unused - we use global store)
 * @return SSL_TLSEXT_ERR_OK (certificate found) or SSL_TLSEXT_ERR_NOACK (use default)
 */
int
sni_servername_callback(SSL *ssl, int *ad, void *arg)
{
  ssl_cert_entry_t *cert_entry = NULL;
  const char *servername = NULL;

  (void)ad;   // Unused parameter
  (void)arg;  // Unused - we use global certificate store

  if (!ssl) {
    log_error("SNI callback: Invalid SSL object");
    return SSL_TLSEXT_ERR_ALERT_FATAL;
  }

  // Extract hostname from SNI extension
  servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

  if (!servername || servername[0] == '\0') {
    return SSL_TLSEXT_ERR_NOACK;
  }

  // Lookup hostname in GLOBAL certificate map (read lock for concurrent lookups)
  pthread_rwlock_rdlock(&proxy_struct->global_cert_lock);
  HASH_FIND_STR(proxy_struct->global_cert_map, servername, cert_entry);
  pthread_rwlock_unlock(&proxy_struct->global_cert_lock);

  if (cert_entry && cert_entry->ssl_ctx) {
    // Found certificate for this hostname - switch SSL context.
    //
    // BUG PREVENTION: SSL_set_SSL_CTX() replaces the SSL_CTX on this connection.
    // The new SSL_CTX does NOT carry the ex_data (proxy_arg_t*) that was stored on
    // the original SSL_CTX by mtls_configure_frontend().  If we switch without
    // preserving proxy_arg, the mTLS client-verify callback will see NULL and
    // reject every client certificate.
    //
    // Fix: save the proxy_arg pointer on the SSL connection object itself
    // (g_ssl_proxy_arg_index, no cleanup callback) before the switch so that
    // mtls_client_verify_callback() can fall back to it.
#ifdef HAVE_MTLS
    if (g_ssl_ctx_proxy_arg_index >= 0 && g_ssl_proxy_arg_index >= 0) {
      SSL_CTX *orig_ctx = SSL_get_SSL_CTX(ssl);
      if (orig_ctx) {
        proxy_arg_t *mtls_arg =
            (proxy_arg_t *)SSL_CTX_get_ex_data(orig_ctx, g_ssl_ctx_proxy_arg_index);
        if (mtls_arg) {
          // Allocate an OWNED per-connection snapshot of the fields the verify
          // callback needs.  Using an owned copy (instead of storing the raw
          // proxy_arg_t pointer) is the production-safe design:
          //   1. SSL_set_SSL_CTX() discards the SSL_CTX-level ex_data, so we
          //      cannot read proxy_arg from the new SSL_CTX in the callback.
          //   2. Rule deletion frees proxy_arg_t concurrently — storing the raw
          //      pointer would be a use-after-free if a handshake is in progress.
          // The snapshot is freed automatically by mtls_ssl_conn_state_cleanup()
          // when the SSL connection is destroyed via SSL_free().
          mtls_ssl_conn_state_t *conn_state =
              (mtls_ssl_conn_state_t *)calloc(1, sizeof(mtls_ssl_conn_state_t));
          if (conn_state) {
            conn_state->require_client_cn = mtls_arg->require_client_cn;
            memcpy(conn_state->client_cn_pattern, mtls_arg->client_cn_pattern,
                   sizeof(conn_state->client_cn_pattern));
            SSL_set_ex_data(ssl, g_ssl_proxy_arg_index, conn_state);
#ifdef HAVE_PROXY_EXTRA_DEBUG
            log_debug("[mTLS] SNI: allocated conn_state=%p for SSL=%p (cn_pat='%s')",
                      (void *)conn_state, (void *)ssl, conn_state->client_cn_pattern);
#endif
          } else {
            log_error("[mTLS] SNI: failed to allocate per-connection mTLS snapshot");
          }
        }
      }
    }
#endif /* HAVE_MTLS */
    SSL_set_SSL_CTX(ssl, (SSL_CTX *)cert_entry->ssl_ctx);
    return SSL_TLSEXT_ERR_OK;
  }

  // Hostname not found in map - use default certificate
  return SSL_TLSEXT_ERR_NOACK;
}

/**
 * Load SSL context for specific hostname
 *
 * Creates new SSL_CTX and loads certificate/key from hostname-specific directory:
 * /opt/loxilb/cert/{host_url}/server.crt
 * /opt/loxilb/cert/{host_url}/server.key
 *
 * @param host_url  Hostname (e.g., "api.example.com")
 * @param mtls_en   Enable mutual TLS (client certificate verification)
 * @return Configured SSL_CTX on success, NULL on failure
 */
static SSL_CTX*
proxy_load_ssl_ctx_for_host(const char *host_url, int mtls_en)
{
  SSL_CTX *ctx = NULL;

  if (!host_url || host_url[0] == '\0') {
    log_error("proxy_load_ssl_ctx_for_host: Invalid hostname");
    return NULL;
  }

  // Create new SSL context with kTLS support.
  // NULL arg ⇒ legacy default version/cipher (this hostname-keyed loader is the
  // SNI default-CTX path; per-rule pinning happens at proxy_add_entry).
  ctx = proxy_server_ssl_ctx_init(NULL);
  if (!ctx) {
    log_error("Failed to create SSL context for hostname '%s'", host_url);
    return NULL;
  }

  // Load certificates from /opt/loxilb/cert/{host_url}/
  if (proxy_ssl_cfg_opts(ctx, host_url, mtls_en) != 0) {
    log_error("Failed to load certificates for hostname '%s'", host_url);
    SSL_CTX_free(ctx);
    return NULL;
  }

  return ctx;
}

/**
 * Cleanup function removed - certificates now stored globally
 * (No longer needed per-proxy cleanup)
 */

/**
 * Register SNI certificate in GLOBAL certificate store
 * Called by REST API: POST /api/v1/sni/certificates
 * 
 * Multiple loadbalancer rules can share the same certificate by hostname.
 * The certificate is stored independently and looked up during TLS handshake.
 *
 * @param hostname    Hostname for SNI matching (e.g., "api.example.com")
 * @param cert_path   Optional certificate path (defaults to /opt/loxilb/cert/{hostname})
 * @return 0 on success, negative error code on failure
 */
int
proxy_add_sni_certificate(const char *hostname, const char *cert_path)
{
  ssl_cert_entry_t *cert_entry = NULL;

  if (!hostname || hostname[0] == '\0') {
    log_error("proxy_add_sni_certificate: Invalid hostname");
    return -EINVAL;
  }

  // Check if certificate already registered (globally)
  pthread_rwlock_rdlock(&proxy_struct->global_cert_lock);
  HASH_FIND_STR(proxy_struct->global_cert_map, hostname, cert_entry);
  pthread_rwlock_unlock(&proxy_struct->global_cert_lock);

  if (cert_entry) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_warn("proxy_add_sni_certificate: Certificate for '%s' already registered globally",
             hostname);
#endif
    return -EEXIST;
  }

  // Create new certificate entry
  cert_entry = calloc(1, sizeof(*cert_entry));
  if (!cert_entry) {
    log_error("proxy_add_sni_certificate: Memory allocation failed");
    return -ENOMEM;
  }

  strncpy(cert_entry->hostname, hostname, sizeof(cert_entry->hostname) - 1);
  cert_entry->hostname[sizeof(cert_entry->hostname) - 1] = '\0';
  
  // Store the cert_path (use provided path or default to hostname)
  const char *actual_cert_path = cert_path ? cert_path : hostname;
  strncpy(cert_entry->cert_path, actual_cert_path, sizeof(cert_entry->cert_path) - 1);
  cert_entry->cert_path[sizeof(cert_entry->cert_path) - 1] = '\0';
  
  cert_entry->ref_count = 0;  // Will be incremented when proxies use it
  cert_entry->loaded_ts = time(NULL);

  // Load certificate from filesystem
  // If cert_path provided, use it; otherwise default to hostname
  cert_entry->ssl_ctx = proxy_load_ssl_ctx_for_host(
    actual_cert_path, 0
  );

  if (!cert_entry->ssl_ctx) {
    log_error("proxy_add_sni_certificate: Failed to load certificate for '%s'",
              hostname);
    free(cert_entry);
    return -ENOENT;  // Certificate files not found
  }

  // Add to GLOBAL certificate map (thread-safe)
  pthread_rwlock_wrlock(&proxy_struct->global_cert_lock);
  HASH_ADD_STR(proxy_struct->global_cert_map, hostname, cert_entry);
  pthread_rwlock_unlock(&proxy_struct->global_cert_lock);

  return 0;
}

/**
 * Unregister SNI certificate from GLOBAL certificate store
 * Called by REST API: DELETE /api/v1/sni/certificates
 *
 * @param hostname    Hostname to remove
 * @return 0 on success, negative error code on failure
 */
int
proxy_remove_sni_certificate(const char *hostname)
{
  ssl_cert_entry_t *cert_entry = NULL;

  if (!hostname || hostname[0] == '\0') {
    log_error("proxy_remove_sni_certificate: Invalid hostname");
    return -EINVAL;
  }

  // Find certificate in global map
  pthread_rwlock_wrlock(&proxy_struct->global_cert_lock);
  HASH_FIND_STR(proxy_struct->global_cert_map, hostname, cert_entry);

  if (!cert_entry) {
    pthread_rwlock_unlock(&proxy_struct->global_cert_lock);
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_warn("proxy_remove_sni_certificate: Certificate for '%s' not found",
             hostname);
#endif
    return -ENOENT;
  }

  // Remove from hash table
  HASH_DEL(proxy_struct->global_cert_map, cert_entry);
  pthread_rwlock_unlock(&proxy_struct->global_cert_lock);

  // Free SSL context and entry
  if (cert_entry->ssl_ctx) {
    SSL_CTX_free((SSL_CTX *)cert_entry->ssl_ctx);
  }
  free(cert_entry);

  return 0;
}

/**
 * List all SNI certificates in GLOBAL certificate store
 * Called by REST API: GET /api/v1/sni/certificates
 *
 * @param callback    Callback function called for each certificate
 * @param user_data   User data passed to callback
 * @return Number of certificates listed, or negative error code
 */
int
proxy_list_sni_certificates(void (*callback)(const char *hostname, void *data),
                            void *user_data)
{
  ssl_cert_entry_t *cert_entry, *tmp;
  int count = 0;

  if (!callback) {
    log_error("proxy_list_sni_certificates: Invalid callback");
    return -EINVAL;
  }

  // Iterate over global certificate map (read lock)
  pthread_rwlock_rdlock(&proxy_struct->global_cert_lock);
  HASH_ITER(hh, proxy_struct->global_cert_map, cert_entry, tmp) {
    callback(cert_entry->hostname, user_data);
    count++;
  }
  pthread_rwlock_unlock(&proxy_struct->global_cert_lock);
  return count;
}

/**
 * List all SNI certificates from GLOBAL certificate store with cert_path
 * Called by REST API: GET /api/v1/sni/certificates
 *
 * @param callback    Callback function called for each certificate with hostname and cert_path
 * @param user_data   User data passed to callback
 * @return Number of certificates listed, or negative error code
 */
int
proxy_list_sni_certificates_with_path(void (*callback)(const char *hostname, const char *cert_path, void *data),
                                      void *user_data)
{
  ssl_cert_entry_t *cert_entry, *tmp;
  int count = 0;

  if (!callback) {
    log_error("proxy_list_sni_certificates_with_path: Invalid callback");
    return -EINVAL;
  }

  // Iterate over global certificate map (read lock)
  pthread_rwlock_rdlock(&proxy_struct->global_cert_lock);
  HASH_ITER(hh, proxy_struct->global_cert_map, cert_entry, tmp) {
    callback(cert_entry->hostname, cert_entry->cert_path, user_data);
    count++;
  }
  pthread_rwlock_unlock(&proxy_struct->global_cert_lock);
  return count;
}

/**
 * Get SSL context for hostname (internal function for SNI callback)
 * 
 * @param hostname  Hostname to lookup
 * @return SSL_CTX pointer if found, NULL otherwise
 */
void *
proxy_get_ssl_ctx_for_hostname(const char *hostname)
{
  ssl_cert_entry_t *cert_entry = NULL;
  void *ssl_ctx = NULL;

  if (!hostname || hostname[0] == '\0') {
    return NULL;
  }

  pthread_rwlock_rdlock(&proxy_struct->global_cert_lock);
  HASH_FIND_STR(proxy_struct->global_cert_map, hostname, cert_entry);
  if (cert_entry) {
    ssl_ctx = cert_entry->ssl_ctx;
  }
  pthread_rwlock_unlock(&proxy_struct->global_cert_lock);

  return ssl_ctx;
}

// ============================================================================
// (..16): certId registry LAYERED OVER the SNI store.
//
// The certId is the canonical management handle for ALL TLS material (frontend
// certs, backend CA/client certs), referenced by short id instead of
// inline path strings (the 768 proxy_arg bytes reclaimed in Task 1). Selection
// at handshake stays BY HOSTNAME (the SNI callback is byte-for-byte unchanged,
// ); certId only drives upload/rotate/delete and backend resolution.
//
// Concurrency: the certId map shares proxy_struct->global_cert_lock with the SNI
// store (one lock domain, lock priority 8) so register/rotate/delete mutate both
// maps atomically with no new lock-ordering edge.
// ============================================================================

/**
 * proxy_certid_dir - Compose the managed dir path for a certId.
 */
static void
proxy_certid_dir(const char *certId, char *out, size_t out_sz)
{
  snprintf(out, out_sz, "%s/%s", PROXY_SSL_CERTID_DIR, certId);
}

/**
 * proxy_certid_derive_hostnames - Read the leaf cert at <dir>/server.crt and
 * extract its hostnames: every SAN-DNS entry first, CN as the
 * fallback when no SAN-DNS is present. Modern SAN-only certs (empty CN) are
 * handled via their SAN. We deliberately do NOT use the OpenSSL single-name
 * host-match helper here — it matches one supplied name and would not ENUMERATE
 * the cert's own names, which is exactly what SNI registration needs (the
 * registry needs the LIST of names the cert speaks for). Pattern semantics from
 * the CN-pattern path are preserved by reading SAN-DNS / CN directly.
 *
 * @dir_path: managed dir containing server.crt
 * @out:      caller array of [CERTID_MAX_HOSTNAMES][256]
 * Returns: number of hostnames derived (>=0), negative errno on read failure.
 */
static int
proxy_certid_derive_hostnames(const char *dir_path,
                              char out[CERTID_MAX_HOSTNAMES][256])
{
  char crt_path[512];
  FILE *fp;
  X509 *cert = NULL;
  int n = 0;

  snprintf(crt_path, sizeof(crt_path), "%s/%s", dir_path, "server.crt");
  fp = fopen(crt_path, "r");
  if (!fp) {
    log_error("proxy_certid: cannot open leaf cert %s", crt_path);
    return -ENOENT;
  }
  cert = PEM_read_X509(fp, NULL, NULL, NULL);
  fclose(fp);
  if (!cert) {
    log_error("proxy_certid: cannot parse leaf cert %s", crt_path);
    return -EINVAL;
  }

  // SAN-DNS first (preferred, RFC 6125;).
  GENERAL_NAMES *sans =
    (GENERAL_NAMES *)X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
  if (sans) {
    int san_count = sk_GENERAL_NAME_num(sans);
    for (int i = 0; i < san_count && n < CERTID_MAX_HOSTNAMES; i++) {
      const GENERAL_NAME *gn = sk_GENERAL_NAME_value(sans, i);
      if (gn->type != GEN_DNS)
        continue;
      const unsigned char *dns = ASN1_STRING_get0_data(gn->d.dNSName);
      int dns_len = ASN1_STRING_length(gn->d.dNSName);
      if (dns && dns_len > 0 && dns_len < 256) {
        memcpy(out[n], dns, dns_len);
        out[n][dns_len] = '\0';
        n++;
      }
    }
    GENERAL_NAMES_free(sans);
  }

  // CN fallback only when no SAN-DNS was found (legacy CN-only certs;).
  if (n == 0) {
    X509_NAME *subj = X509_get_subject_name(cert);
    if (subj) {
      char cn[256] = {0};
      int cn_len = X509_NAME_get_text_by_NID(subj, NID_commonName, cn, sizeof(cn) - 1);
      if (cn_len > 0) {
        memcpy(out[0], cn, (size_t)cn_len);
        out[0][cn_len] = '\0';
        n = 1;
      }
    }
  }

  X509_free(cert);
  return n;
}

/**
 * proxy_register_cert - register entry point.
 *
 * Preconditions: the Go REST handler has already persisted the PEM
 * material to PROXY_SSL_CERTID_DIR/<certId>/ (server.crt + server.key). This
 * function derives the hostname(s) from the leaf SAN/CN and registers EACH into
 * the SNI store via the EXISTING proxy_add_sni_certificate (NO new loader), then
 * records the certId → {dir, hostnames} mapping for later rotate/delete.
 */
int
proxy_register_cert(const char *certId)
{
  cert_id_entry_t *cid = NULL;
  char dir_path[256];
  char hostnames[CERTID_MAX_HOSTNAMES][256];
  int n, i, registered = 0;

  if (!certId || certId[0] == '\0' || strlen(certId) >= CERTID_MAX) {
    log_error("proxy_register_cert: invalid certId");
    return -EINVAL;
  }

  // Reject duplicate registration (use rotate to refresh material).
  pthread_rwlock_rdlock(&proxy_struct->global_cert_lock);
  HASH_FIND_STR(proxy_struct->global_certid_map, certId, cid);
  pthread_rwlock_unlock(&proxy_struct->global_cert_lock);
  if (cid) {
    log_warn("proxy_register_cert: certId '%s' already registered (use rotate)", certId);
    return -EEXIST;
  }

  proxy_certid_dir(certId, dir_path, sizeof(dir_path));

  n = proxy_certid_derive_hostnames(dir_path, hostnames);
  if (n < 0)
    return n;
  if (n == 0) {
    log_error("proxy_register_cert: certId '%s' leaf cert has no SAN/CN hostname", certId);
    return -EINVAL;
  }

  // Register every derived hostname into the SNI store (reuse the proven loader).
  // The managed dir is an absolute path → proxy_ssl_cfg_opts loads
  // <dir>/server.crt + <dir>/server.key for each hostname entry.
  for (i = 0; i < n; i++) {
    int rc = proxy_add_sni_certificate(hostnames[i], dir_path);
    if (rc == 0 || rc == -EEXIST)
      registered++;
    else
      log_warn("proxy_register_cert: SNI add for host '%s' (certId '%s') rc=%d",
               hostnames[i], certId, rc);
  }
  if (registered == 0) {
    log_error("proxy_register_cert: no hostnames registered for certId '%s'", certId);
    return -ENOENT;
  }

  // Record the certId → {dir, hostnames} mapping under the shared lock.
  cid = calloc(1, sizeof(*cid));
  if (!cid)
    return -ENOMEM;
  strncpy(cid->certId, certId, sizeof(cid->certId) - 1);
  strncpy(cid->dir_path, dir_path, sizeof(cid->dir_path) - 1);
  cid->n_hostnames = n;
  for (i = 0; i < n; i++) {
    strncpy(cid->hostnames[i], hostnames[i], sizeof(cid->hostnames[i]) - 1);
  }
  cid->loaded_ts = time(NULL);

  pthread_rwlock_wrlock(&proxy_struct->global_cert_lock);
  HASH_ADD_STR(proxy_struct->global_certid_map, certId, cid);
  pthread_rwlock_unlock(&proxy_struct->global_cert_lock);

  log_info("proxy_register_cert: certId '%s' registered (%d hostname(s))", certId, n);
  return n;
}

/**
 * proxy_rotate_cert - atomic rotation.
 *
 * The Go handler has already swapped fresh PEM into the managed dir. For each
 * hostname this certId owns, load a NEW SSL_CTX and swap it into the SNI store
 * entry under the global_cert_lock WRITE-lock. The OLD ctx is freed only AFTER
 * it is unlinked — in-flight connections already hold their own reference via
 * SSL_set_SSL_CTX-derived SSL objects, so a torn read of a half-swapped cert is
 * impossible ( mitigated). Zero-downtime: the swap is a pointer
 * assignment under the lock.
 */
int
proxy_rotate_cert(const char *certId)
{
  cert_id_entry_t *cid = NULL;
  int i, swapped = 0;

  if (!certId || certId[0] == '\0') {
    log_error("proxy_rotate_cert: invalid certId");
    return -EINVAL;
  }

  pthread_rwlock_rdlock(&proxy_struct->global_cert_lock);
  HASH_FIND_STR(proxy_struct->global_certid_map, certId, cid);
  pthread_rwlock_unlock(&proxy_struct->global_cert_lock);
  if (!cid) {
    log_error("proxy_rotate_cert: certId '%s' not found", certId);
    return -ENOENT;
  }

  for (i = 0; i < cid->n_hostnames; i++) {
    // Build the fresh ctx OUTSIDE the lock (load is the slow part).
    SSL_CTX *new_ctx = proxy_load_ssl_ctx_for_host(cid->dir_path, 0);
    if (!new_ctx) {
      log_error("proxy_rotate_cert: reload failed for host '%s' (certId '%s')",
                cid->hostnames[i], certId);
      continue;
    }

    // Swap into the SNI store entry under the write-lock; free the old ctx after
    // it is unlinked from the map (in-flight SSL objects keep their own ref).
    SSL_CTX *old_ctx = NULL;
    ssl_cert_entry_t *sni = NULL;
    pthread_rwlock_wrlock(&proxy_struct->global_cert_lock);
    HASH_FIND_STR(proxy_struct->global_cert_map, cid->hostnames[i], sni);
    if (sni) {
      old_ctx = (SSL_CTX *)sni->ssl_ctx;
      sni->ssl_ctx = new_ctx;
      sni->loaded_ts = time(NULL);
      swapped++;
    }
    pthread_rwlock_unlock(&proxy_struct->global_cert_lock);

    if (old_ctx)
      SSL_CTX_free(old_ctx);  // safe: unlinked; live SSLs hold their own ref
    if (!sni) {
      // Hostname not in the SNI store (was never registered) — register fresh.
      SSL_CTX_free(new_ctx);
      proxy_add_sni_certificate(cid->hostnames[i], cid->dir_path);
      swapped++;
    }
  }

  cid->loaded_ts = time(NULL);
  log_info("proxy_rotate_cert: certId '%s' rotated (%d hostname(s) swapped)", certId, swapped);
  return swapped > 0 ? 0 : -ENOENT;
}

/**
 * proxy_delete_cert - delete entry point. Scoped: removes ONLY this
 * certId's derived hostnames from the SNI store and frees the registry entry.
 */
int
proxy_delete_cert(const char *certId)
{
  cert_id_entry_t *cid = NULL;
  int i;

  if (!certId || certId[0] == '\0') {
    log_error("proxy_delete_cert: invalid certId");
    return -EINVAL;
  }

  pthread_rwlock_wrlock(&proxy_struct->global_cert_lock);
  HASH_FIND_STR(proxy_struct->global_certid_map, certId, cid);
  if (cid) {
    HASH_DEL(proxy_struct->global_certid_map, cid);
  }
  pthread_rwlock_unlock(&proxy_struct->global_cert_lock);

  if (!cid) {
    log_warn("proxy_delete_cert: certId '%s' not found", certId);
    return -ENOENT;
  }

  // Unregister each derived hostname (proxy_remove_sni_certificate takes its own
  // write-lock, so do this after dropping ours to keep the lock domain simple).
  for (i = 0; i < cid->n_hostnames; i++) {
    proxy_remove_sni_certificate(cid->hostnames[i]);
  }

  log_info("proxy_delete_cert: certId '%s' deleted (%d hostname(s))", certId, cid->n_hostnames);
  free(cid);
  return 0;
}

/**
 * proxy_certid_resolve_backend -: resolve a backend certId into
 * the managed-dir CA / client-cert / client-key paths. A path is emitted only
 * when its file exists under PROXY_SSL_CERTID_DIR/<certId>/; absent files yield
 * "" so the backend builder falls back to its today's behaviour (system CA / no
 * client cert). This is the per-service-with-certId-references landing (
 * sanctioned fallback); a true per-pool backend SSL_CTX cache is a documented
 * residual (Open Question 1).
 */
int
proxy_certid_resolve_backend(const char *certId,
                             char *ca_path_out,
                             char *client_cert_path_out,
                             char *client_key_path_out,
                             size_t out_sz)
{
  char dir_path[256];
  char fpath[512];

  if (!ca_path_out || !client_cert_path_out || !client_key_path_out || out_sz == 0)
    return -EINVAL;

  ca_path_out[0] = '\0';
  client_cert_path_out[0] = '\0';
  client_key_path_out[0] = '\0';

  // empty certId ⇒ no backend material (today's behaviour when paths were empty).
  if (!certId || certId[0] == '\0')
    return 0;
  if (strlen(certId) >= CERTID_MAX)
    return -EINVAL;

  proxy_certid_dir(certId, dir_path, sizeof(dir_path));

  snprintf(fpath, sizeof(fpath), "%s/%s", dir_path, "ca.crt");
  if (!access(fpath, F_OK))
    snprintf(ca_path_out, out_sz, "%s", fpath);

  snprintf(fpath, sizeof(fpath), "%s/%s", dir_path, "client.crt");
  if (!access(fpath, F_OK))
    snprintf(client_cert_path_out, out_sz, "%s", fpath);

  snprintf(fpath, sizeof(fpath), "%s/%s", dir_path, "client.key");
  if (!access(fpath, F_OK))
    snprintf(client_key_path_out, out_sz, "%s", fpath);

  return 0;
}
