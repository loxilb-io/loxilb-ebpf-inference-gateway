/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */

/**
 * sockproxy_mtls.c - mTLS (Mutual TLS) Implementation for LoxiLB
 * 
 * Frontend and Backend mTLS Certificate Verification
 * 
 * This file implements mutual TLS authentication for the FullProxy mode,
 * including:
 * - Frontend: Client certificate verification (optional/required modes)
 * - Backend: Server certificate verification + client cert presentation
 * - CN/SAN pattern matching for additional security
 * - Certificate loading and validation
 * - Integration with OpenSSL verification callbacks
 * 
 * Build with: make HAVE_MTLS=1
 */

#ifdef HAVE_MTLS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <errno.h>
#include <time.h>
#include <fnmatch.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include "log.h"
#include "uthash.h"
#include "sockproxy.h"
#include "sockproxy_mtls.h"
#include "sockproxy_ssl.h"   /* proxy_certid_resolve_backend */

// mTLS constants
#define MTLS_VERIFY_DEPTH_MAX 10     // Max certificate chain depth
#define MTLS_RATE_LIMIT_WINDOW 60    // Rate limit window (seconds)
#define MTLS_RATE_LIMIT_MAX 100      // Max failed attempts per IP per window

// Rate limiting structure for brute-force protection
typedef struct mtls_rate_limit {
    uint32_t client_ip;
    uint32_t failed_attempts;
    time_t window_start;
    UT_hash_handle hh;
} mtls_rate_limit_t;

// Global rate limiting hash table
static mtls_rate_limit_t *g_mtls_rate_limits = NULL;
static pthread_rwlock_t g_mtls_rate_lock = PTHREAD_RWLOCK_INITIALIZER;

// OpenSSL ex_data index for storing proxy_arg_t pointer in SSL_CTX
// Non-static so sockproxy.c can use it for post-handshake CN validation
int g_ssl_ctx_proxy_arg_index = -1;

// OpenSSL ex_data index for storing a per-connection mtls_ssl_conn_state_t snapshot.
// The snapshot is allocated by sni_servername_callback() and freed automatically by
// mtls_ssl_conn_state_cleanup() when the SSL connection is destroyed via SSL_free().
// This is the production-safe design: it eliminates the use-after-free race that
// would occur if we stored a raw proxy_arg_t* while a concurrent rule deletion
// freed that pointer.
int g_ssl_proxy_arg_index = -1;

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * mtls_ssl_conn_state_cleanup - Cleanup callback for SSL-level ex_data
 * @parent: SSL connection (ignored)
 * @ptr:    Pointer to mtls_ssl_conn_state_t allocated by sni_servername_callback
 *
 * Called by OpenSSL automatically when SSL_free() is invoked on the connection.
 * Frees the per-connection mTLS configuration snapshot, completing the
 * alloc/free cycle and preventing memory leaks.
 */
static void mtls_ssl_conn_state_cleanup(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                                        int idx, long argl, void *argp)
{
    (void)parent;
    (void)ad;
    (void)idx;
    (void)argl;
    (void)argp;

    if (ptr) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
        log_debug("[mTLS] SSL conn state cleanup: freeing mtls_ssl_conn_state_t at %p", ptr);
#endif
        free(ptr);
    }
}

/**
 * mtls_proxy_arg_cleanup - Cleanup callback for SSL_CTX ex_data
 * @parent: Parent object (SSL_CTX)
 * @ptr: Pointer to proxy_arg_t to cleanup
 * @ad: CRYPTO_EX_DATA structure
 * @idx: Index of the ex_data
 * @argl: Long argument (unused)
 * @argp: Pointer argument (unused)
 * 
 * This callback is invoked by OpenSSL when SSL_CTX is destroyed.
 * It's responsible for freeing the proxy_arg_t that was allocated on the heap.
 */
static void mtls_proxy_arg_cleanup(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                                    int idx, long argl, void *argp)
{
    (void)parent;
    (void)ad;
    (void)idx;
    (void)argl;
    (void)argp;

    if (ptr) {
        proxy_arg_t *arg = (proxy_arg_t *)ptr;
#ifdef HAVE_PROXY_EXTRA_DEBUG
        log_debug("[mTLS] Cleanup: freeing proxy_arg_t at %p", ptr);
#endif
        free(arg);
    }
}

/**
 * mtls_check_rate_limit - Check if client IP is rate limited
 * @client_ip: Client IP address
 * 
 * Returns: 1 if rate limited, 0 if OK
 */
static int mtls_check_rate_limit(uint32_t client_ip)
{
    mtls_rate_limit_t *entry = NULL;
    time_t now = time(NULL);
    int rate_limited = 0;

#ifdef HAVE_PROXY_EXTRA_DEBUG
    struct in_addr addr = {.s_addr = client_ip};
    log_debug("[mTLS] Checking rate limit for client IP: %s", inet_ntoa(addr));
#endif

    pthread_rwlock_wrlock(&g_mtls_rate_lock);
    
    HASH_FIND(hh, g_mtls_rate_limits, &client_ip, sizeof(uint32_t), entry);
    
    if (entry) {
        // Check if window expired
        if (now - entry->window_start >= MTLS_RATE_LIMIT_WINDOW) {
            // Reset window
#ifdef HAVE_PROXY_EXTRA_DEBUG
            log_debug("[mTLS] Rate limit window expired, resetting for IP %08x (old attempts: %u)",
                      client_ip, entry->failed_attempts);
#endif
            entry->window_start = now;
            entry->failed_attempts = 1;
        } else {
            entry->failed_attempts++;
#ifdef HAVE_PROXY_EXTRA_DEBUG
            log_debug("[mTLS] Failed attempts for IP %08x: %u/%u (window: %ld/%d sec)",
                      client_ip, entry->failed_attempts, MTLS_RATE_LIMIT_MAX,
                      now - entry->window_start, MTLS_RATE_LIMIT_WINDOW);
#endif
            if (entry->failed_attempts > MTLS_RATE_LIMIT_MAX) {
                rate_limited = 1;
#ifdef HAVE_PROXY_EXTRA_DEBUG
                log_debug("[mTLS] RATE LIMITED: IP %08x exceeded max attempts (%u > %u)",
                          client_ip, entry->failed_attempts, MTLS_RATE_LIMIT_MAX);
#endif
            }
        }
    } else {
        // Create new entry
        entry = calloc(1, sizeof(mtls_rate_limit_t));
        if (entry) {
            entry->client_ip = client_ip;
            entry->failed_attempts = 1;
            entry->window_start = now;
            HASH_ADD(hh, g_mtls_rate_limits, client_ip, sizeof(uint32_t), entry);
        }
    }
    
    pthread_rwlock_unlock(&g_mtls_rate_lock);
    return rate_limited;
}

/**
 * mtls_fnmatch_pattern - fnmatch a candidate name against a wildcard pattern
 * @pattern: operator-supplied pattern (supports wildcards like "*.corp.example.com")
 * @name:    candidate identity (a SAN-DNS entry or the cert CN)
 *
 * Returns: 1 if matches, 0 if not
 *
 * Centralizes the wildcard matching semantics shared by the SAN-DNS leg and the
 * CN-fallback leg so both behave identically. FNM_CASEFOLD (a GNU extension)
 * makes the match case-insensitive per RFC 6125 §6.4; portable builds fall back
 * to case-sensitive fnmatch.
 *
 * NOTE: OpenSSL's RFC-6125 hostname-check helper is deliberately NOT used here —
 * it implements single-name matching and does not honor fnmatch '*'/'?'
 * wildcard-pattern semantics, which would silently narrow/break the operator's
 * configured client_cn_pattern.
 */
static int mtls_fnmatch_pattern(const char *pattern, const char *name)
{
    if (!pattern || !name || pattern[0] == '\0' || name[0] == '\0') {
        return 0;
    }
#ifdef FNM_CASEFOLD
    return fnmatch(pattern, name, FNM_CASEFOLD) == 0 ? 1 : 0;
#else
    return fnmatch(pattern, name, 0) == 0 ? 1 : 0;
#endif
}

/**
 * mtls_match_cn_pattern - Match certificate SAN-DNS (then CN) against pattern
 * @cert: X509 certificate
 * @pattern: Pattern to match (supports wildcards)
 *
 * Returns: 1 if matches, 0 if not
 *
 * SAN-DNS entries are matched FIRST, then CN as a fallback.
 *   - A modern SAN-only (empty-CN) cert is accepted when one of its SAN-DNS
 *     entries matches the operator's pattern (previously such a cert died at the
 *     cn_len<=0 return — the e2ehttpsproxy-mtls Test-9 starting failure).
 *   - A legacy CN-only cert still passes via the CN fallback.
 * Both legs use the SAME fnmatch wildcard semantics (mtls_fnmatch_pattern).
 *
 * This matcher reuses the operator's client_cn_pattern, which the verify
 * callback resolves from the per-connection mtls_ssl_conn_state_t snapshot on the
 * SNI path — so SAN matching inherits the SNI-switch-safe snapshot automatically
 * (no new struct field, no new snapshot field).
 */
int mtls_match_cn_pattern(X509 *cert, const char *pattern)
{
    X509_NAME *subject;
    char cn_buf[256] = {0};
    int cn_len;

    if (!cert || !pattern || pattern[0] == '\0') {
        return 0;
    }

    // -----------------------------------------------------------------
    // SAN-DNS first: iterate subjectAltName DNS entries (preferred per
    // X.509 best practice; CN matching is legacy / deprecated).
    // -----------------------------------------------------------------
    int have_san_dns = 0;
    GENERAL_NAMES *sans =
        (GENERAL_NAMES *)X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (sans) {
        int n = sk_GENERAL_NAME_num(sans);
        for (int i = 0; i < n; i++) {
            const GENERAL_NAME *name = sk_GENERAL_NAME_value(sans, i);
            if (!name || name->type != GEN_DNS) {
                continue;
            }
            have_san_dns = 1;
            const unsigned char *dns_data = ASN1_STRING_get0_data(name->d.dNSName);
            int dns_len = ASN1_STRING_length(name->d.dNSName);
            if (!dns_data || dns_len <= 0) {
                continue;
            }
            // Defensively NUL-terminate a bounded copy (ASN1 strings are not
            // guaranteed NUL-terminated, and reject embedded-NUL names).
            char san_buf[256] = {0};
            if (dns_len >= (int)sizeof(san_buf)) {
                continue;  // implausibly long DNS name — skip
            }
            if (memchr(dns_data, '\0', (size_t)dns_len) != NULL) {
                continue;  // embedded NUL — spoofing guard, skip
            }
            memcpy(san_buf, dns_data, (size_t)dns_len);
            san_buf[dns_len] = '\0';

#ifdef HAVE_PROXY_EXTRA_DEBUG
            log_debug("[mTLS] SAN-DNS matching: SAN='%s' vs pattern='%s'",
                      san_buf, pattern);
#endif
            if (mtls_fnmatch_pattern(pattern, san_buf)) {
                GENERAL_NAMES_free(sans);
#ifdef HAVE_PROXY_EXTRA_DEBUG
                log_debug("[mTLS] SAN-DNS match result: MATCH");
#endif
                return 1;
            }
        }
        GENERAL_NAMES_free(sans);
    }

    // If the cert presented SAN-DNS entries but none matched, do NOT silently
    // fall back to CN — per RFC 6125, once SAN is present CN must be ignored.
    if (have_san_dns) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
        log_debug("[mTLS] SAN-DNS present but no match; CN ignored per RFC 6125");
#endif
        return 0;
    }

    // -----------------------------------------------------------------
    // CN fallback: no SAN-DNS present — legacy CN-only cert path.
    // -----------------------------------------------------------------
    subject = X509_get_subject_name(cert);
    if (!subject) {
        return 0;
    }

    // Extract CN from subject
    cn_len = X509_NAME_get_text_by_NID(subject, NID_commonName, cn_buf, sizeof(cn_buf));
    if (cn_len <= 0) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
        log_debug("[mTLS] CN pattern match: no SAN-DNS and no CN in certificate");
#endif
        return 0;
    }

#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[mTLS] CN pattern matching: CN='%s' vs pattern='%s'", cn_buf, pattern);
#endif

    // Use fnmatch for wildcard matching (*, ?) — same semantics as the SAN leg.
    int match = mtls_fnmatch_pattern(pattern, cn_buf);

#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[mTLS] CN pattern match result: %s", match ? "MATCH" : "NO MATCH");
#endif
    return match;
}

/**
 * mtls_get_client_ip - Extract client IP from SSL connection
 * @ssl: SSL connection
 * 
 * Returns: Client IP address (network byte order)
 */
static uint32_t mtls_get_client_ip(SSL *ssl)
{
    int fd;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    fd = SSL_get_fd(ssl);
    if (fd < 0) {
        return 0;
    }

    if (getpeername(fd, (struct sockaddr *)&addr, &addr_len) != 0) {
        return 0;
    }

    if (addr.sin_family != AF_INET) {
        return 0;  // Only IPv4 supported for now
    }

    return addr.sin_addr.s_addr;
}

// ============================================================================
// Frontend mTLS: Client Certificate Verification
// ============================================================================

/**
 * mtls_client_verify_callback - OpenSSL verification callback for client certs
 * @preverify_ok: OpenSSL pre-verification result
 * @x509_ctx: X509 store context
 * 
 * Returns: 1 to accept, 0 to reject
 * 
 * This callback is invoked for each certificate in the client's chain.
 * It performs additional checks beyond OpenSSL's built-in verification.
 */
static int mtls_client_verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    SSL *ssl;
    SSL_CTX *ssl_ctx;
    proxy_arg_t *arg;
    X509 *cert;
    int depth;
    int err;
    char buf[256];

    // Get SSL connection and context
    ssl = X509_STORE_CTX_get_ex_data(x509_ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    if (!ssl) {
        log_error("[mTLS] Failed to get SSL from X509_STORE_CTX");
        return 0;
    }

    ssl_ctx = SSL_get_SSL_CTX(ssl);
    if (!ssl_ctx) {
        log_error("[mTLS] Failed to get SSL_CTX");
        return 0;
    }

    // Get the mTLS config for this connection.
    //
    // Primary path: SSL_CTX ex_data (set by mtls_configure_frontend on rule setup).
    // Fallback path: per-connection snapshot in SSL ex_data (set by sni_servername_callback
    //   BEFORE calling SSL_set_SSL_CTX, which discards the SSL_CTX-level ex_data).
    //
    // The snapshot is a heap-allocated mtls_ssl_conn_state_t (NOT proxy_arg_t) that is
    // owned by the SSL connection and freed via mtls_ssl_conn_state_cleanup when the
    // connection is destroyed.  This design prevents the use-after-free that would occur
    // if we stored a raw proxy_arg_t* while a concurrent rule deletion freed that pointer.
    arg = SSL_CTX_get_ex_data(ssl_ctx, g_ssl_ctx_proxy_arg_index);

    // CN-check fields resolved from whichever source we have
    uint8_t     require_cn = 0;
    const char *cn_pattern = NULL;

    if (arg) {
        // Normal path: no SNI context switch
        require_cn = arg->require_client_cn;
        cn_pattern = arg->client_cn_pattern;
    } else if (g_ssl_proxy_arg_index >= 0) {
        // SNI fallback: use the owned per-connection snapshot
        mtls_ssl_conn_state_t *conn_state =
            (mtls_ssl_conn_state_t *)SSL_get_ex_data(ssl, g_ssl_proxy_arg_index);
        if (!conn_state) {
            log_error("[mTLS] No mTLS config for connection (SNI switch, no snapshot)");
            return 0;
        }
        require_cn = conn_state->require_client_cn;
        cn_pattern = conn_state->client_cn_pattern;
    } else {
        log_error("[mTLS] Failed to get mTLS config: SSL_CTX ex_data NULL, SSL index not initialized");
        return 0;
    }

    cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    depth = X509_STORE_CTX_get_error_depth(x509_ctx);
    err = X509_STORE_CTX_get_error(x509_ctx);

    // Log certificate info
    X509_NAME_oneline(X509_get_subject_name(cert), buf, sizeof(buf));
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[mTLS] Verify client cert: depth=%d subject=%s preverify=%d",
              depth, buf, preverify_ok);
#endif

    // If certificate already failed pre-verification, reject immediately
    if (!preverify_ok) {
        log_error("[mTLS] Client certificate pre-verification failed: %s",
                  X509_verify_cert_error_string(err));
        atomic_fetch_add(&global_stats.mtls_frontend_verify_failures, 1);
        return 0;
    }

    // Additional checks for end-entity certificate (depth 0)
    if (depth == 0) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
        log_debug("[mTLS] Processing end-entity certificate (depth=0): %s", buf);
        log_debug("[mTLS] require_client_cn=%d, pattern='%s'",
                  require_cn, cn_pattern ? cn_pattern : "");
#endif

        // Check CN pattern if required
        if (require_cn && cn_pattern && cn_pattern[0] != '\0') {
            if (!mtls_match_cn_pattern(cert, cn_pattern)) {
                log_error("[mTLS] Client cert CN does not match pattern: %s",
                          cn_pattern);
                atomic_fetch_add(&global_stats.mtls_hostname_mismatch, 1);
                return 0;
            }
#ifdef HAVE_PROXY_EXTRA_DEBUG
            log_debug("[mTLS] CN pattern matched successfully");
#endif
        }

        // Rate limiting check (prevent brute-force attacks)
        uint32_t client_ip = mtls_get_client_ip(ssl);
        if (client_ip != 0) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
            log_debug("[mTLS] Checking rate limit for IP: %08x", client_ip);
#endif
            if (mtls_check_rate_limit(client_ip)) {
                log_error("[mTLS] Client IP rate limited: %08x", client_ip);
                atomic_fetch_add(&global_stats.mtls_rate_limited, 1);
                return 0;
            }
        }

        // Success
        log_info("[mTLS] Client certificate verified successfully: %s", buf);
        atomic_fetch_add(&global_stats.mtls_frontend_verify_success, 1);
#ifdef HAVE_PROXY_EXTRA_DEBUG
        log_debug("[mTLS] Frontend verify success count: %lu",
                  atomic_load(&global_stats.mtls_frontend_verify_success));
#endif
    }

    return 1;  // Accept
}

/**
 * mtls_derive_crl_path - Derive the operator CRL file path from the client CA path
 * @ca_path:  client CA bundle path (arg->client_ca_path)
 * @crl_out:  output buffer for the derived CRL path
 * @crl_sz:   size of crl_out
 *
 * Returns: 1 if an existing CRL file was found at the derived path, 0 otherwise.
 *
 * the CRL is part of the id-referenced TLS-material set
 * supplied by the 77-02 managed-cert directory. Until the dedicated CGO/REST
 * plumb lands in 77-07, the CRL is co-located with the client CA bundle as a
 * sibling "crl.pem" in the same managed directory — the same directory the
 * certId-referenced material set provides. Operator-supplied, static, reloaded
 * whenever mtls_configure_frontend re-runs on a config update (mirroring how
 * client_ca_path is re-applied).
 */
static int mtls_derive_crl_path(const char *ca_path, char *crl_out, size_t crl_sz)
{
    if (!ca_path || ca_path[0] == '\0' || !crl_out || crl_sz == 0) {
        return 0;
    }

    // Locate the last path separator to isolate the managed directory.
    const char *slash = strrchr(ca_path, '/');
    int dir_len = slash ? (int)(slash - ca_path) : 0;  // 0 => current dir

    int written;
    if (dir_len > 0) {
        written = snprintf(crl_out, crl_sz, "%.*s/crl.pem", dir_len, ca_path);
    } else {
        written = snprintf(crl_out, crl_sz, "crl.pem");
    }
    if (written <= 0 || (size_t)written >= crl_sz) {
        return 0;  // truncation — treat as "no CRL"
    }

    // Only signal a CRL when the file actually exists (additive, default-off:
    // absent CRL ⇒ today's behaviour, no CRL_CHECK flag set).
    struct stat st;
    if (stat(crl_out, &st) != 0 || !S_ISREG(st.st_mode)) {
        return 0;
    }
    return 1;
}

/**
 * mtls_load_frontend_crl - Load a leaf-only CRL onto the verify X509_STORE
 * @ctx:      frontend SSL_CTX (its cert store receives the CRL)
 * @crl_path: path to the operator-supplied static CRL (PEM)
 *
 * Returns: 0 on success, negative error code on failure.
 *
 * LEAF-ONLY revocation — sets X509_V_FLAG_CRL_CHECK only (the chain-wide
 * "...CHECK_ALL" variant is intentionally NOT used), matching the HAProxy/Octavia
 * default which does not require a CRL for every CA in the chain. A revoked client leaf then drives
 * preverify_ok=0 → mtls_client_verify_callback returns 0 → handshake rejected.
 *
 * Pitfall 5: the CRL lives CTX-level on the X509_STORE, so it survives the SNI
 * SSL_set_SSL_CTX switch (the per-hostname CTX shares the same store config) —
 * no per-connection snapshot is needed for the CRL.
 */
static int mtls_load_frontend_crl(SSL_CTX *ctx, const char *crl_path)
{
    X509_STORE *store = SSL_CTX_get_cert_store(ctx);
    if (!store) {
        log_error("[mTLS] CRL: failed to get SSL_CTX cert store");
        return -EINVAL;
    }

    X509_LOOKUP *lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    if (!lookup) {
        log_error("[mTLS] CRL: failed to add X509_LOOKUP_file to store");
        return -EINVAL;
    }

    if (X509_load_crl_file(lookup, crl_path, X509_FILETYPE_PEM) != 1) {
        log_error("[mTLS] CRL: failed to load CRL file %s - %s",
                  crl_path, ERR_error_string(ERR_get_error(), NULL));
        return -EINVAL;
    }

    // Leaf-only check — explicitly NOT the chain-wide "...CHECK_ALL" flag.
    if (X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK) != 1) {
        log_error("[mTLS] CRL: failed to set X509_V_FLAG_CRL_CHECK on store");
        return -EINVAL;
    }

    log_info("[mTLS] Loaded client CRL (leaf-only revocation check): %s", crl_path);
    return 0;
}

/**
 * mtls_configure_frontend - Configure frontend mTLS for SSL context
 * @ctx: SSL_CTX to configure
 * @arg: Proxy configuration with mTLS settings
 *
 * Returns: 0 on success, negative on error
 */
int mtls_configure_frontend(SSL_CTX *ctx, proxy_arg_t *arg)
{
    int verify_mode;
    STACK_OF(X509_NAME) *ca_list;

    if (!ctx || !arg) {
        return -EINVAL;
    }

    // Initialize ex_data index if needed
    if (g_ssl_ctx_proxy_arg_index < 0) {
        // Register with cleanup callback to auto-free proxy_arg when SSL_CTX is destroyed
        g_ssl_ctx_proxy_arg_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, 
                                                              mtls_proxy_arg_cleanup);
        if (g_ssl_ctx_proxy_arg_index < 0) {
            log_error("[mTLS] Failed to allocate SSL_CTX ex_data index");
            return -ENOMEM;
        }
    }

    // Initialize SSL-level ex_data index for per-connection mTLS state snapshots.
    // Register WITH a cleanup callback so OpenSSL frees the snapshot automatically
    // when SSL_free() is called (i.e., when the connection closes).
    if (g_ssl_proxy_arg_index < 0) {
        g_ssl_proxy_arg_index = SSL_get_ex_new_index(0, NULL, NULL, NULL,
                                                      mtls_ssl_conn_state_cleanup);
        if (g_ssl_proxy_arg_index < 0) {
            log_error("[mTLS] Failed to allocate SSL ex_data index");
            return -ENOMEM;
        }
    }

    // Store proxy_arg in SSL_CTX for use in verification callback
    if (SSL_CTX_set_ex_data(ctx, g_ssl_ctx_proxy_arg_index, arg) != 1) {
        log_error("[mTLS] Failed to set proxy_arg in SSL_CTX");
        return -EINVAL;
    }

    // Configure verification mode
    switch (arg->frontend_mtls_mode) {
    case 1:  // Optional
        verify_mode = SSL_VERIFY_PEER;
        log_info("[mTLS] Frontend mode: OPTIONAL (accept with/without client cert)");
#ifdef HAVE_PROXY_EXTRA_DEBUG
        log_debug("[mTLS] CA path: %s", arg->client_ca_path[0] ? arg->client_ca_path : "(empty)");
        log_debug("[mTLS] Require CN: %d, CN pattern: %s",
                  arg->require_client_cn, arg->client_cn_pattern);
#endif
        break;
    case 2:  // Required
        verify_mode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
        log_info("[mTLS] Frontend mode: REQUIRED (reject without valid client cert)");
#ifdef HAVE_PROXY_EXTRA_DEBUG
        log_debug("[mTLS] CA path: %s", arg->client_ca_path[0] ? arg->client_ca_path : "(empty)");
        log_debug("[mTLS] Require CN: %d, CN pattern: %s",
                  arg->require_client_cn, arg->client_cn_pattern);
#endif
        break;
    default:  // Disabled
        log_debug("[mTLS] Frontend mTLS disabled (mode=%d)", arg->frontend_mtls_mode);
        return 0;
    }

    // Set verification mode and callback
    SSL_CTX_set_verify(ctx, verify_mode, mtls_client_verify_callback);
    SSL_CTX_set_verify_depth(ctx, MTLS_VERIFY_DEPTH_MAX);

    // Load client CA certificate bundle
    if (arg->client_ca_path[0] != '\0') {
#ifdef HAVE_PROXY_EXTRA_DEBUG
        log_debug("[mTLS] Loading client CA bundle from: %s", arg->client_ca_path);
#endif
        if (SSL_CTX_load_verify_locations(ctx, arg->client_ca_path, NULL) != 1) {
            log_error("[mTLS] Failed to load client CA bundle: %s - %s",
                      arg->client_ca_path, ERR_error_string(ERR_get_error(), NULL));
            atomic_fetch_add(&global_stats.mtls_frontend_verify_failures, 1);
            return -EINVAL;
        }

        log_info("[mTLS] Loaded client CA bundle: %s", arg->client_ca_path);
#ifdef HAVE_PROXY_EXTRA_DEBUG
        log_debug("[mTLS] SSL_CTX verify mode: %d, verify depth: %d",
                  SSL_CTX_get_verify_mode(ctx), SSL_CTX_get_verify_depth(ctx));
#endif

        // Set client CA list (sent in TLS handshake Certificate Request)
        ca_list = SSL_load_client_CA_file(arg->client_ca_path);
        if (ca_list) {
            SSL_CTX_set_client_CA_list(ctx, ca_list);
            log_debug("[mTLS] Set client CA list for TLS handshake");
        } else {
            log_warn("[mTLS] Failed to set client CA list (handshake may fail)");
        }

        // leaf-only client-cert CRL revocation.
        // Placed AFTER SSL_CTX_load_verify_locations so the CRL rides the same
        // verify X509_STORE the CA bundle just populated. The CRL is the
        // operator-supplied static file in the same managed TLS-material
        // directory as the CA bundle (sibling crl.pem); reloaded here on every
        // (re)configure, mirroring how client_ca_path is re-applied. Absent CRL
        // ⇒ today's behaviour (additive / default-off — no CRL_CHECK flag set).
        // prefer the EXPLICIT operator-supplied CRL path
        // (arg->client_crl_path, plumbed by 77-07) when set; otherwise fall back to the
        // 77-04 convention (sibling crl.pem in the CA dir). Both are leaf-only / additive.
        char crl_path[512];
        int have_crl = 0;
        if (arg->client_crl_path[0] != '\0') {
            snprintf(crl_path, sizeof(crl_path), "%s", arg->client_crl_path);
            have_crl = 1;
        } else if (mtls_derive_crl_path(arg->client_ca_path, crl_path, sizeof(crl_path))) {
            have_crl = 1;
        }
        if (have_crl) {
            if (mtls_load_frontend_crl(ctx, crl_path) != 0) {
                log_error("[mTLS] Failed to apply client CRL: %s", crl_path);
                atomic_fetch_add(&global_stats.mtls_frontend_verify_failures, 1);
                return -EINVAL;
            }
        } else {
#ifdef HAVE_PROXY_EXTRA_DEBUG
            log_debug("[mTLS] No client CRL present alongside CA bundle (revocation off)");
#endif
        }
    } else {
        log_warn("[mTLS] Client cert verification enabled but no CA bundle specified");
    }

    log_info("[mTLS] Frontend mTLS configured successfully");
    return 0;
}

// ============================================================================
// Backend mTLS: Server Certificate Verification
// ============================================================================

/**
 * mtls_backend_verify_callback - OpenSSL verification callback for backend server certs
 * @preverify_ok: OpenSSL pre-verification result
 * @x509_ctx: X509 store context
 * 
 * Returns: 1 to accept, 0 to reject
 */
static int mtls_backend_verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    X509 *cert;
    int depth;
    int err;
    char buf[256];

    cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    depth = X509_STORE_CTX_get_error_depth(x509_ctx);
    err = X509_STORE_CTX_get_error(x509_ctx);

    // Log certificate info
    X509_NAME_oneline(X509_get_subject_name(cert), buf, sizeof(buf));
    log_debug("[mTLS] Verify backend cert: depth=%d subject=%s preverify=%d",
              depth, buf, preverify_ok);

    if (!preverify_ok) {
        log_error("[mTLS] Backend cert verification failed: %s (depth=%d)",
                  X509_verify_cert_error_string(err), depth);
        atomic_fetch_add(&global_stats.mtls_backend_verify_failures, 1);
        return 0;
    }

    if (depth == 0) {
        log_info("[mTLS] Backend certificate verified successfully: %s", buf);
        atomic_fetch_add(&global_stats.mtls_backend_verify_success, 1);
    }

    return 1;
}

/**
 * mtls_configure_backend - Configure backend mTLS for client SSL context
 * @ctx: SSL_CTX for backend connections
 * @arg: Proxy configuration with backend mTLS settings
 * 
 * Returns: 0 on success, negative on error
 */
int mtls_configure_backend(SSL_CTX *ctx, proxy_arg_t *arg)
{
    if (!ctx || !arg) {
        return -EINVAL;
    }

    // backend CA/client-cert material is referenced
    // by certId, not inline path strings. Resolve the proxy_arg certId refs into
    // managed-dir paths (/etc/loxilb/certs/<certId>/{ca,client}.{crt,key}) here,
    // before the existing load_verify_locations / cert+key load. Absent files
    // yield "" → today's fallback (system CA / no client cert).
    char backend_ca_path[512] = {0};
    char backend_client_cert_path[512] = {0};
    char backend_client_key_path[512] = {0};
    proxy_certid_resolve_backend(arg->backend_ca_cert_id,
                                 backend_ca_path,
                                 backend_client_cert_path,
                                 backend_client_key_path,
                                 sizeof(backend_ca_path));
    // The CA may live under the client certId dir; if the CA certId resolved no
    // ca.crt but a separate backend_client_cert_id is set, the client cert/key
    // come from that id's dir.
    if (backend_client_cert_path[0] == '\0' && arg->backend_client_cert_id[0] != '\0') {
        char unused_ca[512] = {0};
        proxy_certid_resolve_backend(arg->backend_client_cert_id,
                                     unused_ca,
                                     backend_client_cert_path,
                                     backend_client_key_path,
                                     sizeof(backend_client_cert_path));
    }

    // Configure server certificate verification
    if (arg->backend_verify_cert) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
        log_debug("[mTLS] Configuring backend server certificate verification");
        log_debug("[mTLS] Backend CA path: %s",
                  backend_ca_path[0] ? backend_ca_path : "(system CA store)");
#endif
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, mtls_backend_verify_callback);
        SSL_CTX_set_verify_depth(ctx, MTLS_VERIFY_DEPTH_MAX);

        // Load backend CA bundle
        if (backend_ca_path[0] != '\0') {
#ifdef HAVE_PROXY_EXTRA_DEBUG
            log_debug("[mTLS] Loading backend CA bundle: %s", backend_ca_path);
#endif
            if (SSL_CTX_load_verify_locations(ctx, backend_ca_path, NULL) != 1) {
                log_error("[mTLS] Failed to load backend CA bundle: %s - %s",
                          backend_ca_path, ERR_error_string(ERR_get_error(), NULL));
                atomic_fetch_add(&global_stats.mtls_backend_verify_failures, 1);
                return -EINVAL;
            }
            log_info("[mTLS] Loaded backend CA bundle: %s", backend_ca_path);
        } else {
            // Use system CA store
#ifdef HAVE_PROXY_EXTRA_DEBUG
            log_debug("[mTLS] Loading system default CA paths");
#endif
            if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
                log_error("[mTLS] Failed to load system CA store: %s",
                          ERR_error_string(ERR_get_error(), NULL));
                return -EINVAL;
            }
            log_info("[mTLS] Using system CA store for backend verification");
        }
    } else {
        // No verification (backward compatible default)
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        log_debug("[mTLS] Backend server cert verification disabled");
    }

    // Load client certificate for backend mTLS (if configured)
    if (backend_client_cert_path[0] != '\0') {
#ifdef HAVE_PROXY_EXTRA_DEBUG
        log_debug("[mTLS] Loading backend client certificate: %s", backend_client_cert_path);
        log_debug("[mTLS] Loading backend client key: %s", backend_client_key_path);
#endif
        if (SSL_CTX_use_certificate_chain_file(ctx, backend_client_cert_path) != 1) {
            log_error("[mTLS] Failed to load backend client cert: %s - %s",
                      backend_client_cert_path, ERR_error_string(ERR_get_error(), NULL));
            return -EINVAL;
        }

        if (SSL_CTX_use_PrivateKey_file(ctx, backend_client_key_path, SSL_FILETYPE_PEM) != 1) {
            log_error("[mTLS] Failed to load backend client key: %s - %s",
                      backend_client_key_path, ERR_error_string(ERR_get_error(), NULL));
            return -EINVAL;
        }

        // Verify cert and key match
#ifdef HAVE_PROXY_EXTRA_DEBUG
        log_debug("[mTLS] Verifying backend client cert/key pair");
#endif
        if (SSL_CTX_check_private_key(ctx) != 1) {
            log_error("[mTLS] Backend client cert and key do not match");
            return -EINVAL;
        }

        log_info("[mTLS] Loaded backend client certificate: %s", backend_client_cert_path);
#ifdef HAVE_PROXY_EXTRA_DEBUG
        log_debug("[mTLS] Backend client cert/key verification successful");
#endif
    }

    log_info("[mTLS] Backend mTLS configured successfully");
    return 0;
}

// ============================================================================
// CGO API Functions
// ============================================================================

/**
 * proxy_config_mtls_frontend - Configure frontend mTLS for a service
 * (Stub for - full implementation requires service lookup)
 */
int proxy_config_mtls_frontend(uint32_t service_id, uint8_t client_cert_mode,
                                const char *client_ca_path, uint8_t require_client_cn,
                                const char *client_cn_pattern)
{
    log_info("[mTLS] proxy_config_mtls_frontend called (service=%u, mode=%u)",
             service_id, client_cert_mode);
    // TODO: Implement dynamic configuration
    return -ENOSYS;  // Not yet implemented
}

/**
 * proxy_config_mtls_backend - Configure backend mTLS for a service
 * (Stub for - full implementation requires service lookup)
 */
int proxy_config_mtls_backend(uint32_t service_id, uint8_t verify_cert,
                               const char *backend_ca_path,
                               const char *client_cert_path,
                               const char *client_key_path)
{
    log_info("[mTLS] proxy_config_mtls_backend called (service=%u, verify=%u)",
             service_id, verify_cert);
    // TODO: Implement dynamic configuration
    return -ENOSYS;  // Not yet implemented
}

/**
 * proxy_clear_mtls_config - Clear mTLS configuration for a service
 * (Stub for)
 */
int proxy_clear_mtls_config(uint32_t service_id)
{
    log_info("[mTLS] proxy_clear_mtls_config called (service=%u)", service_id);
    // TODO: Implement dynamic configuration
    return -ENOSYS;  // Not yet implemented
}

#endif /* HAVE_MTLS */
