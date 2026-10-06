/* SPDX-License-Identifier: BSD-3-Clause
 *
 * sockproxy_betls.h - what the backend (re-encryption) leg asks of an
 * endpoint's certificate, and what it presents.
 *
 * A context is built once per listener from a policy; every connection made
 * with it then names the peer it expects:
 *
 *   - Verification is on only when the rule asks for it, and then it needs the
 *     rule's own CA bundle. There is no fallback to another trust store: a
 *     rule that asks for verification and has no CA is an error.
 *   - A verified endpoint must also be the endpoint that was dialled. With a
 *     server name on the rule, the certificate must carry it as a DNS name;
 *     without one, the certificate must carry the endpoint's address. A chain
 *     that is merely signed by the right CA does not pass.
 *   - A client certificate is presented only when the rule names one, and
 *     then both files must load and match. Nothing is presented by default.
 *
 * Self-contained (OpenSSL only) so the unit test builds it without the proxy
 * object graph. Included by one translation unit of the proxy.
 */
#ifndef __SOCKPROXY_BETLS_H__
#define __SOCKPROXY_BETLS_H__

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>

#define BETLS_VERIFY_DEPTH 10

struct betls_policy {
  int verify;                   /* verify the endpoint's certificate */
  const char *ca_file;          /* resolved CA bundle; NULL or "" when absent */
  int client_id_set;            /* the rule names a client certificate */
  const char *client_cert_file; /* resolved; NULL or "" when absent */
  const char *client_key_file;  /* resolved; NULL or "" when absent */
  const char *server_name;      /* SNI and expected DNS name; NULL or "" for none */
};

enum betls_event {
  BETLS_EV_VERIFY_OK = 0,       /* a leaf certificate passed */
  BETLS_EV_VERIFY_FAIL,         /* a certificate, or the rule's CA, was refused */
  BETLS_EV_NAME_MISMATCH,       /* the chain is good but names another peer */
};

/* The includer's counters. */
static void betls_event(enum betls_event ev);

static int betls_name_index = -1;

static inline int
betls_str_set(const char *s)
{
  return s && s[0] != '\0';
}

static void
betls_name_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx,
                long argl, void *argp)
{
  (void)parent; (void)ad; (void)idx; (void)argl; (void)argp;
  free(ptr);
}

static int
betls_verify_cb(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
  int err = X509_STORE_CTX_get_error(x509_ctx);
  int depth = X509_STORE_CTX_get_error_depth(x509_ctx);

  if (!preverify_ok) {
    if (err == X509_V_ERR_HOSTNAME_MISMATCH ||
        err == X509_V_ERR_IP_ADDRESS_MISMATCH) {
      betls_event(BETLS_EV_NAME_MISMATCH);
    }
    betls_event(BETLS_EV_VERIFY_FAIL);
    return 0;
  }
  if (depth == 0) {
    betls_event(BETLS_EV_VERIFY_OK);
  }
  return 1;
}

/* Apply a policy to a client context. Returns 0, or a negative errno with
 * *why naming what was refused. The context is the caller's on every return. */
static inline int
betls_ctx_configure(SSL_CTX *ctx, const struct betls_policy *pol, const char **why)
{
  const char *unused;

  if (!why) why = &unused;
  *why = "";
  if (!ctx || !pol) {
    *why = "no context";
    return -EINVAL;
  }

  if (pol->verify) {
    if (!betls_str_set(pol->ca_file)) {
      *why = "verification is requested and the rule has no CA bundle";
      betls_event(BETLS_EV_VERIFY_FAIL);
      return -ENOENT;
    }
    if (SSL_CTX_load_verify_locations(ctx, pol->ca_file, NULL) != 1) {
      *why = "the CA bundle does not load";
      betls_event(BETLS_EV_VERIFY_FAIL);
      return -EINVAL;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, betls_verify_cb);
    SSL_CTX_set_verify_depth(ctx, BETLS_VERIFY_DEPTH);
  } else {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  }

  if (pol->client_id_set) {
    if (!betls_str_set(pol->client_cert_file) || !betls_str_set(pol->client_key_file)) {
      *why = "the client certificate or its key is missing";
      return -ENOENT;
    }
    if (SSL_CTX_use_certificate_chain_file(ctx, pol->client_cert_file) != 1) {
      *why = "the client certificate does not load";
      return -EINVAL;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, pol->client_key_file, SSL_FILETYPE_PEM) != 1) {
      *why = "the client key does not load";
      return -EINVAL;
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
      *why = "the client certificate and key do not match";
      return -EINVAL;
    }
  }

  if (betls_str_set(pol->server_name)) {
    char *name;

    if (betls_name_index < 0) {
      betls_name_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, betls_name_free);
      if (betls_name_index < 0) {
        *why = "no context slot for the server name";
        return -ENOMEM;
      }
    }
    name = strdup(pol->server_name);
    if (!name || SSL_CTX_set_ex_data(ctx, betls_name_index, name) != 1) {
      free(name);
      *why = "the server name could not be stored";
      return -ENOMEM;
    }
  }
  return 0;
}

/* Name the peer one connection expects, before its handshake. epip is the
 * dialled IPv4 address in network byte order. Returns 0 or a negative errno;
 * on an error the handshake must not be started. */
static inline int
betls_ssl_set_identity(SSL *ssl, uint32_t epip)
{
  SSL_CTX *ctx;
  const char *name = NULL;

  if (!ssl) {
    return -EINVAL;
  }
  ctx = SSL_get_SSL_CTX(ssl);
  if (betls_name_index >= 0) {
    name = SSL_CTX_get_ex_data(ctx, betls_name_index);
  }
  if (betls_str_set(name)) {
    if (SSL_set_tlsext_host_name(ssl, name) != 1) {
      return -EINVAL;
    }
  }
  if (!(SSL_CTX_get_verify_mode(ctx) & SSL_VERIFY_PEER)) {
    return 0;
  }
  if (betls_str_set(name)) {
    /* A DNS name of the certificate, not its subject, and no partial
     * wildcard such as "a*.example.com". */
    SSL_set_hostflags(ssl, X509_CHECK_FLAG_NEVER_CHECK_SUBJECT |
                           X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    if (SSL_set1_host(ssl, name) != 1) {
      return -EINVAL;
    }
  } else {
    if (X509_VERIFY_PARAM_set1_ip(SSL_get0_param(ssl),
                                  (const unsigned char *)&epip, sizeof(epip)) != 1) {
      return -EINVAL;
    }
  }
  return 0;
}

#endif /* __SOCKPROXY_BETLS_H__ */
