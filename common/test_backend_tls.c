/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_backend_tls.c - what the backend leg accepts from an endpoint, and
 * what it presents (sockproxy_betls.h).
 *
 * Each case builds a client context from a policy, names the dialled peer on
 * one connection and runs a real handshake against an in-process server over
 * a BIO pair. Certificates are made here: two CAs, and leaves that differ only
 * in the name or address they carry.
 *
 * THE ORACLE IS SELF-VERIFYING. A leaf signed by the right CA for ANOTHER
 * address is the case the identity step exists for. It is run twice: with the
 * identity step it must be refused and counted as a name mismatch, and without
 * it (the shape before this unit) the same handshake must succeed. If the
 * second run fails, the first one proves nothing.
 *
 * Build (wired into `make test_betls`):
 *   gcc -Wall -Wextra -Werror -o test_backend_tls test_backend_tls.c -I. -lssl -lcrypto
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>

#include "sockproxy_betls.h"
#include "sockproxy_betls_state.h"

static int failures = 0;
static int checks   = 0;
static long ev_count[3];

static void
betls_event(enum betls_event ev)
{
  ev_count[ev]++;
}

static void
check(const char *name, int ok, long got, long want)
{
  checks++;
  if (!ok) {
    failures++;
    printf("FAIL %-66s got %ld want %ld\n", name, got, want);
  } else {
    printf("ok   %-66s (%ld)\n", name, got);
  }
}

/* ---- certificates ---------------------------------------------------- */

static char tmpdir[64];

static EVP_PKEY *
mk_key(void)
{
  return EVP_RSA_gen(2048);
}

/* A certificate for `cn`, signed by (issuer, issuer_key) or self-signed when
 * issuer is NULL. san is an X509v3 subjectAltName value or NULL. */
static X509 *
mk_cert(const char *cn, EVP_PKEY *key, X509 *issuer, EVP_PKEY *issuer_key,
        const char *san, int is_ca)
{
  static long serial = 1;
  X509 *x = X509_new();
  X509_NAME *name;
  X509V3_CTX v3;
  X509_EXTENSION *ext;

  X509_set_version(x, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(x), serial++);
  X509_gmtime_adj(X509_getm_notBefore(x), -3600);
  X509_gmtime_adj(X509_getm_notAfter(x), 3600);
  X509_set_pubkey(x, key);
  name = X509_get_subject_name(x);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)cn, -1, -1, 0);
  X509_set_issuer_name(x, issuer ? X509_get_subject_name(issuer) : name);

  X509V3_set_ctx(&v3, issuer ? issuer : x, x, NULL, NULL, 0);
  ext = X509V3_EXT_conf_nid(NULL, &v3, NID_basic_constraints,
                            is_ca ? "critical,CA:TRUE" : "CA:FALSE");
  X509_add_ext(x, ext, -1);
  X509_EXTENSION_free(ext);
  if (san) {
    ext = X509V3_EXT_conf_nid(NULL, &v3, NID_subject_alt_name, san);
    if (!ext) {
      printf("FAIL cannot build subjectAltName '%s'\n", san);
      exit(2);
    }
    X509_add_ext(x, ext, -1);
    X509_EXTENSION_free(ext);
  }
  if (!X509_sign(x, issuer_key ? issuer_key : key, EVP_sha256())) {
    printf("FAIL cannot sign certificate '%s'\n", cn);
    exit(2);
  }
  return x;
}

static const char *
path_of(const char *file)
{
  static char buf[8][160];
  static int n;
  char *p = buf[n++ % 8];

  snprintf(p, sizeof(buf[0]), "%s/%s", tmpdir, file);
  return p;
}

static void
write_cert(const char *file, X509 *x)
{
  FILE *fp = fopen(path_of(file), "w");
  PEM_write_X509(fp, x);
  fclose(fp);
}

static void
write_key(const char *file, EVP_PKEY *k)
{
  FILE *fp = fopen(path_of(file), "w");
  PEM_write_PrivateKey(fp, k, NULL, NULL, 0, NULL, NULL);
  fclose(fp);
}

static void
write_text(const char *file, const char *text)
{
  FILE *fp = fopen(path_of(file), "w");
  fputs(text, fp);
  fclose(fp);
}

/* ---- one handshake ---------------------------------------------------- */

struct hs_result {
  int ok;                 /* both sides finished */
  char sni[128];          /* the name the server was sent, "" for none */
  int client_cert_seen;   /* the server received a client certificate */
};

static int
server_accept_any(int preverify_ok, X509_STORE_CTX *ctx)
{
  (void)preverify_ok; (void)ctx;
  return 1;
}

/* Run a handshake between a client built from cctx and a server presenting
 * (cert, key). with_identity selects whether the identity step runs. */
static struct hs_result
handshake(SSL_CTX *cctx, X509 *cert, EVP_PKEY *key, const char *dial_ip,
          int with_identity)
{
  struct hs_result r = { 0 };
  SSL_CTX *sctx = SSL_CTX_new(TLS_server_method());
  SSL *c, *s;
  BIO *cb, *sb;
  const char *sni;
  X509 *peer;
  int cdone = 0, sdone = 0, i;

  SSL_CTX_use_certificate(sctx, cert);
  SSL_CTX_use_PrivateKey(sctx, key);
  /* Ask for a client certificate, accept whatever comes, require none. */
  SSL_CTX_set_verify(sctx, SSL_VERIFY_PEER, server_accept_any);

  c = SSL_new(cctx);
  s = SSL_new(sctx);
  BIO_new_bio_pair(&cb, 0, &sb, 0);
  SSL_set_bio(c, cb, cb);
  SSL_set_bio(s, sb, sb);
  SSL_set_connect_state(c);
  SSL_set_accept_state(s);

  if (with_identity) {
    uint32_t epip = inet_addr(dial_ip);
    if (betls_ssl_set_identity(c, epip) != 0) {
      goto out;
    }
  }

  for (i = 0; i < 64 && !(cdone && sdone); i++) {
    int rc;
    if (!cdone) {
      rc = SSL_do_handshake(c);
      if (rc == 1) cdone = 1;
      else if (SSL_get_error(c, rc) != SSL_ERROR_WANT_READ &&
               SSL_get_error(c, rc) != SSL_ERROR_WANT_WRITE) break;
    }
    if (!sdone) {
      rc = SSL_do_handshake(s);
      if (rc == 1) sdone = 1;
      else if (SSL_get_error(s, rc) != SSL_ERROR_WANT_READ &&
               SSL_get_error(s, rc) != SSL_ERROR_WANT_WRITE) break;
    }
  }
  r.ok = cdone && sdone;
  sni = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);
  if (sni) snprintf(r.sni, sizeof(r.sni), "%s", sni);
  peer = SSL_get1_peer_certificate(s);
  r.client_cert_seen = peer != NULL;
  X509_free(peer);
out:
  ERR_clear_error();
  SSL_free(c);
  SSL_free(s);
  SSL_CTX_free(sctx);
  return r;
}

static SSL_CTX *
client_ctx(const struct betls_policy *pol, int *rc)
{
  SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
  const char *why = "";

  *rc = betls_ctx_configure(ctx, pol, &why);
  if (*rc != 0) {
    printf("     refused: %s\n", why);
  }
  ERR_clear_error();
  return ctx;
}

static void
reset_events(void)
{
  memset(ev_count, 0, sizeof(ev_count));
}

int
main(void)
{
  EVP_PKEY *ca_key, *other_ca_key, *leaf_key, *client_key, *stray_key;
  X509 *ca, *other_ca;
  X509 *leaf_ip, *leaf_other_ip, *leaf_wrong_ca, *leaf_dns, *leaf_other_dns, *leaf_cn_only;
  X509 *client;
  struct betls_policy pol;
  struct hs_result r;
  SSL_CTX *ctx;
  int rc;

  snprintf(tmpdir, sizeof(tmpdir), "/tmp/test_betls.XXXXXX");
  if (!mkdtemp(tmpdir)) {
    perror("mkdtemp");
    return 2;
  }

  ca_key = mk_key(); other_ca_key = mk_key(); leaf_key = mk_key();
  client_key = mk_key(); stray_key = mk_key();
  ca = mk_cert("rule ca", ca_key, NULL, NULL, NULL, 1);
  other_ca = mk_cert("other ca", other_ca_key, NULL, NULL, NULL, 1);
  leaf_ip        = mk_cert("ep", leaf_key, ca, ca_key, "IP:10.1.1.1", 0);
  leaf_other_ip  = mk_cert("ep", leaf_key, ca, ca_key, "IP:10.1.1.2", 0);
  leaf_wrong_ca  = mk_cert("ep", leaf_key, other_ca, other_ca_key, "IP:10.1.1.1", 0);
  leaf_dns       = mk_cert("ep", leaf_key, ca, ca_key, "DNS:backend.test", 0);
  leaf_other_dns = mk_cert("ep", leaf_key, ca, ca_key, "DNS:other.test", 0);
  leaf_cn_only   = mk_cert("backend.test", leaf_key, ca, ca_key, NULL, 0);
  client = mk_cert("gateway", client_key, ca, ca_key, NULL, 0);

  write_cert("ca.crt", ca);
  write_cert("client.crt", client);
  write_key("client.key", client_key);
  write_key("stray.key", stray_key);
  write_text("garbage.crt", "not-a-certificate\n");

  /* ---- verification needs the rule's CA ------------------------------ */
  reset_events();
  memset(&pol, 0, sizeof(pol));
  pol.verify = 1;
  ctx = client_ctx(&pol, &rc);
  check("verify without a CA bundle is refused", rc == -ENOENT, rc, -ENOENT);
  check("  and counted as a verification failure", ev_count[BETLS_EV_VERIFY_FAIL] == 1,
        ev_count[BETLS_EV_VERIFY_FAIL], 1);
  SSL_CTX_free(ctx);

  pol.ca_file = path_of("garbage.crt");
  ctx = client_ctx(&pol, &rc);
  check("verify with a CA bundle that does not load is refused", rc == -EINVAL, rc, -EINVAL);
  SSL_CTX_free(ctx);

  /* ---- identity by address ------------------------------------------- */
  memset(&pol, 0, sizeof(pol));
  pol.verify = 1;
  pol.ca_file = path_of("ca.crt");
  ctx = client_ctx(&pol, &rc);
  check("verify with the rule's CA configures", rc == 0, rc, 0);

  reset_events();
  r = handshake(ctx, leaf_ip, leaf_key, "10.1.1.1", 1);
  check("leaf for the dialled address is accepted", r.ok == 1, r.ok, 1);
  check("  and counted once as verified", ev_count[BETLS_EV_VERIFY_OK] == 1,
        ev_count[BETLS_EV_VERIFY_OK], 1);
  check("  and no SNI is sent without a server name", r.sni[0] == '\0', r.sni[0], 0);
  check("  and no client certificate is presented by default", r.client_cert_seen == 0,
        r.client_cert_seen, 0);

  reset_events();
  r = handshake(ctx, leaf_other_ip, leaf_key, "10.1.1.1", 1);
  check("leaf of the same CA for ANOTHER address is refused", r.ok == 0, r.ok, 0);
  check("  and counted as a name mismatch", ev_count[BETLS_EV_NAME_MISMATCH] == 1,
        ev_count[BETLS_EV_NAME_MISMATCH], 1);
  r = handshake(ctx, leaf_other_ip, leaf_key, "10.1.1.1", 0);
  check("  control: without the identity step the same leaf passes", r.ok == 1, r.ok, 1);

  reset_events();
  r = handshake(ctx, leaf_wrong_ca, leaf_key, "10.1.1.1", 1);
  check("leaf of another CA for the right address is refused", r.ok == 0, r.ok, 0);
  check("  and it is not a name mismatch", ev_count[BETLS_EV_NAME_MISMATCH] == 0,
        ev_count[BETLS_EV_NAME_MISMATCH], 0);
  check("  and it is a verification failure", ev_count[BETLS_EV_VERIFY_FAIL] >= 1,
        ev_count[BETLS_EV_VERIFY_FAIL], 1);

  r = handshake(ctx, leaf_dns, leaf_key, "10.1.1.1", 1);
  check("leaf with only a DNS name is refused when no server name is set", r.ok == 0, r.ok, 0);
  SSL_CTX_free(ctx);

  /* ---- identity by server name --------------------------------------- */
  pol.server_name = "backend.test";
  ctx = client_ctx(&pol, &rc);
  check("verify with a server name configures", rc == 0, rc, 0);

  reset_events();
  r = handshake(ctx, leaf_dns, leaf_key, "10.1.1.1", 1);
  check("leaf carrying the server name is accepted", r.ok == 1, r.ok, 1);
  check("  and the server name is sent as SNI", strcmp(r.sni, "backend.test") == 0,
        (long)strlen(r.sni), (long)strlen("backend.test"));

  reset_events();
  r = handshake(ctx, leaf_other_dns, leaf_key, "10.1.1.1", 1);
  check("leaf carrying another name is refused", r.ok == 0, r.ok, 0);
  check("  and counted as a name mismatch", ev_count[BETLS_EV_NAME_MISMATCH] == 1,
        ev_count[BETLS_EV_NAME_MISMATCH], 1);

  r = handshake(ctx, leaf_cn_only, leaf_key, "10.1.1.1", 1);
  check("leaf with the name only in its subject is refused", r.ok == 0, r.ok, 0);

  r = handshake(ctx, leaf_ip, leaf_key, "10.1.1.1", 1);
  check("leaf with only the address is refused when a server name is set", r.ok == 0, r.ok, 0);
  SSL_CTX_free(ctx);

  /* ---- no verification: today's behaviour ---------------------------- */
  memset(&pol, 0, sizeof(pol));
  ctx = client_ctx(&pol, &rc);
  check("no verification configures", rc == 0, rc, 0);
  reset_events();
  r = handshake(ctx, leaf_wrong_ca, leaf_key, "10.9.9.9", 1);
  check("without verification any leaf is accepted", r.ok == 1, r.ok, 1);
  check("  and nothing is counted", ev_count[0] + ev_count[1] + ev_count[2] == 0,
        ev_count[0] + ev_count[1] + ev_count[2], 0);
  check("  and no client certificate is presented", r.client_cert_seen == 0,
        r.client_cert_seen, 0);
  SSL_CTX_free(ctx);

  pol.server_name = "backend.test";
  ctx = client_ctx(&pol, &rc);
  r = handshake(ctx, leaf_other_dns, leaf_key, "10.9.9.9", 1);
  check("a server name without verification is sent as SNI only", r.ok == 1 &&
        strcmp(r.sni, "backend.test") == 0, r.ok, 1);
  SSL_CTX_free(ctx);

  /* ---- client certificate -------------------------------------------- */
  memset(&pol, 0, sizeof(pol));
  pol.client_id_set = 1;
  ctx = client_ctx(&pol, &rc);
  check("a named client certificate with no files is refused", rc == -ENOENT, rc, -ENOENT);
  SSL_CTX_free(ctx);

  pol.client_cert_file = path_of("client.crt");
  ctx = client_ctx(&pol, &rc);
  check("a client certificate without its key is refused", rc == -ENOENT, rc, -ENOENT);
  SSL_CTX_free(ctx);

  pol.client_cert_file = path_of("garbage.crt");
  pol.client_key_file = path_of("client.key");
  ctx = client_ctx(&pol, &rc);
  check("a client certificate that does not parse is refused", rc == -EINVAL, rc, -EINVAL);
  SSL_CTX_free(ctx);

  pol.client_cert_file = path_of("client.crt");
  pol.client_key_file = path_of("stray.key");
  ctx = client_ctx(&pol, &rc);
  check("a client certificate with another key is refused", rc == -EINVAL, rc, -EINVAL);
  SSL_CTX_free(ctx);

  pol.client_key_file = path_of("client.key");
  ctx = client_ctx(&pol, &rc);
  check("a matching client pair configures", rc == 0, rc, 0);
  r = handshake(ctx, leaf_ip, leaf_key, "10.1.1.1", 1);
  check("  and the endpoint receives the client certificate", r.ok == 1 &&
        r.client_cert_seen == 1, r.client_cert_seen, 1);
  SSL_CTX_free(ctx);

  /* A client pair lying next to the CA is not picked up: only a named
   * client certificate is presented. */
  memset(&pol, 0, sizeof(pol));
  pol.verify = 1;
  pol.ca_file = path_of("ca.crt");
  pol.client_cert_file = path_of("client.crt");
  pol.client_key_file = path_of("client.key");
  ctx = client_ctx(&pol, &rc);
  r = handshake(ctx, leaf_ip, leaf_key, "10.1.1.1", 1);
  check("files without a named client certificate are not presented", r.ok == 1 &&
        r.client_cert_seen == 0, r.client_cert_seen, 0);
  SSL_CTX_free(ctx);

  /* ---- what counts as a changed policy --------------------------------- */
  {
    struct betls_installed a, b;

    memset(&a, 0, sizeof(a));
    a.verify = 1;
    snprintf(a.ca_id, sizeof(a.ca_id), "ca-1");
    betls_fp_stat(path_of("ca.crt"), &a.fp[BETLS_FP_CA]);
    check("a CA file that exists has an identity", a.fp[BETLS_FP_CA].size > 0,
          (long)a.fp[BETLS_FP_CA].size, 1);

    b = a;
    betls_fp_stat(path_of("ca.crt"), &b.fp[BETLS_FP_CA]);
    check("the same policy over the same files is unchanged",
          betls_installed_same(&a, &b) == 1, betls_installed_same(&a, &b), 1);

    b = a; b.verify = 0;
    check("verification switched off is a change", betls_installed_same(&a, &b) == 0,
          betls_installed_same(&a, &b), 0);
    b = a; snprintf(b.ca_id, sizeof(b.ca_id), "ca-2");
    check("another CA ID is a change", betls_installed_same(&a, &b) == 0,
          betls_installed_same(&a, &b), 0);
    b = a; snprintf(b.client_id, sizeof(b.client_id), "client-1");
    check("a client ID added is a change", betls_installed_same(&a, &b) == 0,
          betls_installed_same(&a, &b), 0);
    b = a; snprintf(b.server_name, sizeof(b.server_name), "backend.test");
    check("a server name added is a change", betls_installed_same(&a, &b) == 0,
          betls_installed_same(&a, &b), 0);

    /* The CA is replaced under the same ID, the way a rotation writes it:
     * a new file renamed over the old one. */
    write_cert("ca.crt.new", other_ca);
    rename(path_of("ca.crt.new"), path_of("ca.crt"));
    b = a;
    betls_fp_stat(path_of("ca.crt"), &b.fp[BETLS_FP_CA]);
    check("a CA replaced under the same ID is a change", betls_installed_same(&a, &b) == 0,
          betls_installed_same(&a, &b), 0);

    betls_fp_stat(path_of("no-such-file"), &b.fp[BETLS_FP_CA]);
    check("a file that is gone has no identity", b.fp[BETLS_FP_CA].ino == 0 &&
          b.fp[BETLS_FP_CA].size == 0, (long)b.fp[BETLS_FP_CA].size, 0);
  }

  printf("\n%d checks, %d failures\n", checks, failures);
  return failures ? 1 : 0;
}
