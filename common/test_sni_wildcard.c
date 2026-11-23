/* SNI selection: a wildcard certificate serves one left-most label, an exact
 * name comes first, and names compare without regard to case.
 *
 * Certificates are made here and registered through the store's own entry
 * point (proxy_add_sni_certificate), so the key the store keeps is the one
 * registration writes; the handshake side is the SNI callback itself. */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include "uthash.h"
#include "sockproxy_internal.h"
#include "sockproxy_ssl.h"

proxy_struct_t *proxy_struct;

/* The store's key function (sockproxy_ssl.c). Declared here, not in a shared
 * header: every header under common/ is an input of the BPF/native ABI
 * fingerprint, and a test-only symbol is no reason to change it. */
int sni_store_key(const char *name, char *out, size_t out_sz);

static SSL_CTX *listener;

/* A self-signed certificate whose CN names it, written as server.crt and
 * server.key into a fresh directory. */
static void make_cert(char *dir, const char *cn)
{
  char path[512];
  FILE *fp;
  EVP_PKEY *key = EVP_EC_gen("P-256");
  X509 *crt = X509_new();

  assert(mkdtemp(dir));
  assert(key && crt);
  assert(ASN1_INTEGER_set(X509_get_serialNumber(crt), 1) == 1);
  assert(X509_gmtime_adj(X509_getm_notBefore(crt), 0));
  assert(X509_gmtime_adj(X509_getm_notAfter(crt), 3600));
  assert(X509_set_pubkey(crt, key) == 1);
  X509_NAME *name = X509_get_subject_name(crt);
  assert(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                    (const unsigned char *)cn, -1, -1, 0) == 1);
  assert(X509_set_issuer_name(crt, name) == 1);
  assert(X509_sign(crt, key, EVP_sha256()) > 0);

  snprintf(path, sizeof(path), "%s/server.crt", dir);
  assert((fp = fopen(path, "w")));
  assert(PEM_write_X509(fp, crt) == 1);
  fclose(fp);
  snprintf(path, sizeof(path), "%s/server.key", dir);
  assert((fp = fopen(path, "w")));
  assert(PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL) == 1);
  fclose(fp);
  X509_free(crt);
  EVP_PKEY_free(key);
}

static void drop_cert(const char *dir)
{
  char path[512];

  snprintf(path, sizeof(path), "%s/server.crt", dir);
  unlink(path);
  snprintf(path, sizeof(path), "%s/server.key", dir);
  unlink(path);
  rmdir(dir);
}

/* The CN of the certificate a handshake naming sni would be served, or
 * "listener" when the callback leaves the listener's own. */
static const char *served(const char *sni)
{
  static char cn[64];
  uint8_t h1 = 0;
  SSL *ssl = SSL_new(listener);
  int rc;

  assert(ssl);
  assert(SSL_set_tlsext_host_name(ssl, sni) == 1);
  rc = sni_servername_callback(ssl, NULL, &h1);
  if (rc == SSL_TLSEXT_ERR_NOACK) {
    assert(SSL_get_SSL_CTX(ssl) == listener);
    strcpy(cn, "listener");
  } else {
    assert(rc == SSL_TLSEXT_ERR_OK);
    X509 *crt = SSL_CTX_get0_certificate(SSL_get_SSL_CTX(ssl));
    assert(crt);
    assert(X509_NAME_get_text_by_NID(X509_get_subject_name(crt), NID_commonName,
                                     cn, sizeof(cn)) > 0);
  }
  SSL_free(ssl);
  return cn;
}

static int listed_n;
static char listed[8][256];

static void collect(const char *hostname, void *data)
{
  (void)data;
  assert(listed_n < 8);
  strcpy(listed[listed_n++], hostname);
}

static int is_listed(const char *key)
{
  for (int i = 0; i < listed_n; i++)
    if (!strcmp(listed[i], key))
      return 1;
  return 0;
}

int main(void)
{
  proxy_struct_t state = {0};
  char wild[] = "/tmp/sni-wild-XXXXXX";
  char exact[] = "/tmp/sni-exact-XXXXXX";
  char tld[] = "/tmp/sni-tld-XXXXXX";
  char key[256];
  char long_name[300];

  proxy_struct = &state;
  assert(pthread_rwlock_init(&state.global_cert_lock, NULL) == 0);
  assert((listener = SSL_CTX_new(TLS_server_method())));
  make_cert(wild, "wild");
  make_cert(exact, "exact");
  make_cert(tld, "tld");

  /* Registration keeps the lower-case name, the wildcard included. */
  assert(proxy_add_sni_certificate("*.Cluster.Example.COM", wild) == 0);
  assert(proxy_add_sni_certificate("B.cluster.example.com", exact) == 0);
  assert(proxy_add_sni_certificate("*.com", tld) == 0);
  assert(proxy_list_sni_certificates(collect, NULL) == 3);
  assert(is_listed("*.cluster.example.com"));
  assert(is_listed("b.cluster.example.com"));
  assert(is_listed("*.com"));
  /* The same name in another case is the same entry. */
  assert(proxy_add_sni_certificate("b.CLUSTER.example.com", exact) == -EEXIST);

  /* The wildcard serves exactly one left-most label. */
  assert(!strcmp(served("a.cluster.example.com"), "wild"));
  assert(!strcmp(served("cluster.example.com"), "listener"));
  assert(!strcmp(served("a.b.cluster.example.com"), "listener"));
  assert(!strcmp(served(".cluster.example.com"), "listener"));
  /* An exact name comes before the wildcard that would also serve it. */
  assert(!strcmp(served("b.cluster.example.com"), "exact"));
  /* Case does not matter, on either side. */
  assert(!strcmp(served("A.CLUSTER.Example.Com"), "wild"));
  assert(!strcmp(served("B.Cluster.Example.COM"), "exact"));
  /* No wildcard over a single remaining label: "*.com" serves no one. */
  assert(!strcmp(served("example.com"), "listener"));
  /* A name with a "*" in it is no host name. */
  assert(!strcmp(served("*.cluster.example.com"), "listener"));
  assert(!strcmp(served("a*.cluster.example.com"), "listener"));
  /* The lookup API selects as the handshake does. */
  assert(proxy_get_ssl_ctx_for_hostname("Z.cluster.example.com") != NULL);
  assert(proxy_get_ssl_ctx_for_hostname("cluster.example.com") == NULL);

  /* Removal finds the entry in any case; the wildcard then serves the name. */
  assert(proxy_remove_sni_certificate("B.Cluster.EXAMPLE.com") == 0);
  assert(!strcmp(served("b.cluster.example.com"), "wild"));
  assert(proxy_remove_sni_certificate("b.cluster.example.com") == -ENOENT);

  /* A name that does not fit a key is refused, not cut short. A client's
   * name always fits: SNI carries at most 255 bytes. */
  memset(long_name, 'a', sizeof(long_name) - 1);
  long_name[sizeof(long_name) - 1] = '\0';
  assert(sni_store_key(long_name, key, sizeof(key)) == -1);
  assert(proxy_add_sni_certificate(long_name, wild) == -EINVAL);
  long_name[255] = '\0';
  assert(sni_store_key(long_name, key, sizeof(key)) == 0);
  assert(sni_store_key("Ab-9.Z", key, sizeof(key)) == 0 && !strcmp(key, "ab-9.z"));
  assert(sni_store_key("", key, 0) == -1);

  assert(proxy_remove_sni_certificate("*.cluster.example.com") == 0);
  assert(proxy_remove_sni_certificate("*.COM") == 0);
  assert(!strcmp(served("a.cluster.example.com"), "listener"));
  assert(state.global_cert_map == NULL);

  drop_cert(wild);
  drop_cert(exact);
  drop_cert(tld);
  SSL_CTX_free(listener);
  pthread_rwlock_destroy(&state.global_cert_lock);
  puts("SNI wildcard and case-insensitive selection: PASS");
  return 0;
}
