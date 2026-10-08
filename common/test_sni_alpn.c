/* A shared SNI certificate must preserve each connection's listener policy. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "uthash.h"
#include "sockproxy_internal.h"
#include "sockproxy_ssl.h"

proxy_struct_t *proxy_struct;

static void expect_protocol(SSL *ssl, const char *expected)
{
  static const unsigned char offered[] = "\x02h2\x08http/1.1";
  const unsigned char *out = NULL;
  unsigned char len = 0;
  assert(alpn_select_callback(ssl, &out, &len, offered,
                             sizeof(offered) - 1, NULL) == SSL_TLSEXT_ERR_OK);
  assert(len == strlen(expected));
  assert(memcmp(out, expected, len) == 0);
}

int main(void)
{
  proxy_struct_t state = {0};
  ssl_cert_entry_t cert = {0};
  uint8_t h1 = 0, h2 = 1;
  proxy_struct = &state;
  assert(pthread_rwlock_init(&state.global_cert_lock, NULL) == 0);
  SSL_CTX *listener = SSL_CTX_new(TLS_server_method());
  SSL_CTX *shared = SSL_CTX_new(TLS_server_method());
  assert(listener && shared);
  strcpy(cert.hostname, "uc3.gateway.test");
  cert.ssl_ctx = shared;
  HASH_ADD_STR(state.global_cert_map, hostname, &cert);
  SSL *first = SSL_new(listener), *second = SSL_new(listener);
  assert(first && second);
  assert(SSL_set_tlsext_host_name(first, cert.hostname) == 1);
  assert(SSL_set_tlsext_host_name(second, cert.hostname) == 1);
  assert(sni_servername_callback(first, NULL, &h1) == SSL_TLSEXT_ERR_OK);
  assert(SSL_get_SSL_CTX(first) == shared);
  expect_protocol(first, "http/1.1");
  assert(sni_servername_callback(second, NULL, &h2) == SSL_TLSEXT_ERR_OK);
  assert(SSL_get_SSL_CTX(second) == shared);
  expect_protocol(second, "h2");
  /* The second connection must not overwrite the first one's policy. */
  expect_protocol(first, "http/1.1");
  static const unsigned char only_h1[] = "\x08http/1.1";
  const unsigned char *out;
  unsigned char len;
  assert(alpn_select_callback(second, &out, &len, only_h1,
          sizeof(only_h1) - 1, NULL) == SSL_TLSEXT_ERR_ALERT_FATAL);
  HASH_DEL(state.global_cert_map, &cert);
  SSL_free(first); SSL_free(second);
  SSL_CTX_free(listener); SSL_CTX_free(shared);
  pthread_rwlock_destroy(&state.global_cert_lock);
  puts("SNI ALPN connection isolation: PASS");
  return 0;
}
