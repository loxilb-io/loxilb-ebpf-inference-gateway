/* Frontend client trust and TLS-context lifetime across SNI selection. */
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>

#include "uthash.h"
#include "sockproxy_internal.h"
#include "sockproxy_mtls.h"
#include "sockproxy_ssl.h"

proxy_struct_t *proxy_struct;
proxy_global_stats_t global_stats;

enum fault { NONE, CONTEXT_REF, CA_NAMES, SNAPSHOT, SWITCH, STORE };
static enum fault fault;
static SSL *observed_ssl;
static X509_STORE *installed_store;

int __real_SSL_CTX_up_ref(SSL_CTX *ctx);
STACK_OF(X509_NAME) *__real_SSL_dup_CA_list(const STACK_OF(X509_NAME) *names);
int __real_SSL_set_ex_data(SSL *ssl, int index, void *data);
SSL_CTX *__real_SSL_set_SSL_CTX(SSL *ssl, SSL_CTX *ctx);
long __real_SSL_ctrl(SSL *ssl, int cmd, long larg, void *parg);

int __wrap_SSL_CTX_up_ref(SSL_CTX *ctx)
{
  return fault == CONTEXT_REF ? 0 : __real_SSL_CTX_up_ref(ctx);
}

STACK_OF(X509_NAME) *__wrap_SSL_dup_CA_list(const STACK_OF(X509_NAME) *names)
{
  return fault == CA_NAMES ? NULL : __real_SSL_dup_CA_list(names);
}

int __wrap_SSL_set_ex_data(SSL *ssl, int index, void *data)
{
  if (fault == SNAPSHOT && index == g_ssl_proxy_arg_index)
    return 0;
  return __real_SSL_set_ex_data(ssl, index, data);
}

SSL_CTX *__wrap_SSL_set_SSL_CTX(SSL *ssl, SSL_CTX *ctx)
{
  return fault == SWITCH ? NULL : __real_SSL_set_SSL_CTX(ssl, ctx);
}

long __wrap_SSL_ctrl(SSL *ssl, int cmd, long larg, void *parg)
{
  if (fault == STORE && cmd == SSL_CTRL_SET_VERIFY_CERT_STORE)
    return 0;
  long result = __real_SSL_ctrl(ssl, cmd, larg, parg);
  if (ssl == observed_ssl && cmd == SSL_CTRL_SET_VERIFY_CERT_STORE && result == 1)
    installed_store = parg;
  return result;
}

static void assert_listener_policy(SSL *ssl, SSL_CTX *listener, SSL_CTX *selected)
{
  assert(SSL_get_SSL_CTX(ssl) == selected);
  assert(installed_store == SSL_CTX_get_cert_store(listener));
  assert(SSL_get_verify_mode(ssl) == SSL_CTX_get_verify_mode(listener));
  assert(SSL_get_verify_depth(ssl) == SSL_CTX_get_verify_depth(listener));
  assert(SSL_get_verify_callback(ssl) == SSL_CTX_get_verify_callback(listener));
  assert(sk_X509_NAME_num(SSL_get_client_CA_list(ssl)) == 1);
  mtls_ssl_conn_state_t *policy = SSL_get_ex_data(ssl, g_ssl_proxy_arg_index);
  assert(policy && policy->require_client_cn);
  assert(strcmp(policy->client_cn_pattern, "*.example.test") == 0);
}

static void test_callback(void)
{
  SSL_CTX *listener = SSL_CTX_new(TLS_server_method());
  SSL_CTX *selected = SSL_CTX_new(TLS_server_method());
  assert(listener && selected);

  proxy_arg_t *args = calloc(1, sizeof(*args));
  assert(args);
  args->frontend_mtls_mode = 2;
  args->require_client_cn = 1;
  strcpy(args->client_cn_pattern, "*.example.test");
  /* Missing CA is refused. Initialization sets the real callback and its
   * ex_data cleanup. The unit supplies its trust-store state directly. */
  assert(mtls_configure_frontend(listener, args) == -EINVAL);
  STACK_OF(X509_NAME) *names = sk_X509_NAME_new_null();
  X509_NAME *name = X509_NAME_new();
  assert(names && name && sk_X509_NAME_push(names, name) > 0);
  SSL_CTX_set_client_CA_list(listener, names);
  assert(X509_STORE_set_flags(SSL_CTX_get_cert_store(listener), X509_V_FLAG_CRL_CHECK) == 1);

  ssl_cert_entry_t entry = {.ssl_ctx = selected};
  strcpy(entry.hostname, "sni-1b.test");
  HASH_ADD_STR(proxy_struct->global_cert_map, hostname, &entry);
  SSL *ssl = SSL_new(listener);
  int alert = 0;
  assert(ssl && SSL_set_tlsext_host_name(ssl, entry.hostname) == 1);
  observed_ssl = ssl;
  assert(sni_servername_callback(ssl, &alert, NULL) == SSL_TLSEXT_ERR_OK);
  assert_listener_policy(ssl, listener, selected);
  void *first_snapshot = SSL_get_ex_data(ssl, g_ssl_proxy_arg_index);
  /* OpenSSL can call the selection callback again for TLS 1.3 HRR. */
  installed_store = NULL;
  assert(sni_servername_callback(ssl, &alert, NULL) == SSL_TLSEXT_ERR_OK);
  assert_listener_policy(ssl, listener, selected);
  assert(SSL_get_ex_data(ssl, g_ssl_proxy_arg_index) == first_snapshot);
  observed_ssl = NULL;
  installed_store = NULL;
  SSL_free(ssl);

  for (enum fault inject = CONTEXT_REF; inject <= STORE; ++inject) {
    ssl = SSL_new(listener);
    assert(ssl && SSL_set_tlsext_host_name(ssl, entry.hostname) == 1);
    alert = 0;
    fault = inject;
    assert(sni_servername_callback(ssl, &alert, NULL) == SSL_TLSEXT_ERR_ALERT_FATAL);
    fault = NONE;
    assert(alert == SSL_AD_INTERNAL_ERROR);
    SSL_free(ssl);
  }

  HASH_DEL(proxy_struct->global_cert_map, &entry);
  SSL_CTX_free(selected);
  SSL_CTX_free(listener);
}

struct stress {
  SSL_CTX *listener;
  SSL_CTX *client;
  _Atomic int starting;
};

static void accept_step(SSL *ssl)
{
  if (SSL_is_init_finished(ssl))
    return;
  int ret = SSL_do_handshake(ssl);
  if (ret != 1) {
    int error = SSL_get_error(ssl, ret);
    if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
      ERR_print_errors_fp(stderr);
      abort();
    }
  }
}

static void *handshakes(void *arg)
{
  struct stress *s = arg;
  atomic_fetch_add(&s->starting, 1);
  for (int i = 0; i < 800; ++i) {
    SSL *client = SSL_new(s->client), *server = SSL_new(s->listener);
    int fd[2];
    assert(client && server);
    assert(SSL_set_tlsext_host_name(client, "sni-1b.test") == 1);
    assert(SSL_set_max_proto_version(client, i & 1 ? TLS1_2_VERSION : TLS1_3_VERSION) == 1);
    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fd) == 0);
    assert(SSL_set_fd(client, fd[0]) == 1);
    assert(SSL_set_fd(server, fd[1]) == 1);
    SSL_set_connect_state(client);
    SSL_set_accept_state(server);
    for (int step = 0; step < 32 && !(SSL_is_init_finished(client) && SSL_is_init_finished(server)); ++step) {
      accept_step(client);
      accept_step(server);
    }
    assert(SSL_is_init_finished(client) && SSL_is_init_finished(server));
    assert(SSL_get_verify_result(server) == X509_V_OK);
    assert(SSL_get0_peer_certificate(server));
    SSL_free(server);
    SSL_free(client);
    close(fd[0]);
    close(fd[1]);
  }
  return NULL;
}

static void test_rotation(const char *fixture)
{
  struct stress s = {.listener = proxy_server_ssl_ctx_init(NULL),
                     .client = SSL_CTX_new(TLS_client_method())};
  proxy_arg_t *args = calloc(1, sizeof(*args));
  assert(args);
  args->frontend_mtls_mode = 2;
  char path[512];
  assert(s.listener && s.client);
  assert(snprintf(args->client_ca_path, sizeof(args->client_ca_path), "%s/client.crt", fixture)
         < (int)sizeof(args->client_ca_path));
  assert(mtls_configure_frontend(s.listener, args) == 0);
  assert(SSL_CTX_set_tlsext_servername_callback(s.listener, sni_servername_callback) == 1);
  snprintf(path, sizeof(path), "%s/default.crt", fixture);
  assert(SSL_CTX_use_certificate_file(s.listener, path, SSL_FILETYPE_PEM) == 1);
  snprintf(path, sizeof(path), "%s/default.key", fixture);
  assert(SSL_CTX_use_PrivateKey_file(s.listener, path, SSL_FILETYPE_PEM) == 1);
  snprintf(path, sizeof(path), "%s/valid.crt", fixture);
  assert(SSL_CTX_use_certificate_file(s.client, path, SSL_FILETYPE_PEM) == 1);
  snprintf(path, sizeof(path), "%s/valid.key", fixture);
  assert(SSL_CTX_use_PrivateKey_file(s.client, path, SSL_FILETYPE_PEM) == 1);
  snprintf(path, sizeof(path), "%s/server.crt", fixture);
  assert(SSL_CTX_load_verify_locations(s.client, path, NULL) == 1);
  SSL_CTX_set_verify(s.client, SSL_VERIFY_PEER, NULL);

  assert(proxy_register_cert("igw-1b-stress") == 1);
  pthread_t threads[4];
  for (size_t i = 0; i < 4; ++i)
    assert(pthread_create(&threads[i], NULL, handshakes, &s) == 0);
  while (atomic_load(&s.starting) != 4)
    sched_yield();
  /* One admin writer, as in the gateway API. TLS readers run concurrently. */
  for (int i = 0; i < 200; ++i) {
    assert(proxy_rotate_cert("igw-1b-stress") == 0);
    assert(proxy_delete_cert("igw-1b-stress") == 0);
    assert(proxy_register_cert("igw-1b-stress") == 1);
  }
  for (size_t i = 0; i < 4; ++i)
    assert(pthread_join(threads[i], NULL) == 0);
  assert(proxy_delete_cert("igw-1b-stress") == 0);
  SSL_CTX_free(s.client);
  SSL_CTX_free(s.listener);
  puts("Concurrent rotate/delete and 3200 TLS handshakes: PASS");
}

int main(int argc, char **argv)
{
  proxy_struct_t state = {0};
  proxy_struct = &state;
  assert(pthread_rwlock_init(&state.global_cert_lock, NULL) == 0);
  test_callback();
  if (argc == 2)
    test_rotation(argv[1]);
  assert(pthread_rwlock_destroy(&state.global_cert_lock) == 0);
  puts("SNI client trust preservation and failure handling: PASS");
  return 0;
}
