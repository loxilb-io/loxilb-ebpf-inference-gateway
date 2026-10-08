/* test_model_routing.c - model-aware hostname/path lookup regressions. */

#include <assert.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include "uthash.h"
#include "sockproxy_internal.h"
#include "sockproxy_routing.h"

static void
add_pool(proxy_map_ent_t *service, proxy_epval_t *pool, const char *key,
         uint32_t id)
{
  memset(pool, 0, sizeof(*pool));
  pool->_id = id;
  strncpy(pool->ephash_key, key, sizeof(pool->ephash_key) - 1);
  HASH_ADD_STR(service->val.ephash, ephash_key, pool);
}

static void
test_hostname_only_model_pool(void)
{
  proxy_map_ent_t service = {0};
  proxy_epval_t model_pool;

  add_pool(&service, &model_pool,
           "inference.example||Qwen/Qwen2.5-7B-Instruct", 101);

  proxy_epval_t *got = find_endpoint_lpm(
      &service, "inference.example", "/v1/completions",
      "Qwen/Qwen2.5-7B-Instruct");
  assert(got == &model_pool);

  HASH_DEL(service.val.ephash, &model_pool);
}

static void
test_model_pool_precedes_wildcard_path(void)
{
  proxy_map_ent_t service = {0};
  proxy_epval_t model_pool;
  proxy_epval_t wildcard_path;

  add_pool(&service, &model_pool, "inference.example||model-a", 201);
  add_pool(&service, &wildcard_path, "inference.example|/v1", 202);

  proxy_epval_t *got = find_endpoint_lpm(
      &service, "inference.example", "/v1/completions", "model-a");
  assert(got == &model_pool);

  HASH_DEL(service.val.ephash, &model_pool);
  HASH_DEL(service.val.ephash, &wildcard_path);
}

static void
test_unknown_model_uses_wildcard_path(void)
{
  proxy_map_ent_t service = {0};
  proxy_epval_t wildcard_path;

  add_pool(&service, &wildcard_path, "inference.example|/v1", 301);

  proxy_epval_t *got = find_endpoint_lpm(
      &service, "inference.example", "/v1/completions", "unknown-model");
  assert(got == &wildcard_path);

  HASH_DEL(service.val.ephash, &wildcard_path);
}

/* An exact pool may win the full path, never an ancestor candidate. */
static void
test_exact_path_does_not_match_children(void)
{
  proxy_map_ent_t service = {0};
  proxy_epval_t exact, root;
  add_pool(&service, &exact, "inference.example|/v1/exact|model-a", 401);
  exact.path_match_mode = 2;
  add_pool(&service, &root, "inference.example|/|model-a", 402);
  root.path_match_mode = 1;
  assert(find_endpoint_lpm(&service, "inference.example", "/v1/exact", "model-a") == &exact);
  assert(find_endpoint_lpm(&service, "inference.example", "/v1/exact?probe=1", "model-a") == &exact);
  assert(find_endpoint_lpm(&service, "inference.example", "/v1/exact/child", "model-a") == &root);
  HASH_DEL(service.val.ephash, &root);
  assert(find_endpoint_lpm(&service, "inference.example", "/v1/exact/child", "model-a") == NULL);
  HASH_DEL(service.val.ephash, &exact);
}

static void
test_wildcard_exact_and_root_are_exact(void)
{
  proxy_map_ent_t service = {0};
  proxy_epval_t exact, prefix, root;
  add_pool(&service, &exact, "inference.example|/v1/exact", 501);
  exact.path_match_mode = 2;
  add_pool(&service, &prefix, "inference.example|/v1", 502);
  prefix.path_match_mode = 1;
  add_pool(&service, &root, "inference.example|/", 503);
  root.path_match_mode = 2;
  assert(find_endpoint_lpm(&service, "inference.example", "/v1/exact", "unknown") == &exact);
  assert(find_endpoint_lpm(&service, "inference.example", "/v1/exact?probe=1", "unknown") == &exact);
  assert(find_endpoint_lpm(&service, "inference.example", "/v1/exact/child", "unknown") == &prefix);
  assert(find_endpoint_lpm(&service, "inference.example", "/", "unknown") == &root);
  assert(find_endpoint_lpm(&service, "inference.example", "/?probe=1", "unknown") == &root);
  assert(find_endpoint_lpm(&service, "inference.example", "/other", "unknown") == NULL);
  assert(find_endpoint_lpm(&service, "inference.example", "/other", "") == NULL);
  HASH_DEL(service.val.ephash, &exact);
  HASH_DEL(service.val.ephash, &prefix);
  HASH_DEL(service.val.ephash, &root);
}

static void
set_listener(proxy_map_ent_t *service)
{
  assert(inet_pton(AF_INET, "127.0.0.1", &service->key.xip) == 1);
  service->key.xport = htons(2086);
}

static void
test_listener_model_root_and_longest_path(void)
{
  proxy_map_ent_t service = {0};
  proxy_epval_t root, prefix, longer;
  set_listener(&service);
  add_pool(&service, &root, "127.0.0.1:2086|/|model-a", 601);
  add_pool(&service, &prefix, "127.0.0.1:2086|/v1|model-a", 602);
  add_pool(&service, &longer, "127.0.0.1:2086|/v1/chat|model-a", 603);
  assert(find_endpoint_lpm(&service, "floating.example", "/v1/chat/completions", "model-a") == &longer);
  assert(find_endpoint_lpm(&service, "floating.example", "/v1/other", "model-a") == &prefix);
  assert(find_endpoint_lpm(&service, "floating.example", "/other", "model-a") == &root);
  assert(find_endpoint_lpm(&service, "floating.example", "/v1/chat", "wrong-model") == NULL);
  HASH_DEL(service.val.ephash, &longer);
  HASH_DEL(service.val.ephash, &prefix);
  HASH_DEL(service.val.ephash, &root);
}

static void
test_listener_exact_query_and_wrong_path(void)
{
  proxy_map_ent_t service = {0};
  proxy_epval_t exact;
  set_listener(&service);
  add_pool(&service, &exact, "127.0.0.1:2086|/v1/exact|model-a", 701);
  exact.path_match_mode = 2;
  assert(find_endpoint_lpm(&service, "client.example", "/v1/exact", "model-a") == &exact);
  assert(find_endpoint_lpm(&service, "client.example", "/v1/exact?probe=1", "model-a") == &exact);
  assert(find_endpoint_lpm(&service, "client.example", "/v1/exact/child", "model-a") == NULL);
  assert(find_endpoint_lpm(&service, "client.example", "/other", "model-a") == NULL);
  assert(find_endpoint_lpm(&service, "client.example", "/v1/exact", "wrong-model") == NULL);
  HASH_DEL(service.val.ephash, &exact);
}

static void
test_listener_wildcard_path_and_host_precedence(void)
{
  proxy_map_ent_t service = {0};
  proxy_epval_t model, wildcard, explicit_host;
  set_listener(&service);
  add_pool(&service, &model, "127.0.0.1:2086|/v1|model-a", 801);
  add_pool(&service, &wildcard, "127.0.0.1:2086|/v1/chat", 802);
  add_pool(&service, &explicit_host, "client.example|/|model-a", 803);
  assert(find_endpoint_lpm(&service, "other.example", "/v1/chat/completions", "model-a") == &model);
  assert(find_endpoint_lpm(&service, "other.example", "/v1/chat/completions", "unknown") == &wildcard);
  assert(find_endpoint_lpm(&service, "other.example", "/outside", "unknown") == NULL);
  assert(find_endpoint_lpm(&service, "client.example", "/v1/chat/completions", "model-a") == &explicit_host);
  HASH_DEL(service.val.ephash, &explicit_host);
  HASH_DEL(service.val.ephash, &wildcard);
  HASH_DEL(service.val.ephash, &model);
}

static void
test_listener_without_path_remains_supported(void)
{
  proxy_map_ent_t service = {0};
  proxy_epval_t model, wildcard;
  set_listener(&service);
  add_pool(&service, &model, "127.0.0.1:2086||model-a", 901);
  add_pool(&service, &wildcard, "127.0.0.1:2086", 902);
  assert(find_endpoint_lpm(&service, "client.example", "/any", "model-a") == &model);
  assert(find_endpoint_lpm(&service, "client.example", "/any", "unknown") == &wildcard);
  HASH_DEL(service.val.ephash, &wildcard);
  HASH_DEL(service.val.ephash, &model);
}

int
main(void)
{
  test_exact_path_does_not_match_children();
  test_wildcard_exact_and_root_are_exact();
  test_hostname_only_model_pool();
  test_model_pool_precedes_wildcard_path();
  test_unknown_model_uses_wildcard_path();
  test_listener_model_root_and_longest_path();
  test_listener_exact_query_and_wrong_path();
  test_listener_wildcard_path_and_host_precedence();
  test_listener_without_path_remains_supported();
  puts("test_model_routing: ALL PASS");
  return 0;
}
