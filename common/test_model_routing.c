/* test_model_routing.c - model-aware hostname/path lookup regressions. */

#include <assert.h>
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

int
main(void)
{
  test_hostname_only_model_pool();
  test_model_pool_precedes_wildcard_path();
  test_unknown_model_uses_wildcard_path();
  puts("test_model_routing: ALL PASS");
  return 0;
}
