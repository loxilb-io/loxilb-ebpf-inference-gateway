/* SPDX-License-Identifier: BSD-3-Clause */
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "uthash.h"
#include "log.h"
#include "sockproxy_lb.h"

/* Standalone test: retain production JSON extraction while stubbing logging. */
void log_log(int level, const char *file, int line, const char *fmt, ...)
{
  (void)level; (void)file; (void)line; (void)fmt;
}

#include "sockproxy_json.c"

static int vnode_count(const chwbl_ring_t *ring, int ep)
{
  int count = 0;
  for (int i = 0; i < ring->n_vnodes; i++)
    if (ring->vnodes[i].ep_idx == ep)
      count++;
  return count;
}

int main(void)
{
  llm_prefix_key_t parsed;
  const char nested_salt[] =
      "{\"prompt\":\"hello\",\"metadata\":{\"cache_salt\":\"nested\"}}";
  assert(extract_llm_prefix(nested_salt, strlen(nested_salt), &parsed) == 0);
  assert((parsed.flags & PREFIX_HAS_CACHE_SALT) == 0);
  const char duplicate_salt[] =
      "{\"prompt\":\"hello\",\"cache_salt\":\"one\",\"cache_salt\":\"two\"}";
  assert(extract_llm_prefix(duplicate_salt, strlen(duplicate_salt), &parsed) == 0);
  assert(parsed.cache_salt_invalid == 1);
  const char malformed_salt[] = "{\"prompt\":\"hello\",\"cache_salt\":7}";
  assert(extract_llm_prefix(malformed_salt, strlen(malformed_salt), &parsed) == 0);
  assert(parsed.cache_salt_invalid == 1);

  proxy_epval_t epv = {0};
  epv.n_eps = 3;
  for (int i = 0; i < epv.n_eps; i++) {
    epv.eps[i].xip = (uint32_t)(i + 1);
    epv.eps[i].xport = (uint16_t)(8000 + i);
  }

  chwbl_ring_t *ring = chwbl_create_ring(&epv, 7);
  assert(ring && ring->n_vnodes == 21 && ring->replication == 7);
  chwbl_destroy_ring(ring);
  assert(chwbl_create_ring(&epv, INT32_MAX) == NULL);

  epv.eps[0].weight = 1;
  epv.eps[1].weight = 3;
  epv.eps[2].weight = 0;
  ring = chwbl_create_weighted_ring(&epv, 8);
  assert(ring && ring->n_vnodes == 8);
  assert(vnode_count(ring, 0) == 3);
  assert(vnode_count(ring, 1) == 5);
  assert(vnode_count(ring, 2) == 0);
  chwbl_destroy_ring(ring);
  assert(chwbl_create_weighted_ring(&epv, 1) == NULL);

  proxy_arg_t arg = {0};
  proxy_epval_t candidate = epv;
  candidate.select = PROXY_SEL_CHWBL;
  arg.chwbl_prefix_hash_level = 2;
  arg.chwbl_prefix_hash_flags = PREFIX_HAS_CACHE_SALT;
  arg.chwbl_mean_load_factor = 225;
  arg.chwbl_replication = 11;
  arg.chwbl_enable_cache_salt = 1;
  assert(chwbl_prepare_runtime(&candidate, &arg, NULL) == 0);
  assert(candidate.hash_ring->n_vnodes == candidate.n_eps * 11);
  assert(candidate.chwbl_config->prefix_hash_level == 2);
  assert(candidate.chwbl_config->prefix_hash_flags == PREFIX_HAS_CACHE_SALT);
  assert(candidate.chwbl_config->mean_load_factor == 225);
  assert(candidate.chwbl_config->replication == 11);
  assert(candidate.chwbl_config->enable_cache_salt == 1);
  chwbl_release_runtime(&candidate);

  chwbl_config_t policy = {0};
  llm_prefix_key_t key = {0};
  policy.prefix_hash_level = 1;
  policy.prefix_hash_flags = 0;
  key.valid = 1;
  key.level = 3;
  key.flags = PREFIX_HAS_LORA | PREFIX_HAS_SESSION_CTX | PREFIX_HAS_RAG_DOC_IDS;
  assert(chwbl_apply_hash_policy(&policy, &key) == 0);
  assert(key.level == 1 && key.flags == PREFIX_HAS_LORA);

  policy.prefix_hash_level = 3;
  policy.prefix_hash_flags = PREFIX_HAS_SESSION_CTX;
  key.flags = PREFIX_HAS_LORA | PREFIX_HAS_SESSION_CTX;
  assert(chwbl_apply_hash_policy(&policy, &key) == 0);
  assert(key.flags == PREFIX_HAS_SESSION_CTX);

  policy.enable_cache_salt = 1;
  key.flags = 0;
  assert(chwbl_apply_hash_policy(&policy, &key) == -2);
  key.valid = 0;
  assert(chwbl_apply_hash_policy(&policy, &key) == -2);
  policy.enable_cache_salt = 0;
  key.cache_salt_invalid = 1;
  assert(chwbl_apply_hash_policy(&policy, &key) == -2);
  policy.enable_cache_salt = 1;
  key.valid = 1;
  key.flags = PREFIX_HAS_CACHE_SALT;
  assert(chwbl_apply_hash_policy(&policy, &key) == -2);

  puts("PASS: CHWBL/WRR_HASH ring contract");
  return 0;
}
