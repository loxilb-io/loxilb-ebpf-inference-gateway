/* SPDX-License-Identifier: BSD-3-Clause */
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "uthash.h"
#include "log.h"
#include "sockproxy_lb.h"
#include "sockproxy_h2_load.h"

/* Standalone test: retain production JSON extraction while stubbing logging.
 * Error-level lines are counted: the selector runtime reports a load-counter
 * underflow at that level, and the stream-unit cases below assert on it. */
static int log_errors;
void log_log(int level, const char *file, int line, const char *fmt, ...)
{
  (void)file; (void)line; (void)fmt;
  if (level >= LOG_ERROR)
    log_errors++;
}

static uint32_t ep_load(const proxy_epval_t *epv, int ep)
{
  return atomic_load(&epv->chwbl_config->ep_loads[ep].active_conns);
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

  /* HTTP/2 stream units. One unit per stream mapping on a bounded-load pool,
   * released exactly once, and never a connection unit for an HTTP/2 leg. */
  proxy_epval_t h2pool = epv;
  h2pool.select = PROXY_SEL_CHWBL;
  assert(chwbl_prepare_runtime(&h2pool, &arg, NULL) == 0);
  assert(h2_load_units_active(&h2pool));
  log_errors = 0;

  enum { N_STREAMS = 50 };
  int held[N_STREAMS];
  for (int i = 0; i < N_STREAMS; i++) {
    held[i] = h2_load_unit_take(&h2pool, 1);
    assert(held[i] == 1);
  }
  assert(ep_load(&h2pool, 1) == N_STREAMS);
  assert(ep_load(&h2pool, 0) == 0 && ep_load(&h2pool, 2) == 0);

  /* The selector counts its pick as a connection unit; the HTTP/2 path hands
   * that one straight back and takes the mapping's unit instead, so a stream
   * costs exactly one. */
  chwbl_inc_runtime(&h2pool, 1);              /* what the selector did */
  chwbl_dec_runtime(&h2pool, 1);              /* what the H2 path does at once */
  int extra = h2_load_unit_take(&h2pool, 1);  /* the mapping's unit */
  assert(extra == 1 && ep_load(&h2pool, 1) == N_STREAMS + 1);
  h2_load_unit_release(&h2pool, 1, &extra);
  assert(extra == 0 && ep_load(&h2pool, 1) == N_STREAMS);

  /* N closes bring the endpoint back to zero ... */
  for (int i = 0; i < N_STREAMS; i++) {
    h2_load_unit_release(&h2pool, 1, &held[i]);
    assert(held[i] == 0);
  }
  assert(ep_load(&h2pool, 1) == 0);
  assert(log_errors == 0);

  /* ... and a second release of every mapping (stream close followed by
   * session teardown) is a no-op: the counter stays at zero and nothing is
   * reported as an underflow. */
  for (int i = 0; i < N_STREAMS; i++)
    h2_load_unit_release(&h2pool, 1, &held[i]);
  assert(ep_load(&h2pool, 1) == 0);
  assert(log_errors == 0);

  /* The underflow report is live -- a raw release on an empty counter is
   * what the guard above prevents. */
  chwbl_dec_runtime(&h2pool, 1);
  assert(ep_load(&h2pool, 1) == 0);
  assert(log_errors == 1);
  log_errors = 0;

  /* A pool that keeps no units hands out none, so nothing is ever owed. */
  proxy_epval_t rrpool = epv;
  rrpool.select = PROXY_SEL_RR;
  assert(!h2_load_units_active(&rrpool));
  int none = h2_load_unit_take(&rrpool, 0);
  assert(none == 0);
  h2_load_unit_release(&rrpool, 0, &none);
  assert(log_errors == 0);
  assert(h2_load_unit_take(&h2pool, -1) == 0);
  assert(h2_load_unit_take(&h2pool, MAX_PROXY_EP) == 0);

  /* Connection ownership: an HTTP/1.1 leg that routed owns one unit; an
   * HTTP/2 leg, whose units sit on its stream mappings, owns none even
   * though it carries the same (epv, ep_num) for byte accounting. */
  static proxy_fd_ent_t leg;
  memset(&leg, 0, sizeof(leg));
  leg.epv = &h2pool;
  leg.ep_num = 1;
  assert(conn_holds_load_unit(&leg) == 1);
  leg.load_units_per_stream = 1;
  assert(conn_holds_load_unit(&leg) == 0);
  leg.load_units_per_stream = 0;
  leg.ep_num = -1;
  assert(conn_holds_load_unit(&leg) == 0);
  leg.ep_num = 1;
  leg.epv = NULL;
  assert(conn_holds_load_unit(&leg) == 0);
  assert(conn_holds_load_unit(NULL) == 0);

  chwbl_release_runtime(&h2pool);

  puts("PASS: CHWBL/WRR_HASH ring contract");
  puts("PASS: HTTP/2 stream-unit contract");
  return 0;
}
