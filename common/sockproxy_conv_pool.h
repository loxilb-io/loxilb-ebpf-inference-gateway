/*
 * sockproxy_conv_pool.h - pool identity for conversation stickiness.
 *
 * conv_map lives on proxy_map_ent_t, one table per VIP:port, and is keyed by
 * conv_id ALONE. A service with model-keyed rules holds several pools in
 * ent->val.ephash, so two pools on one VIP share that keyspace and collide on
 * a single row - while the ep_idx in that row is only meaningful inside the
 * ONE proxy_epval_t that stored it, every pool's eps[] starting at 0.
 *
 * The selected endpoint is always taken from the request's own resolved pool,
 * so the MODEL is never wrong. What breaks is the stickiness itself:
 *
 *   - the store guard ("no mapping yet?") sees the other pool's row, so the
 *     second pool never records a binding of its own and re-selects forever;
 *   - a store that does land overwrites the other pool's binding, so that
 *     conversation's next turn is sent to whichever member the OTHER pool
 *     happened to pick - a different endpoint of the right model, losing the
 *     KV-cache affinity the binding existed to preserve.
 *
 * is_endpoint_healthy() cannot catch either: an in-range index naming a live
 * endpoint passes. This is the identity rule the HTTP/2 backend-connection
 * slots already follow in sockproxy_h2.c - "(pool, endpoint-in-pool), NEVER
 * the endpoint index alone" - applied to the conversation table.
 *
 * The tag is derived from the pool's ephash_key because that key IS the
 * pool's key in ent->val.ephash: unique within the service by construction,
 * and stable across the in-place rule refresh in proxy_add_entry. A pointer
 * would not survive a pool free/re-create, and the rule id would not
 * distinguish two pools that belong to one rule.
 *
 * Header-only and free of sockproxy.h on purpose, so the identity rule can be
 * exercised standalone (test_conv_pool_alias.c).
 */
#ifndef __SOCKPROXY_CONV_POOL_H__
#define __SOCKPROXY_CONV_POOL_H__

#include <stdint.h>

/* Reserved: "this mapping does not name a pool". conv_pool_tag_of_key()
 * never produces it - FNV-1a's offset basis is non-zero, and the tag of the
 * empty key is the basis itself. */
#define CONV_POOL_TAG_UNKNOWN 0ULL

/* 16 hex digits of pool tag + ':' + the conversation id + NUL. */
#ifndef MAX_CONV_ID_LEN
#define CONV_POOL_KEY_MAX (16 + 1 + 256 + 1)
#else
#define CONV_POOL_KEY_MAX (16 + 1 + MAX_CONV_ID_LEN)
#endif

static inline uint64_t
conv_pool_tag_of_key(const char *ephash_key)
{
  uint64_t h = 0xcbf29ce484222325ULL;   /* FNV-1a 64 offset basis */

  if (!ephash_key)
    return CONV_POOL_TAG_UNKNOWN;

  while (*ephash_key) {
    h ^= (uint64_t)(unsigned char)*ephash_key++;
    h *= 0x100000001b3ULL;              /* FNV-1a 64 prime */
  }
  return h;
}

/*
 * May an endpoint index stored under tag `stored` be applied to the pool
 * tagged `want`?
 *
 * Fails closed: an unknown tag on either side is a MISS, never a wildcard.
 * A MISS costs one rehash and re-store; a false match lets one pool consume
 * or overwrite another pool's binding.
 */
static inline int
conv_pool_tag_matches(uint64_t stored, uint64_t want)
{
  if (stored == CONV_POOL_TAG_UNKNOWN || want == CONV_POOL_TAG_UNKNOWN)
    return 0;
  return stored == want;
}

/*
 * Build the conv_map hash key for (pool, conv_id).
 *
 * The table is per VIP:port and every pool on that VIP shares it, so conv_id
 * alone is not a key: two pools using one conversation id land on a single
 * row and evict each other's binding every turn. Prefixing the pool tag gives
 * each pool its own row, so both keep a stable, independent binding.
 *
 * The tag is fixed-width hex, so the ':' separator can never be ambiguous and
 * two distinct (pool, conv_id) pairs can never produce one key.
 */
static inline void
conv_pool_make_key(char *out, size_t outlen, uint64_t tag, const char *conv_id)
{
  static const char hex[] = "0123456789abcdef";
  size_t i = 0;
  int shift;

  if (!out || outlen == 0)
    return;

  for (shift = 60; shift >= 0 && i + 1 < outlen; shift -= 4)
    out[i++] = hex[(tag >> shift) & 0xf];
  if (i + 1 < outlen)
    out[i++] = ':';
  if (conv_id)
    while (*conv_id && i + 1 < outlen)
      out[i++] = *conv_id++;
  out[i] = '\0';
}

#endif /* __SOCKPROXY_CONV_POOL_H__ */
