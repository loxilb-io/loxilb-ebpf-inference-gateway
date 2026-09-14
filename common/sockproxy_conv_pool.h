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

/* Longest conversation id the data path can hand to conv_pool_make_key.
 * sockproxy_ep.c composes "custom_<session_header_name>_<value>" into
 * char[CONV_POOL_ID_MAX] (ns_session_key, session_key, imm_key) and the
 * header value itself arrives in proxy_fd_ent's custom_session_header_value,
 * so 255 chars + NUL bounds every id that can reach the table. */
#define CONV_POOL_ID_MAX 256

/* 16 hex digits of pool tag + ':' + the conversation id + NUL.
 *
 * Defined UNCONDITIONALLY, and NOT in terms of MAX_CONV_ID_LEN. This value
 * sizes conversation_mapping_t's hkey[] member, so a definition that changed
 * with whether MAX_CONV_ID_LEN had been seen yet would give the struct a
 * different layout in a translation unit that includes this header first than
 * in every other one - silently, with no compiler diagnostic, and the symptom
 * would be heap corruption in the conversation table rather than a build
 * failure. sockproxy.h carries the _Static_assert that this covers a full
 * MAX_CONV_ID_LEN id.
 *
 * It is sized for the callers' buffers rather than for the struct's shorter
 * conv_id[] field, so no id is truncated on the way into the key: truncation
 * here is not a lost suffix but a MERGE - two conversations whose keys agree
 * in a long prefix collapse onto one row and share a single endpoint binding.
 * That is reachable, not theoretical: session_header_name is documented
 * in-tree with "authorization", and the key is then
 * "custom_authorization_Bearer <jwt>", where two tokens share a long prefix. */
#define CONV_POOL_KEY_MAX (16 + 1 + CONV_POOL_ID_MAX)

/* A session id that does not fit is stored as this marker, sixteen hex digits
 * of FNV-1a over the WHOLE value, '.', and the value's decimal length. Length
 * is part of the form so two values must collide in the hash AND be the same
 * size to share a row. 1 + 16 + 1 + 20 + NUL. */
#define CONV_POOL_DIGEST_MARK '~'
#define CONV_POOL_DIGEST_MAX  39

/* Store a session id into a bounded buffer without ever merging two of them.
 *
 * The obvious two ways to handle a value that does not fit are both wrong for
 * a routing key. Truncating merges every value sharing a prefix onto one
 * binding. Dropping the value - which the plain-header extraction path did -
 * silently disables stickiness altogether, and does it precisely for the
 * configuration the tree documents, session_header_name "authorization",
 * where the value is a bearer token far longer than any sane buffer.
 *
 * So an over-long value is reduced to a digest of the whole thing instead: the
 * id stays bounded, distinct conversations keep distinct rows, and the same
 * conversation keeps mapping to the same row on every turn, which is all a
 * stickiness key has to do.
 *
 * A value that fits is stored verbatim unless it could be read back as a
 * digest, which is digested instead so the two forms can never be confused.
 *
 * `val` need not be NUL-terminated; exactly `vallen` bytes are read. Returns 0
 * on success, -1 if the arguments cannot be honoured.
 *
 * This is an affinity key, not a credential: the cost of a collision is a lost
 * KV-cache hit on a healthy endpoint of the correct model, which is why a
 * non-cryptographic hash is the right tool here.
 */
static inline int
conv_pool_store_id(char *out, size_t outlen, const char *val, size_t vallen)
{
  static const char hex[] = "0123456789abcdef";
  uint64_t h = 0xcbf29ce484222325ULL;   /* FNV-1a 64 offset basis */
  size_t i, n, digits;
  char dec[20];

  if (!out || !val || outlen < CONV_POOL_DIGEST_MAX + 1)
    return -1;

  /* Fits, and cannot be mistaken for the digest form. */
  if (vallen < outlen && val[0] != CONV_POOL_DIGEST_MARK) {
    for (i = 0; i < vallen; i++)
      out[i] = val[i];
    out[vallen] = '\0';
    return 0;
  }

  for (i = 0; i < vallen; i++) {
    h ^= (uint64_t)(unsigned char)val[i];
    h *= 0x100000001b3ULL;              /* FNV-1a 64 prime */
  }

  n = 0;
  out[n++] = CONV_POOL_DIGEST_MARK;
  for (i = 0; i < 16; i++)
    out[n++] = hex[(h >> (60 - 4 * i)) & 0xf];
  out[n++] = '.';

  digits = 0;
  do {
    dec[digits++] = (char)('0' + (vallen % 10));
    vallen /= 10;
  } while (vallen && digits < sizeof(dec));
  while (digits)
    out[n++] = dec[--digits];

  out[n] = '\0';
  return 0;
}

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
 * May a sync event that names no pool be applied to a service holding
 * `n_pools` pools?
 *
 * proxy_sync_event_t carries a service_key ("xip:xport:proto") and nothing
 * finer, so the receiver can only resolve the pool by guessing. With exactly
 * one pool the guess is the answer. With more, the guess is a coin toss whose
 * losing side is not a miss but the cross-pool aliasing this file exists to
 * prevent - and worse than the original, because the row is written carrying
 * the guessed pool's tag, so that pool MATCHES it and is handed an index
 * chosen inside a different eps[]. In range and healthy, so nothing
 * downstream can catch it. A DELETE under a wrong guess removes a live
 * binding belonging to a pool the event never named.
 *
 * Fail closed: re-learning stickiness locally costs one re-selection, while a
 * wrong guess silently corrupts a binding until it ages out.
 *
 * When the pool rides on the wire this predicate goes away - replaced by the
 * real identity, not relaxed.
 */
static inline int
conv_pool_sync_may_apply(unsigned int n_pools)
{
  return n_pools == 1;
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
