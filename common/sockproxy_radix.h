/* SPDX-License-Identifier: (GPL-2.0) */
/*
 * sockproxy_radix.h - prefix trie for non-disaggregated prefix routing.
 *
 * Self-contained: does not include sockproxy.h. One trie per pool
 * generation. The trie is byte-agnostic: a key is any byte sequence,
 * 0x00 included, and every length is explicit. In the product its keys are
 * sequences of 8-byte block digests (never request text); lookups then pass
 * unit = 8 so a mismatch inside a digest is a mismatch of that digest.
 *
 * Each key is learned under a namespace (the isolation key). The caller
 * builds the namespace with radix_ns_append(), whose encoding is prefix-free
 * as long as every namespace of a trie has the same fields in the same
 * order (the caller owns that count and order): two different namespaces
 * then differ at a byte before either ends, so no lookup or learning crosses
 * a namespace. A matched length, and any score built on it, never includes
 * namespace bytes; units are counted from the start of the key, whatever
 * the namespace length.
 *
 * Positions: with unit u, a lookup reports the last whole unit matched,
 * p = floor(raw match / u) * u. cand_mask is the subtree mask of the node
 * that contains position p (the shallowest node on the path whose depth is
 * at least p), not of the deepest node reached. Walking back moves p to the
 * last whole unit at or above the parent of that node, by the same rule.
 *
 * Recency: lookup and insert stamp every node whose edge they enter on the
 * path (fully or partly matched) with now, so a node's timestamp is the last
 * use of any key through it. A node that becomes childless keeps the
 * timestamp it has; eviction then compares it as it compares any leaf.
 *
 * Locking: the module takes no lock; the caller does.
 *   - radix_trie_lookup() and radix_trie_stats() may run concurrently with
 *     each other under a shared lock. Lookup changes no structure; its only
 *     write is a relaxed atomic store of a node's coarse timestamp, made only
 *     when the value changes.
 *   - radix_trie_insert(), radix_trie_purge_ep() and radix_trie_free() need
 *     the exclusive lock.
 *   - No call blocks or does I/O.
 *
 * Storage: a node cap and a stored-byte cap (trie struct, sample array,
 * node headers and label capacity). Insert evicts to the caps after linking,
 * never the key it has just linked. Eviction samples childless nodes and
 * removes the one with the oldest timestamp; it is global across namespaces,
 * so a busy namespace can evict a quiet one. Removal never merges a parent
 * with its single remaining child, so eviction and purge allocate nothing and
 * cannot fail; such pass-through nodes count against the node cap until their
 * last child goes.
 *
 * Over-cap exception: if the only childless node is the key just linked, the
 * trie is one chain of nested keys and nothing can be evicted. The excess is
 * then at most the node count of that chain, and it stays while further
 * nested keys are inserted; the first insert outside the chain brings the
 * trie back under the caps. A chain has at most L = ns_len + key_len nodes
 * below the root (every label holds at least one byte), so it cannot occur
 * when max_nodes > L. Its bytes are at most the fixed part + (L + 1) node
 * headers + L (L + 1) / 2 label bytes (a node starting at depth s holds at
 * most L - s), so it cannot occur on the byte cap when max_bytes is larger.
 * sockproxy_radix.c checks both at compile time for the defaults, with
 * L = RADIX_NS_MAX + RADIX_DIGEST_KEY_MAX.
 *
 * Evictions per insert: an insert links at most two nodes and at most
 * 2 * sizeof(node) + L bytes; each eviction frees at least one node and at
 * least sizeof(node) + 1 bytes. Outside the exception above, one insert
 * therefore evicts at most max(2, ceil((2 * sizeof(node) + L) /
 * (sizeof(node) + 1))) nodes, each within the per-eviction work bound
 * K + sum over the evicted node's ancestors of (2 * children + 1).
 */
#ifndef __SOCKPROXY_RADIX_H__
#define __SOCKPROXY_RADIX_H__

#include <stddef.h>
#include <stdint.h>

#define RADIX_MAX_EP                 32   /* width of an endpoint mask */
#define RADIX_NS_MAX                 512  /* namespace bytes */
/* Largest product key: the 16 KiB key-stream cap in 256-byte blocks, one
 * 8-byte digest each, plus one for a trailing partial block. */
#define RADIX_DIGEST_KEY_MAX         (16384 / 256 * 8 + 8)
#define RADIX_DEFAULT_MAX_NODES      8192
#define RADIX_DEFAULT_MAX_BYTES      (4u << 20)
#define RADIX_DEFAULT_WORK_CAP       32768
#define RADIX_DEFAULT_EVICT_SAMPLE   16

typedef struct radix_trie radix_trie_t;

typedef struct radix_limits {
  uint32_t max_nodes;        /* 0 -> RADIX_DEFAULT_MAX_NODES; root included;
                                below 2 -> 2 */
  size_t   max_bytes;        /* 0 -> RADIX_DEFAULT_MAX_BYTES */
  uint32_t lookup_work_cap;  /* 0 -> RADIX_DEFAULT_WORK_CAP */
  uint32_t evict_sample;     /* 0 -> RADIX_DEFAULT_EVICT_SAMPLE */
  uint64_t seed;             /* eviction sampling; 0 -> fixed default */
} radix_limits_t;

typedef enum radix_lookup_rc {
  RADIX_LOOKUP_HIT = 0,           /* matched_len >= unit and cand_mask != 0 */
  RADIX_LOOKUP_MISS,              /* no eligible match in this namespace */
  RADIX_LOOKUP_FALLBACK_WORK_CAP, /* work cap reached; matched_len, cand_mask 0 */
  RADIX_LOOKUP_INVALID,           /* NULL argument, key_len 0, unit 0,
                                     key_len % unit, ns_len > RADIX_NS_MAX */
} radix_lookup_rc_t;

typedef struct radix_lookup_res {
  size_t   matched_len; /* key bytes matched at the chosen point, a multiple
                           of unit; namespace bytes never included */
  uint32_t cand_mask;   /* endpoints at that point, ANDed with eligible */
  uint8_t  full;        /* the whole key matched (before the eligible filter) */
  uint32_t work;        /* child probes + label bytes compared + walk-back steps */
} radix_lookup_res_t;

typedef enum radix_insert_rc {
  RADIX_INSERT_OK = 0,
  RADIX_INSERT_NOOP,      /* the key already matched fully with ep among its
                             endpoints: no structural change */
  RADIX_INSERT_NOMEM,     /* allocation failed: trie and counters unchanged */
  RADIX_INSERT_TOO_LARGE, /* the key alone cannot fit under max_bytes */
  RADIX_INSERT_INVALID,   /* NULL argument, key_len 0, ep >= RADIX_MAX_EP,
                             ns_len > RADIX_NS_MAX */
} radix_insert_rc_t;

typedef struct radix_stats {
  uint32_t nodes;               /* root included */
  uint32_t leaves;              /* childless non-root nodes */
  size_t   bytes;               /* counted against max_bytes */
  uint64_t evicted;             /* childless nodes removed by eviction */
  uint64_t evict_work_max;      /* largest work for one evicted node */
  uint64_t lookup_work_cap_hits;
} radix_stats_t;

/* Returns NULL when an allocation fails (nothing leaked). */
radix_trie_t *radix_trie_create(const radix_limits_t *lim);
void radix_trie_free(radix_trie_t *t);

/* Longest eligible prefix of ns || key, reported in whole units of key.
 * Walks toward the root while the candidate set ANDed with eligible is
 * empty; cost is bounded by the depth and the work cap, never a subtree. */
radix_lookup_rc_t radix_trie_lookup(radix_trie_t *t,
                                    const uint8_t *ns, size_t ns_len,
                                    const uint8_t *key, size_t key_len,
                                    size_t unit, uint32_t eligible,
                                    uint32_t now, radix_lookup_res_t *res);

/* Learn ns || key for endpoint ep, then evict to the caps. */
radix_insert_rc_t radix_trie_insert(radix_trie_t *t,
                                    const uint8_t *ns, size_t ns_len,
                                    const uint8_t *key, size_t key_len,
                                    unsigned ep, uint32_t now);

/* Remove ep from every node in one call; no batch limit, cannot fail. */
void radix_trie_purge_ep(radix_trie_t *t, unsigned ep);

void radix_trie_stats(const radix_trie_t *t, radix_stats_t *out);

/* Append one namespace field as a 2-byte big-endian length followed by its
 * bytes. Returns 0, or -1 (ns unchanged) when it would pass cap or len is
 * above 0xFFFF. */
int radix_ns_append(uint8_t *ns, size_t cap, size_t *off,
                    const void *field, size_t len);

#endif /* __SOCKPROXY_RADIX_H__ */
