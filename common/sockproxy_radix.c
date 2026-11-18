/* SPDX-License-Identifier: (GPL-2.0) */
/*
 * sockproxy_radix.c - prefix trie for non-disaggregated prefix routing.
 * See sockproxy_radix.h for the contract and the locking rules.
 *
 * A key is the byte sequence ns || key. Each node holds the edge label from
 * its parent, own_mask (endpoints whose key ends here) and ep_mask (own_mask
 * of the whole subtree). Children are an intrusive sibling list; labels are
 * stored in the node allocation. Childless non-root nodes are kept in a dense
 * array for sampled eviction.
 */
#include <stdlib.h>
#include <string.h>

#include "sockproxy_radix.h"

struct radix_node {
  struct radix_node *parent;
  struct radix_node *first_child;
  struct radix_node *next_sib;
  uint32_t ep_mask;    /* own_mask | ep_mask of every child */
  uint32_t own_mask;   /* endpoints whose key ends exactly here */
  uint32_t ts;         /* coarse time of last use; atomic under the shared lock */
  uint32_t leaf_idx;   /* index in leaves[] while childless, else UINT32_MAX */
  uint32_t label_len;
  uint32_t label_cap;  /* allocated label bytes, counted in bytes */
  uint8_t  label[];
};

struct radix_trie {
  struct radix_node  *root;
  struct radix_node **leaves;  /* childless non-root nodes, dense */
  uint32_t n_leaves;
  uint32_t nodes;              /* root included */
  size_t   bytes;              /* fixed_bytes + node headers + label_cap */
  size_t   fixed_bytes;        /* trie struct + leaves[] */
  radix_limits_t lim;          /* resolved, no zero fields */
  uint64_t rng;
  uint64_t evicted;
  uint64_t evict_work_max;
  uint64_t lookup_work_cap_hits; /* atomic: lookups run under the shared lock */
};

/* The over-cap exception of the header (a single chain of nested keys)
 * cannot occur at the default limits: a chain holds at most L nodes below
 * the root and at most L (L + 1) / 2 label bytes. */
#define RADIX_L_MAX ((size_t)RADIX_NS_MAX + RADIX_DIGEST_KEY_MAX)
_Static_assert(RADIX_DEFAULT_MAX_NODES > RADIX_L_MAX,
               "default node cap must exceed the longest namespace + key");
_Static_assert(RADIX_DEFAULT_MAX_BYTES >
               sizeof(struct radix_trie) +
               (size_t)RADIX_DEFAULT_MAX_NODES * sizeof(struct radix_node *) +
               (RADIX_L_MAX + 1) * sizeof(struct radix_node) +
               RADIX_L_MAX * (RADIX_L_MAX + 1) / 2,
               "default byte cap must hold the longest single chain");

#define NODE_BYTES(n) (sizeof(struct radix_node) + (n)->label_cap)

/* ns || key, read by position */
typedef struct {
  const uint8_t *ns, *key;
  size_t ns_len, len;
} kseq_t;

static inline uint8_t kat(const kseq_t *k, size_t i)
{
  return i < k->ns_len ? k->ns[i] : k->key[i - k->ns_len];
}

static void kcopy(const kseq_t *k, size_t from, size_t n, uint8_t *dst)
{
  for (size_t i = 0; i < n; i++)
    dst[i] = kat(k, from + i);
}

static inline uint32_t ts_get(const struct radix_node *n)
{
  return __atomic_load_n(&n->ts, __ATOMIC_RELAXED);
}

/* Lookups share the node: store only when the value changes. */
static inline void ts_touch(struct radix_node *n, uint32_t now)
{
  if (__atomic_load_n(&n->ts, __ATOMIC_RELAXED) != now)
    __atomic_store_n(&n->ts, now, __ATOMIC_RELAXED);
}

static struct radix_node *node_alloc(size_t label_cap)
{
  struct radix_node *n = calloc(1, sizeof(*n) + label_cap);
  if (!n)
    return NULL;
  n->leaf_idx = UINT32_MAX;
  n->label_cap = (uint32_t)label_cap;
  return n;
}

static struct radix_node *find_child(const struct radix_node *n, uint8_t b,
                                     uint64_t *work)
{
  for (struct radix_node *c = n->first_child; c; c = c->next_sib) {
    (*work)++;
    if (c->label[0] == b)
      return c;
  }
  return NULL;
}

static void leaf_add(radix_trie_t *t, struct radix_node *n)
{
  n->leaf_idx = t->n_leaves;
  t->leaves[t->n_leaves++] = n;
}

static void leaf_del(radix_trie_t *t, struct radix_node *n)
{
  struct radix_node *last = t->leaves[--t->n_leaves];
  t->leaves[n->leaf_idx] = last;
  last->leaf_idx = n->leaf_idx;
  n->leaf_idx = UINT32_MAX;
}

/* Unlink n from its parent's list; work counts the siblings scanned. */
static void unlink_child(struct radix_node *n, uint64_t *work)
{
  struct radix_node **pp = &n->parent->first_child;
  while (*pp != n) {
    (*work)++;
    pp = &(*pp)->next_sib;
  }
  (*work)++;
  *pp = n->next_sib;
  n->next_sib = NULL;
}

static uint64_t rng_next(radix_trie_t *t)
{
  uint64_t x = t->rng;
  x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
  t->rng = x;
  return x * 0x2545F4914F6CDD1DULL;
}

radix_trie_t *radix_trie_create(const radix_limits_t *lim)
{
  radix_trie_t *t = calloc(1, sizeof(*t));
  if (!t)
    return NULL;
  if (lim)
    t->lim = *lim;
  if (!t->lim.max_nodes) t->lim.max_nodes = RADIX_DEFAULT_MAX_NODES;
  if (t->lim.max_nodes < 2) t->lim.max_nodes = 2;
  if (!t->lim.max_bytes) t->lim.max_bytes = RADIX_DEFAULT_MAX_BYTES;
  if (!t->lim.lookup_work_cap) t->lim.lookup_work_cap = RADIX_DEFAULT_WORK_CAP;
  if (!t->lim.evict_sample) t->lim.evict_sample = RADIX_DEFAULT_EVICT_SAMPLE;
  t->rng = t->lim.seed ? t->lim.seed : 0x9E3779B97F4A7C15ULL;
  t->leaves = calloc(t->lim.max_nodes, sizeof(*t->leaves));
  t->root = node_alloc(0);
  if (!t->leaves || !t->root) {
    free(t->leaves);
    free(t->root);
    free(t);
    return NULL;
  }
  t->fixed_bytes = sizeof(*t) + (size_t)t->lim.max_nodes * sizeof(*t->leaves);
  t->nodes = 1;
  t->bytes = t->fixed_bytes + sizeof(struct radix_node);
  return t;
}

void radix_trie_free(radix_trie_t *t)
{
  struct radix_node *n;

  if (!t)
    return;
  /* post-order without recursion: free a node once its children are gone */
  n = t->root;
  while (n) {
    if (n->first_child) {
      n = n->first_child;
      continue;
    }
    struct radix_node *p = n->parent;
    if (p)
      p->first_child = n->next_sib;
    free(n);
    n = p;
  }
  free(t->leaves);
  free(t);
}

/* Evict one childless node other than protect: the oldest of K samples (all
 * leaves when there are no more than K). Removes it, then every ancestor left
 * childless with an empty own_mask, and recomputes ep_mask toward the root
 * until a mask stops changing. Allocates nothing. Returns 1 when one was
 * evicted; *work receives the units spent. */
static int radix_evict_one(radix_trie_t *t, const struct radix_node *protect,
                           uint64_t *work)
{
  struct radix_node *v = NULL, *n;
  uint64_t w = 0;
  uint32_t k = t->lim.evict_sample;

  if (work)
    *work = 0;
  if (t->n_leaves <= k) {
    for (uint32_t i = 0; i < t->n_leaves; i++) {
      struct radix_node *x = t->leaves[i];
      w++;
      if (x != protect && (!v || ts_get(x) < ts_get(v)))
        v = x;
    }
  } else {
    for (uint32_t i = 0; i < k; i++) {
      struct radix_node *x = t->leaves[rng_next(t) % t->n_leaves];
      w++;
      if (x != protect && (!v || ts_get(x) < ts_get(v)))
        v = x;
    }
    if (!v)
      v = t->leaves[0] != protect ? t->leaves[0] : t->leaves[1];
  }
  if (!v)
    return 0;

  n = v->parent;
  unlink_child(v, &w);
  leaf_del(t, v);
  t->nodes--;
  t->bytes -= NODE_BYTES(v);
  free(v);

  while (n) {
    uint32_t m = n->own_mask;
    w++;
    if (n != t->root && !n->first_child && !n->own_mask) {
      struct radix_node *p = n->parent;
      unlink_child(n, &w);
      t->nodes--;
      t->bytes -= NODE_BYTES(n);
      free(n);
      n = p;
      continue;
    }
    if (n != t->root && !n->first_child && n->leaf_idx == UINT32_MAX)
      leaf_add(t, n);
    for (struct radix_node *c = n->first_child; c; c = c->next_sib) {
      w++;
      m |= c->ep_mask;
    }
    if (m == n->ep_mask)
      break;
    n->ep_mask = m;
    n = n->parent;
  }

  t->evicted++;
  if (w > t->evict_work_max)
    t->evict_work_max = w;
  if (work)
    *work = w;
  return 1;
}

radix_lookup_rc_t radix_trie_lookup(radix_trie_t *t,
                                    const uint8_t *ns, size_t ns_len,
                                    const uint8_t *key, size_t key_len,
                                    size_t unit, uint32_t eligible,
                                    uint32_t now, radix_lookup_res_t *res)
{
  kseq_t k = { ns, key, ns_len, ns_len + key_len };
  struct radix_node *cur, *x = NULL;
  size_t pos = 0, x_start = 0, p;
  uint64_t work = 0, cap;

  if (res)
    memset(res, 0, sizeof(*res));
  if (!t || !key || !res || !key_len || !unit || key_len % unit ||
      ns_len > RADIX_NS_MAX || (ns_len && !ns))
    return RADIX_LOOKUP_INVALID;
  cap = t->lim.lookup_work_cap;

  /* descend as far as the bytes match */
  cur = t->root;
  while (pos < k.len) {
    struct radix_node *c = find_child(cur, kat(&k, pos), &work);
    uint32_t j = 0;
    if (!c)
      break;
    while (j < c->label_len && pos + j < k.len && c->label[j] == kat(&k, pos + j)) {
      j++;
      if (++work > cap)
        break;
    }
    if (work > cap)
      goto over;
    ts_touch(c, now);
    x = c;
    x_start = pos;
    pos += j;
    if (j < c->label_len)
      break;
    cur = c;
  }
  if (work > cap)
    goto over;
  res->full = pos == k.len;
  if (pos <= ns_len)
    goto miss;

  /* report the last whole unit; candidates belong to the node containing it */
  p = (pos - ns_len) / unit * unit;
  while (p) {
    size_t target = ns_len + p;
    uint32_t m;
    while (x_start >= target) {
      x = x->parent;
      x_start -= x->label_len;
      work++;
    }
    m = x->ep_mask & eligible;
    if (m) {
      res->matched_len = p;
      res->cand_mask = m;
      res->work = (uint32_t)work;
      return RADIX_LOOKUP_HIT;
    }
    if (++work > cap)
      goto over;
    if (x_start <= ns_len)
      break;
    p = (x_start - ns_len) / unit * unit;
  }
miss:
  res->work = (uint32_t)work;
  return RADIX_LOOKUP_MISS;
over:
  __atomic_fetch_add(&t->lookup_work_cap_hits, 1, __ATOMIC_RELAXED);
  memset(res, 0, sizeof(*res));
  res->work = (uint32_t)work;
  return RADIX_LOOKUP_FALLBACK_WORK_CAP;
}

static void stamp_path(radix_trie_t *t, struct radix_node *n, uint32_t now)
{
  for (; n && n != t->root; n = n->parent)
    ts_touch(n, now);
}

static void or_up(struct radix_node *n, uint32_t bit)
{
  for (; n; n = n->parent)
    n->ep_mask |= bit;
}

radix_insert_rc_t radix_trie_insert(radix_trie_t *t,
                                    const uint8_t *ns, size_t ns_len,
                                    const uint8_t *key, size_t key_len,
                                    unsigned ep, uint32_t now)
{
  kseq_t k = { ns, key, ns_len, ns_len + key_len };
  struct radix_node *cur, *c = NULL, *term, *mid = NULL, *leaf = NULL;
  size_t pos = 0;
  uint32_t j = 0, bit;
  uint64_t w = 0;

  if (!t || !key || !key_len || ep >= RADIX_MAX_EP || ns_len > RADIX_NS_MAX ||
      (ns_len && !ns))
    return RADIX_INSERT_INVALID;
  if (t->fixed_bytes + 2 * sizeof(struct radix_node) + k.len > t->lim.max_bytes)
    return RADIX_INSERT_TOO_LARGE;
  bit = 1u << ep;

  /* walk: stop at the node where the key ends, or where it leaves the trie */
  cur = t->root;
  while (pos < k.len) {
    c = find_child(cur, kat(&k, pos), &w);
    if (!c)
      break;
    for (j = 0; j < c->label_len && pos + j < k.len &&
                c->label[j] == kat(&k, pos + j); j++)
      ;
    if (j < c->label_len)
      break;
    pos += j;
    cur = c;
    c = NULL;
  }

  if (pos == k.len) {                       /* ends on cur */
    if (cur->ep_mask & bit) {
      stamp_path(t, cur, now);
      return RADIX_INSERT_NOOP;
    }
    cur->own_mask |= bit;
    or_up(cur, bit);
    term = cur;
  } else if (!c) {                          /* new leaf under cur */
    leaf = node_alloc(k.len - pos);
    if (!leaf)
      return RADIX_INSERT_NOMEM;
    leaf->label_len = (uint32_t)(k.len - pos);
    kcopy(&k, pos, leaf->label_len, leaf->label);
    leaf->own_mask = leaf->ep_mask = bit;
    leaf->parent = cur;
    leaf->next_sib = cur->first_child;
    if (cur != t->root && !cur->first_child)
      leaf_del(t, cur);
    cur->first_child = leaf;
    leaf_add(t, leaf);
    t->nodes++;
    t->bytes += NODE_BYTES(leaf);
    or_up(cur, bit);
    term = leaf;
  } else if (pos + j == k.len && (c->ep_mask & bit)) {
    /* ends inside c's edge, and ep is already below that point */
    stamp_path(t, c, now);
    return RADIX_INSERT_NOOP;
  } else {                                  /* split c after j bytes */
    struct radix_node **pp;
    int ends = pos + j == k.len;

    mid = node_alloc(j);
    if (!mid)
      return RADIX_INSERT_NOMEM;
    if (!ends) {
      leaf = node_alloc(k.len - pos - j);
      if (!leaf) {
        free(mid);
        return RADIX_INSERT_NOMEM;
      }
    }
    /* mid takes c's place in cur's list, with c below it */
    mid->label_len = j;
    memcpy(mid->label, c->label, j);
    mid->parent = cur;
    for (pp = &cur->first_child; *pp != c; pp = &(*pp)->next_sib)
      ;
    *pp = mid;
    mid->next_sib = c->next_sib;
    c->next_sib = NULL;
    c->parent = mid;
    memmove(c->label, c->label + j, c->label_len - j);
    c->label_len -= j;
    mid->first_child = c;
    mid->ep_mask = c->ep_mask | bit;
    t->nodes++;
    t->bytes += NODE_BYTES(mid);
    if (ends) {
      mid->own_mask = bit;
      term = mid;
    } else {
      leaf->label_len = (uint32_t)(k.len - pos - j);
      kcopy(&k, pos + j, leaf->label_len, leaf->label);
      leaf->own_mask = leaf->ep_mask = bit;
      leaf->parent = mid;
      leaf->next_sib = mid->first_child;
      mid->first_child = leaf;
      leaf_add(t, leaf);
      t->nodes++;
      t->bytes += NODE_BYTES(leaf);
      term = leaf;
    }
    or_up(cur, bit);
  }
  stamp_path(t, term, now);

  /* back under the caps, never evicting the key just linked */
  while (t->nodes > t->lim.max_nodes || t->bytes > t->lim.max_bytes) {
    uint64_t ew;
    if (!radix_evict_one(t, term, &ew))
      break;
  }
  return RADIX_INSERT_OK;
}

void radix_trie_purge_ep(radix_trie_t *t, unsigned ep)
{
  struct radix_node *n;
  uint32_t keep;

  if (!t || ep >= RADIX_MAX_EP)
    return;
  keep = ~(1u << ep);
  /* post-order without recursion: a node is visited after its children */
  n = t->root;
  while (n->first_child)
    n = n->first_child;
  for (;;) {
    struct radix_node *p = n->parent, *s = n->next_sib;
    uint64_t w = 0;

    n->own_mask &= keep;
    n->ep_mask &= keep;
    if (n == t->root)
      break;
    if (!n->first_child && !n->own_mask) {
      unlink_child(n, &w);
      if (n->leaf_idx != UINT32_MAX)
        leaf_del(t, n);
      t->nodes--;
      t->bytes -= NODE_BYTES(n);
      free(n);
    } else if (!n->first_child && n->leaf_idx == UINT32_MAX) {
      leaf_add(t, n);
    }
    if (s) {
      n = s;
      while (n->first_child)
        n = n->first_child;
    } else {
      n = p;
    }
  }
}

void radix_trie_stats(const radix_trie_t *t, radix_stats_t *out)
{
  memset(out, 0, sizeof(*out));
  if (!t)
    return;
  out->nodes = t->nodes;
  out->leaves = t->n_leaves;
  out->bytes = t->bytes;
  out->evicted = t->evicted;
  out->evict_work_max = t->evict_work_max;
  out->lookup_work_cap_hits = __atomic_load_n(&t->lookup_work_cap_hits,
                                              __ATOMIC_RELAXED);
}

int radix_ns_append(uint8_t *ns, size_t cap, size_t *off,
                    const void *field, size_t len)
{
  if (!ns || !off || len > 0xFFFF || (len && !field) || *off > cap ||
      cap - *off < 2 + len)
    return -1;
  ns[*off] = (uint8_t)(len >> 8);
  ns[*off + 1] = (uint8_t)len;
  if (len)
    memcpy(ns + *off + 2, field, len);
  *off += 2 + len;
  return 0;
}
