/* SPDX-License-Identifier: (GPL-2.0) */
/* test_radix_trie.c - the non-disaggregated prefix trie (sockproxy_radix.c,
 * included directly; it is self-contained).
 *
 * functional  the plan's abcdefgh case, 0x00 and marker bytes, mid-edge
 *             mismatch, walk back to a shallower eligible match, work cap,
 *             digest units (a mismatch inside a digest is a mismatch of that
 *             digest), namespace isolation, no-op insert, purge, invalid
 *             arguments.
 * model       seeded random inserts, lookups and purges under small caps;
 *             every lookup equals a brute-force reference (longest common
 *             prefix over the stored keys, with masks) and, after every
 *             operation, ep_mask is the union of the subtree at every node.
 * limits      node and byte caps after churn, no childless node with an
 *             empty mask, pass-through nodes counted, eviction work per
 *             evicted node against its stated bound on adversarial shapes
 *             (caterpillar, wide caterpillar, star, random), purge of an
 *             endpoint owning more than 256 nodes in one call.
 * alloc       every allocation of create and insert failed in turn: NULL or
 *             RADIX_INSERT_NOMEM, the trie identical to before (structural
 *             dump), counters right, nothing leaked; eviction and purge make
 *             no allocation at all.
 * race        lookups under a shared lock while inserts and purges run under
 *             the exclusive lock (TSan build).
 *
 * Eviction work bound for an evicted childless node X, in the units the
 * module counts (one per sample drawn, per sibling scanned to unlink, per
 * child scanned to recompute a mask, per ancestor step):
 *     B(X) = K + sum over ancestors a of X of (2 * children(a) + 1)
 * with K the eviction sample size. Children of different ancestors are
 * different nodes, so B(X) <= K + 2N + depth(X), N the node count.
 *
 * timing      worst single insert and lookup on the adversarial shapes, and
 *             the heap after a churn at the default limits; the figures are
 *             printed only in a non-sanitized build with -DRADIX_TEST_BENCH
 *             (the checks run in every build).
 *
 * Build: make test_radix_trie test_radix_trie_tsan
 * Run:   ./test_radix_trie        (ASan + UBSan)
 *        ./test_radix_trie_tsan
 */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef RADIX_TEST_BENCH
#include <malloc.h>
#endif

/* ---- allocation wrappers, active only inside sockproxy_radix.c ---- */

static long fa_live;          /* module allocations not yet freed */
static long fa_calls;         /* allocation calls made by the module */
static long fa_fail_at = -1;  /* fail the call with this 0-based index; -1 = never */
static pthread_mutex_t fa_mu = PTHREAD_MUTEX_INITIALIZER;

static int fa_should_fail(void)
{
  long idx = fa_calls++;
  if (fa_fail_at >= 0 && idx == fa_fail_at) {
    fa_fail_at = -1;
    return 1;
  }
  return 0;
}

static __attribute__((unused)) void *fa_malloc(size_t n)
{
  void *p = NULL;
  pthread_mutex_lock(&fa_mu);
  if (!fa_should_fail()) {
    p = malloc(n);
    if (p)
      fa_live++;
  }
  pthread_mutex_unlock(&fa_mu);
  return p;
}

static void *fa_calloc(size_t n, size_t sz)
{
  void *p = NULL;
  pthread_mutex_lock(&fa_mu);
  if (!fa_should_fail()) {
    p = calloc(n, sz);
    if (p)
      fa_live++;
  }
  pthread_mutex_unlock(&fa_mu);
  return p;
}

static __attribute__((unused)) void *fa_realloc(void *old, size_t n)
{
  void *p = NULL;
  pthread_mutex_lock(&fa_mu);
  if (!fa_should_fail()) {
    p = realloc(old, n);
    if (p && !old)
      fa_live++;
  }
  pthread_mutex_unlock(&fa_mu);
  return p;
}

static void fa_free(void *p)
{
  if (!p)
    return;
  pthread_mutex_lock(&fa_mu);
  fa_live--;
  pthread_mutex_unlock(&fa_mu);
  free(p);
}

#define malloc(n) fa_malloc(n)
#define calloc(n, sz) fa_calloc(n, sz)
#define realloc(p, n) fa_realloc(p, n)
#define free(p) fa_free(p)
#include "sockproxy_radix.c"
#undef malloc
#undef calloc
#undef realloc
#undef free

/* ---- reporting ---- */

static int g_fail;
static int g_case_fail;
static const char *g_case;

#define CHECK(c) do {                                                   \
    if (!(c)) {                                                         \
      g_fail++;                                                         \
      if (g_case_fail++ < 6)                                            \
        printf("    check failed: %s (line %d)\n", #c, __LINE__);       \
    }                                                                   \
  } while (0)

static void case_begin(const char *name)
{
  g_case = name;
  g_case_fail = 0;
}

static void case_end(void)
{
  printf("[%s] %s%s\n", g_case_fail ? "FAIL" : "PASS", g_case,
         g_case_fail > 6 ? " (more failures not shown)" : "");
}

/* ---- small helpers ---- */

static uint64_t rng_state;
static uint64_t rnd(void)
{
  uint64_t x = rng_state;
  x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
  rng_state = x;
  return x * 0x2545F4914F6CDD1DULL;
}

static radix_trie_t *mk(uint32_t max_nodes, size_t max_bytes, uint32_t work_cap)
{
  radix_limits_t l = { .max_nodes = max_nodes, .max_bytes = max_bytes,
                       .lookup_work_cap = work_cap, .evict_sample = 0,
                       .seed = 12345 };
  return radix_trie_create(&l);
}

static radix_lookup_rc_t lk(radix_trie_t *t, const void *ns, size_t nsl,
                            const void *k, size_t kl, size_t unit,
                            uint32_t el, uint32_t now, radix_lookup_res_t *r)
{
  return radix_trie_lookup(t, ns, nsl, k, kl, unit, el, now, r);
}

static radix_insert_rc_t ins(radix_trie_t *t, const void *ns, size_t nsl,
                             const void *k, size_t kl, unsigned ep, uint32_t now)
{
  return radix_trie_insert(t, ns, nsl, k, kl, ep, now);
}

#define S(x) (const uint8_t *)(x), (sizeof(x) - 1)
#define BIT(e) (1u << (e))

/* ---- structural checker (reads the module's internals) ---- */

typedef struct {
  uint32_t nodes, leaves, depth_max;
  size_t bytes;
  int bad;
} walk_t;

static void bad(walk_t *w, const char *what)
{
  if (w->bad++ < 3)
    printf("    structure: %s\n", what);
}

static void chk_node(radix_trie_t *t, struct radix_node *n, walk_t *w, uint32_t depth)
{
  uint8_t seen[256];
  uint32_t m = n->own_mask;
  int nch = 0;

  memset(seen, 0, sizeof(seen));
  w->nodes++;
  w->bytes += sizeof(*n) + n->label_cap;
  if (depth > w->depth_max)
    w->depth_max = depth;
  for (struct radix_node *c = n->first_child; c; c = c->next_sib) {
    nch++;
    if (c->parent != n) bad(w, "child's parent pointer");
    if (c->label_len == 0 || c->label_len > c->label_cap) bad(w, "label length");
    else if (seen[c->label[0]]++) bad(w, "two children share a first byte");
    m |= c->ep_mask;
    chk_node(t, c, w, depth + 1);
  }
  if (m != n->ep_mask) bad(w, "ep_mask is not the union of own_mask and children");
  if (n == t->root) {
    if (n->label_len || n->own_mask || n->parent || n->leaf_idx != UINT32_MAX)
      bad(w, "root fields");
  } else if (!nch) {
    w->leaves++;
    if (!n->own_mask) bad(w, "childless node with an empty mask");
    if (n->leaf_idx >= t->n_leaves || t->leaves[n->leaf_idx] != n)
      bad(w, "childless node not at its leaves[] slot");
  } else if (n->leaf_idx != UINT32_MAX) {
    bad(w, "node with children is in leaves[]");
  }
}

/* Returns 0 when the trie is valid and its counters match a recount. */
static int check_trie(radix_trie_t *t, walk_t *out)
{
  walk_t w;
  memset(&w, 0, sizeof(w));
  if (!t || !t->root) {
    bad(&w, "no trie or no root");
    if (out) *out = w;
    return w.bad;
  }
  chk_node(t, t->root, &w, 0);
  if (w.nodes != t->nodes) bad(&w, "node counter");
  if (w.leaves != t->n_leaves) bad(&w, "leaf counter");
  if (t->fixed_bytes != sizeof(*t) + (size_t)t->lim.max_nodes * sizeof(*t->leaves))
    bad(&w, "fixed bytes");
  if (w.bytes + t->fixed_bytes != t->bytes) bad(&w, "byte counter");
  if (out) *out = w;
  return w.bad;
}

static int within_caps(radix_trie_t *t)
{
  return (t->nodes <= t->lim.max_nodes && t->bytes <= t->lim.max_bytes) ||
         t->n_leaves <= 1;
}

/* ---- stored-key sets ---- */

typedef struct { uint8_t *b; size_t len; uint32_t mask; } ent_t;
typedef struct { ent_t *e; size_t n, cap; } set_t;

static void set_add(set_t *s, const uint8_t *b, size_t len, uint32_t mask)
{
  if (s->n == s->cap) {
    s->cap = s->cap ? 2 * s->cap : 64;
    s->e = realloc(s->e, s->cap * sizeof(*s->e));
  }
  s->e[s->n].b = malloc(len ? len : 1);
  memcpy(s->e[s->n].b, b, len);
  s->e[s->n].len = len;
  s->e[s->n].mask = mask;
  s->n++;
}

static void set_clear(set_t *s)
{
  for (size_t i = 0; i < s->n; i++)
    free(s->e[i].b);
  s->n = 0;
}

static void set_free(set_t *s)
{
  set_clear(s);
  free(s->e);
  s->e = NULL;
  s->cap = 0;
}

static int ent_cmp(const void *a, const void *b)
{
  const ent_t *x = a, *y = b;
  size_t m = x->len < y->len ? x->len : y->len;
  int c = memcmp(x->b, y->b, m);
  if (c) return c;
  return x->len < y->len ? -1 : x->len > y->len;
}

static ent_t *set_find(set_t *s, const uint8_t *b, size_t len)
{
  for (size_t i = 0; i < s->n; i++)
    if (s->e[i].len == len && !memcmp(s->e[i].b, b, len))
      return &s->e[i];
  return NULL;
}

static uint8_t path_buf[1 << 16];

static void collect_node(struct radix_node *n, size_t depth, set_t *s)
{
  if (depth + n->label_len > sizeof(path_buf))
    return;
  memcpy(path_buf + depth, n->label, n->label_len);
  depth += n->label_len;
  if (n->own_mask)
    set_add(s, path_buf, depth, n->own_mask);
  for (struct radix_node *c = n->first_child; c; c = c->next_sib)
    collect_node(c, depth, s);
}

/* Every stored full key (ns || key) with the endpoints learned for it. */
static void collect(radix_trie_t *t, set_t *s)
{
  set_clear(s);
  if (t && t->root)
    collect_node(t->root, 0, s);
  if (s->n > 1)
    qsort(s->e, s->n, sizeof(*s->e), ent_cmp);
}

/* Brute-force reference lookup over a stored-key set. */
typedef struct { radix_lookup_rc_t rc; size_t matched; uint32_t cand; uint8_t full; } ref_res_t;

static ref_res_t ref_lookup(set_t *s, const uint8_t *ns, size_t nsl,
                            const uint8_t *k, size_t kl, size_t unit, uint32_t el)
{
  ref_res_t r = { RADIX_LOOKUP_MISS, 0, 0, 0 };
  size_t best = 0;
  size_t *lcp = calloc(s->n ? s->n : 1, sizeof(*lcp));

  for (size_t i = 0; i < s->n; i++) {
    ent_t *e = &s->e[i];
    size_t j = 0;
    if (e->len < nsl || memcmp(e->b, ns, nsl))
      continue;
    while (j < kl && nsl + j < e->len && e->b[nsl + j] == k[j])
      j++;
    lcp[i] = j;
    if (j > best)
      best = j;
  }
  r.full = best == kl;
  for (size_t p = best / unit * unit; p >= unit; p -= unit) {
    uint32_t m = 0;
    for (size_t i = 0; i < s->n; i++)
      if (lcp[i] >= p)
        m |= s->e[i].mask;
    if (m & el) {
      r.rc = RADIX_LOOKUP_HIT;
      r.matched = p;
      r.cand = m & el;
      break;
    }
  }
  free(lcp);
  return r;
}

/* ---- structural dump for before/after identity ---- */

typedef struct { uint8_t *b; size_t n, cap; } buf_t;

static void put(buf_t *d, const void *p, size_t n)
{
  if (d->n + n > d->cap) {
    d->cap = (d->n + n) * 2 + 256;
    d->b = realloc(d->b, d->cap);
  }
  memcpy(d->b + d->n, p, n);
  d->n += n;
}

static struct radix_node *dump_order[1 << 14];
static size_t dump_count;

static void dump_node(struct radix_node *n, buf_t *d)
{
  uint32_t nch = 0;
  if (dump_count < sizeof(dump_order) / sizeof(dump_order[0]))
    dump_order[dump_count] = n;
  dump_count++;
  for (struct radix_node *c = n->first_child; c; c = c->next_sib)
    nch++;
  put(d, &n->label_len, sizeof(n->label_len));
  put(d, n->label, n->label_len);
  put(d, &n->label_cap, sizeof(n->label_cap));
  put(d, &n->own_mask, sizeof(n->own_mask));
  put(d, &n->ep_mask, sizeof(n->ep_mask));
  put(d, &n->ts, sizeof(n->ts));
  put(d, &n->leaf_idx, sizeof(n->leaf_idx));
  put(d, &nch, sizeof(nch));
  for (struct radix_node *c = n->first_child; c; c = c->next_sib)
    dump_node(c, d);
}

static void dump(radix_trie_t *t, buf_t *d)
{
  d->n = 0;
  dump_count = 0;
  put(d, &t->nodes, sizeof(t->nodes));
  put(d, &t->n_leaves, sizeof(t->n_leaves));
  put(d, &t->bytes, sizeof(t->bytes));
  put(d, &t->evicted, sizeof(t->evicted));
  put(d, &t->rng, sizeof(t->rng));
  if (t->root)
    dump_node(t->root, d);
  for (uint32_t i = 0; i < t->n_leaves; i++) {
    uint32_t idx = UINT32_MAX;
    for (size_t j = 0; j < dump_count && j < 1u << 14; j++)
      if (dump_order[j] == t->leaves[i])
        idx = (uint32_t)j;
    put(d, &idx, sizeof(idx));
  }
}

static int same_dump(buf_t *a, buf_t *b)
{
  return a->n == b->n && !memcmp(a->b, b->b, a->n);
}

/* ================= functional ================= */

static int mk_ns(uint8_t *ns, size_t cap, size_t *len, const char *model,
                 const char *tenant);

static void t_plan_case(void)
{
  radix_lookup_res_t r;
  radix_trie_t *t = mk(0, 0, 0);
  enum { A = 0, B = 1 };

  case_begin("functional: plan case abcdefgh / abcdefXY / abcdef / abcdefZZ");
  CHECK(t != NULL);
  if (!t) { case_end(); return; }
  CHECK(ins(t, NULL, 0, S("abcdefgh"), A, 1) == RADIX_INSERT_OK);
  CHECK(lk(t, NULL, 0, S("abcdefXY"), 1, ~0u, 2, &r) == RADIX_LOOKUP_HIT);
  CHECK(r.matched_len == 6 && r.cand_mask == BIT(A) && !r.full);
  CHECK(lk(t, NULL, 0, S("abcdef"), 1, ~0u, 2, &r) == RADIX_LOOKUP_HIT);
  CHECK(r.matched_len == 6 && r.cand_mask == BIT(A) && r.full);
  CHECK(ins(t, NULL, 0, S("abcdefZZ"), B, 3) == RADIX_INSERT_OK);
  CHECK(lk(t, NULL, 0, S("abcdef"), 1, ~0u, 4, &r) == RADIX_LOOKUP_HIT);
  CHECK(r.matched_len == 6 && r.cand_mask == (BIT(A) | BIT(B)) && r.full);
  CHECK(lk(t, NULL, 0, S("abcdefXY"), 1, ~0u, 4, &r) == RADIX_LOOKUP_HIT);
  CHECK(r.matched_len == 6 && r.cand_mask == (BIT(A) | BIT(B)));
  CHECK(lk(t, NULL, 0, S("abcdefgh"), 1, ~0u, 4, &r) == RADIX_LOOKUP_HIT);
  CHECK(r.matched_len == 8 && r.cand_mask == BIT(A) && r.full);
  CHECK(check_trie(t, NULL) == 0);
  radix_trie_free(t);
  case_end();
}

static void t_binary_bytes(void)
{
  static const uint8_t k1[] = { 0x00, 0xFE, 'u', 0x00, 'x', 0xFF, 0xFE, 'a', 1 };
  static const uint8_t k2[] = { 0x00, 0xFE, 'u', 0x00, 'x', 0xFF, 0xFE, 'a', 2 };
  static const uint8_t q1[] = { 0x00, 0xFE, 'u', 0x00, 'y' };
  radix_lookup_res_t r;
  radix_trie_t *t = mk(0, 0, 0);

  case_begin("functional: keys with 0x00, 0xFE and 0xFF bytes");
  CHECK(t != NULL);
  if (!t) { case_end(); return; }
  CHECK(ins(t, NULL, 0, k1, sizeof(k1), 3, 1) == RADIX_INSERT_OK);
  CHECK(ins(t, NULL, 0, k2, sizeof(k2), 4, 1) == RADIX_INSERT_OK);
  CHECK(lk(t, NULL, 0, k1, sizeof(k1), 1, ~0u, 1, &r) == RADIX_LOOKUP_HIT);
  CHECK(r.matched_len == sizeof(k1) && r.cand_mask == BIT(3) && r.full);
  CHECK(lk(t, NULL, 0, k2, sizeof(k2) - 1, 1, ~0u, 1, &r) == RADIX_LOOKUP_HIT);
  CHECK(r.matched_len == sizeof(k2) - 1 && r.cand_mask == (BIT(3) | BIT(4)));
  CHECK(lk(t, NULL, 0, q1, sizeof(q1), 1, ~0u, 1, &r) == RADIX_LOOKUP_HIT);
  CHECK(r.matched_len == 4 && r.cand_mask == (BIT(3) | BIT(4)));
  CHECK(check_trie(t, NULL) == 0);
  radix_trie_free(t);
  case_end();
}

static void t_mid_edge(void)
{
  radix_lookup_res_t r;
  radix_trie_t *t = mk(0, 0, 0);

  case_begin("functional: mismatch in the middle of a compressed edge");
  CHECK(t != NULL);
  if (!t) { case_end(); return; }
  CHECK(ins(t, NULL, 0, S("hello world"), 7, 1) == RADIX_INSERT_OK);
  CHECK(lk(t, NULL, 0, S("hello wxrld"), 1, ~0u, 1, &r) == RADIX_LOOKUP_HIT);
  CHECK(r.matched_len == 7 && r.cand_mask == BIT(7) && !r.full);
  CHECK(lk(t, NULL, 0, S("hello world and more"), 1, ~0u, 1, &r) == RADIX_LOOKUP_HIT);
  CHECK(r.matched_len == 11 && r.cand_mask == BIT(7) && !r.full);
  CHECK(lk(t, NULL, 0, S("xello"), 1, ~0u, 1, &r) == RADIX_LOOKUP_MISS);
  CHECK(r.matched_len == 0 && r.cand_mask == 0);
  radix_trie_free(t);
  case_end();
}

static void t_walk_back(void)
{
  radix_lookup_res_t r;
  radix_trie_t *t = mk(0, 0, 0);

  case_begin("functional: empty eligible set at the deepest match, eligible shallower match");
  CHECK(t != NULL);
  if (!t) { case_end(); return; }
  CHECK(ins(t, NULL, 0, S("abcdefgh"), 0, 1) == RADIX_INSERT_OK);
  CHECK(ins(t, NULL, 0, S("abcdXYZW"), 1, 1) == RADIX_INSERT_OK);
  CHECK(ins(t, NULL, 0, S("ab"), 2, 1) == RADIX_INSERT_OK);
  CHECK(lk(t, NULL, 0, S("abcdefgh"), 1, BIT(1), 1, &r) == RADIX_LOOKUP_HIT);
  CHECK(r.matched_len == 4 && r.cand_mask == BIT(1) && r.full);
  CHECK(lk(t, NULL, 0, S("abcdefgh"), 1, BIT(2), 1, &r) == RADIX_LOOKUP_HIT);
  CHECK(r.matched_len == 2 && r.cand_mask == BIT(2));
  CHECK(lk(t, NULL, 0, S("abcdefgh"), 1, BIT(1) | BIT(2), 1, &r) == RADIX_LOOKUP_HIT);
  CHECK(r.matched_len == 4 && r.cand_mask == BIT(1));
  CHECK(lk(t, NULL, 0, S("abcdefgh"), 1, 0, 1, &r) == RADIX_LOOKUP_MISS);
  CHECK(lk(t, NULL, 0, S("abcdefgh"), 1, BIT(9), 1, &r) == RADIX_LOOKUP_MISS);
  CHECK(r.matched_len == 0 && r.cand_mask == 0);
  radix_trie_free(t);
  case_end();
}

static void t_work_cap(void)
{
  radix_lookup_res_t r;
  radix_stats_t st;
  radix_trie_t *t = mk(0, 0, 4), *u = mk(0, 0, 0);

  case_begin("functional: lookup work cap gives a fall-back result");
  CHECK(t != NULL && u != NULL);
  if (!t || !u) { radix_trie_free(t); radix_trie_free(u); case_end(); return; }
  CHECK(ins(t, NULL, 0, S("abcdefghijklmnop"), 0, 1) == RADIX_INSERT_OK);
  CHECK(ins(u, NULL, 0, S("abcdefghijklmnop"), 0, 1) == RADIX_INSERT_OK);
  CHECK(lk(t, NULL, 0, S("abcdefghijklmnop"), 1, ~0u, 1, &r) ==
        RADIX_LOOKUP_FALLBACK_WORK_CAP);
  CHECK(r.matched_len == 0 && r.cand_mask == 0);
  radix_trie_stats(t, &st);
  CHECK(st.lookup_work_cap_hits == 1);
  CHECK(lk(u, NULL, 0, S("abcdefghijklmnop"), 1, ~0u, 1, &r) == RADIX_LOOKUP_HIT);
  CHECK(r.matched_len == 16 && r.work > 4 && r.work <= RADIX_DEFAULT_WORK_CAP);
  radix_trie_stats(u, &st);
  CHECK(st.lookup_work_cap_hits == 0);
  radix_trie_free(t);
  radix_trie_free(u);
  case_end();
}

static void t_digest_units(void)
{
  /* two 8-byte digests per key */
  static const uint8_t s1[] = "AAAAAAAABBBBCCCC";
  static const uint8_t s2[] = "AAAAAAAABBBBDDDD";
  static const uint8_t q1[] = "AAAAAAAABBBBxxxx";
  static const uint8_t q2[] = "AAAAxxxxBBBBCCCC";
  radix_lookup_res_t r;
  radix_trie_t *t = mk(0, 0, 0);

  case_begin("functional: digest units (unit 8): a mismatch inside a digest is a mismatch of that digest");
  CHECK(t != NULL);
  if (!t) { case_end(); return; }
  CHECK(ins(t, NULL, 0, s1, 16, 0, 1) == RADIX_INSERT_OK);
  CHECK(lk(t, NULL, 0, s1, 16, 8, ~0u, 1, &r) == RADIX_LOOKUP_HIT);
  CHECK(r.matched_len == 16 && r.full);
  CHECK(lk(t, NULL, 0, q1, 16, 8, ~0u, 1, &r) == RADIX_LOOKUP_HIT);
  CHECK(r.matched_len == 8 && r.cand_mask == BIT(0) && !r.full);
  CHECK(lk(t, NULL, 0, q1, 16, 1, ~0u, 1, &r) == RADIX_LOOKUP_HIT);
  CHECK(r.matched_len == 12);
  CHECK(lk(t, NULL, 0, q2, 16, 8, ~0u, 1, &r) == RADIX_LOOKUP_MISS);
  CHECK(r.matched_len == 0);
  /* the split now falls inside the second digest */
  CHECK(ins(t, NULL, 0, s2, 16, 1, 1) == RADIX_INSERT_OK);
  CHECK(lk(t, NULL, 0, s1, 16, 8, BIT(1), 1, &r) == RADIX_LOOKUP_HIT);
  CHECK(r.matched_len == 8 && r.cand_mask == BIT(1));
  CHECK(lk(t, NULL, 0, s1, 16, 8, BIT(0), 1, &r) == RADIX_LOOKUP_HIT);
  CHECK(r.matched_len == 16 && r.cand_mask == BIT(0));
  /* cand_mask belongs to the node containing the reported position (8),
   * not to the deepest node reached (the s1 leaf, at raw match 14) */
  CHECK(lk(t, NULL, 0, "AAAAAAAABBBBCCxx", 16, 8, ~0u, 1, &r) == RADIX_LOOKUP_HIT);
  CHECK(r.matched_len == 8 && r.cand_mask == (BIT(0) | BIT(1)));
  CHECK(lk(t, NULL, 0, s1, 12, 8, ~0u, 1, &r) == RADIX_LOOKUP_INVALID);
  CHECK(lk(t, NULL, 0, s1, 16, 0, ~0u, 1, &r) == RADIX_LOOKUP_INVALID);
  /* units count from the key start whatever the namespace length (6 here) */
  {
    uint8_t ns[16];
    size_t nl = 0;
    CHECK(mk_ns(ns, sizeof(ns), &nl, "m", "t") == 0);
    CHECK(nl == 6);
    if (nl == 6) {
      CHECK(ins(t, ns, nl, s1, 16, 2, 1) == RADIX_INSERT_OK);
      CHECK(lk(t, ns, nl, q1, 16, 8, ~0u, 1, &r) == RADIX_LOOKUP_HIT);
      CHECK(r.matched_len == 8 && r.cand_mask == BIT(2) && !r.full);
      CHECK(lk(t, ns, nl, s1, 16, 8, ~0u, 1, &r) == RADIX_LOOKUP_HIT);
      CHECK(r.matched_len == 16 && r.cand_mask == BIT(2) && r.full);
      CHECK(lk(t, ns, nl, "AAAAAAAxBBBBCCCC", 16, 8, ~0u, 1, &r) == RADIX_LOOKUP_MISS);
      CHECK(r.matched_len == 0);
    }
  }
  radix_trie_free(t);
  case_end();
}

static int mk_ns(uint8_t *ns, size_t cap, size_t *len, const char *model,
                 const char *tenant)
{
  *len = 0;
  if (radix_ns_append(ns, cap, len, model, strlen(model)) != 0)
    return -1;
  return radix_ns_append(ns, cap, len, tenant, strlen(tenant));
}

static void t_ns_encoding(void)
{
  uint8_t a[64], b[64], big[8];
  size_t al = 0, bl = 0, off = 0;
  static const uint8_t want[] = { 0, 1, 'a', 0, 2, 'b', 'c' };

  memset(a, 0, sizeof(a));
  memset(b, 0, sizeof(b));
  case_begin("functional: namespace encoding is length-prefixed and prefix-free");
  CHECK(radix_ns_append(a, sizeof(a), &al, "a", 1) == 0);
  CHECK(radix_ns_append(a, sizeof(a), &al, "bc", 2) == 0);
  CHECK(radix_ns_append(b, sizeof(b), &bl, "ab", 2) == 0);
  CHECK(radix_ns_append(b, sizeof(b), &bl, "c", 1) == 0);
  CHECK(al == 7 && bl == 7 && !memcmp(a, want, 7));
  CHECK(memcmp(a, b, 7) != 0);
  CHECK(radix_ns_append(big, sizeof(big), &off, "123456", 6) == 0);
  CHECK(off == 8);
  CHECK(radix_ns_append(big, sizeof(big), &off, "", 0) == -1);
  CHECK(off == 8);
  off = 0;
  CHECK(radix_ns_append(big, sizeof(big), &off, "1234567", 7) == -1);
  CHECK(off == 0);
  CHECK(radix_ns_append(big, (size_t)1 << 20, &off, big, 0x10000) == -1);
  CHECK(off == 0);
  case_end();
}

static void t_ns_isolation(void)
{
  uint8_t n1[64], n2[64];
  size_t l1 = 0, l2 = 0;
  radix_lookup_res_t r;
  radix_trie_t *t = mk(0, 0, 0);

  case_begin("functional: namespaces isolate learning and lookup; matched length excludes namespace bytes");
  CHECK(t != NULL);
  if (!t) { case_end(); return; }
  CHECK(mk_ns(n1, sizeof(n1), &l1, "model-x", "tenant-1") == 0);
  CHECK(mk_ns(n2, sizeof(n2), &l2, "model-x", "tenant-2") == 0);
  if (!l1 || !l2) { radix_trie_free(t); case_end(); return; }
  CHECK(ins(t, n1, l1, S("system prompt and doc"), 0, 1) == RADIX_INSERT_OK);
  CHECK(lk(t, n2, l2, S("system prompt and doc"), 1, ~0u, 1, &r) == RADIX_LOOKUP_MISS);
  CHECK(r.matched_len == 0 && r.cand_mask == 0);
  CHECK(lk(t, n1, l1, S("system prompt and doc"), 1, ~0u, 1, &r) == RADIX_LOOKUP_HIT);
  CHECK(r.matched_len == 21 && r.full && r.cand_mask == BIT(0));
  CHECK(ins(t, n2, l2, S("system prompt and doc"), 1, 1) == RADIX_INSERT_OK);
  CHECK(lk(t, n1, l1, S("system prompt and doc"), 1, ~0u, 1, &r) == RADIX_LOOKUP_HIT);
  CHECK(r.cand_mask == BIT(0));
  CHECK(lk(t, n2, l2, S("system prompt and doc"), 1, ~0u, 1, &r) == RADIX_LOOKUP_HIT);
  CHECK(r.cand_mask == BIT(1));
  /* the other namespace's endpoint is never a shallower candidate */
  CHECK(lk(t, n2, l2, S("system prompt"), 1, BIT(0), 1, &r) == RADIX_LOOKUP_MISS);
  CHECK(lk(t, n1, l1, S("zzz"), 1, ~0u, 1, &r) == RADIX_LOOKUP_MISS);
  CHECK(check_trie(t, NULL) == 0);
  radix_trie_free(t);
  case_end();
}

static void t_noop_insert(void)
{
  radix_stats_t a, b;
  buf_t d0 = {0}, d1 = {0};
  radix_trie_t *t = mk(0, 0, 0);

  case_begin("functional: no insert work when the key already matches fully for the same endpoint");
  CHECK(t != NULL);
  if (!t) { case_end(); return; }
  CHECK(ins(t, NULL, 0, S("abcdef"), 2, 1) == RADIX_INSERT_OK);
  radix_trie_stats(t, &a);
  dump(t, &d0);
  CHECK(ins(t, NULL, 0, S("abcdef"), 2, 1) == RADIX_INSERT_NOOP);
  CHECK(ins(t, NULL, 0, S("abc"), 2, 1) == RADIX_INSERT_NOOP);
  dump(t, &d1);
  CHECK(same_dump(&d0, &d1));
  radix_trie_stats(t, &b);
  CHECK(a.nodes == b.nodes && a.bytes == b.bytes);
  CHECK(ins(t, NULL, 0, S("abc"), 3, 1) == RADIX_INSERT_OK);
  radix_trie_stats(t, &b);
  CHECK(b.nodes == a.nodes + 1);
  CHECK(check_trie(t, NULL) == 0);
  free(d0.b);
  free(d1.b);
  radix_trie_free(t);
  case_end();
}

static void t_purge_basic(void)
{
  radix_lookup_res_t r;
  radix_trie_t *t = mk(0, 0, 0);

  case_begin("functional: purge removes one endpoint everywhere");
  CHECK(t != NULL);
  if (!t) { case_end(); return; }
  CHECK(ins(t, NULL, 0, S("shared-prefix-A"), 0, 1) == RADIX_INSERT_OK);
  CHECK(ins(t, NULL, 0, S("shared-prefix-A"), 1, 1) == RADIX_INSERT_OK);
  CHECK(ins(t, NULL, 0, S("shared-prefix-B"), 0, 1) == RADIX_INSERT_OK);
  radix_trie_purge_ep(t, 0);
  CHECK(lk(t, NULL, 0, S("shared-prefix-A"), 1, ~0u, 1, &r) == RADIX_LOOKUP_HIT);
  CHECK(r.matched_len == 15 && r.cand_mask == BIT(1));
  CHECK(lk(t, NULL, 0, S("shared-prefix-B"), 1, ~0u, 1, &r) == RADIX_LOOKUP_HIT);
  CHECK(r.matched_len == 14 && r.cand_mask == BIT(1));
  CHECK(lk(t, NULL, 0, S("shared-prefix-B"), 1, BIT(0), 1, &r) == RADIX_LOOKUP_MISS);
  /* root, "shared-prefix-" (now a pass-through: no merge on removal), "A" */
  CHECK(check_trie(t, NULL) == 0 && t->nodes == 3);
  radix_trie_purge_ep(t, 1);
  CHECK(check_trie(t, NULL) == 0 && t->nodes == 1 && t->n_leaves == 0);
  radix_trie_purge_ep(t, 40);   /* out of range: no effect */
  CHECK(check_trie(t, NULL) == 0);
  radix_trie_free(t);
  case_end();
}

static void t_invalid(void)
{
  uint8_t ns[RADIX_NS_MAX + 1];
  radix_lookup_res_t r;
  radix_trie_t *t = mk(0, 0, 0);

  memset(ns, 0, sizeof(ns));
  case_begin("functional: invalid arguments");
  CHECK(t != NULL);
  if (!t) { case_end(); return; }
  CHECK(ins(t, NULL, 0, S("k"), RADIX_MAX_EP, 1) == RADIX_INSERT_INVALID);
  CHECK(ins(t, NULL, 0, "k", 0, 0, 1) == RADIX_INSERT_INVALID);
  CHECK(ins(t, ns, sizeof(ns), S("k"), 0, 1) == RADIX_INSERT_INVALID);
  CHECK(ins(NULL, NULL, 0, S("k"), 0, 1) == RADIX_INSERT_INVALID);
  CHECK(ins(t, NULL, 0, NULL, 1, 0, 1) == RADIX_INSERT_INVALID);
  CHECK(lk(t, NULL, 0, "k", 0, 1, ~0u, 1, &r) == RADIX_LOOKUP_INVALID);
  CHECK(lk(t, ns, sizeof(ns), S("k"), 1, ~0u, 1, &r) == RADIX_LOOKUP_INVALID);
  CHECK(lk(t, NULL, 0, S("k"), 1, ~0u, 1, NULL) == RADIX_LOOKUP_INVALID);
  CHECK(lk(NULL, NULL, 0, S("k"), 1, ~0u, 1, &r) == RADIX_LOOKUP_INVALID);
  CHECK(check_trie(t, NULL) == 0 && t->nodes == 1);
  radix_trie_free(t);
  case_end();
}

static void t_too_large(void)
{
  static uint8_t big[4096];
  radix_limits_t l = { .max_nodes = 64 };
  radix_trie_t *t;

  case_begin("functional: a key that alone exceeds the byte cap is refused");
  l.max_bytes = sizeof(struct radix_trie) + 64 * sizeof(void *) + 1024;
  t = radix_trie_create(&l);
  CHECK(t != NULL);
  if (!t) { case_end(); return; }
  memset(big, 'q', sizeof(big));
  CHECK(ins(t, NULL, 0, big, sizeof(big), 0, 1) == RADIX_INSERT_TOO_LARGE);
  CHECK(check_trie(t, NULL) == 0 && t->nodes == 1);
  CHECK(ins(t, NULL, 0, big, 64, 0, 1) == RADIX_INSERT_OK);
  radix_trie_free(t);
  case_end();
}

static void t_recency(void)
{
  radix_lookup_res_t r;
  uint64_t w;
  radix_trie_t *t = mk(0, 0, 0);

  case_begin("functional: a lookup refreshes recency; eviction takes the oldest");
  CHECK(t != NULL);
  if (!t) { case_end(); return; }
  CHECK(ins(t, NULL, 0, S("key-one"), 0, 10) == RADIX_INSERT_OK);
  CHECK(ins(t, NULL, 0, S("key-two"), 0, 11) == RADIX_INSERT_OK);
  CHECK(ins(t, NULL, 0, S("key-three"), 0, 12) == RADIX_INSERT_OK);
  CHECK(lk(t, NULL, 0, S("key-one"), 1, ~0u, 20, &r) == RADIX_LOOKUP_HIT);
  CHECK(radix_evict_one(t, NULL, &w) == 1);
  CHECK(lk(t, NULL, 0, S("key-one"), 1, ~0u, 21, &r) == RADIX_LOOKUP_HIT && r.full);
  CHECK(lk(t, NULL, 0, S("key-two"), 1, ~0u, 21, &r) == RADIX_LOOKUP_HIT && !r.full);
  CHECK(lk(t, NULL, 0, S("key-three"), 1, ~0u, 21, &r) == RADIX_LOOKUP_HIT && r.full);
  CHECK(check_trie(t, NULL) == 0);
  radix_trie_free(t);
  case_end();
}

/* ================= model check ================= */

static const uint8_t unit_alpha[6][8] = {
  { 'A','A','A','A','A','A','A','A' }, { 'A','A','A','A','B','B','B','B' },
  { 'A','A','A','A','B','B','B','C' }, { 0, 0, 0, 0, 0, 0, 0, 0 },
  { 0xFE,0xFF,0xFE,0xFF,0,0,0,0 },     { 'Z','Z','Z','Z','Z','Z','Z','Z' },
};
static const uint8_t byte_alpha[5] = { 0x00, 'a', 'b', 0xFE, 0xFF };

static size_t gen_key(uint8_t *k, size_t unit)
{
  if (unit == 1) {
    size_t n = 1 + rnd() % 10;
    for (size_t i = 0; i < n; i++)
      k[i] = byte_alpha[rnd() % 5];
    return n;
  }
  size_t n = 1 + rnd() % 5;
  for (size_t i = 0; i < n; i++)
    memcpy(k + 8 * i, unit_alpha[rnd() % 6], 8);
  return 8 * n;
}

static int set_equal(set_t *a, set_t *b)
{
  if (a->n != b->n)
    return 0;
  for (size_t i = 0; i < a->n; i++)
    if (ent_cmp(&a->e[i], &b->e[i]) || a->e[i].mask != b->e[i].mask)
      return 0;
  return 1;
}

static void model_run(uint64_t seed, size_t unit, int nops, uint32_t max_nodes,
                      size_t max_bytes)
{
  uint8_t ns[3][64], key[64], full[128];
  size_t nsl[3];
  set_t ref = {0}, act = {0};
  long n_ins = 0, n_noop = 0, n_lk = 0, n_hit = 0, n_purge = 0, n_evict_ops = 0;
  radix_trie_t *t;
  char name[160];

  snprintf(name, sizeof(name),
           "model: seed %llu, unit %zu, %d ops, max_nodes %u, max_bytes %zu",
           (unsigned long long)seed, unit, nops, max_nodes, max_bytes);
  case_begin(name);
  rng_state = seed;
  t = mk(max_nodes, max_bytes, 0);
  CHECK(t != NULL);
  CHECK(mk_ns(ns[0], 64, &nsl[0], "model", "t1") == 0);
  CHECK(mk_ns(ns[1], 64, &nsl[1], "model", "t2") == 0);
  CHECK(mk_ns(ns[2], 64, &nsl[2], "model2", "t1") == 0);
  if (!t || !nsl[0] || !nsl[1] || !nsl[2]) {
    radix_trie_free(t);
    case_end();
    return;
  }
  for (int op = 0; op < nops && g_case_fail < 6; op++) {
    uint32_t now = 1 + (uint32_t)(op / 50);
    int which = (int)(rnd() % 3);
    size_t kl = gen_key(key, unit);
    uint64_t r = rnd() % 100;

    if (r < 55) {
      unsigned ep = (unsigned)(rnd() % 8 == 0 ? rnd() % 32 : rnd() % 6);
      ref_res_t p = ref_lookup(&ref, ns[which], nsl[which], key, kl, 1, BIT(ep));
      int expect_noop = p.rc == RADIX_LOOKUP_HIT && p.matched == kl;
      uint64_t ev0 = t->evicted;
      radix_insert_rc_t rc = ins(t, ns[which], nsl[which], key, kl, ep, now);

      n_ins++;
      memcpy(full, ns[which], nsl[which]);
      memcpy(full + nsl[which], key, kl);
      CHECK(rc == (expect_noop ? RADIX_INSERT_NOOP : RADIX_INSERT_OK));
      collect(t, &act);
      if (rc == RADIX_INSERT_NOOP) {
        n_noop++;
        CHECK(set_equal(&act, &ref));
      } else {
        ent_t *e = set_find(&ref, full, nsl[which] + kl);
        if (e)
          e->mask |= BIT(ep);
        else
          set_add(&ref, full, nsl[which] + kl, BIT(ep));
        /* survivors keep their exact masks; the new key is never evicted */
        for (size_t i = 0; i < act.n; i++) {
          ent_t *w = set_find(&ref, act.e[i].b, act.e[i].len);
          CHECK(w && w->mask == act.e[i].mask);
        }
        e = set_find(&act, full, nsl[which] + kl);
        CHECK(e && (e->mask & BIT(ep)));
        if (t->evicted != ev0)
          n_evict_ops++;
        set_clear(&ref);
        for (size_t i = 0; i < act.n; i++)
          set_add(&ref, act.e[i].b, act.e[i].len, act.e[i].mask);
      }
      CHECK(within_caps(t));
    } else if (r < 95) {
      uint32_t el = (uint32_t)(rnd() % 4 == 0 ? ~0u : rnd() % 3 == 0 ? 0 :
                               (uint32_t)rnd() & 0x3F);
      radix_lookup_res_t got;
      ref_res_t want;
      radix_lookup_rc_t rc;

      if (rnd() % 2 && ref.n) {   /* query near a stored key */
        ent_t *e = &ref.e[rnd() % ref.n];
        if (e->len >= nsl[which] && !memcmp(e->b, ns[which], nsl[which]) &&
            e->len - nsl[which] <= sizeof(key)) {
          kl = e->len - nsl[which];
          memcpy(key, e->b + nsl[which], kl);
          if (rnd() % 2 && kl > unit)
            key[kl - 1 - rnd() % unit] ^= 0x01;   /* mismatch inside the last unit */
        }
      }
      rc = lk(t, ns[which], nsl[which], key, kl, unit, el, now, &got);
      want = ref_lookup(&ref, ns[which], nsl[which], key, kl, unit, el);
      n_lk++;
      if (rc == RADIX_LOOKUP_HIT)
        n_hit++;
      CHECK(rc == want.rc);
      CHECK(got.matched_len == want.matched && got.cand_mask == want.cand);
      CHECK(got.full == want.full);
    } else if (r < 98) {
      unsigned ep = (unsigned)(rnd() % 6);
      radix_trie_purge_ep(t, ep);
      n_purge++;
      for (size_t i = 0; i < ref.n; i++)
        ref.e[i].mask &= ~BIT(ep);
      collect(t, &act);
      {
        set_t keep = {0};
        for (size_t i = 0; i < ref.n; i++)
          if (ref.e[i].mask)
            set_add(&keep, ref.e[i].b, ref.e[i].len, ref.e[i].mask);
        CHECK(set_equal(&act, &keep));
        set_free(&ref);
        ref = keep;
      }
    }
    CHECK(check_trie(t, NULL) == 0);
  }
  printf("    seed %llu: %ld inserts (%ld no-op, %ld with eviction), %ld lookups"
         " (%ld hits), %ld purges, final nodes %u\n", (unsigned long long)seed,
         n_ins, n_noop, n_evict_ops, n_lk, n_hit, n_purge, t->nodes);
  CHECK(n_ins > 0 && n_lk > 0 && n_hit > 0);
  set_free(&ref);
  set_free(&act);
  radix_trie_free(t);
  case_end();
}

/* ================= limits ================= */

/* B(X) for every childless node, from one DFS. */
typedef struct { struct radix_node *n; uint64_t bound; } lb_t;
static lb_t lb_arr[1 << 15];
static size_t lb_n;

static void bounds_dfs(struct radix_node *n, uint64_t above)
{
  uint64_t c = 0;
  for (struct radix_node *x = n->first_child; x; x = x->next_sib)
    c++;
  if (!c && lb_n < sizeof(lb_arr) / sizeof(lb_arr[0])) {
    lb_arr[lb_n].n = n;
    lb_arr[lb_n].bound = above;
    lb_n++;
  }
  for (struct radix_node *x = n->first_child; x; x = x->next_sib)
    bounds_dfs(x, above + 2 * c + 1);
}

static int ptr_cmp(const void *a, const void *b)
{
  const void *x = *(void *const *)a, *y = *(void *const *)b;
  return x < y ? -1 : x > y;
}

static void *node_ptrs[1 << 15];
static size_t node_ptr_n;

static void ptrs_dfs(struct radix_node *n)
{
  if (node_ptr_n < sizeof(node_ptrs) / sizeof(node_ptrs[0]))
    node_ptrs[node_ptr_n++] = n;
  for (struct radix_node *x = n->first_child; x; x = x->next_sib)
    ptrs_dfs(x);
}

/* Evict everything one node at a time; check each eviction's work against
 * its own B(X), and that eviction allocates nothing. */
static void evict_all_measured(radix_trie_t *t, const char *shape)
{
  uint32_t n0 = t->nodes, d0;
  uint64_t w_max = 0, b_at_max = 0, b_max = 0, evictions = 0, over = 0;
  walk_t w;
  uint64_t K = t->lim.evict_sample;

  check_trie(t, &w);
  d0 = w.depth_max;
  while (t->n_leaves) {
    uint64_t work = 0;
    long calls0 = fa_calls;
    lb_n = 0;
    bounds_dfs(t->root, 0);
    if (radix_evict_one(t, NULL, &work) != 1) {
      CHECK(0 && "eviction found no candidate while leaves exist");
      break;
    }
    CHECK(fa_calls == calls0);
    evictions++;
    node_ptr_n = 0;
    ptrs_dfs(t->root);
    qsort(node_ptrs, node_ptr_n, sizeof(void *), ptr_cmp);
    {
      int found = 0;
      for (size_t i = 0; i < lb_n; i++) {
        void *p = lb_arr[i].n;
        if (bsearch(&p, node_ptrs, node_ptr_n, sizeof(void *), ptr_cmp))
          continue;
        found++;
        if (work > K + lb_arr[i].bound)
          over++;
        if (K + lb_arr[i].bound > b_max)
          b_max = K + lb_arr[i].bound;
        if (work > w_max) {
          w_max = work;
          b_at_max = K + lb_arr[i].bound;
        }
      }
      CHECK(found == 1);
    }
    if (evictions % 64 == 0)
      CHECK(check_trie(t, NULL) == 0);
  }
  CHECK(over == 0);
  CHECK(check_trie(t, NULL) == 0);
  CHECK(t->nodes == 1);
  CHECK(t->evict_work_max == w_max);
  printf("    %s: N %u, depth %u, %llu evictions; max work %llu (its bound %llu);"
         " largest bound %llu; K + 2N = %llu\n", shape, n0, d0,
         (unsigned long long)evictions, (unsigned long long)w_max,
         (unsigned long long)b_at_max, (unsigned long long)b_max,
         (unsigned long long)(K + 2ull * n0));
}

static void t_evict_shapes(void)
{
  static uint8_t key[4096];
  radix_trie_t *t;

  case_begin("limits: eviction work per evicted node within B(X) on adversarial shapes");

  /* caterpillar: keys s^i x; the deepest leg is oldest and has a unique
   * endpoint, so its eviction recomputes masks up the whole spine */
  t = mk(1 << 14, (size_t)64 << 20, 0);
  CHECK(t != NULL);
  if (t) {
    const int D = 1000;
    for (int i = D - 1; i >= 0; i--) {
      memset(key, 's', (size_t)i);
      key[i] = 'x';
      CHECK(ins(t, NULL, 0, key, (size_t)i + 1, i == D - 1 ? 31 : 0,
                i == D - 1 ? 1 : 2 + (uint32_t)(D - i)) == RADIX_INSERT_OK);
    }
    CHECK(check_trie(t, NULL) == 0);
    if (t->nodes > 1)
      evict_all_measured(t, "caterpillar (1000 legs)");
    radix_trie_free(t);
  }

  /* wide caterpillar: 100 spine levels, 15 legs each */
  t = mk(1 << 14, (size_t)64 << 20, 0);
  CHECK(t != NULL);
  if (t) {
    const int D = 100, W = 15;
    for (int i = D - 1; i >= 0; i--)
      for (int c = 0; c < W; c++) {
        int special = i == D - 1 && c == 0;
        memset(key, 's', (size_t)i);
        key[i] = (uint8_t)('a' + c);
        CHECK(ins(t, NULL, 0, key, (size_t)i + 1,
                  special ? 31 : (unsigned)((i * W + c) % 31),
                  special ? 1 : 2 + (uint32_t)(D - i)) == RADIX_INSERT_OK);
      }
    CHECK(check_trie(t, NULL) == 0);
    if (t->nodes > 1)
      evict_all_measured(t, "wide caterpillar (100 x 15)");
    radix_trie_free(t);
  }

  /* star: full fanout 256 at the root and under one child */
  t = mk(1 << 14, (size_t)64 << 20, 0);
  CHECK(t != NULL);
  if (t) {
    for (int b = 0; b < 256; b++) {
      key[0] = (uint8_t)b;
      memcpy(key + 1, "tail", 4);
      CHECK(ins(t, NULL, 0, key, 5, (unsigned)(b % 32), 2) == RADIX_INSERT_OK);
      key[0] = 'S';
      key[1] = (uint8_t)b;
      CHECK(ins(t, NULL, 0, key, 6, (unsigned)(b % 32), 1) == RADIX_INSERT_OK);
    }
    CHECK(check_trie(t, NULL) == 0);
    if (t->nodes > 1)
      evict_all_measured(t, "star (2 x 256)");
    radix_trie_free(t);
  }

  /* random digest-like keys */
  t = mk(1 << 14, (size_t)64 << 20, 0);
  CHECK(t != NULL);
  if (t) {
    rng_state = 777;
    for (int i = 0; i < 2000; i++) {
      size_t n = 2 + rnd() % 30;
      for (size_t j = 0; j < n; j++) {
        uint64_t v = j < 2 ? rnd() % 4 : rnd() % 64;
        memcpy(key + 8 * j, &v, 8);
      }
      ins(t, NULL, 0, key, 8 * n, (unsigned)(rnd() % 32), (uint32_t)(1 + rnd() % 1000));
    }
    CHECK(check_trie(t, NULL) == 0);
    if (t->nodes > 1)
      evict_all_measured(t, "random digest keys (2000)");
    radix_trie_free(t);
  }
  case_end();
}

static uint32_t pass_through_count(struct radix_node *n, struct radix_node *root)
{
  uint32_t c = 0, k = 0;
  for (struct radix_node *x = n->first_child; x; x = x->next_sib) {
    k++;
    c += pass_through_count(x, root);
  }
  if (n != root && k == 1 && !n->own_mask)
    c++;
  return c;
}

static void t_churn_caps(void)
{
  static uint8_t key[512];
  uint8_t ns[10][32];
  size_t nsl[10];
  uint64_t base[50][16];
  radix_stats_t st;
  uint32_t max_pt = 0;
  size_t max_bytes;
  radix_trie_t *t;

  case_begin("limits: caps after churn, no childless empty node, pass-through nodes counted");
  max_bytes = sizeof(struct radix_trie) + 512 * sizeof(void *) +
              300 * (sizeof(struct radix_node) + 96);
  t = mk(512, max_bytes, 0);
  CHECK(t != NULL);
  for (int i = 0; i < 10; i++) {
    char tn[16];
    snprintf(tn, sizeof(tn), "tenant-%d", i);
    CHECK(mk_ns(ns[i], 32, &nsl[i], "m", tn) == 0);
  }
  if (!t || !nsl[9]) { radix_trie_free(t); case_end(); return; }
  rng_state = 4242;
  for (int i = 0; i < 50; i++)
    for (int j = 0; j < 16; j++)
      base[i][j] = rnd();
  for (int op = 0; op < 20000 && g_case_fail < 6; op++) {
    uint64_t r = rnd() % 100;
    int w = (int)(rnd() % 10);
    size_t n = 16 + rnd() % 48;
    memcpy(key, base[rnd() % 50], 16 * 8);
    for (size_t j = 16; j < n; j++) {
      uint64_t v = rnd() % 1000;
      memcpy(key + 8 * j, &v, 8);
    }
    if (r < 90) {
      radix_insert_rc_t rc = ins(t, ns[w], nsl[w], key, 8 * n,
                                 (unsigned)(rnd() % 32), 1 + (uint32_t)op / 10);
      CHECK(rc == RADIX_INSERT_OK || rc == RADIX_INSERT_NOOP);
    } else if (r < 91) {
      radix_trie_purge_ep(t, (unsigned)(rnd() % 32));
    } else {
      radix_lookup_res_t res;
      lk(t, ns[w], nsl[w], key, 8 * n, 8, ~0u, 1 + (uint32_t)op / 10, &res);
    }
    CHECK(within_caps(t));
    if (op % 16 == 0) {
      uint32_t pt;
      CHECK(check_trie(t, NULL) == 0);
      pt = pass_through_count(t->root, t->root);
      if (pt > max_pt)
        max_pt = pt;
    }
  }
  CHECK(check_trie(t, NULL) == 0);
  radix_trie_stats(t, &st);
  CHECK(st.evicted > 0);
  CHECK(st.evict_work_max <= RADIX_DEFAULT_EVICT_SAMPLE + 3ull * (512 + 2));
  printf("    20000 ops: nodes %u/%u, bytes %zu/%zu, evicted %llu, max eviction"
         " work %llu (K + 3*(max_nodes+2) = %u), pass-through nodes now %u, max seen %u\n",
         st.nodes, 512u, st.bytes, max_bytes, (unsigned long long)st.evicted,
         (unsigned long long)st.evict_work_max, RADIX_DEFAULT_EVICT_SAMPLE + 3 * (512 + 2),
         pass_through_count(t->root, t->root), max_pt);
  radix_trie_free(t);
  case_end();
}

static void t_pass_through(void)
{
  radix_lookup_res_t r;
  uint64_t w;
  radix_trie_t *t = mk(0, 0, 0);

  case_begin("limits: a pass-through node left by eviction counts against the node cap");
  CHECK(t != NULL);
  if (!t) { case_end(); return; }
  CHECK(ins(t, NULL, 0, S("abcX"), 0, 1) == RADIX_INSERT_OK);
  CHECK(ins(t, NULL, 0, S("abcY"), 0, 5) == RADIX_INSERT_OK);
  CHECK(t->nodes == 4);           /* root, abc, X, Y */
  CHECK(radix_evict_one(t, NULL, &w) == 1);   /* abcX is older */
  CHECK(t->nodes == 3);           /* root, abc (pass-through), Y */
  CHECK(pass_through_count(t->root, t->root) == 1);
  CHECK(t->root->first_child && t->root->first_child->ts == 5);  /* last use through it */
  CHECK(lk(t, NULL, 0, S("abcY"), 1, ~0u, 6, &r) == RADIX_LOOKUP_HIT);
  CHECK(r.matched_len == 4 && r.full);
  CHECK(lk(t, NULL, 0, S("abcX"), 1, ~0u, 6, &r) == RADIX_LOOKUP_HIT);
  CHECK(r.matched_len == 3 && !r.full);
  CHECK(radix_evict_one(t, NULL, &w) == 1);   /* Y, then abc cascades */
  CHECK(t->nodes == 1 && t->n_leaves == 0);
  CHECK(check_trie(t, NULL) == 0);
  radix_trie_free(t);
  case_end();
}

static void t_node_cap_small(void)
{
  char k[32];
  radix_lookup_res_t r;
  radix_trie_t *t = mk(8, 0, 0);

  case_begin("limits: node cap 8 under 300 inserts; the key just linked is never evicted");
  CHECK(t != NULL);
  if (!t) { case_end(); return; }
  for (int i = 0; i < 300 && g_case_fail < 6; i++) {
    int n = snprintf(k, sizeof(k), "key-%03d-%d", i % 97, i);
    CHECK(ins(t, NULL, 0, k, (size_t)n, (unsigned)(i % 32), (uint32_t)i + 1) == RADIX_INSERT_OK);
    CHECK(lk(t, NULL, 0, k, (size_t)n, 1, BIT(i % 32), (uint32_t)i + 1, &r) == RADIX_LOOKUP_HIT);
    CHECK(r.full && r.matched_len == (size_t)n);
    CHECK(t->nodes <= 8);
    CHECK(check_trie(t, NULL) == 0);
  }
  radix_trie_free(t);
  case_end();
}

static void t_single_chain(void)
{
  radix_lookup_res_t r;
  radix_trie_t *t = mk(4, 0, 0);

  static const char chain[] = "abcdefghijkl";

  case_begin("limits: nested keys past the node cap: excess at most the chain's node count, cleared by one insert outside the chain");
  CHECK(t != NULL);
  if (!t) { case_end(); return; }
  CHECK(ins(t, NULL, 0, S("a"), 0, 1) == RADIX_INSERT_OK);
  CHECK(ins(t, NULL, 0, S("ab"), 0, 2) == RADIX_INSERT_OK);
  CHECK(ins(t, NULL, 0, S("abc"), 0, 3) == RADIX_INSERT_OK);
  CHECK(t->nodes == 4);
  for (size_t len = 4; len <= 12; len++) {
    /* the chain is exactly the len nested keys: len nodes below the root */
    CHECK(ins(t, NULL, 0, chain, len, 0, (uint32_t)len) == RADIX_INSERT_OK);
    CHECK(t->n_leaves == 1);
    CHECK(t->nodes == 1 + len);
    CHECK(t->nodes - 4 <= len);
    CHECK(check_trie(t, NULL) == 0);
  }
  CHECK(ins(t, NULL, 0, S("z"), 1, 20) == RADIX_INSERT_OK);
  CHECK(t->nodes <= 4);
  CHECK(lk(t, NULL, 0, S("z"), 1, ~0u, 21, &r) == RADIX_LOOKUP_HIT && r.full);
  CHECK(lk(t, NULL, 0, S("ab"), 1, ~0u, 21, &r) == RADIX_LOOKUP_HIT && r.full);
  CHECK(lk(t, NULL, 0, S("abc"), 1, ~0u, 21, &r) == RADIX_LOOKUP_HIT);
  CHECK(r.matched_len == 2);
  CHECK(check_trie(t, NULL) == 0);
  radix_trie_free(t);
  case_end();
}

static void t_purge_large(void)
{
  char k[48];
  radix_lookup_res_t r;
  long calls0;
  radix_trie_t *t = mk(1 << 14, (size_t)64 << 20, 0);

  case_begin("limits: purge of an endpoint owning 600 nodes in one call, no allocation");
  CHECK(t != NULL);
  if (!t) { case_end(); return; }
  for (int i = 0; i < 600; i++) {
    int n = snprintf(k, sizeof(k), "only-five-%04d-tail", i);
    CHECK(ins(t, NULL, 0, k, (size_t)n, 5, 1) == RADIX_INSERT_OK);
  }
  for (int i = 0; i < 100; i++) {
    int n = snprintf(k, sizeof(k), "shared-%04d", i);
    CHECK(ins(t, NULL, 0, k, (size_t)n, 5, 1) == RADIX_INSERT_OK);
    CHECK(ins(t, NULL, 0, k, (size_t)n, 6, 1) == RADIX_INSERT_OK);
  }
  CHECK(t->nodes > 600);
  calls0 = fa_calls;
  radix_trie_purge_ep(t, 5);
  CHECK(fa_calls == calls0);
  CHECK(check_trie(t, NULL) == 0);
  CHECK((t->root->ep_mask & BIT(5)) == 0);
  for (int i = 0; i < 600; i += 37) {
    int n = snprintf(k, sizeof(k), "only-five-%04d-tail", i);
    CHECK(lk(t, NULL, 0, k, (size_t)n, 1, ~0u, 2, &r) == RADIX_LOOKUP_MISS);
  }
  for (int i = 0; i < 100; i += 7) {
    int n = snprintf(k, sizeof(k), "shared-%04d", i);
    CHECK(lk(t, NULL, 0, k, (size_t)n, 1, ~0u, 2, &r) == RADIX_LOOKUP_HIT);
    CHECK(r.full && r.cand_mask == BIT(6));
  }
  {
    set_t s = {0};
    collect(t, &s);
    CHECK(s.n == 100);
    set_free(&s);
  }
  radix_trie_free(t);
  case_end();
}

/* Digest-like key: a shared system part, a document part from a pool, a
 * unique tail; n digests in all. */
static size_t gen_digest_key(uint8_t *key, size_t n)
{
  uint64_t sys = rnd() % 4;          /* one of four system prompts */
  for (size_t j = 0; j < n; j++) {
    uint64_t v = j < 8 ? 1000 + 100 * sys + (uint64_t)j :
                 j < 16 ? 2000 + rnd() % 64 : rnd();
    memcpy(key + 8 * j, &v, 8);
  }
  return 8 * n;
}

static uint64_t evict_bound_per_insert(size_t l)
{
  uint64_t hdr = sizeof(struct radix_node);
  uint64_t by = (2 * hdr + l + hdr) / (hdr + 1);   /* ceil((2h + l) / (h + 1)) */
  return by > 2 ? by : 2;
}

static void evictions_per_insert_run(const char *mode, uint32_t max_nodes, size_t max_bytes)
{
  static uint8_t key[8 * 64];
  uint8_t ns[10][32];
  size_t nsl[10];
  uint64_t worst = 0, worst_bound = 0;
  radix_trie_t *t = mk(max_nodes, max_bytes, 0);

  CHECK(t != NULL);
  for (int i = 0; i < 10; i++) {
    char tn[16];
    snprintf(tn, sizeof(tn), "tenant-%d", i);
    CHECK(mk_ns(ns[i], 32, &nsl[i], "m", tn) == 0);
  }
  if (!t || !nsl[9]) { radix_trie_free(t); return; }
  rng_state = 99;
  for (int op = 0; op < 8000 && g_case_fail < 6; op++) {
    int w = (int)(rnd() % 10);
    size_t kl = gen_digest_key(key, 16 + rnd() % 48);
    uint64_t carry = 0, ev0 = t->evicted, bound;
    radix_insert_rc_t rc;

    if (t->nodes > t->lim.max_nodes)
      carry = t->nodes - t->lim.max_nodes;
    if (t->bytes > t->lim.max_bytes) {
      uint64_t c = (t->bytes - t->lim.max_bytes + sizeof(struct radix_node)) /
                   (sizeof(struct radix_node) + 1);
      if (c > carry)
        carry = c;
    }
    bound = evict_bound_per_insert(nsl[w] + kl) + carry;
    rc = ins(t, ns[w], nsl[w], key, kl, (unsigned)(rnd() % 32), 1 + (uint32_t)op / 10);
    CHECK(rc == RADIX_INSERT_OK || rc == RADIX_INSERT_NOOP);
    CHECK(t->evicted - ev0 <= bound);
    if (t->evicted - ev0 > worst) {
      worst = t->evicted - ev0;
      worst_bound = bound;
    }
    CHECK(within_caps(t));
  }
  CHECK(check_trie(t, NULL) == 0);
  CHECK(t->evicted > 0);
  printf("    %s: max evictions by one insert %llu (bound at that insert %llu;"
         " bound for the largest default key %llu)\n", mode,
         (unsigned long long)worst, (unsigned long long)worst_bound,
         (unsigned long long)evict_bound_per_insert(RADIX_NS_MAX + RADIX_DIGEST_KEY_MAX));
  radix_trie_free(t);
}

static void t_evictions_per_insert(void)
{
  case_begin("limits: evictions caused by one insert within max(2, ceil((2h + L) / (h + 1)))");
  evictions_per_insert_run("node cap binding (max_nodes 64)", 64, 0);
  evictions_per_insert_run("byte cap binding (max_bytes 40 KiB)", 4096,
                           sizeof(struct radix_trie) + 4096 * sizeof(void *) + 40 * 1024);
  case_end();
}

static uint64_t now_ns(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

typedef size_t (*shape_key_fn)(uint8_t *key, int i);

static size_t cat_key(uint8_t *key, int i)        /* caterpillar, 1000 legs */
{
  int d = i % 1000;
  memset(key, 's', (size_t)d);
  key[d] = 'x';
  return (size_t)d + 1;
}

static size_t wide_key(uint8_t *key, int i)       /* 100 levels x 15 legs */
{
  int d = (i / 15) % 100, c = i % 15;
  memset(key, 's', (size_t)d);
  key[d] = (uint8_t)('a' + c);
  return (size_t)d + 1;
}

static size_t star_key(uint8_t *key, int i)       /* fanout 256, twice */
{
  int b = i % 256;
  if ((i / 256) % 2) {
    key[0] = 'S';
    key[1] = (uint8_t)b;
    return 2;
  }
  key[0] = (uint8_t)b;
  memcpy(key + 1, "tail", 4);
  return 5;
}

static size_t rand_key(uint8_t *key, int i)       /* random digest keys */
{
  uint64_t x = 0x9E3779B97F4A7C15ull * (uint64_t)(i + 1);
  size_t n = 2 + x % 30;
  for (size_t j = 0; j < n; j++) {
    x ^= x >> 29; x *= 0xBF58476D1CE4E5B9ull; x ^= x >> 32;
    uint64_t v = j < 2 ? x % 4 : x % 64;
    memcpy(key + 8 * j, &v, 8);
  }
  return 8 * n;
}

static void time_shape(const char *name, shape_key_fn fn, int nkeys)
{
  static uint8_t key[4096];
  uint64_t ins_max = 0, ins_ev_max = 0, lk_max = 0, t0;
  radix_trie_t *t = mk(1 << 14, (size_t)64 << 20, 0);
  radix_lookup_res_t r;

  CHECK(t != NULL);
  if (!t)
    return;
  for (int i = 0; i < nkeys; i++) {
    size_t kl = fn(key, i);
    t0 = now_ns();
    radix_insert_rc_t rc = ins(t, NULL, 0, key, kl, (unsigned)(i % 32), (uint32_t)i + 1);
    t0 = now_ns() - t0;
    CHECK(rc == RADIX_INSERT_OK || rc == RADIX_INSERT_NOOP);
    if (t0 > ins_max) ins_max = t0;
  }
  for (int i = 0; i < nkeys; i++) {
    size_t kl = fn(key, i);
    t0 = now_ns();
    radix_lookup_rc_t rc = lk(t, NULL, 0, key, kl, 1, ~0u, (uint32_t)(nkeys + i), &r);
    t0 = now_ns() - t0;
    CHECK(rc == RADIX_LOOKUP_HIT && r.full);
    if (t0 > lk_max) lk_max = t0;
    key[kl - 1] ^= 0x80;     /* miss in the last byte: deepest walk back */
    t0 = now_ns();
    lk(t, NULL, 0, key, kl, 1, BIT(31), (uint32_t)(nkeys + i), &r);
    t0 = now_ns() - t0;
    if (t0 > lk_max) lk_max = t0;
  }
  /* bind the byte cap at the current size: every new key now evicts */
  t->lim.max_bytes = t->bytes;
  for (int i = 0; i < 300; i++) {
    size_t kl = fn(key, nkeys + 7 * i);
    key[kl - 1] ^= 0x40;
    t0 = now_ns();
    radix_insert_rc_t rc = ins(t, NULL, 0, key, kl, 31, (uint32_t)(3 * nkeys + i));
    t0 = now_ns() - t0;
    CHECK(rc == RADIX_INSERT_OK || rc == RADIX_INSERT_NOOP);
    if (t0 > ins_ev_max) ins_ev_max = t0;
  }
  CHECK(check_trie(t, NULL) == 0);
  CHECK(within_caps(t));
#ifdef RADIX_TEST_BENCH
  printf("    %s: worst insert %llu ns, worst insert with eviction %llu ns,"
         " worst lookup %llu ns (N %u)\n", name, (unsigned long long)ins_max,
         (unsigned long long)ins_ev_max, (unsigned long long)lk_max, t->nodes);
#else
  (void)name;
#endif
  radix_trie_free(t);
}

static void t_timing(void)
{
  case_begin("timing: worst single insert and lookup on the adversarial shapes");
  time_shape("caterpillar (1000 legs)", cat_key, 1000);
  time_shape("wide caterpillar (100 x 15)", wide_key, 1500);
  time_shape("star (2 x 256)", star_key, 512);
  time_shape("random digest keys (2000)", rand_key, 2000);
  case_end();
}

static void t_default_churn(void)
{
  static uint8_t key[8 * 40];
  uint8_t ns[10][32];
  size_t nsl[10];
  radix_trie_t *t;
#ifdef RADIX_TEST_BENCH
  struct mallinfo2 m0 = mallinfo2(), m1;
#endif

  case_begin("limits: churn at the default limits with 8 KiB-stream digest keys (256 B)");
  t = radix_trie_create(NULL);
  CHECK(t != NULL);
  for (int i = 0; i < 10; i++) {
    char tn[16];
    snprintf(tn, sizeof(tn), "tenant-%d", i);
    CHECK(mk_ns(ns[i], 32, &nsl[i], "model-name", tn) == 0);
  }
  if (!t || !nsl[9]) { radix_trie_free(t); case_end(); return; }
  rng_state = 2026;
  for (int op = 0; op < 30000 && g_case_fail < 6; op++) {
    int w = (int)(rnd() % 10);
    size_t kl = gen_digest_key(key, 8 + rnd() % 25);
    radix_insert_rc_t rc = ins(t, ns[w], nsl[w], key, kl, (unsigned)(rnd() % 32),
                               1 + (uint32_t)op / 20);
    CHECK(rc == RADIX_INSERT_OK || rc == RADIX_INSERT_NOOP);
    CHECK(within_caps(t));
    if (op % 2000 == 0)
      CHECK(check_trie(t, NULL) == 0);
  }
  CHECK(check_trie(t, NULL) == 0);
  CHECK(t->evicted > 0);
  printf("    nodes %u/%u, bytes %zu/%u, evicted %llu, pass-through nodes %u\n",
         t->nodes, RADIX_DEFAULT_MAX_NODES, t->bytes, RADIX_DEFAULT_MAX_BYTES,
         (unsigned long long)t->evicted, pass_through_count(t->root, t->root));
#ifdef RADIX_TEST_BENCH
  m1 = mallinfo2();
  printf("    mallinfo2: in-use heap grew by %zu bytes (uordblks), arena by %zu bytes;"
         " the trie counts %zu bytes\n", m1.uordblks - m0.uordblks,
         m1.arena - m0.arena, t->bytes);
#endif
  radix_trie_free(t);
  case_end();
}

/* ================= allocation failure ================= */

typedef struct { const char *key; unsigned ep; } kv_t;

static radix_trie_t *build(uint32_t max_nodes, const kv_t *pre, int npre)
{
  radix_trie_t *t = mk(max_nodes, 0, 0);
  if (!t)
    return NULL;
  for (int i = 0; i < npre; i++)
    ins(t, NULL, 0, pre[i].key, strlen(pre[i].key), pre[i].ep, (uint32_t)i + 1);
  return t;
}

static void alloc_case(const char *name, uint32_t max_nodes, const kv_t *pre,
                       int npre, const char *key, unsigned ep, int want_allocs)
{
  int allocs = -1;
  char cname[200];
  buf_t d0 = {0}, d1 = {0}, dc = {0};

  snprintf(cname, sizeof(cname), "alloc: %s", name);
  case_begin(cname);
  for (int k = 0; k < 8; k++) {
    radix_trie_t *t = build(max_nodes, pre, npre), *twin;
    long live0;
    radix_insert_rc_t rc;
    radix_lookup_res_t r, before[8];
    radix_lookup_rc_t before_rc[8];

    CHECK(t != NULL);
    if (!t)
      break;
    for (int i = 0; i < npre && i < 8; i++)
      before_rc[i] = lk(t, NULL, 0, pre[i].key, strlen(pre[i].key), 1,
                        BIT(pre[i].ep), 100, &before[i]);
    dump(t, &d0);
    live0 = fa_live;
    fa_fail_at = fa_calls + k;
    rc = ins(t, NULL, 0, key, strlen(key), ep, 100);
    if (fa_fail_at != -1) {     /* fewer than k + 1 allocations */
      fa_fail_at = -1;
      allocs = k;
      CHECK(rc == RADIX_INSERT_OK);
      radix_trie_free(t);
      break;
    }
    CHECK(rc == RADIX_INSERT_NOMEM);
    dump(t, &d1);
    CHECK(same_dump(&d0, &d1));
    CHECK(check_trie(t, NULL) == 0);
    CHECK(fa_live == live0);
    for (int i = 0; i < npre && i < 8; i++) {
      radix_lookup_rc_t lrc = lk(t, NULL, 0, pre[i].key, strlen(pre[i].key), 1,
                                 BIT(pre[i].ep), 100, &r);
      CHECK(lrc == before_rc[i] && r.matched_len == before[i].matched_len &&
            r.cand_mask == before[i].cand_mask && r.full == before[i].full);
    }
    /* a retry without failure gives the same trie as a clean insert */
    CHECK(ins(t, NULL, 0, key, strlen(key), ep, 100) == RADIX_INSERT_OK);
    twin = build(max_nodes, pre, npre);
    CHECK(twin != NULL);
    if (twin) {
      for (int i = 0; i < npre; i++)   /* same timestamps as t's lookups */
        lk(twin, NULL, 0, pre[i].key, strlen(pre[i].key), 1, BIT(pre[i].ep), 100, &r);
      CHECK(ins(twin, NULL, 0, key, strlen(key), ep, 100) == RADIX_INSERT_OK);
      dump(t, &d1);
      dump(twin, &dc);
      CHECK(same_dump(&d1, &dc));
      radix_trie_free(twin);
    }
    radix_trie_free(t);
  }
  CHECK(allocs == want_allocs);
  if (allocs != want_allocs)
    printf("    allocations made by the insert: %d, expected %d\n", allocs, want_allocs);
  free(d0.b);
  free(d1.b);
  free(dc.b);
  case_end();
}

static void t_alloc_create(void)
{
  int k, made = -1;

  case_begin("alloc: create fails cleanly at each allocation");
  for (k = 0; k < 8; k++) {
    long live0 = fa_live;
    radix_trie_t *t;
    fa_fail_at = fa_calls + k;
    t = mk(0, 0, 0);
    if (fa_fail_at != -1) {
      fa_fail_at = -1;
      made = k;
      CHECK(t != NULL);
      radix_trie_free(t);
      break;
    }
    CHECK(t == NULL);
    CHECK(fa_live == live0);
  }
  CHECK(made == 3);
  case_end();
}

static void t_alloc_insert(void)
{
  static const kv_t pre1[] = { { "abcdefgh", 0 } };
  static const kv_t pre2[] = { { "abcdefgh", 0 }, { "abcdXY", 1 }, { "zz", 2 } };
  static const kv_t pre_full[] = { { "k1", 0 }, { "k2", 0 }, { "k3", 0 } };

  alloc_case("new leaf under the root", 0, NULL, 0, "abc", 0, 1);
  alloc_case("split ending on the new key", 0, pre1, 1, "abcd", 1, 1);
  alloc_case("split with a new leaf", 0, pre1, 1, "abcdXY", 1, 2);
  alloc_case("leaf extending an existing leaf", 0, pre1, 1, "abcdefghij", 1, 1);
  alloc_case("split deep in a branched trie", 0, pre2, 3, "abcdefQQ", 3, 2);
  alloc_case("insert into a full trie (eviction follows the links)", 4, pre_full, 3, "k4", 1, 1);
}

/* ================= race ================= */

static pthread_rwlock_t race_lock = PTHREAD_RWLOCK_INITIALIZER;
static pthread_mutex_t gate_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t gate_cv = PTHREAD_COND_INITIALIZER;
static int gate_open, gate_ready;
static radix_trie_t *race_t;
static int race_bad;

static void gate_wait(void)
{
  pthread_mutex_lock(&gate_mu);
  gate_ready++;
  pthread_cond_broadcast(&gate_cv);
  while (!gate_open)
    pthread_cond_wait(&gate_cv, &gate_mu);
  pthread_mutex_unlock(&gate_mu);
}

static void *race_reader(void *arg)
{
  char k[32];
  long id = (long)arg;
  gate_wait();
  for (int i = 0; i < 4000; i++) {
    radix_lookup_res_t r;
    radix_stats_t st;
    int n = snprintf(k, sizeof(k), "hot-prefix-%d", i % 7);
    pthread_rwlock_rdlock(&race_lock);
    radix_lookup_rc_t rc = radix_trie_lookup(race_t, NULL, 0, (uint8_t *)k, (size_t)n,
                                             1, ~0u, (uint32_t)(i / 100 + id), &r);
    radix_trie_stats(race_t, &st);
    pthread_rwlock_unlock(&race_lock);
    if (rc != RADIX_LOOKUP_HIT && rc != RADIX_LOOKUP_MISS)
      __atomic_fetch_add(&race_bad, 1, __ATOMIC_RELAXED);
  }
  return NULL;
}

static void *race_writer(void *arg)
{
  char k[48];
  (void)arg;
  gate_wait();
  for (int i = 0; i < 1500; i++) {
    int n = snprintf(k, sizeof(k), "hot-prefix-%d-turn-%d", i % 7, i);
    pthread_rwlock_wrlock(&race_lock);
    radix_trie_insert(race_t, NULL, 0, (uint8_t *)k, (size_t)n, (unsigned)(i % 32),
                      (uint32_t)(i / 50));
    if (i % 300 == 299)
      radix_trie_purge_ep(race_t, (unsigned)(i % 32));
    pthread_rwlock_unlock(&race_lock);
  }
  return NULL;
}

static void t_race(void)
{
  pthread_t th[3];
  char k[32];

  case_begin("race: lookups under the shared lock, inserts and purges under the exclusive lock");
  race_t = mk(256, 0, 0);
  CHECK(race_t != NULL);
  if (!race_t) { case_end(); return; }
  for (int i = 0; i < 7; i++) {
    int n = snprintf(k, sizeof(k), "hot-prefix-%d", i);
    CHECK(ins(race_t, NULL, 0, k, (size_t)n, (unsigned)i, 0) == RADIX_INSERT_OK);
  }
  gate_open = gate_ready = 0;
  pthread_create(&th[0], NULL, race_reader, (void *)1L);
  pthread_create(&th[1], NULL, race_reader, (void *)2L);
  pthread_create(&th[2], NULL, race_writer, NULL);
  pthread_mutex_lock(&gate_mu);
  while (gate_ready < 3)
    pthread_cond_wait(&gate_cv, &gate_mu);
  gate_open = 1;
  pthread_cond_broadcast(&gate_cv);
  pthread_mutex_unlock(&gate_mu);
  for (int i = 0; i < 3; i++)
    pthread_join(th[i], NULL);
  CHECK(race_bad == 0);
  CHECK(check_trie(race_t, NULL) == 0);
  CHECK(within_caps(race_t));
  radix_trie_free(race_t);
  case_end();
}

int main(void)
{
  setvbuf(stdout, NULL, _IONBF, 0);
  printf("test_radix_trie: node header %zu bytes, trie struct %zu bytes\n",
         sizeof(struct radix_node), sizeof(struct radix_trie));

  t_plan_case();
  t_binary_bytes();
  t_mid_edge();
  t_walk_back();
  t_work_cap();
  t_digest_units();
  t_ns_encoding();
  t_ns_isolation();
  t_noop_insert();
  t_purge_basic();
  t_invalid();
  t_too_large();
  t_recency();

  model_run(1, 1, 6000, 48, 0);
  model_run(2, 1, 6000, 4096, sizeof(struct radix_trie) + 4096 * sizeof(void *) +
                              30 * (sizeof(struct radix_node) + 12));
  model_run(3, 8, 6000, 48, 0);
  model_run(4, 8, 6000, 4096, sizeof(struct radix_trie) + 4096 * sizeof(void *) +
                              30 * (sizeof(struct radix_node) + 40));

  t_evict_shapes();
  t_churn_caps();
  t_pass_through();
  t_node_cap_small();
  t_single_chain();
  t_purge_large();
  t_evictions_per_insert();
  t_default_churn();
  t_timing();

  t_alloc_create();
  t_alloc_insert();

  t_race();

  CHECK(fa_live == 0);
  if (fa_live)
    printf("module allocations leaked: %ld\n", fa_live);
  printf("test_radix_trie: %s (%d failures)\n", g_fail ? "FAIL" : "PASS", g_fail);
  return g_fail ? 1 : 0;
}
