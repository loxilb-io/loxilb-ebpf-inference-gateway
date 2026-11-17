/* SPDX-License-Identifier: BSD-3-Clause */
/* test_pd_trie_safety.c - concurrency and allocation-failure safety of the
 * P/D prefix trie (sockproxy_pd_trie.c, included directly; it is
 * self-contained).
 *
 * race:  pd_trie_match() runs under the read lock (sockproxy_pd.c:2172), so
 *        two lookups of the same key run at once. Both readers pass a start
 *        gate before their loops, so the loops overlap even on a loaded host.
 *        Built with -fsanitize=thread, any unsynchronized access between
 *        them is a ThreadSanitizer report and a non-zero exit.
 *
 * alloc: every allocation an insert makes is failed in turn (no-child leaf,
 *        split ending on the new key, split with a new leaf). After each
 *        failed insert the trie must be exactly as before: same structure
 *        (test-only dump, list order and timestamps included), node_count
 *        equal to the real node count, no allocation leaked, every earlier
 *        key matching as before. A retry without a failure must then give the
 *        same trie as a clean insert.
 *
 * Allocation failures are injected by wrapping malloc/calloc/free around the
 * #include of the trie source only; the product build is unchanged.
 *
 * Build: make test_pd_trie_safety test_pd_trie_safety_tsan
 * Run:   ./test_pd_trie_safety   (ASan + UBSan)
 *        ./test_pd_trie_safety_tsan
 */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- allocation wrappers, active only inside sockproxy_pd_trie.c ---- */

static long fa_live;          /* trie allocations not yet freed */
static long fa_calls;         /* allocation calls made by the trie */
static long fa_fail_at = -1;  /* fail the call with this 0-based index; -1 = never */

static int fa_should_fail(void)
{
  long idx = fa_calls++;
  if (fa_fail_at >= 0 && idx == fa_fail_at) {
    fa_fail_at = -1;
    return 1;
  }
  return 0;
}

static void *fa_malloc(size_t n)
{
  void *p;
  if (fa_should_fail())
    return NULL;
  p = malloc(n);
  if (p)
    fa_live++;
  return p;
}

static void *fa_calloc(size_t n, size_t sz)
{
  void *p;
  if (fa_should_fail())
    return NULL;
  p = calloc(n, sz);
  if (p)
    fa_live++;
  return p;
}

static void fa_free(void *p)
{
  if (p)
    fa_live--;
  free(p);
}

#define malloc(n) fa_malloc(n)
#define calloc(n, sz) fa_calloc(n, sz)
#define free(p) fa_free(p)
#include "sockproxy_pd_trie.c"
#undef malloc
#undef calloc
#undef free

/* ---- race ---- */

#define RACE_ITERS 20000

static const char race_key[] = "syn-shared-prefix-0001";

static pd_trie_t *race_trie;
static pthread_rwlock_t race_lock = PTHREAD_RWLOCK_INITIALIZER;

/* Start gate: no reader starts its loop before both are ready. */
static pthread_mutex_t gate_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t gate_cv = PTHREAD_COND_INITIALIZER;
static int gate_ready;

static void gate_wait(int parties)
{
  pthread_mutex_lock(&gate_mu);
  if (++gate_ready == parties)
    pthread_cond_broadcast(&gate_cv);
  while (gate_ready < parties)
    pthread_cond_wait(&gate_cv, &gate_mu);
  pthread_mutex_unlock(&gate_mu);
}

static void *race_reader(void *arg)
{
  int *hits = arg;
  gate_wait(2);
  for (int i = 0; i < RACE_ITERS; i++) {
    int ep = -1;
    float rate = 0;
    pthread_rwlock_rdlock(&race_lock);
    if (pd_trie_match(race_trie, race_key, sizeof(race_key) - 1, &ep, &rate) == 0 &&
        ep == 3)
      (*hits)++;
    pthread_rwlock_unlock(&race_lock);
  }
  return NULL;
}

static int test_race(void)
{
  pthread_t t[2];
  int hits[2] = {0, 0};

  race_trie = pd_trie_create();
  if (!race_trie)
    return 1;
  pd_trie_insert(race_trie, race_key, sizeof(race_key) - 1, 3);
  gate_ready = 0;
  for (int i = 0; i < 2; i++)
    pthread_create(&t[i], NULL, race_reader, &hits[i]);
  for (int i = 0; i < 2; i++)
    pthread_join(t[i], NULL);
  pd_trie_free(race_trie);

  if (hits[0] != RACE_ITERS || hits[1] != RACE_ITERS) {
    printf("  [FAIL] race: lookups hit %d and %d of %d\n", hits[0], hits[1], RACE_ITERS);
    return 1;
  }
  printf("  [PASS] race: %d concurrent lookups per reader under the read lock\n",
         RACE_ITERS);
  return 0;
}

/* ---- alloc ---- */

#define DUMP_MAX 8192

typedef struct {
  char buf[DUMP_MAX];
  size_t len;
  int bad_links;   /* parent/parent_key/entry key inconsistencies */
} dump_t;

/* Append to the dump; output past the buffer is dropped (len stays bounded). */
static void dump_add(dump_t *d, int w)
{
  if (w > 0)
    d->len += (size_t)w < DUMP_MAX - 1 - d->len ? (size_t)w : DUMP_MAX - 1 - d->len;
}

/* Depth-first, children in list order. with_ts=0 leaves out access_ts. */
static void dump_node(dump_t *d, const pd_trie_node_t *n, int depth, int with_ts)
{
  dump_add(d, snprintf(d->buf + d->len, DUMP_MAX - d->len, "%d|%zu:%.*s|ep=%d",
                       depth, n->label_len, (int)n->label_len, n->label, n->ep_idx));
  if (with_ts)
    dump_add(d, snprintf(d->buf + d->len, DUMP_MAX - d->len, "|ts=%llu",
                         (unsigned long long)n->access_ts));
  if (d->len < DUMP_MAX - 1)
    d->buf[d->len++] = '\n';
  for (const pd_trie_child_t *c = n->children; c; c = c->next) {
    const pd_trie_node_t *ch = c->node;
    if (ch->parent != n || ch->parent_key != c->key || ch->label_len == 0 ||
        (unsigned char)ch->label[0] != c->key)
      d->bad_links++;
    dump_node(d, ch, depth + 1, with_ts);
  }
}

static void dump_trie(dump_t *d, const pd_trie_t *t, int with_ts)
{
  memset(d, 0, sizeof(*d));
  dump_node(d, t->root, 0, with_ts);
}

static size_t real_count(const pd_trie_node_t *n)
{
  size_t k = 1;
  for (const pd_trie_child_t *c = n->children; c; c = c->next)
    k += real_count(c->node);
  return k;
}

typedef struct {
  const char *key;
  int ep;
} kv_t;

/* Existing keys: one node with a two-key subtree, so a split under it has a
 * subtree to lose, and an unrelated branch. */
static const kv_t base_keys[] = {
  { "syn-p-aaa", 1 },
  { "syn-p-aaa-x", 2 },
  { "syn-p-aaa-y", 3 },
  { "zz-other", 4 },
};
#define N_BASE (sizeof(base_keys) / sizeof(base_keys[0]))

static const struct {
  const char *name;
  kv_t ins;
} alloc_cases[] = {
  { "no-child leaf at root",        { "q-new", 5 } },
  { "no-child leaf under a node",   { "syn-p-aaa-z", 6 } },
  { "split ending on the new key",  { "syn-p", 7 } },
  { "split with a new leaf",        { "syn-p-b", 8 } },
};
#define N_ALLOC_CASES (sizeof(alloc_cases) / sizeof(alloc_cases[0]))

typedef struct {
  int rc, ep;
  float rate;
} match_t;

static pd_trie_t *build_base(void)
{
  pd_trie_t *t = pd_trie_create();
  for (size_t i = 0; t && i < N_BASE; i++)
    pd_trie_insert(t, base_keys[i].key, strlen(base_keys[i].key), base_keys[i].ep);
  return t;
}

static void match_all(pd_trie_t *t, match_t out[N_BASE])
{
  for (size_t i = 0; i < N_BASE; i++) {
    out[i].ep = -1;
    out[i].rate = 0;
    out[i].rc = pd_trie_match(t, base_keys[i].key, strlen(base_keys[i].key),
                              &out[i].ep, &out[i].rate);
  }
}

static int test_alloc_case(size_t ci)
{
  const kv_t *ins = &alloc_cases[ci].ins;
  size_t ins_len = strlen(ins->key);
  int failures = 0;
  long n_allocs;
  static dump_t want_retry, before, after, retry;

  /* Allocations a successful insert makes, and the trie it produces. */
  fa_live = 0;
  pd_trie_t *ref = build_base();
  long calls0 = fa_calls;
  pd_trie_insert(ref, ins->key, ins_len, ins->ep);
  n_allocs = fa_calls - calls0;
  dump_trie(&want_retry, ref, 0);
  pd_trie_free(ref);

  for (long k = 0; k < n_allocs; k++) {
    match_t m_before[N_BASE], m_after[N_BASE];
    char why[256] = "";

    fa_live = 0;
    pd_trie_t *t = build_base();
    long live_before = fa_live;
    match_all(t, m_before);
    dump_trie(&before, t, 1);

    fa_fail_at = fa_calls + k;
    pd_trie_insert(t, ins->key, ins_len, ins->ep);
    if (fa_fail_at != -1) {
      fa_fail_at = -1;
      strcat(why, "; injected failure not reached");
    }

    dump_trie(&after, t, 1);
    match_all(t, m_after);
    size_t nc = t->node_count, nreal = real_count(t->root);
    long live_delta = fa_live - live_before;
    if (live_delta != 0)
      strcat(why, "; live allocations changed");
    if (nc != nreal)
      strcat(why, "; node_count != real count");
    if (after.bad_links || before.len != after.len ||
        memcmp(before.buf, after.buf, before.len) != 0)
      strcat(why, "; structure changed");
    if (memcmp(m_before, m_after, sizeof(m_before)) != 0)
      strcat(why, "; an earlier key matches differently");

    /* Retry without a failure: same trie as a clean insert. */
    if (!why[0]) {
      pd_trie_insert(t, ins->key, ins_len, ins->ep);
      dump_trie(&retry, t, 0);
      if (retry.bad_links || retry.len != want_retry.len ||
          memcmp(retry.buf, want_retry.buf, retry.len) != 0)
        strcat(why, "; retry differs from a clean insert");
    }

    pd_trie_free(t);
    if (!why[0] && fa_live != 0)
      strcat(why, "; allocations leaked after free");

    if (why[0]) {
      printf("  [FAIL] alloc: %s, allocation %ld of %ld fails: %s "
             "(node_count %zu, real %zu, live allocations %+ld)\n",
             alloc_cases[ci].name, k + 1, n_allocs, why + 2, nc, nreal, live_delta);
      failures++;
    } else {
      printf("  [PASS] alloc: %s, allocation %ld of %ld fails\n",
             alloc_cases[ci].name, k + 1, n_allocs);
    }
  }
  return failures;
}

static int test_alloc(void)
{
  int failures = 0;
  for (size_t ci = 0; ci < N_ALLOC_CASES; ci++)
    failures += test_alloc_case(ci);
  return failures;
}

int main(void)
{
  /* Unbuffered: a sanitizer report ends the process with _exit(). */
  setvbuf(stdout, NULL, _IONBF, 0);
  int failures = test_race();
  failures += test_alloc();
  printf("test_pd_trie_safety: %s (%d failures)\n", failures ? "FAIL" : "PASS", failures);
  return failures ? 1 : 0;
}
