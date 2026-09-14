/* test_conv_pool_alias.c - conversation stickiness must not cross model pools.
 *
 * conv_map is one table per VIP:port keyed by conv_id ALONE, but a stored
 * ep_idx indexes ONE pool's eps[]. Every pool on a service starts its index
 * space at 0, so without a pool identity beside the index two model pools on
 * one VIP collide on a single row: one consumes the other's binding (and so
 * never stores its own) or overwrites it. The model served stays correct -
 * the index is always applied to the request's own resolved pool - but the
 * conversation loses its endpoint affinity, and is_endpoint_healthy() cannot
 * catch it because an in-range index naming a live endpoint passes.
 *
 * Build: cc -Wall -Wextra -Werror -o test_conv_pool_alias test_conv_pool_alias.c -I.
 *
 * Built TWICE (see the Makefile): once standalone, once with
 * -DMAX_CONV_ID_LEN so the header is exercised in both include orders. The
 * key-size assertions below must hold identically in both, because
 * conversation_mapping_t embeds a CONV_POOL_KEY_MAX array and a value that
 * moved with include order would give that struct two layouts.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "sockproxy_conv_pool.h"

/* The exposing topology, verbatim from the cicd ai-jwtauth rules: two model
 * pools on ONE VIP:port, both endpoint lists starting at index 0. */
#define POOL_A_KEY "inference.example||llama-70b"
#define POOL_B_KEY "inference.example||mistral-7b"

/* What the conv table stores per row after the fix. */
typedef struct {
  int      ep_idx;
  uint64_t pool_tag;
} row_t;

/* The production decision, in one place: may this row's index be applied to
 * the pool this request resolved to? Mirrors get_conversation_mapping(). */
static int
row_applies_to(const row_t *row, const char *resolved_pool_key)
{
  return conv_pool_tag_matches(row->pool_tag,
                               conv_pool_tag_of_key(resolved_pool_key));
}

static void
test_distinct_pools_get_distinct_tags(void)
{
  uint64_t a = conv_pool_tag_of_key(POOL_A_KEY);
  uint64_t b = conv_pool_tag_of_key(POOL_B_KEY);

  assert(a != b);
  /* Never collides with the reserved "no pool named" value. */
  assert(a != CONV_POOL_TAG_UNKNOWN);
  assert(b != CONV_POOL_TAG_UNKNOWN);
}

static void
test_tag_is_stable_across_a_rule_refresh(void)
{
  /* proxy_add_entry refreshes a pool in place and keeps ephash_key, so a live
   * conversation must survive an endpoint add/remove on its own pool. */
  char key[512];
  snprintf(key, sizeof(key), "%s", POOL_A_KEY);
  assert(conv_pool_tag_of_key(key) == conv_pool_tag_of_key(POOL_A_KEY));
}

/* THE DEFECT. Turn 1 routes on pool A and stores ep_idx=0. Turn 2 carries the
 * same conversation id but resolves to pool B, which indexes a different
 * endpoint list. Pool B must NOT read pool A's row: doing so both borrows an
 * index chosen for another eps[] and suppresses pool B's own store. */
static void
test_index_stored_on_pool_a_is_not_applied_to_pool_b(void)
{
  row_t row = { .ep_idx = 0, .pool_tag = conv_pool_tag_of_key(POOL_A_KEY) };

  assert(row_applies_to(&row, POOL_A_KEY) == 1);   /* same pool: sticky */
  assert(row_applies_to(&row, POOL_B_KEY) == 0);   /* other pool: MISS */
}

/* A row that names no pool can never be applied: it would be the pre-fix
 * bare index again. Fail closed, never wildcard. */
static void
test_untagged_row_never_applies(void)
{
  row_t row = { .ep_idx = 0, .pool_tag = CONV_POOL_TAG_UNKNOWN };

  assert(row_applies_to(&row, POOL_A_KEY) == 0);
  assert(row_applies_to(&row, POOL_B_KEY) == 0);
  /* and an unresolved pool may not pick up a tagged row either */
  row.pool_tag = conv_pool_tag_of_key(POOL_A_KEY);
  assert(conv_pool_tag_matches(row.pool_tag, CONV_POOL_TAG_UNKNOWN) == 0);
  assert(row_applies_to(&row, NULL) == 0);
}

/* The wildcard/back-compat pool carries an empty ephash_key. It is still a
 * real, distinct pool - not "unknown" - so it keeps its own stickiness and
 * still does not alias a model pool. */
static void
test_wildcard_pool_is_a_pool_not_a_wildcard(void)
{
  uint64_t empty = conv_pool_tag_of_key("");
  row_t row = { .ep_idx = 0, .pool_tag = empty };

  assert(empty != CONV_POOL_TAG_UNKNOWN);
  assert(row_applies_to(&row, "") == 1);
  assert(row_applies_to(&row, POOL_A_KEY) == 0);
}

/* The key size may not move with include order. conversation_mapping_t embeds
 * char hkey[CONV_POOL_KEY_MAX]; when the value depended on whether
 * MAX_CONV_ID_LEN had been seen first, a TU that included this header first
 * got 274 and every other TU got 145 - two layouts for one struct, no
 * compiler diagnostic, heap corruption at run time. Compiled in both include
 * orders, so this holds only if the definition is unconditional. */
_Static_assert(CONV_POOL_KEY_MAX == 16 + 1 + 256,
               "CONV_POOL_KEY_MAX must not depend on include order");
_Static_assert(CONV_POOL_ID_MAX == 256,
               "conv ids are bounded by the callers' key buffers");
#ifdef MAX_CONV_ID_LEN
_Static_assert(CONV_POOL_KEY_MAX >= 16 + 1 + MAX_CONV_ID_LEN + 1,
               "conv_map key must hold the pool tag and a full-length conv_id");
#endif

/* Truncating the id inside the key is not a lost suffix, it is a MERGE: two
 * conversations that agree in a long prefix land on ONE row and share a single
 * endpoint binding. Reachable with session_header_name="authorization", where
 * the key is "custom_authorization_Bearer <jwt>" and two tokens share a long
 * prefix. The ids here are the longest the callers can build. */
static void
test_long_ids_that_share_a_prefix_keep_separate_rows(void)
{
  char id_a[CONV_POOL_ID_MAX], id_b[CONV_POOL_ID_MAX];
  char key_a[CONV_POOL_KEY_MAX], key_b[CONV_POOL_KEY_MAX];
  uint64_t tag = conv_pool_tag_of_key(POOL_A_KEY);
  static const char prefix[] =
    "custom_authorization_Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.";

  memset(id_a, 'x', sizeof(id_a));
  memcpy(id_a, prefix, sizeof(prefix) - 1);   /* no NUL: the fill stays */
  id_a[sizeof(id_a) - 1] = '\0';
  memcpy(id_b, id_a, sizeof(id_b));
  id_a[200] = 'A';                            /* the two tokens diverge late */
  id_b[200] = 'B';

  /* Guard the oracle: the inputs must really differ, and really be long. */
  assert(strlen(id_a) == CONV_POOL_ID_MAX - 1);
  assert(strcmp(id_a, id_b) != 0);

  conv_pool_make_key(key_a, sizeof(key_a), tag, id_a);
  conv_pool_make_key(key_b, sizeof(key_b), tag, id_b);

  /* Distinct conversations, distinct rows. */
  assert(strcmp(key_a, key_b) != 0);
  /* And nothing was dropped on the way in. */
  assert(strcmp(key_a + 17, id_a) == 0);
  assert(strlen(key_a) == 16 + 1 + strlen(id_a));
}

/* Two pools and one conversation id still differ, at full id length: the pool
 * tag is fixed-width hex before a ':' that cannot appear in it, so no
 * (pool, id) pair can spell another pair's key. */
static void
test_full_length_id_still_separates_pools(void)
{
  char id[CONV_POOL_ID_MAX];
  char key_a[CONV_POOL_KEY_MAX], key_b[CONV_POOL_KEY_MAX];

  memset(id, 'z', sizeof(id));
  id[sizeof(id) - 1] = '\0';

  conv_pool_make_key(key_a, sizeof(key_a), conv_pool_tag_of_key(POOL_A_KEY), id);
  conv_pool_make_key(key_b, sizeof(key_b), conv_pool_tag_of_key(POOL_B_KEY), id);

  assert(strcmp(key_a, key_b) != 0);
  assert(strcmp(key_a + 17, key_b + 17) == 0);   /* same id, different tag */
}

int
main(void)
{
  test_distinct_pools_get_distinct_tags();
  test_tag_is_stable_across_a_rule_refresh();
  test_index_stored_on_pool_a_is_not_applied_to_pool_b();
  test_untagged_row_never_applies();
  test_wildcard_pool_is_a_pool_not_a_wildcard();
  test_long_ids_that_share_a_prefix_keep_separate_rows();
  test_full_length_id_still_separates_pools();
  /* Name the include order: the two legs of this test differ ONLY in it,
   * so an indistinguishable banner would hide one leg not having run. */
#ifdef MAX_CONV_ID_LEN
  puts("test_conv_pool_alias [via sockproxy.h]: ALL PASS");
#else
  puts("test_conv_pool_alias [standalone]: ALL PASS");
#endif
  return 0;
}
