/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_pfe_clear.c - preparing a pooled connection shell for reuse.
 *
 * A shell is never returned to the heap; it is recycled through a freelist and
 * cleared for its next user. The clear deliberately skips the transfer-params
 * buffer, which is three quarters of the shell and is written only on the
 * disaggregated prefill/decode path. This unit pins both halves of that:
 *
 *   - everything outside the skipped span is zeroed, so no field carries over;
 *   - the skipped span is NOT zeroed, so the saving is real and a clear that
 *     quietly went back to covering the whole shell is caught here;
 *   - the length that bounds every read of the buffer lies outside the span
 *     and is therefore zeroed, so bytes left behind stay unreachable;
 *   - the generation counter lies inside the cleared region, which is why the
 *     caller saves and restores it around the clear;
 *   - a second pass over a shell whose previous user filled the buffer leaves
 *     that user's bytes unreadable through the (buffer, length) pair every
 *     reader uses.
 *
 * Build (wired into `make test_pfec`):
 *   gcc -Wall -Wextra -o test_pfe_clear test_pfe_clear.c -I. ...
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "uthash.h"
#include "sockproxy_pfe_clear.h"

static int checks, failures;

#define CHECK(cond, ...) do {                                        \
    checks++;                                                        \
    if (cond) {                                                      \
      printf("ok %d - ", checks); printf(__VA_ARGS__); printf("\n"); \
    } else {                                                         \
      failures++;                                                    \
      printf("FAIL %d - ", checks); printf(__VA_ARGS__);             \
      printf("   (%s:%d)\n", __FILE__, __LINE__);                    \
    }                                                                \
  } while (0)

#define FILL 0xA5

/* First byte in [from,to) that is not `want`, or -1. */
static long
first_not(const unsigned char *p, size_t from, size_t to, unsigned char want)
{
  size_t i;
  for (i = from; i < to; i++) {
    if (p[i] != want) {
      return (long)i;
    }
  }
  return -1;
}

static void
test_layout(void)
{
  /* The saving is only worth having if the skipped span really is the bulk of
   * the shell; if the buffer is ever resized or moved this says so out loud
   * instead of the clear silently becoming a plain memset with extra steps. */
  size_t skipped = PFE_SKIP_END - PFE_SKIP_OFF;
  size_t cleared = sizeof(proxy_fd_ent_t) - skipped;

  CHECK(skipped == PD_KV_PARAMS_MAX_LEN,
        "the skipped span is exactly the transfer-params buffer (%zu bytes)",
        skipped);
  CHECK(cleared < skipped,
        "the clear touches less than it skips (%zu cleared, %zu skipped)",
        cleared, skipped);
  CHECK(offsetof(proxy_fd_ent_t, pd_kv_params_len) < PFE_SKIP_OFF ||
        offsetof(proxy_fd_ent_t, pd_kv_params_len) >= PFE_SKIP_END,
        "the bounding length lies outside the skipped span");
  CHECK(offsetof(proxy_fd_ent_t, gen) < PFE_SKIP_OFF,
        "the generation counter lies in the cleared region, so the caller "
        "must save and restore it");
}

static void
test_clears_around_the_span(void)
{
  unsigned char *raw = malloc(sizeof(proxy_fd_ent_t));
  proxy_fd_ent_t *pfe = (proxy_fd_ent_t *)raw;
  long bad;

  if (!raw) {
    printf("Bail out! out of memory\n");
    exit(1);
  }
  memset(raw, FILL, sizeof(proxy_fd_ent_t));

  pfe_clear(pfe);

  bad = first_not(raw, 0, PFE_SKIP_OFF, 0x00);
  CHECK(bad < 0, "the run before the skipped span is zeroed (first dirty byte %ld)", bad);

  bad = first_not(raw, PFE_SKIP_END, sizeof(proxy_fd_ent_t), 0x00);
  CHECK(bad < 0, "the run after the skipped span is zeroed (first dirty byte %ld)", bad);

  /* The arm that fails if the clear ever goes back to covering the whole
   * shell: every byte of the buffer must still hold the fill pattern. */
  bad = first_not(raw, PFE_SKIP_OFF, PFE_SKIP_END, FILL);
  CHECK(bad < 0, "the skipped span is left untouched (first cleared byte %ld)", bad);

  CHECK(pfe->pd_kv_params_len == 0,
        "the bounding length is zero after the clear");
  CHECK(pfe->used == 0 && pfe->fd == 0 && pfe->next == NULL && pfe->head == NULL,
        "list and ownership fields are zero after the clear");
  CHECK(pfe->rcvbuf == NULL,
        "the receive-buffer pointer is zero after the clear, so the shell "
        "cannot free or read a buffer it does not own");

  free(raw);
}

static void
test_previous_user_is_unreachable(void)
{
  unsigned char *raw = calloc(1, sizeof(proxy_fd_ent_t));
  proxy_fd_ent_t *pfe = (proxy_fd_ent_t *)raw;
  const char *secret = "{\"block_ids\":[1,2,3]}";
  size_t i, reached;

  if (!raw) {
    printf("Bail out! out of memory\n");
    exit(1);
  }

  /* A connection that used the disaggregated path, as the extract site leaves
   * it: the buffer and the length written together. */
  memcpy(pfe->pd_kv_params, secret, strlen(secret));
  pfe->pd_kv_params_len = strlen(secret);
  pfe->fd = 42;
  atomic_store_explicit(&pfe->gen, 7, memory_order_relaxed);

  pfe_clear(pfe);

  CHECK(pfe->pd_kv_params_len == 0,
        "the next user of the shell sees a length of zero");
  CHECK(memcmp(pfe->pd_kv_params, secret, strlen(secret)) == 0,
        "the bytes themselves are still there -- they are not what makes "
        "this safe");
  CHECK(pfe->fd == 0, "the previous user's descriptor is gone");
  CHECK(atomic_load_explicit(&pfe->gen, memory_order_relaxed) == 0,
        "the generation counter was cleared, so the caller's restore is "
        "load-bearing");

  /* Every reader is handed the pair, never the buffer alone: with the length
   * at zero there is no byte a reader can reach. Counted into one assertion on
   * purpose -- an arm that emitted one per byte would change the size of the
   * assertion set with the outcome, and these are scored per assertion. */
  reached = 0;
  for (i = 0; i < pfe->pd_kv_params_len; i++) {
    reached++;
  }
  CHECK(reached == 0,
        "a reader bounded by the length reaches no bytes (%zu reachable)",
        reached);

  free(raw);
}

int
main(void)
{
  test_layout();
  test_clears_around_the_span();
  test_previous_user_is_unreachable();

  printf("\n1..%d\n", checks);
  if (failures) {
    printf("# %d of %d checks FAILED\n", failures, checks);
    return 1;
  }
  printf("# all %d checks passed\n", checks);
  return 0;
}
