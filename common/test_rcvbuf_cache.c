/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_rcvbuf_cache.c - recycling the per-connection receive buffer.
 *
 * A released buffer is kept for the next leg instead of being unmapped, and
 * when it is handed out again the span its previous user wrote is zeroed --
 * exactly that span, so the saving over a fresh mapping is real. This unit
 * pins both halves and the bounds around them:
 *
 *   - a buffer from an empty cache is allocated and all zero;
 *   - a released buffer comes back to the next caller, zeroed over the span
 *     its user declared, and NOT beyond it -- a cache that quietly zeroed the
 *     whole buffer passes the first check and fails the second;
 *   - the freelist node in the buffer's first bytes is inside the zeroed span
 *     even when the user declared less than its size;
 *   - a buffer used past the dirty bound is freed, not kept;
 *   - no more than `cap` buffers are kept, and cap 0 disables the cache;
 *   - the knob parser: unset keeps the default, "0" disables, a count is a
 *     count, anything else is refused.
 *
 * Build (wired into `make test_rbc`):
 *   gcc -Wall -Wextra -Werror -o test_rcvbuf_cache test_rcvbuf_cache.c -I. -lpthread
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sockproxy_rcvbuf.h"

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

#define SIZE   (256 * 1024)
#define FILL   0xA5

static long
first_not(const uint8_t *p, size_t from, size_t to, uint8_t want)
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
test_knob(void)
{
  size_t cap = 1;

  CHECK(rcvbuf_cache_cap_from_env(NULL, &cap) == RCVBUF_CACHE_CAP_DEFAULT &&
        cap == RCVBUF_CACHE_CAP_DEFAULT, "knob: unset keeps the default cap");
  CHECK(rcvbuf_cache_cap_from_env("", &cap) == RCVBUF_CACHE_CAP_DEFAULT,
        "knob: empty keeps the default cap");
  CHECK(rcvbuf_cache_cap_from_env("0", &cap) == 0 && cap == 0,
        "knob: 0 disables the cache");
  CHECK(rcvbuf_cache_cap_from_env("64", &cap) == 64 && cap == 64,
        "knob: a count is the cap");
  CHECK(rcvbuf_cache_cap_from_env("64k", &cap) < 0 && cap == RCVBUF_CACHE_CAP_DEFAULT,
        "knob: a suffix is refused, default kept");
  CHECK(rcvbuf_cache_cap_from_env("-1", &cap) < 0,
        "knob: a negative count is refused");
}

static void
test_reuse(void)
{
  rcvbuf_cache_t c;
  uint8_t *a, *b;
  const size_t dirty = 1000;

  rcvbuf_cache_init(&c, SIZE, 4, 64 * 1024);

  a = rcvbuf_cache_get(&c);
  CHECK(a != NULL && c.misses == 1 && c.hits == 0, "empty cache: the buffer is allocated");
  CHECK(first_not(a, 0, SIZE, 0) < 0, "empty cache: the buffer is all zero");

  /* The user writes 1,000 bytes and, well beyond them, leaves a mark the
   * cache is not told about: it stands for the pages the user never touched,
   * and must survive so the clear is proven partial. */
  memset(a, FILL, dirty);
  a[SIZE - 1] = FILL;
  rcvbuf_cache_put(&c, a, dirty);
  CHECK(c.count == 1 && c.drops == 0, "release: the buffer is kept");

  b = rcvbuf_cache_get(&c);
  CHECK(b == a && c.hits == 1, "reuse: the same buffer comes back");
  CHECK(first_not(b, 0, dirty, 0) < 0, "reuse: the declared span is zero");
  CHECK(b[SIZE - 1] == FILL, "reuse: beyond the declared span nothing was touched");
  CHECK(first_not(b, dirty, SIZE - 1, 0) < 0, "reuse: and it was zero anyway (untouched)");
  b[SIZE - 1] = 0;

  /* A user that declares less than the freelist node: the node's bytes are
   * still zeroed for the next user. */
  memset(b, FILL, 4);
  rcvbuf_cache_put(&c, b, 1);
  b = rcvbuf_cache_get(&c);
  CHECK(b == a && first_not(b, 0, sizeof(struct rcvbuf_node), 0) < 0,
        "reuse: a span under the node size still clears the node");

  /* The bound on how far a kept buffer was used. */
  rcvbuf_cache_put(&c, b, 64 * 1024 + 1);
  CHECK(c.count == 0 && c.drops == 1, "release: a buffer used past the dirty bound is freed");
  a = rcvbuf_cache_get(&c);
  CHECK(a != NULL && c.misses == 2, "after the drop: the next buffer is allocated");
  rcvbuf_cache_put(&c, a, 64 * 1024);
  CHECK(c.count == 1, "release: a buffer used exactly to the bound is kept");
  free(rcvbuf_cache_get(&c));
}

static void
test_bounds(void)
{
  rcvbuf_cache_t c;
  uint8_t *p[3];
  int i;

  rcvbuf_cache_init(&c, SIZE, 2, 64 * 1024);
  for (i = 0; i < 3; i++) {
    p[i] = rcvbuf_cache_get(&c);
  }
  for (i = 0; i < 3; i++) {
    rcvbuf_cache_put(&c, p[i], 100);
  }
  CHECK(c.count == 2 && c.drops == 1, "cap: the third release is freed, two are kept");
  CHECK(rcvbuf_cache_get(&c) == p[1] && rcvbuf_cache_get(&c) == p[0] && c.count == 0,
        "cap: the kept buffers come back most recent first");
  free(p[0]);
  free(p[1]);

  rcvbuf_cache_init(&c, SIZE, 0, 64 * 1024);
  p[0] = rcvbuf_cache_get(&c);
  CHECK(p[0] != NULL && first_not(p[0], 0, SIZE, 0) < 0, "cap 0: a buffer is allocated");
  rcvbuf_cache_put(&c, p[0], 100);
  CHECK(c.count == 0 && c.drops == 1, "cap 0: a release frees");
  rcvbuf_cache_put(&c, NULL, 0);
  CHECK(c.drops == 1, "release: NULL is ignored");

  rcvbuf_cache_init(&c, SIZE, 2, SIZE * 4);
  CHECK(c.max_dirty == SIZE, "init: the dirty bound is clamped to the buffer size");
}

static void
test_scan(void)
{
  uint8_t buf[64];

  memset(buf, 0, sizeof(buf));
  CHECK(rcvbuf_first_nonzero(buf, 0, sizeof(buf)) < 0, "scan: an all-zero buffer has no offender");
  buf[40] = 1;
  CHECK(rcvbuf_first_nonzero(buf, 8, sizeof(buf)) == 40, "scan: the first non-zero offset is reported");
  CHECK(rcvbuf_first_nonzero(buf, 41, sizeof(buf)) < 0, "scan: from past it, nothing");
}

int
main(void)
{
  test_knob();
  test_reuse();
  test_bounds();
  test_scan();
  printf("%d checks, %d failures\n", checks, failures);
  return failures ? 1 : 0;
}
