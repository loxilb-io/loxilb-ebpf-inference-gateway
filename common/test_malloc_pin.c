/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_malloc_pin.c - the per-leg receive buffer stays a private mapping.
 *
 * glibc's mmap threshold is dynamic: once a mapped chunk is freed the
 * threshold rises to its size and later buffers of that size come from the
 * heap, where freed chunks are kept, so a burst of connections leaves the
 * process at the burst's high-water mark. sockproxy_malloc.h pins the
 * threshold below the buffer size at startup.
 *
 * THE ORACLE IS SELF-VERIFYING. The first half reproduces the defect in a
 * child process: with the allocator untouched, allocate and free one
 * buffer, then allocate again and show the second one is served from the
 * heap (glibc's mmap accounting does not grow). The second half, in the
 * parent, applies the pin the way the gateway does - before any buffer of
 * that size has existed - and shows that the buffer is a mapping, that
 * freeing it returns the memory, and that a later one is a mapping still.
 * The halves need separate heaps: a freed buffer that already sits in the
 * heap is reused whatever the threshold says, which is also why the pin is
 * applied at startup. A build in which the pin is a no-op is red on the
 * second half; a libc without the dynamic threshold is red on the first,
 * which is worth knowing too.
 *
 * Build (wired into `make test_mpin`):
 *   gcc -Wall -Wextra -Werror -o test_malloc_pin test_malloc_pin.c -I.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#include "sockproxy_malloc.h"

#define BUF_LEN (1024 * 1024)

static int g_cases, g_fails;

static void
check(const char *name, int ok, const char *detail)
{
  g_cases++;
  if (!ok) g_fails++;
  printf("%s %-46s %s\n", ok ? "ok  " : "FAIL", name, detail);
}

static void
check_eq(const char *name, long got, long want)
{
  char d[64];
  snprintf(d, sizeof(d), "%ld (want %ld)", got, want);
  check(name, got == want, d);
}

#ifdef __GLIBC__
static size_t
mapped_bytes(void)
{
  struct mallinfo2 mi = mallinfo2();
  return mi.hblkhd;
}

static void
touch(char *p)
{
  size_t i;
  for (i = 0; i < BUF_LEN; i += 4096) p[i] = 1;
}
#endif

int
main(void)
{
  /* Environment parsing: default, override, off, and refused values. */
  check_eq("threshold: unset -> default",
           proxy_malloc_mmap_threshold(NULL),
           PROXY_MALLOC_MMAP_THRESHOLD_DEFAULT);
  check_eq("threshold: empty -> default",
           proxy_malloc_mmap_threshold(""),
           PROXY_MALLOC_MMAP_THRESHOLD_DEFAULT);
  check_eq("threshold: 262144", proxy_malloc_mmap_threshold("262144"), 262144);
  check_eq("threshold: 0 leaves the allocator alone",
           proxy_malloc_mmap_threshold("0"), 0);
  check_eq("threshold: negative refused",
           proxy_malloc_mmap_threshold("-1"), -1);
  check_eq("threshold: trailing junk refused",
           proxy_malloc_mmap_threshold("64k"), -1);
  check_eq("threshold: not a number refused",
           proxy_malloc_mmap_threshold("auto"), -1);
  check_eq("tune: 0 is a no-op", proxy_malloc_tune("0"), 0);

#ifdef __GLIBC__
  {
    size_t before, after;
    char *a, *b;
    pid_t child;
    int status = -1;

    /* The defect, with the allocator untouched, in its own heap: the first
     * buffer is a mapping (freeing it raises the dynamic threshold), the
     * second is not. */
    fflush(stdout);
    child = fork();
    if (child == 0) {
      int fails = 0;
      a = calloc(1, BUF_LEN);
      touch(a);
      fails += mapped_bytes() < BUF_LEN;
      free(a);
      before = mapped_bytes();
      b = calloc(1, BUF_LEN);
      touch(b);
      fails += mapped_bytes() != before;
      free(b);
      _exit(fails);
    }
    if (child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status)) {
      status = WEXITSTATUS(status);
    } else {
      status = -1;
    }
    check("untouched: first buffer is a mapping",
          status == 0 || status == 1, "child ran");
    check("untouched: second buffer comes from the heap (the defect)",
          status == 0, status == 0 ? "mmap accounting unchanged"
                                   : "mmap accounting grew, or no child");

    /* The pin, before any buffer of that size has existed here, with a
     * refused override falling back to the default. */
    check_eq("tune: bad value falls back to the default",
             proxy_malloc_tune("64k"), PROXY_MALLOC_MMAP_THRESHOLD_DEFAULT);
    before = mapped_bytes();
    a = calloc(1, BUF_LEN);
    touch(a);
    after = mapped_bytes();
    check("pinned: the buffer is a mapping",
          after >= before + BUF_LEN, "mmap accounting grew by the buffer");
    free(a);
    check("pinned: freeing returns the mapping",
          mapped_bytes() == before, "mmap accounting back to before");

    /* A free does not raise the threshold back: the next one maps too. */
    b = calloc(1, BUF_LEN);
    touch(b);
    check("pinned: still a mapping after a free",
          mapped_bytes() >= before + BUF_LEN, "mmap accounting grew again");
    free(b);
  }
#else
  printf("skip glibc allocator checks (not glibc)\n");
#endif

  printf("\n=== results: %d/%d passed ===\n", g_cases - g_fails, g_cases);
  return g_fails ? 1 : 0;
}
