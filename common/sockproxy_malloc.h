/*
 * sockproxy_malloc.h - keep the per-leg receive buffers out of the heap.
 *
 * Every relay leg carries a receive buffer of SP_SOCK_MSG_LEN (1 MiB) that
 * lives for the connection and is freed with it. glibc serves a request of
 * that size from mmap() only while it is above its mmap threshold, and that
 * threshold is dynamic: the first time a mapped chunk is freed the threshold
 * grows to that chunk's size, so from the second connection on the buffers
 * come from the heap instead. Freed heap chunks are kept for reuse and the
 * top of the heap is trimmed only when it is contiguous free space, so a
 * burst of connections leaves the process at the burst's high-water mark
 * for the rest of its life: one burst of two thousand connections was
 * measured to leave a gateway near three gigabytes resident, and a
 * one-gigabyte memory limit then kills it on the first such burst.
 *
 * Pinning the threshold below the buffer size keeps every receive buffer a
 * private mapping: it is returned to the kernel on free, so resident memory
 * follows the number of open connections rather than their peak, and the
 * pages arrive zeroed, which is the zero-fill the buffer needs anyway. The
 * default matches glibc's own initial threshold (128 KiB). LLB_MALLOC_MMAP_THRESHOLD
 * overrides it in bytes; 0 leaves the allocator's dynamic behaviour alone.
 */
#ifndef __SOCKPROXY_MALLOC_H__
#define __SOCKPROXY_MALLOC_H__

#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <malloc.h>

#define PROXY_MALLOC_MMAP_THRESHOLD_DEFAULT (128 * 1024)
#define PROXY_MALLOC_MMAP_THRESHOLD_ENV     "LLB_MALLOC_MMAP_THRESHOLD"

/* Resolve the threshold from the environment: -1 on a value that is not a
 * non-negative number, 0 to leave the allocator alone, else the bytes. */
static inline long
proxy_malloc_mmap_threshold(const char *env)
{
  char *end = NULL;
  long v;

  if (env == NULL || *env == '\0') {
    return PROXY_MALLOC_MMAP_THRESHOLD_DEFAULT;
  }
  errno = 0;
  v = strtol(env, &end, 10);
  if (errno != 0 || end == env || *end != '\0' || v < 0 || v > INT_MAX) {
    return -1;
  }
  return v;
}

/* Apply the pin. Returns the threshold in force (0 when left dynamic), or
 * -1 when the allocator refused the value. Setting M_MMAP_THRESHOLD also
 * turns glibc's dynamic adjustment off, which is the point. */
static inline long
proxy_malloc_tune(const char *env)
{
  long thr = proxy_malloc_mmap_threshold(env);

  if (thr < 0) {
    thr = PROXY_MALLOC_MMAP_THRESHOLD_DEFAULT;
  }
  if (thr == 0) {
    return 0;
  }
#ifdef __GLIBC__
  if (mallopt(M_MMAP_THRESHOLD, (int)thr) == 0) {
    return -1;
  }
#endif
  return thr;
}

#endif /* __SOCKPROXY_MALLOC_H__ */
