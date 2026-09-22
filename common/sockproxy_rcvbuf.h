/* SPDX-License-Identifier: BSD-3-Clause
 *
 * sockproxy_rcvbuf.h - recycling the per-connection receive buffer.
 */
#ifndef __SOCKPROXY_RCVBUF_H__
#define __SOCKPROXY_RCVBUF_H__

#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Every connection leg owns a 1 MiB receive buffer for its lifetime. With
 * the allocator pinned so that a buffer of that size is a private mapping,
 * each leg costs an mmap on the way in and an munmap on the way out, and the
 * munmap's TLB flush interrupts every other worker of the process. Under a
 * connection-per-request load that pair is the largest single item in the
 * per-connection CPU cost after the socket work itself.
 *
 * So a released buffer is kept on a bounded freelist and handed to the next
 * leg instead of being unmapped. What makes that safe is that the buffer is
 * returned to the same state a fresh mapping has -- all zero -- over the
 * span the previous user wrote: the caller tells the cache how far into the
 * buffer it got (the connection tracks its own high-water mark), and the
 * cache zeroes exactly that span when the buffer is handed out again. The
 * pages beyond it were never touched, so they are zero already and stay
 * unmapped in practice.
 *
 * Two bounds keep the resident footprint in check. A buffer whose user
 * reached past `max_dirty` goes back to the allocator: the pages it touched
 * are the cost of keeping it, and a large upload is the rare shape. And no
 * more than `cap` buffers are kept; beyond that a release frees as before.
 * The freelist node lives in the first bytes of the free buffer itself, and
 * those bytes lie inside the span that is zeroed on reuse.
 */

#define RCVBUF_CACHE_ENV            "LLB_RCVBUF_CACHE"
#define RCVBUF_CACHE_CAP_DEFAULT    1024
#define RCVBUF_CACHE_MAX_DIRTY      (64 * 1024)

struct rcvbuf_node {
  struct rcvbuf_node *next;
  size_t dirty;               /* bytes to zero before the buffer is reused */
};

typedef struct rcvbuf_cache {
  pthread_mutex_t lock;       /* a leaf: nothing is taken while it is held */
  struct rcvbuf_node *head;
  size_t size;                /* one buffer, bytes */
  size_t cap;                 /* buffers kept at most; 0 disables the cache */
  size_t max_dirty;           /* a buffer used past this is freed instead */
  size_t count;               /* buffers on the list */
  unsigned long hits;         /* handed out from the list */
  unsigned long misses;       /* allocated */
  unsigned long drops;        /* freed on release: over cap or too dirty */
} rcvbuf_cache_t;

/* The knob: unset or empty keeps the default cap, "0" disables the cache,
 * any other non-negative count is the cap. Anything else is refused and the
 * default is used; the caller logs that (a header-only unit cannot). Returns
 * the cap, or -1 when the value was refused (the default is in *cap then). */
static inline long
rcvbuf_cache_cap_from_env(const char *v, size_t *cap)
{
  char *end = NULL;
  unsigned long n;

  *cap = RCVBUF_CACHE_CAP_DEFAULT;
  if (v == NULL || *v == '\0') {
    return (long)*cap;
  }
  errno = 0;
  n = strtoul(v, &end, 10);
  if (errno != 0 || end == v || *end != '\0' || *v == '-' || n > 1000000UL) {
    return -1;
  }
  *cap = (size_t)n;
  return (long)*cap;
}

static inline void
rcvbuf_cache_init(rcvbuf_cache_t *c, size_t size, size_t cap, size_t max_dirty)
{
  memset(c, 0, sizeof(*c));
  pthread_mutex_init(&c->lock, NULL);
  c->size = size;
  c->cap = cap;
  c->max_dirty = max_dirty > size ? size : max_dirty;
}

/* A zeroed buffer of the cache's size, from the list when it has one. */
static inline uint8_t *
rcvbuf_cache_get(rcvbuf_cache_t *c)
{
  struct rcvbuf_node *n;
  size_t dirty;

  pthread_mutex_lock(&c->lock);
  n = c->head;
  if (n) {
    c->head = n->next;
    c->count--;
    c->hits++;
  } else {
    c->misses++;
  }
  pthread_mutex_unlock(&c->lock);

  if (!n) {
    return (uint8_t *)calloc(1, c->size);
  }
  dirty = n->dirty;
  memset(n, 0, dirty);   /* covers the node itself: dirty >= sizeof(*n) */
  return (uint8_t *)n;
}

/* Release a buffer whose user wrote at most the first `dirty` bytes. */
static inline void
rcvbuf_cache_put(rcvbuf_cache_t *c, uint8_t *buf, size_t dirty)
{
  struct rcvbuf_node *n;

  if (!buf) {
    return;
  }
  if (dirty > c->size) {
    dirty = c->size;
  }
  if (c->cap == 0 || dirty > c->max_dirty) {
    pthread_mutex_lock(&c->lock);
    c->drops++;
    pthread_mutex_unlock(&c->lock);
    free(buf);
    return;
  }
  if (dirty < sizeof(*n)) {
    dirty = sizeof(*n);
  }
  n = (struct rcvbuf_node *)buf;
  n->dirty = dirty;

  pthread_mutex_lock(&c->lock);
  if (c->count >= c->cap) {
    c->drops++;
    pthread_mutex_unlock(&c->lock);
    free(buf);
    return;
  }
  n->next = c->head;
  c->head = n;
  c->count++;
  pthread_mutex_unlock(&c->lock);
}

/* First offset in [from, size) holding a non-zero byte, or -1. A debugging
 * aid for the high-water contract: a buffer released with a `dirty` that
 * undercounts the user's writes shows up here. */
static inline long
rcvbuf_first_nonzero(const uint8_t *buf, size_t from, size_t size)
{
  size_t i;

  for (i = from; i < size; i++) {
    if (buf[i] != 0) {
      return (long)i;
    }
  }
  return -1;
}

#endif /* __SOCKPROXY_RCVBUF_H__ */
