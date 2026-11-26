/*
 * Copyright (c) 2026 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */
#ifndef __SOCKPROXY_POOL_H__
#define __SOCKPROXY_POOL_H__

/*
 * The lifetime of a pool (proxy_epval_t).
 *
 * A pool is counted: one reference for the listener's table while it is
 * linked, one for each holder. The holders are the fields that keep a pool
 * past one loop iteration of a notify worker: a connection's epv and
 * learn_epv, an HTTP/2 backend session's epv, a capacity permit's fc (it
 * points into the pool), and a thread other than a notify worker that uses a
 * pool after dropping the proxy lock. A holder takes its reference when it
 * is set and gives it back when it is cleared or overwritten.
 *
 * Taking a reference cannot fail. It is legal on a pool the caller already
 * holds, on a pool the caller found in the index during its current loop
 * iteration (a notify worker), and on a pool found linked under the proxy
 * lock (any other thread). A deleted pool's table reference is given back
 * only after a grace period (sockproxy_qsbr.h), so a worker that found it
 * before the unlink still counts from at least one.
 *
 * The last release frees the pool after a grace period, on the reclaimer,
 * under the proxy lock (the finalizer takes it), so that a thread reading a
 * holder's pointer under the lock cannot see it go.
 *
 * The count lives in a header in front of the pool, outside proxy_epval_t.
 *
 * Notify workers read a listener's pools without a lock, through its
 * published index: an immutable snapshot rebuilt under the write lock after
 * every change to the listener's table and freed after a grace period. The
 * table itself (uthash ephash) is read and written only under the lock.
 */

#include <stdint.h>

#include "sockproxy_qsbr.h"

struct proxy_epval;
struct proxy_map_ent;
struct fc_state;

typedef struct sp_pool_index {
  uint32_t n;                          /* pools, in the table's insertion order */
  uint32_t mask;                       /* key slots - 1 (a power of two) */
  uint32_t n_wildcard;                 /* pools whose host is "*.<suffix>" */
  struct proxy_epval *first;           /* the table's head: order[0] */
  struct proxy_epval **order;
  struct sp_pool_index_slot {
    uint32_t h;
    struct proxy_epval *ep;
  } *slot;
  sp_qsbr_work_t work;
} sp_pool_index_t;

/* A new pool with one reference, the table's. NULL when out of memory. */
struct proxy_epval *sp_pool_alloc(void);

/* A pool that was never linked (an add that failed before the table took
 * it): no reader can have it, so it goes now. */
void sp_pool_discard(struct proxy_epval *p);

/* NULL is accepted and ignored. */
void sp_pool_get(struct proxy_epval *p);
void sp_pool_put(struct proxy_epval *p);

/* Point a holder field at p: a reference on p, the old pool's given back.
 * Nothing when the field already points at p. p NULL clears the field. */
void sp_pool_hold(void **holder, struct proxy_epval *p);

/* A holder slot read by a thread that does not own it (the drain checker,
 * under PROXY_LOCK): one relaxed load, and only that value is used. The
 * owner stores the slot through sp_pool_hold. */
static inline struct proxy_epval *
sp_pool_holder_peek(void *const *holder)
{
  return (struct proxy_epval *)__atomic_load_n(holder, __ATOMIC_RELAXED);
}

/* What a connection's shell gives back when it is recycled: its epv, its
 * learn_epv and its capacity permit's pool. */
struct proxy_fd_ent;
void sp_pool_release_conn(struct proxy_fd_ent *pfe);

/* The pool was taken out of its listener's table and a new index without it
 * published, or was never in an index: the table's reference is given back
 * after a grace period. */
void sp_pool_unlinked(struct proxy_epval *p);

/* Once at start, before the notify workers: fn is what the last release
 * runs before the memory goes, on the reclaimer and with no lock held (the
 * product takes the proxy lock in it and tears down what the pool owns; NULL
 * in a test with nothing to tear down). */
void sp_pool_init(void (*fn)(struct proxy_epval *p));

/* A capacity permit points into its pool (&pool->fc) and holds it: the
 * owner hooks of sockproxy_fc.h, installed with fc_set_owner_hooks. */
void sp_pool_fc_hold(struct fc_state *fc);
void sp_pool_fc_drop(struct fc_state *fc);

uint32_t sp_pool_refs(const struct proxy_epval *p);
/* Pools allocated and not yet freed (deleted ones still held included), and
 * pools freed since start. */
void sp_pool_counts(uint64_t *live, uint64_t *freed);

/* Rebuild and publish the listener's index from its table. Under the proxy
 * write lock. -1 when out of memory: the old index stays published. A
 * published index also lets go of the pools waiting on the listener
 * (sp_pool_unlink). */
int sp_pool_index_publish(struct proxy_map_ent *ent);

/* Put p in the listener's table and publish an index with it. Under the
 * proxy write lock. -1 when the index cannot be built: p is taken out of the
 * table again, so the table and the readers' index agree, and p is the
 * caller's (no reader has seen it). */
int sp_pool_link(struct proxy_map_ent *ent, struct proxy_epval *p);

/* Take p out of the listener's table and publish an index without it; the
 * table's reference goes after a grace period. Under the proxy write lock.
 * -1 when the index cannot be built: readers still find p through the old
 * index, so p waits on the listener until the next index is published. */
int sp_pool_unlink(struct proxy_map_ent *ent, struct proxy_epval *p);

/* Reader side: the published index (NULL when the listener has no pool). */
const sp_pool_index_t *sp_pool_index(const struct proxy_map_ent *ent);
struct proxy_epval *sp_pool_index_find(const sp_pool_index_t *ix, const char *key);
/* The listener's first pool, and the pool of a key; NULL when none. */
struct proxy_epval *sp_pool_first(const struct proxy_map_ent *ent);
struct proxy_epval *sp_pool_find(const struct proxy_map_ent *ent, const char *key);

#endif
