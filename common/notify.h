/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */
#ifndef __NOTIFY_H__
#define __NOTIFY_H__

#include <stdint.h>

typedef enum {
  NOTI_TYPE_IN     = 0x1 << 0,
  NOTI_TYPE_HUP    = 0x1 << 1,
  NOTI_TYPE_OUT    = 0x1 << 2,
  NOTI_TYPE_ERROR  = 0x1 << 3,
  NOTI_TYPE_SHUT   = 0x1 << 4,
} notify_type_t;

typedef struct notify_cbs {
  /* D2 root fix (pfe pool + generation): `gen` is the generation stamp captured
   * for `priv` when its fd was registered (notify_add_ent). The callback compares
   * it against the pfe's CURRENT generation and drops the event if they differ
   * (the pfe slot was recycled since this event was queued). `gen` is opaque to
   * the notifier core — it only shuttles it from add-time to dispatch-time. */
  int (*notify)(int fd, notify_type_t type, void *priv, uint64_t gen);
  void (*pdestroy)(void *priv);
  /* (R1, bounded admission resume): invoked ON THE OWNER WORKER when a
   * parked client fd is woken (notify_wake_worker). The callback re-arms EPOLLIN and
   * re-drives setup_proxy_path for `fd` on its own thread (never cross-thread — the
   * Phase-89/90 UAF invariant). NULL when the admission layer is not wired. The fd
   * is the parked client fd queued by the slot-freeing thread. */
  void (*resume)(int fd);
} notify_cbs_t ;

int notify_check_slot(void *ctx, int fd);
int notify_delete_ent(void *ctx, int fd, int evict);
/* (conc=128 single-owner teardown): remove a fd's poll/earr entry
 * WITHOUT invoking cbs.pdestroy. Unlike notify_delete_ent(evict=0), it never
 * cascades into proxy_pdestroy — the caller owns closing the fd and freeing the
 * pfe exactly once. Used by the reaper's pd_teardown_conn(). */
int notify_deregister_ent(void *ctx, int fd);
/* D2 root fix: `gen` is the pfe's generation stamp at registration time; it is
 * stored on the notify entry and handed back to cbs.notify at dispatch so the
 * callback can detect a recycled-slot stale event. Pass 0 for non-pooled priv. */
int notify_add_ent(void *ctx, int fd, notify_type_t type, void *priv, uint64_t gen);
/* Option A: like notify_add_ent but pins fd to pin_fd's notify worker. */
int notify_add_ent_pinned(void *ctx, int fd, notify_type_t type, void *priv, uint64_t gen, int pin_fd);
/* (R1): which notify worker owns `fd` (its `fd % n_thrs` shard, or the
 * pinned thr_id if registered). Returns -1 if ctx invalid. Lets the slot-freeing
 * thread route a parked fd's resume to its OWNER worker (never re-dispatch off-owner). */
int notify_owner_thr(void *ctx, int fd);
/* (R1): the registered priv (pfe) for `fd` + its registration gen, read
 * under NOTI_LOCK. NULL if fd not registered. Lets the owner-worker resume callback
 * recover the parked pfe from the fd handed to it. */
void *notify_priv_of_fd(void *ctx, int fd, uint64_t *gen_out);
/* (R1): enqueue `fd` onto worker `thr_id`'s MPSC resume-pending queue and
 * wake that worker (eventfd). The worker drains the queue in notify_run and invokes
 * cbs.resume(fd) on its own thread. Returns 0 on success, <0 on error (bad thr_id,
 * queue full, or wake-fd write failure). MPSC-safe: any thread may call it. */
int notify_wake_worker(void *ctx, int thr_id, int fd);
int notify_start(void *ctx);
void *notify_ctx_new(notify_cbs_t *cbs, int n_thrs);

#endif
