/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <fcntl.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <signal.h>
#include <pthread.h>
#include <netdb.h>
#include <poll.h>
#include <ifaddrs.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <linux/tls.h>
#include <linux/tcp.h>
#include "log.h"
#include "notify.h"

#define MAX_NOTIFY_FDS 65535
#define MAX_NOTIFY_POLL_FDS 8192
#define MAX_NOTIFY_THREADS (8)
#define MAX_NOTIFY_POLL_TIMEO (10)

/* (R1): bound on the per-worker resume-pending MPSC ring. A parked conn
 * occupies one slot from wake-enqueue until the owner worker drains it (sub-ms). The
 * ring is sized well above any plausible simultaneous-resume burst (depth-per-EP is
 * <= PD_MAX_QUEUE_DEPTH=64 and resumes are one-per-slot-free); overflow degrades to
 * "the next slot-free re-attempts" (the conn stays parked), never to a wedge. */
#define MAX_NOTIFY_RESUME_PENDING 4096

typedef struct notify_ent {
  int fd;
  notify_type_t type;
  int poll_slot;
  int thr_id;
  void *priv;
  uint64_t gen;   /* D2 root fix: pfe generation stamp at registration time */
} notify_ent_t;

#define NOTI_LOCK(C) pthread_rwlock_wrlock(&(C)->lock)
#define NOTI_UNLOCK(C) pthread_rwlock_unlock(&(C)->lock)

typedef struct notify_thr {
  void *ctx;
  int thrid;
} notify_thr_t;

typedef struct notify_pollfd {
  int evict;
} notify_pollfd_t;

typedef struct notify_poll_ctx {
  int n_pfds;
  notify_pollfd_t npfds[MAX_NOTIFY_POLL_FDS];
  struct pollfd pfds[MAX_NOTIFY_POLL_FDS];

  /* (R1): per-worker wake primitive + resume-pending MPSC ring.
   * wake_fd is an eventfd registered in THIS worker's pfds[] (so poll() returns on
   * a wake). Any thread appends a parked client fd to rq[] under rq_lock and writes
   * wake_fd; the owner worker drains rq[] in notify_run and calls cbs.resume(fd) on
   * its own thread — keeping all dispatch on the owning worker (Phase-89/90 UAF
   * invariant). Default-off: when the admission layer never wakes a worker, wake_fd
   * sits in poll() idle (one extra fd, never readable) — zero relay-path overhead. */
  int wake_fd;                          /* eventfd; -1 until inited */
  pthread_mutex_t rq_lock;              /* guards rq[]/rq_head/rq_tail/rq_count */
  int rq[MAX_NOTIFY_RESUME_PENDING];    /* ring of parked client fds awaiting resume */
  int rq_head, rq_tail, rq_count;
} notify_poll_ctx_t;

typedef struct notify_ctx {
  pthread_rwlock_t lock;
  notify_ent_t earr[MAX_NOTIFY_FDS];
  int n_fds;
  int thr_sel;
  int n_thrs;
  notify_cbs_t cbs;
  notify_poll_ctx_t poll_ctx[MAX_NOTIFY_THREADS];
} notify_ctx_t ;

static short
notify_conv2poll_events(notify_type_t type)
{
  short events = 0;
  if (type & NOTI_TYPE_IN) {
    events |= POLLIN;
  }
  if (type & NOTI_TYPE_OUT) {
    events |= POLLOUT;
  }
  if (type & NOTI_TYPE_HUP) {
    events |= (POLLRDHUP|POLLHUP);
  }
  if (type & NOTI_TYPE_ERROR) {
    events |= POLLERR;
  }
  return events;
}

static notify_type_t
notify_conv4mpoll_events(short events)
{
  notify_type_t type = 0;

  if (events & POLLIN) {
    type |= NOTI_TYPE_IN;
  }
  if (events & POLLOUT) {
    type |= NOTI_TYPE_OUT;
  }
  if (events & (POLLRDHUP|POLLHUP)) {
    type |= NOTI_TYPE_HUP;
  }
  if (events & (POLLERR|POLLNVAL)) {
    type |= NOTI_TYPE_ERROR;
  }

  return type;
}

void *
notify_ctx_new(notify_cbs_t *cbs, int n_thrs)
{
  notify_ctx_t *nc = calloc(1, sizeof(notify_ctx_t));
  assert(nc);

  if (cbs) {
    nc->cbs.notify = cbs->notify;
    nc->cbs.pdestroy = cbs->pdestroy;
    nc->cbs.resume = cbs->resume;   /* (R1): owner-worker resume hook */
  }

  if (n_thrs > MAX_NOTIFY_THREADS) {
    free(nc);
    return NULL;
  }

  nc->n_thrs = n_thrs;

  /* (R1): init each worker's resume-pending ring lock + mark wake_fd
   * uninited. The eventfd itself is created lazily on the worker thread in
   * notify_run (so the fd lives on / is polled by exactly that worker). */
  for (int t = 0; t < MAX_NOTIFY_THREADS; t++) {
    pthread_mutex_init(&nc->poll_ctx[t].rq_lock, NULL);
    nc->poll_ctx[t].wake_fd = -1;
    nc->poll_ctx[t].rq_head = nc->poll_ctx[t].rq_tail = nc->poll_ctx[t].rq_count = 0;
  }

  return nc;
}

/* (R1): the owner worker of `fd` is its `fd % n_thrs` shard unless the
 * fd is already registered with a pinned thr_id (Phase-89 pin). Returns -1 on bad
 * ctx/fd. The slot-freeing thread uses this to route a parked fd's resume. */
int
notify_owner_thr(void *ctx, int fd)
{
  notify_ctx_t *nctx = ctx;
  if (!nctx || fd <= 0 || fd >= MAX_NOTIFY_FDS) {
    return -1;
  }
  int thr;
  NOTI_LOCK(nctx);
  if (nctx->earr[fd].fd > 0) {
    thr = nctx->earr[fd].thr_id;       /* registered (possibly pinned) owner */
  } else {
    thr = (nctx->n_thrs > 0) ? (fd % nctx->n_thrs) : 0;  /* default shard */
  }
  NOTI_UNLOCK(nctx);
  return thr;
}

/* (R1): return the registered priv (pfe) for `fd`, with its captured
 * gen, UNDER NOTI_LOCK — the same provably-live read the dispatcher uses. The owner
 * worker's resume callback uses this to recover the parked pfe from the fd it was
 * handed. *gen_out receives the registration gen (for the caller's staleness check).
 * Returns NULL if fd is not registered. */
void *
notify_priv_of_fd(void *ctx, int fd, uint64_t *gen_out)
{
  notify_ctx_t *nctx = ctx;
  void *priv = NULL;
  if (!nctx || fd <= 0 || fd >= MAX_NOTIFY_FDS) {
    return NULL;
  }
  NOTI_LOCK(nctx);
  if (nctx->earr[fd].fd > 0) {
    priv = nctx->earr[fd].priv;
    if (gen_out) *gen_out = nctx->earr[fd].gen;
  }
  NOTI_UNLOCK(nctx);
  return priv;
}

/* (R1): append `fd` to worker `thr_id`'s resume-pending ring and wake it
 * by writing its eventfd. MPSC-safe (rq_lock). Returns 0 ok, <0 on bad args / ring
 * full / not-yet-inited wake_fd. On ring-full the caller leaves the conn parked; the
 * next slot-free retries — no loss of correctness, only of promptness. */
int
notify_wake_worker(void *ctx, int thr_id, int fd)
{
  notify_ctx_t *nctx = ctx;
  notify_poll_ctx_t *pctx;
  int wfd;

  if (!nctx || thr_id < 0 || thr_id >= nctx->n_thrs || fd <= 0) {
    return -EINVAL;
  }
  pctx = &nctx->poll_ctx[thr_id];

  pthread_mutex_lock(&pctx->rq_lock);
  if (pctx->rq_count >= MAX_NOTIFY_RESUME_PENDING) {
    pthread_mutex_unlock(&pctx->rq_lock);
    log_error("notify_wake_worker: resume ring full (thr %d) — leaving fd %d parked", thr_id, fd);
    return -ENOSPC;
  }
  pctx->rq[pctx->rq_tail] = fd;
  pctx->rq_tail = (pctx->rq_tail + 1) % MAX_NOTIFY_RESUME_PENDING;
  pctx->rq_count++;
  wfd = pctx->wake_fd;
  pthread_mutex_unlock(&pctx->rq_lock);

  if (wfd >= 0) {
    uint64_t one = 1;
    ssize_t w = write(wfd, &one, sizeof(one));
    (void)w;  /* eventfd counter is coalescing; a missed wake is caught next poll() tick */
  }
  return 0;
}

int
notify_check_slot(void *ctx, int fd)
{
  notify_ctx_t *nctx = ctx;
  notify_ent_t *ent;

  assert(ctx);

  if (fd <= 0 || fd >= MAX_NOTIFY_FDS) {
    return 0;
  }

  NOTI_LOCK(nctx);
  ent = &nctx->earr[fd];
  if (ent->fd > 0) {
    NOTI_UNLOCK(nctx);
    return 0;
  }

  NOTI_UNLOCK(nctx);
  return 1;
}

/* (conc=128 wedge fix, Option A): core add with optional worker pinning.
 * When pin_fd is a live, already-registered fd, the new fd inherits pin_fd's worker
 * thread (thr_id) instead of the historic `fd % n_thrs` shard. This serializes both
 * legs of one logical connection (client fd + backend rfd) on a SINGLE notify worker,
 * so the relay path (proxy_notifier) and the teardown/free path (proxy_pdestroy) for
 * that connection can never run concurrently — eliminating the cross-thread pfe
 * use-after-free that permanently wedged loxilb under load. pin_fd<=0 => historic
 * behaviour. The earr[pin_fd] read happens under NOTI_LOCK (held below). */
static int
__notify_add_ent(void *ctx, int fd, notify_type_t type, void *priv, uint64_t gen, int pin_fd)
{
  notify_ctx_t *nctx = ctx;
  notify_ent_t *ent;
  notify_poll_ctx_t *pctx;
  short events;
  int tslot = 0;

  assert(ctx);

  if (fd <= 0 || fd > MAX_NOTIFY_FDS) {
    return -EINVAL;
  }

  events = notify_conv2poll_events(type);
  if (!events) {
    return -EINVAL;
  }

  NOTI_LOCK(nctx); 
  ent = &nctx->earr[fd];
  if (ent->fd > 0) {
    pctx = &nctx->poll_ctx[ent->thr_id];
    assert(pctx);
    if (ent->priv == priv) {
      if (pctx->pfds[ent->poll_slot].events != events) {
        pctx->pfds[ent->poll_slot].events = events;
      }
      NOTI_UNLOCK(nctx);
      return 0;
    }
    NOTI_UNLOCK(nctx); 
    //log_debug("events exist %d", fd);
    return -EEXIST;
  }

  //nctx->thr_sel++;
  //tslot = ctx->thr_sel % nctx->n_thrs;
  /* Option A: pin to pin_fd's worker when it is a live registered fd. */
  if (pin_fd > 0 && pin_fd < MAX_NOTIFY_FDS && nctx->earr[pin_fd].fd > 0) {
    tslot = nctx->earr[pin_fd].thr_id;
    log_debug("notify-pin: fd %d -> worker %d (pinned to fd %d)", fd, tslot, pin_fd);
  } else {
    tslot = fd % nctx->n_thrs;
    if (pin_fd > 0) {
      log_error("notify-pin-FAIL: fd %d pin_fd %d not registered (earr.fd=%d) -> fallback worker %d",
                fd, pin_fd, (pin_fd > 0 && pin_fd < MAX_NOTIFY_FDS) ? nctx->earr[pin_fd].fd : -1, tslot);
    }
  }
  pctx = &nctx->poll_ctx[tslot];
  if (pctx->n_pfds >= MAX_NOTIFY_POLL_FDS) {
    NOTI_UNLOCK(nctx);
    log_error("notify no slots exist %d", fd);
    return -EINVAL;
  }

  ent->type = type;
  ent->fd = fd;
  ent->poll_slot = pctx->n_pfds;
  ent->priv = priv;
  ent->gen = gen;
  ent->thr_id = tslot;
  
  pctx->pfds[pctx->n_pfds].fd = fd;
  pctx->pfds[pctx->n_pfds].events = events;
  pctx->npfds[pctx->n_pfds].evict = 0;

  nctx->n_fds++;
  pctx->n_pfds++;

  //log_trace("notify - add fd  %d tslot %d %d:%d", fd, tslot, nctx->n_fds, pctx->n_pfds);

  NOTI_UNLOCK(nctx);

  return 0;
}

int
notify_add_ent(void *ctx, int fd, notify_type_t type, void *priv, uint64_t gen)
{
  return __notify_add_ent(ctx, fd, type, priv, gen, -1);
}

/* Option A: register fd on the SAME notify worker as pin_fd (its owning
 * client fd), so a connection's client and backend legs serialize on one thread. */
int
notify_add_ent_pinned(void *ctx, int fd, notify_type_t type, void *priv, uint64_t gen, int pin_fd)
{
  return __notify_add_ent(ctx, fd, type, priv, gen, pin_fd);
}

int
notify_delete_ent__(void *ctx, int fd)
{
  int i = 0;
  notify_ctx_t *nctx = ctx;
  notify_ent_t *ent;
  notify_ent_t *pent;
  notify_poll_ctx_t *pctx;
  int poll_slot;
  int tslot;
  void *priv;

  assert(ctx); 

  if (fd <= 0 || fd >= MAX_NOTIFY_FDS) {
    return -EINVAL;
  }

  NOTI_LOCK(nctx);
  ent = &nctx->earr[fd];
  if (ent->fd <= 0) {
    NOTI_UNLOCK(nctx);
    return -ENOENT;
  }

  if (ent->poll_slot < 0 || ent->poll_slot >= MAX_NOTIFY_POLL_FDS) {
    NOTI_UNLOCK(nctx);
    assert(0);
  }

  priv = ent->priv;
  poll_slot = ent->poll_slot;
  tslot = ent->thr_id;

  if (tslot < 0 || tslot >= MAX_NOTIFY_THREADS) {
    NOTI_UNLOCK(nctx);
    assert(0);
  }

  ent->fd = -1;
  ent->type = 0;
  ent->poll_slot = -1;
  ent->priv = NULL;
  ent->thr_id = 0;

  pctx = &nctx->poll_ctx[tslot];

  for (i = poll_slot; i < pctx->n_pfds - 1; i++) {

    pent = NULL;
    if (pctx->pfds[i+1].fd > 0 && pctx->pfds[i+1].fd < MAX_NOTIFY_FDS) {
      pent = &nctx->earr[pctx->pfds[i+1].fd];
    }

    pctx->pfds[i].fd = pctx->pfds[i+1].fd;
    pctx->pfds[i].events = pctx->pfds[i+1].events;
    pctx->npfds[i].evict = 0;

    if (pent) {
      pent->poll_slot = i;
    }
  }

  nctx->n_fds--;
  pctx->n_pfds--;

  //log_trace("notify del fd %d tslot %d %d:%d", fd, tslot, nctx->n_fds, pctx->n_pfds);

  NOTI_UNLOCK(nctx);

  if (priv) {
    if (nctx->cbs.pdestroy) {
      nctx->cbs.pdestroy(priv);
    }
  }

  return 0;
}

#ifdef HAVE_NOTIFY_EVICT
static int
notify_delete_ent_evict__(void *ctx, int fd)
{
  notify_ctx_t *nctx = ctx;
  notify_ent_t *ent;
  notify_ent_t *pent;
  notify_poll_ctx_t *pctx;
  int poll_slot;
  int tslot;

  assert(ctx);

  if (fd <= 0 || fd >= MAX_NOTIFY_FDS) {
    return -EINVAL;
  }

  NOTI_LOCK(nctx);
  ent = &nctx->earr[fd];
  if (ent->fd <= 0) {
    NOTI_UNLOCK(nctx);
    assert(0);
    return -ENOENT;
  }

  if (ent->poll_slot < 0) {
    NOTI_UNLOCK(nctx);
    assert(0);
  }

  tslot = ent->thr_id;
  if (tslot < 0 || tslot >= MAX_NOTIFY_THREADS) {
    NOTI_UNLOCK(nctx);
    assert(0);
  }

  poll_slot = ent->poll_slot;
  if (poll_slot < 0 || poll_slot >= MAX_NOTIFY_POLL_FDS) {
    NOTI_UNLOCK(nctx);
    assert(0);
  }

  pctx = &nctx->poll_ctx[tslot];
  if (pctx->pfds[poll_slot].fd <= 0) {
    NOTI_UNLOCK(nctx);
    assert(0);
  }

  pctx->npfds[poll_slot].evict = 1;
  NOTI_UNLOCK(nctx);

  return 0;
}

#else

static int
notify_delete_ent_evict__(void *ctx, int fd)
{
  return 0;
}

#endif

int
notify_delete_ent(void *ctx, int fd, int evict)
{
  int rc;

  if (evict) {
    rc = notify_delete_ent_evict__(ctx, fd);
  } else {
    rc = notify_delete_ent__(ctx, fd);
  }

  return rc;
}

/* (conc=128 single-owner teardown): deregister a fd from the notifier
 * WITHOUT invoking cbs.pdestroy. Identical to notify_delete_ent__ except it
 * neither reads ent->priv nor calls cbs.pdestroy(priv).
 *
 * Why this exists: the prefill/decode reapers (check_draining_endpoints) used to
 * tear down a P/D connection's legs via notify_delete_ent(), which ALWAYS calls
 * cbs.pdestroy -> proxy_pdestroy(). Inside the reaper (which holds PROXY_LOCK)
 * that (a) re-acquired PROXY_LOCK, and (b) ran proxy_release_rfd_ctx() ->
 * proxy_release_fd_ctx(client) once per backend leg, plus the reaper's own
 * release — N+1 releases of the same client pfe. The repeated non-idempotent
 * frees corrupted an adjacent heap chunk -> "corrupted size vs. prev_size"
 * abort on the next free; the SIGABRT was swallowed on the C thread so the
 * reaper never released PROXY_LOCK and every serving worker wedged (live gdb:
 * drain-checker in _int_free holding PROXY_LOCK, 38 workers blocked on it).
 * The caller (pd_teardown_conn) now owns close()+free of each leg exactly once. */
int
notify_deregister_ent(void *ctx, int fd)
{
  int i = 0;
  notify_ctx_t *nctx = ctx;
  notify_ent_t *ent;
  notify_ent_t *pent;
  notify_poll_ctx_t *pctx;
  int poll_slot;
  int tslot;

  assert(ctx);

  if (fd <= 0 || fd >= MAX_NOTIFY_FDS) {
    return -EINVAL;
  }

  NOTI_LOCK(nctx);
  ent = &nctx->earr[fd];
  if (ent->fd <= 0) {
    NOTI_UNLOCK(nctx);
    return -ENOENT;
  }

  if (ent->poll_slot < 0 || ent->poll_slot >= MAX_NOTIFY_POLL_FDS) {
    NOTI_UNLOCK(nctx);
    assert(0);
  }

  poll_slot = ent->poll_slot;
  tslot = ent->thr_id;

  if (tslot < 0 || tslot >= MAX_NOTIFY_THREADS) {
    NOTI_UNLOCK(nctx);
    assert(0);
  }

  ent->fd = -1;
  ent->type = 0;
  ent->poll_slot = -1;
  ent->priv = NULL;
  ent->thr_id = 0;

  pctx = &nctx->poll_ctx[tslot];

  for (i = poll_slot; i < pctx->n_pfds - 1; i++) {

    pent = NULL;
    if (pctx->pfds[i+1].fd > 0 && pctx->pfds[i+1].fd < MAX_NOTIFY_FDS) {
      pent = &nctx->earr[pctx->pfds[i+1].fd];
    }

    pctx->pfds[i].fd = pctx->pfds[i+1].fd;
    pctx->pfds[i].events = pctx->pfds[i+1].events;
    pctx->npfds[i].evict = 0;

    if (pent) {
      pent->poll_slot = i;
    }
  }

  nctx->n_fds--;
  pctx->n_pfds--;

  NOTI_UNLOCK(nctx);

  return 0;
}

/* (R1): drain THIS worker's resume-pending ring and re-drive each parked
 * fd via cbs.resume — ON THIS (the owner) worker thread. Called from notify_run after
 * the wake eventfd fires. Snapshots fds under rq_lock, then calls cbs.resume OUTSIDE
 * the lock (resume re-drives setup_proxy_path, which itself takes other locks). The
 * eventfd counter is also drained here. No-op when nothing is pending / cbs.resume
 * is NULL (admission layer not wired). */
static void
notify_drain_resume(notify_ctx_t *nctx, int thread)
{
  notify_poll_ctx_t *pctx = &nctx->poll_ctx[thread];

  /* Drain the eventfd counter (coalescing — one read clears all pending wakes). */
  if (pctx->wake_fd >= 0) {
    uint64_t cnt;
    while (read(pctx->wake_fd, &cnt, sizeof(cnt)) == (ssize_t)sizeof(cnt)) {
      /* loop until EAGAIN (NONBLOCK) */
    }
  }

  for (;;) {
    int fd = -1;
    pthread_mutex_lock(&pctx->rq_lock);
    if (pctx->rq_count > 0) {
      fd = pctx->rq[pctx->rq_head];
      pctx->rq_head = (pctx->rq_head + 1) % MAX_NOTIFY_RESUME_PENDING;
      pctx->rq_count--;
    }
    pthread_mutex_unlock(&pctx->rq_lock);

    if (fd < 0) {
      break;  /* ring drained */
    }
    if (nctx->cbs.resume) {
      nctx->cbs.resume(fd);   /* re-drive dispatch on THIS owner worker */
    }
  }
}

static void
notify_run(void *ctx, int thread)
{
  int rc = 0;
  int nproc = 0;
  int i = 0;
  size_t parr_sz;
  int n_pfds = 0;
  void *priv = NULL;
  uint64_t gen = 0;
  char estr[128];;
  struct pollfd *pfds;
  notify_ent_t *ent;
  notify_ctx_t *nctx = ctx;

  assert(nctx);

  if (thread >= MAX_NOTIFY_THREADS) {
    assert(0);
  }

  parr_sz = MAX_NOTIFY_POLL_FDS*sizeof(struct pollfd);
  pfds = calloc(1, MAX_NOTIFY_POLL_FDS*sizeof(struct pollfd));
  assert(pfds);

  /* (R1): create THIS worker's wake eventfd and register it in this
   * worker's own pfds[] so poll() returns when another thread writes it. Created on
   * the worker thread (here) so it is owned/polled by exactly this worker. When the
   * admission layer never wakes a worker, the eventfd sits idle in poll() — never
   * readable — so the relay path is byte-identical to pre-93-05 (default-off). */
  {
    int wfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (wfd < 0) {
      log_error("notify:eventfd:error(%s) — worker %d resume-wake disabled",
                strerror_r(errno, estr, sizeof(estr)), thread);
    } else {
      NOTI_LOCK(nctx);
      notify_poll_ctx_t *pc = &nctx->poll_ctx[thread];
      pc->wake_fd = wfd;
      if (pc->n_pfds < MAX_NOTIFY_POLL_FDS) {
        /* Register at a reserved poll slot; it has NO earr[] entry (not a relayed
         * fd) — notify_run special-cases wake_fd below before the earr lookup. */
        pc->pfds[pc->n_pfds].fd = wfd;
        pc->pfds[pc->n_pfds].events = POLLIN;
        pc->npfds[pc->n_pfds].evict = 0;
        pc->n_pfds++;
      }
      NOTI_UNLOCK(nctx);
    }
  }

  while(1) {

    /* This is seemingly expensive operation */
    NOTI_LOCK(nctx);
    memcpy(pfds, nctx->poll_ctx[thread].pfds, parr_sz);
    n_pfds = nctx->poll_ctx[thread].n_pfds;
    NOTI_UNLOCK(nctx);

    nproc = 0;
    rc = poll(pfds, n_pfds, MAX_NOTIFY_POLL_TIMEO);
    if (rc < 0) {
      log_error("notify:poll:error(%s)", strerror_r(errno, estr, sizeof(estr)));
      usleep(200*1000);
      continue;
    }

    if (rc == 0) {
      int evict = 0;

#ifdef HAVE_NOTIFY_EVICT
      for (i = 0; i < n_pfds; i++) {
        NOTI_LOCK(nctx);
        if (nctx->poll_ctx[thread].npfds[i].evict &&
            nctx->poll_ctx[thread].pfds[i].fd > 0) {
          evict = 1;
          pfds[i].revents = POLLERR;
        }
        NOTI_UNLOCK(nctx);
      }
#endif
      if (!evict) {
        //log_trace("notify:poll:timeout (n_pfds %d)", n_pfds);
        continue;
      }
    }

    for (i = 0 ; i < n_pfds; i++) {
      int fd = pfds[i].fd;
      notify_type_t type = notify_conv4mpoll_events(pfds[i].revents);
      if (type == 0) {
        continue;
      }

      /* (R1): the wake eventfd has NO earr entry — handle it BEFORE
       * the earr lookup below. A readable wake_fd means parked fds are pending for
       * this owner worker: drain the ring + re-drive each via cbs.resume on THIS
       * thread, then move on (never fall through to the relay dispatch). */
      if (nctx->poll_ctx[thread].wake_fd >= 0 && fd == nctx->poll_ctx[thread].wake_fd) {
        notify_drain_resume(nctx, thread);
        nproc++;
        continue;
      }

      if (fd <= 0 || fd >= MAX_NOTIFY_FDS) {
        log_trace("notify:poll:fd invaild (n_pfds %d)", n_pfds);
        continue;
      }

      NOTI_LOCK(nctx);
      ent = &nctx->earr[fd];
      if (ent->fd <= 0) {
        NOTI_UNLOCK(nctx);
        log_trace("notify:poll:ent fd %d invalid (n_pfds %d)", fd, n_pfds);
        notify_delete_ent__(nctx, fd);
        continue;
      }
      priv = ent->priv;
      /* D2 root fix (I2): capture the generation stamp atomically with priv,
       * UNDER NOTI_LOCK — while the pfe is provably still published/alive. The
       * close path must take NOTI_LOCK to clear earr[fd] before it can recycle
       * (and bump the gen of) this pfe, so the value captured here is the live
       * generation. The dispatch below compares it against the pfe's CURRENT
       * gen, dropping the event if the slot was recycled in the meantime. */
      gen = ent->gen;
      NOTI_UNLOCK(nctx);

      if (nctx->cbs.notify) {
        if (type & NOTI_TYPE_OUT) {
          type |= NOTI_TYPE_IN;
        }
        nctx->cbs.notify(fd, type, priv, gen);
      }

      if (type & (NOTI_TYPE_HUP|NOTI_TYPE_ERROR)) {
        //log_trace("notify:hup %d", fd);
        notify_delete_ent__(nctx, fd); 
      }
      nproc++;
    }
  }
}

/* Stage 1 fail-loud: mark this raw pthread as a proxy worker so a fatal signal on
 * it crashes loud+fast (the handler in sockproxy_notifier.c) instead of being
 * swallowed by the Go runtime → ~30s lock-wedge. */
extern __thread volatile sig_atomic_t g_llb_proxy_worker;

static void *
notify_run_worker(void *arg)
{
  notify_thr_t *targ = arg;
  g_llb_proxy_worker = 1;
  
#ifdef HAVE_HTTP_TRACE
  // Set worker ID for this thread (for ring buffer lookup)
  extern void lxb_ring_set_worker_id(int worker_id);
  lxb_ring_set_worker_id(targ->thrid);
#endif
  
  notify_run(targ->ctx, targ->thrid);
  return NULL;
}

int
notify_start(void *ctx)
{
  int i = 0;
  pthread_t *ptarr;
  notify_thr_t *nthr;
  notify_ctx_t *nctx = ctx;

  ptarr = calloc(1, nctx->n_thrs*sizeof(pthread_t));

  for (i = 0; i < nctx->n_thrs; i++) {
    nthr = calloc(1, sizeof(*nthr));
    assert(nthr);

    nthr->ctx = ctx;
    nthr->thrid = i;
    pthread_create(&ptarr[i], NULL, notify_run_worker, nthr);
  }

  while (1) {
    sleep(1);
  }
}
