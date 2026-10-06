/*
 * Copyright (c) 2024 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */
#ifndef __SOCKPROXY_INTERNAL_H__
#define __SOCKPROXY_INTERNAL_H__

/*
 * sockproxy_internal.h - Internal data structures shared across the split TUs
 * that form the refactored sockproxy subsystem.
 *
 * This header is NOT part of the public CGO API (sockproxy.h).
 * Every sockproxy_xxx.c implementation file must include it after system headers.
 *
 * See sockproxy_refactoring_plan.md §3.P1 and §5.
 */

#include "sockproxy.h"

/*
 * DEPENDENCY RULE: This header must remain dependency-free beyond sockproxy.h.
 * Do NOT add #include directives for split modules here.
 */

/* =========================================================================
 * Internal sizing constants
 * ========================================================================= */

/*
 * PROXY_MAX_THREADS - number of per-thread epoll / FD-mapping slots.
 * Used in proxy_mapfd_t mapfd[PROXY_MAX_THREADS] inside proxy_struct_t.
 * See also: PROXY_NUM_BURST_RX (remains in sockproxy.c – cache/I/O concern).
 */
#define PROXY_MAX_THREADS           4

/* FD mapping pool constants */
#define PROXY_START_MAPFD           500
#define PROXY_MAX_MAPFD             200
#define PROXY_MAPFD_ALLOC_RETRIES   100
#define PROXY_MAPFD_RETRIES           5

/* =========================================================================
 * Internal typedef: smap_key_t
 * Convenience alias used throughout the sockproxy split modules.
 * ========================================================================= */
typedef struct llb_sockmap_key smap_key_t;

/* =========================================================================
 * Internal helper types used by proxy_setup_ep__ -> sockproxy_ep.c
 * ========================================================================= */

/*
 * proxy_ep_val_t - per-connection endpoint file-descriptor tracking.
 * Built by proxy_setup_ep__ when connecting to backend endpoints.
 */
typedef struct proxy_ep_val {
  int ep_cfd;
  int ep_num;
  int needs_learning;             /* Session learning flag */
  int connect_pending;            /* handshake in flight: wired from the writable event */
} proxy_ep_val_t;

/*
 * proxy_ep_sel_t - result set from endpoint-selection logic.
 * Carries the list of connected backend FDs and the session-header name.
 */
typedef struct proxy_ep_sel {
  proxy_ep_val_t ep_cfds[MAX_PROXY_EP];
  int n_eps;
  char session_header_name[128];  /* Session header name for learning */
} proxy_ep_sel_t;

/* =========================================================================
 * proxy_mapfd_t - per-thread FD mapping slot
 * Used in proxy_struct_t.mapfd[PROXY_MAX_THREADS].
 * ========================================================================= */
typedef struct proxy_mapfd {
  uint16_t start;
  uint16_t end;
  uint16_t next;
} proxy_mapfd_t;

/* =========================================================================
 * proxy_struct_t - process-wide singleton owning all proxy state.
 *
 * Linkage: defined WITHOUT 'static' in sockproxy.c; declared extern here.
 * See sockproxy_refactoring_plan.md §3.P1 (Problem B).
 *
 * Lock ordering (normative – see §4 of the refactoring plan):
 *   Priority 1: proxy_struct->lock      (PROXY_LOCK / PROXY_RDLOCK)
 *   Priority 2: proxy_val_t.lock        (PROXY_ENT_LOCK)
 *   Priority 3: proxy_val_t.conv_lock
 *   Priority 4: proxy_epval_t.pd_session_lock
 *   Priority 5: proxy_epval_t.pd_trie_lock
 *   Priority 6: chwbl_ring_t.lock
 *   Priority 7: proxy_fd_ent_t.cache_lock (PROXY_ENT_CLOCK)
 *   Priority 8: proxy_struct->global_cert_lock (rarely held with others)
 *
 * NEVER acquire a higher-priority (higher number) lock while holding a
 * lower-priority lock.
 * ========================================================================= */
typedef struct proxy_struct {
  pthread_rwlock_t lock;
  pthread_t pthr;
  pthread_t drain_checker_thr;          /* P2: Draining checker thread */
  pthread_t conversation_cleanup_thr;   /* Conversation mapping cleanup thread */
  pthread_t watchdog_thr;               /* D2-wedge fix: proxy liveness watchdog (lock-wedge self-heal) */
#ifdef HAVE_HTTP_TRACE
  pthread_t trace_cleanup_thr;          /* Trace file cleanup thread */
#endif
  int run;                              /* Control flag for cleanup threads */
  proxy_map_ent_t *head;
  sockmap_cb_t sockmap_cb;
  peer_map_cb_t peer_map_cb;
  verdict_map_cb_t verdict_map_cb;
  void *ns;
  proxy_mapfd_t mapfd[PROXY_MAX_THREADS];
  time_t last_session_cleanup;          /* Last time session cleanup ran */

  /* GLOBAL SNI CERTIFICATE STORE (independent of loadbalancer rules) */
  ssl_cert_entry_t *global_cert_map;    /* Global hash map: hostname -> SSL_CTX */
  pthread_rwlock_t  global_cert_lock;   /* Lock priority 8 (guards BOTH maps below) */

  /* certId registry LAYERED OVER global_cert_map.
   * Keyed by the opaque certId management handle; each entry tracks the managed
   * dir and the SAN/CN-derived hostnames it registered into global_cert_map.
   * Guarded by the SAME global_cert_lock (the registry and the SNI store form one
   * lock domain — register/rotate/delete touch both maps under this single lock,
   * keeping lock priority 8 and avoiding any new lock-ordering edge). */
  cert_id_entry_t  *global_certid_map;  /* Global hash map: certId -> {hostnames, managed dir} */
} proxy_struct_t;

/* =========================================================================
 * Global singleton declaration.
 * Definition (without 'static') is in sockproxy.c.
 * See sockproxy_refactoring_plan.md §3.P1.
 * ========================================================================= */
extern proxy_struct_t *proxy_struct;

/* =========================================================================
 * Internal logging helpers.
 * Defined in sockproxy_cache.c; available to all split TUs.
 * proxy_log is compiled only when HAVE_PROXY_DEBUG is defined in cache.c,
 * but the extern declaration is unconditional because the function is always
 * present in sockproxy_cache.o (HAVE_PROXY_DEBUG is hardcoded there).
 * ========================================================================= */
void proxy_log(const char *str, smap_key_t *key);
void proxy_log_always(const char *str, smap_key_t *key);
void proxy_release_fd_ctx(proxy_fd_ent_t *fd_ent, int reset);
/* single-owner pfe free (refcount used--; frees when used<=0). Also
 * declared in sockproxy_conn.h; mirrored here for the reaper teardown path. */
void proxy_try_free_fd_ctx(proxy_fd_ent_t *pfe);
/* D2 root fix (pfe pool + generation, B-split). pfe_alloc(): return a zeroed pfe
 * shell from a grow-only freelist (its address is permanently valid) with a fresh
 * 1MB rcvbuf allocated; the shell's `gen` is preserved across recycles (monotonic).
 * Returns NULL only on OOM. pfe_recycle(): free the shell's per-connection heap
 * buffers (rcvbuf), bump `gen`, and return the shell to the freelist — NEVER
 * free() it to the heap, so a stale notify dispatch reading pfe->gen is safe. */
proxy_fd_ent_t *pfe_alloc(void);
/* The shell without its receive buffer, for a backend leg whose connect is
 * still in flight; pfe_rcvbuf_alloc attaches the buffer once the leg is
 * connected (0, or -1 on OOM with the shell untouched). */
proxy_fd_ent_t *pfe_alloc_bare(void);
int pfe_rcvbuf_alloc(proxy_fd_ent_t *pfe);
void proxy_rcvbuf_cache_setup(const char *env);
void pfe_recycle(proxy_fd_ent_t *pfe);
/* : read-only snapshot of the pfe-pool high-water gauges for the
 * bounded-footprint soak (live = shells checked out now; total = shells ever made).
 * Lock-guarded, never mutates. NULL out-params are skipped. */
void pfe_pool_snapshot(unsigned long *live, unsigned long *total);
void pd_cleanup(proxy_fd_ent_t *fd_ent);

/* Local responses on the client socket, TLS-aware and bounded
 * (sockproxy_http.c). Every overload or refusal answer the proxy writes
 * itself goes through these, never a raw send(): on a TLS listener a raw
 * send() puts plaintext inside the TLS stream. */
int proxy_send_local_response(proxy_fd_ent_t *pfe, const void *buf, size_t len);
int proxy_send_local_response_and_shutdown(proxy_fd_ent_t *pfe,
                                           const void *buf, size_t len);
void sp_h1_send_admit_deny(proxy_fd_ent_t *pfe, int status, int retry_after,
                           int retry_body, const char *code, const char *msg);
/* `keep`: the refusal leaves the connection open for its next request (the
 * body was fully buffered); otherwise it closes. Non-zero when the response
 * was not written whole. */
int sp_h1_send_capacity_deny(proxy_fd_ent_t *pfe, int status, const char *code,
                             const char *msg, uint32_t inflight, uint32_t queued,
                             uint32_t limit, uint32_t retry_after, int keep);
/* Service identity "VIP:port" from the connection's rule head ("" when the
 * head is gone). */
void proxy_pfe_svc_ident(proxy_fd_ent_t *pfe, char *buf, size_t len);

/* Responses the reaper thread owes a client it is ending (sockproxy_health.c).
 * The reaper never writes the socket itself: it records the kind on
 * pfe->reap_resp and wakes the fd's owner worker, which emits the text through
 * the senders above and ends the connection (sp_reap_finish). */
enum sp_reap_resp {
  SP_REAP_NONE = 0,
  SP_REAP_SSE_CAP,              /* SSE error event: stream duration cap; shutdown */
  SP_REAP_PD_PREFILL_TIMEOUT,   /* 504 pd_prefill_timeout; teardown */
  SP_REAP_PD_DECODE_TIMEOUT,    /* 504 pd_decode_timeout; teardown */
  SP_REAP_PD_PARK_TIMEOUT,      /* 504 pd_admission_park_timeout; teardown */
  SP_REAP_PD_GRACEFUL_DONE,     /* SSE terminator the backend dropped; teardown */
  SP_REAP_PD_STREAM_TIMEOUT,    /* 502 pd_decode_stream_timeout; teardown */
  SP_REAP_PD_IDLE_TIMEOUT,      /* 504 pd_idle_timeout; teardown */
  SP_REAP_FC_QUEUE_TIMEOUT,     /* 504 admission_queue_timeout; teardown */
  SP_REAP_FC_DRAINED,           /* 503 admission_drained; teardown */
  SP_REAP_KINDS,
};
void sp_reap_finish(proxy_fd_ent_t *pfe);
/* Hand a response of `kind` to the connection's owner worker and end the
 * connection there (sockproxy_health.c; the reaper's own entry point). The
 * caller holds PROXY_LOCK. */
void sp_reap_request(proxy_fd_ent_t *pfe, uint8_t kind);

/* Capacity admission at the HTTP/1 dispatch site (sockproxy_http.c). Each
 * returns 0 to proceed, or one of the outcomes below: REFUSED (the
 * response written and the socket shut), QUEUED (the request was parked
 * in the pool's queue: the caller suspends the connection and keeps it),
 * KEPT (refused, the response written, the connection kept for its next
 * request). The endpoint gate returns the endpoint the unit landed on,
 * which may differ from the selector's pick, or one of the outcomes. The
 * role gate takes `may_wait`: a prefill/decode leg never waits. */
#define SP_FC_H1_REFUSED (-1)
#define SP_FC_H1_QUEUED  (-2)
#define SP_FC_H1_KEPT    (-3)
int sp_fc_h1_gate_service(proxy_fd_ent_t *pfe, proxy_epval_t *tepval);
int sp_fc_h1_gate_endpoint(proxy_fd_ent_t *pfe, proxy_epval_t *tepval, int sel);
int sp_fc_h1_gate_role(proxy_fd_ent_t *pfe, proxy_epval_t *tepval, int ep, int role,
                       int may_wait);
int sp_fc_normal_eligible(void *ctx, int ep);
/* End every request waiting in the pool's queue with a response of `kind`
 * (SP_REAP_FC_DRAINED): the pool is going away, or the process drains.
 * The caller holds PROXY_LOCK. */
void sp_fc_drain_pool(proxy_epval_t *tepval, uint8_t kind, int detach);
/* The adaptive ceiling's signal for one pool at the 1 Hz pass: fresh
 * scraped depths and TTFT estimates within the pool's telemetry window.
 * The caller holds PROXY_LOCK. */
void sp_fc_adapt_signal(proxy_epval_t *tepval, uint64_t now_s, uint64_t now_ns,
                        fc_signal_t *sig);
/* A streamed response's first data event: one TTFT sample for the
 * endpoint holding the request's unit, when the pool has a TTFT target. */
void sp_fc_ttft_first_event(proxy_fd_ent_t *pfe);
/* (R1): owner-worker resume of a parked client fd. Registered as
 * notify_cbs.resume and invoked ON THE PARKED FD'S OWNER WORKER (via notify_wake_worker)
 * when a prefill slot frees. Re-arms EPOLLIN, reconstructs the dispatch from the pfe
 * alone (key via proxy_skmap_key_from_fd; phurl via pfe->host_url), and re-drives
 * pd_setup_and_forward. Never runs off-owner (the Phase-89/90 cross-thread UAF invariant). */
void pd_resume_parked(int fd);
/* The writable or error event of a backend leg whose connect setup_proxy_path
 * left in flight. Runs on the worker that owns both legs and consumes the
 * event: completes the leg, resumes the client and forwards the request it
 * held, or fails the request with a 502. `type` is the notify_type_t mask. */
int proxy_backend_connect_event(int fd, proxy_fd_ent_t *pfe, int type);
/* drain (pop + owner-worker wake) EVERY parked-admission entry for an EP that
 * just became ineligible for selection (health inv-flip, circuit-breaker
 * OPEN). The slot-free dequeue pops one head per dying conn — this releases
 * the rest so they re-select instead of stranding until the max-park reap. */
void pd_parked_drain_ep(proxy_epval_t *tepval, int ep_index, const char *why);
void proxy_reset_fd_list(proxy_map_ent_t *ent, void *match_pfe);

/* The listener's backend TLS context, loaded once. */
static inline void *
proxy_ent_epctx(const proxy_map_ent_t *ent)
{
  return __atomic_load_n(&ent->val.ssl_epctx, __ATOMIC_ACQUIRE);
}
/* 1 when a TLS backend leg was made with a context the listener no longer
 * uses. A plaintext leg is never stale: TLS on or off is not swapped in place. */
int proxy_leg_tls_stale(const proxy_map_ent_t *ent, const proxy_fd_ent_t *bpfe);
/* PROXY_LOCK held. Put a shell on a rule's connection list; -1 and a log
 * line when the shell is on a list already (the insert is refused). `what`
 * names the leg in that line. */
int proxy_fdlist_link(proxy_map_ent_t *ent, proxy_fd_ent_t *pfe, const char *what);

/* =========================================================================
 * sockproxy HA state-sync event bridge (CGO C → Go).
 *
 * Emit site count: 11 across 5 C functions (5 in sockproxy_pd.c + 6 in
 * sockproxy_ep.c). Reconciled from SPEC A4 "at least 5" per 70-PATTERNS.md L-12.
 *
 * INVARIANTS (sockproxy_internal.h:89-100 lock hierarchy + Landmines L-5/L-7):
 *   1. Caller MUST release the rwlock that protected the mutation BEFORE
 *      invoking llb_sockproxy_emit_sync_event(). NEVER nested inside any
 *      pthread_rwlock_*(). The Go side then does only a non-blocking
 *      channel send + drop-oldest; no callback into C from this path.
 *   2. Caller MUST pre-resolve service_key (xip:xport:proto string) and any
 *      ep_idx values BEFORE acquiring the wrlock — the emit path never
 *      re-takes proxy_struct->lock (Landmine L-7).
 *   3. Event is copied POD-by-value into a Go-side local immediately; the
 *      C-side pointer `ev` MUST reference a stack-allocated or short-lived
 *      caller buffer (Landmine L-5).
 *
 * Wire format mirrors pkg/loxinet/xsync.proto SockproxySessionEntry.
 * ========================================================================= */
typedef enum {
    SYNC_SESSION_CREATE = 0,
    SYNC_SESSION_UPDATE = 1,
    SYNC_SESSION_DELETE = 2,
    SYNC_CONV_CREATE    = 3,
    SYNC_CONV_UPDATE    = 4,
    SYNC_CONV_DELETE    = 5,
} proxy_sync_event_kind_t;

typedef struct proxy_sync_event {
    int      kind;                       /* proxy_sync_event_kind_t (POD-safe int) */
    char     service_key[64];            /* "xip:xport:proto", caller-resolved */
    char     conv_id[MAX_CONV_ID_LEN];
    int      prefill_ep_idx;             /* -1 if not P/D */
    int      decode_ep_idx;              /* -1 if not P/D */
    int      ep_idx;                     /* for conv mapping; -1 if P/D */
    uint64_t created_ts;
    uint64_t last_access_ts;
    uint32_t request_count;
} proxy_sync_event_t;

/* Implemented Go-side via //export in pkg/loxinet/sockproxy_sync.go.
 *
 * For unit-test (test_sockproxy_sync_emit.c) builds the symbol is supplied
 * by the test harness (the test defines its own llb_sockproxy_emit_sync_event
 * recorder). Production builds link against the Go-side //export. */
extern void llb_sockproxy_emit_sync_event(const proxy_sync_event_t *ev);

#endif /* __SOCKPROXY_INTERNAL_H__ */
