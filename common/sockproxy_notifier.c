/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */
/*
 * sockproxy_notifier.c — extraction
 *
 * Contains the top-level event dispatcher (proxy_notifier) and the
 * initialization entry-point (proxy_main).  Extracted from sockproxy.c.
 */
#define _GNU_SOURCE
#define HAVE_PROXY_EXTRA_DEBUG
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <assert.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <execinfo.h>   /* RCA: backtrace/backtrace_symbols_fd in FAILLOUD */
#include <sys/syscall.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <bpf.h>
#include "common_pdi.h"
#include "llb_dpapi.h"
#include "log.h"
#include "uthash.h"
#include "notify.h"
#include "sockproxy.h"
#include "sockproxy_internal.h"
#include "sockproxy_metrics.h"
#include "sockproxy_cache.h"
#include "sockproxy_conn.h"
#include "sockproxy_ep.h"
#include "sockproxy_routing.h"
#include "sockproxy_lb.h"
#include "sockproxy_health.h"
#include "sockproxy_ssl.h"
#include "sockproxy_trace.h"
#include "sockproxy_json.h"
#include "sockproxy_ktls.h"
#include "sockproxy_h2.h"
#include "sockproxy_http.h"
#ifdef HAVE_MTLS
#include "sockproxy_mtls.h"
#endif
#ifdef HAVE_PII_DETECTION
#include "presidio_config.h"
#include "sockproxy_presidio.h"
#endif
#ifdef HAVE_LLAMAFIREWALL
#include "sockproxy_llamafirewall.h"
#include "llamafirewall_config.h"
#endif
#include "sockproxy_notifier.h"

// Event loop wrappers for HTTP/2 module
int proxy_notify_add_fd(int fd, int type, void *priv)
{
  if (!proxy_struct || !proxy_struct->ns) {
    return -1;
  }
  /* D2 root fix: stamp the registration with the pfe's current generation so a
   * later stale dispatch on a recycled slot is detected and dropped. All priv
   * passed through the notifier are proxy_fd_ent_t shells (pfe_alloc'd). */
  return notify_add_ent(proxy_struct->ns, fd, type, priv,
                        priv ? ((proxy_fd_ent_t *)priv)->gen : 0);
}

int proxy_notify_delete_fd(int fd, int evict)
{
  if (!proxy_struct || !proxy_struct->ns) {
    return -1;
  }
  return notify_delete_ent(proxy_struct->ns, fd, evict);
}


/* FD mapping (HAVE_PROXY_MAPFD block) moved to sockproxy_conn.c */
/* Xmit cache, backpressure, logging helpers moved to sockproxy_cache.c */
/* inject_forwarded_headers, proxy_try_epxmit, proxy_add_entry, proxy_pdestroy,
 * cleanup_expired_sessions, handle_new_connection, handle_client_data, and all
 * HTTP parsing / P/D helpers moved to sockproxy_http.c */

#ifdef D2_DEBUG_INJECT
/* D2 root-fix VALIDATION ONLY — compiled in only with -DD2_DEBUG_INJECT (a
 * dedicated -dbg image; the production build never defines it). This is the
 * deterministic free-during-dispatch reproducer the root-fix design (§9) calls
 * for: the natural cross-worker stale-event race is too rare to trigger under
 * synthetic load, so we force it. Arm via LLB_D2_INJECT=1; on the first eligible
 * client dispatch it recycles THIS pfe and immediately re-allocates the shell —
 * exactly the teardown+reuse that, pre-fix, left a dangling heap pfe under the
 * in-flight dispatch. With the pool+generation fix the shell stays valid and the
 * gen check below drops the now-stale (priv,gen). Success = no abort / ASan-clean
 * + a [NOTIFY_GEN] drop. One-shot (self-disarms). */
static volatile int g_d2_inject = -1;   /* -1=unread env, 0=off, 1=armed */
#endif

static int
proxy_notifier(int fd, notify_type_t type, void *priv, uint64_t gen)
{
  struct llb_sockmap_key key = { 0 };
  struct llb_sockmap_key rkey = { 0 };
  proxy_ep_sel_t ep_sel = { 0 };
  int j __attribute__((unused));
  int protocol __attribute__((unused)), retry __attribute__((unused));
  proxy_fd_ent_t *pfe = priv;
  proxy_fd_ent_t *npfe1 __attribute__((unused)) = NULL;
  proxy_map_ent_t *ent;
  SSL *ssl __attribute__((unused)) = NULL;

  if (!priv) {
    return 0;
  }

#ifdef D2_DEBUG_INJECT
  if (g_d2_inject == -1) {
    const char *e = getenv("LLB_D2_INJECT");
    g_d2_inject = (e && atoi(e) > 0) ? 1 : 0;
  }
  if (g_d2_inject == 1 && (type & NOTI_TYPE_IN) && pfe->fd > 0 && pfe->odir == 0) {
    g_d2_inject = 0;   /* one-shot */
    /* Simulate the concurrent teardown recycling this pfe's shell in the window
     * between the dispatcher's under-lock (priv,gen) capture and this deref: a
     * recycle would bump the shell's generation. We bump it directly (NOT a real
     * pfe_recycle — that would pool a still-registered live shell and risk a
     * later double-recycle, muddying the proof). The gen-check below must now see
     * pfe->gen != captured gen and DROP the event with no crash. The pool
     * round-trip + memory-safety is proven separately by pfe_pool_selftest(). */
    uint64_t before = atomic_fetch_add_explicit(&pfe->gen, 1, memory_order_release);
    log_warn("[D2_INJECT] simulated concurrent recycle on fd=%d: gen %llu->%llu (dispatch captured %llu) — gen check must DROP",
             fd, (unsigned long long)before, (unsigned long long)(before + 1),
             (unsigned long long)gen);
    /* fall through: gen check returns 0; no abort/UAF; process keeps serving. */
  }
#endif

  /* D2 root fix (pfe pool + generation) — THE root-eliminating guard, and it
   * MUST be the first thing we touch on `pfe`. `gen` was captured under NOTI_LOCK
   * when this fd was registered; if the pfe shell has since been recycled (and
   * possibly handed to a different connection on the same address), its current
   * generation no longer matches and this is a stale event for a dead identity —
   * drop it. The read is memory-SAFE because the shell is pooled (never free()d),
   * which is exactly what lets us deref a possibly-recycled pfe at all. This is
   * the principled superset of the Layer-2 pfe->fd!=fd check below (it also
   * catches a same-fd-number recycle, which L2 cannot). */
  if (atomic_load_explicit(&pfe->gen, memory_order_acquire) != gen) {
    static time_t last_gen_log = 0;
    time_t nowt = time(NULL);
    if (nowt != last_gen_log) {   /* rate-limit to 1/s */
      log_warn("[NOTIFY_GEN] dropping stale event: dispatch fd=%d gen=%llu but pfe->gen=%llu (slot recycled)",
               fd, (unsigned long long)gen,
               (unsigned long long)atomic_load_explicit(&pfe->gen, memory_order_relaxed));
      last_gen_log = nowt;
    }
    return 0;
  }

  if (pfe->fd <= 0) {
    return 0;
  }

  /* D2-WEDGE FIX (Layer 2): drop stale notify events for a recycled slot.
   * A closed client/backend fd's proxy_fd_ent slot can be reused for a new
   * connection (pfe->fd changes) while a queued epoll/notify event for the OLD
   * fd is still in flight. Dispatching it parses the recycled pfe's buffer with
   * an llhttp parser belonging to a different connection identity, which can
   * drive llhttp into a corrupted resume state and abort() — wedging the proxy.
   * A legitimate event always targets the fd currently occupying this slot, so
   * pfe->fd == fd is an invariant for live events (see the historical
   * "notify fd = %d(%d)" trace below). Mismatch ⇒ stale event ⇒ skip. */
  if (pfe->fd != fd) {
    static time_t last_stale_log = 0;
    time_t nowt = time(NULL);
    if (nowt != last_stale_log) {   /* rate-limit to 1/s */
      log_warn("[NOTIFY_STALE] dropping stale event: dispatch fd=%d but pfe->fd=%d (slot recycled)",
               fd, pfe->fd);
      last_stale_log = nowt;
    }
    return 0;
  }

  ent = pfe->head;
  if (ent->val.sched_free) {
    return 0;
  }

  // Periodic session cleanup
  time_t now = time(NULL);
  if ((now - proxy_struct->last_session_cleanup) > PROXY_SESSION_CLEANUP_INTERVAL) {
    cleanup_expired_sessions();
    
#ifdef HAVE_DP_GPU_ROUTING
    // PRODUCTION: Validate CHWBL load counters after session cleanup
    // This helps detect and log any load tracking inconsistencies
    if (ent->val.ephash) {
      proxy_epval_t *tepval, *tmp_epval;
      HASH_ITER(hh, ent->val.ephash, tepval, tmp_epval) {
        if (tepval->select == PROXY_SEL_CHWBL) {
          chwbl_validate_load_counters(tepval);
        }
      }
    }
#endif /* HAVE_DP_GPU_ROUTING */

    proxy_struct->last_session_cleanup = now;
  }

  // PII Detection: Reload configuration from shared memory (hot-reload every 5 seconds)
#ifdef HAVE_PII_DETECTION
  static time_t last_presidio_reload = 0;
  static char last_analyzer_url[256] = {0};  // Track analyzer URL changes
  
  if ((now - last_presidio_reload) >= 5) {
    // Reload configuration from shared memory FIRST
    presidio_config_reload();
    
    // NOW get the updated config
    presidio_config_shm_t *pii_cfg = presidio_config_get();
    if (pii_cfg && pii_cfg->analyzer_url[0] != '\0') {
      // Check if this is a localhost URL - skip initialization but track it
      int is_localhost = (strstr(pii_cfg->analyzer_url, "localhost:") != NULL || 
                         strstr(pii_cfg->analyzer_url, "127.0.0.1:") != NULL);
      
      // Check if analyzer URL changed OR if Presidio is not initialized yet
      int url_changed = (last_analyzer_url[0] != '\0' && 
                        strcmp(last_analyzer_url, pii_cfg->analyzer_url) != 0);
      int needs_init = !presidio_is_initialized();  // Not initialized yet
      
      // Skip localhost URLs but still track them
      if (is_localhost) {
        if (url_changed || needs_init) {
          log_info("[Presidio] Skipping localhost URL '%s' - waiting for production configuration",
                   pii_cfg->analyzer_url);
        }
        // Update tracked URL even for localhost (to detect when it changes to production)
        strncpy(last_analyzer_url, pii_cfg->analyzer_url, sizeof(last_analyzer_url) - 1);
        last_analyzer_url[sizeof(last_analyzer_url) - 1] = '\0';
      } else if (url_changed || needs_init) {
        // Production URL detected
        if (url_changed) {
          log_info("[Presidio] ♻️ Analyzer URL changed: %s → %s (re-initializing...)",
                   last_analyzer_url, pii_cfg->analyzer_url);
        } else {
          log_info("[Presidio] Initializing with analyzer URL: %s", pii_cfg->analyzer_url);
        }
        
        // Initialize unified Presidio client
        int ret = presidio_v2_init(pii_cfg);
        if (ret == 0) {
          presidio_set_initialized(1);
          log_info("[Presidio] ✓ %s (analyzer=%s)", 
                   url_changed ? "Re-initialized" : "Initialized", pii_cfg->analyzer_url);
        } else {
          presidio_set_initialized(0);
          log_error("[Presidio] ❌ %s failed",
                   url_changed ? "Re-initialization" : "Initialization");
        }
        
        // Update tracked URL
        strncpy(last_analyzer_url, pii_cfg->analyzer_url, sizeof(last_analyzer_url) - 1);
        last_analyzer_url[sizeof(last_analyzer_url) - 1] = '\0';
      }
    }
    
    last_presidio_reload = now;
  }
#endif

  // LlamaFirewall: Reload configuration from shared memory (hot-reload every 5 seconds, following Presidio pattern)
#ifdef HAVE_LLAMAFIREWALL
  static time_t last_llamafirewall_reload = 0;
  static char last_llamafirewall_url[256] = {0};  // Track server URL changes

  if ((now - last_llamafirewall_reload) >= 5) {
    log_debug("[LlamaFirewall-DEBUG] Hot-reload check: now=%ld last=%ld diff=%ld",
              now, last_llamafirewall_reload, now - last_llamafirewall_reload);

    // Reload configuration from shared memory FIRST
    llamafirewall_config_reload();

    // NOW get the updated config
    llamafirewall_config_shm_t *lf_cfg = llamafirewall_config_get();
    log_debug("[LlamaFirewall-DEBUG] Config retrieved: ptr=%p", lf_cfg);

    if (lf_cfg) {
      log_debug("[LlamaFirewall-DEBUG] Config details: enabled=%d server_url='%s' block_threshold=%.2f",
                lf_cfg->enabled, lf_cfg->server_url, lf_cfg->block_threshold);

      // Check if enabled state changed or server URL changed
      int was_initialized = llamafirewall_is_initialized();
      int should_be_initialized = lf_cfg->enabled;
      int url_changed = (strcmp(last_llamafirewall_url, lf_cfg->server_url) != 0);

      log_debug("[LlamaFirewall-DEBUG] State check: was_initialized=%d should_be=%d url_changed=%d",
                was_initialized, should_be_initialized, url_changed);

      // Case 1: Need to initialize (enabled=1 but not initialized)
      if (should_be_initialized && !was_initialized) {
        log_info("[LlamaFirewall] Enabling (server=%s)...", lf_cfg->server_url);
        log_debug("[LlamaFirewall-DEBUG] Calling sockproxy_llamafirewall_init...");
        int ret = sockproxy_llamafirewall_init(lf_cfg->server_url);
        log_debug("[LlamaFirewall-DEBUG] sockproxy_llamafirewall_init returned: %d", ret);
        if (ret == 0) {
          llamafirewall_set_initialized(1);
          log_info("[LlamaFirewall] ✓ Enabled successfully (server=%s)", lf_cfg->server_url);
          strncpy(last_llamafirewall_url, lf_cfg->server_url, sizeof(last_llamafirewall_url) - 1);
          last_llamafirewall_url[sizeof(last_llamafirewall_url) - 1] = '\0';
        } else {
          llamafirewall_set_initialized(0);
          log_error("[LlamaFirewall] ❌ Failed to enable (server=%s, ret=%d)", lf_cfg->server_url, ret);
        }
      }
      // Case 2: Need to disable (enabled=0 but still initialized)
      else if (!should_be_initialized && was_initialized) {
        log_info("[LlamaFirewall] Disabling...");
        sockproxy_llamafirewall_cleanup();
        llamafirewall_set_initialized(0);
        log_info("[LlamaFirewall] ✓ Disabled");
        last_llamafirewall_url[0] = '\0';
      }
      // Case 3: Server URL changed (need to reconnect)
      else if (was_initialized && url_changed) {
        log_info("[LlamaFirewall] Server URL changed: %s → %s", last_llamafirewall_url, lf_cfg->server_url);
        sockproxy_llamafirewall_cleanup();
        int ret = sockproxy_llamafirewall_init(lf_cfg->server_url);
        if (ret == 0) {
          llamafirewall_set_initialized(1);
          log_info("[LlamaFirewall] ✓ Reconnected to new server (server=%s)", lf_cfg->server_url);
          strncpy(last_llamafirewall_url, lf_cfg->server_url, sizeof(last_llamafirewall_url) - 1);
          last_llamafirewall_url[sizeof(last_llamafirewall_url) - 1] = '\0';
        } else {
          llamafirewall_set_initialized(0);
          log_error("[LlamaFirewall] ❌ Failed to reconnect to new server (server=%s)", lf_cfg->server_url);
          last_llamafirewall_url[0] = '\0';
        }
      }
      // Case 4: Already in desired state (no action needed)
      else {
        log_debug("[LlamaFirewall-DEBUG] No action needed: was_initialized=%d should_be=%d url_changed=%d",
                  was_initialized, should_be_initialized, url_changed);
      }
    } else {
      log_debug("[LlamaFirewall-DEBUG] Config is NULL - shared memory not accessible?");
    }

    last_llamafirewall_reload = now;
  }
#endif

  //log_trace("notify fd = %d(%d) type 0x%x", fd, pfe->fd, type);
restart:
  while (type) {
    if (type & NOTI_TYPE_IN) {
      type &= ~NOTI_TYPE_IN;

      if (pfe->stype == PROXY_SOCK_LISTEN) {
        // Handle new connection acceptance (extracted for clarity)
        int result = handle_new_connection(fd, pfe, ent, &key, &rkey, &ep_sel);
        if (result < 0) {
          goto restart; // Restart requested
        } else if (result > 0) {
          continue; // Continue to next event
        }
        // result == 0: Success, continue normal flow
      } else if (pfe->stype == PROXY_SOCK_ACTIVE) {
        // Handle client data (extracted for clarity and debuggability)
        int result = handle_client_data(fd, pfe, &key, &rkey);
        if (result < 0) {
          goto restart; // Restart requested
        }
        // result == 0: Success, continue normal flow
      }
    } else if (type & NOTI_TYPE_OUT) {
      type &= ~NOTI_TYPE_OUT;
      if (pfe->stype == PROXY_SOCK_ACTIVE) {
        // ============================================================================
        // BUG FIX: Handle HTTP/2 backend EPOLLOUT events for send buffer retry
        // Check if this is a backend pfe with pending HTTP/2 send buffer
        // ============================================================================
        if (pfe->odir == 1 && pfe->backend_h2_session) {
          // This is an HTTP/2 backend connection with send buffer
          if (proxy_h2_handle_backend_writable(pfe) < 0) {
            log_error("[HTTP/2 Backend] fd=%d: Failed to drain send buffer on EPOLLOUT", fd);
            // Don't return -1 here - just log and continue
          }
        } else {
          // HTTP/1.1 cache draining (original behavior)
          PROXY_ENT_LOCK(pfe);
          proxy_xmit_cache(pfe);
          PROXY_ENT_UNLOCK(pfe);
        }
      }
    } else {
      /* Unhandled */
      return 0;
    }
  }
  return 0;
}

/* ── Stage 1: FAIL-LOUD on raw-worker fatal signals ─────────────────────────────
 * The proxy notify/teardown workers are raw pthreads, NOT Go-managed Ms. A fatal
 * signal on one (llhttp abort() on a corrupted parser, a teardown double-free, a
 * UAF deref) is SWALLOWED by the Go runtime (sigtrampgo→badsignal→raisebadsignal
 * spins in usleep): the thread never dies, never releases its locks → the ~30s
 * global-lock wedge the watchdog below has to clean up. This handler converts that
 * silent spin into an IMMEDIATE, loud, unswallowable crash (core + _exit(134)) for
 * OUR worker threads, while preserving Go's own signal semantics (nil-deref
 * recovery, traceback) for Go threads by CHAINING to the handler Go installed.
 * Toggle off with LLB_PROXY_FAILLOUD=0 (faults then fall back to the 30s wedge). */
__thread volatile sig_atomic_t g_llb_proxy_worker = 0;   /* set in each raw worker entry */
static struct sigaction g_go_prev_sa[NSIG];
static volatile sig_atomic_t g_faillood_enabled = 1;

static void
llb_async_write2(const char *s)
{
  ssize_t n = write(2, s, strlen(s));   /* async-signal-safe diagnostic */
  (void)n;
}

static void
llb_fatal_handler(int sig, siginfo_t *si, void *uc)
{
  if (g_llb_proxy_worker && g_faillood_enabled) {
    /* Our raw worker thread faulted — Go would spin on this forever. Fail LOUD:
     * a core (re-raise to default) for the exact fault site, then a guaranteed
     * unswallowable exit so docker --restart unless-stopped self-heals in ~1s. */
    llb_async_write2("[FATAL][FAILLOUD] loxilb proxy worker fatal signal — "
                     "immediate _exit(134)+core (was the ~30s lock-wedge path)\n");
    /* RCA: dump the faulting worker's C backtrace to stderr (docker
     * logs). backtrace_symbols_fd is async-signal-safe (no malloc, writes the fd
     * directly). The binary ships -g/not-stripped, so addr2line on these frames
     * pins the exact fault site even when no core lands. */
    {
      void *bt[64];
      int nbt = backtrace(bt, 64);
      llb_async_write2("[FAILLOUD] C backtrace (innermost first):\n");
      backtrace_symbols_fd(bt, nbt, 2);
    }
    signal(sig, SIG_DFL);
    raise(sig);
    _exit(134);
  }
  /* Not our thread (a Go M): chain to Go's previously-installed handler so Go keeps
   * its own crash / nil-deref-recovery behavior unchanged. */
  struct sigaction *p = &g_go_prev_sa[sig];
  if (p->sa_flags & SA_SIGINFO) {
    if (p->sa_sigaction) { p->sa_sigaction(sig, si, uc); return; }
  } else {
    if (p->sa_handler == SIG_IGN) return;
    if (p->sa_handler != SIG_DFL && p->sa_handler) { p->sa_handler(sig); return; }
  }
  signal(sig, SIG_DFL);
  raise(sig);
  _exit(134);
}

static void
llb_install_fatal_handlers(void)
{
  const char *e = getenv("LLB_PROXY_FAILLOUD");
  if (e && (e[0] == '0' || e[0] == 'n' || e[0] == 'N')) {
    g_faillood_enabled = 0;
    log_warn("[FAILLOUD] DISABLED (LLB_PROXY_FAILLOUD=%s) — worker faults will swallow→wedge ~30s→watchdog-restart", e);
  }
  int sigs[3] = { SIGSEGV, SIGABRT, SIGBUS };
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = llb_fatal_handler;
  sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;
  sigemptyset(&sa.sa_mask);
  for (int i = 0; i < 3; i++) {
    sigaction(sigs[i], NULL, &g_go_prev_sa[sigs[i]]);   /* save Go's handler */
    sigaction(sigs[i], &sa, NULL);                       /* install ours (chains for Go threads) */
  }
  log_info("[FAILLOUD] fail-loud fatal-signal handler installed (SEGV/ABRT/BUS; enabled=%d; "
           "worker faults→_exit(134)+core, Go threads chained)", g_faillood_enabled);
}

/* D2-WEDGE FIX (Layer 1 — structural; defuses the whole "C notify-worker takes a
 * fatal signal (llhttp abort() on a corrupted parser, teardown double-free, …),
 * the Go runtime swallows it (sigtrampgo→badsignal→raisebadsignal spins in usleep)
 * so the dead thread never releases its per-pfe lock → proxy_pdestroy blocks
 * forever holding the GLOBAL PROXY_LOCK → every proxy thread wedges, VIPs 000"
 * class). The process stays "Up" but serves nothing.
 *
 * This watchdog detects that wedge and hard-exits so the container
 * (docker --restart unless-stopped) self-heals in seconds — converting a permanent
 * silent wedge into a brief restart, independent of the specific fault.
 *
 * Probe = a non-blocking READ try-lock on the global proxy lock. Every
 * PROXY_*LOCK holder is a writer (PROXY_RDLOCK is unused in-tree) and writers hold
 * it for microseconds, so a 2s-spaced try-probe succeeds on a healthy proxy and
 * returns EBUSY only when a writer is stuck — exactly the wedge signature — with no
 * reader/writer-starvation false positives. (tryrdlock is base POSIX, with no
 * _GNU_SOURCE/_XOPEN feature-macro dependency unlike the timed lock variants.)
 *
 * Exit = _exit(134), NOT abort(): abort() raises SIGABRT, which on this raw C
 * thread the Go runtime can SWALLOW the same way it swallowed the original crash
 * (sigtrampgo→badsignal→raisebadsignal spin) — leaving us still wedged. _exit is a
 * direct syscall that no signal handler (Go's included) can intercept, guaranteeing
 * the process actually dies so docker --restart unless-stopped self-heals. */
static void *
proxy_liveness_watchdog_thread(void *arg)
{
  (void)arg;
  /* WD_POLL_SEC * WD_MAX_CONSECUTIVE = 2 * 15 = ~30s of continuous global-lock
   * starvation before declaring a wedge. A healthy writer holds the lock for
   * microseconds, so a 2s-spaced probe always finds a gap and never trips under
   * load — only a permanently stuck writer keeps every probe EBUSY. */
  const int WD_POLL_SEC = 2;
  const int WD_MAX_CONSECUTIVE = 15;
  int consecutive = 0;

  for (;;) {
    sleep(WD_POLL_SEC);

    int rc = pthread_rwlock_tryrdlock(&proxy_struct->lock);
    if (rc == 0) {
      pthread_rwlock_unlock(&proxy_struct->lock);
      if (consecutive >= 3) {
        log_warn("[WATCHDOG] proxy global lock recovered after %ds of contention",
                 consecutive * WD_POLL_SEC);
      }
      consecutive = 0;
      continue;
    }

    if (rc == EBUSY) {
      consecutive++;
      if ((consecutive % 3) == 0) {
        log_error("[WATCHDOG] proxy global lock contended: PROXY_LOCK busy ~%ds "
                  "(%d/%d consecutive probes)", consecutive * WD_POLL_SEC,
                  consecutive, WD_MAX_CONSECUTIVE);
      }
      if (consecutive >= WD_MAX_CONSECUTIVE) {
        log_error("[WATCHDOG] proxy data plane WEDGED ~%ds (PROXY_LOCK never released) — "
                  "_exit(134) for container restart (lock-wedge self-heal)",
                  consecutive * WD_POLL_SEC);
        /* Guaranteed, unswallowable process exit (see header comment). */
        _exit(134);
      }
      continue;
    }

    /* Unexpected rc (EINVAL/EDEADLK/EAGAIN) — not a wedge signal; reset. */
    log_warn("[WATCHDOG] pthread_rwlock_tryrdlock rc=%d (ignoring)", rc);
    consecutive = 0;
  }
  return NULL;
}

int
proxy_main(sockmap_cb_t sockmap_cb, int ktls_enabled)
{
  int startfd = PROXY_START_MAPFD;
  notify_cbs_t cbs = { 0 };
  cbs.notify = proxy_notifier;
  cbs.pdestroy = proxy_pdestroy;
  /* (R1): owner-worker resume hook for the bounded admission layer. The
   * notify worker calls this on its OWN thread when a parked client fd is woken
   * (notify_wake_worker), so the re-drive of setup_proxy_path never runs off-owner
   * (the Phase-89/90 cross-thread UAF invariant). Declared in sockproxy_internal.h. */
  cbs.resume = pd_resume_parked;

  proxy_struct = calloc(sizeof(proxy_struct_t), 1);
  if (proxy_struct == NULL) {
    assert(0);
  }
  proxy_struct->sockmap_cb = sockmap_cb;
  proxy_struct->ns = notify_ctx_new(&cbs, PROXY_MAX_THREADS);
  assert(proxy_struct->ns);

  // Initialize GLOBAL SNI certificate store
  proxy_struct->global_cert_map = NULL;
  pthread_rwlock_init(&proxy_struct->global_cert_lock, NULL);

  for (int i = 0; i < PROXY_MAX_THREADS; i++) {
    proxy_struct->mapfd[i].start = startfd;
    proxy_struct->mapfd[i].next = proxy_struct->mapfd[i].start;
    proxy_struct->mapfd[i].end  = proxy_struct->mapfd[i].start + PROXY_MAX_MAPFD;
    startfd += PROXY_MAX_MAPFD + PROXY_MAPFD_ALLOC_RETRIES;
  }

  SSL_library_init();

  // P2.2: Configure kTLS based on --ktlssupport flag
  if (ktls_enabled) {
    if (ktls_check_kernel_support() == 0) {
      g_ktls_cfg.enabled = 1;
    } else {
      g_ktls_cfg.enabled = 0;
    }
  } else {
    g_ktls_cfg.enabled = 0;
  }

  // Initialize control flag for cleanup threads
  proxy_struct->run = 1;
  
  // HTTP/HTTPS Tracing: Initialize ring buffers 
#ifdef HAVE_HTTP_TRACE
  const char *trace_enabled = getenv("LOXILB_HTTP_TRACE_ENABLED");
  if (trace_enabled && strcmp(trace_enabled, "1") == 0) {
    int ret = lxb_trace_enable();
    if (ret < 0) {
      log_error("[HTTP_TRACE] Failed to initialize trace rings: %d", ret);
    } else {
      log_info("[HTTP_TRACE] Ring buffers initialized, tracing enabled");
    }
  } else {
    log_info("[HTTP_TRACE] Tracing disabled (set LOXILB_HTTP_TRACE_ENABLED=1 to enable)");
  }
#endif

  // PII Detection: Initialize dynamic configuration (shared memory)
#ifdef HAVE_PII_DETECTION
  int ret = presidio_config_init();
  if (ret == 0) {
    log_info("[Presidio] ✓ Configuration initialized from shared memory");
    
    // Initialize Go bridge and gRPC client
    // Strategy: Try v2 first (default), fallback to v1 if unavailable
    // IMPORTANT: Skip initialization for localhost URLs - wait for real configuration
    presidio_config_shm_t *pii_cfg = presidio_config_get();
    if (pii_cfg && pii_cfg->analyzer_url[0] != '\0') {
      // Check if this is a localhost/placeholder URL - skip if so
      int is_localhost = (strstr(pii_cfg->analyzer_url, "localhost:") != NULL || 
                         strstr(pii_cfg->analyzer_url, "127.0.0.1:") != NULL);
      
      if (is_localhost) {
        presidio_set_initialized(0);
        log_info("[Presidio] Found localhost URL '%s' in shared memory - clearing and waiting for production configuration",
                 pii_cfg->analyzer_url);
        
        // Clear the localhost URL from shared memory to prevent repeated attempts
        pii_cfg->analyzer_url[0] = '\0';
        pii_cfg->anonymizer_url[0] = '\0';
        log_info("[Presidio] Cleared localhost URLs from shared memory");
      } else {
        // Initialize unified Presidio client
        log_info("[Presidio] Initializing (analyzer=%s)...", pii_cfg->analyzer_url);
        int ret = presidio_v2_init(pii_cfg);
        
        if (ret == 0) {
          presidio_set_initialized(1);
          log_info("[Presidio] ✓ Initialized successfully (analyzer=%s)", pii_cfg->analyzer_url);
        } else {
          presidio_set_initialized(0);
          log_error("[Presidio] ❌ Initialization failed - will retry when config updates");
        }
      }
    } else {
      // No analyzer URL configured yet - wait for runtime configuration
      presidio_set_initialized(0);
      log_info("[Presidio] No analyzer URL configured at startup - will initialize on first config update");
    }
    
    if (presidio_config_is_enabled() && presidio_is_initialized()) {
      log_info("[Presidio] PII detection is ENABLED (initialized)");
      presidio_config_dump();
      
      // .2: Initialize custom recognizer registry and load patterns
      if (presidio_registry_init() == 0) {
        log_info("[Presidio] ✓ Custom recognizer registry initialized");
        
        // Load custom patterns from configuration file
        int patterns_ret = presidio_registry_load_from_file(NULL);
        if (patterns_ret == 0) {
          int pattern_count = presidio_registry_count();
          if (pattern_count > 0) {
            log_info("[Presidio] Loaded %d custom recognizer(s) from configuration", pattern_count);
            
            // Register patterns with Presidio server
            int reg_ret = presidio_register_custom_patterns();
            if (reg_ret == 0) {
              log_info("[Presidio] ✓ Custom patterns registered successfully");
            } else {
              log_warn("[Presidio] Some custom patterns failed to register");
            }
          } else {
            log_debug("[Presidio] No custom patterns configured");
          }
        } else {
          log_debug("[Presidio] No custom patterns file found (will use built-in recognizers)");
        }
      } else {
        log_warn("[Presidio] Failed to initialize custom recognizer registry");
      }
    } else if (!presidio_is_initialized() && pii_cfg && pii_cfg->analyzer_url[0] != '\0') {
      log_info("[Presidio] PII detection is DISABLED (initialization failed, will retry on config update)");
    } else {
      log_info("[Presidio] PII detection is DISABLED (waiting for configuration)");
    }
  } else {
    presidio_set_initialized(0);
    log_info("[Presidio] Configuration not found at startup - will initialize when available");
  }
#endif

  // LlamaFirewall AI Security: Initialize gRPC client (following Presidio pattern)
#ifdef HAVE_LLAMAFIREWALL
  {
    // Initialize shared memory configuration first
    log_info("[LlamaFirewall] Initializing shared memory configuration...");
    int ret = llamafirewall_config_init();
    if (ret != 0) {
      log_error("[LlamaFirewall] ❌ Failed to initialize shared memory config");
      llamafirewall_set_initialized(0);
    } else {
      // Get configuration from shared memory
      llamafirewall_config_shm_t *lf_cfg = llamafirewall_config_get();
      if (lf_cfg && lf_cfg->enabled) {
        const char *server_url = lf_cfg->server_url;
        log_info("[LlamaFirewall] Initializing (server=%s, enabled=%d)...", server_url, lf_cfg->enabled);

        ret = sockproxy_llamafirewall_init(server_url);

        if (ret == 0) {
          llamafirewall_set_initialized(1);
          log_info("[LlamaFirewall] ✓ Initialized successfully (server=%s)", server_url);
          log_info("[LlamaFirewall] AI security scanning ENABLED (PromptGuard, CodeShield, Regex, HiddenASCII)");
        } else {
          llamafirewall_set_initialized(0);
          log_error("[LlamaFirewall] ❌ Initialization failed - will retry when server is available");
          log_info("[LlamaFirewall] AI security scanning DISABLED (server not available)");
        }
      } else {
        log_info("[LlamaFirewall] Disabled in configuration (enabled=%d)", lf_cfg ? lf_cfg->enabled : 0);
        llamafirewall_set_initialized(0);
      }
    }
  }
#endif

  /* Stage 1: install the fail-loud fatal-signal handler BEFORE any raw worker
   * thread starts, so a worker fault crashes loud+fast instead of wedging ~30s. */
  llb_install_fatal_handlers();

#ifdef D2_DEBUG_INJECT
  /* D2 root-fix validation: deterministic pool+generation invariant proof. */
  pfe_pool_selftest();
#endif

  pthread_create(&proxy_struct->pthr, NULL, proxy_run, NULL);

  // P2: Start draining checker thread
  pthread_create(&proxy_struct->drain_checker_thr, NULL, proxy_drain_checker_thread, NULL);
  
  // Start conversation mapping cleanup thread
  pthread_create(&proxy_struct->conversation_cleanup_thr, NULL, proxy_conversation_cleanup_thread, NULL);
  log_info("[CONV_CLEANUP] Started conversation mapping cleanup thread (TTL=%d seconds, interval=%d seconds)",
           CONVERSATION_MAPPING_TTL, CONVERSATION_CLEANUP_INTERVAL);

  // D2-wedge fix (Layer 1): start the proxy liveness watchdog — hard-exits the
  // process if the global PROXY_LOCK stays unacquirable (~30s), so a swallowed
  // C-thread fatal signal self-heals via container restart instead of wedging.
  pthread_create(&proxy_struct->watchdog_thr, NULL, proxy_liveness_watchdog_thread, NULL);
  log_info("[WATCHDOG] Started proxy liveness watchdog (lock-wedge self-heal, ~30s)");

#ifdef HAVE_HTTP_TRACE
  // PHASE 1: Start trace file cleanup thread (5-minute TTL)
  if (is_tracing_enabled()) {
    pthread_create(&proxy_struct->trace_cleanup_thr, NULL, trace_file_cleanup_thread, NULL);
    log_info("[TRACE_CLEANUP] Started trace file cleanup thread (TTL=%d sec, interval=60 sec)",
             TRACE_FILE_TTL_SEC);
  }
#endif

  return 0;
}