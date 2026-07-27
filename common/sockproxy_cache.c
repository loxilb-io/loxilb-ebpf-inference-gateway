/*
 * Copyright (c) 2024 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */

/*
 * sockproxy_cache.c -- Xmit cache, backpressure management, and logging helpers.
 *
 * Extracted from sockproxy.c per sockproxy_refactoring_plan.md §6.1
 *
 * Functions extracted:
 *   pfe_ent_accouting         -- per-connection byte/packet accounting
 * cmp_proxy_ent -- entry equality (temp here; moves to conn in)
 *   proxy_add_xmitcache       -- enqueue a data buffer to the xmit cache (static)
 *   proxy_log / proxy_log_always  -- internal debug logging helpers
 *   proxy_destroy_xmitcache   -- free all cached entries (static)
 *   proxy_list_xmitcache      -- debug list (static, unused)
 *   proxy_check_release_backpressure -- adaptive backpressure release
 *   proxy_xmit_cache          -- drain cache loop (EPOLLOUT, SSL, plain send)
 *
 * Include order MUST be:
 *   uthash.h  ->  log.h  ->  sockproxy_internal.h  ->  sockproxy_cache.h
 */

#include "uthash.h"
#include "log.h"
/* System headers required by llb_dpapi.h (BPF types, POSIX types, sockets) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <stdatomic.h>
#include <bpf.h>
#include "common_pdi.h"
#include "llb_dpapi.h"        /* provides full struct llb_sockmap_key definition */
#include "sockproxy_internal.h"
#include "sockproxy_cache.h"
#ifdef HAVE_HTTP_TRACE
#include "lxb_trace_event.h"
#include "sockproxy_trace.h"
#endif

/* Remaining system headers needed by this module */
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "notify.h"
#include "sockproxy_ktls.h"

void
pfe_ent_accouting(proxy_fd_ent_t *pfe, uint64_t bc, int txdir)
{
  proxy_epval_t *epv __attribute__((unused)) = pfe->epv;
  int n = pfe->ep_num;

  if (!txdir) {
    pfe->nrb += bc;
    pfe->nrp++;
    if (epv && n >= 0 && n < MAX_PROXY_EP) {
      epv->ep_stats[n].nrb += bc;
      epv->ep_stats[n].nrp++;
    } 
  } else {
    pfe->ntb += bc;
    pfe->ntp++;
    
    if (epv && n >= 0 && n < MAX_PROXY_EP) {
      epv->ep_stats[n].ntb += bc;
      epv->ep_stats[n].ntp++;
    } 
  }
}

/* cmp_proxy_ent: promoted to non-static in; will move to sockproxy_conn.c in.
 * See sockproxy_refactoring_plan.md §6.2 */
bool
cmp_proxy_ent(proxy_ent_t *e1, proxy_ent_t *e2)
{
  if (e1->xip == e2->xip &&
      e1->xport == e2->xport &&
      e1->protocol == e2->protocol) {
    return true;
  }
  return false;
}

#if 0
static bool
cmp_proxy_val(proxy_val_t *v1, proxy_val_t *v2)
{
  int i;
  for (i = 0; i < MAX_PROXY_EP; i++) {
    if (!cmp_proxy_ent(&v1->eps[i], &v2->eps[i])) {
      return false;
    }
  }
  return true;
}
#endif

int
proxy_add_xmitcache(proxy_fd_ent_t *ent, uint8_t *cache, size_t len)
{
  struct proxy_cache *new;
  struct proxy_cache *curr;
  struct proxy_cache **prev;
  int need_epollout = 0;

  // Allocate and prepare new cache entry BEFORE taking lock (reduces lock hold time)
  new  = calloc(1, sizeof(struct proxy_cache)+len);
  assert(new);
  new->cache = new->data;
  memcpy(new->cache, cache, len);
  new->off = 0;
  new->len = len;

  // NOW take lock - only for the linked list manipulation and counter updates
  PROXY_ENT_CLOCK(ent);

  // Check if we need EPOLLOUT INSIDE the lock (prevents race with cache drain)
  if (ent->cache_head == NULL) {
    need_epollout = 1;
  }

  curr = ent->cache_head;
  prev = &ent->cache_head;

  while (curr) {
    prev = &curr->next;
    curr = curr->next;
  }

  if (prev) {
    *prev = new;
  }

  // Update cache tracking
  ent->cache_count++;
  ent->cache_total_size += len;

  // ADAPTIVE BACKPRESSURE: Use lower threshold for chunked responses
  // Chunked encoding is fragile - lower threshold prevents SSL timeout corruption
  // Binary transfers can tolerate higher cache without corruption risk
  size_t high_water = ent->is_chunked_response ? 
                      PROXY_CACHE_HIGH_WATER_CHUNKED : PROXY_CACHE_HIGH_WATER;

  // Check and set backpressure AFTER updating size (handles large packets that jump over threshold)
  // This is NOT a "logic error" - it's the normal path for setting backpressure
  if (ent->cache_total_size >= high_water && !ent->cache_backpressure) {
    ent->cache_backpressure = 1;

    // METRICS: Increment cache high water triggers (Metric #5)
    atomic_fetch_add(&global_stats.cache_high_water_triggers, 1);

#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_warn("[BACKPRESSURE_SET] fd=%d: Cache reached HIGH_WATER after add | "
             "size=%.2f MB >= %.2f MB, backpressure activated (chunked=%d)",
             ent->fd,
             ent->cache_total_size / (1024.0 * 1024.0),
             high_water / (1024.0 * 1024.0),
             ent->is_chunked_response);
#endif
  }

  PROXY_ENT_CUNLOCK(ent);

  // Enable EPOLLOUT AFTER releasing lock (prevents deadlock)
  if (need_epollout) {
    notify_add_ent(proxy_struct->ns, ent->fd,
        NOTI_TYPE_IN|NOTI_TYPE_OUT|NOTI_TYPE_HUP, ent, ent->gen);
  }

  return 0;
}

#define HAVE_PROXY_DEBUG
#ifdef HAVE_PROXY_DEBUG
void
proxy_log(const char *str, smap_key_t *key)
{
  char ab1[INET6_ADDRSTRLEN];
  char ab2[INET6_ADDRSTRLEN];

  inet_ntop(AF_INET, (struct in_addr *)&key->dip, ab1, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, (struct in_addr *)&key->sip, ab2, INET_ADDRSTRLEN);
  log_trace("%s %s:%u -> %s:%u", str,
            ab1, ntohs((key->dport >> 16)), ab2, ntohs(key->sport >> 16));
}
#else
#define proxy_log(arg1, arg2)
#endif

void
proxy_log_always(const char *str, smap_key_t *key)
{
  char ab1[INET6_ADDRSTRLEN];
  char ab2[INET6_ADDRSTRLEN];

  inet_ntop(AF_INET, (struct in_addr *)&key->dip, ab1, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, (struct in_addr *)&key->sip, ab2, INET_ADDRSTRLEN);
#ifdef HAVE_PROXY_EXTRA_DEBUG
  log_debug("%s %s:%u -> %s:%u", str,
            ab1, ntohs((key->dport >> 16)), ab2, ntohs(key->sport >> 16));
#endif
}

void
proxy_destroy_xmitcache(proxy_fd_ent_t *ent)
{
  struct proxy_cache *curr = ent->cache_head;
  struct proxy_cache *next;

  while (curr) {
    next = curr->next;
    free(curr);
    curr = next;
  }
  ent->cache_head = NULL;
  
  // Reset cache tracking
  ent->cache_count = 0;
  ent->cache_total_size = 0;
  ent->cache_backpressure = 0;
  ent->read_paused = 0;
}

static void __attribute__((unused))
proxy_list_xmitcache(proxy_fd_ent_t *ent)
{
  int i = 0;
  struct proxy_cache *curr = ent->cache_head;

  while (curr) {
    curr = curr->next;
    i++;
  }
}

// Helper function to check and release backpressure
// Called whenever cache is drained or before returning from cache operations
void
proxy_check_release_backpressure(proxy_fd_ent_t *ent)
{
  if (!ent->cache_backpressure) {
    return; // No backpressure to release
  }

  // ADAPTIVE BACKPRESSURE: Use appropriate threshold for chunked vs non-chunked
  size_t low_water = ent->is_chunked_response ? 
                     PROXY_CACHE_LOW_WATER_CHUNKED : PROXY_CACHE_LOW_WATER;

  if (ent->cache_total_size > low_water) {
    // Still above LOW_WATER, keep backpressure active
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[BACKPRESSURE_STILL_ACTIVE] fd=%d: Cache still above LOW_WATER | "
              "size=%.2f MB > %.2f MB threshold (chunked=%d)",
              ent->fd,
              ent->cache_total_size / (1024.0 * 1024.0),
              low_water / (1024.0 * 1024.0),
              ent->is_chunked_response);
#endif
    return;
  }

  // Cache drained below LOW_WATER, release backpressure
  ent->cache_backpressure = 0;
  ent->read_paused = 0;
#ifdef HAVE_PROXY_EXTRA_DEBUG
  log_warn("[BACKPRESSURE_RELEASED] fd=%d: Cache drained to LOW_WATER | "
           "size=%.2f MB <= %.2f MB threshold, RESUMING READS",
           ent->fd,
           ent->cache_total_size / (1024.0 * 1024.0),
           PROXY_CACHE_LOW_WATER / (1024.0 * 1024.0));
#endif
  
  // CRITICAL: Re-enable reading on the SOURCE connection that feeds this destination
  // For backend (odir==1), find the client connection (odir==0)
  // For client (odir==0), find the backend connection (odir==1)
  if (ent->head) {
    proxy_map_ent_t *map_ent = (proxy_map_ent_t *)ent->head;
    proxy_fd_ent_t *source_pfe = map_ent->val.fdlist;
    int target_odir = (ent->odir == 0) ? 1 : 0;  // Find opposite direction
    
    // Find the source connection that feeds this destination
    while (source_pfe) {
      if (source_pfe->odir == target_odir && 
          (source_pfe->rfd_ent[0] == ent || source_pfe->rfd_ent[1] == ent)) {
        // Always re-enable reading, regardless of read_paused flag
        // This ensures data flow resumes even if pause flag got out of sync
        source_pfe->read_paused = 0;
        notify_add_ent(proxy_struct->ns, source_pfe->fd,
                      NOTI_TYPE_IN|NOTI_TYPE_HUP, source_pfe, source_pfe->gen);
#ifdef HAVE_PROXY_EXTRA_DEBUG
        log_warn("[BACKPRESSURE_RESUME_SOURCE] src_fd=%d (odir=%d) → dst_fd=%d (odir=%d): "
                 "RE-ENABLED EPOLLIN after cache drained",
                 source_pfe->fd, source_pfe->odir, ent->fd, ent->odir);
#endif
        break;
      }
      source_pfe = source_pfe->next;
    }
    
    if (!source_pfe) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("⚠️  [BACKPRESSURE_NO_SOURCE] fd=%d (odir=%d): Could not find source connection to resume",
                ent->fd, ent->odir);
#endif
    }
  }
}

// CRITICAL FIX: Backpressure Race Condition Resolution
// Previous Issue: proxy_check_release_backpressure() was called during cache drain loop
// when send/SSL_write returned EAGAIN/WANT_WRITE. This caused premature EPOLLIN re-enablement
// on the source connection while destination socket was still blocked, creating a tight loop:
// drain partial → resume reads → WANT_WRITE → pause → repeat (no net forward progress).
//
// Fix: Only call proxy_check_release_backpressure() AFTER successful cache drain completion
// (line 700), not during mid-drain failures (removed from lines 547, 577). This ensures
// backpressure is maintained until the destination socket is confirmed writable via EPOLLOUT.
int
proxy_xmit_cache(proxy_fd_ent_t *ent)
{
  struct proxy_cache *curr;
  struct proxy_cache *tmp = NULL;
  int rstev = 0;
  int n = 0;
  size_t initial_size __attribute__((unused)) = ent->cache_total_size;
  int initial_count __attribute__((unused)) = ent->cache_count;

  PROXY_ENT_CLOCK(ent);

  // CRITICAL FIX: Timeout enforcement for graceful shutdown
  // If peer EOF was set more than 30 seconds ago, force close to prevent indefinite hang
  #define GRACEFUL_SHUTDOWN_TIMEOUT 30
  if (ent->peer_eof && ent->eof_timestamp > 0) {
    time_t now = time(NULL);
    time_t elapsed = now - ent->eof_timestamp;

    if (elapsed >= GRACEFUL_SHUTDOWN_TIMEOUT) {
      log_warn("⏰ [GRACEFUL_TIMEOUT] fd=%d: Peer EOF timeout (%ld seconds) - forcing close with cache_count=%u (%.2f MB)",
               ent->fd, elapsed, ent->cache_count, ent->cache_total_size / (1024.0 * 1024.0));

      // Force close connection after timeout
      shutdown(ent->fd, SHUT_RDWR);
      PROXY_ENT_CUNLOCK(ent);
      return -1;
    }
  }

  // CRITICAL FIX: Set draining flag to prevent race condition
  // This prevents direct send bypass while cache is being drained
  ent->cache_draining = 1;

  curr = ent->cache_head;
  if (ent->cache_head == NULL) {
    // Cache is empty, nothing to drain
    ent->cache_draining = 0;  // Clear draining flag
    PROXY_ENT_CUNLOCK(ent);
    return 0;
  }
  rstev = 1;

  while (curr) {
    if (!ent->ssl || ent->ktls_enabled) {
      // Use raw socket I/O for plaintext or kTLS-offloaded connections
      n = send(ent->fd, (uint8_t *)(curr->cache) + curr->off, curr->len, MSG_DONTWAIT|MSG_NOSIGNAL);

      if (n <= 0) {
        // Socket not ready, can't drain more
        // CRITICAL FIX: Don't release backpressure here - we're mid-drain!
        // Releasing backpressure now would re-enable source reads while the destination
        // socket is still blocked, causing a tight loop with no forward progress.
        // Wait for EPOLLOUT event to confirm socket is truly writable.

        // CRITICAL: DON'T clear cache_draining flag here!
        // Draining is PAUSED (not complete). Clearing the flag allows race conditions
        // where new data might bypass the cache queue, causing out-of-order delivery
        // which corrupts chunked transfer encoding.
        // The flag will be cleared on successful completion (line 748) or fatal error.

        PROXY_ENT_CUNLOCK(ent);

        // CRITICAL FIX: Re-register EPOLLOUT for plaintext EAGAIN
        // Without this, socket will never wake up to retry cache drain
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          log_debug("🔄 [EPOLLOUT_REREGISTER] fd=%d: Re-registering EPOLLOUT for plaintext EAGAIN", ent->fd);
          notify_add_ent(proxy_struct->ns, ent->fd,
                        NOTI_TYPE_IN|NOTI_TYPE_OUT|NOTI_TYPE_HUP, ent, ent->gen);
        }

        return -1;
      }
      if (n != curr->len) {
        curr->off += n;
        curr->len -= n;
        pfe_ent_accouting(ent, n, 1);
        continue;
      }
    } else {
      // Use OpenSSL for userspace TLS
      n = SSL_write(ent->ssl, (uint8_t *)(curr->cache) + curr->off, curr->len);
      if (n <= 0) {
        // SSL socket not ready, can't drain more
        // CRITICAL FIX: Don't release backpressure here - we're mid-drain!
        // Releasing backpressure now would re-enable source reads while the SSL
        // socket is still blocked, causing a tight loop with no forward progress.
        // Wait for EPOLLOUT event to confirm socket is truly writable.

        int ssl_err = SSL_get_error(ent->ssl, n);
        log_trace("ssl-write-cache-retry fd=%d ssl_err=%d", ent->fd, ssl_err);

        switch (SSL_get_error(ent->ssl, n)) {
        case SSL_ERROR_NONE:
          // CRITICAL: DON'T clear cache_draining here either!
          // SSL_ERROR_NONE means this write succeeded, but we might have more cache entries.
          // Draining continues in the while loop. Flag cleared at completion (line 748).
          PROXY_ENT_CUNLOCK(ent);
          return 0;
        case SSL_ERROR_WANT_WRITE:
          // CRITICAL: DON'T clear cache_draining flag here!
          // Draining is PAUSED (not complete). Clearing the flag allows race conditions
          // where new data might bypass the cache queue, causing out-of-order delivery
          // which corrupts chunked transfer encoding.
          // The flag will be cleared on successful completion (line 748) or fatal error.

          // METRICS: Track partial cache drains (TIER 3, Metric #11)
          atomic_fetch_add(&global_stats.cache_drain_partial, 1);

          // CRITICAL FIX: Apply backpressure on peer when SSL socket is blocked
          // If SSL can't write (buffer full), stop reading from peer to prevent cache buildup
          // Set backpressure flag - the peer connection will check this and pause reads
          if (!ent->cache_backpressure) {
            ent->cache_backpressure = 1;
#ifdef HAVE_PROXY_EXTRA_DEBUG
            log_warn("[SSL_BACKPRESSURE_SET] fd=%d: SSL_ERROR_WANT_WRITE - activating backpressure to pause peer reads (cache_count=%u, size=%.2f MB)",
                     ent->fd, ent->cache_count, ent->cache_total_size / (1024.0 * 1024.0));
#endif
          }

          PROXY_ENT_CUNLOCK(ent);
          notify_add_ent(proxy_struct->ns, ent->fd,
            NOTI_TYPE_IN|NOTI_TYPE_HUP|NOTI_TYPE_OUT, ent, ent->gen);
          return -1;
        case SSL_ERROR_WANT_READ:
          // CRITICAL: DON'T clear cache_draining flag here!
          // SSL_ERROR_WANT_READ is temporary (renegotiation). Clearing allows race conditions.
          // Draining is PAUSED, not complete. Flag cleared at completion (line 748) or fatal error.

          PROXY_ENT_CUNLOCK(ent);

          // CRITICAL FIX: Register EPOLLIN to wake up when SSL can read
          // SSL_ERROR_WANT_READ means SSL needs to read before it can write (e.g., renegotiation)
          log_debug("🔄 [EPOLLIN_REGISTER] fd=%d: SSL_ERROR_WANT_READ - registering EPOLLIN for renegotiation", ent->fd);
          notify_add_ent(proxy_struct->ns, ent->fd,
                        NOTI_TYPE_IN|NOTI_TYPE_HUP, ent, ent->gen);

          return -1;
        case SSL_ERROR_SYSCALL:
        case SSL_ERROR_SSL:
          ent->cache_draining = 0;  // Clear draining flag
#ifdef HAVE_PROXY_EXTRA_DEBUG
          log_debug("❌ [DRAIN_FLAG_CLEAR] fd=%d: cache_draining=0 (SSL_ERROR_SYSCALL/SSL)",
                    ent->fd);
#endif
          PROXY_ENT_CUNLOCK(ent);
          ent->ssl_err = 1;
          return -1;
        case SSL_ERROR_ZERO_RETURN:
          log_trace("ssl-wr-zero-ret %s",
              ERR_error_string(ERR_get_error(), NULL));
        default:
          SSL_shutdown(ent->ssl);
          ent->cache_draining = 0;  // Clear draining flag
#ifdef HAVE_PROXY_EXTRA_DEBUG
          log_debug("❌ [DRAIN_FLAG_CLEAR] fd=%d: cache_draining=0 (SSL default error)",
                    ent->fd);
#endif
          PROXY_ENT_CUNLOCK(ent);
          return -1;
        }
      }
      
      // CRITICAL FIX: Handle partial writes for SSL (same as plaintext path)
      if (n != curr->len) {
        curr->off += n;
        curr->len -= n;
        pfe_ent_accouting(ent, n, 1);
        continue;  // Retry remaining data
      }
      
      // CRITICAL FIX: Account for full write before freeing
      pfe_ent_accouting(ent, n, 1);
    }

    tmp = curr;

    curr = curr->next;
    ent->cache_head = curr;

    if (tmp) {
      // CRITICAL FIX: Must calculate freed size from tmp, not original_len
      // original_len from line 522 may not match tmp->off+tmp->len if entry was modified
      size_t freed_size = tmp->off + tmp->len;
      
      // Update cache tracking when freeing entries
      ent->cache_count--;
      ent->cache_total_size -= freed_size;
      
      // Debug: Log the free operation to detect accounting bugs
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("🗑️ [CACHE_ENTRY_FREE] fd=%d: Freed cache entry | "
                "off=%u len=%zu freed=%zu | "
                "cache_count=%u cache_size=%.2f MB",
                ent->fd, tmp->off, tmp->len, freed_size,
                ent->cache_count, ent->cache_total_size / (1024.0 * 1024.0));
#endif
      
      free(tmp);
    }
  }

  ent->cache_head = NULL;

  // 🔍 DEBUG: Log successful complete drain

  // Check and release backpressure if cache has drained enough
  proxy_check_release_backpressure(ent);

  // SAFETY: If cache is now completely empty, force-clear backpressure
  // This prevents stuck states where flag is set but cache is empty
  if (ent->cache_total_size == 0 && ent->cache_head == NULL) {
    if (ent->cache_backpressure || ent->read_paused) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_warn("⚠️  [CACHE_DRAIN_FORCE_CLEAR] fd=%d: Cache fully empty, force-clearing stuck flags | "
               "backpressure=%d, read_paused=%d",
               ent->fd, ent->cache_backpressure, ent->read_paused);
#endif
      ent->cache_backpressure = 0;
      ent->read_paused = 0;
      
      // Also try to re-enable source connection
      if (ent->head) {
        proxy_map_ent_t *map_ent = (proxy_map_ent_t *)ent->head;
        proxy_fd_ent_t *source_pfe = map_ent->val.fdlist;
        int target_odir = (ent->odir == 0) ? 1 : 0;
        
        while (source_pfe) {
          if (source_pfe->odir == target_odir && 
              (source_pfe->rfd_ent[0] == ent || source_pfe->rfd_ent[1] == ent)) {
            source_pfe->read_paused = 0;
            notify_add_ent(proxy_struct->ns, source_pfe->fd,
                          NOTI_TYPE_IN|NOTI_TYPE_HUP, source_pfe, source_pfe->gen);
#ifdef HAVE_PROXY_EXTRA_DEBUG
            log_warn("🔓 [FORCE_RESUME_SOURCE] fd=%d: Force re-enabled EPOLLIN on source after full cache drain",
                     source_pfe->fd);
#endif
            break;
          }
          source_pfe = source_pfe->next;
        }
      }
    }
  }

  // CRITICAL FIX: Clear draining flag on successful completion
  ent->cache_draining = 0;

#ifdef HAVE_PROXY_EXTRA_DEBUG
  log_debug("✅ [DRAIN_FLAG_CLEAR] fd=%d: cache_draining=0 (drain completed successfully)",
            ent->fd);
#endif

  PROXY_ENT_CUNLOCK(ent);

  if (rstev) {
    // Cache was drained - if now empty, stop monitoring for EPOLLOUT
    if (ent->cache_head == NULL) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("📭 [CACHE_EMPTY] fd=%d: Cache fully drained, removing EPOLLOUT monitoring", ent->fd);
#endif

#ifdef HAVE_HTTP_TRACE
      // Emit REQ_END event (response fully sent to client)
      // Only emit for client-facing connections (odir=0)
      if (ent->odir == 0 && is_tracing_enabled()) {
        uint64_t duration_us = 0;
        if (ent->req_start_ts > 0) {
          uint64_t now = get_timestamp_ns();
          duration_us = (now - ent->req_start_ts) / 1000;
        }
#ifdef HAVE_PROXY_EXTRA_DEBUG
        log_debug("[TRACE_EVENT_REQ_END] fd=%d odir=%d | "
                  "trace_id=%016lx%016lx parent_span=%016lx root_span=%016lx | "
                  "req_start=%lu duration_us=%lu | "
                  "flags=0x%02x proxy_mode=%s ssl=%p ktls=%d | "
                  "bytes_tx=%lu packets_tx=%lu",
                  ent->fd, ent->odir,
                  ent->trace_id_hi, ent->trace_id_lo, ent->parent_span_id, ent->root_span_id,
                  ent->req_start_ts, duration_us,
                  ent->trace_flags,
                  ent->ssl ? (ent->ktls_enabled ? "HTTPS(kTLS)" : "HTTPS") : "HTTP",
                  ent->ssl, ent->ktls_enabled,
                  ent->ntb, ent->ntp);
#endif
        emit_trace_event(ent, LXB_EVENT_REQ_END, duration_us);
      }
#endif

      // CRITICAL FIX: Check if peer closed and we should now close gracefully
      if (ent->peer_eof) {
        log_info("✅ [GRACEFUL_CLOSE] fd=%d: Cache drained after peer EOF - closing connection gracefully",
                 ent->fd);

        // Shutdown connection gracefully (peer already closed)
        shutdown(ent->fd, SHUT_RDWR);

        // Return -1 to trigger connection cleanup
        return -1;
      }

      notify_add_ent(proxy_struct->ns, ent->fd,
            NOTI_TYPE_IN|NOTI_TYPE_HUP, ent, ent->gen);
    } else {
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("📬 [CACHE_NOT_EMPTY] fd=%d: Cache partially drained, keeping EPOLLOUT monitoring", ent->fd);
#endif
      notify_add_ent(proxy_struct->ns, ent->fd,
            NOTI_TYPE_IN|NOTI_TYPE_OUT|NOTI_TYPE_HUP, ent, ent->gen);
    }
  }

  return 0;
}
