/*
 * Copyright (c) 2022 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * sockproxy_conn.c - Connection & FD management for LoxiLB proxy.
 *
 * refactoring: extracted from sockproxy.c.
 * Functions contained:
 *   - FD mapping (fd_in_use, get_random_fd_range, get_mapped_proxy_fd)
 *   - Socket utilities (proxy_sock_setnb, setnodelay, set_opts, server_setup)
 *   - SSL connect helper (proxy_ssl_connect)
 *   - Endpoint connection setup (proxy_setup_ep_connect)
 *   - Socket listener init (proxy_sock_init)
 *   - Endpoint lookup (proxy_find_ep)
 *   - FD context management (proxy_free_fd_ctx, proxy_try_free_fd_ctx,
 *     proxy_delete_entry__, proxy_release_fd_ctx)
 */

#include "uthash.h"
#include "log.h"
#include <linux/types.h>
#include <stdatomic.h>
#include <bpf.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <poll.h>
#include <assert.h>
#include "common_pdi.h"
#include "llb_dpapi.h"
#include "sockproxy_internal.h"
#include "sockproxy_conn.h"
#include "sockproxy_cache.h"
#include "sockproxy_lb.h"
#include "sockproxy_routing.h"
#include "sockproxy_ssl.h"
#include "sockproxy_ktls.h"
#include "sockproxy_mtls.h"
#ifdef HAVE_HTTP_TRACE
#include "lxb_trace_event.h"
#include "sockproxy_trace.h"
#endif
#include "notify.h"
#include <openssl/ssl.h>
#include <openssl/err.h>

#ifdef HAVE_PROXY_MAPFD
static int
fd_in_use(int fd)
{
  return (fcntl(fd, F_GETFD) != -1) || (errno != EBADF);
}

static int
get_random_fd_range(int r1, int r2)
{
   return r1 + rand() / (RAND_MAX / (r2 - r1 + 1) + 1);
}

int
get_mapped_proxy_fd(int fd, int check_slot)
{
  proxy_mapfd_t *mep;
  int dfd, retry;
  pid_t tid;

  if (check_slot) {
    if (notify_check_slot(proxy_struct->ns, fd)) {
      return fd;
    }
  }

  tid = gettid() % PROXY_MAX_THREADS;
  mep = &proxy_struct->mapfd[tid];

  if (mep->next < mep->start ||
      mep->next >= mep->end) {
    mep->next = mep->start;
  }

  mep->next = get_random_fd_range(mep->start, mep->end);

  for (retry = 0; retry < PROXY_MAPFD_ALLOC_RETRIES; retry++) {
    mep->next++;
    if (fd_in_use(mep->next)) {
      continue;
    }
    dfd = mep->next;
    break;
  }

  if (retry >= PROXY_MAPFD_ALLOC_RETRIES) {
    log_error("mapfd (%d) find failed", fd);
    return fd;
  }

  if (dup2(fd, dfd) < 0) {
    log_error("mapfd (%d) dup2 failed", fd);
    return fd;
  }

  close(fd);
  return dfd;
}
#else
int
get_mapped_proxy_fd(int fd, int check_slot)
{
  return fd;
}
#endif

int
proxy_skmap_key_from_fd(int fd, smap_key_t *skmap_key, int *protocol)
{
  struct sockaddr_in sin_addr;
  socklen_t sin_len;
  socklen_t optsize = sizeof(int);

  if (getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, protocol, &optsize)) {
    log_error("getsockopt failed %s\n", strerror(errno));
    return -1;
  }

  sin_len = sizeof(struct sockaddr);
  if (getsockname(fd, (struct sockaddr*)&sin_addr, &sin_len)) {
    log_error("getsockname failed %s\n", strerror(errno));
    return -1;
  }
  skmap_key->sip = sin_addr.sin_addr.s_addr;
  skmap_key->sport = sin_addr.sin_port << 16;

  if (getpeername(fd, (struct sockaddr*)&sin_addr, &sin_len)) {
    log_error("getpeername failed %s\n", strerror(errno));
    return -1;
  }
  skmap_key->dip = sin_addr.sin_addr.s_addr;
  skmap_key->dport = sin_addr.sin_port << 16;

  return 0;
}


// Task 2.2: kTLS integration with sockmap
// The old proxy_sock_init_ktls() stub has been removed.
// We now use ktls_try_offload() from sockproxy_ktls.c which properly extracts
// TLS session keys and enables kernel TLS offload.
// This allows sockmap to work with HTTPS connections by having the kernel
// handle encryption/decryption transparently.

static void
proxy_sock_setnb(int fd)
{
  int rc, flags;

  flags = fcntl(fd, F_GETFL, 0);
  if (flags == -1) {
    flags = 0;
  }

  rc = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
  if (rc == -1) {
    assert(0);
  }
}

static void
proxy_sock_setnodelay(int fd)
{
  int flag = 1;
  int rc = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
                    (char *) &flag, sizeof(int));
  if (rc == -1) {
    log_error("setsockopt: failed to set tcp nodelay");
  }
}

void
proxy_sock_set_opts(int fd, uint8_t protocol)
{
  struct timeval timeout;
  
  proxy_sock_setnb(fd);

  // CRITICAL FIX: Add socket timeouts to prevent hung connections
  // With high concurrency (512 concurrent), some connections may stall
  // 300s read timeout = max time to wait for LLM response
  timeout.tv_sec = 300;   // 5 minutes for LLM inference
  timeout.tv_usec = 0;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  
  // 60s write timeout = max time to send response
  timeout.tv_sec = 60;
  timeout.tv_usec = 0;
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

  switch (protocol) {
  case IPPROTO_TCP:
    proxy_sock_setnodelay(fd);
    
    // Enable TCP keepalive to detect dead connections
    {
      int keepalive = 1;
      int keepidle = 120;   // Start probes after 120s idle
      int keepintvl = 30;   // Probe every 30s
      int keepcnt = 3;      // 3 failed probes = dead connection
      
      setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
      setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
      setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl));
      setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt));
    }
    break;
  default:
    break;
  }
}

static int
proxy_server_setup(int fd, uint32_t server, uint16_t port, uint8_t protocol)
{
  struct sockaddr_in addr;
  int rc, on = 1, flags;

#ifdef HAVE_SCTP_STREAM_CONF 
  struct sctp_initmsg im;
  if (protocol == IPPROTO_SCTP) {
    memset(&im, 0, sizeof(im));
    im.sinit_num_ostreams = 1;
    im.sinit_max_instreams = 1;
    im.sinit_max_attempts = 4;
    rc = setsockopt(fd, IPPROTO_SCTP, SCTP_INITMSG, &im, sizeof(im));
    if (rc < 0) {
      close(fd);
      return -1;
    }
  }
#endif

  rc = setsockopt(fd, SOL_SOCKET,  SO_REUSEADDR, (char *)&on, sizeof(on));
  if (rc < 0) {
    close(fd);
    return -1;
  }

  flags = fcntl(fd, F_GETFL, 0);
  if (flags == -1) {
    flags = 0;
  }

  rc = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
  if (rc == -1) {
    assert(0);
  }

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = port;
  addr.sin_addr.s_addr = server;
  rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
  if (rc < 0) {
    log_error("bind failed %s", strerror(errno));
    close(fd);
    return -1; 
  }

  rc = listen(fd, 32);
  if (rc < 0) {
    log_error("listen failed %s", strerror(errno));
    close(fd);
    return -1;
  }

  log_info("sock-proxy setup done");
  return 0;
}

static int
proxy_ssl_connect(int fd, void *ssl)
{
  int to = 10;
  int err;
  int ssl_err;
  int sret;
  struct pollfd pfds = { 0 };

  assert(ssl);
  SSL_set_fd(ssl, fd);

  pfds.fd = fd;

  while (to--) {
    err = SSL_connect(ssl);
    if (err == 1) {
      // TLS handshake completed successfully

      // Log negotiated TLS version and cipher
      int tls_version = SSL_version(ssl);
      const char *version_str __attribute__((unused)) = SSL_get_version(ssl);
      const char *cipher_str __attribute__((unused)) = SSL_get_cipher_name(ssl);
      // Try kTLS for TLS 1.2, skip for TLS 1.3
      if (tls_version == TLS1_2_VERSION) {
        // Try to enable kernel TLS offload
        int ktls_ret __attribute__((unused)) = ktls_try_offload(ssl, fd, 1 /* client side */);
      } 

      break;
    }

    ssl_err = SSL_get_error(ssl, err);
    if (ssl_err == SSL_ERROR_WANT_READ) {
      pfds.events = POLLIN;
      sret = poll(&pfds, 1, 500);
      if (sret == -1) {
        return -1;
      }
    } else if (ssl_err == SSL_ERROR_WANT_WRITE) {
      pfds.events = POLLOUT;
      sret = poll(&pfds, 1, 500);
      if (sret == -1) {
        return -1;
      }
    } else {
      log_error("Unable to ssl-connect %s",
        ERR_error_string(ERR_get_error(), NULL));

      return -1;
    }
  }

  return 0;
}

/* Build an IPv4 PROXY protocol v2 header (28 bytes) into buf. All addr/port args
 * are in network byte order. Returns bytes written, or 0 if buf too small.
 * Shared by the L7 fullproxy HTTP/1 (setup_proxy_path) and HTTP/2 backend paths. */
int
proxy_build_ppv2_v4(uint8_t *buf, size_t bufsz, uint32_t sip, uint16_t sport,
                    uint32_t dip, uint16_t dport)
{
  static const uint8_t sig[12] = { 0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D,
                                   0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A };
  if (bufsz < 28) return 0;
  memcpy(buf, sig, 12);
  buf[12] = 0x21;                    /* ver_cmd: version 2, PROXY command */
  buf[13] = 0x11;                    /* family: AF_INET + STREAM (TCP) */
  buf[14] = 0x00; buf[15] = 0x0c;    /* len = 12 (network order) */
  memcpy(buf + 16, &sip, 4);         /* src_addr (client) */
  memcpy(buf + 20, &dip, 4);         /* dst_addr (VIP) */
  memcpy(buf + 24, &sport, 2);       /* src_port */
  memcpy(buf + 26, &dport, 2);       /* dst_port */
  return 28;
}

/* Send the whole buffer, handling short writes / EAGAIN on the non-blocking fd. */
static int
proxy_send_all(int fd, const void *buf, size_t len)
{
  const uint8_t *p = buf;
  size_t off = 0;

  while (off < len) {
    ssize_t n = send(fd, p + off, len - off, MSG_NOSIGNAL);
    if (n > 0) { off += (size_t)n; continue; }
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
      struct pollfd pf = { .fd = fd, .events = POLLOUT|POLLERR };
      if (poll(&pf, 1, 500) <= 0 || (pf.revents & POLLERR)) return -1;
      continue;
    }
    return -1;
  }
  return 0;
}

int
proxy_setup_ep_connect(uint32_t epip, uint16_t epport, uint8_t protocol,
                       void *ssl_ctx, void **ssl, proxy_fd_ent_t *pfe,
                       const void *pp2hdr, int pp2len)
{
  int fd, rc;
  struct sockaddr_in epaddr;
  struct pollfd pfds = { 0 };

  memset(&epaddr, 0, sizeof(epaddr));
  epaddr.sin_family = AF_INET;
  epaddr.sin_port = epport;
  epaddr.sin_addr.s_addr = epip;

  /* SOCK_CLOEXEC: loxilb's control plane forks helpers via Go os/exec (ipsec
   * start, systemctl, sysctl, bash -c for bgp). os/exec relies on close-on-exec
   * to avoid leaking descriptors, and fds created here in C do not have it by
   * default, so without this flag every proxy socket is inherited by those
   * children. The strongswan starter then daemonizes and outlives loxilb still
   * holding them.
   */
  fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, protocol);
  if (fd < 0) {
    log_error("proxy_setup_ep_connect: socket() failed: %s", strerror(errno));
    return -1;
  }

  fd = get_mapped_proxy_fd(fd, 1);
  proxy_sock_set_opts(fd, protocol);

  /* C-7: SSE backend keepalive — override TCP_KEEPIDLE when the rule has a
   * non-zero backend_keepalive_sec. This keeps conntrack entries alive through
   * cloud NAT gateways that silently drop long-idle TCP connections.
   * Failure is non-fatal: log and continue (socket may be in CLOSE_WAIT). */
  if (pfe && pfe->backend_keepalive_sec > 0 && protocol == IPPROTO_TCP) {
    int kv = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &kv, sizeof(kv)) < 0) {
      log_warn("[AIGateway] setsockopt SO_KEEPALIVE on backend fd=%d failed: %s",
               fd, strerror(errno));
    }
    kv = (int)pfe->backend_keepalive_sec;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &kv, sizeof(kv)) < 0) {
      log_warn("[AIGateway] setsockopt TCP_KEEPIDLE=%d on backend fd=%d failed: %s",
               kv, fd, strerror(errno));
    }
  }

  if (connect(fd, (struct sockaddr*)&epaddr, sizeof(epaddr)) < 0) {
    if (errno != EINPROGRESS) {
      log_error("connect failed %s:%u", inet_ntoa(*(struct in_addr *)(&epip)), ntohs(epport));
      close(fd);
      return -1;
    }

    pfds.fd = fd;
    pfds.events = POLLOUT|POLLERR;

    /* per-listener backend connect timeout in ms. The value
     * rides proxy_arg (timeout_member_connect_ms), reached here via the client pfe's
     * proxy_map_ent (pfe->head). It is L7-gated (has_l7_policy): the AI peer and every
 * un-configured listener keep the historic 500ms literal byte-for-byte (
     * Pitfall 3 — NOT Octavia's 5000ms). 0 ⇒ 500 even when an L7 policy is attached. */
    int connect_to_ms = 500;
    {
      proxy_map_ent_t *cnode = pfe ? (proxy_map_ent_t *)pfe->head : NULL;
      if (cnode && cnode->has_l7_policy && cnode->arg_ptr &&
          cnode->arg_ptr->timeout_member_connect_ms > 0) {
        connect_to_ms = (int)cnode->arg_ptr->timeout_member_connect_ms;
      }
    }

    rc = poll(&pfds, 1, connect_to_ms);
    if (rc < 0) {
      log_error("connect poll %s:%u(%s)", inet_ntoa(*(struct in_addr *)(&epip)), ntohs(epport), strerror(errno));
      close(fd);
      return -1;
    }

    if (rc == 0) {
      log_error("connect %s:%u(timedout)", inet_ntoa(*(struct in_addr *)(&epip)), ntohs(epport));
      close(fd);
      return -1;
    }

    if (pfds.revents & POLLERR) {
      log_error("connect %s:%u(errors)", inet_ntoa(*(struct in_addr *)(&epip)), ntohs(epport));
      close(fd);
      return -1;
    }
  }

  /* PROXY protocol v2 header must be the FIRST bytes on the backend connection,
   * before any client payload and before the (optional) backend TLS handshake,
   * since PROXY protocol is a layer below TLS. Sending here on the freshly
   * connected socket is stream-level, hence immune to the GSO issue that breaks
   * the eBPF inline insertion (fullnat path). L7 fullproxy uses this path. */
  if (pp2hdr && pp2len > 0) {
    if (proxy_send_all(fd, pp2hdr, (size_t)pp2len)) {
      log_error("ppv2 send failed %s:%u", inet_ntoa(*(struct in_addr *)(&epip)), ntohs(epport));
      close(fd);
      return -1;
    }
  }

  if (ssl_ctx) {
    // CRITICAL: Check if ssl pointer is NULL before dereferencing
    if (!ssl) {
      log_error("proxy_setup_ep_connect: CRITICAL - ssl parameter is NULL but ssl_ctx provided!");
      log_error("proxy_setup_ep_connect: Cannot store SSL handle, closing connection");
      close(fd);
      return -1;
    }
    
    void *nssl = SSL_new(ssl_ctx);
    assert(nssl);
    
    if (proxy_ssl_connect(fd, nssl)) {
      log_error("ssl-connect %s:%u(failed)", inet_ntoa(*(struct in_addr *)(&epip)), ntohs(epport));
      close(fd);
      SSL_free(nssl);
      return -1;
    }
    *ssl = nssl;
    
#ifdef HAVE_HTTP_TRACE
    // Emit backend TLS handshake event (for *→HTTPS proxy modes)
    // Note: pfe may be NULL if called without context, skip in that case
    if (pfe && is_tracing_enabled()) {
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("[TRACE_EVENT_TLS_HS_BACKEND] fd=%d odir=%d | "
                "trace_id=%016lx%016lx parent_span=%016lx root_span=%016lx | "
                "timestamp=%lu flags=0x%02x (TLS_BACKEND will be set) | "
                "proxy_mode=%s→HTTPS",
                pfe->fd, pfe->odir,
                pfe->trace_id_hi, pfe->trace_id_lo, pfe->parent_span_id, pfe->root_span_id,
                get_timestamp_ns(), pfe->trace_flags,
                pfe->ssl ? "HTTPS" : "HTTP");
#endif
      // Temporarily set odir=1 to indicate backend connection for correct flag
      int saved_odir = pfe->odir;
      pfe->odir = 1;
      emit_trace_event(pfe, LXB_EVENT_TLS_HS, 0);
      pfe->odir = saved_odir;
    }
#endif
  }
  
#ifdef HAVE_HTTP_TRACE
  // NOTE: UP_START event should be emitted AFTER backend pfe is created and trace context is copied
  // See setup_proxy_path() where npfe2 is created - UP_START is emitted there with proper context
#endif
  
  return fd;
}

int
proxy_sock_init(uint32_t IP, uint16_t port, uint8_t protocol)
{
  int listen_sd;

  switch (protocol) {
  case IPPROTO_TCP:
  case IPPROTO_SCTP:
    /* SOCK_CLOEXEC is load-bearing here: this is the VIP LISTEN socket. A
     * forked helper that inherits it keeps the port bound after loxilb exits,
     * so the next loxilb start fails `bind: Address already in use` on every
     * L7 rule while L4 comes up clean — a silent, partial outage.
     */
    listen_sd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, protocol);
    break;
  default:
    return -1;
  }

  if (listen_sd > 0) {
    if (!proxy_server_setup(listen_sd, IP, port, protocol)) {
      return listen_sd;
    }
    close(listen_sd); 
  }

  return -1;
}

int
proxy_find_ep(uint32_t xip, uint16_t xport, uint8_t protocol, 
              uint32_t *epip, uint16_t *epport, uint8_t *epprotocol)
{
#if 0
  int sel = 0;
  proxy_ent_t ent = { 0 };
  proxy_map_ent_t *node = proxy_struct->head;
   
  ent.xip = xip;
  ent.xport = xport;
  ent.protocol = protocol;

  PROXY_LOCK();

  while (node) {

    if (cmp_proxy_ent(&node->key, &ent)) {
      if (!node->val.n_eps) {
        PROXY_UNLOCK();
        return -1;
      }
      sel = node->val.ep_sel % node->val.n_eps;
      if (sel >= MAX_PROXY_EP) break;
      *epip = node->val.eps[sel].xip; 
      *epport = node->val.eps[sel].xport; 
      *epprotocol = node->val.eps[sel].protocol;
      node->val.ep_sel++;
      PROXY_UNLOCK();
      return 0;
    }
    node = node->next;
  }

  PROXY_UNLOCK();
#endif
  return -1;
}

/* ===========================================================================
 * D2 root fix — pfe pool (grow-only freelist + generation), B-split variant.
 *
 * Root cause being eliminated: the notify poll loop captures a pfe pointer under
 * NOTI_LOCK then dereferences it AFTER releasing the lock; the concurrent close
 * path free()s and the allocator reuses that heap chunk in the gap → use-after-
 * free on the recycled pfe (corrupt llhttp parser → abort, lock-wedge).
 *
 * Mechanism: the pfe STRUCT (the "shell") is never returned to the heap. It is
 * recycled through this freelist, so its address is permanently valid and a stale
 * dispatch that derefs it is memory-safe. Each shell carries a monotonic `gen`
 * bumped on every recycle; proxy_notifier captures the gen at registration time
 * and drops any event whose gen no longer matches the shell's current gen — so a
 * recycled-then-reused slot can never be mistaken for the connection the event
 * was queued for. B-split: only the small shell is pooled; the 1MB rcvbuf is
 * malloc/free'd per connection so high-water residency stays bounded (~KB/shell).
 *
 * The pool lock is a LEAF mutex — pfe_alloc/pfe_recycle take no other lock while
 * holding it — so it introduces no ordering relationship with NOTI/PROXY/ENT
 * (invariant I5 preserved).
 * ========================================================================= */
static pthread_mutex_t pfe_pool_lock = PTHREAD_MUTEX_INITIALIZER;
static proxy_fd_ent_t *pfe_pool_free;   /* freelist head, linked via ->next */
static unsigned long   pfe_pool_total;  /* shells ever created (high-water)  */
static unsigned long   pfe_pool_live;   /* shells currently checked out      */

proxy_fd_ent_t *
pfe_alloc(void)
{
  proxy_fd_ent_t *pfe;
  uint64_t gen;

  pthread_mutex_lock(&pfe_pool_lock);
  pfe = pfe_pool_free;
  if (pfe) {
    pfe_pool_free = pfe->pool_next;   /* pop a recycled shell (gen preserved) */
  }
  pfe_pool_live++;
  pthread_mutex_unlock(&pfe_pool_lock);

  /* (AC-4): the global total-footprint gauge — incremented here, the
   * ONE point loxilb commits to holding a connection's footprint (the pfe
   * checkout), and decremented (>0-guarded) on pfe_recycle, exactly balanced with
   * pfe_pool_live above. Every OOM bail-out below mirrors the matching pfe_pool_live
   * decrement so the gauge can never leak (a leak would wedge accept() intake).
   *
   * 93-06 (default-off): maintain this gauge ONLY when the total-inflight bound is
   * enabled (LLB_PD_MAX_TOTAL_INFLIGHT > 0). With the knob unset there is NO hot-
   * path mutation here ⇒ the pfe_alloc/recycle path is byte-identical to pre-93-06
   * (the proven-stable p93d2). pd_max_total_inflight() is getenv-once cached and
   * CONSTANT for the process lifetime, so this inc and the dec in pfe_recycle are
   * gated identically and always stay paired 1:1. */
  if (pd_max_total_inflight() != 0)
    atomic_fetch_add_explicit(&global_stats.pd_admission_total_inflight, 1,
                              memory_order_relaxed);

  if (!pfe) {
    /* Grow: fresh shell, gen starts at 0 (calloc-zeroed). */
    pfe = calloc(1, sizeof(*pfe));
    if (!pfe) {
      pthread_mutex_lock(&pfe_pool_lock);
      pfe_pool_live--;
      pthread_mutex_unlock(&pfe_pool_lock);
      /* mirror the pfe_pool_live dec: this checkout never produced a live shell.
       * Gated identically to the inc above (default-off when the bound is unset). */
      if (pd_max_total_inflight() != 0 &&
          atomic_load_explicit(&global_stats.pd_admission_total_inflight,
                               memory_order_relaxed) > 0)
        atomic_fetch_sub_explicit(&global_stats.pd_admission_total_inflight, 1,
                                  memory_order_relaxed);
      log_error("pfe_alloc: shell OOM");
      return NULL;
    }
    pthread_mutex_lock(&pfe_pool_lock);
    pfe_pool_total++;
    pthread_mutex_unlock(&pfe_pool_lock);
  } else {
    /* Recycled shell: preserve the monotonic gen across the zeroing so a stale
     * dispatcher still holding an old (priv,gen) can never alias the new
     * connection's gen on this same address. */
    gen = atomic_load_explicit(&pfe->gen, memory_order_relaxed);
    memset(pfe, 0, sizeof(*pfe));
    atomic_store_explicit(&pfe->gen, gen, memory_order_relaxed);
  }

  /* B-split: 1MB receive buffer on the heap. calloc to preserve the zero-init
   * semantics of the previously-inline array. */
  pfe->rcvbuf = calloc(1, SP_SOCK_MSG_LEN);
  if (!pfe->rcvbuf) {
    log_error("pfe_alloc: rcvbuf OOM");
    pfe_recycle(pfe);   /* return the shell to the pool (rcvbuf already NULL) */
    return NULL;
  }

  /* -1 = "not parked" (the memset above zeroes it, but 0 is a valid
   * prefill EP index, so a zeroed park_ep_idx would falsely look parked-on-EP0). */
  pfe->park_ep_idx = -1;

  return pfe;
}

void
pfe_recycle(proxy_fd_ent_t *pfe)
{
  if (!pfe) {
    return;
  }

  /* Free the per-connection heap buffer. The shell is NEVER free()d — its address
   * must stay valid for any in-flight stale notify dispatch. */
  if (pfe->rcvbuf) {
    free(pfe->rcvbuf);
    pfe->rcvbuf = NULL;
  }

  /* Bump the generation BEFORE the shell re-enters the freelist (release pairs
   * with the acquire-load in proxy_notifier): any event captured against the old
   * gen now mismatches and is dropped (invariants I2/I3). */
  atomic_fetch_add_explicit(&pfe->gen, 1, memory_order_release);

  pthread_mutex_lock(&pfe_pool_lock);
  pfe->pool_next = pfe_pool_free;
  pfe_pool_free = pfe;
  if (pfe_pool_live > 0) {
    pfe_pool_live--;
  }
  pthread_mutex_unlock(&pfe_pool_lock);

  /* (AC-4): release the global total-footprint gauge, paired 1:1 with
   * the pfe_alloc inc above (the single client-close owner path). >0-guarded to
   * match the pfe_pool_live underflow guard / the active_conns idiom. Gated on the
   * bound being enabled (default-off byte-identical when LLB_PD_MAX_TOTAL_INFLIGHT
   * is unset), paired identically with the pfe_alloc inc. */
  if (pd_max_total_inflight() != 0 &&
      atomic_load_explicit(&global_stats.pd_admission_total_inflight,
                           memory_order_relaxed) > 0)
    atomic_fetch_sub_explicit(&global_stats.pd_admission_total_inflight, 1,
                              memory_order_relaxed);
}

/* (AC-4): read-only snapshot of the pfe-pool gauges for the bounded-
 * footprint soak observability (the soak_footprint.sh sampler reads these from a
 * periodic log line — see the proxy_drain_checker_thread emit). Lock-guarded read
 * of the leaf-mutex statics; never mutates. */
void
pfe_pool_snapshot(unsigned long *live, unsigned long *total)
{
  pthread_mutex_lock(&pfe_pool_lock);
  if (live)  *live  = pfe_pool_live;
  if (total) *total = pfe_pool_total;
  pthread_mutex_unlock(&pfe_pool_lock);
}

#ifdef D2_DEBUG_INJECT
/* D2 root-fix VALIDATION ONLY (-DD2_DEBUG_INJECT). Deterministic, self-contained
 * proof of the pool+generation invariants using the REAL pfe_alloc/pfe_recycle on
 * throwaway shells (no notifier/fdlist involvement — safe). Logs PASS/FAIL once at
 * proxy startup. Proves: (1) the shell address is REUSED across recycle (so a
 * stale dispatcher's pointer stays memory-valid — the property that makes the
 * deref in proxy_notifier safe); (2) gen advances monotonically across recycle,
 * so a captured-then-recycled (priv,gen) is rejected; (3) the per-connection
 * rcvbuf is freed+reallocated (B-split) and writable each cycle (a UAF/OOB here
 * aborts under the fail-loud handler / ASan). */
void
pfe_pool_selftest(void)
{
  proxy_fd_ent_t *p = pfe_alloc();
  if (!p) { log_error("[PFE_SELFTEST] FAIL: pfe_alloc #1 returned NULL"); return; }
  uint64_t gen0 = atomic_load_explicit(&p->gen, memory_order_relaxed);
  void *rcv0 = p->rcvbuf;
  /* touch the whole heap rcvbuf — OOB/UAF would trip ASan / fail-loud */
  memset(p->rcvbuf, 0xD2, SP_SOCK_MSG_LEN);
  uintptr_t addr = (uintptr_t)p;

  pfe_recycle(p);   /* gen++, rcvbuf freed, shell pooled */

  proxy_fd_ent_t *q = pfe_alloc();
  if (!q) { log_error("[PFE_SELFTEST] FAIL: pfe_alloc #2 returned NULL"); return; }
  uint64_t gen1 = atomic_load_explicit(&q->gen, memory_order_relaxed);
  int reused   = ((uintptr_t)q == addr);          /* same shell address reused */
  int gen_adv  = (gen1 != gen0);                  /* generation advanced */
  int stale_rejected = (gen1 != gen0);            /* old (q,gen0) would mismatch q->gen */
  int rcv_fresh = (q->rcvbuf != NULL && q->rcvbuf != rcv0 ? 1 : (q->rcvbuf != NULL));
  if (q->rcvbuf) memset(q->rcvbuf, 0x2D, SP_SOCK_MSG_LEN);  /* fresh buffer writable */

  log_info("[PFE_SELFTEST] %s shell_reused=%d gen %llu->%llu (advanced=%d) stale_rejected=%d rcvbuf_realloced=%d",
           (reused && gen_adv && stale_rejected && rcv_fresh) ? "PASS" : "FAIL",
           reused, (unsigned long long)gen0, (unsigned long long)gen1,
           gen_adv, stale_rejected, rcv_fresh);

  pfe_recycle(q);
}
#endif

static void
proxy_free_fd_ctx(proxy_fd_ent_t *pfe)
{
  if (pfe->used <= 0) {
#ifdef HAVE_PII_DETECTION
    // Free deferred PII masking buffer if allocated
    if (pfe->pii_masked_text) {
      free(pfe->pii_masked_text);
      pfe->pii_masked_text = NULL;
    }
#endif
    /* D2 root fix: recycle the shell into the pool (frees rcvbuf, bumps gen)
     * instead of free()ing it to the heap. */
    pfe_recycle(pfe);
  }
}

void
proxy_try_free_fd_ctx(proxy_fd_ent_t *pfe)
{
  pfe->used--;
  proxy_free_fd_ctx(pfe);
}

int
proxy_delete_entry__(proxy_ent_t *ent, proxy_arg_t *arg, int *mfd,
                     void **ssl_ctx, void **ssl_epctx)
{
  struct proxy_map_ent *prev = NULL;
  struct proxy_map_ent *node;
  proxy_epval_t *tepval;
  int epcount = 0;
  char ephash_key[512];  // P6: Composite key for hash table lookup

  // P6: Build composite key (host|path|model) or shorter form for backward compat
  build_ephash_key(ephash_key, sizeof(ephash_key),
                   arg->host_url,           // "api.example.com"
                   arg->path_prefix,        // "/v1/users" or "" for backward compat
                   arg->model_name);        // "llama-70b" or "" for wildcard pool

  node = proxy_struct->head;

  while (node) {

    if (cmp_proxy_ent(&node->key, ent)) {
      break;
    }
    prev = node;
    node = node->next;
  }

  if (node) {

    HASH_FIND_STR(node->val.ephash, ephash_key, tepval);
    if (tepval == NULL) {
      log_error("sockproxy: %s:%u (%s) not found in ephash", 
                inet_ntoa(*(struct in_addr *)&ent->xip), ntohs(ent->xport), ephash_key);
      return -EINVAL;
    }

#ifdef HAVE_DP_GPU_ROUTING
    // P1.2/P1.3: Cleanup CHWBL resources
    if (tepval->hash_ring) {
      chwbl_destroy_ring(tepval->hash_ring);
      tepval->hash_ring = NULL;
    }
    if (tepval->chwbl_config) {
      free(tepval->chwbl_config);
      tepval->chwbl_config = NULL;
    }
#endif /* HAVE_DP_GPU_ROUTING */

    // P/D Session stickiness cleanup
    {
      pd_session_mapping_t *sm, *sm_tmp;
      pthread_rwlock_wrlock(&tepval->pd_session_lock);
      HASH_ITER(hh, tepval->pd_session_map, sm, sm_tmp) {
        HASH_DEL(tepval->pd_session_map, sm);
        free(sm);
      }
      tepval->pd_session_map = NULL;
      pthread_rwlock_unlock(&tepval->pd_session_lock);
      pthread_rwlock_destroy(&tepval->pd_session_lock);
    }

    /* cleanup radix trie */
    if (tepval->pd_trie) {
      pthread_rwlock_wrlock(&tepval->pd_trie_lock);
      pd_trie_free(tepval->pd_trie);
      tepval->pd_trie = NULL;
      pthread_rwlock_unlock(&tepval->pd_trie_lock);
      pthread_rwlock_destroy(&tepval->pd_trie_lock);
    }

    HASH_DEL(node->val.ephash, tepval);

    epcount = HASH_COUNT(node->val.ephash);
    if (epcount > 0) {
      return 0;
    }

    /* Production fix: when the last routing rule for this VIP:port is deleted,
     * keep the TCP listener socket open.  Incoming connections will be served
     * HTTP 503 by the existing "no matching model pool" path in sockproxy_ep.c
     * rather than getting a TCP connection-refused.  This prevents curl(000)
     * and provides a clean HTTP error to callers.
     *
     * We still clean up per-VIP conversation state here because it is no
     * longer valid, but we intentionally skip node-unlinking and fd-closing
     * so the listening socket and its fdlist entry remain live.
     */
    // CRITICAL FIX: Cleanup conversation mappings to prevent memory leak
    conversation_mapping_t *mapping, *tmp;
    if (pthread_rwlock_trywrlock(&node->val.conv_lock) == 0) {
      HASH_ITER(hh, node->val.conv_map, mapping, tmp) {
        HASH_DEL(node->val.conv_map, mapping);
        free(mapping);
      }
      node->val.conv_map = NULL;
      pthread_rwlock_unlock(&node->val.conv_lock);
    }
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[CONV_CLEANUP] Freed all conversation mappings for proxy %s:%u (listener kept)",
              inet_ntoa(*(struct in_addr *)&ent->xip), ntohs(ent->xport));
    log_info("[PROXY_RULE_DEL] Last rule deleted for %s:%u — listener kept open, will return 503",
             inet_ntoa(*(struct in_addr *)&ent->xip), ntohs(ent->xport));
#endif

    /* Do NOT unlink the node — keep it in the proxy list so the listening
     * socket fd remains registered with the notifier and new connections are
     * accepted.  The empty ephash causes sockproxy_ep to send HTTP 503. */

    /* Do NOT return main_fd — caller would close() it which would stop the
     * listener. We intentionally leave it open. */

    // Note: Global SSL certificates are NOT cleaned up here
    // They remain available for other proxies that may use the same hostname
    
    // Cleanup heap-allocated proxy_arg if present
    // Order matters to prevent double-free:
    //   1. Clear SSL_CTX ex_data pointer FIRST (so OpenSSL callback won't free it)
    //   2. Then manually free the memory
    // This prevents race: proxy_pdestroy() calls SSL_CTX_free() -> callback attempts free
    if (node->arg_ptr) {
#ifdef HAVE_MTLS
      // For mTLS mode: Clear ex_data to prevent OpenSSL callback from freeing
      if (node->val.ssl_ctx && g_ssl_ctx_proxy_arg_index >= 0) {
        SSL_CTX_set_ex_data((SSL_CTX*)node->val.ssl_ctx, g_ssl_ctx_proxy_arg_index, NULL);
      }
#endif
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("[MEM] Freeing heap-allocated proxy_arg=%p for %s:%u",
                (void*)node->arg_ptr,
                inet_ntoa(*(struct in_addr *)&ent->xip), ntohs(ent->xport));
#endif
      free(node->arg_ptr);
      node->arg_ptr = NULL;
    }

    /* This node is freed after cleanup in proxy_pdestroy() */
    //free(node);
  } else {
    return -EINVAL;
  }

  return 0;
}

void
proxy_release_fd_ctx(proxy_fd_ent_t *fd_ent, int reset)
{
  proxy_destroy_xmitcache(fd_ent);

#ifdef HAVE_DP_GPU_ROUTING
  // P1.3/P3.5: Decrement CHWBL/WRR_HASH load counter when connection closes
  if (fd_ent->epv && fd_ent->ep_num >= 0) {
    proxy_epval_t *epv = (proxy_epval_t *)fd_ent->epv;
    if ((epv->select == PROXY_SEL_CHWBL || epv->select == PROXY_SEL_WRR_HASH) && epv->chwbl_config) {
      chwbl_dec_load(epv->chwbl_config, fd_ent->ep_num);
    }
  }
#endif /* HAVE_DP_GPU_ROUTING */

  // Reset HTTP parsing state
  fd_ent->http_pok = 0;
  fd_ent->http_hok = 0;
  fd_ent->http_hvok = 0;
  fd_ent->http_body_complete = 0;
  fd_ent->http_content_length = 0;
  fd_ent->is_streamable = 0;
  fd_ent->rcv_off = 0;
  fd_ent->parsed_off = 0;
  fd_ent->last_header_name[0] = '\0';
  memset(&fd_ent->prefix_key, 0, sizeof(fd_ent->prefix_key));  // P0.2: Reset prefix
  fd_ent->has_conv_id = 0;  // P0.3: Reset conversation ID flag
  memset(fd_ent->conversation_id, 0, sizeof(fd_ent->conversation_id));  // P0.3: Clear conversation ID
  fd_ent->x_model_header[0] = '\0';  // Reset X-Model header

  // Reset vLLM request ID state
  fd_ent->vllm_request_id[0] = '\0';
  fd_ent->has_vllm_request_id = 0;
  fd_ent->request_id_injected = 0;

  // Reset P/D orchestration state and free buffers
  pd_cleanup(fd_ent);

  // CRITICAL FIX: Reset session learning state
  fd_ent->needs_session_learning = 0;
  memset(fd_ent->learned_session_id, 0, sizeof(fd_ent->learned_session_id));
  fd_ent->has_custom_session_header = 0;
  memset(fd_ent->custom_session_header_value, 0, sizeof(fd_ent->custom_session_header_value));

  if (fd_ent->ssl) {
    if (!fd_ent->ssl_err)
      SSL_shutdown(fd_ent->ssl);
  }

  if (fd_ent->fd > 0) {
    shutdown(fd_ent->fd, SHUT_RDWR);
  }

  if (reset) {
    /* (ASan-found conc=128 root cause): the P/D reapers
     * (check_draining_endpoints / force_close_endpoint_connections) call
     * pd_teardown_legs() — which close()s the client fd and sets
     * fd_ent->fd = -1 — BEFORE invoking proxy_release_fd_ctx(pfe, 1).
     * Previously the unlink (proxy_reset_fd_list) lived INSIDE the `fd > 0`
     * branch, so for those callers it was SKIPPED: under NDEBUG the
     * half-cleaned pfe (pd buffers already freed by pd_cleanup above) stayed
     * linked in ent->val.fdlist, and the relay/notify path later touched the
     * dangling node -> `malloc(): mismatching next->prev_size` heap corruption;
     * under assert-enabled/ASan builds the old `else assert(0)` aborted instead.
     * Always perform the unlink on reset, and close the fd only if it is still
     * open. proxy_reset_fd_list is a pure list unlink (it never reads fd_ent->fd
     * and never frees), so it is correct and safe when fd == -1. The node free
     * remains owned by proxy_try_free_fd_ctx (refcounted), unchanged. */
    log_trace("sockproxy fd %d reset", fd_ent->fd);
    proxy_reset_fd_list(fd_ent->head, fd_ent);
    if (fd_ent->fd > 0) {
      close(fd_ent->fd);
      fd_ent->fd = -1;
    }
    if (fd_ent->ssl) {
      SSL_free(fd_ent->ssl);
      fd_ent->ssl = NULL;
    }
  }
}

