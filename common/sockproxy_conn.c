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
#include "sockproxy_connect.h"
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
  /* low-half convention: net-order port in the low 16 bits of the __be32.
   * Must match llb_kern_sockmap.c / llb_kern_sockstream.c key construction
   * (remote_port >> 16, bpf_htonl(local_port) >> 16). Consumers read the port
   * back with a plain (uint16_t) truncation, never >> 16. */
  skmap_key->sport = sin_addr.sin_port;

  if (getpeername(fd, (struct sockaddr*)&sin_addr, &sin_len)) {
    log_error("getpeername failed %s\n", strerror(errno));
    return -1;
  }
  skmap_key->dip = sin_addr.sin_addr.s_addr;
  skmap_key->dport = sin_addr.sin_port;

  return 0;
}

void
proxy_skmap_snapshot_store(proxy_skmap_key_snapshot_t *dst, const smap_key_t *src)
{
  dst->dip = src->dip;
  dst->sip = src->sip;
  dst->dport = src->dport;
  dst->sport = src->sport;
}

void
proxy_skmap_snapshot_restore(smap_key_t *dst, const proxy_skmap_key_snapshot_t *src)
{
  memset(dst, 0, sizeof(*dst));
  dst->dip = src->dip;
  dst->sip = src->sip;
  dst->dport = src->dport;
  dst->sport = src->sport;
}

void
proxy_peer_map_clear(proxy_fd_ent_t *pfe)
{
  pfe->peer_map_pair_installed = 0;
  pfe->peer_map_req_installed = 0;
  pfe->peer_map_resp_installed = 0;
  pfe->peer_map_req_verdict = 0;
  pfe->peer_map_resp_verdict = 0;
  pfe->peer_map_req_pending = 0;
  memset(&pfe->peer_map_client_key, 0, sizeof(pfe->peer_map_client_key));
  memset(&pfe->peer_map_backend_key, 0, sizeof(pfe->peer_map_backend_key));
}

/* Adds what the kernel carried for an accelerated pair to the rule endpoint's
 * statistics, the way pfe_ent_accouting would have counted it in userspace:
 * the response direction as bytes transmitted to the client (ntb/ntp, which is
 * the endpoint counter), the request direction as bytes received from it
 * (nrb/nrp). They are credited to the client entry's endpoint, because the
 * backend entry carries no epv (see setup_proxy_path). Atomic, because the
 * caller holds the backend entry's lock but not always the client's. */
static void
proxy_peer_map_fold(proxy_fd_ent_t *be, const struct llb_sockmap_peer *req,
                    const struct llb_sockmap_peer *resp)
{
  proxy_fd_ent_t *client = be->n_rfd > 0 ? be->rfd_ent[0] : NULL;
  proxy_epval_t *epv;
  int n;

  if (!client || !client->epv) {
    return;
  }
  epv = client->epv;
  n = client->ep_num;
  if (n < 0 || n >= MAX_PROXY_EP) {
    return;
  }
  if (resp->segs) {
    __atomic_fetch_add(&epv->ep_stats[n].ntb, resp->bytes, __ATOMIC_RELAXED);
    __atomic_fetch_add(&epv->ep_stats[n].ntp, resp->segs, __ATOMIC_RELAXED);
  }
  if (req->segs) {
    __atomic_fetch_add(&epv->ep_stats[n].nrb, req->bytes, __ATOMIC_RELAXED);
    __atomic_fetch_add(&epv->ep_stats[n].nrp, req->segs, __ATOMIC_RELAXED);
  }
}

void
proxy_peer_map_delete(proxy_fd_ent_t *pfe)
{
  smap_key_t client_key;
  smap_key_t backend_key;
  struct llb_sockmap_peer req_last = { 0 };
  struct llb_sockmap_peer resp_last = { 0 };

  if (!pfe->peer_map_pair_installed || proxy_struct->peer_map_cb == NULL) {
    return;
  }

  proxy_skmap_snapshot_restore(&client_key, &pfe->peer_map_client_key);
  proxy_skmap_snapshot_restore(&backend_key, &pfe->peer_map_backend_key);

  /* sock_verdict_map first: a socket left there without its peer_map entry would
   * make the verdict SK_PASS, which can stall the reader (llb_kern_sockmap.c). */
  if (pfe->peer_map_req_verdict && proxy_struct->verdict_map_cb &&
      proxy_struct->verdict_map_cb(&client_key, -1, 0) != 0) {
    log_error("Sockmap: sock_verdict_map delete failed for client of fd=%d", pfe->fd);
  }

  if (pfe->peer_map_resp_verdict && proxy_struct->verdict_map_cb &&
      proxy_struct->verdict_map_cb(&backend_key, -1, 0) != 0) {
    log_error("Sockmap: sock_verdict_map delete failed for backend fd=%d", pfe->fd);
  }

  /* Delete only the directions that were actually installed (see the directional
   * sockMapMode gating in setup_proxy_path). Both sockets are out of
   * sock_verdict_map by now, so the counters read here are final but for a
   * verdict that was already running. */
  if (pfe->peer_map_req_installed &&
      proxy_struct->peer_map_cb(&client_key, NULL, 0, &req_last) != 0) {
    log_error("Sockmap: peer_map delete failed for client fd=%d", pfe->fd);
  }

  if (pfe->peer_map_resp_installed &&
      proxy_struct->peer_map_cb(&backend_key, NULL, 0, &resp_last) != 0) {
    log_error("Sockmap: peer_map delete failed for backend fd=%d", pfe->fd);
  }

  proxy_peer_map_fold(pfe, &req_last, &resp_last);
  proxy_peer_map_clear(pfe);
}

/* Activates the request direction of a pair installed by setup_proxy_path: puts
 * the client socket into sock_verdict_map, after which the kernel moves client
 * bytes straight to the backend. It must wait until userspace holds no client
 * byte the backend has not received, or the bytes the client sends next would
 * overtake them: nothing left in rcvbuf, no streamed request body outstanding,
 * and an empty send cache on the backend. Callers invoke it wherever one of
 * those conditions can become true; it does nothing until all of them hold.
 *
 * Bytes that reach the socket between the last read and the add stay in its
 * receive queue; the next read of the client fd runs them through the verdict,
 * so the client fd must stay armed for reads after activation.
 *
 * If the add fails, most commonly because the client has half-closed and the
 * socket is no longer ESTABLISHED, the request entry is removed and the
 * connection stays on the userspace relay. */
void
proxy_peer_map_activate_req(proxy_fd_ent_t *client_pfe)
{
  proxy_fd_ent_t *be;
  smap_key_t client_key;
  int ret;

  if (!client_pfe || client_pfe->odir != 0 || client_pfe->n_rfd <= 0) {
    return;
  }

  be = client_pfe->rfd_ent[0];
  if (!be || !be->peer_map_req_pending || proxy_struct->verdict_map_cb == NULL ||
      proxy_struct->peer_map_cb == NULL) {
    return;
  }

  if (client_pfe->rcv_off != 0 || client_pfe->stream_body_remaining != 0 ||
      client_pfe->pd_phase != PD_PHASE_NONE ||
      be->cache_total_size != 0 || be->cache_head != NULL) {
    return;
  }

  be->peer_map_req_pending = 0;
  proxy_skmap_snapshot_restore(&client_key, &be->peer_map_client_key);

  ret = proxy_struct->verdict_map_cb(&client_key, client_pfe->fd, 1);
  if (ret == 0) {
    be->peer_map_req_verdict = 1;
    return;
  }

  if (proxy_struct->peer_map_cb(&client_key, NULL, 0, NULL) == 0) {
    be->peer_map_req_installed = 0;
    be->peer_map_pair_installed = be->peer_map_resp_installed;
  }

  if (ret == -EOPNOTSUPP) {
    log_debug("Sockmap: client fd=%d no longer established, request direction stays on the userspace relay",
              client_pfe->fd);
  } else {
    log_error("Sockmap: sock_verdict_map add failed for client fd=%d (%d), request direction stays on the userspace relay",
              client_pfe->fd, ret);
  }
}

/* How many connections currently carry a deferred teardown. The health thread
 * ticks fast so a deferred close lands within tens of milliseconds, and this is
 * what keeps that cheap: while it is zero the tick neither takes PROXY_LOCK nor
 * walks a single connection. */
static _Atomic int defer_close_pending;

uint64_t
proxy_mono_ms(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000L);
}

/* Idempotent: a connection deferred twice is counted once, and keeps its first
 * deadline so a repeated EOF cannot postpone its close indefinitely. */
void
proxy_defer_close_mark(proxy_fd_ent_t *pfe)
{
  if (!pfe || pfe->defer_close_ms != 0) {
    return;
  }
  pfe->defer_close_ms = proxy_mono_ms();
  if (pfe->defer_close_ms == 0) {
    pfe->defer_close_ms = 1;      /* 0 means "not deferred" */
  }
  atomic_fetch_add(&defer_close_pending, 1);
}

/* Called both when the sweep finishes a deferred close and when the pfe is
 * recycled, since a deferred connection can also end on its own first (the
 * backend completing, the client closing for real). Whichever comes first
 * decrements; the other sees 0 and does nothing. */
void
proxy_defer_close_clear(proxy_fd_ent_t *pfe)
{
  if (!pfe || pfe->defer_close_ms == 0) {
    return;
  }
  pfe->defer_close_ms = 0;
  atomic_fetch_sub(&defer_close_pending, 1);
}

int
proxy_defer_close_pending(void)
{
  return atomic_load(&defer_close_pending);
}

/* Backend legs whose connect is still in flight, kept so the health thread's
 * fast tick can skip its walk while there are none. */
static _Atomic int connect_pending_legs;

void
proxy_connect_pending_mark(proxy_fd_ent_t *pfe)
{
  if (!pfe || pfe->connect_pending) {
    return;
  }
  pfe->connect_pending = 1;
  atomic_fetch_add(&connect_pending_legs, 1);
}

/* Idempotent: the leg's completion, a teardown that reaches it first and the
 * reaper all call this; whichever comes first counts. */
void
proxy_connect_pending_clear(proxy_fd_ent_t *pfe)
{
  if (!pfe || !pfe->connect_pending) {
    return;
  }
  pfe->connect_pending = 0;
  atomic_fetch_sub(&connect_pending_legs, 1);
}

int
proxy_connect_pending_legs(void)
{
  return atomic_load(&connect_pending_legs);
}

/* proxy_sockmap_drop_accel — close the connections of one rule that the kernel
 * is currently accelerating, and report how many were closed.
 *
 * Why this exists. The verdict decides on the peer_map lookup alone, so a rule
 * changed or deleted applies to new connections while an accelerated pair keeps
 * redirecting until it closes. That is deliberate: the verdict must never return
 * SK_PASS on a socket in sock_verdict_map, which is what exposed it to the
 * tcp_bpf copied_seq defect. It leaves the operator with no way to stop
 * acceleration on live connections, and this is that way.
 *
 * It CLOSES rather than unmaps. Removing a socket from the sockhash while
 * traffic flows races the strp_wq path and can drop bytes mid-connection;
 * closing cannot, because the connection is over either way. The client sees a
 * closed connection and reconnects, and the new connection follows the rule as
 * it now stands.
 *
 * Only accelerated pairs are touched. A connection of the same rule that was
 * never paired — one that has not sent a request yet, or an h2 connection,
 * which installs no pair — keeps running on the userspace relay.
 *
 * shutdown() is called under PROXY_LOCK, the way the health path's stream-timeout
 * teardown does: the lock keeps the pfe alive for the call, and the owning worker
 * sees POLLHUP and runs the ordinary destroy, which removes the verdict entry
 * before its peer_map entry (proxy_peer_map_delete) and so preserves the
 * invariant this whole design rests on.
 *
 * Returns the number of connections dropped, or -ENOENT when the rule does not
 * exist. A rule with nothing accelerated returns 0.
 */
int
proxy_sockmap_drop_accel(proxy_ent_t *key)
{
  proxy_map_ent_t *node;
  proxy_fd_ent_t *pfe;
  int found = 0;
  int dropped = 0;

  if (!key) {
    return -EINVAL;
  }

  PROXY_LOCK();
  for (node = proxy_struct->head; node; node = node->next) {
    if (!cmp_proxy_ent(&node->key, key)) {
      continue;
    }
    found = 1;
    /* fdlist carries the BACKEND pfe of each pair, which is where the install
     * path records the peer_map flags; rfd_ent[0] is its client leg. Both ends
     * are closed, since either alone would leave the other half-open on a
     * connection whose point was that the kernel moves its bytes. */
    for (pfe = node->val.fdlist; pfe; pfe = pfe->next) {
      if (!pfe->peer_map_req_installed && !pfe->peer_map_resp_installed) {
        continue;
      }
      if (pfe->fd > 0) {
        shutdown(pfe->fd, SHUT_RDWR);
      }
      if (pfe->n_rfd > 0 && pfe->rfd_ent[0] && pfe->rfd_ent[0]->fd > 0) {
        shutdown(pfe->rfd_ent[0]->fd, SHUT_RDWR);
      }
      dropped++;
    }
    break;
  }
  PROXY_UNLOCK();

  if (!found) {
    return -ENOENT;
  }

  log_info("Sockmap: dropped %d accelerated connection(s) on %s:%u",
           dropped, inet_ntoa(*(struct in_addr *)&key->xip), ntohs(key->xport));
  return dropped;
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

  /* A burst of connects waits in the kernel backlog until the listener
   * shard drains it (a batch per poll round). The kernel caps the backlog
   * at net.core.somaxconn. */
  rc = listen(fd, SOMAXCONN);
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

/* The listener's backend connect deadline in ms. The value rides proxy_arg
 * (timeout_member_connect_ms), reached here via the client pfe's
 * proxy_map_ent (pfe->head). It is L7-gated (has_l7_policy): the AI peer and
 * every un-configured listener keep the historic 500ms literal byte-for-byte
 * (Pitfall 3 — NOT Octavia's 5000ms). 0 ⇒ 500 even when an L7 policy is
 * attached. */
int
proxy_ep_connect_deadline_ms(proxy_fd_ent_t *pfe)
{
  int connect_to_ms = 500;
  proxy_map_ent_t *cnode = pfe ? (proxy_map_ent_t *)pfe->head : NULL;

  if (cnode && cnode->has_l7_policy && cnode->arg_ptr &&
      cnode->arg_ptr->timeout_member_connect_ms > 0) {
    connect_to_ms = (int)cnode->arg_ptr->timeout_member_connect_ms;
  }
  return connect_to_ms;
}

/* Socket, options and the connect() of one backend leg. On
 * PROXY_CONNECT_FAILED the socket is already closed and *fd_out is -1. */
static proxy_connect_state_t
proxy_ep_connect_start(uint32_t epip, uint16_t epport, uint8_t protocol,
                       proxy_fd_ent_t *pfe, int deadline_ms, int *fd_out)
{
  int fd;
  struct sockaddr_in epaddr;
  proxy_connect_state_t st;

  *fd_out = -1;

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
    return PROXY_CONNECT_FAILED;
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

  st = proxy_connect_start(fd, &epaddr, deadline_ms);
  if (st == PROXY_CONNECT_FAILED) {
    log_error("connect failed %s:%u", inet_ntoa(*(struct in_addr *)(&epip)), ntohs(epport));
    close(fd);
    return st;
  }

  *fd_out = fd;
  return st;
}

/* Everything that follows a completed handshake: the PROXY protocol header,
 * then the backend TLS handshake. The tail of the synchronous connect, and
 * the part of an asynchronous one that runs from the writable event. Returns
 * the fd, or -1 with the fd closed. */
static int
proxy_ep_connect_finish_leg(int fd, uint32_t epip, uint16_t epport,
                            void *ssl_ctx, void **ssl, proxy_fd_ent_t *pfe,
                            const void *pp2hdr, int pp2len)
{
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
proxy_setup_ep_connect(uint32_t epip, uint16_t epport, uint8_t protocol,
                       void *ssl_ctx, void **ssl, proxy_fd_ent_t *pfe,
                       const void *pp2hdr, int pp2len)
{
  int fd;
  proxy_connect_state_t st;

  st = proxy_ep_connect_start(epip, epport, protocol, pfe, 0, &fd);
  if (st == PROXY_CONNECT_FAILED) {
    return -1;
  }

  if (st == PROXY_CONNECT_PENDING) {
    /* The calling thread waits for the handshake: see sockproxy_connect.h
     * for the callers that need this, and proxy_setup_ep_connect_async for
     * the relay path, which does not. */
    if (proxy_connect_wait(fd, proxy_ep_connect_deadline_ms(pfe))) {
      if (errno == ETIMEDOUT) {
        log_error("connect %s:%u(timedout)", inet_ntoa(*(struct in_addr *)(&epip)), ntohs(epport));
      } else {
        log_error("connect %s:%u(errors)", inet_ntoa(*(struct in_addr *)(&epip)), ntohs(epport));
      }
      close(fd);
      return -1;
    }
  }

  return proxy_ep_connect_finish_leg(fd, epip, epport, ssl_ctx, ssl, pfe, pp2hdr, pp2len);
}

/* The relay path's connect: never waits for the handshake. Returns the fd
 * with *pending set while the handshake is in flight; the caller registers
 * it for POLLOUT and completes the leg with proxy_setup_ep_connect_complete
 * from the writable event. A connect that completes at once (a local
 * backend) returns a finished leg with *pending clear, the PROXY header
 * already sent. Plaintext backends only: a TLS backend's handshake is driven
 * synchronously and keeps the synchronous connect. -1 on failure. */
int
proxy_setup_ep_connect_async(uint32_t epip, uint16_t epport, uint8_t protocol,
                             proxy_fd_ent_t *pfe, const void *pp2hdr, int pp2len,
                             int *pending)
{
  int fd;
  proxy_connect_state_t st;

  *pending = 0;
  st = proxy_ep_connect_start(epip, epport, protocol, pfe,
                              proxy_ep_connect_deadline_ms(pfe), &fd);
  if (st == PROXY_CONNECT_FAILED) {
    return -1;
  }
  if (st == PROXY_CONNECT_PENDING) {
    *pending = 1;
    return fd;
  }
  return proxy_ep_connect_finish_leg(fd, epip, epport, NULL, NULL, pfe, pp2hdr, pp2len);
}

/* Second half of proxy_setup_ep_connect_async, from the leg's writable or
 * error event: the connect result, then the PROXY header that has to open
 * the stream. 0 when the leg is ready for payload, else an errno; the fd is
 * left to the caller either way. */
int
proxy_setup_ep_connect_complete(int fd, const void *pp2hdr, int pp2len)
{
  int err = proxy_connect_finish(fd);

  if (err) {
    return err;
  }
  if (pp2hdr && pp2len > 0 && proxy_send_all(fd, pp2hdr, (size_t)pp2len)) {
    return errno ? errno : EPIPE;
  }
  return 0;
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
/* `used` of a shell that sits on the freelist; no live shell can reach it */
#define PFE_POOLED (-0x7ffffff)

/* Connection-list operation trace. When LLB_FDLIST_TRACE=1 is set in the
 * environment, every insert into and unlink from a rule's connection list, and
 * every pool pop and recycle of a shell, writes one line carrying the list
 * head and count observed at that moment. An offline replay of those lines
 * (audit-perf/fdlist_replay.py) rebuilds the list and reports the first
 * operation after which the real list and the rebuilt one disagree. Off by
 * default: the enable check is one relaxed load. */
static int pfe_trace_state = -1;   /* -1 not yet read, 0 off, 1 on */

int
pfe_trace_enabled(void)
{
  int s = __atomic_load_n(&pfe_trace_state, __ATOMIC_RELAXED);
  if (s < 0) {
    const char *e = getenv("LLB_FDLIST_TRACE");
    s = (e && *e && *e != '0') ? 1 : 0;
    __atomic_store_n(&pfe_trace_state, s, __ATOMIC_RELAXED);
  }
  return s;
}

void
pfe_trace_op(const char *op, void *rule, proxy_fd_ent_t *pfe)
{
  proxy_map_ent_t *ent = rule;
  if (!pfe_trace_enabled() || !pfe) {
    return;
  }
  log_error("[FDLIST-OP] %s rule=%p node=%p fd=%d odir=%d used=%d gen=%lu next=%p head=%p list=%p nfds=%u tid=%ld",
            op, rule, (void *)pfe, pfe->fd, pfe->odir, pfe->used,
            (unsigned long)atomic_load_explicit(&pfe->gen, memory_order_relaxed),
            (void *)pfe->next, pfe->head,
            ent ? (void *)ent->val.fdlist : NULL, ent ? ent->val.nfds : 0u,
            (long)syscall(SYS_gettid));
}

static pthread_mutex_t pfe_pool_lock = PTHREAD_MUTEX_INITIALIZER;
static proxy_fd_ent_t *pfe_pool_free;   /* freelist head, linked via ->next */
static unsigned long   pfe_pool_total;  /* shells ever created (high-water)  */
static unsigned long   pfe_pool_live;   /* shells currently checked out      */

static proxy_fd_ent_t *
pfe_alloc_ex(int with_rcvbuf)
{
  proxy_fd_ent_t *pfe;
  uint64_t gen;

  pthread_mutex_lock(&pfe_pool_lock);
  pfe = pfe_pool_free;
  if (pfe) {
    pfe_pool_free = pfe->pool_next;   /* pop a recycled shell (gen preserved) */
    pfe->used = 0;                    /* clears the PFE_POOLED mark (memset below does too) */
  }
  pfe_pool_live++;
  pthread_mutex_unlock(&pfe_pool_lock);

  /* : the global total-footprint gauge — incremented here, the
   * ONE point loxilb commits to holding a connection's footprint (the pfe
   * checkout), and decremented (>0-guarded) on pfe_recycle, exactly balanced with
   * pfe_pool_live above. Every OOM bail-out below mirrors the matching pfe_pool_live
   * decrement so the gauge can never leak (a leak would wedge accept() intake).
   *
   * (default-off): maintain this gauge ONLY when the total-inflight bound is
   * enabled (LLB_PD_MAX_TOTAL_INFLIGHT > 0). With the knob unset there is NO hot-
   * path mutation here ⇒ the pfe_alloc/recycle path is byte-identical to pre-
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
    pfe_trace_op("pop", pfe->head, pfe);
    memset(pfe, 0, sizeof(*pfe));
    atomic_store_explicit(&pfe->gen, gen, memory_order_relaxed);
  }

  /* B-split: 1MB receive buffer on the heap. calloc to preserve the zero-init
   * semantics of the previously-inline array. A leg whose connect is still
   * in flight takes the shell without it (pfe_alloc_bare) and attaches the
   * buffer once connected (pfe_rcvbuf_alloc): a backend that is slow to
   * accept would otherwise hold a megabyte per pending leg for nothing. */
  if (with_rcvbuf && pfe_rcvbuf_alloc(pfe)) {
    pfe_recycle(pfe);   /* return the shell to the pool (rcvbuf already NULL) */
    return NULL;
  }

  /* -1 = "not parked" (the memset above zeroes it, but 0 is a valid
   * prefill EP index, so a zeroed park_ep_idx would falsely look parked-on-EP0). */
  pfe->park_ep_idx = -1;

  return pfe;
}

proxy_fd_ent_t *
pfe_alloc(void)
{
  return pfe_alloc_ex(1);
}

proxy_fd_ent_t *
pfe_alloc_bare(void)
{
  return pfe_alloc_ex(0);
}

int
pfe_rcvbuf_alloc(proxy_fd_ent_t *pfe)
{
  if (pfe->rcvbuf) {
    return 0;
  }
  pfe->rcvbuf = calloc(1, SP_SOCK_MSG_LEN);
  if (!pfe->rcvbuf) {
    log_error("pfe_alloc: rcvbuf OOM");
    return -1;
  }
  return 0;
}

void
pfe_recycle(proxy_fd_ent_t *pfe)
{
  if (!pfe) {
    return;
  }
  if (pfe->used == PFE_POOLED) {
    /* Double recycle: the shell is already on the freelist. Refuse and log.
     * The mark lives in `used` (a pooled shell has no user), so the layout of
     * proxy_fd_ent stays unchanged. */
    log_error("[PFE_POOL] double recycle of shell %p (fd=%d odir=%d used=%d gen=%lu) refused",
              (void *)pfe, pfe->fd, pfe->odir, pfe->used,
              (unsigned long)atomic_load_explicit(&pfe->gen, memory_order_relaxed));
    return;
  }
  pfe_trace_op("rec", pfe->head, pfe);
  pfe->used = PFE_POOLED;

  /* A connection that ended on its own before the sweep reached it must not
   * leave the pending count raised, or the fast tick keeps walking for nothing. */
  proxy_defer_close_clear(pfe);

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

  /* : release the global total-footprint gauge, paired 1:1 with
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

/* : read-only snapshot of the pfe-pool gauges for the bounded-
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
  if (pfe->used == PFE_POOLED) {
    return;   /* already on the freelist (pfe_recycle logged the double release) */
  }
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
  if (pfe->used == PFE_POOLED || pfe->used <= 0) {
    /* A second release of a shell whose last reference is already gone: the
     * first release recycled it (or is about to). Dropping the count below
     * zero would recycle it again — see the pooled guard in pfe_recycle. */
    log_error("[PFE_POOL] release of an already-freed shell %p (fd=%d odir=%d used=%d) — ignored",
              (void *)pfe, pfe->fd, pfe->odir, pfe->used);
    return;
  }
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
    proxy_epval_t retired_chwbl = {0};
    pthread_rwlock_wrlock(&tepval->chwbl_state_lock);
    retired_chwbl.hash_ring = tepval->hash_ring;
    retired_chwbl.chwbl_config = tepval->chwbl_config;
    tepval->hash_ring = NULL;
    tepval->chwbl_config = NULL;
    tepval->select = PROXY_SEL_RR;
    pthread_rwlock_unlock(&tepval->chwbl_state_lock);
    chwbl_release_runtime(&retired_chwbl);
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
  proxy_connect_pending_clear(fd_ent);

#ifdef HAVE_DP_GPU_ROUTING
  // P1.3/P3.5: Decrement CHWBL/WRR_HASH load counter when connection closes
  if (fd_ent->epv && fd_ent->ep_num >= 0) {
    proxy_epval_t *epv = (proxy_epval_t *)fd_ent->epv;
    chwbl_dec_runtime(epv, fd_ent->ep_num);
  }
#endif /* HAVE_DP_GPU_ROUTING */

  // Reset HTTP parsing state
  fd_ent->http_pok = 0;
  fd_ent->http_hok = 0;
  fd_ent->http_hvok = 0;
  fd_ent->http_body_complete = 0;
  fd_ent->http_content_length = 0;
  fd_ent->is_streamable = 0;
  fd_ent->json_stream_route_pending = 0;
  fd_ent->json_stream_continue_sent = 0;
  fd_ent->ka_reparse = 0;
  fd_ent->ka_keep_leg = 0;
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
