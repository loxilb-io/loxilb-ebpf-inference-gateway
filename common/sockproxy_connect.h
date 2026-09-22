/*
 * sockproxy_connect.h - a backend connect in two halves.
 *
 * A backend connect used to be one call on the relay worker: a non-blocking
 * connect() followed by a poll() on the same thread until the socket became
 * writable, bounded by the listener's connect timeout. On a veth bed the
 * round trip is a few tens of microseconds and the wait never shows. On a
 * real network every connection costs its worker one backend round trip
 * during which nothing else on that worker moves, so a worker's connection
 * rate is bounded by 1 / RTT with the CPU idle: a millisecond of extra
 * latency toward the backends took a third of the gateway's connection rate.
 *
 * proxy_connect_start() returns as soon as connect() has been issued (after
 * one zero-timeout probe, since a near peer's handshake is often complete by
 * then and such a leg stays on the inline path). While the handshake is in
 * flight the caller registers the fd for POLLOUT and
 * finishes the leg from the writable event with proxy_connect_finish(),
 * which reads the socket's pending error. The connect deadline moves into
 * the kernel: TCP_USER_TIMEOUT is set for the handshake and cleared once it
 * completes, so an unanswered SYN fails at the socket's first retransmit
 * after the deadline. The kernel checks the deadline when its retransmit
 * timer fires, so the effective bound is the deadline rounded up to the SYN
 * retransmit schedule (one second on the first retry); a connection that
 * completes is never affected because the option is cleared before any
 * payload moves.
 *
 * proxy_connect_wait() is the synchronous half, kept for the callers that
 * need a connected socket before they can go on: the HTTP/2 backend, the
 * P/D dialects that open several legs in one step, and TLS backends, whose
 * handshake is driven synchronously anyway.
 */
#ifndef __SOCKPROXY_CONNECT_H__
#define __SOCKPROXY_CONNECT_H__

#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

typedef enum {
  PROXY_CONNECT_FAILED  = -1,   /* connect() failed at once, errno is set */
  PROXY_CONNECT_DONE    = 0,    /* the socket is connected */
  PROXY_CONNECT_PENDING = 1,    /* handshake in flight: wait for POLLOUT */
} proxy_connect_state_t;

/* Issue the connect on a non-blocking socket. deadline_ms > 0 arms the
 * kernel handshake deadline on a pending connect; proxy_connect_finish()
 * clears it again. A synchronous caller passes 0 and bounds the wait in
 * proxy_connect_wait() instead. */
static inline proxy_connect_state_t
proxy_connect_start(int fd, const struct sockaddr_in *addr, int deadline_ms)
{
  if (connect(fd, (const struct sockaddr *)addr, sizeof(*addr)) == 0) {
    return PROXY_CONNECT_DONE;
  }
  if (errno != EINPROGRESS) {
    return PROXY_CONNECT_FAILED;
  }
  if (deadline_ms > 0) {
    /* With a local or very near peer the handshake has usually completed by
     * the time connect() returns EINPROGRESS (the reply is processed in the
     * same softirq turn). One zero-timeout probe keeps such a leg on the
     * inline path, for the single poll() the synchronous wait cost there;
     * otherwise a completed connect would pay a notifier round trip for
     * nothing. A probe that reports an error is left to the event path. */
    struct pollfd probe = { .fd = fd, .events = POLLOUT | POLLERR, .revents = 0 };
    unsigned int to = (unsigned int)deadline_ms;

    if (poll(&probe, 1, 0) > 0 && (probe.revents & POLLOUT) &&
        !(probe.revents & (POLLERR | POLLHUP))) {
      return PROXY_CONNECT_DONE;
    }
    (void)setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &to, sizeof(to));
  }
  return PROXY_CONNECT_PENDING;
}

/* From the writable or error event of a pending connect: 0 when the socket
 * connected, else its pending errno (ECONNREFUSED, ETIMEDOUT, ...). On
 * success the handshake deadline is cleared so it cannot cut the connection
 * later. */
static inline int
proxy_connect_finish(int fd)
{
  int err = 0;
  socklen_t len = sizeof(err);

  if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
    return errno ? errno : EIO;
  }
  if (err == 0) {
    unsigned int off = 0;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &off, sizeof(off));
  }
  return err;
}

/* The synchronous half: block the calling thread until the socket is
 * writable or timeout_ms passes. 0 when connected; -1 with errno set
 * otherwise (ETIMEDOUT on the deadline, the socket's pending error on a
 * failed handshake). */
static inline int
proxy_connect_wait(int fd, int timeout_ms)
{
  struct pollfd pfd = { .fd = fd, .events = POLLOUT | POLLERR, .revents = 0 };
  int rc = poll(&pfd, 1, timeout_ms);

  if (rc < 0) {
    return -1;
  }
  if (rc == 0) {
    errno = ETIMEDOUT;
    return -1;
  }
  if (pfd.revents & POLLERR) {
    int err = 0;
    socklen_t len = sizeof(err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err == 0) {
      err = ECONNREFUSED;
    }
    errno = err;
    return -1;
  }
  return 0;
}

#endif /* __SOCKPROXY_CONNECT_H__ */
