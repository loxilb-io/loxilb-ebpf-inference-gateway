/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_async_connect.c - a backend connect no longer holds its worker for
 * the round trip.
 *
 * The relay worker used to issue the backend connect() and then poll() the
 * socket on the same thread until it was writable, bounded by the listener's
 * connect timeout. Every connection therefore cost its worker one backend
 * round trip during which nothing else on that worker moved, so a worker's
 * connection rate was bounded by 1 / RTT with the CPU idle. The connect is
 * now split in two halves (sockproxy_connect.h): proxy_connect_start()
 * returns as soon as the connect is issued, the leg is finished from the
 * socket's writable event with proxy_connect_finish(), and the connect
 * deadline moves into the kernel (TCP_USER_TIMEOUT for the handshake only).
 *
 * The delay is injected with a listener whose accept queue is full: the
 * kernel drops every further SYN, so a connect to it stays in flight until
 * the deadline. The first case proves that the injected delay is real.
 *
 * THE ORACLE IS SELF-VERIFYING. The synchronous half is kept in the header
 * for the callers that still need it, so the pre-fix shape can be measured
 * in the same run: N connects through proxy_connect_wait() must cost at
 * least N times the deadline (the collapse that was the defect), and the
 * same N through proxy_connect_start() must cost less than one deadline.
 * A build in which the asynchronous half waits is red on the second case;
 * a bed on which the injected delay does not hold is red on the first.
 *
 * Build (wired into `make test_aconn`):
 *   gcc -Wall -Wextra -Werror -o test_async_connect test_async_connect.c -I.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <arpa/inet.h>

#include "sockproxy_connect.h"

static int failures = 0;
static int checks   = 0;

#define N_CONNECTS   8
#define DEADLINE_MS  100
#define KERNEL_DEADLINE_BOUND_MS 3000   /* SYN retransmit schedule: 1 s first retry */

static void
check(const char *name, int ok, long got, long want)
{
  checks++;
  if (!ok) {
    failures++;
    printf("FAIL %-60s got %ld want %ld\n", name, got, want);
  } else {
    printf("ok   %-60s (%ld)\n", name, got);
  }
}

static long
now_ms(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static int
nonblock_socket(void)
{
  int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    perror("socket");
    exit(2);
  }
  return fd;
}

/* A loopback listener on an ephemeral port; *addr receives it. */
static int
listener(struct sockaddr_in *addr, int backlog)
{
  int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  socklen_t len = sizeof(*addr);
  int one = 1;

  if (fd < 0) {
    perror("socket");
    exit(2);
  }
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  memset(addr, 0, sizeof(*addr));
  addr->sin_family = AF_INET;
  addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr->sin_port = 0;
  if (bind(fd, (struct sockaddr *)addr, sizeof(*addr)) < 0 ||
      listen(fd, backlog) < 0 ||
      getsockname(fd, (struct sockaddr *)addr, &len) < 0) {
    perror("listen");
    exit(2);
  }
  return fd;
}

/* A listener that never answers: backlog 0 and its one queued connection
 * already taken, so the kernel drops every further SYN (accept queue full)
 * and a connect to it stays in flight until its deadline. The filler fds
 * are kept open for the run. */
static int
blackhole_listener(struct sockaddr_in *addr, int *fillers, int n_fillers)
{
  int lfd = listener(addr, 0);
  int i;

  for (i = 0; i < n_fillers; i++) {
    fillers[i] = nonblock_socket();
    (void)proxy_connect_start(fillers[i], addr, 0);
  }
  usleep(50 * 1000);
  return lfd;
}

/* Poll one fd for its writable or error event, bounded. Returns the revents
 * mask, 0 on the timeout. */
static short
wait_event(int fd, int timeout_ms)
{
  struct pollfd pfd = { .fd = fd, .events = POLLOUT | POLLERR, .revents = 0 };
  if (poll(&pfd, 1, timeout_ms) <= 0) {
    return 0;
  }
  return pfd.revents;
}

int
main(void)
{
  struct sockaddr_in live_addr;
  struct sockaddr_in hole_addr;
  int fillers[4];
  int fds[N_CONNECTS];
  int i;
  long t0;
  long elapsed;

  int live_fd = listener(&live_addr, 16);
  int hole_fd = blackhole_listener(&hole_addr, fillers, 4);

  /* --- the injected delay is real: a connect to the full listener never
   *     completes on its own ------------------------------------------- */
  {
    int fd = nonblock_socket();
    proxy_connect_state_t st = proxy_connect_start(fd, &hole_addr, 0);
    check("full listener: connect is left pending", st == PROXY_CONNECT_PENDING, st,
          PROXY_CONNECT_PENDING);
    check("full listener: no event within 300 ms", wait_event(fd, 300) == 0, 0, 0);
    close(fd);
  }

  /* --- a connect that completes ---------------------------------------- */
  {
    int fd = nonblock_socket();
    proxy_connect_state_t st = proxy_connect_start(fd, &live_addr, DEADLINE_MS);
    check("live listener: connect issued", st != PROXY_CONNECT_FAILED, st, 0);
    if (st == PROXY_CONNECT_PENDING) {
      check("live listener: writable within 1 s", (wait_event(fd, 1000) & POLLOUT) != 0, 1, 1);
    } else {
      /* loopback: the handshake completed inside connect(), the probe saw it */
      check("live listener: completed inline, no deadline armed", st == PROXY_CONNECT_DONE, st,
            PROXY_CONNECT_DONE);
    }
    check("live listener: finish reports connected", proxy_connect_finish(fd) == 0, 0, 0);
    {
      unsigned int to = 1;
      socklen_t len = sizeof(to);
      getsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &to, &len);
      check("live listener: handshake deadline cleared once connected", to == 0, to, 0);
    }
    close(fd);
  }

  /* --- a refused connect ------------------------------------------------ */
  {
    struct sockaddr_in dead_addr;
    int dead_fd = listener(&dead_addr, 1);
    int fd;
    proxy_connect_state_t st;
    int err;

    close(dead_fd);                       /* the port is now closed */
    fd = nonblock_socket();
    st = proxy_connect_start(fd, &dead_addr, DEADLINE_MS);
    if (st == PROXY_CONNECT_PENDING) {
      (void)wait_event(fd, 1000);
      err = proxy_connect_finish(fd);
    } else {
      err = (st == PROXY_CONNECT_FAILED) ? errno : 0;
    }
    check("closed port: refused", err == ECONNREFUSED, err, ECONNREFUSED);
    close(fd);
  }

  /* --- the pre-fix shape, kept as the synchronous half: N connects pay
   *     N deadlines in a row (the collapse) ------------------------------ */
  t0 = now_ms();
  for (i = 0; i < N_CONNECTS; i++) {
    int fd = nonblock_socket();
    int rc;
    proxy_connect_state_t st = proxy_connect_start(fd, &hole_addr, 0);
    if (st != PROXY_CONNECT_PENDING) {
      check("synchronous half: connect is left pending", 0, st, PROXY_CONNECT_PENDING);
    }
    rc = proxy_connect_wait(fd, DEADLINE_MS);
    if (rc != -1 || errno != ETIMEDOUT) {
      check("synchronous half: the wait times out", 0, rc == -1 ? errno : rc, ETIMEDOUT);
    }
    close(fd);
  }
  elapsed = now_ms() - t0;
  check("synchronous half: N connects cost at least N deadlines",
        elapsed >= (long)N_CONNECTS * DEADLINE_MS - DEADLINE_MS / 2,
        elapsed, (long)N_CONNECTS * DEADLINE_MS);

  /* --- the asynchronous half: N connects are issued within one deadline
   *     and the kernel ends each of them ------------------------------- */
  t0 = now_ms();
  for (i = 0; i < N_CONNECTS; i++) {
    fds[i] = nonblock_socket();
    if (proxy_connect_start(fds[i], &hole_addr, DEADLINE_MS) != PROXY_CONNECT_PENDING) {
      check("asynchronous half: connect is left pending", 0, 0, PROXY_CONNECT_PENDING);
    }
  }
  elapsed = now_ms() - t0;
  check("asynchronous half: N connects issued within one deadline",
        elapsed < DEADLINE_MS, elapsed, DEADLINE_MS);

  {
    int ended = 0;
    int timed_out = 0;
    long bound = now_ms() + KERNEL_DEADLINE_BOUND_MS;
    while (ended < N_CONNECTS && now_ms() < bound) {
      struct pollfd pfds[N_CONNECTS];
      for (i = 0; i < N_CONNECTS; i++) {
        pfds[i].fd = fds[i];
        pfds[i].events = POLLOUT | POLLERR;
        pfds[i].revents = 0;
      }
      if (poll(pfds, N_CONNECTS, 200) <= 0) {
        continue;
      }
      for (i = 0; i < N_CONNECTS; i++) {
        if (pfds[i].fd >= 0 && pfds[i].revents) {
          int err = proxy_connect_finish(fds[i]);
          if (err == ETIMEDOUT) {
            timed_out++;
          }
          close(fds[i]);
          fds[i] = -1;
          ended++;
        }
      }
    }
    elapsed = now_ms() - t0;
    check("asynchronous half: the kernel ends every pending connect in time",
          ended == N_CONNECTS, ended, N_CONNECTS);
    check("asynchronous half: each ended with the handshake deadline",
          timed_out == N_CONNECTS, timed_out, N_CONNECTS);
    check("asynchronous half: all N ended within the retransmit bound",
          elapsed < KERNEL_DEADLINE_BOUND_MS, elapsed, KERNEL_DEADLINE_BOUND_MS);
    for (i = 0; i < N_CONNECTS; i++) {
      if (fds[i] >= 0) {
        close(fds[i]);
      }
    }
  }

  for (i = 0; i < 4; i++) {
    close(fillers[i]);
  }
  close(hole_fd);
  close(live_fd);

  printf("\n%d checks, %d failures\n", checks, failures);
  return failures ? 1 : 0;
}
