/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_notify_shard.c - listening sockets are polled by a shard of their own.
 *
 * The notifier used to place a listening socket like any other fd, on the
 * relay shard `fd % n_thrs`. That worker then accepted one connection per
 * poll round, behind the round's relay events, so a burst of connects was
 * admitted at the pace of the relay loop: with 2,000 connects in a second
 * the last ones waited over two seconds for their first byte while the
 * kernel backlog reported no overflow at all. Listeners now register on a
 * shard after the relay shards, which polls listeners only, and the accept
 * path drains the backlog in batches.
 *
 * This unit drives the registration rule on a real notifier context (no
 * worker threads are started): a listener lands on the listener shard, no
 * relay fd ever does, and relay placement (fd modulo, pinned) is unchanged.
 *
 * THE ORACLE IS SELF-VERIFYING. The pre-fix placement of a listener is
 * `fd % n_thrs`, computed below as `relay_shard_of`; each listener case
 * requires that the shipped rule and the pre-fix rule disagree, so the case
 * cannot pass against a notifier that still shares the listener with a relay
 * worker.
 *
 * The second half drives the listener pause of the accept valve on a running
 * listener shard. A listening socket with a connection left in its backlog is
 * readable for good, and level-triggered poll reports it on every round: a
 * callback that declines to accept (the valve at its bound) spins the shard.
 * The first case measures that spin, so the pause cases cannot pass against a
 * fixture that does not reproduce it.
 *
 * Build (wired into `make test_shard`):
 *   gcc -Wall -Wextra -Werror -o test_notify_shard test_notify_shard.c notify.c log.c -I. -lpthread
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <stdatomic.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "notify.h"

/* notify.c marks its workers fail-loud through this thread-local, which the
 * proxy core defines; no worker is started here. */
__thread volatile sig_atomic_t g_llb_proxy_worker = 0;

static int failures = 0;
static int checks   = 0;

#define N_RELAY 4

static void
check(const char *name, int ok, int got, int want)
{
  checks++;
  if (!ok) {
    failures++;
    printf("FAIL %-56s got %d want %d\n", name, got, want);
  } else {
    printf("ok   %-56s (%d)\n", name, got);
  }
}

/* The PRE-FIX placement: a listener took the relay shard of its fd number. */
static int
relay_shard_of(int fd)
{
  return fd % N_RELAY;
}

static void
expect_listener(void *ns, int fd, const char *name)
{
  int priv;
  int thr;
  char label[128];

  check(name, notify_add_ent_listener(ns, fd, NOTI_TYPE_IN | NOTI_TYPE_HUP, &priv, 1) == 0, 0, 0);
  thr = notify_ent_thr(ns, fd);
  snprintf(label, sizeof(label), "%s: on the listener shard", name);
  check(label, thr == notify_listener_thr(ns), thr, notify_listener_thr(ns));
  snprintf(label, sizeof(label), "%s: off every relay shard", name);
  check(label, thr >= N_RELAY, thr, N_RELAY);
  /* self-verification: the pre-fix rule would have shared a relay worker */
  snprintf(label, sizeof(label), "%s: pre-fix rule differs", name);
  check(label, relay_shard_of(fd) != thr, relay_shard_of(fd), thr);
}

static void
expect_relay(void *ns, int fd, int pin_fd, int want, const char *name)
{
  int priv;
  int rc;
  int thr;
  char label[128];

  if (pin_fd > 0) {
    rc = notify_add_ent_pinned(ns, fd, NOTI_TYPE_IN | NOTI_TYPE_HUP, &priv, 1, pin_fd);
  } else {
    rc = notify_add_ent(ns, fd, NOTI_TYPE_IN | NOTI_TYPE_HUP, &priv, 1);
  }
  check(name, rc == 0, rc, 0);
  thr = notify_ent_thr(ns, fd);
  snprintf(label, sizeof(label), "%s: relay placement unchanged", name);
  check(label, thr == want, thr, want);
  snprintf(label, sizeof(label), "%s: never the listener shard", name);
  check(label, thr != notify_listener_thr(ns), thr, notify_listener_thr(ns));
}


/* ---- listener pause (accept valve) ---- */

static void *g_vns;               /* the context whose listener shard runs */
static int g_lfd = -1;            /* the listener under test */
static atomic_int g_disp;         /* dispatches of g_lfd */
static atomic_int g_pause_in_cb;  /* the callback pauses, as the valve does */
static atomic_int g_gate_open;    /* what the gate predicate answers */
static atomic_int g_gate_calls;   /* how often the notifier asked it */
static atomic_int g_cb_rc;        /* last notify_pause_ent result in the callback */

static int
gate_open(void)
{
  atomic_fetch_add(&g_gate_calls, 1);
  return atomic_load(&g_gate_open);
}

/* The accept valve at its bound: never accept, optionally pause. */
static int
valve_cb(int fd, notify_type_t type, void *priv, uint64_t gen)
{
  (void)type; (void)priv; (void)gen;
  if (fd == g_lfd) {
    atomic_fetch_add(&g_disp, 1);
    if (atomic_load(&g_pause_in_cb)) {
      atomic_store(&g_cb_rc, notify_pause_ent(g_vns, fd, gate_open));
    }
  }
  return 0;
}

static void *
run_shards(void *arg)
{
  notify_start(arg);
  return NULL;
}

static void
sleep_ms(int ms)
{
  struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
  nanosleep(&ts, NULL);
}

/* dispatches of the listener over `ms` */
static int
dispatches_over(int ms)
{
  int before = atomic_load(&g_disp);
  sleep_ms(ms);
  return atomic_load(&g_disp) - before;
}

/* A loopback listener with one connection queued and never accepted. */
static int
backlogged_listener(int *client)
{
  struct sockaddr_in sa;
  socklen_t sl = sizeof(sa);
  int one = 1;
  int lfd = socket(AF_INET, SOCK_STREAM, 0);

  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  if (bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) || listen(lfd, 16) ||
      getsockname(lfd, (struct sockaddr *)&sa, &sl)) {
    return -1;
  }
  *client = socket(AF_INET, SOCK_STREAM, 0);
  if (connect(*client, (struct sockaddr *)&sa, sizeof(sa))) {
    return -1;
  }
  return lfd;
}

static void
listener_pause_cases(void)
{
  notify_cbs_t cbs;
  pthread_t thr;
  int client = -1, client2 = -1;
  int lfd2;
  int lpriv, lpriv2, lpriv3;
  int n, rc, calls;

  memset(&cbs, 0, sizeof(cbs));
  cbs.notify = valve_cb;
  g_vns = notify_ctx_new(&cbs, 1);
  g_lfd = backlogged_listener(&client);
  check("valve: backlogged loopback listener", g_lfd > 0, g_lfd, 1);
  check("valve: listener registered",
        notify_add_ent_listener(g_vns, g_lfd, NOTI_TYPE_IN | NOTI_TYPE_HUP, &lpriv, 1) == 0, 0, 0);
  pthread_create(&thr, NULL, run_shards, g_vns);
  pthread_detach(thr);
  sleep_ms(50);

  /* self-verification: declining without a pause spins the shard */
  n = dispatches_over(100);
  check("valve: a declining listener spins (fixture reproduces)", n > 200, n, 201);

  /* the valve pauses: the listener stops being reported */
  atomic_store(&g_gate_open, 0);
  atomic_store(&g_pause_in_cb, 1);
  sleep_ms(30);
  check("valve: pause leaves the listener paused", atomic_load(&g_cb_rc) == 1,
        atomic_load(&g_cb_rc), 1);
  check("valve: one listener paused", notify_paused_count(g_vns) == 1,
        notify_paused_count(g_vns), 1);
  n = dispatches_over(100);
  check("valve: a paused listener is not reported", n <= 1, n, 1);

  /* a pause of an already paused listener adds nothing */
  check("valve: second pause is a no-op", notify_pause_ent(g_vns, g_lfd, gate_open) == 0, 0, 0);
  check("valve: still one paused", notify_paused_count(g_vns) == 1, notify_paused_count(g_vns), 1);

  /* re-arm while the gate is still closed leaves it paused */
  rc = notify_rearm_paused(g_vns, gate_open);
  check("valve: closed gate re-arms nothing", rc == 0, rc, 0);
  n = dispatches_over(50);
  check("valve: still not reported", n <= 1, n, 1);

  /* room appears: re-arm, and the listener is reported again at once */
  atomic_store(&g_pause_in_cb, 0);
  atomic_store(&g_gate_open, 1);
  rc = notify_rearm_paused(g_vns, gate_open);
  check("valve: open gate re-arms the listener", rc == 1, rc, 1);
  check("valve: nothing left paused", notify_paused_count(g_vns) == 0,
        notify_paused_count(g_vns), 0);
  n = dispatches_over(50);
  check("valve: a re-armed listener is reported again", n > 20, n, 21);

  /* nothing paused: the re-arm returns without asking the gate */
  calls = atomic_load(&g_gate_calls);
  rc = notify_rearm_paused(g_vns, gate_open);
  check("valve: re-arm with nothing paused is a no-op", rc == 0, rc, 0);
  check("valve: ... and never evaluates the gate", atomic_load(&g_gate_calls) == calls,
        atomic_load(&g_gate_calls) - calls, 0);

  /* the same registration updated in place while paused stays paused, and
   * the re-arm applies the updated mask */
  atomic_store(&g_gate_open, 0);
  check("valve: pause before an in-place update", notify_pause_ent(g_vns, g_lfd, gate_open) == 1, 0, 0);
  check("valve: in-place update of the paused listener",
        notify_add_ent_listener(g_vns, g_lfd, NOTI_TYPE_HUP, &lpriv, 1) == 0, 0, 0);
  n = dispatches_over(50);
  check("valve: an update does not unpause", n <= 1 && notify_paused_count(g_vns) == 1, n, 1);
  atomic_store(&g_gate_open, 1);
  rc = notify_rearm_paused(g_vns, gate_open);
  check("valve: the updated listener is re-armed", rc == 1, rc, 1);
  n = dispatches_over(50);
  check("valve: ... with its updated mask (hang-ups only)", n == 0, n, 0);
  check("valve: in-place update back to IN|HUP",
        notify_add_ent_listener(g_vns, g_lfd, NOTI_TYPE_IN | NOTI_TYPE_HUP, &lpriv, 1) == 0, 0, 0);
  n = dispatches_over(50);
  check("valve: ... and reported again", n > 20, n, 21);

  /* the race: the valve saw the bound, a context was freed before the pause
   * landed, and that release found nothing paused to re-arm. The pause itself
   * must see the open gate and re-arm, or the listener stays paused with room. */
  atomic_store(&g_gate_open, 1);
  rc = notify_pause_ent(g_vns, g_lfd, gate_open);
  check("valve: pause after room appeared re-arms at once", rc == 0, rc, 0);
  check("valve: ... and leaves nothing paused", notify_paused_count(g_vns) == 0,
        notify_paused_count(g_vns), 0);
  n = dispatches_over(50);
  check("valve: ... and the listener is still reported", n > 20, n, 21);

  /* a paused listener that is released and its fd registered again by someone
   * else (asking for hang-ups only): a later re-arm, woken by another paused
   * listener, must not hand the new registration the old listener's events */
  atomic_store(&g_gate_open, 0);
  check("valve: pause before release", notify_pause_ent(g_vns, g_lfd, gate_open) == 1, 0, 0);
  check("valve: release the paused listener", notify_deregister_ent(g_vns, g_lfd) == 0, 0, 0);
  check("valve: the fd registered again, hang-ups only",
        notify_add_ent_listener(g_vns, g_lfd, NOTI_TYPE_HUP, &lpriv2, 2) == 0, 0, 0);
  check("valve: a released pause is not counted", notify_paused_count(g_vns) == 0,
        notify_paused_count(g_vns), 0);
  lfd2 = backlogged_listener(&client2);
  check("valve: second listener registered", lfd2 > 0 &&
        notify_add_ent_listener(g_vns, lfd2, NOTI_TYPE_IN | NOTI_TYPE_HUP, &lpriv3, 3) == 0, 0, 0);
  check("valve: second listener paused", notify_pause_ent(g_vns, lfd2, gate_open) == 1, 0, 0);
  atomic_store(&g_gate_open, 1);
  rc = notify_rearm_paused(g_vns, gate_open);
  check("valve: only the live pause is re-armed", rc == 1, rc, 1);
  check("valve: ... and nothing is left paused", notify_paused_count(g_vns) == 0,
        notify_paused_count(g_vns), 0);
  n = dispatches_over(50);
  check("valve: the new registration keeps its own events", n == 0, n, 0);

  close(client2);
  close(lfd2);
  close(client);
}

int
main(void)
{
  void *ns = notify_ctx_new(NULL, N_RELAY);

  check("context with 4 relay shards", ns != NULL, ns != NULL, 1);
  check("listener shard follows the relay shards", notify_listener_thr(ns) == N_RELAY,
        notify_listener_thr(ns), N_RELAY);

  /* one listener per relay-shard residue, so no fd number happens to agree */
  expect_listener(ns, 20, "listener fd 20");
  expect_listener(ns, 21, "listener fd 21");
  expect_listener(ns, 22, "listener fd 22");
  expect_listener(ns, 23, "listener fd 23");

  /* an accepted client keeps its fd-modulo shard, a backend leg its pin */
  expect_relay(ns, 101, -1, 101 % N_RELAY, "client fd 101");
  expect_relay(ns, 102, -1, 102 % N_RELAY, "client fd 102");
  expect_relay(ns, 205, 101, 101 % N_RELAY, "backend fd 205 pinned to 101");

  /* a listener that is released and registered again returns to the shard */
  check("release listener fd 22", notify_deregister_ent(ns, 22) == 0, 0, 0);
  check("released fd is unregistered", notify_ent_thr(ns, 22) == -1, notify_ent_thr(ns, 22), -1);
  expect_listener(ns, 22, "listener fd 22 again");

  /* re-registering the same priv only updates the event mask */
  {
    int priv;
    check("re-add of a live client", notify_add_ent(ns, 103, NOTI_TYPE_IN, &priv, 1) == 0, 0, 0);
    check("re-add keeps the shard",
          notify_add_ent(ns, 103, NOTI_TYPE_IN | NOTI_TYPE_OUT, &priv, 1) == 0 &&
          notify_ent_thr(ns, 103) == 103 % N_RELAY, notify_ent_thr(ns, 103), 103 % N_RELAY);
  }

  /* the fd range is the entry table: its last slot is one below the size */
  {
    int priv;
    check("fd 65535 is refused", notify_add_ent(ns, 65535, NOTI_TYPE_IN, &priv, 1) < 0, 0, 0);
    check("fd 65534 is accepted", notify_add_ent(ns, 65534, NOTI_TYPE_IN, &priv, 1) == 0, 0, 0);
  }

  /* the shard count is bounded by the thread table, listener shard included */
  check("8 relay shards leave no room for the listener shard", notify_ctx_new(NULL, 8) == NULL, 0, 0);
  check("7 relay shards fit", notify_ctx_new(NULL, 7) != NULL, 1, 1);

  listener_pause_cases();

  printf("\n%d checks, %d failures\n", checks, failures);
  return failures ? 1 : 0;
}
