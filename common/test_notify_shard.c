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
 * Build (wired into `make test_shard`):
 *   gcc -Wall -Wextra -Werror -o test_notify_shard test_notify_shard.c notify.c log.c -I. -lpthread
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>

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

  printf("\n%d checks, %d failures\n", checks, failures);
  return failures ? 1 : 0;
}
