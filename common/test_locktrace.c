/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_locktrace.c - global proxy lock accounting by call site.
 *
 * With LLB_PROXY_LOCK_TRACE=1 every acquire of the global proxy lock records
 * how long the caller waited and every release how long the caller held,
 * both on the site (function and line) that took the lock. This unit drives
 * the two inline helpers the PROXY_LOCK macros expand to, on a private
 * rwlock, and checks:
 *
 *   - a hold lands on its own site with the right histogram bucket;
 *   - two sites in one function are distinct, one site seen twice counts 2;
 *   - a lock taken in one function and released in another is attributed
 *     to the taker;
 *   - nested read locks are attributed to their own sites, released LIFO;
 *   - a caller that waited for a writer records that wait;
 *   - holds deeper than the per-thread stack are dropped, not misattributed,
 *     and the lock is released all the same;
 *   - a release the tracker did not see acquired only unlocks;
 *   - the interval report lists the active sites once, then nothing new;
 *   - with the trace off the helpers are the bare lock calls.
 *
 * Build (wired into `make test_lt`):
 *   gcc -Wall -Wextra -Werror -o test_locktrace test_locktrace.c sockproxy_locktrace.c log.c -I. -lpthread
 */

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "sockproxy_locktrace.h"

static int checks, failures;

#define CHECK(cond, ...) do {                                        \
    checks++;                                                        \
    if (cond) {                                                      \
      printf("ok %d - ", checks); printf(__VA_ARGS__); printf("\n"); \
    } else {                                                         \
      failures++;                                                    \
      printf("FAIL %d - ", checks); printf(__VA_ARGS__);             \
      printf(" (%s:%d)\n", __FILE__, __LINE__);                      \
    }                                                                \
  } while (0)

static pthread_rwlock_t L = PTHREAD_RWLOCK_INITIALIZER;

static void
sleep_ms(long ms)
{
  struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
  nanosleep(&ts, NULL);
}

static const proxy_lock_site_stat_t *
site_of(const char *func, int line)
{
  static proxy_lock_site_stat_t st[128];
  int n = proxy_lock_trace_sites(st, 128), i;
  for (i = 0; i < n; i++) {
    if (strcmp(st[i].func, func) == 0 && st[i].line == line) {
      return &st[i];
    }
  }
  return NULL;
}

/* A lock taken here ... */
static int
taker(void)
{
  int line = __LINE__ + 1;
  proxy_lock_take(&L, 1, __func__, line);
  sleep_ms(2);
  return line;
}

/* ... and released here is the taker's hold. */
static void
dropper(void)
{
  proxy_lock_drop(&L);
}

static _Atomic int writer_holds;
static int writer_line;

static void *
writer(void *arg)
{
  (void)arg;
  writer_line = __LINE__ + 1;
  proxy_lock_take(&L, 1, __func__, writer_line);
  atomic_store(&writer_holds, 1);
  sleep_ms(5);
  proxy_lock_drop(&L);
  return NULL;
}

int
main(void)
{
  const proxy_lock_site_stat_t *s, *s2;
  int line, line2, i;
  pthread_t thr;

  setenv("LLB_PROXY_LOCK_TRACE", "1", 1);
  CHECK(proxy_lock_trace_enabled() == 1, "the environment variable turns the trace on");

  /* histogram edges: <=10us, <=100us, <=1ms, <=10ms, <=100ms, more */
  CHECK(proxy_lock_trace_bucket(0) == 0 && proxy_lock_trace_bucket(10000) == 0,
        "0 and 10 us fall in the first bucket");
  CHECK(proxy_lock_trace_bucket(10001) == 1 && proxy_lock_trace_bucket(100000) == 1,
        "10 us + 1 ns and 100 us fall in the second");
  CHECK(proxy_lock_trace_bucket(1000000) == 2 && proxy_lock_trace_bucket(1000001) == 3,
        "1 ms is the third, 1 ms + 1 ns the fourth");
  CHECK(proxy_lock_trace_bucket(50000000) == 4 && proxy_lock_trace_bucket(200000000) == 5,
        "50 ms is the fifth, 200 ms the last");

  /* one write hold of about 2 ms on its own site */
  line = __LINE__ + 1;
  proxy_lock_take(&L, 1, __func__, line);
  sleep_ms(2);
  proxy_lock_drop(&L);
  s = site_of("main", line);
  CHECK(s != NULL, "the site is known after one acquire");
  CHECK(s && s->n == 1 && s->wr == 1, "one write acquire on it");
  CHECK(s && s->hold_ns >= 2000000ULL && s->hold_ns < 200000000ULL,
        "hold of 2 ms recorded (%.3f ms)", s ? s->hold_ns / 1e6 : -1.0);
  CHECK(s && s->hist[3] == 1 && s->hold_max_ns == s->hold_ns,
        "in the 1-10 ms bucket, max equals the single hold");
  CHECK(s && s->wait_ns < 1000000ULL, "an uncontended acquire waited under 1 ms");

  /* the same site twice, and a second site in the same function */
  proxy_lock_take(&L, 1, __func__, line);
  proxy_lock_drop(&L);
  line2 = __LINE__ + 1;
  proxy_lock_take(&L, 0, __func__, line2);
  proxy_lock_drop(&L);
  s = site_of("main", line);
  s2 = site_of("main", line2);
  CHECK(s && s->n == 2, "the first site now counts 2");
  CHECK(s2 && s2->n == 1 && s2->wr == 0, "the second line is a site of its own, read");
  CHECK(proxy_lock_trace_sites(NULL, 0) == 2, "two sites known so far");

  /* taken in one function, released in another */
  line = taker();
  dropper();
  s = site_of("taker", line);
  CHECK(s && s->n == 1 && s->hold_ns >= 2000000ULL,
        "the hold lands on the taker's site (%.3f ms)", s ? s->hold_ns / 1e6 : -1.0);
  CHECK(site_of("dropper", 0) == NULL, "the releasing function is not a site");

  /* nested read locks, released in reverse order */
  line = __LINE__ + 1;
  proxy_lock_take(&L, 0, __func__, line);
  sleep_ms(1);
  line2 = __LINE__ + 1;
  proxy_lock_take(&L, 0, __func__, line2);
  sleep_ms(1);
  proxy_lock_drop(&L);   /* inner */
  proxy_lock_drop(&L);   /* outer */
  s = site_of("main", line);
  s2 = site_of("main", line2);
  CHECK(s && s2 && s->n == 1 && s2->n == 1, "both nested sites count one hold");
  CHECK(s && s2 && s->hold_ns > s2->hold_ns && s->hold_ns >= 2000000ULL && s2->hold_ns >= 1000000ULL,
        "outer hold (%.3f ms) exceeds inner hold (%.3f ms)",
        s ? s->hold_ns / 1e6 : -1.0, s2 ? s2->hold_ns / 1e6 : -1.0);
  CHECK(pthread_rwlock_trywrlock(&L) == 0, "the lock is free after both releases");
  pthread_rwlock_unlock(&L);

  /* waiting for a writer */
  atomic_store(&writer_holds, 0);
  pthread_create(&thr, NULL, writer, NULL);
  while (!atomic_load(&writer_holds)) {
    sleep_ms(1);
  }
  line = __LINE__ + 1;
  proxy_lock_take(&L, 1, __func__, line);
  proxy_lock_drop(&L);
  pthread_join(thr, NULL);
  s = site_of("main", line);
  CHECK(s && s->wait_ns >= 3000000ULL,
        "the waiter recorded its wait for the writer (%.3f ms)", s ? s->wait_ns / 1e6 : -1.0);
  CHECK(s && s->wait_max_ns == s->wait_ns, "wait max equals the single wait");
  s2 = site_of("writer", writer_line);
  CHECK(s2 && s2->n == 1 && s2->hold_ns >= 5000000ULL,
        "the writer's hold of 5 ms is on its own site (%.3f ms)", s2 ? s2->hold_ns / 1e6 : -1.0);

  /* deeper than the per-thread stack: 10 nested read locks on one site */
  line = __LINE__ + 2;
  for (i = 0; i < 10; i++) {
    proxy_lock_take(&L, 0, __func__, line);
  }
  for (i = 0; i < 10; i++) {
    proxy_lock_drop(&L);
  }
  s = site_of("main", line);
  CHECK(s && s->n == 8, "8 of 10 nested holds recorded, the rest dropped (%llu)",
        s ? (unsigned long long)s->n : 0ULL);
  CHECK(pthread_rwlock_trywrlock(&L) == 0, "all 10 were released");
  pthread_rwlock_unlock(&L);

  /* a release the tracker never saw acquired */
  pthread_rwlock_wrlock(&L);
  proxy_lock_drop(&L);
  CHECK(pthread_rwlock_trywrlock(&L) == 0, "an untracked hold is released by the helper");
  pthread_rwlock_unlock(&L);
  CHECK(proxy_lock_trace_sites(NULL, 0) == 8, "no site was invented for it (8 sites)");

  /* the interval report: every active site once, then nothing new */
  i = proxy_lock_trace_report(1);
  CHECK(i == 8, "the forced report lists the 8 active sites (%d)", i);
  i = proxy_lock_trace_report(1);
  CHECK(i == 0, "a second report with no new activity lists none (%d)", i);
  line = __LINE__ + 1;
  proxy_lock_take(&L, 1, __func__, line);
  proxy_lock_drop(&L);
  i = proxy_lock_trace_report(1);
  CHECK(i == 1, "one more hold, one site in the next report (%d)", i);

  /* trace off: the helpers lock and unlock, nothing is recorded */
  proxy_lock_trace_state = 0;
  CHECK(proxy_lock_trace_enabled() == 0, "the trace is off");
  proxy_lock_take(&L, 1, __func__, line);
  CHECK(pthread_rwlock_trywrlock(&L) != 0, "the lock is held through the off path");
  proxy_lock_drop(&L);
  CHECK(pthread_rwlock_trywrlock(&L) == 0, "and released through it");
  pthread_rwlock_unlock(&L);
  proxy_lock_trace_state = 1;
  s = site_of("main", line);
  CHECK(s && s->n == 1, "the off-path hold was not recorded");

  printf("%s %d/%d\n", failures ? "FAIL" : "PASS", checks - failures, checks);
  return failures ? 1 : 0;
}
