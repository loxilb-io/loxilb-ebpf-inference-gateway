/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_fdlist.c - a rule's connection list.
 *
 * The list is doubly linked with a per-shell rule mark so that an insert's
 * membership check and an unlink touch only the shell and its neighbours.
 * This unit pins what the relay relies on:
 *
 *   - inserts go to the head, so the newest shell is walked first and the
 *     count follows;
 *   - a shell that is on a list is refused a second insert, into the same
 *     rule or another, and nothing changes;
 *   - unlinking the head, a middle node and the tail each leaves the rest
 *     intact, the count right and the shell clean, and the shell can then be
 *     inserted again, into any rule;
 *   - unlinking a shell that is on no list, or on another rule's list, is
 *     refused and changes nothing;
 *   - clearing a rule's list leaves every shell unlinked and the count zero;
 *   - a shell that kept its list fields across the pool (recycled while
 *     linked) is refused a re-insert and is still unlinked correctly;
 *   - over thousands of shells inserted and removed in a scattered order the
 *     invariants hold after every step.
 *
 * Build (wired into `make test_fdl`):
 *   gcc -Wall -Wextra -Werror -o test_fdlist test_fdlist.c -I.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* The two structures the unit touches, with the members it touches: the
 * shell's list fields and the rule's list head and count. */
typedef struct proxy_fd_ent {
  int fd;
  struct proxy_fd_ent *next;
  struct proxy_fd_ent *prev;
  struct proxy_map_ent *fdlist_rule;
} proxy_fd_ent_t;

typedef struct proxy_map_ent {
  struct {
    uint32_t nfds;
    struct proxy_fd_ent *fdlist;
  } val;
} proxy_map_ent_t;

#include "sockproxy_fdlist.h"

static int checks, failures;

#define CHECK(cond, ...) do {                                        \
    checks++;                                                        \
    if (cond) {                                                      \
      printf("ok %d - ", checks); printf(__VA_ARGS__); printf("\n"); \
    } else {                                                         \
      failures++;                                                    \
      printf("FAIL %d - ", checks); printf(__VA_ARGS__);             \
      printf("   (%s:%d)\n", __FILE__, __LINE__);                    \
    }                                                                \
  } while (0)

/* The fds along the list, head first, as a string like "3,2,1". */
static const char *
walk(const proxy_map_ent_t *ent, char *buf, size_t cap)
{
  size_t n = 0;
  const proxy_fd_ent_t *p;

  buf[0] = '\0';
  for (p = ent->val.fdlist; p && n < cap; p = p->next) {
    n += (size_t)snprintf(buf + n, cap - n, "%s%d", n ? "," : "", p->fd);
  }
  return buf;
}

static int
unlinked(const proxy_fd_ent_t *p)
{
  return p->next == NULL && p->prev == NULL && p->fdlist_rule == NULL;
}

static void
test_order_and_refusal(void)
{
  proxy_map_ent_t r = { { 0, NULL } }, other = { { 0, NULL } };
  proxy_fd_ent_t a = { 1, 0, 0, 0 }, b = { 2, 0, 0, 0 }, c = { 3, 0, 0, 0 };
  char s[64];

  CHECK(fdlist_link(&r, &a) == 0 && fdlist_link(&r, &b) == 0 && fdlist_link(&r, &c) == 0,
        "three inserts accepted");
  CHECK(strcmp(walk(&r, s, sizeof(s)), "3,2,1") == 0 && r.val.nfds == 3,
        "inserted at the head, newest first, count 3 (%s)", s);
  CHECK(c.prev == NULL && b.prev == &c && a.prev == &b && a.next == NULL,
        "back pointers follow the walk");
  CHECK(a.fdlist_rule == &r && b.fdlist_rule == &r && c.fdlist_rule == &r,
        "every shell marked with its rule");
  CHECK(fdlist_verify(&r) == 0, "list verifies");

  CHECK(fdlist_link(&r, &b) == -1, "re-insert of a linked shell refused");
  CHECK(fdlist_link(&other, &b) == -1, "insert into another rule refused while linked");
  CHECK(strcmp(walk(&r, s, sizeof(s)), "3,2,1") == 0 && r.val.nfds == 3 && other.val.nfds == 0,
        "a refused insert changes nothing (%s)", s);
}

static void
test_unlink(void)
{
  proxy_map_ent_t r = { { 0, NULL } }, other = { { 0, NULL } };
  proxy_fd_ent_t n[5];
  proxy_fd_ent_t loose = { 9, 0, 0, 0 };
  char s[64];
  int i;

  for (i = 0; i < 5; i++) {
    memset(&n[i], 0, sizeof(n[i]));
    n[i].fd = i + 1;
    fdlist_link(&r, &n[i]);
  }
  /* list: 5,4,3,2,1 */
  CHECK(fdlist_unlink(&r, &n[2]) == 0 && strcmp(walk(&r, s, sizeof(s)), "5,4,2,1") == 0 &&
        r.val.nfds == 4 && n[3].next == &n[1] && n[1].prev == &n[3] && unlinked(&n[2]),
        "middle node unlinked, neighbours spliced, shell clean (%s)", s);
  CHECK(fdlist_unlink(&r, &n[4]) == 0 && strcmp(walk(&r, s, sizeof(s)), "4,2,1") == 0 &&
        r.val.fdlist == &n[3] && n[3].prev == NULL && unlinked(&n[4]),
        "head unlinked, new head has no prev (%s)", s);
  CHECK(fdlist_unlink(&r, &n[0]) == 0 && strcmp(walk(&r, s, sizeof(s)), "4,2") == 0 &&
        n[1].next == NULL && unlinked(&n[0]),
        "tail unlinked, new tail ends the list (%s)", s);
  CHECK(fdlist_verify(&r) == 0 && r.val.nfds == 2, "list verifies after three unlinks");

  CHECK(fdlist_unlink(&r, &loose) == -1 && r.val.nfds == 2,
        "unlink of a shell on no list refused");
  CHECK(fdlist_link(&other, &n[0]) == 0 && fdlist_unlink(&r, &n[0]) == -1 &&
        other.val.nfds == 1 && r.val.nfds == 2,
        "unlink from a rule the shell is not on refused");
  CHECK(fdlist_unlink(&other, &n[0]) == 0 && fdlist_link(&r, &n[0]) == 0 &&
        strcmp(walk(&r, s, sizeof(s)), "1,4,2") == 0 && fdlist_verify(&r) == 0,
        "an unlinked shell inserts again, into any rule (%s)", s);

  CHECK(fdlist_unlink(&r, &n[3]) == 0 && fdlist_unlink(&r, &n[1]) == 0 && fdlist_unlink(&r, &n[0]) == 0 &&
        r.val.fdlist == NULL && r.val.nfds == 0,
        "emptied by unlinks: head NULL, count 0");
}

static void
test_clear(void)
{
  proxy_map_ent_t r = { { 0, NULL } };
  proxy_fd_ent_t n[4];
  int i, clean = 1;

  for (i = 0; i < 4; i++) {
    memset(&n[i], 0, sizeof(n[i]));
    n[i].fd = i + 1;
    fdlist_link(&r, &n[i]);
  }
  CHECK(fdlist_clear(&r) == 4 && r.val.fdlist == NULL && r.val.nfds == 0,
        "clear reports 4, head NULL, count 0");
  for (i = 0; i < 4; i++) {
    clean = clean && unlinked(&n[i]);
  }
  CHECK(clean, "every shell clean after clear");
  CHECK(fdlist_clear(&r) == 0, "clearing an empty list reports 0");
  CHECK(fdlist_link(&r, &n[1]) == 0 && r.val.nfds == 1, "a cleared shell inserts again");
}

/* A shell recycled while still linked keeps next, prev and its rule mark
 * across the pool; the rest of it is zeroed. Its next insert must be refused
 * and it must still unlink cleanly by its kept neighbours. */
static void
test_recycled_while_linked(void)
{
  proxy_map_ent_t r = { { 0, NULL } };
  proxy_fd_ent_t a = { 1, 0, 0, 0 }, b = { 2, 0, 0, 0 }, c = { 3, 0, 0, 0 };
  proxy_fd_ent_t *nx, *pv;
  proxy_map_ent_t *rule;
  char s[64];

  fdlist_link(&r, &a);
  fdlist_link(&r, &b);
  fdlist_link(&r, &c);
  /* the pool's pop: zero the shell, keep the list fields */
  nx = b.next; pv = b.prev; rule = b.fdlist_rule;
  memset(&b, 0, sizeof(b));
  b.next = nx; b.prev = pv; b.fdlist_rule = rule;

  CHECK(fdlist_link(&r, &b) == -1 && strcmp(walk(&r, s, sizeof(s)), "3,0,1") == 0 && r.val.nfds == 3,
        "re-insert of the recycled shell refused, list intact (%s)", s);
  CHECK(fdlist_unlink(&r, &b) == 0 && strcmp(walk(&r, s, sizeof(s)), "3,1") == 0 &&
        fdlist_verify(&r) == 0 && unlinked(&b),
        "the recycled shell still unlinks by its kept neighbours (%s)", s);
  CHECK(fdlist_link(&r, &b) == 0 && r.val.nfds == 3 && fdlist_verify(&r) == 0,
        "and inserts again once unlinked");
}

static void
test_many(void)
{
  enum { N = 20000 };
  proxy_map_ent_t r = { { 0, NULL } };
  proxy_fd_ent_t *n = calloc(N, sizeof(*n));
  int i, ok = 1;
  uint32_t left = N;

  for (i = 0; i < N; i++) {
    n[i].fd = i;
    ok = ok && fdlist_link(&r, &n[i]) == 0;
  }
  CHECK(ok && r.val.nfds == N && fdlist_verify(&r) == 0, "%d shells inserted, list verifies", N);

  /* remove every third, then every other of the rest, then the rest, and
   * verify after each pass; the counts are exact */
  for (i = 0; i < N; i += 3) {
    ok = ok && fdlist_unlink(&r, &n[i]) == 0;
    left--;
  }
  CHECK(ok && r.val.nfds == left && fdlist_verify(&r) == 0, "every third removed: %u left, verifies", left);
  for (i = 1; i < N; i += 2) {
    if (n[i].fdlist_rule) {
      ok = ok && fdlist_unlink(&r, &n[i]) == 0;
      left--;
    }
  }
  CHECK(ok && r.val.nfds == left && fdlist_verify(&r) == 0, "every other removed: %u left, verifies", left);
  for (i = 0; i < N; i++) {
    int on = n[i].fdlist_rule != NULL;
    ok = ok && fdlist_unlink(&r, &n[i]) == (on ? 0 : -1);
  }
  CHECK(ok && r.val.nfds == 0 && r.val.fdlist == NULL, "the rest removed, the removed refused: empty");
  for (i = 0; i < N; i++) {
    ok = ok && unlinked(&n[i]);
  }
  CHECK(ok, "every shell clean");
  free(n);
}

int
main(void)
{
  test_order_and_refusal();
  test_unlink();
  test_clear();
  test_recycled_while_linked();
  test_many();
  printf("=== results: %d/%d passed ===\n", checks - failures, checks);
  return failures ? 1 : 0;
}
