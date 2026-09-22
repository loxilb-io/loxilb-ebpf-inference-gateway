/* SPDX-License-Identifier: BSD-3-Clause
 *
 * sockproxy_fdlist.h - a rule's connection list.
 */
#ifndef __SOCKPROXY_FDLIST_H__
#define __SOCKPROXY_FDLIST_H__

#include <stddef.h>
#include <stdint.h>

/* Every rule keeps the shells of its live connections on one list: the
 * listener, every client leg and every backend leg. The relay walks it to
 * collect metrics, to reap idle and draining connections and to tear the
 * rule down; a connection's shell is linked when its socket is set up and
 * unlinked when it is released. All of that happens under the global proxy
 * lock.
 *
 * The list is doubly linked, and every shell records the rule whose list it
 * is on. That makes the two per-connection operations constant-time: an
 * insert learns whether the shell is on a list already from the shell
 * itself, and an unlink splices the shell out between its own neighbours.
 * With a singly linked list both were a walk of the whole list, and under a
 * connection-per-request load that walk was the largest single item held
 * under the lock: the more connections a rule carried, the longer every
 * accept and every close kept the other workers waiting.
 *
 * The forward pointer keeps its name, `next`, so the readers that walk the
 * list are unchanged; they never touch `prev` or `fdlist_rule`. Shells are
 * pooled and never freed, and a shell that is recycled while still linked
 * keeps its list fields across the pool, so its next insert is refused
 * instead of closing the list into a cycle, and a later unlink still finds
 * its neighbours.
 *
 * Included after the shell and rule types are defined: it uses the shell's
 * `next`, `prev` and `fdlist_rule` and the rule's `val.fdlist` and
 * `val.nfds`, and nothing else of either.
 */

/* Push `pfe` at the head of `ent`'s list. Returns -1, and changes nothing,
 * when the shell is on a list already. */
static inline int
fdlist_link(proxy_map_ent_t *ent, proxy_fd_ent_t *pfe)
{
  if (pfe->fdlist_rule) {
    return -1;
  }
  pfe->prev = NULL;
  pfe->next = ent->val.fdlist;
  if (pfe->next) {
    pfe->next->prev = pfe;
  }
  ent->val.fdlist = pfe;
  ent->val.nfds++;
  pfe->fdlist_rule = ent;
  return 0;
}

/* Take `pfe` off `ent`'s list. Returns -1, and changes nothing, when the
 * shell is not on that list. */
static inline int
fdlist_unlink(proxy_map_ent_t *ent, proxy_fd_ent_t *pfe)
{
  if (pfe->fdlist_rule != ent) {
    return -1;
  }
  if (pfe->prev) {
    pfe->prev->next = pfe->next;
  } else {
    ent->val.fdlist = pfe->next;
  }
  if (pfe->next) {
    pfe->next->prev = pfe->prev;
  }
  pfe->next = NULL;
  pfe->prev = NULL;
  pfe->fdlist_rule = NULL;
  ent->val.nfds--;
  return 0;
}

/* Empty `ent`'s list, leaving every shell that was on it unlinked. Returns
 * how many there were. */
static inline uint32_t
fdlist_clear(proxy_map_ent_t *ent)
{
  proxy_fd_ent_t *p = ent->val.fdlist;
  proxy_fd_ent_t *n;
  uint32_t k = 0;

  while (p) {
    n = p->next;
    p->next = NULL;
    p->prev = NULL;
    p->fdlist_rule = NULL;
    p = n;
    k++;
  }
  ent->val.fdlist = NULL;
  ent->val.nfds = 0;
  return k;
}

/* The first inconsistency in `ent`'s list, or 0: 1 a node whose rule mark is
 * not `ent`, 2 a node whose `prev` is not the node before it, 3 a count that
 * differs from the nodes reached. A walk, for tests and diagnostics only. */
static inline int
fdlist_verify(const proxy_map_ent_t *ent)
{
  const proxy_fd_ent_t *p = ent->val.fdlist;
  const proxy_fd_ent_t *before = NULL;
  uint32_t k = 0;

  while (p) {
    if (p->fdlist_rule != ent) {
      return 1;
    }
    if (p->prev != before) {
      return 2;
    }
    before = p;
    p = p->next;
    k++;
  }
  return k == ent->val.nfds ? 0 : 3;
}

#endif /* __SOCKPROXY_FDLIST_H__ */
