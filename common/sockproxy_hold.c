/*
 * Copyright (c) 2026 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 *
 * sockproxy_hold.c - holding a client that half-closed after its request.
 */
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

/* uthash precedes sockproxy.h (UT_hash_handle) */
#include "uthash.h"
#include "log.h"
#include "sockproxy_internal.h"
#include "sockproxy_hold.h"

int
sp_eof_held(const proxy_fd_ent_t *pfe)
{
  return pfe && pfe->odir == 0 && pfe->eof_hold;
}

int
sp_notify_arm(void *ns, int fd, notify_type_t type, proxy_fd_ent_t *pfe, uint64_t gen)
{
  if (sp_eof_held(pfe)) {
    type &= ~(NOTI_TYPE_IN | NOTI_TYPE_HUP);
    if (!type) {
      return notify_disarm_ent(ns, fd);
    }
  }
  /* The one direct arming call: the source invariant check allows it here
   * and nowhere else. */
  return notify_add_ent(ns, fd, type, pfe, gen);
}
