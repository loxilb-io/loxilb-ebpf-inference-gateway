/*
 * Copyright (c) 2026 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */
#ifndef __SOCKPROXY_HOLD_H__
#define __SOCKPROXY_HOLD_H__

/*
 * Holding a client that half-closed after its request.
 *
 * A client that writes its request and then shuts down its write side is
 * saying "that was my last request", not "forget the answer". A connection
 * held for that reason keeps its write side open until the answer is out.
 * Its read side is already at EOF, which changes how its fd may be armed:
 * see sp_notify_arm.
 */

#include <stdint.h>

#include "notify.h"

struct proxy_fd_ent;

/* Whether this client is held on EOF: its FIN has been read and it is being
 * kept open for an answer still owed. Every place that treats a held client
 * differently asks this and nothing else, so they cannot disagree. A client
 * whose FIN was only seen as RDHUP while its reads were paused, and not yet
 * read, is not held on EOF. */
int sp_eof_held(const struct proxy_fd_ent *pfe);

/* Arms fd's poll events. Every arming of a proxy connection's fd goes
 * through here, so the rule for a held client is kept in one place.
 *
 * A held client's socket reports POLLIN and POLLRDHUP for as long as it is
 * armed for them, level-triggered: its read side is at EOF. Armed that way,
 * every poll would re-enter the EOF handling. So for a held client the read
 * events (IN, and HUP, which asks for RDHUP) are dropped: OUT is kept while
 * there is something to write, and with nothing left the fd is disarmed.
 * POLLHUP and POLLERR are reported without being asked for, so a reset or a
 * full close still tears the connection down.
 *
 * Anything else - a backend, a client not held, a NULL pfe - is armed exactly
 * as asked. */
int sp_notify_arm(void *ns, int fd, notify_type_t type, struct proxy_fd_ent *pfe,
                  uint64_t gen);

#endif /* __SOCKPROXY_HOLD_H__ */
