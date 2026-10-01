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
#include "sockproxy_hold_core.h"

struct proxy_fd_ent;
struct proxy_epval;

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

/* The EOF handling read a client's FIN. Returns 1 when the caller must stop
 * there and keep the connection (the client is now held, or was already),
 * 0 to carry on as today. Called without the entry's lock; takes it. */
int sp_hold_eof(struct proxy_fd_ent *pfe);

/* The response framer saw an answer begin or end (interim responses are not
 * answers). Client's lock held, or the backend's worker at its EOF. */
void sp_hold_answer_began(struct proxy_fd_ent *client);
void sp_hold_answer_ended(struct proxy_fd_ent *client);

/* A write to the client succeeded (client's lock held). */
void sp_hold_progress(struct proxy_fd_ent *dst);

/* A backend's relay cache emptied: the request has reached the backend
 * (backend's lock held). */
void sp_hold_handoff(struct proxy_fd_ent *be);

/* The leg carrying the client's answer ended: its EOF, or its teardown
 * detaching the client. A new leg attached to the client clears it: rules
 * that route per request let a leg go between requests and take another. */
void sp_hold_leg_ended(struct proxy_fd_ent *client);
void sp_hold_leg_attached(struct proxy_fd_ent *client);

/* After a write that left the client's relay cache empty (client's lock
 * held): returns 1 when the hold is over and the caller should close the
 * client (SHUT_RDWR), 0 to keep waiting or when the client is not held. */
int sp_hold_settle(struct proxy_fd_ent *client);

/* A write to the client, or its pending socket error at teardown, failed
 * with err. */
void sp_hold_peer_error(struct proxy_fd_ent *client, int err);

/* The client woke for OUT; counts it when there was nothing to write. */
void sp_hold_out_wake(struct proxy_fd_ent *client);

/* The connection's shell is being recycled: count how its hold ended. */
void sp_hold_retire(struct proxy_fd_ent *pfe);

/* The health pass: whether there is anything to do, and doing it (expiry,
 * release, the oldest-hold gauge). sp_hold_sweep runs under PROXY_LOCK. */
int sp_hold_sweep_due(void);
void sp_hold_sweep(void);

/* Whether a client may be paired with its backend for kernel redirection.
 * Under a hold-mode rule a client that has already sent its FIN is not: the
 * pair would take its answer out of the hold's reach. */
int sp_hold_pairing_allowed(struct proxy_fd_ent *client, struct proxy_epval *epv);

#endif /* __SOCKPROXY_HOLD_H__ */
