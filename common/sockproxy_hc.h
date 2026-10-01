/*
 * Copyright (c) 2026 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */
#ifndef __SOCKPROXY_HC_H__
#define __SOCKPROXY_HC_H__

/*
 * Half-close observation: what a client's FIN looked like when it arrived,
 * and how a response made progress towards the client.
 *
 * Observation only. Every hook here records and returns; none of them changes
 * what the proxy relays, when it closes, or what any caller does next, and
 * none of them asserts. The values leave the process as metrics through
 * proxy_get_metrics (hc_metrics_fill).
 *
 * Client-side hooks take the CLIENT entry. Where a hook is called with the
 * entry's lock held, the comment at the hook says so.
 */

#include <stddef.h>
#include <stdint.h>

#include "sockproxy_hc_core.h"

struct proxy_fd_ent;
struct proxy_metrics_snapshot;

/* The kernel was given a direction of this connection (a verdict entry was
 * added). Sticky: never cleared. */
void hc_note_accel(struct proxy_fd_ent *client, uint8_t bits);

/* Request framer (the client's worker). */
void hc_req_begin(struct proxy_fd_ent *client);
void hc_req_header_field(struct proxy_fd_ent *client, const char *at, size_t len);
void hc_req_header_field_done(struct proxy_fd_ent *client);
void hc_req_header_value(struct proxy_fd_ent *client, const char *at, size_t len);
void hc_req_header_value_done(struct proxy_fd_ent *client);
void hc_req_headers_done(struct proxy_fd_ent *client);
void hc_req_done(struct proxy_fd_ent *client);

/* The request's "stream" field where the proxy read the whole body:
 * 1 true, 0 false or absent, -1 the body was not a complete JSON object. */
void hc_note_stream(struct proxy_fd_ent *client, int stream);

/* A request was parked (setup or keep-alive queue). */
void hc_note_park(struct proxy_fd_ent *client, enum hc_entry kind);

/* A FIN was seen at `entry`. Only the first sight of a FIN on a connection
 * counts; later exits of the same FIN return without counting. `partial`: the
 * request the FIN arrived behind was not complete, so no gap is taken. */
void hc_fin_seen(struct proxy_fd_ent *client, enum hc_entry entry, int partial);

/* Which pause held a client's reads when an RDHUP found them paused. */
enum hc_entry hc_paused_entry(struct proxy_fd_ent *client);

/* A TLS client's read ended at a FIN, by `path`. */
void hc_tls_fin_seen(struct proxy_fd_ent *client, enum hc_tls_path path);

/* A TLS read on a client failed with SSL_ERROR_SSL / SSL_ERROR_SYSCALL. Call
 * before anything pops the OpenSSL error queue, with errno as the read left
 * it. Counts a FIN without close_notify, or a reset; a real TLS error is not
 * counted. */
void hc_tls_read_failed(struct proxy_fd_ent *client, int ssl_err, int rval, int err_no);

/* A client connection was reset (read error or pending socket error). */
void hc_client_reset_seen(struct proxy_fd_ent *client);
void hc_client_reset_check(struct proxy_fd_ent *client);

/* An answer began (response framer, client's lock held) or ended (the framer
 * under the same lock, or a backend's close without it). Interim responses
 * are not reported. */
void hc_resp_headers(struct proxy_fd_ent *client);
void hc_resp_done(struct proxy_fd_ent *client);

/* A write to `dst` succeeded (dst's lock held). A write to a backend is where
 * a framed request is handed over; a write to a client is response progress. */
void hc_prog_write(struct proxy_fd_ent *dst);

/* The client's relay cache is empty after a write, or the client is being
 * torn down (client's lock held). */
void hc_prog_settled(struct proxy_fd_ent *client);

void hc_metrics_fill(struct proxy_metrics_snapshot *s);

#endif /* __SOCKPROXY_HC_H__ */
