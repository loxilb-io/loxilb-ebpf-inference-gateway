/* SPDX-License-Identifier: BSD-3-Clause
 * Links the production HTTP and SGLang TUs, their real structs and enums.
 * Only metrics exports and owner scheduling are fixture edges; cleanup is real. */
#define _GNU_SOURCE
#include "uthash.h" /* Must precede sockproxy.h, which embeds UT_hash_handle. */
#include "sockproxy_ai_gw.h"
#include "sockproxy_internal.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

proxy_global_stats_t global_stats;
proxy_struct_t *proxy_struct;
static int records, phase, streams;
int notify_owner_thr(void *ctx, int fd)
{
  (void)ctx;
  (void)fd;
  assert(0);
  return -1;
}
int notify_wake_worker(void *ctx, int worker, int fd)
{
  (void)ctx;
  (void)worker;
  (void)fd;
  assert(0);
  return -1;
}

void llb_ai_pd_record(char *m, int64_t p, int64_t d, int kv, int error)
{
  (void)m;
  (void)p;
  (void)d;
  (void)kv;
  records++;
  phase = error;
}
int llb_ai_stream_end(char *t, char *m)
{
  (void)t;
  (void)m;
  streams++;
  return 0;
}
void sp_reap_request(proxy_fd_ent_t *p, uint8_t kind)
{
  assert(p->pd_phase == PD_PHASE_ERROR);
  assert(p->n_rfd == 1); /* drain retained; dead decode detached first */
  p->reap_resp = kind;
}

int main(void)
{
  proxy_fd_ent_t *c = calloc(1, sizeof(*c));
  proxy_fd_ent_t *d = calloc(1, sizeof(*d));
  proxy_fd_ent_t *drain = calloc(1, sizeof(*drain));
  assert(c && d && drain);
  int wire[2], dw[2];
  assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, wire));
  assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, dw));
  c->fd = wire[0];
  c->pd_phase = PD_PHASE_DECODE_SENDING;
  c->pd_sg_active = 1;
  c->rfd_ent[0] = drain;
  c->rfd_ent[1] = d;
  c->n_rfd = 2;
  drain->fd = dw[0];
  drain->pd_sg_drain = 1;
  d->is_pd_decode_backend = 1;
  d->rfd_ent[0] = c;
  d->n_rfd = 1;
  sp_pd_decode_backend_eof(d, c);
  char body[512] = {0};
  assert(recv(wire[1], body, sizeof(body) - 1, MSG_DONTWAIT) > 0);
  assert(strstr(body, "502 Bad Gateway") && strstr(body, "pd_decode_backend_died"));
  assert(atomic_load(&global_stats.pd_decode_ep_died) == 1);
  assert(atomic_load(&global_stats.pd_decode_zero_byte_eof) == 1);
  assert(atomic_load(&global_stats.pd_sg_decode_close_drain) == 1);
  assert(records == 1 && phase == 2 && c->pd_phase == PD_PHASE_NONE && !c->reap_resp);
  assert(recv(dw[1], body, 1, 0) == 0); /* actual shutdown, not just a counter */

  c->pd_phase = PD_PHASE_DECODE_SENDING;
  c->pd_decode_bytes_received = 20;
  sp_pd_decode_backend_eof(d, c);
  assert(phase == 0 && records == 2 && c->pd_phase == PD_PHASE_NONE && !c->reap_resp);
  assert(atomic_load(&global_stats.pd_decode_ep_died) == 1);
  assert(recv(wire[1], body, sizeof(body), MSG_DONTWAIT) == -1); /* no SSE in JSON */

  c->pd_phase = PD_PHASE_DECODE_STREAMING;
  c->sse_active = 1;
  c->pd_sg_active = 1;
  drain->pd_sg_drain_handled = 0;
  sp_pd_decode_backend_eof(d, c);
  assert(phase == 2 && records == 3 && streams == 1);
  assert(atomic_load(&global_stats.pd_decode_ep_died) == 2);
  assert(atomic_load(&global_stats.pd_decode_zero_byte_eof) == 1);
  assert(atomic_load(&global_stats.pd_sg_decode_close_drain) == 2);
  assert(c->reap_resp == SP_REAP_PD_DECODE_EOF && c->pd_phase == PD_PHASE_ERROR);
  assert(!c->rfd_ent[1] && !d->rfd_ent[0] && !d->n_rfd);
  sp_pd_decode_backend_eof(d, c);
  assert(records == 3); /* once-only */
  c->pd_phase = PD_PHASE_DECODE_STREAMING;
  d->is_pd_decode_backend = 0;
  sp_pd_decode_backend_eof(d, c);
  assert(records == 3); /* prefill cannot classify */
  close(wire[0]);
  close(wire[1]);
  close(dw[0]);
  close(dw[1]);
  free(c);
  free(d);
  free(drain);
  puts("real EOF taxonomy: zero-byte 502/counters/drain; JSON success; streaming "
       "error/owner handoff: PASS");
  return 0;
}
