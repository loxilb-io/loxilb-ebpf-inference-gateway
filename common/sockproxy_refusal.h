/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __SOCKPROXY_REFUSAL_H__
#define __SOCKPROXY_REFUSAL_H__
#include <stddef.h>
#include <stdint.h>

/* The callers build their answers in buffers of 512 bytes; the reply holds
 * one with its refusal mark (the stage and the request's ID after the status
 * line). The room for the mark is SP_REFUSAL_MARK_MAX, as a number: this
 * header is included by sockproxy.h, and sockproxy_refusal_mark.h must not
 * be pulled in ahead of sockproxy_ai_admit.h (its check of the stage numbers
 * is compiled only behind that one). sockproxy_refusal.c holds the two equal. */
#define SP_PD_REPLY_TEXT_MAX 512
#define SP_PD_REPLY_MARK_ROOM 313
#define SP_PD_REPLY_MAX (SP_PD_REPLY_TEXT_MAX + SP_PD_REPLY_MARK_ROOM)
#define SP_PD_REPLY_TIMEOUT_NS (200ULL * 1000 * 1000)

/* Owned by the client's notifier worker. The bytes remain stable across TLS
 * WANT_READ/WANT_WRITE retries; no request buffer or stack pointer is retained. */
typedef struct sp_pd_reply {
  uint8_t active, wait, draining;
  uint16_t len, off;
  uint64_t deadline_ns;
  size_t drain_remaining;
  uint8_t bytes[SP_PD_REPLY_MAX];
} sp_pd_reply_t;

struct proxy_fd_ent;
/* 0: fully written and close-ready; 1: held for output/drain readiness;
 * -1: terminal send failure. The
 * caller must not tear down while active. None of these functions polls.
 * The response goes out with the refusal mark after its status line: the
 * wire name of `stage` when it has one, and the request's own ID when it
 * has one (sockproxy_refusal_mark.h). Nothing else of it changes. */
int sp_pd_send_refusal(struct proxy_fd_ent *pfe, int stage, uint16_t status,
                       const char *code, const void *response, size_t len,
                       size_t drain_remaining);
void sp_pd_refusal_event(struct proxy_fd_ent *pfe, int type);
void sp_pd_refusal_tick(void);
#endif
