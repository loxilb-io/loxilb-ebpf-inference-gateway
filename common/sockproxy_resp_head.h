/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-Clause) */
/*
 * sockproxy_resp_head.h - the head of an admitted HTTP/1.1 response, put
 * together when the backend sent it in more than one read.
 *
 * The admission headers (fc_expose_h1) and the class headers
 * (sp_class_expose_h1) go on a response head only when the whole head is in
 * the buffer they are given. A head that came in pieces used to leave
 * without them, and with whatever lines of those names the backend sent.
 * Here the pieces are kept, at most SP_RESP_HEAD_ASSEMBLE_MAX bytes of
 * them, until the blank line arrives; the two helpers then see one whole
 * head, and it leaves ahead of the bytes that followed it in the last read.
 * The strip of a backend's X-Loxilb-Refusal-* lines, which the relay makes
 * on a head that is whole in its read, is made on the head put together
 * here as well.
 *
 * What is kept is only ever the start of a response head: the status line
 * so far reads "HTTP/1.x ddd", and no blank line has been seen. A client
 * can do nothing with those bytes before the rest arrives, so keeping them
 * delays nothing it could act on. An interim (1xx) head is passed on as
 * soon as it is whole and the final head is still awaited. A head longer
 * than the bound is passed on as it came, and the caller counts it.
 *
 * Pure: no socket, no lock, no connection type. The relay calls
 * sp_resp_head_relay under the client entry's lock; the unit
 * (test_resp_head_assemble.c) calls the same function.
 */
#ifndef __SOCKPROXY_RESP_HEAD_H__
#define __SOCKPROXY_RESP_HEAD_H__

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "sockproxy_fc.h"
#include "sockproxy_obj_hint.h"

/* The longest head that is put together. One that is whole in a single
 * read is not bound by this: it never enters the buffer. */
#define SP_RESP_HEAD_ASSEMBLE_MAX (16 * 1024)
/* Room behind the head for the lines the two helpers add (192 + 320). */
#define SP_RESP_HEAD_ROOM         1024

/* Per client connection. buf is allocated when a head turns out to be
 * split and freed when that head leaves, so a connection holds
 * SP_RESP_HEAD_ASSEMBLE_MAX + SP_RESP_HEAD_ROOM bytes while a head is
 * being put together and nothing otherwise. */
typedef struct sp_resp_head {
  uint8_t *buf;
  uint32_t len;                  /* bytes of the head kept so far */
  uint8_t  over_logged;          /* the over-bound log line was written */
} sp_resp_head_t;

static inline void
sp_resp_head_free(sp_resp_head_t *a)
{
  free(a->buf);
  a->buf = NULL;
  a->len = 0;
}

/* A head longer than the bound was passed on as it came: counted every
 * time, and 1 is returned the first time on a connection, when the caller
 * writes its one log line. */
static inline int
sp_resp_head_over(sp_resp_head_t *a)
{
  atomic_fetch_add_explicit(&fc_anomaly_total[FC_A_EXPOSE_HEAD_OVERFLOW], 1,
                            memory_order_relaxed);
  if (a->over_logged)
    return 0;
  a->over_logged = 1;
  return 1;
}

/* What the two helpers need of the request, and the two flags that say a
 * head still owes their lines. */
typedef struct sp_resp_expose {
  uint8_t *fc_pending;           /* the admission headers are owed */
  uint8_t *class_pending;        /* the class headers are owed */
  int fc_x;                      /* fc_expose_take's answer for this read */
  const fc_expose_t *fc_v;
  const char *objective;
  uint8_t priority_class;
  const char *requested;         /* NULL unless the objective was denied */
  /* What is removed from every relayed response head (a backend's
   * X-Loxilb-Refusal-*), run once more on a head that was put together:
   * the relay's own pass saw it in pieces and left it. buf holds exactly
   * one head; returns its new length. May be NULL. */
  size_t (*strip)(uint8_t *buf, size_t len);
} sp_resp_expose_t;

/* The two helpers on the bytes at `buf`, as the relay has always called
 * them: each clears its flag unless what it saw was an interim head.
 * `skipped` (may be NULL) is set when the admission helper had values and
 * did not write them. Returns the new length. */
static inline size_t
sp_resp_expose_apply(const sp_resp_expose_t *x, uint8_t *buf, size_t len,
                     size_t cap, int *skipped)
{
  if (skipped)
    *skipped = 0;
  if (*x->fc_pending) {
    int xr = FC_EXPOSE_H1_SKIPPED;

    if (x->fc_x)
      len = fc_expose_h1(buf, len, cap, x->fc_v, &xr);
    if (xr != FC_EXPOSE_H1_INTERIM)
      *x->fc_pending = 0;
    if (skipped && x->fc_x && xr == FC_EXPOSE_H1_SKIPPED)
      *skipped = 1;
  }
  /* The class headers, after the block above: it removes every line of
   * the admission family the backend sent before it adds its own. */
  if (*x->class_pending) {
    int xr = SP_CLASS_H1_SKIPPED;

    len = sp_class_expose_h1(buf, len, cap, x->objective, x->priority_class,
                             x->requested, &xr);
    if (xr != SP_CLASS_H1_INTERIM)
      *x->class_pending = 0;
  }
  return len;
}

/* Can b[0..n) be the start of "HTTP/1.x ddd"? The same test the two
 * helpers make of a whole status line, on as many bytes as there are. */
static inline int
sp_resp_head_prefix_ok(const uint8_t *b, size_t n)
{
  static const char p[] = "HTTP/1.";

  for (size_t i = 0; i < n && i < 12; i++) {
    if (i < 7) {
      if (b[i] != (uint8_t)p[i]) return 0;
    } else if (i == 8) {
      if (b[i] != ' ') return 0;
    } else if (i == 9) {
      if (b[i] < '1' || b[i] > '5') return 0;
    } else if (i > 9) {
      if (b[i] < '0' || b[i] > '9') return 0;
    }
  }
  return 1;
}

static inline int
sp_resp_head_status(const uint8_t *b)
{
  return (b[9] - '0') * 100 + (b[10] - '0') * 10 + (b[11] - '0');
}

/* The length of the head at b, its blank line included; 0 when b[0..n)
 * does not hold all of it. */
static inline size_t
sp_resp_head_whole(const uint8_t *b, size_t n)
{
  for (size_t i = 0; i + 3 < n; i++) {
    if (b[i] == '\r' && b[i + 1] == '\n' && b[i + 2] == '\r' &&
        b[i + 3] == '\n')
      return i + 4;
  }
  return 0;
}

enum sp_resp_head_res {
  SP_RESP_HEAD_DONE = 0,         /* a final head was given to the helpers */
  SP_RESP_HEAD_PASS,             /* only interim heads: the final one is awaited */
  SP_RESP_HEAD_HELD,             /* the start of a head is kept; more must come */
  SP_RESP_HEAD_NOT_HEAD,         /* not a response head: as it came, flags cleared */
  SP_RESP_HEAD_OVER,             /* longer than the bound: as it came, flags cleared */
  SP_RESP_HEAD_ERR,              /* emit failed: the connection is to be closed */
};

/* Bytes that leave now, ahead of whatever stays in the read. Returns < 0
 * when they could not be taken. */
typedef int (*sp_resp_head_emit_fn)(void *ctx, const uint8_t *buf, size_t len);

/*
 * One read of a response whose head still owes headers (either flag of
 * `x` set), or the read after one that left bytes kept.
 *
 * msg[0..*len) is the read, in a buffer of `cap` bytes. On return the
 * caller sends msg[*off .. *off + *len) the way it sends any read; the
 * bytes before *off were taken into the kept head and have left through
 * `emit`, in order, or are still kept. *len may be 0.
 *
 * Order on the wire is the order of arrival: `emit` is called only for
 * bytes that precede everything left in msg, and nothing is kept behind
 * bytes that are sent.
 */
static inline enum sp_resp_head_res
sp_resp_head_relay(sp_resp_head_t *a, const sp_resp_expose_t *x,
                   uint8_t *msg, size_t *len, size_t cap, size_t *off,
                   sp_resp_head_emit_fn emit, void *ctx, int *skipped)
{
  size_t n = *len, pos = 0, base, p;

  *off = 0;
  if (skipped)
    *skipped = 0;

  if (a->len > 0) {
    /* Bytes are kept: the read continues that head. */
    int whole = 0, bad = 0, over = 0;

    while (pos < n) {
      if (a->len >= SP_RESP_HEAD_ASSEMBLE_MAX) {
        over = 1;
        break;
      }
      a->buf[a->len++] = msg[pos++];
      if (a->len <= 12 && !sp_resp_head_prefix_ok(a->buf, a->len)) {
        bad = 1;
        break;
      }
      if (a->len >= 4 && a->buf[a->len - 4] == '\r' &&
          a->buf[a->len - 3] == '\n' && a->buf[a->len - 2] == '\r' &&
          a->buf[a->len - 1] == '\n') {
        whole = 1;
        break;
      }
    }
    if (!whole && !bad && !over) {
      *off = n;
      *len = 0;
      return SP_RESP_HEAD_HELD;
    }
    if (whole && x->strip)
      a->len = (uint32_t)x->strip(a->buf, a->len);
    if (whole && sp_resp_head_status(a->buf) >= 200) {
      a->len = (uint32_t)sp_resp_expose_apply(x, a->buf, a->len,
                   SP_RESP_HEAD_ASSEMBLE_MAX + SP_RESP_HEAD_ROOM, skipped);
    }
    {
      int final = whole && sp_resp_head_status(a->buf) >= 200;
      int rc = emit(ctx, a->buf, a->len);

      sp_resp_head_free(a);
      *off = pos;
      *len = n - pos;
      if (rc < 0)
        return SP_RESP_HEAD_ERR;
      if (bad) {
        *x->fc_pending = *x->class_pending = 0;
        return SP_RESP_HEAD_NOT_HEAD;
      }
      if (over) {
        *x->fc_pending = *x->class_pending = 0;
        return SP_RESP_HEAD_OVER;
      }
      if (final)
        return SP_RESP_HEAD_DONE;
    }
    /* An interim head left; the final one starts at msg[pos], if it has
     * arrived. */
  }

  base = p = pos;
  for (;;) {
    size_t rem = n - p, e;

    if (rem == 0) {
      *len = p - base;
      return SP_RESP_HEAD_PASS;
    }
    if (!sp_resp_head_prefix_ok(msg + p, rem)) {
      *x->fc_pending = *x->class_pending = 0;
      *len = n - base;
      return SP_RESP_HEAD_NOT_HEAD;
    }
    e = sp_resp_head_whole(msg + p, rem);
    if (e == 0) {
      if (rem > SP_RESP_HEAD_ASSEMBLE_MAX) {
        *x->fc_pending = *x->class_pending = 0;
        *len = n - base;
        return SP_RESP_HEAD_OVER;
      }
      a->buf = malloc(SP_RESP_HEAD_ASSEMBLE_MAX + SP_RESP_HEAD_ROOM);
      if (!a->buf) {
        /* No memory to keep it: as before, the head goes as it came. */
        *x->fc_pending = *x->class_pending = 0;
        *len = n - base;
        return SP_RESP_HEAD_NOT_HEAD;
      }
      memcpy(a->buf, msg + p, rem);
      a->len = (uint32_t)rem;
      *len = p - base;
      return SP_RESP_HEAD_HELD;
    }
    if (sp_resp_head_status(msg + p) < 200) {
      p += e;                    /* a whole interim head: it goes with the read */
      continue;
    }
    *len = (p - base) + sp_resp_expose_apply(x, msg + p, n - p, cap - p, skipped);
    return SP_RESP_HEAD_DONE;
  }
}

#endif /* __SOCKPROXY_RESP_HEAD_H__ */
