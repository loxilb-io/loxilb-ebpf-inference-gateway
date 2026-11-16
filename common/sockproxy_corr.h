/* SPDX-License-Identifier: BSD-3-Clause
 *
 * sockproxy_corr.h - what a request's traceparent and X-Client-Session-Id
 * put in its audit records (deny, completion, settle).
 *
 * The rule for each field: recorded when valid, absent otherwise - never
 * invented, never cut, never rewritten. A header received more than once
 * (two lines or fields in any spelling of the name, an empty one included)
 * or as one comma-joined value is absent: picking one would guess which the
 * client meant. That voids THAT header only; the other one is still recorded.
 *
 * This is the audit capture alone. It runs in every build, beside and
 * independent of the trace-event path (HAVE_HTTP_TRACE), which keeps its own
 * parse. Neither header is read by endpoint selection, the P/D session store
 * or rule matching, and neither is changed on the way to the backend.
 *
 *   traceparent          W3C trace context: "vv-<32 hex>-<16 hex>-<2 hex>",
 *                        lower-case hex; trace-id and parent-id not all zero;
 *                        version ff invalid; version 00 exactly 55 bytes; a
 *                        higher version 55 bytes, or more after a '-'. Gives
 *                        trace_id and parent_span_id (the CALLER's span: the
 *                        gateway has none of its own on the wire). trace-flags
 *                        and tracestate are not read.
 *   X-Client-Session-Id  1-128 bytes of A-Z a-z 0-9 . _ : - ; gives
 *                        session_id. Correlation only: never identity.
 *
 * Optional whitespace (SP, HTAB) around a value is not part of it.
 */
#ifndef __SOCKPROXY_CORR_H__
#define __SOCKPROXY_CORR_H__

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>

#include "sockproxy_ai_gw.h"   /* ai_corr_t */

enum {
  SP_CORR_NONE = 0,         /* a header the capture does not read */
  SP_CORR_TRACEPARENT = 1,
  SP_CORR_SESSION = 2,
};

/* One request's capture. All-zero is "nothing seen". rec is kept as the
 * record must read at every moment, so a caller may hand &rec to a record
 * export directly. */
typedef struct {
  ai_corr_t rec;
  uint8_t   tp_seen;        /* traceparent lines seen: 0, 1, 2 = more */
  uint8_t   sid_seen;       /* X-Client-Session-Id lines seen, the same */
} sp_corr_cap_t;

/* Which field a header name is: the whole name, in any case. name need not
 * be NUL-terminated. */
static inline int
sp_corr_field(const char *name, size_t len)
{
  switch (len) {
  case sizeof("traceparent") - 1:
    return strncasecmp(name, "traceparent", len) == 0
           ? SP_CORR_TRACEPARENT : SP_CORR_NONE;
  case sizeof("x-client-session-id") - 1:
    return strncasecmp(name, "x-client-session-id", len) == 0
           ? SP_CORR_SESSION : SP_CORR_NONE;
  default:
    return SP_CORR_NONE;
  }
}

/* n lower-case hex digits, not all '0' when nonzero is set. */
static inline int
sp_corr_hex_(const char *p, size_t n, int nonzero)
{
  int any = 0;
  for (size_t i = 0; i < n; i++) {
    char c = p[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
      return 0;
    any |= c != '0';
  }
  return !nonzero || any;
}

static inline int
sp_corr_traceparent_ok_(const char *v, size_t len)
{
  if (len < 55 || memchr(v, ',', len))       /* a comma: more than one value */
    return 0;
  if (!sp_corr_hex_(v, 2, 0) || (v[0] == 'f' && v[1] == 'f'))
    return 0;
  if (v[2] != '-' || v[35] != '-' || v[52] != '-')
    return 0;
  if (!sp_corr_hex_(v + 3, 32, 1) || !sp_corr_hex_(v + 36, 16, 1) ||
      !sp_corr_hex_(v + 53, 2, 0))
    return 0;
  if (v[0] == '0' && v[1] == '0')
    return len == 55;
  return len == 55 || v[55] == '-';
}

static inline int
sp_corr_session_ok_(const char *v, size_t len)
{
  if (len < 1 || len > sizeof(((ai_corr_t *)0)->session_id) - 1)
    return 0;
  for (size_t i = 0; i < len; i++) {
    char c = v[i];
    if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
          (c >= '0' && c <= '9') || c == '.' || c == '_' || c == ':' ||
          c == '-'))
      return 0;
  }
  return 1;
}

/* One complete field value of field (one HTTP/1.1 header line, one HPACK
 * field). value need not be NUL-terminated; len 0 is an empty value, which
 * still counts as the header received. SP_CORR_NONE is a no-op. */
static inline void
sp_corr_value(sp_corr_cap_t *cap, int field, const char *value, size_t len)
{
  if (field == SP_CORR_NONE)
    return;
  while (len > 0 && (*value == ' ' || *value == '\t')) {
    value++;
    len--;
  }
  while (len > 0 && (value[len - 1] == ' ' || value[len - 1] == '\t'))
    len--;

  if (field == SP_CORR_TRACEPARENT) {
    cap->rec.trace_id[0] = '\0';
    cap->rec.parent_span_id[0] = '\0';
    if (cap->tp_seen < 2)
      cap->tp_seen++;
    if (cap->tp_seen == 1 && sp_corr_traceparent_ok_(value, len)) {
      memcpy(cap->rec.trace_id, value + 3, 32);
      cap->rec.trace_id[32] = '\0';
      memcpy(cap->rec.parent_span_id, value + 36, 16);
      cap->rec.parent_span_id[16] = '\0';
    }
  } else if (field == SP_CORR_SESSION) {
    cap->rec.session_id[0] = '\0';
    if (cap->sid_seen < 2)
      cap->sid_seen++;
    if (cap->sid_seen == 1 && sp_corr_session_ok_(value, len)) {
      memcpy(cap->rec.session_id, value, len);
      cap->rec.session_id[len] = '\0';
    }
  }
}

/* The record's three fields, each "" when absent. Reads; does not consume. */
static inline void
sp_corr_export(const sp_corr_cap_t *cap, ai_corr_t *out)
{
  *out = cap->rec;
}

/* Back to "nothing seen": the next request on the connection starts empty. */
static inline void
sp_corr_reset(sp_corr_cap_t *cap)
{
  memset(cap, 0, sizeof(*cap));
}

/* The pointer a record export is handed: the capture as it stands. The
 * exports take a non-const pointer (a Go export cannot spell const); none of
 * them writes through it. */
static inline ai_corr_t *
sp_corr_rec(const sp_corr_cap_t *cap)
{
  return (ai_corr_t *)&cap->rec;
}

#endif /* __SOCKPROXY_CORR_H__ */
