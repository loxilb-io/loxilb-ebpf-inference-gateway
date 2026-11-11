/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-Clause) */
/*
 * The objective a request asks for by header, and the class headers an
 * admitted response carries. Kept apart from the proxy so the unit test
 * runs the same code on buffers of exact size.
 */
#ifndef __SOCKPROXY_OBJ_HINT_H__
#define __SOCKPROXY_OBJ_HINT_H__

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#define SP_OBJ_HDR       "x-llm-d-inference-objective"
#define SP_OBJ_HDR_OLD   "x-gateway-inference-objective"

/* What a header name is to the capture. */
#define SP_OBJ_NOT       0
#define SP_OBJ_CANON     1   /* SP_OBJ_HDR */
#define SP_OBJ_OLD       2   /* SP_OBJ_HDR_OLD, deprecated */

/* A name longer than an objective can be names no objective. It is kept
 * as this value, which no objective can have, so the request reads as one
 * that asked for an objective it may not use, not as one that asked for
 * nothing. */
#define SP_OBJ_OVERSIZE  "(oversize)"

typedef struct sp_obj_hint {
  char    name[64];     /* the objective asked for; "" = none */
  uint8_t len;
  uint8_t canon;        /* name came from SP_OBJ_HDR */
  uint8_t capturing;    /* SP_OBJ_* of the value in progress; 0 = none */
  uint8_t skip;         /* the value in progress is not kept */
} sp_obj_hint_t;

/* The whole name is compared, length included: a longer header that only
 * begins with one of the two is not a hint. */
static inline int
sp_obj_hint_which(const char *hname, size_t hlen)
{
  if (hlen == sizeof(SP_OBJ_HDR) - 1 &&
      !strncasecmp(hname, SP_OBJ_HDR, hlen))
    return SP_OBJ_CANON;
  if (hlen == sizeof(SP_OBJ_HDR_OLD) - 1 &&
      !strncasecmp(hname, SP_OBJ_HDR_OLD, hlen))
    return SP_OBJ_OLD;
  return SP_OBJ_NOT;
}

static inline void
sp_obj_hint_reset(sp_obj_hint_t *h)
{
  memset(h, 0, sizeof(*h));
}

/* A new header name: whatever value was being collected is complete. */
static inline void
sp_obj_hint_name(sp_obj_hint_t *h)
{
  h->capturing = SP_OBJ_NOT;
  h->skip = 0;
}

/*
 * One fragment of a header value whose name is `which`. A value can come
 * in several fragments (a read boundary inside it); they are appended. The
 * new name wins over the deprecated one in either order; a header repeated
 * under one name is last-one-wins, like the proxy's other captures.
 */
static inline void
sp_obj_hint_val(sp_obj_hint_t *h, int which, const char *at, size_t len)
{
  if (which == SP_OBJ_NOT)
    return;
  if (h->capturing != which) {
    h->capturing = (uint8_t)which;
    h->skip = (which == SP_OBJ_OLD && h->canon) ? 1 : 0;
    if (!h->skip) {
      h->name[0] = '\0';
      h->len = 0;
      h->canon = which == SP_OBJ_CANON;
    }
  }
  if (h->skip || len == 0)
    return;
  if (!strcmp(h->name, SP_OBJ_OVERSIZE) && h->len == 0)
    return;
  if ((size_t)h->len + len >= sizeof(h->name)) {
    snprintf(h->name, sizeof(h->name), "%s", SP_OBJ_OVERSIZE);
    h->len = 0;
    return;
  }
  memcpy(h->name + h->len, at, len);
  h->len += (uint8_t)len;
  h->name[h->len] = '\0';
}

static inline const char *
sp_class_name(uint8_t priority_class)
{
  return priority_class == 1 ? "critical" :
         priority_class == 2 ? "sheddable" : "standard";
}

#define SP_CLASS_HDR_OBJ   "x-loxilb-admission-objective"
#define SP_CLASS_HDR_CLASS "x-loxilb-admission-class"
/* What the request asked for, on a response whose request named an
 * objective it may not use and was admitted at its default all the same.
 * Absent on every other response: its absence says "not denied". */
#define SP_CLASS_HDR_OBJ_REQ "x-loxilb-admission-objective-requested"

/* A header value is written only when every byte of it is a visible
 * character: an objective name is whatever the operator stored. */
static inline int
sp_class_hdr_value_ok(const char *v)
{
  if (!v || !v[0])
    return 0;
  for (; *v; v++)
    if ((unsigned char)*v <= 0x20 || (unsigned char)*v >= 0x7f)
      return 0;
  return 1;
}

#define SP_CLASS_H1_DONE     0
#define SP_CLASS_H1_INTERIM  1   /* a 1xx head: the final head is still to come */
#define SP_CLASS_H1_SKIPPED  2   /* head not whole in this read, or no room */

/*
 * Put X-Loxilb-Admission-Class, X-Loxilb-Admission-Objective when a hint
 * was applied, and X-Loxilb-Admission-Objective-Requested when `requested`
 * is given (the caller passes it only for a request whose objective was
 * denied) on a response head. Lines of those three names the backend sent
 * are removed first: they say what the gateway decided. All of it or none:
 * a head with no room for every line takes none. Only the head is touched;
 * the bytes after it move as they are. Returns the new length (len itself
 * when nothing was done).
 */
static inline size_t
sp_class_expose_h1(uint8_t *buf, size_t len, size_t cap, const char *objective,
                   uint8_t priority_class, const char *requested, int *res)
{
  char add[320];
  int rlen = 0;
  size_t end = 0, i, n;
  int alen, status;

  if (res) *res = SP_CLASS_H1_SKIPPED;
  if (!buf || len < 12 || memcmp(buf, "HTTP/1.", 7) != 0 ||
      buf[8] != ' ' || buf[9] < '1' || buf[9] > '5' ||
      buf[10] < '0' || buf[10] > '9' || buf[11] < '0' || buf[11] > '9')
    return len;
  status = (buf[9] - '0') * 100 + (buf[10] - '0') * 10 + (buf[11] - '0');
  if (status < 200) { if (res) *res = SP_CLASS_H1_INTERIM; return len; }
  for (i = 0; i + 3 < len; i++) {
    if (buf[i] == '\r' && buf[i + 1] == '\n' &&
        buf[i + 2] == '\r' && buf[i + 3] == '\n') {
      end = i + 2;              /* the blank line's own CRLF starts here */
      break;
    }
  }
  if (end == 0)
    return len;

  i = 0;
  while (i < end && !(buf[i] == '\r' && buf[i + 1] == '\n')) i++;
  i += 2;                       /* past the status line */
  while (i < end) {
    size_t eol = i, nlen = 0;

    while (eol < end && !(buf[eol] == '\r' && buf[eol + 1] == '\n')) eol++;
    eol += 2;
    while (i + nlen < eol && buf[i + nlen] != ':') nlen++;
    if ((nlen == sizeof(SP_CLASS_HDR_OBJ) - 1 &&
         !strncasecmp((const char *)buf + i, SP_CLASS_HDR_OBJ, nlen)) ||
        (nlen == sizeof(SP_CLASS_HDR_CLASS) - 1 &&
         !strncasecmp((const char *)buf + i, SP_CLASS_HDR_CLASS, nlen)) ||
        (nlen == sizeof(SP_CLASS_HDR_OBJ_REQ) - 1 &&
         !strncasecmp((const char *)buf + i, SP_CLASS_HDR_OBJ_REQ, nlen))) {
      memmove(buf + i, buf + eol, len - eol);
      len -= eol - i; end -= eol - i;
      continue;
    }
    i = eol;
  }
  if (sp_class_hdr_value_ok(objective))
    alen = snprintf(add, sizeof(add),
                    "X-Loxilb-Admission-Objective: %s\r\n"
                    "X-Loxilb-Admission-Class: %s\r\n",
                    objective, sp_class_name(priority_class));
  else
    alen = snprintf(add, sizeof(add), "X-Loxilb-Admission-Class: %s\r\n",
                    sp_class_name(priority_class));
  if (alen <= 0 || (size_t)alen >= sizeof(add))
    return len;
  if (sp_class_hdr_value_ok(requested)) {
    rlen = snprintf(add + alen, sizeof(add) - (size_t)alen,
                    "X-Loxilb-Admission-Objective-Requested: %s\r\n", requested);
    if (rlen <= 0 || (size_t)rlen >= sizeof(add) - (size_t)alen)
      return len;
  }
  n = (size_t)alen + (size_t)rlen;
  if (len + n > cap)
    return len;
  memmove(buf + end + n, buf + end, len - end);
  memcpy(buf + end, add, n);
  if (res) *res = SP_CLASS_H1_DONE;
  return len + n;
}

#endif /* __SOCKPROXY_OBJ_HINT_H__ */
