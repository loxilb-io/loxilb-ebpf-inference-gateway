/* SPDX-License-Identifier: (GPL-2.0) */
/*
 * sockproxy_radix_scan.c - routing key of a chat request for prefix routing.
 * See sockproxy_radix_scan.h for the contract.
 *
 * One structural pass over the body with a cursor. Each message object is
 * walked once to find and check its role and content; its content is then
 * added to the key stream: a string value is decoded from the positions the
 * walk recorded, a text-part array is walked a second time part by part.
 * Any other value is skimmed by skim_value(), which keeps its open
 * containers in a bit stack, so nothing here recurses on the input.
 */
#include <string.h>

#define XXH_INLINE_ALL
#include "xxhash.h"

#include "sockproxy_radix_scan.h"

#define NAME_BYTES 24               /* longest name compared is 20 bytes */

typedef struct {
  const uint8_t *p, *end;
} cur_t;

typedef struct {
  /* key stream: one block, then digests */
  uint8_t  blk[RADIX_SCAN_BLOCK];
  uint8_t  dig[RADIX_SCAN_KEY_CAP(RADIX_SCAN_CAP_MAX)];
  size_t   fill, stream, content, cap;
  uint64_t h;
  uint32_t n_blocks, n_messages;
  int      full;
  /* the last key name or role, unescaped */
  uint8_t  name[NAME_BYTES];
  size_t   name_len;
  int      name_over;
  /* work */
  uint64_t skim, decode, hash;
} scan_t;

static void wipe(void *p, size_t n)
{
  volatile uint8_t *v = p;
  while (n--)
    *v++ = 0;
}

/* ---- key stream ---- */

/* Append k bytes as one piece, or stop the stream if they do not fit. */
static int put(scan_t *s, const uint8_t *b, size_t k, int content)
{
  if (s->full)
    return 0;
  if (s->stream + k > s->cap) {
    s->full = 1;
    return 0;
  }
  for (size_t i = 0; i < k; i++) {
    s->blk[s->fill++] = b[i];
    if (s->fill == RADIX_SCAN_BLOCK) {
      uint8_t *d = s->dig + (size_t)s->n_blocks * RADIX_SCAN_DIGEST;
      s->h = XXH64(s->blk, RADIX_SCAN_BLOCK, s->h);
      for (int j = 0; j < RADIX_SCAN_DIGEST; j++)
        d[j] = (uint8_t)(s->h >> (8 * j));
      s->n_blocks++;
      s->fill = 0;
    }
  }
  s->stream += k;
  if (content)
    s->content += k;
  return 1;
}

/* Append n content bytes that are each a whole character (a run of ASCII
 * that decodes to itself), as n one-byte puts would: as many as fit under
 * the cap, then the stream stops. Copies up to each block boundary and
 * digests full blocks exactly as put() does. Returns the bytes stored. */
static size_t put_run(scan_t *s, const uint8_t *b, size_t n)
{
  size_t room, take, done = 0;

  if (s->full)
    return 0;
  room = s->cap - s->stream;
  take = n < room ? n : room;
  while (done < take) {
    size_t k = RADIX_SCAN_BLOCK - s->fill;
    if (k > take - done)
      k = take - done;
    memcpy(s->blk + s->fill, b + done, k);
    s->fill += k;
    done += k;
    if (s->fill == RADIX_SCAN_BLOCK) {
      uint8_t *d = s->dig + (size_t)s->n_blocks * RADIX_SCAN_DIGEST;
      s->h = XXH64(s->blk, RADIX_SCAN_BLOCK, s->h);
      for (int j = 0; j < RADIX_SCAN_DIGEST; j++)
        d[j] = (uint8_t)(s->h >> (8 * j));
      s->n_blocks++;
      s->fill = 0;
    }
  }
  s->stream += take;
  s->content += take;
  if (take < n)
    s->full = 1;
  return take;
}

static int hexval(uint8_t c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

/* p holds four hex digits (checked by the caller or by skim_string). */
static uint32_t hex4(const uint8_t *p)
{
  return ((uint32_t)hexval(p[0]) << 12) | ((uint32_t)hexval(p[1]) << 8) |
         ((uint32_t)hexval(p[2]) << 4) | (uint32_t)hexval(p[3]);
}

static size_t utf8_put(uint32_t cp, uint8_t *o)
{
  if (cp < 0x80) {
    o[0] = (uint8_t)cp;
    return 1;
  }
  if (cp < 0x800) {
    o[0] = (uint8_t)(0xC0 | (cp >> 6));
    o[1] = (uint8_t)(0x80 | (cp & 0x3F));
    return 2;
  }
  if (cp < 0x10000) {
    o[0] = (uint8_t)(0xE0 | (cp >> 12));
    o[1] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
    o[2] = (uint8_t)(0x80 | (cp & 0x3F));
    return 3;
  }
  o[0] = (uint8_t)(0xF0 | (cp >> 18));
  o[1] = (uint8_t)(0x80 | ((cp >> 12) & 0x3F));
  o[2] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
  o[3] = (uint8_t)(0x80 | (cp & 0x3F));
  return 4;
}

/* Length of the RFC 3629 sequence at p (p < e), or 0 if it is invalid or
 * cut by e. */
static size_t utf8_seq(const uint8_t *p, const uint8_t *e)
{
  uint8_t c = p[0], lo = 0x80, hi = 0xBF;
  size_t n;
  if (c < 0xC2)
    return 0;                       /* continuation byte or overlong lead */
  if (c < 0xE0) {
    n = 2;
  } else if (c < 0xF0) {
    n = 3;
    if (c == 0xE0) lo = 0xA0;       /* overlong */
    if (c == 0xED) hi = 0x9F;       /* surrogates */
  } else if (c < 0xF5) {
    n = 4;
    if (c == 0xF0) lo = 0x90;       /* overlong */
    if (c == 0xF4) hi = 0x8F;       /* above U+10FFFF */
  } else {
    return 0;
  }
  if ((size_t)(e - p) < n || p[1] < lo || p[1] > hi)
    return 0;
  for (size_t i = 2; i < n; i++)
    if ((p[i] & 0xC0) != 0x80)
      return 0;
  return n;
}

/* Decode the inside of a string already checked by skim_string ([p, e), e at
 * the closing quote) into the stream, until it ends or the stream stops. */
static radix_scan_rc_t decode_string(scan_t *s, const uint8_t *p, const uint8_t *e)
{
  while (p < e && !s->full) {
    uint8_t o[4];
    size_t k, used;
    if (*p == '\\') {
      uint32_t cp;
      used = 2;
      switch (p[1]) {
      case 'b': cp = '\b'; break;
      case 'f': cp = '\f'; break;
      case 'n': cp = '\n'; break;
      case 'r': cp = '\r'; break;
      case 't': cp = '\t'; break;
      case 'u':
        cp = hex4(p + 2);
        used = 6;
        if (cp >= 0xD800 && cp <= 0xDBFF) {
          uint32_t lo;
          if (e - p < 12 || p[6] != '\\' || p[7] != 'u')
            return RADIX_SKIP_INVALID_UTF8;
          lo = hex4(p + 8);
          if (lo < 0xDC00 || lo > 0xDFFF)
            return RADIX_SKIP_INVALID_UTF8;
          cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
          used = 12;
        } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
          return RADIX_SKIP_INVALID_UTF8;
        }
        break;
      default: cp = p[1]; break;     /* \" \\ \/ */
      }
      k = utf8_put(cp, o);
    } else if (*p < 0x80) {
      /* a run of bytes that decode to themselves, appended at once; the
       * work counter matches one character at a time, which counts the
       * character that no longer fits as well. The run is looked for only
       * as far as one byte past the room left under the cap: that byte, if
       * the run reaches it, is the one that no longer fits. */
      size_t room = s->cap - s->stream, got;
      const uint8_t *q = p + 1;
      const uint8_t *lim = (size_t)(e - p) > room + 1 ? p + room + 1 : e;
      while (q < lim && *q != '\\' && *q < 0x80)
        q++;
      got = put_run(s, p, (size_t)(q - p));
      s->decode += got + (got < (size_t)(q - p));
      p += got;
      continue;
    } else {
      k = used = utf8_seq(p, e);
      if (!k)
        return RADIX_SKIP_INVALID_UTF8;
      memcpy(o, p, k);
    }
    s->decode += used;
    put(s, o, k, 1);
    p += used;
  }
  return RADIX_SCAN_OK;
}

/* ---- structural walk ---- */

static void ws(cur_t *c)
{
  while (c->p < c->end &&
         (*c->p == ' ' || *c->p == '\t' || *c->p == '\n' || *c->p == '\r'))
    c->p++;
}

static void name_add(scan_t *s, uint8_t b)
{
  if (s->name_len < NAME_BYTES)
    s->name[s->name_len++] = b;
  else
    s->name_over = 1;
}

/* c->p at the opening quote. Checks the string and steps past it; *cs and
 * *ce get its inside. With s, the unescaped value goes to s->name (ASCII
 * escapes only; others make it match nothing). */
static radix_scan_rc_t skim_string(cur_t *c, scan_t *s,
                                   const uint8_t **cs, const uint8_t **ce)
{
  const uint8_t *p = c->p + 1;
  if (s) {
    s->name_len = 0;
    s->name_over = 0;
  }
  if (cs)
    *cs = p;
  for (;;) {
    uint8_t ch;
    if (p >= c->end)
      goto bad;
    ch = *p;
    if (ch == '"')
      break;
    if (ch < 0x20)
      goto bad;
    if (ch != '\\') {
      if (s)
        name_add(s, ch);
      p++;
      continue;
    }
    if (c->end - p < 2)
      goto bad;
    switch (p[1]) {
    case '"': case '\\': case '/': case 'b': case 'f': case 'n': case 'r': case 't':
      if (s)
        name_add(s, p[1] == 'b' ? '\b' : p[1] == 'f' ? '\f' : p[1] == 'n' ? '\n' :
                    p[1] == 'r' ? '\r' : p[1] == 't' ? '\t' : p[1]);
      p += 2;
      break;
    case 'u':
      if (c->end - p < 6 || hexval(p[2]) < 0 || hexval(p[3]) < 0 ||
          hexval(p[4]) < 0 || hexval(p[5]) < 0)
        goto bad;
      if (s) {
        uint32_t cp = hex4(p + 2);
        if (cp < 0x80)
          name_add(s, (uint8_t)cp);
        else
          s->name_over = 1;
      }
      p += 6;
      break;
    default:
      goto bad;
    }
  }
  if (ce)
    *ce = p;
  c->p = p + 1;
  return RADIX_SCAN_OK;
bad:
  c->p = p < c->end ? p : c->end;
  return RADIX_SKIP_MALFORMED;
}

static int is_name(const scan_t *s, const char *n)
{
  size_t l = strlen(n);
  return !s->name_over && s->name_len == l && !memcmp(s->name, n, l);
}

/* 0 true, 1 false, 2 null, -1 not a literal */
static int skim_literal(cur_t *c)
{
  static const char *const lit[3] = { "true", "false", "null" };
  for (int i = 0; i < 3; i++) {
    size_t l = strlen(lit[i]);
    if ((size_t)(c->end - c->p) >= l && !memcmp(c->p, lit[i], l)) {
      c->p += l;
      return i;
    }
  }
  return -1;
}

static int is_digit(const cur_t *c)
{
  return c->p < c->end && *c->p >= '0' && *c->p <= '9';
}

static radix_scan_rc_t skim_number(cur_t *c)
{
  if (c->p < c->end && *c->p == '-')
    c->p++;
  if (!is_digit(c))
    return RADIX_SKIP_MALFORMED;
  if (*c->p++ != '0')
    while (is_digit(c))
      c->p++;
  if (c->p < c->end && *c->p == '.') {
    c->p++;
    if (!is_digit(c))
      return RADIX_SKIP_MALFORMED;
    while (is_digit(c))
      c->p++;
  }
  if (c->p < c->end && (*c->p == 'e' || *c->p == 'E')) {
    c->p++;
    if (c->p < c->end && (*c->p == '+' || *c->p == '-'))
      c->p++;
    if (!is_digit(c))
      return RADIX_SKIP_MALFORMED;
    while (is_digit(c))
      c->p++;
  }
  return RADIX_SCAN_OK;
}

/* "key" : with c->p at the quote; leaves c->p at the value. */
static radix_scan_rc_t member_key(cur_t *c, scan_t *s)
{
  radix_scan_rc_t rc;
  if (c->p >= c->end || *c->p != '"')
    return RADIX_SKIP_MALFORMED;
  rc = skim_string(c, s, NULL, NULL);
  if (rc)
    return rc;
  ws(c);
  if (c->p >= c->end || *c->p != ':')
    return RADIX_SKIP_MALFORMED;
  c->p++;
  ws(c);
  return c->p < c->end ? RADIX_SCAN_OK : RADIX_SKIP_MALFORMED;
}

/* After a member or element: ',' (1), the closing byte (0) or an error. */
static int next_or_close(cur_t *c, uint8_t close, radix_scan_rc_t *rc)
{
  ws(c);
  if (c->p < c->end && *c->p == ',') {
    c->p++;
    ws(c);
    return 1;
  }
  if (c->p < c->end && *c->p == close) {
    c->p++;
    return 0;
  }
  *rc = RADIX_SKIP_MALFORMED;
  return -1;
}

/* Any JSON value at c->p (after whitespace), inside `depth` open containers. */
static radix_scan_rc_t skim_value(cur_t *c, unsigned depth)
{
  uint64_t is_obj[(RADIX_SCAN_DEPTH_MAX + 63) / 64] = { 0 };
  unsigned d = 0;                         /* containers opened here */
  radix_scan_rc_t rc;

  for (;;) {
    uint8_t ch;
    ws(c);
    if (c->p >= c->end)
      return RADIX_SKIP_MALFORMED;
    ch = *c->p;
    if (ch == '{' || ch == '[') {
      if (depth + d + 1 > RADIX_SCAN_DEPTH_MAX)
        return RADIX_SKIP_TOO_DEEP;
      if (ch == '{')
        is_obj[d / 64] |= 1ull << (d % 64);
      else
        is_obj[d / 64] &= ~(1ull << (d % 64));
      d++;
      c->p++;
      ws(c);
      if (c->p < c->end && *c->p == (ch == '{' ? '}' : ']')) {
        c->p++;
        d--;
      } else if (ch == '{') {
        if ((rc = member_key(c, NULL)))
          return rc;
        continue;
      } else {
        continue;
      }
    } else if (ch == '"') {
      if ((rc = skim_string(c, NULL, NULL, NULL)))
        return rc;
    } else if (ch == 't' || ch == 'f' || ch == 'n') {
      if (skim_literal(c) < 0)
        return RADIX_SKIP_MALFORMED;
    } else if (ch == '-' || (ch >= '0' && ch <= '9')) {
      if ((rc = skim_number(c)))
        return rc;
    } else {
      return RADIX_SKIP_MALFORMED;
    }
    /* a value ended: close containers until one continues */
    for (;;) {
      int obj, n;
      if (d == 0)
        return RADIX_SCAN_OK;
      obj = (int)((is_obj[(d - 1) / 64] >> ((d - 1) % 64)) & 1);
      rc = RADIX_SCAN_OK;
      n = next_or_close(c, obj ? '}' : ']', &rc);
      if (n < 0)
        return rc;
      if (n == 0) {
        d--;
        continue;
      }
      if (obj && (rc = member_key(c, NULL)))
        return rc;
      break;
    }
  }
}

static int value_start(uint8_t ch)
{
  return ch == '{' || ch == '[' || ch == '"' || ch == 't' || ch == 'f' ||
         ch == 'n' || ch == '-' || (ch >= '0' && ch <= '9');
}

/* ---- chat structure ---- */

enum { C_ABSENT, C_NULL, C_STRING, C_ARRAY };

/* Second walk of a content array checked by the first one: each part must be
 * {"type":"text","text":"..."} (other members skimmed); texts go to the
 * stream in order. */
static radix_scan_rc_t parts(scan_t *s, const uint8_t *arr, const uint8_t *end)
{
  cur_t q = { arr + 1, end };
  radix_scan_rc_t rc = RADIX_SCAN_OK;

  ws(&q);
  if (q.p < q.end && *q.p == ']') {
    q.p++;
    goto out;
  }
  for (;;) {
    int have_type = 0, type_str = 0, type_text = 0, have_text = 0, text_str = 0, n;
    const uint8_t *ts = NULL, *te = NULL;
    ws(&q);
    if (q.p >= q.end || *q.p != '{') {
      rc = q.p < q.end ? RADIX_SKIP_BAD_MESSAGE : RADIX_SKIP_MALFORMED;
      goto out;
    }
    q.p++;
    ws(&q);
    if (q.p < q.end && *q.p == '}') {
      q.p++;
    } else {
      do {
        if ((rc = member_key(&q, s)))
          goto out;
        if (is_name(s, "type")) {
          if (have_type++) {
            rc = RADIX_SKIP_DUPLICATE_KEY;
            goto out;
          }
          if (*q.p == '"') {
            type_str = 1;
            rc = skim_string(&q, s, NULL, NULL);
            type_text = is_name(s, "text");
          } else {
            rc = skim_value(&q, 5);
          }
        } else if (is_name(s, "text")) {
          if (have_text++) {
            rc = RADIX_SKIP_DUPLICATE_KEY;
            goto out;
          }
          if (*q.p == '"') {
            text_str = 1;
            rc = skim_string(&q, NULL, &ts, &te);
          } else {
            rc = skim_value(&q, 5);
          }
        } else {
          rc = skim_value(&q, 5);
        }
        if (rc)
          goto out;
      } while ((n = next_or_close(&q, '}', &rc)) == 1);
      if (n < 0)
        goto out;
    }
    if (!have_type || !type_str) {
      rc = RADIX_SKIP_BAD_MESSAGE;
      goto out;
    }
    if (!type_text) {
      rc = RADIX_SKIP_NON_TEXT_PART;
      goto out;
    }
    if (!have_text || !text_str) {
      rc = RADIX_SKIP_BAD_MESSAGE;
      goto out;
    }
    if ((rc = decode_string(s, ts, te)))
      goto out;
    n = next_or_close(&q, ']', &rc);
    if (n < 0)
      goto out;
    if (n == 0)
      break;
  }
out:
  s->skim += (uint64_t)(q.p - arr);
  return rc;
}

static uint8_t role_byte(const scan_t *s)
{
  if (is_name(s, "system")) return 's';
  if (is_name(s, "developer")) return 'd';
  if (is_name(s, "user")) return 'u';
  if (is_name(s, "assistant")) return 'a';
  if (is_name(s, "tool")) return 't';
  return 0;
}

/* One message object at c->p ('{'): check it, then add it to the stream. */
static radix_scan_rc_t message(scan_t *s, cur_t *c)
{
  int have_role = 0, have_content = 0, kind = C_ABSENT, n;
  uint8_t role = 0;
  const uint8_t *cs = NULL, *ce = NULL;
  radix_scan_rc_t rc = RADIX_SCAN_OK;

  c->p++;
  ws(c);
  if (c->p < c->end && *c->p == '}') {
    c->p++;
  } else {
    do {
      if ((rc = member_key(c, s)))
        return rc;
      if (is_name(s, "role")) {
        if (have_role++)
          return RADIX_SKIP_DUPLICATE_KEY;
        if (*c->p != '"')
          return RADIX_SKIP_BAD_MESSAGE;
        if ((rc = skim_string(c, s, NULL, NULL)))
          return rc;
        if (!(role = role_byte(s)))
          return RADIX_SKIP_UNKNOWN_ROLE;
      } else if (is_name(s, "content")) {
        if (have_content++)
          return RADIX_SKIP_DUPLICATE_KEY;
        if (*c->p == '"') {
          kind = C_STRING;
          rc = skim_string(c, NULL, &cs, &ce);
        } else if (*c->p == '[') {
          kind = C_ARRAY;
          cs = c->p;
          rc = skim_value(c, 3);
        } else if (*c->p == 'n') {
          kind = C_NULL;
          if (skim_literal(c) != 2)
            return RADIX_SKIP_MALFORMED;
        } else {
          return RADIX_SKIP_BAD_MESSAGE;
        }
        if (rc)
          return rc;
      } else if ((rc = skim_value(c, 3))) {
        return rc;
      }
    } while ((n = next_or_close(c, '}', &rc)) == 1);
    if (n < 0)
      return rc;
  }
  if (!have_role)
    return RADIX_SKIP_BAD_MESSAGE;

  {
    uint8_t st[2] = { RADIX_MARK_MSG, role }, en = RADIX_MARK_END;
    if (put(s, st, 2, 0))
      s->n_messages++;
    if (kind == C_STRING)
      rc = decode_string(s, cs, ce);
    else if (kind == C_ARRAY)
      rc = parts(s, cs, c->p);
    if (rc)
      return rc;
    put(s, &en, 1, 0);
  }
  return RADIX_SCAN_OK;
}

static radix_scan_rc_t messages(scan_t *s, cur_t *c)
{
  radix_scan_rc_t rc = RADIX_SCAN_OK;
  int n;
  if (*c->p != '[')
    return RADIX_SKIP_NO_MESSAGES;
  c->p++;
  ws(c);
  if (c->p >= c->end)
    return RADIX_SKIP_MALFORMED;
  if (*c->p == ']')
    return RADIX_SKIP_NO_MESSAGES;
  do {
    if (c->p >= c->end)
      return RADIX_SKIP_MALFORMED;
    if (*c->p != '{')
      return value_start(*c->p) ? RADIX_SKIP_BAD_MESSAGE : RADIX_SKIP_MALFORMED;
    if ((rc = message(s, c)))
      return rc;
  } while ((n = next_or_close(c, ']', &rc)) == 1);
  return n < 0 ? rc : RADIX_SCAN_OK;
}

/* A top-level value hashed raw as sent; null is absent (has stays 0). */
static radix_scan_rc_t hashed(scan_t *s, cur_t *c, uint8_t *has, uint64_t *h)
{
  const uint8_t *v = c->p;
  radix_scan_rc_t rc;
  if (*c->p == 'n')
    return skim_literal(c) == 2 ? RADIX_SCAN_OK : RADIX_SKIP_MALFORMED;
  if ((rc = skim_value(c, 1)))
    return rc;
  *has = 1;
  *h = XXH64(v, (size_t)(c->p - v), 0);
  s->hash += (uint64_t)(c->p - v);
  return RADIX_SCAN_OK;
}

static radix_scan_rc_t top(scan_t *s, cur_t *c, radix_scan_res_t *res)
{
  int have_msgs = 0, have_tmpl = 0, have_tools = 0, have_kwargs = 0, n;
  radix_scan_rc_t rc = RADIX_SCAN_OK;

  ws(c);
  if (c->p >= c->end || *c->p != '{')
    return RADIX_SKIP_MALFORMED;
  c->p++;
  ws(c);
  if (c->p < c->end && *c->p == '}') {
    c->p++;
  } else {
    do {
      if ((rc = member_key(c, s)))
        return rc;
      if (is_name(s, "messages")) {
        if (have_msgs++)
          return RADIX_SKIP_DUPLICATE_KEY;
        rc = messages(s, c);
      } else if (is_name(s, "tools")) {
        if (have_tools++)
          return RADIX_SKIP_DUPLICATE_KEY;
        rc = hashed(s, c, &res->has_tools, &res->tools_hash);
      } else if (is_name(s, "chat_template_kwargs")) {
        if (have_kwargs++)
          return RADIX_SKIP_DUPLICATE_KEY;
        rc = hashed(s, c, &res->has_tmpl_kwargs, &res->tmpl_kwargs_hash);
      } else if (is_name(s, "chat_template")) {
        if (have_tmpl++)
          return RADIX_SKIP_DUPLICATE_KEY;
        if (*c->p != 'n')
          return RADIX_SKIP_TEMPLATE_OVERRIDE;
        if (skim_literal(c) != 2)
          return RADIX_SKIP_MALFORMED;
      } else {
        rc = skim_value(c, 1);
      }
      if (rc)
        return rc;
    } while ((n = next_or_close(c, '}', &rc)) == 1);
    if (n < 0)
      return rc;
  }
  ws(c);
  if (c->p != c->end)
    return RADIX_SKIP_MALFORMED;
  if (!have_msgs)
    return RADIX_SKIP_NO_MESSAGES;
  if (!s->content)
    return RADIX_SKIP_EMPTY;
  if (s->stream < RADIX_SCAN_BLOCK)
    return RADIX_SKIP_SHORT;
  return RADIX_SCAN_OK;
}

radix_scan_rc_t radix_scan_chat(const char *body, size_t body_len,
                                size_t max_body, size_t cap,
                                uint8_t *key, size_t key_cap,
                                radix_scan_res_t *res)
{
  scan_t s;
  cur_t c;
  radix_scan_rc_t rc;

  if (!res)
    return RADIX_SKIP_BAD_ARG;
  memset(res, 0, sizeof(*res));
  if (!body || !key || !cap || cap > RADIX_SCAN_CAP_MAX ||
      key_cap < RADIX_SCAN_KEY_CAP(cap))
    return RADIX_SKIP_BAD_ARG;
  if (body_len > max_body)
    return RADIX_SKIP_BODY_TOO_LARGE;

  memset(&s, 0, sizeof(s));
  s.cap = cap;
  c.p = (const uint8_t *)body;
  c.end = c.p + body_len;
  rc = top(&s, &c, res);

  s.skim += (uint64_t)(c.p - (const uint8_t *)body);
  res->stream_bytes = s.stream;
  res->n_blocks = s.n_blocks;
  res->n_messages = s.n_messages;
  res->truncated = (uint8_t)s.full;
  res->skim_bytes = s.skim;
  res->decode_bytes = s.decode;
  res->hash_bytes = s.hash;
  if (rc == RADIX_SCAN_OK) {
    res->key_len = (size_t)s.n_blocks * RADIX_SCAN_DIGEST;
    memcpy(key, s.dig, res->key_len);
  }
  wipe(&s, sizeof(s));
  return rc;
}

size_t radix_scan_matched_bytes(size_t matched_key_len)
{
  return matched_key_len / RADIX_SCAN_DIGEST * RADIX_SCAN_BLOCK;
}

const char *radix_scan_rc_name(radix_scan_rc_t rc)
{
  static const char *const names[RADIX_SCAN__COUNT] = {
    [RADIX_SCAN_OK]                = "ok",
    [RADIX_SKIP_BODY_TOO_LARGE]    = "body_too_large",
    [RADIX_SKIP_MALFORMED]         = "malformed",
    [RADIX_SKIP_TOO_DEEP]          = "too_deep",
    [RADIX_SKIP_NO_MESSAGES]       = "no_messages",
    [RADIX_SKIP_DUPLICATE_KEY]     = "duplicate_key",
    [RADIX_SKIP_BAD_MESSAGE]       = "bad_message",
    [RADIX_SKIP_UNKNOWN_ROLE]      = "unknown_role",
    [RADIX_SKIP_NON_TEXT_PART]     = "non_text_part",
    [RADIX_SKIP_TEMPLATE_OVERRIDE] = "template_override",
    [RADIX_SKIP_INVALID_UTF8]      = "invalid_utf8",
    [RADIX_SKIP_EMPTY]             = "empty",
    [RADIX_SKIP_SHORT]             = "short",
    [RADIX_SKIP_BAD_ARG]           = "bad_arg",
  };
  if ((unsigned)rc < RADIX_SCAN__COUNT && names[rc])
    return names[rc];
  return "unknown";
}
