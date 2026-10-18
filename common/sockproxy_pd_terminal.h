/* P/D failure framing. An idle transport is never evidence of success. */
#ifndef SOCKPROXY_PD_TERMINAL_H
#define SOCKPROXY_PD_TERMINAL_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
/* Only a complete, bounded last SSE data event can prove generation ended.
 * An oversized/malformed event or a later partial data event clears the proof. */
#define SP_PD_EVENT_MAX 4096u
typedef struct {
  char line[SP_PD_EVENT_MAX], event[SP_PD_EVENT_MAX];
  size_t line_len, event_len;
  uint8_t line_overflow, event_bad, has_data, finished;
} sp_pd_finish_t;
void sp_pd_finish_feed(sp_pd_finish_t *state, const char *data, size_t len);
int sp_pd_idle_policy(int deadline_due, int finished);

#define SP_PD_TERMINAL_PAD_MAX 65536u
/* Only client-facing decode bytes feed this state. Retain the position in the
 * raw HTTP chunk stream so an EOF inside a chunk cannot turn an SSE error into
 * an invalid chunk-size line. Never infer framing from the internal prefill. */
typedef struct {
  uint64_t size, left;
  unsigned header_tail;
  uint8_t headers, chunked, fixed, state, digits, bad, extquote, extescape, extlast;
} sp_pd_wire_t;
enum {
  SP_PD_SIZE,
  SP_PD_EXT,
  SP_PD_SIZE_LF,
  SP_PD_DATA,
  SP_PD_DATA_CR,
  SP_PD_DATA_LF,
  SP_PD_END
};
static inline void sp_pd_wire_feed(sp_pd_wire_t *s, const char *p, size_t n)
{
  for (size_t i = 0; i < n && !s->bad; i++) {
    unsigned char c = (unsigned char)p[i];
    if (!s->headers) {
      s->header_tail = (s->header_tail << 8) | c;
      if (s->header_tail == 0x0d0a0d0aU)
        s->headers = 1;
      continue;
    }
    if (!s->chunked)
      continue;
    switch (s->state) {
    case SP_PD_SIZE: {
      unsigned d = c >= '0' && c <= '9'   ? c - '0'
                   : c >= 'a' && c <= 'f' ? c - 'a' + 10
                   : c >= 'A' && c <= 'F' ? c - 'A' + 10
                                          : 16;
      if (d < 16) {
        if (s->size > (UINT64_MAX - d) / 16) {
          s->bad = 1;
          break;
        }
        s->size = s->size * 16 + d;
        s->digits = 1;
      } else if (s->digits && c == ';') {
        s->state = SP_PD_EXT;
        s->extlast = c;
      } else if (s->digits && c == '\r')
        s->state = SP_PD_SIZE_LF;
      else
        s->bad = 1;
      break;
    }
    case SP_PD_EXT:
      if (c == '\r')
        s->state = SP_PD_SIZE_LF;
      else if (c == '\n')
        s->bad = 1;
      else {
        if (s->extescape)
          s->extescape = 0;
        else if (s->extquote && c == '\\')
          s->extescape = 1;
        else if (c == '"')
          s->extquote = !s->extquote;
        s->extlast = c;
      }
      break;
    case SP_PD_SIZE_LF:
      if (c != '\n') {
        s->bad = 1;
        break;
      }
      s->left = s->size;
      s->state = s->left ? SP_PD_DATA : SP_PD_END;
      break;
    case SP_PD_DATA:
      if (--s->left == 0)
        s->state = SP_PD_DATA_CR;
      break;
    case SP_PD_DATA_CR:
      if (c == '\r')
        s->state = SP_PD_DATA_LF;
      else
        s->bad = 1;
      break;
    case SP_PD_DATA_LF:
      if (c != '\n')
        s->bad = 1;
      else {
        s->state = SP_PD_SIZE;
        s->size = 0;
        s->digits = 0;
      }
      break;
    case SP_PD_END:
      break;
    }
  }
}
/* Complete at most one interrupted chunk with blank lines, then emit a new
 * error event and the HTTP terminator. No success [DONE], token replay, or
 * unbounded padding. Returns zero if the already-sent framing cannot safely be
 * extended (fixed length, ended, malformed or oversized interrupted chunk). */
static inline size_t sp_pd_terminal_payload(const sp_pd_wire_t *s, const char *event,
                                            size_t n, char *out, size_t cap)
{
  size_t off = 0;
  uint64_t pad = 0;
  if (!n || !s->headers || s->bad || s->fixed)
    return 0;
  if (!s->chunked) {
    if ((size_t)n > cap)
      return 0;
    memcpy(out, event, n);
    return (size_t)n;
  }
  switch (s->state) {
  case SP_PD_SIZE:
    if (!s->digits)
      break;
    if (!s->size)
      return 0;
    if (cap < 2)
      return 0;
    memcpy(out, "\r\n", 2);
    off = 2;
    pad = s->size;
    break;
  case SP_PD_EXT:
    if (!s->size || cap < 8)
      return 0;
    if (s->extescape)
      out[off++] = 'x';
    if (s->extquote)
      out[off++] = '"';
    else if (s->extlast == ';' || s->extlast == '=')
      out[off++] = 'x';
    memcpy(out + off, "\r\n", 2);
    off += 2;
    pad = s->size;
    break;
  case SP_PD_SIZE_LF:
    if (!s->size || cap < 1)
      return 0;
    out[off++] = '\n';
    pad = s->size;
    break;
  case SP_PD_DATA:
    pad = s->left;
    break;
  case SP_PD_DATA_CR:
    if (cap < 2)
      return 0;
    memcpy(out, "\r\n", 2);
    off = 2;
    break;
  case SP_PD_DATA_LF:
    if (cap < 1)
      return 0;
    out[off++] = '\n';
    break;
  default:
    return 0;
  }
  if (pad > SP_PD_TERMINAL_PAD_MAX || pad + off + 2 > cap)
    return 0;
  if (pad) {
    memset(out + off, '\n', (size_t)pad);
    off += (size_t)pad;
    memcpy(out + off, "\r\n", 2);
    off += 2;
  }
  int k = snprintf(out + off, cap - off, "%zx\r\n%s\r\n0\r\n\r\n", (size_t)n, event);
  return k > 0 && (size_t)k < cap - off ? off + (size_t)k : 0;
}
static inline size_t sp_pd_terminal_format(const sp_pd_wire_t *s, const char *code,
                                           char *out, size_t cap)
{
  char event[160];
  int n = snprintf(event, sizeof(event), "\n\ndata: {\"error\":\"%s\"}\n\n", code);
  if (n <= 0 || (size_t)n >= sizeof(event))
    return 0;
  return sp_pd_terminal_payload(s, event, (size_t)n, out, cap);
}

static inline size_t sp_pd_terminal_done_format(const sp_pd_wire_t *s, char *out,
                                                size_t cap)
{
  static const char done[] = "\n\ndata: [DONE]\n\n";
  return sp_pd_terminal_payload(s, done, sizeof(done) - 1, out, cap);
}
#endif
