/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __SOCKPROXY_STREAM_FALLBACK_H__
#define __SOCKPROXY_STREAM_FALLBACK_H__

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>

/* The routing-only prefix is intentionally much smaller than the JSON body
 * inspection cap.  Oversize bodies are streamed; only enough bytes to obtain
 * the direct top-level model may be retained before the backend is selected. */
#define SP_JSON_ROUTE_PREFIX_MAX (64U * 1024U)
#define SP_LOCAL_SEND_RETRY_MAX 8U

typedef ssize_t (*sp_send_once_fn)(void *ctx, const uint8_t *buf, size_t len,
                                   int *retryable);

static inline const uint8_t *
sp_http_header_end(const uint8_t *buf, size_t len)
{
  size_t i;

  if (!buf || len < 4)
    return NULL;
  for (i = 0; i + 4 <= len; i++) {
    if (buf[i] == '\r' && buf[i + 1] == '\n' &&
        buf[i + 2] == '\r' && buf[i + 3] == '\n')
      return buf + i;
  }
  return NULL;
}

/* Complete a small local HTTP response without assuming one nonblocking write
 * consumes it. Positive writes advance monotonically; retryable stalls are
 * bounded independently so a peer that never becomes writable cannot pin the
 * proxy worker forever. */
static inline int
sp_send_all_bounded(sp_send_once_fn send_once, void *ctx,
                    const uint8_t *buf, size_t len, unsigned retry_max)
{
  size_t off = 0;
  unsigned retries = 0;

  if (!send_once || (!buf && len != 0))
    return -1;
  while (off < len) {
    int retryable = 0;
    ssize_t n = send_once(ctx, buf + off, len - off, &retryable);

    if (n > 0) {
      if ((size_t)n > len - off)
        return -1;
      off += (size_t)n;
      continue;
    }
    if (!retryable || retries++ >= retry_max)
      return -1;
  }
  return 0;
}

/* Locate the HTTP body and expose at most the routing prefix. `at_limit` is
 * based on body bytes only: large headers neither consume nor extend the cap. */
static inline int
sp_json_route_body_prefix(const uint8_t *buf, size_t len,
                          const uint8_t **body, size_t *prefix_len,
                          int *at_limit)
{
  const uint8_t *hdr_end;
  size_t body_len;

  if (!buf || !body || !prefix_len || !at_limit)
    return -1;
  hdr_end = sp_http_header_end(buf, len);
  if (!hdr_end)
    return 1;
  *body = hdr_end + 4;
  body_len = len - (size_t)(*body - buf);
  *prefix_len = body_len < SP_JSON_ROUTE_PREFIX_MAX ?
      body_len : SP_JSON_ROUTE_PREFIX_MAX;
  *at_limit = body_len >= SP_JSON_ROUTE_PREFIX_MAX;
  return 0;
}

/* Once headers are present, never accumulate more than the bounded body
 * routing prefix while endpoint selection is pending. */
static inline size_t
sp_json_route_read_want(const uint8_t *buf, size_t len, size_t want)
{
  const uint8_t *hdr_end;
  size_t body_off;
  size_t max_total;

  if (!buf)
    return want;
  hdr_end = sp_http_header_end(buf, len);
  if (!hdr_end)
    return want;
  body_off = (size_t)((hdr_end + 4) - buf);
  if (body_off > SIZE_MAX - SP_JSON_ROUTE_PREFIX_MAX)
    return 0;
  max_total = body_off + SP_JSON_ROUTE_PREFIX_MAX;
  if (len >= max_total)
    return 0;
  return want < max_total - len ? want : max_total - len;
}

static inline int
sp_http_expect_100_continue(const uint8_t *buf, size_t len)
{
  const uint8_t *p;
  const uint8_t *end;

  if (!buf || len < 4)
    return 0;
  p = buf;
  end = buf + len;

  while (p + 1 < end) {
    const uint8_t *line_end = NULL;
    const uint8_t *colon;
    const uint8_t *value;
    const uint8_t *value_end;

    for (const uint8_t *q = p; q + 1 < end; q++) {
      if (q[0] == '\r' && q[1] == '\n') {
        line_end = q;
        break;
      }
    }
    if (!line_end || line_end == p)
      break;

    colon = memchr(p, ':', (size_t)(line_end - p));
    if (colon && (size_t)(colon - p) == 6 &&
        strncasecmp((const char *)p, "Expect", 6) == 0) {
      value = colon + 1;
      while (value < line_end && (*value == ' ' || *value == '\t'))
        value++;
      value_end = line_end;
      while (value_end > value &&
             (value_end[-1] == ' ' || value_end[-1] == '\t'))
        value_end--;
      if ((size_t)(value_end - value) == 12 &&
          strncasecmp((const char *)value, "100-continue", 12) == 0)
        return 1;
    }
    p = line_end + 2;
  }
  return 0;
}

static inline int
sp_http_should_send_100_continue(const uint8_t *buf, size_t len,
                                 int already_sent)
{
  return !already_sent && sp_http_expect_100_continue(buf, len);
}

/* Remove every Expect: 100-continue line before the locally-acknowledged
 * request is forwarded.  This prevents the selected backend from emitting a
 * second informational response.  Body bytes are shifted byte-for-byte. */
static inline int
sp_http_strip_expect_100_continue(uint8_t *buf, size_t *len)
{
  uint8_t *p;
  uint8_t *end;
  int removed = 0;

  if (!buf || !len)
    return 0;

  p = buf;
  end = buf + *len;
  while (p + 1 < end) {
    uint8_t *line_end = NULL;
    uint8_t *colon;
    uint8_t *value;
    uint8_t *value_end;

    for (uint8_t *q = p; q + 1 < end; q++) {
      if (q[0] == '\r' && q[1] == '\n') {
        line_end = q;
        break;
      }
    }
    if (!line_end || line_end == p)
      break;

    colon = memchr(p, ':', (size_t)(line_end - p));
    if (colon && (size_t)(colon - p) == 6 &&
        strncasecmp((const char *)p, "Expect", 6) == 0) {
      value = colon + 1;
      while (value < line_end && (*value == ' ' || *value == '\t'))
        value++;
      value_end = line_end;
      while (value_end > value &&
             (value_end[-1] == ' ' || value_end[-1] == '\t'))
        value_end--;
      if ((size_t)(value_end - value) == 12 &&
          strncasecmp((const char *)value, "100-continue", 12) == 0) {
        size_t line_len = (size_t)((line_end + 2) - p);
        memmove(p, line_end + 2, (size_t)(end - (line_end + 2)));
        *len -= line_len;
        end -= line_len;
        removed++;
        continue;
      }
    }
    p = line_end + 2;
  }
  return removed;
}

static inline size_t
sp_stream_body_remaining(size_t content_length, size_t buffered_body)
{
  return buffered_body < content_length ? content_length - buffered_body : 0;
}

/* Once an inspected body model is complete it is authoritative over X-Model.
 * This mirrors the API-key gate's anti-spoof contract on the stream path. */
static inline int
sp_store_authoritative_body_model(char *body_model, size_t body_model_cap,
                                  char *header_model,
                                  const char *parsed_body_model)
{
  size_t n;

  if (!body_model || body_model_cap == 0 || !header_model ||
      !parsed_body_model || parsed_body_model[0] == '\0')
    return -1;
  n = strlen(parsed_body_model);
  if (n >= body_model_cap)
    n = body_model_cap - 1;
  memcpy(body_model, parsed_body_model, n);
  body_model[n] = '\0';
  header_model[0] = '\0';
  return 0;
}

#endif /* __SOCKPROXY_STREAM_FALLBACK_H__ */
