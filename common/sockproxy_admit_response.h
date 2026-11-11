/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef SOCKPROXY_ADMIT_RESPONSE_H
#define SOCKPROXY_ADMIT_RESPONSE_H

#include <stddef.h>
#include <stdio.h>

#include "sockproxy_refusal_mark.h"

/* Frame a terminal policy denial independently of transport EOF. The body and
 * Retry-After shapes retain their existing contract; callers supply the same
 * internal error labels/messages used by admission. Never send truncated JSON
 * or a Content-Length calculated from snprintf's would-have-written length.
 * `stage` is the wire name of the stage that refused and `request_id` the
 * request's ID: both go out as the refusal mark (sockproxy_refusal_mark.h),
 * each only when there is one to send. */
static inline int
sp_h1_format_admit_deny(char *out, size_t cap, int status, int retry_after,
                        int retry_body, const char *code, const char *msg,
                        const char *stage, const char *request_id)
{
  char body[512];
  char retry[64] = "";
  char mark[SP_REFUSAL_MARK_MAX + 1];
  const char *status_line =
    status == 400 ? "400 Bad Request" :
    status == 401 ? "401 Unauthorized" :
    status == 403 ? "403 Forbidden" :
    status == 413 ? "413 Content Too Large" :
    status == 429 ? "429 Too Many Requests" :
                    "503 Service Unavailable";
  int blen, n;

  if (!out || cap == 0 || !code || (!retry_body && !msg))
    return -1;
  out[0] = '\0';
  if (retry_body)
    blen = snprintf(body, sizeof(body),
                    "{\"error\":\"%s\",\"retry_after\":%d}\r\n",
                    code, retry_after);
  else
    blen = snprintf(body, sizeof(body),
                    "{\"error\":\"%s\",\"message\":\"%s\"}\r\n",
                    code, msg);
  if (blen < 0 || blen >= (int)sizeof(body))
    return -1;

  if (retry_body || retry_after > 0) {
    n = snprintf(retry, sizeof(retry), "Retry-After: %d\r\n", retry_after);
    if (n < 0 || n >= (int)sizeof(retry))
      return -1;
  }
  if (sp_refusal_mark_h1(mark, sizeof(mark), stage, request_id) < 0)
    return -1;
  n = snprintf(out, cap,
               "HTTP/1.1 %s\r\n"
               "Content-Type: application/json\r\n"
               "Content-Length: %d\r\n"
               "%s%s"
               "Connection: close\r\n\r\n%s",
               status_line, blen, retry, mark, body);
  if (n < 0 || (size_t)n >= cap) {
    out[0] = '\0';
    return -1;
  }
  return n;
}

#endif
