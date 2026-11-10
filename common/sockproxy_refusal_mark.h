/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * The two header lines an answer the gateway wrote itself can carry:
 *
 *   X-Loxilb-Refusal-Stage: <stage>   which stage of the gateway refused
 *   X-Request-Id: <request_id>        the ID of the request being answered
 *
 * They are independent of each other.
 *
 * A response that carries X-Loxilb-Refusal-Stage was written by the gateway
 * before any byte of the request reached a backend. The value is the audit
 * wire name of the stage (aiDenyStage, pkg/loxinet/ai_gateway_audit.go), or
 * "queue" for a request that ended while it waited for capacity. Outage
 * answers and anything a backend sent carry no stage; a backend's own header
 * of this family is removed from every relayed response head.
 *
 * X-Request-Id on an answer the gateway wrote is the ID of THAT request and
 * of no other: the connection's live field (SP_REFUSAL_LIVE_RID), or the
 * HTTP/2 stream's own. It is on a refusal and on an outage alike, and left
 * out when the request has no ID of its own at that moment (refused before
 * one was read or minted, or answered after it was forwarded and the field
 * cleared for the next request). It is never proxy_request_id(): that is
 * the audit key, which on a keep-alive connection falls back to a snapshot
 * that can still hold the previous request's ID.
 *
 * Pure helpers, kept in a header so the unit test runs the code the senders
 * run. No allocation, no logging.
 */
#ifndef __SOCKPROXY_REFUSAL_MARK_H__
#define __SOCKPROXY_REFUSAL_MARK_H__

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#define SP_REFUSAL_STAGE_HDR    "X-Loxilb-Refusal-Stage"
#define SP_REFUSAL_STAGE_HDR_H2 "x-loxilb-refusal-stage"
#define SP_REFUSAL_RID_HDR      "X-Request-Id"
#define SP_REFUSAL_RID_HDR_H2   "x-request-id"
/* The family a backend may not send to a client, whatever its members. */
#define SP_REFUSAL_HDR_PREFIX   "X-Loxilb-Refusal-"

/* The request ID an answer on an HTTP/1.1 connection may echo: the live
 * field of its proxy_fd_ent_t, empty when the request has none of its own.
 * A macro, so this header keeps depending on nothing. */
#define SP_REFUSAL_LIVE_RID(pfe) ((pfe)->vllm_request_id)

/* A request that ended in the capacity queue (deadline, drain, eviction,
 * TTL). Its audit record stays at the capacity stage. */
#define SP_REFUSAL_STAGE_QUEUE  "queue"

/* A request ID is at most 255 bytes (vllm_request_id[256]); it is echoed
 * whole or not at all. The longest stage name is 9 bytes. */
#define SP_REFUSAL_RID_MAX   255
#define SP_REFUSAL_STAGE_MAX 16
/* The most the two lines add to a response head. A buffer that held a
 * refusal before holds it marked when it grows by this much. */
#define SP_REFUSAL_MARK_MAX                                                \
  (sizeof(SP_REFUSAL_STAGE_HDR ": \r\n") - 1 + SP_REFUSAL_STAGE_MAX +      \
   sizeof(SP_REFUSAL_RID_HDR ": \r\n") - 1 + SP_REFUSAL_RID_MAX)

/* The wire name of an ai_gw_admit_stage_t (sockproxy_ai_admit.h), the same
 * string the stage has in the audit record. NULL for NONE and for a value
 * this table does not know: such an answer goes out unmarked, never with an
 * invented stage. The numbers are the enum's, which never move once
 * recorded; where the enum is in scope the assertion below holds them. */
static inline const char *
sp_refusal_stage_name(int stage)
{
  switch (stage) {
  case 1: return "auth";
  case 2: return "conflict";
  case 3: return "ratelimit";
  case 4: return "reserve";
  case 5: return "capacity";
  case 6: return "objective";
  case 7: return "route";
  case 8: return "framing";
  case 9: return "security";
  default: return NULL;
  }
}

#ifdef __SOCKPROXY_AI_ADMIT_H__
_Static_assert(AI_GW_STAGE_NONE == 0 && AI_GW_STAGE_AUTH == 1 &&
               AI_GW_STAGE_CONFLICT == 2 && AI_GW_STAGE_RATELIMIT == 3 &&
               AI_GW_STAGE_RESERVE == 4 && AI_GW_STAGE_CAPACITY == 5 &&
               AI_GW_STAGE_OBJECTIVE == 6 && AI_GW_STAGE_ROUTE == 7 &&
               AI_GW_STAGE_FRAMING == 8 && AI_GW_STAGE_SECURITY == 9,
               "sp_refusal_stage_name reads these numbers");
#endif

/* Whether a request ID can be echoed as one header value: not empty, at
 * most SP_REFUSAL_RID_MAX bytes, no control byte (so no line break), and no
 * blank at either end (HTTP/2 refuses such a field). An ID that fails is
 * left out; it is never cut or rewritten. */
static inline int
sp_refusal_rid_ok(const char *rid)
{
  size_t n;

  if (!rid || rid[0] == '\0' || rid[0] == ' ' || rid[0] == '\t')
    return 0;
  for (n = 0; rid[n] != '\0'; n++) {
    unsigned char c = (unsigned char)rid[n];

    if (n >= SP_REFUSAL_RID_MAX)
      return 0;
    if ((c < 0x20 && c != '\t') || c == 0x7f)
      return 0;
  }
  return rid[n - 1] != ' ' && rid[n - 1] != '\t';
}

/* The mark as HTTP/1.1 header lines: the stage line when `stage` names one,
 * then the request-ID line when the ID can be echoed. Returns the length
 * written (0 when there is nothing to add), or -1 with `out` emptied when
 * the lines do not fit: a mark is whole or absent. */
static inline int
sp_refusal_mark_h1(char *out, size_t cap, const char *stage, const char *rid)
{
  int n = 0, m;

  if (!out || cap == 0)
    return -1;
  out[0] = '\0';
  if (stage && stage[0] != '\0') {
    n = snprintf(out, cap, SP_REFUSAL_STAGE_HDR ": %s\r\n", stage);
    if (n < 0 || (size_t)n >= cap) {
      out[0] = '\0';
      return -1;
    }
  }
  if (sp_refusal_rid_ok(rid)) {
    m = snprintf(out + n, cap - (size_t)n, SP_REFUSAL_RID_HDR ": %s\r\n", rid);
    if (m < 0 || (size_t)m >= cap - (size_t)n) {
      out[0] = '\0';
      return -1;
    }
    n += m;
  }
  return n;
}

/* A finished HTTP/1.1 response with the mark placed after its status line.
 * For the answers that exist as whole texts: nothing of the response is
 * changed, the body and its Content-Length least of all. Returns the length
 * written into `out` (a NUL follows it, not counted), or 0 when `resp` is
 * not a response with a whole status line, there is nothing to add, or
 * `out` is too small; the caller then sends `resp` as it is. */
static inline size_t
sp_refusal_mark_splice(char *out, size_t cap, const void *resp, size_t len,
                       const char *stage, const char *rid)
{
  char mark[SP_REFUSAL_MARK_MAX + 1];
  const char *r = (const char *)resp;
  size_t head = 0, i;
  int m;

  if (!out || !r || len < 12 || memcmp(r, "HTTP/1.", 7) != 0)
    return 0;
  for (i = 0; i + 1 < len; i++) {
    if (r[i] == '\r' && r[i + 1] == '\n') {
      head = i + 2;
      break;
    }
  }
  if (head == 0)
    return 0;
  m = sp_refusal_mark_h1(mark, sizeof(mark), stage, rid);
  if (m <= 0 || len + (size_t)m >= cap)
    return 0;
  memcpy(out, r, head);
  memcpy(out + head, mark, (size_t)m);
  memcpy(out + head + (size_t)m, r + head, len - head);
  out[len + (size_t)m] = '\0';
  return len + (size_t)m;
}

/* Whether an HTTP/2 field name belongs to the family. */
static inline int
sp_refusal_hdr_is_mark(const uint8_t *name, size_t namelen)
{
  return name && namelen > sizeof(SP_REFUSAL_HDR_PREFIX) - 1 &&
         strncasecmp((const char *)name, SP_REFUSAL_HDR_PREFIX,
                     sizeof(SP_REFUSAL_HDR_PREFIX) - 1) == 0;
}

#endif /* __SOCKPROXY_REFUSAL_MARK_H__ */
