/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __SOCKPROXY_CONV_HDR_H__
#define __SOCKPROXY_CONV_HDR_H__

/* Which HTTP/1.1 request headers carry a conversation ID.
 *
 * A conversation ID is an affinity key: it is the session key of a
 * prefill/decode rule (ahead of the JSON "user" field) and the hash a
 * CHWBL / GPU-aware / WRR-hash rule places a request by when the request
 * has no prompt prefix to hash. So a header belongs here only when a
 * client means it to hold requests together.
 *
 * X-Request-Id does not: it names ONE request, and a client or a gateway in
 * front of this one sends a new value every time. It is the correlation
 * key (vllm_request_id) and nothing else. HTTP/2 has always read it that
 * way (sockproxy_h2.c takes x-conversation-id alone).
 *
 * The match is on the start of the name, as it has always been for these
 * three. Pure, no allocation, so the unit can compile it alone. */

#include <strings.h>

static inline int
sp_h1_conv_id_header(const char *name)
{
  return name &&
         (!strncasecmp("X-Conversation-ID", name, 17) ||
          !strncasecmp("X-Session-ID", name, 12) ||
          !strncasecmp("X-Trace-ID", name, 10));
}

#endif /* __SOCKPROXY_CONV_HDR_H__ */
