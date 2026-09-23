/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2026 LoxiLB Authors
 *
 * sockproxy_hdr_deadline.h — the listener header-completion deadline.
 *
 * Every L7 listener bounds how long a client may take to finish sending
 * request headers (the slowloris guard). The rule field timeout_tcp_inspect_ms
 * sets that bound; a rule that sets nothing, or sets 0, gets the product
 * default. There is NO value that disables the deadline: 0 is "default",
 * not "off", and the swagger description says so. This header holds the one
 * resolution rule so the proxy and its unit agree on it, and so a comment
 * elsewhere cannot quietly promise a disable switch the code never had.
 *
 * Deliberately free of project includes so a unit can exercise it without the
 * proxy object graph.
 */
#ifndef __SOCKPROXY_HDR_DEADLINE_H__
#define __SOCKPROXY_HDR_DEADLINE_H__

#include <stdint.h>

/* Header-completion deadline (ms) for every listener whose rule sets no
 * timeout_tcp_inspect_ms. 10 s mirrors a conservative HAProxy `timeout
 * http-request`: long enough not to trip legitimate slow clients, short
 * enough to bound a slowloris hold. */
#ifndef L7_TCP_INSPECT_DEFAULT_MS
#define L7_TCP_INSPECT_DEFAULT_MS 10000
#endif

/* The deadline a listener enforces, from the value its rule configured.
 * 0 (unset) resolves to the default; any positive value is used as given. */
static inline uint32_t
sp_hdr_deadline_resolve_ms(uint32_t configured_ms)
{
  return configured_ms > 0 ? configured_ms : L7_TCP_INSPECT_DEFAULT_MS;
}

#endif /* __SOCKPROXY_HDR_DEADLINE_H__ */
