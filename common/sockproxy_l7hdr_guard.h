/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2024-2025 LoxiLB Authors
 *
 * sockproxy_l7hdr_guard.h — the last check before a header field is written
 * into a protocol message.
 *
 * An HTTP/1 header line ends at CRLF, so a field carrying CR or LF does not
 * stay one field: the receiver reads whatever follows the break as a header
 * line of its own. That is header injection, and it matters most for the
 * fields a backend trusts to say who is calling (X-Auth-User, X-Auth-Tenant).
 *
 * Every producer that reaches a splice is already expected to have rejected
 * such a field -- the config API refuses CR/LF in a policy header, and the
 * identity mapper refuses a claim it cannot carry -- so this header is the
 * last line of defence, not the first. Its job is to make the splice itself
 * incapable of emitting a message whose framing it cannot vouch for, no
 * matter which producer grows a gap later.
 *
 * Deliberately free of project includes so a unit can exercise it without the
 * proxy object graph.
 *
 * On NUL: it is NOT checked, and that is not an oversight. Names and values
 * arrive here as C strings, so an interior NUL has already terminated the
 * string and cannot be observed from this side. A guard for it would pass
 * unconditionally -- an assertion that cannot fail is worse than no assertion,
 * because it reads as coverage. Whatever truncates at a NUL must be caught
 * where the bytes still have a length.
 */
#ifndef __SOCKPROXY_L7HDR_GUARD_H__
#define __SOCKPROXY_L7HDR_GUARD_H__

/*
 * Non-zero when `s` cannot be written into a header field: it is absent, or
 * it carries CR or LF. A NULL pointer counts as unsafe so a caller that lost
 * its value refuses rather than dereferences.
 */
static inline int
l7_hdr_field_has_break(const char *s)
{
  if (!s)
    return 1;
  for (; *s; s++) {
    if (*s == '\r' || *s == '\n')
      return 1;
  }
  return 0;
}

/*
 * Non-zero when the name/value pair must not be spliced. An empty name is
 * refused too: it would emit ": value", a line no parser agrees on.
 */
static inline int
l7_hdr_pair_unsafe(const char *name, const char *value)
{
  if (!name || !*name)
    return 1;
  return l7_hdr_field_has_break(name) || l7_hdr_field_has_break(value);
}

#endif /* __SOCKPROXY_L7HDR_GUARD_H__ */
