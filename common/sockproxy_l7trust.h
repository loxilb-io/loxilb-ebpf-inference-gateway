/* SPDX-License-Identifier: BSD-3-Clause
 *
 * sockproxy_l7trust.h - attributing a request to the address it came from.
 */
#ifndef __SOCKPROXY_L7TRUST_H__
#define __SOCKPROXY_L7TRUST_H__

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

/*
 * At the edge of a network the address a request came from is the address of
 * the socket peer, and nothing a client sends can change that. Behind another
 * load balancer, an ingress or a CDN it is not: the peer is that upstream, and
 * the client's own address is whatever the upstream recorded in the forwarding
 * chain it passed along. A listener therefore has to be told which peers are
 * upstreams of ours before anything in a request header can be believed.
 *
 * A listener carries the ranges those upstreams occupy. Nothing is trusted by
 * default, so a listener told nothing behaves exactly as one at the edge: the
 * peer is the origin and an inbound chain is replaced rather than extended.
 *
 * Which element of the chain is the origin: the right-most one that is not
 * ours. A chain grows left to right, each hop appending the peer it saw, so a
 * client controls only its left end - it can prepend anything it likes, and
 * everything to the right of what it sent was written by a hop that observed
 * the connection it wrote about. Walking from the right past the hops we know
 * are ours therefore lands on the address of whoever sent the request to the
 * outermost of them, whatever forgeries precede it. If every hop in the chain
 * is ours the chain says nothing we did not already know and the peer is the
 * origin.
 *
 * Two consequences are worth stating because they are easy to get backwards.
 * A hop that cannot be read as an address in one of the ranges is not ours,
 * so the walk stops on it: an element we cannot account for ends the trusted
 * run rather than being stepped over. And the number of hops the walk stepped
 * past is part of the answer, not a diagnostic - without it an origin equal to
 * the peer cannot be told apart from a chain that resolved back to the peer.
 *
 * The walk reads a normalised hop list rather than header text, so a second
 * way of carrying a chain is a second parser filling the same list and not a
 * second rule about which element to believe.
 */

#ifndef L7_MAX_TRUSTED_RANGES
#define L7_MAX_TRUSTED_RANGES 16   /* per listener; bounded, stored by value */
#endif

#ifndef L7_MAX_HOPS
#define L7_MAX_HOPS 16             /* hops retained from one inbound chain */
#endif

#ifndef L7_HOP_TEXT_MAX
#define L7_HOP_TEXT_MAX 46         /* INET6_ADDRSTRLEN */
#endif

/* One range of addresses belonging to our own upstreams. IPv4: the request
 * path reads an IPv4 socket peer, so an IPv6 hop is never inside a range and
 * reads as untrusted, which is the safe direction. `addr` is in network byte
 * order and already masked to `prefix_len`, so a containment test is a
 * compare and no parse survives into the request path. */
typedef struct {
  uint32_t addr;
  uint8_t  prefix_len;             /* 0..32 */
} l7_trusted_range_t;

/* One inbound chain, normalised: one address per entry, left-most first, no
 * whitespace, no brackets and no port. A chain longer than the list keeps its
 * RIGHT-most hops, because those are the ones the walk reads first and the
 * ones a client cannot have written; `truncated` records that the left end was
 * dropped. */
typedef struct {
  char    hop[L7_MAX_HOPS][L7_HOP_TEXT_MAX];
  uint8_t n_hops;
  uint8_t truncated;
} l7_hop_list_t;

/* The host-order mask for `prefix_len`. Split out because shifting a 32-bit
 * value by 32 is undefined, which is exactly the /0 case. */
static inline uint32_t
l7_trust_mask(uint8_t prefix_len)
{
  if (prefix_len == 0)
    return 0;
  if (prefix_len >= 32)
    return 0xFFFFFFFFu;
  return 0xFFFFFFFFu << (32 - prefix_len);
}

/* Parse "A.B.C.D/N" into `out`, masking the address to the prefix so that two
 * spellings of one range are stored identically. A bare address is /32.
 * Returns 0, or -1 on a malformed address, a prefix above 32, a prefix that is
 * not a plain number, or trailing text. */
static inline int
l7_trust_parse_cidr(const char *text, l7_trusted_range_t *out)
{
  char addr_text[INET_ADDRSTRLEN];
  const char *slash;
  size_t addr_len;
  struct in_addr addr;
  unsigned prefix = 32;

  if (!text || !out)
    return -1;

  slash = strchr(text, '/');
  addr_len = slash ? (size_t)(slash - text) : strlen(text);
  if (addr_len == 0 || addr_len >= sizeof(addr_text))
    return -1;
  memcpy(addr_text, text, addr_len);
  addr_text[addr_len] = '\0';

  if (slash) {
    const char *p = slash + 1;
    if (*p == '\0')
      return -1;
    prefix = 0;
    for (; *p != '\0'; p++) {
      if (*p < '0' || *p > '9')
        return -1;
      prefix = prefix * 10 + (unsigned)(*p - '0');
      if (prefix > 32)
        return -1;
    }
  }

  if (inet_pton(AF_INET, addr_text, &addr) != 1)
    return -1;

  out->prefix_len = (uint8_t)prefix;
  out->addr = addr.s_addr & htonl(l7_trust_mask((uint8_t)prefix));
  return 0;
}

/* Is `text` an address inside one of `ranges`? Anything that is not an IPv4
 * literal - an IPv6 hop, a name, "unknown", an empty entry - is not, so the
 * walk treats it as a hop we cannot account for. */
static inline int
l7_trust_contains(const l7_trusted_range_t *ranges, uint8_t n_ranges,
                  const char *text)
{
  struct in_addr addr;
  uint8_t i;

  if (!ranges || n_ranges == 0 || !text || text[0] == '\0')
    return 0;
  if (inet_pton(AF_INET, text, &addr) != 1)
    return 0;

  if (n_ranges > L7_MAX_TRUSTED_RANGES)
    n_ranges = L7_MAX_TRUSTED_RANGES;
  for (i = 0; i < n_ranges; i++) {
    uint32_t mask = htonl(l7_trust_mask(ranges[i].prefix_len));
    if ((addr.s_addr & mask) == (ranges[i].addr & mask))
      return 1;
  }
  return 0;
}

/* Copy one chain element into `out`, dropping surrounding whitespace, the
 * brackets around an IPv6 literal and a trailing port. A port is only ever
 * removed where removing it cannot corrupt the address: after brackets, or
 * from text holding exactly one colon, which an IPv6 literal never does.
 * `out` is always terminated; an element too long to hold is emptied, so it
 * reads as a hop we cannot account for rather than as a truncated address. */
static inline void
l7_hop_normalise(const char *begin, const char *end, char *out, size_t outlen)
{
  size_t len;
  int bracketed = 0;

  if (!out || outlen == 0)
    return;
  out[0] = '\0';
  if (!begin || !end || end < begin)
    return;

  while (begin < end && (*begin == ' ' || *begin == '\t'))
    begin++;
  while (end > begin && (end[-1] == ' ' || end[-1] == '\t'))
    end--;

  if (end - begin >= 2 && *begin == '[') {
    const char *close = (const char *)memchr(begin, ']', (size_t)(end - begin));
    if (close) {
      bracketed = 1;
      begin++;
      end = close;
    }
  }

  len = (size_t)(end - begin);
  if (len == 0 || len >= outlen)
    return;
  memcpy(out, begin, len);
  out[len] = '\0';

  if (!bracketed) {
    char *colon = strchr(out, ':');
    if (colon && strchr(colon + 1, ':') == NULL)
      *colon = '\0';
  }
}

/* Fill `out` from the comma-separated chain in `text`. Returns the number of
 * hops retained. An empty or absent chain leaves an empty list, which the
 * attribution reads as "the peer is the origin". */
static inline uint8_t
l7_hop_list_from_xff(const char *text, l7_hop_list_t *out)
{
  const char *p;

  if (!out)
    return 0;
  memset(out, 0, sizeof(*out));
  if (!text)
    return 0;

  for (p = text; ; ) {
    const char *comma = strchr(p, ',');
    const char *end = comma ? comma : p + strlen(p);
    char hop[L7_HOP_TEXT_MAX];

    l7_hop_normalise(p, end, hop, sizeof(hop));
    if (hop[0] != '\0') {
      if (out->n_hops == L7_MAX_HOPS) {
        /* Keep the right-most hops: drop the left end, which is the end a
         * client could have written, and record that we did. */
        memmove(out->hop[0], out->hop[1],
                (size_t)(L7_MAX_HOPS - 1) * L7_HOP_TEXT_MAX);
        out->n_hops = L7_MAX_HOPS - 1;
        out->truncated = 1;
      }
      memcpy(out->hop[out->n_hops], hop, sizeof(hop));
      out->n_hops++;
    }

    if (!comma)
      break;
    p = comma + 1;
  }
  return out->n_hops;
}

/* Attribute the request: the right-most hop in `hops` that is not inside
 * `ranges`, or `peer_ip` when every hop is. Writes the address to `out` and
 * the number of trusted hops stepped past to `skipped`. Returns 1 when the
 * answer came from the chain and 0 when it is the peer, so a caller can tell
 * a chain that resolved back to the peer from a direct connection even without
 * comparing addresses.
 *
 * With no ranges configured no hop can be trusted, the walk stops on the
 * right-most hop and `skipped` is 0 - but a listener at the edge is not meant
 * to call this at all, and the caller keeps replacing the chain there. */
static inline int
l7_attribute_origin(const l7_hop_list_t *hops,
                    const l7_trusted_range_t *ranges, uint8_t n_ranges,
                    const char *peer_ip,
                    char *out, size_t outlen, uint8_t *skipped)
{
  uint8_t n, i, walked = 0;

  if (skipped)
    *skipped = 0;
  if (!out || outlen == 0)
    return 0;
  out[0] = '\0';

  n = hops ? hops->n_hops : 0;
  if (n > L7_MAX_HOPS)
    n = L7_MAX_HOPS;
  for (i = n; i > 0; i--) {
    const char *hop = hops->hop[i - 1];
    if (!l7_trust_contains(ranges, n_ranges, hop)) {
      size_t len = strlen(hop);
      if (len == 0 || len >= outlen)
        break;                     /* unusable: fall back to the peer */
      memcpy(out, hop, len + 1);
      if (skipped)
        *skipped = walked;
      return 1;
    }
    walked++;
  }

  if (skipped)
    *skipped = walked;
  if (peer_ip) {
    size_t len = strlen(peer_ip);
    if (len > 0 && len < outlen)
      memcpy(out, peer_ip, len + 1);
  }
  return 0;
}

/* Join another chain header line onto `dst`, which may be empty. Several chain
 * header lines are one list in the order they arrived (RFC 7230), so they are
 * joined rather than replaced: the chain's meaning rests on hops appending to
 * the right, and a later line replacing an earlier one would move which hop is
 * right-most and so change which hop a request is attributed to. A line that
 * would not fit leaves `dst` as it stands rather than cutting it, for the same
 * reason. Returns the resulting length. */
static inline size_t
l7_chain_join(char *dst, size_t dstlen, const char *value, size_t valuelen)
{
  size_t used, need;

  if (!dst || dstlen == 0)
    return 0;
  used = strlen(dst);
  if (!value || valuelen == 0)
    return used;

  need = valuelen + (used ? 2 : 0);
  if (used + need >= dstlen)
    return used;                 /* keep what we have rather than cut it */
  if (used) {
    dst[used++] = ',';
    dst[used++] = ' ';
  }
  memcpy(dst + used, value, valuelen);
  used += valuelen;
  dst[used] = '\0';
  return used;
}

/* The whole rule for one listener: which address a request arriving on it came
 * from, given the chain it arrived with and the ranges the listener trusts.
 *
 * A listener told nothing about what sits in front of it does not read the
 * chain at all - the peer is the origin and no hop was stepped past. Reading a
 * chain a listener cannot vouch for would let whoever sent it choose the
 * answer, so the emptiness of the range set is the whole gate.
 *
 * `hops_out`, when given, receives the normalised hop list, so a caller that
 * also forwards the chain does not parse it a second time. Returns 1 when the
 * answer came from the chain and 0 when it is the peer. */
static inline int
l7_origin_for_listener(const char *inbound_chain,
                       const l7_trusted_range_t *ranges, uint8_t n_ranges,
                       const char *peer_ip,
                       char *out, size_t outlen, uint8_t *skipped,
                       l7_hop_list_t *hops_out)
{
  l7_hop_list_t local;
  l7_hop_list_t *hops = hops_out ? hops_out : &local;

  memset(hops, 0, sizeof(*hops));
  if (skipped)
    *skipped = 0;
  if (!out || outlen == 0)
    return 0;
  out[0] = '\0';

  if (n_ranges == 0) {
    size_t len = peer_ip ? strlen(peer_ip) : 0;
    if (len > 0 && len < outlen)
      memcpy(out, peer_ip, len + 1);
    return 0;
  }

  l7_hop_list_from_xff(inbound_chain, hops);
  return l7_attribute_origin(hops, ranges, n_ranges, peer_ip,
                             out, outlen, skipped);
}

/* Build the chain to pass upstream: the inbound chain with `peer_ip`
 * appended, which is what every hop in a chain does and what makes the next
 * hop's own walk work. Returns the written length, or 0 when nothing could be
 * written - a chain that does not fit is dropped rather than truncated, since
 * a truncated chain would silently move which hop is right-most. */
static inline size_t
l7_chain_append_peer(const l7_hop_list_t *hops, const char *peer_ip,
                     char *out, size_t outlen)
{
  size_t used = 0;
  uint8_t n, i;

  if (!out || outlen == 0)
    return 0;
  out[0] = '\0';
  if (!peer_ip || peer_ip[0] == '\0')
    return 0;

  n = hops ? hops->n_hops : 0;
  if (n > L7_MAX_HOPS)
    n = L7_MAX_HOPS;
  for (i = 0; i < n; i++) {
    size_t len = strlen(hops->hop[i]);
    size_t need = len + (used ? 2 : 0);
    if (used + need >= outlen) {
      out[0] = '\0';
      return 0;
    }
    if (used) {
      out[used++] = ',';
      out[used++] = ' ';
    }
    memcpy(out + used, hops->hop[i], len);
    used += len;
    out[used] = '\0';
  }

  {
    size_t len = strlen(peer_ip);
    size_t need = len + (used ? 2 : 0);
    if (used + need >= outlen) {
      out[0] = '\0';
      return 0;
    }
    if (used) {
      out[used++] = ',';
      out[used++] = ' ';
    }
    memcpy(out + used, peer_ip, len);
    used += len;
    out[used] = '\0';
  }
  return used;
}

#endif /* __SOCKPROXY_L7TRUST_H__ */
