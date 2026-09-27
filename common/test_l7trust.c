/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_l7trust.c - attributing a request to the address it came from.
 *
 * This unit pins the rule the request path relies on, and in particular the
 * parts of it that are easy to implement backwards:
 *
 *   - a range is stored masked, so two spellings of one range are one range,
 *     and a malformed range is refused rather than silently widened;
 *   - a chain is normalised to one address per hop, without whitespace,
 *     brackets or port, and a chain longer than the list keeps its RIGHT-most
 *     hops, because those are the ones the walk reads and the ones a client
 *     cannot have written;
 *   - the origin is the right-most hop that is not ours, so forgeries the
 *     client prepended cannot change the answer;
 *   - a hop that cannot be read as an address in a range ENDS the trusted run
 *     instead of being stepped over;
 *   - a chain that is entirely ours attributes the peer, and says so, so that
 *     answer can be told apart from a direct connection;
 *   - the count of hops stepped past is reported for every outcome;
 *   - a listener told no ranges trusts nothing;
 *   - the chain passed upstream is the inbound chain plus the peer, and is
 *     dropped rather than truncated when it does not fit;
 *   - several chain header lines APPEND to one list in the order they arrived,
 *     and a line past the end of the list evicts from the LEFT, so a client
 *     cannot push a trusted upstream's hop out with a long chain of its own;
 *   - and, as one listener applies all of it: told no ranges it does not read
 *     the chain at all, told its ranges it recovers the client the upstream
 *     recorded.
 *
 * Build (wired into `make test_l7tr`):
 *   gcc -Wall -Wextra -Werror -o test_l7trust test_l7trust.c -I.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "sockproxy_l7trust.h"

static int checks, failures;

#define CHECK(cond, ...) do {                                        \
    checks++;                                                        \
    if (cond) {                                                      \
      printf("ok %d - ", checks); printf(__VA_ARGS__); printf("\n"); \
    } else {                                                         \
      failures++;                                                    \
      printf("FAIL %d - ", checks); printf(__VA_ARGS__);             \
      printf("   (%s:%d)\n", __FILE__, __LINE__);                    \
    }                                                                \
  } while (0)

/* Build a range set from CIDR text; every entry must parse. */
static uint8_t
ranges_of(l7_trusted_range_t *out, const char **cidrs, uint8_t n)
{
  uint8_t i;
  for (i = 0; i < n; i++) {
    if (l7_trust_parse_cidr(cidrs[i], &out[i]) != 0)
      return 0;
  }
  return n;
}

static void
test_parse_cidr(void)
{
  l7_trusted_range_t r, r2;

  CHECK(l7_trust_parse_cidr("10.0.0.0/8", &r) == 0 && r.prefix_len == 8 &&
        r.addr == inet_addr("10.0.0.0"), "a range parses and keeps its prefix");

  /* Masking at parse: a host address inside a range stores as the range. */
  CHECK(l7_trust_parse_cidr("10.1.2.3/8", &r) == 0 &&
        l7_trust_parse_cidr("10.0.0.0/8", &r2) == 0 &&
        r.addr == r2.addr && r.prefix_len == r2.prefix_len,
        "a host address inside a range stores as the range itself");

  CHECK(l7_trust_parse_cidr("192.0.2.7", &r) == 0 && r.prefix_len == 32 &&
        r.addr == inet_addr("192.0.2.7"), "a bare address is a single host");

  CHECK(l7_trust_parse_cidr("0.0.0.0/0", &r) == 0 && r.prefix_len == 0 &&
        r.addr == 0, "/0 parses and masks to nothing");

  CHECK(l7_trust_parse_cidr("10.0.0.0/33", &r) != 0, "a prefix above 32 is refused");
  CHECK(l7_trust_parse_cidr("10.0.0.0/", &r) != 0, "an empty prefix is refused");
  CHECK(l7_trust_parse_cidr("10.0.0.0/8x", &r) != 0, "a non-numeric prefix is refused");
  CHECK(l7_trust_parse_cidr("10.0.0.0/ 8", &r) != 0, "a spaced prefix is refused");
  CHECK(l7_trust_parse_cidr("10.0.0/8", &r) != 0, "a short address is refused");
  CHECK(l7_trust_parse_cidr("10.0.0.256/8", &r) != 0, "an out-of-range octet is refused");
  CHECK(l7_trust_parse_cidr("2001:db8::1/64", &r) != 0, "an IPv6 range is refused");
  CHECK(l7_trust_parse_cidr("", &r) != 0, "empty text is refused");
  CHECK(l7_trust_parse_cidr(NULL, &r) != 0, "no text is refused");
  CHECK(l7_trust_parse_cidr("10.0.0.0/8", NULL) != 0, "nowhere to store is refused");
}

static void
test_contains(void)
{
  static const char *cidrs[] = { "10.0.0.0/8", "192.168.1.0/24", "203.0.113.9/32" };
  l7_trusted_range_t r[3];
  uint8_t n = ranges_of(r, cidrs, 3);

  CHECK(n == 3, "the range set parses");
  CHECK(l7_trust_contains(r, n, "10.255.255.254"), "an address in a wide range is ours");
  CHECK(l7_trust_contains(r, n, "192.168.1.1"), "an address in a narrow range is ours");
  CHECK(l7_trust_contains(r, n, "203.0.113.9"), "a single-host range matches its host");
  CHECK(!l7_trust_contains(r, n, "203.0.113.10"), "and only its host");
  CHECK(!l7_trust_contains(r, n, "11.0.0.1"), "an address outside every range is not ours");
  CHECK(!l7_trust_contains(r, n, "192.168.2.1"), "a neighbouring subnet is not ours");

  /* The fail-safe direction: anything unreadable as an IPv4 address is not
   * inside an IPv4 range, whatever it is. */
  CHECK(!l7_trust_contains(r, n, "2001:db8::1"), "an IPv6 hop is not ours");
  CHECK(!l7_trust_contains(r, n, "unknown"), "an opaque hop is not ours");
  CHECK(!l7_trust_contains(r, n, ""), "an empty hop is not ours");
  CHECK(!l7_trust_contains(r, n, NULL), "no hop is not ours");
  CHECK(!l7_trust_contains(NULL, 0, "10.0.0.1"), "with no ranges nothing is ours");
  CHECK(!l7_trust_contains(r, 0, "10.0.0.1"), "an empty range set trusts nothing");

  {
    l7_trusted_range_t all;
    CHECK(l7_trust_parse_cidr("0.0.0.0/0", &all) == 0 &&
          l7_trust_contains(&all, 1, "8.8.8.8") &&
          l7_trust_contains(&all, 1, "10.0.0.1"),
          "/0 covers every address");
  }
}

static void
test_hop_list(void)
{
  l7_hop_list_t h;

  CHECK(l7_hop_list_from_xff("203.0.113.5", &h) == 1 &&
        strcmp(h.hop[0], "203.0.113.5") == 0 && !h.truncated,
        "a single hop parses");

  CHECK(l7_hop_list_from_xff("203.0.113.5, 10.0.0.1,10.0.0.2", &h) == 3 &&
        strcmp(h.hop[0], "203.0.113.5") == 0 &&
        strcmp(h.hop[1], "10.0.0.1") == 0 &&
        strcmp(h.hop[2], "10.0.0.2") == 0,
        "hops keep their order, spaced or not");

  CHECK(l7_hop_list_from_xff("\t203.0.113.5 , 10.0.0.1\t", &h) == 2 &&
        strcmp(h.hop[0], "203.0.113.5") == 0 &&
        strcmp(h.hop[1], "10.0.0.1") == 0,
        "surrounding whitespace is dropped");

  CHECK(l7_hop_list_from_xff("203.0.113.5:44321", &h) == 1 &&
        strcmp(h.hop[0], "203.0.113.5") == 0,
        "a port on an IPv4 hop is dropped");

  CHECK(l7_hop_list_from_xff("[2001:db8::1]:44321", &h) == 1 &&
        strcmp(h.hop[0], "2001:db8::1") == 0,
        "brackets and the port around an IPv6 hop are dropped");

  CHECK(l7_hop_list_from_xff("2001:db8::1", &h) == 1 &&
        strcmp(h.hop[0], "2001:db8::1") == 0,
        "a bare IPv6 hop keeps every colon it has");

  CHECK(l7_hop_list_from_xff("203.0.113.5, ,, 10.0.0.1", &h) == 2 &&
        strcmp(h.hop[0], "203.0.113.5") == 0 &&
        strcmp(h.hop[1], "10.0.0.1") == 0,
        "empty elements are skipped, not stored");

  CHECK(l7_hop_list_from_xff("", &h) == 0 && h.n_hops == 0,
        "an empty chain is an empty list");
  CHECK(l7_hop_list_from_xff(NULL, &h) == 0 && h.n_hops == 0,
        "no chain is an empty list");

  /* An element too long to hold is emptied rather than truncated, so it can
   * never read as some other, shorter address. */
  {
    char buf[L7_HOP_TEXT_MAX + 32];
    memset(buf, 'a', sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    CHECK(l7_hop_list_from_xff(buf, &h) == 0,
          "an over-long element is dropped, not shortened");
  }

  /* Overflow keeps the right-most hops: the walk reads from the right, and the
   * left end is the end a client can write. */
  {
    char chain[L7_MAX_HOPS * 16 + 64];
    size_t used = 0;
    int i, total = L7_MAX_HOPS + 3;
    for (i = 0; i < total; i++) {
      used += (size_t)snprintf(chain + used, sizeof(chain) - used,
                               "%s10.0.0.%d", i ? ", " : "", i + 1);
    }
    CHECK(l7_hop_list_from_xff(chain, &h) == L7_MAX_HOPS && h.truncated,
          "a chain longer than the list fills it and says it was truncated");
    CHECK(strcmp(h.hop[L7_MAX_HOPS - 1], "10.0.0.19") == 0 &&
          strcmp(h.hop[0], "10.0.0.4") == 0,
          "and what it kept is the right-most end of the chain");
  }
}

static void
test_attribution(void)
{
  static const char *cidrs[] = { "10.0.0.0/8" };
  l7_trusted_range_t r[1];
  uint8_t n = ranges_of(r, cidrs, 1);
  l7_hop_list_t h;
  char out[L7_HOP_TEXT_MAX];
  uint8_t skipped;

  CHECK(n == 1, "the range set parses");

  /* The shape this exists for: one of our load balancers in front, the client
   * recorded to its left. */
  l7_hop_list_from_xff("203.0.113.5, 10.0.0.7", &h);
  CHECK(l7_attribute_origin(&h, r, n, "10.0.0.7", out, sizeof(out), &skipped) == 1 &&
        strcmp(out, "203.0.113.5") == 0 && skipped == 1,
        "one hop of ours is stepped past and counted");

  /* Two of ours: the walk keeps going. */
  l7_hop_list_from_xff("203.0.113.5, 10.0.0.7, 10.0.0.8", &h);
  CHECK(l7_attribute_origin(&h, r, n, "10.0.0.8", out, sizeof(out), &skipped) == 1 &&
        strcmp(out, "203.0.113.5") == 0 && skipped == 2,
        "two hops of ours are stepped past and counted");

  /* Forgeries: the client prepended three addresses, including one of ours.
   * They are all to the LEFT of what our own hop recorded, so none of them
   * can change the answer. */
  l7_hop_list_from_xff("1.2.3.4, 10.0.0.99, 5.6.7.8, 203.0.113.5, 10.0.0.7", &h);
  CHECK(l7_attribute_origin(&h, r, n, "10.0.0.7", out, sizeof(out), &skipped) == 1 &&
        strcmp(out, "203.0.113.5") == 0 && skipped == 1,
        "forgeries prepended by the client do not change the answer");

  /* Every hop ours: the chain says nothing new, so the peer is the origin -
   * and the return value says so, which is what tells this apart from a
   * direct connection that happens to share the address. */
  l7_hop_list_from_xff("10.0.0.6, 10.0.0.7", &h);
  CHECK(l7_attribute_origin(&h, r, n, "10.0.0.7", out, sizeof(out), &skipped) == 0 &&
        strcmp(out, "10.0.0.7") == 0 && skipped == 2,
        "a chain that is entirely ours attributes the peer, and says so");

  /* A direct connection: no chain at all. Same address as above would be
   * indistinguishable without the count and the return value. */
  l7_hop_list_from_xff(NULL, &h);
  CHECK(l7_attribute_origin(&h, r, n, "203.0.113.5", out, sizeof(out), &skipped) == 0 &&
        strcmp(out, "203.0.113.5") == 0 && skipped == 0,
        "no chain attributes the peer with nothing stepped past");

  /* The fail-safe: a hop we cannot read ends the trusted run. It is to the
   * right of a hop of ours, so stepping over it would attribute something a
   * client chose. */
  l7_hop_list_from_xff("203.0.113.5, unknown, 10.0.0.7", &h);
  CHECK(l7_attribute_origin(&h, r, n, "10.0.0.7", out, sizeof(out), &skipped) == 1 &&
        strcmp(out, "unknown") == 0 && skipped == 1,
        "a hop that cannot be read ends the trusted run");

  l7_hop_list_from_xff("203.0.113.5, [2001:db8::1]:443, 10.0.0.7", &h);
  CHECK(l7_attribute_origin(&h, r, n, "10.0.0.7", out, sizeof(out), &skipped) == 1 &&
        strcmp(out, "2001:db8::1") == 0 && skipped == 1,
        "an IPv6 hop ends the trusted run too");

  /* Told no ranges, nothing is ours, so the right-most hop is the origin. The
   * caller does not use the chain at such a listener at all; this pins that
   * the rule itself does not invent trust. */
  l7_hop_list_from_xff("203.0.113.5, 10.0.0.7", &h);
  CHECK(l7_attribute_origin(&h, NULL, 0, "10.0.0.7", out, sizeof(out), &skipped) == 1 &&
        strcmp(out, "10.0.0.7") == 0 && skipped == 0,
        "with no ranges the right-most hop is the origin");

  /* Every hop ours and no peer to fall back to. */
  l7_hop_list_from_xff("10.0.0.6, 10.0.0.7", &h);
  CHECK(l7_attribute_origin(&h, r, n, NULL, out, sizeof(out), &skipped) == 0 &&
        out[0] == '\0' && skipped == 2,
        "with no peer either, nothing is attributed and the count still reports");

  /* The count is reported even where the caller passes no room for an answer. */
  CHECK(l7_attribute_origin(&h, r, n, "10.0.0.7", out, 0, &skipped) == 0 && skipped == 0,
        "no room for an answer attributes nothing");

  /* A caller that does not want the count still gets an answer. */
  l7_hop_list_from_xff("203.0.113.5, 10.0.0.7", &h);
  CHECK(l7_attribute_origin(&h, r, n, "10.0.0.7", out, sizeof(out), NULL) == 1 &&
        strcmp(out, "203.0.113.5") == 0,
        "the count is optional");

  /* An answer that does not fit falls back to the peer rather than being cut. */
  l7_hop_list_from_xff("203.0.113.5, 10.0.0.7", &h);
  {
    char small[8];
    CHECK(l7_attribute_origin(&h, r, n, "1.2.3.4", small, sizeof(small), &skipped) == 0 &&
          strcmp(small, "1.2.3.4") == 0,
          "an answer too long for the caller falls back to the peer");
  }
}

static void
test_chain_append(void)
{
  l7_hop_list_t h;
  char out[512];

  l7_hop_list_from_xff("203.0.113.5, 10.0.0.7", &h);
  CHECK(l7_chain_append_peer(&h, "10.0.0.8", out, sizeof(out)) > 0 &&
        strcmp(out, "203.0.113.5, 10.0.0.7, 10.0.0.8") == 0,
        "the chain passed upstream is the inbound chain plus the peer");

  l7_hop_list_from_xff(NULL, &h);
  CHECK(l7_chain_append_peer(&h, "203.0.113.5", out, sizeof(out)) > 0 &&
        strcmp(out, "203.0.113.5") == 0,
        "with no inbound chain it is just the peer");

  /* The chain is normalised on the way out too: what we forward is what we
   * read, not the client's spacing or ports. */
  l7_hop_list_from_xff(" 203.0.113.5:9000 ,10.0.0.7", &h);
  CHECK(l7_chain_append_peer(&h, "10.0.0.8", out, sizeof(out)) > 0 &&
        strcmp(out, "203.0.113.5, 10.0.0.7, 10.0.0.8") == 0,
        "and it is the normalised chain, not the text that arrived");

  CHECK(l7_chain_append_peer(&h, NULL, out, sizeof(out)) == 0 && out[0] == '\0',
        "without a peer there is no chain to pass on");

  /* Dropped rather than truncated: a cut chain would move which hop is
   * right-most, and so change what the next hop attributes. */
  {
    char small[16];
    l7_hop_list_from_xff("203.0.113.5, 10.0.0.7", &h);
    CHECK(l7_chain_append_peer(&h, "10.0.0.8", small, sizeof(small)) == 0 &&
          small[0] == '\0',
          "a chain that does not fit is dropped, not truncated");
  }
}

/* Capturing the chain as it is parsed: several chain header lines append to one
 * list in arrival order. A later line displacing an earlier one, or being
 * refused because the list is full, would drop the RIGHT end - and a client
 * could then fill the list with a long chain of its own and push the real hop
 * out, choosing what it is attributed to. */
static void
test_chain_append_lines(void)
{
  l7_hop_list_t h;
  int i;

  memset(&h, 0, sizeof(h));
  CHECK(l7_hop_list_append_n("203.0.113.5", 11, &h) == 1 &&
        strcmp(h.hop[0], "203.0.113.5") == 0,
        "the first chain line is the chain so far");

  CHECK(l7_hop_list_append_n("10.0.0.7", 8, &h) == 2 &&
        strcmp(h.hop[1], "10.0.0.7") == 0,
        "a second chain line is appended to the right of the first");

  CHECK(l7_hop_list_append_n("10.0.0.8", 8, &h) == 3 &&
        strcmp(h.hop[2], "10.0.0.8") == 0,
        "and a third to the right of that, in arrival order");

  CHECK(l7_hop_list_append_n(NULL, 0, &h) == 3 && h.n_hops == 3,
        "an empty line changes nothing");

  /* The bytes handed over are length-delimited, not terminated: a parser gives
   * us a slice of its own buffer. */
  CHECK(l7_hop_list_append_n("198.51.100.9 and then some junk", 12, &h) == 4 &&
        strcmp(h.hop[3], "198.51.100.9") == 0,
        "only the bytes named are read, so an unterminated slice is safe");

  /* Overflow across lines drops the LEFT end, so the hop a trusted upstream
   * wrote in a later line cannot be pushed out by a long earlier one. */
  memset(&h, 0, sizeof(h));
  for (i = 0; i < L7_MAX_HOPS; i++) {
    char one[32];
    int n = snprintf(one, sizeof(one), "10.9.9.%d", i + 1);
    l7_hop_list_append_n(one, (size_t)n, &h);
  }
  CHECK(h.n_hops == L7_MAX_HOPS && !h.truncated, "the list fills exactly");
  CHECK(l7_hop_list_append_n("203.0.113.5", 11, &h) == L7_MAX_HOPS &&
        h.truncated &&
        strcmp(h.hop[L7_MAX_HOPS - 1], "203.0.113.5") == 0 &&
        strcmp(h.hop[0], "10.9.9.2") == 0,
        "a line past the end evicts from the LEFT and keeps the newest hop");
}

/* The rule as one listener applies it, which is how the request path calls it. */
static void
test_listener_rule(void)
{
  static const char *cidrs[] = { "10.0.0.0/8" };
  l7_trusted_range_t r[1];
  uint8_t n = ranges_of(r, cidrs, 1);
  l7_hop_list_t hops;
  char out[L7_HOP_TEXT_MAX];
  uint8_t skipped;

  CHECK(n == 1, "the range set parses");

  /* A listener at the edge does not consult the chain, whatever it says. This
   * is the case that has to stay byte-for-byte what it was. */
  l7_hop_list_from_xff("1.2.3.4, 5.6.7.8", &hops);
  CHECK(l7_origin_for_listener(&hops, NULL, 0, "203.0.113.5",
                               out, sizeof(out), &skipped) == 0 &&
        strcmp(out, "203.0.113.5") == 0 && skipped == 0,
        "told no ranges, a listener does not consult the chain at all");

  /* Behind one of ours: the chain is read and the client recovered. */
  l7_hop_list_from_xff("203.0.113.5", &hops);
  CHECK(l7_origin_for_listener(&hops, r, n, "10.0.0.7",
                               out, sizeof(out), &skipped) == 1 &&
        strcmp(out, "203.0.113.5") == 0 && skipped == 0,
        "told its ranges, it recovers the client the upstream recorded");

  /* Two of ours in front, so the chain really does end in a hop of ours. */
  l7_hop_list_from_xff("203.0.113.5, 10.0.0.6", &hops);
  CHECK(l7_origin_for_listener(&hops, r, n, "10.0.0.7",
                               out, sizeof(out), &skipped) == 1 &&
        strcmp(out, "203.0.113.5") == 0 && skipped == 1,
        "and steps past the hop between two of ours");

  /* A direct connection to a listener that does have ranges. */
  l7_hop_list_from_xff("", &hops);
  CHECK(l7_origin_for_listener(&hops, r, n, "203.0.113.5",
                               out, sizeof(out), &skipped) == 0 &&
        strcmp(out, "203.0.113.5") == 0 && skipped == 0,
        "a direct connection to such a listener is still the peer");
}

int
main(void)
{
  test_parse_cidr();
  test_contains();
  test_hop_list();
  test_attribution();
  test_chain_append();
  test_chain_append_lines();
  test_listener_rule();
  printf("=== results: %d/%d passed ===\n", checks - failures, checks);
  return failures ? 1 : 0;
}
