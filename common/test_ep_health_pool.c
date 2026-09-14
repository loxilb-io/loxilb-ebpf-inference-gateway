/* test_ep_health_pool.c - a health signal must reach the endpoint it is about.
 *
 * A service with model-keyed rules holds several proxy_epval_t pools, each
 * numbering its own eps[] from 0. The health path used to resolve a caller's
 * index against whichever pool hashed first - its loop returned during the
 * first iteration - so on a multi-pool service it marked a healthy backend
 * down and left the failed one taking traffic. An in-range index naming a
 * live endpoint looks exactly like a correct one, so nothing downstream could
 * catch it.
 *
 * Build: cc -Wall -Wextra -Werror -o test_ep_health_pool test_ep_health_pool.c -I.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "sockproxy_ep_health.h"

/* Two model pools on one VIP:port, the cicd ai-jwtauth topology. Both number
 * their endpoints from 0, and they share a backend host. */
#define LLAMA_EP0_IP    0x0a000005u   /* 10.0.0.5 */
#define LLAMA_EP0_PORT  0x1f90u       /* 8080 */
#define MISTRAL_EP0_IP  0x0a000006u   /* 10.0.0.6 */
#define MISTRAL_EP0_PORT 0x1f90u

/* A second listener on the SAME host as llama's endpoint 0. */
#define SIBLING_PORT    0x1f91u       /* 8081 */

static void
test_an_index_is_not_resolvable_across_pools(void)
{
  /* One pool: the index is the only possible answer. */
  assert(ep_health_index_is_resolvable(1) == 1);

  /* Two pools: the caller's index names a position in a list it never
   * identified. Resolving it against the pool that happens to hash first is
   * what marked the wrong backend down. */
  assert(ep_health_index_is_resolvable(2) == 0);
  assert(ep_health_index_is_resolvable(5) == 0);

  /* No pool at all is not a wildcard either. */
  assert(ep_health_index_is_resolvable(0) == 0);
}

static void
test_address_names_the_same_backend_in_every_pool(void)
{
  /* The address is what survives the pool boundary: the signal is about this
   * backend wherever it appears, so both pools' rows must match it. */
  assert(ep_health_addr_matches(LLAMA_EP0_IP, LLAMA_EP0_PORT,
                                LLAMA_EP0_IP, LLAMA_EP0_PORT) == 1);

  /* And it must not match a different backend that merely shares an index. */
  assert(ep_health_addr_matches(MISTRAL_EP0_IP, MISTRAL_EP0_PORT,
                                LLAMA_EP0_IP, LLAMA_EP0_PORT) == 0);
}

static void
test_a_probed_port_does_not_take_down_its_sibling(void)
{
  /* Two listeners on one host. A probe that knows the port is about one of
   * them; matching on address alone would mark both down. */
  assert(ep_health_addr_matches(LLAMA_EP0_IP, SIBLING_PORT,
                                LLAMA_EP0_IP, LLAMA_EP0_PORT) == 0);
  assert(ep_health_addr_matches(LLAMA_EP0_IP, LLAMA_EP0_PORT,
                                LLAMA_EP0_IP, LLAMA_EP0_PORT) == 1);
}

static void
test_a_host_level_signal_covers_every_listener(void)
{
  /* A GPU node turning red is about the HOST, so every listener on it is
   * affected and the caller passes no port. */
  assert(ep_health_addr_matches(LLAMA_EP0_IP, LLAMA_EP0_PORT,
                                LLAMA_EP0_IP, EP_HEALTH_ANY_PORT) == 1);
  assert(ep_health_addr_matches(LLAMA_EP0_IP, SIBLING_PORT,
                                LLAMA_EP0_IP, EP_HEALTH_ANY_PORT) == 1);

  /* Still bounded by the address - a host-level signal is not a wildcard. */
  assert(ep_health_addr_matches(MISTRAL_EP0_IP, MISTRAL_EP0_PORT,
                                LLAMA_EP0_IP, EP_HEALTH_ANY_PORT) == 0);
}

int
main(void)
{
  test_an_index_is_not_resolvable_across_pools();
  test_address_names_the_same_backend_in_every_pool();
  test_a_probed_port_does_not_take_down_its_sibling();
  test_a_host_level_signal_covers_every_listener();
  puts("test_ep_health_pool: ALL PASS");
  return 0;
}
