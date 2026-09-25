/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_request_id_join.c - the three records of one request must be joinable.
 *
 * A request's completion record, its token settle and any refusal all carry
 * one correlation key, and that key is the only thing that joins them. The
 * key lives on the connection shell, in vllm_request_id, written when the
 * request head is parsed (client-supplied X-Request-Id) or minted just before
 * the admission gate decides.
 *
 * The connection is keep-alive, so the moment a request has been FORWARDED
 * the shell is reset for the next request on the same connection, and that
 * reset clears vllm_request_id. Every consumer named above runs after that
 * point: the response has not even arrived yet. A consumer that reads the
 * live field therefore reads an empty string for every request that got as
 * far as being forwarded - refusals kept their key only because they are
 * decided before the forward path, which is exactly why the two disagreed.
 *
 * The fix is the one the effective model already uses: snapshot across the
 * boundary and resolve through an accessor that prefers the live field. This
 * unit pins the pair.
 *
 * THE ORACLE IS SELF-VERIFYING. The keep-alive case is scored twice: once
 * against proxy_request_id(), and once against prefix_request_id() below -
 * the pre-fix rule kept verbatim. The case only counts if it PASSES the
 * shipped accessor and FAILS the pre-fix one, so a test that cannot go red
 * proves nothing.
 *
 * Build (wired into `make test_ridjoin`):
 *   gcc -Wall -Wextra -o test_request_id_join test_request_id_join.c -I.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "uthash.h"
#include "sockproxy.h"

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

/* The PRE-FIX rule: response-phase consumers read the live request field. */
static const char *
prefix_request_id(const proxy_fd_ent_t *pfe)
{
  return pfe->vllm_request_id;
}

/* The shell as the keep-alive reset leaves it: the key snapshotted, then the
 * live field cleared for the next request. Mirrors the reset in
 * pd_setup_and_forward, in that order. */
static void
forward_and_reset(proxy_fd_ent_t *pfe)
{
  proxy_request_id_snapshot(pfe);
  pfe->vllm_request_id[0] = '\0';
  pfe->has_vllm_request_id = 0;
  pfe->request_id_injected = 0;
}

static proxy_fd_ent_t *
fresh_shell(void)
{
  proxy_fd_ent_t *pfe = calloc(1, sizeof(*pfe));
  if (!pfe) {
    printf("Bail out! calloc\n");
    exit(1);
  }
  return pfe;
}

/* Before the forward - the gate's own frame - the live field answers, so a
 * refusal names the request it refused. */
static void
test_gate_frame(void)
{
  proxy_fd_ent_t *pfe = fresh_shell();

  snprintf(pfe->vllm_request_id, sizeof(pfe->vllm_request_id), "%s",
           "4ab2c0de00000000b000000000000001");

  CHECK(!strcmp(proxy_request_id(pfe), "4ab2c0de00000000b000000000000001"),
        "the live key answers before the request is forwarded");

  free(pfe);
}

/* After the forward - where the completion, the settle and the teardown
 * release all run - the snapshot answers with the SAME key. */
static void
test_survives_keepalive_reset(void)
{
  proxy_fd_ent_t *pfe = fresh_shell();
  const char *minted = "4ab2c0de00000000b000000000000002";

  snprintf(pfe->vllm_request_id, sizeof(pfe->vllm_request_id), "%s", minted);
  forward_and_reset(pfe);

  CHECK(!strcmp(proxy_request_id(pfe), minted),
        "the completion and settle name the request the gate decided");
  CHECK(strcmp(prefix_request_id(pfe), minted) != 0,
        "the pre-fix rule reports no key here, so this case can go red");

  free(pfe);
}

/* A client-supplied X-Request-Id is adopted rather than minted, and must
 * cross the same boundary: it is the key the client will join on. */
static void
test_client_supplied_key(void)
{
  proxy_fd_ent_t *pfe = fresh_shell();

  snprintf(pfe->vllm_request_id, sizeof(pfe->vllm_request_id), "%s",
           "client-chosen-id-1");
  pfe->has_vllm_request_id = 1;
  forward_and_reset(pfe);

  CHECK(!strcmp(proxy_request_id(pfe), "client-chosen-id-1"),
        "an adopted client key survives the reset too");

  free(pfe);
}

/* The next request on the connection owns the key from the moment it has
 * one: its gate frame must never report its predecessor's. */
static void
test_next_request_wins(void)
{
  proxy_fd_ent_t *pfe = fresh_shell();

  snprintf(pfe->vllm_request_id, sizeof(pfe->vllm_request_id), "%s", "first");
  forward_and_reset(pfe);
  snprintf(pfe->vllm_request_id, sizeof(pfe->vllm_request_id), "%s", "second");

  CHECK(!strcmp(proxy_request_id(pfe), "second"),
        "the request in hand outranks the snapshot of the one before it");

  free(pfe);
}

/* Nothing was ever parsed on this connection: the accessor answers with an
 * empty string, never a dangling read. */
static void
test_no_request_at_all(void)
{
  proxy_fd_ent_t *pfe = fresh_shell();

  CHECK(proxy_request_id(pfe)[0] == '\0',
        "a connection with no request reports no key");

  free(pfe);
}

/* The snapshot must hold the longest key the live field can: a truncated
 * copy would join to nothing. */
static void
test_snapshot_holds_a_full_key(void)
{
  proxy_fd_ent_t *pfe = fresh_shell();
  char big[sizeof(pfe->vllm_request_id)];
  size_t i;

  for (i = 0; i < sizeof(big) - 1; i++) {
    big[i] = 'k';
  }
  big[sizeof(big) - 1] = '\0';

  memcpy(pfe->vllm_request_id, big, sizeof(big));
  forward_and_reset(pfe);

  CHECK(sizeof(pfe->resp_request_id) == sizeof(pfe->vllm_request_id),
        "the snapshot is as wide as the field it snapshots");
  CHECK(!strcmp(proxy_request_id(pfe), big),
        "a full-width key crosses the boundary intact");

  free(pfe);
}

int
main(void)
{
  test_gate_frame();
  test_survives_keepalive_reset();
  test_client_supplied_key();
  test_next_request_wins();
  test_no_request_at_all();
  test_snapshot_holds_a_full_key();

  printf("\n1..%d\n", checks);
  if (failures) {
    printf("# %d of %d checks FAILED\n", failures, checks);
    return 1;
  }
  printf("# all %d checks passed\n", checks);
  return 0;
}
