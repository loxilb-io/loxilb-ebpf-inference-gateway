/* SPDX-License-Identifier: (GPL-2.0) */
/* test_radix_pfe.c - the per-connection prefix-routing state on a real
 * connection shell (proxy_fd_ent_t), under LeakSanitizer.
 *
 * The pointer (proxy_fd_ent_t.radix_req) lies in the first run that
 * pfe_clear zeroes. The sites that end its life:
 *   message begin  radix_req_reset: reset, kept for the next request
 *   pfe_recycle    pfe_radix_req_release: freed, NULL (the ONLY push onto the
 *                  shell freelist)
 *   pfe_clear      the only clear of the range, on a shell popped from that
 *                  freelist: finds NULL, frees nothing
 * This test drives the same helpers on a real shell with the real allocation
 * (radix_route_decide), in the order the shell lives them: requests with a
 * reset between them, recycle, pop and clear, a new connection's requests,
 * recycle, pop and clear. LeakSanitizer fails the run on any leak.
 * "./test_radix_pfe leak" is the negative control: the shell is cleared
 * without the recycle's release, and LeakSanitizer must report it.
 *
 * The decided mark (proxy_fd_ent_t.radix_decided) lives with the request: a
 * request decided again on a park's wake is counted once; message begin
 * clears it with the reset (the two statements sockproxy_http.c runs there,
 * held together by test_radix_wiring), so the next request on the connection
 * is counted again; pfe_clear zeroes it.
 *
 * Build: make test_radix_pfe
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "uthash.h"
#include "sockproxy_pfe_clear.h"
#include "sockproxy_radix.c"
#include "sockproxy_radix_scan.c"
#include "sockproxy_radix_route.c"

static int fails;
#define CHECK(c) do { if (!(c)) { fails++; printf("    check failed: %s (line %d)\n", #c, __LINE__); } } while (0)

static size_t body(char *b)
{
  size_t n = (size_t)sprintf(b, "{\"model\":\"m\",\"messages\":[{\"role\":\"system\",\"content\":\"");
  memset(b + n, 'x', 900); n += 900;
  n += (size_t)sprintf(b + n, "\"}]}");
  return n;
}

static void use(radix_pool_t *p, proxy_fd_ent_t *pfe, const char *b, size_t len)
{
  radix_route_in_t in;
  radix_route_out_t out;
  memset(&in, 0, sizeof(in));
  in.pool_id = p; in.ai_gw_mode = 1; in.fc_active = 1; in.model = "m"; in.model_len = 1;
  in.body = b; in.body_len = len; in.eligible = 0x3; in.n_eps = 2;
  radix_route_decide(p, &pfe->radix_req, &in, &out);
}

static void use_marked(radix_pool_t *p, proxy_fd_ent_t *pfe, const char *b, size_t len)
{
  radix_route_in_t in;
  radix_route_out_t out;
  memset(&in, 0, sizeof(in));
  in.pool_id = p; in.ai_gw_mode = 1; in.fc_active = 1; in.model = "m"; in.model_len = 1;
  in.body = b; in.body_len = len; in.eligible = 0x3; in.n_eps = 2;
  in.decided = &pfe->radix_decided;
  radix_route_decide(p, &pfe->radix_req, &in, &out);
}

static uint64_t misses(radix_pool_t *p)
{
  return __atomic_load_n(&p->st.decided[RADIX_R_MISS], __ATOMIC_RELAXED);
}

int main(int argc, char **argv)
{
  radix_route_cfg_t cfg;
  radix_pool_t *p;
  proxy_fd_ent_t *pfe = calloc(1, sizeof(*pfe));
  char *b = malloc(4096);
  size_t len = body(b);
  radix_req_t *first;

  memset(&cfg, 0, sizeof(cfg));
  p = radix_pool_create(&cfg);
  if (argc > 1 && !strcmp(argv[1], "leak")) {
    use(p, pfe, b, len);
    memset(pfe, 0, PFE_SKIP_OFF);              /* a clear without the release */
    radix_pool_free(p);
    free(b);
    free(pfe);
    printf("test_radix_pfe: negative control done (LeakSanitizer must report)\n");
    return 0;
  }

  printf("radix_req at offset %zu, cleared run [0, %zu), skipped [%zu, %zu)\n",
         offsetof(proxy_fd_ent_t, radix_req), (size_t)PFE_SKIP_OFF,
         (size_t)PFE_SKIP_OFF, (size_t)PFE_SKIP_END);
  CHECK(offsetof(proxy_fd_ent_t, radix_req) < PFE_SKIP_OFF);

  for (int conn = 0; conn < 2; conn++) {
    /* a connection's requests: message begin resets, the state is reused */
    use(p, pfe, b, len);
    CHECK(pfe->radix_req != NULL);
    first = pfe->radix_req;
    radix_req_reset(pfe->radix_req);
    CHECK(pfe->radix_req == first && !first->scanned && !first->learnable);
    use(p, pfe, b, len);
    CHECK(pfe->radix_req == first);
    /* recycle: released before the shell goes on the freelist */
    pfe_radix_req_release(pfe);
    CHECK(pfe->radix_req == NULL);
    /* pop: the clear finds nothing to free */
    pfe_clear(pfe);
    CHECK(pfe->radix_req == NULL);
  }
  /* the decided mark: decide, a park's wake decides again (counted once);
   * message begin; the next request is counted again */
  {
    uint64_t m0 = misses(p);
    CHECK(offsetof(proxy_fd_ent_t, radix_decided) < PFE_SKIP_OFF);
    use_marked(p, pfe, b, len);
    CHECK(pfe->radix_decided == 1 && misses(p) == m0 + 1);
    use_marked(p, pfe, b, len);                /* the wake */
    CHECK(misses(p) == m0 + 1);
    radix_req_reset(pfe->radix_req);           /* message begin */
    pfe->radix_decided = 0;
    use_marked(p, pfe, b, len);
    CHECK(pfe->radix_decided == 1 && misses(p) == m0 + 2);
    pfe_radix_req_release(pfe);
    pfe_clear(pfe);
    CHECK(pfe->radix_decided == 0);
  }

  /* a release of a shell that never met a radix pool is a no-op */
  pfe_radix_req_release(pfe);
  CHECK(pfe->radix_req == NULL);

  radix_pool_free(p);
  free(b);
  free(pfe);
  printf("test_radix_pfe: %s (%d failed checks)\n", fails ? "FAIL" : "PASS", fails);
  return fails ? 1 : 0;
}
