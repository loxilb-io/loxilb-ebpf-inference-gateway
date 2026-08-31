/* test_pd_ids.c - Unit tests for the generated engine wire IDs
 * (sockproxy_pd_ids.h) and the strict kv_engine_type -> dialect resolution
 * in sockproxy_pd_core.c: an unknown wire value must map to
 * PD_ENGINE_INVALID and resolve to NO dialect table (never default to the
 * vLLM machine).
 *
 * Build: gcc -Wall -Wextra -ffunction-sections -fdata-sections \
 *   -Wl,--gc-sections -o test_pd_ids test_pd_ids.c -I. -DTEST_PD_IDS
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>

/* The real mapper/resolver are compiled in by including the source (the
 * repo's standalone C-unit pattern, cf. test_pd_rewriter.c). Only the two
 * functions under test are referenced; --gc-sections drops the rest, and
 * the dialect ops tables the resolver returns are satisfied by the dummy
 * definitions below (their identity, not their content, is under test). */
#include "sockproxy_pd_core.c"

const pd_dialect_ops_t pd_dialect_vllm = {0};
const pd_dialect_ops_t pd_dialect_sglang = {0};
const pd_dialect_ops_t pd_dialect_trtllm = {0};

static int failures = 0;

#define CHECK(cond, name) do {                          \
    if (cond) {                                         \
      printf("PASS: %s\n", name);                       \
    } else {                                            \
      printf("FAIL: %s\n", name);                       \
      failures++;                                       \
    }                                                   \
  } while (0)

int
main(void)
{
  /* Generated-header sanity: the ABI-frozen IDs and the sentinel. */
  CHECK(PD_ENGINE_VLLM == 0 && PD_ENGINE_SGLANG == 1 && PD_ENGINE_TRTLLM == 2,
        "generated IDs keep the ABI-frozen numbering");
  CHECK(PD_ENGINE_ID_MAX == 2, "PD_ENGINE_ID_MAX covers the generated set");
  CHECK(PD_ENGINE_INVALID > PD_ENGINE_ID_MAX,
        "invalid sentinel is outside the generated ID range");

  /* Mapper: known wire values pass through. */
  CHECK(pd_engine_from_kv_engine_type(PD_ENGINE_VLLM) == PD_ENGINE_VLLM,
        "mapper: vllm wire value maps to vllm");
  CHECK(pd_engine_from_kv_engine_type(PD_ENGINE_SGLANG) == PD_ENGINE_SGLANG,
        "mapper: sglang wire value maps to sglang");
  CHECK(pd_engine_from_kv_engine_type(PD_ENGINE_TRTLLM) == PD_ENGINE_TRTLLM,
        "mapper: trtllm wire value maps to trtllm");

  /* Mapper: STRICT on unknowns — never a silent vLLM degrade. */
  CHECK(pd_engine_from_kv_engine_type(PD_ENGINE_ID_MAX + 1) == PD_ENGINE_INVALID,
        "mapper: first unknown wire value maps to INVALID");
  CHECK(pd_engine_from_kv_engine_type(7) == PD_ENGINE_INVALID,
        "mapper: arbitrary unknown wire value maps to INVALID");
  CHECK(pd_engine_from_kv_engine_type(0xFE) == PD_ENGINE_INVALID,
        "mapper: high unknown wire value maps to INVALID");
  CHECK(pd_engine_from_kv_engine_type(PD_ENGINE_INVALID) == PD_ENGINE_INVALID,
        "mapper: the sentinel itself stays INVALID");

  /* Resolver: known engines return exactly their own ops table. */
  CHECK(pd_dialect_resolve(PD_ENGINE_VLLM) == &pd_dialect_vllm,
        "resolve: vllm returns the vllm dialect");
  CHECK(pd_dialect_resolve(PD_ENGINE_SGLANG) == &pd_dialect_sglang,
        "resolve: sglang returns the sglang dialect");
  CHECK(pd_dialect_resolve(PD_ENGINE_TRTLLM) == &pd_dialect_trtllm,
        "resolve: trtllm returns the trtllm dialect");

  /* Resolver: STRICT on unknowns — NULL, so P/D orchestration cannot run
   * a dialect nobody declared. */
  CHECK(pd_dialect_resolve(PD_ENGINE_INVALID) == NULL,
        "resolve: INVALID sentinel resolves to no dialect");
  CHECK(pd_dialect_resolve(PD_ENGINE_ID_MAX + 1) == NULL,
        "resolve: unknown engine resolves to no dialect");
  CHECK(pd_dialect_resolve(0x7F) == NULL,
        "resolve: arbitrary unknown engine resolves to no dialect");

  if (failures) {
    printf("test_pd_ids: %d FAILURE(S)\n", failures);
    return 1;
  }
  printf("test_pd_ids: ALL PASS\n");
  return 0;
}
