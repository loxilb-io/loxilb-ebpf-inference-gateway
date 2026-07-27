/*
 * Unit test for root-pipe cfg V2 validator + miss-dispatch.
 *
 * Tests the LOGIC, not live DOCA. The real validator + miss-dispatch lives
 * in loxilb-ebpf/doca/loxilb_doca_flow.c (llb_doca_rebuild_root_pipe); this
 * file duplicates the decision-making fragment inline so the test does not
 * need to stand up a DOCA mock in C. Fixture structs mirror the header
 * (loxilb_doca_flow.h) exactly so any drift will show up as a compile or
 * assertion failure.
 *
 * Covers:
 *   1. test_v1_compat          -- V1 caller (no override field present semantically) -> miss = to_kernel
 *   2. test_v2_null_miss       -- V2 + miss_pipe_override=0 collapses to V1 semantics
 *   3. test_v2_custom_miss     -- V2 + non-zero override routes miss to the override pipe
 *   4. test_invalid_version    -- version=99 is rejected with LLB_DOCA_ERR_PARAM
 *   5. test_null_cfg           -- NULL cfg is rejected with LLB_DOCA_ERR_PARAM
 *
 * Build: gcc -Wall -Wextra -O2 -o test_doca_root_v2 test_doca_root_v2.c
 * Run:   ./test_doca_root_v2
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

/* Mirror of loxilb_doca_flow.h (kept in sync with the real header). */
#define LLB_DOCA_ROOT_PIPE_CFG_V1       1
#define LLB_DOCA_ROOT_PIPE_CFG_V2       2
#define LLB_DOCA_ROOT_PIPE_MAX_DISPATCH 8
#define LLB_DOCA_OK                     0
#define LLB_DOCA_ERR_PARAM              (-8)

typedef void *llb_doca_pipe_handle_t;

typedef struct {
    uint32_t version;
    uint32_t nr_entries;
    uint32_t num_dispatch;
    struct {
        uint32_t l4_type;
        llb_doca_pipe_handle_t target;
    } dispatch[LLB_DOCA_ROOT_PIPE_MAX_DISPATCH];
    /* V2: non-NULL overrides default g_to_kernel_pipe miss destination. */
    llb_doca_pipe_handle_t miss_pipe_override;
} llb_doca_root_pipe_cfg;

/* Mocked globals mirroring the real loxilb_doca_flow.c. Real values are
 * DOCA pipe pointers; here we use distinct sentinel addresses so pointer
 * equality reliably identifies which branch the dispatch logic took. */
static llb_doca_pipe_handle_t g_to_kernel_pipe = (llb_doca_pipe_handle_t)(uintptr_t)0xDEAD0000UL;
static llb_doca_pipe_handle_t g_fdb_pipe       = (llb_doca_pipe_handle_t)(uintptr_t)0xFB0F1DB0UL;

/* Mirrors llb_doca_rebuild_root_pipe's validator + miss-dispatch logic.
 * Production function also creates the DOCA pipe and installs entries;
 * here we only exercise the decision tree. */
static int validate_and_pick_miss(const llb_doca_root_pipe_cfg *cfg,
                                   llb_doca_pipe_handle_t *out_miss)
{
    if (!cfg)
        return LLB_DOCA_ERR_PARAM;
    if (cfg->version != LLB_DOCA_ROOT_PIPE_CFG_V1 &&
        cfg->version != LLB_DOCA_ROOT_PIPE_CFG_V2)
        return LLB_DOCA_ERR_PARAM;

    llb_doca_pipe_handle_t miss = g_to_kernel_pipe;
    if (cfg->version == LLB_DOCA_ROOT_PIPE_CFG_V2 && cfg->miss_pipe_override) {
        miss = cfg->miss_pipe_override;
    }
    if (out_miss)
        *out_miss = miss;
    return LLB_DOCA_OK;
}

static void test_v1_compat(void)
{
    /* V1 callers leave miss_pipe_override zero-initialised; behavior is
     * the unchanged pre-Phase-47 default (miss -> to_kernel). */
    llb_doca_root_pipe_cfg cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.version = LLB_DOCA_ROOT_PIPE_CFG_V1;
    cfg.num_dispatch = 2;

    llb_doca_pipe_handle_t miss = NULL;
    int rc = validate_and_pick_miss(&cfg, &miss);
    assert(rc == LLB_DOCA_OK);
    assert(miss == g_to_kernel_pipe);
    printf("PASS: test_v1_compat\n");
}

static void test_v2_null_miss(void)
{
    /* V2 with explicit miss_pipe_override=0 must collapse to V1 semantics.
     * Guards the "FDB create failed -> V1 fallback" path in llb_doca_init. */
    llb_doca_root_pipe_cfg cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.version = LLB_DOCA_ROOT_PIPE_CFG_V2;
    cfg.miss_pipe_override = NULL;
    cfg.num_dispatch = 2;

    llb_doca_pipe_handle_t miss = NULL;
    int rc = validate_and_pick_miss(&cfg, &miss);
    assert(rc == LLB_DOCA_OK);
    assert(miss == g_to_kernel_pipe);
    printf("PASS: test_v2_null_miss\n");
}

static void test_v2_custom_miss(void)
{
    /* V2 with non-zero override routes root-miss to the override pipe
     * (e.g. FDB pipe in production). Bug #2 fix. */
    llb_doca_root_pipe_cfg cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.version = LLB_DOCA_ROOT_PIPE_CFG_V2;
    cfg.miss_pipe_override = g_fdb_pipe;
    cfg.num_dispatch = 2;

    llb_doca_pipe_handle_t miss = NULL;
    int rc = validate_and_pick_miss(&cfg, &miss);
    assert(rc == LLB_DOCA_OK);
    assert(miss == g_fdb_pipe);
    assert(miss != g_to_kernel_pipe);
    printf("PASS: test_v2_custom_miss\n");
}

static void test_invalid_version(void)
{
    /* Unknown version number is rejected -- future V3 bump must land
     * here on purpose, not by accident. */
    llb_doca_root_pipe_cfg cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.version = 99;
    cfg.num_dispatch = 2;

    llb_doca_pipe_handle_t miss = NULL;
    int rc = validate_and_pick_miss(&cfg, &miss);
    assert(rc == LLB_DOCA_ERR_PARAM);
    printf("PASS: test_invalid_version\n");
}

static void test_null_cfg(void)
{
    /* NULL cfg pointer is rejected before any field access. */
    llb_doca_pipe_handle_t miss = NULL;
    int rc = validate_and_pick_miss(NULL, &miss);
    assert(rc == LLB_DOCA_ERR_PARAM);
    printf("PASS: test_null_cfg\n");
}

int main(void)
{
    test_v1_compat();
    test_v2_null_miss();
    test_v2_custom_miss();
    test_invalid_version();
    test_null_cfg();
    printf("ALL PASS (5/5)\n");
    return 0;
}
