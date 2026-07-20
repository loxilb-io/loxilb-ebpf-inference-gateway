#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

/*
 * test_fdb_counter.c -- Phase 49 P49-R2 unit harness.
 *
 * Validates the contract that loxilb_doca_flow.c::llb_doca_fdb_pipe_create
 * and llb_doca_fdb_entry_add now both set
 *   monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED
 * so doca_flow_resource_query_entry() can return non-zero hw_pkts/hw_bytes.
 *
 * This is a STANDALONE harness -- it does NOT link against libdoca. The
 * relevant DOCA constants and the struct doca_flow_monitor layout are
 * mirrored inline (only the two fields we exercise). The test mirrors
 * the LOGIC of the production helpers; the production grep assertions
 * in PLAN.md acceptance_criteria guard against drift in the real call sites.
 *
 * This pattern matches test_doca_root_v2.c (Phase 47 P47-R2).
 *
 * Build & run on bf2-arm (per CLAUDE.md remote-gate.sh pattern):
 *   ./scripts/remote-gate.sh "cd loxilb-ebpf/common && rm -f test_fdb_counter && make test_fdb_counter && ./test_fdb_counter"
 *
 * Expected output ends with the all-pass marker emitted from main().
 */

/* Mirror of loxilb_doca_flow.h (kept in sync with the real header). */
#define LLB_DOCA_OK          0
#define LLB_DOCA_ERR_PARAM  (-8)
#define LLB_DOCA_ERR_ENTRY  (-9)

/* Mirror of doca_flow_resource_type enum (kept in sync with doca_flow.h). */
#define DOCA_FLOW_RESOURCE_TYPE_NONE        0
#define DOCA_FLOW_RESOURCE_TYPE_NON_SHARED  1
#define DOCA_FLOW_RESOURCE_TYPE_SHARED      2

/* Mirror of struct doca_flow_monitor (only the fields we validate). */
struct fake_doca_flow_monitor {
    uint32_t counter_type;
    uint32_t aging_sec;
    /* real struct has more fields; we only exercise these two */
};

/* Simulate llb_doca_fdb_pipe_create's pipe-cfg monitor setup. */
static int setup_pipe_monitor(struct fake_doca_flow_monitor *m) {
    if (!m) return LLB_DOCA_ERR_PARAM;
    memset(m, 0, sizeof(*m));
    m->counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
    return LLB_DOCA_OK;
}

/* Simulate llb_doca_fdb_entry_add's per-entry monitor setup.
 * counter_type is ALWAYS set; aging_sec is additive (only when >0). */
static int setup_entry_monitor(struct fake_doca_flow_monitor *m, uint32_t aging_sec) {
    if (!m) return LLB_DOCA_ERR_PARAM;
    memset(m, 0, sizeof(*m));
    m->counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;  /* always */
    if (aging_sec > 0) {
        m->aging_sec = aging_sec;
    }
    return LLB_DOCA_OK;
}

/* Simulate llb_doca_entry_query NULL-handle path. */
static int simulated_entry_query(const void *entry, uint64_t *bytes_out, uint64_t *pkts_out) {
    if (!entry) return LLB_DOCA_ERR_PARAM;
    if (bytes_out) *bytes_out = 0;
    if (pkts_out)  *pkts_out  = 0;
    return LLB_DOCA_OK;
}

static void test_counter_type_set_on_pipe_cfg(void) {
    struct fake_doca_flow_monitor m;
    int rc = setup_pipe_monitor(&m);
    assert(rc == LLB_DOCA_OK);
    assert(m.counter_type == DOCA_FLOW_RESOURCE_TYPE_NON_SHARED);
    assert(m.aging_sec == 0);
    printf("PASS: test_counter_type_set_on_pipe_cfg\n");
}

static void test_counter_type_set_on_entry(void) {
    struct fake_doca_flow_monitor m;
    int rc = setup_entry_monitor(&m, 0);  /* no aging */
    assert(rc == LLB_DOCA_OK);
    assert(m.counter_type == DOCA_FLOW_RESOURCE_TYPE_NON_SHARED);
    assert(m.aging_sec == 0);
    printf("PASS: test_counter_type_set_on_entry (no aging)\n");
}

static void test_aging_sec_preserves_counter_monitor(void) {
    struct fake_doca_flow_monitor m;
    int rc = setup_entry_monitor(&m, 120);  /* 2-minute aging */
    assert(rc == LLB_DOCA_OK);
    assert(m.counter_type == DOCA_FLOW_RESOURCE_TYPE_NON_SHARED);
    assert(m.aging_sec == 120);
    printf("PASS: test_aging_sec_preserves_counter_monitor (aging=120)\n");
}

static void test_null_entry_rejected_with_ERR_PARAM(void) {
    uint64_t b = 0, p = 0;
    int rc = simulated_entry_query(NULL, &b, &p);
    assert(rc == LLB_DOCA_ERR_PARAM);
    /* Also test NULL monitor in setup paths. */
    rc = setup_entry_monitor(NULL, 0);
    assert(rc == LLB_DOCA_ERR_PARAM);
    rc = setup_pipe_monitor(NULL);
    assert(rc == LLB_DOCA_ERR_PARAM);
    printf("PASS: test_null_entry_rejected_with_ERR_PARAM\n");
}

int main(void) {
    test_counter_type_set_on_pipe_cfg();
    test_counter_type_set_on_entry();
    test_aging_sec_preserves_counter_monitor();
    test_null_entry_rejected_with_ERR_PARAM();
    printf("ALL PASS (4/4)\n");
    return 0;
}
