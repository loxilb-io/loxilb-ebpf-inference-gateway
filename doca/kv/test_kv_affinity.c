/*
 * Copyright (c) 2022 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * test_kv_affinity.c -- Unit tests for core affinity parsing,
 *                        validation, auto-detect, and stub behavior.
 *
 * Tests:
 *   1. test_parse_valid: "0,1:2,3,4,5:6,7" -> net={0,1}, deq={2,3,4,5}, ctrl={6,7}
 *   2. test_parse_single_cores: "0:1:2" -> 1/1/1
 *   3. test_parse_invalid_format: "0,1:2,3" (only 2 groups) -> error
 *   4. test_parse_invalid_char: "0,1:a,b:6,7" -> error
 *   5. test_auto_detect: produces valid assignment on current machine
 *   6. test_validate_overlap: cores in multiple groups -> error
 *   7. test_validate_oob: core ID >= online count -> error
 *   8. test_stub_noop: stub parse succeeds, apply is no-op
 *
 * Build: gcc -Wall -Werror -g -o test_kv_affinity test_kv_affinity.c \
 *        loxilb_kv_affinity_stub.c -lpthread
 * Run:   ./test_kv_affinity
 */

#include "loxilb_kv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  TEST %d: %-40s ", tests_run, name); \
} while(0)

#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while(0)

/* ------------------------------------------------------------------ */
/* Test 1: Parse valid 3-group spec                                    */
/* ------------------------------------------------------------------ */
static void test_parse_valid(void)
{
    TEST("parse valid 3-group spec");
    llb_kv_affinity_t aff;
    memset(&aff, 0, sizeof(aff));

    int rc = llb_kv_affinity_parse("0,1:2,3,4,5:6,7", &aff);
    if (rc != LLB_KV_OK) { FAIL("parse returned error"); return; }
    if (aff.net_count != 2) { FAIL("net_count != 2"); return; }
    if (aff.deq_count != 4) { FAIL("deq_count != 4"); return; }
    if (aff.ctrl_count != 2) { FAIL("ctrl_count != 2"); return; }

    /* Verify net IDs */
    if (aff.net_ids[0] != 0 || aff.net_ids[1] != 1) {
        FAIL("net_ids mismatch"); return;
    }
    /* Verify deq IDs */
    if (aff.deq_ids[0] != 2 || aff.deq_ids[1] != 3 ||
        aff.deq_ids[2] != 4 || aff.deq_ids[3] != 5) {
        FAIL("deq_ids mismatch"); return;
    }
    /* Verify ctrl IDs */
    if (aff.ctrl_ids[0] != 6 || aff.ctrl_ids[1] != 7) {
        FAIL("ctrl_ids mismatch"); return;
    }

    /* Verify cpu_set_t membership */
    if (!CPU_ISSET(0, &aff.net_cores) || !CPU_ISSET(1, &aff.net_cores)) {
        FAIL("net_cores cpu_set mismatch"); return;
    }
    if (!CPU_ISSET(2, &aff.deq_cores) || !CPU_ISSET(5, &aff.deq_cores)) {
        FAIL("deq_cores cpu_set mismatch"); return;
    }
    if (!CPU_ISSET(6, &aff.ctrl_cores) || !CPU_ISSET(7, &aff.ctrl_cores)) {
        FAIL("ctrl_cores cpu_set mismatch"); return;
    }

    PASS();
}

/* ------------------------------------------------------------------ */
/* Test 2: Parse single cores per group                                */
/* ------------------------------------------------------------------ */
static void test_parse_single_cores(void)
{
    TEST("parse single cores per group");
    llb_kv_affinity_t aff;
    memset(&aff, 0, sizeof(aff));

    int rc = llb_kv_affinity_parse("0:1:2", &aff);
    if (rc != LLB_KV_OK) { FAIL("parse returned error"); return; }
    if (aff.net_count != 1) { FAIL("net_count != 1"); return; }
    if (aff.deq_count != 1) { FAIL("deq_count != 1"); return; }
    if (aff.ctrl_count != 1) { FAIL("ctrl_count != 1"); return; }
    if (aff.net_ids[0] != 0 || aff.deq_ids[0] != 1 || aff.ctrl_ids[0] != 2) {
        FAIL("ids mismatch"); return;
    }
    PASS();
}

/* ------------------------------------------------------------------ */
/* Test 3: Invalid format (only 2 groups)                              */
/* ------------------------------------------------------------------ */
static void test_parse_invalid_format(void)
{
    TEST("parse invalid format (2 groups)");
    llb_kv_affinity_t aff;
    memset(&aff, 0, sizeof(aff));

    int rc = llb_kv_affinity_parse("0,1:2,3", &aff);
    if (rc != LLB_KV_OK) {
        PASS();
    } else {
        FAIL("expected error for 2 groups");
    }
}

/* ------------------------------------------------------------------ */
/* Test 4: Invalid character in spec                                   */
/* ------------------------------------------------------------------ */
static void test_parse_invalid_char(void)
{
    TEST("parse invalid character");
    llb_kv_affinity_t aff;
    memset(&aff, 0, sizeof(aff));

    int rc = llb_kv_affinity_parse("0,1:a,b:6,7", &aff);
    if (rc != LLB_KV_OK) {
        PASS();
    } else {
        FAIL("expected error for non-numeric");
    }
}

/* ------------------------------------------------------------------ */
/* Test 5: Auto-detect on current machine                              */
/* ------------------------------------------------------------------ */
static void test_auto_detect(void)
{
    int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu < 4) {
        TEST("auto-detect (SKIPPED: <4 cores)");
        printf("SKIP\n");
        tests_run--; /* don't count as run */
        return;
    }

    TEST("auto-detect on current machine");
    llb_kv_affinity_t aff;
    memset(&aff, 0, sizeof(aff));

    int rc = llb_kv_affinity_auto_detect(&aff);
    if (rc != LLB_KV_OK) { FAIL("auto_detect returned error"); return; }
    if (aff.net_count < 1) { FAIL("net_count < 1"); return; }
    if (aff.deq_count < 1) { FAIL("deq_count < 1"); return; }
    if (aff.ctrl_count < 1) { FAIL("ctrl_count < 1"); return; }

    /* Total should equal online CPU count */
    int total = aff.net_count + aff.deq_count + aff.ctrl_count;
    if (total != ncpu) { FAIL("total != ncpu"); return; }

    /* Validate: should pass since auto-detect produces valid assignment */
    rc = llb_kv_affinity_validate(&aff);
    if (rc != LLB_KV_OK) { FAIL("validate failed on auto-detect result"); return; }

    PASS();
}

/* ------------------------------------------------------------------ */
/* Test 6: Validate overlap detection                                  */
/* ------------------------------------------------------------------ */
static void test_validate_overlap(void)
{
    TEST("validate overlap detection");
    llb_kv_affinity_t aff;
    memset(&aff, 0, sizeof(aff));

    /* Manually construct overlapping groups: core 2 in both net and deq */
    CPU_ZERO(&aff.net_cores);
    CPU_SET(0, &aff.net_cores);
    CPU_SET(2, &aff.net_cores);
    aff.net_ids[0] = 0; aff.net_ids[1] = 2; aff.net_count = 2;

    CPU_ZERO(&aff.deq_cores);
    CPU_SET(2, &aff.deq_cores);
    CPU_SET(3, &aff.deq_cores);
    aff.deq_ids[0] = 2; aff.deq_ids[1] = 3; aff.deq_count = 2;

    CPU_ZERO(&aff.ctrl_cores);
    CPU_SET(4, &aff.ctrl_cores);
    aff.ctrl_ids[0] = 4; aff.ctrl_count = 1;

    int rc = llb_kv_affinity_validate(&aff);
    if (rc != LLB_KV_OK) {
        PASS();
    } else {
        FAIL("expected error for overlapping cores");
    }
}

/* ------------------------------------------------------------------ */
/* Test 7: Validate out-of-bounds core ID                              */
/* ------------------------------------------------------------------ */
static void test_validate_oob(void)
{
    TEST("validate out-of-bounds core ID");
    int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
    llb_kv_affinity_t aff;
    memset(&aff, 0, sizeof(aff));

    CPU_ZERO(&aff.net_cores);
    CPU_SET(0, &aff.net_cores);
    aff.net_ids[0] = 0; aff.net_count = 1;

    CPU_ZERO(&aff.deq_cores);
    CPU_SET(1, &aff.deq_cores);
    aff.deq_ids[0] = 1; aff.deq_count = 1;

    /* Use a core ID that's >= online count */
    CPU_ZERO(&aff.ctrl_cores);
    int oob_core = ncpu + 10;
    CPU_SET(oob_core, &aff.ctrl_cores);
    aff.ctrl_ids[0] = oob_core; aff.ctrl_count = 1;

    int rc = llb_kv_affinity_validate(&aff);
    if (rc != LLB_KV_OK) {
        PASS();
    } else {
        FAIL("expected error for OOB core ID");
    }
}

/* ------------------------------------------------------------------ */
/* Test 8: Stub apply is no-op                                         */
/* ------------------------------------------------------------------ */
static void test_stub_noop(void)
{
    TEST("stub apply is no-op");
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);

    /* On stub build, apply should succeed (no-op) */
    int rc = llb_kv_affinity_apply_thread(&cpuset);
    if (rc == 0) {
        PASS();
    } else {
        FAIL("apply_thread returned error");
    }
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */
int main(void)
{
    printf("=== KV Affinity Unit Tests ===\n\n");

    test_parse_valid();
    test_parse_single_cores();
    test_parse_invalid_format();
    test_parse_invalid_char();
    test_auto_detect();
    test_validate_overlap();
    test_validate_oob();
    test_stub_noop();

    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);

    if (tests_passed != tests_run) {
        printf("SOME TESTS FAILED\n");
        return 1;
    }

    printf("ALL TESTS PASSED\n");
    return 0;
}
