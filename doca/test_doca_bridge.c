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
 * test_doca_bridge.c -- Standalone C test for loxilb_doca_flow bridge API.
 *
 * Tests the complete lifecycle: init -> pipe create -> entry add ->
 * entry query -> entry remove -> pipe destroy -> shutdown.
 *
 * Run on BF2 only:
 *   BF2_PCI_ADDR=0000:03:00.0 ./test_doca_bridge
 *
 * Exit code = number of failures (0 = all passed).
 */

#include "loxilb_doca_flow.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

static int g_pass = 0;
static int g_fail = 0;

#define TEST_PASS(step, fmt, ...) do { \
    printf("STEP %d: PASS -- " fmt "\n", step, ##__VA_ARGS__); \
    g_pass++; \
} while (0)

#define TEST_FAIL(step, fmt, ...) do { \
    printf("STEP %d: FAIL -- " fmt "\n", step, ##__VA_ARGS__); \
    g_fail++; \
} while (0)

int main(void)
{
    const char *pci_addr = getenv("BF2_PCI_ADDR");
    if (!pci_addr || !*pci_addr)
        pci_addr = "0000:03:00.0";

    printf("============================================\n");
    printf("test_doca_bridge: LoxiLB DOCA Flow Bridge Test\n");
    printf("  PCI: %s\n", pci_addr);
    printf("============================================\n\n");

    int rc;

    /* Step 1: Init */
    llb_doca_config cfg = {
        .ct_pipe_capacity = 256,
        .snat_pipe_capacity = 128,
        .num_repr = 2,
    };
    rc = llb_doca_init(pci_addr, 1, &cfg);  /* no-huge mode */
    if (rc != LLB_DOCA_OK) {
        TEST_FAIL(1, "llb_doca_init returned %d", rc);
        printf("\nResults: %d passed, %d failed\n", g_pass, g_fail);
        return g_fail;
    }
    TEST_PASS(1, "llb_doca_init succeeded");

    /* Step 2: Check initialized */
    if (!llb_doca_is_initialized()) {
        TEST_FAIL(2, "llb_doca_is_initialized returned 0 after init");
    } else {
        TEST_PASS(2, "llb_doca_is_initialized returned non-zero");
    }

    /* Step 3: Get port ID */
    int port_id = llb_doca_get_port_id();
    if (port_id < 0) {
        TEST_FAIL(3, "llb_doca_get_port_id returned %d", port_id);
    } else {
        TEST_PASS(3, "llb_doca_get_port_id = %d", port_id);
    }

    /* Step 4: Get port MAC */
    uint8_t mac[6] = {0};
    rc = llb_doca_get_port_mac(mac);
    if (rc != LLB_DOCA_OK) {
        TEST_FAIL(4, "llb_doca_get_port_mac returned %d", rc);
    } else {
        TEST_PASS(4, "port MAC = %02x:%02x:%02x:%02x:%02x:%02x",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }

    /* Step 5: Create BASIC pipe */
    llb_doca_pipe_handle_t basic_pipe = llb_doca_pipe_create_basic(
        "test_basic",
        UINT32_MAX,   /* exact dst_ip match */
        UINT16_MAX,   /* exact dst_port match */
        0,            /* src_ip: wildcard (no src match) */
        0,            /* src_port: wildcard */
        6,            /* IPPROTO_TCP */
        LLB_DOCA_FWD_PORT,
        0,            /* fwd_port_id */
        256);         /* nr_entries */
    if (!basic_pipe) {
        TEST_FAIL(5, "llb_doca_pipe_create_basic returned NULL");
        goto skip_basic;
    }
    TEST_PASS(5, "BASIC pipe created");

    /* Step 6: Add BASIC entry */
    {
        uint32_t dst_ip = htonl(0xCB007164);    /* 203.0.113.100 */
        uint16_t dst_port = htons(80);
        uint32_t new_ip = htonl(0xC633640A);    /* 198.51.100.10 */
        uint16_t new_port = htons(8080);

        uint8_t zero_mac[6] = {0};
        /* Pre-existing technical debt: this test still uses the legacy
         * pre-Phase-35 / pre-Phase-38 short signature. Adding the recent
 * trailing params (aging_sec, user_ctx, meter_id) plus the 
         * paired-steer out-param keeps test_doca_bridge in lockstep with the
         * production header so `make test_bridge` still compiles. */
        llb_doca_entry_handle_t entry = llb_doca_entry_add_basic(
            basic_pipe,
            dst_ip, dst_port,     /* match dst */
            0, 0,                 /* match src (0=don't match) */
            new_ip, new_port,     /* new dst (DNAT rewrite) */
            0, 0,                 /* new src (no SNAT rewrite) */
            zero_mac, zero_mac,   /* dst/src MAC (no rewrite) */
            5000,                 /* timeout_ms */
            6,                    /* match_proto: IPPROTO_TCP */
            0,                    /* fwd_port_id: 0 (default) */
            0,                    /* aging_sec: 0 (no DOCA aging in this test) */
            0,                    /* user_ctx: 0 (test does not exercise aging) */
            0xFFFFFFFF,           /* meter_id: LLB_DOCA_METER_NONE */
            NULL);                /* P2: out_es_entry — test does not exercise paired steer */
        if (!entry) {
            TEST_FAIL(6, "llb_doca_entry_add_basic returned NULL");
            goto destroy_basic;
        }
        TEST_PASS(6, "BASIC entry added (203.0.113.100:80 -> 198.51.100.10:8080)");

        /* Step 7: Query entry stats */
        uint64_t bytes = 0, pkts = 0;
        rc = llb_doca_entry_query(entry, &bytes, &pkts);
        if (rc != LLB_DOCA_OK) {
            TEST_FAIL(7, "llb_doca_entry_query returned %d", rc);
        } else {
            TEST_PASS(7, "entry stats: bytes=%llu pkts=%llu",
                      (unsigned long long)bytes, (unsigned long long)pkts);
        }

        /* Step 8: Remove entry */
        rc = llb_doca_entry_remove(basic_pipe, entry, 5000);
        if (rc != LLB_DOCA_OK) {
            TEST_FAIL(8, "llb_doca_entry_remove returned %d", rc);
        } else {
            TEST_PASS(8, "BASIC entry removed");
        }
    }

destroy_basic:
    /* Step 9: Destroy BASIC pipe */
    rc = llb_doca_pipe_destroy(basic_pipe);
    if (rc != LLB_DOCA_OK) {
        TEST_FAIL(9, "llb_doca_pipe_destroy returned %d", rc);
    } else {
        TEST_PASS(9, "BASIC pipe destroyed");
    }

skip_basic:
    /* Step 10: Shutdown */
    llb_doca_shutdown();
    if (llb_doca_is_initialized()) {
        TEST_FAIL(10, "llb_doca_is_initialized still returns non-zero after shutdown");
    } else {
        TEST_PASS(10, "llb_doca_shutdown succeeded");
    }

    printf("\n============================================\n");
    printf("Results: %d passed, %d failed\n", g_pass, g_fail);
    printf("============================================\n");

    return g_fail;
}
