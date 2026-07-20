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
 * test_kv_ring.c -- Unit tests for SPMC lockfree ring buffer.
 *
 * Tests:
 *   1. Init with valid/invalid capacity
 *   2. Push/pop data integrity
 *   3. Full ring backpressure
 *   4. Empty ring returns -1
 *   5. Wraparound correctness
 *   6. Multi-consumer concurrent pop (2 threads)
 *
 * Build: gcc -Wall -Werror -g -o test_kv_ring test_kv_ring.c loxilb_kv_ring.c -lpthread
 * Run:   ./test_kv_ring
 */

#include "loxilb_kv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

/* ------------------------------------------------------------------ */
/* Test assertion macro                                                */
/* ------------------------------------------------------------------ */

#define ASSERT(x) do {                                            \
    if (!(x)) {                                                   \
        fprintf(stderr, "FAIL: %s:%d: %s\n",                     \
                __FILE__, __LINE__, #x);                          \
        return 1;                                                 \
    }                                                             \
} while (0)

/* ------------------------------------------------------------------ */
/* Test 1: Init with valid/invalid capacity                            */
/* ------------------------------------------------------------------ */

static int test_ring_init(void)
{
    printf("  test_ring_init ... ");
    llb_kv_ring_t r;

    /* Power-of-2 capacity should succeed */
    ASSERT(llb_kv_ring_init(&r, 128) == LLB_KV_OK);
    ASSERT(r.capacity == 128);
    ASSERT(r.elems != NULL);
    llb_kv_ring_destroy(&r);

    /* Non-power-of-2 should fail */
    ASSERT(llb_kv_ring_init(&r, 100) == LLB_KV_ERR_BOUNDS);

    /* Zero should fail */
    ASSERT(llb_kv_ring_init(&r, 0) == LLB_KV_ERR_BOUNDS);

    printf("PASS\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test 2: Push/pop data integrity                                     */
/* ------------------------------------------------------------------ */

static int test_ring_push_pop(void)
{
    printf("  test_ring_push_pop ... ");
    llb_kv_ring_t r;
    ASSERT(llb_kv_ring_init(&r, 128) == LLB_KV_OK);

    /* Push 5 elements */
    for (uint32_t i = 0; i < 5; i++) {
        llb_kv_ring_elem_t e = { .slot_idx = i, .data_len = i * 100,
                                 .session_id = 0xDEAD0000 + i };
        ASSERT(llb_kv_ring_push(&r, &e) == 0);
    }

    /* Pop 5 elements, verify data */
    for (uint32_t i = 0; i < 5; i++) {
        llb_kv_ring_elem_t e;
        ASSERT(llb_kv_ring_pop(&r, &e) == 0);
        ASSERT(e.slot_idx == i);
        ASSERT(e.data_len == i * 100);
        ASSERT(e.session_id == 0xDEAD0000 + i);
    }

    llb_kv_ring_destroy(&r);
    printf("PASS\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test 3: Full ring backpressure                                      */
/* ------------------------------------------------------------------ */

static int test_ring_full(void)
{
    printf("  test_ring_full ... ");
    llb_kv_ring_t r;
    ASSERT(llb_kv_ring_init(&r, 8) == LLB_KV_OK);

    /* Fill to capacity */
    for (uint32_t i = 0; i < 8; i++) {
        llb_kv_ring_elem_t e = { .slot_idx = i, .data_len = 0, .session_id = 0 };
        ASSERT(llb_kv_ring_push(&r, &e) == 0);
    }

    /* Next push should return -1 */
    llb_kv_ring_elem_t e = { .slot_idx = 99, .data_len = 0, .session_id = 0 };
    ASSERT(llb_kv_ring_push(&r, &e) == -1);

    llb_kv_ring_destroy(&r);
    printf("PASS\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test 4: Empty ring returns -1                                       */
/* ------------------------------------------------------------------ */

static int test_ring_empty(void)
{
    printf("  test_ring_empty ... ");
    llb_kv_ring_t r;
    ASSERT(llb_kv_ring_init(&r, 8) == LLB_KV_OK);

    llb_kv_ring_elem_t e;
    ASSERT(llb_kv_ring_pop(&r, &e) == -1);

    llb_kv_ring_destroy(&r);
    printf("PASS\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test 5: Wraparound correctness                                      */
/* ------------------------------------------------------------------ */

static int test_ring_wraparound(void)
{
    printf("  test_ring_wraparound ... ");
    llb_kv_ring_t r;
    ASSERT(llb_kv_ring_init(&r, 8) == LLB_KV_OK);

    /* Fill and drain to advance head/tail past capacity */
    for (int round = 0; round < 4; round++) {
        for (uint32_t i = 0; i < 8; i++) {
            llb_kv_ring_elem_t e = { .slot_idx = round * 8 + i,
                                     .data_len = 0, .session_id = 0 };
            ASSERT(llb_kv_ring_push(&r, &e) == 0);
        }
        for (uint32_t i = 0; i < 8; i++) {
            llb_kv_ring_elem_t e;
            ASSERT(llb_kv_ring_pop(&r, &e) == 0);
            ASSERT(e.slot_idx == (uint32_t)(round * 8 + i));
        }
    }

    llb_kv_ring_destroy(&r);
    printf("PASS\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test 6: Multi-consumer concurrent pop (2 threads)                   */
/* ------------------------------------------------------------------ */

#define MC_TOTAL_ELEMS 100

typedef struct {
    llb_kv_ring_t *ring;
    uint8_t        seen[MC_TOTAL_ELEMS];
    int            count;
} mc_thread_arg_t;

static void *mc_consumer(void *arg)
{
    mc_thread_arg_t *a = (mc_thread_arg_t *)arg;
    llb_kv_ring_elem_t e;
    int empty_streak = 0;

    while (a->count < MC_TOTAL_ELEMS && empty_streak < 100000) {
        if (llb_kv_ring_pop(a->ring, &e) == 0) {
            if (e.slot_idx < MC_TOTAL_ELEMS) {
                __atomic_fetch_add(&a->seen[e.slot_idx], 1, __ATOMIC_RELAXED);
                __atomic_fetch_add(&a->count, 1, __ATOMIC_RELAXED);
            }
            empty_streak = 0;
        } else {
            empty_streak++;
        }
    }
    return NULL;
}

static int test_ring_multi_consumer(void)
{
    printf("  test_ring_multi_consumer ... ");
    llb_kv_ring_t r;
    ASSERT(llb_kv_ring_init(&r, 128) == LLB_KV_OK);

    mc_thread_arg_t shared;
    memset(&shared, 0, sizeof(shared));
    shared.ring = &r;

    /* Push all elements first (single producer) */
    for (uint32_t i = 0; i < MC_TOTAL_ELEMS; i++) {
        llb_kv_ring_elem_t e = { .slot_idx = i, .data_len = 0, .session_id = i };
        ASSERT(llb_kv_ring_push(&r, &e) == 0);
    }

    /* 2 consumer threads */
    pthread_t t1, t2;
    pthread_create(&t1, NULL, mc_consumer, &shared);
    pthread_create(&t2, NULL, mc_consumer, &shared);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    /* Verify all 100 popped exactly once */
    ASSERT(shared.count == MC_TOTAL_ELEMS);
    for (int i = 0; i < MC_TOTAL_ELEMS; i++) {
        ASSERT(shared.seen[i] == 1);
    }

    llb_kv_ring_destroy(&r);
    printf("PASS\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

int main(void)
{
    printf("=== test_kv_ring ===\n");
    int fail = 0;

    fail |= test_ring_init();
    fail |= test_ring_push_pop();
    fail |= test_ring_full();
    fail |= test_ring_empty();
    fail |= test_ring_wraparound();
    fail |= test_ring_multi_consumer();

    if (fail) {
        printf("SOME TESTS FAILED\n");
        return 1;
    }
    printf("All ring tests passed\n");
    return 0;
}
