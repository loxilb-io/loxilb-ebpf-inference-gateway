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
 * test_kv_bufpool.c -- Unit tests for buffer pool with atomic bitmap.
 *
 * Tests:
 *   1. Init with valid parameters
 *   2. Allocate all 64 slots, next returns -1
 *   3. Free and reuse slot
 *   4. Slot pointer arithmetic
 *   5. Double-free idempotency
 *   6. Concurrent alloc (2 threads)
 *
 * Uses stub (malloc-based) so tests work on any platform.
 *
 * Build: gcc -Wall -Werror -g -o test_kv_bufpool test_kv_bufpool.c loxilb_kv_bufpool_stub.c -lpthread
 * Run:   ./test_kv_bufpool
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
/* Test 1: Init with valid parameters                                  */
/* ------------------------------------------------------------------ */

static int test_bufpool_init(void)
{
    printf("  test_bufpool_init ... ");
    llb_kv_bufpool_t pool;

    /* 64 slots x 4096 bytes = 256KB pool */
    size_t slot_size = 4096;
    size_t pool_size = 64 * slot_size;
    ASSERT(llb_kv_bufpool_init(&pool, pool_size, slot_size, 0, NULL) == LLB_KV_OK);
    ASSERT(pool.num_slots == 64);
    ASSERT(pool.base != NULL);
    ASSERT(pool.hugepage == 0);  /* stub never uses hugepages */
    llb_kv_bufpool_destroy(&pool);

    /* Invalid: zero pool_size */
    ASSERT(llb_kv_bufpool_init(&pool, 0, slot_size, 0, NULL) == LLB_KV_ERR_BOUNDS);

    /* Invalid: more than 64 slots */
    ASSERT(llb_kv_bufpool_init(&pool, 65 * slot_size, slot_size, 0, NULL) == LLB_KV_ERR_BOUNDS);

    printf("PASS\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test 2: Allocate all 64 slots, next returns -1                      */
/* ------------------------------------------------------------------ */

static int test_bufpool_alloc_all(void)
{
    printf("  test_bufpool_alloc_all ... ");
    llb_kv_bufpool_t pool;
    size_t slot_size = 4096;
    size_t pool_size = 64 * slot_size;
    ASSERT(llb_kv_bufpool_init(&pool, pool_size, slot_size, 0, NULL) == LLB_KV_OK);

    uint8_t seen[64];
    memset(seen, 0, sizeof(seen));

    for (int i = 0; i < 64; i++) {
        int idx = llb_kv_bufpool_alloc(&pool);
        ASSERT(idx >= 0 && idx < 64);
        ASSERT(seen[idx] == 0);  /* no duplicate */
        seen[idx] = 1;
    }

    /* Next alloc should fail */
    ASSERT(llb_kv_bufpool_alloc(&pool) == -1);

    llb_kv_bufpool_destroy(&pool);
    printf("PASS\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test 3: Free and reuse slot                                         */
/* ------------------------------------------------------------------ */

static int test_bufpool_free_reuse(void)
{
    printf("  test_bufpool_free_reuse ... ");
    llb_kv_bufpool_t pool;
    size_t slot_size = 4096;
    size_t pool_size = 4 * slot_size;
    ASSERT(llb_kv_bufpool_init(&pool, pool_size, slot_size, 0, NULL) == LLB_KV_OK);

    int idx1 = llb_kv_bufpool_alloc(&pool);
    ASSERT(idx1 >= 0);

    /* Free it */
    llb_kv_bufpool_free(&pool, idx1);

    /* Allocate again -- should get same slot (lowest bit) */
    int idx2 = llb_kv_bufpool_alloc(&pool);
    ASSERT(idx2 == idx1);

    llb_kv_bufpool_destroy(&pool);
    printf("PASS\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test 4: Slot pointer arithmetic                                     */
/* ------------------------------------------------------------------ */

static int test_bufpool_slot_ptr(void)
{
    printf("  test_bufpool_slot_ptr ... ");
    llb_kv_bufpool_t pool;
    size_t slot_size = 4096;
    size_t pool_size = 4 * slot_size;
    ASSERT(llb_kv_bufpool_init(&pool, pool_size, slot_size, 0, NULL) == LLB_KV_OK);

    /* Slot 0 = base */
    ASSERT(llb_kv_bufpool_slot_ptr(&pool, 0) == pool.base);

    /* Slot 1 = base + slot_size */
    ASSERT(llb_kv_bufpool_slot_ptr(&pool, 1) ==
           (char *)pool.base + slot_size);

    /* Out of bounds */
    ASSERT(llb_kv_bufpool_slot_ptr(&pool, 99) == NULL);
    ASSERT(llb_kv_bufpool_slot_ptr(&pool, -1) == NULL);

    llb_kv_bufpool_destroy(&pool);
    printf("PASS\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test 5: Double-free idempotency                                     */
/* ------------------------------------------------------------------ */

static int test_bufpool_double_free(void)
{
    printf("  test_bufpool_double_free ... ");
    llb_kv_bufpool_t pool;
    size_t slot_size = 4096;
    size_t pool_size = 4 * slot_size;
    ASSERT(llb_kv_bufpool_init(&pool, pool_size, slot_size, 0, NULL) == LLB_KV_OK);

    int idx = llb_kv_bufpool_alloc(&pool);
    ASSERT(idx >= 0);

    /* Free once */
    llb_kv_bufpool_free(&pool, idx);
    uint64_t bm_after_first = atomic_load(&pool.free_bitmap);
    ASSERT(bm_after_first & ((uint64_t)1 << idx));

    /* Free again -- bitmap should be unchanged (idempotent OR) */
    llb_kv_bufpool_free(&pool, idx);
    uint64_t bm_after_second = atomic_load(&pool.free_bitmap);
    ASSERT(bm_after_second == bm_after_first);

    llb_kv_bufpool_destroy(&pool);
    printf("PASS\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test 6: Concurrent alloc (2 threads)                                */
/* ------------------------------------------------------------------ */

#define CONC_NUM_SLOTS 64

typedef struct {
    llb_kv_bufpool_t *pool;
    int               indices[CONC_NUM_SLOTS];
    int               count;
} conc_thread_arg_t;

static void *conc_allocator(void *arg)
{
    conc_thread_arg_t *a = (conc_thread_arg_t *)arg;
    for (;;) {
        int idx = llb_kv_bufpool_alloc(a->pool);
        if (idx < 0)
            break;
        int pos = __atomic_fetch_add(&a->count, 1, __ATOMIC_RELAXED);
        a->indices[pos] = idx;
    }
    return NULL;
}

static int test_bufpool_concurrent_alloc(void)
{
    printf("  test_bufpool_concurrent_alloc ... ");
    llb_kv_bufpool_t pool;
    size_t slot_size = 4096;
    size_t pool_size = CONC_NUM_SLOTS * slot_size;
    ASSERT(llb_kv_bufpool_init(&pool, pool_size, slot_size, 0, NULL) == LLB_KV_OK);

    conc_thread_arg_t shared;
    memset(&shared, 0, sizeof(shared));
    shared.pool = &pool;

    pthread_t t1, t2;
    pthread_create(&t1, NULL, conc_allocator, &shared);
    pthread_create(&t2, NULL, conc_allocator, &shared);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    /* All 64 slots should be allocated, no duplicates */
    ASSERT(shared.count == CONC_NUM_SLOTS);

    uint8_t seen[CONC_NUM_SLOTS];
    memset(seen, 0, sizeof(seen));
    for (int i = 0; i < CONC_NUM_SLOTS; i++) {
        int idx = shared.indices[i];
        ASSERT(idx >= 0 && idx < CONC_NUM_SLOTS);
        ASSERT(seen[idx] == 0);
        seen[idx] = 1;
    }

    llb_kv_bufpool_destroy(&pool);
    printf("PASS\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

int main(void)
{
    printf("=== test_kv_bufpool ===\n");
    int fail = 0;

    fail |= test_bufpool_init();
    fail |= test_bufpool_alloc_all();
    fail |= test_bufpool_free_reuse();
    fail |= test_bufpool_slot_ptr();
    fail |= test_bufpool_double_free();
    fail |= test_bufpool_concurrent_alloc();

    if (fail) {
        printf("SOME TESTS FAILED\n");
        return 1;
    }
    printf("All bufpool tests passed\n");
    return 0;
}
