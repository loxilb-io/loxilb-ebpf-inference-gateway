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
 * loxilb_kv_bufpool_stub.c -- malloc-based fallback buffer pool.
 *
 * Same API as loxilb_kv_bufpool.c but uses calloc instead of
 * mmap/MAP_HUGETLB. Thread-safe via same atomic bitmap pattern.
 * No DOCA dependency. Works on any platform.
 */

#include "loxilb_kv.h"

#include <stdlib.h>
#include <string.h>

int llb_kv_bufpool_init(llb_kv_bufpool_t *pool, size_t pool_size,
                        size_t slot_size, int use_hugepages,
                        void *doca_dev)
{
    (void)use_hugepages;  /* ignored in stub */
    (void)doca_dev;

    if (!pool || !pool_size || !slot_size)
        return LLB_KV_ERR_BOUNDS;

    uint32_t num_slots = (uint32_t)(pool_size / slot_size);
    if (num_slots == 0 || num_slots > 64)
        return LLB_KV_ERR_BOUNDS;

    memset(pool, 0, sizeof(*pool));
    pool->pool_size = pool_size;
    pool->slot_size = slot_size;
    pool->num_slots = num_slots;
    pool->hugepage = 0;
    pool->doca_mmap = NULL;

    pool->base = calloc(1, pool_size);
    if (!pool->base)
        return LLB_KV_ERR_NOMEM;

    /* All slots free: bits [0..num_slots-1] = 1 */
    atomic_store(&pool->free_bitmap,
                 (num_slots == 64) ? ~(uint64_t)0
                                   : ((uint64_t)1 << num_slots) - 1);

    return LLB_KV_OK;
}

int llb_kv_bufpool_alloc(llb_kv_bufpool_t *pool)
{
    uint64_t old, new_map;

    do {
        old = atomic_load(&pool->free_bitmap);
        if (!old)
            return -1;  /* all slots in use */
        int idx = __builtin_ctzll(old);
        new_map = old & ~((uint64_t)1 << idx);
    } while (!atomic_compare_exchange_weak(&pool->free_bitmap, &old, new_map));

    return __builtin_ctzll(old ^ new_map);
}

void llb_kv_bufpool_free(llb_kv_bufpool_t *pool, int slot_idx)
{
    if (!pool || slot_idx < 0 || (uint32_t)slot_idx >= pool->num_slots)
        return;

    atomic_fetch_or(&pool->free_bitmap, (uint64_t)1 << slot_idx);
}

void *llb_kv_bufpool_slot_ptr(llb_kv_bufpool_t *pool, int slot_idx)
{
    if (!pool || slot_idx < 0 || (uint32_t)slot_idx >= pool->num_slots)
        return NULL;

    return (char *)pool->base + ((size_t)slot_idx * pool->slot_size);
}

void llb_kv_bufpool_destroy(llb_kv_bufpool_t *pool)
{
    if (!pool)
        return;

    free(pool->base);
    memset(pool, 0, sizeof(*pool));
}
