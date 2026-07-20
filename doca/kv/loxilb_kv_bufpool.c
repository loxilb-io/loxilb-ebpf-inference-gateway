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
 * loxilb_kv_bufpool.c -- Hugepage-backed buffer pool with atomic bitmap
 *                         slot allocator for pre-pinned staging buffers.
 *
 * DOCA build: uses MAP_HUGETLB + mlock for DMA-ready buffers.
 * Thread-safe: CAS-based alloc/free on _Atomic uint64_t bitmap.
 * Max 64 slots (one bit per slot in uint64_t bitmap).
 *
 * The doca_mmap field is set externally by DMA init for dma_src pool.
 */

#include "loxilb_kv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

int llb_kv_bufpool_init(llb_kv_bufpool_t *pool, size_t pool_size,
                        size_t slot_size, int use_hugepages,
                        void *doca_dev)
{
    (void)doca_dev;  /* reserved for future DOCA mmap registration */

    if (!pool || !pool_size || !slot_size)
        return LLB_KV_ERR_BOUNDS;

    uint32_t num_slots = (uint32_t)(pool_size / slot_size);
    if (num_slots == 0 || num_slots > 64)
        return LLB_KV_ERR_BOUNDS;

    memset(pool, 0, sizeof(*pool));
    pool->pool_size = pool_size;
    pool->slot_size = slot_size;
    pool->num_slots = num_slots;

    void *base = MAP_FAILED;

    if (use_hugepages) {
        base = mmap(NULL, pool_size, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
        if (base != MAP_FAILED) {
            pool->hugepage = 1;
        } else {
            fprintf(stderr, "WARNING: MAP_HUGETLB failed, falling back to "
                    "regular mmap. Reserve hugepages with: "
                    "echo N > /proc/sys/vm/nr_hugepages\n");
        }
    }

    if (base == MAP_FAILED) {
        base = mmap(NULL, pool_size, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (base == MAP_FAILED)
            return LLB_KV_ERR_NOMEM;
        pool->hugepage = 0;
    }

    /* Pin pages for DMA readiness */
    if (mlock(base, pool_size) != 0) {
        fprintf(stderr, "WARNING: mlock() failed -- pages may be swapped\n");
    }

    pool->base = base;
    pool->doca_mmap = NULL;  /* set externally by DMA init */

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

    return __builtin_ctzll(old ^ new_map);  /* the cleared bit */
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

    if (pool->base) {
        munlock(pool->base, pool->pool_size);
        munmap(pool->base, pool->pool_size);
    }

    memset(pool, 0, sizeof(*pool));
}
