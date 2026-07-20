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
 * loxilb_kv_ring.c -- SPMC lockfree ring buffer for inter-stage handoff.
 *
 * Single-producer multi-consumer design:
 *   - push: single producer, relaxed head writes with release fence
 *   - pop: multi-consumer safe via CAS loop on tail
 *
 * Non-blocking: returns -1 on full (push) or empty (pop).
 * POSIX-only (stdatomic.h), no DOCA dependency.
 */

#include "loxilb_kv.h"

#include <stdlib.h>
#include <string.h>

/* Check if n is a power of 2 */
static inline int is_power_of_2(uint32_t n)
{
    return n && !(n & (n - 1));
}

int llb_kv_ring_init(llb_kv_ring_t *r, uint32_t capacity)
{
    if (!r || !is_power_of_2(capacity))
        return LLB_KV_ERR_BOUNDS;

    r->elems = calloc(capacity, sizeof(llb_kv_ring_elem_t));
    if (!r->elems)
        return LLB_KV_ERR_NOMEM;

    r->capacity = capacity;
    atomic_store_explicit(&r->head, 0, memory_order_relaxed);
    atomic_store_explicit(&r->tail, 0, memory_order_relaxed);
    return LLB_KV_OK;
}

int llb_kv_ring_push(llb_kv_ring_t *r, const llb_kv_ring_elem_t *e)
{
    uint64_t h = atomic_load_explicit(&r->head, memory_order_relaxed);
    uint64_t t = atomic_load_explicit(&r->tail, memory_order_acquire);

    if ((h - t) >= r->capacity)
        return -1;  /* full -- backpressure */

    r->elems[h & (r->capacity - 1)] = *e;
    atomic_store_explicit(&r->head, h + 1, memory_order_release);
    return 0;
}

int llb_kv_ring_pop(llb_kv_ring_t *r, llb_kv_ring_elem_t *e)
{
    uint64_t t, h;

    do {
        t = atomic_load_explicit(&r->tail, memory_order_relaxed);
        h = atomic_load_explicit(&r->head, memory_order_acquire);
        if (t == h)
            return -1;  /* empty */
        *e = r->elems[t & (r->capacity - 1)];
    } while (!atomic_compare_exchange_weak_explicit(
        &r->tail, &t, t + 1,
        memory_order_release, memory_order_relaxed));

    return 0;
}

void llb_kv_ring_destroy(llb_kv_ring_t *r)
{
    if (!r)
        return;
    free(r->elems);
    memset(r, 0, sizeof(*r));
}
