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
 * loxilb_kv_ring.c -- MPMC lockfree ring buffer for inter-stage handoff.
 *
 * Bounded multi-producer multi-consumer queue (Vyukov): every cell carries
 * a sequence counter that publishes ownership, so a producer never exposes
 * a cell before writing it and never reuses one before a consumer has
 * drained it.
 *
 * Both stage handoffs need this. decomp_to_deq_ring is 1 producer (the poll
 * thread) to N consumers (dequantize workers); deq_to_dma_ring is N
 * producers (those same workers) to 1 consumer -- and the poll thread also
 * re-pushes an element it popped for another session, so that ring has
 * concurrent producers even when worker_count == 1.
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

    r->cells = calloc(capacity, sizeof(llb_kv_ring_cell_t));
    if (!r->cells)
        return LLB_KV_ERR_NOMEM;

    /* Cell i starts writable by the producer holding ticket i. */
    for (uint32_t i = 0; i < capacity; i++)
        atomic_store_explicit(&r->cells[i].seq, i, memory_order_relaxed);

    r->capacity = capacity;
    atomic_store_explicit(&r->head, 0, memory_order_relaxed);
    atomic_store_explicit(&r->tail, 0, memory_order_relaxed);
    return LLB_KV_OK;
}

int llb_kv_ring_push(llb_kv_ring_t *r, const llb_kv_ring_elem_t *e)
{
    const uint64_t mask = r->capacity - 1;
    uint64_t h = atomic_load_explicit(&r->head, memory_order_relaxed);

    for (;;) {
        llb_kv_ring_cell_t *c = &r->cells[h & mask];
        uint64_t seq = atomic_load_explicit(&c->seq, memory_order_acquire);
        int64_t  diff = (int64_t)seq - (int64_t)h;

        if (diff == 0) {
            /* Cell is free and ours if we win the ticket. */
            if (atomic_compare_exchange_weak_explicit(
                    &r->head, &h, h + 1,
                    memory_order_relaxed, memory_order_relaxed)) {
                c->elem = *e;
                /* Release: publishes the payload before the consumer may
                 * observe seq == h + 1 and read it. */
                atomic_store_explicit(&c->seq, h + 1, memory_order_release);
                return 0;
            }
            /* CAS failed -- h now holds the current head, retry. */
        } else if (diff < 0) {
            /* Cell still holds an undrained element: the ring is full.
             * Non-blocking contract -- caller applies backpressure. */
            return -1;
        } else {
            /* Another producer already claimed this ticket. Re-read. */
            h = atomic_load_explicit(&r->head, memory_order_relaxed);
        }
    }
}

int llb_kv_ring_pop(llb_kv_ring_t *r, llb_kv_ring_elem_t *e)
{
    const uint64_t mask = r->capacity - 1;
    uint64_t t = atomic_load_explicit(&r->tail, memory_order_relaxed);

    for (;;) {
        llb_kv_ring_cell_t *c = &r->cells[t & mask];
        uint64_t seq = atomic_load_explicit(&c->seq, memory_order_acquire);
        int64_t  diff = (int64_t)seq - (int64_t)(t + 1);

        if (diff == 0) {
            /* Cell is filled and ours if we win the ticket. */
            if (atomic_compare_exchange_weak_explicit(
                    &r->tail, &t, t + 1,
                    memory_order_relaxed, memory_order_relaxed)) {
                *e = c->elem;
                /* Release: hands the cell to the producer one lap ahead,
                 * only after we have finished copying the payload out. */
                atomic_store_explicit(&c->seq, t + mask + 1,
                                      memory_order_release);
                return 0;
            }
            /* CAS failed -- t now holds the current tail, retry. */
        } else if (diff < 0) {
            return -1;  /* empty */
        } else {
            /* Another consumer already claimed this ticket. Re-read. */
            t = atomic_load_explicit(&r->tail, memory_order_relaxed);
        }
    }
}

void llb_kv_ring_destroy(llb_kv_ring_t *r)
{
    if (!r)
        return;
    free(r->cells);
    memset(r, 0, sizeof(*r));
}
