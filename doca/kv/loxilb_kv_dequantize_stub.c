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
 * loxilb_kv_dequantize_stub.c -- Scalar FP8 E4M3 -> FP16 dequantize
 *                                 worker pool (no NEON, any platform).
 *
 * Uses scalar bit manipulation for FP8 E4M3 to IEEE FP16 conversion.
 * Worker threads drain input ring, convert, push to output ring.
 * No pthread_setaffinity_np (stub may run on macOS/x86 for tests).
 */

#include "loxilb_kv.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

/* ------------------------------------------------------------------ */
/* Internal context struct                                             */
/* ------------------------------------------------------------------ */
struct llb_kv_dequantize_ctx {
    int              worker_count;
    pthread_t       *threads;
    _Atomic int      stop;
    llb_kv_ring_t   *input_ring;
    llb_kv_ring_t   *output_ring;
    llb_kv_bufpool_t *src_pool;
    llb_kv_bufpool_t *dst_pool;
    _Atomic uint64_t chunks_done;
};

/* ------------------------------------------------------------------ */
/* FP8 E4M3 -> FP16 scalar conversion                                 */
/* ------------------------------------------------------------------ */

/*
 * FP8 E4M3 format: [sign:1][exp:4][man:3]
 *   - exp bias = 7 (E4M3)
 *   - exp=0: subnormal (or zero if man=0)
 *   - exp=15, man=7: NaN (E4M3 has no Inf; only exp=15+man=7 is NaN)
 *
 * FP16 format: [sign:1][exp:5][man:10]
 *   - exp bias = 15
 *   - exp=0: subnormal (or zero if man=0)
 *   - exp=31: Inf (man=0) or NaN (man!=0)
 *
 * Conversion:
 *   sign16 = sign8
 *   For exp8=0 (subnormal/zero): exp16=0, man16=man8<<7
 *   For exp8=15 (NaN):           exp16=31, man16=man8<<7 (preserve NaN payload)
 *   For normal (1..14):          exp16=exp8-7+15=exp8+8, man16=man8<<7
 */
static inline uint16_t
fp8e4m3_scalar(uint8_t x)
{
    uint16_t sign = ((uint16_t)(x >> 7)) << 15;
    uint8_t  exp8 = (x >> 3) & 0x0F;
    uint8_t  man8 = x & 0x07;
    uint16_t man16 = (uint16_t)man8 << 7;  /* 3-bit -> 10-bit mantissa */
    uint16_t exp16;

    /* NaN: ONLY exp=15 AND man=7 (0x7F/0xFF canonical NaN) */
    if (exp8 == 15 && man8 == 7)
        return sign | 0x7FFF;   /* FP16 NaN */

    if (exp8 == 0) {
        /* Subnormal or zero: preserve exp=0 */
        exp16 = 0;
    } else {
        /* Normal: rebias from E4M3 bias(7) to FP16 bias(15) */
        exp16 = (uint16_t)(exp8 + 8);
    }

    return sign | (exp16 << 10) | man16;
}

void
llb_kv_fp8e4m3_to_fp16(const uint8_t *src, uint16_t *dst, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        dst[i] = fp8e4m3_scalar(src[i]);
    }
}

/* ------------------------------------------------------------------ */
/* Worker thread                                                       */
/* ------------------------------------------------------------------ */
static void *
dequantize_worker(void *arg)
{
    struct llb_kv_dequantize_ctx *ctx = (struct llb_kv_dequantize_ctx *)arg;
    llb_kv_ring_elem_t elem;

    while (!atomic_load(&ctx->stop)) {
        /* Try to pop from input ring */
        if (llb_kv_ring_pop(ctx->input_ring, &elem) != 0) {
            /* Ring empty -- back off to avoid busy-spin */
            usleep(10);
            continue;
        }

        /* Get source buffer (FP8 data) */
        void *src_buf = llb_kv_bufpool_slot_ptr(ctx->src_pool,
                                                 (int)elem.slot_idx);
        if (!src_buf) {
            continue;  /* Invalid slot -- skip */
        }

        /* Allocate destination slot (FP16 data = 2x size) */
        int dst_slot;
        while ((dst_slot = llb_kv_bufpool_alloc(ctx->dst_pool)) < 0) {
            if (atomic_load(&ctx->stop)) {
                /* Stopping -- free source and bail */
                llb_kv_bufpool_free(ctx->src_pool, (int)elem.slot_idx);
                return NULL;
            }
            usleep(1);  /* Backpressure -- wait for free slot */
        }

        void *dst_buf = llb_kv_bufpool_slot_ptr(ctx->dst_pool, dst_slot);

        /* Convert FP8 E4M3 -> FP16 */
        size_t num_elements = elem.data_len;  /* data_len = number of FP8 bytes */
        llb_kv_fp8e4m3_to_fp16((const uint8_t *)src_buf,
                               (uint16_t *)dst_buf, num_elements);

        /* Free source slot */
        llb_kv_bufpool_free(ctx->src_pool, (int)elem.slot_idx);

        /* Push result to output ring */
        llb_kv_ring_elem_t out_elem = {
            .slot_idx   = (uint32_t)dst_slot,
            .data_len   = (uint32_t)(num_elements * 2),  /* FP16 = 2 bytes each */
            .session_id = elem.session_id,
        };

        while (llb_kv_ring_push(ctx->output_ring, &out_elem) != 0) {
            if (atomic_load(&ctx->stop)) {
                llb_kv_bufpool_free(ctx->dst_pool, dst_slot);
                return NULL;
            }
            usleep(1);  /* Output ring full -- backpressure */
        }

        atomic_fetch_add(&ctx->chunks_done, 1);
    }

    return NULL;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

llb_kv_dequantize_ctx_t *
llb_kv_dequantize_init(int worker_count,
                       llb_kv_ring_t *input_ring,
                       llb_kv_ring_t *output_ring,
                       llb_kv_bufpool_t *src_pool,
                       llb_kv_bufpool_t *dst_pool)
{
    if (worker_count <= 0 || !input_ring || !output_ring ||
        !src_pool || !dst_pool) {
        return NULL;
    }

    struct llb_kv_dequantize_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

    ctx->worker_count = worker_count;
    ctx->input_ring   = input_ring;
    ctx->output_ring  = output_ring;
    ctx->src_pool     = src_pool;
    ctx->dst_pool     = dst_pool;
    atomic_store(&ctx->stop, 0);
    atomic_store(&ctx->chunks_done, 0);

    ctx->threads = calloc((size_t)worker_count, sizeof(pthread_t));
    if (!ctx->threads) {
        free(ctx);
        return NULL;
    }

    return ctx;
}

int
llb_kv_dequantize_start(llb_kv_dequantize_ctx_t *ctx,
                        const int *core_ids, int num_cores)
{
    (void)core_ids;
    (void)num_cores;

    if (!ctx) return -1;

    for (int i = 0; i < ctx->worker_count; i++) {
        if (pthread_create(&ctx->threads[i], NULL, dequantize_worker, ctx) != 0) {
            /* Failed -- stop already-started threads */
            atomic_store(&ctx->stop, 1);
            for (int j = 0; j < i; j++) {
                pthread_join(ctx->threads[j], NULL);
            }
            return -1;
        }
    }

    return 0;
}

void
llb_kv_dequantize_stop(llb_kv_dequantize_ctx_t *ctx)
{
    if (!ctx) return;

    atomic_store(&ctx->stop, 1);
    for (int i = 0; i < ctx->worker_count; i++) {
        pthread_join(ctx->threads[i], NULL);
    }
}

void
llb_kv_dequantize_destroy(llb_kv_dequantize_ctx_t *ctx)
{
    if (!ctx) return;
    free(ctx->threads);
    free(ctx);
}

uint64_t
llb_kv_dequantize_get_chunks_done(llb_kv_dequantize_ctx_t *ctx)
{
    if (!ctx) return 0;
    return atomic_load(&ctx->chunks_done);
}
