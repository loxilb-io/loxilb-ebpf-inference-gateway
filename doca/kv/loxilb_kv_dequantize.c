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
 * loxilb_kv_dequantize.c -- NEON-accelerated FP8 E4M3 -> FP16 dequantize
 *                            worker pool for ShadowServe pipeline.
 *
 * On aarch64: Uses ARM NEON SIMD intrinsics to process 8 FP8 elements
 *             per iteration with correct subnormal (exp=0) and NaN
 *             (exp=15) handling via vceqq/vbslq/vbicq masking.
 * On other:   Falls back to scalar conversion (identical to stub).
 *
 * Worker threads drain the decompress->dequantize ring buffer and push
 * FP16 results to the dequantize->DMA ring buffer.
 */

#include "loxilb_kv.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#ifdef __aarch64__
#include <arm_neon.h>
#endif

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
    int              core_ids[64];
    int              num_cores;
};

/* ------------------------------------------------------------------ */
/* Scalar FP8 E4M3 -> FP16 (fallback / tail)                          */
/* ------------------------------------------------------------------ */
static inline uint16_t
fp8e4m3_scalar(uint8_t x)
{
    uint16_t sign = ((uint16_t)(x >> 7)) << 15;
    uint8_t  exp8 = (x >> 3) & 0x0F;
    uint8_t  man8 = x & 0x07;
    uint16_t man16 = (uint16_t)man8 << 7;
    uint16_t exp16;

    /* NaN: ONLY exp=15 AND man=7 (0x7F/0xFF canonical NaN) */
    if (exp8 == 15 && man8 == 7)
        return sign | 0x7FFF;   /* FP16 NaN */

    if (exp8 == 0) {
        exp16 = 0;              /* subnormal preserved */
    } else {
        exp16 = (uint16_t)(exp8 + 8);  /* Normal: rebias +8 (works for exp=15 non-NaN too) */
    }

    return sign | (exp16 << 10) | man16;
}

/* ------------------------------------------------------------------ */
/* FP8 E4M3 -> FP16 conversion (NEON + scalar tail)                    */
/* ------------------------------------------------------------------ */

void
llb_kv_fp8e4m3_to_fp16(const uint8_t *src, uint16_t *dst, size_t n)
{
#ifdef __aarch64__
    size_t i = 0;
    size_t vec_end = n & ~(size_t)7;  /* process in groups of 8 */

    for (; i < vec_end; i += 8) {
        /* Load 8 FP8 bytes */
        uint8x8_t raw = vld1_u8(&src[i]);

        /* Extract sign (bit 7), exp (bits 6..3), mantissa (bits 2..0) */
        uint8x8_t sign8 = vshr_n_u8(raw, 7);            /* 0 or 1 */
        uint8x8_t exp8  = vand_u8(vshr_n_u8(raw, 3),
                                   vdup_n_u8(0x0F));      /* 4-bit exp */
        uint8x8_t man8  = vand_u8(raw, vdup_n_u8(0x07)); /* 3-bit man */

        /* Widen to 16-bit for FP16 assembly */
        uint16x8_t sign16    = vshlq_n_u16(vmovl_u8(sign8), 15);
        uint16x8_t exp16     = vmovl_u8(exp8);
        uint16x8_t mant16_raw = vmovl_u8(man8);              /* unshifted for NaN check */
        uint16x8_t man16     = vshlq_n_u16(mant16_raw, 7);   /* 3->10 bit */

        /*
         * Rebias exponent: FP8 E4M3 bias=7, FP16 bias=15.
         * Normal: exp16 = exp8 + 8
         * But exp8=0 (subnormal) must stay 0.
         * exp8=15 with man!=7 is a valid normal value (rebias to 23).
         */
        uint16x8_t exp_biased = vaddq_u16(exp16, vdupq_n_u16(8));

        /* Mask: subnormal (exp8==0) -> force exp to 0 */
        uint16x8_t zero_mask = vceqq_u16(exp16, vdupq_n_u16(0));
        exp_biased = vbicq_u16(exp_biased, zero_mask);

        /* Normal result: sign | (exp_biased << 10) | man16 */
        uint16x8_t normal_result = vorrq_u16(sign16,
                                    vorrq_u16(vshlq_n_u16(exp_biased, 10), man16));

        /* NaN mask: ONLY exp=15 AND man=7 */
        uint16x8_t nan_exp  = vceqq_u16(exp16, vdupq_n_u16(15));
        uint16x8_t nan_mant = vceqq_u16(mant16_raw, vdupq_n_u16(7));
        uint16x8_t nan_mask = vandq_u16(nan_exp, nan_mant);

        /* NaN result: sign | 0x7FFF */
        uint16x8_t nan_result = vorrq_u16(sign16, vdupq_n_u16(0x7FFF));

        /* Select: NaN mask -> nan_result, else -> normal_result */
        uint16x8_t result = vbslq_u16(nan_mask, nan_result, normal_result);

        vst1q_u16(&dst[i], result);
    }

    /* Scalar tail for remainder */
    for (; i < n; i++) {
        dst[i] = fp8e4m3_scalar(src[i]);
    }
#else
    /* Pure scalar fallback (x86, etc.) */
    for (size_t i = 0; i < n; i++) {
        dst[i] = fp8e4m3_scalar(src[i]);
    }
#endif
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
        if (llb_kv_ring_pop(ctx->input_ring, &elem) != 0) {
            usleep(10);
            continue;
        }

        void *src_buf = llb_kv_bufpool_slot_ptr(ctx->src_pool,
                                                 (int)elem.slot_idx);
        if (!src_buf) {
            continue;
        }

        int dst_slot;
        while ((dst_slot = llb_kv_bufpool_alloc(ctx->dst_pool)) < 0) {
            if (atomic_load(&ctx->stop)) {
                llb_kv_bufpool_free(ctx->src_pool, (int)elem.slot_idx);
                return NULL;
            }
            usleep(1);
        }

        void *dst_buf = llb_kv_bufpool_slot_ptr(ctx->dst_pool, dst_slot);

        size_t num_elements = elem.data_len;
        llb_kv_fp8e4m3_to_fp16((const uint8_t *)src_buf,
                               (uint16_t *)dst_buf, num_elements);

        llb_kv_bufpool_free(ctx->src_pool, (int)elem.slot_idx);

        llb_kv_ring_elem_t out_elem = {
            .slot_idx   = (uint32_t)dst_slot,
            .data_len   = (uint32_t)(num_elements * 2),
            .session_id = elem.session_id,
        };

        while (llb_kv_ring_push(ctx->output_ring, &out_elem) != 0) {
            if (atomic_load(&ctx->stop)) {
                llb_kv_bufpool_free(ctx->dst_pool, dst_slot);
                return NULL;
            }
            usleep(1);
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
    ctx->num_cores    = 0;
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
    if (!ctx) return -1;

    /* Save core affinity info */
    if (core_ids && num_cores > 0) {
        ctx->num_cores = num_cores;
        for (int i = 0; i < num_cores && i < 64; i++) {
            ctx->core_ids[i] = core_ids[i];
        }
    }

    for (int i = 0; i < ctx->worker_count; i++) {
        pthread_attr_t attr;
        pthread_attr_init(&attr);

#ifdef __linux__
        /* Set CPU affinity if core_ids provided */
        if (core_ids && i < num_cores) {
            cpu_set_t cpuset;
            CPU_ZERO(&cpuset);
            CPU_SET(core_ids[i], &cpuset);
            pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpuset);
        }
#endif

        int rc = pthread_create(&ctx->threads[i], &attr,
                                dequantize_worker, ctx);
        pthread_attr_destroy(&attr);

        if (rc != 0) {
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
