/*
 * Copyright (c) 2022 NetLOX Inc
 *
 * test_kv_dequantize.c -- Unit tests for FP8 E4M3 -> FP16 conversion
 *                          and dequantize worker pool.
 *
 * Compiled against stub implementations (no NEON, no DOCA).
 */

#include "loxilb_kv.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) \
    do { \
        tests_run++; \
        printf("  TEST %-40s ", #name); \
        test_##name(); \
        tests_passed++; \
        printf("PASS\n"); \
    } while(0)

/* ------------------------------------------------------------------ */
/* FP8 E4M3 conversion tests                                          */
/* ------------------------------------------------------------------ */

/*
 * FP8 E4M3 encoding:
 *   [sign:1][exp:4][man:3]
 *   bias = 7
 *   exp=0: subnormal/zero
 *   exp=15: NaN (no Inf in E4M3)
 *
 * Expected FP16 results:
 *   sign16 = sign8 (bit 15)
 *   Normal: exp16 = exp8 + 8, man16 = man8 << 7
 *   Subnormal: exp16 = 0, man16 = man8 << 7
 *   NaN: exp16 = 31, man16 = man8 << 7
 */

static void test_fp8_zero(void)
{
    /* 0x00 = +0.0: sign=0, exp=0, man=0 -> FP16 0x0000 */
    uint8_t src = 0x00;
    uint16_t dst = 0xFFFF;
    llb_kv_fp8e4m3_to_fp16(&src, &dst, 1);
    assert(dst == 0x0000);
}

static void test_fp8_one(void)
{
    /*
     * 1.0 in E4M3: sign=0, exp=7 (bias=7, so unbiased=0), man=0
     * Binary: 0_0111_000 = 0x38
     * FP16: sign=0, exp=7+8=15, man=0
     * FP16 binary: 0_01111_0000000000 = 0x3C00
     */
    uint8_t src = 0x38;
    uint16_t dst = 0;
    llb_kv_fp8e4m3_to_fp16(&src, &dst, 1);
    assert(dst == 0x3C00);
}

static void test_fp8_negative(void)
{
    /*
     * -1.0 in E4M3: sign=1, exp=7, man=0
     * Binary: 1_0111_000 = 0xB8
     * FP16: sign=1, exp=15, man=0
     * FP16 binary: 1_01111_0000000000 = 0xBC00
     */
    uint8_t src = 0xB8;
    uint16_t dst = 0;
    llb_kv_fp8e4m3_to_fp16(&src, &dst, 1);
    assert(dst == 0xBC00);
}

static void test_fp8_subnormal(void)
{
    /*
     * Smallest subnormal in E4M3: sign=0, exp=0, man=1
     * Binary: 0_0000_001 = 0x01
     * FP16: sign=0, exp=0 (subnormal preserved), man=1<<7=0x80
     * FP16 binary: 0_00000_0010000000 = 0x0080
     */
    uint8_t src = 0x01;
    uint16_t dst = 0;
    llb_kv_fp8e4m3_to_fp16(&src, &dst, 1);
    /* exp must be 0 (subnormal) */
    uint16_t exp16 = (dst >> 10) & 0x1F;
    assert(exp16 == 0);
    assert(dst == 0x0080);
}

static void test_fp8_nan(void)
{
    /*
     * NaN in E4M3: sign=0, exp=15, man=7 (the ONLY NaN encoding)
     * Binary: 0_1111_111 = 0x7F
     * FP16: sign=0 | 0x7FFF = 0x7FFF (canonical NaN)
     */
    uint8_t src = 0x7F;
    uint16_t dst = 0;
    llb_kv_fp8e4m3_to_fp16(&src, &dst, 1);
    assert(dst == 0x7FFF);  /* NaN: sign | 0x7FFF */
}

static void test_fp8_negative_nan(void)
{
    /*
     * Negative NaN: sign=1, exp=15, man=7
     * Binary: 1_1111_111 = 0xFF
     * FP16: 0x8000 | 0x7FFF = 0xFFFF (negative NaN)
     */
    uint8_t src = 0xFF;
    uint16_t dst = 0;
    llb_kv_fp8e4m3_to_fp16(&src, &dst, 1);
    assert(dst == 0xFFFF);  /* Negative NaN */
}

static void test_fp8_max_normal(void)
{
    /*
     * Max normal in E4M3: sign=0, exp=14, man=7
     * Binary: 0_1110_111 = 0x77
     * Value = 2^(14-7) * (1 + 7/8) = 128 * 1.875 = 240
     * FP16: sign=0, exp=14+8=22, man=7<<7=0x380
     * FP16 binary: 0_10110_1110000000 = (22<<10)|0x380 = 0x5B80
     */
    uint8_t src = 0x77;
    uint16_t dst = 0;
    llb_kv_fp8e4m3_to_fp16(&src, &dst, 1);
    /* exp=22, man=0x380 => 0_10110_1110000000 */
    assert(dst == ((22 << 10) | 0x0380));  /* 0x5B80 */
}

static void test_fp8_exp15_man6(void)
{
    /*
     * 0x7E: sign=0, exp=15, man=6 -- NOT NaN (only exp=15+man=7 is NaN)
     * exp16 = 15+8 = 23, man16 = 6<<7 = 0x0300
     * FP16 = (23<<10) | 0x0300 = 0x5C00 | 0x0300 = 0x5F00
     * Value = (1 + 6/8) * 2^(23-15) = 1.75 * 256 = 448.0
     */
    uint8_t src = 0x7E;
    uint16_t dst = 0;
    llb_kv_fp8e4m3_to_fp16(&src, &dst, 1);
    assert(dst == 0x5F00);  /* 448.0, NOT NaN */
}

static void test_fp8_exp15_man0(void)
{
    /*
     * 0x78: sign=0, exp=15, man=0 -- NOT NaN
     * exp16 = 23, man16 = 0
     * FP16 = (23<<10) = 0x5C00
     * Value = 1.0 * 2^(23-15) = 256.0
     */
    uint8_t src = 0x78;
    uint16_t dst = 0;
    llb_kv_fp8e4m3_to_fp16(&src, &dst, 1);
    assert(dst == 0x5C00);  /* 256.0, NOT NaN */
}

static void test_fp8_neg_exp15_man6(void)
{
    /*
     * 0xFE: sign=1, exp=15, man=6 -- NOT NaN
     * FP16 = 0x8000 | (23<<10) | 0x0300 = 0x8000 | 0x5F00 = 0xDF00
     * Value = -448.0
     */
    uint8_t src = 0xFE;
    uint16_t dst = 0;
    llb_kv_fp8e4m3_to_fp16(&src, &dst, 1);
    assert(dst == 0xDF00);  /* -448.0, NOT NaN */
}

static void test_fp8_batch(void)
{
    /* Test batch conversion of multiple values */
    uint8_t src[4] = {0x00, 0x38, 0xB8, 0x7F};
    uint16_t dst[4] = {0};
    llb_kv_fp8e4m3_to_fp16(src, dst, 4);
    assert(dst[0] == 0x0000);  /* zero */
    assert(dst[1] == 0x3C00);  /* 1.0 */
    assert(dst[2] == 0xBC00);  /* -1.0 */
    assert(dst[3] == 0x7FFF);  /* NaN (sign|0x7FFF) */
}

/* ------------------------------------------------------------------ */
/* Worker pool tests                                                   */
/* ------------------------------------------------------------------ */

static void test_worker_pool(void)
{
    /*
     * Setup: 2 buffer pools (src for FP8, dst for FP16),
     * 2 ring buffers, 2 dequantize workers.
     * Push 10 elements to input ring with known FP8 patterns.
     * Verify 10 elements appear in output ring with data_len doubled.
     */
    llb_kv_ring_t input_ring, output_ring;
    llb_kv_bufpool_t src_pool, dst_pool;

    /* Init rings (capacity must be power of 2) */
    assert(llb_kv_ring_init(&input_ring, 128) == 0);
    assert(llb_kv_ring_init(&output_ring, 128) == 0);

    /* Init buffer pools: 64KB each, 1KB slots = 64 slots */
    assert(llb_kv_bufpool_init(&src_pool, 64 * 1024, 1024, 0, NULL) == 0);
    assert(llb_kv_bufpool_init(&dst_pool, 64 * 1024, 1024, 0, NULL) == 0);

    /* Fill 10 input slots with known FP8 data */
    int num_elems = 10;
    int fp8_count = 16;  /* 16 FP8 bytes per chunk */

    for (int i = 0; i < num_elems; i++) {
        int slot = llb_kv_bufpool_alloc(&src_pool);
        assert(slot >= 0);

        uint8_t *buf = (uint8_t *)llb_kv_bufpool_slot_ptr(&src_pool, slot);
        assert(buf != NULL);

        /* Fill with known pattern: alternating 0x38 (1.0) and 0x00 (zero) */
        for (int j = 0; j < fp8_count; j++) {
            buf[j] = (j % 2 == 0) ? 0x38 : 0x00;
        }

        llb_kv_ring_elem_t elem = {
            .slot_idx   = (uint32_t)slot,
            .data_len   = (uint32_t)fp8_count,
            .session_id = 42,
        };
        assert(llb_kv_ring_push(&input_ring, &elem) == 0);
    }

    /* Init and start 2 dequantize workers */
    llb_kv_dequantize_ctx_t *ctx = llb_kv_dequantize_init(
        2, &input_ring, &output_ring, &src_pool, &dst_pool);
    assert(ctx != NULL);
    assert(llb_kv_dequantize_start(ctx, NULL, 0) == 0);

    /* Wait for output ring to have all elements (max 2 seconds) */
    int received = 0;
    for (int wait = 0; wait < 200 && received < num_elems; wait++) {
        llb_kv_ring_elem_t out;
        while (llb_kv_ring_pop(&output_ring, &out) == 0) {
            /* Verify: data_len should be doubled (FP8->FP16 = 2 bytes each) */
            assert(out.data_len == (uint32_t)(fp8_count * 2));
            assert(out.session_id == 42);

            /* Verify FP16 content */
            uint16_t *fp16 = (uint16_t *)llb_kv_bufpool_slot_ptr(&dst_pool,
                                                                   (int)out.slot_idx);
            assert(fp16 != NULL);
            for (int j = 0; j < fp8_count; j++) {
                if (j % 2 == 0) {
                    assert(fp16[j] == 0x3C00);  /* 1.0 */
                } else {
                    assert(fp16[j] == 0x0000);  /* 0.0 */
                }
            }

            /* Free output slot */
            llb_kv_bufpool_free(&dst_pool, (int)out.slot_idx);
            received++;
        }
        usleep(10000);  /* 10ms */
    }

    assert(received == num_elems);
    assert(llb_kv_dequantize_get_chunks_done(ctx) == (uint64_t)num_elems);

    /* Cleanup */
    llb_kv_dequantize_stop(ctx);
    llb_kv_dequantize_destroy(ctx);
    llb_kv_ring_destroy(&input_ring);
    llb_kv_ring_destroy(&output_ring);
    llb_kv_bufpool_destroy(&src_pool);
    llb_kv_bufpool_destroy(&dst_pool);
}

static void test_worker_stop(void)
{
    /*
     * Verify clean stop: start workers with empty rings,
     * immediately stop -- no hang, all threads join cleanly.
     */
    llb_kv_ring_t input_ring, output_ring;
    llb_kv_bufpool_t src_pool, dst_pool;

    assert(llb_kv_ring_init(&input_ring, 64) == 0);
    assert(llb_kv_ring_init(&output_ring, 64) == 0);
    assert(llb_kv_bufpool_init(&src_pool, 32 * 1024, 1024, 0, NULL) == 0);
    assert(llb_kv_bufpool_init(&dst_pool, 32 * 1024, 1024, 0, NULL) == 0);

    llb_kv_dequantize_ctx_t *ctx = llb_kv_dequantize_init(
        2, &input_ring, &output_ring, &src_pool, &dst_pool);
    assert(ctx != NULL);
    assert(llb_kv_dequantize_start(ctx, NULL, 0) == 0);

    /* Brief pause to let threads start their loops */
    usleep(5000);

    /* Stop immediately -- should not hang */
    llb_kv_dequantize_stop(ctx);
    llb_kv_dequantize_destroy(ctx);

    llb_kv_ring_destroy(&input_ring);
    llb_kv_ring_destroy(&output_ring);
    llb_kv_bufpool_destroy(&src_pool);
    llb_kv_bufpool_destroy(&dst_pool);
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */
int main(void)
{
    printf("=== KV Dequantize Tests ===\n");

    /* FP8 conversion edge cases */
    TEST(fp8_zero);
    TEST(fp8_one);
    TEST(fp8_negative);
    TEST(fp8_subnormal);
    TEST(fp8_nan);
    TEST(fp8_negative_nan);
    TEST(fp8_max_normal);
    TEST(fp8_exp15_man6);
    TEST(fp8_exp15_man0);
    TEST(fp8_neg_exp15_man6);
    TEST(fp8_batch);

    /* Worker pool tests */
    TEST(worker_pool);
    TEST(worker_stop);

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
