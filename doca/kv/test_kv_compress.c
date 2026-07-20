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
 * test_kv_compress.c -- Unit tests for compress/decompress round-trip
 *                        using the zlib stub implementation.
 *
 * Tests:
 *   1. Compress then decompress round-trip
 *   2. Decompress known pre-compressed data
 *   3. Dequantize hook invocation
 *   4. Buffer too small (output undersized)
 *
 * Build: gcc -Wall -Werror -g -o test_kv_compress \
 *        test_kv_compress.c loxilb_kv_compress_stub.c -lz
 * Run:   ./test_kv_compress
 */

#include "loxilb_kv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

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
/* Test 1: Compress then decompress round-trip                         */
/* ------------------------------------------------------------------ */

static int test_roundtrip(void)
{
    llb_kv_compress_ctx_t *ctx = llb_kv_compress_init(NULL, 4 * 1024 * 1024);
    ASSERT(ctx != NULL);

    /* Create test data: 4KB of repeating pattern */
    const size_t data_len = 4096;
    uint8_t *original = malloc(data_len);
    ASSERT(original != NULL);
    for (size_t i = 0; i < data_len; i++)
        original[i] = (uint8_t)(i & 0xFF);

    /* Compress */
    uint8_t *compressed = malloc(data_len * 2);
    ASSERT(compressed != NULL);
    size_t compressed_len = 0;

    int rc = llb_kv_compress(ctx, original, data_len,
                             compressed, data_len * 2, &compressed_len);
    ASSERT(rc == LLB_KV_OK);
    ASSERT(compressed_len > 0);
    ASSERT(compressed_len < data_len * 2);

    /* Decompress */
    uint8_t *decompressed = malloc(data_len);
    ASSERT(decompressed != NULL);
    size_t decompressed_len = 0;

    rc = llb_kv_decompress(ctx, compressed, compressed_len,
                           decompressed, data_len, &decompressed_len);
    ASSERT(rc == LLB_KV_OK);
    ASSERT(decompressed_len == data_len);

    /* Verify round-trip */
    ASSERT(memcmp(original, decompressed, data_len) == 0);

    free(original);
    free(compressed);
    free(decompressed);
    llb_kv_compress_destroy(ctx);

    printf("  PASS: test_roundtrip\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test 2: Decompress known pre-compressed blob                        */
/* ------------------------------------------------------------------ */

static int test_decompress_known(void)
{
    llb_kv_compress_ctx_t *ctx = llb_kv_compress_init(NULL, 4 * 1024 * 1024);
    ASSERT(ctx != NULL);

    /* Pre-compress "Hello, KV Cache!" using zlib directly */
    const char *expected = "Hello, KV Cache!";
    size_t expected_len = strlen(expected);

    uint8_t compressed[256];
    uLongf compressed_len = sizeof(compressed);

    /* Use zlib compress() to create a known blob */
    int zrc = compress(compressed, &compressed_len,
                       (const unsigned char *)expected, expected_len);
    ASSERT(zrc == Z_OK);

    /* Now decompress using our API */
    char output[256];
    size_t output_len = 0;

    int rc = llb_kv_decompress(ctx, compressed, compressed_len,
                               output, sizeof(output), &output_len);
    ASSERT(rc == LLB_KV_OK);
    ASSERT(output_len == expected_len);
    ASSERT(memcmp(output, expected, expected_len) == 0);

    llb_kv_compress_destroy(ctx);

    printf("  PASS: test_decompress_known\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test 3: Dequantize hook invocation                                  */
/* ------------------------------------------------------------------ */

/* Hook tracking state */
static int g_hook_called = 0;
static size_t g_hook_len = 0;
static void *g_hook_user = NULL;

static void test_dequantize_hook(void *data, size_t len, void *user_ctx)
{
    (void)data;
    g_hook_called = 1;
    g_hook_len = len;
    g_hook_user = user_ctx;
}

static int test_dequantize_hook_called(void)
{
    llb_kv_compress_ctx_t *ctx = llb_kv_compress_init(NULL, 4 * 1024 * 1024);
    ASSERT(ctx != NULL);

    /* Set hook */
    int sentinel = 42;
    llb_kv_compress_set_dequantize(ctx, test_dequantize_hook, &sentinel);

    /* Create test data and compress */
    const char *data = "Test dequantize hook data payload";
    size_t data_len = strlen(data);

    uint8_t compressed[256];
    size_t compressed_len = 0;

    int rc = llb_kv_compress(ctx, data, data_len,
                             compressed, sizeof(compressed), &compressed_len);
    ASSERT(rc == LLB_KV_OK);

    /* Reset tracking state */
    g_hook_called = 0;
    g_hook_len = 0;
    g_hook_user = NULL;

    /* Decompress -- should trigger hook */
    char output[256];
    size_t output_len = 0;
    rc = llb_kv_decompress(ctx, compressed, compressed_len,
                           output, sizeof(output), &output_len);
    ASSERT(rc == LLB_KV_OK);

    /* Verify hook was called with correct parameters */
    ASSERT(g_hook_called == 1);
    ASSERT(g_hook_len == data_len);
    ASSERT(g_hook_user == &sentinel);

    llb_kv_compress_destroy(ctx);

    printf("  PASS: test_dequantize_hook_called\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test 4: Buffer too small                                            */
/* ------------------------------------------------------------------ */

static int test_buffer_too_small(void)
{
    llb_kv_compress_ctx_t *ctx = llb_kv_compress_init(NULL, 4 * 1024 * 1024);
    ASSERT(ctx != NULL);

    /* Create 4KB test data and compress */
    const size_t data_len = 4096;
    uint8_t *original = malloc(data_len);
    ASSERT(original != NULL);
    for (size_t i = 0; i < data_len; i++)
        original[i] = (uint8_t)(i & 0xFF);

    uint8_t *compressed = malloc(data_len * 2);
    ASSERT(compressed != NULL);
    size_t compressed_len = 0;

    int rc = llb_kv_compress(ctx, original, data_len,
                             compressed, data_len * 2, &compressed_len);
    ASSERT(rc == LLB_KV_OK);

    /* Try to decompress into a buffer that's too small (16 bytes) */
    uint8_t tiny_buf[16];
    size_t tiny_len = 0;
    rc = llb_kv_decompress(ctx, compressed, compressed_len,
                           tiny_buf, sizeof(tiny_buf), &tiny_len);
    /* Should return an error (Z_BUF_ERROR -> LLB_KV_ERR_BOUNDS or LLB_KV_ERR_HW) */
    ASSERT(rc != LLB_KV_OK);

    free(original);
    free(compressed);
    llb_kv_compress_destroy(ctx);

    printf("  PASS: test_buffer_too_small\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

int main(void)
{
    int failures = 0;

    printf("=== test_kv_compress: Compress/decompress unit tests ===\n");

    failures += test_roundtrip();
    failures += test_decompress_known();
    failures += test_dequantize_hook_called();
    failures += test_buffer_too_small();

    printf("--- Results: %d/%d passed ---\n",
           4 - failures, 4);

    return failures;
}
