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
 * test_kv_chunk.c -- Unit tests for chunk header serialization,
 *                     deserialization, and CRC32 validation.
 *
 * Tests:
 *   1. Serialize/deserialize round-trip
 *   2. Magic validation (corrupt magic -> LLB_KV_ERR_CRC)
 *   3. CRC validation pass
 *   4. CRC validation fail (corrupt payload byte)
 *   5. Version check (wrong version -> error)
 *   6. Network byte order verification
 *
 * Build: gcc -Wall -Werror -g -o test_kv_chunk test_kv_chunk.c loxilb_kv_chunk.c -lz
 * Run:   ./test_kv_chunk
 */

#include "loxilb_kv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
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
/* Test 1: Serialize/deserialize round-trip                            */
/* ------------------------------------------------------------------ */

static int test_roundtrip(void)
{
    llb_kv_chunk_hdr_t orig = {
        .magic          = LLB_KV_CHUNK_MAGIC,
        .version        = LLB_KV_CHUNK_VERSION,
        .algo           = LLB_KV_ALGO_DEFLATE,
        .chunk_index    = 42,
        .compressed_len = 1024,
        .original_len   = 4096,
        .crc32          = 0xDEADBEEF,
        .session_id     = 0x0102030405060708ULL,
    };

    uint8_t buf[sizeof(llb_kv_chunk_hdr_t)];
    int rc;

    rc = llb_kv_chunk_hdr_serialize(&orig, buf, sizeof(buf));
    ASSERT(rc == LLB_KV_OK);

    llb_kv_chunk_hdr_t decoded;
    rc = llb_kv_chunk_hdr_deserialize(buf, sizeof(buf), &decoded);
    ASSERT(rc == LLB_KV_OK);

    ASSERT(decoded.magic          == orig.magic);
    ASSERT(decoded.version        == orig.version);
    ASSERT(decoded.algo           == orig.algo);
    ASSERT(decoded.chunk_index    == orig.chunk_index);
    ASSERT(decoded.compressed_len == orig.compressed_len);
    ASSERT(decoded.original_len   == orig.original_len);
    ASSERT(decoded.crc32          == orig.crc32);
    ASSERT(decoded.session_id     == orig.session_id);

    printf("  PASS: test_roundtrip\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test 2: Magic validation -- corrupt magic -> LLB_KV_ERR_CRC        */
/* ------------------------------------------------------------------ */

static int test_bad_magic(void)
{
    llb_kv_chunk_hdr_t orig = {
        .magic   = LLB_KV_CHUNK_MAGIC,
        .version = LLB_KV_CHUNK_VERSION,
    };

    uint8_t buf[sizeof(llb_kv_chunk_hdr_t)];
    int rc;

    rc = llb_kv_chunk_hdr_serialize(&orig, buf, sizeof(buf));
    ASSERT(rc == LLB_KV_OK);

    /* Corrupt magic byte at offset 0 */
    buf[0] ^= 0xFF;

    llb_kv_chunk_hdr_t decoded;
    rc = llb_kv_chunk_hdr_deserialize(buf, sizeof(buf), &decoded);
    ASSERT(rc == LLB_KV_ERR_CRC);

    printf("  PASS: test_bad_magic\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test 3: CRC validation pass                                         */
/* ------------------------------------------------------------------ */

static int test_crc_pass(void)
{
    const char payload[] = "Hello KV Cache Pipeline";
    size_t payload_len = strlen(payload);

    uint32_t crc = crc32(0L, (const unsigned char *)payload, payload_len);

    llb_kv_chunk_hdr_t hdr = {
        .magic          = LLB_KV_CHUNK_MAGIC,
        .version        = LLB_KV_CHUNK_VERSION,
        .algo           = LLB_KV_ALGO_DEFLATE,
        .compressed_len = (uint32_t)payload_len,
        .crc32          = crc,
    };

    int rc = llb_kv_chunk_validate_crc(&hdr, payload, payload_len);
    ASSERT(rc == LLB_KV_OK);

    printf("  PASS: test_crc_pass\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test 4: CRC validation fail -- corrupt one byte                     */
/* ------------------------------------------------------------------ */

static int test_crc_fail(void)
{
    char payload[] = "Hello KV Cache Pipeline";
    size_t payload_len = strlen(payload);

    uint32_t crc = crc32(0L, (const unsigned char *)payload, payload_len);

    llb_kv_chunk_hdr_t hdr = {
        .magic          = LLB_KV_CHUNK_MAGIC,
        .version        = LLB_KV_CHUNK_VERSION,
        .compressed_len = (uint32_t)payload_len,
        .crc32          = crc,
    };

    /* Corrupt one byte of the payload */
    payload[5] ^= 0xFF;

    int rc = llb_kv_chunk_validate_crc(&hdr, payload, payload_len);
    ASSERT(rc == LLB_KV_ERR_CRC);

    printf("  PASS: test_crc_fail\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test 5: Version check -- wrong version -> error                     */
/* ------------------------------------------------------------------ */

static int test_bad_version(void)
{
    llb_kv_chunk_hdr_t orig = {
        .magic   = LLB_KV_CHUNK_MAGIC,
        .version = 99,  /* Invalid version */
    };

    uint8_t buf[sizeof(llb_kv_chunk_hdr_t)];
    int rc;

    rc = llb_kv_chunk_hdr_serialize(&orig, buf, sizeof(buf));
    ASSERT(rc == LLB_KV_OK);

    llb_kv_chunk_hdr_t decoded;
    rc = llb_kv_chunk_hdr_deserialize(buf, sizeof(buf), &decoded);
    ASSERT(rc == LLB_KV_ERR_CRC);

    printf("  PASS: test_bad_version\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test 6: Network byte order -- verify serialized bytes               */
/* ------------------------------------------------------------------ */

static int test_network_byte_order(void)
{
    llb_kv_chunk_hdr_t orig = {
        .magic          = LLB_KV_CHUNK_MAGIC,  /* 0x4C585648 */
        .version        = LLB_KV_CHUNK_VERSION,
        .algo           = LLB_KV_ALGO_DEFLATE,
        .chunk_index    = 0x0102,
        .compressed_len = 0x03040506,
        .original_len   = 0x0708090A,
        .crc32          = 0x0B0C0D0E,
        .session_id     = 0x1112131415161718ULL,
    };

    uint8_t buf[sizeof(llb_kv_chunk_hdr_t)];
    int rc;

    rc = llb_kv_chunk_hdr_serialize(&orig, buf, sizeof(buf));
    ASSERT(rc == LLB_KV_OK);

    /* Check magic is in big-endian (network byte order) */
    /* 0x4C585648 -> bytes: 4C 58 56 48 */
    ASSERT(buf[0] == 0x4C);
    ASSERT(buf[1] == 0x58);
    ASSERT(buf[2] == 0x56);
    ASSERT(buf[3] == 0x48);

    /* Check version at offset 4 (single byte, no swap) */
    ASSERT(buf[4] == LLB_KV_CHUNK_VERSION);

    /* Check algo at offset 5 (single byte, no swap) */
    ASSERT(buf[5] == LLB_KV_ALGO_DEFLATE);

    /* Check chunk_index at offset 6-7 in big-endian: 0x0102 -> 01 02 */
    ASSERT(buf[6] == 0x01);
    ASSERT(buf[7] == 0x02);

    /* Check compressed_len at offset 8-11: 0x03040506 -> 03 04 05 06 */
    ASSERT(buf[8]  == 0x03);
    ASSERT(buf[9]  == 0x04);
    ASSERT(buf[10] == 0x05);
    ASSERT(buf[11] == 0x06);

    printf("  PASS: test_network_byte_order\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

int main(void)
{
    int failures = 0;

    printf("=== test_kv_chunk: Chunk protocol unit tests ===\n");

    failures += test_roundtrip();
    failures += test_bad_magic();
    failures += test_crc_pass();
    failures += test_crc_fail();
    failures += test_bad_version();
    failures += test_network_byte_order();

    printf("--- Results: %d/%d passed ---\n",
           6 - failures, 6);

    return failures;
}
