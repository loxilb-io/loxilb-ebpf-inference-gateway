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
 * loxilb_kv_compress_stub.c -- zlib SW fallback for compress/decompress.
 *
 * This is a REAL implementation (not an empty stub). It provides the
 * same API as the DOCA HW version (loxilb_kv_compress.c) but uses
 * zlib inflate/deflate for software-only operation on any platform.
 *
 * Build: HAVE_DOCA=0 (no DOCA SDK needed, only zlib).
 */

#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include "loxilb_kv.h"

/* ------------------------------------------------------------------ */
/* Compress context (stub version -- opaque to callers)                */
/* ------------------------------------------------------------------ */
struct llb_kv_compress_ctx {
    /* Dequantize hook (called after decompress, before DMA) */
    void (*dequantize_hook)(void *data, size_t len, void *user_ctx);
    void  *dequantize_user_ctx;
};

/* ------------------------------------------------------------------ */
/* Init / Destroy                                                      */
/* ------------------------------------------------------------------ */

llb_kv_compress_ctx_t *
llb_kv_compress_init(void *dev_unused, size_t staging_size_unused)
{
    (void)dev_unused;
    (void)staging_size_unused;

    llb_kv_compress_ctx_t *ctx = calloc(1, sizeof(*ctx));
    return ctx;  /* NULL on alloc failure */
}

void
llb_kv_compress_destroy(llb_kv_compress_ctx_t *ctx)
{
    free(ctx);
}

/* ------------------------------------------------------------------ */
/* Decompress (zlib inflate)                                           */
/* ------------------------------------------------------------------ */

int
llb_kv_decompress(llb_kv_compress_ctx_t *ctx,
                  const void *compressed, size_t compressed_len,
                  void *output, size_t output_capacity,
                  size_t *output_len)
{
    z_stream strm;
    int ret;

    if (!ctx || !compressed || !output || !output_len)
        return LLB_KV_ERR_INTERNAL;

    memset(&strm, 0, sizeof(strm));
    ret = inflateInit(&strm);
    if (ret != Z_OK)
        return LLB_KV_ERR_HW;

    strm.next_in   = (unsigned char *)(uintptr_t)compressed;
    strm.avail_in  = (uInt)compressed_len;
    strm.next_out  = (unsigned char *)output;
    strm.avail_out = (uInt)output_capacity;

    ret = inflate(&strm, Z_FINISH);
    if (ret != Z_STREAM_END) {
        inflateEnd(&strm);
        /* Z_BUF_ERROR means output buffer too small */
        if (ret == Z_BUF_ERROR)
            return LLB_KV_ERR_BOUNDS;
        return LLB_KV_ERR_HW;
    }

    *output_len = strm.total_out;
    inflateEnd(&strm);

    /* Call dequantize hook if set */
    if (ctx->dequantize_hook)
        ctx->dequantize_hook(output, *output_len, ctx->dequantize_user_ctx);

    return LLB_KV_OK;
}

/* ------------------------------------------------------------------ */
/* Compress (zlib deflate -- write-back path)                          */
/* ------------------------------------------------------------------ */

int
llb_kv_compress(llb_kv_compress_ctx_t *ctx,
                const void *raw, size_t raw_len,
                void *output, size_t output_capacity,
                size_t *output_len)
{
    z_stream strm;
    int ret;

    if (!ctx || !raw || !output || !output_len)
        return LLB_KV_ERR_INTERNAL;

    memset(&strm, 0, sizeof(strm));
    ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
    if (ret != Z_OK)
        return LLB_KV_ERR_HW;

    strm.next_in   = (unsigned char *)(uintptr_t)raw;
    strm.avail_in  = (uInt)raw_len;
    strm.next_out  = (unsigned char *)output;
    strm.avail_out = (uInt)output_capacity;

    ret = deflate(&strm, Z_FINISH);
    if (ret != Z_STREAM_END) {
        deflateEnd(&strm);
        if (ret == Z_BUF_ERROR)
            return LLB_KV_ERR_BOUNDS;
        return LLB_KV_ERR_HW;
    }

    *output_len = strm.total_out;
    deflateEnd(&strm);

    return LLB_KV_OK;
}

/* ------------------------------------------------------------------ */
/* Dequantize hook setter                                              */
/* ------------------------------------------------------------------ */

void
llb_kv_compress_set_dequantize(llb_kv_compress_ctx_t *ctx,
                               void (*hook)(void *data, size_t len,
                                            void *user_ctx),
                               void *user_ctx)
{
    if (!ctx)
        return;
    ctx->dequantize_hook     = hook;
    ctx->dequantize_user_ctx = user_ctx;
}
