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
 * loxilb_kv_dma_stub.c -- memcpy fallback for non-DOCA builds.
 *
 * Provides the same API surface as loxilb_kv_dma.c but uses plain
 * memcpy instead of DOCA DMA hardware. GPU mmap is simulated with
 * a malloc'd buffer, allowing full pipeline testing on machines
 * without GPU or DOCA SDK.
 */

#include "loxilb_kv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* DMA context (stub -- full definition, opaque to callers)            */
/* ------------------------------------------------------------------ */

struct llb_kv_dma_ctx {
    void   *local_buf;
    size_t  local_buf_size;
};

/* ------------------------------------------------------------------ */
/* Init                                                                */
/* ------------------------------------------------------------------ */

llb_kv_dma_ctx_t *
llb_kv_dma_init(void *dev_unused, size_t staging_size)
{
    llb_kv_dma_ctx_t *ctx;

    (void)dev_unused;

    if (staging_size == 0)
        return NULL;

    ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;

    ctx->local_buf = malloc(staging_size);
    if (!ctx->local_buf) {
        free(ctx);
        return NULL;
    }
    ctx->local_buf_size = staging_size;

    return ctx;
}

/* ------------------------------------------------------------------ */
/* Per-session GPU mmap import (stub -- malloc mock buffer)             */
/* ------------------------------------------------------------------ */

int
llb_kv_dma_import_gpu_mmap(llb_kv_dma_ctx_t *ctx,
                           const void *export_desc, size_t desc_len,
                           void **out_gpu_mmap)
{
    void *mock_buf;

    (void)ctx;

    if (!export_desc || desc_len == 0 || !out_gpu_mmap)
        return LLB_KV_ERR_INTERNAL;

    /*
     * Allocate a mock buffer to simulate GPU HBM for CICD.
     * The desc_len serves as the simulated GPU region size.
     */
    mock_buf = malloc(desc_len);
    if (!mock_buf) {
        *out_gpu_mmap = NULL;
        return LLB_KV_ERR_NOMEM;
    }

    memset(mock_buf, 0, desc_len);
    *out_gpu_mmap = mock_buf;
    return LLB_KV_OK;
}

/* ------------------------------------------------------------------ */
/* Transfer to GPU (memcpy fallback)                                   */
/* ------------------------------------------------------------------ */

int
llb_kv_dma_to_gpu(llb_kv_dma_ctx_t *ctx, void *gpu_mmap,
                  const void *src, size_t len, size_t gpu_offset)
{
    (void)ctx;

    if (!gpu_mmap || !src || len == 0)
        return LLB_KV_ERR_INTERNAL;

    memcpy((char *)gpu_mmap + gpu_offset, src, len);
    return LLB_KV_OK;
}

/* ------------------------------------------------------------------ */
/* Transfer from GPU (memcpy fallback)                                 */
/* ------------------------------------------------------------------ */

int
llb_kv_dma_from_gpu(llb_kv_dma_ctx_t *ctx, void *gpu_mmap,
                    size_t gpu_offset, size_t len, void *dst)
{
    (void)ctx;

    if (!gpu_mmap || !dst || len == 0)
        return LLB_KV_ERR_INTERNAL;

    memcpy(dst, (char *)gpu_mmap + gpu_offset, len);
    return LLB_KV_OK;
}

/* ------------------------------------------------------------------ */
/* Destroy                                                             */
/* ------------------------------------------------------------------ */

void
llb_kv_dma_destroy(llb_kv_dma_ctx_t *ctx)
{
    if (!ctx)
        return;

    free(ctx->local_buf);
    free(ctx);
}
