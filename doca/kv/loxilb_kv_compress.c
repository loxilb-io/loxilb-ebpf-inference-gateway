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
 * loxilb_kv_compress.c -- DOCA Compress HW Deflate implementation.
 *
 * Provides async decompress/compress via DOCA Compress engine on BF2.
 * Uses a dedicated Progress Engine (PE) per context to avoid
 * head-of-line blocking (see RESEARCH pitfall #1).
 *
 * Build: HAVE_DOCA=1 only (real DOCA SDK required).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include "loxilb_kv.h"

#include <doca_compress.h>
#include <doca_pe.h>
#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_mmap.h>
#include <doca_ctx.h>
#include <doca_dev.h>

/* Max PE progress loop iterations before declaring timeout */
#define LLB_KV_COMPRESS_PE_MAX_ITERS    100000
/* Microseconds to yield between PE progress calls */
#define LLB_KV_COMPRESS_PE_YIELD_US     10

/* ------------------------------------------------------------------ */
/* Compress context (full definition -- opaque to callers)             */
/* ------------------------------------------------------------------ */
struct llb_kv_compress_ctx {
    struct doca_compress      *compress;
    struct doca_pe            *pe;
    struct doca_dev           *dev;
    struct doca_buf_inventory *buf_inv;
    void                      *src_buf;     /* staging: compressed data  */
    void                      *dst_buf;     /* staging: decompressed data */
    size_t                     staging_size;
    int                        dev_owned;    /* 1 if we opened the device */

    /* Dequantize hook (called after decompress, before DMA) */
    void (*dequantize_hook)(void *data, size_t len, void *user_ctx);
    void  *dequantize_user_ctx;

    /* Per-task completion state */
    volatile int  task_done;
    int           task_result;   /* LLB_KV_OK or error code */
    size_t        produced_len;  /* bytes produced by last task */
};

/* ------------------------------------------------------------------ */
/* Task completion callbacks                                           */
/* ------------------------------------------------------------------ */

static void
decompress_done_cb(struct doca_compress_task_decompress_deflate *task,
                   union doca_data task_user_data,
                   union doca_data ctx_user_data)
{
    (void)ctx_user_data;
    llb_kv_compress_ctx_t *ctx = (llb_kv_compress_ctx_t *)task_user_data.ptr;

    /* Extract produced length from destination buffer */
    struct doca_buf *dst_buf = doca_compress_task_decompress_deflate_get_dst(task);
    size_t data_len = 0;
    doca_buf_get_data_len(dst_buf, &data_len);

    ctx->produced_len = data_len;
    ctx->task_result  = LLB_KV_OK;
    ctx->task_done    = 1;

    /* Free task to return it to the task pool */
    doca_task_free(doca_compress_task_decompress_deflate_as_task(task));
}

static void
decompress_error_cb(struct doca_compress_task_decompress_deflate *task,
                    union doca_data task_user_data,
                    union doca_data ctx_user_data)
{
    (void)ctx_user_data;
    llb_kv_compress_ctx_t *ctx = (llb_kv_compress_ctx_t *)task_user_data.ptr;

    ctx->produced_len = 0;
    ctx->task_result  = LLB_KV_ERR_HW;
    ctx->task_done    = 1;

    /* Free task to return it to the task pool */
    doca_task_free(doca_compress_task_decompress_deflate_as_task(task));
}

static void
compress_done_cb(struct doca_compress_task_compress_deflate *task,
                 union doca_data task_user_data,
                 union doca_data ctx_user_data)
{
    (void)ctx_user_data;
    llb_kv_compress_ctx_t *ctx = (llb_kv_compress_ctx_t *)task_user_data.ptr;

    struct doca_buf *dst_buf = doca_compress_task_compress_deflate_get_dst(task);
    size_t data_len = 0;
    doca_buf_get_data_len(dst_buf, &data_len);

    ctx->produced_len = data_len;
    ctx->task_result  = LLB_KV_OK;
    ctx->task_done    = 1;

    doca_task_free(doca_compress_task_compress_deflate_as_task(task));
}

static void
compress_error_cb(struct doca_compress_task_compress_deflate *task,
                  union doca_data task_user_data,
                  union doca_data ctx_user_data)
{
    (void)ctx_user_data;
    llb_kv_compress_ctx_t *ctx = (llb_kv_compress_ctx_t *)task_user_data.ptr;

    ctx->produced_len = 0;
    ctx->task_result  = LLB_KV_ERR_HW;
    ctx->task_done    = 1;

    doca_task_free(doca_compress_task_compress_deflate_as_task(task));
}

/* ------------------------------------------------------------------ */
/* Init / Destroy                                                      */
/* ------------------------------------------------------------------ */

llb_kv_compress_ctx_t *
llb_kv_compress_init(void *dev, size_t staging_size)
{
    struct doca_dev *doca_dev = (struct doca_dev *)dev;
    doca_error_t ret;
    llb_kv_compress_ctx_t *ctx;

    if (staging_size == 0)
        return NULL;

    ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;

    /* Auto-open device if caller passes NULL */
    if (!doca_dev) {
        ret = llb_kv_cap_open_device(NULL, &doca_dev);
        if (ret != DOCA_SUCCESS) {
            free(ctx);
            return NULL;
        }
        ctx->dev_owned = 1;
    }

    ctx->dev          = doca_dev;
    ctx->staging_size = staging_size;

    /* 1. Create dedicated PE (avoids head-of-line blocking) */
    ret = doca_pe_create(&ctx->pe);
    if (ret != DOCA_SUCCESS)
        goto err_free;

    /* 2. Create DOCA Compress engine */
    ret = doca_compress_create(doca_dev, &ctx->compress);
    if (ret != DOCA_SUCCESS)
        goto err_pe;

    /* 3. Configure task completion callbacks (log2(64)=6 -> 64 tasks) */
    doca_compress_task_decompress_deflate_set_conf(
        ctx->compress, decompress_done_cb, decompress_error_cb, 6);
    doca_compress_task_compress_deflate_set_conf(
        ctx->compress, compress_done_cb, compress_error_cb, 6);

    /* 4. Connect PE to compress context */
    struct doca_ctx *dctx = doca_compress_as_ctx(ctx->compress);
    ret = doca_pe_connect_ctx(ctx->pe, dctx);
    if (ret != DOCA_SUCCESS)
        goto err_compress;

    /* 5. Allocate staging buffers (plain mmap -- DOCA mmaps are per-call) */
    ctx->src_buf = mmap(NULL, staging_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ctx->src_buf == MAP_FAILED) {
        ctx->src_buf = NULL;
        goto err_compress;
    }

    ctx->dst_buf = mmap(NULL, staging_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ctx->dst_buf == MAP_FAILED) {
        ctx->dst_buf = NULL;
        goto err_src;
    }

    /* 6. Create buffer inventory (2-arg form, DOCA 2.9.4) */
    ret = doca_buf_inventory_create(128, &ctx->buf_inv);
    if (ret != DOCA_SUCCESS)
        goto err_dst;
    ret = doca_buf_inventory_start(ctx->buf_inv);
    if (ret != DOCA_SUCCESS)
        goto err_inv;

    /* 7. Start the compress context */
    ret = doca_ctx_start(dctx);
    if (ret != DOCA_SUCCESS)
        goto err_inv_stop;

    return ctx;

err_inv_stop:
    doca_buf_inventory_stop(ctx->buf_inv);
err_inv:
    doca_buf_inventory_destroy(ctx->buf_inv);
err_dst:
    munmap(ctx->dst_buf, staging_size);
err_src:
    munmap(ctx->src_buf, staging_size);
err_compress:
    doca_compress_destroy(ctx->compress);
err_pe:
    doca_pe_destroy(ctx->pe);
err_free:
    free(ctx);
    return NULL;
}

void
llb_kv_compress_destroy(llb_kv_compress_ctx_t *ctx)
{
    if (!ctx)
        return;

    if (ctx->compress) {
        struct doca_ctx *dctx = doca_compress_as_ctx(ctx->compress);
        doca_ctx_stop(dctx);
    }
    if (ctx->buf_inv) {
        doca_buf_inventory_stop(ctx->buf_inv);
        doca_buf_inventory_destroy(ctx->buf_inv);
    }
    if (ctx->dst_buf)
        munmap(ctx->dst_buf, ctx->staging_size);
    if (ctx->src_buf)
        munmap(ctx->src_buf, ctx->staging_size);

    if (ctx->compress)
        doca_compress_destroy(ctx->compress);
    if (ctx->pe)
        doca_pe_destroy(ctx->pe);
    if (ctx->dev_owned && ctx->dev)
        doca_dev_close(ctx->dev);

    free(ctx);
}

/* ------------------------------------------------------------------ */
/* Decompress (HW Deflate)                                             */
/* ------------------------------------------------------------------ */

int
llb_kv_decompress(llb_kv_compress_ctx_t *ctx,
                  const void *compressed, size_t compressed_len,
                  void *output, size_t output_capacity,
                  size_t *output_len)
{
    struct doca_buf *src_buf = NULL, *dst_buf = NULL;
    struct doca_mmap *call_src_mmap = NULL, *call_dst_mmap = NULL;
    doca_error_t ret;
    int i, rc = LLB_KV_ERR_HW;

    if (!ctx || !compressed || !output || !output_len)
        return LLB_KV_ERR_INTERNAL;
    if (compressed_len > ctx->staging_size || output_capacity > ctx->staging_size)
        return LLB_KV_ERR_BOUNDS;

    /* Copy compressed data into source staging buffer */
    memcpy(ctx->src_buf, compressed, compressed_len);

    /* Create FRESH per-call mmaps (VD16 pattern) */
    ret = doca_mmap_create(&call_src_mmap);
    if (ret != DOCA_SUCCESS)
        return LLB_KV_ERR_HW;
    doca_mmap_add_dev(call_src_mmap, ctx->dev);
    doca_mmap_set_memrange(call_src_mmap, ctx->src_buf, compressed_len);
    ret = doca_mmap_start(call_src_mmap);
    if (ret != DOCA_SUCCESS)
        goto err_src_mmap;

    ret = doca_mmap_create(&call_dst_mmap);
    if (ret != DOCA_SUCCESS)
        goto err_src_mmap_stop;
    doca_mmap_add_dev(call_dst_mmap, ctx->dev);
    doca_mmap_set_memrange(call_dst_mmap, ctx->dst_buf, output_capacity);
    ret = doca_mmap_start(call_dst_mmap);
    if (ret != DOCA_SUCCESS)
        goto err_dst_mmap;

    /* Use buf_get_by_addr (VD16 pattern) */
    ret = doca_buf_inventory_buf_get_by_addr(
        ctx->buf_inv, call_src_mmap,
        ctx->src_buf, compressed_len, &src_buf);
    if (ret != DOCA_SUCCESS)
        goto err_dst_mmap_stop;

    ret = doca_buf_inventory_buf_get_by_addr(
        ctx->buf_inv, call_dst_mmap,
        ctx->dst_buf, output_capacity, &dst_buf);
    if (ret != DOCA_SUCCESS)
        goto err_src_buf;

    /* buf_get_by_addr sets data_len=0; set source data range */
    doca_buf_set_data(src_buf, ctx->src_buf, compressed_len);
    /* Mark dst as empty — output written by HW */
    doca_buf_set_data(dst_buf, ctx->dst_buf, 0);

    /* Allocate and submit decompress task */
    union doca_data ud = { .ptr = ctx };
    struct doca_compress_task_decompress_deflate *task = NULL;

    ret = doca_compress_task_decompress_deflate_alloc_init(
        ctx->compress, src_buf, dst_buf, ud, &task);
    if (ret != DOCA_SUCCESS)
        goto err_dst_buf;

    ret = doca_task_submit(
        doca_compress_task_decompress_deflate_as_task(task));
    if (ret != DOCA_SUCCESS)
        goto err_dst_buf;

    /* PE progress loop with yield to avoid spin starvation */
    ctx->task_done = 0;
    for (i = 0; i < LLB_KV_COMPRESS_PE_MAX_ITERS && !ctx->task_done; i++) {
        doca_pe_progress(ctx->pe);
        if (!ctx->task_done)
            usleep(LLB_KV_COMPRESS_PE_YIELD_US);
    }

    if (!ctx->task_done) {
        rc = LLB_KV_ERR_TIMEOUT;
    } else {
        rc = ctx->task_result;
    }

    /* Copy decompressed data to caller's output buffer on success */
    if (rc == LLB_KV_OK) {
        *output_len = ctx->produced_len;
        if (ctx->produced_len > 0)
            memcpy(output, ctx->dst_buf, ctx->produced_len);

        /* Call dequantize hook if set */
        if (ctx->dequantize_hook)
            ctx->dequantize_hook(output, *output_len, ctx->dequantize_user_ctx);
    }

err_dst_buf:
    doca_buf_dec_refcount(dst_buf, NULL);
err_src_buf:
    doca_buf_dec_refcount(src_buf, NULL);
err_dst_mmap_stop:
    doca_mmap_stop(call_dst_mmap);
err_dst_mmap:
    doca_mmap_destroy(call_dst_mmap);
err_src_mmap_stop:
    doca_mmap_stop(call_src_mmap);
err_src_mmap:
    doca_mmap_destroy(call_src_mmap);

    return rc;
}

/* ------------------------------------------------------------------ */
/* Compress (HW Deflate -- write-back path)                            */
/* ------------------------------------------------------------------ */

int
llb_kv_compress(llb_kv_compress_ctx_t *ctx,
                const void *raw, size_t raw_len,
                void *output, size_t output_capacity,
                size_t *output_len)
{
    struct doca_buf *src_buf = NULL, *dst_buf = NULL;
    struct doca_mmap *call_src_mmap = NULL, *call_dst_mmap = NULL;
    doca_error_t ret;
    int i, rc = LLB_KV_ERR_HW;

    if (!ctx || !raw || !output || !output_len)
        return LLB_KV_ERR_INTERNAL;
    if (raw_len > ctx->staging_size || output_capacity > ctx->staging_size)
        return LLB_KV_ERR_BOUNDS;

    /* Copy raw data into source staging buffer */
    memcpy(ctx->src_buf, raw, raw_len);

    /* Create FRESH per-call mmaps (VD16 pattern) */
    ret = doca_mmap_create(&call_src_mmap);
    if (ret != DOCA_SUCCESS)
        return LLB_KV_ERR_HW;
    doca_mmap_add_dev(call_src_mmap, ctx->dev);
    doca_mmap_set_memrange(call_src_mmap, ctx->src_buf, raw_len);
    ret = doca_mmap_start(call_src_mmap);
    if (ret != DOCA_SUCCESS)
        goto err_src_mmap;

    ret = doca_mmap_create(&call_dst_mmap);
    if (ret != DOCA_SUCCESS)
        goto err_src_mmap_stop;
    doca_mmap_add_dev(call_dst_mmap, ctx->dev);
    doca_mmap_set_memrange(call_dst_mmap, ctx->dst_buf, output_capacity);
    ret = doca_mmap_start(call_dst_mmap);
    if (ret != DOCA_SUCCESS)
        goto err_dst_mmap;

    /* Use buf_get_by_addr (VD16 pattern) */
    ret = doca_buf_inventory_buf_get_by_addr(
        ctx->buf_inv, call_src_mmap,
        ctx->src_buf, raw_len, &src_buf);
    if (ret != DOCA_SUCCESS)
        goto err_dst_mmap_stop;

    ret = doca_buf_inventory_buf_get_by_addr(
        ctx->buf_inv, call_dst_mmap,
        ctx->dst_buf, output_capacity, &dst_buf);
    if (ret != DOCA_SUCCESS)
        goto err_src_buf;

    /* buf_get_by_addr sets data_len=0; set source data range */
    doca_buf_set_data(src_buf, ctx->src_buf, raw_len);
    /* Mark dst as empty — output written by HW */
    doca_buf_set_data(dst_buf, ctx->dst_buf, 0);

    /* Allocate and submit compress task */
    union doca_data ud = { .ptr = ctx };
    struct doca_compress_task_compress_deflate *task = NULL;

    ret = doca_compress_task_compress_deflate_alloc_init(
        ctx->compress, src_buf, dst_buf, ud, &task);
    if (ret != DOCA_SUCCESS)
        goto err_dst_buf;

    ret = doca_task_submit(
        doca_compress_task_compress_deflate_as_task(task));
    if (ret != DOCA_SUCCESS)
        goto err_dst_buf;

    /* PE progress loop with yield */
    ctx->task_done = 0;
    for (i = 0; i < LLB_KV_COMPRESS_PE_MAX_ITERS && !ctx->task_done; i++) {
        doca_pe_progress(ctx->pe);
        if (!ctx->task_done)
            usleep(LLB_KV_COMPRESS_PE_YIELD_US);
    }

    if (!ctx->task_done) {
        rc = LLB_KV_ERR_TIMEOUT;
    } else {
        rc = ctx->task_result;
    }

    /* Copy compressed data to caller's output buffer on success */
    if (rc == LLB_KV_OK) {
        *output_len = ctx->produced_len;
        if (ctx->produced_len > 0)
            memcpy(output, ctx->dst_buf, ctx->produced_len);
    }

err_dst_buf:
    doca_buf_dec_refcount(dst_buf, NULL);
err_src_buf:
    doca_buf_dec_refcount(src_buf, NULL);
err_dst_mmap_stop:
    doca_mmap_stop(call_dst_mmap);
err_dst_mmap:
    doca_mmap_destroy(call_dst_mmap);
err_src_mmap_stop:
    doca_mmap_stop(call_src_mmap);
err_src_mmap:
    doca_mmap_destroy(call_src_mmap);

    return rc;
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
