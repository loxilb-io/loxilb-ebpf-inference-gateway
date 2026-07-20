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
 * loxilb_kv_dma.c -- DOCA DMA P2P transfer for the KV pipeline.
 *
 * Compiled only when HAVE_DOCA=1. Provides asynchronous DMA transfers
 * between BF2 DDR staging buffers and GPU HBM via DOCA DMA engine.
 * Uses a dedicated PE instance (separate from compress PE per DOCA
 * pitfall #1: one PE per context type).
 *
 * GPU HBM mapping is per-session via doca_mmap_create_from_export(),
 * supporting up to 64 concurrent sessions targeting different GPU
 * HBM regions.
 */

#include "loxilb_kv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sched.h>

#include <doca_dma.h>
#include <doca_pe.h>
#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_mmap.h>
#include <doca_ctx.h>
#include <doca_dev.h>

/* ------------------------------------------------------------------ */
/* DMA context (full definition -- opaque to callers via header)        */
/* ------------------------------------------------------------------ */

struct llb_kv_dma_ctx {
    struct doca_dma            *dma;
    struct doca_pe             *pe;           /* Dedicated PE (separate from compress) */
    struct doca_dev            *dev;          /* Saved for per-session mmap import     */
    struct doca_buf_inventory  *buf_inv;
    void                       *local_buf;    /* Pre-allocated DDR staging             */
    size_t                      local_buf_size;
    volatile int                task_done;
    int                         task_result;
    int                         dev_owned;    /* 1 if we opened the device */
};

/* Max outstanding DMA tasks */
#define DMA_MAX_TASKS 64

/* Buffer inventory size */
#define DMA_BUF_INV_SIZE 128

/* ------------------------------------------------------------------ */
/* Callbacks                                                           */
/* ------------------------------------------------------------------ */

static void
dma_done_cb(struct doca_dma_task_memcpy *task,
            union doca_data task_user_data,
            union doca_data ctx_user_data)
{
    llb_kv_dma_ctx_t *ctx = (llb_kv_dma_ctx_t *)ctx_user_data.ptr;

    (void)task;
    (void)task_user_data;

    ctx->task_result = LLB_KV_OK;
    ctx->task_done   = 1;
}

static void
dma_error_cb(struct doca_dma_task_memcpy *task,
             union doca_data task_user_data,
             union doca_data ctx_user_data)
{
    llb_kv_dma_ctx_t *ctx = (llb_kv_dma_ctx_t *)ctx_user_data.ptr;

    (void)task;
    (void)task_user_data;

    ctx->task_result = LLB_KV_ERR_HW;
    ctx->task_done   = 1;
}

/* ------------------------------------------------------------------ */
/* Init                                                                */
/* ------------------------------------------------------------------ */

llb_kv_dma_ctx_t *
llb_kv_dma_init(void *dev, size_t staging_size)
{
    struct doca_dev *ddev = (struct doca_dev *)dev;
    llb_kv_dma_ctx_t *ctx;
    union doca_data ctx_data = { 0 };
    doca_error_t rc;

    if (staging_size == 0)
        return NULL;

    ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;

    /* Auto-open device if caller passes NULL */
    if (!ddev) {
        doca_error_t drc = llb_kv_cap_open_device(NULL, &ddev);
        if (drc != DOCA_SUCCESS) {
            free(ctx);
            return NULL;
        }
        ctx->dev_owned = 1;
    }

    ctx->dev = ddev;
    ctx->local_buf_size = staging_size;

    /* 1. Create dedicated PE for DMA (separate from compress PE) */
    rc = doca_pe_create(&ctx->pe);
    if (rc != DOCA_SUCCESS) {
        fprintf(stderr, "kv_dma: PE create failed: %s\n",
                doca_error_get_descr(rc));
        goto err_free;
    }

    /* 2. Create DMA engine */
    rc = doca_dma_create(ddev, &ctx->dma);
    if (rc != DOCA_SUCCESS) {
        fprintf(stderr, "kv_dma: DMA create failed: %s\n",
                doca_error_get_descr(rc));
        goto err_pe;
    }

    /* 3. Set task callbacks */
    rc = doca_dma_task_memcpy_set_conf(ctx->dma, dma_done_cb,
                                       dma_error_cb, DMA_MAX_TASKS);
    if (rc != DOCA_SUCCESS) {
        fprintf(stderr, "kv_dma: set conf failed: %s\n",
                doca_error_get_descr(rc));
        goto err_dma;
    }

    /* 4. Connect DMA context to PE */
    ctx_data.ptr = ctx;
    rc = doca_pe_connect_ctx(ctx->pe, doca_dma_as_ctx(ctx->dma));
    if (rc != DOCA_SUCCESS) {
        fprintf(stderr, "kv_dma: PE connect failed: %s\n",
                doca_error_get_descr(rc));
        goto err_dma;
    }

    /* Set user data on context for callback access */
    rc = doca_ctx_set_user_data(doca_dma_as_ctx(ctx->dma), ctx_data);
    if (rc != DOCA_SUCCESS) {
        fprintf(stderr, "kv_dma: set user data failed: %s\n",
                doca_error_get_descr(rc));
        goto err_dma;
    }

    /* 5. Allocate local staging buffer (plain mmap -- DOCA mmaps are per-call) */
    ctx->local_buf = mmap(NULL, staging_size,
                          PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ctx->local_buf == MAP_FAILED) {
        fprintf(stderr, "kv_dma: staging mmap failed\n");
        ctx->local_buf = NULL;
        goto err_dma;
    }

    /* 6. Create buffer inventory */
    rc = doca_buf_inventory_create(DMA_BUF_INV_SIZE, &ctx->buf_inv);
    if (rc != DOCA_SUCCESS) {
        fprintf(stderr, "kv_dma: buf inventory create failed: %s\n",
                doca_error_get_descr(rc));
        goto err_staging;
    }

    rc = doca_buf_inventory_start(ctx->buf_inv);
    if (rc != DOCA_SUCCESS) {
        fprintf(stderr, "kv_dma: buf inventory start failed: %s\n",
                doca_error_get_descr(rc));
        goto err_buf_inv;
    }

    /* 8. Start DMA context */
    rc = doca_ctx_start(doca_dma_as_ctx(ctx->dma));
    if (rc != DOCA_SUCCESS) {
        fprintf(stderr, "kv_dma: ctx start failed: %s\n",
                doca_error_get_descr(rc));
        goto err_buf_inv;
    }

    return ctx;

err_buf_inv:
    doca_buf_inventory_destroy(ctx->buf_inv);
err_staging:
    munmap(ctx->local_buf, staging_size);
    ctx->local_buf = NULL;
err_dma:
    doca_dma_destroy(ctx->dma);
err_pe:
    doca_pe_destroy(ctx->pe);
err_free:
    free(ctx);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Per-session GPU mmap import                                         */
/* ------------------------------------------------------------------ */

int
llb_kv_dma_import_gpu_mmap(llb_kv_dma_ctx_t *ctx,
                           const void *export_desc, size_t desc_len,
                           void **out_gpu_mmap)
{
    struct doca_mmap *gpu_mmap = NULL;
    doca_error_t rc;

    if (!ctx || !export_desc || desc_len == 0 || !out_gpu_mmap)
        return LLB_KV_ERR_INTERNAL;

    /*
     * Import remote memory from host-side export descriptor.
     * The host calls doca_mmap_export_pci() on GPU HBM and delivers
     * the opaque descriptor via POST /kv/session (Plan 39-06).
     * Pattern follows dma_copy_host_sample.c.
     */
    rc = doca_mmap_create_from_export(NULL, export_desc, desc_len,
                                      ctx->dev, &gpu_mmap);
    if (rc != DOCA_SUCCESS) {
        fprintf(stderr, "kv_dma: GPU mmap import failed: %s\n",
                doca_error_get_descr(rc));
        *out_gpu_mmap = NULL;
        return LLB_KV_ERR_HW;
    }

    *out_gpu_mmap = gpu_mmap;
    return LLB_KV_OK;
}

/* ------------------------------------------------------------------ */
/* Transfer to GPU (BF2 DDR -> GPU HBM)                                */
/* ------------------------------------------------------------------ */

int
llb_kv_dma_to_gpu(llb_kv_dma_ctx_t *ctx, void *gpu_mmap,
                  const void *src, size_t len, size_t gpu_offset)
{
    struct doca_mmap *gmmap = (struct doca_mmap *)gpu_mmap;
    struct doca_mmap *call_local_mmap = NULL;
    struct doca_buf *src_buf = NULL, *dst_buf = NULL;
    struct doca_dma_task_memcpy *task = NULL;
    doca_error_t rc;
    int result = LLB_KV_ERR_HW;

    if (!ctx || !gmmap || !src || len == 0)
        return LLB_KV_ERR_INTERNAL;

    /* Validate against local staging capacity */
    if (len > ctx->local_buf_size)
        return LLB_KV_ERR_BOUNDS;

    /* Copy source data into local staging */
    memcpy(ctx->local_buf, src, len);

    /* Create FRESH per-call local mmap (VD17 pattern) */
    rc = doca_mmap_create(&call_local_mmap);
    if (rc != DOCA_SUCCESS)
        return LLB_KV_ERR_HW;
    doca_mmap_add_dev(call_local_mmap, ctx->dev);
    doca_mmap_set_memrange(call_local_mmap, ctx->local_buf, len);
    rc = doca_mmap_start(call_local_mmap);
    if (rc != DOCA_SUCCESS) {
        doca_mmap_destroy(call_local_mmap);
        return LLB_KV_ERR_HW;
    }

    /* Create source buf from per-call local mmap (VD17 pattern) */
    rc = doca_buf_inventory_buf_get_by_addr(ctx->buf_inv, call_local_mmap,
                                            ctx->local_buf, len, &src_buf);
    if (rc != DOCA_SUCCESS) {
        fprintf(stderr, "kv_dma: src buf get failed: %s\n",
                doca_error_get_descr(rc));
        goto err_local_mmap;
    }

    /* Set data on src buf */
    doca_buf_set_data(src_buf, ctx->local_buf, len);

    /* Create dest buf from GPU mmap at gpu_offset */
    rc = doca_buf_inventory_buf_get_by_addr(ctx->buf_inv, gmmap,
                                            (void *)((uintptr_t)0 + gpu_offset),
                                            len, &dst_buf);
    if (rc != DOCA_SUCCESS) {
        fprintf(stderr, "kv_dma: dst buf get failed (bounds?): %s\n",
                doca_error_get_descr(rc));
        result = LLB_KV_ERR_BOUNDS;
        goto err_src_buf;
    }

    /* Mark dst as empty write destination */
    doca_buf_set_data(dst_buf, (void *)((uintptr_t)0 + gpu_offset), 0);

    /* Allocate and submit DMA memcpy task */
    rc = doca_dma_task_memcpy_alloc_init(ctx->dma, src_buf, dst_buf,
                                         (union doca_data){ 0 }, &task);
    if (rc != DOCA_SUCCESS) {
        fprintf(stderr, "kv_dma: task alloc failed: %s\n",
                doca_error_get_descr(rc));
        goto err_dst_buf;
    }

    ctx->task_done = 0;
    ctx->task_result = LLB_KV_ERR_HW;

    rc = doca_task_submit(doca_dma_task_memcpy_as_task(task));
    if (rc != DOCA_SUCCESS) {
        fprintf(stderr, "kv_dma: task submit failed: %s\n",
                doca_error_get_descr(rc));
        doca_task_free(doca_dma_task_memcpy_as_task(task));
        goto err_dst_buf;
    }

    /* PE progress loop with yield */
    while (!ctx->task_done) {
        (void)doca_pe_progress(ctx->pe);
        sched_yield();
    }

    result = ctx->task_result;

err_dst_buf:
    doca_buf_dec_refcount(dst_buf, NULL);
err_src_buf:
    doca_buf_dec_refcount(src_buf, NULL);
err_local_mmap:
    doca_mmap_stop(call_local_mmap);
    doca_mmap_destroy(call_local_mmap);

    return result;
}

/* ------------------------------------------------------------------ */
/* Transfer from GPU (GPU HBM -> BF2 DDR)                              */
/* ------------------------------------------------------------------ */

int
llb_kv_dma_from_gpu(llb_kv_dma_ctx_t *ctx, void *gpu_mmap,
                    size_t gpu_offset, size_t len, void *dst)
{
    struct doca_mmap *gmmap = (struct doca_mmap *)gpu_mmap;
    struct doca_mmap *call_local_mmap = NULL;
    struct doca_buf *src_buf = NULL, *dst_buf = NULL;
    struct doca_dma_task_memcpy *task = NULL;
    doca_error_t rc;
    int result = LLB_KV_ERR_HW;

    if (!ctx || !gmmap || !dst || len == 0)
        return LLB_KV_ERR_INTERNAL;

    /* Validate against local staging capacity */
    if (len > ctx->local_buf_size)
        return LLB_KV_ERR_BOUNDS;

    /* Create source buf from GPU mmap at gpu_offset (remote memory) */
    rc = doca_buf_inventory_buf_get_by_addr(ctx->buf_inv, gmmap,
                                            (void *)((uintptr_t)0 + gpu_offset),
                                            len, &src_buf);
    if (rc != DOCA_SUCCESS) {
        fprintf(stderr, "kv_dma: gpu src buf get failed (bounds?): %s\n",
                doca_error_get_descr(rc));
        return LLB_KV_ERR_BOUNDS;
    }

    /* Set data on source buf */
    doca_buf_set_data(src_buf, (void *)((uintptr_t)0 + gpu_offset), len);

    /* Create FRESH per-call local mmap for dst (VD17 pattern) */
    rc = doca_mmap_create(&call_local_mmap);
    if (rc != DOCA_SUCCESS) {
        doca_buf_dec_refcount(src_buf, NULL);
        return LLB_KV_ERR_HW;
    }
    doca_mmap_add_dev(call_local_mmap, ctx->dev);
    doca_mmap_set_memrange(call_local_mmap, ctx->local_buf, len);
    rc = doca_mmap_start(call_local_mmap);
    if (rc != DOCA_SUCCESS) {
        doca_mmap_destroy(call_local_mmap);
        doca_buf_dec_refcount(src_buf, NULL);
        return LLB_KV_ERR_HW;
    }

    /* Create dest buf from per-call local mmap (VD17 pattern) */
    rc = doca_buf_inventory_buf_get_by_addr(ctx->buf_inv, call_local_mmap,
                                            ctx->local_buf, len, &dst_buf);
    if (rc != DOCA_SUCCESS) {
        fprintf(stderr, "kv_dma: local dst buf get failed: %s\n",
                doca_error_get_descr(rc));
        goto err_local_mmap;
    }

    /* Mark dst as empty write destination */
    doca_buf_set_data(dst_buf, ctx->local_buf, 0);

    /* Allocate and submit DMA memcpy task */
    rc = doca_dma_task_memcpy_alloc_init(ctx->dma, src_buf, dst_buf,
                                         (union doca_data){ 0 }, &task);
    if (rc != DOCA_SUCCESS) {
        fprintf(stderr, "kv_dma: task alloc failed: %s\n",
                doca_error_get_descr(rc));
        goto err_dst_buf;
    }

    ctx->task_done = 0;
    ctx->task_result = LLB_KV_ERR_HW;

    rc = doca_task_submit(doca_dma_task_memcpy_as_task(task));
    if (rc != DOCA_SUCCESS) {
        fprintf(stderr, "kv_dma: task submit failed: %s\n",
                doca_error_get_descr(rc));
        doca_task_free(doca_dma_task_memcpy_as_task(task));
        goto err_dst_buf;
    }

    /* PE progress loop with yield */
    while (!ctx->task_done) {
        (void)doca_pe_progress(ctx->pe);
        sched_yield();
    }

    /* Copy result from local staging to caller's destination */
    if (ctx->task_result == LLB_KV_OK)
        memcpy(dst, ctx->local_buf, len);

    result = ctx->task_result;

err_dst_buf:
    doca_buf_dec_refcount(dst_buf, NULL);
err_local_mmap:
    doca_buf_dec_refcount(src_buf, NULL);
    doca_mmap_stop(call_local_mmap);
    doca_mmap_destroy(call_local_mmap);

    return result;
}

/* ------------------------------------------------------------------ */
/* Destroy                                                             */
/* ------------------------------------------------------------------ */

void
llb_kv_dma_destroy(llb_kv_dma_ctx_t *ctx)
{
    if (!ctx)
        return;

    if (ctx->dma) {
        (void)doca_ctx_stop(doca_dma_as_ctx(ctx->dma));
        doca_dma_destroy(ctx->dma);
    }

    if (ctx->buf_inv) {
        (void)doca_buf_inventory_stop(ctx->buf_inv);
        doca_buf_inventory_destroy(ctx->buf_inv);
    }

    if (ctx->local_buf)
        munmap(ctx->local_buf, ctx->local_buf_size);

    if (ctx->pe)
        doca_pe_destroy(ctx->pe);
    if (ctx->dev_owned && ctx->dev)
        doca_dev_close(ctx->dev);

    free(ctx);
}
