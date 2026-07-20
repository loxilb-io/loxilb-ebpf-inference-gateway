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
 * loxilb_kv_pipeline_stub.c -- Stub pipeline for non-DOCA builds.
 *
 * Provides the same API surface as loxilb_kv_pipeline.c but uses
 * stub compress (zlib) and stub DMA (memcpy). No ComCh support
 * (REST-triggered only). Enables full CICD testing without DOCA.
 *
 * The state machine logic is identical to the DOCA version --
 * only the GPU mmap lifecycle differs (free() instead of
 * doca_mmap_destroy()).
 */

#include "loxilb_kv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

#define LLB_KV_MAX_CHUNK_DECOMPRESSED   (4 * 1024 * 1024)
#define LLB_KV_MAX_CHUNK_COMPRESSED     (4 * 1024 * 1024)
#define LLB_KV_PIPELINE_POLL_US         100
#define LLB_KV_EVICTION_PROTECT_PCT     50

/* ------------------------------------------------------------------ */
/* Internal session struct                                             */
/* ------------------------------------------------------------------ */

typedef struct {
    kv_session_t        base;
    llb_kv_comch_msg_t  req;
    void               *tcp_conn;
    llb_kv_chunk_hdr_t  cur_chunk;
    void               *chunk_payload;
    void               *decompress_buf;
    size_t              decompress_len;
    size_t              gpu_write_offset;
    void               *gpu_mmap;
    int                 evicting;
    int                 gpu_mmap_owned;
} kv_session_internal_t;

/* ------------------------------------------------------------------ */
/* Pipeline context                                                    */
/* ------------------------------------------------------------------ */

struct llb_kv_pipeline_ctx {
    kv_session_internal_t  sessions[LLB_KV_MAX_SESSIONS];
    int                    session_count;
    volatile int           running;

    llb_kv_transport_ops  *transport;
    llb_kv_compress_ctx_t *compress;
    llb_kv_dma_ctx_t      *dma;
    llb_kv_comch_ctx_t    *comch;   /* always NULL in stub */

    /* v2 fields (4-stage pipeline with ring buffer handoff) */
    int                    use_v2;
    llb_kv_ring_t          decomp_to_deq_ring;
    llb_kv_ring_t          deq_to_dma_ring;
    llb_kv_bufpool_t      *decompress_pool;
    llb_kv_bufpool_t      *dequantize_pool;
    llb_kv_bufpool_t      *dma_src_pool;
    llb_kv_bufpool_t      *gpu_dst_pool;
    llb_kv_dequantize_ctx_t *dequantize;
    llb_kv_affinity_t      affinity;

    uint64_t total_fetches;
    uint64_t total_errors;
    uint64_t total_evictions;
    uint64_t total_bytes_transferred;
};

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static uint64_t
get_time_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int
find_idle_slot(llb_kv_pipeline_ctx_t *ctx)
{
    for (int i = 0; i < LLB_KV_MAX_SESSIONS; i++) {
        if (ctx->sessions[i].base.state == KV_SESSION_IDLE)
            return i;
    }
    return -1;
}

static int
find_eviction_candidate(llb_kv_pipeline_ctx_t *ctx, uint32_t new_priority)
{
    int best = -1;
    float best_progress = 1.0f;

    for (int i = 0; i < LLB_KV_MAX_SESSIONS; i++) {
        kv_session_internal_t *s = &ctx->sessions[i];

        if (s->base.state == KV_SESSION_IDLE ||
            s->base.state == KV_SESSION_ERROR ||
            s->evicting)
            continue;

        if (s->base.priority >= new_priority)
            continue;

        if (s->base.total_chunks > 0) {
            uint32_t pct = (s->base.chunks_done * 100) / s->base.total_chunks;
            if (pct > LLB_KV_EVICTION_PROTECT_PCT)
                continue;
        }

        float progress = (s->base.total_chunks > 0)
            ? (float)s->base.chunks_done / (float)s->base.total_chunks
            : 0.0f;

        if (best < 0 || progress < best_progress) {
            best = i;
            best_progress = progress;
        }
    }

    return best;
}

static void
session_reset(llb_kv_pipeline_ctx_t *ctx, kv_session_internal_t *sess)
{
    if (sess->tcp_conn && ctx->transport && ctx->transport->close) {
        ctx->transport->close(sess->tcp_conn);
        sess->tcp_conn = NULL;
    }

    /* Stub: free() for mock GPU mmap */
    if (sess->gpu_mmap && sess->gpu_mmap_owned) {
        free(sess->gpu_mmap);
        sess->gpu_mmap = NULL;
    }

    free(sess->chunk_payload);
    sess->chunk_payload = NULL;
    free(sess->decompress_buf);
    sess->decompress_buf = NULL;

    memset(&sess->base, 0, sizeof(sess->base));
    sess->base.state = KV_SESSION_IDLE;
    sess->gpu_write_offset = 0;
    sess->evicting = 0;
    sess->gpu_mmap_owned = 0;
    memset(&sess->req, 0, sizeof(sess->req));
    memset(&sess->cur_chunk, 0, sizeof(sess->cur_chunk));
}

static int
allocate_session(llb_kv_pipeline_ctx_t *ctx, uint32_t priority)
{
    int idx = find_idle_slot(ctx);
    if (idx >= 0)
        return idx;

    idx = find_eviction_candidate(ctx, priority);
    if (idx < 0)
        return -1;

    kv_session_internal_t *victim = &ctx->sessions[idx];
    victim->evicting = 1;
    victim->base.state = KV_SESSION_ERROR;

    /* Brief drain (no DOCA PE, just TCP cleanup) */
    if (victim->tcp_conn && ctx->transport && ctx->transport->close) {
        ctx->transport->close(victim->tcp_conn);
        victim->tcp_conn = NULL;
    }

    ctx->total_evictions++;
    session_reset(ctx, victim);

    return idx;
}

/* ------------------------------------------------------------------ */
/* Init                                                                */
/* ------------------------------------------------------------------ */

llb_kv_pipeline_ctx_t *
llb_kv_pipeline_init(llb_kv_transport_ops *transport,
                     llb_kv_compress_ctx_t *compress,
                     llb_kv_dma_ctx_t *dma)
{
    llb_kv_pipeline_ctx_t *ctx;

    ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;

    ctx->transport = transport;
    ctx->compress  = compress;
    ctx->dma       = dma;
    ctx->running   = 1;

    for (int i = 0; i < LLB_KV_MAX_SESSIONS; i++)
        ctx->sessions[i].base.state = KV_SESSION_IDLE;

    return ctx;
}

/* ------------------------------------------------------------------ */
/* Init v2 -- 4-stage pipeline with ring buffer handoff                */
/* ------------------------------------------------------------------ */

llb_kv_pipeline_ctx_t *
llb_kv_pipeline_init_v2(const llb_kv_pipeline_config_t *cfg)
{
    llb_kv_pipeline_ctx_t *ctx;
    int rc;
    int ring_cap;

    if (!cfg || !cfg->transport || !cfg->compress || !cfg->dma)
        return NULL;
    if (!cfg->decompress_pool || !cfg->dequantize_pool)
        return NULL;

    ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;

    ctx->transport = cfg->transport;
    ctx->compress  = cfg->compress;
    ctx->dma       = cfg->dma;
    ctx->running   = 1;
    ctx->use_v2    = 1;

    /* Store buffer pool pointers */
    ctx->decompress_pool = cfg->decompress_pool;
    ctx->dequantize_pool = cfg->dequantize_pool;
    ctx->dma_src_pool    = cfg->dma_src_pool;
    ctx->gpu_dst_pool    = cfg->gpu_dst_pool;

    /* Store affinity if provided */
    if (cfg->affinity)
        memcpy(&ctx->affinity, cfg->affinity, sizeof(ctx->affinity));

    /* Ring capacity: default 128, must be power of 2 */
    ring_cap = cfg->ring_capacity > 0 ? cfg->ring_capacity
                                       : LLB_KV_PIPELINE_DEFAULT_RING_CAP;

    /* Initialize ring buffers for inter-stage handoff */
    rc = llb_kv_ring_init(&ctx->decomp_to_deq_ring, (uint32_t)ring_cap);
    if (rc != LLB_KV_OK)
        goto err_free;

    rc = llb_kv_ring_init(&ctx->deq_to_dma_ring, (uint32_t)ring_cap);
    if (rc != LLB_KV_OK)
        goto err_ring1;

    /* Init dequantize workers */
    int deq_count = cfg->affinity ? cfg->affinity->deq_count : 1;
    if (deq_count < 1) deq_count = 1;

    ctx->dequantize = llb_kv_dequantize_init(
        deq_count,
        &ctx->decomp_to_deq_ring,
        &ctx->deq_to_dma_ring,
        ctx->decompress_pool,
        ctx->dequantize_pool);
    if (!ctx->dequantize)
        goto err_ring2;

    /* Start dequantize workers (with or without affinity) */
    {
        const int *core_ids = cfg->affinity ? cfg->affinity->deq_ids : NULL;
        int num_cores = cfg->affinity ? cfg->affinity->deq_count : 0;
        rc = llb_kv_dequantize_start(ctx->dequantize, core_ids, num_cores);
        if (rc != 0)
            goto err_deq;
    }

    /* Apply ctrl core affinity to pipeline main thread (if provided) */
    if (cfg->affinity && cfg->affinity->ctrl_count > 0) {
        llb_kv_affinity_apply_thread(&cfg->affinity->ctrl_cores);
    }

    /* Initialize all sessions to IDLE */
    for (int i = 0; i < LLB_KV_MAX_SESSIONS; i++)
        ctx->sessions[i].base.state = KV_SESSION_IDLE;

    return ctx;

err_deq:
    llb_kv_dequantize_destroy(ctx->dequantize);
err_ring2:
    llb_kv_ring_destroy(&ctx->deq_to_dma_ring);
err_ring1:
    llb_kv_ring_destroy(&ctx->decomp_to_deq_ring);
err_free:
    free(ctx);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* GPU mmap pre-registration (stub: uses DMA stub's malloc mock)       */
/* ------------------------------------------------------------------ */

int
llb_kv_pipeline_register_gpu_mmap(llb_kv_pipeline_ctx_t *ctx,
                                  uint64_t session_id,
                                  const void *export_desc,
                                  size_t desc_len)
{
    int idx;

    if (!ctx || !export_desc || desc_len == 0)
        return LLB_KV_ERR_INTERNAL;

    idx = find_idle_slot(ctx);
    if (idx < 0)
        return LLB_KV_ERR_NO_SESSION;

    kv_session_internal_t *sess = &ctx->sessions[idx];
    sess->base.session_id = session_id;

    int rc = llb_kv_dma_import_gpu_mmap(ctx->dma, export_desc, desc_len,
                                         &sess->gpu_mmap);
    if (rc != LLB_KV_OK)
        return rc;

    sess->gpu_mmap_owned = 1;
    return LLB_KV_OK;
}

/* ------------------------------------------------------------------ */
/* Fetch start                                                         */
/* ------------------------------------------------------------------ */

int
llb_kv_pipeline_fetch_start(llb_kv_pipeline_ctx_t *ctx,
                            const llb_kv_comch_msg_t *msg)
{
    int idx;
    kv_session_internal_t *sess;
    int rc;

    if (!ctx || !msg)
        return LLB_KV_ERR_INTERNAL;

    /* Check for pre-registered session */
    for (int i = 0; i < LLB_KV_MAX_SESSIONS; i++) {
        if (ctx->sessions[i].base.state == KV_SESSION_IDLE &&
            ctx->sessions[i].base.session_id == msg->session_id &&
            ctx->sessions[i].gpu_mmap != NULL) {
            idx = i;
            goto found;
        }
    }

    idx = allocate_session(ctx, msg->priority);
    if (idx < 0)
        return LLB_KV_ERR_NO_SESSION;

found:
    sess = &ctx->sessions[idx];

    memcpy(&sess->req, msg, sizeof(*msg));
    sess->base.session_id   = msg->session_id;
    sess->base.priority     = msg->priority;
    sess->base.total_chunks = msg->total_chunks;
    sess->base.chunks_done  = 0;
    sess->base.total_bytes  = 0;
    sess->base.start_ns     = get_time_ns();
    sess->gpu_write_offset  = msg->gpu_base_offset;

    if (!sess->chunk_payload) {
        sess->chunk_payload = malloc(LLB_KV_MAX_CHUNK_COMPRESSED);
        if (!sess->chunk_payload) {
            session_reset(ctx, sess);
            return LLB_KV_ERR_NOMEM;
        }
    }
    if (!sess->decompress_buf) {
        sess->decompress_buf = malloc(LLB_KV_MAX_CHUNK_DECOMPRESSED);
        if (!sess->decompress_buf) {
            session_reset(ctx, sess);
            return LLB_KV_ERR_NOMEM;
        }
    }

    if (!ctx->transport || !ctx->transport->connect) {
        session_reset(ctx, sess);
        return LLB_KV_ERR_INTERNAL;
    }

    rc = ctx->transport->connect(msg->kv_store_host, msg->kv_store_port,
                                  &sess->tcp_conn);
    if (rc != LLB_KV_OK) {
        ctx->total_errors++;
        session_reset(ctx, sess);
        return rc;
    }

    sess->base.state = KV_SESSION_TCP_RECV;
    ctx->total_fetches++;
    ctx->session_count++;

    return LLB_KV_OK;
}

/* ------------------------------------------------------------------ */
/* Write-back start                                                    */
/* ------------------------------------------------------------------ */

int
llb_kv_pipeline_writeback_start(llb_kv_pipeline_ctx_t *ctx,
                                const llb_kv_comch_msg_t *msg)
{
    int idx;
    kv_session_internal_t *sess;

    if (!ctx || !msg)
        return LLB_KV_ERR_INTERNAL;

    idx = allocate_session(ctx, msg->priority);
    if (idx < 0)
        return LLB_KV_ERR_NO_SESSION;

    sess = &ctx->sessions[idx];

    memcpy(&sess->req, msg, sizeof(*msg));
    sess->base.session_id   = msg->session_id;
    sess->base.priority     = msg->priority;
    sess->base.total_chunks = msg->total_chunks;
    sess->base.chunks_done  = 0;
    sess->base.total_bytes  = 0;
    sess->base.start_ns     = get_time_ns();
    sess->gpu_write_offset  = msg->gpu_base_offset;

    if (!sess->decompress_buf) {
        sess->decompress_buf = malloc(LLB_KV_MAX_CHUNK_DECOMPRESSED);
        if (!sess->decompress_buf) {
            session_reset(ctx, sess);
            return LLB_KV_ERR_NOMEM;
        }
    }
    if (!sess->chunk_payload) {
        sess->chunk_payload = malloc(LLB_KV_MAX_CHUNK_COMPRESSED);
        if (!sess->chunk_payload) {
            session_reset(ctx, sess);
            return LLB_KV_ERR_NOMEM;
        }
    }

    sess->base.state = KV_SESSION_WRITEBACK_DMA;
    ctx->session_count++;

    return LLB_KV_OK;
}

/* ------------------------------------------------------------------ */
/* Process one session (identical state machine to DOCA version)        */
/* ------------------------------------------------------------------ */

static void
process_session(llb_kv_pipeline_ctx_t *ctx, kv_session_internal_t *sess)
{
    int rc;

    switch (sess->base.state) {

    case KV_SESSION_TCP_RECV:
        rc = llb_kv_recv_chunk(ctx->transport, sess->tcp_conn,
                               &sess->cur_chunk,
                               sess->chunk_payload,
                               LLB_KV_MAX_CHUNK_COMPRESSED,
                               5000);
        if (rc != LLB_KV_OK) {
            sess->base.state = KV_SESSION_ERROR;
            break;
        }
        sess->base.state = KV_SESSION_DECOMPRESS;
        break;

    case KV_SESSION_DECOMPRESS:
        if (ctx->use_v2) {
            /* v2: decompress into bufpool slot, push to ring */
            int slot = llb_kv_bufpool_alloc(ctx->decompress_pool);
            if (slot < 0) {
                /* Pool full -- backpressure, stay in DECOMPRESS */
                break;
            }
            void *slot_buf = llb_kv_bufpool_slot_ptr(ctx->decompress_pool, slot);
            sess->decompress_len = 0;
            rc = llb_kv_decompress(ctx->compress,
                                   sess->chunk_payload,
                                   sess->cur_chunk.compressed_len,
                                   slot_buf,
                                   ctx->decompress_pool->slot_size,
                                   &sess->decompress_len);
            if (rc != LLB_KV_OK) {
                llb_kv_bufpool_free(ctx->decompress_pool, slot);
                sess->base.state = KV_SESSION_ERROR;
                break;
            }
            /* Push to decompress->dequantize ring */
            llb_kv_ring_elem_t elem = {
                .slot_idx   = (uint32_t)slot,
                .data_len   = (uint32_t)sess->decompress_len,
                .session_id = sess->base.session_id,
            };
            if (llb_kv_ring_push(&ctx->decomp_to_deq_ring, &elem) != 0) {
                /* Ring full -- free slot, stay in DECOMPRESS (backpressure) */
                llb_kv_bufpool_free(ctx->decompress_pool, slot);
                break;
            }
            sess->base.state = KV_SESSION_DEQUANTIZE;
        } else {
            /* v1: inline decompress -> DMA (legacy 3-stage) */
            sess->decompress_len = 0;
            rc = llb_kv_decompress(ctx->compress,
                                   sess->chunk_payload,
                                   sess->cur_chunk.compressed_len,
                                   sess->decompress_buf,
                                   LLB_KV_MAX_CHUNK_DECOMPRESSED,
                                   &sess->decompress_len);
            if (rc != LLB_KV_OK) {
                sess->base.state = KV_SESSION_ERROR;
                break;
            }
            sess->base.state = KV_SESSION_DMA_TRANSFER;
        }
        break;

    case KV_SESSION_DEQUANTIZE:
        /* v2 only: poll deq_to_dma_ring for this session's output */
        {
            llb_kv_ring_elem_t out;
            if (llb_kv_ring_pop(&ctx->deq_to_dma_ring, &out) != 0) {
                /* Workers still processing -- stay in DEQUANTIZE */
                break;
            }
            /* Check session_id match */
            if (out.session_id != sess->base.session_id) {
                /* Not ours -- push back and retry later.
                 * In practice with single-session tests this won't happen,
                 * but for multi-session, we'd need a per-session queue.
                 * For now, push back to ring (other sessions will find theirs). */
                llb_kv_ring_push(&ctx->deq_to_dma_ring, &out);
                break;
            }
            /* Store FP16 output info for DMA stage */
            sess->decompress_len = out.data_len;
            /* The FP16 data is in dequantize_pool at out.slot_idx.
             * Copy it to decompress_buf for DMA (or use pool directly).
             * In v2, DMA reads from dequantize_pool slot. */
            void *fp16_buf = llb_kv_bufpool_slot_ptr(ctx->dequantize_pool,
                                                      (int)out.slot_idx);
            if (fp16_buf && sess->decompress_buf) {
                size_t copy_len = out.data_len;
                if (copy_len > LLB_KV_MAX_CHUNK_DECOMPRESSED)
                    copy_len = LLB_KV_MAX_CHUNK_DECOMPRESSED;
                memcpy(sess->decompress_buf, fp16_buf, copy_len);
            }
            /* Free dequantize pool slot */
            llb_kv_bufpool_free(ctx->dequantize_pool, (int)out.slot_idx);
            sess->base.state = KV_SESSION_DMA_TRANSFER;
        }
        break;

    case KV_SESSION_DMA_TRANSFER:
        rc = llb_kv_dma_to_gpu(ctx->dma, sess->gpu_mmap,
                               sess->decompress_buf,
                               sess->decompress_len,
                               sess->gpu_write_offset);
        if (rc != LLB_KV_OK) {
            sess->base.state = KV_SESSION_ERROR;
            break;
        }
        sess->gpu_write_offset += sess->decompress_len;
        sess->base.chunks_done++;
        sess->base.total_bytes += sess->decompress_len;
        ctx->total_bytes_transferred += sess->decompress_len;

        if (sess->base.chunks_done >= sess->base.total_chunks)
            sess->base.state = KV_SESSION_DONE;
        else
            sess->base.state = KV_SESSION_TCP_RECV;
        break;

    case KV_SESSION_WRITEBACK_DMA:
        if (!sess->gpu_mmap) {
            sess->base.state = KV_SESSION_ERROR;
            break;
        }
        {
            size_t read_len = sess->req.original_size;
            if (read_len > LLB_KV_MAX_CHUNK_DECOMPRESSED)
                read_len = LLB_KV_MAX_CHUNK_DECOMPRESSED;

            rc = llb_kv_dma_from_gpu(ctx->dma, sess->gpu_mmap,
                                     sess->gpu_write_offset,
                                     read_len,
                                     sess->decompress_buf);
            if (rc != LLB_KV_OK) {
                sess->base.state = KV_SESSION_ERROR;
                break;
            }
            sess->decompress_len = read_len;
            sess->gpu_write_offset += read_len;
        }
        sess->base.state = KV_SESSION_COMPRESS;
        break;

    case KV_SESSION_COMPRESS:
        {
            size_t compressed_len = 0;
            rc = llb_kv_compress(ctx->compress,
                                 sess->decompress_buf,
                                 sess->decompress_len,
                                 sess->chunk_payload,
                                 LLB_KV_MAX_CHUNK_COMPRESSED,
                                 &compressed_len);
            if (rc != LLB_KV_OK) {
                sess->base.state = KV_SESSION_ERROR;
                break;
            }
            sess->cur_chunk.compressed_len = (uint32_t)compressed_len;
            sess->base.total_bytes += compressed_len;
            ctx->total_bytes_transferred += compressed_len;
        }
        sess->base.state = KV_SESSION_WRITEBACK_TCP;
        break;

    case KV_SESSION_WRITEBACK_TCP:
        if (!sess->tcp_conn && ctx->transport && ctx->transport->connect) {
            rc = ctx->transport->connect(sess->req.kv_store_host,
                                          sess->req.kv_store_port,
                                          &sess->tcp_conn);
            if (rc != LLB_KV_OK) {
                sess->base.state = KV_SESSION_ERROR;
                break;
            }
        }

        if (ctx->transport && ctx->transport->send_all) {
            uint8_t hdr_buf[sizeof(llb_kv_chunk_hdr_t)];
            llb_kv_chunk_hdr_serialize(&sess->cur_chunk, hdr_buf,
                                       sizeof(hdr_buf));
            rc = ctx->transport->send_all(sess->tcp_conn, hdr_buf,
                                           sizeof(hdr_buf));
            if (rc != LLB_KV_OK) {
                sess->base.state = KV_SESSION_ERROR;
                break;
            }
            rc = ctx->transport->send_all(sess->tcp_conn,
                                           sess->chunk_payload,
                                           sess->cur_chunk.compressed_len);
            if (rc != LLB_KV_OK) {
                sess->base.state = KV_SESSION_ERROR;
                break;
            }
        }

        sess->base.chunks_done++;
        if (sess->base.chunks_done >= sess->base.total_chunks)
            sess->base.state = KV_SESSION_WRITEBACK_DONE;
        else
            sess->base.state = KV_SESSION_WRITEBACK_DMA;
        break;

    case KV_SESSION_WRITEBACK_DONE:
        /* No ComCh in stub -- session completes silently */
        session_reset(ctx, sess);
        ctx->session_count--;
        break;

    case KV_SESSION_DONE:
        /* No ComCh in stub */
        session_reset(ctx, sess);
        ctx->session_count--;
        break;

    case KV_SESSION_ERROR:
        ctx->total_errors++;
        session_reset(ctx, sess);
        ctx->session_count--;
        break;

    case KV_SESSION_IDLE:
    default:
        break;
    }
}

/* ------------------------------------------------------------------ */
/* Process all active sessions                                         */
/* ------------------------------------------------------------------ */

int
llb_kv_pipeline_process(llb_kv_pipeline_ctx_t *ctx)
{
    if (!ctx)
        return LLB_KV_ERR_INTERNAL;

    for (int i = 0; i < LLB_KV_MAX_SESSIONS; i++) {
        if (ctx->sessions[i].base.state != KV_SESSION_IDLE)
            process_session(ctx, &ctx->sessions[i]);
    }
    return LLB_KV_OK;
}

/* ------------------------------------------------------------------ */
/* Main event loop (stub: no ComCh polling)                            */
/* ------------------------------------------------------------------ */

int
llb_kv_pipeline_run(llb_kv_pipeline_ctx_t *ctx)
{
    if (!ctx)
        return LLB_KV_ERR_INTERNAL;

    while (ctx->running) {
        llb_kv_pipeline_process(ctx);
        usleep(LLB_KV_PIPELINE_POLL_US);
    }

    return LLB_KV_OK;
}

/* ------------------------------------------------------------------ */
/* Set ComCh (stub: no-op)                                             */
/* ------------------------------------------------------------------ */

void
llb_kv_pipeline_set_comch(llb_kv_pipeline_ctx_t *ctx,
                          llb_kv_comch_ctx_t *comch)
{
    if (ctx)
        ctx->comch = comch;
}

/* ------------------------------------------------------------------ */
/* Statistics                                                          */
/* ------------------------------------------------------------------ */

void
llb_kv_pipeline_get_stats(llb_kv_pipeline_ctx_t *ctx,
                          uint64_t *fetches, uint64_t *errors,
                          uint64_t *evictions, uint64_t *bytes)
{
    if (!ctx)
        return;
    if (fetches)   *fetches   = ctx->total_fetches;
    if (errors)    *errors    = ctx->total_errors;
    if (evictions) *evictions = ctx->total_evictions;
    if (bytes)     *bytes     = ctx->total_bytes_transferred;
}

/* ------------------------------------------------------------------ */
/* Stop                                                                */
/* ------------------------------------------------------------------ */

int
llb_kv_pipeline_session_count(llb_kv_pipeline_ctx_t *ctx)
{
    return ctx ? ctx->session_count : 0;
}

void
llb_kv_pipeline_stop(llb_kv_pipeline_ctx_t *ctx)
{
    if (ctx)
        ctx->running = 0;
}

/* ------------------------------------------------------------------ */
/* Destroy                                                             */
/* ------------------------------------------------------------------ */

void
llb_kv_pipeline_destroy(llb_kv_pipeline_ctx_t *ctx)
{
    if (!ctx)
        return;

    ctx->running = 0;

    /* Stop dequantize workers (v2) before session cleanup */
    if (ctx->use_v2 && ctx->dequantize) {
        llb_kv_dequantize_stop(ctx->dequantize);
        llb_kv_dequantize_destroy(ctx->dequantize);
        ctx->dequantize = NULL;
    }

    for (int i = 0; i < LLB_KV_MAX_SESSIONS; i++) {
        if (ctx->sessions[i].base.state != KV_SESSION_IDLE)
            session_reset(ctx, &ctx->sessions[i]);
    }

    /* Destroy ring buffers (v2) */
    if (ctx->use_v2) {
        llb_kv_ring_destroy(&ctx->decomp_to_deq_ring);
        llb_kv_ring_destroy(&ctx->deq_to_dma_ring);
    }

    free(ctx);
}
