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
 * loxilb_kv_comch.c -- DOCA ComCh server for KV pipeline IPC.
 *
 * Implements the BF ARM-side ComCh server that receives KV_FETCH_REQ
 * and KV_WRITEBACK_REQ messages from the vLLM host and dispatches
 * them to the pipeline orchestrator. Sends KV_FETCH_DONE and
 * KV_WRITEBACK_DONE responses back.
 *
 * Follows the DOCA 2.9.4 PE-driven server/client architecture
 * from vd11_comch.c (ground truth reference).
 *
 * Build: HAVE_DOCA=1 only (requires DOCA SDK + representor device).
 */

#include "loxilb_kv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <doca_comch.h>
#include <doca_pe.h>
#include <doca_ctx.h>
#include <doca_dev.h>

/* Service name: must match what the vLLM host client uses */
#define LLB_KV_COMCH_SVC_NAME  "loxilb-kv-channel"

/* Send task pool size */
#define LLB_KV_COMCH_SEND_POOL  64

/* Recv queue depth */
#define LLB_KV_COMCH_RECV_QUEUE 128

/* ------------------------------------------------------------------ */
/* ComCh context (full definition -- opaque to callers)                */
/* ------------------------------------------------------------------ */

struct llb_kv_comch_ctx {
    struct doca_comch_server    *server;
    struct doca_pe             *pe;
    struct doca_comch_connection *conn;     /* current active connection   */
    llb_kv_pipeline_ctx_t      *pipeline;  /* back-pointer for dispatch   */
    volatile int                connected; /* 1 = host client connected   */
};

/* ------------------------------------------------------------------ */
/* PE Callbacks (DOCA 2.9.4 architecture)                              */
/* ------------------------------------------------------------------ */

/*
 * Message receive callback -- dispatches to pipeline based on msg_type.
 */
static void
comch_recv_cb(struct doca_comch_event_msg_recv *event,
              uint8_t *recv_buffer, uint32_t msg_len,
              struct doca_comch_connection *connection)
{
    llb_kv_comch_ctx_t *ctx;
    llb_kv_comch_msg_t msg;

    (void)event;
    (void)connection;

    if (!recv_buffer || msg_len < sizeof(llb_kv_comch_msg_t))
        return;

    memcpy(&msg, recv_buffer, sizeof(msg));

    /*
     * Retrieve our context from the connection's server.
     * The pipeline pointer was stored during init.
     */
    /* Use container_of pattern via global -- DOCA 2.9.4 ComCh recv
     * callback does not carry user_data directly. We store the ctx
     * in a module-level pointer set during init. This is safe because
     * there is exactly one ComCh server per kv-agent process. */
    extern llb_kv_comch_ctx_t *g_kv_comch_ctx;
    ctx = g_kv_comch_ctx;
    if (!ctx || !ctx->pipeline)
        return;

    switch (msg.msg_type) {
    case LLB_KV_COMCH_MSG_FETCH_REQ:
        llb_kv_pipeline_fetch_start(ctx->pipeline, &msg);
        break;
    case LLB_KV_COMCH_MSG_WRITEBACK_REQ:
        llb_kv_pipeline_writeback_start(ctx->pipeline, &msg);
        break;
    default:
        fprintf(stderr, "kv-comch: unknown msg_type=%u\n", msg.msg_type);
        break;
    }
}

/*
 * Connection status: host client connected.
 */
static void
comch_conn_cb(struct doca_comch_event_connection_status_changed *event,
              struct doca_comch_connection *connection,
              uint8_t change_successful)
{
    extern llb_kv_comch_ctx_t *g_kv_comch_ctx;

    (void)event;

    if (change_successful && g_kv_comch_ctx) {
        g_kv_comch_ctx->connected = 1;
        g_kv_comch_ctx->conn = connection;
    }
}

/*
 * Connection status: host client disconnected.
 */
static void
comch_disconn_cb(struct doca_comch_event_connection_status_changed *event,
                 struct doca_comch_connection *connection,
                 uint8_t change_successful)
{
    extern llb_kv_comch_ctx_t *g_kv_comch_ctx;

    (void)event;
    (void)connection;
    (void)change_successful;

    if (g_kv_comch_ctx) {
        g_kv_comch_ctx->connected = 0;
        g_kv_comch_ctx->conn = NULL;
    }
}

/*
 * Send task completion callback.
 */
static void
comch_send_done_cb(struct doca_comch_task_send *task,
                   union doca_data task_user_data,
                   union doca_data ctx_user_data)
{
    (void)task;
    (void)task_user_data;
    (void)ctx_user_data;
    /* Send completed -- no action needed */
}

/*
 * Send task error callback.
 */
static void
comch_send_err_cb(struct doca_comch_task_send *task,
                  union doca_data task_user_data,
                  union doca_data ctx_user_data)
{
    (void)task;
    (void)task_user_data;
    (void)ctx_user_data;
    fprintf(stderr, "kv-comch: send task failed\n");
}

/* ------------------------------------------------------------------ */
/* Module-level context pointer (one ComCh server per process)         */
/* ------------------------------------------------------------------ */
llb_kv_comch_ctx_t *g_kv_comch_ctx = NULL;

/* ------------------------------------------------------------------ */
/* Init -- 10-step DOCA ComCh server initialization                    */
/* ------------------------------------------------------------------ */

llb_kv_comch_ctx_t *
llb_kv_comch_init(void *dev, void *rep_dev,
                  llb_kv_pipeline_ctx_t *pipeline)
{
    llb_kv_comch_ctx_t *ctx;
    struct doca_dev *doca_dev = (struct doca_dev *)dev;
    struct doca_dev_rep *doca_rep = (struct doca_dev_rep *)rep_dev;
    doca_error_t ret;

    if (!dev || !rep_dev)
        return NULL;

    ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;

    /* Step 1: Create Progress Engine */
    ret = doca_pe_create(&ctx->pe);
    if (ret != DOCA_SUCCESS) {
        fprintf(stderr, "kv-comch: doca_pe_create failed: %s\n",
                doca_error_get_descr(ret));
        goto err_free;
    }

    /* Step 2: Create ComCh server */
    ret = doca_comch_server_create(doca_dev, doca_rep,
                                   LLB_KV_COMCH_SVC_NAME, &ctx->server);
    if (ret != DOCA_SUCCESS) {
        fprintf(stderr, "kv-comch: server_create failed: %s\n",
                doca_error_get_descr(ret));
        goto err_pe;
    }

    /* Step 3: Set max message size (MANDATORY before ctx_start) */
    ret = doca_comch_server_set_max_msg_size(ctx->server,
                                              sizeof(llb_kv_comch_msg_t));
    if (ret != DOCA_SUCCESS) {
        fprintf(stderr, "kv-comch: set_max_msg_size failed: %s\n",
                doca_error_get_descr(ret));
        goto err_server;
    }

    /* Step 4: Set recv queue size (MANDATORY before ctx_start) */
    ret = doca_comch_server_set_recv_queue_size(ctx->server,
                                                LLB_KV_COMCH_RECV_QUEUE);
    if (ret != DOCA_SUCCESS) {
        fprintf(stderr, "kv-comch: set_recv_queue_size failed: %s\n",
                doca_error_get_descr(ret));
        goto err_server;
    }

    /* Step 5: Register message receive callback */
    ret = doca_comch_server_event_msg_recv_register(ctx->server,
                                                     comch_recv_cb);
    if (ret != DOCA_SUCCESS) {
        fprintf(stderr, "kv-comch: event_msg_recv_register failed: %s\n",
                doca_error_get_descr(ret));
        goto err_server;
    }

    /* Step 6: Register connection status callbacks */
    ret = doca_comch_server_event_connection_status_changed_register(
        ctx->server, comch_conn_cb, comch_disconn_cb);
    if (ret != DOCA_SUCCESS) {
        fprintf(stderr, "kv-comch: event_connection_register failed: %s\n",
                doca_error_get_descr(ret));
        goto err_server;
    }

    /* Step 7: Configure async send task pool (MANDATORY before ctx_start) */
    ret = doca_comch_server_task_send_set_conf(ctx->server,
                                                comch_send_done_cb,
                                                comch_send_err_cb,
                                                LLB_KV_COMCH_SEND_POOL);
    if (ret != DOCA_SUCCESS) {
        fprintf(stderr, "kv-comch: task_send_set_conf failed: %s\n",
                doca_error_get_descr(ret));
        goto err_server;
    }

    /* Step 8: Connect server context to PE */
    ret = doca_pe_connect_ctx(ctx->pe,
                              doca_comch_server_as_ctx(ctx->server));
    if (ret != DOCA_SUCCESS) {
        fprintf(stderr, "kv-comch: pe_connect_ctx failed: %s\n",
                doca_error_get_descr(ret));
        goto err_server;
    }

    /* Step 9: Start server context */
    ret = doca_ctx_start(doca_comch_server_as_ctx(ctx->server));
    if (ret != DOCA_SUCCESS) {
        fprintf(stderr, "kv-comch: ctx_start failed: %s\n",
                doca_error_get_descr(ret));
        goto err_server;
    }

    /* Step 10: Store pipeline back-pointer */
    ctx->pipeline = pipeline;

    /* Set module-level pointer for callbacks */
    g_kv_comch_ctx = ctx;

    return ctx;

err_server:
    doca_comch_server_destroy(ctx->server);
err_pe:
    doca_pe_destroy(ctx->pe);
err_free:
    free(ctx);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Send done/error message back to vLLM host                           */
/* ------------------------------------------------------------------ */

int
llb_kv_comch_send_done(llb_kv_comch_ctx_t *ctx, uint64_t session_id,
                       uint8_t msg_type, int result_code)
{
    struct doca_comch_task_send *task = NULL;
    llb_kv_comch_msg_t msg;
    doca_error_t ret;

    if (!ctx || !ctx->server || !ctx->conn || !ctx->connected)
        return LLB_KV_ERR_CONN;

    memset(&msg, 0, sizeof(msg));
    msg.msg_type   = msg_type;
    msg.session_id = session_id;
    msg.flags      = (uint16_t)(result_code & 0xFFFF);

    ret = doca_comch_server_task_send_alloc_init(
        ctx->server, ctx->conn, (const void *)&msg,
        (uint32_t)sizeof(msg), &task);
    if (ret != DOCA_SUCCESS)
        return LLB_KV_ERR_HW;

    ret = doca_task_submit(doca_comch_task_send_as_task(task));
    if (ret != DOCA_SUCCESS)
        return LLB_KV_ERR_HW;

    return LLB_KV_OK;
}

/* ------------------------------------------------------------------ */
/* Poll PE for incoming messages and send completions                   */
/* ------------------------------------------------------------------ */

int
llb_kv_comch_poll(llb_kv_comch_ctx_t *ctx)
{
    if (!ctx || !ctx->pe)
        return LLB_KV_ERR_INTERNAL;

    doca_pe_progress(ctx->pe);
    return LLB_KV_OK;
}

/* ------------------------------------------------------------------ */
/* Destroy                                                             */
/* ------------------------------------------------------------------ */

void
llb_kv_comch_destroy(llb_kv_comch_ctx_t *ctx)
{
    if (!ctx)
        return;

    if (ctx->server) {
        doca_ctx_stop(doca_comch_server_as_ctx(ctx->server));
        doca_comch_server_destroy(ctx->server);
    }
    if (ctx->pe)
        doca_pe_destroy(ctx->pe);

    if (g_kv_comch_ctx == ctx)
        g_kv_comch_ctx = NULL;

    free(ctx);
}
