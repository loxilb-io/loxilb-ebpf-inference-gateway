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
 * loxilb_kv_comch_stub.c -- Empty ComCh stub for non-DOCA builds.
 *
 * ComCh requires DOCA representor devices (BF ARM-side only).
 * Without DOCA, all functions return LLB_KV_ERR_HW. The pipeline
 * can still be triggered via REST API in stub mode.
 */

#include "loxilb_kv.h"

#include <stdio.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/* ComCh context (stub -- minimal)                                     */
/* ------------------------------------------------------------------ */

struct llb_kv_comch_ctx {
    int dummy; /* empty struct not allowed in C */
};

/* ------------------------------------------------------------------ */
/* Init                                                                */
/* ------------------------------------------------------------------ */

llb_kv_comch_ctx_t *
llb_kv_comch_init(void *dev, void *rep_dev,
                  llb_kv_pipeline_ctx_t *pipeline)
{
    (void)dev;
    (void)rep_dev;
    (void)pipeline;

    fprintf(stderr, "kv-comch: ComCh unavailable -- use REST API\n");
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Send done                                                           */
/* ------------------------------------------------------------------ */

int
llb_kv_comch_send_done(llb_kv_comch_ctx_t *ctx, uint64_t session_id,
                       uint8_t msg_type, int result_code)
{
    (void)ctx;
    (void)session_id;
    (void)msg_type;
    (void)result_code;
    return LLB_KV_ERR_HW;
}

/* ------------------------------------------------------------------ */
/* Poll                                                                */
/* ------------------------------------------------------------------ */

int
llb_kv_comch_poll(llb_kv_comch_ctx_t *ctx)
{
    (void)ctx;
    return LLB_KV_ERR_HW;
}

/* ------------------------------------------------------------------ */
/* Destroy                                                             */
/* ------------------------------------------------------------------ */

void
llb_kv_comch_destroy(llb_kv_comch_ctx_t *ctx)
{
    free(ctx);
}
