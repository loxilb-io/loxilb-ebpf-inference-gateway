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
 * loxilb_kv_xlio.c -- XLIO transport ops placeholder for BF3 upgrade path.
 *
 * XLIO (formerly VMA / Mellanox Messaging Accelerator) provides
 * kernel-bypass TCP via LD_PRELOAD on BF3 DPUs.  This file implements
 * the llb_kv_transport_ops interface to prove the transport abstraction
 * allows zero-change swap from TCP.
 *
 * This file is NOT compiled by default.  It requires HAVE_XLIO=1 and
 * the XLIO SDK to be installed.
 *
 * Key verification (KV-03): The pipeline orchestrator (plan 39-05)
 * takes a llb_kv_transport_ops * parameter.  Swapping &llb_kv_tcp_ops
 * for &llb_kv_xlio_ops requires zero changes to pipeline, compress,
 * or DMA code.
 */

#ifdef HAVE_XLIO

#include "loxilb_kv.h"

/* ------------------------------------------------------------------ */
/* XLIO transport stubs -- future BF3 implementation                   */
/* ------------------------------------------------------------------ */

static int xlio_connect(const char *host, uint16_t port, void **conn_out)
{
    (void)host;
    (void)port;
    (void)conn_out;
    /* TODO: XLIO implementation for BF3 */
    return LLB_KV_ERR_INTERNAL;
}

static int xlio_recv_exact(void *conn, void *buf, size_t len, int timeout_ms)
{
    (void)conn;
    (void)buf;
    (void)len;
    (void)timeout_ms;
    /* TODO: XLIO implementation for BF3 */
    return LLB_KV_ERR_INTERNAL;
}

static int xlio_send_all(void *conn, const void *buf, size_t len)
{
    (void)conn;
    (void)buf;
    (void)len;
    /* TODO: XLIO implementation for BF3 */
    return LLB_KV_ERR_INTERNAL;
}

static void xlio_close(void *conn)
{
    (void)conn;
    /* TODO: XLIO implementation for BF3 */
}

/* ------------------------------------------------------------------ */
/* XLIO transport ops -- same interface as TCP ops                     */
/* ------------------------------------------------------------------ */

llb_kv_transport_ops llb_kv_xlio_ops = {
    .connect    = xlio_connect,
    .recv_exact = xlio_recv_exact,
    .send_all   = xlio_send_all,
    .close      = xlio_close,
};

#endif /* HAVE_XLIO */
