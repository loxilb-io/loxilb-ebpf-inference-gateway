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
 * loxilb_kv_mmap.h -- Shared mmap ring allocator for staging buffers.
 *
 * Used by both compress and DMA modules to allocate staging buffers
 * and (optionally) register them with DOCA mmap for HW access.
 *
 * When HAVE_DOCA=1: allocates via mmap(MAP_ANONYMOUS) and registers
 * with doca_mmap for device access.
 * When HAVE_DOCA=0: plain mmap(MAP_ANONYMOUS) allocation, no DOCA
 * registration needed.
 */

#pragma once

#include <stddef.h>
#include <sys/mman.h>
#include <string.h>

#include "loxilb_kv.h"

#ifdef HAVE_DOCA
#include <doca_mmap.h>
#include <doca_dev.h>

/*
 * Allocate a staging buffer and register it with a DOCA mmap for
 * device access. The caller owns both the buffer and the mmap.
 *
 * Returns LLB_KV_OK on success. On failure, *buf_out and *mmap_out
 * are set to NULL.
 */
static inline int
llb_kv_staging_alloc(struct doca_dev *dev, size_t size,
                     void **buf_out, struct doca_mmap **mmap_out)
{
    void *buf;
    struct doca_mmap *dmap = NULL;
    doca_error_t ret;

    if (!buf_out || !mmap_out || size == 0)
        return LLB_KV_ERR_NOMEM;

    *buf_out  = NULL;
    *mmap_out = NULL;

    buf = mmap(NULL, size, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED)
        return LLB_KV_ERR_NOMEM;
    memset(buf, 0, size);

    ret = doca_mmap_create(&dmap);
    if (ret != DOCA_SUCCESS) {
        munmap(buf, size);
        return LLB_KV_ERR_HW;
    }

    ret = doca_mmap_add_dev(dmap, dev);
    if (ret != DOCA_SUCCESS) {
        doca_mmap_destroy(dmap);
        munmap(buf, size);
        return LLB_KV_ERR_HW;
    }

    ret = doca_mmap_set_memrange(dmap, buf, size);
    if (ret != DOCA_SUCCESS) {
        doca_mmap_destroy(dmap);
        munmap(buf, size);
        return LLB_KV_ERR_HW;
    }

    ret = doca_mmap_start(dmap);
    if (ret != DOCA_SUCCESS) {
        doca_mmap_destroy(dmap);
        munmap(buf, size);
        return LLB_KV_ERR_HW;
    }

    *buf_out  = buf;
    *mmap_out = dmap;
    return LLB_KV_OK;
}

/*
 * Unregister and free a staging buffer previously allocated with
 * llb_kv_staging_alloc().
 */
static inline void
llb_kv_staging_free(void *buf, struct doca_mmap *dmap, size_t size)
{
    if (dmap) {
        doca_mmap_stop(dmap);
        doca_mmap_destroy(dmap);
    }
    if (buf && buf != MAP_FAILED)
        munmap(buf, size);
}

#else /* !HAVE_DOCA */

/*
 * Stub: allocate staging buffer with plain mmap. No DOCA mmap
 * registration. The mmap_out pointer is always set to NULL.
 */
static inline int
llb_kv_staging_alloc_plain(size_t size, void **buf_out)
{
    void *buf;

    if (!buf_out || size == 0)
        return LLB_KV_ERR_NOMEM;

    *buf_out = NULL;

    buf = mmap(NULL, size, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED)
        return LLB_KV_ERR_NOMEM;
    memset(buf, 0, size);

    *buf_out = buf;
    return LLB_KV_OK;
}

/*
 * Stub: free a staging buffer. mmap_unused is ignored.
 */
static inline void
llb_kv_staging_free_plain(void *buf, size_t size)
{
    if (buf && buf != MAP_FAILED)
        munmap(buf, size);
}

#endif /* HAVE_DOCA */

/* EOF */
