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
 * loxilb_kv_chunk.c -- Chunk header serialization, deserialization,
 *                       and CRC32 validation for the KV cache pipeline.
 *
 * This file is unconditional (COMMON_OBJS) -- it does not depend on
 * DOCA and requires only zlib for CRC32.
 */

#include "loxilb_kv.h"

#include <string.h>
#include <arpa/inet.h>  /* htonl, htons, ntohl, ntohs */
#include <zlib.h>       /* crc32() */

/* ------------------------------------------------------------------ */
/* Internal helpers for 64-bit network byte order                      */
/* ------------------------------------------------------------------ */

#ifndef htonll
static inline uint64_t htonll(uint64_t val)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return ((uint64_t)htonl((uint32_t)(val & 0xFFFFFFFF)) << 32) |
           (uint64_t)htonl((uint32_t)(val >> 32));
#else
    return val;
#endif
}
#endif

#ifndef ntohll
static inline uint64_t ntohll(uint64_t val)
{
    return htonll(val);  /* symmetric */
}
#endif

/* ------------------------------------------------------------------ */
/* Serialize chunk header to buffer in network byte order              */
/* ------------------------------------------------------------------ */

int llb_kv_chunk_hdr_serialize(const llb_kv_chunk_hdr_t *hdr,
                               void *buf, size_t len)
{
    if (!hdr || !buf)
        return LLB_KV_ERR_INTERNAL;
    if (len < sizeof(llb_kv_chunk_hdr_t))
        return LLB_KV_ERR_NOMEM;

    llb_kv_chunk_hdr_t wire;

    wire.magic          = htonl(hdr->magic);
    wire.version        = hdr->version;        /* single byte -- no swap */
    wire.algo           = hdr->algo;           /* single byte -- no swap */
    wire.chunk_index    = htons(hdr->chunk_index);
    wire.compressed_len = htonl(hdr->compressed_len);
    wire.original_len   = htonl(hdr->original_len);
    wire.crc32          = htonl(hdr->crc32);
    wire.session_id     = htonll(hdr->session_id);

    memcpy(buf, &wire, sizeof(wire));
    return LLB_KV_OK;
}

/* ------------------------------------------------------------------ */
/* Deserialize chunk header from network byte order buffer             */
/* ------------------------------------------------------------------ */

int llb_kv_chunk_hdr_deserialize(const void *buf, size_t len,
                                 llb_kv_chunk_hdr_t *hdr)
{
    if (!buf || !hdr)
        return LLB_KV_ERR_INTERNAL;
    if (len < sizeof(llb_kv_chunk_hdr_t))
        return LLB_KV_ERR_NOMEM;

    llb_kv_chunk_hdr_t wire;
    memcpy(&wire, buf, sizeof(wire));

    hdr->magic          = ntohl(wire.magic);
    hdr->version        = wire.version;
    hdr->algo           = wire.algo;
    hdr->chunk_index    = ntohs(wire.chunk_index);
    hdr->compressed_len = ntohl(wire.compressed_len);
    hdr->original_len   = ntohl(wire.original_len);
    hdr->crc32          = ntohl(wire.crc32);
    hdr->session_id     = ntohll(wire.session_id);

    /* Validate magic */
    if (hdr->magic != LLB_KV_CHUNK_MAGIC)
        return LLB_KV_ERR_CRC;

    /* Validate version */
    if (hdr->version != LLB_KV_CHUNK_VERSION)
        return LLB_KV_ERR_CRC;

    return LLB_KV_OK;
}

/* ------------------------------------------------------------------ */
/* CRC32 validation of payload                                         */
/* ------------------------------------------------------------------ */

int llb_kv_chunk_validate_crc(const llb_kv_chunk_hdr_t *hdr,
                              const void *payload, size_t payload_len)
{
    if (!hdr || !payload)
        return LLB_KV_ERR_INTERNAL;

    uint32_t computed = crc32(0L, (const unsigned char *)payload, payload_len);

    if (computed != hdr->crc32)
        return LLB_KV_ERR_CRC;

    return LLB_KV_OK;
}
