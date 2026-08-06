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
 * loxilb_kv.h -- Public API header for the LoxiLB KV Cache Pipeline.
 *
 * Defines shared types, error codes, chunk framing protocol, transport
 * abstraction, session state, and hardware capability structures used
 * by all KV pipeline modules and CGO bridge.
 */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdatomic.h>

/* ------------------------------------------------------------------ */
/* Portable cpu_set_t shim (Linux has it natively; macOS needs compat)  */
/* ------------------------------------------------------------------ */
#ifdef __linux__
#include <sched.h>
#else
/* Minimal cpu_set_t compatibility for macOS/non-Linux (test/stub only) */
#include <string.h>
#define CPU_SETSIZE 1024
typedef struct {
    unsigned long __bits[CPU_SETSIZE / (8 * sizeof(unsigned long))];
} cpu_set_t;
#define CPU_ZERO(set)      memset((set), 0, sizeof(cpu_set_t))
#define CPU_SET(cpu, set)  ((set)->__bits[(cpu) / (8 * sizeof(unsigned long))] |= \
                            (1UL << ((cpu) % (8 * sizeof(unsigned long)))))
#define CPU_ISSET(cpu, set) (((set)->__bits[(cpu) / (8 * sizeof(unsigned long))] >> \
                              ((cpu) % (8 * sizeof(unsigned long)))) & 1UL)
#endif

/* ------------------------------------------------------------------ */
/* Error codes                                                         */
/* ------------------------------------------------------------------ */
typedef enum {
    LLB_KV_OK            =  0,
    LLB_KV_ERR_CRC       = -1,
    LLB_KV_ERR_TIMEOUT   = -2,
    LLB_KV_ERR_CONN      = -3,
    LLB_KV_ERR_NOMEM     = -4,
    LLB_KV_ERR_NO_SESSION= -5,
    LLB_KV_ERR_EVICTED   = -6,
    LLB_KV_ERR_HW        = -7,
    LLB_KV_ERR_INTERNAL  = -8,
    LLB_KV_ERR_BOUNDS    = -9,
} llb_kv_err_t;

/* ------------------------------------------------------------------ */
/* Chunk framing protocol                                              */
/* ------------------------------------------------------------------ */

/* Magic: "LXVH" (LoxiLB KV Header) in big-endian */
#define LLB_KV_CHUNK_MAGIC    0x4C585648
#define LLB_KV_CHUNK_VERSION  1

/* Compression algorithm identifiers */
typedef enum {
    LLB_KV_ALGO_RAW     = 0,
    LLB_KV_ALGO_DEFLATE = 1,
    LLB_KV_ALGO_LZ4     = 2,  /* reserved for future use */
} llb_kv_algo_t;

/*
 * Chunk header -- 28 bytes, packed, transmitted in network byte order.
 *
 * Wire layout:
 *   [0..3]   magic           (u32)
 *   [4]      version         (u8)
 *   [5]      algo            (u8)
 *   [6..7]   chunk_index     (u16)
 *   [8..11]  compressed_len  (u32)
 *   [12..15] original_len    (u32)
 *   [16..19] crc32           (u32)
 *   [20..27] session_id      (u64)
 */
typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint8_t  version;
    uint8_t  algo;
    uint16_t chunk_index;
    uint32_t compressed_len;
    uint32_t original_len;
    uint32_t crc32;
    uint64_t session_id;
} llb_kv_chunk_hdr_t;

_Static_assert(sizeof(llb_kv_chunk_hdr_t) == 28, "chunk header must be 28 bytes");

/* ------------------------------------------------------------------ */
/* Transport abstraction                                               */
/* ------------------------------------------------------------------ */

/*
 * KV-26: Transport ops abstraction -- pipeline/compress/dequantize/dma
 * MUST NOT import these types. Only pipeline_init and pipeline_process
 * use transport_ops to drive the TCP recv/send stages.
 */
typedef struct {
    int   (*connect)(const char *host, uint16_t port, void **conn_out);
    int   (*recv_exact)(void *conn, void *buf, size_t len, int timeout_ms);
    int   (*send_all)(void *conn, const void *buf, size_t len);
    void  (*close)(void *conn);
} llb_kv_transport_ops;

/* Default TCP transport ops (unconditional -- POSIX, no DOCA dependency) */
extern llb_kv_transport_ops llb_kv_tcp_ops;

/* XLIO transport ops (BF3 upgrade path -- requires HAVE_XLIO=1) */
#ifdef HAVE_XLIO
extern llb_kv_transport_ops llb_kv_xlio_ops;
#endif

/* ------------------------------------------------------------------ */
/* Function declarations -- TCP transport (loxilb_kv_tcp.c)            */
/* ------------------------------------------------------------------ */

/*
 * Receive a complete chunk (header + payload) with CRC32 validation.
 * Reads the 28-byte header, deserializes it, receives the payload,
 * and validates CRC. Returns LLB_KV_OK only when all bytes received
 * and CRC matches.
 */
int llb_kv_recv_chunk(llb_kv_transport_ops *ops, void *conn,
                      llb_kv_chunk_hdr_t *hdr,
                      void *payload_buf, size_t payload_buf_len,
                      int timeout_ms);

/* ------------------------------------------------------------------ */
/* Session management                                                  */
/* ------------------------------------------------------------------ */

#define LLB_KV_MAX_SESSIONS  64

typedef enum {
    KV_SESSION_IDLE          = 0,
    KV_SESSION_TCP_RECV      = 1,
    KV_SESSION_DECOMPRESS    = 2,
    KV_SESSION_DEQUANTIZE    = 3,  /* v2: wait for dequantize worker */
    KV_SESSION_DMA_TRANSFER  = 4,
    KV_SESSION_DONE          = 5,
    KV_SESSION_WRITEBACK_DMA = 6,
    KV_SESSION_COMPRESS      = 7,
    KV_SESSION_WRITEBACK_TCP = 8,
    KV_SESSION_WRITEBACK_DONE= 9,
    KV_SESSION_ERROR         = 10,
} kv_session_state_t;

typedef struct {
    uint64_t           session_id;
    kv_session_state_t state;
    uint32_t           priority;
    uint32_t           total_chunks;
    uint32_t           chunks_done;
    uint64_t           total_bytes;
    uint64_t           start_ns;
} kv_session_t;

/* ------------------------------------------------------------------ */
/* Hardware capability detection                                       */
/* ------------------------------------------------------------------ */

typedef struct {
    bool     hw_deflate;           /* DOCA Compress HW engine present  */
    bool     hw_dma;               /* DOCA DMA engine present          */
    bool     comch;                /* DOCA Communication Channel       */
    bool     pci_export_hw;        /* PCI mmap export support          */
    uint32_t comch_max_msg_bytes;  /* Max ComCh message size in bytes  */
    char     health_status[16];    /* "ok", "degraded", or "down"      */
} llb_kv_capabilities_t;

/* ------------------------------------------------------------------ */
/* Function declarations -- chunk framing (loxilb_kv_chunk.c)          */
/* ------------------------------------------------------------------ */

/*
 * Serialize chunk header to buffer in network byte order.
 * Returns LLB_KV_OK on success, LLB_KV_ERR_NOMEM if buf too small.
 */
int llb_kv_chunk_hdr_serialize(const llb_kv_chunk_hdr_t *hdr,
                               void *buf, size_t len);

/*
 * Deserialize chunk header from network byte order buffer.
 * Validates magic and version. Returns LLB_KV_ERR_CRC on bad magic.
 */
int llb_kv_chunk_hdr_deserialize(const void *buf, size_t len,
                                 llb_kv_chunk_hdr_t *hdr);

/*
 * Validate CRC32 of payload against header's crc32 field.
 * Returns LLB_KV_OK on match, LLB_KV_ERR_CRC on mismatch.
 */
int llb_kv_chunk_validate_crc(const llb_kv_chunk_hdr_t *hdr,
                              const void *payload, size_t payload_len);

/* ------------------------------------------------------------------ */
/* Function declarations -- capability probe (loxilb_kv_cap.c/stub)    */
/* ------------------------------------------------------------------ */

/*
 * Probe DOCA device capabilities. Populates caps struct.
 * Stub version sets all HW flags false.
 */
int llb_kv_capability_probe(llb_kv_capabilities_t *caps);

/*
 * Write capability struct as JSON to the given path.
 * Creates parent directories as needed.
 */
int llb_kv_capability_write_json(const llb_kv_capabilities_t *caps,
                                 const char *path);

#ifdef HAVE_DOCA
#include <doca_dev.h>
#include <doca_error.h>
/*
 * Open a DOCA device by PCI address (or first available if pci_addr is NULL).
 */
doca_error_t llb_kv_cap_open_device(const char *pci_addr,
                                     struct doca_dev **dev_out);
#endif

/* ------------------------------------------------------------------ */
/* Compress context (opaque -- defined in loxilb_kv_compress*.c)       */
/* ------------------------------------------------------------------ */

/*
 * Opaque compress context. The full struct definition lives in the
 * implementation file (DOCA HW or zlib stub). Callers only use
 * pointers to this type.
 */
typedef struct llb_kv_compress_ctx llb_kv_compress_ctx_t;

/* ------------------------------------------------------------------ */
/* Function declarations -- compress (loxilb_kv_compress.c / stub)     */
/* ------------------------------------------------------------------ */

/*
 * Allocate and initialize a compress context. For DOCA HW builds,
 * dev must be a valid doca_dev; for stub builds, dev is ignored.
 * staging_size controls pre-allocated buffer size (e.g. 4MB).
 * Returns a heap-allocated context on success, NULL on failure.
 */
llb_kv_compress_ctx_t *llb_kv_compress_init(void *dev,
                                            size_t staging_size);

/*
 * Decompress data from compressed input to output buffer.
 * output_len receives the number of bytes produced.
 * If a dequantize hook is set, it is called after decompression.
 * Returns LLB_KV_OK on success.
 */
int llb_kv_decompress(llb_kv_compress_ctx_t *ctx,
                      const void *compressed, size_t compressed_len,
                      void *output, size_t output_capacity,
                      size_t *output_len);

/*
 * Compress raw data into output buffer (write-back path).
 * output_len receives the number of bytes produced.
 * Returns LLB_KV_OK on success.
 */
int llb_kv_compress(llb_kv_compress_ctx_t *ctx,
                    const void *raw, size_t raw_len,
                    void *output, size_t output_capacity,
                    size_t *output_len);

/*
 * Set the dequantize hook to be called after each decompress.
 * The hook receives the decompressed data pointer, length, and
 * a user-provided context.
 */
void llb_kv_compress_set_dequantize(llb_kv_compress_ctx_t *ctx,
                                    void (*hook)(void *data, size_t len,
                                                 void *user_ctx),
                                    void *user_ctx);

/*
 * Destroy a compress context and release all resources.
 */
void llb_kv_compress_destroy(llb_kv_compress_ctx_t *ctx);

/* ------------------------------------------------------------------ */
/* DMA context (opaque -- defined in loxilb_kv_dma*.c)                 */
/* ------------------------------------------------------------------ */

/*
 * Opaque DMA context. The full struct definition lives in the
 * implementation file (DOCA HW or memcpy stub). Callers only use
 * pointers to this type.
 */
typedef struct llb_kv_dma_ctx llb_kv_dma_ctx_t;

/* ------------------------------------------------------------------ */
/* Function declarations -- DMA P2P (loxilb_kv_dma.c / stub)           */
/* ------------------------------------------------------------------ */

/*
 * Allocate and initialize a DMA context. For DOCA HW builds, dev
 * must be a valid doca_dev; for stub builds, dev is ignored.
 * staging_size controls the pre-allocated DDR staging buffer.
 * Returns a heap-allocated context on success, NULL on failure.
 */
llb_kv_dma_ctx_t *llb_kv_dma_init(void *dev, size_t staging_size);

/*
 * Import remote GPU mmap from host-side PCI export descriptor.
 * Called once per session at session start; per-session cleanup
 * destroys the returned mmap. Supports 64 concurrent sessions.
 * Stub allocates a mock buffer via malloc.
 */
int llb_kv_dma_import_gpu_mmap(llb_kv_dma_ctx_t *ctx,
                               const void *export_desc, size_t desc_len,
                               void **out_gpu_mmap);

/*
 * DMA transfer from BF2 DDR staging to GPU HBM.
 * gpu_mmap: per-session mmap from llb_kv_dma_import_gpu_mmap().
 * Returns LLB_KV_ERR_BOUNDS if gpu_offset+len exceeds mmap size.
 */
int llb_kv_dma_to_gpu(llb_kv_dma_ctx_t *ctx, void *gpu_mmap,
                      const void *src, size_t len, size_t gpu_offset);

/*
 * DMA transfer from GPU HBM to BF2 DDR staging (write-back path).
 * gpu_mmap: per-session mmap from llb_kv_dma_import_gpu_mmap().
 */
int llb_kv_dma_from_gpu(llb_kv_dma_ctx_t *ctx, void *gpu_mmap,
                        size_t gpu_offset, size_t len, void *dst);

/*
 * Destroy a DMA context and release all resources.
 * Per-session gpu_mmap must be destroyed separately via pipeline.
 */
void llb_kv_dma_destroy(llb_kv_dma_ctx_t *ctx);

/* ------------------------------------------------------------------ */
/* ComCh message protocol                                              */
/* ------------------------------------------------------------------ */

#define LLB_KV_COMCH_MSG_FETCH_REQ      1
#define LLB_KV_COMCH_MSG_FETCH_DONE     2
#define LLB_KV_COMCH_MSG_WRITEBACK_REQ  3
#define LLB_KV_COMCH_MSG_WRITEBACK_DONE 4

typedef struct __attribute__((packed)) {
    uint8_t  msg_type;
    uint8_t  reserved;
    uint16_t flags;
    uint32_t priority;
    uint64_t session_id;
    uint32_t total_chunks;
    uint32_t chunk_size;        /* expected compressed chunk size      */
    char     kv_store_host[64]; /* KV store TCP address                */
    uint16_t kv_store_port;
    uint16_t pad;
    uint64_t gpu_base_offset;   /* base offset within pre-registered GPU mmap */
    uint32_t original_size;     /* total decompressed size             */
} llb_kv_comch_msg_t;

/* ~104 bytes -- well under comch_max_msg_bytes (256 minimum) */
_Static_assert(sizeof(llb_kv_comch_msg_t) <= 256,
               "ComCh message must fit within minimum message size");

/* ------------------------------------------------------------------ */
/* Ring buffer (MPMC -- multi-producer multi-consumer, lock-free)      */
/* ------------------------------------------------------------------ */

typedef struct {
    uint32_t slot_idx;
    uint32_t data_len;
    uint64_t session_id;
} llb_kv_ring_elem_t;

/*
 * One ring cell: the payload plus its Vyukov sequence counter.
 *
 * seq encodes the cell's lifecycle position, not just "full/empty":
 *   seq == pos      -> writable by the producer claiming ticket pos
 *   seq == pos + 1  -> readable by the consumer claiming ticket pos
 * Any other value means another thread owns this cell right now, so the
 * caller must re-read the head/tail ticket and try again.
 */
typedef struct {
    _Atomic uint64_t   seq;
    llb_kv_ring_elem_t elem;
} llb_kv_ring_cell_t;

typedef struct {
    _Atomic uint64_t head;      /* producer ticket, CAS-claimed */
    _Atomic uint64_t tail;      /* consumer ticket, CAS-claimed */
    uint32_t         capacity;  /* must be power of 2 */
    llb_kv_ring_cell_t *cells;
} llb_kv_ring_t;

/* ------------------------------------------------------------------ */
/* Function declarations -- Ring buffer (loxilb_kv_ring.c)             */
/* ------------------------------------------------------------------ */

int  llb_kv_ring_init(llb_kv_ring_t *r, uint32_t capacity);
int  llb_kv_ring_push(llb_kv_ring_t *r, const llb_kv_ring_elem_t *e);
int  llb_kv_ring_pop(llb_kv_ring_t *r, llb_kv_ring_elem_t *e);
void llb_kv_ring_destroy(llb_kv_ring_t *r);

/* ------------------------------------------------------------------ */
/* Buffer pool (hugepage-backed, atomic bitmap slot allocator)         */
/* ------------------------------------------------------------------ */

typedef struct {
    void              *base;
    size_t             pool_size;
    size_t             slot_size;
    uint32_t           num_slots;     /* max 64 */
    _Atomic uint64_t   free_bitmap;   /* 1 = free, 0 = allocated; CAS for thread safety */
    void              *doca_mmap;     /* NULL unless DOCA-registered (dma_src pool) */
    int                hugepage;      /* 1 = MAP_HUGETLB succeeded */
} llb_kv_bufpool_t;

/* ------------------------------------------------------------------ */
/* Function declarations -- Buffer pool (loxilb_kv_bufpool*.c)         */
/* ------------------------------------------------------------------ */

int  llb_kv_bufpool_init(llb_kv_bufpool_t *pool, size_t pool_size,
                         size_t slot_size, int use_hugepages, void *doca_dev);
int  llb_kv_bufpool_alloc(llb_kv_bufpool_t *pool);
void llb_kv_bufpool_free(llb_kv_bufpool_t *pool, int slot_idx);
void *llb_kv_bufpool_slot_ptr(llb_kv_bufpool_t *pool, int slot_idx);
void llb_kv_bufpool_destroy(llb_kv_bufpool_t *pool);

/* ------------------------------------------------------------------ */
/* Dequantize context (opaque -- defined in loxilb_kv_dequantize*.c)   */
/* ------------------------------------------------------------------ */

typedef struct llb_kv_dequantize_ctx llb_kv_dequantize_ctx_t;

/* ------------------------------------------------------------------ */
/* Function declarations -- Dequantize (loxilb_kv_dequantize*.c)       */
/* ------------------------------------------------------------------ */

/*
 * Allocate and initialize a dequantize worker pool context.
 * worker_count: number of worker threads to spawn.
 * input_ring: decompress -> dequantize ring (pop side).
 * output_ring: dequantize -> DMA ring (push side).
 * src_pool: buffer pool holding FP8 compressed data (source).
 * dst_pool: buffer pool for FP16 output data (destination).
 * Returns heap-allocated context on success, NULL on failure.
 */
llb_kv_dequantize_ctx_t *llb_kv_dequantize_init(
    int worker_count,
    llb_kv_ring_t *input_ring,
    llb_kv_ring_t *output_ring,
    llb_kv_bufpool_t *src_pool,
    llb_kv_bufpool_t *dst_pool);

/*
 * Start dequantize worker threads. If core_ids is non-NULL and
 * num_cores >= worker_count, each thread is pinned to the
 * corresponding core via pthread_setaffinity_np.
 * If core_ids is NULL, threads run without affinity.
 * Returns 0 on success, -1 on failure.
 */
int llb_kv_dequantize_start(llb_kv_dequantize_ctx_t *ctx,
                            const int *core_ids, int num_cores);

/*
 * Signal all dequantize workers to stop and join threads.
 */
void llb_kv_dequantize_stop(llb_kv_dequantize_ctx_t *ctx);

/*
 * Destroy a dequantize context and free all resources.
 */
void llb_kv_dequantize_destroy(llb_kv_dequantize_ctx_t *ctx);

/*
 * Return cumulative count of chunks processed by all workers.
 */
uint64_t llb_kv_dequantize_get_chunks_done(llb_kv_dequantize_ctx_t *ctx);

/*
 * Convert FP8 E4M3 data to FP16 (scalar fallback, exposed for testing).
 * n: number of FP8 elements to convert.
 */
void llb_kv_fp8e4m3_to_fp16(const uint8_t *src, uint16_t *dst, size_t n);

/* ------------------------------------------------------------------ */
/* Pipeline context (opaque -- defined in loxilb_kv_pipeline*.c)       */
/* ------------------------------------------------------------------ */

typedef struct llb_kv_pipeline_ctx llb_kv_pipeline_ctx_t;

/* ------------------------------------------------------------------ */
/* ComCh context (opaque -- defined in loxilb_kv_comch*.c)             */
/* ------------------------------------------------------------------ */

typedef struct llb_kv_comch_ctx llb_kv_comch_ctx_t;

/* ------------------------------------------------------------------ */
/* Function declarations -- ComCh (loxilb_kv_comch.c / stub)           */
/* ------------------------------------------------------------------ */

/*
 * Initialize DOCA ComCh server for KV channel IPC.
 * dev/rep_dev: DOCA device and representor for BF ARM side.
 * pipeline: back-pointer for dispatching received messages.
 * Returns heap-allocated context on success, NULL on failure.
 */
llb_kv_comch_ctx_t *llb_kv_comch_init(void *dev, void *rep_dev,
                                      llb_kv_pipeline_ctx_t *pipeline);

/*
 * Send completion/error message back to vLLM host.
 * msg_type: LLB_KV_COMCH_MSG_FETCH_DONE or LLB_KV_COMCH_MSG_WRITEBACK_DONE.
 * result_code: LLB_KV_OK on success, error code on failure.
 */
int llb_kv_comch_send_done(llb_kv_comch_ctx_t *ctx, uint64_t session_id,
                           uint8_t msg_type, int result_code);

/*
 * Poll ComCh PE for incoming messages and send completions.
 * Called from main event loop.
 */
int llb_kv_comch_poll(llb_kv_comch_ctx_t *ctx);

/*
 * Destroy ComCh context and release all resources.
 */
void llb_kv_comch_destroy(llb_kv_comch_ctx_t *ctx);

/* ------------------------------------------------------------------ */
/* Function declarations -- Pipeline (loxilb_kv_pipeline.c / stub)     */
/* ------------------------------------------------------------------ */

/*
 * Allocate and initialize pipeline context with subsystem pointers.
 * Returns heap-allocated context on success, NULL on failure.
 * (Legacy 3-stage init -- no ring buffers, no dequantize stage.)
 */
llb_kv_pipeline_ctx_t *llb_kv_pipeline_init(llb_kv_transport_ops *transport,
                                            llb_kv_compress_ctx_t *compress,
                                            llb_kv_dma_ctx_t *dma);

/*
 * Register pre-exported GPU mmap for a session (Option B).
 * Called from REST handler BEFORE ComCh KV_FETCH_REQ arrives.
 * export_desc/desc_len: host-side PCI export descriptor.
 */
int llb_kv_pipeline_register_gpu_mmap(llb_kv_pipeline_ctx_t *ctx,
                                      uint64_t session_id,
                                      const void *export_desc,
                                      size_t desc_len);

/*
 * Start a KV fetch session (triggered by KV_FETCH_REQ).
 * Allocates session slot, connects to KV store, begins chunk recv.
 */
int llb_kv_pipeline_fetch_start(llb_kv_pipeline_ctx_t *ctx,
                                const llb_kv_comch_msg_t *msg);

/*
 * Start a write-back session (triggered by KV_WRITEBACK_REQ).
 * DMA from GPU -> compress -> TCP send.
 */
int llb_kv_pipeline_writeback_start(llb_kv_pipeline_ctx_t *ctx,
                                    const llb_kv_comch_msg_t *msg);

/*
 * Advance all active sessions through their state machines.
 * Called from main event loop after comch_poll.
 */
int llb_kv_pipeline_process(llb_kv_pipeline_ctx_t *ctx);

/*
 * Main event loop: polls ComCh + advances pipeline.
 * Blocks until signaled to stop.
 */
int llb_kv_pipeline_run(llb_kv_pipeline_ctx_t *ctx);

/*
 * Set the ComCh context for pipeline done notifications.
 */
void llb_kv_pipeline_set_comch(llb_kv_pipeline_ctx_t *ctx,
                               llb_kv_comch_ctx_t *comch);

/*
 * Get pipeline statistics for Prometheus metrics.
 */
void llb_kv_pipeline_get_stats(llb_kv_pipeline_ctx_t *ctx,
                               uint64_t *fetches, uint64_t *errors,
                               uint64_t *evictions, uint64_t *bytes);

/*
 * Return the number of active sessions in the pipeline.
 */
int llb_kv_pipeline_session_count(llb_kv_pipeline_ctx_t *ctx);

/*
 * Signal pipeline to stop (for clean shutdown).
 */
void llb_kv_pipeline_stop(llb_kv_pipeline_ctx_t *ctx);

/*
 * Destroy pipeline context and release all resources.
 */
void llb_kv_pipeline_destroy(llb_kv_pipeline_ctx_t *ctx);

/* ------------------------------------------------------------------ */
/* Core affinity (loxilb_kv_affinity.c / stub)                         */
/* ------------------------------------------------------------------ */

#define LLB_KV_AFFINITY_MAX_CORES 64

typedef struct {
    cpu_set_t net_cores;
    cpu_set_t deq_cores;
    cpu_set_t ctrl_cores;
    int       net_count;
    int       deq_count;
    int       ctrl_count;
    int       net_ids[LLB_KV_AFFINITY_MAX_CORES];
    int       deq_ids[LLB_KV_AFFINITY_MAX_CORES];
    int       ctrl_ids[LLB_KV_AFFINITY_MAX_CORES];
} llb_kv_affinity_t;

/*
 * Parse colon-separated affinity spec "net_cores:deq_cores:ctrl_cores".
 * Each group is a comma-separated list of integer core IDs.
 * Returns LLB_KV_OK on success, LLB_KV_ERR_BOUNDS on format error.
 */
int llb_kv_affinity_parse(const char *spec, llb_kv_affinity_t *aff);

/*
 * Auto-detect core assignment based on online CPU count.
 * BF2 (8+ cores): net=0,1 / deq=2..N-3 / ctrl=N-2,N-1.
 * 4-7 cores:      net=0   / deq=1..N-2 / ctrl=N-1.
 * <4 cores:       net=0   / deq=1..N-2 / ctrl=N-1 (minimum viable).
 */
int llb_kv_affinity_auto_detect(llb_kv_affinity_t *aff);

/*
 * Validate affinity assignment:
 *   - No core ID >= online CPU count
 *   - No core appears in multiple groups
 *   - Each group has at least 1 core
 * Returns LLB_KV_OK or LLB_KV_ERR_BOUNDS.
 */
int llb_kv_affinity_validate(const llb_kv_affinity_t *aff);

/*
 * Apply CPU affinity to the calling thread via pthread_setaffinity_np.
 * Stub version is a no-op (returns 0).
 */
int llb_kv_affinity_apply_thread(const cpu_set_t *cpuset);

/* ------------------------------------------------------------------ */
/* Extended pipeline init (v2 -- 4-stage with ring buffer handoff)     */
/* ------------------------------------------------------------------ */

/*
 * Extended pipeline init with buffer pools, affinity, and 4-stage
 * dequantize pipeline. Ring buffers provide inter-stage handoff:
 *   TCP_RECV -> DECOMPRESS -> (ring) -> DEQUANTIZE -> (ring) -> DMA
 *
 * Write-back path (GPU->compress->TCP send) is UNMODIFIED by init_v2.
 */
#define LLB_KV_PIPELINE_DEFAULT_RING_CAP  128

typedef struct {
    llb_kv_transport_ops  *transport;
    llb_kv_compress_ctx_t *compress;
    llb_kv_dma_ctx_t      *dma;
    llb_kv_bufpool_t      *decompress_pool;  /* FP8 output from decompress */
    llb_kv_bufpool_t      *dequantize_pool;  /* FP16 output from dequantize */
    llb_kv_bufpool_t      *dma_src_pool;     /* DMA source (== dequantize output) */
    llb_kv_bufpool_t      *gpu_dst_pool;     /* GPU DMA destination */
    llb_kv_affinity_t     *affinity;         /* NULL = no affinity */
    int                    ring_capacity;    /* 0 = default 128, must be power of 2 */
} llb_kv_pipeline_config_t;

llb_kv_pipeline_ctx_t *llb_kv_pipeline_init_v2(const llb_kv_pipeline_config_t *cfg);

/* EOF */
