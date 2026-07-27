/*
 * Copyright (c) 2025 LoxiLB Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __SOCKPROXY_KV_EXACT_H__
#define __SOCKPROXY_KV_EXACT_H__

#include <stdint.h>

/* Forward declarations — full types in sockproxy.h */
struct proxy_epval;
struct proxy_fd_ent;

/* ---------- Constants ---------- */

/* Hash algorithm identifiers (matches kv_hash_algo field) */
#define KV_HASH_SHA256_CBOR   0
#define KV_HASH_XXHASH_CBOR  1
/* (SGL-02): SGLang radix-page hash. Value 2 is FREE in THIS
 * enum (the NATS "2" reservation lives on the kv_exact_mode MODE enum in
 * sockproxy.h — Pitfall 6 applies there only). Contract pinned to sglang
 * python/sglang/srt/mem_cache/cpp_utils/hash_binding.cpp @ d8ef76682e:
 *   digest_i = SHA256([32-byte raw parent digest if i>0] || tok0_LE4 || ...)
 *   published uint64 = FIRST 8 digest bytes big-endian
 *                      (== int(hexdigest[:16],16), hash_str_to_int64 bit
 *                      pattern) — NOT vLLM's last-8 truncation, and block 0
 *   has NO parent bytes (no NONE_HASH seed). */
#define KV_HASH_SHA256_SGLANG 2

/* Maximum token IDs per request for block hash computation */
#define KV_MAX_TOKENS         4096

/* Maximum hash bytes per block: sha256=32, xxhash128=16 */
#define KV_MAX_HASH_BYTES     32

/* Maximum blocks per request (KV_MAX_TOKENS / min_block_size) */
#define KV_MAX_BLOCKS         256

/* Default ZMQ PUB socket port on vLLM prefill endpoints */
#define KV_ZMQ_PORT_DEFAULT   5557

/* Default warmup period after ZMQ subscriber connects (seconds) */
#define KV_WARMUP_DEFAULT_SEC 30

/* ---------- C2 (81-07): capacity-weighted bounded-load cap ----------
 *
 * The C-side mirror of the Go pure-Go cap math in
 * pkg/loxinet/ai_kv_unified.go (kvClampCapacity / kvCapFor). It lights up
 * the reserved PROXY_SEL_GPU_AWARE weights (DEFAULT_KV_CACHE_WEIGHT /
 * DEFAULT_QUEUE_WEIGHT / DEFAULT_SWAP_WEIGHT — defined in sockproxy.h but
 * never consumed) inside pd_select_prefill so the P/D prefill selector can
 * weight a candidate EP by its advertised NumGPUBlocks (capacity) AND its
 * live load (active_conns + queued_requests). Kept header-only + pure so
 * BOTH pd_select_prefill (sockproxy_pd.c) and the unit harness
 * (test_kv_exact.c, which #includes sockproxy_kv_exact.c → this header) can
 * call it without a 3rd CGO crossing.
 *
 * V5 guards: capacity_i is clamped to [1, KV_CAPACITY_CLAMP_MAX]
 * before any division and the caller's total_cap is built from clamped values
 * so it is always ≥ n_eps ≥ 1 — a buggy vLLM advertising NumGPUBlocks=0 (or a
 * huge value) can never divide-by-zero or overflow. The result is floored at 1
 * (a live EP always has room for one request — mirrors sockproxy_lb.c
 * min_bound and the Go kvCapFor floor).
 */

/* Upper bound for a single advertised NumGPUBlocks before it enters the cap
 * division. 8M is ~13× the largest realistic vLLM num_gpu_blocks (~600k);
 * anything beyond is clamped so the weighted sum cannot overflow the uint64
 * accumulator. MUST match kvCapacityClampMax in ai_kv_unified.go. */
#define KV_CAPACITY_CLAMP_MAX 8000000ULL

/* Default mean-load factor c = (1+ε)·100 (175 ⇒ ε=0.75). MUST match
 * kvUnifiedDefaultMeanLoadFactor in ai_kv_unified.go and the documented
 * sockproxy_lb.c value (Pitfall 5). */
#define KV_DEFAULT_MEAN_LOAD_FACTOR 175ULL

/*
 * pd_kv_clamp_capacity — bound an advertised capacity into
 * [1, KV_CAPACITY_CLAMP_MAX]. A 0 (absent/malicious NumGPUBlocks) becomes 1 so
 * the EP still participates with the smallest positive weight and can never
 * zero the weighted sum. Mirrors Go kvClampCapacity.
 */
static inline uint64_t
pd_kv_clamp_capacity(uint32_t capacity)
{
  if (capacity == 0)
    return 1ULL;
  if ((uint64_t)capacity > KV_CAPACITY_CLAMP_MAX)
    return KV_CAPACITY_CLAMP_MAX;
  return (uint64_t)capacity;
}

/*
 * pd_capacity_weighted_cap — cap_i = ceil((1+ε)·total_load·capacity_i/Σcapacity).
 *
 *   total_load             Σ load over the candidate EPs.
 *   clamped_cap_i          this EP's CLAMPED capacity weight (pd_kv_clamp_capacity).
 *   total_clamped_cap      Σ clamped capacity over the candidate EPs (>0 by construction).
 *   mean_load_factor_pct   c·100 == (1+ε)·100 (KV_DEFAULT_MEAN_LOAD_FACTOR).
 *
 * All arithmetic is uint64; the +(den-1) numerator bias implements ceiling.
 * Returns ≥1 always (a live EP always has room for one request).
 *
 * MUST stay numerically identical to Go kvCapFor (ai_kv_unified.go): the
 * head-to-head A/B compares the C-side P/D path against the Go-side overlap
 * path on ONE build — a divergent cap would split the measurement.
 */
static inline uint64_t
pd_capacity_weighted_cap(uint64_t total_load, uint64_t clamped_cap_i,
                         uint64_t total_clamped_cap,
                         uint64_t mean_load_factor_pct)
{
  /* numerator   = mean_load_factor_pct · total_load · capacity_i
   *             == 100·(1+ε)·load·cap
   * denominator = 100 · Σ(clamped capacity)
   * cap_i       = ceil(numerator / denominator) */
  if (total_clamped_cap == 0ULL)
    return 1ULL; /* defensive — caller builds total from clamped values (>0) */
  uint64_t num = mean_load_factor_pct * total_load * clamped_cap_i;
  uint64_t den = 100ULL * total_clamped_cap;
  if (den == 0ULL)
    return 1ULL; /* never divide-by-zero */
  uint64_t cap = (num + den - 1ULL) / den; /* ceiling division */
  return cap < 1ULL ? 1ULL : cap;
}

/*
 * pd_capacity_blend_score — the C2 selection score for a prefill EP, lighting
 * up the reserved PROXY_SEL_GPU_AWARE weights (sockproxy.h, defined but never
 * consumed before 81-07). Lower is better — drop-in for the COMP-07
 * (active_conns + queued_requests) Tier-2 score in pd_select_prefill, but
 * capacity-aware: a larger-capacity EP is penalised LESS for the same live
 * load. With the default weights (KV_CACHE 20 / QUEUE 50 / SWAP 30) and equal
 * capacity it preserves the COMP-07 load ordering; with skewed capacity it
 * down-weights load on the bigger EP so it absorbs more before being passed
 * over (the C4 herding fix).
 *
 *   active_conns / queued / swap   the live per-EP load signals
 *   clamped_cap_i                  pd_kv_clamp_capacity(num_gpu_blocks)
 *   total_clamped_cap              Σ clamped capacity (>0 by construction)
 *   queue_w / kv_w / swap_w        PROXY_SEL_GPU_AWARE weights (DEFAULT_*)
 *
 * The capacity divisor is normalised by the mean capacity (total/n_eps) so the
 * score stays scale-free: an EP at the fleet-mean capacity is unweighted, an
 * 8×-mean EP has its load divided by ~8. Integer math throughout; the +1 on the
 * divisor and the result floor keep it divide-safe when capacity clamps to 1.
 */
static inline uint64_t
pd_capacity_blend_score(uint32_t active_conns, uint32_t queued, uint32_t swap,
                        uint64_t clamped_cap_i, uint64_t total_clamped_cap,
                        int n_eps, uint32_t queue_w, uint32_t kv_w,
                        uint32_t swap_w)
{
  /* Weighted live-load (PROXY_SEL_GPU_AWARE weights consumed here). */
  uint64_t weighted_load = (uint64_t)active_conns * (uint64_t)kv_w +
                           (uint64_t)queued * (uint64_t)queue_w +
                           (uint64_t)swap * (uint64_t)swap_w;

  /* Capacity factor: load is divided by (capacity_i / mean_capacity), i.e.
   * multiplied by mean_capacity and divided by capacity_i. Scale by 100 first
   * so the integer divide keeps a fractional bit of resolution. */
  int eps = (n_eps > 0) ? n_eps : 1;
  uint64_t mean_cap = total_clamped_cap / (uint64_t)eps;
  if (mean_cap == 0ULL)
    mean_cap = 1ULL;
  uint64_t cap_i = (clamped_cap_i == 0ULL) ? 1ULL : clamped_cap_i;

  /* score = weighted_load · mean_cap / capacity_i  (bigger capacity → lower). */
  uint64_t score = (weighted_load * mean_cap) / cap_i;
  return score;
}

/* ---------- Per-stage hot-path instrumentation (C3) ---------- */
/*
 * The 4 Tier-1.5 stages timed in pd_kv_exact_select (the C3 "routing overhead"
 * breakdown). Each stage carries an independent µs latency histogram, split by
 * the hit/miss outcome so the C3 hit-vs-miss attribution is queryable.
 *
 *   KV_STAGE_TOKENIZE  llb_ai_kv_tokenize     (CGO -> Go HF tokenizer)
 *   KV_STAGE_HASH      kv_compute_block_hashes (CBOR + chained block hash)
 *   KV_STAGE_CGO       llb_ai_kv_best_worker  (CGO crossing; the scan stage is
 *                                              folded in here C-side — the
 *                                              inventory scan is timed Go-side
 *                                              in plan 81-02)
 *   KV_STAGE_SCAN      reserved for a C-side scan split (Go-side scan timing is
 *                      plan 81-02); kept in the enum so the histogram array and
 *                      the Go-parity bucket layout already carry the 4th slot.
 */
enum kv_stage {
  KV_STAGE_TOKENIZE = 0,
  KV_STAGE_HASH     = 1,
  KV_STAGE_CGO      = 2,
  KV_STAGE_SCAN     = 3,
  KV_N_STAGES       = 4
};

/* Outcome axis: index 0 = miss (Tier-2 fallthrough), index 1 = hit (Tier-1.5 win). */
#define KV_STAGE_OUTCOME_MISS 0
#define KV_STAGE_OUTCOME_HIT  1
#define KV_N_STAGE_OUTCOMES   2

/* Number of µs latency buckets per (stage,outcome) — mirrors the 12-bucket
 * record_latency_sample histogram so the Go CGO bucketBounds parity holds. */
#define KV_STAGE_N_BUCKETS    12

/*
 * record_kv_stage — accumulate one per-stage µs timing into the off-path
 * histogram for (stage, is_hit). Off-path only: a fixed-bucket atomic_fetch_add
 * mirror of record_latency_sample — NO synchronous logging (C3 anti-perturbation).
 *
 *   stage       one of KV_STAGE_TOKENIZE/HASH/CGO/SCAN
 *   is_hit      1 = Tier-1.5 hit path, 0 = Tier-2 miss/fallthrough path
 *   latency_us  measured stage duration in microseconds
 */
void record_kv_stage(int stage, int is_hit, uint64_t latency_us);

/* ---------- Function Declarations ---------- */

/*
 * pd_kv_exact_select — Tier 1.5 KV block-hash exact routing.
 *
 * Tokenizes the request prompt, computes block hashes, and queries
 * the Go-side KV inventory to find the prefill EP with the most
 * matching cached blocks.
 *
 * Parameters:
 *   tepval        service endpoint pool
 *   pfe           per-connection state (contains prompt text and model)
 *   ep_out        output: selected EP index (0-based)
 *   excluded_mask bitmask of EPs to exclude (health/circuit-breaker)
 *
 * Returns:
 *    0  Tier 1.5 selected an EP (written to *ep_out)
 *   -1  fallthrough to Tier 2 (mode off, warmup, tokenizer error, no match)
 */
int pd_kv_exact_select(struct proxy_epval *tepval, struct proxy_fd_ent *pfe,
                       int *ep_out, uint32_t excluded_mask);

/*
 * kv_compute_block_hashes — compute chained block hashes for a token sequence.
 *
 * For each block of block_size tokens, CBOR-encodes (parent_hash, token_ids, NULL)
 * then hashes with the configured algorithm (SHA256 or XXH3_128).
 *
 * Parameters:
 *   hash_algo     KV_HASH_SHA256_CBOR or KV_HASH_XXHASH_CBOR
 *   tokens        array of token IDs
 *   n_tokens      number of tokens
 *   block_size    tokens per block
 *   out_hashes    output buffer for block hashes (hash_stride * max_blocks bytes)
 *   hash_stride   bytes per hash (32 for sha256, 16 for xxhash128)
 *   max_blocks    maximum blocks to compute
 *
 * Returns: number of hashes computed, or -1 on error.
 */
int kv_compute_block_hashes(uint8_t hash_algo, const uint32_t *tokens,
                            int n_tokens, uint32_t block_size,
                            uint8_t *out_hashes, int hash_stride,
                            int max_blocks);

/*
 * kv_cbor_encode_block_input — encode (parent_hash, token_ids, null) as canonical CBOR.
 *
 * Parameters:
 *   parent_hash      parent block hash bytes
 *   parent_hash_len  length of parent hash (32 for sha256, 16 for xxhash128)
 *   token_ids        array of token IDs for this block
 *   n_tokens         number of tokens in this block
 *   out_buf          output buffer for CBOR bytes
 *   out_buf_len      size of output buffer
 *
 * Returns: bytes written, or -1 on overflow.
 */
int kv_cbor_encode_block_input(const uint8_t *parent_hash, int parent_hash_len,
                               const uint32_t *token_ids, int n_tokens,
                               uint8_t *out_buf, int out_buf_len);

/*
 * kv_compute_single_block_hash — compute one block hash with an explicit parent.
 *
 * Primarily a test hook for known-vector fixtures that need to pin a non-zero
 * parent (e.g. block N chained from block N-1). In production, prefer
 * kv_compute_block_hashes which handles the zeros→chain parent sequence.
 *
 * Parameters:
 *   hash_algo        KV_HASH_SHA256_CBOR or KV_HASH_XXHASH_CBOR
 *   parent_hash      parent block digest bytes (length must match algo:
 *                    32 for sha256_cbor, 16 for xxhash_cbor)
 *   parent_hash_len  length of parent_hash buffer
 *   tokens           block token IDs
 *   n_tokens         number of tokens in this block
 *   out              output buffer for the digest (size >= 32 for sha256,
 *                    >= 16 for xxhash128)
 *   out_len          size of out buffer
 *
 * Returns: digest length written (32 | 16), or -1 on error.
 */
int kv_compute_single_block_hash(uint8_t hash_algo,
                                 const uint8_t *parent_hash, int parent_hash_len,
                                 const uint32_t *tokens, int n_tokens,
                                 uint8_t *out, int out_len);

/*
 * kv_hash_debug_test_set — force the LLB_KV_HASH_DEBUG gate without
 * setenv/unsetenv race hazards in unit tests. Pass 1 to enable the
 * [KV_HASH] logger, 0 to disable. Intended for unit tests only.
 */
void kv_hash_debug_test_set(int on);

#endif /* __SOCKPROXY_KV_EXACT_H__ */
