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

/*
 * sockproxy_kv_exact.c — Tier 1.5 KV block-hash exact routing for P/D.
 *
 * Implements:
 *   - Minimal canonical CBOR encoder for (parent_hash, token_ids, null) tuples
 *   - Block hash computation (SHA256 or XXH3_128 over CBOR)
 *   - pd_kv_exact_select: tokenize → hash → best-worker lookup via CGO
 *
 * Hash parity: the CBOR encoding and hash computation must produce
 * bit-identical results to Python's cbor2.dumps(canonical=True) + hashlib/xxhash.
 */

#ifndef TEST_KV_EXACT
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <time.h>
#include <pthread.h>
#include <openssl/sha.h>
#include "log.h"
#include "uthash.h"
#include "sockproxy.h"
#include "sockproxy_kv_exact.h"
#include "sockproxy_ai_gw.h"
#define XXH_INLINE_ALL
#include "xxhash.h"
#else
/* Test mode: headers provided by test_kv_exact.c before #include-ing this file.
 * We only need openssl/sha.h and xxhash.h here. */
#include <openssl/sha.h>
#include <stdbool.h>
#include <time.h>
#define XXH_INLINE_ALL
#include "xxhash.h"
#include "sockproxy_kv_exact.h"
#endif

/* PD_CTRL_* packed-word constants + accessors. Normally from
 * sockproxy.h; absent under the TEST_KV_EXACT unit build — define idempotently
 * (the sockproxy_pd.c PD_PREFILL_NO_CAPACITY precedent). Lockstep with the
 * frozen aictrl.v1 EpState enum (96-02). */
#ifndef PD_CTRL_ST_NONE
#define PD_CTRL_ST_NONE     0
#define PD_CTRL_ST_ACTIVE   1
#define PD_CTRL_ST_DRAINING 2
#define PD_CTRL_ST_DISABLED 3
#define PD_CTRL_STATE(p)  (((p) >> 24) & 0xff)
#define PD_CTRL_WEIGHT(p) ((p) & 0xff)
#endif

/* single-role kv_exact_mode value. Canonical definition lives
 * in sockproxy.h (beside proxy_epval_t); this idempotent twin exists for the
 * TEST_KV_EXACT single-TU unit build, which does not include sockproxy.h
 * (the PD_CTRL_ST_NONE precedent above). Value 2 stays reserved for NATS. */
#ifndef KV_EXACT_MODE_SINGLE_ROLE
#define KV_EXACT_MODE_SINGLE_ROLE 3
#endif

/* ========================================================================== */
/* Minimal Canonical CBOR Encoder                                              */
/* ========================================================================== */

/*
 * CBOR canonical encoding rules (RFC 7049 Section 3.9):
 *   - Integers use smallest encoding (0-23: 1 byte, 24-255: 2 bytes,
 *     256-65535: 3 bytes, 65536+: 5 bytes)
 *   - Arrays use definite-length encoding
 *   - Bytes use definite-length encoding
 */

/* Encode a CBOR unsigned integer with given major type.
 * Returns bytes written, or -1 if buffer too small. */
static int
cbor_encode_uint(uint8_t *buf, int buf_len, uint8_t major, uint64_t val)
{
  uint8_t mt = (major << 5);

  if (val <= 23) {
    if (buf_len < 1) return -1;
    buf[0] = mt | (uint8_t)val;
    return 1;
  } else if (val <= 0xFF) {
    if (buf_len < 2) return -1;
    buf[0] = mt | 24;
    buf[1] = (uint8_t)val;
    return 2;
  } else if (val <= 0xFFFF) {
    if (buf_len < 3) return -1;
    buf[0] = mt | 25;
    buf[1] = (uint8_t)(val >> 8);
    buf[2] = (uint8_t)(val);
    return 3;
  } else if (val <= 0xFFFFFFFF) {
    if (buf_len < 5) return -1;
    buf[0] = mt | 26;
    buf[1] = (uint8_t)(val >> 24);
    buf[2] = (uint8_t)(val >> 16);
    buf[3] = (uint8_t)(val >> 8);
    buf[4] = (uint8_t)(val);
    return 5;
  } else {
    if (buf_len < 9) return -1;
    buf[0] = mt | 27;
    buf[1] = (uint8_t)(val >> 56);
    buf[2] = (uint8_t)(val >> 48);
    buf[3] = (uint8_t)(val >> 40);
    buf[4] = (uint8_t)(val >> 32);
    buf[5] = (uint8_t)(val >> 24);
    buf[6] = (uint8_t)(val >> 16);
    buf[7] = (uint8_t)(val >> 8);
    buf[8] = (uint8_t)(val);
    return 9;
  }
}

int
kv_cbor_encode_block_input(const uint8_t *parent_hash, int parent_hash_len,
                           const uint32_t *token_ids, int n_tokens,
                           uint8_t *out_buf, int out_buf_len)
{
  int pos = 0;
  int n;

  /* Outer array(3): [parent_hash_bytes, [token_ids...], null] */
  n = cbor_encode_uint(out_buf + pos, out_buf_len - pos, 4 /* array */, 3);
  if (n < 0) return -1;
  pos += n;

  /* Element 0: byte string (parent hash) */
  n = cbor_encode_uint(out_buf + pos, out_buf_len - pos, 2 /* bytes */, parent_hash_len);
  if (n < 0) return -1;
  pos += n;

  if (pos + parent_hash_len > out_buf_len) return -1;
  memcpy(out_buf + pos, parent_hash, parent_hash_len);
  pos += parent_hash_len;

  /* Element 1: array of unsigned ints (token IDs) */
  n = cbor_encode_uint(out_buf + pos, out_buf_len - pos, 4 /* array */, n_tokens);
  if (n < 0) return -1;
  pos += n;

  for (int i = 0; i < n_tokens; i++) {
    n = cbor_encode_uint(out_buf + pos, out_buf_len - pos, 0 /* uint */, token_ids[i]);
    if (n < 0) return -1;
    pos += n;
  }

  /* Element 2: null (0xF6) */
  if (pos + 1 > out_buf_len) return -1;
  out_buf[pos] = 0xF6;
  pos += 1;

  return pos;
}

/* ========================================================================== */
/* Block Hash Computation                                                      */
/* ========================================================================== */

/* Maximum CBOR buffer: 10 (outer array + bytes header + inner array header)
 * + KV_MAX_HASH_BYTES + KV_MAX_TOKENS * 5 (worst case uint32) + 1 (null)
 * Conservative: 32 + 4096*5 + 16 = ~20,500 */
#define KV_CBOR_BUF_SIZE  (32 + 16 + 4096 * 5 + 16)

/* ---------------------------------------------------------------------------
 * Canonical reference: vLLM v0.17.0 BlockHasher.hash_block_with_parent
 * (vllm/v1/core/kv_cache_utils.py). Per-block hash input is produced via
 *   cbor2.dumps([parent_hash_bytes, token_ids, None], canonical=True)
 * then fed into SHA256 (sha256_cbor) or xxhash.xxh3_128_digest
 * (xxhash_cbor); the first 8 bytes (big-endian) become the uint64 key that
 * loxilb's Go inventory stores (ai_kv_subscriber.go:cBlockHashesToUint64).
 * adds an env-gated [KV_HASH] logger immediately after the hash
 * step to expose CBOR bytes + uint64 truncation for cross-layer parity
 * audits. Zero-cost when LLB_KV_HASH_DEBUG is unset.
 * --------------------------------------------------------------------------- */

/* LLB_KV_HASH_DEBUG runtime gate: sticky init, thread-safe check.
 * 0/unset → zero [KV_HASH] lines emitted, one predicted-not-taken branch
 *            on the hot path.
 * "1"     → one [KV_HASH] line emitted per computed block (CBOR hex +
 *            uint64 truncation) — intended for CICD / debug use only. */
static _Atomic int llb_kv_hash_debug_initialized = 0;
static int llb_kv_hash_debug = 0;

static int
kv_hash_debug_on(void)
{
  int init = atomic_load_explicit(&llb_kv_hash_debug_initialized,
                                  memory_order_acquire);
  if (init) return llb_kv_hash_debug;
  const char *v = getenv("LLB_KV_HASH_DEBUG");
  int on = (v && v[0] == '1' && v[1] == '\0') ? 1 : 0;
  llb_kv_hash_debug = on;
  atomic_store_explicit(&llb_kv_hash_debug_initialized, 1,
                        memory_order_release);
  return on;
}

/* Test hook: force the debug gate without setenv/unsetenv races in unit
 * tests. The kv_hash_debug_test_set symbol is declared in sockproxy_kv_exact.h. */
void
kv_hash_debug_test_set(int on)
{
  llb_kv_hash_debug = on ? 1 : 0;
  atomic_store_explicit(&llb_kv_hash_debug_initialized, 1,
                        memory_order_release);
}

/* kv_now_us — monotonic microsecond clock for the per-stage hot-path timers
 * (C3, plan 81-01). CLOCK_MONOTONIC is the same source the P/D decode-latency
 * timers use (sockproxy_http.c:3033). Returns 0 only if clock_gettime fails,
 * which makes the stage delta degrade to 0 (a no-perturbation safe value)
 * rather than a wild number. */
static inline uint64_t
kv_now_us(void)
{
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
  return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

/* Emit a single [KV_HASH] log line describing one computed block.
 *   blk_idx     0-based block index within this kv_compute_block_hashes call
 *   algo        "sha256_cbor" | "xxhash_cbor"
 *   n_tokens    token count for this block (≤ block_size)
 *   cbor_buf    raw CBOR-encoded (parent_hash, tokens, null) tuple
 *   cbor_len    length of cbor_buf in bytes
 *   digest      FULL raw hash output (32 bytes for sha256, 16 bytes for xxhash)
 *   digest_len  32 | 16
 * Log payload is hex-encoded. CBOR can run to ~20KB per block, so the hex
 * is truncated at 1024 hex chars (= 512 raw bytes) with a "..." suffix.
 * Full CBOR is reconstructible from the client side by re-encoding tokens.
 * The uint64 field is the LOW 64 bits of the full digest interpreted big-
 * endian — equivalently digest[digest_len-8 .. digest_len-1] BE — matching
 * vLLM v0.17.0 maybe_convert_block_hash (kv_cache_utils.py:71-74) and the
 * Go-side cBlockHashesToUint64 output after the 44-04 C-side truncation
 * fix (see kv_compute_block_hashes). */
static void
kv_hash_debug_emit(int blk_idx, const char *algo, int n_tokens,
                   const uint8_t *cbor_buf, int cbor_len,
                   const uint8_t *digest, int digest_len)
{
  static const char H[] = "0123456789abcdef";
  int cap = cbor_len;
  if (cap > 512) cap = 512;
  /* +4 for optional "..." truncation suffix + NUL */
  char hexbuf[2 * 512 + 4];
  for (int k = 0; k < cap; k++) {
    hexbuf[2*k]   = H[(cbor_buf[k] >> 4) & 0xf];
    hexbuf[2*k+1] = H[ cbor_buf[k]       & 0xf];
  }
  if (cap < cbor_len) {
    hexbuf[2*cap]   = '.';
    hexbuf[2*cap+1] = '.';
    hexbuf[2*cap+2] = '.';
    hexbuf[2*cap+3] = '\0';
  } else {
    hexbuf[2*cap] = '\0';
  }

  /* vLLM v0.17.0 maybe_convert_block_hash semantic:
   *   int.from_bytes(full_digest, 'big') & ((1 << 64) - 1)
   * == digest[digest_len-8 .. digest_len-1] interpreted big-endian.
   * Prior to 44-04, we emitted BE(digest[:8]), which silently disagreed
   * with the Admin API inventory populated from vLLM-published ZMQ
   * events (0% overlap in TK27 first-run — see 44-04-evidence). */
  uint64_t u64 = 0;
  int bn = (digest_len < 8) ? digest_len : 8;
  const uint8_t *low64 = digest + (digest_len - bn);
  for (int k = 0; k < bn; k++) u64 = (u64 << 8) | low64[k];

  log_info("[KV_HASH] blk=%d algo=%s n_tokens=%d cbor_len=%d hash=0x%016llx cbor=%s",
           blk_idx, algo, n_tokens, cbor_len,
           (unsigned long long)u64, hexbuf);
}

/* kv_compute_none_hash — compute the first-block parent ("NONE_HASH").
 *
 * Mirrors vLLM v0.17.0 init_none_hash (kv_cache_utils.py:92-106):
 *   if PYTHONHASHSEED unset: NONE_HASH = os.urandom(32)   // non-deterministic
 *   else:                     NONE_HASH = hash_fn(seed_str) // deterministic
 *
 * The non-deterministic branch is unsupportable cross-process (loxilb has
 * no way to learn vLLM's random bytes). We require the operator to set
 * PYTHONHASHSEED on vLLM AND LLB_KV_NONE_HASH_SEED on loxilb to the same
 * short text string — both sides then compute the same NONE_HASH.
 *
 * CBOR encoding for a short text string (len ≤ 23) is `0x60|len` + bytes.
 * Longer seeds would need a 1-byte length extension (0x78); not supported
 * here — operators pick short seeds like "0". If the env is unset or the
 * seed is too long, fall back to zeros (backwards-compatible with pre-
 * testbeds; mismatches a vLLM that has PYTHONHASHSEED set).
 *
 * 44-04 drift #2 root cause: TK27 second-run proved the truncation fix
 * (fa541a7 + f2ec335) was necessary but not sufficient — admin API
 * inventory had zero intersection with [KV_HASH] emits because the C
 * side used all-zero first-block parent while vLLM used a random (or
 * seeded) NONE_HASH. See 44-04-evidence/. */
static void
kv_compute_none_hash(uint8_t hash_algo, uint8_t *out, int out_len)
{
  int digest_len = (hash_algo == KV_HASH_SHA256_CBOR) ? 32 : 16;
  const char *seed = getenv("LLB_KV_NONE_HASH_SEED");

  if (!seed || !seed[0]) {
    memset(out, 0, digest_len);
    return;
  }

  size_t seed_len = strlen(seed);
  if (seed_len > 23) {
    /* Short-string CBOR path only. Keep the scope tight; document the
     * limitation. Fall back to zeros + one-shot warn. */
    static _Atomic int warned = 0;
    int expected = 0;
    if (atomic_compare_exchange_strong(&warned, &expected, 1)) {
      log_warn("LLB_KV_NONE_HASH_SEED longer than 23 bytes "
               "(unsupported CBOR short-string); using zero NONE_HASH");
    }
    memset(out, 0, digest_len);
    return;
  }

  /* CBOR text-string short form: major type 3 (0x60), 5-bit length. */
  uint8_t cbor[1 + 23];
  cbor[0] = (uint8_t)(0x60 | (uint8_t)seed_len);
  memcpy(cbor + 1, seed, seed_len);
  size_t cbor_len = 1 + seed_len;

  if (hash_algo == KV_HASH_SHA256_CBOR) {
    SHA256(cbor, cbor_len, out);
  } else if (hash_algo == KV_HASH_XXHASH_CBOR) {
    XXH128_hash_t h = XXH3_128bits(cbor, cbor_len);
    XXH128_canonical_t canonical;
    XXH128_canonicalFromHash(&canonical, h);
    memcpy(out, canonical.digest, 16);
  } else {
    memset(out, 0, digest_len);
  }
  (void)out_len;
}

/* kv_compute_single_block_hash — hash one block with an explicit parent.
 *
 * Computes CBOR(parent_hash, token_ids, null) and feeds it to the
 * requested algorithm. Writes the vLLM-compatible uint64 truncation (low
 * 64 bits of the full digest, big-endian) into the FIRST 8 bytes of
 * `out`; bytes 8..digest_len-1 are zero-padded. Emits the env-gated
 * [KV_HASH] diagnostic log for this single block with blk_idx=0.
 *
 * Returns the digest length written (32 | 16), or -1 on error. The return
 * value preserves the historical contract: callers size `out` as if the
 * full digest were written, and test_kv_exact asserts dlen == 32 | 16.
 * Only the first 8 bytes of `out` carry cross-layer meaning (the uint64
 * consumed by Go-side cBlockHashesToUint64 and by the test harness).
 *
 * Pre-44-04: this function wrote the FULL digest to `out` and downstream
 * code took BE(digest[:8]). TK27 first-run proved that semantic diverges
 * from vLLM v0.17.0 maybe_convert_block_hash (kv_cache_utils.py:71-74),
 * which publishes `int.from_bytes(digest, 'big') & ((1 << 64) - 1)` —
 * equivalently BE(digest[-8:]). This function now aligns to that wire
 * semantic so loxilb's computed uint64s intersect with the vLLM ZMQ
 * publisher's inventory (TK27 green).
 *
 * This is the single-block primitive behind kv_compute_block_hashes; test
 * code uses it to exercise fixtures that carry a non-zero parent (block 1
 * chained from block 0) without needing to reproduce the chaining loop. */
int
kv_compute_single_block_hash(uint8_t hash_algo,
                             const uint8_t *parent_hash, int parent_hash_len,
                             const uint32_t *tokens, int n_tokens,
                             uint8_t *out, int out_len)
{
  if (!parent_hash || parent_hash_len <= 0 ||
      !tokens || n_tokens <= 0 ||
      !out || out_len <= 0)
    return -1;

  int expected_parent_len;
  int digest_len;
  const char *algo_name;
  if (hash_algo == KV_HASH_SHA256_CBOR) {
    expected_parent_len = 32;
    digest_len = 32;
    algo_name = "sha256_cbor";
  } else if (hash_algo == KV_HASH_XXHASH_CBOR) {
    expected_parent_len = 16;
    digest_len = 16;
    algo_name = "xxhash_cbor";
  } else {
    return -1;
  }

  if (parent_hash_len != expected_parent_len || out_len < digest_len)
    return -1;

  uint8_t cbor_buf[KV_CBOR_BUF_SIZE];
  int cbor_len = kv_cbor_encode_block_input(
      parent_hash, parent_hash_len,
      tokens, n_tokens,
      cbor_buf, sizeof(cbor_buf));
  if (cbor_len < 0)
    return -1;

  /* Compute into a local full-digest buffer so we can both (a) write the
   * vLLM-compatible truncation to out[0..7] and (b) pass the full digest
   * to kv_hash_debug_emit for accurate BE(digest[-8:]) logging. */
  uint8_t digest_full[KV_MAX_HASH_BYTES];
  if (hash_algo == KV_HASH_SHA256_CBOR) {
    SHA256(cbor_buf, cbor_len, digest_full);
  } else {
    /* KV_HASH_XXHASH_CBOR: XXH3_128bits → 16 bytes in canonical (big-endian)
     * form. XXH128_canonicalFromHash stores high64 first, then low64, both
     * big-endian. This matches Python xxhash.xxh3_128_digest() byte order. */
    XXH128_hash_t h = XXH3_128bits(cbor_buf, cbor_len);
    XXH128_canonical_t canonical;
    XXH128_canonicalFromHash(&canonical, h);
    memcpy(digest_full, canonical.digest, 16);
  }

  /* vLLM-aligned truncation: out[0..7] = digest_full[digest_len-8 .. digest_len-1].
   * Remaining bytes of out (if any — 24 bytes for sha256, 8 for xxhash) are
   * zero-padded so stale stack contents don't leak past byte 7. */
  memcpy(out, digest_full + (digest_len - 8), 8);
  if (digest_len > 8)
    memset(out + 8, 0, (size_t)(digest_len - 8));

  if (kv_hash_debug_on()) {
    kv_hash_debug_emit(0, algo_name, n_tokens,
                       cbor_buf, cbor_len, digest_full, digest_len);
  }

  return digest_len;
}

/* kv_hash_sglang_block — one SGLang radix-page digest (SGL-02).
 *
 * Source of record: sglang python/sglang/srt/mem_cache/cpp_utils/
 * hash_binding.cpp (hash_page) @ d8ef76682e — do NOT re-derive from a moved
 * checkout; parity vectors in test_kv_exact.c pin this exact math.
 *
 *   digest = SHA256( [32-byte RAW parent digest, only if has_parent] ||
 *                    token0_LE4 || token1_LE4 || ... )
 *
 * Differences from the vLLM CBOR arms (never share their code paths):
 *   - NO CBOR envelope: tokens are hashed as a raw uint32 little-endian
 *     buffer (hash_binding.cpp hashes the page's uint32 words directly;
 *     x86_64 memory order == 4-byte LE per token).
 *   - Block 0 has NO parent bytes at all (no NONE_HASH seed, no zeros) —
 *     has_parent=false skips the parent update entirely.
 *   - The parent for block i>0 is block i-1's FULL 32-byte digest.
 *
 * Returns 0; out_hash_32 receives the full 32-byte digest. */
static int
kv_hash_sglang_block(const uint8_t *parent_hash_32, bool has_parent,
                     const uint32_t *tokens, int n_tokens,
                     uint8_t *out_hash_32)
{
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  if (has_parent && parent_hash_32)
    SHA256_Update(&ctx, parent_hash_32, 32);
  for (int i = 0; i < n_tokens; i++) {
    uint8_t le4[4] = { (uint8_t)(tokens[i] & 0xFF),
                       (uint8_t)((tokens[i] >> 8) & 0xFF),
                       (uint8_t)((tokens[i] >> 16) & 0xFF),
                       (uint8_t)((tokens[i] >> 24) & 0xFF) };
    SHA256_Update(&ctx, le4, 4);
  }
  SHA256_Final(out_hash_32, &ctx);
  return 0;
}

int
kv_compute_block_hashes(uint8_t hash_algo, const uint32_t *tokens,
                        int n_tokens, uint32_t block_size,
                        uint8_t *out_hashes, int hash_stride,
                        int max_blocks)
{
  if (!tokens || n_tokens <= 0 || block_size == 0 || !out_hashes)
    return -1;

  uint8_t parent_hash[KV_MAX_HASH_BYTES];
  int parent_len;
  int digest_len;
  const char *algo_name;
  int n_blocks = 0;

  /* Determine parent/digest length based on algorithm */
  if (hash_algo == KV_HASH_SHA256_CBOR) {
    parent_len = 32;
    digest_len = 32;
    algo_name = "sha256_cbor";
  } else if (hash_algo == KV_HASH_XXHASH_CBOR) {
    parent_len = 16;
    digest_len = 16;
    algo_name = "xxhash_cbor";
  } else if (hash_algo == KV_HASH_SHA256_SGLANG) {
    parent_len = 32;
    digest_len = 32;
    algo_name = "sha256_sglang";
  } else {
    return -1;
  }

  /* --- SGLang arm (SGL-02): dedicated loop ----
   * Kept fully separate from the vLLM CBOR loop below so the algo-0/1 code
 * paths stay byte-identical. Contract differences (pinned by
   * the committed parity vectors, sglang d8ef76682e):
   *   1. NO kv_compute_none_hash seed — block 0 hashes with NO parent bytes.
   *   2. NO CBOR — kv_hash_sglang_block hashes raw parent||tokens_LE4.
   *   3. uint64 truncation = FIRST 8 digest bytes BE (hash_str_to_int64 =
   *      int(hexdigest[:16],16)) — NOT the vLLM last-8 slice (the TK27
   *      digest[:8]-vs-digest[-8:] drift class, inverted for SGLang). */
  if (hash_algo == KV_HASH_SHA256_SGLANG) {
    bool has_parent = false;
    for (int offset = 0; offset < n_tokens && n_blocks < max_blocks;
         offset += (int)block_size, n_blocks++) {
      int block_tokens = n_tokens - offset;
      if (block_tokens > (int)block_size)
        block_tokens = (int)block_size;

      uint8_t digest_full[KV_MAX_HASH_BYTES];
      kv_hash_sglang_block(has_parent ? parent_hash : NULL, has_parent,
                           tokens + offset, block_tokens, digest_full);

      /* SGLang truncation: out[0..7] = digest_full[0..7] (FIRST 8, BE
       * uint64). Go-side cBlockHashesToUint64 reads raw[i*stride : +8] as
       * BE — yielding exactly the hash_str_to_int64 bit pattern SGLang
       * publishes. Zero-pad the slot tail like the vLLM path. */
      uint8_t *out = out_hashes + n_blocks * hash_stride;
      memcpy(out, digest_full, 8);
      if (hash_stride > 8)
        memset(out + 8, 0, (size_t)(hash_stride - 8));

      if (kv_hash_debug_on()) {
        /* Dedicated emit: kv_hash_debug_emit's hash field is contractually
         * BE(digest[-8:]) (vLLM); logging that here would misreport the
         * SGLang published value. No CBOR exists on this path. */
        uint64_t sgl_u64 = 0;
        for (int k = 0; k < 8; k++)
          sgl_u64 = (sgl_u64 << 8) | digest_full[k];
        log_info("[KV_HASH] blk=%d algo=%s n_tokens=%d cbor_len=0 hash=0x%016llx (first-8 BE)",
                 n_blocks, algo_name, block_tokens,
                 (unsigned long long)sgl_u64);
      }

      /* Parent for the next block: the FULL 32-byte digest. */
      memcpy(parent_hash, digest_full, (size_t)digest_len);
      has_parent = true;
    }
    return n_blocks;
  }

  /* First block: parent = NONE_HASH (seeded via LLB_KV_NONE_HASH_SEED to
   * mirror vLLM v0.17.0 init_none_hash under PYTHONHASHSEED). Fallback to
 * zeros if env unset — backwards-compatible with pre- testbeds
   * but mismatches a vLLM that has PYTHONHASHSEED set. See 44-04. */
  kv_compute_none_hash(hash_algo, parent_hash, parent_len);

  /* Stack-allocate CBOR buffer once; reuse per iteration. The per-block
   * [KV_HASH] emit carries the n_blocks index so logs stay ordered per call. */
  uint8_t cbor_buf[KV_CBOR_BUF_SIZE];

  for (int offset = 0; offset < n_tokens && n_blocks < max_blocks;
       offset += (int)block_size, n_blocks++) {
    int block_tokens = n_tokens - offset;
    if (block_tokens > (int)block_size)
      block_tokens = (int)block_size;

    /* CBOR encode: (parent_hash, block_token_ids, null). We inline the
     * encode + hash here (rather than call kv_compute_single_block_hash
     * per block) so the debug emit can carry the correct n_blocks index
     * — kv_compute_single_block_hash always logs blk=0 for its caller. */
    int cbor_len = kv_cbor_encode_block_input(
        parent_hash, parent_len,
        tokens + offset, block_tokens,
        cbor_buf, sizeof(cbor_buf));
    if (cbor_len < 0)
      return -1;

    /* Hash into a local FULL-digest buffer so parent chaining uses the
     * real hash output (matching vLLM BlockHasher.hash_block_with_parent)
     * while the stride-aligned output slot carries only the vLLM-
     * compatible uint64 truncation. See 44-04: TK27 first-run proved the
     * pre-fix storage of BE(digest[:8]) diverges from vLLM's
     * maybe_convert_block_hash (kv_cache_utils.py:71-74), which emits
     * BE(digest[-8:]). */
    uint8_t digest_full[KV_MAX_HASH_BYTES];
    if (hash_algo == KV_HASH_SHA256_CBOR) {
      SHA256(cbor_buf, cbor_len, digest_full);
    } else {
      XXH128_hash_t h = XXH3_128bits(cbor_buf, cbor_len);
      XXH128_canonical_t canonical;
      XXH128_canonicalFromHash(&canonical, h);
      memcpy(digest_full, canonical.digest, 16);
    }

    /* Write vLLM-aligned truncation to the stride-aligned output slot:
     * out[0..7] = digest_full[digest_len-8 .. digest_len-1] (BE uint64).
     * Go-side cBlockHashesToUint64 takes raw[i*stride : i*stride+8] and
     * reads it as BE, yielding the exact vLLM uint64. Remaining bytes of
     * the slot (stride-8) are zero-padded — they carry no semantic. */
    uint8_t *out = out_hashes + n_blocks * hash_stride;
    memcpy(out, digest_full + (digest_len - 8), 8);
    if (hash_stride > 8)
      memset(out + 8, 0, (size_t)(hash_stride - 8));

    if (kv_hash_debug_on()) {
      kv_hash_debug_emit(n_blocks, algo_name, block_tokens,
                         cbor_buf, cbor_len, digest_full, digest_len);
    }

    /* Update parent for next block using the FULL digest (not the
     * truncated output slot). CBOR input for the next block is
     * (parent=digest_full, tokens, null), matching vLLM semantics. */
    memcpy(parent_hash, digest_full, digest_len);
  }

  return n_blocks;
}

/* ========================================================================== */
/* Tier 1.5: KV Block-Hash Exact Routing                                       */
/* ========================================================================== */

#if !defined(TEST_KV_EXACT) || defined(TEST_KV_EXACT_WITH_GUARDS)

/* KV91_NO_SKIP_LB — invariant: KV-exact relies on the Go
 * capacity-bounded blend (kvUnifiedSelect, fed loxilb's own pd_ep_loads load+cap
 * via the kv_load[]/kv_cap[] arrays below) for its load cap. skip_load_balance
 * MUST remain 0 on this path (sockproxy_lb.c:524) — that flag is for the strict
 * pure-locality prefix_hash mode and DISABLES the bounded-load cap, which would
 * re-introduce the single-EP prefill hot-spot fixes (81-09 a417f037).
 * This path never enters the C chwbl ring and never enables skip_load_balance
 * (asserted in test/audit): selection is the Go export, the cap is the blend. */
int
pd_kv_exact_select(proxy_epval_t *tepval, proxy_fd_ent_t *pfe,
                   int *ep_out, uint32_t excluded_mask)
{
  /* GUARD A: mode off */
  if (!tepval || tepval->kv_exact_mode == 0) {
    log_info("[KV_T15] fd=%d GUARD_A mode_off kv_exact_mode=%u warmup_start=%lld warmup_sec=%u n_prefill_eps=%u",
             pfe ? pfe->fd : -1,
             tepval ? tepval->kv_exact_mode : 0,
             tepval ? (long long)tepval->kv_warmup_start : -1LL,
             tepval ? tepval->kv_warmup_sec : 0,
             tepval ? (unsigned)tepval->n_prefill_eps : 0);
    atomic_fetch_add(&global_stats.pd_kv_t15_miss_mode_off, 1);
    return -1;
  }

  /* GUARD B: warmup period */
  if (tepval->kv_warmup_start > 0 && tepval->kv_warmup_sec > 0) {
    time_t now = time(NULL);
    time_t ready_at = tepval->kv_warmup_start + (time_t)tepval->kv_warmup_sec;
    if (now < ready_at) {
      log_info("[KV_T15] fd=%d GUARD_B warmup_remaining=%lds",
               pfe->fd, (long)(ready_at - now));
      atomic_fetch_add(&global_stats.pd_kv_t15_miss_warmup, 1);
      return -1;
    }
  }

  /* Extract text for tokenization.
   * Primary gate: prefix_key.valid == 1 (extraction succeeded).
   * Fallback: rcvbuf (raw body) when prefix extraction did not produce a valid key. */
  char *text = NULL;
  const char *text_src = "none";
  if (pfe->prefix_key.valid == 1 && pfe->prefix_key.prefix[0] != '\0') {
    text = pfe->prefix_key.prefix;
    text_src = "prefix_key";
  } else if (pfe->rcvbuf != NULL && ((char *)pfe->rcvbuf)[0] != '\0') {
    text = (char *)pfe->rcvbuf;
    text_src = "rcvbuf";
    log_info("[KV_T15] fd=%d FALLBACK_TEXT_RCVBUF prefix_valid=%u",
             pfe->fd, pfe->prefix_key.valid);
  }

  /* GUARD C: text empty */
  if (!text || text[0] == '\0') {
    log_info("[KV_T15] fd=%d GUARD_C text_empty prefix_valid=%u prefix0=0x%02x x_model='%s' pk_model='%s'",
             pfe->fd, pfe->prefix_key.valid,
             (unsigned)pfe->prefix_key.prefix[0],
             pfe->x_model_header, pfe->prefix_key.model);
    atomic_fetch_add(&global_stats.pd_kv_t15_miss_text_empty, 1);
    return -1;
  }

  /* Extract model name */
  char *model = NULL;
  const char *model_src = "none";
  if (pfe->x_model_header[0] != '\0') {
    model = pfe->x_model_header;
    model_src = "x_model_header";
  } else if (pfe->prefix_key.model[0] != '\0') {
    model = pfe->prefix_key.model;
    model_src = "prefix_key.model";
  }

  /* GUARD D: model empty */
  if (!model || model[0] == '\0') {
    log_info("[KV_T15] fd=%d GUARD_D model_empty text_src=%s text_len=%zu x_model='%s' pk_model='%s'",
             pfe->fd, text_src, strlen(text),
             pfe->x_model_header, pfe->prefix_key.model);
    atomic_fetch_add(&global_stats.pd_kv_t15_miss_model_empty, 1);
    return -1;
  }

  log_info("[KV_T15] fd=%d PRE_TOKENIZE text_src=%s model_src=%s model='%s' text_len=%zu",
           pfe->fd, text_src, model_src, model, strlen(text));

  /* C3 per-stage timing (plan 81-01): monotonic µs deltas around the 4 stages.
   * `measured[]` tracks which stages actually ran so a miss-path early-return
   * flushes ONLY the stages it reached. record_kv_stage is the always-on,
   * off-path atomic add (NO synchronous logging in the timed windows — the
   * existing [KV_T15] log_info lines stay OUTSIDE the t0/t1 brackets). The
   * outcome (hit=1 / miss=0) is known only at the exit, so deltas are stashed
   * in `stage_us[]` and flushed via KV_T15_FLUSH(outcome) at every return. */
  uint64_t stage_us[KV_N_STAGES] = {0};
  int      measured[KV_N_STAGES] = {0};
#define KV_T15_FLUSH(outcome) do {                                          \
    for (int _s = 0; _s < KV_N_STAGES; _s++) {                              \
      if (measured[_s]) record_kv_stage(_s, (outcome), stage_us[_s]);       \
    }                                                                       \
    /* Optional content-free per-request structured record: \
     * flag-gated so the production path is byte-identical when off.        \
     * Logs ONLY stage timings + outcome — never prompt text/hashes. */     \
    if (kv_hash_debug_on()) {                                               \
      log_info("[KV_T15_STAGE] fd=%d outcome=%s tok_us=%llu hash_us=%llu "  \
               "cgo_us=%llu",                                               \
               pfe->fd, (outcome) ? "hit" : "miss",                         \
               (unsigned long long)stage_us[KV_STAGE_TOKENIZE],             \
               (unsigned long long)stage_us[KV_STAGE_HASH],                 \
               (unsigned long long)stage_us[KV_STAGE_CGO]);                 \
    }                                                                       \
  } while (0)

  /* STAGE 1: tokenize via CGO.
 * (B1): branch on the request-scoped is_chat signal set in
   * sockproxy_http.c. For /v1/chat/completions the un-templated first-user-message
   * in prefix_key.prefix does NOT tokenize to vLLM's ids (apply_chat_template adds
   * the ChatML/system/role wrappers), so pass the RAW JSON body to the chat bridge
   * (llb_ai_kv_tokenize_chat) which renders the template + Encodes in Go to vLLM
   * parity. Completions keep the existing single-text path. The chat bridge owns
   * the WithEncodeSpecialTokens mode (88-01/88-02 resolved: one tokenizer mode
   * serves both paths), so no per-path mode is needed C-side. On -1 (no messages /
   * no known template / tokenize fail) GUARD_E below falls back — never routes a
   * mis-hashed request through KV-exact. The raw body is reachable contiguously
   * within rcvbuf at (body_off,body_len); fall back to `text` if locators unset. */
  uint32_t tokens[KV_MAX_TOKENS];
  uint64_t _t0 = kv_now_us();
  int n_tokens;
  if (pfe->is_chat) {
    char *raw_body = text;  /* fail-safe default */
    if (pfe->rcvbuf != NULL && pfe->body_len > 0 &&
        ((char *)pfe->rcvbuf)[pfe->body_off] != '\0') {
      raw_body = (char *)pfe->rcvbuf + pfe->body_off;
    }
    n_tokens = llb_ai_kv_tokenize_chat(raw_body, model, tokens, KV_MAX_TOKENS);
  } else {
    n_tokens = llb_ai_kv_tokenize(text, model, tokens, KV_MAX_TOKENS);
  }
  stage_us[KV_STAGE_TOKENIZE] = kv_now_us() - _t0;
  measured[KV_STAGE_TOKENIZE] = 1;

  /* GUARD E: tokenize fail */
  if (n_tokens <= 0) {
    log_info("[KV_T15] fd=%d GUARD_E tokenize_fail model='%s' n_tokens=%d",
             pfe->fd, model, n_tokens);
    atomic_fetch_add(&global_stats.pd_kv_t15_miss_tokenize, 1);
    KV_T15_FLUSH(KV_STAGE_OUTCOME_MISS);
    return -1;
  }

  /* Compute block hashes */
  uint32_t block_size = tepval->kv_block_size;
  if (block_size == 0) block_size = 16;

  /* (SGL-02) confirm, no code change: algo 2 (KV_HASH_SHA256_SGLANG)
   * takes the else branch here → stride 32, matching its 32-byte digest. */
  int hash_stride = (tepval->kv_hash_algo == KV_HASH_XXHASH_CBOR) ? 16 : 32;
  uint8_t hashes[KV_MAX_BLOCKS * KV_MAX_HASH_BYTES];

  /* STAGE 2: CBOR + chained block hash */
  uint64_t _t1 = kv_now_us();
  int n_hashes = kv_compute_block_hashes(
      tepval->kv_hash_algo, tokens, n_tokens, block_size,
      hashes, hash_stride, KV_MAX_BLOCKS);
  stage_us[KV_STAGE_HASH] = kv_now_us() - _t1;
  measured[KV_STAGE_HASH] = 1;

  /* GUARD F: hashes <= 0 */
  if (n_hashes <= 0) {
    log_info("[KV_T15] fd=%d GUARD_F no_hashes n_tokens=%d n_hashes=%d",
             pfe->fd, n_tokens, n_hashes);
    atomic_fetch_add(&global_stats.pd_kv_t15_miss_hashes, 1);
    KV_T15_FLUSH(KV_STAGE_OUTCOME_MISS);
    return -1;
  }

  /* Build candidate EP bitmask — bit i set iff ep_role[i] == 1 (P/D prefill).
 * at kv_exact_mode == KV_EXACT_MODE_SINGLE_ROLE the
   * disjunct admits ALL EPs (single-role services have no roles — ep_role[]
   * is all-zero, Assumption A2); at mode 1 the disjunct is provably never
   * true, so the P/D mask build is byte-identical (mutation-locked by
   * test_mask_mode1_byte_identity in test_kv_exact.c).
   * MAX_PROXY_EP == 32 so uint32_t gives EXACT 1:1 coverage (bits 0..31).
   * The static_assert below fires if MAX_PROXY_EP is ever increased —
   * BOTH prefill_mask and excluded_mask would need to widen to uint64_t.
 * Single call-site per Pitfall 2 to prevent -style branch drift. */
  _Static_assert(MAX_PROXY_EP <= 32,
                 "prefill_mask/excluded_mask uint32_t requires MAX_PROXY_EP <= 32; "
                 "widen both masks (and CGO signature) to uint64_t if MAX_PROXY_EP grows");
  uint32_t prefill_mask = 0;
  for (int i = 0; i < tepval->n_eps && i < 32; i++) {
    if (tepval->ep_role[i] == 1 ||
        tepval->kv_exact_mode == KV_EXACT_MODE_SINGLE_ROLE)
      prefill_mask |= (1u << (unsigned)i);
  }

  /* (Option B): feed the Go selector loxilb's OWN balancer-tracked
   * per-EP live load + advertised capacity, indexed by the ABSOLUTE epIdx (the
   * same index space as prefill_mask/excluded_mask). This replaces the dead
   * vLLM workerMetrics scraper path (rules.go:3423 builds it with updateFn=nil
   * → load was always 0 → the blend ran BLIND → single-EP prefill hot-spot, the
   * 81-09 root cause a417f037). kv_load[i] = live in-flight active_conns,
   * kv_cap[i] = advertised num_gpu_blocks. Fixed-width [32] reuses the
   * MAX_PROXY_EP<=32 _Static_assert above; an empty/degenerate set stays
   * all-zero (Tier-2-safe). atomic_load idiom copied verbatim from
   * sockproxy_pd.c:1038/1053. KV91_NO_SKIP_LB: this Go-side capacity-bounded
   * blend is the cap; skip_load_balance MUST remain 0 on this path
   * (sockproxy_lb.c:524) or the bounded-load cap is disabled and the hot-spot
   * returns — see pd_kv_exact_select header. */
  uint32_t kv_load[32] = {0};
  uint32_t kv_cap[32] = {0};
  int n_ep_slots = (tepval->n_eps < 32) ? tepval->n_eps : 32;
  for (int i = 0; i < n_ep_slots; i++) {
    kv_load[i] = atomic_load(&tepval->pd_ep_loads[i].active_conns);
    kv_cap[i] = atomic_load(&tepval->pd_ep_loads[i].num_gpu_blocks);
  }

  /* per-EP controller weights for the Go Tier-1.5 selector.
   * Twin-lockstep discipline: the Go //export signature, the C prototype
   * (sockproxy_ai_gw.h) and this call site change in the SAME commit. mode 0
   * (controller absent) => pass NULL — the Go side treats nil as all-100, the
   * byte-identical G3 path with ZERO extra per-EP loads here. mode != 0: the
   * array carries PD_CTRL_WEIGHT(pd_ctrl_ep[i]) with packed==0 mapped to 100
   * (no instruction == full weight); an explicit ACTIVE|weight=0 flows through
   * as 0 and degrades to the smallest positive share Go-side (kvClampCapacity's
   * >=1 floor — true removal is a STATE, not a weight). Weights come from the
   * C pd_ctrl_ep[] atomics, NOT the scraper map (same provenance rule as the
   * 81-09 blind-blend fix for kv_load/kv_cap above). */
  uint32_t kv_weight[32];
  const uint32_t *kv_weight_ptr = NULL;
  if (atomic_load(&tepval->pd_ctrl_mode) != 0) {
    for (int i = 0; i < n_ep_slots; i++) {
      uint32_t p = atomic_load(&tepval->pd_ctrl_ep[i]);
      kv_weight[i] = (p == 0) ? 100 : PD_CTRL_WEIGHT(p);
    }
    for (int i = n_ep_slots; i < 32; i++) kv_weight[i] = 100;
    kv_weight_ptr = kv_weight;
  }

  /* STAGE 3: CGO crossing into the Go inventory scorer. The best_worker scan
   * (STAGE 4) runs INSIDE this call; it is timed Go-side in plan 81-02, so it
   * is folded into the CGO delta here (the enum reserves the 4th slot).
 * (SGL-04, Pitfall 2): tepval->kv_svc_id threads the calling rule's
   * identity across the CGO seam so the Go selector scores ONLY this rule's
   * inventories (cross-VIP contamination fix). Zero (legacy/uninitialized
   * structs) means "no identity" — the Go side keeps today's all-services
   * loop, so the seam is independently default-off (kv_weight precedent). */
  int score = 0;
  uint64_t _t2 = kv_now_us();
  /* (§9 relief default): kv_exact_mode rides the same seam so the Go
   * side can default the Phase-95 pressure-relief pass ON for single-role
   * rules only (twin-lockstep with sockproxy_ai_gw.h + ai_kv_subscriber.go). */
  int best_ep = llb_ai_kv_best_worker(
      hashes, hash_stride, n_hashes, model,
      prefill_mask, excluded_mask, kv_load, kv_cap, kv_weight_ptr,
      n_ep_slots, tepval->kv_svc_id, tepval->kv_exact_mode, &score);
  stage_us[KV_STAGE_CGO] = kv_now_us() - _t2;
  measured[KV_STAGE_CGO] = 1;

  /* GUARD G: differentiate no-worker vs excluded/unhealthy/CB-open.
   * best_ep<0 or score<=0  → no candidate returned by inventory.
   * best_ep>=0 but filtered → excluded mask / inv / CB_OPEN. */
  if (best_ep < 0 || score <= 0) {
    log_info("[KV_T15] fd=%d GUARD_G no_worker best_ep=%d score=%d excluded_mask=0x%x prefill_mask=0x%x n_prefill_eps=%u",
             pfe->fd, best_ep, score, excluded_mask, prefill_mask,
             (unsigned)tepval->n_prefill_eps);
    atomic_fetch_add(&global_stats.pd_kv_t15_miss_no_worker, 1);
    KV_T15_FLUSH(KV_STAGE_OUTCOME_MISS);
    return -1;
  }

  /* Check excluded mask, health, circuit breaker */
  if (excluded_mask & (1u << (unsigned)best_ep)) {
    log_info("[KV_T15] fd=%d GUARD_G excluded best_ep=%d score=%d excluded_mask=0x%x reason=excluded_mask",
             pfe->fd, best_ep, score, excluded_mask);
    atomic_fetch_add(&global_stats.pd_kv_t15_miss_excluded, 1);
    KV_T15_FLUSH(KV_STAGE_OUTCOME_MISS);
    return -1;
  }
  if (tepval->eps[best_ep].inv) {
    log_info("[KV_T15] fd=%d GUARD_G excluded best_ep=%d score=%d excluded_mask=0x%x reason=ep_inv",
             pfe->fd, best_ep, score, excluded_mask);
    atomic_fetch_add(&global_stats.pd_kv_t15_miss_excluded, 1);
    KV_T15_FLUSH(KV_STAGE_OUTCOME_MISS);
    return -1;
  }
  if (tepval->cb_enabled &&
      tepval->circuit_breakers[best_ep].state == CB_STATE_OPEN) {
    log_info("[KV_T15] fd=%d GUARD_G excluded best_ep=%d score=%d excluded_mask=0x%x reason=cb_open",
             pfe->fd, best_ep, score, excluded_mask);
    atomic_fetch_add(&global_stats.pd_kv_t15_miss_excluded, 1);
    KV_T15_FLUSH(KV_STAGE_OUTCOME_MISS);
    return -1;
  }

  /* Tier-1.5 WIN: all 3 measured stages recorded on the HIT path. */
  KV_T15_FLUSH(KV_STAGE_OUTCOME_HIT);
#undef KV_T15_FLUSH
  *ep_out = best_ep;
  return 0;
}

#endif /* !TEST_KV_EXACT || TEST_KV_EXACT_WITH_GUARDS */
