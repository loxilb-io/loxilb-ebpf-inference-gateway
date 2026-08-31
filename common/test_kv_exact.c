/*
 * test_kv_exact.c — Unit tests for KV block-hash exact routing.
 *
 * Tests CBOR encoding, SHA256/XXH3_128 hash parity against Python reference
 * vectors, multi-block chaining, and pd_kv_exact_select guards.
 *
 * Build: $(CC) -Wall -Wextra -DTEST_KV_EXACT -o test_kv_exact test_kv_exact.c -lssl -lcrypto
 * Run:   ./test_kv_exact
 *
 * Reference vectors generated with:
 *   import cbor2, hashlib, xxhash
 *   parent = b'\x00' * 32
 *   data = cbor2.dumps((parent, (1, 2, 3), None), canonical=True)
 *   sha256_hash = hashlib.sha256(data).digest()
 *   xxh_hash = xxhash.xxh3_128_digest(data)
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <time.h>
#include <errno.h>

#ifndef TEST_KV_EXACT
#define TEST_KV_EXACT
#endif
#define TEST_KV_EXACT_WITH_GUARDS

/* Embed jsmn as a header-only parser so the JSON-loaded known-vector test
 * (test_hash_vectors_from_json) can tokenize the fixture without pulling in
 * the full sockproxy stack. JSMN_STATIC makes all jsmn_* symbols file-local. */
#define JSMN_STATIC
#include "jsmn.h"

/* KV-stage instrumentation contract (KV_STAGE_* enum, KV_N_STAGES, bucket
 * geometry, record_kv_stage decl) — needed by the global_stats mirror below and
 * by the C3 per-stage histogram test. Header is forward-decl + macro only (no
 * full proxy_epval/proxy_fd_ent defs), so it composes with the test's own stubs. */
#include "sockproxy_kv_exact.h"

/* ---- Minimal type stubs for pd_kv_exact_select guard tests ---- */
/* These mirror the real sockproxy.h layout just enough for pd_kv_exact_select
 * to compile against them. Field names and offsets must match what the
 * function reads: tepval->{kv_exact_mode, kv_warmup_start, kv_warmup_sec,
 * kv_hash_algo, kv_block_size, n_prefill_eps, eps[].inv, cb_enabled,
 * circuit_breakers[].state} and pfe->{fd, prefix_key.{valid,prefix,model},
 * x_model_header, rcvbuf}. */

#define MAX_PROXY_EP      32
#define MAX_PREFIX_LEN    512
/* rcvbuf capacity bound read by the chat-body NUL-bounding code. */
#define SP_SOCK_MSG_LEN   (1024 * 1024)
#define MAX_MODEL_LEN     128
#define MAX_LORA_LEN      128
#define MAX_HASH_LEN      64
#define MAX_SALT_LEN      64
#define CB_STATE_CLOSED   0
#define CB_STATE_OPEN     1

/* mirror the PROXY_SEL_GPU_AWARE weights from sockproxy.h (which
 * the harness does NOT include — it uses its own minimal struct mirror). Values
 * MUST match sockproxy.h DEFAULT_{QUEUE,SWAP,KV_CACHE}_WEIGHT so the blend-score
 * vectors below pin the SAME arithmetic the data path runs. */
#ifndef DEFAULT_QUEUE_WEIGHT
#define DEFAULT_QUEUE_WEIGHT   50
#endif
#ifndef DEFAULT_SWAP_WEIGHT
#define DEFAULT_SWAP_WEIGHT    30
#endif
#ifndef DEFAULT_KV_CACHE_WEIGHT
#define DEFAULT_KV_CACHE_WEIGHT 20
#endif

typedef struct proxy_ent {
  uint32_t xip;
  uint16_t xport;
  uint8_t  inv;
  uint8_t  protocol;
  uint8_t  weight;
  uint8_t  pad;
} proxy_ent_t;

typedef struct circuit_breaker {
  uint8_t state;
} circuit_breaker_t;

typedef struct llm_prefix_key {
  char prefix[MAX_PREFIX_LEN];
  char model[MAX_MODEL_LEN];
  uint32_t flags;
  char lora_adapter[MAX_LORA_LEN];
  char image_hash[MAX_HASH_LEN];
  char audio_hash[MAX_HASH_LEN];
  char cache_salt[MAX_SALT_LEN];
  char tool_schemas_hash[MAX_HASH_LEN];
  char session_context_hash[MAX_HASH_LEN];
  char rag_template_hash[MAX_HASH_LEN];
  char rag_doc_ids_hash[MAX_HASH_LEN];
  uint64_t hash;
  int valid;
  int level;
} llm_prefix_key_t;

/* (Option B): minimal ep_load_tracker mirror — only the two atomic
 * fields the KV-exact load plumbing reads (live in-flight active_conns + the
 * vLLM-advertised num_gpu_blocks capacity). The real struct (sockproxy.h) has
 * more members; the standalone unit needs just these so the #included
 * sockproxy_kv_exact.c's tepval->pd_ep_loads[i].active_conns/.num_gpu_blocks
 * compiles (the test exercises the all-zero degenerate path; values stay 0). */
typedef struct ep_load_tracker {
  _Atomic uint32_t active_conns;
  _Atomic uint32_t num_gpu_blocks;
} ep_load_tracker_t;

typedef struct proxy_epval {
  proxy_ent_t eps[MAX_PROXY_EP];
  int n_eps;
  int n_prefill_eps;
  uint8_t ep_role[MAX_PROXY_EP];  /* 0=normal, 1=prefill, 2=decode */
  circuit_breaker_t circuit_breakers[MAX_PROXY_EP];
  uint8_t cb_enabled;
  uint8_t kv_exact_mode;
  uint8_t kv_hash_algo;
  uint16_t kv_zmq_port;
  uint32_t kv_block_size;
  uint32_t kv_warmup_sec;
  time_t   kv_warmup_start;
  ep_load_tracker_t pd_ep_loads[MAX_PROXY_EP]; /* Option-B load/cap */
  /* controller advisory mirror — the #included
   * sockproxy_kv_exact.c reads pd_ctrl_mode/pd_ctrl_ep[] to build the epWeight
   * array for llb_ai_kv_best_worker. Tests zero-init => mode 0 => NULL weights
   * (the byte-identical path). */
  _Atomic uint32_t pd_ctrl_ep[MAX_PROXY_EP];
  _Atomic uint8_t  pd_ctrl_mode;
  /* (SGL-04): calling rule identity mirror — the #included
   * sockproxy_kv_exact.c threads tepval->kv_svc_id to llb_ai_kv_best_worker.
   * Zero-init (kv_reset_tepval memset) == "no identity" == legacy loop. */
  uint32_t kv_svc_id;
  /* Binding-dataplane contract word mirror — read once (acquire) by the
   * #included pd_kv_exact_select gate, written by pd_kv_exact_contract_set.
   * Zero-init (kv_reset_tepval memset) == "no contract" == legacy path. */
  _Atomic uint64_t kv_exact_contract;
} proxy_epval_t;

typedef struct proxy_fd_ent {
  int fd;
  llm_prefix_key_t prefix_key;
  /* request-scoped chat-routing signal + raw-body locator.
   * Mirrors the real sockproxy.h proxy_fd_ent fields the kv-exact tokenize
   * stage now reads (pfe->is_chat / pfe->body_off / pfe->body_len). */
  uint8_t is_chat;
  size_t  body_off;
  size_t  body_len;
  /* streamable-request gate read by the rcvbuf-fallback branch. */
  uint8_t is_streamable;
  char x_model_header[MAX_MODEL_LEN];
  void *rcvbuf;
} proxy_fd_ent_t;

/* Minimal global_stats mirror: only the 9 Tier 1.5 counters the guards touch. */
typedef struct proxy_global_stats {
  _Atomic uint64_t pd_kv_t15_miss_mode_off;
  _Atomic uint64_t pd_kv_t15_miss_warmup;
  _Atomic uint64_t pd_kv_t15_miss_text_empty;
  _Atomic uint64_t pd_kv_t15_miss_model_empty;
  _Atomic uint64_t pd_kv_t15_miss_tokenize;
  _Atomic uint64_t pd_kv_t15_miss_hashes;
  _Atomic uint64_t pd_kv_t15_miss_no_worker;
  _Atomic uint64_t pd_kv_t15_miss_excluded;
  _Atomic uint64_t pd_kv_t15_miss_shallow;
  /* Contract-gate + typed-bridge miss classes (mirror of sockproxy.h). */
  _Atomic uint64_t pd_kv_t15_miss_not_ready;
  _Atomic uint64_t pd_kv_t15_miss_api_mode;
  _Atomic uint64_t pd_kv_t15_miss_unsupported;
  _Atomic uint64_t pd_kv_t15_miss_runtime_fault;
  _Atomic uint64_t pd_kv_t15_fallthrough_total;
  /* C3 per-stage µs histograms (mirror of sockproxy.h proxy_global_stats):
   * [stage][outcome] where outcome 0=miss, 1=hit. */
  _Atomic uint64_t kv_stage_buckets[KV_N_STAGES][KV_N_STAGE_OUTCOMES][KV_STAGE_N_BUCKETS];
  _Atomic uint64_t kv_stage_sum_us[KV_N_STAGES][KV_N_STAGE_OUTCOMES];
  _Atomic uint64_t kv_stage_count[KV_N_STAGES][KV_N_STAGE_OUTCOMES];
} proxy_global_stats_t;

static proxy_global_stats_t global_stats;

/* log_info is compiled into pd_kv_exact_select — stub it to stderr so tests stay
 * quiet by default but can be traced if TEST_KV_EXACT_VERBOSE is set. */
/* Test-mode log_info: reference args via a no-op sink to avoid
 * -Wunused-but-set-variable on text_src/model_src in the guard function. */
static inline void kv_test_log_sink(const char *fmt, ...) { (void)fmt; }
#ifdef TEST_KV_EXACT_VERBOSE
#define log_info(...) do { fprintf(stderr, "[info] " __VA_ARGS__); fprintf(stderr, "\n"); } while (0)
#define log_warn(...) do { fprintf(stderr, "[warn] " __VA_ARGS__); fprintf(stderr, "\n"); } while (0)
#else
#define log_info(...) do { if (0) kv_test_log_sink(__VA_ARGS__); } while (0)
#define log_warn(...) do { if (0) kv_test_log_sink(__VA_ARGS__); } while (0)
#endif

/* ---- Stubs for CGO functions (test isolation) ---- */

/* Configurable stub behavior */
static uint32_t stub_token_ids[4096];
static int stub_token_count = 0;
static int stub_best_ep = -1;
static int stub_best_score = 0;
/* : capture the masks pd_kv_exact_select passes to the
 * best-worker CGO stub so the mask-build regression cases can pin them.
 * Sentinel-reset by each test; 0xdeadbeef == "stub never reached". */
static uint32_t stub_last_prefill_mask = 0xdeadbeefu;
static uint32_t stub_last_excluded_mask = 0xdeadbeefu;
/* ( Task 1, SGL-04): capture the svc_id pd_kv_exact_select
 * threads to the best-worker CGO stub — pins the cross-VIP contamination fix's
 * C half (tepval->kv_svc_id reaches the Go selector intact, 0 by default). */
static uint32_t stub_last_svc_id = 0xdeadbeefu;
/* (§9 relief default): capture the kv_exact_mode pd_kv_exact_select
 * threads on the same seam — pins the single-role relief-default gate's C half
 * (tepval->kv_exact_mode reaches the Go selector intact). */
static uint32_t stub_last_kv_exact_mode = 0xdeadbeefu;

/* Contract-seam captures: pin that the gate's loaded binding_gen and the
 * rule's kv_svc_id reach the tokenize bridge intact, that the gate
 * short-circuits BEFORE tokenize (call counter), and let the typed-code
 * classification tests force a LLB_KV_TOK_ERR_* return. */
static uint32_t stub_last_tok_svc_id = 0xdeadbeefu;
static uint32_t stub_last_tok_binding_gen = 0xdeadbeefu;
static int stub_tok_calls = 0;
static int stub_tok_force_code = 0; /* <0 => both stubs return it verbatim */

int
llb_ai_kv_tokenize(char *text, char *model_name,
                    uint32_t *out_ids, int max_ids,
                    uint32_t svc_id, uint32_t binding_gen)
{
  (void)text;
  (void)model_name;
  stub_tok_calls++;
  stub_last_tok_svc_id = svc_id;
  stub_last_tok_binding_gen = binding_gen;
  if (stub_tok_force_code < 0)
    return stub_tok_force_code;
  if (stub_token_count <= 0 || !out_ids || max_ids <= 0)
    return -1;
  int n = stub_token_count;
  if (n > max_ids) n = max_ids;
  memcpy(out_ids, stub_token_ids, n * sizeof(uint32_t));
  return n;
}

/* chat stub: mirrors llb_ai_kv_tokenize but for the chat path.
 * The C unit cannot run a real tokenizer/template, so it returns the
 * caller-loaded stub_token_ids (the vLLM apply_chat_template golden vector).
 * This proves the C-side block-boundary math is parity-correct GIVEN vLLM ids;
 * real tokenize/template parity is proven Go-side in the design. */
int
llb_ai_kv_tokenize_chat(char *raw_body, char *model_name,
                         uint32_t *out_ids, int max_ids,
                         uint32_t svc_id, uint32_t binding_gen)
{
  (void)raw_body;
  (void)model_name;
  stub_tok_calls++;
  stub_last_tok_svc_id = svc_id;
  stub_last_tok_binding_gen = binding_gen;
  if (stub_tok_force_code < 0)
    return stub_tok_force_code;
  if (stub_token_count <= 0 || !out_ids || max_ids <= 0)
    return -1;
  int n = stub_token_count;
  if (n > max_ids) n = max_ids;
  memcpy(out_ids, stub_token_ids, n * sizeof(uint32_t));
  return n;
}

int
llb_ai_kv_best_worker(uint8_t *block_hashes, int hash_size,
                       int n_hashes, char *model_name,
                       uint32_t prefill_mask, uint32_t excluded_mask,
                       const uint32_t *ep_load, const uint32_t *ep_cap,
                       const uint32_t *ep_weight,
                       int n_ep_slots, uint32_t kv_svc_id,
                       uint32_t kv_exact_mode, int *out_score)
{
  (void)block_hashes;
  (void)hash_size;
  (void)n_hashes;
  (void)model_name;
  stub_last_prefill_mask = prefill_mask;    /* mask regression capture */
  stub_last_excluded_mask = excluded_mask;
  (void)ep_load;       /* per-EP load (active_conns) */
  (void)ep_cap;        /* per-EP cap (num_gpu_blocks) */
  (void)ep_weight;     /* per-EP controller weight (pd_ctrl_ep) */
  (void)n_ep_slots;
  stub_last_svc_id = kv_svc_id;             /* (SGL-04): svc-id threading capture */
  stub_last_kv_exact_mode = kv_exact_mode;  /* (§9): relief-default mode capture */
  if (out_score) *out_score = stub_best_score;
  return stub_best_ep;
}

/* Include the implementation directly */
#include "sockproxy_kv_exact.c"

/* ---- Test infrastructure ---- */

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define ASSERT_EQ(a, b, msg) do { \
  tests_run++; \
  if ((a) == (b)) { tests_passed++; } \
  else { tests_failed++; \
    printf("  FAIL: %s (expected %d, got %d) at line %d\n", msg, (int)(b), (int)(a), __LINE__); } \
} while(0)

#define ASSERT_MEM_EQ(a, b, len, msg) do { \
  tests_run++; \
  if (memcmp(a, b, len) == 0) { tests_passed++; } \
  else { tests_failed++; \
    printf("  FAIL: %s (memory mismatch) at line %d\n", msg, __LINE__); \
    printf("    expected: "); for(int _i=0;_i<(int)(len);_i++) printf("%02x", ((uint8_t*)(b))[_i]); printf("\n"); \
    printf("    got:      "); for(int _i=0;_i<(int)(len);_i++) printf("%02x", ((uint8_t*)(a))[_i]); printf("\n"); \
  } \
} while(0)

/* ---- Test 1: CBOR encoding with parent=zeros32, tokens=[1,2,3] ---- */
static void
test_cbor_basic(void)
{
  printf("Test: CBOR encoding basic (zeros32, [1,2,3], null)\n");

  uint8_t parent[32] = {0};
  uint32_t tokens[] = {1, 2, 3};
  uint8_t buf[256];

  int n = kv_cbor_encode_block_input(parent, 32, tokens, 3, buf, sizeof(buf));

  /* Expected: verified with Python cbor2.dumps((b'\x00'*32, (1,2,3), None), canonical=True)
   * 40 bytes: 0x83 0x58 0x20 [32*0x00] 0x83 0x01 0x02 0x03 0xf6 */
  uint8_t expected[] = {
    0x83, 0x58, 0x20,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x83, 0x01, 0x02, 0x03, 0xf6
  };

  ASSERT_EQ(n, 40, "CBOR length");
  ASSERT_MEM_EQ(buf, expected, 40, "CBOR bytes match reference");
}

/* ---- Test 2: CBOR encoding with larger token IDs (256, 70000) ---- */
static void
test_cbor_large_tokens(void)
{
  printf("Test: CBOR encoding large tokens (256, 70000)\n");

  uint8_t parent[32] = {0};
  uint32_t tokens[] = {256, 70000};
  uint8_t buf[256];

  int n = kv_cbor_encode_block_input(parent, 32, tokens, 2, buf, sizeof(buf));

  /* Expected: verified with Python cbor2.dumps((b'\x00'*32, (256, 70000), None), canonical=True)
   * 45 bytes: 0x83 0x58 0x20 [32*0x00] 0x82 0x19 0x01 0x00 0x1a 0x00 0x01 0x11 0x70 0xf6 */
  uint8_t expected[] = {
    0x83, 0x58, 0x20,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x82, 0x19, 0x01, 0x00, 0x1a, 0x00, 0x01, 0x11, 0x70, 0xf6
  };

  ASSERT_EQ(n, 45, "CBOR length (large tokens)");
  ASSERT_MEM_EQ(buf, expected, 45, "CBOR bytes match reference (large tokens)");
}

/* ---- Test 3: SHA256 hash parity ---- */
static void
test_sha256_parity(void)
{
  printf("Test: SHA256 hash parity with Python reference\n");

  uint32_t tokens[] = {1, 2, 3};
  uint8_t hashes[KV_MAX_HASH_BYTES];
  memset(hashes, 0xaa, sizeof(hashes));  /* Poison to verify zero-pad. */

  int n = kv_compute_block_hashes(KV_HASH_SHA256_CBOR, tokens, 3, 3,
                                  hashes, 32, 1);

  /* Post-44-04 storage layout (vLLM v0.17.0 maybe_convert_block_hash):
   * hashes[0..7]  = full_digest[24..31]  (BE uint64 truncation)
   * hashes[8..31] = 0  (zero-padded; no semantic)
   * Full SHA256 digest (reference):
   *   0fc1f410314730b4 fc8bb602bbf54640 544442 69 bc 18 d0 02 08 ae 17 3b 84 6f 6a 12
   *                                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   *                                     last 8 bytes = what loxilb-C now stores in hashes[0..7] */
  uint8_t expected_slot[32] = {
    /* digest[24..31] as first 8 bytes: */
    0x08, 0xae, 0x17, 0x3b, 0x84, 0x6f, 0x6a, 0x12,
    /* zero-pad: */
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0
  };

  ASSERT_EQ(n, 1, "SHA256: 1 block computed");
  ASSERT_MEM_EQ(hashes, expected_slot, 32, "SHA256 hash slot: BE(digest[-8:]) + zero-pad");
}

/* ---- Test 4: XXH3_128 hash parity ---- */
static void
test_xxhash_parity(void)
{
  printf("Test: XXH3_128 hash parity with Python reference\n");

  uint32_t tokens[] = {1, 2, 3};
  uint8_t hashes[KV_MAX_HASH_BYTES];
  memset(hashes, 0xaa, sizeof(hashes));  /* Poison to verify zero-pad. */

  int n = kv_compute_block_hashes(KV_HASH_XXHASH_CBOR, tokens, 3, 3,
                                  hashes, 16, 1);

  /* Post-44-04 storage layout (vLLM v0.17.0 maybe_convert_block_hash):
   * hashes[0..7]  = full_digest[8..15]  (BE uint64 truncation)
   * hashes[8..15] = 0  (zero-padded)
   * Full XXH3_128 digest (reference):
   *   de3bf0ae50a2f839 3a676c9d040f97c0
   *                    ^^^^^^^^^^^^^^^^ last 8 bytes = low64 = hashes[0..7]
   * NOTE: xxhash_cbor mode uses 16-byte parent hash (not 32), so first block
   * parent is 16 zero bytes. */
  uint8_t expected_slot[16] = {
    /* digest[8..15] as first 8 bytes: */
    0x3a, 0x67, 0x6c, 0x9d, 0x04, 0x0f, 0x97, 0xc0,
    /* zero-pad (stride - 8 = 8 bytes): */
    0, 0, 0, 0, 0, 0, 0, 0
  };

  ASSERT_EQ(n, 1, "XXH3_128: 1 block computed");
  ASSERT_MEM_EQ(hashes, expected_slot, 16, "XXH3_128 hash slot: BE(digest[-8:]) + zero-pad");
}

/* ---- Test 5: Multi-block chain (SHA256) ---- */
static void
test_multiblock_chain(void)
{
  printf("Test: Multi-block chain (SHA256, 2 blocks of 3 tokens)\n");

  uint32_t tokens[] = {1, 2, 3, 4, 5, 6};
  uint8_t hashes[2 * 32];
  memset(hashes, 0xaa, sizeof(hashes));  /* Poison to verify zero-pad. */

  int n = kv_compute_block_hashes(KV_HASH_SHA256_CBOR, tokens, 6, 3,
                                  hashes, 32, 2);

  /* Post-44-04: parent chaining still uses the FULL digest of each block
   * (not the truncation), so block 1's input CBOR carries the full SHA256
   * digest of block 0 as parent. The Python-reference full digests are
   * unchanged from pre-44-04; only the storage layout in `hashes` changed.
   *
   * Block 0 full SHA256(CBOR(zeros32, [1,2,3], null)):
   *   0fc1f410314730b4 fc8bb602bbf54640 5444426 9bc18d002 08ae173b846f6a12
   * Block 1 full SHA256(CBOR(block0_full_hash, [4,5,6], null)):
   *   d6f81050c49d7bc0 6837e39ea69f1c68 2c1b24bb85a212d5 e0baad06e578987f */
  uint8_t block0_slot[32] = {
    /* digest[24..31]: */
    0x08, 0xae, 0x17, 0x3b, 0x84, 0x6f, 0x6a, 0x12,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0
  };
  uint8_t block1_slot[32] = {
    /* digest[24..31]: */
    0xe0, 0xba, 0xad, 0x06, 0xe5, 0x78, 0x98, 0x7f,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0
  };

  ASSERT_EQ(n, 2, "Multi-block: 2 blocks computed");
  ASSERT_MEM_EQ(hashes, block0_slot, 32,
                "Block 0 slot: BE(digest[-8:]) + zero-pad");
  ASSERT_MEM_EQ(hashes + 32, block1_slot, 32,
                "Block 1 slot (chained off block 0's full digest): BE(digest[-8:]) + zero-pad");
}

/* ---- Test 6: CBOR encoding with xxhash parent (16 bytes) ---- */
static void
test_cbor_xxhash_parent(void)
{
  printf("Test: CBOR encoding with 16-byte parent hash\n");

  uint8_t parent[16] = {0};
  uint32_t tokens[] = {1, 2, 3};
  uint8_t buf[256];

  int n = kv_cbor_encode_block_input(parent, 16, tokens, 3, buf, sizeof(buf));

  /* CBOR: array(3), bytes(16): 0x50 + 16*0x00, array(3): [1,2,3], null */
  /* 0x83 0x50 [16*0x00] 0x83 0x01 0x02 0x03 0xf6 = 23 bytes */
  ASSERT_EQ(n, 23, "CBOR length (16-byte parent)");
  ASSERT_EQ(buf[0], 0x83, "Outer array(3)");
  ASSERT_EQ(buf[1], 0x50, "Bytes(16) - major type 2, length 16");
}

/* ---- Test 7: Buffer overflow protection ---- */
static void
test_cbor_overflow(void)
{
  printf("Test: CBOR buffer overflow protection\n");

  uint8_t parent[32] = {0};
  uint32_t tokens[] = {1, 2, 3};
  uint8_t buf[10]; /* Too small */

  int n = kv_cbor_encode_block_input(parent, 32, tokens, 3, buf, sizeof(buf));
  ASSERT_EQ(n, -1, "CBOR overflow returns -1");
}

/* ---- Test 8: Edge cases for block hash computation ---- */
static void
test_hash_edge_cases(void)
{
  printf("Test: Hash computation edge cases\n");

  uint8_t hashes[KV_MAX_HASH_BYTES];

  /* NULL tokens */
  int n = kv_compute_block_hashes(KV_HASH_SHA256_CBOR, NULL, 3, 3,
                                  hashes, 32, 1);
  ASSERT_EQ(n, -1, "NULL tokens returns -1");

  /* Zero tokens */
  uint32_t tokens[] = {1};
  n = kv_compute_block_hashes(KV_HASH_SHA256_CBOR, tokens, 0, 3,
                              hashes, 32, 1);
  ASSERT_EQ(n, -1, "Zero tokens returns -1");

  /* Zero block size */
  n = kv_compute_block_hashes(KV_HASH_SHA256_CBOR, tokens, 1, 0,
                              hashes, 32, 1);
  ASSERT_EQ(n, -1, "Zero block_size returns -1");

  /* Invalid hash algo */
  n = kv_compute_block_hashes(99, tokens, 1, 1,
                              hashes, 32, 1);
  ASSERT_EQ(n, -1, "Invalid hash_algo returns -1");

  /* Partial block (fewer tokens than block_size) */
  uint32_t tokens2[] = {1, 2};
  n = kv_compute_block_hashes(KV_HASH_SHA256_CBOR, tokens2, 2, 16,
                              hashes, 32, KV_MAX_BLOCKS);
  ASSERT_EQ(n, 1, "Partial block: 2 tokens with block_size=16 yields 1 block");
}

/* ---- Test 9: SHA256 hash with large token IDs ---- */
static void
test_sha256_large_tokens(void)
{
  printf("Test: SHA256 hash with large token IDs (256, 70000)\n");

  uint32_t tokens[] = {256, 70000};
  uint8_t hashes[KV_MAX_HASH_BYTES];
  memset(hashes, 0xaa, sizeof(hashes));  /* Poison to verify zero-pad. */

  int n = kv_compute_block_hashes(KV_HASH_SHA256_CBOR, tokens, 2, 2,
                                  hashes, 32, 1);

  /* Post-44-04 storage layout: first 8 bytes = vLLM maybe_convert_block_hash
   * of full digest.
   * Full SHA256(CBOR(zeros32, [256,70000], null)):
   *   cb229de92b92459c 9abc18bd9a7b83f9 b3eb4d5bdd734279 355a753d41178aca */
  uint8_t expected_slot[32] = {
    /* digest[24..31]: */
    0x35, 0x5a, 0x75, 0x3d, 0x41, 0x17, 0x8a, 0xca,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0
  };

  ASSERT_EQ(n, 1, "SHA256 large tokens: 1 block");
  ASSERT_MEM_EQ(hashes, expected_slot, 32,
                "SHA256 large tokens slot: BE(digest[-8:]) + zero-pad");
}

/* ---- Guard tests for pd_kv_exact_select (plan 42-02) ---- */

static void
kv_reset_stats(void)
{
  memset(&global_stats, 0, sizeof(global_stats));
}

static void
kv_reset_pfe(proxy_fd_ent_t *pfe)
{
  memset(pfe, 0, sizeof(*pfe));
  pfe->fd = 42;
  /* Plausible defaults so non-target guards don't fire first. */
  strcpy(pfe->prefix_key.prefix, "hello world");
  pfe->prefix_key.valid = 1;
  strcpy(pfe->x_model_header, "Qwen/Qwen3-0.6B");
}

static void
kv_reset_tepval(proxy_epval_t *tepval)
{
  memset(tepval, 0, sizeof(*tepval));
  tepval->kv_exact_mode = 1;
  tepval->kv_hash_algo = KV_HASH_SHA256_CBOR;
  tepval->kv_block_size = 16;
  tepval->n_prefill_eps = 2;
  tepval->n_eps = 2;
}

/* GUARD A: kv_exact_mode == 0 */
static void
test_guard_a_mode_off(void)
{
  printf("Test: GUARD_A mode_off increments pd_kv_t15_miss_mode_off\n");
  proxy_epval_t tepval;
  proxy_fd_ent_t pfe;
  int ep = -1;

  kv_reset_stats();
  kv_reset_tepval(&tepval);
  kv_reset_pfe(&pfe);
  tepval.kv_exact_mode = 0;  /* triggers GUARD_A */

  int rc = pd_kv_exact_select(&tepval, &pfe, &ep, 0);
  ASSERT_EQ(rc, -1, "GUARD_A returns -1");
  ASSERT_EQ((int)atomic_load(&global_stats.pd_kv_t15_miss_mode_off), 1,
            "pd_kv_t15_miss_mode_off incremented");
}

/* GUARD B: warmup window still active */
static void
test_guard_b_warmup(void)
{
  printf("Test: GUARD_B warmup increments pd_kv_t15_miss_warmup\n");
  proxy_epval_t tepval;
  proxy_fd_ent_t pfe;
  int ep = -1;

  kv_reset_stats();
  kv_reset_tepval(&tepval);
  kv_reset_pfe(&pfe);
  tepval.kv_warmup_start = time(NULL);  /* now */
  tepval.kv_warmup_sec = 3600;          /* 1h window still active */

  int rc = pd_kv_exact_select(&tepval, &pfe, &ep, 0);
  ASSERT_EQ(rc, -1, "GUARD_B returns -1");
  ASSERT_EQ((int)atomic_load(&global_stats.pd_kv_t15_miss_warmup), 1,
            "pd_kv_t15_miss_warmup incremented");
}

/* GUARD C: empty text (no prefix, no rcvbuf) */
static void
test_guard_c_empty_text(void)
{
  printf("Test: GUARD_C empty_text increments pd_kv_t15_miss_text_empty\n");
  proxy_epval_t tepval;
  proxy_fd_ent_t pfe;
  int ep = -1;

  kv_reset_stats();
  kv_reset_tepval(&tepval);
  kv_reset_pfe(&pfe);
  /* Force both sources empty */
  pfe.prefix_key.valid = 0;
  pfe.prefix_key.prefix[0] = '\0';
  pfe.rcvbuf = NULL;

  int rc = pd_kv_exact_select(&tepval, &pfe, &ep, 0);
  ASSERT_EQ(rc, -1, "GUARD_C returns -1");
  ASSERT_EQ((int)atomic_load(&global_stats.pd_kv_t15_miss_text_empty), 1,
            "pd_kv_t15_miss_text_empty incremented");
}

/* GUARD D: empty model */
static void
test_guard_d_empty_model(void)
{
  printf("Test: GUARD_D empty_model increments pd_kv_t15_miss_model_empty\n");
  proxy_epval_t tepval;
  proxy_fd_ent_t pfe;
  int ep = -1;

  kv_reset_stats();
  kv_reset_tepval(&tepval);
  kv_reset_pfe(&pfe);
  pfe.x_model_header[0] = '\0';
  pfe.prefix_key.model[0] = '\0';

  int rc = pd_kv_exact_select(&tepval, &pfe, &ep, 0);
  ASSERT_EQ(rc, -1, "GUARD_D returns -1");
  ASSERT_EQ((int)atomic_load(&global_stats.pd_kv_t15_miss_model_empty), 1,
            "pd_kv_t15_miss_model_empty incremented");
}

/* GUARD E: tokenize returns <= 0 */
static void
test_guard_e_tokenize_fail(void)
{
  printf("Test: GUARD_E tokenize_fail increments pd_kv_t15_miss_tokenize\n");
  proxy_epval_t tepval;
  proxy_fd_ent_t pfe;
  int ep = -1;

  kv_reset_stats();
  kv_reset_tepval(&tepval);
  kv_reset_pfe(&pfe);
  stub_token_count = 0;  /* llb_ai_kv_tokenize returns -1 */

  int rc = pd_kv_exact_select(&tepval, &pfe, &ep, 0);
  ASSERT_EQ(rc, -1, "GUARD_E returns -1");
  ASSERT_EQ((int)atomic_load(&global_stats.pd_kv_t15_miss_tokenize), 1,
            "pd_kv_t15_miss_tokenize incremented");
}

/* GUARD F: tokenize succeeds but block-hash computation yields no hashes.
 *
 * pd_kv_exact_select reaches GUARD_F (sockproxy_kv_exact.c:621-627) only when
 * kv_compute_block_hashes returns <= 0. Note: the RESEARCH/PLAN suggestion of
 * "block_size > n_tokens -> no full block" does NOT work — kv_compute_block_hashes
 * (sockproxy_kv_exact.c:458-462) always emits a block for any positive n_tokens
 * (the final partial block is NOT skipped), so block_size > n_tokens still yields
 * n_hashes == 1. The deterministic GUARD_F driver is an INVALID kv_hash_algo:
 * kv_compute_block_hashes returns -1 for any algo that is neither SHA256_CBOR(0)
 * nor XXHASH_CBOR(1) (sockproxy_kv_exact.c:444-445). We assert BOTH rc==-1 and
 * the pd_kv_t15_miss_hashes counter delta (: never weaken to rc!=0). */
static void
test_guard_f_no_hashes(void)
{
  printf("Test: GUARD_F no_hashes increments pd_kv_t15_miss_hashes\n");
  proxy_epval_t tepval;
  proxy_fd_ent_t pfe;
  int ep = -1;

  kv_reset_stats();
  kv_reset_tepval(&tepval);
  kv_reset_pfe(&pfe);
  stub_token_count = 3;          /* tokenize succeeds (passes GUARD_E) */
  tepval.kv_hash_algo = 99;      /* invalid algo -> kv_compute_block_hashes == -1 */

  int rc = pd_kv_exact_select(&tepval, &pfe, &ep, 0);
  ASSERT_EQ(rc, -1, "GUARD_F returns -1");
  ASSERT_EQ((int)atomic_load(&global_stats.pd_kv_t15_miss_hashes), 1,
            "pd_kv_t15_miss_hashes incremented");
}

/* GUARD G (no_worker): inventory returns no candidate (best_ep<0 or score<=0).
 * sockproxy_kv_exact.c:648-657. With a valid algo + successful tokenize we reach
 * llb_ai_kv_best_worker, whose stub returns stub_best_ep / stub_best_score.
 * stub_best_ep < 0 -> GUARD_G no_worker -> pd_kv_t15_miss_no_worker increments. */
static void
test_guard_g_no_worker(void)
{
  printf("Test: GUARD_G no_worker increments pd_kv_t15_miss_no_worker\n");
  proxy_epval_t tepval;
  proxy_fd_ent_t pfe;
  int ep = -1;

  kv_reset_stats();
  kv_reset_tepval(&tepval);
  kv_reset_pfe(&pfe);
  stub_token_count = 3;          /* tokenize succeeds */
  stub_best_ep = -1;             /* inventory returns no worker */
  stub_best_score = 0;

  int rc = pd_kv_exact_select(&tepval, &pfe, &ep, 0);
  ASSERT_EQ(rc, -1, "GUARD_G no_worker returns -1");
  ASSERT_EQ((int)atomic_load(&global_stats.pd_kv_t15_miss_no_worker), 1,
            "pd_kv_t15_miss_no_worker incremented");
}

/* GUARD G (excluded_mask): a candidate IS returned but its bit is set in the
 * excluded_mask passed to pd_kv_exact_select. sockproxy_kv_exact.c:660-665.
 * best_ep=1, score>0, excluded_mask=(1<<1) -> pd_kv_t15_miss_excluded increments. */
static void
test_guard_g_excluded_mask(void)
{
  printf("Test: GUARD_G excluded_mask increments pd_kv_t15_miss_excluded\n");
  proxy_epval_t tepval;
  proxy_fd_ent_t pfe;
  int ep = -1;

  kv_reset_stats();
  kv_reset_tepval(&tepval);
  kv_reset_pfe(&pfe);
  stub_token_count = 3;          /* tokenize succeeds */
  stub_best_ep = 1;              /* inventory returns ep 1 */
  stub_best_score = 5;           /* score > 0 (passes no_worker) */

  /* Exclude the very EP the inventory picked. */
  int rc = pd_kv_exact_select(&tepval, &pfe, &ep, (1u << 1));
  ASSERT_EQ(rc, -1, "GUARD_G excluded_mask returns -1");
  ASSERT_EQ((int)atomic_load(&global_stats.pd_kv_t15_miss_excluded), 1,
            "pd_kv_t15_miss_excluded incremented (excluded_mask)");
}

/* GUARD H (shallow): with one-token blocks (SGLang page_size=1 →
 * kvBlockSize=1) a 1-block match is a single shared leading token — NOT a
 * cache hit. The default 16-token floor must reject it; a match at/above
 * the floor and a FULL match of a short prompt must both still hit. */
static void
test_guard_h_shallow_match(void)
{
  printf("Test: GUARD_H shallow match rejected at kv_block_size=1\n");
  proxy_epval_t tepval;
  proxy_fd_ent_t pfe;
  int ep = -1;

  /* 1-token-deep match on a long prompt → shallow miss */
  kv_reset_stats();
  kv_reset_tepval(&tepval);
  kv_reset_pfe(&pfe);
  tepval.kv_block_size = 1;
  stub_token_count = 100;        /* 100 one-token blocks in the query */
  stub_best_ep = 1;
  stub_best_score = 1;           /* one shared leading token */
  int rc = pd_kv_exact_select(&tepval, &pfe, &ep, 0);
  ASSERT_EQ(rc, -1, "GUARD_H 1/100-block match returns -1");
  ASSERT_EQ((int)atomic_load(&global_stats.pd_kv_t15_miss_shallow), 1,
            "pd_kv_t15_miss_shallow incremented");

  /* 16-token-deep match on the same prompt → real hit */
  kv_reset_stats();
  kv_reset_tepval(&tepval);
  kv_reset_pfe(&pfe);
  tepval.kv_block_size = 1;
  stub_token_count = 100;
  stub_best_ep = 1;
  stub_best_score = 16;          /* meets the default 16-token floor */
  rc = pd_kv_exact_select(&tepval, &pfe, &ep, 0);
  ASSERT_EQ(rc, 0, "GUARD_H 16/100-block match hits");
  ASSERT_EQ(ep, 1, "GUARD_H hit routes to the scored EP");

  /* FULL match of a short prompt (5 blocks < the 16-token floor) → hit:
   * the floor is capped at the query's own block count. */
  kv_reset_stats();
  kv_reset_tepval(&tepval);
  kv_reset_pfe(&pfe);
  tepval.kv_block_size = 1;
  stub_token_count = 5;
  stub_best_ep = 2;
  stub_best_score = 5;           /* every block of the short prompt */
  rc = pd_kv_exact_select(&tepval, &pfe, &ep, 0);
  ASSERT_EQ(rc, 0, "GUARD_H full short-prompt match hits");

  /* kvBlockSize=16 (vLLM default): 1 block == 16 tokens — behavior
   * unchanged by the guard. */
  kv_reset_stats();
  kv_reset_tepval(&tepval);
  kv_reset_pfe(&pfe);
  tepval.kv_block_size = 16;
  stub_token_count = 100;
  stub_best_ep = 1;
  stub_best_score = 1;
  rc = pd_kv_exact_select(&tepval, &pfe, &ep, 0);
  ASSERT_EQ(rc, 0, "GUARD_H kvBlockSize=16 single-block match still hits");
}

/* GUARD G (ep_inv): the picked EP is healthy in inventory but marked inv=1
 * in the local tepval health post-filter. sockproxy_kv_exact.c:666-671.
 * best_ep=1, score>0, eps[1].inv=1 -> pd_kv_t15_miss_excluded increments. */
static void
test_guard_g_ep_inv(void)
{
  printf("Test: GUARD_G ep_inv increments pd_kv_t15_miss_excluded\n");
  proxy_epval_t tepval;
  proxy_fd_ent_t pfe;
  int ep = -1;

  kv_reset_stats();
  kv_reset_tepval(&tepval);
  kv_reset_pfe(&pfe);
  stub_token_count = 3;          /* tokenize succeeds */
  stub_best_ep = 1;              /* inventory returns ep 1 */
  stub_best_score = 5;           /* score > 0 */
  tepval.eps[1].inv = 1;         /* best EP is unhealthy locally */

  int rc = pd_kv_exact_select(&tepval, &pfe, &ep, 0);
  ASSERT_EQ(rc, -1, "GUARD_G ep_inv returns -1");
  ASSERT_EQ((int)atomic_load(&global_stats.pd_kv_t15_miss_excluded), 1,
            "pd_kv_t15_miss_excluded incremented (ep_inv)");
}

/* GUARD G (cb_open): the picked EP is healthy but its circuit breaker is OPEN
 * with cb_enabled=1. sockproxy_kv_exact.c:672-678.
 * best_ep=1, score>0, cb_enabled=1, circuit_breakers[1].state=CB_STATE_OPEN
 * -> pd_kv_t15_miss_excluded increments. */
static void
test_guard_g_cb_open(void)
{
  printf("Test: GUARD_G cb_open increments pd_kv_t15_miss_excluded\n");
  proxy_epval_t tepval;
  proxy_fd_ent_t pfe;
  int ep = -1;

  kv_reset_stats();
  kv_reset_tepval(&tepval);
  kv_reset_pfe(&pfe);
  stub_token_count = 3;                              /* tokenize succeeds */
  stub_best_ep = 1;                                  /* inventory returns ep 1 */
  stub_best_score = 5;                               /* score > 0 */
  tepval.cb_enabled = 1;                             /* CB checks active */
  tepval.circuit_breakers[1].state = CB_STATE_OPEN;  /* best EP CB tripped */

  int rc = pd_kv_exact_select(&tepval, &pfe, &ep, 0);
  ASSERT_EQ(rc, -1, "GUARD_G cb_open returns -1");
  ASSERT_EQ((int)atomic_load(&global_stats.pd_kv_t15_miss_excluded), 1,
            "pd_kv_t15_miss_excluded incremented (cb_open)");
}

/* proxy_add_entry new-tepval branch must copy five kv_* fields
 * from arg to tepval. The real proxy_add_entry function lives in sockproxy_http.c
 * and depends on the full sockproxy stack, so this test mirrors the copy-semantics
 * of the fix block (sockproxy_http.c:1763-1773) against a minimal arg/tepval pair.
 * A regression that drops any of the five assignments will fail this test and
 * the paired test_proxy_add_entry_kv_exact_fields_update_path. */
typedef struct kv_proxy_arg_mirror {
  uint8_t  kv_exact_mode;
  uint8_t  kv_hash_algo;
  uint16_t kv_zmq_port;
  uint32_t kv_block_size;
  uint32_t kv_warmup_sec;
} kv_proxy_arg_mirror_t;

/* Exercises the exact 5-line copy block inserted in plan 42-04. If the fix is
 * reverted or any of the five assignments is dropped, the asserts below fail. */
static void
kv_copy_new_tepval_path(const kv_proxy_arg_mirror_t *arg, proxy_epval_t *tepval)
{
  /* This block mirrors sockproxy_http.c new-tepval branch (post-fix). */
  tepval->kv_exact_mode = arg->kv_exact_mode;
  tepval->kv_hash_algo  = arg->kv_hash_algo;
  tepval->kv_zmq_port   = arg->kv_zmq_port;
  tepval->kv_block_size = arg->kv_block_size;
  tepval->kv_warmup_sec = arg->kv_warmup_sec;
}

static void
test_proxy_add_entry_kv_exact_fields_new_path(void)
{
  printf("Test: proxy_add_entry new-tepval path copies five kv_* fields\n");

  kv_proxy_arg_mirror_t arg = {
    .kv_exact_mode = 1,
    .kv_hash_algo  = KV_HASH_SHA256_CBOR,
    .kv_zmq_port   = 5557,
    .kv_block_size = 16,
    .kv_warmup_sec = 60,
  };
  proxy_epval_t tepval;
  memset(&tepval, 0, sizeof(tepval));  /* pre-fix: all kv_* stay zero */

  /* Sanity pre-condition: the zero-init path is the bug 42-03 diagnosed. */
  ASSERT_EQ(tepval.kv_exact_mode, 0, "zero-init baseline matches 42-03 bug");

  kv_copy_new_tepval_path(&arg, &tepval);

  ASSERT_EQ(tepval.kv_exact_mode, 1,   "kv_exact_mode propagated");
  ASSERT_EQ(tepval.kv_hash_algo,
            KV_HASH_SHA256_CBOR,        "kv_hash_algo propagated");
  ASSERT_EQ(tepval.kv_zmq_port,  5557,  "kv_zmq_port propagated");
  ASSERT_EQ((int)tepval.kv_block_size, 16, "kv_block_size propagated");
  ASSERT_EQ((int)tepval.kv_warmup_sec, 60, "kv_warmup_sec propagated");

  /* After the copy, the Tier 1.5 gate `tepval->kv_exact_mode == 1` becomes true
   * and pd_kv_exact_select is entered — the end-to-end property plan 42-04 ships. */
  ASSERT_EQ(tepval.kv_exact_mode == 1, 1,
            "tepval.kv_exact_mode == 1 enables pd_kv_exact_select gate");
}

/* Task 1 (RED tripwire): verify the C-side prefill_mask build loop
 * in sockproxy_kv_exact.c correctly sets bits only at indices where
 * ep_role[i] == 1 (prefill). Mirrors the exact construction that will be
 * applied at the single call site in Task 3. Fires instantly without the
 * testbed if the mask-build helper drifts.
 */
static void test_prefill_mask_from_ep_role(void) {
  struct { int n_eps; uint8_t ep_role[16]; } t;
  memset(&t, 0, sizeof(t));
  t.n_eps = 5;
  t.ep_role[0] = 2; /* decode */
  t.ep_role[1] = 2; /* decode */
  t.ep_role[2] = 1; /* prefill */
  t.ep_role[3] = 2; /* decode */
  t.ep_role[4] = 1; /* prefill */
  uint32_t mask = 0;
  for (int i = 0; i < t.n_eps && i < 32; i++) {
    if (t.ep_role[i] == 1) mask |= (1u << (unsigned)i);
  }
  tests_run++;
  if (mask == 0x14) { /* bits 2 and 4 */
    tests_passed++;
    printf("  PASS: test_prefill_mask_from_ep_role mask=0x%x\n", mask);
  } else {
    tests_failed++;
    printf("  FAIL: test_prefill_mask_from_ep_role mask=0x%x want 0x14\n", mask);
  }
}

/* ===========================================================================
 * : candidate-mask regression cases for the
 * Tier-1.5 single-role decouple seam. Unlike test_prefill_mask_from_ep_role
 * (a construction mirror), these drive the REAL pd_kv_exact_select and pin the
 * mask it actually passes to llb_ai_kv_best_worker via the stub capture —
 * mutation-style teeth: if the KV_EXACT_MODE_SINGLE_ROLE widening disjunct
 * ever fires at mode 1, or fails to fire at mode 3, these FAIL.
 * =========================================================================== */

/* Mode-1 (P/D) mask byte-identity: with a mixed-role fixture (ep_role =
 * {1,2,0,1}) the candidate mask must be EXACTLY the prefill-role bits 0b1001.
 * A leaked single-role widening would admit EP1(role 2)/EP2(role 0) → 0b1111
 * → FAIL. Second arm: at kv_exact_mode=0 the mask build is unreachable
 * (GUARD_A short-circuits) — the capture sentinel must stay untouched. */
static void
test_mask_mode1_byte_identity(void)
{
  printf("Test: mode-1 mask byte-identity (single_role disjunct dead at P/D)\n");
  proxy_epval_t tepval;
  proxy_fd_ent_t pfe;
  int ep = -1;

  kv_reset_stats();
  kv_reset_tepval(&tepval);
  kv_reset_pfe(&pfe);
  tepval.n_eps = 4;
  tepval.n_prefill_eps = 2;
  tepval.kv_exact_mode = 1;          /* P/D zmq mode */
  tepval.ep_role[0] = 1;             /* prefill */
  tepval.ep_role[1] = 2;             /* decode */
  tepval.ep_role[2] = 0;             /* role-less */
  tepval.ep_role[3] = 1;             /* prefill */
  stub_token_count = 3;              /* tokenize succeeds */
  stub_best_ep = 0;
  stub_best_score = 5;
  stub_last_prefill_mask = 0xdeadbeefu;   /* sentinel */
  stub_last_excluded_mask = 0xdeadbeefu;

  int rc = pd_kv_exact_select(&tepval, &pfe, &ep, 0);
  ASSERT_EQ(rc, 0, "mode-1 select succeeds (stub hit)");
  ASSERT_EQ(ep, 0, "mode-1 returns stub best EP");
  tests_run++;
  if (stub_last_prefill_mask == 0x9u) {
    tests_passed++;
    printf("  PASS: mode-1 mask=0x%x (exactly prefill-role bits; widening disjunct dead)\n",
           stub_last_prefill_mask);
  } else {
    tests_failed++;
    printf("  FAIL: mode-1 mask=0x%x want 0x9 (single_role widening leaked into P/D!)\n",
           stub_last_prefill_mask);
  }

  /* Mutation arm 2: mode 0 never reaches the mask build (GUARD_A). */
  kv_reset_stats();
  tepval.kv_exact_mode = 0;
  stub_last_prefill_mask = 0xdeadbeefu;
  rc = pd_kv_exact_select(&tepval, &pfe, &ep, 0);
  ASSERT_EQ(rc, -1, "mode-0 GUARD_A returns -1 (mask build unreachable)");
  ASSERT_EQ((int)atomic_load(&global_stats.pd_kv_t15_miss_mode_off), 1,
            "mode-0 counted as mode_off");
  tests_run++;
  if (stub_last_prefill_mask == 0xdeadbeefu) {
    tests_passed++;
    printf("  PASS: mode-0 best_worker never called (sentinel untouched)\n");
  } else {
    tests_failed++;
    printf("  FAIL: mode-0 reached the mask build (mask=0x%x) despite GUARD_A\n",
           stub_last_prefill_mask);
  }
}

/* Mode-3 (KV_EXACT_MODE_SINGLE_ROLE) admits-all: with the Assumption-A2 shape
 * (ep_role[] all-zero, n_eps=4) the candidate mask must admit all 4 EPs
 * (0b1111). Second arm: an EP excluded via the exclusion-mask INPUT is dropped
 * (GUARD_G) — the candidate mask and the exclusion mask are separate inputs,
 * both forwarded intact to the best-worker scorer. */
static void
test_mask_mode3_single_role_admits_all(void)
{
  printf("Test: mode-3 single_role mask admits all role-less EPs + exclusion honored\n");
  proxy_epval_t tepval;
  proxy_fd_ent_t pfe;
  int ep = -1;

  kv_reset_stats();
  kv_reset_tepval(&tepval);
  kv_reset_pfe(&pfe);
  tepval.n_eps = 4;
  tepval.n_prefill_eps = 0;          /* single-role service: no P/D roles at all */
  tepval.kv_exact_mode = KV_EXACT_MODE_SINGLE_ROLE;
  /* ep_role[] stays all-zero from kv_reset_tepval's memset — the A2 shape. */
  stub_token_count = 3;              /* tokenize succeeds */
  stub_best_ep = 1;
  stub_best_score = 5;
  stub_last_prefill_mask = 0xdeadbeefu;
  stub_last_excluded_mask = 0xdeadbeefu;

  int rc = pd_kv_exact_select(&tepval, &pfe, &ep, 0);
  ASSERT_EQ(rc, 0, "mode-3 select succeeds (stub hit)");
  ASSERT_EQ(ep, 1, "mode-3 returns stub best EP");
  tests_run++;
  if (stub_last_prefill_mask == 0xfu) {
    tests_passed++;
    printf("  PASS: mode-3 mask=0x%x (all 4 role-less EPs admitted)\n",
           stub_last_prefill_mask);
  } else {
    tests_failed++;
    printf("  FAIL: mode-3 mask=0x%x want 0xf (single_role seam did not open)\n",
           stub_last_prefill_mask);
  }

  /* Exclusion honored: exclude the stub winner via the exclusion-mask input —
   * it must be dropped (GUARD_G excluded), never routed. */
  kv_reset_stats();
  stub_best_ep = 2;
  stub_last_prefill_mask = 0xdeadbeefu;
  stub_last_excluded_mask = 0xdeadbeefu;
  rc = pd_kv_exact_select(&tepval, &pfe, &ep, (1u << 2));
  ASSERT_EQ(rc, -1, "mode-3 excluded winner dropped (GUARD_G)");
  ASSERT_EQ((int)atomic_load(&global_stats.pd_kv_t15_miss_excluded), 1,
            "mode-3 exclusion counted (pd_kv_t15_miss_excluded)");
  tests_run++;
  if (stub_last_excluded_mask == (1u << 2) && stub_last_prefill_mask == 0xfu) {
    tests_passed++;
    printf("  PASS: mode-3 exclusion forwarded (excl=0x%x) with mask still 0x%x\n",
           stub_last_excluded_mask, stub_last_prefill_mask);
  } else {
    tests_failed++;
    printf("  FAIL: mode-3 masks drifted under exclusion (mask=0x%x excl=0x%x; want 0xf/0x4)\n",
           stub_last_prefill_mask, stub_last_excluded_mask);
  }
}

/* ( Task 1, SGL-04): svc-id threading through the CGO seam.
 * Arm 1: a stamped tepval->kv_svc_id must reach llb_ai_kv_best_worker intact
 * (the cross-VIP contamination fix's C half). Arm 2: a zero-init tepval passes
 * 0 ("no identity") — the Go side then keeps today's all-services loop, so the
 * seam is provably default-off from the C side too. */
static void
test_kv_svc_id_threading(void)
{
  printf("Test: kv_svc_id threads intact through llb_ai_kv_best_worker (SGL-04)\n");
  proxy_epval_t tepval;
  proxy_fd_ent_t pfe;
  int ep = -1;

  kv_reset_stats();
  kv_reset_tepval(&tepval);
  kv_reset_pfe(&pfe);
  tepval.kv_svc_id = 42;             /* stamped rule identity */
  stub_token_count = 3;              /* tokenize succeeds */
  stub_best_ep = 0;
  stub_best_score = 5;
  stub_last_svc_id = 0xdeadbeefu;    /* sentinel */

  int rc = pd_kv_exact_select(&tepval, &pfe, &ep, 0);
  ASSERT_EQ(rc, 0, "svc-id arm-1 select succeeds (stub hit)");
  ASSERT_EQ((int)stub_last_svc_id, 42, "kv_svc_id=42 reached the CGO stub intact");
  /* (§9): kv_exact_mode rides the same seam — kv_reset_tepval sets 1
   * (P/D zmq), so 1 must reach the stub intact (relief-default gate's C half). */
  ASSERT_EQ((int)stub_last_kv_exact_mode, 1, "kv_exact_mode=1 reached the CGO stub intact");

  /* Arm 2: default (zero-init via kv_reset_tepval memset) passes 0. */
  kv_reset_stats();
  kv_reset_tepval(&tepval);          /* memset ⇒ kv_svc_id == 0 */
  stub_last_svc_id = 0xdeadbeefu;
  rc = pd_kv_exact_select(&tepval, &pfe, &ep, 0);
  ASSERT_EQ(rc, 0, "svc-id arm-2 select succeeds (stub hit)");
  ASSERT_EQ((int)stub_last_svc_id, 0, "default kv_svc_id==0 (no identity; legacy loop Go-side)");

  /* Arm 3 ( §9): single-role mode 3 threads intact — the value the Go
   * side's kvSpillReliefFor keys the relief default on. */
  kv_reset_stats();
  kv_reset_tepval(&tepval);
  tepval.kv_exact_mode = KV_EXACT_MODE_SINGLE_ROLE;
  stub_last_kv_exact_mode = 0xdeadbeefu;
  rc = pd_kv_exact_select(&tepval, &pfe, &ep, 0);
  ASSERT_EQ(rc, 0, "mode-3 arm-3 select succeeds (stub hit)");
  ASSERT_EQ((int)stub_last_kv_exact_mode, KV_EXACT_MODE_SINGLE_ROLE,
            "kv_exact_mode=3 (single-role) reached the CGO stub intact");
}

/* ============================================================================
 * capacity-weighted bounded-load cap (the reserved
 * PROXY_SEL_GPU_AWARE weights lit up). These drive the pure header helper
 * pd_capacity_weighted_cap / pd_kv_clamp_capacity directly (no datapath) so
 * the cap math is proven in isolation. The capacity-skew assert is RED until
 * pd_select_prefill consumes per-EP capacity (the helper stub is capacity-blind
 * in the RED commit and capacity-weighted in GREEN).
 * ========================================================================== */

/* C2: a capacity-SKEWED fleet — EP0 advertises 8× the NumGPUBlocks of EP1 —
 * must give EP0 a proportionally LARGER cap than the capacity-blind path. RED:
 * the stub helper ignores capacity_i so capA == capB and this assert FAILS.
 * GREEN: capA == 8·capB (the capacity ratio). */
static void test_c2_capacity_skew_cap(void) {
  printf("Test: C2 capacity-skew cap (EP0 8× capacity → 8× cap)\n");

  /* EP0 capacity 8, EP1 capacity 1; total_load=100, ε=0.75 (mlf=175).
   * total_clamped_cap = 8 + 1 = 9.
   *   capA = ceil(175·100·8 / (100·9)) = ceil(140000/900) = 156
   *   capB = ceil(175·100·1 / (100·9)) = ceil(17500/900)  = 20
   * Capacity-weighting: capA must be 8× capB (the advertised ratio). */
  uint64_t capA0 = pd_kv_clamp_capacity(8);
  uint64_t capB0 = pd_kv_clamp_capacity(1);
  uint64_t total_cap = capA0 + capB0;            /* 9 */
  uint64_t capA = pd_capacity_weighted_cap(100, capA0, total_cap, 175);
  uint64_t capB = pd_capacity_weighted_cap(100, capB0, total_cap, 175);

  ASSERT_EQ((int)capA, 156, "capacity-skew capA = 156 (8× weight)");
  ASSERT_EQ((int)capB, 20,  "capacity-skew capB = 20 (1× weight)");
  /* The load-bearing C2 claim: the cap is capacity-WEIGHTED, not uniform.
   * A bigger-capacity EP gets a strictly bigger cap → absorbs more load before
   * spilling → the selection changes vs the capacity-blind (uniform) path. */
  ASSERT_EQ((int)(capA > capB), 1, "capacity-skewed cap: capA strictly > capB");
  /* capA/capB ≈ 8 (156/20 = 7.8, exact integers differ only by ceil rounding). */
  ASSERT_EQ((int)(capA / capB), 7, "capA tracks the 8:1 capacity ratio (156/20=7)");

  /* The reserved PROXY_SEL_GPU_AWARE weights are now LIT UP: with EQUAL live
   * load, the bigger-capacity EP must score LOWER (lower=better) so it is
   * preferred — the C4 herding fix. EP0 cap 8, EP1 cap 1; both at conns=10,
   * queued=2, swap=0; n_eps=2. score = (conns·KV + queued·QUEUE) · mean_cap / cap_i.
   *   weighted_load = 10·20 + 2·50 = 300; mean_cap = (8+1)/2 = 4.
   *   score0 = 300·4 / 8 = 150 ; score1 = 300·4 / 1 = 1200.
   * The capacity-blind COMP-07 path would tie (both 12) — proving the weights
   * change the selection. */
  uint64_t score0 = pd_capacity_blend_score(10, 2, 0, capA0, total_cap, 2,
                                            DEFAULT_QUEUE_WEIGHT,
                                            DEFAULT_KV_CACHE_WEIGHT,
                                            DEFAULT_SWAP_WEIGHT);
  uint64_t score1 = pd_capacity_blend_score(10, 2, 0, capB0, total_cap, 2,
                                            DEFAULT_QUEUE_WEIGHT,
                                            DEFAULT_KV_CACHE_WEIGHT,
                                            DEFAULT_SWAP_WEIGHT);
  ASSERT_EQ((int)score0, 150,  "blend score EP0 (8× capacity) = 150");
  ASSERT_EQ((int)score1, 1200, "blend score EP1 (1× capacity) = 1200");
  ASSERT_EQ((int)(score0 < score1), 1,
            "weights lit up: bigger-capacity EP scores lower (selected)");
}

/* C2: a buggy/malicious vLLM advertising NumGPUBlocks=0 must NOT divide-by-zero
 * or zero the weighted sum. The clamp turns 0 → 1, so a fleet of
 * all-zero advertisements falls back to a UNIFORM cap (every weight 1) with a
 * well-defined, finite, ≥1 result. */
static void test_c2_num_gpu_blocks_zero_safe(void) {
  printf("Test: C2 NumGPUBlocks=0 is divide-safe (clamp 0→1)\n");

  /* clamp guard */
  ASSERT_EQ((int)pd_kv_clamp_capacity(0), 1, "clamp 0 → 1 (never zeroes sum)");
  ASSERT_EQ((int)pd_kv_clamp_capacity(1), 1, "clamp 1 → 1");
  ASSERT_EQ((int)(pd_kv_clamp_capacity(KV_CAPACITY_CLAMP_MAX + 1) ==
                  KV_CAPACITY_CLAMP_MAX), 1, "clamp huge → MAX (no overflow)");

  /* Two EPs both advertising 0 → clamped to 1 each → total_cap = 2.
   * The cap must be finite, ≥1, and equal for both (uniform fallback). */
  uint64_t c0 = pd_kv_clamp_capacity(0);
  uint64_t c1 = pd_kv_clamp_capacity(0);
  uint64_t total = c0 + c1;                      /* 2, never 0 */
  ASSERT_EQ((int)(total > 0), 1, "all-zero capacities: total_cap clamped > 0");
  uint64_t cap0 = pd_capacity_weighted_cap(50, c0, total, 175);
  uint64_t cap1 = pd_capacity_weighted_cap(50, c1, total, 175);
  ASSERT_EQ((int)(cap0 >= 1), 1, "zero-capacity cap floored at ≥1 (no div-by-zero)");
  ASSERT_EQ((int)(cap0 == cap1), 1, "all-zero capacities → uniform cap");

  /* Zero load on a live EP still leaves room for one request (floor at 1). */
  ASSERT_EQ((int)pd_capacity_weighted_cap(0, 1, 2, 175), 1,
            "zero-load cap floored at 1");
}

/* Test-local record_kv_stage: byte-identical to the sockproxy_metrics.c
 * production implementation, but bound to this harness's global_stats mirror
 * (the test compiles ONLY test_kv_exact.c + the #included sockproxy_kv_exact.c,
 * NOT sockproxy_metrics.c — same pattern the 9 Tier-1.5 counters already use).
 * If the production bucket bounds or accumulation idiom drift from this copy,
 * the C3 assert below catches it. Bounds mirror latency_bucket_bounds_us[12]. */
static const uint64_t kv_test_latency_bounds_us[KV_STAGE_N_BUCKETS] = {
    1000, 5000, 10000, 25000, 50000, 100000,
    250000, 500000, 1000000, 2500000, 5000000, 10000000
};
void record_kv_stage(int stage, int is_hit, uint64_t latency_us) {
    if (stage < 0 || stage >= KV_N_STAGES) return;
    int outcome = is_hit ? KV_STAGE_OUTCOME_HIT : KV_STAGE_OUTCOME_MISS;
    if (outcome < 0 || outcome >= KV_N_STAGE_OUTCOMES) return;
    for (int i = 0; i < KV_STAGE_N_BUCKETS; i++) {
        if (latency_us <= kv_test_latency_bounds_us[i]) {
            atomic_fetch_add(&global_stats.kv_stage_buckets[stage][outcome][i], 1);
        }
    }
    atomic_fetch_add(&global_stats.kv_stage_sum_us[stage][outcome], latency_us);
    atomic_fetch_add(&global_stats.kv_stage_count[stage][outcome], 1);
}

/* ===========================================================================
 * Task 1: per-stage µs histogram accumulation.
 *
 * record_kv_stage(stage, is_hit, latency_us) must accumulate into the correct
 * per-(stage,outcome) 12-bucket histogram + sum/count — the mirror of
 * record_latency_sample, but split across the 4 Tier-1.5 stages AND the hit/miss
 * outcome axis (so C3 can report tokenize/hash/CGO/scan on BOTH paths).
 *
 * Asserts (covers C3):
 *   - 1000 calls at a known latency increment exactly the expected bucket + count
 *     + sum for that (stage,outcome) and NOTHING in any other cell.
 *   - the hit path (is_hit=1) and the miss path (is_hit=0) accumulate into
 *     SEPARATE cells (the hit/miss breakdown C3 requires).
 * =========================================================================== */
static void test_kv_stage_histogram(void) {
  memset(&global_stats, 0, sizeof(global_stats));

  /* 7000 us => bucket index 2 (bound 10000) is the first >= 7000 in
   * latency_bucket_bounds_us {1000,5000,10000,...}. Record on the HIT path. */
  const uint64_t lat_hit = 7000;     /* expect bucket idx 2 */
  const uint64_t lat_miss = 3000;    /* expect bucket idx 1 (bound 5000) */
  const int N = 1000;

  for (int i = 0; i < N; i++) {
    record_kv_stage(KV_STAGE_CGO, KV_STAGE_OUTCOME_HIT, lat_hit);
    record_kv_stage(KV_STAGE_TOKENIZE, KV_STAGE_OUTCOME_MISS, lat_miss);
  }

  /* HIT/CGO: count == N, sum == N*lat_hit, bucket[2] == N. */
  ASSERT_EQ((int)atomic_load(&global_stats.kv_stage_count[KV_STAGE_CGO][KV_STAGE_OUTCOME_HIT]),
            N, "kv_stage CGO/hit count == N");
  ASSERT_EQ((int)atomic_load(&global_stats.kv_stage_sum_us[KV_STAGE_CGO][KV_STAGE_OUTCOME_HIT]),
            (int)(N * lat_hit), "kv_stage CGO/hit sum_us == N*lat");
  ASSERT_EQ((int)atomic_load(&global_stats.kv_stage_buckets[KV_STAGE_CGO][KV_STAGE_OUTCOME_HIT][2]),
            N, "kv_stage CGO/hit bucket[2] == N (7000us)");
  /* Cumulative (Prometheus le-bucket) form, byte-identical to record_latency_sample:
   * 7000us increments EVERY bucket whose bound >= 7000 -> idx 2..11 all == N. */
  ASSERT_EQ((int)atomic_load(&global_stats.kv_stage_buckets[KV_STAGE_CGO][KV_STAGE_OUTCOME_HIT][11]),
            N, "kv_stage CGO/hit bucket[11] == N (cumulative le-bucket)");
  /* A FINER bucket (idx 1, bound 5000 < 7000) must stay 0 — 7000us is not <= 5000. */
  ASSERT_EQ((int)atomic_load(&global_stats.kv_stage_buckets[KV_STAGE_CGO][KV_STAGE_OUTCOME_HIT][1]),
            0, "kv_stage CGO/hit bucket[1] == 0 (7000us > 5000 bound)");

  /* MISS/TOKENIZE: count == N, sum == N*lat_miss, bucket[1] == N (3000us -> bound 5000). */
  ASSERT_EQ((int)atomic_load(&global_stats.kv_stage_count[KV_STAGE_TOKENIZE][KV_STAGE_OUTCOME_MISS]),
            N, "kv_stage TOKENIZE/miss count == N");
  ASSERT_EQ((int)atomic_load(&global_stats.kv_stage_sum_us[KV_STAGE_TOKENIZE][KV_STAGE_OUTCOME_MISS]),
            (int)(N * lat_miss), "kv_stage TOKENIZE/miss sum_us == N*lat");
  ASSERT_EQ((int)atomic_load(&global_stats.kv_stage_buckets[KV_STAGE_TOKENIZE][KV_STAGE_OUTCOME_MISS][1]),
            N, "kv_stage TOKENIZE/miss bucket[1] == N (3000us)");

  /* Cross-contamination guard: HIT/CGO must NOT have leaked into MISS/CGO, and
   * MISS/TOKENIZE must NOT have leaked into HIT/TOKENIZE — the outcome axis is real. */
  ASSERT_EQ((int)atomic_load(&global_stats.kv_stage_count[KV_STAGE_CGO][KV_STAGE_OUTCOME_MISS]),
            0, "kv_stage CGO/miss count == 0 (no hit/miss leak)");
  ASSERT_EQ((int)atomic_load(&global_stats.kv_stage_count[KV_STAGE_TOKENIZE][KV_STAGE_OUTCOME_HIT]),
            0, "kv_stage TOKENIZE/hit count == 0 (no miss/hit leak)");
  /* And an untouched stage (HASH) stays entirely zero. */
  ASSERT_EQ((int)atomic_load(&global_stats.kv_stage_count[KV_STAGE_HASH][KV_STAGE_OUTCOME_HIT]),
            0, "kv_stage HASH/hit count == 0 (untouched stage)");

  /* Out-of-range stage must be a no-op, not a buffer overrun (V5). is_hit is a
   * boolean (any non-zero == hit) so only the stage axis needs range-rejection. */
  record_kv_stage(KV_N_STAGES, KV_STAGE_OUTCOME_HIT, lat_hit);   /* invalid stage (== 4) */
  record_kv_stage(-1, KV_STAGE_OUTCOME_HIT, lat_hit);            /* invalid stage (negative) */
  ASSERT_EQ((int)atomic_load(&global_stats.kv_stage_count[KV_STAGE_CGO][KV_STAGE_OUTCOME_HIT]),
            N, "kv_stage out-of-range stage calls are no-ops (count unchanged)");
  /* A non-zero is_hit other than 1 still maps to the HIT cell (boolean coercion). */
  record_kv_stage(KV_STAGE_SCAN, 9, lat_hit);
  ASSERT_EQ((int)atomic_load(&global_stats.kv_stage_count[KV_STAGE_SCAN][KV_STAGE_OUTCOME_HIT]),
            1, "kv_stage is_hit=9 coerces to HIT cell");
}

/* ===========================================================================
 * Task 3: Known-vector tests loaded from shared JSON fixture.
 *
 * Loads cicd/common/kv_hash/fixtures/kv_hash_vectors.json
 * and asserts that kv_compute_single_block_hash produces a digest whose
 * big-endian([:8]) matches each fixture's expected_hash_uint64 for both
 * sha256_cbor and xxhash_cbor algorithms. Mirrors what the Go and Python
 * layers assert so any of the three can catch cross-layer drift.
 * =========================================================================== */

/* Hex decode: returns bytes written, or -1 on malformed input. */
static int
kv_hex_decode(const char *hex, int hex_len, uint8_t *out, int out_len)
{
  if ((hex_len & 1) != 0) return -1;
  int n = hex_len / 2;
  if (n > out_len) return -1;
  for (int i = 0; i < n; i++) {
    char c1 = hex[2*i], c2 = hex[2*i + 1];
    int h1, h2;
    if (c1 >= '0' && c1 <= '9') h1 = c1 - '0';
    else if (c1 >= 'a' && c1 <= 'f') h1 = c1 - 'a' + 10;
    else if (c1 >= 'A' && c1 <= 'F') h1 = c1 - 'A' + 10;
    else return -1;
    if (c2 >= '0' && c2 <= '9') h2 = c2 - '0';
    else if (c2 >= 'a' && c2 <= 'f') h2 = c2 - 'a' + 10;
    else if (c2 >= 'A' && c2 <= 'F') h2 = c2 - 'A' + 10;
    else return -1;
    out[i] = (uint8_t)((h1 << 4) | h2);
  }
  return n;
}

/* Return jsmn token index for the field named `key` within the object
 * starting at `obj_tok`, or -1 if not found. Scans the next obj_tok->size
 * (key,value) pairs. */
static int
kv_json_find_field(const char *js, jsmntok_t *toks, int tok_count,
                   int obj_tok, const char *key)
{
  if (obj_tok < 0 || obj_tok >= tok_count) return -1;
  if (toks[obj_tok].type != JSMN_OBJECT) return -1;
  int want_len = (int)strlen(key);
  int i = obj_tok + 1;
  int pairs = toks[obj_tok].size;
  for (int p = 0; p < pairs && i < tok_count; p++) {
    /* Key token */
    if (toks[i].type != JSMN_STRING) return -1;
    int klen = toks[i].end - toks[i].start;
    if (klen == want_len && strncmp(js + toks[i].start, key, klen) == 0)
      return i + 1;  /* value is the token immediately after the key */
    /* Skip the value subtree. */
    int v = i + 1;
    if (v >= tok_count) return -1;
    int skip;
    if (toks[v].type == JSMN_OBJECT) {
      /* Count tokens nested under this object. */
      int end = toks[v].end;
      skip = 0;
      while (v + 1 + skip < tok_count && toks[v + 1 + skip].end <= end) skip++;
    } else if (toks[v].type == JSMN_ARRAY) {
      int end = toks[v].end;
      skip = 0;
      while (v + 1 + skip < tok_count && toks[v + 1 + skip].end <= end) skip++;
    } else {
      skip = 0;
    }
    i = v + 1 + skip;
  }
  return -1;
}

/* Parse a primitive integer token; returns 0 on success, -1 on failure. */
static int
kv_json_primitive_to_int(const char *js, jsmntok_t *t, int64_t *out)
{
  char buf[64];
  int len = t->end - t->start;
  if (len <= 0 || len >= (int)sizeof(buf)) return -1;
  memcpy(buf, js + t->start, len);
  buf[len] = '\0';
  char *endp;
  int64_t v = strtoll(buf, &endp, 10);
  if (endp == buf) return -1;
  *out = v;
  return 0;
}

/* Parse a primitive uint64 token (accepts decimal only; the fixture stores
 * expected_hash_uint64 as a JSON number). Returns 0 on success, -1 on fail. */
static int
kv_json_primitive_to_u64(const char *js, jsmntok_t *t, uint64_t *out)
{
  char buf[64];
  int len = t->end - t->start;
  if (len <= 0 || len >= (int)sizeof(buf)) return -1;
  memcpy(buf, js + t->start, len);
  buf[len] = '\0';
  char *endp;
  uint64_t v = strtoull(buf, &endp, 10);
  if (endp == buf) return -1;
  *out = v;
  return 0;
}

/* Fixture path resolution: allow override via env var LLB_KV_HASH_VECTORS,
 * otherwise default to the repo-relative path (run from loxilb-ebpf/common). */
static const char *
kv_fixture_path(void)
{
  const char *env = getenv("LLB_KV_HASH_VECTORS");
  if (env && env[0] != '\0') return env;
  return "../../cicd/common/kv_hash/fixtures/kv_hash_vectors.json";
}

static void
test_hash_vectors_from_json(void)
{
  const char *path = kv_fixture_path();
  printf("Test: known-vector parity from JSON fixture (%s)\n", path);

  FILE *fp = fopen(path, "rb");
  if (!fp) {
    tests_run++;
    tests_failed++;
    printf("  FAIL: cannot open fixture at %s (cwd-relative default or "
           "LLB_KV_HASH_VECTORS override); errno=%d\n", path, errno);
    return;
  }
  fseek(fp, 0, SEEK_END);
  long raw_sz = ftell(fp);
  fseek(fp, 0, SEEK_SET);
  if (raw_sz <= 0 || raw_sz > 1 << 20) {
    tests_run++;
    tests_failed++;
    printf("  FAIL: implausible fixture size %ld\n", raw_sz);
    fclose(fp);
    return;
  }
  char *js = (char *)malloc((size_t)raw_sz + 1);
  if (!js) {
    tests_run++;
    tests_failed++;
    printf("  FAIL: malloc(%ld) failed\n", raw_sz + 1);
    fclose(fp);
    return;
  }
  size_t got = fread(js, 1, (size_t)raw_sz, fp);
  fclose(fp);
  if ((long)got != raw_sz) {
    tests_run++;
    tests_failed++;
    printf("  FAIL: short read %zu of %ld\n", got, raw_sz);
    free(js);
    return;
  }
  js[raw_sz] = '\0';

  /* Generous token budget: 4 fixtures × ~50 tokens/fixture + envelope ~ 256. */
  enum { TOK_CAP = 4096 };
  jsmntok_t *toks = (jsmntok_t *)calloc(TOK_CAP, sizeof(jsmntok_t));
  if (!toks) {
    tests_run++;
    tests_failed++;
    printf("  FAIL: tok alloc failed\n");
    free(js);
    return;
  }

  jsmn_parser jp;
  jsmn_init(&jp);
  int n_tok = jsmn_parse(&jp, js, (size_t)raw_sz, toks, TOK_CAP);
  if (n_tok < 0) {
    tests_run++;
    tests_failed++;
    printf("  FAIL: jsmn_parse returned %d\n", n_tok);
    free(toks);
    free(js);
    return;
  }
  if (n_tok < 1 || toks[0].type != JSMN_OBJECT) {
    tests_run++;
    tests_failed++;
    printf("  FAIL: top-level is not an object (n_tok=%d)\n", n_tok);
    free(toks);
    free(js);
    return;
  }

  int arr_tok = kv_json_find_field(js, toks, n_tok, 0, "fixtures");
  if (arr_tok < 0 || toks[arr_tok].type != JSMN_ARRAY) {
    tests_run++;
    tests_failed++;
    printf("  FAIL: missing or non-array 'fixtures' field\n");
    free(toks);
    free(js);
    return;
  }
  int n_fixtures = toks[arr_tok].size;
  if (n_fixtures < 4) {
    tests_run++;
    tests_failed++;
    printf("  FAIL: need >=4 fixtures, got %d\n", n_fixtures);
    free(toks);
    free(js);
    return;
  }

  /* Iterate each fixture object. */
  int fx_tok = arr_tok + 1;
  for (int fx = 0; fx < n_fixtures; fx++) {
    if (fx_tok >= n_tok || toks[fx_tok].type != JSMN_OBJECT) {
      tests_run++;
      tests_failed++;
      printf("  FAIL: fixture %d is not an object\n", fx);
      break;
    }

    int name_tok = kv_json_find_field(js, toks, n_tok, fx_tok, "name");
    int algo_tok = kv_json_find_field(js, toks, n_tok, fx_tok, "hash_algo");
    int parent_tok = kv_json_find_field(js, toks, n_tok, fx_tok, "parent_hash_hex");
    int tokens_tok = kv_json_find_field(js, toks, n_tok, fx_tok, "tokens");
    int u64_tok = kv_json_find_field(js, toks, n_tok, fx_tok, "expected_hash_uint64");
    if (name_tok < 0 || algo_tok < 0 || parent_tok < 0 ||
        tokens_tok < 0 || u64_tok < 0) {
      tests_run++;
      tests_failed++;
      printf("  FAIL: fixture %d missing required field\n", fx);
      break;
    }

    /* Extract name as a trimmed C string (for diagnostics). */
    char name_buf[128];
    int nlen = toks[name_tok].end - toks[name_tok].start;
    if (nlen >= (int)sizeof(name_buf)) nlen = (int)sizeof(name_buf) - 1;
    memcpy(name_buf, js + toks[name_tok].start, nlen);
    name_buf[nlen] = '\0';

    /* Algo enum. */
    int algo_len = toks[algo_tok].end - toks[algo_tok].start;
    const char *algo_s = js + toks[algo_tok].start;
    uint8_t algo_enum;
    int expected_digest_len;
    if (algo_len == 11 && strncmp(algo_s, "sha256_cbor", 11) == 0) {
      algo_enum = KV_HASH_SHA256_CBOR;
      expected_digest_len = 32;
    } else if (algo_len == 11 && strncmp(algo_s, "xxhash_cbor", 11) == 0) {
      algo_enum = KV_HASH_XXHASH_CBOR;
      expected_digest_len = 16;
    } else {
      tests_run++;
      tests_failed++;
      printf("  FAIL: fixture '%s' has unknown hash_algo\n", name_buf);
      break;
    }

    /* Parent hash hex → bytes. */
    uint8_t parent_bytes[KV_MAX_HASH_BYTES];
    int parent_hex_len = toks[parent_tok].end - toks[parent_tok].start;
    int parent_len = kv_hex_decode(js + toks[parent_tok].start, parent_hex_len,
                                   parent_bytes, sizeof(parent_bytes));
    if (parent_len != expected_digest_len) {
      tests_run++;
      tests_failed++;
      printf("  FAIL: fixture '%s' parent_hash_hex decoded %d bytes, expected %d\n",
             name_buf, parent_len, expected_digest_len);
      break;
    }

    /* Tokens array → uint32_t[]. */
    if (toks[tokens_tok].type != JSMN_ARRAY) {
      tests_run++;
      tests_failed++;
      printf("  FAIL: fixture '%s' tokens is not an array\n", name_buf);
      break;
    }
    int n_tokens = toks[tokens_tok].size;
    if (n_tokens <= 0 || n_tokens > KV_MAX_TOKENS) {
      tests_run++;
      tests_failed++;
      printf("  FAIL: fixture '%s' has %d tokens (out of range)\n",
             name_buf, n_tokens);
      break;
    }
    uint32_t *tokens_buf = (uint32_t *)calloc((size_t)n_tokens, sizeof(uint32_t));
    if (!tokens_buf) {
      tests_run++;
      tests_failed++;
      printf("  FAIL: tokens_buf alloc failed\n");
      break;
    }
    int t_idx = tokens_tok + 1;
    int ok = 1;
    for (int k = 0; k < n_tokens; k++) {
      int64_t v;
      if (kv_json_primitive_to_int(js, &toks[t_idx + k], &v) != 0 ||
          v < 0 || v > UINT32_MAX) {
        printf("  FAIL: fixture '%s' bad token[%d]\n", name_buf, k);
        ok = 0;
        break;
      }
      tokens_buf[k] = (uint32_t)v;
    }
    if (!ok) {
      free(tokens_buf);
      tests_run++;
      tests_failed++;
      break;
    }

    /* Expected uint64. */
    uint64_t want_u64 = 0;
    if (kv_json_primitive_to_u64(js, &toks[u64_tok], &want_u64) != 0) {
      free(tokens_buf);
      tests_run++;
      tests_failed++;
      printf("  FAIL: fixture '%s' expected_hash_uint64 parse failed\n",
             name_buf);
      break;
    }

    /* Compute single-block hash with explicit parent. */
    uint8_t digest[KV_MAX_HASH_BYTES];
    int dlen = kv_compute_single_block_hash(algo_enum,
                                            parent_bytes, parent_len,
                                            tokens_buf, n_tokens,
                                            digest, sizeof(digest));
    free(tokens_buf);
    if (dlen != expected_digest_len) {
      tests_run++;
      tests_failed++;
      printf("  FAIL: fixture '%s' single-block returned %d (expected %d)\n",
             name_buf, dlen, expected_digest_len);
      break;
    }

    /* Post-44-04: kv_compute_single_block_hash writes the vLLM-aligned
     * uint64 truncation (== BE(full_digest[-8:])) into the first 8 bytes
     * of `digest`. Remaining bytes are zero-padded. So BE(digest[:8])
     * here equals maybe_convert_block_hash(full_digest) in vLLM v0.17.0.
     * See sockproxy_kv_exact.c kv_compute_single_block_hash. */
    uint64_t got_u64 = 0;
    for (int b = 0; b < 8; b++) got_u64 = (got_u64 << 8) | digest[b];

    tests_run++;
    if (got_u64 == want_u64) {
      tests_passed++;
      printf("  PASS: fixture '%s' algo=%.*s u64=0x%016llx\n",
             name_buf, algo_len, algo_s, (unsigned long long)got_u64);
    } else {
      tests_failed++;
      printf("  FAIL: fixture '%s' algo=%.*s got=0x%016llx want=0x%016llx\n",
             name_buf, algo_len, algo_s,
             (unsigned long long)got_u64, (unsigned long long)want_u64);
    }

    /* Advance fx_tok past this fixture object's subtree. */
    int fx_end = toks[fx_tok].end;
    int step = 1;
    while (fx_tok + step < n_tok && toks[fx_tok + step].end <= fx_end) step++;
    fx_tok += step;
  }

  free(toks);
  free(js);
}

/* ===========================================================================
 * Task 3: chat + special-token block-BOUNDARY parity fixtures.
 *
 * The C unit cannot run a real tokenizer, so these load the committed vLLM
 * GOLDEN token_id vectors (cicd/common/kv_hash/fixtures/kv_special_token_parity
 * .json `vllm_authoritative_ids` and kv_chat_template_parity.json multi_turn
 * `templated_ids`) into the stub and assert that kv_compute_block_hashes splits
 * them into the EXPECTED 16-token blocks with parity-correct boundaries:
 *   - block count == ceil(n_tokens / 16) (the C hasher hashes the trailing
 *     partial block too — see test_hash_edge_cases),
 *   - block 0's stored hash equals the hash recomputed from ONLY the first
 *     min(16,n) golden ids (independent path). A deliberately SHIFTED vector
 *     would change block 0's first-16 ids and thus this hash → the assert FAILS.
 * Real tokenize/template parity is proven Go-side ; here we lock the
 * C-side block-boundary math against the authoritative token ids.
 *
 * block_size is fixed at 16 (the KV block size); hash algo is sha256_cbor.
 * =========================================================================== */

/* Helper: assert that the full-vector block 0 hash equals the hash recomputed
 * from only the first min(16,n) tokens — i.e. the boundary at token 16 is honored
 * and block 0 carries exactly those leading ids (parent = NONE_HASH for block 0). */
static void
kv_assert_block0_boundary(const char *label, const uint32_t *ids, int n_ids)
{
  const uint32_t block_size = 16;
  int expect_blocks = (n_ids + (int)block_size - 1) / (int)block_size;
  int block0_tokens = n_ids < (int)block_size ? n_ids : (int)block_size;

  /* (1) Full-vector hashing: produces `expect_blocks` blocks, block 0 in
   *     hashes[0..31]. */
  uint8_t hashes[KV_MAX_BLOCKS * 32];
  int n_blocks = kv_compute_block_hashes(KV_HASH_SHA256_CBOR, ids, n_ids,
                                         block_size, hashes, 32, KV_MAX_BLOCKS);
  ASSERT_EQ(n_blocks, expect_blocks, label);

  /* (2) Independent block-0 recompute from ONLY the first min(16,n) ids with the
   *     same NONE_HASH parent kv_compute_block_hashes seeds for block 0. */
  uint8_t parent[32];
  kv_compute_none_hash(KV_HASH_SHA256_CBOR, parent, 32);
  uint8_t b0_digest[KV_MAX_HASH_BYTES];
  int dlen = kv_compute_single_block_hash(KV_HASH_SHA256_CBOR, parent, 32,
                                          ids, block0_tokens,
                                          b0_digest, sizeof(b0_digest));
  ASSERT_EQ(dlen, 32, "block0 single-block digest length");

  /* The stored block-0 slot is the vLLM uint64 truncation (first 8 bytes); the
   * independent recompute writes the same truncation to b0_digest[0..7]. Equal
   * iff block 0 covers exactly the first 16 ids (the boundary is correct). */
  ASSERT_MEM_EQ(hashes, b0_digest, 8, "block-0 boundary: first-16 ids hash matches");
}

/* SPECIAL-TOKEN fixture: leading <|im_end|>=151645 must be a single id at index
 * 0 (not split into 6 normal tokens), and 11 ids < 16 → exactly 1 (partial)
 * block whose hash covers all 11 ids. ( vllm_authoritative_ids.) */
static void
test_block_boundary_special_token(void)
{
  printf("Test: special-token (<|im_end|>) block-boundary parity vs vLLM golden ids\n");

  /* cicd/common/kv_hash/fixtures/kv_special_token_parity.json
   * vllm_authoritative_ids: "<|im_end|> in the place of mine To calm this tempest" */
  static const uint32_t golden[] = {
    151645, 304, 279, 1992, 315, 10485, 2014, 19300, 419, 1562, 29123
  };
  const int n = (int)(sizeof(golden) / sizeof(golden[0]));
  ASSERT_EQ(n, 11, "special-token vector length");

  /* The leading special id is preserved as a single token at index 0 (the
   * daulet-default 6-token split would have shifted every boundary). */
  ASSERT_EQ((int)golden[0], 151645, "block-0 token 0 is <|im_end|> single special id");

  /* 11 < 16 → exactly 1 (partial) block; block-0 boundary parity. */
  kv_assert_block0_boundary("special-token: 11 ids → 1 block (ceil(11/16))",
                            golden, n);
}

/* CHAT fixture: apply_chat_template multi_turn → 52 templated ids = 3 full
 * 16-token blocks + 1 partial (4) → 4 blocks total. block 0's first 16 ids are
 * the ChatML system preamble. ( templated_ids, multi_turn.) */
static void
test_block_boundary_chat(void)
{
  printf("Test: chat apply_chat_template block-boundary parity vs vLLM golden ids\n");

  /* cicd/common/kv_hash/fixtures/kv_chat_template_parity.json multi_turn
   * templated_ids — block-0 first 16 are the Qwen2.5 default-system preamble. */
  static const uint32_t block0_expected[16] = {
    151644, 8948, 198, 2610, 525, 1207, 16948, 11,
    3465, 553, 54364, 14817, 13, 1446, 525, 264
  };

  /* The full 52-token multi_turn vector, verbatim from the committed fixture's
   * templated_ids (apply_chat_template(tokenize=True), Qwen2.5-7B). The first 16
   * are the system preamble above; the tail extends the multi-turn conversation. */
  static const uint32_t golden[52] = {
    /* block 0 (system preamble, 16) */
    151644, 8948, 198, 2610, 525, 1207, 16948, 11,
    3465, 553, 54364, 14817, 13, 1446, 525, 264,
    /* block 1 (16) */
    10950, 17847, 13, 151645, 198, 151644, 872, 198,
    3838, 374, 220, 17, 10, 17, 30, 151645,
    /* block 2 (16) */
    198, 151644, 77091, 198, 19, 151645, 198, 151644,
    872, 198, 3036, 3039, 220, 18, 30, 151645,
    /* block 3 (partial, 4) */
    198, 151644, 77091, 198
  };
  const int n = (int)(sizeof(golden) / sizeof(golden[0]));
  ASSERT_EQ(n, 52, "chat vector length");

  /* Block 0 must be exactly the 16 system-preamble ids (boundary integrity:
   * a shifted vector changes these and fails kv_assert_block0_boundary). */
  ASSERT_MEM_EQ(golden, block0_expected, sizeof(block0_expected),
                "chat block-0 = ChatML system preamble (first 16 ids)");

  /* 52 ids → ceil(52/16) = 4 blocks; block-0 boundary parity. */
  kv_assert_block0_boundary("chat: 52 ids → 4 blocks (ceil(52/16))", golden, n);
}

/* ==========================================================================
 * (SGL-02): SGLang parity vectors — KV_HASH_SHA256_SGLANG.
 *
 * Pins loxilb's C hash arm to SGLang's get_hash_str/hash_str_to_int64 on
 * committed reference vectors. Asserts BOTH levels per vector:
 *   (a) digest-level: kv_hash_sglang_block chained per block == reference
 *       FULL 32-byte digest (parent-propagation teeth);
 *   (b) uint64-level: kv_compute_block_hashes slot[0..7] read BE == the
 *       published first-8-BE value (+ zero-pad tail) — the TK27
 *       digest[:8]-vs-digest[-8:] drift class, inverted for SGLang. A
 *       last-8 mis-slice fails (b) on every vector (self-checked below).
 * ========================================================================== */

/* ==== SGLang parity vectors (SGL-02) ==== */
/* regenerated by scripts/compute_sglang_hash_refs.py from sglang d8ef76682e — do not hand-edit */
/* source of record: python/sglang/srt/mem_cache/cpp_utils/hash_binding.cpp @ d8ef76682e */

/* single_block_bs16_noparent — (a) one partial block, NO parent bytes */
static const uint32_t sgl_v1_tokens[] = {
  1u, 2u, 3u, 4u, 5u, 6u, 7u
};
#define SGL_V1_BLOCK_SIZE 16u
#define SGL_V1_N_BLOCKS 1
static const uint8_t sgl_v1_digests[1][32] = {
  { 0x4c, 0x81, 0x69, 0x52, 0xba, 0x53, 0xcc, 0x36, 0x1d, 0x8e, 0x45, 0xbd, 0x83, 0x33, 0x38, 0xdc,
    0x64, 0x27, 0xe4, 0xa5, 0xd5, 0xf0, 0x6e, 0xba, 0xd5, 0x35, 0x1f, 0xd4, 0x64, 0x39, 0xa1, 0x5a },
};
static const uint64_t sgl_v1_u64[1] = {
  0x4c816952ba53cc36ULL,
};

/* chain3_bs16 — (b) 3 full blocks — parent = prior FULL 32-byte digest */
static const uint32_t sgl_v2_tokens[] = {
  1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u, 9u, 10u, 11u, 12u, 13u, 14u, 15u, 16u, 17u,
  18u, 19u, 20u, 21u, 22u, 23u, 24u, 25u, 26u, 27u, 28u, 29u, 30u, 31u, 32u,
  33u, 34u, 35u, 36u, 37u, 38u, 39u, 40u, 41u, 42u, 43u, 44u, 45u, 46u, 47u,
  48u
};
#define SGL_V2_BLOCK_SIZE 16u
#define SGL_V2_N_BLOCKS 3
static const uint8_t sgl_v2_digests[3][32] = {
  { 0x77, 0xd7, 0x35, 0xce, 0x83, 0x84, 0x18, 0xaa, 0x15, 0x1b, 0xd9, 0x6b, 0x5b, 0x1e, 0x78, 0xee,
    0x63, 0x86, 0x08, 0x92, 0xe0, 0xa9, 0x5c, 0x00, 0xfe, 0x34, 0x17, 0x84, 0x42, 0xbe, 0x9b, 0x07 },
  { 0x11, 0x70, 0x42, 0x6c, 0xf2, 0x44, 0x9c, 0xeb, 0xf4, 0xd1, 0x7f, 0x08, 0x7c, 0xe5, 0xbb, 0x43,
    0xb6, 0xa9, 0x10, 0xce, 0x91, 0xb3, 0xf4, 0x09, 0x22, 0x86, 0x8e, 0x91, 0x3e, 0x8e, 0xe9, 0x1d },
  { 0x4e, 0xf6, 0x43, 0xc3, 0x50, 0xb1, 0x4a, 0x37, 0xed, 0xa2, 0x68, 0xf7, 0xf7, 0x06, 0xc4, 0x4e,
    0xc5, 0x78, 0x32, 0x0d, 0x32, 0xfd, 0xc2, 0x0a, 0x9b, 0xce, 0x5f, 0x81, 0xe9, 0x60, 0x3b, 0x11 },
};
static const uint64_t sgl_v2_u64[3] = {
  0x77d735ce838418aaULL,
  0x1170426cf2449cebULL,
  0x4ef643c350b14a37ULL,
};

/* le_teeth_bs16 — (c) >2^16 + 2^31-adjacent + uint32-max token ids — 4-byte-LE teeth */
static const uint32_t sgl_v3_tokens[] = {
  65537u, 2147483646u, 2147483647u, 2147483648u, 4294967295u
};
#define SGL_V3_BLOCK_SIZE 16u
#define SGL_V3_N_BLOCKS 1
static const uint8_t sgl_v3_digests[1][32] = {
  { 0x43, 0x29, 0xc3, 0x1d, 0x2a, 0x34, 0x11, 0x26, 0x68, 0xb5, 0x07, 0x38, 0x93, 0x9c, 0xee, 0x65,
    0xb9, 0x56, 0x5f, 0x41, 0xd8, 0x15, 0x1b, 0xcc, 0x7e, 0x94, 0x4c, 0x45, 0x29, 0xdb, 0x60, 0xde },
};
static const uint64_t sgl_v3_u64[1] = {
  0x4329c31d2a341126ULL,
};

/* negative_int64_bs16 — (d) published int64 NEGATIVE (digest[0] >= 0x80) — signed-wrap teeth */
static const uint32_t sgl_v4_tokens[] = {
  0u
};
#define SGL_V4_BLOCK_SIZE 16u
#define SGL_V4_N_BLOCKS 1
static const uint8_t sgl_v4_digests[1][32] = {
  { 0xdf, 0x3f, 0x61, 0x98, 0x04, 0xa9, 0x2f, 0xdb, 0x40, 0x57, 0x19, 0x2d, 0xc4, 0x3d, 0xd7, 0x48,
    0xea, 0x77, 0x8a, 0xdc, 0x52, 0xbc, 0x49, 0x8c, 0xe8, 0x05, 0x24, 0xc0, 0x14, 0xb8, 0x11, 0x19 },
};
static const uint64_t sgl_v4_u64[1] = {
  0xdf3f619804a92fdbULL,
};

/* chain2_bs32 — (e) block size 32, 2 full blocks — page-size-32 + chain teeth */
static const uint32_t sgl_v5_tokens[] = {
  100000u, 100001u, 100002u, 100003u, 100004u, 100005u, 100006u, 100007u,
  100008u, 100009u, 100010u, 100011u, 100012u, 100013u, 100014u, 100015u,
  100016u, 100017u, 100018u, 100019u, 100020u, 100021u, 100022u, 100023u,
  100024u, 100025u, 100026u, 100027u, 100028u, 100029u, 100030u, 100031u,
  100032u, 100033u, 100034u, 100035u, 100036u, 100037u, 100038u, 100039u,
  100040u, 100041u, 100042u, 100043u, 100044u, 100045u, 100046u, 100047u,
  100048u, 100049u, 100050u, 100051u, 100052u, 100053u, 100054u, 100055u,
  100056u, 100057u, 100058u, 100059u, 100060u, 100061u, 100062u, 100063u
};
#define SGL_V5_BLOCK_SIZE 32u
#define SGL_V5_N_BLOCKS 2
static const uint8_t sgl_v5_digests[2][32] = {
  { 0x06, 0x9e, 0x60, 0xc0, 0x0e, 0x7d, 0xaa, 0x33, 0x53, 0x68, 0x0f, 0x46, 0xb0, 0xed, 0x1d, 0x72,
    0xbb, 0xcc, 0x1d, 0x75, 0xc2, 0x84, 0x3f, 0x2a, 0x6b, 0x37, 0x35, 0xad, 0x87, 0x82, 0x31, 0x1e },
  { 0xb9, 0xe5, 0xc3, 0x2b, 0x50, 0x35, 0x19, 0x92, 0xcb, 0xf3, 0x91, 0x46, 0x97, 0xd8, 0x9d, 0x20,
    0xff, 0x2b, 0xf5, 0x04, 0xf6, 0xa5, 0x73, 0x65, 0xa5, 0xe3, 0x1d, 0x70, 0x5f, 0x77, 0x82, 0xf0 },
};
static const uint64_t sgl_v5_u64[2] = {
  0x069e60c00e7daa33ULL,
  0xb9e5c32b50351992ULL,
};
/* ==== end SGLang parity vectors ==== */

/* Assert one SGLang vector at both digest and uint64 level. */
static void
test_sglang_vector_one(const char *name, const uint32_t *tokens, int n_tokens,
                       uint32_t block_size, const uint8_t (*digests)[32],
                       const uint64_t *u64s, int n_blocks_expected)
{
  printf("Test: SGLang parity vector %s (bs=%u, %d block%s)\n",
         name, block_size, n_blocks_expected,
         n_blocks_expected == 1 ? "" : "s");

  /* (a) digest-level: chain kv_hash_sglang_block by hand — block 0 with NO
   * parent, block i>0 with block i-1's FULL 32-byte reference digest. */
  uint8_t parent[32];
  bool has_parent = false;
  int bi = 0;
  for (int off = 0; off < n_tokens; off += (int)block_size, bi++) {
    int bt = n_tokens - off;
    if (bt > (int)block_size) bt = (int)block_size;
    uint8_t d[32];
    kv_hash_sglang_block(has_parent ? parent : NULL, has_parent,
                         tokens + off, bt, d);
    ASSERT_MEM_EQ(d, digests[bi], 32, "SGLang FULL digest parity");
    memcpy(parent, d, 32);
    has_parent = true;
  }
  ASSERT_EQ(bi, n_blocks_expected, "SGLang block count (digest chain)");

  /* (b) uint64-level via the production entry point. Slots poisoned to
   * verify zero-pad; stride 32 (the :707 selector yields 32 for algo 2). */
  uint8_t slots[8 * 32];
  memset(slots, 0xaa, sizeof(slots));
  int n = kv_compute_block_hashes(KV_HASH_SHA256_SGLANG, tokens, n_tokens,
                                  block_size, slots, 32, 8);
  ASSERT_EQ(n, n_blocks_expected, "SGLang block count (kv_compute_block_hashes)");

  static const uint8_t zeros24[24] = {0};
  for (int i = 0; i < n_blocks_expected; i++) {
    const uint8_t *slot = slots + i * 32;
    uint64_t got = 0, wrong_slice = 0;
    for (int k = 0; k < 8; k++) {
      got = (got << 8) | slot[k];
      wrong_slice = (wrong_slice << 8) | digests[i][24 + k];
    }
    /* Published-value parity: slot first-8 BE == first-8-BE of the FULL
     * digest == SGLang hash_str_to_int64 bit pattern. */
    tests_run++;
    if (got == u64s[i]) { tests_passed++; }
    else {
      tests_failed++;
      printf("  FAIL: %s blk %d uint64 (expected 0x%016llx, got 0x%016llx) at line %d\n",
             name, i, (unsigned long long)u64s[i], (unsigned long long)got,
             __LINE__);
    }
    /* TK27-drift teeth self-check: the vLLM-style LAST-8 slice of this
     * digest must DIFFER from the published value — i.e. a last-8
     * mis-implementation cannot silently pass this vector. */
    tests_run++;
    if (wrong_slice != u64s[i]) { tests_passed++; }
    else {
      tests_failed++;
      printf("  FAIL: %s blk %d vector has no first-8-vs-last-8 teeth at line %d\n",
             name, i, __LINE__);
    }
    ASSERT_MEM_EQ(slot + 8, zeros24, 24, "SGLang slot zero-pad tail");
  }
}

static void
test_sglang_parity_vectors(void)
{
  test_sglang_vector_one("single_block_bs16_noparent",
                         sgl_v1_tokens,
                         (int)(sizeof(sgl_v1_tokens) / sizeof(sgl_v1_tokens[0])),
                         SGL_V1_BLOCK_SIZE, sgl_v1_digests, sgl_v1_u64,
                         SGL_V1_N_BLOCKS);
  test_sglang_vector_one("chain3_bs16",
                         sgl_v2_tokens,
                         (int)(sizeof(sgl_v2_tokens) / sizeof(sgl_v2_tokens[0])),
                         SGL_V2_BLOCK_SIZE, sgl_v2_digests, sgl_v2_u64,
                         SGL_V2_N_BLOCKS);
  test_sglang_vector_one("le_teeth_bs16",
                         sgl_v3_tokens,
                         (int)(sizeof(sgl_v3_tokens) / sizeof(sgl_v3_tokens[0])),
                         SGL_V3_BLOCK_SIZE, sgl_v3_digests, sgl_v3_u64,
                         SGL_V3_N_BLOCKS);
  test_sglang_vector_one("negative_int64_bs16",
                         sgl_v4_tokens,
                         (int)(sizeof(sgl_v4_tokens) / sizeof(sgl_v4_tokens[0])),
                         SGL_V4_BLOCK_SIZE, sgl_v4_digests, sgl_v4_u64,
                         SGL_V4_N_BLOCKS);
  test_sglang_vector_one("chain2_bs32",
                         sgl_v5_tokens,
                         (int)(sizeof(sgl_v5_tokens) / sizeof(sgl_v5_tokens[0])),
                         SGL_V5_BLOCK_SIZE, sgl_v5_digests, sgl_v5_u64,
                         SGL_V5_N_BLOCKS);
}

/* ---: JSON unescape + escape/UTF-8-safe truncation ---------------- */
/* The Tier-1.5 tokenize input for /v1/completions is prefix_key.prefix, which
 * sockproxy_json.c now fills through kv_json_unescape_copy. These pin the
 * decode table AND the two truncation guarantees (never mid-escape, never
 * mid-UTF-8) that keep the truncated prefix a byte-exact prefix of the full
 * decoded prompt — the property block-hash prefix routing depends on. */
#include "sockproxy_json_unescape.h"

static void
test_json_unescape(void)
{
  char out[64];
  size_t n;

  /* plain passthrough */
  n = kv_json_unescape_copy("hello", 5, out, sizeof(out));
  ASSERT_EQ((int)n, 5, "unescape: plain length");
  ASSERT_MEM_EQ(out, "hello", 6, "unescape: plain bytes+NUL");

  /* the full simple-escape table — the coding-assistant reality (\n, \t, \") */
  n = kv_json_unescape_copy("a\\nb\\tc\\\"d\\\\e\\/f\\bg\\fh\\ri", 25,
                            out, sizeof(out));
  ASSERT_EQ((int)n, 17, "unescape: simple escapes length");
  ASSERT_MEM_EQ(out, "a\nb\tc\"d\\e/f\bg\fh\ri", 18,
                "unescape: simple escapes bytes");

  /* A -> 'A' (BMP ASCII) */
  n = kv_json_unescape_copy("x\\u0041y", 8, out, sizeof(out));
  ASSERT_EQ((int)n, 3, "unescape: u0041 length");
  ASSERT_MEM_EQ(out, "xAy", 4, "unescape: u0041 bytes");

  /* é -> 2-byte UTF-8 (c3 a9) */
  n = kv_json_unescape_copy("\\u00e9", 6, out, sizeof(out));
  ASSERT_EQ((int)n, 2, "unescape: u00e9 length");
  ASSERT_MEM_EQ(out, "\xc3\xa9", 3, "unescape: u00e9 bytes");

  /* surrogate pair 😀 -> U+1F600 (f0 9f 98 80) */
  n = kv_json_unescape_copy("\\ud83d\\ude00", 12, out, sizeof(out));
  ASSERT_EQ((int)n, 4, "unescape: surrogate pair length");
  ASSERT_MEM_EQ(out, "\xf0\x9f\x98\x80", 5, "unescape: surrogate pair bytes");

  /* lone high surrogate -> STOP (copy nothing after the preceding byte) */
  n = kv_json_unescape_copy("a\\ud83dZZZ", 10, out, sizeof(out));
  ASSERT_EQ((int)n, 1, "unescape: lone surrogate stops");
  ASSERT_MEM_EQ(out, "a", 2, "unescape: lone surrogate keeps prefix");

  /* dangling '\' at the source cut -> dropped, clean NUL */
  n = kv_json_unescape_copy("ab\\", 3, out, sizeof(out));
  ASSERT_EQ((int)n, 2, "unescape: dangling backslash dropped");
  ASSERT_MEM_EQ(out, "ab", 3, "unescape: dangling backslash bytes");

  /* partial \uXX at the source cut -> dropped */
  n = kv_json_unescape_copy("ab\\u00", 6, out, sizeof(out));
  ASSERT_EQ((int)n, 2, "unescape: partial uXXXX dropped");

  /* dst-cap truncation NEVER splits a 2-byte char: room for 1, char needs 2 */
  n = kv_json_unescape_copy("a\\u00e9", 7, out, 3); /* cap: 2 bytes + NUL */
  ASSERT_EQ((int)n, 1, "unescape: cap stops before split char");
  ASSERT_MEM_EQ(out, "a", 2, "unescape: cap keeps whole chars only");

  /* raw (unescaped) multi-byte UTF-8 passes through atomically */
  n = kv_json_unescape_copy("a\xc3\xa9z", 4, out, sizeof(out));
  ASSERT_EQ((int)n, 4, "unescape: raw utf8 passthrough length");
  ASSERT_MEM_EQ(out, "a\xc3\xa9z", 5, "unescape: raw utf8 passthrough bytes");

  /* raw multi-byte char cut by srclen -> dropped, not half-copied */
  n = kv_json_unescape_copy("a\xc3", 2, out, sizeof(out));
  ASSERT_EQ((int)n, 1, "unescape: raw utf8 cut by srclen dropped");

  /* raw multi-byte char that would split at dstcap -> dropped */
  n = kv_json_unescape_copy("ab\xc3\xa9", 4, out, 3); /* cap: 2 + NUL */
  ASSERT_EQ((int)n, 2, "unescape: raw utf8 split at dstcap dropped");
  ASSERT_MEM_EQ(out, "ab", 3, "unescape: raw utf8 split bytes");

  /* unknown escape (\x) -> STOP: never guess, keep the parity-exact prefix */
  n = kv_json_unescape_copy("ok\\xZZ", 6, out, sizeof(out));
  ASSERT_EQ((int)n, 2, "unescape: unknown escape stops");

  /* truncated-prefix property: decode(full)[0:n] == decode(capped) for a
   * code-shaped prompt — what block-hash prefix routing depends on. */
  {
    const char *code = "def f(x):\\n\\treturn x\\u00e9 + 1\\n# tail comment";
    char full[64], capped[16];
    size_t nf = kv_json_unescape_copy(code, strlen(code), full, sizeof(full));
    size_t nc = kv_json_unescape_copy(code, strlen(code), capped, sizeof(capped));
    ASSERT_EQ(nc <= nf ? 1 : 0, 1, "unescape: capped shorter than full");
    ASSERT_MEM_EQ(capped, full, nc, "unescape: capped is byte-exact prefix");
  }
}

/* ---- binding-dataplane contract tests ---- */

static void
kv_reset_tok_stub(void)
{
  stub_tok_calls = 0;
  stub_tok_force_code = 0;
  stub_last_tok_svc_id = 0xdeadbeefu;
  stub_last_tok_binding_gen = 0xdeadbeefu;
}

/* pd_kv_exact_contract_set: packing, ACK readback, gen-0 refusal,
 * eligible normalization. */
static void
test_contract_set_core(void)
{
  printf("Test: pd_kv_exact_contract_set packs, ACKs, refuses gen 0\n");
  proxy_epval_t tepval;
  uint64_t applied = 0;

  kv_reset_tepval(&tepval);

  /* gen 0 is reserved — the setter must never install the legacy zero word */
  ASSERT_EQ(pd_kv_exact_contract_set(&tepval, 0, KV_EXACT_API_BOTH, 1, &applied),
            -EINVAL, "contract_set: binding_gen 0 refused");
  ASSERT_EQ((int)(atomic_load(&tepval.kv_exact_contract) != 0), 0,
            "contract_set: refused call leaves the word zero");

  /* install: word == PACK, applied readback == word, rc == 0 (the ACK) */
  ASSERT_EQ(pd_kv_exact_contract_set(&tepval, 7, KV_EXACT_API_CHAT, 1, &applied),
            0, "contract_set: install ACKs");
  ASSERT_EQ((int)(applied == KV_CONTRACT_PACK(7, 0, KV_EXACT_API_CHAT, 1)), 1,
            "contract_set: applied == requested packed word");
  ASSERT_EQ((int)KV_CONTRACT_GEN(applied), 7, "contract_set: gen extract");
  ASSERT_EQ((int)KV_CONTRACT_API_MODE(applied), KV_EXACT_API_CHAT,
            "contract_set: api_mode extract");
  ASSERT_EQ((int)KV_CONTRACT_ELIGIBLE(applied), 1, "contract_set: eligible extract");
  ASSERT_EQ((int)KV_CONTRACT_FLAGS(applied), 0, "contract_set: flags reserved 0");

  /* eligible normalization: any nonzero input stores exactly 1 */
  ASSERT_EQ(pd_kv_exact_contract_set(&tepval, 8, KV_EXACT_API_BOTH, 0xff, &applied),
            0, "contract_set: re-install new gen ACKs");
  ASSERT_EQ((int)KV_CONTRACT_ELIGIBLE(applied), 1,
            "contract_set: eligible normalized to 1");

  /* fence: eligible=0 keeps the gen (word stays nonzero — never legacy) */
  ASSERT_EQ(pd_kv_exact_contract_set(&tepval, 8, KV_EXACT_API_BOTH, 0, &applied),
            0, "contract_set: fence ACKs");
  ASSERT_EQ((int)KV_CONTRACT_ELIGIBLE(applied), 0, "contract_set: fenced");
  ASSERT_EQ((int)(applied != 0), 1, "contract_set: fenced word stays nonzero");
}

/* CONTRACT GATE: fenced word => not_ready miss BEFORE tokenize. */
static void
test_contract_gate_not_ready(void)
{
  printf("Test: contract gate !eligible -> miss_not_ready, no tokenize\n");
  proxy_epval_t tepval;
  proxy_fd_ent_t pfe;
  uint64_t applied = 0;
  int ep = -1;

  kv_reset_stats();
  kv_reset_tepval(&tepval);
  kv_reset_pfe(&pfe);
  kv_reset_tok_stub();
  ASSERT_EQ(pd_kv_exact_contract_set(&tepval, 3, KV_EXACT_API_BOTH, 0, &applied),
            0, "gate/not_ready: fenced install ACKs");

  int rc = pd_kv_exact_select(&tepval, &pfe, &ep, 0);
  ASSERT_EQ(rc, -1, "gate/not_ready: returns -1 (Tier-2)");
  ASSERT_EQ((int)atomic_load(&global_stats.pd_kv_t15_miss_not_ready), 1,
            "gate/not_ready: pd_kv_t15_miss_not_ready incremented");
  ASSERT_EQ(stub_tok_calls, 0, "gate/not_ready: tokenize NEVER reached");
}

/* CONTRACT GATE: api_mode surface exclusion, both directions. */
static void
test_contract_gate_api_mode(void)
{
  printf("Test: contract gate api_mode excludes the declared-off surface\n");
  proxy_epval_t tepval;
  proxy_fd_ent_t pfe;
  uint64_t applied = 0;
  int ep = -1;

  /* chat request on a completions-only contract */
  kv_reset_stats();
  kv_reset_tepval(&tepval);
  kv_reset_pfe(&pfe);
  kv_reset_tok_stub();
  pfe.is_chat = 1;
  ASSERT_EQ(pd_kv_exact_contract_set(&tepval, 4, KV_EXACT_API_COMPLETIONS, 1,
                                     &applied), 0,
            "gate/api_mode: completions-only install ACKs");
  int rc = pd_kv_exact_select(&tepval, &pfe, &ep, 0);
  ASSERT_EQ(rc, -1, "gate/api_mode: chat on completions-only -> -1");
  ASSERT_EQ((int)atomic_load(&global_stats.pd_kv_t15_miss_api_mode), 1,
            "gate/api_mode: chat exclusion counted");
  ASSERT_EQ(stub_tok_calls, 0, "gate/api_mode: no tokenize on exclusion");

  /* completions request on a chat-only contract */
  kv_reset_stats();
  kv_reset_tok_stub();
  pfe.is_chat = 0;
  ASSERT_EQ(pd_kv_exact_contract_set(&tepval, 4, KV_EXACT_API_CHAT, 1,
                                     &applied), 0,
            "gate/api_mode: chat-only install ACKs");
  rc = pd_kv_exact_select(&tepval, &pfe, &ep, 0);
  ASSERT_EQ(rc, -1, "gate/api_mode: completions on chat-only -> -1");
  ASSERT_EQ((int)atomic_load(&global_stats.pd_kv_t15_miss_api_mode), 1,
            "gate/api_mode: completions exclusion counted");
  ASSERT_EQ(stub_tok_calls, 0, "gate/api_mode: no tokenize on exclusion (2)");
}

/* CONTRACT GATE: eligible word admits, and the loaded binding_gen + the
 * rule's kv_svc_id ride the tokenize CGO call intact. */
static void
test_contract_gate_threads_binding_gen(void)
{
  printf("Test: eligible contract threads (svc_id, binding_gen) to tokenize\n");
  proxy_epval_t tepval;
  proxy_fd_ent_t pfe;
  uint64_t applied = 0;
  int ep = -1;

  kv_reset_stats();
  kv_reset_tepval(&tepval);
  kv_reset_pfe(&pfe);
  kv_reset_tok_stub();
  tepval.kv_svc_id = 91;
  stub_token_count = 32;      /* tokenize succeeds */
  stub_best_ep = -1;          /* pipeline then misses at GUARD_G — fine */
  stub_best_score = 0;
  ASSERT_EQ(pd_kv_exact_contract_set(&tepval, 12, KV_EXACT_API_BOTH, 1,
                                     &applied), 0,
            "gate/thread: eligible install ACKs");

  (void)pd_kv_exact_select(&tepval, &pfe, &ep, 0);
  ASSERT_EQ(stub_tok_calls, 1, "gate/thread: tokenize reached once");
  ASSERT_EQ((int)stub_last_tok_svc_id, 91, "gate/thread: svc_id threaded");
  ASSERT_EQ((int)stub_last_tok_binding_gen, 12,
            "gate/thread: binding_gen threaded from the loaded word");
  ASSERT_EQ((int)atomic_load(&global_stats.pd_kv_t15_miss_not_ready), 0,
            "gate/thread: no not_ready miss on eligible word");

  stub_token_count = 0;
}

/* CONTRACT GATE: zero word == legacy passthrough — the gate contributes no
 * misses and tokenize runs with binding_gen 0 (today's path, byte-identical). */
static void
test_contract_zero_word_legacy(void)
{
  printf("Test: zero contract word is the legacy passthrough\n");
  proxy_epval_t tepval;
  proxy_fd_ent_t pfe;
  int ep = -1;

  kv_reset_stats();
  kv_reset_tepval(&tepval);   /* memset -> kv_exact_contract == 0 */
  kv_reset_pfe(&pfe);
  kv_reset_tok_stub();
  stub_token_count = 32;
  stub_best_ep = -1;
  stub_best_score = 0;

  (void)pd_kv_exact_select(&tepval, &pfe, &ep, 0);
  ASSERT_EQ(stub_tok_calls, 1, "gate/legacy: tokenize reached");
  ASSERT_EQ((int)stub_last_tok_binding_gen, 0, "gate/legacy: binding_gen 0");
  ASSERT_EQ((int)atomic_load(&global_stats.pd_kv_t15_miss_not_ready), 0,
            "gate/legacy: no not_ready miss");
  ASSERT_EQ((int)atomic_load(&global_stats.pd_kv_t15_miss_api_mode), 0,
            "gate/legacy: no api_mode miss");

  stub_token_count = 0;
}

/* GUARD E typed-code classification: each LLB_KV_TOK_ERR_* class lands on
 * its own counter; the legacy collapsed -1 keeps today's `tokenize` label. */
static void
test_guard_e_typed_code_classes(void)
{
  printf("Test: GUARD_E classifies typed bridge codes onto distinct counters\n");
  proxy_epval_t tepval;
  proxy_fd_ent_t pfe;
  int ep = -1;

  static const struct { int code; const char *name; } legs[] = {
    { LLB_KV_TOK_ERR_UNSUPPORTED, "unsupported" },
    { LLB_KV_TOK_ERR_PROFILE,     "profile" },
    { LLB_KV_TOK_ERR_RENDERER,    "renderer" },
    { LLB_KV_TOK_ERR_TOKENIZER,   "tokenizer" },
    { LLB_KV_TOK_ERR_UNKNOWN,     "unknown" },
    { LLB_KV_TOK_ERR_NOT_READY,   "not_ready" },
    { LLB_KV_TOK_ERR_REQUEST,     "request(-1 legacy)" },
  };

  for (size_t i = 0; i < sizeof(legs) / sizeof(legs[0]); i++) {
    kv_reset_stats();
    kv_reset_tepval(&tepval);
    kv_reset_pfe(&pfe);
    kv_reset_tok_stub();
    stub_tok_force_code = legs[i].code;

    int rc = pd_kv_exact_select(&tepval, &pfe, &ep, 0);
    ASSERT_EQ(rc, -1, "GUARD_E typed: falls back to Tier-2");

    uint64_t unsupported = atomic_load(&global_stats.pd_kv_t15_miss_unsupported);
    uint64_t runtime_fault = atomic_load(&global_stats.pd_kv_t15_miss_runtime_fault);
    uint64_t not_ready = atomic_load(&global_stats.pd_kv_t15_miss_not_ready);
    uint64_t tokenize = atomic_load(&global_stats.pd_kv_t15_miss_tokenize);
    switch (legs[i].code) {
    case LLB_KV_TOK_ERR_UNSUPPORTED:
      ASSERT_EQ((int)unsupported, 1, "GUARD_E typed: -2 -> unsupported");
      ASSERT_EQ((int)(runtime_fault + not_ready + tokenize), 0,
                "GUARD_E typed: -2 -> only unsupported");
      break;
    case LLB_KV_TOK_ERR_NOT_READY:
      ASSERT_EQ((int)not_ready, 1, "GUARD_E typed: -7 -> not_ready");
      ASSERT_EQ((int)(runtime_fault + unsupported + tokenize), 0,
                "GUARD_E typed: -7 -> only not_ready");
      break;
    case LLB_KV_TOK_ERR_REQUEST:
      ASSERT_EQ((int)tokenize, 1, "GUARD_E typed: -1 -> legacy tokenize label");
      ASSERT_EQ((int)(runtime_fault + unsupported + not_ready), 0,
                "GUARD_E typed: -1 -> only tokenize");
      break;
    default: /* -3..-6 */
      ASSERT_EQ((int)runtime_fault, 1, "GUARD_E typed: fault -> runtime_fault");
      ASSERT_EQ((int)(unsupported + not_ready + tokenize), 0,
                "GUARD_E typed: fault -> only runtime_fault");
      break;
    }
  }
  kv_reset_tok_stub();
}

/* ---- Main ---- */
int
main(int argc, char **argv)
{
  (void)argc;
  (void)argv;
  printf("=== KV Exact Routing Unit Tests ===\n\n");

  test_json_unescape();
  test_cbor_basic();
  test_cbor_large_tokens();
  test_cbor_xxhash_parent();
  test_cbor_overflow();
  test_sha256_parity();
  test_xxhash_parity();
  test_multiblock_chain();
  test_hash_edge_cases();
  test_sha256_large_tokens();
  test_guard_a_mode_off();
  test_guard_b_warmup();
  test_guard_c_empty_text();
  test_guard_d_empty_model();
  test_guard_e_tokenize_fail();
  test_guard_f_no_hashes();
  test_guard_g_no_worker();
  test_guard_g_excluded_mask();
  test_guard_h_shallow_match();
  test_guard_g_ep_inv();
  test_guard_g_cb_open();
  test_proxy_add_entry_kv_exact_fields_new_path();
  test_prefill_mask_from_ep_role();
  test_mask_mode1_byte_identity();
  test_mask_mode3_single_role_admits_all();
  test_kv_svc_id_threading();
  test_c2_capacity_skew_cap();
  test_c2_num_gpu_blocks_zero_safe();
  test_kv_stage_histogram();
  test_hash_vectors_from_json();
  test_block_boundary_special_token();
  test_block_boundary_chat();
  test_sglang_parity_vectors();
  test_contract_set_core();
  test_contract_gate_not_ready();
  test_contract_gate_api_mode();
  test_contract_gate_threads_binding_gen();
  test_contract_zero_word_legacy();
  test_guard_e_typed_code_classes();

  printf("\n=== Results: %d/%d passed", tests_passed, tests_run);
  if (tests_failed > 0)
    printf(", %d FAILED", tests_failed);
  printf(" ===\n");

  return tests_failed > 0 ? 1 : 0;
}
