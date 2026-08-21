/* test_pd_rewriter.c - Unit tests for P/D body rewriting and worker selection 
 * Standalone test binary: no sockproxy.c dependencies.
 * Build: gcc -Wall -Wextra -o test_pd_rewriter test_pd_rewriter.c -I. -DTEST_PD_REWRITER
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <errno.h>

/* Minimal stubs for standalone compilation */
#define MAX_PROXY_EP 32
#define PD_KV_PARAMS_MAX_LEN 65536
#define MAX_SALT_LEN 64

/* Circuit breaker states (from sockproxy.h) */
#define CB_STATE_CLOSED   0
#define CB_STATE_OPEN     1
#define CB_STATE_HALF_OPEN 2

/* Proxy selection modes (from sockproxy.h) */
#define PROXY_SEL_RR  0
#define PROXY_SEL_WRR 6

typedef struct {
  uint32_t xip;
  uint16_t xport;
  uint8_t  inv;        /* 0=active, non-zero=inactive */
  uint8_t  protocol;
  uint8_t  weight;
  uint8_t  pad[3];
} proxy_ent_t;

typedef struct {
  uint8_t state;  /* CB_STATE_CLOSED, CB_STATE_OPEN, CB_STATE_HALF_OPEN */
} circuit_breaker_t;

typedef struct {
  int n_eps;
  int ep_sel;
  int select;
  proxy_ent_t eps[MAX_PROXY_EP];

  circuit_breaker_t circuit_breakers[MAX_PROXY_EP];
  uint8_t cb_enabled;

  uint8_t  pd_disagg_enabled;
  uint8_t  ai_gw_mode;
  uint8_t  ep_role[MAX_PROXY_EP];
  int      n_prefill_eps;
  int      n_decode_eps;
  int      pd_prefill_rr;
  int      pd_decode_rr;

  int      pd_prefill_wrr_weights[MAX_PROXY_EP];
  int      pd_decode_wrr_weights[MAX_PROXY_EP];
  uint8_t  pd_wrr_initialized;
} proxy_epval_t;

/* Stub log functions */
#define log_error(fmt, ...) fprintf(stderr, "ERROR: " fmt "\n", ##__VA_ARGS__)
#define log_warn(fmt, ...) fprintf(stderr, "WARN: " fmt "\n", ##__VA_ARGS__)
#define log_debug(fmt, ...) ((void)0)

/* Include the implementation directly */
#include "sockproxy_pd.c"

/* ===== Test framework ===== */
static int tests_run = 0;
static int tests_passed = 0;

#define ASSERT_EQ(a, b, msg) do { \
  if ((a) != (b)) { \
    printf("  FAIL: %s (expected %d, got %d)\n", msg, (int)(b), (int)(a)); \
    return 0; \
  } \
} while(0)

#define ASSERT_STR_CONTAINS(hay, haylen, needle, msg) do { \
  if (!memmem(hay, haylen, needle, strlen(needle))) { \
    printf("  FAIL: %s (needle '%s' not found)\n", msg, needle); \
    return 0; \
  } \
} while(0)

#define ASSERT_STR_NOT_CONTAINS(hay, haylen, needle, msg) do { \
  if (memmem(hay, haylen, needle, strlen(needle))) { \
    printf("  FAIL: %s (needle '%s' found but shouldn't be)\n", msg, needle); \
    return 0; \
  } \
} while(0)

#define RUN_TEST(fn) do { \
  tests_run++; \
  printf("  [%d] %s ... ", tests_run, #fn); \
  if (fn()) { tests_passed++; printf("PASS\n"); } \
  else { printf("\n"); } \
} while(0)

/* ===== Suite A: JSON rewriting tests ===== */

static int test_normal_rewrite(void) {
  const char *input = "{\"model\":\"llama\",\"max_tokens\":200,\"stream\":true}";
  uint8_t out[2048];
  size_t out_len = 0;

  ASSERT_EQ(pd_prepare_prefill_body((const uint8_t *)input, strlen(input),
            out, &out_len, sizeof(out)), 0, "rewrite succeeds");
  ASSERT_STR_CONTAINS(out, out_len, "\"max_tokens\":1", "max_tokens=1");
  ASSERT_STR_CONTAINS(out, out_len, "\"stream\":false", "stream=false");
  ASSERT_STR_CONTAINS(out, out_len, "\"kv_transfer_params\"", "kv_transfer_params injected");
  ASSERT_STR_CONTAINS(out, out_len, "\"do_remote_decode\":true", "do_remote_decode");
  return 1;
}

static int test_space_variant(void) {
  const char *input = "{\"model\":\"llama\",\"max_tokens\": 200}";
  uint8_t out[2048];
  size_t out_len = 0;

  ASSERT_EQ(pd_prepare_prefill_body((const uint8_t *)input, strlen(input),
            out, &out_len, sizeof(out)), 0, "rewrite succeeds");
  /* Space between colon and value is preserved: "max_tokens": 1 */
  ASSERT_STR_CONTAINS(out, out_len, "\"max_tokens\": 1", "max_tokens rewritten with space");
  return 1;
}

static int test_nested_sampling_params(void) {
  const char *input = "{\"model\":\"llama\",\"sampling_params\":{\"max_tokens\":500}}";
  uint8_t out[2048];
  size_t out_len = 0;

  ASSERT_EQ(pd_prepare_prefill_body((const uint8_t *)input, strlen(input),
            out, &out_len, sizeof(out)), 0, "nested rewrite succeeds");
  ASSERT_STR_CONTAINS(out, out_len, "\"max_tokens\":1", "nested max_tokens=1");
  return 1;
}

static int test_buffer_overflow(void) {
  const char *input = "{\"model\":\"llama\",\"max_tokens\":200}";
  uint8_t out[50]; /* Too small for kv_transfer_params injection */
  size_t out_len = 0;

  ASSERT_EQ(pd_prepare_prefill_body((const uint8_t *)input, strlen(input),
            out, &out_len, sizeof(out)), -1, "overflow returns error");
  return 1;
}

static int test_missing_max_tokens(void) {
  const char *input = "{\"model\":\"llama\",\"stream\":true}";
  uint8_t out[2048];
  size_t out_len = 0;

  ASSERT_EQ(pd_prepare_prefill_body((const uint8_t *)input, strlen(input),
            out, &out_len, sizeof(out)), 0, "missing max_tokens still succeeds");
  ASSERT_STR_CONTAINS(out, out_len, "\"stream\":false", "stream still rewritten");
  ASSERT_STR_CONTAINS(out, out_len, "\"kv_transfer_params\"", "kv_params still injected");
  return 1;
}

static int test_max_completion_tokens(void) {
  const char *input = "{\"model\":\"llama\",\"max_completion_tokens\":500,\"stream\":true}";
  uint8_t out[2048];
  size_t out_len = 0;

  ASSERT_EQ(pd_prepare_prefill_body((const uint8_t *)input, strlen(input),
            out, &out_len, sizeof(out)), 0, "rewrite succeeds");
  ASSERT_STR_CONTAINS(out, out_len, "\"max_completion_tokens\":1", "max_completion_tokens=1");
  return 1;
}

static int test_min_tokens_rewrite(void) {
  const char *input = "{\"model\":\"llama\",\"max_tokens\":200,\"min_tokens\":50}";
  uint8_t out[2048];
  size_t out_len = 0;

  ASSERT_EQ(pd_prepare_prefill_body((const uint8_t *)input, strlen(input),
            out, &out_len, sizeof(out)), 0, "rewrite succeeds");
  ASSERT_STR_CONTAINS(out, out_len, "\"min_tokens\":1", "min_tokens=1");
  return 1;
}

static int test_stream_options_removal(void) {
  const char *input = "{\"model\":\"llama\",\"stream\":true,\"stream_options\":{\"include_usage\":true},\"max_tokens\":200}";
  uint8_t out[2048];
  size_t out_len = 0;

  ASSERT_EQ(pd_prepare_prefill_body((const uint8_t *)input, strlen(input),
            out, &out_len, sizeof(out)), 0, "rewrite succeeds");
  ASSERT_STR_CONTAINS(out, out_len, "\"stream\":false", "stream=false");
  ASSERT_STR_NOT_CONTAINS(out, out_len, "stream_options", "stream_options removed");
  return 1;
}

/* ===== Suite B: P/D worker selection tests ===== */

/* Standalone selection functions for testing (reimplemented from sockproxy.c logic) */

static int
test_pd_rr_select_from_role(proxy_epval_t *tepval, int target_role, int *rr_counter)
{
  int start, i, candidate;
  if (!tepval || !rr_counter || tepval->n_eps <= 0) return -1;
  start = *rr_counter;
  if (start < 0 || start >= tepval->n_eps) start = 0;
  for (i = 0; i < tepval->n_eps; i++) {
    candidate = (start + i) % tepval->n_eps;
    if (candidate >= MAX_PROXY_EP) break;
    if (tepval->ep_role[candidate] != target_role) continue;
    if (tepval->eps[candidate].inv) continue;
    if (tepval->cb_enabled && tepval->circuit_breakers[candidate].state == CB_STATE_OPEN) continue;
    *rr_counter = (candidate + 1) % tepval->n_eps;
    return candidate;
  }
  return -1;
}

static int
test_pd_wrr_select_from_role(proxy_epval_t *tepval, int target_role, int *wrr_weights)
{
  int total_weight = 0, selected = -1, max_cw = INT_MIN;
  if (!tepval || !wrr_weights) return -1;
  for (int i = 0; i < tepval->n_eps && i < MAX_PROXY_EP; i++) {
    if (tepval->ep_role[i] != target_role) continue;
    if (tepval->eps[i].inv) continue;
    if (tepval->cb_enabled && tepval->circuit_breakers[i].state == CB_STATE_OPEN) continue;
    int w = tepval->eps[i].weight ? tepval->eps[i].weight : 1;
    wrr_weights[i] += w;
    total_weight += w;
    if (wrr_weights[i] > max_cw) { max_cw = wrr_weights[i]; selected = i; }
  }
  if (selected < 0 || total_weight == 0) return -1;
  wrr_weights[selected] -= total_weight;
  return selected;
}

static int
test_pd_select_worker_pair(proxy_epval_t *tepval, int *prefill_ep, int *decode_ep)
{
  int p_idx, d_idx;
  if (!tepval || !prefill_ep || !decode_ep) return -1;
  if (tepval->select == PROXY_SEL_WRR && tepval->pd_wrr_initialized) {
    p_idx = test_pd_wrr_select_from_role(tepval, 1, tepval->pd_prefill_wrr_weights);
    d_idx = test_pd_wrr_select_from_role(tepval, 2, tepval->pd_decode_wrr_weights);
  } else {
    p_idx = test_pd_rr_select_from_role(tepval, 1, &tepval->pd_prefill_rr);
    d_idx = test_pd_rr_select_from_role(tepval, 2, &tepval->pd_decode_rr);
  }
  if (p_idx < 0 || d_idx < 0) return -1;
  *prefill_ep = p_idx;
  *decode_ep = d_idx;
  return 0;
}

/* Helper to init a test proxy_epval_t */
static void init_test_epval(proxy_epval_t *ev, int n_eps, int select_mode) {
  memset(ev, 0, sizeof(*ev));
  ev->n_eps = n_eps;
  ev->select = select_mode;
}

static int test_rr_selection(void) {
  proxy_epval_t ev;
  int p, d;

  init_test_epval(&ev, 4, PROXY_SEL_RR);
  /* EP0=prefill, EP1=decode, EP2=prefill, EP3=decode */
  ev.ep_role[0] = 1; ev.ep_role[1] = 2; ev.ep_role[2] = 1; ev.ep_role[3] = 2;
  ev.eps[0].weight = 1; ev.eps[1].weight = 1; ev.eps[2].weight = 1; ev.eps[3].weight = 1;
  ev.n_prefill_eps = 2; ev.n_decode_eps = 2;
  ev.pd_disagg_enabled = 1;

  /* First selection: should get EP0(prefill) + EP1(decode) */
  ASSERT_EQ(test_pd_select_worker_pair(&ev, &p, &d), 0, "first pair succeeds");
  ASSERT_EQ(p, 0, "first prefill=EP0");
  ASSERT_EQ(d, 1, "first decode=EP1");

  /* Second selection: RR advances -> EP2(prefill) + EP3(decode) */
  ASSERT_EQ(test_pd_select_worker_pair(&ev, &p, &d), 0, "second pair succeeds");
  ASSERT_EQ(p, 2, "second prefill=EP2");
  ASSERT_EQ(d, 3, "second decode=EP3");

  /* Third wraps back */
  ASSERT_EQ(test_pd_select_worker_pair(&ev, &p, &d), 0, "third pair succeeds");
  ASSERT_EQ(p, 0, "third prefill=EP0 (wrap)");
  ASSERT_EQ(d, 1, "third decode=EP1 (wrap)");

  return 1;
}

static int test_wrr_selection(void) {
  proxy_epval_t ev;
  int p, d;
  int prefill_counts[MAX_PROXY_EP] = {0};

  init_test_epval(&ev, 4, PROXY_SEL_WRR);
  /* EP0=prefill(w=60), EP1=decode(w=50), EP2=prefill(w=40), EP3=decode(w=50) */
  ev.ep_role[0] = 1; ev.eps[0].weight = 60;
  ev.ep_role[1] = 2; ev.eps[1].weight = 50;
  ev.ep_role[2] = 1; ev.eps[2].weight = 40;
  ev.ep_role[3] = 2; ev.eps[3].weight = 50;
  ev.n_prefill_eps = 2; ev.n_decode_eps = 2;
  ev.pd_disagg_enabled = 1;
  ev.pd_wrr_initialized = 1;

  /* Run 10 selections and count prefill distribution */
  for (int i = 0; i < 10; i++) {
    ASSERT_EQ(test_pd_select_worker_pair(&ev, &p, &d), 0, "wrr pair succeeds");
    prefill_counts[p]++;
  }

  /* EP0 (weight 60) should get more selections than EP2 (weight 40) */
  /* With 60/40 weights over 10 selections: EP0 ~6, EP2 ~4 */
  ASSERT_EQ(prefill_counts[0] > prefill_counts[2], 1,
            "EP0(w=60) gets more than EP2(w=40)");
  ASSERT_EQ(prefill_counts[0] + prefill_counts[2], 10,
            "all 10 went to prefill EPs");

  return 1;
}

static int test_health_skip(void) {
  proxy_epval_t ev;
  int p, d;

  init_test_epval(&ev, 4, PROXY_SEL_RR);
  ev.ep_role[0] = 1; ev.ep_role[1] = 2; ev.ep_role[2] = 1; ev.ep_role[3] = 2;
  ev.eps[0].weight = 1; ev.eps[1].weight = 1; ev.eps[2].weight = 1; ev.eps[3].weight = 1;
  ev.n_prefill_eps = 2; ev.n_decode_eps = 2;

  /* Mark EP0 (prefill) as inactive */
  ev.eps[0].inv = 1;

  ASSERT_EQ(test_pd_select_worker_pair(&ev, &p, &d), 0, "pair with inactive EP succeeds");
  ASSERT_EQ(p, 2, "skips inactive EP0, selects EP2");

  return 1;
}

static int test_empty_pool(void) {
  proxy_epval_t ev;
  int p, d;

  init_test_epval(&ev, 2, PROXY_SEL_RR);
  /* Only decode endpoints, no prefill */
  ev.ep_role[0] = 2; ev.ep_role[1] = 2;
  ev.eps[0].weight = 1; ev.eps[1].weight = 1;
  ev.n_prefill_eps = 0; ev.n_decode_eps = 2;

  ASSERT_EQ(test_pd_select_worker_pair(&ev, &p, &d), -1, "empty prefill pool returns -1");

  return 1;
}

static int test_circuit_breaker_skip(void) {
  proxy_epval_t ev;
  int p, d;
  int decode_counts[MAX_PROXY_EP] = {0};

  init_test_epval(&ev, 4, PROXY_SEL_WRR);
  ev.ep_role[0] = 1; ev.eps[0].weight = 50;
  ev.ep_role[1] = 2; ev.eps[1].weight = 50;
  ev.ep_role[2] = 1; ev.eps[2].weight = 50;
  ev.ep_role[3] = 2; ev.eps[3].weight = 50;
  ev.n_prefill_eps = 2; ev.n_decode_eps = 2;
  ev.pd_wrr_initialized = 1;
  ev.cb_enabled = 1;

  /* Mark EP1 (decode) as circuit breaker OPEN */
  ev.circuit_breakers[1].state = CB_STATE_OPEN;

  for (int i = 0; i < 5; i++) {
    ASSERT_EQ(test_pd_select_worker_pair(&ev, &p, &d), 0, "pair with CB OPEN succeeds");
    decode_counts[d]++;
  }

  /* EP1 should never be selected */
  ASSERT_EQ(decode_counts[1], 0, "CB OPEN EP1 never selected");
  ASSERT_EQ(decode_counts[3], 5, "all decode goes to EP3");

  return 1;
}

/* ===== Suite C: kv_transfer_params extraction ===== */

static int test_kv_extract_typical(void) {
  const char *resp =
    "{\"id\":\"cmpl-abc123\",\"choices\":[{\"text\":\"ok\"}],"
    "\"kv_transfer_params\":{\"do_remote_prefill\":false,"
    "\"do_remote_decode\":true,\"remote_engine_id\":\"eng-42\","
    "\"remote_host\":\"10.0.1.5\",\"remote_port\":12345,"
    "\"remote_block_ids\":[1,2,3]}}";
  char kv_out[4096];
  size_t kv_len = 0;

  ASSERT_EQ(pd_extract_kv_params((const uint8_t *)resp, strlen(resp),
            kv_out, &kv_len, sizeof(kv_out)), 0, "extract succeeds");
  /* Should contain the full object */
  ASSERT_EQ(kv_len > 0, 1, "kv_len > 0");
  ASSERT_EQ(kv_out[0], '{', "starts with {");
  ASSERT_EQ(kv_out[kv_len - 1], '}', "ends with }");
  ASSERT_STR_CONTAINS((uint8_t *)kv_out, kv_len,
                      "\"do_remote_decode\":true", "contains do_remote_decode");
  ASSERT_STR_CONTAINS((uint8_t *)kv_out, kv_len,
                      "\"remote_engine_id\":\"eng-42\"", "contains remote_engine_id");
  return 1;
}

static int test_kv_extract_not_found(void) {
  const char *resp = "{\"id\":\"cmpl-abc\",\"choices\":[{\"text\":\"ok\"}]}";
  char kv_out[4096];
  size_t kv_len = 999;

  ASSERT_EQ(pd_extract_kv_params((const uint8_t *)resp, strlen(resp),
            kv_out, &kv_len, sizeof(kv_out)), -ENOENT, "returns -ENOENT when not found");
  ASSERT_EQ(kv_len, 0, "kv_len == 0 when not found");
  ASSERT_EQ(kv_out[0], '\0', "kv_out is empty string");
  return 1;
}

static int test_kv_extract_deep_nesting(void) {
  const char *resp =
    "{\"kv_transfer_params\":{\"nested\":{\"deep\":{\"value\":42}}}}";
  char kv_out[4096];
  size_t kv_len = 0;

  ASSERT_EQ(pd_extract_kv_params((const uint8_t *)resp, strlen(resp),
            kv_out, &kv_len, sizeof(kv_out)), 0, "deep nesting extract succeeds");
  ASSERT_EQ(kv_len > 0, 1, "kv_len > 0");
  ASSERT_STR_CONTAINS((uint8_t *)kv_out, kv_len,
                      "\"deep\":{\"value\":42}", "nested content preserved");
  return 1;
}

static int test_kv_extract_braces_in_strings(void) {
  /* Braces inside string values should not confuse the scanner */
  const char *resp =
    "{\"kv_transfer_params\":{\"desc\":\"has { and } chars\",\"val\":1}}";
  char kv_out[4096];
  size_t kv_len = 0;

  ASSERT_EQ(pd_extract_kv_params((const uint8_t *)resp, strlen(resp),
            kv_out, &kv_len, sizeof(kv_out)), 0, "braces-in-strings extract ok");
  ASSERT_EQ(kv_len > 0, 1, "kv_len > 0");
  ASSERT_STR_CONTAINS((uint8_t *)kv_out, kv_len,
                      "\"val\":1", "correct brace matching");
  return 1;
}

static int test_kv_extract_buffer_overflow(void) {
  const char *resp =
    "{\"kv_transfer_params\":{\"do_remote_decode\":true,\"data\":\"long\"}}";
  char kv_out[10]; /* Too small for the kv_params object */
  size_t kv_len = 999;

  ASSERT_EQ(pd_extract_kv_params((const uint8_t *)resp, strlen(resp),
            kv_out, &kv_len, sizeof(kv_out)), -EMSGSIZE, "overflow returns -EMSGSIZE");
  ASSERT_EQ(kv_len, 0, "kv_len == 0 on overflow");
  return 1;
}

static int test_kv_extract_empty_response(void) {
  char kv_out[4096];
  size_t kv_len = 999;

  ASSERT_EQ(pd_extract_kv_params(NULL, 0,
            kv_out, &kv_len, sizeof(kv_out)), -ENOENT, "null resp returns -ENOENT");
  ASSERT_EQ(kv_len, 0, "kv_len == 0 for null resp");
  return 1;
}

/* ===== Suite D: Decode body construction ===== */

static int test_decode_body_with_kv(void) {
  const char *orig = "{\"model\":\"llama\",\"max_tokens\":200,\"stream\":true}";
  const char *kv = "{\"do_remote_decode\":true,\"remote_engine_id\":\"eng-42\"}";
  uint8_t out[2048];
  size_t out_len = 0;

  ASSERT_EQ(pd_prepare_decode_body((const uint8_t *)orig, strlen(orig),
            kv, strlen(kv), out, &out_len, sizeof(out)), 0, "decode body succeeds");
  ASSERT_STR_CONTAINS(out, out_len, "\"kv_transfer_params\":", "kv_transfer_params injected");
  ASSERT_STR_CONTAINS(out, out_len, "\"do_remote_decode\":true", "kv value present");
  ASSERT_STR_CONTAINS(out, out_len, "\"stream\":true", "stream preserved (not forced false)");
  ASSERT_STR_CONTAINS(out, out_len, "\"max_tokens\":200", "max_tokens preserved");
  /* Should still be valid JSON (ends with }) */
  ASSERT_EQ(out[out_len - 1], '}', "ends with }");
  return 1;
}

static int test_decode_body_empty_kv(void) {
  const char *orig = "{\"model\":\"llama\",\"max_tokens\":200}";
  uint8_t out[2048];
  size_t out_len = 0;

  ASSERT_EQ(pd_prepare_decode_body((const uint8_t *)orig, strlen(orig),
            NULL, 0, out, &out_len, sizeof(out)), 0, "empty kv succeeds");
  ASSERT_EQ(out_len, strlen(orig), "output same length as original");
  ASSERT_EQ(memcmp(out, orig, out_len), 0, "output identical to original");
  return 1;
}

static int test_decode_body_empty_kv_string(void) {
  const char *orig = "{\"model\":\"llama\"}";
  uint8_t out[2048];
  size_t out_len = 0;

  ASSERT_EQ(pd_prepare_decode_body((const uint8_t *)orig, strlen(orig),
            "", 0, out, &out_len, sizeof(out)), 0, "empty kv string succeeds");
  ASSERT_EQ(out_len, strlen(orig), "output same length");
  return 1;
}

static int test_decode_body_overflow(void) {
  const char *orig = "{\"model\":\"llama\",\"max_tokens\":200}";
  const char *kv = "{\"do_remote_decode\":true}";
  uint8_t out[50]; /* Too small for injection */
  size_t out_len = 0;

  /* Should still succeed but use original body (graceful degradation) */
  ASSERT_EQ(pd_prepare_decode_body((const uint8_t *)orig, strlen(orig),
            kv, strlen(kv), out, &out_len, sizeof(out)), 0, "overflow degrades gracefully");
  /* Output should be original body length (no injection) */
  ASSERT_EQ(out_len, strlen(orig), "output is original body");
  return 1;
}

static int test_decode_body_stream_preserved(void) {
  const char *orig = "{\"model\":\"llama\",\"stream\":true,\"max_tokens\":200}";
  const char *kv = "{\"v\":1}";
  uint8_t out[2048];
  size_t out_len = 0;

  ASSERT_EQ(pd_prepare_decode_body((const uint8_t *)orig, strlen(orig),
            kv, strlen(kv), out, &out_len, sizeof(out)), 0, "stream preserved");
  ASSERT_STR_CONTAINS(out, out_len, "\"stream\":true", "stream=true preserved");
  ASSERT_STR_CONTAINS(out, out_len, "\"kv_transfer_params\":", "kv injected");
  return 1;
}

/* ===== Suite E: Real vLLM format (BUF-03) ===== */

/* Count occurrences of a substring in a buffer */
static int count_substr(const char *hay, size_t hay_len, const char *needle) {
  int count = 0;
  size_t nlen = strlen(needle);
  const char *p = hay;
  const char *end = hay + hay_len;
  while (p < end && (p = memmem(p, end - p, needle, nlen)) != NULL) {
    count++;
    p += nlen;
  }
  return count;
}

/* Build a response with N block IDs per TP rank, R ranks.
 * Uses deterministic pseudo-random 5-digit block IDs to mimic real vLLM allocation.
 * Includes all nixl_connector.py fields: do_remote_prefill, do_remote_decode,
 * remote_engine_id, remote_host, remote_port, remote_block_ids, block_mapping,
 * connector_type, tp_size, remote_request_id.
 * Wraps in full vLLM response structure with model and usage fields.
 * Caller must free the returned buffer. */
static uint8_t *
build_large_response(int ranks, int blocks_per_rank, size_t *out_len)
{
  /* Estimate size: header ~400B + each int ~7B + punctuation */
  size_t payload_size = (size_t)ranks * (size_t)blocks_per_rank * 8 + 1024;
  uint8_t *buf = malloc(payload_size + 1024);
  if (!buf) return NULL;

  int pos = 0;
  pos += snprintf((char *)buf + pos, payload_size + 1024 - pos,
    "{\"id\":\"cmpl-abc123\",\"choices\":[{\"text\":\"ok\"}],"
    "\"model\":\"meta-llama/Llama-3.1-70B\","
    "\"usage\":{\"prompt_tokens\":128,\"completion_tokens\":1,\"total_tokens\":129},"
    "\"kv_transfer_params\":{"
    "\"do_remote_decode\":true,"
    "\"do_remote_prefill\":false,"
    "\"remote_block_ids\":[");

  for (int r = 0; r < ranks; r++) {
    if (r > 0) buf[pos++] = ',';
    buf[pos++] = '[';
    for (int b = 0; b < blocks_per_rank; b++) {
      if (b > 0) buf[pos++] = ',';
      /* Deterministic pseudo-random 5-digit block IDs (10000-99999) */
      uint32_t block_id = (uint32_t)(10000 + ((r * 7919 + b * 6271 + 42) % 90000));
      pos += snprintf((char *)buf + pos, payload_size + 1024 - pos, "%u", block_id);
    }
    buf[pos++] = ']';
  }

  pos += snprintf((char *)buf + pos, payload_size + 1024 - pos,
    "],\"block_mapping\":[],\"connector_type\":\"NixlConnector\","
    "\"tp_size\":%d,\"remote_host\":\"10.0.1.21\","
    "\"remote_port\":9001,\"remote_engine_id\":\"engine-abc123\","
    "\"remote_request_id\":\"req-00000000-0000-0000-0000-000000000001\"}}", ranks);

  *out_len = (size_t)pos;
  return buf;
}

static int test_kv_extract_real_vllm_format(void) {
  /* Real vLLM nixl_connector.py format: remote_block_ids is nested array
   * Includes all nixl_connector.py fields: do_remote_prefill, do_remote_decode,
   * remote_engine_id, remote_host, remote_port, remote_block_ids, block_mapping,
   * connector_type, tp_size, remote_request_id */
  const char *resp =
    "{\"id\":\"cmpl-abc\",\"choices\":[{\"text\":\"ok\"}],"
    "\"kv_transfer_params\":{"
    "\"do_remote_decode\":true,"
    "\"do_remote_prefill\":false,"
    "\"remote_block_ids\":[[1001,1002,1003],[2001,2002,2003]],"
    "\"block_mapping\":[],"
    "\"connector_type\":\"NixlConnector\","
    "\"remote_host\":\"10.0.1.21\","
    "\"remote_port\":9001,"
    "\"remote_engine_id\":\"engine-abc123\","
    "\"remote_request_id\":\"req-00000000-0000\","
    "\"tp_size\":2"
    "}}";
  char kv_out[PD_KV_PARAMS_MAX_LEN];
  size_t kv_len = 0;

  ASSERT_EQ(pd_extract_kv_params((const uint8_t *)resp, strlen(resp),
            kv_out, &kv_len, sizeof(kv_out)), 0, "extract succeeds");
  ASSERT_EQ(kv_len > 0, 1, "kv_len > 0");
  /* Nested array marker */
  ASSERT_STR_CONTAINS((uint8_t *)kv_out, kv_len, "[[", "remote_block_ids is nested array");
  ASSERT_STR_CONTAINS((uint8_t *)kv_out, kv_len, "\"tp_size\":2", "tp_size present");
  ASSERT_STR_CONTAINS((uint8_t *)kv_out, kv_len, "\"remote_host\"", "remote_host present");
  ASSERT_STR_CONTAINS((uint8_t *)kv_out, kv_len, "\"do_remote_decode\"", "do_remote_decode present");
  ASSERT_STR_CONTAINS((uint8_t *)kv_out, kv_len, "\"remote_engine_id\"", "remote_engine_id present");
  ASSERT_STR_CONTAINS((uint8_t *)kv_out, kv_len, "\"block_mapping\"", "block_mapping present");
  ASSERT_STR_CONTAINS((uint8_t *)kv_out, kv_len, "\"connector_type\"", "connector_type present");
  return 1;
}

static int test_kv_extract_large_block_ids_32kb(void) {
  /* 4 ranks x 1200 blocks = ~32KB of block_ids JSON */
  size_t resp_len = 0;
  uint8_t *resp = build_large_response(4, 1200, &resp_len);
  ASSERT_EQ(resp != NULL, 1, "build_large_response succeeded");

  char *kv_out = malloc(PD_KV_PARAMS_MAX_LEN);
  ASSERT_EQ(kv_out != NULL, 1, "kv_out malloc succeeded");
  size_t kv_len = 0;

  ASSERT_EQ(pd_extract_kv_params(resp, resp_len,
            kv_out, &kv_len, PD_KV_PARAMS_MAX_LEN), 0, "32KB extract succeeds");
  ASSERT_EQ(kv_len > 25000, 1, "kv_len > 25000 (large payload fits in 64KB buffer)");
  ASSERT_STR_CONTAINS((uint8_t *)kv_out, kv_len, "[[", "nested array present");

  free(kv_out);
  free(resp);
  return 1;
}

static int test_kv_extract_overflow_70kb(void) {
  /* 4 ranks x 4000 blocks = ~70KB+ of block_ids JSON — exceeds 64KB buffer */
  size_t resp_len = 0;
  uint8_t *resp = build_large_response(4, 4000, &resp_len);
  ASSERT_EQ(resp != NULL, 1, "build_large_response succeeded");

  char *kv_out = malloc(PD_KV_PARAMS_MAX_LEN);
  ASSERT_EQ(kv_out != NULL, 1, "kv_out malloc succeeded");
  size_t kv_len = 999;

  /* Should trigger -EMSGSIZE: overflow detected */
  ASSERT_EQ(pd_extract_kv_params(resp, resp_len,
            kv_out, &kv_len, PD_KV_PARAMS_MAX_LEN), -EMSGSIZE, "70KB overflow returns -EMSGSIZE");
  ASSERT_EQ(kv_len, 0, "kv_len == 0 on overflow");

  free(kv_out);
  free(resp);
  return 1;
}

static int test_kv_extract_tp_size_field(void) {
  const char *resp =
    "{\"id\":\"cmpl-tp\",\"choices\":[{\"text\":\"ok\"}],"
    "\"kv_transfer_params\":{"
    "\"do_remote_decode\":true,"
    "\"remote_block_ids\":[[1,2,3]],"
    "\"tp_size\":8"
    "}}";
  char kv_out[4096];
  size_t kv_len = 0;

  ASSERT_EQ(pd_extract_kv_params((const uint8_t *)resp, strlen(resp),
            kv_out, &kv_len, sizeof(kv_out)), 0, "tp_size extract ok");
  ASSERT_EQ(kv_len > 0, 1, "kv_len > 0");
  ASSERT_STR_CONTAINS((uint8_t *)kv_out, kv_len, "\"tp_size\":8", "tp_size=8 present");
  return 1;
}

/* ===== Suite C addition: null args test ===== */

static int test_kv_extract_null_args(void) {
  char kv_out[64];
  size_t kv_len = 0;

  ASSERT_EQ(pd_extract_kv_params(NULL, 0, NULL, NULL, 0), -EINVAL, "all-null returns -EINVAL");
  ASSERT_EQ(pd_extract_kv_params((const uint8_t *)"x", 1, kv_out, NULL, sizeof(kv_out)),
            -EINVAL, "null kv_out_len returns -EINVAL");
  ASSERT_EQ(pd_extract_kv_params((const uint8_t *)"x", 1, NULL, &kv_len, 64),
            -EINVAL, "null kv_out returns -EINVAL");
  ASSERT_EQ(pd_extract_kv_params((const uint8_t *)"x", 1, kv_out, &kv_len, 0),
            -EINVAL, "zero capacity returns -EINVAL");
  return 1;
}

/* ===== Suite E additions: boundary-precise and content verification ===== */

/* Build a response whose kv_transfer_params object is approximately target_kv_bytes.
 * Uses iterative adjustment on blocks_per_rank to hit the target.
 * kv_size_out receives the actual kv_transfer_params object size. */
static uint8_t *
build_response_with_kv_size(size_t target_kv_bytes, int ranks, size_t *out_len, size_t *kv_size_out)
{
  /* Estimate blocks needed: each block ID is ~6 bytes (5 digits + comma) */
  int blocks_per_rank = (int)(target_kv_bytes / (ranks * 7));
  if (blocks_per_rank < 10) blocks_per_rank = 10;

  /* Iterate to find the right block count */
  for (int attempt = 0; attempt < 20; attempt++) {
    size_t resp_len = 0;
    uint8_t *resp = build_large_response(ranks, blocks_per_rank, &resp_len);
    if (!resp) return NULL;

    /* Find kv_transfer_params object boundaries */
    const char *kv_key = "\"kv_transfer_params\":";
    const char *found = memmem(resp, resp_len, kv_key, strlen(kv_key));
    if (!found) { free(resp); return NULL; }

    /* Skip to the opening { */
    const char *obj_start = found + strlen(kv_key);
    while (*obj_start == ' ' || *obj_start == '\t') obj_start++;
    if (*obj_start != '{') { free(resp); return NULL; }

    /* Find matching closing } */
    int depth = 0;
    int in_string = 0;
    const char *p = obj_start;
    const char *obj_end = NULL;
    while (p < (const char *)resp + resp_len) {
      if (*p == '\\' && in_string) { p += 2; continue; }
      if (*p == '"') { in_string = !in_string; }
      else if (!in_string) {
        if (*p == '{') depth++;
        else if (*p == '}') { depth--; if (depth == 0) { obj_end = p + 1; break; } }
      }
      p++;
    }
    if (!obj_end) { free(resp); return NULL; }

    size_t kv_size = (size_t)(obj_end - obj_start);
    *kv_size_out = kv_size;

    if (kv_size >= target_kv_bytes && kv_size <= target_kv_bytes + 100) {
      *out_len = resp_len;
      return resp;
    } else if (kv_size < target_kv_bytes) {
      /* Need more blocks */
      int deficit = (int)(target_kv_bytes - kv_size);
      blocks_per_rank += deficit / (ranks * 6) + 1;
    } else {
      /* Too many blocks */
      int surplus = (int)(kv_size - target_kv_bytes);
      blocks_per_rank -= surplus / (ranks * 6) + 1;
      if (blocks_per_rank < 10) blocks_per_rank = 10;
    }
    free(resp);
  }

  /* Couldn't hit exact target, return best effort */
  return build_large_response(ranks, blocks_per_rank, out_len);
}

static int test_kv_extract_boundary_65535(void) {
  /* kv_transfer_params object approximately 65535 bytes — should succeed */
  size_t resp_len = 0, kv_size = 0;
  uint8_t *resp = build_response_with_kv_size(65535, 4, &resp_len, &kv_size);
  ASSERT_EQ(resp != NULL, 1, "build succeeded");

  char *kv_out = malloc(PD_KV_PARAMS_MAX_LEN);
  ASSERT_EQ(kv_out != NULL, 1, "kv_out malloc succeeded");
  size_t kv_len = 0;

  /* kv_size should be <= 65535 (fits in 64KB buffer) */
  if (kv_size < PD_KV_PARAMS_MAX_LEN) {
    int ret = pd_extract_kv_params(resp, resp_len, kv_out, &kv_len, PD_KV_PARAMS_MAX_LEN);
    ASSERT_EQ(ret, 0, "boundary-1 kv_params extracts successfully");
    ASSERT_EQ(kv_len > 60000, 1, "kv_len near 65535");
    ASSERT_EQ(kv_out[0], '{', "starts with {");
    ASSERT_EQ(kv_out[kv_len - 1], '}', "ends with }");
  }

  free(kv_out);
  free(resp);
  return 1;
}

static int test_kv_extract_boundary_65536(void) {
  /* kv_transfer_params object >= 65536 bytes — should trigger -EMSGSIZE */
  size_t resp_len = 0, kv_size = 0;
  uint8_t *resp = build_response_with_kv_size(65536, 4, &resp_len, &kv_size);
  ASSERT_EQ(resp != NULL, 1, "build succeeded");

  char *kv_out = malloc(PD_KV_PARAMS_MAX_LEN);
  ASSERT_EQ(kv_out != NULL, 1, "kv_out malloc succeeded");
  size_t kv_len = 999;

  /* kv_size should be >= 65536 (exceeds buffer) */
  if (kv_size >= PD_KV_PARAMS_MAX_LEN) {
    int ret = pd_extract_kv_params(resp, resp_len, kv_out, &kv_len, PD_KV_PARAMS_MAX_LEN);
    ASSERT_EQ(ret, -EMSGSIZE, "boundary kv_params triggers -EMSGSIZE");
    ASSERT_EQ(kv_len, 0, "kv_len == 0 on overflow");
  }

  free(kv_out);
  free(resp);
  return 1;
}

static int test_kv_extract_content_verification(void) {
  /* 4 ranks x 1200 blocks — verify extracted JSON content integrity */
  size_t resp_len = 0;
  uint8_t *resp = build_large_response(4, 1200, &resp_len);
  ASSERT_EQ(resp != NULL, 1, "build succeeded");

  char *kv_out = malloc(PD_KV_PARAMS_MAX_LEN);
  ASSERT_EQ(kv_out != NULL, 1, "kv_out malloc succeeded");
  size_t kv_len = 0;

  int ret = pd_extract_kv_params(resp, resp_len, kv_out, &kv_len, PD_KV_PARAMS_MAX_LEN);
  ASSERT_EQ(ret, 0, "extraction succeeds");
  ASSERT_EQ(kv_len > 0, 1, "kv_len > 0");

  /* Verify JSON structure */
  ASSERT_EQ(kv_out[0], '{', "starts with {");
  ASSERT_EQ(kv_out[kv_len - 1], '}', "ends with }");

  /* Verify all nixl_connector.py fields present */
  ASSERT_STR_CONTAINS((uint8_t *)kv_out, kv_len, "\"do_remote_decode\"", "has do_remote_decode");
  ASSERT_STR_CONTAINS((uint8_t *)kv_out, kv_len, "\"do_remote_prefill\"", "has do_remote_prefill");
  ASSERT_STR_CONTAINS((uint8_t *)kv_out, kv_len, "\"remote_engine_id\"", "has remote_engine_id");
  ASSERT_STR_CONTAINS((uint8_t *)kv_out, kv_len, "\"remote_host\"", "has remote_host");
  ASSERT_STR_CONTAINS((uint8_t *)kv_out, kv_len, "\"remote_port\"", "has remote_port");
  ASSERT_STR_CONTAINS((uint8_t *)kv_out, kv_len, "\"remote_block_ids\"", "has remote_block_ids");
  ASSERT_STR_CONTAINS((uint8_t *)kv_out, kv_len, "\"block_mapping\"", "has block_mapping");
  ASSERT_STR_CONTAINS((uint8_t *)kv_out, kv_len, "\"connector_type\"", "has connector_type");
  ASSERT_STR_CONTAINS((uint8_t *)kv_out, kv_len, "\"tp_size\"", "has tp_size");

  /* Verify nested array structure (4 ranks) */
  ASSERT_STR_CONTAINS((uint8_t *)kv_out, kv_len, "[[", "has nested array start");

  /* Count inter-rank separators to verify 4 ranks */
  int bracket_groups = count_substr(kv_out, kv_len, "],[");
  ASSERT_EQ(bracket_groups, 3, "4 ranks = 3 inter-rank separators");

  free(kv_out);
  free(resp);
  return 1;
}

/* ===== Main ===== */

/* ===== Suite F: SGLang bootstrap triple injection ===== */

static int test_sg_inject_flat(void) {
  const char *input = "{\"model\":\"llama\",\"prompt\":\"hi\",\"stream\":true}";
  uint8_t out[2048];
  size_t out_len = 0;

  ASSERT_EQ(pd_sg_inject_bootstrap((const uint8_t *)input, strlen(input),
            out, &out_len, sizeof(out), "10.0.0.11", 8998, 42), 0,
            "inject succeeds");
  ASSERT_STR_CONTAINS(out, out_len, "\"bootstrap_host\":\"10.0.0.11\"", "host injected");
  ASSERT_STR_CONTAINS(out, out_len, "\"bootstrap_port\":8998", "port injected");
  ASSERT_STR_CONTAINS(out, out_len, "\"bootstrap_room\":42", "room injected");
  /* Triple lands INSIDE the object: last byte is still the closing brace,
   * and the pre-existing fields are untouched. */
  ASSERT_EQ(out[out_len - 1], '}', "still ends with }");
  ASSERT_STR_CONTAINS(out, out_len, "\"stream\":true", "original fields untouched");
  return 1;
}

static int test_sg_inject_nested_tail(void) {
  /* Body ENDING in a nested object — the splice must target the OUTER
   * closing brace, not the nested one. */
  const char *input = "{\"model\":\"llama\",\"opts\":{\"temperature\":0.5}}";
  uint8_t out[2048];
  size_t out_len = 0;

  ASSERT_EQ(pd_sg_inject_bootstrap((const uint8_t *)input, strlen(input),
            out, &out_len, sizeof(out), "10.0.0.11", 8998, 7), 0,
            "inject succeeds");
  ASSERT_STR_CONTAINS(out, out_len, "{\"temperature\":0.5},\"bootstrap_host\"",
                      "spliced after the nested object, before the outer brace");
  ASSERT_EQ(out[out_len - 1], '}', "still ends with }");
  return 1;
}

static int test_sg_inject_escaped_brace_in_string(void) {
  /* A '}' inside a string value must not confuse the splice point. */
  const char *input = "{\"prompt\":\"code: if (x) { y(); }\"}";
  uint8_t out[2048];
  size_t out_len = 0;

  ASSERT_EQ(pd_sg_inject_bootstrap((const uint8_t *)input, strlen(input),
            out, &out_len, sizeof(out), "10.0.0.11", 8998, 7), 0,
            "inject succeeds");
  ASSERT_STR_CONTAINS(out, out_len, "y(); }\",\"bootstrap_host\"",
                      "spliced after the string value");
  ASSERT_EQ(out[out_len - 1], '}', "still ends with }");
  return 1;
}

static int test_sg_inject_trailing_whitespace(void) {
  const char *input = "{\"model\":\"llama\"}\n";
  uint8_t out[2048];
  size_t out_len = 0;

  ASSERT_EQ(pd_sg_inject_bootstrap((const uint8_t *)input, strlen(input),
            out, &out_len, sizeof(out), "10.0.0.11", 8998, 7), 0,
            "inject succeeds");
  ASSERT_STR_CONTAINS(out, out_len, "\"bootstrap_room\":7}\n",
                      "spliced before the brace, trailing newline preserved");
  return 1;
}

static int test_sg_inject_ipv6_wrap(void) {
  const char *input = "{\"model\":\"llama\"}";
  uint8_t out[2048];
  size_t out_len = 0;

  ASSERT_EQ(pd_sg_inject_bootstrap((const uint8_t *)input, strlen(input),
            out, &out_len, sizeof(out), "fd00::11", 8998, 7), 0,
            "inject succeeds");
  ASSERT_STR_CONTAINS(out, out_len, "\"bootstrap_host\":\"[fd00::11]\"",
                      "IPv6 host bracket-wrapped");
  return 1;
}

static int test_sg_inject_ipv6_already_bracketed(void) {
  const char *input = "{\"model\":\"llama\"}";
  uint8_t out[2048];
  size_t out_len = 0;

  ASSERT_EQ(pd_sg_inject_bootstrap((const uint8_t *)input, strlen(input),
            out, &out_len, sizeof(out), "[fd00::11]", 8998, 7), 0,
            "inject succeeds");
  ASSERT_STR_CONTAINS(out, out_len, "\"bootstrap_host\":\"[fd00::11]\"",
                      "already-bracketed host left alone");
  ASSERT_STR_NOT_CONTAINS(out, out_len, "[[", "no double wrap");
  return 1;
}

static int test_sg_inject_empty_object(void) {
  const char *input = "{}";
  uint8_t out[2048];
  size_t out_len = 0;

  ASSERT_EQ(pd_sg_inject_bootstrap((const uint8_t *)input, strlen(input),
            out, &out_len, sizeof(out), "10.0.0.11", 8998, 7), 0,
            "inject succeeds");
  ASSERT_STR_CONTAINS(out, out_len, "{\"bootstrap_host\"",
                      "no leading comma after the opening brace");
  ASSERT_EQ(out[out_len - 1], '}', "still ends with }");
  return 1;
}

static int test_sg_inject_room_max(void) {
  /* Room upper bound 2^63-1 must round-trip through the decimal format. */
  const char *input = "{\"model\":\"llama\"}";
  uint8_t out[2048];
  size_t out_len = 0;

  ASSERT_EQ(pd_sg_inject_bootstrap((const uint8_t *)input, strlen(input),
            out, &out_len, sizeof(out), "10.0.0.11", 8998,
            (uint64_t)INT64_MAX), 0, "inject succeeds");
  ASSERT_STR_CONTAINS(out, out_len, "\"bootstrap_room\":9223372036854775807",
                      "room formatted as full positive i64");
  return 1;
}

static int test_sg_inject_overflow(void) {
  const char *input = "{\"model\":\"llama\"}";
  uint8_t out[32]; /* too small for body + triple */
  size_t out_len = 0;

  ASSERT_EQ(pd_sg_inject_bootstrap((const uint8_t *)input, strlen(input),
            out, &out_len, sizeof(out), "10.0.0.11", 8998, 7), -1,
            "overflow rejected");
  return 1;
}

static int test_sg_inject_no_brace(void) {
  const char *input = "not json at all";
  uint8_t out[2048];
  size_t out_len = 0;

  ASSERT_EQ(pd_sg_inject_bootstrap((const uint8_t *)input, strlen(input),
            out, &out_len, sizeof(out), "10.0.0.11", 8998, 7), -1,
            "brace-less body rejected");
  return 1;
}

static int test_sg_inject_original_untouched(void) {
  /* The retry path re-injects a FRESH room into the SAVED original body —
   * the source buffer must come through pristine. */
  const char *input = "{\"model\":\"llama\",\"prompt\":\"hi\"}";
  char orig[128];
  uint8_t out[2048];
  size_t out_len = 0;

  strcpy(orig, input);
  ASSERT_EQ(pd_sg_inject_bootstrap((const uint8_t *)orig, strlen(orig),
            out, &out_len, sizeof(out), "10.0.0.11", 8998, 7), 0,
            "inject succeeds");
  ASSERT_EQ(strcmp(orig, input), 0, "original body untouched");
  return 1;
}

static int test_sg_room_id_range(void) {
  /* Every draw must succeed and land in [0, 2^63-1] (top bit clear). */
  int i;
  uint64_t room = 0;

  for (i = 0; i < 1000; i++) {
    ASSERT_EQ(pd_sg_room_id(&room), 0, "room draw succeeds");
    ASSERT_EQ((room >> 63), 0, "room top bit clear (i64-positive range)");
  }
  ASSERT_EQ(pd_sg_room_id(NULL), -1, "NULL out rejected");
  return 1;
}

static int test_sg_room_id_distinct(void) {
  /* Two draws colliding is a 2^-63 event — a repeat means the RNG is not
   * actually random (the exact failure rooms must never have). */
  uint64_t a = 0, b = 0;

  ASSERT_EQ(pd_sg_room_id(&a), 0, "first draw succeeds");
  ASSERT_EQ(pd_sg_room_id(&b), 0, "second draw succeeds");
  ASSERT_EQ(a != b, 1, "consecutive rooms distinct");
  return 1;
}

/* ===== Suite G: TRT-LLM dialect body surgery ===== */

static int test_trt_prefill_basic(void) {
  const char *input =
      "{\"model\":\"m\",\"prompt\":\"hi\",\"max_tokens\":200,"
      "\"stream\":true,\"stream_options\":{\"include_usage\":true}}";
  uint8_t out[2048];
  size_t out_len = 0;

  ASSERT_EQ(pd_trt_prepare_prefill_body_id((const uint8_t *)input,
            strlen(input), out, &out_len, sizeof(out), 42), 0,
            "trt prefill rewrite succeeds");
  ASSERT_STR_CONTAINS(out, out_len, "\"stream\":false", "stream forced false");
  ASSERT_STR_NOT_CONTAINS(out, out_len, "stream_options",
                          "stream_options dropped");
  ASSERT_STR_CONTAINS(out, out_len,
      "\"disaggregated_params\":{\"request_type\":\"context_only\","
      "\"disagg_request_id\":42}", "context splice present");
  /* THE dialect divergence: the context worker forces its own token cap. */
  ASSERT_STR_CONTAINS(out, out_len, "\"max_tokens\":200",
                      "max_tokens NOT rewritten");
  ASSERT_STR_NOT_CONTAINS(out, out_len, "kv_transfer_params",
                          "no vLLM fields (extra=forbid would 400)");
  return 1;
}

static int test_trt_prefill_exact_bytes(void) {
  const char *input = "{\"prompt\":\"a\",\"stream\":true}";
  const char *expect =
      "{\"prompt\":\"a\",\"stream\":false,\"disaggregated_params\":"
      "{\"request_type\":\"context_only\",\"disagg_request_id\":7}}";
  uint8_t out[1024];
  size_t out_len = 0;

  ASSERT_EQ(pd_trt_prepare_prefill_body_id((const uint8_t *)input,
            strlen(input), out, &out_len, sizeof(out), 7), 0,
            "rewrite succeeds");
  ASSERT_EQ((int)out_len, (int)strlen(expect), "exact length");
  ASSERT_EQ(memcmp(out, expect, out_len), 0, "exact bytes");
  return 1;
}

static int test_trt_prefill_empty_object(void) {
  const char *input = "{}";
  uint8_t out[512];
  size_t out_len = 0;

  ASSERT_EQ(pd_trt_prepare_prefill_body_id((const uint8_t *)input,
            strlen(input), out, &out_len, sizeof(out), 1), 0,
            "empty-object rewrite succeeds");
  ASSERT_STR_CONTAINS(out, out_len, "{\"disaggregated_params\"",
                      "leading comma dropped on empty object");
  return 1;
}

static int test_trt_prefill_fresh_ids(void) {
  /* The production entry draws a fresh int63 per call — a retry must not
   * reuse the previous disagg_request_id. */
  const char *input = "{\"prompt\":\"a\"}";
  uint8_t out_a[512], out_b[512];
  size_t len_a = 0, len_b = 0;

  ASSERT_EQ(pd_trt_prepare_prefill_body((const uint8_t *)input,
            strlen(input), out_a, &len_a, sizeof(out_a)), 0, "draw A");
  ASSERT_EQ(pd_trt_prepare_prefill_body((const uint8_t *)input,
            strlen(input), out_b, &len_b, sizeof(out_b)), 0, "draw B");
  ASSERT_EQ((len_a != len_b) || memcmp(out_a, out_b, len_a) != 0, 1,
            "consecutive ids distinct");
  return 1;
}

/* C2-capture-shaped context response fixture. */
static const char trt_ctx_resp[] =
    "{\"id\":\"cmpl-1\",\"object\":\"text_completion\",\"model\":\"m\","
    "\"choices\":[{\"index\":0,\"text\":\"x\",\"finish_reason\":\"length\","
    "\"disaggregated_params\":{\"request_type\":\"context_only\","
    "\"first_gen_tokens\":[123],\"ctx_request_id\":7,"
    "\"encoded_opaque_state\":\"QUJDREVG\",\"draft_tokens\":null}}],"
    "\"usage\":{\"prompt_tokens\":8,\"completion_tokens\":1}}";

static int test_trt_extract_typical(void) {
  char dp[4096];
  size_t dp_len = 0;

  ASSERT_EQ(pd_trt_extract_disagg_params((const uint8_t *)trt_ctx_resp,
            sizeof(trt_ctx_resp) - 1, dp, &dp_len, sizeof(dp)), 0,
            "extract succeeds");
  ASSERT_EQ(dp[0], '{', "span is an object");
  ASSERT_EQ(dp[dp_len - 1], '}', "span closes");
  ASSERT_STR_CONTAINS(dp, dp_len, "\"encoded_opaque_state\":\"QUJDREVG\"",
                      "opaque state carried");
  ASSERT_STR_CONTAINS(dp, dp_len, "\"request_type\":\"context_only\"",
                      "request_type carried verbatim");
  return 1;
}

static int test_trt_extract_null_params(void) {
  const char *resp =
      "{\"choices\":[{\"index\":0,\"finish_reason\":\"stop\","
      "\"disaggregated_params\":null}]}";
  char dp[256];
  size_t dp_len = 1;

  ASSERT_EQ(pd_trt_extract_disagg_params((const uint8_t *)resp, strlen(resp),
            dp, &dp_len, sizeof(dp)), -ENOENT, "null params -> ENOENT");
  ASSERT_EQ((int)dp_len, 0, "out length zeroed");
  return 1;
}

static int test_trt_extract_outside_choices(void) {
  /* The descent bounds the search to the choices array — a same-named key
   * elsewhere in the envelope must never be picked up. */
  const char *resp =
      "{\"disaggregated_params\":{\"bogus\":1},"
      "\"choices\":[{\"index\":0,\"finish_reason\":\"stop\"}]}";
  char dp[256];
  size_t dp_len = 0;

  ASSERT_EQ(pd_trt_extract_disagg_params((const uint8_t *)resp, strlen(resp),
            dp, &dp_len, sizeof(dp)), -ENOENT,
            "envelope-level key not matched");
  return 1;
}

static int test_trt_extract_overflow(void) {
  char dp[16];
  size_t dp_len = 0;

  ASSERT_EQ(pd_trt_extract_disagg_params((const uint8_t *)trt_ctx_resp,
            sizeof(trt_ctx_resp) - 1, dp, &dp_len, sizeof(dp)), -EMSGSIZE,
            "tiny capacity -> EMSGSIZE");
  ASSERT_EQ((int)dp_len, 0, "degrades to empty");
  return 1;
}

static int test_trt_decode_body(void) {
  const char *orig =
      "{\"model\":\"m\",\"prompt\":\"hi\",\"stream\":true,\"max_tokens\":200}";
  const char *dp =
      "{\"request_type\":\"context_only\",\"encoded_opaque_state\":\"QUJD\"}";
  uint8_t out[4096];
  size_t out_len = 0;

  ASSERT_EQ(pd_trt_prepare_decode_body((const uint8_t *)orig, strlen(orig),
            dp, strlen(dp), out, &out_len, sizeof(out)), 0,
            "decode body build succeeds");
  ASSERT_STR_CONTAINS(out, out_len,
      ",\"disaggregated_params\":{\"request_type\":\"generation_only\","
      "\"encoded_opaque_state\":\"QUJD\"}", "params spliced, type flipped");
  ASSERT_STR_NOT_CONTAINS(out, out_len, "context_only",
                          "no context_only residue");
  ASSERT_STR_CONTAINS(out, out_len, "\"stream\":true",
                      "client stream preserved");
  ASSERT_STR_CONTAINS(out, out_len, "\"max_tokens\":200",
                      "max_tokens preserved");
  ASSERT_EQ(out[out_len - 1], '}', "body closes");
  return 1;
}

static int test_trt_decode_body_no_request_type(void) {
  const char *orig = "{\"prompt\":\"hi\"}";
  const char *dp = "{\"encoded_opaque_state\":\"QUJD\"}";
  uint8_t out[1024];
  size_t out_len = 0;

  ASSERT_EQ(pd_trt_prepare_decode_body((const uint8_t *)orig, strlen(orig),
            dp, strlen(dp), out, &out_len, sizeof(out)), 0,
            "build succeeds");
  ASSERT_STR_CONTAINS(out, out_len,
      "{\"request_type\":\"generation_only\",\"encoded_opaque_state\":\"QUJD\"}",
      "request_type injected");
  return 1;
}

static int test_trt_decode_body_empty_params(void) {
  const char *orig = "{\"prompt\":\"hi\",\"stream\":true}";
  uint8_t out[1024];
  size_t out_len = 0;

  ASSERT_EQ(pd_trt_prepare_decode_body((const uint8_t *)orig, strlen(orig),
            NULL, 0, out, &out_len, sizeof(out)), 0, "build succeeds");
  ASSERT_EQ((int)out_len, (int)strlen(orig), "original length");
  ASSERT_EQ(memcmp(out, orig, out_len), 0,
            "original body unchanged (converged-serve degradation)");
  return 1;
}

static int test_trt_decode_body_empty_obj_params(void) {
  const char *orig = "{\"prompt\":\"hi\"}";
  const char *dp = "{}";
  uint8_t out[1024];
  size_t out_len = 0;

  ASSERT_EQ(pd_trt_prepare_decode_body((const uint8_t *)orig, strlen(orig),
            dp, strlen(dp), out, &out_len, sizeof(out)), 0, "build succeeds");
  ASSERT_STR_CONTAINS(out, out_len,
      ",\"disaggregated_params\":{\"request_type\":\"generation_only\"}",
      "empty span gets the field, no trailing comma");
  return 1;
}

static int test_trt_early_exit_verdicts(void) {
  const char *stop =
      "{\"choices\":[{\"finish_reason\":\"stop\",\"text\":\"x\"}]}";
  const char *length =
      "{\"choices\":[{\"finish_reason\":\"length\",\"text\":\"x\"}]}";
  const char *notfin =
      "{\"choices\":[{\"finish_reason\":\"not_finished\",\"text\":\"x\"}]}";
  const char *nul =
      "{\"choices\":[{\"finish_reason\":null,\"text\":\"x\"}]}";
  const char *absent = "{\"choices\":[{\"text\":\"x\"}]}";

  ASSERT_EQ(pd_trt_ctx_early_exit_check((const uint8_t *)stop, strlen(stop)),
            1, "stop -> early exit");
  ASSERT_EQ(pd_trt_ctx_early_exit_check((const uint8_t *)length,
            strlen(length)), 0, "length -> decode");
  ASSERT_EQ(pd_trt_ctx_early_exit_check((const uint8_t *)notfin,
            strlen(notfin)), 0, "not_finished -> decode");
  /* Fail-safe direction: only a definite string verdict skips the decode
   * leg — a wrong skip truncates the response, a wrong decode recomputes. */
  ASSERT_EQ(pd_trt_ctx_early_exit_check((const uint8_t *)nul, strlen(nul)),
            0, "null -> decode");
  ASSERT_EQ(pd_trt_ctx_early_exit_check((const uint8_t *)absent,
            strlen(absent)), 0, "absent -> decode");
  return 1;
}

static int test_trt_stream_requested(void) {
  const char *s_true = "{\"prompt\":\"a\",\"stream\":true}";
  const char *s_false = "{\"prompt\":\"a\",\"stream\":false}";
  const char *s_absent = "{\"prompt\":\"a\"}";

  ASSERT_EQ(pd_trt_stream_requested((const uint8_t *)s_true, strlen(s_true)),
            1, "stream:true detected");
  ASSERT_EQ(pd_trt_stream_requested((const uint8_t *)s_false,
            strlen(s_false)), 0, "stream:false");
  ASSERT_EQ(pd_trt_stream_requested((const uint8_t *)s_absent,
            strlen(s_absent)), 0, "stream absent");
  ASSERT_EQ(pd_trt_stream_requested(NULL, 0), 0, "null body");
  return 1;
}

int main(void) {
  printf("=== Suite A: P/D JSON Rewriting ===\n");
  RUN_TEST(test_normal_rewrite);
  RUN_TEST(test_space_variant);
  RUN_TEST(test_nested_sampling_params);
  RUN_TEST(test_buffer_overflow);
  RUN_TEST(test_missing_max_tokens);
  RUN_TEST(test_max_completion_tokens);
  RUN_TEST(test_min_tokens_rewrite);
  RUN_TEST(test_stream_options_removal);

  printf("\n=== Suite B: P/D Worker Selection ===\n");
  RUN_TEST(test_rr_selection);
  RUN_TEST(test_wrr_selection);
  RUN_TEST(test_health_skip);
  RUN_TEST(test_empty_pool);
  RUN_TEST(test_circuit_breaker_skip);

  printf("\n=== Suite C: kv_transfer_params Extraction ===\n");
  RUN_TEST(test_kv_extract_typical);
  RUN_TEST(test_kv_extract_not_found);
  RUN_TEST(test_kv_extract_deep_nesting);
  RUN_TEST(test_kv_extract_braces_in_strings);
  RUN_TEST(test_kv_extract_buffer_overflow);
  RUN_TEST(test_kv_extract_empty_response);
  RUN_TEST(test_kv_extract_null_args);

  printf("\n=== Suite D: Decode Body Construction ===\n");
  RUN_TEST(test_decode_body_with_kv);
  RUN_TEST(test_decode_body_empty_kv);
  RUN_TEST(test_decode_body_empty_kv_string);
  RUN_TEST(test_decode_body_overflow);
  RUN_TEST(test_decode_body_stream_preserved);

  printf("\n=== Suite E: Real vLLM format (BUF-03) ===\n");
  RUN_TEST(test_kv_extract_real_vllm_format);
  RUN_TEST(test_kv_extract_large_block_ids_32kb);
  RUN_TEST(test_kv_extract_overflow_70kb);
  RUN_TEST(test_kv_extract_tp_size_field);
  RUN_TEST(test_kv_extract_boundary_65535);
  RUN_TEST(test_kv_extract_boundary_65536);
  RUN_TEST(test_kv_extract_content_verification);

  printf("\n=== Suite F: SGLang Bootstrap Injection ===\n");
  RUN_TEST(test_sg_inject_flat);
  RUN_TEST(test_sg_inject_nested_tail);
  RUN_TEST(test_sg_inject_escaped_brace_in_string);
  RUN_TEST(test_sg_inject_trailing_whitespace);
  RUN_TEST(test_sg_inject_ipv6_wrap);
  RUN_TEST(test_sg_inject_ipv6_already_bracketed);
  RUN_TEST(test_sg_inject_empty_object);
  RUN_TEST(test_sg_inject_room_max);
  RUN_TEST(test_sg_inject_overflow);
  RUN_TEST(test_sg_inject_no_brace);
  RUN_TEST(test_sg_inject_original_untouched);
  RUN_TEST(test_sg_room_id_range);
  RUN_TEST(test_sg_room_id_distinct);

  printf("\n=== Suite G: TRT-LLM Dialect Body Surgery ===\n");
  RUN_TEST(test_trt_prefill_basic);
  RUN_TEST(test_trt_prefill_exact_bytes);
  RUN_TEST(test_trt_prefill_empty_object);
  RUN_TEST(test_trt_prefill_fresh_ids);
  RUN_TEST(test_trt_extract_typical);
  RUN_TEST(test_trt_extract_null_params);
  RUN_TEST(test_trt_extract_outside_choices);
  RUN_TEST(test_trt_extract_overflow);
  RUN_TEST(test_trt_decode_body);
  RUN_TEST(test_trt_decode_body_no_request_type);
  RUN_TEST(test_trt_decode_body_empty_params);
  RUN_TEST(test_trt_decode_body_empty_obj_params);
  RUN_TEST(test_trt_early_exit_verdicts);
  RUN_TEST(test_trt_stream_requested);

  printf("\n=== Results: %d/%d tests passed ===\n", tests_passed, tests_run);

  return (tests_passed == tests_run) ? 0 : 1;
}
