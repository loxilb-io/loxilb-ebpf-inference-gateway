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
 * Unit tests for the two halves of AI-gateway token accounting:
 * extract_usage_tokens — the OpenAI "usage" object extractor on the response
 * tail window (SSE events with framing, or a JSON body possibly truncated at
 * the front; the vectors mirror live final-chunk shapes captured from
 * llama.cpp, vLLM P/D, SGLang P/D and TensorRT-LLM fleets) — and
 * inject_include_usage, the request-side stream_options.include_usage
 * force-inject that guarantees the extractor has a usage chunk to read.
 *
 * Build: make test_usage_extract
 * Run:   ./test_usage_extract
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "log.h"
#include "sockproxy_stream_fallback.h"

/* log.c is not linked into this standalone test */
void
log_log(int level, const char *file, int line, const char *fmt, ...)
{
  (void)level; (void)file; (void)line; (void)fmt;
}


static int fail_prefix_allocation;
static void *
prefix_test_malloc(size_t len)
{
  return fail_prefix_allocation ? NULL : malloc(len);
}

#define malloc prefix_test_malloc
#include "sockproxy_json.c"
#undef malloc

static int g_fails = 0;
static int g_cases = 0;

static void
expect_model_prefix(const char *name, const char *body, size_t len,
                    int want_rc, const char *want_model)
{
  char model[128] = {0};
  int rc = extract_model_field_prefix(body, len, model, sizeof(model));

  g_cases++;
  if (rc != want_rc ||
      (want_rc == 0 && strcmp(model, want_model ? want_model : "") != 0)) {
    printf("FAIL %-38s rc=%d model='%s' (want rc=%d model='%s')\n",
           name, rc, model, want_rc, want_model ? want_model : "");
    g_fails++;
    return;
  }
  printf("ok   %-38s rc=%d model='%s'\n", name, rc, model);
}

static void
expect(const char *name, const char *window, int want_rc,
       int want_p, int want_c)
{
  int p = -1, c = -1;
  int rc = extract_usage_tokens(window, strlen(window), &p, &c);

  g_cases++;
  if (rc != want_rc ||
      (want_rc == 0 && (p != want_p || c != want_c))) {
    printf("FAIL %-38s rc=%d p=%d c=%d (want rc=%d p=%d c=%d)\n",
           name, rc, p, c, want_rc, want_p, want_c);
    g_fails++;
    return;
  }
  printf("ok   %-38s rc=%d p=%d c=%d\n", name, rc, p, c);
}

/* Run inject_include_usage on a copy of body in a slack buffer and compare
 * the exact rewritten bytes (want_out; NULL when want_rc==1 asserts the
 * buffer is byte-for-byte unchanged). */
static void
expect_inject(const char *name, const char *body, int want_rc,
              const char *want_out)
{
  char buf[4096];
  size_t blen = strlen(body);
  size_t nl = 0;
  int rc;

  g_cases++;
  if (blen >= sizeof(buf)) {
    printf("FAIL %-38s vector too large\n", name);
    g_fails++;
    return;
  }
  memcpy(buf, body, blen);
  rc = inject_include_usage(buf, blen, sizeof(buf), &nl);

  if (rc != want_rc) {
    printf("FAIL %-38s rc=%d (want %d)\n", name, rc, want_rc);
    g_fails++;
    return;
  }
  if (want_rc == 1) {
    if (nl != blen || memcmp(buf, body, blen) != 0) {
      printf("FAIL %-38s body mutated on rc=1\n", name);
      g_fails++;
      return;
    }
  } else {
    if (nl != strlen(want_out) || memcmp(buf, want_out, nl) != 0) {
      printf("FAIL %-38s got  %.*s\n     %-38s want %s\n",
             name, (int)nl, buf, "", want_out);
      g_fails++;
      return;
    }
  }
  printf("ok   %-38s rc=%d len=%zu\n", name, rc, nl);
}

static void
test_request_token_budget(void)
{
  static const char head[] = "{\"model\":\"Qwen/Qwen3-32B-FP8\",\"tools\":[{\"model\":\"nested\",\"enum\":[";
  static const char tail[] = "]}],\"messages\":[{\"tool_calls\":[{\"id\":\"x\"}],\"role\":\"user\",\"content\":\"test prompt\"}]}";
  static const int sizes[] = {2047, 2048, 2049, 3586, 8192, 8193};
  /* The fixed skeleton contributes 22 tokens. Each enum entry adds one. */
  for (size_t test = 0; test < sizeof(sizes) / sizeof(sizes[0]); test++) {
    int elements = sizes[test] - 22;
    size_t capacity = sizeof(head) + (size_t)elements * 2 + sizeof(tail);
    char *body = malloc(capacity);
    if (!body)
      exit(1);
    char *end = body;
    memcpy(end, head, sizeof(head) - 1);
    end += sizeof(head) - 1;
    for (int i = 0; i < elements; i++) {
      if (i)
        *end++ = ',';
      *end++ = '0';
    }
    memcpy(end, tail, sizeof(tail));
    size_t length = strlen(body);

    char model[MAX_MODEL_LEN] = {0};
    llm_prefix_key_t prefix;
    int model_rc = extract_model_field(body, length, model, sizeof(model));
    int prefix_rc = extract_llm_prefix(body, length, &prefix);
    int ok;
    if (sizes[test] <= 8192) {
      ok = model_rc == 0 && prefix_rc == 0 && prefix.valid &&
           strcmp(model, "Qwen/Qwen3-32B-FP8") == 0 &&
           strcmp(prefix.model, model) == 0 &&
           strcmp(prefix.prefix, "test prompt") == 0;
    } else {
      ok = model_rc == 0 && prefix_rc == LLM_PREFIX_SKIPPED &&
           !prefix.valid && !strcmp(prefix.model, model);
    }
    printf("%s full-request-token-budget-%d\n", ok ? "ok  " : "FAIL", sizes[test]);
    g_cases++;
    g_fails += !ok;

    /* Removing the final root delimiter must fail even after a heap retry. */
    if (sizes[test] == 3586) {
      ok = extract_model_field(body, length - 1, model, sizeof(model)) < 0 &&
           extract_llm_prefix(body, length - 1, &prefix) < 0 && !prefix.valid;
      printf("%s truncated-expanded-request\n", ok ? "ok  " : "FAIL");
      g_cases++;
      g_fails += !ok;
    }
    if (sizes[test] == 3586) {
      fail_prefix_allocation = 1;
      ok = extract_model_field(body, length, model, sizeof(model)) == 0 &&
           extract_llm_prefix(body, length, &prefix) == LLM_PREFIX_SKIPPED &&
           !strcmp(prefix.model, model) && !prefix.valid;
      fail_prefix_allocation = 0;
      printf("%s prefix-allocation-failure-keeps-model\n", ok ? "ok  " : "FAIL");
      g_cases++; g_fails += !ok;
    }
    free(body);
  }
}


static void
test_incremental_metadata(void)
{
  const char *bodies[] = {
    "{\"model\":\"m1\",\"user\":\"u\\u0031\",\"x\":[{\"model\":\"nested\"}]}",
    "{\"model\":\"m1\",\"model\":\"m2\"}",
    "{\"mod\\u0065l\":\"m1\",\"model\":\"m2\"}",
    "{\"model\":null,\"model\":\"m2\"}",
    "{\"model\":{\"nested\":[]},\"model\":\"m2\"}",
  };
  for (size_t test = 0; test < sizeof(bodies) / sizeof(bodies[0]); test++) {
    const char *body = bodies[test];
    size_t len = strlen(body);
    int ok = 1;
    for (size_t split = 0; split <= len; split++) {
      sp_json_scan_t scan;
      sp_json_scan_init(&scan);
      int rc = sp_json_scan_feed(&scan, body, split);
      if (!rc) rc = sp_json_scan_feed(&scan, body + split, len - split);
      if (!rc) rc = sp_json_scan_finish(&scan);
      ok &= test ? rc == SP_JSON_DUPLICATE_MODEL :
                   rc == 0 && !strcmp(scan.model, "m1") && !strcmp(scan.user, "u1");
    }
    printf("%s incremental-metadata-%zu\n", ok ? "ok  " : "FAIL", test);
    g_cases++; g_fails += !ok;
  }

  size_t depth = 12000;
  char *body = malloc(depth * 2 + 128), *at = body;
  at += sprintf(at, "{\"model\":\"deep\",\"user\":\"session\",\"nested\":");
  memset(at, '[', depth); at += depth;
  *at++ = '0';
  memset(at, ']', depth); at += depth;
  *at++ = '}'; *at = 0;
  char model[128], user[128];
  llm_prefix_key_t prefix;
  int ok = extract_model_field(body, strlen(body), model, sizeof(model)) == 0 &&
           extract_user_id(body, strlen(body), user, sizeof(user)) == 0 &&
           !strcmp(model, "deep") && !strcmp(user, "session") &&
           extract_llm_prefix(body, strlen(body), &prefix) == LLM_PREFIX_SKIPPED &&
           !strcmp(prefix.model, "deep") && !prefix.valid;
  printf("%s deep-metadata-without-token-tree\n", ok ? "ok  " : "FAIL");
  g_cases++; g_fails += !ok;
  free(body);
}

int
main(void)
{
  test_request_token_budget();
  test_incremental_metadata();
  /* Oversize JSON routing needs a complete direct top-level model before the
   * rest of the document exists. Every truncated key/value remains pending;
   * nested or string-embedded spoof keys never win. */
  expect_model_prefix("model-prefix-open-object", "{", 1, 1, NULL);
  expect_model_prefix("model-prefix-split-key", "{\"mo", 4, 1, NULL);
  expect_model_prefix("model-prefix-split-value", "{\"model\":\"Qwen/", 15,
                      1, NULL);
  expect_model_prefix("model-prefix-complete-no-root",
                      "{\"model\":\"Qwen/Qwen3-0.6B\"",
                      strlen("{\"model\":\"Qwen/Qwen3-0.6B\""),
                      0, "Qwen/Qwen3-0.6B");
  expect_model_prefix("model-prefix-nested-spoof",
                      "{\"meta\":{\"model\":\"evil\"},"
                      "\"model\":\"good\",\"prompt\":\"partial",
                      strlen("{\"meta\":{\"model\":\"evil\"},"
                             "\"model\":\"good\",\"prompt\":\"partial"),
                      0, "good");
  expect_model_prefix("model-prefix-string-spoof",
                      "{\"note\":\"\\\"model\\\":\\\"evil\\\"\","
                      "\"model\":\"good\",\"prompt\":",
                      strlen("{\"note\":\"\\\"model\\\":\\\"evil\\\"\","
                             "\"model\":\"good\",\"prompt\":"),
                      0, "good");
  expect_model_prefix("model-prefix-escaped",
                      "{\"model\":\"Qwen\\/Qwen3\",\"prompt\":",
                      strlen("{\"model\":\"Qwen\\/Qwen3\",\"prompt\":"),
                      0, "Qwen/Qwen3");
  expect_model_prefix("model-prefix-non-string",
                      "{\"model\":123,", strlen("{\"model\":123,"),
                      -1, NULL);

  /* The stream fallback's limit is a body-prefix contract, including when a
   * single initial read already contains bytes beyond it. A complete model at
   * the final allowed byte is routable; one wholly after the cap is not. */
  {
    static const char edge_model[] = "\"model\":\"edge\"";
    static const char late_model[] = "\"model\":\"late\"";
    char *body = malloc(SP_JSON_ROUTE_PREFIX_MAX + sizeof(late_model) + 8);

    if (!body) return 2;
    body[0] = '{';
    memset(body + 1, ' ', SP_JSON_ROUTE_PREFIX_MAX - 1);
    memcpy(body + SP_JSON_ROUTE_PREFIX_MAX - (sizeof(edge_model) - 1),
           edge_model, sizeof(edge_model) - 1);
    expect_model_prefix("model-at-body-cap", body,
                        SP_JSON_ROUTE_PREFIX_MAX, 0, "edge");

    memset(body + SP_JSON_ROUTE_PREFIX_MAX - (sizeof(edge_model) - 1), ' ',
           sizeof(edge_model) - 1);
    memcpy(body + SP_JSON_ROUTE_PREFIX_MAX, late_model,
           sizeof(late_model) - 1);
    /* Direct framing/header arithmetic is exercised separately in
     * test_stream_fallback; here the extractor receives the exact clamped
     * production body prefix. */
    expect_model_prefix("model-after-body-cap-clamped", body,
                        SP_JSON_ROUTE_PREFIX_MAX, 1, NULL);
    expect_model_prefix("model-after-body-cap-full-control", body,
                        SP_JSON_ROUTE_PREFIX_MAX + sizeof(late_model) - 1,
                        0, "late");
    free(body);
  }

  /* vLLM final chunk: usage object last, empty choices, then [DONE]. */
  expect("vllm-final-chunk",
         "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\","
         "\"choices\":[],\"usage\":{\"prompt_tokens\":38,"
         "\"total_tokens\":59,\"completion_tokens\":21}}\n\n"
         "data: [DONE]\n\n",
         0, 38, 21);

  /* SGLang: every content chunk carries "usage":null; the real object is
   * on the final chunk. The null primitives must be skipped, and the
   * extra reasoning_tokens key must not confuse the walk. */
  expect("sglang-null-usage-chunks",
         "data: {\"choices\":[{\"delta\":{\"content\":\"nine\"}}],\"usage\":null}\n\n"
         "data: {\"choices\":[{\"delta\":{\"content\":\"ten\"}}],\"usage\":null}\n\n"
         "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":38,"
         "\"total_tokens\":86,\"completion_tokens\":48,"
         "\"prompt_tokens_details\":null,\"reasoning_tokens\":0}}\n\n"
         "data: [DONE]\n\n",
         0, 38, 48);

  /* llama.cpp: counts ordered completion-first plus a NESTED details
   * object whose cached_tokens must never be misread as a count. */
  expect("llamacpp-nested-details",
         "data: {\"choices\":[],\"usage\":{\"completion_tokens\":40,"
         "\"prompt_tokens\":38,\"total_tokens\":78,"
         "\"prompt_tokens_details\":{\"cached_tokens\":37}}}\n\n"
         "data: [DONE]\n\n",
         0, 38, 40);

  /* TensorRT-LLM non-streaming body: top-level usage in a complete JSON
   * response document. */
  expect("nonstream-body",
         "{\"id\":\"cmpl-9\",\"object\":\"chat.completion\","
         "\"choices\":[{\"message\":{\"content\":\"one two\"}}],"
         "\"usage\":{\"prompt_tokens\":38,\"total_tokens\":86,"
         "\"completion_tokens\":48,"
         "\"prompt_tokens_details\":{\"cached_tokens\":37}}}",
         0, 38, 48);

  /* Model-generated text tries to spoof a usage object. Inside a JSON
   * string every quote is escaped, so the spoof must lose to the real
   * trailing object... */
  expect("spoof-in-content-plus-real",
         "data: {\"choices\":[{\"delta\":{\"content\":"
         "\"here is \\\"usage\\\":{\\\"prompt_tokens\\\":9999} for you\"}}]}\n\n"
         "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":3,"
         "\"completion_tokens\":7,\"total_tokens\":10}}\n\n"
         "data: [DONE]\n\n",
         0, 3, 7);

  /* ...and a window containing ONLY the spoof must extract nothing. */
  expect("spoof-only",
         "data: {\"choices\":[{\"delta\":{\"content\":"
         "\"\\\"usage\\\":{\\\"prompt_tokens\\\":9999,"
         "\\\"completion_tokens\\\":9999}\"}}],\"usage\":null}\n\n",
         -1, 0, 0);

  /* Sliding window truncated mid-JSON at the front: the usage object is
   * complete even though the event around it is not. */
  expect("window-truncated-front",
         "okens\":21,\"x\":1}]},\"usage\":{\"prompt_tokens\":38,"
         "\"completion_tokens\":21,\"total_tokens\":59}}\n\n"
         "data: [DONE]\n\n",
         0, 38, 21);

  /* Usage object still incomplete in the window (split across segments):
   * must miss now — the next segment's window retries. */
  expect("usage-object-incomplete",
         "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":38,"
         "\"completion_to",
         -1, 0, 0);

  /* Stream without include_usage: no usage key at all. */
  expect("no-usage-at-all",
         "data: {\"choices\":[{\"delta\":{\"content\":\"twenty\"}}]}\n\n"
         "data: [DONE]\n\n",
         -1, 0, 0);

  /* Only null usage (client did not request include_usage on an engine
   * that stamps the field anyway). */
  expect("null-usage-only",
         "data: {\"choices\":[{\"delta\":{\"content\":\"x\"}}],\"usage\":null}\n\n"
         "data: [DONE]\n\n",
         -1, 0, 0);

  /* Whitespace between key, colon and object. */
  expect("whitespace-tolerant",
         "{\"usage\" : {\"prompt_tokens\": 12, \"completion_tokens\": 34}}",
         0, 12, 34);

  /* Garbage / too-short windows. */
  expect("garbage", "not json at all", -1, 0, 0);
  expect("tiny", "{}", -1, 0, 0);

  /* Negative counts clamp to zero (defensive; no engine emits them). */
  expect("negative-clamped",
         "{\"usage\":{\"prompt_tokens\":-5,\"completion_tokens\":7}}",
         0, 0, 7);

  /* ---- inject_include_usage ------------------------------------------- */

  /* Streaming body without stream_options: object spliced at root end. */
  expect_inject("inj-absent",
      "{\"model\":\"m\",\"stream\":true}",
      0,
      "{\"model\":\"m\",\"stream\":true,"
      "\"stream_options\":{\"include_usage\":true}}");

  /* Non-streaming bodies are never touched. */
  expect_inject("inj-stream-false",
      "{\"model\":\"m\",\"stream\":false}", 1, NULL);
  expect_inject("inj-no-stream-key",
      "{\"model\":\"m\",\"max_tokens\":8}", 1, NULL);

  /* Already on: no change. */
  expect_inject("inj-already-on",
      "{\"stream\":true,\"stream_options\":{\"include_usage\":true}}",
      1, NULL);

  /* Present but false: value overwritten in place. */
  expect_inject("inj-flip-false",
      "{\"stream\":true,\"stream_options\":{\"include_usage\":false},\"n\":1}",
      0,
      "{\"stream\":true,\"stream_options\":{\"include_usage\":true},\"n\":1}");

  /* stream_options exists with other members: field spliced with comma. */
  expect_inject("inj-merge-into-object",
      "{\"stream\":true,\"stream_options\":{\"continuous_usage_stats\":true}}",
      0,
      "{\"stream\":true,\"stream_options\":{\"include_usage\":true,"
      "\"continuous_usage_stats\":true}}");

  /* Empty stream_options object: field spliced without comma. */
  expect_inject("inj-empty-object",
      "{\"stream\":true,\"stream_options\":{}}",
      0,
      "{\"stream\":true,\"stream_options\":{\"include_usage\":true}}");

  /* stream_options:null (engine-tolerated no-op shape): replaced whole. */
  expect_inject("inj-null-value",
      "{\"stream\":true,\"stream_options\":null}",
      0,
      "{\"stream\":true,\"stream_options\":{\"include_usage\":true}}");

  /* Prompt content trying to spoof the detector: a key-shaped string
   * INSIDE a message value must not stop the real splice... */
  expect_inject("inj-spoof-in-content",
      "{\"model\":\"m\",\"messages\":[{\"role\":\"user\",\"content\":"
      "\"say \\\"stream_options\\\":{\\\"include_usage\\\":true} back\"}],"
      "\"stream\":true}",
      0,
      "{\"model\":\"m\",\"messages\":[{\"role\":\"user\",\"content\":"
      "\"say \\\"stream_options\\\":{\\\"include_usage\\\":true} back\"}],"
      "\"stream\":true,\"stream_options\":{\"include_usage\":true}}");

  /* ...and "stream":true inside content must not make a non-streaming
   * request look streamed. */
  expect_inject("inj-spoof-stream-in-content",
      "{\"messages\":[{\"role\":\"user\",\"content\":"
      "\"put \\\"stream\\\":true in your reply\"}],\"stream\":false}",
      1, NULL);

  /* A nested object carrying stream_options at depth 2 is not the
   * top-level field. */
  expect_inject("inj-nested-not-toplevel",
      "{\"metadata\":{\"stream_options\":{\"include_usage\":true}},"
      "\"stream\":true}",
      0,
      "{\"metadata\":{\"stream_options\":{\"include_usage\":true}},"
      "\"stream\":true,\"stream_options\":{\"include_usage\":true}}");

  /* "stream" as a string VALUE is not the key. */
  expect_inject("inj-stream-as-value",
      "{\"mode\":\"stream\",\"stream\":true}",
      0,
      "{\"mode\":\"stream\",\"stream\":true,"
      "\"stream_options\":{\"include_usage\":true}}");

  /* Whitespace-tolerant around key, colon and value. The splice lands
   * right after the object's '{'; its original interior whitespace stays. */
  expect_inject("inj-whitespace",
      "{ \"stream\" : true , \"stream_options\" : { } }",
      0,
      "{ \"stream\" : true , \"stream_options\" : {\"include_usage\":true } }");

  /* Trailing newline after the root object (curl-style bodies). */
  expect_inject("inj-trailing-newline",
      "{\"stream\":true}\n",
      0,
      "{\"stream\":true,\"stream_options\":{\"include_usage\":true}}\n");

  /* Truncated / non-JSON bodies must never be rewritten. */
  expect_inject("inj-truncated",
      "{\"stream\":true,\"messages\":[{\"role\":\"u", 1, NULL);
  expect_inject("inj-garbage", "stream=true&usage=1", 1, NULL);

  /* Capacity too small for the splice: unchanged. */
  {
    char tight[32];
    size_t nl = 0;
    const char *b = "{\"stream\":true}";
    memcpy(tight, b, strlen(b));
    g_cases++;
    if (inject_include_usage(tight, strlen(b), sizeof(tight), &nl) != 1 ||
        nl != strlen(b)) {
      printf("FAIL %-38s capacity guard breached\n", "inj-overflow-guard");
      g_fails++;
    } else {
      printf("ok   %-38s rc=1 (unchanged)\n", "inj-overflow-guard");
    }
  }

  /* ---- estimate_prompt_tokens ----------------------------------------- */

  /* messages extent 18 bytes -> 4 tokens; prompt string likewise; neither
   * field -> 0; nested "prompt" inside content must not be measured. */
  {
    struct { const char *name; const char *body; int want; } est_vecs[] = {
      { "est-messages",
        "{\"messages\":[{\"a\":\"xxxxxxxx\"}],\"stream\":true}", 4 },
      { "est-prompt",
        "{\"prompt\":\"0123456789abcdef\",\"stream\":true}", 4 },
      { "est-neither", "{\"stream\":true,\"model\":\"m\"}", 0 },
      { "est-garbage", "not json", 0 },
    };
    size_t vi;
    for (vi = 0; vi < sizeof(est_vecs) / sizeof(est_vecs[0]); vi++) {
      int got = estimate_prompt_tokens(est_vecs[vi].body,
                                       strlen(est_vecs[vi].body));
      g_cases++;
      if (got != est_vecs[vi].want) {
        printf("FAIL %-38s est=%d (want %d)\n",
               est_vecs[vi].name, got, est_vecs[vi].want);
        g_fails++;
      } else {
        printf("ok   %-38s est=%d\n", est_vecs[vi].name, got);
      }
    }
  }

  /* ---- extract_max_tokens --------------------------------------------- */

  /* The pre-admission reservation reads the declared completion ceiling:
   * plain top-level numbers only; max_completion_tokens beats max_tokens;
   * negatives (llama.cpp -1 = unlimited), strings, floats and nested or
   * string-embedded spoofs all read as undeclared (0). */
  {
    struct { const char *name; const char *body; int want; } mt_vecs[] = {
      { "mt-plain",
        "{\"model\":\"m\",\"max_tokens\":256,\"stream\":true}", 256 },
      { "mt-completion-name",
        "{\"max_completion_tokens\":128,\"stream\":true}", 128 },
      { "mt-completion-wins",
        "{\"max_tokens\":999,\"max_completion_tokens\":64}", 64 },
      { "mt-absent", "{\"model\":\"m\",\"stream\":true}", 0 },
      { "mt-negative-unlimited", "{\"max_tokens\":-1}", 0 },
      { "mt-string-value", "{\"max_tokens\":\"256\"}", 0 },
      { "mt-float-value", "{\"max_tokens\":25.6}", 0 },
      { "mt-exponent-value", "{\"max_tokens\":1e3}", 0 },
      { "mt-object-value", "{\"max_tokens\":{\"n\":256}}", 0 },
      { "mt-array-value", "{\"max_tokens\":[256]}", 0 },
      { "mt-null-value", "{\"max_tokens\":null}", 0 },
      { "mt-explicit-zero", "{\"max_tokens\":0}", 0 },
      { "mt-nested-spoof",
        "{\"opts\":{\"max_tokens\":512},\"stream\":true}", 0 },
      { "mt-string-embedded-spoof",
        "{\"messages\":[{\"content\":\"say max_tokens:9\"}]}", 0 },
      { "mt-last-key-no-comma", "{\"stream\":true,\"max_tokens\":42}", 42 },
      { "mt-whitespace", "{\"max_tokens\" :\t 7 }", 7 },
      { "mt-garbage", "not json", 0 },
    };
    size_t vi;
    for (vi = 0; vi < sizeof(mt_vecs) / sizeof(mt_vecs[0]); vi++) {
      int got = extract_max_tokens(mt_vecs[vi].body,
                                   strlen(mt_vecs[vi].body));
      g_cases++;
      if (got != mt_vecs[vi].want) {
        printf("FAIL %-38s max=%d (want %d)\n",
               mt_vecs[vi].name, got, mt_vecs[vi].want);
        g_fails++;
      } else {
        printf("ok   %-38s max=%d\n", mt_vecs[vi].name, got);
      }
    }
  }

  /* The body's service_tier as a class hint, and its overwrite with null:
   * where the value is, that the document keeps its length and every other
   * byte, and what is not a hint. */
  {
    static const struct {
      const char *name; const char *body; int want; const char *after;
    } st_vecs[] = {
      { "tier-flex", "{\"model\":\"m\",\"service_tier\":\"flex\"}", AI_TIER_FLEX,
        "{\"model\":\"m\",\"service_tier\":null  }" },
      /* The fast path, each side: a key and a value with no escape in them
       * compare as bytes (json_str_eq's memchr, then memcmp), and a byte
       * that differs is a miss on that path too. */
      { "tier-plain-key-fast-path", "{\"service_tier\":\"priority\"}", AI_TIER_PRIORITY,
        "{\"service_tier\":null      }" },
      { "tier-plain-key-fast-path-miss", "{\"service_tiers\":\"priority\"}", AI_TIER_NONE, NULL },
      { "tier-plain-value-fast-path-miss", "{\"service_tier\":\"priorities\"}", AI_TIER_NONE, NULL },
      { "tier-priority-first-key", "{\"service_tier\":\"priority\",\"n\":1}", AI_TIER_PRIORITY,
        "{\"service_tier\":null      ,\"n\":1}" },
      { "tier-fast-whitespace", "{\"service_tier\" :\t \"fast\" ,\"n\":1}", AI_TIER_FAST,
        "{\"service_tier\" :\t null   ,\"n\":1}" },
      { "tier-auto-is-no-hint", "{\"service_tier\":\"auto\"}", AI_TIER_NONE, NULL },
      { "tier-default-is-no-hint", "{\"service_tier\":\"default\"}", AI_TIER_NONE, NULL },
      { "tier-case-differs", "{\"service_tier\":\"Flex\"}", AI_TIER_NONE, NULL },
      { "tier-number", "{\"service_tier\":1}", AI_TIER_NONE, NULL },
      { "tier-null", "{\"service_tier\":null}", AI_TIER_NONE, NULL },
      { "tier-empty-string", "{\"service_tier\":\"\"}", AI_TIER_NONE, NULL },
      { "tier-nested", "{\"opts\":{\"service_tier\":\"flex\"}}", AI_TIER_NONE, NULL },
      /* A nested key after a comma of its own object: the walk keeps the
       * depth, not only the key / value alternation. */
      { "tier-nested-after-a-comma", "{\"opts\":{\"a\":1,\"service_tier\":\"flex\"}}", AI_TIER_NONE, NULL },
      { "tier-nested-after-a-comma-left", "{\"opts\":{\"a\":1,\"service_tier\":\"fast\"},\"service_tier\":\"flex\"}",
        AI_TIER_FLEX, "{\"opts\":{\"a\":1,\"service_tier\":\"fast\"},\"service_tier\":null  }" },
      { "tier-in-a-message", "{\"messages\":[{\"content\":\"\\\"service_tier\\\":\\\"flex\\\"\"}]}",
        AI_TIER_NONE, NULL },
      { "tier-absent", "{\"model\":\"m\"}", AI_TIER_NONE, NULL },
      /* Duplicate keys: the last one is read, as a parser that keeps the
       * last duplicate reads it, and every one is nulled. */
      { "tier-dup-last-decides", "{\"service_tier\":\"flex\",\"service_tier\":\"priority\"}",
        AI_TIER_PRIORITY, "{\"service_tier\":null  ,\"service_tier\":null      }" },
      { "tier-dup-three-all-nulled", "{\"service_tier\":\"fast\",\"n\":{\"service_tier\":\"x\"},\"service_tier\":\"auto\",\"service_tier\":\"flex\"}",
        AI_TIER_FLEX, "{\"service_tier\":null  ,\"n\":{\"service_tier\":\"x\"},\"service_tier\":null  ,\"service_tier\":null  }" },
      { "tier-dup-last-no-hint", "{\"service_tier\":\"priority\",\"service_tier\":\"auto\"}", AI_TIER_NONE, NULL },
      { "tier-dup-last-short", "{\"service_tier\":\"flex\",\"service_tier\":1}", AI_TIER_NONE, NULL },
      /* An escaped spelling of the key is the key, as the engine's parser
       * reads it: read, and nulled with the literal spellings. The last
       * occurrence decides whichever spelling it has. */
      { "tier-escaped-key-is-read", "{\"service\\u005ftier\":\"priority\"}", AI_TIER_PRIORITY,
        "{\"service\\u005ftier\":null      }" },
      { "tier-escaped-after-literal-decides", "{\"service_tier\":\"flex\",\"service\\u005ftier\":\"priority\"}",
        AI_TIER_PRIORITY, "{\"service_tier\":null  ,\"service\\u005ftier\":null      }" },
      { "tier-literal-after-escaped-decides", "{\"service\\u005ftier\":\"priority\",\"service_tier\":\"flex\"}",
        AI_TIER_FLEX, "{\"service\\u005ftier\":null      ,\"service_tier\":null  }" },
      { "tier-escaped-every-byte", "{\"\\u0073\\u0065\\u0072\\u0076\\u0069\\u0063\\u0065\\u005f\\u0074\\u0069\\u0065\\u0072\":\"fast\"}",
        AI_TIER_FAST, "{\"\\u0073\\u0065\\u0072\\u0076\\u0069\\u0063\\u0065\\u005f\\u0074\\u0069\\u0065\\u0072\":null  }" },
      { "tier-escaped-key-nested-is-not-read", "{\"opts\":{\"service\\u005ftier\":\"flex\"}}", AI_TIER_NONE, NULL },
      /* Decoded, it is another key; or it decodes to nothing (not JSON). */
      { "tier-escaped-other-key", "{\"service\\u005ftie\\u0072s\":\"flex\"}", AI_TIER_NONE, NULL },
      { "tier-escaped-key-prefix", "{\"service\\u005ftie\":\"flex\"}", AI_TIER_NONE, NULL },
      { "tier-escaped-bad-hex", "{\"service\\u005gtier\":\"flex\"}", AI_TIER_NONE, NULL },
      { "tier-escaped-cut", "{\"service\\u005\":\"flex\"}", AI_TIER_NONE, NULL },
      { "tier-escaped-lone-surrogate", "{\"service\\ud800tier\":\"flex\"}", AI_TIER_NONE, NULL },
      { "tier-escaped-unknown-letter", "{\"service\\xtier\":\"flex\"}", AI_TIER_NONE, NULL },
      /* The value is read decoded too: "priorit\u0079" names the tier. */
      { "tier-escaped-value-is-read", "{\"service_tier\":\"priorit\\u0079\"}", AI_TIER_PRIORITY,
        "{\"service_tier\":null           }" },
      { "tier-escaped-value-other", "{\"service_tier\":\"flex\\u0021\"}", AI_TIER_NONE, NULL },
      { "tier-escaped-value-not-json", "{\"service_tier\":\"fle\\q\"}", AI_TIER_NONE, NULL },
      { "tier-garbage", "not json", AI_TIER_NONE, NULL },
    };
    size_t vi;
    for (vi = 0; vi < sizeof(st_vecs) / sizeof(st_vecs[0]); vi++) {
      size_t len = strlen(st_vecs[vi].body), off = 99, vlen = 99;
      char *buf = malloc(len);          /* exact size: the sanitizer sees a step outside */
      int got, ok;
      memcpy(buf, st_vecs[vi].body, len);
      got = extract_service_tier(buf, len, &off, &vlen);
      ok = got == st_vecs[vi].want;
      if (got == AI_TIER_NONE) {
        ok = ok && off == 0 && vlen == 0 && !memcmp(buf, st_vecs[vi].body, len);
      } else {
        ok = ok && off + vlen <= len && buf[off] == '"' && buf[off + vlen - 1] == '"';
        /* what the proxy does with a consumed tier */
        ok = ok && json_null_top_key(buf, len, "service_tier", 12) > 0;
        ok = ok && st_vecs[vi].after && strlen(st_vecs[vi].after) == len &&
             !memcmp(buf, st_vecs[vi].after, len);
      }
      g_cases++;
      if (!ok) {
        printf("FAIL %-38s tier=%d (want %d) off=%zu vlen=%zu -> %.*s\n",
               st_vecs[vi].name, got, st_vecs[vi].want, off, vlen, (int)len, buf);
        g_fails++;
      } else {
        printf("ok   %-38s tier=%d\n", st_vecs[vi].name, got);
      }
      free(buf);
    }
    /* Every top-level occurrence is overwritten, and only those. */
    {
      char b[] = "{\"service_tier\":\"flex\",\"service_tier\":\"priority\",\"service_tier\":2,\"x\":[{\"service_tier\":\"fast\"}],\"service\\u005ftier\":\"fast\"}";
      const char *want = "{\"service_tier\":null  ,\"service_tier\":null      ,\"service_tier\":2,\"x\":[{\"service_tier\":\"fast\"}],\"service\\u005ftier\":null  }";
      int n = json_null_top_key(b, strlen(b), "service_tier", 12);
      g_cases++;
      if (n != 3 || strcmp(b, want)) { printf("FAIL null-top-key-every-occurrence n=%d -> %s\n", n, b); g_fails++; }
      else printf("ok   null-top-key-every-occurrence\n");
      g_cases++;
      if (json_null_top_key(NULL, 4, "service_tier", 12) != 0 || json_null_top_key(b, 0, "service_tier", 12) != 0) {
        printf("FAIL null-top-key-empty\n"); g_fails++;
      } else printf("ok   null-top-key-empty\n");
    }
    /* An escaped key spelling reads the same for the jsmn extractor and
     * the walk: "mod\u0065l" is "model" to every parser downstream, so it
     * is the model the allowlist binds to. */
    {
      const char *b = "{\"mod\\u0065l\":\"m1\",\"n\":1}";
      char m1[32] = "", m2[32] = "";
      int r1 = extract_model_field(b, strlen(b), m1, sizeof(m1));
      int r2 = extract_model_field_prefix(b, strlen(b), m2, sizeof(m2));
      g_cases++;
      if (r1 != 0 || strcmp(m1, "m1") || r2 != 0 || strcmp(m2, "m1")) {
        printf("FAIL model-escaped-key r1=%d m1=%s r2=%d m2=%s\n", r1, m1, r2, m2); g_fails++;
      } else printf("ok   model-escaped-key\n");
    }
    /* An escaped model VALUE reads decoded through both extractors too: the
     * model the allowlist binds to is the one the engine will serve, and the
     * one the routing extractor read. */
    {
      const char *b = "{\"model\":\"m\\u0031\\u002dx\",\"n\":1}";
      char m1[32] = "", m2[32] = "";
      int r1 = extract_model_field(b, strlen(b), m1, sizeof(m1));
      int r2 = extract_model_field_prefix(b, strlen(b), m2, sizeof(m2));
      g_cases++;
      if (r1 != 0 || strcmp(m1, "m1-x") || r2 != 0 || strcmp(m2, "m1-x")) {
        printf("FAIL model-escaped-value r1=%d m1=%s r2=%d m2=%s\n", r1, m1, r2, m2); g_fails++;
      } else printf("ok   model-escaped-value\n");
    }
    /* The user id (session affinity) reads decoded: one session for both spellings. */
    {
      const char *b1 = "{\"user\":\"alice\"}", *b2 = "{\"user\":\"alic\\u0065\"}";
      char u1[64] = "", u2[64] = "";
      extract_user_id(b1, strlen(b1), u1, sizeof(u1));
      extract_user_id(b2, strlen(b2), u2, sizeof(u2));
      g_cases++;
      if (strcmp(u1, "alice") || strcmp(u2, "alice")) {
        printf("FAIL user-escaped-value u1=%s u2=%s\n", u1, u2); g_fails++;
      } else printf("ok   user-escaped-value\n");
    }
    /* The overwrite refuses what does not fit: nothing is written. */
    {
      char b[] = "0123456789";
      json_null_value(b, 10, 8, 4);     /* runs past the end */
      json_null_value(b, 10, 11, 4);    /* starts past the end */
      json_null_value(b, 10, 2, 3);     /* too short for null */
      json_null_value(NULL, 10, 0, 4);
      g_cases++;
      if (memcmp(b, "0123456789", 10)) { printf("FAIL null-value-bounds -> %s\n", b); g_fails++; }
      else printf("ok   null-value-bounds\n");
      json_null_value(b, 10, 6, 4);     /* the last four bytes: fits exactly */
      g_cases++;
      if (memcmp(b, "012345null", 10)) { printf("FAIL null-value-exact-fit -> %s\n", b); g_fails++; }
      else printf("ok   null-value-exact-fit\n");
    }
    /* A client-supplied engine priority: the top-level key is renamed in
     * place, at the same length, whatever its value (a number, a string, a
     * short one, a negative one); an escaped spelling is renamed too and
     * the bytes of its escape become underscores; a nested one (inside
     * messages or tool arguments) is no engine field and is left as sent;
     * the body keeps its size. */
    {
      static const struct { const char *name, *body, *after; int n; } rn[] = {
        { "prio-number", "{\"model\":\"m\",\"priority\":5}", "{\"model\":\"m\",\"_gw_prio\":5}", 1 },
        { "prio-negative", "{\"priority\":-5,\"model\":\"m\"}", "{\"_gw_prio\":-5,\"model\":\"m\"}", 1 },
        { "prio-string", "{\"priority\":\"high\"}", "{\"_gw_prio\":\"high\"}", 1 },
        { "prio-spaced", "{ \"priority\" : 0 , \"x\":1}", "{ \"_gw_prio\" : 0 , \"x\":1}", 1 },
        { "prio-escaped-key", "{\"priorit\\u0079\":7}", "{\"_gw_prio_____\":7}", 1 },
        { "prio-twice", "{\"priority\":1,\"priority\":2}", "{\"_gw_prio\":1,\"_gw_prio\":2}", 2 },
        { "prio-nested-untouched", "{\"messages\":[{\"priority\":9,\"content\":\"priority\"}],\"tool\":{\"priority\":1}}", NULL, 0 },
        { "prio-in-string-untouched", "{\"content\":\"\\\"priority\\\":3\"}", NULL, 0 },
        { "prio-absent", "{\"model\":\"m\",\"max_tokens\":4}", NULL, 0 },
        { "prio-not-json", "priority", NULL, 0 },
      };
      size_t ri;
      for (ri = 0; ri < sizeof(rn) / sizeof(rn[0]); ri++) {
        size_t len = strlen(rn[ri].body);
        char *buf = malloc(len);          /* exact size: the sanitizer sees a step outside */
        int n, ok;
        memcpy(buf, rn[ri].body, len);
        n = json_rename_top_key(buf, len, "priority", 8, "_gw_prio", 8);
        ok = n == rn[ri].n;
        if (rn[ri].after)
          ok = ok && strlen(rn[ri].after) == len && !memcmp(buf, rn[ri].after, len);
        else
          ok = ok && !memcmp(buf, rn[ri].body, len);
        g_cases++;
        if (!ok) { printf("FAIL %-38s n=%d -> %.*s\n", rn[ri].name, n, (int)len, buf); g_fails++; }
        else printf("ok   %-38s n=%d\n", rn[ri].name, n);
        free(buf);
      }
      /* A name longer than the key, an empty one, no body: nothing is written. */
      {
        char b[] = "{\"priority\":1}";
        g_cases++;
        if (json_rename_top_key(b, strlen(b), "priority", 8, "a_longer_name", 13) != 0 ||
            json_rename_top_key(b, strlen(b), "priority", 8, "", 0) != 0 ||
            json_rename_top_key(NULL, 14, "priority", 8, "_gw_prio", 8) != 0 ||
            json_rename_top_key(b, 0, "priority", 8, "_gw_prio", 8) != 0 ||
            strcmp(b, "{\"priority\":1}")) {
          printf("FAIL prio-rename-bounds -> %s\n", b); g_fails++;
        } else printf("ok   prio-rename-bounds\n");
      }
      /* The tier null and the rename share one walk: both apply to one body. */
      {
        char b[] = "{\"service_tier\":\"flex\",\"priority\":3,\"messages\":[{\"priority\":1}]}";
        const char *want = "{\"service_tier\":null  ,\"_gw_prio\":3,\"messages\":[{\"priority\":1}]}";
        int a = json_null_top_key(b, strlen(b), "service_tier", 12);
        int c = json_rename_top_key(b, strlen(b), "priority", 8, "_gw_prio", 8);
        g_cases++;
        if (a != 1 || c != 1 || strcmp(b, want)) { printf("FAIL prio-with-tier a=%d c=%d -> %s\n", a, c, b); g_fails++; }
        else printf("ok   prio-with-tier\n");
      }
    }
  }

  printf("\n=== results: %d/%d passed ===\n", g_cases - g_fails, g_cases);
  return g_fails ? 1 : 0;
}
