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
#include <string.h>
#include <stdarg.h>

#include "log.h"

/* log.c is not linked into this standalone test */
void
log_log(int level, const char *file, int line, const char *fmt, ...)
{
  (void)level; (void)file; (void)line; (void)fmt;
}

#include "sockproxy_json.c"

static int g_fails = 0;
static int g_cases = 0;

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

int
main(void)
{
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

  printf("\n=== results: %d/%d passed ===\n", g_cases - g_fails, g_cases);
  return g_fails ? 1 : 0;
}
