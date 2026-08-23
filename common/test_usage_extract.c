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
 * Unit tests for extract_usage_tokens — the OpenAI "usage" object extractor
 * feeding AI-gateway token accounting. The input is a response TAIL WINDOW
 * (SSE events with framing, or a JSON body possibly truncated at the front),
 * never a guaranteed-complete JSON document, and the vectors below mirror
 * the live final-chunk shapes captured from llama.cpp, vLLM P/D, SGLang P/D
 * and TensorRT-LLM fleets.
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

  printf("\n=== results: %d/%d passed ===\n", g_cases - g_fails, g_cases);
  return g_fails ? 1 : 0;
}
