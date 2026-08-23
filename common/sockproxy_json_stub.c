/*
 * Copyright (c) 2022 NetLOX Inc
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

/* sockproxy_json_stub.c — No-op stubs compiled when HAVE_DP_GPU_ROUTING is
 * not set on builds that do not require JSON/LLM prefix extraction.
 */

#include <stddef.h>
#include "uthash.h"
#include "sockproxy_json.h"

int
extract_user_id(const char *body, size_t len, char *out, size_t cap)
{
  (void)body; (void)len; (void)cap;
  if (out) out[0] = '\0';
  return -1;
}

int
extract_llm_prefix(const char *json_body, size_t len,
                   llm_prefix_key_t *prefix_key)
{
  (void)json_body; (void)len; (void)prefix_key;
  return -1;
}

int
inject_include_usage(char *body, size_t body_len, size_t cap, size_t *new_len)
{
  (void)body; (void)cap;
  if (new_len) *new_len = body_len;
  return 1;
}

int
estimate_prompt_tokens(const char *body, size_t len)
{
  (void)body; (void)len;
  return 0;
}

uint64_t
compute_prefix_hash(llm_prefix_key_t *pk)
{
  (void)pk;
  return 0;
}
