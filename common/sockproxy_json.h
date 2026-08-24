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
#ifndef __SOCKPROXY_JSON_H__
#define __SOCKPROXY_JSON_H__

#include "sockproxy.h"

/* Extract the "user" field from an OpenAI-compatible JSON body.
 * Returns 0 on success (found user id in out), -1 on miss.
 */
int extract_user_id(const char *body, size_t len, char *out, size_t cap);

/* Extract the top-level "model" field from an OpenAI-compatible JSON body.
 * Returns 0 on success (found model in out), -1 on miss.
 */
int extract_model_field(const char *body, size_t len, char *out, size_t cap);

/* Extract prompt_tokens / completion_tokens from the last complete OpenAI
 * "usage" object in a response byte window (SSE tail or JSON body tail;
 * the window need not be a complete JSON document).
 * Returns 0 when at least one count was extracted, -1 on miss.
 */
int extract_usage_tokens(const char *buf, size_t len, int *prompt_tokens,
                         int *completion_tokens);

/* Force stream_options.include_usage=true into a streaming OpenAI-compatible
 * request body (in place; cap is the buffer capacity behind body) so the
 * final SSE chunk carries the usage object token accounting charges from.
 * Returns 0 when the body was modified (*new_len updated), 1 when no change
 * was needed or possible (*new_len == body_len).
 */
int inject_include_usage(char *body, size_t body_len, size_t cap,
                         size_t *new_len);

/* Estimate the prompt-token count of a request body from the byte extent of
 * its top-level "messages" or "prompt" value (~4 bytes/token). Estimate net
 * for responses whose usage object never materializes. Returns 0 on miss.
 */
int estimate_prompt_tokens(const char *body, size_t len);

/* Read the request's declared completion ceiling: top-level
 * max_completion_tokens (preferred) or max_tokens as a plain non-negative
 * number. Feeds the pre-admission token reservation. Returns 0 when the
 * request declares no usable ceiling.
 */
int extract_max_tokens(const char *body, size_t len);

/* Extract LLM prefix key (model, prompt/messages, optional L2/L3 fields)
 * from the JSON request body.
 *
 * @json_body: Request body string
 * @len:       Length of json_body
 * @prefix_key: Output struct filled on success
 * Returns 0 on success, -1 on parse failure (non-fatal; caller falls back
 * to round-robin selection).
 */
int extract_llm_prefix(const char *json_body, size_t len,
                       llm_prefix_key_t *prefix_key);

/* Compute xxHash-64 cache key from a filled llm_prefix_key_t.
 * Returns 0 if pk is NULL or not valid.
 */
uint64_t compute_prefix_hash(llm_prefix_key_t *pk);

#endif /* __SOCKPROXY_JSON_H__ */
