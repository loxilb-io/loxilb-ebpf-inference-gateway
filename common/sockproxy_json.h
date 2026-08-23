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
