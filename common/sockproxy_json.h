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

/* The token budget applies only to optional prefix/hash inspection. */
#define LLM_JSON_TOKEN_LIMIT_EXCEEDED (-4)
#define LLM_PREFIX_SKIPPED 1

/* Extract the "user" field from an OpenAI-compatible JSON body.
 * Returns 0 on success (found user id in out), -1 on miss.
 */
int extract_user_id(const char *body, size_t len, char *out, size_t cap);

/* Extract the top-level "model" field from an OpenAI-compatible JSON body.
 * Returns 0 on success (found model in out), -1 on miss, or
 * SP_JSON_DUPLICATE_MODEL when more than one decoded model key is present.
 */
int extract_model_field(const char *body, size_t len, char *out, size_t cap);

/* Extract a complete direct top-level "model" string from an incomplete JSON
 * prefix. Returns 0 on success, 1 when more bytes may complete the field, and
 * -1 when a complete root object has no usable model or the value is invalid.
 * Used only to select a model-specific pool before streaming an oversize body. */
int extract_model_field_prefix(const char *body, size_t len,
                               char *out, size_t cap);

/* Extract prompt_tokens / completion_tokens from the last complete OpenAI
 * "usage" object in a response byte window (SSE tail or JSON body tail;
 * the window need not be a complete JSON document).
 * Returns 0 when at least one count was extracted, -1 on miss.
 */
int extract_usage_tokens(const char *buf, size_t len, int *prompt_tokens,
                         int *completion_tokens);

/* The top-level "stream" field of a complete JSON request body: 1 when it is
 * true, 0 when it is anything else or absent, -1 when the body is not a
 * complete JSON object. Read for observation; the relay does not use it.
 */
int json_stream_flag(const char *body, size_t len);

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

/* The body's top-level "service_tier" read as a class hint. With the key
 * more than once, the LAST occurrence is read (what a parser that keeps the
 * last duplicate reads). Key and value are read DECODED, as a parser reads
 * them: "service\u005ftier" is the key and "priorit\u0079" is "priority".
 * Returns AI_TIER_FLEX, AI_TIER_PRIORITY or
 * AI_TIER_FAST when that value is exactly that string, and then sets
 * [*off, *off + *vlen) to it in the body, quotes included. Returns AI_TIER_NONE for any other value, an
 * absent key, or a body that is not a complete JSON object. The AI_TIER_*
 * values are in sockproxy_ai_gw.h, beside the export they are handed to. */
int extract_service_tier(const char *body, size_t len, size_t *off, size_t *vlen);

/* Overwrite a JSON value of at least four bytes in place with null, padded
 * with spaces to the same length: the document keeps its size. */
void json_null_value(char *body, size_t body_len, size_t off, size_t vlen);

/* Overwrite with null, in place and at the same length, the value of EVERY
 * top-level occurrence of key whose value is at least four bytes long.
 * Returns how many were overwritten. Keys are matched decoded: an escaped
 * spelling of key ("service\u005ftier") is key, and is overwritten too. */
int json_null_top_key(char *body, size_t body_len, const char *key, size_t klen);

/* Rename, in place and at the same length, EVERY top-level occurrence of
 * key to `to` (tolen <= klen bytes; the bytes of a longer raw spelling past
 * it become '_'): the document keeps its size and the value stays where it
 * was, under a key no engine reads. Keys are matched decoded, as
 * json_null_top_key matches them; a nested occurrence is left as sent.
 * Returns how many were renamed. */
int json_rename_top_key(char *body, size_t body_len, const char *key, size_t klen,
                        const char *to, size_t tolen);

/* Extract LLM prefix key (model, prompt/messages, optional L2/L3 fields)
 * from the JSON request body.
 *
 * @json_body: Request body string
 * @len:       Length of json_body
 * @prefix_key: Output struct filled on success
 * Returns 0 on success, -1 on parse failure (non-fatal; caller falls back
 * to ordinary routing), LLM_PREFIX_SKIPPED when the optional inspection
 * budget is exhausted, or SP_JSON_DUPLICATE_MODEL for an ambiguous model.
 */
int extract_llm_prefix(const char *json_body, size_t len,
                       llm_prefix_key_t *prefix_key);

/* Reuse metadata already validated by the request's incremental scanner. */
int extract_llm_prefix_scanned(const char *body, size_t len,
                               const sp_json_scan_t *scan, llm_prefix_key_t *key);

/* Compute xxHash-64 cache key from a filled llm_prefix_key_t.
 * Returns 0 if pk is NULL or not valid.
 */
uint64_t compute_prefix_hash(llm_prefix_key_t *pk);

#endif /* __SOCKPROXY_JSON_H__ */
