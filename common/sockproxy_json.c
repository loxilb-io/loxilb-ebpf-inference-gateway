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

/* P0.2 + P1.1: JSON prefix extraction and LLM cache key hashing
 * Extracted from sockproxy.c section 27.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#define XXH_STATIC_LINKING_ONLY
#include "xxhash.h"
#include "uthash.h"
#include "log.h"
#include "sockproxy_internal.h"
#include "sockproxy_json.h"
#include "sockproxy_json_unescape.h"

// ============================================================================
// P0.2: JSON Prefix Extraction Functions
// ============================================================================
// Helper: Compare JSON token with string
static int jsoneq(const char *json, jsmntok_t *tok, const char *s)
{
  if (tok->type == JSMN_STRING && 
      (int)strlen(s) == tok->end - tok->start &&
      strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
    return 0;
  }
  return -1;
}

// Extract string value from token
static int json_extract_string(const char *json, jsmntok_t *tok, 
                                char *out, size_t out_size)
{
  int len = tok->end - tok->start;
  if (len >= (int)out_size) len = out_size - 1;
  if (len > 0) {
    strncpy(out, json + tok->start, len);
    out[len] = '\0';
  }
  return 0;
}

// PHASE 1: Helper functions for content hashing
static int compute_image_content_hash(const char *json_body, jsmntok_t *token,
                                     char *hash_buf, size_t hash_buf_size)
{
  XXH64_state_t *state;
  uint64_t hash;
  
  if (!json_body || !token || !hash_buf || hash_buf_size == 0) {
    return -1;
  }
  
  // Validate token type (should be array or string)
  if (token->type != JSMN_ARRAY && token->type != JSMN_STRING) {
    log_error("compute_image_content_hash: Expected array/string, got type=%d", token->type);
    return -1;
  }
  
  state = XXH64_createState();
  if (!state) {
    log_error("compute_image_content_hash: XXH64_createState() failed");
    return -1;
  }
  
  XXH64_reset(state, 0);
  
  // Hash the image content (URL or base64 data)
  size_t content_len = token->end - token->start;
  XXH64_update(state, json_body + token->start, content_len);
  
  hash = XXH64_digest(state);
  XXH64_freeState(state);
  
  // Convert hash to hex string
  snprintf(hash_buf, hash_buf_size, "%016lx", hash);
  
#ifdef HAVE_PROXY_EXTRA_DEBUG
  log_debug("[IMAGE_HASH] Computed: %s", hash_buf);
#endif
  
  return 0;
}

static int compute_audio_content_hash(const char *json_body, jsmntok_t *token,
                                     char *hash_buf, size_t hash_buf_size)
{
  XXH64_state_t *state;
  uint64_t hash;
  
  if (!json_body || !token || !hash_buf || hash_buf_size == 0) {
    return -1;
  }
  
  state = XXH64_createState();
  if (!state) {
    log_error("compute_audio_content_hash: XXH64_createState() failed");
    return -1;
  }
  
  XXH64_reset(state, 0);
  
  // Hash the audio content
  size_t content_len = token->end - token->start;
  XXH64_update(state, json_body + token->start, content_len);
  
  hash = XXH64_digest(state);
  XXH64_freeState(state);
  
  snprintf(hash_buf, hash_buf_size, "%016lx", hash);
  
#ifdef HAVE_PROXY_EXTRA_DEBUG
  log_debug("[AUDIO_HASH] Computed: %s", hash_buf);
#endif
  
  return 0;
}

static int compute_tools_hash(const char *json_body, jsmntok_t *token,
                             char *hash_buf, size_t hash_buf_size)
{
  XXH64_state_t *state;
  uint64_t hash;
  
  if (!json_body || !token || !hash_buf || hash_buf_size == 0) {
    return -1;
  }
  
  state = XXH64_createState();
  if (!state) {
    log_error("compute_tools_hash: XXH64_createState() failed");
    return -1;
  }
  
  XXH64_reset(state, 0);
  
  // Hash the tool definitions
  size_t content_len = token->end - token->start;
  XXH64_update(state, json_body + token->start, content_len);
  
  hash = XXH64_digest(state);
  XXH64_freeState(state);
  
  snprintf(hash_buf, hash_buf_size, "%016lx", hash);
  
#ifdef HAVE_PROXY_EXTRA_DEBUG
  log_debug("[TOOLS_HASH] Computed: %s", hash_buf);
#endif
  
  return 0;
}

// PHASE 2: Session Context Hash Computation
/**
 * compute_session_context_hash() - Compute hash of summarized session context
 *
 * @json_body: JSON string
 * @token: jsmn token pointing to "session_context" field
 * @hash_buf: Output buffer for hash string
 * @hash_buf_size: Size of output buffer
 *
 * Returns: 0 on success, -1 on error
 *
 * Design: Extracts SHORT session summary and computes hash
 *   - NOT full conversation history (would fragment cache)
 *   - Summarized user profile, task context, preferences
 *   - Pattern: Similar to existing tool schema hash
 *
 * WARNING: Level 2 hashing disperses cache across sessions
 *   - Use ONLY when session stickiness is required
 *   - Expected cache locality: per-user, not global
 */
static int
compute_session_context_hash(const char *json_body, jsmntok_t *token,
                             char *hash_buf, size_t hash_buf_size)
{
  XXH64_state_t *state;
  uint64_t hash;
  
  if (!json_body || !token || !hash_buf || hash_buf_size == 0) {
    return -1;
  }
  
  state = XXH64_createState();
  if (!state) {
    log_error("compute_session_context_hash: XXH64_createState() failed");
    return -1;
  }
  
  XXH64_reset(state, 0);
  
  // Hash the session context summary
  // Expected format: JSON object with user profile, task context
  // Example: {"user_id": "user123", "task": "coding_assistant", "language": "python"}
  size_t ctx_len = token->end - token->start;
  XXH64_update(state, json_body + token->start, ctx_len);
  
  hash = XXH64_digest(state);
  XXH64_freeState(state);
  
  // Convert hash to hex string
  snprintf(hash_buf, hash_buf_size, "%016lx", hash);
  
#ifdef HAVE_PROXY_EXTRA_DEBUG
  log_debug("[SESSION_CTX_HASH] Computed: %s (len=%zu)", hash_buf, ctx_len);
  log_warn("[L2_WARNING] Level 2 hashing enabled - cache will be per-session, not global");
#endif
  
  return 0;
}

/**
 * compute_rag_template_hash() - Compute hash of RAG template/header
 * 
 * @param json_body: JSON body string
 * @param token: jsmn token pointing to rag_template field
 * @param hash_buf: Buffer to store hex hash string
 * @param hash_buf_size: Size of hash_buf
 * @return: 0 on success, -1 on error
 * 
 * Hashes the RAG template/header text that provides context for retrieval.
 * Example: "You are a helpful assistant. Use the following documents to answer:"
 */
static int
compute_rag_template_hash(const char *json_body, jsmntok_t *token,
                         char *hash_buf, size_t hash_buf_size)
{
  XXH64_state_t *state;
  uint64_t hash;
  
  if (!json_body || !token || !hash_buf || hash_buf_size < 17) {
    log_error("[RAG_TEMPLATE_HASH] Invalid parameters");
    return -1;
  }
  
  state = XXH64_createState();
  if (!state) {
    log_error("[RAG_TEMPLATE_HASH] Failed to create XXH64 state");
    return -1;
  }
  
  XXH64_reset(state, 0);
  
  // Hash the RAG template string content
  size_t template_len = token->end - token->start;
  XXH64_update(state, json_body + token->start, template_len);
  
  hash = XXH64_digest(state);
  XXH64_freeState(state);
  
  // Convert hash to hex string
  snprintf(hash_buf, hash_buf_size, "%016lx", hash);
  
#ifdef HAVE_PROXY_EXTRA_DEBUG
  log_debug("[RAG_TEMPLATE_HASH] Computed: %s (len=%zu)", hash_buf, template_len);
#endif
  
  return 0;
}

/**
 * compute_rag_doc_ids_hash() - Compute hash of SORTED document ID list
 * 
 * @param json_body: JSON body string
 * @param token: jsmn token pointing to document_ids array
 * @param hash_buf: Buffer to store hex hash string
 * @param hash_buf_size: Size of hash_buf
 * @return: 0 on success, -1 on error
 * 
 * Hashes document IDs in sorted order for consistency. This allows requests
 * with the same document set (regardless of order) to hit the same cache.
 * Example: ["doc_456", "doc_123"] == ["doc_123", "doc_456"] (same hash)
 */
static int
compute_rag_doc_ids_hash(const char *json_body, jsmntok_t *token,
                        char *hash_buf, size_t hash_buf_size)
{
  XXH64_state_t *state;
  uint64_t hash;
  int i, j;
  
  if (!json_body || !token || !hash_buf || hash_buf_size < 17) {
    log_error("[RAG_DOC_IDS_HASH] Invalid parameters");
    return -1;
  }
  
  if (token->type != JSMN_ARRAY) {
    log_error("[RAG_DOC_IDS_HASH] document_ids must be an array");
    return -1;
  }
  
  state = XXH64_createState();
  if (!state) {
    log_error("[RAG_DOC_IDS_HASH] Failed to create XXH64 state");
    return -1;
  }
  
  XXH64_reset(state, 0);
  
  // Collect document IDs into a temporary array
  #define MAX_DOC_IDS 256
  #define MAX_DOC_ID_LEN 128
  static char doc_ids[MAX_DOC_IDS][MAX_DOC_ID_LEN];
  int num_docs = 0;
  
  // Extract all document IDs from array
  for (i = 0; i < token->size && num_docs < MAX_DOC_IDS; i++) {
    jsmntok_t *doc_token = token + 1 + i;
    if (doc_token->type == JSMN_STRING) {
      size_t doc_len = doc_token->end - doc_token->start;
      if (doc_len < MAX_DOC_ID_LEN) {
        memcpy(doc_ids[num_docs], json_body + doc_token->start, doc_len);
        doc_ids[num_docs][doc_len] = '\0';
        num_docs++;
      }
    }
  }
  
  // Sort document IDs alphabetically for consistent hashing
  // Simple bubble sort (sufficient for typical RAG workloads with <100 docs)
  for (i = 0; i < num_docs - 1; i++) {
    for (j = 0; j < num_docs - i - 1; j++) {
      if (strcmp(doc_ids[j], doc_ids[j+1]) > 0) {
        char temp[MAX_DOC_ID_LEN];
        strcpy(temp, doc_ids[j]);
        strcpy(doc_ids[j], doc_ids[j+1]);
        strcpy(doc_ids[j+1], temp);
      }
    }
  }
  
  // Hash sorted document IDs
  for (i = 0; i < num_docs; i++) {
    XXH64_update(state, doc_ids[i], strlen(doc_ids[i]));
  }
  
  hash = XXH64_digest(state);
  XXH64_freeState(state);
  
  // Convert hash to hex string
  snprintf(hash_buf, hash_buf_size, "%016lx", hash);
  
#ifdef HAVE_PROXY_EXTRA_DEBUG
  log_debug("[RAG_DOC_IDS_HASH] Computed: %s (num_docs=%d)", hash_buf, num_docs);
  log_warn("[L3_WARNING] Level 3 hashing enabled - cache will be per-RAG-context");
#endif
  
  return 0;
}

/*
 * jsmn_subtree_count - count all tokens in the subtree rooted at tokens[idx].
 *
 * In jsmn, tokens[idx].size is the number of DIRECT children (key-value pairs
 * for OBJECT, elements for ARRAY), NOT the total number of tokens in the
 * subtree.  This helper walks the subtree recursively to compute the exact
 * count, which is needed to correctly skip over a nested value when iterating
 * top-level keys of an outer object.
 */
static int
jsmn_subtree_count(jsmntok_t *tokens, int idx, int total)
{
  int count = 1; /* the token itself */
  int j;

  if (idx >= total)
    return 0;

  if (tokens[idx].type == JSMN_ARRAY) {
    for (j = 0; j < tokens[idx].size; j++)
      count += jsmn_subtree_count(tokens, idx + count, total);
  } else if (tokens[idx].type == JSMN_OBJECT) {
    for (j = 0; j < tokens[idx].size; j++) {
      count += jsmn_subtree_count(tokens, idx + count, total); /* key   */
      count += jsmn_subtree_count(tokens, idx + count, total); /* value */
    }
  }
  /* STRING and PRIMITIVE: no sub-tokens, count stays 1 */
  return count;
}

// P/D Session stickiness: Extract "user" field from OpenAI-compatible JSON body.
// Iterates ONLY the top-level key-value pairs of the outer object so that
// nested "user" values (e.g. messages[].role == "user") are never mistaken for
// the top-level "user" field.  Returns 0 on success, -1 on miss.
int
extract_user_id(const char *body, size_t len, char *out, size_t cap)
{
  jsmn_parser p;
  jsmntok_t tokens[64];
  int r, i, pair;

  if (!body || len == 0 || !out || cap == 0) return -1;

  jsmn_init(&p);
  r = jsmn_parse(&p, body, len, tokens, 64);
  if (r < 2 || tokens[0].type != JSMN_OBJECT) return -1;

  /* Iterate only the direct key-value pairs of the top-level object.
   * tokens[0].size == number of key-value pairs at the top level. */
  i = 1;
  for (pair = 0; pair < tokens[0].size && i + 1 < r; pair++) {
    if (tokens[i].type == JSMN_STRING &&
        jsoneq(body, &tokens[i], "user") == 0 &&
        tokens[i + 1].type == JSMN_STRING) {
      json_extract_string(body, &tokens[i + 1], out, cap);
      return (out[0] != '\0') ? 0 : -1;
    }
    /* Skip the key token (always 1) then skip the entire value subtree. */
    i++;
    i += jsmn_subtree_count(tokens, i, r);
  }
  return -1;
}

// AI Gateway allowed_models: extract the top-level "model" field from an
// OpenAI-compatible JSON body. Same top-level-only iteration as
// extract_user_id so nested "model" strings (e.g. inside messages content)
// are never matched. The token pool must fit the WHOLE body — jsmn fails
// outright rather than partially when it runs out — so it is sized like
// extract_llm_prefix's, not extract_user_id's 64.
int
extract_model_field(const char *body, size_t len, char *out, size_t cap)
{
  jsmn_parser p;
  jsmntok_t tokens[2048];
  int r, i, pair;

  if (!body || len == 0 || !out || cap == 0) return -1;

  jsmn_init(&p);
  r = jsmn_parse(&p, body, len, tokens, 2048);
  if (r < 2 || tokens[0].type != JSMN_OBJECT) return -1;

  i = 1;
  for (pair = 0; pair < tokens[0].size && i + 1 < r; pair++) {
    if (tokens[i].type == JSMN_STRING &&
        jsoneq(body, &tokens[i], "model") == 0 &&
        tokens[i + 1].type == JSMN_STRING) {
      json_extract_string(body, &tokens[i + 1], out, cap);
      return (out[0] != '\0') ? 0 : -1;
    }
    /* Skip the key token (always 1) then skip the entire value subtree. */
    i++;
    i += jsmn_subtree_count(tokens, i, r);
  }
  return -1;
}

// AI Gateway token accounting: pull prompt_tokens / completion_tokens out of
// the OpenAI "usage" object in a response byte window. The window is NOT a
// complete JSON document — it is the tail of a response stream (SSE events
// with their framing, or a JSON body possibly truncated at the front) — so
// this scans backwards for the LAST `"usage"` key whose value is a complete
// object and jsmn-parses ONLY that object. Model-generated text can never
// spoof the key: inside a JSON string value every quote is escaped, so the
// raw byte sequence "usage" with unescaped quotes cannot occur within
// content deltas. Engines that put "usage":null on every content chunk
// (SGLang) fail the value-must-be-an-object check and are skipped.
// Counts inside nested detail objects (prompt_tokens_details.cached_tokens)
// are never matched: only the usage object's DIRECT pairs are read.
// Returns 0 when at least one count was extracted, -1 otherwise.
int
extract_usage_tokens(const char *buf, size_t len, int *prompt_tokens,
                     int *completion_tokens)
{
  static const char key[] = "\"usage\"";
  const size_t klen = sizeof(key) - 1;
  size_t pos;
  int failed_candidates = 0;

  if (!prompt_tokens || !completion_tokens)
    return -1;
  *prompt_tokens = 0;
  *completion_tokens = 0;
  if (!buf || len < klen + 4)
    return -1;

  pos = len - klen;
  for (;;) {
    if (memcmp(buf + pos, key, klen) == 0 &&
        (pos == 0 || buf[pos - 1] != '\\')) {
      const char *p = buf + pos + klen;
      const char *end = buf + len;
      while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n'))
        p++;
      if (p < end && *p == ':') {
        p++;
        while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n'))
          p++;
      } else {
        p = end;  /* not a key:value shape — disqualify this candidate */
      }
      if (p < end && *p == '{') {
        /* Balanced-brace scan (string- and escape-aware) to find the end of
         * the usage object; an object still missing its closing brace in
         * this window fails here and a later segment retries. */
        const char *q = p;
        int depth = 0, instr = 0, esc = 0, complete = 0;
        for (; q < end; q++) {
          char ch = *q;
          if (esc) { esc = 0; continue; }
          if (ch == '\\') { esc = 1; continue; }
          if (instr) { if (ch == '"') instr = 0; continue; }
          if (ch == '"') { instr = 1; continue; }
          if (ch == '{') depth++;
          else if (ch == '}') {
            depth--;
            if (depth == 0) { q++; complete = 1; break; }
          }
        }
        if (complete) {
          jsmn_parser jp;
          jsmntok_t toks[64];
          int r, ti, pair, got = 0;
          jsmn_init(&jp);
          r = jsmn_parse(&jp, p, (size_t)(q - p), toks, 64);
          if (r >= 3 && toks[0].type == JSMN_OBJECT) {
            ti = 1;
            for (pair = 0; pair < toks[0].size && ti + 1 < r; pair++) {
              if (toks[ti].type == JSMN_STRING &&
                  toks[ti + 1].type == JSMN_PRIMITIVE) {
                long v;
                if (jsoneq(p, &toks[ti], "prompt_tokens") == 0) {
                  v = strtol(p + toks[ti + 1].start, NULL, 10);
                  if (v < 0) v = 0;
                  if (v > 100000000L) v = 100000000L;
                  *prompt_tokens = (int)v;
                  got = 1;
                } else if (jsoneq(p, &toks[ti], "completion_tokens") == 0) {
                  v = strtol(p + toks[ti + 1].start, NULL, 10);
                  if (v < 0) v = 0;
                  if (v > 100000000L) v = 100000000L;
                  *completion_tokens = (int)v;
                  got = 1;
                }
              }
              ti++;
              ti += jsmn_subtree_count(toks, ti, r);
            }
          }
          if (got)
            return 0;
        }
      }
      /* Matched "usage" but no extractable object — walk further back, but
       * give up after a few dead candidates (null-usage chunks etc.). */
      if (++failed_candidates > 4)
        return -1;
    }
    if (pos == 0)
      break;
    pos--;
  }
  return -1;
}

/* Delimit one JSON value starting at vs: objects/arrays by string-aware
 * bracket matching, strings by escape-aware quote scan, primitives by
 * delimiter scan. Returns one past the value's last byte, or NULL when the
 * value does not complete before end. */
static const char *
json_value_extent(const char *vs, const char *end)
{
  if (vs >= end)
    return NULL;
  if (*vs == '{' || *vs == '[') {
    char open = *vs, close = (open == '{') ? '}' : ']';
    int depth = 0, instr = 0, esc = 0;
    const char *q;
    for (q = vs; q < end; q++) {
      char ch = *q;
      if (esc) { esc = 0; continue; }
      if (ch == '\\') { esc = 1; continue; }
      if (instr) { if (ch == '"') instr = 0; continue; }
      if (ch == '"') { instr = 1; continue; }
      if (ch == open) depth++;
      else if (ch == close) { depth--; if (depth == 0) return q + 1; }
    }
    return NULL;
  }
  if (*vs == '"') {
    int esc = 0;
    const char *q;
    for (q = vs + 1; q < end; q++) {
      if (esc) { esc = 0; continue; }
      if (*q == '\\') { esc = 1; continue; }
      if (*q == '"') return q + 1;
    }
    return NULL;
  }
  {
    const char *q = vs;
    while (q < end && *q != ',' && *q != '}' && *q != ']' &&
           *q != ' ' && *q != '\t' && *q != '\r' && *q != '\n')
      q++;
    return q;
  }
}

/* Locate the value of a DIRECT (depth-1) key of a JSON object with a single
 * string- and escape-aware depth walk. No token pool: unlike the jsmn-based
 * extractors above this handles bodies of any size, and like them it can
 * never be spoofed by key-shaped text inside string values (quotes there
 * are escaped) or inside nested objects (depth != 1).
 * Returns 0 with [*val_start, *val_end) set; -1 when the key is absent
 * (*root_close then points at the object's closing brace); -2 when the
 * input is not a complete JSON object. */
static int
json_top_find(const char *body, size_t len, const char *key, size_t klen,
              const char **val_start, const char **val_end,
              const char **root_close)
{
  const char *p = body, *end = body + len;
  const char *str_start = NULL;
  int depth = 0, instr = 0, esc = 0, expect_value = 0, key_matched = 0;

  if (val_start) *val_start = NULL;
  if (val_end) *val_end = NULL;
  if (root_close) *root_close = NULL;
  if (!body || len == 0)
    return -2;

  while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n'))
    p++;
  if (p >= end || *p != '{')
    return -2;

  for (; p < end; p++) {
    char c = *p;
    if (instr) {
      if (esc) { esc = 0; continue; }
      if (c == '\\') { esc = 1; continue; }
      if (c == '"') {
        instr = 0;
        if (depth == 1 && !expect_value) {
          key_matched = ((size_t)(p - str_start) == klen &&
                         memcmp(str_start, key, klen) == 0);
        }
      }
      continue;
    }
    switch (c) {
    case '"':
      instr = 1;
      esc = 0;
      str_start = p + 1;
      break;
    case ':':
      if (depth == 1 && key_matched) {
        const char *vs = p + 1, *ve;
        while (vs < end &&
               (*vs == ' ' || *vs == '\t' || *vs == '\r' || *vs == '\n'))
          vs++;
        ve = json_value_extent(vs, end);
        if (!ve)
          return -2;
        if (val_start) *val_start = vs;
        if (val_end) *val_end = ve;
        return 0;
      }
      if (depth == 1)
        expect_value = 1;
      break;
    case ',':
      if (depth == 1) {
        expect_value = 0;
        key_matched = 0;
      }
      break;
    case '{':
    case '[':
      depth++;
      break;
    case '}':
    case ']':
      depth--;
      if (depth == 0) {
        if (root_close) *root_close = p;
        return -1;
      }
      break;
    default:
      break;
    }
  }
  return -2;
}

/* Splice ins_len bytes into body at offset pos. Caller has verified
 * body_len + ins_len <= cap. */
static void
json_splice_in(char *body, size_t body_len, size_t pos,
               const char *ins, size_t ins_len)
{
  memmove(body + pos + ins_len, body + pos, body_len - pos);
  memcpy(body + pos, ins, ins_len);
}

// AI Gateway token accounting: force stream_options.include_usage=true into
// a streaming OpenAI-compatible request body so the backend's final SSE
// chunk carries the usage object the response-path extractor charges from.
// A client that omits the flag would otherwise stream tokens invisible to
// the per-tenant quota. Non-streaming requests are left untouched — their
// responses carry usage unconditionally.
// Rewrites in place (cap is the buffer capacity behind body). Returns 0 when
// the body was modified (*new_len updated), 1 when no change was needed or
// the body could not be safely rewritten (*new_len == body_len).
int
inject_include_usage(char *body, size_t body_len, size_t cap, size_t *new_len)
{
  static const char frag_obj[] = ",\"stream_options\":{\"include_usage\":true}";
  static const char frag_field[] = "\"include_usage\":true";
  static const char frag_value[] = "{\"include_usage\":true}";
  const char *vs, *ve, *root_close;
  int rc;

  if (new_len)
    *new_len = body_len;
  if (!body || body_len == 0 || !new_len)
    return 1;

  /* Streaming requests only. */
  rc = json_top_find(body, body_len, "stream", 6, &vs, &ve, &root_close);
  if (rc != 0 || (size_t)(ve - vs) != 4 || memcmp(vs, "true", 4) != 0)
    return 1;

  rc = json_top_find(body, body_len, "stream_options", 14,
                     &vs, &ve, &root_close);
  if (rc == -2)
    return 1;

  if (rc == -1) {
    /* No stream_options — splice a full object before the root's closing
     * brace ("stream" exists, so the object is non-empty and the leading
     * comma is always right). */
    size_t flen = sizeof(frag_obj) - 1;
    if (!root_close || body_len + flen > cap)
      return 1;
    json_splice_in(body, body_len, (size_t)(root_close - body),
                   frag_obj, flen);
    *new_len = body_len + flen;
    return 0;
  }

  if (*vs == '{') {
    /* stream_options is an object — find its direct include_usage. */
    const char *ivs, *ive, *iclose;
    size_t so_len = (size_t)(ve - vs);
    rc = json_top_find(vs, so_len, "include_usage", 13, &ivs, &ive, &iclose);
    if (rc == -2)
      return 1;
    if (rc == 0) {
      if ((size_t)(ive - ivs) == 4 && memcmp(ivs, "true", 4) == 0)
        return 1;                       /* already on — nothing to do */
      /* Present but not true (false/null/junk) — overwrite the value. */
      {
        size_t old_vlen = (size_t)(ive - ivs);
        size_t pos = (size_t)(ivs - body);
        if (body_len - old_vlen + 4 > cap)
          return 1;
        memmove(body + pos + 4, body + pos + old_vlen,
                body_len - pos - old_vlen);
        memcpy(body + pos, "true", 4);
        *new_len = body_len - old_vlen + 4;
      }
      return 0;
    }
    /* Object without include_usage — splice the field in after its '{',
     * with a trailing comma when the object already has members. */
    {
      const char *q = vs + 1;
      size_t flen = sizeof(frag_field) - 1;
      char frag[sizeof(frag_field) + 1];
      int empty;
      while (q < ve && (*q == ' ' || *q == '\t' || *q == '\r' || *q == '\n'))
        q++;
      empty = (q < ve && *q == '}');
      memcpy(frag, frag_field, flen);
      if (!empty)
        frag[flen++] = ',';
      if (body_len + flen > cap)
        return 1;
      json_splice_in(body, body_len, (size_t)(vs + 1 - body), frag, flen);
      *new_len = body_len + flen;
      return 0;
    }
  }

  /* stream_options present but not an object (null, string, number) —
   * replace the whole value with an enabling object. */
  {
    size_t old_vlen = (size_t)(ve - vs);
    size_t vlen = sizeof(frag_value) - 1;
    size_t pos = (size_t)(vs - body);
    if (body_len - old_vlen + vlen > cap)
      return 1;
    memmove(body + pos + vlen, body + pos + old_vlen,
            body_len - pos - old_vlen);
    memcpy(body + pos, frag_value, vlen);
    *new_len = body_len - old_vlen + vlen;
    return 0;
  }
}

// AI Gateway token accounting, estimate net: size the request's prompt in
// tokens from the byte extent of its top-level "messages" (chat) or
// "prompt" (completions) value, at the ~4-bytes-per-token English-text
// convention. Only charged — flagged as estimated — when the response's
// usage object never materializes; the JSON scaffolding inside a messages
// array makes this a mild overestimate, which is the right bias for a
// quota backstop. Returns 0 when neither field is found.
int
estimate_prompt_tokens(const char *body, size_t len)
{
  const char *vs, *ve;
  long est;

  if (json_top_find(body, len, "messages", 8, &vs, &ve, NULL) != 0 &&
      json_top_find(body, len, "prompt", 6, &vs, &ve, NULL) != 0)
    return 0;
  est = (long)(ve - vs) / 4;
  if (est < 0) est = 0;
  if (est > 100000000L) est = 100000000L;
  return (int)est;
}

#ifdef HAVE_LLM_SYSTEM_PROMPT_HASH
/* User-prefix affinity fallback: chat bodies with NO system message used to
 * return -1 here, so every such request was sprayed (per-request hash) and
 * repeats always landed cold. When no system role exists, hash a BOUNDED
 * prefix of the FIRST user message instead. The bound matters: later turns
 * of a conversation diverge, but they share their opening, so hashing only
 * the first N bytes keeps turn N co-located with turn 1.
 * Env LLB_LLM_USER_PREFIX_FALLBACK_LEN overrides; 0 disables (restores the
 * spray behavior). System-keyed traffic is byte-for-byte unaffected. */
#define LLM_USER_PREFIX_FALLBACK_DEFAULT 256
static int
llm_user_prefix_fallback_len(void)
{
  static int len = -1;
  if (len < 0) {
    const char *env = getenv("LLB_LLM_USER_PREFIX_FALLBACK_LEN");
    len = env ? atoi(env) : LLM_USER_PREFIX_FALLBACK_DEFAULT;
    if (len < 0) len = 0;
    if (len >= MAX_PREFIX_LEN) len = MAX_PREFIX_LEN - 1;
  }
  return len;
}
#endif

// Main extraction function for LLM prefix (PHASE 1 ENHANCED)
int extract_llm_prefix(const char *json_body, size_t len,
                       llm_prefix_key_t *prefix_key)
{
  jsmn_parser parser;
  jsmntok_t tokens[2048];  // Increased from 512 to handle large system prompts
  int r, i;
#ifdef HAVE_LLM_SYSTEM_PROMPT_HASH
  char first_user[MAX_PREFIX_LEN] = {0};
  int has_first_user = 0;
#endif

  memset(prefix_key, 0, sizeof(*prefix_key));
  prefix_key->level = 1;  // Default: L1 routing
  prefix_key->flags = 0;  // No optional fields initially
  
  
  jsmn_init(&parser);
  r = jsmn_parse(&parser, json_body, len, tokens, 2048);
  
  if (r < 0) {
    // CRITICAL FIX: Don't fail the connection on JSON parse errors
    // Just log and continue without prefix extraction (round-robin fallback)
    log_debug("[JSON_PARSE_ERROR] JSMN parse failed with error %d, len=%zu, fallback to round-robin", r, len);
    log_debug("[JSON_PREVIEW] First 100 bytes: %.100s", json_body);
    return -1;  // Non-fatal: connection continues without prefix routing
  }
  
  if (r < 1 || tokens[0].type != JSMN_OBJECT) {
    log_debug("[JSON_INVALID] Parse succeeded but not a JSON object (r=%d, type=%d)", 
              r, r > 0 ? tokens[0].type : -1);
    return -1;  // Non-fatal
  }
  
  // FIRST PASS: Extract model and lora_adapter (top-level fields)
  for (i = 1; i < r; ) {
    if (tokens[i].type != JSMN_STRING) {
      i++;
      continue;
    }
    
    if (jsoneq(json_body, &tokens[i], "model") == 0) {
      json_extract_string(json_body, &tokens[i+1], 
                         prefix_key->model, sizeof(prefix_key->model));
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("P0.2 DEBUG: Extracted model='%s'", prefix_key->model);
#endif
      i += 2;
      continue;
    }
    else if (jsoneq(json_body, &tokens[i], "lora_adapter") == 0) {
      json_extract_string(json_body, &tokens[i+1], 
                         prefix_key->lora_adapter, sizeof(prefix_key->lora_adapter));
      if (prefix_key->lora_adapter[0] != '\0') {
        prefix_key->flags |= PREFIX_HAS_LORA;
      }
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("[EXTRACT_L1] Found lora_adapter: '%s'", prefix_key->lora_adapter);
#endif
      i += 2;
      continue;
    }
    else if (jsoneq(json_body, &tokens[i], "cache_salt") == 0) {
      json_extract_string(json_body, &tokens[i+1],
                         prefix_key->cache_salt, sizeof(prefix_key->cache_salt));
      if (prefix_key->cache_salt[0] != '\0') {
        prefix_key->flags |= PREFIX_HAS_CACHE_SALT;
      }
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("[EXTRACT_L1] Found cache_salt: '%s'", prefix_key->cache_salt);
#endif
      i += 2;
      continue;
    }
    else if (jsoneq(json_body, &tokens[i], "images") == 0) {
      // Compute hash of image content/URLs
      if (compute_image_content_hash(json_body, &tokens[i+1],
                                     prefix_key->image_hash,
                                     sizeof(prefix_key->image_hash)) == 0) {
        prefix_key->flags |= PREFIX_HAS_IMAGE;
#ifdef HAVE_PROXY_EXTRA_DEBUG
        log_debug("[EXTRACT_L1] Computed image_hash: '%s'", prefix_key->image_hash);
#endif
      }
      i += 2;
      continue;
    }
    else if (jsoneq(json_body, &tokens[i], "audio") == 0) {
      // Compute hash of audio content
      if (compute_audio_content_hash(json_body, &tokens[i+1],
                                     prefix_key->audio_hash,
                                     sizeof(prefix_key->audio_hash)) == 0) {
        prefix_key->flags |= PREFIX_HAS_AUDIO;
#ifdef HAVE_PROXY_EXTRA_DEBUG
        log_debug("[EXTRACT_L1] Computed audio_hash: '%s'", prefix_key->audio_hash);
#endif
      }
      i += 2;
      continue;
    }
    else if (jsoneq(json_body, &tokens[i], "tools") == 0) {
      // Compute hash of tool definitions
      if (compute_tools_hash(json_body, &tokens[i+1],
                            prefix_key->tool_schemas_hash,
                            sizeof(prefix_key->tool_schemas_hash)) == 0) {
        prefix_key->flags |= PREFIX_HAS_TOOL_SCHEMAS;
#ifdef HAVE_PROXY_EXTRA_DEBUG
        log_debug("[EXTRACT_L1] Computed tool_schemas_hash: '%s'", prefix_key->tool_schemas_hash);
#endif
      }
      i += 2;
      continue;
    }
    else if (jsoneq(json_body, &tokens[i], "session_context") == 0) {
      // PHASE 2: Extract session context summary
      // This should be a SHORT summary of conversation history (not full history)
      if (compute_session_context_hash(json_body, &tokens[i+1],
                                       prefix_key->session_context_hash,
                                       sizeof(prefix_key->session_context_hash)) == 0) {
        prefix_key->flags |= PREFIX_HAS_SESSION_CTX;
        prefix_key->level = 2;  // Upgrade to L2 hashing
#ifdef HAVE_PROXY_EXTRA_DEBUG
        log_debug("[EXTRACT_L2] Computed session_context_hash: '%s'",
                  prefix_key->session_context_hash);
#endif
      }
      i += 2;
      continue;
    }
    else if (jsoneq(json_body, &tokens[i], "rag_context") == 0) {
      // PHASE 3: RAG context with template and document IDs (L3 routing)
      jsmntok_t *rag_obj = &tokens[i+1];
      if (rag_obj->type == JSMN_OBJECT) {
        // Search for rag_template and document_ids within rag_context object
        int rag_items = rag_obj->size;
        int j, rag_start = i + 2;
        for (j = 0; j < rag_items * 2; j += 2) {
          jsmntok_t *rag_key = &tokens[rag_start + j];
          jsmntok_t *rag_val = &tokens[rag_start + j + 1];
          
          if (jsoneq(json_body, rag_key, "rag_template") == 0) {
            if (compute_rag_template_hash(json_body, rag_val,
                                         prefix_key->rag_template_hash,
                                         sizeof(prefix_key->rag_template_hash)) == 0) {
              prefix_key->flags |= PREFIX_HAS_RAG_TEMPLATE;
#ifdef HAVE_PROXY_EXTRA_DEBUG
              log_debug("[EXTRACT_L3] Found rag_template: '%s'", prefix_key->rag_template_hash);
#endif
            }
          }
          else if (jsoneq(json_body, rag_key, "document_ids") == 0) {
            if (compute_rag_doc_ids_hash(json_body, rag_val,
                                        prefix_key->rag_doc_ids_hash,
                                        sizeof(prefix_key->rag_doc_ids_hash)) == 0) {
              prefix_key->flags |= PREFIX_HAS_RAG_DOC_IDS;
#ifdef HAVE_PROXY_EXTRA_DEBUG
              log_debug("[EXTRACT_L3] Found document_ids: '%s'", prefix_key->rag_doc_ids_hash);
#endif
            }
          }
        }
        
        // If both RAG fields present, upgrade to L3
        if ((prefix_key->flags & PREFIX_HAS_RAG_TEMPLATE) && 
            (prefix_key->flags & PREFIX_HAS_RAG_DOC_IDS)) {
          prefix_key->level = 3;  // Upgrade to L3 hashing
#ifdef HAVE_PROXY_EXTRA_DEBUG
          log_debug("[EXTRACT_L3] Both RAG fields present, upgraded to L3");
#endif
        }
      }
      i += 2;
      continue;
    }
    else {
      i++;
    }
  }
  
  // SECOND PASS: Extract prompt field OR messages array
  for (i = 1; i < r; ) {
    if (tokens[i].type != JSMN_STRING) {
      i++;
      continue;
    }
    
    // Check for direct "prompt" field (used in /v1/completions endpoint)
    if (jsoneq(json_body, &tokens[i], "prompt") == 0) {
      i++;  // Move to prompt value
      if (tokens[i].type == JSMN_STRING) {
        // Extract prompt text for prefix hashing.
        // DECODE the JSON escapes while copying (see
        // sockproxy_json_unescape.h). The raw strncpy that used to live here
        // fed still-escaped bytes ("line1\\nline2") to the Tier-1.5 tokenizer
        // while the publisher/vLLM hash the DECODED text — so any prompt with
        // an escape (every real coding-assistant prompt) silently never
        // matched. The helper also guarantees the MAX_PREFIX_LEN truncation
        // never ends mid-escape or mid-UTF-8, keeping the truncated prefix a
        // byte-exact prefix of the full decoded prompt (what block-hash
        // prefix routing needs). Pass the FULL raw span — the copy bounds
        // itself by the destination capacity.
        kv_json_unescape_copy(json_body + tokens[i].start,
                              (size_t)(tokens[i].end - tokens[i].start),
                              prefix_key->prefix, sizeof(prefix_key->prefix));
        prefix_key->valid = 1;
        
#ifdef HAVE_PROXY_EXTRA_DEBUG
        log_debug("P0.2 DEBUG: Extracted prompt (first 200 chars): %.200s", prefix_key->prefix);
#endif
        return 0;  // Success - found prompt
      }
      i++;
      continue;
    }
    
    if (jsoneq(json_body, &tokens[i], "messages") == 0) {
      // Found messages array - extract first user message
      i++;  // Move to messages array token
      if (tokens[i].type != JSMN_ARRAY) {
        continue;
      }
      
      int array_size = tokens[i].size;
      int j = i + 1;  // First element in array
      
      // Iterate through messages array
      for (int msg_idx = 0; msg_idx < array_size; msg_idx++) {
        if (tokens[j].type != JSMN_OBJECT) {
          j++;
          continue;
        }
        
        int obj_size = tokens[j].size;
        j++;  // Move into object
        
        char role[32] = {0};
        char content[MAX_PREFIX_LEN] = {0};
        int has_role = 0;
        int has_content = 0;
        
        // Parse message object fields
        for (int k = 0; k < obj_size; k++) {
          if (jsoneq(json_body, &tokens[j], "role") == 0) {
            json_extract_string(json_body, &tokens[j+1], role, sizeof(role));
            has_role = 1;
            j += 2;
          }
          else if (jsoneq(json_body, &tokens[j], "content") == 0) {
            json_extract_string(json_body, &tokens[j+1], content, sizeof(content));
            has_content = 1;
            j += 2;
          }
          else {
            // Skip unknown field
            j += 2;
          }
        }
        
#ifdef HAVE_LLM_SYSTEM_PROMPT_HASH
        // Check if this is a system message (what vLLM actually caches!)
        if (has_role && has_content && strcmp(role, "system") == 0) {
          // Found system message - extract for prefix hashing
          strncpy(prefix_key->prefix, content, sizeof(prefix_key->prefix) - 1);
          prefix_key->prefix[sizeof(prefix_key->prefix) - 1] = '\0';
          prefix_key->valid = 1;
          
          // Debug: Log full prefix hash input
#ifdef HAVE_PROXY_EXTRA_DEBUG
          log_debug("P0.2 DEBUG: System prompt for hashing (first 200 chars): %.200s", prefix_key->prefix);
#endif
          
          return 0;  // Success - found system message for cache alignment
        }
        // No system role seen so far — remember the FIRST user message as the
        // bounded fallback hash source (used only if the full scan finds no
        // system message; see the fallback below the scan loop).
        if (!has_first_user && has_role && has_content &&
            strcmp(role, "user") == 0 && content[0] != '\0') {
          strncpy(first_user, content, sizeof(first_user) - 1);
          has_first_user = 1;
        }
#else
        // Check if this is a user message (per-query routing)
        if (has_role && has_content && strcmp(role, "user") == 0) {
          // Found first user message - extract prefix
          strncpy(prefix_key->prefix, content, sizeof(prefix_key->prefix) - 1);
          prefix_key->prefix[sizeof(prefix_key->prefix) - 1] = '\0';
          prefix_key->valid = 1;
          
          
          return 0;  // Success - found first user message
        }
#endif
      }
      
      // Finished parsing messages array
      i = j;  // Continue from where messages parsing ended
      continue;
    }
    else {
      // Skip unknown top-level field (key + value)
      i += 2;
      continue;
    }
  }
  
  if (!prefix_key->valid) {
#ifdef HAVE_LLM_SYSTEM_PROMPT_HASH
    int fb_len = llm_user_prefix_fallback_len();
    if (fb_len > 0 && has_first_user) {
      strncpy(prefix_key->prefix, first_user, fb_len);
      prefix_key->prefix[fb_len] = '\0';
      prefix_key->valid = 1;
      log_debug("[PREFIX_USER_FALLBACK] no system message; hashing first %d "
                "bytes of first user message", fb_len);
      return 0;
    }
#endif
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("No user message found in JSON");
#endif
    return -1;
  }
  
#ifdef HAVE_PROXY_EXTRA_DEBUG
  log_debug("[EXTRACT_SUCCESS] level=%d, flags=0x%x",
            prefix_key->level, prefix_key->flags);
#endif
  
  return 0;
}

// P1.1: Compute hash for prefix-based routing using xxHash (PHASE 1 ENHANCED)
uint64_t compute_prefix_hash(llm_prefix_key_t *pk)
{
  XXH64_state_t *state;
  uint64_t hash;
  
  // Validation: Check required fields
  if (!pk || !pk->valid) {
    return 0;
  }
  
  // Initialize XXH64 state
  state = XXH64_createState();
  if (!state) {
    log_error("compute_prefix_hash: XXH64_createState() failed");
    return 0;
  }
  
  XXH64_reset(state, 0);
  
  // LEVEL 1: Global Prefix (always included)
  // Core fields: prefix and model (always hashed)
  XXH64_update(state, pk->prefix, strlen(pk->prefix));
  XXH64_update(state, pk->model, strlen(pk->model));
  
  // Optional L1 fields: conditionally include based on presence flags
  if (pk->flags & PREFIX_HAS_LORA) {
    XXH64_update(state, pk->lora_adapter, strlen(pk->lora_adapter));
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[HASH_L1] Including lora_adapter: '%s'", pk->lora_adapter);
#endif
  }
  
  if (pk->flags & PREFIX_HAS_IMAGE) {
    XXH64_update(state, pk->image_hash, strlen(pk->image_hash));
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[HASH_L1] Including image_hash: '%s'", pk->image_hash);
#endif
  }
  
  if (pk->flags & PREFIX_HAS_AUDIO) {
    XXH64_update(state, pk->audio_hash, strlen(pk->audio_hash));
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[HASH_L1] Including audio_hash: '%s'", pk->audio_hash);
#endif
  }
  
  if (pk->flags & PREFIX_HAS_CACHE_SALT) {
    XXH64_update(state, pk->cache_salt, strlen(pk->cache_salt));
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[HASH_L1] Including cache_salt: '%s'", pk->cache_salt);
#endif
  }
  
  if (pk->flags & PREFIX_HAS_TOOL_SCHEMAS) {
    XXH64_update(state, pk->tool_schemas_hash, strlen(pk->tool_schemas_hash));
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[HASH_L1] Including tool_schemas_hash: '%s'", pk->tool_schemas_hash);
#endif
  }
  
  // Stop at L1 if level=1 (default for CHWBL routing)
  if (pk->level == 1)
    goto finalize;
  
  // LEVEL 2: Session Context (optional)
  if (pk->flags & PREFIX_HAS_SESSION_CTX) {
    XXH64_update(state, pk->session_context_hash, strlen(pk->session_context_hash));
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[HASH_L2] Including session_context_hash: '%s'", pk->session_context_hash);
#endif
  }
  
  // Stop at L2 if level=2
  if (pk->level == 2)
    goto finalize;
  
  // LEVEL 3: RAG Context (optional)
  if (pk->flags & PREFIX_HAS_RAG_TEMPLATE) {
    XXH64_update(state, pk->rag_template_hash, strlen(pk->rag_template_hash));
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[HASH_L3] Including rag_template_hash: '%s'", pk->rag_template_hash);
#endif
  }
  
  if (pk->flags & PREFIX_HAS_RAG_DOC_IDS) {
    XXH64_update(state, pk->rag_doc_ids_hash, strlen(pk->rag_doc_ids_hash));
#ifdef HAVE_PROXY_EXTRA_DEBUG
    log_debug("[HASH_L3] Including rag_doc_ids_hash: '%s'", pk->rag_doc_ids_hash);
#endif
  }
  
finalize:
  // Compute final hash
  hash = XXH64_digest(state);
  XXH64_freeState(state);
  
#ifdef HAVE_PROXY_EXTRA_DEBUG
  log_debug("[HASH_COMPUTED] level=%d, flags=0x%x, hash=0x%lx",
            pk->level, pk->flags, hash);
#endif
  
  return hash;
}
