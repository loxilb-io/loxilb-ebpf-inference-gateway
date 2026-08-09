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

// Main extraction function for LLM prefix (PHASE 1 ENHANCED)
int extract_llm_prefix(const char *json_body, size_t len,
                       llm_prefix_key_t *prefix_key)
{
  jsmn_parser parser;
  jsmntok_t tokens[2048];  // Increased from 512 to handle large system prompts
  int r, i;
  
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
        // D-LC2: DECODE the JSON escapes while copying (see
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
