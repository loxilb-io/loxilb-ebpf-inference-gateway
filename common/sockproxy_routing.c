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

/* P6: Host + Path Prefix Routing Helpers
 * Extracted from sockproxy.c section 26.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "uthash.h"             /* MUST precede sockproxy.h */
#include "log.h"
#include "sockproxy_internal.h" /* includes sockproxy.h    */
#include "sockproxy_routing.h"

// ============================================================================
// P6: Host + Path Prefix Routing Helpers
// ============================================================================

/**
 * Build ephash lookup key from hostname, optional path prefix, and optional model name
 *
 * Format: "api.example.com|/v1/users|llama-70b" (with path and model)
 *         "api.example.com|/v1/users" (with path, no model - backward compatible)
 *         "api.example.com||llama-70b" (no path, with model)
 *         "api.example.com" (without path or model - backward compatible)
 *
 * @param key_buf Output buffer for composite key
 * @param buf_size Size of key_buf
 * @param host Hostname (e.g., "api.example.com")
 * @param path_prefix Path prefix (e.g., "/v1/users") or NULL/empty for hostname-only
 * @param model_name AI model name (e.g., "llama-70b") or NULL/empty for wildcard pool
 */
void
build_ephash_key(char *key_buf, size_t buf_size,
                 const char *host, const char *path_prefix,
                 const char *model_name)
{
  int has_path = (path_prefix && path_prefix[0] != '\0');
  int has_model = (model_name && model_name[0] != '\0');

  if (has_path && has_model) {
    // Composite key: "host|path|model"
    snprintf(key_buf, buf_size, "%s|%s|%s", host, path_prefix, model_name);
  } else if (has_path) {
    // Composite key: "host|path" (backward compatible)
    snprintf(key_buf, buf_size, "%s|%s", host, path_prefix);
  } else if (has_model) {
    // Composite key: "host||model" (no path prefix)
    snprintf(key_buf, buf_size, "%s||%s", host, model_name);
  } else {
    // Backward compatibility: hostname-only
    snprintf(key_buf, buf_size, "%s", host);
  }
}

/**
 * Find endpoint using Longest Prefix Match (LPM)
 *
 * Example: Request "/v1/users/profile/settings" matches:
 *   1. Try "host|/v1/users/profile/settings" (exact, no match)
 *   2. Try "host|/v1/users/profile" (no match)
 *   3. Try "host|/v1/users" ✅ (longest match found)
 *   4. Would try "host|/v1" if step 3 failed
 *   5. Would try "host|/" if all prefix matches failed
 *   6. Fallback to "host" (hostname-only, backward compat)
 *
 * @param ent Proxy map entry containing ephash table
 * @param host Hostname without port (e.g., "api.example.com")
 * @param request_path Full request path (e.g., "/v1/users/profile/settings")
 * @param model_name AI model name or NULL/empty for wildcard
 * @return Endpoint value or NULL if not found
 */
proxy_epval_t*
find_endpoint_lpm(proxy_map_ent_t *ent, const char *host, const char *request_path,
                  const char *model_name)
{
  proxy_epval_t *best_match = NULL;
  proxy_epval_t *tepval = NULL;
  char search_key[512];
  char path_copy[256];
  int best_match_len = -1;  /* Used for debug logging and path matching */

  if (!ent || !host) {
    return NULL;
  }

  /* Default to root path if not provided */
  const char *path = (request_path && request_path[0] != '\0') ? request_path : "/";

  /* Copy path for progressive shortening */
  strncpy(path_copy, path, sizeof(path_copy) - 1);
  path_copy[sizeof(path_copy) - 1] = '\0';

  /* Progressive prefix matching: "/v1/users/profile" → "/v1/users" → "/v1" → "/"
   * IMPORTANT: We try progressively shorter prefixes to find the LONGEST match */
  while (strlen(path_copy) > 0) {
    /* Build search key: "host|path[|model]" */
    build_ephash_key(search_key, sizeof(search_key), host, path_copy, model_name);

    /* Try to find this prefix */
    HASH_FIND_STR(ent->val.ephash, search_key, tepval);

    if (tepval) {
      /* Found a match! This is the LONGEST prefix match since we search longest-first */
      best_match = tepval;
      best_match_len = strlen(path_copy);

#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("LPM match: %s (len=%d)\n", search_key, best_match_len);
#endif

      /* P6 FIX: Return immediately on first match (longest prefix)
       * Don't continue searching shorter prefixes! */
      return best_match;
    }

    /* No match yet - shorten path by removing last segment
     * "/v1/users/profile" → "/v1/users" */
    char *last_slash = strrchr(path_copy, '/');
    if (last_slash == path_copy) {
      /* path_copy is "/segment" or "/" — try root "/" as final prefix match.
       * When path_copy is already "/" this is a harmless re-check (already tried
       * in loop body); when path_copy is "/v1" etc., "/" hasn't been tried yet. */
      build_ephash_key(search_key, sizeof(search_key), host, "/", model_name);
      HASH_FIND_STR(ent->val.ephash, search_key, tepval);
      if (tepval) {
        best_match = tepval;
        best_match_len = 1;
        return best_match;
      }
      break;  /* Done with path matching */
    } else if (last_slash) {
      *last_slash = '\0';  /* Truncate at last slash */
    } else {
      break;  /* No more slashes */
    }
  }

  /* Criterion B: If model-specific path LPM found nothing, retry with wildcard model.
   * This implements two-level model routing: specific pool first, then wildcard pool.
   * Pure C hash-table lookup — zero CGO calls in this path. */
  if (!best_match && model_name && model_name[0] != '\0') {
    /* Re-initialize path_copy for wildcard retry */
    strncpy(path_copy, path, sizeof(path_copy) - 1);
    path_copy[sizeof(path_copy) - 1] = '\0';

    while (strlen(path_copy) > 0) {
      build_ephash_key(search_key, sizeof(search_key), host, path_copy, "");
      HASH_FIND_STR(ent->val.ephash, search_key, tepval);
      if (tepval) {
        return tepval;  /* Wildcard pool found */
      }
      char *last_slash = strrchr(path_copy, '/');
      if (last_slash == path_copy) {
        /* Try root "/" as final prefix (harmless re-check when path_copy is "/") */
        build_ephash_key(search_key, sizeof(search_key), host, "/", "");
        HASH_FIND_STR(ent->val.ephash, search_key, tepval);
        if (tepval) return tepval;
        break;
      } else if (last_slash) {
        *last_slash = '\0';
      } else {
        break;
      }
    }
    /* Fall through to hostname-only and default fallbacks below.
     * IP-based VIPs are registered without a model, so use empty model. */
  }

  /* Fallback: Try hostname-only (backward compatibility)
 * Use empty model — IP-based VIPs have no model in their key. */
  if (!best_match) {
    build_ephash_key(search_key, sizeof(search_key), host, "", "");
    HASH_FIND_STR(ent->val.ephash, search_key, tepval);
    if (tepval) {
      best_match = tepval;
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("LPM fallback: hostname-only match '%s'\n", search_key);
#endif
    }
  }

  /* Fallback: listener-identity key. Rules created WITHOUT a host get their
   * host_url substituted with the listener's own "ip:port" before the ephash
   * key is built (llb_conv_nat2proxy, loxilb_libdp.c). No Host-header-derived
   * lookup above can ever produce that key — the port is stripped from the
   * header before matching — so without this fallback an empty-host rule is
   * unreachable whenever the client's Host string differs from the rule's
   * stored form (e.g. clients arriving via a NAT'd/floating external IP).
   * Keying on the listener identity makes empty-host rules Host-agnostic,
   * which is their intended wildcard semantic. */
  if (!best_match) {
    char self_key[256];   /* "ip:port||model" — model_name alone can be 128 */
    char ab1[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, (struct in_addr *)&ent->key.xip, ab1, sizeof(ab1))) {
      char self_host[64];
      snprintf(self_host, sizeof(self_host), "%s:%u", ab1, ntohs(ent->key.xport));
      if (model_name && model_name[0] != '\0') {
        /* model-specific pool under the listener identity first */
        build_ephash_key(self_key, sizeof(self_key), self_host, "", model_name);
        HASH_FIND_STR(ent->val.ephash, self_key, tepval);
        if (tepval) return tepval;
      }
      build_ephash_key(self_key, sizeof(self_key), self_host, "", "");
      HASH_FIND_STR(ent->val.ephash, self_key, tepval);
      if (tepval) {
        return tepval;
      }
    }
  }

  /* Final fallback: Try empty hostname (default IP-based routing)
   * This handles cases where LB is configured without a specific hostname
   * (e.g., "loxicmd create lb 10.10.10.254 --tcp=2020:8080 --endpoints=...") */
  if (!best_match) {
    build_ephash_key(search_key, sizeof(search_key), "", "", "");
    HASH_FIND_STR(ent->val.ephash, search_key, tepval);
    if (tepval) {
      best_match = tepval;
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("LPM fallback: default (empty hostname) match\n");
#endif
    }
  }

  return best_match;
}
