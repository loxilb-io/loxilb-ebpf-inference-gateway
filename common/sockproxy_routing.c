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
 *
 * Host names compare without regard to case (RFC 9110 section 4.2.3), so the
 * host part of the key is folded to lower case. Rules and requests build their
 * keys here alike, so "API.Example.com" in either one finds the other. The path
 * and the model name keep their case.
 */
void
build_ephash_key(char *key_buf, size_t buf_size,
                 const char *host, const char *path_prefix,
                 const char *model_name)
{
  int has_path = (path_prefix && path_prefix[0] != '\0');
  int has_model = (model_name && model_name[0] != '\0');
  char *c;

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

  /* A host never holds '|': everything before the first one is the host. */
  for (c = key_buf; buf_size && *c && *c != '|'; c++) {
    if (*c >= 'A' && *c <= 'Z')
      *c = (char)(*c - 'A' + 'a');
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
 * @param ix The listener's published pool index, read once per lookup
 * @param host Hostname without port (e.g., "api.example.com")
 * @param request_path Full request path (e.g., "/v1/users/profile/settings")
 * @param model_name AI model name or NULL/empty for wildcard
 * @return Endpoint value or NULL if not found
 */
static proxy_epval_t*
find_endpoint_for_host(const sp_pool_index_t *ix, const char *host,
                       const char *request_path, const char *model_name)
{
  proxy_epval_t *best_match = NULL;
  proxy_epval_t *tepval = NULL;
  char search_key[512];
  char path_copy[256];
  int best_match_len = -1;  /* Used for debug logging and path matching */

  if (!ix || !host) {
    return NULL;
  }

  /* Default to root path if not provided */
  const char *path = (request_path && request_path[0] != '\0') ? request_path : "/";
  /* Routing compares the URI path, not its query. Keep the original length
   * so a bounded copy cannot turn a longer URI into an exact match. */
  size_t path_len = strcspn(path, "?");
  size_t copy_len = path_len < sizeof(path_copy) - 1
                      ? path_len : sizeof(path_copy) - 1;

  /* Copy path for progressive shortening */
  memcpy(path_copy, path, copy_len);
  path_copy[copy_len] = '\0';

  /* Progressive prefix matching: "/v1/users/profile" → "/v1/users" → "/v1" → "/"
   * IMPORTANT: We try progressively shorter prefixes to find the LONGEST match */
  while (strlen(path_copy) > 0) {
    /* Build search key: "host|path[|model]" */
    build_ephash_key(search_key, sizeof(search_key), host, path_copy, model_name);

    /* Try to find this prefix */
    tepval = sp_pool_index_find(ix, search_key);

    if (tepval && (tepval->path_match_mode != 2 ||
                   strlen(path_copy) == path_len)) {
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
      tepval = sp_pool_index_find(ix, search_key);
      if (tepval && (tepval->path_match_mode != 2 || path_len == 1)) {
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

  /* A model-specific rule does not need a path_prefix. proxy_add_entry stores
   * that valid shape as "host||model", so try it before falling back to any
   * wildcard-model path. Without this lookup, a hostname-only model pool was
   * inserted successfully and shown by the management API, yet every request
   * for that model returned 503 model_unavailable. The older model-routing
   * scenario always configured path_prefix="/" and therefore could not expose
   * this missing branch. */
  if (!best_match && model_name && model_name[0] != '\0') {
    build_ephash_key(search_key, sizeof(search_key), host, "", model_name);
    tepval = sp_pool_index_find(ix, search_key);
    if (tepval) {
      return tepval;
    }
  }

  /* Criterion B: If model-specific path LPM found nothing, retry with wildcard model.
   * This implements two-level model routing: specific pool first, then wildcard pool.
   * Pure C hash-table lookup — zero CGO calls in this path. */
  if (!best_match && model_name && model_name[0] != '\0') {
    /* Re-initialize path_copy for wildcard retry */
    memcpy(path_copy, path, copy_len);
    path_copy[copy_len] = '\0';

    while (strlen(path_copy) > 0) {
      build_ephash_key(search_key, sizeof(search_key), host, path_copy, "");
      tepval = sp_pool_index_find(ix, search_key);
      if (tepval && (tepval->path_match_mode != 2 ||
                     strlen(path_copy) == path_len)) {
        return tepval;  /* Wildcard pool found */
      }
      char *last_slash = strrchr(path_copy, '/');
      if (last_slash == path_copy) {
        /* Try root "/" as final prefix (harmless re-check when path_copy is "/") */
        build_ephash_key(search_key, sizeof(search_key), host, "/", "");
        tepval = sp_pool_index_find(ix, search_key);
        if (tepval && (tepval->path_match_mode != 2 || path_len == 1))
          return tepval;
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
    tepval = sp_pool_index_find(ix, search_key);
    if (tepval) {
      best_match = tepval;
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("LPM fallback: hostname-only match '%s'\n", search_key);
#endif
    }
  }

  return best_match;
}

/* Wildcard host rules, Gateway API (v1.5.1) hostname semantics: "*.example.com"
 * matches a host with one or more labels in front of "example.com", and never
 * "example.com" itself. For a request host l1.l2...ln the candidates are
 * "*.l2...ln", "*.l3...ln", ... "*.ln", longest suffix first, so a more
 * specific wildcard wins. Each candidate is looked up the way an exact host is
 * (find_endpoint_for_host: Exact path, then longest prefix, then the model
 * stages). A candidate with rules but no matching path does not end the search:
 * the next candidate is tried, as Gateway API ranks rules on host and path
 * together. The first candidate that yields a pool answers, an endpoint-less
 * pool included. */
static proxy_epval_t *
find_endpoint_wildcard(const sp_pool_index_t *ix, const char *host,
                       const char *request_path, const char *model_name)
{
  char candidate[260];
  const char *dot;

  for (dot = strchr(host, '.'); dot && dot[1] != '\0'; dot = strchr(dot + 1, '.')) {
    int n = snprintf(candidate, sizeof(candidate), "*%s", dot);

    if (n < 0 || (size_t)n >= sizeof(candidate))
      continue;  /* longer than any host a rule can hold */
    proxy_epval_t *ep = find_endpoint_for_host(ix, candidate, request_path,
                                               model_name);
    if (ep)
      return ep;
  }
  return NULL;
}

proxy_epval_t*
find_endpoint_lpm(proxy_map_ent_t *ent, const char *host, const char *request_path,
                  const char *model_name)
{
  if (!ent || !host) {
    return NULL;
  }

  /* One index for the whole lookup: every fallback below is answered from
   * the same snapshot of the listener's pools (sockproxy_pool.h). */
  const sp_pool_index_t *ix = sp_pool_index(ent);
  proxy_epval_t *best_match = find_endpoint_for_host(ix, host, request_path,
                                                   model_name);
  if (best_match) {
    return best_match;
  }

  /* Then the wildcard host rules, between the exact host and the listener's
   * host-less rules. Skipped on a listener without one: the candidates cost a
   * lookup per path level each, and most listeners have none. */
  if (ix && ix->n_wildcard) {
    best_match = find_endpoint_wildcard(ix, host, request_path, model_name);
    if (best_match) {
      return best_match;
    }
  }
  proxy_epval_t *tepval = NULL;
  char search_key[512];

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
    char ab1[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, (struct in_addr *)&ent->key.xip, ab1, sizeof(ab1))) {
      char self_host[64];
      snprintf(self_host, sizeof(self_host), "%s:%u", ab1, ntohs(ent->key.xport));
      /* A no-host rule can carry the same model/path constraints as a
       * host rule. Reuse the complete lookup instead of checking only
       * pathless keys, preserving exact and longest-prefix semantics. */
      best_match = find_endpoint_for_host(ix, self_host, request_path,
                                         model_name);
      if (best_match) {
        return best_match;
      }
    }
  }

  /* Final fallback: Try empty hostname (default IP-based routing)
   * This handles cases where LB is configured without a specific hostname
   * (e.g., "loxicmd create lb 10.10.10.254 --tcp=2020:8080 --endpoints=...") */
  if (!best_match) {
    build_ephash_key(search_key, sizeof(search_key), "", "", "");
    tepval = sp_pool_index_find(ix, search_key);
    if (tepval) {
      best_match = tepval;
#ifdef HAVE_PROXY_EXTRA_DEBUG
      log_debug("LPM fallback: default (empty hostname) match\n");
#endif
    }
  }

  return best_match;
}

/* The model a pool was added for: the third field of its key
 * (build_ephash_key: "host|path|model" or "host||model"), "" for a wildcard
 * pool. */
static const char *
sp_pool_key_model(const proxy_epval_t *p)
{
  const char *sep = strchr(p->ephash_key, '|');

  sep = sep ? strchr(sep + 1, '|') : NULL;
  return sep ? sep + 1 : "";
}

/* The pool of a request that reached dispatch with no usable Host (ROUTE-01's
 * second defence). The listener's first pool is whatever rule was added first,
 * so on a listener whose pools name models it would serve the request from
 * another model's engine. There the request goes to the pool that names its
 * model (exact name, the first in the table's order), or is refused when none
 * does or it names none. A listener with no model pool keeps the first pool,
 * as before: a plain rule, or a raw TCP stream, has no Host to lose.
 * *pool is NULL on a refusal and when the listener has no pool. */
int
sp_route_hostless(const proxy_map_ent_t *ent, const char *model,
                  proxy_epval_t **pool)
{
  const sp_pool_index_t *ix = sp_pool_index(ent);
  proxy_epval_t *named = NULL;
  int any_model = 0;

  *pool = NULL;
  if (!ix) {
    return SP_HOSTLESS_FIRST;
  }
  for (uint32_t i = 0; i < ix->n; i++) {
    proxy_epval_t *p = ix->order[i];
    const char *pm = sp_pool_key_model(p);

    if (pm[0] == '\0') {
      continue;
    }
    any_model = 1;
    if (!named && model && model[0] != '\0' && strcmp(pm, model) == 0) {
      named = p;
    }
  }
  if (!any_model) {
    *pool = ix->first;
    return SP_HOSTLESS_FIRST;
  }
  if (!named) {
    return SP_HOSTLESS_REFUSE;
  }
  *pool = named;
  return SP_HOSTLESS_MODEL;
}

/* The default reservation of the pool a request's host, path and model
 * select: the lookup dispatch runs, read for one field. host NULL = no
 * usable Host, where dispatch asks sp_route_hostless. 0 when no pool
 * matches. */
int
sp_resv_default_tokens_route(proxy_map_ent_t *ent, const char *host,
                             const char *path, const char *model)
{
  proxy_epval_t *ep;

  if (!ent)
    return 0;
  if (!host)
    sp_route_hostless(ent, model, &ep);
  else
    ep = find_endpoint_lpm(ent, host, path ? path : "/", model ? model : "");
  return ep ? (int)ep->ai_default_tokens : 0;
}

/* The same lookup for the rule's ai_objective_strict. 0 when no pool
 * matches: the request is refused at dispatch whatever it names. */
int
sp_resv_objective_strict_route(proxy_map_ent_t *ent, const char *host,
                               const char *path, const char *model)
{
  proxy_epval_t *ep;

  if (!ent)
    return 0;
  if (!host)
    sp_route_hostless(ent, model, &ep);
  else
    ep = find_endpoint_lpm(ent, host, path ? path : "/", model ? model : "");
  return ep ? (int)ep->ai_objective_strict : 0;
}
