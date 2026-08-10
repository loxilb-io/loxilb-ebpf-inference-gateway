/* sockproxy_pd.c - P/D disaggregation body rewriting for vLLM prefill/decode
 *
 * Uses targeted memmem() + memmove() string replacement. Safe for OpenAI API
 * which has predictable flat JSON structure.
 */

#define _GNU_SOURCE  /* for memmem() */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>

/* Include log.h for production builds; test builds define log_error as macro */
#if !defined(TEST_PD_REWRITER) && !defined(TEST_PD_CACHE_AWARE)
#include "log.h"
#include "sockproxy_kv_exact.h"
#include <stdatomic.h>
/* AI Gateway CGO bridge: P/D session hit counter */
extern void llb_ai_pd_session_hit(char *model_name);
/* Forward-declare overflow counter increment (defined in sockproxy_metrics.c) */
extern void pd_kv_overflow_inc(void);
#else
/* Test builds: no-op for overflow counter */
static inline void pd_kv_overflow_inc(void) {}
#endif

#if !defined(TEST_PD_REWRITER) && !defined(TEST_PD_CACHE_AWARE)
/* LLB_KV_HASH_DEBUG gate — file-local mirror of kv_hash_debug_on()
 * (sockproxy_kv_exact.c) rather than an exported symbol, because the
 * test_pd_* unit binaries compile this file without sockproxy_kv_exact.c.
 * Emits one [PD_KV_PARAMS] line per successful kv_transfer_params
 * extraction; the G2 sizing sweep (LC-3.1, uint16→uint32 widening
 * decision) parses this exact format — keep it stable. */
static _Atomic int pd_kv_dbg_initialized = 0;
static int pd_kv_dbg = 0;
static int
pd_kv_hash_debug_on(void)
{
  int init = atomic_load_explicit(&pd_kv_dbg_initialized,
                                  memory_order_acquire);
  if (init) return pd_kv_dbg;
  const char *v = getenv("LLB_KV_HASH_DEBUG");
  pd_kv_dbg = (v && v[0] == '1' && v[1] == '\0') ? 1 : 0;
  atomic_store_explicit(&pd_kv_dbg_initialized, 1, memory_order_release);
  return pd_kv_dbg;
}
#define PD_KV_PARAMS_DBG(len, cap) do {                                   \
    if (pd_kv_hash_debug_on())                                            \
      log_info("[PD_KV_PARAMS] len=%zu cap=%zu pct=%zu",                  \
               (size_t)(len), (size_t)(cap),                              \
               ((size_t)(len) * 100) / (size_t)(cap));                    \
  } while (0)
#else
#define PD_KV_PARAMS_DBG(len, cap) ((void)0)
#endif

/* KV transfer params to inject into prefill body */
#define PD_KV_TRANSFER_PARAMS \
  ",\"kv_transfer_params\":{\"do_remote_decode\":true,\"do_remote_prefill\":false}"

/* Find the value portion of a JSON field.
 * Given key like "max_tokens", finds the value start and end in the JSON buffer.
 * Handles spacing: "key": value and "key":value
 * Returns 0 on success, -1 if key not found.
 * val_start points to first char of value, val_end points past last char of value.
 */
static int
pd_find_json_value(const uint8_t *buf, size_t buf_len,
                   const char *key, size_t key_len,
                   const uint8_t **val_start, const uint8_t **val_end)
{
  /* Build search pattern: "key" */
  char pattern[128];
  int plen;
  const uint8_t *pos, *end, *vs, *ve;

  if (key_len + 3 > sizeof(pattern)) return -1;

  plen = snprintf(pattern, sizeof(pattern), "\"%s\"", key);
  end = buf + buf_len;

  pos = memmem(buf, buf_len, pattern, plen);
  while (pos) {
    /* H-5 fix: reject matches inside string values.
     * Valid preceding bytes: { , \n \r \t space (or pos==buf for start-of-buffer).
     * If preceded by a printable non-separator, this is inside a value string. */
    if (pos == buf || *(pos - 1) == '{' || *(pos - 1) == ',' ||
        *(pos - 1) == '\n' || *(pos - 1) == '\r' ||
        *(pos - 1) == '\t' || *(pos - 1) == ' ') {
      break;  /* Valid match */
    }
    /* Skip this false match and search remainder */
    size_t skip = (pos - buf) + plen;
    if (skip >= buf_len) return -1;
    pos = memmem(pos + plen, buf_len - skip, pattern, plen);
  }
  if (!pos) return -1;

  /* Skip past "key" */
  vs = pos + plen;

  /* Skip whitespace and colon */
  while (vs < end && (*vs == ' ' || *vs == '\t' || *vs == '\n' || *vs == '\r')) vs++;
  if (vs >= end || *vs != ':') return -1;
  vs++; /* skip ':' */
  while (vs < end && (*vs == ' ' || *vs == '\t' || *vs == '\n' || *vs == '\r')) vs++;
  if (vs >= end) return -1;

  /* Determine value extent based on type */
  if (*vs == '"') {
    /* String value - find closing quote (handle escapes) */
    ve = vs + 1;
    while (ve < end) {
      if (*ve == '\\') { ve += 2; continue; }
      if (*ve == '"') { ve++; break; }
      ve++;
    }
  } else if (*vs == '{') {
    /* Object - find matching brace */
    int depth = 1;
    int in_string = 0;
    ve = vs + 1;
    while (ve < end && depth > 0) {
      if (in_string) {
        if (*ve == '\\') { ve++; }
        else if (*ve == '"') { in_string = 0; }
      } else {
        if (*ve == '"') in_string = 1;
        else if (*ve == '{') depth++;
        else if (*ve == '}') depth--;
      }
      ve++;
    }
  } else if (*vs == '[') {
    /* Array - find matching bracket */
    int depth = 1;
    int in_string = 0;
    ve = vs + 1;
    while (ve < end && depth > 0) {
      if (in_string) {
        if (*ve == '\\') { ve++; }
        else if (*ve == '"') { in_string = 0; }
      } else {
        if (*ve == '"') in_string = 1;
        else if (*ve == '[') depth++;
        else if (*ve == ']') depth--;
      }
      ve++;
    }
  } else if (*vs == 't' || *vs == 'f' || *vs == 'n') {
    /* true, false, null */
    ve = vs;
    while (ve < end && *ve != ',' && *ve != '}' && *ve != ']' &&
           *ve != ' ' && *ve != '\t' && *ve != '\n' && *ve != '\r') {
      ve++;
    }
  } else {
    /* Number */
    ve = vs;
    while (ve < end && *ve != ',' && *ve != '}' && *ve != ']' &&
           *ve != ' ' && *ve != '\t' && *ve != '\n' && *ve != '\r') {
      ve++;
    }
  }

  *val_start = vs;
  *val_end = ve;
  return 0;
}

/* Replace a JSON value in buffer. Shifts surrounding data via memmove.
 * Returns new buffer length, or -1 on error (overflow).
 */
static int
pd_replace_json_value(uint8_t *buf, size_t buf_len, size_t buf_capacity,
                      const uint8_t *val_start, const uint8_t *val_end,
                      const char *new_val, size_t new_val_len)
{
  size_t old_len = val_end - val_start;
  size_t offset = val_start - buf;
  ssize_t delta = (ssize_t)new_val_len - (ssize_t)old_len;

  if ((ssize_t)buf_len + delta > (ssize_t)buf_capacity) {
    return -1; /* overflow */
  }

  /* Shift data after old value */
  memmove((uint8_t *)val_start + new_val_len, val_end,
          buf_len - (offset + old_len));

  /* Write new value */
  memcpy((uint8_t *)val_start, new_val, new_val_len);

  return (int)((ssize_t)buf_len + delta);
}

/* Remove a JSON field (key + value + surrounding comma).
 * Handles both ",key:val" and "key:val," patterns.
 * Returns new buffer length, or -1 if key not found.
 */
static int
pd_remove_json_field(uint8_t *buf, size_t buf_len,
                     const char *key, size_t key_len)
{
  char pattern[128];
  int plen;
  const uint8_t *pos, *field_start, *field_end;
  const uint8_t *val_start, *val_end;

  if (key_len + 3 > sizeof(pattern)) return -1;

  plen = snprintf(pattern, sizeof(pattern), "\"%s\"", key);

  pos = memmem(buf, buf_len, pattern, plen);
  if (!pos) return -1;

  /* Find value extent */
  if (pd_find_json_value(buf, buf_len, key, key_len, &val_start, &val_end) < 0) {
    return -1;
  }

  field_start = pos;
  field_end = val_end;

  /* Consume leading comma+whitespace or trailing comma+whitespace */
  if (field_start > buf) {
    const uint8_t *p = field_start - 1;
    while (p >= buf && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p--;
    if (p >= buf && *p == ',') {
      field_start = p;
    }
  }
  if (field_start == pos && field_end < buf + buf_len) {
    /* No leading comma found, try trailing */
    const uint8_t *p = field_end;
    while (p < buf + buf_len && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
    if (p < buf + buf_len && *p == ',') {
      field_end = p + 1;
    }
  }

  size_t remove_len = field_end - field_start;
  size_t offset = field_start - buf;
  memmove((uint8_t *)field_start, field_end, buf_len - offset - remove_len);

  return (int)(buf_len - remove_len);
}

/* Prepare a prefill request body by rewriting JSON fields.
 * Copies orig_body to out_buf, then performs in-place rewrites:
 * 1. max_tokens -> 1
 * 2. max_completion_tokens -> 1
 * 3. min_tokens -> 1 (if present and > 1)
 * 4. stream -> false; remove stream_options if present
 * 5. Append kv_transfer_params before closing }
 *
 * Returns 0 on success, -1 on error.
 * out_len is set to the final body length.
 */
int
pd_prepare_prefill_body(const uint8_t *orig_body, size_t orig_body_len,
                        uint8_t *out_buf, size_t *out_len, size_t out_capacity)
{
  const uint8_t *vs, *ve;
  int new_len;

  if (!orig_body || !out_buf || !out_len || orig_body_len == 0) {
    return -1;
  }

  if (orig_body_len >= out_capacity) {
    return -1;
  }

  /* Copy to output buffer for in-place rewriting */
  memcpy(out_buf, orig_body, orig_body_len);
  new_len = (int)orig_body_len;

  /* 1. Rewrite max_tokens to 1 */
  if (pd_find_json_value(out_buf, new_len, "max_tokens", 10, &vs, &ve) == 0) {
    int r = pd_replace_json_value(out_buf, new_len, out_capacity, vs, ve, "1", 1);
    if (r < 0) return -1;
    new_len = r;
  }

  /* 2. Rewrite max_completion_tokens to 1 */
  if (pd_find_json_value(out_buf, new_len, "max_completion_tokens", 21, &vs, &ve) == 0) {
    int r = pd_replace_json_value(out_buf, new_len, out_capacity, vs, ve, "1", 1);
    if (r < 0) return -1;
    new_len = r;
  }

  /* 3. Rewrite min_tokens to 1 (if present and > 1) */
  if (pd_find_json_value(out_buf, new_len, "min_tokens", 10, &vs, &ve) == 0) {
    /* Check if value > 1 (simple: if not "0" or "1", rewrite) */
    size_t vlen = ve - vs;
    if (!(vlen == 1 && (*vs == '0' || *vs == '1'))) {
      int r = pd_replace_json_value(out_buf, new_len, out_capacity, vs, ve, "1", 1);
      if (r < 0) return -1;
      new_len = r;
    }
  }

  /* 4. Rewrite stream to false */
  if (pd_find_json_value(out_buf, new_len, "stream", 6, &vs, &ve) == 0) {
    int r = pd_replace_json_value(out_buf, new_len, out_capacity, vs, ve, "false", 5);
    if (r < 0) return -1;
    new_len = r;
  }

  /* 4b. Remove stream_options if present */
  {
    int r = pd_remove_json_field(out_buf, new_len, "stream_options", 14);
    if (r > 0) new_len = r;
  }

  /* 5. Append kv_transfer_params before closing } */
  {
    /* Find last } in the body */
    int i;
    int insert_pos = -1;
    for (i = new_len - 1; i >= 0; i--) {
      if (out_buf[i] == '}') {
        insert_pos = i;
        break;
      }
    }

    if (insert_pos < 0) return -1;

    size_t kv_len = strlen(PD_KV_TRANSFER_PARAMS);
    if ((size_t)new_len + kv_len >= out_capacity) return -1;

    /* Shift closing } and anything after it */
    memmove(out_buf + insert_pos + kv_len, out_buf + insert_pos,
            new_len - insert_pos);
    memcpy(out_buf + insert_pos, PD_KV_TRANSFER_PARAMS, kv_len);
    new_len += kv_len;
  }

  *out_len = (size_t)new_len;
  return 0;
}

/* Extract kv_transfer_params from prefill response.
 * Searches the prefill response body for "kv_transfer_params" JSON object
 * and copies the full nested object value to kv_out buffer.
 *
 * Returns 0 on success (kv_out_len > 0 when found, == 0 when not found).
 * Returns -1 on error (invalid args).
 * Graceful degradation: when not found, kv_out_len=0, kv_out="", return 0.
 */
int
pd_extract_kv_params(const uint8_t *resp_buf, size_t resp_len,
                     char *kv_out, size_t *kv_out_len, size_t kv_capacity)
{
  const uint8_t *val_start, *val_end;
  size_t val_len;

  if (!kv_out || !kv_out_len || kv_capacity == 0) {
    return -EINVAL;
  }

  /* Default: empty (graceful degradation) */
  *kv_out_len = 0;
  kv_out[0] = '\0';

  if (!resp_buf || resp_len == 0) {
    return -ENOENT;  /* No response body to search */
  }

  /* Use pd_find_json_value to locate "kv_transfer_params" object.
   * It handles nested braces and strings with escaped characters. */
  if (pd_find_json_value(resp_buf, resp_len,
                         "kv_transfer_params", 18,
                         &val_start, &val_end) != 0) {
    /* Not found — let call site decide log level based on pd_disagg context */
    return -ENOENT;
  }

  val_len = (size_t)(val_end - val_start);

  /* Buffer overflow check */
  if (val_len >= kv_capacity) {
    pd_kv_overflow_inc();
    log_warn("kv_transfer_params too large (%zu >= %zu capacity)", val_len, kv_capacity);
    *kv_out_len = 0;
    kv_out[0] = '\0';
    return -EMSGSIZE;
  }

  memcpy(kv_out, val_start, val_len);
  kv_out[val_len] = '\0';
  *kv_out_len = val_len;

  PD_KV_PARAMS_DBG(val_len, kv_capacity);

  return 0;
}

/* Prepare decode request body.
 * Combines original request body with kv_transfer_params extracted from
 * prefill response. Inserts ,"kv_transfer_params":<kv_params> before
 * the closing } of the JSON body.
 *
 * If kv_params is empty/NULL, uses original body unchanged (graceful degradation).
 * stream field preserves client's original value (NOT forced false like prefill).
 *
 * Returns 0 on success, -1 on error.
 */
int
pd_prepare_decode_body(const uint8_t *orig_body, size_t orig_body_len,
                       const char *kv_params, size_t kv_params_len,
                       uint8_t *out_buf, size_t *out_len, size_t out_capacity)
{
  if (!orig_body || !out_buf || !out_len || orig_body_len == 0) {
    return -1;
  }

  if (orig_body_len >= out_capacity) {
    return -1;
  }

  /* If no kv_params, use original body unchanged */
  if (!kv_params || kv_params_len == 0) {
    memcpy(out_buf, orig_body, orig_body_len);
    *out_len = orig_body_len;
    return 0;
  }

  /* Copy original body to output buffer */
  memcpy(out_buf, orig_body, orig_body_len);

  /* Find last '}' in the body for injection point */
  int insert_pos = -1;
  int i;
  for (i = (int)orig_body_len - 1; i >= 0; i--) {
    if (out_buf[i] == '}') {
      insert_pos = i;
      break;
    }
  }

  if (insert_pos < 0) {
    /* No closing brace — malformed JSON, return original body */
    *out_len = orig_body_len;
    return 0;
  }

  /* Build injection string: ,"kv_transfer_params":<kv_params_json> */
  static const char kv_prefix[] = ",\"kv_transfer_params\":";
  size_t prefix_len = sizeof(kv_prefix) - 1;
  size_t inject_len = prefix_len + kv_params_len;

  /* Buffer overflow check */
  if (orig_body_len + inject_len >= out_capacity) {
    log_error("decode body overflow (%zu + %zu >= %zu) "
              "— using original body", orig_body_len, inject_len, out_capacity);
    *out_len = orig_body_len;
    return 0;
  }

  /* Shift closing '}' and anything after it to make room */
  memmove(out_buf + insert_pos + inject_len,
          out_buf + insert_pos,
          orig_body_len - (size_t)insert_pos);

  /* Insert ,"kv_transfer_params": prefix */
  memcpy(out_buf + insert_pos, kv_prefix, prefix_len);

  /* Insert the kv_params JSON value */
  memcpy(out_buf + insert_pos + prefix_len, kv_params, kv_params_len);

  *out_len = orig_body_len + inject_len;
  return 0;
}

/* ============================================================================
 * P/D Session Stickiness (Tier 0 cache-aware routing)
 *
 * Pins multi-turn conversations to the same (prefill, decode) endpoint pair.
 * Uses uthash for O(1) lookup, rwlock for concurrency, atomic last_access_ts
 * for benign updates under rdlock.
 * ============================================================================ */

#ifndef TEST_PD_REWRITER

#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include <limits.h>
#include "uthash.h"

#ifdef TEST_PD_CACHE_AWARE
/* Test mode: struct stubs provided by test file, skip sockproxy.h */
#else
#include "sockproxy.h"
#include "sockproxy_internal.h"
#endif

#define PD_SESSION_MAX_ENTRIES 4096
#define PD_SESSION_DEFAULT_TTL 300  /* 5 minutes */

/* sockproxy HA state-sync emit helpers.
 *
 * INVARIANT (sockproxy_internal.h emit-after-unlock contract):
 *   Caller MUST have released tepval->pd_session_lock BEFORE invoking these
 *   helpers. They are deliberately FREE functions (not methods on tepval)
 *   so the lock-state can be reasoned about statically per call-site.
 *
 * Service-key resolution: the parent proxy_map_ent_t is found by walking
 * proxy_struct->head under PROXY_RDLOCK (Pri-1). This is safe AFTER
 * pd_session_lock (Pri-4) is released — lock order Pri-1 < Pri-4 means
 * acquiring Pri-1 alone is never a hierarchy violation. Landmine L-7 is
 * mitigated because we are NOT holding any higher-priority lock here.
 *
 * Test builds (TEST_PD_*) compile these out — the test harness defines its
 * own llb_sockproxy_emit_sync_event mock and exercises the emit-after-unlock
 * property directly via the call-sites below.
 */
#ifndef TEST_PD_CACHE_AWARE

/* Resolve service_key for the proxy_map_ent_t that owns tepval. Returns 1
 * on success (out filled), 0 on miss. Walks proxy_struct->head under
 * rdlock — caller MUST NOT be holding pd_session_lock. */
static int
pd_session_resolve_service_key(const proxy_epval_t *tepval,
                               char *out, size_t out_len)
{
  proxy_map_ent_t   *node;
  const proxy_epval_t *iter, *tv_tmp;
  int found = 0;

  if (!tepval || !out || out_len < 24)
    return 0;

  pthread_rwlock_rdlock(&proxy_struct->lock);
  node = proxy_struct->head;
  while (node && !found) {
    HASH_ITER(hh, node->val.ephash, iter, tv_tmp) {
      if (iter == tepval) {
        uint32_t xip = node->key.xip;
        snprintf(out, out_len, "%u.%u.%u.%u:%u:%u",
                 (xip >> 24) & 0xFF, (xip >> 16) & 0xFF,
                 (xip >> 8) & 0xFF,  xip & 0xFF,
                 (unsigned)node->key.xport,
                 (unsigned)node->key.protocol);
        found = 1;
        break;
      }
    }
    if (!found) node = node->next;
  }
  pthread_rwlock_unlock(&proxy_struct->lock);
  return found;
}

/* Build a proxy_sync_event_t into *ev. Caller has ALREADY released
 * pd_session_lock. service_key resolution happens here (separate rdlock).
 * On resolution miss → ev->service_key stays empty; caller MUST refuse to
 * emit (preserves SPEC invariant that emitted events have a valid service_key).
 *
 * Returns 1 if event is emit-ready (service_key resolved), 0 otherwise. */
static int
pd_session_build_event(proxy_sync_event_t *ev,
                       const proxy_epval_t *tepval,
                       int kind,
                       const char *conv_id,
                       int prefill_ep, int decode_ep,
                       uint64_t created_ts, uint64_t last_access_ts,
                       uint32_t request_count)
{
  if (!ev || !tepval || !conv_id || conv_id[0] == '\0')
    return 0;

  memset(ev, 0, sizeof(*ev));
  ev->kind = kind;
  ev->prefill_ep_idx = prefill_ep;
  ev->decode_ep_idx  = decode_ep;
  ev->ep_idx         = -1;
  ev->created_ts     = created_ts;
  ev->last_access_ts = last_access_ts;
  ev->request_count  = request_count;

  strncpy(ev->conv_id, conv_id, sizeof(ev->conv_id) - 1);
  ev->conv_id[sizeof(ev->conv_id) - 1] = '\0';

  return pd_session_resolve_service_key(tepval, ev->service_key, sizeof(ev->service_key));
}

#else  /* TEST_PD_CACHE_AWARE — no proxy_struct singleton; build is a no-op. */
static inline int
pd_session_build_event(void *ev,
                       const proxy_epval_t *tepval,
                       int kind,
                       const char *conv_id,
                       int prefill_ep, int decode_ep,
                       uint64_t created_ts, uint64_t last_access_ts,
                       uint32_t request_count)
{
  (void)ev; (void)tepval; (void)kind; (void)conv_id;
  (void)prefill_ep; (void)decode_ep;
  (void)created_ts; (void)last_access_ts; (void)request_count;
  return 0;
}
#endif  /* TEST_PD_CACHE_AWARE */

/* No macro — each emit site below calls llb_sockproxy_emit_sync_event()
 * directly so the SPEC §verification grep counts each occurrence. The
 * pd_session_build_event() helper composes the struct; the actual emit is
 * inlined verbatim at each call site for grep-visibility. */

/*
 * pd_session_lookup() - Look up cached (prefill, decode) pair for a session key.
 *
 * Uses rdlock for concurrent reads. Updates last_access_ts atomically (benign
 * race under rdlock is acceptable for timestamp). Increments request_count
 * (benign race OK for counter).
 *
 * Returns 0 on hit (populates prefill_ep, decode_ep), -1 on miss or expired.
 */
int
pd_session_lookup(proxy_epval_t *tepval, const char *key,
                  int *prefill_ep, int *decode_ep)
{
  pd_session_mapping_t *m = NULL;
  uint64_t now;
  uint32_t ttl;

  if (!tepval || !key || !key[0] || !prefill_ep || !decode_ep)
    return -1;

  ttl = tepval->pd_session_ttl_sec ? tepval->pd_session_ttl_sec : PD_SESSION_DEFAULT_TTL;

  pthread_rwlock_rdlock(&tepval->pd_session_lock);
  HASH_FIND_STR(tepval->pd_session_map, key, m);
  if (m) {
    now = (uint64_t)time(NULL);
    if ((now - atomic_load(&m->last_access_ts)) > ttl) {
      /* Expired -- caller should treat as miss */
      pthread_rwlock_unlock(&tepval->pd_session_lock);
      return -1;
    }
    *prefill_ep = m->prefill_ep_idx;
    *decode_ep = m->decode_ep_idx;
    atomic_store(&m->last_access_ts, now);
    m->request_count++;  /* benign race OK for counter */
    pthread_rwlock_unlock(&tepval->pd_session_lock);
    return 0;
  }
  pthread_rwlock_unlock(&tepval->pd_session_lock);
  return -1;
}

/*
 * pd_session_store() - Upsert a session entry with LRU eviction at max_entries.
 *
 * Uses wrlock for exclusive access. If key exists: updates EP indices and
 * timestamps. If new: checks entry count, evicts oldest entry if at capacity,
 * then inserts.
 */
void
pd_session_store(proxy_epval_t *tepval, const char *key,
                 int prefill_ep, int decode_ep)
{
  pd_session_mapping_t *m = NULL;
  uint64_t now;
  /* emit-after-unlock state. Captured under wrlock, used after. */
  int      emit_kind = -1;                    /* -1 = no emit */
  uint64_t emit_created_ts = 0;
  uint32_t emit_request_count = 0;
  char     emit_evicted_conv_id[MAX_CONV_ID_LEN] = {0};
  uint64_t emit_evicted_created_ts = 0;

  if (!tepval || !key || !key[0])
    return;

  now = (uint64_t)time(NULL);

  pthread_rwlock_wrlock(&tepval->pd_session_lock);

  HASH_FIND_STR(tepval->pd_session_map, key, m);
  if (m) {
    /* Update existing entry */
    m->prefill_ep_idx = prefill_ep;
    m->decode_ep_idx = decode_ep;
    atomic_store(&m->last_access_ts, now);
    m->request_count++;
    /* emit-state #1: capture for SYNC_SESSION_UPDATE after unlock. */
    emit_kind = SYNC_SESSION_UPDATE;
    emit_created_ts = m->created_ts;
    emit_request_count = m->request_count;
    pthread_rwlock_unlock(&tepval->pd_session_lock);
    /* EMIT SITE #1 (sockproxy_pd.c) [PHASE_70_EMIT_PD_001] — update existing entry.
     * Emit-after-unlock: pd_session_lock released above. */
    {
      proxy_sync_event_t _ev70;
      if (pd_session_build_event(&_ev70, tepval, SYNC_SESSION_UPDATE, key,
                                 prefill_ep, decode_ep, emit_created_ts, now,
                                 emit_request_count))
        llb_sockproxy_emit_sync_event(&_ev70);
    }
    return;
  }

  /* New entry -- check capacity and evict LRU if needed */
  if (HASH_COUNT(tepval->pd_session_map) >= PD_SESSION_MAX_ENTRIES) {
    pd_session_mapping_t *iter, *tmp, *oldest = NULL;
    uint64_t oldest_ts = UINT64_MAX;

    HASH_ITER(hh, tepval->pd_session_map, iter, tmp) {
      uint64_t ts = atomic_load(&iter->last_access_ts);
      if (ts < oldest_ts) {
        oldest_ts = ts;
        oldest = iter;
      }
    }
    if (oldest) {
      /* emit-state #2: capture LRU victim for SYNC_SESSION_DELETE
       * emit after unlock (Landmine L-6 — batch under lock, emit after). */
      strncpy(emit_evicted_conv_id, oldest->conv_id, MAX_CONV_ID_LEN - 1);
      emit_evicted_conv_id[MAX_CONV_ID_LEN - 1] = '\0';
      emit_evicted_created_ts = oldest->created_ts;
      HASH_DEL(tepval->pd_session_map, oldest);
      free(oldest);
    }
  }

  m = calloc(1, sizeof(*m));
  if (!m) {
    pthread_rwlock_unlock(&tepval->pd_session_lock);
    /* Emit the LRU-eviction even on calloc failure (state changed).
 * EMIT SITE #2 (sockproxy_pd.c) [PHASE_70_EMIT_PD_002] — LRU eviction (calloc-fail path). */
    if (emit_evicted_conv_id[0] != '\0') {
      proxy_sync_event_t _ev70;
      if (pd_session_build_event(&_ev70, tepval, SYNC_SESSION_DELETE, emit_evicted_conv_id,
                                 -1, -1, emit_evicted_created_ts, now, 0))
        llb_sockproxy_emit_sync_event(&_ev70);
    }
    return;
  }
  strncpy(m->conv_id, key, MAX_CONV_ID_LEN - 1);
  m->conv_id[MAX_CONV_ID_LEN - 1] = '\0';
  m->prefill_ep_idx = prefill_ep;
  m->decode_ep_idx = decode_ep;
  m->created_ts = now;
  atomic_store(&m->last_access_ts, now);
  m->request_count = 1;
  HASH_ADD_STR(tepval->pd_session_map, conv_id, m);
  /* emit-state #3: capture for SYNC_SESSION_CREATE after unlock. */
  emit_kind = SYNC_SESSION_CREATE;
  emit_created_ts = m->created_ts;
  emit_request_count = m->request_count;

  pthread_rwlock_unlock(&tepval->pd_session_lock);

  /* EMIT SITE #3 (sockproxy_pd.c) [PHASE_70_EMIT_PD_003] — LRU eviction during insert
   * (post-calloc success path). Lands BEFORE the new entry's CREATE emit
   * so the receiver sees the same sequence of state transitions. */
  if (emit_evicted_conv_id[0] != '\0') {
    proxy_sync_event_t _ev70;
    if (pd_session_build_event(&_ev70, tepval, SYNC_SESSION_DELETE, emit_evicted_conv_id,
                               -1, -1, emit_evicted_created_ts, now, 0))
      llb_sockproxy_emit_sync_event(&_ev70);
  }

  /* EMIT SITE #4 (sockproxy_pd.c) [PHASE_70_EMIT_PD_004] — new-entry CREATE. */
  if (emit_kind == SYNC_SESSION_CREATE) {
    proxy_sync_event_t _ev70;
    if (pd_session_build_event(&_ev70, tepval, SYNC_SESSION_CREATE, key,
                               prefill_ep, decode_ep, emit_created_ts, now,
                               emit_request_count))
      llb_sockproxy_emit_sync_event(&_ev70);
  }
}

/*
 * pd_session_evict() - Batch evict all expired entries.
 *
 * Called from maintenance/cleanup loop. Uses wrlock.
 */
void
pd_session_evict(proxy_epval_t *tepval)
{
  pd_session_mapping_t *iter, *tmp;
  uint64_t now;
  uint32_t ttl;
  /* Landmine L-6: batch deletions to a stack-local list under
   * wrlock, emit AFTER unlock. Cap victims at 256 per pass; if more entries
   * are expired they will be picked up next tick (cleanup runs every 30s). */
  #define PD_SESSION_EVICT_BATCH 256
  struct {
    char     conv_id[MAX_CONV_ID_LEN];
    uint64_t created_ts;
  } victims[PD_SESSION_EVICT_BATCH];
  uint32_t n_victims = 0;

  if (!tepval)
    return;

  ttl = tepval->pd_session_ttl_sec ? tepval->pd_session_ttl_sec : PD_SESSION_DEFAULT_TTL;
  now = (uint64_t)time(NULL);

  pthread_rwlock_wrlock(&tepval->pd_session_lock);
  HASH_ITER(hh, tepval->pd_session_map, iter, tmp) {
    if ((now - atomic_load(&iter->last_access_ts)) > ttl) {
      if (n_victims < PD_SESSION_EVICT_BATCH) {
        strncpy(victims[n_victims].conv_id, iter->conv_id, MAX_CONV_ID_LEN - 1);
        victims[n_victims].conv_id[MAX_CONV_ID_LEN - 1] = '\0';
        victims[n_victims].created_ts = iter->created_ts;
        n_victims++;
      }
      HASH_DEL(tepval->pd_session_map, iter);
      free(iter);
    }
  }
  pthread_rwlock_unlock(&tepval->pd_session_lock);

  /* EMIT SITE #5 (sockproxy_pd.c) [PHASE_70_EMIT_PD_005] — bulk TTL evict.
   * Emit-after-unlock: per-victim DELETE events. Landmine L-6 compliant. */
  for (uint32_t i = 0; i < n_victims; i++) {
    proxy_sync_event_t _ev70;
    if (pd_session_build_event(&_ev70, tepval, SYNC_SESSION_DELETE, victims[i].conv_id,
                               -1, -1, victims[i].created_ts, now, 0))
      llb_sockproxy_emit_sync_event(&_ev70);
  }
  #undef PD_SESSION_EVICT_BATCH
}

/*
 * pd_session_evict_key() - Remove a single session entry by key.
 *
 * Used when an EP goes down (health-check failure path).
 */
void
pd_session_evict_key(proxy_epval_t *tepval, const char *key)
{
  pd_session_mapping_t *m = NULL;
  /* capture state under lock, emit after unlock. */
  int emit_was_present = 0;
  uint64_t emit_created_ts = 0;

  if (!tepval || !key || !key[0])
    return;

  pthread_rwlock_wrlock(&tepval->pd_session_lock);
  HASH_FIND_STR(tepval->pd_session_map, key, m);
  if (m) {
    emit_was_present = 1;
    emit_created_ts = m->created_ts;
    HASH_DEL(tepval->pd_session_map, m);
    free(m);
  }
  pthread_rwlock_unlock(&tepval->pd_session_lock);

  /* EMIT SITE #6 (sockproxy_pd.c) [PHASE_70_EMIT_PD_006] — single-key evict.
   * Emit-after-unlock contract preserved. */
  if (emit_was_present) {
    proxy_sync_event_t _ev70;
    if (pd_session_build_event(&_ev70, tepval, SYNC_SESSION_DELETE, key, -1, -1,
                               emit_created_ts, (uint64_t)time(NULL), 0))
      llb_sockproxy_emit_sync_event(&_ev70);
  }
}

/* ============================================================================
 * 3-Tier P/D Endpoint Selection (: Cache-Aware Routing)
 *
 * pd_select_prefill: Tier 0 (session) -> Tier 1 (trie) -> Tier 2 (min-load)
 * pd_select_decode:  Session hint -> min-load among decode EPs
 * ============================================================================ */

/*
 * pd_select_prefill() - Select prefill EP via 3-tier fallback.
 *
 * Tier 0: Session stickiness (always active for pd_disagg services)
 * Tier 1: Radix trie cache affinity (gated by pd_cache_aware_mode)
 * Tier 2: Min-load among healthy prefill EPs
 *
 * excluded_mask: bitmask of EP indices to skip unconditionally.
 *   Pass 0 for normal (first-attempt) selection.
 *   Pass (1u << failed_ep) for mid-cycle failover retries so that an EP
 *   whose TCP connect just failed is not re-selected even though its inv flag
 *   has not yet been updated by the health-check cycle.
 *
 * IMPORTANT: Does NOT call pd_session_store() — that happens at the call site
 * after BOTH prefill and decode EPs are selected (INTG-04).
 *
 * Returns 0 on success (*ep_out set), -1 if no healthy prefill EP found.
 */

/* KV-exact load-balancing experiment toggles (cached getenv, read once).
 * Default 0 = the shipped unguarded KV-exact (Tier 1.5 routes purely by KV-cache
 * overlap, no load awareness — diagnosed prefill hot-spot, C1 TTFT p90 ~2x RR).
 *   LLB_KV_LOADGUARD=1  Approach A: hard load-imbalance guard at the T1.5 call site,
 *                       mirroring the existing Tier-1 guard (skip KV-exact when
 *                       (max-min) active_conns > pd_balance_abs_threshold).
 *   LLB_KV_LOADBLEND=1  Approach B: soft blend — penalise loaded EPs inside the
 *                       overlap scorer (llb_ai_kv_best_worker), no hard cutoff. */
static int
pd_kv_loadguard_on(void)
{
  static int cached = -1;
  int v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
  if (v >= 0) return v;
  const char *e = getenv("LLB_KV_LOADGUARD");
  v = (e && *e && *e != '0') ? 1 : 0;
  __atomic_store_n(&cached, v, __ATOMIC_RELEASE);
  return v;
}

/* distinct return for "all prefill EPs at in-flight cap". Normally provided
 * by sockproxy.h, but under the unit-test guards (TEST_PD_CACHE_AWARE) sockproxy.h is
 * not included, so define it here too (idempotent #ifndef). */
#ifndef PD_PREFILL_NO_CAPACITY
#define PD_PREFILL_NO_CAPACITY (-2)
#endif

/* distinct return for "all prefill EPs capped but a per-EP parked
 * FIFO has room" (hold-don't-drop). Like PD_PREFILL_NO_CAPACITY, normally from
 * sockproxy.h but absent under TEST_PD_CACHE_AWARE — define idempotently. */
#ifndef PD_PREFILL_PARKED
#define PD_PREFILL_PARKED (-3)
#endif

/* compile cap for the per-EP parked ring (sockproxy.h provides it in
 * production; define here for the cache_aware unit build where sockproxy.h is skipped). */
#ifndef PD_MAX_QUEUE_DEPTH
#define PD_MAX_QUEUE_DEPTH 64
#endif

/* PD_CTRL_* packed-word constants + accessors. Normally provided
 * by sockproxy.h; absent under the TEST_PD_CACHE_AWARE unit build — define
 * idempotently (PD_PREFILL_NO_CAPACITY precedent). State values are lockstep with
 * the frozen loxilb.aictrl.v1 EpState enum : 1=ACTIVE 2=DRAINING 3=DISABLED,
 * 0=no-instruction. Packed layout: state bits 31-24, weight bits 7-0 [0,100]. */
#ifndef PD_CTRL_ST_NONE
#define PD_CTRL_ST_NONE     0
#define PD_CTRL_ST_ACTIVE   1
#define PD_CTRL_ST_DRAINING 2
#define PD_CTRL_ST_DISABLED 3
#define PD_CTRL_STATE(p)  (((p) >> 24) & 0xff)
#define PD_CTRL_WEIGHT(p) ((p) & 0xff)
#endif

/* per-EP in-flight admission cap (env LLB_PD_MAX_INFLIGHT_PER_EP, cached
 * getenv-once). 0/unset = DISABLED -> pd_select_prefill is byte-identical to today
 * (back-compat). When >0, pd_select_prefill excludes any prefill EP whose real-time
 * active_conns >= cap so selection spills to an under-cap EP across ALL tiers; when
 * every healthy prefill EP is at cap it returns PD_PREFILL_NO_CAPACITY and the
 * dispatch site sheds a retriable 429. This bounds the backend queue depth loxilb
 * creates per prefill EP -> bounds tail TTFT (the Phase-92 vs-vllm-router gap). The
 * signal is loxilb's own active_conns (real-time), NOT the 10s-stale scraped queue. */
static uint32_t
pd_max_inflight_per_ep(void)
{
  static int cached = -1;  /* -1 = unresolved; >=0 = resolved cap (0 = disabled) */
  int v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
  if (v >= 0) return (uint32_t)v;
  v = 0;
  const char *e = getenv("LLB_PD_MAX_INFLIGHT_PER_EP");
  if (e && *e) {
    long n = strtol(e, NULL, 10);
    if (n > 0 && n < 100000) v = (int)n;
  }
  __atomic_store_n(&cached, v, __ATOMIC_RELEASE);
  return (uint32_t)v;
}

/* count of requests shed by the in-flight cap (observability; also logged
 * per shed via [PD_ADMISSION]). File-static atomic — no global_stats struct churn. */
static _Atomic uint64_t pd_admission_shed_total = 0;

/* bounded backpressured admission — per-EP parked FIFO depth (env
 * LLB_PD_QUEUE_DEPTH_PER_EP, cached getenv-once; mirrors pd_max_inflight_per_ep
 * EXACTLY). 0/unset = DISABLED -> the all-capped branch sheds a 429 exactly as
 * (byte-identical back-compat). When >0 (clamped to PD_MAX_QUEUE_DEPTH),
 * the all-capped branch ENQUEUES the request onto the least-loaded eligible EP's
 * FIFO (hold-don't-drop) and returns PD_PREFILL_PARKED; 429 then fires ONLY when
 * every candidate FIFO is also full (overflow valve).: non-static so the
 * pd_cleanup dequeue hook (sockproxy_http.c) can gate on it (default-off invariant). */
uint32_t
pd_queue_depth_per_ep(void)
{
  static int cached = -1;  /* -1 = unresolved; >=0 = resolved depth (0 = disabled) */
  int v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
  if (v >= 0) return (uint32_t)v;
  v = 0;
  const char *e = getenv("LLB_PD_QUEUE_DEPTH_PER_EP");
  if (e && *e) {
    long n = strtol(e, NULL, 10);
    if (n > 0) {
      if (n > PD_MAX_QUEUE_DEPTH) n = PD_MAX_QUEUE_DEPTH;  /* clamp to ring capacity */
      v = (int)n;
    }
  }
  __atomic_store_n(&cached, v, __ATOMIC_RELEASE);
  return (uint32_t)v;
}

/* admission observability — requests held (parked, NOT shed) by the
 * FIFO, and requests shed only because every candidate FIFO was also full
 * (overflow valve). File-static atomics mirroring pd_admission_shed_total. */
static _Atomic uint64_t pd_admission_queued_total = 0;
static _Atomic uint64_t pd_admission_overflow_shed_total = 0;

/* [PD_CTRL] fold-in transition observability. A DISABLED/DRAINING
 * EP folds on EVERY selection while the snapshot holds, so logging per request
 * would spam the hot path — instead we log + count only on TRANSITIONS of the
 * folded set (the [PD_ADMISSION] tagged-prefix shape, rare-event discipline).
 * fold_state packs (disabled_mask << 32) | draining_mask; the counter mirrors the
 * pd_admission_* file-static pattern (no global_stats churn — accessor export can
 * follow the pd_admission_stats_get seam when OBS-02 lands with the applier; logs
 * are SECONDARY evidence per P11, Prometheus export is the primary). NOTE: state
 * is file-global across services (MVP — single P/D service per deployment today). */
static _Atomic uint64_t pd_ctrl_fold_state = 0;
static _Atomic uint64_t pd_ctrl_fold_transitions_total = 0;

/* (OBS-01): read-only export of the Phase-93 file-static admission
 * counters for the Prometheus snapshot (proxy_get_metrics in sockproxy_metrics.c).
 * The accessor route is deliberate — the Phase-93 comments above explicitly
 * avoided global_stats struct churn, so the counters stay file-static and are
 * exported through this one seam (migration to global_stats noted as debt in
 * -SUMMARY). which==0 -> shed_total, which==1 -> queued_total, any other
 * value -> 0. Prototype lives next to proxy_get_metrics in sockproxy_metrics.h. */
uint64_t
pd_admission_stats_get(int which)
{
  switch (which) {
  case 0:  return atomic_load(&pd_admission_shed_total);
  case 1:  return atomic_load(&pd_admission_queued_total);
  default: return 0;
  }
}

/* CLOCK_MONOTONIC nanoseconds (matches the sockproxy_http.c reaper
 * idiom). Stamped on each parked entry's enqueue_ns for the max-park reap. */
static uint64_t
pd_now_ns(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* ===========================================================================
 * H-17 (metrics audit): scraper queue-depth staleness guard.
 *
 * queued_requests is pushed by the Go vLLM scraper; when an EP dies or its
 * /metrics endpoint becomes unreachable the pushes stop, and without a guard
 * the scorers keep trusting the LAST value forever — a dead EP whose final
 * report was queue=0 looks least-loaded indefinitely and swallows traffic.
 *
 * llb_ai_update_ep_queue_depth stamps last_update_ts (CLOCK_MONOTONIC secs)
 * on every push. A value older than PD_QUEUE_STALE_SEC (3x the default 10s
 * scrape interval) is no longer trusted: the scorer substitutes the average
 * fresh queue depth of the candidate set (neutral — the EP is neither favored
 * nor punished on a signal nobody is refreshing). ts==0 means the scraper
 * never reported at all; queued_requests is 0 there, preserving the legacy
 * min-active_conns behavior when no scraper runs.
 * =========================================================================== */
#define PD_QUEUE_STALE_SEC 30

static inline int
pd_queued_is_fresh(ep_load_tracker_t *ld, uint64_t now_sec)
{
  uint64_t ts = atomic_load(&ld->last_update_ts);
  return !(ts != 0 && now_sec > ts && now_sec - ts > PD_QUEUE_STALE_SEC);
}

static inline uint32_t
pd_queued_or_fill(ep_load_tracker_t *ld, uint64_t now_sec, uint32_t stale_fill)
{
  if (!pd_queued_is_fresh(ld, now_sec))
    return stale_fill;
  return atomic_load(&ld->queued_requests);
}

/* ===========================================================================
 * bounded-admission FIFO dequeue + reap primitives.
 *
 * These are pure ring-buffer ops on a single pd_parked_fifo_t. They do NOT take
 * pd_parked_lock — the CALLER holds it (the production callers run them under
 * tepval->pd_parked_lock, exactly like the enqueue). They never touch a
 * pfe, never free, never dispatch: the UAF-critical re-drive/teardown happens in
 * the caller (sockproxy_http.c dequeue hook on the pinned owner; sockproxy_health.c
 * reap via the single-owner pd_teardown_conn). Single-sourcing the FIFO math here
 * lets test_pd_admission exercise it ASan-clean without sockproxy_http/health.
 * =========================================================================== */

/* Pop the OLDEST parked entry (FIFO head). Returns 1 and fills *out on success,
 * 0 when the FIFO is empty. O(1). Exported (non-static) so the production dequeue
 * hook in sockproxy_http.c and the reap in sockproxy_health.c call the SAME math. */
int
pd_parked_pop_head(pd_parked_fifo_t *q, pd_parked_ent_t *out)
{
  if (!q || q->count == 0) return 0;
  if (out) *out = q->slot[q->head];
  q->head = (uint16_t)((q->head + 1) % PD_MAX_QUEUE_DEPTH);
  q->count--;
  return 1;
}

/* Peek the OLDEST parked entry without popping. Returns 1 + fills *out, else 0.
 * Used by the max-park reap to test the head's age before committing to a pop. */
int
pd_parked_peek_head(const pd_parked_fifo_t *q, pd_parked_ent_t *out)
{
  if (!q || q->count == 0) return 0;
  if (out) *out = q->slot[q->head];
  return 1;
}

/* Remove the entry matching want_fd (and, if want_gen!=0, also want_gen) from the
 * FIFO regardless of position, preserving FIFO order of the survivors. Returns 1
 * if removed, 0 if not found. O(count). Used by the reap path to drop a specific
 * aged parked conn that the caller already chose to tear down. */
int
pd_parked_remove_fd(pd_parked_fifo_t *q, int want_fd, uint64_t want_gen)
{
  if (!q || q->count == 0) return 0;
  uint16_t n = q->count;
  uint16_t idx = q->head;
  int found = 0;
  pd_parked_ent_t keep[PD_MAX_QUEUE_DEPTH];
  uint16_t nk = 0;
  for (uint16_t k = 0; k < n; k++) {
    pd_parked_ent_t e = q->slot[idx];
    idx = (uint16_t)((idx + 1) % PD_MAX_QUEUE_DEPTH);
    if (!found && e.fd == want_fd && (want_gen == 0 || e.gen == want_gen)) {
      found = 1;
      continue;  /* drop this one */
    }
    keep[nk++] = e;
  }
  if (!found) return 0;
  /* Re-lay survivors compactly from index 0. */
  q->head = 0;
  q->tail = nk;
  q->count = nk;
  for (uint16_t k = 0; k < nk; k++) q->slot[k] = keep[k];
  return 0 == 0 ? 1 : 0;
}

/* Runtime max-park bound (env LLB_PD_MAX_PARK_SEC), cached getenv-once — mirrors
 * pd_queue_depth_per_ep EXACTLY. 0/unset = DISABLED (no reap; the entry only
 * leaves the FIFO via slot-free dequeue). When >0, a parked conn older than this
 * many seconds is reaped (504 + single-owner teardown). The default is 0 so the
 * reap pass is a strict no-op unless the operator opts in alongside the queue. */
uint32_t
pd_max_park_sec(void)
{
  static int cached = -1;  /* -1 = unresolved; >=0 = resolved seconds (0 = disabled) */
  int v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
  if (v >= 0) return (uint32_t)v;
  v = 0;
  const char *e = getenv("LLB_PD_MAX_PARK_SEC");
  if (e && *e) {
    long n = strtol(e, NULL, 10);
    if (n > 0 && n < 100000) v = (int)n;
  }
  __atomic_store_n(&cached, v, __ATOMIC_RELEASE);
  return (uint32_t)v;
}

/* : global total in-flight+queued footprint bound (env
 * LLB_PD_MAX_TOTAL_INFLIGHT), cached getenv-once — mirrors pd_max_park_sec
 * EXACTLY. 0/unset = DISABLED ⇒ accept() is byte-identical (no gate, no counter
 * check). When >0, accept() refuses a new client connection once the global
 * pd_admission_total_inflight gauge has reached this bound, leaving the SYN in
 * the listen(fd,32) backlog so the kernel applies natural TCP backpressure (the
 * XDP-safest primitive under --net=host — no established-conn epoll/XDP state is
 * touched). This is a SEPARATE outer guard from the per-EP cap and the
 * per-EP FIFO (/05). */
uint32_t
pd_max_total_inflight(void)
{
  static int cached = -1;  /* -1 = unresolved; >=0 = resolved bound (0 = disabled) */
  int v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
  if (v >= 0) return (uint32_t)v;
  v = 0;
  const char *e = getenv("LLB_PD_MAX_TOTAL_INFLIGHT");
  if (e && *e) {
    long n = strtol(e, NULL, 10);
    if (n > 0 && n < 2000000000L) v = (int)n;
  }
  __atomic_store_n(&cached, v, __ATOMIC_RELEASE);
  return (uint32_t)v;
}

/* : the pure accept-gate decision, factored out so it is
 * unit-testable in isolation (the accept loop itself is hard to drive standalone
 * — integration is covered by the live conc=128 gate + footprint soak). Returns
 * 1 = ACCEPT, 0 = REFUSE. bound==0 (feature off) ALWAYS accepts (byte-identical).
 * REFUSE iff bound>0 AND cur_inflight >= bound. */
int
pd_admission_should_accept(uint64_t cur_inflight, uint32_t bound)
{
  if (bound == 0) return 1;                  /* feature OFF: never gate */
  return cur_inflight < (uint64_t)bound;     /* ACCEPT iff strictly under the bound */
}

/* advisory DRAINING predicate for NEW-session assignment.
 *
 * Design rationale : the controller path deliberately does NOT
 * write tepval->drain_state[] — that array is owned by the local health
 * machinery (proxy_update_ep_health writer, check_draining_endpoints reaper),
 * and a second writer would need origin tracking to clear safely. (Survey
 * finding: drain_state[] is never consulted inside the selection path at all —
 * local draining excludes EPs from selection via eps[i].inv; the timed/immediate
 * policies only force-close established conns.) So the controller's DRAINING
 * verb is composed by OR-extending every NEW-session eligibility predicate in
 * pd_select_prefill with this check:
 *   - OR can only SHRINK eligibility — a locally-inv/CB-open/excluded EP stays
 *     ineligible regardless of the snapshot (local-wins by construction, G4);
 *   - the advisory vanishes the moment the packed word clears (write 0) —
 *     pure-intersection compliant (P4);
 *   - Tier-0 pinned sessions intentionally do NOT consult this: DRAINING
 *     excludes NEW assignment only; existing sessions drain gracefully
 *     (mirrors the one existing graceful-drain concept).
 * cmode is the caller's already-loaded pd_ctrl_mode so the mode-0 hot path pays
 * ZERO extra atomic loads (G3). */
static inline int
pd_ctrl_draining(proxy_epval_t *tepval, int i, uint8_t cmode)
{
  if (cmode == 0) return 0;  /* controller absent — never drains anything */
  return PD_CTRL_STATE(atomic_load(&tepval->pd_ctrl_ep[i])) == PD_CTRL_ST_DRAINING;
}

/* controller weight applied to an EP's CLAMPED effective
 * capacity in the Tier-2 scorer. weight 100 or packed==0 (no instruction) is an
 * arithmetic no-op; weight>100 is clamped to 100 ( pure-intersection —
 * the snapshot may only scale capacity down-or-neutral, never widen); weight 0
 * is treated as "no weight instruction" here per the plan's Tier-2 contract
 * (true removal is a STATE — DISABLED — not a weight). Integer math only; the
 * >=1 floor mirrors pd_kv_clamp_capacity (V5 — never zero the weighted sum). */
static inline uint64_t
pd_ctrl_eff_cap(proxy_epval_t *tepval, int i, uint64_t clamped_cap, uint8_t cmode)
{
  if (cmode == 0) return clamped_cap;  /* G3: zero controller work at mode 0 */
  uint32_t w = PD_CTRL_WEIGHT(atomic_load(&tepval->pd_ctrl_ep[i]));
  if (w == 0 || w >= 100) return clamped_cap;
  uint64_t eff = clamped_cap * w / 100;
  if (eff < 1) eff = 1;
  return eff;
}

int
pd_select_prefill(proxy_epval_t *tepval, proxy_fd_ent_t *pfe, int *ep_out,
                  uint32_t excluded_mask)
{
  /* --: global-controller advisory fold-in (SNAP-03/04) ---
   * G3 guard order (Pitfall 2): read pd_ctrl_mode FIRST. mode 0 == controller
   * absent/autonomous == ZERO further controller work (no loop, no pd_ctrl_ep
   * loads) — the Phase-95 byte-identical hot path. mode != 0: ONE walk over
   * pd_ctrl_ep[] collects
   *   (a) DISABLED bits -> OR'd into excluded_mask BEFORE any tier body. Every
   *       tier already honors excluded_mask, and the per-tier CB/health checks
   *       run AFTER this fold-in, so the applier's word can only SHRINK
   *       eligibility — a locally-excluded/CB-open EP is never resurrected by
 * an ACTIVE snapshot (G4 ordering; pure intersection);
   *   (b) DRAINING bits -> ctrl_drain, consumed via pd_ctrl_draining() at the
   *       NEW-session assignment predicates below and OR'd into the mask passed
   *       to Tier 1.5's pd_kv_exact_select (Tier-0 pinned sessions keep routing
   *       to a DRAINING EP — graceful-drain semantics). */
  uint8_t cmode = atomic_load(&tepval->pd_ctrl_mode);
  uint32_t ctrl_drain = 0;
  if (cmode != 0) {
    uint32_t ctrl_excl = 0;
    for (int i = 0; i < tepval->n_eps && i < 32; i++) {
      uint32_t st = PD_CTRL_STATE(atomic_load(&tepval->pd_ctrl_ep[i]));
      if (st == PD_CTRL_ST_DISABLED)
        ctrl_excl |= (1u << (unsigned)i);
      else if (st == PD_CTRL_ST_DRAINING)
        ctrl_drain |= (1u << (unsigned)i);
    }
    excluded_mask |= ctrl_excl;
    /* [PD_CTRL] transition-edge observability ([PD_ADMISSION] shape): log +
     * count only when the folded set CHANGES, never per request. */
    uint64_t fold_now = ((uint64_t)ctrl_excl << 32) | (uint64_t)ctrl_drain;
    uint64_t fold_prev = atomic_exchange(&pd_ctrl_fold_state, fold_now);
    if (fold_prev != fold_now) {
      uint64_t tn = atomic_fetch_add(&pd_ctrl_fold_transitions_total, 1) + 1;
      (void)tn;  /* consumed by log_info below (no-op in unit-test builds) */
      log_info("[PD_CTRL] fd=%d fold-in transition: disabled_mask=0x%x->0x%x "
               "draining_mask=0x%x->0x%x mode=%u (transitions_total=%lu)",
               pfe ? pfe->fd : -1, (uint32_t)(fold_prev >> 32), ctrl_excl,
               (uint32_t)fold_prev, ctrl_drain, (unsigned)cmode,
               (unsigned long)tn);
    }
  }

  /* --: per-EP in-flight admission cap (excluded_mask augmentation) ---
   * Exclude prefill EPs already at the in-flight cap so every tier below spills to
   * an under-cap EP; if ALL healthy prefill EPs are at cap, shed (caller -> 429).
   * cap==0 -> skip entirely (byte-identical back-compat). */
  {
    uint32_t cap = pd_max_inflight_per_ep();
    if (cap > 0) {
      uint32_t cap_excl = 0;
      int healthy_elig = 0, under_cap = 0;
      for (int i = 0; i < tepval->n_eps && i < 32; i++) {
        if (tepval->ep_role[i] != 1 || tepval->eps[i].inv) continue;
        if (excluded_mask & (1u << (unsigned)i)) continue;
        if (tepval->cb_enabled &&
            tepval->circuit_breakers[i].state == CB_STATE_OPEN) continue;
        if (pd_ctrl_draining(tepval, i, cmode)) continue;  /* no NEW work */
        healthy_elig++;
        if (atomic_load(&tepval->pd_ep_loads[i].active_conns) >= cap)
          cap_excl |= (1u << (unsigned)i);
        else
          under_cap++;
      }
      if (healthy_elig > 0 && under_cap == 0) {
        /* All healthy prefill EPs at the in-flight cap. */
        uint32_t depth = pd_queue_depth_per_ep();
        if (depth == 0) {
          /* Default-off: shed (retriable) exactly as . Byte-identical. */
          uint64_t n = atomic_fetch_add(&pd_admission_shed_total, 1) + 1;
          (void)n;  /* consumed by log_info below (no-op in unit-test builds) */
          log_info("[PD_ADMISSION] fd=%d shed: all %d healthy prefill EPs at in-flight "
                   "cap=%u (shed_total=%lu)", pfe ? pfe->fd : -1, healthy_elig, cap,
                   (unsigned long)n);
          return PD_PREFILL_NO_CAPACITY;
        }
        /* hold-don't-drop. Pick the eligible (healthy, capped, not
         * excluded) prefill EP with the SHORTEST parked FIFO; if its depth < the
         * runtime bound, ENQUEUE (fd, gen, now) and PARK. Only when EVERY eligible
         * FIFO is also full do we shed (overflow valve). Selection re-walks the EPs
         * (the cap loop already proved they are all capped & eligible) under
         * pd_parked_lock so the depth read and the enqueue are atomic together. */
        pthread_mutex_lock(&tepval->pd_parked_lock);
        int park_ep = -1;
        uint32_t best_count = depth;  /* only EPs strictly under bound qualify */
        for (int i = 0; i < tepval->n_eps && i < 32; i++) {
          if (tepval->ep_role[i] != 1 || tepval->eps[i].inv) continue;
          if (excluded_mask & (1u << (unsigned)i)) continue;
          if (tepval->cb_enabled &&
              tepval->circuit_breakers[i].state == CB_STATE_OPEN) continue;
          if (pd_ctrl_draining(tepval, i, cmode)) continue;  /* no NEW work */
          uint32_t c = tepval->pd_parked[i].count;
          if (c < best_count) { best_count = c; park_ep = i; }
        }
        if (park_ep >= 0) {
          pd_parked_fifo_t *q = &tepval->pd_parked[park_ep];
          uint64_t pg = pfe ? atomic_load_explicit(&pfe->gen, memory_order_relaxed) : 0;
          uint64_t now = pd_now_ns();
          q->slot[q->tail].fd = pfe ? pfe->fd : -1;
          q->slot[q->tail].gen = pg;
          q->slot[q->tail].enqueue_ns = now;
          q->tail = (uint16_t)((q->tail + 1) % PD_MAX_QUEUE_DEPTH);
          q->count++;
          pthread_mutex_unlock(&tepval->pd_parked_lock);
          if (pfe) {
            pfe->park_ep_idx   = park_ep;
            pfe->park_start_ts = now;
          }
          uint64_t qn = atomic_fetch_add(&pd_admission_queued_total, 1) + 1;
          (void)qn;
          log_info("[PD_ADMISSION] fd=%d PARKED ep=%d depth=%u bound=%u "
                   "(queued_total=%lu)", pfe ? pfe->fd : -1, park_ep,
                   (unsigned)(best_count + 1), depth, (unsigned long)qn);
          *ep_out = park_ep;  /* expose the parked EP to the caller/unit (not a dispatch) */
          return PD_PREFILL_PARKED;
        }
        /* Every eligible FIFO is also at the bound -> overflow: shed (429). */
        pthread_mutex_unlock(&tepval->pd_parked_lock);
        uint64_t on = atomic_fetch_add(&pd_admission_overflow_shed_total, 1) + 1;
        (void)on;
        log_info("[PD_ADMISSION] fd=%d overflow shed: all %d healthy prefill EPs at "
                 "cap=%u AND parked FIFO full (bound=%u, overflow_shed_total=%lu)",
                 pfe ? pfe->fd : -1, healthy_elig, cap, depth, (unsigned long)on);
        return PD_PREFILL_NO_CAPACITY;
      }
      /* At least one under-cap EP: hide the capped ones from all tiers below. */
      excluded_mask |= cap_excl;
    }
  }

  /* --- Tier 0: Session stickiness (always active for pd_disagg) --- */
  const char *session_key = NULL;
  const char *session_key_src = "none";
  /* Prefer explicit user_id over auto-generated conversation_id (prefix "auto-").
   * Client-provided X-Conversation-Id still takes highest priority. */
  if (pfe->has_user_id && pfe->user_id[0] != '\0') {
    session_key = pfe->user_id;
    session_key_src = "user_id";  /* TE2: stickiness via JSON user field */
  }
  if (pfe->has_conv_id && pfe->conversation_id[0] != '\0' &&
      strncmp(pfe->conversation_id, "auto-", 5) != 0) {
    session_key = pfe->conversation_id;  /* Client-provided overrides user_id */
    session_key_src = "conv_id";          /* TE1/TE3/TE4/TE5: X-Conversation-Id */
  }

  if (session_key) {
    int pre, dec;
    if (pd_session_lookup(tepval, session_key, &pre, &dec) == 0) {
      /* Health check: pinned EP must be healthy AND not in the excluded mask */
      if (pre >= 0 && pre < tepval->n_eps &&
          !(excluded_mask & (1u << (unsigned)pre)) &&
          !tepval->eps[pre].inv &&
          !(tepval->cb_enabled &&
            tepval->circuit_breakers[pre].state == CB_STATE_OPEN)) {
        pfe->pd_decode_ep_idx = dec;  /* Pass decode hint to pd_select_decode */
        *ep_out = pre;
        /* US-H105: Record Tier-0 session stickiness hit for Prometheus */
#if !defined(TEST_PD_REWRITER) && !defined(TEST_PD_CACHE_AWARE)
        {
          const char *sh_model = "";
          if (pfe->x_model_header[0] != '\0') {
            sh_model = pfe->x_model_header;
          } else if (pfe->prefix_key.model[0] != '\0') {
            sh_model = pfe->prefix_key.model;
          }
          llb_ai_pd_session_hit((char *)sh_model);
        }
#endif
        return 0;  /* Tier 0 hit */
      }
      /* Stale session: evict, fall through */
      pd_session_evict_key(tepval, session_key);
    }
  }

  /* --- Tier 1: Radix trie (when pd_cache_aware_mode=1) --- */
  if (tepval->pd_cache_aware_mode && tepval->pd_trie &&
      pfe->prefix_key.prefix[0] != '\0') {
    /* Load-imbalance guard: compute min/max among healthy prefill EPs */
    /* Bug2-fix: use uint32_t to match _Atomic uint32_t active_conns type */
    uint32_t min_load = UINT32_MAX, max_load = 0;
    for (int i = 0; i < tepval->n_eps; i++) {
      if (tepval->ep_role[i] != 1 || tepval->eps[i].inv) continue;
      if (excluded_mask & (1u << (unsigned)i)) continue;
      if (tepval->cb_enabled &&
          tepval->circuit_breakers[i].state == CB_STATE_OPEN) continue;
      if (pd_ctrl_draining(tepval, i, cmode)) continue;  /* not a candidate */
      uint32_t load = atomic_load(&tepval->pd_ep_loads[i].active_conns);
      if (load < min_load) min_load = load;
      if (load > max_load) max_load = load;
    }

    if ((max_load - min_load) <= (uint32_t)tepval->pd_balance_abs_threshold) {
      int trie_ep = -1;
      float match_rate = 0.0f;
      pthread_rwlock_rdlock(&tepval->pd_trie_lock);
      pd_trie_match(tepval->pd_trie, pfe->prefix_key.prefix,
                    strlen(pfe->prefix_key.prefix), &trie_ep, &match_rate);
      pthread_rwlock_unlock(&tepval->pd_trie_lock);

      float threshold = (tepval->pd_cache_threshold ? tepval->pd_cache_threshold : 20) / 100.0f;
      if (trie_ep >= 0 && match_rate >= threshold &&
          !(excluded_mask & (1u << (unsigned)trie_ep)) &&
          !tepval->eps[trie_ep].inv &&
          !(tepval->cb_enabled &&
            tepval->circuit_breakers[trie_ep].state == CB_STATE_OPEN) &&
          !pd_ctrl_draining(tepval, trie_ep, cmode) /* no NEW work */) {
        /* Tier 1 hit — update trie timestamp */
        pthread_rwlock_wrlock(&tepval->pd_trie_lock);
        pd_trie_insert(tepval->pd_trie, pfe->prefix_key.prefix,
                       strlen(pfe->prefix_key.prefix), trie_ep);
        pthread_rwlock_unlock(&tepval->pd_trie_lock);
        *ep_out = trie_ep;
        return 0;
      }
    }
  }

  /* -- Tier 1.5: KV block-hash exact routing --- */
  if (tepval->kv_exact_mode == 1) {
    /* Approach A (env LLB_KV_LOADGUARD=1): hard load-imbalance guard that
     * mirrors the Tier-1 (radix-trie) guard above. KV-exact has NO load awareness,
     * so under a shared-prefix trace it hot-spots the cache-owner prefill EP. Only
     * honor cache affinity while prefill load is balanced; once
     * (max_load-min_load) > pd_balance_abs_threshold, fall through to Tier-2 min-load. */
    int kv_loadguard_ok = 1;
    if (pd_kv_loadguard_on()) {
      uint32_t min_load = UINT32_MAX, max_load = 0;
      for (int i = 0; i < tepval->n_eps; i++) {
        if (tepval->ep_role[i] != 1 || tepval->eps[i].inv) continue;
        if (excluded_mask & (1u << (unsigned)i)) continue;
        if (tepval->cb_enabled &&
            tepval->circuit_breakers[i].state == CB_STATE_OPEN) continue;
        if (pd_ctrl_draining(tepval, i, cmode)) continue;  /* not a candidate */
        uint32_t load = atomic_load(&tepval->pd_ep_loads[i].active_conns);
        if (load < min_load) min_load = load;
        if (load > max_load) max_load = load;
      }
      if (min_load == UINT32_MAX) min_load = 0;  /* no eligible EP → no imbalance */
      if ((max_load - min_load) > (uint32_t)tepval->pd_balance_abs_threshold) {
        kv_loadguard_ok = 0;
        atomic_fetch_add(&global_stats.pd_kv_t15_fallthrough_total, 1);
        log_info("[KV_T15_LOADGUARD] fd=%d skip KV-exact (prefill imbalance "
                 "max=%u min=%u thr=%u) -> Tier 2 min-load",
                 pfe->fd, max_load, min_load,
                 (unsigned)tepval->pd_balance_abs_threshold);
      }
    }
    /* Tier 1.5 is always a NEW-session assignment, so controller-
     * DRAINING EPs are folded into the mask it sees (ctrl_drain == 0 at mode 0
     * — byte-identical). pd_kv_exact_select lives in a different TU; widening
     * the mask keeps its predicate chain and the Go argmax untouched. */
    if (kv_loadguard_ok &&
        pd_kv_exact_select(tepval, pfe, ep_out,
                           excluded_mask | ctrl_drain) == 0) {
      return 0;  /* Tier 1.5 hit */
    }
    if (kv_loadguard_ok) {
      /* KV_T15_FALLTHROUGH: Tier 1.5 declined — observable fallthrough to Tier 2 RR.
       * Individual guard reasons are logged + counted inside pd_kv_exact_select. */
      atomic_fetch_add(&global_stats.pd_kv_t15_fallthrough_total, 1);
      log_info("[KV_T15_FALLTHROUGH] fd=%d falling through to Tier 2 RR", pfe->fd);
    }
  }

  /* --- Tier 2: Min-load fallback with queue-depth scoring and RR tie-breaking --- */
  {
    int best_ep = -1;
    /* COMP-07: Composite score = active_conns + queued_requests (lower is better).
     * When vLLM scraper is not active, queued_requests remains 0 so behavior is
     * identical to the original min-active_conns logic. */
    uint64_t best_score = UINT64_MAX;
    int candidates[MAX_PROXY_EP], n_cand = 0;

    /* capacity-weighted bounded-load scoring is the GPU-aware arm.
     * It is engaged ONLY when ep_sel == PROXY_SEL_GPU_AWARE; otherwise the
     * scorer below is byte-identical to the shipped COMP-07 path (C1), so the
 * A/B is one build flag-toggled. When engaged we pre-sum the clamped
     * capacity across the eligible prefill EPs so pd_capacity_blend_score can
     * normalise each EP's load by its share of fleet capacity — lighting up the
     * reserved PROXY_SEL_GPU_AWARE weights. */
    int c2_capacity_aware = (tepval->ep_sel == PROXY_SEL_GPU_AWARE);
    uint64_t total_clamped_cap = 0;
    int n_prefill_elig = 0;
    if (c2_capacity_aware) {
      for (int i = 0; i < tepval->n_eps; i++) {
        if (tepval->ep_role[i] != 1 || tepval->eps[i].inv) continue;
        if (excluded_mask & (1u << (unsigned)i)) continue;
        if (tepval->cb_enabled &&
            tepval->circuit_breakers[i].state == CB_STATE_OPEN) continue;
        if (pd_ctrl_draining(tepval, i, cmode)) continue;  /* not a candidate */
        uint32_t cap = atomic_load(&tepval->pd_ep_loads[i].num_gpu_blocks);
        /* controller weight scales the CLAMPED effective capacity
         * (no-op at mode 0 / weight 100 / packed 0) — the pre-sum and the
         * per-EP cap_i below MUST see the SAME scaled value so the blend's
         * capacity-share normalisation stays consistent. */
        total_clamped_cap += pd_ctrl_eff_cap(tepval, i,
                                             pd_kv_clamp_capacity(cap),
                                             cmode); /* clamp 0→1: Σ>0 (V5) */
        n_prefill_elig++;
      }
      /* Σcapacity>0 guard: if no eligible EP (shouldn't happen — we recompute
       * below) fall back to C1 to avoid a divide on an empty set. */
      if (total_clamped_cap == 0 || n_prefill_elig == 0)
        c2_capacity_aware = 0;
    }

    /* H-17: neutral fill-in for stale queue depths — the average fresh queued
     * across the same candidate set (filters mirror the loop below). */
    uint64_t q_now_sec = pd_now_ns() / 1000000000ULL;
    uint64_t fresh_q_sum = 0;
    int fresh_q_n = 0;
    for (int i = 0; i < tepval->n_eps; i++) {
      if (tepval->ep_role[i] != 1 || tepval->eps[i].inv) continue;
      if (excluded_mask & (1u << (unsigned)i)) continue;
      if (tepval->cb_enabled &&
          tepval->circuit_breakers[i].state == CB_STATE_OPEN) continue;
      if (pd_ctrl_draining(tepval, i, cmode)) continue;
      if (!pd_queued_is_fresh(&tepval->pd_ep_loads[i], q_now_sec)) continue;
      fresh_q_sum += atomic_load(&tepval->pd_ep_loads[i].queued_requests);
      fresh_q_n++;
    }
    uint32_t stale_fill = fresh_q_n ? (uint32_t)(fresh_q_sum / (uint64_t)fresh_q_n) : 0;

    for (int i = 0; i < tepval->n_eps; i++) {
      if (tepval->ep_role[i] != 1 || tepval->eps[i].inv) continue;
      if (excluded_mask & (1u << (unsigned)i)) continue;
      if (tepval->cb_enabled &&
          tepval->circuit_breakers[i].state == CB_STATE_OPEN) continue;
      if (pd_ctrl_draining(tepval, i, cmode)) continue;  /* no NEW work */
      uint32_t conns = atomic_load(&tepval->pd_ep_loads[i].active_conns);
      uint32_t queued = pd_queued_or_fill(&tepval->pd_ep_loads[i], q_now_sec, stale_fill);
      uint64_t score;
      if (c2_capacity_aware) {
        /* C2: capacity-weighted blend — consumes the reserved
         * DEFAULT_{QUEUE,KV_CACHE,SWAP}_WEIGHT (PROXY_SEL_GPU_AWARE). A
         * larger-capacity EP is penalised LESS for the same live load.
 * cap_i carries the controller weight (same scaling as the
         * pre-sum above; no-op at mode 0 / weight 100 / packed 0). */
        uint32_t swap = atomic_load(&tepval->pd_ep_loads[i].swap_pressure);
        uint64_t cap_i = pd_ctrl_eff_cap(tepval, i,
            pd_kv_clamp_capacity(
                atomic_load(&tepval->pd_ep_loads[i].num_gpu_blocks)),
            cmode);
        score = pd_capacity_blend_score(conns, queued, swap,
                                        cap_i, total_clamped_cap, n_prefill_elig,
                                        DEFAULT_QUEUE_WEIGHT,
                                        DEFAULT_KV_CACHE_WEIGHT,
                                        DEFAULT_SWAP_WEIGHT);
      } else {
        /* C1 (default, byte-identical to the shipped path): COMP-07. */
        score = (uint64_t)conns + (uint64_t)queued;
      }
      if (score < best_score) {
        best_score = score;
        candidates[0] = i;
        n_cand = 1;
      } else if (score == best_score) {
        candidates[n_cand++] = i;
      }
    }
    if (n_cand <= 0) {
      log_error("no healthy prefill candidates (n_eps=%d excluded_mask=0x%x)\n",
                tepval->n_eps, excluded_mask);
      return -1;
    }
    /* Bug5-fix: only advance RR counter on genuine tie (n_cand > 1); advancing
     * unconditionally biases even-numbered calls toward candidates[0] */
    uint32_t rr = (n_cand > 1) ? atomic_fetch_add(&tepval->pd_tier2_rr, 1) : 0;
    best_ep = candidates[rr % (uint32_t)n_cand];
    *ep_out = best_ep;

    /* Update trie after Tier 2 selection + evict if needed */
    if (tepval->pd_cache_aware_mode && tepval->pd_trie &&
        pfe->prefix_key.prefix[0] != '\0') {
      pthread_rwlock_wrlock(&tepval->pd_trie_lock);
      pd_trie_insert(tepval->pd_trie, pfe->prefix_key.prefix,
                     strlen(pfe->prefix_key.prefix), best_ep);
      pd_trie_evict_lru(tepval->pd_trie, 8192);
      pthread_rwlock_unlock(&tepval->pd_trie_lock);
    }
  }

  return 0;
}

/*
 * pd_select_decode() - Select decode EP using session hint or min-load.
 *
 * If pd_select_prefill set pd_decode_ep_idx (from Tier 0 session hit),
 * use that if healthy. Otherwise min-load among healthy decode EPs.
 *
 * Returns 0 on success (*ep_out set), -1 if no healthy decode EP found.
 */
int
pd_select_decode(proxy_epval_t *tepval, proxy_fd_ent_t *pfe, int *ep_out)
{
  /* Session-pinned decode EP from Tier 0 */
  if (pfe->pd_decode_ep_idx >= 0 &&
      pfe->pd_decode_ep_idx < tepval->n_eps &&
      tepval->ep_role[pfe->pd_decode_ep_idx] == 2 &&
      !tepval->eps[pfe->pd_decode_ep_idx].inv &&
      !(tepval->cb_enabled &&
        tepval->circuit_breakers[pfe->pd_decode_ep_idx].state == CB_STATE_OPEN)) {
    *ep_out = pfe->pd_decode_ep_idx;
    return 0;
  }

  /* Min-load with RR tie-breaking among decode EPs (P2 fix: TB3/TB4 — all decode EPs selected) */
  int candidates[MAX_PROXY_EP];
  int n_cand = 0;
  uint64_t best_score = UINT64_MAX;
  /* H-17: same staleness guard as the prefill scorer — neutral fill-in from
   * the fresh candidates so a dead EP's last queue report is not trusted. */
  uint64_t q_now_sec = pd_now_ns() / 1000000000ULL;
  uint64_t fresh_q_sum = 0;
  int fresh_q_n = 0;
  for (int i = 0; i < tepval->n_eps; i++) {
    if (tepval->ep_role[i] != 2 || tepval->eps[i].inv) continue;
    if (tepval->cb_enabled &&
        tepval->circuit_breakers[i].state == CB_STATE_OPEN) continue;
    if (!pd_queued_is_fresh(&tepval->pd_ep_loads[i], q_now_sec)) continue;
    fresh_q_sum += atomic_load(&tepval->pd_ep_loads[i].queued_requests);
    fresh_q_n++;
  }
  uint32_t stale_fill = fresh_q_n ? (uint32_t)(fresh_q_sum / (uint64_t)fresh_q_n) : 0;
  for (int i = 0; i < tepval->n_eps; i++) {
    if (tepval->ep_role[i] != 2 || tepval->eps[i].inv) continue;
    if (tepval->cb_enabled &&
        tepval->circuit_breakers[i].state == CB_STATE_OPEN) continue;
    uint32_t conns = atomic_load(&tepval->pd_ep_loads[i].active_conns);
    uint32_t queued = pd_queued_or_fill(&tepval->pd_ep_loads[i], q_now_sec, stale_fill);
    uint64_t score = (uint64_t)conns + (uint64_t)queued;
    if (score < best_score) { best_score = score; n_cand = 0; }
    if (score == best_score) candidates[n_cand++] = i;
  }
  if (n_cand == 0) return -1;
  uint32_t rr = atomic_fetch_add(&tepval->pd_decode_rr, 1);
  int best_ep = candidates[rr % n_cand];
  *ep_out = best_ep;
  pfe->pd_decode_ep_idx = best_ep;
  return 0;
}

/**
 * pd_select_any_healthy() - Fallback: select any healthy EP regardless of role.
 * Called when pd_select_prefill or pd_select_decode fails (all role-specific EPs unhealthy).
 * Returns 0 on success (ep_out set), -1 if no healthy EP found.
 */
int
pd_select_any_healthy(proxy_epval_t *tepval, int *ep_out)
{
  int best = -1;
  uint32_t min_load = UINT32_MAX;

  for (int i = 0; i < tepval->n_eps; i++) {
    if (tepval->eps[i].inv)
      continue;
    /* P5-fix: skip role-specific EPs (prefill=1, decode=2); only role=0 EPs are
     * valid fallback candidates.  Without this, a decode EP would be picked as
     * "any healthy" fallback when the only prefill EP goes inactive, incorrectly
     * returning 200 instead of 503 for a P/D-only pool. */
    if (tepval->ep_role[i] != 0)
      continue;
    if (tepval->cb_enabled &&
        tepval->circuit_breakers[i].state == CB_STATE_OPEN)
      continue;
    uint32_t load = atomic_load(&tepval->pd_ep_loads[i].active_conns);
    if (load < min_load) {
      min_load = load;
      best = i;
    }
  }

  if (best >= 0) {
    *ep_out = best;
    return 0;
  }
  return -1;
}

#endif /* !TEST_PD_REWRITER */
