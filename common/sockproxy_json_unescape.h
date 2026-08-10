/*
 * Copyright (c) 2026 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */
#ifndef __SOCKPROXY_JSON_UNESCAPE_H__
#define __SOCKPROXY_JSON_UNESCAPE_H__

/*
 * sockproxy_json_unescape.h — bounded JSON string unescape (header-only).
 *
 * root fix: extract_llm_prefix used to strncpy the RAW (still-escaped)
 * JSON bytes of the "prompt" value into prefix_key.prefix. The Tier-1.5
 * KV-exact selector then tokenized that RAW text — so any prompt containing a
 * JSON escape (`\n`, `\t`, `\"` … i.e. every real coding-assistant prompt)
 * tokenized to a DIFFERENT id stream than the publisher/vLLM side (which hash
 * the decoded text), and Tier-1.5 silently never matched (permanent Tier-2 RR).
 * The old cicd corpus dodged this by keeping every prompt "JSON-escape-clean".
 *
 * This helper decodes the escapes while copying, bounded by the destination
 * capacity, with two truncation guarantees the raw strncpy did not have:
 *   (1) never ends mid-escape (a dangling `\` or partial `\uXX` at the cut is
 *       dropped, not copied);
 *   (2) never ends mid-UTF-8-sequence (a multi-byte char that does not fully
 *       fit — whether raw or decoded from \uXXXX — is dropped entirely), so the
 *       truncated text stays valid tokenizer input and remains a byte-exact
 *       PREFIX of the full decoded prompt (the property block-hash prefix
 *       routing depends on).
 *
 * Invalid input (lone surrogate, non-hex \u, unknown escape) STOPS the copy at
 * that point rather than guessing: a shorter-but-parity-correct prefix still
 * routes by its leading blocks, while a mis-decoded byte would silently break
 * parity for the whole tail.
 *
 * Header-only (static inline) so sockproxy_json.c uses it in the datapath and
 * test_kv_exact.c unit-tests the same bytes under `make test_kv` (layer 1 of
 * the vllm-kvcache-routing-cpu sentinel) with zero Makefile surgery.
 */

#include <stddef.h>
#include <stdint.h>

/* Parse exactly 4 hex digits at s into *out. Returns 0 on success, -1 else. */
static inline int
kv_json__hex4(const char *s, uint32_t *out)
{
  uint32_t v = 0;
  for (int i = 0; i < 4; i++) {
    char c = s[i];
    v <<= 4;
    if (c >= '0' && c <= '9') v |= (uint32_t)(c - '0');
    else if (c >= 'a' && c <= 'f') v |= (uint32_t)(c - 'a' + 10);
    else if (c >= 'A' && c <= 'F') v |= (uint32_t)(c - 'A' + 10);
    else return -1;
  }
  *out = v;
  return 0;
}

/* UTF-8 byte length a codepoint encodes to (0 for invalid planes). */
static inline size_t
kv_json__utf8_len(uint32_t cp)
{
  if (cp < 0x80) return 1;
  if (cp < 0x800) return 2;
  if (cp < 0x10000) return 3;
  if (cp <= 0x10FFFF) return 4;
  return 0;
}

/* Emit cp as UTF-8 at dst (caller guarantees room). Returns bytes written. */
static inline size_t
kv_json__utf8_emit(uint32_t cp, char *dst)
{
  if (cp < 0x80) {
    dst[0] = (char)cp;
    return 1;
  }
  if (cp < 0x800) {
    dst[0] = (char)(0xC0 | (cp >> 6));
    dst[1] = (char)(0x80 | (cp & 0x3F));
    return 2;
  }
  if (cp < 0x10000) {
    dst[0] = (char)(0xE0 | (cp >> 12));
    dst[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
    dst[2] = (char)(0x80 | (cp & 0x3F));
    return 3;
  }
  dst[0] = (char)(0xF0 | (cp >> 18));
  dst[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
  dst[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
  dst[3] = (char)(0x80 | (cp & 0x3F));
  return 4;
}

/*
 * kv_json_unescape_copy — decode a RAW JSON string span (the bytes BETWEEN the
 * quotes, escapes still present) into dst, NUL-terminating always.
 *
 * Copies until src is exhausted, dst is full, or an invalid/incomplete escape
 * is hit (see header comment — stop, never guess). A raw multi-byte UTF-8
 * character is copied atomically: if its remaining bytes do not fit (or are
 * cut off by srclen), it is dropped entirely.
 *
 * Returns the number of bytes written (excluding the NUL).
 */
static inline size_t
kv_json_unescape_copy(const char *src, size_t srclen, char *dst, size_t dstcap)
{
  size_t si = 0, di = 0;

  if (dst == NULL || dstcap == 0) return 0;
  if (src == NULL) { dst[0] = '\0'; return 0; }

  while (si < srclen && di < dstcap - 1) {
    unsigned char c = (unsigned char)src[si];

    if (c == '\\') {
      if (si + 1 >= srclen) break;          /* dangling escape at the cut */
      char e = src[si + 1];
      char decoded;
      switch (e) {
      case '"':  decoded = '"';  break;
      case '\\': decoded = '\\'; break;
      case '/':  decoded = '/';  break;
      case 'b':  decoded = '\b'; break;
      case 'f':  decoded = '\f'; break;
      case 'n':  decoded = '\n'; break;
      case 'r':  decoded = '\r'; break;
      case 't':  decoded = '\t'; break;
      case 'u': {
        uint32_t cp;
        if (si + 6 > srclen || kv_json__hex4(src + si + 2, &cp) != 0)
          goto stop;                         /* partial/bad \uXXXX at the cut */
        si += 6;
        if (cp >= 0xD800 && cp <= 0xDBFF) {  /* high surrogate: need the pair */
          uint32_t lo;
          if (si + 6 > srclen || src[si] != '\\' || src[si + 1] != 'u' ||
              kv_json__hex4(src + si + 2, &lo) != 0 ||
              lo < 0xDC00 || lo > 0xDFFF)
            goto stop;                       /* lone/broken surrogate */
          cp = 0x10000 + (((cp - 0xD800) << 10) | (lo - 0xDC00));
          si += 6;
        } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
          goto stop;                         /* lone low surrogate */
        }
        {
          size_t need = kv_json__utf8_len(cp);
          if (need == 0) goto stop;
          if (di + need > dstcap - 1) goto stop;   /* would split the char */
          di += kv_json__utf8_emit(cp, dst + di);
        }
        continue;
      }
      default:
        goto stop;                           /* unknown escape: invalid JSON */
      }
      dst[di++] = decoded;
      si += 2;
      continue;
    }

    if (c < 0x80) {                          /* plain ASCII byte */
      dst[di++] = (char)c;
      si++;
      continue;
    }

    /* Raw multi-byte UTF-8: copy the whole sequence or none of it. */
    {
      size_t need;
      if ((c & 0xE0) == 0xC0) need = 2;
      else if ((c & 0xF0) == 0xE0) need = 3;
      else if ((c & 0xF8) == 0xF0) need = 4;
      else goto stop;                        /* stray continuation/invalid lead */
      if (si + need > srclen) goto stop;     /* sequence cut off by srclen */
      if (di + need > dstcap - 1) goto stop; /* would split the char in dst */
      for (size_t k = 0; k < need; k++) {
        if (((unsigned char)src[si + k] & 0xC0) != 0x80 && k > 0)
          goto stop;                         /* malformed continuation */
        if (k > 0) dst[di + k] = src[si + k];
      }
      dst[di] = (char)c;
      di += need;
      si += need;
    }
  }

stop:
  dst[di] = '\0';
  return di;
}

#endif /* __SOCKPROXY_JSON_UNESCAPE_H__ */
