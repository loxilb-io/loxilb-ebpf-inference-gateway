/* SPDX-License-Identifier: (GPL-2.0) */
/*
 * sockproxy_radix_scan.h - routing key of a chat request for prefix routing.
 *
 * Self-contained: does not include sockproxy.h. Reads a complete
 * POST /v1/chat/completions JSON body and returns a digest key: request text
 * never leaves the scanner, and it holds at most one 256-byte block of it at
 * a time, plus up to 24 bytes of a key name or role, on its own stack
 * (cleared before return). It writes no log.
 *
 * Key stream (hashed, never returned). For each element of "messages", in
 * request order from messages[0]:
 *     0xFE, role byte, decoded content, 0xFF
 * with role bytes 's' system, 'd' developer, 'u' user, 'a' assistant,
 * 't' tool. Content is a string, an array of {"type":"text","text":...}
 * parts concatenated in order, null, or absent (both empty). JSON escapes
 * are decoded; \u0000 contributes a real 0x00. The decoder never emits 0xFE
 * or 0xFF, so markers cannot be forged by content.
 *
 * Cap: the stream stops at cap bytes, markers included, before the first
 * marker pair, marker or UTF-8 character that does not fit whole; nothing
 * after that point is added, so a cut is never marked as a message end and
 * the stream is always a prefix of the uncapped one.
 *
 * Digest key: the stream in full 256-byte blocks, h_i = XXH64(block_i,
 * seed h_{i-1}), h_{-1} = 0, each h_i written as 8 bytes little-endian. A
 * trailing partial block is not part of the key, so the key of turn n of a
 * conversation is a prefix of the key of turn n + 1.
 *   key_len = (stream_bytes / 256) * 8
 *   score   = radix_scan_matched_bytes(matched key length) / stream_bytes
 *
 * One structural pass validates the whole body as JSON and finds the
 * top-level keys wherever they appear; no allocation, no token array, so no
 * dependence on the size limits of the existing parser. Bounds (counted in
 * the result):
 *   skim_bytes   <= 2 * body_len  (bytes of a text-part array are visited
 *                                  twice: once with their message, once
 *                                  part by part; every other byte once)
 *   decode_bytes <= 6 * cap + 12  (source bytes decoded into the stream: at
 *                                  most 6 per stream byte for \uXXXX, plus
 *                                  one character that does not fit)
 *   hash_bytes   <= body_len      (raw "tools" and "chat_template_kwargs"
 *                                  values, hashed whole)
 *   digest work  = n_blocks * 256 <= cap
 * Every message is validated (role, content type, part types), also after
 * the cap; content after the cap is only skimmed, not decoded, so its UTF-8
 * is not checked.
 *
 * Isolation inputs: "tools" and "chat_template_kwargs" are hashed over their
 * raw top-level value as sent (XXH64, seed 0). For an array or object value
 * these are the same bytes, and so the same value, as the existing
 * tool_schemas_hash. A null value is treated as absent: has_* stays 0 and
 * nothing is hashed. A non-null "chat_template" skips; null is no override.
 * A second occurrence of any of these keys is a duplicate, also when the
 * first value was null. Other fields that
 * change the rendered prompt (add_generation_prompt, continue_final_message,
 * add_special_tokens, documents, mm_processor_kwargs, tool_calls, name) are
 * not read: a known isolation gap that can cost a cache miss, never change a
 * response. For tool_calls it means two conversations that differ only in
 * tool-call arguments share a key until their next content differs.
 *
 * Top-level and member key names, and the role value, are compared after
 * JSON unescaping.
 *
 * Key buffer: written only on RADIX_SCAN_OK, and only key[0, key_len); on a
 * skip it is not touched. Digests are held on the stack until the end, so
 * cap is limited to RADIX_SCAN_CAP_MAX.
 * Thread safety: no global state; reentrant.
 */
#ifndef __SOCKPROXY_RADIX_SCAN_H__
#define __SOCKPROXY_RADIX_SCAN_H__

#include <stddef.h>
#include <stdint.h>

#define RADIX_SCAN_BLOCK        256
#define RADIX_SCAN_DIGEST       8
#define RADIX_SCAN_DEPTH_MAX    128   /* containers, top-level object included */
#define RADIX_SCAN_CAP_MAX      16384 /* key-stream cap; 512 digest-key bytes */
#define RADIX_MARK_MSG          0xFE  /* followed by one role byte */
#define RADIX_MARK_END          0xFF

/* Digest-key bytes for a key-stream cap. */
#define RADIX_SCAN_KEY_CAP(cap) ((cap) / RADIX_SCAN_BLOCK * RADIX_SCAN_DIGEST)

typedef enum radix_scan_rc {
  RADIX_SCAN_OK = 0,
  RADIX_SKIP_BODY_TOO_LARGE,    /* body_len > max_body; nothing read */
  RADIX_SKIP_MALFORMED,         /* not one JSON object, bad syntax or escape,
                                   control character in a string */
  RADIX_SKIP_TOO_DEEP,          /* valid so far, but nesting deeper than
                                   RADIX_SCAN_DEPTH_MAX */
  RADIX_SKIP_NO_MESSAGES,       /* "messages" absent, not an array, or empty */
  RADIX_SKIP_DUPLICATE_KEY,     /* a second top-level messages, tools,
                                   chat_template or chat_template_kwargs; a
                                   second role or content in a message; a
                                   second type or text in a part */
  RADIX_SKIP_BAD_MESSAGE,       /* message not an object; role missing or not
                                   a string; content of another type; part
                                   not an object, without a string type, or a
                                   text part without a string text */
  RADIX_SKIP_UNKNOWN_ROLE,
  RADIX_SKIP_NON_TEXT_PART,     /* a part whose type is not "text" */
  RADIX_SKIP_TEMPLATE_OVERRIDE, /* a non-null top-level chat_template */
  RADIX_SKIP_INVALID_UTF8,      /* decoded content (up to the cap) is not
                                   valid UTF-8 (RFC 3629), lone surrogate
                                   escapes included */
  RADIX_SKIP_EMPTY,             /* no content byte in the stream */
  RADIX_SKIP_SHORT,             /* stream shorter than one block: no key */
  RADIX_SKIP_BAD_ARG,           /* NULL pointer, cap 0 or above
                                   RADIX_SCAN_CAP_MAX, key_cap too small */
  RADIX_SCAN__COUNT
} radix_scan_rc_t;

typedef struct radix_scan_res {
  size_t   key_len;          /* digest-key bytes written; 0 unless OK */
  size_t   stream_bytes;     /* key-stream bytes extracted, <= cap */
  uint32_t n_blocks;         /* full blocks = digests in the key */
  uint32_t n_messages;       /* messages whose start marker is in the stream */
  uint8_t  truncated;        /* the cap stopped the stream */
  uint8_t  has_tools;         /* 0 or 1: present and not null */
  uint8_t  has_tmpl_kwargs;   /* 0 or 1: present and not null */
  uint64_t tools_hash;
  uint64_t tmpl_kwargs_hash;
  uint64_t skim_bytes;
  uint64_t decode_bytes;
  uint64_t hash_bytes;
} radix_scan_res_t;

/* body: read-only, body_len bytes, not NUL-terminated; never read past
 * body_len. key: caller-owned, key_cap >= RADIX_SCAN_KEY_CAP(cap). res is
 * always filled (counters too, on a skip). */
radix_scan_rc_t radix_scan_chat(const char *body, size_t body_len,
                                size_t max_body, size_t cap,
                                uint8_t *key, size_t key_cap,
                                radix_scan_res_t *res);

/* Key-stream bytes covered by a matched digest-key length (whole digests). */
size_t radix_scan_matched_bytes(size_t matched_key_len);

/* Static name of a result, for counters; never request bytes. */
const char *radix_scan_rc_name(radix_scan_rc_t rc);

#endif /* __SOCKPROXY_RADIX_SCAN_H__ */
