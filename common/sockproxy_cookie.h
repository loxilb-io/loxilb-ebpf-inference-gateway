/* SPDX-License-Identifier: GPL-2.0
 *
 * sockproxy_cookie.h — STATELESS LB-generated cookie persistence
 * (HTTP_COOKIE mode) primitives.
 *
 * These are PURE functions (no socket I/O, no nghttp2, no proxy_fd_ent state) so
 * they are unit-testable in isolation (sockproxy_cookie_test.c) and can be reused
 * verbatim by sockproxy_l7policy.c (the data-plane caller). They implement the
 * stateless token discipline of CONTEXT:
 *
 *   - The binding between a client and its backend lives ONLY in the cookie value
 *     (an opaque keyed-HMAC token of the member identity). NOTHING is stored on
 *     proxy_fd_ent / no per-connection map — so the affinity SURVIVES HA failover
 * with ZERO xSync wire-format change ( resolves the cookie 🔴).
 *
 *   - The token is base64url(HMAC-SHA256(per_vip_secret, member_id)[:N]). The raw
 * member id is NEVER exposed, so a client cannot read off a backend id
 *     and forge a cookie targeting a chosen backend.
 *
 *   - per_vip_secret is derived DETERMINISTICALLY from already-synced config
 *     (the VIP:port, which is byte-identical on both HA peers) keyed by a fixed
 *     build-time constant: per_vip_secret = HMAC-SHA256(LB_COOKIE_ROOT_KEY,
 *     "VIP:port"). Both HA peers therefore compute the SAME secret and the SAME
 *     token for the same VIP+port+member with no synced secret blob (Open-Q2).
 *
 *   - Read-back re-derives every LIVE member's token and compares CONSTANT-TIME
 *     (Security V4 — no early return on first mismatched byte). A forged or stale
 *     token MISSES (returns L7_COOKIE_MISS) → the caller falls through to the
 *     normal LB hash; it can NEVER target an arbitrary/attacker-chosen backend
 *.
 *
 * Crypto: uses the ALREADY-LINKED openssl libcrypto (HMAC / CRYPTO_memcmp) — the
 * HMAC is NOT hand-rolled (Security V6). Zero new packages (T-76-SC).
 */
#ifndef SOCKPROXY_COOKIE_H
#define SOCKPROXY_COOKIE_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/crypto.h> /* CRYPTO_memcmp — constant-time compare */

/* The fixed Octavia/haproxy-convention cookie NAME the LB mints + reads back. */
#define LB_COOKIE_NAME            "OCTAVIA_SESSION"

/* Build-time root key for per-VIP secret derivation. It is NOT a secret-of-record
 * (a leak only weakens token unforgeability to "guess a live member id", and a
 * miss still falls through to the normal hash — never a wrong backend). It
 * exists so the token is a KEYED HMAC (not a bare hash) and is identical on both
 * HA peers without any synced blob. */
#define LB_COOKIE_ROOT_KEY        "loxilb-octavia-http-cookie-v1"

/* Truncate the HMAC-SHA256 (32 bytes) to N bytes before base64url. 16 bytes =
 * 128 bits of unforgeability, encodes to a compact 22-char token. */
#define LB_COOKIE_TOKEN_RAW_LEN   16
/* base64url of 16 bytes (no padding) = ceil(16/3)*4 = 24 chars worst case; we
 * strip '=' padding so 22 chars + NUL. Size the buffer generously. */
#define LB_COOKIE_TOKEN_MAX       40

/* Per-VIP secret is a full HMAC-SHA256 digest (32 bytes). */
#define LB_COOKIE_VIP_SECRET_LEN  SHA256_DIGEST_LENGTH

/* Read-back sentinel: no live member's token matched the presented cookie. The
 * caller MUST treat this as "rehash" (normal LB hash), NOT as an endpoint index. */
#define L7_COOKIE_MISS            (-1)

/* base64url alphabet (RFC 4648 §5), no padding. */
static const char lb_cookie_b64url_tbl[64] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/* base64url-encode `inlen` bytes of `in` into `out` (NUL-terminated, no '='
 * padding). `out` must hold at least ceil(inlen/3)*4 + 1 bytes. Returns the
 * encoded length (excluding NUL). */
static inline size_t
lb_cookie_b64url(const uint8_t *in, size_t inlen, char *out, size_t outsz)
{
  size_t i = 0, o = 0;
  while (i + 3 <= inlen) {
    uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
    if (o + 4 >= outsz) break;
    out[o++] = lb_cookie_b64url_tbl[(v >> 18) & 0x3f];
    out[o++] = lb_cookie_b64url_tbl[(v >> 12) & 0x3f];
    out[o++] = lb_cookie_b64url_tbl[(v >> 6) & 0x3f];
    out[o++] = lb_cookie_b64url_tbl[v & 0x3f];
    i += 3;
  }
  if (i < inlen) {
    uint32_t v = (uint32_t)in[i] << 16;
    int rem = (int)(inlen - i); /* 1 or 2 */
    if (rem == 2) v |= (uint32_t)in[i + 1] << 8;
    if (o + 2 < outsz) {
      out[o++] = lb_cookie_b64url_tbl[(v >> 18) & 0x3f];
      out[o++] = lb_cookie_b64url_tbl[(v >> 12) & 0x3f];
      if (rem == 2 && o + 1 < outsz)
        out[o++] = lb_cookie_b64url_tbl[(v >> 6) & 0x3f];
    }
  }
  if (o < outsz) out[o] = '\0';
  return o;
}

/* Derive the per-VIP secret deterministically from the VIP:port string. Both HA
 * peers, configured with the same VIP+port, compute a BYTE-IDENTICAL secret with
 * NO synced secret blob (Open-Q2). `out` must hold LB_COOKIE_VIP_SECRET_LEN
 * bytes. Returns 0 on success, -1 on failure. */
static inline int
l7_cookie_derive_vip_secret(const char *vip_port, uint8_t out[LB_COOKIE_VIP_SECRET_LEN])
{
  unsigned int mdlen = 0;
  if (!vip_port || !out)
    return -1;
  if (HMAC(EVP_sha256(),
           (const unsigned char *)LB_COOKIE_ROOT_KEY, (int)strlen(LB_COOKIE_ROOT_KEY),
           (const unsigned char *)vip_port, strlen(vip_port),
           out, &mdlen) == NULL || mdlen != LB_COOKIE_VIP_SECRET_LEN)
    return -1;
  return 0;
}

/* Derive the opaque cookie token for `member_id` under `per_vip_secret`. The
 * token is base64url(HMAC-SHA256(per_vip_secret, member_id)[:LB_COOKIE_TOKEN_RAW_LEN]).
 * `out` must hold LB_COOKIE_TOKEN_MAX bytes. Returns the token length (>0) on
 * success, -1 on failure. DETERMINISTIC: same inputs ⇒ same token (the basis for
 * cross-peer affinity). */
static inline int
l7_cookie_derive_token(const char *member_id,
                       const uint8_t per_vip_secret[LB_COOKIE_VIP_SECRET_LEN],
                       char *out, size_t outsz)
{
  uint8_t mac[SHA256_DIGEST_LENGTH];
  unsigned int mdlen = 0;
  size_t n;
  if (!member_id || !per_vip_secret || !out || outsz < LB_COOKIE_TOKEN_MAX)
    return -1;
  if (HMAC(EVP_sha256(),
           per_vip_secret, LB_COOKIE_VIP_SECRET_LEN,
           (const unsigned char *)member_id, strlen(member_id),
           mac, &mdlen) == NULL || mdlen != SHA256_DIGEST_LENGTH)
    return -1;
  n = lb_cookie_b64url(mac, LB_COOKIE_TOKEN_RAW_LEN, out, outsz);
  return (n > 0) ? (int)n : -1;
}

/* Format a member's stable identity into `buf` ("ip:port", network-order fields
 * as supplied). This is the HMAC message; it is NEVER exposed to the client
 * (only its HMAC is). Returns 0 on success. */
static inline int
l7_cookie_member_id(uint32_t xip_net, uint16_t xport_net, char *buf, size_t bufsz)
{
  /* Render the raw 32-bit IP + 16-bit port verbatim (no inet_ntop dependency) so
   * the message is identical on both HA peers regardless of byte-order helpers.
   * The exact textual form is irrelevant for security — only its determinism and
   * per-member uniqueness matter. */
  int n = snprintf(buf, bufsz, "%u:%u", (unsigned)xip_net, (unsigned)xport_net);
  return (n > 0 && (size_t)n < bufsz) ? 0 : -1;
}

/* CONSTANT-TIME token comparison (Security V4). Compares the full
 * presented token against a candidate over a FIXED span derived from the longer
 * of the two, accumulating a difference WITHOUT early return, so the timing does
 * not leak how many leading bytes matched. Returns 1 on exact match, 0 otherwise. */
static inline int
l7_cookie_token_eq_ct(const char *presented, const char *candidate)
{
  size_t lp, lc, span, i;
  unsigned char diff = 0;
  if (!presented || !candidate)
    return 0;
  lp = strnlen(presented, LB_COOKIE_TOKEN_MAX);
  lc = strnlen(candidate, LB_COOKIE_TOKEN_MAX);
  /* Fold the length difference into the accumulator (so unequal lengths never
   * match) but STILL scan a fixed span so timing is independent of the data. */
  diff |= (unsigned char)(lp ^ lc);
  span = (lp > lc) ? lp : lc;
  for (i = 0; i < span; i++) {
    unsigned char a = (i < lp) ? (unsigned char)presented[i] : 0;
    unsigned char b = (i < lc) ? (unsigned char)candidate[i] : 0;
    diff |= (unsigned char)(a ^ b);
  }
  return diff == 0;
}

/* Read-back: re-derive every LIVE member's token and constant-time-match it
 * against the presented `token`. Returns the matched member index [0, n_eps), or
 * L7_COOKIE_MISS on no match (the caller MUST then fall through to the normal LB
 * hash —: a forged/stale token NEVER targets an arbitrary
 * backend). `eps` is the live member array (each carrying network-order
 * xip/xport); `member_inv[i]!=0` (optional, may be NULL) marks a member down. */
static inline int
l7_cookie_match_token_eps(const char *token,
                          const uint8_t per_vip_secret[LB_COOKIE_VIP_SECRET_LEN],
                          const uint32_t *xip, const uint16_t *xport,
                          const uint8_t *member_inv, int n_eps)
{
  int i, matched = L7_COOKIE_MISS;
  if (!token || token[0] == '\0' || !per_vip_secret || !xip || !xport || n_eps <= 0)
    return L7_COOKIE_MISS;
  for (i = 0; i < n_eps; i++) {
    char mid[64];
    char cand[LB_COOKIE_TOKEN_MAX];
    if (member_inv && member_inv[i] != 0)
      continue; /* skip a member health-checked down (stale token ⇒ rehash) */
    if (l7_cookie_member_id(xip[i], xport[i], mid, sizeof(mid)) != 0)
      continue;
    if (l7_cookie_derive_token(mid, per_vip_secret, cand, sizeof(cand)) <= 0)
      continue;
    if (l7_cookie_token_eq_ct(token, cand))
      matched = i; /* do NOT break — keep the scan length data-independent */
  }
  return matched;
}

#endif /* SOCKPROXY_COOKIE_H */
