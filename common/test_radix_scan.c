/* SPDX-License-Identifier: (GPL-2.0) */
/* test_radix_scan.c - the chat-request routing-key scanner
 * (sockproxy_radix_scan.c, included directly; it is self-contained).
 *
 * Every body is built from a list of messages, and the expected key comes
 * from a reference in this file that builds the key stream from the same
 * list (0xFE, role byte, content, 0xFF per message; cut at the cap before
 * the first piece that does not fit whole) and digests its full 256-byte
 * blocks. The reference lives here only; the product file has no stream
 * output.
 *
 * Every scan reads an exact-size heap copy of the body, so a read past the
 * end is an AddressSanitizer report.
 *
 * Build: make test_radix_scan     Run: ./test_radix_scan (ASan + UBSan)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sockproxy_radix_scan.c"

/* ---- reporting ---- */

static int g_fail, g_case_fail;
static const char *g_case;

#define CHECK(c) do {                                                   \
    if (!(c)) {                                                         \
      g_fail++;                                                         \
      if (g_case_fail++ < 6)                                            \
        printf("    check failed: %s (line %d)\n", #c, __LINE__);       \
    }                                                                   \
  } while (0)

static void case_begin(const char *name) { g_case = name; g_case_fail = 0; }
static void case_end(void)
{
  printf("[%s] %s%s\n", g_case_fail ? "FAIL" : "PASS", g_case,
         g_case_fail > 6 ? " (more failures not shown)" : "");
}

/* ---- message lists ---- */

enum { F_STRING, F_PARTS, F_NULL, F_ABSENT, F_ROLE_LAST, F_PARTS_TEXT_FIRST };

typedef struct {
  char role;            /* s d u a t */
  const char *text;     /* UTF-8 */
  size_t len;
  int form;
  int nparts;           /* F_PARTS*: split into this many parts */
} msg_t;

static const char *role_name(char r)
{
  switch (r) {
  case 's': return "system";
  case 'd': return "developer";
  case 'u': return "user";
  case 'a': return "assistant";
  case 't': return "tool";
  }
  return "?";
}

/* ---- reference key stream ---- */

typedef struct {
  uint8_t s[1 << 17];
  size_t n, cap, content;
  int full;
} ref_t;

static size_t utf8_len(uint8_t c)
{
  return c < 0x80 ? 1 : (c & 0xE0) == 0xC0 ? 2 : (c & 0xF0) == 0xE0 ? 3 : 4;
}

static void ref_put(ref_t *r, const uint8_t *b, size_t k, int content)
{
  if (r->full)
    return;
  if (r->n + k > r->cap) {
    r->full = 1;
    return;
  }
  memcpy(r->s + r->n, b, k);
  r->n += k;
  if (content)
    r->content += k;
}

static void ref_build(ref_t *r, size_t cap, const msg_t *m, int nm)
{
  memset(r, 0, sizeof(*r));
  r->cap = cap;
  for (int i = 0; i < nm; i++) {
    uint8_t st[2] = { RADIX_MARK_MSG, (uint8_t)m[i].role }, en = RADIX_MARK_END;
    ref_put(r, st, 2, 0);
    if (m[i].form != F_NULL && m[i].form != F_ABSENT)
      for (size_t j = 0; j < m[i].len; ) {
        size_t k = utf8_len((uint8_t)m[i].text[j]);
        ref_put(r, (const uint8_t *)m[i].text + j, k, 1);
        j += k;
      }
    ref_put(r, &en, 1, 0);
  }
}

/* expected rc and key */
static radix_scan_rc_t ref_key(const ref_t *r, uint8_t *key, size_t *klen)
{
  uint64_t h = 0;
  size_t nb = r->n / RADIX_SCAN_BLOCK;
  for (size_t i = 0; i < nb; i++) {
    h = XXH64(r->s + i * RADIX_SCAN_BLOCK, RADIX_SCAN_BLOCK, h);
    for (int b = 0; b < 8; b++)
      key[8 * i + b] = (uint8_t)(h >> (8 * b));
  }
  *klen = nb * 8;
  if (!r->content)
    return RADIX_SKIP_EMPTY;
  if (r->n < RADIX_SCAN_BLOCK)
    return RADIX_SKIP_SHORT;
  return RADIX_SCAN_OK;
}

/* ---- JSON body builder ---- */

typedef struct { char *b; size_t n, cap; } jb_t;

static void jb_bytes(jb_t *j, const void *p, size_t n)
{
  if (j->n + n + 1 > j->cap) {
    j->cap = (j->n + n + 1) * 2;
    j->b = realloc(j->b, j->cap);
  }
  memcpy(j->b + j->n, p, n);
  j->n += n;
  j->b[j->n] = 0;                   /* kept terminated for strstr */
}

static void jb_raw(jb_t *j, const char *s) { jb_bytes(j, s, strlen(s)); }

static uint32_t utf8_cp(const uint8_t *p, size_t k)
{
  if (k == 1) return p[0];
  if (k == 2) return ((uint32_t)(p[0] & 0x1F) << 6) | (p[1] & 0x3F);
  if (k == 3) return ((uint32_t)(p[0] & 0x0F) << 12) | ((uint32_t)(p[1] & 0x3F) << 6) | (p[2] & 0x3F);
  return ((uint32_t)(p[0] & 0x07) << 18) | ((uint32_t)(p[1] & 0x3F) << 12) |
         ((uint32_t)(p[2] & 0x3F) << 6) | (p[3] & 0x3F);
}

static void jb_u(jb_t *j, uint32_t u)
{
  char e[8];
  snprintf(e, sizeof(e), "\\u%04X", u);
  jb_raw(j, e);
}

/* esc 0: minimal escaping; 1: also non-ASCII as \u; 2: every char as \u */
static int g_esc;

static void jb_str(jb_t *j, const char *t, size_t len)
{
  jb_raw(j, "\"");
  for (size_t i = 0; i < len; ) {
    const uint8_t *p = (const uint8_t *)t + i;
    size_t k = utf8_len(p[0]);
    uint32_t cp = utf8_cp(p, k);
    if (g_esc == 2 || (g_esc == 1 && cp >= 0x80)) {
      if (cp >= 0x10000) {
        cp -= 0x10000;
        jb_u(j, 0xD800 + (cp >> 10));
        jb_u(j, 0xDC00 + (cp & 0x3FF));
      } else {
        jb_u(j, cp);
      }
    } else if (cp == '"') {
      jb_raw(j, "\\\"");
    } else if (cp == '\\') {
      jb_raw(j, "\\\\");
    } else if (cp == '\n') {
      jb_raw(j, "\\n");
    } else if (cp == '\t') {
      jb_raw(j, "\\t");
    } else if (cp < 0x20) {
      jb_u(j, cp);
    } else {
      jb_bytes(j, p, k);
    }
    i += k;
  }
  jb_raw(j, "\"");
}

static void jb_msg(jb_t *j, const msg_t *m)
{
  char role[48];
  snprintf(role, sizeof(role), "\"role\":\"%s\"", role_name(m->role));
  jb_raw(j, "{");
  if (m->form != F_ROLE_LAST) {
    jb_raw(j, role);
    if (m->form != F_ABSENT)
      jb_raw(j, ",");
  }
  if (m->form == F_STRING || m->form == F_ROLE_LAST) {
    jb_raw(j, "\"content\":");
    jb_str(j, m->text, m->len);
  } else if (m->form == F_NULL) {
    jb_raw(j, "\"content\":null");
  } else if (m->form == F_PARTS || m->form == F_PARTS_TEXT_FIRST) {
    int np = m->nparts > 0 ? m->nparts : 1;
    size_t at = 0;
    jb_raw(j, "\"content\":[");
    for (int p = 0; p < np; p++) {
      size_t end = p == np - 1 ? m->len : m->len * (size_t)(p + 1) / (size_t)np;
      while (end < m->len && ((uint8_t)m->text[end] & 0xC0) == 0x80)
        end++;                          /* parts end on a character */
      if (p)
        jb_raw(j, ",");
      if (m->form == F_PARTS) {
        jb_raw(j, "{\"type\":\"text\",\"text\":");
        jb_str(j, m->text + at, end - at);
        jb_raw(j, "}");
      } else {
        jb_raw(j, "{\"text\":");
        jb_str(j, m->text + at, end - at);
        jb_raw(j, ",\"cache_control\":{\"type\":\"ephemeral\"},\"type\":\"text\"}");
      }
      at = end;
    }
    jb_raw(j, "]");
  }
  if (m->form == F_ROLE_LAST) {
    jb_raw(j, ",");
    jb_raw(j, role);
  }
  jb_raw(j, "}");
}

/* {before "messages":[...] after} */
static void jb_chat(jb_t *j, const char *before, const msg_t *m, int nm, const char *after)
{
  j->n = 0;
  jb_raw(j, "{");
  if (before && *before) {
    jb_raw(j, before);
    jb_raw(j, ",");
  }
  jb_raw(j, "\"model\":\"m\",\"messages\":[");
  for (int i = 0; i < nm; i++) {
    if (i)
      jb_raw(j, ",");
    jb_msg(j, &m[i]);
  }
  jb_raw(j, "]");
  if (after && *after) {
    jb_raw(j, ",");
    jb_raw(j, after);
  }
  jb_raw(j, "}");
}

/* ---- scan wrapper: exact-size heap copy ---- */

#define KEYCAP_MAX RADIX_SCAN_KEY_CAP(1 << 16)
static uint8_t g_key[KEYCAP_MAX];

static radix_scan_rc_t scan_n(const char *body, size_t len, size_t max_body,
                              size_t cap, radix_scan_res_t *res)
{
  char *copy = malloc(len ? len : 1);
  radix_scan_rc_t rc;
  memcpy(copy, body, len);
  memset(g_key, 0, sizeof(g_key));
  rc = radix_scan_chat(copy, len, max_body, cap, g_key,
                       RADIX_SCAN_KEY_CAP(cap), res);
  free(copy);
  return rc;
}

static radix_scan_rc_t scan(jb_t *j, size_t cap, radix_scan_res_t *res)
{
  return scan_n(j->b, j->n, (size_t)16 << 20, cap, res);
}

static radix_scan_rc_t scan_s(const char *s, size_t cap, radix_scan_res_t *res)
{
  return scan_n(s, strlen(s), (size_t)16 << 20, cap, res);
}

static void check_bounds(const radix_scan_res_t *r, size_t body_len, size_t cap)
{
  CHECK(r->skim_bytes <= 2 * (uint64_t)body_len);
  CHECK(r->decode_bytes <= 6 * (uint64_t)cap + 12);
  CHECK(r->hash_bytes <= body_len);
  CHECK(r->stream_bytes <= cap);
  CHECK((uint64_t)r->n_blocks * RADIX_SCAN_BLOCK <= cap);
  CHECK(r->has_tools <= 1 && r->has_tmpl_kwargs <= 1);
}

/* Scan j and compare with the reference built from the same messages. */
static void expect_ref(jb_t *j, size_t cap, const msg_t *m, int nm)
{
  static ref_t r;
  uint8_t want[KEYCAP_MAX];
  size_t wl;
  radix_scan_res_t res;
  radix_scan_rc_t rc, wrc;

  ref_build(&r, cap, m, nm);
  wrc = ref_key(&r, want, &wl);
  rc = scan(j, cap, &res);
  CHECK(rc == wrc);
  CHECK(res.stream_bytes == r.n);
  CHECK(res.truncated == r.full);
  if (wrc == RADIX_SCAN_OK) {
    CHECK(res.key_len == wl && res.n_blocks == wl / 8);
    CHECK(!memcmp(g_key, want, wl));
  } else {
    CHECK(res.key_len == 0);
  }
  check_bounds(&res, j->n, cap);
}

/* Synthetic text: ASCII words, code with newlines and tabs, Hangul
 * syllables (U+AC00 block, 3 bytes each) and one 4-byte character, built
 * from code points so the source holds no non-ASCII text. */
static size_t gen_text(char *out, size_t len, uint32_t seed, int mix)
{
  size_t n = 0;
  uint32_t x = seed * 2654435761u + 1;
  while (n < len) {
    uint32_t cp;
    x = x * 1103515245u + 12345u;
    switch (mix ? (x >> 16) % 6 : 0) {
    case 1: cp = 0xAC00 + (x >> 8) % 11172; break;          /* Hangul */
    case 2: cp = (x >> 20) % 2 ? '\n' : '\t'; break;
    case 3: cp = 0x1F600 + (x >> 8) % 64; break;            /* 4-byte */
    default: cp = 'a' + (x >> 8) % 26; break;
    }
    uint8_t b[4];
    size_t k = cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4;
    if (k == 1) b[0] = (uint8_t)cp;
    else if (k == 3) { b[0] = 0xE0 | (cp >> 12); b[1] = 0x80 | ((cp >> 6) & 0x3F); b[2] = 0x80 | (cp & 0x3F); }
    else { b[0] = 0xF0 | (cp >> 18); b[1] = 0x80 | ((cp >> 12) & 0x3F); b[2] = 0x80 | ((cp >> 6) & 0x3F); b[3] = 0x80 | (cp & 0x3F); }
    if (n + k > len)
      break;
    memcpy(out + n, b, k);
    n += k;
  }
  return n;
}

static char tA[1 << 16], tB[1 << 16], tC[1 << 16];

/* ================= E6: functional ================= */

static void t_string_vs_parts(void)
{
  jb_t j = {0};
  size_t n = gen_text(tA, 3000, 1, 1);
  msg_t s[2] = { { 's', "system prompt", 13, F_STRING, 0 }, { 'u', tA, n, F_STRING, 0 } };
  msg_t p[2] = { { 's', "system prompt", 13, F_PARTS, 1 }, { 'u', tA, n, F_PARTS, 5 } };
  uint8_t k1[KEYCAP_MAX];
  radix_scan_res_t r1, r2;

  case_begin("E6: string and text-part-array content give the same key");
  jb_chat(&j, NULL, s, 2, NULL);
  expect_ref(&j, 8192, s, 2);
  CHECK(scan(&j, 8192, &r1) == RADIX_SCAN_OK);
  memcpy(k1, g_key, r1.key_len);
  jb_chat(&j, NULL, p, 2, NULL);
  expect_ref(&j, 8192, s, 2);
  CHECK(scan(&j, 8192, &r2) == RADIX_SCAN_OK);
  CHECK(r1.key_len == r2.key_len && r1.key_len > 0 && !memcmp(k1, g_key, r1.key_len));
  free(j.b);
  case_end();
}

static void t_order_and_escapes(void)
{
  jb_t j = {0};
  size_t n = gen_text(tA, 2000, 2, 1);
  msg_t a[2] = { { 's', "be brief", 8, F_STRING, 0 }, { 'u', tA, n, F_STRING, 0 } };
  msg_t b[2] = { { 's', "be brief", 8, F_ROLE_LAST, 0 }, { 'u', tA, n, F_PARTS_TEXT_FIRST, 3 } };

  case_begin("E6: role after content, type after text, and escaped spellings give the same key");
  jb_chat(&j, NULL, b, 2, NULL);
  expect_ref(&j, 8192, a, 2);
  for (g_esc = 1; g_esc <= 2; g_esc++) {
    jb_chat(&j, NULL, a, 2, NULL);
    expect_ref(&j, 8192, a, 2);
  }
  g_esc = 0;
  /* escaped key names are recognized */
  jb_chat(&j, NULL, a, 2, NULL);
  {
    char *at = strstr(j.b, "\"messages\"");
    CHECK(at != NULL);
    if (at) {
      jb_t k = {0};
      jb_bytes(&k, j.b, (size_t)(at - j.b));
      jb_raw(&k, "\"m\\u0065ssages\"");
      jb_bytes(&k, at + 10, j.n - (size_t)(at - j.b) - 10);
      expect_ref(&k, 8192, a, 2);
      free(k.b);
    }
  }
  free(j.b);
  case_end();
}

static void t_markers(void)
{
  jb_t j = {0};
  size_t n = gen_text(tA, 600, 3, 0);
  msg_t u[1] = { { 'u', tA, n, F_STRING, 0 } };
  msg_t s[1] = { { 's', tA, n, F_STRING, 0 } };
  msg_t two[2] = { { 'u', tA, 100, F_STRING, 0 }, { 'u', tA + 100, n - 100, F_STRING, 0 } };
  uint8_t ku[KEYCAP_MAX];
  radix_scan_res_t r;

  case_begin("E6: role and boundary markers change the digest");
  jb_chat(&j, NULL, u, 1, NULL);
  expect_ref(&j, 8192, u, 1);
  CHECK(scan(&j, 8192, &r) == RADIX_SCAN_OK && r.key_len >= 8);
  memcpy(ku, g_key, 8);
  jb_chat(&j, NULL, s, 1, NULL);
  expect_ref(&j, 8192, s, 1);
  CHECK(scan(&j, 8192, &r) == RADIX_SCAN_OK && memcmp(ku, g_key, 8) != 0);
  jb_chat(&j, NULL, two, 2, NULL);
  expect_ref(&j, 8192, two, 2);
  CHECK(scan(&j, 8192, &r) == RADIX_SCAN_OK && memcmp(ku, g_key, 8) != 0);
  free(j.b);
  case_end();
}

/* Two single-message requests whose streams agree on exactly L bytes. */
static void shared_case(size_t L, int boundary_msg)
{
  jb_t j = {0};
  uint8_t k1[KEYCAP_MAX];
  radix_scan_res_t r1, r2;
  size_t n = 2000, want = L / RADIX_SCAN_BLOCK;

  memset(tA, 'a', n);
  memcpy(tB, tA, n);
  if (!boundary_msg) {
    /* stream = FE 'u' content...: content byte L - 2 is the first difference */
    tB[L - 2] = 'b';
    msg_t a[1] = { { 'u', tA, n, F_STRING, 0 } }, b[1] = { { 'u', tB, n, F_STRING, 0 } };
    jb_chat(&j, NULL, a, 1, NULL);
    expect_ref(&j, 8192, a, 1);
    scan(&j, 8192, &r1);
    memcpy(k1, g_key, r1.key_len);
    jb_chat(&j, NULL, b, 1, NULL);
    expect_ref(&j, 8192, b, 1);
    scan(&j, 8192, &r2);
  } else {
    /* first message fills exactly L bytes (a block boundary); the second
     * message's role differs, so the streams differ from byte L on */
    msg_t a[2] = { { 's', tA, L - 3, F_STRING, 0 }, { 'u', tA, 600, F_STRING, 0 } };
    msg_t b[2] = { { 's', tA, L - 3, F_STRING, 0 }, { 'a', tA, 600, F_STRING, 0 } };
    jb_chat(&j, NULL, a, 2, NULL);
    expect_ref(&j, 8192, a, 2);
    scan(&j, 8192, &r1);
    memcpy(k1, g_key, r1.key_len);
    jb_chat(&j, NULL, b, 2, NULL);
    expect_ref(&j, 8192, b, 2);
    scan(&j, 8192, &r2);
  }
  {
    size_t common = 0;
    while (common + 8 <= r1.key_len && common + 8 <= r2.key_len &&
           !memcmp(k1 + common, g_key + common, 8))
      common += 8;
    CHECK(r1.key_len > 0 && r2.key_len > 0);
    CHECK(common / 8 == want);
    if (common / 8 != want)
      printf("    shared %zu bytes%s: %zu common digests, expected %zu\n", L,
             boundary_msg ? " (message boundary)" : "", common / 8, want);
  }
  free(j.b);
}

static void t_shared_blocks(void)
{
  case_begin("E6: requests sharing exactly n full blocks share exactly n digests");
  shared_case(256 * 3, 0);          /* ends on a block boundary */
  shared_case(256 * 3 + 1, 0);      /* one byte into a block */
  shared_case(256 * 3 + 255, 0);    /* last byte of a block */
  shared_case(255, 0);              /* inside the first block: nothing shared */
  shared_case(256 * 2, 1);          /* a message boundary on a block boundary */
  shared_case(256 * 4, 1);
  case_end();
}

static void t_turns(void)
{
  jb_t j = {0};
  size_t n1 = gen_text(tA, 900, 4, 1), n2 = gen_text(tB, 700, 5, 1), n3 = gen_text(tC, 500, 6, 1);
  msg_t turn1[2] = { { 's', "you are a coding assistant", 26, F_STRING, 0 }, { 'u', tA, n1, F_STRING, 0 } };
  msg_t turn2[4] = { turn1[0], turn1[1], { 'a', tB, n2, F_STRING, 0 }, { 'u', tC, n3, F_STRING, 0 } };
  uint8_t k1[KEYCAP_MAX];
  radix_scan_res_t r1, r2;

  case_begin("E6: the key of turn n is a strict prefix of the key of turn n + 1");
  jb_chat(&j, NULL, turn1, 2, NULL);
  expect_ref(&j, 8192, turn1, 2);
  CHECK(scan(&j, 8192, &r1) == RADIX_SCAN_OK);
  memcpy(k1, g_key, r1.key_len);
  jb_chat(&j, NULL, turn2, 4, NULL);
  expect_ref(&j, 8192, turn2, 4);
  CHECK(scan(&j, 8192, &r2) == RADIX_SCAN_OK);
  CHECK(r1.key_len > 0 && r2.key_len > r1.key_len);
  CHECK(!memcmp(k1, g_key, r1.key_len));
  free(j.b);
  case_end();
}

static void t_partial_tail(void)
{
  jb_t j = {0};
  uint8_t k1[KEYCAP_MAX];
  radix_scan_res_t r1, r2;
  /* stream 2 + 700 + 1 = 703: two full blocks, 191 trailing bytes */
  memset(tA, 'q', 700);
  memcpy(tB, tA, 700);
  tB[690] = 'z';                       /* inside the trailing partial block */
  msg_t a[1] = { { 'u', tA, 700, F_STRING, 0 } }, b[1] = { { 'u', tB, 700, F_STRING, 0 } };
  msg_t c[1] = { { 'u', tA, 760, F_STRING, 0 } };   /* longer tail, same blocks */

  case_begin("E6: bodies differing only in the trailing partial block give the same key");
  memset(tA + 700, 'q', 60);
  jb_chat(&j, NULL, a, 1, NULL);
  expect_ref(&j, 8192, a, 1);
  CHECK(scan(&j, 8192, &r1) == RADIX_SCAN_OK && r1.key_len == 16 && r1.stream_bytes == 703);
  memcpy(k1, g_key, r1.key_len);
  jb_chat(&j, NULL, b, 1, NULL);
  CHECK(scan(&j, 8192, &r2) == RADIX_SCAN_OK && r2.key_len == 16 && !memcmp(k1, g_key, 16));
  jb_chat(&j, NULL, c, 1, NULL);
  CHECK(scan(&j, 8192, &r2) == RADIX_SCAN_OK && r2.key_len == 16 && !memcmp(k1, g_key, 16));
  free(j.b);
  case_end();
}

static void t_short(void)
{
  jb_t j = {0};
  radix_scan_res_t r;
  memset(tA, 'w', 300);
  msg_t m255[1] = { { 'u', tA, 252, F_STRING, 0 } };   /* 2 + 252 + 1 = 255 */
  msg_t m256[1] = { { 'u', tA, 253, F_STRING, 0 } };   /* 256 */

  case_begin("E6: a 255-byte stream skips (SHORT), a 256-byte stream gives one digest");
  jb_chat(&j, NULL, m255, 1, NULL);
  CHECK(scan(&j, 8192, &r) == RADIX_SKIP_SHORT);
  CHECK(r.stream_bytes == 255 && r.key_len == 0 && r.n_blocks == 0);
  expect_ref(&j, 8192, m255, 1);
  jb_chat(&j, NULL, m256, 1, NULL);
  CHECK(scan(&j, 8192, &r) == RADIX_SCAN_OK);
  CHECK(r.stream_bytes == 256 && r.key_len == 8 && r.n_blocks == 1);
  expect_ref(&j, 8192, m256, 1);
  free(j.b);
  case_end();
}

static void t_cap_utf8(void)
{
  jb_t j = {0};
  static const size_t caps[3] = { 4096, 8192, 16384 };
  size_t n = gen_text(tA, 40000, 7, 1);
  msg_t m[2] = { { 's', "review this file", 16, F_STRING, 0 }, { 'u', tA, n, F_STRING, 0 } };

  case_begin("E6: the cap lands on a UTF-8 boundary at 4, 8 and 16 KiB (Hangul, code newlines)");
  jb_chat(&j, NULL, m, 2, NULL);
  for (int c = 0; c < 3; c++) {
    static ref_t r;
    radix_scan_res_t res;
    ref_build(&r, caps[c], m, 2);
    expect_ref(&j, caps[c], m, 2);
    CHECK(scan(&j, caps[c], &res) == RADIX_SCAN_OK);
    CHECK(res.truncated && res.stream_bytes > caps[c] - 4 && res.stream_bytes <= caps[c]);
    CHECK(res.key_len == RADIX_SCAN_KEY_CAP(caps[c]) ||
          res.key_len == RADIX_SCAN_KEY_CAP(caps[c]) - 8);
    /* the reference cut is at a character start: the next stream byte of
     * the uncapped stream is a lead byte */
    CHECK((r.s[r.n - 1] & 0xC0) != 0xC0);
  }
  /* the same text with every non-ASCII character escaped */
  g_esc = 1;
  jb_chat(&j, NULL, m, 2, NULL);
  for (int c = 0; c < 3; c++)
    expect_ref(&j, caps[c], m, 2);
  g_esc = 0;
  free(j.b);
  case_end();
}

static void t_nul(void)
{
  jb_t j = {0};
  radix_scan_res_t r;
  uint8_t k1[KEYCAP_MAX];
  memset(tA, 'n', 400);
  tA[10] = 0;                          /* encoded as \u0000 by jb_str */
  memset(tB, 'n', 400);
  tB[10] = '0';
  msg_t a[1] = { { 'u', tA, 400, F_STRING, 0 } }, b[1] = { { 'u', tB, 400, F_STRING, 0 } };

  case_begin("E6: a \\u0000 escape contributes a real 0x00 to the stream");
  jb_chat(&j, NULL, a, 1, NULL);
  CHECK(strstr(j.b, "\\u0000") != NULL);
  expect_ref(&j, 8192, a, 1);
  CHECK(scan(&j, 8192, &r) == RADIX_SCAN_OK);
  memcpy(k1, g_key, r.key_len);
  jb_chat(&j, NULL, b, 1, NULL);
  CHECK(scan(&j, 8192, &r) == RADIX_SCAN_OK && memcmp(k1, g_key, 8) != 0);
  free(j.b);
  case_end();
}

static void t_side_hashes(void)
{
  jb_t j = {0};
  radix_scan_res_t r;
  static const char tools1[] = "[{\"type\":\"function\",\"function\":{\"name\":\"read\",\"parameters\":{}}}]";
  static const char tools2[] = "[{\"type\":\"function\",\"function\":{\"name\":\"edit\",\"parameters\":{}}}]";
  static const char kw1[] = "{\"enable_thinking\":false}";
  static const char kw2[] = "{\"enable_thinking\":true}";
  char before[256], after[256];
  uint64_t h_tools, h_kw;
  size_t n = gen_text(tA, 800, 8, 0);
  msg_t m[1] = { { 'u', tA, n, F_STRING, 0 } };

  case_begin("E6: tools and chat_template_kwargs hashes: raw value, stable wherever they appear; null is absent");
  jb_chat(&j, NULL, m, 1, NULL);
  CHECK(scan(&j, 8192, &r) == RADIX_SCAN_OK);
  CHECK(!r.has_tools && !r.has_tmpl_kwargs && r.tools_hash == 0 && r.tmpl_kwargs_hash == 0);

  snprintf(before, sizeof(before), "\"tools\":%s,\"chat_template_kwargs\":%s", tools1, kw1);
  jb_chat(&j, before, m, 1, NULL);
  CHECK(scan(&j, 8192, &r) == RADIX_SCAN_OK);
  CHECK(r.has_tools && r.has_tmpl_kwargs);
  CHECK(r.tools_hash == XXH64(tools1, sizeof(tools1) - 1, 0));
  CHECK(r.tmpl_kwargs_hash == XXH64(kw1, sizeof(kw1) - 1, 0));
  CHECK(r.hash_bytes == sizeof(tools1) - 1 + sizeof(kw1) - 1);
  h_tools = r.tools_hash;
  h_kw = r.tmpl_kwargs_hash;

  snprintf(after, sizeof(after), "\"chat_template_kwargs\":%s,\"stream\":true,\"tools\":%s", kw1, tools1);
  jb_chat(&j, NULL, m, 1, after);
  CHECK(scan(&j, 8192, &r) == RADIX_SCAN_OK);
  CHECK(r.tools_hash == h_tools && r.tmpl_kwargs_hash == h_kw);

  snprintf(after, sizeof(after), "\"t\\u006fols\":%s,\"chat_template_kwargs\":%s", tools2, kw2);
  jb_chat(&j, NULL, m, 1, after);
  CHECK(scan(&j, 8192, &r) == RADIX_SCAN_OK);
  CHECK(r.has_tools && r.tools_hash != h_tools && r.tmpl_kwargs_hash != h_kw);

  /* null template: no override */
  jb_chat(&j, "\"chat_template\":null", m, 1, NULL);
  CHECK(scan(&j, 8192, &r) == RADIX_SCAN_OK);

  /* null tools and kwargs: absent, nothing hashed */
  jb_chat(&j, "\"tools\":null", m, 1, "\"chat_template_kwargs\" : null");
  CHECK(scan(&j, 8192, &r) == RADIX_SCAN_OK);
  CHECK(!r.has_tools && !r.has_tmpl_kwargs && r.tools_hash == 0 &&
        r.tmpl_kwargs_hash == 0 && r.hash_bytes == 0);
  /* any other value is hashed raw, also a string or a scalar */
  jb_chat(&j, "\"tools\":\"none\"", m, 1, "\"chat_template_kwargs\":0");
  CHECK(scan(&j, 8192, &r) == RADIX_SCAN_OK);
  CHECK(r.has_tools == 1 && r.tools_hash == XXH64("\"none\"", 6, 0));
  CHECK(r.has_tmpl_kwargs == 1 && r.tmpl_kwargs_hash == XXH64("0", 1, 0));
  CHECK(r.hash_bytes == 7);

  /* a second key is a duplicate also when the first was null; the result
   * of the skip keeps has_* at 0 or 1 */
  {
    static const struct { const char *before, *after; } dup[4] = {
      { "\"tools\":[]", "\"tools\":[]" },
      { "\"tools\":null", "\"tools\":[]" },
      { "\"chat_template_kwargs\":{}", "\"chat_template_kwargs\":{}" },
      { "\"chat_template_kwargs\":null", "\"chat_template_kwargs\":null" },
    };
    for (int i = 0; i < 4; i++) {
      jb_chat(&j, dup[i].before, m, 1, dup[i].after);
      CHECK(scan(&j, 8192, &r) == RADIX_SKIP_DUPLICATE_KEY);
      CHECK(r.has_tools <= 1 && r.has_tmpl_kwargs <= 1);
      CHECK(r.has_tools == (i == 0) && r.has_tmpl_kwargs == (i == 2));
    }
  }
  free(j.b);
  case_end();
}

static void t_roles_and_empty_content(void)
{
  jb_t j = {0};
  size_t n = gen_text(tA, 400, 9, 1);
  msg_t m[7] = {
    { 's', "sys", 3, F_STRING, 0 }, { 'd', "dev", 3, F_STRING, 0 },
    { 'u', tA, n, F_STRING, 0 },    { 'a', "", 0, F_NULL, 0 },
    { 't', "tool output", 11, F_STRING, 0 }, { 'a', "", 0, F_ABSENT, 0 },
    { 'u', "", 0, F_PARTS, 1 },
  };

  case_begin("E6: all five roles; null, absent and empty content give markers only");
  jb_chat(&j, NULL, m, 7, NULL);
  expect_ref(&j, 8192, m, 7);
  {
    radix_scan_res_t r;
    CHECK(scan(&j, 8192, &r) == RADIX_SCAN_OK && r.n_messages == 7);
  }
  free(j.b);
  case_end();
}

typedef struct { const char *name; const char *body; radix_scan_rc_t want; } skip_t;

static void t_skips(void)
{
  static char big[1 << 15], deep_ok[1024], deep_bad[1024];
  static const skip_t cases[] = {
    { "non-text part", "{\"messages\":[{\"role\":\"user\",\"content\":[{\"type\":\"text\",\"text\":\"hi\"},{\"type\":\"image_url\",\"image_url\":{\"url\":\"x\"}}]}]}", RADIX_SKIP_NON_TEXT_PART },
    { "chat_template", "{\"chat_template\":\"{{x}}\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}", RADIX_SKIP_TEMPLATE_OVERRIDE },
    { "chat_template, escaped key", "{\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}],\"chat_\\u0074emplate\":\"t\"}", RADIX_SKIP_TEMPLATE_OVERRIDE },
    { "overlong UTF-8", "{\"messages\":[{\"role\":\"user\",\"content\":\"a\xC0\x80" "b\"}]}", RADIX_SKIP_INVALID_UTF8 },
    { "lead byte F5", "{\"messages\":[{\"role\":\"user\",\"content\":\"a\xF5\x80\x80\x80\"}]}", RADIX_SKIP_INVALID_UTF8 },
    { "UTF-8 surrogate", "{\"messages\":[{\"role\":\"user\",\"content\":\"a\xED\xA0\x80\"}]}", RADIX_SKIP_INVALID_UTF8 },
    { "above U+10FFFF", "{\"messages\":[{\"role\":\"user\",\"content\":\"a\xF4\x90\x80\x80\"}]}", RADIX_SKIP_INVALID_UTF8 },
    { "stray continuation", "{\"messages\":[{\"role\":\"user\",\"content\":\"a\x80\"}]}", RADIX_SKIP_INVALID_UTF8 },
    { "sequence cut by the quote", "{\"messages\":[{\"role\":\"user\",\"content\":\"a\xE3\x81\"}]}", RADIX_SKIP_INVALID_UTF8 },
    { "lone high surrogate escape", "{\"messages\":[{\"role\":\"user\",\"content\":\"a\\uD800b\"}]}", RADIX_SKIP_INVALID_UTF8 },
    { "lone low surrogate escape", "{\"messages\":[{\"role\":\"user\",\"content\":\"\\uDC00\"}]}", RADIX_SKIP_INVALID_UTF8 },
    { "not an object", "[{\"messages\":[]}]", RADIX_SKIP_MALFORMED },
    { "trailing comma", "{\"messages\":[{\"role\":\"user\",\"content\":\"hi\"},]}", RADIX_SKIP_MALFORMED },
    { "unterminated string", "{\"messages\":[{\"role\":\"user\",\"content\":\"hi}]}", RADIX_SKIP_MALFORMED },
    { "bad escape", "{\"messages\":[{\"role\":\"user\",\"content\":\"h\\xi\"}]}", RADIX_SKIP_MALFORMED },
    { "short \\u escape", "{\"messages\":[{\"role\":\"user\",\"content\":\"h\\u12\"}]}", RADIX_SKIP_MALFORMED },
    { "control character", "{\"messages\":[{\"role\":\"user\",\"content\":\"h\ni\"}]}", RADIX_SKIP_MALFORMED },
    { "garbage after the object", "{\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]} x", RADIX_SKIP_MALFORMED },
    { "mismatched bracket", "{\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}}", RADIX_SKIP_MALFORMED },
    { "bad literal", "{\"stream\":tru,\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}", RADIX_SKIP_MALFORMED },
    { "truncated body", "{\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]", RADIX_SKIP_MALFORMED },
    { "empty body", "", RADIX_SKIP_MALFORMED },
    { "no messages", "{\"model\":\"m\",\"prompt\":\"hi\"}", RADIX_SKIP_NO_MESSAGES },
    { "messages not an array", "{\"messages\":{\"role\":\"user\"}}", RADIX_SKIP_NO_MESSAGES },
    { "messages empty", "{\"messages\":[]}", RADIX_SKIP_NO_MESSAGES },
    { "duplicate messages", "{\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}],\"m\\u0065ssages\":[]}", RADIX_SKIP_DUPLICATE_KEY },
    { "duplicate tools", "{\"tools\":[],\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}],\"tools\":[]}", RADIX_SKIP_DUPLICATE_KEY },
    { "duplicate role", "{\"messages\":[{\"role\":\"user\",\"role\":\"system\",\"content\":\"hi\"}]}", RADIX_SKIP_DUPLICATE_KEY },
    { "duplicate content", "{\"messages\":[{\"role\":\"user\",\"content\":\"a\",\"content\":\"b\"}]}", RADIX_SKIP_DUPLICATE_KEY },
    { "duplicate part type", "{\"messages\":[{\"role\":\"user\",\"content\":[{\"type\":\"text\",\"type\":\"text\",\"text\":\"a\"}]}]}", RADIX_SKIP_DUPLICATE_KEY },
    { "message not an object", "{\"messages\":[\"hi\"]}", RADIX_SKIP_BAD_MESSAGE },
    { "role missing", "{\"messages\":[{\"content\":\"hi\"}]}", RADIX_SKIP_BAD_MESSAGE },
    { "role not a string", "{\"messages\":[{\"role\":1,\"content\":\"hi\"}]}", RADIX_SKIP_BAD_MESSAGE },
    { "content a number", "{\"messages\":[{\"role\":\"user\",\"content\":5}]}", RADIX_SKIP_BAD_MESSAGE },
    { "part not an object", "{\"messages\":[{\"role\":\"user\",\"content\":[\"hi\"]}]}", RADIX_SKIP_BAD_MESSAGE },
    { "part without type", "{\"messages\":[{\"role\":\"user\",\"content\":[{\"text\":\"hi\"}]}]}", RADIX_SKIP_BAD_MESSAGE },
    { "text part without text", "{\"messages\":[{\"role\":\"user\",\"content\":[{\"type\":\"text\"}]}]}", RADIX_SKIP_BAD_MESSAGE },
    { "unknown role", "{\"messages\":[{\"role\":\"narrator\",\"content\":\"hi\"}]}", RADIX_SKIP_UNKNOWN_ROLE },
    { "no content at all", "{\"messages\":[{\"role\":\"user\",\"content\":\"\"},{\"role\":\"assistant\",\"content\":null}]}", RADIX_SKIP_EMPTY },
    { "short stream", "{\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}", RADIX_SKIP_SHORT },
  };
  radix_scan_res_t r;
  int seen[RADIX_SCAN__COUNT] = {0};

  case_begin("E6: every skip reason is produced by its input");
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    radix_scan_rc_t rc = scan_s(cases[i].body, 8192, &r);
    if (rc != cases[i].want) {
      CHECK(rc == cases[i].want);
      printf("    %s: got %d, want %d\n", cases[i].name, rc, cases[i].want);
    }
    CHECK(r.key_len == 0);
    seen[cases[i].want]++;
  }

  /* checks after the cap: a non-text part and an unknown role still skip */
  {
    jb_t j = {0};
    size_t n = gen_text(tA, 10000, 10, 0);
    msg_t m[1] = { { 'u', tA, n, F_STRING, 0 } };
    static const char img[] = ",{\"role\":\"user\",\"content\":[{\"type\":\"image_url\",\"image_url\":{}}]}]}";
    size_t base;
    jb_chat(&j, NULL, m, 1, NULL);
    j.n -= 2;                       /* drop ]} and append one more message */
    base = j.n;
    jb_raw(&j, img);
    CHECK(scan(&j, 4096, &r) == RADIX_SKIP_NON_TEXT_PART);
    j.n = base;
    jb_raw(&j, ",{\"role\":\"narrator\",\"content\":\"x\"}]}");
    CHECK(scan(&j, 4096, &r) == RADIX_SKIP_UNKNOWN_ROLE);
    free(j.b);
  }

  /* body over the maximum: nothing read */
  memset(big, ' ', sizeof(big));
  CHECK(scan_n(big, sizeof(big), sizeof(big) - 1, 8192, &r) == RADIX_SKIP_BODY_TOO_LARGE);
  CHECK(r.skim_bytes == 0 && r.decode_bytes == 0);
  seen[RADIX_SKIP_BODY_TOO_LARGE]++;

  /* nesting: 128 containers deep is accepted, 129 is too deep */
  {
    size_t n = 0;
    int extra = RADIX_SCAN_DEPTH_MAX - 1;      /* plus the top-level object */
    memset(tA, 'v', 300);
    n += (size_t)snprintf(deep_ok + n, sizeof(deep_ok) - n, "{\"x\":");
    for (int i = 0; i < extra; i++) deep_ok[n++] = '[';
    for (int i = 0; i < extra; i++) deep_ok[n++] = ']';
    n += (size_t)snprintf(deep_ok + n, sizeof(deep_ok) - n,
                          ",\"messages\":[{\"role\":\"user\",\"content\":\"%.300s\"}]}", tA);
    CHECK(scan_n(deep_ok, n, 1 << 20, 8192, &r) == RADIX_SCAN_OK);
    n = 0;
    n += (size_t)snprintf(deep_bad + n, sizeof(deep_bad) - n, "{\"x\":");
    for (int i = 0; i <= extra; i++) deep_bad[n++] = '[';
    for (int i = 0; i <= extra; i++) deep_bad[n++] = ']';
    n += (size_t)snprintf(deep_bad + n, sizeof(deep_bad) - n,
                          ",\"messages\":[{\"role\":\"user\",\"content\":\"%.300s\"}]}", tA);
    CHECK(scan_n(deep_bad, n, 1 << 20, 8192, &r) == RADIX_SKIP_TOO_DEEP);
    seen[RADIX_SKIP_TOO_DEEP]++;
  }

  /* bad arguments */
  {
    uint8_t k[8];
    CHECK(radix_scan_chat(NULL, 0, 100, 8192, k, sizeof(k), &r) == RADIX_SKIP_BAD_ARG);
    CHECK(radix_scan_chat("{}", 2, 100, 0, k, sizeof(k), &r) == RADIX_SKIP_BAD_ARG);
    CHECK(radix_scan_chat("{}", 2, 100, 8192, k, sizeof(k), &r) == RADIX_SKIP_BAD_ARG);
    CHECK(radix_scan_chat("{}", 2, 100, 8192, k, sizeof(k), NULL) == RADIX_SKIP_BAD_ARG);
    CHECK(radix_scan_chat("{}", 2, 100, RADIX_SCAN_CAP_MAX + 1, g_key,
                          RADIX_SCAN_KEY_CAP(RADIX_SCAN_CAP_MAX + 1), &r) == RADIX_SKIP_BAD_ARG);
    seen[RADIX_SKIP_BAD_ARG]++;
  }
  for (int rc = 1; rc < RADIX_SCAN__COUNT; rc++) {
    CHECK(seen[rc] > 0);
  }
  case_end();
}

static void t_helpers(void)
{
  case_begin("E6: score helper and result names");
  CHECK(radix_scan_matched_bytes(0) == 0);
  CHECK(radix_scan_matched_bytes(8) == 256);
  CHECK(radix_scan_matched_bytes(15) == 256);
  CHECK(radix_scan_matched_bytes(256) == 8192);
  for (int a = 0; a < RADIX_SCAN__COUNT; a++) {
    const char *na = radix_scan_rc_name((radix_scan_rc_t)a);
    CHECK(na && *na);
    for (int b = 0; b < a; b++)
      CHECK(na && strcmp(na, radix_scan_rc_name((radix_scan_rc_t)b)) != 0);
  }
  CHECK(radix_scan_rc_name(RADIX_SCAN__COUNT) && *radix_scan_rc_name(RADIX_SCAN__COUNT));
  case_end();
}

/* ================= E7: bounds and no retained text ================= */

static void t_bounds_768k(void)
{
  jb_t j = {0};
  static char huge[800 * 1024];
  char tools[64];
  radix_scan_res_t r;
  size_t n = gen_text(huge, 690 * 1024, 11, 1);   /* escaped newlines make ~768 KiB */
  msg_t m[2] = { { 's', "summarize", 9, F_STRING, 0 }, { 'u', huge, n, F_STRING, 0 } };

  case_begin("E7: a 768 KiB body: decode and digest bounded by the cap, skim by 2x the body");
  snprintf(tools, sizeof(tools), "\"tools\":[{\"type\":\"function\"}]");
  jb_chat(&j, NULL, m, 2, tools);
  CHECK(j.n >= 740 * 1024 && j.n <= 800 * 1024);
  for (size_t cap = 4096; cap <= 16384; cap *= 2) {
    expect_ref(&j, cap, m, 2);
    CHECK(scan(&j, cap, &r) == RADIX_SCAN_OK);
    CHECK(r.has_tools);
    CHECK(r.decode_bytes <= 6 * cap + 12);
    CHECK(r.skim_bytes >= j.n && r.skim_bytes <= 2 * (uint64_t)j.n);
    printf("    cap %zu: body %zu, skim %llu, decode %llu, hash %llu, stream %zu, blocks %u\n",
           cap, j.n, (unsigned long long)r.skim_bytes, (unsigned long long)r.decode_bytes,
           (unsigned long long)r.hash_bytes, r.stream_bytes, r.n_blocks);
  }
  free(j.b);
  case_end();
}

static void t_bounds_tokens(void)
{
  jb_t j = {0};
  radix_scan_res_t r;
  static msg_t m[6000];
  size_t tok = 0;

  case_begin("E7: a body above 8,192 JSON tokens (6,000 messages, 3,000 tools)");
  for (int i = 0; i < 6000; i++) {
    m[i].role = i % 2 ? 'a' : 'u';
    m[i].text = "step";
    m[i].len = 4;
    m[i].form = F_STRING;
  }
  jb_chat(&j, NULL, m, 6000, NULL);
  j.n -= 1;
  jb_raw(&j, ",\"tools\":[");
  for (int i = 0; i < 3000; i++)
    jb_raw(&j, i ? ",{\"type\":\"function\",\"n\":1}" : "{\"type\":\"function\",\"n\":1}");
  jb_raw(&j, "]}");
  for (size_t i = 0; i < j.n; i++)       /* every string, number and container */
    tok += j.b[i] == '{' || j.b[i] == '[' || j.b[i] == ':' || j.b[i] == ',';
  CHECK(tok > 8192);
  expect_ref(&j, 8192, m, 6000);
  CHECK(scan(&j, 8192, &r) == RADIX_SCAN_OK && r.has_tools);
  CHECK(r.skim_bytes <= 2 * (uint64_t)j.n);
  printf("    body %zu bytes, > %zu tokens: skim %llu, decode %llu, stream %zu\n", j.n, tok,
         (unsigned long long)r.skim_bytes, (unsigned long long)r.decode_bytes, r.stream_bytes);
  free(j.b);
  case_end();
}

static void t_bounds_parts(void)
{
  jb_t j = {0};
  radix_scan_res_t r;
  static msg_t m[200];
  size_t n = gen_text(tA, 20000, 12, 0);

  case_begin("E7: a body of text-part arrays: skim needs and stays within 2x the body");
  for (int i = 0; i < 200; i++) {
    m[i].role = 'u';
    m[i].text = tA;
    m[i].len = n;
    m[i].form = F_PARTS;
    m[i].nparts = 40;
  }
  jb_chat(&j, NULL, m, 200, NULL);
  expect_ref(&j, 8192, m, 200);
  CHECK(scan(&j, 8192, &r) == RADIX_SCAN_OK);
  CHECK(r.skim_bytes > (uint64_t)j.n * 3 / 2 && r.skim_bytes <= 2 * (uint64_t)j.n);
  printf("    body %zu bytes: skim %llu (%.2f x body)\n", j.n,
         (unsigned long long)r.skim_bytes, (double)r.skim_bytes / (double)j.n);
  free(j.b);
  case_end();
}

static void t_bounds_escapes(void)
{
  jb_t j = {0};
  radix_scan_res_t r;
  size_t n = gen_text(tA, 30000, 13, 0);
  msg_t m[1] = { { 'u', tA, n, F_STRING, 0 } };

  case_begin("E7: fully \\u-escaped content: decode work at most 6 source bytes per stream byte");
  g_esc = 2;
  jb_chat(&j, NULL, m, 1, NULL);
  g_esc = 0;
  for (size_t cap = 4096; cap <= 16384; cap *= 2) {
    expect_ref(&j, cap, m, 1);
    CHECK(scan(&j, cap, &r) == RADIX_SCAN_OK);
    CHECK(r.decode_bytes > 5 * (uint64_t)cap && r.decode_bytes <= 6 * (uint64_t)cap + 12);
  }
  free(j.b);
  case_end();
}

static int contains(const uint8_t *hay, size_t hn, const char *needle, size_t nn)
{
  for (size_t i = 0; i + nn <= hn; i++)
    if (!memcmp(hay + i, needle, nn))
      return 1;
  return 0;
}

static void t_no_text_retained(void)
{
  static const char mark[] = "ZQXJ-marker-7f3a9c1e";
  const size_t ml = sizeof(mark) - 1;
  jb_t j = {0};
  radix_scan_res_t r;
  size_t n = 0;

  case_begin("E7: key buffer and result hold digests and counters only (marker string absent)");
  for (int i = 0; i < 300; i++) {      /* the marker in the first block and far beyond */
    memcpy(tA + n, mark, ml);
    n += ml;
    tA[n++] = ' ';
  }
  {
    msg_t m[1] = { { 'u', tA, n, F_STRING, 0 } };
    jb_chat(&j, NULL, m, 1, NULL);
  }
  for (size_t cap = 4096; cap <= 16384; cap *= 2) {
    radix_scan_rc_t rc = scan(&j, cap, &r);
    CHECK(rc == RADIX_SCAN_OK);
    for (size_t w = 4; w <= ml; w += 4) {   /* any 4-byte or longer window */
      for (size_t at = 0; at + w <= ml; at++) {
        CHECK(!contains(g_key, sizeof(g_key), mark + at, w));
        CHECK(!contains((const uint8_t *)&r, sizeof(r), mark + at, w));
      }
    }
  }
  /* also on a skip after the content was read */
  j.n -= 2;
  jb_raw(&j, ",{\"role\":\"narrator\",\"content\":\"x\"}]}");
  CHECK(scan(&j, 8192, &r) == RADIX_SKIP_UNKNOWN_ROLE);
  CHECK(!contains(g_key, sizeof(g_key), mark, 8));
  CHECK(!contains((const uint8_t *)&r, sizeof(r), mark, 8));
  free(j.b);
  case_end();
}

/* ================= robustness: untrusted input ================= */

/* Valid bodies, each OK at full length: string content, text parts, tools
 * and kwargs, escapes, multi-byte text, role last, null and absent content. */
#define ROB_N 7
static jb_t g_rob[ROB_N];

static void rob_bodies(void)
{
  static char a[4096], b[4096], c[4096];
  size_t na = gen_text(a, 1200, 21, 1), nb = gen_text(b, 900, 22, 1), nc = gen_text(c, 700, 23, 0);
  msg_t m0[2] = { { 's', "you are terse", 13, F_STRING, 0 }, { 'u', a, na, F_STRING, 0 } };
  msg_t m1[2] = { { 's', "sys", 3, F_PARTS, 2 }, { 'u', b, nb, F_PARTS_TEXT_FIRST, 4 } };
  msg_t m2[2] = { { 'd', c, nc, F_STRING, 0 }, { 'u', "go \"on\" \\ now", 13, F_PARTS, 1 } };
  msg_t m3[1] = { { 'u', a, na, F_STRING, 0 } };
  msg_t m4[1] = { { 'u', c, 300, F_STRING, 0 } };
  msg_t m5[5] = { { 's', c, 280, F_ROLE_LAST, 0 }, { 'a', "", 0, F_NULL, 0 },
                  { 't', "{\"ok\":1}", 8, F_STRING, 0 }, { 'a', "", 0, F_ABSENT, 0 },
                  { 'u', b, 200, F_PARTS, 3 } };
  msg_t m6[1] = { { 'u', b, nb, F_STRING, 0 } };

  for (int i = 0; i < ROB_N; i++)
    free(g_rob[i].b);
  memset(g_rob, 0, sizeof(g_rob));
  jb_chat(&g_rob[0], NULL, m0, 2, "\"stream\":true,\"max_tokens\":128,\"temperature\":0.7,\"stop\":null");
  jb_chat(&g_rob[1], "\"model_ext\":{\"a\":[1,-2.5e3,true,false,null]}", m1, 2, NULL);
  jb_chat(&g_rob[2], "\"tools\":[{\"type\":\"function\",\"function\":{\"name\":\"f\",\"parameters\":{}}}]",
          m2, 2, "\"chat_template_kwargs\":{\"enable_thinking\":false},\"chat_template\":null");
  g_esc = 1;
  jb_chat(&g_rob[3], NULL, m3, 1, NULL);
  g_esc = 2;
  jb_chat(&g_rob[4], NULL, m4, 1, NULL);
  g_esc = 0;
  jb_chat(&g_rob[5], NULL, m5, 5, NULL);
  jb_chat(&g_rob[6], "\"messages_x\":1", m6, 1, "\"tools\":[]");
}

/* Scan an exact-size heap copy into a key buffer filled with 0xA5; returns
 * whether every key byte at or beyond key_len (all of it on a skip) is
 * still 0xA5. */
static int scan_canary(const char *body, size_t len, size_t cap,
                       radix_scan_rc_t *rc, radix_scan_res_t *res)
{
  char *copy = malloc(len ? len : 1);
  size_t from;
  memcpy(copy, body, len);
  memset(g_key, 0xA5, sizeof(g_key));
  *rc = radix_scan_chat(copy, len, (size_t)1 << 20, cap, g_key,
                        RADIX_SCAN_KEY_CAP(cap), res);
  free(copy);
  from = *rc == RADIX_SCAN_OK ? res->key_len : 0;
  for (size_t i = from; i < sizeof(g_key); i++)
    if (g_key[i] != 0xA5)
      return 0;
  return 1;
}

/* Rule: a strict prefix of a body that ends at its closing brace is never one
 * complete JSON object, so every strict prefix skips as MALFORMED. With
 * whitespace after the closing brace, every prefix that holds the brace is
 * the same object and gives the full body's rc and key. */
static void t_truncation(void)
{
  static const size_t caps[2] = { 512, 8192 };
  static uint8_t want[KEYCAP_MAX];
  unsigned long scans = 0;

  case_begin("robustness: every strict prefix of a valid body skips MALFORMED; key untouched");
  rob_bodies();
  for (int b = 0; b < ROB_N; b++) {
    jb_t *j = &g_rob[b];
    for (int c = 0; c < 2; c++) {
      radix_scan_res_t r, full;
      radix_scan_rc_t rc, frc;
      size_t n = j->n;
      CHECK(scan_canary(j->b, n, caps[c], &frc, &full));
      CHECK(frc == RADIX_SCAN_OK);
      memcpy(want, g_key, full.key_len);
      for (size_t len = 0; len < n; len++) {
        int ok = scan_canary(j->b, len, caps[c], &rc, &r);
        scans++;
        CHECK((unsigned)rc < RADIX_SCAN__COUNT);
        CHECK(rc == RADIX_SKIP_MALFORMED);
        CHECK(ok && r.key_len == 0);
        check_bounds(&r, len, caps[c]);
        if (rc != RADIX_SKIP_MALFORMED && g_case_fail <= 6)
          printf("    body %d cap %zu prefix %zu of %zu: %s\n", b, caps[c], len, n,
                 radix_scan_rc_name(rc));
      }
      jb_raw(j, " \n\t");
      for (size_t len = n; len <= j->n; len++) {
        int ok = scan_canary(j->b, len, caps[c], &rc, &r);
        scans++;
        CHECK(rc == frc && ok && r.key_len == full.key_len);
        CHECK(!memcmp(g_key, want, full.key_len));
      }
      j->n = n;
      j->b[n] = 0;
    }
  }
  printf("    %lu scans over %d bodies at caps 512 and 8192\n", scans, ROB_N);
  case_end();
}

static uint64_t g_mx = 0x9E3779B97F4A7C15ULL;
static uint64_t mrnd(void)
{
  g_mx ^= g_mx >> 12; g_mx ^= g_mx << 25; g_mx ^= g_mx >> 27;
  return g_mx * 0x2545F4914F6CDD1DULL;
}

/* Fixed seed; byte flips, bit flips, inserts, deletes and slice copies on the
 * robustness bodies. Expect: no sanitizer report, rc in range, the work
 * bounds on every scan, the key buffer untouched beyond key_len, and an OK
 * key of whole digests within the key capacity. */
static void t_mutation(void)
{
  enum { ITER = 200000 };
  static const size_t caps[4] = { 256, 1024, 8192, 16384 };
  static const char dict[] = "{}[]\":,\\u0aAnt-.eE \x7f\x80\xbf\xc0\xc2\xe0\xed\xf0\xf4\xf5\xfe\xff";
  static char buf[8192];
  unsigned long hist[RADIX_SCAN__COUNT + 1] = {0};

  case_begin("robustness: 200,000 mutated bodies (fixed seed): rc in range, bounds hold, key untouched");
  rob_bodies();
  for (int it = 0; it < ITER; it++) {
    const jb_t *src = &g_rob[mrnd() % ROB_N];
    size_t n = src->n, cap = caps[mrnd() % 4];
    int nm = 1 + (int)(mrnd() % 4);
    radix_scan_rc_t rc;
    radix_scan_res_t r;
    int ok;
    memcpy(buf, src->b, n);
    for (int k = 0; k < nm; k++) {
      size_t at = n ? mrnd() % n : 0;
      uint64_t op = mrnd() % 6;
      uint8_t v = mrnd() % 2 ? (uint8_t)dict[mrnd() % (sizeof(dict) - 1)] : (uint8_t)mrnd();
      if (op == 0 && n) {
        buf[at] = (char)v;
      } else if (op == 1 && n) {
        buf[at] ^= (char)(1u << (mrnd() % 8));
      } else if (op == 2 && n + 1 < sizeof(buf)) {
        memmove(buf + at + 1, buf + at, n - at);
        buf[at] = (char)v;
        n++;
      } else if (op == 3 && n) {
        memmove(buf + at, buf + at + 1, n - at - 1);
        n--;
      } else if (op == 4 && n) {
        size_t from = mrnd() % n, len = 1 + mrnd() % 32;
        if (from + len > n) len = n - from;
        if (at + len > n) len = n - at;
        memmove(buf + at, buf + from, len);
      } else if (op == 5 && n) {
        size_t from = mrnd() % n, len = 1 + mrnd() % 32;
        if (from + len > n) len = n - from;
        if (n + len < sizeof(buf)) {
          char tmp[32];
          memcpy(tmp, buf + from, len);
          memmove(buf + at + len, buf + at, n - at);
          memcpy(buf + at, tmp, len);
          n += len;
        }
      }
    }
    ok = scan_canary(buf, n, cap, &rc, &r);
    CHECK((unsigned)rc < RADIX_SCAN__COUNT);
    hist[(unsigned)rc < RADIX_SCAN__COUNT ? rc : RADIX_SCAN__COUNT]++;
    CHECK(ok);
    check_bounds(&r, n, cap);
    if (rc == RADIX_SCAN_OK) {
      CHECK(r.key_len == (size_t)r.n_blocks * 8 && r.key_len <= RADIX_SCAN_KEY_CAP(cap));
      CHECK(r.n_blocks == r.stream_bytes / RADIX_SCAN_BLOCK && r.n_blocks > 0);
    } else {
      CHECK(r.key_len == 0);
    }
  }
  printf("    results:");
  for (int i = 0; i < RADIX_SCAN__COUNT; i++)
    if (hist[i])
      printf(" %s %lu", radix_scan_rc_name((radix_scan_rc_t)i), hist[i]);
  printf("%s\n", hist[RADIX_SCAN__COUNT] ? " OUT-OF-RANGE" : "");
  case_end();
}

/* ================= ASCII runs: pin the append path =================
 *
 * A run is a stretch of content bytes that decode to themselves (not '\',
 * below 0x80). These cases pin, against the reference stream, what happens
 * where a run meets a block boundary, the cap, an escape, a multi-byte
 * character, a \u0000 and a text-part boundary. The differential case
 * compares every counter of these bodies, and of a wider set, with values
 * recorded from the per-character append (test_radix_scan_golden.h). */

enum { RUN_EDGES, RUN_CAP, RUN_INTERRUPT, RUN_PARTS, RUN__GROUPS };

static void fill_ascii(char *out, size_t n, uint32_t seed)
{
  uint32_t x = seed * 2654435761u + 7;
  for (size_t i = 0; i < n; i++) {
    x = x * 1103515245u + 12345u;
    out[i] = (char)('a' + (x >> 16) % 26);
  }
}

static size_t put_cp(char *out, uint32_t cp)
{
  if (cp < 0x80) { out[0] = (char)cp; return 1; }
  if (cp < 0x800) { out[0] = (char)(0xC0 | (cp >> 6)); out[1] = (char)(0x80 | (cp & 0x3F)); return 2; }
  if (cp < 0x10000) {
    out[0] = (char)(0xE0 | (cp >> 12)); out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
    out[2] = (char)(0x80 | (cp & 0x3F)); return 3;
  }
  out[0] = (char)(0xF0 | (cp >> 18)); out[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
  out[2] = (char)(0x80 | ((cp >> 6) & 0x3F)); out[3] = (char)(0x80 | (cp & 0x3F)); return 4;
}

/* Body idx of the run cases: fills j, the cap, the reference messages and
 * the group; 0 past the last body. One user message unless stated, so
 * content byte i sits at stream offset 2 + i. */
static int run_body(int idx, jb_t *j, size_t *cap, msg_t *m, int *nm, int *group)
{
  static const size_t edges[6] = { 255, 256, 257, 511, 512, 513 };
  static const size_t caps[3] = { 4096, 8192, 16384 };
  static const uint32_t inter[4] = { 0xE9, 0xAC00, 0x1F600, 0 };   /* 2, 3, 4 bytes; NUL */
  static const char esc[5] = { '"', '\\', '\n', '\t', 1 };
  int i = idx;

  *nm = 1;
  *cap = 8192;
  m[0] = (msg_t){ 'u', tA, 0, F_STRING, 0 };

  /* edges: the stream ends at e; a run ends at e before an escape; a run
   * ends at e before a 3-byte character */
  if (i < 18) {
    size_t e = edges[i / 3];
    *group = RUN_EDGES;
    switch (i % 3) {
    case 0:
      fill_ascii(tA, e - 3, (uint32_t)e);
      m[0].len = e - 3;
      break;
    case 1:
      fill_ascii(tA, 1200, (uint32_t)e + 1);
      tA[e - 2] = '\n';
      m[0].len = 1200;
      break;
    default:
      fill_ascii(tA, 1200, (uint32_t)e + 2);
      put_cp(tA + e - 2, 0xAC00);
      m[0].len = 1200;
      break;
    }
    jb_chat(j, NULL, m, 1, NULL);
    return 1;
  }
  i -= 18;

  /* cap: a 600-byte run between two tabs; the cap 300 bytes into it, at
   * its first byte (cap = start, cap = start + 1), at its last byte
   * (cap = end - 1, cap = end), for 4, 8 and 16 KiB; then the run as the
   * string's last bytes, ending at the cap and one byte past it (the next
   * piece is the end marker, not a character) */
  if (i < 15) {
    size_t c = caps[i / 5], s, A, B = 600;
    *group = RUN_CAP;
    switch (i % 5) {
    case 0: s = c - 300; break;
    case 1: s = c; break;
    case 2: s = c - 1; break;
    case 3: s = c + 1 - B; break;
    default: s = c - B; break;
    }
    A = s - 3;                         /* 2 marker bytes, A bytes, the tab */
    fill_ascii(tA, A + 1 + B + 1 + 2000, (uint32_t)(c + i));
    tA[A] = '\t';
    tA[A + 1 + B] = '\t';
    m[0].len = A + 1 + B + 1 + 2000;
    *cap = c;
    jb_chat(j, NULL, m, 1, NULL);
    return 1;
  }
  i -= 15;
  if (i < 6) {
    size_t c = caps[i / 2], B = 600, e = c + (size_t)(i % 2), A = e - B - 3;
    *group = RUN_CAP;
    fill_ascii(tA, A + 1 + B, (uint32_t)(c + 40 + i));
    tA[A] = '\t';
    m[0].len = A + 1 + B;              /* the run ends the string at e */
    *cap = c;
    jb_chat(j, NULL, m, 1, NULL);
    return 1;
  }
  i -= 6;

  /* interrupt: at stream offsets 255, 256, 257 a run meets each escape,
   * each multi-byte character and a \u0000 */
  if (i < 27) {
    size_t off = 255 + (size_t)(i % 3), at = off - 2;
    int what = i / 3;                   /* 0-4 escapes, 5-8 characters */
    *group = RUN_INTERRUPT;
    fill_ascii(tA, 1500, (uint32_t)(off * 10 + (size_t)what));
    if (what < 5) {
      tA[at] = esc[what];
    } else {
      char cbuf[4];
      size_t k = put_cp(cbuf, inter[what - 5]);
      memcpy(tA + at, cbuf, k);
    }
    m[0].len = 1500;
    jb_chat(j, NULL, m, 1, NULL);
    return 1;
  }
  i -= 27;

  /* A inside a run: an escape that decodes to ASCII */
  if (i < 3) {
    size_t off = 255 + (size_t)i, at = off - 2;
    *group = RUN_INTERRUPT;
    fill_ascii(tA, 900, (uint32_t)(off + 77));
    tA[at] = 'A';
    m[0].len = 900;
    j->n = 0;
    jb_raw(j, "{\"model\":\"m\",\"messages\":[{\"role\":\"user\",\"content\":\"");
    jb_bytes(j, tA, at);
    jb_raw(j, "\\u0041");
    jb_bytes(j, tA + at + 1, 900 - at - 1);
    jb_raw(j, "\"}]}");
    return 1;
  }
  i -= 3;

  /* parts: one run split across two text parts at stream offsets 255..257
   * and 511..513 (the builder splits at len / 2) */
  if (i < 6) {
    size_t off = edges[i], len = 2 * (off - 2);
    *group = RUN_PARTS;
    fill_ascii(tA, len, (uint32_t)(off + 500));
    m[0].len = len;
    m[0].form = F_PARTS;
    m[0].nparts = 2;
    jb_chat(j, NULL, m, 1, NULL);
    m[0].form = F_STRING;               /* the reference: same stream */
    m[0].nparts = 0;
    return 1;
  }
  return 0;
}

static void t_runs(void)
{
  static const char *names[RUN__GROUPS] = {
    "runs: a run or the stream ends at a block boundary and one byte either side (255-257, 511-513)",
    "runs: the cap inside a run, at its first byte and at its last, at 4, 8 and 16 KiB",
    "runs: a run meets an escape, a 2/3/4-byte character, a \\u0000 and a \\u0041 at 255-257",
    "runs: one run split across two text parts at a block boundary and one byte either side",
  };
  jb_t j = {0};
  msg_t m[2];
  size_t cap;
  int nm, g;

  for (int grp = 0; grp < RUN__GROUPS; grp++) {
    int n = 0;
    case_begin(names[grp]);
    for (int i = 0; run_body(i, &j, &cap, m, &nm, &g); i++) {
      if (g != grp)
        continue;
      expect_ref(&j, cap, m, nm);
      n++;
    }
    CHECK(n > 0);
    case_end();
  }
  free(j.b);
}

/* ---- differential: results recorded from the per-character append ---- */

typedef struct {
  int      rc;
  size_t   key_len, stream_bytes;
  uint32_t n_blocks, n_messages;
  unsigned truncated, has_tools, has_tmpl_kwargs;
  uint64_t tools_hash, tmpl_kwargs_hash, skim_bytes, decode_bytes, hash_bytes;
  const char *key_hex;
} golden_t;

/* Body idx of the differential set: every run body, then generated bodies
 * (ASCII and mixed text, three escaping levels, four sizes, string and
 * four-part content), four caps on one long body, and the robustness
 * bodies (tools, kwargs, five roles, null and absent content). */
static int diff_body(int idx, jb_t *j, size_t *cap)
{
  static const size_t sizes[4] = { 300, 2900, 9000, 20000 };
  static const size_t caps[4] = { 256, 4096, 8192, 16384 };
  msg_t m[2];
  int nm, g, i = idx;

  if (run_body(i, j, cap, m, &nm, &g))
    return 1;
  for (int k = 0; run_body(k, j, cap, m, &nm, &g); k++)
    i--;                                /* i -= number of run bodies */
  *cap = 8192;
  if (i < 48) {
    int mix = i / 24, esc = (i / 8) % 3, sz = (i / 2) % 4, parts = i % 2;
    size_t n = gen_text(tB, sizes[sz], (uint32_t)(100 + i), mix);
    m[0] = (msg_t){ 's', "you answer in one line", 22, F_STRING, 0 };
    m[1] = (msg_t){ 'u', tB, n, parts ? F_PARTS : F_STRING, parts ? 4 : 0 };
    g_esc = esc;
    jb_chat(j, NULL, m, 2, NULL);
    g_esc = 0;
    return 1;
  }
  i -= 48;
  if (i < 4) {
    size_t n = gen_text(tB, 20000, 999, 1);
    m[0] = (msg_t){ 'u', tB, n, F_STRING, 0 };
    *cap = caps[i];
    jb_chat(j, NULL, m, 1, NULL);
    return 1;
  }
  i -= 4;
  if (i < ROB_N) {
    if (i == 0)
      rob_bodies();
    if (!g_rob[i].b)
      return 0;
    j->n = 0;
    jb_bytes(j, g_rob[i].b, g_rob[i].n);
    return 1;
  }
  return 0;
}

static void key_hex(char *out, const uint8_t *k, size_t n)
{
  static const char hx[] = "0123456789abcdef";
  for (size_t i = 0; i < n; i++) {
    out[2 * i] = hx[k[i] >> 4];
    out[2 * i + 1] = hx[k[i] & 15];
  }
  out[2 * n] = 0;
}

#ifdef RADIX_SCAN_GOLDEN_RECORD
/* Prints test_radix_scan_golden.h from the scanner this file includes. */
static void record_golden(void)
{
  jb_t j = {0};
  size_t cap;
  static char hex[2 * KEYCAP_MAX + 1];
  printf("/* SPDX-License-Identifier: (GPL-2.0) */\n"
         "/* test_radix_scan_golden.h - scan results of the differential set in\n"
         " * test_radix_scan.c, recorded from the per-character append (before\n"
         " * the ASCII-run append). Generated: build test_radix_scan.c with\n"
         " * -DRADIX_SCAN_GOLDEN_RECORD and run it; do not edit by hand. */\n"
         "static const golden_t g_golden[] = {\n");
  for (int i = 0; diff_body(i, &j, &cap); i++) {
    radix_scan_res_t r;
    radix_scan_rc_t rc = scan(&j, cap, &r);
    key_hex(hex, g_key, rc == RADIX_SCAN_OK ? r.key_len : 0);
    printf("  { %d, %zu, %zu, %u, %u, %u, %u, %u, 0x%016llxull, 0x%016llxull, %llu, %llu, %llu,\n    \"%s\" },\n",
           (int)rc, r.key_len, r.stream_bytes, r.n_blocks, r.n_messages,
           (unsigned)r.truncated, (unsigned)r.has_tools, (unsigned)r.has_tmpl_kwargs,
           (unsigned long long)r.tools_hash, (unsigned long long)r.tmpl_kwargs_hash,
           (unsigned long long)r.skim_bytes, (unsigned long long)r.decode_bytes,
           (unsigned long long)r.hash_bytes, hex);
  }
  printf("};\n");
  free(j.b);
}
#else
#include "test_radix_scan_golden.h"

static void t_differential(void)
{
  jb_t j = {0};
  size_t cap, n = 0;
  static char hex[2 * KEYCAP_MAX + 1];

  case_begin("runs: differential: key bytes and every counter equal the recorded per-character results");
  for (int i = 0; diff_body(i, &j, &cap); i++, n++) {
    radix_scan_res_t r;
    radix_scan_rc_t rc;
    const golden_t *gd;
    if (i >= (int)(sizeof(g_golden) / sizeof(g_golden[0]))) {
      CHECK(!"more bodies than recorded results");
      break;
    }
    gd = &g_golden[i];
    rc = scan(&j, cap, &r);
    key_hex(hex, g_key, rc == RADIX_SCAN_OK ? r.key_len : 0);
    CHECK((int)rc == gd->rc);
    CHECK(r.key_len == gd->key_len && !strcmp(hex, gd->key_hex));
    CHECK(r.stream_bytes == gd->stream_bytes && r.n_blocks == gd->n_blocks);
    CHECK(r.n_messages == gd->n_messages && r.truncated == gd->truncated);
    CHECK(r.has_tools == gd->has_tools && r.has_tmpl_kwargs == gd->has_tmpl_kwargs);
    CHECK(r.tools_hash == gd->tools_hash && r.tmpl_kwargs_hash == gd->tmpl_kwargs_hash);
    CHECK(r.skim_bytes == gd->skim_bytes && r.decode_bytes == gd->decode_bytes);
    CHECK(r.hash_bytes == gd->hash_bytes);
  }
  CHECK(n == sizeof(g_golden) / sizeof(g_golden[0]));
  printf("    %zu bodies compared\n", n);
  free(j.b);
  case_end();
}
#endif

int main(void)
{
  setvbuf(stdout, NULL, _IONBF, 0);

#ifdef RADIX_SCAN_GOLDEN_RECORD
  record_golden();
  return 0;
#endif

  t_string_vs_parts();
  t_order_and_escapes();
  t_markers();
  t_shared_blocks();
  t_turns();
  t_partial_tail();
  t_short();
  t_cap_utf8();
  t_nul();
  t_side_hashes();
  t_roles_and_empty_content();
  t_skips();
  t_helpers();

  t_bounds_768k();
  t_bounds_tokens();
  t_bounds_parts();
  t_bounds_escapes();
  t_no_text_retained();

  t_runs();
#ifndef RADIX_SCAN_GOLDEN_RECORD
  t_differential();
#endif

  t_truncation();
  t_mutation();

  printf("test_radix_scan: %s (%d failures)\n", g_fail ? "FAIL" : "PASS", g_fail);
  return g_fail ? 1 : 0;
}
