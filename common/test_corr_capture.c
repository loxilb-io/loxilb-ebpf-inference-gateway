/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_corr_capture.c - what a request's traceparent and X-Client-Session-Id
 * put in its audit records (WP-D, IGW-05).
 *
 * The rule for each field: recorded when valid, absent otherwise -- never
 * invented, never cut, never rewritten. A header received twice (two lines,
 * any spelling, or one comma-joined value) voids THAT header only: the other
 * header's field is still recorded. The capture is pure, so this unit
 * drives it alone; test_corr_h1.py drives it through the HTTP/1.1 parser
 * callbacks and checks where HTTP/2 calls it.
 *
 * What the unit needs from sockproxy_corr.h (written in WP-D step B):
 *   ai_corr_t        trace_id[33], parent_span_id[17], session_id[129],
 *                    each "" when absent (sockproxy_ai_gw.h, design 8)
 *   sp_corr_cap_t    one request's capture; all-zero is "nothing seen"
 *   sp_corr_field(name, len)   SP_CORR_TRACEPARENT, SP_CORR_SESSION or
 *                    SP_CORR_NONE: the whole name, in any case
 *   sp_corr_value(cap, field, value, len)   one complete field value (one
 *                    HTTP/1.1 line, one HPACK field); SP_CORR_NONE is a no-op
 *   sp_corr_export(cap, out)   the record's three fields
 *   sp_corr_reset(cap)         back to "nothing seen"
 *
 * Neither name nor value is NUL-terminated where the parsers hand them over,
 * so every call here passes a pointer into a larger buffer with a length.
 *
 * Build (wired into `make test_corr`):
 *   cc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined \
 *      -o test_corr_capture test_corr_capture.c -I.
 */
#include <stdio.h>
#include <string.h>

#include "sockproxy_corr.h"

static int checks, failures;

#define CHECK(cond, ...) do {                                        \
    checks++;                                                        \
    if (cond) {                                                      \
      printf("ok %d - ", checks); printf(__VA_ARGS__); printf("\n"); \
    } else {                                                         \
      failures++;                                                    \
      printf("FAIL %d - ", checks); printf(__VA_ARGS__);             \
      printf("   (%s:%d)\n", __FILE__, __LINE__);                    \
    }                                                                \
  } while (0)

#define T   "4bf92f3577b34da6a3ce929d0e0e4736"
#define P   "00f067aa0ba902b7"
#define TP  "00-" T "-" P "-01"
#define S   "loxigpt.app:sess_01-A"

/* Hand the capture a value the way a parser does: inside a buffer that goes
 * on past it, with a length. The bytes after the value are a valid-looking
 * tail, so a capture that read past the length would record them. */
static void
feed(sp_corr_cap_t *c, const char *name, const char *value)
{
  char nbuf[256], vbuf[512];
  size_t nlen = strlen(name), vlen = strlen(value);

  snprintf(nbuf, sizeof(nbuf), "%sX-Client-Session-Id", name);
  snprintf(vbuf, sizeof(vbuf), "%s" "abc", value);
  sp_corr_value(c, sp_corr_field(nbuf, nlen), vbuf, vlen);
}

/* The record's fields as "trace|parent|session", "-" for an absent one. */
static const char *
rec(const sp_corr_cap_t *c)
{
  static char out[256];
  ai_corr_t r;

  memset(&r, 0x5a, sizeof(r));      /* an export must write every field */
  sp_corr_export(c, &r);
  snprintf(out, sizeof(out), "%s|%s|%s",
           r.trace_id[0] ? r.trace_id : "-",
           r.parent_span_id[0] ? r.parent_span_id : "-",
           r.session_id[0] ? r.session_id : "-");
  return out;
}

/* One request: up to three header lines, then its record. */
static const char *
req(const char *n1, const char *v1, const char *n2, const char *v2,
    const char *n3, const char *v3)
{
  static sp_corr_cap_t c;

  memset(&c, 0, sizeof(c));
  if (n1) feed(&c, n1, v1);
  if (n2) feed(&c, n2, v2);
  if (n3) feed(&c, n3, v3);
  return rec(&c);
}

#define EXPECT(want, got, ...) do {                                  \
    const char *g_ = (got);                                          \
    CHECK(strcmp(g_, (want)) == 0, __VA_ARGS__);                     \
    if (strcmp(g_, (want)) != 0)                                     \
      printf("#   want '%s'\n#   got  '%s'\n", (want), g_);          \
  } while (0)

static void
names(void)
{
  static const char *const tp[] = { "traceparent", "TraceParent", "TRACEPARENT" };
  static const char *const sid[] = { "X-Client-Session-Id", "x-client-session-id",
                                     "X-CLIENT-SESSION-ID" };
  static const char *const none[] = {
    "X-Client-Session-Idx", "X-Client-Session-Id-Foo", "X-Client-Session",
    "Client-Session-Id", "traceparent2", "tracestate", "trace-parent",
    "X-Session-ID", "X-Session-IDx", "X-Session-ID-Foo", "X-Trace-ID",
    "X-Conversation-ID", "X-Request-Id", "", };
  size_t i;

  for (i = 0; i < sizeof(tp) / sizeof(tp[0]); i++)
    CHECK(sp_corr_field(tp[i], strlen(tp[i])) == SP_CORR_TRACEPARENT,
          "'%s' is the traceparent field", tp[i]);
  for (i = 0; i < sizeof(sid) / sizeof(sid[0]); i++)
    CHECK(sp_corr_field(sid[i], strlen(sid[i])) == SP_CORR_SESSION,
          "'%s' is the session field", sid[i]);
  for (i = 0; i < sizeof(none) / sizeof(none[0]); i++)
    CHECK(sp_corr_field(none[i], strlen(none[i])) == SP_CORR_NONE,
          "'%s' is neither: the whole name is matched, never a prefix", none[i]);
  CHECK(sp_corr_field("traceparentXYZ", 11) == SP_CORR_TRACEPARENT,
        "the name's length is honoured (no NUL where the parser hands it over)");
  CHECK(sp_corr_field("X-Client-Session-Id", 18) == SP_CORR_NONE,
        "one byte short of the name is not the name");
  CHECK(SP_CORR_NONE == 0 && SP_CORR_TRACEPARENT != SP_CORR_SESSION &&
        SP_CORR_TRACEPARENT != 0 && SP_CORR_SESSION != 0,
        "the field codes are distinct and NONE is zero (a zeroed request has none)");
}

static void
traceparent(void)
{
  EXPECT(T "|" P "|-", req("traceparent", TP, 0, 0, 0, 0), "a valid traceparent");
  EXPECT(T "|" P "|-", req("TraceParent", TP, 0, 0, 0, 0), "in any spelling of its name");
  EXPECT(T "|" P "|-", req("traceparent", " \t" TP " \t", 0, 0, 0, 0),
         "optional whitespace around the value is not part of it");

  static const char *const bad[] = {
    "00-4BF92F3577B34DA6A3CE929D0E0E4736-" P "-01",       /* upper-case trace-id */
    "00-" T "-00F067AA0BA902B7-01",                         /* upper-case parent-id */
    "00-" T "-" P "-0A",                                    /* upper-case flags */
    "00-00000000000000000000000000000000-" P "-01",         /* all-zero trace-id */
    "00-" T "-0000000000000000-01",                         /* all-zero parent-id */
    "ff-" T "-" P "-01",                                    /* version ff */
    "0g-" T "-" P "-01",                                    /* version not hex */
    "0-" T "-" P "-01",                                     /* version one digit */
    "00-" T "-" P "-0",                                     /* 54 bytes */
    "00-" T "-" P "-01-",                                   /* version 00 and 56 bytes */
    "00-" T "-" P "-01-x",                                  /* version 00 and a tail */
    "00-" T "-" P "-0g",                                    /* flags not hex */
    "00_" T "_" P "_01",                                    /* not dashes */
    "00-" T "f-" P "-01",                                   /* trace-id 33 digits */
    "00-" T "-" P "f-01",                                   /* parent-id 17 digits */
    "01-" T "-" P "-01x",                                   /* higher version, no dash after 55 */
    "",                                                     /* empty */
    TP "," TP,                                              /* comma-joined */
    TP ", 00-" T "-00f067aa0ba902b8-01",                    /* comma-joined, two values */
  };
  for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
    EXPECT("-|-|-", req("traceparent", bad[i], 0, 0, 0, 0), "invalid '%s': absent", bad[i]);

  EXPECT(T "|" P "|-", req("traceparent", "01-" T "-" P "-01", 0, 0, 0, 0),
         "a higher version of 55 bytes is read as version 00");
  EXPECT(T "|" P "|-", req("traceparent", "01-" T "-" P "-01-future-fields", 0, 0, 0, 0),
         "a higher version may go on after a dash");
  EXPECT(T "|" P "|-", req("traceparent", "fe-" T "-" P "-01", 0, 0, 0, 0),
         "fe is a version (only ff is not)");

  EXPECT("-|-|-", req("traceparent", TP, "traceparent", "00-" T "-00f067aa0ba902b8-01", 0, 0),
         "two traceparent lines: absent");
  EXPECT("-|-|-", req("traceparent", TP, "TraceParent", TP, 0, 0),
         "two lines in two spellings, the same value: absent (no guess which was meant)");
  EXPECT("-|-|-", req("traceparent", TP, "traceparent", "", 0, 0),
         "a valid line and an empty one: absent (still received twice)");
  EXPECT("-|-|-", req("traceparent", "bogus", "traceparent", TP, 0, 0),
         "an invalid line and a valid one: absent");
}

static void
session(void)
{
  char s128[129], s129[130], v[160];

  memset(s128, 'a', 128); s128[128] = '\0';
  memset(s129, 'b', 129); s129[129] = '\0';

  EXPECT("-|-|" S, req("X-Client-Session-Id", S, 0, 0, 0, 0), "a valid session value");
  EXPECT("-|-|AZaz09._:-", req("X-Client-Session-Id", "AZaz09._:-", 0, 0, 0, 0),
         "every allowed class of byte");
  EXPECT("-|-|x", req("x-client-session-id", "x", 0, 0, 0, 0), "one byte is enough");
  snprintf(v, sizeof(v), "-|-|%s", s128);
  EXPECT(v, req("X-Client-Session-Id", s128, 0, 0, 0, 0), "128 bytes, recorded whole");
  EXPECT("-|-|-", req("X-Client-Session-Id", s129, 0, 0, 0, 0), "129 bytes: absent, not cut");
  EXPECT("-|-|" S, req("X-Client-Session-Id", "  " S "\t", 0, 0, 0, 0),
         "optional whitespace around the value is not part of it");

  static const char *const bad[] = {
    "", "sess 01", "sess/01", "sess,01", "sess;01", "sess=01", "\"sess\"",
    "sess\x7f" "01", "sess\x80" "01", "s\xc3\xa9ss", "sess+01", "sess@01",
    S "," S,
  };
  for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
    EXPECT("-|-|-", req("X-Client-Session-Id", bad[i], 0, 0, 0, 0),
           "invalid session value #%zu: absent", i);

  EXPECT("-|-|-", req("X-Client-Session-Id", S, "x-client-session-id", "other", 0, 0),
         "two session lines: absent");
  EXPECT("-|-|-", req("X-Client-Session-Id", S, "X-Client-Session-Id", S, 0, 0),
         "two lines, the same value: absent");
  EXPECT("-|-|-", req("X-Client-Session-Id", S, "X-Client-Session-Id", "", 0, 0),
         "a valid line and an empty one: absent");
}

static void
cross(void)
{
  EXPECT(T "|" P "|" S, req("traceparent", TP, "X-Client-Session-Id", S, 0, 0),
         "both valid: both recorded");
  EXPECT(T "|" P "|" S, req("X-Client-Session-Id", S, "traceparent", TP, 0, 0),
         "in either order");
  EXPECT("-|-|" S, req("traceparent", TP, "X-Client-Session-Id", S, "TraceParent", TP),
         "duplicate traceparent beside a valid session: the session is kept");
  EXPECT(T "|" P "|-", req("X-Client-Session-Id", S, "traceparent", TP, "x-client-session-id", S),
         "duplicate session beside a valid traceparent: the trace is kept");
  EXPECT("-|-|" S, req("traceparent", "ff-" T "-" P "-01", "X-Client-Session-Id", S, 0, 0),
         "invalid traceparent beside a valid session: the session is kept");
  EXPECT(T "|" P "|-", req("traceparent", TP, "X-Client-Session-Id", "a b", 0, 0),
         "invalid session beside a valid traceparent: the trace is kept");
  EXPECT("-|-|" S, req("traceparent", TP "," TP, "X-Client-Session-Id", S, 0, 0),
         "comma-joined traceparent beside a valid session: the session is kept");
  EXPECT(T "|" P "|" S, req("traceparent", TP, "X-Session-ID", "conv-1", "X-Client-Session-Id", S),
         "a conversation header between them changes neither");
  EXPECT(T "|" P "|-", req("traceparent", TP, "X-Session-IDx", S, 0, 0),
         "X-Session-IDx is not the session header");
  EXPECT(T "|" P "|-", req("traceparent", TP, "X-Client-Session-Idx", S, 0, 0),
         "nor is X-Client-Session-Idx");
  EXPECT(T "|" P "|-", req("traceparent", TP, "tracestate", "k=v", 0, 0),
         "tracestate is not read");
}

static void
lifecycle(void)
{
  sp_corr_cap_t c;

  memset(&c, 0, sizeof(c));
  EXPECT("-|-|-", rec(&c), "a request with neither header: nothing invented");

  sp_corr_value(&c, SP_CORR_NONE, TP, strlen(TP));
  EXPECT("-|-|-", rec(&c), "a value of no field changes nothing");

  feed(&c, "traceparent", TP);
  feed(&c, "X-Client-Session-Id", S);
  EXPECT(T "|" P "|" S, rec(&c), "captured");
  EXPECT(T "|" P "|" S, rec(&c), "export reads, it does not consume");

  sp_corr_reset(&c);
  EXPECT("-|-|-", rec(&c), "reset: the next request on the connection starts empty");
  feed(&c, "traceparent", "00-" T "-00f067aa0ba902b9-01");
  EXPECT(T "|00f067aa0ba902b9|-", rec(&c),
         "after a reset one line is one line, not a duplicate of the last request's");

  ai_corr_t r;
  CHECK(sizeof(r.trace_id) == 33 && sizeof(r.parent_span_id) == 17 &&
        sizeof(r.session_id) == 129, "ai_corr_t holds each field whole, with its NUL");
}

int
main(void)
{
  names();
  traceparent();
  session();
  cross();
  lifecycle();

  printf("\n1..%d\n", checks);
  if (failures) {
    printf("# %d of %d checks FAILED\n", failures, checks);
    return 1;
  }
  printf("# all %d checks passed\n", checks);
  return 0;
}
