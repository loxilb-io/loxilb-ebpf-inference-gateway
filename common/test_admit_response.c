/* SPDX-License-Identifier: BSD-3-Clause */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "llhttp.h"
#include "sockproxy_admit_response.h"

static unsigned complete;
static size_t received;
static int on_complete(llhttp_t *p) { (void)p; complete++; return 0; }
static int on_body(llhttp_t *p, const char *at, size_t n)
{ (void)p; (void)at; received += n; return 0; }

/* The sender's buffer (sp_h1_send_admit_deny). */
#define WIRE_MAX (640 + SP_REFUSAL_MARK_MAX)

/* `stage` / `rid`: the refusal mark the response must carry, NULL for none.
 * Whatever the mark, the status, the retry hint, the body and its length are
 * the ones the response always had. */
static void check_response(int status, int retry, int retry_body,
                           const char *stage, const char *rid)
{
  char wire[WIRE_MAX];
  int n = sp_h1_format_admit_deny(wire, sizeof(wire), status, retry,
                                 retry_body, "invalid_api_key", "key disabled",
                                 stage, rid);
  assert(n > 0);
  {
    char line[SP_REFUSAL_MARK_MAX + 8];
    const char *at;

    at = strstr(wire, "X-Loxilb-Refusal-Stage: ");
    assert((at != NULL) == (stage != NULL));
    if (stage) {
      snprintf(line, sizeof(line), "\r\nX-Loxilb-Refusal-Stage: %s\r\n", stage);
      assert(strstr(wire, line) && !strstr(at + 1, "X-Loxilb-Refusal-Stage: "));
      /* a header line, before the blank line */
      assert(at < strstr(wire, "\r\n\r\n"));
    }
    at = strstr(wire, "X-Request-Id: ");
    assert((at != NULL) == (rid != NULL));
    if (rid) {
      snprintf(line, sizeof(line), "\r\nX-Request-Id: %s\r\n", rid);
      assert(strstr(wire, line) && !strstr(at + 1, "X-Request-Id: "));
      assert(at < strstr(wire, "\r\n\r\n"));
    }
  }
  char status_prefix[32];
  snprintf(status_prefix, sizeof(status_prefix), "HTTP/1.1 %d ", status);
  assert(strncmp(wire, status_prefix, strlen(status_prefix)) == 0);
  assert(strstr(wire, "Content-Type: application/json\r\n"));
  assert(strstr(wire, "Connection: close\r\n"));
  const char *body = strstr(wire, "\r\n\r\n") + 4;
  const char *cl = strstr(wire, "Content-Length: ");
  assert(cl);
  assert(strtoul(cl + 16, NULL, 10) == strlen(body));
  assert(!strstr(cl + 16, "Content-Length: "));
  assert((strstr(wire, "Retry-After: ") != NULL) ==
         (retry_body || retry > 0));
  char expected[128];
  if (retry_body)
    snprintf(expected, sizeof(expected), "{\"error\":\"invalid_api_key\",\"retry_after\":%d}\r\n", retry);
  else
    snprintf(expected, sizeof(expected), "{\"error\":\"invalid_api_key\",\"message\":\"key disabled\"}\r\n");
  assert(strcmp(body, expected) == 0);
  for (size_t split = 0; split <= (size_t)n; split++) {
    llhttp_t parser; llhttp_settings_t settings;
    llhttp_settings_init(&settings);
    settings.on_message_complete = on_complete;
    settings.on_body = on_body;
    llhttp_init(&parser, HTTP_RESPONSE, &settings);
    complete = 0; received = 0;
    assert(llhttp_execute(&parser, wire, split) == HPE_OK);
    assert(llhttp_execute(&parser, wire + split, (size_t)n - split) == HPE_OK);
    /* No EOF/llhttp_finish: a delayed FIN must not delay message completion. */
    assert(complete == 1 && received == strlen(body));
    assert(llhttp_finish(&parser) == HPE_OK);
    assert(complete == 1);
  }

  llhttp_t parser; llhttp_settings_t settings;
  llhttp_settings_init(&settings);
  settings.on_message_complete = on_complete;
  llhttp_init(&parser, HTTP_RESPONSE, &settings);
  complete = 0;
  assert(llhttp_execute(&parser, wire, (size_t)n - 1) == HPE_OK);
  assert(complete == 0);
  assert(llhttp_finish(&parser) == HPE_INVALID_EOF_STATE);
}

int main(void)
{
  const int statuses[] = {400, 401, 403, 413, 429, 503};
  char longest_id[SP_REFUSAL_RID_MAX + 1];
  memset(longest_id, 'r', SP_REFUSAL_RID_MAX);
  longest_id[SP_REFUSAL_RID_MAX] = '\0';
  for (size_t i = 0; i < sizeof(statuses)/sizeof(statuses[0]); i++) {
    /* unmarked, the stage alone, the stage with an ID, with the longest ID */
    const char *const marks[][2] = { { NULL, NULL }, { "auth", NULL },
                                     { "ratelimit", "9f1c2b7e4d5a4c0e8b3f6a7d1e2c3b4a" },
                                     { "objective", longest_id } };
    for (size_t m = 0; m < sizeof(marks)/sizeof(marks[0]); m++) {
      check_response(statuses[i], 0, 0, marks[m][0], marks[m][1]);
      check_response(statuses[i], 2, 0, marks[m][0], marks[m][1]);
      check_response(statuses[i], 0, 1, marks[m][0], marks[m][1]);
      check_response(statuses[i], 2, 1, marks[m][0], marks[m][1]);
    }
  }
  char tiny[8] = "old";
  assert(sp_h1_format_admit_deny(tiny, sizeof(tiny), 401, 0, 0,
                               "invalid_api_key", "key disabled", "auth", "r1") == -1);
  assert(tiny[0] == '\0');
  char long_message[1024]; memset(long_message, 'x', sizeof(long_message)-1);
  long_message[sizeof(long_message)-1] = '\0';
  char wire[WIRE_MAX];
  assert(sp_h1_format_admit_deny(wire, sizeof(wire), 401, 0, 0,
                               "invalid_api_key", long_message, "auth", "r1") == -1);
  assert(wire[0] == '\0');
  assert(sp_h1_format_admit_deny(NULL, 0, 401, 0, 0, "e", "m", "auth", "r1") == -1);

  /* The sender's buffer holds the largest refusal there is: the longest
   * body the formatter accepts (511 bytes), a Retry-After, the longest
   * status line, and the mark with a 255-byte request ID. The same refusal
   * in the buffer the sender had before the mark does not fit, and is
   * refused whole rather than sent short. */
  {
    char msg[512];
    size_t fixed = strlen("{\"error\":\"invalid_api_key\",\"message\":\"\"}\r\n");
    memset(msg, 'm', sizeof(msg));
    msg[511 - fixed] = '\0';
    int n = sp_h1_format_admit_deny(wire, sizeof(wire), 503, 86400, 0,
                                    "invalid_api_key", msg, "ratelimit", longest_id);
    assert(n > 0 && (size_t)n < sizeof(wire));
    const char *body = strstr(wire, "\r\n\r\n") + 4;
    assert(strlen(body) == 511 && body[510] == '\n' && body[508] == '}');
    assert(strstr(wire, longest_id));
    char before[640];
    assert(sp_h1_format_admit_deny(before, sizeof(before), 503, 86400, 0,
                                   "invalid_api_key", msg, "ratelimit", longest_id) == -1);
    assert(before[0] == '\0');
    msg[511 - fixed] = 'm'; msg[512 - fixed] = '\0';     /* one byte more: no body fits */
    assert(sp_h1_format_admit_deny(wire, sizeof(wire), 503, 86400, 0,
                                   "invalid_api_key", msg, "ratelimit", longest_id) == -1);
  }
  /* A request ID that is not one header value is left out, never cut, and
   * cannot add a line of its own; the stage still goes out. */
  {
    int n = sp_h1_format_admit_deny(wire, sizeof(wire), 401, 0, 0, "invalid_api_key",
                                    "key disabled", "auth",
                                    "x\r\nX-Loxilb-Refusal-Stage: capacity");
    assert(n > 0 && strstr(wire, "\r\nX-Loxilb-Refusal-Stage: auth\r\n"));
    assert(!strstr(wire, "X-Request-Id") && !strstr(wire, "capacity"));
    char over[SP_REFUSAL_RID_MAX + 2];
    memset(over, 'r', sizeof(over)); over[sizeof(over) - 1] = '\0';
    n = sp_h1_format_admit_deny(wire, sizeof(wire), 401, 0, 0, "invalid_api_key",
                                "key disabled", "auth", over);
    assert(n > 0 && !strstr(wire, "X-Request-Id") && !strstr(wire, "rrrr"));
  }
  puts("Admission response: all status/retry/body variants with and without the refusal mark, every split, delayed EOF, truncated-body rejection, the largest refusal in the sender's buffer PASS");
  return 0;
}
