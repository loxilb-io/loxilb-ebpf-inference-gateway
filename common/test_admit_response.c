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

static void check_response(int status, int retry, int retry_body)
{
  char wire[640];
  int n = sp_h1_format_admit_deny(wire, sizeof(wire), status, retry,
                                 retry_body, "invalid_api_key", "key disabled");
  assert(n > 0);
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
  for (size_t i = 0; i < sizeof(statuses)/sizeof(statuses[0]); i++) {
    check_response(statuses[i], 0, 0);
    check_response(statuses[i], 2, 0);
    check_response(statuses[i], 0, 1);
    check_response(statuses[i], 2, 1);
  }
  char tiny[8] = "old";
  assert(sp_h1_format_admit_deny(tiny, sizeof(tiny), 401, 0, 0,
                               "invalid_api_key", "key disabled") == -1);
  assert(tiny[0] == '\0');
  char long_message[1024]; memset(long_message, 'x', sizeof(long_message)-1);
  long_message[sizeof(long_message)-1] = '\0';
  char wire[640];
  assert(sp_h1_format_admit_deny(wire, sizeof(wire), 401, 0, 0,
                               "invalid_api_key", long_message) == -1);
  assert(wire[0] == '\0');
  assert(sp_h1_format_admit_deny(NULL, 0, 401, 0, 0, "e", "m") == -1);
  puts("Admission response: all status/retry/body variants, every split, delayed EOF and truncated-body rejection PASS");
  return 0;
}
