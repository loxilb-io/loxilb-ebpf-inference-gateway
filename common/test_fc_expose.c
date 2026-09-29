/*
 * Copyright (c) 2026 LoxiLB Authors
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

/*
 * The admission headers on admitted responses, driven alone: the switch from
 * the environment and the rule with its source, which requests report them
 * (units held on an exposing pool, nothing else), the values a request
 * reads, and the HTTP/1 head splice: a final head whole in the buffer gets
 * the three lines before its blank line and everything after it moves
 * unread (a body, chunks, an event stream), a backend's lines of the same
 * names give way, and an interim head, a split head, a buffer that is not a
 * head and a head with no room are left as they are.
 *
 * Build: make test_fc_expose (also run by `make test_fc`).
 */
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sockproxy_fc.h"

#define CAP 1024

static void
pool(fc_state_t *fc, uint8_t mode, uint32_t max_out, uint8_t expose)
{
  fc_cfg_t cfg = {0};

  memset(fc, 0, sizeof(*fc));
  pthread_mutex_init(&fc->queue.lock, NULL);
  cfg.mode = mode;
  cfg.max_outstanding = max_out;
  cfg.expose_headers = expose;
  fc_state_apply(fc, &cfg);
}

static size_t
splice(uint8_t *buf, const char *in, size_t cap, const fc_expose_t *v, int *res)
{
  size_t len = strlen(in);

  memset(buf, 0, CAP);
  memcpy(buf, in, len);
  return fc_expose_h1(buf, len, cap, v, res);
}

static void
test_config_resolves(void)
{
  fc_cfg_t env, out, other;
  fc_rule_cfg_t rule = {0};

  unsetenv("LLB_FC_EXPOSE_HEADERS");
  fc_cfg_from_env(&env);
  assert(env.expose_headers == 0 && env.src[FC_L_EXPOSE_HEADERS] == FC_SRC_DEFAULT);
  setenv("LLB_FC_EXPOSE_HEADERS", "on", 1);
  fc_cfg_from_env(&env);
  assert(env.expose_headers == 1 && env.src[FC_L_EXPOSE_HEADERS] == FC_SRC_ENV);
  setenv("LLB_FC_EXPOSE_HEADERS", "off", 1);
  fc_cfg_from_env(&env);
  assert(env.expose_headers == 0 && env.src[FC_L_EXPOSE_HEADERS] == FC_SRC_ENV);
  setenv("LLB_FC_EXPOSE_HEADERS", "yes", 1);    /* not a switch value: unset */
  fc_cfg_from_env(&env);
  assert(env.expose_headers == 0 && env.src[FC_L_EXPOSE_HEADERS] == FC_SRC_DEFAULT);

  setenv("LLB_FC_EXPOSE_HEADERS", "on", 1);
  fc_cfg_from_env(&env);
  fc_cfg_resolve(&out, &env, &rule);            /* inherit */
  assert(out.expose_headers == 1 && out.src[FC_L_EXPOSE_HEADERS] == FC_SRC_ENV);
  rule.expose_headers = FC_RULE_EXPOSE_OFF;     /* a rule may say "off" under "on" */
  fc_cfg_resolve(&other, &env, &rule);
  assert(other.expose_headers == 0 && other.src[FC_L_EXPOSE_HEADERS] == FC_SRC_RULE);
  assert(!fc_cfg_equal(&out, &other));
  unsetenv("LLB_FC_EXPOSE_HEADERS");
  fc_cfg_from_env(&env);
  rule.expose_headers = FC_RULE_EXPOSE_ON;
  fc_cfg_resolve(&out, &env, &rule);
  assert(out.expose_headers == 1 && out.src[FC_L_EXPOSE_HEADERS] == FC_SRC_RULE);
  rule.expose_headers = 3;                      /* out of range: inherit */
  fc_cfg_resolve(&other, &env, &rule);
  assert(other.expose_headers == 0 && other.src[FC_L_EXPOSE_HEADERS] == FC_SRC_DEFAULT);
  printf("  config: env and rule resolve with their source; a change is a change\n");
}

static void
test_who_reports(void)
{
  fc_state_t fc;
  fc_permit_t a, b, c;
  fc_expose_t v;

  /* Units held on an exposing pool: the pool as the request finds it,
   * itself included. */
  pool(&fc, FC_MODE_ENFORCE, 4, 1);
  fc_permit_init(&a);
  fc_permit_init(&b);
  assert(fc_service_acquire_h1_tenant(&fc, &a, 0, 0) == FC_ADMIT);
  assert(fc_service_acquire_h1_tenant(&fc, &b, 0, 0) == FC_ADMIT);
  memset(&v, 0xff, sizeof(v));
  assert(fc_expose_take(&a, &v) == 1);
  assert(v.inflight == 2 && v.queued == 0 && v.limit == 4);

  /* Handed back: nothing to report. */
  fc_permit_release(&a);
  assert(fc_expose_take(&a, &v) == 0);
  assert(fc_expose_take(&b, &v) == 1 && v.inflight == 1);
  fc_permit_release(&b);

  /* A request that never took a unit (a bypassed one, or none at all). */
  fc_permit_init(&c);
  assert(fc_expose_take(&c, &v) == 0);
  fc_bypass(&fc, &c);
  assert(fc_expose_take(&c, &v) == 0);
  assert(fc_expose_take(NULL, &v) == 0);

  /* A pool that does not expose them. */
  pool(&fc, FC_MODE_ENFORCE, 4, 0);
  fc_permit_init(&a);
  assert(fc_service_acquire_h1_tenant(&fc, &a, 0, 0) == FC_ADMIT);
  assert(fc_expose_take(&a, &v) == 0);
  fc_permit_release(&a);

  /* Observe mode admits with units held: it reports; an unlimited pool
   * reports 0 as its limit. */
  pool(&fc, FC_MODE_OBSERVE, 0, 1);
  fc_permit_init(&a);
  assert(fc_service_acquire_h1_tenant(&fc, &a, 0, 0) == FC_ADMIT);
  assert(a.state == FC_P_EXECUTING);
  assert(fc_expose_take(&a, &v) == 1 && v.limit == 0);
  fc_permit_release(&a);

  /* Off: the gate takes nothing, so nothing reports. */
  pool(&fc, FC_MODE_OFF, 4, 1);
  fc_permit_init(&a);
  (void)fc_service_acquire_h1_tenant(&fc, &a, 0, 0);
  assert(fc_expose_take(&a, &v) == 0);
  fc_permit_release(&a);
  printf("  take: units held on an exposing pool report, and nothing else\n");
}

static const fc_expose_t V = { .inflight = 3, .queued = 7, .limit = 16 };
static const char ADD[] =
  "X-Loxilb-Admission-Inflight: 3\r\n"
  "X-Loxilb-Admission-Queued: 7\r\n"
  "X-Loxilb-Admission-Limit: 16\r\n";

static void
test_final_head(void)
{
  uint8_t buf[CAP];
  const char *in =
    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
  const char *want_head = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                          "Content-Length: 2\r\n";
  size_t n;
  int res = -1;

  n = splice(buf, in, CAP, &V, &res);
  assert(res == FC_EXPOSE_H1_DONE);
  assert(n == strlen(in) + strlen(ADD));
  assert(!memcmp(buf, want_head, strlen(want_head)));
  assert(!memcmp(buf + strlen(want_head), ADD, strlen(ADD)));
  assert(!memcmp(buf + strlen(want_head) + strlen(ADD), "\r\n{}", 4));

  /* An error answer is a final response too, and HTTP/1.0 is HTTP/1. */
  n = splice(buf, "HTTP/1.0 503 Service Unavailable\r\n\r\n", CAP, &V, &res);
  assert(res == FC_EXPOSE_H1_DONE);
  assert(n == strlen("HTTP/1.0 503 Service Unavailable\r\n\r\n") + strlen(ADD));
  printf("  head: the three lines go before the blank line, the body after it untouched\n");
}

static void
test_stream_bodies_untouched(void)
{
  uint8_t buf[CAP];
  const char *head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                     "Content-Type: text/event-stream\r\n";
  /* Chunk data that looks like a head and like our own header names. */
  const char *rest = "\r\n1f\r\ndata: HTTP/1.1 200 OK\r\n\r\n\r\n"
                     "1c\r\nX-Loxilb-Admission-Queued: 9\r\n\r\n0\r\n\r\n";
  char in[CAP];
  size_t n;
  int res;

  snprintf(in, sizeof(in), "%s%s", head, rest);
  n = splice(buf, in, CAP, &V, &res);
  assert(res == FC_EXPOSE_H1_DONE);
  assert(n == strlen(in) + strlen(ADD));
  assert(!memcmp(buf, head, strlen(head)));
  assert(!memcmp(buf + strlen(head), ADD, strlen(ADD)));
  assert(!memcmp(buf + strlen(head) + strlen(ADD), rest, strlen(rest)));
  printf("  stream: chunked / event-stream bytes after the head are moved, never read\n");
}

static void
test_backend_lines_give_way(void)
{
  uint8_t buf[CAP];
  const char *in = "HTTP/1.1 200 OK\r\nx-loxilb-admission-inflight: 99\r\n"
                   "Server: engine\r\nX-LOXILB-ADMISSION-LIMIT: 1\r\n\r\nbody";
  const char *want = "HTTP/1.1 200 OK\r\nServer: engine\r\n";
  size_t n;
  int res;

  n = splice(buf, in, CAP, &V, &res);
  assert(res == FC_EXPOSE_H1_DONE);
  assert(!memcmp(buf, want, strlen(want)));
  assert(!memcmp(buf + strlen(want), ADD, strlen(ADD)));
  assert(!memcmp(buf + strlen(want) + strlen(ADD), "\r\nbody", 6));
  assert(n == strlen(want) + strlen(ADD) + 6);
  assert(!memmem(buf, n, ": 99", 4));
  printf("  spoof: a backend's lines of the same names are replaced, not doubled\n");
}

static void
test_left_as_is(void)
{
  uint8_t buf[CAP];
  const char *interim = "HTTP/1.1 100 Continue\r\n\r\n";
  const char *split = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n";
  const char *body = "data: {\"x\":1}\n\n";
  const char *whole = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
  size_t n;
  int res;

  n = splice(buf, interim, CAP, &V, &res);
  assert(res == FC_EXPOSE_H1_INTERIM && n == strlen(interim));
  assert(!memcmp(buf, interim, n));

  n = splice(buf, split, CAP, &V, &res);
  assert(res == FC_EXPOSE_H1_SKIPPED && n == strlen(split));
  assert(!memcmp(buf, split, n));

  n = splice(buf, body, CAP, &V, &res);
  assert(res == FC_EXPOSE_H1_SKIPPED && n == strlen(body));
  assert(!memcmp(buf, body, n));

  /* One byte short of the room the lines need. */
  n = splice(buf, whole, strlen(whole) + strlen(ADD) - 1, &V, &res);
  assert(res == FC_EXPOSE_H1_SKIPPED && n == strlen(whole));
  assert(!memcmp(buf, whole, n));
  n = splice(buf, whole, strlen(whole) + strlen(ADD), &V, &res);
  assert(res == FC_EXPOSE_H1_DONE && n == strlen(whole) + strlen(ADD));

  n = splice(buf, "HTTP/2 200\r\n\r\n", CAP, &V, &res);
  assert(res == FC_EXPOSE_H1_SKIPPED);
  n = fc_expose_h1(buf, 5, CAP, &V, &res);
  assert(res == FC_EXPOSE_H1_SKIPPED && n == 5);
  printf("  as is: interim, split, body-only, no-room and non-HTTP/1 buffers are untouched\n");
}

int
main(void)
{
  printf("fc admission headers:\n");
  test_config_resolves();
  test_who_reports();
  test_final_head();
  test_stream_bodies_untouched();
  test_backend_lines_give_way();
  test_left_as_is();
  printf("OK\n");
  return 0;
}
