/*
 * Copyright (c) 2026 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 *
 * test_hc_metrics.c - the pure half of the half-close observation
 * (sockproxy_hc_core.h): bucket edges, the gate, the early-FIN edge, how a TLS
 * read ended, User-Agent families and the incremental header-name match.
 *
 * Build (wired into `make test_hc`):
 *   gcc -Wall -Wextra -Werror -o test_hc_metrics test_hc_metrics.c -I.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "sockproxy_hc_core.h"

static void
test_fin_buckets(void)
{
  /* Upper bounds are inclusive; the one past the last bound is +Inf. */
  assert(hc_fin_bucket(0) == 0);
  assert(hc_fin_bucket(1000) == 0);
  assert(hc_fin_bucket(1001) == 1);
  assert(hc_fin_bucket(HC_EARLY_FIN_US) == 6);          /* the 100ms edge */
  assert(hc_fin_bounds_us[6] == HC_EARLY_FIN_US);
  assert(hc_fin_bucket(HC_EARLY_FIN_US + 1) == 7);
  assert(hc_fin_bucket(60000000) == HC_FIN_NB - 2);
  assert(hc_fin_bucket(60000001) == HC_FIN_NB - 1);
  printf("  fin buckets: ok\n");
}

static void
test_prog_buckets(void)
{
  int i;

  /* Strictly increasing, and long enough to hold a multi-minute gap. */
  for (i = 1; i < HC_PROG_NB - 1; i++) {
    assert(hc_prog_bounds_us[i] > hc_prog_bounds_us[i - 1]);
  }
  assert(hc_prog_bounds_us[HC_PROG_NB - 2] >= 1800ull * 1000000);
  assert(hc_prog_bucket(240ull * 1000000) == 12);       /* 300s bucket */
  assert(hc_prog_bucket(3600ull * 1000000) == HC_PROG_NB - 1);
  printf("  progress buckets: ok\n");
}

static void
test_cumulative(void)
{
  uint64_t cum[HC_FIN_NB - 1] = { 0 };
  uint64_t samples[] = { 0, 1000, 1001, HC_EARLY_FIN_US, 60000001 };
  size_t s;
  int i;

  /* Counting a sample from its first bucket on gives Prometheus's le
   * buckets: each holds the samples at or under its bound. */
  for (s = 0; s < sizeof(samples) / sizeof(samples[0]); s++) {
    for (i = hc_cum_first(hc_fin_bounds_us, HC_FIN_NB, samples[s]); i < HC_FIN_NB - 1; i++) {
      cum[i]++;
    }
  }
  assert(cum[0] == 2);                                  /* 0 and 1ms */
  assert(cum[1] == 3);                                  /* + 1.001ms */
  assert(cum[5] == 3);                                  /* 50ms */
  assert(cum[6] == 4);                                  /* + the 100ms edge */
  assert(cum[HC_FIN_NB - 2] == 4);                      /* past 60s is +Inf only */
  for (i = 1; i < HC_FIN_NB - 1; i++) {
    assert(cum[i] >= cum[i - 1]);
  }
  printf("  cumulative buckets: ok\n");
}

static void
test_early(void)
{
  uint64_t done = 5000000000ull;

  assert(!hc_is_early(0, done));                        /* no request framed */
  assert(hc_is_early(done, done));
  assert(hc_is_early(done, done + HC_EARLY_FIN_US * 1000));
  assert(!hc_is_early(done, done + HC_EARLY_FIN_US * 1000 + 1000));
  assert(!hc_is_early(done, done - 1));                 /* FIN before the request ended */
  printf("  early FIN: ok\n");
}

static void
test_tls_path(void)
{
  /* OpenSSL 3: SSL_ERROR_SSL with the unexpected-EOF reason. */
  assert(hc_tls_eof_path(HC_SSL_ERR_SSL, 0, 0, 1) == HC_TLS_UNEXPECTED_EOF);
  /* A real TLS error is not a FIN. */
  assert(hc_tls_eof_path(HC_SSL_ERR_SSL, 0, 0, 0) == -1);
  assert(hc_tls_eof_path(HC_SSL_ERR_SSL, -1, 1, 0) == -1);
  /* OpenSSL 1.1.1: SYSCALL, zero return, nothing queued. */
  assert(hc_tls_eof_path(HC_SSL_ERR_SYSCALL, 0, 1, 0) == HC_TLS_UNEXPECTED_EOF);
  /* A reset or an error behind the SYSCALL is not a FIN. */
  assert(hc_tls_eof_path(HC_SSL_ERR_SYSCALL, -1, 1, 0) == -1);
  assert(hc_tls_eof_path(HC_SSL_ERR_SYSCALL, 0, 0, 0) == -1);
  assert(hc_tls_eof_path(2 /* WANT_READ */, 0, 1, 1) == -1);
  printf("  TLS read end: ok\n");
}

static void
test_classify(void)
{
  /* TLS and accel take the connection out of the gate whatever else holds. */
  assert(hc_classify(1, HC_ACCEL_RESP, 1, 1) == HC_OUT_TLS);
  assert(hc_classify(0, HC_ACCEL_REQ, 0, 1) == HC_OUT_ACCEL);
  assert(hc_classify(0, HC_ACCEL_RESP, 0, 0) == HC_OUT_ACCEL);
  /* In the gate, a paused mid-request read is counted, never sampled. */
  assert(hc_classify(0, 0, 1, 1) == HC_OUT_PARTIAL);
  assert(hc_classify(0, 0, 0, 1) == HC_OUT_OWED);
  assert(hc_classify(0, 0, 0, 0) == HC_OUT_IDLE);
  printf("  gate: ok\n");
}

static void
test_ua(void)
{
#define UA(s) hc_ua_classify((s), strlen(s))
  assert(hc_ua_classify(NULL, 0) == HC_UA_OTHER);
  assert(UA("curl/8.5.0") == HC_UA_CURL);
  assert(UA("CURL/7.1") == HC_UA_CURL);                 /* case-insensitive */
  assert(UA("python-requests/2.31.0") == HC_UA_PY_REQUESTS);
  assert(UA("python-httpx/0.27.0") == HC_UA_PY_HTTPX);
  assert(UA("Python/3.11 aiohttp/3.9.1") == HC_UA_PY_AIOHTTP);
  assert(UA("Python-urllib/3.12") == HC_UA_PY_URLLIB);
  /* The SDKs sit on top of httpx / node-fetch and must win over them. */
  assert(UA("OpenAI/Python 1.30.1") == HC_UA_OPENAI_PY);
  assert(UA("OpenAI/JS 4.47.1") == HC_UA_OPENAI_NODE);
  assert(UA("Go-http-client/1.1") == HC_UA_GO);
  assert(UA("node-fetch") == HC_UA_NODE);
  assert(UA("undici") == HC_UA_NODE);
  assert(UA("axios/1.6.8") == HC_UA_NODE);
  assert(UA("Java/17.0.2") == HC_UA_JAVA);
  assert(UA("Apache-HttpClient/4.5.14 (Java/17)") == HC_UA_JAVA);
  assert(UA("okhttp/4.12.0") == HC_UA_JAVA);
  assert(UA("Mozilla/5.0 (X11; Linux x86_64)") == HC_UA_BROWSER);
  assert(UA("my-tool/1.0") == HC_UA_OTHER);
  /* A value shorter than the prefix does not read past its end. */
  assert(hc_ua_classify("cur", 3) == HC_UA_OTHER);
  assert(hc_ua_classify("curl/8", 4) == HC_UA_OTHER);
#undef UA
  printf("  user-agent families: ok\n");
}

static void
test_ua_name(void)
{
  int st;

  /* In one piece, and split anywhere. */
  assert(hc_ua_name_step(0, "User-Agent", 10) == HC_UA_NAME_LEN);
  st = hc_ua_name_step(0, "User-", 5);
  assert(st == 5);
  st = hc_ua_name_step(st, "AGENT", 5);
  assert(st == HC_UA_NAME_LEN);
  /* Longer names and other names do not match; once lost it stays lost. */
  assert(hc_ua_name_step(0, "User-Agents", 11) == -1);
  assert(hc_ua_name_step(0, "Host", 4) == -1);
  assert(hc_ua_name_step(-1, "User-Agent", 10) == -1);
  /* A prefix alone is not a match (the caller checks for the full length). */
  assert(hc_ua_name_step(0, "User", 4) == 4);
  printf("  user-agent header name: ok\n");
}

int
main(void)
{
  printf("test_hc_metrics\n");
  test_fin_buckets();
  test_prog_buckets();
  test_cumulative();
  test_early();
  test_tls_path();
  test_classify();
  test_ua();
  test_ua_name();
  printf("ALL PASS\n");
  return 0;
}
