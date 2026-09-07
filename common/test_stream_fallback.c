/* SPDX-License-Identifier: BSD-3-Clause */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "sockproxy_stream_fallback.h"

struct send_script {
  const ssize_t *steps;
  size_t step_count;
  size_t step;
  uint8_t output[256];
  size_t output_len;
};

static ssize_t
scripted_send(void *arg, const uint8_t *buf, size_t len, int *retryable)
{
  struct send_script *script = arg;
  ssize_t n;

  assert(script->step < script->step_count);
  n = script->steps[script->step++];
  if (n < 0) {
    *retryable = n == -1;
    return -1;
  }
  assert((size_t)n <= len);
  assert(script->output_len + (size_t)n <= sizeof(script->output));
  memcpy(script->output + script->output_len, buf, (size_t)n);
  script->output_len += (size_t)n;
  return n;
}

int
main(void)
{
  static const char request[] =
      "POST /v1/completions HTTP/1.1\r\n"
      "Host: 10.10.10.254:8080\r\n"
      "eXpEcT:\t100-CoNtInUe  \r\n"
      "Content-Length: 8\r\n\r\n"
      "A\0B\r\nCDE";
  static const char expected[] =
      "POST /v1/completions HTTP/1.1\r\n"
      "Host: 10.10.10.254:8080\r\n"
      "Content-Length: 8\r\n\r\n"
      "A\0B\r\nCDE";
  uint8_t buf[sizeof(request)];
  size_t len = sizeof(request) - 1;

  assert(!sp_http_expect_100_continue(NULL, 0));
  memcpy(buf, request, len);
  assert(sp_http_expect_100_continue(buf, len));
  assert(sp_http_should_send_100_continue(buf, len, 0));
  assert(!sp_http_should_send_100_continue(buf, len, 1));
  assert(sp_http_strip_expect_100_continue(buf, &len) == 1);
  assert(len == sizeof(expected) - 1);
  assert(memcmp(buf, expected, len) == 0);
  assert(!sp_http_expect_100_continue(buf, len));
  assert(sp_http_strip_expect_100_continue(buf, &len) == 0);

  assert(sp_stream_body_remaining(1381179, 0) == 1381179);
  assert(sp_stream_body_remaining(1381179, 65361) == 1315818);
  assert(sp_stream_body_remaining(8, 8) == 0);
  assert(sp_stream_body_remaining(8, 9) == 0);

  {
    uint8_t routed[SP_JSON_ROUTE_PREFIX_MAX + 128];
    const uint8_t *body;
    size_t prefix_len;
    int at_limit;
    static const char headers[] =
        "POST /v1/completions HTTP/1.1\r\nX-Pad: 1234567890\r\n\r\n";
    size_t header_len = sizeof(headers) - 1;

    memcpy(routed, headers, header_len);
    memset(routed + header_len, 'x', sizeof(routed) - header_len);
    assert(sp_json_route_body_prefix(routed, header_len + 17, &body,
                                     &prefix_len, &at_limit) == 0);
    assert(body == routed + header_len);
    assert(prefix_len == 17 && !at_limit);
    assert(sp_json_route_read_want(routed, header_len + 17, 100000) ==
           SP_JSON_ROUTE_PREFIX_MAX - 17);
    assert(sp_json_route_body_prefix(routed,
                                     header_len + SP_JSON_ROUTE_PREFIX_MAX + 9,
                                     &body, &prefix_len, &at_limit) == 0);
    assert(prefix_len == SP_JSON_ROUTE_PREFIX_MAX && at_limit);
    assert(sp_json_route_read_want(routed,
                                   header_len + SP_JSON_ROUTE_PREFIX_MAX,
                                   4096) == 0);
  }

  {
    static const uint8_t local_100[] = "HTTP/1.1 100 Continue\r\n\r\n";
    static const ssize_t steps[] = { 5, -1, 3, -1, 17 };
    struct send_script script = {
      .steps = steps,
      .step_count = sizeof(steps) / sizeof(steps[0]),
    };

    assert(sp_send_all_bounded(scripted_send, &script, local_100,
                               sizeof(local_100) - 1,
                               SP_LOCAL_SEND_RETRY_MAX) == 0);
    assert(script.output_len == sizeof(local_100) - 1);
    assert(memcmp(script.output, local_100, script.output_len) == 0);
    assert(script.step == sizeof(steps) / sizeof(steps[0]));
  }

  {
    static const uint8_t one[] = "x";
    static const ssize_t steps[] = { -1, -1, -1 };
    struct send_script script = {
      .steps = steps,
      .step_count = sizeof(steps) / sizeof(steps[0]),
    };

    assert(sp_send_all_bounded(scripted_send, &script, one, 1, 2) == -1);
    assert(script.output_len == 0);
  }

  {
    char body_model[32] = {0};
    char header_model[32] = "spoofed-header-model";
    assert(sp_store_authoritative_body_model(body_model, sizeof(body_model),
                                             header_model,
                                             "body-model") == 0);
    assert(strcmp(body_model, "body-model") == 0);
    assert(header_model[0] == '\0');
  }

  puts("ALL PASS (30/30)");
  return 0;
}
