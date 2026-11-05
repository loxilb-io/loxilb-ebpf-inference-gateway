#!/usr/bin/env python3
"""Exercise production HTTP media callbacks with the bundled llhttp parser."""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parent
source = (root / "sockproxy_http.c").read_text()
start = source.index("enum {\n  SP_H1_MEDIA_JSON")
end = source.index("};", start) + 2
media_enum = source[start:end]
start = source.index("static void\nsp_h1_header_span(")
end = source.index("\nint\nhandle_header_name(", start)
callbacks = source[start:end]
prefix = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "llhttp.h"
typedef struct {
  char *rcvbuf;
  int odir, http_hdrs_done;
  size_t http_header_start, http_header_len;
  uint8_t http_content_type_field, http_body_media;
} proxy_fd_ent_t;
'''
suffix = r'''
static int begin(llhttp_t *parser)
{
  llhttp_settings_t *settings = parser->settings;
  proxy_fd_ent_t *p = settings->uarg;
  p->http_hdrs_done = p->http_header_len = 0;
  p->http_content_type_field = p->http_body_media = 0;
  return 0;
}
static int field(llhttp_t *parser, const char *at, size_t len)
{
  llhttp_settings_t *settings = parser->settings;
  sp_h1_header_span(settings->uarg, at, len);
  return 0;
}
static int value(llhttp_t *parser, const char *at, size_t len)
{
  llhttp_settings_t *settings = parser->settings;
  proxy_fd_ent_t *p = settings->uarg;
  if (p->http_content_type_field)
    sp_h1_header_span(p, at, len);
  return 0;
}
static int headers(llhttp_t *parser)
{
  llhttp_settings_t *settings = parser->settings;
  proxy_fd_ent_t *p = settings->uarg;
  p->http_hdrs_done = 1;
  assert(parser->content_length == 2);
  return 0;
}
static void test(const char *header, int expected)
{
  char wire[8192];
  size_t len = (size_t)snprintf(wire, sizeof(wire),
      "POST / HTTP/1.1\r\nHost: test\r\n%sContent-Length: 2\r\n\r\n{}", header);
  assert(len < sizeof(wire));
  llhttp_settings_t settings;
  llhttp_settings_init(&settings);
  settings.on_message_begin = begin;
  settings.on_header_field = field;
  settings.on_header_field_complete = sp_h1_header_field_complete;
  settings.on_header_value = value;
  settings.on_header_value_complete = sp_h1_header_value_complete;
  settings.on_headers_complete = headers;
  proxy_fd_ent_t p = {.rcvbuf = wire};
  settings.uarg = &p;
  llhttp_t parser;
  for (size_t split = 0; split <= len; split++) {
    llhttp_init(&parser, HTTP_REQUEST, &settings);
    assert(llhttp_execute(&parser, wire, split) == HPE_OK);
    assert(llhttp_execute(&parser, wire + split, len - split) == HPE_OK);
    assert(p.http_body_media == expected);
  }
  /* Reuse the same parser for consecutive requests, each delivered bytewise. */
  llhttp_init(&parser, HTTP_REQUEST, &settings);
  for (int request = 0; request < 3; request++) {
    for (size_t i = 0; i < len; i++)
      assert(llhttp_execute(&parser, wire + i, 1) == HPE_OK);
    assert(p.http_body_media == expected);
  }
}
int main(void)
{
  test("Content-Type: application/json\r\n", SP_H1_MEDIA_JSON);
  test("cOnTeNt-TyPe: ApPlIcAtIoN/JsOn \t; charset=utf-8\r\n", SP_H1_MEDIA_JSON);
  test("Content-Type: application/x-www-form-urlencoded; charset=utf-8\r\n", SP_H1_MEDIA_FORM);
  test("X-Content-Type: application/json\r\n", 0);
  test("Content-Type-Extra: application/json\r\n", 0);
  test("Content-Type: application/json-extra\r\n", 0);
  test("Content-Type: text/plain; note=\"application/json\"\r\n", 0);
  test("Content-Type: \r\n", 0);
  test("", 0);
  char header[4096];
  for (int offset = 2032; offset <= 2033; offset++) {
    int prefix = (int)strlen("POST / HTTP/1.1\r\nHost: test\r\nX-Pad: \r\nContent-Type: ");
    snprintf(header, sizeof(header), "X-Pad: %*s\r\nContent-Type: application/json\r\n",
             offset - prefix, "");
    test(header, SP_H1_MEDIA_JSON);
  }
  puts("HTTP media callbacks: every split, bytewise keep-alive, exact names/types, JSON/form and 2032/2033 boundaries PASS");
}
'''
with tempfile.TemporaryDirectory() as folder:
    folder = Path(folder)
    unit = folder / "test.c"
    binary = folder / "test"
    unit.write_text(prefix + media_enum + callbacks + suffix)
    subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra",
                    "-Werror", "-Wno-unused-parameter", "-fsanitize=address,undefined", "-I", str(root),
                    str(unit), str(root / "llhttp.c"), str(root / "httpapi.c"),
                    str(root / "http.c"), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
