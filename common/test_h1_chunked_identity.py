#!/usr/bin/env python3
"""Run H1 upstream hygiene with real llhttp framing and header splice helpers."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

root = Path(__file__).resolve().parent
source = (root / "sockproxy_http.c").read_text()
start = source.index("static size_t\nai_strip_upstream_api_key(")
end = source.index("\n/*\n * sp_llmd_forward_headers", start)
production = source[start:end]
fixture = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "llhttp.h"
#define log_error(...) ((void)0)
#include "sockproxy_l7hdr_guard.h"
#include "sockproxy_h1_hdr.h"
typedef struct { uint8_t apikey_auth; } proxy_epval_t;
typedef struct { proxy_epval_t pool; } proxy_map_ent_t;
typedef struct {
  int odir, auth_jwt_capable, auth_strip_authz, auth_fwd_identity, auth_netid_fwd;
  char tenant_id[32], auth_user_id[32];
  proxy_map_ent_t *head;
  llhttp_t parser;
} proxy_fd_ent_t;
static proxy_epval_t *sp_pool_first(proxy_map_ent_t *node) { return &node->pool; }
static int proxy_svc_forwards_netid(proxy_map_ent_t *node) { (void)node; return 0; }
static int ai_security_should_strip_api_key(uint8_t policy) { return policy == 3; }
/* PRODUCTION */
static int pause_complete(llhttp_t *parser) { (void)parser; return HPE_PAUSED; }
static unsigned passed;
static void run(const char *name, const char *te, size_t pad,
                const char *decoy, int chunked, int at_gate, int body_decoy) {
  proxy_map_ent_t node = { .pool = { .apikey_auth = 3 } };
  proxy_fd_ent_t pfe = {
    .auth_jwt_capable = 1, .auth_strip_authz = 1, .auth_fwd_identity = 1,
    .head = &node, .tenant_id = "verified-tenant", .auth_user_id = "alice"
  };
  llhttp_settings_t settings;
  uint8_t buf[16384];
  char encoded_body[1024];
  const char *body = body_decoy ?
      "{\"model\":\"m\",\"text\":\"Transfer-Encoding: chunked\"}" :
      "{\"model\":\"m\",\"text\":\"payload\"}";
  int n;
  size_t len, wire_body_len, old_header_len;
  uint8_t *header_end;
  llhttp_settings_init(&settings);
  settings.on_message_complete = pause_complete;
  llhttp_init(&pfe.parser, HTTP_REQUEST, &settings);
  if (chunked)
    n = snprintf(encoded_body, sizeof(encoded_body), "%zx\r\n%s\r\n0\r\n\r\n", strlen(body), body);
  else
    n = snprintf(encoded_body, sizeof(encoded_body), "%s", body);
  assert(n > 0 && (size_t)n < sizeof(encoded_body));
  wire_body_len = (size_t)n;
  n = snprintf((char *)buf, sizeof(buf),
      "POST /v1/chat/completions HTTP/1.1\r\nHost: test\r\n"
      "Authorization: Bearer consumed-token\r\nX-Api-Key: consumed-key\r\n"
      "X-Auth-Tenant: spoofed\r\nX-Auth-User: spoofed\r\nX-Pad: ");
  assert(n > 0); len = (size_t)n;
  assert(len + pad + 2048 < sizeof(buf));
  memset(buf + len, 'x', pad); len += pad;
  n = snprintf((char *)buf + len, sizeof(buf) - len, "\r\n%s", decoy);
  assert(n >= 0); len += (size_t)n;
  if (chunked)
    n = snprintf((char *)buf + len, sizeof(buf) - len, "%s\r\n", te);
  else
    n = snprintf((char *)buf + len, sizeof(buf) - len, "Content-Length: %zu\r\n", strlen(body));
  assert(n > 0); len += (size_t)n;
  memcpy(buf + len, "\r\n", 2); len += 2;
  old_header_len = len;
  memcpy(buf + len, encoded_body, wire_body_len); len += wire_body_len;
  assert(llhttp_execute(&pfe.parser, (const char *)buf, len) == HPE_PAUSED);
  assert(!!(pfe.parser.flags & F_CHUNKED) == chunked);
  len = ai_strip_upstream_api_key(&pfe, buf, len, sizeof(buf), at_gate);
  header_end = memmem(buf, len, "\r\n\r\n", 4);
  assert(header_end);
  size_t hlen = (size_t)(header_end + 4 - buf);
  assert(!memmem(buf, hlen, "Authorization:", 14));
  assert(!memmem(buf, hlen, "X-Api-Key:", 10));
  assert(!memmem(buf, hlen, "spoofed", 7));
  if (!chunked && at_gate) {
    assert(memmem(buf, hlen, "X-Auth-Tenant: verified-tenant\r\n", 32));
    assert(memmem(buf, hlen, "X-Auth-User: alice\r\n", 20));
  } else {
    assert(!memmem(buf, hlen, "X-Auth-", 7));
  }
  assert(len - hlen == wire_body_len);
  assert(memcmp(buf + hlen, encoded_body, wire_body_len) == 0);
  assert(hlen < old_header_len + 128);
  printf("PASS: %s\n", name); fflush(stdout); passed++;
}
int main(void) {
  run("canonical chunked", "Transfer-Encoding: chunked", 0, "", 1, 1, 0);
  run("mixed value", "Transfer-Encoding: Chunked", 0, "", 1, 1, 0);
  run("mixed name/value", "tRaNsFeR-EnCoDiNg: ChUnKeD", 0, "", 1, 1, 0);
  run("late chunked header", "Transfer-Encoding: chunked", 4096, "", 1, 1, 0);
  run("late mixed chunked header", "transfer-encoding: CHUNKED", 4096, "", 1, 1, 0);
  run("Content-Length body decoy still injects", NULL, 0, "", 0, 1, 1);
  run("Content-Length header decoy still injects", NULL, 0,
      "X-Note: Transfer-Encoding: chunked\r\n", 0, 1, 0);
  run("relay read never injects", NULL, 0, "", 0, 0, 0);
  assert(passed == 8);
  puts("ALL PASS (8/8 H1 framing and identity paths)");
}
'''.replace("/* PRODUCTION */", production)
with tempfile.TemporaryDirectory(prefix="h1-chunked-identity-") as directory:
    test = Path(directory) / "test.c"
    binary = Path(directory) / "test"
    test.write_text(fixture)
    subprocess.run(shlex.split(os.environ.get("CC", "cc")) + [
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
        "-fsanitize=address,undefined", "-I", str(root), str(test),
        str(root / "llhttp.c"), str(root / "httpapi.c"), str(root / "http.c"),
        "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
