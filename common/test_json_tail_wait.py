#!/usr/bin/env python3
"""Exercise the production dispatch guard with a deliberately short body.

Normal model_ready dispatch already has enough bytes. Extract only its defensive
block into a small read-loop fixture; this is branch coverage, not an HTTP test.
"""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

root = Path(__file__).resolve().parent
source = (root / "sockproxy_http.c").read_text()
start = source.index("            if (pfe->json_guard_active && !pfe->http_pok &&")
end = source.index("            // Setup backend connection + forward.", start)
block = source[start:end]
fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "sockproxy_stream_fallback.h"
struct client {
  int json_guard_active, http_pok, json_guard_streaming, json_guard_chunked;
  uint8_t rcvbuf[256], json_guard_tail[5];
  size_t rcv_off, json_guard_tail_len;
};
static unsigned waits;
#define log_debug(fmt, ...) do { if (strstr(fmt, "JSON_GUARD_WAIT")) waits++; } while (0)
static void run(int chunked) {
  struct client client = { .json_guard_active = 1, .json_guard_chunked = chunked };
  struct client *pfe = &client;
  const char *header = "POST / HTTP/1.1\r\nHost: test\r\n\r\n";
  size_t hlen = strlen(header), hold = chunked ? 5 : 1;
  unsigned dispatched = 0;
  memcpy(pfe->rcvbuf, header, hlen);
  for (unsigned read = 0; read < 2; read++) {
    /* Force the normally unreachable state, then append enough body bytes. */
    size_t body = read == 0 ? hold - 1 : hold;
    memset(pfe->rcvbuf + hlen, 'x', body);
    pfe->rcv_off = hlen + body;
    assert(pfe->json_guard_active == 1);
    assert(pfe->json_guard_streaming == 0);
    assert(pfe->json_guard_tail_len == 0);
    /* PRODUCTION_BLOCK */
    dispatched++;
    assert(read == 1); /* A fail-open branch dispatches on the first read. */
    assert(pfe->json_guard_active == 1 && pfe->json_guard_streaming == 1);
    assert(pfe->json_guard_tail_len == hold && pfe->rcv_off == hlen);
  }
  assert(dispatched == 1);
}
int main(void) {
  run(0); run(1);
  assert(waits == 2);
  puts("ALL PASS (2/2 dispatch wait/resume paths)");
}
'''.replace("    /* PRODUCTION_BLOCK */", block)
with tempfile.TemporaryDirectory(prefix="json-tail-wait-") as directory:
    test = Path(directory) / "test.c"
    binary = Path(directory) / "test"
    test.write_text(fixture)
    subprocess.run(shlex.split(os.environ.get("CC", "cc")) + [
        "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined",
        "-I", str(root), str(test), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
