#!/usr/bin/env python3
"""Exercise the real terminal sender and client read-entry guard on queued events.

Only transport/admission are stubbed. Re-enter the read path after a refusal,
including failed writes/formatting, and require one decision and no forwarding.
"""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

root = Path(__file__).resolve().parent
source = (root / "sockproxy_http.c").read_text()
start = source.index("void\nsp_h1_send_admit_deny(")
end = source.index("\n}\n", start) + 3
sender = source[start:end]
start = source.index("int\nhandle_client_data(")
start = source.index("  if (!pfe->odir && pfe->ai_gw_denied)", start)
end = source.index("\n\n", start)
guard = source[start:end]
fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "sockproxy_admit_response.h"
typedef struct {
  int fd, odir, ai_gw_denied, ai_gw_stream_gated;
} proxy_fd_ent_t;
static unsigned decisions, audits, notes, writes, closes, forwarded;
static int write_result, format_failure;
static int format_response(char *out, size_t cap, int status, int retry,
                           int retry_body, const char *code, const char *msg) {
  if (format_failure) return -1;
  return sp_h1_format_admit_deny(out, cap, status, retry, retry_body, code, msg);
}
#define sp_h1_format_admit_deny format_response
#define log_error(...) ((void)0)
#define SHUT_RDWR 2
static int shutdown(int fd, int how) {
  (void)fd; assert(how == SHUT_RDWR); closes++; return 0;
}
static void proxy_note_local_refusal(proxy_fd_ent_t *pfe, unsigned status) {
  (void)pfe; assert(status >= 400); notes++;
}
static int proxy_send_local_response_and_shutdown(proxy_fd_ent_t *pfe,
                                                  const char *out, size_t n) {
  (void)pfe;
  assert(n > 0 && strncmp(out, "HTTP/1.1 ", 9) == 0);
  writes++; closes++; return write_result;
}
/* PRODUCTION_SENDER */
static int read_event(proxy_fd_ent_t *pfe, int status) {
/* PRODUCTION_GUARD */
  if (pfe->odir) { forwarded++; return 0; }
  if (!pfe->ai_gw_stream_gated) {
    decisions++;
    if (status) {
      audits++;
      sp_h1_send_admit_deny(pfe, status, 1, status == 429,
                            "fixture_denied", "fixture refusal");
      return -1;
    }
    pfe->ai_gw_stream_gated = 1;
  }
  forwarded++;
  return 0;
}
static void reset(void) {
  decisions=audits=notes=writes=closes=forwarded=0;
}
static void denied(int status, int send_failure, int bad_format) {
  proxy_fd_ent_t client = { .fd=77 };
  reset(); write_result=send_failure; format_failure=bad_format;
  for (int event=0; event<64; event++)
    assert(read_event(&client, status) == -1);
  assert(decisions == 1 && audits == 1 && forwarded == 0);
  assert(closes == 1 && notes == (bad_format ? 0u : 1u));
  assert(writes == (bad_format ? 0u : 1u));
}
int main(void) {
  const int statuses[] = {400,401,403,413,429,503};
  for (unsigned i=0; i<sizeof(statuses)/sizeof(statuses[0]); i++) {
    denied(statuses[i], 0, 0);
    denied(statuses[i], -1, 0);
    denied(statuses[i], 0, 1);
  }
  proxy_fd_ent_t allowed = { .fd=78 };
  reset(); format_failure=0; write_result=0;
  for (int event=0; event<64; event++) assert(read_event(&allowed, 0) == 0);
  assert(decisions == 1 && audits == 0 && writes == 0 && forwarded == 64);
  proxy_fd_ent_t backend = { .fd=79, .odir=1, .ai_gw_denied=1 };
  reset(); assert(read_event(&backend, 403) == 0);
  assert(decisions == 0 && forwarded == 1);
  puts("PASS terminal H1 denial: 18 fault/status cases x64 queued events; allowed-stream and backend-direction controls");
}
'''.replace("/* PRODUCTION_SENDER */", sender).replace("/* PRODUCTION_GUARD */", guard)
with tempfile.TemporaryDirectory(prefix="h1-terminal-deny-") as directory:
    test = Path(directory) / "test.c"
    binary = Path(directory) / "test"
    test.write_text(fixture)
    subprocess.run(shlex.split(os.environ.get("CC", "cc")) + [
        "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined",
        "-I", str(root), str(test), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
