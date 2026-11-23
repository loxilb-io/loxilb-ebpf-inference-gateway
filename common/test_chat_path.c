/* SPDX-License-Identifier: (GPL-2.0) */
/*
 * test_chat_path.c - sp_is_chat_path() (sockproxy.h) gives, on every kind of
 * path, the value the HTTP/1.1 is_chat line computed before it used the
 * predicate. That value feeds the KV-exact tokenize stage, so it must not
 * change. old_is_chat() below is that line's expression, verbatim, on the
 * same field type (proxy_fd_ent_t.request_path).
 */
#include <stdio.h>
#include <string.h>

#include "uthash.h"
#include "sockproxy.h"

typedef char request_path_t[sizeof(((proxy_fd_ent_t *)0)->request_path)];

static uint8_t old_is_chat(const request_path_t request_path)
{
  uint8_t is_chat = 0;
  if (request_path[0] != '\0' &&
      strncmp(request_path, "/v1/chat/completions", 20) == 0 &&
      (request_path[20] == '\0' || request_path[20] == '?')) {
    is_chat = 1;
  }
  return is_chat;
}

int main(void)
{
  static const struct { const char *path; int want; } t[] = {
    { "/v1/chat/completions", 1 },            /* exact */
    { "/v1/chat/completions?stream=true", 1 },/* with a query */
    { "/v1/chat/completions?", 1 },
    { "/v1/chat/completions/", 0 },           /* trailing slash */
    { "/v1/chat/completionsX", 0 },           /* longer, same prefix */
    { "/v1/chat/completions/x", 0 },
    { "/v1/chat/completion", 0 },             /* shorter */
    { "", 0 },                                /* empty */
    { "/v1/completions", 0 },                 /* different */
    { "/v1/embeddings", 0 },
    { "/V1/chat/completions", 0 },
    { "v1/chat/completions", 0 },
  };
  int fail = 0;

  printf("| path | old expression | sp_is_chat_path | expected |\n|---|---|---|---|\n");
  for (unsigned i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
    request_path_t rp;
    int o, n;

    memset(rp, 'Z', sizeof(rp));              /* bytes after the NUL are not read */
    snprintf(rp, sizeof(rp), "%s", t[i].path);
    o = old_is_chat(rp);
    n = sp_is_chat_path(rp) ? 1 : 0;
    printf("| `%s` | %d | %d | %d |%s\n", t[i].path, o, n, t[i].want,
           o == n && n == t[i].want ? "" : " MISMATCH");
    fail += !(o == n && n == t[i].want);
  }
  printf("test_chat_path: %s (%d mismatches)\n", fail ? "FAIL" : "PASS", fail);
  return fail ? 1 : 0;
}
