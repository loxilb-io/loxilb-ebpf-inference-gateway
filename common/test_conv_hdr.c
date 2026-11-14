/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_conv_hdr.c - which request headers are a conversation ID on HTTP/1.1.
 *
 * X-Request-Id used to be one. It is a per-request correlation key, so a
 * client that sent a fresh one with every request lost its JSON "user"
 * stickiness on prefill/decode rules and was placed by the hash of the ID
 * on hash-selected rules. The capture in handle_header_val now asks
 * sp_h1_conv_id_header, which this unit pins.
 *
 * THE ORACLE IS SELF-VERIFYING: prefix_rule() below is the capture's name
 * test as it was, kept verbatim. The X-Request-Id cases count only if they
 * pass the shipped helper and FAIL the old rule.
 *
 * Build (wired into `make test_convhdr`):
 *   gcc -Wall -Wextra -o test_conv_hdr test_conv_hdr.c -I.
 */
#include <stdio.h>
#include <string.h>

#include "sockproxy_conv_hdr.h"

static int checks, failures;

#define CHECK(cond, ...) do {                                        \
    checks++;                                                        \
    if (cond) {                                                      \
      printf("ok %d - ", checks); printf(__VA_ARGS__); printf("\n"); \
    } else {                                                         \
      failures++;                                                    \
      printf("FAIL %d - ", checks); printf(__VA_ARGS__);             \
      printf("   (%s:%d)\n", __FILE__, __LINE__);                    \
    }                                                                \
  } while (0)

/* The PRE-FIX rule, verbatim from handle_header_val. */
static int
prefix_rule(const char *name)
{
  return !strncasecmp("X-Conversation-ID", name, 17) ||
         !strncasecmp("X-Request-Id", name, 12) ||
         !strncasecmp("X-Session-ID", name, 12) ||
         !strncasecmp("X-Trace-ID", name, 10);
}

int
main(void)
{
  static const char *const keep[] = {
    "X-Conversation-ID", "x-conversation-id", "X-Conversation-Id",
    "X-Session-ID", "x-session-id", "X-Trace-ID", "x-trace-id",
  };
  static const char *const not_one[] = {
    "X-Request-Id", "x-request-id", "X-REQUEST-ID", "X-Request-Id-Source",
  };
  static const char *const never[] = {
    "Host", "Content-Type", "X-Api-Key", "X-Conversation", "X-Session", "X-Trace",
    "X-Model", "Authorization", "",
  };
  size_t i;

  for (i = 0; i < sizeof(keep) / sizeof(keep[0]); i++) {
    CHECK(sp_h1_conv_id_header(keep[i]), "%s is a conversation ID", keep[i]);
    CHECK(prefix_rule(keep[i]), "%s was one before, too: nothing is taken away", keep[i]);
  }
  for (i = 0; i < sizeof(not_one) / sizeof(not_one[0]); i++) {
    CHECK(!sp_h1_conv_id_header(not_one[i]), "%s is not a conversation ID", not_one[i]);
    CHECK(prefix_rule(not_one[i]), "the pre-fix rule took %s for one, so this case can go red", not_one[i]);
  }
  for (i = 0; i < sizeof(never) / sizeof(never[0]); i++)
    CHECK(!sp_h1_conv_id_header(never[i]) && !prefix_rule(never[i]),
          "'%s' is not one, before or after", never[i]);
  CHECK(!sp_h1_conv_id_header(NULL), "no name is no conversation ID");

  printf("\n1..%d\n", checks);
  if (failures) {
    printf("# %d of %d checks FAILED\n", failures, checks);
    return 1;
  }
  printf("# all %d checks passed\n", checks);
  return 0;
}
