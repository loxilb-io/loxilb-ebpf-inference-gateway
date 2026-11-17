/* SPDX-License-Identifier: BSD-3-Clause */
/* test_chwbl_prefix_hash.c - pins the CHWBL prefix hash for a fixed corpus.
 *
 * Runs the production path a CHWBL pool uses to key a request:
 * extract_llm_prefix() -> chwbl_apply_hash_policy() -> compute_prefix_hash().
 * The corpus is synthetic (no real prompt text). The expected values were
 * recorded at native 3e18489; a change to extraction, policy or hashing that
 * moves any request to another ring position fails here.
 *
 * The values depend on HAVE_LLM_SYSTEM_PROMPT_HASH (user-prefix fallback) and
 * HAVE_DP_GPU_ROUTING (chwbl_apply_hash_policy); the Makefile rule pins both.
 * LLB_LLM_USER_PREFIX_FALLBACK_LEN is cleared so the default bound applies.
 *
 * Build: make test_chwbl_prefix_hash
 * Run:   ./test_chwbl_prefix_hash          (check)
 *        ./test_chwbl_prefix_hash --print  (print the table, no check)
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "uthash.h"
#include "log.h"
#include "sockproxy_lb.h"

void log_log(int level, const char *file, int line, const char *fmt, ...)
{
  (void)level; (void)file; (void)line; (void)fmt;
}

#include "sockproxy_json.c"

#define SYN_300A "syn-user-opening-0001 syn-user-opening-0002 syn-user-opening-0003 " \
                 "syn-user-opening-0004 syn-user-opening-0005 syn-user-opening-0006 " \
                 "syn-user-opening-0007 syn-user-opening-0008 syn-user-opening-0009 " \
                 "syn-user-opening-0010 syn-user-opening-0011 syn-user-opening-0012 " \
                 "syn-user-tail-aaaa"
#define SYN_300B "syn-user-opening-0001 syn-user-opening-0002 syn-user-opening-0003 " \
                 "syn-user-opening-0004 syn-user-opening-0005 syn-user-opening-0006 " \
                 "syn-user-opening-0007 syn-user-opening-0008 syn-user-opening-0009 " \
                 "syn-user-opening-0010 syn-user-opening-0011 syn-user-opening-0012 " \
                 "syn-user-tail-bbbb"

static const struct {
  const char *name;
  const char *body;
} corpus[] = {
  { "sys_a_user_1",
    "{\"model\":\"syn-model-1\",\"messages\":[{\"role\":\"system\",\"content\":\"syn-sys-A\"},"
    "{\"role\":\"user\",\"content\":\"syn-user-1\"}]}" },
  { "sys_a_user_2",
    "{\"model\":\"syn-model-1\",\"messages\":[{\"role\":\"system\",\"content\":\"syn-sys-A\"},"
    "{\"role\":\"user\",\"content\":\"syn-user-2\"}]}" },
  { "sys_b_user_1",
    "{\"model\":\"syn-model-1\",\"messages\":[{\"role\":\"system\",\"content\":\"syn-sys-B\"},"
    "{\"role\":\"user\",\"content\":\"syn-user-1\"}]}" },
  { "sys_a_model_2",
    "{\"model\":\"syn-model-2\",\"messages\":[{\"role\":\"system\",\"content\":\"syn-sys-A\"},"
    "{\"role\":\"user\",\"content\":\"syn-user-1\"}]}" },
  { "user_only_short",
    "{\"model\":\"syn-model-1\",\"messages\":[{\"role\":\"user\",\"content\":\"syn-user-1\"}]}" },
  { "user_only_long_a",
    "{\"model\":\"syn-model-1\",\"messages\":[{\"role\":\"user\",\"content\":\"" SYN_300A "\"}]}" },
  { "user_only_long_b",
    "{\"model\":\"syn-model-1\",\"messages\":[{\"role\":\"user\",\"content\":\"" SYN_300B "\"}]}" },
  { "completions_prompt",
    "{\"model\":\"syn-model-1\",\"prompt\":\"syn-completion-prompt-1\"}" },
  { "lora",
    "{\"model\":\"syn-model-1\",\"lora_adapter\":\"syn-lora-1\",\"messages\":["
    "{\"role\":\"system\",\"content\":\"syn-sys-A\"},{\"role\":\"user\",\"content\":\"syn-user-1\"}]}" },
  { "cache_salt",
    "{\"model\":\"syn-model-1\",\"cache_salt\":\"syn-salt-1\",\"messages\":["
    "{\"role\":\"system\",\"content\":\"syn-sys-A\"},{\"role\":\"user\",\"content\":\"syn-user-1\"}]}" },
  { "tools",
    "{\"model\":\"syn-model-1\",\"tools\":[{\"type\":\"function\",\"function\":{\"name\":\"syn_tool_1\","
    "\"parameters\":{\"type\":\"object\"}}}],\"messages\":["
    "{\"role\":\"system\",\"content\":\"syn-sys-A\"},{\"role\":\"user\",\"content\":\"syn-user-1\"}]}" },
  { "images",
    "{\"model\":\"syn-model-1\",\"images\":[\"syn-image-ref-1\"],\"messages\":["
    "{\"role\":\"system\",\"content\":\"syn-sys-A\"},{\"role\":\"user\",\"content\":\"syn-user-1\"}]}" },
  { "session_context",
    "{\"model\":\"syn-model-1\",\"session_context\":\"syn-session-1\",\"messages\":["
    "{\"role\":\"system\",\"content\":\"syn-sys-A\"},{\"role\":\"user\",\"content\":\"syn-user-1\"}]}" },
  { "rag_context",
    "{\"model\":\"syn-model-1\",\"rag_context\":{\"rag_template\":\"syn-rag-template-1\","
    "\"document_ids\":[\"syn-doc-2\",\"syn-doc-1\"]},\"messages\":["
    "{\"role\":\"system\",\"content\":\"syn-sys-A\"},{\"role\":\"user\",\"content\":\"syn-user-1\"}]}" },
  { "no_prefix",
    "{\"model\":\"syn-model-1\"}" },
};

static const struct {
  const char *name;
  uint32_t level, flags;
  uint8_t require_salt;
} policies[] = {
  { "L1", 1, 0, 0 },
  { "L2", 2, 0, 0 },
  { "L3", 3, 0, 0 },
  { "L1salt", 1, 0, 1 },
};

#define N_CORPUS (sizeof(corpus) / sizeof(corpus[0]))
#define N_POLICY (sizeof(policies) / sizeof(policies[0]))

typedef struct {
  int extract_rc, policy_rc, level;
  uint32_t flags;
  unsigned long long hash;
} row_t;

/* Expected values: one row per (corpus entry, policy), corpus-major. */
static const row_t expected[N_CORPUS * N_POLICY] = {
  { 0, 0, 1, 0x00, 0x3ad87b45e8ca9cb0ULL }, /* sys_a_user_1 L1 */
  { 0, 0, 2, 0x00, 0x3ad87b45e8ca9cb0ULL }, /* sys_a_user_1 L2 */
  { 0, 0, 3, 0x00, 0x3ad87b45e8ca9cb0ULL }, /* sys_a_user_1 L3 */
  { 0, -2, 0, 0x00, 0x0000000000000000ULL }, /* sys_a_user_1 L1salt */
  { 0, 0, 1, 0x00, 0x3ad87b45e8ca9cb0ULL }, /* sys_a_user_2 L1 */
  { 0, 0, 2, 0x00, 0x3ad87b45e8ca9cb0ULL }, /* sys_a_user_2 L2 */
  { 0, 0, 3, 0x00, 0x3ad87b45e8ca9cb0ULL }, /* sys_a_user_2 L3 */
  { 0, -2, 0, 0x00, 0x0000000000000000ULL }, /* sys_a_user_2 L1salt */
  { 0, 0, 1, 0x00, 0xb0256f3296cc12f0ULL }, /* sys_b_user_1 L1 */
  { 0, 0, 2, 0x00, 0xb0256f3296cc12f0ULL }, /* sys_b_user_1 L2 */
  { 0, 0, 3, 0x00, 0xb0256f3296cc12f0ULL }, /* sys_b_user_1 L3 */
  { 0, -2, 0, 0x00, 0x0000000000000000ULL }, /* sys_b_user_1 L1salt */
  { 0, 0, 1, 0x00, 0x8986517b02624879ULL }, /* sys_a_model_2 L1 */
  { 0, 0, 2, 0x00, 0x8986517b02624879ULL }, /* sys_a_model_2 L2 */
  { 0, 0, 3, 0x00, 0x8986517b02624879ULL }, /* sys_a_model_2 L3 */
  { 0, -2, 0, 0x00, 0x0000000000000000ULL }, /* sys_a_model_2 L1salt */
  { 0, 0, 1, 0x00, 0x2bcb5824555b8625ULL }, /* user_only_short L1 */
  { 0, 0, 2, 0x00, 0x2bcb5824555b8625ULL }, /* user_only_short L2 */
  { 0, 0, 3, 0x00, 0x2bcb5824555b8625ULL }, /* user_only_short L3 */
  { 0, -2, 0, 0x00, 0x0000000000000000ULL }, /* user_only_short L1salt */
  { 0, 0, 1, 0x00, 0x9048eae7e2b97a74ULL }, /* user_only_long_a L1 */
  { 0, 0, 2, 0x00, 0x9048eae7e2b97a74ULL }, /* user_only_long_a L2 */
  { 0, 0, 3, 0x00, 0x9048eae7e2b97a74ULL }, /* user_only_long_a L3 */
  { 0, -2, 0, 0x00, 0x0000000000000000ULL }, /* user_only_long_a L1salt */
  { 0, 0, 1, 0x00, 0x9048eae7e2b97a74ULL }, /* user_only_long_b L1 */
  { 0, 0, 2, 0x00, 0x9048eae7e2b97a74ULL }, /* user_only_long_b L2 */
  { 0, 0, 3, 0x00, 0x9048eae7e2b97a74ULL }, /* user_only_long_b L3 */
  { 0, -2, 0, 0x00, 0x0000000000000000ULL }, /* user_only_long_b L1salt */
  { 0, 0, 1, 0x00, 0xb00575498227f9c3ULL }, /* completions_prompt L1 */
  { 0, 0, 2, 0x00, 0xb00575498227f9c3ULL }, /* completions_prompt L2 */
  { 0, 0, 3, 0x00, 0xb00575498227f9c3ULL }, /* completions_prompt L3 */
  { 0, -2, 0, 0x00, 0x0000000000000000ULL }, /* completions_prompt L1salt */
  { 0, 0, 1, 0x01, 0xa68a701817aa7772ULL }, /* lora L1 */
  { 0, 0, 2, 0x01, 0xa68a701817aa7772ULL }, /* lora L2 */
  { 0, 0, 3, 0x01, 0xa68a701817aa7772ULL }, /* lora L3 */
  { 0, -2, 0, 0x00, 0x0000000000000000ULL }, /* lora L1salt */
  { 0, 0, 1, 0x08, 0x0552dfc1eebba5f4ULL }, /* cache_salt L1 */
  { 0, 0, 2, 0x08, 0x0552dfc1eebba5f4ULL }, /* cache_salt L2 */
  { 0, 0, 3, 0x08, 0x0552dfc1eebba5f4ULL }, /* cache_salt L3 */
  { 0, 0, 1, 0x08, 0x0552dfc1eebba5f4ULL }, /* cache_salt L1salt */
  { 0, 0, 1, 0x10, 0xf52314b48122a143ULL }, /* tools L1 */
  { 0, 0, 2, 0x10, 0xf52314b48122a143ULL }, /* tools L2 */
  { 0, 0, 3, 0x10, 0xf52314b48122a143ULL }, /* tools L3 */
  { 0, -2, 0, 0x00, 0x0000000000000000ULL }, /* tools L1salt */
  { 0, 0, 1, 0x02, 0x3be6788e0dfcb774ULL }, /* images L1 */
  { 0, 0, 2, 0x02, 0x3be6788e0dfcb774ULL }, /* images L2 */
  { 0, 0, 3, 0x02, 0x3be6788e0dfcb774ULL }, /* images L3 */
  { 0, -2, 0, 0x00, 0x0000000000000000ULL }, /* images L1salt */
  { 0, 0, 1, 0x00, 0x3ad87b45e8ca9cb0ULL }, /* session_context L1 */
  { 0, 0, 2, 0x20, 0x4014de9182434d37ULL }, /* session_context L2 */
  { 0, 0, 3, 0x20, 0x4014de9182434d37ULL }, /* session_context L3 */
  { 0, -2, 0, 0x00, 0x0000000000000000ULL }, /* session_context L1salt */
  { 0, 0, 1, 0x00, 0x3ad87b45e8ca9cb0ULL }, /* rag_context L1 */
  { 0, 0, 2, 0x00, 0x3ad87b45e8ca9cb0ULL }, /* rag_context L2 */
  { 0, 0, 3, 0xc0, 0x9730e7bc4d79564eULL }, /* rag_context L3 */
  { 0, -2, 0, 0x00, 0x0000000000000000ULL }, /* rag_context L1salt */
  { -1, -1, 0, 0x00, 0x0000000000000000ULL }, /* no_prefix L1 */
  { -1, -1, 0, 0x00, 0x0000000000000000ULL }, /* no_prefix L2 */
  { -1, -1, 0, 0x00, 0x0000000000000000ULL }, /* no_prefix L3 */
  { -1, -2, 0, 0x00, 0x0000000000000000ULL }, /* no_prefix L1salt */
};

int main(int argc, char **argv)
{
  int print = argc > 1 && strcmp(argv[1], "--print") == 0;
  int failures = 0;

  unsetenv("LLB_LLM_USER_PREFIX_FALLBACK_LEN");
  for (size_t c = 0; c < N_CORPUS; c++) {
    llm_prefix_key_t parsed;
    int erc = extract_llm_prefix(corpus[c].body, strlen(corpus[c].body), &parsed);
    for (size_t p = 0; p < N_POLICY; p++) {
      chwbl_config_t cfg = {0};
      llm_prefix_key_t key = parsed;
      row_t got = {0};
      cfg.prefix_hash_level = policies[p].level;
      cfg.prefix_hash_flags = policies[p].flags;
      cfg.enable_cache_salt = policies[p].require_salt;
      got.extract_rc = erc;
      got.policy_rc = chwbl_apply_hash_policy(&cfg, &key);
      if (got.policy_rc == 0) {
        got.level = key.level;
        got.flags = key.flags;
        got.hash = (unsigned long long)compute_prefix_hash(&key);
      }
      if (print) {
        printf("  { %d, %d, %d, 0x%02x, 0x%016llxULL }, /* %s %s */\n",
               got.extract_rc, got.policy_rc, got.level, got.flags, got.hash,
               corpus[c].name, policies[p].name);
        continue;
      }
      const row_t *want = &expected[c * N_POLICY + p];
      if (memcmp(&got, want, sizeof(got)) != 0) {
        fprintf(stderr, "FAIL %s %s: got {%d,%d,%d,0x%02x,0x%016llx} "
                "want {%d,%d,%d,0x%02x,0x%016llx}\n",
                corpus[c].name, policies[p].name,
                got.extract_rc, got.policy_rc, got.level, got.flags, got.hash,
                want->extract_rc, want->policy_rc, want->level, want->flags, want->hash);
        failures++;
      }
    }
  }
  if (print)
    return 0;
  printf("test_chwbl_prefix_hash: %zu cases, %d failures\n",
         N_CORPUS * N_POLICY, failures);
  return failures ? 1 : 0;
}
