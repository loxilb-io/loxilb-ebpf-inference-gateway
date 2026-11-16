/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_ai_gw_stub_proto.c - the record exports' prototypes, as the datapath
 * declares them and as its weak stubs define them (WP-D, design section 8).
 *
 * The C side calls the Go exports by name through sockproxy_ai_gw.h, and a
 * binary without the Go side binds to the weak stubs of
 * sockproxy_ai_gw_stub.c. This unit holds:
 *   - the three record exports end in one ai_corr_t * (D-10), and nothing
 *     else about them moved: each prototype is compared whole;
 *   - llb_ai_kv_best_worker takes plain uint32_t * (no const a Go export
 *     cannot spell; row 72 S0-1 (b));
 *   - the stubs compile against those prototypes (this file links them) and
 *     accept a correlation or NULL without touching it.
 *
 * Build: make test_ai_gw_stub_proto (ASan + UBSan).
 */
#include <stdio.h>
#include <string.h>

#include "sockproxy_ai_gw.h"

#define SAME(fn, type)                                                   \
  _Static_assert(__builtin_types_compatible_p(__typeof__(&fn), type),    \
                 #fn ": prototype differs")

SAME(llb_ai_record_request,
     void (*)(char *, char *, int, int64_t, int, int, int, int, char *,
              char *, char *, char *, char *, int, int, char *, char *,
              int, int, char *, int, int, char *, ai_corr_t *));
SAME(llb_ai_record_deny,
     void (*)(char *, int, char *, char *, char *, char *, char *, int, int,
              char *, char *, char *, int, int, char *, int, int, char *,
              ai_corr_t *));
SAME(llb_ai_token_quota_consume,
     int (*)(char *, char *, char *, char *, char *, int, int, int, int,
             int64_t, char *, int, int, char *, ai_gw_decision_t *,
             ai_corr_t *));
SAME(llb_ai_kv_best_worker,
     int (*)(uint8_t *, int, int, char *, uint32_t, uint32_t, uint32_t *,
             uint32_t *, uint32_t *, int, uint32_t, uint32_t, int *));

_Static_assert(sizeof(((ai_corr_t *)0)->trace_id) == 33 &&
               sizeof(((ai_corr_t *)0)->parent_span_id) == 17 &&
               sizeof(((ai_corr_t *)0)->session_id) == 129 &&
               sizeof(ai_corr_t) == 179,
               "ai_corr_t: each field whole with its NUL, no padding");

int
main(void)
{
  ai_corr_t corr, before;
  ai_gw_decision_t dec;
  uint32_t w[2] = { 1, 2 };
  int score = 0, fails = 0;

  memset(&corr, 0, sizeof(corr));
  snprintf(corr.trace_id, sizeof(corr.trace_id), "%s",
           "4bf92f3577b34da6a3ce929d0e0e4736");
  snprintf(corr.parent_span_id, sizeof(corr.parent_span_id), "%s",
           "00f067aa0ba902b7");
  snprintf(corr.session_id, sizeof(corr.session_id), "%s", "s1");
  before = corr;
  memset(&dec, 0, sizeof(dec));

  for (int pass = 0; pass < 2; pass++) {
    ai_corr_t *c = pass ? NULL : &corr;
    llb_ai_record_request("t", "m", 200, 1, 1, 1, 0, 0, "", "r", "", "", "",
                          0, -1, "", "", 0, 0, "", 0, 0, "", c);
    llb_ai_record_deny("r", -1, "", "m", "t", "", "", 1, 401, "e", "", "", 0,
                       0, "", 0, 0, "", c);
    if (llb_ai_token_quota_consume("t", "m", "", "", "", 1, 1, 0, 0, 0, "r",
                                   -1, 0, "", &dec, c) != 0) {
      printf("FAIL: the consume stub allows (0)\n");
      fails++;
    }
  }
  (void)llb_ai_kv_best_worker(NULL, 32, 0, "m", 0, 0, w, w, w, 2, 0, 0, &score);

  if (memcmp(&corr, &before, sizeof(corr)) != 0) {
    printf("FAIL: a stub wrote through the correlation\n");
    fails++;
  }
  if (fails)
    return 1;
  puts("record exports: prototypes as declared (trailing ai_corr_t *), "
       "kv_best_worker without const, stubs take a correlation or NULL PASS");
  return 0;
}
