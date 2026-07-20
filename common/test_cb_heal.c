/*
 * test_cb_heal.c — 93-02 (D1) proactive circuit-breaker recovery unit test.
 *
 * Asserts: an OPEN circuit breaker that has been open past open_timeout_sec
 * reaches HALF_OPEN and then CLOSED driven by the 1 Hz HEALTH PASS ALONE — i.e.
 * via circuit_breaker_proactive_heal() with NO intervening
 * circuit_breaker_should_skip()/selection call — and the endpoint is selectable
 * again afterward (the raw `state == CB_STATE_OPEN` skip the P/D path uses is false).
 *
 * Self-contained in the repo's test idiom: it defines a minimal circuit_breaker_t
 * matching the real layout (sockproxy.h:341) and the CB_STATE_* macros, then
 * includes circuit_breaker_heal.h so the function UNDER TEST is the literal
 * production transition (zero copy-paste). The surrounding existing transitions
 * (record_success closing from HALF_OPEN; record_failure re-opening) are modelled
 * locally to validate the end-to-end sequence — they mirror sockproxy_health.c
 * circuit_breaker_record_{success,failure} but are NOT the code being changed.
 */
#include <stdio.h>
#include <stdint.h>
#include <time.h>

/* ---- Minimal, layout-compatible CB types (mirror sockproxy.h) ---- */
#define CB_STATE_CLOSED    0
#define CB_STATE_OPEN      1
#define CB_STATE_HALF_OPEN 2

typedef struct circuit_breaker {
  int      state;
  uint32_t failure_count;
  uint32_t success_count;
  time_t   last_failure_ts;
  time_t   open_ts;
  uint32_t failure_threshold;
  uint32_t success_threshold;
  uint32_t open_timeout_sec;
  uint32_t half_open_max_requests;
  uint32_t half_open_requests;
} circuit_breaker_t;

/* The actual production transition under test. */
#include "circuit_breaker_heal.h"

/* ---- Local mirrors of the UNCHANGED existing transitions (for sequencing) ---- */
/* Mirrors sockproxy_health.c circuit_breaker_record_success() HALF_OPEN arm. */
static void model_record_success(circuit_breaker_t *cb) {
  if (cb->state == CB_STATE_HALF_OPEN) {
    cb->success_count++;
    if (cb->success_count >= cb->success_threshold) {
      cb->state = CB_STATE_CLOSED;
      cb->failure_count = 0;
    }
  } else if (cb->state == CB_STATE_CLOSED) {
    cb->failure_count = 0;
  }
}
/* Mirrors sockproxy_health.c circuit_breaker_record_failure() HALF_OPEN arm. */
static void model_record_failure(circuit_breaker_t *cb, time_t now) {
  if (cb->state == CB_STATE_HALF_OPEN) {
    cb->state = CB_STATE_OPEN;
    cb->open_ts = now;
    cb->failure_count = cb->failure_threshold;
  }
}
/* The exact predicate the P/D selection path uses to skip an EP (raw state read,
 * sockproxy_pd.c:934/1106/1121 etc.). selectable == !skip. */
static int pd_path_would_skip(const circuit_breaker_t *cb) {
  return cb->state == CB_STATE_OPEN;
}

static void cb_open(circuit_breaker_t *cb, time_t opened_at) {
  cb->state = CB_STATE_OPEN;
  cb->open_ts = opened_at;
  cb->open_timeout_sec = 30;
  cb->success_threshold = 1;
  cb->failure_threshold = 5;
  cb->half_open_max_requests = 3;
  cb->success_count = 0;
  cb->half_open_requests = 0;
}

/* ---- harness ---- */
static int tests_run = 0, tests_passed = 0;
#define ASSERT_EQ(a, b, msg) do { \
  if ((a) != (b)) { printf("  FAIL: %s (expected %d, got %d)\n", msg, (int)(b), (int)(a)); return 0; } } while(0)
#define ASSERT_TRUE(cond, msg) do { \
  if (!(cond)) { printf("  FAIL: %s\n", msg); return 0; } } while(0)
#define RUN_TEST(fn) do { \
  tests_run++; printf("  [%d] %s ... ", tests_run, #fn); \
  if (fn()) { tests_passed++; printf("PASS\n"); } else { printf("\n"); } } while(0)

/* CLOSED breaker: the health pass must not touch it. */
static int test_heal_noop_when_closed(void) {
  circuit_breaker_t cb = {0};
  cb.state = CB_STATE_CLOSED;
  int healed = circuit_breaker_proactive_heal(&cb, 1000);
  ASSERT_EQ(healed, 0, "closed breaker must not heal");
  ASSERT_EQ(cb.state, CB_STATE_CLOSED, "state unchanged");
  return 1;
}

/* OPEN but still within open_timeout_sec: must keep rejecting. */
static int test_heal_noop_within_timeout(void) {
  circuit_breaker_t cb;
  cb_open(&cb, 1000);
  int healed = circuit_breaker_proactive_heal(&cb, 1000 + 29);  /* 29s < 30s */
  ASSERT_EQ(healed, 0, "must not heal before open_timeout_sec");
  ASSERT_EQ(cb.state, CB_STATE_OPEN, "still OPEN within timeout");
  ASSERT_TRUE(pd_path_would_skip(&cb), "P/D path still skips it");
  return 1;
}

/* CORE: OPEN past timeout reaches HALF_OPEN driven by the health pass ALONE. */
static int test_heal_drives_half_open(void) {
  circuit_breaker_t cb;
  cb_open(&cb, 1000);
  cb.half_open_requests = 7; cb.success_count = 3;  /* stale, must reset */
  /* The ONLY call is the health-pass transition — no should_skip/selection. */
  int healed = circuit_breaker_proactive_heal(&cb, 1000 + 30);  /* exactly at timeout */
  ASSERT_EQ(healed, 1, "must heal at open_timeout_sec");
  ASSERT_EQ(cb.state, CB_STATE_HALF_OPEN, "OPEN->HALF_OPEN by health pass alone");
  ASSERT_EQ((int)cb.half_open_requests, 0, "half_open_requests reset");
  ASSERT_EQ((int)cb.success_count, 0, "success_count reset");
  ASSERT_TRUE(!pd_path_would_skip(&cb), "EP is selectable again (P/D no longer skips)");
  return 1;
}

/* Idempotent: a second health pass on HALF_OPEN does not re-transition. */
static int test_heal_idempotent_on_half_open(void) {
  circuit_breaker_t cb;
  cb_open(&cb, 1000);
  ASSERT_EQ(circuit_breaker_proactive_heal(&cb, 1100), 1, "first heal");
  int again = circuit_breaker_proactive_heal(&cb, 1200);
  ASSERT_EQ(again, 0, "no re-transition on HALF_OPEN");
  ASSERT_EQ(cb.state, CB_STATE_HALF_OPEN, "remains HALF_OPEN");
  return 1;
}

/* FULL SEQUENCE: OPEN -(health pass)-> HALF_OPEN -(relay success)-> CLOSED,
 * with NO should_skip/selection call to drive the OPEN->HALF_OPEN step. */
static int test_full_recovery_health_pass_then_success(void) {
  circuit_breaker_t cb;
  cb_open(&cb, 1000);
  ASSERT_TRUE(pd_path_would_skip(&cb), "starts dark (OPEN)");
  /* Step 1: health pass alone un-sticks it. */
  ASSERT_EQ(circuit_breaker_proactive_heal(&cb, 1031), 1, "health pass heals");
  ASSERT_EQ(cb.state, CB_STATE_HALF_OPEN, "HALF_OPEN");
  /* Step 2: now selectable, a genuine relay success closes it. */
  model_record_success(&cb);
  ASSERT_EQ(cb.state, CB_STATE_CLOSED, "HALF_OPEN->CLOSED on relay success");
  ASSERT_TRUE(!pd_path_would_skip(&cb), "fully back in rotation");
  return 1;
}

/* Guardrail: an up-but-failing EP re-opens cleanly (no oscillation hazard). */
static int test_half_open_failure_reopens(void) {
  circuit_breaker_t cb;
  cb_open(&cb, 1000);
  ASSERT_EQ(circuit_breaker_proactive_heal(&cb, 1031), 1, "health pass heals");
  model_record_failure(&cb, 1031);
  ASSERT_EQ(cb.state, CB_STATE_OPEN, "HALF_OPEN->OPEN on probe failure");
  /* And it will heal again only after another full open_timeout_sec. */
  ASSERT_EQ(circuit_breaker_proactive_heal(&cb, 1031 + 29), 0, "no premature re-heal");
  ASSERT_EQ(circuit_breaker_proactive_heal(&cb, 1031 + 30), 1, "re-heals after timeout");
  return 1;
}

int main(void) {
  printf("=== 93-02 proactive circuit-breaker recovery (health-pass self-heal) ===\n");
  RUN_TEST(test_heal_noop_when_closed);
  RUN_TEST(test_heal_noop_within_timeout);
  RUN_TEST(test_heal_drives_half_open);
  RUN_TEST(test_heal_idempotent_on_half_open);
  RUN_TEST(test_full_recovery_health_pass_then_success);
  RUN_TEST(test_half_open_failure_reopens);
  printf("=== %d/%d passed ===\n", tests_passed, tests_run);
  return (tests_passed == tests_run) ? 0 : 1;
}
