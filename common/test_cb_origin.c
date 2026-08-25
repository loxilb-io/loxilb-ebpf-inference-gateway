/*
 * test_cb_origin.c — origin-error demotion unit test.
 *
 * Asserts: an endpoint that keeps answering origin 5xx trips its breaker
 * after the configured streak even though every CONNECT succeeds (the
 * connect-success reset that defeats failure_count cannot defeat the origin
 * streak), an origin success resets the streak, a HALF_OPEN probe that draws
 * another origin error re-trips immediately, and threshold 0 disables the
 * mechanism. Recovery coupling: an origin-tripped breaker withholds the
 * HALF_OPEN connect-success close (the EP accepts TCP fine — that is why it
 * tripped) and closes only on an origin success; a connect-tripped breaker
 * keeps the connect-success close.
 *
 * Self-contained in the repo's test idiom (test_cb_heal.c): it defines a
 * minimal circuit_breaker_t matching the real layout and the CB_STATE_*
 * macros, then includes circuit_breaker_origin.h so the predicate UNDER TEST
 * is the literal production transition (zero copy-paste). The connect-success
 * reset is modelled locally to prove the defeat scenario — it mirrors
 * sockproxy_health.c circuit_breaker_record_success() but is NOT the code
 * being changed.
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
  uint32_t origin_err_streak;
  uint8_t  origin_tripped;
} circuit_breaker_t;

/* The actual production transition under test. */
#include "circuit_breaker_origin.h"

/* Mirrors sockproxy_health.c circuit_breaker_record_success() — the
 * connect-level reset that makes failure_count blind to origin 5xx, and
 * the HALF_OPEN close that the origin gate must withhold. */
static void model_connect_success(circuit_breaker_t *cb) {
  if (cb->state == CB_STATE_CLOSED) {
    cb->failure_count = 0;
  } else if (cb->state == CB_STATE_HALF_OPEN) {
    if (circuit_breaker_origin_gates_connect_close(cb)) {
      return;
    }
    cb->success_count++;
    if (cb->success_count >= cb->success_threshold) {
      cb->state = CB_STATE_CLOSED;
      cb->failure_count = 0;
    }
  }
}

/* Mirrors sockproxy_health.c circuit_breaker_record_origin_success() close
 * actions (the caller-owned side of note_success returning 1). */
static void model_origin_success(circuit_breaker_t *cb) {
  if (circuit_breaker_origin_note_success(cb)) {
    cb->state = CB_STATE_CLOSED;
    cb->failure_count = 0;
    cb->success_count = 0;
    cb->origin_tripped = 0;
  }
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

/* CORE: consecutive origin 5xx trip at the threshold even though every
 * request's connect success resets failure_count in between. */
static int test_streak_trips_despite_connect_success(void) {
  circuit_breaker_t cb = {0};
  int i, trip = 0;
  cb.state = CB_STATE_CLOSED;
  for (i = 0; i < 3; i++) {
    model_connect_success(&cb);            /* the per-request connect reset */
    trip = circuit_breaker_origin_note_error(&cb, 3);
    if (i < 2) {
      ASSERT_EQ(trip, 0, "no trip below the threshold");
    }
  }
  ASSERT_EQ(trip, 1, "third consecutive origin 5xx trips");
  ASSERT_EQ((int)cb.failure_count, 0, "connect counter stayed blind (the defeat)");
  ASSERT_EQ((int)cb.origin_err_streak, 0, "streak resets on trip");
  return 1;
}

/* An origin success anywhere in the run resets the streak. */
static int test_origin_success_resets_streak(void) {
  circuit_breaker_t cb = {0};
  cb.state = CB_STATE_CLOSED;
  ASSERT_EQ(circuit_breaker_origin_note_error(&cb, 3), 0, "err 1");
  ASSERT_EQ(circuit_breaker_origin_note_error(&cb, 3), 0, "err 2");
  circuit_breaker_origin_note_success(&cb);
  ASSERT_EQ((int)cb.origin_err_streak, 0, "streak cleared by origin success");
  ASSERT_EQ(circuit_breaker_origin_note_error(&cb, 3), 0, "err restarts at 1");
  ASSERT_EQ(circuit_breaker_origin_note_error(&cb, 3), 0, "err 2 again");
  ASSERT_EQ(circuit_breaker_origin_note_error(&cb, 3), 1, "fresh streak of 3 trips");
  return 1;
}

/* A HALF_OPEN recovery probe that draws another origin error re-trips
 * immediately — no fresh streak required. */
static int test_half_open_error_retrips_immediately(void) {
  circuit_breaker_t cb = {0};
  cb.state = CB_STATE_HALF_OPEN;
  ASSERT_EQ(circuit_breaker_origin_note_error(&cb, 3), 1, "HALF_OPEN retrip on first error");
  ASSERT_EQ((int)cb.origin_err_streak, 0, "streak reset on retrip");
  return 1;
}

/* Already OPEN: further origin errors are a no-op (no double trip). */
static int test_open_is_noop(void) {
  circuit_breaker_t cb = {0};
  cb.state = CB_STATE_OPEN;
  ASSERT_EQ(circuit_breaker_origin_note_error(&cb, 3), 0, "no trip while OPEN");
  ASSERT_EQ((int)cb.origin_err_streak, 0, "streak untouched while OPEN");
  return 1;
}

/* Threshold 0 disables the mechanism completely. */
static int test_threshold_zero_disables(void) {
  circuit_breaker_t cb = {0};
  int i;
  cb.state = CB_STATE_CLOSED;
  for (i = 0; i < 100; i++) {
    ASSERT_EQ(circuit_breaker_origin_note_error(&cb, 0), 0, "disabled never trips");
  }
  ASSERT_EQ((int)cb.origin_err_streak, 0, "disabled leaves the streak untouched");
  cb.state = CB_STATE_HALF_OPEN;
  ASSERT_EQ(circuit_breaker_origin_note_error(&cb, 0), 0, "disabled in HALF_OPEN too");
  return 1;
}

/* Threshold 1: every origin 5xx trips (the most aggressive setting). */
static int test_threshold_one(void) {
  circuit_breaker_t cb = {0};
  cb.state = CB_STATE_CLOSED;
  ASSERT_EQ(circuit_breaker_origin_note_error(&cb, 1), 1, "threshold 1 trips instantly");
  return 1;
}

/* CORE (recovery): an origin-tripped breaker in HALF_OPEN ignores the
 * probe's connect success (the flap defect: TCP always succeeds on these
 * EPs, so the old close re-admitted a still-broken EP every heal cycle)
 * and closes only on the probe's origin success. */
static int test_origin_trip_closes_on_origin_success_only(void) {
  circuit_breaker_t cb = {0};
  int i;
  cb.state = CB_STATE_CLOSED;
  cb.success_threshold = 1;
  for (i = 0; i < 3; i++) {
    (void)circuit_breaker_origin_note_error(&cb, 3);
  }
  ASSERT_EQ((int)cb.origin_tripped, 1, "trip marks origin_tripped");
  cb.state = CB_STATE_HALF_OPEN;             /* heal timeout elapsed */
  model_connect_success(&cb);                /* probe's TCP connect */
  ASSERT_EQ(cb.state, CB_STATE_HALF_OPEN, "connect success withheld from closing");
  model_origin_success(&cb);                 /* probe answered < 400 */
  ASSERT_EQ(cb.state, CB_STATE_CLOSED, "origin success closes");
  ASSERT_EQ((int)cb.origin_tripped, 0, "flag cleared on close");
  model_connect_success(&cb);                /* back to normal semantics */
  ASSERT_EQ(cb.state, CB_STATE_CLOSED, "post-recovery CLOSED behavior intact");
  return 1;
}

/* A connect-tripped breaker (origin_tripped=0) keeps the legacy
 * connect-success close — the gate must not leak into that path. */
static int test_connect_trip_keeps_connect_close(void) {
  circuit_breaker_t cb = {0};
  cb.state = CB_STATE_HALF_OPEN;             /* opened by connect faults */
  cb.success_threshold = 1;
  ASSERT_EQ((int)cb.origin_tripped, 0, "precondition: connect trip");
  model_connect_success(&cb);
  ASSERT_EQ(cb.state, CB_STATE_CLOSED, "connect-tripped closes on connect success");
  return 1;
}

/* An origin success on a CLOSED or connect-tripped breaker never asks for a
 * close (note_success returns 1 only for origin-tripped HALF_OPEN). */
static int test_origin_success_no_spurious_close_request(void) {
  circuit_breaker_t cb = {0};
  cb.state = CB_STATE_CLOSED;
  ASSERT_EQ(circuit_breaker_origin_note_success(&cb), 0, "CLOSED: no close request");
  cb.state = CB_STATE_HALF_OPEN;
  cb.origin_tripped = 0;
  ASSERT_EQ(circuit_breaker_origin_note_success(&cb), 0, "connect-tripped HALF_OPEN: no close request");
  return 1;
}

/* HALF_OPEN origin error re-trips AND stays origin-tripped, so the next
 * cycle still demands an origin success. */
static int test_retrip_keeps_origin_gate(void) {
  circuit_breaker_t cb = {0};
  cb.state = CB_STATE_HALF_OPEN;
  cb.origin_tripped = 1;
  ASSERT_EQ(circuit_breaker_origin_note_error(&cb, 3), 1, "HALF_OPEN origin error re-trips");
  ASSERT_EQ((int)cb.origin_tripped, 1, "gate persists across re-trip");
  return 1;
}

int main(void) {
  printf("=== origin-error demotion (streak immune to connect-success reset) ===\n");
  RUN_TEST(test_streak_trips_despite_connect_success);
  RUN_TEST(test_origin_success_resets_streak);
  RUN_TEST(test_half_open_error_retrips_immediately);
  RUN_TEST(test_open_is_noop);
  RUN_TEST(test_threshold_zero_disables);
  RUN_TEST(test_threshold_one);
  RUN_TEST(test_origin_trip_closes_on_origin_success_only);
  RUN_TEST(test_connect_trip_keeps_connect_close);
  RUN_TEST(test_origin_success_no_spurious_close_request);
  RUN_TEST(test_retrip_keeps_origin_gate);
  printf("=== %d/%d passed ===\n", tests_passed, tests_run);
  return (tests_passed == tests_run) ? 0 : 1;
}
