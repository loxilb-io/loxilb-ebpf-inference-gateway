/*
 * circuit_breaker_heal.h — 93-02 (D1) proactive circuit-breaker recovery predicate.
 *
 * Pure, dependency-free transition shared VERBATIM by production
 * (sockproxy_health.c, the 1 Hz health pass) and the unit test (test_cb_heal.c),
 * so the test exercises the literal production logic with zero copy-paste.
 *
 * The includer must already provide:
 *   - the `circuit_breaker_t` type with fields:
 *       state, open_ts, open_timeout_sec, half_open_requests, success_count
 *   - the macros/enum CB_STATE_OPEN and CB_STATE_HALF_OPEN
 *   - <time.h> (for time_t)
 *
 * Rationale (full stuck-state map in 93-CONTEXT.md / T1): the P/D selection path
 * reads circuit_breakers[].state RAW (== CB_STATE_OPEN -> skip) and never calls
 * circuit_breaker_should_skip(), so the OPEN->HALF_OPEN timeout transition never
 * runs for prefill EPs -> a restarted EP stays dark forever. This predicate drives
 * that transition from the health thread (off the relay/teardown path) so the EP
 * re-enters rotation without waiting for organic traffic; the next genuine relay
 * success closes the breaker. It is intentionally PURE — no counter bumps, no
 * logging, no I/O — so the caller owns observability and the test owns nothing else.
 */
#ifndef CIRCUIT_BREAKER_HEAL_H
#define CIRCUIT_BREAKER_HEAL_H

/*
 * Drive a single OPEN->HALF_OPEN proactive transition if the breaker has been
 * OPEN for at least open_timeout_sec. Mirrors the transition in
 * circuit_breaker_should_skip() exactly (state=HALF_OPEN, counters reset).
 *
 * Returns 1 if it transitioned this call, 0 otherwise (not OPEN, or still within
 * the timeout, or cb==NULL). The caller increments observability counters and logs
 * ONLY when this returns 1.
 */
static inline int
circuit_breaker_proactive_heal(circuit_breaker_t *cb, time_t now)
{
  if (!cb || cb->state != CB_STATE_OPEN) {
    return 0;
  }
  if ((now - cb->open_ts) < (time_t)cb->open_timeout_sec) {
    return 0;  /* still within the open timeout — keep rejecting */
  }
  cb->state = CB_STATE_HALF_OPEN;
  cb->half_open_requests = 0;
  cb->success_count = 0;
  return 1;
}

#endif /* CIRCUIT_BREAKER_HEAL_H */
