/*
 * circuit_breaker_origin.h — origin-error demotion predicate.
 *
 * Pure, dependency-free transition shared VERBATIM by production
 * (sockproxy_health.c) and the unit test (test_cb_origin.c), the
 * circuit_breaker_heal.h idiom.
 *
 * The includer must already provide:
 *   - the `circuit_breaker_t` type with fields:
 *       state, origin_err_streak, origin_tripped
 *   - the enum values CB_STATE_CLOSED, CB_STATE_OPEN, CB_STATE_HALF_OPEN
 *
 * Why a separate streak: the breaker's failure_count is fed by CONNECT-level
 * faults and reset by every connect success. An endpoint that accepts TCP
 * but keeps answering HTTP 5xx therefore never accumulates failures — and
 * warm KV affinity keeps re-selecting it, so the erroring endpoint is pinned
 * indefinitely. origin_err_streak is touched only by origin response
 * statuses, so the connect-success reset cannot defeat it.
 */
#ifndef CIRCUIT_BREAKER_ORIGIN_H
#define CIRCUIT_BREAKER_ORIGIN_H

/*
 * Note one origin 5xx for this endpoint. Returns 1 when the breaker should
 * trip to OPEN now (the caller owns the trip actions, observability and
 * locking), 0 otherwise.
 *
 * threshold <= 0 disables the mechanism entirely (streak untouched).
 * CLOSED: increment the streak; trip when it reaches the threshold (streak
 *         resets so a later re-close starts a fresh count).
 * HALF_OPEN: trip immediately — a recovery probe drew another origin error.
 * OPEN: no-op (already tripped).
 */
static inline int
circuit_breaker_origin_note_error(circuit_breaker_t *cb, int threshold)
{
  if (!cb || threshold <= 0) {
    return 0;
  }
  switch (cb->state) {
  case CB_STATE_CLOSED:
    cb->origin_err_streak++;
    if (cb->origin_err_streak >= (uint32_t)threshold) {
      cb->origin_err_streak = 0;
      cb->origin_tripped = 1;
      return 1;
    }
    return 0;
  case CB_STATE_HALF_OPEN:
    cb->origin_err_streak = 0;
    cb->origin_tripped = 1;
    return 1;
  default:
    return 0;
  }
}

/* An origin-tripped breaker must NOT close on a connect success: the EP
 * accepts TCP fine — that is exactly why it tripped. Returns 1 when the
 * connect-success close must be withheld (the HALF_OPEN probe's ORIGIN
 * status decides instead, see note_success below). */
static inline int
circuit_breaker_origin_gates_connect_close(const circuit_breaker_t *cb)
{
  return cb && cb->origin_tripped;
}

/* Note an origin success (status < 400): the streak resets. Returns 1 when
 * the caller should CLOSE the breaker now — a HALF_OPEN probe on an
 * origin-tripped breaker drew a real origin success, which is the recovery
 * proof a connect success cannot provide. The caller owns the close actions
 * (state change, counter resets, clearing origin_tripped, observability),
 * mirroring the note_error trip contract. Connect-tripped breakers return 0:
 * their HALF_OPEN -> CLOSED recovery stays with the connect-success path. */
static inline int
circuit_breaker_origin_note_success(circuit_breaker_t *cb)
{
  if (!cb) {
    return 0;
  }
  cb->origin_err_streak = 0;
  return (cb->state == CB_STATE_HALF_OPEN && cb->origin_tripped) ? 1 : 0;
}

#endif /* CIRCUIT_BREAKER_ORIGIN_H */
