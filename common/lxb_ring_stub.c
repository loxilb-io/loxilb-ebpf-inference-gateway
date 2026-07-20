/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 *
 * Stub implementations for lxb_ring functions when HAVE_HTTP_TRACE is disabled.
 * Provides no-op versions to satisfy linker requirements.
 */
#include "lxb_ring.h"
#include "log.h"

// Stub implementation when HTTP tracing is disabled
int lxb_ring_init(int num_workers) {
  (void)num_workers;  // Unused
  log_debug("[LXB_RING_STUB] HTTP tracing disabled, ring init skipped\n");
  return 0;  // Success (no-op)
}

int lxb_ring_is_initialized(void) {
  return 0;  // Not initialized (tracing disabled)
}

void lxb_ring_cleanup(void) {
  // No-op: nothing to cleanup when tracing is disabled
  log_debug("[LXB_RING_STUB] HTTP tracing disabled, ring cleanup skipped\n");
}

lxb_ring_t* lxb_ring_get(void) {
  return NULL;  // No ring buffer when tracing is disabled
}

void lxb_ring_set_worker_id(int worker_id) {
  (void)worker_id;  // Unused
  // No-op: worker ID not needed when tracing is disabled
}

uint64_t lxb_gen_trace_id_part(void) {
  return 0;  // Not used when tracing is disabled
}

uint64_t lxb_gen_span_id(void) {
  return 0;  // Not used when tracing is disabled
}

void lxb_gen_trace_id(uint64_t *hi, uint64_t *lo) {
  if (hi) *hi = 0;
  if (lo) *lo = 0;
  // Not used when tracing is disabled
}
