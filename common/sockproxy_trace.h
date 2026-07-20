/*
 * Copyright (c) 2022 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __SOCKPROXY_TRACE_H__
#define __SOCKPROXY_TRACE_H__

#include "sockproxy.h"

/* CGO exports — always present (stubs when HAVE_HTTP_TRACE is not set) */
int lxb_trace_enable(void);
int lxb_trace_disable(void);
int lxb_trace_is_enabled(void);

#ifdef HAVE_HTTP_TRACE

#define TRACE_FILE_TTL_SEC 300  /* 5 minutes */

/* Is HTTP tracing currently active? Zero-overhead check via atomic read. */
int is_tracing_enabled(void);

/* Monotonic nanosecond clock (clock_gettime CLOCK_MONOTONIC_RAW) */
uint64_t get_timestamp_ns(void);

/* Emit a trace event into the per-thread ring buffer */
void emit_trace_event(proxy_fd_ent_t *pfe, uint8_t event_type,
                      uint32_t duration_us);

/* Look up catalog ID for a VIP (IP + port + protocol).
 * Returns 0 if no catalog is configured for this endpoint. */
uint16_t lxb_lookup_service_catalog(uint32_t xip, uint16_t xport,
                                     uint8_t protocol);

/* Cleanup thread for /dev/shm trace files — started by proxy notifier */
void *trace_file_cleanup_thread(void *arg);

#endif /* HAVE_HTTP_TRACE */

#endif /* __SOCKPROXY_TRACE_H__ */
