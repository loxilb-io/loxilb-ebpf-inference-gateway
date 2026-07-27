/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */
#define _GNU_SOURCE
#define HAVE_PROXY_EXTRA_DEBUG
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <fcntl.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <netdb.h>
#include <poll.h>
#include <bpf.h>
#include <ifaddrs.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <dirent.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <linux/tls.h>
#include <linux/tcp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "log.h"
#include "common_pdi.h"
#include "llb_dpapi.h"

/* strnstr_portable moved to sockproxy_http.c */
#include "notify.h"
#include "uthash.h"
#include "sockproxy.h"
#include "sockproxy_internal.h"
#include "sockproxy_metrics.h"
#include "sockproxy_routing.h"
#include "sockproxy_json.h"
#include "sockproxy_trace.h"
#include "sockproxy_cache.h"
#include "sockproxy_lb.h"
#include "sockproxy_health.h"
#include "sockproxy_ssl.h"
#include "sockproxy_conn.h"
#include "sockproxy_ep.h"
#include "sockproxy_http.h"
#include "sockproxy_ktls.h"
#include "sockproxy_h2.h"

#ifdef HAVE_MTLS
#include "sockproxy_mtls.h"
#endif

/* P/D extern decls, internal fwd decls (pd_initiate_decode, pd_update_content_length,
 * handle_on_message_complete), xxhash include — all moved to sockproxy_http.c */

/* HTTP trace includes, globals, forward decls moved to sockproxy_trace.c */

/* PII Detection: includes for presidio_config_reload/get/v2_init (used by proxy_notifier) */
#ifdef HAVE_PII_DETECTION
#include "presidio_config.h"
#include "sockproxy_presidio.h"
/* g_presidio_initialized, presidio_is_initialized/set defined in sockproxy_http.c */
#endif

/* LlamaFirewall: includes for llamafirewall_config_reload/get and init/cleanup */
#ifdef HAVE_LLAMAFIREWALL
#include "sockproxy_llamafirewall.h"
#include "llamafirewall_config.h"
/* g_llamafirewall_initialized, llamafirewall_is_initialized/set defined in sockproxy_http.c */
#endif

/* PROXY_SSL_FNAME_SZ, PROXY_SSL_CERT_DIR, PROXY_SSL_CA_DIR moved to sockproxy_ssl.h */
/* PROXY_CACHE_HIGH/LOW_WATER constants moved to sockproxy_cache.h */
/* PROXY_NUM_BURST_RX, PROXY_MAX_CACHE_ENTRIES/SIZE moved to sockproxy_http.c */
/* PROXY_SESSION_TIMEOUT, PROXY_SESSION_CLEANUP_INTERVAL moved to sockproxy_http.h */
/* CONVERSATION_MAPPING_TTL, CONVERSATION_CLEANUP_INTERVAL moved to sockproxy_ep.h */

proxy_struct_t *proxy_struct;

// ============================================================================
// HTTP/HTTPS TRACING: Runtime Control 
// ============================================================================
/* HTTP trace runtime control (lxb_trace_enable/disable/is_enabled, is_tracing_enabled) moved to sockproxy_trace.c */

// ============================================================================
// PRESIDIO STATUS QUERY API
// ============================================================================
#ifdef HAVE_PII_DETECTION
// CGO Export: Get Presidio initialization status (0=not initialized, 1=initialized)
// This can be called from Go for metrics/status reporting
int presidio_get_active_version(void) {
  return presidio_is_initialized();
}
#else
int presidio_get_active_version(void) {
  return 0;  // PII detection not compiled
}
#endif

// ============================================================================
// PROMETHEUS METRICS: Global Statistics (Phases 1-3)
// ============================================================================
/*
 * NOTE: global_stats definition moved to sockproxy_metrics.c.
 * proxy_set_service_catalog, proxy_get_metrics, record_latency_sample
 * all moved to sockproxy_metrics.c  -- see sockproxy_refactoring_plan.md §6.8.
 */

/* CHWBL/WRR_HASH forward declarations moved to sockproxy_lb.h */

/* Health/drain/CB forward declarations replaced by #include "sockproxy_health.h" */

/* proxy_notify_add_fd, proxy_notify_delete_fd, proxy_notifier, proxy_main
 * moved to sockproxy_notifier.c */
#include "sockproxy_notifier.h"
