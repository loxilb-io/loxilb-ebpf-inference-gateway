# SPDX-License-Identifier: (GPL-2.0)
CC := gcc

# HTTP/HTTPS Tracing Support (Phase 2: Protocol Analyzer)
# Enable with: make HAVE_HTTP_TRACE=1
ifdef HAVE_HTTP_TRACE
TRACE_OBJS := lxb_ring.o
CFLAGS_TRACE := -DHAVE_HTTP_TRACE=1
else
TRACE_OBJS := lxb_ring_stub.o
CFLAGS_TRACE :=
endif

# PII Detection Support (Presidio Integration)
# Enable with: make HAVE_PII_DETECTION=1
# Note: Stub is NOT included here - it's added separately for C-only builds
ifdef HAVE_PII_DETECTION
PII_OBJS := presidio_config.o sockproxy_presidio.o
CFLAGS_PII := -DHAVE_PII_DETECTION=1
else
PII_OBJS :=
CFLAGS_PII :=
endif

# mTLS Support (Mutual TLS Authentication)
# Enable with: make HAVE_MTLS=1
ifdef HAVE_MTLS
MTLS_OBJS := sockproxy_mtls.o
CFLAGS_MTLS := -DHAVE_MTLS=1
else
MTLS_OBJS :=
CFLAGS_MTLS :=
endif

all: common_libbpf.o common_pdi.o common_sum.o common_frame.o log.o throttler.o cgroup.o sockproxy.o sockproxy_metrics.o sockproxy_routing.o sockproxy_json.o sockproxy_trace.o sockproxy_cache.o sockproxy_lb.o sockproxy_health.o sockproxy_ssl.o sockproxy_conn.o sockproxy_ep.o sockproxy_http.o sockproxy_notifier.o sockproxy_ktls.o sockproxy_h2.o notify.o picohttpparser.o llhttp.o httpapi.o http.o xxhash.o sockproxy_pd.o sockproxy_pd_core.o sockproxy_pd_vllm.o sockproxy_pd_sglang.o sockproxy_pd_trtllm.o sockproxy_pd_trie.o sockproxy_kv_exact.o sockproxy_sync.o sockproxy_l7policy.o $(TRACE_OBJS) $(PII_OBJS) $(MTLS_OBJS)

CFLAGS := -g -Wall -I../libbpf/src/ -DHAVE_DP_GPU_ROUTING=1 -DHAVE_LLM_SYSTEM_PROMPT_HASH=1 $(CFLAGS_TRACE) $(CFLAGS_PII) $(CFLAGS_MTLS)
# Phase 90 diag: opt-in AddressSanitizer hook for the full-binary conc=128 heap-
# overflow hunt. Empty by default (zero effect on normal/CI builds); set
# ASAN_CFLAGS='-fsanitize=address -fno-omit-frame-pointer' to instrument the
# sockproxy orchestration .o's. The Go link must also pass -asan + libasan.
CFLAGS += $(ASAN_CFLAGS)
LDFLAGS += -lnghttp2

LIBBPF_DIR = ../libbpf/src/
CFLAGS += -I$(LIBBPF_DIR)/build/usr/include/  -I../headers

# Phase 93-06 build-hygiene: automatic header-dependency tracking.
# The per-object prerequisite lists below are hand-maintained and were INCOMPLETE
# — e.g. the objects that touch proxy_global_stats_t / global_stats (declared in
# sockproxy.h, pulled in via sockproxy_internal.h: sockproxy_conn/ep/http/health/pd)
# did NOT list sockproxy.h. So an incremental build after a struct-layout change
# (db24869c added 2 mid-struct fields to proxy_global_stats_t) left those .o's stale
# at the OLD field offsets, linked against freshly-compiled TUs → cross-TU ABI skew
# → memory corruption → worker SEGV (the p93d3 crash; see
# claudedocs/PHASE-93-06-CRASH-RCA-RESULTS.md). -MMD makes gcc emit a .d capturing
# EVERY project header each TU actually pulls in; the `-include` at the bottom feeds
# them back so any header change forces the correct recompiles. This eliminates the
# stale-object class at its source (strictly better than the hand-maintained lists,
# which are kept only as a first-build backstop before any .d exists).
DEPFLAGS := -MMD -MP
CFLAGS += $(DEPFLAGS)

common_libbpf.o: common_libbpf.c common_libbpf.h
	$(CC) $(CFLAGS) -c -o $@ $<

common_pdi.o: common_pdi.c common_pdi.h
	$(CC) $(CFLAGS) -c -o $@ $<

common_sum.o: common_sum.c common_sum.h
	$(CC) $(CFLAGS) -c -o $@ $<

common_frame.o: common_frame.c common_frame.h
	$(CC) $(CFLAGS) -c -o $@ $<

log.o: log.c log.h
	$(CC) $(CFLAGS) -c -o $@ $<

throttler.o: throttler.c throttler.h
	$(CC) $(CFLAGS) -c -o $@ $<

cgroup.o: cgroup.c cgroup.h
	$(CC) $(CFLAGS) -c -o $@ $<

sockproxy.o: sockproxy.c sockproxy.h sockproxy_internal.h sockproxy_metrics.h sockproxy_routing.h sockproxy_json.h sockproxy_trace.h sockproxy_cache.h sockproxy_lb.h sockproxy_health.h sockproxy_ssl.h sockproxy_conn.h sockproxy_ep.h sockproxy_http.h
	$(CC) $(CFLAGS) -c -o $@ $<

sockproxy_metrics.o: sockproxy_metrics.c sockproxy_metrics.h sockproxy_internal.h
	$(CC) $(CFLAGS) -c -o $@ $<

sockproxy_routing.o: sockproxy_routing.c sockproxy_routing.h sockproxy_internal.h
	$(CC) $(CFLAGS) -c -o $@ $<

sockproxy_routing_stub.o: sockproxy_routing_stub.c sockproxy_routing.h
	$(CC) $(CFLAGS) -c -o $@ $<

sockproxy_json.o: sockproxy_json.c sockproxy_json.h sockproxy_internal.h
	$(CC) $(CFLAGS) -c -o $@ $<

sockproxy_json_stub.o: sockproxy_json_stub.c sockproxy_json.h
	$(CC) $(CFLAGS) -c -o $@ $<

sockproxy_trace.o: sockproxy_trace.c sockproxy_trace.h sockproxy_internal.h
	$(CC) $(CFLAGS) -c -o $@ $<

sockproxy_cache.o: sockproxy_cache.c sockproxy_cache.h sockproxy_internal.h
	$(CC) $(CFLAGS) -c -o $@ $<

sockproxy_lb.o: sockproxy_lb.c sockproxy_lb.h sockproxy_internal.h sockproxy_json.h
	$(CC) $(CFLAGS) -c -o $@ $<

sockproxy_health.o: sockproxy_health.c sockproxy_health.h sockproxy_internal.h
	$(CC) $(CFLAGS) -c -o $@ $<

sockproxy_ssl.o: sockproxy_ssl.c sockproxy_ssl.h sockproxy_internal.h
	$(CC) $(CFLAGS) -c -o $@ $<

sockproxy_conn.o: sockproxy_conn.c sockproxy_conn.h sockproxy_internal.h sockproxy_ssl.h sockproxy_cache.h
	$(CC) $(CFLAGS) -c -o $@ $<

sockproxy_ep.o: sockproxy_ep.c sockproxy_ep.h sockproxy_internal.h \
                sockproxy_cache.h sockproxy_conn.h sockproxy_routing.h \
                sockproxy_lb.h sockproxy_health.h
	$(CC) $(CFLAGS) -c -o $@ $<

sockproxy_http.o: sockproxy_http.c sockproxy_http.h sockproxy_internal.h \
                  sockproxy_metrics.h sockproxy_routing.h sockproxy_json.h \
                  sockproxy_trace.h sockproxy_cache.h sockproxy_lb.h \
                  sockproxy_health.h sockproxy_ssl.h sockproxy_conn.h \
                  sockproxy_ep.h sockproxy_ktls.h sockproxy_h2.h sockproxy_pd.h
	$(CC) $(CFLAGS) $(CFLAGS_TRACE) $(CFLAGS_PII) $(CFLAGS_LLAMAFIREWALL) -c -o $@ $<

sockproxy_notifier.o: sockproxy_notifier.c sockproxy_notifier.h sockproxy_internal.h \
                      sockproxy_metrics.h sockproxy_cache.h sockproxy_conn.h \
                      sockproxy_ep.h sockproxy_routing.h sockproxy_lb.h \
                      sockproxy_health.h sockproxy_ssl.h sockproxy_trace.h \
                      sockproxy_json.h sockproxy_ktls.h sockproxy_h2.h sockproxy_http.h
	$(CC) $(CFLAGS) $(CFLAGS_TRACE) $(CFLAGS_PII) $(CFLAGS_LLAMAFIREWALL) -c -o $@ $<

sockproxy_ktls.o: sockproxy_ktls.c sockproxy_ktls.h
	$(CC) $(CFLAGS) -c -o $@ $<

sockproxy_h2.o: sockproxy_h2.c sockproxy_h2.h
	$(CC) $(CFLAGS) -c -o $@ $<

notify.o: notify.c notify.h
	$(CC) $(CFLAGS) -c -o $@ $<

picohttpparser.o: picohttpparser.c picohttpparser.h
	$(CC) $(CFLAGS) -c -o $@ $<

llhttp.o: llhttp.c llhttp.h
	$(CC) $(CFLAGS) -c -o $@ $<

httpapi.o: httpapi.c
	$(CC) $(CFLAGS) -c -o $@ $<

http.o: http.c
	$(CC) $(CFLAGS) -c -o $@ $<

xxhash.o: xxhash.c xxhash.h
	$(CC) $(CFLAGS) -c -o $@ $<

sockproxy_pd.o: sockproxy_pd.c
	$(CC) $(CFLAGS) -c -o $@ $<

# P/D engine-dialect core (ops-table resolution; machine-agnostic glue)
sockproxy_pd_core.o: sockproxy_pd_core.c sockproxy_pd.h sockproxy.h
	$(CC) $(CFLAGS) -c -o $@ $<

# P/D vLLM sequential dialect machine
sockproxy_pd_vllm.o: sockproxy_pd_vllm.c sockproxy_pd.h sockproxy.h \
                     sockproxy_internal.h sockproxy_ai_gw.h
	$(CC) $(CFLAGS) -c -o $@ $<

# P/D SGLang dual-dispatch dialect machine
sockproxy_pd_sglang.o: sockproxy_pd_sglang.c sockproxy_pd.h sockproxy.h \
                       sockproxy_internal.h sockproxy_ai_gw.h
	$(CC) $(CFLAGS) -c -o $@ $<

# P/D TRT-LLM sequential dialect (rides the vLLM machine)
sockproxy_pd_trtllm.o: sockproxy_pd_trtllm.c sockproxy_pd.h sockproxy.h \
                       sockproxy_internal.h sockproxy_ai_gw.h
	$(CC) $(CFLAGS) -c -o $@ $<

sockproxy_pd_trie.o: sockproxy_pd_trie.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Phase 70 — sockproxy HA state sync receiver
sockproxy_sync.o: sockproxy_sync.c sockproxy.h sockproxy_internal.h
	$(CC) $(CFLAGS) -c -o $@ $<

# Phase 75 — L7 content-routing policy engine (Plan 01: compiling stub TU)
# Phase 76-07 (FR-10): also depends on sockproxy_cookie.h (stateless cookie token
# primitives). HMAC/CRYPTO_memcmp resolve at the final loxilb/CGO link (-lcrypto,
# already pulled by sockproxy_conn.o / sockproxy_h2.o / sockproxy_ktls.o).
sockproxy_l7policy.o: sockproxy_l7policy.c sockproxy_l7policy.h sockproxy_cookie.h sockproxy.h sockproxy_internal.h
	$(CC) $(CFLAGS) -c -o $@ $<

# HTTP/HTTPS Tracing ring buffer (conditional)
lxb_ring.o: lxb_ring.c lxb_ring.h lxb_trace_event.h lxb_traceparent.h
	$(CC) $(CFLAGS) -c -o $@ $<

# Stub implementation when HTTP tracing is disabled
lxb_ring_stub.o: lxb_ring_stub.c lxb_ring.h
	$(CC) $(CFLAGS) -c -o $@ $<

# PII Detection configuration (conditional)
presidio_config.o: presidio_config.c presidio_config.h
	$(CC) $(CFLAGS) -c -o $@ $<

# PII Detection integration (conditional)
sockproxy_presidio.o: sockproxy_presidio.c sockproxy_presidio.h presidio_config.h
	$(CC) $(CFLAGS) -c -o $@ $<

# PII Detection stub for C-only builds (conditional)
sockproxy_presidio_stub.o: sockproxy_presidio_stub.c
	$(CC) $(CFLAGS) -c -o $@ $<

# PII Detection enhanced stub for C-only builds (conditional)
sockproxy_presidio_enhanced_stub.o: sockproxy_presidio_enhanced_stub.c
	$(CC) $(CFLAGS) -c -o $@ $<

# LlamaFirewall configuration (conditional)
llamafirewall_config.o: llamafirewall_config.c llamafirewall_config.h
	$(CC) $(CFLAGS) -c -o $@ $<

# LlamaFirewall proxy integration (conditional)
sockproxy_llamafirewall.o: sockproxy_llamafirewall.c sockproxy_llamafirewall.h llamafirewall_config.h
	$(CC) $(CFLAGS) -c -o $@ $<

# LlamaFirewall stub for C-only builds (conditional)
sockproxy_llamafirewall_stub.o: sockproxy_llamafirewall_stub.c sockproxy_llamafirewall.h
	$(CC) $(CFLAGS) -c -o $@ $<

# AI Gateway CGO stub for C-only builds (always needed)
sockproxy_ai_gw_stub.o: sockproxy_ai_gw_stub.c sockproxy_ai_gw.h
	$(CC) $(CFLAGS) -c -o $@ $<
# mTLS implementation (conditional)
sockproxy_mtls.o: sockproxy_mtls.c sockproxy_mtls.h sockproxy.h
	$(CC) $(CFLAGS) -c -o $@ $<

llhttp.a: llhttp.o llhttpapi.o http.o
	$(AR) rcs -c $@ $^

# US-501: Request-ID generation and injection unit tests (standalone)
test_request_id: test_request_id.c
	$(CC) -Wall -Wextra -o $@ $< -I. -DTEST_REQUEST_ID

.PHONY: test_rid
test_rid: test_request_id
	./test_request_id

# US-503/US-504/US-510: P/D body rewriting and worker selection unit tests (standalone)
# -fsanitize=address detects buffer overflows and use-after-free in JSON rewriting
test_pd_rewriter: test_pd_rewriter.c sockproxy_pd.c
	$(CC) -Wall -Wextra -fsanitize=address -o $@ $< -I. -DTEST_PD_REWRITER

# Phase 76-03 (FR-08/FR-10): non-terminal H2 response-header injector proof.
# Links the REAL shipped proxy_h2_inject_resp_headers() out of sockproxy_h2.c
# (no copy, no drift) and proves, against a real in-process nghttp2 server
# session, that the emitted HEADERS frame does NOT set END_STREAM, the injected
# nv is present, and the per-stream DATA provider stays attached. The injector
# is self-contained (malloc/realloc/memcpy/free + nghttp2 types only), so the
# test TU + sockproxy_h2.o link with just -lnghttp2 and the openssl/pthread libs
# sockproxy_h2.o transitively needs. --gc-sections drops the unreferenced rest
# of sockproxy_h2.o so no other production symbol must be resolved.
test_h2_inject: test_h2_inject_obj sockproxy_h2_gc.o
	$(CC) -Wall -Wextra -o $@ test_h2_inject.o sockproxy_h2_gc.o \
		-Wl,--gc-sections -lnghttp2 -lssl -lcrypto -lpthread

test_h2_inject_obj: sockproxy_h2_inject_test.c sockproxy_h2.h
	$(CC) -Wall -Wextra $(CFLAGS) -ffunction-sections -fdata-sections \
		-c -o test_h2_inject.o sockproxy_h2_inject_test.c

# A --gc-sections-friendly build of sockproxy_h2.o for the inject test link.
sockproxy_h2_gc.o: sockproxy_h2.c sockproxy_h2.h
	$(CC) $(CFLAGS) -ffunction-sections -fdata-sections -c -o $@ $<

.PHONY: test_h2inj
test_h2inj: test_h2_inject
	./test_h2_inject

# Phase 76-07 (FR-10): stateless cookie token derive/verify + miss->rehash +
# constant-time + cross-peer-failover C unit. Standalone — includes only the pure
# sockproxy_cookie.h primitives, links -lssl -lcrypto (the already-linked HMAC).
test_cookie: sockproxy_cookie_test.c sockproxy_cookie.h
	$(CC) -Wall -Wextra -o $@ $< -I. -lssl -lcrypto

.PHONY: test_cook
test_cook: test_cookie
	./test_cookie

# Phase 87-01 (FIX-1/2/3/4): P/D streaming-completion connection-leak unit.
# Standalone — includes only the pure sockproxy_pd_leak.h helpers (no sockproxy.c
# machinery). -fsanitize=address detects over-reads in the bounded detector and
# use-after-free in the two-leg teardown. The TU supplies a fake proxy_fd_ent and
# a recording notifier (SOCKPROXY_PD_LEAK_FAKE_ENT), test_pd_cache_aware.c style.
test_pd_leak: test_pd_leak.c sockproxy_pd_leak.h
	$(CC) -Wall -Wextra -fsanitize=address -o $@ $< -I. -DTEST_PD_LEAK

# Phase 89-01 (T3): load-path streaming-completion stall fix unit. Standalone —
# includes only the pure sockproxy_pd_leak.h helpers (no sockproxy.c machinery).
# Proves the windowed completion detector pd_scan_msg_end_window() catches a
# message-end terminator split across two reads — the Bug-A stall on the
# sse_active==0 path that the single-packet FIX-4 scan missed. -fsanitize=address
# guards the bounded window/tail copies.
test_pd_complete: test_pd_complete.c sockproxy_pd_leak.h
	$(CC) -Wall -Wextra -fsanitize=address -o $@ $< -I. -DTEST_PD_COMPLETE

# Phase 90-02 (REQ-REG / contract §5): adversarial HTTP-response message-framing
# regression units for the M1 response-leg parser. UNLIKE the header-only
# test_pd_complete recipe, this links the real llhttp parser triad
# (llhttp.c httpapi.c http.c) -- it drives an HTTP_RESPONSE parser through five
# adversarial fragmentations and asserts exactly one on_message_complete per
# message (no double-fire, no miss). Case 5 asserts completions==0 for a
# no-terminator keep-alive socket -- the proof the graceful-[DONE] reaper
# (Phase 89) is still required. -fsanitize=address catches any over-read.
test_resp_framing: test_resp_framing.c llhttp.c httpapi.c http.c
	$(CC) -Wall -Wextra -fsanitize=address -o $@ $< llhttp.c httpapi.c http.c -I.

# Phase 93-02 (D1): proactive circuit-breaker recovery unit. Standalone — includes
# only circuit_breaker_heal.h (the pure production transition under test, no
# sockproxy.c machinery). Proves OPEN->HALF_OPEN is driven by the 1Hz health pass
# ALONE (no should_skip/selection call) and the EP becomes selectable again, then
# HALF_OPEN->CLOSED on a genuine relay success. -fsanitize=address for hygiene.
test_cb_heal: test_cb_heal.c circuit_breaker_heal.h
	$(CC) -Wall -Wextra -fsanitize=address -o $@ $< -I.

# Same idiom for the origin-error demotion predicate: a minimal CB struct plus
# only circuit_breaker_origin.h. Proves consecutive origin 5xx trip the breaker
# at the streak threshold even though every request's connect success resets
# failure_count in between (the reset that lets warm affinity pin an
# up-but-erroring EP), origin successes reset the streak, HALF_OPEN probes
# re-trip immediately, and threshold 0 disables. -fsanitize=address for hygiene.
test_cb_origin: test_cb_origin.c circuit_breaker_origin.h
	$(CC) -Wall -Wextra -fsanitize=address -o $@ $< -I.

.PHONY: test_pd
test_pd: test_pd_rewriter test_h2_inject test_cookie test_pd_leak test_pd_complete test_resp_framing test_cb_heal test_cb_origin test_pd_admission test_pd_ctrl
	./test_pd_rewriter
	./test_h2_inject
	./test_cookie
	./test_pd_leak
	./test_pd_complete
	./test_resp_framing
	./test_cb_heal
	./test_cb_origin
	./test_pd_admission
	./test_pd_ctrl

# Phase 93-04: bounded backpressured admission layer unit tests. Now compiles the
# production selector (sockproxy_pd.c) directly (mirrors test_pd_cache_aware) so the
# cap+enqueue decision (PD_PREFILL_PARKED / overflow-429) is exercised end-to-end.
# -fsanitize=address for hygiene.
test_pd_admission: test_pd_admission.c sockproxy_pd.c sockproxy_pd_trie.c
	$(CC) -Wall -Wextra -fsanitize=address -o $@ $< -I. -DTEST_PD_ADMISSION -lpthread

# Phase 96-03: global-controller advisory influence unit (SNAP-03 G3 byte-identity
# + SNAP-04 G4 non-resurrection). Compiles the production selector (sockproxy_pd.c)
# directly (mirrors test_pd_admission); the C2 blend math comes from the REAL
# sockproxy_kv_exact.h static inlines so TC-4's weight assertion runs production
# arithmetic. -fsanitize=address on every case.
test_pd_ctrl: test_pd_ctrl.c sockproxy_pd.c sockproxy_pd_trie.c sockproxy_kv_exact.h
	$(CC) -Wall -Wextra -fsanitize=address -o $@ $< -I. -DTEST_PD_CTRL -lpthread

# US-PD805: P/D cache-aware routing unit tests (standalone, no sockproxy.c dependencies)
# -fsanitize=address detects buffer overflows and use-after-free in session/trie code
test_pd_cache_aware: test_pd_cache_aware.c sockproxy_pd.c sockproxy_pd_trie.c
	$(CC) -Wall -Wextra -fsanitize=address -o $@ $< -I. -DTEST_PD_CACHE_AWARE -lpthread

.PHONY: test_pd_cache
test_pd_cache: test_pd_cache_aware
	./test_pd_cache_aware
	LLB_PD_MAX_INFLIGHT_PER_EP=4 ./test_pd_cache_aware cap

# Phase 6: KV-cache exact routing unit tests (CBOR encoding + hash parity)
test_kv_exact: test_kv_exact.c sockproxy_kv_exact.c sockproxy_kv_exact.h xxhash.h
	$(CC) -Wall -Wextra -DTEST_KV_EXACT -o $@ $< -I. -lssl -lcrypto

.PHONY: test_kv
test_kv: test_kv_exact
	./test_kv_exact

# Phase 47 P47-R2: root-pipe cfg V2 validator + miss-dispatch unit test
# Standalone -- mirrors the header struct inline, does NOT link against DOCA.
test_doca_root_v2: test_doca_root_v2.c
	$(CC) -Wall -Wextra -O2 -o $@ $<

.PHONY: test_root_v2
test_root_v2: test_doca_root_v2
	./test_doca_root_v2

# Phase 49 P49-R2: FDB pipe counter_type enablement unit test
# Standalone -- mirrors the header struct inline, does NOT link against DOCA.
# NOTE per CLAUDE.md Dev->QA Pipeline lesson: before running on bf2-arm,
#      caller MUST `rm -f test_fdb_counter` first (macOS binary rsync poison).
test_fdb_counter: test_fdb_counter.c
	$(CC) -Wall -Wextra -O2 -o $@ $<

.PHONY: test_fdb
test_fdb: test_fdb_counter
	./test_fdb_counter

# Phase 70: sockproxy HA state-sync emit-after-unlock + 10K ring overflow unit test
# Standalone. Task A0 ships a placeholder "OK" main; Task A2 fleshes out the assertions.
test_sockproxy_sync_emit: test_sockproxy_sync_emit.c
	$(CC) -Wall -Wextra -o $@ $< -I. -DTEST_SOCKPROXY_SYNC -lpthread

.PHONY: test_sync
test_sync: test_sockproxy_sync_emit
	./test_sockproxy_sync_emit

.PHONY: clean

clean:
	rm -f *.o *.d test_request_id test_pd_rewriter test_pd_cache_aware test_kv_exact test_doca_root_v2 test_fdb_counter test_sockproxy_sync_emit test_h2_inject test_cookie test_pd_leak test_pd_complete test_resp_framing test_pd_admission test_pd_ctrl

# Phase 93-06 build-hygiene (see DEPFLAGS above): pull in the gcc-generated header
# dependency files so any header edit forces the correct recompiles. `-include` with
# a wildcard is silent on the very first build when no .d exists yet. Keep this as
# the LAST directive in the Makefile.
-include $(wildcard *.d)
