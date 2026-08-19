# Common Makefile parts for BPF-building with libbpf
# --------------------------------------------------
# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
#
# This file should be included from your Makefile like:
#  COMMON_DIR = ../common/
#  include $(COMMON_DIR)/common.mk
#
# It is expected that you define the variables:
#  XDP_TARGETS and USER_TARGETS
# as a space-separated list
#
LLC = llc
CLANG := $(shell if [ -f /usr/bin/clang-14 ];then echo clang-14; else echo clang; fi;)
CC ?= gcc
BPFTOOL ?= bpftool

XDP_C = ${XDP_TARGETS:=.c}
TC_C = ${TC_TARGETS:=.c}
TC_EC = ${TC_ETARGETS:=.c}
MON_C = ${MON_TARGETS:=.c}
SOCK_C = ${SOCK_TARGETS:=.c}
SM_C = ${SOCKMAP_TARGETS:=.c}
STREAM_C = ${SOCKSTREAM_TARGETS:=.c}
SOCKDIR_C = ${SOCKDIR_TARGETS:=.c}
XDP_OBJ = ${XDP_C:.c=.o}
TC_OBJ = ${TC_C:.c=.o}
TC_EOBJ = ${TC_EC:.c=.o}
MON_OBJ = ${MON_C:.c=.o}
SOCK_OBJ = ${SOCK_C:.c=.o}
SM_OBJ = ${SM_C:.c=.o}
STREAM_OBJ = ${STREAM_C:.c=.o}
SOCKDIR_OBJ = ${SOCKDIR_C:.c=.o}

USER_C := ${USER_TARGETS:=.c}
USER_OBJ := ${USER_C:.c=.o}
USER_TARGETS_LIB := libloxilbdp.a

UNAME := $(shell uname -m)
ARCH := $(shell uname -m | sed 's/x86_64/x86/')
ifeq ($(UNAME), aarch64)
ARCH=arm64
endif

# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
  | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
  Q =
  msg =
else
  Q = @
  msg = @printf '  %-8s %s%s\n'         \
          "$(1)"            \
          "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))" \
          "$(if $(3), $(3))";
  MAKEFLAGS += --no-print-directory
endif


# Expect this is defined by including Makefile, but define if not
COMMON_DIR ?= ../common/
LIBBPF_DIR ?= ../libbpf/src/

OBJECT_LIBBPF = $(LIBBPF_DIR)/libbpf.a

# Extend if including Makefile already added some
COMMON_OBJS += $(COMMON_DIR)/common_sum.o $(COMMON_DIR)/common_libbpf.o $(COMMON_DIR)/common_pdi.o $(COMMON_DIR)/common_frame.o $(COMMON_DIR)/log.o $(COMMON_DIR)/throttler.o $(COMMON_DIR)/cgroup.o $(COMMON_DIR)/sockproxy.o $(COMMON_DIR)/sockproxy_metrics.o $(COMMON_DIR)/sockproxy_routing.o $(COMMON_DIR)/sockproxy_l7policy.o $(COMMON_DIR)/sockproxy_json.o $(COMMON_DIR)/sockproxy_trace.o $(COMMON_DIR)/sockproxy_cache.o $(COMMON_DIR)/sockproxy_lb.o $(COMMON_DIR)/sockproxy_health.o $(COMMON_DIR)/sockproxy_ssl.o $(COMMON_DIR)/sockproxy_conn.o $(COMMON_DIR)/sockproxy_ep.o $(COMMON_DIR)/sockproxy_http.o $(COMMON_DIR)/sockproxy_notifier.o $(COMMON_DIR)/sockproxy_ktls.o $(COMMON_DIR)/sockproxy_h2.o $(COMMON_DIR)/sockproxy_pd.o $(COMMON_DIR)/sockproxy_pd_core.o $(COMMON_DIR)/sockproxy_pd_vllm.o $(COMMON_DIR)/sockproxy_pd_trie.o $(COMMON_DIR)/sockproxy_kv_exact.o $(COMMON_DIR)/sockproxy_sync.o $(COMMON_DIR)/notify.o $(COMMON_DIR)/picohttpparser.o $(COMMON_DIR)/llhttp.o $(COMMON_DIR)/httpapi.o $(COMMON_DIR)/http.o

# HTTP/HTTPS Tracing Support: Add lxb_ring.o if HAVE_HTTP_TRACE is enabled, otherwise add stub
ifdef HAVE_HTTP_TRACE
COMMON_OBJS += $(COMMON_DIR)/lxb_ring.o
else
COMMON_OBJS += $(COMMON_DIR)/lxb_ring_stub.o
endif

# PII Detection Support: Add presidio objects if HAVE_PII_DETECTION is enabled
ifdef HAVE_PII_DETECTION
COMMON_OBJS += $(COMMON_DIR)/presidio_config.o $(COMMON_DIR)/sockproxy_presidio.o
endif

# LlamaFirewall Support: Add llamafirewall objects if HAVE_LLAMAFIREWALL is enabled
ifdef HAVE_LLAMAFIREWALL
COMMON_OBJS += $(COMMON_DIR)/llamafirewall_config.o $(COMMON_DIR)/sockproxy_llamafirewall.o
endif

# mTLS Support: Add mTLS objects if HAVE_MTLS is enabled
ifdef HAVE_MTLS
COMMON_OBJS += $(COMMON_DIR)/sockproxy_mtls.o
endif

# L4 Connection Tracing Support: Always add lxb_l4_trace.o (contains stubs when disabled)
ifdef HAVE_L4_TRACE
LIBLXB_DIR ?= ../liblxb
COMMON_OBJS += $(LIBLXB_DIR)/lxb_l4_trace.o
endif

# Create expansions for dependencies
COMMON_H := ${COMMON_OBJS:.o=.h}

EXTRA_DEPS +=

# BPF-prog kern and userspace shares struct via header file:
KERN_USER_H ?= $(wildcard common_kern_user.h)

# DPU Slim Build Profile (BF2 kernel 5.15 compatibility)
# Strips: IP_FILTER, SECURITY_RATE_LIMIT, SECURITY_RATE_RUNTIME_CONFIG,
#          GPU_ROUTING, RSS, SCTP_SUM, PROXY_EXTRA_DEBUG
# Keeps: FC, EXTCT (tunnel CT), CT_SYNC, PERSIST_TFC, FW
ifdef HAVE_DP_DPU_SLIM
DPU_CPUS ?= 8
CFLAGS_ALL := -DHAVE_DP_DPU_SLIM=1 \
              -DHAVE_DP_FC=1 \
              -DHAVE_DP_EXTCT=1 \
              -DHAVE_DP_CT_SYNC=1 \
              -DMAX_REAL_CPUS=$(DPU_CPUS) \
              -DHAVE_DP_PERSIST_TFC=1 \
              -DHAVE_DP_FW=1
export HAVE_DP_DPU_SLIM
export DPU_CPUS
endif

# DPU BF3 Build Profile (kernel 6.8 -- full features, XDP skipped)
# Same flags as normal build, only MAX_REAL_CPUS overridden
ifdef HAVE_DP_DPU_BF3
DPU_CPUS ?= 16
CFLAGS_ALL := -DHAVE_DP_DPU_BF3=1 \
              -DHAVE_DP_FC=1 -DHAVE_DP_EXTCT=1 -DHAVE_DP_SCTP_SUM=1 \
              -DHAVE_DP_CT_SYNC=1 -DMAX_REAL_CPUS=$(DPU_CPUS) \
              -DHAVE_DP_RSS=1 -DHAVE_DP_PERSIST_TFC=1 -DHAVE_DP_FW=1 \
              -DHAVE_DP_GPU_ROUTING=1 -DHAVE_DP_IP_FILTER=1 \
              -DHAVE_DP_SECURITY_RATE_LIMIT=1 \
              -DHAVE_DP_SECURITY_RATE_RUNTIME_CONFIG=1 \
              -DHAVE_PROXY_EXTRA_DEBUG=1
export HAVE_DP_DPU_BF3
export DPU_CPUS
endif

# Combining gpu-security features with main's base flags
# Note: -DHAVE_DP_LOG_LVL_DBG=1 removed for kernel 5.15 compatibility (bpf_printk unavailable)
# CFLAGS_ALL ?= -DHAVE_DP_FC=1 -DHAVE_DP_EXTCT=1 -DHAVE_DP_SCTP_SUM=1 -DHAVE_DP_CT_SYNC=1 -DMAX_REAL_CPUS=16 -DHAVE_DP_RSS=1 -DHAVE_DP_PERSIST_TFC=1 -DHAVE_DP_FW=1 -DHAVE_DP_GPU_ROUTING=1 -DHAVE_DP_IP_FILTER=1 -DHAVE_DP_SECURITY_RATE_LIMIT=1 -DHAVE_DP_SECURITY_RATE_RUNTIME_CONFIG=1
CFLAGS_ALL ?= -DHAVE_DP_FC=1 -DHAVE_DP_EXTCT=1 -DHAVE_DP_SCTP_SUM=1 -DHAVE_DP_CT_SYNC=1 -DMAX_REAL_CPUS=16 -DHAVE_DP_RSS=1 -DHAVE_DP_PERSIST_TFC=1 -DHAVE_DP_FW=1 -DHAVE_DP_GPU_ROUTING=1 -DHAVE_DP_IP_FILTER=1 -DHAVE_DP_SECURITY_RATE_LIMIT=1 -DHAVE_DP_SECURITY_RATE_RUNTIME_CONFIG=1 -DHAVE_PROXY_EXTRA_DEBUG=1

# Allow EXTRA_CFLAGS from command line (e.g., make EXTRA_CFLAGS="-DHAVE_L4_TRACE")
ifdef EXTRA_CFLAGS
CFLAGS_ALL += $(EXTRA_CFLAGS)
# Export for sub-makes (liblxb)
export EXTRA_CFLAGS
# Extract feature flags for conditional compilation
ifneq (,$(findstring -DHAVE_L4_TRACE,$(EXTRA_CFLAGS)))
HAVE_L4_TRACE := 1
export HAVE_L4_TRACE
endif
endif

# HTTP/HTTPS Tracing Support: Add -DHAVE_HTTP_TRACE=1 if enabled
ifdef HAVE_HTTP_TRACE
CFLAGS_ALL += -DHAVE_HTTP_TRACE=1
export HAVE_HTTP_TRACE
endif

# LlamaFirewall Support: Add -DHAVE_LLAMAFIREWALL=1 if enabled
ifdef HAVE_LLAMAFIREWALL
CFLAGS_ALL += -DHAVE_LLAMAFIREWALL=1
export HAVE_LLAMAFIREWALL
endif

# mTLS Support: Add -DHAVE_MTLS=1 if enabled
ifdef HAVE_MTLS
CFLAGS_ALL += -DHAVE_MTLS=1
export HAVE_MTLS
endif

ifeq ($(CLANG), clang-13)
CFLAGS_ALL += -DHAVE_CLANG13
endif
CFLAGS ?= -I$(LIBBPF_DIR)/build/usr/include/ -g
CFLAGS += -I../headers/ -I$(LIBBPF_DIR)/ $(CFLAGS_ALL)
# Phase 90 diag: opt-in ASan for the USERSPACE links of common objects
# (loxilb_libdp / loxilb_dp_debug). Deliberately on CFLAGS, NOT CFLAGS_ALL —
# BPF_CFLAGS (clang -target bpf) pulls CFLAGS_ALL and must stay ASan-free, since
# eBPF bytecode cannot be sanitized. Empty by default; the link must pull libasan
# because common/*.o are built with ASAN_CFLAGS and reference __asan_* symbols.
CFLAGS += $(ASAN_CFLAGS)
LDFLAGS ?= -L$(LIBBPF_DIR)

ifeq ($(DOCKER_BUILDX_ARM64), true)
CFLAGS_ALL += -DDOCKER_BUILDX_ARM64=1
endif

BPF_CFLAGS ?= -I$(LIBBPF_DIR)/build/usr/include/ -I../headers/ -I/usr/include/$(shell uname -m)-linux-gnu $(CFLAGS_ALL)

# Libraries: json-c added for Phase 2.2 custom pattern recognition (PII detection)
LIBS = $(OBJECT_LIBBPF) -lelf $(USER_LIBS) -lz -lpthread -lssl -lcrypto -lnghttp2 -ljson-c

all: llvm-check $(USER_TARGETS) $(XDP_OBJ) $(TC_OBJ) $(TC_EOBJ) $(MON_OBJ) $(SOCK_OBJ) $(SM_OBJ) $(STREAM_OBJ) $(SOCKDIR_OBJ) $(USER_TARGETS_LIB)

.PHONY: clean $(CLANG) $(LLC)

clean:
	rm -rf $(LIBBPF_DIR)/build
	$(MAKE) -C $(LIBBPF_DIR) clean
	$(MAKE) -C $(COMMON_DIR) clean
	rm -f $(USER_TARGETS) $(XDP_OBJ) $(USER_OBJ) $(TC_OBJ) $(TC_EOBJ) $(MON_OBJ) $(MON_OBJ) $(SOCK_OBJ) $(SM_OBJ) $(STREAM_OBJ) $(SOCKDIR_OBJ) $(USER_TARGETS_LIB)
	rm -f loxilb_dp_debug 
	rm -f vmlinux vmlinux.h
	rm -f *skel*.h
	rm -f $@
	rm -f *.ll
	rm -f *~

# For build dependency on this file, if it gets updated
COMMON_MK = $(COMMON_DIR)/common.mk

llvm-check: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if [ ! $$(command -v $${TOOL} 2>/dev/null) ]; then \
			echo "*** ERROR: Cannot find tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

$(OBJECT_LIBBPF):
	@if [ ! -d $(LIBBPF_DIR) ]; then \
		echo "Error: Need libbpf submodule"; \
		echo "May need to run git submodule update --init"; \
		exit 1; \
	else \
		cd $(LIBBPF_DIR) && $(MAKE) all; \
		mkdir -p build; DESTDIR=build $(MAKE) install_headers; \
		DESTDIR=build $(MAKE) install; \
	fi

# Create dependency: detect if C-file change and touch H-file, to trigger
# target $(COMMON_OBJS)
$(COMMON_H): %.h: %.c
	touch $@

# Detect if any of common obj changed and create dependency on .h-files
$(COMMON_OBJS): %.o: %.h
	make -C $(COMMON_DIR)

# L4 tracing: Build liblxb objects separately
ifdef HAVE_L4_TRACE
$(LIBLXB_DIR)/lxb_l4_trace.o: $(LIBLXB_DIR)/lxb_l4_trace.c
	make -C $(LIBLXB_DIR) HAVE_L4_TRACE=1
endif

# PII Detection & LlamaFirewall: Build stubs for C-only targets
# Collect all stub dependencies based on enabled features
#
# AI Gateway CGO stub is always required because llb_ai_stream_start/end and
# llb_ai_record_request are called unconditionally from sockproxy.c (C-1/C-5).
STUB_OBJS := $(COMMON_DIR)/sockproxy_ai_gw_stub.o

$(COMMON_DIR)/sockproxy_ai_gw_stub.o: $(COMMON_DIR)/sockproxy_ai_gw_stub.c \
                                       $(COMMON_DIR)/sockproxy_ai_gw.h
	make -C $(COMMON_DIR) sockproxy_ai_gw_stub.o

ifdef HAVE_PII_DETECTION
STUB_OBJS += $(COMMON_DIR)/sockproxy_presidio_stub.o $(COMMON_DIR)/sockproxy_presidio_enhanced_stub.o

$(COMMON_DIR)/sockproxy_presidio_stub.o: $(COMMON_DIR)/sockproxy_presidio_stub.c
	make -C $(COMMON_DIR) sockproxy_presidio_stub.o

$(COMMON_DIR)/sockproxy_presidio_enhanced_stub.o: $(COMMON_DIR)/sockproxy_presidio_enhanced_stub.c
	make -C $(COMMON_DIR) sockproxy_presidio_enhanced_stub.o
endif

ifdef HAVE_LLAMAFIREWALL
STUB_OBJS += $(COMMON_DIR)/sockproxy_llamafirewall_stub.o

$(COMMON_DIR)/sockproxy_llamafirewall_stub.o: $(COMMON_DIR)/sockproxy_llamafirewall_stub.c
	make -C $(COMMON_DIR) sockproxy_llamafirewall_stub.o
endif

# Build C-only debug binary with stubs (if any features enabled)
ifneq ($(STUB_OBJS),)
$(USER_TARGETS): %: %.c  $(OBJECT_LIBBPF) Makefile $(COMMON_MK) $(COMMON_OBJS) $(KERN_USER_H) $(EXTRA_DEPS) %.skel.h $(STUB_OBJS)
	$(CC) -Wall $(CFLAGS) $(LDFLAGS) -o loxilb_dp_debug loxilb_dp_debug.c $(COMMON_OBJS) $(STUB_OBJS) $< $(LIBS)
	@touch $@
else
# Build C-only debug binary without any stubs
$(USER_TARGETS): %: %.c  $(OBJECT_LIBBPF) Makefile $(COMMON_MK) $(COMMON_OBJS) $(KERN_USER_H) $(EXTRA_DEPS) %.skel.h
	$(CC) -Wall $(CFLAGS) $(LDFLAGS) -o loxilb_dp_debug loxilb_dp_debug.c $(COMMON_OBJS) $< $(LIBS)
	@touch $@
endif

$(USER_TARGETS_LIB): %: $(USER_OBJ) $(COMMON_OBJS)
	$(AR) rcu $@ $^
	ranlib $@

$(XDP_OBJ): %.o: %.c  Makefile $(COMMON_MK) $(KERN_USER_H) $(EXTRA_DEPS) $(XDP_DEPS)
	$(CLANG) \
		-target bpf \
		-D __BPF_TRACING__ \
		$(BPF_CFLAGS) \
		-Wall \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Werror \
		-O2 -g -c -o ${@:.o=.o} $<
	@#$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}
	@sudo mkdir -p /opt/loxilb/
	@sudo cp $@ /opt/loxilb/

## Remove debug in production
## -DLL_XDP_DEBUG=1

$(TC_OBJ): %.o: %.c  Makefile $(COMMON_MK) $(KERN_USER_H) $(EXTRA_DEPS) $(XDP_DEPS)
	$(CLANG) \
		-target bpf \
		-D __BPF_TRACING__ \
		-DLL_TC_EBPF=1 \
		$(BPF_CFLAGS) \
		-Wall \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Werror \
		-O2 -g -c -o ${@:.o=.o} $<
	@#$(LLC) -march=bpf -mattr=dwarfris -filetype=obj -o $@ ${@:.o=.o}
	@sudo mkdir -p /opt/loxilb/
	@sudo cp $@ /opt/loxilb/
	@#sudo pahole -J /opt/loxilb/$@

$(TC_EOBJ): %.o: %.c  Makefile $(COMMON_MK) $(KERN_USER_H) $(EXTRA_DEPS) $(XDP_DEPS)
	$(CLANG) \
		-target bpf \
		-D __BPF_TRACING__ \
		-DLL_TC_EBPF=1 \
		-DLL_TC_EBPF_EHOOK=1 \
		$(BPF_CFLAGS) \
		-Wall \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Werror \
		-O2 -g -c -o ${@:.o=.o} $<
	@#$(LLC) -march=bpf -mattr=dwarfris -filetype=obj -o $@ ${@:.o=.o}
	@sudo mkdir -p /opt/loxilb/
	@sudo cp $@ /opt/loxilb/
	@#sudo pahole -J /opt/loxilb/$@

vmlinux.h:
	@touch $@

vmlinux: vmlinux.h
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	@touch $@

$(MON_OBJ): %.o: %.c  Makefile $(COMMON_MK) $(KERN_USER_H) $(EXTRA_DEPS) $(XDP_DEPS) vmlinux
	$(CLANG) \
		-target bpf \
		-D __BPF_TRACING__ \
		-D__TARGET_ARCH_$(ARCH) \
		-DLL_TC_EBPF=1 \
		$(BPF_CFLAGS) \
		$(CLANG_BPF_SYS_INCLUDES) \
		-O2 -g -c -o ${@:.o=.o} $<
	@#$(LLC) -march=bpf -mattr=dwarfris -filetype=obj -o $@ ${@:.o=.o}
	@sudo cp $@ /opt/loxilb/
	@#sudo pahole -J /opt/loxilb/$@

$(SOCK_OBJ): %.o: %.c  Makefile $(COMMON_MK) $(KERN_USER_H) $(EXTRA_DEPS) 
	$(CLANG) \
		-target bpf \
		-D __BPF_TRACING__ \
		-D__TARGET_ARCH_$(ARCH) \
		-DLL_TC_EBPF=1 \
		$(BPF_CFLAGS) \
		$(CLANG_BPF_SYS_INCLUDES) \
		-O2 -g -c -o ${@:.o=.o} $<
	@#$(LLC) -march=bpf -mattr=dwarfris -filetype=obj -o $@ ${@:.o=.o}
	@sudo cp $@ /opt/loxilb/
	@#sudo pahole -J /opt/loxilb/$@

$(SM_OBJ): %.o: %.c  Makefile $(COMMON_MK) $(KERN_USER_H) $(EXTRA_DEPS) vmlinux
	$(CLANG) \
		-target bpf \
		-D __BPF_TRACING__ \
		-D__TARGET_ARCH_$(ARCH) \
		$(BPF_CFLAGS) \
		$(CLANG_BPF_SYS_INCLUDES) \
		-O2 -g -c -o ${@:.o=.o} $<
	@sudo cp $@ /opt/loxilb/

$(STREAM_OBJ): %.o: %.c  Makefile $(COMMON_MK) $(KERN_USER_H) $(EXTRA_DEPS)
	$(CLANG) \
		-target bpf \
		-D __BPF_TRACING__ \
		-D__TARGET_ARCH_$(ARCH) \
		$(BPF_CFLAGS) \
		$(CLANG_BPF_SYS_INCLUDES) \
		-O2 -g -c -o ${@:.o=.o} $<
	@sudo cp $@ /opt/loxilb/

$(SOCKDIR_OBJ): %.o: %.c  Makefile $(COMMON_MK) $(KERN_USER_H) $(EXTRA_DEPS)
	$(CLANG) \
		-target bpf \
		-D __BPF_TRACING__ \
		-D__TARGET_ARCH_$(ARCH) \
		$(BPF_CFLAGS) \
		$(CLANG_BPF_SYS_INCLUDES) \
		-O2 -g -c -o ${@:.o=.o} $<
	@sudo cp $@ /opt/loxilb/

# Generate BPF skeletons
%.skel.h: $(MON_OBJ)
	$(call msg,GEN-SKEL,$@)
	$(BPFTOOL) gen skeleton $< > $@

install:
	@sudo cp -f /opt/loxilb/llb_*.o ${dpinstalldir}/
	@sudo cp -fr ../libbpf/src/build/* ${dpinstalldir}/
