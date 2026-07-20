# Copyright (c) 2022 NetLOX Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# loxilb-ebpf/doca/Makefile -- Build libloxilb_doca_flow.a
#
# Usage:
#   make                  # Stub library (no DOCA deps)
#   make HAVE_DOCA=1      # Real DOCA library (requires DOCA SDK)
#   make HAVE_DOCA=1 test_bridge  # Build test program
#   make clean
#
# The static library is consumed by CGO (pkg/loxinet/dpu_doca_cgo.go)
# via -l:libloxilb_doca_flow.a in LDFLAGS.

# ---- Paths (identical to tools/doca2-verify/Makefile) ----
DOCA_PREFIX   ?= /opt/mellanox/doca
DOCA_PKG_PATH := $(DOCA_PREFIX)/lib/aarch64-linux-gnu/pkgconfig:$(DOCA_PREFIX)/lib/x86_64-linux-gnu/pkgconfig
DPDK_PKG_PATH := /opt/mellanox/dpdk/lib/aarch64-linux-gnu/pkgconfig:/opt/mellanox/dpdk/lib/x86_64-linux-gnu/pkgconfig
ALL_PKG_PATH  := $(DOCA_PKG_PATH):$(DPDK_PKG_PATH)

# ---- Compiler ----
CC      ?= gcc
AR      ?= ar
CFLAGS  := -Wall -Wextra -Wno-unused-parameter -g -O2
CFLAGS  += -D_GNU_SOURCE

# ---- Output ----
LIB     := libloxilb_doca_flow.a

.PHONY: all clean test_bridge check-doca-pipeline-contract

ifdef HAVE_DOCA
# ================================================================
# REAL DOCA BUILD (BF2 with DOCA 2.9.4 SDK installed)
# ================================================================

# Verify pkg-config is available
DOCA_PC_OK := $(shell PKG_CONFIG_PATH=$(ALL_PKG_PATH) pkg-config --exists doca-common 2>/dev/null && echo yes)
ifneq ($(DOCA_PC_OK),yes)
  $(error DOCA pkg-config not found -- ensure DOCA 2.9.4 is installed and DOCA_PREFIX is correct)
endif

DOCA_CFLAGS  := $(shell PKG_CONFIG_PATH=$(ALL_PKG_PATH) pkg-config --cflags doca-common)
DPDK_CFLAGS  := $(shell PKG_CONFIG_PATH=$(ALL_PKG_PATH) pkg-config --cflags libdpdk)
FLOW_LFLAGS  := $(shell PKG_CONFIG_PATH=$(ALL_PKG_PATH) pkg-config --libs doca-common doca-flow doca-dpdk-bridge)
DPDK_LFLAGS  := $(shell PKG_CONFIG_PATH=$(ALL_PKG_PATH) pkg-config --libs libdpdk)
EXTRA_LFLAGS := -pthread -ldl -lm -lstdc++ -libverbs -lmlx5

CFLAGS += $(DOCA_CFLAGS) $(DPDK_CFLAGS)

# Exported for CGO consumption (parent Makefile / Go build)
export DOCA_CGO_CFLAGS  := $(DOCA_CFLAGS) $(DPDK_CFLAGS)
export DOCA_CGO_LDFLAGS := $(FLOW_LFLAGS) $(DPDK_LFLAGS) $(EXTRA_LFLAGS)

OBJS := loxilb_doca_flow.o loxilb_doca_metrics.o

all: check-doca-pipeline-contract $(LIB)

$(LIB): $(OBJS)
	$(AR) rcu $@ $^
	ranlib $@

loxilb_doca_flow.o: loxilb_doca_flow.c loxilb_doca_flow.h
	$(CC) $(CFLAGS) -c -o $@ $<

loxilb_doca_metrics.o: loxilb_doca_metrics.c loxilb_doca_metrics.h loxilb_doca_flow.h
	$(CC) $(CFLAGS) -c -o $@ $<

# Test program (HAVE_DOCA only)
test_bridge: test_doca_bridge
test_doca_bridge: test_doca_bridge.c loxilb_doca_flow.h $(LIB)
	$(CC) $(CFLAGS) -o $@ $< -L. -l:$(LIB) $(FLOW_LFLAGS) $(DPDK_LFLAGS) $(EXTRA_LFLAGS)

else
# ================================================================
# STUB BUILD (no DOCA SDK -- any platform)
# ================================================================

OBJS := loxilb_doca_flow_stub.o

all: check-doca-pipeline-contract $(LIB)

$(LIB): $(OBJS)
	$(AR) rcu $@ $^
	ranlib $@

loxilb_doca_flow_stub.o: loxilb_doca_flow_stub.c loxilb_doca_flow.h
	$(CC) $(CFLAGS) -c -o $@ $<

# Test program not available without DOCA
test_bridge:
	@echo "test_bridge requires HAVE_DOCA=1"
	@exit 1

endif

# ---- CGO flag print targets (consumed by root Makefile) ----
.PHONY: print-cgo-cflags print-cgo-ldflags

ifdef HAVE_DOCA
print-cgo-cflags:
	@echo $(DOCA_CFLAGS) $(DPDK_CFLAGS) -I$(CURDIR)

print-cgo-ldflags:
	@echo -L$(CURDIR) -l:libloxilb_doca_flow.a $(FLOW_LFLAGS) $(DPDK_LFLAGS) $(EXTRA_LFLAGS)
else
print-cgo-cflags:
	@echo -I$(CURDIR)

print-cgo-ldflags:
	@echo -L$(CURDIR) -l:libloxilb_doca_flow.a
endif

# ---- Phase 63 D-13: Anti-pattern contract guard ----
# Prevents reintroduction of the forbidden DOCA pipeline anti-patterns in
# loxilb_doca_flow.c:
#   - DOCA_FLOW_PIPE_DOMAIN_EGRESS   (EGRESS-domain steering — obsolete; the
#                                     BF2 ~10-entry silicon ceiling proves it)
#   - DOCA_FLOW_FWD_CHANGEABLE       (sample uses FWD_PORT(0xFFFF) instead)
#
# NOTE: doca_flow_pipe_cfg_set_dir_info() was originally on this list, but BF2
# hardware validation (Phase 63-08) proved set_dir_info(BIDIRECTIONAL) on the CT
# pipes is LOAD-BEARING for the FWD_TARGET(KERNEL) slow-path return — without it,
# reply-direction packets reach the to_kernel pipe but never land on the kernel
# netdev. The "DOCA ground truth reset" retraction was derived from the validated
# samples, which deliver to kernel via FWD_RSS and so never exercised the kernel
# target. set_dir_info is therefore NOT an anti-pattern and is no longer guarded.
# What WAS the real Phase 54 regression — EGRESS-domain pipes — stays forbidden.
#
# Bareword tokens; hits are filtered to drop lines whose first non-space
# character is `/*`, `*`, or `//` so comment-only mentions pass.
#
# Wired as a prerequisite of `all:` in both HAVE_DOCA and stub branches so every
# `make` invocation enforces it. `make $(LIB)` directly bypasses for one-off
# developer probes (per D-13 "lightest-touch enforcement").
#
# See .planning/phases/63-doca-pipeline-rebuild-from-validated-samples/63-CONTEXT.md D-13.
check-doca-pipeline-contract:
	@FORBIDDEN='\b(DOCA_FLOW_PIPE_DOMAIN_EGRESS\b|DOCA_FLOW_FWD_CHANGEABLE\b)'; \
	HITS=$$(grep -nE "$$FORBIDDEN" loxilb_doca_flow.c 2>/dev/null \
	  | grep -vE '^[^:]+:[[:space:]]*(/\*|\*|//)') ; \
	if [ -n "$$HITS" ]; then \
	  echo "ERROR: forbidden DOCA pipeline anti-pattern found in loxilb_doca_flow.c:"; \
	  echo "$$HITS"; \
	  echo "(see .planning/phases/63-doca-pipeline-rebuild-from-validated-samples/63-CONTEXT.md D-13)"; \
	  exit 1; \
	fi
	@echo "doca-pipeline-contract OK (no DOMAIN_EGRESS / FWD_CHANGEABLE)"

# ---- Clean ----
clean:
	rm -f *.o $(LIB) test_doca_bridge
