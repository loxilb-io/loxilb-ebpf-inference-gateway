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

# loxilb-ebpf/doca/kv/Makefile -- Build libloxilb_kv.a
#
# Usage:
#   make                  # Stub library (no DOCA deps)
#   make HAVE_DOCA=1      # Real DOCA library (requires DOCA SDK)
#   make test_kv_unit     # Unit tests (populated in later plans)
#   make clean
#
# The static library is consumed by CGO (KV agent binary) via
# -l:libloxilb_kv.a in LDFLAGS.

# ---- Paths (identical to parent doca/Makefile) ----
DOCA_PREFIX   ?= /opt/mellanox/doca
DOCA_PKG_PATH := $(DOCA_PREFIX)/lib/aarch64-linux-gnu/pkgconfig:$(DOCA_PREFIX)/lib/x86_64-linux-gnu/pkgconfig
DPDK_PKG_PATH := /opt/mellanox/dpdk/lib/aarch64-linux-gnu/pkgconfig:/opt/mellanox/dpdk/lib/x86_64-linux-gnu/pkgconfig
ALL_PKG_PATH  := $(DOCA_PKG_PATH):$(DPDK_PKG_PATH)

# ---- Compiler ----
CC      ?= gcc
AR      ?= ar
CFLAGS  := -Wall -Werror -Wextra -Wno-unused-parameter -g -O2
CFLAGS  += -D_GNU_SOURCE -I. -I../../common

# ---- Output ----
LIB     := libloxilb_kv.a

# ---- Common objects (unconditional -- no DOCA dependency) ----
# TCP transport is POSIX, not DOCA-dependent, so it lives here.
COMMON_OBJS := loxilb_kv_chunk.o loxilb_kv_tcp.o loxilb_kv_ring.o

.PHONY: all clean test_kv_unit

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

CFLAGS += $(DOCA_CFLAGS) $(DPDK_CFLAGS) -Wno-deprecated-declarations -DHAVE_DOCA

# DOCA-dependent objects (real implementations)
KV_OBJS := loxilb_kv_cap.o \
           loxilb_kv_compress.o \
           loxilb_kv_dma.o \
           loxilb_kv_comch.o \
           loxilb_kv_pipeline.o \
           loxilb_kv_affinity.o \
           loxilb_kv_bufpool.o \
           loxilb_kv_dequantize.o

# Exported for CGO consumption
DOCA_KV_LFLAGS := $(shell PKG_CONFIG_PATH=$(ALL_PKG_PATH) pkg-config --libs doca-common doca-compress doca-dma doca-comch)
export DOCA_KV_CGO_CFLAGS  := $(DOCA_CFLAGS) $(DPDK_CFLAGS) -I$(CURDIR)
export DOCA_KV_CGO_LDFLAGS := -L$(CURDIR) -l:$(LIB) $(DOCA_KV_LFLAGS) -lz

all: $(LIB)

$(LIB): $(COMMON_OBJS) $(KV_OBJS)
	$(AR) rcu $@ $^
	ranlib $@

# ---- Unit test targets ----
test_kv_chunk: test_kv_chunk.c loxilb_kv_chunk.c loxilb_kv.h
	$(CC) $(CFLAGS) -o $@ test_kv_chunk.c loxilb_kv_chunk.c -lz
	./$@

test_kv_pipeline: test_kv_pipeline.c loxilb_kv_pipeline_stub.c loxilb_kv_chunk.c loxilb_kv_compress_stub.c loxilb_kv_dma_stub.c loxilb_kv_comch_stub.c loxilb_kv_tcp.c loxilb_kv_ring.c loxilb_kv_bufpool_stub.c loxilb_kv_dequantize_stub.c loxilb_kv_affinity_stub.c loxilb_kv.h
	$(CC) $(CFLAGS) -o $@ test_kv_pipeline.c loxilb_kv_pipeline_stub.c loxilb_kv_chunk.c loxilb_kv_compress_stub.c loxilb_kv_dma_stub.c loxilb_kv_comch_stub.c loxilb_kv_tcp.c loxilb_kv_ring.c loxilb_kv_bufpool_stub.c loxilb_kv_dequantize_stub.c loxilb_kv_affinity_stub.c -lz -lpthread
	./$@

test_kv_compress: test_kv_compress.c loxilb_kv_compress_stub.c loxilb_kv.h
	$(CC) $(CFLAGS) -o $@ test_kv_compress.c loxilb_kv_compress_stub.c -lz
	./$@

test_kv_affinity: test_kv_affinity.c loxilb_kv_affinity_stub.c loxilb_kv.h
	$(CC) $(CFLAGS) -o $@ test_kv_affinity.c loxilb_kv_affinity_stub.c -lpthread
	./$@

test_kv_ring: test_kv_ring.c loxilb_kv_ring.c loxilb_kv.h
	$(CC) $(CFLAGS) -o $@ test_kv_ring.c loxilb_kv_ring.c -lpthread
	./$@

test_kv_bufpool: test_kv_bufpool.c loxilb_kv_bufpool_stub.c loxilb_kv.h
	$(CC) $(CFLAGS) -o $@ test_kv_bufpool.c loxilb_kv_bufpool_stub.c -lpthread
	./$@

test_kv_dequantize: test_kv_dequantize.c loxilb_kv_dequantize_stub.c loxilb_kv_ring.c loxilb_kv_bufpool_stub.c loxilb_kv.h
	$(CC) $(CFLAGS) -o $@ test_kv_dequantize.c loxilb_kv_dequantize_stub.c loxilb_kv_ring.c loxilb_kv_bufpool_stub.c -lpthread -lz
	./$@

test_kv_integration: test_kv_integration.c loxilb_kv_pipeline_stub.c loxilb_kv_chunk.c loxilb_kv_compress_stub.c loxilb_kv_dma_stub.c loxilb_kv_comch_stub.c loxilb_kv_tcp.c loxilb_kv_ring.c loxilb_kv_bufpool_stub.c loxilb_kv_dequantize_stub.c loxilb_kv_affinity_stub.c loxilb_kv.h
	$(CC) $(CFLAGS) -o $@ test_kv_integration.c loxilb_kv_pipeline_stub.c loxilb_kv_chunk.c loxilb_kv_compress_stub.c loxilb_kv_dma_stub.c loxilb_kv_comch_stub.c loxilb_kv_tcp.c loxilb_kv_ring.c loxilb_kv_bufpool_stub.c loxilb_kv_dequantize_stub.c loxilb_kv_affinity_stub.c -lz -lpthread
	./$@

test_kv_e2e: test_kv_e2e.c loxilb_kv_chunk.c loxilb_kv.h
	$(CC) $(CFLAGS) -o $@ test_kv_e2e.c loxilb_kv_chunk.c -lz

test_kv_unit: test_kv_chunk test_kv_pipeline test_kv_compress test_kv_affinity test_kv_ring test_kv_bufpool test_kv_dequantize test_kv_integration
	@echo "All KV unit tests passed"

else
# ================================================================
# STUB BUILD (no DOCA SDK -- any platform)
# ================================================================

# Stub objects replace DOCA-dependent implementations
KV_OBJS := loxilb_kv_cap_stub.o \
           loxilb_kv_compress_stub.o \
           loxilb_kv_dma_stub.o \
           loxilb_kv_comch_stub.o \
           loxilb_kv_pipeline_stub.o \
           loxilb_kv_affinity_stub.o \
           loxilb_kv_bufpool_stub.o \
           loxilb_kv_dequantize_stub.o

all: $(LIB)

$(LIB): $(COMMON_OBJS) $(KV_OBJS)
	$(AR) rcu $@ $^
	ranlib $@

# ---- Unit test targets (stub build -- all use stubs, no DOCA needed) ----
test_kv_chunk: test_kv_chunk.c loxilb_kv_chunk.c loxilb_kv.h
	$(CC) $(CFLAGS) -o $@ test_kv_chunk.c loxilb_kv_chunk.c -lz
	./$@

test_kv_pipeline: test_kv_pipeline.c loxilb_kv_pipeline_stub.c loxilb_kv_chunk.c loxilb_kv_compress_stub.c loxilb_kv_dma_stub.c loxilb_kv_comch_stub.c loxilb_kv_tcp.c loxilb_kv_ring.c loxilb_kv_bufpool_stub.c loxilb_kv_dequantize_stub.c loxilb_kv_affinity_stub.c loxilb_kv.h
	$(CC) $(CFLAGS) -o $@ test_kv_pipeline.c loxilb_kv_pipeline_stub.c loxilb_kv_chunk.c loxilb_kv_compress_stub.c loxilb_kv_dma_stub.c loxilb_kv_comch_stub.c loxilb_kv_tcp.c loxilb_kv_ring.c loxilb_kv_bufpool_stub.c loxilb_kv_dequantize_stub.c loxilb_kv_affinity_stub.c -lz -lpthread
	./$@

test_kv_compress: test_kv_compress.c loxilb_kv_compress_stub.c loxilb_kv.h
	$(CC) $(CFLAGS) -o $@ test_kv_compress.c loxilb_kv_compress_stub.c -lz
	./$@

test_kv_affinity: test_kv_affinity.c loxilb_kv_affinity_stub.c loxilb_kv.h
	$(CC) $(CFLAGS) -o $@ test_kv_affinity.c loxilb_kv_affinity_stub.c -lpthread
	./$@

test_kv_ring: test_kv_ring.c loxilb_kv_ring.c loxilb_kv.h
	$(CC) $(CFLAGS) -o $@ test_kv_ring.c loxilb_kv_ring.c -lpthread
	./$@

test_kv_bufpool: test_kv_bufpool.c loxilb_kv_bufpool_stub.c loxilb_kv.h
	$(CC) $(CFLAGS) -o $@ test_kv_bufpool.c loxilb_kv_bufpool_stub.c -lpthread
	./$@

test_kv_dequantize: test_kv_dequantize.c loxilb_kv_dequantize_stub.c loxilb_kv_ring.c loxilb_kv_bufpool_stub.c loxilb_kv.h
	$(CC) $(CFLAGS) -o $@ test_kv_dequantize.c loxilb_kv_dequantize_stub.c loxilb_kv_ring.c loxilb_kv_bufpool_stub.c -lpthread -lz
	./$@

test_kv_integration: test_kv_integration.c loxilb_kv_pipeline_stub.c loxilb_kv_chunk.c loxilb_kv_compress_stub.c loxilb_kv_dma_stub.c loxilb_kv_comch_stub.c loxilb_kv_tcp.c loxilb_kv_ring.c loxilb_kv_bufpool_stub.c loxilb_kv_dequantize_stub.c loxilb_kv_affinity_stub.c loxilb_kv.h
	$(CC) $(CFLAGS) -o $@ test_kv_integration.c loxilb_kv_pipeline_stub.c loxilb_kv_chunk.c loxilb_kv_compress_stub.c loxilb_kv_dma_stub.c loxilb_kv_comch_stub.c loxilb_kv_tcp.c loxilb_kv_ring.c loxilb_kv_bufpool_stub.c loxilb_kv_dequantize_stub.c loxilb_kv_affinity_stub.c -lz -lpthread
	./$@

test_kv_unit: test_kv_chunk test_kv_pipeline test_kv_compress test_kv_affinity test_kv_ring test_kv_bufpool test_kv_dequantize test_kv_integration
	@echo "All KV unit tests passed"

endif

# ---- Implicit rules ----
%.o: %.c loxilb_kv.h
	$(CC) $(CFLAGS) -c -o $@ $<

# ---- CGO flag print targets (consumed by root Makefile) ----
.PHONY: print-cgo-cflags print-cgo-ldflags

ifdef HAVE_DOCA
print-cgo-cflags:
	@echo $(DOCA_CFLAGS) $(DPDK_CFLAGS) -I$(CURDIR)

print-cgo-ldflags:
	@echo -L$(CURDIR) -l:$(LIB) $(DOCA_KV_LFLAGS) -lz
else
print-cgo-cflags:
	@echo -I$(CURDIR)

print-cgo-ldflags:
	@echo -L$(CURDIR) -l:$(LIB) -lz
endif

# ---- Clean ----
clean:
	rm -f *.o $(LIB) test_kv_chunk test_kv_pipeline test_kv_compress test_kv_affinity test_kv_ring test_kv_bufpool test_kv_dequantize test_kv_integration
