# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

.DEFAULT_GOAL := all

XDP_DEPS := llb_kern_devif.c      \
            llb_kern_l2fwd.c      \
            llb_kern_l3fwd.c      \
            llb_kern_sessfwd.c    \
            llb_kern_natlbfwd.c   \
            llb_kern_policer.c    \
            llb_kern_fcfwd.c      \
            llb_kern_entry.c      \
            llb_kern_ct.c

XDP_TARGETS  := llb_xdp_main
# DPU builds skip XDP (BF2 has no XDP HW mode, BF3 skips XDP too)
ifdef HAVE_DP_DPU_SLIM
XDP_TARGETS :=
endif
ifdef HAVE_DP_DPU_BF3
XDP_TARGETS :=
endif
TC_TARGETS   := llb_ebpf_main
TC_ETARGETS  := llb_ebpf_emain
MON_TARGETS  := llb_kern_mon
USER_TARGETS := loxilb_libdp

SOCK_TARGETS       := llb_kern_sock
SOCKMAP_TARGETS    := llb_kern_sockmap
SOCKSTREAM_TARGETS := llb_kern_sockstream
SOCKDIR_TARGETS    := llb_kern_sockdirect

LLC ?= llc
CLANG ?= clang
CC := gcc

.PHONY: test_unparse_gate
test_unparse_gate: test_unparse_gate.c llb_kern_unparse_gate.h
	$(CC) -Wall -Wextra -Werror -o $@ test_unparse_gate.c
	./$@

LIBBPF_DIR = ../libbpf/src/
COMMON_DIR = ../common

LDFLAGS +=  -lz 

include $(COMMON_DIR)/common.mk

loxilb_libdp.o: llb_map_abi.h llb_map_abi_table.h

.PHONY: test_nat_map_abi test_nat_map_abi_kernel
test_nat_map_abi: test_nat_map_abi.c llb_map_abi.h
	$(CC) -std=gnu11 -Wall -Wextra -Werror -I$(LIBBPF_DIR) -O2 -o test_nat_map_abi test_nat_map_abi.c
	./test_nat_map_abi
	$(CC) -std=gnu11 -Wall -Wextra -Werror -I$(LIBBPF_DIR) -g -fsanitize=address,undefined -fno-omit-frame-pointer -o test_nat_map_abi_sanitized test_nat_map_abi.c
	ASAN_OPTIONS=detect_leaks=1 ./test_nat_map_abi_sanitized

# Privileged integration check; run in a disposable container, not on host pins.
test_nat_map_abi_kernel: test_nat_map_abi_kernel.c llb_map_abi.h $(OBJECT_LIBBPF)
	$(CC) -std=gnu11 -Wall -Wextra -Werror -I$(LIBBPF_DIR) -g -o test_nat_map_abi_kernel test_nat_map_abi_kernel.c $(OBJECT_LIBBPF) -lelf -lz
	./test_nat_map_abi_kernel

.PHONY: test_l4_trace_helper_compat
test_l4_trace_helper_compat: $(TC_OBJ) test_l4_trace_helper_compat.sh
	sh ./test_l4_trace_helper_compat.sh llb_ebpf_main.o

.PHONY: test_build_deps
test_build_deps:
	python3 test_build_deps.py
