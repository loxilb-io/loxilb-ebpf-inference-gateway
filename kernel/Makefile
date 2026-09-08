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

.PHONY: test_l4_trace_helper_compat
test_l4_trace_helper_compat: $(TC_OBJ) test_l4_trace_helper_compat.sh
	sh ./test_l4_trace_helper_compat.sh llb_ebpf_main.o
