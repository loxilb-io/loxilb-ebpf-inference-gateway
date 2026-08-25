/*
 * llb_ebpf_main.c: LoxiLB TC eBPF egress Main processing
 * Copyright (c) 2022-2025  LoxiLB Authors
 * 
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_arp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* This image runs on the TC egress qdisc. It must stay FUNCTIONALLY IDENTICAL
 * to the ingress image: both reuse the same pinned tail-call table (pgm_tbl),
 * so whichever image attaches last supplies the tail-called programs for both
 * hooks. Direction-specific behaviour (e.g. which policer id applies) is
 * decided at runtime inside the shared pipeline, never by a compile-time
 * define here.
 */
#include "llb_kern_entry.c"

char _license[] SEC("license") = "Dual BSD/GPL";
