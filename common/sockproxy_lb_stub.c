/*
 * Copyright (c) 2024 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */

/*
 * sockproxy_lb_stub.c -- No-op stubs for LB algorithms when GPU routing is off.
 *
 * Used when HAVE_DP_GPU_ROUTING is NOT defined.
 * CHWBL functions are guarded in this file so if someone builds without the
 * flag but links this stub, the builds succeeds with no CHWBL functionality.
 *
 * NOTE: WRR functions (wrr_init_state, wrr_select_endpoint) are always needed
 *       and are defined in sockproxy_lb.c itself (no stubs required).
 */

#include "sockproxy_lb.h"

/* WRR stubs (used when sockproxy_lb.o is excluded -- currently not needed) */
void wrr_init_state(proxy_epval_t *epv) { (void)epv; }
int  wrr_select_endpoint(proxy_epval_t *epv) { (void)epv; return -1; }
