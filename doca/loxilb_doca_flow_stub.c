/*
 * Copyright (c) 2022 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * loxilb_doca_flow_stub.c -- Stub implementation for non-DOCA builds.
 *
 * All functions return LLB_DOCA_ERR_NOTSUP (or NULL for handle-returning
 * functions, 0 for llb_doca_is_initialized).  This file is compiled when
 * HAVE_DOCA is NOT set, producing libloxilb_doca_flow.a with all symbols
 * present but non-functional.
 *
 * Pattern follows sockproxy_ai_gw_stub.c style.
 */

#include "loxilb_doca_flow.h"
#include <stddef.h>  /* NULL */

int llb_doca_init(const char *pci_addr, int no_huge, const llb_doca_config *cfg)
{
    (void)pci_addr;
    (void)no_huge;
    (void)cfg;
    return LLB_DOCA_ERR_NOTSUP;
}

void llb_doca_shutdown(void)
{
    /* no-op */
}

int llb_doca_is_initialized(void)
{
    return 0;
}

int llb_doca_get_port_id(void)
{
    return LLB_DOCA_ERR_NOTSUP;
}

int llb_doca_get_port_mac(uint8_t mac_out[6])
{
    (void)mac_out;
    return LLB_DOCA_ERR_NOTSUP;
}

int llb_doca_get_port_count(void)
{
    return 0;
}

int llb_doca_get_port_mac_by_id(uint16_t port_id, uint8_t mac_out[6])
{
    (void)port_id;
    (void)mac_out;
    return LLB_DOCA_ERR_NOTSUP;
}

int llb_doca_get_port_ifindex(uint16_t port_id, unsigned int *ifindex_out)
{
    (void)port_id;
    (void)ifindex_out;
    return LLB_DOCA_ERR_NOTSUP;
}

llb_doca_pipe_handle_t llb_doca_pipe_create_basic(
    const char *name,
    uint32_t match_dst_ip_mask,
    uint16_t match_dst_port_mask,
    uint32_t match_src_ip_mask,
    uint16_t match_src_port_mask,
    uint8_t  match_proto,
    int fwd_type,
    uint16_t fwd_port_id,
    uint32_t nr_entries)
{
    (void)name;
    (void)match_dst_ip_mask;
    (void)match_dst_port_mask;
    (void)match_src_ip_mask;
    (void)match_src_port_mask;
    (void)match_proto;
    (void)fwd_type;
    (void)fwd_port_id;
    (void)nr_entries;
    return NULL;
}

llb_doca_pipe_handle_t llb_doca_get_root_pipe(void)
{
    return NULL;
}

llb_doca_pipe_handle_t llb_doca_get_ct_fwd_pipe(void)
{
    return NULL;
}

llb_doca_pipe_handle_t llb_doca_get_udp_ct_pipe(void)
{
    return NULL;
}

/* Stub for non-DOCA builds; accepts V1 and V2 cfg transparently since
 * no logic depends on cfg contents. The ABI bump from V1->V2 (Phase 47 D-04:
 * appended miss_pipe_override field) is source-compatible -- the typedef name
 * is unchanged and (void)cfg; ignores the extra byte. Tests rely on the stub
 * loudly returning NOTSUP; do NOT change to OK. */
int llb_doca_rebuild_root_pipe(const llb_doca_root_pipe_cfg *cfg)
{
    (void)cfg;
    return LLB_DOCA_ERR_NOTSUP;
}

/* Phase 36: FDB L2 pipe stubs */

llb_doca_pipe_handle_t llb_doca_fdb_pipe_create(uint32_t nr_entries)
{
    (void)nr_entries;
    return NULL;
}

llb_doca_entry_handle_t llb_doca_fdb_entry_add(
    llb_doca_pipe_handle_t pipe,
    const uint8_t dst_mac[6],
    uint16_t fwd_port_id,
    uint32_t aging_sec,
    uint64_t user_ctx,
    uint32_t timeout_ms)
{
    (void)pipe;
    (void)dst_mac;
    (void)fwd_port_id;
    (void)aging_sec;
    (void)user_ctx;
    (void)timeout_ms;
    return NULL;
}

llb_doca_pipe_handle_t llb_doca_get_fdb_pipe(void)
{
    return NULL;
}

/* Phase 37: ACL deny pipe stubs */

llb_doca_pipe_handle_t llb_doca_acl_pipe_create(
    uint32_t src_ip_mask, uint32_t dst_ip_mask,
    uint16_t src_port_mask, uint16_t dst_port_mask,
    llb_doca_pipe_handle_t miss_target, uint32_t nr_entries)
{
    (void)src_ip_mask; (void)dst_ip_mask;
    (void)src_port_mask; (void)dst_port_mask;
    (void)miss_target; (void)nr_entries;
    return NULL;
}

llb_doca_entry_handle_t llb_doca_acl_entry_add(
    llb_doca_pipe_handle_t pipe,
    uint32_t src_ip, uint32_t dst_ip,
    uint16_t src_port, uint16_t dst_port,
    uint32_t timeout_ms)
{
    (void)pipe; (void)src_ip; (void)dst_ip;
    (void)src_port; (void)dst_port; (void)timeout_ms;
    return NULL;
}

void llb_doca_set_acl_pipe(llb_doca_pipe_handle_t pipe) { (void)pipe; }

llb_doca_pipe_handle_t llb_doca_get_acl_pipe(void) { return NULL; }

void llb_doca_acl_pipe_destroy(llb_doca_pipe_handle_t pipe) { (void)pipe; }
void llb_doca_acl_query_all(void) {}

/* Phase 37: L4 dispatch pipe stubs */

llb_doca_pipe_handle_t llb_doca_l4_dispatch_pipe_create(void) { return NULL; }

llb_doca_pipe_handle_t llb_doca_get_l4_dispatch_pipe(void) { return NULL; }

int llb_doca_pipe_destroy(llb_doca_pipe_handle_t pipe)
{
    (void)pipe;
    return LLB_DOCA_ERR_NOTSUP;
}

llb_doca_entry_handle_t llb_doca_entry_add_basic(
    llb_doca_pipe_handle_t pipe,
    uint32_t dst_ip,
    uint16_t dst_port,
    uint32_t src_ip,
    uint16_t src_port,
    uint32_t new_dst_ip,
    uint16_t new_dst_port,
    uint32_t new_src_ip,
    uint16_t new_src_port,
    uint8_t  new_dst_mac[6],
    uint8_t  new_src_mac[6],
    uint32_t timeout_ms,
    uint8_t  match_proto,
    uint16_t fwd_port_id,
    uint32_t aging_sec,
    uint64_t user_ctx,
    uint32_t meter_id)
{
    (void)pipe;
    (void)dst_ip;
    (void)dst_port;
    (void)src_ip;
    (void)src_port;
    (void)new_dst_ip;
    (void)new_dst_port;
    (void)new_src_ip;
    (void)new_src_port;
    (void)new_dst_mac;
    (void)new_src_mac;
    (void)timeout_ms;
    (void)match_proto;
    (void)fwd_port_id;
    (void)aging_sec;
    (void)user_ctx;
    (void)meter_id;
    /* Phase 63-06 (D-12): out_es_entry out-param dropped along with the
     * paired g_egress_steer entry pattern (Plan 63-04 deleted the pipe;
     * Plan 63-02's g_egress_dispatch handles per-port FWD via static
     * init-time entries). Stub still returns NULL because DOCA is absent. */
    return NULL;
}

int llb_doca_entry_remove(llb_doca_pipe_handle_t pipe,
                           llb_doca_entry_handle_t entry,
                           uint32_t timeout_ms)
{
    (void)pipe;
    (void)entry;
    (void)timeout_ms;
    return LLB_DOCA_ERR_NOTSUP;
}

int llb_doca_entry_query(llb_doca_entry_handle_t entry,
                          uint64_t *bytes_out,
                          uint64_t *pkts_out)
{
    (void)entry;
    (void)bytes_out;
    (void)pkts_out;
    return LLB_DOCA_ERR_NOTSUP;
}

int llb_doca_aging_poll(uint64_t quota_time, uint32_t timeout_us, uint32_t max_entries)
{
    (void)quota_time;
    (void)timeout_us;
    (void)max_entries;
    return 0;
}

int llb_doca_entries_drain(uint32_t timeout_us, uint32_t max_entries)
{
    (void)timeout_us;
    (void)max_entries;
    return 0;
}

int llb_doca_get_aged_entries(uint64_t *out_ctx, int max_out)
{
    (void)out_ctx;
    (void)max_out;
    return 0;
}

/* Phase 38: Meter classification pipe stubs */

llb_doca_pipe_handle_t llb_doca_meter_pipe_create(
    llb_doca_pipe_handle_t miss_target, uint32_t meter_id, uint32_t nr_entries)
{
    (void)miss_target; (void)meter_id; (void)nr_entries;
    return NULL;
}

llb_doca_entry_handle_t llb_doca_meter_pipe_entry_add(
    llb_doca_pipe_handle_t pipe,
    uint32_t dst_ip, uint32_t timeout_ms)
{
    (void)pipe; (void)dst_ip; (void)timeout_ms;
    return NULL;
}

llb_doca_pipe_handle_t llb_doca_get_meter_pipe(void) { return NULL; }
void llb_doca_set_meter_pipe(llb_doca_pipe_handle_t pipe) { (void)pipe; }

/* Phase 38: Shared meter stubs */

int llb_doca_meter_add(uint32_t meter_id, uint64_t cir_bps, uint64_t cbs, uint64_t ebs)
{
    (void)meter_id;
    (void)cir_bps;
    (void)cbs;
    (void)ebs;
    return LLB_DOCA_ERR_NOTSUP;
}

int llb_doca_meter_del(uint32_t meter_id)
{
    (void)meter_id;
    return LLB_DOCA_ERR_NOTSUP;
}

int llb_doca_meter_query(uint32_t meter_id, struct llb_doca_meter_stats *stats)
{
    (void)meter_id;
    (void)stats;
    return LLB_DOCA_ERR_NOTSUP;
}

int llb_doca_entry_update_meter(llb_doca_pipe_handle_t pipe, void *entry_handle, uint32_t meter_id)
{
    (void)pipe;
    (void)entry_handle;
    (void)meter_id;
    return LLB_DOCA_ERR_NOTSUP;
}
