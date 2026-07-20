/*
 *  llb_kern_synflood.c: loxilb kernel eBPF unified security rate limiting
 *  Copyright (C) 2024,  NetLOX <www.netlox.io>
 *
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 *
 * P0-5 + P0-6 + P0-7: Unified Security Rate Limiting - XDP Layer DDoS Defense
 *
 * This implements XDP-layer unified security rate limiting combining:
 * - P0-5: SYN flood protection (per-source-IP SYN rate limiting)
 * - P0-6: Connection rate limiting (new connections per second)
 * - P0-7: UDP flood protection (per-source-IP UDP packet/bandwidth rate limiting)
 *
 * Design Pattern: Single unified map for all features (optimal memory usage)
 * Performance Target: <2µs per packet at XDP layer
 *
 * Build-time feature flag: HAVE_DP_SECURITY_RATE_LIMIT
 * Enable with: make EXTRA_CFLAGS="-DHAVE_DP_SECURITY_RATE_LIMIT"
 */

#ifndef __LLB_KERN_SYNFLOOD_C
#define __LLB_KERN_SYNFLOOD_C

#include "../common/llb_dpapi.h"

#ifdef HAVE_DP_SECURITY_RATE_LIMIT

// Build-time configuration choice:
// - HAVE_DP_SECURITY_RATE_RUNTIME_CONFIG: Version-based cache (~0.05µs overhead, runtime configurable)
// - Default (no flag): Hardcoded thresholds (0µs overhead, build-time only)

#ifdef HAVE_DP_SECURITY_RATE_RUNTIME_CONFIG
// Runtime configurable thresholds (version-based cache)
#define SYN_FLOOD_THRESHOLD     100  // Default SYNs/sec (overridable via Go API)
#define SYN_COOKIE_THRESHOLD    50   // Default SYN cookie trigger (overridable via Go API)
#define CONN_RATE_THRESHOLD     50   // Default connections/sec (overridable via Go API)
#define UDP_PKT_THRESHOLD       1000 // Default UDP packets/sec (overridable via Go API)
#define UDP_BANDWIDTH_THRESHOLD (100 * 1024 * 1024) // Default 100MB/sec (overridable via Go API)
#else
// Hardcoded thresholds (compile-time constants, zero overhead)
#define SYN_FLOOD_THRESHOLD     100  // Max SYNs per second per IP (FIXED)
#define SYN_COOKIE_THRESHOLD    50   // Enable SYN cookies above this rate (FIXED)
#define CONN_RATE_THRESHOLD     50   // Max connections per second per IP (FIXED)
#define UDP_PKT_THRESHOLD       1000 // Max UDP packets per second per IP (FIXED)
#define UDP_BANDWIDTH_THRESHOLD (100 * 1024 * 1024) // Max 100MB/sec per IP (FIXED)
#endif

// Statistics map indices (unified stats for P0-5 + P0-6 + P0-7)
#define STAT_SYN_BLOCKED        0
#define STAT_SYN_PASSED         1
#define STAT_SYN_COOKIES        2
#define STAT_CONN_BLOCKED       3
#define STAT_CONN_PASSED        4
#define STAT_CONCURRENT_BLOCKED 5  // reserved (concurrent limit removed) - index kept as unwritten hole
#define STAT_UNIQUE_IPS         6
#define STAT_UDP_BLOCKED        7  // P0-7: UDP packets blocked
#define STAT_UDP_PASSED         8  // P0-7: UDP packets passed
#define STAT_UDP_BYTES_BLOCKED  9  // P0-7: UDP bytes blocked
#define STAT_UDP_BYTES_PASSED   10 // P0-7: UDP bytes passed

// Configuration map index
#define CONFIG_INDEX            0

// Time window for rate limiting (1 second in nanoseconds)
#define RATE_WINDOW_NS          1000000000ULL

#ifdef HAVE_DP_SECURITY_RATE_RUNTIME_CONFIG
/*
 * RUNTIME CONFIG MODE
 * Per-CPU cached configuration (avoids repeated map lookups)
 * Updated only when version changes
 * Performance: ~0.05µs overhead (version check only)
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct dp_security_rate_config);
    __uint(max_entries, 1);
} security_rate_config_cache SEC(".maps");

/*
 * Helper: Get current unified configuration with version-based caching
 *
 * Performance optimization:
 * - Checks version number (single u32 read from config map)
 * - Reloads config only if version changed
 * - Typical overhead: ~0.05µs (just version check)
 * - Config reload overhead: ~0.2µs (only when config updates)
 *
 * Returns thresholds via pointers
 */
static void __always_inline
dp_get_security_rate_config(__u32 *syn_threshold, __u32 *cookie_threshold,
                             __u32 *conn_rate_threshold,
                             __u32 *syn_enabled, __u32 *conn_enabled,
                             __u32 *udp_pkt_threshold, __u32 *udp_bandwidth_threshold,
                             __u32 *udp_enabled)
{
    __u32 cfg_key = CONFIG_INDEX;
    struct dp_security_rate_config *config;
    struct dp_security_rate_config *cached;

    // Get cached config (per-CPU, fast)
    cached = bpf_map_lookup_elem(&security_rate_config_cache, &cfg_key);
    if (!cached) {
        // Cache not available, use defaults (all protection OFF until configured)
        *syn_threshold = SYN_FLOOD_THRESHOLD;
        *cookie_threshold = SYN_COOKIE_THRESHOLD;
        *conn_rate_threshold = CONN_RATE_THRESHOLD;
        *syn_enabled = 0;
        *conn_enabled = 0;
        *udp_pkt_threshold = UDP_PKT_THRESHOLD;
        *udp_bandwidth_threshold = UDP_BANDWIDTH_THRESHOLD;
        *udp_enabled = 0;
        return;
    }

    // Lookup main config to check version
    config = bpf_map_lookup_elem(&sec_rate_cfg, &cfg_key);
    if (!config) {
        // No config set, use cached or defaults
        if (cached->version > 0) {
            *syn_threshold = cached->syn_threshold;
            *cookie_threshold = cached->cookie_threshold;
            *conn_rate_threshold = cached->conn_rate_threshold;
            *syn_enabled = cached->syn_enabled;
            *conn_enabled = cached->conn_rate_enabled;
            *udp_pkt_threshold = cached->udp_pkt_threshold;
            *udp_bandwidth_threshold = cached->udp_bandwidth_threshold;
            *udp_enabled = cached->udp_enabled;
        } else {
            *syn_threshold = SYN_FLOOD_THRESHOLD;
            *cookie_threshold = SYN_COOKIE_THRESHOLD;
            *conn_rate_threshold = CONN_RATE_THRESHOLD;
            *syn_enabled = 0;
            *conn_enabled = 0;
            *udp_pkt_threshold = UDP_PKT_THRESHOLD;
            *udp_bandwidth_threshold = UDP_BANDWIDTH_THRESHOLD;
            *udp_enabled = 0;
        }
        return;
    }

    // BUG FIX: Treat version=0 as uninitialized (use defaults instead of zeros)
    // Check if config version changed AND version > 0 (cache invalidation)
    if (config->version > 0 && config->version != cached->version) {
        // Config updated - reload cache
        cached->version = config->version;
        cached->syn_threshold = config->syn_threshold;
        cached->cookie_threshold = config->cookie_threshold;
        cached->conn_rate_threshold = config->conn_rate_threshold;
        cached->syn_enabled = config->syn_enabled;
        cached->conn_rate_enabled = config->conn_rate_enabled;
        cached->udp_pkt_threshold = config->udp_pkt_threshold;
        cached->udp_bandwidth_threshold = config->udp_bandwidth_threshold;
        cached->udp_enabled = config->udp_enabled;
    } else if (config->version == 0) {
        // version=0 means uninitialized - use defaults (protection OFF)
        *syn_threshold = SYN_FLOOD_THRESHOLD;
        *cookie_threshold = SYN_COOKIE_THRESHOLD;
        *conn_rate_threshold = CONN_RATE_THRESHOLD;
        *syn_enabled = 0;
        *conn_enabled = 0;
        *udp_pkt_threshold = UDP_PKT_THRESHOLD;
        *udp_bandwidth_threshold = UDP_BANDWIDTH_THRESHOLD;
        *udp_enabled = 0;
        return;
    }

    // Return cached values (always up-to-date)
    *syn_threshold = cached->syn_threshold;
    *cookie_threshold = cached->cookie_threshold;
    *conn_rate_threshold = cached->conn_rate_threshold;
    *syn_enabled = cached->syn_enabled;
    *conn_enabled = cached->conn_rate_enabled;
    *udp_pkt_threshold = cached->udp_pkt_threshold;
    *udp_bandwidth_threshold = cached->udp_bandwidth_threshold;
    *udp_enabled = cached->udp_enabled;
}
#else
/*
 * HARDCODED MODE (zero overhead)
 * Thresholds are compile-time constants
 * No runtime configuration support
 * Performance: 0µs overhead (compiler inlines constants)
 */
static void __always_inline
dp_get_security_rate_config(__u32 *syn_threshold, __u32 *cookie_threshold,
                             __u32 *conn_rate_threshold,
                             __u32 *syn_enabled, __u32 *conn_enabled,
                             __u32 *udp_pkt_threshold, __u32 *udp_bandwidth_threshold,
                             __u32 *udp_enabled)
{
    // Hardcoded values - compiler will optimize this away completely
    *syn_threshold = SYN_FLOOD_THRESHOLD;
    *cookie_threshold = SYN_COOKIE_THRESHOLD;
    *conn_rate_threshold = CONN_RATE_THRESHOLD;
    *syn_enabled = 0;      // Disabled by default until configured
    *conn_enabled = 0;     // Disabled by default
    *udp_pkt_threshold = UDP_PKT_THRESHOLD;
    *udp_bandwidth_threshold = UDP_BANDWIDTH_THRESHOLD;
    *udp_enabled = 0;      // Disabled by default
}
#endif /* HAVE_DP_SECURITY_RATE_RUNTIME_CONFIG */

/*
 * Helper: Update global statistics (unified stats for P0-5 + P0-6 + P0-7)
 *
 * Pattern: Simple atomic updates like P0-7 packets/bytes counters
 * Performance: <0.1µs per update
 */
static void __always_inline
dp_update_security_stats(__u32 stat_type, __u64 increment)
{
    __u64 *counter = bpf_map_lookup_elem(&sec_rate_stats, &stat_type);
    if (counter) {
        // Simple atomic update (like P0-7 pattern)
        __sync_fetch_and_add(counter, increment);
    } else {
        BPF_DBG_PRINTK("[XDP-SECURITY-STATS-DEBUG] FAILED to lookup stat_type=%u in sec_rate_stats map\n", stat_type);
    }
}

/*
 * IPv4 Unified Security Rate Check Function
 *
 * Integration: Called from dp_do_security_rate_main_xdp() for IPv4 packets
 * Pattern: Unified tracking for P0-5 SYN flood + P0-6 connection rate + P0-7 UDP flood
 *
 * Key Pattern: DIRECT ASSIGNMENT (not byte-by-byte like P0-7 LPM_TRIE)
 * Rationale: LRU_HASH with __u32 key doesn't need byte array extraction
 *
 * Performance: <2µs per packet
 *
 * Returns: XDP_DROP (blocked) or XDP_PASS (allowed)
 */
static int __always_inline
dp_do_security_rate_check_v4_xdp(struct xdp_md *ctx, struct xfi *xf, int is_syn, int is_udp)
{
    struct dp_security_rate_state *state;
    struct dp_security_rate_state new_state;
    __u32 key;
    __u64 now_ns;
    __u32 now_sec;
    __u32 window_elapsed;
    __u32 syn_threshold, cookie_threshold, conn_rate_threshold;
    __u32 syn_enabled, conn_enabled;
    __u32 udp_pkt_threshold, udp_bandwidth_threshold, udp_enabled;

    // Get runtime configuration
    dp_get_security_rate_config(&syn_threshold, &cookie_threshold,
                                &conn_rate_threshold,
                                &syn_enabled, &conn_enabled,
                                &udp_pkt_threshold, &udp_bandwidth_threshold,
                                &udp_enabled);

    // DEBUG: Log UDP config and packet info
    // BPF_DBG_PRINTK("[XDP-SECURITY-UDP-DEBUG] is_udp=%d, udp_enabled=%u, udp_pkt_thr=%u, udp_bw_thr=%u\n",
    //                is_udp, udp_enabled, udp_pkt_threshold, udp_bandwidth_threshold);

    // CRITICAL: Validate that L3/L4 parsing was successful
    // Without this check, xf->l34m.saddr4 might contain garbage data
    if (!xf->l34m.valid) {
        return XDP_PASS;  // Skip security check for unparsed packets
    }

    // Direct key assignment (simpler than P0-7 byte extraction)
    // Pattern: Native __u32 for exact IP match (not CIDR)
    key = xf->l34m.saddr4;  // Already in network byte order
    
    // Sanity check: Reject obviously invalid IPs (0.0.0.0, 255.255.255.255)
    if (key == 0 || key == 0xFFFFFFFF) {
        return XDP_PASS;  // Skip security check for invalid IPs
    }

    // WHITELIST BYPASS: Check if source IP is whitelisted (P0-7 integration)
    // Whitelisted IPs bypass ALL rate limiting (both SYN flood and connection rate)
    // Pattern: Same as P0-7 IP filter whitelist check
    struct dp_ip_filter_key wl_key;
    struct dp_ip_filter_rule *wl_rule;
    
    memset(&wl_key, 0, sizeof(wl_key));
    wl_key.prefixlen = 32;  // /32 for exact match, LPM finds longest prefix
    
    // CRITICAL: Convert saddr from network byte order to host byte order first!
    // iph->saddr is in network byte order (big-endian), but we need host order for byte extraction
    __u32 saddr_host = bpf_ntohl(xf->l34m.saddr4);
    wl_key.data[0] = (saddr_host >> 24) & 0xFF;  // First byte (MSB)
    wl_key.data[1] = (saddr_host >> 16) & 0xFF;  // Second byte
    wl_key.data[2] = (saddr_host >> 8) & 0xFF;   // Third byte
    wl_key.data[3] = saddr_host & 0xFF;          // Fourth byte (LSB)
    
    BPF_DBG_PRINTK("[XDP-SECURITY] Whitelist lookup: src_net=0x%x src_host=0x%x, key_bytes=[%d.%d.%d.%d], prefixlen=%d\n",
                   xf->l34m.saddr4, saddr_host, wl_key.data[0], wl_key.data[1], wl_key.data[2], wl_key.data[3], wl_key.prefixlen);
    
    wl_rule = bpf_map_lookup_elem(&ip_whitelist_map, &wl_key);
    if (wl_rule) {
        BPF_DBG_PRINTK("[XDP-SECURITY] Whitelist HIT: action=%d, zone=%d, priority=%d, packets=%llu\n",
                       wl_rule->action, wl_rule->zone, wl_rule->priority, wl_rule->packets);
    } else {
        BPF_DBG_PRINTK("[XDP-SECURITY] Whitelist MISS: no entry found\n");
    }
    
    if (wl_rule && wl_rule->action == 0) {  // action=0 means ALLOW
        // IP is whitelisted - bypass all rate limiting.
        // NOTE: no stat update here - the ipfilter stage already counted this
        // packet against the whitelist rule; incrementing again double-counts
        // (and the old read-modify-write here raced with ipfilter's atomics).
        BPF_DBG_PRINTK("[XDP-SECURITY] ✓ IPv4 WHITELIST BYPASS: src=0x%x\n", saddr_host);
        return XDP_PASS;  // Allow whitelisted IP without rate limiting
    }

    // Get current time for window tracking (convert ns to seconds)
    now_ns = bpf_ktime_get_ns();
    now_sec = (__u32)(now_ns / 1000000000ULL);

    // Lookup existing state
    state = bpf_map_lookup_elem(&sec_rate_v4, &key);
    
    if (state) {
        // Existing tracking entry - use atomic updates (IP filter pattern)
        // No spinlock needed - minor race conditions acceptable for rate limiting
        
        // P0-5: SYN Flood Check
        if (syn_enabled && is_syn) {
            window_elapsed = now_sec - state->syn_timestamp;

            if (window_elapsed >= 1) {
                // New window - reset SYN counter (race condition acceptable)
                state->syn_timestamp = now_sec;
                state->syn_count = 1;
            } else {
                // Same window - atomic increment (IP filter pattern)
                // BPF requires 64-bit atomic operations
                __u64 current_count = __sync_fetch_and_add(&state->syn_count, 1);

                // Check SYN threshold (use fetched value before increment)
                if (current_count + 1 > (__u64)syn_threshold) {
                    BPF_DBG_PRINTK("[XDP-SECURITY] IPv4 SYN DROP: src=0x%x count=%llu threshold=%u\n",
                                   bpf_ntohl(key), current_count + 1, syn_threshold);
                    
                    dp_update_security_stats(STAT_SYN_BLOCKED, 1);
                    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_ACT_DROP);
                    return XDP_DROP;
                } else if (current_count + 1 > cookie_threshold) {
                    // Above cookie threshold - mark for SYN cookies
                    BPF_DBG_PRINTK("[XDP-SECURITY] IPv4 SYN COOKIE: src=0x%x count=%llu\n",
                                   bpf_ntohl(key), current_count + 1);
                    dp_update_security_stats(STAT_SYN_COOKIES, 1);
                }
            }
        }

        // P0-6: Connection Rate Check (only for SYN packets - new connections)
        // BUG FIX: Only count SYN packets as new connections
        // Previously: counted every packet, causing false positives
        if (conn_enabled && is_syn) {
            // Read current timestamp
            __u64 current_timestamp = state->conn_timestamp;
            window_elapsed = now_sec - current_timestamp;
            __u64 current_count;  // Declare here for use in both NEW WINDOW and SAME WINDOW blocks

            if (window_elapsed >= 1) {
                // New window - use atomic CAS on timestamp to ensure only ONE CPU resets the counter
                // This prevents multiple CPUs from all resetting to 0 and incrementing CONN_PASSED
                // BUG FIX: Retry CAS if window changed again between CAS and fallback logic
                __u64 expected_timestamp = current_timestamp;
                __u64 old_timestamp = __sync_val_compare_and_swap(&state->conn_timestamp, expected_timestamp, (__u64)now_sec);

                if (old_timestamp == expected_timestamp) {
                    // WE won the race - we are the ONLY CPU to reset the counter
                    __u64 old_count = state->conn_count;
                    (void)old_count; /* Used only in debug builds */

                    BPF_DBG_PRINTK("[XDP-SECURITY-DEBUG] IPv4 NEW WINDOW: src=0x%x old_count=%llu timestamp=%u->%u [FIRST CPU - RESETTING]\n",
                                   bpf_ntohl(key), old_count, current_timestamp, now_sec);

                    // Reset counter to 1 atomically (we are connection #1 in new window)
                    __sync_lock_test_and_set(&state->conn_count, 1);
                    current_count = 0;  // We got count=0 before our increment to 1

                    // Check threshold=0 case
                    if (conn_rate_threshold == 0) {
                        __sync_lock_test_and_set(&state->conn_count, 0);
                        BPF_DBG_PRINTK("[XDP-SECURITY-DEBUG] IPv4 CONN RATE DROP: src=0x%x count=1 threshold=0 [BLOCKED]\n",
                                       bpf_ntohl(key));
                        dp_update_security_stats(STAT_CONN_BLOCKED, 1);
                        LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_ACT_DROP);
                        return XDP_DROP;
                    }
                } else {
                    // Another CPU already updated timestamp - re-check window status
                    // BUG FIX: Timestamp may have been updated AGAIN, need to re-verify window
                    BPF_DBG_PRINTK("[XDP-SECURITY-DEBUG] IPv4 NEW WINDOW RACE: src=0x%x timestamp already updated by another CPU\n",
                                   bpf_ntohl(key));

                    // Re-read timestamp to check current window status
                    __u64 updated_timestamp = state->conn_timestamp;
                    __u32 updated_elapsed = now_sec - updated_timestamp;

                    if (updated_elapsed >= 1) {
                        // Window STILL expired after CAS failure - window changed AGAIN
                        // This means another CPU reset WHILE we were checking
                        // Retry CAS to attempt reset (limit retries to prevent infinite loop)
                        BPF_DBG_PRINTK("[XDP-SECURITY-DEBUG] IPv4 WINDOW STILL EXPIRED: src=0x%x elapsed=%u, retrying CAS\n",
                                       bpf_ntohl(key), updated_elapsed);

                        // One retry attempt
                        expected_timestamp = updated_timestamp;
                        old_timestamp = __sync_val_compare_and_swap(&state->conn_timestamp, expected_timestamp, (__u64)now_sec);

                        if (old_timestamp == expected_timestamp) {
                            // Won on retry - reset counter
                            __sync_lock_test_and_set(&state->conn_count, 1);
                            current_count = 0;

                            if (conn_rate_threshold == 0) {
                                __sync_lock_test_and_set(&state->conn_count, 0);
                                dp_update_security_stats(STAT_CONN_BLOCKED, 1);
                                LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_ACT_DROP);
                                return XDP_DROP;
                            }
                        } else {
                            // Lost retry - treat as same window (another CPU won)
                            current_count = __sync_fetch_and_add(&state->conn_count, 1);

                            if (current_count >= (__u64)conn_rate_threshold) {
                                __sync_fetch_and_sub(&state->conn_count, 1);
                                dp_update_security_stats(STAT_CONN_BLOCKED, 1);
                                LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_ACT_DROP);
                                return XDP_DROP;
                            }
                        }
                    } else {
                        // Window is now valid (another CPU successfully reset it)
                        // Treat as SAME WINDOW - increment normally
                        current_count = __sync_fetch_and_add(&state->conn_count, 1);

                        BPF_DBG_PRINTK("[XDP-SECURITY-DEBUG] IPv4 SAME WINDOW (after race): src=0x%x count=%llu->%llu threshold=%u\n",
                                       bpf_ntohl(key), current_count, current_count + 1, conn_rate_threshold);

                        // Check if we exceeded threshold
                        if (current_count >= (__u64)conn_rate_threshold) {
                            // Exceeded threshold - revert and drop
                            __sync_fetch_and_sub(&state->conn_count, 1);
                            BPF_DBG_PRINTK("[XDP-SECURITY-DEBUG] IPv4 CONN RATE DROP: src=0x%x old_count=%llu threshold=%u [BLOCKED - REVERTED]\n",
                                           bpf_ntohl(key), current_count, conn_rate_threshold);
                            dp_update_security_stats(STAT_CONN_BLOCKED, 1);
                            LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_ACT_DROP);
                            return XDP_DROP;
                        }
                    }
                }
            } else {
                // Same window - atomic increment and check
                // CRITICAL: We increment first, then check if we EXCEEDED the limit
                // If we did, we need to decrement back and drop the packet
                current_count = __sync_fetch_and_add(&state->conn_count, 1);

                BPF_DBG_PRINTK("[XDP-SECURITY-DEBUG] IPv4 SAME WINDOW: src=0x%x count=%llu->%llu threshold=%u\n",
                               bpf_ntohl(key), current_count, current_count + 1, conn_rate_threshold);

                // Check if the OLD count (before increment) was already at threshold
                // This means our increment pushed us OVER the limit
                if (current_count >= (__u64)conn_rate_threshold) {
                    // We exceeded the limit - decrement back and drop
                    __sync_fetch_and_sub(&state->conn_count, 1);
                    
                    BPF_DBG_PRINTK("[XDP-SECURITY-DEBUG] IPv4 CONN RATE DROP: src=0x%x old_count=%llu threshold=%u [BLOCKED - REVERTED]\n",
                                   bpf_ntohl(key), current_count, conn_rate_threshold);
                    
                    dp_update_security_stats(STAT_CONN_BLOCKED, 1);
                    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_ACT_DROP);
                    return XDP_DROP;
                }
            }

            BPF_DBG_PRINTK("[XDP-SECURITY-DEBUG] IPv4 CONN PASSED: src=0x%x conn_count=%llu [INCREMENTING CONN_PASSED]\n",
                           bpf_ntohl(key), state->conn_count);
            dp_update_security_stats(STAT_CONN_PASSED, 1);
        }
        

        // Count the SYN as passed only after it survived BOTH the SYN-rate
        // and connection-rate checks; counting before the conn-rate drop made
        // passed+blocked exceed total SYNs.
        if (syn_enabled && is_syn) {
            dp_update_security_stats(STAT_SYN_PASSED, 1);
        }

        // P0-7: UDP Flood Check
        if (udp_enabled && is_udp) {
            // BPF_DBG_PRINTK("[XDP-SECURITY-UDP-DEBUG] Processing UDP packet: src=0x%x now_sec=%u udp_timestamp=%u\n",
            //                bpf_ntohl(key), now_sec, state->udp_timestamp);
            window_elapsed = now_sec - state->udp_timestamp;
            // BPF_DBG_PRINTK("[XDP-SECURITY-UDP-DEBUG] window_elapsed=%u (threshold: 1 second)\n", window_elapsed);

            if (window_elapsed >= 1) {
                // New window - reset UDP counters
                state->udp_timestamp = now_sec;
                state->udp_pkt_count = 1;
                state->udp_byte_count = xf->pm.l3_len;
                BPF_DBG_PRINTK("[XDP-SECURITY-UDP-DEBUG] New window: reset counters (pkt=1, bytes=%u)\n", xf->pm.l3_len);
            } else {
                // Same window - atomic increment for both packets and bytes
                __u64 current_pkt_count = __sync_fetch_and_add(&state->udp_pkt_count, 1);
                __u64 current_byte_count = __sync_fetch_and_add(&state->udp_byte_count, xf->pm.l3_len);
                // Check UDP packet rate threshold
                if (current_pkt_count + 1 > (__u64)udp_pkt_threshold) {                    
                    dp_update_security_stats(STAT_UDP_BLOCKED, 1);
                    dp_update_security_stats(STAT_UDP_BYTES_BLOCKED, xf->pm.l3_len);
                    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_ACT_DROP);
                    return XDP_DROP;
                }

                // Check UDP bandwidth threshold
                if (current_byte_count + xf->pm.l3_len > (__u64)udp_bandwidth_threshold) {
                    
                    dp_update_security_stats(STAT_UDP_BLOCKED, 1);
                    dp_update_security_stats(STAT_UDP_BYTES_BLOCKED, xf->pm.l3_len);
                    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_ACT_DROP);
                    return XDP_DROP;
                }
            }
            dp_update_security_stats(STAT_UDP_PASSED, 1);
            dp_update_security_stats(STAT_UDP_BYTES_PASSED, xf->pm.l3_len);
        }
        
    } else {
        // New source IP - only create entry if:
        // 1. This is a SYN packet (for SYN flood protection), OR
        // 2. Connection rate limiting is enabled (track all TCP connections), OR
        // 3. This is a UDP packet and UDP flood protection is enabled
        if (!is_syn && !conn_enabled && (!is_udp || !udp_enabled)) {
            // Skip tracking: non-SYN TCP, conn rate disabled, and (non-UDP or UDP protection disabled)
            return XDP_PASS;
        }

        // Create new tracking entry
        // BUG FIX: Only count SYN packets for connection rate tracking
        __builtin_memset(&new_state, 0, sizeof(new_state));
        new_state.syn_timestamp = now_sec;
        new_state.syn_count = is_syn ? 1 : 0;
        new_state.conn_timestamp = now_sec;
        new_state.conn_count = is_syn ? 1 : 0;  // Only count SYNs as new connections
        new_state.udp_timestamp = now_sec;
        new_state.udp_pkt_count = is_udp ? 1 : 0;
        new_state.udp_byte_count = is_udp ? xf->pm.l3_len : 0;
        new_state.flags = 0;

        // Insert into LRU map (auto-evicts old entries)
        int ret = bpf_map_update_elem(&sec_rate_v4, &key, &new_state, BPF_ANY);
        if (ret != 0) {
            // Map full or error - allow packet (fail open)
            BPF_DBG_PRINTK("[XDP-SECURITY] IPv4 map update failed: ret=%d\n", ret);
        }
        // Note: uniqueIps counter is calculated by Go control plane via map iteration
        // (no eBPF counter needed - avoids monotonic increase bug on LRU eviction)

        if (is_syn && syn_enabled) {
            dp_update_security_stats(STAT_SYN_PASSED, 1);
        }
        if (conn_enabled && is_syn) {  // BUG FIX: Only count SYN packets
            BPF_DBG_PRINTK("[XDP-SECURITY-DEBUG] IPv4 NEW IP CONN PASSED: src=0x%x [NEW TRACKING ENTRY][INCREMENTING CONN_PASSED]\n",
                           bpf_ntohl(key));
            dp_update_security_stats(STAT_CONN_PASSED, 1);
        }
        if (is_udp && udp_enabled) {
            BPF_DBG_PRINTK("[XDP-SECURITY-UDP-DEBUG] NEW IP UDP PASSED: src=0x%x [NEW TRACKING ENTRY] updating stats (pkt=1, bytes=%u)\n",
                           bpf_ntohl(key), xf->pm.l3_len);
            dp_update_security_stats(STAT_UDP_PASSED, 1);
            dp_update_security_stats(STAT_UDP_BYTES_PASSED, xf->pm.l3_len);
        }
    }
    return XDP_PASS;
}

/*
 * IPv6 Unified Security Rate Check Function
 *
 * Integration: Called from dp_do_security_rate_main_xdp() for IPv6 packets
 * Pattern: Same as IPv4 but with struct in6_addr key
 *
 * Key Pattern: Use __builtin_memcpy for IPv6 address (128-bit)
 * Performance: <2µs per packet
 *
 * Returns: XDP_DROP (blocked) or XDP_PASS (allowed)
 */
static int __always_inline
dp_do_security_rate_check_v6_xdp(struct xdp_md *ctx, struct xfi *xf, int is_syn, int is_udp)
{
    struct dp_security_rate_state *state;
    struct dp_security_rate_state new_state;
    struct in6_addr key;
    __u64 now_ns;
    __u32 now_sec;
    __u32 window_elapsed;
    __u32 syn_threshold, cookie_threshold, conn_rate_threshold;
    __u32 syn_enabled, conn_enabled;
    __u32 udp_pkt_threshold, udp_bandwidth_threshold, udp_enabled;

    // Get runtime configuration
    dp_get_security_rate_config(&syn_threshold, &cookie_threshold,
                                &conn_rate_threshold,
                                &syn_enabled, &conn_enabled,
                                &udp_pkt_threshold, &udp_bandwidth_threshold,
                                &udp_enabled);

    // CRITICAL: Validate that L3/L4 parsing was successful
    if (!xf->l34m.valid) {
        return XDP_PASS;  // Skip security check for unparsed packets
    }

    // Copy IPv6 address to key (native struct in6_addr)
    __builtin_memcpy(&key, xf->l34m.saddr, sizeof(struct in6_addr));

    // WHITELIST BYPASS: Check if source IPv6 is whitelisted (P0-7 integration)
    // Whitelisted IPs bypass ALL rate limiting (both SYN flood and connection rate)
    // Pattern: Same as P0-7 IP filter whitelist check
    struct dp_ip_filter_key wl_key;
    struct dp_ip_filter_rule *wl_rule;
    
    memset(&wl_key, 0, sizeof(wl_key));
    wl_key.prefixlen = 128;  // IPv6 /128 for exact match, LPM finds longest prefix
    
    // Copy IPv6 address into data byte array (P0-7 pattern)
    *((__u32 *)&wl_key.data[0]) = xf->l34m.saddr[0];
    *((__u32 *)&wl_key.data[4]) = xf->l34m.saddr[1];
    *((__u32 *)&wl_key.data[8]) = xf->l34m.saddr[2];
    *((__u32 *)&wl_key.data[12]) = xf->l34m.saddr[3];
    
    /* v6 sources must be checked against the v6 trie - the v4 trie would
     * cross-family match short IPv4 prefixes against IPv6 sources. */
    wl_rule = bpf_map_lookup_elem(&ip_whitelist6_map, &wl_key);
    if (wl_rule && wl_rule->action == 0) {  // action=0 means ALLOW
        // IP is whitelisted - bypass all rate limiting.
        // NOTE: no stat update here - the ipfilter stage already counted this
        // packet against the whitelist rule (see IPv4 path).
        BPF_DBG_PRINTK("[XDP-SECURITY] IPv6 WHITELIST BYPASS\n");
        return XDP_PASS;  // Allow whitelisted IP without rate limiting
    }

    // Get current time (convert ns to seconds)
    now_ns = bpf_ktime_get_ns();
    now_sec = (__u32)(now_ns / 1000000000ULL);

    // Lookup existing state
    state = bpf_map_lookup_elem(&sec_rate_v6, &key);
    
    if (state) {
        // Existing tracking entry - use atomic updates (IP filter pattern)
        // No spinlock needed - minor race conditions acceptable for rate limiting
        
        // P0-5: SYN Flood Check
        if (syn_enabled && is_syn) {
            window_elapsed = now_sec - state->syn_timestamp;

            if (window_elapsed >= 1) {
                state->syn_timestamp = now_sec;
                state->syn_count = 1;
            } else {
                __u64 current_count = __sync_fetch_and_add(&state->syn_count, 1);

                if (current_count + 1 > (__u64)syn_threshold) {
                    BPF_DBG_PRINTK("[XDP-SECURITY] IPv6 SYN DROP: count=%llu\n", current_count + 1);
                    dp_update_security_stats(STAT_SYN_BLOCKED, 1);
                    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_ACT_DROP);
                    return XDP_DROP;
                } else if (current_count + 1 > cookie_threshold) {
                    BPF_DBG_PRINTK("[XDP-SECURITY] IPv6 SYN COOKIE: count=%llu\n", current_count + 1);
                    dp_update_security_stats(STAT_SYN_COOKIES, 1);
                }
            }
        }
        
        // P0-6: Connection Rate Check (only for SYN packets - new connections)
        // BUG FIX: Only count SYN packets as new connections
        if (conn_enabled && is_syn) {
            __u64 current_timestamp = state->conn_timestamp;
            window_elapsed = now_sec - current_timestamp;
            __u64 current_count;

            if (window_elapsed >= 1) {
                // New window - use atomic CAS on timestamp to ensure only ONE CPU resets the counter
                // BUG FIX: Retry CAS if window changed again between CAS and fallback logic
                __u64 expected_timestamp = current_timestamp;
                __u64 old_timestamp = __sync_val_compare_and_swap(&state->conn_timestamp, expected_timestamp, (__u64)now_sec);

                if (old_timestamp == expected_timestamp) {
                    // WE won the race - we are the ONLY CPU to reset the counter
                    __u64 old_count = state->conn_count;
                    (void)old_count; /* Used only in debug builds */

                    BPF_DBG_PRINTK("[XDP-SECURITY-DEBUG] IPv6 NEW WINDOW: old_count=%llu timestamp=%u->%u [FIRST CPU - RESETTING]\n",
                                   old_count, current_timestamp, now_sec);

                    // Reset counter to 1 atomically (we are connection #1 in new window)
                    __sync_lock_test_and_set(&state->conn_count, 1);
                    current_count = 0;  // We got count=0 before our increment to 1

                    // Check threshold=0 case
                    if (conn_rate_threshold == 0) {
                        __sync_lock_test_and_set(&state->conn_count, 0);
                        BPF_DBG_PRINTK("[XDP-SECURITY-DEBUG] IPv6 CONN RATE DROP: count=1 threshold=0 [BLOCKED]\n");
                        dp_update_security_stats(STAT_CONN_BLOCKED, 1);
                        LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_ACT_DROP);
                        return XDP_DROP;
                    }
                } else {
                    // Another CPU already updated timestamp - re-check window status
                    // BUG FIX: Timestamp may have been updated AGAIN, need to re-verify window
                    BPF_DBG_PRINTK("[XDP-SECURITY-DEBUG] IPv6 NEW WINDOW RACE: timestamp already updated by another CPU\n");

                    // Re-read timestamp to check current window status
                    __u64 updated_timestamp = state->conn_timestamp;
                    __u32 updated_elapsed = now_sec - updated_timestamp;

                    if (updated_elapsed >= 1) {
                        // Window STILL expired after CAS failure - window changed AGAIN
                        // Retry CAS to attempt reset (limit retries to prevent infinite loop)
                        BPF_DBG_PRINTK("[XDP-SECURITY-DEBUG] IPv6 WINDOW STILL EXPIRED: elapsed=%u, retrying CAS\n",
                                       updated_elapsed);

                        // One retry attempt
                        expected_timestamp = updated_timestamp;
                        old_timestamp = __sync_val_compare_and_swap(&state->conn_timestamp, expected_timestamp, (__u64)now_sec);

                        if (old_timestamp == expected_timestamp) {
                            // Won on retry - reset counter
                            __sync_lock_test_and_set(&state->conn_count, 1);
                            current_count = 0;

                            if (conn_rate_threshold == 0) {
                                __sync_lock_test_and_set(&state->conn_count, 0);
                                dp_update_security_stats(STAT_CONN_BLOCKED, 1);
                                LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_ACT_DROP);
                                return XDP_DROP;
                            }
                        } else {
                            // Lost retry - treat as same window (another CPU won)
                            current_count = __sync_fetch_and_add(&state->conn_count, 1);

                            if (current_count >= (__u64)conn_rate_threshold) {
                                __sync_fetch_and_sub(&state->conn_count, 1);
                                dp_update_security_stats(STAT_CONN_BLOCKED, 1);
                                LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_ACT_DROP);
                                return XDP_DROP;
                            }
                        }
                    } else {
                        // Window is now valid (another CPU successfully reset it)
                        // Treat as SAME WINDOW - increment normally
                        current_count = __sync_fetch_and_add(&state->conn_count, 1);

                        BPF_DBG_PRINTK("[XDP-SECURITY-DEBUG] IPv6 SAME WINDOW (after race): count=%llu->%llu threshold=%u\n",
                                       current_count, current_count + 1, conn_rate_threshold);

                        // Check if we exceeded threshold
                        if (current_count >= (__u64)conn_rate_threshold) {
                            // Exceeded threshold - revert and drop
                            __sync_fetch_and_sub(&state->conn_count, 1);
                            BPF_DBG_PRINTK("[XDP-SECURITY-DEBUG] IPv6 CONN RATE DROP: old_count=%llu threshold=%u [BLOCKED - REVERTED]\n",
                                           current_count, conn_rate_threshold);
                            dp_update_security_stats(STAT_CONN_BLOCKED, 1);
                            LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_ACT_DROP);
                            return XDP_DROP;
                        }
                    }
                }
            } else {
                // Same window - atomic increment and check
                // CRITICAL: We increment first, then check if we EXCEEDED the limit
                // If we did, we need to decrement back and drop the packet
                current_count = __sync_fetch_and_add(&state->conn_count, 1);

                BPF_DBG_PRINTK("[XDP-SECURITY-DEBUG] IPv6 SAME WINDOW: count=%llu->%llu threshold=%u\n",
                               current_count, current_count + 1, conn_rate_threshold);

                // Check if the OLD count (before increment) was already at threshold
                // This means our increment pushed us OVER the limit
                if (current_count >= (__u64)conn_rate_threshold) {
                    // We exceeded the limit - decrement back and drop
                    __sync_fetch_and_sub(&state->conn_count, 1);
                    
                    BPF_DBG_PRINTK("[XDP-SECURITY-DEBUG] IPv6 CONN RATE DROP: old_count=%llu threshold=%u [BLOCKED - REVERTED]\n",
                                   current_count, conn_rate_threshold);
                    
                    dp_update_security_stats(STAT_CONN_BLOCKED, 1);
                    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_ACT_DROP);
                    return XDP_DROP;
                }
            }

            dp_update_security_stats(STAT_CONN_PASSED, 1);
        }
        

        // Count the SYN as passed only after it survived BOTH the SYN-rate
        // and connection-rate checks; counting before the conn-rate drop made
        // passed+blocked exceed total SYNs.
        if (syn_enabled && is_syn) {
            dp_update_security_stats(STAT_SYN_PASSED, 1);
        }

        // P0-7: UDP Flood Check
        if (udp_enabled && is_udp) {
            window_elapsed = now_sec - state->udp_timestamp;

            if (window_elapsed >= 1) {
                state->udp_timestamp = now_sec;
                state->udp_pkt_count = 1;
                state->udp_byte_count = xf->pm.l3_len;
            } else {
                __u64 current_pkt_count = __sync_fetch_and_add(&state->udp_pkt_count, 1);
                __u64 current_byte_count = __sync_fetch_and_add(&state->udp_byte_count, xf->pm.l3_len);

                if (current_pkt_count + 1 > (__u64)udp_pkt_threshold) {
                    BPF_DBG_PRINTK("[XDP-SECURITY] IPv6 UDP PKT DROP: pkt_count=%llu\n", current_pkt_count + 1);
                    dp_update_security_stats(STAT_UDP_BLOCKED, 1);
                    dp_update_security_stats(STAT_UDP_BYTES_BLOCKED, xf->pm.l3_len);
                    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_ACT_DROP);
                    return XDP_DROP;
                }

                if (current_byte_count + xf->pm.l3_len > (__u64)udp_bandwidth_threshold) {
                    BPF_DBG_PRINTK("[XDP-SECURITY] IPv6 UDP BW DROP: byte_count=%llu\n", current_byte_count + xf->pm.l3_len);
                    dp_update_security_stats(STAT_UDP_BLOCKED, 1);
                    dp_update_security_stats(STAT_UDP_BYTES_BLOCKED, xf->pm.l3_len);
                    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_ACT_DROP);
                    return XDP_DROP;
                }
            }
            dp_update_security_stats(STAT_UDP_PASSED, 1);
            dp_update_security_stats(STAT_UDP_BYTES_PASSED, xf->pm.l3_len);
        }
        
    } else {
        // New source IP - only create entry if:
        // 1. This is a SYN packet (for SYN flood protection), OR
        // 2. Connection rate limiting is enabled (track all TCP connections), OR
        // 3. This is a UDP packet and UDP flood protection is enabled
        if (!is_syn && !conn_enabled && (!is_udp || !udp_enabled)) {
            // Skip tracking: non-SYN TCP, conn rate disabled, and (non-UDP or UDP protection disabled)
            return XDP_PASS;
        }

        // Create new tracking entry
        // BUG FIX: Only count SYN packets for connection rate tracking
        __builtin_memset(&new_state, 0, sizeof(new_state));
        new_state.syn_timestamp = now_sec;
        new_state.syn_count = is_syn ? 1 : 0;
        new_state.conn_timestamp = now_sec;
        new_state.conn_count = is_syn ? 1 : 0;  // Only count SYNs as new connections
        new_state.udp_timestamp = now_sec;
        new_state.udp_pkt_count = is_udp ? 1 : 0;
        new_state.udp_byte_count = is_udp ? xf->pm.l3_len : 0;
        new_state.flags = 0;

        int ret = bpf_map_update_elem(&sec_rate_v6, &key, &new_state, BPF_ANY);
        if (ret != 0) {
            BPF_DBG_PRINTK("[XDP-SECURITY] IPv6 map update failed: ret=%d\n", ret);
        }
        // Note: uniqueIps counter is calculated by Go control plane via map iteration
        // (no eBPF counter needed - avoids monotonic increase bug on LRU eviction)

        if (is_syn && syn_enabled) {
            dp_update_security_stats(STAT_SYN_PASSED, 1);
        }
        if (conn_enabled && is_syn) {  // BUG FIX: Only count SYN packets
            dp_update_security_stats(STAT_CONN_PASSED, 1);
        }
        if (is_udp && udp_enabled) {
            dp_update_security_stats(STAT_UDP_PASSED, 1);
            dp_update_security_stats(STAT_UDP_BYTES_PASSED, xf->pm.l3_len);
        }
    }
    return XDP_PASS;
}

/*
 * Main Entry Point: Unified Security Rate Check (called from xdp_packet_func)
 *
 * Integration Point: llb_kern_entry.c:xdp_packet_func() (after IP filter)
 * Pattern: Follows P0-7 dp_do_ipfilter_main_xdp() structure
 *
 * Processing Flow:
 * 1. Check if packet is TCP SYN (for P0-5 SYN flood protection)
 * 2. Check if packet is UDP (for P0-7 UDP flood protection)
 * 3. Route to IPv4 or IPv6 handler based on protocol
 * 4. Perform unified rate limiting (P0-5 + P0-6 + P0-7) and return XDP_DROP or XDP_PASS
 *
 * Performance: <2µs per packet at XDP layer
 */
static int __always_inline
dp_do_security_rate_main_xdp(struct xdp_md *ctx, struct xfi *xf)
{
    int is_syn = 0;
    int is_udp = 0;

    // Check protocol type for rate limiting
    // Process TCP (for SYN flood + connection rate) and UDP (for UDP flood)
    if (xf->l34m.nw_proto == IPPROTO_TCP) {
        // TCP traffic - derive SYN from parser-computed flags rather than
        // re-parsing the raw frame. The parser already accounts for VLAN tags
        // and IPv6 extension headers, which the raw re-parse helpers do not,
        // so tagged/encapsulated SYNs no longer bypass the check. A SYN without
        // ACK marks a new connection (SYN-ACK replies are excluded).
        if ((xf->pm.tcp_flags & LLB_TCP_SYN) && !(xf->pm.tcp_flags & LLB_TCP_ACK)) {
            is_syn = 1;
        }
    } else if (xf->l34m.nw_proto == IPPROTO_UDP) {
        // UDP traffic - set flag for UDP flood check
        is_udp = 1;
    } else {
        // Other protocols (ICMP, etc.) - pass through
        return XDP_PASS;
    }

    // Check for IPv4
    if (xf->l2m.dl_type == bpf_htons(ETH_P_IP)) {
        return dp_do_security_rate_check_v4_xdp(ctx, xf, is_syn, is_udp);
    } 
    // Check for IPv6
    else if (xf->l2m.dl_type == bpf_htons(ETH_P_IPV6)) {
        return dp_do_security_rate_check_v6_xdp(ctx, xf, is_syn, is_udp);
    }

    // Non-IP traffic, pass through
    return XDP_PASS;
}

#endif /* HAVE_DP_SECURITY_RATE_LIMIT */

#endif /* __LLB_KERN_SYNFLOOD_C */