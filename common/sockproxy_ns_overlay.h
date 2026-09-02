/*
 * Copyright (c) 2024-2026 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */
#ifndef __SOCKPROXY_NS_OVERLAY_H__
#define __SOCKPROXY_NS_OVERLAY_H__

/*
 * sockproxy_ns_overlay.h — pure resolution of the DFL session-header /
 * IP-persist stickiness overlay (the pd_fallback_normal block of
 * proxy_find_ep in sockproxy_ep.c). Split into a dependency-free helper so
 * the P/D gate is unit-testable without the whole proxy_find_ep graph.
 *
 * The overlay is a CONVERGED-rule mechanism. A P/D-disaggregated rule
 * selects its prefill endpoint through the 3-tier P/D ladder, increments the
 * paired active_conns on (prefill, decode), and records pfe->pd_prefill_ep_idx
 * for the phase machine; it also carries its own Tier-0 pair stickiness
 * (pd_session_store, keyed on user/conversation id). If the converged
 * learned-binding overlay were allowed to repoint algorithm_selection here,
 * the connection would land on a different endpoint than the one the load
 * accounting and phase machine track — a silent desync whenever a stale
 * binding names an endpoint other than this request's prefill choice (it
 * only stays benign while the rule has a single prefill endpoint, where the
 * learned value equals the sole choice). So on a P/D rule the overlay is
 * skipped entirely: the ladder's selection stands, and the learn-store side
 * (ns_overlay_should_learn) is gated the same way so a P/D request never
 * writes a binding the read side will never honor.
 *
 * PRIORITY 1 (header hash) and PRIORITY 2 (IP persist) already fire only
 * when algo_in < 0, which never holds after a successful P/D selection; the
 * unguarded override was PRIORITY 0 (learned binding). The gate here makes
 * the skip explicit and total for all three.
 */

typedef enum {
  NS_OVERLAY_NONE = 0, /* selection unchanged (miss, or nothing configured) */
  NS_OVERLAY_LEARNED,  /* PRIORITY 0: a learned session-header binding won */
  NS_OVERLAY_HASH,     /* PRIORITY 1: deterministic header-value hash */
  NS_OVERLAY_IP,       /* PRIORITY 2: client-IP persistence */
  NS_OVERLAY_PD_SKIP,  /* P/D rule: overlay not applied (the G-1 gate) */
} ns_overlay_kind_t;

/* Resolved dependency values for one selection. The caller performs the
 * lookups/health checks (which need the live proxy maps) and hands the
 * results here; this function owns only the priority ORDERING and the P/D
 * gate — the part that carried the defect. */
typedef struct {
  int pd_disagg_enabled;      /* tepval->pd_disagg_enabled */
  int session_header_enabled; /* tepval->session_header_enabled */
  int header_present;         /* custom_session_header set and non-empty */
  int learned_ep;             /* lookup_conversation_endpoint result (-1 = miss) */
  int learned_ok;             /* learned_ep in range && !inv && healthy */
  int hash_ep;                /* PRIORITY 1 candidate: session_key_hash % n_eps */
  int hash_ok;                /* hash_ep healthy */
  int sel_sticky;             /* tepval->select == PROXY_SEL_STICKY */
  int ip_ep;                  /* PRIORITY 2 candidate: client-IP hash % n_eps */
  int ip_ok;                  /* ip_ep healthy */
} ns_overlay_in_t;

/* algo_in = the selection the ladder above chose (-1 = none yet).
 * Returns the resolved selection; *kind reports which rule fired. */
static inline int
ns_overlay_resolve(int algo_in, const ns_overlay_in_t *in, ns_overlay_kind_t *kind)
{
  *kind = NS_OVERLAY_NONE;

  if (in->pd_disagg_enabled) {
    /* G-1 gate: a P/D rule's ladder selection is authoritative. */
    *kind = NS_OVERLAY_PD_SKIP;
    return algo_in;
  }

  if (in->session_header_enabled && in->header_present) {
    if (in->learned_ok) {              /* PRIORITY 0 */
      *kind = NS_OVERLAY_LEARNED;
      return in->learned_ep;
    }
    if (algo_in < 0 && in->hash_ok) {  /* PRIORITY 1 */
      *kind = NS_OVERLAY_HASH;
      return in->hash_ep;
    }
    return algo_in;
  }

  if (in->sel_sticky && algo_in < 0 && in->ip_ok) { /* PRIORITY 2 */
    *kind = NS_OVERLAY_IP;
    return in->ip_ep;
  }

  return algo_in;
}

/* Whether a fresh selection should be persisted as a learned session-header
 * binding and flagged for response-learn. Gated on !pd_disagg_enabled for
 * the same reason the read side is: a P/D rule must not populate the
 * converged learned-binding map (the read side skips it, and a stale write
 * would also mislead an HA peer that consulted the map). used_learned is the
 * "a learned binding already won this turn" flag — never re-persist that. */
static inline int
ns_overlay_should_learn(int pd_disagg_enabled, int session_header_enabled,
                        int used_learned)
{
  return !pd_disagg_enabled && session_header_enabled && !used_learned;
}

#endif /* __SOCKPROXY_NS_OVERLAY_H__ */
