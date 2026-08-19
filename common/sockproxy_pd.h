/* sockproxy_pd.h - P/D disaggregation engine-dialect ops table
 *
 * Each LLM framework speaks a different P/D orchestration dialect:
 *   vLLM   — SEQUENTIAL machine: kv_transfer_params append → prefill send →
 *            response parse/extract → decode re-dispatch → prefill retry.
 *   SGLang — DUAL-DISPATCH machine: bootstrap triple injection (room RNG),
 *            simultaneous prefill(drain)/decode legs, pair-retry,
 *            rendezvous-wedge reaper.
 * The HTTP engine selects an ops pointer once per rule (proxy_add, from
 * pd_engine) and caches it on the epval; request-lifecycle events then call
 * through the table and never ask which engine they are speaking to.
 *
 * The table SHAPE is fixed here; exact slot signatures may adapt while the
 * machines are extracted into sockproxy_pd_vllm.c / sockproxy_pd_sglang.c.
 * Slots not yet routed through the table are NULL until the owning machine
 * is extracted.
 */

#ifndef __SOCKPROXY_PD_H__
#define __SOCKPROXY_PD_H__

#include <stddef.h>
#include <stdint.h>
#include <time.h>

struct proxy_fd_ent;   /* sockproxy.h */
struct proxy_epval;    /* sockproxy.h */

typedef struct pd_dialect_ops {
  const char *name;              /* "vllm" | "sglang" */
  int         needs_full_body;   /* body rewrite requires the buffered body */
  size_t      max_inspect_body;  /* body-inspection cap for this dialect */

  /* Body rewrite before dispatch, called with the located request body
   * (hdr_len/body point into pfe->rcvbuf). vllm: save original +
   * kv_transfer_params prefill rewrite. sglang: bootstrap triple injection.
   * Returns 0 to continue forwarding, <0 when the request was terminated
   * (fail-closed 503 already sent) and the caller must restart the fd. */
  int (*prepare_request)(struct proxy_fd_ent *pfe, struct proxy_epval *epval,
                         size_t hdr_len, const uint8_t *body, size_t body_len);

  /* Forward the prepared request. vllm: prefill leg only, phase →
   * PREFILL_WAITING. sglang: pd_sg_dual_dispatch (failure 503 handled
   * inside). Returns 0 on success, <0 on dispatch failure. */
  int (*dispatch)(struct proxy_fd_ent *pfe);

  /* Prefill-leg response bytes. vllm: parse, extract kv_transfer_params,
   * build + send the decode request. sglang: drain + status-check only. */
  int (*on_prefill_response)(struct proxy_fd_ent *pfe,
                             const uint8_t *buf, size_t len);

  /* Failure coupling + retry eligibility (HTTP status vs transport error). */
  int (*on_leg_error)(struct proxy_fd_ent *pfe, int leg, int err);

  /* proxy_pdestroy deferred-retry collection (prefill-retry vs pair-retry). */
  int (*collect_retry)(struct proxy_fd_ent *pfe);

  /* Timeout semantics (30s prefill timeout vs rendezvous wedge 504). */
  int (*reap)(struct proxy_fd_ent *pfe, time_t now);
} pd_dialect_ops_t;

/* Dialect instances. Defined next to their machines (sockproxy_http.c until
 * extraction moves them into their sockproxy_pd_<engine>.c homes). */
extern const pd_dialect_ops_t pd_dialect_vllm;
extern const pd_dialect_ops_t pd_dialect_sglang;

/* Wire kv_engine_type → PD_ENGINE_* (sockproxy.h). Unknown values degrade
 * to PD_ENGINE_VLLM. */
uint8_t pd_engine_from_kv_engine_type(uint8_t kv_engine_type);

/* PD_ENGINE_* (sockproxy.h) → ops table. Never returns NULL. */
const pd_dialect_ops_t *pd_dialect_resolve(uint8_t pd_engine);

#endif /* __SOCKPROXY_PD_H__ */
