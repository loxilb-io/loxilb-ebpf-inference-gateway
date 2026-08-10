/* SPDX-License-Identifier: GPL-2.0
 *
 * sockproxy_l7policy.h — L7 content-routing policy engine (public contract).
 *
 * This header declares the STABLE prototype contract for the userspace L7
 * content-routing engine that runs as a SIBLING of the AI model path (CONTEXT
 *..), dispatched AFTER the AI-GW auth/QUOTA gate at the two
 * find_endpoint_lpm seams (sockproxy_ep.c:400 / sockproxy_h2.c:1962).
 *
 * Plan shipped this as a COMPILING STUB (opaque void* IR). Plan 
 * (this revision) narrows the IR to the concrete TRANSLATION-NEUTRAL SUPERSET
 * types below — a superset of OpenStack Octavia l7policy/l7rule AND the
 * Kubernetes Gateway API HTTPRoute (CONTEXT) — and implements
 * the real ordered first-match-wins evaluation engine in sockproxy_l7policy.c.
 *
 * IR shape (locked, CONTEXT):
 *   - Per-VIP ORDERED list of routes; each route has an explicit `position`.
 * The engine walks routes position-sorted, FIRST-MATCH-WINS.
 * Each route has matchSets: OR ACROSS sets, AND WITHIN a set.
 * Each condition = {field, op, key, value, invert}.
 * One tagged-union action per route: FORWARD / REDIRECT / REJECT.
 * The IR RESERVES a filter slot for (header set/add/remove,
 *     URLRewrite-without-redirect, RequestMirror) and the SSL_* field-type
 * space for — neither is implemented here ( deferred).
 *
 * REGEX (CONTEXT landmine — ReDoS): POSIX <regex.h> has no match
 * timeout, so the pattern is compiled ONCE at attach time (regcomp, Plan 05),
 * cached on the condition (re + re_valid), and the operand is length-bounded to
 * L7_REGEX_INPUT_MAX before regexec. The evaluate path NEVER calls regcomp.
 *
 * The 4096-byte proxy_arg _Static_assert (sockproxy.h:750) forbids carrying the
 * variable-length ordered route array inline on proxy_arg — hence the separate
 * proxy_attach_l7_policy / proxy_detach_l7_policy CGO attach calls,
 * modeled on proxy_update_mtls_config. Those signatures stay STABLE for Plan 05.
 */
#ifndef __SOCKPROXY_L7POLICY_H__
#define __SOCKPROXY_L7POLICY_H__

#include <regex.h>   /* POSIX regex_t / regcomp / regexec — REGEX compare op */
#include <stdint.h>
#include <stdbool.h> /* sockproxy.h / sockproxy_cache.h use bool */
#include <pthread.h> /* sockproxy.h uses pthread_rwlock_t but does not include this itself */

#include "uthash.h"     /* MUST precede sockproxy.h — provides UT_hash_handle */
#include "sockproxy.h"  /* struct proxy_fd_ent, struct proxy_ent, MAX_PROXY_EP */

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Capacity macros (bounded fixed sizes — no per-route heap growth in the IR).
 * ------------------------------------------------------------------------- */
#ifndef L7_MAX_CONDS_PER_SET
#define L7_MAX_CONDS_PER_SET   8     /* AND-conditions in one match set */
#endif
#ifndef L7_MAX_SETS_PER_ROUTE
#define L7_MAX_SETS_PER_ROUTE  8     /* OR-sets in one route */
#endif
#ifndef L7_KEY_MAX
#define L7_KEY_MAX             64    /* header/cookie/query NAME (== L7_HDR_NAME_MAX) */
#endif
#ifndef L7_VALUE_MAX
#define L7_VALUE_MAX           256   /* condition operand value */
#endif
#ifndef FILTER_RESERVED_BYTES
#define FILTER_RESERVED_BYTES  64    /* legacy reserved slot — retained for naming continuity */
#endif

/* -------------------------------------------------------------------------
 * (CONTEXT) — request header insertion filter slot.
 * The Phase-75 IR reserved a per-route filter slot; fills it with a
 * BOUNDED tagged-op {SET|ADD|REMOVE} filter list (a faithful superset of BOTH
 * Octavia insert_headers (SET/ADD) AND Gateway API RequestHeaderModifier
 * (set/add/remove)). DECLARATIONS ONLY this phase — the SET/ADD/REMOVE engine
 * is Plans 06/07. These ride the heap route array (proxy_attach_l7_policy),
 * NOT proxy_arg, so the 4096-byte eBPF-map-value budget is untouched.
 * ------------------------------------------------------------------------- */
#ifndef L7_HDR_NAME_MAX
#define L7_HDR_NAME_MAX  64   /* == sockproxy.h L7_HDR_NAME_MAX (header NAME, incl NUL) */
#endif
#ifndef L7_HDR_VALUE_MAX
#define L7_HDR_VALUE_MAX 256  /* == sockproxy.h L7_HDR_VALUE_MAX (header VALUE, incl NUL) */
#endif
#ifndef L7_MAX_HDR_FILTERS
/* Bounded count of insertHeaders ops per route (DoS bound). Aligned to
 * the L7_MAX_CAPTURED_HEADERS=32-style discipline; chosen 8 (≤32) — enough for the
 * X-Forwarded-* trio plus several custom headers, far below the 32 ceiling. */
#define L7_MAX_HDR_FILTERS 8
#endif

/* Tagged op for an insertHeaders filter entry (CONTEXT). */
typedef enum {
  L7HDR_SET    = 0,  /* set/overwrite the header to `value` (Octavia + Gateway "set") */
  L7HDR_ADD    = 1,  /* append `value` (Octavia + Gateway "add")                       */
  L7HDR_REMOVE = 2,  /* remove the header by name (`value` ignored; Gateway "remove")  */
} l7_hdr_op_t;

/* One bounded insertHeaders filter entry. */
typedef struct {
  uint8_t op;                       /* l7_hdr_op_t */
  char    name[L7_HDR_NAME_MAX];    /* header name (required)                       */
  char    value[L7_HDR_VALUE_MAX];  /* header value (ignored for L7HDR_REMOVE)      */
} l7_hdr_filter_t;
#ifndef L7_REGEX_INPUT_MAX
#define L7_REGEX_INPUT_MAX     1024  /* ReDoS bound: operand truncated to this before regexec */
#endif
#ifndef L7_REDIRECT_LOCATION_MAX
#define L7_REDIRECT_LOCATION_MAX 512 /* assembled Location: URL for a REDIRECT decision */
#endif

/* -------------------------------------------------------------------------
 * l7_route_dispatch outcome sentinels (Plan 04). The shared dispatch helper
 * returns one of these so the two divergent routing seams (H1 ep.c:400 /
 * H2 h2.c:1962) act identically and cannot drift ( parity).
 * ------------------------------------------------------------------------- */
#define L7_DISPATCH_FALLTHROUGH 0  /* no L7 policy attached — run the AI/LPM path UNCHANGED */
#define L7_DISPATCH_FORWARD     1  /* FORWARD decision — *tepval_out resolved to a plain pool       */
#define L7_DISPATCH_TERMINATED  2  /* REJECT/REDIRECT/no-match emitted — caller returns -1 (terminal) */

/* -------------------------------------------------------------------------
 * Match field (CONTEXT). HOST/PATH/HEADER/COOKIE/FILE_TYPE are the Octavia
 * l7rule types; METHOD/QUERY are the Gateway API additions. The SSL_* field-type
 * range (Octavia SSL_CONN_HAS_CERT / SSL_VERIFY_RESULT / SSL_DN_FIELD) is
 * RESERVED for (needs listener-level mTLS) — DO NOT add SSL_*
 * enumerators here; new SSL_* values must start at L7F__SSL_RESERVED_BASE so the
 * existing wire values never shift.
 * ------------------------------------------------------------------------- */
typedef enum {
  L7F_HOST       = 0,   /* :authority / Host header (port-stripped)   */
  L7F_PATH       = 1,   /* request path ("/v1/users")                 */
  L7F_HEADER     = 2,   /* arbitrary header by name (key required)    */
  L7F_COOKIE     = 3,   /* a cookie by name (key required)            */
  L7F_FILE_TYPE  = 4,   /* path file extension (Octavia FILE_TYPE)    */
  L7F_METHOD     = 5,   /* HTTP method (Gateway)                      */
  L7F_QUERY      = 6,   /* URL query param by name (key required)     */
  /* L7F__SSL_RESERVED_BASE = 64 -- SSL_* field types start here */
} l7_field_t;

/* -------------------------------------------------------------------------
 * Compare op (CONTEXT). Octavia EQUAL_TO/STARTS_WITH/ENDS_WITH/CONTAINS/
 * REGEX ∪ Gateway Exact/PathPrefix/RegularExpression. SEGMENT_PREFIX is the
 * Gateway PathPrefix semantics (prefix must end on a "/" path segment boundary).
 * Per-condition `invert` (Octavia-only) flips the result (see l7_condition_t).
 * ------------------------------------------------------------------------- */
typedef enum {
  L7OP_EQUAL          = 0,  /* operand == value (Octavia EQUAL_TO / Gateway Exact) */
  L7OP_PREFIX         = 1,  /* operand starts with value (Octavia STARTS_WITH)     */
  L7OP_SEGMENT_PREFIX = 2,  /* Gateway PathPrefix — value is a path-segment prefix */
  L7OP_SUFFIX         = 3,  /* operand ends with value (Octavia ENDS_WITH)         */
  L7OP_CONTAINS       = 4,  /* operand contains value (Octavia CONTAINS)           */
  L7OP_REGEX          = 5,  /* POSIX ERE — cached re, input-bounded regexec        */
} l7_op_t;

/* One predicate. AND-combined within a match set. */
typedef struct {
  l7_field_t field;
  l7_op_t    op;
  char       key[L7_KEY_MAX];     /* header/cookie/query NAME (required for HEADER/COOKIE/QUERY) */
  char       value[L7_VALUE_MAX]; /* operand to compare the request field against               */
  uint8_t    invert;              /* 1 => negate this condition's result (Octavia-only)          */
  regex_t    re;                  /* compiled at attach (op == L7OP_REGEX only) — never in eval  */
  uint8_t    re_valid;            /* 1 if `re` holds a compiled program (set by attach/Plan 05)  */
} l7_condition_t;

/* A match set: ALL conditions must hold (AND within a set). */
typedef struct {
  l7_condition_t conds[L7_MAX_CONDS_PER_SET];
  uint8_t        n_conds;
} l7_match_set_t;

/* -------------------------------------------------------------------------
 * Action tagged union (CONTEXT) — covers Octavia + Gateway in one shape.
 * ------------------------------------------------------------------------- */
typedef enum {
  L7A_FORWARD  = 0,   /* route to a (weighted) backend pool                       */
  L7A_REDIRECT = 1,   /* synthetic 3xx with a Location: header                    */
  L7A_REJECT   = 2,   /* synthetic 4xx, terminal                                  */
} l7_action_kind_t;

/* FORWARD: a plain pool (reuses the existing intra-pool EP-select), optionally
 * with per-endpoint weights (Gateway weighted backendRefs). Resolution to a
 * tepval-equivalent is Plan 04's l7_resolve_pool — the engine only carries it. */
typedef struct {
  uint32_t pool_id;               /* target plain pool id */
  struct {
    uint32_t ep;                  /* endpoint identifier within the pool */
    uint8_t  weight;              /* relative weight (Gateway backendRefs) */
  } refs[MAX_PROXY_EP];
  uint8_t  n_refs;                /* 0 => use the pool's own member set */
} l7_forward_t;

/* REDIRECT path rewrite mode (Octavia REDIRECT_PREFIX / Gateway path modifier). */
typedef enum {
  L7PATH_NONE           = 0,  /* keep the original request path           */
  L7PATH_REPLACE_FULL   = 1,  /* replace the whole path with `value`      */
  L7PATH_REPLACE_PREFIX = 2,  /* replace the matched prefix with `value`  */
} l7_path_op_t;

typedef struct {
  char         scheme[8];         /* "http"/"https"; "" => keep request scheme   */
  char         host[256];         /* target host; "" => keep request host        */
  uint16_t     port;              /* target port; 0 => keep / default            */
  l7_path_op_t path_op;           /* how `value` rewrites the path               */
  char         value[L7_VALUE_MAX]; /* replacement path (per path_op)            */
  uint16_t     status_code;       /* 301/302/303/307/308; 0 => default 302       */
} l7_redirect_t;

typedef struct {
  uint16_t status_code;           /* 4xx; 0 => default 403                        */
} l7_reject_t;

typedef struct {
  l7_action_kind_t kind;
  union {
    l7_forward_t  fwd;
    l7_redirect_t redir;
    l7_reject_t   reject;
  } u;
} l7_action_t;

/* -------------------------------------------------------------------------
 * One route (CONTEXT): explicit position + OR-sets + one action, plus the
 * Phase-76 filter slot now realised as a BOUNDED insertHeaders filter (
 *) and an HTTP_COOKIE session-persistence marker. Both are
 * ADDITIVE and DECLARATIONS-ONLY here (the engine is Plans 06/07): a route with
 * n_hdr_filters==0 && cookie_persist==0 behaves exactly as a Phase-75 route.
 * These ride the heap route array, NEVER proxy_arg — the 4096-byte eBPF map
 * value budget is untouched.
 * ------------------------------------------------------------------------- */
typedef struct {
  int             position;       /* explicit precedence; engine sorts ascending */
  l7_match_set_t  sets[L7_MAX_SETS_PER_ROUTE]; /* OR across sets */
  uint8_t         n_sets;
  l7_action_t     action;         /* the tagged-union action */
  /* bounded insertHeaders SET/ADD/REMOVE filter list. */
  l7_hdr_filter_t hdr_filters[L7_MAX_HDR_FILTERS];
  uint8_t         n_hdr_filters;  /* 0 => no header insertion for this route      */
  /* HTTP_COOKIE session-persistence marker. 0=off; when set, the
   * attach path enables PROXY_AFFINITY_COOKIE (sockproxy.h:773) for this route.
   * Mutually exclusive with APP_COOKIE/SOURCE_IP per pool (Octavia semantics). */
  uint8_t         cookie_persist; /* 0=off, 1=HTTP_COOKIE LB-generated cookie mode */
} l7_route_t;

/* -------------------------------------------------------------------------
 * Evaluate output. l7_policy_evaluate fills `kind` + the matching action's
 * fields. For REDIRECT it also assembles the final Location URL into `location`
 * (the dispatch hook, Plan 04, hands it to l7_send_redirect). reject_body is an
 * optional static synthetic body for REJECT (NULL => default).
 * ------------------------------------------------------------------------- */
typedef struct {
  l7_action_kind_t kind;
  union {
    l7_forward_t  fwd;
    l7_redirect_t redir;
    l7_reject_t   reject;
  } u;
  char        location[L7_REDIRECT_LOCATION_MAX]; /* assembled REDIRECT Location: */
  const char *reject_body;        /* optional static body for REJECT (NULL = default) */
} l7_decision_t;

/* -------------------------------------------------------------------------
 * Public contract. Plan 05 calls proxy_attach_l7_policy / proxy_detach_l7_policy
 * (signatures STABLE since Plan 01); Plan 04 calls l7_policy_evaluate /
 * l7_send_reject / l7_send_redirect at the two dispatch seams.
 * ------------------------------------------------------------------------- */

/*
 * l7_policy_evaluate — walk the ordered route array (assumed position-sorted by
 * the attach path, Plan 05) for the parsed request on `pfe`, first-match-wins,
 * OR-across-sets / AND-within-a-set, applying per-condition invert.
 *
 * PURE: it reads `pfe` + `routes` and writes ONLY *decision_out; it NEVER sends
 * on the socket (REJECT/REDIRECT/FORWARD execution is Plan 04) and NEVER calls
 * regcomp (compile is attach-time, Plan 05 — ReDoS hot-path mitigation).
 *
 * Returns 0 on a route match (decision_out populated), -1 on no-match (caller
 * emits the configured default — 404 for Gateway parity).
 */
int l7_policy_evaluate(struct proxy_fd_ent *pfe, const l7_route_t *routes,
                       int n_routes, l7_decision_t *decision_out);

/*
 * l7_send_reject — emit a synthetic terminal REJECT response (default 403) on
 * the client fd and shut it down, bypassing the backend. Generalizes the proven
 * 403/401 send+shutdown idiom (sockproxy_http.c:4543). Body executor: Plan 04.
 */
int l7_send_reject(struct proxy_fd_ent *pfe, int status_code, const char *body);

/*
 * l7_send_redirect — emit a synthetic terminal REDIRECT response (default 302)
 * with a Location: header on the client fd. Generalizes the 429 snprintf idiom
 * (sockproxy_http.c:4576). Body executor: Plan 04.
 */
int l7_send_redirect(struct proxy_fd_ent *pfe, int status_code,
                     const char *location);

/*
 * proxy_h2_send_l7_synthetic — emit a synthetic terminal L7 response (REJECT or
 * REDIRECT) on the ACTIVE HTTP/2 stream via nghttp2 framing, instead of the raw
 * HTTP/1.1 bytes l7_send_reject/redirect write on H1. Raw "HTTP/1.1 ..." bytes on
 * an h2 socket are an h2 protocol violation (the client aborts the connection —
 * the H1/H2 parity failure this fixes). Headers-only (`:status`, optional
 * `location`, `content-length: 0`, END_STREAM); no fd shutdown (h2 multiplexes —
 * only the one stream is closed). The active stream id is read from
 * proxy_h2_session.l7_active_stream_id (set at the H2 dispatch seam, sockproxy_h2.c).
 *
 * Defined in sockproxy_h2.c (keeps nghttp2 out of sockproxy_l7policy.c). Returns 0
 * when it emitted an h2 response (caller is done); -1 when pfe is not on an active
 * h2 session (caller falls back to the H1 raw-response path). `location` is NULL
 * for REJECT, the resolved URL for REDIRECT; `body` is advisory and may be NULL.
 */
int proxy_h2_send_l7_synthetic(struct proxy_fd_ent *pfe, int status_code,
                               const char *location, const char *body);

/*
 * proxy_attach_l7_policy — attach the ordered L7 route array to the running
 * proxy_map_ent keyed by `key` (VIP:port:proto), compiling REGEX conditions ONCE
 * at attach time (regcomp -> cond->re / cond->re_valid) and setting
 * has_l7_policy=1. Modeled on proxy_update_mtls_config. Body: Plan 05.
 */
int proxy_attach_l7_policy(struct proxy_ent *key, const l7_route_t *routes,
                           int n_routes);

/*
 * proxy_detach_l7_policy — drop the attached L7 policy for `key` and regfree
 * every compiled REGEX program (DELETE path). Body: Plan 05.
 */
int proxy_detach_l7_policy(struct proxy_ent *key);

/*
 * l7_resolve_pool — map a FORWARD action's target pool to a tepval-equivalent
 * (proxy_epval_t *) so a FORWARD decision re-enters the EXISTING intra-pool
 * endpoint selector (CONTEXT — a plain pool, never the AI model engine).
 * Returns NULL when there is no usable pool. Defined in sockproxy_l7policy.c.
 */
struct proxy_epval *l7_resolve_pool(struct proxy_map_ent *ent,
                                    l7_forward_t *fwd);

/*
 * l7_route_dispatch — the SINGLE shared discriminator + dispatch helper invoked
 * at BOTH routing seams (H1 sockproxy_ep.c:400 and H2 sockproxy_h2.c:1962) so the
 * two paths cannot drift (the dominant H1/H2 parity landmine).
 *
 * Discriminator: if `ent` has no attached L7 policy (has_l7_policy==0,
 * the default for every AI service), this is a PURE NO-OP returning
 * L7_DISPATCH_FALLTHROUGH — the caller then runs the AI/LPM path byte-for-byte
 * unchanged (Pitfall 5).
 *
 * Otherwise it runs l7_policy_evaluate and acts on the decision:
 *   REJECT / REDIRECT / no-match -> emit terminal response, return
 *                                   L7_DISPATCH_TERMINATED (caller returns -1)
 *   FORWARD -> *tepval_out = l7_resolve_pool(...), return L7_DISPATCH_FORWARD
 *
 * NOTE (H1/H2 contract): the engine is pfe-only. For HTTP/2 the per-request
 * authority/path/method live on the stream, so the H2 caller MUST mirror them
 * into pfe (host_url/request_path/url_path/http_method) BEFORE calling this.
 */
int l7_route_dispatch(struct proxy_fd_ent *pfe, struct proxy_map_ent *ent,
                      struct proxy_epval **tepval_out);

/* -------------------------------------------------------------------------
 * (CONTEXT) — request header insertion.
 *
 * THE SINGLE SHARED applier consumed by BOTH the H1 (sockproxy_http.c) and the
 * H2 (sockproxy_h2.c) request-egress seams (Pitfall 1 H1/H2 parity — the
 * dominant Phase-75 landmine was reimplementing per-protocol logic twice). The
 * applier is protocol-NEUTRAL: it computes the ordered set of header ops (the
 * always-overwrite X-Forwarded-* trio first, then the matched route's
 * insertHeaders SET/ADD/REMOVE ops) and hands each one to a protocol-specific
 * EMIT callback. The H1 caller splices CRLF bytes; the H2 caller builds an
 * nghttp2_nv — but the OP SELECTION, VALIDATION and ORDER live here, once.
 *
 * nghttp2 is deliberately kept OUT of this TU (it only ever calls `emit`), so
 * the applier links into both the H1-only and the H2 object graphs.
 * ------------------------------------------------------------------------- */

/* CRLF / header-injection guards. A name/value containing a CR, LF,
 * NUL, or any other ASCII control char (<0x20 or 0x7f) is REJECTED at apply time
 * — defence-in-depth behind the REST-handler 400, because the IR could also be
 * driven by a future internal caller. Empty name is invalid. Return 1=valid. */
int l7_hdr_name_valid(const char *name);
int l7_hdr_value_valid(const char *value);

/*
 * synthesize the HSTS header VALUE from the
 * proxy_arg HSTS scalars. Protocol-neutral string build shared by BOTH emit
 * seams (H1 \r\n splice in sockproxy_http.c, H2 nghttp2_nv in sockproxy_h2.c) —
 * the one-synthesizer/two-emit-seams pattern. Writes
 * "max-age=N[; includeSubDomains][; preload]" into `out` (NUL-terminated).
 * Returns the written length (>0) on success, or 0 when max_age==0 (caller MUST
 * NOT inject — default-off, RFC 6797) or on a buffer overflow. The caller pairs
 * the value with the header NAME at its seam ("Strict-Transport-Security" on H1,
 * lowercase "strict-transport-security" on H2). Callers gate on
 * have_ssl && has_l7_policy before calling.
 */
size_t l7_hsts_synthesize(uint32_t max_age, uint8_t include_subdomains,
                          uint8_t preload, char *out, size_t outlen);

/* Per-op emit callback. `op` is an l7_hdr_op_t (SET/ADD/REMOVE). For REMOVE,
 * `value` is "" (REMOVE drops by name). name/value are NUL-terminated and have
 * already passed l7_hdr_name_valid / l7_hdr_value_valid. */
typedef void (*l7_hdr_emit_fn)(void *ctx, int op, const char *name,
                               const char *value);

/*
 * l7_apply_req_filters — emit the request-header op set for `pfe` on the
 * L7_Proxy peer `ent`. Emits, IN ORDER:
 * 1. SET X-Forwarded-For = `xff_ip` (the REAL TCP peer IP —, always
 *                                          overwrites any client-supplied XFF)
 * 2. SET X-Forwarded-Port = `listener_port` (the listener port)
 *   3. SET X-Forwarded-Proto= `xfproto`  ("http"/"https" — actual client scheme)
 *   4. each insertHeaders op of the FIRST MATCHING route's hdr_filters[]
 * (validated; bounded by L7_MAX_HDR_FILTERS) —.
 * Invalid (control-char) names/values are SKIPPED (never emitted). The XFF/XFP/
 * XFProto trio uses SET semantics (strip-any-existing + add) so the client can
 * never spoof them. `xff_ip`/`xfproto` are caller-provided (the peer IP and
 * scheme are protocol/socket facts the applier does not own). This function does
 * NOT gate on has_l7_policy — the CALLER gates (mirrors the dispatch seam); it is
 * only ever invoked on the L7_Proxy peer.
 */
void l7_apply_req_filters(struct proxy_fd_ent *pfe, struct proxy_map_ent *ent,
                          const char *xff_ip, uint16_t listener_port,
                          const char *xfproto,
                          l7_hdr_emit_fn emit, void *ctx);

/* -------------------------------------------------------------------------
 * Operand extractors REUSED from sockproxy_http.c (RESEARCH §Don't Hand-Roll).
 * Plan narrows the L7 engine to consume these proven helpers instead of
 * hand-rolling a cookie/query parser. They were file-static in sockproxy_http.c;
 * this header gives them external linkage so sockproxy_l7policy.c can call them.
 * Definitions remain in sockproxy_http.c (the `static` qualifier is dropped
 * there in lock-step with these declarations).
 * ------------------------------------------------------------------------- */
int extract_cookie_by_name(const char *headers, const char *cookie_name,
                           char *value, size_t value_size);
int extract_query_param_value(const char *url, const char *param_name,
                              char *value, size_t value_size);

/* -------------------------------------------------------------------------
 * (CONTEXT) — STATELESS HTTP_COOKIE
 * persistence node-level bridges (definitions in sockproxy_l7policy.c). The PURE
 * token primitives live in sockproxy_cookie.h; these marshal the data-plane
 * structs (proxy_map_ent / proxy_epval) into them. NOTHING is stored on
 * proxy_fd_ent — the cookie value IS the binding (survives HA failover).
 * The per-VIP secret is derived deterministically from node->key (VIP:port) so
 * both HA peers compute byte-identical tokens with zero xSync change.
 * ------------------------------------------------------------------------- */
#include "sockproxy_cookie.h" /* LB_COOKIE_* constants, pure token primitives */

/* Deterministic per-VIP secret from node->key (VIP:port). Returns 0 on success. */
int l7_cookie_node_vip_secret(const struct proxy_map_ent *node,
                              uint8_t out[LB_COOKIE_VIP_SECRET_LEN]);
/* Mint the Set-Cookie token for live member `ep_idx` of `tepval`. Returns len>0. */
int l7_cookie_node_token_for_ep(const struct proxy_map_ent *node,
                                const struct proxy_epval *tepval, int ep_idx,
                                char *out, size_t outsz);
/* Read-back: constant-time match `token` to a live member; L7_COOKIE_MISS = rehash. */
int l7_cookie_node_match(const struct proxy_map_ent *node,
                         const struct proxy_epval *tepval, const char *token);
/* 1 if the first matching route enables HTTP_COOKIE persistence, else 0. */
int l7_cookie_persist_active(struct proxy_fd_ent *pfe, struct proxy_map_ent *ent);
/* Extract the presented LB_COOKIE_NAME cookie from pfe->l7_headers[]. 0 on hit. */
int l7_cookie_read_presented(struct proxy_fd_ent *pfe, char *out, size_t outsz);

#ifdef __cplusplus
}
#endif

#endif /* __SOCKPROXY_L7POLICY_H__ */
