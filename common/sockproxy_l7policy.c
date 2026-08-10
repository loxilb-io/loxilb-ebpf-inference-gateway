/* SPDX-License-Identifier: GPL-2.0
 *
 * sockproxy_l7policy.c — L7 content-routing policy engine.
 *
 * Plan shipped this as a compiling STUB; Plan (this revision)
 * implements the real ORDERED FIRST-MATCH-WINS evaluation engine over the
 * concrete superset IR defined in sockproxy_l7policy.h (CONTEXT).
 *
 *   l7_policy_evaluate(pfe, routes, n_routes, decision_out)
 *     - routes arrive POSITION-SORTED (the attach path, Plan 05, sorts them) and
 *       are walked in array order; the FIRST route whose match succeeds wins.
 *     - A route matches if ANY of its matchSets matches (OR across sets); a set
 *       matches if ALL its conditions match (AND within the set).
 *     - A condition matches when its compare op holds between the request operand
 *       and the operand value; `invert` flips the per-condition result.
 *     - Operands are resolved from the parsed request on `pfe` and the bounded
 * generic header/cookie store populated in Plan (pfe->l7_headers /
 *       n_l7_headers). Cookie/query extraction REUSES the proven sockproxy_http.c
 *       helpers (RESEARCH §Don't Hand-Roll) — never hand-rolled here.
 *     - REGEX uses the PRE-COMPILED, cached cond->re (compiled ONCE at attach,
 *       Plan 05) and runs regexec on an operand TRUNCATED to L7_REGEX_INPUT_MAX.
 * The hot path NEVER calls regcomp (ReDoS mitigation; POSIX has no
 * match timeout). No raw operand pointer reaches the matcher.
 *
 * The function is PURE: it reads pfe + routes and writes only *decision_out; it
 * never sends on the socket (REJECT/REDIRECT/FORWARD execution is Plan 04).
 *
 * The synthetic-response responders (l7_send_reject / l7_send_redirect) and the
 * attach/detach calls remain Plan 04/05 STUBS here — Plan 03's scope is the IR
 * types (Task 1) + the evaluation engine (Task 2).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>   /* malloc / free / qsort — attach-time deep-copy + position sort */
#include <string.h>
#include <strings.h>  /* strcasecmp — case-insensitive header/cookie name match */
#include <regex.h>
#include <sys/socket.h>  /* send / shutdown (terminal synthetic-response idiom) */

#include "sockproxy_l7policy.h"
#include "sockproxy_internal.h" /* proxy_struct_t, proxy_struct, PROXY_LOCK/UNLOCK (attach) */
#include "sockproxy_cache.h"    /* cmp_proxy_ent — entry equality at attach/detach */
#include "sockproxy_cookie.h"   /* stateless cookie token derive/verify (pure) */
#include "log.h"                /* log_error — attach diagnostics */

/* strip_port_from_hostname is declared in sockproxy.h (external linkage) — used
 * to normalize the HOST operand (RESEARCH §Don't Hand-Roll). */

/* -------------------------------------------------------------------------
 * Compare-op primitives. All take NUL-terminated C strings; the operand has
 * already been resolved + (for REGEX) bounded by the caller.
 * ------------------------------------------------------------------------- */

/* L7OP_SUFFIX — does `s` end with `suffix`? */
static int
l7_str_ends_with(const char *s, const char *suffix)
{
  size_t ls = strlen(s);
  size_t lf = strlen(suffix);
  if (lf > ls)
    return 0;
  return strcmp(s + (ls - lf), suffix) == 0;
}

/* L7OP_SEGMENT_PREFIX — Gateway PathPrefix: `value` is a prefix of `s` AND the
 * match ends on a path-segment boundary. "/foo" matches "/foo" and "/foo/bar"
 * but NOT "/foobar". A trailing slash in `value` is treated segment-wise too. */
static int
l7_path_segment_prefix(const char *s, const char *value)
{
  size_t lv = strlen(value);
  /* Normalize away a single trailing '/' on value so "/foo" and "/foo/" behave
   * identically as a segment prefix (Gateway semantics). */
  if (lv > 1 && value[lv - 1] == '/')
    lv--;
  if (lv == 0)
    return 1;                       /* empty / "/" prefix matches everything */
  if (strncmp(s, value, lv) != 0)
    return 0;                       /* not a leading substring at all */
  /* Segment boundary: the char right after the prefix in `s` must be end-of-
   * string or '/'. */
  char after = s[lv];
  return (after == '\0' || after == '/');
}

/* Apply one compare op between the resolved request `operand` and the condition
 * `value`. For REGEX, `re` is the pre-compiled program and `re_valid` says
 * whether it holds one. Returns 1 on match, 0 otherwise. */
static int
l7_op_matches(l7_op_t op, const char *operand, const char *value,
              const regex_t *re, uint8_t re_valid)
{
  size_t lv;

  if (!operand)
    return 0;

  switch (op) {
  case L7OP_EQUAL:
    return strcmp(operand, value) == 0;

  case L7OP_PREFIX:
    lv = strlen(value);
    return strncmp(operand, value, lv) == 0;

  case L7OP_SEGMENT_PREFIX:
    return l7_path_segment_prefix(operand, value);

  case L7OP_SUFFIX:
    return l7_str_ends_with(operand, value);

  case L7OP_CONTAINS:
    return strstr(operand, value) != NULL;

  case L7OP_REGEX: {
    /* ReDoS bound: copy the operand into a fixed stack buffer,
     * truncating to L7_REGEX_INPUT_MAX, so an unbounded attacker-controlled
     * field can never reach regexec. NEVER regcomp here — the pattern was
     * compiled ONCE at attach time (Plan 05). */
    char bounded[L7_REGEX_INPUT_MAX];
    if (!re_valid)
      return 0;                     /* no compiled program => cannot match */
    snprintf(bounded, sizeof(bounded), "%s", operand);
    return regexec(re, bounded, 0, NULL, 0) == 0;
  }

  default:
    return 0;
  }
}

/* -------------------------------------------------------------------------
 * Operand resolution. Reads the parsed request fields off `pfe` and the Plan-02
 * generic header/cookie store. Writes the resolved NUL-terminated operand into
 * `buf` (capacity `buflen`). Returns a pointer to the operand on success, or
 * NULL if the field is absent for this request (a NULL operand never matches).
 *
 * NOTE (H1/H2 contract): the engine reads HOST/PATH/METHOD/QUERY from the
 * per-connection pfe fields (host_url / request_path / http_method / url_path).
 * For HTTP/2 those per-request values live on the stream; the Plan-04 dispatch
 * hook mirrors the active stream's authority/path/method into pfe before calling
 * l7_policy_evaluate, keeping this engine protocol-neutral and pfe-only. The
 * HEADER/COOKIE store (pfe->l7_headers) is already populated for BOTH protocols
 * by Plan (handle_header_val + proxy_h2_on_header_callback).
 * ------------------------------------------------------------------------- */
static const char *
l7_resolve_operand(struct proxy_fd_ent *pfe, const l7_condition_t *cond,
                   char *buf, size_t buflen)
{
  if (!pfe || buflen == 0)
    return NULL;
  buf[0] = '\0';

  switch (cond->field) {
  case L7F_HOST:
    /* Normalize: strip any :port from the authority/Host (RESEARCH reuse). */
    if (pfe->host_url[0] == '\0')
      return NULL;
    strip_port_from_hostname(pfe->host_url, buf, buflen);
    return buf;

  case L7F_PATH:
    if (pfe->request_path[0] == '\0')
      return NULL;
    return pfe->request_path;

  case L7F_FILE_TYPE: {
    /* Octavia FILE_TYPE: the path's file extension (without the dot), e.g.
     * "/img/logo.png" -> "png". No dot in the last segment => no operand. */
    const char *path = pfe->request_path;
    const char *q;
    const char *slash;
    const char *dot;
    if (path[0] == '\0')
      return NULL;
    /* Trim any query string first. */
    q = strchr(path, '?');
    {
      size_t plen = q ? (size_t)(q - path) : strlen(path);
      if (plen >= buflen)
        plen = buflen - 1;
      memcpy(buf, path, plen);
      buf[plen] = '\0';
    }
    slash = strrchr(buf, '/');
    dot = strrchr(slash ? slash : buf, '.');
    if (!dot || dot[1] == '\0')
      return NULL;
    /* Shift the extension to the front of buf so the caller sees just "png". */
    memmove(buf, dot + 1, strlen(dot + 1) + 1);
    return buf;
  }

  case L7F_METHOD:
#ifdef HAVE_HTTP_TRACE
    if (pfe->http_method[0] == '\0')
      return NULL;
    return pfe->http_method;
#else
    /* pfe->http_method is only captured under HAVE_HTTP_TRACE. Without it,
     * L7F_METHOD has no operand (METHOD is a Gateway-API superset extra, not
     * exercised by the Octavia a-j gate) — treat as no-match rather than
     * referencing a field that does not exist in non-trace builds. */
    return NULL;
#endif

  case L7F_HEADER: {
    /* Look the named header up in the Plan-02 generic store (case-insensitive,
     * matching HTTP header semantics). */
    uint16_t i;
    for (i = 0; i < pfe->n_l7_headers; i++) {
      if (strcasecmp(pfe->l7_headers[i].name, cond->key) == 0)
        return pfe->l7_headers[i].value;
    }
    return NULL;
  }

  case L7F_COOKIE: {
    /* Reuse extract_cookie_by_name (RESEARCH §Don't Hand-Roll). It expects a
     * "Cookie: ..." header string, so reconstruct one from the captured Cookie
     * header in the Plan-02 store. */
    uint16_t i;
    const char *cookie_val = NULL;
    char cookie_header[L7_HDR_VALUE_MAX + 16];
    for (i = 0; i < pfe->n_l7_headers; i++) {
      if (strcasecmp(pfe->l7_headers[i].name, "Cookie") == 0) {
        cookie_val = pfe->l7_headers[i].value;
        break;
      }
    }
    if (!cookie_val)
      return NULL;
    snprintf(cookie_header, sizeof(cookie_header), "Cookie: %s", cookie_val);
    if (extract_cookie_by_name(cookie_header, cond->key, buf, buflen) != 0)
      return NULL;
    return buf;
  }

  case L7F_QUERY:
    /* Reuse extract_query_param_value over the full URL (with query string). */
    if (pfe->url_path[0] == '\0')
      return NULL;
    if (extract_query_param_value(pfe->url_path, cond->key, buf, buflen) != 0)
      return NULL;
    return buf;

  default:
    /* SSL_* and any future field types are not resolvable yet. */
    return NULL;
  }
}

/* -------------------------------------------------------------------------
 * Match levels.
 * ------------------------------------------------------------------------- */

/* One condition: resolve the operand, apply the op, then apply `invert`. */
static int
l7_condition_matches(struct proxy_fd_ent *pfe, const l7_condition_t *cond)
{
  char buf[L7_REGEX_INPUT_MAX];
  const char *operand = l7_resolve_operand(pfe, cond, buf, sizeof(buf));
  /* A NULL operand (field absent) is a non-match BEFORE inversion: an inverted
   * "header X == foo" must match a request that LACKS header X (the field-absent
   * case is a legitimate negative), so we still apply invert below. */
  int raw = l7_op_matches(cond->op, operand, cond->value,
                          &cond->re, cond->re_valid);
  return cond->invert ? !raw : raw;
}

/* One match set: AND within the set (every condition must match). An empty set
 * (n_conds == 0) matches nothing — a route must declare at least one condition
 * to match (a catch-all is expressed as a single always-true condition). */
static int
l7_set_matches(struct proxy_fd_ent *pfe, const l7_match_set_t *set)
{
  uint8_t i;
  uint8_t n = set->n_conds;
  if (n == 0)
    return 0;
  if (n > L7_MAX_CONDS_PER_SET)
    n = L7_MAX_CONDS_PER_SET;
  for (i = 0; i < n; i++) {
    if (!l7_condition_matches(pfe, &set->conds[i]))
      return 0;                     /* AND: one failure fails the set */
  }
  return 1;
}

/* One route: OR across sets (any set matching matches the route). */
static int
l7_route_matches(struct proxy_fd_ent *pfe, const l7_route_t *route)
{
  uint8_t i;
  uint8_t n = route->n_sets;
  if (n > L7_MAX_SETS_PER_ROUTE)
    n = L7_MAX_SETS_PER_ROUTE;
  for (i = 0; i < n; i++) {
    if (l7_set_matches(pfe, &route->sets[i]))
      return 1;                     /* OR: one set matching matches the route */
  }
  return 0;
}

/* -------------------------------------------------------------------------
 * Public entry point — ordered first-match-wins evaluation.
 * ------------------------------------------------------------------------- */
int
l7_policy_evaluate(struct proxy_fd_ent *pfe, const l7_route_t *routes,
                   int n_routes, l7_decision_t *decision_out)
{
  int i;

  if (!pfe || !routes || !decision_out || n_routes <= 0)
    return -1;

  /* INVARIANT: `routes` is position-sorted at attach time (Plan 05). The engine
 * walks them in array order and the FIRST matching route wins. */
  for (i = 0; i < n_routes; i++) {
    const l7_route_t *route = &routes[i];
    if (!l7_route_matches(pfe, route))
      continue;

    /* First match wins — copy the route's action into the decision. */
    memset(decision_out, 0, sizeof(*decision_out));
    decision_out->kind = route->action.kind;
    switch (route->action.kind) {
    case L7A_FORWARD:
      decision_out->u.fwd = route->action.u.fwd;
      break;
    case L7A_REDIRECT:
      decision_out->u.redir = route->action.u.redir;
      /* The assembled Location URL is built by the dispatch hook (Plan 04),
       * which has the live request scheme/host/path; leave it empty here. */
      decision_out->location[0] = '\0';
      break;
    case L7A_REJECT:
      decision_out->u.reject = route->action.u.reject;
      break;
    default:
      /* Unknown action kind — treat as no usable decision. */
      return -1;
    }
    return 0;
  }

  /* No route matched: the caller (Plan 04) emits the configured default
   * (404 for Gateway parity / Octavia explicit REJECT). */
  decision_out->kind = L7A_REJECT;
  decision_out->u.reject.status_code = 0; /* 0 => caller's default */
  return -1;
}

/* -------------------------------------------------------------------------
 * Terminal synthetic-response responders (Plan 04 — generalized from the proven
 * 403/401 (sockproxy_http.c:4543/4552) + 429 (sockproxy_http.c:4576) idiom:
 * snprintf a complete HTTP/1.1 response into a stack buffer, send() it on the
 * client fd, then shutdown(SHUT_RDWR) and return. Terminal — bypasses the backend
 * and never interacts with SSE.
 * ------------------------------------------------------------------------- */

/* Map a status code to its canonical reason phrase. Only the codes the L7 engine
 * emits are enumerated; anything else falls back to a generic phrase. */
static const char *
l7_reason_phrase(int code)
{
  switch (code) {
  case 301: return "Moved Permanently";
  case 302: return "Found";
  case 303: return "See Other";
  case 307: return "Temporary Redirect";
  case 308: return "Permanent Redirect";
  case 400: return "Bad Request";
  case 401: return "Unauthorized";
  case 403: return "Forbidden";
  case 404: return "Not Found";
  case 405: return "Method Not Allowed";
  case 410: return "Gone";
  case 429: return "Too Many Requests";
  default:  return "Error";
  }
}

/* True if `s` contains a CR or LF — header/CRLF-injection guard. A
 * value that fails this MUST NOT be emitted verbatim into a header line. */
static int
l7_has_crlf(const char *s)
{
  return s != NULL && (strchr(s, '\r') != NULL || strchr(s, '\n') != NULL);
}

/*
 * l7_send_reject — emit a synthetic terminal REJECT (default 403). The optional
 * `body` is plain text; to avoid leaking backend internals (ASVS V7)
 * the caller passes only minimal text (NULL => a generic one-liner). Any CR/LF in
 * `body` is rejected (it would otherwise let an attacker-influenced value inject
 * headers) — on a tainted body we fall back to the safe generic body.
 */
int l7_send_reject(struct proxy_fd_ent *pfe, int status_code, const char *body)
{
  char resp[512];
  const char *safe_body;
  int code = status_code;
  int n;

  if (!pfe || pfe->fd < 0)
    return -1;

  /* Default 403 for REJECT; clamp to a sane 4xx/5xx range. */
  if (code == 0)
    code = 403;
  if (code < 400 || code > 599)
    code = 403;

  /* CRLF-safe body: a tainted body collapses to the generic one. */
  safe_body = (body && !l7_has_crlf(body)) ? body : "Request rejected by policy";

  /* HTTP/2: on an active h2 stream the raw "HTTP/1.1..." bytes below
   * are an h2 framing violation (the client aborts the connection — curl 000), so
   * frame the REJECT via nghttp2 instead. Returns 0 when it handled h2; -1 (off
   * h2) falls through to the H1 raw-response path. */
  if (proxy_h2_send_l7_synthetic(pfe, code, NULL, safe_body) == 0)
    return 0;

  n = snprintf(resp, sizeof(resp),
               "HTTP/1.1 %d %s\r\n"
               "Content-Type: text/plain\r\n"
               "Connection: close\r\n"
               "\r\n"
               "%s\r\n",
               code, l7_reason_phrase(code), safe_body);
  if (n > 0 && n < (int)sizeof(resp))
    send(pfe->fd, resp, (size_t)n, MSG_DONTWAIT | MSG_NOSIGNAL);

  shutdown(pfe->fd, SHUT_RDWR);
  return 0;
}

/*
 * l7_send_redirect — emit a synthetic terminal 3xx with a Location: header
 * (default 302). The status code is restricted to {301,302,303,307,308} (any
 * other value coerces to 302). CRLF-SAFE: a `location` carrying a CR or
 * LF is rejected outright (we send a 400 instead of emitting an injectable
 * header) — no attacker-influenced value ever reaches the header line unfiltered.
 */
int l7_send_redirect(struct proxy_fd_ent *pfe, int status_code,
                     const char *location)
{
  char resp[L7_REDIRECT_LOCATION_MAX + 256];
  int code = status_code;
  int n;

  if (!pfe || pfe->fd < 0)
    return -1;

  /* Restrict to the five allowed redirect codes; default/coerce to 302. */
  switch (code) {
  case 301: case 302: case 303: case 307: case 308:
    break;
  default:
    code = 302;
    break;
  }

  /* CRLF / header-injection guard: never emit a Location with CR/LF.
   * Also reject an empty/absent location (a redirect with no target is invalid). */
  if (!location || location[0] == '\0' || l7_has_crlf(location)) {
    l7_send_reject(pfe, 400, "Invalid redirect target");
    return 0;
  }

  /* HTTP/2: frame the 3xx + Location via nghttp2 on the active stream;
   * the raw "HTTP/1.1 ..." bytes below corrupt an h2 connection. 0 = handled on
   * h2; -1 (off h2) falls through to the H1 raw-response path. */
  if (proxy_h2_send_l7_synthetic(pfe, code, location, NULL) == 0)
    return 0;

  n = snprintf(resp, sizeof(resp),
               "HTTP/1.1 %d %s\r\n"
               "Location: %s\r\n"
               "Content-Length: 0\r\n"
               "Connection: close\r\n"
               "\r\n",
               code, l7_reason_phrase(code), location);
  if (n > 0 && n < (int)sizeof(resp))
    send(pfe->fd, resp, (size_t)n, MSG_DONTWAIT | MSG_NOSIGNAL);

  shutdown(pfe->fd, SHUT_RDWR);
  return 0;
}

/* -------------------------------------------------------------------------
 * FORWARD resolution + the shared dispatch helper (Plan 04, Task 2).
 * ------------------------------------------------------------------------- */

/*
 * l7_resolve_pool — map a FORWARD action to a tepval-equivalent (proxy_epval_t *)
 * representing the MATCHED ROUTE'S target backend set so FORWARD re-enters the
 * EXISTING intra-pool endpoint selector (a plain pool, never the AI model
 * engine) but selects ONLY among the route's endpoints (honoring weights).
 *
 * Mechanism (gap-fix): the service's backends are the members (eps[]) of the base
 * pool ent->val.ephash. A FORWARD route names a SUBSET of those members by index
 * in fwd->refs[].ep (the position of the member in the VIP's endpoint list, e.g.
 * ep0/ep1/ep2 from the LB-rule seed) plus an optional per-ref weight. We build a
 * NARROWED copy of the base pool that carries only the referenced endpoints, then
 * hand it back so the existing EP-select switch picks WITHIN that subset.
 *
 *   fwd->n_refs == 0  -> no subset named: forward to the whole base pool (the
 *                        prior behavior — a plain catch-all FORWARD).
 *   fwd->n_refs  > 0  -> forward to exactly the referenced endpoints, with their
 *                        weights applied (single ref => that one endpoint).
 *
 * Lifetime / safety: the narrowed pool lives in a SINGLE reusable scratch buffer
 * on the proxy_map_ent (ent->l7_resolved_pool), allocated lazily. The proxy hot
 * path is single-threaded (one proxy_run event-loop thread) and each request
 * fully consumes the resolved pool (connects to the selected endpoint) within the
 * same synchronous dispatch before the next request is routed — exactly the model
 * under which the existing code mutates tepval->ep_sel without per-call locking.
 * We DO NOT return a stack temporary, and we deliberately DROP every shared owned
 * pointer (hash_ring / chwbl_config / pd_trie / session maps / locks) from the
 * scratch copy and force select = PROXY_SEL_RR (or PROXY_SEL_WRR when the refs
 * carry non-uniform weights) so the narrowed pool never touches — and can never
 * double-free — those subsystems. Returns NULL when there is no usable pool.
 */
proxy_epval_t *
l7_resolve_pool(proxy_map_ent_t *ent, l7_forward_t *fwd)
{
  proxy_epval_t *base;
  proxy_epval_t *sub;
  int i, n_sel;
  uint8_t saw_weight, nonuniform;
  uint8_t first_weight;

  if (!ent)
    return NULL;

  base = ent->val.ephash;
  if (!base)
    return NULL;

  /* No subset named -> forward to the whole service pool (plain catch-all). */
  if (!fwd || fwd->n_refs == 0)
    return base;

  /* Lazily allocate the single reusable scratch resolved-pool on the map_ent. */
  if (!ent->l7_resolved_pool) {
    ent->l7_resolved_pool = calloc(1, sizeof(proxy_epval_t));
    if (!ent->l7_resolved_pool)
      return base;                  /* allocation failed -> degrade to base pool */
  }
  sub = (proxy_epval_t *)ent->l7_resolved_pool;

  /* Start from a byte copy of the base pool so the EP-select switch sees the same
   * shape, THEN strip every shared owned pointer (we must never free those via the
   * scratch) and reset the per-pool selection state. */
  memcpy(sub, base, sizeof(*sub));
  sub->hash_ring        = NULL;     /* never touch CHWBL state through the scratch */
  sub->chwbl_config     = NULL;
  sub->pd_trie          = NULL;
  sub->pd_session_map   = NULL;
  sub->pd_disagg_enabled = 0;       /* a FORWARD subset is a plain pool */
  sub->ai_gw_mode       = 0;
  sub->pd_cache_aware_mode = 0;
  sub->cb_enabled       = 0;        /* circuit-breaker state belongs to the base   */
  sub->ep_sel           = 0;        /* fresh RR cursor for the narrowed set        */
  sub->wrr_initialized  = 0;        /* recompute WRR for the narrowed weights      */

  /* Copy ONLY the referenced endpoints into the narrowed eps[]. fwd->refs[i].ep is
   * the index of a member in the base pool; out-of-range / inactive refs are
   * skipped. We also carry the ref weight onto the endpoint (Gateway weighted
   * backendRefs) and detect whether the weights are non-uniform. */
  n_sel = 0;
  saw_weight = 0;
  nonuniform = 0;
  first_weight = 0;
  for (i = 0; i < fwd->n_refs && i < MAX_PROXY_EP; i++) {
    uint32_t ei = fwd->refs[i].ep;
    uint8_t  w  = fwd->refs[i].weight;
    if (ei >= (uint32_t)base->n_eps || ei >= MAX_PROXY_EP)
      continue;                     /* ref names a non-existent member -> skip      */
    sub->eps[n_sel] = base->eps[ei];        /* xip/xport/protocol/inv/... */
    sub->ep_stats[n_sel] = base->ep_stats[ei];
    if (w != 0)
      sub->eps[n_sel].weight = w;           /* ref weight overrides member weight   */
    if (!saw_weight) {
      first_weight = sub->eps[n_sel].weight;
      saw_weight = 1;
    } else if (sub->eps[n_sel].weight != first_weight) {
      nonuniform = 1;
    }
    n_sel++;
  }

  if (n_sel == 0)
    return NULL;                    /* every ref was invalid -> no usable backend   */

  sub->n_eps = n_sel;

  /* Uniform (or single-endpoint) weights -> plain round-robin within the subset;
   * non-uniform weights -> weighted round-robin (the existing EP-select switch
   * computes the smooth-WRR schedule from eps[].weight on demand). Either way the
   * subset is a PLAIN pool — it never re-enters CHWBL / P/D / the AI model engine. */
  sub->select = (n_sel > 1 && nonuniform) ? PROXY_SEL_WRR : PROXY_SEL_RR;

  return sub;
}

/*
 * l7_assemble_redirect_location — build the final `Location:` URL for an L7A_REDIRECT
 * decision from the matched route's redirect IR (`redir`) plus the LIVE request
 * context on `pfe` (scheme / Host / path). Runs in l7_route_dispatch so it sees the
 * real per-connection (H1) or stream-mirrored (H2) request fields — the engine is
 * pfe-only . Writes a NUL-terminated, snprintf-bounded, CRLF-free URL
 * into `out` (capacity `outsz`, expected L7_REDIRECT_LOCATION_MAX).
 *
 * Field resolution (per the IR contract, sockproxy_l7policy.h):
 *   scheme : redir.scheme if set, else the request scheme — "https" when the client
 *            connection is TLS (pfe->ssl != NULL, the same predicate used by
 *            rewrite_location_header, sockproxy_http.c) else "http".
 *   host   : redir.host if set, else the request Host/authority (pfe->host_url),
 *            port-stripped via strip_port_from_hostname (reused, IPv6-aware).
 *   port   : appended ":port" only when redir.port is set AND not the scheme default
 *            (80 for http / 443 for https) — otherwise omitted.
 *   path   : L7PATH_NONE        -> the request path (pfe->request_path, "/" if empty)
 *            L7PATH_REPLACE_FULL -> redir.value (Octavia REDIRECT_TO_URL / Gateway
 *                                   full path replace; the gate's pos50 leg)
 *            L7PATH_REPLACE_PREFIX -> the matched prefix is NOT propagated into the
 *                                   decision today (l7_decision_t carries only the
 *                                   redirect IR, not the matched condition value), so
 *                                   we cannot reconstruct the post-prefix remainder.
 *                                   Best-effort, valid (never injectable): use
 *                                   redir.value as the replacement prefix joined with
 *                                   the request path. NOTE: a fully-correct
 *                                   ReplacePrefixMatch needs the matched prefix in the
 *                                   decision (future IR addition); REPLACE_PREFIX is
 *                                   NOT exercised by the Phase-75 gate (REPLACE_FULL).
 *
 * Returns 0 on success (out holds a usable URL), -1 if no host could be resolved or
 * the assembled value would carry CR/LF (caller then leaves Location empty so
 * l7_send_redirect fails closed to 400 — never an injectable header).
 */
static int
l7_assemble_redirect_location(struct proxy_fd_ent *pfe, const l7_redirect_t *redir,
                              char *out, size_t outsz)
{
  const char *scheme;
  char host[256];
  char portbuf[8];
  const char *path;
  int n;

  if (!pfe || !redir || !out || outsz == 0)
    return -1;
  out[0] = '\0';

  /* scheme: explicit override, else derive from the client connection's TLS state
   * (mirrors rewrite_location_header's `pfe->ssl != NULL` predicate). */
  if (redir->scheme[0] != '\0')
    scheme = redir->scheme;
  else
    scheme = (pfe->ssl != NULL) ? "https" : "http";

  /* host: explicit override, else the request Host/authority — always port-stripped
   * (IPv6-aware). An empty result means we have no usable target host. */
  host[0] = '\0';
  if (redir->host[0] != '\0')
    strip_port_from_hostname(redir->host, host, sizeof(host));
  else if (pfe->host_url[0] != '\0')
    strip_port_from_hostname(pfe->host_url, host, sizeof(host));
  if (host[0] == '\0')
    return -1; /* no target host -> caller fails closed (400) */

  /* port: append only when set and not the scheme default. */
  portbuf[0] = '\0';
  if (redir->port != 0) {
    int is_https = (strcmp(scheme, "https") == 0);
    int dflt = is_https ? 443 : 80;
    if ((int)redir->port != dflt)
      snprintf(portbuf, sizeof(portbuf), ":%u", (unsigned)redir->port);
  }

  /* path: per path_op (see contract above). */
  switch (redir->path_op) {
  case L7PATH_REPLACE_FULL:
    path = redir->value;
    break;
  case L7PATH_REPLACE_PREFIX:
    /* Best-effort (matched prefix not in the decision): replacement-prefix + request
     * path. Bounded compose into `out` first, then fall through to the final URL. */
    path = (pfe->request_path[0] != '\0') ? pfe->request_path : "/";
    {
      char joined[L7_VALUE_MAX + 256];
      const char *rp = path;
      /* Avoid a doubled '/' between value and the request path. */
      if (redir->value[0] != '\0' && redir->value[strlen(redir->value) - 1] == '/'
          && rp[0] == '/')
        rp++;
      snprintf(joined, sizeof(joined), "%s%s", redir->value, rp);
      n = snprintf(out, outsz, "%s://%s%s%s", scheme, host, portbuf, joined);
      if (n <= 0 || (size_t)n >= outsz || l7_has_crlf(out)) {
        out[0] = '\0';
        return -1;
      }
      return 0;
    }
  case L7PATH_NONE:
  default:
    path = (pfe->request_path[0] != '\0') ? pfe->request_path : "/";
    break;
  }

  /* Compose scheme://host[:port]path, snprintf-bounded + CRLF-checked. */
  n = snprintf(out, outsz, "%s://%s%s%s", scheme, host, portbuf, path);
  if (n <= 0 || (size_t)n >= outsz || l7_has_crlf(out)) {
    out[0] = '\0';
    return -1;
  }
  return 0;
}

/*
 * l7_route_dispatch — shared discriminator + dispatch. See the header for the
 * full contract. Invoked IDENTICALLY at both the H1 (sockproxy_ep.c:400) and the
 * H2 (sockproxy_h2.c:1962) find_endpoint_lpm seams so they cannot drift.
 */
int
l7_route_dispatch(struct proxy_fd_ent *pfe, proxy_map_ent_t *ent,
                  proxy_epval_t **tepval_out)
{
  l7_decision_t d;
  const l7_route_t *routes;

  /* DISCRIMINATOR: no L7 policy attached => pure no-op fall-through, so
 * every AI/model service runs UNCHANGED (Pitfall 5). This is
   * the first reader of has_l7_policy (declared on proxy_map_ent by Plan 04;
   * populated by Plan 05's proxy_attach_l7_policy). */
  if (!ent || !ent->has_l7_policy)
    return L7_DISPATCH_FALLTHROUGH;

  routes = (const l7_route_t *)ent->l7_routes; /* opaque void* on proxy_map_ent */

  memset(&d, 0, sizeof(d));
  if (l7_policy_evaluate(pfe, routes, ent->n_l7_routes, &d) == 0) {
    switch (d.kind) {
    case L7A_REJECT:
      l7_send_reject(pfe, d.u.reject.status_code, d.reject_body);
      return L7_DISPATCH_TERMINATED;
    case L7A_REDIRECT:
      /* Assemble the final Location URL from the matched route's redirect IR + the
       * LIVE request context (scheme/Host/path) — the engine left d.location empty
       * (l7_policy_evaluate) precisely so it could be built here, where pfe carries
       * the per-connection (H1) / stream-mirrored (H2) request fields. On failure to
       * resolve a target, d.location stays empty and l7_send_redirect fails closed to
 * 400 rather than emitting an injectable/invalid header. */
      l7_assemble_redirect_location(pfe, &d.u.redir, d.location, sizeof(d.location));
      l7_send_redirect(pfe, d.u.redir.status_code, d.location);
      return L7_DISPATCH_TERMINATED;
    case L7A_FORWARD:
      if (tepval_out)
        *tepval_out = l7_resolve_pool(ent, &d.u.fwd);
      return L7_DISPATCH_FORWARD;
    default:
      /* Unknown action kind — terminal default reject. */
      l7_send_reject(pfe, 404, NULL);
      return L7_DISPATCH_TERMINATED;
    }
  }

  /* No route matched: Gateway no-match default is 404 (configurable, RESEARCH
   * Open-Questions resolution). */
  l7_send_reject(pfe, 404, NULL);
  return L7_DISPATCH_TERMINATED;
}

/* -------------------------------------------------------------------------
 * (CONTEXT) — request header insertion applier.
 *
 * THE SINGLE SHARED op-selection + validation logic for BOTH H1 and H2 (Pitfall
 * 1 parity). Protocol-neutral: it emits the ordered op set (X-Forwarded-* trio
 * first, then the matched route's insertHeaders SET/ADD/REMOVE) through a caller
 * EMIT callback. nghttp2 / CRLF byte-splicing live in the per-protocol callers;
 * the WHAT and the validation live here, ONCE.
 * ------------------------------------------------------------------------- */

/* Reject CR/LF/NUL/control chars in a header NAME ( CRLF injection).
 * Empty name is invalid. Bounded scan to L7_HDR_NAME_MAX. */
int
l7_hdr_name_valid(const char *name)
{
  size_t i;
  if (!name || name[0] == '\0')
    return 0;
  for (i = 0; i < (size_t)L7_HDR_NAME_MAX && name[i] != '\0'; i++) {
    unsigned char c = (unsigned char)name[i];
    /* Forbid CR, LF, NUL (handled by loop) and any other ASCII control char,
     * plus DEL — no header-name byte may break the request framing. */
    if (c < 0x20 || c == 0x7f || c == ':')
      return 0;
  }
  /* name must be NUL-terminated within the bound (no over-long unterminated). */
  return (name[i] == '\0') ? 1 : 0;
}

/* Reject CR/LF/NUL/control chars in a header VALUE. An EMPTY value
 * is allowed (a header may legitimately carry an empty value). Bounded scan. */
int
l7_hdr_value_valid(const char *value)
{
  size_t i;
  if (!value)
    return 0;
  for (i = 0; i < (size_t)L7_HDR_VALUE_MAX && value[i] != '\0'; i++) {
    unsigned char c = (unsigned char)value[i];
    /* HT (0x09) is permitted in header values; CR/LF/other controls are not. */
    if (c == '\t')
      continue;
    if (c < 0x20 || c == 0x7f)
      return 0;
  }
  return (value[i] == '\0') ? 1 : 0;
}

/*
 * synthesize the HSTS header VALUE, shared by the H1
 * and H2 emit seams (one-synthesizer/two-emit-seams). Builds
 * "max-age=N[; includeSubDomains][; preload]" from the proxy_arg HSTS scalars.
 * max_age==0 ⇒ no injection (returns 0; default-off, RFC 6797). The value is
 * fully server-synthesized (no client/operator string flows in — low injection
 * surface), but the caller still runs l7_hdr_value_valid on it for defence in
 * depth. Returns the written length (>0) or 0 on no-injection / overflow.
 */
size_t
l7_hsts_synthesize(uint32_t max_age, uint8_t include_subdomains,
                   uint8_t preload, char *out, size_t outlen)
{
  int n;
  if (!out || outlen == 0)
    return 0;
  out[0] = '\0';
  if (max_age == 0)            /* 0 ⇒ no HSTS injection. */
    return 0;
  n = snprintf(out, outlen, "max-age=%u%s%s",
               (unsigned)max_age,
               include_subdomains ? "; includeSubDomains" : "",
               preload ? "; preload" : "");
  if (n <= 0 || (size_t)n >= outlen) {
    out[0] = '\0';
    return 0;
  }
  return (size_t)n;
}

/* Return the FIRST matching route for `pfe` over `ent`'s position-sorted array
 * (mirrors l7_policy_evaluate's first-match-wins), or NULL if none match. Its
 * hdr_filters are the insertHeaders ops that apply to this request. */
static const l7_route_t *
l7_first_matching_route(struct proxy_fd_ent *pfe, proxy_map_ent_t *ent)
{
  const l7_route_t *routes;
  int i;
  if (!pfe || !ent || !ent->l7_routes || ent->n_l7_routes <= 0)
    return NULL;
  routes = (const l7_route_t *)ent->l7_routes;
  for (i = 0; i < ent->n_l7_routes; i++) {
    if (l7_route_matches(pfe, &routes[i]))
      return &routes[i];
  }
  return NULL;
}

void
l7_apply_req_filters(struct proxy_fd_ent *pfe, struct proxy_map_ent *ent,
                     const char *xff_ip, uint16_t listener_port,
                     const char *xfproto,
                     l7_hdr_emit_fn emit, void *ctx)
{
  const l7_route_t *route;
  char port_str[8];
  uint8_t i, n;

  if (!pfe || !ent || !emit)
    return;

  /* (1)-(3) Always-overwrite X-Forwarded-* trio. SET semantics =
   * strip-any-existing + add, so a client-supplied XFF can NEVER be trusted —
 * loxilb is the trust boundary. Each value is validated (the peer
   * IP / scheme are loxilb-derived and well-formed, but validate anyway as
   * defence-in-depth — a malformed one is dropped, never spliced). */
  if (xff_ip && l7_hdr_value_valid(xff_ip))
    emit(ctx, L7HDR_SET, "X-Forwarded-For", xff_ip);

  snprintf(port_str, sizeof(port_str), "%u", (unsigned)listener_port);
  emit(ctx, L7HDR_SET, "X-Forwarded-Port", port_str);

  if (xfproto && l7_hdr_value_valid(xfproto))
    emit(ctx, L7HDR_SET, "X-Forwarded-Proto", xfproto);

  /* (4) The matched route's bounded insertHeaders ops. */
  route = l7_first_matching_route(pfe, (proxy_map_ent_t *)ent);
  if (!route)
    return;

  n = route->n_hdr_filters;
  if (n > L7_MAX_HDR_FILTERS)
    n = L7_MAX_HDR_FILTERS;               /* DoS bound */
  for (i = 0; i < n; i++) {
    const l7_hdr_filter_t *f = &route->hdr_filters[i];
    /* Reject control-char names/values at APPLY time (defence-in-depth behind the
 * REST 400) — a bad entry is SKIPPED, never spliced. */
    if (!l7_hdr_name_valid(f->name))
      continue;
    if (f->op != L7HDR_REMOVE && !l7_hdr_value_valid(f->value))
      continue;
    emit(ctx, (int)f->op, f->name,
         (f->op == L7HDR_REMOVE) ? "" : f->value);
  }
}

/* -------------------------------------------------------------------------
 * (CONTEXT) — STATELESS HTTP_COOKIE
 * persistence: node-level bridges from the data-plane structs (proxy_map_ent /
 * proxy_epval) to the PURE token primitives in sockproxy_cookie.h. NOTHING is
 * stored on proxy_fd_ent — the cookie value IS the entire binding, so the
 * affinity survives HA failover with zero xSync change. The primitives are unit-
 * tested standalone (sockproxy_cookie_test.c) — here we only marshal struct
 * fields into them.
 * ------------------------------------------------------------------------- */

/* Compute this service's deterministic per-VIP secret from node->key (VIP:port).
 * Byte-identical on both HA peers (the key is synced config), so a cookie minted
 * on peer A read-back-matches on peer B ( cross-peer affinity). Returns 0 on
 * success. */
int
l7_cookie_node_vip_secret(const struct proxy_map_ent *node,
                          uint8_t out[LB_COOKIE_VIP_SECRET_LEN])
{
  char vip_port[64];
  if (!node || !out)
    return -1;
  /* key.xip / key.xport are network-order; render verbatim — only determinism +
   * per-VIP uniqueness matter (identical on both peers from the same config). */
  snprintf(vip_port, sizeof(vip_port), "%u:%u",
           (unsigned)node->key.xip, (unsigned)node->key.xport);
  return l7_cookie_derive_vip_secret(vip_port, out);
}

/* Derive the cookie token for a SPECIFIC live member index of `tepval` (the
 * Set-Cookie value the LB mints for the backend it chose). Returns the token
 * length (>0) on success, -1 on bad input / index. */
int
l7_cookie_node_token_for_ep(const struct proxy_map_ent *node,
                            const struct proxy_epval *tepval, int ep_idx,
                            char *out, size_t outsz)
{
  uint8_t secret[LB_COOKIE_VIP_SECRET_LEN];
  char mid[64];
  if (!node || !tepval || ep_idx < 0 || ep_idx >= tepval->n_eps || !out)
    return -1;
  if (l7_cookie_node_vip_secret(node, secret) != 0)
    return -1;
  if (l7_cookie_member_id(tepval->eps[ep_idx].xip, tepval->eps[ep_idx].xport,
                          mid, sizeof(mid)) != 0)
    return -1;
  return l7_cookie_derive_token(mid, secret, out, outsz);
}

/* Read-back: match a presented cookie `token` against the LIVE member set of
 * `tepval`, constant-time. Returns the matched EP index, or L7_COOKIE_MISS on no
 * match (the caller MUST then fall through to the normal LB hash — never an
 * arbitrary backend). Down members (inv!=0) are skipped so a
 * stale token rehashes. */
int
l7_cookie_node_match(const struct proxy_map_ent *node,
                     const struct proxy_epval *tepval, const char *token)
{
  uint8_t secret[LB_COOKIE_VIP_SECRET_LEN];
  uint32_t xip[MAX_PROXY_EP];
  uint16_t xport[MAX_PROXY_EP];
  uint8_t inv[MAX_PROXY_EP];
  int i, n;
  if (!node || !tepval || !token || token[0] == '\0')
    return L7_COOKIE_MISS;
  if (l7_cookie_node_vip_secret(node, secret) != 0)
    return L7_COOKIE_MISS;
  n = tepval->n_eps;
  if (n > MAX_PROXY_EP)
    n = MAX_PROXY_EP;
  for (i = 0; i < n; i++) {
    xip[i]   = tepval->eps[i].xip;
    xport[i] = tepval->eps[i].xport;
    inv[i]   = tepval->eps[i].inv;
  }
  return l7_cookie_match_token_eps(token, secret, xip, xport, inv, n);
}

/* Is HTTP_COOKIE persistence enabled on the FIRST matching route for `pfe`?
 * (Mirrors first-match-wins; the listener-level cookie_persist marker rides the
 * matched route.) Returns 1 if cookie mode is active, else 0. */
int
l7_cookie_persist_active(struct proxy_fd_ent *pfe, struct proxy_map_ent *ent)
{
  const l7_route_t *route;
  if (!pfe || !ent || !ent->has_l7_policy)
    return 0;
  route = l7_first_matching_route(pfe, (proxy_map_ent_t *)ent);
  return (route && route->cookie_persist) ? 1 : 0;
}

/* Reconstruct the presented cookie value of name LB_COOKIE_NAME from the bounded
 * generic header store (pfe->l7_headers[], H1/H2 parity) and extract it via the
 * proven extract_cookie_by_name() (RESEARCH §Don't Hand-Roll). Returns 0 + fills
 * `out` on success, -1 if no such cookie is present. */
int
l7_cookie_read_presented(struct proxy_fd_ent *pfe, char *out, size_t outsz)
{
  const char *cookie_val = NULL;
  char cookie_header[L7_HDR_VALUE_MAX + 16];
  uint16_t i;
  if (!pfe || !out || outsz == 0)
    return -1;
  for (i = 0; i < pfe->n_l7_headers; i++) {
    if (strcasecmp(pfe->l7_headers[i].name, "Cookie") == 0) {
      cookie_val = pfe->l7_headers[i].value;
      break;
    }
  }
  if (!cookie_val)
    return -1;
  snprintf(cookie_header, sizeof(cookie_header), "Cookie: %s", cookie_val);
  if (extract_cookie_by_name(cookie_header, LB_COOKIE_NAME, out, outsz) != 0)
    return -1;
  return 0;
}

/* -------------------------------------------------------------------------
 * Attach / detach (Plan 05). These run on the control-plane CGO thread, behind
 * PROXY_LOCK, to (un)install an ordered L7 route array on a proxy_map_ent.
 *
 * The discriminator fields (has_l7_policy / l7_routes / n_l7_routes) were already
 * DECLARED on proxy_map_ent by Plan 04; this code only POPULATES them. The
 * 4096-byte proxy_arg _Static_assert is NOT touched — the route array lives on the
 * per-service heap struct, never on the eBPF map value (Pitfall 2).
 * ------------------------------------------------------------------------- */

/* qsort comparator: ascending `position` (FIRST-MATCH-WINS depends on this — the
 * evaluate engine, Plan 03, assumes the array is position-sorted). */
static int
l7_route_cmp_position(const void *a, const void *b)
{
  const l7_route_t *ra = (const l7_route_t *)a;
  const l7_route_t *rb = (const l7_route_t *)b;
  if (ra->position < rb->position)
    return -1;
  if (ra->position > rb->position)
    return 1;
  return 0;
}

/* regfree every compiled REGEX program across a route array, then free the array.
 * Mirrors the inverse of the attach-time regcomp loop so no compiled program leaks
 * (DELETE path / re-attach replace). Safe on NULL. */
static void
l7_free_routes(l7_route_t *routes, int n_routes)
{
  int i;
  uint8_t si, ci;
  if (!routes)
    return;
  for (i = 0; i < n_routes; i++) {
    l7_route_t *r = &routes[i];
    uint8_t ns = r->n_sets;
    if (ns > L7_MAX_SETS_PER_ROUTE)
      ns = L7_MAX_SETS_PER_ROUTE;
    for (si = 0; si < ns; si++) {
      l7_match_set_t *set = &r->sets[si];
      uint8_t nc = set->n_conds;
      if (nc > L7_MAX_CONDS_PER_SET)
        nc = L7_MAX_CONDS_PER_SET;
      for (ci = 0; ci < nc; ci++) {
        l7_condition_t *cond = &set->conds[ci];
        if (cond->re_valid) {
          regfree(&cond->re);
          cond->re_valid = 0;
        }
      }
    }
  }
  free(routes);
}

/* Detach (and free) any policy currently attached to `ent`. Caller holds the lock.
 * Clears the three discriminator fields so l7_route_dispatch reverts to a no-op. */
static void
l7_clear_attached(proxy_map_ent_t *ent)
{
  if (!ent)
    return;
  if (ent->l7_routes) {
    l7_free_routes((l7_route_t *)ent->l7_routes, ent->n_l7_routes);
    ent->l7_routes = NULL;
  }
  ent->n_l7_routes = 0;
  ent->has_l7_policy = 0;
  /* Free the FORWARD scratch resolved-pool (gap-fix). It holds NO owned sub-
   * objects (l7_resolve_pool deliberately strips every shared owned pointer —
   * hash_ring/chwbl_config/pd_trie/session maps — before use), so a plain free
   * of the buffer itself is correct and leak-free. */
  if (ent->l7_resolved_pool) {
    free(ent->l7_resolved_pool);
    ent->l7_resolved_pool = NULL;
  }
}

/*
 * proxy_attach_l7_policy — install the ordered L7 route array on the running
 * proxy_map_ent keyed by `key`. Modeled on proxy_set_service_catalog (lock, walk
 * proxy_struct->head, cmp_proxy_ent, store, unlock) and the proxy_update_mtls_config
 * lifecycle. On match:
 *   1. free any PRIOR policy (regfree its compiled programs) — replace semantics;
 *   2. deep-copy the n_routes into a heap array OWNED by the map_ent;
 *   3. regcomp ONCE (REG_EXTENDED | REG_NOSUB) every L7OP_REGEX condition into
 *      cond->re / cond->re_valid — this is the ONLY place regcomp runs (ReDoS,
 *; the hot path NEVER compiles). A malformed pattern => roll back
 *      the whole attach and return -1 (the handler maps that to a REST 400);
 *   4. sort the routes ascending by `position` (the evaluate engine assumes sorted);
 *   5. POPULATE the Plan-04 discriminator fields: l7_routes / n_l7_routes /
 *      has_l7_policy = 1.
 * Returns 0 on success, negative on error.
 */
int proxy_attach_l7_policy(struct proxy_ent *key, const l7_route_t *routes,
                           int n_routes)
{
  proxy_map_ent_t *node;
  l7_route_t *copy;
  int i;
  uint8_t si, ci;

  if (!key)
    return -1;
  if (!proxy_struct)
    return -1;
  /* n_routes == 0 is a valid "clear the policy" request (delegated to detach). */
  if (n_routes <= 0 || !routes)
    return proxy_detach_l7_policy(key);

  /* Deep-copy the route array onto the heap (ownership transfers to the map_ent).
   * Done BEFORE taking the lock so the (potentially slow) regcomp loop does not
   * hold PROXY_LOCK for longer than the swap. */
  copy = (l7_route_t *)calloc((size_t)n_routes, sizeof(l7_route_t));
  if (!copy)
    return -1;
  memcpy(copy, routes, (size_t)n_routes * sizeof(l7_route_t));

  /* regcomp ONCE per REGEX condition (the SINGLE compile site — Pattern 3 /
 * ReDoS). The incoming `routes` carry re_valid == 0 (the handler IR
   * never compiles); we own the compiled programs from here. On ANY failure we
   * regfree everything compiled so far and abort the attach (=> REST 400). */
  for (i = 0; i < n_routes; i++) {
    l7_route_t *r = &copy[i];
    uint8_t ns = r->n_sets;
    if (ns > L7_MAX_SETS_PER_ROUTE)
      ns = r->n_sets = L7_MAX_SETS_PER_ROUTE;
    for (si = 0; si < ns; si++) {
      l7_match_set_t *set = &r->sets[si];
      uint8_t nc = set->n_conds;
      if (nc > L7_MAX_CONDS_PER_SET)
        nc = set->n_conds = L7_MAX_CONDS_PER_SET;
      for (ci = 0; ci < nc; ci++) {
        l7_condition_t *cond = &set->conds[ci];
        /* Never trust an inbound re_valid — recompile authoritatively here. */
        cond->re_valid = 0;
        if (cond->op == L7OP_REGEX) {
          if (regcomp(&cond->re, cond->value, REG_EXTENDED | REG_NOSUB) != 0) {
            /* Bad pattern: roll back the partial compile + abort. */
            log_error("l7policy attach: regcomp FAILED for pattern \"%s\"", cond->value);
            cond->re_valid = 0; /* this one is NOT compiled */
            l7_free_routes(copy, n_routes);
            return -1;
          }
          cond->re_valid = 1;
        }
      }
    }
  }

  /* Sort ascending by position so the evaluate engine's first-match-wins walk is
   * correct (Plan 03 assumes a position-sorted array). */
  qsort(copy, (size_t)n_routes, sizeof(l7_route_t), l7_route_cmp_position);

  /* Install under the lock: find the service, free any prior policy, swap in. */
  PROXY_LOCK();
  node = proxy_struct->head;
  while (node) {
    if (cmp_proxy_ent(&node->key, key)) {
      l7_clear_attached(node);          /* replace any prior policy (regfree) */
      node->l7_routes = copy;           /* POPULATE Plan-04 discriminator field */
      node->n_l7_routes = n_routes;     /* POPULATE Plan-04 discriminator field */
      node->has_l7_policy = 1;          /* POPULATE Plan-04 discriminator field */
      PROXY_UNLOCK();
      return 0;
    }
    node = node->next;
  }
  {
    int _cnt = 0;
    proxy_map_ent_t *_n = proxy_struct->head;
    while (_n) {
      log_error("l7policy attach: have proxy ent xip=0x%08x xport=%u proto=%u",
                (unsigned)_n->key.xip, (unsigned)_n->key.xport, (unsigned)_n->key.protocol);
      _cnt++;
      _n = _n->next;
    }
    log_error("l7policy attach: NO PROXY SERVICE for xip=0x%08x xport=%u proto=%u (%d proxy entries exist)",
              (unsigned)key->xip, (unsigned)key->xport, (unsigned)key->protocol, _cnt);
  }
  PROXY_UNLOCK();

  /* No matching service — free the compiled copy we never installed. */
  l7_free_routes(copy, n_routes);
  return -1;
}

/*
 * proxy_detach_l7_policy — drop the attached L7 policy for `key`, regfree every
 * compiled REGEX program, free the route array, and clear the discriminator fields
 * (mirrors proxy_cleanup_mtls_config). Returns 0 (success / nothing to do).
 */
int proxy_detach_l7_policy(struct proxy_ent *key)
{
  proxy_map_ent_t *node;

  if (!key || !proxy_struct)
    return 0;

  PROXY_LOCK();
  node = proxy_struct->head;
  while (node) {
    if (cmp_proxy_ent(&node->key, key)) {
      l7_clear_attached(node);          /* regfree + free + clear has_l7_policy */
      PROXY_UNLOCK();
      return 0;
    }
    node = node->next;
  }
  PROXY_UNLOCK();
  return 0;
}
