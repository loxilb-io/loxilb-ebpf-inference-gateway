/*
 * Copyright (c) 2026 LoxiLB Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
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
 * The AI gateway admission gate, extracted verbatim from the H1 parser's
 * handle_on_message_complete (see sockproxy_http.c for the call site and
 * the response emission). One gate, N protocol callers — the HTTP/2 hole
 * existed precisely because the gate was inlined in the H1 parser, so a
 * second inlined copy was never an option.
 *
 * Stage order (first refusal wins):
 *   1. credential + model authorization (401/403/503)  — a request with no
 *      usable credential learns nothing else about the service.
 *   2. body/header model conflict (400)                — decided after the
 *      credential so an unauthenticated probe still reads as 401, before
 *      rate/quota so an ill-formed request never consumes budget.
 *      Between 2 and 3, while any class is configured: the class of the
 *      request (403 on a rule with ai_objective_strict when it names an
 *      objective it may not use; otherwise never a refusal).
 *   3. RPS / token-quota latch (429, 503 on store loss)
 *   4. pre-admission token reservation (429)
 */

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <pthread.h>
#include <time.h>
#include <arpa/inet.h>

#include "xxhash.h"
#include "uthash.h"
#include "log.h"
#include "sockproxy_internal.h"
#include "sockproxy_ai_admit.h"
#include "sockproxy_json.h"

/* The header mirrors MAX_MODEL_LEN rather than including the proxy-internal
 * world; hold the mirror to the original. */
_Static_assert(AI_GW_MODEL_LEN == MAX_MODEL_LEN,
               "AI_GW_MODEL_LEN must mirror MAX_MODEL_LEN");

void
ai_gw_svc_ident(uint32_t xip_be, uint16_t xport_be, char *buf, size_t len)
{
  char vip[INET_ADDRSTRLEN] = {0};

  if (!buf || len == 0)
    return;
  buf[0] = '\0';
  if (!inet_ntop(AF_INET, &xip_be, vip, sizeof(vip)))
    return;
  snprintf(buf, len, "%s:%u", vip, (unsigned)ntohs(xport_be));
}

static void
set_deny(ai_gw_admit_result_t *res, ai_gw_admit_stage_t stage, int status,
         int retry_after, int retry_body, const char *code, const char *msg)
{
  res->verdict = AI_GW_ADMIT_DENY;
  res->stage = stage;
  res->http_status = status;
  res->retry_after = retry_after;
  res->retry_body = retry_body;
  snprintf(res->error_code, sizeof(res->error_code), "%s", code);
  snprintf(res->error_msg, sizeof(res->error_msg), "%s", msg);
}

/* Per-thread xorshift64* state for request IDs. Seeded lazily from the
 * clocks, the thread and a process-wide salt, so two workers started in
 * the same nanosecond still diverge. */
static __thread uint64_t mint_state;
static _Atomic uint64_t mint_salt;

static uint64_t
mint_next(void)
{
  if (mint_state == 0) {
    struct timespec mono, wall;
    uint64_t s;
    clock_gettime(CLOCK_MONOTONIC, &mono);
    clock_gettime(CLOCK_REALTIME, &wall);
    s = ((uint64_t)wall.tv_sec << 32) ^ (uint64_t)wall.tv_nsec;
    s ^= ((uint64_t)mono.tv_nsec << 20) ^ (uint64_t)pthread_self();
    s += atomic_fetch_add(&mint_salt, 0x9E3779B97F4A7C15ULL) +
         0x9E3779B97F4A7C15ULL;
    /* splitmix64 finaliser: spreads a poor seed over all 64 bits. */
    s ^= s >> 30; s *= 0xBF58476D1CE4E5B9ULL;
    s ^= s >> 27; s *= 0x94D049BB133111EBULL;
    s ^= s >> 31;
    mint_state = s ? s : 0x123456789ABCDEF0ULL;
  }
  uint64_t x = mint_state;
  x ^= x >> 12;
  x ^= x << 25;
  x ^= x >> 27;
  mint_state = x;
  return x * 0x2545F4914F6CDD1DULL;
}

void
ai_gw_mint_request_id(char *buf, size_t len)
{
  if (!buf || len == 0)
    return;
  uint64_t hi = mint_next();
  uint64_t lo = mint_next();
  /* UUID v4 shape: version nibble in hi, variant bits in lo. */
  hi = (hi & ~((uint64_t)0xF << 12)) | ((uint64_t)0x4 << 12);
  lo = (lo & ~((uint64_t)0x3 << 62)) | ((uint64_t)0x2 << 62);
  snprintf(buf, len, "%016llx%016llx",
           (unsigned long long)hi, (unsigned long long)lo);
}

static int ai_gw_admit_decide(const ai_gw_req_ctx_t *req,
                              ai_gw_admit_result_t *res);

int
ai_gw_admit(const ai_gw_req_ctx_t *req, ai_gw_admit_result_t *res)
{
  int rc = ai_gw_admit_decide(req, res);

  /* Every refusal is reported here, at the verdict, whatever arm produced
   * it: the arms all return through this one frame, so an arm added to the
   * decision cannot refuse a request unrecorded. The record carries the
   * identity the arm resolved (empty when it refused before resolving one)
   * and the correlation the caller supplied. */
  if (res->verdict == AI_GW_ADMIT_DENY) {
    llb_ai_record_deny((char *)(req->request_id ? req->request_id : ""),
                       req->producer_id,
                       (char *)(req->svc_ident ? req->svc_ident : ""),
                       res->effective_model, res->tenant_id, res->key_id,
                       res->user_id, (int)res->stage, res->http_status,
                       res->error_code,
                       (char *)(req->client_ip ? req->client_ip : ""),
                       (char *)(req->origin_ip ? req->origin_ip : ""),
                       req->trusted_hops, (int)res->auth_src,
                       res->net_identity, res->priority,
                       AI_GW_CLASS_INFO(res->class_ran, res->priority_class,
                                        res->objective_denied,
                                        res->hint_not_applied),
                       res->objective);
  }
  return rc;
}

void
ai_gw_record_local_deny(int stage, const char *request_id, int producer_id,
                        const char *svc_ident, const char *model,
                        const char *tenant_id, const char *key_id,
                        const char *user_id, int http_status,
                        const char *error_code,
                        const char *client_ip, const char *origin_ip,
                        int trusted_hops, int auth_src,
                        const char *net_identity,
                        int priority, int class_info,
                        const char *objective)
{
  /* The same attribution every other record carries, with the same
   * meaning: client_ip is the socket peer, origin_ip is "" unless the header
   * splice derived one before this refusal, and trusted_hops pairs with it. */
  llb_ai_record_deny((char *)(request_id ? request_id : ""), producer_id,
                     (char *)(svc_ident ? svc_ident : ""),
                     (char *)(model ? model : ""),
                     (char *)(tenant_id ? tenant_id : ""),
                     (char *)(key_id ? key_id : ""),
                     (char *)(user_id ? user_id : ""),
                     stage, http_status,
                     (char *)(error_code ? error_code : ""),
                     (char *)(client_ip ? client_ip : ""),
                     (char *)(origin_ip ? origin_ip : ""),
                     trusted_hops, auth_src,
                     (char *)(net_identity ? net_identity : ""),
                     priority, class_info,
                     (char *)(objective ? objective : ""));
}

void
ai_gw_record_capacity_deny(const char *request_id, int producer_id,
                           const char *svc_ident, const char *model,
                           const char *tenant_id, const char *key_id,
                           const char *user_id, int http_status,
                           const char *error_code,
                           const char *client_ip, const char *origin_ip,
                           int trusted_hops, int auth_src,
                           const char *net_identity,
                           int priority, int class_info,
                           const char *objective)
{
  ai_gw_record_local_deny((int)AI_GW_STAGE_CAPACITY, request_id, producer_id,
                          svc_ident, model, tenant_id, key_id, user_id,
                          http_status, error_code, client_ip, origin_ip,
                          trusted_hops, auth_src, net_identity, priority,
                          class_info, objective);
}

/* ---- services with a network-identity binding ---------------------------
 *
 * Two open-addressing tables of service-identity hashes and one state word.
 * The control plane fills the table requests are not reading and then swaps
 * the state word, which names the table, the mode and a generation. A
 * request probes the table its state word names, at a load of a quarter or
 * less, and reads the word again: a different word means a replacement ran
 * underneath, and it reads once more from the new one. It never waits for a
 * writer. A slot holds a hash with its three low bits replaced: bit 0 marks
 * the slot taken, bit 1 is the service's fail-closed flag, bit 2 its
 * forward-identity flag. Two services whose hashes agree above those bits
 * share a slot and its flags; that costs one of them a resolver call it did
 * not need, or a client-sent X-Auth-* header it would have passed on, and
 * admits nothing. */

enum { NETID_NONE = 0, NETID_LISTED = 1, NETID_ALL = 2 };

#define NETID_TBL_SLOTS  (AI_GW_NETID_SVC_MAX * 4)   /* a power of two */
#define NETID_TBL_MASK   (NETID_TBL_SLOTS - 1)
_Static_assert((NETID_TBL_SLOTS & NETID_TBL_MASK) == 0, "table size");

#define NETID_ST_MODE        0x3u    /* NETID_* */
#define NETID_ST_ALL_CLOSED  0x4u    /* every service fails closed */
#define NETID_ST_ANY_CLOSED  0x8u    /* some slot carries the flag */
#define NETID_ST_ALL_FWD     0x10u   /* every service forwards identity */
#define NETID_ST_ANY_FWD     0x20u   /* some slot carries the flag */
#define NETID_ST_TBL         0x40u   /* which table is published */
#define NETID_ST_GEN         0x80u   /* generation, one step */

#define NETID_SLOT_USED      0x1ull
#define NETID_SLOT_CLOSED    0x2ull
#define NETID_SLOT_FWD       0x4ull
#define NETID_SLOT_FLAGS     (NETID_SLOT_CLOSED | NETID_SLOT_FWD)
#define NETID_SLOT_LOW       (NETID_SLOT_USED | NETID_SLOT_FLAGS)
_Static_assert(NETID_SLOT_CLOSED == AI_GW_NETID_FAIL_CLOSED &&
               NETID_SLOT_FWD == AI_GW_NETID_FWD, "slot flags are the API's");

static _Atomic uint32_t netid_state;     /* NETID_NONE is the one load a
                                          * request pays with no binding */
static _Atomic uint64_t netid_tbl[2][NETID_TBL_SLOTS];
static _Atomic int netid_ifmatch;        /* a binding matches on an interface */
static pthread_mutex_t netid_wlock = PTHREAD_MUTEX_INITIALIZER;

static uint64_t
netid_hash(const char *s)
{
  uint64_t h = 0xcbf29ce484222325ULL;   /* FNV-1a */
  for (; *s; s++) {
    h ^= (uint8_t)*s;
    h *= 0x100000001b3ULL;
  }
  return h;
}

static inline uint32_t
netid_slot0(uint64_t h)
{
  return (uint32_t)((h >> 3) ^ (h >> 33)) & NETID_TBL_MASK;
}

void
ai_gw_netid_bound_set(const char *const *svc_idents, const uint8_t *flags,
                      int n, int all)
{
  uint32_t cnt = 0;
  uint32_t st, next;
  _Atomic uint64_t *tbl;

  pthread_mutex_lock(&netid_wlock);
  st = atomic_load(&netid_state);
  next = (st & NETID_ST_TBL) ^ NETID_ST_TBL;
  tbl = netid_tbl[next ? 1 : 0];

  for (uint32_t i = 0; i < NETID_TBL_SLOTS; i++)
    atomic_store_explicit(&tbl[i], 0, memory_order_relaxed);

  for (int i = 0; svc_idents && i < n; i++) {
    if (!svc_idents[i] || !svc_idents[i][0])
      continue;
    uint64_t fl = flags ? (flags[i] & NETID_SLOT_FLAGS) : 0;
    uint64_t want = (netid_hash(svc_idents[i]) & ~NETID_SLOT_LOW) |
                    NETID_SLOT_USED;
    uint32_t at = netid_slot0(want);
    uint64_t v;

    while ((v = atomic_load_explicit(&tbl[at], memory_order_relaxed)) != 0 &&
           (v & ~NETID_SLOT_FLAGS) != want)
      at = (at + 1) & NETID_TBL_MASK;
    if (v == 0) {
      if (cnt == AI_GW_NETID_SVC_MAX) {
        /* More than the set holds: never miss one, never run one that
         * asked to fail closed as if it had not, and never pass a
         * client-sent identity header on to one that forwards its own. */
        all |= AI_GW_NETID_BOUND | (int)fl;
        continue;
      }
      cnt++;
      v = want;
    }
    v |= fl;
    if (fl & NETID_SLOT_CLOSED)
      next |= NETID_ST_ANY_CLOSED;
    if (fl & NETID_SLOT_FWD)
      next |= NETID_ST_ANY_FWD;
    atomic_store_explicit(&tbl[at], v, memory_order_relaxed);
  }

  if (all & AI_GW_NETID_BOUND) {
    next |= NETID_ALL;
    if (all & AI_GW_NETID_FAIL_CLOSED)
      next |= NETID_ST_ALL_CLOSED;
    if (all & AI_GW_NETID_FWD)
      next |= NETID_ST_ALL_FWD;
  } else if (cnt) {
    next |= NETID_LISTED;
  }
  next |= (st & ~(NETID_ST_GEN - 1)) + NETID_ST_GEN;
  atomic_store(&netid_state, next);
  pthread_mutex_unlock(&netid_wlock);
}

int
ai_gw_netid_bound(const char *svc_ident)
{
  uint32_t st = atomic_load_explicit(&netid_state, memory_order_relaxed);

  if ((st & NETID_ST_MODE) == NETID_NONE || !svc_ident || !svc_ident[0])
    return 0;

  uint64_t want = (netid_hash(svc_ident) & ~NETID_SLOT_LOW) | NETID_SLOT_USED;
  for (;;) {
    uint32_t mode = st & NETID_ST_MODE;
    int ret = 0;

    if (mode == NETID_NONE)
      return 0;
    if (mode == NETID_ALL) {
      ret = AI_GW_NETID_BOUND;
      if (st & NETID_ST_ALL_CLOSED)
        ret |= AI_GW_NETID_FAIL_CLOSED;
      if (st & NETID_ST_ALL_FWD)
        ret |= AI_GW_NETID_FWD;
      /* A slot can only add a flag the whole set does not carry. */
      if ((!(st & NETID_ST_ANY_CLOSED) || (ret & AI_GW_NETID_FAIL_CLOSED)) &&
          (!(st & NETID_ST_ANY_FWD) || (ret & AI_GW_NETID_FWD)))
        return ret;
    }

    const _Atomic uint64_t *tbl = netid_tbl[(st & NETID_ST_TBL) ? 1 : 0];
    uint32_t at = netid_slot0(want);
    /* The table is never more than a quarter full, so a probe ends on an
     * empty slot; the bound only holds a read of a table that is being
     * refilled underneath, which the check below discards. */
    for (uint32_t i = 0; i < NETID_TBL_SLOTS; i++) {
      uint64_t v = atomic_load_explicit(&tbl[at], memory_order_relaxed);
      if (v == 0)
        break;
      if ((v & ~NETID_SLOT_FLAGS) == want) {
        ret |= AI_GW_NETID_BOUND | (int)(v & NETID_SLOT_FLAGS);
        break;
      }
      at = (at + 1) & NETID_TBL_MASK;
    }

    uint32_t now = atomic_load(&netid_state);
    if (now == st)
      return ret;
    st = now;             /* replaced underneath: read the new one */
  }
}

int
ai_gw_netid_fwd_any(void)
{
  return (atomic_load_explicit(&netid_state, memory_order_relaxed) &
          (NETID_ST_ALL_FWD | NETID_ST_ANY_FWD)) != 0;
}

static _Atomic int class_on_state;

void
ai_gw_class_on_set(int on)
{
  atomic_store_explicit(&class_on_state, on ? 1 : 0, memory_order_relaxed);
}

int
ai_gw_class_on(void)
{
  return atomic_load_explicit(&class_on_state, memory_order_relaxed);
}

void
ai_gw_netid_ifmatch_set(int on)
{
  atomic_store(&netid_ifmatch, on ? 1 : 0);
}

int
ai_gw_netid_ifmatch(void)
{
  return atomic_load_explicit(&netid_ifmatch, memory_order_relaxed);
}

/* The keyless decision of a non-enforcing service: the opt-in per-VIP shared
 * bucket, then UNMETERED. */
static int
admit_keyless(ai_gw_admit_result_t *res, const char *svc_ident)
{
  /* The one ladder arm keyless traffic has: the opt-in per-VIP shared
   * bucket. A fully-empty identity makes this the keyless probe on the
   * Go side — no bucket configured (or defaults unknowable) admits, so
   * services that never opted in keep their exact legacy behaviour. */
  if (svc_ident[0]) {
    ai_gw_decision_t vs_dec = {0};
    if (llb_ai_ratelimit_check("", "", "", (char *)svc_ident, "",
                               &vs_dec) != 0) {
      set_deny(res, AI_GW_STAGE_RATELIMIT,
               vs_dec.decision == 4 ? 503 : 429,
               vs_dec.retry_after, 1,
               vs_dec.error_code[0] ? vs_dec.error_code
                                    : "rate_limit_exceeded", "");
      return -1;
    }
  }
  res->verdict = AI_GW_ADMIT_UNMETERED;
  return 0;
}

/* Ask the resolver for the binding of this request's source. Returns 1 with
 * *nid filled when one matches, 0 when none does, and -1 when the resolver
 * could not answer, which includes a match that names no tenant. Nothing but
 * a clean match ever admits anything. */
static int
netid_lookup(const ai_gw_req_ctx_t *req, const char *svc_ident,
             const char *model, ai_gw_netid_t *nid)
{
  memset(nid, 0, sizeof(*nid));
  if (llb_ai_netid_resolve((char *)(req->client_ip ? req->client_ip : ""),
                           req->in_ifindex, (char *)svc_ident,
                           (char *)model, nid) != 0) {
    memset(nid, 0, sizeof(*nid));
    return -1;
  }
  if (!nid->matched) {
    memset(nid, 0, sizeof(*nid));
    return 0;
  }
  nid->tenant_id[sizeof(nid->tenant_id) - 1] = '\0';
  nid->binding[sizeof(nid->binding) - 1] = '\0';
  if (nid->tenant_id[0] == '\0') {
    memset(nid, 0, sizeof(*nid));
    return -1;
  }
  return 1;
}

/* The gate's question: 1 a binding matches, 0 none does, -1 the request is
 * refused (res is set). A resolver that cannot answer is "no binding" - it
 * never admits by network and never refuses a valid credential - unless the
 * service asked to fail closed, where every request the resolver would have
 * decided is refused until it answers again. */
static int
netid_ask(const ai_gw_req_ctx_t *req, ai_gw_admit_result_t *res,
          const char *svc_ident, const char *model, ai_gw_netid_t *nid)
{
  int rc = netid_lookup(req, svc_ident, model, nid);

  if (rc >= 0)
    return rc;
  if (!(req->netid_bound & AI_GW_NETID_FAIL_CLOSED))
    return 0;
  set_deny(res, AI_GW_STAGE_AUTH, 503, 5, 0, "netid_unavailable",
           "Network identity cannot be resolved; request refused");
  return -1;
}

/* The identity a request is metered as, however it was decided. */
typedef struct {
  const char *tenant_id;
  const char *key_id;
  const char *user_id;
  int         auth_flags;
  /* Network path only: the binding refuses this model. Checked after the
   * conflict rule, where a credential's own allowlist was checked by its
   * validator before it. */
  int         net_model_refused;
} admit_ident_t;

/* The class stage: what the request asks for, held under what its identity
 * allows. Runs once the tenant is known and before anything is charged, so
 * a refusal here spends nothing. A resolver that cannot answer leaves the
 * request standard: a class is a preference between admitted requests,
 * never a condition of admission. Returns -1 when it refused. */
static int
admit_class(const ai_gw_req_ctx_t *req, ai_gw_admit_result_t *res,
            const char *svc_ident, const admit_ident_t *id, const char *model)
{
  const char *hint = req->objective_hint ? req->objective_hint : "";
  const char *profile = (res->auth_src == AI_GW_AUTH_SRC_BEARER && req->jwt_profile)
                        ? req->jwt_profile : "";
  ai_gw_class_t cls;
  size_t off = 0, vlen = 0;
  int tier = AI_TIER_NONE;

  res->class_ran = 1;
  /* The body's hint is read only from a body that is whole in the buffer,
   * the condition the model is read under. */
  if (req->body && req->body_len > 0 && !req->prefix_only)
    tier = extract_service_tier(req->body, req->body_len, &off, &vlen);
  else if (!hint[0])
    res->hint_not_applied = 1;

  memset(&cls, 0, sizeof(cls));
  if (llb_ai_class_resolve((char *)id->tenant_id, (char *)id->key_id,
                           (char *)res->net_identity, (char *)profile,
                           (char *)svc_ident, (char *)hint, tier, &cls) != 0)
    memset(&cls, 0, sizeof(cls));
  cls.objective[sizeof(cls.objective) - 1] = '\0';

  res->priority = cls.priority;
  res->priority_class = cls.priority_class <= AI_GW_CLASS_SHEDDABLE
                        ? cls.priority_class : AI_GW_CLASS_STANDARD;
  res->objective_denied = cls.objective_denied ? 1 : 0;
  snprintf(res->objective, sizeof(res->objective), "%s", cls.objective);

  if (res->objective_denied &&
      (req->objective_strict_of
         ? req->objective_strict_of(req->default_tokens_arg, model)
         : req->objective_strict)) {
    set_deny(res, AI_GW_STAGE_OBJECTIVE, 403, 0, 0, "objective_not_allowed",
             "Objective not permitted for this identity");
    return -1;
  }
  /* The gateway read the tier, so the backend does not get to read it
   * again: the caller nulls the value, whichever hint decided. */
  if (tier != AI_TIER_NONE) {
    res->tier_consumed = 1;
    res->tier_off = (uint32_t)off;
    res->tier_len = (uint32_t)vlen;
  }
  return 0;
}

/* Stages 2 to 4 for an identity that is already decided: the conflict
 * rule, rate and quota, the reservation. One body for every way a tenant
 * is decided, so a network tenant is held to exactly what a credential's
 * tenant is. */
static int
admit_metered(const ai_gw_req_ctx_t *req, ai_gw_admit_result_t *res,
              const char *svc_ident, const char *model,
              const char *body_bound, const char *hdr_model,
              const admit_ident_t *id)
{
  /* Stage 2: on enforcing services a body/header model disagreement is a
   * hard 400, never a silent steer. Before this check existed the auth
   * stage bound allowed_models to the body model while endpoint selection
   * derived its own model header-first — so a key authorized only for
   * model A could reach model B's pool by naming A in the body and B in
   * X-Model. Both present and equal is fine; either alone is fine. */
  if (body_bound[0] && hdr_model[0] && strcmp(body_bound, hdr_model) != 0) {
    set_deny(res, AI_GW_STAGE_CONFLICT, 400, 0, 0, "model_conflict",
             "JSON body model and X-Model header disagree");
    /* The identity is real (the credential validated) — carry it so the
     * caller can log and count the denial against the right tenant. */
    snprintf(res->tenant_id, sizeof(res->tenant_id), "%s", id->tenant_id);
    snprintf(res->key_id, sizeof(res->key_id), "%s", id->key_id);
    return -1;
  }

  if (id->net_model_refused) {
    set_deny(res, AI_GW_STAGE_AUTH, 403, 0, 0, "model_not_allowed",
             "Model not permitted for this network identity");
    snprintf(res->tenant_id, sizeof(res->tenant_id), "%s", id->tenant_id);
    return -1;
  }

  snprintf(res->tenant_id, sizeof(res->tenant_id), "%s", id->tenant_id);
  snprintf(res->key_id, sizeof(res->key_id), "%s", id->key_id);
  snprintf(res->user_id, sizeof(res->user_id), "%s", id->user_id);
  res->auth_flags = id->auth_flags;
  snprintf(res->effective_model, sizeof(res->effective_model), "%s", model);

  /* The class, for a request that has a tenant, while any class is
   * configured. Before the rate limit: a request refused for the objective
   * it named is not counted against its tenant's rate. */
  if (req->class_on && id->tenant_id[0] &&
      admit_class(req, res, svc_ident, id, model) != 0)
    return -1;

  /* Stage 3: per-key then per-tenant RPS check → 429. The body-bound model
   * rides along so the token-quota stage can consult the tenant|model
   * bucket next to the tenant aggregate. Three shapes arrive on the deny
   * path: the request-rate limit, the token-quota debt latch, and (as
   * decision 4) the stage's own keyed-identity-with-no-store invariant
   * guard — the last is the gateway's outage and carries 503, never a 429
   * that reads as "slow down". */
  ai_gw_decision_t rl_dec = {0};
  int rl_rc = llb_ai_ratelimit_check((char *)id->key_id, (char *)id->tenant_id,
                                     (char *)id->user_id, (char *)svc_ident,
                                     (char *)model, &rl_dec);
  if (rl_rc != 0) {
    const char *rl_err =
      rl_dec.error_code[0] ? rl_dec.error_code : "rate_limit_exceeded";
    set_deny(res, AI_GW_STAGE_RATELIMIT,
             rl_dec.decision == 4 ? 503 : 429,
             rl_dec.retry_after, 1, rl_err, "");
    return -1;
  }

  /* Stage 4: pre-admission token reservation → 429 BEFORE dispatch. Claim
   * the request's worst case (prompt estimate + declared max_tokens
   * ceiling, or the rule's default when none is declared) against the
   * tenant quota now, while denial costs one cheap
   * response — not a backend prefill whose tokens the latch only bills
   * afterwards. The claim and its window tag ride back to the caller for
   * the settle call. */
  if ((req->body && req->body_len > 0) ||
      (req->prefix_only && req->declared_content_length > 0)) {
    int resv_prompt = 0;
    int resv_max = 0;
    if (req->body && req->body_len > 0) {
      resv_prompt = estimate_prompt_tokens(req->body, req->body_len);
      resv_max = extract_max_tokens(req->body, req->body_len);
    }
    /* A prefix shows at most the first bytes of the messages array; the
     * declared length is the whole of it. Size the claim from the larger of
     * the two so a streamed long-context request reserves what its bytes
     * imply, exactly as its buffered sibling would. */
    if (req->prefix_only && req->declared_content_length > 0) {
      size_t from_bytes = req->declared_content_length / 4;
      if (from_bytes > 100000000UL)
        from_bytes = 100000000UL;
      if ((int)from_bytes > resv_prompt)
        resv_prompt = (int)from_bytes;
    }
    /* No declared ceiling: the rule's default stands in for it, as a claim
     * the quota may shrink but never refuses on. The prompt estimate (and a
     * declared ceiling) stay the firm part, refused when they do not fit. */
    int resv_default = 0;
    if (resv_max <= 0) {
      int dflt = req->default_tokens_of
                   ? req->default_tokens_of(req->default_tokens_arg, model)
                   : req->default_tokens;
      if (dflt > 0)
        resv_default = dflt;
    }
    if (resv_prompt > 0 || resv_max > 0 || resv_default > 0) {
      ai_gw_decision_t rs_dec = {0};
      int64_t rs_epoch = 0;
      int rs_granted = 0;
      if (llb_ai_token_quota_reserve((char *)id->tenant_id, (char *)model,
                                     (char *)id->user_id, (char *)id->key_id,
                                     (char *)svc_ident,
                                     resv_prompt, resv_max, resv_default,
                                     &rs_epoch, &rs_granted, &rs_dec) != 0) {
        set_deny(res, AI_GW_STAGE_RESERVE, 429, rs_dec.retry_after, 1,
                 rs_dec.error_code, "");
        /* Log parity: the inlined gate reported what it asked for. The
         * default is left out: it is never what was refused. */
        res->reserved_toks = (uint32_t)(resv_prompt + resv_max);
        return -1;
      }
      if (rs_epoch != 0) {
        /* Settlement gives back exactly what is stored here, so it is the
         * granted total and not the asked one. */
        if (rs_granted < 0)
          rs_granted = 0;
        res->reserved_toks = (uint32_t)rs_granted;
        res->res_epoch = rs_epoch;
        if (resv_default > 0 &&
            rs_granted < resv_prompt + resv_max + resv_default)
          res->reservation_clamped = 1;
      }
    }
  }

  res->verdict = AI_GW_ADMIT_ALLOW;
  return 0;
}

/* The network path: the binding's tenant, with no key and no user, through
 * the same stages a credential's tenant goes through. */
static int
admit_network(const ai_gw_req_ctx_t *req, ai_gw_admit_result_t *res,
              const char *svc_ident, const char *model,
              const char *body_bound, const char *hdr_model,
              const ai_gw_netid_t *nid)
{
  admit_ident_t id = {
    .tenant_id = nid->tenant_id,
    .key_id = "",
    .user_id = "",
    .net_model_refused = !nid->model_ok,
  };

  res->auth_src = AI_GW_AUTH_SRC_NETWORK;
  res->net_forward_identity = nid->forward_identity ? 1 : 0;
  snprintf(res->net_identity, sizeof(res->net_identity), "%s", nid->binding);
  return admit_metered(req, res, svc_ident, model, body_bound, hdr_model, &id);
}

static int
ai_gw_admit_decide(const ai_gw_req_ctx_t *req, ai_gw_admit_result_t *res)
{
  memset(res, 0, sizeof(*res));

  const char *api_key = req->api_key ? req->api_key : "";
  const char *prefix_model = req->prefix_model ? req->prefix_model : "";
  const char *hdr_model = req->hdr_model ? req->hdr_model : "";

  const char *svc_ident = req->svc_ident ? req->svc_ident : "";

  /* Skip enforcement only for the two DECLARED non-enforcing values.
   * 1 enforces, and so does anything out of range: a wire value this code
   * does not recognise is a corrupted policy, and a corrupted policy that
   * admits keyless traffic fails open on exactly the services an operator
   * tried to protect. */
  int enforcing = !(req->auth_mode == 0 || req->auth_mode == 2);

  /* A binding is looked for only on a service that has one, and a service
   * is known by its identity. */
  int netid = (req->netid_bound & AI_GW_NETID_BOUND) && svc_ident[0];

  if (!enforcing && !netid && !req->parsed_body_model)
    return admit_keyless(res, svc_ident);

  /* One allocation-free model result is shared by policy and routing. */
  char body_model[AI_GW_MODEL_LEN] = {0};
  int model_rc = 0;
  if (req->parsed_body_model) {
    snprintf(body_model, sizeof(body_model), "%s", req->parsed_body_model);
    model_rc = req->model_parse_result;
  } else if (req->body && req->body_len && !req->prefix_only) {
    model_rc = extract_model_field(req->body, req->body_len, body_model, sizeof(body_model));
  }
  if (model_rc == SP_JSON_DUPLICATE_MODEL || model_rc == SP_JSON_DUPLICATE_USER) {
    set_deny(res, AI_GW_STAGE_FRAMING, 400, 0, 0,
             model_rc == SP_JSON_DUPLICATE_USER ? "duplicate_user_field" : "duplicate_model_field",
             "more than one decoded top-level routing key");
    return -1;
  }
  if (!enforcing && !netid)
    return admit_keyless(res, svc_ident);

  const char *body_bound = body_model[0] ? body_model : prefix_model;
  const char *model = body_bound[0] ? body_bound : hdr_model;

  ai_gw_netid_t nid;
  int nid_asked = 0;
  int nid_match = 0;

  if (!enforcing) {
    /* Rows 1 and 2. A source with a binding is that binding's tenant; any
     * other source is the keyless traffic it was before the service had
     * bindings, decided by the same code with the same result. */
    nid_match = netid_ask(req, res, svc_ident, model, &nid);
    if (nid_match < 0)
      return -1;
    if (nid_match) {
      snprintf(res->effective_model, sizeof(res->effective_model), "%s", model);
      return admit_network(req, res, svc_ident, model, body_bound, hdr_model,
                           &nid);
    }
    return admit_keyless(res, svc_ident);
  }

  /* Resolved before any arm can refuse, so a refusal names the model the
   * request asked for; the ALLOW path writes the same value again below. */
  snprintf(res->effective_model, sizeof(res->effective_model), "%s", model);

  /* Stage 1: validate the credential → 401 (missing/invalid), 403 (model
   * denied), 503 (store cannot answer). The store outage is deliberately
   * NOT a 401: a client that retries a 503 is behaving correctly; a client
   * that retries a 401 is replaying a credential that will never work.
   *
   * Arm dispatch: mode 1 is the API-key arm and mode 3 the JWT arm.
   * Mode 4 (apikey-or-jwt) picks by which credential is PRESENT, API key
   * winning: a present X-Api-Key decides alone and its refusal is final —
   * falling back to the JWT arm after a failed key would let a caller
   * probe one credential per request behind a single 401. With no key the
   * Bearer arm decides (its missing-token 401 covers the neither-present
   * case). Unknown wire values keep the old fail-closed posture and
   * enforce the API-key arm — a JWT-only client is denied there, never
   * admitted unchecked. Identities are never merged across arms. */
  const char *bearer = req->bearer ? req->bearer : "";
  const char *jwt_profile = req->jwt_profile ? req->jwt_profile : "";

  /* The capture hands over the RAW Authorization value, reassembled from
   * however many fragments the parser delivered it in. Only the Bearer
   * scheme feeds the JWT arm — Basic belongs to the session-affinity
   * extractor — and the tag is stripped HERE, after reassembly, so a
   * fragment boundary inside the header can never split the prefix this
   * dispatch keys on. RFC 7235 allows more than one SP before the token.
   * A non-Bearer value reads as "no bearer credential": on the JWT arm
   * that is the missing-token 401. */
  if (!strncasecmp(bearer, "Bearer ", 7)) {
    bearer += 7;
    while (*bearer == ' ')
      bearer++;
  } else {
    bearer = "";
  }

  /* Row 6: no credential at all, from a source whose binding stands in for
   * one. "No credential" is neither a key nor a bearer token, whichever arm
   * the service declares, and a token dropped for its size was presented:
   * a request that presents a credential is decided by that credential,
   * and a refused one never falls back to where it came from. Anything
   * short of a credential-bearing binding goes to the credential arm,
   * which answers the missing credential as it always has (row 7). */
  if (netid && api_key[0] == '\0' && bearer[0] == '\0' &&
      !req->bearer_oversize) {
    nid_asked = 1;
    nid_match = netid_ask(req, res, svc_ident, model, &nid);
    if (nid_match < 0)
      return -1;
    if (nid_match && nid.credential_network)
      return admit_network(req, res, svc_ident, model, body_bound, hdr_model,
                           &nid);
  }

  int jwt_arm = (req->auth_mode == 3) ||
                (req->auth_mode == 4 && api_key[0] == '\0');

  ai_gw_decision_t key_dec = {0};
  int ai_rc;
  if (jwt_arm) {
    int bearer_flags = req->bearer_oversize ? AI_GW_BEARERF_OVERSIZE : 0;
    ai_rc = llb_ai_validate_bearer((char *)bearer, (char *)model,
                                   (char *)jwt_profile, bearer_flags,
                                   &key_dec);
  } else {
    ai_rc = llb_ai_validate_key((char *)api_key, (char *)model, &key_dec);
  }
  if (ai_rc != 0) {
    /* The Go arm names its refusal (invalid_token/token_expired/…); fall
     * back to the arm-appropriate legacy code when it did not. */
    const char *deny_code = key_dec.error_code[0] ? key_dec.error_code
                          : (jwt_arm ? "invalid_token" : "invalid_api_key");
    if (key_dec.decision == 4) {
      set_deny(res, AI_GW_STAGE_AUTH, 503, 5, 0,
               key_dec.error_code[0] ? key_dec.error_code
                                     : "policy_store_unavailable",
               "Credential policy store is unavailable; request refused");
    } else if (key_dec.decision == 2) {
      set_deny(res, AI_GW_STAGE_AUTH, 403, 0, 0, "model_not_allowed",
               jwt_arm ? "Model not permitted for this token"
                       : "Model not permitted for this API key");
      /* The credential validated and named its tenant; only the model was
       * refused. Carry the identity so the refusal is attributable, as the
       * CONFLICT arm below already does. */
      if (jwt_arm)
        res->auth_src = AI_GW_AUTH_SRC_BEARER;
      snprintf(res->tenant_id, sizeof(res->tenant_id), "%s", key_dec.tenant_id);
      snprintf(res->key_id, sizeof(res->key_id), "%s", key_dec.key_id);
      snprintf(res->user_id, sizeof(res->user_id), "%s", key_dec.user_id);
    } else {
      set_deny(res, AI_GW_STAGE_AUTH, 401, 0, 0, deny_code,
               jwt_arm ? "Missing or invalid bearer token"
                       : "Missing or invalid X-Api-Key header");
    }
    return -1;
  }
  /* A token validated: every record of this request, a later refusal's
   * included, says a bearer token decided its tenant. */
  if (jwt_arm)
    res->auth_src = AI_GW_AUTH_SRC_BEARER;

  /* Rows 4 and 5: the credential validated, and the source has a binding.
   * An advisory binding is noted and changes nothing. A strict one holds
   * the credential to the network it came from: its tenant must be the
   * binding's, and the model must pass the binding's allowlist as well as
   * the credential's own, which its validator has just checked. */
  if (netid) {
    if (!nid_asked)
      nid_match = netid_ask(req, res, svc_ident, model, &nid);
    if (nid_match < 0) {
      /* The credential validated and named its tenant: the refusal is
       * attributable to it, as the mismatch below is. */
      snprintf(res->tenant_id, sizeof(res->tenant_id), "%s", key_dec.tenant_id);
      snprintf(res->key_id, sizeof(res->key_id), "%s", key_dec.key_id);
      snprintf(res->user_id, sizeof(res->user_id), "%s", key_dec.user_id);
      return -1;
    }
    if (nid_match) {
      snprintf(res->net_identity, sizeof(res->net_identity), "%s", nid.binding);
      res->net_forward_identity = nid.forward_identity ? 1 : 0;
      if (nid.enforce) {
        int mismatch = strcmp(nid.tenant_id, key_dec.tenant_id) != 0;
        if (mismatch || !nid.model_ok) {
          if (mismatch)
            set_deny(res, AI_GW_STAGE_AUTH, 403, 0, 0,
                     "network_tenant_mismatch",
                     "Credential is not valid from this network");
          else
            set_deny(res, AI_GW_STAGE_AUTH, 403, 0, 0, "model_not_allowed",
                     "Model not permitted for this network identity");
          snprintf(res->tenant_id, sizeof(res->tenant_id), "%s",
                   key_dec.tenant_id);
          snprintf(res->key_id, sizeof(res->key_id), "%s", key_dec.key_id);
          snprintf(res->user_id, sizeof(res->user_id), "%s", key_dec.user_id);
          return -1;
        }
      }
    }
  }

  admit_ident_t id = {
    .tenant_id = key_dec.tenant_id,
    .key_id = key_dec.key_id,
    .user_id = key_dec.user_id,
    .auth_flags = key_dec.auth_flags,
  };
  return admit_metered(req, res, svc_ident, model, body_bound, hdr_model, &id);
}
