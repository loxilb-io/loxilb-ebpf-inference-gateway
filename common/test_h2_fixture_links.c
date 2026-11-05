/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_h2_fixture_links.c - the rest of the gateway, for the HTTP/2 fixture
 * (test_h2_fixture.c, which fakes the functions the forward path needs to
 * reach a backend).
 *
 * proxy_h2_forward_to_backend links most of the gateway. The functions the
 * fixture's tests pass through get a stub that does nothing and answers 0
 * (no identity, no binding, nothing to record: the tests do not depend on
 * them). Every other one has not been reached by any test and aborts with
 * its name, so a test that starts to reach one fails loudly instead of
 * running on a guess. Apart from the standalone scanner types, these are
 * header-free link stand-ins, called through the product's own prototypes;
 * the ones that do
 * run return int, void or a pointer, where 0 in the return register is the
 * same answer for each.
 */
#include <string.h>
#include "sockproxy_json_scan.h"

int puts(const char *s);
void abort(void);

#define REACHED(name) long name(void) { return 0; }
#define NOT_REACHED(name) \
  long name(void) { puts("test_h2_fixture_links: " #name " reached"); abort(); return 0; }

/* Every stream initializes fixed scanner storage, including non-JSON
 * streams. These fixtures declare no JSON media type: reaching JSON body
 * inspection would change the lifetime test's setup and must fail loudly. */
void
sp_json_scan_init(sp_json_scan_t *scan)
{
  memset(scan, 0, sizeof(*scan));
}

int
sp_json_scan_feed(sp_json_scan_t *scan, const char *data, size_t len)
{
  (void)scan; (void)data; (void)len;
  puts("test_h2_fixture_links: sp_json_scan_feed reached");
  abort();
}

int
sp_json_scan_finish(sp_json_scan_t *scan)
{
  (void)scan;
  puts("test_h2_fixture_links: sp_json_scan_finish reached");
  abort();
}

/* The header guard: every header value of the test requests is valid. */
int l7_hdr_value_valid(const char *value) { (void)value; return 1; }

/* The response record of one stream (sockproxy_http.c resp_note_write_
 * through proxy_h2_note_stream_response): kept here for the tests to read —
 * how many notes, the last status, and whether the last one sampled TTFB
 * (1 for a backend reply, 0 for an answer the gateway wrote). */
int h2fx_notes, h2fx_note_status, h2fx_note_ttfb;
int
proxy_h2_note_stream_response(void *stream, unsigned short status, int sample_ttfb)
{
  (void)stream;
  h2fx_notes++;
  h2fx_note_status = status;
  h2fx_note_ttfb = sample_ttfb;
  return 1;
}

/* The lookup host: the authority without its port, as the product does. */
void
strip_port_from_hostname(const char *in, char *out, unsigned long size)
{
  unsigned long i = 0;

  if (!size)
    return;
  for (; in && in[i] && in[i] != ':' && i + 1 < size; i++)
    out[i] = in[i];
  out[i] = 0;
}

int h2fx_class_on;
int ai_gw_class_on(void) { return h2fx_class_on; }
REACHED(ai_gw_mint_request_id)
REACHED(ai_gw_netid_bound)
REACHED(ai_gw_netid_fwd_any)
REACHED(ai_gw_netid_ifmatch)
REACHED(ai_gw_record_capacity_deny)
NOT_REACHED(ai_gw_record_local_deny)
REACHED(ai_gw_svc_ident)
NOT_REACHED(ai_security_copy_api_key)
NOT_REACHED(ai_security_h2_upstream_hygiene)
NOT_REACHED(chwbl_dec_runtime)
NOT_REACHED(chwbl_inc_runtime)
NOT_REACHED(circuit_breaker_candidate)
NOT_REACHED(compute_prefix_hash)
NOT_REACHED(extract_llm_prefix)
NOT_REACHED(extract_llm_prefix_scanned)
REACHED(extract_model_field)
NOT_REACHED(get_conversation_mapping)
REACHED(get_timestamp_ns)
NOT_REACHED(is_endpoint_healthy)
NOT_REACHED(json_null_top_key)
/* QA-01: where the class stage ran, the H2 submit renames a top-level
 * priority (0 = no such key, which is what the fixture's bodies have) and,
 * only when a request carries x-vllm-priority, rebuilds the header set
 * without it; the fixture's requests carry none. */
REACHED(json_rename_top_key)
NOT_REACHED(ai_security_h2_drop_native_priority)
NOT_REACHED(l7_apply_req_filters)
NOT_REACHED(l7_cookie_node_match)
NOT_REACHED(l7_cookie_node_token_for_ep)
NOT_REACHED(l7_cookie_persist_active)
NOT_REACHED(l7_cookie_read_presented)
NOT_REACHED(l7_hsts_synthesize)
NOT_REACHED(l7_mcp_header_used)
NOT_REACHED(llb_ai_record_request)
REACHED(llb_ai_record_unmetered)
NOT_REACHED(llb_ai_record_usage_missing)
REACHED(llb_ai_token_quota_consume)
NOT_REACHED(llhttp_execute)
NOT_REACHED(llhttp_get_error_pos)
NOT_REACHED(llhttp_init)
NOT_REACHED(llhttp_settings_init)
REACHED(notify_worker_id)
NOT_REACHED(pd_dialect_plain)
REACHED(pfe_ent_accouting)
NOT_REACHED(proxy_build_ppv2_v4)
REACHED(proxy_lock_trace_acquire)
REACHED(proxy_lock_trace_init)
REACHED(proxy_lock_trace_release)
REACHED(proxy_lock_trace_state)
REACHED(proxy_mono_ms)
REACHED(sp_fc_normal_eligible)
REACHED(sp_fc_route_eligible)
NOT_REACHED(sp_notify_arm)
REACHED(sp_resv_default_tokens_of)
REACHED(sp_resv_objective_strict_of)
NOT_REACHED(store_conversation_endpoint)
