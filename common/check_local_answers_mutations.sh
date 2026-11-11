#!/bin/sh
# Mutation tests for check_local_answers.sh: each rule is broken once in a
# scratch copy of the sources, and the check must fail with that rule's
# message. The unmutated copy must pass. Exit 1 when a mutation survives.
#
#   sh check_local_answers_mutations.sh    (from anywhere; needs python3)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

survived=0
n=0

fresh() {
  rm -rf "$work/src"
  mkdir "$work/src"
  cp "$here"/sockproxy*.c "$here"/sockproxy_resp_note.h "$here/check_local_answers.sh" "$work/src/"
}

# mut FILE OLD NEW: replace the one occurrence of OLD (it must exist once).
mut() {
  python3 - "$work/src/$1" "$2" "$3" <<'EOF'
import sys
p, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(p).read()
if s.count(old) != 1:
    sys.exit("mutation anchor found %d times in %s: %r" % (s.count(old), p, old))
open(p, "w").write(s.replace(old, new))
EOF
}

# expect NAME MESSAGE: the check fails, and says MESSAGE.
expect() {
  n=$((n + 1))
  if out=$(sh "$work/src/check_local_answers.sh" "$work/src" 2>&1); then
    echo "SURVIVED: $1 (the check passed)"
    survived=1
  elif ! printf '%s\n' "$out" | grep -qF "$2"; then
    echo "SURVIVED: $1 (failed without: $2)"
    printf '%s\n' "$out" | sed 's/^/    /'
    survived=1
  else
    echo "killed: $1"
  fi
}

fresh
sh "$work/src/check_local_answers.sh" "$work/src" >/dev/null ||
  { echo "the unmutated sources fail the check"; exit 1; }

# Rule 1: a local answer that records nothing.
fresh
mut sockproxy_ep.c 'sp_send_local_refusal(pfe, AI_GW_STAGE_ROUTE, 503, "model_unavailable",' 'proxy_send_local_response(pfe,'
expect "rule 1: a route refusal sent raw" "sockproxy_ep.c:proxy_setup_ep__:proxy_send_local_response:-"

fresh
mut sockproxy_h2.c 'h2_send_local_refusal(pfe, stream, AI_GW_STAGE_ROUTE, 503, lookup_model,' 'proxy_h2_send_ai_deny(pfe, stream, 503, 0, 0,'
expect "rule 1: an HTTP/2 route refusal sent raw" "proxy_h2_send_ai_deny:model_unavailable"

fresh
mut sockproxy_http.c '  proxy_record_local_deny(pfe, stage, status, code);
  ml = sp_refusal_mark_splice(' '  ml = sp_refusal_mark_splice('
expect "rule 1: the refusal sender drops its deny record" "sp_send_local_refusal must record: proxy_record_local_deny(pfe, stage"

fresh
mut sockproxy_http.c '  proxy_record_local_completion(pfe, status);
  ml = sp_refusal_mark_splice(marked, sizeof(marked), buf, len, NULL,' '  proxy_note_local_answer(pfe, status);
  ml = sp_refusal_mark_splice(marked, sizeof(marked), buf, len, NULL,'
expect "rule 1: the outage sender drops its completion" "sp_send_local_outage must record: proxy_record_local_completion(pfe, status)"

fresh
mut sockproxy_h2.c '  stream->metric_response_status = status_code;
' ''
expect "rule 1: the HTTP/2 outage sender drops its status" "h2_send_local_outage must record"

fresh
mut sockproxy_h2.c '  ai_gw_record_local_deny(stage, stream->request_id, notify_worker_id(),' '  ai_gw_record_local_xxxx(stage, stream->request_id, notify_worker_id(),'
expect "rule 1: the HTTP/2 deny record drops its export" "h2_record_local_deny must record: ai_gw_record_local_deny(stage"

fresh
mut sockproxy_health.c '    proxy_record_local_completion(pfe, 502);' '    ;'
expect "rule 1: the reaper drops a P/D timeout's completion" "sp_reap_record must record: proxy_record_local_completion(pfe, 502)"

fresh
mut sockproxy_health.c '  case SP_REAP_FC_TTL:
    proxy_note_local_refusal(pfe, 429);' '  case SP_REAP_FC_TTL:
    ;'
expect "rule 1: the reaper drops an eviction's or a client TTL's 429" "sp_reap_record must record: proxy_note_local_refusal(pfe, 429)"

fresh
mut sockproxy_health.c '  proxy_note_local_refusal(pfe, 429);
  if (len > 0 && proxy_send_local_response(pfe, framed, len) == 0)' '  if (len > 0 && proxy_send_local_response(pfe, framed, len) == 0)'
expect "rule 1: a kept eviction answer drops its record" "sp_fc_shed_answer_kept must record: proxy_note_local_refusal(pfe, 429)"

fresh
mut sockproxy_l7policy.c '    proxy_record_local_deny(pfe, AI_GW_STAGE_ROUTE, code, "l7_policy_reject");' ''
expect "rule 1: an L7-policy REJECT drops its deny record" "l7_send_reject must record: proxy_record_local_deny(pfe, AI_GW_STAGE_ROUTE, code"

fresh
mut sockproxy_h2.c '      l7_stream->metric_response_status = status_code;' '      (void)0;'
expect "rule 1: an HTTP/2 L7 REDIRECT drops its status" "proxy_h2_send_l7_synthetic must record: l7_stream->metric_response_status = status_code"

fresh
mut sockproxy_http.c '  log_debug("[JSON_STREAM_CONTINUE] fd=%d sent local 100 Continue", pfe->fd);' '  proxy_send_local_response(pfe, response, 0);'
expect "rule 1: a second answer under one allowlist key" "allowlist entry covers 1 call(s), found 2"

# F-20: the MCP refusals, the HTTP/2 outages and the smuggling 400 record.

fresh
mut sockproxy_http.c '    proxy_record_local_deny(pfe, AI_GW_STAGE_FRAMING, status,
                            sp_mcp_refusal_code(status));' '    ;'
expect "rule 1: the MCP refusal drops its deny record" "sp_mcp_h1_refuse must record: proxy_record_local_deny(pfe, AI_GW_STAGE_FRAMING, status"

fresh
mut sockproxy_h2.c '    h2_record_local_deny(pfe, stream, AI_GW_STAGE_FRAMING, status_code,
                         stream->effective_model, sp_mcp_refusal_code(status_code));' '    ;'
expect "rule 1: the HTTP/2 MCP frame drops its deny record" "h2_send_mcp_frame must record: h2_record_local_deny(pfe, stream, AI_GW_STAGE_FRAMING"

fresh
mut sockproxy_h2.c 'h2_send_local_outage(pfe, stream, 503, "backend_unreachable",' 'proxy_h2_send_ai_deny(pfe, stream, 503, 0, 0, "backend_unreachable",'
expect "rule 1: an HTTP/2 connect failure answered raw" "proxy_h2_send_ai_deny:backend_unreachable"

fresh
mut sockproxy_h2.c 'h2_send_local_refusal(pfe, stream, AI_GW_STAGE_FRAMING, 413,
                            stream->effective_model,"mcp_headers_too_large",' 'proxy_h2_send_ai_deny(pfe,stream,413,0,0,"mcp_headers_too_large",'
expect "rule 1: an HTTP/2 MCP header refusal answered raw" "proxy_h2_send_ai_deny:mcp_headers_too_large"

fresh
mut sockproxy_h2.c 'h2_send_mcp_frame(pfe,stream,status,body,(int)blen,' 'h2_send_deny_frame(pfe,stream,status,0,body,(int)blen,'
expect "rule 1: the HTTP/2 MCP gate frames its refusal raw" "sockproxy_h2.c:sp_mcp_h2_gate:h2_send_deny_frame:-"

fresh
mut sockproxy_http.c 'if (proxy_send_local_response(pfe, response, sizeof(response) - 1) != 0) {' 'if (sp_send_raw(pfe, response, sizeof(response) - 1) != 0) {'
expect "rule 1: an allowlist entry that matches nothing" "allowlist entry covers 1 call(s), found 0"

# Rule 1b: a raw write of a built response records first.

fresh
mut sockproxy_http.c '              proxy_note_local_refusal(pfe, 400);
              proxy_record_local_deny(pfe, AI_GW_STAGE_FRAMING, 400,
                                      "bad_request");
' ''
expect "rule 1b: the smuggling refusal writes its 400 unrecorded" "sockproxy_http.c:handle_client_data:raw:smuggle_400"
fresh
mut sockproxy_http.c '      proxy_record_local_completion(client, 502);
' ''
expect "rule 1b: the connect-failure 502 written raw without its record" "sockproxy_http.c:proxy_backend_connect_event:raw:lb_502"

fresh
mut sockproxy_pd_sglang.c '  proxy_record_local_completion(client_pfe, 502);
' ''
expect "rule 1b: a SGLang pair abort written raw without its record" "sockproxy_pd_sglang.c:pd_sg_abort_pair:raw:pd_sg_err"

fresh
mut sockproxy_pd_vllm.c '    proxy_record_local_completion(client_pfe, 503);
' ''
expect "rule 1b: the vLLM prefill failover 503 written raw without its record" "sockproxy_pd_vllm.c:pd_retry_prefill:raw:pd_prefill_err"

fresh
mut sockproxy_http.c '          proxy_note_local_refusal(pfe, 403);
          proxy_record_local_deny(pfe, AI_GW_STAGE_SECURITY, 403, "llamafirewall_block");
' ''
expect "rule 1b: the LlamaFirewall block written raw without its record" "sockproxy_http.c:handle_on_message_complete:raw:block_response"

fresh
mut sockproxy_http.c '          memset(&pfe->prefix_key, 0, sizeof(pfe->prefix_key));  // P0.2: Reset prefix' '          memset(&pfe->prefix_key, 0, sizeof(pfe->prefix_key));  // P0.2: Reset prefix
          sp_raw_status_write(pfe, smuggle_400, 0, MSG_NOSIGNAL);'
expect "rule 1b: a second raw write of the smuggling 400, farther than 12 lines from its record" "sockproxy_http.c:handle_client_data:raw:smuggle_400"

# Rule 2: a local answer never samples TTFB.
fresh
mut sockproxy_http.c 'return proxy_note_response_(pfe, status, 0);' 'return proxy_note_response_(pfe, status, 1);'
expect "rule 2: the local wrapper samples TTFB" "proxy_note_local_answer must be proxy_note_response_(pfe, status, 0)"

fresh
mut sockproxy_http.c 'if ((take & RESP_NOTE_TTFB) && req_start_ns > 0) {' 'if (req_start_ns > 0) {'
expect "rule 2: the writer samples whatever the caller asked" "must sample TTFB only under (take & RESP_NOTE_TTFB)"

fresh
mut sockproxy_h2.c '  return proxy_h2_note_stream_response(stream, status, 0);' '  return proxy_h2_note_stream_response(stream, status, 1);'
expect "rule 2: the HTTP/2 local wrapper samples TTFB" "h2_note_local_answer must be proxy_h2_note_stream_response(stream, status, 0)"

fresh
mut sockproxy_h2.c '  h2_note_local_answer(stream, (uint16_t)status_code);' '  proxy_h2_note_stream_response(stream, (uint16_t)status_code, 1);'
expect "rule 2: an HTTP/2 site notes around the wrappers" "only h2_note_backend_response and h2_note_local_answer call it"

fresh
mut sockproxy_http.c '  return resp_note_write_(&stream->metric_resp_noted,
                          stream->metric_req_start_ns, status, sample_ttfb);' '  atomic_fetch_add(&global_stats.http_responses_total, 1);
  return 1;'
expect "rule 2: the HTTP/2 wrapper writes the record itself" "a wrapper writes the record itself"

fresh
mut sockproxy_resp_note.h 'return RESP_NOTE_COUNT | (sample_ttfb ? RESP_NOTE_TTFB : 0);' 'return RESP_NOTE_COUNT | RESP_NOTE_TTFB;'
expect "rule 2: the latch hands every caller a TTFB sample" "resp_note_take must claim, then take TTFB only when sample_ttfb"

fresh
mut sockproxy_http.c 'proxy_note_local_answer(proxy_fd_ent_t *pfe, uint16_t status)
{' 'proxy_note_local_answer(proxy_fd_ent_t *pfe, uint16_t status)
{
  atomic_fetch_add(&global_stats.http_status_5xx, 1);'
expect "rule 2: a wrapper writes the record itself" "a wrapper writes the record itself"

# Rule 3: every refusal names its stage.
fresh
mut sockproxy_http.c '  proxy_record_local_deny(pfe, AI_GW_STAGE_FRAMING, status, code);
  sp_h1_send_admit_deny(pfe, AI_GW_STAGE_FRAMING, status, 0, 0, code, msg);' '  sp_h1_send_admit_deny(pfe, AI_GW_STAGE_FRAMING, status, 0, 0, code, msg);'
expect "rule 3: a framing 413 without its deny record" "sp_h1_send_framing_deny answers through sp_h1_send_admit_deny without the refusal's deny record"

fresh
mut sockproxy_http.c '  ai_gw_record_capacity_deny(proxy_request_id(pfe), notify_worker_id(),
                             svc_ident, proxy_effective_model(pfe),
                             pfe->tenant_id, pfe->auth_key_id,
                             pfe->auth_user_id, status, code,' '  ai_gw_record_capacity_xxxx(proxy_request_id(pfe), notify_worker_id(),
                             svc_ident, proxy_effective_model(pfe),
                             pfe->tenant_id, pfe->auth_key_id,
                             pfe->auth_user_id, status, code,'
expect "rule 3: an HTTP/1.1 capacity refusal without its deny record" "through sp_h1_send_capacity_deny without the refusal's deny record"

fresh
mut sockproxy_ep.c 'AI_GW_STAGE_ROUTE, 503, "no_rules"' 'AI_GW_STAGE_NONE, 503, "no_rules"'
expect "rule 3: a refusal recorded at stage NONE" "a local deny record without its AI_GW_STAGE_*"

fresh
mut sockproxy_ep.c 'AI_GW_STAGE_CAPACITY, 429, "pd_overloaded"' '0, 429, "pd_overloaded"'
expect "rule 3: a refusal recorded with a bare stage number" "a local deny record without its AI_GW_STAGE_*"

fresh
mut sockproxy_health.c 'ai_gw_record_capacity_deny(proxy_request_id(pfe), notify_worker_id(),' 'ai_gw_record_capacity_xxxx(proxy_request_id(pfe), notify_worker_id(),'
expect "rule 3: the reaper's capacity refusal without its deny record" "sp_reap_fc_format must take the queued refusal's deny record"

# Rule 4: the 100 Continue never records.
fresh
mut sockproxy_http.c '  pfe->json_stream_continue_sent = 1;' '  pfe->json_stream_continue_sent = 1;
  proxy_note_local_answer(pfe, 100);'
expect "rule 4: the 100 Continue takes the latch" "proxy_send_local_100_continue records"

# Rule 5: a refusal leaves no completion owed.
fresh
mut sockproxy_http.c '  if (noted)
    pfe->metric_ai_recorded = 1;
  return noted;' '  return noted;'
expect "rule 5: the refusal note leaves a completion owed" "proxy_note_local_refusal must mark the request recorded when its note took the latch"

fresh
mut sockproxy_http.c '  if (noted)
    pfe->metric_ai_recorded = 1;
  return noted;' '  pfe->metric_ai_recorded = 1;
  return noted;'
expect "rule 5: the refusal note marks a request whose response it did not record" "proxy_note_local_refusal must mark the request recorded when its note took the latch"

fresh
mut sockproxy_pd_sglang.c 'proxy_note_local_refusal(client_pfe, 503);' 'proxy_note_local_answer(client_pfe, 503);'
expect "rule 5: a refusal recorded with the completion note" "proxy_note_local_answer outside a completion"

fresh
mut sockproxy_http.c '    /* The request record is the caller'"'"'s (ai_gw_record_capacity_deny). */
    proxy_note_local_refusal(pfe, (uint16_t)status);' '    /* The request record is the caller'"'"'s (ai_gw_record_capacity_deny). */
    proxy_note_local_answer(pfe, (uint16_t)status);'
expect "rule 5: the capacity refusal recorded with the completion note" "sp_h1_send_capacity_deny must record: proxy_note_local_refusal(pfe"

# Rule 6: a started answer takes no new status line.
fresh
mut sockproxy_http.c '  if (sp_answer_is_status_line(buf, len) && sp_answer_started(pfe)) {
    sp_end_started_answer(pfe, buf, len);
    return -1;
  }
  return sp_send_all_bounded(proxy_send_local_once' '  return sp_send_all_bounded(proxy_send_local_once'
expect "rule 6: the sender writes a status line into an answer in progress" "proxy_send_local_response must hold"

fresh
mut sockproxy_http.c '  if (sp_answer_is_status_line(buf, len) && sp_answer_started(pfe)) {
    sp_end_started_answer(pfe, buf, len);
    return -1;
  }
  return sp_send_all_bounded_then_shutdown(' '  return sp_send_all_bounded_then_shutdown('
expect "rule 6: the closing sender writes a status line into an answer in progress" "proxy_send_local_response_and_shutdown must hold"

fresh
mut sockproxy_http.c '  if (sp_answer_started(pfe)) {
    sp_end_started_answer(pfe, buf, len);
    return -1;
  }
  if (pfe->ssl)
    return SSL_write(' '  if (pfe->ssl)
    return SSL_write('
expect "rule 6: the raw-write helper writes into an answer in progress" "sp_raw_status_write must hold"

fresh
mut sockproxy_health.c '    if (!t->body && sp_answer_started(pfe)) {
      /* A whole response cannot follow' '    if (0) {
      /* A whole response cannot follow'
expect "rule 6: the reaper writes its status line into an answer in progress" "sp_reap_finish must hold"

fresh
mut sockproxy_health.c '    if (!t->body && sp_answer_started(pfe)) {
      /* An answer is in progress' '    if (0) {
      /* An answer is in progress'
expect "rule 6: the reaper fallback writes its status line into an answer in progress" "pd_reap_respond must hold"

fresh
mut sockproxy_pd_sglang.c 'sp_raw_status_write(client_pfe, pd_sg_err, sizeof(pd_sg_err) - 1,' 'send(client_pfe->fd, pd_sg_err, sizeof(pd_sg_err) - 1,'
expect "rule 6: the SGLang pair abort writes its 502 with a bare send" "a status line written by a bare send()/SSL_write()"

fresh
mut sockproxy_http.c '    sp_answer_msg_begin(&pfe->cresp_in_msg);
' ''
expect "rule 6: the framer does not mark the start of a message" "cresp_on_message_begin must hold"

fresh
mut sockproxy_http.c '    sp_answer_framing_lost(&client->cresp_in_msg);
' ''
expect "rule 6: a framer that lost the framing reads as outside a message" "cresp_feed must hold"

fresh
mut sockproxy_refusal.c 'sp_answer_is_status_line(response, len) && sp_answer_started(pfe)' '0'
expect "rule 6: native P/D async refusal overwrites a begun answer" "sp_pd_send_refusal must hold"

fresh
mut sockproxy_refusal.c '  proxy_note_local_refusal(pfe, status);' ''
expect "rule 1: native P/D async refusal drops response receipt" "sp_pd_send_refusal must record: proxy_note_local_refusal"

fresh
mut sockproxy_refusal.c '  proxy_record_local_deny(pfe, stage, status, code);' ''
expect "rule 1: native P/D async refusal drops staged deny" "sp_pd_send_refusal must record: proxy_record_local_deny"

[ "$survived" = "0" ] || { echo "check_local_answers.sh: a mutation survived"; exit 1; }
echo "check_local_answers.sh mutations: $n/$n killed"
