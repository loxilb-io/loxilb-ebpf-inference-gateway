#!/bin/sh
# Source invariant: a response the gateway writes itself is recorded as the
# client receives it, and once as a request, by what it means.
#
# A request the gateway answers in place of a backend is a response its
# client received. It is recorded through proxy_note_local_answer (status and
# the responses-by-status class counter, no TTFB sample: the histogram has no
# labels, and a refusal storm would pull the inference latency distribution
# down), and once as a request:
#
#   - a refusal, decided before any backend was chosen, by a deny record at
#     its stage (llb_ai_record_deny: the gate's verdict frame ai_gw_admit, or
#     ai_gw_record_local_deny / ai_gw_record_capacity_deny outside it),
#     outcome "denied";
#   - an outage, no backend able to take the request, by a completion with
#     the status written (proxy_record_local_completion on HTTP/1.1, the
#     stream's status for its settle on HTTP/2), outcome "completed".
#
# Rules (exit 1 on a violation):
#   1. Every call of a local sender is inside a function that records, or is
#      on the allowlist below with the reason it does not. A new answer fails
#      until it records or is listed; an entry that matches nothing fails too.
#   1b. A raw write (send, SSL_write) of a response built in the same
#      function (a buffer initialised with an HTTP status line) is preceded,
#      within 12 lines of that function, by its record: the paths that write
#      on a worker that must not block (the P/D legs, the connect event, the
#      LlamaFirewall block) keep their raw write and record before it. Or it
#      is allowlisted, keyed by its buffer.
#   2. proxy_note_local_answer never samples TTFB: it is
#      proxy_note_response_(pfe, status, 0), proxy_note_client_response is
#      (..., 1), and the writer samples only under RESP_NOTE_TTFB. That the
#      writer is the only one of the class counters and the TTFB sample is
#      check_pd_status_sites.sh rule 1c.
#   3. Every refusal names its stage: a function that records a refusal's
#      response also takes its deny record, or its callers do, and every
#      local deny record passes an AI_GW_STAGE_* other than NONE.
#   4. The 100 Continue never records: the latch belongs to the real response.
#   5. A refusal's response record is proxy_note_local_refusal, which marks
#      the request recorded when it took the latch: the status the note sets
#      would otherwise leave a completion owed, and the refusal would be
#      counted again, as completed, at the next request or the teardown.
#      proxy_note_local_answer is called only by that wrapper and by
#      proxy_record_local_completion, whose answers complete the request.
#
#   6. An answer the client has begun to receive takes no new status line
#      (sockproxy_answer.h). The two senders and sp_raw_status_write check
#      sp_answer_started before writing a status line, and the reaper checks
#      it before its own; the response framer keeps that state, from the
#      first status-line byte to the end of the message, and when it loses
#      the framing; and no status line goes out through a bare send() or
#      SSL_write(): a path that keeps a raw write uses sp_raw_status_write.
#      The stream behaviours follow the framer's Content-Type on every
#      AI-gateway connection, not only where sse_mode asks for them.
#
#   sh check_local_answers.sh [dir]   (dir defaults to this script's directory)
set -eu
cd "${1:-$(dirname "$0")}"

fail=0
# The loops below run in pipeline subshells; they flag a violation here.
FAILF=$(mktemp)
trap 'rm -f "$FAILF"' EXIT
SRCS=$(ls sockproxy*.c | grep -v '^sockproxy_.*test' | grep -v '^test_' || true)

# Allowlist: file:function:sender:code|calls|reason. `code` is the first
# string literal of the call, "-" when it has none; `calls` is how many calls
# the entry covers, exactly, so a second answer under one key fails. F-6, F-7 are the design
# follow-ups (ANALYSIS-AND-FIX-DESIGN §4.1).
ALLOW='
sockproxy_http.c:proxy_send_local_100_continue:proxy_send_local_response:-|1|interim 100 Continue: the real response follows and takes the latch (rule 4)
sockproxy_h2.c:proxy_h2_forward_to_backend:proxy_h2_send_ai_deny:-|1|the gate verdict on HTTP/2: the deny record is ai_gw_admit'"'"'s, at the verdict; no class counter on HTTP/2 (F-7)
sockproxy_health.c:pd_reap_respond:send:-|1|reaper fallback when the owner worker cannot be woken (no owner, ring full): the health thread may not write the request'"'"'s record fields, which the owner owns (a dispatch past its lookup may still record); counted in reap_fallback; F-6, F-13
'

# Functions that record their answer, each with the pattern its body must
# hold: the response record and, where the function owns it, the request
# record. Rule 3's "the callers take the deny record" cases are below.
# sp_fc_shed_answer_kept: an eviction answered by its own worker, the 429
# admission_shed; the deny record is sp_reap_fc_format's (rule 3 below).
# sp_reap_record: a queued or parked request is refused (capacity); a P/D
# request that timed out on its legs completes with the status written; the
# SSE events are body bytes inside a response in progress, not a response.
RECORDS='
sockproxy_refusal.c:sp_pd_send_refusal:proxy_note_local_refusal(pfe, status);proxy_record_local_deny(pfe, stage
sockproxy_http.c:sp_send_local_refusal:proxy_note_local_refusal(pfe, status);proxy_record_local_deny(pfe, stage
sockproxy_http.c:sp_send_local_outage:proxy_record_local_completion(pfe, status)
sockproxy_http.c:proxy_send_backend_unreachable:proxy_record_local_completion(pfe, 502)
sockproxy_http.c:sp_mcp_h1_refuse:proxy_record_local_completion(pfe, (uint16_t)status);proxy_note_local_refusal(pfe, (uint16_t)status);proxy_record_local_deny(pfe, AI_GW_STAGE_FRAMING, status
sockproxy_h2.c:h2_send_mcp_frame:stream->metric_response_status = status_code;h2_record_local_deny(pfe, stream, AI_GW_STAGE_FRAMING
sockproxy_http.c:sp_h1_send_admit_deny:proxy_note_local_refusal(pfe
sockproxy_http.c:sp_h1_send_capacity_deny:proxy_note_local_refusal(pfe
sockproxy_http.c:sp_h1_stream_model_unresolvable:proxy_note_local_refusal(pfe, 400);proxy_record_local_deny(pfe, AI_GW_STAGE_FRAMING
sockproxy_health.c:sp_reap_finish:sp_reap_record(pfe, kind)
sockproxy_health.c:sp_reap_record:proxy_note_local_refusal(pfe, 504);proxy_note_local_refusal(pfe, 503);proxy_note_local_refusal(pfe, 429);proxy_record_local_deny(pfe, AI_GW_STAGE_CAPACITY, 504;proxy_record_local_completion(pfe, 504);proxy_record_local_completion(pfe, 502)
sockproxy_health.c:sp_fc_shed_answer_kept:proxy_note_local_refusal(pfe, 429)
sockproxy_l7policy.c:l7_send_reject:proxy_note_local_refusal(pfe, (uint16_t)code);proxy_record_local_deny(pfe, AI_GW_STAGE_ROUTE, code
sockproxy_l7policy.c:l7_send_redirect:proxy_record_local_completion(pfe, (uint16_t)code)
sockproxy_h2.c:proxy_h2_send_l7_synthetic:l7_stream->metric_response_status = status_code;h2_record_local_deny(pfe, l7_stream, AI_GW_STAGE_ROUTE
sockproxy_h2.c:h2_send_local_refusal:h2_record_local_deny(pfe, stream, stage
sockproxy_h2.c:h2_record_local_deny:ai_gw_record_local_deny(stage
sockproxy_h2.c:h2_send_local_outage:stream->metric_response_status = status_code
'

# A sender's own body calling the sender below it is its implementation.
IMPL='
sockproxy_http.c:proxy_send_local_response_and_shutdown
sockproxy_h2.c:proxy_h2_send_ai_deny
sockproxy_h2.c:proxy_h2_send_capacity_deny
'

# The body of function $2 in file $1 (its definition line through the
# closing brace at column 0).
fnbody() {
  awk -v n="$2" '
    !on && $0 ~ "^[A-Za-z_]" && $0 ~ ("(^|[ *])" n "\\(") && $0 !~ /;[[:space:]]*$/ {on = 1}
    on {print}
    on && /^}/ {exit}' "$1"
}

# file:function:sender:code for every local-sender call. A function is named
# by its definition line (column 0, no trailing ";"); file scope resets at a
# closing brace in column 0. Raw send() is a local sender in the two files
# whose answers are built text; elsewhere it is the relay.
CALLS=$(awk '
  FNR == 1 { fn = ""; reset() }
  /^}/ { fn = ""; reset(); next }
  /^[A-Za-z_]/ && /\(/ && !/;[[:space:]]*$/ && !/^#/ {
    t = $0; sub(/\(.*/, "", t); n = split(t, a, /[ *]+/); fn = a[n]; reset(); next
  }
  # A buffer initialised with an HTTP status line (on its line or the next
  # two) is a built response; the last record call bounds rule 1b.
  /char[^=;(]*[ *][A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?[ \t]*=/ {
    t = $0; sub(/[ \t]*(\[[^]]*\])?[ \t]*=.*/, "", t); n = split(t, a, /[ *]+/); bname = a[n]; bleft = 3
  }
  bleft > 0 { if ($0 ~ /"HTTP\/1\.[01] [1-5][0-9][0-9]/) built[bname] = 1; bleft-- }
  /proxy_record_local_completion\(|proxy_note_local_answer\(|proxy_note_local_refusal\(|proxy_record_local_deny\(/ &&
  !/^[[:space:]]*(\*|\/\*|\/\/)/ { lastrec = FNR }
  pend == "" && !/^[[:space:]]*(\*|\/\*|\/\/)/ && match($0, /(^|[^a-z_])(send|SSL_write|sp_raw_status_write)\(/) {
    r = substr($0, RSTART + RLENGTH); split(r, args, ","); buf = args[2]
    gsub(/^[ \t]+|[ \t]+$/, "", buf)
    if (buf in built && !(lastrec > 0 && FNR - lastrec <= 12))
      print FILENAME ":" fn ":raw:" buf
  }
  pend != "" {
    acc = acc " " $0
    if (acc ~ /;/ || ++k > 8) { emit(); pend = "" }
    next
  }
  /^[[:space:]]*(\*|\/\*|\/\/)/ { next }
  {
    if (match($0, /(proxy_send_local_response_and_shutdown|proxy_send_local_response|proxy_h2_send_ai_deny|h2_send_deny_frame|proxy_h2_send_l7_synthetic)\(/)) {
      pend = substr($0, RSTART, RLENGTH - 1); acc = substr($0, RSTART + RLENGTH); k = 0
    } else if ((FILENAME == "sockproxy_health.c" || FILENAME == "sockproxy_l7policy.c") &&
               match($0, /(^|[^a-z_])send\(pfe->fd/)) {
      pend = "send"; acc = substr($0, RSTART + RLENGTH); k = 0
    } else next
    if (acc ~ /;/) { emit(); pend = "" }
  }
  function reset(  k) { for (k in built) delete built[k]; lastrec = 0; bleft = 0 }
  function emit(  c, d, i, ch) {
    # The call'"'"'s own arguments only: up to its closing parenthesis.
    d = 1
    for (i = 1; i <= length(acc) && d > 0; i++) {
      ch = substr(acc, i, 1)
      if (ch == "(") d++
      else if (ch == ")") d--
    }
    acc = substr(acc, 1, i - 1)
    c = "-"
    if (match(acc, /"([^"\\]|\\.)*"/)) c = substr(acc, RSTART + 1, RLENGTH - 2)
    print FILENAME ":" fn ":" pend ":" c
  }' $SRCS)

# 1. Every local-sender call records, is a sender's implementation, or is
#    allowlisted.
printf '%s\n' "$RECORDS" | while IFS= read -r r; do
  [ -n "$r" ] || continue
  f=${r%%:*}; rest=${r#*:}; fn=${rest%%:*}; pats=${rest#*:}
  body=$(fnbody "$f" "$fn")
  if [ -z "$body" ]; then
    echo "$f: recording function $fn not found"; echo x >> "$FAILF"; continue
  fi
  old_ifs=$IFS; IFS=';'
  for p in $pats; do
    printf '%s\n' "$body" | grep -qF "$p" || { echo "$f: $fn must record: $p"; echo x >> "$FAILF"; }
  done
  IFS=$old_ifs
done
recfns=$(printf '%s\n' "$RECORDS" | awk -F: 'NF {print $1 ":" $2}')
implfns=$(printf '%s\n' "$IMPL" | awk 'NF')
allowkeys=$(printf '%s\n' "$ALLOW" | awk -F'|' 'NF {print $1}')
printf '%s\n' "$CALLS" | while IFS= read -r c; do
  [ -n "$c" ] || continue
  ff=$(printf '%s' "$c" | cut -d: -f1-2)
  printf '%s\n' "$recfns" | grep -qxF "$ff" && continue
  printf '%s\n' "$implfns" | grep -qxF "$ff" && continue
  printf '%s\n' "$allowkeys" | grep -qxF "$c" && continue
  echo "$c"
  echo "  ^ a local answer that records nothing: send it through a recording sender (sp_send_local_refusal, sp_send_local_outage, h2_send_local_refusal, h2_send_local_outage) or allowlist it with its reason"
  echo x >> "$FAILF"
done
printf '%s\n' "$ALLOW" | while IFS='|' read -r a n _; do
  [ -n "$a" ] || continue
  got=$(printf '%s\n' "$CALLS" | grep -cxF "$a" || true)
  [ "$got" = "$n" ] || { echo "allowlist entry covers $n call(s), found $got: $a"; echo x >> "$FAILF"; }
done

# 2. A local answer never samples TTFB. The writer (resp_note_write_) takes
#    the latch with sample_ttfb; the HTTP/1.1 wrappers and the HTTP/2 ones
#    (sockproxy_h2.c h2_note_backend_response / h2_note_local_answer) say
#    which kind of response a site records, and every HTTP/2 note goes
#    through one of the two.
w=$(fnbody sockproxy_http.c resp_note_write_)
h1=$(fnbody sockproxy_http.c proxy_note_response_)
h2=$(fnbody sockproxy_http.c proxy_h2_note_stream_response)
la=$(fnbody sockproxy_http.c proxy_note_local_answer)
cr=$(fnbody sockproxy_http.c proxy_note_client_response)
h2la=$(fnbody sockproxy_h2.c h2_note_local_answer)
h2cr=$(fnbody sockproxy_h2.c h2_note_backend_response)
printf '%s\n' "$la" | grep -q 'return proxy_note_response_(pfe, status, 0);' ||
  { echo "sockproxy_http.c: proxy_note_local_answer must be proxy_note_response_(pfe, status, 0)"; fail=1; }
printf '%s\n' "$cr" | grep -q 'return proxy_note_response_(pfe, status, 1);' ||
  { echo "sockproxy_http.c: proxy_note_client_response must be proxy_note_response_(pfe, status, 1)"; fail=1; }
printf '%s\n' "$h2la" | grep -q 'return proxy_h2_note_stream_response(stream, status, 0);' ||
  { echo "sockproxy_h2.c: h2_note_local_answer must be proxy_h2_note_stream_response(stream, status, 0)"; fail=1; }
printf '%s\n' "$h2cr" | grep -q 'return proxy_h2_note_stream_response(stream, status, 1);' ||
  { echo "sockproxy_h2.c: h2_note_backend_response must be proxy_h2_note_stream_response(stream, status, 1)"; fail=1; }
h2notes=$(grep -c 'proxy_h2_note_stream_response(' sockproxy_h2.c || true)
[ "$h2notes" = "2" ] ||
  { echo "sockproxy_h2.c: proxy_h2_note_stream_response is called $h2notes times; only h2_note_backend_response and h2_note_local_answer call it"; fail=1; }
if printf '%s\n%s\n%s\n%s\n' "$la" "$cr" "$h1" "$h2" | grep -qE 'record_latency_sample|global_stats\.'; then
  echo "sockproxy_http.c: a wrapper writes the record itself; only resp_note_write_ does"; fail=1
fi
printf '%s\n' "$w" | grep -q 'resp_note_take(noted, sample_ttfb)' ||
  { echo "sockproxy_http.c: resp_note_write_ must take the latch with sample_ttfb (resp_note_take)"; fail=1; }
printf '%s\n' "$w" | grep -B3 'record_latency_sample(' | grep -q 'if ((take & RESP_NOTE_TTFB)' ||
  { echo "sockproxy_http.c: resp_note_write_ must sample TTFB only under (take & RESP_NOTE_TTFB)"; fail=1; }
grep -A2 '^resp_note_take(' sockproxy_resp_note.h | grep -q 'resp_note_claim(noted)' &&
  grep -A5 '^resp_note_take(' sockproxy_resp_note.h | grep -q 'RESP_NOTE_COUNT | (sample_ttfb ? RESP_NOTE_TTFB : 0)' ||
  { echo "sockproxy_resp_note.h: resp_note_take must claim, then take TTFB only when sample_ttfb"; fail=1; }

# 3. Every refusal names its stage. The senders whose callers own the deny
#    record: each caller holds one.
for spec in 'sockproxy_http.c:sp_h1_send_admit_deny:ai_gw_admit(|proxy_record_local_deny(pfe, AI_GW_STAGE_' \
            'sockproxy_http.c:sp_h1_send_capacity_deny:ai_gw_record_capacity_deny(' \
            'sockproxy_h2.c:proxy_h2_send_capacity_deny:ai_gw_record_capacity_deny('; do
  f=${spec%%:*}; rest=${spec#*:}; s=${rest%%:*}; pat=${rest#*:}
  callers=$(awk -v s="$s" '
    /^}/ {fn = ""; next}
    /^[A-Za-z_]/ && /\(/ && !/;[[:space:]]*$/ && !/^#/ {t = $0; sub(/\(.*/, "", t); n = split(t, a, /[ *]+/); fn = a[n]; next}
    /^[[:space:]]*(\*|\/\*|\/\/)/ {next}
    $0 ~ ("(^|[^a-z_])" s "\\(") && fn != "" && fn != s {print fn}' "$f" | sort -u)
  [ -n "$callers" ] || { echo "$f: no caller of $s found"; fail=1; }
  for c in $callers; do
    fnbody "$f" "$c" | grep -qE "$(printf '%s' "$pat" | sed 's/[(]/\\(/g')" ||
      { echo "$f: $c answers through $s without the refusal's deny record ($pat)"; fail=1; }
  done
done
# The reaper's capacity refusals: the deny record is the formatter's.
fnbody sockproxy_health.c sp_reap_fc_format | grep -q 'ai_gw_record_capacity_deny(' ||
  { echo "sockproxy_health.c: sp_reap_fc_format must take the queued refusal's deny record"; fail=1; }
# Every local deny record passes a stage, never NONE.
bad=$(awk '
  /(sp_pd_send_refusal|sp_send_local_refusal|proxy_record_local_deny|h2_send_local_refusal|ai_gw_record_local_deny)\(/ &&
  !/^[A-Za-z_]/ && !/^[[:space:]]*(\*|\/\*|\/\/)/ {
    acc = $0; k = 0
    while (acc !~ /;/ && k++ < 4 && (getline nl) > 0) acc = acc " " nl
    if (acc ~ /(sp_pd_send_refusal|sp_send_local_refusal|proxy_record_local_deny|h2_send_local_refusal)\([a-z_]+, (stream, )?(stage|AI_GW_STAGE_[A-Z]+)/ ||
        acc ~ /ai_gw_record_local_deny\((stage|\(int\)AI_GW_STAGE_[A-Z]+),/) {
      if (acc !~ /AI_GW_STAGE_NONE/) next
    }
    print FILENAME ":" FNR ": " acc
  }' $SRCS sockproxy_ai_admit.c)
if [ -n "$bad" ]; then
  printf '%s\n' "$bad"
  echo "  ^ a local deny record without its AI_GW_STAGE_*"
  fail=1
fi

# 4. The 100 Continue never records.
if fnbody sockproxy_http.c proxy_send_local_100_continue | grep -qE 'proxy_note_|proxy_record_local|llb_ai_record'; then
  echo "sockproxy_http.c: proxy_send_local_100_continue records; the latch belongs to the real response"
  fail=1
fi

# 5. A refusal leaves no completion owed.
fnbody sockproxy_http.c proxy_note_local_refusal | tr -d '\n' |
  grep -qE 'int noted = proxy_note_local_answer\(pfe, status\);[[:space:]]*if \(noted\)[[:space:]]*pfe->metric_ai_recorded = 1;' ||
  { echo "sockproxy_http.c: proxy_note_local_refusal must mark the request recorded when its note took the latch"; fail=1; }
stray=$(awk '
  /^}/ {fn = ""; next}
  /^[A-Za-z_]/ && /\(/ && !/;[[:space:]]*$/ && !/^#/ {t = $0; sub(/\(.*/, "", t); n = split(t, a, /[ *]+/); fn = a[n]; next}
  /^[[:space:]]*(\*|\/\*|\/\/)/ {next}
  /(^|[^a-z_])proxy_note_local_answer\(/ && fn != "proxy_note_local_refusal" &&
    fn != "proxy_record_local_completion" && fn != "" {print FILENAME ":" FNR ": " fn}' $SRCS)
if [ -n "$stray" ]; then
  printf '%s\n' "$stray"
  echo "  ^ proxy_note_local_answer outside a completion: a refusal records through proxy_note_local_refusal, or it is counted again as completed"
  fail=1
fi

# 6. A started answer takes no new status line.
for spec in \
  'sockproxy_refusal.c:sp_pd_send_refusal:sp_answer_is_status_line(response, len) && sp_answer_started(pfe)' \
  'sockproxy_http.c:proxy_send_local_response:sp_answer_is_status_line(buf, len) && sp_answer_started(pfe)' \
  'sockproxy_http.c:proxy_send_local_response_and_shutdown:sp_answer_is_status_line(buf, len) && sp_answer_started(pfe)' \
  'sockproxy_http.c:sp_raw_status_write:if (sp_answer_started(pfe))' \
  'sockproxy_health.c:sp_reap_finish:!t->body && sp_answer_started(pfe)' \
  'sockproxy_health.c:pd_reap_respond:!t->body && sp_answer_started(pfe)' \
  'sockproxy_http.c:cresp_on_message_begin:sp_answer_msg_begin(&pfe->cresp_in_msg)' \
  'sockproxy_http.c:cresp_on_message_complete:sp_answer_msg_done(&pfe->cresp_in_msg)' \
  'sockproxy_http.c:cresp_feed:sp_answer_framing_lost(&client->cresp_in_msg)'; do
  f=${spec%%:*}; rest=${spec#*:}; fn=${rest%%:*}; pat=${rest#*:}
  fnbody "$f" "$fn" | grep -qF "$pat" ||
    { echo "$f: $fn must hold: $pat (a started answer takes no new status line)"; fail=1; }
done
bare=$(for f in $SRCS; do awk '
  FNR == 1 { fn = ""; reset() }
  /^}/ { fn = ""; reset(); next }
  /^[A-Za-z_]/ && /\(/ && !/;[[:space:]]*$/ && !/^#/ { t = $0; sub(/\(.*/, "", t); n = split(t, a, /[ *]+/); fn = a[n]; reset(); next }
  /char[^=;(]*[ *][A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?[ \t]*=/ {
    t = $0; sub(/[ \t]*(\[[^]]*\])?[ \t]*=.*/, "", t); n = split(t, a, /[ *]+/); bname = a[n]; bleft = 3
  }
  bleft > 0 { if ($0 ~ /"HTTP\/1\.[01] [1-5][0-9][0-9]/) built[bname] = 1; bleft-- }
  !/^[[:space:]]*(\*|\/\*|\/\/)/ && match($0, /(^|[^a-z_])(send|SSL_write)\(/) {
    r = substr($0, RSTART + RLENGTH); split(r, args, ","); b = args[2]
    gsub(/^[ \t]+|[ \t]+$/, "", b)
    if (b in built) print FILENAME ":" FNR ": " fn ": " b
  }
  function reset(  k) { for (k in built) delete built[k]; bleft = 0 }' "$f"; done)
if [ -n "$bare" ]; then
  printf '%s\n' "$bare"
  echo "  ^ a status line written by a bare send()/SSL_write(): use sp_raw_status_write, which will not write it into an answer in progress"
  fail=1
fi

[ -s "$FAILF" ] && fail=1
[ "$fail" = "0" ] || exit 1
echo "Local answers: OK (every gateway answer records its response without a TTFB sample, and its request as a staged refusal or an outage completion; none is written into an answer in progress; $(printf '%s\n' "$ALLOW" | grep -c '|') allowlisted with reasons)"
