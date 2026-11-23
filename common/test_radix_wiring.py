#!/usr/bin/env python3
"""test_radix_wiring.py - where the radix decision sits in proxy_setup_ep__.

Source-order checks of sockproxy_ep.c that the unit harness cannot drive
(proxy_setup_ep__ needs the whole proxy):
  1. an endpoint the EPP chose never reaches radix_route_decide: the EPP pin
     exits with `goto pd_failover_ok` before the radix decision, and that
     label comes after it;
  2. the only other forward jump to that label before the radix decision is
     the P/D metadata path, and the radix block excludes P/D pools;
  3. the radix inputs mark a persistence (sticky) pool and the session overlay
     as pins; the keep-alive gather treats sticky, session header, EPP, MCP
     and L7 policy as gates it cannot evaluate.
  4. one eligible-mask helper (sp_radix_eligible, sockproxy_mcp_rr.h) holds
     the per-endpoint rule (route, drain, role, breaker, in-flight); the
     HTTP/1.1 gatherer calls it and keeps no loop of its own;
  5. one chat predicate (sp_is_chat_path): HTTP/1.1 sets is_chat from it,
     the gatherer passes not_chat from is_chat, and no other copy of the
     path compare remains;
  6. the HTTP/1.1 gatherer passes the request's decided mark, and message
     begin clears it together with the radix_req reset.
Each check runs on the real files, then on a mutated copy where it must fail
(the check has teeth).
"""
import re
import sys

SRC = "sockproxy_ep.c"
SHARED_SRCS = ("sockproxy_ep.c", "sockproxy_http.c", "sockproxy_h2.c", "sockproxy_mcp_rr.h")


def body_of(src, name):
    i = src.index("\n%s(" % name)
    j = src.index("\n{", i)
    depth, k = 0, j + 1
    while True:
        c = src[k]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return src[j:k + 1]
        k += 1


def check(src):
    errs = []
    f = body_of(src, "proxy_setup_ep__")
    radix = f.find("radix_route_decide(")
    label = f.find("\npd_failover_ok:")
    epp_stage = f.find("tepval->epp_mode != EPP_MODE_OFF")
    epp_exit = f.find("if (pin == EPP_PIN_OK)\n              goto pd_failover_ok;")
    if min(radix, label, epp_stage, epp_exit) < 0:
        return ["a landmark is missing"]
    if not (epp_stage < epp_exit < radix < label):
        errs.append("order EPP stage < EPP pin exit < radix decision < pd_failover_ok broken")
    early = [m.start() for m in re.finditer(r"goto pd_failover_ok;", f[:radix])]
    others = [g for g in early if g != epp_exit + len("if (pin == EPP_PIN_OK)\n              ")]
    pd_block = f.find("if (!l7_subset && tepval->pd_disagg_enabled && pfe) {")
    for g in others:
        if not (pd_block >= 0 and pd_block < g):
            errs.append("a jump past the radix decision outside the EPP pin and the P/D path")
    if "if (pfe && tepval->radix && !tepval->pd_disagg_enabled)" not in f:
        errs.append("the radix block does not exclude P/D pools")
    if "radix_nsk != NS_OVERLAY_NONE" not in f[:radix + 200]:
        errs.append("the session overlay is not passed as a pin")
    g = body_of(src, "sp_radix_gather")
    if "in->sticky_select = pool->select == PROXY_SEL_STICKY" not in g:
        errs.append("a sticky pool is not marked")
    for gate in ("pool->session_header_enabled", "pool->select == PROXY_SEL_STICKY",
                 "pool->epp_mode != EPP_MODE_OFF", "pool->mcp_stateless", "l7_policy_on(node)"):
        if gate not in g.split("in->gates_unknown")[-1]:
            errs.append("keep-alive gate missing: " + gate)
    return errs


def body_inline(src, name):
    """Body of the static inline helper name, or None."""
    m = re.search(r"static inline [^;{]*\b%s\(" % name, src)
    if not m:
        return None
    j = src.index("{", m.end())
    depth, k = 0, j
    while True:
        c = src[k]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return src[j:k + 1]
        k += 1


def check_shared(f):
    errs = []
    helper = body_inline(f["sockproxy_mcp_rr.h"], "sp_radix_eligible")
    if helper is None:
        errs.append("sp_radix_eligible missing from sockproxy_mcp_rr.h")
        helper = ""
    for need in ("sp_route_allows(pfe, i)", "pool->eps[i].inv == 0", "pool->ep_role[i] == 0",
                 "circuit_breaker_candidate(pool, i)", "fc_ep_inflight(&pool->fc, i, FC_ROLE_NORMAL)"):
        if need not in helper:
            errs.append("eligible helper lacks " + need)
    g = body_of(f["sockproxy_ep.c"], "sp_radix_gather")
    if "in->eligible = sp_radix_eligible(pfe, pool, n, inflight);" not in g:
        errs.append("the HTTP/1.1 gatherer does not take the eligible mask from the helper")
    if "circuit_breaker_candidate" in g or "fc_ep_inflight" in g:
        errs.append("the HTTP/1.1 gatherer keeps its own eligible loop")
    if "in->not_chat = pfe->is_chat ? 0 : 1;" not in g:
        errs.append("the HTTP/1.1 gatherer does not pass not_chat from is_chat")
    if "pfe->is_chat = sp_is_chat_path(pfe->request_path) ? 1 : 0;" not in f["sockproxy_http.c"]:
        errs.append("HTTP/1.1 is_chat is not set by sp_is_chat_path")
    for n in ("sockproxy_ep.c", "sockproxy_http.c", "sockproxy_h2.c"):
        if '"/v1/chat/completions"' in f[n]:
            errs.append("a second chat path compare in " + n)
    if "in->decided = &pfe->radix_decided;" not in g:
        errs.append("the HTTP/1.1 gatherer does not pass the decided mark")
    begin = "    radix_req_reset(pfe->radix_req);   /* the prefix-routing key is request N's too */\n" \
            "    pfe->radix_decided = 0;"
    if begin not in f["sockproxy_http.c"]:
        errs.append("message begin does not clear the decided mark with the radix_req reset")
    return errs


def main():
    src = open(SRC).read()
    fails = 0
    errs = check(src)
    print("[%s] wiring of %s%s" % ("FAIL" if errs else "PASS", SRC, "".join("\n    " + e for e in errs)))
    fails += bool(errs)
    f = body_of(src, "proxy_setup_ep__")
    radix_line = f[f.rfind("\n", 0, f.find("int rsel = radix_route_decide(")):f.find("\n", f.find("int rsel = radix_route_decide("))]
    mutants = {
        "radix decision moved before the EPP stage":
            src.replace(radix_line, "", 1).replace(
                "if (pfe && tepval->epp_mode != EPP_MODE_OFF) {",
                radix_line.strip() + "\n        if (pfe && tepval->epp_mode != EPP_MODE_OFF) {", 1),
        "sticky not marked":
            src.replace("in->sticky_select = pool->select == PROXY_SEL_STICKY ? 1 : 0;", "", 1),
        "EPP gate dropped at keep-alive":
            src.replace("pool->epp_mode != EPP_MODE_OFF || pool->mcp_stateless", "pool->mcp_stateless", 1),
    }
    for name, m in mutants.items():
        caught = bool(check(m))
        print("[%s] negative control: %s" % ("PASS" if caught else "FAIL", name))
        fails += not caught
    files = {n: open(n).read() for n in SHARED_SRCS}
    errs = check_shared(files)
    print("[%s] shared eligible helper and chat predicate (HTTP/1.1)%s" % (
        "FAIL" if errs else "PASS", "".join("\n    " + e for e in errs)))
    fails += bool(errs)

    def mut(name, old, new):
        m = dict(files)
        if old not in m[name]:
            return None
        m[name] = m[name].replace(old, new, 1)
        return m
    shared_mutants = {
        "the helper drops the breaker":
            mut("sockproxy_mcp_rr.h", "circuit_breaker_candidate(pool, i)", "1"),
        "the HTTP/1.1 gatherer passes no not_chat":
            mut("sockproxy_ep.c", "in->not_chat = pfe->is_chat ? 0 : 1;", ""),
        "HTTP/1.1 is_chat by its own compare":
            mut("sockproxy_http.c", "pfe->is_chat = sp_is_chat_path(pfe->request_path) ? 1 : 0;",
                'pfe->is_chat = !strcmp(pfe->request_path, "/v1/chat/completions");'),
        "the HTTP/1.1 gatherer passes no decided mark":
            mut("sockproxy_ep.c", "in->decided = &pfe->radix_decided;", ""),
        "message begin keeps the decided mark":
            mut("sockproxy_http.c", "    pfe->radix_decided = 0;", ""),
        "the HTTP/1.1 gatherer keeps its own loop":
            mut("sockproxy_ep.c", "in->eligible = sp_radix_eligible(pfe, pool, n, inflight);",
                "for (int i = 0; i < n; i++) if (circuit_breaker_candidate(pool, i)) in->eligible |= 1u << i;"),
    }
    for name, m in shared_mutants.items():
        caught = m is not None and bool(check_shared(m))
        print("[%s] negative control: %s" % ("PASS" if caught else "FAIL", name))
        fails += not caught
    print("test_radix_wiring: %s" % ("FAIL" if fails else "PASS"))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
