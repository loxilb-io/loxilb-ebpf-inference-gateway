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
Each check runs on the real file, then on a mutated copy where it must fail
(the check has teeth).
"""
import re
import sys

SRC = "sockproxy_ep.c"


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
    print("test_radix_wiring: %s" % ("FAIL" if fails else "PASS"))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
