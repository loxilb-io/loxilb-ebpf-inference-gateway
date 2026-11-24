#!/usr/bin/env python3
"""test_radix_cfg_wiring.py - where a rule's prefix-affinity arguments travel.

Source checks of the sites the unit harness cannot drive (they need the whole
data plane):
  1. llb_conv_nat2proxy (kernel/loxilb_libdp.c) copies the three arguments
     from dp_proxy_tacts into proxy_arg;
  2. proxy_add_entry applies them to the pool on both create paths and in the
     refresh block (sp_radix_apply), so an update reaches a CHWBL/WRR_HASH
     pool that is refreshed rather than re-created;
  3. the pool's radix pointer is read in one place: sp_radix_active
     (sockproxy_radix_cfg.h), one acquire load, published by sp_radix_apply
     with a release store; no other read of ->radix remains in the request,
     health and refresh paths;
  4. the counters line [RADIX_STATS] is written at debug level;
  5. the exporter's getter proxy_get_radix_stats walks the pools under the
     read lock and reports only pools whose radix is on, from one counters
     snapshot;
  6. no radix source names the balance guard "spread";
  7. the radix sources write no log (no request text can reach one).
Each check runs on the real files, then on a mutated copy where it must fail
(the check has teeth).
"""
import re
import sys

FILES = {
    "conv": "../kernel/loxilb_libdp.c",
    "http": "sockproxy_http.c",
    "ep": "sockproxy_ep.c",
    "h2": "sockproxy_h2.c",
    "health": "sockproxy_health.c",
    "metrics_h": "sockproxy_metrics.h",
    "cfg_h": "sockproxy_radix_cfg.h",
    "route_c": "sockproxy_radix_route.c",
    "route_h": "sockproxy_radix_route.h",
    "scan_c": "sockproxy_radix_scan.c",
    "trie_c": "sockproxy_radix.c",
}

ARGS = ("prefix_affinity_mode", "prefix_affinity_match_pct", "prefix_affinity_balance_abs")


def read(path):
    try:
        return open(path).read()
    except OSError:
        return None


def body_of(src, name):
    m = re.search(r"\n(?:static\s+)?(?:inline\s+)?[A-Za-z_][\w \*]*\n?%s\(" % re.escape(name), src)
    if not m:
        m = re.search(r"\n%s\(" % re.escape(name), src)
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


def check(f):
    errs = []
    if any(f[k] is None for k in FILES):
        return ["missing file(s): " + ", ".join(FILES[k] for k in FILES if f[k] is None)]

    # 1. the conversion
    conv = body_of(f["conv"], "llb_conv_nat2proxy") or ""
    for a in ARGS:
        if "pval->%s = dat->%s;" % (a, a) not in conv:
            errs.append("llb_conv_nat2proxy does not copy " + a)

    # 2. the three apply sites of proxy_add_entry
    add = body_of(f["http"], "proxy_add_entry") or ""
    call = "sp_radix_apply(tepval, arg)"
    r0 = add.find("HASH_FIND_STR(ent->val.ephash, ephash_key, tepval);")
    r1 = add.find('log_info("sockproxy : %s:%u (%s) updated"')
    refresh = add[r0:r1] if 0 <= r0 < r1 else ""
    if call not in refresh:
        errs.append("the refresh block does not apply the arguments")
    elif refresh.find(call) > refresh.rfind("PROXY_UNLOCK();"):
        errs.append("the refresh block applies the arguments after the unlock")
    if add.count(call) != 3:
        errs.append("proxy_add_entry applies the arguments %d times, not 3" % add.count(call))
    links = [m.start() for m in re.finditer(r"sp_pool_link\(", add)]
    calls = [m.start() for m in re.finditer(re.escape(call), add)]
    outside = [c for c in calls if not (r0 <= c < r1)]
    if len(links) != 2 or len(outside) != 2 or not all(c < l for c, l in zip(outside, links)):
        errs.append("a create path does not apply the arguments before linking the pool")

    # 3. one reader of the pointer
    active = None
    m = re.search(r"static inline radix_pool_t \*\s*\n?sp_radix_active\(", f["cfg_h"])
    if m:
        active = f["cfg_h"][m.start():f["cfg_h"].index("\n}", m.end()) + 2]
    if not active or active.count("__atomic_load_n(&") != 1 or "__ATOMIC_ACQUIRE" not in active \
            or "radix_pool_is_on(" not in active:
        errs.append("sp_radix_active is not one acquire load plus the on check")
    if "__atomic_store_n(&tepval->radix," not in f["cfg_h"] or "__ATOMIC_RELEASE" not in f["cfg_h"]:
        errs.append("sp_radix_apply does not publish the object with a release store")
    for k in ("ep", "h2", "http", "health"):
        for ln, line in enumerate(f[k].split("\n"), 1):
            code = line.split("//")[0]
            if re.search(r"->radix\b", code) and not code.lstrip().startswith("*"):
                errs.append("%s:%d reads ->radix outside sp_radix_active" % (FILES[k], ln))

    # 4. the counters line at debug level
    if 'log_debug("[RADIX_STATS]' not in f["health"]:
        errs.append("[RADIX_STATS] is not written at debug level")
    if re.search(r'log_(info|warn|err\w*)\("\[RADIX_STATS\]', f["health"]):
        errs.append("[RADIX_STATS] is still written above debug level")

    # 5. the exporter's getter
    getter = body_of(f["http"], "proxy_get_radix_stats") or ""
    for need in ("PROXY_RDLOCK()", "sp_radix_active(", "radix_pool_stats_read(", "PROXY_UNLOCK()"):
        if need not in getter:
            errs.append("proxy_get_radix_stats lacks " + need)
    if "proxy_get_radix_stats(" not in f["metrics_h"]:
        errs.append("proxy_get_radix_stats is not declared in sockproxy_metrics.h")

    # 6. the name
    for k in ("route_c", "route_h", "health", "cfg_h"):
        if re.search(r"spread", f[k], re.I):
            errs.append(FILES[k] + " still says spread")

    # 7. no log in the radix sources
    for k in ("route_c", "scan_c", "trie_c", "cfg_h"):
        if re.search(r"\blog_(debug|info|warn|err\w*|trace)\s*\(", f[k]):
            errs.append(FILES[k] + " writes a log")
    return errs


def main():
    f = {k: read(p) for k, p in FILES.items()}
    fails = 0
    errs = check(f)
    print("[%s] prefix-affinity argument wiring%s" % (
        "FAIL" if errs else "PASS", "".join("\n    " + e for e in errs)))
    fails += bool(errs)
    if errs:
        print("test_radix_cfg_wiring: FAIL (negative controls not run on a failing tree)")
        return 1

    def mut(key, old, new):
        m = dict(f)
        if old not in m[key]:
            return None
        m[key] = m[key].replace(old, new, 1)
        return m
    mutants = {
        "conversion drops the threshold":
            mut("conv", "pval->prefix_affinity_match_pct = dat->prefix_affinity_match_pct;", ""),
        "refresh block without the apply":
            (lambda a: mut("http", a[0], a[1]))(_refresh_drop(f["http"])),
        "a request path reads ->radix again":
            mut("ep", "sp_radix_active(tepval)", "tepval->radix"),
        "counters line back at info":
            mut("health", 'log_debug("[RADIX_STATS]', 'log_info("[RADIX_STATS]'),
        "getter reports pools with radix off":
            mut("http", "sp_radix_active(tepval)) == NULL", "tepval->radix) == NULL"),
        "guard named spread again":
            mut("route_c", '"balance"', '"spread"'),
        "a log call in the decision":
            mut("route_c", "static void rr_count(", "static void rr_count_(void){log_info(\"x\");}\nstatic void rr_count("),
    }
    for name, m in mutants.items():
        caught = m is not None and bool(check(m))
        print("[%s] negative control: %s" % ("PASS" if caught else "FAIL", name))
        fails += not caught
    print("test_radix_cfg_wiring: %s" % ("FAIL" if fails else "PASS"))
    return 1 if fails else 0


def _refresh_drop(http):
    """(old, new) that removes the refresh block's apply call only."""
    r0 = http.find("HASH_FIND_STR(ent->val.ephash, ephash_key, tepval);")
    i = http.find("sp_radix_apply(tepval, arg)", r0)
    if r0 < 0 or i < 0:
        return ("\0never\0", "")
    line0 = http.rfind("\n", 0, i)
    line1 = http.find("\n", i)
    return (http[line0:line1], "")


if __name__ == "__main__":
    sys.exit(main())
