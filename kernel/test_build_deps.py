#!/usr/bin/env python3
"""Inspect a built tree without compiling or installing. Restore touched times."""

import argparse
import os
import re
import subprocess
import time
from pathlib import Path


def build_plan(kernel_dir, objects):
    targets = objects + ["libloxilbdp.a"]
    result = subprocess.run(
        ["make", "--no-print-directory", "-n", *targets],
        cwd=kernel_dir,
        text=True,
        capture_output=True,
    )
    if result.returncode:
        raise SystemExit(result.stdout + result.stderr)
    print(result.stdout, end="")
    scheduled = {
        name for name in objects
        if re.search(r"-o\s+" + re.escape(name) + r"(?:\s|$)", result.stdout)
    }
    if re.search(r"ar\s+\w+\s+libloxilbdp\.a", result.stdout):
        scheduled.add("libloxilbdp.a")
    return scheduled


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--expect-gap", action="store_true")
    args = parser.parse_args()
    kernel_dir = Path(__file__).resolve().parent
    objects = [
        "llb_xdp_main.o", "llb_ebpf_main.o", "llb_ebpf_emain.o", "llb_kern_mon.o",
        "llb_kern_sock.o", "llb_kern_sockmap.o", "llb_kern_sockstream.o",
        "llb_kern_sockdirect.o", "loxilb_libdp.o",
    ]
    if os.environ.get("HAVE_DP_DPU_SLIM") or os.environ.get("HAVE_DP_DPU_BF3"):
        objects.remove("llb_xdp_main.o")
    targets = objects + ["libloxilbdp.a"]
    for name in targets:
        if not (kernel_dir / name).is_file():
            raise SystemExit("Requires a fully built tree: missing " + name)
    print("BEFORE shared-header touch")
    before = build_plan(kernel_dir, objects)
    if before - {"libloxilbdp.a"}:
        raise SystemExit("Objects are not up to date before inspection: " + str(sorted(before)))
    for header in ["../common/llb_dpapi.h", "llb_kern_cdefs.h"]:
        path = kernel_dir / header
        original = path.stat()
        try:
            timestamp = max(
                time.time_ns(),
                max((kernel_dir / target).stat().st_mtime_ns for target in targets)
                + 2_000_000_000,
            )
            os.utime(path, ns=(original.st_atime_ns, timestamp))
            print("AFTER touch " + header)
            scheduled = build_plan(kernel_dir, objects)
            missing = set(targets) - scheduled
            print("SCHEDULED", sorted(scheduled), "MISSING", sorted(missing))
            if args.expect_gap:
                if not missing:
                    raise SystemExit("Expected baseline dependency gap was absent")
            elif missing:
                raise SystemExit("Shared-header rebuild gap: " + str(sorted(missing)))
        finally:
            os.utime(path, ns=(original.st_atime_ns, original.st_mtime_ns))
    message = (
        "baseline gap demonstrated" if args.expect_gap
        else "all BPF/native/archive shared-header rebuilds scheduled"
    )
    print("PASS: " + message)


if __name__ == "__main__":
    main()
