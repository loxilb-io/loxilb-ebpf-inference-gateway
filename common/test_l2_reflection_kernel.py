#!/usr/bin/env python3
# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
"""Replay foreign unicast and a routed hairpin through an installed TC program.

Requires root on Linux, Docker, nsenter, ip, and bpftool in the test container.
The neighbor must already be reachable on the same interface. This reads maps
and uses BPF_PROG_TEST_RUN; it does not rewrite maps, FDB, routes or policies.
"""
import argparse
import ipaddress
import json
import struct
import subprocess
import tempfile
from pathlib import Path


def output(*args):
    return subprocess.check_output(args, text=True)


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def packet(dst_mac, src, dst):
    src_ip = ipaddress.IPv4Address(src).packed
    dst_ip = ipaddress.IPv4Address(dst).packed
    tcp = struct.pack("!HHIIBBHHH", 49191, 32499, 1, 0, 0x50, 2, 4096, 0, 0)
    pseudo = src_ip + dst_ip + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0, src_ip, dst_ip)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return dst_mac + bytes.fromhex("0200000000990800") + ip + tcp


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", required=True)
    parser.add_argument("--neighbor-ip", required=True)
    parser.add_argument("--source-ip", required=True)
    parser.add_argument("--interface", default="eth0")
    parser.add_argument("--expect-foreign", type=int, default=2,
                        help="TC_ACT_SHOT=2 for fixed image; TC_ACT_REDIRECT=7 for red twin")
    args = parser.parse_args()
    pid = json.loads(output("docker", "inspect", args.container))[0]["State"]["Pid"]
    if not pid:
        raise RuntimeError("test container is not running")
    net = json.loads(output("docker", "exec", args.container, "bpftool", "-j", "net", "show"))[0]
    hook = next(x for x in net["tc"] if x["devname"] == args.interface and
                x["kind"] == "clsact/ingress")
    neighbors = json.loads(output("nsenter", "-t", str(pid), "-n", "ip", "-j", "neigh", "show"))
    neighbor = next(x for x in neighbors if x.get("dst") == args.neighbor_ip and
                    x.get("dev") == args.interface and x.get("lladdr"))
    neighbor_mac = bytes.fromhex(neighbor["lladdr"].replace(":", ""))
    maps = json.loads(output("docker", "exec", args.container, "bpftool", "-j", "map", "dump",
                             "pinned", "/opt/loxilb/dp/bpf/dmac_map"))
    if not any(bytes(x["formatted"]["key"]["dmac"]) == neighbor_mac for x in maps):
        raise RuntimeError("neighbor is not in the dataplane DMAC map; learn it before replay")
    local = output("docker", "exec", args.container, "cat",
                   "/sys/class/net/" + args.interface + "/address").strip()
    local_mac = bytes.fromhex(local.replace(":", ""))
    with tempfile.TemporaryDirectory(prefix="uc5-l2-replay-") as directory:
        root = Path(directory)
        ctx = bytearray(192)
        struct.pack_into("<II", ctx, 36, hook["ifindex"], hook["ifindex"])
        (root / "ctx").write_bytes(ctx)
        remote = "/tmp/" + root.name
        subprocess.run(["docker", "exec", args.container, "mkdir", "-m", "700", remote], check=True)
        try:
            subprocess.run(["docker", "cp", str(root / "ctx"), args.container + ":" + remote + "/ctx"], check=True)
            for name, mac, expected in [("foreign", neighbor_mac, args.expect_foreign),
                                        ("routed", local_mac, 7)]:
                wire = packet(mac, args.source_ip, args.neighbor_ip)
                (root / name).write_bytes(wire)
                subprocess.run(["docker", "cp", str(root / name), args.container + ":" + remote + "/" + name], check=True)
                result = json.loads(output("docker", "exec", args.container, "bpftool", "-j", "prog", "run",
                                           "id", str(hook["id"]), "data_in", remote + "/" + name,
                                           "ctx_in", remote + "/ctx", "data_out", remote + "/out", "repeat", "1"))
                if result["retval"] != expected:
                    raise AssertionError(f"{name}: expected {expected}, got {result['retval']}")
                if name == "routed":
                    subprocess.run(["docker", "cp", args.container + ":" + remote + "/out", str(root / "out")], check=True)
                    if (root / "out").read_bytes()[6:12] == wire[6:12]:
                        raise AssertionError("routed hairpin did not rewrite source MAC")
                print(json.dumps({"case": name, "retval": result["retval"], "pass": True}))
        finally:
            subprocess.run(["docker", "exec", args.container, "rm", "-f", remote + "/ctx",
                            remote + "/foreign", remote + "/routed", remote + "/out"], check=True)
            subprocess.run(["docker", "exec", args.container, "rmdir", remote], check=True)


if __name__ == "__main__":
    main()
