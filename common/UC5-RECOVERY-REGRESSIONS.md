# UC-5 recovery regressions

A concurrent gateway on the same Linux bridge could reflect an unchanged
foreign unicast frame through the interface on which it arrived. A learned
neighbor DMAC selected `DP_SET_RM_L2VLAN`, including for untagged traffic. The
upstream bridge then learned the original sender's MAC on the reflecting
container's veth. SYN/ACK and backend responses were misdelivered, causing TCP
retransmissions, five-second client timeouts, and `backend_unreachable` despite
healthy direct backend probes. This surfaced after database recovery and key
policy changes; neither operation was itself the proven cause of packet loss.

`dp_do_dmac_lkup` now applies split horizon to unchanged same-interface L2
forwarding. Local L3 ownership, NAT or next-hop processing, tunnel processing,
and actual VLAN translation retain their existing forwarding behavior. The
check covers direct-port and VLAN DMAC actions. It does not change explicit
firewall redirects, mirror/rewire actions, or transport deadlines.

Terminal admission responses now include their exact `Content-Length`, retaining
existing status, JSON, `Retry-After`, bounded transport send, and shutdown
behavior. This makes a complete denial independent of a delayed FIN. The prior
close-delimited response was legal HTTP; missing `Content-Length` alone was not
the root cause of the bridge failure.

## Reproduce and verify

On Linux with the build dependencies installed:

```sh
make -C common test_uc5
```

This runs the admission-response, stream, UC-3 model/SNI/SSE/framing, and L2
split-horizon regressions. The admission test covers every byte split for six
statuses and four retry/body variants, exact body/header lengths, truncated
body rejection, and output overflow. The L2 test exhausts VLAN IDs and routing,
NAT, tunnel, different-port, and VLAN-translation exemptions. New C tests run
with AddressSanitizer and UndefinedBehaviorSanitizer.

For the actual installed TC pipeline, use an isolated gateway container, an
already learned same-interface neighbor, and a source address belonging to the
lab. The host needs root, Docker, `nsenter`, and `ip`; the container needs
`bpftool`. This reads maps and invokes `BPF_PROG_TEST_RUN`, without changing FDB,
routes, or policies:

```sh
python3 common/test_l2_reflection_kernel.py \
  --container "$TEST_GATEWAY" --neighbor-ip "$TEST_BACKEND_IP" \
  --source-ip "$TEST_CLIENT_IP"
```

Expected: foreign frame returns `TC_ACT_SHOT=2`; a packet addressed to the local
MAC but routed to that neighbor returns `TC_ACT_REDIRECT=7` and changes its source
MAC. Against the unpatched base, use `--expect-foreign 7` to verify the red twin.
Only temporary files created by this tool are removed.

## Observed author verification

Ubuntu 24.04.1, kernel 6.8.0-124, Gateway main content at `290a764d`, eBPF base
`f054ddd5` plus this patch, CLI `28832f0c`:

- Identical real-kernel replay: unpatched foreign frame redirects; patched frame
  drops; routed hairpin redirects with source-MAC rewrite in both versions.
- Concurrent peer retained, then original neighbor learning recreated: two
  30-request series complete with HTTP 200 inside the unchanged five-second
  bound. No static FDB entries or test-network workaround were introduced.
- Fresh recovery lab: RPS-clear 30/30 HTTP 200; disabled key 20/20 HTTP 401 with
  zero backend receipts, all curl exits zero inside five seconds.
- Burst: 2 accepted and 10 rate-limited requests; rejected backend receipts zero.
- Full recovery, restart, recreation, replacement, failed dependency restore,
  corruption quarantine, DB recovery, effective TLS rejection, REST/CLI deletion,
  and image rollback: 181 evidence assertions pass.

These are author observations with mock backends, not independent QA, release
qualification, certification, or real-model performance results. Original
failed packet captures and private runtime evidence remain outside Git.
