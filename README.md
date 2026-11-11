[![eBPF Emerging Project](https://img.shields.io/badge/ebpf.io-Emerging--Project-success)](https://ebpf.io/projects#loxilb) ![gpl](https://img.shields.io/badge/license-GPL-blue.svg)  ![bsd](https://img.shields.io/badge/license-BSD-blue.svg)

## This README is here for anyone who wants to build loxilb ebpf only modules

## Install Dependencies

sudo apt install clang llvm libelf-dev gcc-multilib libpcap-dev  
sudo apt install linux-tools-$(uname -r)  
sudo apt install elfutils dwarves  

## Build libbpf

cd libbpf/src  
sudo make install  
sudo ldconfig  

## Build loxilb ebpf

cd -   
make  

## Native prefill/decode request bounds

Bodyless HTTP/1 requests on a P/D rule use the first healthy decode endpoint in
programmed pool order. Connection retries stay within the decode role. These
requests take ordinary service/endpoint admission units and no prefill/decode
role units or P/D load reservations. No usable decode produces
`503 pd_pool_unavailable`.

Native P/D bodies must be fully buffered. The default byte limit is 786432
(768 KiB). Set `LLB_PD_MAX_BODY_BYTES` before starting the daemon to a positive
integer up to 786432 to lower it. Unset, invalid, zero, or larger values use the
default. The setting is read once per process and logged at daemon startup. Oversized bodies produce
`413 pd_body_too_large` with `max_body_bytes`. Streamed and chunked bodies
produce `413 pd_body_unbufferable` before a backend is connected. Bodies require
a JSON Content-Type. Non-JSON bodies of any size produce
`415 pd_body_unsupported_media`, even if another header mentions JSON.
JSON bodies up to the configured limit retain native P/D handling.
All dialects prepare before connecting either role. Rewrite or allocation
failure produces `500 pd_prepare_failed` and returns the reserved P/D and
admission units.

This native P/D policy applies to HTTP/1 only. HTTP/2 follows a separate
bridge path. HTTP/1 pipelining is refused with
`400 pd_pipelining_unsupported`. Sequential keep-alive requests reselect
their roles for every request.

These rules apply to the native P/D ladder and EPP FailOpen. An explicit EPP
endpoint decision and an L7 FORWARD route use their own forwarding contract.

Run `make -C common test_pd_request_limit` for environment-limit coverage. The
gateway EPP datapath lane covers bodyless routing, in-flight role capacity,
bounded bodies, and refusal before backend traffic.

## MCP 2026-07-28 FullProxy dataplane

The Gateway may explicitly enable `mcp_stateless` in the existing proxy action ABI for a TCP FullProxy listener. All aliases on that listener must use the same mode. The Gateway API exposes this as `mcp_protocol_version: "2026-07-28"`; omission retains the legacy behavior. Modern requests are validated before per-request RR/WRR selection. Sockmap must remain disabled for this listener.

The modern path accepts bounded POST bodies (768 KiB), validates mirrored method/name/version metadata, and rejects request trailers and HTTP/1 pipelining. Frontend HTTP/2 can relay to HTTP/1 backends with per-stream upstream connections and a limit of 32 bridge slots per frontend connection. Configured FC admission and endpoint-return warmup apply to modern requests, with L7 route membership retained during capacity fallback. These bounds are product implementation limits rather than an assertion of full MCP SDK conformance.

Run the validator, capture, weighted-selection and actual response-callback sanitizer regressions with:

```sh
make -C common test_mcp
```

The dependent Gateway repository contains independent backend fixtures and real HTTP/TLS/HTTP2 runtime checks under `cicd/mcp-stateless`. Run those against an image built from this exact dataplane and the matching Gateway source; portable tests alone do not qualify installed behavior.

## NAT map compatibility

Startup refuses a missing or incompatible NAT map before userspace workers
or configuration replay. Shared-header dependency files keep incremental BPF
and native artifacts aligned. See [the compatibility contract](docs/nat-map-compatibility.md)
for tests and matched-build requirements.

The startup geometry table additionally protects other fixed-buffer native
and Go/CGO map readers, including CT/FW and auxiliary socket maps.
