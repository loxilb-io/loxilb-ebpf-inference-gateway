#!/bin/sh
set -eu

object=${1:-llb_ebpf_main.o}
objdump=${LLVM_OBJDUMP:-llvm-objdump}

if ! command -v "$objdump" >/dev/null 2>&1; then
  echo "L4 trace helper compatibility: FAIL ($objdump not found)" >&2
  exit 1
fi

if [ ! -s "$object" ]; then
  echo "L4 trace helper compatibility: FAIL ($object missing or empty)" >&2
  exit 1
fi

for marker in L4_TRACE_SAMPLE L4_TRACE_EMIT; do
  if ! strings "$object" | grep -q "$marker"; then
    echo "L4 trace helper compatibility: FAIL ($marker absent; trace/debug object required)" >&2
    exit 1
  fi
done

if "$objdump" -d "$object" | grep -Eq 'call[[:space:]]+(177|0xb1)([[:space:]]|$)'; then
  echo "L4 trace helper compatibility: FAIL (unsupported helper 177 present)" >&2
  exit 1
fi

echo "L4 trace helper compatibility: PASS (trace markers present, helper 177 absent)"
