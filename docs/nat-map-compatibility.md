# NAT map compatibility and matched builds

A raw BPF lookup copies the live value size without a destination-length
argument. The loader now refuses a missing or incompatible NAT hash map
(type, key and value size) with exit 1 before workers/config replay. Geometry
is immutable for a descriptor, so one startup check covers all later accesses,
including delete's stack buffer and add's static .bss oldv buffer. No
per-operation compatibility failure is added. Proxy-only/no-eBPF behavior
is unchanged.

IPv4 TCP/SCTP FULLPROXY rules skip the NAT write in add. Delete uses the same
predicate, releases sockmap portsets and the native pool, and returns 0 instead
of looking up a nonexistent NAT row and returning EINVAL. IPv6 and other
protocols keep the kernel NAT path.

All eight BPF rules and the native object emit MMD/MP dependencies. A shared
header fence also covers previously built trees without .d files. Clean removes
all dependency files across profiles. The NAT-only userspace guard header does
not force BPF rebuilds. Use a clean build when changing compiler feature flags.

make -C kernel test_nat_map_abi runs normal and ASan/UBSan metadata checks.
make -C kernel test_nat_map_abi_kernel creates anonymous kernel maps and needs
privileges; the CI step uses sudo and pinned libbpf. On a fully built tree,
make -C kernel test_build_deps uses Python3 to preserve/restore timestamps and
verify all eight BPF objects, native object and archive rebuild after touching
llb_dpapi.h and llb_kern_cdefs.h. --expect-gap records the base defect. That
built-tree check requires the full dataplane/skeleton/common build and is not
part of the small C-unit job. Python3 is a test-only dependency at this layer;
ordinary native builds do not invoke it.
