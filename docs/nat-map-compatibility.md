# Map compatibility and matched builds

A BPF lookup has no destination-length argument. The kernel copies the live
map value size; per-CPU maps additionally return an aligned value for every
possible CPU. Static C size assertions cannot compare separately built objects.

## Startup contract

The loader requires NAT to exist and checks its actual descriptor against
`dp_nat_key` and `dp_proxy_tacts`. A missing map, failed inspection or mismatch
refuses initialization with exit status 1 and expected/live type and sizes.
It checks the per-map expected geometry table for the other maps userspace
reads into fixed buffers, including CT, IPv4/IPv6 firewall, interface, policer,
FC and per-CPU statistics maps, plus the fixed-size Go/CGO readers for IP
filtering, security configuration/counters, GPU stats and trace configuration.
The security/trace scalar arrays express the existing frozen Go wire layouts;
this change does not silently resize those mirrors. Auxiliary sockmap descriptors are checked before
publication too. Feature-disabled maps may be absent; a present map with an
incompatible declared geometry is never accepted as a substitute.

Direct userspace lookup sites were reviewed; the generic CT/FC walkers and fixed Go/CGO/auxiliary socket readers are covered by the table.
The slim profile's missing ct_err_stats remains a follow-up; its table entry is not weakened here.

Descriptor geometry is immutable. This one startup validation covers every
later access through that descriptor, including NAT delete's stack buffer and
NAT add's static `.bss` `oldv` buffer, which a stack protector cannot detect.
It runs before workers start or configuration is replayed. NAT operations do
not repeat compatibility checks or return new compatibility errors. Proxy-only
mode retains its no-eBPF behavior. Existing operation error/state semantics
are unchanged; the Gateway separately logs a native delete failure.

## Shared-header fingerprint

`gen_abi_fingerprint.py` hashes shared header paths and bytes in stable order,
excluding generated headers, skeletons and vmlinux. The generated identity also
encodes the presence of shared `HAVE_*` feature macros and MAX_REAL_CPUS as
seen by each compiler. Every BPF translation unit embeds it in its own
`.rodata.llbabi` global-data map. Userspace embeds the expected identity and
checks a bounded read from the live read-only data map at load. An absent,
malformed or unequal identity refuses initialization. The primary loader replaces its owned `llb_abi` alias once per process,
including upgrades over a persistent bpffs. The TC/XDP peer call leaves that
pin in place. Only no-loader consumers compare the existing alias.

`make all` runs `check_abi_identity` after the selected BPF/native artifacts
are built, comparing the native object/archive identity with every built BPF
object. A native-only feature flag therefore fails at build time. Python3 is
a build dependency. The generator alone owns the input exclusions; Make asks
its `--list-inputs` mode for prerequisites. Editing a shared header comment
also changes this identity and requires redeploying native and BPF together.
Map pin failure is fatal so an alias cannot advertise an incompletely pinned set.

The fingerprint detects shared-source/feature skew even when map sizes match.
It is a compatibility identity, not a signature or protection against a party
that deliberately forges an identity. A matched source/build/toolchain remains
the deployment unit; it does not prove arbitrary Go mirrors or external code
have compatible semantics. No map is automatically resized, migrated or deleted
to repair a mismatch. Existing pin ownership must be respected.

## Incremental builds

All BPF rules and the native archive object emit `-MMD -MP` dependency files.
A conservative shared-header prerequisite list also rebuilds the whole BPF/native
artifact set when upgrading a previously built tree without `.d` files, including
monitor/socket objects that do not directly include every dataplane header.
The userspace-only NAT guard header does not force BPF rebuilds. Clean removes
dependency files and the generated identity header.

Use a clean build when changing feature profiles/compiler options: Make does
not track arbitrary command-line flag changes. The runtime geometry/fingerprint
checks refuse a mismatched set instead of accepting stale incremental artifacts.

## Checks

`make -C kernel test_nat_map_abi` runs the production metadata helper normally
and under ASan/UBSan. `make -C kernel test_nat_map_abi_kernel` requires privileges
to create anonymous BPF maps; it checks matching data and incompatible map
geometry, array/hash/per-CPU types and invalid descriptors without existing pins.
The C unit workflow runs the privileged check on a standard sudo-capable runner.

On a fully built tree, `make -C kernel test_build_deps` preserves and restores
header timestamps while recording dry-run plans after touching `llb_dpapi.h`
and `llb_kern_cdefs.h`. Every selected BPF object, native object and archive must
be scheduled. This check needs the full dataplane build, generated skeleton and
common libraries, so it belongs with release-build qualification rather than the
small standalone C unit job. `--expect-gap` records the unpatched baseline gap.

Runtime qualification separately exercises a release-Dockerfile image's repeated
fullnat and fullproxy create/delete, native map and proxy rule-pool removal (the existing listener may stay open
to return 503 after its last pool is deleted),
persist/restore/delete, empty restore and graceful shutdown. Negative objects
must include wrong NAT/CT/FW geometry, missing NAT and equal-geometry fingerprint
skew. A REST DELETE success alone never proves asynchronous native cleanup.

IPv4 TCP/SCTP FULLPROXY add and delete share one predicate: these rules use
the native proxy and do not have a NAT row. Delete releases portsets and the
proxy pool and returns success without looking up a nonexistent NAT row.
IPv6 and other protocols retain the kernel NAT delete path.
