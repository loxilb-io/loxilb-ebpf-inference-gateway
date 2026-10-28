#!/bin/bash
# Mount the cgroup2 hierarchy loxilb attaches its sockops/sockmap programs to.
#
# The decision is made on the MOUNT STATE of the path, never on whether the
# directory exists: a restarted container keeps its writable layer (so the
# directory created by the previous boot is still there) but gets a fresh mount
# namespace (so the cgroup2 mount is gone). The mount result is the exit code,
# so the caller can tell a skipped mount from a failed one.
#
# With an argument (the daemon's own call, inside its container): mount only
# when cgroup2 is not already there - a hostPath-mounted hierarchy from the
# no-argument branch below is left alone.
# Without an argument (host-side bootstrap, e.g. the k3s initContainer via
# nsenter): always remount, so the hierarchy is a fresh one.
CG=/opt/loxilb/cgroup
OPTS=rw,relatime,nsdelegate,memory_recursiveprot

is_cg2() { [ "$(stat -f -c %T "$CG" 2>/dev/null)" = "cgroup2fs" ]; }

mkdir -p "$CG" || exit 1
if [ "$#" -ne 0 ]; then
  is_cg2 && exit 0
  exec mount -t cgroup2 -o "$OPTS" cgroup2 "$CG"
fi
is_cg2 && umount "$CG"
exec mount -t cgroup2 -o "$OPTS" cgroup2 "$CG"
