#!/bin/sh
# Source invariant: every arming of a proxy connection's fd goes through
# sp_notify_arm() (sockproxy_hold.c).
#
# A client held open after its FIN has its read side at EOF, so its socket
# reports POLLIN and POLLRDHUP, level-triggered, for as long as it is armed for
# them; armed that way it re-enters the EOF handling on every poll. The helper
# is the one place that knows not to. A rule kept by convention at a list of
# call sites does not hold - such a list has leaked before - so the build
# checks it: outside the helper, nothing calls notify_add_ent( directly.
#
# The token is matched exactly. notify_add_ent_pinned( (a backend leg pinned to
# its client's worker) and notify_add_ent_listener( (a listener) are other
# primitives and never arm a client fd.
#
# Not scanned: the notifier's own module (notify.c/.h, which defines it) and
# unit tests (test_*.c, which exercise the notifier directly).
# The one allowed call: the helper's body in sockproxy_hold.c, exactly once.
#
#   sh check_notify_arm.sh    (from anywhere; exit 1 on a violation)
set -eu
cd "$(dirname "$0")"

pat='(^|[^A-Za-z0-9_])notify_add_ent\('
files=$(ls ./*.c ./*.h | grep -vE '^\./(notify\.[ch]|test_[^/]*\.c)$')

bad=$(grep -nE "$pat" $files | grep -v '^\./sockproxy_hold\.c:' || true)
helper=$(grep -cE "$pat" ./sockproxy_hold.c || true)

if [ -n "$bad" ]; then
  echo "direct notify_add_ent( outside sp_notify_arm (use sp_notify_arm):"
  echo "$bad"
  exit 1
fi
if [ "$helper" != "1" ]; then
  echo "sockproxy_hold.c must call notify_add_ent( exactly once (the helper body); found $helper"
  exit 1
fi
echo "notify arming: OK (one direct call, in sp_notify_arm)"
