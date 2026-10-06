#!/bin/sh
# Source invariant: a client kept open after its FIN has its read side shut,
# never its write side (sp_client_eof_keep, sockproxy_hold.c).
#
# A client that half-closed after a complete request is kept so its answer can
# still reach it: deferred to the sweep where the kernel carries the response
# direction, or held where the proxy relays the answer itself. Both ways shut
# the read side only. A SHUT_RDWR there raises POLLHUP at once; the dispatch
# tears the connection down on it, and the answer goes with it. Both bodies are
# in the one function so the build can count what they do: inside it, no
# SHUT_RDWR, and exactly the two read-side shutdowns.
#
#   sh check_client_eof_keep.sh    (from anywhere; exit 1 on a violation)
set -eu
cd "$(dirname "$0")"

fn=sp_client_eof_keep
defs=$(grep -c "^$fn(" ./sockproxy_hold.c || true)
if [ "$defs" != "1" ]; then
  echo "sockproxy_hold.c must define $fn( exactly once at the start of a line; found $defs"
  exit 1
fi

# The function's text: from its name at the start of a line to the first
# closing brace at the start of a line after it.
body=$(awk -v fn="$fn(" 'index($0, fn) == 1 {on = 1} on {print} on && /^}/ {exit}' ./sockproxy_hold.c)

rdwr=$(printf '%s\n' "$body" | grep -c 'SHUT_RDWR' || true)
rd=$(printf '%s\n' "$body" | grep -cE 'shutdown\(pfe->fd, SHUT_RD\)' || true)

if [ "$rdwr" != "0" ]; then
  echo "$fn shuts a client's write side (SHUT_RDWR) - the answer it is kept for goes with it:"
  printf '%s\n' "$body" | grep -n 'SHUT_RDWR'
  exit 1
fi
if [ "$rd" != "2" ]; then
  echo "$fn must shut the read side once in each of its two ways (shutdown(pfe->fd, SHUT_RD)); found $rd"
  exit 1
fi
echo "client EOF keep: OK (read side only, in both ways)"
