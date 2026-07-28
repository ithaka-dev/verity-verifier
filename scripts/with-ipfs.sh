#!/usr/bin/env bash
# Run a command with a local IPFS node available, and only for as long as it takes.
#
# The daemon is a test dependency, not a background service. Leaving one running between test runs
# means the suite passes against state nobody can reproduce — and a fetch test that silently
# skipped would look identical to one that passed.
#
#   scripts/with-ipfs.sh cargo test --features fetch
#
# If a daemon is already running this defers to it and leaves it alone, so a developer who keeps
# one up is not fought with.

set -euo pipefail

API="${IPFS_API:-http://127.0.0.1:5001}"
GATEWAY="${IPFS_GATEWAY:-http://127.0.0.1:8080}"
STARTED_BY_US=0
DAEMON_PID=""

daemon_up() { curl -fsS -X POST "$API/api/v0/id" >/dev/null 2>&1; }

cleanup() {
  if [ "$STARTED_BY_US" -eq 1 ] && [ -n "$DAEMON_PID" ]; then
    echo "→ stopping IPFS daemon (pid $DAEMON_PID)" >&2
    kill "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

if ! command -v ipfs >/dev/null 2>&1; then
  echo "→ ipfs not installed; fetch tests will skip" >&2
elif daemon_up; then
  echo "→ using the IPFS daemon already running at $API" >&2
else
  [ -d "${IPFS_PATH:-$HOME/.ipfs}" ] || ipfs init >/dev/null 2>&1
  # --offline: these tests serve content the test itself added. Reaching the public swarm would
  # make them slower, non-deterministic, and dependent on someone else's network.
  ipfs daemon --offline >/tmp/verity-ipfs-daemon.log 2>&1 &
  DAEMON_PID=$!
  STARTED_BY_US=1
  for _ in $(seq 1 40); do daemon_up && break; sleep 0.25; done
  if daemon_up; then
    echo "→ started IPFS daemon (pid $DAEMON_PID, offline)" >&2
  else
    echo "→ IPFS daemon failed to start; see /tmp/verity-ipfs-daemon.log" >&2
  fi
fi

IPFS_API="$API" IPFS_GATEWAY="$GATEWAY" "$@"
