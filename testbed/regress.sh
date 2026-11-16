#!/usr/bin/env bash
# The whole regression, in lanes: the unit tests, then every gate, each
# lane in a network namespace of its own (unshare), so that each has its
# own 127.0.0.1:8770 and its own Chrome debugging ports, with no change to
# the gates' URLs. A lane takes the longest gate left; gates in a lane run
# one after the other. Each lane has its own server log and pid and its own
# work root (bin/regress/laneN); the binaries are built once, before.
# Without unprivileged namespaces it runs the gates one after the other.
#   docker-check needs the network: only with DOCKER=1, after the lanes.
# Usage: testbed/regress.sh [-j LANES] [gate...]   (default: 3 lanes, every gate)
#   Logs: bin/regress/<gate>.log; summary: bin/regress/results.txt.
set -uo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
. "$root/testbed/lib/env.sh"
ensure_go_in_path || exit 1
dir=bin/regress

# Longest first (minutes, measured 2026-11-05): a lane that starts the
# long ones early keeps the whole short.
all=(frontier-tabs-check explore-check flows-gate session-check parallel-check bench export-check roles-check replay-check
  attach-guard lan-check frontier-check archive-check endpoints-check monitor-check waf-check pipeline-check crosscheck-check verify-check proxy-check webrtc-check bola-check)

gate_cmd() { # gate -> runs it
  case "$1" in
    bench) GATE=1 TOOLS=jsharvest testbed/bench.sh ;;
    *) "testbed/$1.sh" ;;
  esac
}

# A lane, inside its namespace: pop gates off the queue until it is empty.
if [ "${1:-}" = "--lane" ]; then
  n=$2
  export TESTBED_WORK="$dir/lane$n" TESTBED_LOG="$dir/lane$n/testbed.log" TESTBED_PID="$dir/lane$n/testbed.pid" TESTBED_NO_BUILD=1
  mkdir -p "$TESTBED_WORK"
  ip link set lo up 2>/dev/null || true
  while :; do
    g=$(flock "$dir/queue.lock" sh -c '
      IFS= read -r first <"$1" || exit 0
      printf "%s\n" "$first"
      tail -n +2 "$1" >"$1.tmp" && mv "$1.tmp" "$1"
    ' _ "$dir/queue")
    [ -z "$g" ] && break
    start=$(date +%s)
    timeout 3000 bash -c "$(declare -f gate_cmd); gate_cmd $g" >"$dir/$g.log" 2>&1
    code=$?
    echo "$g $code $(($(date +%s) - start)) lane$n" >>"$dir/results.txt"
    echo "  $g: $([ "$code" = 0 ] && echo ok || echo "FAIL (exit $code)") in $(($(date +%s) - start)) s (lane $n)"
  done
  exit 0
fi

lanes=3
if [ "${1:-}" = "-j" ]; then
  lanes=$2
  shift 2
fi
gates=("$@")
[ ${#gates[@]} -eq 0 ] && gates=("${all[@]}")

require_cmds jq flock curl python3 timeout awk || exit 1
require_built_apps "$root" || exit 1

began=$(date +%s)
rm -rf "$dir"
mkdir -p "$dir"
echo "== build"
go build -o bin/jsharvest ./cmd/jsharvest && go build -o bin/testbed ./testbed/cmd/testbed || exit 1
echo "== unit tests (in the background)"
(t=$(date +%s); go test -race ./cmd/... ./internal/... >"$dir/unit.log" 2>&1; echo "unit $? $(($(date +%s) - t)) host" >>"$dir/results.txt") &
unit=$!
printf '%s\n' "${gates[@]}" >"$dir/queue"

if unshare -rn true 2>/dev/null; then
  echo "== ${#gates[@]} gates in $lanes lanes"
  uid=$(id -u) gid=$(id -g)
  pids=()
  for n in $(seq 1 "$lanes"); do
    # Root in the first namespace, to bring lo up; then back to our own
    # uid, as Chrome will not run as root without --no-sandbox.
    unshare -rn bash -c "ip link set lo up && exec unshare --user --map-user=$uid --map-group=$gid bash testbed/regress.sh --lane $n" &
    pids+=($!)
  done
  wait "${pids[@]}"
else
  echo "== ${#gates[@]} gates one after the other (no unprivileged network namespaces)"
  bash testbed/regress.sh --lane 1
fi
wait "$unit"
if [ -n "${DOCKER:-}" ]; then
  echo "== docker-check"
  start=$(date +%s)
  NO_BUILD="${NO_BUILD:-}" testbed/docker-check.sh >"$dir/docker-check.log" 2>&1
  echo "docker-check $? $(($(date +%s) - start)) host" >>"$dir/results.txt"
fi

echo "== results ($(($(date +%s) - began)) s in all)"
sort -k3 -n -r "$dir/results.txt" | awk '{printf "  %-16s %-5s %4ss  %s\n", $1, ($2 == 0 ? "ok" : "FAIL"), $3, $4}'
failed=$(awk '$2 != 0' "$dir/results.txt")
missing=$(for g in "${gates[@]}" unit; do grep -q "^$g " "$dir/results.txt" || echo "$g"; done)
[ -n "$missing" ] && echo "not run: $missing"
if [ -n "$failed" ] || [ -n "$missing" ]; then
  echo "regress: FAILED (logs: $dir/<gate>.log)"
  exit 1
fi
echo "regress: ok"
