#!/usr/bin/env bash
# Starts or stops the testbed server in the background, tracked by a pidfile.
# Usage: testbed/run.sh start <app> [addr] | testbed/run.sh stop
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
pidfile="$root/${TESTBED_PID:-bin/testbed.pid}"
logfile="$root/${TESTBED_LOG:-bin/testbed.log}"

case "${1:-}" in
  start)
    "$0" stop
    nohup "$root/bin/testbed" serve -app "$root/testbed/apps/$2" -addr "${3:-127.0.0.1:8770}" >"$logfile" 2>&1 &
    echo $! >"$pidfile"
    sleep 0.5
    echo "testbed $2 running (pid $(cat "$pidfile")), log: $logfile"
    ;;
  stop)
    if [ -f "$pidfile" ]; then
      kill "$(cat "$pidfile")" 2>/dev/null || true
      rm -f "$pidfile"
    fi
    ;;
  *)
    echo "usage: $0 start <app> [addr] | stop" >&2
    exit 2
    ;;
esac
