#!/usr/bin/env bash
# The whole 4.3 gate: flows-check at the truth's pace and at 30 ms between
# steps must pass; with the tagger off (time windows only) it must fail,
# which shows the causal tracing is what passes it. Then the 4.3d gate:
# the driver asks jsharvest mcp after each step what it sent, with the
# guard off and on. With PLAYWRIGHT=1 it also runs the Playwright driver
# (needs Docker).
# A lane of testbed/regress.sh gives each gate its own server log and pid,
# and its own root for the work directories; alone, a gate uses bin/.
export TESTBED_LOG="${TESTBED_LOG:-bin/testbed.log}" TESTBED_PID="${TESTBED_PID:-bin/testbed.pid}" TESTBED_WORK="${TESTBED_WORK:-bin}"
cd "$(dirname "$0")/.." || exit 1
failed=0
run() { echo "== $1"; shift; testbed/flows-check.sh "$@" 2>&1 | grep -E "^(run|FAIL|WRONG|PROBLEM|USER|WATCH|GUARD|ENDPOINTS|flowscore|mcp:|MCP WRONG|drive failed)"; return "${PIPESTATUS[0]}"; }
run "paced" || failed=1
run "fast (30 ms)" 30 || failed=1
MCP=1 run "agent over MCP" || failed=1
MCP=1 GUARD=on run "agent over MCP, guard on" || failed=1
if [ "${PLAYWRIGHT:-}" = 1 ]; then
  DRIVER=playwright run "playwright" || failed=1
fi
if run "time windows only (must fail)" -1 -flow-tag=false >/dev/null; then
  echo "time windows alone passed the gate: the gate no longer tells causal tracing apart"
  failed=1
else
  echo "== time windows only: failed, as it must"
fi
[ "$failed" = 0 ] && echo "flows gate: ok"
exit "$failed"
