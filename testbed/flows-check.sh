#!/usr/bin/env bash
# The 4.3 gate: jsharvest watches a tab of a running Chrome while a driver
# works through flows-app's features over CDP, as Playwright or an AI agent
# would; then flowscore checks every request landed under the right action,
# and every endpoint seen is one the scripts call (4.3b).
# Usage: testbed/flows-check.sh [pause_ms] [extra watch flags...]
#   pause_ms defaults to the truth file's; 30 is the fast run.
#   DRIVER=playwright drives with testbed/playwright/flows.mjs instead, in
#   a node:22-alpine container (needs Docker, and the network once to
#   install playwright-core).
#   MCP=1 makes the driver ask jsharvest mcp, after each step, what the step
#   sent (the 4.3d gate). GUARD=on runs the watch with the guard: with MCP=1
#   the check is then of the writes, and of blocked.
# Exit 1 when the score is below the gate or the user's tab was closed.
set -uo pipefail
# The browser engine: these gates test what Chrome sees (crawl -engine auto
# would take the HTTP engine for anon).
export JSHARVEST_ENGINE="${JSHARVEST_ENGINE:-cdp}"
# A lane of testbed/regress.sh gives each gate its own server log and pid,
# and its own root for the work directories; alone, a gate uses bin/.
export TESTBED_LOG="${TESTBED_LOG:-bin/testbed.log}" TESTBED_PID="${TESTBED_PID:-bin/testbed.pid}" TESTBED_WORK="${TESTBED_WORK:-bin}"
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
. "$root/testbed/lib/env.sh"
ensure_go_in_path || exit 1
CHROME_BIN="$(find_chrome)" || exit 1
build_testbed_bins || exit 1
pause="${1:--1}"
shift || true
work=${TESTBED_WORK}/flows-check
rm -rf "$work"
mkdir -p "$work/profile"
port=9333
app=testbed/apps/flows-app

./testbed/run.sh start flows-app >/dev/null
"$CHROME_BIN" --headless=new --remote-debugging-port=$port --user-data-dir="$work/profile" --no-first-run about:blank >"$work/chrome.log" 2>&1 &
chrome=$!
watch=""
cleanup() {
  [ -n "$watch" ] && kill "$watch" 2>/dev/null
  kill "$chrome" 2>/dev/null
  ./testbed/run.sh stop
}
trap cleanup EXIT
sleep 2

guard="${GUARD:-off}"
./bin/jsharvest watch -attach "http://127.0.0.1:$port" -open http://127.0.0.1:8770/ -guard "$guard" -o "$work/out" "$@" >"$work/watch.log" 2>&1 &
watch=$!
for _ in $(seq 50); do
  grep -q "watching" "$work/watch.log" && break
  sleep 0.2
done
sleep 2 # the page's load and its first background requests
if [ "${DRIVER:-}" = playwright ]; then
  docker run --rm --network host -u "$(id -u):$(id -g)" -e HOME=/tmp -v "$root:/w" -w /w/testbed/playwright node:22-alpine \
    sh -c "[ -d node_modules/playwright-core ] || npm install --no-audit --no-fund >/dev/null; node flows.mjs /w/$app/flows.truth.json /w/$work/steps.jsonl http://127.0.0.1:$port" \
    >"$work/drive.log" 2>&1 || { echo "playwright failed:"; tail -5 "$work/drive.log"; exit 1; }
else
  ask=()
  if [ -n "${MCP:-}" ]; then
    ask=(-mcp "./bin/jsharvest mcp -o $work/out")
    [ "$guard" = on ] && ask+=(-mcp-guard)
  fi
  ./bin/testbed drive -cdp "http://127.0.0.1:$port" -tab '127\.0\.0\.1:8770' -steps "$app/flows.truth.json" -log "$work/steps.jsonl" -pause "$pause" "${ask[@]}" >"$work/drive.log" 2>&1 || {
    echo "drive failed:"; grep -E "^mcp|MCP WRONG" "$work/drive.log"; tail -3 "$work/drive.log"; exit 1
  }
  [ -n "${MCP:-}" ] && grep -E "^mcp:" "$work/drive.log"
fi
sleep 3 # the last step's requests
kill -INT "$watch"
wait "$watch"
code=$?
watch=""

failed=0
if [ "$code" != 0 ]; then
  echo "WATCH FAILED: exit $code"; tail -3 "$work/watch.log"
  failed=1
fi
if ! curl -s "http://127.0.0.1:$port/json/list" | grep -q '127.0.0.1:8770'; then
  echo "USER TAB CLOSED by the watch"
  # What there is instead, and how the watch ended, for the next time.
  curl -s "http://127.0.0.1:$port/json/list" | jq -c '[.[] | {type, url}]' | sed 's/^/  tabs: /'
  grep -E "watch stopped|ERROR|WARN" "$work/watch.log" | tail -5 | sed 's/^/  watch: /'
  cp -r "$work" "$work.failed-$(date +%s)" 2>/dev/null
  failed=1
fi
scoreflags=()
[ "$guard" = on ] && scoreflags=(-guard)
./bin/testbed flowscore -truth "$app/flows.truth.json" -steps "$work/steps.jsonl" -out "$work/out/127.0.0.1/anon" "${scoreflags[@]}" || failed=1
if [ "$guard" = on ] && [ -s "$work/out/127.0.0.1/anon/requests.jsonl" ]; then
  # Every write of the truth is held back.
  writes=$(jq -r '.steps[].expect // [] | .[] | select(startswith("GET ") | not)' "$app/flows.truth.json" | wc -l)
  held=$(jq -r 'select(.outcome | startswith("held_back")) | select(.url | test("/api/analytics") | not) | .id' "$work/out/127.0.0.1/anon/requests.jsonl" | wc -l)
  if [ "$held" -lt "$writes" ]; then
    echo "GUARD: $held held back, want the truth's $writes writes"
    failed=1
  fi
fi
# 4.3b: every endpoint the traffic shows is one the scripts call (flows-app
# builds no URL the code does not spell out).
eps="$work/out/127.0.0.1/anon/endpoints.jsonl"
unseen=$(jq -r 'select((.third_party | not) and .status == "observed") | "\(.method) \(.host)\(.path)"' "$eps")
if [ -n "$unseen" ]; then
  echo "ENDPOINTS in the traffic, not found in the code:"; echo "$unseen"
  failed=1
fi
jq -c '.flows' "$work/out/127.0.0.1/anon/run.json"
jq -c '.endpoints' "$work/out/127.0.0.1/anon/run.json"
exit "$failed"
