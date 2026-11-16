#!/usr/bin/env bash
# The 4.3b gate: endpoints from the code that has not run to the traffic,
# on endpoints-app (a production webpack build, with a lazy admin chunk that
# only an admin's page loads).
#   1. not run: a crawl as anon lists every endpoint the scripts call, the
#      admin chunk's included (the resolver fetches it), each with its method
#      and parameters, and no noise; the ones the page calls on load are
#      both, the others static;
#   2. while it runs: a watch of the same output while a driver clicks six
#      features; meanwhile jsharvest mcp lists the admin endpoints as static;
#   3. run: after the watch, the six are both (the client's base confirmed
#      by the traffic), and the rest is as before.
# Usage: testbed/endpoints-check.sh   (exit 1 on failure)
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
export JSHARVEST_CHROME="$CHROME_BIN"
require_built_apps "$root" || exit 1
build_testbed_bins || exit 1
work=${TESTBED_WORK}/endpoints-check
rm -rf "$work"
mkdir -p "$work/profile"
port=9333
app=testbed/apps/endpoints-app
out="$work/out/127.0.0.1/anon"
failed=0

./testbed/run.sh start endpoints-app >/dev/null
chrome=""
watch=""
cleanup() {
  [ -n "$watch" ] && kill "$watch" 2>/dev/null
  [ -n "$chrome" ] && kill "$chrome" 2>/dev/null
  ./testbed/run.sh stop >/dev/null
}
trap cleanup EXIT

echo "== 1. not run: crawl as anon"
timeout 180 ./bin/jsharvest crawl -u http://127.0.0.1:8770/ -guard on -o "$work/out" </dev/null >"$work/crawl.log" 2>&1 || {
  echo "crawl failed"; tail -3 "$work/crawl.log"; exit 1
}
./bin/testbed epscore -truth "$app/endpoints.truth.json" -out "$out" || failed=1

echo "== 2. while it runs: watch, a driver clicks, mcp is asked"
"$CHROME_BIN" --headless=new --remote-debugging-port=$port --user-data-dir="$work/profile" --no-first-run about:blank >"$work/chrome.log" 2>&1 &
chrome=$!
sleep 2
./bin/jsharvest watch -attach "http://127.0.0.1:$port" -open http://127.0.0.1:8770/ -guard on -o "$work/out" ${WATCH_FLAGS:-} >"$work/watch.log" 2>&1 &
watch=$!
for _ in $(seq 50); do
  grep -q "watching" "$work/watch.log" && break
  sleep 0.2
done
sleep 2
./bin/testbed drive -cdp "http://127.0.0.1:$port" -tab '127\.0\.0\.1:8770' -steps "$app/flows.truth.json" -log "$work/steps.jsonl" \
  -mcp "./bin/jsharvest mcp -o $work/out" -mcp-guard >"$work/drive.log" 2>&1 || {
  echo "drive failed:"; grep -E "^mcp|MCP WRONG" "$work/drive.log"; tail -3 "$work/drive.log"; failed=1
}
grep -E "^mcp:" "$work/drive.log"
./bin/testbed mcpcall -cmd "./bin/jsharvest mcp -o $work/out" -tool endpoints -args '{"status":"static","contains":"/admin/"}' >"$work/mcp-static.json" || failed=1
admin=$(jq '[.endpoints[] | select(.path | test("admin"))] | length' "$work/mcp-static.json")
if [ "$admin" != 5 ]; then
  echo "2: mcp lists $admin admin endpoints as static during the watch, want 5"
  failed=1
else
  echo "2: mcp lists the 5 admin endpoints as static during the watch"
fi
kill -INT "$watch"
wait "$watch"
watch=""

echo "== 3. run: the clicked features are both"
ran="POST /api/articles,POST /api/profiles/{}/follow,POST /api/articles/{}/comments,GET /api/export/csv,GET /api/articles/feed,GET /api/profiles/{}"
./bin/testbed epscore -truth "$app/endpoints.truth.json" -out "$out" -ran "$ran" || failed=1
base=$(jq -r 'select(.path == "/profiles/{}/follow" and .method == "POST") | .base' "$out/endpoints.jsonl")
if [ "$base" != "/api" ]; then
  echo "3: the client's base is ${base:-unconfirmed}, want /api"
  failed=1
fi

echo "== 4. Invariant #9 perf & RSS gate (2,000 scripts: <= 15s, <= 500 MB)"
./bin/testbed perfgate -bin ./bin/jsharvest -work "$work/perf" || failed=1

[ "$failed" = 0 ] && echo "endpoints gate: ok"
exit "$failed"
