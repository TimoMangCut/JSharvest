#!/usr/bin/env bash
# The 4.6 gate: crawl -explore does on its own what a person would, safely.
#   1. explore-app (56 hard cases): every case is one explore action holding
#      its requests, precision >= 0.95; no write, logout or held navigation
#      reaches the server (testbed explorescore -log).
#   2. flows-app: every feature of flows.truth.json found with no script.
#   3. webpack-vanilla without the resolver: click, scroll and form markers
#      by real interaction (they miss without explore).
#   4. edge-cases: inline:handler.
#   5. -allow-write: writes may pass, but no DELETE, no GET that approves,
#      no logout ever reaches the server.
#   6. session-app with -role user: the session survives exploring (wipe and
#      expire on the way), and only the login posts.
# Usage: testbed/explore-check.sh   (exit 1 on failure)
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
build_testbed_bins || exit 1
work=${TESTBED_WORK}/explore-check
rm -rf "$work"
mkdir -p "$work"
trap './testbed/run.sh stop >/dev/null' EXIT
failed=0
fail() { echo "FAIL $*"; failed=1; }
crawl() { # name app-relative-args... -> runs, output in $work/<name>
  local name=$1
  shift
  timeout 1200 ./bin/jsharvest crawl -u http://127.0.0.1:8770/ -explore -page-rate 10 -o "$work/$name" "$@" </dev/null >"$work/$name.log" 2>&1
}
out() { echo "$work/$1/127.0.0.1/${2:-anon}"; }

echo "== 1. explore-app"
./testbed/run.sh start explore-app >/dev/null
n=$(wc -l <${TESTBED_LOG})
crawl app -depth 1 -explore-actions 150 || fail "explore-app crawl exit $?"
./bin/testbed explorescore -truth testbed/apps/explore-app/explore.truth.json -out "$(out app)" -log ${TESTBED_LOG} -from "$n" |
  grep -v '^  pass' || fail "explore-app score"
jq -c '.explore | {pages, actions, untrusted, restores, navigations, errors, took_ms}' "$(out app)/run.json"

echo "== 5. explore-app, -allow-write"
n=$(wc -l <${TESTBED_LOG})
crawl write -explore-actions 150 -allow-write || fail "allow-write crawl exit $?"
bad=$(tail -n "+$((n + 1))" ${TESTBED_LOG} | grep -E ' DELETE |/approve|logged-out|signed-out')
[ -z "$bad" ] || fail "with -allow-write, these reached the server: $bad"
echo "writes that passed (agreed): $(tail -n "+$((n + 1))" ${TESTBED_LOG} | grep -cE ' (POST|PUT|PATCH) ')"
./testbed/run.sh stop >/dev/null

echo "== 2. flows-app"
./testbed/run.sh start flows-app >/dev/null
n=$(wc -l <${TESTBED_LOG})
crawl flows || fail "flows-app crawl exit $?"
./bin/testbed explorescore -truth testbed/apps/flows-app/flows.truth.json -out "$(out flows)" -log ${TESTBED_LOG} -from "$n" |
  grep -v '^  pass' || fail "flows-app score"
./testbed/run.sh stop >/dev/null

echo "== 3. webpack-vanilla, no resolver"
./testbed/run.sh start webpack-vanilla >/dev/null
crawl webpack -depth 1 -resolve=false || fail "webpack crawl exit $?"
s=$(./bin/testbed score -app testbed/apps/webpack-vanilla -out "$(out webpack)")
for m in click:report scroll:comments form:welcome; do
  echo "$s" | grep -q "ok    JSHMARK:$m" || fail "webpack-vanilla: $m"
done
echo "$s" | grep recall
./testbed/run.sh stop >/dev/null

echo "== 4. edge-cases"
./testbed/run.sh start edge-cases >/dev/null
crawl edge || fail "edge-cases crawl exit $?"
./bin/testbed score -app testbed/apps/edge-cases -out "$(out edge)" | grep -q "ok    JSHMARK:inline:handler" || fail "edge-cases: inline:handler"
./testbed/run.sh stop >/dev/null

echo "== 6. session-app, -role user"
export SESSION_APP_USER=member@app.test SESSION_APP_PASS=hunter22
./testbed/run.sh start session-app >/dev/null
n=$(wc -l <${TESTBED_LOG})
./bin/jsharvest login -u http://127.0.0.1:8770/login -role user -profiles "$work/profiles" \
  -steps testbed/apps/session-app/login.steps.json >"$work/login.log" 2>&1 || fail "login"
timeout 1200 ./bin/jsharvest crawl -u http://127.0.0.1:8770/members/home -role user -profiles "$work/profiles" -explore -depth 2 -page-rate 10 \
  -o "$work/session" </dev/null >"$work/session.log" 2>&1
code=$?
[ "$code" = 0 ] || fail "session crawl exit $code"
run="$(out session user)/run.json"
jq -c '{session: (.session | {restored, relogins, lost}), explore: (.explore | {pages, actions, session_ends})}' "$run"
jq -e '.session.lost | not' "$run" >/dev/null || fail "session lost while exploring"
# /members/a's "Reset view" ends the session in the page: noticed after the
# click, put back, and the pages after it still reached (markers below).
jq -e '.explore.session_ends >= 1' "$run" >/dev/null || fail "the reset during explore was not noticed"
missed=$(./bin/testbed score -app testbed/apps/session-app -out "$(out session user)" | grep MISS | grep -v entry:main)
[ -z "$missed" ] || fail "session-app markers: $missed"
writes=$(tail -n "+$((n + 1))" ${TESTBED_LOG} | grep -E ' (POST|PUT|PATCH|DELETE) ' | grep -v ' POST /api/login$')
[ -z "$writes" ] || fail "writes reached the server: $writes"

[ "$failed" = 0 ] && echo "explore gate: ok"
exit "$failed"
