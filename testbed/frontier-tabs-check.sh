#!/usr/bin/env bash
# The gate of crawl -depth -tabs N (docs/gd5-parallel-design.md 8, stage C).
#   1. frontier-app -depth 3, the guard on, -tabs 1 then -tabs 3: the same
#      pages visited (URL, depth, from) and listed (URL, reason, from); one
#      run; requests.jsonl true to the server's log both ways (no request
#      twice: one capture per tab, the workers' to one); every flow but
#      background ones has its requests in one tab; action IDs unique;
#      the three tabs used; frontscore passes on the -tabs 3 run.
#   2. -tabs 3 -page-rate 2: no two pages start loading closer than the
#      rate allows (0.7 of the gap, the limiter's jitter; pages.jsonl
#      started, not the documents: frames and redirects are a page's own).
#   3. -tabs 3 interrupted: exit 130, stopped "interrupted".
#   5. session-app -role user -depth 2 -tabs 3 (/account/privacy clears the
#      site's data, /account/expire ends the session on the server): the
#      same pages as -tabs 1, every marker, the session put back with at
#      most two logins, no write but the logins; the pages lost the
#      session at the same time visited again alone, the two that end it
#      named.
#   6. the same without the login script: one failed recovery, exit 4.
#   7. explore-app -explore -tabs 3: explorescore as explore-check (every
#      case an action holding its requests, precision >= 0.95, no write,
#      logout or held navigation to the server); more than one tab used.
#   8. flows-app -explore -tabs 3: every feature found (explorescore).
#   9. session-app -role user -explore -depth 2 -tabs 3: the session lives
#      through the reset and the wipe, every marker, only the logins post.
# Usage: testbed/frontier-tabs-check.sh   (exit 1 on failure)
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
work=${TESTBED_WORK}/frontier-tabs-check
rm -rf "$work"
mkdir -p "$work"
trap './testbed/run.sh stop >/dev/null' EXIT
failed=0
fail() { echo "FAIL $*"; failed=1; }
since() { tail -n +$(($1 + 1)) "${TESTBED_LOG}"; }
app=testbed/apps/frontier-app

echo "== 1. frontier-app, -tabs 1 and -tabs 3"
./testbed/run.sh start frontier-app >/dev/null
crawl() { # name tabs [flags...]
  local name=$1 tabs=$2 n
  shift 2
  n=$(wc -l <"${TESTBED_LOG}")
  timeout 300 ./bin/jsharvest crawl -u http://127.0.0.1:8770/ -depth 3 -page-rate 20 -guard on -tabs "$tabs" "$@" -o "$work/$name" \
    </dev/null >"$work/$name.log" 2>&1
  local code=$?
  sleep 0.5
  since "$n" >"$work/server-$name.log"
  return $code
}
crawl t1 1 || fail "-tabs 1: exit $?"
crawl t3 3 || fail "-tabs 3: exit $?"
d1="$work/t1/127.0.0.1/anon" d3="$work/t3/127.0.0.1/anon"
for t in 1 3; do
  d="$work/t$t/127.0.0.1/anon"
  jq -r 'select(.visited) | "\(.url) \(.depth) \(.from)"' "$d/pages.jsonl" | sort >"$work/visited$t"
  jq -r 'select(.visited | not) | "\(.url) \(.reason) \(.from)"' "$d/pages.jsonl" | sort >"$work/listed$t"
done
echo "-tabs 1: $(wc -l <"$work/visited1") pages in $(jq .duration_ms "$d1/run.json") ms; -tabs 3: $(wc -l <"$work/visited3") in $(jq .duration_ms "$d3/run.json") ms"
diff "$work/visited1" "$work/visited3" >/dev/null || fail "pages visited differ: $(diff "$work/visited1" "$work/visited3" | head -5)"
diff "$work/listed1" "$work/listed3" >/dev/null || fail "pages listed differ: $(diff "$work/listed1" "$work/listed3" | head -5)"
[ "$(wc -l <"$d3/runs.jsonl")" = 1 ] || fail "not one run"
./bin/testbed reqcheck -log "$work/server-t3.log" -requests "$d3/requests.jsonl" >"$work/reqcheck.log" 2>&1 ||
  fail "reqcheck: $(tail -3 "$work/reqcheck.log")"
./bin/testbed frontscore -truth "$app/frontier.truth.json" -out "$d3" -log "$work/server-t3.log" >"$work/frontscore.log" 2>&1 ||
  fail "frontscore: $(tail -3 "$work/frontscore.log")"
[ "$(jq -s '[.[] | select(.visited) | .tab] | unique' -c "$d3/pages.jsonl")" = "[1,2,3]" ] || fail "not the three tabs: $(jq -s '[.[] | select(.visited) | .tab] | unique' -c "$d3/pages.jsonl")"
jq -e 'select(.tab == null)' "$d3/requests.jsonl" >/dev/null && fail "a request without its tab"
# Every flow but the background ones in one tab; no action id twice.
mixed=$(jq -n --slurpfile r "$d3/requests.jsonl" --slurpfile f "$d3/flows.jsonl" '
  ($r | map({key: (.id | tostring), value: .tab}) | from_entries) as $tab |
  [$f[] | select(.kind != "background") | {action, tabs: ([.requests[].id | $tab[tostring]] | unique)} | select(.tabs | length > 1)]')
[ "$mixed" = "[]" ] || fail "flows over several tabs: $mixed"
jq -s '[.[].action] | group_by(.) | map(select(length > 1)) | length' "$d3/flows.jsonl" | grep -qx 0 || fail "an action id twice"

echo "== 2. -tabs 3 -page-rate 2: the pace holds"
crawl pace 3 -page-rate 2 || fail "pace: exit $?"
gap=$(jq -r 'select(.visited) | .started' "$work/pace/127.0.0.1/anon/pages.jsonl" | python3 -c '
import sys, re, datetime
def at(s):
    s = re.sub(r"\.(\d{1,6})\d*", lambda m: "." + m.group(1).ljust(6, "0"), s.strip().replace("Z", "+00:00"))
    return datetime.datetime.fromisoformat(s)
ts = sorted(at(l) for l in sys.stdin if l.strip())
print(min((b - a).total_seconds() for a, b in zip(ts, ts[1:])) if len(ts) > 1 else 1)')
echo "least gap between page loads: $gap s"
python3 -c "import sys; sys.exit(0 if $gap >= 0.3 else 1)" || fail "page loads $gap s apart at -page-rate 2"

echo "== 3. -tabs 3 interrupted"
./bin/jsharvest crawl -u http://127.0.0.1:8770/ -depth 3 -page-rate 1 -guard on -tabs 3 -o "$work/int" </dev/null >"$work/int.log" 2>&1 &
pid=$!
sleep 5
kill -INT "$pid"
wait "$pid"
code=$?
[ "$code" = 130 ] || fail "interrupted: exit $code, want 130"
jq -e '.frontier.stopped == "interrupted"' "$work/int/127.0.0.1/anon/run.json" >/dev/null ||
  fail "interrupted: $(jq -c .frontier "$work/int/127.0.0.1/anon/run.json")"

echo "== 5. session-app, -role user -depth 2 -tabs 3 (C4)"
export SESSION_APP_USER=member@app.test SESSION_APP_PASS=hunter22
./testbed/run.sh start session-app >/dev/null
./bin/jsharvest login -u http://127.0.0.1:8770/login -role user -profiles "$work/profiles" \
  -steps testbed/apps/session-app/login.steps.json >"$work/login.log" 2>&1 || fail "login: $(tail -2 "$work/login.log")"
role() { # name tabs profiles
  local n
  n=$(wc -l <"${TESTBED_LOG}")
  timeout 300 ./bin/jsharvest crawl -u http://127.0.0.1:8770/members/home -role user -profiles "$3" -depth 2 -page-rate 10 -tabs "$2" \
    -o "$work/$1" </dev/null >"$work/$1.log" 2>&1
  local code=$?
  sleep 0.5
  since "$n" >"$work/server-$1.log"
  return $code
}
role s1 1 "$work/profiles" || fail "session -tabs 1: exit $?"
role s3 3 "$work/profiles" || fail "session -tabs 3: exit $?"
s3="$work/s3/127.0.0.1/user"
jq -c '.session | {restored, relogins, lost, events: [.events[] | "\(.cause) -> \(.outcome)"]}' "$s3/run.json"
jq -e '.session.restored >= 1 and .session.relogins >= 1 and .session.relogins <= 2 and (.session.lost | not)' "$s3/run.json" >/dev/null ||
  fail "session -tabs 3: not restored, relogged in more than twice, or lost"
logins=$(grep -c ' POST /api/login$' "$work/server-s3.log")
[ "$logins" -le 2 ] || fail "session -tabs 3: $logins logins posted"
writes=$(grep -E ' (POST|PUT|PATCH|DELETE) ' "$work/server-s3.log" | grep -v ' POST /api/login$')
[ -z "$writes" ] || fail "session -tabs 3: writes reached the server: $writes"
missed=$(./bin/testbed score -app testbed/apps/session-app -out "$s3" | grep MISS | grep -v entry:main)
[ -z "$missed" ] || fail "session -tabs 3: markers: $missed"
for t in 1 3; do jq -r 'select(.visited) | .url' "$work/s$t/127.0.0.1/user/pages.jsonl" | sort -u >"$work/s-visited$t"; done
diff -q "$work/s-visited1" "$work/s-visited3" >/dev/null || fail "session: pages differ from -tabs 1: $(diff "$work/s-visited1" "$work/s-visited3")"
# A page lost the session alone at most once: every page visited again
# was visited alone, and each ender ends up named.
jq -e -s '[.[] | select(.error // "" | test("this page ends the session"))] | length == 2' "$s3/pages.jsonl" >/dev/null ||
  fail "session -tabs 3: not the two pages that end the session named"

echo "== 6. the same without the login script: lost once, the run stops (exit 4)"
mkdir -p "$work/noscript/127.0.0.1"
cp -r "$work/profiles/127.0.0.1/user" "$work/noscript/127.0.0.1/user"
jq 'del(.steps)' "$work/profiles/127.0.0.1/user/jsharvest-session.json" >"$work/noscript/127.0.0.1/user/jsharvest-session.json"
chmod 600 "$work/noscript/127.0.0.1/user/jsharvest-session.json"
role ns 3 "$work/noscript"
code=$?
[ "$code" = 4 ] || fail "no login script: exit $code, want 4"
ns="$work/ns/127.0.0.1/user/run.json"
jq -c '.session | {lost, failed: [.events[] | select(.outcome == "failed")] | length}' "$ns"
jq -e '.session.lost and .frontier.stopped == "session-lost" and ([.session.events[] | select(.outcome == "failed")] | length) == 1' "$ns" >/dev/null ||
  fail "no login script: not one failed recovery, or not stopped"
./testbed/run.sh stop >/dev/null

echo "== 7. explore-app -explore -tabs 3 (C5)"
xcrawl() { # name app-relative-args...
  local name=$1
  shift
  timeout 1200 ./bin/jsharvest crawl -u http://127.0.0.1:8770/ -explore -page-rate 10 -tabs 3 -o "$work/$name" "$@" </dev/null >"$work/$name.log" 2>&1
}
./testbed/run.sh start explore-app >/dev/null
n=$(wc -l <"${TESTBED_LOG}")
xcrawl xapp -depth 1 -explore-actions 150 || fail "explore-app -tabs 3: exit $?"
./bin/testbed explorescore -truth testbed/apps/explore-app/explore.truth.json -out "$work/xapp/127.0.0.1/anon" -log "${TESTBED_LOG}" -from "$n" |
  grep -v '^  pass' || fail "explore-app -tabs 3 score"
jq -c '.explore | {pages, actions, navigations, took_ms}' "$work/xapp/127.0.0.1/anon/run.json"
[ "$(jq -s '[.[] | select(.visited) | .tab] | unique | length' "$work/xapp/127.0.0.1/anon/pages.jsonl")" -ge 2 ] || fail "explore-app: one tab did it all"

echo "== 8. flows-app -explore -tabs 3"
./testbed/run.sh start flows-app >/dev/null
n=$(wc -l <"${TESTBED_LOG}")
xcrawl xflows || fail "flows-app -tabs 3: exit $?"
./bin/testbed explorescore -truth testbed/apps/flows-app/flows.truth.json -out "$work/xflows/127.0.0.1/anon" -log "${TESTBED_LOG}" -from "$n" |
  grep -v '^  pass' || fail "flows-app -tabs 3 score"

echo "== 9. session-app -role user -explore -depth 2 -tabs 3"
./testbed/run.sh start session-app >/dev/null
# The server keeps its sessions in memory: a new one, for the restarted server.
./bin/jsharvest login -u http://127.0.0.1:8770/login -role user -profiles "$work/profiles" \
  -steps testbed/apps/session-app/login.steps.json >"$work/login2.log" 2>&1 || fail "login: $(tail -2 "$work/login2.log")"
n=$(wc -l <"${TESTBED_LOG}")
timeout 1200 ./bin/jsharvest crawl -u http://127.0.0.1:8770/members/home -role user -profiles "$work/profiles" -explore -depth 2 -page-rate 10 -tabs 3 \
  -o "$work/xsession" </dev/null >"$work/xsession.log" 2>&1 || fail "session explore -tabs 3: exit $?"
xs="$work/xsession/127.0.0.1/user"
jq -c '{session: (.session | {restored, relogins, lost}), explore: (.explore | {pages, actions, session_ends})}' "$xs/run.json"
jq -e '(.session.lost | not) and .explore.session_ends >= 1 and .session.relogins <= 2' "$xs/run.json" >/dev/null ||
  fail "session explore -tabs 3: lost, the reset not noticed, or more than two logins"
missed=$(./bin/testbed score -app testbed/apps/session-app -out "$xs" | grep MISS | grep -v entry:main)
[ -z "$missed" ] || fail "session explore -tabs 3: markers: $missed"
writes=$(since "$n" | grep -E ' (POST|PUT|PATCH|DELETE) ' | grep -v ' POST /api/login$')
[ -z "$writes" ] || fail "session explore -tabs 3: writes reached the server: $writes"
./testbed/run.sh stop >/dev/null

[ "$failed" = 0 ] && echo "frontier-tabs-check: ok" || { echo "frontier-tabs-check: FAILED"; exit 1; }
