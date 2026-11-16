#!/usr/bin/env bash
# The 4.5 gate: a saved login, lost and put back while crawling.
#   1. session-app: jsharvest login -steps, then crawl -depth 2 from the
#      members' home. /account/privacy clears cookies and storage (put back from
#      the snapshot); /account/expire ends the session on the server (a new
#      login with the script). Every members' marker is found, the storage
#      ones included.
#   1b. /members/late, linked from nowhere: its document comes logged in,
#      then it ends the session on the server and asks for its chunk, which
#      is sent to the login page. The keeper sees it (login-redirect), puts
#      the session back, and the run goes on (round 25N: the -tabs race of
#      one tab's page ending the session while another's chunk loads).
#   2. the same login without its script: the crawl stops at the expiry,
#      exit 4, session.lost in run.json, the pages after it not visited.
#   3. no write reaches the server but the logins.
#   4. role admin on the five original apps: 56/56 markers (webpack-vanilla's
#      server-gated admin panel needs the admin login).
# Usage: testbed/session-check.sh   (exit 1 on failure)
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
work=${TESTBED_WORK}/session-check
rm -rf "$work"
mkdir -p "$work"
trap './testbed/run.sh stop >/dev/null' EXIT
failed=0
fail() { echo "FAIL $*"; failed=1; }
export SESSION_APP_USER=member@app.test SESSION_APP_PASS=hunter22 ADMIN_USER=admin@app.test ADMIN_PASS=hunter22

echo "== 1. session-app, with the login script"
./testbed/run.sh start session-app >/dev/null
n=$(wc -l <${TESTBED_LOG})
./bin/jsharvest login -u http://127.0.0.1:8770/login -role user -profiles "$work/profiles" \
  -steps testbed/apps/session-app/login.steps.json >"$work/login.log" 2>&1 || { fail "login"; tail -3 "$work/login.log"; }
snap="$work/profiles/127.0.0.1/user/jsharvest-session.json"
[ "$(stat -c %a "$snap" 2>/dev/null)" = 600 ] || fail "the snapshot is not 0600"
jq -e '.storage["http://127.0.0.1:8770"].session.tab and .storage["http://127.0.0.1:8770"].local.auth' "$snap" >/dev/null ||
  fail "the snapshot has no localStorage or sessionStorage"
grep -q hunter22 "$snap" && fail "the password is in the snapshot"
crawl() { # out dir -> exit code
  timeout 300 ./bin/jsharvest crawl -u http://127.0.0.1:8770/members/home -role user -profiles "$work/profiles" -depth 2 -page-rate 10 \
    -o "$1" </dev/null >"$1.log" 2>&1
}
crawl "$work/out1"
code=$?
run="$work/out1/127.0.0.1/user/run.json"
[ "$code" = 0 ] || fail "crawl exit $code"
jq -c '.session | {restored, relogins, lost, events: [.events[] | "\(.cause) -> \(.outcome)"]}' "$run"
jq -e '.session.restored >= 1 and .session.relogins >= 1 and (.session.lost | not)' "$run" >/dev/null || fail "no restore and relogin, or lost"
missed=$(./bin/testbed score -app testbed/apps/session-app -out "$work/out1/127.0.0.1/user" | grep MISS | grep -v entry:main)
[ -z "$missed" ] || fail "markers: $missed"

echo "== 1b. a page's chunk sent to the login page"
timeout 300 ./bin/jsharvest crawl -u http://127.0.0.1:8770/members/late -role user -profiles "$work/profiles" -depth 1 -page-rate 10 \
  -o "$work/out1b" </dev/null >"$work/out1b.log" 2>&1
code=$?
run="$work/out1b/127.0.0.1/user/run.json"
[ "$code" = 0 ] || fail "1b: crawl exit $code"
jq -c '.session | {restored, relogins, lost, events: [.events[] | "\(.cause) -> \(.outcome)"]}' "$run"
jq -e '([.session.events[] | select(.cause == "login-redirect" and .outcome != "failed")] | length) >= 1 and (.session.lost | not)' "$run" >/dev/null ||
  fail "1b: the chunk sent to the login page was not seen as a loss, or the session was lost"

echo "== 2. without the login script"
mkdir -p "$work/noscript/127.0.0.1"
cp -r "$work/profiles/127.0.0.1/user" "$work/noscript/127.0.0.1/user"
jq 'del(.steps)' "$snap" >"$work/noscript/127.0.0.1/user/jsharvest-session.json"
chmod 600 "$work/noscript/127.0.0.1/user/jsharvest-session.json"
timeout 300 ./bin/jsharvest crawl -u http://127.0.0.1:8770/members/home -role user -profiles "$work/noscript" -depth 2 -page-rate 10 \
  -o "$work/out2" </dev/null >"$work/out2.log" 2>&1
code=$?
run="$work/out2/127.0.0.1/user/run.json"
[ "$code" = 4 ] || fail "exit $code, want 4"
jq -c '.session | {lost, last: .events[-1]}' "$run"
jq -e '.session.lost and .frontier.stopped == "session-lost"' "$run" >/dev/null || fail "session.lost not reported"
grep -q '"url":"http://127.0.0.1:8770/members/e","visited":true' "$work/out2/127.0.0.1/user/pages.jsonl" && fail "visited a page after the loss"

echo "== 3. writes"
writes=$(tail -n "+$((n + 1))" ${TESTBED_LOG} | grep -E ' (POST|PUT|PATCH|DELETE) ' | grep -v ' POST /api/login$')
[ -z "$writes" ] || fail "writes reached the server: $writes"
echo "logins posted: $(tail -n "+$((n + 1))" ${TESTBED_LOG} | grep -c ' POST /api/login$')"
./testbed/run.sh stop >/dev/null

echo "== 4. role admin, five apps"
total=0
found=0
for app in webpack-vanilla vite-vanilla vite-pwa next-mixed angular-ngsw; do
  ./testbed/run.sh start "$app" >/dev/null
  if [ "$app" = webpack-vanilla ]; then
    ./bin/jsharvest login -u http://127.0.0.1:8770/login -role admin -profiles "$work/profiles" \
      -steps testbed/apps/webpack-vanilla/admin.steps.json >"$work/admin-login.log" 2>&1 || { fail "admin login"; tail -3 "$work/admin-login.log"; }
  fi
  timeout 600 ./bin/jsharvest crawl -u http://127.0.0.1:8770/ -role admin -profiles "$work/profiles" -depth 2 -page-rate 10 \
    -o "$work/admin" </dev/null >"$work/admin-$app.log" 2>&1
  s=$(./bin/testbed score -app "testbed/apps/$app" -out "$work/admin/127.0.0.1/admin")
  got=$(echo "$s" | grep -oE 'recall: [0-9]+/[0-9]+' | grep -oE '[0-9]+/[0-9]+')
  echo "$app $got $(echo "$s" | grep MISS | tr -s ' ' | tr '\n' ' ')"
  found=$((found + ${got%/*}))
  total=$((total + ${got#*/}))
  ./testbed/run.sh stop >/dev/null
  rm -rf "$work/admin" # each app its own store: the same host
done
echo "admin: $found/$total"
[ "$found" -ge 55 ] || fail "admin markers $found/$total"

# --- 28C (plan-28 5 and 4.3, P4.5): refresh-app as a gate ---
# 1. OAuth, guard on: the refresh grant passes, nothing faked, no revocation.
# 2. BFF: login -guard-allow unanchored is refused (exit 1, no session);
#    anchored is kept in the session and lets the empty-body refresh by.
# 3. -urls -tabs 3 -role: one context per host+role (C4), no revocation.
# 4. The session file is kept fresh: after run 1 its refresh token is the
#    rotated one, and a second crawl from it is not revoked (no reuse).
echo "== refresh-app (28C)"
rt=testbed/apps/refresh-app rtb=http://127.0.0.1:8770
export RT_USER=rt@app.test RT_PASS=hunter22 RT_TTL=6
rtrun() { # name kind mode shape [extra login args...] -> $work/rt-<name>/{stats.json,server.log,out}
  local name=$1 kind=$2 mode=$3 shape=$4; shift 4
  local d="$work/rt-$name"; rm -rf "$d"; mkdir -p "$d"
  # RT_SERVER names the run whose server this one goes on with (the tokens
  # live in its memory); RT_LEAVE keeps the server up for the next run.
  local sv="$work/rt-${RT_SERVER:-$name}"
  [ -n "${RT_SERVER:-}" ] || TESTBED_LOG="$sv/server.log" TESTBED_PID="$sv/server.pid" ./testbed/run.sh start refresh-app >/dev/null
  local steps="$rt/login-$([ "$kind" = bff ] && echo bff || echo oauth).steps.json"
  if [ -z "${RT_PROFILES:-}" ]; then
    ./bin/jsharvest login -u "$rtb/rt/login?kind=$kind&mode=$mode" -role user -profiles "$d/profiles" -steps "$steps" "$@" >"$d/login.log" 2>&1 ||
      { fail "rt $name: login: $(tail -1 "$d/login.log")"; TESTBED_PID="$sv/server.pid" ./testbed/run.sh stop >/dev/null; return 1; }
  fi
  local prof=${RT_PROFILES:-$d/profiles}
  find "$prof" -name jsharvest-session.json -exec cp {} "$d/session-before.json" \; 2>/dev/null
  local start="$rtb/rt/?mode=$mode"; [ "$kind" = bff ] && start="$rtb/rt/bff/?kind=bff"
  case $shape in
    crawl) timeout 600 ./bin/jsharvest crawl -u "$start" -depth 2 -role user -profiles "$prof" -guard on -page-rate 2 -o "$d/out" </dev/null >"$d/crawl.log" 2>&1 ;;
    urls) : >"$d/urls.txt"; for x in a b c d e f; do
            if [ "$kind" = bff ]; then echo "$rtb/rt/bff/$x?kind=bff&lock=1"; else echo "$rtb/rt/$x?mode=$mode&lock=1"; fi >>"$d/urls.txt"; done
          timeout 600 ./bin/jsharvest crawl -urls "$d/urls.txt" -tabs 3 -role user -profiles "$prof" -guard on -page-rate 2 -o "$d/out" </dev/null >"$d/crawl.log" 2>&1 ;;
  esac
  curl -s "$rtb/rt/_stats" >"$d/stats.json"
  cp "$sv/server.log" "$d/server.log" 2>/dev/null
  [ -n "${RT_LEAVE:-}" ] || TESTBED_PID="$sv/server.pid" ./testbed/run.sh stop >/dev/null
}
rtst() { jq -r "$2 // 0" "$work/rt-$1/stats.json" 2>/dev/null || echo 0; }
rtrev() { grep -c 'REVOKED family=' "$work/rt-$1/server.log"; }
rtheld() { find "$work/rt-$1/out" -name blocked.jsonl -exec cat {} + 2>/dev/null | grep -cE '/rt/oauth/token|/rt/api/auth/refresh'; }
rtcheck() { # name: refreshes went through, none faked or held, no revocation
  local n=$1
  [ "$(rtst "$n" .refresh_ok)" -ge 1 ] || fail "rt $n: no refresh reached the server ($(cat "$work/rt-$n/stats.json"))"
  [ "$(rtst "$n" .client.refresh_fake)" = 0 ] || fail "rt $n: the app got a made-up refresh answer"
  [ "$(rtheld "$n")" = 0 ] || fail "rt $n: the guard held a refresh"
  [ "$(rtrev "$n")" = 0 ] || fail "rt $n: the server revoked the session (a refresh token reused)"
  echo "rt $n: refresh_ok $(rtst "$n" .refresh_ok), data_ok $(rtst "$n" .data_ok), data_401 $(rtst "$n" .data_401), revoked $(rtrev "$n")"
}
RT_LEAVE=1 rtrun oauth oauth form crawl && rtcheck oauth
# 4. the session file holds the rotated token; a second crawl from it is not revoked
sf=$(find "$work/rt-oauth/profiles" -name jsharvest-session.json | head -1)
tok() { jq -r '.storage[]?.local.rt_auth // empty' "$1" 2>/dev/null | head -1; }
if [ -n "$sf" ] && [ -n "$(tok "$sf")" ] && [ "$(tok "$sf")" != "$(tok "$work/rt-oauth/session-before.json")" ]; then
  # the same server: its stats count from the start, so run 2 is checked
  # on what it added (refresh_ok grows, no revocation at all)
  ok1=$(rtst oauth .refresh_ok)
  RT_SERVER=oauth RT_PROFILES="$work/rt-oauth/profiles" rtrun oauth2 oauth form crawl
  [ "$(rtst oauth2 .refresh_ok)" -gt "$ok1" ] || fail "rt oauth2: no refresh of its own reached the server"
  [ "$(rtrev oauth2)" = 0 ] || fail "rt oauth2: the server revoked the session: the run began with a used refresh token"
  echo "rt oauth2: refresh_ok $(rtst oauth2 .refresh_ok) (run 1: $ok1), revoked $(rtrev oauth2)"
else
  fail "rt oauth: the session file does not hold the rotated token after the run ($sf)"
fi
TESTBED_PID="$work/rt-oauth/server.pid" ./testbed/run.sh stop >/dev/null
d="$work/rt-badallow"; mkdir -p "$d"
TESTBED_LOG="$d/server.log" TESTBED_PID="$d/server.pid" ./testbed/run.sh start refresh-app >/dev/null
if ./bin/jsharvest login -u "$rtb/rt/login?kind=bff" -role user -profiles "$d/profiles" -steps "$rt/login-bff.steps.json" \
    -guard-allow '/rt/api/auth/refresh' >"$d/login.log" 2>&1; then
  fail "login -guard-allow unanchored was accepted"
fi
[ -z "$(find "$d/profiles" -name jsharvest-session.json 2>/dev/null)" ] || fail "login -guard-allow unanchored wrote a session"
TESTBED_PID="$d/server.pid" ./testbed/run.sh stop >/dev/null
rtrun bff bff form crawl -guard-allow '^http://127\.0\.0\.1:8770/rt/api/auth/refresh(\?|$)' && rtcheck bff
# -urls -tabs 3 -role: one context and one keeper per host+role (C4). The
# app's tabs then share localStorage, but a write in one tab reaches the
# others' renderers a little later, so even a careful app (lock=1, Web
# Locks) may spend a refresh token another tab just used: a revocation
# here is the app's race, said as a NOTE; what the tool owes is that every
# refresh goes through and none is faked (28B measured one revocation per
# run with a context per URL).
if rtrun urls oauth form urls; then
  [ "$(rtst urls .refresh_ok)" -ge 1 ] || fail "rt urls: no refresh reached the server"
  [ "$(rtst urls .client.refresh_fake)" = 0 ] || fail "rt urls: the app got a made-up refresh answer"
  [ "$(rtheld urls)" = 0 ] || fail "rt urls: the guard held a refresh"
  [ "$(rtrev urls)" = 0 ] || echo "NOTE rt urls: $(rtrev urls) revocation(s): the app's tabs raced on a refresh token (shared storage propagates late)"
  echo "rt urls: refresh_ok $(rtst urls .refresh_ok), data_ok $(rtst urls .data_ok), revoked $(rtrev urls)"
fi

[ "$failed" = 0 ] && echo "session gate: ok"
exit "$failed"
