#!/usr/bin/env bash
# The 5.1 gate (docs/gd5-replay-design.md): jsharvest authz and replay,
# which send requests, against the testbed only.
#   A. authz-app: user and admin log in; anon, user and admin are crawled
#      alike (-explore, the guard holds the writes); jsharvest diff.
#   B. authz, reads only: every verdict of authz.truth.json, nothing else;
#      no trial of user or anon carries an admin's secret; the server saw
#      exactly what sent.jsonl says was sent, and never a write, the
#      destructive wipe, a login or a logout.
#   B2. authz -concurrency 4 (no rate): the same verdicts, in the same
#      order, as B; the server saw what sent.jsonl says.
#   B3. authz -concurrency 4 -rate 10: no two requests start closer than
#      the rate allows.
#   C. authz -allow-write: the writes' verdicts; still never the wipe.
#   D. authz -dry-run: nothing reaches the server.
#   E. the server restarted (every session gone): no verdict but unclear
#      and skipped; a dead session never reads as enforced.
#   F. flows-app, CSRF tokens good for 3 s: the recorded save, sent as it
#      is, is refused; replay -flow takes the token fresh and gets 200;
#      without -allow-write the save is skipped; -dry-run sends nothing.
#   G. CDN/WAF blocks (TESTBED_CF_BLOCK, round 25H): authz under a ban
#      gives the host up after one control; verify under a rule on one
#      path (1020) goes on, under a ban after 6 requests stops at 8, under
#      one 429 asks again; -on-block stop stops at the first block.
# Usage: testbed/replay-check.sh   (exit 1 on failure)
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
work=${TESTBED_WORK}/replay-check
rm -rf "$work"
mkdir -p "$work"
trap './testbed/run.sh stop >/dev/null' EXIT
failed=0
fail() { echo "FAIL $*"; failed=1; }
export AUTHZ_APP_USER=member@authz.test AUTHZ_APP_ADMIN=admin@authz.test AUTHZ_APP_PASS=hunter22
app=testbed/apps/authz-app
out=$work/out
since() { tail -n +$(($1 + 1)) ${TESTBED_LOG}; }

echo "== A. authz-app: three roles, diff"
./testbed/run.sh start authz-app >/dev/null
for r in user admin; do
  ./bin/jsharvest login -u http://127.0.0.1:8770/login -role "$r" -profiles "$work/profiles" -steps "$app/$r.steps.json" \
    >"$work/login-$r.log" 2>&1 || fail "login $r"
done
for r in anon user admin; do
  rf=()
  [ "$r" != anon ] && rf=(-role "$r")
  timeout 600 ./bin/jsharvest crawl -u http://127.0.0.1:8770/ "${rf[@]}" -profiles "$work/profiles" -depth 0 -explore -page-rate 10 -o "$out" \
    </dev/null >"$work/crawl-$r.log" 2>&1 || fail "crawl $r: exit $?"
done
./bin/jsharvest diff -o "$out" -target 127.0.0.1 -roles anon,user,admin >"$work/diff.log" 2>&1 || fail "diff: $(tail -1 "$work/diff.log")"
# The admin's secrets: its session cookie, and the CSRF tokens it sent.
{
  jq -r '.cookies[] | select(.name == "session") | .value' "$work/profiles/127.0.0.1/admin/jsharvest-session.json"
  jq -r '.headers["x-csrf-token"] // empty' "$out/127.0.0.1/admin/requests.jsonl"
} | sort -u >"$work/secrets.txt"
[ -s "$work/secrets.txt" ] || fail "no admin secret to look for"

authz() { # name flags...
  local name=$1
  shift
  local n
  n=$(wc -l <${TESTBED_LOG})
  ./bin/jsharvest authz -o "$out" -profiles "$work/profiles" -target 127.0.0.1 -rate 50 "$@" >"$work/authz-$name.log" 2>&1 ||
    fail "authz $name: $(tail -2 "$work/authz-$name.log")"
  rm -rf "$work/authz-$name"
  cp -r "$out/127.0.0.1/authz" "$work/authz-$name"
  since "$n" >"$work/server-$name.log"
  grep -E "^authz|^note|^stopped" "$work/authz-$name.log"
}
# The server saw each request sent.jsonl says went out, and no other.
sent_matches() { # name
  local sent seen
  sent=$(jq -r 'select(.dry_run != true and (.error // "") == "") | .n' "$work/authz-$1/sent.jsonl" | wc -l)
  seen=$(grep -cE " /api/az/" "$work/server-$1.log")
  [ "$sent" = "$seen" ] || fail "$1: sent.jsonl has $sent requests, the server saw $seen"
}
never() { # name pattern...
  local name=$1
  shift
  for p in "$@"; do
    grep -qE "$p" "$work/server-$name.log" && fail "$name: the server saw $p"
  done
}

echo "== B. authz, reads only"
authz read
./bin/testbed authzscore -truth "$app/authz.truth.json" -authz "$work/authz-read" -secrets "$work/secrets.txt" || fail "authzscore read"
sent_matches read
never read "/api/az/admin/cache" "/api/login" "/api/logout" "POST /api/az/admin/invite" "POST /api/az/admin/notes"
for f in authz.json authz.md sent.jsonl; do
  [ "$(stat -c %a "$work/authz-read/$f")" = 600 ] || fail "$f not 0600"
done

verdicts() { jq -c '[.items[] | {key, trials: [.trials[] | {role, verdict}]}]' "$work/authz-$1/authz.json"; }

echo "== B2. authz -concurrency 4"
authz conc -concurrency 4 -rate 0
./bin/testbed authzscore -truth "$app/authz.truth.json" -authz "$work/authz-conc" -secrets "$work/secrets.txt" || fail "authzscore conc"
[ "$(verdicts conc)" = "$(verdicts read)" ] || fail "concurrency 4: verdicts differ from one at a time: $(diff <(verdicts read | jq .) <(verdicts conc | jq .) | head -20)"
sent_matches conc
never conc "/api/az/admin/cache" "/api/login" "/api/logout" "POST /api/az/admin/invite" "POST /api/az/admin/notes"

echo "== B3. authz -concurrency 4 -rate 10: the pace holds"
authz pace -concurrency 4 -rate 10
gap=$(jq -r '.ts' "$work/authz-pace/sent.jsonl" | python3 -c '
import sys, re, datetime
def at(l):  # RFC 3339 with up to 9 digits: microseconds are enough
    l = re.sub(r"\.(\d{1,6})\d*", lambda m: "." + m.group(1).ljust(6, "0"), l.strip().replace("Z", "+00:00"))
    return datetime.datetime.fromisoformat(l)
ts = sorted(at(l) for l in sys.stdin if l.strip())
print(min((b - a).total_seconds() for a, b in zip(ts, ts[1:])) if len(ts) > 1 else 1)')
python3 -c "import sys; sys.exit(0 if $gap >= 0.09 else 1)" || fail "concurrency 4 at rate 10: two requests $gap s apart"
[ "$(verdicts pace)" = "$(verdicts read)" ] || fail "rate 10: verdicts differ"

echo "== C. authz -allow-write"
authz write -allow-write
./bin/testbed authzscore -truth "$app/authz.truth.json" -authz "$work/authz-write" -write -secrets "$work/secrets.txt" || fail "authzscore write"
sent_matches write
never write "/api/az/admin/cache" "/api/login" "/api/logout"

echo "== D. authz -dry-run"
authz dry -dry-run
[ -s "$work/server-dry.log" ] && fail "a dry run reached the server: $(head -2 "$work/server-dry.log")"
jq -e 'select(.dry_run != true)' "$work/authz-dry/sent.jsonl" >/dev/null && fail "a dry run logged a request as sent"

echo "== E. every session gone"
./testbed/run.sh start authz-app >/dev/null
authz dead
jq -e '[.items[].trials[].verdict] | all(. == "unclear" or . == "skipped")' "$work/authz-dead/authz.json" >/dev/null ||
  fail "dead sessions: $(jq -c '.summary' "$work/authz-dead/authz.json")"
grep -q "session is dead" "$work/authz-dead.log" || fail "dead sessions: no note says so"

echo "== F. flows-app: a save, its CSRF token fresh"
TESTBED_CSRF_TTL=3 testbed/flows-check.sh >"$work/flows.log" 2>&1 || fail "flows-check: $(tail -2 "$work/flows.log")"
cp -r ${TESTBED_WORK}/flows-check/out "$work/fa"
TESTBED_CSRF_TTL=3 ./testbed/run.sh start flows-app >/dev/null
fa=$work/fa/127.0.0.1/anon
./bin/jsharvest export -o "$work/fa" -target 127.0.0.1 2>"$work/export.log" || fail "export"
save=$(jq -r 'select((.label | test("Save profile")) and (.writes | length) > 0) | .action' "$fa/flows.jsonl" | head -1)
[ -n "$save" ] || fail "no save flow"
sleep 4
exec 3<>/dev/tcp/127.0.0.1/8770
cat "$fa/export/endpoints/POST-api-profile.http" >&3
status=$(head -1 <&3 | awk '{print $2}')
exec 3<&- 3>&-
[ "$status" = 403 ] || fail "the recorded save, its token expired: $status, want 403"
replay() { # name flags...
  local name=$1
  shift
  local n
  n=$(wc -l <${TESTBED_LOG})
  ./bin/jsharvest replay -o "$work/fa" -target 127.0.0.1 -flow "$save" -rate 50 "$@" >"$work/replay-$name.log" 2>&1 ||
    fail "replay $name: $(tail -2 "$work/replay-$name.log")"
  since "$n" >"$work/server-replay-$name.log"
  sed -n '/^replay of/,$p' "$work/replay-$name.log"
}
replay write -allow-write
sum=$(ls -d "$fa"/replay/"$save"-* | tail -1)/summary.json
jq -e '.steps[] | select(.method == "POST" and (.endpoint | test("/api/profile"))) | select(.status == 200 and (.refreshed | index("header:x-csrf-token")))' "$sum" >/dev/null ||
  fail "replay: the save did not get 200 with its token fresh: $(jq -c '.steps' "$sum")"
replay read
grep -q "POST /api/profile" "$work/server-replay-read.log" && fail "replay without -allow-write sent the save"
grep -q "a write" "$work/replay-read.log" || fail "replay without -allow-write: the save is not said skipped"
replay dry -allow-write -dry-run
[ -s "$work/server-replay-dry.log" ] && fail "a dry replay reached the server"

echo "== G. CDN/WAF blocks (round 25H, -on-block): a rule marks its request, a ban gives the host up"
# G1. authz, every request 1006: the probe is blocked, its control (GET /)
# too: the host is given up, and with it the run; two requests, and the
# blocked probe never reads as a dead session.
TESTBED_CF_BLOCK=1006 ./testbed/run.sh start authz-app >/dev/null
authz cf1006 -max 50
jq -e '(.stopped | test("every host is blocked")) and .sent == 2 and (.hosts_blocked["127.0.0.1:8770"] | test("1006"))' "$work/authz-cf1006/authz.json" >/dev/null ||
  fail "G1 authz 1006: $(jq -c '{sent, stopped, hosts_blocked, summary}' "$work/authz-cf1006/authz.json")"
[ "$(wc -l <"$work/server-cf1006.log")" = 2 ] || fail "G1 authz 1006: server saw $(wc -l <"$work/server-cf1006.log") requests, want 2"
grep -q "session is dead" "$work/authz-cf1006.log" && fail "G1 authz 1006: a vendor's block read as a dead session"
grep -q "host given up: 127.0.0.1:8770" "$work/authz-cf1006.log" || fail "G1 authz 1006: the host given up is not said"

# verify on verify-app (testbed/apps/verify-app/README.txt), under a rule.
vf() { # name cf-block flags...
  local name=$1 cf=$2
  shift 2
  TESTBED_CF_BLOCK=$cf ./testbed/run.sh start verify-app >/dev/null
  rm -rf "$work/vf-$name"
  mkdir -p "$work/vf-$name/127.0.0.1/anon"
  cp testbed/apps/verify-app/catalog.jsonl "$work/vf-$name/127.0.0.1/anon/endpoints.jsonl"
  local n
  n=$(wc -l <"${TESTBED_LOG}")
  ./bin/jsharvest verify -o "$work/vf-$name" -target 127.0.0.1 -scope fqdn -rate 50 "$@" >"$work/verify-$name.log" 2>&1 ||
    fail "verify $name exit $?: $(tail -2 "$work/verify-$name.log")"
  since "$n" >"$work/server-verify-$name.log"
  vj="$work/vf-$name/127.0.0.1/anon/verify/verify.json"
}
by_path() { jq -c '[.results[] | {k: (.method + " " + .path), v: .verdict}] | sort_by(.k)' "$1"; }
# G2. no rule: the baseline the others are read against.
vf base ""
base_json=$vj
base_sent=$(jq .sent "$base_json")
jq -e '.stopped == null and .hosts_blocked == null and (.verdicts.waf_blocked // 0) == 0' "$base_json" >/dev/null || fail "G2 baseline: $(jq -c '{sent, stopped, verdicts}' "$base_json")"
# G3. a rule (1020) on /api/v1/items: that draft waf_blocked, one control
# request more, every other verdict as the baseline's, the run not stopped.
vf r1020 '1020:^/api/v1/items'
jq -e '.stopped == null and .hosts_blocked == null and ([.results[] | select(.verdict == "waf_blocked") | .path] == ["/api/v1/items"])' "$vj" >/dev/null ||
  fail "G3 1020: $(jq -c '{sent, stopped, hosts_blocked, verdicts}' "$vj")"
[ "$(jq .sent "$vj")" = $((base_sent + 1)) ] || fail "G3 1020: sent $(jq .sent "$vj"), want $((base_sent + 1)) (the baseline's and one control)"
[ "$(by_path "$vj" | jq -c 'map(select(.k != "GET /api/v1/items"))')" = "$(by_path "$base_json" | jq -c 'map(select(.k != "GET /api/v1/items"))')" ] ||
  fail "G3 1020: other verdicts changed: $(by_path "$vj")"
# G4. banned after 6 requests: the 7th is blocked, its control (the first
# read answered) too: 8 requests in all, the rest host_blocked, and no
# block page read as a route.
vf after '1006-after:6'
jq -e '(.stopped | test("every host is blocked")) and .sent == 8 and (.hosts_blocked["127.0.0.1:8770"] | test("1006")) and (.verdicts.host_blocked // 0) > 0' "$vj" >/dev/null ||
  fail "G4 1006-after:6: $(jq -c '{sent, stopped, hosts_blocked, verdicts}' "$vj")"
[ "$(wc -l <"$work/server-verify-after.log")" = 8 ] || fail "G4 1006-after:6: server saw $(wc -l <"$work/server-verify-after.log") requests, want 8"
jq -e '[.results[] | select(.verdict == "verified_alive" and .answer.status == 403)] | length == 0' "$vj" >/dev/null || fail "G4: a 403 block page read as alive"
# G5. one 429 (1015, Retry-After: 1): asked again after the wait; the
# baseline's verdicts, one request more.
vf r1015 '1015:3'
jq -e '.stopped == null and .hosts_blocked == null' "$vj" >/dev/null || fail "G5 1015: $(jq -c '{sent, stopped, hosts_blocked}' "$vj")"
[ "$(jq .sent "$vj")" = $((base_sent + 1)) ] || fail "G5 1015: sent $(jq .sent "$vj"), want $((base_sent + 1))"
[ "$(by_path "$vj")" = "$(by_path "$base_json")" ] || fail "G5 1015: verdicts differ from the baseline's: $(by_path "$vj")"
# G6. -on-block stop: the first block stops the run (no control request).
vf stop '1020:^/api/v1/items' -on-block stop
jq -e '(.stopped | test("1020")) and .hosts_blocked == null' "$vj" >/dev/null || fail "G6 stop: $(jq -c '{sent, stopped, hosts_blocked}' "$vj")"
tail -1 "$work/server-verify-stop.log" | grep -q "/api/v1/items" || fail "G6 stop: a request after the block: $(tail -1 "$work/server-verify-stop.log")"

[ $failed = 0 ] && echo "replay-check: ok"
exit $failed
