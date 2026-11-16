#!/usr/bin/env bash
# The 4.7 gate: jsharvest diff tells what each role of role-app reaches.
#   A. anon, user and admin crawled alike (-depth 1 -explore): diff.json
#      has every item of roles.truth.json with its class and lowest role,
#      and nothing else (testbed rolescore); only the logins post.
#   B. user crawled with -max-pages 1: what lies on the admin page is
#      not_covered for user, never higher_only (no claim without a look).
#   C. anon crawled without -explore: a warning says the roles were not
#      crawled alike.
#   D. anon crawled by the HTTP engine (crawl's default for anon) next to
#      user and admin crawled with Chrome: one note that anon's scripts
#      never ran, no -no-debugger or explore mismatch (NEW-D14-02).
# Usage: testbed/roles-check.sh   (exit 1 on failure)
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
work=${TESTBED_WORK}/roles-check
rm -rf "$work"
mkdir -p "$work"
trap './testbed/run.sh stop >/dev/null' EXIT
failed=0
fail() { echo "FAIL $*"; failed=1; }
export ROLE_APP_USER=member@app.test ROLE_APP_ADMIN=admin@app.test ROLE_APP_PASS=hunter22
crawl() { # out role extra-flags...
  local out=$1 role=$2
  shift 2
  local r=()
  [ "$role" != anon ] && r=(-role "$role")
  timeout 900 ./bin/jsharvest crawl -u http://127.0.0.1:8770/ "${r[@]}" -profiles "$work/profiles" -page-rate 10 -o "$out" "$@" \
    </dev/null >"$out-$role.log" 2>&1 || fail "crawl $role ($out) exit $?"
}

./testbed/run.sh start role-app >/dev/null
n=$(wc -l <${TESTBED_LOG})
for r in user admin; do
  ./bin/jsharvest login -u http://127.0.0.1:8770/login -role "$r" -profiles "$work/profiles" \
    -steps "testbed/apps/role-app/$r.steps.json" >"$work/login-$r.log" 2>&1 || fail "login $r"
done

echo "== A. three roles alike"
for r in anon user admin; do crawl "$work/a" "$r" -depth 1 -explore; done
./bin/jsharvest diff -o "$work/a" -target 127.0.0.1 2>"$work/a-diff.log" || fail "diff exit $?"
cat "$work/a-diff.log"
[ "$(stat -c %a "$work/a/127.0.0.1/diff.json")" = 600 ] || fail "diff.json is not 0600"
./bin/testbed rolescore -truth testbed/apps/role-app/roles.truth.json -diff "$work/a/127.0.0.1/diff.json" | grep -v '^  pass' || fail "roles score"

echo "== B. user cut short"
mkdir -p "$work/b/127.0.0.1"
cp -r "$work/a/127.0.0.1/anon" "$work/a/127.0.0.1/admin" "$work/b/127.0.0.1/"
crawl "$work/b" user -depth 1 -explore -max-pages 1
./bin/jsharvest diff -o "$work/b" -target 127.0.0.1 2>/dev/null || fail "diff B exit $?"
for k in '"/ra/admin"' '"click /ra/admin #rotate"'; do
  c=$(jq -r ".items[] | select(.key == $k) | .class" "$work/b/127.0.0.1/diff.json")
  [ "$c" = not_covered ] || fail "B: $k is ${c:-missing}, want not_covered (user never went there)"
done
c=$(jq -r '.items[] | select(.key | endswith("/api/ra/admin/keys")) | .class' "$work/b/127.0.0.1/diff.json")
[ "$c" = not_covered ] || fail "B: POST /api/ra/admin/keys is ${c:-missing}, want not_covered"

echo "== C. anon without explore"
mkdir -p "$work/c/127.0.0.1"
cp -r "$work/a/127.0.0.1/user" "$work/a/127.0.0.1/admin" "$work/c/127.0.0.1/"
crawl "$work/c" anon -depth 1
./bin/jsharvest diff -o "$work/c" -target 127.0.0.1 2>/dev/null || fail "diff C exit $?"
jq -e '.warnings | any(test("anon and user were not crawled alike"))' "$work/c/127.0.0.1/diff.json" >/dev/null || fail "C: no warning about the unlike crawls"

echo "== D. anon by the HTTP engine"
mkdir -p "$work/d/127.0.0.1"
cp -r "$work/a/127.0.0.1/user" "$work/a/127.0.0.1/admin" "$work/d/127.0.0.1/"
crawl "$work/d" anon -depth 1 -engine http -archive=false
./bin/jsharvest diff -o "$work/d" -target 127.0.0.1 2>/dev/null || fail "diff D exit $?"
dj="$work/d/127.0.0.1/diff.json"
jq -e '.warnings | any(test("anon was crawled without a browser .* and user, admin with Chrome"))' "$dj" >/dev/null || fail "D: no note that anon was crawled without a browser"
jq -e '.warnings | any(test("anon: crawled with -no-debugger|anon and (user|admin) were not crawled alike"))' "$dj" >/dev/null &&
  fail "D: the engine's differences reported as a mismatch: $(jq -c .warnings "$dj")"

echo "== writes"
# GraphQL queries over POST read, and pass the guard; the mutation is held.
writes=$(tail -n "+$((n + 1))" ${TESTBED_LOG} | grep -E ' (POST|PUT|PATCH|DELETE) ' | grep -v -e ' POST /api/login$' -e ' POST /api/ra/graphql$')
[ -z "$writes" ] || fail "writes reached the server: $writes"
jq -e 'select(.url | endswith("/api/ra/graphql")) | select(.body // "" | contains("PurgeUsers")) | select(.outcome | startswith("held_back"))' \
  "$work/a/127.0.0.1/admin/requests.jsonl" >/dev/null || fail "the PurgeUsers mutation was not held back"

[ "$failed" = 0 ] && echo "roles gate: ok"
exit "$failed"
