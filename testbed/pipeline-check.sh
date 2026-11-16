#!/usr/bin/env bash
# Gate 17 (round 22B): the http engine's pipeline on pipe-app
# (testbed/apps/pipe-app/README.txt), under real-looking names.
#   1. app.jsh.test: the API description of the seed's origin and of the
#      API host the script names (/api-json of a NestJS, an OpenID
#      configuration), a JSON page observed, intel.json's server hints and
#      CORS note, run.json's page and tool requests; requests.jsonl agrees
#      with the server's log (reqcheck).
#   2. The archive's catalog fills today's line (EnrichFromArchive): an
#      offline rebuild (jsharvest endpoints), historical.jsonl untouched.
#   3. spa.jsh.test without and with -spa-boot (Chrome, guarded).
#   4. The output directory of a host on a port of its own (host_port), and
#      -target in its three forms.
# Usage: testbed/pipeline-check.sh   (exit 1 on failure)
set -uo pipefail
export TESTBED_LOG="${TESTBED_LOG:-bin/testbed.log}" TESTBED_PID="${TESTBED_PID:-bin/testbed.pid}" TESTBED_WORK="${TESTBED_WORK:-bin}"
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
. "$root/testbed/lib/env.sh"
ensure_go_in_path || exit 1
build_testbed_bins || exit 1
work=${TESTBED_WORK}/pipeline-check
rm -rf "$work"
mkdir -p "$work"
trap './testbed/run.sh stop >/dev/null' EXIT
failed=0
fail() { echo "FAIL $*"; failed=1; }
rules="MAP *.jsh.test 127.0.0.1"
crawl() { # name url args...
  local name=$1 u=$2
  shift 2
  timeout 600 ./bin/jsharvest crawl -u "$u" -host-resolver-rules "$rules" -archive=false -http-rate 50 -o "$work/$name" "$@" </dev/null >"$work/$name.log" 2>&1
}
./testbed/run.sh start pipe-app >/dev/null

echo "== 1. app.jsh.test (http engine)"
n=$(wc -l <"${TESTBED_LOG}")
crawl app http://app.jsh.test:8770/ || fail "app crawl exit $?"
app="$work/app/app.jsh.test_8770/anon"
[ -d "$app" ] || fail "no host_port directory: $(ls "$work/app")"
[ ! -e "$work/app/app.jsh.test" ] || fail "a bare-host directory too"
tail -n "+$((n + 1))" "${TESTBED_LOG}" >"$work/app.serverlog"
./bin/testbed reqcheck -host app.jsh.test:8770,api.jsh.test:8770 -log "$work/app.serverlog" -requests "$app/requests.jsonl" >"$work/app.reqcheck" 2>&1 ||
  fail "reqcheck: $(grep -c -E '^(MISSING|NOT ON SERVER|DUPLICATE)' "$work/app.reqcheck") line(s), see $work/app.reqcheck"
grep -q ' GET /api-json$' "$work/app.serverlog" || fail "the API host's /api-json was not asked"
jq -c '{requests, page_requests, internal_requests, endpoints, openapi: .http.openapi}' "$app/run.json"

echo "== 2. the archive's catalog fills a line (offline)"
mkdir -p "$work/app/app.jsh.test/archive"
printf '%s\n' '{"method":"GET","path":"{}/api/boot-status","status":"static","kind":"fetch","query":["verbose"],"confidence":"code"}' \
  >"$work/app/app.jsh.test/archive/endpoints.jsonl"
printf '%s\n' '{"class":"in_current_code","method":"GET","path":"{}/api/boot-status","query":["verbose"],"scripts":[]}' \
  >"$work/app/app.jsh.test/archive/historical.jsonl"
before=$(sha256sum <"$work/app/app.jsh.test/archive/historical.jsonl")
n=$(wc -l <"${TESTBED_LOG}")
for t in app.jsh.test:8770 app.jsh.test_8770 http://app.jsh.test:8770/; do
  ./bin/jsharvest endpoints -o "$work/app" -target "$t" -json >"$work/endpoints.out" 2>"$work/endpoints.err" ||
    fail "jsharvest endpoints -target $t: $(tail -1 "$work/endpoints.err")"
done
[ "$(sha256sum <"$work/app/app.jsh.test/archive/historical.jsonl")" = "$before" ] || fail "historical.jsonl changed"
[ "$(wc -l <"${TESTBED_LOG}")" = "$n" ] || fail "an offline rebuild sent requests"

echo "== 3. spa.jsh.test, without and with -spa-boot"
JSHARVEST_ENGINE=auto crawl spa0 http://spa.jsh.test:8770/ || fail "spa crawl exit $?"
JSHARVEST_ENGINE=auto crawl spa1 http://spa.jsh.test:8770/ -spa-boot || fail "spa -spa-boot crawl exit $?"
grep -qi 'chrome boots it' "$work/spa0.log" && fail "-spa-boot off, yet Chrome"

echo "== 4. checks"
./bin/testbed pipecheck -app "$app" -spa0 "$work/spa0/spa.jsh.test_8770/anon" -spa1 "$work/spa1/spa.jsh.test_8770/anon" ||
  fail "pipecheck"

[ $failed = 0 ] && echo "pipeline-check: PASS" || echo "pipeline-check: FAIL"
exit $failed
