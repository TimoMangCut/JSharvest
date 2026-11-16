#!/usr/bin/env bash
# Gate 19 (round 24): end-to-end cross-check of ENH-01..ENH-13 on the five
# multi-host local fixtures served by `testbed crossserve`:
#   1. sub.jsh.test + jsh.test + api.jsh.test + ext.other.test (ENH-01, ENH-03, ENH-04a)
#   2. nest.jsh.test (ENH-02, ENH-09, ENH-13)
#   3. n8n.jsh.test (ENH-10, ENH-12)
#   4. Vite multi-chunk ESM + bundled Axios Basic auth (ENH-05, ENH-08)
#   5. dicom.jsh.test / and /covered (ENH-06, ENH-07, ENH-11)
# Usage: testbed/crosscheck-check.sh   (exit 1 on failure)
set -uo pipefail
export TESTBED_LOG="${TESTBED_LOG:-bin/testbed.log}" TESTBED_PID="${TESTBED_PID:-bin/testbed.pid}" TESTBED_WORK="${TESTBED_WORK:-bin}"
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
. "$root/testbed/lib/env.sh"
ensure_go_in_path || exit 1
build_testbed_bins || exit 1
work=${TESTBED_WORK}/crosscheck-check
rm -rf "$work"
mkdir -p "$work"

stop_server() {
  if [ -f "$root/$TESTBED_PID" ]; then
    kill "$(cat "$root/$TESTBED_PID")" 2>/dev/null || true
    rm -f "$root/$TESTBED_PID"
  fi
}
trap stop_server EXIT
stop_server
nohup "$root/bin/testbed" crossserve -addr 127.0.0.1:8770 >"$root/$TESTBED_LOG" 2>&1 &
echo $! >"$root/$TESTBED_PID"
sleep 0.5

failed=0
fail() { echo "FAIL $*"; failed=1; }
since() { tail -n "+$(($1 + 1))" "$root/$TESTBED_LOG"; }
rules="MAP *.jsh.test 127.0.0.1, MAP jsh.test 127.0.0.1, MAP ext.other.test 127.0.0.1"
proxy="http://127.0.0.1:8770"

echo "== 1 & 4. sub.jsh.test + api.jsh.test + Vite ESM + Axios Basic"
n=$(wc -l <"$root/$TESTBED_LOG")
timeout 180 ./bin/jsharvest crawl -u http://sub.jsh.test:8770/ -engine cdp -depth 1 -scope rdn -page-scope auto \
  -host-resolver-rules "$rules" -archive=false -o "$work/sub" </dev/null >"$work/sub-crawl.log" 2>&1 || fail "sub crawl: $(tail -2 "$work/sub-crawl.log")"
./bin/jsharvest export -o "$work/sub" -target sub.jsh.test:8770 -drafts >"$work/sub-export.log" 2>&1 || fail "sub export: $(tail -2 "$work/sub-export.log")"
./bin/jsharvest verify -o "$work/sub" -target sub.jsh.test:8770 -proxy "$proxy" -rate 50 >"$work/sub-verify.log" 2>&1 || fail "sub verify: $(tail -2 "$work/sub-verify.log")"
since "$n" >"$work/sub.serverlog"

echo "== 2. nest.jsh.test (method-scoped 404, OpenAPI security, parent canary)"
timeout 120 ./bin/jsharvest crawl -u http://nest.jsh.test:8770/ -engine http -host-resolver-rules "$rules" -archive=false -http-rate 50 \
  -o "$work/nest" </dev/null >"$work/nest-crawl.log" 2>&1 || fail "nest crawl: $(tail -2 "$work/nest-crawl.log")"
./bin/jsharvest verify -o "$work/nest" -target nest.jsh.test:8770 -proxy "$proxy" -rate 50 >"$work/nest-verify.log" 2>&1 || fail "nest verify: $(tail -2 "$work/nest-verify.log")"

echo "== 3. n8n.jsh.test (dynamic baseURL + observed /rest + bare strings)"
timeout 180 ./bin/jsharvest crawl -u http://n8n.jsh.test:8770/ -engine cdp -host-resolver-rules "$rules" -archive=false \
  -o "$work/n8n" </dev/null >"$work/n8n-crawl.log" 2>&1 || fail "n8n crawl: $(tail -2 "$work/n8n-crawl.log")"
./bin/jsharvest verify -o "$work/n8n" -target n8n.jsh.test:8770 -proxy "$proxy" -rate 50 >"$work/n8n-verify.log" 2>&1 || fail "n8n verify: $(tail -2 "$work/n8n-verify.log")"
cp -r "$work/n8n" "$work/n8n-str"
./bin/jsharvest verify -o "$work/n8n-str" -target n8n.jsh.test:8770 -include-strings -proxy "$proxy" -rate 50 >"$work/n8n-str-verify.log" 2>&1 || fail "n8n verify -include-strings: $(tail -2 "$work/n8n-str-verify.log")"

echo "== 5. dicom.jsh.test / and /covered (pointer-events:none, DICOM folder, covered fallback)"
timeout 180 ./bin/jsharvest crawl -u http://dicom.jsh.test:8770/ -engine cdp -explore -guard on -host-resolver-rules "$rules" -archive=false \
  -o "$work/dicom" </dev/null >"$work/dicom-crawl.log" 2>&1 || fail "dicom crawl: $(tail -2 "$work/dicom-crawl.log")"
timeout 180 ./bin/jsharvest crawl -u http://dicom.jsh.test:8770/covered -engine cdp -explore -guard on -host-resolver-rules "$rules" -archive=false \
  -o "$work/covered" </dev/null >"$work/covered-crawl.log" 2>&1 || fail "covered crawl: $(tail -2 "$work/covered-crawl.log")"

echo "== 6. redir.jsh.test -> www.jsh.test (httpcrawl seed 302 redirect, hardcoded Basic, export -redact -drafts)"
n=$(wc -l <"$root/$TESTBED_LOG")
timeout 60 ./bin/jsharvest crawl -u http://redir.jsh.test:8770/ -engine http -depth 1 -scope rdn -page-scope auto \
  -host-resolver-rules "$rules" -archive=false -http-rate 50 -o "$work/redir" </dev/null >"$work/redir-crawl.log" 2>&1 || fail "redir crawl: $(tail -2 "$work/redir-crawl.log")"
since "$n" >"$work/redir.serverlog"
./bin/jsharvest export -o "$work/redir" -target redir.jsh.test:8770 -drafts >"$work/redir-export.log" 2>&1 || fail "redir export: $(tail -2 "$work/redir-export.log")"
cp -r "$work/redir" "$work/redir-red"
./bin/jsharvest export -o "$work/redir-red" -target redir.jsh.test:8770 -redact -drafts >"$work/redir-red-export.log" 2>&1 || fail "redir redact export: $(tail -2 "$work/redir-red-export.log")"

echo "== 7. wedge.jsh.test + dead.jsh.test (recycleTab + resolver circuit breaker + slow body > 8s)"
n=$(wc -l <"$root/$TESTBED_LOG")
timeout 180 ./bin/jsharvest crawl -u http://wedge.jsh.test:8770/ -engine cdp -depth 1 -scope rdn -page-scope auto \
  -nav-timeout 3s -idle 500ms -idle-max 2s -resolve-rate 50 \
  -host-resolver-rules "$rules" -archive=false -o "$work/wedge" </dev/null >"$work/wedge-crawl.log" 2>&1 || fail "wedge crawl: $(tail -2 "$work/wedge-crawl.log")"
since "$n" >"$work/wedge.serverlog"

echo "== 8. tsmap.jsh.test (3-module Via + barrel export * + 2-arg get/post + streamRequest + TS/Vue sourcemap + -include-source-only)"
timeout 180 ./bin/jsharvest crawl -u http://tsmap.jsh.test:8770/ -engine cdp \
  -host-resolver-rules "$rules" -archive=false -o "$work/tsmap" </dev/null >"$work/tsmap-crawl.log" 2>&1 || fail "tsmap crawl: $(tail -2 "$work/tsmap-crawl.log")"
./bin/jsharvest verify -o "$work/tsmap" -target tsmap.jsh.test:8770 -proxy "$proxy" -rate 50 >"$work/tsmap-verify.log" 2>&1 || fail "tsmap verify: $(tail -2 "$work/tsmap-verify.log")"
cp -r "$work/tsmap" "$work/tsmap-src"
./bin/jsharvest verify -o "$work/tsmap-src" -target tsmap.jsh.test:8770 -include-source-only -proxy "$proxy" -rate 50 >"$work/tsmap-src-verify.log" 2>&1 || fail "tsmap verify -include-source-only: $(tail -2 "$work/tsmap-src-verify.log")"

echo "== score"
./bin/testbed crosscheck \
  -sub "$work/sub/sub.jsh.test_8770/anon" \
  -sub-log "$work/sub.serverlog" \
  -nest "$work/nest/nest.jsh.test_8770/anon" \
  -n8n "$work/n8n/n8n.jsh.test_8770/anon" \
  -n8n-strings "$work/n8n-str/n8n.jsh.test_8770/anon/verify/verify.json" \
  -dicom "$work/dicom/dicom.jsh.test_8770/anon" \
  -covered "$work/covered/dicom.jsh.test_8770/anon" \
  -redir "$work/redir/redir.jsh.test_8770/anon" \
  -redir-redacted "$work/redir-red/redir.jsh.test_8770/anon" \
  -redir-log "$work/redir.serverlog" \
  -wedge "$work/wedge/wedge.jsh.test_8770/anon" \
  -wedge-log "$work/wedge.serverlog" \
  -tsmap "$work/tsmap/tsmap.jsh.test_8770/anon" \
  -tsmap-source-only "$work/tsmap-src/tsmap.jsh.test_8770/anon/verify/verify.json" || fail "crosscheck"

[ $failed = 0 ] && echo "crosscheck-check: PASS" || echo "crosscheck-check: FAIL"
exit $failed
