#!/usr/bin/env bash
# Gate 18 (round 23): jsharvest export -drafts and jsharvest verify on
# verify-app (testbed/apps/verify-app/README.txt), from its catalog alone.
#   1. export -drafts with no traffic: a document's line left out.
#   2. verify -dry-run: nothing reaches the server.
#   3. verify (reads only): each trap's verdict; no write, logout,
#      destructive URL or third party reaches the server.
#   4. export -drafts again: the document's line, now verified, is in.
#   5. verify -allow-write: the one POST, the server's missing field.
# Usage: testbed/verify-check.sh   (exit 1 on failure)
set -uo pipefail
export TESTBED_LOG="${TESTBED_LOG:-bin/testbed.log}" TESTBED_PID="${TESTBED_PID:-bin/testbed.pid}" TESTBED_WORK="${TESTBED_WORK:-bin}"
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
. "$root/testbed/lib/env.sh"
ensure_go_in_path || exit 1
build_testbed_bins || exit 1
work=${TESTBED_WORK}/verify-check
rm -rf "$work"
mkdir -p "$work"
trap './testbed/run.sh stop >/dev/null' EXIT
failed=0
fail() { echo "FAIL $*"; failed=1; }
catalog() { # out
  mkdir -p "$1/127.0.0.1/anon"
  cp testbed/apps/verify-app/catalog.jsonl "$1/127.0.0.1/anon/endpoints.jsonl"
}
since() { tail -n "+$(($1 + 1))" "${TESTBED_LOG}"; }
verify() { # out mode args...
  local out=$1 mode=$2
  shift 2
  local n
  n=$(wc -l <"${TESTBED_LOG}")
  ./bin/jsharvest verify -o "$out" -target 127.0.0.1 -scope fqdn -rate 50 "$@" >"$out.log" 2>&1 || fail "verify $mode exit $?: $(tail -1 "$out.log")"
  since "$n" >"$out.serverlog"
  ./bin/testbed verifycheck -dir "$out/127.0.0.1/anon/verify" -log "$out.serverlog" -mode "$mode" || fail "verifycheck $mode"
}
./testbed/run.sh start verify-app >/dev/null

echo "== 1. export -drafts, no traffic"
catalog "$work/read"
./bin/jsharvest export -o "$work/read" -target 127.0.0.1 -drafts 2>"$work/export1.log" || fail "export -drafts: $(tail -1 "$work/export1.log")"
idx="$work/read/127.0.0.1/anon/export/drafts/index.json"
[ "$(jq -r '.drafts[] | select(.path == "/docs-only/ping") | .file // ""' "$idx")" = "" ] || fail "a document's line drafted before verify"
[ "$(jq -r '.drafts[] | select(.path == "/api/v1/items") | .file // ""' "$idx")" != "" ] || fail "no draft of /api/v1/items"
[ "$(jq -r '.drafts[] | select(.third_party) | .file // ""' "$idx" | tr -d '\n')" = "" ] || fail "a third party's line drafted"

echo "== 2. verify -dry-run"
catalog "$work/dry"
verify "$work/dry" dry -dry-run
[ -s "$work/dry/127.0.0.1/anon/verify/sent.jsonl" ] || fail "no plan in sent.jsonl"

echo "== 3. verify, reads only"
verify "$work/read" read

echo "== 4. export -drafts after verify"
./bin/jsharvest export -o "$work/read" -target 127.0.0.1 -drafts 2>"$work/export2.log" || fail "export -drafts again: $(tail -1 "$work/export2.log")"
[ "$(jq -r '.drafts[] | select(.path == "/docs-only/ping") | .file // ""' "$idx")" != "" ] || fail "the verified document's line not drafted"

echo "== 5. verify -allow-write"
catalog "$work/write"
verify "$work/write" write -allow-write

[ $failed = 0 ] && echo "verify-check: PASS" || echo "verify-check: FAIL"
exit $failed
