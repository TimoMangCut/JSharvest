#!/usr/bin/env bash
# The 4.8 gate: jsharvest export of flows-app's recorded runs, checked by
# testbed exportcheck (see docs/gd4-export-design.md, 7 and 9).
#   off: the run with the guard off. Every step's request has a raw file
#        in its flow, the files say what the log says, the HARs import,
#        the ffuf files are their request with one value replaced,
#        params.jsonl has the truth's params; replayed, the endpoints'
#        GETs get the recorded status (and body where it is stable), the
#        profile's save gets 200 (its cookie and CSRF token are in the file)
#        and the worker's export gets 200 (its cookie borrowed).
#   red: the same export with -redact: no secret of the log in it, and the
#        same two replays are refused (403, 401).
#   on:  the run with the guard on: the writes are .held.http files, and
#        the held save, replayed, gets 200 (a cookie borrowed, its token).
#   No export sends anything: the server's log does not grow while they run.
# Usage: testbed/export-check.sh   (exit 1 on failure)
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
work=${TESTBED_WORK}/export-check
rm -rf "$work"
mkdir -p "$work"
failed=0
fail() { echo "FAIL $*"; failed=1; }
app=testbed/apps/flows-app

echo "== record: guard off, then on"
testbed/flows-check.sh >"$work/flows-off.log" 2>&1 || fail "flows-check (guard off): $(tail -2 "$work/flows-off.log")"
cp -r ${TESTBED_WORK}/flows-check/out "$work/off"
GUARD=on testbed/flows-check.sh >"$work/flows-on.log" 2>&1 || fail "flows-check (guard on): $(tail -2 "$work/flows-on.log")"
cp -r ${TESTBED_WORK}/flows-check/out "$work/on"

./testbed/run.sh start flows-app >/dev/null
trap './testbed/run.sh stop >/dev/null' EXIT
n=$(wc -l <${TESTBED_LOG})
off=$work/off/127.0.0.1/anon on=$work/on/127.0.0.1/anon
./bin/jsharvest export -o "$work/off" -target 127.0.0.1 2>"$work/export-off.log" || fail "export off: $(tail -1 "$work/export-off.log")"
./bin/jsharvest export -o "$work/off" -target 127.0.0.1 -redact -dest "$work/red" 2>"$work/export-red.log" || fail "export red"
./bin/jsharvest export -o "$work/on" -target 127.0.0.1 2>"$work/export-on.log" || fail "export on: $(tail -1 "$work/export-on.log")"
# Again over its own export: replaced in place.
./bin/jsharvest export -o "$work/off" -target 127.0.0.1 2>>"$work/export-off.log" || fail "export off, again"
# Never over a directory it did not write.
mkdir -p "$work/mine" && echo keep >"$work/mine/notes.txt"
./bin/jsharvest export -o "$work/off" -target 127.0.0.1 -dest "$work/mine" 2>/dev/null && fail "export replaced a directory it did not write"
[ -f "$work/mine/notes.txt" ] || fail "export removed a file it did not write"
# OpenAPI: alone, again (the same bytes), redacted, and along with the files.
./bin/jsharvest export -o "$work/off" -target 127.0.0.1 -format openapi -dest "$work/oa" 2>"$work/export-oa.log" || fail "export openapi: $(tail -1 "$work/export-oa.log")"
./bin/jsharvest export -o "$work/off" -target 127.0.0.1 -format openapi -dest "$work/oa2" 2>>"$work/export-oa.log" || fail "export openapi, again"
cmp -s "$work/oa/openapi.json" "$work/oa2/openapi.json" || fail "openapi.json differs between two runs"
./bin/jsharvest export -o "$work/off" -target 127.0.0.1 -format openapi -dest "$work/oa2" 2>>"$work/export-oa.log" || fail "export openapi, over its own directory"
./bin/jsharvest export -o "$work/off" -target 127.0.0.1 -format openapi -redact -dest "$work/oa-red" 2>>"$work/export-oa.log" || fail "export openapi -redact"
./bin/jsharvest export -o "$work/off" -target 127.0.0.1 -format all -dest "$work/all" 2>>"$work/export-oa.log" || fail "export -format all"
[ -f "$work/all/manifest.json" ] && cmp -s "$work/all/openapi.json" "$work/oa/openapi.json" || fail "export -format all: no manifest.json, or another openapi.json"
./bin/jsharvest export -o "$work/off" -target 127.0.0.1 -dest "$work/oa2" 2>>"$work/export-oa.log" || fail "a plain export did not replace an openapi-only directory"
./bin/jsharvest export -o "$work/off" -target 127.0.0.1 -format yaml 2>/dev/null && fail "export took -format yaml"
[ "$(wc -l <${TESTBED_LOG})" = "$n" ] || fail "the exports sent requests: $(tail -n +$((n + 1)) ${TESTBED_LOG} | head -3)"

check() { # name flags...
  local name=$1
  shift
  echo "== $name"
  ./bin/testbed exportcheck -truth "$app/export.truth.json" -steps "$app/flows.truth.json" -replay http://127.0.0.1:8770 "$@" \
    >"$work/check-$name.log" 2>&1 || fail "exportcheck $name"
  cat "$work/check-$name.log"
}
check off -export "$off/export" -log "$off"
check red -export "$work/red" -log "$off" -redacted
openapi_check() { # name file flags...
  local name=$1 file=$2
  shift 2
  echo "== openapi $name"
  ./bin/testbed exportcheck -truth "$app/export.truth.json" -openapi "$file" -log "$off" "$@" >"$work/check-openapi-$name.log" 2>&1 || fail "exportcheck openapi $name"
  cat "$work/check-openapi-$name.log"
}
openapi_check off "$work/oa/openapi.json"
openapi_check red "$work/oa-red/openapi.json"
check on -export "$on/export" -log "$on" -held

[ $failed = 0 ] && echo "export-check: ok"
exit $failed
