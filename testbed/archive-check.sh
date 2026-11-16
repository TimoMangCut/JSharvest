#!/usr/bin/env bash
# The 5.3 gate (docs/gd5-archive-design.md): jsharvest archive against
# archive-app's fake archives (history.json, served under /fake/ by the
# testbed): a Wayback CDX server with its troubles (a 503, a 429, a
# memento that moves, a gzip-coded one, the Internet Archive's offline
# page as a 200, a 502), OTX and Common Crawl. Every run lists with -since
# 2020-01-01: a script archived before, and only revisited since, is
# fetched at a revisit (round 16).
#   A. Today's crawl (-explore), then archive: historical.jsonl, the store
#      (alive, live_same, captures), the summary, the modes, no secret of
#      the archived URLs anywhere; the live checks: each old script's path
#      once, GET, never the URL with a token (testbed archivecheck).
#   B. Stopped in the middle (SIGINT), then run again: the same result, and
#      no memento fetched twice.
#   C. -live=false: nothing sent to the target.
# Usage: testbed/archive-check.sh   (exit 1 on failure)
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
work=${TESTBED_WORK}/archive-check
rm -rf "$work"
mkdir -p "$work"
trap './testbed/run.sh stop >/dev/null' EXIT
failed=0
fail() { echo "FAIL $*"; failed=1; }
app=testbed/apps/archive-app
out=$work/out
arch=$out/127.0.0.1/archive
export JSHARVEST_WAYBACK_URL=http://127.0.0.1:8770/fake/wayback JSHARVEST_OTX_URL=http://127.0.0.1:8770/fake/otx \
  JSHARVEST_CC_INDEX_URL=http://127.0.0.1:8770/fake/cc JSHARVEST_CC_DATA_URL=http://127.0.0.1:8770/fake/ccdata \
  JSHARVEST_URLSCAN_URL=http://127.0.0.1:8770/fake/urlscan
since() { tail -n +$(($1 + 1)) ${TESTBED_LOG}; }
archive() { # scale log flags...
  local scale=$1 log=$2
  shift 2
  JSHARVEST_ARCHIVE_SCALE=$scale ./bin/jsharvest archive -o "$out" -target 127.0.0.1 -sources wayback,otx,commoncrawl,urlscan -page-size 3 -since 2020-01-01 "$@" >"$log" 2>&1
}

echo "== A. crawl, then archive"
./testbed/run.sh start archive-app >/dev/null
./bin/jsharvest crawl -u http://127.0.0.1:8770/ -explore -o "$out" </dev/null >"$work/crawl.log" 2>&1 || fail "crawl"
./testbed/run.sh start archive-app >/dev/null # the fake archive's troubles, anew
n=$(wc -l <${TESTBED_LOG})
archive 0.01 "$work/a.log" || fail "archive: $(tail -2 "$work/a.log")"
since "$n" >"$work/server-a.log"
grep -E "^archive|^historical|^finding" "$work/a.log"
./bin/testbed archivecheck -dir "$arch" -truth "$app/archive.truth.json" -log "$work/server-a.log" || fail "archivecheck A"
cp "$arch/historical.jsonl" "$work/historical-a.jsonl"

echo "== B. stopped, then resumed"
rm -rf "$arch"
./testbed/run.sh start archive-app >/dev/null
n=$(wc -l <${TESTBED_LOG})
JSHARVEST_ARCHIVE_SCALE=0.2 ./bin/jsharvest archive -o "$out" -target 127.0.0.1 -sources wayback,otx,commoncrawl,urlscan -page-size 3 -since 2020-01-01 >"$work/b1.log" 2>&1 &
pid=$!
for _ in $(seq 240); do
  [ -s "$arch/done.log" ] && break
  sleep 0.25
done
kill -INT "$pid"
wait "$pid"
[ -s "$arch/done.log" ] || fail "the first run fetched nothing before the stop"
grep -q "stopped: run again to resume" "$work/b1.log" || fail "the stopped run does not say so: $(tail -1 "$work/b1.log")"
archive 0.01 "$work/b2.log" || fail "resumed archive: $(tail -2 "$work/b2.log")"
grep -q "resuming" "$work/b2.log" || fail "the second run did not resume"
since "$n" >"$work/server-b.log"
./bin/testbed archivecheck -dir "$arch" -truth "$app/archive.truth.json" || fail "archivecheck B"
cmp -s <(sort "$work/historical-a.jsonl") <(sort "$arch/historical.jsonl") || fail "resumed: another historical.jsonl"
twice=$(grep -E '^\S+ \S+ 200 GET /fake/wayback/web/' "$work/server-b.log" | awk '{print $5}' | sed 's#/fake/wayback/web/[0-9]*id_/##' | sort | uniq -d)
[ -z "$twice" ] || fail "mementos fetched twice: $twice"

echo "== B2. -max-pages, then the rest"
rm -rf "$arch"
./testbed/run.sh start archive-app >/dev/null
archive 0.01 "$work/b3.log" -max-pages 1 || fail "archive -max-pages 1: $(tail -2 "$work/b3.log")"
grep -q "more remain" "$work/b3.log" || fail "-max-pages: no note that more remain"
archive 0.01 "$work/b4.log" || fail "archive after -max-pages: $(tail -2 "$work/b4.log")"
./bin/testbed archivecheck -dir "$arch" -truth "$app/archive.truth.json" || fail "archivecheck B2: the pages after -max-pages were not listed"

echo "== C. -live=false"
rm -rf "$arch"
./testbed/run.sh start archive-app >/dev/null
n=$(wc -l <${TESTBED_LOG})
archive 0.01 "$work/c.log" -live=false || fail "archive -live=false: $(tail -2 "$work/c.log")"
since "$n" >"$work/server-c.log"
./bin/testbed archivecheck -dir "$arch" -truth "$app/archive.truth.json" -log "$work/server-c.log" -no-live || fail "archivecheck C"

if [ -n "${LIVE_ARCHIVE:-}" ]; then
  # The real Wayback, a little: example.com, no live check, two small pages.
  echo "== D. the real Wayback (LIVE_ARCHIVE=1)"
  env -u JSHARVEST_WAYBACK_URL ./bin/jsharvest archive -o "$work/real" -target example.com -sources wayback -live=false \
    -page-size 25 -max-pages 2 -max-files 3 >"$work/real.log" 2>&1 || fail "real Wayback: $(tail -2 "$work/real.log")"
  grep -E "^archive|^note" "$work/real.log"
  grep -q "listed wayback 50" "$work/real.log" || fail "real Wayback: not 50 captures listed"
fi

[ $failed = 0 ] && echo "archive-check: ok"
exit $failed
