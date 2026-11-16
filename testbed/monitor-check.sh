#!/usr/bin/env bash
# The 5.4 gate (docs/gd5-monitor-design.md): jsharvest monitor between the
# builds of monitor-app (dist, dist-v2), and its noise.
#   A. v1 crawled three times, monitor after each: a baseline, then no
#      change of low or above.
#   B. v2: exactly the changes of monitor.truth.json at low and above;
#      -fail-on high exits 5; the webhook gets counts, no path.
#   C. monitor again, no crawl: nothing new.
#   D. v2 with -max-pages 1 (another config): not comparable, nothing at
#      low or above, no baseline moved; then v2 in full: no change (no
#      flood of new ones).
#   D3. a batch (-urls): every run of it is taken, nothing reported, and
#      it does not compare with (nor become the baseline of) single crawls.
#   E. a webhook that fails: its URL never in the output, the payload kept
#      and sent on the next run.
#   F. monitor sends nothing to the target; files 0600, directories 0700.
# Usage: testbed/monitor-check.sh   (exit 1 on failure)
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
work=${TESTBED_WORK}/monitor-check
rm -rf "$work"
mkdir -p "$work"
trap './testbed/run.sh stop >/dev/null' EXIT
failed=0
fail() { echo "FAIL $*"; failed=1; }
out=$work/out
mon=$out/127.0.0.1/monitor
truth=testbed/apps/monitor-app/monitor.truth.json
export TESTBED_WEBHOOK_LOG="$root/$work/webhook.jsonl"
build() { # dist
  TESTBED_DIST=$1 TESTBED_WEBHOOK_LOG="$TESTBED_WEBHOOK_LOG" ./testbed/run.sh start monitor-app >/dev/null
}
crawl() { # flags...
  ./bin/jsharvest crawl -u http://127.0.0.1:8770/ -o "$out" "$@" </dev/null >>"$work/crawl.log" 2>&1 || fail "crawl $*"
}
monitor() { # log flags... ; the server's log lines it caused go to <log>.server
  local log=$1 n
  shift
  n=$(wc -l <${TESTBED_LOG})
  ./bin/jsharvest monitor -o "$out" -target 127.0.0.1 "$@" >"$log" 2>&1
  local code=$?
  tail -n +$((n + 1)) ${TESTBED_LOG} >"$log.server"
  return $code
}
# changes at low and above of the last snapshot, as "severity kind key".
latest() {
  local snap
  snap=$(jq -r .snapshot "$mon/changes.jsonl" 2>/dev/null | tail -1)
  jq -r --arg s "$snap" 'select(.snapshot == $s and .severity != "info") | "\(.severity) \(.kind) \(.key)"' "$mon/changes.jsonl" 2>/dev/null | sort
}

echo "== A. v1, three times"
build dist
crawl
monitor "$work/a1.log" || fail "monitor a1"
grep -q "first runs, the baseline" "$work/a1.log" || fail "a1: no baseline"
for i in 2 3; do
  crawl
  monitor "$work/a$i.log" || fail "monitor a$i"
  grep -q "0 high, 0 medium, 0 low" "$work/a$i.log" || fail "v1 again (a$i): $(head -1 "$work/a$i.log")"
done

echo "== B. v2"
build dist-v2
crawl
monitor "$work/b.log" -fail-on high
code=$?
[ "$code" = 5 ] || fail "-fail-on high: exit $code, want 5"
want=$(jq -r '.v1_to_v2[] | "\(.severity) \(.kind) \(.key)"' "$truth" | sort)
got=$(latest)
[ "$got" = "$want" ] || fail "v1 to v2:$(diff <(echo "$want") <(echo "$got") | sed 's/^/  /')"
grep -q "high" "$work/b.log" && echo "$(grep -c '^  ' "$work/b.log") changes listed"

echo "== C. monitor again, no crawl"
monitor "$work/c.log" || fail "monitor c"
grep -q "no new crawl" "$work/c.log" || fail "c: $(head -1 "$work/c.log")"

echo "== D. a partial run, then a full one"
crawl -max-pages 1
monitor "$work/d1.log" || fail "monitor d1"
grep -q "0 high, 0 medium, 0 low" "$work/d1.log" || fail "a partial run reported: $(head -1 "$work/d1.log")"
grep -q "not comparable" "$work/d1.log" || fail "d1: not said not comparable"
crawl
monitor "$work/d2.log" || fail "monitor d2"
grep -q "0 high, 0 medium, 0 low" "$work/d2.log" || fail "after a partial run, a full one reported: $(sed -n '1,4p' "$work/d2.log")"

echo "== D3. a batch (-urls): every run of it taken"
printf 'http://127.0.0.1:8770/index.html?from=batch\nhttp://127.0.0.1:8770/\n' >"$work/urls.txt"
./bin/jsharvest crawl -urls "$work/urls.txt" -o "$out" </dev/null >>"$work/crawl.log" 2>&1 || fail "crawl -urls"
monitor "$work/d3.log" || fail "monitor d3"
snap=$(ls -t "$mon"/snapshots/*.json | head -1)
[ "$(jq '[.roles[] | select(.role == "anon") | .runs[]] | length' "$snap")" = 2 ] || fail "the batch's runs: $(jq -c '.roles' "$snap")"
grep -q "0 high, 0 medium, 0 low" "$work/d3.log" || fail "a batch of the same build reported: $(sed -n '1,4p' "$work/d3.log")"
grep -q "other start URLs" "$work/d3.log" || fail "a batch compared with a single crawl's baseline"

echo "== E. a webhook that fails, then works"
build dist
crawl
JSHARVEST_WEBHOOK="http://127.0.0.1:1/hooks/T0KEN-of-the-chat" monitor "$work/e1.log"
grep -q "T0KEN" "$work/e1.log" && fail "the webhook's URL is in the output"
[ -f "$mon/pending-webhook.json" ] || fail "the failed payload was not kept"
build dist-v2
crawl
rm -f "$work/webhook.jsonl"
JSHARVEST_WEBHOOK="http://127.0.0.1:8770/fake-webhook" monitor "$work/e2.log"
[ "$(wc -l <"$work/webhook.jsonl" 2>/dev/null)" = 2 ] || fail "webhook: $(wc -l <"$work/webhook.jsonl" 2>/dev/null) payloads, want 2 (the kept one, and this run's)"
grep -qE '/api/|admin|include_deleted' "$work/webhook.jsonl" && fail "the webhook got paths (counts only by default)"
jq -e 'select(.counts.high >= 1)' "$work/webhook.jsonl" >/dev/null || fail "the webhook's counts: $(head -c 300 "$work/webhook.jsonl")"

echo "== F. nothing to the target, modes"
cat "$work"/*.log.server | grep -v "/fake-webhook" | grep -q . && fail "monitor sent requests to the target: $(cat "$work"/*.log.server | grep -v /fake-webhook | head -2)"
find "$mon" -type f ! -perm 600 | grep -q . && fail "files not 0600: $(find "$mon" -type f ! -perm 600 | head -2)"
find "$mon" -type d ! -perm 700 | grep -q . && fail "directories not 0700"

[ $failed = 0 ] && echo "monitor-check: ok"
exit $failed
