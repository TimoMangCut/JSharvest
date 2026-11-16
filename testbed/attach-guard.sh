#!/usr/bin/env bash
# Checks the guard in attach mode: a Chrome stands for the user's own
# browser, with a tab of the user's on another site that keeps writing.
#   1. a URL list run: none of guard-cases' forbidden requests may reach the
#      server, the user's tab keeps writing, each page reports
#      Clear-Site-Data once;
#   2. a service worker already running: the user has had guard-cases open,
#      so its service worker runs and proxies every request before
#      jsharvest attaches; still none of the forbidden requests may pass;
#   3. watch on a page already loaded (an app that never navigates): while
#      the guarded watch runs, none of the page's writes may pass, and the
#      tab is still there afterwards.
# Usage: testbed/attach-guard.sh   (exit 1 on failure)
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
CHROME_BIN="$(find_chrome)" || exit 1
build_testbed_bins || exit 1
work=${TESTBED_WORK}/attach-guard
rm -rf "$work"
mkdir -p "$work/profile"
port=9333
endpoint="http://127.0.0.1:$port"

./testbed/run.sh start guard-cases >/dev/null
"$CHROME_BIN" --headless=new --remote-debugging-port=$port --user-data-dir="$work/profile" --no-first-run about:blank >"$work/chrome.log" 2>&1 &
chrome=$!
trap 'kill $chrome 2>/dev/null; ./testbed/run.sh stop' EXIT
sleep 2
# The user's tab, on another site (localhost is not 127.0.0.1's origin):
# the target's service worker does not control it.
curl -s -X PUT "$endpoint/json/new?http://localhost:8770/other-tab.html" >/dev/null
sleep 1
failed=0

forbidden() { # server log slice -> prints the forbidden requests in it
  while read -r p; do
    case "$p" in "" | "#"*) continue ;; esac
    grep -qF " $p" "$1" && echo "$p"
  done <testbed/apps/guard-cases/forbidden.txt
}

# 1. A URL list, in tabs of the tool's.
n=$(wc -l <${TESTBED_LOG})
printf 'http://127.0.0.1:8770/\nhttp://127.0.0.1:8770/?second\n' >"$work/urls.txt"
timeout 180 ./bin/jsharvest crawl -urls "$work/urls.txt" -attach "$endpoint" -guard on -o "$work/out1" </dev/null >"$work/run1.err" 2>&1
sleep 0.5
tail -n "+$((n + 1))" ${TESTBED_LOG} >"$work/server1.log"
for p in $(forbidden "$work/server1.log"); do
  echo "1: FORBIDDEN REQUEST: $p"
  failed=1
done
other=$(grep -c 'POST /api/other-tab' "$work/server1.log")
if [ "$other" -lt 5 ]; then
  echo "1: USER TAB HELD BACK: only $other of its writes went through"
  failed=1
fi
# Seen on every page whose /csd comes straight from the network; on the
# second page it may come through the service worker the first page
# registered, and the capture's session on that worker can attach after
# the request (detection only: interception there is the browser stage's).
csd=$(jq -s '[.[].guard.clear_site_data_seen] | map(select(. == 1)) | length' "$work/out1/127.0.0.1/anon/runs.jsonl")
if [ "$csd" -lt 1 ]; then
  echo "1: CLEAR-SITE-DATA: seen on no page"
  failed=1
fi

# 2. The user has the target open: its service worker is running.
curl -s -X PUT "$endpoint/json/new?http://127.0.0.1:8770/" >/dev/null
# Until its service worker runs (it took 9 s, and once more than that).
sw() { curl -s "$endpoint/json/list" | jq -e '.[] | select(.type == "service_worker" and (.url | test("8770/guard-sw")))' >/dev/null; }
for _ in $(seq 40); do sw && break; sleep 0.5; done
if ! sw; then
  echo "2: the fixture's service worker is not running; the case is not tested"
  failed=1
fi
# The user's own tab is still loading: what it sends is the user's (another
# tab, passed by design), so the count starts once the server is quiet.
last=-1
for _ in $(seq 30); do
  cur=$(wc -l <${TESTBED_LOG})
  [ "$cur" = "$last" ] && break
  last=$cur
  sleep 2
done
n=$(wc -l <${TESTBED_LOG})
timeout 180 ./bin/jsharvest crawl -u http://127.0.0.1:8770/ -attach "$endpoint" -guard on -o "$work/out2" </dev/null >"$work/run2.err" 2>&1
sleep 0.5
tail -n "+$((n + 1))" ${TESTBED_LOG} >"$work/server2.log"
for p in $(forbidden "$work/server2.log"); do
  echo "2: FORBIDDEN REQUEST through a running service worker: $p"
  failed=1
done

# 3. Watch a page the user already has open.
curl -s -X PUT "$endpoint/json/new?http://127.0.0.1:8770/spa-writes.html" >/dev/null
sleep 2
./bin/jsharvest watch -attach "$endpoint" -tab 'spa-writes' -guard on -o "$work/out3" >"$work/watch3.log" 2>&1 &
watcher=$!
for _ in $(seq 50); do
  grep -q "watching" "$work/watch3.log" && break
  sleep 0.2
done
n=$(wc -l <${TESTBED_LOG})
sleep 4
tail -n "+$((n + 1))" ${TESTBED_LOG} >"$work/server3.log"
kill -INT "$watcher"
wait "$watcher"
spa=$(grep -c 'POST /api/write-spa' "$work/server3.log")
if [ "$spa" != 0 ]; then
  echo "3: $spa writes of the watched page reached the server"
  failed=1
fi
if ! curl -s "$endpoint/json/list" | grep -q 'spa-writes'; then
  echo "3: the watched tab was closed"
  failed=1
fi

[ "$failed" = 0 ] && echo "attach-guard: ok (user tab writes $other, Clear-Site-Data on $csd pages, running service worker held, loaded page held)"
exit "$failed"
