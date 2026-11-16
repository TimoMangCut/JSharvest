#!/usr/bin/env bash
# The P2.3 gate (plan-28.md 3.3): one -proxy for every client of a run.
# The gate runs in a network namespace that has a loopback and nothing else
# (unshare -rn): a connection that does not go through the proxy has no
# route, and the names it uses (*.jsh.test) resolve only inside the proxy
# (testbed logproxy maps them to 127.0.0.1 and logs every request). The
# jsharvest processes have no host rules for those names.
#   1. crawl -engine http -proxy ... on archive-app, the archive after it
#      (the fake archive's name is a .jsh.test name too): the proxy's log
#      holds the page's requests and the archive's (/fake/wayback);
#      stderr says "proxy: http://127.0.0.1:8899"; run.json says why the
#      AIA is off.
#   2. archive -proxy ... (the fake archive serves its captures as the
#      target's: FAKE_ARCHIVE_REHOST; the live check asks the target through
#      the proxy and fetches something; HTTPS_PROXY/HTTP_PROXY point at a dead address:
#      the flag wins over the environment): the archive's requests are in
#      the proxy's log, and the run ends 0.
#   3. verify -proxy ... on verify-app's catalog, its host a .jsh.test name
#      (intel.json says it speaks http): plain requests, not tunnels, in the
#      proxy's log; the run ends 0.
#   4. the proxy comes from the environment alone (JSHARVEST_PROXY): the
#      same, and "-proxy none" turns it off (the proxy sees nothing).
# PASS when each ends as said, the log holds the requests of all three
# commands, and the log has no REFUSED or DIRECT line.
# Usage: testbed/proxy-check.sh   (exit 1 on failure; no browser)
set -uo pipefail
export TESTBED_LOG="${TESTBED_LOG:-bin/testbed.log}" TESTBED_PID="${TESTBED_PID:-bin/testbed.pid}" TESTBED_WORK="${TESTBED_WORK:-bin}"
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
. "$root/testbed/lib/env.sh"
ensure_go_in_path || exit 1
build_testbed_bins || exit 1
# Into the namespace: root there, loopback up, nothing else.
if [ -z "${PROXY_CHECK_NS:-}" ]; then
  if ! unshare -rn true 2>/dev/null; then
    echo "SKIP: no unprivileged network namespaces (cannot isolate loopback proxy gate)"
    [ "${ALLOW_NETNS_SKIP:-}" = 1 ] && exit 0
    exit 1
  fi
  exec env TESTBED_NO_BUILD=1 PROXY_CHECK_NS=1 unshare -rn bash -c 'ip link set lo up && exec bash "$0"' "$0"
fi
work=${TESTBED_WORK}/proxy-check
rm -rf "$work"
mkdir -p "$work"
pidfile=$work/proxy.pid
plog=$work/proxy.log
: >"$plog"
proxy=http://127.0.0.1:8899
failed=0
fail() { echo "FAIL $*"; failed=1; }
cleanup() {
  [ -f "$pidfile" ] && kill "$(cat "$pidfile")" 2>/dev/null
  ./testbed/run.sh stop >/dev/null 2>&1
  [ -f "$work/verify.pid" ] && kill "$(cat "$work/verify.pid")" 2>/dev/null
}
trap cleanup EXIT

# The fake archive's captures are the target's under the name the gate uses
# (without it they name 127.0.0.1:8770, which no proxy is asked for).
export FAKE_ARCHIVE_REHOST=pxy.jsh.test:8770
./bin/testbed logproxy -listen 127.0.0.1:8899 -log "$plog" >"$work/proxy.out" 2>&1 &
echo $! >"$pidfile"
./testbed/run.sh start archive-app >/dev/null
./bin/testbed serve -app testbed/apps/verify-app -addr 127.0.0.1:8771 >"$work/verify-server.log" 2>&1 &
echo $! >"$work/verify.pid"
sleep 1
logn() { wc -l <"$plog"; }
since() { tail -n "+$(($1 + 1))" "$plog"; }

wb=http://wb.jsh.test:8770/fake
export JSHARVEST_WAYBACK_URL=$wb/wayback JSHARVEST_OTX_URL=$wb/otx JSHARVEST_CC_INDEX_URL=$wb/cc \
  JSHARVEST_CC_DATA_URL=$wb/ccdata JSHARVEST_URLSCAN_URL=$wb/urlscan JSHARVEST_ARCHIVE_SCALE=0.01
# The environment's proxy is somewhere nothing listens: only -proxy (or
# JSHARVEST_PROXY) is the right one.
export HTTPS_PROXY=http://127.0.0.1:1 HTTP_PROXY=http://127.0.0.1:1 https_proxy=http://127.0.0.1:1 http_proxy=http://127.0.0.1:1
unset JSHARVEST_PROXY

echo "== 1. crawl -engine http -proxy, the archive after it"
n=$(logn)
timeout 180 ./bin/jsharvest crawl -engine http -u http://pxy.jsh.test:8770/ -depth 1 -proxy "$proxy" -o "$work/out" </dev/null >"$work/crawl.log" 2>&1
code=$?
since "$n" >"$work/crawl.proxy"
[ "$code" = 0 ] || fail "crawl exit $code: $(tail -2 "$work/crawl.log")"
grep -q "^proxy: $proxy\$" "$work/crawl.log" || fail "crawl: no 'proxy: $proxy' line on stderr"
grep -q 'pxy.jsh.test:8770/' "$work/crawl.proxy" || fail "crawl: the proxy saw no request of the page"
grep -q 'wb.jsh.test:8770/fake/wayback' "$work/crawl.proxy" || fail "crawl: the archive's requests did not go through the proxy"
rj=$(ls "$work"/out/pxy.jsh.test*/anon/run.json 2>/dev/null | head -1)
[ -n "$rj" ] && jq -e '.warnings // [] | map(select(startswith("aia disabled"))) | length > 0' "$rj" >/dev/null || fail "run.json does not say why the AIA is off (${rj:-no run.json})"

echo "== 2. archive -proxy (HTTPS_PROXY is dead)"
./testbed/run.sh start archive-app >/dev/null # the fake archive's troubles, anew
n=$(logn)
timeout 180 ./bin/jsharvest archive -o "$work/out" -target http://pxy.jsh.test:8770 -sources wayback,otx -page-size 3 -since 2020-01-01 -proxy "$proxy" >"$work/archive.log" 2>&1
code=$?
since "$n" >"$work/archive.proxy"
[ "$code" = 0 ] || fail "archive exit $code: $(tail -2 "$work/archive.log")"
grep -q "^proxy: $proxy\$" "$work/archive.log" || fail "archive: no 'proxy:' line on stderr"
grep -q 'wb.jsh.test:8770/fake/wayback' "$work/archive.proxy" || fail "archive: the archive's requests did not go through the proxy"
grep -q 'pxy.jsh.test:8770/' "$work/archive.proxy" || fail "archive: the live check did not go through the proxy"
fetched=$(sed -n 's/.*fetched \([0-9][0-9]*\) (alive \([0-9][0-9]*\).*/\1 \2/p' "$work/archive.log" | head -1)
set -- $fetched
{ [ "${1:-0}" -gt 0 ] || [ "${2:-0}" -gt 0 ]; } || fail "archive: nothing fetched or alive (${fetched:-no summary line}): $(grep -E '^archive' "$work/archive.log")"

echo "== 3. verify -proxy"
vt=pxy.jsh.test:8771
vd="$work/vout/pxy.jsh.test_8771/anon"
mkdir -p "$vd"
sed 's/127.0.0.1:8770/pxy.jsh.test:8771/' testbed/apps/verify-app/catalog.jsonl >"$vd/endpoints.jsonl"
# verify takes a host's scheme from what the run saw of it, https for a name
# that is not loopback: intel.json says this one speaks http.
echo '{"bases":["http://pxy.jsh.test:8771"]}' >"$vd/intel.json"
n=$(logn)
timeout 120 ./bin/jsharvest verify -o "$work/vout" -target "$vt" -scope fqdn -rate 50 -proxy "$proxy" >"$work/verify.log" 2>&1
code=$?
since "$n" >"$work/verify.proxy"
[ "$code" = 0 ] || fail "verify exit $code: $(tail -2 "$work/verify.log")"
grep -q "^proxy: $proxy\$" "$work/verify.log" || fail "verify: no 'proxy:' line on stderr"
grep -q 'pxy.jsh.test:8771' "$work/verify.proxy" || fail "verify: the proxy saw none of its requests"
grep -Eq '^(GET|HEAD|OPTIONS|POST) pxy.jsh.test:8771/' "$work/verify.proxy" || fail "verify: only tunnels (CONNECT) in the proxy's log: it spoke https to an http server"
grep -q 'server gave HTTP response to HTTPS client' "$work/verify.log" && fail "verify: https to an http server"

echo "== 4. the environment's JSHARVEST_PROXY, and -proxy none"
n=$(logn)
JSHARVEST_PROXY=$proxy timeout 120 ./bin/jsharvest archive -o "$work/out" -target http://pxy.jsh.test:8770 -sources wayback -page-size 3 -since 2020-01-01 -live=false >"$work/env.log" 2>&1 \
  || fail "archive with JSHARVEST_PROXY: $(tail -2 "$work/env.log")"
since "$n" | grep -q 'wb.jsh.test:8770/fake/wayback' || fail "JSHARVEST_PROXY was not taken"
n=$(logn)
JSHARVEST_PROXY=$proxy timeout 60 ./bin/jsharvest archive -o "$work/out" -target http://pxy.jsh.test:8770 -sources wayback -page-size 3 -since 2020-01-01 -live=false -proxy none >"$work/none.log" 2>&1
# (the archive may end 0 with its sources unreachable: what counts is that
# the proxy was not used and nothing went around it to a name only it knows)
[ "$(since "$n" | wc -l)" = 0 ] || fail "-proxy none: the proxy was asked"

echo "== the proxy's log"
if grep -E '^(REFUSED|DIRECT)' "$plog"; then fail "the proxy refused or was spoken to as a server"; fi
for f in crawl archive verify; do
  [ -s "$work/$f.proxy" ] || fail "no request of $f in the proxy's log"
done

[ $failed = 0 ] && echo "proxy-check: PASS" || echo "proxy-check: FAIL"
exit $failed
