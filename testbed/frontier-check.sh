#!/usr/bin/env bash
# The 4.4 gate: crawl frontier-app from its index with -depth 3 and the
# guard on. Every source of URLs leads to its page (links, area, SVG,
# frames, srcdoc, closed shadow root, template, noscript, comment, inline
# handler, javascript: link, script-built link, script strings, HTML in a
# string, route, GET form, meta refresh, timer, HTTP redirect, headers,
# robots.txt, sitemap, hash route); what must not be opened is only named
# (a POST form, a cite, a logout, a page named delete, a file, another
# site, a page too deep), and the server never sees it. Then
# webpack-vanilla at -depth 1 -resolve-max 3: the resolver's limit and
# counts hold over the run's pages.
# Usage: testbed/frontier-check.sh   (exit 1 on failure)
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
require_built_apps "$root" || exit 1
build_testbed_bins || exit 1
work=${TESTBED_WORK}/frontier-check
rm -rf "$work"
mkdir -p "$work"
app=testbed/apps/frontier-app

./testbed/run.sh start frontier-app >/dev/null
trap './testbed/run.sh stop >/dev/null' EXIT
n=$(wc -l <${TESTBED_LOG})
timeout 300 ./bin/jsharvest crawl -u http://127.0.0.1:8770/ -depth 3 -page-rate 20 -guard on -o "$work/out" </dev/null >"$work/crawl.log" 2>&1
code=$?
sleep 0.5
tail -n "+$((n + 1))" ${TESTBED_LOG} >"$work/server.log"
failed=0
if [ "$code" != 0 ]; then
  echo "CRAWL FAILED: exit $code"; tail -3 "$work/crawl.log"
  failed=1
fi
./bin/testbed frontscore -truth "$app/frontier.truth.json" -out "$work/out/127.0.0.1/anon" -log "$work/server.log" || failed=1
jq -c '.frontier' "$work/out/127.0.0.1/anon/run.json"
# Every page load is an action of the flows.
loads=$(jq -s '[.[] | select(.kind == "load")] | length' "$work/out/127.0.0.1/anon/flows.jsonl")
visited=$(jq '.frontier.visited' "$work/out/127.0.0.1/anon/run.json")
if [ "$loads" -lt $((visited * 9 / 10)) ]; then
  echo "FLOWS: $loads load actions for $visited pages"
  failed=1
fi

# The resolver after every page: -resolve-max, its counts and a stop are
# the run's (webpack-vanilla: chunks to resolve, pages to follow).
./testbed/run.sh start webpack-vanilla >/dev/null
timeout 300 ./bin/jsharvest crawl -u http://127.0.0.1:8770/ -depth 1 -resolve-max 3 -page-rate 10 -o "$work/rmax" \
  </dev/null >"$work/rmax.log" 2>&1 || { echo "RESOLVER: crawl exit $?"; failed=1; }
rmax="$work/rmax/127.0.0.1/anon/run.json"
jq -c '{pages: .frontier.visited, resolver: (.resolver | {fetched, failed, by_method, stopped})}' "$rmax"
jq -e '.frontier.visited > 1 and (.resolver.fetched + .resolver.failed) <= 3 and (.resolver.fetched + .resolver.failed) == ([.resolver.by_method[]] | add // 0)
  and ([.warnings[] | select(startswith("resolver:"))] | length) <= 1' "$rmax" >/dev/null || {
  echo "RESOLVER: -resolve-max, or its counts, not kept over the run"
  failed=1
}
[ "$failed" = 0 ] && echo "frontier gate: ok ($loads load actions)"
exit "$failed"
