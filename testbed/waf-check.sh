#!/usr/bin/env bash
# The D1 gate (CF-01, CF-02): a bot challenge is the vendor's, never the
# target's. On local fixtures that run as a challenge does (testbed serve,
# /cf-challenge and /cf-healthy; they imitate no live service):
#   1. a challenge page (403, cf-mitigated): the run exits 3; no script of the
#      page reaches js/ or index.jsonl (the inline loader, the platform
#      script, its three eval blocks, the site script on the page); the
#      platform's POSTs to /cdn-cgi/ pass the guard (the server answers them,
#      blocked.jsonl has none); endpoints.jsonl names neither /cdn-cgi/ nor
#      what the challenge page asked for; run.json counts the drops;
#   1b. a deny page only its title tells ("Attention Required!", no
#      cf-mitigated; round 18): exit 3, none of its inline scripts stored;
#      the site's own 403 behind the CDN keeps its script;
#   2. a healthy page behind the CDN: exit 0; the site's script is stored and
#      its endpoint listed; the injected jsd snippet and the platform script
#      are dropped; Cloudflare's email decoder is kept as cdn-infra, and its
#      beacon POST passes the guard and is no endpoint.
#   3. the HTTP engine (D3, CF-03/CF-04b) on the challenge page: exit 3, no
#      script, and the archive fallback runs (archive-app's fake archive):
#      the old front page names scripts, fetched live first;
#   3b. the HTTP engine's defaults on archive-app's healthy front page: depth
#      3, then the archive (the fake one) after the crawl;
#   4. the HTTP engine on the healthy page (-archive=false): exit 0, the site's script and its
#      endpoint, the CDN helper kept as cdn-infra, no challenge script, and
#      no browser.
#   5. what Chrome presents when it must be used (D5, CF-06): no HeadlessChrome
#      in the User-Agent of the page or its worker, Google Chrome in
#      Sec-CH-UA, navigator.webdriver false;
#   6. a challenge that passes on its own: the guard lets its answer through
#      and the crawl waits for the reload (-challenge-wait): exit 0, the
#      site's script stored, the challenge's dropped.
#   8. crawl -engine auto (round 18): a page plain HTTP meets a challenge on
#      (the second page, or the seed) goes to Chrome, which passes it; its
#      scripts land in the same output, run.json says escalated; -engine
#      http never starts a browser.
#   7. source maps (round 17, MAX-04/07), both engines, on maps-app: the map
#      a script names and the one a guess finds (app.js.map, no comment)
#      give their own sources to the store and their endpoints to the
#      catalog; node_modules is left out; a library bundle's map is never
#      guessed (no GET of vendors.js.map).
# Usage: testbed/waf-check.sh   (exit 1 on failure)
set -uo pipefail
# The browser engine: these gates test what Chrome sees (crawl -engine auto
# would take the HTTP engine for anon).
export JSHARVEST_ENGINE="${JSHARVEST_ENGINE:-cdp}"
export TESTBED_LOG="${TESTBED_LOG:-bin/testbed.log}" TESTBED_PID="${TESTBED_PID:-bin/testbed.pid}" TESTBED_WORK="${TESTBED_WORK:-bin}"
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
. "$root/testbed/lib/env.sh"
ensure_go_in_path || exit 1
build_testbed_bins || exit 1
work=${TESTBED_WORK}/waf-check
rm -rf "$work"
mkdir -p "$work"
failed=0
fail() { echo "FAIL: $*"; failed=1; }

./testbed/run.sh start edge-cases >/dev/null
trap './testbed/run.sh stop >/dev/null' EXIT

echo "== 1. a challenge page"
out="$work/blocked"
timeout 120 ./bin/jsharvest crawl -u http://127.0.0.1:8770/cf-challenge -guard on -o "$out" </dev/null >"$work/blocked.log" 2>&1
code=$?
d="$out/127.0.0.1/anon"
[ "$code" = 3 ] || fail "exit $code, want 3"
n=$(wc -l <"$d/index.jsonl" 2>/dev/null || echo 0)
[ "$n" = 0 ] || { fail "$n scripts in index.jsonl, want 0"; jq -c '{urls, kinds, tags}' "$d/index.jsonl"; }
if ls "$d/js/"*.js >/dev/null 2>&1; then
  fail "js/ holds $(ls "$d/js" | wc -l) files"
fi
dropped=$(jq '.stats.challenge_scripts // 0' "$d/run.json")
[ "$dropped" -ge 4 ] || fail "run.json counts $dropped challenge scripts dropped, want >= 4 (loader, platform, evals, page script)"
if [ -s "$d/blocked.jsonl" ] && grep -q '/cdn-cgi/' "$d/blocked.jsonl"; then
  fail "blocked.jsonl holds /cdn-cgi/ requests"
fi
posts=$(grep -c 'POST /cdn-cgi/challenge-platform/h/b/f' "$TESTBED_LOG")
[ "$posts" = 2 ] || fail "the server saw $posts of the platform's 2 POSTs (the guard must pass them)"
if grep -Eq 'cdn-cgi|on-blocked-page|vm-junk' "$d/endpoints.jsonl" 2>/dev/null; then
  fail "endpoints.jsonl names the challenge's: $(jq -c '[.method, .path]' "$d/endpoints.jsonl" | tr '\n' ' ')"
fi
grep -q '"challenge"' "$d/requests.jsonl" || fail "requests.jsonl tags none of the challenge page's requests"
echo "1: exit $code, $n scripts kept, $dropped dropped, $posts platform POSTs passed"

echo "== 1b. a deny page only its title tells, and the site's own 403"
out="$work/deny"
timeout 120 ./bin/jsharvest crawl -u http://127.0.0.1:8770/cf-deny -o "$out" </dev/null >"$work/deny.log" 2>&1
code=$?
d="$out/127.0.0.1/anon"
[ "$code" = 3 ] || fail "1b: the deny page: exit $code, want 3"
n=$(wc -l <"$d/index.jsonl" 2>/dev/null || echo 0)
[ "$n" = 0 ] || { fail "1b: $n scripts of the deny page stored, want 0"; jq -c '{urls, kinds}' "$d/index.jsonl"; }
out="$work/site403"
timeout 120 ./bin/jsharvest crawl -u http://127.0.0.1:8770/cf-site-403 -o "$out" </dev/null >"$work/site403.log" 2>&1
d="$out/127.0.0.1/anon"
grep -q site-403-inline "$d"/js/*.js 2>/dev/null || fail "1b: the site's own 403 page lost its inline script"
echo "1b: deny exit $code, $n scripts; the site's 403 kept its script"

echo "== 2. a healthy page behind the CDN"
out="$work/healthy"
timeout 120 ./bin/jsharvest crawl -u http://127.0.0.1:8770/cf-healthy -guard on -o "$out" </dev/null >"$work/healthy.log" 2>&1
code=$?
d="$out/127.0.0.1/anon"
[ "$code" = 0 ] || fail "exit $code, want 0"
jq -e 'select(.urls[]? | endswith("/cf-app.js"))' "$d/index.jsonl" >/dev/null || fail "the site's script is not stored"
jq -e 'select(.urls[]? | test("email-decode")) | select(.tags | index("cdn-infra"))' "$d/index.jsonl" >/dev/null ||
  fail "the email decoder is not kept as cdn-infra"
if jq -e 'select((.urls[]? | test("challenge-platform")) or (.kinds | index("inline")))' "$d/index.jsonl" >/dev/null; then
  fail "a challenge script was stored: $(jq -c 'select((.urls[]? | test("challenge-platform")) or (.kinds | index("inline"))) | .urls' "$d/index.jsonl")"
fi
jq -e 'select(.path == "/api/cf-real")' "$d/endpoints.jsonl" >/dev/null || fail "the site's endpoint /api/cf-real is not listed"
grep -q '/cdn-cgi/' "$d/endpoints.jsonl" && fail "endpoints.jsonl names /cdn-cgi/"
if [ -s "$d/blocked.jsonl" ] && grep -q '/cdn-cgi/' "$d/blocked.jsonl"; then
  fail "the guard held a /cdn-cgi/ request"
fi
grep -q 'POST /cdn-cgi/rum' "$TESTBED_LOG" || fail "the beacon POST did not reach the server"
echo "2: exit $code; $(wc -l <"$d/index.jsonl") scripts kept, $(jq '.stats.challenge_scripts // 0' "$d/run.json") dropped"

echo "== 3. the HTTP engine on a challenge page, with the archive fallback"
./testbed/run.sh start archive-app >/dev/null
out="$work/http-blocked"
JSHARVEST_WAYBACK_URL=http://127.0.0.1:8770/fake/wayback JSHARVEST_OTX_URL=http://127.0.0.1:8770/fake/otx JSHARVEST_CC_INDEX_URL=http://127.0.0.1:8770/fake/cc JSHARVEST_CC_DATA_URL=http://127.0.0.1:8770/fake/ccdata JSHARVEST_URLSCAN_URL=http://127.0.0.1:8770/fake/urlscan JSHARVEST_ARCHIVE_SCALE=0.01 \
  timeout 300 ./bin/jsharvest crawl -engine http -u http://127.0.0.1:8770/cf-challenge -o "$out" </dev/null >"$work/http-blocked.log" 2>&1
code=$?
d="$out/127.0.0.1/anon"
[ "$code" = 3 ] || fail "http engine: exit $code, want 3"
[ "$(jq -r .mode "$d/run.json")" = http ] || fail "run.json mode is not http"
n=$(wc -l <"$d/index.jsonl" 2>/dev/null || echo 0)
[ "$n" = 0 ] || fail "http engine: $n scripts of a challenge page stored"
grep -q 'GET /cf-on-blocked.js' "$TESTBED_LOG" && fail "http engine fetched a script of the challenge page"
fetched=$(jq '.fallback.summary.fetched // 0' "$d/run.json")
alive=$(jq '.fallback.summary.alive // 0' "$d/run.json")
pages=$(jq '.fallback.summary.pages_read // 0' "$d/run.json")
[ "$pages" -ge 1 ] || fail "the fallback read no old page: $(jq -c '.fallback' "$d/run.json" | head -c 300)"
[ "$fetched" -ge 1 ] && [ "$alive" -ge 1 ] || fail "the fallback fetched $fetched old scripts, $alive alive"
[ -s "$out/127.0.0.1/archive/historical.jsonl" ] || fail "the fallback wrote no historical.jsonl"
echo "3: exit $code; fallback: $pages old pages read, $fetched scripts fetched, $alive alive"

echo "== 3b. the HTTP engine's defaults: the site in depth, then its history"
out="$work/http-defaults"
JSHARVEST_WAYBACK_URL=http://127.0.0.1:8770/fake/wayback JSHARVEST_OTX_URL=http://127.0.0.1:8770/fake/otx JSHARVEST_CC_INDEX_URL=http://127.0.0.1:8770/fake/cc JSHARVEST_CC_DATA_URL=http://127.0.0.1:8770/fake/ccdata JSHARVEST_URLSCAN_URL=http://127.0.0.1:8770/fake/urlscan JSHARVEST_ARCHIVE_SCALE=0.01 \
  timeout 300 ./bin/jsharvest crawl -engine http -u http://127.0.0.1:8770/ -o "$out" </dev/null >"$work/http-defaults.log" 2>&1
code=$?
d="$out/127.0.0.1/anon"
[ "$code" = 0 ] || fail "http engine defaults: exit $code, want 0"
[ "$(jq -r .config.depth "$d/run.json")" = 3 ] || fail "http engine defaults: depth $(jq -r .config.depth "$d/run.json"), want 3"
[ "$(jq -r '.fallback // empty' "$d/run.json")" = "" ] || fail "http engine defaults: a fallback on a page that is not blocked"
fetched=$(jq '.archive.summary.fetched // 0' "$d/run.json")
[ "$fetched" -ge 1 ] || fail "http engine defaults: the archive did not run after the crawl: $(jq -c '.archive' "$d/run.json" | head -c 300)"
[ -s "$out/127.0.0.1/archive/historical.jsonl" ] || fail "http engine defaults: no historical.jsonl"
for src in wayback otx commoncrawl urlscan; do # every archive, by default (the fake ones: never the real)
  [ "$(jq ".archive.summary.listed.$src // 0" "$d/run.json")" -ge 1 ] || fail "http engine defaults: $src not listed"
done
echo "3b: exit $code; depth 3; archive after the crawl (wayback, otx, commoncrawl, urlscan): $fetched old scripts fetched"

echo "== 4. the HTTP engine on a healthy page"
./testbed/run.sh start edge-cases >/dev/null
out="$work/http-healthy"
timeout 120 ./bin/jsharvest crawl -engine http -archive=false -u http://127.0.0.1:8770/cf-healthy -o "$out" </dev/null >"$work/http-healthy.log" 2>&1
code=$?
d="$out/127.0.0.1/anon"
[ "$code" = 0 ] || fail "http engine: exit $code, want 0"
jq -e 'select(.urls[]? | endswith("/cf-app.js")) | select(.via | index("http"))' "$d/index.jsonl" >/dev/null || fail "http engine: the site's script is not stored"
jq -e 'select(.urls[]? | test("email-decode")) | select(.tags | index("cdn-infra"))' "$d/index.jsonl" >/dev/null ||
  fail "http engine: the email decoder is not kept as cdn-infra"
if jq -e 'select((.urls[]? | test("challenge-platform")) or (.kinds | index("inline")))' "$d/index.jsonl" >/dev/null; then
  fail "http engine stored a challenge script"
fi
grep -q 'GET /cdn-cgi/challenge-platform/scripts/jsd/main.js' "$TESTBED_LOG" && fail "http engine fetched the challenge script"
jq -e 'select(.path == "/api/cf-real")' "$d/endpoints.jsonl" >/dev/null || fail "http engine: /api/cf-real is not listed"
if jq -e 'select(.path | test("robots|sitemap|manifest|cdn-cgi"))' "$d/endpoints.jsonl" >/dev/null; then
  fail "http engine: a probe or the CDN in endpoints.jsonl: $(jq -c '[.method,.path]' "$d/endpoints.jsonl" | tr '\n' ' ')"
fi
[ -e "$out/127.0.0.1/archive" ] && fail "-archive=false: the archive ran"
echo "4: exit $code; $(wc -l <"$d/index.jsonl") scripts kept"

echo "== 5. what Chrome presents"
./testbed/run.sh start edge-cases >/dev/null
timeout 120 ./bin/jsharvest crawl -engine cdp -u http://127.0.0.1:8770/ua-page -o "$work/ua" </dev/null >"$work/ua.log" 2>&1 || fail "crawl /ua-page"
grep -q 'HeadlessChrome' "$TESTBED_LOG" && fail "HeadlessChrome reached the server: $(grep -m1 HeadlessChrome "$TESTBED_LOG")"
grep -q 'UA page .*Chrome/[0-9]' "$TESTBED_LOG" || fail "the page's User-Agent was not logged"
grep -q 'UA worker .*Chrome/[0-9]' "$TESTBED_LOG" || fail "the worker's User-Agent was not logged"
grep -q 'UA page .*CH .*Google Chrome' "$TESTBED_LOG" || fail "Sec-CH-UA does not name Google Chrome: $(grep -m1 'UA page' "$TESTBED_LOG")"
grep -q 'GET /ua-check?from=page&wd=false' "$TESTBED_LOG" || fail "navigator.webdriver is not false"
echo "5: $(grep -m1 'UA page' "$TESTBED_LOG" | sed 's/.*UA page //' | cut -c1-140)"

echo "== 6. a challenge that passes on its own"
out="$work/passes"
timeout 120 ./bin/jsharvest crawl -engine cdp -u http://127.0.0.1:8770/cf-passes -guard on -o "$out" </dev/null >"$work/passes.log" 2>&1
code=$?
d="$out/127.0.0.1/anon"
[ "$code" = 0 ] || fail "a challenge that passes: exit $code, want 0 ($(grep -m1 -E 'challenge' "$work/passes.log"))"
jq -e 'select(.urls[]? | endswith("/cf-passed-app.js"))' "$d/index.jsonl" >/dev/null || fail "the site's script after the challenge is not stored"
grep -q '_cf_chl_opt' "$d"/js/*.js 2>/dev/null && fail "the challenge's inline code was stored"
jq -e 'select(.path == "/api/after-challenge")' "$d/endpoints.jsonl" >/dev/null || fail "/api/after-challenge is not listed"
# The pass must be the -challenge-wait loop's, not the idle wait's
# (NEW-D14-01): the page was a challenge when the tab first went quiet.
grep -q 'the page is a challenge; waiting' "$work/passes.log" || fail "the crawl did not wait on the challenge (-challenge-wait loop never ran)"
grep -q 'the challenge passed' "$work/passes.log" || fail "the challenge's passing was not seen by the -challenge-wait loop"
echo "6: exit $code; $(grep -c 'challenge passed' "$work/passes.log") pass seen"

echo "== 7. source maps, both engines"
for eng in cdp http; do
  ./testbed/run.sh start maps-app >/dev/null
  out="$work/maps-$eng"
  timeout 120 ./bin/jsharvest crawl -engine "$eng" -archive=false -depth 0 -u http://127.0.0.1:8770/ -o "$out" </dev/null >"$work/maps-$eng.log" 2>&1 ||
    fail "$eng: crawl maps-app: $(tail -1 "$work/maps-$eng.log")"
  d="$out/127.0.0.1/anon"
  n=$(jq -s '[.[] | select(.kinds | index("source"))] | length' "$d/index.jsonl")
  [ "$n" = 2 ] || fail "$eng: $n sources from maps, want 2 (orders.ts, users.ts): $(jq -c 'select(.kinds | index("source")) | .urls' "$d/index.jsonl" | tr '\n' ' ')"
  for p in /api/from-named-map/orders '/api/from-guessed-map/users/{}'; do
    jq -e --arg p "$p" 'select(.path == $p)' "$d/endpoints.jsonl" >/dev/null || fail "$eng: $p is not listed"
  done
  if jq -e 'select(.path | test("vendor"))' "$d/endpoints.jsonl" >/dev/null; then
    fail "$eng: a dependency's or a library map's endpoint: $(jq -c 'select(.path | test("vendor")) | .path' "$d/endpoints.jsonl" | tr '\n' ' ')"
  fi
  grep -q 'GET /assets/vendors.js.map' "$TESTBED_LOG" && fail "$eng: a library bundle's map was guessed"
  grep -q 'GET /assets/app.js.map' "$TESTBED_LOG" || fail "$eng: app.js.map was not guessed"
  echo "7 ($eng): $n sources from maps"
done

echo "== 8. crawl -engine auto: Chrome takes the pages a challenge stops plain HTTP on"
./testbed/run.sh start edge-cases >/dev/null
out="$work/escalate"
JSHARVEST_ENGINE=auto timeout 180 ./bin/jsharvest crawl -u http://127.0.0.1:8770/cf-links -depth 1 -archive=false -o "$out" </dev/null >"$work/escalate.log" 2>&1
code=$?
d="$out/127.0.0.1/anon"
[ "$code" = 0 ] || fail "8a: exit $code, want 0 ($(tail -1 "$work/escalate.log"))"
jq -e '.mode == "http" and .escalated.runs[0].host == "127.0.0.1" and .escalated.runs[0].blocked == false and .escalated.pages[0].asked' "$d/run.json" >/dev/null ||
  fail "8a: run.json escalated: $(jq -c .escalated "$d/run.json")"
for f in /cf-app.js /cf-passed-app.js; do
  jq -e --arg f "$f" 'select(.urls[]? | endswith($f))' "$d/index.jsonl" >/dev/null || fail "8a: $f is not stored"
done
grep -q '_cf_chl_opt' "$d"/js/*.js 2>/dev/null && fail "8a: the challenge's inline code was stored"
n=$(wc -l <"$d/runs.jsonl")
[ "$n" = 2 ] || fail "8a: $n runs in runs.jsonl, want 2 (http, then Chrome's)"
jq -e 'select(.path == "/api/after-challenge")' "$d/endpoints.jsonl" >/dev/null || fail "8a: /api/after-challenge is not listed"
echo "8a: exit $code; $(jq -c '.escalated.runs' "$d/run.json")"
# Round 25L: Chrome goes on as the HTTP engine was: the application's
# cookie the crawl got (not the CDN's), and the same User-Agent.
chrome_req=$(jq -c 'select(.resource_type == "Document" and (.url | endswith("/cf-passes")) and ((.tags // []) | index("http") | not))' "$d/requests.jsonl" | head -1)
http_ua=$(jq -r '.http.user_agent // empty' "$d/run.json")
[ -n "$chrome_req" ] || fail "8a: no Chrome request for /cf-passes in requests.jsonl"
echo "$chrome_req" | jq -e '(.headers.cookie // "") | test("app_region=vn")' >/dev/null || fail "8a: Chrome did not take on the crawl's cookie: $(echo "$chrome_req" | jq -c .headers.cookie)"
echo "$chrome_req" | jq -e '(.headers.cookie // "") | test("go-client") | not' >/dev/null || fail "8a: Chrome took on the HTTP client's CDN cookie"
[ -n "$http_ua" ] && [ "$(echo "$chrome_req" | jq -r '.headers["user-agent"]')" = "$http_ua" ] ||
  fail "8a: Chrome's User-Agent $(echo "$chrome_req" | jq -r '.headers["user-agent"]') is not the HTTP engine's $http_ua"

out="$work/escalate-seed"
JSHARVEST_ENGINE=auto timeout 180 ./bin/jsharvest crawl -u http://127.0.0.1:8770/cf-passes -depth 0 -archive=false -archive-fallback=false -o "$out" </dev/null >"$work/escalate-seed.log" 2>&1
code=$?
d="$out/127.0.0.1/anon"
[ "$code" = 0 ] || fail "8b: the seed a challenge: exit $code, want 0 once Chrome passed it"
jq -e '.blocked.blocked and .escalated.runs[0].blocked == false' "$d/run.json" >/dev/null || fail "8b: run.json: $(jq -c '{blocked, escalated}' "$d/run.json")"
jq -e 'select(.urls[]? | endswith("/cf-passed-app.js"))' "$d/index.jsonl" >/dev/null || fail "8b: /cf-passed-app.js is not stored"
echo "8b: exit $code"

out="$work/escalate-off"
timeout 120 ./bin/jsharvest crawl -engine http -u http://127.0.0.1:8770/cf-links -depth 1 -archive=false -o "$out" </dev/null >"$work/escalate-off.log" 2>&1
d="$out/127.0.0.1/anon"
jq -e '.escalated' "$d/run.json" >/dev/null && fail "8c: -engine http started a browser"
jq -e 'select(.urls[]? | endswith("/cf-passed-app.js"))' "$d/index.jsonl" >/dev/null && fail "8c: -engine http got past the challenge"
echo "8c: -engine http: no browser"

[ "$failed" = 0 ] && echo "waf-check: ok" || echo "waf-check: FAILED"
exit "$failed"
