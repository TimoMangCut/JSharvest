#!/usr/bin/env bash
# The 4.4 gate on testbeds others wrote (see README.md): jsharvest's frontier
# from each site's root, the guard on.
#   Crawlground: >= 50/59 tests scored by the server.
#   security-crawl-maze: >= 51/84 answers requested or listed; and, with the
#   test pages whose names read as destructive (js-delete.html,
#   …-remove-button.html) allowed as pages, javascript >= 19/20 with no write
#   reaching the server (the allowlist covers .html pages only, so the
#   DELETE those pages make is still held back).
# Each run gets fresh containers on ports of its own, so that an earlier
# run's container (or its scores) cannot be counted.
# EXTRA adds flags to every crawl; with EXTRA=-explore (4.6) Crawlground must
# reach 55/59.
# Usage: [EXTRA=-explore] testbed/external/run.sh   (exit 1 on failure, 2 without the images)
set -uo pipefail
# The browser engine: these runs test what Chrome sees (crawl -engine auto
# would take the HTTP engine for anon).
export JSHARVEST_ENGINE="${JSHARVEST_ENGINE:-cdp}"
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
. "$root/testbed/lib/env.sh"
ensure_go_in_path || exit 1
for img in jsh-ext-crawlground jsh-ext-crawlmaze; do
  docker image inspect "$img" >/dev/null 2>&1 || { echo "missing image $img: see testbed/external/README.md"; exit 2; }
done
go build -o bin/jsharvest ./cmd/jsharvest && go build -o bin/testbed ./testbed/cmd/testbed || exit 1
work=bin/external
rm -rf "$work"
mkdir -p "$work"
rate="${RATE:-10}"
read -r -a extra <<<"${EXTRA:-}"
cgmin=50
[[ " ${extra[*]} " == *" -explore "* ]] && cgmin=55
cg=jsh-ext-cg-$$
cm=jsh-ext-cm-$$
trap 'docker rm -f $cg $cm >/dev/null 2>&1' EXIT
failed=0

echo "== Crawlground"
docker run -d --name $cg -p 127.0.0.1:3457:3456 jsh-ext-crawlground >/dev/null || exit 1
for _ in $(seq 30); do curl -sf http://127.0.0.1:3457/ >/dev/null && break; sleep 0.5; done
curl -sf -X POST "http://127.0.0.1:3457/set-tool?name=jsharvest" >/dev/null || { echo "set-tool failed"; exit 1; }
start=$(date +%s)
timeout 1800 ./bin/jsharvest crawl -u http://127.0.0.1:3457/ -depth 4 -page-rate "$rate" -guard on "${extra[@]}" -o "$work/cg" </dev/null >"$work/cg.log" 2>&1
curl -s http://127.0.0.1:3457/results.json >"$work/cg-results.json"
cgscore=$(jq '.summary.tools[] | select(.name == "jsharvest") | .scored' "$work/cg-results.json")
echo "crawlground: ${cgscore:-0}/59 in $(($(date +%s) - start)) s; missed:"
jq -r '.tests[] | select(.tools.jsharvest.scored | not) | "  " + .id' "$work/cg-results.json"
[ "${cgscore:-0}" -ge "$cgmin" ] || { echo "CRAWLGROUND below $cgmin"; failed=1; }

maze() { # name, extra flags... -> scores the run
  local name=$1
  shift
  docker rm -f $cm >/dev/null 2>&1
  docker run -d --name $cm -p 127.0.0.1:8091:8080 jsh-ext-crawlmaze >/dev/null || return 1
  for _ in $(seq 30); do curl -sf http://127.0.0.1:8091/ >/dev/null && break; sleep 0.5; done
  local start
  start=$(date +%s)
  timeout 1800 ./bin/jsharvest crawl -u http://127.0.0.1:8091/ -depth 6 -page-rate "$rate" -guard on "${extra[@]}" "$@" -o "$work/$name" </dev/null >"$work/$name.log" 2>&1
  docker logs $cm >"$work/$name.server.log" 2>&1
  echo "($name, $(($(date +%s) - start)) s)"
}

echo "== security-crawl-maze"
maze cm
./bin/testbed mazescore -expected testbed/external/crawlmaze-expected.json -log "$work/cm.server.log" -out "$work/cm/127.0.0.1/anon" -min 51 || failed=1

echo "== security-crawl-maze, destructive-named test pages allowed as pages"
maze cm-allow -guard-allow '/javascript/interactive/[^/]*\.html/?$'
./bin/testbed mazescore -expected testbed/external/crawlmaze-expected.json -log "$work/cm-allow.server.log" -out "$work/cm-allow/127.0.0.1/anon" -min-js 19 || failed=1
writes=$(sed 's/\x1b\[[0-9;]*m//g' "$work/cm-allow.server.log" | grep -cE '"(DELETE|PUT|POST|PATCH) ')
echo "writes reaching the server: $writes"
[ "$writes" = 0 ] || failed=1

[ "$failed" = 0 ] && echo "external gate: ok"
exit "$failed"
