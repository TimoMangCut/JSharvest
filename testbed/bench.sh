#!/usr/bin/env bash
# Runs each tool against each testbed app and prints the recall table.
# Usage: testbed/bench.sh [app...]            (default: every built app)
# Env:   TOOLS="jsharvest katana-hl katana-hh"  (default: jsharvest katana-hl)
#        GATE=1  fail (exit 1) when jsharvest loses a marker of an app's
#                baseline.txt, stores a capture artefact, or its request log
#                differs from the server's (testbed reqcheck)
#        JSHARVEST_ARGS="..."  extra flags for jsharvest crawl
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

apps=("$@")
if [ ${#apps[@]} -eq 0 ]; then
  for d in testbed/apps/*/; do
    # the apps the bench scores: a dist and a truth.txt (lan-app and the
    # like are gates of their own)
    [ -d "$d/dist" ] && [ -f "$d/truth.txt" ] && apps+=("$(basename "$d")")
  done
fi
tools=(${TOOLS:-jsharvest katana-hl})
url="http://127.0.0.1:8770/"
results="${TESTBED_WORK}/bench/results.txt"
failed=0
mkdir -p ${TESTBED_WORK}/bench
: >"$results"

run_tool() { # tool out
  case "$1" in
    jsharvest)
      # An app can ask for flags of its own (the guard fixture wants -guard).
      extra=""
      [ -f "testbed/apps/$app/jsharvest.args" ] && extra=$(cat "testbed/apps/$app/jsharvest.args")
      timeout 180 ./bin/jsharvest crawl -u "$url" -o "$2" $extra ${JSHARVEST_ARGS:-} </dev/null >/dev/null 2>&1
      echo "$2/127.0.0.1/anon"
      ;;
    katana-hl | katana-hh)
      # katana reads target URLs from stdin when it is not a terminal and
      # waits for ever on an open pipe, so stdin is closed.
      timeout 300 katana -u "$url" "-${1#katana-}" -jc -jsl -xhr -aff -d 5 -sr -srd "$2" -silent -system-chrome </dev/null >/dev/null 2>&1
      echo "$2"
      ;;
    *)
      echo "unknown tool $1" >&2
      return 1
      ;;
  esac
}

for app in "${apps[@]}"; do
  ./testbed/run.sh start "$app" >/dev/null
  for tool in "${tools[@]}"; do
    out="${TESTBED_WORK}/bench/$tool/$app"
    rm -rf "$out"
    logstart=$(wc -l <${TESTBED_LOG})
    dir=$(run_tool "$tool" "$out")
    sleep 0.3 # let the server log the requests the browser's exit ended
    tail -n "+$((logstart + 1))" ${TESTBED_LOG} >"$out.serverlog"
    gate=()
    if [ "${GATE:-}" = 1 ] && [ "$tool" = jsharvest ]; then
      gate=(-gate)
    fi
    status=""
    if ! ./bin/testbed score -app "testbed/apps/$app" -out "$dir" "${gate[@]}" >"$out.score" 2>&1; then
      status="  GATE FAILED: $(grep -E 'gate failed: |gate: ' "$out.score" | tail -1)"
      failed=1
    fi
    # Requests the tool must never make, such as out-of-scope decoys.
    if [ "${GATE:-}" = 1 ] && [ "$tool" = jsharvest ] && [ -f "testbed/apps/$app/forbidden.txt" ]; then
      while read -r p; do
        case "$p" in "" | "#"*) continue ;; esac
        if grep -qF " $p" ${TESTBED_LOG}; then
          status="$status  FORBIDDEN REQUEST: $p"
          failed=1
        fi
      done <"testbed/apps/$app/forbidden.txt"
    fi
    # Requests that must still be made, such as reads behind the guard.
    if [ "${GATE:-}" = 1 ] && [ "$tool" = jsharvest ] && [ -f "testbed/apps/$app/required.txt" ]; then
      while read -r p; do
        case "$p" in "" | "#"*) continue ;; esac
        if ! grep -qF " $p" ${TESTBED_LOG}; then
          status="$status  MISSING REQUEST: $p"
          failed=1
        fi
      done <"testbed/apps/$app/required.txt"
    fi
    # The request log must hold every request the server saw, and nothing
    # the server did not.
    if [ "${GATE:-}" = 1 ] && [ "$tool" = jsharvest ]; then
      if ! ./bin/testbed reqcheck -log "$out.serverlog" -requests "$dir/requests.jsonl" >"$out.reqcheck" 2>&1; then
        status="$status  REQCHECK: $(grep -c -E '^(MISSING|NOT ON SERVER|DUPLICATE)' "$out.reqcheck") line(s), see $out.reqcheck"
        failed=1
      fi
    fi
    recall=$(grep -o 'recall: .*' "$out.score" || echo 'recall: n/a')
    printf '%-14s %-12s %s%s\n' "$app" "$tool" "${recall#recall: }" "$status" | tee -a "$results"
  done
done
./testbed/run.sh stop
echo "details: ${TESTBED_WORK}/bench/<tool>/<app>.score"
exit "$failed"
