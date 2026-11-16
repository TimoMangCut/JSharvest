#!/usr/bin/env bash
# The gate of crawl -urls -tabs N (docs/gd5-parallel-design.md, stage B).
#   1. guard-cases, 3 pages on each of two hosts (a.jsh.test, b.jsh.test,
#      -scope fqdn), the guard on: crawl -urls -tabs 1, then -tabs 3. For
#      each URL the -tabs 3 run has what the -tabs 1 run has: requests,
#      held-back requests, the guard's count, every request on its own page;
#      each host's index the same scripts, every line whole; six run IDs, no
#      two alike; the runs overlapped, and -urls-rate still paced the
#      starts; the server saw the same requests, none of forbidden.txt.
#   2. session-app, -role user, seven members' pages, -tabs 1 and 3: each
#      URL runs with its host's saved login (-urls ignored it before), and
#      so with the guard under -guard auto; each tab's
#      browser context gets the saved session, cookies and storage: no page
#      sent to the login, no session lost, the members' and storage
#      markers found.
#   3. -tabs 2 interrupted (SIGINT) early: exit 130, the batch record says
#      so, and no page loads after the interrupt.
#   4. -tabs is refused without -urls and with -attach.
# Usage: testbed/parallel-check.sh   (exit 1 on failure)
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
work=${TESTBED_WORK}/parallel-check
rm -rf "$work"
mkdir -p "$work"
trap './testbed/run.sh stop >/dev/null' EXIT
failed=0
fail() { echo "FAIL $*"; failed=1; }
since() { tail -n +$(($1 + 1)) ${TESTBED_LOG}; }
rules="MAP *.jsh.test 127.0.0.1"

echo "== 1. guard-cases, two hosts, -tabs 1 and -tabs 3"
./testbed/run.sh start guard-cases >/dev/null
for h in a b; do
  for p in index.html spa-writes.html other-tab.html; do echo "http://$h.jsh.test:8770/$p"; done
done >"$work/urls.txt"
batch() { # name tabs
  local n
  n=$(wc -l <${TESTBED_LOG})
  timeout 600 ./bin/jsharvest crawl -urls "$work/urls.txt" -tabs "$2" -guard on -scope fqdn -host-resolver-rules "$rules" \
    -o "$work/$1" </dev/null >"$work/$1.log" 2>&1 || fail "$1: exit $?: $(tail -2 "$work/$1.log")"
  since "$n" | awk '{print $3, $4, $5}' | sort >"$work/server-$1.log"
}
batch seq 1
batch par 3
# One line for each run: its URL, its requests, the held-back ones, the
# guard's count, and the pages its requests came from.
per_run() { # name
  for h in a b; do
    local d="$work/$1/$h.jsh.test_8770/anon"
    jq -r '[.run_id, .target, (.guard.blocked // 0)] | @tsv' "$d/runs.jsonl" | while IFS=$'\t' read -r id t g; do
      jq -r --arg r "$id" 'select(.run == $r) | [.outcome, (.page // "" | sub("[?#].*"; ""))] | @tsv' "$d/requests.jsonl" |
        awk -F'\t' -v t="$t" -v g="$g" '{n++; if ($1 ~ /^held_back/) h++; p[$2]++}
          END {printf "%s requests=%d held=%d guard=%s pages=", t, n, h, g; for (k in p) printf "%s:%d ", k, p[k]; print ""}'
    done
  done | sort
}
per_run seq >"$work/runs-seq.txt"
per_run par >"$work/runs-par.txt"
cat "$work/runs-par.txt"
diff "$work/runs-seq.txt" "$work/runs-par.txt" >/dev/null || fail "the runs differ: $(diff "$work/runs-seq.txt" "$work/runs-par.txt")"
awk '{split($1, u, "?"); for (i = 5; i <= NF; i++) { p = $i; sub(/^pages=/, "", p); if (index(p, u[1] ":") != 1) print "a request of " $1 " on " p }}' \
  "$work/runs-par.txt" | grep . && fail "a run has requests of another page"
for h in a b; do
  d="$work/par/$h.jsh.test_8770/anon"
  jq -c . "$d/index.jsonl" >/dev/null || fail "$h: index.jsonl has a broken line"
  jq -c . "$d/requests.jsonl" >/dev/null || fail "$h: requests.jsonl has a broken line"
  [ "$(jq -r .sha256 "$d/index.jsonl" | sort)" = "$(jq -r .sha256 "$work/seq/$h.jsh.test_8770/anon/index.jsonl" | sort)" ] ||
    fail "$h: the scripts differ from -tabs 1"
  [ "$(wc -l <"$d/blocked.jsonl")" = "$(wc -l <"$work/seq/$h.jsh.test_8770/anon/blocked.jsonl")" ] || fail "$h: blocked.jsonl differs"
  jq -e 'select(.tabs != 3)' "$d/runs.jsonl" >/dev/null && fail "$h: a run without tabs 3"
  for f in index.jsonl requests.jsonl blocked.jsonl runs.jsonl run.json endpoints.jsonl; do
    [ "$(stat -c %a "$d/$f")" = 600 ] || fail "$h: $f not 0600"
  done
done
cat "$work"/par/*/anon/runs.jsonl | jq -r .run_id | sort | uniq -d | grep . && fail "two runs have one ID"
[ "$(cat "$work"/par/*/anon/runs.jsonl | wc -l)" = 6 ] || fail "not six runs"
b="$(ls "$work"/par/batch-*.json)"
jq -c '{tabs, unclaimed_held, failed, blocked}' "$b"
jq -e '.tabs == 3 and .failed == 0 and (.pages | length) == 6' "$b" >/dev/null || fail "the batch record"
# The runs overlapped (one started before another ended), and the starts
# kept -urls-rate (2 a second). A start is taken once its tab is made, not
# when the rate let it go: under load one pair may come closer than the
# gap (POL-23-4). So: no pair under 0.1 s, and two gaps in a row at least
# 0.7 s (a span of the whole batch would hide a limiter that let the first
# tabs go at once behind the waits for a free tab).
cat "$work"/par/*/anon/runs.jsonl | jq -rs 'sort_by(.started) | map([.started, .ended]) | .[] | @tsv' | python3 -c '
import sys, re, datetime
def at(s):
    s = re.sub(r"\.(\d{1,6})\d*", lambda m: "." + m.group(1).ljust(6, "0"), s.replace("Z", "+00:00"))
    return datetime.datetime.fromisoformat(s)
runs = [tuple(at(x) for x in l.split()) for l in sys.stdin if l.strip()]
gaps = [(b[0] - a[0]).total_seconds() for a, b in zip(runs, runs[1:])]
overlap = any(b[0] < a[1] for a, b in zip(runs, runs[1:]))
print("start gaps", " ".join("%.2f" % g for g in gaps), "overlap", overlap)
spans = [a + b for a, b in zip(gaps, gaps[1:])]
print("two-gap spans", " ".join("%.2f" % x for x in spans))
sys.exit(0 if overlap and min(gaps) >= 0.1 and min(spans) >= 0.7 else 1)' || fail "the runs did not overlap, or started closer than -urls-rate"
for p in $(grep -v '^#' testbed/apps/guard-cases/forbidden.txt); do
  grep -qF " $p" "$work/server-par.log" && fail "the server saw $p"
done
diff -q "$work/server-seq.log" "$work/server-par.log" >/dev/null ||
  fail "the server saw other requests: $(diff "$work/server-seq.log" "$work/server-par.log" | head -5)"
echo "seq $(grep -o 'took=[^ ]*\|batch done.*' "$work/seq.log" | tail -1); $(jq -r '((.ended | sub("\\.[0-9]+Z$"; "Z") | fromdate) - (.started | sub("\\.[0-9]+Z$"; "Z") | fromdate) | tostring) + " s"' "$work"/seq/batch-*.json) vs par $(jq -r '((.ended | sub("\\.[0-9]+Z$"; "Z") | fromdate) - (.started | sub("\\.[0-9]+Z$"; "Z") | fromdate) | tostring) + " s"' "$b")"

echo "== 2. session-app, -role user, -tabs 1 and 3"
export SESSION_APP_USER=member@app.test SESSION_APP_PASS=hunter22
./testbed/run.sh start session-app >/dev/null
./bin/jsharvest login -u http://127.0.0.1:8770/login -role user -profiles "$work/profiles" \
  -steps testbed/apps/session-app/login.steps.json >"$work/login.log" 2>&1 || fail "login: $(tail -2 "$work/login.log")"
for p in home a b c d e f; do echo "http://127.0.0.1:8770/members/$p"; done >"$work/members.txt"
role_batch() { # tabs
  local n d="$work/role$1/127.0.0.1/user"
  n=$(wc -l <${TESTBED_LOG})
  timeout 600 ./bin/jsharvest crawl -urls "$work/members.txt" -tabs "$1" -role user -profiles "$work/profiles" -o "$work/role$1" \
    </dev/null >"$work/role$1.log" 2>&1 || fail "role batch -tabs $1: exit $?: $(tail -2 "$work/role$1.log")"
  since "$n" >"$work/server-role$1.log"
  [ "$(jq -s 'map(select(.exit_code == 0 and .session != null and (.session.lost | not))) | length' "$d/runs.jsonl")" = 7 ] ||
    fail "-tabs $1: a run failed, ran without the login or lost it: $(jq -c '{target, exit_code, session}' "$d/runs.jsonl" | head -3)"
  # A guessed source map (<script>.map, round 17) may well be a 404: no page.
  grep -E "GET /members/" "$work/server-role$1.log" | grep -vE "GET /members/[^ ]*\.map( |$)" | grep -vE "^[^ ]+ [^ ]+ 200 " &&
    fail "-tabs $1: a members' page was not answered 200"
  grep -q "POST /api/login" "$work/server-role$1.log" && fail "-tabs $1: a tab logged in again"
  jq -e 'select(.guard == null or .config.guard != true)' "$d/runs.jsonl" >/dev/null && fail "-tabs $1: a logged-in run without the guard (-guard auto)"
  missed=$(./bin/testbed score -app testbed/apps/session-app -out "$d" | grep MISS | grep -v entry:main)
  [ -z "$missed" ] || fail "-tabs $1: markers: $missed"
  echo "-tabs $1: $(jq -s 'map(.duration_ms) | add / 1000 | floor' "$d/runs.jsonl") s of runs, $(grep -c . "$work/server-role$1.log") requests"
}
role_batch 1
role_batch 3

echo "== 3. interrupted: no URL starts after the interrupt"
./testbed/run.sh start guard-cases >/dev/null
n=$(wc -l <${TESTBED_LOG})
./bin/jsharvest crawl -urls "$work/urls.txt" -tabs 2 -urls-rate 0.5 -guard on -scope fqdn -host-resolver-rules "$rules" \
  -o "$work/int" </dev/null >"$work/int.log" 2>&1 &
pid=$!
sleep 4
kill -INT "$pid"
wait "$pid"
code=$?
sleep 1
[ "$code" = 130 ] || fail "interrupted: exit $code, want 130"
b="$(ls "$work"/int/batch-*.json 2>/dev/null)"
started=$(jq '.pages | length' "$b")
loaded=$(since "$n" | grep -cE "GET /(index|spa-writes|other-tab)\.html")
echo "interrupted after $started page(s); the server served $loaded"
jq -e '.canceled' "$b" >/dev/null || fail "interrupted: the batch record does not say so"
[ "$started" -lt 6 ] && [ "$loaded" -le "$started" ] || fail "interrupted: $loaded pages loaded for $started started"

echo "== 4. -tabs refused where it does not apply"
./bin/jsharvest crawl -u http://127.0.0.1:8770/ -tabs 2 -o "$work/x" </dev/null >"$work/refuse1.log" 2>&1 && fail "-tabs without -urls ran"
grep -q "works with -urls, or with -depth" "$work/refuse1.log" || fail "-tabs without -urls or -depth: $(tail -1 "$work/refuse1.log")"
./bin/jsharvest crawl -urls "$work/members.txt" -tabs 2 -attach http://127.0.0.1:1 -o "$work/x" </dev/null >"$work/refuse2.log" 2>&1 &&
  fail "-tabs with -attach ran"
grep -q "cannot be used with -attach" "$work/refuse2.log" || fail "-tabs with -attach: $(tail -1 "$work/refuse2.log")"

[ "$failed" = 0 ] && echo "parallel-check: ok" || { echo "parallel-check: FAILED"; exit 1; }
