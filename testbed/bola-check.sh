#!/usr/bin/env bash
# The BOLA gate (plan-28 P5.3; docs/gd7-bola-design.md 6.3): jsharvest
# authz -peers, which sends requests, against peer-app only.
#   A. peer-app: alice, bob, charlie, dave log in; anon and the four are
#      crawled alike (-explore, the guard holds the writes); the crawl of each
#      has the requests peer.truth.json needs (keys?action=regenerate too);
#      the server is told the crawl is over (quota expires for all).
#   B. authz -peers alice,bob -relation same-org: every verdict of
#      peer.truth.json, nothing else; -reveal as well; then -private
#      'orgs/.*/projects' turns the shared project into a bypass; 0600 files,
#      the server saw what bola.sent.jsonl says, never a login, a logout, a
#      regeneration.
#   C. authz -peers alice,charlie -relation cross-org, and with -substitute.
#   D. authz -peers alice,dave -relation cross-org (dave owns nothing: Bogus);
#      no Bogus id in id_A +- 1000, negative or 0.
#   E. the server restarted (every session gone): no verdict but unclear and
#      skipped; a dead session never reads as enforced or replay_broken.
#   F. the MCP tool get_authz: secrets masked by default (even over a run with
#      -reveal), the untrusted envelope; shown with the MCP's -reveal.
# Not in testbed/regress.sh yet: it goes there when authz -peers is built.
# Usage: testbed/bola-check.sh   (exit 1 on failure)
set -uo pipefail
# The browser engine: these gates test what Chrome sees.
export JSHARVEST_ENGINE="${JSHARVEST_ENGINE:-cdp}"
# A lane of testbed/regress.sh gives each gate its own server log and pid,
# and its own root for the work directories; alone, a gate uses bin/.
export TESTBED_LOG="${TESTBED_LOG:-bin/testbed.log}" TESTBED_PID="${TESTBED_PID:-bin/testbed.pid}" TESTBED_WORK="${TESTBED_WORK:-bin}"
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
. "$root/testbed/lib/env.sh"
ensure_go_in_path || exit 1
build_testbed_bins || exit 1
work=${TESTBED_WORK}/bola-check
rm -rf "$work"
mkdir -p "$work"
trap './testbed/run.sh stop >/dev/null' EXIT
failed=0
fail() { echo "FAIL $*"; failed=1; }
export PEER_PASS=hunter22
app=testbed/apps/peer-app
truth=$app/peer.truth.json
out=$work/out
host=127.0.0.1
people=(alice bob charlie dave)
since() { tail -n +$(($1 + 1)) ${TESTBED_LOG}; }

echo "== A. peer-app: four people, five crawls"
./testbed/run.sh start peer-app >/dev/null
for u in "${people[@]}"; do
  ./bin/jsharvest login -u http://127.0.0.1:8770/login -role "$u" -profiles "$work/profiles" -steps "$app/login-$u.steps.json" \
    >"$work/login-$u.log" 2>&1 || fail "login $u"
done
for r in anon "${people[@]}"; do
  rf=()
  [ "$r" != anon ] && rf=(-role "$r")
  timeout 600 ./bin/jsharvest crawl -u http://127.0.0.1:8770/ "${rf[@]}" -profiles "$work/profiles" -depth 0 -explore -page-rate 10 -o "$out" \
    </dev/null >"$work/crawl-$r.log" 2>&1 || fail "crawl $r: exit $?"
done
# What each crawl recorded: the open pages for anon; for a person, the
# requests of its own ids. Case 11 (the regeneration) is a click of the
# explore: if it was not clicked there is nothing for replayActionRe to skip.
grep -q "/api/peer/announcements/" "$out/$host/anon/requests.jsonl" || fail "anon: no announcement recorded"
for u in alice bob charlie; do
  for p in "/api/peer/private-notes/" "/api/peer/orders/" "/api/peer/wallets-leaky/" "/api/peer/graphql" "/api/peer/quota/" \
    "/api/peer/signed-preview/" "/api/peer/files/" "/api/peer/lookup?itemId=" "/api/peer/orgs/" "/api/peer/keys/"; do
    grep -qF "$p" "$out/$host/$u/requests.jsonl" || fail "$u: no request $p recorded"
  done
  grep -qF "action=regenerate" "$out/$host/$u/requests.jsonl" || fail "$u: the regenerate click was not recorded (case 11)"
done
grep -qF "/api/peer/preferences?userId=" "$out/$host/dave/requests.jsonl" || fail "dave: no preferences request recorded"
for p in "/api/peer/private-notes/" "/api/peer/orders/" "/api/peer/wallets/" "/api/peer/lookup" "GetVaultItem"; do
  grep -qF "$p" "$out/$host/dave/requests.jsonl" && fail "dave asked for $p: he owns nothing"
done
# The credentials of each person: its session cookie and its CSRF token.
: >"$work/creds.txt"
for u in "${people[@]}"; do
  jq -r --arg u "$u" '.cookies[] | select(.name == "peer_session" or .name == "peer_csrf") | $u + "\t" + .value' \
    "$work/profiles/$host/$u/jsharvest-session.json" >>"$work/creds.txt"
done
[ "$(wc -l <"$work/creds.txt")" -ge 8 ] || fail "creds.txt: $(wc -l <"$work/creds.txt") lines, want 8 (two a person)"
# The crawl is over: from now on quota's token is expired for everybody.
curl -sf -X POST 'http://127.0.0.1:8770/api/peer/_phase?p=replay' >/dev/null || fail "the phase call"

# bola NAME PEERS SCENARIO [peerscore flags...] -- [authz flags...]
# (SCENARIO - : no peerscore, the caller judges the run)
bola() {
  local name=$1 peers=$2 scenario=$3 n
  shift 3
  local score=()
  while [ $# -gt 0 ] && [ "$1" != -- ]; do score+=("$1"); shift; done
  [ "${1:-}" = -- ] && shift
  rm -rf "$out/$host/authz"
  n=$(wc -l <${TESTBED_LOG})
  ./bin/jsharvest authz -o "$out" -profiles "$work/profiles" -target "$host" -rate 50 -peers "$peers" "$@" >"$work/bola-$name.log" 2>&1 ||
    fail "authz $name: $(tail -2 "$work/bola-$name.log")"
  rm -rf "$work/bola-$name"
  cp -r "$out/$host/authz" "$work/bola-$name"
  since "$n" >"$work/server-$name.log"
  grep -E "^authz|^note|^stopped" "$work/bola-$name.log"
  [ "$scenario" = - ] && return
  ./bin/testbed peerscore -truth "$truth" -bola "$work/bola-$name" -scenario "$scenario" -secrets "$app/secrets.txt" -creds "$work/creds.txt" "${score[@]}" ||
    fail "peerscore $name"
}
# The server saw each request bola.sent.jsonl says went out, and no other.
sent_matches() { # name
  local sent seen
  sent=$(jq -r 'select(.dry_run != true and (.error // "") == "") | .n' "$work/bola-$1/bola.sent.jsonl" | wc -l)
  seen=$(grep -c " PEERLOG user=" "$work/server-$1.log")
  [ "$sent" = "$seen" ] || fail "$1: bola.sent.jsonl has $sent requests, the server saw $seen"
}
never() { # name
  local name=$1 p
  for p in "/api/login" "/api/logout" "/api/peer/login" "/api/peer/logout" "action=regenerate" "/api/peer/_phase"; do
    grep -qF "$p" "$work/server-$name.log" && fail "$name: the server saw $p"
  done
}
modes() { # name: the files of the run, 0600, in 0700 directories (no trial file when every session is dead)
  local d=$work/bola-$1 f
  for f in "$d"/bola.json "$d"/bola.md "$d"/bola.sent.jsonl "$d"/trials/*.http; do
    [ -e "$f" ] || continue
    [ "$(stat -c %a "$f")" = 600 ] || fail "$1: ${f#"$d"/} not 0600"
  done
  for f in "$d" "$d/trials"; do
    [ "$(stat -c %a "$f")" = 700 ] || fail "$1: $f not 0700"
  done
}
check_run() { sent_matches "$1"; never "$1"; modes "$1"; }

echo "== B. authz -peers alice,bob (same-org)"
bola same alice,bob alice-bob-same-org -- -redact=false -relation same-org
check_run same
bola redacted alice,bob - -- -relation same-org
check_run redacted
grep -q "REDACTED_" "$work/bola-redacted/bola.sent.jsonl" || fail "bola default -redact: no REDACTED_ in bola.sent.jsonl"
while IFS=$'\t' read -r _ cred; do
  [ -z "$cred" ] && continue
  grep -qF -- "$cred" "$work/bola-redacted/bola.sent.jsonl" "$work/bola-redacted"/trials/*.http 2>/dev/null &&
    fail "bola default -redact: raw peer credential leaked into bola.sent.jsonl or trials/"
done <"$work/creds.txt"
bola reveal alice,bob alice-bob-same-org -reveal -- -redact=false -relation same-org -reveal
check_run reveal
bola private alice,bob alice-bob-same-org-private -- -redact=false -relation same-org -private 'orgs/.*/projects'
check_run private
jq -e '[.items[] | select(.key | test("/projects/")) | .verdict] | all(. == "bypass")' "$work/bola-private/bola.json" >/dev/null ||
  fail "-private: the projects are not all bypass"
jq -e '[.items[] | select(.key | test("/projects/")) | .verdict] | all(. == "shared")' "$work/bola-same/bola.json" >/dev/null ||
  fail "same-org: the projects are not all shared"

echo "== C. authz -peers alice,charlie (cross-org)"
bola cross alice,charlie alice-charlie-cross-org -- -redact=false -relation cross-org
check_run cross
bola subst alice,charlie alice-charlie-cross-org-substitute -- -redact=false -relation cross-org -substitute
check_run subst

echo "== D. authz -peers alice,dave (cross-org): Bogus"
bola dave alice,dave alice-dave-cross-org -- -redact=false -relation cross-org
check_run dave
# featured answers a Bogus id as it answers the trial: enforced (gd7 8 #5), so
# nothing is stopped here; the fuse is tested in internal/replay.
jq -e '[.items[] | select(.reason | test("names nothing"))] | length > 0' "$work/bola-dave/bola.json" >/dev/null || fail "dave: no item concluded from a Bogus id"
python3 -I - "$work/bola-dave/bola.json" <<'PY' || fail "dave: a Bogus id is not far enough from id_A"
import json, sys
bad = n = 0
for it in json.load(open(sys.argv[1]))["items"]:
    for i in it.get("ids") or []:
        b, v = i.get("bogus") or "", i.get("value") or ""
        if not b:
            continue
        if b == v:
            print("bogus equals the id:", it["key"], v); bad += 1
        if b.isdigit() and v.isdigit():
            n += 1
            if int(b) <= 0 or abs(int(b) - int(v)) <= 1000:
                print("bogus too near:", it["key"], v, b); bad += 1
        elif b.startswith("-"):
            print("negative bogus:", it["key"], b); bad += 1
if n == 0:
    print("no numeric Bogus id in bola.json"); bad += 1
sys.exit(1 if bad else 0)
PY

echo "== E. every session gone"
./testbed/run.sh start peer-app >/dev/null
bola dead alice,bob - -- -relation same-org
check_run dead
jq -e '[.items[].verdict] | length > 0 and all(. == "unclear" or . == "skipped")' "$work/bola-dead/bola.json" >/dev/null ||
  fail "dead sessions: $(jq -c '.summary' "$work/bola-dead/bola.json")"
grep -qi "session is dead" "$work/bola-dead.log" "$work/bola-dead/bola.md" || fail "dead sessions: no note says so"

echo "== F. get_authz over MCP: masked by default, shown with -reveal"
# A copy of the out directory whose authz is the run of B with -reveal.
cp -r "$out" "$work/mcpout"
rm -rf "$work/mcpout/$host/authz"
cp -r "$work/bola-reveal" "$work/mcpout/$host/authz"
args='{"mode":"peers"}'
./bin/testbed mcpcall -cmd "./bin/jsharvest mcp -o $work/mcpout" -tool get_authz -args "$args" >"$work/mcp-masked.json" || fail "get_authz"
./bin/testbed mcpcall -cmd "./bin/jsharvest mcp -reveal -o $work/mcpout" -tool get_authz -args "$args" >"$work/mcp-revealed.json" || fail "get_authz -reveal"
for f in mcp-masked mcp-revealed; do
  jq -e '.untrusted == "target"' "$work/$f.json" >/dev/null || fail "$f: no untrusted envelope"
  jq -e . "$work/$f.json" >/dev/null || fail "$f: not JSON"
done
leaks_masked=0 leaks_revealed=0
while IFS= read -r s; do
  case "$s" in "#"* | "") continue ;; esac
  grep -qF -- "$s" "$work/mcp-masked.json" && leaks_masked=$((leaks_masked + 1))
  grep -qF -- "$s" "$work/mcp-revealed.json" && leaks_revealed=$((leaks_revealed + 1))
done <"$app/secrets.txt"
[ "$leaks_masked" = 0 ] || fail "get_authz: $leaks_masked secret(s) in the masked answer"
[ "$leaks_revealed" -gt 0 ] || fail "get_authz -reveal: no secret in the answer"
grep -q "REDACTED_" "$work/mcp-masked.json" || fail "get_authz: no REDACTED_ value in the masked answer"

[ "$failed" = 0 ] && echo "bola-check: ok"
exit "$failed"
