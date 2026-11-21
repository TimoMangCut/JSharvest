#!/usr/bin/env bash
# Layer 1 of "a public page never touches the internal network" (plan-28
# 3.4, P3.2). A "public" page is served from 198.51.100.10:8770 (TEST-NET-2,
# put on lo inside a network namespace of our own); an "internal" server
# listens on 127.0.0.1:8771. lan-app's page reaches for the internal one by
# fetch, <img>, a decimal IP, localhost and a service worker.
#   1. -guard on: no /lan/* request reaches the internal server; blocked.jsonl
#      has each with reason private-address (the service worker's too); the
#      page's own /ok and /done go through; lan.jsh.test (no host rules: a
#      name that does not resolve) is not a private literal and is not held.
#   2. With -host-resolver-rules "MAP lan.jsh.test 127.0.0.1": the request to
#      lan.jsh.test:8771 reaches the internal server and is not in
#      blocked.jsonl (host rules make it an internal host that is allowed);
#      the literals are still held. (Chrome's own LNA may still refuse the
#      host: it judges by the address it connects to; that is a NOTE.)
#   3. -guard off (layer 1 does not run): the same page's requests to
#      127.0.0.1 still do not reach the internal server, Chrome's Local
#      Network Access (layer 2) refuses them, and run.json has
#      stats.lna_denied > 0.
# Usage: testbed/lan-check.sh   (exit 1 on failure). Re-executes itself in
# a network namespace (unshare -rn) and, inside, as its own user again, as
# Chrome will not run as root with its sandbox.
set -uo pipefail
export JSHARVEST_ENGINE=cdp
export TESTBED_LOG="${TESTBED_LOG:-bin/testbed.log}" TESTBED_PID="${TESTBED_PID:-bin/testbed.pid}" TESTBED_WORK="${TESTBED_WORK:-bin}"
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
. "$root/testbed/lib/env.sh"
ensure_go_in_path || exit 1

if [ "${1:-}" != "--inside" ]; then
  build_testbed_bins || exit 1
  if ! unshare -rn true 2>/dev/null; then
    echo "SKIP: no unprivileged network namespaces (the public address cannot be made)"
    [ "${ALLOW_NETNS_SKIP:-}" = 1 ] && exit 0
    exit 1
  fi
  uid=$(id -u) gid=$(id -g)
  exec unshare -rn bash -c "ip link set lo up && ip addr add 198.51.100.10/32 dev lo && exec unshare --user --map-user=$uid --map-group=$gid env TESTBED_NO_BUILD=1 bash testbed/lan-check.sh --inside"
fi

work=${TESTBED_WORK}/lan-check
rm -rf "$work"
mkdir -p "$work"
failed=0
fail() { echo "FAIL: $*"; failed=1; }
app="$root/testbed/apps/lan-app"
pub="$work/public.log" lan="$work/internal.log"
pids=()
trap 'kill "${pids[@]}" 2>/dev/null' EXIT

serve() { # addr log
  nohup ./bin/testbed serve -app "$app" -addr "$1" >"$2" 2>&1 &
  pids+=($!)
}
serve 198.51.100.10:8770 "$pub"
serve 127.0.0.1:8771 "$lan"
sleep 1

blocked() { find "$1" -name blocked.jsonl 2>/dev/null | head -1; }

echo "== 1. a public page reaches for the internal network"
out="$work/one"
timeout 120 ./bin/jsharvest crawl -u http://198.51.100.10:8770/ -guard on -page-dwell 6s -o "$out" </dev/null >"$work/one.log" 2>&1
code=$?
[ "$code" = 0 ] || { fail "exit $code, want 0"; tail -5 "$work/one.log"; }
# /lan/sw: a service worker needs a secure context, which http://198.51.100.10
# is not, so it never runs here; the worker branch of the origin is unit
# tested (guard referenceOrigin). The server must still never see it.
for p in /lan/fetch /lan/img /lan/num /lan/localhost /lan/sw; do
  grep -q " GET $p" "$lan" && fail "the internal server saw $p"
done
b=$(blocked "$out")
for p in /lan/fetch /lan/img /lan/num /lan/localhost; do
  [ -n "$b" ] && jq -e --arg p "$p" 'select((.url | endswith($p)) and .reason == "private-address")' "$b" >/dev/null 2>&1 ||
    fail "blocked.jsonl has no private-address record for $p"
done
grep -q " GET /ok" "$pub" || fail "the page's own /ok did not go through"
grep -q " GET /done" "$pub" || fail "the page's own /done did not go through"
grep -q " GET /lan/rules" "$lan" && fail "lan.jsh.test reached the internal server without host rules (it has no address)"

echo "== 2. host rules make lan.jsh.test an internal host that is allowed"
: >"$lan"
out="$work/two"
timeout 120 ./bin/jsharvest crawl -u http://198.51.100.10:8770/ -guard on -page-dwell 6s -host-resolver-rules "MAP lan.jsh.test 127.0.0.1" -o "$out" </dev/null >"$work/two.log" 2>&1
code=$?
[ "$code" = 0 ] || { fail "exit $code, want 0"; tail -5 "$work/two.log"; }
# Layer 1 lets lan.jsh.test through (host rules: internal, allowed). Chrome's
# own Local Network Access may still refuse it, a public http page asking a
# loopback address (cors:InsecureLocalNetwork): that is Chrome, not the guard.
if ! grep -q " GET /lan/rules" "$lan"; then
  r=$(find "$out" -name requests.jsonl | head -1)
  o=$([ -n "$r" ] && jq -r 'select(.url | endswith("/lan/rules")) | .outcome' "$r" | head -1)
  case "$o" in
    failed:cors:*LocalNetwork*) echo "NOTE: Chrome's LNA refused lan.jsh.test ($o), the guard let it through" ;;
    *) fail "the request to lan.jsh.test did not reach the internal server (outcome: ${o:-none})" ;;
  esac
fi
b=$(blocked "$out")
if [ -n "$b" ] && grep -q '/lan/rules' "$b"; then fail "blocked.jsonl holds /lan/rules"; fi
for p in /lan/fetch /lan/num /lan/localhost; do
  grep -q " GET $p" "$lan" && fail "host rules opened $p, a literal"
done

echo "== 3. layer 2 alone: -guard off -lan-guard off (layer 1 does not run), Chrome's Local Network Access"
: >"$lan"
out="$work/three"
timeout 120 ./bin/jsharvest crawl -u http://198.51.100.10:8770/ -guard off -lan-guard off -page-dwell 3s -o "$out" </dev/null >"$work/three.log" 2>&1
code=$?
[ "$code" = 0 ] || { fail "exit $code, want 0"; tail -5 "$work/three.log"; }
for p in /lan/fetch /lan/img /lan/num /lan/localhost /lan/sw; do
  grep -q " GET $p" "$lan" && fail "-guard off -lan-guard off: the internal server saw $p (LNA did not refuse it)"
done
grep -q " GET /ok" "$pub" || fail "-guard off -lan-guard off: the page's own /ok did not go through"
runjson=$(find "$out" -name run.json 2>/dev/null | head -1)
# An http public page: Chrome 156 refuses its local requests itself
# (InsecureLocalNetwork, stats.lna_insecure); the permission jsharvest
# denies (stats.lna_denied) is what a secure page meets. Either counts here;
# that Chrome took the deny is checked by the absence of its warning.
n=$([ -n "$runjson" ] && jq '(.stats.lna_denied // 0) + (.stats.lna_insecure // 0)' "$runjson" || echo 0)
[ "$n" -gt 0 ] || fail "run.json counts no request refused by LNA (got $n)"
[ -n "$runjson" ] && jq -e '(.warnings // []) | map(select(startswith("Local Network Access could not be denied"))) | length == 0' "$runjson" >/dev/null ||
  fail "Chrome took neither LNA permission name: $(jq -c '.warnings' "$runjson")"
[ -n "$(blocked "$out")" ] && grep -q private-address "$(blocked "$out")" && fail "-guard off -lan-guard off: blocked.jsonl holds layer 1's records"

echo "== 4. default -guard off keeps -lan-guard on (layer 1 still refuses private literals)"
: >"$lan"
: >"$pub"
out="$work/four"
timeout 120 ./bin/jsharvest crawl -u http://198.51.100.10:8770/ -guard off -page-dwell 6s -o "$out" </dev/null >"$work/four.log" 2>&1
code=$?
[ "$code" = 0 ] || { fail "case 4 exit $code, want 0"; tail -5 "$work/four.log"; }
for p in /lan/fetch /lan/img /lan/num /lan/localhost /lan/sw; do
  grep -q " GET $p" "$lan" && fail "-guard off (default -lan-guard on): the internal server saw $p"
done
b=$(blocked "$out")
for p in /lan/fetch /lan/img /lan/num /lan/localhost; do
  [ -n "$b" ] && jq -e --arg p "$p" 'select((.url | endswith($p)) and .reason == "private-address")' "$b" >/dev/null 2>&1 ||
    fail "case 4: blocked.jsonl has no private-address record for $p"
done
grep -q " GET /ok" "$pub" || fail "case 4: the page's own /ok did not go through"

[ "$failed" = 0 ] && echo "lan-check: ok" || { echo "lan-check: FAILED"; exit 1; }
