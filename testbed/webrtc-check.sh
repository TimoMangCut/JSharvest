#!/usr/bin/env bash
# Layer against WebRTC leaking the real address around a proxy (plan-28 3.4,
# P3.5). With -proxy, jsharvest starts Chrome with
# --force-webrtc-ip-handling-policy=disable_non_proxied_udp. Chrome ignores
# a switch it does not know without a word, so the fixture is the proof:
# webrtc-app gathers the page's ICE candidates and reports their kinds.
#   1. control, no -proxy: at least one candidate (host, mDNS or not). A
#      Chrome that gathers none here proves nothing about step 2: FAIL.
#   2. -proxy http://127.0.0.1:8899 (the page is webrtc.jsh.test, which the
#      proxy maps to the testbed: it goes through the proxy, loopback would
#      not): the page's report arrived, through the proxy, and has no host
#      and no srflx.
# The proxy is a few lines of Python here (maps *.jsh.test to the testbed);
# bin/testbed logproxy can stand in for it.
# Usage: testbed/webrtc-check.sh   (exit 1 on failure)
set -uo pipefail
export JSHARVEST_ENGINE="${JSHARVEST_ENGINE:-cdp}"
export TESTBED_LOG="${TESTBED_LOG:-bin/testbed.log}" TESTBED_PID="${TESTBED_PID:-bin/testbed.pid}" TESTBED_WORK="${TESTBED_WORK:-bin}"
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
. "$root/testbed/lib/env.sh"
ensure_go_in_path || exit 1
# Chrome gathers no ICE candidate on loopback alone (a regress lane has
# nothing else): the gate re-executes itself in a network namespace of its
# own with a dummy interface (an RFC 5737 address), then in a user
# namespace mapped back to the caller (Chrome will not run as root with its
# sandbox). The Docker step (WEBRTC_IMAGE) stays on the host's network.
if [ -z "${WEBRTC_IMAGE:-}" ] && [ "${1:-}" != "--inside" ]; then
  build_testbed_bins || exit 1
  if ! unshare -rn true 2>/dev/null; then
    echo "SKIP: no unprivileged network namespaces"
    [ "${ALLOW_NETNS_SKIP:-}" = 1 ] && exit 0
    exit 1
  fi
  uid=$(id -u) gid=$(id -g)
  exec unshare -rn bash -c "ip link set lo up && ip link add dummy0 type dummy && ip addr add 192.0.2.10/24 dev dummy0 && ip link set dummy0 up && ip route add default dev dummy0 && exec unshare --user --map-user=$uid --map-group=$gid env TESTBED_NO_BUILD=1 bash testbed/webrtc-check.sh --inside"
fi
build_testbed_bins || exit 1
work=${TESTBED_WORK}/webrtc-check
rm -rf "$work"
mkdir -p "$work"
failed=0
fail() { echo "FAIL: $*"; failed=1; }

./testbed/run.sh start webrtc-app >/dev/null
proxylog="$work/proxy.log"
python3 -I - >"$proxylog" 2>&1 <<'PY' &
import http.client, http.server, urllib.parse, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        print("PROXY", u.hostname, u.path, flush=True)
        host = "127.0.0.1" if (u.hostname or "").endswith(".jsh.test") else u.hostname
        c = http.client.HTTPConnection(host, u.port or 80, timeout=10)
        c.request("GET", u.path + ("?" + u.query if u.query else ""), headers={"Host": u.netloc})
        r = c.getresponse(); b = r.read()
        self.send_response(r.status)
        for k, v in r.getheaders():
            if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("127.0.0.1", 8899), H).serve_forever()
PY
ppid=$!
trap 'kill "$ppid" 2>/dev/null; ./testbed/run.sh stop >/dev/null' EXIT
sleep 1

# jsh OUTDIR args...: jsharvest here, or in the Docker image when
# WEBRTC_IMAGE is set (docker-check step 8; the container is on the host's
# network, so the proxy and the testbed are at 127.0.0.1 for it too).
jsh() {
  out=$1
  shift
  if [ -n "${WEBRTC_IMAGE:-}" ]; then
    docker run --rm --network host -e JSHARVEST_ENGINE "$WEBRTC_IMAGE" "$@" -o /tmp/o
  else
    ./bin/jsharvest "$@" -o "$out"
  fi
}

report() { # run name -> the page's JSON report from the server's log
  grep -o "rtc/report?run=$1&c=[^ ]*" "$TESTBED_LOG" | tail -1 | sed 's/^[^&]*&c=//' |
    python3 -I -c 'import sys,urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))'
}

echo "== 1. control: no proxy"
jsh "$work/control" crawl -u "http://webrtc.jsh.test:8770/?run=control" -host-resolver-rules "MAP webrtc.jsh.test 127.0.0.1" -idle 5s \
  </dev/null >"$work/control.log" 2>&1 || { fail "control crawl exit $?"; tail -3 "$work/control.log"; }
c=$(report control)
n=$(jq '.kinds | length' <<<"$c" 2>/dev/null || echo 0)
if [ -z "$c" ]; then
  fail "control: the page's report never arrived"
elif [ "${n:-0}" -eq 0 ]; then
  echo "NOTE: this Chrome gathered no ICE candidate without a proxy ($c): step 2 would prove nothing"
  fail "control: no candidate (state: $(jq -r .state <<<"$c"))"
else
  jq -e '.kinds | index("host")' <<<"$c" >/dev/null || fail "control: candidates but no host: $c"
fi

echo "== 2. -proxy: no host, no srflx"
jsh "$work/proxy" crawl -u "http://webrtc.jsh.test:8770/?run=proxy" -proxy http://127.0.0.1:8899 -idle 5s \
  </dev/null >"$work/proxy-run.log" 2>&1 || { fail "proxy crawl exit $?"; tail -3 "$work/proxy-run.log"; }
grep -q "PROXY webrtc.jsh.test /" "$proxylog" || fail "the page did not go through the proxy"
p=$(report proxy)
if [ -z "$p" ]; then
  fail "proxy: the page's report never arrived (through the proxy: $(grep -c 'rtc/report' "$proxylog"))"
else
  jq -e '.state == "ok"' <<<"$p" >/dev/null || fail "proxy: the probe did not run: $p"
  jq -e '(.kinds | index("host")) or (.kinds | index("srflx"))' <<<"$p" >/dev/null && fail "proxy: a host or srflx candidate leaked: $p"
fi

[ "$failed" = 0 ] && echo "webrtc-check: ok (control $c, proxy $p)" || { echo "webrtc-check: FAILED"; exit 1; }
