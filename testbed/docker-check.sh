#!/usr/bin/env bash
# The 5.2 gate (docs/gd5-container-design.md, 4): the image, run as the
# user does.
#   1. It runs as uid 1000, with the pinned Chrome; jsharvest help works.
#   2. Crawls of webpack-vanilla and vite-pwa (--network host) keep the
#      bench's baseline; the files on the host are uid 1000, 0600/0700;
#      --user 1234:1234 writes files of 1234.
#   3. Under Docker's default seccomp, --no-sandbox with a warning; with
#      seccomp=unconfined, no-new-privileges and no capabilities (compose),
#      Chrome's own sandbox.
#   4. docker stop in a crawl: out within 10 s, run.json written, no zombie.
#   5. A login by hand: noVNC answers on the host's loopback, VNC listens
#      on the container's loopback only, Chrome runs with a window on :99;
#      Enter on stdin saves the snapshot, 0600. The person's login is a page
#      that logs in when opened (/dev/hand-login).
#      Without -i, the login says no Enter can come and saves nothing.
#   6. A login with a script (session-app), then crawl -role user with it.
#   7. docker compose, as shipped: Chrome's sandbox on, the baseline kept.
#   8. With -proxy, the image's Chrome gathers no host or srflx ICE candidate
#      (WebRTC policy; the same fixture as testbed/webrtc-check.sh, run in the
#      image). NOT YET RUN: written from the other steps, first run is O's.
# Usage: testbed/docker-check.sh   (exit 1 on failure; needs Docker)
set -uo pipefail
# The browser engine: these gates test what Chrome sees (crawl -engine auto
# would take the HTTP engine for anon).
export JSHARVEST_ENGINE="${JSHARVEST_ENGINE:-cdp}"
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
. "$root/testbed/lib/env.sh"
ensure_go_in_path || exit 1
require_cmds docker jq curl awk || exit 1
require_built_apps "$root" || exit 1
go build -o bin/testbed ./testbed/cmd/testbed || exit 1
img=${IMAGE:-jsharvest:dev}
chrome=156.0.8078.79
gw=$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')
work=bin/docker-check
rm -rf "$work"
mkdir -p "$work/out" "$work/profiles"
chmod 700 "$work/out" "$work/profiles"
failed=0
fail() { echo "FAIL $*"; failed=1; }
cleanup() {
  docker rm -f jsh-stop jsh-login >/dev/null 2>&1
  ./testbed/run.sh stop >/dev/null
}
trap cleanup EXIT
[ -z "${NO_BUILD:-}" ] && { docker build -t "$img" . >"$work/build.log" 2>&1 || { tail -5 "$work/build.log"; exit 1; }; }
run() { # docker run args... -- jsharvest args...
  docker run --rm --network host -e JSHARVEST_ENGINE -v "$root/$work/out:/output" -v "$root/$work/profiles:/profiles" "$@"
}

echo "== 1. the image"
[ "$(docker run --rm "$img" id -u)" = 1000 ] || fail "not uid 1000"
if [ "$(uname -m)" = "x86_64" ]; then
  docker run --rm "$img" chrome --version | grep -q "$chrome" || fail "Chrome is not $chrome"
else
  docker run --rm "$img" chrome --version >/dev/null || fail "Chrome binary failed"
fi
docker run --rm "$img" help | grep -q "jsharvest crawl" || fail "jsharvest help"
# Every command of the usage reaches jsharvest, not a program of that name.
for c in $(docker run --rm "$img" help | awk '$1 == "jsharvest" && $2 ~ /^[a-z]+$/ {print $2}' | sort -u); do
  h=$(docker run --rm "$img" "$c" -h 2>&1) # whole: grep -q would end docker's write early
  grep -qiE "^usage of $c" <<<"$h" || fail "docker run $c does not reach jsharvest: $(head -c 200 <<<"$h")"
done

echo "== 2. crawls"
for app in webpack-vanilla vite-pwa; do
  ./testbed/run.sh start "$app" >/dev/null
  rm -rf "$work/out/127.0.0.1"
  run "$img" crawl -u http://127.0.0.1:8770/ >"$work/crawl-$app.log" 2>&1 || fail "crawl $app: $(tail -2 "$work/crawl-$app.log")"
  ./bin/testbed score -app "testbed/apps/$app" -out "$work/out/127.0.0.1/anon" -gate >"$work/score-$app.log" 2>&1 ||
    fail "$app below its baseline: $(tail -2 "$work/score-$app.log")"
  echo "$app: $(grep -m1 'recall:' "$work/score-$app.log" | xargs)"
done
for f in "$work/out/127.0.0.1/anon/requests.jsonl" "$work/out/127.0.0.1/anon/index.jsonl"; do
  [ "$(stat -c '%u %a' "$f")" = "1000 600" ] || fail "$f: $(stat -c '%u %a' "$f"), want 1000 600"
done
[ "$(stat -c '%u %a' "$work/out/127.0.0.1/anon")" = "1000 700" ] || fail "output dir: $(stat -c '%u %a' "$work/out/127.0.0.1/anon"), want 1000 700"
# Another uid (--user "$(id -u):$(id -g)" of a host user who is not 1000).
mkdir -p "$work/other" && chmod 777 "$work/other"
docker run --rm --network host -e JSHARVEST_ENGINE --user 1234:1234 -v "$root/$work/other:/output" "$img" crawl -u http://127.0.0.1:8770/ >"$work/crawl-uid.log" 2>&1 ||
  fail "crawl as uid 1234: $(tail -2 "$work/crawl-uid.log")"
# Its directories are 0700 and its: only their owner looks inside.
[ "$(stat -c '%u %a' "$work/other/127.0.0.1" 2>/dev/null)" = "1234 700" ] || fail "as uid 1234: $(stat -c '%u %a' "$work/other/127.0.0.1" 2>&1), want 1234 700"
docker run --rm --user 1234:1234 -v "$root/$work/other:/output" "$img" sh -c 'test -s /output/127.0.0.1/anon/requests.jsonl' || fail "as uid 1234: no request log"
docker run --rm --user 1234:1234 -v "$root/$work/other:/output" "$img" sh -c 'rm -rf /output/*' # theirs to remove

echo "== 3. Chrome's sandbox"
# Docker's default seccomp: no user namespaces, so --no-sandbox, said so.
run "$img" crawl -u http://127.0.0.1:8770/ -o /tmp/o >"$work/sandbox-default.log" 2>&1 || fail "crawl under the default seccomp"
grep -q "warning: no user namespaces" "$work/sandbox-default.log" || fail "no warning of --no-sandbox"
# As docker-compose.yml runs it: Chrome's sandbox on, all capabilities
# dropped, no new privileges.
run --security-opt seccomp=unconfined --security-opt no-new-privileges:true --cap-drop ALL "$img" crawl -u http://127.0.0.1:8770/ -o /tmp/o \
  >"$work/sandbox-on.log" 2>&1 || fail "crawl with Chrome's sandbox: $(tail -2 "$work/sandbox-on.log")"
grep -q "Chrome sandbox: on" "$work/sandbox-on.log" || fail "Chrome's sandbox is not on: $(head -2 "$work/sandbox-on.log")"

echo "== 4. docker stop in a crawl"
./testbed/run.sh start frontier-app >/dev/null
rm -rf "$work/out/127.0.0.1"
docker run -d --name jsh-stop --network host -e JSHARVEST_ENGINE -v "$root/$work/out:/output" "$img" crawl -u http://127.0.0.1:8770/ -depth 5 -page-rate 1 >/dev/null
sleep 8
z=$(docker exec jsh-stop sh -c 'grep -l "^State:.*Z" /proc/[0-9]*/status 2>/dev/null | wc -l')
[ "$z" = 0 ] || fail "$z zombie processes in a crawl"
t0=$(date +%s)
docker stop -t 10 jsh-stop >/dev/null
dt=$(($(date +%s) - t0))
code=$(docker inspect -f '{{.State.ExitCode}}' jsh-stop)
docker logs jsh-stop >"$work/stop.log" 2>&1
docker rm jsh-stop >/dev/null
[ "$dt" -le 10 ] || fail "docker stop took ${dt}s"
[ -f "$work/out/127.0.0.1/anon/run.json" ] || fail "no run.json after docker stop (exit $code)"
echo "stopped in ${dt}s, exit $code"

echo "== 5. a login by hand, through noVNC"
# The login's container is on the bridge network, to publish noVNC on the
# host's loopback only: the testbed listens on the bridge's gateway, which
# only containers reach.
./testbed/run.sh start session-app "$gw:8770" >/dev/null
rm -f "$work/stdin"
mkfifo "$work/stdin"
exec 4<>"$work/stdin"
docker run -i --name jsh-login -p 127.0.0.1:6080:6080 -e JSHARVEST_VNC_PASSWORD=gate-pass -v "$root/$work/profiles:/profiles" \
  "$img" login -u "http://$gw:8770/dev/hand-login" -role hand <"$work/stdin" >"$work/login-hand.log" 2>&1 &
lp=$!
ok=""
for _ in $(seq 40); do
  curl -fs -o /dev/null http://127.0.0.1:6080/vnc.html && { ok=1; break; }
  sleep 0.5
done
[ -n "$ok" ] || fail "noVNC does not answer on 127.0.0.1:6080"
# 5900 (0x170C) only on the container's loopback (0100007F).
# 5900 (0x170C) only on the container's loopback: 127.0.0.1 or ::1.
docker exec jsh-login sh -c 'cat /proc/net/tcp /proc/net/tcp6' | awk '$4 == "0A" && $2 ~ /:170C$/ {print $2}' |
  grep -vE '^(0100007F|00000000000000000000000001000000):' && fail "VNC listens beyond the loopback"
docker exec jsh-login sh -c 'cat /proc/net/tcp /proc/net/tcp6' | awk '$4 == "0A" && $2 ~ /:170C$/' | grep -q . || fail "VNC does not listen"
docker exec jsh-login sh -c 'ls -A /tmp/.X11-unix; cat /proc/net/unix' | grep -q '@/tmp/.X11-unix/X99' && fail "Xvfb listens on an abstract socket"
sleep 3
procs=$(docker exec jsh-login sh -c 'for p in /proc/[0-9]*/cmdline; do tr "\0" " " <$p; echo; done' | grep -E '(^| )(/opt/chrome-linux64/chrome|/usr/local/bin/chrome|/usr/lib/chromium/chromium|/usr/bin/chromium)' || true)
[ -n "$procs" ] || fail "no Chrome in the login"
grep -q -- "--headless" <<<"$procs" && fail "the login's Chrome is headless"
echo >&4
for _ in $(seq 40); do kill -0 "$lp" 2>/dev/null || break; sleep 0.5; done
wait "$lp" || fail "login by hand: $(tail -2 "$work/login-hand.log")"
exec 4>&-
docker rm jsh-login >/dev/null 2>&1
snap="$work/profiles/${gw}_8770/hand/jsharvest-session.json"
[ "$(stat -c '%a' "$snap" 2>/dev/null)" = 600 ] || fail "no snapshot 0600 after the login by hand"

# Without -i, stdin is at its end: no Enter can come, so the login waits
# for the tab to close, and saves nothing meanwhile.
docker run -d --name jsh-login -v "$root/$work/profiles:/profiles" "$img" login -u "http://$gw:8770/dev/hand-login" -role noin >/dev/null
sleep 8
docker logs jsh-login 2>&1 | grep -q "stdin is closed" || fail "login without -i: $(docker logs jsh-login 2>&1 | tail -2)"
[ "$(docker inspect -f '{{.State.Running}}' jsh-login)" = true ] || fail "login without -i did not wait"
docker rm -f jsh-login >/dev/null
[ -e "$work/profiles/${gw}_8770/noin/jsharvest-session.json" ] && fail "login without -i saved a session nobody logged in to"

echo "== 6. a login with a script, then crawl -role"
./testbed/run.sh start session-app >/dev/null
rm -rf "$work/out/127.0.0.1"
run -e SESSION_APP_USER=member@app.test -e SESSION_APP_PASS=hunter22 -v "$root/testbed/apps/session-app:/steps:ro" "$img" \
  login -u http://127.0.0.1:8770/login -role user -steps /steps/login.steps.json >"$work/login-steps.log" 2>&1 || fail "login -steps: $(tail -2 "$work/login-steps.log")"
run -e SESSION_APP_USER=member@app.test -e SESSION_APP_PASS=hunter22 -v "$root/testbed/apps/session-app:/steps:ro" "$img" \
  crawl -u http://127.0.0.1:8770/members/home -role user -depth 1 >"$work/crawl-role.log" 2>&1 || fail "crawl -role: $(tail -2 "$work/crawl-role.log")"
jq -e '.session.lost != true and (.pages // 1) > 0' "$work/out/127.0.0.1/user/run.json" >/dev/null 2>&1 || fail "crawl -role user: $(jq -c '.session' "$work/out/127.0.0.1/user/run.json" 2>/dev/null)"
grep -q "members" "$work/out/127.0.0.1/user/pages.jsonl" 2>/dev/null || fail "crawl -role user reached no members' page"

echo "== 7. docker compose"
mkdir -p "$work/compose-out" "$work/compose-profiles"
./testbed/run.sh start vite-vanilla "$gw:8770" >/dev/null # no service worker: http on the gateway is no secure context
JSH_IMAGE="$img" JSH_UID="$(id -u)" JSH_GID="$(id -g)" JSH_OUTPUT="$root/$work/compose-out" JSH_PROFILES="$root/$work/compose-profiles" \
  docker compose -p jshgate run --rm -T -e JSHARVEST_ENGINE jsharvest crawl -u "http://$gw:8770/" >"$work/compose.log" 2>&1 || fail "compose run: $(tail -2 "$work/compose.log")"
grep -q "Chrome sandbox: on" "$work/compose.log" || fail "compose: Chrome's sandbox is not on"
./bin/testbed score -app testbed/apps/vite-vanilla -out "$work/compose-out/${gw}_8770/anon" -gate >"$work/score-compose.log" 2>&1 ||
  fail "compose crawl below the baseline: $(tail -2 "$work/score-compose.log")"
echo "compose: $(grep -m1 'recall:' "$work/score-compose.log" | xargs)"

echo "== 8. WebRTC behind a proxy, in the image"
WEBRTC_IMAGE="$img" TESTBED_NO_BUILD=1 TESTBED_WORK="$work" TESTBED_LOG="$work/webrtc-testbed.log" TESTBED_PID="$work/webrtc-testbed.pid" \
  testbed/webrtc-check.sh >"$work/webrtc.log" 2>&1 || fail "webrtc-check in the image: $(tail -3 "$work/webrtc.log")"

[ $failed = 0 ] && echo "docker-check: ok"
exit $failed
