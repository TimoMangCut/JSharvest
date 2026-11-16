#!/bin/sh
# Runs jsharvest, with a virtual display and noVNC when a person has to
# use the browser (a login by hand, or JSHARVEST_DISPLAY=1). Anything that
# is not a jsharvest command runs as it is (sh, id).
set -eu

# Every command of jsharvest's usage (docker-check.sh checks that the list
# keeps up with it): a name not here runs as a program.
case "${1:-help}" in
  crawl|watch|login|mcp|endpoints|diff|export|authz|replay|verify|archive|monitor|help|-h|--help) ;;
  *) exec "$@" ;;
esac

# A home Chrome can write in, whatever the uid (--user "$(id -u):$(id -g)").
if [ ! -w "${HOME:-/nonexistent}" ]; then
  export HOME=/tmp/jsharvest-home
fi
mkdir -p "$HOME"

# Chrome's sandbox when the container may make user namespaces (a
# seccomp profile that allows them, as docker-compose.yml sets); else
# --no-sandbox, and the container is all that stands between a hostile
# page and /profiles.
if [ -z "${JSHARVEST_NO_SANDBOX:-}" ]; then
  if unshare -U -r -p -n --fork true 2>/dev/null; then
    export JSHARVEST_NO_SANDBOX=0
  else
    export JSHARVEST_NO_SANDBOX=1
    echo "warning: no user namespaces here, so Chrome runs without its sandbox (--no-sandbox): a hostile page's exploit would reach /profiles and this container's network. Run with --security-opt seccomp=unconfined (as docker-compose.yml does) to have Chrome's sandbox; see docs/gd5-container-design.md." >&2
  fi
fi
[ "$JSHARVEST_NO_SANDBOX" = 0 ] && echo "Chrome sandbox: on" >&2

display=${JSHARVEST_DISPLAY:-0}
if [ "${1:-}" = login ]; then
  # A login with a script, or into a running Chrome, needs no screen.
  case " $* " in
    *" -steps "*|*" -steps="*|*" --steps "*|*" --steps="*|*" -attach "*|*" -attach="*|*" --attach "*|*" --attach="*) ;;
    *) display=1 ;;
  esac
fi

fail() {
  echo "$1" >&2
  [ -f "$2" ] && tail -5 "$2" >&2
  exit 1
}

if [ "$display" = 1 ]; then
  # Xvfb with a cookie, and no socket but its file: on the host's network
  # an abstract socket would let any process of the host type into it.
  export DISPLAY=:99 XAUTHORITY="$HOME/.Xauthority"
  touch "$XAUTHORITY"
  xauth -f "$XAUTHORITY" add :99 . "$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
  Xvfb :99 -screen 0 1366x900x24 -auth "$XAUTHORITY" -nolisten tcp -nolisten local >/tmp/xvfb.log 2>&1 &
  for _ in $(seq 30); do [ -e /tmp/.X11-unix/X99 ] && break; sleep 0.2; done
  [ -e /tmp/.X11-unix/X99 ] || fail "Xvfb did not start (is display :99 taken?)" /tmp/xvfb.log

  # VNC's password is 8 characters at most: that is all it checks.
  pass=${JSHARVEST_VNC_PASSWORD:-}
  if [ -z "$pass" ]; then
    pass=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 8)
    echo "noVNC password: $pass" >&2
  fi
  x11vnc -storepasswd "$pass" "$HOME/.vncpass" >/dev/null 2>&1
  unset pass JSHARVEST_VNC_PASSWORD

  # noVNC on the container's own interfaces, to publish on the host's
  # loopback (-p 127.0.0.1:6080:6080); on the host's network, on its
  # loopback only.
  listen=${JSHARVEST_NOVNC_LISTEN:-}
  if [ -z "$listen" ]; then
    listen=0.0.0.0
    [ -e /sys/class/net/docker0 ] && listen=127.0.0.1 # the host's network
  fi
  x11vnc -display :99 -auth "$XAUTHORITY" -localhost -rfbport 5900 -rfbauth "$HOME/.vncpass" -forever -shared -quiet >/tmp/x11vnc.log 2>&1 &
  vnc=$!
  websockify --web /usr/share/novnc "$listen:6080" localhost:5900 >/tmp/novnc.log 2>&1 &
  novnc=$!
  # Up when both live and listen (5900 is 0x170C, 6080 0x17C0): a port
  # another process holds does not count, as the process that lost it exits.
  listening() { cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk -v p=":$1$" '$4 == "0A" && $2 ~ p {f = 1} END {exit !f}'; }
  up=""
  for _ in $(seq 30); do
    sleep 0.2
    kill -0 "$vnc" 2>/dev/null || fail "x11vnc did not start (is port 5900 taken?)" /tmp/x11vnc.log
    kill -0 "$novnc" 2>/dev/null || fail "noVNC did not start (is port 6080 taken?)" /tmp/novnc.log
    if listening 170C && listening 17C0; then
      up=1
      break
    fi
  done
  [ -n "$up" ] || fail "x11vnc or noVNC does not listen" /tmp/x11vnc.log
  if [ "$listen" = 127.0.0.1 ]; then
    echo "noVNC: http://127.0.0.1:6080/vnc.html (on this host's loopback: from elsewhere, through an SSH tunnel)" >&2
  else
    echo "noVNC: http://127.0.0.1:6080/vnc.html (publish it on the host's loopback only: -p 127.0.0.1:6080:6080)" >&2
  fi
fi

exec jsharvest "$@"
