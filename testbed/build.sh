#!/usr/bin/env bash
# Builds the testbed apps inside a Node container (or with host npm when
# USE_HOST_NODE=1 or Docker is unavailable).
# Usage: [USE_HOST_NODE=1] testbed/build.sh [app...]   (default: every app with package.json under testbed/apps)
set -euo pipefail

NODE_IMAGE="${NODE_IMAGE:-node:22-alpine}"
here="$(cd "$(dirname "$0")" && pwd)"
cd "$here/apps"

apps=("$@")
if [ ${#apps[@]} -eq 0 ]; then
  apps=()
  for d in */; do
    d="${d%/}"
    [ -f "$d/package.json" ] && apps+=("$d")
  done
fi

use_host="${USE_HOST_NODE:-0}"
if [ "$use_host" != 1 ]; then
  if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    if command -v npm >/dev/null 2>&1; then
      echo "note: docker unavailable, falling back to host npm" >&2
      use_host=1
    else
      echo "missing docker daemon and host npm; install one of them to build testbed apps" >&2
      exit 1
    fi
  fi
fi

for app in "${apps[@]}"; do
  [ -f "$here/apps/$app/package.json" ] || continue
  echo "==> $app"
  if [ "$use_host" = 1 ]; then
    (cd "$here/apps/$app" && npm_config_update_notifier=false npm install --no-audit --no-fund --loglevel=error && npm run build)
  else
    docker run --rm \
      --user "$(id -u):$(id -g)" \
      -e HOME=/tmp -e npm_config_update_notifier=false \
      -v "$here/apps/$app:/app" -w /app \
      "$NODE_IMAGE" \
      sh -c 'npm install --no-audit --no-fund --loglevel=error && npm run build'
  fi
done
