#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/compose.yml"

die() {
  echo "ERROR: $*" >&2
  exit 1
}

# Resolve the actual Docker network name created by compose for the "lab" network.
DIRECTUS_CID="$(docker compose -f "$COMPOSE_FILE" ps -q directus)"
[ -n "$DIRECTUS_CID" ] || die "directus container is not running; bring the lab up first"

NETWORK_NAME="$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}' "$DIRECTUS_CID")"
[ -n "$NETWORK_NAME" ] || die "could not determine Docker network for directus"

echo "=== docker network inspect ${NETWORK_NAME} ==="
docker network inspect "$NETWORK_NAME"

INTERNAL_FLAG="$(docker network inspect -f '{{.Internal}}' "$NETWORK_NAME")"
if [ "$INTERNAL_FLAG" != "true" ]; then
  die "Expected network ${NETWORK_NAME} .Internal == true, got '${INTERNAL_FLAG}'"
fi
echo "PASS: network ${NETWORK_NAME} has .Internal == true"

echo "=== Probing outbound isolation from directus ==="
if ! docker compose -f "$COMPOSE_FILE" exec -T directus node -e "
const https = require('https');
const req = https.get('https://example.com', () => process.exit(1));
req.setTimeout(5000, () => { req.destroy(new Error('timeout')); });
req.on('error', () => process.exit(0));
"; then
  die "FAIL: directus reached https://example.com (outbound network is not isolated)"
fi
echo "PASS: directus cannot reach https://example.com"

echo "=== Probing outbound isolation from jellyfin ==="
if docker compose -f "$COMPOSE_FILE" exec -T jellyfin sh -c 'command -v curl >/dev/null 2>&1'; then
  if docker compose -f "$COMPOSE_FILE" exec -T jellyfin curl -fsS --max-time 5 https://example.com >/dev/null 2>&1; then
    die "FAIL: jellyfin reached https://example.com (outbound network is not isolated)"
  fi
  echo "PASS: jellyfin cannot reach https://example.com"
else
  echo "NOTE: curl not present in jellyfin image; skipping jellyfin outbound probe (network .Internal == true already verified)."
fi

echo "All isolation checks passed."
