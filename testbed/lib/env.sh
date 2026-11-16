# Shared environment helpers for testbed scripts.

ensure_go_in_path() {
  local d
  for d in /usr/local/go/bin "${HOME:-}/go/bin"; do
    [ -d "$d" ] || continue
    case ":$PATH:" in
      *":$d:"*) ;;
      *) export PATH="$PATH:$d" ;;
    esac
  done
  export GOTOOLCHAIN="${GOTOOLCHAIN:-auto}"
  if ! command -v go >/dev/null 2>&1; then
    echo "missing 'go' in PATH (install Go 1.25+ or ensure go is on PATH)" >&2
    return 1
  fi
}

find_chrome() {
  local c
  if [ -n "${JSHARVEST_CHROME:-}" ] && [ -x "${JSHARVEST_CHROME}" ]; then
    printf '%s\n' "$JSHARVEST_CHROME"
    return 0
  fi
  for c in google-chrome google-chrome-stable chromium chromium-browser chrome; do
    if command -v "$c" >/dev/null 2>&1; then
      command -v "$c"
      return 0
    fi
  done
  for c in /opt/chrome-linux64/chrome "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"; do
    if [ -x "$c" ]; then
      printf '%s\n' "$c"
      return 0
    fi
  done
  echo "missing Chrome/Chromium binary (set JSHARVEST_CHROME or install google-chrome / chromium)" >&2
  return 1
}

require_cmds() {
  local missing=() c
  for c in "$@"; do
    command -v "$c" >/dev/null 2>&1 || missing+=("$c")
  done
  if [ ${#missing[@]} -gt 0 ]; then
    echo "missing required command(s): ${missing[*]}" >&2
    return 1
  fi
}

require_built_apps() {
  local root="${1:-.}" app missing=()
  for app in "$root"/testbed/apps/*/; do
    [ -f "${app}package.json" ] || continue
    [ -d "${app}dist" ] || missing+=("$(basename "$app")")
  done
  if [ ${#missing[@]} -gt 0 ]; then
    echo "missing built testbed dist/ for: ${missing[*]}. Run ./testbed/build.sh first." >&2
    return 1
  fi
}

build_testbed_bins() {
  [ -n "${TESTBED_NO_BUILD:-}" ] && return 0
  go build -o bin/jsharvest ./cmd/jsharvest && go build -o bin/testbed ./testbed/cmd/testbed
}
