#!/usr/bin/env bash
# The 4.8 export read by the real tools (docs/gd4-export-design.md, 9.13):
# ffuf and sqlmap, pinned, built and run in containers, against the
# testbed on 127.0.0.1 only. Run testbed/export-check.sh first: this uses
# its export of the run with the guard off.
#   ffuf: the path of /api/items/FUZZ, and the JSON body of the profile's
#         save with values of other lengths: every answer 200, which needs
#         the session cookie, the CSRF token, valid JSON and the length
#         ffuf writes; the server's log has each.
#   sqlmap: a GET with a query and the JSON save (CSRF, cookie): parsed,
#         connected, the parameter tested, never a 403.
# Usage: testbed/export-tools.sh   (exit 1 on failure; needs Docker)
set -uo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
FFUF_VERSION=v2.3.0
SQLMAP_VERSION=1.10.11
exp=bin/export-check/off/127.0.0.1/anon/export
[ -f "$exp/manifest.json" ] || { echo "no export: run testbed/export-check.sh first"; exit 1; }
work=bin/export-tools
rm -rf "$work"
mkdir -p "$work" bin/tools
failed=0
fail() { echo "FAIL $*"; failed=1; }
me="$(id -u):$(id -g)"

if [ ! -x "bin/tools/ffuf-$FFUF_VERSION" ]; then
  docker run --rm -u "$me" -e HOME=/tmp -e GOPATH=/tmp/go -e GOCACHE=/tmp/cache -e CGO_ENABLED=0 -e GOBIN=/out \
    -v "$root/bin/tools:/out" golang:1.24-alpine go install "github.com/ffuf/ffuf/v2@$FFUF_VERSION" >"$work/build.log" 2>&1 &&
    mv bin/tools/ffuf "bin/tools/ffuf-$FFUF_VERSION" || { fail "build ffuf: $(tail -2 "$work/build.log")"; exit 1; }
fi
if [ ! -d "bin/tools/sqlmap-$SQLMAP_VERSION" ]; then
  docker run --rm -u "$me" -e HOME=/tmp -v "$root/bin/tools:/out" python:3.12-alpine \
    pip install --no-cache-dir --target "/out/sqlmap-$SQLMAP_VERSION" "sqlmap==$SQLMAP_VERSION" >"$work/pip.log" 2>&1 ||
    { fail "install sqlmap: $(tail -2 "$work/pip.log")"; exit 1; }
fi

./testbed/run.sh start flows-app >/dev/null
trap './testbed/run.sh stop >/dev/null' EXIT
in_box() { # image cmd...: the export and work dirs mounted, the host's network
  local image=$1
  shift
  docker run --rm --network host -u "$me" -e HOME=/tmp -v "$root/$exp:/export:ro" -v "$root/$work:/work" \
    -v "$root/bin/tools:/tools:ro" "$image" "$@"
}

echo "== ffuf"
n=$(wc -l <bin/testbed.log)
printf '42\n108\n7\n' >"$work/ids.txt"
in_box alpine "/tools/ffuf-$FFUF_VERSION" -request /export/ffuf/GET-api-items-id/path-3.http -request-proto http \
  -w /work/ids.txt -mc all -o /work/ffuf-path.json -of json -s >"$work/ffuf-path.log" 2>&1 || fail "ffuf path: $(tail -2 "$work/ffuf-path.log")"
printf 'Al\nAlice Liddell\na much longer display name, to change the body length well past the original\n' >"$work/names.txt"
in_box alpine "/tools/ffuf-$FFUF_VERSION" -request /export/ffuf/POST-api-profile/json-display-name.http -request-proto http \
  -w /work/names.txt -mc all -o /work/ffuf-body.json -of json -s >"$work/ffuf-body.log" 2>&1 || fail "ffuf body: $(tail -2 "$work/ffuf-body.log")"
python3 - "$work" <<'EOF' || failed=1
import json, sys
work = sys.argv[1]
ok = True
for name, want in (("ffuf-path", {"42", "108", "7"}), ("ffuf-body", None)):
    res = json.load(open(f"{work}/{name}.json"))["results"]
    got = {r["input"]["FUZZ"]: r["status"] for r in res}
    print(f"{name}: {got}")
    if len(got) != 3 or any(s != 200 for s in got.values()):
        print(f"FAIL {name}: every answer must be 200"); ok = False
    if want and set(got) != want:
        print(f"FAIL {name}: inputs {set(got)}"); ok = False
sys.exit(0 if ok else 1)
EOF
log=$(tail -n +$((n + 1)) bin/testbed.log)
for id in 42 108 7; do grep -q "200 GET /api/items/$id\b" <<<"$log" || fail "server log: no GET /api/items/$id"; done
[ "$(grep -c '200 POST /api/profile' <<<"$log")" = 3 ] || fail "server log: $(grep -c 'POST /api/profile' <<<"$log") profile saves, want 3 with 200"

echo "== sqlmap"
sq() { # name file param
  in_box python:3.12-alpine env PYTHONPATH="/tools/sqlmap-$SQLMAP_VERSION" python "/tools/sqlmap-$SQLMAP_VERSION/sqlmap/sqlmap.py" \
    -r "/export/$2" -p "$3" --batch --flush-session --technique=B --level 1 --risk 1 --output-dir /work/sqlmap >"$work/sqlmap-$1.log" 2>&1
  if ! grep -q "testing connection to the target URL" "$work/sqlmap-$1.log" || grep -qiE "403 \(Forbidden\)|no parameter\(s\) found|connection refused|unable to connect" "$work/sqlmap-$1.log" ||
    ! grep -qE "parameter '?\(?[A-Za-z_ #]*\)?$3'? (does not seem|appears|is)" "$work/sqlmap-$1.log"; then
    fail "sqlmap $1: $(grep -E 'CRITICAL|ERROR|WARNING' "$work/sqlmap-$1.log" | head -3)"
  else
    echo "sqlmap $1: $(grep -E "parameter .*$3" "$work/sqlmap-$1.log" | tail -1)"
  fi
}
sq search endpoints/GET-api-search.http q
sq profile endpoints/POST-api-profile.http display_name

[ $failed = 0 ] && echo "export-tools: ok (ffuf $FFUF_VERSION, sqlmap $SQLMAP_VERSION)"
exit $failed
