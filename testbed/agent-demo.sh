#!/usr/bin/env bash
# The 4.3d demo with a real agent: Claude (claude -p) drives flows-app
# through chrome-devtools-mcp, while jsharvest watch records the same
# Chrome, and asks jsharvest mcp after each step what the step sent.
# Not a gate (a model's run is not deterministic, and it costs): run it by
# hand. Needs Docker (chrome-devtools-mcp runs in node:22-alpine), the
# network once to fetch it, and a logged-in claude CLI.
# Usage: testbed/agent-demo.sh [model]   (default sonnet)
set -uo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
. "$root/testbed/lib/env.sh"
ensure_go_in_path || exit 1
CHROME_BIN="$(find_chrome)" || exit 1
go build -o bin/jsharvest ./cmd/jsharvest || exit 1
model="${1:-sonnet}"
work="$root/bin/agent-demo"
rm -rf "$work"
mkdir -p "$work/profile" "$work/npm"
port=9333

./testbed/run.sh start flows-app >/dev/null
"$CHROME_BIN" --headless=new --remote-debugging-port=$port --user-data-dir="$work/profile" --no-first-run about:blank >"$work/chrome.log" 2>&1 &
chrome=$!
watch=""
cleanup() {
  [ -n "$watch" ] && kill -INT "$watch" 2>/dev/null && wait "$watch"
  kill "$chrome" 2>/dev/null
  ./testbed/run.sh stop
}
trap cleanup EXIT
sleep 2
./bin/jsharvest watch -attach "http://127.0.0.1:$port" -open http://127.0.0.1:8770/ -guard on -o "$work/out" >"$work/watch.log" 2>&1 &
watch=$!
for _ in $(seq 50); do
  grep -q "watching" "$work/watch.log" && break
  sleep 0.2
done
sleep 2

cat >"$work/mcp.json" <<EOF
{"mcpServers": {
  "chrome": {"command": "docker", "args": ["run", "--rm", "-i", "--network", "host", "-u", "$(id -u):$(id -g)", "-e", "HOME=/tmp",
    "-v", "$work/npm:/tmp/.npm", "node:22-alpine", "npx", "-y", "chrome-devtools-mcp@1.12.0", "--browser-url=http://127.0.0.1:$port"]},
  "jsharvest": {"command": "$root/bin/jsharvest", "args": ["mcp", "-o", "$work/out"]}
}}
EOF

prompt='A web app is open at http://127.0.0.1:8770/ in the browser that the chrome tools control (select that page first). jsharvest records what the page sends. Do these steps in order, with the chrome tools, and after EACH step call the jsharvest last_action tool once:
1. type "shoes" into the search box (#q) and click the Search button;
2. click the Open button of item 42;
3. click "Save profile";
4. click "Slow report";
5. click "New note".
Then call jsharvest blocked once.
Answer with only a JSON object, no prose: {"steps": [{"step": n, "actions": ["<action id> <label>"], "requests": ["<METHOD> <path and query>"], "late": ["<action id>: <METHOD> <path>"]}], "blocked": ["<METHOD> <path> <action id>"]}. Take every value from the last_action and blocked answers; do not guess.'

timeout 900 claude -p "$prompt" --model "$model" --mcp-config "$work/mcp.json" --strict-mcp-config \
  --allowedTools "mcp__chrome__*" "mcp__jsharvest__*" --max-budget-usd 3 --output-format json \
  >"$work/claude.json" 2>"$work/claude.err"
echo "claude exit $?"
jq -r '.result' "$work/claude.json"
jq -c '{cost: .total_cost_usd, turns: .num_turns, ms: .duration_ms}' "$work/claude.json"
