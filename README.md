# jsharvest

**jsharvest** is a Go toolkit for web security assessment and client-side attack surface mapping: collecting JavaScript bundles/sourcemaps (both live and from public web archives), statically extracting API endpoints, bases, SPAs/routers, client-side authorization surfaces, and secret patterns without CGo, recording causal browser flows over CDP, comparing roles, and exporting or safely replaying verified requests.

> [!IMPORTANT]
> **Authorized testing only.** Subcommands such as `crawl`, `login`, `verify`, `authz`, `replay`, and `archive` interact with live targets or third-party archives. Only run **jsharvest** against applications you own or have explicit written authorization to test. Active write operations require explicit flags such as `-allow-write`.

---

## Key Capabilities

- **Adaptive Collection (`crawl`, `watch`):**
  - Automatic HTTP-first collection for unauthenticated targets (`-engine auto` defaults unauthenticated crawls to HTTP + bounded headless Chrome escalation when browser-passable challenges are detected).
  - Multi-tab Chrome DevTools Protocol (CDP) collection and interactive `-explore` mode capturing tab, iframe, Worker, Service Worker, and Shared Worker scripts (`js/`, `requests.jsonl`).
  - Causal action-to-request grouping (`flows.jsonl`) and request safety guard (`-guard on`) that holds state-changing / destructive / private-network requests in memory before they leave the browser.
- **Static JS / TS / SFC Analysis (`endpoints`, `intel.json`):**
  - Pure-Go extraction powered by `tdewolff/parse/v2` and `esbuild` (`internal/jsapi`) for JS bundles, TypeScript sources/sourcemaps, and Vue/Svelte SFCs.
  - Infers dynamic `baseURL` values, cross-chunk module imports/exports, hierarchical client routes, OpenAPI/OIDC/OAuth/SAML discovery hints, client authorization rules (`client_authz`), cloud storage links, and prefix-matched secret patterns (`internal/secretsig`).
- **Role Comparison & Authorization Testing (`login`, `diff`, `authz`, `replay`, `verify`):**
  - Saves reusable session snapshots (`0600`), detects and recovers from mid-crawl session loss or `Clear-Site-Data`.
  - Compares multi-role crawl surfaces (`diff`) and probes vertical/horizontal authorization (`authz`, including `-peers` for BOLA checks) and dependency-aware single flows (`replay`) with DNS-rebinding protection (`internal/netsafe`) and WAF/rate backoff.
  - Synthesizes catalog drafts and gateway-canary probes (`verify`, `export -drafts`) without fabricating live results when traffic is absent.
- **Exports, Historical Mining, Drift & MCP (`export`, `archive`, `monitor`, `mcp`):**
  - Exports HAR, raw HTTP requests (`ffuf`, `sqlmap`, Burp), parameter catalogs (`params.jsonl`), and OpenAPI 3.1 (`openapi.json`).
  - Mines public archives (Wayback Machine, OTX, Common Crawl, urlscan) for `historical_only` or version-changed endpoints (`archive`).
  - Tracks newly added, removed, or status-changed endpoints across runs (`monitor`).
  - Exposes read-only stdio Model Context Protocol tools (`mcp`: `status`, `last_action`, `list_flows`, `get_flow`, `get_request`, `blocked`, `endpoints`, `get_intel`, `get_diff`, `get_authz`, `search_scripts`, `read_script`) with secret redaction on by default.

---

## Requirements

| Mode | Minimum Requirements |
|---|---|
| **Build, Unit Tests & Offline / HTTP Commands** (`endpoints`, `diff`, `export`, `mcp`, `archive`, `monitor`, `verify`, HTTP `crawl`) | **Go 1.25.4+** (pure Go, `CGO_ENABLED=0` works cleanly) |
| **Browser Engine (`-engine cdp`, `watch`, `login`, `-explore`)** | Google Chrome or Chromium on `PATH` (or set `JSHARVEST_CHROME=/path/to/chrome`) |
| **Full Testbed Regression (`./testbed/regress.sh`)** | **Linux** (`unshare` namespaces, process-group isolation), plus `jq`, `flock`, `curl`, `python3`, `timeout`, `awk`, and Node/Docker to build the frontend testbed fixtures |
| **Container Image (`Dockerfile`, `docker-compose.yml`)** | Docker / Docker Compose (amd64 installs pinned Chrome for Testing; other architectures fall back to Debian Chromium) |

---

## Quick Start

### 1. Build from Source

```bash
git clone https://github.com/TimoMangCut/JSharvest.git
cd JSharvest
go build -o bin/jsharvest ./cmd/jsharvest
./bin/jsharvest help
```

Or run via Docker:

```bash
mkdir -p output profiles
chmod 700 output profiles
docker build -t jsharvest .
docker compose run --rm jsharvest help
```

### 2. Common Workflows

```bash
# Unauthenticated discovery + static extraction
./bin/jsharvest crawl -u https://example.com -o output

# Re-analyze collected scripts offline
./bin/jsharvest endpoints -target example.com -o output

# Export OpenAPI 3.1 and request drafts without live flows
./bin/jsharvest export -target example.com -format all -drafts -o output

# Authenticated multi-role crawl & diff
./bin/jsharvest login -u https://example.com/login -role user -profiles profiles
./bin/jsharvest crawl -u https://example.com -role user -explore -guard on -o output -profiles profiles
./bin/jsharvest diff -target example.com -roles anon,user -o output

# Safe read-only endpoint verification (use -dry-run first to inspect plan)
./bin/jsharvest verify -target example.com -o output -dry-run

# Mine archived JS for retired endpoints
./bin/jsharvest archive -target example.com -o output

# Start read-only stdio MCP server on collected output
./bin/jsharvest mcp -o output -target example.com -role anon
```

Run `./bin/jsharvest <subcommand> -h` for complete flag documentation on any subcommand.

---

## Output Layout

Collected data is written with restrictive permissions (`0700` directories, `0600` files) under `<out>/<target_dir>/<role>/` (non-default ports use `host_port`; archival results live under `<out>/<host>/archive/`):

- `run.json` — run configuration, stop reason, counts, and static analysis stats
- `requests.jsonl` — HTTP/browser request & response log
- `flows.jsonl` — action-grouped request flows (causal tagger + timing)
- `endpoints.jsonl` — unified static + observed API catalog (`static`, `observed`, `both`)
- `intel.json` — discovered API bases, headers, secret findings, routes, cloud assets, auth flows, and client authz matrix
- `js/` — deduplicated JavaScript/TypeScript/sourcemap corpus indexed by `index.jsonl`
- `drafts/`, `export/`, `authz/`, `verify/`, `monitor/` — generated subcommand artifacts

---

## Development & Testing

### Unit & Race Tests

```bash
go vet ./...
go test -race ./...
```

### End-to-End Testbed Gates (Linux)

The 7 JS bundler fixtures under `testbed/apps/` (`angular-ngsw`, `angular-ngsw-default`, `endpoints-app`, `next-mixed`, `vite-pwa`, `vite-vanilla`, `webpack-vanilla`) omit `dist/` from git and must be built once before running browser regression gates:

```bash
# Build JS testbed fixtures (uses Docker node:22-alpine, or host npm with USE_HOST_NODE=1)
./testbed/build.sh

# Run full regression suite across isolated network namespace lanes
./testbed/regress.sh

# Optional: include container verification gate
DOCKER=1 ./testbed/regress.sh
```

> [!NOTE]
> **Linux User/Network Namespace Note:** `regress.sh` parallel lanes and network-isolation gates (`lan-check.sh`, `webrtc-check.sh`, `proxy-check.sh`) require unprivileged `unshare -rn`. On Ubuntu systems restricting unprivileged user namespaces via AppArmor, temporarily allow them with `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`, or set `ALLOW_NETNS_SKIP=1` when intentionally running without unprivileged network namespaces.

---

## Documentation

Architecture specs and engineering design history are maintained under `docs/`:

- [docs/CURRENT.md](docs/CURRENT.md) — Current baseline, known limitations, and backlog
- [docs/rounds-history.md](docs/rounds-history.md) — High-level iteration index ([full changelog](docs/archive/rounds-history-full.md))
- Design docs: [capture-v2-spec.md](docs/capture-v2-spec.md), [gd4-plan.md](docs/gd4-plan.md), [gd4-recorder-design.md](docs/gd4-recorder-design.md), [gd4-flows-design.md](docs/gd4-flows-design.md), [gd4-guard-sw-design.md](docs/gd4-guard-sw-design.md), [gd4-mcp-design.md](docs/gd4-mcp-design.md), [gd4-static-endpoints-design.md](docs/gd4-static-endpoints-design.md), [gd4-frontier-design.md](docs/gd4-frontier-design.md), [gd4-session-design.md](docs/gd4-session-design.md), [gd4-explore-design.md](docs/gd4-explore-design.md), [gd4-roles-design.md](docs/gd4-roles-design.md), [gd4-export-design.md](docs/gd4-export-design.md), [gd5-replay-design.md](docs/gd5-replay-design.md), [gd5-archive-design.md](docs/gd5-archive-design.md), [gd5-monitor-design.md](docs/gd5-monitor-design.md), [gd5-parallel-design.md](docs/gd5-parallel-design.md), [gd5-container-design.md](docs/gd5-container-design.md), [gd6-waf-design.md](docs/gd6-waf-design.md), [gd7-bola-design.md](docs/gd7-bola-design.md)

---

## License

Released under the [MIT License](LICENSE).
