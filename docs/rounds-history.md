# Lịch sử các Giai đoạn và Đợt phát triển (`GĐ1` → `Đợt 31`)

Đây là chỉ mục tóm tắt gọn các mốc phát triển. Bản ghi nguyên văn đầy đủ GĐ1 → Đợt 30 lưu tại [rounds-history-full.md](archive/rounds-history-full.md). Khi có xung đột, [CLAUDE.md](../CLAUDE.md) và [CURRENT.md](CURRENT.md) có hiệu lực cao hơn.

## 1. Giai đoạn GĐ1 – GĐ5 & Mở rộng Song song

| Mốc | Nội dung cốt lõi | Tài liệu gốc / Gate |
|---|---|---|
| **GĐ1 – GĐ3** | Lõi CDP (`launch` + `attach`), dedupe SHA256, chunk resolver v1, đối chuẩn testbed 5 app (`53/56`) & external (`Crawlground`, `crawl-maze`). | `capture-v2-spec.md`, `gd2-design.md`, `bench.sh` |
| **GĐ4.0 – 4.3** | `-urls`, `internal/guard` (`Fetch` cấp browser + mọi target có sẵn, `otherTab`, `Clear-Site-Data`), `internal/traffic` (`-redact`), `watch` + `flows` (`console.createTask` + `internal/flow`), bỏ `-explore-llm` (giao điều khiển Chrome cho MCP ngoài). | `gd4-recorder-design.md`, `gd4-guard-sw-design.md`, `gd4-flows-design.md`, `flows-gate.sh`, `attach-guard.sh` |
| **GĐ4.3b / 4.3d** | `internal/jsapi` (`tdewolff/parse`), `internal/endpoints` (`static/<sha>.json`, `intel.json`), `jsharvest mcp` (7 tool stdio RO). | `gd4-static-endpoints-design.md`, `gd4-mcp-design.md`, `endpoints-check.sh` |
| **GĐ4.4 – 4.6** | `frontier` BFS theo source + `SpecPaths`, `login` (`-steps`, UI, `-attach`) + `session` keeper, `explore` (`DOMSnapshot` + `DOMDebugger`, `isTrusted`, `HoldNavigations`). | `gd4-frontier/session/explore-design.md`, `frontier-check.sh`, `session-check.sh`, `explore-check.sh` |
| **GĐ4.7 – 4.8** | `roles diff` (3/4 lớp, `client_gated` BFLA) và `export` (`.http`, HAR, `ffuf`, `sqlmap`, Markdown). | `gd4-roles/export-design.md`, `roles-check.sh`, `export-check.sh` |
| **GĐ5.1 – 5.4** | `replay`/`authz` (an toàn ghi, `Identity` không gửi cred cao xuống thấp, `Dual-Control`), Docker (`Dockerfile` + `noVNC` + `docker-compose.yml`), `archive` (Wayback, CC WARC, OTX, URLScan + live check), `monitor` (theo dõi nhiều run + webhook). | `gd5-replay/container/archive/monitor-design.md`, `replay-check.sh`, `docker-check.sh`, `archive-check.sh`, `monitor-check.sh` |
| **Song song `-tabs N`** | Đa tab an toàn theo context (`-urls -tabs N`, `frontier -tabs N`, `exploreShared`). | `gd5-parallel-design.md`, `parallel-check.sh`, `frontier-tabs-check.sh` |

## 2. Chuỗi Đợt 13 – 27F (WAF, Engine HTTP, OpSec & `jsapi` — tham chiếu `docs/gd6-waf-design.md`)

| Đợt | Mục `gd6` | `jsapi` | Trọng tâm |
|---|---|---|---|
| **Đợt 13–15** | `1–9` | v1–v7 | Phản biện đánh giá độc lập (`D1–D5`), `eval` đa nhánh 16 giá trị, `.replace`/`this.<prop>`, `intel.json`. |
| **Đợt 16–19** | `10–13` | v8–v9 | Archive (`ARC/MAX`), `engine` HTTP Pure-Go + `-escalate`, `endpoints.Build`, Next/Turbopack/Workbox/Sourcemap. |
| **Đợt 20–22B** | `14–19` | v10–v15 | Mở rộng `COV/TRU/FIN/QAL/PIP/REQ`, `flow.EntryTemplates`, `internal/detect` đa WAF, AIA TLS, `-spa-boot`, `pipeline-check.sh`. |
| **Đợt 23–24E** | `20–21` | v16–v18 | `internal/verify` (canaries, `Sig`, `drafts/`, `WriteDraftsFull`), `ENH-01..13`, `verify-check.sh`. |
| **Đợt 25A–25O** | `22–34` | v19–v23 | TS/SFC (`esbuild`), liên kết module đa tầng, `-on-block`, OpSec (`uahints`, `marker` `pf-8d1e7b.js`/`rt-4f9c2a.js`), `waf-check`, `crosscheck-check`, keeper redirect. |
| **Đợt 26A–26H** | `35–42` | v24–v30 | OOP `classes.go`, kiểm mù #1 Keycloak (thành dev), #2 `@appwrite/console` (`1.070/1.098`), #3 `@medusajs/dashboard` (`300/420`), #4 `@directus/app` (`89/136` → `93/136`). |
| **Đợt 27A–27F** | `43–48` | v31–v35 | Liên kết xuyên script `deferred.go` (`PrepareModule`), `urlreturn.go` (Appwrite `1.087/1.098`), kiểm mù #5 Jellyfin Web 12.4 (`3/364` → `302/364`, thành dev), `descriptor.go`. |

## 3. Các Đợt Gần Nhất (`Đợt 28–31`)

- **Đợt 28–30 (`2026-11-15 → 16`, [plan-28.md](plan-28.md), [gd7-bola-design.md](gd7-bola-design.md), `jsapi v36`):**
  - Hợp nhất bộ kết luận SFC + mã lỗi số trong body 200 + GraphQL theo từng operation.
  - Khoá mạng `internal/netsafe` (resolve-once, `PrivateAddr`, dial IP, một nguồn proxy `-proxy`, 3 lớp chặn private IP phía trình duyệt, WebRTC bằng preference profile) → `lan-check`, `proxy-check`, `webrtc-check`.
  - Phiên & guard 28C: ngoại lệ refresh POST, `-guard-allow` neo origin+path, đồng bộ token xoay vòng, `flock`, `-urls -role`.
  - **BOLA ngang `authz -peers`** (`bola-check`, lab Jellyfin/Directus `testbed/lab/`), `export -format openapi`, MCP `get_intel`/`get_diff`/`get_authz`/`search_scripts`/`read_script` kèm envelope `untrusted`. (Bỏ Bước 30 sau đo 28B(c); `P5.T` chờ target thật có 2 tài khoản).
- **Đợt 31 (`2026-11-16`, `3bb9b78..21c82f0`, [plan-31.md](plan-31.md), `jsapi v37` → `v38`):**
  - **(P0)** Dọn dung lượng repo (`4.1 GB -> 540 MB`), xoá `devtools/worker/`, harness 28B và dead code 0-caller, chuẩn hoá `CLAUDE.md` & `docs/`.
  - **(P1–P3)** Bundler Webpack 3/4/5 + `webpackAsyncContext` + liên kết `runtimeChunk`; router phân cấp (`routes` / `route_entries`); gói `internal/secretsig` + MCP redact; sửa `export -format all` khi thiếu flows; Spec Probe 2 pha + cầu chì `D3` (`-no-spec-probe`); Cloud Storage ACL qua `netsafe` (`-no-cloud-probe`) + bóc tách Pre-Auth SSO `auth_flows`; `client_authz` (CASL/guards/ROLES/RouteMeta) + định trị Terser `+=`/`=` & `.map()` 2 chặng (`endpoints` corpus 2.568 file: `lost: 0`, `Routes: 362 -> 425`, `perfgate`: `5.34–5.55 s` / `254.9–274.7 MB` RSS; `regress.sh`: `24/24 PASS`).
