# Lịch sử các Giai đoạn và Đợt phát triển (`GĐ1` → `Đợt 41`)

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

## 3. Các Đợt Gần Nhất (`Đợt 28–41`)

- **Đợt 28–30 (`2026-11-15 → 16`, [plan-28.md](plan-28.md), [gd7-bola-design.md](gd7-bola-design.md), `jsapi v36`):**
  - Hợp nhất bộ kết luận SFC + mã lỗi số trong body 200 + GraphQL theo từng operation.
  - Khoá mạng `internal/netsafe` (resolve-once, `PrivateAddr`, dial IP, một nguồn proxy `-proxy`, 3 lớp chặn private IP phía trình duyệt, WebRTC bằng preference profile) → `lan-check`, `proxy-check`, `webrtc-check`.
  - Phiên & guard 28C: ngoại lệ refresh POST, `-guard-allow` neo origin+path, đồng bộ token xoay vòng, `flock`, `-urls -role`.
  - **BOLA ngang `authz -peers`** (`bola-check`, lab Jellyfin/Directus `testbed/lab/`), `export -format openapi`, MCP `get_intel`/`get_diff`/`get_authz`/`search_scripts`/`read_script` kèm envelope `untrusted`. (Bỏ Bước 30 sau đo 28B(c); `P5.T` chờ target thật có 2 tài khoản).
- **Đợt 31 (`2026-11-16`, `3bb9b78..21c82f0`, [plan-31.md](plan-31.md), `jsapi v37` → `v38`):**
  - **(P0)** Dọn dung lượng repo (`4.1 GB -> 540 MB`), xoá `devtools/worker/`, harness 28B và dead code 0-caller, chuẩn hoá `CLAUDE.md` & `docs/`.
  - **(P1–P3)** Bundler Webpack 3/4/5 + `webpackAsyncContext` + liên kết `runtimeChunk`; router phân cấp (`routes` / `route_entries`); gói `internal/secretsig` + MCP redact; sửa `export -format all` khi thiếu flows; Spec Probe 2 pha + cầu chì `D3` (`-no-spec-probe`); Cloud Storage ACL qua `netsafe` (`-no-cloud-probe`) + bóc tách Pre-Auth SSO `auth_flows`; `client_authz` (CASL/guards/ROLES/RouteMeta) + định trị Terser `+=`/`=` & `.map()` 2 chặng (`endpoints` corpus 2.568 file: `lost: 0`, `Routes: 362 -> 425`, `perfgate`: `5.34–5.55 s` / `254.9–274.7 MB` RSS; `regress.sh`: `24/24 PASS`).
- **Đợt 32 (`2026-11-17`, [plan-32.md](plan-32.md), `jsapi v38` → `v39`):**
  - **(P1 — Hiệu năng, Đồng bộ An toàn & Đa nền tảng):** Xoá double-AST parsing giữa `httpcrawl` và `endpoints.Analyze` qua `ExtractCached` + lọc sớm `Vendor`/`Tracker`/`Infra` ở `Depth == 0`; tách cross-origin Spec Probe trong `-engine cdp` qua `netsafe`, kích cầu chì `D3` trên `neterr`, gom `resolve.Policy` và mở rộng `nonAPIInfraDomains`; thay đệ quy `QueryUnescape` bằng vòng lặp phẳng tối đa 2 lớp trong `reflector.hit`; đồng bộ `resolve.Policy` với `netsafe`; lọc sớm `direction`/`role` cho MCP `get_authz` + khoá `user`/`user_created` trong `privateMarker`; đồng bộ macOS native (`uahints`, `Setpgid`, `perfgate` RSS).
  - **(P3–P4 — Giao thức Web Hiện đại):** Bổ sung hỗ trợ tĩnh & động cho **Next.js Server Actions** (`Next-Action` / `$ACTION_ID_<hex>` + giải mã RSC Flight), **tRPC `v10`/`v11`** (proxy chains + tách lô `?batch=1` + span JSON trong query URL-encoded), **GraphQL Tagged Templates** (`gql` / `graphql()` / `Document` -> tổng hợp thân JSON cho `verify`, tự bỏ qua `mutation`/`subscription` khi thiếu `-allow-write`), và **ConnectRPC / gRPC-Web** (service/method descriptors + bảo vệ đường dẫn `/<pkg.Service>/<Method>` + khoá không `Patch` khung nhị phân 5-byte proto).
- **Đợt 33 (`2026-11-17`, [plan-33.md](plan-33.md), `jsapi v39` → `v40`):**
  - **(B1–B2 — Mở toàn bộ giới hạn cứng & Cô lập lỗi theo host):** Đặt mặc định `0` (không giới hạn) cho `crawl`, `frontier`/`specprobe`, `archive` và `verify`/`authz`; cô lập lỗi WAF/challenge theo từng host (`specBlocked`) trong Spec Probe để bảo vệ `specProbePhase2`; lọc sourcemap thư viện vendor tự host độc lập (`FilesFor`) và chặn trang lỗi mềm XHTML (`<?xml`, cửa sổ 4 KB) lọt vào kho `.js`.
  - **(B3–B4 — Verify Canary Parity, Archive Origin & `jsapi` v40):** Đồng bộ header giữa probe và `canaryOptions` để triệt tiêu dương tính giả `verified_alive` trên tường xác thực AJAX `401/403`; bảo toàn & khôi phục `Origin` trong `historical.jsonl`, cô lập `client_headers` theo script/origin, suy luận mã ngôn ngữ i18n cho slot đường dẫn, khử nhân bản đường dẫn OpenAPI export; bổ sung giải mã module nội bộ Webpack 4/5 (`req.d`, `module.exports`), `JSON.parse('{...}')`, trích xuất `Keys` trên gán thuộc tính/class field và sửa lệch slot `pathNames` trước `?`/`#`.
- **Đợt 37 (`2026-11-19`, `d917bd2`) & 37.1 (`2026-11-19`, [plan-37.1.md](plan-37.1.md)):**
  - **(37 — Tốc độ):**
    - archive chạy hai stage (Stage 1 chồng lên crawl), AIMD và stride cho CDX, WARC fallback;
    - crawl trả worker sớm, có breaker dial, dedup sourcemap;
    - `verify -host-inflight`.
  - **(37.1 — Sửa gốc sau review):**
    - crawl: thêm trạng thái "đã ổn định" cho origin (không còn khoá 1 request vĩnh viễn; 3xx không là shell, `Location` được thu); breaker theo origin; request bị giữ không vào `requests.jsonl`;
    - archive: `archiveEnv`/`archive.Mode` dùng chung giữa hai stage (bỏ `ExitOnError` trong crawl và cờ nội bộ); chỉ truyền chặn mức IP từ CDX sang Memento;
    - verify: re-judge shell, root canary ở mọi N, `gateSer` tự nhả;
    - sourcemap: cache tham chiếu SHA, công bố sau khi lưu;
    - `internal/testlint` cùng 11 race trong test.
- **Đợt 38 (`2026-11-19`, [plan-38.md](plan-38.md)):**
  - Đóng `T1` (xoá `VerifiedBase` khi `rejudgeShells` hạ verdict) và `T3` (`testlint` bỏ `RLock`, bắt ghi map/slice/field/pointer và `delete()` kèm `testdata`);
  - Bổ sung log timing `archive`/`history` + harness đo offline `JSH_HISTORY_BENCH`;
  - Streaming subdomain mới từ `httpcrawl` vào Stage 1 (`ExtraHostCh` fan-out độc lập cho OTX/URLScan) + debounce `saveMaybeLocked`;
  - Guarded Sub-Path SPA Brake trong `specProbeWithScope` kèm `spaBraked` cho `plan.Services` (giữ nguyên origin root & OIDC sub-path);
  - Singleflight theo SHA-256 + `extractHeavySem` trong `endpoints.ExtractCached`.
- **Đợt 39 (`2026-11-19`, [plan-39.md](plan-39.md)):**
  - Khử trùng dòng RSC Flight (`htmlscan.RSCDeduper`, `-98.8%` dung lượng đĩa/AST lặp trên Next.js App Router) + trích chunk RSC/Turbopack escape + chặn FP Soft-`200` HTML trùng shell Canary `404` + bổ sung vendor `adminlte` & lọc CDN `onetrust.com`;
  - Bổ sung build manifest Pre-Auth cho SSR/Full-stack (`/mix-manifest.json`, `/build/.vite/manifest.json` + fallback `/build/manifest.json`, `/build/entrypoints.json`) cho cả live & archive;
  - Quét `pages.jsonl` bắt `AuthFlows` trên trang Login HTML, thăng cấp route sạch từ `redirect_uri` in-scope vào `intel.Routes`/`CrawlHosts`, nhận diện framework qua tên cookie/header (`Laravel`, `ASP.NET`, `Drupal`...);
  - Phân tầng `/swagger/v1/swagger.json` (`SpecPaths`) vs `OriginSpecPaths` (chỉ ở Origin Root), giải mã `SwaggerUIURLs` từ HTML wrapper, và khai thác `<link rel="manifest">`, `apple-app-site-association`, `assetlinks.json`.
- **Đợt 40 (`2026-11-20`, [plan-40.md](plan-40.md), `jsapi v45` → `v46`):**
  - `jsapi` v46 (`R40-A1`, `R40-A2`): giải `ObjectPattern` destructuring trực tiếp từ `*js.ObjectExpr` (Vite `import.meta.env`) với `destructDefault` fallback riêng; thêm `"domain"` vào `isBaseName`; hỗ trợ hậu tố vùng/env viết HOA cho khoá hằng (`keyNameMatch` + `strongKeyValue`); nối `{ baseURL }` cấp request cho `clientMethods` kèm `x.reqBase` không trộn `client:` của instance;
  - `specProbe` (`R40-B1`): khoá `SpecCollector.Plan` (`plan.Bases`/`plan.Services`) và `OriginSpecPaths` (HTTP + CDP) theo `inScope`, mở rộng `nonAPIInfraDomains` làm lớp phụ chặn IdP/SDK/map/schema XML (giữ probe gốc D2);
  - `verify` (`R40-A3`): nạp `http.spa_origins` từ `run.json`, mở rộng ứng viên `[l.Origin, extBases...]` cho API tương đối trên origin SPA (reverse-proxy chốt `l.Origin`, decoupled SPA tự cắt tỉa `l.Origin` sau 16 path chết);
  - `engine` & `httpcrawl` (`R40-B3`, `R40-B2`): bổ sung bộ đếm request vào `EscalatedRun` + khối `totals` trong `run.json` (giữ nguyên số liệu riêng của run HTTP, `unique_scripts = st.Len() + Σ er.NewScripts`); đánh dấu soft-200 SPA fallback trong `http.soft_probes` (giữ `http.probes`).
- **Đợt 41 (`2026-11-21`, [plan-41.md](plan-41.md), [threat-model-2026-11-20.md](threat-model-2026-11-20.md)):**
  - **(41A — An toàn cốt lõi & DoS AST):** tuyến tính hoá tra dòng + trần `maxLooseMatches`/`maxLooseEndpoints` (`H1`); cầu chì độ sâu ngoặc `maxEsbuildNesting = 400` trên mọi nhánh `esbuild` (`M7`) + ngân sách fallback tất định mỗi script (`M13`, snapshot `jsapi` trùng 100% HEAD); tự động gỡ hoặc giữ `Unclear` credential query/body của role cao không làm mới được + vá `Patch` lỗi & `Judge` `c.Kept` (`M1`); `verify` trước `snap.Save` + `SensitiveWindow` cho `relogin` (`M6`); ghi nguyên tử & khoá `monitor` tôn trọng `-dry-run` (`M10`); `traffic.LogURL` che token/userinfo/fragment trên log (`M5`); UA Chrome cho AIA (`L1`) và `nxResolver` cho test `httpcrawl` (`L9`).
  - **(41B — Đĩa, Redact, Scope & LAN Guard):** trần 2 tầng cho sourcemap + `-max-source-files 50000` đồng bộ singleflight `NoteStored` + flush hình học `store` (`H3`); ngân sách đĩa `-max-store-mb 2048` cho `crawl`/`watch`/`archive` + trần manifest tất định `10.000` O(N log N) (`M11`); bật mặc định `-redact=true` cho `authz` & `verify` phủ `sent.jsonl`, `trials/*.http`, `drafts/*.http`, `Result.URL` (`H2`); cờ `-probe-offscope=auto|on|off` tự tắt sau `-proxy` và khoá cả follow-up Swagger UI (`M2`/`M4`); bật mặc định Lớp 1 `-lan-guard=on` (`URLPattern: "*"`) khi `-guard off` (`M3`).
  - **(41C — MCP, Tín hiệu, Báo cáo & Hoàn thiện bề mặt):** nonce `fence` 16-hex mỗi phiên MCP + cờ `suspicious_instructions` (`M8`); giữ CDP qua `context.WithoutCancel(ctx)`, cảnh báo ở tín hiệu thứ 2, dọn thư mục tạm ở tín hiệu thứ 3 + quét profile mồ côi `> 24h` (`M9`); xét `BodyActionFields` + GraphQL mutation phá huỷ vô điều kiện trong `guard` và xếp logout body/GraphQL là `Never` trong `replay` (`M12`); marker dẫn xuất theo seed build + `-archive-ua` (`L2`); `mdsafe` escape cho 5 báo cáo `.md` + lọc C0/C1 ở stderr (`L3`); kiểm `Content-Length`/cụt bản ghi WARC (`L4`); `traffic.AppendOpen` cô lập dòng JSONL cụt + `Scanner` đọc `runs.jsonl` + `fsync` lúc đóng run (`L5`); `crawl` khoá profile trước `loadLogin` (`L6`); lưu mật khẩu VNC Docker vào `$HOME/vnc-password` `0600` (`L7`); `.gitignore` + quét secret `gitleaks` ghim SHA-256 trong CI (`L8`); nối `ProbeCloud` qua `Sender.DoExternal` (`L10`); chặn `fec0::/10` trong `netsafe` (`L11`).
