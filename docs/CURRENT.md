# Trạng thái Hiện hành (`jsharvest` — Sau Đợt 31)

Tài liệu nhập ngữ cảnh nhanh cho session mới (~5 KB). Đọc cùng [CLAUDE.md](../CLAUDE.md) (bất biến & quy trình gate); chỉ mở [rounds-history.md](rounds-history.md) hoặc [plan-31.md](plan-31.md) khi cần chi tiết lịch sử/thiết kế cũ.

## 1. Quy mô & Trạng thái Mốc Đợt 31 (`21c82f0`)

- **Mã nguồn:** 70.608 dòng Go (không tính `*_test.go`) trên 32 package trong `internal/` + `cmd/jsharvest` (`go 1.25.4`, `CGO_ENABLED=0`); dung lượng repo `~540 MB` (đã dọn `4.1 GB -> 540 MB` ở Đợt 31).
- **Trạng thái kiểm định trên `21c82f0`:**
  - `testbed/regress.sh` (`DOCKER=1`): **24/24 PASS** (`unit` + `docker-check` + 22 gate tích hợp, gồm `lan-check`, `proxy-check`, `webrtc-check`).
  - `JSAPI_SNAPSHOT` trên corpus 2.568 script (`52.9 MB`): `Endpoints 956 -> 956 (lost: 0)`, `Routes 362 -> 425`, `RouteEntries 316`, `Keys 36 -> 36`, `ClientAuthz 25 scripts`.
  - `bin/testbed perfgate` (2.000 script): `5.34–5.55 s`, peak RSS `254.9–274.7 MB` (trần: `≤ 15.0 s`, `≤ 500.0 MB`).
  - Kiểm tra dữ liệu sạch trên diff Đợt 31: `0` vi phạm từ khoá mục tiêu thật.
- **Phiên bản extractor:** `jsapi.Version = 38` (bản Đợt 31 gốc là `37`; bản vá hậu Đợt 31 bổ sung lọc UI `PropBases`/SPA routes trong `SpecCollector` và đọc `meta.permission` object `{ action, object }` + enum cục bộ).

## 2. Kiến trúc & Năng lực Mới từ Đợt 31 (`3bb9b78..b029a67`)

1. **Bundler (`internal/resolve/webpack.go`, `httpcrawl`, `engine`):**
   - Giải mã **Webpack 3/4/5** (`.u`, hàm rời, biểu thức `.src = function(e){...}(e)`), trích `chunkId` (`ids[1:]`) từ `webpackAsyncContext` (loại trừ sync context và Browserify), và liên kết `WebpackRuntime` liên script (`runtimeChunk` + `app.js`/`vendors.js`) trên cùng trang.
2. **Router SPA phân cấp & Scope (`internal/jsapi/routes.go`, `endpoints/intel.go`, `frontier`):**
   - Duyệt đệ quy cây router có neo chuẩn (`VueRouter`, `createRouter`, `createBrowserRouter`, `RouterModule`...), giải biến/spread/`concat`, ghép đúng đường dẫn cha–con, xuất `routes` & `route_entries` trong `intel.json`/MCP và đẩy route tĩnh vào `frontier`.
   - Tách `isTrackerDomain` cho tracker/analytics phổ biến; tài nguyên bên thứ ba do ứng dụng trực tiếp nạp/gọi mặc định thuộc `in-scope` trong `intel.json`.
3. **Bí mật tiền tố dùng chung (`internal/secretsig`, `jsapi`, `mcpserver`, `redact`):**
   - Nhận diện 2 tầng (theo tên thuộc tính + chữ ký tiền tố chặt cho Google Maps `AIza`, AWS `AKIA/ASIA`, Stripe, GitHub, Slack, SendGrid, Mapbox, Sentry), đồng bộ che bí mật qua MCP/redact.
4. **Xuất OpenAPI khi không có luồng động (`cmd/jsharvest/export.go`):**
   - `export -format all` (kèm hoặc không `-drafts`) vẫn xuất `openapi.json` từ `endpoints.jsonl` khi `flows.jsonl` rỗng (`ErrNoFlows`).
5. **Thăm dò OpenAPI/Swagger 2 pha có ngữ cảnh (`internal/frontier/specprobe.go`, `httpcrawl`, `engine`):**
   - Mở rộng `SpecPaths` (`/v2/api-docs`, `/swagger-resources`), thêm Pha 2 hậu phân tích JS dùng `Bases` in-scope + top tiền tố dịch vụ con + `client_headers` cô lập theo đúng origin API, kèm **cầu chì tự hãm `D3`** khi gateway trả `401`/`403`/`400` đồng nhất (cờ tắt: `crawl -no-spec-probe`).
6. **Cloud Storage ACL & Pre-Auth SSO (`internal/endpoints/{cloud,authflow}.go`, `verify`, `mcpserver`):**
   - Phân tích cấu trúc URL Cloud (`Provider`, `Bucket`, `Region`, `ObjectPrefix`, `BucketRootURL`), mặc định dò ACL an toàn (`HEAD` object + `GET 8 KB` gốc bucket) qua `netsafe` + `-proxy` không gửi cookie ứng dụng (cờ tắt: `verify -no-cloud-probe`).
   - Bóc tách thụ động 100% luồng OAuth2/OIDC/SAML/CAS từ `Location` & body `2xx`/`3xx` → xuất `auth_flows` vào `intel.json`, `verify.json` và MCP `get_intel`.
7. **Bề mặt phân quyền client & AST Terser (`internal/jsapi/{authz,defs,eval,calls}.go`, `endpoints/client_authz.go`):**
   - Xuất `client_authz` (`roles`, `rules`, `public_routes`, `guarded_routes`) từ CASL (`$can`/`can`/`cannot`), guard (`hasPermission`/`checkRole`), từ điển `ROLES`/`PERMISSIONS`, `RouteMeta` vào `intel.json` & MCP `get_intel`.
   - Giải chuỗi gán nối tiếp `+=`/`=` kiểu Terser (chống nối lặp bằng `assignLHS`) và truyền phần tử mảng qua `.map`/`.forEach` 1–2 chặng.

## 3. Quyết định & Lưu ý Vận hành Hiện tại

- **`D1`–`D4` đã chốt:** (`D1`) `routes` + `client_authz` nằm trong `intel.json` & MCP `get_intel`; (`D2`) tài nguyên ứng dụng nạp/gọi trực tiếp mặc định là `in-scope`, cloud ACL probe chạy mặc định qua `netsafe` + `-proxy`; (`D3`) **tự hãm Spec Probe 2 pha đang ở chế độ thử nghiệm mặc định — cần theo dõi khi benchmark target mới**; (`D4`) nhánh `main` giữ commits chưa push theo quy ước.
- **Chưa chạy lại crawl sống trên target thực tế sau Đợt 31:** toàn bộ Đợt 31 đã qua unit/corpus/perfgate/`regress.sh`, chưa re-run live scan lên target benchmark để tránh leo thang kiểm thử sớm.
- **Ubuntu 24.04 AppArmor `userns`:** sau mỗi lần reboot host, cần `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` để `regress.sh` chạy song song đa lane và vượt 3 gate netns (`lan-check`, `proxy-check`, `webrtc-check`).

## 4. Nợ Kiến trúc & Lộ trình Dài hạn (chưa thực hiện ở Đợt 31)

Nếu mở đợt nâng cấp kiến trúc tiếp theo, các hạng mục ROI cao nhất gồm:

1. **Giảm phình `internal/jsapi` (~13.9k LOC) & `internal/engine` (~6.2k LOC):** loại dần sự phụ thuộc con trỏ `x.cursor` / `locate.go` bằng bảng span lexer cố định, mở lớp giải vỏ `__awaiter` / `__async` trong `helpers.go`, giữ SDK `@org/*`/`*sdk*` chọn lọc trong `sourcemap.go`; tách `engine` (`Config` 48 trường + >7 mutex) sang các driver độc lập (`uidriver`, `chunkresolver`).
2. **Lưu trữ & Công suất quy mô lớn (multi-10k pages / multi-process):** thay đọc tuần tự `O(N)` JSONL bằng chỉ mục nhúng thuần Go (`modernc.org/sqlite` WAL hoặc `bbolt` + `flock`) kết hợp nén `zstd`, dọn double-extraction giữa `httpcrawl` (`Depth > 0`) và `endpoints.Analyze`, thu hẹp `Fetch.enable` của `Guard` với asset thuần hiển thị, tối ưu `explore` (`Input.insertText` thay gõ từng phím).
3. **Giao thức & Stealth hiện đại:** hỗ trợ **GraphQL Tagged Template (`gql\`...\``)** theo từng operation trong `verify`, **Next.js Server Actions** (`Next-Action`), **tRPC**, **ConnectRPC/gRPC-Web**, và tuỳ chọn `-stealth` với `uTLS` + HTTP/2 fingerprint chuẩn Chrome / Isolated World hooks.
