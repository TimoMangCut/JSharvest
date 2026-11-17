# Trạng thái Hiện hành (`jsharvest` — Sau Đợt 34)

Tài liệu nhập ngữ cảnh nhanh cho session mới (~5 KB). Đọc cùng [CLAUDE.md](../CLAUDE.md) (bất biến & quy trình gate); chỉ mở [rounds-history.md](rounds-history.md), [plan-34.md](plan-34.md), [plan-33.md](plan-33.md) hoặc [plan-32.md](plan-32.md) khi cần chi tiết lịch sử/thiết kế cũ.

## 1. Quy mô & Trạng thái Mốc Đợt 34

- **Mã nguồn:** Go 1.25.4 (`CGO_ENABLED=0`, single binary, không thêm phụ thuộc ngoài); Đợt 34 bổ sung bộ điều khiển Độ lợi Thông tin Biên (`ΔInformation`), kiến trúc Streaming Archive DAG + Bộ nhớ đệm RAM có trần (`-mem-cache-mb`), lập lịch công bằng Weighted DRR đa tầng, nén Gzip chỉ mục CDX và hiệu chuẩn sâu `verify`/`detect`.
- **Trạng thái kiểm định:**
  - `go vet ./...` (trên cả `darwin/arm64` và `linux/amd64`) & `go test -race ./...`: **100% PASS** toàn bộ package.
  - `bin/testbed perfgate` (2.000 script, `43.1 MB`): `~2.7 s`, peak RSS `~281 MB` (trần cứng: `<= 15.0 s`, `<= 500.0 MB`).
  - Gate tích hợp `verify-check.sh`, `archive-check.sh`: **PASS 100%** (`precision 1.000`, `recall 1.000`, kể cả tạm dừng `SIGINT` & resume).
  - Kiểm tra hygiene đường dẫn & dữ liệu sạch (`.github/workflows/ci.yml`): **`0` vi phạm**.
- **Phiên bản extractor:** `jsapi.Version = 40`.

## 2. Năng lực Mới từ Đợt 34 ([plan-34.md](plan-34.md)), Đợt 33 ([plan-33.md](plan-33.md)) & Đợt 32 ([plan-32.md](plan-32.md))

1. **Điều khiển `ΔInformation`, Streaming Archive DAG & Tối ưu RAM/I/O (Đợt 34):**
   - **Tầng Crawl & Frontier:** Prefix Trie `skeletonController` (ngưỡng fan-out `K = 8` + tập khoá query) nhận diện khung trang động SSR/phân trang bão hoà (`template-saturated`, hoàn trả slot `Queue.Refund`) mà không chạm tới các tab tính năng tĩnh; `frontier.Queue` lập lịch công bằng **Weighted DRR** theo host (`weight 1..4`) kèm cơ chế tăng/giảm trọng số `Feedback`.
   - **Tầng Archive & Bộ nhớ đệm RAM (`-mem-cache-mb`, mặc định `512` MiB cho `crawl`/`archive`):** xoá bỏ hoàn toàn tệp tạm `html.jsonl` và đỉnh RAM nạp lại bằng `HTMLTop` giới hạn trên luồng (`stateVersion = 3`); mở rộng `store.CanonicalKey` cho các họ bundle CMS/bundler (`js_[h].js`, `autoptimize_[h].js`, `[h].js`, `eael-[h].min.js`); áp dụng **Coarse-Stride (`8` mốc) + Binary Zoom-In** theo `SemanticAPISig` kèm hàng đợi 2 tầng (`Origin -> CanonicalFamily`); chồng pha tải trước memento trong lúc kéo shard ZipNum; gửi `Accept-Encoding: gzip` cho mọi truy vấn chỉ mục (giữ `identity` cho memento/WARC); bộ đệm ghi `4 MB`, đếm URL độc nhất trên RAM, nhớ nâng cấp `http -> https` theo host và nâng mặc định `archive` lên `-concurrency 16`, `-live-rate 10`.
   - **Độ chính xác `verify` & `detect`:** nhận diện trang chặn F5 BIG-IP ASM (`Request Rejected` `200 text/html`) là `BlockRequest`; bổ sung sổ đăng ký `htmlShells` và **sub-canary tự động** cho các phân đoạn nhạy cảm sau prefix 2-segment (`/admin/`, `/internal/`, `/management/`, `/console/`, `/actuator/`...); chống nhân đôi tiền tố API có phiên bản (`/api/v1/.../api/v1/...`) trong `verify.join`.

2. **Mở toàn bộ trần quét & Cô lập lỗi theo từng host (Đợt 33 — `B1`–`B2`):**
   - Đặt mặc định `0` (không giới hạn) cho `crawl` (`-max-pages`, `-resolve-max`), `frontier`/`specprobe` (`MaxAPIOrigins`, `MaxSpecBases`, `MaxServiceDocPrefixes`, `MaxPhase2SpecProbes`), `archive` (`-max-files`, `MaxExtraHosts`, đầy đủ `HistLine.Scripts`) và `verify`/`authz` (`-max`, `-gate-after`, `maxCandidates`, `MaxPrefixes`).
   - **Đa luồng & Chống nghẽn đồng bộ toàn tuyến (`B5.1`):** phân mảnh Wayback CDX theo ZipNum (`showNumPages=true` + `page=0..N-1` + `collapse=digest`) chạy song song đa worker có checkpoint từng shard (`PagesDone`); đa luồng hoá `extra` subdomains (OTX/URLScan), hàng đợi tải động `archive.fetch` (`-concurrency 8` mặc định) kèm `singleflight` khử trùng `liveCheckAs`, song song hoá `SpecProbe` đa origin/gateway trong `httpcrawl`, và nâng mặc định `-concurrency 8` cho `verify`.
   - Giữ nguyên thăm dò API origin bên thứ ba theo `D2`, nhưng cô lập mọi phản hồi chặn/429/challenge (`specBlocked[host]`) ở pha Spec Probe để không bao giờ đánh dấu `Stopped` toàn cục hay làm mất `specProbePhase2` của các host trong scope.
   - Nhận diện sourcemap của thư viện vendor tự host độc lập (`FilesFor`: CKEditor, Bootstrap, Livewire, `/vendor/`, `/wp-includes/js/`...) trong khi bảo toàn bundle ứng dụng lai (`app.js.map`); nâng cấp `notScriptBody`/`htmlLike` chặn trang lỗi mềm XHTML (`<?xml`, cửa sổ 4 KB) lọt vào kho `.js`.
3. **Độ chính xác của `verify`, `archive`, `export` & `jsapi` v40 (Đợt 33 — `B3`–`B4`):**
   - Đồng bộ toàn bộ `Headers`/`SampleHeaders` giữa request probe và `canaryOptions` (khoá cache canary theo `(prefix, headerKey)`), chặn triệt để dương tính giả `verified_alive` trên các tường xác thực AJAX trả `401/403` cho `OPTIONS`.
   - Bảo toàn `Origin` trong `historical.jsonl` và tự khôi phục origin từ `Scripts[].URL` trên dữ liệu lịch sử cũ; cô lập `client_headers` theo script/origin trên quét đa subdomain; tự suy luận mã ngôn ngữ i18n cho slot đường dẫn; khử nhân bản chéo base tương đối trong `export -format openapi`.
   - Trong `internal/jsapi`: giải mã xuất/nhập giá trị nội bộ bundle Webpack 4/5 (`req.d`, `module.exports`, `exports.<k>`), lan truyền hằng đối tượng `JSON.parse('{...}')`, thu nhận secret gán trên `this.<prop>` / class field (lọc hằng tự gọi tên như `REFRESH_TOKEN = "refresh_token"`), và sửa lệch slot `pathNames` khi nối `${baseUrl}?query=${q}`.

4. **Hiệu năng Crawl HTTP, An toàn Mạng & Giao thức Hiện đại (Đợt 32):**
   - Xoá hoàn toàn double-AST parsing giữa `httpcrawl` và `endpoints.Analyze` qua `endpoints.ExtractCached` (`static/<sha>.json` `0600` nguyên tử) + nhớ đệm theo SHA256 trong suốt phiên crawl; lọc sớm script `Vendor`/`Tracker`/`Infra` ngay từ `Depth == 0`.
   - Trong `crawl -engine cdp`: tách các Spec Probe **cross-origin** sang `netsafe` HTTP client trực tiếp (tránh nghẽn CORS preflight khi gắn `client_headers`), giữ probe cùng origin trong tab để tận dụng cookie `HttpOnly`; tự kích cầu chì `D3` sau 2 lỗi mạng/CORS liên tiếp (`neterr`); dùng chung 1 `resolve.Policy` xuyên suốt phiên; lọc miền SaaS/captcha/embed dùng chung khỏi `nonAPIInfraDomains`.
   - Thay đệ quy `QueryUnescape` không trần trong `reflector.hit` bằng vòng lặp phẳng tối đa 2 lớp (`len <= 8192`); đồng bộ `resolve.Policy` sang `netsafe`; MCP `get_authz` lọc sớm `direction`/`role`; đồng bộ macOS native (`uahints`, `Setpgid`, `perfgate`).
   - Hỗ trợ tĩnh & động cho **Next.js App Router Server Actions**, **tRPC `v10`/`v11`**, **GraphQL Tagged Templates (`gql\`...\``)** và **ConnectRPC / gRPC-Web**.

## 3. Quyết định & Lưu ý Vận hành Hiện tại

- **`D1`–`D4` giữ nguyên hiệu lực**; cầu chì `D3` của Spec Probe 2 pha đã được vá nhánh `neterr` và chờ ghi nhận thực địa (`P2.1` / `P5.T`) trên target có phép.
- **Ubuntu 24.04+ AppArmor `userns`:** sau mỗi lần reboot máy Linux, chạy `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` trước khi chạy `testbed/regress.sh`.

## 4. Lộ trình Dài hạn (chưa thực hiện, chỉ mở khi có nhu cầu thực tế)

1. **Tách dần module nội bộ theo thay đổi tính năng:** thu gọn dần sự phụ thuộc `x.cursor` trong `internal/jsapi` và cấu trúc `Config` trong `internal/engine` theo từng tính năng chạm tới (không đại phẫu tách rời).
2. **Tùy chọn Stealth nâng cao:** `-stealth` với `uTLS` + HTTP/2 fingerprint chuẩn Chrome / Isolated World hooks nếu gặp WAF kiểm tra JA4/H2 frame ở pha HTTP pre-auth.
