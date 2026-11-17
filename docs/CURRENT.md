# Trạng thái Hiện hành (`jsharvest` — Sau Đợt 33)

Tài liệu nhập ngữ cảnh nhanh cho session mới (~5 KB). Đọc cùng [CLAUDE.md](../CLAUDE.md) (bất biến & quy trình gate); chỉ mở [rounds-history.md](rounds-history.md), [plan-33.md](plan-33.md) hoặc [plan-32.md](plan-32.md) khi cần chi tiết lịch sử/thiết kế cũ.

## 1. Quy mô & Trạng thái Mốc Đợt 33

- **Mã nguồn:** Go 1.25.4 (`CGO_ENABLED=0`, single binary, không thêm phụ thuộc ngoài); Đợt 33 gỡ toàn bộ trần cứng mặc định (`0` = không giới hạn), cô lập lỗi Spec Probe theo từng host và nâng cấp độ chính xác ở `sourcemap`, `archive`, `verify`, `export` và `jsapi`.
- **Trạng thái kiểm định:**
  - `go vet ./...` (trên cả `darwin/arm64` và `linux/amd64`) & `go test -race ./...`: **100% PASS** toàn bộ package.
  - `bin/testbed perfgate` (2.000 script, `43.1 MB`): `~2.5 s`, peak RSS `~272 MB` (trần cứng: `<= 15.0 s`, `<= 500.0 MB`).
  - Kiểm tra hygiene đường dẫn & dữ liệu sạch (`.github/workflows/ci.yml`): **`0` vi phạm**.
  - **Cần chạy xác nhận trên máy Linux:** `DOCKER=1 testbed/regress.sh -j 3` (do các gate tích hợp browser/netns dùng `unshare -rn` của Linux).
- **Phiên bản extractor:** `jsapi.Version = 40` (tăng từ `39` sau khi bổ sung liên kết module nội bộ Webpack/Rspack/CJS `req.d` / `module.exports`, hằng đối tượng `JSON.parse('{...}')`, trích xuất `Keys` trên thuộc tính gán và căn chỉnh slot đường dẫn `pathNames`).

## 2. Năng lực Mới từ Đợt 33 ([plan-33.md](plan-33.md)) & Đợt 32 ([plan-32.md](plan-32.md))

1. **Mở toàn bộ trần quét & Cô lập lỗi theo từng host (Đợt 33 — `B1`–`B2`):**
   - Đặt mặc định `0` (không giới hạn) cho `crawl` (`-max-pages`, `-resolve-max`), `frontier`/`specprobe` (`MaxAPIOrigins`, `MaxSpecBases`, `MaxServiceDocPrefixes`, `MaxPhase2SpecProbes`), `archive` (`-max-files`, `MaxExtraHosts`, đầy đủ `HistLine.Scripts`) và `verify`/`authz` (`-max`, `-gate-after`, `maxCandidates`, `MaxPrefixes`).
   - Giữ nguyên thăm dò API origin bên thứ ba theo `D2`, nhưng cô lập mọi phản hồi chặn/429/challenge (`specBlocked[host]`) ở pha Spec Probe để không bao giờ đánh dấu `Stopped` toàn cục hay làm mất `specProbePhase2` của các host trong scope.
   - Nhận diện sourcemap của thư viện vendor tự host độc lập (`FilesFor`: CKEditor, Bootstrap, Livewire, `/vendor/`, `/wp-includes/js/`...) trong khi bảo toàn bundle ứng dụng lai (`app.js.map`); nâng cấp `notScriptBody`/`htmlLike` chặn trang lỗi mềm XHTML (`<?xml`, cửa sổ 4 KB) lọt vào kho `.js`.
2. **Độ chính xác của `verify`, `archive`, `export` & `jsapi` v40 (Đợt 33 — `B3`–`B4`):**
   - Đồng bộ toàn bộ `Headers`/`SampleHeaders` giữa request probe và `canaryOptions` (khoá cache canary theo `(prefix, headerKey)`), chặn triệt để dương tính giả `verified_alive` trên các tường xác thực AJAX trả `401/403` cho `OPTIONS`.
   - Bảo toàn `Origin` trong `historical.jsonl` và tự khôi phục origin từ `Scripts[].URL` trên dữ liệu lịch sử cũ; cô lập `client_headers` theo script/origin trên quét đa subdomain; tự suy luận mã ngôn ngữ i18n cho slot đường dẫn; khử nhân bản chéo base tương đối trong `export -format openapi`.
   - Trong `internal/jsapi`: giải mã xuất/nhập giá trị nội bộ bundle Webpack 4/5 (`req.d`, `module.exports`, `exports.<k>`), lan truyền hằng đối tượng `JSON.parse('{...}')`, thu nhận secret gán trên `this.<prop>` / class field (lọc hằng tự gọi tên như `REFRESH_TOKEN = "refresh_token"`), và sửa lệch slot `pathNames` khi nối `${baseUrl}?query=${q}`.

3. **Hiệu năng Crawl HTTP, An toàn Mạng & Giao thức Hiện đại (Đợt 32):**
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
