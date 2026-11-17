# Trạng thái Hiện hành (`jsharvest` — Sau Đợt 32)

Tài liệu nhập ngữ cảnh nhanh cho session mới (~5 KB). Đọc cùng [CLAUDE.md](../CLAUDE.md) (bất biến & quy trình gate); chỉ mở [rounds-history.md](rounds-history.md), [plan-32.md](plan-32.md) hoặc [plan-31.md](plan-31.md) khi cần chi tiết lịch sử/thiết kế cũ.

## 1. Quy mô & Trạng thái Mốc Đợt 32

- **Mã nguồn:** Go 1.25.4 (`CGO_ENABLED=0`, single binary, không thêm phụ thuộc ngoài); toàn bộ mở rộng giao thức Đợt 32 được cô lập trong `internal/flow/rpc.go`, `internal/jsapi/modern_rpc.go`, `internal/jsapi/gql.go` và `internal/engine/specprobe.go`.
- **Trạng thái kiểm định:**
  - `go vet ./...` (trên cả `darwin/arm64`, `linux/amd64`, `windows/amd64`) & `go test -race ./...`: **100% PASS** toàn bộ package.
  - `bin/testbed perfgate` (2.000 script, `43.1 MB`): `~2.4–2.6 s`, peak RSS `~272 MB` (trần cứng: `<= 15.0 s`, `<= 500.0 MB`).
  - Kiểm tra hygiene đường dẫn & dữ liệu sạch (`.github/workflows/ci.yml`): **`0` vi phạm**.
  - **Cần chạy xác nhận trên máy Linux:** `DOCKER=1 testbed/regress.sh -j 3` (do các gate tích hợp browser/netns dùng `unshare -rn` của Linux).
- **Phiên bản extractor:** `jsapi.Version = 39` (tăng từ `38` sau khi bổ sung Next.js Server Actions, tRPC, GraphQL `GraphQLDoc` và ConnectRPC/gRPC-Web).

## 2. Năng lực Mới từ Đợt 32 ([plan-32.md](plan-32.md))

1. **Hiệu năng Crawl HTTP & Spec Probe (`P1.1`–`P1.3`):**
   - Xoá hoàn toàn double-AST parsing giữa `httpcrawl` và `endpoints.Analyze` qua `endpoints.ExtractCached` (`static/<sha>.json` `0600` nguyên tử) + nhớ đệm theo SHA256 trong suốt phiên crawl; lọc sớm script `Vendor`/`Tracker`/`Infra` ngay từ `Depth == 0`.
   - Trong `crawl -engine cdp`: tách các Spec Probe **cross-origin** sang `netsafe` HTTP client trực tiếp (tránh nghẽn CORS preflight khi gắn `client_headers`), giữ probe cùng origin trong tab để tận dụng cookie `HttpOnly`; tự kích cầu chì `D3` sau 2 lỗi mạng/CORS liên tiếp (`neterr`); dùng chung 1 `resolve.Policy` xuyên suốt phiên; lọc miền SaaS/captcha/embed dùng chung khỏi `nonAPIInfraDomains`.
2. **An toàn Mạng, BOLA & Đa nền tảng (`P1.4`–`P1.7`):**
   - Thay đệ quy `QueryUnescape` không trần trong `reflector.hit` bằng vòng lặp phẳng tối đa 2 lớp (`len <= 8192`), hạ thời gian xử lý chuỗi `%2525...` 100 KB từ `8.66 s` xuống `< 1 ms`.
   - Đồng bộ `resolve.Policy` sang `netsafe.RefuseHost`, `LiteralHost`, `PrivateAddr` (chặn `0x7f.1`, NAT64 `64:ff9b::/96`, `6to4`, `198.18/15`, `*.localhost` trong khi giữ nguyên `noDNS` cho `-proxy` / `-host-resolver-rules`).
   - MCP `get_authz` hỗ trợ lọc sớm `direction` và `role` trước khi đếm `Total` và chạy `maskAuthz`; bổ sung khoá chủ sở hữu `user` (khớp lá chính xác) và `user_created` cho `privateMarker`.
   - Đồng bộ macOS native: dò đường dẫn `/Applications/Google Chrome.app/...` trong `uahints`, tách `Setpgid: true` cho mọi HĐH Unix (`proc_unix.go`) để `Ctrl+C` dọn sạch profile tạm trước khi tắt Chrome, chuẩn hoá đơn vị byte `Maxrss` trên Darwin cho `perfgate`.
3. **Giao thức Web Hiện đại (`P3.1`–`P3.4`):**
   - **Next.js App Router Server Actions:** trích xuất tĩnh `createServerReference` / `registerServerReference` / `createActionProxy` thành draft riêng từng `Next-Action`; phân tách động theo `Next-Action: <hex>` và `$ACTION_ID_<hex>` trên `export`, `diff`, `monitor`, `authz -peers`; giải mã luồng RSC Flight (`text/x-component`) thành cây JSON có cấu trúc cho `JudgePeer`.
   - **tRPC `v10`/`v11`:** trích xuất tĩnh chuỗi proxy `@trpc/client` & `@trpc/react-query` (loại trừ TanStack React Query thuần); tách lô động `/trpc/procA,procB?batch=1` (`GET` & `POST`) thành từng procedure độc lập, ánh xạ span lá JSON ngay bên trong query URL-encoded (`query:input$.0.json.id`) cho `Patch`/`BogusID`, và bảo vệ tên procedure dưới `/trpc/` trong `flow.Templates`.
   - **GraphQL Tagged Templates (`gql\`...\``):** trích xuất `GraphQLDoc` (`<= 8192` byte, nối cả fragment tĩnh `${Frag}` và kiểu biến `$id: ID!`) từ `gql`, `graphql()` và `Document` AST; sinh thân JSON thực thi riêng cho từng `query` tĩnh trong `verify` và **luôn bỏ qua** `mutation`/`subscription` tĩnh khi không bật `-allow-write`.
   - **ConnectRPC & gRPC-Web:** trích xuất descriptor `@connectrpc/connect` (`POST` + `GET` khi `NoSideEffects`) và `MethodDescriptor` của `grpc-web`; bảo vệ `/<pkg.Service>/<Method>` trong `flow.Templates`; hỗ trợ BOLA đầy đủ trên `application/connect+json` và khoá không cho `Patch` làm hỏng khung nhị phân 5-byte (`application/grpc-web+proto`, `application/connect+proto`, `application/proto`).

## 3. Quyết định & Lưu ý Vận hành Hiện tại

- **`D1`–`D4` giữ nguyên hiệu lực**; cầu chì `D3` của Spec Probe 2 pha đã được vá nhánh `neterr` và chờ ghi nhận thực địa (`P2.1` / `P5.T`) trên target có phép.
- **Ubuntu 24.04+ AppArmor `userns`:** sau mỗi lần reboot máy Linux, chạy `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` trước khi chạy `testbed/regress.sh`.

## 4. Lộ trình Dài hạn (chưa thực hiện, chỉ mở khi có nhu cầu thực tế)

1. **Tách dần module nội bộ theo thay đổi tính năng:** thu gọn dần sự phụ thuộc `x.cursor` trong `internal/jsapi` và cấu trúc `Config` trong `internal/engine` theo từng tính năng chạm tới (không đại phẫu tách rời).
2. **Tùy chọn Stealth nâng cao:** `-stealth` với `uTLS` + HTTP/2 fingerprint chuẩn Chrome / Isolated World hooks nếu gặp WAF kiểm tra JA4/H2 frame ở pha HTTP pre-auth.
