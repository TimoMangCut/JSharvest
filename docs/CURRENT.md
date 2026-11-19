# Trạng thái Hiện hành (`jsharvest` — Sau Đợt 37.1)

Tài liệu nhập ngữ cảnh nhanh cho session mới (~5 KB). Đọc cùng [CLAUDE.md](../CLAUDE.md) (bất biến & quy trình gate); chỉ mở [rounds-history.md](rounds-history.md), [plan-34.md](plan-34.md), [plan-33.md](plan-33.md) hoặc [plan-32.md](plan-32.md) khi cần chi tiết lịch sử/thiết kế cũ.

## 1. Quy mô & Trạng thái Mốc Đợt 34

- **Mã nguồn:** Go 1.25.4 (`CGO_ENABLED=0`, single binary, không thêm phụ thuộc ngoài); Đợt 34 bổ sung bộ điều khiển Độ lợi Thông tin Biên (`ΔInformation`), kiến trúc Streaming Archive DAG + Bộ nhớ đệm RAM có trần (`-mem-cache-mb`), lập lịch công bằng Weighted DRR đa tầng, nén Gzip chỉ mục CDX và hiệu chuẩn sâu `verify`/`detect`.
- **Trạng thái kiểm định:**
  - `go vet ./...` (trên cả `darwin/arm64` và `linux/amd64`) & `go test -race ./...`: **100% PASS** toàn bộ package.
  - `bin/testbed perfgate` (2.000 script, `43.1 MB`): `~2.5 s` trên macOS ARM64 / `~8.6 s` trên Linux x86_64, peak RSS `~278–282 MB` (trần cứng: `<= 15.0 s`, `<= 500.0 MB`).
  - Gate tích hợp `verify-check.sh`, `archive-check.sh`, `pipeline-check.sh`, `frontier-check.sh`, `frontier-tabs-check.sh`: **PASS 100%** (`precision 1.000`, `recall 1.000`, kể cả tạm dừng `SIGINT` & resume, `-tabs 1 == -tabs 3`).
  - Kiểm tra hygiene đường dẫn & dữ liệu sạch (`.github/workflows/ci.yml`): **`0` vi phạm**.
- **Phiên bản extractor:** `jsapi.Version = 42`.

## 1b. Đợt 37 & 37.1 (tốc độ, giữ chất lượng; [plan-37.1.md](plan-37.1.md), [research-2026-11-19-speed-plan-review.md](research-2026-11-19-speed-plan-review.md))

Đợt 35–36 xem `git log` (`f9725e0`, `db98e0d`, `2e5c5fc`).

- **Crawl HTTP:**
  - Worker được trả khi tải xong, commit vẫn đúng thứ tự heap.
  - Origin **ổn định** ở mọi câu trả lời HTTP, gán cho cả origin yêu cầu lẫn origin cuối. Trang 3xx không bao giờ là shell, nhưng link của nó (kể cả `Location`) vẫn được thu.
  - Hai breaker:
    - **dial** theo `host:port`: First-Dial Gate, 2–3 strike, half-open 3 phút;
    - **origin** theo `scheme://host:port`: 3 lỗi sau khi đã kết nối, chỉ với origin chưa từng trả lời.
  - Request bị giữ **không gửi**: không vào `requests.jsonl`, không tính lượt thăm (`pages.jsonl` `reason: origin-unreachable`, `stats.held_by_breaker`), không tốn hạn mức `-http-rate`.
  - Probe dịch vụ (spec probe) song song theo host.
  - Dedup sourcemap theo `(sha256 script, loại thư viện, ref tương đối)`: map tải 1 lần; host sau ghi sighting theo SHA (`store_errors.sighting_missing` nếu hụt).
- **Archive:**
  - Gap CDX 2,5 s (Internet Archive giới hạn ~30 req/phút), AIMD lên tối đa 10 s; duyệt shard theo stride, có `wayback_listed_pct`.
  - Lỗi được cô lập theo nguồn: `ErrBlocked` của Wayback không hủy CC/OTX/URLScan; Memento bị chặn thì chuyển sang WARC của CC; `history()` luôn chạy.
  - `crawl -archive`: Stage 1 (`ModeListOnly`, 0 request tới target) chạy cùng crawl; Stage 2 (`ModeResume`) chạy sau Escalate/SPABoot. Cả hai dùng chung một `archiveEnv` (khoá, client, budget); trần `-archive-max-pages 150`.
  - CDX bị **từ chối kết nối** thì Memento chờ và dừng ngay ở lần từ chối đầu; 429 của CDX không truyền sang Memento.
  - Cờ nội bộ `-list-only`/`-stage2` đã bỏ.
- **Verify:**
  - `-host-inflight N` (mặc định 1, chỉ có lợi khi `-rate` lớn hơn 1/RTT). Singleflight cho canary, sub-canary, OPTIONS và root canary.
  - Root canary chạy ở **mọi** N.
  - **Re-judge** 2xx-HTML với mọi shell canary đã biết: 0 request thêm, chỉ hạ `verified_alive`, tất định theo thứ tự.
  - Host hạ về 1 khi gặp 429 (một chiều), hoặc khi đang đếm gate (tự nhả khi host trả lời khác).
- **Test:** `internal/testlint` chặn handler test ghi biến capture mà không khoá.

## 2. Năng lực Mới từ Đợt 34 / 34.1 / 34.2 ([plan-34.md](plan-34.md)), Đợt 33 ([plan-33.md](plan-33.md)) & Đợt 32 ([plan-32.md](plan-32.md))

1. **Điều khiển `ΔInformation`, Streaming Archive DAG, Dual-Pool MemCache, Liên Kết Hằng Liên Chunk & Gia Cố Chống Gãy (Đợt 34, 34.1 & 34.2):**
   - **Tầng Crawl & Frontier (HTTP + CDP dùng chung `frontier.Skeleton`):** Prefix Trie 2 tầng có trần bộ nhớ bảo vệ tuyệt đối các route controller cấp gốc `/` (`/admin`, `/billing`, `/api-keys`...) và ưu tiên cây con tĩnh đã mở trước `collapsed`, giới hạn khóa query (`<= 8`), chặn phình mảng `Queue.Listed` (`maxListedEntries = 50000` + `ExtraListed`); mở rộng sang **CDP Browser Engine** bằng **Windowed Dynamic Admission (`W = 12`)** tất định 100% tại `commit()` (`-tabs 1 == -tabs N` tuyệt đối, đo chữ ký ngữ nghĩa cho inline `__NEXT_DATA__` và phân tích gia tăng `AnalyzeExcept`); `frontier.Queue` lập lịch công bằng **Weighted DRR** theo host (`weight 1..4`) kèm `Feedback`.
   - **Tầng Archive, Fault Isolation & Anti-OOM (`-mem-cache-mb`, mặc định `512` MiB):** xoá bỏ hoàn toàn tệp tạm `html.jsonl` bằng `HTMLTop` giới hạn trên luồng (`stateVersion = 3`, tắt hẳn khi `-max-html 0`); máy trạng thái 4 pha (`Pending | Valid | Dead | Pruned`) cho **Coarse-Stride (`8` mốc) + Binary Zoom-In** theo `SemanticAPISig` tách biệt `archBody` lịch sử khỏi bản `live`, nạp sẵn mốc từ `loadCurrent` (`SHA1B32 -> SHA256`) + Prefetch (`|Δt| >= 60d`), tách `deadRetries` khỏi `familyMaxZoom`, kèm `drrQueue` 2 tầng; tách riêng **`Wayback.IndexClient` (CDX, trần `64 MiB`)** và **`Wayback.Client` (Memento)** để lỗi `ErrBlocked` lúc prefetch không bao giờ hủy luồng quét CDX, khóa `CheckRedirect` trên `ccClient`; đo kích thước byte chuỗi thật trong `estimateResultBytes`, gộp 1 lượt đọc `AnalyzeSlim` + `SaveIntelFromScripts`, thay `cur.files() [][]byte` bằng quét streaming từng file `<= 32 MiB` với `pathMatcher` biên dịch sẵn, đặt trần sourcemap (`32/64 MiB`).
   - **Độ chính xác `verify`, `detect`, Vệ sinh HTTP & Ranh giới `-attach`:** nhận diện trang chặn F5 BIG-IP ASM (`Request Rejected` `200 text/html`) là `BlockRequest`; hàm `sameHTMLShell` bắt buộc khớp tuyệt đối mã băm `Shell` (bỏ `<title>` rỗng, thăng cấp toàn RDN khi có nhãn WAF hoặc xuất hiện trên `>= 2` host) cho cả canary lẫn **sub-canary** phân đoạn nhạy cảm; lọc triệt để CRLF/NUL và header sai chuẩn RFC 7230 ở cả `jsapi.clientHeaders` lẫn `verify.Draft.raw`; fallback `ExtractLoose` cho bundle monolith `16..64 MiB` thay vì bỏ trắng; báo lỗi đĩa sớm tại `store.flushLocked`; bắt buộc **mọi** SpecProbe cross-origin (kể cả ở chế độ `-attach`) đi qua `netsafe` `directSpecFetch`.
   - **Phân tích tĩnh `jsapi` v42 & Tối ưu Lượt Duyệt AST:** bóc ngoặc `(function(){...})` của Terser và `MethodDecl`, hỗ trợ `constOrSingleExpr` và `Object.freeze`, giải thuộc tính qua `thisProps` (`<= 256` phần tử đồng thuận), liên kết từ điển hằng số/enum liên chunk (`ConstExports` `<= 1024` khóa ↔ `BuildIntel`/`MergeClientAuthz`, hỗ trợ cả CJS lồng nhau `c.PERMISSION.READ`, destructured `canVars` và JSX `<Can>`), đồng thời cắt 4–6 lượt duyệt AST thừa.

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
