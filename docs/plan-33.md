# Kế hoạch Thực thi Đợt 33 (`jsharvest` — Mở Toàn Bộ Trần Quét, Cô Lập Lỗi Theo Host & Nâng Cấp AST / Verify / Archive)

Tài liệu thiết kế và theo dõi nghiệm thu cho **Đợt 33** (tiếp nối Đợt 32 [plan-32.md](plan-32.md), đối chiếu các bất biến tại [CLAUDE.md](../CLAUDE.md) và [CURRENT.md](CURRENT.md)).

## 1. Phạm vi & Quyết định Kiến trúc

1. **Gỡ toàn bộ giới hạn cứng mặc định (`0` = không giới hạn):** Cho phép bao phủ tối đa trên hạ tầng multi-subdomain / enterprise lớn ở cả 4 giai đoạn:
   - `crawl`: `-max-pages 0`, `-resolve-max 0` (`httpcrawl.Options.MaxPages = 0`, `MaxFiles = 0`).
   - `frontier` / `specprobe`: `MaxAPIOrigins = 0`, `MaxSpecBases = 0`, `MaxServiceDocPrefixes = 0`, `MaxPhase2SpecProbes = 0`.
   - `archive`: `-max-files 0`, `MaxExtraHosts = 0` (OTX / URLScan trên toàn bộ subdomain), bỏ cắt cụt `5` mục của `HistLine.Scripts` trong `historical.jsonl`.
   - `verify` / `authz`: `-max 0`, `-gate-after 0`, `maxCandidates = 0`, `Options.MaxPrefixes = 0` (vẫn giữ cơ chế kế thừa canary cha khi truyền `MaxPrefixes > 0`).
2. **Giữ nguyên thăm dò 3rd-party theo `D2` nhưng cô lập lỗi theo từng host (`specBlocked`):** Không loại bỏ API origin bên thứ ba mà ứng dụng gọi khỏi `SpecProbe`; tuy nhiên mọi phản hồi chặn/429/challenge (`403 cf-mitigated: challenge`, WAF vendor...) trong pha Spec Probe hậu crawl chỉ khoá riêng host đó (`specBlocked[host]`), tuyệt đối không đặt cờ dừng toàn cục (`cr.stopped`) hay làm mất `specProbePhase2` của các host trong scope.
3. **Đồng bộ Header Canary `OPTIONS` & Chống Dương tính Giả Tường Auth (`verify`):** `canaryOptions` dựng request qua `Draft` mang cùng bộ `Headers` / `SampleHeaders` (ví dụ `X-Requested-With: XMLHttpRequest`) và khoá cache `canaries` theo `(prefix, headerKey)`, kết hợp chốt chặn trong `judge()` để tường `401/403` trên cả `GET` lẫn `OPTIONS` luôn phân loại chính xác là `auth_wall_opaque` thay vì `verified_alive`.
4. **Nâng `jsapi.Version` một lần duy nhất (`39 -> 40`):** Bổ sung liên kết intra-bundle Webpack/Rspack/CJS (`I.d`, `module.exports`, `exports.<k>`), hằng đối tượng `JSON.parse('{...}')`, trích xuất `Keys` trên thuộc tính gán (`this.clientSecret = "..."`) và căn chỉnh slot tham số đường dẫn `pathNames` khi ghép `${baseUrl}?query=${q}`.

---

## 2. Bảng Tiến độ & Bộ Gate Nghiệm thu

| Mã | Hạng mục | Tệp chạm chính | Gate kiểm chứng | Trạng thái |
|---|---|---|---|---|
| **B1.1** | Nhận diện sourcemap thư viện vendor tự host độc lập (`FilesFor`: CKEditor, Bootstrap, Livewire, `/vendor/`, `/wp-includes/js/`...) trong khi giữ nguyên bundle ứng dụng lai (`app.js.map`) | [sourcemap.go](../internal/sourcemap/sourcemap.go), [http.go](../internal/engine/http.go), [sourcemaps.go](../internal/engine/sourcemaps.go), [fetch.go](../internal/archive/fetch.go) | `go test -race ./internal/sourcemap/...`, `waf-check.sh` | `[x]` |
| **B1.2** | Bảo toàn `Origin` & toàn bộ danh sách `Scripts` trong `historical.jsonl`; gỡ trần `MaxExtraHosts` & `-max-files` của `archive` | [history.go](../internal/archive/history.go), [list.go](../internal/archive/list.go), [archive.go](../cmd/jsharvest/archive.go) | `go test -race ./internal/archive/...`, `archive-check.sh` | `[x]` |
| **B2.1** | Mở trần `0` (không giới hạn) cho `crawl`, `frontier`, `specprobe`; cô lập lỗi WAF/challenge theo từng host (`politeSpecAt` / `specBlocked`) ở pha Spec Probe | [crawl.go](../internal/httpcrawl/crawl.go), [queue.go](../internal/frontier/queue.go), [specprobe.go](../internal/frontier/specprobe.go), [main.go](../cmd/jsharvest/main.go) | `go test -race ./internal/httpcrawl/... ./internal/frontier/...`, `frontier-check.sh`, `pipeline-check.sh` | `[x]` |
| **B2.2** | Chặn trang lỗi mềm XHTML/XML (`<?xml`, `<!doctype `, cửa sổ 4 KB, kiểm `Content-Type` `text/html` / `application/xhtml+xml`) không lọt vào kho `.js` | [crawl.go](../internal/httpcrawl/crawl.go), [fetch.go](../internal/archive/fetch.go) | `go test -race ./internal/httpcrawl/... ./internal/archive/...` | `[x]` |
| **B3.1** | Đồng bộ header giữa probe và `canaryOptions`, khoá `canaries` theo bộ header và chặn dương tính giả `401/403` `OPTIONS` trên tường xác thực AJAX | [verify.go](../internal/verify/verify.go), [verify.go](../cmd/jsharvest/verify.go), [authz.go](../cmd/jsharvest/authz.go) | `go test -race ./internal/verify/...`, `verify-check.sh`, `crosscheck-check.sh` | `[x]` |
| **B3.2** | Khôi phục `Origin` cho draft lịch sử từ `Scripts[].URL`, cô lập `client_headers` theo script/origin trên đa subdomain, suy luận mã ngôn ngữ i18n cho slot đường dẫn, chống nhân bản đường dẫn OpenAPI export | [draft.go](../internal/verify/draft.go), [catalog.go](../internal/export/catalog.go), [openapi.go](../internal/export/openapi.go) | `go test -race ./internal/verify/... ./internal/export/...`, `export-check.sh` | `[x]` |
| **B4.1** | Liên kết intra-bundle Webpack 4/5 (`req.d`, `module.exports`) + `JSON.parse('{...}')` + `keyExpr` trên gán thuộc tính/class field + sửa lệch slot `pathNames` trước `?`/`#`; nâng `jsapi.Version = 40` | [modules.go](../internal/jsapi/modules.go), [eval.go](../internal/jsapi/eval.go), [defs.go](../internal/jsapi/defs.go), [params.go](../internal/jsapi/params.go), [jsapi.go](../internal/jsapi/jsapi.go) | `JSAPI_SNAPSHOT`, `JSAPI_STATS`, `perfgate`, `endpoints-check.sh` | `[x]` |
| **B5.1** | Đa luồng & Đồng bộ hoá toàn tuyến (`archive` ZipNum `showNumPages` + `collapse=digest` + worker pool song song cho CDX shards, OTX/URLScan `extra` subdomains, `fetch` + `singleflight` live-check; song song hoá `SpecProbe` đa origin; nâng mặc định `-concurrency 8` cho `archive` & `verify`) | [wayback.go](../internal/archive/wayback.go), [list.go](../internal/archive/list.go), [fetch.go](../internal/archive/fetch.go), [crawl.go](../internal/httpcrawl/crawl.go), [archive.go](../cmd/jsharvest/archive.go), [verify.go](../cmd/jsharvest/verify.go) | `go test -race ./internal/archive/... ./internal/httpcrawl/...`, `archive-check.sh`, `verify-check.sh` | `[x]` |

---

## 3. Quy trình Kiểm tra Lại trên Máy Linux (`pull` từ `main`)

```bash
# 1. Mở quyền userns trên Ubuntu 24.04+ (nếu vừa reboot)
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0

# 2. Chạy toàn bộ unit test với race detector + perfgate
go vet ./...
go test -race ./...
go build -o bin/jsharvest ./cmd/jsharvest
go build -o bin/testbed ./testbed/cmd/testbed
./bin/testbed perfgate -bin ./bin/jsharvest

# 3. Chạy toàn bộ 24 gate tích hợp (netns + Chrome + Docker)
DOCKER=1 testbed/regress.sh -j 3
```
