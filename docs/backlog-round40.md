# Kế hoạch & Chi tiết Kỹ thuật Đợt 40 (Hậu Đợt 39)

**Nền mã nguồn:** `14ee04f` (sau Đợt 39) · **Trạng thái:** đã xác định nguyên nhân gốc đến từng file/hàm, sẵn sàng triển khai ở session tiếp theo.

**Nguyên tắc bất biến:** Zero Band-Aids — không cắt recall trên reverse-proxy SPA (nơi frontend và `/api/*` dùng chung origin), không cho phép probe OpenAPI lan sang SaaS/IdP/SDK bên thứ ba ngoài scope mục tiêu, không phá vỡ SSRF guard cho dải IP nội bộ, không đưa tên mục tiêu thật hoặc đường dẫn máy cá nhân vào repo/test.

| Mã | Mức ưu tiên | Vùng mã nguồn | Tóm tắt lỗi & mục tiêu |
|---|---|---|---|
| **R40-A1** | Cao | `internal/jsapi` (`eval.go`, `defs.go`, `result.go`) | Giải `ObjectPattern` destructuring trực tiếp từ `*js.ObjectExpr` (mẫu build production của Vite `import.meta.env`) + trích `Result.Bases` cho `*API*DOMAIN*` / `*API*URL*` / `VITE_BASE_*` + bắt hậu tố key `*_KEY_<LOCALE>` |
| **R40-A2** | Cao | `internal/jsapi` (`calls.go`) | Nối `o.base` (`x.optBasePre(o.base)`) cho nhánh `clientMethods` (`axiosInstance.get(url, { baseURL })` / `axiosInstance.post(url, body, { baseURL })`) để không làm cụt prefix microservice |
| **R40-A3** | Cao | `internal/endpoints`, `internal/verify` (`endpoints.go`, `draft.go`) | Tránh ghim cứng `Origin` của SPA frontend (`spa_origins`) cho các endpoint `wrapper` / `client` tương đối khi dự án có `intel.Bases` tách rời (ví dụ API Gateway riêng), giữ thử nghiệm cả API base lẫn fallback SPA origin mà không mất `139+` route sau Kong |
| **R40-B1** | Trung bình | `internal/frontier`, `internal/httpcrawl` (`specprobe.go`, `queue.go`, `crawl.go`) | Chặn `OriginSpecPaths` & `specProbePhase2` nhân bản request sang origin của SDK/IdP/bản đồ/tài liệu bên thứ ba (`login.microsoftonline.*`, `graph.microsoft.com`, `nominatim.openstreetmap.org`, `reactrouter.com`, `ns.adobe.com`, `xfa.org`...) |
| **R40-B2** | Trung bình | `internal/httpcrawl` (`crawl.go`) | Không ghi nhận `200` giả vào `http.probes` khi phản hồi là SPA fallback HTML (`matchesOriginSPAShell` / `text/html` cho `.json`/`.yaml` manifest & spec) |
| **R40-B3** | Trung bình | `internal/engine` (`http.go`) | Đồng bộ lại `run.Scripts`, `run.UniqueScripts`, `run.NewScripts` và `run.Requests` trong `run.json` sau khi chạy `Escalated` hoặc `SPABoot` (`launch`) |

---

## 1. Nhóm R40-A — Độ phủ `jsapi`, `intel.bases` & Ghép Base cho Decoupled SPA

### R40-A1. Giải Vite `import.meta.env` Object Literal Destructuring & `Result.Bases`
- **Hiện tượng thực tế:**
  - Trên SPA dùng Vite (`driver-spa.staging.example.test`, bundle `9.64 MB`), trình biên dịch Rollup/Vite inline `const { VITE_BASE_API_DOMAIN, ... } = import.meta.env` thành destructuring trực tiếp từ một Object Literal:
    ```js
    const {
      VITE_BASE_API_DOMAIN,
      VITE_MEDIA_API_URL,
      VITE_BASE_SAP_DECRYPT_PUBLIC_KEY,
      VITE_BASE_SAP_DECRYPT_PUBLIC_KEY_LAO
    } = {
      VITE_BASE_API_DOMAIN: "https://api.staging.example.test",
      VITE_MEDIA_API_URL: "https://media-static.staging.example.test",
      VITE_BASE_SAP_DECRYPT_PUBLIC_KEY: "<64-hex>",
      VITE_BASE_SAP_DECRYPT_PUBLIC_KEY_LAO: "<64-hex>",
      BASE_URL: "/",
      MODE: "production"
    };
    const ACCOUNT_API_URL = `${VITE_BASE_API_DOMAIN}/account/v1/public`;
    ```
  - Do không giải được `VITE_BASE_API_DOMAIN`, `ACCOUNT_API_URL` bị biến thành `{}/account/v1/public`, đồng thời `intel.json` trả `bases: null` khiến toàn bộ `148` probe trong `verify` chỉ rơi vào S3 SPA frontend (`200 text/html` → `dead_or_fp`). Ngoài ra khóa thứ hai mang hậu tố quốc gia (`_PUBLIC_KEY_LAO`) bị lọt khỏi `intel.keys`.
- **Nguyên nhân gốc trong mã:**
  1. [eval.go](../internal/jsapi/eval.go#L362-L373): `evalVar` viết `if src, ok := x.destructFrom[v].(*js.Var); ok` nên chỉ giải khi vế phải là biến `*js.Var`, bỏ qua hoàn toàn trường hợp `x.destructFrom[v]` bản thân đã là `*js.ObjectExpr` (dù `x.object(x.destructFrom[v])` đã hỗ trợ cả hai).
  2. [defs.go](../internal/jsapi/defs.go#L159-L168) & logic thu thập `Bases` / `Keys`: các thuộc tính URL gốc API (`*API*DOMAIN*`, `*API*URL*`, `VITE_BASE_*`) nằm trong object literal của phép destructuring chưa được đưa vào `Result.Bases`; biểu thức khớp tên hằng nhạy cảm chưa nhận hậu tố vùng ngắn sau `_KEY` / `_SECRET` / `_TOKEN` (ví dụ `_[A-Z]{2,5}$`).
- **Hướng sửa:**
  - Tại `evalVar` (`eval.go:362`) và các điểm đọc `x.destructFrom` liên quan (`keys.go`, `calls.go`, `result.go`): gọi thẳng `if obj, ok := x.object(x.destructFrom[v]); ok` trước, chỉ fallback sang `fromCallersOf` khi `x.destructFrom[v]` là `*js.Var`.
  - Quét các cặp key-value chuỗi URL hợp lệ mang tên cấu hình API base trong object literal khởi tạo/destructuring để đưa vào `Result.Bases`.
  - Mở rộng bộ lọc tên key trong `jsapi` nhận hậu tố môi trường/quốc gia ngắn (`_LAO`, `_VN`, `_EU`, `_DEV`, `_PROD`...) khi giá trị thỏa ngưỡng entropy/hex key.

### R40-A2. Nối `{ baseURL }` theo từng request ở nhánh `clientMethods` (`axiosInstance.get/post/...`)
- **Hiện tượng thực tế:**
  - Ứng dụng khởi tạo `axiosInstance = axios.create({ timeout, headers })` không gắn `baseURL` mặc định, sau đó truyền `{ baseURL: ACCOUNT_API_URL }` hoặc `{ baseURL: MISSION_API_URL }` ở đối số cấu hình của **89 lời gọi** `axiosInstance.get(path, { baseURL })` / `axiosInstance.post(path, data, { baseURL })` trên 21 microservice khác nhau.
  - Kết quả trích xuất tĩnh bị rơi mất hoàn toàn `baseURL`, chỉ còn đường dẫn cụt `/supplier/profile` thay vì `https://api.staging.example.test/account/v1/public/supplier/profile`.
- **Nguyên nhân gốc trong mã:**
  - Tại [calls.go](../internal/jsapi/calls.go#L257-L276) (nhánh `clientMethods[prop]`):
    ```go
    if len(as) > cfg {
        if o, ok := x.options(as[cfg]); ok {
            ep.Query, ep.Headers = o.query, o.headers
        }
    }
    x.pre = x.prefixesOf(d.X)
    ```
    Trong khi `axios.request({ url, baseURL })` (`calls.go:413`), `helpers.go:515` và `modules.go:811` đều gọi `x.optBasePre(o.base)`, nhánh `clientMethods` chỉ lấy `o.query, o.headers` mà bỏ quên `o.base`.
- **Hướng sửa:**
  - Khi `o.base != nil` trong `calls.go:266-274`, tính `optPre, isClient := x.optBasePre(o.base)` (và `ep.BaseKeys = x.baseKeysOf(o.base, false, 0)` nếu `isClient`): nếu `o.base` là URL đầy đủ hoặc đường dẫn gốc thì ghi đè/ghép chuẩn với `x.prefixesOf(d.X)` theo đúng quy tắc `axios` (`baseURL` cấp request ghi đè `baseURL` của instance).
  - Bắt buộc chạy snapshot `TestSnapshot` trên `internal/jsapi` và `perfgate` để đảm bảo 0 hồi quy.

### R40-A3. Không ghim chết `Origin` vào SPA Frontend Host cho `wrapper` / `client` tương đối
- **Hiện tượng thực tế:**
  - Trên `portal-a.staging.example.test`, `intel.json` đã tìm thấy `bases: ["https://api.staging.example.test"]`, nhưng **639/860** endpoint trong `endpoints.jsonl` (chủ yếu `kind: "wrapper"` gọi qua helper `et.post(PATH, body)` từ bundle chính) lại bị gán cứng `origin: "https://portal-a.staging.example.test"`, chỉ **221** endpoint có `origin` rỗng hoặc gắn host API.
  - Khi sang `verify`, nhóm gắn `api.staging.example.test` xác nhận được **`139` `auth_wall_opaque`** (`401` sau Kong Gateway), còn **532** endpoint mang `origin` của SPA frontend chỉ được thử vào nginx SPA (`200 text/html`) rồi bị kết luận `dead_or_fp` mà không được thử lên `https://api.staging.example.test`!
- **Nguyên nhân gốc trong mã:**
  - [endpoints.go](../internal/endpoints/endpoints.go#L948) (`ep.Origin = pageOrigin(ep, inScope)`) gắn cứng `Origin` của trang SPA chứa script cho các endpoint đường dẫn tương đối không có `{}` đầu chuỗi; sau đó [draft.go](../internal/verify/draft.go#L602-L603) thấy `l.Origin != ""` thì chỉ tạo duy nhất 1 URL `l.Origin + l.Path`, bỏ qua danh sách `intel.Bases` ngoài origin!
- **Hướng sửa:**
  - Phân biệt rõ `kind == "navigation"` (route điều hướng trình duyệt) với lời gọi API (`client`, `wrapper`, `fetch`, `xhr`, `options`):
    - Khi `l.Origin` nằm trong tập `spa_origins` (hoặc trả SPA shell) **và** dự án có `intel.Bases` in-scope khác origin (ví dụ `https://api.staging.example.test`), `verify` (`draft.go`) cần cho phép ghép ứng viên từ `intel.Bases` (ưu tiên API base ngoài SPA shell hoặc thử tiếp ứng viên API base khi SPA origin trả đúng SPA canary shell), **đồng thời vẫn giữ nguyên** khả năng verify trên chính origin cho mô hình Nginx reverse-proxy SPA.

---

## 2. Nhóm R40-B — Chống Nhiễu `specProbe`, `http.probes` & Đồng bộ `run.json`

### R40-B1. Chặn `OriginSpecPaths` & `specProbePhase2` lan sang Host SDK / IdP Bên Thứ Ba
- **Hiện tượng thực tế:**
  - Trên `portal-a.staging.example.test` (`253` chunks chứa MSAL Azure AD, OpenStreetMap, Google Maps tiles, React Router...), `http.probes` phát sinh tới **768 request**, phần lớn bắn vào domain của SDK/dịch vụ ngoài (`login.microsoftonline.com` ×197, `login.microsoftonline.us` ×197, `login.chinacloudapi.cn` ×197, `graph.microsoft.com` ×25, `microsoftgraph.chinacloudapi.cn` ×25, `sdk.partner.example.net` ×25, `mt0.google.com` ×15, `nominatim.openstreetmap.org` ×15, `reactrouter.com` ×15).
  - Tương tự trên bundle có `pdf.worker.min.mjs`, các URI chuẩn XML (`http://ns.adobe.com/xdp/`, `http://www.xfa.org/schema/*`) xuất hiện trong danh sách `pages.jsonl` (`reason: "scope"`).
- **Nguyên nhân gốc trong mã:**
  - [crawl.go](../internal/httpcrawl/crawl.go#L1700) (`cr.specCtx.Plan(seedOrig, cr.o.InScope)`) và `cr.specPolicy` cho phép cross-origin API bases để bắt trường hợp frontend `example.com` gọi API `example-api.com`, nhưng chưa lọc các đám mây IdP/SaaS/bản đồ/tài liệu công cộng và chưa giới hạn `OriginSpecPaths` nghiêm ngặt cho host thuộc phạm vi mục tiêu (`InScope`).
- **Hướng sửa:**
  1. Trong `frontier/queue.go` (`nonAPIInfraDomains`) và `frontier/specprobe.go`: bổ sung danh sách loại trừ các hạ tầng bên thứ ba phổ biến không bao giờ là OpenAPI của mục tiêu (`microsoftonline.com`, `microsoftonline.us`, `chinacloudapi.cn`, `microsoftonline.cn`, `graph.microsoft.com`, `live.com`, `openstreetmap.org`, `mapbox.com`, `maplibre.org`, `tileserver.org`, `mt0.google.com`, `mt1.google.com`, `googleapis.com`, `reactrouter.com`, `ns.adobe.com`, `adobe.com`, `xfa.org`...).
  2. Trong `specProbeWithScope` / `specCtx.Plan`: **chỉ** chạy `OriginSpecPaths` và nhân bản sub-path `ServiceDocPaths` (`197` probe/host!) trên các host thỏa `inScope(host)` (với cross-origin ngoài `inScope`, tối đa chỉ cho phép kiểm tra nhẹ hoặc bỏ qua hoàn toàn nếu không được cờ cho phép rõ ràng).

### R40-B2. Không ghi Soft-`200` SPA Fallback (`text/html`) như Hit `200` trong `http.probes`
- **Hiện tượng thực tế:**
  - Trên các SPA trả `200 text/html` (`index.html`) cho mọi đường dẫn lạ (`staff-dev.example.test` 51/54, `driver-spa.staging.example.test` 21/21), `run.json -> http.probes` ghi toàn bộ `/.vite/manifest.json: 200`, `/openapi.json: 200`, `/mix-manifest.json: 200`, `/ngsw.json: 200`... gây hiểu nhầm khi đọc báo cáo tóm tắt (dù bộ parser bên dưới đã từ chối nạp vì là HTML).
- **Nguyên nhân gốc trong mã:**
  - [crawl.go](../internal/httpcrawl/crawl.go#L1347), [L1575](../internal/httpcrawl/crawl.go#L1575) và [L1792](../internal/httpcrawl/crawl.go#L1792) ghi thẳng `st.Probes[key] = a.Status` ngay sau khi fetch, trước khi kiểm tra `matchesOriginSPAShell(a)` hoặc đối chiếu kỳ vọng định dạng (JSON/YAML/XML/txt).
- **Hướng sửa:**
  - Khi `a.Status >= 200 && a.Status < 300` nhưng `matchesOriginSPAShell(a)` là `true` (hoặc probe kỳ vọng JSON/manifest mà `htmlLike(a.Body)` là `true` và không phải trang Swagger UI thật), không ghi `200` vào `http.probes` (hoặc quy ước mã phân biệt / tách trường `soft_404_probes` để `http.probes` phản ánh đúng trạng thái thực). Kiểm tra tương thích với các assert hiện có trong `internal/httpcrawl/*_test.go`.

### R40-B3. Đồng bộ Thống kê `run.json` sau khi chạy `Escalated` hoặc `SPABoot` (`launch`)
- **Hiện tượng thực tế:**
  - Khi pha `http` leo thang sang Chrome (`Escalated` do lỗi kết nối đầu trang trên `alert-static.example.test`, hoặc `SPABoot` trên `driver-spa` và `portal-a`), `runs.jsonl` ghi đủ 2 lượt chạy nhưng `run.json` ngoài cùng vẫn giữ số liệu cũ của riêng pha `http`:
    - `alert-static.example.test`: `http` gặp `connection reset by peer` (`requests: 1, unique_scripts: 0`), `launch` tải thành công (`21` requests, `1` script, `8/8` endpoint `verified_alive`), nhưng `run.json` vẫn báo `requests: 1, unique_scripts: 0`.
    - `driver-spa`: `run.json` ghi `unique_scripts: 8` trong khi `index.jsonl` / `js/` có `9` scripts (`+1` từ `spa_boot`).
    - `portal-a`: `run.json` ghi `unique_scripts: 251` trong khi `index.jsonl` / `js/` có `253` scripts (`+2` từ `spa_boot`).
- **Nguyên nhân gốc trong mã:**
  - Tại [http.go](../internal/engine/http.go#L397-L417), sau `run.Escalated` và `run.SPABoot`, code gọi `tmp.writeEndpoints()` và chỉ chép lại `run.Endpoints, run.StaticAnalysis, run.Warnings`, bỏ sót cập nhật `run.Scripts`, `run.UniqueScripts`, `run.NewScripts` từ `store` và cộng dồn `Requests` / `PageRequests` từ các `EscalatedRun`.
- **Hướng sửa:**
  - Viết helper đồng bộ lại danh sách SHA script hiện có trong `store` (`run.Scripts`, `run.UniqueScripts`, `run.NewScripts`) và cộng dồn bộ đếm request từ `run.Escalated` / `run.SPABoot` ngay tại `http.go:402` và `http.go:416` (cũng như sau `Fallback`/`Archive` nếu có nạp thêm live script vào store).

---

## 3. Kiểm thử & Gate Bắt Buộc Khi Thực Thi Đợt 40

1. **Unit & Regression Tests:**
   - `internal/jsapi/round40_test.go`: test Vite `import.meta.env` inline `*js.ObjectExpr` destructuring + template `${VITE_BASE_API_DOMAIN}/service/v1/public` + `axiosInstance.get/post(url, [data,] { baseURL: SERVICE_URL })` + key hậu tố `_PUBLIC_KEY_LAO`.
   - `internal/verify/round40_test.go` & `internal/endpoints/round40_test.go`: test decoupled SPA (`spa_origins` trả `200 text/html` shell, `intel.Bases` chứa `https://api.example.test` trả `401`/`200 JSON`) đảm bảo cả endpoint `wrapper` lẫn `client` đều verify trúng `api.example.test` mà không làm hỏng case reverse-proxy SPA cùng origin.
   - `internal/httpcrawl/round40_test.go` & `internal/engine/round40_test.go`: test chặn probe sang `login.microsoftonline.com` / `nominatim.openstreetmap.org` (`0` request), lọc soft-`200` SPA shell khỏi `http.probes`, và đồng bộ `run.UniqueScripts` / `run.Requests` sau `Escalated` & `SPABoot`.
2. **Quality Gates:**
   - Snapshot kiểm tra khác biệt có kiểm soát trên `internal/jsapi` (`TestSnapshot`).
   - `go vet ./...`, `go test -race -count=1 ./...` (bao gồm `internal/testlint` cho mọi `httptest.NewServer` mới).
   - `testbed/verify-check.sh`, `testbed/pipeline-check.sh`, `testbed/archive-check.sh`, `testbed/waf-check.sh`, và `./bin/testbed perfgate -bin ./bin/jsharvest`.
