# Kế hoạch & Chi tiết Kỹ thuật Đợt 40 (Hậu Đợt 39)

**Nền mã nguồn:** `83c308f` (sau Đợt 39) · **Trạng thái:** đã triển khai đầy đủ theo đặc tả v2 (xem tổng kết tại [plan-40.md](plan-40.md)). Thứ tự triển khai: A1+A2 → đo lại → B1 → A3 → B3 → B2 → D.

### Điều chỉnh sau review (v2)

| Mục | Đặc tả v1 | Vấn đề tìm thấy khi đối chiếu mã | v2 |
|---|---|---|---|
| A1 | Ghi `it.Value.Default` vào `x.chains` | `evalVar` chỉ vào nhánh `destructFrom` khi `len(x.chains[v]) == 0` → default thành nguồn **chính**, tắt luôn nhánh đọc object/`fromCallersOf` | Map riêng `destructDefault`, chỉ dùng khi không giải được từ object và từ nơi gọi |
| A1 | Loại trừ `_ID`, `_TYPE`… ngay trong `keyNameRe` | Go RE2 không có lookahead; `TOKEN_TYPE = "Bearer"` vẫn qua `keyValue` (≥ 6 ký tự) | Cắt hậu tố bằng code + đòi giá trị trông như khoá thật cho tên chỉ khớp nhờ hậu tố |
| A2 | Gán `ep.BaseKeys` từ `o.base` trước `x.add` | `add()` ([strings.go:117](../internal/jsapi/strings.go#L117)) luôn nối thêm `client:` keys của instance → trộn base đã bị ghi đè | Cờ nội bộ để `add` bỏ nối khoá instance khi có `baseURL` cấp request |
| B1 | Tham chiếu `IsNonAPIInfraHost` | Hàm không tồn tại; tên thật `isStaticOrNonAPIHost` (không export) | Sửa tham chiếu; danh sách chặn chỉ là lớp phụ, quy tắc scope là lớp chính; ghi rõ đánh đổi `-scope fqdn` |
| B2 | Bỏ key khỏi `Probes` khi soft-200; "chỉ 1 test dùng `Probes`" | [pipeline_test.go:83](../internal/httpcrawl/pipeline_test.go#L83) dùng key của `Probes` để biết host nào đã probe; lo ngại race không có cơ sở | Giữ `Probes[key]`, thêm `SoftProbes` riêng; bỏ phần lo ngại race |
| A3 | `extBases` luôn đứng trước `l.Origin` | `one()` dừng ở `Alive`/`Resource404` đầu tiên → SPA reverse-proxy có thể chốt sai base; cắt tỉa cần 16 path chết, không phải "vài" | Thứ tự theo bằng chứng canary; làm sau khi đo lại A1+A2 |
| B3 | Cộng request/script của Chrome vào bản ghi run HTTP | Run Chrome có dòng riêng trong `runs.jsonl` (pipecheck (e) kiểm 2 dòng) → đếm trùng, lệch `run_id` ↔ `requests.jsonl`, đổi baseline `monitor` | Giữ số riêng của run HTTP, thêm khối `totals` |
| Cổng | Thiếu gate theo CLAUDE.md | — | Thêm `endpoints-check`, snapshot so HEAD, `frontier-check` + `external/run.sh`, `crosscheck-check`; bỏ `archive-check` |

**Nguyên tắc bất biến (Zero Band-Aids):**
- Không cắt recall trên mô hình reverse-proxy SPA (nơi frontend và `/api/*` dùng chung origin).
- Không cho phép probe OpenAPI nhân bản sang SaaS/IdP/SDK/bản đồ/schema bên thứ ba ngoài scope mục tiêu, nhưng vẫn bảo toàn `D2` cho API cross-origin sạch (ví dụ `example.com` gọi `example-api.com`).
- Không phá vỡ SSRF guard (`netsafe`), quyền tệp `0600`/`0700`, hay schema `endpoints.jsonl` hiện tại (giữ nguyên `ep.Origin` làm provenance).
- Khi thay đổi kết quả phân tích tĩnh `internal/jsapi`, **bắt buộc bump `jsapi.Version` (`45 -> 46`)** để vô hiệu hóa cache `static/<sha>.json` cũ.
- Giữ `perfgate` trong trần cứng `<= 15.0 s`, `<= 500.0 MB` (lưu ý nền Linux hiện tại đang ở `~13.24 s / 365.7 MB`, nên tránh thêm lượt duyệt AST thừa trong `internal/jsapi`).
- Không đưa tên mục tiêu thật hoặc đường dẫn máy cá nhân vào tài liệu/test/commit.

| Bước | Mã | Mức ưu tiên | Vùng mã nguồn | Tóm tắt lỗi & mục tiêu |
|---|---|---|---|---|
| **1** | **R40-A1** | Cao | `internal/jsapi` (`eval.go`, `defs.go`, `jsapi.go`, `calls.go`) | Giải `ObjectPattern` destructuring trực tiếp từ `*js.ObjectExpr` (mẫu Vite `import.meta.env`) + thêm hậu tố `"domain"` vào `isBaseName` + cho phép hậu tố vùng/env viết HOA sau key hằng (`*_KEY_<LOCALE>`) + bump `jsapi.Version = 46` |
| **1** | **R40-A2** | Cao | `internal/jsapi` (`calls.go`, `strings.go`) | Nối `x.optBasePre(o.base)` cho nhánh `clientMethods` (`axiosInstance.get/post(..., { baseURL })`) đúng quy tắc ghi đè `baseURL` của `axios`, và không trộn `BaseKeys` của instance |
| **2** | **R40-B1** | Trung bình | `internal/frontier` (`queue.go`, `specprobe.go`), `internal/httpcrawl` (`crawl.go`), `internal/engine` (`specprobe.go`) | Chỉ sinh `plan.Bases`/`plan.Services` và chạy `OriginSpecPaths` cho host `inScope` trên **cả HTTP lẫn CDP engine**; origin ngoài scope chỉ còn probe gốc `SpecPaths` (D2); danh sách hạ tầng là lớp phụ |
| **3** | **R40-A3** | Cao | `internal/verify` (`draft.go`, `verify.go`) | Đọc tùy chọn `spa_origins` từ `run.json`; thêm ứng viên `intel.Bases` in-scope khác origin cho endpoint API tương đối trên origin SPA, **thứ tự theo bằng chứng canary**; làm sau khi đo lại A1+A2 |
| **4** | **R40-B3** | Trung bình | `internal/engine` (`escalate.go`, `http.go`) | Bộ đếm request trong `EscalatedRun`; khối `totals` mới trong `run.json`; **giữ nguyên** số liệu riêng của run HTTP |
| **5** | **R40-B2** | Thấp (tuỳ chọn) | `internal/httpcrawl` (`crawl.go`) | Đánh dấu probe soft-200 SPA fallback HTML trong `SoftProbes` riêng, **giữ** `Probes[key]` (chỉ là telemetry) |
| **6** | **R40-D** | Thấp | `docs/` (`CURRENT.md`, `plan-40.md`, `rounds-history.md`), `CLAUDE.md` | Đồng bộ tài liệu (số đo `perfgate` mới, `waf-check.sh` trong `CURRENT.md`, `jsapi.Version` trong `CLAUDE.md`) |

---

## 1. Bước 1 — Nhóm `R40-A1` & `R40-A2` (`internal/jsapi`, bump `Version = 46`)

### R40-A1. Giải Vite `import.meta.env` Object Literal Destructuring, `isBaseName` (`domain`) & Key Suffix

#### Hiện trạng & nguyên nhân gốc (đã kiểm chứng trên mã nguồn)
Trên SPA dùng Vite (`driver-spa.staging.example.test`, bundle `9.64 MB`), Rollup/Vite inline `const { VITE_BASE_API_DOMAIN, ... } = import.meta.env` thành destructuring trực tiếp từ Object Literal:
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
Ba nguyên nhân gốc chính xác trong mã nguồn:
1. **[eval.go:362-373](../internal/jsapi/eval.go#L362-L373) (`evalVar`):** Viết `if src, ok := x.destructFrom[v].(*js.Var); ok` nên chỉ giải khi vế phải là `*js.Var`, bỏ qua hoàn toàn `*js.ObjectExpr` (kể cả khi bọc trong `(...)` hoặc `Object.freeze(...)`), dù [eval.go:1357](../internal/jsapi/eval.go#L1357) (`objectN`) đã gọi thẳng `x.objectN(src, depth+1)` trên mọi `js.IExpr`. Ngoài ra [defs.go:159-168](../internal/jsapi/defs.go#L159-L168) chưa lưu fallback mặc định `it.Value.Default` nếu destructuring viết dạng `const { VITE_BASE_API_DOMAIN = "https://..." } = env`.
2. **[jsapi.go:181](../internal/jsapi/jsapi.go#L181) (`isBaseName`):** [defs.go:338-350](../internal/jsapi/defs.go#L338-L350) **vốn đã duyệt** mọi `*js.Property` của mọi `*js.ObjectExpr` (kể cả object literal ở vế phải destructuring) qua `case isBaseName(name): x.baseValue(n.Value)`. Lý do thực sự `VITE_BASE_API_DOMAIN` bị trượt khỏi `Result.Bases` là [isBaseName](../internal/jsapi/jsapi.go#L181) chỉ nhận hậu tố `url|base|uri|endpoint|root|host|path|prefix` mà **thiếu `"domain"`**. *(Lưu ý: `VITE_MEDIA_API_URL` bị loại có chủ đích bởi từ khóa `"media"` ở [jsapi.go:167](../internal/jsapi/jsapi.go#L167) để tránh kéo CDN/media bucket thành API base — giữ nguyên rule này.)*
3. **[jsapi.go:303](../internal/jsapi/jsapi.go#L303) (`keyNameRe`):** Neo cuối `$` ngay sau `public[_-]?key` và `...KEY` nên bỏ lỡ khóa mang hậu tố quốc gia/môi trường như `VITE_BASE_SAP_DECRYPT_PUBLIC_KEY_LAO`.

#### Đặc tả thay đổi
1. **`evalVar` ([eval.go:360-374](../internal/jsapi/eval.go#L360-L374)):**
   - Đọc `src := x.destructFrom[v]`; nếu `src != nil`:
     - Gọi trước `if obj, ok := x.object(src); ok`: tra `val := objectValue(obj, x.propOf[v])`; nếu `val != nil && !x.busy[v]` thì đánh dấu `x.busy[v] = true` (`defer delete`) và trả về `x.eval(val, q, depth+1)`. *(Lưu ý: `x.object` xử lý luôn `*js.ObjectExpr`, `*js.GroupExpr`, `Object.freeze({...})`, lẫn `*js.Var` trỏ tới object.)*
     - Chỉ khi `x.object(src)` không ra object và `sv, ok := src.(*js.Var); ok` mới fallback sang `x.fromCallersOf(root(sv), x.propOf[v], q, depth)`.
   - Giá trị mặc định trong destructuring (`const { API_URL = "https://..." } = import.meta.env`, [defs.go:159-168](../internal/jsapi/defs.go#L159-L168)): **không** ghi vào `x.chains`. `evalVar` chỉ đi nhánh `destructFrom` khi `len(x.chains[v]) == 0`, nên default trong `chains` sẽ thành nguồn chính và tắt nhánh đọc object lẫn `fromCallersOf`. Thay vào đó:
     - thêm `destructDefault map[*js.Var]js.IExpr` vào `extractor`, ghi `it.Value.Default` tại defs.go khi `it.Value.Default != nil`;
     - trong `evalVar`, chỉ dùng `x.eval(destructDefault[v], …)` khi `objectValue` trả `nil` **và** `fromCallersOf` trả `nil` (đúng ngữ nghĩa JS: default chỉ áp dụng khi thuộc tính là `undefined`).
   - Kiểm tra [calls.go:1050-1062](../internal/jsapi/calls.go#L1050-L1062) (`baseKeysOf`): giữ gọn nhánh `*js.Var` cho `x.args` và cho phép phân giải `objectValue` trực tiếp nếu `x.destructFrom[rv]` là `*js.ObjectExpr`.
2. **`isBaseName` ([jsapi.go:181](../internal/jsapi/jsapi.go#L181)):**
   - Thêm `"domain"` vào danh sách hậu tố của nhánh `strings.Contains(n, "api") && has("url", "base", "uri", "endpoint", "root", "host", "path", "prefix", "domain")`.
   - Không thêm pass quét AST riêng (tận dụng đúng nhánh `case *js.Property` có sẵn ở [defs.go:343](../internal/jsapi/defs.go#L343) → 0 chi phí `perfgate`).
   - Do yêu cầu `strings.Contains(n, "api")` đồng thời đi qua bộ lọc loại trừ ở dòng 167, các tên như `auth_domain`, `cookie_domain`, `app_domain` không bị dương tính giả.
3. **Hậu tố vùng/môi trường sau tên khoá (`keyName`, [jsapi.go:217](../internal/jsapi/jsapi.go#L217); `keyNameRe` giữ nguyên):**
   - Go RE2 **không có lookahead**, nên không thể loại `_ID`/`_TYPE`… ngay trong regex. Làm bằng code trong `keyName`:
     1. Nếu `keyNameRe` khớp tên gốc → như cũ.
     2. Nếu không, và tên là `UPPER_SNAKE_CASE` kết thúc bằng `_[A-Z]{2,5}` (nhạy hoa/thường) mà hậu tố **không** thuộc danh sách metadata (`ID`, `IDS`, `NAME`, `TYPE`, `LEN`, `SIZE`, `PATH`, `URL`, `URI`, `FILE`, `CODE`, `LIST`, `MAP`, `ALG`, `FMT`, `REF`, `EXP`, `TTL`, `AGE`, `HDR`, `KEY`, `MODE`, `FLAG`, `HASH`): cắt hậu tố rồi so `keyNameRe` lần nữa.
     3. Tên chỉ khớp nhờ bước 2 trả về một cờ `suffixOnly`; nơi gọi (`case keyName(name)` ở defs.go) khi đó đòi thêm giá trị trông như khoá thật: hex ≥ 32 ký tự, base64/base64url ≥ 16 ký tự có cả chữ và số, hoặc PEM. Lý do: `TOKEN_TYPE = "Bearer"` qua được `keyValue` (≥ 6 ký tự).
   - Kết quả mong đợi: `VITE_BASE_SAP_DECRYPT_PUBLIC_KEY_LAO`, `API_KEY_VN`, `PUBLIC_KEY_PROD` (giá trị là khoá thật) khớp; `public_key_id`, `api_key_name`, `secret_type`, `TOKEN_TYPE`, `API_KEY_LAO = "enabled"` không khớp.
4. **Bump phiên bản cache ([jsapi.go:25](../internal/jsapi/jsapi.go#L25)):**
   - Tăng `const Version = 45` → `46`.

---

### R40-A2. Nối `{ baseURL }` cấp request cho nhánh `clientMethods` (`axiosInstance.get/post/...`)

#### Hiện trạng & nguyên nhân gốc
Tại [calls.go:257-276](../internal/jsapi/calls.go#L257-L276), nhánh `clientMethods[prop]` (`get`, `post`, `put`, `patch`, `delete`, `head`, `options`) chỉ trích `o.query, o.headers` từ `as[cfg]` mà bỏ quên `o.base`, trong khi [calls.go:413](../internal/jsapi/calls.go#L413) (`axios.request({ url, baseURL })`), `helpers.go:515`, và `modules.go:811` đều gọi [x.optBasePre(o.base)](../internal/jsapi/keys.go#L619-L644). Hậu quả: 89 lời gọi `axiosInstance.get("/supplier/profile", { baseURL: ACCOUNT_API_URL })` trên 21 microservice bị cụt toàn bộ prefix.

#### Đặc tả thay đổi ([calls.go:258-276](../internal/jsapi/calls.go#L258-L276))
- Trong nhánh `if len(as) > cfg`:
  - Khai báo `var optPre []string; hasOptBase := false`.
  - Khi `o, ok := x.options(as[cfg]); ok`:
    - Giữ `ep.Query, ep.Headers = o.query, o.headers`.
    - Nếu `o.base != nil`:
      - `hasOptBase = true`
      - `pre, isClient := x.optBasePre(o.base)` (lưu ý `optBasePre` đã tự trả `[]string{unknown}, true` nếu `o.base` là biểu thức động không giải được, và trả `nil, false` chỉ khi `o.base` giải ra `""` hoặc `"/"`).
      - `optPre = pre`
      - Nếu `isClient`: gán `ep.Client = true` và `ep.BaseKeys = x.baseKeysOf(o.base, false, 0)`.
      - **Chặn trộn khoá instance:** `add()` ([strings.go:117](../internal/jsapi/strings.go#L117)) luôn nối thêm `client:` keys của `d.X` cho mọi `Kind == "client"` có path tương đối. Khi `hasOptBase`, đặt một cờ nội bộ của extractor (ví dụ `x.reqBase = true`, xoá ngay sau `x.add`; **không** dùng `ep.NoInheritBase` vì cờ đó có nghĩa khác ở endpoints) để `add` bỏ qua bước nối khoá instance. Áp dụng cả khi `baseURL: "/"` (`optPre == nil`): base của instance đã bị ghi đè.
- Chọn `x.pre` đúng ngữ nghĩa `axios` (request-level `baseURL` ghi đè instance-level `defaults.baseURL`):
  ```go
  if hasOptBase {
      x.pre = optPre // ghi đè baseURL của instance; nếu o.base == "/" thì optPre == nil (không dán base mặc định lên)
  } else {
      x.pre = x.prefixesOf(d.X)
  }
  ```
- Giữ `key := x.add(as[0], ep, c, call)` và `x.pre = nil`.
- **Bất biến:** Khi `o.base == nil`, hành vi giống hệt trước đây (0 thay đổi cho mọi call không truyền `baseURL`). Khi `as[0]` đã là absolute URL (`https://...`), `x.prefixed` ([clients.go:179](../internal/jsapi/clients.go#L179)) không ghép `x.pre` (chỉ ghép khi path bắt đầu bằng `/`, không phải `//`) — đã xác nhận.
- Ghi chú: nhánh `axios.request({url, baseURL})` ([calls.go:413-420](../internal/jsapi/calls.go#L413-L420)) giữ `x.pre` cũ khi `pre` rỗng; không đổi nhánh đó trong đợt này.

---

## 2. Bước 2 — `R40-B1` (`frontier`, `httpcrawl`, `engine`); `R40-B2` để cuối, tuỳ chọn (bước 5)

### R40-B1. Chặn `OriginSpecPaths` & `specProbePhase2` lan sang Host SDK / IdP / Map / Schema Bên Thứ Ba

#### Hiện trạng & nguyên nhân gốc (tại sao `login.microsoftonline.*` nhận tới 197 request)
1. [frontier/queue.go:459-495](../internal/frontier/queue.go#L459-L495) (`nonAPIInfraDomains`) chưa lọc các tên miền hạ tầng SDK/IdP/bản đồ/schema XML công cộng (`microsoftonline.*`, `chinacloudapi.cn`, `graph.microsoft.com`, `openstreetmap.org`, `mapbox.com`, `googleapis.com`, `reactrouter.com`, `adobe.com`, `xfa.org`...).
2. [frontier/specprobe.go:373-452](../internal/frontier/specprobe.go#L373-L452) (`SpecCollector.Plan`): ghi `st.inScope`, nhưng chỉ dùng để **sort ưu tiên** (`L426`) chứ không chặn host ngoài scope; khi `MaxSpecBases = 0` và `MaxServiceDocPrefixes = 0`, mọi sub-path của `login.microsoftonline.com` (`/common/oauth2/v2.0`, `/organizations/...`) đều vào `plan.Bases` và `plan.Services` rồi nhân bản thành `~197` request/host!
3. [httpcrawl/crawl.go:1599](../internal/httpcrawl/crawl.go#L1599) và bản CDP [engine/specprobe.go:231](../internal/engine/specprobe.go#L231): bật `OriginSpecPaths` cho **mọi** origin root kể cả cross-origin ngoài `InScope`.

#### Đặc tả thay đổi (áp dụng đồng nhất cho cả HTTP lẫn CDP engine)
Lớp chính là **quy tắc scope** (mục 2–3): nó chặn mọi host ngoài scope, kể cả host chưa có trong danh sách nào. Danh sách hạ tầng (mục 1) chỉ là lớp phụ cho probe gốc D2, vì danh sách tên miền không bao giờ đủ.

1. **Mở rộng `nonAPIInfraDomains` ([frontier/queue.go:459](../internal/frontier/queue.go#L459)) — lớp phụ:**
   - Thêm các hạ tầng công cộng không bao giờ chứa OpenAPI của mục tiêu (`mapbox.com` đã có sẵn, không thêm lại):
     - IdP / Cloud SDK công cộng: `microsoftonline.com`, `microsoftonline.us`, `microsoftonline.cn`, `chinacloudapi.cn`, `graph.microsoft.com`, `live.com`, `accounts.google.com`, `appleid.apple.com`, `login.salesforce.com`.
     - Bản đồ / Tile / Geocoding: `openstreetmap.org`, `maplibre.org`, `tileserver.org`, `mt0.google.com`, `mt1.google.com`, `mt2.google.com`, `mt3.google.com`, `googleapis.com`.
     - Tài liệu thư viện / XML Namespace: `reactrouter.com`, `reactjs.org`, `react.dev`, `vuejs.org`, `angular.io`, `mozilla.org`, `adobe.com`, `xfa.org`, `xmlsoap.org`, `json-schema.org`, `ietf.org`, `purl.org`.
   - Bộ lọc dùng chung là `isStaticOrNonAPIHost` ([queue.go:524](../internal/frontier/queue.go#L524), không export; đã gọi `IsTrackerHost`). Nó đang được gọi ở `APIOrigins` ([queue.go:557](../internal/frontier/queue.go#L557)) — nguồn của `cr.apiOrigins` ở cả hai engine — và ở `normalizeSpecBase`/`resolveEndpointPath` ([specprobe.go:569, 609](../internal/frontier/specprobe.go#L569)). Không cần thêm điểm lọc mới; không tạo hàm `IsNonAPIInfraHost`.
2. **Khoá phạm vi nhân bản trong `SpecCollector.Plan` ([frontier/specprobe.go:365-545](../internal/frontier/specprobe.go#L365-L545)):**
   - **Quy tắc rõ ràng cho `inScope != nil`:**
     - `plan.Bases` (gateway sub-paths) và `plan.Services` (`ServiceDocPaths`) **chỉ sinh cho các URL có `inScope(u.Hostname()) == true`**. Không bao giờ nhân bản sub-path hoặc `ServiceDocPaths` lên host ngoài `inScope` (triệt tiêu hoàn toàn vụ `197` request sang IdP/partner SDK).
   - **Bảo toàn quyết định `D2`:** Một API origin cross-origin sạch (ví dụ `example-api.com`, không thuộc `trackerDomains`/`nonAPIInfraDomains`) vẫn được phép probe nhẹ 1 lần ở origin root qua `cr.apiOrigins` (`SpecPaths` chuẩn, không nhân sub-path và không cộng `OriginSpecPaths`).
   - **Sửa sau triển khai (40.1):** khoá cứng `plan.Bases` theo `inScope` làm mất probe stage của API trên hạ tầng cloud (`execute-api …/prod`, `workers.dev/v1`). Quy tắc chốt: host ngoài scope nhận `SpecPaths` ở gốc và ở tối đa 2 base do code đặt tên (`Result.Bases`); không base suy ra, không `OriginSpecPaths`, không `Services`. Xem `plan-40.md`.
   - **Đánh đổi đã chấp nhận với `-scope fqdn`:** `fqdn` = host target và subdomain của nó. Chạy trên `www.example.com` thì `api.example.com` là ngoài scope, nên gateway anh em chỉ còn probe gốc D2, mất probe sub-path/service. Không nới quy tắc thành "cùng RDN", vì `-scope` là giới hạn người dùng chọn cho nơi request được gửi tới. Muốn probe đủ thì chạy `-scope rdn`. Ghi đánh đổi này vào `CURRENT.md` ở R40-D.
3. **Giới hạn `OriginSpecPaths` theo `inScope` ở cả 2 engine:**
   - [httpcrawl/crawl.go:1599](../internal/httpcrawl/crawl.go#L1599): đổi điều kiện thành `(u.Path == "" || u.Path == "/") && !cr.spa[orig] && (cr.o.InScope == nil || cr.o.InScope(u.Hostname()))`.
   - [engine/specprobe.go:231](../internal/engine/specprobe.go#L231): đổi điều kiện thành `bu != nil && (bu.Path == "" || bu.Path == "/") && (e.cfg.InScope == nil || e.cfg.InScope(bu.Hostname()))`.

---

### R40-B2. Đánh dấu Soft-`200` SPA Fallback HTML trong `http.soft_probes` (giữ `http.probes`)

#### Hiện trạng & kiểm chứng thứ tự gọi
- Đã kiểm chứng tại [crawl.go:2031-2040](../internal/httpcrawl/crawl.go#L2031-L2040): `cr.spaCheck` chạy **ngay trước** `cr.probe(ctx, probeURL)`, do đó `cr.spa[orig]` và `cr.prints[orig]` đã sẵn sàng ở cả 3 điểm ghi `st.Probes[key] = a.Status`:
  1. [crawl.go:1347](../internal/httpcrawl/crawl.go#L1347) (`probe()` — `robots.txt`, `sitemap.xml`, manifests, deep-link well-knowns)
  2. [crawl.go:1575](../internal/httpcrawl/crawl.go#L1575) (`specProbeWithScope()`)
  3. [crawl.go:1792](../internal/httpcrawl/crawl.go#L1792) (`specProbePhase2()` nhánh `plan.Services`)
- Đã kiểm chứng toàn bộ test hiện có: chỉ duy nhất [crawl_test.go:349](../internal/httpcrawl/crawl_test.go#L349) assert `res.Stats.Probes["/robots.txt"] != 200` (trên phản hồi `text/plain` thật, không bị ảnh hưởng).

- **Bổ sung v2:** ngoài crawl_test.go:349, [pipeline_test.go:83](../internal/httpcrawl/pipeline_test.go#L83) dùng **key** của `Probes` để biết host API nào đã được probe. Vì vậy key phải được giữ: `Probes` trả lời câu hỏi "đã gửi probe tới đâu". Trong mã sản phẩm không có nơi nào đọc `Probes` (chỉ là telemetry trong `run.json`), nên mục này để ưu tiên thấp, tuỳ chọn.

#### Đặc tả thay đổi
1. Thêm trường `SoftProbes []string \`json:"soft_probes,omitempty"\`` vào `httpcrawl.Stats`: các key của `Probes` mà phản hồi là soft-200 SPA fallback, giới hạn 64 phần tử (vượt thì chỉ tăng thêm `SoftProbesMore int \`json:"soft_probes_more,omitempty"\``).
2. Viết helper dùng chung `(cr *crawler) recordProbeStatus(key, targetURL, pathHint string, a answer)`:
   - Xác định `isSoftSPA`:
     - Chỉ xét khi `a.Err == nil && a.Status >= 200 && a.Status < 300 && len(a.Body) > 0`.
     - Kiểm tra `htmlBody := strings.Contains(ct, "html") || htmlLike(a.Body)`.
     - Nếu `!htmlBody` → không phải soft-200 SPA.
     - **Ngoại lệ HTML hợp lệ (không coi là soft-200):** nếu `pathHint == "/api/documentation"` (hoặc URL doc HTML) mà `len(jsapi.SwaggerUIURLs(a.Body)) > 0` → ghi `st.Probes[key] = a.Status` bình thường.
     - Ngược lại, coi là soft-200 SPA fallback khi **một trong hai** đúng:
       1. Origin đã xác nhận SPA (`cr.spa[orig] && cr.prints[orig] != ""`) và `shellPrint(htmlscan.Scan(a.Body[:min(len(a.Body), 64<<10)], a.URL)) == cr.prints[orig]`; **hoặc**
       2. `targetURL`/`pathHint` là đường dẫn kỳ vọng phi-HTML (`.json`, `.yaml`, `.yml`, `.xml`, `.txt`, `.well-known/*`, `/v2/api-docs`, `/v3/api-docs`, `/api-json`, `/docs-json`, `/swagger-resources`) nhưng trả về `htmlBody == true`.
   - Luôn ghi `st.Probes[key] = a.Status` như cũ (giữ thông tin "đã gửi").
   - Khi `isSoftSPA == true`: thêm `key` vào `st.SoftProbes` (trong cùng `cr.count`).
3. Gọi `cr.recordProbeStatus(...)` tại cả 3 điểm ([crawl.go:1347](../internal/httpcrawl/crawl.go#L1347), [L1575](../internal/httpcrawl/crawl.go#L1575), [L1792](../internal/httpcrawl/crawl.go#L1792)).
   - **Thread-safety (đã kiểm, không cần khoá thêm):** `cr.spa` chỉ được ghi trong `spaCheck` ([crawl.go:571](../internal/httpcrawl/crawl.go#L571)) và `cr.prints` trong `commitPage` ([crawl.go:988](../internal/httpcrawl/crawl.go#L988)), cả hai trên goroutine commit. `probe()` và `specProbe` sớm ([crawl.go:1420](../internal/httpcrawl/crawl.go#L1420), gọi bên trong `probe()`) cũng chạy trên goroutine đó; `L1575`/`L1792` chạy sau `cr.pages()` nên chỉ đọc. Dòng [1599](../internal/httpcrawl/crawl.go#L1599) hiện đã đọc `cr.spa[orig]` ở đúng các ngữ cảnh này. Vẫn chạy `go test -race`.

---

## 3. Bước 3 — `R40-A3` (`internal/verify`): Mở rộng Ứng viên API Base cho Decoupled SPA

**Điều kiện bắt đầu:** làm sau A1+A2. Sau A2, các lời gọi `axiosInstance.get(path, { baseURL })` có `Base` riêng và không còn rơi vào nhánh `case l.Origin != ""`. Trước khi viết A3, chạy lại `endpoints` trên dữ liệu đã có (offline, không gửi request) và đếm số dòng API còn lại có `l.Origin` thuộc `spa_origins` mà không có `Base`/`Bases`/`Host`. Nếu con số không đáng kể thì hoãn A3.

#### Hiện trạng & 3 ràng buộc thiết kế đã kiểm chứng
1. [endpoints.go:948](../internal/endpoints/endpoints.go#L948) (`ep.Origin = pageOrigin(ep, inScope)`) gắn origin của trang SPA chứa script cho các endpoint đường dẫn tương đối (`kind: "wrapper"`, `"client"`, `"fetch"`, `"xhr"`, `"options"`). **Giữ nguyên** `ep.Origin` trong `endpoints.jsonl` để không làm mất provenance và không phá test `internal/endpoints`.
2. [verify/draft.go:223-265](../internal/verify/draft.go#L223-L265) (`Inputs` & `Load`): hiện chỉ đọc `endpoints.jsonl`, `intel.json`, `historical.jsonl`, **chưa đọc `run.json` (`http.spa_origins`)**.
3. [verify/verify.go:518-563](../internal/verify/verify.go#L518-L563) (`one()`): với draft nhiều ứng viên (`d.URL == ""` và `len(d.Candidates) > 1`), vòng lặp chỉ `return` sớm khi gặp `Alive` hoặc `Resource404`, **không** dừng sớm khi gặp `AuthWallOpaque` (`401` sau Kong Gateway). Tuy nhiên `verify` đã có **`isSpecBasePruned(candBase)` / `noteSpecBase(candBase, d.Path, res.Verdict)`** tại [verify.go:533-545](../internal/verify/verify.go#L533-L545). Nếu `l.Origin` nằm trong `d.CandidateBases`, nó bị cắt tỉa khi đã có **16 path khác nhau** trả `DeadOrFP` (`specBasePruneAfter = 16`, [verify.go:395](../internal/verify/verify.go#L395)) và **chưa có tín hiệu nào** (`Alive`, `Resource404`, `ServerError`, `AuthWall`, `WAFBlocked`). Sau đó các draft khác bỏ qua `l.Origin` (trừ khi nó là ứng viên cuối cùng còn lại). Chi phí thừa trên SPA frontend vì vậy là khoảng 16 request mỗi origin, không phải 532.
4. Vòng lặp ứng viên trong `one()` **dừng ngay** ở `Alive` hoặc `Resource404` đầu tiên ([verify.go:550](../internal/verify/verify.go#L550)). Vì vậy thứ tự ứng viên quyết định base được chốt.

#### Đặc tả thay đổi
1. **Nạp `SPAOrigins` trong `verify.Inputs` ([draft.go:223-253](../internal/verify/draft.go#L223-L253)):**
   - Thêm `SPAOrigins []string` vào `struct Inputs`.
   - Trong `Load(roleDir, archiveDir string, historical bool)`: đọc tùy chọn `filepath.Join(roleDir, "run.json")` (nếu file tồn tại), parse tối thiểu `struct { HTTP *struct { SPAOrigins []string \`json:"spa_origins"\` } \`json:"http"\` }`, chuẩn hóa lowercase + bỏ dấu `/` cuối, lưu vào `in.SPAOrigins`. Thiếu `run.json` hoặc parse lỗi không báo lỗi (tương thích hoàn toàn với các test/pipeline chỉ có `endpoints.jsonl`).
2. **Mở rộng ứng viên có kiểm soát trong `draftOfWithLangs` ([draft.go:602-604](../internal/verify/draft.go#L602-L604)):**
   - Tại nhánh `case l.Origin != "":`:
     - Kiểm tra điều kiện **Decoupled SPA**:
       1. `isAPICallKind(l.Kind)`: `l.Kind` thuộc `{"client", "wrapper", "fetch", "xhr", "options"}` (tuyệt đối **loại trừ** `"navigation"`, `"string"`, `"doc"`, `"beacon"`, `"websocket"`, `"sse"`).
       2. `isSPAOrigin(l.Origin, in.SPAOrigins)` là `true`.
       3. Lọc các base tuyệt đối (`http://` / `https://`) từ `bases` (đã qua lọc `inScope` ở `targetBases`) có **origin khác** `l.Origin` (gọi là `extBases`).
     - Nếu `len(extBases) == 0` (ví dụ: không phải SPA, hoặc Nginx reverse-proxy SPA chỉ có 1 origin duy nhất): **giữ nguyên 100%** hành vi cũ `target = strings.TrimRight(l.Origin, "/") + l.Path`.
     - Nếu `len(extBases) > 0`:
       - Tạo danh sách `d.Candidates` / `d.CandidateBases` theo thứ tự **dựa trên bằng chứng của chính verify**:
         1. `l.Origin` **đứng đầu** (kèm `CandidateBases` ghi đúng `l.Origin`).
         2. Sau đó các `extBases` (ví dụ `https://api.staging.example.test`).
       - Lý do không đặt `extBases` lên trước (khác v1): vòng lặp dừng ở `Alive`/`Resource404` đầu tiên. Với SPA reverse-proxy, nếu host API trả 404 của riêng nó (khác canary) cho `/api/local`, base sai sẽ bị chốt và origin SPA không bao giờ được thử.
       - Cách thứ tự này tự thích nghi, không cần cơ chế mới:
         - **SPA tách rời:** origin SPA trả shell → `DeadOrFP` (shell đã học qua `rootCanary`) → vòng lặp thử tiếp `extBases`. Sau 16 path chết không tín hiệu, `isSpecBasePruned(l.Origin)` đúng, và các draft sau bỏ qua `l.Origin` (vì `i < len(targets)-1`), nên `extBases` thực tế thành ứng viên đầu.
         - **SPA reverse-proxy / hỗn hợp:** route sống trên origin SPA cho tín hiệu → `l.Origin` không bao giờ bị cắt → mọi draft thử origin SPA trước, đúng ngữ nghĩa. Chi phí tối đa là 1 request thêm cho mỗi draft trước các `extBases`.
3. **Kiểm tra tác động phụ tới `export -drafts` & `Draft.Tier` ([draft.go:741-754](../internal/verify/draft.go#L741-L754)):**
   - Khi `d.URL == ""` và `len(d.Candidates) > 1`, `d.Tier` sẽ là `Incomplete` trước khi `verify`, và sau khi `verify` xác nhận `Alive` / `Resource404` trên `extBase`, `res.VerifiedBase` ghi rõ API base đúng để `export -drafts` xuất ra URL chuẩn.
   - Với `AuthWallOpaque` (`401` từ gateway), `one()` chọn `best` theo `verdictRank` ([verify.go:556-565](../internal/verify/verify.go#L556-L565)): `AuthWallOpaque` có rank cao hơn `DeadOrFP`, nên kết quả cuối cùng báo `auth_wall_opaque` với `Target` trên host API thay vì `dead_or_fp` của SPA frontend. Lưu ý `AuthWallOpaque` **không** tính là tín hiệu trong `noteSpecBase`, nên không cản việc cắt tỉa `l.Origin`.
   - **Giới hạn nổ ứng viên:** nếu `extBases` có nhiều hơn 8 base, chỉ giữ base cấp origin (`path == ""` hoặc `"/"`) rồi lấy tiếp theo thứ tự trong `intel.Bases`, tối đa 8. Hằng số đặt tên riêng, không dùng chung `maxCandidates` (đang là `0` = không giới hạn).

---

## 4. Bước 4 — `R40-B3` (`internal/engine`) & Tài liệu (`R40-D`)

### R40-B3. Khối `totals` trong `run.json` sau `Escalated` và `SPABoot`

#### Hiện trạng (đã kiểm chứng trên mã nguồn)
1. [escalate.go:29-38](../internal/engine/escalate.go#L29-L38): `EscalatedRun` hiện **chưa có** các trường `Requests`, `PageRequests`, `InternalRequests`, mặc dù `rec` trả về từ `RunRecord` tại [escalate.go:135](../internal/engine/escalate.go#L135) và [escalate.go:193](../internal/engine/escalate.go#L193) đã có đủ các số đếm này.
2. [http.go:365-368, 397-417](../internal/engine/http.go#L365-L417): `run.UniqueScripts = st.Len()` lấy từ store trong RAM của pha HTTP, nên không tính các script mà run Chrome (`Escalated`/`SPABoot`) ghi thêm vào `index.jsonl` sau đó.

#### Ràng buộc ngữ nghĩa (lý do bỏ cách "cộng dồn" của v1)
- Mỗi run Chrome là **một run riêng**, có `run_id` và dòng riêng trong `runs.jsonl`. Doc của `Record.Escalated` ([engine.go:265-266](../internal/engine/engine.go#L265-L266)) ghi rõ điều này, và pipecheck (e) kiểm `-spa-boot` cho đúng 2 dòng `runs.jsonl`.
- Các dòng trong `requests.jsonl` mang `run` = `run_id`. `run.Requests` của run HTTP phải khớp số dòng có `run_id` của chính nó.
- `results.Finished` ([results.go:381](../internal/results/results.go#L381)) đọc `requests` của từng dòng `runs.jsonl`. Cộng request của Chrome vào dòng HTTP sẽ **đếm trùng** khi cộng qua các run.
- `monitor` coi run `mode: "http"` có `scripts` là baseline ([monitor/runs.go:53](../internal/monitor/runs.go#L53)). Gộp script của Chrome vào sẽ làm baseline đổi theo việc lần đó có gặp challenge hay không.

#### Đặc tả thay đổi
1. **Mở rộng `EscalatedRun` ([escalate.go:29-38](../internal/engine/escalate.go#L29-L38)):**
   ```go
   Requests         int `json:"requests,omitempty"`
   PageRequests     int `json:"page_requests,omitempty"`
   InternalRequests int `json:"internal_requests,omitempty"`
   ```
   Điền từ `rec` tại cả `Escalate` (escalate.go:135) lẫn `SPABoot` (escalate.go:193).
2. **Khối `totals` mới trong `Record`** (`Totals *RunTotals \`json:"totals,omitempty"\``), chỉ đặt khi có ít nhất một run Chrome:
   ```go
   type RunTotals struct {
       Requests         int `json:"requests"`          // run HTTP + mọi run Chrome
       PageRequests     int `json:"page_requests"`
       InternalRequests int `json:"internal_requests"`
       NewScripts       int `json:"new_scripts"`
       Runs             []string `json:"runs"`          // run_id của các run Chrome đã cộng
   }
   ```
   Cộng từ `run.*` của run HTTP và từng `EscalatedRun` (trong `run.Escalated.Runs` và `run.SPABoot`).
3. **`run.UniqueScripts`** là số của cả thư mục, không phải của riêng run, nên được cập nhật: `st.Len() + Σ er.NewScripts`. Run Chrome ghi vào cùng thư mục (`c.OutHost`, [escalate.go:116](../internal/engine/escalate.go#L116)) và mở store sau khi pha HTTP đã `Flush` ([http.go:357](../internal/engine/http.go#L357)), nên `isNew` của nó được tính so với `index.jsonl` đã có script của HTTP. Như vậy phép cộng không trùng và không cần mở lại store. Test ở bước 4 phải xác nhận `unique_scripts` bằng số SHA khác nhau trong `index.jsonl`.
4. **Giữ nguyên** `run.Requests`, `run.PageRequests`, `run.InternalRequests`, `run.Scripts`, `run.NewScripts` của run HTTP.
5. Dòng log `done` ([http.go:483](../internal/engine/http.go#L483)) in thêm `total_requests` khi có `totals`.
- **Bất biến:** khi không có `Escalated` hay `SPABoot`, `run.json` không đổi một byte. Khi có, `totals.page_requests + totals.internal_requests == totals.requests`, và `run.requests` vẫn bằng số dòng `requests.jsonl` có `run_id` của run HTTP.

### R40-D. Cập nhật Tài liệu (cuối Đợt 40)
- Tạo `docs/plan-40.md` (hoặc chuyển trạng thái tài liệu này khi xong).
- Cập nhật [docs/CURRENT.md](CURRENT.md):
  - Bổ sung tóm tắt Đợt 40 vào Mục `1b` và bump `jsapi.Version = 46`.
  - Cập nhật số liệu `perfgate` thực đo sau Đợt 40 trên Linux (thay số cũ thời Đợt 34 ở dòng 10).
  - Bổ sung `waf-check.sh` vào danh sách gate ở dòng 11.
  - Ghi đánh đổi `-scope fqdn` của B1 (gateway anh em ngoài scope chỉ còn probe gốc D2).
  - Ghi khối `totals` của B3 và quy ước "số liệu của run HTTP chỉ là của riêng nó".
- Cập nhật [docs/rounds-history.md](rounds-history.md).
- Cập nhật `CLAUDE.md`: mục **jsapi** đang ghi "hiện `40`", sửa thành `46`; thêm `totals` vào mô tả `run.json` nếu cần.

---

## 5. Ma trận Kiểm thử & Cổng Kiểm chứng Bắt Buộc

### 1. Unit & Regression Tests (tuân thủ `internal/testlint` — không ghi biến capture chưa khoá trong `httptest` handler)
- **Bước 1 (`internal/jsapi/round40_test.go`):**
  1. `TestRound40ViteEnvObjectLiteralDestructuring`: inline `const { VITE_BASE_API_DOMAIN, VITE_BASE_SAP_DECRYPT_PUBLIC_KEY, VITE_BASE_SAP_DECRYPT_PUBLIC_KEY_LAO } = { ... }` + template `` `${VITE_BASE_API_DOMAIN}/account/v1/public` `` + biến thể bọc ngoặc / `Object.freeze({...})` → kiểm tra `ACCOUNT_API_URL` giải đầy đủ (không có `{}`), `Result.Bases` chứa `https://api.staging.example.test` (không chứa `media-static`), `Result.Keys` bắt đủ cả `_PUBLIC_KEY` lẫn `_PUBLIC_KEY_LAO` và **không** bắt nhầm `public_key_id` / `api_key_name` / `TOKEN_TYPE = "Bearer"` / `API_KEY_LAO = "enabled"`.
  2. `TestRound40DestructureDefaultIsFallbackOnly`: (a) `const { API_URL = "https://fallback.example.test" } = { API_URL: "https://api.example.test" }` → chỉ ra `https://api.example.test`; (b) cùng mẫu với object không có `API_URL` → ra giá trị default; (c) `function f(e){ const { apiBase = "/x" } = e; … } f({ apiBase: "/real" })` → vẫn ra `/real` qua `fromCallersOf` (v1 sẽ trượt ca này).
  3. `TestRound40AxiosClientMethodPerRequestBaseURL`: `axiosInstance.get("/supplier/profile", { baseURL: ACCOUNT_API_URL })` và `axiosInstance.post("/orders", payload, { baseURL: MISSION_API_URL })` (kể cả khi `axiosInstance` có `baseURL` mặc định khác, khi `{ baseURL: dynVar }` và khi `{ baseURL: "/" }`) → kiểm tra URL đầy đủ, `ep.Client`, và `ep.BaseKeys` **không** chứa khoá `client:` của instance.
- **Bước 2 (`internal/frontier/round40_test.go`, `internal/httpcrawl/round40_test.go`, `internal/engine/round40_test.go`):**
  1. `TestRound40SpecProbeBlocksThirdPartySDKAndLimitsOriginSpecPaths`: bundle chứa URL tới `login.microsoftonline.com/common/oauth2/v2.0`, `nominatim.openstreetmap.org/search`, `reactrouter.com/docs` + 1 API cross-origin sạch (`api-partner.example.net`) + 1 subdomain `inScope` → kiểm tra **0 request** tới SDK/IdP/map; `SpecCollector.Plan` không sinh `plan.Bases`/`plan.Services` cho host ngoài `inScope`; `OriginSpecPaths` chỉ chạy cho host `inScope` (cả HTTP lẫn CDP); host ngoài scope **chưa có trong danh sách hạ tầng** cũng không bị nhân sub-path (chứng minh lớp chính là quy tắc scope).
  2. `TestRound40ScopeFqdnSiblingGatewayRootOnly`: seed `www.example.test` với `-scope fqdn`, bundle gọi `https://api.example.test/gw/auth/v1/...` → `api.example.test` chỉ nhận `SpecPaths` ở gốc (D2), không nhận probe sub-path/service; với `-scope rdn` thì nhận đủ.
  3. (Bước 5, tuỳ chọn) `TestRound40Soft200SPAShellMarkedInSoftProbes`: SPA trả `200 text/html` shell cho `/.vite/manifest.json`, `/openapi.json`, `/robots.txt` → các key vẫn có trong `res.Stats.Probes`, đồng thời có trong `res.Stats.SoftProbes`; `/robots.txt` (`text/plain`) và `/api/documentation` (Swagger UI HTML có URL spec thật) **không** nằm trong `SoftProbes`. `pipeline_test.go` vẫn qua.
- **Bước 3 (`internal/verify/round40_test.go`):**
  1. `TestRound40DecoupledSPAVerifiesAgainstIntelBases`: `run.json` có `spa_origins: ["https://portal.example.test"]`, `intel.json` có `bases: ["https://api.example.test"]`, endpoint `wrapper` có `origin: "https://portal.example.test"`, `path: "/v1/orders"` → SPA trả `200 text/html` shell, API Gateway trả `401` JSON (và 1 route trả `200` JSON) → kiểm tra `verify` xác nhận đúng `auth_wall_opaque` / `verified_alive` trên `api.example.test`, và `l.Origin` bị `isSpecBasePruned` cắt tỉa sớm thay vì bị bắn lặp lại; route `kind: "navigation"` **không** bị ghép sang `api.example.test`.
  2. `TestRound40ReverseProxySPAPreservesSameOrigin`: SPA có cả `api.example.test` lẫn `/api/local` phục vụ ngay trên chính origin SPA, và `api.example.test` trả **404 JSON của riêng nó** (khác canary) cho `/api/local` → kiểm tra `/api/local` vẫn `verified_alive` trên origin SPA, với `VerifiedBase` là origin SPA (ca này thất bại nếu đặt `extBases` lên trước như v1).
  3. `TestRound40SPAOriginPrunedAfter16DeadPaths`: 20 draft tách rời trên cùng origin SPA → số request tới origin SPA ≤ 16 (+ canary), các draft sau đi thẳng tới host API.
- **Bước 4 (`internal/engine/round40_test.go`):**
  1. `TestRound40RunJSONTotalsAfterEscalateAndSPABoot`: giả lập `ho.Escalate` và `ho.SPABoot` ghi thêm script vào `index.jsonl` và trả `EscalatedRun` có `Requests`/`PageRequests`/`InternalRequests`/`NewScripts` → kiểm tra:
     - `run.json` có `totals` với tổng đúng, và `totals.page_requests + totals.internal_requests == totals.requests`;
     - `requests`, `page_requests`, `internal_requests`, `scripts`, `new_scripts` của run HTTP **không đổi** so với khi không có Chrome;
     - `unique_scripts` bằng số SHA khác nhau trong `index.jsonl`;
     - không có Chrome → `run.json` không có `totals`, giống hệt trước một byte.
  2. pipecheck (e)/(f) vẫn qua: `-spa-boot` cho 2 dòng `runs.jsonl`, và `page_requests + internal_requests == requests` trên run HTTP.

### 2. Cổng Kiểm chứng Bắt Buộc (theo bảng gate trong `CLAUDE.md`; chạy tuần tự, không chạy song song nhiều `testbed/*-check.sh`)
1. **jsapi (bước 1):** so snapshot với HEAD đúng quy trình trong `CLAUDE.md`: chạy `JSAPI_SNAPSHOT=<file tuyệt đối> go test -v -run TestSnapshot ./internal/jsapi | grep '^SNAP' | md5sum` trên HEAD và trên nhánh sửa. Output chỉ được khác ở các chỗ A1/A2 định sửa; rà từng khác biệt. Sau đó chạy `JSAPI_STATS=list go test -run TestStats ./internal/jsapi` để xem nhiễu.
2. `go vet ./...`
3. `go test -race -count=1 ./cmd/... ./internal/...` (bao gồm `internal/testlint`).
4. Build lại `./bin/jsharvest` và chạy tuần tự theo vùng đã sửa:
   - Bước 1 (`internal/jsapi`): `./testbed/endpoints-check.sh` + `./bin/testbed perfgate -bin ./bin/jsharvest` (`<= 15.0 s`, `<= 500.0 MB`).
   - Bước 2 (`internal/frontier`, `httpcrawl`, `engine/specprobe.go`): `./testbed/frontier-check.sh` (và `testbed/external/run.sh` trước khi chốt bước), `./testbed/pipeline-check.sh`, `./testbed/waf-check.sh`.
   - Bước 3 (`internal/verify`, base khác origin): `./testbed/verify-check.sh` + `./testbed/crosscheck-check.sh`.
   - Bước 4 (`engine/http.go`, `escalate.go`): `./testbed/pipeline-check.sh` (kiểm (e)/(f)) + `./testbed/monitor-check.sh` (`runs.jsonl`).
   - `archive-check.sh` không bắt buộc: đợt này không sửa `internal/archive`.
