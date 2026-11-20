# Đợt 40: Độ phủ Vite/Axios (`jsapi` v46), Khoá Scope `specProbe`, Decoupled SPA `verify`, `run.json` `totals` & `soft_probes`

**Ngày:** 2026-11-20 · **Nền mã nguồn:** `83c308f` (sau Đợt 39) · **Trạng thái:** đã triển khai đầy đủ theo đặc tả v2 ([backlog-round40.md](backlog-round40.md)).

**Nguyên tắc bất biến:** Zero Band-Aids — không cắt recall trên reverse-proxy SPA cùng origin, khoá cứng phạm vi nhân bản `specProbe` theo `inScope` (vẫn giữ probe gốc D2 cho API cross-origin sạch), giữ nguyên `ep.Origin` trong `endpoints.jsonl` và số liệu per-run của run HTTP trong `run.json`, bump `jsapi.Version` (`45 -> 46`), không đưa tên mục tiêu thật vào tài liệu/test.

| Bước | Mã | Vùng | Tóm tắt |
|---|---|---|---|
| **1** | **R40-A1 + A2** | `internal/jsapi` (`jsapi.go`, `defs.go`, `eval.go`, `calls.go`, `strings.go`) | Giải destructuring trực tiếp từ `*js.ObjectExpr` (Vite `import.meta.env`) với `destructDefault` fallback riêng; thêm `"domain"` vào `isBaseName`; hỗ trợ hậu tố vùng/env viết HOA sau key hằng (`keyNameMatch` + `strongKeyValue`); nối `{ baseURL }` cấp request ở `clientMethods` kèm `x.reqBase` không trộn `client:` của instance; bump `jsapi.Version = 46` |
| **2** | **R40-B1** | `internal/frontier` (`queue.go`, `specprobe.go`), `internal/httpcrawl` (`crawl.go`), `internal/engine` (`specprobe.go`) | Khoá `SpecCollector.Plan` (`plan.Bases`/`plan.Services`) và `OriginSpecPaths` (cả HTTP lẫn CDP) chỉ cho host `inScope`; mở rộng `nonAPIInfraDomains` (`isStaticOrNonAPIHost`) làm lớp phụ chặn IdP/SDK/map/schema XML |
| **3** | **R40-A3** | `internal/verify` (`draft.go`) | Nạp tùy chọn `http.spa_origins` từ `run.json`; mở rộng ứng viên `[l.Origin, extBases...]` (tối đa `maxDecoupledSPABases = 8`) cho API tương đối trên origin SPA, ưu tiên `l.Origin` trước để bảo vệ reverse-proxy SPA và tự cắt tỉa `l.Origin` sau `16` path chết (`specBasePruneAfter`) trên decoupled SPA |
| **4** | **R40-B3** | `internal/engine` (`escalate.go`, `engine.go`, `http.go`) | Bổ sung `Requests`/`PageRequests`/`InternalRequests` vào `EscalatedRun`; thêm khối `totals` (`RunTotals`) vào `run.json` và cập nhật `unique_scripts = st.Len() + Σ er.NewScripts` trong khi **giữ nguyên** số liệu riêng của run HTTP |
| **5** | **R40-B2** | `internal/httpcrawl` (`crawl.go`) | Giữ nguyên `http.probes[key]` (bảo vệ tương thích & telemetry "đã gửi") và đánh dấu phản hồi soft-200 SPA fallback HTML vào `http.soft_probes` (trần 64) + `http.soft_probes_more` (ngoại lệ cho Swagger UI HTML thật) |
| **6** | **R40-D** | `docs/`, `CLAUDE.md` | Tạo `docs/plan-40.md`, cập nhật `docs/CURRENT.md`, `docs/rounds-history.md`, `docs/backlog-round40.md`, `CLAUDE.md` |

---

## 1. Bước 1 — `R40-A1` & `R40-A2` (`internal/jsapi`, `Version = 46`)

- **Destructuring từ Object Literal & Default Fallback ([defs.go](../internal/jsapi/defs.go), [eval.go](../internal/jsapi/eval.go), [calls.go](../internal/jsapi/calls.go)):**
  - `evalVar` gọi `x.object(x.destructFrom[v])` trực tiếp (hỗ trợ `*js.ObjectExpr`, `(...)`, `Object.freeze({...})`, `*js.Var`), fallback sang `fromCallersOf` khi `src` là `*js.Var`, và chỉ dùng map riêng `destructDefault[v]` khi cả object lẫn caller đều không có thuộc tính.
  - `baseKeysOf` mở rộng phân giải `objectValue` trên `destructFrom` là object literal.
- **`isBaseName` & Hậu tố vùng/env cho khoá hằng ([jsapi.go](../internal/jsapi/jsapi.go)):**
  - Thêm `"domain"` vào nhánh `strings.Contains(n, "api") && has(...)` của `isBaseName` (tận dụng `defs.go:343`, 0 lượt duyệt AST thêm).
  - `keyNameMatch` cắt hậu tố `_[A-Z]{2,5}` trên tên `UPPER_SNAKE_CASE` (loại trừ tập metadata `ID`, `TYPE`, `NAME`, `URL`...); các tên chỉ khớp qua hậu tố phải đạt `strongKeyValue` (PEM, hex `>= 32`, hoặc base64/base64url `>= 16` có cả chữ lẫn số).
- **`{ baseURL }` cấp request cho `clientMethods` ([calls.go](../internal/jsapi/calls.go), [strings.go](../internal/jsapi/strings.go)):**
  - Đọc `o.base` qua `x.optBasePre(o.base)` ở nhánh `axiosInstance.get/post/...`, ghi đè `x.pre` của instance theo đúng ngữ nghĩa `axios`, và bật cờ nội bộ `x.reqBase` để `addOne` không nối thêm `client:` keys của instance.
- **Kiểm chứng:** 3 test mới trong [round40_test.go](../internal/jsapi/round40_test.go); so `TestSnapshot` trên 2.568 file corpus với HEAD: `0` sai lệch `endpoints`/`bases`/`keys`/`routes` (chỉ 7 file dịch chuyển `line`/`col` trong `imports` do `destructDefault`); `endpoints-check.sh` PASS; `perfgate`: `10.44s–11.68s, peak RSS 353.8–355.9 MB` (`<= 15.0s, <= 500.0 MB`).

---

## 2. Bước 2 — `R40-B1` (Khoá Scope `specProbe` & Lọc SDK/IdP Bên Thứ Ba)

- **Lớp chặn chính (Scope):**
  - [specprobe.go](../internal/frontier/specprobe.go): `SpecCollector.Plan` lọc `inScope` trong cả `noteBase` và `addSvc` — không bao giờ sinh `plan.Bases` hay `plan.Services` cho host ngoài scope.
  - [crawl.go](../internal/httpcrawl/crawl.go) & [engine/specprobe.go](../internal/engine/specprobe.go): chỉ chạy `OriginSpecPaths` khi `inScope(host)` là `true` trên cả HTTP lẫn CDP engine.
  - Vẫn bảo toàn quyết định `D2`: API cross-origin sạch (ngoài `nonAPIInfraDomains`) vẫn được probe gốc nhẹ bằng `SpecPaths`.
  - **Đánh đổi với `-scope fqdn`:** chạy trên `www.example.test` với `-scope fqdn` thì gateway anh em `api.example.test` nằm ngoài scope, chỉ còn probe gốc D2 (muốn probe đủ sub-path/service hãy chạy `-scope rdn`).
- **Lớp chặn phụ (Hạ tầng công cộng):** mở rộng `nonAPIInfraDomains` trong [queue.go](../internal/frontier/queue.go) (dùng bởi `isStaticOrNonAPIHost`) thêm các host IdP/cloud SDK (`microsoftonline.*`, `chinacloudapi.cn`, `graph.microsoft.com`, `live.com`...), bản đồ/tile (`openstreetmap.org`, `maplibre.org`, `googleapis.com`...), tài liệu/schema XML (`reactrouter.com`, `adobe.com`, `xfa.org`...).
- **Kiểm chứng:** [frontier/round40_test.go](../internal/frontier/round40_test.go), [httpcrawl/round40_test.go](../internal/httpcrawl/round40_test.go), [engine/round40_test.go](../internal/engine/round40_test.go).

---

## 3. Bước 3 — `R40-A3` (Decoupled SPA `verify`)

- [verify/draft.go](../internal/verify/draft.go):
  - `verify.Inputs` thêm `SPAOrigins []string`, nạp tùy chọn từ `run.json` (`http.spa_origins`) trong `Load()`.
  - Trong `draftOfWithLangs` nhánh `case l.Origin != ""`: nếu là lời gọi API (`client`, `wrapper`, `fetch`, `xhr`, `options`), `l.Origin` thuộc `SPAOrigins`, và có base tuyệt đối `inScope` khác origin (`decoupledSPABases`, trần `maxDecoupledSPABases = 8`), mở rộng thành `d.Candidates` theo thứ tự `[l.Origin, extBases...]`.
  - **Tự thích nghi theo bằng chứng `verify`:** reverse-proxy SPA giữ nguyên `VerifiedBase = l.Origin` (không bị host API trả 404 riêng chiếm trước); decoupled SPA cắt tỉa `l.Origin` sau 16 path chết (`specBasePruneAfter`) để các draft sau đi thẳng tới API host.
- **Kiểm chứng:** 3 test trong [verify/round40_test.go](../internal/verify/round40_test.go); `verify-check.sh` & `crosscheck-check.sh` PASS.

---

## 4. Bước 4 & 5 — `R40-B3` (`run.json` `totals`) & `R40-B2` (`http.soft_probes`)

- **`R40-B3` ([escalate.go](../internal/engine/escalate.go), [engine.go](../internal/engine/engine.go), [http.go](../internal/engine/http.go)):**
  - `EscalatedRun` bổ sung `Requests`, `PageRequests`, `InternalRequests`.
  - `Record` thêm `Totals *RunTotals` (`requests`, `page_requests`, `internal_requests`, `new_scripts`, `runs`) khi có run Chrome follow-up; cập nhật `unique_scripts = st.Len() + Σ er.NewScripts` và log thêm `total_requests`, trong khi **giữ nguyên** các bộ đếm riêng của run HTTP để không đếm trùng trên `runs.jsonl` hay lệch baseline `monitor`.
- **`R40-B2` ([crawl.go](../internal/httpcrawl/crawl.go)):**
  - `Stats` giữ nguyên `Probes[key]` và thêm `SoftProbes []string` (trần 64) + `SoftProbesMore int` đánh dấu các phản hồi soft-200 SPA/HTML fallback qua `recordProbeStatus` (giữ ngoại lệ cho Swagger UI HTML thật ở `/api/documentation`).
- **Kiểm chứng:** [engine/round40_test.go](../internal/engine/round40_test.go), [httpcrawl/round40_test.go](../internal/httpcrawl/round40_test.go); `pipeline-check.sh`, `waf-check.sh`, `monitor-check.sh` PASS.
