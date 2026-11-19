# Đợt 39: Mở rộng Độ Phủ Pre-Auth (SSR Manifests, HTML AuthFlows, OriginSpecPaths & Deep-Links) và Tối ưu Next.js RSC / `verify`

**Ngày:** 2026-11-19 · **Nền mã nguồn:** `34ad7f2` (sau Đợt 38) · **Trạng thái:** đã triển khai đầy đủ 4 bước.

**Nguyên tắc bất biến:** Zero Band-Aids — không cắt độ sâu BFS hay khả năng mở khoá sub-route của Next.js App Router; không nhân bản bừa bãi đường dẫn probe lên mọi sub-path gây `429`; không tự động gửi request vào luồng login/callback OAuth; không ghi giá trị cookie vào `intel.json`; không đưa tên mục tiêu thật hoặc đường dẫn máy cá nhân vào repo.

| Bước | Mã hạng mục | Vùng | Tóm tắt |
|---|---|---|---|
| **1** | **R39-A** | `htmlscan`, `resolve`, `httpcrawl`, `engine`, `verify`, `sourcemap`, `frontier` | Khử trùng dòng RSC Flight (`self.__next_f.push`) không mất dữ liệu (`-98.8%` dung lượng đĩa & AST lặp); bắt chunk RSC/Turbopack escape trong `resolve.Static`; chặn FP Soft-`200` HTML trùng shell Canary `404`; bổ sung vendor `adminlte`... & lọc CDN cookie (`onetrust.com`...) |
| **2** | **R39-B** | `resolve`, `httpcrawl`, `archive` | Bổ sung build manifest của hệ sinh thái Full-stack/SSR (`/mix-manifest.json`, `/build/.vite/manifest.json` kèm fallback `/build/manifest.json` lách rule chặn dotfile `/.`, `/build/entrypoints.json`), sửa sửa lỗi JSON phẳng trong `AssetManifest` |
| **3** | **R39-C** | `endpoints`, `archive` | Quét `pages.jsonl` bắt `AuthFlows` trên trang Login HTML (`<a href>` / `<form>`); thăng cấp `redirect_uri` in-scope sang `intel.Routes` & `CrawlHosts`; nhận diện framework thụ động qua tên Cookie/Header (`Laravel`, `ASP.NET`, `Drupal`...) |
| **4** | **R39-D** | `frontier`, `jsapi`, `htmlscan`, `httpcrawl`, `engine`, `docs` | Thêm `/swagger/v1/swagger.json` vào `SpecPaths`, tách riêng `OriginSpecPaths` chỉ hỏi 1 lần ở Origin Root, bóc URL spec động từ Swagger UI HTML (`SwaggerUIURLs`), khai thác `<link rel="manifest">`, `apple-app-site-association` và `assetlinks.json` |

---

## 1. R39-A — Khử Trùng RSC Next.js App Router, Chặn FP Soft-`200` `verify` & Lọc Vendor/CDN

1. **Lossless Next.js RSC Flight Row Deduper ([rsc.go](../internal/htmlscan/rsc.go)):**
   - Giải mã chuẩn bằng `json.Unmarshal` cho mảng `[tag, "<flight>"]` trong `self.__next_f.push(...)` (`>= 16 KiB`), băm SHA-256 phần thân từng dòng Flight sau tiền tố `<hex_id>:` theo từng origin (`maxSeenRSCRows = 65536`).
   - Trang đầu giữ nguyên 100% nguyên bản; các trang sau trên cùng origin chỉ đóng gói lại các dòng mới chưa từng thấy (trả `keep = false` khi `0` dòng mới). Trong chế độ đa tab CDP (`-tabs > 1`), `Freeze()` khoá bảng từ điển ngay sau seed commit để khử trùng không phụ thuộc thứ tự tab.
   - Bổ sung `nextRSCRefRe` và nhánh `TURBOPACK` trong [static.go](../internal/resolve/static.go) để bắt các đường dẫn chunk bị escape `\"/_next/static/...js\"` bên trong chuỗi Flight.
2. **Chặn Soft-`200` HTML trùng Shell với Canary `404` ([verify.go](../internal/verify/verify.go)):**
   - Tách `sameHTMLShellBody(ex, s Sig)`: khi probe nhận `2xx` HTML có `Shell` và quy mô từ (`<= 25%`) trùng khớp chính xác với canary `404` HTML của cùng prefix, hạ về `ClientRoute` (bare string) hoặc `DeadOrFP` (endpoint code như `POST {}/upload` được probe bằng `GET`).
3. **Sourcemap & Non-API CDN ([sourcemap.go](../internal/sourcemap/sourcemap.go), [queue.go](../internal/frontier/queue.go)):**
   - Thêm `adminlte`, `toastr`, `sweetalert\d*`, `apexcharts`, `echarts`, `fullcalendar`, `dropzone`, `summernote`, `quill` vào `standaloneVendorFileRe` (vẫn bảo toàn `explicitAppSourcePath`).
   - Thêm `onetrust.com`, `cookielaw.org`, `cookiebot.com`, `trustarc.com`, `usercentrics.eu` vào `nonAPIInfraDomains`.

---

## 2. R39-B — Pre-Auth Build Manifests cho Ứng Dụng SSR / Full-Stack

- Tại [manifest.go](../internal/resolve/manifest.go) và [crawl.go](../internal/httpcrawl/crawl.go):
  - Sửa điều kiện fallback JSON phẳng (`len(m.Files) == 0 && len(m.Entrypoints) == 0`) trong `AssetManifest` và hỗ trợ cả `.js`/`.mjs` + `/mix-manifest.json` (Laravel Mix).
  - Hỗ trợ `/build/.vite/manifest.json` và fallback `/build/manifest.json` (Laravel Vite — giải tương đối theo `/build/` và lách rule chặn `403` dotfile `/.`).
  - Hỗ trợ `/build/entrypoints.json` (`EncoreEntrypoints` cho Symfony Webpack Encore).
  - Tự động áp dụng cho cả `httpcrawl` và `archive` (`assetKind == "manifest"`).

---

## 3. R39-C — `AuthFlows` từ HTML (`pages.jsonl`), `redirect_uri` In-Scope & `ServerHints`

- Tại [infra.go](../internal/endpoints/infra.go), [intel.go](../internal/endpoints/intel.go) và [hosts.go](../internal/archive/hosts.go):
  - Quét `pages.jsonl` cho các liên kết xuất phát từ trang `inScope` để trích xuất đầy đủ `AuthFlows` (`entra_id`, `keycloak`, `okta`, `auth0`, `cognito`...) và `SecurityNotes` trên các trang Login HTML.
  - Đưa đường dẫn sạch (không kèm query) của `AuthFlow.RedirectURI` thuộc `inScope` vào `intel.Routes`, đồng thời bổ sung hostname vào `archive.CrawlHosts` (không gửi HTTP request trực tiếp vào callback OAuth).
  - Nhận diện thụ động `Laravel`, `ASP.NET`, `Java Servlet`, `PHP`, `Ruby on Rails`, `Express`, `CodeIgniter`, `Drupal` qua tên cookie trong `Set-Cookie` (không lưu giá trị cookie) và header framework.

---

## 4. R39-D — Phân Tầng `SpecPaths` / `OriginSpecPaths`, Swagger UI & Deep-Link Manifests

- Tại [queue.go](../internal/frontier/queue.go), [openapi.go](../internal/jsapi/openapi.go), [applinks.go](../internal/frontier/applinks.go), [crawl.go](../internal/httpcrawl/crawl.go) và [specprobe.go](../internal/engine/specprobe.go):
  - Thêm `/swagger/v1/swagger.json` vào `SpecPaths`; tách riêng `OriginSpecPaths` (`/swagger.json`, `/swagger.yaml`, `/docs/api-docs.json`, `/storage/api-docs/api-docs.json`, `/api/documentation`) chỉ hỏi trên Origin Root để không gây `429` trên sub-path.
  - Thêm `SwaggerConfigURLs` đọc JSON `swagger-config` (`url` / `urls[]`) và `SwaggerUIURLs` bóc đường dẫn spec từ HTML wrapper của Swagger UI / Redoc / Scalar (giữ nguyên `SwaggerResources` cho mảng `/swagger-resources`).
  - Khai thác route & subdomain liên kết từ `<link rel="manifest">`, `/.well-known/apple-app-site-association` và `/.well-known/assetlinks.json`.
