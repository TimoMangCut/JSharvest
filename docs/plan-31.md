# Đợt 31: Kế hoạch nâng cấp kiến trúc từ đối chuẩn toàn trình (2026-11-16)

> **Trạng thái: ĐÃ HOÀN TẤT (`3bb9b78..21c82f0`).** Bản tóm tắt vận hành hiện hành xem tại [CURRENT.md](CURRENT.md); dưới đây là đặc tả tham chiếu lúc triển khai.

Nguồn: đợt đối chuẩn đầu-cuối (từ bước thu thập/crawl JS, giải mã bundler, phân tích tĩnh AST, thăm dò đặc tả API, kiểm tra hạ tầng đám mây/SSO tới xuất báo cáo) giữa `jsharvest` (tại `8dfc0be`) với trình thu thập đối chứng (`katana -jc -jsl`) và rà soát thủ công toàn diện trên cổng quản trị SPA thực tế dùng cổng API tập trung (`/api-gateway/*`).

**Mục tiêu cốt lõi:** chuyển hoá toàn bộ khoảng trống phát hiện qua benchmark thành **cơ chế kiến trúc tổng quát ở cấp framework/bundler/protocol**, nâng độ phủ tự động cho mọi cổng SPA/microservice tương tự trong tương lai. **Tuyệt đối không** viết biểu thức chính quy vá theo từng ứng dụng hay từng tên miền.

---

## 0. Bất biến thiết kế & Ranh giới an toàn

Mọi hạng mục trong Đợt 31 phải giữ nguyên các bất biến đã khoá ở Đợt 28–30 (`CLAUDE.md`):

1. **Tổng quát hoá kiến trúc, không vá cục bộ:** mọi luật mới trong `resolve`, `jsapi`, `frontier`, `httpcrawl`, `verify`, `endpoints` chỉ được bám vào ngữ pháp của công cụ đóng gói (Webpack 3/4/5, Vite, Rollup), chuẩn framework định tuyến (`vue-router`, `react-router`, `@angular/router`, TanStack Router), chuẩn giao thức (OpenAPI 2.0/3.x, OAuth2/OIDC, S3/GCS/Azure XML/REST) và cấu trúc AST chuẩn của Terser/Babel.
2. **Phạm vi ứng dụng (`App-Referenced Scope` — chốt từ `D2`) & Ranh giới OpSec (`B1`, `B2`, `B3`):**
   - **Tất cả tài nguyên ứng dụng thực sự sử dụng đều thuộc phạm vi đánh giá (`in-scope`):** tách bạch rõ *nhiễu quảng cáo/analytics chung của bên thứ ba* (`google-analytics.com`, `googletagmanager.com`, `facebook.net`, `doubleclick.net`, `hotjar.com`, `clarity.ms`...) với *hạ tầng khác tên miền nhưng do ứng dụng nạp/gọi trực tiếp* (bundle JS chính đặt trên CloudFront/CDN riêng, bucket S3/GCS/Azure/R2 trong mã nguồn, cổng SSO/IdP, API backend trên domain anh em). Không bỏ rơi `Bases`, `Keys`, `ClientHeaders`, `Cloud` hay `Endpoints` chỉ vì khác hậu tố tên miền (`rdn`).
   - **Giữ nguyên chốt chặn chống chạm mạng nội bộ của máy chạy tool (`internal/netsafe`):** mọi kết nối mạng (kể cả tới Cloud Storage, CDN hay API ngoài tên miền chính) bắt buộc đi qua `netsafe` + nguồn `-proxy` thống nhất + giới hạn tốc độ/WAF; từ chối tuyệt đối IP nội bộ/loopback/link-local (`127.0.0.1`, `169.254.169.254`, LAN) trừ mục tiêu nội bộ hợp lệ.
   - **Cô lập thông tin xác thực theo nguồn đích:** `client_headers` tĩnh chỉ gửi tới đúng nguồn API khai báo chúng; không bao giờ đính kèm `Cookie` hay `Authorization` của phiên người dùng sang miền ngoài (như S3/GCS).
3. **Ngân sách nhiễu & hiệu năng:**
   - Không làm tăng tỷ lệ dương tính giả (FP) trên tập kiểm chuẩn (`TestSnapshot`, `TestStats` của `jsapi` và `endpoints`).
   - Giữ nguyên trần `perfgate` (`≤ 15 s` thời gian chạy, `≤ 500 MB` RSS đỉnh) và độ phức tạp tuyến tính theo kích thước bundle.
4. **Vệ sinh dữ liệu:** không ghi tên miền, khoá bí mật, đường dẫn đặc thù của khách hàng vào mã nguồn, fixture, test hay tài liệu trong git; dùng tên giả lập chuẩn (`admin.example.com`, `/api-gateway`, `AIzaSyDUMMY000000000000000000000000000`).

---

## 1. Nguyên tắc thực thi & Kiểm chứng

- **Test đỏ trước khi sửa (Red-to-Green TDD):** mỗi mục phải có unit test tái hiện đúng cấu trúc bundle/AST/giao thức làm HEAD thất bại trước khi viết mã sửa.
- **Tăng `jsapi.Version` một lần (`36 → 37`):** gom các thay đổi thay đổi đầu ra `jsapi.Result` (cây router phân cấp, quét tiền tố bí mật, `client_authz`, định trị AST Terser) vào phiên bản cache `37`; kiểm tra tương thích `stale_cache` của MCP (`internal/endpoints/endpoints.go`).
- **Mỗi commit một mục độc lập**, chạy đúng bộ gate trong bảng Mục 5.2 trước khi chuyển sang mục kế tiếp.

---

## 2. Ưu tiên 1 (P1): Chuẩn hoá tầng thu thập Bundler, Cây định tuyến SPA, Chữ ký bí mật & Xuất dữ liệu

### 2.1. Giải mã Webpack đa thế hệ (Webpack 3/4/5, `webpackAsyncContext` & Liên kết `runtimeChunk` liên script)

- **Vấn đề gốc trong code (`internal/resolve/static.go`):**
  1. `webpackPlainRe` (`static.go:66`) chỉ khớp mẫu hàm `.u = function(e){return ...}` của Webpack 5. Ở Webpack 3 và Webpack 4 (khi chunk không gắn hash hoặc trộn `nameMap`), trình nạp dùng hàm `jsonpScriptSrc(e)` hoặc gán trực tiếp `.src = function(e){return r.p + "prefix/" + ({0:"foo"}[e]||e) + ".js"}(e)` nên `webpackPlain` trả rỗng (`0%` lazy chunk).
  2. `webpackPlain` (`static.go:331`) chỉ thu thập mã chunk từ lệnh gọi tường minh `<req>.e(42)` (`webpackLoadRe`), bỏ sót hoàn toàn bảng ánh xạ ngữ cảnh bất đồng bộ `webpackAsyncContext` do Webpack sinh ra cho `import("./dir/" + x)` và `require.context(..., "lazy")`:
     ```js
     var map = { "./en-US.json": [1476, 0], "./vi-VN.json": [1477, 1], "./view.vue": [1502, 2, 5] };
     function webpackAsyncContext(req) { ... return Promise.all(ids.slice(1).map(t.e)).then(...) }
     ```
     Trong đó phần tử `[0]` là `moduleId`, còn **`[1:]` (khi độ dài mảng `≥ 2`) là danh sách `chunkId`**.
  3. Khi ứng dụng tách `runtime~main.js` riêng (`optimization.runtimeChunk: "single"`), mẫu URL chunk nằm ở `runtime.js` còn lệnh gọi `.e(...)` và bảng `webpackAsyncContext` nằm ở `app.js` / `vendors.js`; `webpackPlain` hiện chỉ xét từng file đơn lẻ nên đánh mất liên kết.

- **Thiết kế kiến trúc:**
  1. **Mở rộng bộ nhận diện hàm tạo URL chunk (`internal/resolve/static.go`):**
     - Hỗ trợ cả 3 thế hệ runtime: Webpack 5 (`<req>.u = ...`), Webpack 3/4 hàm rời (`function <fn>(<id>){return <req>.p + ...}`), và Webpack 3/4 biểu thức hàm nội tuyến (`.src = function(<id>){return <req>.p + ...}(<id>)`), bao gồm cả biến thể có hoặc không có bảng tên `({...}[<id>] || <id>)`.
     - Chuẩn hoá kết quả trích xuất thành cấu trúc `WebpackRuntime` xuất công khai từ gói `resolve`: `{PublicPath string, Prefix string, NameMap map[string]string, HashMap map[string]string, Suffix string}`.
  2. **Bộ trích xuất `webpackAsyncContext` neo ngữ nghĩa:**
     - Quét các object literal có khoá chuỗi tương đối (`"./..."`) ánh xạ tới mảng số nguyên/chuỗi độ dài `≥ 2`, **chỉ khi** trong cửa sổ lân cận (ví dụ `≤ 800` byte phía sau bảng map trong cùng module) xuất hiện lời gọi nạp chunk của Webpack (`.slice(1).map(<req>.e)` hoặc `<req>.e(<arr>[1])`).
     - Chỉ lấy các phần tử từ chỉ số `1` trở đi (`ids[1:]`) làm `chunkId`.
  3. **Liên kết `WebpackRuntime` liên script trong cùng trang/nguồn (`internal/httpcrawl/crawl.go` & `internal/engine/`):**
     - Lưu `WebpackRuntime` tìm được từ các script cùng nguồn của trang hiện hành, kết hợp với tập `chunkIDs` thu được từ mọi script thuộc chính ứng dụng đó (`!ThirdParty`) trên cùng trang để sinh `Candidate{Method: "webpack-runtime"}`.

- **Bẫy cần tránh:**
  - **Không nhầm `moduleId` là `chunkId`:** `require.context` đồng bộ (`sync`) sinh `"./a.json": 1476` hoặc `[1476]` (độ dài 1) và không gọi `.e`. Nếu lấy phần tử `[0]` sẽ tạo hàng trăm URL `1476.js` giả.
  - **Không dính bẫy Browserify:** gói Browserify có dạng `{1:[function(require,module,exports){...},{"./dep":2}]}`. Điều kiện neo `.e` + khoá `"./..."` trực tiếp loại bỏ hoàn toàn Browserify.
  - **Chống ký tự bẩn & tràn số lượng:** chỉ chấp nhận `chunkId` khớp `^[A-Za-z0-9_.-]{1,64}$` (loại bỏ lỗi nối chuỗi xuống dòng `%5Cn`), giới hạn tối đa `maxPlainChunks = 128` cho mỗi runtime không hash, và giữ nguyên bộ lọc từ chối phản hồi SPA HTML fallback (`text/html` / `<!doctype html`) khi tải chunk.

- **Gate:** unit test trong `internal/resolve/static_test.go` (Webpack 3, Webpack 4 inline + `nameMap`, Webpack 4/5 `webpackAsyncContext` mảng 2 và 3 phần tử, tách `runtime.js` + `app.js`, negative test Browserify & sync context); `pipeline-check`, `frontier-check`.

---

### 2.2. Bộ dựng cây định tuyến SPA phân cấp (Hierarchical SPA Router AST Walker)

- **Vấn đề gốc trong code (`internal/jsapi/calls.go:57-65`):**
  - `callVisitor` hiện chỉ bắt từng object đơn lẻ có thuộc tính `path: "/..."` bắt đầu bằng dấu `/`. Mọi route con tương đối nằm trong mảng `children: [{path: "devices"}, {path: ":id/edit"}]` (chuẩn của `vue-router` v3/v4, `react-router` v6 `createBrowserRouter`, `@angular/router`, TanStack Router) đều bị bỏ qua (benchmark thực tế chỉ đạt `84 / 163 = 51,5%` route lá).

- **Thiết kế kiến trúc (`internal/jsapi/routes.go` mới, tích hợp vào `callVisitor` & `Result`):**
  1. **Neo điểm gốc của cây định tuyến (`Router Root Anchors`) để giữ nhiễu = 0:**
     Chỉ kích hoạt trình duyệt cây định tuyến từ hai loại gốc xác thực:
     - Lời gọi khởi tạo router: `new VueRouter(...)`, `createRouter(...)`, `createBrowserRouter(...)`, `createHashRouter(...)`, `createMemoryRouter(...)`, `RouterModule.forRoot(...)`, `RouterModule.forChild(...)`, `provideRouter(...)`, `$routeProvider.when(...)`.
     - Object định tuyến có cấu trúc xác thực: object có `path` bắt đầu bằng `"/"` đi kèm `children` / `component` / `components` / `redirect` / `loadChildren` / `element`, hoặc mảng chứa các object thoả điều kiện trên.
  2. **Giải tham chiếu biến & Duyệt đệ quy có giới hạn:**
     - Tại mỗi nút route, giải trị thuộc tính `children` qua mảng trực tiếp, biến trung gian (`x.defs[root(v)]`), phần tử trải (`...subRoutes`), hoặc lời gọi `.concat(...)`.
     - Chuẩn hoá phép ghép đường dẫn theo đúng ngữ nghĩa chuẩn SPA:
       - `child.path == ""` (index route) → giữ nguyên `parentPath`;
       - `child.path` bắt đầu bằng `"/"` → đường dẫn tuyệt đối từ gốc (`child.path`), không ghép lặp `parentPath`;
       - `child.path` tương đối (`"ecu"`, `":id/edit"`, `"*"`) → `strings.TrimRight(parentPath, "/") + "/" + child.path`.
     - Bổ sung vào `Result.Routes` (giữ tương thích ngược cho `frontier`) **và** xuất danh sách có cấu trúc `Result.RouteEntries []RouteEntry` (`Path`, `Redirect`, `AuthRequired *bool`, `Roles []string`, `Permissions []string`, `LazyChunk string`, `Line int`) để phục vụ `intel.json` (Mục 4.1).
  3. **Liên kết `frontier` (`internal/frontier/discover.go`):**
     - `frontier` tự động nhận toàn bộ các route tĩnh mới được nối đầy đủ (`/ota/release-package`, `/settings/users`...) để đưa vào hàng đợi duyệt trang; các route chứa tham số (`:id`, `*`, `{}`) vẫn được lọc bởi `templatePath` khi crawl nhưng được bảo toàn nguyên vẹn trong `intel.json` cho pentester.

- **Bẫy cần tránh:**
  - **Không quét mù `{path: "foo"}` không có neo router:** các thư viện UI/biểu tượng/JSON Schema dùng `{path: "M10 10..."}` hoặc `{path: "user.name"}` rất nhiều; bắt buộc phải qua `Router Root Anchors`.
  - **Vòng lặp tham chiếu `children`:** giữ tập `visited map[js.INode]bool`, giới hạn độ sâu `maxRouteDepth = 12` và trần `maxRoutesPerScript = 2000`.

- **Gate:** unit test cho `vue-router` (nested + biến mảng phụ + spread + redirect), `react-router` v6 (`createBrowserRouter` + index route), `@angular/router` (relative root trong `forRoot`/`forChild`); `TestSnapshot`/`TestStats` trên `jsapi`; `frontier-check`, `explore-check`.

---

### 2.3. Bộ nhận diện khoá/bí mật hai tầng dùng chung (`internal/secretsig`)

- **Vấn đề gốc trong code (`internal/jsapi/jsapi.go:282-307` & `internal/mcpserver/scripts.go:41`):**
  - `x.key(name, value, line)` chỉ giữ giá trị khi tên thuộc tính khớp `keyNameRe` (`apiKey`, `secret`, `clientId`...). Khi SDK dùng tên thuộc tính ngắn như `{key: "AIza..."}` (chuẩn của `@googlemaps/js-api-loader`) hoặc truyền thẳng chuỗi vào hàm khởi tạo `loadStripe("pk_live_...")`, khoá bị bỏ sót. Không thể thêm từ `"key"` vào `keyNameRe` vì sẽ bắt nhầm hàng nghìn `key` của danh sách Vue/React và cột bảng.
  - Trong khi đó, `mcpserver/scripts.go:41` đã có `scriptSecretRe` nhận diện theo tiền tố nhà cung cấp, nhưng tách rời khỏi `jsapi` và `redact`.

- **Thiết kế kiến trúc:**
  1. Tạo gói nhỏ dùng chung `internal/secretsig` định nghĩa tập chữ ký định danh độ chính xác cao theo cấu trúc nhà cung cấp (tiền tố cố định + bảng chữ cái + độ dài chặt):
     - `google_api_key`: `AIza[0-9A-Za-z_-]{35}` (đúng 39 ký tự, không có ký tự chữ/số nối tiếp hai đầu)
     - `aws_access_key_id`: `(?:AKIA|ASIA)[0-9A-Z]{16}`
     - `stripe_key`: `(?:pk|sk|rk)_(?:live|test)_[0-9A-Za-z]{16,99}`
     - `github_token`: `(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})`
     - `slack_token`: `xox[abprs]-[0-9]{10,13}-[0-9A-Za-z-]{10,128}`
     - `sendgrid_key`: `SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`
     - `mapbox_token`: `(?:pk|sk)\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}`
     - `sentry_dsn`: `https://[0-9a-f]{32}@(?:[a-z0-9-]+\.)*ingest(?:\.[a-z]{2})?\.sentry\.io/\d+`
  2. **Tích hợp hai tầng vào `jsapi`:**
     - **Tầng 1 (theo tên thuộc tính — giữ nguyên):** `keyNameRe` + `keyValue` cho các khoá không có tiền tố chuẩn (`client_secret`, `app_id`, `tenant_id`).
     - **Tầng 2 (theo chữ ký giá trị — mới):** trong `stringVisitor` (cho cả `LiteralExpr`, `TemplateExpr` tĩnh và `configPairs`), nếu chuỗi khớp `secretsig.Match(s)` và không phải mẫu ví dụ giả (`EXAMPLE`, `DUMMY`, chuỗi lặp 1 ký tự), ghi nhận vào `Result.Keys` (giữ tên thuộc tính thật nếu nằm trong `*js.Property`, ngược lại dùng nhãn loại chữ ký như `google_api_key`).
  3. **Đồng bộ che dấu (`redact` & `mcpserver`):** `mcpserver.scriptText` và `redact` dùng chung `secretsig` để mọi khoá trích xuất được ở `intel.json` đều chắc chắn được che khi chạy không có `-reveal`.

- **Bẫy cần tránh:**
  - **Không dùng độ đo entropy mù:** chuỗi nén base64, font nhúng, hash sourcemaps và đường cong SVG sẽ gây nhiễu nặng nếu quét theo Shannon entropy. Chỉ chấp nhận chữ ký có định dạng nhà cung cấp xác định.
  - **Giữ nguyên lọc `ThirdParty`:** `BuildIntel` (`internal/endpoints/intel.go:57`) tiếp tục bỏ qua `s.ThirdParty` để khoá công khai của script bên thứ ba trên CDN ngoài không tràn vào hồ sơ mục tiêu.

- **Gate:** unit test cho `secretsig`, `jsapi`, `mcpserver` redaction; `TestStats` trên corpus dev (kiểm tra 0 nhiễu mới); `flows-check MCP=1`, `endpoints-check`.

---

### 2.4. Sửa lỗi nuốt đầu ra `openapi.json` của `export -format all` khi không có luồng động

- **Vấn đề gốc trong code (`cmd/jsharvest/export.go:127-137`):**
  - Khi chạy trên thư mục kết quả `-engine http`, file `requests.jsonl` tồn tại (`haveLog == true`) nhưng chỉ chứa lượt tải trang/script chứ không có luồng API động nên `export.Export` trả `export.ErrNoFlows`.
  - Ở `format == "all"`: nếu không truyền `-drafts`, lệnh thoát lỗi ngay dòng 128; nếu truyền `-drafts`, lệnh ghi `drafts/` rồi `return nil` sớm ở dòng 136 trước khi gọi `writeOpenAPI`. Trong cả hai trường hợp, `openapi.json` không được tạo dù `endpoints.jsonl` có đầy đủ danh mục tĩnh.

- **Luật sửa:**
  - Khi `format == "all"` và `export.Export` trả `export.ErrNoFlows`: không thoát sớm; ghi nhận thông báo gọn ra `stderr`, tiếp tục thực thi nhánh `writeOpenAPI` (nếu có danh mục trong `endpoints.jsonl` hoặc luồng) và nhánh `writeDrafts` (nếu bật `-drafts`). Chỉ trả lỗi khi **cả** luồng động, danh mục OpenAPI lẫn drafts đều rỗng.

- **Gate:** unit/CLI test cho cả 3 tổ hợp (`-format all` trên thư mục chỉ có static catalog, `-format all -drafts`, và thư mục hoàn toàn rỗng); `export-check`.

---

## 3. Ưu tiên 2 (P2): Khám phá chủ động hai pha có ngữ cảnh & Làm giàu hạ tầng Đám mây / SSO

### 3.1. Thăm dò đặc tả API hai pha có ngữ cảnh (`SpecPaths` mở rộng + Pha 2 sau phân tích JS)

- **Vấn đề gốc trong code (`internal/frontier/queue.go:297`, `internal/httpcrawl/crawl.go:1134`, `internal/engine/frontier.go:979`):**
  1. `frontier.SpecPaths` thiếu hai đường dẫn chuẩn rất phổ biến của hệ sinh thái Java Springfox / Swagger 2.0 là `/v2/api-docs` và `/swagger-resources`.
  2. `specProbe` hiện chỉ chạy **Pha 1** (ngay ở gốc origin `/` trước khi phân tích xong toàn bộ bundle JS) và gửi yêu cầu trần (không có `Bases` tương đối như `/api-gateway`, không có tiền tố microservice đứng sau gateway, và không đính kèm `client_headers` tĩnh mà cổng API bắt buộc kiểm tra ở tầng pre-auth).

- **Thiết kế kiến trúc:**
  1. **Mở rộng `SpecPaths` & trình kiểm tra nội dung:**
     - Bổ sung `"/v2/api-docs"` và `"/swagger-resources"` vào `frontier.SpecPaths`.
     - Kiểm tra `jsapi.IsOpenAPI` nhận diện đầy đủ `"swagger": "2.0"`; bổ sung `jsapi.SwaggerResources(body []byte) []string` để đọc mảng JSON `[{"location": "/..."}]` của Springfox và nạp tiếp tối đa `MaxSwaggerResources = 5` tài liệu con cùng origin.
  2. **Bổ sung Pha 2 (Post-JS Context-Aware Spec Probe) vào cuối `httpcrawl` và `engine`:**
     - Sau khi các script của mục tiêu đã được thu thập và chạy phân tích sơ bộ (`BuildIntel` / `Catalog`), tổng hợp:
       - Các `Bases` nội bộ cùng phạm vi (`inScope`), tối đa `MaxSpecBases = 4` (ví dụ `https://admin.example.com/api-gateway`);
       - Tối đa `MaxServiceDocPrefixes = 5` tiền tố dịch vụ con có tần suất endpoint cao nhất nằm dưới gateway (ví dụ `/api-gateway/auth`, `/api-gateway/user`), trên đó **chỉ** hỏi 2 đường dẫn chuẩn của microservice (`/v3/api-docs`, `/v2/api-docs`);
       - Tập `client_headers` tĩnh của mục tiêu (các cặp khoá-giá trị hằng số không chứa `{}` như `client_id`, `client_secret`, `x-app-version`, loại trừ các header nhạy cảm tầng HTTP như `Host`, `Cookie`, `Authorization`, `Content-Length`, `Origin`).
     - Gửi yêu cầu `GET` chỉ đọc qua bộ điều phối hiện hành (`netsafe` + `-proxy` + giới hạn tốc độ).
     - **Cầu chì dừng sớm (Canary/Gate Short-Circuit):** trước khi hỏi hàng loạt đường dẫn dưới một `Base` mới, gửi thử hoặc đối chiếu phản hồi đầu tiên: nếu gateway trả vỏ HTML của SPA giống nhau hoặc tường chặn đồng nhất (`401`/`403`/`400` cùng chữ ký `SigOf`), dừng ngay các tiền tố con của gateway đó để không gây ồn trên WAF.

- **Bẫy cần tránh (OpSec `B1`/`B3`):**
  - **Cô lập theo nguồn cho `client_headers`:** chỉ đính kèm `client_headers` khi thăm dò chính origin của trang hoặc các `APIOrigins` thuộc `inScope` mà script mục tiêu khai báo; tuyệt đối không gửi sang miền ngoài.
  - **Trần ngân sách cứng:** tổng số yêu cầu Pha 2 trong trường hợp xấu nhất không vượt quá `≤ 46` yêu cầu `GET` trên toàn phiên crawl (và chỉ `≤ 6` khi gặp cổng chặn đồng nhất).

- **Gate:** unit test với máy chủ giả lập cổng `/api-gateway` yêu cầu `client_id` mới trả `/v2/api-docs` + `/swagger-resources`, test cầu chì dừng sớm khi gateway trả `401` đồng nhất, test không rò header sang host khác; `pipeline-check`, `waf-check`, `frontier-check`.

---

### 3.2. Phân tích cấu trúc & Kiểm tra tự động quyền truy cập Cloud Storage (`intel.json` & `verify`)

- **Vấn đề gốc trong code (`internal/endpoints/intel.go:44-47`):**
  - `Intel.Cloud` chỉ lưu chuỗi URL thô (`{"url": "https://s3.ap-southeast-1.amazonaws.com/my-bucket/dir", "sources": [...]}`), chưa bóc tách nhà cung cấp/tên bucket/vùng và chưa cho biết đối tượng hay gốc bucket đang mở công khai (`public_listable`, `public_object`) hay đã khoá (`access_denied`, `not_found`).

- **Thiết kế kiến trúc (theo quyết định `D2`: bucket ứng dụng sử dụng thuộc phạm vi mặc định):**
  1. **Làm giàu cấu trúc (`BuildIntel`):**
     - Mở rộng `IntelURL` (giữ nguyên các trường JSON cũ `url`, `sources`) với các trường `omitempty`: `Provider` (`aws_s3`, `gcs`, `azure_blob`, `cloudflare_r2`, `digitalocean_spaces`, `alibaba_oss`, `firebase`), `Bucket`, `Region`, `ObjectPrefix`, `BucketRootURL`, `Status`.
     - Xử lý chính xác cả 2 kiểu địa chỉ S3: path-style (`s3.<region>.amazonaws.com/<bucket>/<key>`) và virtual-hosted-style (`<bucket>.s3.<region>.amazonaws.com/<key>`), kể cả khi URL xuất hiện trong bundle ứng dụng nạp từ CDN riêng.
  2. **Kiểm tra trạng thái quyền truy cập mặc định (có cờ tắt `-no-cloud-probe` khi cần thuần offline):**
     - Đi qua `netsafe` + `-proxy`, **không** đính kèm bất kỳ cookie/header xác thực nào của ứng dụng, giới hạn an toàn `MaxCloudTargets = 10`:
       - Gửi `HEAD` tới URL mẫu trong code → phân biệt `200` (`public_object`), `403` (`private`), `404` (`object_not_found`);
       - Gửi `GET` (đọc tối đa `8 KB`) tới `BucketRootURL` → kiểm tra chữ ký XML `<ListBucketResult` (`public_listable` — rủi ro cao), `AccessDenied` (`bucket_exists_private`), `NoSuchBucket` (`bucket_missing` — nguy cơ chiếm quyền tên bucket).
     - Ghi kết quả vào `intel.json` (`cloud[].status`, `security_notes`) và `verify.json` (`cloud_checks`).

- **Gate:** unit test phân tích cú pháp mọi biến thể URL đám mây + máy chủ giả lập XML S3 (`ListBucketResult` / `AccessDenied` / `NoSuchBucket`) qua `-proxy`; `verify-check`, `proxy-check`, `endpoints-check`.

---

### 3.3. Trích xuất thụ động cấu hình SSO / OAuth2 / OIDC từ phản hồi Pre-Auth (`Infra` & `verify`)

- **Vấn đề gốc trong code (`internal/endpoints/infra.go` & `internal/verify/verify.go`):**
  - Nhiều ứng dụng SPA gọi một API công khai trước đăng nhập (ví dụ `GET /auth/v1/sso/url`) hoặc nhận `302 Location` trả về URL uỷ quyền đầy đủ của nhà cung cấp danh tính (Azure Entra ID `login.microsoftonline.com/<tenant_id>/oauth2/v2.0/authorize?client_id=...&redirect_uri=...`, Keycloak, Cognito, Auth0, Okta, Google). Hiện `verify` chỉ đánh dấu `verified_alive` (`200`), còn pentester phải mở từng thân phản hồi để đọc thủ công `tenant_id`, `client_id`, `redirect_uri`.

- **Thiết kế kiến trúc (100% thụ động trên dữ liệu phản hồi đã nhận, 0 yêu cầu mạng phát sinh):**
  1. Xây dựng bộ giải mã giao thức `ExtractAuthFlows(sourceURL string, headers map[string]string, body []byte) []AuthFlow` trong `internal/endpoints/infra.go`:
     - Quét header `Location` và các URL chứa đường dẫn chuẩn OAuth2/OIDC (`/oauth2/`, `/protocol/openid-connect/auth`, `/authorize` đi kèm tham số `client_id=` và `redirect_uri=` hoặc `response_type=`) trong thân phản hồi `2xx`/`3xx` kích thước hợp lệ (`≤ 256 KB`).
     - Trích xuất cấu trúc `AuthFlow`: `Provider` (`entra_id`, `okta`, `auth0`, `cognito`, `keycloak`, `google`, `oidc_generic`), `AuthorizationEndpoint`, `TenantID` (ví dụ GUID trong đường dẫn Entra ID hoặc realm của Keycloak), `ClientID`, `RedirectURI`, `ResponseType`, `Scope`, `SourceURL`.
  2. Ghi nhận vào `Intel.AuthFlows` (`auth_flows,omitempty` trong `intel.json`) khi chạy `SaveIntel`, đồng thời gắn tóm tắt vào `verify.Result` khi `verify` bắt gặp phản hồi chứa luồng đăng nhập.
  3. Sinh `SecurityNote` thụ động khi phát hiện cấu hình đáng chú ý cho pentester: `oauth_implicit_flow` (`response_type` chứa `token` trần), `oauth_http_redirect_uri` (`redirect_uri` dùng `http://` không phải loopback).

- **Gate:** unit test với phản hồi mẫu của Entra ID, Keycloak, Cognito, Auth0 (cả JSON body lẫn `302 Location`); `endpoints-check`, `verify-check`.

---

## 4. Ưu tiên 3 (P3): Mô hình hoá phân quyền phía Client & Hoàn thiện bộ định trị AST Terser

### 4.1. Bề mặt phân quyền phía Client (`client_authz` trong `intel.json`)

- **Vấn đề gốc:**
  - Các cổng quản trị SPA thường nhúng toàn bộ ma trận vai trò (`ROLE_ADMIN`, `ROLE_AUDITOR`...), danh sách quyền nghiệp vụ (CASL `$can("update", "Firmware")`, `ability.can(...)`, `hasPermission("user:delete")`) và cờ bảo vệ từng route (`meta: { authRequired: false, permission: "..." }`) ngay trong bundle. Công cụ hiện chưa gom lớp ngữ nghĩa này thành bản đồ kiểm thử phân quyền.

- **Thiết kế kiến trúc (`internal/jsapi/authz.go` mới + tổng hợp ở `internal/endpoints/intel.go`):**
  1. **Thu thập 3 nguồn ngữ nghĩa phân quyền có độ tin cậy cao trong AST:**
     - **Lời gọi kiểm tra quyền chuẩn (CASL & Guard Helpers):**
       - CASL: `<obj>.$can(action, subject)`, `<ability>.can(action, subject)`, `<ability>.cannot(action, subject)`, component `<Can I="..." a="...">` sau biên dịch template.
       - Hàm kiểm tra quyền tường minh: hàm/phương thức có tên khớp `^(?:has|check|require)(?:Permission|Role|Authority|Access)s?$` nhận đối số chuỗi hằng hoặc mảng chuỗi hằng.
     - **Từ điển hằng vai trò/quyền (`Role/Permission Dictionaries`):** object đóng băng hoặc bảng hằng có tên biến/thuộc tính khớp `(?i)^(?:ROLES?|PERMISSIONS?|AUTHORITIES|USER_ROLES)$` với các giá trị chuỗi ngắn, không phải câu thông báo giao diện.
     - **Siêu dữ liệu định tuyến (`RouteMeta` từ Mục 2.2):** thuộc tính `meta` trên nút route chứa `authRequired` / `requiresAuth` / `public` / `guest` / `roles` / `permissions` / `permission` / `authority`.
  2. **Tổng hợp thành trường `ClientAuthz` (`client_authz,omitempty`) trong `intel.json` (và trả tự động qua tool MCP `get_intel`):**
     - `Roles []string`: danh sách vai trò duy nhất đã chuẩn hoá;
     - `Rules []AuthzRule`: cặp `{Action, Subject, Source}` (ví dụ `{"action": "manage", "subject": "Order"}`);
     - `PublicRoutes []string`: các đường dẫn UI đánh dấu rõ không yêu cầu đăng nhập (`authRequired: false` / `public: true`) — mục tiêu ưu tiên kiểm tra lộ tính năng pre-auth;
     - `GuardedRoutes []GuardedRoute`: đường dẫn UI kèm quyền/vai trò yêu cầu — đầu vào trực tiếp để đối chiếu chéo với API thực tế trong kiểm thử BOLA/BFLA (`authz`).

- **Bẫy cần tránh:**
  - **Không bắt nhầm phương thức `.can*` của trình duyệt/DOM:** `HTMLMediaElement.canPlayType`, `PaymentRequest.canMakePayment`, `navigator.canShare`. Chỉ khớp đúng tên `.can` / `.cannot` / `.$can` / `.$cannot` với 1–2 đối số chuỗi định danh ngắn (`^[A-Za-z0-9_:.*-]{1,64}$`, không chứa khoảng trắng câu văn hay dấu `/` của MIME type).

- **Gate:** unit test CASL Vue/React, `hasPermission`/`ROLES` enum, `RouteMeta` public vs guarded, negative test `canPlayType("video/mp4")`; `TestStats` `jsapi`; `endpoints-check`, `flows-check MCP=1`.

---

### 4.2. Hoàn thiện bộ định trị biểu thức AST Terser (`+=` / `=` nội tuyến & Chuỗi `.map()` hai chặng)

- **Vấn đề gốc trong code (`internal/jsapi/eval.go` & `internal/jsapi/defs.go`):**
  1. **Gán ghép lồng trong biểu thức của Terser (`eval.go:91` & `defs.go:226`):**
     Terser rút gọn chuỗi lệnh:
     ```js
     let t = "svc/v1/items";
     t += "/export";
     t = "".concat(t, "?type=csv");
     ```
     thành một câu lệnh duy nhất: `t = "".concat(t += "/export", "?type=csv")`.
     Trong `eval.go:91`, nhánh `*js.BinaryExpr` chỉ xử lý `+`, `||`, `??`, `&&`; khi gặp `t += "/export"` (`js.AddEqToken`) hoặc `t = ...` (`js.EqToken`) đóng vai trò biểu thức con, `eval` rơi xuống cuối hàm và trả `unk` (`"{}"`), làm mất đoạn đường dẫn đứng trước (`"{}?type=csv"`).
  2. **Chuỗi `.map()` hai chặng bọc object cấu hình URL:**
     Mẫu hàm tải song song nhiều tài nguyên:
     ```js
     ["/v1/summary", "/v1/metrics"].map(u => ({ url: u, params })).map(cfg => client.request(cfg))
     ```
     hoặc mảng cấu hình tĩnh `[{url: "/v1/a"}, {url: "/v1/b"}].forEach(c => axios(c))` hiện chưa truyền từng phần tử object từ mảng nguồn vào tham số của callback nhận cấu hình request.

- **Thiết kế kiến trúc:**
  1. **Định trị `AddEqToken` và `EqToken` an toàn trong `eval` + chống nhân đôi chuỗi ở `defsVisitor`:**
     - **Bẫy thứ tự duyệt AST (rất quan trọng):** `defsVisitor.Enter` duyệt theo thứ tự tiền tự (preorder). Với `t = "".concat(t += "/export", "?a=1")`, `defsVisitor` gặp phép gán ngoài `t = ...` **trước**, đẩy bước `'='` vào `x.chains[t]`, rồi mới đi xuống biểu thức con `t += "/export"` và đẩy thêm bước `'+'` vào **sau** bước `'='`! Nếu chỉ sửa `eval` mà không sửa `defsVisitor`, `evalChain` sẽ nối `"/export"` hai lần (`.../export?a=1/export`).
     - **Luật chính xác:**
       - Trong `defsVisitor`: giữ ngăn xếp biến đích đang được gán ở vế phải (`assignLHS`). Khi đang ở bên trong vế phải của `vr = ...` (hoặc `vr += ...`), một phép gán lồng tới **chính `vr`** không được đẩy thành bước nối đuôi độc lập thứ hai trong `x.chains[vr]`.
       - Trong `eval` (`*js.BinaryExpr`):
         - Khi `n.Op == js.EqToken`: trả `x.eval(n.Y, q, depth+1)`; nếu `n.X` là `*js.Var` đang có mặt trong `x.bind[root(v)]`, cập nhật `x.bind[root(v)]` cho các tham chiếu tiếp theo cùng biểu thức.
         - Khi `n.Op == js.AddEqToken`: nếu `n.X` là `*js.Var` đang có trong `x.bind[root(v)]`, tính `cur = cat(x.bind[root(v)], x.eval(n.Y, q, depth+1))`, cập nhật `x.bind[root(v)] = cur` và trả `cur`; nếu `n.X` chưa nằm trong `x.bind` (ví dụ `fetch("".concat(t += "/export", "?a=1"))`), định trị chuỗi `chains[root(v)]` **chỉ tính tới đúng bước sinh ra bởi nút AST `n`** (không tính lặp `n.Y` và không tính các bước gán xảy ra ở dòng code sau `fetch`).
  2. **Truyền phần tử mảng qua `.map` / `.forEach` / `Promise.all(...map(...))`:**
     - Trong `callVisitor` / `objectN` (`eval.go:869`): khi đối số cấu hình hoặc URL của một lời gọi HTTP là tham số `p` của hàm callback truyền vào `<arrExpr>.forEach(fn)` hoặc `<arrExpr>.map(fn)` (kể cả qua tối đa 1 bước biến đổi `.map(x => ({url: ...}))` với độ dài mảng tĩnh `≤ maxAlts`), cho phép `evalVar` / `objectN` giải hội (`union`) trên các phần tử của `<arrExpr>`.

- **Gate:** unit test đầy đủ cho: (a) `t = "".concat(t += "/a", "?b=1")` (không nhân đôi `"/a"`), (b) `fetch("".concat(t += "/a", "?b=1")); t += "/later"` (không dính `"/later"` vào `fetch` trước đó), (c) `t = "".concat(t += "/a", t)` (cập nhật `bind` tại chỗ), (d) chuỗi `.map` 1 chặng và 2 chặng vào `axios`/`fetch`/helper; `TestSnapshot`, `TestStats`, `perfgate`.

---

## 5. Phase P0 (Dọn sạch Repo & Nợ kỹ thuật trước Đợt 31) và Lộ trình thực thi

### 5.0. Phase `P0-Hygiene`: Dọn dung lượng (~3,35 GB đĩa + 2,73 GB Docker), Code chết & Tài liệu lệch

Thực hiện trước khi viết tính năng mới để repo nhẹ, sạch và tài liệu khớp 100% với code:

1. **Giải phóng dung lượng rác không ảnh hưởng git/gate (~3,35 GB trên đĩa + 2,73 GB Docker):**
   - Xoá ở root: `google-chrome-stable_current_amd64.deb` (139 MB), `go1.25.4.linux-amd64.tar.gz` (57 MB), thư mục rỗng `spike/`.
   - Dọn `bin/` (2,1 GB → ~44 MB): xoá toàn bộ thư mục chạy nháp/log cũ (`refresh-measure`, `guardreply-measure`, `regress`, `c4try`, `dbg*`, `all-gates.sh`, binary `spike*`/`jsharvest-race`), build lại `bin/jsharvest` và `bin/testbed`.
   - Dọn `testbed/apps/*/node_modules` (1,02 GB trên 7 app đã có sẵn `dist/`). **Giữ lại `testbed/playwright/node_modules` (8,2 MB)** để `PLAYWRIGHT=1 testbed/flows-gate.sh` chạy offline không cần kéo mạng.
   - Dọn `output/` (giữ bắt buộc `output/_live_25e_max` cho `TestSnapshot`/`perfgate` và `groundtruth_v4.json`): xoá `_baseline_crawls` (182 MB), `_live_25d` (125 MB), `_round30_*` chạy thử, các `.log` lẻ, `n8n-2.12.3-src/` (31 MB), `__pycache__/` và các snapshot `baseline_v18..v33` cũ.
   - Gỡ `devtools/worker/` (đã thay bằng bản chụp worker ngoài repo `$SNAP_DIR`) + xoá Docker image `jsh-worker:1` (2,73 GB) và 3 volume `jsh-cred-agy`, `jsh-cred-claude`, `jsh-gocache` (**giữ nguyên** 4 volume `jshlab_*` của lab BOLA).
2. **Dọn code chết & công cụ đo 28B đã xong nhiệm vụ (có kiểm chứng tránh 6 bẫy):**
   - Xoá các thành phần 0-caller đã xác minh: `oaBody.exOrder`, `Rect.{X,Y}`, `tlsutil.ErrPrivate`, `(*AIA).Verify` (giữ `a.verify` nội bộ), `(*Dialer).DialTLSContext` (kèm test riêng không dùng), `httpcrawl.Result.Warnings`, `crawler.add`, `store.touched` + `TakeTouched`, `jsapi.EvalBuilder` (hàm rời), `jsapi.pathForward`, `jsapi.IsMark`, `archive.pathRe`, `session.ErrLost`, `(Draft).Key`, `sourcemap.Guesses.Held`, `Map.Paths`, `marker.SourceURL`; chuyển `archive.NewClient` vào `client_test.go` (unexported) để khoá chặt API bỏ qua `netsafe`; đồng bộ hằng `Version` cho `mcpserver` ở `cmd/jsharvest/main.go:787`.
   - Gỡ bộ script đo 28B đã hoàn tất (`testbed/refresh-measure.sh`, `testbed/guardreply-measure.sh`, `testbed/timers-measure.sh` + `timerscore.go`/`timers.go`/`timers.truth.json`, công tắc `JSHARVEST_GUARD_REPLY`).
   - **Không xoá:** `internal/jsapi/dump_test.go` (`TestStats`/`TestDump` đang dùng trong quy trình chuẩn), `analyze_bench_test.go`, `pipeline_bench_test.go`, `replay.Block*` (đang dùng ở `replay`), `testbed/gate_test.go` (chỉ sửa docstring), `testbed/external/run.sh` (`mazescore`). Thay thế đường dẫn tên miền cũ trong `internal/resolve/vrp_test.go`.
3. **Đồng bộ `CLAUDE.md` (về `≤ 20 KB`) & `docs/`:**
   - Sửa 5 điểm sai lệch trong `CLAUDE.md` (bỏ `jsluice`, bỏ `Profiler` coverage, bỏ `maps/ inline/`, cập nhật trạng thái Docker đã hoàn tất, cập nhật tên `pf-8d1e7b.js` / `rt-4f9c2a.js`).
   - Xoá `docs/session-2026-11-02.jsonl` (436 KB log thô trùng với `.md`), đánh dấu rõ mục đã huỷ/đóng trong `docs/plan-28.md`, dọn 3 file nháp untracked ở root và các báo cáo sơ khai ngày 02–03/11 đã bị thay thế (**giữ nguyên** toàn bộ `docs/gd4-*-design.md`, `gd5-*.md`, `gd6-waf-design.md`, `gd7-bola-design.md` đang được bảng kiến trúc và code tham chiếu).

### 5.1. Thứ tự thực thi theo Phase

Chia thành 5 phase tuần tự theo mức độ phụ thuộc dữ liệu và ranh giới tin cậy:

| Phase | Mục đặc tả | Ranh giới tin cậy | Tệp chính dự kiến chạm | Phụ thuộc |
|---|---|---|---|---|
| **P0-Hygiene** | **5.0** (Dọn ổ đĩa, Docker worker, dead code 0-caller, tài liệu `CLAUDE.md` & `docs/`) | Nền tảng toàn repo | `CLAUDE.md`, `docs/`, `devtools/worker/`, dead code các gói `internal/*`, `testbed/` | Làm đầu tiên, chốt mốc `go test` xanh |
| **P1-Offline** | **2.4** (`export -format all`), **2.3** (`secretsig` + `jsapi` keys + `mcpserver`), **2.2** (Router AST Walker) + tách `isTrackerDomain` khỏi `App-Referenced` (`D2`) | **B0, B4** (Offline đọc đĩa, xuất báo cáo & che bí mật MCP — không chạm mạng) | `cmd/jsharvest/export.go`, `internal/secretsig/*`, `internal/jsapi/{routes.go,jsapi.go,strings.go,calls.go}`, `internal/endpoints/{endpoints.go,intel.go}`, `internal/mcpserver/scripts.go` | Sau P0 |
| **P1-Bundler** | **2.1** (Webpack 3/4/5 + `webpackAsyncContext` + liên kết `runtimeChunk` liên script) | **B0 × B1** (Giải mã ứng viên script tĩnh → hàng đợi tải script) | `internal/resolve/static.go`, `internal/httpcrawl/crawl.go`, `internal/engine/` | Sau P1-Offline |
| **P2-Context** | **3.1** (Spec Probe 2 pha có ngữ cảnh), **3.3** (SSO/OIDC thụ động), **3.2** (Cloud cấu trúc + kiểm tra quyền mặc định qua `netsafe`) | **B0, B1, B3** (Thăm dò mạng có kiểm soát rate/header & phân tích phản hồi) | `internal/frontier/queue.go`, `internal/httpcrawl/crawl.go`, `internal/engine/frontier.go`, `internal/endpoints/{intel.go,infra.go}`, `internal/verify/verify.go` | Sau P1 |
| **P3-Semantics** | **4.1** (`client_authz` RBAC/CASL + `RouteMeta`), **4.2** (Terser `+=`/`=` & `.map()` 2 chặng) + nâng chốt `jsapi.Version = 37` | **B0** (AST chuyên sâu, hiệu năng & độ chính xác tĩnh) | `internal/jsapi/{authz.go,defs.go,eval.go,calls.go}`, `internal/endpoints/intel.go` | Dùng `RouteEntries` đã dựng ở Mục 2.2 |

### 5.2. Bảng Gate bắt buộc theo từng Phase

Mọi thay đổi phải vượt qua unit test của chính gói đó **và** các gate tích hợp tương ứng:

- **Sau P1-Offline & P1-Bundler:**
  - `go test ./internal/secretsig/... ./internal/resolve/... ./internal/jsapi/... ./internal/endpoints/... ./cmd/jsharvest/...`
  - Kiểm đối chứng `TestSnapshot` & `TestStats` của `jsapi` (mọi thay đổi trên tập snapshot phải là endpoint/route/key thật được mở thêm, 0 dương tính giả).
  - Gate tích hợp: `export-check`, `endpoints-check`, `frontier-check`, `pipeline-check`, `flows-check MCP=1`.
- **Sau P2-Context:**
  - `go test ./internal/frontier/... ./internal/httpcrawl/... ./internal/verify/... ./internal/endpoints/...`
  - Gate tích hợp: `pipeline-check`, `waf-check`, `verify-check`, `proxy-check` (xác nhận `-check-cloud` và Pha 2 Spec Probe tuyệt đối không rò kết nối trực tiếp ngoài proxy).
- **Sau P3-Semantics & Nghiệm thu tổng thể Đợt 31:**
  - `perfgate` (3 lần chạy lấy trung vị: thời gian `≤ 15 s`, RSS đỉnh `≤ 500 MB`).
  - Rà quét sạch 100% (0 chuỗi vi phạm từ khoá nhạy cảm).
  - Toàn bộ bộ hồi quy: `DOCKER=1 testbed/regress.sh -j 3` xanh trên tất cả các gate.

### 5.3. Chỉ tiêu nghiệm thu định lượng (Benchmark Kỳ vọng sau Đợt 31)

Đối chiếu trên kiến trúc ứng dụng tương đương bài đo chuẩn (SPA đa bundle Webpack 3/4/5 + cổng API tập trung + phân quyền CASL/RBAC + Cloud/SSO):

| Hạng mục đo lường | Trước Đợt 31 (`8dfc0be`) | Mục tiêu sau Đợt 31 | Cơ chế kiến trúc giải quyết |
|---|---|---|---|
| Độ phủ Webpack Lazy Chunks (gồm Webpack 3/4 & `webpackAsyncContext`) | `0%` (trên Webpack 4 inline/`asyncContext`) | **`100%`** | Mục 2.1 |
| Độ phủ Route giao diện SPA có phân cấp (`children` lồng nhau) | `~51,5%` | **`≥ 98%`** | Mục 2.2 |
| Độ phủ khoá API nhúng cứng (gồm thuộc tính tên ngắn `{key: "AIza..."}`) | `75%` | **`100%`** (0 nhiễu base64/UI) | Mục 2.3 |
| Xuất đồng thời `openapi.json` + `drafts/` ở `-engine http` (`-format all`) | Lỗi thoát sớm / thiếu `openapi.json` | **`100%`** tạo đủ tệp | Mục 2.4 |
| Thăm dò đặc tả OpenAPI/Swagger sau cổng `/api-gateway` có `client_headers` | Chỉ hỏi gốc `/` không ngữ cảnh | **Tự động 2 pha** (`≤ 46` GET có cầu chì) | Mục 3.1 |
| Phân loại trạng thái Cloud Bucket & bóc tách tham số SSO/OIDC pre-auth | URL thô / phải đọc tay body | **Tự động cấu trúc hoá trong `intel.json`** | Mục 3.2, 3.3 |
| Trích xuất bề mặt phân quyền client (`roles`, CASL `$can`, `public_routes`) | `0%` (chưa có trường dữ liệu) | **Đầy đủ trong `intel.json` (`client_authz`)** | Mục 4.1 |
| Định trị đường dẫn API qua gán lồng Terser (`t += ...`) & `.map()` 2 chặng | `~98,9%` | **`100%`** | Mục 4.2 |

---

## 6. Quyết định kiến trúc (`D1`–`D4`)

1. **`D1` — Đã chốt:** Gộp `routes` và `client_authz` trực tiếp vào `intel.json` để cả CLI lẫn MCP `get_intel` tra cứu thống nhất một nơi.
2. **`D2` — Đã chốt:** Mọi tài nguyên được ứng dụng thực sự nạp/tham chiếu (bundle trên CDN riêng, Cloud Storage bucket, SSO/IdP, API khác domain không thuộc danh sách tracker/analytics rác) **đều thuộc phạm vi đánh giá mặc định (`in-scope`)**. Việc kiểm tra quyền đọc/liệt kê Cloud Bucket chạy mặc định qua `netsafe` + `-proxy` (có `-no-cloud-probe` khi cần chạy thuần offline).
3. **`D3` — Đã chốt (tạm áp dụng mặc định, theo dõi thực tế về sau):** Cơ chế tự phanh chống khoá IP khi dò tìm file Swagger/OpenAPI ẩn:
   - Hỏi đủ bộ đường dẫn Swagger ở gốc gateway; với các dịch vụ con chỉ hỏi 2 đường dẫn chuẩn nhất (`/v3/api-docs`, `/v2/api-docs`) trên nhóm dịch vụ chính; và **tự phanh ngay** nếu 2–3 lần thử đầu bị gateway trả về cùng một trang chặn `401`/`403` hoặc cùng vỏ HTML (có `-no-spec-probe` nếu cần tắt hẳn).
4. **`D4` — Đã chốt:** Orchestrator trực tiếp điều phối thực thi tuần tự từng commit TDD (`P0` → `P1` → `P2` → `P3`) trên cây chính và tự chạy lại toàn bộ gate hồi quy.
