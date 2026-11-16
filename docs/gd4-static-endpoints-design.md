# GĐ4 4.3b — Endpoint từ JS: từ lúc chưa chạy đến lúc chạy

**Mục tiêu (plan).** Trích các lời gọi API từ mọi script trong store, kể cả chunk chưa từng chạy (chunk admin khi đang là `anon`). Mỗi endpoint ghi method, path, tên tham số, `source: static_js`, đặt cạnh traffic quan sát được. Lọc nhiễu theo kiểu xnLinkFinder (theo tài liệu đánh giá độc lập, dòng 1157).

**Mở rộng theo yêu cầu "từ lúc chưa chạy đến lúc chạy".** Mỗi endpoint có một vòng đời:
- `static`: chỉ thấy trong code, chưa chạy;
- `both`: vừa có trong code vừa đã thấy request thật;
- `observed`: chỉ thấy trong traffic, ví dụ URL dựng động hoặc script không có trong store.

Agent hoặc người dùng dùng danh sách `static` làm việc cần làm: những tính năng còn lại để thao tác (4.6) hoặc để fuzz (4.8).

**Cổng nghiệm thu (plan).** Khi chạy role `anon`, các API chỉ nằm trong chunk admin phải được liệt kê.

## 1. Spike: jsluice hay tự viết

**Fixture.** `testbed/apps/endpoints-app`, build bằng webpack 5 production (terser). Fixture có 26 endpoint, mỗi endpoint là một idiom thật:
- `fetch` với template literal và `URLSearchParams`; `fetch` POST có body JSON và header;
- client kiểu axios có `baseURL`; wrapper `request(method, url)`; XHR; `$.ajax` / `$.post`;
- GraphQL; WebSocket; EventSource; `sendBeacon`; URL tuyệt đối; URL lấy từ object cấu hình; `window.open`;
- 5 endpoint chỉ có trong chunk admin, chỉ chạy khi `/api/me` trả về role admin.

Fixture còn có route phía client và chuỗi nhiễu: MIME, path SVG, ngày, `yyyy/mm/dd`, module `./x.js`, `16/9`, chữ "and/or".

**Hai phát hiện khi build fixture.**
- Bản viết đầu bị webpack tree-shake gần hết: export không dùng thì bị xoá, lời gọi với tham số hằng bị gập lại. Fixture được viết lại để mọi lời gọi nhận giá trị từ trang, như trong app thật.
- **Sau khi minify, tên thư viện biến mất:** `$.ajax` thành `i({url,type})`, `$.post` thành `s(url,data)`, client axios thành `r.LV.post(...)`, wrapper thành `(0,r.Em)("PUT",url,…)`. Extractor vì vậy phải nhận diện theo **hình dạng lời gọi**, không theo tên.

**Kết quả jsluice** (`BishopFox/jsluice`, commit cuối 2024-01, cần CGo/tree-sitter):

| Ca | Kết quả |
|---|---|
| Template literal có biến (`` `${l}/articles/${e}` ``, `` `/api/admin/users/${e}` ``) | trượt, kể cả `DELETE /api/admin/users/{id}` của admin |
| Nối chuỗi với biến hằng (`l+"/articles"`) | trượt |
| Method qua wrapper (`Em("PUT",url)`) hoặc `.post` / `.put` | để trống |
| Tham số body (`JSON.stringify({...})`) | không lấy được tham số nào |
| Nhiễu | báo cả `./utils/format.js`, `.3fd8376a.chunk.js`, `/api`, `/comments`, các route |

**Quyết định.** Tự viết bằng Go thuần, dùng parser `github.com/tdewolff/parse/v2/js`:
- hỗ trợ ES2020+, phát hành 2026-10, không có dependency, giữ được `CGO_ENABLED=0`;
- tham chiếu biến được nối vào cùng một `*js.Var` theo scope, nên giải hằng đúng scope mà không cần tự dựng bảng ký hiệu;
- AST không mang vị trí, nên dòng và cột được tìm lại bằng cách dò mảnh literal dài nhất trong source.

## 2. Extractor (`internal/jsapi`, hàm thuần)

**Ước lượng biểu thức URL thành template:**
- literal và template literal; `+` và `.concat`;
- biến hằng (một lần gán bằng chuỗi, đúng scope);
- thuộc tính của object hằng (`ENDPOINTS.upload`);
- `location.origin` / `location.host` được hiểu là cùng origin;
- phần không biết được thay bằng `{}`;
- `new URLSearchParams({...})` cho ra tên các tham số query.

**Nhận diện lời gọi theo hình dạng:**

| Kind | Nhận diện | Method |
|---|---|---|
| `fetch` | `fetch(url, opts)` / `new Request(url, opts)` | `opts.method`, mặc định GET |
| `xhr` | `x.open("POST", url)` | đối số 1 |
| `client` | `X.get/post/put/patch/delete/head(url, data, config)` | tên method; base lấy từ `baseURL` |
| `wrapper` | lời gọi bất kỳ có đối số URL, cùng một đối số là tên method HTTP, hoặc object có `method`/`type` | theo đối số |
| `options` | lời gọi có object `{url: …, type/method, data, params}` | `type`/`method` |
| `websocket`, `sse`, `beacon` | `new WebSocket`, `new EventSource`, `navigator.sendBeacon` | —, GET, POST |
| `navigation` | `window.open`, `location.assign/replace`, gán `location.href` | GET |

Ngoài ra:
- **Tham số:** body là key của object trong `JSON.stringify`, `URLSearchParams` hoặc tham số `data` (lấy đến độ sâu 2, dạng `user.email`); query là key của `params` và `URLSearchParams`, cộng các tên trong chuỗi `?a=`; header là key của `headers`.
- **GraphQL:** chuỗi `query|mutation|subscription Tên` gắn vào lời gọi chứa nó.
- **Chuỗi đứng riêng** (không nằm trong lời gọi nào) chỉ được báo khi trông giống API: có `/api/`, `/v1/`, `/graphql`, `/rest/`, hoặc là URL tuyệt đối. Những chuỗi này có `kind: string` và độ tin cậy thấp.
- **Route:** giá trị `path: "/…"` trong object được báo là `route`, không phải API. Danh sách này sẽ là đầu vào cho frontier (4.4).
- **Nhiễu bị loại** cả trong lời gọi: MIME, path SVG, ngày / số / tỉ lệ, chuỗi định dạng ngày, `./` và `../`, file tĩnh (`.js .css .png …`), namespace w3.org, chuỗi có khoảng trắng, `/` đứng một mình, URL toàn `{}`.
- **Parse lỗi** thì không báo gì kèm `error` (không fallback sang regex, để tránh nhiễu), và có test.

## 3. Danh mục theo role (`internal/endpoints`)

**Cache tĩnh.** Mỗi script có một file `static/<sha256>.json` ghi phiên bản extractor; đổi phiên bản thì phân tích lại.
- Engine đưa script mới vào hàng đợi phân tích nền ngay khi lưu, nên cache được lấp dần trong lúc `watch`.
- `finish` phân tích bù những script còn thiếu.

**Gộp tĩnh với quan sát** thành `endpoints.jsonl` cho mỗi `<host>/<role>`, gồm mọi run. Thứ tự gộp:
1. Request trong `requests.jsonl` được đối chiếu với pattern tĩnh: path khớp theo segment, `{}` khớp một hoặc nhiều segment; method phải khớp nếu cả hai bên đều biết. Khớp thì endpoint thành `both`, và dùng template của code (tốt hơn suy đoán theo hình dạng: slug cũng được nhận ra là giá trị).
2. Endpoint tĩnh chưa có base (lời gọi kiểu `client`) được thử với các `baseURL` thấy trong store. Nếu đúng một base khớp với request quan sát, base đó được xác nhận; nếu không, base được ghi là ứng viên.
3. Request còn lại được gom theo `flow.Templates` và có trạng thái `observed`.

**Mỗi dòng** gồm: `method`, `host` (rỗng là cùng origin), `path`, `query[]`, `body[]`, `headers[]`, `operations[]`, `kind`, `status`, `static[]` (sha256, URL của script, dòng, cột, kind, đoạn code), `observed` (số request, lần đầu, lần cuối, mẫu, outcome, thao tác trong `flows`), `third_party`.

**Đầu vào:**
- `jsharvest crawl` / `watch` ghi `endpoints.jsonl` khi kết thúc;
- `jsharvest endpoints -o OUT [-target -role]` dựng lại khi không chạy;
- MCP tool `endpoints` có thêm `status=static|observed|both|all`, nên agent hỏi được "endpoint nào có trong code mà chưa chạy".

## 4. Kiểm thử và gate

- **Unit** cho `jsapi`: từng idiom; nhiễu; giải hằng theo scope (cùng tên ở scope khác không bị nhầm); parse lỗi; độ dài cực lớn.
- **`testbed epscore`** trên `endpoints-app`, khi `crawl` với role `anon` và `-resolve`:
  - recall ≥ 24/26 (theo path);
  - method đúng ở mọi endpoint mà code cho phép biết;
  - 0 chuỗi nhiễu, 0 route bị báo là API;
  - 5/5 endpoint admin có `status: static`;
  - các endpoint gọi lúc tải trang có `both`.
- **`flows-app` qua `flows-check`:** mọi request mà truth mong đợi phải có endpoint `both`. Đây là phép đo recall của phân tích tĩnh, đối chiếu với runtime trên code chưa minify.
- **Nhiễu trên thư viện thật** (đã có trong `node_modules` của testbed: react-dom, các chunk Next, Angular): đếm endpoint loại lời gọi mà extractor báo trên code không phải của app; kết quả phải gần 0. Đo thêm tốc độ (MB/s) trên bundle lớn.
- Bench gate và flows gate không được giảm.

## 5. Sửa đổi khi làm

- **Resolver bỏ sót mọi chunk của runtime webpack không có bảng chunk.** Dạng này gặp khi app chỉ có một chunk lazy (`.u=e=>"static/js/"+e+".3fd8376a.chunk.js"`) hoặc khi build dùng `chunkFilename: "[id].js"` (`.u=e=>e+".js"`). Cách sửa: `resolve.webpackPlain` ghép tiền tố, id và hậu tố, trong đó id lấy từ các lời gọi `X.e(id)` của runtime. Có test cho cả hai dạng. Trên fixture, chunk admin trước đây không được tải.
- **Biến đếm vòng lặp bị coi là hằng.** `for(let i=0;…;i++)` cho ra `/api/upload/0`. Giờ `++`, `--` và mọi phép gán kết hợp (`-=`, `*=`, `??=` …) đều làm biến mất tư cách hằng. Phát hiện được nhờ phép đo trên `flows-app`. `jsapi.Version` tăng lên 2 để cache cũ được phân tích lại.
- **Tham chiếu từ scope lồng.** Trong tdewolff, một tham chiếu nằm trong scope con là một `*js.Var` riêng, mang `NoDecl` và có `Link` trỏ về biến đã khai báo. `DotExpr.Y` là `LiteralExpr` dạng giá trị chứ không phải con trỏ. Lượt đầu bỏ sót cả hai, làm mọi lời gọi qua member và mọi hằng dùng trong hàm đều trượt. Đã có test cho scope.
- **Nhiễu trên code thật** có 3 nguồn. Mỗi nguồn được xử lý bằng một quy tắc riêng, không phải danh sách chặn theo từng app:
  - link tài liệu (`react.dev`, `angular.dev`) và chuỗi test của polyfill URL (`http://n`, `https://тест`): URL tuyệt đối phải có host thật, và chuỗi đứng riêng phải có path trông giống API;
  - `startsWith("/api/")` và `console.error(url)`: lời gọi tới method của string hoặc console không được coi là request;
  - `Map.get("@babel/…")`, `require("json/parse")`, `path.join(d,"package.json")`: dùng 3 mức chắc chắn `sure`, `call`, `weak`; đường dẫn tương đối chỉ được chấp nhận khi chắc là có request.
- **Helper một cấp.** Hàm `s=(e,t)=>fetch(e,{method:"POST",…})` được tóm tắt: tham số URL, method và tham số body. Nhờ vậy `s("/api/users/login",{email,password})` ra được `POST` kèm tham số.
- **Fixture lần đầu bị tree-shake gần hết**, và nút Publish gọi `createArticle()` không có đối số. Gate đã bắt được lỗi thứ hai.
- **Snapshot của `watch` có lần ngừng khoảng 20 giây** (chập chờn, chưa tái hiện được). Chu kỳ tick được tính bằng 20 lần thời gian của lần ghi vừa rồi, *tính cả I/O*, nên chỉ một lần ghi chậm 0,5 giây đã đẩy tick kế tiếp ra 10 giây. Đây là giả thuyết, đã có biện pháp giảm thiểu nhưng chưa được chứng minh:
  - chỉ đo phần gom cụm;
  - làm mượt bằng trung bình trượt;
  - giới hạn chu kỳ tối đa 30 giây;
  - ghi cảnh báo khi một snapshot quá 0,5 giây.

  Sau khi sửa, 3 lần chạy liên tiếp đều 6/6.
- **Đối chiếu với traffic** dùng index theo segment hiếm nhất của mỗi endpoint. Benchmark 20k request × 2000 endpoint giảm từ 1,17 giây xuống 0,15 giây.

## 6. Kết quả

**`endpoints-app`** (webpack production, 26 endpoint, 5 trong chunk admin):

| | jsluice | jsharvest |
|---|---|---|
| Path tìm được | khoảng 19/26 (tính dễ dãi: chấp nhận khi thiếu base `/api`) | **26/26** |
| Method đúng | 8/26 | **26/26** (gồm wrapper, helper, client) |
| Tham số body, query, header | 0 | **đủ theo truth** |
| Endpoint admin (role `anon`) | 4/5 (trượt `DELETE /api/admin/users/{id}`) | **5/5** |
| Nhiễu và route bị báo là URL | ≥ 9 | **0** (route tách riêng ra `routes`) |
| Trạng thái từ chưa chạy đến đã chạy | — | **đúng 26/26** ở cả 2 thời điểm |

**Gate `testbed/endpoints-check.sh`** (đạt 3 lần liên tiếp):
1. **Chưa chạy:** `crawl` với role `anon` đạt 26/26. 4 endpoint gọi lúc tải trang là `both`, 22 endpoint còn lại là `static`.
2. **Đang chạy:** `watch` cùng driver bấm 6 nút; MCP `last_action` đạt 6/6, và MCP `endpoints status=static` liệt kê đủ 5 endpoint admin.
3. **Đã chạy:** cả 6 endpoint vừa bấm chuyển sang `both`; base `/api` của client được traffic xác nhận; các endpoint còn lại giữ nguyên.

**`flows-app`** (app viết tay, 17 tính năng): 29/29 endpoint quan sát được đều có trong code. Kiểm tra này nằm trong `flows-check.sh` và chạy ở mọi lượt của flows gate.

**Code không phải của app:**

| Bộ mẫu | Kích thước | Lỗi parse | Tốc độ | Endpoint báo ra |
|---|---|---|---|---|
| Bundle trình duyệt của testbed (React, Next, Angular) | 116 file, 2,3 MB | 0 | 5–7 MB/s | chỉ endpoint thật của app; 0 nhiễu từ framework |
| `node_modules` | 181 file, 100 MB | 0 | 7–11 MB/s | chủ yếu là lời gọi `fetch` thật trong code Node (`localhost`, figma, fonts, dev overlay của Next) cùng vài chuỗi URL tuyệt đối của AMP |

## 7. Giới hạn

- **Base của client chỉ là ứng viên khi chưa có traffic.** Lấy từ `baseURL` (một hoặc nhiều giá trị). Base chỉ được xác nhận khi có request khớp. Base được tính trên cả store của role, không theo từng bundle.
- **Helper chỉ được tóm tắt một cấp, và chỉ helper gọi `fetch`.** Không tóm tắt helper gọi XHR hay helper lồng helper. Client gọi qua object export của module webpack (`r.LV.post`) vẫn nhận diện được nhờ tên method, nhưng wrapper qua export không có method literal thì chỉ được nhận khi path trông giống API.
- **URL ghép từ dữ liệu lúc chạy** (cấu hình tải về, `import.meta.env` đã bị thay giá trị) ra `{}`.
- **Không phân tích code nằm trong chuỗi** `eval` / `new Function`. Code này có trong store dưới dạng script `eval` riêng, và được phân tích như mọi script khác.
- **Script lớn hơn 16 MB** không được phân tích.
- **Trong MCP**, danh mục được dựng lại ở mỗi lần gọi (đọc cache tĩnh và index request). Nhanh với kích thước của testbed; nếu chậm trên target lớn thì cần cache theo trạng thái file.

## 8. Hai lần lỗi chập chờn khi chạy toàn bộ gate (ghi lại, chưa sửa)

- **Bench `flows-app`, REQCHECK:** server có 21 `GET /api/heartbeat`, log có 20. Request thiếu được gửi ở giây cuối của run.
  - Đo được: sau `h.Stop()` còn khoảng 7–9 ms công việc, trong đó việc dựng danh mục chiếm 6–7 ms. Khoảng hở lớn hơn nhiều nằm ở lúc đóng trình duyệt, trong khi timer của trang vẫn chạy. Khoảng hở này có từ GĐ4.2.
  - Kết quả lặp lại: 0 lỗi trong 5 lần chạy riêng `flows-app`.
  - Cách sửa đúng, để làm sau: với tab của chính tool, đóng băng trang (`Page.setWebLifecycleState frozen`) trước khi dừng capture.
- **Flows gate, lượt nhanh: "USER TAB CLOSED".** Lặp lại 3 lần đều đạt. Code mới của `watch` (phân tích nền, danh mục) không gửi lệnh CDP nào. Log của lần lỗi đã bị ghi đè, nên `flows-check.sh` giờ in danh sách tab và giữ lại thư mục chạy mỗi khi lỗi này xảy ra.

## 9. Đợt 15 (OPT-01 → OPT-07, 2026-11-08)

Phân tích `app.js` (3,48 MB, Vue 2 + Babel, axios với `baseURL` tính lúc chạy) của `admin.target-a.example`. Mọi khẳng định đã được kiểm lại trên chính file đó trước khi sửa. `jsapi.Version` lên 7.

**Đã làm:**
- **Ước lượng ra nhiều giá trị.** `eval` trả về tối đa 16 template thay vì một (`maxAlts`). Hai vế của `?:`, `||`/`??`, `obj[key]` với key không biết (mỗi giá trị có `/` của object hằng), biến được gán nhiều lần: mỗi trường hợp là một endpoint. Vượt 16 thì coi là bảng dữ liệu và trả `{}`.
- **Chuỗi gán của biến** (`chains`, thay cho "gán hai lần thì không biết"). Mỗi phép gán thường mở một chuỗi. `t += x`, `t = "".concat(t, …)` và `t = new B(t).x()` nối vào chuỗi cuối, và lúc ước lượng thì biến được thay bằng giá trị trước đó (`bind`).
  - Phép gán nằm dưới một điều kiện mà khai báo không nằm dưới (`a && (t += x)`) thì giữ cả giá trị trước nó.
  - Hai phép gán ở **hai nhánh của cùng một if / `?:` / switch** là anh em: kết quả là một trong hai, không bao giờ là giá trị trước cả hai. Trước khi sửa điểm này, bản đầu đã sinh ra `…/detailsize={}`.
  - Biến đếm (`i++`, `k *= 2`) vẫn ra `{}`, như trước.
- **`.replace` / `.replaceAll`.** Pattern là chuỗi, hoặc regexp chỉ gồm chữ thường (`/report-vehicle/g`). Pattern không đọc được thì giữ nguyên chuỗi. `cleanURL` đổi `{id}`, `{<name>_id}` thành `{}`.
- **Builder:** `new B(url).ctx(e).sortBy(…).toRequest()` cho ra `url`, với điều kiện `B` là class của app, không phải class của trình duyệt.
- **`this.<prop>`** lấy từ mọi phép gán `this.x = …` (và qua alias `e = this`) trong cả script, cộng giá trị khởi tạo trong `data()` của Vue. Gom theo tên trên toàn script, vì prop thường do component cha gán (`detailUrl`). `keys(this.loginForm)` chỉ dùng khi tên đó có đúng một object literal: `this.form` ở 30 component thì không nói được gì.
- **Tham số:** `<bất kỳ>.stringify(x)` (gồm `qs.stringify`), `Object.assign(…)`, và `obj.prop` của object hằng.
- **Base động.** `baseURL` không phải literal thì được ước lượng sau pass 1. Nếu vẫn không ra (`e.getURL(qn.c.API)`), ứng viên là các chuỗi có dạng gốc của API (`/api-gateway/`, `/api/v1`) mà không phải route của trang; có nhiều ứng viên thì ưu tiên chuỗi có `/` ở cuối; tối đa 3 ứng viên. Base bị bỏ khỏi `routes`/`paths`, nên frontier không còn thăm `/api-gateway/`.
- **Path tương đối có đoạn version** (`relAPIRe`: `<service>/v1.0/…`) được nhận trong lời gọi helper của app không có method (trước đây bị bỏ), và trong chuỗi đứng riêng. Path như vậy trong `wrapper`/`options` có `client: true`, nên catalog gắn `bases`. Ngưỡng chặt hơn đề xuất (`apiLike`) vì `require("json/parse")` cũng khớp `apiLike`.
- **`concat` thuộc `stringMethods`**, và chuỗi `"".concat(…)` đứng riêng được đọc như `a + b`. Các mảnh của một chuỗi ghép không còn là path riêng, nên `"".concat("app", "/setDeviceState")` của Vuex không còn là route. Ghép trong lời gọi (`fetch(base + "/x")`) thì không sinh thêm endpoint `string`.
- **Bundle thư viện** (`frontier.Vendor`: `vendors.js`, `chunk-vendors.*`, `vendors~main`, `vendors-node_modules_*`, `polyfills`, `runtime`, `framework-<hash>`): `FromScript(…, vendor=true)` bỏ routes và paths, giữ navigation. Engine HTTP giải path của script theo URL **trang** (trước đây theo URL của script).
- **Header và cloud** (`Result.ClientHeaders`, `Result.Cloud`).
  - Header: gán `*.headers.X = v`, `*.headers["X"] = v`, `defaults.headers.common.X`, và `headers` của `create({…})`, kèm giá trị dạng template (`Bearer {}`).
  - Cloud: URL S3, GCS, Azure blob, Spaces, R2, Firebase, OSS, B2, Wasabi trong mọi chuỗi.
  - Kết quả ghi vào `<role>/intel.json` (0600; `endpoints.SaveIntel`), chỉ lấy từ script của target. File được viết bởi `crawl`/`watch` (khi có `-redact` thì giá trị bị che), lệnh `endpoints` và `archive` (secret cũ có thể vẫn dùng được).
  - Log chỉ in **tên** header, không in giá trị.
- `locate` dùng bảng đầu dòng: bundle một dòng 3,4 MB trước đây quét lại từ đầu cho mỗi endpoint.

**Không làm theo đề xuất:**
- Không suy query từ tên method của builder (`.sortBy` → `sort=`?). Tên tham số thật nằm trong class builder, đoán thì sai.
- Không tự gắn header của intel vào `authz`/`export`. Hai lệnh này dùng traffic thật, vốn đã mang các header đó. Ghép header vào endpoint chỉ có trong code là việc của bước thăm dò endpoint tĩnh (đã để sau ở 5.1).

**Kết quả** (`jsharvest endpoints -target admin.target-a.example -scope fqdn`, chỉ đọc output, không gửi request):
- `app.js`: 214 → 396 endpoint.
  - Không mất endpoint nào. 26 endpoint trước đây `kind: string` giờ có method.
  - Có đủ các endpoint được kiểm tra: RBAC `system-user/v1.0/admin/roles/{}`…, OAuth/LDAP `v1.0/*/oauth/token` có body `grant_type, username, password, client_id, captcha_*`, GPS, `iot-device/report` (cả item batch), firmware, dump.
- Catalog: 392 dòng, 387 có `bases: ["/api-gateway"]`.
- `intel.json`: `client_id`, `client_secret`, `app_version = 1.14`, `Authorization = Bearer {}`…, và 9 URL S3 khác nhau (reviewer đếm 10 là tính cả URL lặp).
- Thời gian phân tích `app.js`: 0,94 s → 1,29 s.
- `vendors.js` không còn route rác vào frontier.
- 43 file JS của testbed: kết quả cũ/mới giống hệt.
- 387 file thư viện (khoảng 178 MB, JS của VS Code và node_modules): mất 18 dòng nhiễu (`/windows/system32/…/powershell.exe`…), thêm 77 dòng, chủ yếu là URL tuyệt đối đầy đủ thay cho `"/v2/track"` cụt, và endpoint thật của SDK.

**Giới hạn:**
- Phân tích không theo luồng: một biến được gán trong callback được coi như gán tuần tự.
- `this.<prop>` gom theo tên trên toàn script, nên method của component A có thể đi kèm URL do component B gán.
- Chỉ có khi nhận diện được base động bằng chuỗi gốc API. Base lấy từ cấu hình tải về lúc chạy thì vẫn không biết.
