# GĐ4 4.7 — So sánh giữa các role

**Mục tiêu** (plan bản 2, mục 4.7; bản 1, mục 4.5). Từ dữ liệu `crawl` của nhiều role trên cùng một host, chỉ ra những gì role cao hơn dùng được mà role thấp hơn không dùng được: script, endpoint, trang và tính năng. Mỗi mục kèm bằng chứng, để làm đầu vào cho việc kiểm thử phân quyền theo kiểu Autorize (gửi lại request của role cao bằng session của role thấp; việc gửi đó thuộc 4.8/GĐ5).

**Chỉ đọc dữ liệu, không gửi request nào.** Lệnh `diff` chỉ đọc các thư mục output.

**Cổng nghiệm thu (plan):** chỉ ra được tính năng và endpoint chỉ có ở admin trên testbed. Cụ thể hơn, mục 6.

## 1. Đầu vào

```
<out>/<host>/<role>/  index.jsonl  endpoints.jsonl  flows.jsonl  pages.jsonl  requests.jsonl  runs.jsonl  run.json
```

- **Role được sắp từ thấp đến cao** bằng `-roles anon,user,admin`. Mặc định: `anon` (hoặc `default`) đứng đầu, `admin` đứng cuối, các role còn lại theo thứ tự chữ cái, và lệnh in ra thứ tự đã dùng.
- **Dữ liệu của mỗi role là toàn bộ thư mục role đó**, tức hợp của mọi run, vì đó là những gì role ấy đã thấy.
- **Kiểm tra mức tương đương.** `run.json` có thêm `config`: `depth`, `explore`, `resolve`, `max_pages`, `guard`. Nếu các role được crawl khác nhau, `diff` cảnh báo rõ: "admin explore, anon không", vì khi đó "chỉ admin có" có thể chỉ là do admin được crawl kỹ hơn. Dữ liệu cũ không có `config` thì báo là "không rõ".

## 2. Mô hình: ma trận trạng thái theo role

Mỗi **mục** (script, endpoint, trang, tính năng) có một trạng thái cho từng role:

| Trạng thái | Ý nghĩa |
|---|---|
| `absent` | Role này không thấy mục đó |
| `code` | Chỉ có trong code mà role này tải được: endpoint `static`, hoặc script resolver tải về mà không chạy (`tags: resolved`, không có `via: debugger`) |
| `denied` | Đã gọi hoặc thăm nhưng bị từ chối: 401/403, bị đưa về trang login |
| `held` | Đã gọi; guard giữ lại vì đó là request ghi (với role này, mục đó tồn tại nhưng server không trả lời) |
| `used` | Đã chạy hoặc đã gọi thành công |

**Phân loại** dựa trên role **thấp nhất dùng được mục đó** (L, trạng thái `used` hoặc `held`) và trạng thái của các role thấp hơn L. Lấy trạng thái "lộ nhất" trong số đó, theo thứ tự `code` > `denied` > `absent`:

| Lớp | Điều kiện | Ý nghĩa cho kiểm thử |
|---|---|---|
| `client_gated` | Có role dưới L ở trạng thái `code` | Code của role thấp có sẵn endpoint hoặc chunk, chỉ giao diện chặn. **Ưu tiên 1**: gửi lại bằng session role thấp |
| `denied_below` | Có role dưới L ở trạng thái `denied` | Server đã từ chối role thấp. Vẫn đáng gửi lại với tham số khác (IDOR) |
| `higher_only` | Mọi role dưới L đều `absent` | Role thấp không hề biết tới mục này. Script loại này gọi là `server_gated` (server chỉ phục vụ cho role cao) |
| `unreached` | Không role nào dùng được, nhưng có role thấy trong code | Ngay cả admin cũng chưa chạm tới (cần kích hoạt bằng tay hoặc bằng AI qua MCP) |
| `content_differs` (script) | Cùng URL hoặc khoá chuẩn, SHA khác nhau giữa các role | Server render khác nhau theo role: config, feature flag, state ban đầu |
| `shape_differs` (endpoint) | Cùng endpoint, nhưng role cao gửi thêm tham số query/body/header hoặc operation GraphQL | Tham số chỉ admin dùng (`role`, `include_deleted`) là đầu vào cho mass assignment |
| `same` | L là role thấp nhất và không khác gì | Không báo (trừ khi có `-all`) |

Với nhiều role, mỗi mục được báo **một lần** kèm cả ma trận. Ví dụ: `GET /api/admin/stats` với `{anon: denied, user: denied, admin: used}` thuộc lớp `denied_below`, L=admin.

## 3. Bốn tầng và khoá ghép cặp

### 3.1 Script (`index.jsonl`)
- **Khoá:** URL đã bỏ query. Với script không có URL (inline, eval), dùng `canonical_keys`. Ghép theo khoá, không theo SHA, vì cùng một file có thể khác nhau giữa các role.
- **Trạng thái:**
  - `used` nếu có `via: debugger` (V8 đã biên dịch) hoặc entry đó không phải chỉ do resolver tải;
  - `code` nếu chỉ có `tags: resolved` mà không có `debugger`;
  - `absent` nếu không có.
- **Lớp riêng:** `content_differs`: tập SHA của cùng một khoá khác nhau giữa các role mà role đó `used`.
- **Bỏ qua:** script `third-party`, và script `internal` của jsharvest.
- **Giới hạn:** run có `-no-debugger` không phân biệt được `code` với `used`. Trường hợp này được ghi vào cảnh báo.

### 3.2 Endpoint (`endpoints.jsonl`)
- **Khoá chuẩn** (Reviewer bẫy 1, bẫy 2):
  - `METHOD host path`, trong đó mọi `{…}` (`{}`, `{id}`, `{uuid}`…) đều đưa về `{}`, và bỏ `/` ở cuối;
  - endpoint có `Base` dùng `Base+Path`;
  - endpoint chưa có `Base` mà có `Bases` (client chưa được traffic xác nhận) sinh ra **nhiều khoá ứng viên**: mỗi `b+Path` một khoá, cộng thêm `Path`. Hai endpoint ở hai role được ghép khi tập khoá của chúng giao nhau (union-find).
- **Trạng thái** từ `status` và `observed.outcomes`:
  - `static` → `code`;
  - `both`/`observed` → `used` nếu có outcome `ok` hoặc `redirect`; `held` nếu chỉ có `held_back:*`; `denied` nếu chỉ có `http:401`/`http:403`; ngược lại là `used`.
- **`shape_differs`:** `query`, `body`, `headers`, `operations` của role cao có thêm tên mà role thấp không có. Chỉ xét những role mà endpoint là `used` hoặc `held`.

### 3.3 Trang (`pages.jsonl`)
- **Khoá:** đường dẫn của URL được yêu cầu, với chữ số đưa về `#` (cùng cách chuẩn hoá với explore).
- **Trạng thái:**
  - `used`: đã thăm, status 2xx, và `final_url` không phải trang login;
  - `denied`: status 401/403, hoặc bị đưa về trang login;
  - `code`: có trong `pages.jsonl` nhưng không được thăm (ví dụ vì độ sâu), tức role này biết URL;
  - `absent`: không có.
- **Nhận diện trang login:** `login_url` trong session của role, hoặc đường dẫn có `login`/`signin`/`sign-in`/`auth`.

### 3.4 Tính năng (`flows.jsonl`)
- **Khoá** (Reviewer bẫy 5): `kind | page path chuẩn hoá | element.tag | element.role | nhãn chuẩn hoá`, không dùng id hành động (`a1`, `a2`).
- **Chỉ xét:** hành động của người dùng hoặc explore (không xét `load` và `background`).
- **Trạng thái:**
  - `used`: tính năng có ít nhất một request không bị từ chối;
  - `denied`: mọi request đều 401/403;
  - `held`: chỉ có request bị guard giữ.
- **Kèm theo:** tập endpoint (đã chuẩn hoá) và các request ghi (`writes`) của tính năng.

## 4. Output

- **`<out>/<host>/diff.json`:**
  - `roles` (theo thứ tự), `generated`, `config` của từng role, `warnings`;
  - `items[]`: `{layer, key, class, lowest, states: {role: state}, evidence}`. `evidence` gồm: endpoint là `samples` và `refs` (run, id) ở role L; script là URL, SHA và trang; trang là `final_url`/status theo role; tính năng là nhãn, endpoint và `writes`;
  - `summary`: số mục theo tầng và lớp.
- **`<out>/<host>/diff.md`:** tóm tắt cho người đọc, sắp theo mức ưu tiên. Thứ tự: endpoint `client_gated`, rồi `denied_below`, `higher_only`, `shape_differs`; sau đó tính năng, trang, script.
- **CLI:** `jsharvest diff -o OUT -target HOST [-roles a,b,c] [-all]`. In bảng tóm tắt ra stderr và trả mã thoát 0. Thiếu thư mục của một role thì báo lỗi.
- **Che giá trị nhạy cảm:** `samples` có thể chứa token trong query, nên mặc định che như MCP; `-reveal` để xem nguyên bản. File có quyền 0600.

## 5. Package

- **`internal/roles`:** hàm thuần, đọc thư mục bằng `internal/results` và `internal/endpoints`, trả về `Report`. Đặt tên `roles` thay vì `diff` (gợi ý của Reviewer) để không trùng với từ `diff` đã dùng cho script (monitor ở GĐ5).
- **Unit test bằng thư mục dựng tay:** ma trận và phân lớp, khoá endpoint (`{}`/`{id}`, `Base`/`Bases`), script chỉ resolver tải (`code`), `content_differs`, trang login, khoá của tính năng.
- **`cmd/jsharvest/diff.go`.**
- **Engine:** `run.json.config`.

## 6. Fixture `role-app` và gate

Testbed server có sẵn session với role (`/api/login`: email bắt đầu bằng `admin` thì là admin). Thêm các route của `role-app`:

| Mục | anon | user | admin | Lớp mong đợi |
|---|---|---|---|---|
| `GET /api/ra/pub/news` (mọi role gọi) | used | used | used | `same` (không được báo) |
| `GET /api/ra/me/profile` (app gọi luôn) | denied (401) | used | used | `denied_below`, L=user |
| `GET /api/ra/admin/stats` (app gọi luôn) | denied | denied (403) | used | `denied_below`, L=admin |
| `GET /api/ra/me/orders` (nút "My orders" chỉ hiện khi đã đăng nhập) | code | used | used | `client_gated`, L=user |
| Chunk `/ra/js/admin-chunk.js` (chỉ nạp khi `/api/me` trả về admin; có `import()` nên resolver của anon/user vẫn tải được) | code | code | used | script `client_gated` |
| Endpoint trong chunk admin: `GET /api/ra/admin/users`, `POST /api/ra/admin/invite`, `DELETE /api/ra/admin/users/{id}` | code | code | used/held | `client_gated`, L=admin |
| Script `/private/ra-audit.js` (server chỉ trả cho admin) và `GET /api/ra/admin/audit` trong đó | absent | absent | used | `higher_only` (script là `server_gated`) |
| `/ra/config.js` (server trả `window.CONFIG` theo role) | used | used | used | `content_differs` |
| `POST /api/ra/search`: admin gửi thêm `include_deleted` | used | used | used | `shape_differs` |
| Trang `/ra/admin` (anon về login, user 403, admin 200), có nút "Rotate keys" | denied | denied | used | trang `denied_below`; tính năng "Rotate keys" `higher_only` |
| Nút "My orders" | absent | used | used | tính năng `higher_only`, L=user |

Gate `testbed/roles-check.sh`:
1. login user và admin bằng kịch bản;
2. crawl 3 role với cùng cấu hình (`-depth 1 -explore`);
3. chạy `jsharvest diff`;
4. `testbed roledscore` đối chiếu `diff.json` với `role-app/roles.truth.json`: mọi mục mong đợi có đúng lớp và đúng L, các mục `same` không được báo, không có mục nào ngoài truth (trừ nhiễu đã khai báo);
5. 0 request ghi tới server.

Thêm một bản crawl lệch cấu hình (anon không explore) để kiểm tra cảnh báo.

## 7. Ngoài phạm vi
- **Mô phỏng quyền** (sửa response `/me` để lộ chunk admin; research mục 2.4): là thăm dò chủ động, để sau, bật bằng cờ riêng.
- **Gửi lại request bằng session của role thấp:** thuộc 4.8 (xuất) và GĐ5 (replay).
- **Tool MCP `diff`:** để sau; MCP hiện làm việc theo từng thư mục.

## 8. Dữ liệu thật và đánh giá độc lập (2026-11-04) — có hiệu lực cao hơn mục 2–4

Trước khi viết code, mình crawl `role-app` với 3 role để xem dữ liệu thật. Song song, một agent đánh giá độc lập thiết kế trên code (không được biết trước kết luận của tác giả). Cả hai nguồn cho cùng một kết luận: **bảng outcome ở mục 3.2 sai**.

| # | Phát hiện | Kiểm tra | Quyết định |
|---|---|---|---|
| (tự thấy) M1 | Recorder ghi `ok` cho **mọi** response, kể cả 401/403; không có `http:NNN` | `record.go:438-455`; dữ liệu `role-app`: `admin/stats` của anon có outcome `ok` | `endpoints.jsonl` thêm `observed.statuses` (các mã HTTP khác nhau, không tính request bị giữ). Trạng thái lấy từ mã HTTP: có 2xx → `used`; chỉ 401/403 → `denied`; chỉ 3xx → `redirected`; chỉ bị giữ → `held`; chỉ `failed`/`incomplete` → `unknown` (không còn "ngược lại là used") |
| (tự thấy) M2 | `shape_differs` không tính được từ catalog, vì tên trường body chỉ đến từ code tĩnh | `observe()` chỉ thêm tên query | Lấy hình dạng request từ chính `requests.jsonl` của mỗi role (`flow.RequestValues`) |
| (tự thấy) | Tagger của jsharvest bị lưu như script `eval` của target (có từ 4.3) | `index.jsonl` của cả 3 role | Sửa ở capture (`ownScript`), có test |
| (tự thấy) | `via: debugger` không đáng tin cho "đã chạy": `config.js` của admin chỉ có `network` | Dữ liệu `role-app` | Script: `code` khi chỉ do resolver tải (`resolved`, không có `debugger`); `loaded` khi trang tự tải. Cả hai được tính là "role này có" |
| M3 | GraphQL và RPC (`?action=`) gộp nhiều thao tác vào một endpoint | Đúng | Khoá endpoint có thêm tên operation GraphQL (từ body) và giá trị của các tham số phân biệt (`action`, `method`, `op`, `cmd`, `operation`, `func`, `task`) |
| M4 | Ghép endpoint giữa role: template không hội tụ, union-find gộp bắc cầu, wrapper chung kiểu `/api/{}` | Đúng (`flow.Templates` cần ≥ 3 giá trị; `ep.Bases` lấy từ mọi script) | **Đổi cách làm:** endpoint quan sát được dựng từ **traffic của mọi role gộp lại**, qua cùng `flow.Templates`. Endpoint chỉ có trong code được ghép một-một bằng khớp template, ưu tiên khớp đúng `Base+Path`. Template "chung" (ít hơn 2 đoạn cố định) không dùng để ghép. Host rỗng nghĩa là target; method rỗng khớp mọi method |
| M5 | Script có hash trong tên đổi theo từng build; thư mục role cộng dồn nhiều build; script inline có nonce | Đúng | Khoá script là `canonical_keys` (hash thành `[h]`). `content_differs` chỉ xét file không có hash trong tên, và chỉ so SHA của run gần nhất (`last_seen`). Script inline chỉ so có hay không. Cảnh báo khi bundle chính khác SHA giữa các role |
| M6 | Role thấp dùng được endpoint "của admin" thì bị ẩn thành `same`, mà đây là manh mối quý nhất | Đúng | Thêm lớp `lower_ok`: L thấp hơn **role gốc** của endpoint. Role gốc xác định bằng một trong ba cách: endpoint nằm trong script `client_gated`/`server_gated` của một role cao hơn; endpoint được gọi từ trang hoặc tính năng chỉ role cao có; path có `admin`/`manage`/`internal`/`staff`/`backoffice`. Thêm lớp `inconsistent`: role thấp `used` trong khi role cao hơn `denied` |
| M7 | Trang: SPA trả 200 rồi client tự chuyển về `/`; trang chưa thăm vì hết ngân sách bị coi là `code`; `auth` khớp nhầm `/authors` | Đúng | `final_url` khác path được yêu cầu → `redirected`. Lý do `depth`/`limit` → `unknown`. Trang login chỉ nhận theo đoạn path đúng (`login`, `signin`, `sign-in`, `log-in`) hoặc `login_url` của session. Một URL có nhiều dòng → lấy run gần nhất |
| S1 | Cùng cấu hình không có nghĩa là cùng độ phủ | Đúng | Role thấp chỉ là `absent` khi nó đã thăm (được hoặc bị từ chối) trang nơi role cao gặp mục đó; nếu chưa thăm thì là `unknown`. Đọc cấu hình từ mọi run trong `runs.jsonl`; cảnh báo run bị mất session |
| S2 | Chỉ nên dùng `via: debugger` | **Không nhận**: dữ liệu thật cho thấy script đã chạy vẫn có thể thiếu `debugger` | Như dòng "(tự thấy)" ở trên; ghi vào giới hạn: script được prefetch thì là `loaded` |
| S3 | `code` > `denied` đánh giá quá cao những gì server đã chặn | Đúng | Lớp quyết định theo **role ngay dưới L**: role đó `denied` → `denied_below`, kể cả khi role thấp hơn nữa có code |
| S4 | Trong cùng một role, vừa 2xx vừa 403 cho cùng template là dấu hiệu IDOR ngang | Đúng | Ghi `mixed: true` cùng các mã HTTP của từng role vào evidence |
| S5 | Nhãn tính năng chứa tên người dùng hoặc số đếm | Đúng | Khoá tính năng ưu tiên `id` → `name` → `href`/`action` → nhãn đã chuẩn hoá (chữ số, email) |
| S6 | Sắp role theo chữ cái làm đảo thứ tự với `manager`/`superadmin` | Đúng | Bắt buộc `-roles` khi có tên role ngoài `anon`/`default`/`user`/`admin` |
| S7 | `store.Open` xoá file; `Catalog(analyze)` ghi cache | Đúng | `roles` chỉ đọc file jsonl trực tiếp. Cảnh báo khi một role đang được `watch` |
| Riêng tư | Token trong path, `final_url`, nhãn | Đúng | Che giá trị nhạy cảm cho mọi chuỗi trong evidence (dùng chung bộ che của MCP), `-reveal` để xem nguyên bản. `diff.json` và `diff.md` có quyền 0600 |

**Fixture thêm:**
- bundle có hash đổi theo role (không được báo, chỉ cảnh báo);
- nhãn chứa tên người dùng;
- XHR 302 về login;
- GraphQL có mutation chỉ admin dùng;
- RPC `?action=`;
- user được 200 trên `/api/ra/admin/*` (`lower_ok`);
- kết quả đảo chiều giữa các role (`inconsistent`);
- trang `/authors` (không phải login);
- một lần chạy anon bị giới hạn `-max-pages` (phải ra `unknown`, không ra `client_gated`).

## 9. Kết quả (2026-11-04)

| Kiểm tra | Kết quả |
|---|---|
| A. `role-app`, 3 role crawl như nhau (`-depth 1 -explore`) | **27/27** mục đúng lớp và đúng role thấp nhất, **0 mục thừa**. Cụ thể: 15 endpoint, 7 tính năng, 1 trang, 4 script. Gồm `lower_ok` (user được 200 trên `/api/ra/admin/summary`), `inconsistent` (`/pub/legacy`), mutation GraphQL và action RPC chỉ admin có (`client_gated`), `shape_differs` (`include_deleted`), và tính năng "My orders" với nhãn khác nhau theo role (gộp đúng theo `id`). Không báo `News`, `action=list`, `/authors`, bundle có hash; có cảnh báo về build |
| B. user bị cắt bằng `-max-pages 1` | Trang `/ra/admin`, tính năng "Rotate keys" và `POST /api/ra/admin/keys` ra `not_covered`, không ra `higher_only` |
| C. anon không explore | Có cảnh báo "anon and user were not crawled alike" |
| An toàn | Chỉ `POST /api/login` và GraphQL *query* (guard cho qua vì là đọc) tới server; mutation `PurgeUsers` bị giữ |
| Hồi quy | unit `-race`, bench (thêm baseline cho `role-app`), flows-gate, attach-guard, frontier, session, endpoints, explore: **đều đạt** |

**Sửa thêm khi làm:**
- Tagger không còn bị lưu thành script của target.
- Mã HTTP được lưu trong catalog (`observed.statuses`).
- `run.json` có thêm `config` và `scope`.
- Đoạn path trông như token, hash hoặc email được che trong evidence (`MaskTokens`).

**Giới hạn:**
- `endpoints.jsonl` của các role có thể đến từ các phiên bản `jsapi` khác nhau, mà `diff` không cảnh báo.
- Script được prefetch nhưng không chạy tính là `used` (không phân biệt được với script đã chạy; xem mục 8, S2).
- `content_differs` không xét script inline, vì chúng có nonce.
- Không mô phỏng quyền và không gửi lại request: mục 7.
