# GĐ4 4.3 — Hành động và cụm (`flows.jsonl`), chế độ `watch`: thiết kế

Mục tiêu (người giao việc): "click vào một tính năng thì bắt được cả chùm request", gom lại theo tính năng để fuzz. Bước này:
- ghi lại **hành động** (thao tác người dùng, tải trang);
- **gán mỗi request vào hành động đã gây ra nó**;
- suy ra **endpoint dạng template** và **phụ thuộc dữ liệu** giữa các request.

Người điều khiển trình duyệt có thể là người bấm tay, AI agent hoặc Playwright (chế độ `watch`). Explore tự động sẽ có ở 4.6.

## 0. Sửa đổi sau đánh giá độc lập (có hiệu lực cao hơn các mục bên dưới)

Agent đánh giá đã tự chạy spike riêng để kiểm chứng. Những gì được xác nhận:
- tag khớp **chính xác** giữa hai world, kể cả giá trị như `3267.39999999851`;
- `WithDetachOnCancel` không đóng tab của người dùng;
- binding trong isolated world không gọi được từ trang;
- `sendBeacon` có mang tag;
- binding đến **sau** các request mà nó gây ra, nên việc gán phải làm sau, không làm ngay khi request đến.

Các thay đổi:

1. **Tag có thể mất khi trang bận** (khoảng 12k promise trong 2,5 s thì chuỗi `setTimeout` mất hết mắt xích, có lẽ do V8 bỏ async stack cũ).
   - Chuỗi không có mắt xích async nào nhưng có frame JS thì coi là **"không rõ"**, rồi dùng cửa sổ thời gian.
   - `run.json` ghi tỷ lệ request còn giữ tag.
   - Fixture thêm bộ sinh promise nền ở tốc độ tương đương zone.js.
2. **Tag bám vào công việc chạy lâu.** Nếu có `setInterval` nằm **giữa request và tag** trong chuỗi, hoặc cùng method và template lặp lại theo chu kỳ (≥ 3 lần) dưới một tag, thì request đó thuộc **`background`** và ghi `started_by: <action>`.
3. **Một thao tác sinh nhiều event, nên gom thành *cử chỉ* (gesture).**
   - Reporter báo **mọi** loại event mà wrapper bọc: `click`, `dblclick`, `pointerup`, `mouseup`, `keydown`, `input`, `change`, `submit`. Hai danh sách này phải giống hệt nhau.
   - Go gom các event trong cùng document có `timeStamp` cách nhau ≤ 5 ms thành một cử chỉ (`pointerup`, `mouseup`, `click` có cùng timeStamp; `keydown`, `click`, `submit` cách nhau khoảng 2 ms).
   - Một hành động là một cử chỉ, mang **tập tag** của các event trong đó. Nhãn và `kind` lấy theo ưu tiên `submit` > `click` > `change` > `key` > `input`.
   - Tag không khớp chính xác với hành động nào thì gán cho **cử chỉ gần nhất trước nó**, trong cùng document, cách ≤ 5 ms theo timeStamp (tag mang timeStamp của chính nó). Trường hợp này phủ được cả `submit` trong shadow DOM.
   - Chuỗi có nhiều tag thì ưu tiên tag **trusted**. Cử chỉ chỉ gồm event untrusted (do app tự gọi `el.click()`) vẫn là hành động, nhưng **không đóng cửa sổ** của hành động trước.
   - Hành động `input`/`key` không có request nào thì bỏ khỏi output. Search debounce khớp với tag của lần `input` cuối.
4. **Shadow DOM:** phần tử lấy từ `composedPath()[0]`.
5. **Rule cho handler dạng thuộc tính HTML:** stack chỉ có frame `on<type>` ở URL của document, không có mắt xích async. Request đó được gán cho cử chỉ gần nhất trước nó có event kiểu đó, `how: "handler"`. Cửa sổ thời gian chỉ còn dùng cho: request không có stack JS (worker, điều hướng), chuỗi bị cắt, và document chưa cài wrapper.
6. **Recorder:** `initiator.chain` ghi **mọi** mô tả async (tối đa 64), tách khỏi giới hạn 16 frame.
7. **Setter `on*`:** `window.onclick` là thuộc tính của chính `window`; `SVGElement.prototype` có setter riêng; còn có `Document.prototype`. Getter trả về hàm gốc, thuộc tính giữ `configurable` (zone.js sẽ patch lại). Không bọc `onerror` và `onbeforeunload`.
8. **`watch`:**
   - bắt buộc chọn guard rõ ràng (`-guard on|off`);
   - khi thoát, in cảnh báo "tải lại tab để gỡ script của jsharvest", và có `-reload-on-exit`;
   - trang đã tải sẵn: dùng `Page.createIsolatedWorld` cho frame chính rồi evaluate reporter;
   - iframe khác site: cài binding, hai script và async depth trên session của nó;
   - `setAsyncCallStackDepth` chỉ bật ở chế độ có hành động;
   - tên world là `jsharvest-actions` (resolver đã dùng `jsharvest`);
   - `popstate`/`hashchange` được báo thành hành động `nav`.
9. **Template:**
   - khoá frame gồm URL, hàm, dòng **và cột** (bundle minify chỉ có một dòng);
   - thứ tự xử lý: heuristic từng segment → phát hiện hàm trung tâm → gộp theo initiator;
   - chỉ gộp khi có **≥ 3 giá trị khác nhau**, và ghi lại các giá trị đã thấy (`values`) để dùng khi fuzz.
10. **`depends_on`:**
    - chỉ nhận số có ≥ 5 chữ số; chuỗi ≥ 6 ký tự nhưng bỏ chuỗi toàn chữ thường (thường là từ thông dụng);
    - ưu tiên header và cookie, rồi tới chuỗi, rồi tới số;
    - một chỉ mục toàn cục `giá trị → vị trí gần nhất`, có giới hạn kích thước;
    - có test kiểm tra không sinh liên kết sai.
11. **Ghi định kỳ:** khi `watch`, `flows.partial.jsonl` được ghi lại mỗi 10 s (ghi file tạm rồi đổi tên). Khi kết thúc bình thường thì nối vào `flows.jsonl` và xoá file partial.
12. **`requests` trong flow** là `[{"id": 15, "how": "causal|handler|window"}]`.
13. **Gate khó hơn:**
    - fixture thêm: poll `setTimeout` đệ quy, poll do một click khởi động, request lúc tải trang đến *sau* click đầu tiên, bộ sinh promise nền, "tạo xong rồi dùng id mới", Enter trong form, click vào label;
    - chạy hai lượt: lượt thường và lượt **nhanh** (30 ms giữa các bước);
    - các ca 1–5 phải có `how: causal`;
    - chấm điểm từng ca;
    - **bản chỉ dùng cửa sổ thời gian (`-flow-tag=false`) phải trượt**;
    - gate chạy với `-guard off` (testbed là của mình) để luồng "tạo rồi dùng id" chạy đúng.
14. **Chưa kiểm:**
    - jsharvest chết khi đang giữ worker trong tab của người dùng;
    - Playwright `route` (Fetch ở cấp trang) chạy cùng guard (Fetch ở cấp browser).

    Thử bằng Playwright mẫu.

## 1. Spike (2026-11-03): chuỗi nhân quả qua Async Stack Tagging

Cách làm: script chạy trước trang bọc `addEventListener` (cùng setter `onclick`, `onsubmit`…), để mỗi handler chạy trong `console.createTask("jsh:<…>").run(...)`. Debugger bật `setAsyncCallStackDepth(32)`. Tên task xuất hiện thành một mắt xích trong `initiator.stack.parent…` của `Network.requestWillBeSent`.

| Ca | Mắt xích tìm thấy |
|---|---|
| `fetch` trong handler | `"" ← jsh:click:86.8` ✅ |
| `setTimeout` rồi `fetch` | `"" ← setTimeout ← jsh:click` ✅ |
| `await fetch()`, rồi `fetch()` sau `await` | cả hai ✅ (`await ← jsh:click`) |
| Delegation trên `document` + `Promise.then` (kiểu React) | ✅ |
| `el.onclick = …` | ✅ |
| XHR | ✅ |
| `setInterval` nền | `"" ← setInterval`, **không có tag** ✅ (đúng: không thuộc thao tác nào) |
| Worker (`postMessage` rồi `fetch` trong worker) | **không có chuỗi**; async stack không đi qua ranh giới sang worker |

**Kết luận:** chuỗi nhân quả là cách gán chính, chính xác cho request phát sinh từ trang. Request từ worker và request không mang tag dùng **cửa sổ thời gian** làm phương án dự phòng, và được ghi độ tin cậy thấp hơn.

## 2. Ghi lại hành động

**Hai script, chạy ở hai world khác nhau** (đều có `//# sourceURL=jsharvest-internal`):

1. **World chính, script gắn tag.** Bọc `EventTarget.prototype.addEventListener` và `removeEventListener`, dùng `WeakMap` để `remove` nhận đúng hàm đã bọc. Bọc thêm setter `on<type>` của `HTMLElement`, `Document`, `Window`. Các loại event được bọc: `click`, `dblclick`, `submit`, `change`, `input`, `keydown`, `pointerup`.
   - Tên task: `jsh:<timeOrigin>:<timeStamp>:<type>`, trong đó `performance.timeOrigin` và `event.timeStamp` lấy từ chính event đó.
   - Không có `console.createTask` (trình duyệt cũ) thì không bọc, và mọi request rơi về cửa sổ thời gian.
   - **Không bọc được:** handler dạng thuộc tính HTML (`<button onclick="…">`), vì Chrome biên dịch chúng mà không đi qua setter. Những handler này cũng rơi về cửa sổ thời gian.

2. **Isolated world `jsharvest`, script ghi hành động.** Nghe ở capture phase trên `window` các event `click`, `submit`, `change`, `keydown` (chỉ Enter), `input` (gộp: các lần `input` liên tiếp trên cùng phần tử trong 1 s tính là một hành động). Script báo qua `Runtime.addBinding{name, executionContextName: "jsharvest"}`. Binding chỉ tồn tại trong isolated world, nên **script của trang không gọi giả được**. Mỗi báo cáo gồm:
   - `tag`: `<timeOrigin>:<timeStamp>:<type>`, khớp với tên task của world chính, vì cả hai world thấy cùng một event;
   - `kind`, `trusted` (`isTrusted`), `wall` (`Date.now()`);
   - phần tử: `tag`, `id`, `name`, `type`, `role`, accessible name (`aria-label`, `labelledby`, `innerText` cắt 60 ký tự, `value` của nút, `placeholder`), selector CSS rút gọn, `href`, `action` của form;
   - `url` của frame, và cờ cho biết có phải frame chính không.

- **Hành động `load`:** request Document của frame chính (lấy từ recorder). Mỗi lần điều hướng là một hành động. Điều hướng SPA (`navigatedWithinDocument`) không tạo hành động riêng, vì nó thường là hệ quả của một click.
- **`watch` gắn vào trang đã tải sẵn:** script được nạp thêm bằng `Runtime.evaluate` vào document hiện tại. Listener đã đăng ký từ trước thì không được bọc, nên chuỗi nhân quả chỉ đầy đủ sau khi tải lại trang. Có `-reload` để tool tự tải lại, và một cảnh báo trong log.
- Script gắn tag chỉ cài khi bật hành động (`watch`, và explore ở 4.6). `crawl` hiện chỉ có hành động `load`, nên không cài, không tốn thêm chi phí và không thay đổi gì trên trang.

## 3. Gán request vào hành động (`internal/flow`, hàm thuần, test được)

Đầu vào:
- **Hành động:** `id`, `tag`, `kind`, `wall`, phần tử, `page`.
- **Request:** tóm tắt từ recorder: `id`, `ts`, `end`, `target`, `frame`, method, URL, `outcome`, `chain` (mọi mô tả async, tối đa 32), `tags` (các mô tả `jsh:`), frame ứng dụng đầu tiên, giá trị trích ra (xem mục 5).

Thứ tự áp dụng:
1. **Nhân quả:** request có tag khớp với một hành động → gán vào đó, `how: "causal"`. Nếu có nhiều tag thì lấy tag gần nhất, tức nằm sâu nhất trong chuỗi.
2. **Nền chắc chắn:** không có tag, và đáy chuỗi là `setInterval` → `background`.
3. **Cửa sổ thời gian:** với request còn lại, tìm hành động gần nhất bắt đầu trước request (`wall ≤ ts`), sao cho request nằm trong cửa sổ của hành động đó.
   - **Cửa sổ:** từ lúc hành động bắt đầu, kéo dài tới khi mạng yên 1,5 s sau request cuối của hành động, tối đa 10 s.
   - Cửa sổ của một hành động **đóng lại khi hành động người dùng kế tiếp bắt đầu**.
   - Request gán theo cách này có `how: "window"`.
   - Ngoại lệ: request khớp **mẫu nền đã học** (cùng method và template, lặp lại ≥ 3 lần với khoảng cách gần đều nhau, có ít nhất một lần nằm ngoài mọi cửa sổ) thì không gán theo cửa sổ.
4. Hành động `load` dùng cùng quy tắc cửa sổ, tính từ request Document.
5. Còn lại → `background` của trang (một cụm cho mỗi trang).

`confidence` của một cụm: tỷ lệ request được gán theo nhân quả, cùng số request gán theo cửa sổ.

## 4. Endpoint template

**Heuristic cho từng segment:**
- số → `{id}`;
- UUID hoặc ULID → `{uuid}`;
- hex ≥ 16 ký tự, hoặc base64url ≥ 20 ký tự có trộn chữ và số → `{hash}`;
- JWT → `{token}`;
- email → `{email}`;
- ngày hoặc timestamp → `{date}`.

**Gộp có hỗ trợ initiator:** gom request theo (method, host, frame ứng dụng, số segment). Trong mỗi nhóm, nếu các request chỉ khác nhau ở segment thứ k thì segment k → `{param}`. Ví dụ `/api/projects/my-first/settings` và `/api/projects/demo/settings` được gọi từ cùng một dòng code.

**Frame ứng dụng đầu tiên:** duyệt các frame trong `initiator.stack` từ trên xuống, bỏ qua:
- frame `jsharvest-internal`;
- frame thuộc script ngoài scope;
- frame thuộc file mang tên thư viện (`vendor`, `framework`, `polyfill`, `runtime`, `node_modules`, `axios`, `jquery`, `react-dom`, `zone`…);
- frame **"trung tâm"**: vị trí (URL, dòng) là đỉnh của các request tới **≥ 3 template khác nhau**. Đó là hàm bọc của chính app, kiểu `apiClient()`; quy tắc này học từ dữ liệu, không cần danh sách tên.

Khoá được dùng là URL script dạng chuẩn, cộng tên hàm và dòng.

Gộp theo cây prefix kiểu Akita (dựa trên số lượng giá trị khác nhau) để sau, khi có dữ liệu thật.

## 5. `depends_on`

- **Lúc ghi**, từ response (JSON, form, text ≤ 64 KiB và header, trừ `Date`, `Content-Length`…) trích tối đa 200 giá trị vô hướng: chuỗi ≥ 6 ký tự không phải từ thông dụng, số ≥ 3 chữ số, và giá trị từng cookie trong `Set-Cookie`. Từ request trích các giá trị ở path segment, query, header (trừ `Cookie`, vì trình duyệt tự gửi), và body JSON hoặc form.
- Chỉ giữ giá trị và vị trí, không giữ body, để bộ nhớ có giới hạn khi chạy `watch` lâu.
- Một liên kết được ghi khi giá trị của request j xuất hiện trong response i, với i kết thúc trước khi j bắt đầu, trong cùng run và cùng trang. Ví dụ `{"request": 17, "at": "header:x-csrf-token", "from": {"request": 15, "at": "json:$.csrf"}}`.
- Nếu giá trị xuất hiện ở nhiều response thì lấy response gần nhất.
- `flows.jsonl` **không chứa giá trị**, chỉ chứa vị trí, nên không cần che. `label` và `page` được che bằng `-redact` như các URL khác.

## 6. Output `flows.jsonl` (ghi khi kết thúc run, hoặc khi `watch` dừng)

```json
{"run":"…","action":"a7","kind":"click","label":"button \"Save profile\"","trusted":true,
 "element":{"tag":"button","id":"save","role":"button","name":"Save profile","selector":"form#profile > button"},
 "page":"http://app/settings","started":"…","ended":"…",
 "requests":[15,16,17],"writes":[17],
 "endpoints":[{"method":"GET","host":"app","template":"/api/csrf","requests":[15,16]},
              {"method":"POST","host":"app","template":"/api/profile","requests":[17],"outcome":"held_back:write"}],
 "depends_on":[{"request":17,"at":"header:x-csrf-token","from":{"request":15,"at":"json:$.csrf"}}],
 "attribution":{"causal":3,"window":0}}
```

- `kind` là một trong `load`, `click`, `submit`, `change`, `input`, `key`, `background`.
- `requests` chứa các `id` trong `requests.jsonl` của cùng run.
- `requests.jsonl` **không** có thêm `action_id`, vì lúc ghi một dòng thì việc gán theo cửa sổ chưa xong. Liên kết chỉ đi một chiều, từ flow sang request.

## 7. Chế độ `watch`

```
jsharvest watch -attach http://127.0.0.1:9222 (-tab REGEX | -open URL) [-reload] [-duration D] [-o …] [-role …]
```

- `-tab`: gắn vào một tab có sẵn có URL khớp regex (lấy danh sách qua `/json/list`; phải khớp đúng một tab). `-open URL`: mở tab mới, cài script, rồi điều hướng.
- Dùng `chromedp.WithTargetID` + **`WithDetachOnCancel`**. Không có tuỳ chọn này, chromedp sẽ **đóng tab** của người dùng khi kết thúc (đã kiểm tra trong mã nguồn: `CloseTarget`). Có test cho trường hợp này.
- Guard: `auto` thì bật (vì là attach). Với `-tab`, tab được đăng ký bằng `Guard.AddTab`.
- Dừng khi: SIGINT/SIGTERM, hết `-duration`, hoặc tab đóng. Sau đó ghi `requests.jsonl` (đã ghi dần trong lúc chạy), `flows.jsonl`, `blocked.*` và `run.json` (`mode: "watch"`).
- In ra stderr mỗi khi có hành động: kiểu, nhãn, số request. Người hoặc AI đang điều khiển nhìn vào đó để biết tool đang ghi.

## 8. Fixture `flows-app` và cổng nghiệm thu

App viết tay (không cần build), nằm ở `testbed/apps/flows-app/dist`. Mọi request API đều đi qua **một hàm bọc dùng chung `apiClient()`**:

| # | Tính năng | Thao tác | Request đáp án |
|---|---|---|---|
| 1 | Tìm kiếm | nhập `#q`, click `#search` | `GET /api/search?q=…` |
| 2 | Mở item | click `.open[data-id=42]`, rồi `[data-id=108]` | `GET /api/items/{id}`, rồi `GET /api/items/{id}/reviews` (chuỗi Promise); template `/api/items/{id}` |
| 3 | Lưu hồ sơ | submit `#profile` | `GET /api/csrf` → `POST /api/profile` có header `X-CSRF-Token` lấy từ response trước (`depends_on`) |
| 4 | Xoá có xác nhận | click `#delete` (mở modal, không có request), rồi `#confirm` | `DELETE /api/items/42` thuộc về `#confirm` |
| 5 | Wizard | `#next1`, rồi `#next2` | `POST /api/wizard/step1`; `setTimeout` → `POST /api/wizard/step2` → `GET /api/wizard/summary` |
| 6 | Xuất file qua worker | click `#export` | worker `GET /api/export?format=csv` (gán theo cửa sổ) |
| 7 | Handler dạng thuộc tính HTML | click `#legacy` (`onclick="…"`) | `GET /api/legacy` (gán theo cửa sổ) |

**Nhiễu:**
- khi tải trang: `GET /api/me`, `GET /api/config`;
- `setInterval` 2 s: `GET /api/notifications`;
- `setInterval` 5 s: `POST /api/analytics` (beacon).

Testbed có thêm `/api/csrf` (trả token), và `/api/items/{id}` trả JSON chứa `id`.

**Bộ điều khiển cho gate:** `bin/testbed drive -cdp … -tab … -steps testbed/apps/flows-app/flows.truth.json`. Nó gắn vào tab bằng chromedp và click hoặc gõ bằng sự kiện input CDP (event có `isTrusted`), giống như cách Playwright hay một AI agent điều khiển từ bên ngoài.

**Chấm điểm:** `bin/testbed flowscore`. Với mỗi bước trong đáp án, tìm cụm của hành động có phần tử khớp với bước đó, rồi so tập request (method + path). Cách đếm:
- **Precision** = số request gán đúng / số request được gán vào các hành động người dùng. Nhiễu bị gán vào một click thì tính là sai.
- **Recall** = số request đáp án được gán đúng / tổng số request đáp án.

Cổng nghiệm thu:
- precision **≥ 95%** và recall **≥ 95%**;
- template `/api/items/{id}` đúng; liên kết `depends_on` của bước 3 đúng;
- nhiễu nằm ở `background` hoặc `load`;
- tab của người dùng **không bị đóng** sau khi `watch` dừng.

Script `testbed/flows-check.sh` chạy toàn bộ: Chrome có cổng debug, `watch -open`, `drive`, SIGINT, rồi `flowscore`.

**Playwright:** `testbed/playwright/flows.mjs` dùng `connectOverCDP` để thao tác cùng các bước trên. Script chạy trong container `node:22` với `playwright-core` (không tải trình duyệt). Chạy bằng tay, không nằm trong gate (cần mạng để cài `playwright-core`), nhưng kết quả phải đạt cùng ngưỡng.

## 9. Rủi ro

| Rủi ro | Biện pháp |
|---|---|
| Bọc `addEventListener` làm hỏng app (định danh handler, `handleEvent`, `once`, `AbortSignal`) | Dùng `WeakMap` theo handler; giữ nguyên `options`; object có `handleEvent` được gọi qua `handleEvent`; chỉ bọc khi bật hành động; có thể tắt bằng `-flow-tag=false` |
| App nhận ra được việc bọc (`addEventListener.toString()`) | Chấp nhận được (tool cho pentest có ủy quyền); ghi trong README |
| `timeStamp` khác nhau giữa hai world | Spike chỉ thử world chính; fixture sẽ kiểm. Nếu sai thì chuyển sang khớp theo (type, `wall` ±50 ms, phần tử) |
| Cửa sổ thời gian gán nhầm khi hai thao tác nhanh liên tiếp | Cửa sổ đóng khi có hành động kế tiếp; request theo cửa sổ được ghi `how` |
| Bộ nhớ khi `watch` chạy lâu | Chỉ giữ tóm tắt request và tối đa 200 giá trị mỗi response |

## 10. Kết quả (2026-11-03)

**Gate 4.3** (`testbed/flows-gate.sh`, chạy `flows-check.sh` nhiều lượt):
- `flows-app`: 22 bước, 17 tính năng, 28 request đáp án; 14 tính năng phải được gán theo nhân quả.
- Nhiễu gồm: poll `setInterval`, poll `setTimeout` đệ quy, poll do click khởi động, request lúc tải trang đến sau click đầu tiên, và promise nền ở tốc độ kiểu zone.js.
- Các ca do review code bổ sung: timer sau `await`, form có control tên `id`/`action`, upload chia chunk tuần tự, độ trễ kiểu RxJS dùng `setInterval`, gõ phím ngay sau một tính năng worker chậm.

| Lượt | Precision | Recall | Ghi chú |
|---|---|---|---|
| CDP driver, nhịp 2,5 s | 28/28 | 28/28 | đạt mọi ca; template (`/api/items/{id}`, `/api/upload/{id}`) và `depends_on` (CSRF, id mới tạo) đúng |
| CDP driver, nhịp **30 ms** | 28/28 | 28/28 | |
| **Playwright** (`connectOverCDP`, container `node:22-alpine`, `PLAYWRIGHT=1`) | 28/28 | 28/28 | cùng kết quả với CDP driver |
| Chỉ dùng cửa sổ thời gian (`-flow-tag=false`) | 2/14 (lượt đầu) | 2/19 | **trượt như mong muốn**: chuỗi nhân quả là thứ làm nên độ chính xác |

Tab của người dùng không bị đóng sau `watch` (đã kiểm tra trong cả 4 lượt).

**Các lỗi phát hiện khi chạy thật** (unit test không bắt được):
- Payload `wall` là số mili-giây, nhưng `flow.Event.Wall` có kiểu `time.Time`, nên `json.Unmarshal` lỗi và **mọi event bị bỏ âm thầm**. Đã sửa bằng một struct payload riêng.
- Reporter lấy tham chiếu tới binding ngay khi khởi động, có thể trước lúc Chrome gắn binding vào isolated world. Đã chuyển sang tra lúc gửi.
- Recorder coi request là "của jsharvest" nếu **bất kỳ** frame nào là `jsharvest-internal`. Wrapper của tagger nằm ở đáy mọi handler, nên **mọi request có tag bị loại**. Giờ chỉ xét frame trên cùng.
- Quy tắc handler dạng thuộc tính HTML bắt nhầm `onmessage` của worker. Giờ chỉ áp dụng cho các loại event được báo về, và không áp dụng cho worker. Không tìm được cử chỉ phù hợp thì chuyển sang cửa sổ thời gian.
- **Mất tag khi trang bận** (đúng như review dự đoán): `/api/report/ready` đến 2,5 s sau click có chuỗi rỗng. Cách sửa: tagger bọc `setTimeout`/`setInterval`, để callback chạy trong task mới tạo lúc timer kích hoạt, tên là `jsh:<tag>:setTimeout|setInterval`, hoặc `jsh:none:<origin>:…` cho timer đặt ngoài mọi hành động. Mắt xích gần nhất luôn còn. Hậu tố `:setInterval` đánh dấu poll do hành động khởi động.
- Lượt nhanh lúc đầu có precision 83%: nhiễu bị mất chuỗi nên rơi vào cửa sổ của click cuối. Đã sửa bằng hai cách: dùng `jsh:none` như trên, và phát hiện chu kỳ theo template trên **mọi** request không có tag.

**An toàn:** kill -9 jsharvest khi đang `watch -guard on`:
- tab vẫn còn;
- worker có sẵn vẫn chạy;
- tải lại trang thì **worker mới vẫn chạy**, vì thiết lập tạm dừng worker mất cùng kết nối.

Lưu ý: sau khi tool chết, guard cũng không còn chặn gì nữa.

**Gate hồi quy `crawl`:** recall không đổi trên 8 app cũ; `flows-app` 2/2 (đã ghi baseline); `reqcheck` đạt trên cả 9 app.

**Đánh giá code độc lập** (agent riêng; tự kiểm bằng Go test và Chrome). Đã sửa:
1. Timer đặt sau `await` trong handler được gắn `jsh:none` và **ném mất tag thật** nằm sâu hơn trong chuỗi. Giờ `jsh:none` chỉ có hiệu lực khi không còn tag nào khác.
2. Chuỗi không rỗng nhưng không có tag bị đẩy thẳng vào background. Giờ chuyển sang cửa sổ thời gian, đúng như §0.
3. **Form có control tên `action` hoặc `id`** làm `form.action`/`form.id` trả về phần tử, JSON lỗi, và mọi event của form bị bỏ. Reporter giờ đọc thuộc tính qua `getAttribute` và getter của prototype; Go giải mã `element` tách riêng, nên phần tử lỗi không làm mất event.
4. Mặc định coi request định kỳ là poll gây nhận nhầm với upload chia chunk và click đều tay. Giờ đòi hỏi có khoảng nghỉ giữa các lần gọi, và (với nhóm không thuộc hành động nào) có ít nhất một lần nằm ngoài mọi cửa sổ.
5. RxJS dùng `setInterval` cho độ trễ một lần. Giờ chỉ từ lần kích hoạt thứ hai mới tính là lặp; tick đầu của một poll thật được gom về poll nhờ phát hiện chu kỳ.
6. Trên trang đã tải sẵn, handler có thể chạy hai lần, và `removeEventListener` có thể không gỡ được. Wrapper giờ gỡ hàm gốc trước khi thêm, và gỡ cả hai khi remove.
7. Reporter đọc `innerText` với mọi phím gõ, và có thể chép chữ người dùng gõ vào `label`. Giờ chỉ mô tả phần tử với `click`/`submit`/`change`, không đọc text của ô nhập hoặc vùng contenteditable, và dùng `textContent` có giới hạn.
8. Gõ phím đóng cửa sổ của click trước. Giờ `input`/`key` không đóng cửa sổ.
9. Giá trị trích ra giữ cả body trong bộ nhớ (`strings.Clone`); checkpoint giãn ra khi log lớn.
10. `watch` ghi cả traffic khi tab rời khỏi scope. Giờ không ghi request của trang ngoài scope.
11. Tagger dùng chung `sourceURL` với resolver, nên `setTimeout(fetch, 0, url)` bị coi là traffic của tool. Tagger giờ có `jsharvest-tagger` riêng.
12. Các mục nhỏ:
    - `watch` kết thúc khi mất kết nối tới trình duyệt;
    - Ctrl-C lần hai thoát ngay;
    - file partial chỉ bị xoá khi đã ghi file cuối thành công;
    - `onclick` chỉ nhận hàm;
    - thêm `MathMLElement`;
    - `SetSkipAllPauses` khi tự bật Debugger;
    - `flows-check.sh` kiểm cả mã thoát của `watch`;
    - lượt "chỉ cửa sổ thời gian phải trượt" đã được tự động hoá.

**Còn mở sau review:**
- **Guard ở chế độ `watch`** chặn ghi của worker, service worker và iframe *mọi tab khác* mà nó không xác định được nguồn gốc. Hiện mới có cảnh báo; khuyến nghị dùng profile riêng cho target (Chrome 136+ đã bắt buộc profile riêng khi bật cổng debug). Cần giới hạn guard theo cây frame và target của tab đang `watch` trước bước 4.5.
- Trang có thể giả mạo việc gán bằng `console.createTask("jsh:…")`. Chấp nhận được với công cụ pentest có ủy quyền.
- Script chống bot có thể nhận ra `setTimeout`/`addEventListener` đã bị thay.

**Giới hạn còn lại:**
- Chuỗi `await`/Promise dài trên trang bận vẫn có thể mất tag. Lúc đó request được gán theo cửa sổ thời gian; nếu ngoài cửa sổ thì vào background.
- Event không được bọc (`scroll`, `IntersectionObserver`, `message`, `mousedown`/`pointerdown`) không tạo hành động. Request của chúng được gán theo cửa sổ thời gian, hoặc vào background nếu đến trước mọi hành động (một dropdown mở bằng `mousedown` gửi request trước khi có `click`).
- Handler đăng ký trước khi `watch` gắn vào (khi không dùng `-reload`) được gán theo cửa sổ thời gian.
- Chưa thử Playwright `route` (Fetch ở cấp trang) chạy cùng guard.
