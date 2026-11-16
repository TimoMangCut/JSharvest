# GĐ4 4.2 — Recorder (`requests.jsonl`): thiết kế

Mục tiêu: ghi **mọi request** mà tab và các target của nó (worker, service worker, shared worker, OOPIF) gửi đi, kèm response, thành `requests.jsonl`. Đây là đầu vào cho 4.3 (gom theo tính năng) và 4.8 (xuất cho fuzz).

## 1. Nguồn và cách ghép

Mỗi session capture có một `recorder` riêng (`internal/capture/record.go`). `netTracker` hiện có (chỉ lo body của script) **không bị sửa**, để không ảnh hưởng tới phần thu thập JS đã ổn định.

| Event | Dùng để |
|---|---|
| `requestWillBeSent` | method, URL, header (chưa có Cookie), body (`postDataEntries`; nếu `hasPostData` mà không có entry thì gọi `getRequestPostData`), loại, frame, initiator, thời điểm. Nếu có `redirectResponse`: kết thúc hop trước, mở hop mới **cùng `requestId`** |
| `requestWillBeSentExtraInfo` | header thật gửi lên dây (có Cookie) |
| `responseReceived` | status, header, mime, protocol, IP, nguồn (mạng, disk cache, service worker, prefetch), `hasExtraInfo` |
| `responseReceivedExtraInfo` | header thật (có Set-Cookie), status thật (304 với cache) |
| `loadingFinished` / `loadingFailed` | kết thúc; lỗi (`errorText`, `canceled`, `blockedReason`, CORS) |

**Thứ tự không đảm bảo** giữa các loại event (chromedp phát mỗi loại qua một subscription riêng; chính CDP cũng ghi rõ ExtraInfo có thể đến trước hoặc sau). Trong cùng một loại thì thứ tự được giữ. Vì vậy:
- Mỗi `requestId` là một **exchange** gồm danh sách hop. ExtraInfo được xếp hàng theo thứ tự đến và gán lần lượt cho các hop có cờ extra (`redirectHasExtraInfo` cho hop redirect, `hasExtraInfo` cho hop cuối). DevTools ghép theo cách này.
- Exchange chỉ được ghi ra khi:
  - đã kết thúc (finished hoặc failed);
  - không còn lấy body dở;
  - và đã nhận đủ ExtraInfo dự kiến, **hoặc** đã quá 1,5 s kể từ khi kết thúc.

  Một ticker 500 ms kiểm tra điều kiện này. Khi capture dừng, mọi exchange còn lại được ghi với `outcome: "incomplete"` (long-poll, EventSource) hoặc với những gì đã có.

### Target con: phải tạm dừng worker khi khởi động

Trước đây, target con được gắn vào **sau khi** nó đã chạy. Debugger gửi lại script đã chạy, nhưng Network không có cơ chế tương tự, nên các request đầu tiên của worker bị mất (đo được: `importScripts` của worker trong webpack-vanilla).

Spike ngày 2026-11-03 thử `Target.setAutoAttach{waitForDebuggerOnStart}` trên tab:

| Cách resume | Worker | iframe khác site | Service worker |
|---|---|---|---|
| `runIfWaitingForDebugger` trên session riêng của mình | chạy tiếp | **không** chạy tiếp, trang không bao giờ load xong | chromedp treo 20 s ở `Runtime.evaluate("self")` |
| `sendMessageToTarget` tới session tự gắn | "No session with given id" (Chrome không cho dùng ở chế độ flatten) | như bên trái | như bên trái |
| detach session tự gắn | **chạy tiếp, kể cả khi không gắn session riêng** | không chạy tiếp | — |

**Cài đặt** (`targets.go`, `holdWorkers`):
- Auto-attach có chờ, **chỉ áp dụng cho `worker`** (bộ lọc loại các kiểu khác). Cấu hình này thay cho auto-attach của chromedp trên tab; capture vẫn tìm frame và worker bằng discovery như trước.
- Worker được thả ra theo hai đường song song: `runIfWaitingForDebugger` trên session của mình sau khi recorder đã đăng ký, và detach session tự gắn.
- `release` chạy trong mọi trường hợp: khi attach trả về, khi worker không thuộc diện cần gắn (ví dụ `blob:`), khi quá `AttachTimeout + 1 s`, và khi `stop`. Trước khi `stop`, auto-attach được đặt lại về không chờ.
- Lỗi khi thả worker được log ở mức Warn.

**Giới hạn đã biết** (ở `-record all`, webpack-vanilla thiếu 3/20 request):
- request đầu tiên của **iframe khác site** (`frame.js`);
- script của **service worker**, do trình duyệt tự tải (`sw.js`);
- `importScripts` lúc service worker khởi động (`sw-dep.js`).

- request mà service worker gửi **khi cài đặt, trước lúc attach** (vite-pwa: Workbox precache tải lại `registerSW.js`). Request này dùng `fetch()`, nên chế độ `api` **cũng bị thiếu**. Đây là giới hạn thật cho fuzz nếu service worker gọi API ngay khi cài đặt (hiếm gặp).

Ba mục đầu là `.js`, nên chế độ `api` không ghi chúng; JS của chúng vẫn được thu qua Debugger. Muốn khắc phục thì cần một kết nối CDP phụ có thể gửi lệnh tới session tự gắn. chromedp v0.21 không làm được việc này; để backlog.

**Request đã có response nhưng không kết thúc:** `fetch()` mà trang không đọc body thì không bao giờ có `loadingFinished`. Recorder ghi `ok` kèm `body_omitted: "unfinished"`. Request chậm hoặc long-poll được giữ cho tới khi kết thúc, hoặc tới khi capture dừng.

## 2. Request bị guard chặn

Fetch `fulfillRequest` vẫn sinh event Network bình thường (response giả `200 {}` hoặc `204`), nên nếu không có dấu hiệu gì, recorder sẽ ghi sai thành `ok`. Response giả cũng được coi là điểm kết thúc request: `fetch()` bị chặn mà trang không đọc body thì không bao giờ có `loadingFinished`. Lần chạy đầu bị ghi trùng 10 dòng vì lý do này; `reqcheck` giờ kiểm tra cả dòng trùng.
- Guard thêm header **`X-Jsharvest-Guard: <lý do>`** vào response giả. Recorder thấy header này thì ghi `outcome: "held_back:<lý do>"`, bỏ response giả và không lấy body. Cách này đúng ở mọi target, kể cả worker, nơi `networkId` của Fetch rỗng.
- Khi kết thúc lần chạy, các bản ghi guard **không khớp** với dòng nào (ví dụ target không được gắn vào) được ghi thành dòng riêng với `source: "guard"`.

## 3. Một dòng

```json
{"run":"20261103T101500Z","id":17,"ts":"…","duration_ms":12.5,
 "target":"page","target_url":"","page":"http://app/","frame":"…","cdp_id":"123.4","hop":0,
 "resource_type":"Fetch","method":"POST","url":"http://app/api/save",
 "headers":{"content-type":"application/json","cookie":"sid=…"},
 "body":"{\"name\":\"x\"}",
 "response":{"status":200,"status_text":"OK","headers":{…},"mime":"application/json","source":"network",
             "protocol":"http/1.1","remote_ip":"127.0.0.1","body":"{…}"},
 "initiator":{"type":"script","url":"…/app.js","line":10,"col":4,"stack":[{"fn":"save","url":"…","line":10,"col":4}]},
 "outcome":"ok","tags":[]}
```

- **Tên header** viết thường. Header lặp lại được nối bằng `\n`, theo đúng cách CDP làm (ví dụ nhiều `Set-Cookie`).
- **Body** không phải UTF-8 thì ghi base64 và đặt `body_base64: true`. Body vượt giới hạn thì bị cắt, kèm `body_truncated: true`. Không lấy body response thì ghi lý do vào `body_omitted` (`type`, `mime`, `size`, `held_back`, `lost:<lý do>`).
- **`outcome`:** `ok` | `redirect` (hop trung gian) | `failed:<errorText>` | `held_back:<lý do>` | `incomplete`.
- **`tags`:** `jsharvest` khi request do chính tool tạo ra (initiator có `jsharvest-internal`, tức script fetch của resolver). Cờ này giúp lọc khi fuzz.
- `action_id` được thêm ở 4.3.

## 4. Lọc và giới hạn

- `-record api` (mặc định): ghi mọi loại **trừ** Script, Stylesheet, Image, Media, Font, TextTrack. Script đã có trong store JS. `-record all` ghi tất cả; `-record off` tắt.
- **Body response** chỉ lấy khi:
  - loại là Document, XHR, Fetch, Other, hoặc bất kỳ loại nào khi chạy `-record all`;
  - mime dạng văn bản (json, text, xml, html, javascript, x-www-form-urlencoded, graphql);
  - `encodedDataLength` ≤ 4 × giới hạn.
- `-record-body N`: số byte tối đa cho mỗi body, request lẫn response (mặc định 128 KiB; `0` thì không ghi body nào).
- Lấy body dùng chung semaphore với phần lấy body script, nên không tăng số lệnh CDP song song.

## 5. Bảo mật

- `requests.jsonl` được ghi **thêm vào cuối** (mỗi dòng có `run`), quyền **0600**. `blocked.jsonl` và `blocked.har` cũng chuyển sang 0600, vì chứa header và body thật.
- `-redact` (mặc định tắt, vì fuzz cần giá trị thật) áp dụng cho `requests.jsonl`, `blocked.jsonl` và `blocked.har`:
  - **Header:** che `authorization`, `proxy-authorization`, các header có tên nhạy cảm, và giá trị từng cookie trong `cookie`/`set-cookie` (tên cookie được giữ).
  - **Tham số nhạy cảm:** query, form urlencoded, trường JSON (đệ quy). Tên nhạy cảm gồm:
    - chứa `pass`, `pwd`, `secret`, `token`, `auth`, `session`, `cookie`, `csrf`, `xsrf`, `apikey`/`api_key`, `credential`, `jwt`, `signature`;
    - hoặc đúng các tên ngắn `sid`, `key`, `otp`, `pin`, `code`, `sig`.
  - **Chuỗi dạng JWT** (`eyJ….eyJ….…`) ở bất kỳ đâu.
  - Giá trị thay thế: `REDACTED_<8 hex của HMAC-SHA256 với khoá ngẫu nhiên mỗi lần chạy>`. Trong cùng một file, giá trị giống nhau cho ra chuỗi giống nhau, nên vẫn ghép được. **Không dùng sha256 thuần**, vì hash ngắn của mật khẩu yếu có thể dò lại bằng từ điển.
  - Ngoài các tên trên, còn che: tên **kết thúc bằng** `key`/`keys` (`private_key`, `x-access-key`, `api_keys`); tên kết thúc bằng `code`/`codes` khi đứng sau các từ như `verification`, `recovery`, `otp` (nhưng `country_code` thì không); và tên chứa `passcode`, `newpass`, `verifier`, `ticket`, `saml`.
  - **Dạng dữ liệu được nhận diện:**
    - cặp JSON, kể cả giá trị là mảng;
    - khoá JS không có ngoặc kép hoặc dùng ngoặc đơn, phép gán `token = "…"`;
    - tham số GraphQL `password: \"…\"`;
    - JSON escape nằm trong chuỗi (quét vào trong, tối đa 3 tầng);
    - multipart nhiều dòng; thẻ `<input>`.
  - `"code": 200` được giữ nguyên, vì đó là mã trạng thái chứ không phải OAuth code.
  - **Body base64** (body nhị phân, hoặc text bị cắt giữa ký tự) được giải mã, che phần text bên trong, rồi mã hoá lại. Khi cắt body, điểm cắt được lùi về ranh giới ký tự UTF‑8.
  - **Chưa làm:** che nội dung file trong multipart (file được giữ nguyên), và che stack URL trong `initiator` của `blocked.jsonl`.

## 6. Kiểm chứng (cổng 4.2)

- `bin/testbed reqcheck -log <đoạn log của lần chạy> -requests <file>`:
  - **Chiều 1 (đầy đủ):** mọi dòng trong log server (method + URI, tính cả số lần) đều có trong `requests.jsonl` dưới dạng một dòng **đi qua mạng**, nghĩa là không bị chặn và không lấy từ cache hay service worker. Nhờ vậy, request bị chặn mà vẫn tới được server sẽ hiện thành `MISSING`. Ở chế độ `api`, bỏ qua path tài nguyên tĩnh (`.js`, `.css`, ảnh, font). Host được chấp nhận gồm `127.0.0.1:8770` và bí danh khác site `localhost:8770`.
  - **Không trùng:** một cặp (`cdp_id`, hop) chỉ xuất hiện một lần.
  - Nguồn response gồm `network`, `disk-cache`, `memory-cache` (`requestServedFromCache`), `service-worker`, `prefetch`. Retry khi gặp 401/407 lấy cặp ExtraInfo cuối cùng.
  - **Chiều 2 (không bịa):** mọi dòng `ok` lấy từ mạng (`source: network`) tới testbed đều có trong log server.
  - Lệch thì in ra từng dòng.
- `bench.sh` khi `GATE=1`: tách đoạn log của riêng jsharvest (tính theo số dòng trước và sau khi chạy) rồi chạy `reqcheck`.
- Ngoại lệ đã biết, phải ghi rõ khi gặp, ví dụ request do chính trình duyệt khởi tạo như favicon nếu Network không thấy.
- **Unit test:** che giá trị (header, cookie, query, form, JSON lồng nhau, JWT, HMAC ổn định trong một lần chạy), giới hạn body, base64, ghép ExtraInfo theo hop (hoán vị thứ tự event), lọc theo loại.
- **Chi phí:** so thời gian chạy bench `-record off` và `-record api`; ngưỡng ≤ 15%.

## 7. Kết quả (2026-11-03)

**Gate (`GATE=1 bench.sh`, chế độ `api`):** recall JS không đổi trên cả 8 app; `reqcheck` đạt trên cả 8 app (đủ, không bịa, không trùng). `guard-cases`: 15 request bị chặn được ghi `held_back`, mỗi request đúng một dòng.

**Kiểm tra nghiêm ngặt (`-record all`, mọi request kể cả file tĩnh), số request server phục vụ so với số có trong log:**

| App | Server | Thiếu | Lý do |
|---|---|---|---|
| angular-ngsw | 15 | 1 | `ngsw-worker.js` (script service worker) |
| angular-ngsw-default | 13 | 0 | |
| edge-cases | 10 | 0 | |
| guard-cases | 9 | 1 | `guard-sw.js` (script service worker) |
| next-mixed | 17 | 0 | |
| vite-pwa | 16 | 3 | `sw.js`, `workbox-*.js` (`importScripts`), precache `registerSW.js` |
| vite-vanilla | 11 | 0 | |
| webpack-vanilla | 20 | 3 | `sw.js`, `sw-dep.js`, `frame.js` (iframe khác site) |

Tổng: 103/111 (93%); mọi chỗ thiếu đều thuộc các giới hạn đã biết ở mục 1. 0 dòng bịa, 0 dòng trùng.

**Chi phí:** thời gian chạy `-record off`, `api`, `all` chênh nhau dưới ±0,3 s trên mọi app, nhỏ hơn dao động giữa các lần chạy. Đạt ngưỡng ≤ 15%.

**Đánh giá độc lập** (agent riêng, đọc code, không được xem kết luận của mình). Các lỗi đã sửa:
- `-redact` bỏ qua body base64 (H1);
- nhiều tên và dạng dữ liệu lọt khi che (H2);
- worker có thể bị dừng vĩnh viễn sau `Stop` (M3);
- request chậm hơn 10 s bị ghi sớm và mất response (M5);
- retry 401/407 bị ghép sai header thật (M6);
- `reqcheck` chứng minh ít hơn những gì nó tuyên bố, và memory cache bị ghi là `network` (M7).

Còn để lại:
- Request gửi giữa lúc `Stop` sweep và lúc đóng tab không được ghi.
- Lần sweep cưỡng bức khi `Stop` có thể ghi request vừa xong mà thiếu header thật.
- Body về sau `Drain` bị mất.
- Che nội dung file trong multipart, và che `initiator` trong `blocked.jsonl`.
