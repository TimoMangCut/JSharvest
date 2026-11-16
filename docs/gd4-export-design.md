# GĐ4 4.8 — Xuất cho fuzz theo cụm

**Mục tiêu** (plan bản 2, mục 4.8). Từ output của một role (`<out>/<host>/<role>/`), xuất ra những gì công cụ fuzz có sẵn dùng được ngay. Đơn vị là **cụm** (một hành động và các request nó gây ra), cộng một bản đã khử trùng theo **endpoint**:
- HAR (Burp qua extension, Caido, ZAP, DevTools);
- file request thô (`ffuf -request`, `sqlmap -r`, Burp Repeater);
- danh mục tham số `params.jsonl`.

**Chỉ đọc output, không gửi request nào.** Replay và fuzz tự động thuộc GĐ5. Gate dùng một lệnh replay riêng của testbed, chỉ nhắm vào server testbed.

**Cổng nghiệm thu (plan):** mỗi cụm ra được HAR, file request thô và danh mục tham số; replay một request đã xuất trên testbed cho response giống bản gốc. Cụ thể hơn ở mục 7.

## 1. Đầu vào

```
<out>/<host>/<role>/  requests.jsonl  flows.jsonl  endpoints.jsonl  run.json  runs.jsonl
```

- **Request:** `requests.jsonl` qua `results.Dir` (header thật lấy từ `requestWillBeSentExtraInfo`, có `cookie`; body request; response, kể cả body nếu đã lưu).
- **Cụm:** `flows.jsonl` của run được chọn: hành động, request kèm `how`, `depends_on`, `writes`.
- **Code:** catalog endpoint (`endpoints.Catalog`, chỉ đọc cache), cho biết tham số nào có trong JS và tham số nào **chỉ có trong JS**.
- **Run:** mặc định là run mới nhất có `flows.jsonl`. `-run ID` chọn run cụ thể, `-run all` gộp mọi run (mỗi cụm vẫn thuộc một run).

## 2. Chọn request

Request được xuất khi:
- thuộc scope của target (`-scope` của run, lấy từ `run.json`). **Host ngoài scope không bao giờ được xuất mặc định** (analytics, CDN, SSO bên thứ ba), vì fuzz chúng là đi ra ngoài phạm vi được phép. `-third-party` để xuất cả chúng, kèm cảnh báo;
- không phải request của jsharvest (`Internal`: resolver; tagger);
- thuộc loại gọi ứng dụng: `Fetch`, `XHR`, `EventSource`, `Ping`, `Other` (chỉ khi catalog biết endpoint đó), và `Document` khi có tham số (query, body) hoặc method khác GET (form submit);
- không phải WebSocket (công cụ đích không fuzz được qua file request thô; vẫn liệt kê trong `params.jsonl` với `in: ws`).

**Request bị guard giữ lại** (`held_back:*`) **vẫn được xuất**. Đây chính là các request ghi mà người kiểm thử cần nhất. Chúng được đánh dấu rõ: tên file có `held`, HAR có `_jsharvest.held_back`, và response trong HAR là response giả của guard kèm ghi chú "never reached the server".

## 3. Định dạng file request thô

Một file là một request HTTP/1.1, xuống dòng CRLF:

```
POST /api/profile HTTP/1.1
Host: app.example.com
Content-Type: application/json
X-Csrf-Token: cd4b5e777d645459a88b29ed
Cookie: sid=…
…
Content-Length: 22

{"display_name":"Bob"}
```

- **Luôn là HTTP/1.1**, kể cả khi Chrome đã gửi bằng HTTP/2 hoặc 3. Công cụ đích không đọc HTTP/2 từ file. Pseudo-header (`:authority`, `:method`, `:path`, `:scheme`) được đổi thành dòng request và `Host`.
- **Host đứng đầu**, các header khác theo thứ tự cố định gần với thứ tự Chrome gửi (CDP trả header dạng map nên thứ tự gốc đã mất). Tên header viết theo dạng chuẩn (`X-Csrf-Token`).
- **Bỏ** `Connection`, `Keep-Alive`, `Transfer-Encoding`, `Priority`, `Accept-Encoding` (header hop-by-hop, chỉ có nghĩa với HTTP/2, hoặc làm công cụ nhận body nén mà không giải được).
- **Dòng request ở dạng origin-form** (`/path?query`, đã escape, không có fragment). Scheme không nằm trong file. `README.txt` và `manifest.json` ghi lệnh cho từng công cụ: `-request-proto http|https` cho ffuf, `--force-ssl` cho sqlmap khi target dùng https.
- **`Content-Length` được tính lại** theo body thực sự được ghi ra file (mục 3.1).
- **Bỏ `Accept-Encoding`** (mục 3.1).
- Nhiều header trùng tên (hiếm, vì Chrome gộp `Cookie` thành một dòng) được gộp lại: `Cookie` nối bằng `; `, các header khác nối bằng `, `.
- **Body đúng từng byte** như Chrome đã gửi (giải base64 nếu body nhị phân).
- **Body không đủ** thì vẫn xuất, nhưng `manifest.json` ghi lý do và file không được chọn làm bản đại diện của endpoint. Có hai trường hợp: (a) recorder đã cắt (`body_truncated`); (b) `content-length` gốc lớn hơn body ghi được, thường là multipart có file vì CDP không trả nội dung file.

### 3.1 Tương thích công cụ

Tra cứu mã nguồn và tài liệu ngày 2026-11-04. Không chạy công cụ nào; xem mục 7 về việc kiểm bằng công cụ thật.

| Công cụ | Cách đọc | Hệ quả cho export |
|---|---|---|
| **ffuf** `-request` (`parseRawRequest`) | Nhận cả `\n` lẫn `\r\n`. Dòng request tách theo dấu cách, chỉ dùng method và target. URL dựng bằng `-request-proto` (mặc định **https**) + header `Host`, **tra theo đúng chữ `Host`** (phân biệt hoa thường). Header lưu trong map nên trùng tên thì chỉ còn dòng cuối. **Bỏ `Content-Length`** và để Go tự tính sau khi thay `FUZZ`. Tự giải nén gzip, br, deflate, **nhưng không giải nén zstd**. `FUZZ` thay được trong method, URL, tên header, giá trị header và body | Viết `Host` theo dạng chuẩn. Bỏ `Accept-Encoding`: khi đó Go tự thêm gzip và tự giải nén. Không có pseudo-header (tên header rỗng làm hỏng mọi request). Ghi `-request-proto` vào README |
| **sqlmap** `-r` (`parseRequestFile`) | Nhận `\n` hoặc `\r\n`. Dòng request khớp `HTTP/[\d.]+`. **Bắt buộc có `Host`**. Scheme lấy từ `Host: x:443` hoặc `--force-ssl`, **nếu không thì là http**. Bỏ `Content-Length` rồi tính lại. Tự lọc `Accept-Encoding`. **Mọi dấu `*` là điểm tiêm** (URL, body, cookie, header), trừ `*/*` và `;q=…` trong header | File không đánh dấu không được có `*` lạc. Không thể bỏ `*` mà không đổi request, nên `manifest.json` liệt kê các file có `*` (`sqlmap_marker`) để người dùng biết. Ghi `--force-ssl` vào README |
| **Burp** | **Không nhập HAR** nếu không cài thêm extension (BApp "HAR Importer"). Repeater mở được file thô ("Paste from file"), có "Update Content-Length". Không có cách nhập hàng loạt file thô | README: file thô dùng cho Repeater; để đưa cả cụm vào Burp thì cho ffuf hoặc sqlmap đi qua proxy của Burp (`-replay-proxy`, `--proxy`), hoặc dùng BApp |
| **Caido** | Không nhập HAR | Như Burp: dùng proxy |
| **ZAP** | Nhập HAR có sẵn (add-on Import/Export). **Đọc `response` mà không kiểm null**; phiên bản HTTP lạ bị bỏ | Mọi entry phải có `response`. `httpVersion` chỉ dùng `HTTP/1.1`, `HTTP/2` hoặc `HTTP/3` |
| **DevTools** (`HARFormat.ts`) | Bắt buộc có: `log.creator`, `log.entries`; trong mỗi entry có `startedDateTime`, `time` (0 cũng được), `request` (`headersSize`, `bodySize`), `response` (`httpVersion`, `content.size`), `timings` (`send`, `wait`, `receive`). Không bắt buộc `pages` | Theo HAR 1.2: request có `queryString`, response có `redirectURL` và `content.mimeType`; trường riêng bắt đầu bằng `_` |

**Quyết định:**
- File thô **mặc định không đánh dấu**, vì `FUZZ` của ffuf và `*` của sqlmap hại nhau. Bản có đánh dấu nằm riêng trong `ffuf/`.
- Request không có response (bị guard giữ, lỗi mạng) có trong HAR với `response.status: 0`, `content: {size: 0, mimeType: "x-unknown"}`, giống cách Chrome ghi request bị chặn, kèm `_jsharvest` nêu lý do.

## 4. Cấu trúc output

```
<dest>/                      (mặc định <out>/<host>/<role>/export/; thư mục 0700, file 0600)
├── manifest.json            run, số lượng, cảnh báo, từng cụm và file của nó
├── README.txt               lệnh mẫu cho từng công cụ
├── all.har                  mọi request đã chọn của các run, kèm response
├── params.jsonl             danh mục tham số (mục 5)
├── flows/<NN>-<kind>-<slug>/
│   ├── flow.har
│   ├── flow.json            hành động, request (id, file), depends_on viết dễ đọc
│   └── <NN>-<METHOD>-<slug>[.held].http
├── endpoints/<METHOD>-<slug>.http      một request đại diện cho mỗi endpoint
└── ffuf/<METHOD>-<slug>/<in>-<name>.http   FUZZ đặt ở đúng một chỗ
```

- **`flows/`** giữ đúng thứ tự trong cụm: replay một tính năng là chạy lần lượt các file của nó. Với cụm `background`, mỗi endpoint chỉ xuất **một** request, vì heartbeat có thể lặp hàng trăm lần.
- **`endpoints/`** là bản đã khử trùng, để fuzz mỗi endpoint đúng một lần. Endpoint là template đã suy chung trên mọi request được chọn (`flow.Templates`, như 4.7). Bản đại diện là request mới nhất có body đủ và response 2xx; không có thì lấy request mới nhất.
- **`ffuf/`**: mỗi tham số của mỗi endpoint một file, trong đó giá trị của tham số được thay bằng `FUZZ`. Bất biến: thay `FUZZ` bằng giá trị gốc phải cho lại đúng từng byte file trong `endpoints/`. Bỏ qua tham số kiểu `graphql` (cả câu query) và tham số `dynamic` (mục 5) có tên nhạy cảm, vì fuzz token CSRF chỉ tạo ra 403.
- **Ghi đè an toàn:** output được ghi vào thư mục tạm rồi đổi tên. Thư mục đích cũ chỉ bị xoá khi nó chứa `manifest.json` do jsharvest tạo; nếu không thì lệnh dừng với lỗi.

## 5. `params.jsonl`

Mỗi dòng ứng với một bộ (endpoint, vị trí, tên):

```json
{"endpoint":"POST 127.0.0.1:8770/api/profile","in":"header","name":"x-csrf-token","type":"hex",
 "samples":["cd4b5e777d645459a88b29ed"],"count":1,"observed":true,"in_js":null,
 "dynamic":{"from":"GET /api/csrf","at":"json:$.csrf"},"sensitive":true,
 "flows":["a8"],"requests":[{"run":"…","id":27}],"file":"endpoints/POST-api-profile.http","ffuf":null}
```

- **`in`** là một trong: `path` (kèm `index` của đoạn path, `name` là tên trong template, ví dụ `{id}`, hoặc `seg3`), `query`, `json` (`name` là JSON path `$.user.email`), `form`, `multipart`, `header` (bỏ các header thông thường, như `flow.plainHeader`), `cookie` (từng cookie), `ws`.
- **Đoạn path là tham số** khi template có placeholder ở đó, **hoặc** khi `depends_on` cho biết giá trị đó lấy từ một response trước (`GET /api/notes/note_53ec…` chỉ gặp một lần nên không suy được template, nhưng `path:3 ← json:$.id`).
- **`type`** suy từ các giá trị mẫu: `int`, `float`, `bool`, `uuid`, `hex`, `jwt`, `base64`, `email`, `url`, `date`, `json`, `graphql`, `empty`, `string`. Nhiều kiểu khác nhau thì ghi kiểu chung nhất.
- **`samples`**: tối đa 5 giá trị khác nhau.
- **`dynamic`**: giá trị lấy từ response trước (`depends_on`). Khi replay hoặc fuzz phải lấy giá trị mới, không được dùng giá trị đã ghi (token CSRF, id vừa tạo).
- **`in_js`**: `true` khi catalog có tên tham số này cho endpoint đó; `false` khi catalog có endpoint đó và có liệt kê tham số, nhưng không có tên này; `null` khi không biết (endpoint không có trong code, hoặc extractor không thấy body).
- **Tham số chỉ có trong JS** (`observed:false`): tên mà code gửi tới endpoint nhưng traffic chưa từng có, ví dụ `include_deleted`. Đây là tham số ẩn đáng thử nhất. Endpoint chỉ có trong code (`static`) cũng được liệt kê theo cách này, nhưng **4.8 không dựng request tổng hợp cho chúng** (mục 8).
- **`sensitive`**: theo `traffic.Sensitive`.

## 6. Che giá trị nhạy cảm

- **Mặc định xuất giá trị thật**, vì mục đích là replay trên target được phép: thiếu cookie hay token thì file vô dụng. Điều này giống recorder (ghi giá trị thật trừ khi có `-redact`). File 0600, thư mục 0700; `README.txt` và stderr nhắc rằng thư mục này chứa credential.
- **`-redact`** dùng `traffic.Redactor` (HMAC theo lần chạy) cho mọi nơi: URL, header, body, HAR, `params.jsonl`. Dùng khi cần chia sẻ; file khi đó không replay được.
- Nếu `requests.jsonl` đã bị che lúc ghi (có giá trị `REDACTED_…`), export cảnh báo rằng file sẽ không replay được.

## 7. Fixture và gate (`testbed/export-check.sh`)

**Fixture.** Server của flows-app hiện không kiểm CSRF hay session, nên replay trên đó không chứng minh được export mang đủ thông tin xác thực. Thêm vào server:
- `/api/config` đặt cookie `fsid` (session);
- `GET /api/csrf` ghi token đã cấp cho session đó; `POST /api/profile` trả 403 khi thiếu cookie hoặc token không thuộc session.

Request mong đợi của flows-app không đổi, nên `flows-check.sh` vẫn giữ ý nghĩa cũ.

**Gate:**
1. Chạy flows-app như `flows-check.sh` (watch, driver CDP), một lần khi guard tắt và một lần khi guard bật; sau đó chạy `jsharvest export`.
2. **Đủ:** mọi request trong scope có loại được chọn đều xuất hiện trong đúng một cụm; mọi cụm có `flow.har`; mọi endpoint quan sát được có một file trong `endpoints/`.
3. **Đúng định dạng:** mọi file `.http` đọc được bằng `http.ReadRequest` của Go; method, URL, body và header (trừ các header đã bỏ) khớp với `requests.jsonl`. HAR đủ các trường bắt buộc của HAR 1.2.
4. **Replay** (`bin/testbed replay`, chỉ tới `127.0.0.1:8770`):
   - mọi GET trong `endpoints/` cho cùng status, và cùng body với các route tất định;
   - `POST /api/profile` từ bản export cho 200, còn bản `-redact` cho 403.
5. **ffuf:** trong mỗi file có đúng một `FUZZ`; thay bằng giá trị gốc thì ra đúng file đại diện.
6. **params.jsonl** khớp `export.truth.json`:
   - `GET /api/search` có query `q` (string) và `page` (int, in_js);
   - `POST /api/profile` có header `x-csrf-token` là dynamic từ `GET /api/csrf`;
   - `GET /api/notes/{…}` có path là dynamic từ `POST /api/notes`;
   - `PUT /api/upload/{id}` có path int;
   - analytics `t`.
7. **Guard bật:** các request ghi bị giữ vẫn có file `.held.http`, và HAR ghi rõ là bị giữ.
8. **Công cụ thật (tuỳ chọn, cần người dùng cho phép chạy image bên ngoài):** `ffuf -request` và `sqlmap -r` trong Docker tới testbed. Nếu không được phép, gate dựa trên `http.ReadRequest` và một bộ đọc mô phỏng đúng các quy tắc ở mục 3.1 (Host phân biệt hoa thường, bỏ Content-Length, `*`).
9. **An toàn:** quyền 0600/0700; bản `-redact` không chứa cookie, token hay giá trị CSRF nào đã biết; không có host ngoài scope; `export` không gửi request nào (log server không đổi trong lúc export).

## 8. Ngoài phạm vi (để sau)

- Request tổng hợp cho endpoint chỉ có trong code (`static`), với `FUZZ` ở các chỗ `{}`.
- Đổi credential sang role thấp hơn để kiểm thử phân quyền (lấy request của admin, gắn cookie của user), nối với 4.7.
- Template nuclei.
- Replay và fuzz tự động (GĐ5).

## 9. Đánh giá độc lập (2026-11-04) — có hiệu lực cao hơn mục 1–8

Reviewer đọc code và dữ liệu thật (`bin/flows-check`, `bin/rx`, `bin/explore-check`). Mình kiểm lại từng phát hiện quan trọng trên dữ liệu trước khi nhận.

**Phải sửa:**
1. **Request bị guard giữ, request của worker và request trả từ cache chỉ có header tạm** (provisional): không có `Cookie`, `Host`, `Origin`. Đã kiểm trên mọi output cũ: 100% request `held_back` đều như vậy. Lý do: không có `requestWillBeSentExtraInfo` khi request không ra tới mạng. Sửa:
   - recorder ghi `headers_provisional: true` (dữ liệu cũ: nhận ra bằng việc thiếu `host` và `:authority`);
   - export **mượn** `Cookie` từ request có header thật gần nhất (trước, rồi sau) tới cùng host trong cùng run, và thêm `Origin` (origin của trang) cho request không phải GET; ghi `cookie_from` vào `_jsharvest` và manifest;
   - entry có header tạm không được chọn làm bản đại diện khi có entry header thật;
   - gate replay `POST /api/profile` **bị giữ** (run có guard) phải ra 200; `/api/export` (gọi từ worker) đòi cookie `fsid`.
   - Hướng đúng hơn (để sau): guard lấy cookie bằng CDP lúc giữ request.
2. **Bất biến của `ffuf/`.** File ffuf **không có `Content-Length`** (ffuf bỏ nó). Chèn `FUZZ` bằng cách thay đúng đoạn byte trong request gốc, không serialize lại. "Giá trị gốc" là **đoạn đã mã hoá** (`a%20b`, `\"`), không phải giá trị đã giải mã trong `params.jsonl`. Nếu request đã chứa chữ `FUZZ` thì dùng keyword khác và ghi vào manifest. README ghi `-enc` cho path, query và form.
3. **Khoá endpoint phải có operation GraphQL/RPC** như 4.7. Nếu không thì mọi operation trên `POST /graphql` gộp thành một. `gqlOperation` và `discriminators` chuyển sang `flow.Operation`, dùng chung cho `roles` và `export`.
4. **Giá trị header có `\n`** (CDP nối header trùng bằng `\n`): tách rồi nối lại. `raw.go` đã làm như vậy từ đầu; mục 3 ghi sai giả định.

**Nên sửa (đã nhận):**
5. HAR của request bị giữ: `status: 0` ở mọi chỗ (recorder không có response giả). `guard/report.go` ghi `httpVersion: ""`, ZAP sẽ bỏ: sửa thành `HTTP/1.1`.
6. Chọn request:
   - **hop chuyển hướng:** chỉ hop 0 có file `.http`, HAR giữ mọi hop;
   - **`Document` GET không có query** vẫn được xuất khi template có placeholder hoặc có đoạn path lấy từ response trước (IDOR kiểu `/members/123`);
   - request trang mà service worker trả lời và request mạng của chính service worker là trùng nhau: bỏ bản `source: service-worker` khỏi `.http`;
   - loại `Preflight`;
   - `failed:*` và `incomplete` không bao giờ là bản đại diện;
   - loại `""` được tính như `endpoints.apiTypes`;
   - bỏ `in: ws` (không có frame nào được ghi).
7. **`dynamic` đổi thành `derived_from`** (một sự kiện) kèm `refresh: likely|unknown`. `likely` khi tên là tên nhạy cảm, hoặc khi nguồn trả giá trị khác nhau ở các lần gọi khác nhau. Lý do: `dependsOn` khớp theo giá trị chính xác, nên giá trị ổn định (user id) hay giá trị người dùng nhập được phản hồi lại cũng tạo liên kết. `flow.json` ghi các **request tiên quyết nằm ở cụm khác** (ví dụ token CSRF lấy lúc tải trang).
8. **`in_js` theo từng vị trí:** `false` chỉ khi catalog có danh sách **cho đúng vị trí đó**; `path` và `cookie` luôn là `null`. Tên body trong catalog là tên phẳng: khớp với khoá cấp đầu hoặc tên lá của JSON path. Ghép với catalog qua template (như `roles.pair`). Fixture thêm một tham số chỉ có trong code, không bao giờ được gửi.
9. **File ffuf của một tham số lấy từ request mới nhất có chứa tham số đó**, không phải luôn từ bản đại diện (tham số tuỳ chọn, biến thể).
10. **Khoá endpoint dùng thêm `depends_on` và catalog:** đoạn path lấy từ response trước, hoặc khớp `{}` của template trong catalog, trở thành placeholder (`/api/notes/note_53ec…` không suy được bằng hình dạng).
11. **Endpoint phá huỷ** (DELETE, `guard.Destructive`: logout, wipe…): có cờ `destructive` trong manifest và `params.jsonl`, và file ffuf của chúng nằm riêng ở `ffuf-destructive/`.
12. **Rò rỉ qua tên file:** slug luôn dựng từ method, template (đã qua `roles.MaskTokens`) và loại hành động, không lấy từ nhãn hay path thô. Với `-redact`: nhãn, manifest và `samples` đi qua Redactor; HAR bỏ body response.
13. Gate:
    - mỗi kiểm tra ghi rõ dùng run nào (`-run`);
    - độ đủ so với danh sách request trong `flows.truth.json`, không so với template do chính export suy ra;
    - dòng request lấy từ chuỗi URL gốc (bỏ scheme, host và fragment), không dùng `RequestURI()` vì hàm này có thể escape lại; fixture có path chứa `{}|[]`;
    - **chạy ffuf và sqlmap thật ít nhất một lần trước khi chốt 4.8** (cần người dùng cho phép chạy image bên ngoài).
14. Nhỏ:
    - chỉ số `path:N` tính từ 1, sau khi bỏ `/` ở hai đầu;
    - với `-run all`, tên file có thêm run;
    - `-redact` dùng khoá HMAC mới, nên mã che khác với `requests.jsonl` đã che lúc ghi;
    - README nhắc `-timeout` cho EventSource;
    - thêm `-scope fqdn` lúc export, để thu hẹp so với scope `rdn` của run.

**Reviewer xác nhận đúng:** fixture CSRF (token theo session) không làm hỏng flows-check, endpoints-check hay explore-check, vì cookie là header thông thường nên không tạo `depends_on` mới; vẫn phải chạy lại cả 3 gate. Cũng đúng: loại host ngoài scope theo mặc định; file thô không đánh dấu; bỏ `Accept-Encoding`; chuyển về HTTP/1.1; `Ping`; `Other` chỉ khi catalog biết.

## 10. Kết quả (2026-11-04)

**Lệnh:** `jsharvest export -target HOST [-role R] [-run ID|all] [-dest DIR] [-scope rdn|fqdn] [-third-party] [-redact]`. Package `internal/export`:
- `raw.go`: file thô;
- `parse.go`: vị trí byte của từng tham số, đọc lại từ chính file thô;
- `har.go`;
- `catalog.go`: ghép với catalog qua template;
- `params.go`;
- `export.go`: chọn request, vá header tạm, template;
- `write.go`.

**Sửa ở chỗ khác:**
- recorder ghi `headers_provisional`;
- thêm `flow.Operation` và `flow.EntryTemplates`; `flow.PlainHeader` được export;
- `guard/report.go` ghi `httpVersion: HTTP/1.1`;
- lệnh `diff` đọc `JSHARVEST_OUTPUT` (trước đây đọc nhầm `JSHARVEST_OUT`).

**Phát hiện khi chạy trên dữ liệu thật:**
1. **Template phải suy theo frame của ứng dụng nằm dưới hàm bọc request**, như `flows.jsonl` làm (`appFrames` bỏ qua "hub"). Dùng frame trên cùng (`results.Req.Initiator`) thì mọi request của flows-app đi qua `apiClient` gộp lại thành `/api/{param}` (15 endpoint thay vì 29). **4.7 cũng mắc lỗi này** (`roles/endpoints.go` truyền `Frame: q.Initiator`); role-app không bắt được vì gọi `fetch` trực tiếp. Đã sửa cả hai bằng `flow.EntryTemplates`.
2. **Cookie là tham số của host, không phải của endpoint.** Khi fixture có cookie `fsid`, `params.jsonl` có 27 dòng `fsid` (mỗi endpoint một dòng) và 27 file ffuf fuzz chính session cookie. `traffic.Sensitive("fsid")` là `false`, nên luật bỏ qua credential không bắt được. Giờ mỗi cookie có một dòng cho mỗi host (`endpoint: "* host"`) và không có file ffuf.
3. Với `-redact`, body response bị bỏ trước khi tính `refresh`, nên `refresh: likely` chỉ còn dựa vào tên. Đã sửa: giá trị của các nguồn được đọc trước khi che.
4. **Bản thân gate từng yếu ở hai chỗ:**
   - server chấp nhận mọi `fsid` khác rỗng, nên bản `-redact` vẫn lấy được `/api/export`: giờ `fsid` được ký như token CSRF;
   - bảng token CSRF nằm trong bộ nhớ nên mất khi server khởi động lại: giờ token được ký theo session (nonce cộng HMAC).

**Gate `testbed/export-check.sh`** ghi flows-app hai lần (guard tắt, rồi guard bật), chạy export ba bản, và kiểm bằng `bin/testbed exportcheck`:

| | off | red (`-redact`) | on (guard bật) |
|---|---|---|---|
| request của các bước có file thô trong cụm | 28/28 | 28/28 | 28/28; mọi request ghi là `.held.http` |
| request API nằm trong đúng một cụm | 139/139 | 139/139 | 139/139 |
| file thô đọc được bằng `http.ReadRequest` / khớp log | 110 / 35 | 110 / 35 (header chỉ kiểm tên) | 110 / 35 |
| HAR đủ trường bắt buộc (ZAP, DevTools) | 23 | 23 | 23 |
| file ffuf: một keyword, đúng là request nguồn với một giá trị được thay | 41 (+5 không có file trong cụm) | — | 41 (+5) |
| `params.jsonl` khớp truth | 12/12 | 12/12 | 11/11 (`derived_from` của note không có, vì `POST /api/notes` bị giữ) |
| replay GET của `endpoints/`: cùng status (và cùng body ở route tất định) | 18/18 | — | 18/18 |
| replay save profile / export của worker | 200 / 200 | **403 / 401** | **200** (save bị giữ, cookie mượn) / 200 |
| không còn bí mật nào của log | — | đạt | — |
| cookie mượn cho request có header tạm | 2 | 2 | 16 |

Kiểm thêm:
- export không gửi request nào (log server không tăng);
- chạy lại export thì thay đúng thư mục do mình tạo;
- từ chối ghi đè một thư mục lạ;
- quyền 0600/0700;
- chỉ có một host.

**Hồi quy:**
- unit `-race` đạt;
- `flows-gate`: 28/28 ở nhịp thường, nhịp nhanh, MCP và guard;
- `roles-check`: 27 mục;
- `endpoints-check`: 26/26;
- `explore-check`, `frontier-check` (33/33) và `attach-guard` đạt;
- bench đạt (webpack 19/20, vite 10/10, vite-pwa 10/10…).

**Đánh giá độc lập đợt 3 (2026-11-04):**
- NEW-4.8-01: endpoint khớp cả bản ghi catalog bị gate lẫn bản ghi không bị gate thì không có `native` theo script. Đã sửa bằng `roles.nativeOf`.
- NEW-4.8-03: vị trí byte của cookie nay đúng cả với `a=1;b=2`. Đã sửa.
- NEW-4.8-02: mượn cookie theo host. Chuyển sang GĐ5.1, khi guard lấy cookie qua CDP.
- Testbed: route `/api/ra/admin/` ghi 403 hai lần. Đã sửa.

**Chưa làm:**
- chạy ffuf và sqlmap thật: script `testbed/export-tools.sh` đã có (ffuf v2.3.0, sqlmap 1.10.11, build và chạy trong container, chỉ tới testbed), nhưng lệnh chạy bị bộ phân loại an toàn chặn vì là mã từ nguồn ngoài; cần người dùng chạy hoặc cho phép;
- fixture có path chứa `{}|[]` (mới có unit test cho `requestTarget`);
- guard lấy cookie bằng CDP lúc giữ request (hiện vẫn mượn theo host);
- request tổng hợp cho endpoint chỉ có trong code;
- đổi credential sang role thấp hơn;
- template nuclei.
