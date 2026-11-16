# Đợt 28–30: kế hoạch đã chốt (2026-11-15)

Nguồn: bốn vòng review chéo (góc nhìn ngoài, ba bản đối chiếu code, threat model bậc hai) trên các báo cáo đánh giá độc lập. Tài liệu này là bản chốt; khi mâu thuẫn với các bản review thì tài liệu này thắng.

**Đây là đặc tả** (luật, bẫy, gate của từng mục). Thứ tự làm, phase, giao việc, nghiệm thu và tiến độ ở **`docs/plan-28-exec.md`**.

## 0. Quyết định của người dùng (2026-11-15)

1. **Trọng tâm:** dừng vá `jsapi` theo từng app. Trọng tâm chuyển sang **BOLA ngang (Bước 29)**. Bước 30 chỉ làm **một** cơ chế tổng quát, chọn theo số liệu 28B(c).
2. **28B(d) (challenge) bỏ ở đợt này.** Làm lại khi có zone Cloudflare riêng. Không đo trên target thật hay của bên thứ ba.
3. **28B(a):** được kéo image Docker **Jellyfin** và **Directus** (bản SQLite), ghim theo `@sha256`. Chạy trong mạng cô lập, tắt telemetry/update, không có kết nối ra ngoài.
4. **Bước 29 không chờ tài khoản ngoài:** thiết kế và gate trên fixture `peer-app` (có cả `same-org` lẫn `cross-org`), có thể thử thêm với 2 tài khoản tạo local trên Directus/Jellyfin. Tài khoản trên target thật được cấp sau khi gate local qua.
5. **Bước 30:** tập kiểm mù đề xuất sau khi có bảng 28B(c). Nguyên tắc: SPA mã nguồn mở có OpenAPI làm ground truth; **không mở bundle trước khi code Bước 30 xong**.
6. **Proxy:** khi có `-proxy`, chỉ kiểm IP literal cộng scope. **Không có cờ tra DNS cục bộ** (proxy tự phân giải lại nên cờ đó không chặn được rebinding, và phá bất biến "không traffic nào đi thẳng").
7. **Guard chặn IP private:** `FailRequest(BlockedByClient)`. Ở `-attach`, sự bảo vệ chỉ có trong lúc `watch` chạy (giới hạn, mục 10).

## 1. Nguyên tắc thực thi

- **Mỗi lỗi "đã xác nhận" phải có test fail trước khi sửa.** Qua các vòng review, các bản đã sai tên trường (`Params` không thuộc `Result`), thứ tự thực thi (`finishTab` trước `finishRun`) và mô hình an toàn (`Sender.dial`). Ba LLM đồng ý không có nghĩa là đã kiểm chứng.
- **Mỗi commit một mục**, chạy gate theo bảng trong CLAUDE.md. Mục nào đổi khoá hoặc định dạng output thì chạy thêm `monitor-check`, `roles-check`, `export-check`.
- Mốc: `testbed/regress.sh -j 3` tại `f6f0cd4` (27F) trước khi bắt đầu 28A.
- Hiệu năng không có số đo thì không vào 28A (để ở mục 9, gate `perfgate`).

## 2. 28A-đúng (lỗi đúng/sai đã kiểm trong code)

### 2.1. `endpoints.Load` và tool MCP `endpoints`
- **Lỗi:** `Load` (`internal/endpoints/endpoints.go`) không gắn `s.Load`, nên `linkDeferred` bỏ qua mọi `Deferred`. Ảnh hưởng cả MCP `endpoints` lẫn `export` (`Catalog(…, false)`, gồm `export -drafts`). MCP gọi `Build` trực tiếp nên bỏ qua `EnrichFromArchive`.
- **Luật:** `Load` gắn `s.Load` (đọc `js/<sha>.js`). Cache có `Version` khác `jsapi.Version` **vẫn dùng** (MCP chỉ đọc, không ghi lại được), nhưng đếm vào `AnalyzeStats` (`stale_cache`) và MCP hiện số đó. Không trộn cache cũ vào output ghi ra đĩa.
- **Bẫy:** MCP **không** gọi `CatalogWithStats` (mở `results.Open` mới, đọc `requests.jsonl` từ byte 0). Giữ `Dir` đã cache (`s.open`) để đọc tăng dần; dựng catalog từ `Load` + `Build(…, endpoints.Requests(d), …)` + `EnrichFromArchive`.
- **Bẫy:** gắn `Load` làm `linkDeferred` parse module ở mỗi lần gọi tool (chi phí mới). Cache kết quả catalog trong MCP theo (stat của `index.jsonl`, stat của thư mục `static/`, stat của `archive/endpoints.jsonl`, `d.off`, `jsapi.Version`); khác thì dựng lại.
- **Gate:** unit test; `flows-check MCP=1`, `export-check`, `endpoints-check`.

### 2.2. SFC nhiều thẻ `<script>`
- **Lỗi:** `extractSFCSpans` (`internal/jsapi/preprocess.go`) không gộp `ReExports`, `Builders`, `Deferred`. (`Params` thuộc `Endpoint`, không thuộc `Result`.)
- **Luật:** gộp đủ; test dùng reflect điền mọi trường slice của `Result` rồi chạy qua phần gộp, để trường mới bị quên sẽ fail.
- **Gate:** unit test; snapshot jsapi so với HEAD (không đổi trên corpus dev, vì corpus không có SFC hai thẻ); `crosscheck-check`.

### 2.3. Mã lỗi dạng số (`verify`, `replay`)
- `SigOf` (`internal/verify/sig.go`): nhận `code` dạng số (an toàn: chỉ để phân biệt chữ ký route thật với canary).
- `errorBody` (`internal/replay/compare.go`): **không** coi mọi số khác 0/200 là lỗi (`code: 1`, `20000` là thành công ở nhiều backend). Phân loại code số (khoá `code`, `status`, `statusCode`, `errcode`, `errorCode`, `error_code`):
  - âm → lỗi;
  - **ba chữ số đầu** (khi ≥ 100) nằm trong 400–599 → lỗi. Mã nghiệp vụ kiểu `40301`, `50001`, `401001` phổ biến ở backend VN/TQ; luật "400–599" trần không bắt được chúng (phát hiện khi đọc `Judge`, 2026-11-15);
  - thành công **chỉ** khi `0`, 200–299, hoặc 2·10^k (`2000`, `20000`, `200000`). **Không** dùng "ba chữ số đầu 200–299": `2001` (invalid token), `2004` (permission denied) là mã lỗi nhóm 2xxx phổ biến (review ngoài, vòng 5);
  - còn lại (`1`, `1001`, `2001`…) → không biết: lỗi khi khác code của bản đối chứng, **hoặc** khi body không mang dữ liệu: ngoài code chỉ có các trường kiểu thông báo/siêu dữ liệu (`msg`, `message`, `error`, `status`, `timestamp`, `trace_id`/`traceId`/`request_id`…), hoặc `data` là `null`/rỗng. Ví dụ: control và trial cùng nhận `{"code":2001,"msg":"invalid token"}` (phiên role cao hết hạn) thì không được ra bypass (Carbon, vòng 6). Xét theo **cấu trúc**, không theo từ khoá trong `msg` (thông báo tiếng Việt, tiếng Trung không khớp từ điển). `{"code":1,"data":{…}}` có dữ liệu thật thì vẫn hợp lệ.
- **Root là mảng** (GraphQL lô, kể cả `[{op1}]` của 2.4): `errorBody` hiện chỉ đọc `map`, gặp `[` là trả `false`. Đọc từng phần tử: mọi phần tử là body lỗi → lỗi; chỉ một số → `NeedsReview`. `flatten` đã đọc được mảng.
- **Bẫy:** hiện tại control chỉ bị coi là thất bại khi status không 2xx. Control (role cao) cũng nhận `{"code":40301}` thì trial giống control → `compareBodies` ra `same` → **bypass giả** (lỗi có thật ở HEAD). Luật: **control có body lỗi (theo `errorBody`) là control thất bại → `Unclear`**.
- `flatten`: mảng không thứ tự so theo tập chữ ký phần tử, vẫn giữ điều kiện độ dài (mảng rỗng không khớp mảng có phần tử).
- **Fixture:** `code: 0`, `1`, `20000`, `40301` (cả hai phía), mảng đảo thứ tự.
- **Gate:** unit test; `verify-check`, `replay-check`.

### 2.4. GraphQL gửi theo lô
- **Lỗi:** `flow/operation.go` chỉ unmarshal vào `map`; body `[{…},{…}]` (Apollo BatchHttpLink) cho ra `op` rỗng. Guard thì đã xử lý mảng.
- **Luật:** **mỗi operation một khoá**; một request lô thuộc về nhiều endpoint. **Không** dùng khoá `op=A+B` (Apollo gom theo cửa sổ thời gian, cùng operation rơi vào nhiều tổ hợp).
- **Bẫy:**
  - `export.Params` lưu byte offset trên body gốc. Tách lô phải làm **trong `export`**: dựng bản đại diện có body một operation (giữ dạng mảng: `[{op1}]`, vì có server bắt buộc mảng) rồi chạy lại `Params` trên chính body đó.
  - `replay -flow` **giữ nguyên request lô gốc** (các bước sau có thể đọc `$[i]` qua `depends_on`).
  - Draft của `verify` (`internal/verify/draft.go`, khoá dedup) gộp mất `Operations`: tách theo operation.
- **Gate:** unit test; `flows-check`, `export-check`, `roles-check`, `monitor-check`, `verify-check`.

### 2.5. Rò rỉ map trong capture
- **Lỗi:** `c.initiators`, `c.requests` (`internal/capture/capture.go`) và key của `n.reqs` (`internal/capture/network.go`) không bao giờ bị xoá.
- **Bẫy:**
  - `finishRun` chạy **sau** `finishTab` và vẫn gọi `Guard.TakeFor` → `Owns`/`InitiatorOf`. Không được dọn ở `finishTab`.
  - Không dọn trong `recorder.sweep`: `rec` là `nil` khi `-record off`.
  - `LoadingFinished` có thể đến trước `ResponseReceived`; chưa có response thì chưa biết request có phải do guard trả.
  - Request không bao giờ hoàn tất (`fetch` không đọc body), các bước redirect dùng chung `requestId`, worker có `networkId` rỗng.
- **Luật:** dọn trong đường xử lý request hoàn tất của capture. Thêm cờ `held` từ header `X-Jsharvest-Guard` của response. Chỉ xoá khi đã `responded` và `finished`, không `held`, và đã qua bước redirect cuối; request thất bại (`loadingFailed`) thì xoá. Key `done` quá `staleAfter` trong `n.reqs` cũng xoá.
- Nhỏ, cùng commit: `Guard.RemoveTab` đối xứng `AddTab` (`g.ours`, gọi khi `batchPage` đóng tab). `g.csd` chỉ có khoá cho response có `Clear-Site-Data` (hiếm), không cần dọn.
- **Gate:** unit test; `parallel-check`, `explore-check`, `flows-gate`, `attach-guard`; đo heap trên `watch` dài.

### 2.6. Dữ liệu không tin cậy qua MCP
- **Luật:** JSON envelope (ví dụ trường `untrusted: "target"` ở cấp output) cộng mô tả trong từng tool. **Không** bọc bằng thẻ phân cách: `json.Marshal` đã escape chuỗi; thẻ sẽ phải escape thẻ đóng và vẫn dễ sai.
- **Gate:** `flows-check MCP=1`.

## 3. 28A-OpSec

### 3.1. `internal/netsafe`: một dialer dùng chung
- **Lỗi:**
  - `httpcrawl` kiểm `Policy.Check` (tra DNS, cache) rồi `dialer.DialContext` phân giải lại: TOCTOU. `Policy.public` coi lỗi DNS là public.
  - `replay.Sender.dial` **không phải mẫu an toàn**: chỉ so tính private với IP trình duyệt đã ghi (`Recorded`); host chưa được ghi (ví dụ `verify` tới host chỉ có trong code) thì dial vào đâu cũng được, kể cả `169.254.169.254`; `private()` thiếu CGNAT.
- **Luật:** phân giải một lần trong dialer → kiểm mọi địa chỉ bằng một hàm private chung (gốc là `tlsutil.Private`: có CGNAT, unspecified) → dial bằng IP. DNS lỗi hoặc không có địa chỉ hợp lệ thì **từ chối**, không có nhánh dial theo tên. Dùng cho `httpcrawl`, `replay.Sender`, AIA, kiểm live của `archive`.
- **Ngoại lệ:**
  - địa chỉ từ `-host-resolver-rules` (người dùng khai báo) là tin cậy;
  - target tự là nội bộ (`TargetPublic == false`, testbed) thì cho phép private.
- **Bẫy:**
  - `http.Transport` dùng `DialContext` để nối **tới proxy** (proxy `http://`), và `DialTLSContext` với địa chỉ proxy khi proxy là `https://` (Go 1.25 `transport.go:1757`). Miễn kiểm cho địa chỉ của proxy ở cả hai nhánh. AIA không được áp lên chứng chỉ của proxy (AIA đã tắt khi có proxy).
  - Giữ thứ tự IPv4 trước rồi thử lần lượt.
  - TLS phải nhận hostname gốc (SNI, kiểm chứng chỉ), không phải IP.
  - Testbed `*.jsh.test`: tra DNS lỗi → `TargetPublic=true`; nhờ ngoại lệ host rules mà gate không gãy. Cần unit test cho cả hai nhánh.
- **Gate:** unit test; `waf-check`, `pipeline-check`, `archive-check`, `verify-check`, `replay-check`.

### 3.2. Kiểm IP literal khi có proxy
- Khi có `-proxy`, `DialContext` chỉ thấy địa chỉ proxy; tên miền đích đi qua `CONNECT` để proxy tự phân giải. Chốt ở dialer không có tác dụng.
- **Luật:** kiểm ở tầng request (trước khi giao cho transport): từ chối khi target public mà host là
  - IP literal private (sau khi chuẩn hoá IPv4-mapped IPv6, `[::]`, `0.0.0.0`);
  - dạng số của IPv4 (`2130706433`, `0x7f.1`, `0177.0.0.1`, dạng rút gọn), chuẩn hoá theo cách đọc IPv4 của WHATWG; không chuẩn hoá được thì từ chối;
  - `localhost`, `*.localhost` (RFC 6761).
- Không tra DNS cục bộ (quyết định 6). Rủi ro còn lại: host trong scope có A record nội bộ, đi qua proxy (mục 10).

### 3.3. Một nguồn proxy cho mọi client
- **Lỗi:** `archive` dùng bản sao `http.DefaultTransport` → theo `HTTPS_PROXY` của env nhưng bỏ qua `-proxy`; `httpcrawl`/`replay` ngược lại.
- **Luật:** `-proxy`, mặc định lấy từ env; mọi client (gồm `archive`) theo cùng một giá trị. Khi đã chọn proxy thì in ra stderr (không in credential).
- **Bẫy:** Go không đưa `localhost` qua proxy nhưng **vẫn đưa `x.jsh.test`**: máy dev có `HTTPS_PROXY` sẽ gãy gate. Host có trong host rules thì không đi qua proxy. Có proxy thì AIA tắt: ghi lý do vào `run.json`.
- **Gate mới:** namespace chỉ có route tới một proxy ghi log; chạy `crawl`, `archive`, `verify` với `-proxy`; mọi kết nối đi thẳng sẽ lỗi và gate bắt được.

### 3.4. Chrome
- **Luật chung cho 3.1 và cả ba lớp dưới đây:** host khớp `-host-resolver-rules` mang IP mà luật trỏ tới. Trỏ về IP private thì host đó là **nội bộ được phép**: origin mốc của nó không bị coi là public (lớp 1 không chặn request của nó), và request tới nó không bị chặn hay báo ở lớp nào. Ca thật: Jellyfin/Directus local dưới tên `*.jsh.test` (P4.4, P5.6); DNS của `*.jsh.test` lỗi nên không được để rơi về nhánh "không biết thì coi là public".
- **WebRTC:** có `-proxy` thì thêm `--force-webrtc-ip-handling-policy=disable_non_proxied_udp`. Chrome **bỏ qua cờ lạ mà không báo**, nên phải có fixture gom ICE candidate: không có candidate `host`/`srflx`. Kiểm trên Chrome 156 và trong image Docker. (`--enforce-webrtc-ip-permission-check` chưa kiểm, không dùng nếu fixture không cần.)
- **Ba lớp chống trang public chạm IP private:**
  1. **Guard:** khi origin mốc là public, `FailRequest(BlockedByClient)` cho request tới IP literal private / `localhost` / `*.localhost` (cùng luật 3.2). Origin mốc: frame cấp cao nhất của tab; request của SW/shared worker (`FrameID` rỗng) lấy origin của worker. **Không có mốc thì coi là public** (đóng), không bỏ qua.
  2. **LNA của Chrome:** deny bằng `Browser.setPermission` cho cả `localNetworkAccess` và `localNetwork` (cdproto v0.159 có cả hai; test xem Chrome 156 dùng kiểu nào), không truyền origin. Ở `-attach` gọi `Browser.resetPermissions` khi dừng. Xác nhận bằng `loadingFailed` có `CorsErrorLocalNetworkAccessPermissionDenied` (cũng ghi vào `run.json`). Kiểm testbed (loopback → loopback) không gãy.
  3. **Cầu chì `remoteIPAddress`:** trang có origin public mà `responseReceived.remoteIPAddress` là private → ghi `private_address_hit` (host, IP, URL, cùng origin hay không) vào `run.json`, run không thoát 0. Áp cho cả session worker/SW. Mức phạt theo nguy cơ (review ngoài, vòng 5: một `<img>` của `dev-cdn` trỏ nhầm về `10.x` không được làm hỏng cả buổi crawl):
     - **JS đọc được response** → đóng tab, không thăm thêm trang của host đó. Gồm: cùng origin với frame/worker gửi request (mẫu DNS rebinding); response có `Access-Control-Allow-Origin` (`*` hoặc khớp origin trang); `ResourceType` là `Script` (script thực thi trong trang, kể cả JSONP) hoặc script của worker (Carbon, vòng 6);
     - **còn lại** (`<img>`, CSS, font, media khác origin, không CORS) → đưa host đó vào danh sách guard chặn (`FailRequest`) cho phần còn lại của run, tiếp tục crawl.
     - **Có proxy thì tắt lớp này:** `remoteIPAddress` là địa chỉ proxy (Burp ở `127.0.0.1`).
     - Host trong `-host-resolver-rules` được miễn.
     - Cắt `[]` của IPv6 trước khi parse. Bỏ qua khi rỗng, `fromDiskCache`, `fromPrefetchCache`, `fromServiceWorker` (request mà SW tự gửi ra mạng thì vẫn kiểm trên session của SW).
     - Đây là cầu chì, không phải chốt chặn: response nhỏ có thể đã được JS đọc.
- **Gate:** fixture có origin public giả lập (gate local mặc định là `TargetPublic=false` nên không kiểm được nhánh này); `attach-guard`, `waf-check`, `docker-check`.

## 4. 28B: đo trước khi làm (không đổi hành vi)

Mỗi cấu hình chạy 3 lần, báo trung vị. Image ghim theo digest.

- **(b) làm trước — refresh token:** fixture có access token TTL ngắn, refresh token xoay vòng một lần, hai kiểu: OAuth (`grant_type=refresh_token`, form/JSON/query) và BFF (cookie HttpOnly, `POST /api/auth/refresh` body rỗng). Đo:
  - guard có giết refresh của app không (dự kiến có: `rules.go` trả `Fake` cho request ghi);
  - `-urls -tabs 3 -role` (mỗi URL một context với bản chép cookie: `batch.go`) và `crawl -depth 2 -tabs 3 -role` có làm server thu hồi phiên không.
  Fixture này thành gate ở 28C.
- **(a) guard trả `200 {}` / `422 JSON` / `403 JSON`** (403 có `X-Jsharvest-Guard` để keeper bỏ qua) trên `explore-app`, `flows-app`, Crawlground, Jellyfin, Directus. Đo: coverage, route rác (`/x/undefined`), số form bị kẹt trong overlay, số lần app tự đăng xuất (interceptor 401/403), số request refresh và request đọc qua POST bị chặn.
- **(c)** phân loại endpoint còn thiếu trên 5 tập dev OpenAPI (Keycloak, Appwrite, Medusa, Directus, Jellyfin) theo nguyên nhân (module của webpack/Rspack, `__awaiter`, sink chung, không có trong code…), cộng tỉ lệ loại bundler trên `output/_live_25e_max` (5 tập dev ít webpack).
- **(e) gán nhân quả:** fixture `setTimeout` gọi lặp lại chính nó và scheduler kiểu RxJS trong `flows-app`. Nếu gán nhầm thì sửa bằng cách phát hiện timer tự hẹn lại chính callback của nó (cùng cơ chế nhịp thứ hai của `setInterval`), **không** dùng TTL theo giờ thực (cắt nhầm upload/export dài).
- ~~(d) challenge~~: bỏ ở đợt này.

### 4.1. Số liệu 28B (2026-11-15, trung vị 3 lần; chi tiết ở `docs/plan-28-exec.md` mục 4)

**(b) refresh token** — `testbed/refresh-measure.sh`, `refresh-app`, `RT_TTL=8s`, role `user`:

| Cấu hình | guard | refresh thử | refresh ok | bị giả `200 {}` | bị giữ | thu hồi (reuse) | data ok | data 401 | `session_lost` |
|---|---|---|---|---|---|---|---|---|---|
| A OAuth form / JSON / query, `-depth 2` | on | 21 | **0** | 21 | 21 | 0 | 4 | 24 | 0 |
| C BFF, `-depth 2` | on | 22 | **0** | 21 | 21 | 0 | 4 | 24 | 0 |
| D OAuth/BFF, `-urls 6 -tabs 3` | on | 8 | 0 | 6 | 8 | 0 | 9 | 8 | 0 |
| E OAuth/BFF, `-depth 2 -tabs 3` | on | 15 | 0 | 15 | 15 | 0 | 4 | 19 | 0 |
| F OAuth/BFF, `-depth 2` (đối chứng) | off | 7 | 7 | 0 | 0 | 0 | 28 | 7 | 0 |
| G OAuth/BFF, `-urls 6 -tabs 3` | off | 17–22 | 1 | 0 | 0 | **1 (họ phiên bị thu hồi)** | 9–10 | 18–23 | 0 |
| H OAuth/BFF, `-depth 2 -tabs 3` | off | 5 | 5 | 0 | 0 | 0 | 20 | 6–7 | 0 |

- Guard giết **100 %** refresh của app (mọi biến thể OAuth và BFF): sau TTL đầu, app chỉ còn nhận 401.
- `-urls -tabs N -role` (mỗi URL một context với bản chép cookie) **làm server thu hồi phiên** khi refresh được phép (G: refresh token cũ bị dùng lại → `REVOKED reason=reuse`); `-depth 2 -tabs 3` (chung context) thì không (H).
- Phát hiện thêm: `session_lost` luôn 0 dù app đã mất phiên (24 lần 401 trên XHR): keeper chỉ xét document chính, không thấy phiên chết ở tầng API.

**(e) gán nhân quả** — `testbed/timers-measure.sh`, `flows-app/timers.html` (đúng / tổng request):

| Ca | đúng | gán vào action sai | rơi vào background sai |
|---|---|---|---|
| poll tự hẹn lại (n=0 thuộc action, sau là nền) | 23/24 | 0 | 1 (n=0) |
| retry 503×2 (cả 3 thuộc action) | 0/3 | 0 | 3 |
| export poll tới khi xong (cả 10 thuộc action) | 2/10 | 0 | 8 |
| scheduler kiểu RxJS | 16/17 | 0 | 1 (search) |
| `setInterval` thật | 5/6 | 0 | 1 (nhịp đầu) |

- **Không có request nào bị gán nhầm sang action khác.** Mọi sai lệch theo một chiều: chuỗi do timer gây ra được gom vào flow `background started by button "…"` (vẫn trỏ đúng action gây ra), kể cả request đầu tiên sau `setTimeout` và chuỗi retry/export là hệ quả của action. Lỗi mà sửa ở 28C nhắm tới (gán nhầm vào action) không xuất hiện.

**(a) mã trả về khi guard giữ** — `testbed/guardreply-measure.sh` (`JSHARVEST_GUARD_REPLY`), guard on:

| App | `200 {}` | `422` | `403` |
|---|---|---|---|
| explore-app (điểm explore, trang, form kẹt) | 56, 10, 1 | 56, 10, 1 | 56, 10, 1 |
| flows-app (điểm, trang, route rác) | 18, 1, 1 | 18, 1, 1 | 18, 1, 1 |
| Crawlground (/59, trang) | 56, 132 | 56, 132 | 56, 132 |
| Jellyfin (endpoint thấy, trang) | 38, 40 | 38, 40 | 38, 40 |
| Directus (endpoint thấy, trang, refresh bị giữ) | **22**, 42, 56 | **4**, 42, 7 | **4**, 42, 7 |

- Bốn app không khác nhau giữa ba mã. Directus: với `422`/`403` refresh (`POST /auth/refresh {"mode":"session"}`, kiểu BFF) thất bại → app tự đăng xuất sớm → coverage 22 → 4; với `200 {}` app tiếp tục (và thử refresh 56 lần). Không có app nào hưởng lợi từ 422/403; không thấy route rác (`undefined`, `null`…) tăng ở `200 {}`.

**(c) endpoint bị sót trên 5 tập dev OpenAPI** (P7.1a, S, 228 operation bị sót ở v35; O kiểm mẫu trên bundle):

| Nguyên nhân | Jellyfin | Directus | Appwrite | Keycloak | Medusa | Tổng |
|---|---|---|---|---|---|---|
| không có trong bundle (server-only, deprecated, client khác) | 18 | 11 | 11 | 71 | 29 | **140** |
| sink chung qua hàm bọc import (`getEndpoint(collection)`, collection là dữ liệu runtime) | 0 | 29 | 0 | 0 | 0 | 29 |
| `apiClient.getUrl("Rel/Path")` + `ajax({type})`/`getJSON` (thư viện jellyfin-apiclient) | 28 | 0 | 0 | 0 | 0 | 28 |
| template khác giá trị cụ thể của GT (`/auth/${actor}/${method}`…) | 9 | 2 | 0 | 2 | 9 | 22 |
| chỉ thấy chuỗi, không method | 6 | 1 | 0 | 0 | 0 | 7 |
| base/tiền tố sai; lọc đuôi `.css` | 0 | 0 | 0 | 1 | 0 | 1+1 |
| **tách module webpack/Rspack** | 0 | 0 | 0 | 0 | 0 | **0** |
| **`__awaiter`/`_asyncToGenerator`** | 0 | 0 | 0 | 0 | 0 | **0** |

Bundler: Jellyfin webpack 5; Directus Vite; Keycloak Vite (thư viện, không minify); Medusa esbuild/tsup; Appwrite SDK TypeScript (cjs/esm/iife). Hai cơ chế dự kiến cho Bước 30 **không thu hồi operation nào** trên tập dev; phần thu hồi được (khoảng 65–88) chia ba hướng nhỏ. Bảng đầy đủ do O giữ (không commit, dữ liệu suy từ gói của bên thứ ba): chọn cơ chế ở **P7.2 (chờ người dùng)**.

### 4.2. P4.D: đề xuất cho 28C (chờ người dùng duyệt)

1. **Mã trả về khi guard giữ: giữ `200 {}`.** Không làm phần "đóng overlay khi 422". Công tắc `JSHARVEST_GUARD_REPLY` giữ làm công cụ đo.
2. **Ngoại lệ refresh: làm**, đúng như mục 5: grant `refresh_token` (form/JSON/query, kể cả tại `token_endpoint` của OIDC), sau `Deny`/`Destructive`/DELETE trá hình; `revocation_endpoint` luôn chặn; không theo chuỗi `refresh`/`token`. BFF (Directus, `refresh-app` BFF) qua `-guard-allow` neo origin+path, lưu vào `jsharvest-session.json` lúc `login`. Fixture P4.1 thành gate trong `session-check`.
3. **`-urls -role`: làm theo mô hình C4** (một context và một keeper cho mỗi host+role). Số liệu G/H cho thấy bản chép cookie theo từng context làm server thu hồi phiên.
4. **Gán nhân quả timer: không sửa ở 28C** (không có gán nhầm). Tuỳ chọn để sau: gom chuỗi timer có điểm dừng (retry, export) vào action thay vì "background started by".
5. **Mới, đề xuất thêm vào 28C:** keeper nhận ra phiên chết ở tầng API (chuỗi 401/403 trên XHR/fetch của cùng origin sau khi đã có 2xx, không có header guard) → `session_lost`/re-login như với document. Không làm nếu người dùng muốn giữ phạm vi 28C như đặc tả.

### 4.3. Quyết định P4.D của người dùng (2026-11-15)

Duyệt mục 1, 2, 3, 4 và **thêm mục 5 vào P4.5**, với ba ràng buộc bắt buộc:

1. **Đồng bộ lại token xoay vòng:** khi phiên đang sống và trình duyệt đã xoay vòng cookie/localStorage/sessionStorage (ví dụ sau refresh), cập nhật vào `keeper.login.Snapshot` và lưu lại `jsharvest-session.json` cuối phiên crawl (**chỉ ghi khi phiên không bị lost**), để `keeper.recover()` không nạp lại refresh token cũ (gây reuse → thu hồi) và để `authz -peers` (P5) đọc được token mới còn sống.
2. **`-guard-allow` trong `login`/session:** kiểm **fail-closed** (từ chối lưu, báo lỗi; không chỉ cảnh báo) nếu regex không neo `^https?://<host trong scope>/`; **Deny trước Allow** trong `Rules.Classify`; `crawl` có thêm `-guard-allow` thì **hợp (OR)** với rule trong session. Ngoại lệ `grant_type=refresh_token` chỉ áp cho **POST**, sau toàn bộ các nhánh Deny/Destructive/DELETE trá hình.
3. **Mục 5 (keeper tầng API):** chỉ xét **401** (không xét 403 trên XHR: tránh dương tính giả do RBAC ở role thấp), trên request **cùng origin không mang header guard**; reset bộ đếm về 0 ngay khi có bất kỳ response 2xx cùng origin; chạm ngưỡng chuỗi 401 thì **chờ một nhịp ngắn** cho SPA tự refresh, rồi xác nhận lại qua `CheckURL`/`goneOnServer`, vẫn thất bại mới gọi `keeper.recover()`.

Sau P4.5: P6.5 (flock), rồi P5.1 → P5.6 kèm P6.2b; dừng ở P5.T (hoặc P7.2 nếu chưa có tài khoản target thật).

### 4.4. Quyết định của người dùng sau P5/P7.1 (2026-11-16)

1. **P5.T:** chưa có hai tài khoản trên target thật → **đóng P5 tại đây**; chạy thực chiến khi có tài khoản được cấp phép. **Không** thêm `user`/`user_created` vào khoá chủ sở hữu của Q2 (`gd7` mục 8): trên tài nguyên cộng tác cùng tổ chức, chúng dễ cho bypass giả; giữ kết luận `shared`.
2. **P7.2 (Bước 30):** jsapi v36 đã phủ khoảng 96,2 % endpoint có mặt trong bundle trên 5 tập dev, và hai cơ chế tổng quát dự kiến thu hồi 0/228 (mục 4.1 (c)) → **bỏ Bước 30** (không làm P7.3–P7.5), chuyển thẳng sang P8.
3. **Trong P8**, trước `DOCKER=1 testbed/regress.sh -j 3` và chốt lịch sử: `refreshGrant` (guard) không cho lọt request có body GraphQL (ví dụ `POST /graphql?grant_type=refresh_token` mang mutation); `testbed/lab/setup.sh` tự tạo `user3` và trường `user_created` của `notes` trên Directus; mục hiệu năng (đặc tả 9) chỉ làm khi có số đo chứng minh cần.

## 5. 28C: chỉ làm những gì 28B chứng minh

- **Ngoại lệ refresh của guard:** chỉ cho qua grant `refresh_token` (body form, body JSON hoặc query), kể cả khi request tới `token_endpoint` của OIDC discovery (`jsapi.ExtractOIDC`). `token_endpoint` còn phục vụ grant login (`authorization_code`, `password`): chỉ grant refresh được qua. `revocation_endpoint` luôn chặn. **Không** cho qua theo chuỗi `refresh`/`token` trong path (`/api-tokens/refresh` xoay secret thật).
  - **Vị trí trong `Rules.Classify`:** sau `Deny`, `Destructive(req.URL)` và kiểm DELETE trá hình; trước nhánh chặn request ghi. Không đặt ở đầu hàm như `Allow`, nếu không `/revoke?grant_type=refresh_token` sẽ lọt.
  - Refresh kiểu BFF (body rỗng): người dùng khai báo qua `-guard-allow`, lưu vào `jsharvest-session.json` lúc `login` để `crawl -role` tự dùng. `Allow` khớp **cả URL** và cho qua cả request phá huỷ (kiểm trước mọi luật), nên regex phải neo cả origin lẫn path (`^https://app\.x\.com/api/auth/refresh(\?|$)`), không chỉ path. Ghi cảnh báo nếu regex không neo `^` với scheme+host.
- **Mã trả về khi guard giữ request:** theo số liệu (a). Nếu chọn 422 thì explore phải đóng overlay: sau khi submit bị guard giữ, bấm Escape (hộp thoại JS đã có handler), đếm vào thống kê.
- **`-urls -role`:** dùng mô hình C4 (một context và một keeper cho mỗi host+role; tab 2..N không gắn SW). Trộn URL của nhiều org trong một lần chạy là giới hạn đã biết. "Chép cookie mới nhất khi mở tab" không giải được race (tab đang chạy vẫn giữ token cũ).

## 6. Bước 29: BOLA ngang (`authz -peers userA,userB`)

Viết design doc riêng (`docs/gd7-bola-design.md`) theo khung `gd5-replay` mục 8, kèm đánh giá độc lập. Các luật đã chốt:

- **Nguồn:** đọc thẳng `export.Load`/flows của hai peer (không qua `diff.json`, nơi hai role cùng gọi được thì thành `Same` và bị loại). Thử cả hai chiều.
- **Người dùng khai báo quan hệ:** `same-org` hay `cross-org`. Cùng tổ chức có thể được xem của nhau theo thiết kế; kết luận phụ thuộc khai báo.
- **Ứng viên:** request mang ít nhất một giá trị định danh của A **không xuất hiện ở bất kỳ** response nào của B hay anon (phép hợp, ANY). Tham số entropy cao (JWT, chữ ký HMAC, `X-Amz-Signature`) không phải ID. Giải Relay global ID (base64 `Type:id`).
- **Phép thử chính:** giữ nguyên request của A (path, query, body, header tenant), chỉ đổi danh tính sang B (cách `authz` đang làm). Thay từng tham số là phần thêm.
- **Đối chứng tam giác:** Trial(B, id_A) so với Control(A, id_A) (gửi live, hai lần để biết trường thay đổi theo lần gọi) và Self(B, id_B).
  - Trial giống Self(B) (server bỏ qua id_A, trả dữ liệu của B) → `enforced`.
  - **Bypass chỉ khi Trial chứa giá trị riêng của A:** tập giá trị riêng lấy từ Control(A), **trừ** `id_A` và mọi giá trị đã gửi trong request (chống phản chiếu), trừ giá trị xuất hiện ở bất kỳ response nào của B/anon, trừ trường thay đổi giữa hai lần đối chứng. Giá trị ngắn (số dư, cấp bậc) được khớp theo **tổ hợp nhiều cặp (json_path, value)**, mỗi cặp phải khác giá trị tương ứng ở Self(B) hoặc Bogus.
- **Thiếu Self(B):** dùng Bogus(B, id_giả).
  - **Không** dùng `id_A ± k` (ID tuần tự trúng dữ liệu người thứ ba).
  - UUID: sinh ngẫu nhiên cùng phiên bản. Số nguyên: dương hợp lệ, cùng kiểu (ID nhỏ thì vùng gần trần int32; ID int64 kiểu snowflake thì cùng số chữ số). Tránh 0, âm, tràn kiểu (bị validator chặn trước tầng phân quyền).
  - Bogus trả 200 kèm dữ liệu → `unclear`, dừng thử endpoint đó, ghi lại.
- **Anon:** probe `NoIdentity` vẫn chạy; signed/capability URL → `unauthenticated` (có test riêng).
- **`replay_broken`:** Control(A) live thất bại trong khi lúc ghi nhận trả 2xx → báo rõ (request signing, nonce, session gắn TLS), không kết luận.
- **An toàn:** giữ `replay.Policy` (mặc định chỉ đọc). Danh sách động từ **riêng của replay** thêm `verify`, `magic`, `regenerate`, `refresh` (không thêm vào guard: chặn nhầm request đọc).
- **Fixture `peer-app`:** `same-org` và `cross-org`; các ca: `/me`, tài nguyên dùng chung, server bỏ qua `userId`, response phản chiếu ID, B trống dữ liệu, khoá phân cấp (`orgs/{o}/projects/{p}`), signed URL, GraphQL theo lô, `code` số. Thử thêm với 2 tài khoản local trên Directus/Jellyfin.

## 7. Bước 30: jsapi tổng quát [ĐÃ HUỶ THEO MỤC 4.4]

- Một cơ chế đứng đầu bảng 28B(c) (dự kiến tách module webpack/Rspack). Sửa nhỏ mang tính tổng quát đi kèm: bóc `__awaiter`/`_asyncToGenerator`.
- **`node_modules` trong sourcemap giữ nguyên bị chặn.** Code của SDK đã có trong bundle được phân tích; chỉ mở lại nếu 28B(c) cho thấy endpoint thiếu *chỉ vì* không đọc được bản minify, và khi đó chỉ gói được code first-party import trực tiếp, cộng denylist SDK công khai.
- Gate: snapshot dev không giảm; `perfgate`; một lần kiểm mù (quyết định 5).

## 8. Song song

- Rút gọn CLAUDE.md: lịch sử các đợt sang `docs/rounds-history.md`; CLAUDE.md giữ bất biến, bảng gate, bẫy CDP và con trỏ tới docs.
- `export -format openapi`, kiểm schema trong `exportcheck`.
- Tool MCP chỉ đọc: `get_intel`, `get_diff`, `get_authz`, `search_scripts`, `read_script` (`flows-check MCP=1`).
  - `read_script` chỉ nhận sha256 có trong `index.jsonl`; không bao giờ ghép đường dẫn từ tên trong sourcemap (có thể chứa `../`).
  - Phân trang theo **byte** (bundle minify 2–5 MB thường chỉ một dòng), không theo dòng. Áp envelope `untrusted` và luật che secret khi không có `-reveal`.
- Khoá liên tiến trình (`flock`) trên `<out>/<host>/<role>`: hai lệnh ghi cùng thư mục (ví dụ `watch` và `crawl`) có thể làm mất cập nhật `index.jsonl` (`flushLocked` ghi đè cả file), và `recoverOrphans` (`internal/store/store.go`) có thể xoá `.tmp-*` của tiến trình kia. Cần test hai tiến trình trước khi sửa; lệnh thứ hai chờ hoặc báo lỗi rõ.
  - **Chỉ giữa các lệnh ghi** (`crawl`, `watch`, `login`, `archive`, `endpoints` khi phân tích lại). Lệnh chỉ đọc (`mcp`, `diff`, `export`) **không** lấy khoá: luồng chính là `watch` ghi liên tục trong khi MCP đọc nối đuôi cùng thư mục.

## 9. Hiệu năng [ĐÃ ĐÓNG Ở P8.1 — KHÔNG SỬA CODE]

- `w.redact.Entry` ra ngoài khoá (`internal/traffic/traffic.go`).
- `linkDeferred` gom theo script đích để thả `*jsapi.Module` sớm.
- `httpcrawl` dùng lại cache `static/<sha>.json` thay vì `jsapi.Extract` lần nữa.
- `archive`: `fetch` tải tuần tự (`internal/archive/fetch.go`); `cur.files()` nạp mọi `.js` của mọi role vào RAM (`internal/archive/history.go`).
- CDP: guard tạm dừng cả font/stylesheet/media (`Fetch.enable` với `*`). Nếu thu hẹp theo `ResourceType`, `<img src="http://127.0.0.1/…">` sẽ không qua lớp 1 của 3.4 mà rơi xuống LNA: giữ pattern cho các dải local, hoặc cập nhật test của lớp 1 tương ứng; explore gõ từng ký tự (thay bằng `Input.insertText`, giữ phím thật cho Enter/Tab/Escape) và gọi `getEventListeners(-1)` toàn trang sau mỗi thao tác; `-tabs N` chờ theo tầng (`engine/frontier.go`); `runState.summary` giữ mọi request trong RAM.

## 10. Giới hạn đã biết (ghi vào docs người dùng khi làm xong mục tương ứng)

- Có `-proxy`: chỉ kiểm IP literal cộng scope. Host trong scope có A record nội bộ thì proxy sẽ nối tới; cầu chì `remoteIPAddress` tắt.
- Gắn IP trong Go không chặn được rebinding phía Chrome (resolver `pageFetch`, trang); lớp chặn ở đó là LNA, cầu chì là `remoteIPAddress`.
- `-attach`: guard chỉ bảo vệ trong lúc `watch` chạy.
- `-urls -role` trộn URL của nhiều org: storage dùng chung.
- `NO_PROXY` không được đọc (P2.3/P2.R); loopback không bao giờ đi qua proxy (như `<-loopback>` của Chrome).
- Chrome 156 bỏ qua `--force-webrtc-ip-handling-policy`: chính sách WebRTC đặt bằng preference của profile (P3.5). Ở `-attach`, người dùng tự đặt (preference hoặc policy `WebRtcIPHandlingPolicy`).
- WebSocket mở từ worker (hoặc trang khi `-guard-allow-websocket`) không qua `Fetch`: lớp 1 và 3 không thấy; lớp 2 (LNA) vẫn áp.
- `-guard off`: lớp 1 không chạy (lớp 2, 3 vẫn chạy).
- Lớp 3 không có gate dựng được ca thật (cách map tên duy nhất cho Chrome là host rules, vốn được miễn): chỉ có unit test.
- Chrome 156 tự chặn request từ trang **http** public tới mạng local (`InsecureLocalNetwork`), kể cả host được người dùng map bằng host rules.

## 11. Để sau (chỉ khi có bằng chứng)

uTLS và fingerprint HTTP/2 (bằng chứng: verdict `Blocked`/`hosts_blocked` trên target thật), chế độ tách riêng cho challenge (28B(d)), SQLite/bbolt, thay parser, MCP chủ động, parser `gql`, Server Action, tRPC.

Ghi lại để không trôi (từ báo cáo đánh giá ban đầu, chưa có bằng chứng cần làm ngay):
- Quét secret theo tiền tố + entropy trên mọi literal (hiện chỉ theo tên khoá trong object literal, `internal/jsapi/defs.go`). Cân nhắc xuất cho trufflehog thay vì tự viết.
- `authz`/`replay` tự làm mới Bearer JWT hết hạn (hiện chỉ gỡ, `internal/replay/identity.go`).
- Tách `internal/engine` (bỏ các `&engine{}` giả trong `engine/http.go` khi gọi `writeEndpoints`; chia `Config` theo khối) và `extractor` của `jsapi`.
- `jsapi/locate.go`: thay con trỏ `x.cursor` bằng bảng offset token lấy từ lexer (đã gây lệch dòng ở 27D/27E).

## 12. Tiến độ

Chuyển sang `docs/plan-28-exec.md` mục 4. Mốc `regress.sh -j 3` tại `f6f0cd4`: xanh (2026-11-15, 918 s); lần đầu `bench` fail ở `reqcheck` của angular-ngsw (thiếu `GET /ngsw.json?ngsw-cache-bust=…`, request của service worker, giới hạn đã biết), chạy lại riêng thì qua.
