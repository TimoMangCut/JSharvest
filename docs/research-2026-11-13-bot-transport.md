# Nghiên cứu: lớp gửi request "như người dùng thật" trước bot management (2026-11-13)

Tài liệu này trả lời câu hỏi: vì sao jsharvest bị chặn hoặc chạy kém hiệu quả trên các target có Cloudflare đứng trước, và nên dựng lại lớp gửi request thế nào. Nó dùng ba nguồn: dữ liệu của các lần chạy thật (chỉ đọc lại output, không gửi request mới), kiểm toán code hiện tại, và nghiên cứu bên ngoài (có dẫn nguồn ở cuối).

Ký hiệu nguồn: **[P]** là nguồn gốc (tài liệu của nhà cung cấp, spec, mã nguồn hoặc README); **[V]** là blog của nhà cung cấp; **[C]** là cộng đồng hoặc dịch vụ scraping. Chỗ nào là suy luận thì ghi rõ "suy luận".

## 0. Nguyên tắc (người dùng chốt ngày 2026-11-13)

1. Bị bot management chặn không có nghĩa là mình làm sai, vì Cloudflare chặn bot chứ không chặn người.
2. **Không khai mình là bot**, không dựa vào việc xin whitelist hay khai báo. Tool tự động hoá đúng những gì một người dùng trình duyệt thật làm.
3. **Không chuyển mọi request sang Chrome**, vì quá nặng. Trình duyệt chỉ được dùng khi thật sự cần.

## 1. Bằng chứng thực nghiệm (output đã có trên đĩa)

### 1.1. Mã 1006 ở đây chặn theo client, không theo IP
- Trong 25E-max (2026-11-12, từ 15:28 đến 15:40 UTC), client Go của `verify` nhận `403 text/plain` với nội dung `error code: 1006`:
  - `api.target-c.example`, `target-c.example`, `go.target-c.example`, `developer.target-c.example`: 566/566 request;
  - `api.target-b.example`: 18/18 request.
- **Chrome trên cùng IP, cùng host, chỉ sớm hơn vài giây, vẫn được trả lời bình thường:**
  - `api.target-b.example`: lúc 15:40:39 Chrome nhận 200 (5), 304 (5), 404 (7) và 422 (1); lúc 15:40:41 Go nhận 1006 cho cả 18 request.
  - `api.target-c.example`: lúc 15:27:53 Chrome nhận 200, 301 và 401; lúc 15:28:07 Go nhận 1006.
- Cloudflare mô tả 1006 là "IP bị cấm" [P]. Dữ liệu trên lại cho thấy luật này phụ thuộc vào client. Khả năng cao là một luật xét cookie `__cf_bm`/điểm bot/UA, đi kèm danh sách IP (suy luận).
- **Cách hiểu "1006 = cấm IP" mà 25H đã đưa vào code (`BlockClient`, rồi bỏ host) là sai với dữ liệu thực tế.**
- Riêng `admin-a` thì Chrome cũng nhận trang HTML 1006 (lúc 17:21–17:22). `admin-a` có thể là cấm IP thật. Các lần đó Chrome được mở mới, không có cookie từ trước.

### 1.2. Trước đó cùng client Go chưa bị chặn
- 25D (lúc 11:02 UTC): client Go không có UA (Go tự điền `Go-http-client/1.1`) nhận phản hồi bình thường từ `target-c` (301, 401, 404, 405).
- Giữa 11:04 và 15:28 phía target có thay đổi. Trong khoảng đó, `verify` đã gửi:
  - 300 request tới `admin-a` trong 150 giây (cách nhau 0,5 s đều đặn). App trả 400 cho 299 request: `"unauthorized_client"` (yêu cầu danh tính thiết bị).
  - 224 request tới `target-c`.
  - Tất cả đều mang UA `Go-http-client/1.1` và path canary `__jsharvest_canary_*`.
- Ba zone thuộc ba registrable domain khác nhau (`target-a.example`, `target-b.example`, `target-c.example`) cùng đổi hành vi trong một khoảng thời gian. **Suy luận (chưa chứng minh được):** có thể chúng dùng chung một tài khoản hoặc một danh sách IP, và phía target đã chặn đúng "chữ ký" mà tool tự khai ra.

### 1.3. Nhận diện bị thủng và thông tin thu về rất ít
- **Dạng text thuần `error code: 1006`** (Cloudflare trả dạng này khi `Accept` không phải HTML) không được `detect.Check` nhận ra, kể cả `ClassifyBlock` của 25H. Kiểm bằng unit test ngày 2026-11-13: kết quả trả về là `nil`. Hậu quả: 566 request bị gửi đi và 208 mục bị chấm sai thành `auth_wall_opaque`.
- **`growth.target-c.example`** trả trang "Attention Required! | Cloudflare" với nội dung "Sorry, you have been blocked" (một luật WAF chặn) cho cả Go lẫn Chrome, qua hai ngày. 25H xếp nhầm "attention required" vào `challenge`.
- **Lượng thông tin thu được trên số request đã gửi (`verify.json`):**

  | Run | Gửi | Mục có thông tin | Ghi chú |
  |---|---|---|---|
  | admin-a 25D | 300 | **0** | 12/12 canary nhận cùng một phản hồi 400 JSON (cổng kiểm tra thiết bị của app). 14 mục `verified_alive` là **dương tính giả**: cùng skeleton 400 với 273 mục `dead_or_fp`, nhưng prefix `/api-gateway/service` vượt `maxPrefixes` nên bị chấm theo canary `/` (200 HTML). Đã sửa trong 25I (canary cha). |
  | target-c 25E | 566 | 0 | mọi phản hồi đều là 1006 |
  | portal-b 25E | 18 | 0 | 1006 |
  | target-d 25E | 371 | 208 | target không có CDN |

  Ngay từ vài canary đầu đã thấy mọi path nhận cùng một phản hồi, nhưng `verify` vẫn gửi tiếp.

### 1.3b. Đối chứng bổ sung (review ngày 2026-11-13): yếu tố phân biệt nhiều khả năng là UA và HTTP/1.1, không phải TLS
- Lúc 17:17 UTC (khoảng 2 giờ sau khi `verify` bị 1006), engine HTTP với TLS và HTTP/2 của Go, UA `Chrome/141`, không có Sec-CH-UA, đã nhận **200** từ `api.target-c.example/api-json`, `/openapi.yaml`, `/v3/api-docs`… (`run.json`, mục `http.probes`).
- Khác biệt so với `Sender` lúc 15:28 là UA (`Go-http-client/1.1`) và HTTP/1.1. TLS giống nhau. Dữ liệu không loại được khả năng lệnh chặn đã hết hạn vào lúc 17:17.
- `admin-a` và `growth.target-c.example` thì chặn cả Chrome 156 thật, nên đổi TLS cũng không giúp được.
- **Hệ quả:** chưa có bằng chứng cần N2 (giả TLS/H2). N0 (bỏ `Go-http-client`) đã xử lý nguyên nhân quan sát được. Xem lại mục 6 và 8.

### 1.4. Leo thang không mang theo danh tính
- Engine HTTP xưng là `Chrome/141.0.0.0`, trong khi Chrome thật trên máy và trong image là 156. Khi leo thang, Chrome hiện bản 156: "người" đổi phiên bản giữa chừng.
- Cookie jar của engine HTTP (có `__cf_bm`) **không được chuyển** sang Chrome khi leo thang, cũng không sang `Sender`.

## 2. Bot management quyết định thế nào (tóm tắt nghiên cứu)

### 2.1. Cloudflare
- **Bốn engine** [P]:
  - **Heuristics** chạy trên mọi request, khớp "cơ sở dữ liệu fingerprint độc hại". Khớp với độ tin cậy cao thì điểm là 1.
  - **ML (Adaptive Intelligence)** đưa ra phần lớn kết luận. Đầu vào gồm header, đặc tính phiên và tín hiệu từ trình duyệt.
  - **Anomaly Detection** đã deprecated.
  - **JS Detections (JSD)** là tuỳ chọn.
- **Từ 9/2025, có thêm baseline ML riêng cho từng khách hàng** [P/V]. Mô hình học lộ trình người dùng thường đi trong site, chuỗi request, và việc client có tương tác với phần tử động hay không. Những gì bị gắn cờ: duyệt theo thứ tự ở tốc độ máy, đọc dưới 1 giây mỗi trang, quét API tuần tự kể cả với khối lượng thấp. Ngoài ra có khoảng 50 heuristic toàn cục dựa trên fingerprint HTTP/2 và ClientHello.
- **JA4 và JA4 Signals** (gói Enterprise): thống kê theo JA4 trong 1 giờ gần nhất, như `browser_ratio_1h`, `h2h3_ratio_1h`, `cache_ratio_1h`, `heuristic_ratio_1h`. Cloudflare nói thẳng fingerprint dễ bị giả, nên họ ghép với hành vi [P].
- **Fingerprint HTTP/2 kiểu Akamai** gồm SETTINGS, WINDOW_UPDATE, PRIORITY và thứ tự pseudo-header. Nó lộ ra implementation thật phía sau một UA giả [P].
- **Cookie:**
  - `__cf_bm` dùng để làm mượt điểm bot theo phiên; hết hạn sau 30 phút không hoạt động; `Partitioned` [P].
  - `cf_clearance` là bằng chứng đã qua challenge, và chứa kết quả JSD.
    - Gắn với "khách và thiết bị" đã nhận nó; Cloudflare không định nghĩa "thiết bị".
    - **Không có nguồn gốc nào nói nó gắn với dấu vân tay TLS.** Nguồn cộng đồng thì nói có [C].
    - Thời hạn passage mặc định 30 phút; kết quả JSD 15 phút.
    - Precursor có thể thu hồi sớm.
    - Đổi IP thì Managed Challenge mất hiệu lực [P].
- **JSD:** script ẩn được chèn vào **chỉ các phản hồi HTML**; bản thân nó không chặn ai. Site phải tự viết luật trên `cf.bot_management.js_detection.passed`. Client chưa từng chạy JSD thì `passed=false` [P].
- **Challenge:** Managed Challenge tự chọn kiểu non-interactive hay interactive dựa trên tín hiệu trình duyệt. Request XHR/fetch không giải được challenge. Header `cf-mitigated: challenge` là dấu hiệu đáng tin [P].
- **Mã lỗi** [P]:
  - 1006/1007/1008/1106: "IP bị cấm" (nhưng xem 1.1: thực tế có thể phụ thuộc client);
  - 1010: chặn theo chữ ký trình duyệt;
  - 1015: rate limit;
  - 1020: luật chặn.

### 2.2. Phát hiện Chrome tự động (2024–2026)
- `navigator.webdriver` bật khi có `--enable-automation`. Cờ `--disable-blink-features=AutomationControlled` giữ nó là false. Patchright còn bỏ hẳn `--enable-automation` [P/C].
- **Headless kiểu cũ đã bị gỡ từ Chrome 132.** `--headless` bây giờ là new headless, fingerprint gần như giống bản có giao diện. Vì vậy bên phát hiện chuyển sang soi các tác dụng phụ của CDP [P/V].
- **Rò rỉ qua `Runtime.enable`** (getter `stack` chạy khi DevTools serialize lỗi): V8 đã vá vào tháng 5/2025 [V]. Có một báo cáo cộng đồng về cách vượt khác [C]. Cloudflare và DataDome từng dùng kỹ thuật này [V].
- **Code chèn vào main world** bị lộ qua `Function.prototype.toString`, qua tên `sourceURL` trong stack, và qua global/symbol. Kết luận chung: **không vá main world** [P/C].
- **Đổi UA qua CDP:** thiếu `userAgentMetadata` thì mất `Sec-CH-UA`/`userAgentData`. Service worker không nhận `Emulation`, phải gửi `Network.setUserAgentOverride` trên session của worker [P].
- **Input qua CDP có `isTrusted: true`** [C]. Việc phát hiện dựa vào đường di chuột và nhịp thao tác (suy luận từ [V]).
- Một benchmark cộng đồng (một IP, một đêm, 5/2026): **Chrome hệ thống có giao diện, điều khiển qua CDP thô**, cho kết quả tốt nhất trước 31 target Cloudflare. Dùng Chrome thật quan trọng hơn các bản vá. curl_cffi ngang một trình duyệt đã vá (26/31) nhưng trượt mọi thứ cần JS [C].

### 2.3. Kiến trúc của các công cụ khác
- **Burp (browser-powered scanning) và ZAP (AJAX spider):** trình duyệt điều hướng, nhưng **request đi ra bằng network stack của chính scanner** [P]. Hai công cụ này không phải tiền lệ cho kiến trúc "trình duyệt làm lớp gửi". (Lượt trước tôi đã nói sai điều này.)
- **Crawlee:**
  - SessionPool: một phiên gồm cookie, IP và fingerprint; bị chặn thì `retire` cả phiên.
  - fingerprint-suite: sinh bộ header nhất quán.
  - AdaptivePlaywrightCrawler: chọn HTTP hay trình duyệt cho từng request, và kiểm lại trên một mẫu [P].
- **Playwright `APIRequestContext`:** dùng chung cookie với browser context nhưng **gửi bằng HTTP của Node**, không phải bằng Chrome [P].
- **FlareSolverr:** trình duyệt giải challenge rồi trả cookie và UA. Bên dùng **bắt buộc** phải dùng lại đúng UA đó, nếu không sẽ bị challenge lại [P]. Vòng lặp challenge thường do đổi IP hoặc lệch TLS [C].
- **Bên trong Chrome (CDP):**
  - `Fetch.continueRequest` ghi đè được URL, method, header và body, **trừ Cookie**, và không áp lại khi bị redirect [P].
  - `fetch()` trong trang bị giới hạn bởi CORS và các header cấm.
  - `Network.loadNetworkResource` là experimental, chỉ có GET.
- **Client nhẹ mô phỏng trình duyệt (Go):**
  - **uTLS** [P]:
    - `HelloChrome_Auto` hiện là 155, mới chỉ có trên master (commit 2026-10-06); bản tag mới nhất là v1.8.2.
    - Preset có xáo trộn extension, ECH GREASE và X25519MLKEM768.
    - **Có độ trễ**: Auto đứng ở 133 suốt khoảng 17 tháng.
    - README cảnh báo có thể đang tồn tại điểm phân biệt được.
    - Chỉ lo TLS, không lo HTTP/2.
  - **bogdanfinn/fhttp** thêm thứ tự header, thứ tự pseudo-header và SETTINGS HTTP/2 giống Chrome. **bogdanfinn/tls-client** = uTLS + fhttp, profile tới `chrome_154`, bản phát hành gần nhất 2026-11-11 [P].
  - **curl_cffi (fork lexiforest)** có profile Chrome 151/152 và cập nhật fingerprint không cần phát hành bản mới [P].
- **JA3 và JA4:** Chrome xáo trộn extension từ bản 110, nên JA3 gần như khác nhau ở mỗi kết nối. JA4 sắp xếp lại trước khi băm, nên ổn định [P].
- **Công cụ scan thích nghi theo phản hồi:**
  - feroxbuster: `auto-tune`/`auto-bail` khi lỗi vượt ngưỡng, ≥90% phản hồi là 403, hoặc có 429;
  - ffuf: `-ac` (tự hiệu chỉnh), `-sf` (dừng khi >95% là 403), `-p` (độ trễ ngẫu nhiên);
  - nuclei: `-mhe 30` (bỏ host sau 30 lỗi);
  - sqlmap: `--safe-url`/`--safe-freq`.

## 3. Kiểm toán jsharvest: mỗi thành phần đang lộ gì
Chi tiết kèm vị trí trong code nằm trong báo cáo kiểm toán; dưới đây là phần quan trọng. Các điểm then chốt đã được kiểm lại trực tiếp: `client.go:22`, `crawl.go:449`, `actions.go:42/124`, `archive/client.go:69`, và chromedp `allocate.go:115`.

| Thành phần | Stack | UA | Cookie | TLS/H2 | Tự khai báo |
|---|---|---|---|---|---|
| Engine HTTP (`httpcrawl`) | Go net/http, ép HTTP/2 | cứng `Chrome/141` (máy dùng 156), **không có Sec-CH-UA** | jar riêng cho mỗi lần crawl, không chia sẻ | TLS của Go; SETTINGS H2 của Go; thứ tự header ngẫu nhiên (duyệt map); `Accept-Encoding: gzip` | `GET /jsharvest-<hex>-no-such-page` trên mỗi origin mới; khoảng 18 request thăm dò (robots, sitemap, manifest, 7 đường dẫn spec, sw.js) ngay sau trang đầu |
| Leo thang sang Chrome | Chrome 156 | UA của Chrome (156) ≠ 141 | không mang theo jar | Chrome | như dòng Chrome bên dưới |
| Chrome (crawl/explore/watch) | new headless, `--remote-debugging-pipe`, **`--enable-automation`** + `AutomationControlled` | override qua CDP, có metadata | theo profile hoặc phiên đã lưu | Chrome | (explore/watch) tagger trong **main world**: `Symbol.for("jsharvest.tagger")`, `sourceURL=jsharvest-tagger`, vá `setTimeout`/`addEventListener`/`on*`; guard thay `WebSocket` và ghi `console.debug("jsharvest guard: …")`; file upload tên `jsharvest.txt` |
| Resolver | `fetch` trong isolated world | của Chrome | cùng origin | Chrome | `sourceURL` chỉ nằm trong isolated world |
| `Sender` (`verify`/`authz`/`replay`) | Go net/http, **HTTP/1.1** (ALPN chỉ http/1.1), header được sắp xếp theo alphabet | `verify`: **`Go-http-client/1.1`**; `authz`/`replay`: UA đã ghi lại | chỉ cookie của danh tính | TLS của Go | `__jsharvest_canary_*`, `jsharvest@example.com` |
| Kiểm live của `archive` | `Sender` | **`Mozilla/5.0 (jsharvest archive check)`** | không | Go | chuỗi UA |
| Nguồn archive (Wayback…) | Go | `jsharvest (archive; +github…)` | không | Go | gửi tới archive, không tới target |

Hành vi:
- Engine HTTP chạy 5 request/s với nhịp cố định, không dao động.
- `Sender` chạy 2 request/s, không dao động.
- Explore: click không có đường di chuột, gõ phím không có độ trễ giữa các phím, cuộn bằng `scrollTo` thay vì sự kiện wheel.

## 4. Chẩn đoán: vì sao bị chặn hoặc chạy kém hiệu quả

1. **Danh tính không nhất quán giữa các thành phần.** Cùng một run, cùng một IP, mà xuất hiện bốn "người" khác nhau:
   - Go xưng Chrome/141 nhưng không có Sec-CH-UA, TLS và H2 của Go;
   - Chrome 156;
   - `Go-http-client`;
   - một UA tự xưng là jsharvest.

   Cookie hạ tầng của CDN không được chuyển giữa các thành phần. Đây chính là thứ các heuristic và ML về sự nhất quán của header/TLS/H2 được thiết kế để bắt (2.1). Riêng chuyện "UA nói Chrome mà JA4 nói Go" là suy luận từ các tín hiệu đã được công bố.
2. **Tự khai báo:** `Go-http-client`, `__jsharvest_canary_`, `/jsharvest-…-no-such-page`, UA của archive, `jsharvest.tagger`. Theo 1.2, đây có thể là thứ phía target đã nhắm vào.
3. **Hành vi máy:** chuỗi canary và thăm dò tuần tự đều đặn (0,5 s), và hàng trăm 404/400 không mang thông tin. Đây đúng là loại tín hiệu mà baseline của Cloudflare gắn cờ (2.1).
4. **Thiếu "tự giới hạn khi phản hồi giống hệt nhau":** gặp cổng chặn đồng nhất mà vẫn gửi hết (1.3). Các công cụ khác đều có cơ chế này: ffuf `-ac`/`-sf`, feroxbuster `auto-bail`.
5. **Phân loại và phản ứng sai:** không nhận ra 1006 dạng text thuần; coi "Attention Required" là challenge; coi 1006 là cấm IP; request đối chứng của 25H lại gửi bằng chính client đang bị chặn.

## 5. Các phương án lớp gửi

| Tầng tín hiệu | (1) Go net/http (hiện tại) | (2) Client mô phỏng (uTLS + fhttp) mang phiên lấy từ Chrome | (3) Gửi qua Chrome |
|---|---|---|---|
| IP | như nhau | phải giữ đúng IP lúc giải challenge | như nhau |
| TLS (JA4) | Go, không bao giờ khớp UA Chrome | gần đúng; preset trễ 1–6 bản lớn, cần kiểm lại sau mỗi lần Chrome cập nhật | đúng tuyệt đối |
| HTTP/2 | của Go | SETTINGS và thứ tự giống Chrome; phần PRIORITY và hành vi stream chưa kiểm | đúng |
| Header | tự dựng, dễ lệch | chép mẫu header theo từng loại request từ chính Chrome của run | đúng |
| Cookie/phiên | tự quản lý | dùng được **nếu** IP, UA và (có lẽ) TLS khớp; phải làm mới theo JSD 15 phút / passage 30 phút | đúng |
| JS/JSD | không chạy, nên `passed=false` | như (1) giữa các lần làm mới | thật |
| Hành vi | lộ hoàn toàn | lộ ở phần HTTP, cần tự điều nhịp | điều hướng thì tự nhiên; probe `fetch` vẫn cần điều nhịp |
| Chi phí | thấp | thấp, cộng một lần mở Chrome mỗi host hoặc mỗi phiên | cao |

Trước khi chọn (2), **phải đo thực nghiệm** điều chưa có tài liệu: `cf_clearance`/`__cf_bm` lấy từ Chrome có còn hiệu lực khi client uTLS (preset cùng bản lớn với Chrome, cùng IP, cùng UA) dùng lại suốt hơn 30 phút hay không.

## 6. Kiến trúc đề xuất: "một người duy nhất" cho mỗi run, mặc định nhẹ, chỉ dùng Chrome khi cần

**N0. Bỏ mọi chỗ tự khai báo** (không có rủi ro, làm ngay):
- canary và đường dẫn kiểm tra SPA dùng tên trung tính, kiểu một slug ngẫu nhiên trông như route thật;
- bỏ UA tự xưng ở kiểm live của archive;
- không bao giờ để rơi về `Go-http-client`;
- email mẫu và tên file upload trung tính;
- `--enable-automation`: bỏ (giữ `AutomationControlled`);
- tagger trong main world: bỏ symbol và tên `sourceURL` dễ nhận ra; về lâu dài chuyển sang isolated world nếu được (cần thiết kế riêng, vì tagger cần bọc handler của trang);
- guard: không ghi `console.debug` với chữ jsharvest.

**N1. Một danh tính cho mỗi run** (`identity` dùng chung cho engine HTTP, Chrome và `Sender`):
- UA, Sec-CH-UA*, Accept-Language và **mẫu header theo từng loại request** (document, script, fetch) lấy từ chính Chrome của máy: mở Chrome một lần ngắn rồi cache theo phiên bản Chrome, hoặc lấy từ traffic đã ghi.
- Bỏ hằng `Chrome/141`.
- **Cookie hạ tầng của CDN** (`__cf_bm`, `cf_clearance`…) chỉ được chuyển **trong bộ nhớ của đúng phiên (target, role)**, ví dụ khi leo thang trong `-engine auto`. Không ghi jar bền ra đĩa, và không dùng chung giữa các role (sửa sau review: giữ cách ly giữa các role; các cookie này có thể nối danh tính anon, user và admin với nhau).
- Header của `Sender` theo đúng mẫu của Chrome; dùng HTTP/2 khi host có H2.

**N2. Client nhẹ đúng TLS/H2 của trình duyệt.** **Hoãn (review ngày 2026-11-13):** chưa có bằng chứng cần (mục 1.3b). fhttp là bản fork của net/http, nên vướng `tlsutil.AIA`, `httptest` và việc ghim Go 1.25.4. Preset trễ so với Chrome có thể còn tạo ra điểm bất nhất. Chỉ xét lại khi thí nghiệm ở mục 7 cho thấy client Go có UA và header đúng vẫn bị chặn trong khi Chrome qua.
- Dùng uTLS + fhttp (hoặc tls-client), chọn preset **trùng bản lớn với Chrome của run**. Trễ quá N bản thì cảnh báo, hoặc tự chuyển phần đó sang Chrome.
- Áp cho cả engine HTTP và `Sender`.
- Kiểm tương thích với Go 1.25.x trước khi thêm dependency (CLAUDE.md giữ dòng `go 1.25.x`).

**N3. Chrome chỉ dùng khi cần, theo từng host.** **Hoãn cùng N2.** Với target cần challenge hoặc kiểm tra thiết bị, đường đi chuẩn hiện nay là `jsharvest login` hoặc `-attach` trên trình duyệt của kiểm thử viên.
- Gặp `challenge` (`cf-mitigated`), hoặc JSD bị bắt buộc: mở Chrome trên host đó với **cùng danh tính và cùng jar**, để Chrome tự qua challenge non-interactive, rồi chuyển cookie về cho client nhẹ.
- Challenge cần tương tác: **giao cho người** qua cửa sổ có giao diện hoặc noVNC (đã có cho `login`). Không dùng dịch vụ giải captcha.
- Làm mới phiên khi gặp lại `cf-mitigated`, hoặc khi cookie sắp hết hạn (15/30 phút).
- Nếu thí nghiệm ở mục 5 cho thấy clearance không sống được trên client nhẹ, thì riêng host đó chuyển hẳn sang Chrome. Đây là mô hình lai của Crawlee: mặc định nhẹ, lấy mẫu để kiểm lại.

**N4. Hành vi và hiệu suất thông tin:**
- Mỗi host một request một lúc, nhịp có dao động, chuỗi Referer hợp lý, request thăm dò xen kẽ với điều hướng bình thường.
- `verify`: **dừng sớm khi gặp cổng chặn đồng nhất.** Nếu canary của k prefix (ví dụ 3) và các probe đầu đều nhận cùng một chữ ký phản hồi (cổng xác thực hoặc kiểm tra thiết bị của app, hoặc trang chặn), thì dừng host đó và báo "cần danh tính hoặc header thiết bị". Với `admin-a` 25D, cơ chế này đã tiết kiệm khoảng 280/300 request (ước lượng).
- Ngân sách lỗi theo host kiểu nuclei `-mhe`; tự điều chỉnh rate kiểu feroxbuster.

**N5. Sửa lại cách xử lý khi bị chặn của 25H:**
- Nhận diện 1xxx dạng text thuần (`error code: 1006`); coi "Sorry, you have been blocked" là `request` (luật WAF), không phải `challenge`.
- **1006 không còn được coi là bằng chứng cấm IP.** Chỉ kết luận "bỏ host" khi request đối chứng gửi bằng lớp gửi tốt nhất đang có (N1/N2, hoặc Chrome theo N3) cũng bị chặn.
- Request đối chứng không được gửi bằng chính client vừa bị chặn.

## 7. Thí nghiệm cần làm trước khi chốt N2/N3
Testbed hiện tại không mô phỏng được cách Cloudflare chấm điểm. Đề xuất **một zone Cloudflare của chính anh/chị** (gói free có Bot Fight Mode; nếu có gói cao hơn thì bật JSD) để đo, không động tới target của khách:
1. Go net/http, uTLS + fhttp (cùng bản lớn với Chrome), và Chrome: tỉ lệ bị chặn và challenge trên cùng IP.
2. `cf_clearance` lấy từ Chrome rồi dùng lại bằng uTLS + fhttp suốt 30–60 phút: có sống không, bị challenge lại lúc nào.
3. Tác động của N0 (bỏ tự khai báo) và N4 (nhịp) lên hành vi của Bot Fight Mode.

## 8. Quyết định cần người dùng chốt
1. **"Không giả TLS"** (CLAUDE.md dòng 184, `gd6-waf-design.md:78`): giữ nguyên, hay cho phép uTLS + fhttp ghim theo bản lớn của Chrome đang dùng (N2)?
2. **Cookie jar hạ tầng bền theo host** và dùng chung giữa các engine (N1).
3. **Zone Cloudflare thí nghiệm** riêng (mục 7).
4. Challenge cần tương tác thì giao cho người (N3).

Thứ tự đề xuất: N0 và N5 (sửa lỗi, không cần chốt gì) → N1 → N4 → thí nghiệm ở mục 7 → N2/N3.

**Cập nhật sau review (2026-11-13):**
- N0, N5 và phần dừng sớm của N4 đã xong (Đợt 25I, mục 28 của `gd6-waf-design.md`).
- N1 thu hẹp lại: UA và Sec-CH-UA theo đúng bản Chrome; `Sender` dùng HTTP/2; cookie chỉ trong bộ nhớ của từng (target, role).
- N2/N3 hoãn vì chưa có bằng chứng (mục 1.3b).

## 9. Nguồn
- Cloudflare: [bot detection engines](https://developers.cloudflare.com/bots/concepts/bot-detection-engines/) · [per-customer bot defenses](https://blog.cloudflare.com/per-customer-bot-defenses) · [Adaptive Intelligence](https://blog.cloudflare.com/introducing-adaptive-intelligence/) · [JA3/JA4](https://developers.cloudflare.com/bots/additional-configurations/ja3-ja4-fingerprint/) · [JA4 signals](https://blog.cloudflare.com/ja4-signals/) · [cookies](https://developers.cloudflare.com/fundamentals/reference/policies-compliances/cloudflare-cookies/) · [clearance](https://developers.cloudflare.com/cloudflare-challenges/concepts/clearance/) · [challenge passage](https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/challenge-passage/) · [how challenges work](https://developers.cloudflare.com/cloudflare-challenges/concepts/how-challenges-work/) · [JavaScript detections](https://developers.cloudflare.com/cloudflare-challenges/challenge-types/javascript-detections/) · [detect challenge response](https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/) · [1xxx errors](https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-1xxx-errors/) · [residential proxy detection](https://blog.cloudflare.com/residential-proxy-bot-detection-using-machine-learning/)
- HTTP/2 fingerprint: [Black Hat EU 2017](https://www.blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients.pdf) · JA4: [FoxIO](https://github.com/FoxIO-LLC/ja4) · Chrome xáo trộn extension: [blink-dev](https://groups.google.com/a/chromium.org/g/blink-dev/c/bYZK81WxYBo), [Fastly](https://www.fastly.com/blog/a-first-look-at-chromes-tls-clienthello-permutation-in-the-wild)
- Chrome/CDP: [gỡ headless kiểu cũ](https://developer.chrome.com/blog/removing-headless-old-from-chrome) · [remote-debugging-port từ Chrome 136](https://developer.chrome.com/blog/remote-debugging-port) · [WebDriver spec](https://w3c.github.io/webdriver/#interface) · [Castle: Runtime.enable signal](https://blog.castle.io/why-a-classic-cdp-bot-detection-signal-suddenly-stopped-working-and-nobody-noticed/) · [rebrowser](https://rebrowser.net/blog/how-to-fix-runtime-enable-cdp-detection-of-puppeteer-playwright-and-other-automation-libraries) · [rebrowser-patches](https://github.com/rebrowser/rebrowser-patches) · [Patchright](https://github.com/Kaliiiiiiiiii-Vinyzu/patchright) · [nodriver](https://github.com/ultrafunkamsterdam/nodriver) · [Electron UA metadata](https://github.com/electron/electron/pull/34481) · [Playwright SW UA](https://github.com/microsoft/playwright/pull/41071) · [UA reduction](https://www.chromium.org/updates/ua-reduction) · [CDP Fetch.pdl](https://github.com/ChromeDevTools/devtools-protocol/blob/master/pdl/domains/Fetch.pdl) · [Network.pdl](https://github.com/ChromeDevTools/devtools-protocol/blob/master/pdl/domains/Network.pdl) · [Cookie override bị bỏ qua](https://github.com/microsoft/playwright/pull/35168) · [Fetch spec forbidden headers](https://fetch.spec.whatwg.org/#forbidden-request-header) · [Fetch metadata](https://w3c.github.io/webappsec-fetch-metadata/) · [benchmark 2026 (C)](https://dev.to/ianlpaterson/anti-detect-browser-benchmark-2026-7-stealth-tools-31-cloudflare-targets-651-verdicts-4361)
- Kiến trúc tham khảo: [Burp browser-powered scanning](https://portswigger.net/blog/browser-powered-scanning-in-burp-suite) · [Burp docs](https://portswigger.net/burp/documentation/desktop/scanning/browser-powered) · [ZAP AJAX spider](https://www.zaproxy.org/docs/desktop/addons/ajax-spider/) · [ZAP client spider](https://www.zaproxy.org/blog/2025-01-31-client-spider/) · [katana](https://github.com/projectdiscovery/katana) · [Crawlee sessions](https://crawlee.dev/js/docs/guides/session-management) · [fingerprint-suite](https://github.com/apify/fingerprint-suite) · [AdaptivePlaywrightCrawler](https://crawlee.dev/js/api/playwright-crawler/class/AdaptivePlaywrightCrawler) · [Playwright fetch.ts](https://github.com/microsoft/playwright/blob/main/packages/playwright-core/src/server/fetch.ts) · [FlareSolverr](https://github.com/FlareSolverr/FlareSolverr) · [cf_clearance loop (C)](https://dev.to/bshahin/cloudflare-cfclearance-why-it-expires-and-how-to-stop-the-re-challenge-loop-do9)
- Client nhẹ: [uTLS](https://github.com/refraction-networking/utls) · [fhttp](https://github.com/bogdanfinn/fhttp) · [tls-client](https://github.com/bogdanfinn/tls-client) · [azuretls-client](https://github.com/Noooste/azuretls-client) · [curl-impersonate](https://github.com/lwthiker/curl-impersonate) · [curl_cffi](https://github.com/lexiforest/curl_cffi) · [curl_cffi FAQ](https://curl-cffi.readthedocs.io/en/latest/impersonate/faq.html) · [Kyber → ML-KEM trong Chrome](https://security.googleblog.com/2024/09/a-new-path-for-kyber-on-web.html)
- Nhà cung cấp khác: [DataDome Device Check](https://docs.datadome.co/docs/device-check) · [HUMAN cookies](https://docs.humansecurity.com/pxconsole/docs/cookies) · [Akamai _abck (C)](https://scrapfly.io/blog/posts/akamai-bot-manager-understanding-abck-cookies-and-sensor-data)
- Công cụ scan thích nghi: [feroxbuster auto-tune](https://epi052.github.io/feroxbuster-docs/docs/examples/auto-tune/) · [ffuf](https://github.com/ffuf/ffuf) · [nuclei mass scanning](https://docs.projectdiscovery.io/tools/nuclei/mass-scanning-cli) · [sqlmap usage](https://github.com/sqlmapproject/sqlmap/wiki/usage)
