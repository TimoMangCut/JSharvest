# Đợt 13 — Pre-Auth không cần trình duyệt, cách ly WAF/challenge (D1–D5)

**Nguồn:** đánh giá độc lập, Đợt 13 (`CF-01` → `CF-06`, lộ trình D1 → D5). Chủ dự án đã gỡ quy ước cũ "chỉ phát hiện, không vượt" trong `CLAUDE.md`.

**Hiện trường** (`output/admin.target-a.example/anon/`, chạy ngày 2026-11-06):
- trang `/` trả `403` kèm `cf-mitigated: challenge`, request gửi đi mang `HeadlessChrome`;
- guard giữ hai POST telemetry của challenge (`/cdn-cgi/challenge-platform/h/b/f*`);
- store nhận 8 script của Cloudflare: 1 inline loader, 2 file, 5 khối eval khoảng 1,3 MB;
- `endpoints.jsonl` có 3 endpoint `/cdn-cgi/…`;
- `archive` liệt kê được 2 capture `text/html` nhưng tải được 0.

**Quyết định của người dùng (2026-11-08):** `crawl -engine auto` (mặc định) chọn engine **HTTP** cho anon và chỉ dùng Chrome khi cần: có `-role` khác anon, `-profile`, phiên đã lưu, `-attach`, `-explore` hoặc `-headful`. Đánh đổi đã nêu và người dùng chấp nhận:
- anon mặc định không còn traffic thật của trang (flows, request API);
- muốn có traffic thật thì chạy `-engine cdp`;
- các gate cũ đặt `JSHARVEST_ENGINE=cdp`.

## 1. D1 — Cách ly challenge (CF-01) và `/cdn-cgi/` đi qua guard (CF-02)

**Nhận diện** (`internal/detect`):
- `ChallengeURL`: challenge-platform, `images/trace` và Turnstile của Cloudflare; DataDome (captcha-delivery, js.datadome.co); PerimeterX; `_Incapsula_Resource`; hCaptcha; reCAPTCHA; Arkose.
- `InfraURL`: các script khác dưới `/cdn-cgi/` (email-decode, Zaraz, RUM) và `static.cloudflareinsights.com`. Gắn tag `cdn-infra`: vẫn giữ trong store nhưng không đọc endpoint.
- `IsChallengeScript(url, initiator, kind, body, pageBlocked)` trả true khi gặp một trong ba trường hợp:
  - URL của script, hoặc initiator của nó, là của challenge. Các khối eval của VM Cloudflare không có URL; initiator của chúng là platform.
  - Trang đang là trang challenge (`pageBlocked`).
  - Script inline hoặc eval **nhỏ hơn hoặc bằng 64 KB** chứa dấu hiệu riêng của challenge (`_cf_chl_opt`, `__cf_chl_tk`, `/cdn-cgi/challenge-platform/`…). File của site có nhắc tới các chuỗi đó, hoặc code inline lớn, thì vẫn giữ: code của site có thể xử lý challenge.
- `InfraPath(path)`: path bắt đầu bằng `/cdn-cgi/`. Không bao giờ là endpoint của site.
- `Quarantined(tags, urls, initiators)`: dùng để đọc output cũ, ghi từ trước khi capture biết bỏ challenge.

**Capture** (`internal/capture`):
- Script challenge **bị bỏ ngay ở `emit`**: không tới sink, store, resolver hay catalog. Trước đây chúng được giữ và gắn tag; Reviewer yêu cầu cách ly.
- Script có URL hoặc initiator là challenge thì không đọc source luôn: `Debugger.getScriptSource` và `Network.getResponseBody` không được gọi. Hash của nó được đánh dấu `challengeSHA`, nên các lần thấy lại cũng bị bỏ.
- `mainBlocked` lấy theo document chính mới nhất (`detect.Check`). Khi document chính bị chặn, mọi script của target `page` đều là của challenge.
- Recorder gắn tag `challenge` cho request do code challenge tạo (theo initiator hoặc stack), và cho request chạy trên trang bị chặn. Request vẫn được ghi trong `requests.jsonl` vì nó đã thật sự được gửi. Tuy vậy, `endpoints`, flows (`Internal`), `roles` và `export` đều bỏ qua nó.
- `run.json` có `stats.challenge_scripts` (đếm một lần cho mỗi nội dung hoặc URL). Cảnh báo `AllChallenge` giờ tính trên tổng số script đã thấy, gồm cả số đã bỏ.

**Guard** (`guard.Rules.Classify`):
- Path `/cdn-cgi/…` được cho qua với lý do `cdn-infra`, **trước** luật phá huỷ, vì token ngẫu nhiên của challenge có thể vô tình chứa một từ như "Delete".
- `-guard-deny` của người dùng vẫn được áp trước.
- Ngoại lệ: **`/cdn-cgi/access/`** (Cloudflare Access; `/cdn-cgi/access/logout` là logout thật) vẫn đi qua luật thường.
- Path được `path.Clean` sau khi decode hai lần, nên `/cdn-cgi/%2e%2e/api/x` không thoát được kiểm tra.

**Frontier:** URL `/cdn-cgi/` được liệt kê trong `pages.jsonl` với lý do `cdn-infra`, không được thăm.

**Endpoints:**
- `readIndex` bỏ các script `Quarantined`. Nhờ đó các khối eval không tag trong output cũ cũng bị bỏ.
- `Build` bỏ path `/cdn-cgi/`, cả từ code lẫn từ traffic. `Requests` bỏ request có tag `challenge`.
- Kiểm trên bản chép output thật của target-a: từ 3 endpoint còn 0.

## 2. D2 — `archive` đọc trang HTML cũ (CF-04a)

- `take` ghi các capture `text/html` có status 200 (không phải revisit, không mang credential) vào `html.jsonl`.
- `pages()` chạy sau bước liệt kê và trước bước tải:
  - chọn capture mới nhất của mỗi URL, ưu tiên `/` (trang này gọi entry bundle), rồi tới path nông nhất, rồi mới nhất; tối đa `-max-html` trang (mặc định 10);
  - tải memento `id_` của từng trang rồi đọc bằng `internal/htmlscan` (package mới, dùng chung với engine HTTP): `<script src>`, module, import map, `modulepreload`/`preload as=script`, code inline, và `__NEXT_DATA__` (build id, chỉ nhận ký tự an toàn, để suy ra `/_next/static/<id>/_buildManifest.js`).
- Trang challenge đã được lưu trong archive (title "Just a moment", script challenge, `_cf_chl_opt`) thì bị bỏ qua. Script của trang đó **không bao giờ được yêu cầu**.
- Code inline được đưa vào store archive với kind `inline`, tag `archive-html`.
- Script do trang cũ chỉ ra được ghi vào `js.jsonl` dưới dạng capture không có digest (`source: archive-html`). Bước tải xử lý như với URL của OTX:
  - kiểm trên server hiện tại trước (live check, chỉ tới các host crawl đã tới);
  - sau đó tải memento ở thời điểm của trang;
  - memento trả 404 tính là `not_archived`, không phải lỗi.
- **Đệ quy:** mỗi body tải được (bản live hoặc bản archive) đi qua `resolve.Static`. Chunk tìm được nằm trong scope thì được đưa vào hàng đợi (`source: archive-resolve`) và ghi vào `js.jsonl`, nên lần chạy tiếp vẫn còn.
- Khi bước liệt kê chỉ xong một phần (`-max-pages`), một script có thể được một trang cũ chỉ ra trước khi dòng CDX có digest của nó được liệt kê. Ở nhánh "merged", nếu store đã có bản live trùng byte thì đặt `live_same`.
- Summary có thêm: `html_captures`, `pages_read`, `page_scripts`, `inline`, `resolved`, `not_archived`, `skipped["challenge page"]`.
- Fixture `archive-app`:
  - trang `/` năm 2023 trỏ tới `/static/html-only.js` (chỉ có trong archive, nạp `html-chunk.js`) và `/assets/live-only.js` (không có trong archive, vẫn còn trên server, nạp `live-chunk.js`), cộng một script inline;
  - một trang `/login` là trang challenge đã lưu.
  - Truth có `live_only` cho phần chỉ tìm được nhờ live check (chế độ `-live=false` bỏ qua phần này).

## 3. D3 — Engine HTTP thuần Go (CF-03) và cứu viện bằng archive (CF-04b)

**`internal/httpcrawl`** (không phụ thuộc trình duyệt):
- **Client:**
  - `net/http` có HTTP/2, cookie jar riêng cho mỗi run, rate chung cho mọi loại request (`-http-rate`, mặc định 5/s);
  - header giống trình duyệt: `User-Agent` của Chrome desktop ổn định (`-ua` để đổi), `Accept`, `Accept-Language`, và `Sec-Fetch-*` theo loại request (document, script, data);
  - để transport của Go tự xử lý gzip, không thêm thư viện brotli;
  - redirect ra ngoài scope thì dừng;
  - hiểu `MAP` của `-host-resolver-rules`.
  - **Không giả TLS fingerprint** (JA3 vẫn là của Go). Reviewer không yêu cầu, và việc đó đi quá xa so với "không tự gắn nhãn bot".
- **Trang:**
  - BFS qua `frontier.Queue`, dùng chung luật phá huỷ với guard;
  - mỗi trang được kiểm `detect.Check` bằng header, status, title và tối đa 64 KB đầu của body;
  - nếu trang là challenge: không lấy script nào, không đi theo link nào;
  - ngược lại: `htmlscan.Scan` lấy script, `frontier.FromHTML` lấy link, và code inline đi qua `resolve.Static`.
- **Thăm dò** (một lần, sau trang đầu): `robots.txt` cùng các sitemap, `asset-manifest.json` (CRA, cả dạng phẳng), `ngsw.json`, `.vite/manifest.json`, `/service-worker.js` và `/sw.js` (danh sách precache của Workbox). File không có chỉ tốn một 404.
- **Script:**
  - worker pool (4 worker);
  - mỗi URL phải qua `resolve.Policy` (scope, IP private), ngân sách `-resolve-max`, và không phải `ChallengeURL`;
  - nhận khi status 200 và body không giống HTML;
  - sau đó `resolve.Static` trên body, đệ quy tới hết đồ thị;
  - nếu `-depth > 0`, route lấy được từ `jsapi` được đưa vào hàng đợi trang.
- **Dừng lịch sự:** khi gặp 429, `cf-mitigated`, hoặc 503 có `Retry-After`, từ trang thứ hai trở đi.
- **`resolve.Static` mới hiểu thêm worker:** `serviceWorker(?.)register("…")`, `new Worker("…")`, `new SharedWorker("…")` với URL hằng, resolve theo document. Resolver của CDP cũng được thêm phần này.

**`engine.RunHTTP`:**
- Output giống hệt một run của trình duyệt: store, index, `pages.jsonl`, `endpoints.jsonl`, `run.json` và `runs.jsonl` với `mode: "http"`, `config.engine: "http"`, và `http{…}` (số request, cách tìm thấy script, kết quả thăm dò, stop).
- `requests.jsonl` ghi với target `http`, theo `-record`. Request thăm dò và source map dùng loại `Other` và có tag `jsharvest`, nên không thành endpoint. `CrawlHosts` của archive vẫn thấy được host đã tới.
- Thoát với mã 3 khi trang đầu là challenge.

**Cứu viện** (`-archive-fallback`, mặc định bật với engine HTTP): khi trang đầu là challenge và không lấy được script nào, `crawl` gọi `jsharvest archive -target <host> -sources wayback,otx` qua `archiveRun`. Kết quả ghi vào `run.json` dưới `fallback{archive, summary}`. Mã thoát vẫn là 3, vì trang live đã bị chặn. **Bước này gửi request tới Wayback và OTX thật**, trừ khi đặt biến môi trường của gate.

**CLI:**
- Các cờ mới: `-engine auto|http|cdp` (env `JSHARVEST_ENGINE`), `-http-rate`, `-probe`, `-sourcemaps`, `-sourcemap-guess`, `-archive-fallback`, `-challenge-wait`.
- `-engine http` cùng với `-attach`, `-explore`, `-headful` hoặc phiên đã lưu thì báo lỗi.
- `-urls` với engine HTTP chạy lần lượt từng URL.

**`monitor`:**
- Run `http` giờ được lấy.
- `config.engine` khác nhau nên run HTTP không so với mốc của trình duyệt.
- Khi `http.stopped` có giá trị, snapshot được đánh dấu là chưa đủ (partial).

**Số liệu** (testbed, engine HTTP, không có Chrome, mỗi app khoảng 3–4 s): webpack-vanilla 16/20, vite-vanilla 10/10, vite-pwa 10/10, next-mixed 7/9, angular-ngsw 7/7, **tổng 50/56**.
- Các marker còn trượt đều cần runtime hoặc phiên: eval, chunk chỉ trả cho admin, iframe khác site, và 2 route của Next App Router.
- So sánh: Capture v2 chỉ tải trang được 39/56; katana `-hl` được 30/56.

## 4. D4 — Source map (CF-05)

- **`internal/sourcemap`:**
  - `Find` tìm map theo thứ tự: header `SourceMap`/`X-SourceMap`, rồi comment `sourceMappingURL` cuối cùng trong 4 KB cuối file (cả dạng `data:` inline), rồi đoán `<script>.map` (chỉ với `-sourcemap-guess`, vì tốn thêm một request cho mỗi script);
  - `Parse` hiểu tiền tố XSSI `)]}'`, map dạng section (indexed), và chỉ nhận map v3;
  - `Files` trả các nguồn có nội dung, nguồn của site trước; nguồn `node_modules`, `webpack/` được đánh dấu là vendor;
  - `Clean` chuẩn hoá đường dẫn (bỏ `webpack://`, `../`, `?hash`).
- **Engine HTTP:** map hợp lệ được lưu nguyên vào `maps/<sha256>.map`. Mỗi nguồn của site (không phải vendor) đi vào store với kind `source`, URL `<map>#<path>`, tag `sourcemap` và `source:<path>`, initiator là script gốc.
- **Endpoint:** parser của `jsapi` không đọc được TypeScript, JSX hay Vue. Vì vậy với script có tag `sourcemap` mà parse lỗi, `endpoints` dùng **`jsapi.ExtractLoose`**:
  - tìm lời gọi theo hình dạng: `fetch(`, `axios.get(`, `http.post<T>(`… lấy method, URL (template `${x}` và `:id` thành `{}`) và tên query;
  - tìm thêm các chuỗi path có từ hai đoạn trở lên (kind `string`), bỏ asset và đường dẫn module.
  - Không tăng `jsapi.Version`: kết quả của script đã parse được không đổi.
- **Để sau:** engine CDP chưa tải source map (store chỉ ghi `source_map_url`).

## 5. D5 — Chrome khi buộc phải dùng (CF-06)

- `browser.New`:
  - thêm cờ `--disable-blink-features=AutomationControlled`, nên `navigator.webdriver` là false;
  - sau khi khởi động, `cleanUA` gọi `Browser.getVersion` rồi đổi `HeadlessChrome/` thành `Chrome/` (hoặc dùng `-ua` / UA của phiên đăng nhập);
  - dựng `UserAgentMetadata`: brand "Google Chrome" và "Chromium" (major và bản đầy đủ), platform theo UA, architecture, bitness 64;
  - áp vào tab đầu tiên và gắn vào context (`browser.UAOf`). Trình duyệt `-attach` là của người dùng nên không bị đụng tới.
- Capture áp UA đó cho **mọi session nó gắn vào** trước khi bật Network: `Emulation.setUserAgentOverride` cho page và iframe, `Network.setUserAgentOverride` (lệnh thô, vì cdproto chỉ có bản của Emulation) cho worker và service worker. Tab 2..N và browser context của `-urls` thừa hưởng qua context.
- `login` ghi `navigator.userAgent` vào `jsharvest-session.json` (`user_agent`). `crawl -role` dùng lại UA đó nếu không có `-ua`, vì `cf_clearance` gắn với UA. `authz`/`replay` gửi lại header đã ghi, nên cũng giữ đúng UA của crawl.
- **Thời gian chờ challenge** (`-challenge-wait`, mặc định 6 s): sau `settle`, nếu document chính là trang challenge thì đợi document chính kế tiếp. Nếu challenge tự qua và trang tự tải lại thì chờ mạng yên lần nữa rồi tiếp tục. Việc này chỉ có tác dụng vì CF-02 đã cho câu trả lời của challenge đi qua guard. Testbed: `/cf-passes`.
- **Để sau:** request do worker gửi chưa mang Sec-CH-UA (testbed thấy rỗng; chưa rõ do override trên session worker hay do Chrome không gửi client hint từ worker). Header `User-Agent` của worker đã sạch.

## 6. Gate

`testbed/waf-check.sh` (đã thêm vào `regress.sh`) gồm 6 phần:
1. Trang challenge `/cf-challenge` với CDP: thoát 3; 0 script được giữ; ít nhất 4 script bị bỏ; 2 POST của platform đi qua guard; `endpoints.jsonl` và `blocked.jsonl` sạch.
2. Trang lành `/cf-healthy`: script của site được giữ; email-decode là `cdn-infra`; jsd bị bỏ; beacon đi qua guard.
3. Engine HTTP trên trang challenge, cứu viện bằng archive giả của archive-app: đọc trang cũ, tải script, có script còn sống.
4. Engine HTTP trên trang lành: không có challenge; thăm dò không thành endpoint.
5. `/ua-page` với CDP: không có `HeadlessChrome` ở trang và worker; Sec-CH-UA là Google Chrome; `webdriver=false`.
6. `/cf-passes`: challenge tự qua; thoát 0; script của site được giữ. Challenge trả lời sau 2,5 s, lâu hơn `-idle` 1,5 s, và gate đòi log của vòng chờ `-challenge-wait` (xem mục 9).

Unit test liên quan: `detect`, `guard` (`/cdn-cgi/`), `htmlscan`, `archive` (`pagePick`, `challengePage`), `httpcrawl` (dùng `httptest`: chunk map, modulepreload, inline, map, asset-manifest, robots, trang challenge, host rules), `sourcemap`, `jsapi` (`ExtractLoose`), `resolve` (worker).

## 7. Để sau, giới hạn đã biết

- Engine CDP chưa đọc source map. Engine HTTP không có eval, event, phiên hay flows: dùng `-engine cdp`.
- Không giả TLS/JA3. Một WAF chặn theo fingerprint TLS vẫn sẽ chặn engine HTTP; khi đó còn bước cứu viện bằng archive.
- Bước cứu viện chạy `archive` với cấu hình mặc định (Wayback và OTX thật, ngân sách chậm). Tắt bằng `-archive-fallback=false`.
- `diff` giữa role anon (HTTP) và role đã đăng nhập (CDP): chỉ còn một ghi chú (mục 9), không còn cảnh báo lệch config. Muốn so request thì crawl anon bằng `-engine cdp`.
- Chưa crawl lại `admin.target-a.example` (D1, tiêu chí 3), vì đó là request ra target thật; cần người dùng cho phép. `endpoints.jsonl` cũ đã được dựng lại offline (mục 9).

## 8. Đánh giá độc lập (2026-11-08) và các sửa đổi

Một agent review riêng đọc diff, chạy `go vet` và `go test -race` trên các package mới; không chạy gate. Có 7 phát hiện, đã sửa hết:

1. **(cao)** Engine HTTP bỏ qua `-proxy`. Cùng lúc `NoDNS` lại được bật, nên request đi thẳng từ IP của máy, vượt qua Burp hoặc egress đã được phép. Đã sửa: `RunHTTP` truyền `Proxy` vào; thêm unit test `TestProxy`.
2. **(trung bình)** "Trang bị chặn" được đọc lúc `emit` hoặc lúc quét recorder, tức là sau khi đọc body bất đồng bộ. Script và request của trang N (còn lành) có thể bị bỏ khi trang N+1 bị chặn, và sha của chúng bị đưa vào danh sách đen cho cả run. Đã sửa: `blockedPages` gồm URL của document bị chặn và nhãn trang lúc nó tới; chỉ script hoặc request của **đúng trang đó** mới bị bỏ theo trang; lần bỏ theo trang không ghi vào `challenges`.
3. **(trung bình)** DataDome và PerimeterX coi 401/403 của chính app là bị chặn, vì `x-datadome`/`x-px` có trên mọi response. Đã sửa: DataDome cần thêm `x-dd-b` hoặc dấu hiệu `captcha-delivery.com` trong body; PerimeterX cần `x-px-block` hoặc dấu hiệu trong body; bỏ 401 khỏi `blockingStatus`. Fixture `/blocked-datadome` có thêm `X-Dd-B`.
4. **(thấp)** `cdnInfra` decode path quá mạnh, nên `/logout%2f..%2fcdn-cgi/x`, `/cdn-cgi/..;/api/delete`, `..%5c`, `/cdn-cgi/access;x/logout` đều được cho qua. Đã sửa: chỉ path thô bắt đầu bằng `/cdn-cgi/` theo đúng ký tự, không có `%`, `;`, `\`, `//` hay đoạn `.`/`..`. Có thêm test cho từng ca.
5. **(thấp)** Engine HTTP không dừng khi gặp trang chặn của vendor khác Cloudflare. Đã sửa: `polite` dùng `detect.Check` cho mọi câu trả lời, và một trang challenge sau trang đầu sẽ dừng crawl. Thăm dò sau trang đầu bị chặn vẫn chạy (theo CF-03), nhưng thăm dò nào gặp challenge thì dừng ngay.
6. **(thấp)** Redirect chỉ được kiểm scope. Đã sửa: redirect phải qua `resolve.Policy`, luật phá huỷ, và không được mang userinfo; URL script có userinfo không bao giờ được gửi.
7. **(thấp)** `ua.Apply` trong `browser.New` không có timeout. Đã thêm timeout 10 s.

Những phần reviewer xác nhận không có lỗi: sổ sách hash (`challengeSHA`, waiter), `drain()` (không deadlock, dừng đúng khi huỷ), challenge không lọt qua engine HTTP, archive (không gửi URL mang credential, không tải memento hai lần, resume đúng), thứ tự khoá của recorder.

## 9. Đợt 14 của đánh giá độc lập (2026-11-08)

Reviewer chấm 9,6/10 và nêu 3 điểm:

1. **NEW-D14-01.** Phần 6 của `waf-check` không thật sự kiểm vòng chờ `challengeGrace`. Fixture `/cf-passes` trả lời sau 1 s, ngắn hơn `-idle` 1,5 s, nên `WaitIdle` đầu tiên đã chờ qua lúc trang tải lại; log in ra `0 pass seen`. Đã sửa ở fixture chứ không đổi cờ của gate: challenge trả lời sau 2,5 s, nên tab yên khi trang vẫn là challenge, và gate đòi cả hai dòng log `the page is a challenge; waiting` và `the challenge passed`. Kết quả hiện tại: `1 pass seen`.
2. **NEW-D14-02.**
   - `diff`: `roles.RunConfig` đọc thêm `engine`. Một role mà mọi run đều là `http` được coi là role tĩnh:
     - không bị cảnh báo `-no-debugger` (engine HTTP không có debugger);
     - giữa role tĩnh và role chạy Chrome không so `explore`/`resolve`, vì hai khác biệt này đi kèm engine; `depth` vẫn được so;
     - thay vào đó là **một ghi chú cho mỗi role tĩnh**: script của role đó không chạy, nên endpoint mà role cao hơn dùng còn role tĩnh chỉ có trong code sẽ ra `client_gated` vì role tĩnh không gửi gì, không phải vì client của nó ẩn đi (`authz` vẫn thử từng endpoint).
   - Unit test là `TestCompareConfigsEngines`. Gate là phần D của `roles-check.sh`: anon chạy `-engine http` cạnh user/admin chạy Chrome.
   - Source map cho engine CDP: để sau, như reviewer đề xuất.
3. **NEW-D14-03.** `jsharvest endpoints -target admin.target-a.example -scope fqdn` chỉ đọc store có sẵn và không gửi request nào. `endpoints.jsonl` đi từ 3 endpoint của `/cdn-cgi/challenge-platform/` xuống 0. Lần chạy ngày 06/11 không giữ được script nào của site, chỉ có script challenge. Crawl lại vẫn chờ người dùng cho phép.

## 10. Mặc định của pha pre-auth: đi sâu và đọc lịch sử ngay (2026-11-08)

Người dùng chạy `crawl -u https://admin.target-a.example -scope fqdn` và hỏi: sao không đi sâu ngay từ đầu, và sao không lấy JS cũ luôn? CLAUDE.md mô tả pha pre-auth gồm cả HTTP, giải mã tĩnh lẫn archive, nên mặc định phải làm đủ cả hai:

- **`-depth` mặc định là 3 với engine HTTP** khi người dùng không truyền `-depth` và không dùng `-urls`. Vẫn giữ `-max-pages 200` và `-http-rate`. `-depth 0` để chỉ thăm một trang. Engine CDP vẫn giữ `-depth 0` như cũ, để bench và các gate giữ nguyên ý nghĩa.
- **`-archive` (mặc định bật) với engine HTTP:** crawl xong thì chạy `archive` cho host (mọi nguồn: `wayback,otx,commoncrawl` từ 2026-11-09, trước đó `wayback,otx`; `-scope` và `-proxy` lấy theo crawl), mỗi host một lần trong một danh sách. Archive chạy sau khi đã ghi `requests.jsonl`, nên bước kiểm live biết được host nào crawl đã tới.
  - Kết quả được ghi vào `run.json` ở `archive`. Khi trang đầu bị chặn và không có script nào, kết quả vẫn được ghi ở `fallback` như trước.
  - Crawl bị ngắt hoặc lỗi thì không chạy archive. Archive lỗi thì chỉ cảnh báo, không đổi mã thoát của crawl.
  - `-archive=false` quay lại hành vi cũ: chỉ cứu viện khi bị chặn, theo `-archive-fallback`.
- Hệ quả: `diff` sẽ báo `depth 3 vs 0` nếu role đăng nhập (CDP) không được crawl với `-depth` tương đương. Đó là cảnh báo đúng. `monitor` coi run có depth khác là không so được với mốc cũ.
- Gate: `waf-check` phần 3b (engine HTTP không cờ trên archive-app: `config.depth` là 3, `archive.summary.fetched` ≥ 1, không có `fallback`); phần 4 và phần D của `roles-check` đặt `-archive=false`, để gate không bao giờ gửi request tới Wayback thật.

### 10.1. Lần chạy thật đầu tiên với mặc định mới (target-a, 2026-11-08)

Người dùng tự chạy lệnh trên. Kết quả: 200 trang, 0 script mới, archive không đọc trang HTML cũ nào. Có ba lỗi:

1. **SPA trả cùng một shell cho mọi path.** Cả 200 trang đều là `index.html` (`found=8`). Các path lấy từ script là route của Vue router, chuỗi trong thư viện xlsx (`!DocumentSummaryInformation`, `_VBA_PROJECT_CUR/VBA/dir`), transport của sockjs (`xhr_send`, `eventsource`) và tên mutation của Vuex (`setUserInfo`). Đã sửa:
   - Chữ ký của shell (`shellPrint`) gồm title và danh sách script theo thứ tự (script inline tính theo code của nó).
   - Sau trang đầu (khi `-depth` > 0), tool gửi **một** GET tới path không thể tồn tại (`/jsharvest-<hex>-no-such-page`, loại `Other`, tag `jsharvest`). Nếu trả 200 với đúng shell đó thì `spa`: mọi URL do script chỉ ra (route, navigation, path) chỉ được liệt kê với `reason: spa-route`; link trong HTML, robots và sitemap vẫn được thăm.
   - Trang nào ra lại shell thì có `shell: true`, không đọc lại link (`http.shells`).
2. **GET tới URL API mẫu.** Ví dụ `/service/v1.0/admin/items/%7Bitem_id%7D/commands/item-blocking`. Trên host này đó chỉ là shell, nhưng ở một app có API cùng origin thì đây là GET thật tới endpoint lệnh. Đã sửa trong `frontier` (dùng chung với engine CDP), cho URL đến từ script (`JS`/`Route`):
   - path có `{`/`}` thì `reason: template`;
   - đoạn path `v<số>(.<số>)*` được tính là API như `/api/`.
3. **Archive tiếp tục từ checkpoint ngày 06/11** (do bản cũ tạo, chưa có `html.jsonl`). Đã sửa: `stateVersion = 2` nằm trong khoá của checkpoint; checkpoint cũ hơn thì liệt kê lại từ đầu.
   - **Đính chính (đánh giá độc lập đợt 16, 2026-11-09):** ghi chú trước đây nói việc này làm bỏ lỡ "bản HTML của `/` chụp ngày 29/05/2024". Sai: Wayback chỉ có hai capture ngày đó, `http://…/` là `text/html` nhưng **301** (chuyển sang https), còn `https://…/` là **403** `application/json`. Không có trang 200 nào để đọc, nên kể cả với checkpoint mới thì `pages_read` vẫn là 0. OTX liệt kê 0 URL vì hỏi sai section (`domain` cho một subdomain, ARC-02); đã sửa ở `docs/gd5-archive-design.md` mục 10.

Unit test: `TestCrawlSPA`, `TestCrawlTemplates`, các ca mới trong `TestQueue`. Trên 5 app của testbed (đều có SPA fallback), engine HTTP với mặc định mới đạt **51/56** (next-mixed 8/9 nhờ đi sâu), trước đây là 50/56.

## 11. đánh giá độc lập đợt 17: không tự dừng sớm, source map mặc định (2026-11-09)

Phần archive xem `docs/gd5-archive-design.md` mục 11.

**MAX-02 (`httpcrawl`).** Kiểm trên code thì mô tả "huỷ các `.js` đang chờ trong `drain()`" không đúng: `drain()` chạy đồng bộ theo từng trang, nên khi trang sau bị chặn thì script của các trang trước đã tải xong. Ba chỗ tự giới hạn có thật đã sửa:
- `fetch()` bọc mọi request: 429 (không có `Retry-After` thì chờ 2 s) hoặc 503 có `Retry-After` ≤ 15 s thì chờ rồi hỏi lại, tối đa 2 lần. Mỗi lần thử đều được ghi vào `requests.jsonl`. `Retry-After` dài hơn, hoặc `cf-mitigated`, vẫn làm dừng crawl (`polite`).
- Một trang sau bị challenge chỉ bỏ qua trang đó (có thể chỉ là luật WAF cho một path); **3 trang bị challenge liên tiếp** mới dừng crawl.
- Chạm `-resolve-max` chỉ dừng việc tải script, trang vẫn được thăm tiếp (`http.capped`, cảnh báo trong `run.json`).

**MAX-04.** `-sourcemap-guess` mặc định bật. Chỉ đoán cho script của app; bundle thư viện (`frontier.Vendor`: `vendors.js`, `polyfills`, `framework`…) không bị đoán.

**MAX-07 (engine CDP).** Resolver đọc map của các script vừa capture được: theo `sourceMapURL` của Debugger, header `SourceMap`, comment `sourceMappingURL` (kể cả `data:`), hoặc đoán `<script>.map` cho script của app. Map được tải qua trang như chunk (isolated world, chính sách scope, `-resolve-rate`, tính vào `-resolve-max`, đọc tối đa 16 MB), và dừng khi gặp 429 hoặc challenge. Nguồn của chính app vào store với kind `source`, via `sourcemap`; `run.json` có `resolver.source_maps` và `map_sources`. Cờ dùng chung với engine HTTP: `-sourcemaps`, `-sourcemap-guess`.

**Gate:** `waf-check` phần 7 (fixture `maps-app`, cả hai engine): 2 nguồn (map được chỉ tên và map đoán ra), cả hai endpoint có trong catalog, không có endpoint nào của `node_modules`, không có `GET /assets/vendors.js.map`. `parallel-check` không tính 404 của `.map` đoán vào phép kiểm "mọi trang members trả 200"; `maps-app` có trong `bench` (3/3). Unit test `TestNoEarlyStop` (429 được chờ qua; một trang bị challenge thì crawl đi tiếp; 3 trang liên tiếp thì dừng; chạm ngân sách script thì trang vẫn được thăm).


## 12. Đợt 18: target-c.example, một SPA thật đứng sau Cloudflare (2026-11-09)

Người dùng tự chạy `crawl -u https://target-c.example -scope rdn -depth 4 -max-pages 500 -resolve-max 2000 -http-rate 10`. Kết quả: 372 trang, 438 script, 1241 request. Đọc output (không gửi request nào) thấy các vấn đề dưới đây.

**Cloudflare.** Không có trang nào của `target-c.example`, `developer.` hay `accounts.` bị chặn. `challenge_scripts: 347` là script JSD mà Cloudflare chèn inline vào mọi trang lành; loại ra là đúng. Chỉ `growth.target-c.example/` trả 403 challenge, nên không có JS nào của host đó.
- Đã sửa: engine HTTP ghi các trang bị challenge vào `Result.Challenged`.
  - Một host đã bị challenge `hostGiveUp` = 2 lần mà chưa trang nào của nó qua thì không bị hỏi thêm; các trang còn lại ghi `reason: challenged-host`.
  - Với `-engine auto` (mặc định) và `-escalate` (mặc định bật), `engine.Escalate` chạy Chrome (engine CDP) **một lần cho mỗi host bị challenge**, tối đa 5 host:
    - target là trang bị challenge nông nhất của host, các trang còn lại là `Seeds`;
    - `Depth` là phần còn lại của `-depth`;
    - `PageScope` chỉ là host đó, trừ khi trang bị challenge chính là trang đầu: khi đó là cả scope;
    - output ghi vào thư mục của seed (`OutHost`).
  - `run.json` của lần chạy HTTP có `escalated` (`pages`, `runs[]`: `host`, `run_id`, `pages`, `new_scripts`, `blocked`, `exit_code`). `runs.jsonl` có cả lần chạy của Chrome.
  - Trang đầu bị challenge mà Chrome qua được thì mã thoát là 0 và không chạy archive fallback.
  - Chrome không qua được challenge tương tác hay trang chặn, và lần chạy đó ghi `blocked`.
  - `-engine http` không bao giờ mở browser.
  - Crawl dừng vì 429 hoặc `Retry-After` thì không chuyển sang Chrome, vì browser chỉ làm tăng tải.

**Resolver bỏ sót 4 file JS thật.** So các đường dẫn `.js` mà code đã tải có nhắc tới với danh sách đã tải: 50 file chưa tải, trong đó 46 là đường dẫn `node_modules` nằm trong comment của bundle.
- `new SharedWorker(new URL(`/_vite/notification-shared-worker-….js`, ``+import.meta.url))`: rolldown viết bằng backtick và có `""+`. `newURLRe` giờ nhận cả hai cách viết, và thêm `new URL(x, location|self.location|document.baseURI)` (tính theo tài liệu).
- `__mfImport("./pendingShares-….js")` (Module Federation), `var ps="/firebase-messaging-sw.js"` rồi `register(ps)`, `{url:"/_vite/hub-runtime.js"}`. Thêm phương thức yếu nhất **`js-string`**:
  - nhận mọi chuỗi `./x.js`, `../x.js` (tính theo script) và `/x.js` (tính theo origin của trang) mà chưa phương thức nào tìm thấy;
  - không nhận tên trần, scheme, `${}`, `//` hay `/node_modules/`;
  - đoán sai thì tốn một 404, hoặc nhận về shell của SPA và bị loại vì không phải script.

**Lãng phí request.**
- **431 lần đoán `.map`, không lần nào trúng:** 410 trả 404, 21 trả về shell HTML. Thêm `sourcemap.Guesses`, dùng chung cho cả hai engine: một origin đã trượt `GuessMisses` = 10 lần mà chưa trúng lần nào thì không đoán thêm (`map_guesses_held`). Map được chỉ tên thì vẫn tải.
- **111 trang rác** như `/timings/wait`, `/postData/params/comment`, `/cookies`, lấy từ bundle kiểm HAR. Đó là `instancePath`/`schemaPath` trong code standalone của Ajv. jsapi v8 không đọc giá trị của `instancePath`, `dataPath`, `schemaPath`, `errorPath`, `keywordLocation`, `instanceLocation`, `absoluteKeywordLocation`. Trên bundle thật số path giảm từ 148 xuống 37; 37 path còn lại là URL tài liệu tuyệt đối nằm ngoài scope.
- **19 trang là pattern hoặc ID route.** Frontier giờ xếp vào `template` mọi path do script chỉ ra (`JS`/`Route`) mà:
  - có đoạn `:x`, `$x`, `$`, hoặc `[x]`;
  - có `*` hoặc `**`;
  - có đoạn `(group)`, `...` hoặc `__root__`;
  - có `/node_modules/`.
  ID route của TanStack (`/_authenticated/home`, layout không có path) bị bỏ khi trang tương ứng (`/home`) cũng có trong script. `/_x` đứng riêng bị bỏ khi `_x` đã được chứng minh là layout, hoặc khi script có `__root__`. `/_next/…` và `/_admin` không có bằng chứng như vậy nên vẫn được thăm.
- **`shells` = 0 trên 350 trang SPA.** Script JSD chèn inline mang ray ID riêng cho từng response, nên `shellPrint` của mỗi trang đều khác. Giờ `shellPrint` bỏ script challenge (inline và URL) trước khi băm.

**Hồi quy do chính bản sửa `shellPrint` gây ra (bắt được ở lần chạy lại thật).** Khi đã nhận đúng shell, `target-c.example` được xác định là SPA. Nhưng cờ `spa` là của cả crawl, nên mọi URL do script chỉ ra đều chỉ được liệt kê `spa-route`, kể cả `developer.target-c.example` và `accounts.target-c.example` (các app khác). Kết quả là chỉ còn 1 trang và 25 script. Đã sửa: chữ ký shell và cờ `spa` tính **theo từng origin** (`prints`, `spa` map, `http.spa_origins`); trang đầu tiên của mỗi origin được thăm dò SPA riêng (thêm một GET cho mỗi origin). Unit test `TestSPAIsPerOrigin`.

**Trang chặn chỉ nhận ra được qua title (bắt được ở lần chạy lại thật).** Chrome mở `growth.target-c.example` và nhận trang "Attention Required! | Cloudflare" (403, là trang chặn của WAF; Chrome cũng không qua được). Trang này không có header `cf-mitigated`. Capture xác định trang bị chặn ngay lúc nhận response, khi chưa có title, nên 3 script inline của Cloudflare (`_cf_translation`, đoạn kiểm cookie, script hiện IP ở footer) đã lọt vào store.
- Đã sửa: `detect.Suspect` là document 403/429/503 sau một vendor được nhận diện, mà header và status chưa đủ để kết luận bị chặn. Script của trang đó bị **giữ lại** (`Capture.hold`) cho tới khi `MainDocument` đọc được title (`judge`): nếu là trang chặn thì loại và tính vào `challenge`; nếu không thì lưu bình thường.
- `challengeGrace` luôn đọc title ngay khi trang yên, trước resolver, kể cả khi `-challenge-wait 0`.
- Script đang giữ mà chưa có kết luận sẽ được lưu khi có document mới hoặc khi `Stop`.
- Gate: `waf-check` phần 1b, fixture `/cf-deny` và `/cf-site-403`. Binary cũ lưu 3 script, binary mới lưu 0; trang 403 của chính site vẫn giữ script của nó.

**Kết quả trên target-c.example, lần chạy lại thứ ba (cùng lệnh):**

| | Trước | Sau |
|---|---|---|
| Request (HTTP) | 1241 | 515 |
| Trang thăm | 372 | 33 (thêm 278 `spa-route` chỉ liệt kê) |
| Đoán `.map` | 431 | 37 (`map_guesses_held` 398) |
| Script | 438 | 442 của site (+4 file bị sót trước đây: shared worker, `pendingShares`, `firebase-messaging-sw.js`, `hub-runtime.js`); `developer.` 387 và `accounts.` 30 không đổi |
| `growth.target-c.example` | 1 trang bị challenge | Chrome chạy thử, cũng bị chặn (trang chặn của WAF, `escalated.runs[0].blocked`) |
| Thời gian | 490 s | 398 s (gồm Chrome và archive) |

Lần chạy thứ ba dùng binary trước bản sửa trang chặn, nên output vẫn còn 3 script inline của trang chặn trên `growth`.

**Thấy nhưng không phải lỗi của tool:**
- `developer.target-c.example/docs` chuyển hướng sang `http://developer.target-c.example:8080/docs/`, làm lộ cổng nội bộ.
- App con trong marketplace được nạp qua Module Federation từ `cdn_url + "remoteEntry.js"`, với `cdn_url` lấy từ API khi người dùng mở `/apps/$slug`. Danh sách host được phép nạp nằm trong code: `cdn.target-c.example`, `*.internal.example`, `*.partner-api.example`. Muốn lấy JS của các app này thì phải chạy `-role`.

**Gate:**
- Unit test:
  - `TestStaticRolldown`: các đoạn code nguyên văn;
  - `TestGuesses`;
  - `TestJSONPointersAreNoPaths`;
  - `TestRouterPatternsAreNoPages`;
  - `TestShellPrintIgnoresChallengeScript`: trượt khi không có bản sửa;
  - `TestChallengedHostLeftAlone`.
- `waf-check` phần 1b (trang chặn chỉ nhận ra qua title) và phần 8, fixture `/cf-links` → `/cf-passes`:
  - 8a: trang thứ hai bị challenge; Chrome qua được; `cf-passed-app.js` và `/api/after-challenge` nằm cùng output; `runs.jsonl` có 2 lần chạy;
  - 8b: trang đầu bị challenge; Chrome qua được; mã thoát 0;
  - 8c: `-engine http` không mở browser.

## 13. Đợt 19: CASE-19-01 → CASE-19-10 trên target-c.example (2026-11-10)

đánh giá độc lập đợt 19 đọc output của mục 12 và nêu 10 lỗi ở 4 khâu. Mỗi mục được đối chiếu với dữ liệu thật trước khi sửa; tất cả đều đúng.

**Nhóm 1 – jsapi (v9).**
- CASE-19-01: bundle developer (`index-C2MVMwx5.js`) có 51 lời gọi `yT`/`ST`; bản cũ lấy được 10.
  - `summaryOf` đi qua nhiều tầng: `yT(e,t) → eT(mT(e),t) → fetch(e,{...t})`.
  - `summary.urls` cho helper thử hai URL (`ST(a,b,…)`); `optsArg` là tham số options, kể cả khi được spread; URL lấy qua `paramIn` (`mT(e)`).
  - `initCall` đọc helper dựng `RequestInit` (`bT("POST", data, extra)`, các nhánh `?:`), gắn tham số qua `x.args`.
  - `relAPIRe` nhận 1–3 đoạn trước `/v1`.
  - Kết quả: 55 endpoint (51 lời gọi, `ST` cho 2 URL), method và body đúng.
- CASE-19-02:
  - `opts.isOpt`: `{method:"DELETE"}` và `{body, signal}` không còn thành body `["method"]`.
  - `storeLike` bỏ `cache.put(k, res.clone())` và các store khác.
  - `R("/auth/fail")({component})` là route, không phải endpoint.
  - **Chưa làm:** body của hàm bọc một tham số trên accounts (`requestMfaChallenge(e)`). Nơi gọi nằm ở chunk khác, qua bảng export của Turbopack (`e.s([...], 30483)` → `(0,H.$)(url, {...})`); muốn nối được phải liên kết module giữa các chunk.
- CASE-19-03: `locate` tìm mọi mảnh của template theo đúng thứ tự (`inOrder`, bám mảnh dài nhất, tối đa 256 vị trí). Bản cũ gắn sai snippet ở 8/11 endpoint của bundle developer; bản mới đúng 55/55.

**Nhóm 2 – base URL.**
- CASE-19-04:
  - `encoded` giải chuỗi base64 JSON, cả thuận lẫn đảo ngược (`globalThis._$c`): ra `apiBaseUrl` production và 7 khoá Firebase, nay nằm trong `intel.json` mục `keys`.
  - `configPairs` đọc cặp `"key":"value"` trong chuỗi (payload RSC của accounts: `API_URL`, `AUTH_API_URL`, `CLIENT_API_URL`).
  - `isBaseName` thay danh sách tên cố định.
  - `dT("VITE_…", "/x")` là base mặc định, không phải endpoint.
  - `evalCall` giải hàm của app, chẳng hạn `fe()` → `GET /openapi.yaml`. Chỉ giải hàm không tham số, hoặc hàm có ít nhất một đối số đã biết; tối đa 2 tầng lồng và 5.000 lần cho mỗi script; hàm không tham số được cache. Lần đo đầu không có giới hạn này: `crypto-browserify` mất 5 phút 23 giây.
- CASE-19-05:
  - `clients.go` theo dõi tiền tố của từng biến client: `Z=wy("/api")` → `/api/account/v1/me`; `Dy=Cy("/auth")` → `/auth/v1/oauth/token`; `Ey` → `/api/public/v1/workspaces/{}/config`, khớp request thật trong Burp của người dùng. Lời gọi factory không còn là endpoint.
  - `endpoints.Build`: bases theo origin của script; `PreferInScope` loại `https://api.hub.ecom-dev.internal.example/hub` vì có base trong scope; `baseFor` cắt base có path trùng đầu path endpoint (`…/hub/console/v1` + `/hub/console/v1/apps` → `https://api.target-c.example`), rồi xếp base tuyệt đối ngắn nhất lên trước.
  - **Giới hạn:** trên accounts, client được tạo từ `CLIENT_API_URL` hoặc `AUTH_API_URL` truyền vào từ module khác, nên tool chỉ đưa đủ ứng viên, không chọn được base đúng cho từng endpoint. `servers` của `openapi.yaml` là `https://{hostname}`, nên base đúng (`…/hub/openapi`) cũng chỉ là một ứng viên.

**Nhóm 3 – crawler.**
- CASE-19-06: `frontier.SpecFile` (`openapi|swagger|api-docs…` `.yaml/.json`) không bị liệt kê `spa-route`, cũng không bị xếp `api`. Trang không phải HTML mà là tài liệu OpenAPI thì được lưu với tag `openapi`. `jsapi.ExtractOpenAPI` (yaml.v3, `$ref` nội bộ, `allOf`) chỉ chạy cho script có tag này. Trên target-c: 51 endpoint, 8 có query, 15 có body.
- CASE-19-07: `internalPath` bỏ `/_head`, `/_tree`, `/ROOT/`, `/_index`, `/_not-found`, `/_app`, `/_error`, `/_next/` và `/_vite/` khi không có file, `/a/b`; bỏ cả chuỗi có `,` hoặc `*` (CSP). `realHost` không nhận host có `,` hoặc `*`. `vendorRe` thêm `turbopack` và `webpack`.

**Nhóm 4 – archive.**
- CASE-19-08: `samePath` cần ít nhất một đoạn có tên trùng (không tính `v1`); phần đuôi sau `{}` không được khớp vào placeholder. Giải nén `zstd` (kể cả khi không có header, nhận qua magic) và `br`.
- CASE-19-09:
  - Resolver: `base + '/x.js'` với `var base = "./static"` được tính theo script; base không biết thì không đoán theo gốc origin.
  - Memento của URL không có digest: 403 (trừ khi chủ domain loại trừ) cũng là chưa lưu; tối đa 50 s.
- CASE-19-10:
  - Live check mỗi URL một lần trong một run.
  - `Sender.dial` thử IPv4 trước, rồi lần lượt các địa chỉ khác; kiểm DNS rebinding trên mọi địa chỉ.
  - Với `-scope rdn`, OTX và urlscan được hỏi thêm tối đa 10 host khác mà crawl đã tới (`ExtraHosts`, `archive.json` `extra`).
- Phát sinh khi chạy lại thật: vì `https://api.target-c.example/hub/openapi` nay là base (không còn bị thăm như một trang), `api.target-c.example` không còn được tính là host đã tới, và live check của archive bằng 0. `CrawlHosts` giờ tính cả host của base trong scope có trong `intel.json`: đó là API mà code hôm nay đang dùng, không phải tên cũ có thể đã đổi chủ.

**Hiệu năng và nhiễu.** Tập 1.999 file (code của target-c, target-a, testbed, cộng một mẫu 1/8 `node_modules`):
- code của site 6,2 s, bằng HEAD; `node_modules` 5,4 s, so với 4,4 s của HEAD;
- endpoint mới trong `node_modules`: 1 (URL tài liệu của rollup);
- 35 endpoint "mất" đều là thay đổi có chủ đích: đổi tên vì có tiền tố client, rác bị bỏ, base không còn là endpoint.

**target-c.example, cùng lệnh, so với lần chạy cuối của đợt 18:**

| | Đợt 18 | Đợt 19 |
|---|---|---|
| Endpoint (`anon`) | 73 | 170 (55 của developer, 51 từ OpenAPI) |
| Base của endpoint target-c.example | `…ecom-dev.internal.example/hub` (dev) | `https://api.target-c.example/hub` |
| `intel.json` | 1 base (dev), không có khoá | 8 base, khoá Firebase production |
| Trang thăm | 33 (11 là tên nội bộ, trả 404/400) | 21, cộng `openapi.yaml` |
| Script | 442 | 443 (+`openapi.yaml`; 2 inline RSC khác nhau chỉ vì nonce) |
| Request (HTTP) | 514 | 501 |
| Archive | fetched 6, failed 6, 8 live check (4 lặp, 3 lỗi IPv6) | fetched 6, failed 0, not_archived 7, 6 live check khác nhau |
| `historical.jsonl` | 2 (3/6 `customer-profiles` bị nuốt) | 13: 6/6 `customer-profiles` kèm base growth, `chat-core` đang sống (200) với `/conversations` và `/mcps/{}/…` |
| `sdk-0.0.14.js` zstd | lưu nhị phân, lỗi parse | giải nén, gộp với bản thường |
| Thời gian | 870 s | 433 s (Common Crawl vẫn 504 cả 3 collection) |

Mọi endpoint ở trên vẫn là `static`: chưa có request nào kiểm chứng.

**Gate:** unit test `round19_test.go` trong `jsapi`, `endpoints`, `archive`, `httpcrawl`; `TestStaticConcatBase`; `TestRouterPatternsAreNoPages` mở rộng. Toàn bộ `regress.sh -j 3` qua. frontier-tabs-check và parallel-check trượt một lần khi máy đang tải nặng (so nhiễu chạy song song), rồi qua khi chạy lại lúc máy rảnh; chúng thuộc engine CDP, không bị đợt này sửa.

## 14. Đợt 20: COV-01 → COV-06, độ phủ và tham số trên target-c.example (2026-11-10)

Mỗi mục của đánh giá độc lập (Phần 2) được đối chiếu với output thật trước khi sửa. Cơ chế Reviewer mô tả đúng, nhưng nhiều chi tiết không khớp với dữ liệu:
- SHA và tên file không có trong output: `586ac5b…`, `aa3ac125…`, `cd8ec5c4…`, `/vbot/sdk/…`.
- COV-02: `/webhook/v1/…`, `/api/v2/Order…`, `/api/v2/SyncData/…`, `/api/v1.0/shortlinks`, `preview-tokens`, `/console/v1/apps/{app_id}/…` không có trong 443 file JS. `SyncData` chỉ là tên biến của bridge iframe.
- COV-03:
  - `POST …/apps` (`RT`) gửi đúng 8 trường, không phải ≥10; bản marketplace (`zT`) gửi 11.
  - `permission-scopes` gửi `{entries}`, không phải `scopes.map(…)`.
  - `_D` trả `locales.*`.
  - `MT` không đặt `page_token`.
- COV-05: không có `/v1/auth/logout` trong `index-CmkF70ZO.js`. Hai snippet lệch thật nằm ở chỗ khác, không phải chỗ Reviewer chỉ.
- COV-01: `rating` gửi `{rating}`, không phải `comment, rating`; `notes` nhận body là tham số truyền thẳng.
- COV-04: ký hiệu export thật là `"$"` cho `requestMfaChallenge`, `"g"` cho `verifyMfa`.

**Sửa (jsapi v10):**
- `helpers.go` thay `summary` cũ. Mỗi helper giữ lời gọi lá hoặc lời gọi helper khác; tại nơi gọi, tham số được gắn với đối số qua mọi tầng (`readCall`, `bindParams`). Các trường hợp được xử lý:
  - URL dựng từ tham số: `${o}/mcps/${s}/${e}` cho 5 route MCP, `RE(e,t,"remove")` cho `remove`/`withdraw`/`rotate`;
  - URL là thuộc tính của options (`e.exchangeUrl`, `e.url`);
  - `fetch` dưới tên khác (`n = e.fetch`, `{fetchFn: i}`, `e.fetchImpl`);
  - helper có URL cố định nhận body (`Ax` → `push-devices` với 6 trường);
  - query là tham số khác của URL (`r(t)+wr(a)`);
  - GET/HEAD không có body;
  - hàm dựng URL từ base (`sendUrl`/`eventsUrl`).
- `clientLeaf` chỉ nhận client thật (`isClientObj`). Lần thử đầu đã gặp `Map.delete` của một hàm kiểm tra bị đọc thành `DELETE https://{}`.
- `keys`: spread, `?:`, dấu phẩy, `.map`, lời gọi hàm của app (kể cả `let r={…}; r.x=…; return r`); hàm kiểm tra nhiều nhánh (`H(obj, "json.object")`) trả lại object nó nhận. `queries`, `URLSearchParams.set/append`, helper chỉ trả query string (`FE(n)`).
  - Ngân sách của `evalCall` giờ tính theo từng biểu thức gốc (300 lần), trần chung 50.000. Ngân sách 5.000 cho cả script đã cạn trên bundle developer, nên `FE(n)` không được giải.
- `modules.go` + `endpoints.linkModules` (COV-04): `M.s([...], id)` ↔ `(0,H.x)(cfg.AUTH_API_URL, {...})`. Body lấy từ bên gọi; base lấy theo tên setting (`Settings` từ config RSC), đúng một base.
- `docs.go` (COV-02): `kind: "doc"` từ bảng Markdown, `METHOD /path` và `curl -X`. Endpoint loại này không bị thăm và không được gắn base của origin. Không có endpoint `doc` nào trong 1.435 file `node_modules`.
- `prefixesOf`: `(W.sameOriginApi ? Z : Dy).post(…)` cho ra cả `/api/…` và `/auth/…`.
- `litsOf`: mỗi nhánh giá trị dùng literal của chính nó; URL của helper được đọc theo thứ tự source.
- Header: `.set("X-…")`, `l["X-…"] = v`, thuộc tính `X-…`/`Authorization`.
- endpoints:
  - origin đã biết mà không có base thì không mượn base của origin khác;
  - OpenAPI ưu tiên base có `/openapi`;
  - nhãn `openapi`/lời gọi thắng `doc`.
- archive: endpoint lịch sử có trong text của script hôm nay (hoặc chỉ có trong tài liệu) thì giữ trong `historical.jsonl` với lớp `in_current_code`. Trước đây chúng bị bỏ.

**Hiệu năng và nhiễu (1.996 file, gồm cả target-c):** 12,6 s so với 12,5 s của Đợt 19. Có 6 endpoint mới trong `node_modules`, đều là request thật của chính thư viện, tìm được qua helper nhiều tầng (overlay dev của Next, figma, Google Fonts).

**target-c.example, cùng lệnh:**

| | Đợt 19 | Đợt 20 |
|---|---|---|
| Endpoint `anon` | 170 | 229 (+53 `doc`, +6 lời gọi) |
| Có body / có query | 46 / 20 | 54 / 27 |
| Đúng một base | 29 | 43 (accounts theo `AUTH_API_URL`/`CLIENT_API_URL`; OpenAPI `…/hub/openapi`) |
| `historical.jsonl` | 13 | 29 (12 `historical`, 12 `in_current_code`, 5 `low`) |
| Header client (`anon`) | `cookie` | `X-CSRF-Token`, `Authorization`, `X-AXIS`, `cookie` |
| Request / script | 501 / 435 | 500 / 435 |

**Gate:** unit test `round20_test.go`; `go test -race ./...` qua; toàn bộ `regress.sh` qua (endpoints-check trượt một lần vì `$.ajax` có method `e.type||"GET"`, đã sửa). Riêng `replay.TestSenderConcurrency` là test thời gian vốn chập chờn: trên 100 lần chạy, `dial` cũ trượt 8, `dial` mới trượt 5.

## 15. Đợt 21: TRU-01 → TRU-05, base xác định và dọn nhiễu (2026-11-10)

đánh giá độc lập (Phần 2) được đối chiếu với output Đợt 20 trước khi sửa. Script nghiệm thu ở mục 2.7 chạy trên output Đợt 20 thì trượt 21 khẳng định. Một số khẳng định sai so với dữ liệu hoặc schema; những chỗ đó được ghi lại và kiểm bằng bản đã chỉnh (`check21.py`, mỗi khẳng định in PASS/FAIL riêng):
- Trường là `kind`, không phải `kinds`: khẳng định OpenAPI gốc luôn trượt.
- `_D(r)` đặt `display_name` dưới `locales[]`: trường đúng là `metadata.locales.display_name`.
- `GET /hub/auth`, `/hub/access-code` là `fetch("/hub/…")` tương đối tới chính `accounts.target-c.example` (route của Next), không có base là đúng. Tiêu chí J2 trong bảng cũng chỉ nói endpoint của `developer.target-c.example`.
- `/events` của chat-core là `r(…)+wr({lastEventId:t})` ngay trong `eventsUrl`, không qua biến `r = wr(…)` như Reviewer viết.

**Sửa (jsapi v11):**
- TRU-01:
  - `x.nests` đi qua biến, `?:`, `||`/`&&`/`??`, nhóm và dấu phẩy: `{entries: n}` với `n = t.map(…)` cho 3 trường `entries.*`; `{metadata: a}` với `a = r ? _D(r) : void 0` cho 17 trường `metadata.*`.
  - Hàm dựng query string từ các entry của tham số object (`Object.entries(e)`, `Object.keys`, `new URLSearchParams(e)`, `for…in`) thì các khoá của object được truyền vào là query (`queryParam`).
  - `url(...) + query(...)`: query ở vế phải gắn vào endpoint mà vế trái tạo ra (`queryTail`).
- TRU-02:
  - `baseFor`: base mà path bắt đầu bằng path của nó, hoặc chung đoạn đầu kiểu gateway (`/hub`; không tính `/api`, `/v1`, `/auth`…), thì chỉ giữ origin đó, không nối thêm các ứng viên khác. OpenAPI chỉ giữ base `…/openapi` khi có. Các trường hợp còn lại vẫn là danh sách ứng viên như cũ.
  - `Factory` (`modules.go`): hàm trả về bảng method của một client (`l(e)` với 16 method, export hay không). URL template được giải (`/v1/auth/sessions/refresh${r}`, `/v1/auth/social/${e}/start`). Export ghi factory của nó; lời gọi cục bộ `a(e.CLIENT_API_URL)` ghi setting cho factory. `linkModules` áp setting cho mọi method của factory.
- TRU-03:
  - Khung của helper (`POST …/permission-scopes/{}/{}`, `POST {}/mcps/{}/{}`) bị bỏ khi chỉ được tạo ở lời gọi trong thân helper, và mọi lời gọi tới helper đều làm URL đầy đủ hơn. Khung vẫn được giữ nếu có lời gọi để trống (`GE(a, b)`).
  - Lời gọi tới hàm dựng client (`Rr(cfg)`: lời gọi request nằm trong method mà nó trả về) không tạo request, nên không được tính.
  - `endpoints.Build`: endpoint không method gộp vào bản có method cùng path, kể cả khi bản đó có `{}` ở đầu (`/auth/exchange` → `POST {}/auth/exchange`).
- TRU-04:
  - `docs.go`: base để người đọc tự điền (`{base}/…`, `$BASE_URL/…`, `https://<host>/…`) hoặc host bịa (`example.com`, `.test`, `localhost`) không còn là một phần của path. Version và mã mẫu (`1.0.0`, `SKU-001`) thành `{}`.
  - `mergeDocs`: dòng `doc` trùng method và path với endpoint lấy từ code (kể cả `{}` ở đầu) thì gộp vào endpoint đó. Path tài liệu viết tắt (ít nhất hai đoạn có tên ở cuối) thì gộp vào bản đầy đủ có cùng đuôi.
- TRU-05:
  - `urlBuilder` chỉ nhận hàm ghép base mà URL của một request gọi tới (`fetch(r(t)+o)`, `builderVisitor`) hoặc có base trông như của API. `wt(e)` ghép basepath của router thì tạo route.
  - `navigation` vẫn do `jsapi` phát ra (frontier cần), nhưng `endpoints.Build` bỏ những cái ngoài scope hoặc không giống API (`jsapi.APILike`).
  - `split`: host `{}` (`https://{}/x`) là base chưa biết, không phải bên thứ ba.
  - Header có giá trị là số, boolean, `null` hoặc `undefined` thì không được nhận (`{"X-AXIS": 48}` của Mermaid).

**Không làm, hoặc làm khác chỉ định:**
- `/conversations/{}/messages/send` vẫn chưa có method. URL đi qua `buildSendUrl` vào transport của AI SDK (`new P({api, prepareSendMessagesRequest})`), không có `method` nào trong code. Tôi không thêm luật suy `POST` từ chữ `/send` trong path, vì đó là đoán theo tên.
- `api.partner-api.example/open/product-catalog/…` được giữ, và gắn `third_party` vì nằm ngoài scope. Reviewer gọi đây là "tên miền ví dụ" nhưng không đưa bằng chứng; trang tài liệu dùng nó trong lệnh curl kèm `X-API-Key`. Bản viết tắt `/v1/public/feed/items/…` được gộp vào bản đầy đủ này.
- Route chat-core mà trang tài liệu nhắc tới (`/conversations…`, `/mcps/…`, `POST …/rating`) vẫn nằm trong `anon` với kind `doc`. Loại theo tiền tố path là vá theo tên. Tài liệu ghi `POST …/rating` còn SDK dùng `PUT`: sai lệch này là của chính tài liệu, đáng để người kiểm thử biết.

**Hiệu năng và nhiễu (1.996 file, gồm cả target-c):** 13,4 s so với 12,6 s của Đợt 20 (+6%). So từng dòng endpoint: bỏ 50 dòng, thêm 30 dòng. Phần bị bỏ gồm khung của helper (`https://{}` trong `next/dist`, `POST https://{}` của SDK growth), route của `wt()` và các dòng `doc` có `{}` ở đầu. Phần thêm vào gồm các dòng `doc` đã chuẩn hoá, và method thật của `Xe({url, method: "POST"})` trong SDK growth (trước đây ra không method). Không có endpoint mới nào trong `node_modules`.

**target-c.example, cùng lệnh (chạy lại từ đầu; 377 s, Đợt 20 là 470 s):**

| | Đợt 20 | Đợt 21 |
|---|---|---|
| Endpoint `anon` | 229 | 204 (bỏ 10 `navigation`, 3 route không method, 1 khung, 11 `doc` trùng) |
| Đúng một base / nhiều base / không base | 43 / 117 / 69 | 159 / 0 / 45 |
| OpenAPI có đúng `…/hub/openapi` | 0/51 | 51/51 |
| `/hub/*` của developer có đúng `https://api.target-c.example` | 0/57 | 57/57 |
| accounts (`/v1/auth`, `/v1/oauth`, `/v1/me`, `/v1/invite-links`) có một base | 13/21 | 21/21 |
| Có body / có query | 54 / 27 | 54 / 23 (4 query mất đều thuộc `navigation` đã bỏ) |
| Endpoint không method | 3 | 0 |
| `historical.jsonl` | 29 | 27 (bỏ `/auth/exchange` không method và khung MCP) |
| Header client | `Authorization`, `X-AXIS`, `X-CSRF-Token`, `cookie` | `Authorization`, `X-CSRF-Token`, `cookie` |
| Request / script (`runs.jsonl`) | 63 / 443 | 66 / 443 |

**Script nghiệm thu (`check21.py`):** 15/21 khẳng định qua, 6 trượt (bản báo cáo đầu ghi nhầm thành "21 qua"). Ba khẳng định trượt là bản gốc sai schema hoặc sai dữ liệu, và bản đã chỉnh của chúng đều qua. Ba khẳng định còn lại trượt có chủ đích: `messages/send`, `api.partner-api.example` và `POST …/rating`, đã giải thích ở trên.

**Gate:** unit test `round21_test.go` (jsapi, endpoints); `go test -race ./...` qua; `regress.sh -j 3` qua cả 16 gate (842 s).

## 16. Đợt 21B: FIN-01 → FIN-06 (2026-11-10)

Mọi mục của đánh giá độc lập (Phần 2, Đợt 21B) đều có thật trên output Đợt 21. Script nghiệm thu ở mục 2.7 chạy trên output đó trượt cả 14/14 khẳng định. Riêng 4 khẳng định thì sai so với dữ liệu hoặc schema, nên được kiểm thêm bằng bản đã chỉnh (`check21b.py` in cả bản gốc lẫn bản đã chỉnh):
- FIN-02 đòi có `POST {}/customer-profiles/Order`, nhưng path này không có trong script nào (kể cả `sdk-0.0.15.js`). Bản chỉnh kiểm `sdk-0.0.15.js` có trong `anon` và `POST {}/customer-profiles` có trong catalog.
- FIN-05b và FIN-06b tra `historical.jsonl` theo trường `url`, nhưng dòng của file này có `path`, không có `url`. Bản gốc vì vậy luôn trượt.
- FIN-06a đòi không còn `/api/revalidate`. Trang `operations-*.js` tự ghi `POST /api/revalidate?path=…` (không có host). Phần sai thật chỉ là nguồn `routing-*.js` (`my-space.example.com`), và nguồn đó đã bị bỏ.
- FIN-06a cho `/console-api`: script không có base tương đối `/console-api` như Reviewer giả định. Đây là tiền tố của client: `Ty = W.sameOriginApi ? new Sy("/console-api") : Cy("/console")`, với `Cy(e) = new Sy(`${W.apiBaseUrl}${e}`)`.

**Sửa (jsapi v13):**
- FIN-01 (`docs.go`):
  - Đọc từng lệnh curl (`shellWords`, nối dòng bằng `\`). Method lấy từ `-X`; nếu không có thì `-I` → HEAD, `-T` → PUT, `-G` hoặc không có data → GET, có data → POST.
  - URL bắt đầu bằng scheme, `$VAR`, `{placeholder}` hoặc `/`.
  - Query lấy từ `?k=` và từ `--data-urlencode`/`-d` khi có `-G`. Body lấy từ khoá JSON của `-d` (lồng tới hai cấp, phần tử đầu của mảng object), từ cặp `k=v`, và từ `-F`.
  - `export VAR="https://…"` của cùng tài liệu thành `Endpoint.Base`, trừ host dev, host ví dụ và host placeholder (`balance-service.dev.internal.example` không được dùng).
  - Query trong bảng và dòng `METHOD /path?…` được giữ.
  - Khối code ```ts/js (hoặc chuỗi chỉ gồm code có `fetch(`) được đọc bằng chính extractor (`extract(…, nested)`).
  - Cùng khoá thì gộp query, body và base vào nhau.
  - UUID mẫu trong path thành `{}`.
- FIN-01 (`endpoints.Build`): base của tài liệu (`docBases`) là base của endpoint. Lời gọi ví dụ có giá trị thật trong path (`content_types/page`, `spaces/brand-car`) được gộp vào template mà tài liệu ghi (`instance`).
- FIN-02 (`resolve.Static`): URL `.js` tuyệt đối viết ở bất cứ đâu trong text (`js-url`). Policy của tầng gọi (scope) quyết định có tải hay không; URL ngoài scope không tốn `-resolve-max`.
- FIN-03: biến `new FormData`/`URLSearchParams` cho ra các khoá `.append`/`.set` của nó trong `keys()`, kể cả khi được trả về từ hàm (`LT`).
- FIN-04: `keys()` và `nests()` đi qua mảng (`{files: [{…}]}`).
- FIN-05:
  - Lời gọi method qua object (`DD.appMembers.changeRole(…)`, `n.conversations.sendNote(…)`) dùng hàm của method cùng tên. Điều kiện: script định nghĩa đúng một hàm cho tên đó (method viết tắt, `name: fn`, getter `() => sE` của namespace module, method của class), tên là camelCase, và đối tượng gọi không phải global của nền tảng.
  - Đây là ghép theo tên nên có thể sai khi hai object khác nhau có method trùng tên mà chỉ một cái được định nghĩa trong script.
  - `propKey` đọc được tên method viết tắt, vốn trước đây bị `factoryOf`/`factoryMethod` bỏ qua.
- FIN-06:
  - Tài liệu ghi host ví dụ (`example.com`, …) thì endpoint đó bị bỏ hẳn, không chỉ bỏ host.
  - Tiền tố client là path của origin trang (`new Sy("/console-api")`) và không client nào đặt nó sau một base tính toán (`ownPre`/`basedPre`), thì URL dưới tiền tố đó là URL đầy đủ, không cần base (`Client: false`). `/console/…` (sau `${apiBaseUrl}`) vẫn nhận base của origin. `/api/…` có cả hai cách gọi nên vẫn giữ ứng viên.
  - `baseFor`: base tương đối mà path bắt đầu bằng nó thì trả về không base.
  - `archive.weak` thay `generic` khi xếp lớp `low`: lời gọi có method và có đoạn tên riêng (`GET /conversations`) không còn bị xếp `low`. `generic()` dùng để so khớp thì giữ nguyên.

**Hiệu năng và nhiễu (1.996 file):** 13,2–13,4 s, bằng Đợt 21. So với Đợt 21: thêm 47 dòng, bỏ 3 dòng, tất cả nằm trong tài liệu của target-c (curl, khối code, query). Ba dòng bị bỏ là `/api/revalidate` của host ví dụ. Không có dòng mới nào trong `node_modules`.

**target-c.example, cùng lệnh (chạy lại từ đầu; 329 s):**

| | Đợt 21 | Đợt 21B |
|---|---|---|
| Endpoint `anon` | 204 | 216 (+8 của `sdk-0.0.15.js`, +4 `doc` từ curl không có `-X`) |
| Có body / có query | 54 / 23 | 68 / 32 |
| `doc` có query hoặc body | 0/42 | 16/46 |
| Đúng một base / không base / nhiều base | 159 / 45 / 0 | 169 / 47 / 0 |
| Script `anon` | 443 | 444 (`cdn.target-c.example/media/martech/sdk-0.0.15.js`) |
| `historical.jsonl` | 27 (12 `historical`, 11 `in_current_code`, 4 `low`) | 19 (5 `historical`, 14 `in_current_code`, 0 `low`) |

`historical.jsonl` giảm vì 8 endpoint của SDK growth (`customer-profiles`, snowplow `tp2`, `/i`) giờ đã có trong code hôm nay (`sdk-0.0.15.js` trong `anon`). 4 dòng `/conversations` chuyển từ `low` sang `in_current_code`.

**Script nghiệm thu (`check21b.py`):** bản gốc 10/14 qua; 4 khẳng định trượt là 4 khẳng định sai đã nêu ở trên, và cả 4 bản đã chỉnh đều qua. `check21.py` (Đợt 21) vẫn 15/21 như trước.

**Gate:** unit test `round21_test.go` (jsapi, endpoints), `static_test.go` (`js-url`), `round19_test.go` (`weak`); `go test -race ./...` qua; `regress.sh -j 3` qua cả 16 gate (822 s).

## 17. Đợt 21C: FIN-21C, bốn tồn đọng của 21B, sửa offline (2026-11-11)

Reviewer chấm 21B 9,4/10 và nêu 4 tồn đọng, đều đã đối chiếu với output thật trước khi sửa. Đợt 16 → 21B được commit trước (`565cc59`) để tách mốc. jsapi lên v14. Toàn bộ kiểm chứng làm offline trên 444 script đã có (`jsharvest endpoints -o output -target target-c.example`, 2,6 s khi dựng lại cache `static/` từ đầu), không gửi request nào tới target-c.

- **(1) `methodOf` không còn ghép thuần theo tên** (`helpers.go`):
  - Trước tiên giải chính xác chuỗi thuộc tính qua hằng số (`memberValue`/`objectOf`): `DD.appMembers.changeRole`, với `DD = {appMembers: QT}` và `QT = t({changeRole: () => sE})` (namespace của esbuild: object mà mọi giá trị là getter không tham số). Giải được thì dùng đúng hàm đó, không xét tên.
  - Không giải được (receiver là props của component) thì mới ghép theo tên, với cả ba điều kiện:
    1. Receiver có tên nhánh cha: `X.P.name`, hoặc biến không minify dài từ 3 ký tự.
    2. Số đối số khớp (`takes`): bằng số tham số, ít hơn chỉ khi các tham số còn lại có giá trị mặc định, tham số rest nhận mọi số.
    3. Tên `P` được gán cho đúng object hoặc class chứa method (`holds`): `P: {…}` trực tiếp, hoặc `P: c` / `P = …` / `this.P = …` mà giá trị do hàm trả về object đó tạo ra (`function Cr(){return {…}}`), kể cả qua `useMemo(() => Cr(…))`, `await`, `new C()`.
  - Có hai định nghĩa cùng thoả thì bỏ. Không còn điều kiện "script chỉ có một hàm tên đó": tên trùng giờ được phân biệt bằng nhánh cha.
  - Fixture cũ của `TestFormArraysMethods` chính là ca rủi ro (không có `DD`, không có gì nối `conversations` với `Cr`), nên đã sửa cho giống code thật. Test mới `TestMethodsJoinedByName` có các ca phủ định: receiver khác, không có nhánh cha, thừa hoặc thiếu đối số, hai object cùng giữ.
- **(2) `$SLINK_HOST` định nghĩa ở trang khác của cùng portal:**
  - `$VAR` không được `export` trong cùng tài liệu thì `Endpoint.Base` giữ tên `"$VAR"`.
  - `Result.DocVars` là các biến mà tài liệu của script `export` (chỉ biến có một giá trị). Biến định nghĩa ở chuỗi khác của cùng script được giải ngay trong `result()`.
  - `endpoints.Build` giải phần còn lại bằng `DocVars` của các script **cùng origin**. Hai giá trị khác nhau thì không gán base.
- **(3) curl minh hoạ route không tồn tại** (`noRoute`): bỏ lệnh curl khi một trong tối đa 3 dòng chú thích (`#`, `//`) ngay phía trên nói route, endpoint hoặc path không tồn tại (`route KHÔNG tồn tại`, `does not exist`, `unknown route`, `sai đường dẫn`…).
  - Chỉ dựa vào "404" thì không đủ: ví dụ ngay phía trên cũng là 404 ("route tồn tại, tài nguyên không"), và route đó có thật.
- **(4) tham số destructure** (`bindParams`): `async function Gr({baseUrl: e, body: n})` gắn mỗi tên vào thuộc tính cùng khoá của object literal mà lời gọi truyền vào.
  - Kèm theo: `x.object` có giới hạn 16 tầng, vì hai tham số có thể trỏ qua lại nhau. Lần chạy đầu trên target-c tràn stack, và unit test không bắt được lỗi này.

**target-c.example, dựng lại catalog offline từ cùng 444 script; so từng dòng với 21B:** 216 → 215 dòng. Chỉ đổi đúng 5 dòng, không dòng nào khác thay đổi:

| Dòng | 21B | 21C |
|---|---|---|
| `GET /cms/delivery/v1/spaces/{}/datasets/{}/entries` (ví dụ 404 trong `errors-*.js`) | có | bỏ |
| `DELETE /{}/shortlinks/{}` | không base | `https://api.target-c.example/slink-integration/api/v1` |
| `PUT /{}/shortlinks/{}` | không base | như trên |
| `POST {}/customer-profiles/webpush-reset` | body rỗng | `anonymous_id, device_id` |
| `POST {}/customer-profiles/webpush-subscription` | body rỗng | `anonymous_id, browser, browser_instance_id, device_id, hostname, subscription, user_id` |

`PUT /hub/console/v1/apps/{}/members/{}` vẫn có body `role`, giờ là nhờ giải chính xác chuỗi thuộc tính. `POST /conversations/{}/notes` (script trong archive) vẫn có `data, message`, qua `conversations: c`, `c = useMemo(() => Cr(…))`. `historical.jsonl` chưa dựng lại vì lệnh `archive` gửi request ra ngoài.

**Nhiễu (1.996 file):** so với 21B, bỏ 2 dòng (đúng ví dụ 404 ở trên, trong 2 bản `errors-*.js`), không thêm dòng nào.
Thời gian ngang 21B khi chạy xen kẽ hai bản trong cùng điều kiện tải: 21B 19,7 s / 16,1 s, 21C 19,9 s / 14,8 s. Máy đang có tải nền nên cả hai đều chậm hơn mức 13,2 s đo ở 21B.

**Gate:** unit test mới `TestMethodsJoinedByName`, `TestDestructuredParams`, `TestDocNoRoute`, `TestDocVarsElsewhere` (jsapi) và `TestDocVarsAcrossScripts` (endpoints); `regress.sh -j 3` qua cả 16 gate (841 s). Trong `go test -race ./...`, `replay.TestSenderConcurrency` trượt 1/8 lần trên code mới và qua 8/8 trên HEAD. Đợt này không động tới `replay`; test đó đo khoảng cách thời gian 25 ms dưới `-race`, nên là test chập chờn sẵn có và chưa được sửa.

## 18. Đợt 22A: QAL-01 → QAL-05, chất lượng catalog tĩnh (2026-11-11)

Theo đánh giá độc lập Phần 3, Chốt 1. Bước 0 (commit FIN-21C `940a080`, `TestSenderConcurrency` kiểm khoảng trải của cả đoàn request) làm trước. jsapi lên v15. Mọi kiểm chứng đều offline: dựng lại catalog từ script có sẵn trong `output/` (`jsharvest endpoints [-role archive] [-scope fqdn]`), không gửi request nào tới target-c.example hay target-a.

**Đối chiếu trước khi sửa:** cả 9 khiếm khuyết đều có thật trong dữ liệu (B1: 9 nhóm, 12 dòng thừa; B6: 28 dòng không method trên target-a). Riêng FP1: câu "space app" mà Reviewer trích nằm ở chỗ khác. Ngữ cảnh thật quanh `POST /api/revalidate` là "next: { revalidate: 60 }… cửa sổ ISR".

- **QAL-01a (B3a):** `fetch(e.url, {headers: e.headers})`: `readCall` đọc `headers` trong object options riêng của fetch (`l.extra`) khi các tham số đã được gắn. Cả 6 endpoint `customer-profiles` có `x-api-key`.
- **QAL-01b (B6):** `this.x(…)`:
  - `callVisitor` giữ ngăn xếp hàm (`fnStack`). `methodVisitor` ghi object hoặc class sở hữu mỗi method (`ownerOf`), cùng object cha và tên khoá của nó (`objParent`/`objKey`).
  - `thisMethod` tra theo thứ tự: chính object đó; component (`methods`, object chứa hook vòng đời); rồi định nghĩa duy nhất trong mọi khối `methods: {…}` của script (mixin), trừ các tên chung (`get`, `post`, `request`…).
  - **Khác đặc tả:** số đối số được phép *ít hơn* số tham số, vì `genBySection(e,n,t,o)` được gọi với 3 đối số, `o` dùng theo kiểu `o||…`. Đòi `takes` khớp đúng thì ca này bị loại.
  - `clientNameRe` có thêm `gateway` (`this.$gateway`).
  - `keys()` của biến cục bộ có thêm các thuộc tính gán sau đó (`setOn`: `r.start_index = e`).
  - `fetchLike` không coi `this.fetchComponent` (method do app định nghĩa) là fetch. Nếu coi như vậy, route `/_error` của Next sẽ thành endpoint.
- **QAL-01c (B2):**
  - `fromCallers`: với `e.apiBase` (tên có dạng base) mà `e` là tham số chưa gắn, lấy giá trị từ tối đa 4 nơi gọi. Nơi nào cũng phải giải được và có phần path cố định. Destructure (`let {apiBase: t} = e`, `destructFrom`) cũng được hỗ trợ.
  - Hàm dựng URL `r = e => ${t}${e}` có base dạng `{}/api/v1` thì tiền tố đó được ghép vào cả nhánh `sum.urls` lẫn nhánh `generic` (`builderPath`, `helperCall.pre`).
  - `calleeFn` (dùng trong `evalCall`) giải được method (`methodOf`) và hàm do nơi gọi truyền qua thuộc tính của tham số (`givenFn`: `e.buildSendUrl`). Bước đi qua method không tính vào `maxCallDepth` (vẫn là 2).
  - SSE: hàm có dùng `text/event-stream` và đưa tham số làm đối số đầu của một lời gọi (`sseParam`); lời gọi tới nó là `GET`, kind `sse`.
  - Transport: thuộc tính `prepareSendMessagesRequest` là `POST`, kind `transport`, lấy body từ object mà callback trả về.
  - Hàm dựng query (`queryParam`) cho kết quả không biết thì vẫn là query.
- **QAL-02 (FP2, FP3):**
  - Biểu thức URL có một giá trị khớp mẫu collector (`/com.snowplowanalytics.snowplow/`, `/(g|j|mp)/collect`) thì mọi giá trị của nó mang `NoInheritBase` và `Collector`. `Build` không cho chúng mượn base, và đánh dấu `third_party`.
  - `{}/x.json` (không phải file đặc tả) mang `NoInheritBase`. File cấu hình (`config`/`manifest`/`settings`/`env`) bị bỏ.
- **QAL-03:** `ParamSpec{name, in, position, type, values, required}` (`params.go`):
  - AST: `keys()` ghi kiểu và giá trị của từng trường (`keyInfo`, làm mới ở mỗi lời gọi) qua `typeOf` (literal, `!0`, mảng/`.map`, object, bảng tra `{day:"daily"}[x]`, hằng). `required` là hằng cố định. Trường cha `files` (array) được thêm cùng `files.x`.
  - Path: tên lấy từ các biểu thức chèn trong template (`tenantId`, `e.appSlug`, `encodeURIComponent(id)`), bỏ tên do minifier tạo ra. Khi code không cho tên thì dùng `by-slug/{}`.
  - OpenAPI: `parameters` và schema (`enum`/`default`/`example`, `required`).
  - Tài liệu: giá trị JSON của `curl -d` và khối `http`, header của `-H`.
  - Gộp đơn điệu (`MergeParams`); `archive.HistLine` có `headers`, `params`, `confidence`.
- **QAL-04:**
  - `curl -H` / dòng header của khối `http`: chỉ giữ header xác thực và header riêng của API.
  - Khối ```` ```http ````: body nằm cùng khối hoặc ở khối dữ liệu kế dưới (không lấy nếu đoạn chữ ở giữa nói tới response, và không lấy cho GET). Với MDX đã biên dịch (mỗi khối một chuỗi), body nằm ở chuỗi kế tiếp (`pendingBody`).
  - Ô bảng `` `GET` / `POST /x` ``; câu "nằm dưới `{agentHub}/api/v1`" làm tiền tố cho bảng ngay sau nó.
  - Host placeholder (`<auth-host>`, `{agentHub}`) thành dấu `Base`. `Build` giải dấu này bằng `Settings` cùng origin (`settingNorm`: bỏ `VITE_`, `_BASE_URL`…; `open-platform` ↔ `openapi`), rồi toàn portal nếu khớp đúng một giá trị. `window.__ENV__ = {VITE_…}` giờ là setting.
  - Bảng `| prd | https://… |` (`DocProd`) cùng `export X=https://…-dev…` (`DocDev`): host production suy từ host dev bằng cách bỏ token môi trường, và chỉ nhận khi bảng có đúng host đó (`ProdOf`).
  - Dòng tài liệu không có base nhận base chung của ít nhất 2 dòng anh em có cùng hai đoạn đầu (`siblingBases`).
  - FP1: route quy ước của app Next của khách (`/api/revalidate|draft|preview…`) có ngữ cảnh Next/ISR trong ±800 ký tự thì bị bỏ.
  - `confidence`: `confirmed > spec > code > string > doc`.
- **QAL-05:**
  - `Origin`: gán cho lời gọi tương đối không có base, khi các script nguồn thuộc đúng một origin trong scope (bỏ qua `cdn.`/`static.`/`assets.`); `Bases` giữ nguyên là nil.
  - `canonicalMerge`: sau khi giải base và gộp dòng không method, và trước khi khớp traffic, gộp theo `METHOD host + path đầy đủ`. Bản đại diện là bản có đúng một base, base dài nhất; kind lấy hạng cao nhất trong nhóm.
  - Instance tài liệu gộp vào template thì mang theo cả header và params.

**Kết quả (offline):**

| | 21C | 22A |
|---|---|---|
| target-c `anon`: dòng | 215 | 205 (12 dòng gộp theo B1, bỏ FP1/FP3, `oauth/token` gộp) |
| …có `params` / `origin` / `confidence` | — | 126 / 4 / 205 (spec 51, code 106, doc 48) |
| target-a: dòng không method | 28 | 3 (`splitToChunk` không được định nghĩa trong bundle; 2 dòng `/maps/api/js`) |
| target-c `archive`: route chat | `/conversations/…` không method/body | `{}/api/v1/…`, `events` GET `sse`, `messages/send` POST `transport` + 8 trường |

Script nghiệm thu theo mục 3.6: 24/24. Lần chạy đầu được 22/24:
- B4 trượt vì bản đại diện ưu tiên code hơn base cụ thể nhất. Đã đổi thứ tự (URL vật lý vẫn như cũ).
- `by-slug/{}` không có tên trong code (`encodeURIComponent(e)`); đã thêm quy tắc `by-x/{}`.

**Nhiễu và hiệu năng (1.996 file):**
- Không có dòng nào thêm hoặc mất trong `node_modules` hay testbed. Mọi thay đổi nằm ở `output/target-a…` (+51/−25) và `output/target-c…` (+18/−11).
- Thời gian: chạy xen kẽ ba lượt với v14, máy có tải nền (load 2,6–3,4), v14 mất 12,9 / 13,1 / 13,9 s, 22A mất 14,6 / 15,1 / 15,4 s. 22A chậm hơn khoảng 13%; mốc ≤ 15 s chỉ đạt ở mức sát nút.
- Đã tối ưu: thoát sớm `methodOf` khi script không định nghĩa method tên đó, ghi nhớ kết quả theo receiver cố định, ghi nhớ `fromCallers`/`givenFn`, chỉ chạy `sseParam` khi script có `text/event-stream`, `baseProps` không gồm `url` đứng một mình, chỉ ghi `named` cho giá trị có thể là object.
- RSS đỉnh 179 MB.

**Gate:**
- Unit test: `round22_test.go` (jsapi: `TestThisMethods`, `TestHeadersFromCall`, `TestBaseFromCallersSSETransport`, `TestCollectorAndStaticJSON`, `TestParamSpecs`, `TestDocsContext`, `TestSlotNames`; endpoints: `TestCanonicalMergeAndOrigin`, `TestCollectorsAndConfigFiles`, `TestDocHosts`). `TestFormArraysMethods` đổi `DD.members` → `DD = {…, members: QT}` từ Đợt 21C; `TestDocCurl` kỳ vọng dấu `<hook-base>`.
- `go test -race ./...` qua; `regress.sh -j 3` qua cả 16 gate (844 s).

## 19. Đợt 22B: PIP-01 → PIP-04, CASE-22B-01 → CASE-22B-05 (2026-11-11)

Nguồn: đánh giá độc lập mục 2.4, 3.7A, 3.7B, 3.8. Không gửi gói tin nào tới target thật: mọi kiểm chứng chạy trên testbed hoặc trên dữ liệu có sẵn trong `output/`. Trước khi sửa, từng khiếm khuyết được đối chiếu với `output/target-d.example`: seed `:3016` lỗi `x509: certificate signed by unknown authority`; resolver `js-string` 69/69 thất bại; `run.json` ghi `requests: 82`, trong đó 80 dòng có tag `jsharvest`.

**CASE-22B-02, thư mục theo cổng:**
- `scope.TargetDir(u)` trả về `host` hoặc `host_port`. Giữ tên `host` khi cổng là cổng mặc định của scheme, hoặc khi host là loopback.
- `scope.NormalizeTargetArg` nhận cả ba cách viết: `x_3016`, `x:3016`, `https://x:3016`. `scope.TargetHost` cho hostname, dùng để dựng scope.
- Áp dụng cho:
  - `outDir`, `Escalate.OutHost`, `keepUnclaimed`, `Logins` của `-urls`;
  - profile của `login` và `crawl`;
  - mọi lệnh có `-target` (`endpoints`, `diff`, `export`, `replay`, `authz`, `monitor`, `mcp`).
- `archive` vẫn ghi theo hostname (`<host>/archive`) vì lịch sử là của host. `-target x:3016` thêm `x:3016` vào danh sách live check. `archive.hostOnly` hiểu cả `host_port`.
- **Lệch so với Bất biến #15:** `parallel-check.sh` dùng `a.jsh.test:8770` qua `-host-resolver-rules`, không phải loopback, nên thư mục giờ là `a.jsh.test_8770`. Gate đã được sửa theo; giữ tên trần cho host không phải loopback sẽ trái mục đích của CASE-22B-02.

**CASE-22B-03:**
- `resolve.moduleID` bỏ chuỗi là đối số của `__webpack_require__(…)`, `require(…)`, `__webpack_require__.bind(__webpack_require__, …)`, và khoá của module map (`"./x.js": function`, `=>`, số kiểu Browserify, method rút gọn `"./x.js"(…) {` của webpack 5), sau khi bỏ qua comment.
- Kết quả trên dữ liệu thật:
  - target-d: 69 → 2. Còn lại `webWorkerPath` và `codecsPath`, là cấu hình thật của loader.
  - target-a: 139 → 0. Đó là `"./af.js":522` của context map moment.js.
  - target-c: 7/7 và 5/5, không đổi.
- `run.json` có thêm `page_requests` và `internal_requests` (đếm theo tag `jsharvest`). `requests` giữ nguyên và các dòng nội bộ vẫn được ghi vào `requests.jsonl` (Bất biến #14).

**CASE-22B-01:**
- `internal/tlsutil`: `AIA.DialTLS` thay `DialContext` của TLS (HTTP/2 chỉ được đề nghị khi transport hỗ trợ).
  - Hostname được kiểm theo host của request, kể cả IP. `VerifyConnection` của Go không có ServerName khi kết nối tới IP, nên không dùng.
  - Gặp `UnknownAuthorityError` thì tải `caIssuers`: tối đa 2 tầng, 5 s mỗi lần, ≤ 64 KB, DER hoặc PEM, cache theo URL. Sau đó kiểm lại chuỗi tới root của hệ thống.
  - Không bao giờ dial tới địa chỉ private, loopback, link-local hay CGNAT (`tlsutil.Private`); địa chỉ được kiểm trước khi dial.
  - Host phải dùng AIA mới xác thực được thì được ghi vào `response.tls_incomplete_chain` của `requests.jsonl`.
- Áp dụng cho `httpcrawl` (không có proxy) và `replay.Sender`, tức cả live check của archive.
- `crawl -insecure`: engine HTTP, Chrome (`--ignore-certificate-errors`) và `archive -insecure`.
- CASE-22B-01c: `httpcrawl.Result.SeedError` được đặt khi trang đầu không có response.
  - Luôn ghi cảnh báo `seed request failed: …`; nếu lỗi là x509 thì gợi ý `-insecure`.
  - Với `-engine auto`, lỗi không phải DNS, connection refused hay timeout thì thử Chrome một lần (`escalatable`).
  - Vẫn không lấy được trang và không có script nào: không chạy archive, mã thoát 1.

**CASE-22B-04b:** `endpoints.Infra` đọc `requests.jsonl` (chỉ host trong scope) và ghi vào `intel.json`:
- `server_hints`: `{name, origins, evidence}` lấy từ `Server`, `X-Powered-By`, body lỗi mặc định của NestJS và trang `<pre>Cannot GET` của Express.
- `security_notes`:
  - `cors_wildcard_with_credentials`;
  - `cors_credentials_for_origin` thay cho `cors_reflected_origin_with_credentials`. Nhìn thụ động không phân biệt được allowlist với phản chiếu, vì không gửi Origin lạ;
  - `tls_incomplete_chain`.
- `intel.json` được ghi cả khi không có endpoint nào.
- **Lệch:** `server_hints` là danh sách object có origin, không phải `[]string`, vì một target theo rdn có nhiều server.
- Trên `output/target-d.example`: Express và NestJS ở `:3016`, `cors_wildcard_with_credentials` (81 response). target-c chỉ có Next.js và cloudflare, target-a chỉ có cloudflare; không có note nào.

**CASE-22B-05:**
- **Lệch:** explore đã bật `Page.setInterceptFileChooserDialog` từ 4.6.
- Lỗi thật: input `webkitdirectory` tạo tại chỗ nhận một file thì không có file nào được gán và `change` không bao giờ chạy. Giờ input chọn thư mục (`folderInput`, đọc `this.webkitdirectory` qua `jsharvest-internal`) nhận thư mục upload tạm, chứa hai file vô hại.
- Ca mới trong explore-app: "folder picker made on the spot", `GET /api/x/folder-picked`.

**PIP-01:**
- `endpoints.EnrichFromArchive` chạy trong `Catalog`, nên `jsharvest endpoints` dựng lại offline vẫn ra cùng kết quả.
- Nguồn là `archive/endpoints.jsonl`, chỉ các dòng code/spec có method.
- **Lệch:** không dùng `historical.jsonl`. Khi archive chạy lại, các dòng đã có trong catalog hiện tại bị `classify` bỏ khỏi `historical`, nên sẽ không còn gì để bổ sung.
- Quy tắc ghép:
  - path giống nhau, không tính `{}` đầu;
  - host giống nhau hoặc chưa biết;
  - method giống nhau, hoặc một bên chưa có (khi chưa có thì bên archive chỉ được có một method).
- Bổ sung method, query, body, header và params. Thêm `enriched_from: ["archive"]`; dòng doc/string được nâng lên `code`. `Bases` và `historical.jsonl` không bị đổi.
- `http.go` ghi lại catalog sau escalate, sau SPA boot và sau archive.
- target-c (offline): 12 dòng tài liệu chat được bổ sung, ví dụ `messages/send` có 8 trường body. `rating` bị bỏ qua vì tài liệu ghi POST còn code ghi PUT.

**PIP-02:** trang mà `httpcrawl` tải về là JSON (2xx–4xx; không phải OpenAPI hay file cấu hình tĩnh) được ghi với `resource_type: Fetch`, nên catalog thấy nó là `both`/`confirmed`. Body JSON được giữ (`RecordBody`).

**PIP-03:**
- `frontier.SpecPaths` gồm 7 đường dẫn. Hỏi seed origin, và tối đa 5 API host trong scope do code chỉ ra (`frontier.APIOrigins`, không gồm `cdn.`/`static.`/`assets.`).
  - Engine HTTP hỏi seed trong `probe`; API host được hỏi sau khi hết trang.
  - Engine CDP dùng `specFiles` qua trang (`-depth` hoặc `-explore`). Origin khác được hỏi không kèm credential.
- Tài liệu OpenAPI được lưu với tag `openapi`; cấu hình OIDC được lưu với tag `openapi`+`oidc` và đọc bằng `jsapi.ExtractOIDC`.
- OpenAPI không có `servers` thì lấy origin của chính tài liệu làm base.
- `canonHost` giữ cổng không mặc định ở cả dòng có host lẫn dòng có base. Đây là sửa lỗi của 22A: trước đây hai dòng cùng URL trên cổng 8770 không được gộp.
- `-probe` áp dụng cho cả hai engine.

**PIP-04:**
- `crawl -spa-boot` (mặc định tắt, chỉ với `-engine auto`). Khi engine HTTP thấy SPA mà không có endpoint nào được quan sát, `engine.SPABoot` mở mỗi SPA origin một lần bằng `RunRecord`: tối đa 3 origin, mỗi lần 8 s, guard bật, `-depth 0`.
- `run.json` có `spa_boot`.

**Gate 17 `testbed/pipeline-check.sh`:**
- Fixture `pipe-app` có ba host: `app.jsh.test`, `api.jsh.test` (NestJS) và `spa.jsh.test`.
- Phần 1 crawl `app.jsh.test`, có `reqcheck` cho cả hai host.
- Phần 2 kiểm làm giàu từ archive bằng file fixture, rồi dựng lại offline với `-target` ở cả ba cách viết. Gate xác nhận `historical.jsonl` không đổi và server không nhận thêm request nào.
- Phần 3 chạy `spa.jsh.test` không có và có `-spa-boot`.
- `bin/testbed pipecheck` kiểm (a)–(f).
- Unit test:
  - `tlsutil/aia_test.go`: chuỗi thật đi qua AIA dạng DER và PEM; AIA trỏ tới loopback bị chặn; chuỗi giả, chứng chỉ tự ký và body quá lớn bị từ chối; sai hostname bị từ chối; HTTP/2 vẫn dùng được.
  - `resolve/vrp_test.go`, `endpoints/round22b_test.go`, `httpcrawl/round22b_test.go`, `jsapi/oidc_test.go`.
  - `engine/http_test.go`: seed tự ký thì exit 1 và không chạy archive; với `-insecure` thì crawl được.

## 20. Đợt 23-Offline: POL-22B, VER-01 → VER-04 (2026-11-11)

Nguồn: đánh giá độc lập mục 3.8B, 3.9–3.11. Chưa có gói tin nào tới target thật: `verify` chỉ được chạy với `-dry-run` trên `output/`, và chạy thật trên testbed.

**POL-22B:**
- `NormalizeTargetArg("x:443")` (không có scheme), cũng như `:80`, cho thư mục `x`.
- `AIA.Incomplete` được khoá theo `host:port`. `Verify` không có cổng thì coi là 443. `httpcrawl` hỏi bằng `host:port`, nên hai cổng của một host là hai server.

**VER-01, `internal/verify/draft.go`:**
- `Drafts(Inputs)` lấy dữ liệu từ `endpoints.jsonl` và `intel.json`; thêm `archive/historical.jsonl` khi có `-include-historical`, bỏ lớp `low`.
- Thứ tự giải URL:
  - `Base`;
  - một base duy nhất (cắt phần path trùng với path của base);
  - `Host`;
  - `Origin`;
  - nhiều base: mỗi base một `Candidates`;
  - không có base: tối đa 4 base trong scope của `intel.json`, ngắn nhất trước.
- **Lệch:** base tương đối (`/api-gateway` của target-a) được giải theo origin duy nhất của các script nguồn (`scriptOrigin`). Không làm vậy thì 386/389 dòng của target-a không có URL.
- Điền `{}`:
  - lấy từ sample quan sát được khi có;
  - không có thì theo `ParamSpec` của path: id/uuid/guid cho UUID; slug/code/name/key, hoặc đoạn đứng sau `by-slug`, cho `sample-item`; số cho `1`;
  - không có tên mà đoạn trước là danh từ số nhiều (`/tenants/{}`) thì dùng UUID.
- Query và body: dùng `Values[0]`, không có thì dùng mẫu theo kiểu, rồi theo tên (bool, email…). Khoá có dấu chấm thành cây JSON; cha có kiểu `array` thì phần tử con được bọc trong `[ {…} ]`.
- Header client lấy từ `intel.json`, không gồm cookie; giá trị `{}` thay bằng `sample`. Phần này không tính vào tier, vì đó là định danh chứ không phải tham số.
- Tier:
  - `ready`: không có giá trị mẫu nào;
  - `parameterized`;
  - `incomplete`: không có method, hoặc không có đúng một URL.
- `Draft.Raw` là HTTP/1.1 đọc được bằng `http.ReadRequest`.
- `WriteDrafts`:
  - ghi `drafts/` (0700/0600) kèm `index.json` (file hoặc lý do bị bỏ qua);
  - chỉ thay thư mục có `index.json` của chính nó;
  - bỏ dòng `doc` trừ khi có `-include-docs` hoặc `verify/verify.json` ghi `verified_alive`/`resource_404` (`AliveKeys`);
  - bỏ third party.

**`export -drafts [-include-docs]`:**
- Viết thêm vào `<dest>/drafts/`.
- Vẫn chạy khi không có `requests.jsonl`, và khi không có run nào có flow (`export.ErrNoFlows`).
- `export` thay được thư mục chỉ chứa `drafts/` của chính nó (`draftsOnly`).
- Không có `-drafts` thì hành vi giữ nguyên (Bất biến #12).

**VER-02/03, `internal/verify/verify.go`, `sig.go`:**
- `GatewayPrefix`: tối đa 2 đoạn cố định đầu, không lấy hết các đoạn, dừng ở giá trị mẫu. Mỗi origin có tối đa 12 prefix; quá thì dùng `/`.
- Canary là `GET <origin><prefix>/__jsharvest_canary_<8 hex>`, hỏi một lần cho mỗi prefix.
- `Sig` gồm status, media type, rồi:
  - với JSON: skeleton (đường dẫn khoá kèm kiểu, list tính một phần tử; mọi giá trị đều bỏ, nên `request_id`/`trace_id` không làm khác) và mã lỗi ổn định (`code`/`error_code`/`error`, dạng định danh ≤ 48 ký tự);
  - với HTML: shell (title và script);
  - còn lại: số từ, cho lệch ±15%.
- Verdict:
  - giống canary và 401/403: `auth_wall_opaque`, trừ khi OPTIONS của endpoint khác OPTIONS của canary (status hoặc `Allow`), khi đó là `verified_alive`;
  - giống canary: `dead_or_fp`;
  - 2xx: `verified_alive`;
  - 405: `verified_alive` (method lấy từ `Allow`);
  - 400/415/422: `verified_alive` (`MissingParams`: `missing`/`required`, `errors[].field`, `loc` của FastAPI, thông báo `x should|must|is required` của class-validator);
  - 401/403 khác canary: `verified_alive`;
  - 404 khác canary: `resource_404`;
  - 5xx: `server_error`;
  - 3xx khác canary: `verified_alive`.
- Ngoài ra có thêm `unreachable`, `skipped` và `planned` (dry-run).
- Nhiều candidate: thử lần lượt, dừng ở candidate đầu tiên còn sống (`verified_base`).

**`jsharvest verify`:**
- Cờ: `-target`, `-o`, `-role`, `-profiles`, `-include-historical`, `-include-docs` (mặc định bật), `-scope`, cộng các cờ replay (`-allow-write`, `-read-allow`, `-allow-auth`, `-rate`, `-max`, `-proxy`, `-insecure`, `-hosts`, `-dry-run`, `-timeout`).
- Gửi qua `replay.Sender`: chỉ tới host trong scope của các draft; ghim IP theo `Recorded` lấy từ `archive.CrawlHosts`; có AIA; dừng khi gặp 429, challenge hoặc `Clear-Site-Data`.
- Không bao giờ gửi:
  - third party;
  - `replay.Policy` trả Never (logout, luồng login khi chưa có `-allow-auth`);
  - URL mà `guard.Destructive` coi là phá huỷ;
  - request ghi khi chưa có `-allow-write`.
- Request ghi khi chưa có `-allow-write` được thay bằng một GET trên đúng path, nếu policy coi GET đó là đọc.
- `-dry-run` ghi kế hoạch vào `sent.jsonl` (không mở socket), `-max` không giới hạn trừ khi được đặt. Kết quả ghi vào `verify/verify.json`, `verify.md`, `drafts/` và `sent.jsonl`, tất cả 0600.
- `-profiles`: cookie của phiên đã lưu cho role đó (`replay.NewIdentity` + `Apply`).
- **Lệch:**
  - không có `-concurrency`: `verify` chạy lần lượt và `-rate` là trần;
  - định danh chỉ có cookie, chưa có header credential;
  - request ghi được thăm dò bằng GET chứ không bằng OPTIONS. OPTIONS thường được middleware CORS trả 204 cho mọi path, nên chỉ dùng sau auth wall.

**Gate 18 `testbed/verify-check.sh`:**
- Fixture `verify-app`: `catalog.jsonl` và `testbed/cmd/testbed/verifyapp.go`.
- Năm phần: `export -drafts` khi chưa có traffic, `verify -dry-run`, `verify` chỉ đọc, `export -drafts` sau khi verify, `verify -allow-write`.
- `bin/testbed verifycheck` kiểm:
  - 13 verdict;
  - UUID mẫu;
  - không có request ghi, logout, URL phá huỷ hay third party nào tới server;
  - đúng một POST khi có `-allow-write`, và đọc được `server_missing_params` = `warehouse_id`;
  - mọi file `.http` đọc được và có quyền 0600.
- Unit test: `internal/verify/verify_test.go`.

**Offline trên dữ liệu thật (dry-run, 0 gói tin):**

| | target-c.example | admin.target-a.example |
|---|---|---|
| Draft (catalog + historical) | 223 (205 + 18) | 389 |
| Tier ready / parameterized / incomplete | 29 / 146 / 48 | 50 / 336 / 3 |
| Confidence | code 136, spec 51, doc 36 | code 389 |
| Canary (gateway prefix) | 17 | 13 |
| Request dự kiến | 228 (135 draft được lên kế hoạch, 88 bỏ qua: 60 là luồng login theo `replay.Policy`, 12 ngoài scope, phần còn lại là GET có động từ hoặc phá huỷ) | 380 (367 lên kế hoạch, 22 bỏ qua) |
| `export -drafts` | 167/205 file (ready 24, parameterized 131, incomplete 12 với candidate đầu) | 387/389 |

**Đợt 23B-Polish (POL-23-1 → POL-23-4, đánh giá độc lập mục 3.13):**
- **POL-23-1:** một candidate mà policy không gửi (base `…/hub/auth`) không còn kết thúc cả dòng: các candidate sau vẫn được thử. Nếu không candidate nào là route, dòng được ghi verdict "nói được nhiều nhất" (`verdictRank`); `skipped` chỉ khi không candidate nào được gửi.
  - Kết quả trên target-c: dòng bị bỏ vì luồng login giảm từ 60 xuống 22 (Reviewer ước 20). Cả 22 đều là auth, MFA, session hay token thật. Request dự kiến tăng từ 228 lên 266.
- **POL-23-2:**
  - Header mà giá trị là mẫu (`Bearer {}` thành `Bearer sample`) được ghi vào `Draft.SampleHeaders`. File `.http` giữ chúng để người dùng điền tay.
  - `verify` chạy không có identity thì bỏ các header đó khỏi request thăm dò và canary (`raw(target, bare)`). Có identity thì `replay.Apply` thay bằng giá trị thật.
  - **Lệch:** không dùng `replay.Apply(NoIdentity())` như đặc tả. Cách đó bỏ mọi header nhạy cảm, kể cả `client_id`/`client_secret` cố định mà app gửi cả khi chưa đăng nhập.
  - `Accept` mặc định chỉ thêm khi chưa có. Header response (`Access-Control-Allow-*`) và header do trình duyệt tự đặt (`Accept-Language`…) không có giá trị trong code thì không ghi.
  - `verify -role X` (khác anon) hoặc có phiên đã lưu: Identity lấy thêm header credential từ `requests.jsonl` của role (`roleEntries`).
- **POL-23-3:**
  - `AliveKeys` trả về `method path` → URL đã sống; `WriteDrafts` dùng URL đó thay cho `Candidates[0]`.
  - `verify.md` ghi "(probed via GET)" cho request ghi được thăm dò bằng GET.
- **POL-23-4:** phép kiểm nhịp của `parallel-check.sh` đổi sang: mỗi khoảng ≥ 0,1 s, và mỗi hai khoảng liền nhau ≥ 0,7 s.
  - **Lệch:** không dùng tổng khoảng trải như đặc tả. Với các khoảng 0,49 / 0,60 / 7,15 / 9,07 / 0,18 của lần trượt, các khoảng chờ tab rảnh (7–9 s) sẽ che cả một bộ điều tốc thả ba run đầu cùng lúc.
- Sau sửa: target-c 266 request dự kiến (173 lên kế hoạch, 50 bỏ qua), target-a 380 (367, 22). Không request nào mang `Bearer sample`, `Accept` trùng hay `Access-Control-*`. Unit test `TestCandidatesAndSampleHeaders`.

---

## 21. Đợt 24 & Hậu Kiểm 24D–24E (ENH-01 → ENH-13, P0-1 → P0-6, P1-1 → P1-6)

Tổng hợp từ lượt đối chiếu thực địa với `katana` trên 3 target thực tế (`portal.target-b.example`, `target-d.example:3016`, `target-d.example`) và đợt kiểm định độc lập sau Đợt 24 (`đánh giá độc lập` Mục 2–4). `jsapi.Version = 18`.

### 21.1. Sửa Lỗi Cốt Lõi `verify` & Giải Base (`ENH-01`, `ENH-02`, `ENH-10`, `ENH-13`, `P0-1`, `P0-4`, `P0-5`, `P1-1`)
- **Bảo toàn Host API khác miền (`ENH-01`, `P0-4`):**
  - `endpoints.Build` giữ nguyên `Host` và tách `Base` tương đối (`/fe/v1`) cho cả dòng `static` lẫn `both` khi `Observed` xác nhận host cross-origin (`api.target-b.example`), đồng thời gộp trùng khoá chính tắc `(Method, Host, fullPath)`.
  - `verify.lineOf` giải `Base`/`Bases` tương đối theo `Host` khi `Host != ""`. Fallback `uniqueIntelOriginForBase` chỉ khôi phục host cho dòng có `Observed` của catalog cũ trên đĩa (hoặc không có origin script) và tự tắt khi `Intel.Bases` cũng chứa `relBase` tương đối, tránh lái nhầm dòng `static` sang subdomain khác.
- **Nhận diện route ghi theo `(method, path)` (`ENH-02`, `P1-1`):**
  - `Sig.MethodScoped` nhận diện cả phản hồi `405` lẫn `404` mang chữ ký định tuyến theo method của Express (`text/html` `<pre>Cannot GET /...</pre>` không chứa `<script src=...>`) và NestJS/Fastify (JSON `"Cannot GET /..."`, `"Route GET:..."`).
  - Khi thăm dò chỉ đọc bằng `GET` trùng canary có `MethodScoped == true` (và `OPTIONS` không phân biệt được), `verify` chấm **`write_unverified`** thay vì `dead_or_fp`. Ngược lại, API trả JSON `404` đồng nhất (`{"error":"not_found"}`) giữ `MethodScoped == false` để route ghi chết vẫn ra `dead_or_fp`.
- **Helper dùng `baseURL` động của Axios & chặn base giả (`ENH-10`, `P0-1`, `P0-5`):**
  - `jsapi` nhận diện object cấu hình `{method, baseURL, endpoint}` (cùng helper truyền tiếp và lời gọi context-wrapper `fn(ctx, METHOD, PATH, body)` khi thoả điều kiện ngữ cảnh API trong `isContextWrapper`) thành `{}/path` (`Client: true`), nhưng **không** bật `dynBase` trên lời gọi generic, loại bỏ mọi đường dẫn endpoint khỏi `baseCands`, và siết `baseCandRe` chỉ khớp tiền tố cổng API thực sự (chặn triệt để base giả `/api-keys` cũng như các lời gọi `sendEvent`/`bus.emit`/`router.register`).
  - `endpoints.Build` không gán `pageOrigin` đè lên dòng `{}` khi origin đó đã có base quan sát được (`obsBaseByOrigin` / `obsSegByHost`), nhưng chỉ lan truyền từ các đường dẫn mang gốc API xác thực (`api`, `rest`, `graphql`, `v1`, `gateway`…), không bao giờ lấy thư mục tài nguyên tĩnh như `/locales`.
- **Canary cha 1-segment (`ENH-13`):** Khi một origin vượt trần `maxPrefixes` (`12`), prefix 2 đoạn (`/chat/tools`) ưu tiên dùng canary đã hiệu chuẩn của cha 1 đoạn (`/chat`) trước khi rơi về `/`.

### 21.2. Tham Số Thực, Redaction, Phạm Vi Crawl & Vận Hành Tab (`ENH-03..07`, `ENH-11`, `P0-2`, `P0-3`, `P1-5`, `P1-6`)
- **Giá trị tham số quan sát được & chặn lộ nhạy cảm (`ENH-03`, `P0-2`):**
  - `endpoints.Build` ghi tối đa 3 giá trị thực tế vào `ParamSpec.Values` nhưng lọc qua `SampleValueOK` (hợp nhất `traffic.Sensitive` + từ khoá PII `otp`, `pwd`, `pin`, `pass`, `cvv`, `email`, `phone`… và chặn mọi chuỗi `REDACTED_*` hoặc JWT `eyJ*`).
  - `verify.RedactDrafts` áp dụng `traffic.Redactor` lên toàn bộ URL, query, header và JSON/form body khi chạy `export -redact -drafts`.
  - Heuristic số trong `draft.go` khớp theo ranh giới từ (`splitIdentWords`), mặc định `country="us"`, `lang="en"`, không khớp nhầm `country`/`account` vào `"count"`.
- **Khoanh vùng `-page-scope` & redirect trang Seed (`ENH-04a`, `P0-3`):**
  - Cờ `-page-scope auto|fqdn|rdn` (mặc định `auto`): giữ trang thăm trong subdomain mục tiêu nhưng vẫn giữ `-scope rdn` cho script và API cross-origin; dòng `third_party` không kế thừa base của mục tiêu và không sinh file `.http`.
  - Trong `httpcrawl`, chuỗi redirect của trang Seed đầu tiên được miễn kiểm tra `pageScope` (vẫn kiểm `InScope` và `policy.Check`), tự mở rộng `pageScope` theo host đích hợp lệ; nếu Seed redirect ra ngoài `InScope`, ghi `SeedError` và thoát mã `1` (không leo thang Chrome, không trả `0` rỗng).
- **Nối module ESM nhiều chunk (`ENH-05`):** `jsapi/esm.go` trích xuất `import`/`export` chuẩn ES Module (kể cả bí danh minify `export { ly as e }` / `import { e as Z }` và `{ params: e }`) để `linkModules` nối tham số query/body xuyên suốt các chunk Vite/Rollup.
- **Tương tác UI & FileChooser (`ENH-06`, `ENH-07`, `ENH-11`):** `hitAt` dùng `elementsFromPoint` xuyên qua lớp phủ `pointer-events: none`; fallback script click bật `UserGesture: true` để mở `Page.fileChooserOpened`; `covered-for-good` tính vào `skipped` thay vì `errors`; thư mục mồi `webkitdirectory` có file nhị phân DICOM tối thiểu `IM000001` (`DICM`).
- **Thay tab treo & tách timeout Resolver (`ENH-04b`, `ENH-04c`, `P1-5`, `P1-6`):**
  - `resolver` áp dụng circuit-breaker 3 lần lỗi liên tiếp theo host và tách `AbortController` thành 2 giai đoạn: `8 s` cho TTFB/header và `25 s` cho đọc luồng body chunk/sourcemap lớn (`30 s` Go timeout).
  - `recycleTab` bảo vệ `e.tab`/`e.mainID` bằng `tabMu`, khởi tạo capture mới (`startOn`) trước khi đóng capture cũ (dừng lane an toàn nếu mở tab mới thất bại), và huỷ dứt điểm mọi listener trên tab cũ qua `listenCtx`/`popupWatch.stop`.

### 21.3. Header Basic, Hợp Đồng Auth OpenAPI, `roles` & Chuỗi Trần (`ENH-08`, `ENH-09`, `ENH-12`, `P1-2..P1-4`)
- **Lọc Basic giả nhưng giữ Basic gắn cứng (`ENH-08`, `P1-2`):** `eval` giải hằng `btoa(...)` sang Base64 thật; `isGenericBasicAuth` chỉ lọc bỏ bộ serializer tổng quát khi cả hai vế `username`/`password` đều động, giữ nguyên credential gắn cứng (`{username:"svc", password:"hunter2"}` → `Basic c3ZjOmh1bnRlcjI=`).
- **OpenAPI `security` (`ENH-09`, `P1-4`):** `ExtractOpenAPI` đọc `security` toàn cục và từng operation (`security: []` mở công khai) vào `Endpoint.Auth` (`bearer`, `basic`, `apiKey:<name>`), ép kiểu chuỗi an toàn khi thiếu `scheme` (không bao giờ sinh `"<nil>"`).
- **Ghép host trong `roles` (`P1-3`):** Khi `Endpoint.Bases` chứa cả base tuyệt đối khác miền lẫn base tương đối `/...`, `comparer.pair` cho phép khớp traffic trên cả host API lẫn host mục tiêu.
- **Chuỗi đường dẫn trần (`ENH-12`):** Dòng `confidence == "string"` không method mặc định được bỏ qua trong `verify` và `WriteDrafts` (`-include-strings` để bật; khớp SPA shell `200 text/html` thì ghi `client_route`).
- **Gate 19:** `testbed/crosscheck-check.sh` (`testbed/cmd/testbed/crosscheck.go`, 7 kịch bản đa host bao phủ toàn bộ `ENH-01..13`, `P0-1..5` và `P1-1..6`).

---

## 22. Đợt 25 — Tiền Xử Lý TypeScript/SFC Bằng esbuild, Thống Nhất Export.Via Đa Tầng & Kiểm Định Ground-Truth Độc Lập

Chuyển từ cách vá quy tắc theo từng target sang kiến trúc tổng quát hoá dựa trên mẫu số Ground-Truth độc lập đóng băng (`đánh giá độc lập` Đợt 25). `jsapi.Version = 20`.

### 22.1. Tập Ground-Truth Độc Lập Đóng Băng (`output/_groundtruth/groundtruth.json`)
- **Nguyên tắc:** Mẫu số không được sinh từ chính `jsapi` hay một bộ regex mô phỏng lại `jsapi`. Tệp `output/_groundtruth/groundtruth.json` (`sha256 = 14939e00ffa4d58292c4e5b512962fec7b115cdd247afa81629f787ab78a2e38`, quyền `0600`, chỉ lưu cục bộ, không commit) đóng băng 5 tập đối chiếu:
  - **`target-d.example` (`n8n@2.12.3`, `2.066` file JS + SourceMap):** trích xuất từ cây mã nguồn TypeScript chính thức của `n8n@2.12.3` (`packages/frontend/@n8n/rest-api-client` và `editor-ui`) đối chiếu với các chunk biên dịch — gồm **`286` route `active`** (có mặt trong bundle đang chạy) và **`6` route `sourcemap_only`** (chỉ còn trong `.js.map` do bị bundler tree-shake).
  - **`target-d.example_3016`:** đặc tả OpenAPI 3.0 `/api-json` (**`30` operation**).
  - **`portal.target-b.example`:** giao hợp `requests.jsonl` thực tế (`4`) và rà soát thủ công toàn bộ định nghĩa client trong bundle (`3`) = **`7` route `api.target-b.example`**.
  - **`admin.target-a.example` & `target-c.example`:** mỗi target **`30` route gán nhãn thủ công** đọc trực tiếp từ bundle gốc.

### 22.2. Tiền Xử Lý TypeScript/TSX & SFC Bằng `esbuild` (`Round 25A`, `jsapi.Version = 19`)
- **Đường nhanh 0 chi phí cho `.js` (`internal/jsapi/preprocess.go`, `ExtractSource`):** Mọi script JavaScript hợp lệ tiếp tục đi thẳng qua `js.Parse` mà không qua bước biến đổi nào.
- **Che SFC bảo toàn tuyệt đối số dòng (`maskSFC`, `extractSFCSpans`):** Với `.vue`/`.svelte`, mọi byte ngoài cặp `<script>...</script>` (trừ ký tự xuống dòng `'\n'`) được thay bằng `' '`, giữ nguyên tỷ lệ `1:1` cho số dòng gốc; nếu SFC có đồng thời `<script>` và `<script setup>` trùng tên import, từng khối được biên dịch độc lập rồi hợp nhất kết quả.
- **Hạ cấp cú pháp TypeScript/TSX bằng Go thuần (`transformTS`):** Khi `js.Parse` gặp lỗi cú pháp, `github.com/evanw/esbuild/pkg/api.Transform` (Go thuần, không CGo, giữ nguyên `go 1.25.4`, `TreeShakingFalse`, `Sourcemap: SourceMapExternal`, thử kèm `experimentalDecorators: true`) xoá bỏ hoàn toàn kiểu TS, decorator (`@Injectable`, `@Component`), `namespace`, `abstract`/`accessor`, generic arrow và JSX. Bộ giải mã VLQ (`esbuildLineMap`) ánh xạ ngược `(Line, Col)` và `Snippet` về đúng tệp `.ts`/`.tsx`/`.vue` ban đầu.
- **Giải hằng `enum` / `namespace` IIFE (`registerEnumIIFE`):** Nhận diện mẫu IIFE do `esbuild`/`tsc` sinh ra (`((E2) => { E2.Users = "/v1/users"; })(E || (E = {}))`) để bảo toàn giá trị hằng số `E.Users` trong biểu thức URL và tham số; giữ `ExtractLoose` làm lưới an toàn cuối cùng cho tệp lỗi cú pháp thật sự.

### 22.3. Tổng Quát Hoá `summary` Nội Cục, Thống Nhất `Export.Via` & Nhãn `source_only` (`Round 25B`, `jsapi.Version = 20`)
- **Tổng quát hoá `summary` nội cục (`internal/jsapi/helpers.go`, `jsapi.go`):**
  - `paramIndex` nhận diện cả `*js.BindingObject` và `*js.BindingArray`; `paramOrigin` và `argStringAt` (`depth <= 8`) truy ngược chuỗi biến cục bộ qua `x.destructFrom`, thuộc tính `*js.DotExpr` (`ctx.baseUrl`), phép gán thuộc tính sau khởi tạo trên biến cấu hình (`o.data = body`, `o.params = query`), và tách biểu thức `${ctx.baseUrl}${endpoint}` (`splitBaseAndPath`).
  - Lược bỏ nhánh phải của toán tử ba ngôi (`cond ? `?a=${cond}` : ""`) khi biến điều kiện gắn với tham số tuỳ chọn bị lược bỏ tại nơi gọi (`x.omitted`).
  - Giải hàm bậc cao trả về hàm helper hoặc bảng method client (`instantiateHOF`, `curriedHelper` kèm bộ lọc nhanh `hasHOFAPIArg` và bảng nhớ `x.msums`).
- **Một kiểu `jsapi.Export` thống nhất kèm chuỗi bắc cầu `Via` & `ReExport` (`internal/jsapi/modules.go`, `internal/endpoints/endpoints.go`):**
  - Không tạo kiểu export song song: `jsapi.Export` được mở rộng trực tiếp với `ParamURL`, `ParamMethod`, `Local`, `HasDynBase` và `Via *ExportVia` (ghi nhận lời gọi chuyển tiếp sang import khác cùng ánh xạ tham số `ArgMap`, hằng method/prefix/query/body), đi kèm `Result.ReExports` (`export * from`, `export { a as b } from`, `export { default as x } from`).
  - `endpoints.linkModules` định tuyến thống nhất trên cả 3 không gian module (**Bundler ID**, **HTTP ESM URL**, và **SourceMap `#<sourcePath>`** gồm alias `@/`, `~/`, gói monorepo `@scope/pkg` cùng phần mở rộng ngầm `.ts`/`.tsx`/`.vue`/`index.ts`) bằng DFS có tập `visited` chống vòng lặp và trần cứng `depth <= 8`; tự động dùng summary lá của chính `Export` khi module đích nằm ngoài tập thu thập.
- **Tách nhãn `source_only` cho endpoint bị tree-shake:**
  - `Endpoint.SourceOnly` được bật `true` khi mọi nguồn tĩnh của dòng đều mang tag `sourcemap` (không xuất hiện trong bất kỳ bundle JS đang chạy nào và không có `Observed`).
  - `verify` và `export -drafts` mặc định bỏ qua dòng `source_only` để không làm loãng ngân sách `-max 300`; cả hai lệnh hỗ trợ cờ `-include-source-only` khi người dùng muốn chủ động kiểm tra các endpoint cũ/ẩn còn sót trên server.

### 22.4. Gate Tự Động & Kết Quả Đối Chiếu Trên 5 Target (`Round 25C`)
- **Gate tự động Bất biến #9 (`bin/testbed perfgate` trong `testbed/endpoints-check.sh`):** Sinh tự động `2.000` tệp (`1.600 .js`, `300 .ts` chứa `@Injectable`/generics/`enum`/`Via`, `100 .vue` SFC) và kiểm tra cứng thời gian phân tích `<= 15,0 s` cùng RSS đỉnh `<= 500,0 MB` (`rusage.Maxrss`). Kết quả thực tế: **`3.896` endpoint trong `2,51 s`, RSS đỉnh `54,3 MB`**; đo trực tiếp bằng `/usr/bin/time -v` trên `2.066` tệp thực tế của `target-d.example`: **`9,80 s`**, RSS đỉnh **`402,9 MB`**.
- **Gate 19 mở rộng (`testbed/crosscheck-check.sh`, Kịch bản 8 — `tsmap.jsh.test`):** Kiểm chứng đầy đủ chuỗi 3 tầng `Via` (`workflows.api.ts -> index.ts -> helpers.ts -> http.ts`), barrel `export * from`, helper 2 tham số `get`/`post`, `streamRequest`, `.js.map` chứa decorator/generics/`enum` cùng route bị tree-shake `/v1/legacy-treeshaken` (`source_only: true`), `.vue` SFC giữ đúng `Line == 10`, `verify` mặc định bỏ qua `source_only`, và `verify -include-source-only` thăm dò `/rest/v1/legacy-treeshaken?dryRun=sample` ra `verified_alive`.
- **Đối chiếu Ground-Truth offline (0 gói tin mạng, chạy trong `unshare -rn`):**

| Target | Chỉ số | Baseline (`v18`) | Sau `25A` (`v19`) | Sau `25B/25C` (`v20`) |
|---|---|---|---|---|
| **`target-d.example`** (`n8n@2.12.3`, `2.066` file) | Active Recall (`286` GT) | `256/286` (`89,51%`, `FN=30`, `loose=3`) | `256/286` (`89,51%`, `FN=30`, `loose=0`) | **`286/286` (`100,00%`, `FN=0`, `loose=0`)** |
| | Tree-shaken `sourcemap_only` (`6` GT) | `0/6` gắn nhãn (`4` lẫn vào active) | `0/6` gắn nhãn (`6` lẫn vào active) | **`6/6` gắn `source_only: true` (`0` lẫn vào active)** |
| | Dòng catalog / `verify -dry-run` / `.http` lỗi | `309` / `224` req / `0/318` lỗi | `278` / `226` req / `0/320` lỗi | **`317` / `261` req (`< 300`) / `0/353` lỗi** |
| **`target-d.example_3016`** (`10` file) | Active Recall (`30` OpenAPI GT) | `30/30` (`100,00%`) | `30/30` (`100,00%`) | **`30/30` (`100,00%`)** (`37` req, `0/30` `.http` lỗi) |
| **`portal.target-b.example`** (`61` file) | Active Recall (`7` `api` GT) | `7/7` (`100,00%`) | `7/7` (`100,00%`) | **`7/7` (`100,00%`)** (`7` req, `0/47` `.http` lỗi) |
| **`admin.target-a.example`** (`4` file) | Active Recall (`30` GT) | `30/30` (`100,00%`) | `30/30` (`100,00%`) | **`30/30` (`100,00%`)** (`380` req, `0/387` `.http` lỗi) |
| **`target-c.example`** (`444` file) | Active Recall (`30` GT) | `30/30` (`100,00%`) | `30/30` (`100,00%`) | **`30/30` (`100,00%`)** (`224` req, `0/167` `.http` lỗi; thêm `5` dòng Firebase SDK `third_party: true`) |

---

## 23. Đợt 25D — Hậu Kiểm Độc Lập Đợt 25: Khoanh Vùng Provenance Base, Toạ Độ `Import`, Tối Ưu RSS/Perfgate & Kiểm Định Mù Held-Out + Live 5 Domain

Giải quyết triệt để các lỗi precision (`9` dòng gắn sai base `/rest` trên `target-d.example`), thiếu toạ độ nguồn (`line: 0` trên `Import`), mặt bằng kiểm định `perfgate` quá nhỏ (`~5 MB`), và thiếu tập Held-Out độc lập do đợt kiểm định độc lập chỉ ra sau Đợt 25. `jsapi.Version = 21`.

### 23.1. Khoanh Vùng Provenance Khi Kế Thừa Base & Giải Hằng Base Liên Module (`internal/jsapi`, `internal/endpoints`)
- **Truy vết nguồn gốc tham số base (`Endpoint.BaseKeys`, `Import.BaseKeys`):**
  - `baseKeysOf` ghi nhận nguồn gốc biểu thức đối số base tại nơi gọi (`client:<name>` cho biến đối tượng HTTP client khi `ep.Kind == "client"`, `prop:<key>` cho thuộc tính cấu hình như `ctx.baseUrl` hay `s.templatesHost`, `var:<name>` cho biến cục bộ, `param:<name>` cho tham số hàm chưa gắn giá trị).
  - Trong cả hai bước kế thừa base mặc định theo origin của `endpoints.Build` (`origins[ep]`) và bước lan truyền base quan sát được (`ENH-10`), một dòng `{}/...` **chỉ** được phép nhận base chính của ứng dụng (`/rest`) nếu `hints[ep]` khớp tường minh hoặc `hasPrimaryClientBaseKey(ep.baseKeys)` xác nhận đối số base là đối tượng client chính (`client:...`) hay tên cấu hình gốc tổng quát (`baseUrl`, `apiUrl`, `restEndpoint`… trong `genericBaseNormWords`). Các lời gọi truyền biến dịch vụ phụ (`s.templatesHost` → `prop:templatesHost`) hoặc tham số mở (`param:apiEndpoint`) giữ nguyên `Bases: []` (`{}/health`, `{}/templates/...`), không bị gán nhầm `/rest`.
- **Giải hằng chuỗi base xuất qua ES Module (`Result.ExportedConsts`, `Import.BaseArgExpr`):**
  - `modules.go` ghi nhận các hằng chuỗi cấp module được xuất qua `export { JN as a }` vào `ExportedConsts` và lưu tên biến đối số base của lời gọi import vào `Import.BaseArgExpr` (hỗ trợ cả `Export` có `ParamBase >= 0` và `Via` chuyển tiếp qua module trung gian).
  - Khi `linkModules` giải được hằng URL tuyệt đối khác miền (ví dụ `JN = "https://api.n8n.io/api"` cho `POST /accounts/onboarding`), dòng tạo ra được gắn trực tiếp `Bases: ["https://api.n8n.io/api"]` và đánh dấu `ThirdParty` khi khác miền mục tiêu, chặn hoàn toàn việc lọt vào tập route `/rest` của target.
- **Cắt nhánh rỗng giả của toán tử ba ngôi phân đoạn path (`x.supplied`):**
  - Ngoài `x.omitted`, `helpers.go` theo dõi tập tham số đã được truyền giá trị thật tại nơi gọi (`x.supplied`). Với biểu thức ba ngôi kiểu nối đoạn đường dẫn tuỳ chọn (`param ? \`/${param}\` : ""`) mà điều kiện là chính tham số đã được cung cấp đối số tại call-site (`runId` trong `DELETE /workflows/${id}/test-runs${runId ? \`/${runId}\` : ""}`), nhánh rỗng `""` bị loại bỏ, xoá bỏ route giả `DELETE /rest/workflows/{}/test-runs` mà vẫn giữ nguyên các biểu thức ba ngôi chọn 2 đường dẫn thật khác nhau.
- **Bảo toàn toạ độ nguồn & khoá tham số trung gian trên mọi lời gọi liên module (`Import.Line`, `Import.Col`, `Import.Snippet`, `extractExportKeys`):**
  - `esm.go` và `modules.go` gọi `x.locate(c.X)` khi ghi nhận `Import` (và ánh xạ ngược qua `esbuildLineMap` đối với `.ts`/`.tsx`/`.vue`), để `endpoints.linkModules` gán đúng `(Line, Col, Snippet)` cho dòng sinh ra từ liên kết module; đồng thời `resolveChain` truyền tiếp các khoá `QueryArg`/`BodyArg` đã xác định ở tầng `Via` trung gian xuống `applyLeaf` mà không tạo bản ghi `Static` trùng lặp. Số dòng code tĩnh có `line == 0` (`code_line0`) giảm từ **`179` xuống `0`** trên `target-d.example` và **`0` trên cả 5 target** (các mục `line == 0` còn lại chỉ là tài liệu đặc tả `kind == "openapi"`/`"oidc"` không gắn dòng JS).

### 23.2. Giảm Đỉnh RSS, Tăng Tốc Phân Tích TS/SFC & Nâng Cấp `perfgate` Thực Tế (`preprocess.go`, `endpoints.go`, `perfgate.go`)
- **Đi thẳng `transformTS` cho `.ts`/`.tsx` & bảng VLQ phẳng:** Các nguồn đã biết trước là TypeScript (`.ts`, `.tsx`, `.mts`, `.cts` hoặc `<script lang="ts">` trong SFC) chuyển thẳng vào `esbuild.Transform` mà không tốn lượt thử `js.Parse` thất bại trước (~`1.400` file trên `target-d.example`). Bộ đọc source map của `esbuild` quét trực tiếp trường byte `"mappings"` (`extractMappingsField`, bỏ `json.Unmarshal` toàn map) và nén bảng ánh xạ thành hai mảng phẳng `segs []vlqSeg` (`12 byte`/phần tử `int32`) + `lineOff []int32` thay vì cấp phát hàng nghìn slice con theo từng dòng.
- **Giới hạn đồng thời cho bundle đa MB (`heavySem`):** Trong `endpoints.Analyze`, các worker dùng chung semaphore `2` slot cho script có kích thước `>= 512 KB`, ngăn 8 goroutine giữ đồng thời nhiều cây AST khổng lồ trên heap.
- **Nâng cấp `bin/testbed perfgate` lên corpus `43,1 MB`:** Thay thế corpus nhỏ (`~5 MB`) bằng tập `2.000` tệp sát thực tế (`43,1 MB` tổng dung lượng, có kiểm sàn `>= 40,0 MB`, gồm `8` bundle lớn `~1,5 MB`, `24` bundle vừa `~250 KB`, `1.568` chunk `.js`, `300` tệp `.ts` và `100` tệp `.vue`). Kết quả đo tự động: **`3.896` endpoint trong `3,91 s`, RSS đỉnh `245,3 MB`** (trần gate: `<= 15,0 s`, `<= 500,0 MB`).

### 23.3. Kết Quả Kiểm Định Offline (`groundtruth_v2`), Kiểm Định Mù Held-Out & Benchmark Live 5 Domain
- **Tập Ground-Truth v2 đóng băng trước khi sửa code (`output/_groundtruth/groundtruth_v2.json`, `sha256 = e5eeccb39587deb8763f7f4a1c2a49c93038216c9d0ecf16f2b1637fabafe845`):** bổ sung bộ khử generic nhiều dòng cân bằng ngoặc cho nguồn `n8n@2.12.3` (`288` active route — thêm `GET /rest/chat/settings` và `POST /rest/data-tables/uploads`), `9` quy tắc âm tính kiểm tra precision (`negative_rules`), và giữ cố định xuyên suốt toàn bộ quá trình đánh giá:
  - **`target-d.example` (offline `2.066` file):** Recall **`288/288` (`100,00%`)**, Precision tăng từ `96,97%` (`FP = 9`, `neg_viol = 10` ở `v20`) lên **`100,00%` (`FP = 0`, `neg_viol = 0`)**, `sourcemap_only = 6/6`, `code_line0: 179 -> 0`, thời gian phân tích lạnh giảm từ `6,82 s` xuống **`5,15 s`**, RSS đỉnh **`386,9 MB`**, `verify -dry-run` giảm từ `261` xuống **`259` request**.
  - **4 target còn lại (offline):** `target-d.example_3016` đạt **`30/30` (`100%` recall, `100%` precision, `0,91 s`, `101,3 MB`)**; `portal.target-b.example` **`7/7` (`100%`, `code_line0 = 0`)**; `admin.target-a.example` giữ nguyên **`389` dòng catalog** (`0` sai khác so với `v18`/`v20`, `code_line0 = 0`; `32/40` trên tập mẫu đóng băng do 5 mục hoán vị đoạn path và 3 mục dấu `/` cuối trong script tạo mẫu ban đầu — không sửa ngược tệp GT đã đóng băng); `target-c.example` **`28/28` (`100%`, `code_line0 = 0`)**.
- **Kiểm định mù một lần duy nhất trên Held-Out `@keycloak/keycloak-admin-ui@26.8.2` (`heldout_keycloak_gt.json`, `sha256 = c619ec0dcaecedba306cb3d66a08b0bc1e1fcbdf1859ca8ec999da3a9cc78eea`, `415` OpenAPI operation, chạy sau khi đã đóng băng mã nguồn ở commit `d05a590`):**
  - *[Đính chính ở Mục 24 — Đợt 25E]:* Trong lần chạy `v21`, `index-Cqtr7vCN.js` (`4,19 MB`) và `FlowDetails-Clef74HX.js` gặp lỗi parser `tdewolff/parse/v2 v2.8.20` (`parse: unexpected =>` trên `({ a: b = 1 } = { a: 1 }) => b`) và bị bỏ qua âm thầm không có fallback; do đó con số `2,89 s` của `v21` chưa phản ánh việc phân tích AST của bundle chính, và nhận định về `class extends`/`#private` chỉ được kiểm chứng thực nghiệm đầy đủ sau khi sửa parser ở Mục 24.3 bên dưới.
- **Benchmark live chỉ-đọc trên 5 domain được phép (`output/_live_25d/`, `0` request ghi trên toàn bộ mục tiêu):**
  - **`target-d.example` (`crawl -insecure -explore -guard on -depth 2 -max-pages 20`):** thăm `20` trang, thu `2.045` script (`297` bundle + `1.748` sourcemap) trong `220,0 s`; phân tích lạnh **`4,92 s`**, RSS **`387,4 MB`**, **`288/288` recall (`100%`), `0` FP (`100%` precision), `code_line0 = 0`**; `verify` chỉ-đọc gửi `300` request (`210 GET`, `90 OPTIONS`, **`0` write**) thu về **`136 verified_alive`**, `30 write_unverified`, `1 auth_wall_opaque`; `export -drafts` sinh `370/370` tệp `.http` hợp lệ (`0` lộ giá trị nhạy cảm).
  - **`portal.target-b.example` (`-explore -guard on -depth 2 -max-pages 20`):** thăm `13` trang (`98` thao tác explore), thu `26` script của bản build Vite hiện hành trong `191,6 s`; phân tích lạnh **`0,46 s`**, RSS **`58,2 MB`**, trích xuất đủ **`6/6` route `api.target-b.example` đang có trên bản live** (route thứ `7` `POST /user/login` trong tập offline thuộc bundle CRA lịch sử `main.b0da88a2.chunk.js` từ Archive); `verify` gửi `7 GET` (**`0` write**), đạt **`6/6 verified_alive`**, `192/192` tệp `.http` hợp lệ.
  - **`target-c.example` (`-depth 4 -max-pages 500 -resolve-max 2000`):** thăm `22` trang, `444` script trong `147,8 s` (lưu ý: `crawl -engine http` mặc định đã chạy bước `archive`); phân tích lạnh **`2,15 s`**, RSS **`162,7 MB`**, **`28/28` (`100%`)**, `code_line0 = 0`; `verify` gửi `224 GET` (**`0` write**), đạt **`126 verified_alive`**, `164/164` tệp `.http` hợp lệ.
  - **`admin.target-a.example` (`-engine http -scope fqdn -depth 3`):** `4` script trong `172,7 s` (có chạy `archive` mặc định của `engine http`); phân tích lạnh **`2,02 s`**, RSS **`253,1 MB`**, `389` dòng catalog (`code_line0 = 0`); `verify` gửi `300 GET` chạm trần mặc định `-max 300` trên tổng `380` request dự kiến (**`0` write**), đạt **`14 verified_alive`**, `387/387` tệp `.http` hợp lệ.
  - **`target-d.example:3016`:** tại thời điểm chạy live (2026-11-12 18:05+07), cổng `3016` trên máy chủ không phản hồi kết nối (`Client.Timeout exceeded` trên cả HTTPS `-insecure` lẫn HTTP), nên chỉ đánh giá được đầy đủ trên bản chụp offline (`30/30` route, `100%` precision).

---

## 24. Đợt 25E — Lối Thoát & Quan Sát Lỗi Parse Bundle, Đối Sánh Biểu Thức Base Không Danh Sách Cứng & Chuẩn Hoá `groundtruth_v3` / Held-Out (`jsapi v22`)

Khắc phục 4 vấn đề từ đợt kiểm định độc lập đối với Đợt 25D trước khi mở rộng mô hình hoá `class`. `jsapi.Version = 22`.

### 24.1. Lối Thoát AST (`transformJSLower`), Fallback `ExtractLoose` & Quan Sát Lỗi Parse Cho Mọi Bundle (`internal/jsapi`, `internal/endpoints`, `internal/engine`)
- **Nguyên nhân gốc ở thượng nguồn:** Kiểm tra `github.com/tdewolff/parse/v2@master` xác nhận `v2.8.20` (`0013eb97556f`, 2026-10-22) đã là bản mới nhất trên nhánh chính và vẫn gặp lỗi chuyển đổi cover-grammar `parse: unexpected =>` đối với hàm mũi tên ES2015 hợp lệ kết hợp đổi tên + giá trị mặc định trong destructuring kèm mặc định đối tượng (`const f = ({ a: b = 1 } = { a: 1 }) => b;`). Mẫu này xuất hiện trong `index-Cqtr7vCN.js` (`4,19 MB`, dòng `84062`) và `FlowDetails-Clef74HX.js` của Keycloak cũng như `ParameterInputList-BjcY8PSZ.js` (`884 KB`, dòng `140`) của `n8n`.
- **Hạ cấp hàm mũi tên JS thuần bằng `esbuild` (`transformJSLower`, `ASTLowered`):**
  - Khi `js.Parse` trả lỗi `"parse..."`, cả `jsapi.Extract` lẫn `jsapi.ExtractSource` chạy `transformJSLower` (`esbuild.Transform` Go thuần với `Loader: api.LoaderJS`, `Target: api.ESNext`, `Supported: map[string]bool{"arrow": false}`, `TreeShakingFalse`, kèm giải mã VLQ SourceMap v3). Các hàm mũi tên được hạ xuống `function` thường (với `const _this = this` vốn đã được `jsapi.isThis` hỗ trợ), giữ nguyên `class`, `#private`, ES module và ánh xạ chính xác số dòng gốc (`ASTLowered = true`), trong khi `Extract` vẫn từ chối cú pháp TypeScript/JSX. `transformTSWithSupported` áp dụng cơ chế tương tự khi mã đầu ra của `.ts`/`.vue` vẫn vướng lỗi `js.Parse`.
- **Fallback `ExtractLoose` cho cả bundle & báo cáo tường minh (`AnalyzeStats`):**
  - Trong `endpoints.analyzeOne`, điều kiện giới hạn `info.source` được gỡ bỏ: mọi script (cả bundle lẫn sourcemap) nếu vẫn còn lỗi `parse` sau bước hạ cấp đều rơi về `jsapi.ExtractLoose(src)` với `LooseFallback = true` và lưu lỗi gốc vào `ParseError`, đảm bảo không bao giờ bỏ rơi trắng một bundle.
  - `endpoints.AnalyzeStats` (`SummarizeScripts`, `CatalogWithStats`) ghi nhận `total`, `bundle_parse_errors`, `bundle_ast_lowered`, `source_parse_fallbacks` và `failed_bundles` vào `run.json` (`static_analysis`), log `slog.Info("endpoints", ...)`, phát `slog.Warn` + cảnh báo trong `run.Warnings` khi `BundleParseErrors > 0`, và in ra `stderr` của lệnh `jsharvest endpoints`.

### 24.2. Đối Sánh Biểu Thức Base Có Nguyên Tắc — Xoá Bỏ `genericBaseNormWords` (`internal/jsapi/jsapi.go`, `internal/endpoints/endpoints.go`)
- **Xoá hoàn toàn danh sách từ cứng:** `genericBaseNormWords` và `hasPrimaryClientBaseKey` bị loại bỏ khỏi `internal/endpoints/endpoints.go`.
- **Đối sánh trực tiếp biểu thức base tại nơi gọi (`BaseKeys`):**
  - Ở tầng tĩnh, `jsapi` ghi nhận thêm các thuộc tính cấu hình mang đường dẫn gốc tương đối (`/...`, ví dụ `baseURL: "/rest"`) vào `Result.Settings` bên cạnh URL tuyệt đối `https://...`. Trong `endpoints.Build`, lời gọi mang `prop:<name>` chỉ nhận base tĩnh cùng origin nếu tên thuộc tính khớp trực tiếp `settingsByProp[origin][strings.ToLower(name)]`; biến đối tượng HTTP client đã gắn (`hasBoundClientKey`, `client:...`) tiếp tục nhận base của client/origin đó.
  - Ở tầng lan truyền từ traffic quan sát được (`ENH-10`), `canonBaseKey` thu thập các khoá biểu thức base từ những dòng đã khớp `Observed` trên cùng origin vào `obsBaseByOriginKey`. Một dòng `Static` chưa có base chỉ nhận base quan sát được khi có `client:...` hoặc có khoá biểu thức (`prop:<lower>`, `exp:<sha>\x00<name>`) giao với `obsBaseByOriginKey[origin]` (hoặc khi toàn origin không dùng biểu thức khoá nào). Nhờ vậy `ctx.host` trỏ dịch vụ analytics không bị gán nhầm `/rest`, còn client chính đặt tên tuỳ ý như `client.authServer` vẫn nhận đúng base đã quan sát.

### 24.3. Kết Quả Kiểm Định Phân Tách Tập Phát Triển (`groundtruth_v3`) và Tập Kiểm Mù (`heldout_keycloak`)
- **Tập Phát Triển (`groundtruth_v3.json`, `split: "dev"`, `sha256 = c12000d40699d9ecdd0026281725db2d8dcedd89e7befac22c997be1af993dac`; giữ nguyên `groundtruth_v2.json`):**
  - Sửa dứt điểm bộ mẫu `admin.target-a.example` kèm nhật ký thay đổi tường minh so với `v2`: chỉnh 2 đường dẫn OAuth đảo thứ tự (`v1.0/system-user/oauth/token`, `v1.0/ldap/oauth/token`), giữ dấu `/` cuối thật trong bundle của 3 route `problem-{catalog-groups,catalogs,infos}/admin/`, thay 3 mục `GET` không tồn tại trong `app.js` bằng các lời gọi `.replace`/`+`/`.concat` có thật và nâng đủ `60` route đúng như mô tả.
  - **Kết quả offline trên Tập Phát Triển (`dev`, chạy trong `unshare -rn`):**
    - **`target-d.example` (`2.066` script):** Dev Recall **`288/288` (`100,00%`)**, Dev Precision **`100,00%` (`FP = 0`, `neg_viol = 0`)**, `sourcemap_only = 6/6`, `bundle_parse_errors = 0`, `bundle_ast_lowered = 1` (`ParameterInputList-BjcY8PSZ.js` không còn bị bỏ qua), `code_line0 = 0`, phân tích lạnh `5,53 s`, RSS đỉnh `372,7 MB`.
    - **`target-d.example_3016` (`10` script):** Dev Recall **`30/30` (`100,00%`)**, Dev Precision **`100,00%` (`FP = 0`)**, `bundle_parse_errors = 0`, `0,88 s`, RSS `104,4 MB`.
    - **`portal.target-b.example` (`61` script):** Dev Recall **`7/7` (`100,00%`)**, `bundle_parse_errors = 0`, `1,12 s`, RSS `121,2 MB`.
    - **`admin.target-a.example` (`4` script):** Dev Recall **`60/60` (`100,00%`)**, `bundle_parse_errors = 0`, `2,06 s`, RSS `273,9 MB`.
    - **`target-c.example` (`444` script):** Dev Recall **`28/28` (`100,00%`)**, `bundle_parse_errors = 0`, `2,13 s`, RSS `159,9 MB`.
- **Tập Kiểm Mù Độc Lập (`@keycloak/keycloak-admin-ui@26.8.2`, `split: "heldout"`, đo phân tích lạnh thật sau khi xoá `anon/static/`):**
  - Toàn bộ **`21` bundle** (`bundle_parse_errors = 0`, `bundle_ast_lowered = 2`: `index-Cqtr7vCN.js` `4,19 MB` và `FlowDetails-Clef74HX.js`) cùng **`648` tệp `.ts`/`.tsx` từ sourcemap** (`source_parse_fallbacks = 0`) được phân tích AST trọn vẹn với **`code_line0 = 0`**, thời gian `endpoints` lạnh **`1,77 s`** (tổng crawl + phân tích lạnh `6,21 s`) và RSS đỉnh **`198,1 MB`**.
  - Từ AST của `index-Cqtr7vCN.js`, `jsapi v22` trích xuất được `11` dòng catalog (gồm `{}/.well-known/openid-configuration` ở dòng `21470` bên trong phương thức `#_(t)`, `{}/account` ở dòng `21843`, base mặc định `http://127.0.0.1:8180` ở dòng `7245`, và ánh xạ VLQ chính xác tới dòng `96378`), nhưng số operation khớp đặc tả Admin REST API vẫn là **`0/415`** (`1` dòng `POST /` chưa khớp).
  - **Kết luận kiến trúc đã kiểm chứng sau khi parse thành công:** Toàn bộ `307` định nghĩa endpoint của `@keycloak/keycloak-admin-client` đi qua chuỗi 3 lớp kết hợp kế thừa + uỷ quyền trường `#private` + đột biến `URL.pathname` (`index-Cqtr7vCN.js:123-252`): lớp con `class BH extends za` truyền tiền tố tài nguyên qua `super(t, { path: "/admin/realms/{realm}/..." })` và gán thuộc tính lớp `findOne = this.makeRequest({ method: "GET", path: "/users/{id}" })`; lớp cha `za` giữ `this.#e = new UH({ client: t, ...n })` và uỷ quyền `makeRequest = (t) => this.#e.request(t)`; lớp `UH` lưu `this.#n = path`, trả về closure `async (p = {}, m) => this.#r(...)`, và trong `async #r` ghép đường dẫn bằng `const f = new URL(this.#s()), g = tP(g0(this.#n, n)); f.pathname = g0(f.pathname, g.expand(i)); await Ds(f, { ...u, method: t })`. Giữ nguyên quy tắc không tinh chỉnh đặc thù theo Keycloak ở bước này.

---

## 25. Đợt 25F — Kiểm Định Tối Đa Công Suất Chỉ-Đọc Trên 5 Domain & Sửa Tổng Quát Hoá 3 Lỗi Thực Chiến Của Công Cụ

Chạy toàn bộ các phân hệ chỉ-đọc ở công suất tối đa (`crawl -engine auto -spa-boot -escalate -probe -sourcemaps -sourcemap-guess -archive`, `crawl -engine cdp -tabs 3 -explore -guard on`, `monitor` baseline + diff, `endpoints`, `verify -max 1500 -include-historical -include-docs -include-source-only -include-strings`, `export -run all -drafts` thường & `-redact`, và `mcp` stdio JSON-RPC 2.0) trên cả 5 mục tiêu được phép để vừa đánh giá kết quả vừa kiểm định chéo chính công cụ; sau đó phân tích nguyên nhân gốc, sửa tổng quát hoá và kiểm chứng lại cả 3 lỗi thực chiến lộ ra.

### 25.1. Ba Lỗi Công Cụ Lộ Ra Khi Chạy Tối Đa Công Suất & Cách Sửa Tổng Quát Hoá
1. **Panic `assignment to entry in nil map` khi resume `archive.json` có Common Crawl lỗi một phần (`internal/archive/run.go`):**
   - **Hiện tượng & nguyên nhân gốc:** Ở lượt chạy `target-d.example`, cả 3 collection của Common Crawl đều trả `504`, nên `archive.json` ghi `commoncrawl.next` khác rỗng trong khi `commoncrawl.listed` rỗng và bị lược bỏ bởi `json:"listed,omitempty"`. Khi `target-d.example:3016` resume cùng thư mục `target-d.example/archive`, `json.Unmarshal` để `cc.Next != nil` nhưng `cc.Listed == nil`; `listCC` chỉ kiểm `if cc.Next == nil` rồi gán `cc.Listed[coll] = true` gây panic (`rc = 2`).
   - **Sửa tổng quát hoá:** Khởi tạo độc lập toàn bộ trường `map` của `state` và `Summary` (`Summary.Listed`, `Summary.Skipped`, `Summary.Historical`, `CC.Next`, `CC.Listed`, `Extra`) ngay sau khi đọc checkpoint trong `archive.Run`, đồng thời kiểm tra tách rời `cc.Next == nil` và `cc.Listed == nil` dưới `r.mu.Lock()` trong `listCC`.
2. **Treo CPU `~335 s` và mù tín hiệu `SIGINT` trong `archive.classify` / `inScripts` (`internal/archive/history.go`, `run.go`):**
   - **Hiện tượng & nguyên nhân gốc:** Sau khi tải xong JS cũ của `target-c.example` và ghi `archive/endpoints.jsonl`, bước `classify()` treo CPU hơn `108 s` cho tới hết timeout và bỏ qua `SIGINT` suốt `25 s` tới khi bị `SIGKILL` (`rc = -9`). Tái lập xác nhận: toàn bộ `27` wrapper endpoint trong `target-c.example/archive/endpoints.jsonl` có dạng `{}/api/v1/...` (base động chưa giải). `placeRe.Split("{}/api/v1/conversations", -1)` sinh `pieces[0] == ""`, khiến `pathRe` bắt đầu bằng wildcard không neo `[^"'`\s]{1,80}?` — vừa làm mất hoàn toàn tối ưu literal-prefix của `regexp` (quét NFA 80 trạng thái từng byte trên `445` bundle `13,99 MB`, tốn `12,43 s`/endpoint), vừa gây lỗi ngữ nghĩa (không khớp `a("GET", "/api/v1/conversations")` vì bắt buộc có ít nhất 1 ký tự khác dấu nháy trước `/`). Ngoài ra `r.history()` và `classify()` không nhận `context.Context`.
   - **Sửa tổng quát hoá:**
     - Gọt tiền tố placeholder đầu đường dẫn (`leadPlaceRe = ^(/?\{[^}]*\})+`) trước khi tách mảnh trong `compilePath`, để `{}/api/v1/conversations` neo trực tiếp vào `(?:/|["'`])api/v1/conversations` (khớp cả `"/api/..."`, `"api/..."` và `` `${base}/api/...` ``, đồng thời vẫn loại `"foo-api/..."`).
     - Bổ sung bộ lọc sơ cấp `bytes.Contains` trên toàn bộ mảnh cố định (sắp xếp mảnh dài nhất trước) trong `pathMatcher.matches` trước khi gọi `re.Match`, giảm thời gian quét `27` endpoint trên `14 MB` JS từ `~335 s` xuống `< 10 ms`.
     - Truyền `ctx context.Context` xuyên suốt `r.history(ctx)` -> `classifyCtx(ctx, ...)` -> `inScriptsCtx(ctx, ...)` để huỷ tức thì khi nhận `SIGINT` mà không ghi dở `historical.jsonl`.
3. **Bỏ lọt trang chặn IP/Rate-Limit `Error 1xxx` của Cloudflare (`Error 1006: Access denied`), làm bẩn `store` và `endpoints.jsonl` (`internal/detect/detect.go`, `internal/archive/pages.go`):**
   - **Hiện tượng & nguyên nhân gốc:** `admin.target-a.example` trả `HTTP 403` từ Cloudflare với `<title>Access denied | admin.target-a.example used Cloudflare to restrict access | admin.target-a.example | Cloudflare</title>`, `id="cf-error-details"` (`cloudflare-1xxx-errors/error-1006/`), `3` inline script (`sparrow.cloudflare.com/api/v1/event`, `cf-footer-ip-reveal`, `window._cf_translation`) và `https://performance.radar.cloudflare.com/beacon.js`. Luật `Cloudflare` trong `detect.go` trước đó chỉ kiểm `"just a moment"` / `"attention required"`, nên trả `Blocked: false`: `capture` xả cả `4` script của Cloudflare vào `anon/index.jsonl`, `endpoints` trích xuất `4` endpoint của Cloudflare Radar/Sparrow, và `explore` click cả nút khảo sát trên trang lỗi (bị `-guard on` giữ lại).
   - **Sửa tổng quát hoá (bảo toàn âm tính chuẩn):**
     - Mở rộng luật `block` của `Cloudflare` khi `blockingStatus` (`403`/`429`/`503`) và có `server: cloudflare` hoặc `cf-ray`: nhận diện `<title>` chứa `"cloudflare"` đi kèm `"access denied |"`, `"used cloudflare to restrict access"`, `"you are being rate limited"` hoặc `"error 10"`/`"error 11"`/`"error 12"`, cũng như thân HTML chứa `"cloudflare-1xxx-errors"` hoặc `id="cf-error-details"` kèm thông điệp chặn. Trang `403` của chính ứng dụng đứng sau Cloudflare (`<title>Access Denied</title>`, `<title>403 Forbidden</title>`, JSON lỗi) không có dấu hiệu trang lỗi Cloudflare nên vẫn giữ `Blocked: false`.
     - Đưa `performance.radar.cloudflare.com/` vào `InfraURL` (`cdn-infra` / `Quarantined`), thêm `sparrow.cloudflare.com/api/v1/event`, `cf-footer-ip-reveal`, `window._cf_translation` vào `challengeBody`, và cập nhật `archive.challengePage` để bỏ qua cả bản chụp Wayback của trang lỗi Cloudflare `1xxx`.

### 25.2. Kết Quả Kiểm Chứng Toàn Diện Live 5 Target (Sau Đợt 25F)
- **An toàn & quyền tệp tuyệt đối trên cả 5 target (`live_25f_verified_report.json`):** `0` tệp/thư mục sai quyền `0600`/`0700` (`bad_permissions_count = 0`); **`0` request ghi ứng dụng lọt ra mạng** trên cả `crawl` (`87` request ghi bị `-guard on` chặn: `82` trên `target-c.example`, `5` trên `target-d.example`), `archive` live-check (`GET` duy nhất) và `verify` (`GET` + `OPTIONS` duy nhất); `jsharvest mcp` qua stdio đạt **`6/6` phản hồi JSON-RPC hợp lệ, đủ `7/7` tool, `0` lỗi** trên cả `5/5` target.
- **Số liệu chi tiết từng target:**
  - **`target-d.example` (`n8n@2.12.3`):** thu `2.075` script live (`302` bundle + `1.773` sourcemap, `bundle_parse_errors = 0`, `bundle_ast_lowered = 1`), `319` dòng catalog, **`288/288` recall (`100%`), `100%` precision (`FP = 0`)**, `verify` gửi `264 GET + 107 OPTIONS` đạt **`175 verified_alive`**, `export` kiểm đạt `461/461` tệp `.http` (`0` lỗi).
  - **`target-d.example:3016` (online trở lại):** resume `target-d.example/archive` hoàn tất sạch **`rc = 0`** (không còn panic `listCC`), thu `10` script live (`1` OpenAPI `/api-json`), **`30/30` recall & `100%` precision**, `verify` gửi `37 GET + 24 OPTIONS` đạt **`10 verified_alive`** + `18 write_unverified`, `30/30` tệp `.http` hợp lệ.
  - **`target-c.example`:** `crawl -archive` hoàn tất sạch **`rc = 0`** (không còn treo `classify()`), ghi `target-c.example/archive/historical.jsonl` gồm **`19` dòng** (`17 historical`, `2 in_current_code`); thu `445` script live (`1` OpenAPI), `265` dòng catalog (`12` dòng làm giàu từ archive), **`28/28` (`100%`)**, `verify` gửi `283 GET + 283 OPTIONS` (`208 auth_wall_opaque`), `772/772` tệp `.http` hợp lệ.
  - **`portal.target-b.example`:** thu `36` script live + archive, `9` dòng catalog, **`7/7` (`100%` — khôi phục đủ cả route thứ `7` `POST /user/login` nhờ gộp Archive)**, `verify` gửi `9 GET + 9 OPTIONS` đạt **`6 verified_alive`**, `257/257` tệp `.http` hợp lệ.
  - **`admin.target-a.example` (đang bật chặn IP Cloudflare `Error 1006`):** cả `crawl -engine auto` lẫn `crawl -engine cdp -tabs 3 -explore -guard on` đều nhận diện chính xác `blocked: true, vendor: "cloudflare"`, dừng ngay với `frontier.stopped = "blocked"` và mã thoát **`3` (`ErrBlocked` trong `8,95 s` ở CDP)**, cách ly trọn vẹn **`0` script rác trong `anon/index.jsonl` và `0` endpoint rác trong `anon/endpoints.jsonl`**.

---

## 26. Đợt 25G — Dừng `replay.Sender` Khi Bị WAF Chặn, Luồng Dữ Liệu Base Tĩnh Không `requests.jsonl` / Không `isBaseName` & Chuẩn Hoá Minh Bạch `groundtruth_v4` (`jsapi v23`)

Khắc phục trọn vẹn các vấn đề từ đợt kiểm định độc lập đối với Đợt 25E/25F hoàn toàn offline (`unshare -rn`, **0 gói tin mạng ra ngoài**). `jsapi.Version = 23`.

### 26.1. Dừng Tức Thì `replay.Sender` (`verify`, `authz`, `replay`, `archive` Live-Check) Khi Gặp Trang Chặn Của Nhà Cung Cấp WAF (`internal/replay`, `internal/verify`, `testbed/replay-check.sh`)
- **Nguyên nhân gốc:** Luật nhận diện `Cloudflare Error 1xxx` (`Error 1006: Access denied`) ở Đợt 25F mới áp dụng cho `crawl` và `archive.pages`. `replay.Sender.Send` chỉ dừng khi gặp `429`, `cf-mitigated`, `503` kèm `Retry-After` hoặc `Clear-Site-Data`; vì trang `1006` là `HTTP 403` không có `cf-mitigated`, nếu IP bị cấm giữa chừng thì `verify`/`authz` sẽ bắn tiếp tới hết ngân sách `-max` và `verify.probe` còn có nguy cơ chấm nhầm `403` của WAF thành `verified_alive`.
- **Cách sửa tổng quát hoá:**
  - Bổ sung `vendorBlock(rawURL, status, hdr, bodyHead)` trong `internal/replay/send.go` kết hợp `htmlscan.Scan` (`Title`) và `detect.Check` trên `64 KB` đầu body: khi `blk.Blocked == true` (Cloudflare `1xxx`/challenge, Akamai, Imperva, DataDome, AWS WAF), `Sender` gọi `s.stop(...)` ngay sau phản hồi đầu tiên. Trang `403` JSON hoặc HTML của chính ứng dụng đứng sau `Server: cloudflare` không có dấu hiệu trang chặn của nhà cung cấp nên vẫn tiếp tục bình thường.
  - Tích hợp `vendorBlock` vào `replay.Judge` (`internal/replay/compare.go`) để gán `Verdict: Blocked` cho phép thử bị WAF chặn, và kiểm tra `v.o.Sender.Stopped()` ngay sau `v.send` trong `verify.probe` (`internal/verify/verify.go`) để ghi nhận `Unreachable` (`"the run stopped: ..."`), tuyệt đối không gán `verified_alive`.
  - Mở rộng `testbed` (`TESTBED_CF_BLOCK=1006`) và thêm Mục `G` vào Gate `testbed/replay-check.sh`: kiểm chứng cả `authz -max 50` lẫn `verify -max 50` dừng ngay ở `.sent == 1` (`server log == 1`) với `verified_alive == 0`.
  - Bổ sung rào chắn an toàn offline cho `output/_groundtruth/live_max_audit.py`: bắt buộc `ALLOW_LIVE=1` (và `ALLOW_SENSITIVE_TARGETS=1` cho `target-a`/`target-c`), không xoá đè `OUT_ROOT` cũ, cấu hình `gentle` cho `target-a` (tắt `-explore`, `-tabs 1`, `-depth 1 -max-pages 10 -http-rate 1`, `-archive=false`, `verify -max 40 -rate 1` không bật cờ `-include-*` sinh canary hàng loạt), và dừng ngay chuỗi pass nếu `run.json` báo `blocked` hoặc `verify.json` báo `stopped`.

### 26.2. Khôi Phục Giải Base Tĩnh Khi Không Có `requests.jsonl` & Bỏ Phụ Thuộc Tên Biến `isBaseName` (`internal/jsapi`, `internal/endpoints`)
- **Nguyên nhân gốc:** Ở `v22`, khi chạy không có `requests.jsonl` (chế độ mặc định `-engine http` cho `anon` hoặc phân tích từ `archive`), một endpoint mang `prop:<name>` chỉ nhận base tĩnh nếu `settingsByProp` có giá trị literal — mà `Result.Settings` lại chỉ ghi khi `isBaseName(name)` đúng và chưa bóc biểu thức reactive (`.value`, `ref`/`computed`, Pinia setup-store `defineStore(() => { const baseUrl = computed(() => ...); return { baseUrl } })` + `window.BASE_PATH`). Hậu quả là trên `target-d.example` (`n8n`) khi bỏ `requests.jsonl`, số dòng có `/rest` tụt từ `295` (`v21`) xuống `1` (`v22`), đồng thời các tên thuộc tính không theo mẫu như `client.authServer` hay `cfg.customGw` vẫn lệ thuộc vào `isBaseName`.
- **Cách sửa theo luồng dữ liệu biểu thức (`jsapi v23`):**
  - Bổ sung `Result.PropBases` (`settlePropBases()` trong `jsapi.go` chạy với `noMarkUsed = true` để không làm ảnh hưởng Pass 3 `stringVisitor`, giữ nguyên `Result.Settings` cho `frontier.APIOrigins`): ghi nhận mọi thuộc tính object hoặc phép gán `obj.prop = val` (trừ khoá định tuyến `path`/`redirect` và khoá đích request `url`/`uri`/`endpoint`/`pathname`) có giá trị biểu thức giải được thành URL `http(s)://` sạch hoặc tiền tố đường dẫn gốc tương đối (`propRelBaseRe`), hoàn toàn không kiểm tra `isBaseName`.
  - Hỗ trợ bóc lớp reactive `.value` (`ref`, `shallowRef`, `computed`) và Pinia setup-store (`unwrapReactiveExpr`, `singleReturnExpr`) cùng biến toàn cục gốc ứng dụng (`window.BASE_PATH`, `window.__BASE_PATH__`, `import.meta.env.BASE_URL` -> `"{origin}/"` gộp sạch trong `cleanURL`).
  - Tổng quát hoá `splitBaseAndPath` (`splitPair` trong `helpers.go`) và nhận diện base trong `modules.go` dựa trên cấu trúc hai tham số/thuộc tính độc lập thay vì `isBaseName`; trong `endpoints.Build`, nạp `settingsByProp` và `linkModules` từ cả `Settings` lẫn `PropBases`, đồng thời gắn `ep.ThirdParty = true` khi mọi `ep.Bases` giải ra đều nằm ngoài scope (`allOutOfScopeBases`).
- **Số liệu kiểm chứng không có `requests.jsonl` trên `target-d.example` (`n8n@2.12.3`, `2.066` script, chạy trong `unshare -rn`):**
  - **`v21` (`5dcdbdf`, dùng danh sách cứng `genericBaseNormWords`):** `295` dòng có `/rest`, Active GT **`288/288`**, `FP = 0`, `unresolved_dyn = 7`, `9,05 s`, RSS `374,7 MB`.
  - **`v22` (`6462661`, xoá danh sách cứng nhưng thiếu luồng base tĩnh):** tụt còn **`1`** dòng có `/rest`, Active GT **`0/288`**, `unresolved_dyn = 295`, `8,69 s`, RSS `377,7 MB`.
  - **`v23` (luồng dữ liệu `PropBases` + reactive unwrapping, không `genericBaseNormWords`, không `isBaseName`):** khôi phục đủ **`295` dòng có `/rest`**, Active GT **`288/288` (`100,00%`)**, Dev Precision **`100,00%` (`FP = 0`, `neg_viol = 0`)**, `unresolved_dyn = 7` (cả 7 route `templatesHost` giữ nguyên `bases: []`), `POST api.n8n.io /api/accounts/onboarding` gắn đúng `third_party: true`, thời gian **`8,42 s`**, RSS **`407,0 MB`**.

### 26.3. Sửa `looksLikePath` Cho Chuỗi Truy Vấn RSQL & Báo Cáo Tách Bạch Thay Đổi Ground-Truth (`groundtruth_v4`) vs Thay Đổi Code (`v22 -> v23`)
- **Sửa lỗi code (`looksLikePath` trong `internal/jsapi/jsapi.go`):** Tách kiểm tra phần đường dẫn trước `?` và phần query sau `?`; với lời gọi HTTP thực sự (`lv >= call`), cho phép dấu nháy đơn/kép và khoảng trắng bên trong giá trị tham số query (như biểu thức lọc RSQL `?query=type=='TRANSACTION'`) trong khi vẫn giữ chặt điều kiện không nháy/khoảng trắng ở phần path và ở mức `weak`.
- **Chuẩn hoá `groundtruth_v4.json` (`sha256 = 1662ddc14a565a28e8aabcb1a578933e68539240c65d40aa821ca6d2022f5bb7`; giữ nguyên bất biến `groundtruth_v2.json` và `groundtruth_v3.json` trên đĩa):**
  - **Phần thay đổi của Ground-Truth (`v2 [40] -> v3 [60] -> v4 [158]`):** Bỏ hoàn toàn trần cắt nhân tạo `if len(items) >= 60: break` từng làm `v3` đánh rơi âm thầm `15` route hợp lệ của `v2` (`notification/v1.0/tags`, `otp-blacklist`, `battery/blacklist`, các route `export`...), khôi phục toàn bộ `15` route này cùng `82` route literal/`.replace` còn lại trong `app.js`, bổ sung `GET /api-gateway/charge-point/v1.0/transactions/admin/report-on-day` (biến gán literal nối query RSQL), cập nhật mô tả khớp đúng `158` route và lưu đối chiếu chi tiết trong `target_a_diff_v2_v3_v4`.
  - **Phần thay đổi thực tế của Code trên cùng `groundtruth_v4.json` (`unshare -rn`):**
    - **`v22` (`6462661`):** đạt **`157/158` (`99,37%`)** trên `admin.target-a.example` — bỏ sót đúng 1 route `GET /api-gateway/charge-point/v1.0/transactions/admin/report-on-day` (cả `15` route khôi phục từ `v2` lẫn `82` route bỏ trần đều đã có sẵn trong catalog từ `v21`/`v22`).
    - **`v23` (hiện tại):** đạt **`158/158` (`100,00%`)** trên `admin.target-a.example` (`2,84 s`, RSS `262,5 MB`) — tăng thực chất **`+1` endpoint** (`GET /charge-point/v1.0/transactions/admin/report-on-day`, `bases: ["/api-gateway"]`, `query: ["page", "query", "size"]`).
  - **Toàn bộ các mục tiêu còn lại không hồi quy (`v23`, `unshare -rn`):** `target-d.example` **`288/288`** (`100%` precision, `FP = 0`, `11,48 s`, `376,3 MB`), `target-d.example_3016` **`30/30`** (`100%` precision, `1,12 s`), `portal.target-b.example` **`7/7`** (`1,94 s`), `target-c.example` **`28/28`** (`3,24 s`), và tập kiểm mù `Keycloak 26.8.2` (`21` bundle `b_err = 0, low = 2`, `648` sourcemap, `code_line0 = 0`, `1,92 s`, RSS `202,1 MB`).
- **Hồi quy toàn bộ (`testbed/regress.sh`, giữ nguyên log trong `bin/regress/`):** `go test -count=1 -race ./internal/... ./cmd/...` và toàn bộ **`18/18` gate mặc định** đều đạt `ok` trong `915 s` (`perfgate`: `2.000` script `43,1 MB` trong `13,22 s`, RSS đỉnh `262,5 MB`; `replay-check` Mục `G`: dừng ở `1` request trên cả `authz` lẫn `verify` khi gặp Cloudflare `1006`).






---

## 27. Đợt 25H: chính sách khi CDN/WAF chặn (`-on-block`), thay cho cách dừng toàn cục của 26.1

### 27.1. Vì sao bỏ cách làm của 26.1
- 26.1 dừng **cả run, mọi host** ngay khi **một** phản hồi bất kỳ bị `detect.Check` nhận là trang chặn. Cách này có ba lỗi:
  - **Không phân biệt được luật chặn một request với lệnh cấm IP.** Cloudflare 1020 (luật firewall khớp một path hoặc payload) và 1006 (cấm IP) có cùng title "Access denied | … used Cloudflare to restrict access". `verify` gửi giá trị mẫu, đường dẫn canary và path `/admin/…`, nên chỉ cần một request khớp luật WAF là mất hết phần còn lại.
  - **Dừng theo run, không theo host.** Một subdomain bị challenge (như `growth.target-c.example`) làm dừng luôn việc kiểm tra các host khác.
  - **Verdict gán sai.** Mục bị dừng thành `unreachable`. `authz` báo "session đã chết" khi probe gặp trang chặn. `authz` còn tự dừng toàn cục khi một trial bị `Judge` gán `blocked` (có từ 5.1).
- Nguyên tắc (người dùng chốt ngày 2026-11-13): bị chặn không có nghĩa là mình làm sai. Chỉ dừng khi việc gửi tiếp **không còn thu được thông tin gì**, tức khi host đã thực sự cấm client. Mọi trường hợp khác thì ghi nhận rồi chạy tiếp.

### 27.2. Phân loại (`replay.ClassifyBlock`, `internal/replay/block.go`)
`ClassifyBlock(status, header, 64 KB đầu body)` trả `nil` khi đó là phản hồi của chính app (kể cả 403 JSON/HTML sau `Server: cloudflare`). Nếu không, nó trả `*Block{Kind, Vendor, Code, Evidence, RetryAfter}`:

| Kind | Nhận diện | Ý nghĩa |
|---|---|---|
| `rate` | 429; 503 có `Retry-After`; Cloudflare 1015 | cần chờ |
| `challenge` | `cf-mitigated`; "Just a moment"; captcha DataDome/PX | cần trình duyệt |
| `client` | Cloudflare 1005, 1006, 1007, 1008, 1009, 1012 | client (IP, ASN, quốc gia) bị cấm |
| `signature` | Cloudflare 1010 | chữ ký client bị chặn; Chrome (CDP) có thể vẫn qua |
| `request` | 1020; trang chặn của Akamai/Imperva; 403 khớp `wafRe` | luật khớp riêng request này |

Mã lỗi đọc từ body (`Error 1006`, `cf-error-code">1015`, `/error-1010/`) và chỉ được tin khi `detect.Check` đã xác nhận đó là trang của nhà cung cấp.

### 27.3. Hành vi của `Sender` (`internal/replay/send.go`)
- Trạng thái lưu theo `host:port` trong `hostState`:
  - `given`: lý do đã bỏ host;
  - `consec`: số lần bị chặn liên tiếp;
  - `good`: một request đọc mà host đã trả lời không bị chặn, dùng làm request đối chứng;
  - `pauseUntil`: thời điểm hết chờ sau phản hồi `rate`.
- **Phản hồi không bị chặn:** đặt `consec = 0`. GET/HEAD đầu tiên có status dưới 500 được giữ làm request đối chứng.
- **`rate`:**
  - Request đọc (GET/HEAD/OPTIONS): chờ `Retry-After` (nếu không có thì 5 s, rồi 10 s), sau đó hỏi lại, tối đa `rateTries = 3` lần. Thời gian chờ chỉ áp cho host đó; host khác vẫn dùng slot và lượt bình thường, trần `-rate` chung vẫn giữ.
  - Hết 3 lần mà vẫn bị, hoặc `Retry-After` dài hơn 60 s: với `host` thì bỏ host.
  - Request ghi: **không hỏi lại** (có thể server đã thực hiện), chỉ tạm dừng host.
- **Các kind còn lại, với `-on-block host` (mặc định):**
  - Lần chặn đầu tiên trong một chuỗi chặn liên tiếp: gửi **một request đối chứng**, `purpose: block-check`, ghi vào `sent.jsonl` và tính vào `-max`. Request đối chứng là request đọc đã từng được trả lời; nếu chưa có thì dùng `GET /` với đúng User-Agent của request bị chặn, không kèm credential.
  - Nếu request đối chứng cũng bị chặn (khác `rate`) thì **bỏ host đó**. Các request sau tới host đó trả `ErrHostBlocked` mà không gửi gì (`errors.Is(err, errStopped)` vẫn đúng, nên các nơi gọi vẫn coi là bị bỏ qua).
  - Nếu request đối chứng được trả lời bình thường thì đó là luật trên riêng request kia: run chạy tiếp, và kiểm lại cứ sau mỗi `recheckEvery = 5` lần bị chặn liên tiếp.
  - Request đối chứng lỗi mạng: không kết luận gì.
  - Nhiều request bị chặn cùng lúc (`-concurrency`) chỉ sinh một request đối chứng: có khoá `hostState.check` và so `checkedAt` với thời điểm request bắt đầu.
  - Khi **mọi** host được phép đều đã bị bỏ thì run dừng: `stopped: every host is blocked: …`.
- **`-on-block skip`:** chỉ đánh dấu, không gửi request đối chứng, không bao giờ bỏ host (phản hồi `rate` vẫn được chờ rồi hỏi lại).
- **`-on-block stop`:** hành vi cũ. Lần chặn đầu tiên (kể cả `rate`) dừng run; dành cho target cần để lại ít dấu vết nhất.
- `Answer.Block` và `Sent.block` (trong `sent.jsonl`) ghi lại trang chặn. `Sender.BlockedHosts()` được đưa vào báo cáo.
- `Clear-Site-Data` và 5 lỗi liên tiếp vẫn dừng toàn cục như trước, vì đó là chuyện an toàn của phiên chứ không phải WAF.

### 27.4. Nơi dùng
- **`verify`:**
  - Có thêm hai verdict: `waf_blocked` (trang của nhà cung cấp, không phải của route; trước đây trang 403 này có thể bị chấm `verified_alive` qua nhánh "an auth guard the canary does not meet") và `host_blocked` (không gửi vì host đã bị bỏ).
  - Canary bị chặn thì có `Err: blocked: …`, không được dùng làm mốc so sánh. OPTIONS bị chặn thì coi như không có OPTIONS.
  - `verify.json` có thêm `hosts_blocked`; `verify.md` ghi các host đã bỏ.
- **`authz`:**
  - Bỏ việc tự dừng toàn cục khi một trial là `blocked`.
  - Probe gặp trang chặn thì không kết luận phiên chết.
  - `Judge`: trial bị `rate` cho ra `unclear`; control của role cao bị chặn cũng cho ra `unclear` và nói rõ lý do.
  - `authz.json`/`authz.md` có thêm `hosts_blocked`.
- **`replay`:** bước bị chặn có trường `blocked`, CLI in ra `BLOCKED: …`; `summary.json` có thêm `hosts_blocked`.
- **Kiểm live của `archive`:** bị chặn hoặc host đã bị bỏ thì coi là **không biết** (nil), không kết luận file đã chết; bản lưu trong archive vẫn được tải.
- **CLI:** `verify`, `authz`, `replay` có `-on-block host|skip|stop` (mặc định `host`). `archive` dùng `host`. Các host bị bỏ được in dạng `host given up: H: lý do`.

### 27.5. Kiểm chứng
- **Unit test:**
  - `internal/replay/block_test.go`: phân loại 13 ca (gồm 403 JSON/HTML của app sau Cloudflare); 1020 rồi 1006 trên hai host; host cuối cùng bị bỏ thì dừng run (request đối chứng `GET /` mang đúng UA); chặn đồng thời chỉ sinh một request đối chứng; kiểm lại sau mỗi 5 lần chặn liên tiếp; 429 được chờ và hỏi lại, POST thì không; `stop`/`skip`.
  - `internal/verify/verify_test.go`: ca bị cấm IP và ca có luật trên một path.
  - `TestSender` cũ: 429 nay được hỏi lại 3 lần rồi bỏ host.
- **Testbed:** `TESTBED_CF_BLOCK` có các dạng `1006`, `1006-after:N`, `1020:REGEXP`, `1015:N`.
- **Gate `testbed/replay-check.sh`, mục G:**
  - G1: `authz` khi mọi request bị 1006: 2 request (probe và request đối chứng), `hosts_blocked`, không có ghi chú "session is dead".
  - G2: `verify` trên verify-app không có luật, làm mốc.
  - G3: luật 1020 trên `/api/v1/items`: chỉ mục đó thành `waf_blocked`, gửi hơn mốc đúng 1 request, các verdict khác giống hệt mốc.
  - G4: bị 1006 sau 6 request: dừng ở 8 request, không có trang 403 nào được chấm `alive`.
  - G5: một 429 có `Retry-After: 1`: gửi hơn mốc 1 request, verdict giống hệt mốc.
  - G6: `-on-block stop` dừng ngay tại request bị chặn.

### 27.6. Để sau
- Gửi lại qua Chrome (CDP) khi gặp `signature` (1010) hoặc `challenge`. Hiện chỉ ghi verdict và lý do.
- Canary bị chặn trong khi probe đi qua: `judge` chấm như khi canary lỗi (đã có từ trước). Một 401/403 khi đó có thể là `verified_alive` mà không có mốc so sánh.

---

## 28. Đợt 25I: không tự khai báo là bot (N0), sửa cách xử lý khi bị chặn (N5), dừng sớm khi gặp cổng chặn (một phần N4)

Nền tảng: `docs/research-2026-11-13-bot-transport.md`. Người dùng chốt ngày 2026-11-13: không khai báo hay xin whitelist, mà tự động hoá đúng như người dùng trình duyệt thật; không chuyển mọi request sang Chrome; **giữ tốc độ quét**. Vì vậy đợt này không thêm độ trễ ngẫu nhiên hay giới hạn một request mỗi host. Phần nhịp sẽ được đo ở zone Cloudflare riêng trước khi quyết.

### 28.1. N0: bỏ mọi dấu hiệu tự khai báo
- **`internal/marker`** chứa các tên trung tính:
  - `Internal` (`rt-4f9c2a.js`): `sourceURL` của code jsharvest evaluate (resolver, explore, socket stub của guard, phần khôi phục storage của phiên, reporter);
  - `Tagger` (`pf-8d1e7b.js`): `sourceURL` của tagger;
  - `TaggerKey`: khoá `Symbol.for` của tagger (trước là `jsharvest.tagger`).

  `IsInternal`/`IsTagger`/`InSource` vẫn nhận ra tên cũ `jsharvest-internal`/`jsharvest-tagger`, nên output cũ được `capture` và `flow` đọc đúng. Tên là hằng số, không ngẫu nhiên theo mỗi lần chạy: `flow` đọc lại `requests.jsonl` của các lần chạy trước.
- `marker.Slug()` sinh đoạn path ngẫu nhiên kiểu route (12 ký tự a-z0-9, mở đầu bằng chữ), dùng cho:
  - kiểm tra SPA của engine HTTP (trước là `/jsharvest-<hex>-no-such-page`);
  - canary của `verify` (trước là `__jsharvest_canary_<hex>`).

  `bin/testbed verifycheck` giờ đếm canary theo URL ghi trong `verify.json`, và kiểm thêm rằng không request nào mang chữ "jsharvest".
- **`Sender` không bao giờ để rơi về `Go-http-client`:** `SenderOptions.UserAgent` được điền vào request thô nào chưa có UA. CLI lấy UA mà Chrome của target đã gửi nhiều nhất (`observedUA`: ưu tiên traffic của Chrome, rồi mới tới traffic của engine HTTP; bỏ UA headless hoặc tự xưng), nếu không có thì dùng `marker.FallbackUA`. Áp cho `verify`, `authz`, `replay` và kiểm live của `archive`; kiểm live bỏ UA `Mozilla/5.0 (jsharvest archive check)`.
- Email mẫu là `test.user@example.com`; file upload của explore là `document.txt`/`image.png`.
- Chrome không còn `--enable-automation`; vẫn giữ `--disable-blink-features=AutomationControlled`.
- Socket stub của guard: class tên `WebSocket`, lỗi của WebTransport giống thông báo gốc của trình duyệt, không còn `console.debug("jsharvest guard: …")`.
- **Còn lại:**
  - header `X-Jsharvest-Guard` trên phản hồi giả của guard (các gate dựa vào nó);
  - tên isolated world (trang không thấy được);
  - UA nguồn archive gửi tới Wayback, OTX…, không tới target;
  - tagger vẫn vá main world và có thể bị lộ qua `Function.prototype.toString`;
  - UA `Chrome/141` cứng của engine HTTP, và TLS/H2 của Go: để cho N1/N2.

### 28.2. N5: nhận diện và phản ứng khi bị chặn
- `detect.Check` nhận ra dạng text thuần `error code: 1xxx` (body chỉ có đúng chuỗi đó, status chặn, có header Cloudflare). Đây là dạng Cloudflare trả cho client không đòi HTML. Ngày 2026-11-12, `verify` đã gửi 566 request tới `api.target-c.example` mà không nhận ra dạng này.
- `ClassifyBlock`: trang "Sorry, you have been blocked" / "You are unable to access" là `request` (luật WAF), không phải `challenge`. Chỉ còn coi là challenge khi có dấu hiệu riêng của challenge (`just a moment`, `_cf_chl_opt`, script orchestrate/turnstile).
- `BlockClient` (1005–1009, 1012): **chỉ sửa chú thích, hành vi không đổi.** Từ 25H, cả `BlockClient` lẫn `BlockRequest` đều qua cùng một request đối chứng gửi bằng `Sender`, và host chỉ bị bỏ khi request đối chứng cũng bị chặn. Bằng chứng ghi trong chú thích: Chrome qua được còn client Go nhận 1006, cùng IP, cách nhau 2 s.

### 28.3. N4 (một phần): `verify` dừng sớm khi gặp cổng chặn
- `-gate-after N` (mặc định 15; 0 để tắt): nếu N probe liên tiếp trên một host đều trả lời **giống canary của chúng, giống nhau**, và verdict là `dead_or_fp`/`auth_wall_opaque`, thì các draft còn lại của host đó thành `host_gated` và không được gửi. Một probe cho verdict khác (kể cả `verified_alive` nhờ OPTIONS) là tắt cơ chế dừng sớm cho host đó.
- `verify.json` có thêm `hosts_gated`; CLI in `host gated: …`.
- Với target-a ngày 2026-11-12 (300 request, 299 cái là cùng một 400 "Thiết bị không có quyền thực hiện API"), cơ chế này đã dừng sau khoảng 15 probe cộng canary.
- Test: `TestVerifyGatedHostStopsEarly` (30 draft, `GateAfter: 5`, tối đa 8 request).

### 28.4. Sửa sau review (2026-11-13; hai bản đánh giá độc lập: kiến trúc tổng thể, và 25H/25I)
- **`-gate-after` từng chặn nhầm host bình thường.**
  - Trước đây: 404 JSON đồng nhất hoặc trang shell 200 của SPA đều được tính là cổng chặn.
  - Nay: chỉ tính phản hồi **trước định tuyến** (400, 401, 403, 407, 412, 426, 428), và phải thấy trên ít nhất **3 gateway prefix**. 404, 405 và 2xx/3xx là phản hồi định tuyến, không bao giờ làm host bị bỏ (`TestVerifyUniform404IsNotAGate`).
- **Canary cha khi vượt `maxPrefixes`:** service thứ 13 của một gateway được so với canary 1 đoạn (`/api-gateway`, có ngân sách riêng), không so với `/`. Trước đây có 14 `verified_alive` giả ở target-a (`TestVerifyParentCanaryPastMaxPrefixes`).
- Host đã bị bỏ thì không tạo canary mới, verdict là `host_blocked` ngay.
- **Request đối chứng không mang danh tính:** `hs.good` được cắt bằng `strip` (Cookie, Authorization, token trong query). Lý do: trong `authz`, một `Sender` dùng chung cho nhiều role, và gửi lại cookie cũ có thể làm hỏng phiên có cookie xoay vòng (`TestSenderControlCarriesNoCredential`).
- **5 lỗi mạng liên tiếp tính theo host** (`hostState.errs`): chỉ bỏ host đó; host cuối cùng bị bỏ thì run dừng (`TestSenderErrorsPerHost`).
- `sent.jsonl` ghi cả UA mà `Sender` tự thêm (`TestSenderLogsAddedUserAgent`). `drafts/*.http` (từ `verify` và `export -drafts`) có UA của trình duyệt (`verify.WithUserAgent`), để ffuf/sqlmap không tự điền UA mặc định của chúng.
- **Thứ tự ưu tiên UA (`pickUA`):** `Snapshot.UserAgent` của phiên đăng nhập → traffic của đúng role → traffic của cả target → `marker.FallbackUA`.
- **Tagger:**
  - tên task `console.createTask` dùng `marker.TaskPrefix` (`flow` vẫn đọc được `jsh:`, `TestTaskPrefixRead`);
  - `createTask` gốc được bind lúc cài đặt, nên tên task không đi qua hàm nào mà trang có thể thay.
  - Còn lại: wrapper và socket stub vẫn lộ qua `toString`.
- **Từ bản đánh giá kiến trúc:**
  - race ở `results.Dir.Runs()` (đọc `d.runs` sau khi đã nhả lock; `TestRunsConcurrentWithFlows` bắt được race trên code cũ);
  - `noteCaptured` giữ body script khi không resolve (watch, `-resolve=false`): nay chỉ giữ khi `cfg.Resolve` (`TestNoteCapturedKeepsBodiesOnlyToResolve`).
- **Hoãn:**
  - bản nhớ cho `frontier.commit()`: một SHA cũ có thể có thêm URL giữa các tầng, nên cần làm mới thông tin từ index để giữ C3; đo trước rồi mới làm;
  - N2/N3 (xem mục 1.3b của tài liệu nghiên cứu).

---

## 29. Đợt 25J: Bước 1 của lộ trình sau review (dừng sớm nhanh hơn, request đối chứng, một bộ phân loại chặn dùng chung)

Nền tảng: review tổng hợp ngày 2026-11-13 và bản thẩm định các bẫy kỹ thuật của từng bước.

### 29.1. `verify`: xen kẽ prefix, ngưỡng tính trên draft gửi được
- `probeOrder`: draft được **gửi xen kẽ theo gateway prefix** (mỗi prefix một draft, rồi vòng tiếp theo; nhóm xếp theo thứ tự xuất hiện; thứ tự xác định). Draft không gửi thì xếp lên đầu. `verify.json` vẫn liệt kê theo thứ tự gốc của draft.
- Trên target-a ngày 2026-11-12, prefix thứ 3 trước đây chỉ tới ở probe thứ 51; nay tới ở probe thứ 3, nên cơ chế dừng sớm kích hoạt sau `GateAfter` probe (`TestVerifyGatedHostStopsEarly`: tối đa 8 request).
- Ngưỡng prefix là `min(3, số prefix của các draft được gửi)`. Việc đếm dùng cùng `preSkip`/`sendPlan` với `probe` (scope, policy Never, destructive, `-include-*`). Một prefix chỉ có draft logout không được tính (`TestVerifyGateCountsSentPrefixesOnly`). Draft nhiều candidate được tính theo candidate đầu tiên trong scope mà policy cho gửi.

### 29.2. `Sender`
- Request đối chứng nhận 429/1015 thì host chờ đúng `Retry-After` (tối đa 60 s), dùng cùng `rateWait`/`pauseLocked` với `onBlock` (`TestSenderControlRateAnswerPausesHost`).
- Chú thích nói rõ `consec = 1` sau khi request đối chứng qua: lần kiểm lại rơi vào lần chặn thứ 5 liên tiếp, tính cả lần đầu.

### 29.3. CLI: đọc `requests.jsonl` dạng luồng, một lần
- `scanEntries`, `uaCounts`, `pickUA`: mỗi file đọc một lần, không giữ các dòng.
- `verify` chỉ giữ danh sách request cho danh tính khi có phiên đăng nhập hoặc `-role` khác anon (`TestPickUA`).

### 29.4. `detect.Classify`: một bộ phân loại cho mọi nơi gọi
- `Block`, `BlockKind` (`request`, `client`, `signature`, `challenge`, `rate`), `RetryAfter` và các regex (`cfCodeRe`, `wafBlockRe`, `challengeRe`, `wafRe`) chuyển từ `replay` sang `detect`. `replay` chỉ còn alias và `ClassifyBlock` (đọc title HTML rồi gọi `detect.Classify`). `detect` vẫn chỉ dùng thư viện chuẩn; title là việc của nơi gọi.
- `BlockKind.BrowserMayPass()`: chỉ đúng với `challenge` và `signature`.
- **Frontier CDP:** trang có tài liệu chính là trang chặn mà không phải challenge (theo title: "Attention Required!", "Access denied | … Cloudflare") thì chỉ ghi lỗi cho trang đó (`blocked by a rule: …`) rồi đi tiếp. **3 trang liên tiếp** như vậy thì dừng `blocked`, như MAX-02 của engine HTTP. Tab không có body, nên ở đây cấm và luật chặn trông giống nhau; trang thứ 3 liên tiếp dừng cả hai.
- **Engine HTTP:** `Challenged.Kind` ghi loại chặn. `browserPassable` chỉ leo thang sang Chrome cho host có ít nhất một trang mà trình duyệt có thể qua (challenge, signature, hoặc loại chưa biết). Host chỉ gặp luật WAF, cấm hay rate limit thì không leo thang; `run.json` cảnh báo `not escalated to Chrome: …` (`TestBrowserPassable`). Đã thấy hai lần leo thang uổng cho `growth.target-c.example`.
- `polite()` của engine HTTP vẫn chỉ xét header, như trước.

### 29.5. Còn lại
- Bước 2: N1 thu hẹp, `verify` song song giữa các host, engine HTTP chạy gối các việc.
- Bước 3: bản nhớ cho `frontier.commit()`; tách `jsapi` và `archive/run.go`.

---

## 30. Đợt 25K: Bước 2.1 (N1 thu hẹp) và 2.2 (`verify` song song giữa các host)

Theo bản thẩm định các bẫy kỹ thuật của Bước 2: jar CDN tách theo (target, role) **trước**, sau đó mới bật HTTP/2 và song song hoá. Bước 2.3 (engine HTTP chạy gối các việc) là đợt riêng.

### 30.0. Hai điểm còn sót của Bước 1
- `polite()` của engine HTTP dùng `detect.Classify` trên status, header, title và đầu body. Gặp luật chặn trên đúng một URL (một probe hay một script bị 1020) thì chỉ bỏ URL đó. Challenge, cấm hoặc chặn theo chữ ký thì dừng như trước; rate limit đã có cơ chế chờ riêng.
- `page()`: trang 403 có nội dung trang WAF mà không có nhà cung cấp nào nhận (`wafRe`) giờ cũng là trang bị chặn, không còn được tính là trang qua.
- `wafRe` xét cả title. Chú thích của `BrowserMayPass` nói rõ ranh giới của 1006: trước đây nó phụ thuộc client (client tự khai `Go-http-client`); engine HTTP trình diện như Chrome thật, nên một 1006 nó gặp được coi là Chrome cũng sẽ gặp.

### 30.1. N1: một trình duyệt cho mọi client (`internal/uahints`)
- `LocalChromeMajor` lấy bản lớn từ `chrome --version` (một lần mỗi process). `ChromeUA(major)` là UA rút gọn của Chrome desktop. `Hints(ua)` là Sec-CH-UA, -Mobile, -Platform khớp **đúng UA được gửi** (UA Windows của phiên đăng nhập thì cho Windows và bản của nó); UA không phải Chrome thật (Firefox, Edge, HeadlessChrome, thư viện) thì không có hints.
- `Brands` là nguồn chung cho cả `browser.cleanUA`: Chrome, engine HTTP và `Sender` gửi cùng một danh sách brand.
- **Engine HTTP:** UA mặc định là của Chrome trên máy (`httpUA`: `-ua`, rồi UA của phiên đăng nhập, rồi Chrome trên máy; cũng là UA mà Chrome khi leo thang trình diện); thêm Sec-CH-UA* trên mọi request HTTPS (`TestClientHintsOnSecureOrigins`).
- **`Sender`:**
  - `prepare` viết lại request thô **trước khi gửi**, và `sent.jsonl` ghi đúng bản đó: bỏ header hop-by-hop (Connection, Keep-Alive, Proxy-Connection, Transfer-Encoding, Upgrade, TE khác `trailers`); thêm UA khi thiếu; thêm Sec-CH-UA* trên HTTPS khi thiếu (request ghi lại từ Chrome vẫn giữ hints gốc).
  - HTTP/2: `ForceAttemptHTTP2` cộng `AIA.DialTLS(…, true)` (`TestSenderWireIsTheBrowsers`: `HTTP/2.0`, đúng UA và platform, không còn Keep-Alive, `sent.jsonl` khớp).
  - UA mặc định là của Chrome trên máy, rồi mới tới `marker.FallbackUA`.
- **Cookie CDN theo role, chỉ trong bộ nhớ:**
  - `traffic.CDNCookie` nhận ra `__cf_bm`, `cf_clearance`, `_cfuvid`, `_abck`, `bm_sz`, `datadome`, `_px*`, `incap_ses_*`…
  - `Sender.cdnJar(role)` giữ cookie CDN mà host đặt cho role đó. Request sau của **cùng role** mang theo chúng, và bản mới thay bản cũ trong Cookie header; cookie phiên giữ nguyên.
  - Role khác không bao giờ nhận; request đối chứng (role rỗng) không nhận; không ghi ra đĩa.
  - `updateJar` bỏ qua cookie CDN: `__cf_bm` xoay vòng không còn bị coi là phiên xoay (`rotates`) hay cookie danh tính bị xoá (`TestSenderCDNCookiesPerRole`).
- **Chưa làm:** chuyển cookie từ engine HTTP sang Chrome khi leo thang (`Storage.setCookies`). Giờ UA hai bên đã khớp, nên việc này làm được, nhưng cần sửa đường đi của `Escalate`.

### 30.2. `verify -concurrency N` (mặc định 1)
- `byHost`: mỗi host do một worker xử lý tuần tự theo `probeOrder`. N worker chạy N host cùng lúc; `-rate` vẫn là trần chung (slot của `Sender` lấy từ `-concurrency`). Draft không gửi thì cho kết quả ngay.
- `lockHost` giữ host trong suốt "gate → canary → gửi → OPTIONS → noteGate", kể cả khi draft nhiều candidate rơi sang host khác. Không lồng khoá: mỗi probe chỉ giữ host của chính nó.
- `v.mu` bảo vệ các map dùng chung (`canaryFor`, `gateOf`, `hostMu`).
- Test `TestVerifyConcurrentHosts`: 3 host, mỗi host không bao giờ có 2 request cùng lúc, các host có chạy chồng lên nhau, verdict và số request giống hệt `-concurrency 1`.

---

## 31. Đợt 25L: Bước 2.3, engine HTTP cho các trang trong một tầng chạy gối nhau

### 31.1. Đo trước khi sửa (`JSH_PIPE_BENCH=1 [JSH_PIPE_RATE=R] go test -run TestPipelineBench -v ./internal/httpcrawl`)
Site giả: 20 trang, mỗi trang 10 script, RTT 120 ms, mỗi trang có một script chậm 1,5 s; 221 request.

| `-http-rate` | Trước (rào chắn theo trang) | Sau (rào chắn theo tầng) |
|---|---|---|
| 5 (mặc định) | 44,1 s, 100% trần | 44,1 s, 100% trần |
| 20 | 35,0 s, 32% trần | **13,1 s, 85% trần** |
| 50 | 35,0 s, 13% trần | **10,5 s, 42% trần** |

Ở mặc định, việc lấy trang tuần tự không tốn gì (trần rate là giới hạn). Khi tăng `-http-rate` để quét nhanh hơn, trước đây mỗi trang phải chờ script chậm nhất của nó, nên thời gian kẹt ở khoảng 35 s bất kể rate.

### 31.2. Thiết kế (`httpcrawl.pages`)
- Trang đầu tiên (seed, các file well-known, script của nó) vẫn làm **một mình**, rồi đưa kết quả vào hàng đợi ngay.
- Trong một tầng, các trang vẫn được lấy **lần lượt** (`page` → `spaCheck`), nên thứ tự lấy trang, bộ đếm challenge/MAX-02 và `hostState` không đổi. Nhưng việc tải script của một trang (`drain`) chạy song song với các trang tiếp theo, tối đa `maxPagesInFlight` = 4 trang cùng lúc, dùng chung bộ giới hạn `-http-rate`.
- Mọi thứ một trang tìm được nằm trong **bucket** của trang đó, mang theo qua `job.b`: route do script khai báo, API host (kèm script nguồn), và **trạng thái SPA tại lúc trang xong** (`b.spa`, dùng cho `addWith`, để một route được xếp loại như khi crawl từng trang một).
- **Cuối tầng** (khi trang kế tiếp sâu hơn, hoặc hàng đợi rỗng): chờ mọi lượt tải script, rồi đưa link, route và API host vào hàng đợi **theo thứ tự lấy trang**. Mọi thứ tìm được đều ở tầng sau, và hàng đợi luôn lấy tầng nông trước, nên thứ tự trang giống hệt crawl từng trang một (giống C3 của frontier).
- Kết quả trong một trang được **sắp theo script nguồn** (`bucket.sorted`). Trước đây 4 worker xong theo thứ tự ngẫu nhiên, nên cùng một crawl chạy hai lần có thể lấy trang theo hai thứ tự khác nhau. Nay crawl xác định hơn trước.
- API host (tối đa `frontier.MaxAPIOrigins`) được chọn theo thứ tự trang, rồi theo script.
- **Test:** `TestPipelinedPagesAreDeterministic`: site có độ trễ khác nhau theo path, 2 tầng, script khai báo route và API host. 4 trang cùng lúc cho ra **cùng danh sách trang, cùng thứ tự, cùng route, cùng API host được thăm dò** như 1 trang một lúc (chạy với `-race`, lặp 8 lần).
- **Khác biệt duy nhất:** khi bị dừng giữa chừng (429, challenge từ một script), những trang đã được lấy song song lúc đó vẫn xong; crawl từng trang một sẽ dừng sớm hơn đúng số trang ấy.

### 31.3. Còn lại
- Chuyển cookie từ engine HTTP sang Chrome khi leo thang, dùng `httpUA` cho Chrome của lượt leo thang; chỉ trong bộ nhớ của lượt đó, không ghi vào profile của role nào.
- `polite()` gặp challenge trên script hoặc request thăm dò thì dừng crawl, nhưng không ghi vào `Challenged`, nên không tự leo thang.
- Hai điểm nhỏ còn lại của review 2.1/2.2: `NewIdentity` vẫn nạp cookie CDN cũ từ traffic hoặc phiên đã lưu; `NewSender` không biết `-chrome` khi Chrome nằm ngoài PATH.
- Bước 3.

---

## 32. Đợt 25M: review của Bước 2.3, và các mục còn lại của Bước 2

### 32.1. Script dùng chung giữa các trang cùng tầng (sửa một lỗi của 25L)
- Review đúng, và mức độ cao hơn P2: tuyên bố "thứ tự trang giống hệt crawl từng trang một" của 25L **không đúng khi các trang dùng chung một script** (bundle `main.js`). Trang nào có worker giành `claim()` trước thì route của script đó rơi vào bucket của trang ấy. Chạy tuần tự thì trang trước luôn giành được; chạy gối thì tuỳ thời gian. Test của 25L không có script dùng chung.
- **Sửa:** `admit()` (kiểm challenge, credential trong URL, policy, rồi `claim`) được gọi cho **mọi script của một trang ngay khi lấy trang đó**, trên luồng chính, theo thứ tự lấy trang. Job đã được nhận đánh dấu `admitted`, `script()` không `claim` lại.
- Chunk do một script khai báo vẫn được `claim` lúc đọc script đó. Một chunk mà HTML của trang sau cũng khai báo có thể thuộc về trang sau. Tương tự, khi chạm `-resolve-max`, tập file được tải có thể khác bản tuần tự.
- **Test:** `TestPipelinedSharedScriptAttribution`. Trang b có script riêng khai báo `/b/route`, sắp trước `main.js`. Nếu `main.js` bị gán cho b thì `/shared/route` vào hàng đợi sau `/b/route`. Test **trượt 3/3 trên code 25L, qua 5/5 với `-race` trên code mới**.

### 32.2. Các điểm nhỏ của review 2.3
- **Dừng thì cắt cả việc đang chạy:** `Crawl` dùng context nội bộ, `setStop` huỷ nó, nên một script đang chờ `Retry-After` không giữ crawl lại. Đoạn cuối kiểm context **của bên gọi**, nên vẫn trả `ErrStopped` chứ không phải `context.Canceled` (`TestStopEndsWorkInFlight`: 429 kèm `Retry-After: 10` cộng một challenge, kết thúc trong 0,2 s).
- Bỏ `cr.found` và nhánh `b == nil` của `routes` (script của request thăm dò API sau vòng lặp không đưa gì vào hàng đợi, như trước).
- `MaxIdleConnsPerHost` 16 (4 trang, mỗi trang 4 worker, qua HTTP/1.1).

### 32.3. Challenge gặp trên script, request thăm dò hay kiểm tra SPA thì leo thang
- `politeAt(a, page, depth)`: một challenge mà trình duyệt có thể qua (`BrowserMayPass`) ghi **trang chứa** vào `Challenged` (`Asked`, `Kind`, có khoá, bỏ trùng). Với script là `j.page`/`j.depth`; với file well-known, kiểm tra SPA và thăm dò đặc tả là seed ở tầng 0. Không bao giờ ghi URL của file (Chrome sẽ mở nó như một trang). Trang hoặc file ngoài scope thì không ghi (`TestAssetChallengeNamesItsPage`).

### 32.4. Leo thang: Chrome tiếp tục như engine HTTP
- `httpcrawl.recJar` ghi lại từng Set-Cookie kèm thuộc tính. `Result.Cookies` là cookie **của ứng dụng** còn sống lúc kết thúc (đối chiếu với jar để bỏ cookie đã xoá, hết hạn hoặc bị ghi đè), trong scope, **không có cookie CDN**, vì cookie CDN gắn với client Go; Chrome tự lấy của mình (`TestCrawlCookies`).
- `engine.CookieParams`: cookie host-only theo URL đã đặt nó, cookie domain theo Domain; giữ SameSite và Expires.
- `escalationConfig`: UA của Chrome là `httpUA` (fallback giống phía HTTP), không profile, `Config.Cookies` chỉ trong bộ nhớ (`TestEscalationConfig`). `RunRecord` nạp chúng vào browser context trước trang đầu, cho cả `runPage` lẫn `runFrontier`.
- `run.json` có thêm `http.user_agent`.
- Gate `waf-check` 8a: request đầu tiên của Chrome tới `/cf-passes` mang `app_region=vn` (cookie mà fixture `/cf-links` đặt cho engine HTTP), không mang `__cf_bm=go-client`, và có UA đúng bằng `http.user_agent`.

### 32.5. Hai điểm nhỏ của review 2.1/2.2
- `NewIdentity` bỏ cookie CDN, từ cả phiên đã lưu lẫn traffic. Một `cf_clearance` lưu lúc `login` cũng bị bỏ, đúng nguyên tắc cookie CDN không phải cookie phiên (`TestIdentityLeavesCDNCookies`).
- `SenderOptions.ChromePath` (rỗng thì lấy `JSHARVEST_CHROME`). `verify`, `authz` và `replay` có thêm cờ `-chrome`.

### 32.6. Còn lại
Bước 3: bản nhớ cho `frontier.commit()` (giữ C3, làm mới URL, ThirdParty và Source từ index); tách `jsapi` khi làm phần class/#private; tách `archive/run.go` theo pha.

## 33. Đợt 25N: review của Bước 2, và Bước 3

### 33.1. `recJar` xác định phạm vi cookie như trình duyệt (lỗi P2 của review)
- Review đúng: `Set-Cookie` không có `Path` từ một URL lồng sâu (`/app/login`) được ghi với Path rỗng. Khi đối chiếu với jar ở gốc `/`, cookie đó không còn "sống" nên bị bỏ khỏi `Result.Cookies`. Vì vậy Chrome leo thang không nhận được cookie phiên. Đã tái hiện bằng test trước khi sửa.
- **Sửa (RFC 6265, như `net/http/cookiejar`):** `SetCookies` ghi lại phạm vi thật của mỗi cookie lúc nó được đặt:
  - `Path` thiếu, hoặc không bắt đầu bằng `/`, thì lấy thư mục của URL (`defaultPath`);
  - `Domain` thì bỏ dấu chấm đầu; Domain mà host không nằm dưới thì bị bỏ, đúng như jar từ chối;
  - `Max-Age < 0` là xoá; `Max-Age > 0` tính từ lúc đặt; `Expires` trong quá khứ là xoá.
- `cookies()`: khoá là tên + (domain hoặc host của cookie host-only) + path; bản đặt **cuối cùng** thắng. Cookie đã xoá, hết hạn, cookie CDN và cookie ngoài scope bị bỏ. Còn sống hay không được kiểm bằng jar **tại đúng path của cookie**. Cookie có Domain xuất ra là `.domain`; cookie host-only mang URL `scheme://host/path`, nên `CookieParams` đặt nó đúng host và path.
- Test `TestCrawlCookiesPathsAndDomains`: `sid` đặt từ `/app/login` có Path `/app`; `consent` có `Domain=x.test` do hai host đặt chỉ còn một cookie `.x.test`; `Domain=other.test` bị bỏ.

### 33.2. Kiểm tra SPA ghi đúng tầng của trang
`spaCheck(ctx, seed, depth)`: challenge gặp ở request kiểm tra SPA của một trang ở tầng D được ghi vào `Challenged` với tầng D. Trước đây luôn ghi tầng 0, nên Chrome leo thang mở trang đó như seed.

### 33.3. Bước 3.1 (bản nhớ cho `frontier.commit()`): đo rồi bỏ
- Đo bằng `JSH_ANALYZE_DIR=… go test -run TestAnalyzeBench ./internal/endpoints` (`analyze_bench_test.go`, chỉ chạy khi có biến môi trường). Trên 2.075 script thật (target-d, target-c, keycloak), lần đầu (lạnh) 9,2 s, các lần sau (cache `static/<sha>.json` ấm) 175–221 ms.
- `commit()` chạy một lần mỗi tầng, nên phần có thể tiết kiệm là khoảng 0,2 s mỗi tầng. Đổi lại phải giữ đồng bộ một bản nhớ với index (URL, ThirdParty, Source) và rủi ro phá tính xác định C3. **Không làm.** Chỉ làm lại khi số đo trên target thật cho thấy `commit()` là nút thắt.

### 33.4. Bước 3.2: tách `internal/jsapi/jsapi.go` (5.363 dòng)
- Tách cơ học thành 8 file, mỗi file có dòng `// This file: …`:
  - `jsapi.go` (555 dòng): kiểu, `Extract`, extractor, config;
  - `defs.go`: định nghĩa, chuỗi gán, base giữ trong thuộc tính;
  - `eval.go`: giải hằng;
  - `keys.go`: khoá của body và query;
  - `calls.go`: lời gọi request;
  - `strings.go`: endpoint dạng chuỗi;
  - `locate.go`: toạ độ;
  - `result.go`: dựng `Result`.
- **Kiểm không đổi ngữ nghĩa:** `JSAPI_SNAPSHOT=<danh sách file> go test -run TestSnapshot ./internal/jsapi` (`snapshot_test.go`) in JSON đầy đủ của `ExtractSource` cho từng file. Trên 2.543 file (`.js`/`.ts`/`.vue`/map của target-d, target-c, keycloak), md5 của toàn bộ output **giống hệt** trước và sau khi tách (`fe4841e7bedcd1e308bd068116063942`). `jsapi.Version` giữ nguyên.
- Khi làm phần `class extends`/`#private` (Keycloak 0/415) thì sửa trong `calls.go`/`defs.go`/`eval.go`, và chạy lại snapshot để thấy đúng phần output thay đổi.

### 33.5. Bước 3.3: tách `internal/archive/run.go` (1.268 dòng) theo pha
- Gồm 4 file:
  - `run.go`: điều phối, trạng thái, checkpoint;
  - `list.go`: liệt kê song song các nguồn và lấy capture (script/asset, URL mang credential);
  - `groups.go`: `done.log`, gom capture theo URL chuẩn hoá;
  - `fetch.go`: kiểm live trên server hiện tại, memento, WARC.
- Chỉ di chuyển code. Ghép phần thân 4 file (bỏ import và dòng trống) thì giống hệt bản gốc. Unit test và `archive-check` qua.

### 33.6. Hồi quy
- `regress.sh -j 3`: 17/18 gate qua.
- `frontier-tabs-check` mục 9 (session-app, `-role user -explore -depth 2 -tabs 3`) trượt một lần với marker `storage:session` khi 3 luồng cùng chạy. Chạy riêng 3 lần đều qua. Code của đợt này không đi qua đường đó (engine Chrome; `recJar`/`spaCheck` chỉ thuộc engine HTTP; tách jsapi không đổi output).

### 33.7. Còn lại
- `archive -live` chưa có cờ `-chrome` (vẫn đọc `JSHARVEST_CHROME`).
- `class extends` + `#private` cho Keycloak Admin REST API.

## 34. Đợt 25O: review của 25N

### 34.1. Cookie đặt trên địa chỉ IP
Review đúng (biên nhỏ): `Domain=127.0.0.1` trên host `127.0.0.1` từng được xuất thành `.127.0.0.1`. Địa chỉ IP không có subdomain. Theo `net/http/cookiejar` và trình duyệt, Domain bằng chính địa chỉ đó là cookie host-only; địa chỉ khác thì bị từ chối (`TestRecJarIPDomain`).

### 34.2. Request của trang bị đẩy về trang login (race của `-tabs` trong 25N)
- **Review đúng về cơ chế:** lần trượt của `frontier-tabs-check` mục 9 nhiều khả năng không phải flake ngẫu nhiên. Cơ chế được tái hiện tất định ở `session-check` 1b; đúng lần trượt đó thì không chạy lại được (chỉ xảy ra một lần khi 3 luồng cùng chạy). Keeper chỉ xét tài liệu chính, cookie dấu hiệu và `Clear-Site-Data`, trong khi `epoch` chỉ tăng khi tab gặp mất phiên đã vào `recover`. Nếu tab A nhận HTML `/members/d` khi phiên còn sống, rồi tab B mở `/account/expire` (xoá phiên phía server nhưng giữ cookie), thì chunk `d-chunk.js` của A bị 302 về `/login`. A vẫn tới `check` trước khi B kịp `recover`, nên trang bị chốt là thành công dù thiếu chunk.
- **Sửa:**
  - Capture có thêm `OnRedirect(from, to)` (từ `requestWillBeSent` có `redirectResponse`, trên mọi session của tab). Engine đếm theo tab các request bị đẩy về **đúng host và path của trang login**, từ path khác (`keeperLogin`, `isLoginRedirect`). Không tính khi trang login là `/` hoặc khi crawl bắt đầu từ trang login.
  - `check` trả về nguyên nhân `login-redirect` khi tài liệu chính không có dấu hiệu nào khác **và phiên được xác nhận đã mất phía server** (`goneOnServer`). Nếu có `check_url` thì hỏi nó. Nếu không, fetch trang mà login dừng ở đó (`redirect: "manual"`, `no-store`, không đụng tới trang trong tab); trả về 0 (bị redirect), 401 hoặc 403 thì là mất.
  - Lý do cần xác nhận: app có thể đẩy về trang login một script mà role không có quyền (trang của user xin chunk của admin) trong khi phiên vẫn sống. Mỗi trang như vậy sẽ tốn một lần recover, và có thể chạm `maxRecoveries`. Không xác nhận được thì bỏ qua tín hiệu, tức là giữ hành vi cũ.
  - `recover` xoá bộ đếm cùng chỗ với `keeperCSD`. Sau đó trang được thăm lại như mọi nguyên nhân khác (`blame`).
- **Gate:** `session-check` mục 1b. Fixture `/members/late` (không có link nào trỏ tới) xoá phiên phía server rồi xin chunk. Code mới cho ra `login-redirect -> relogin` hai lần (lần đầu và lần thăm lại), phiên không mất. Binary của 25N cùng kịch bản thì chốt trang là thành công, không có event nào cho trang đó, trong khi `late-chunk.js` bị 302 về `/login`. Mục 1 vẫn ra đúng các event như trước.
- Còn lại: API trả 401/403 cho request của trang (thay vì redirect) không được dùng làm tín hiệu, vì quá nhiễu (endpoint bị từ chối theo quyền là chuyện thường).

## 35. Đợt 26A: request đi qua class (`class extends`, `#private`, `url.pathname`), jsapi v24

### 35.1. Review 25O: nhánh `check_url` của `goneOnServer`
Review đúng ở cả hai điểm. `check_url` khác origin với tab (bị gửi với `credentials: "omit"`) và fetch lỗi (`-1`) đều từng bị coi là phiên đã mất. Giờ chỉ hỏi `check_url` khi nó cùng origin với tab; nếu khác origin thì dùng trang đích của login như nhánh còn lại. Fetch lỗi là "không xác nhận được", nên tín hiệu bị bỏ qua.

### 35.2. Phương pháp
- Phát triển chỉ trên **fixture dev** viết cho đợt này (`internal/jsapi/classes_test.go`), mô phỏng hai mẫu SDK client phổ biến, không chép cấu trúc của Keycloak:
  - **A:** resource class kế thừa base class giữ transport trong trường `#private`. Method là class field tạo bởi factory được kế thừa (`list = this.makeRequest({…})`). Path đưa vào qua `super(client, {path})`. Transport dựng URL bằng `new URL(base)` + `url.pathname = join(…)` + template RFC 6570 `parseTemplate(t).expand(params)`.
  - **ATS:** như A, nhưng ở dạng TypeScript emit khi không bật `useDefineForClassFields` (field gán trong constructor sau `super(…)`, method thường).
  - **B:** service dùng trường public, method kế thừa (`this.get(path)` → `this.http.send(…)`), tiền tố đưa qua `super(http, "/prefix")`, client là instance truyền vào constructor (`new InvoiceService(new ApiClient("/api"))`).
- Mỗi fixture được đọc ở 3 dạng: nguyên bản, minify bằng esbuild (tên `#private` bị rút còn `#e`/`#t` và trùng giữa các class), và đi qua nhánh hạ cấp `transformJSLower`.
- Kiểm không hồi quy bằng `TestSnapshot` trên **corpus dev** (2.568 file của `_live_25e_max`, **không có Keycloak**, vì xem diff trên Keycloak cũng là nhìn vào tập kiểm mù). Tập kiểm mù chỉ chạy **một lần**, sau khi code đã chốt.

### 35.3. Cơ chế (`internal/jsapi/classes.go`)
- **Chỉ mục class (`indexClasses`, sau `methodVisitor`):**
  - Mỗi class có: constructor, đối số của `super(…)`, member theo tên (method, field gán hàm; tên `#private` giữ cả `#`), và field (initializer, `this.x = …` trong constructor, không tính hàm lồng có `this` riêng).
  - Thêm: nơi `new C(…)` cho mỗi class, và các phép gán `u.pathname/search/hash = …`.
  - Field gán hàm public cũng được thêm vào `methodDefs`.
- **Giải method theo cấu trúc, lúc summarize (`classCallee`):**
  - `this.m(…)` là member của class sở hữu code hoặc của class cha (lên tối đa 8 tầng).
  - `this.f.m(…)` là method của class mà field `f` được gán bằng `new C(…)` trong class đó hoặc class cha.
  - Class sở hữu được tính từ `fnStack`, chỉ trong phần summarize đẩy vào (phía trên `fnBase`). Hàm thường có `this` riêng; arrow dùng chung `this` bên ngoài. Ở pha gọi, class đó là `entryClass`, lấy từ `thisStack` (initializer của field hoặc method của class).
  - Summary được cache theo hàm, nên ở bước này không bao giờ đi theo tham số đã gắn.
- **Giải lúc đọc (`lazy`, `readCallee`):** `this.http.send(…)`, với `http` là thứ constructor nhận vào, chỉ biết được khi đã gắn tham số. Summary giữ lời gọi đó như ứng viên cuối (`lazy`), chỉ dùng khi hàm không có lời gọi request nào khác.
- **Instance (`bindInstance`):**
  - Đọc một lời gọi trên `this` trong class thì cần một instance của class đó. Constructor của class được gắn với đối số của `new C(…)` duy nhất trong script (`madeOnce`; không có hoặc nhiều hơn một thì là không biết). Constructor của từng class cha được gắn với đối số `super(…)` tương ứng; class không có constructor chuyển nguyên đối số lên cha.
  - `x.self` là instance đang đọc. `this.f` đọc giá trị field **của class đó** (`thisFieldValues`, `thisFieldExpr`), không còn đọc bảng `thisProps` chung theo tên, vốn trộn `#e` của mọi class.
  - Gọi qua field (`this.#transport.request(…)`) thì gắn tham số của method trước, tính trong instance của bên gọi, rồi mới đẩy instance mới (`readVia`, `readBound`).
- **URL object (`evalURLObject`):** `const u = new URL(base); u.pathname = P` cho ra origin của base cộng giá trị của `P`, trong đó `u.pathname` bên trong `P` là path của base. Gán `pathname` hai lần thì không giải (giá trị phụ thuộc luồng chạy).
- **Giá trị và nhánh:**
  - `.expand(…)` trên kết quả của lời gọi parse template trả về chính template (`templateArg`).
  - `s.slice(a, b)` của chuỗi đã biết.
  - `?:` chọn đúng một nhánh khi điều kiện giải được (`condTruth`): `endsWith`/`startsWith`/`includes`, và `===`/`!==` với `charAt(s.length - 1)`. Chỉ áp cho **biểu thức ổn định** (`stableExpr`: literal, biến, template hay phép nối của chúng, field của instance đang đọc), không áp cho `x.value` của ref hay thuộc tính của object do trang thay đổi.
- **Gắn tham số (`bindParams`):** dùng giá trị mặc định (`(e, t = {})`, `({path = ""})`) và đi qua spread (`{client, ...settings}`, qua `objectValueSpread`; spread này cũng dùng trong `memberN`). Đối số đọc field của instance (`this.prefix + path`) thì tính cả biểu thức, không lấy riêng tham số (`readsSelfField`).
- **Lời gọi client:** `this.post(url, body)` mà class của app có hoặc kế thừa method `post` thì được đọc như helper, không còn đọc như `client.post`.
- **Nhánh hạ cấp:** esbuild hạ arrow trong class field thành `function` và gọi tới `_this`, nhưng **không khai báo `_this` ở đâu** (initializer của field không có hàm bao). Đây là artefact của chính bước hạ cấp của jsharvest. `isThis` coi biến `_this`/`_thisN` chưa khai báo (`Decl == NoDecl`) là `this` (`loweredThis`).

### 35.4. Kết quả
- **Fixture dev:** A, ATS và B ra đúng toàn bộ endpoint ở cả 3 dạng (A 5/5, ATS 5/5, B 2/2, kèm body `card`). Trước đợt này: A 0/5; B chỉ ra `POST /{}/pay`, sai tiền tố.
- **Snapshot corpus dev (2.568 file):** output giống hệt HEAD, chỉ khác số `version`. Hai lệch đã sửa trong đợt:
  - `?:` trên `api.charAt(api.length-1) === "/"` từng đưa ra nhánh `slice` sai (`…/fe/v`);
  - `condTruth` từng chọn nhánh theo giá trị khởi tạo của một ref Vue.
- **Đánh giá dev (`groundtruth_v4`):** 288/288, 30/30, 7/7, 158/158, 28/28; FP = 0; thời gian và RAM như trước (`output/_groundtruth/eval_26a_v24_dev.json`).
- **Gate:** `perfgate` 2.000 script trong 8,2 s, RSS 274 MB; `endpoints-check`, `crosscheck-check` và unit `-race` toàn bộ đều qua.
- **Kiểm mù Keycloak 26.8.2 (chạy một lần): vẫn 0/415** (catalog 11 dòng, 1 dòng có method; 21 bundle, `b_err = 0`, `low = 2`; 3,1 s, RSS 217 MB; `output/_groundtruth/heldout_keycloak_v24.json`). Cơ chế tổng quát đã đúng trên các mẫu dev nhưng không chuyển sang được bundle thật. Chưa xem nguyên nhân: xem là dùng tập kiểm mù làm dev.

### 35.5. Còn lại
- Class đã hạ cấp xuống ES2020 (`#private` thành `WeakMap` + `__privateGet(this, _x)`; field thành `__publicField(this, "x", v)`; tên helper bị minify) cho ra 0 trên fixture A. B (không dùng field hay private) vẫn đúng.
- Đa hình: method được giải theo class định nghĩa code (summary được cache theo hàm), nên method của cha gọi `this.m()` mà lớp con ghi đè thì vẫn đọc bản của cha.
- `this` truyền làm đối số (`new Projects(this)`) được đọc trong instance đang đọc, không phải instance của bên gọi.
- Quyết định cần người dùng chốt: chẩn đoán 0/415 trên Keycloak (khi đó Keycloak thành tập dev, và cần một tập kiểm mù mới, ví dụ một app khác dùng SDK dạng class), hay giữ Keycloak mù và mở rộng fixture dev.

## 36. Đợt 26B: review 26A, Keycloak chuyển thành tập dev, jsapi v25

### 36.1. Quyết định phương pháp
- Theo khuyến nghị (a) của review 26A: **Keycloak 26.8.2 không còn là tập kiểm mù**. Từ đợt này nó là tập dev và tập chẩn đoán. Mọi con số Keycloak từ đây là số dev, không chứng minh khả năng tổng quát hoá.
- **Cần một tập kiểm mù mới** (một app khác dùng SDK dạng class, có OpenAPI chính thức) trước khi tuyên bố bất cứ điều gì về tổng quát hoá. Việc chọn và tải app đó cần người dùng chốt (tải package từ registry là gửi request ra ngoài).

### 36.2. Bốn lỗi review chỉ ra (đều có thật, đã sửa)
1. **`const X = class Y {}`:** `methodVisitor` ghi `classOf` bằng `Y`, đè lên `X`. Giờ không ghi đè. `classByVar` ghi mọi tên: tên khai báo, `const/let X = class …`, `X = class …`.
2. **`madeOnce` chỉ nhận đúng một `new C(…)`:** thay bằng `instanceSites`, gồm các nơi `new` của class **và của các class con** (base class nhiều khi chỉ được tạo qua class con, mỗi class con một `super(…)`), tối đa 4 nơi. Không có nơi nào (`new` nằm ở chunk khác) thì đọc với đối số không biết. Lời gọi được đọc lần lượt trong từng instance.
3. **Instance chỉ được gắn trong `helper()`:** giờ `callVisitor` đọc **mọi lời gọi có dùng `this`** trong class trong từng instance (`callInInstances`), kể cả `fetch(this.base + …)` trực tiếp. `readsThis` đi qua cả hằng cục bộ (`const url = new URL(this.base)`) và `url.pathname = …`. Lời gọi từ bên ngoài (`sdk.raw.send(…)`, `api.users.find(…)`) được đọc trong instance mà receiver trỏ tới (`instanceOf` qua thuộc tính object và field của instance).
4. **Hàm đã hạ cấp trong class field:** `thisClass` nhận cả `FuncDecl` mà class field trỏ tới.

### 36.3. Hệ quả cần chặn khi đọc mọi lời gọi trong instance
- **Khung của helper:** một lời gọi trong method chuyển tiếp nguyên tham số làm đuôi path (`this.request("GET", e)`, `` `${this.baseUrl}${t}` ``, kể cả qua hằng cục bộ hay nhánh `?:` trong template) là khung, endpoint thật nằm ở nơi gọi. Lời gọi đó không được đọc trong instance (`forwardsPath`). Tham số đứng sau `/` là một đoạn path, vẫn được đọc.
- **`frame`:** ghi `inst` cho **mọi lời gọi trên chuỗi helper** đã đi qua (`readChain`), không chỉ tầng ngoài cùng. Một instance được coi là đầy đủ hơn khung cả khi số chỗ trống bằng nhau nhưng biết nhiều chữ hơn, **với điều kiện nó khớp khung** (`fills`). Nhờ `fills`, `…/marketplace/apps/{}` không được coi là bản cụ thể của khung `…/apps/{}`.
- **Literal:** một lần đọc trong instance mà không sinh endpoint nào thì hoàn tác các literal nó đã đánh dấu (`usedLog`). Nhờ vậy URL collector trong một object cấu hình vẫn còn trong `paths`.
- **Client stub:** `Z.get(…)`, với `Z` là instance của class có method `get` thân rỗng (stub hoặc thư viện), vẫn được đọc như client. Chỉ method thật sự làm request (`requestMethod`: có summary) mới được đọc như helper.

### 36.4. Cơ chế mới tìm ra nhờ chẩn đoán Keycloak (đều tổng quát)
- **Hàm nối path variadic (`joinCall`):** `function g(...e) { return e.map(cb).join(SEP) }` (urlJoin, joinPaths): các đối số được nối bằng `SEP`. Khi `cb` có dùng `SEP` (tức là cắt dấu phân cách ở hai đầu mỗi phần), mỗi chỗ nối chỉ còn một `SEP`. `map` làm việc khác (ví dụ viết hoa) thì không áp. `[a, b].join(sep)` trên mảng literal cũng được đánh giá. Đây là **nút thắt chính** của 0/415.
- **`#private` theo class khai báo (`lookupClass`, `privOwner`):** `this.#e` trong code của `za` là `#e` của `za`, kể cả khi instance thuộc class con khai báo một `#e` khác (`x$` có `#e = new k$(t)`). Parser liên kết lần dùng với khai báo (`root(use) == root(decl)`). Fixture A có thêm ca che tên; tắt `lookupClass` thì 6 biến thể trượt.
- **Field gán lại ngoài constructor:** `this.x = …` trong mọi method được thu thập (`later`). Khi field có giá trị khác, giá trị giữ chỗ của constructor (`""`, `null`, `void 0`, `!1`, `0`) bị bỏ (ví dụ `customerProfileBaseUrl = ""` trong constructor, `= ua()` trong `init`).
- `this.<field> + param` trong method của class được tách thành (base, path) theo cấu trúc (`splitPair`), không cần đoán theo tên.
- Hằng số chỉ gồm literal (`"https://…".trim()`) là biểu thức ổn định, và tính được "thật/giả". Biến khác (chuỗi query dựng lúc chạy, tham số) thì không.

### 36.5. Kết quả
- **Fixture dev:** A, ATS, B, C (4 lỗi của review), D (nối path, kèm ca đối chứng `map` viết hoa); mỗi fixture ở 3 dạng (nguyên bản, minify, hạ cấp): tất cả đúng.
- **Snapshot corpus dev (2.568 file, so với v24):** chỉ 2 file đổi endpoint, đều có chủ đích:
  - target-c growth SDK: 5 endpoint `customer-profiles` có base thật `https://api.target-c.example/growth/api/v1.0` thay cho `{}`;
  - target-d: hai khung jsdelivr chung `…/npm/{}@{}` được thay bằng bản cụ thể `…/npm/@types/{}@{}`.
- **Đánh giá dev (`groundtruth_v4`):** 288/288, 30/30, 7/7, 158/158, 28/28; FP = 0 (`output/_groundtruth/eval_26b_v25_dev.json`).
- **Keycloak (giờ là dev): 0/415 lên 341/415** (`output/_groundtruth/keycloak_dev_v25.json`).
  - 74 operation còn thiếu: kiểm chuỗi trên code đã ship cho thấy gần như tất cả **không có trong code UI dưới path đó**. Ví dụ `client-templates` (23 operation, 0 lần trong code); `/roles/{name}/composites` trong khi UI dùng `/roles-by-id/{id}/composites`; `members/count`, `permission/search`. 4 ca mà phép kiểm thô coi là "có" thì thực ra code chỉ có method khác. Như vậy 341 là gần trọn phần lấy được bằng phân tích tĩnh.
  - 79 dòng có method mà không khớp ground truth: phần lớn là trích xuất đúng theo code nhưng không có trong bản OpenAPI (`ssf/*`, `vc/*`, `ui-ext/*`, `authz/…/permission/{type}/{id}`). Precision không đo chính xác hơn được với ground truth này.
- **Gate:** `perfgate` 2.000 script trong 7,9 s, RSS 257 MB. `crosscheck-check` mục 7 (`recycleTab`, `page1` bị treo V8) trượt một lần (`hasP1=false`: script của trang bị treo không kịp được bắt); chạy riêng 2 lần đều qua. Mục này thuộc engine Chrome, không đi qua jsapi.

### 36.6. Còn lại
- Tập kiểm mù mới (36.1).
- Class hạ cấp ES2020 (`WeakMap` + `__privateGet`/`__publicField`, tên helper bị minify); target-c thật có dùng dạng `U(this, "x", v)`.
- Đa hình (method của cha gọi `this.m()` mà lớp con ghi đè); `evalURLObject` với `+=`, gán trong hai nhánh, hay `this.#url.pathname`; getter/setter/static.

## 37. Đợt 26C: review 26B, tập kiểm mù mới (Appwrite Console SDK), jsapi v26

### 37.1. Hai lỗi review 26B chỉ ra (có thật, đã sửa, có test bắt được lỗi cũ)
1. **Bất định:** `subclasses` (và `classByVar` lấy từ `classOf`, `later` lấy từ `info.members`) từng được dựng bằng cách lặp map. Với hơn `maxInstanceSites` class con, tập instance được đọc thay đổi giữa các lần chạy. Giờ mọi thứ theo thứ tự khai báo (`classOrder`, `c.List`). `TestInstanceSitesDeterministic`: 9 class con, 30 lần chạy; với code cũ trượt ngay lần đầu.
   - `maxInstanceSites` nâng từ 4 lên 8 (SDK thật có hàng chục resource; Keycloak có 18 class kế thừa `za`).
2. **`forwardsPath` xét mọi đối số:** `create(payload) { return fetch(this.base + "/items", payload) }` bị coi là khung, nên mất base của instance. Giờ chỉ xét **đối số URL** (`urlArgs`):
   - `fetch`/client: đối số đầu;
   - helper có summary: vị trí tham số URL của nó;
   - còn lại: đối số đầu tiên không phải object và không phải literal method HTTP, cộng `url/uri/endpoint/path/pathname` của object options.
   - `TestForwardsPathReadsTheURLOnly`: code cũ cho `{}/items`.
- **Biên nhỏ:** `const X = (class Y {})` (`ungroup`); hàm nối có `.filter(…)` trước hoặc sau `map`. Chưa làm: dạng `(base, ...parts)` có tham số cố định đứng trước.
- **Snapshot corpus dev so với v25:** chỉ một thay đổi, là cải thiện: `POST https://api.target-c.example/growth/api/v1.0/customer-profiles` thay cho `{}/customer-profiles`. Lời gọi `la(this.customerProfileBaseUrl, n, f, …)` trước đây bị bỏ vì `n` và `f` (body) bị xét như path.
- **Đánh giá dev:** 100%, FP = 0. Keycloak (dev) giữ 341/415. Khi đo trên cùng dữ liệu, binary của đợt này và HEAD mất thời gian như nhau; phần tăng thời gian ở lần đo trước là do máy đang bận (load 16).

### 37.2. Tập kiểm mù #2: `@appwrite.io/console@21.1.0`
- **Chọn:** theo review. Console SDK của Appwrite là các service class dùng chung một `Client`; spec và SDK được sinh từ cùng một nguồn.
- **Phiên bản:** README trên registry ghi "targets Appwrite server version 2.7.x". Spec `appwrite/specs` `specs/2.7.x/open-api3-2.7.x.json` được ghim ở commit `218c99f7593e854ebf3089137aae4ad8bd50c48d` (2026-11-05), trước ngày SDK phát hành (2026-11-06).
- **Tải:** người dùng đã cho phép. Tarball có SHA-1 `b38ca730…` khớp registry; SHA-256 `30683208…`. Spec SHA-256 `a10f75cd…`. Cả hai nằm ở `output/_groundtruth/heldout_appwrite/` (0600). **Tarball không được giải nén hay đọc** trước khi chạy đánh giá; phiên bản lấy từ metadata của registry.
- **Ground truth (chốt trước):** operation có `x-appwrite.platforms` chứa `console`, gồm **1.098** operation (99 deprecated), không có khoá trùng. Path chuẩn là `/v1` + path của spec, mỗi `{tham số}` thành `{}`. File `heldout_appwrite_gt.json` có SHA-256 `0f4ff325a51efb267a15569fab16ba5f63d2882100ec757832c278185307c9de`.
- **Luật so khớp (chốt trước, trong `eval_heldout_appwrite.py`):**
  - Dòng có method khớp nếu METHOD bằng nhau và một trong các path ứng viên bằng path chuẩn, hoặc bằng path của spec khi base để trống.
  - Bỏ dòng `string`/`doc`. Dòng `third_party` **được tính**, vì host API khác host loopback dùng để phục vụ SDK; báo riêng số khớp nhờ dòng `third_party`.
- **Cách chạy:**
  - Phục vụ mọi file `.js/.mjs/.cjs/.map` của package qua loopback, giữ nguyên đường dẫn, với một `index.html` nạp tất cả script;
  - `crawl -engine http -depth 1 -archive=false -probe=false`, rồi `endpoints` lạnh, tất cả trong `unshare -rn`.
  - **Chạy một lần**: file đánh dấu `heldout_appwrite_RUN.json` khiến lần chạy thứ hai bị từ chối.

### 37.3. Kết quả kiểm mù #2 (chạy một lần, commit `8f7c291`, working tree sạch)
- **1.070/1.098 operation (97,4%)**; không tính deprecated thì 971/999 (97,2%). Chỉ 1 operation khớp nhờ dòng `third_party`.
- Catalog có 1.083 dòng, 1.081 dòng có method, **10 dòng không khớp spec**. 3 script được phục vụ (185 mục index tính cả source map); `b_err = 0`, không hạ cấp; `endpoints` 1,6 s, RSS 171 MB. Kết quả lưu ở `output/_groundtruth/heldout_appwrite_v26.json`, file đánh dấu ở `heldout_appwrite_RUN.json`.
- **28 operation bị thiếu** (chỉ là quan sát; **không chỉnh code theo kết quả này**):
  - `avatars/*` (9), cùng các URL `…/download`, `…/preview`, `…/view` (file, deployment, invoice). Theo tên, nhiều khả năng đây là method SDK **trả về URL** (cho `<img src>` hay link tải) mà không tự gửi request. Đây là một loại "dựng URL" mà jsapi chưa coi là endpoint.
  - `monitors/*`, `alerts/*`, `organizations/{}/monitors|alerts`: chưa rõ có trong SDK hay không.
- **10 dòng không khớp:** `account/devices*`, `project/oauth2/vipps*`, `project/policies/account-devices`, `proxy/rules/{}/function|redirect|site`. Có trong SDK, không có trong spec ghim: nhiều khả năng do lệch phiên bản giữa SDK và spec, không phải trích xuất sai.
- **Ý nghĩa:** cơ chế class của 26A–26C tổng quát hoá được sang một kiến trúc SDK khác (service class dùng chung client) mà không cần chỉnh theo app. Tập kiểm mù này **đã dùng**; mọi việc chỉnh theo kết quả ở trên sẽ biến Appwrite thành tập dev.

### 37.4. Còn lại
- Method SDK trả về URL (không gửi request) chưa được coi là endpoint. Đây là ứng viên tổng quát cho đợt sau, cần fixture dev riêng.
- Dạng `(base, ...parts)` của hàm nối path; class hạ cấp ES2020 (`WeakMap`, `__publicField`); đa hình.
- Tập kiểm mù tiếp theo (nếu cần): một bundle UI đã minify và chia chunk (ví dụ `@medusajs/dashboard`).

## 38. Đợt 26D: review 26C

### 38.1. `urlArgs` khi helper đã có summary (P2 của review, có thật)
- `create(payload) { return this.postItem(payload) }`, với `postItem` có path cố định `"/items"`: `postItem` có summary nhưng `s.urls` rỗng, nên code rơi xuống nhánh dự phòng "đối số đầu không phải object". Kết quả là `payload` bị coi là path được chuyển tiếp, lời gọi không được đọc trong instance, và mất base (`POST {}/items`). Tương tự với `putItem(id, …)` dùng `"/items/" + id`.
- **Sửa:** khi helper có summary thì **summary quyết định**, không đoán. Ứng viên chỉ là các tham số helper dùng làm **nguyên path** (`pathParams`):
  - `s.urls`;
  - path của một `fetch(base + path)` mà helper tách base;
  - tham số helper chuyển nguyên cho helper khác;
  - tham số mà URL của leaf, qua hằng cục bộ và `?:`, đặt ở vị trí path (`forwardVars`, chung logic với `pathForward`).
  - Không có ứng viên nào nghĩa là không chuyển tiếp path. Chỉ lời gọi `lazy` mới dùng nhánh đoán, và nhánh này nhận cả object nằm trong biến (`x.object`).
- `TestForwardsPathThroughHelpers`: code 26C cho thêm `POST {}/items` và `PUT {}/items/{}`.
  - Phiên bản đầu của bản sửa (chỉ `s.urls` cùng path tách base) làm khung `/console-api{}` của target-c quay lại. Snapshot bắt được, nên `forwardVars` được thêm vào. Snapshot corpus dev cuối cùng **giống hệt v26**.
- **Biên nhỏ:** `ungroup` trong `methodVisitor` và `classOfExpr`; nối path có `filter` bỏ các phần `""`. Comment "at most four" sửa thành "eight".

### 38.2. Kết quả lưu cho commit `e886969` (v27)
- Đánh giá dev: 100%, FP = 0 (`output/_groundtruth/eval_26d_v27_dev.json`). Keycloak (dev): 341/415 (`keycloak_dev_v27.json`). Regress 18/18.

### 38.3. Đọc con số Appwrite (nhận xét của review)
- Luật so khớp cho phép khớp theo `/v1/…` hoặc theo path của spec khi base để trống, nhưng harness **không đếm riêng** hai nhánh. Output của lần chạy nằm trong thư mục tạm đã xoá, và harness từ chối chạy lại, nên không tách được nữa. Nhận xét của review hợp lý: 10 dòng không khớp đều có dạng `{}/…` với `bases=[]`, nên phần lớn dòng khớp nhiều khả năng cũng là `{}/…`.
- Điều này bình thường với một package SDK thuần, vì base do app đặt (`setEndpoint`). Nghĩa là 97,4% đo khả năng trích **method + path** qua service class, không đo khả năng giải base. Harness kiểm mù sau phải đếm riêng hai nhánh này.

### 38.4. Hướng tiếp
- "Method trả về URL" (`avatars/*`, `download/preview/view`): chỉ nhận khi URL dựng từ base của client hoặc path API rõ ràng, có fixture âm (hàm nối URL của UI, tài nguyên tĩnh), để không làm phình ngân sách `verify`.
- Kiểm mù #3 trên bundle UI thật đã minify và chia chunk (`@medusajs/dashboard`), harness đếm riêng `/v1/…` và path khi base để trống. Cần người dùng cho phép tải.

## 39. Đợt 26E: kiểm mù #3 trên bundle UI thật (`@medusajs/dashboard`)

### 39.1. Chuẩn bị (người dùng cho phép tải; mọi thứ chốt trước khi giải nén)
- **Gói:** `@medusajs/dashboard@2.22.7` (bản mới nhất, phát hành 2026-11-13, dựng sẵn và chia chunk; `dist/app.mjs` là entry). Dashboard để `@medusajs/js-sdk` là dependency bên ngoài, nên tải thêm `@medusajs/js-sdk@2.22.7`, cùng `gitHead` `2ed5d39e343a7794363a90c57d70e89f74a75fde`. Một bản admin triển khai thật gói chung cả hai. SHA-1 của cả hai tarball khớp registry.
- **Spec:** `medusajs/medusa` `www/apps/api-reference/specs/admin/openapi.full.yaml` tại đúng commit đó (spec ghi `info.version` 2.22.6), SHA-256 `4069a9aa…`.
- **Ground truth:** 420 operation (404 `/admin/*`, 16 `/auth/*`, 2 deprecated), không có khoá trùng. File `heldout_medusa_gt.json` có SHA-256 `114ff138ae8120386111033c40f1526876ab08724c6ae23137bff4887be9947f`.
- **Harness `eval_heldout_medusa.py`:** hai chế độ trong cùng một lần chạy.
  - **`entries`** (con số chính, giống crawl một bản admin thật): import map `@medusajs/js-sdk` → entry ESM của js-sdk; script module là các entry trong `exports` của dashboard (`app/lib/hooks/components.mjs`) cộng entry của js-sdk; crawler tự tìm chunk.
  - **`all`:** nạp mọi file JS của hai gói, để tách lỗi tìm chunk khỏi lỗi trích xuất.
  - **Đếm riêng theo từng operation:** khớp theo path đầy đủ; chỉ khớp khi base để trống; chỉ nhờ dòng `third_party`; chỉ nhờ dòng `source_only`.
  - **File đánh dấu:** ghi sau khi hai lần crawl xong và trước khi chấm điểm. Một lần chạy hỏng giữa chừng (chưa thấy kết quả) thì chạy lại được; đã chấm điểm rồi thì không.

### 39.2. Kết quả (chạy một lần, `efcd3fe`, working tree sạch; `output/_groundtruth/heldout_medusa_v27.json`)

| Chế độ | Khớp | Path đầy đủ | Chỉ khi base trống | Dòng có method / không khớp | File JS tìm thấy / phục vụ | `b_err` / hạ cấp | `endpoints` |
|---|---|---|---|---|---|---|---|
| `entries` | **300/420 (71,4%)** | 300 | 0 | 349 / 49 | 430 / 564 | 0 / 0 | 2,3 s, 133 MB |
| `all` | 300/420 | 300 | 0 | 326 / 26 | 491 / 564 | 0 / 0 | 3,9 s, 336 MB |

- Hai chế độ thiếu **đúng cùng 120 operation**: khâu tìm chunk không phải nút thắt. `entries` chạm trần `-resolve-max (500)` nhưng recall không đổi.
- Không có operation nào khớp chỉ nhờ base trống, `third_party` hay `source_only`.
- **Dòng không khớp** (chỉ là quan sát): `@medusajs/js-sdk` gồm cả Store API (`/store/carts…`, `/store/customers…`) và `/rbac/*`, vốn không có trong Admin spec. Auth được dựng theo template `/auth/{actor}/{provider}…`, trong khi spec liệt kê giá trị cụ thể (`/auth/user/…`, thuộc 6 operation thiếu của `/auth/user`). Nhiều khả năng đây là trích xuất đúng nằm ngoài ground truth, không phải FP.
- **120 operation bị thiếu** rải đều trên nhiều tài nguyên (`products` 9, `promotions` 8, `workflows-executions` 8, `orders` 6, `store-credit-accounts` 6…). Chẩn đoán đòi đọc code, tức là biến Medusa thành tập dev. **Chưa làm**, chờ người dùng quyết định.

### 39.3. So sánh ba lần kiểm mù
- **Keycloak** (0/415 ở 26A, sau đó chuyển thành dev): cơ chế class lúc đó chưa đủ.
- **Appwrite** (97,4%): SDK thuần, mỗi method một lời gọi `client.call` theo một mẫu đều.
- **Medusa** (71,4%): bundle UI thật cộng SDK. Đây là con số sát với crawl một ứng dụng thật nhất trong ba lần.

## 40. Đợt 26F: Medusa chuyển thành tập dev, GET mặc định của fetch, jsapi v28

### 40.1. Quyết định phương pháp
- Theo review 26E, hướng (c): từ đợt này **Medusa (`@medusajs/dashboard` + `@medusajs/js-sdk` 2.22.7) là tập dev**, không còn là tập kiểm mù #3. Con số 300/420 ở mục 39 là kết quả kiểm mù cuối cùng của tập này; mọi con số Medusa từ đây là số dev. Tập kiểm mù #4 (một bundle UI thật khác) sẽ được đề xuất gói và spec cụ thể, và chờ xác nhận trước khi tải.
- Harness dev tách riêng (bản sao trong scratchpad, không có file đánh dấu, `-resolve-max` cấu hình được). Harness kiểm mù vẫn từ chối chạy lại.

### 40.2. Chẩn đoán
- **Trần resolve (bước đầu theo review):** chạy lại chế độ `all` với `-resolve-max 2000` thì tìm được 555/564 file và có thêm 23 dòng `/store/*`, nhưng recall **vẫn 300/420**. Cả 120 operation thiếu đều do trích xuất.
- **93 GET bị thiếu:** js-sdk viết list/retrieve là `this.client.fetch(path, { headers, query })`, **không có `method`** (POST/DELETE thì có). `Client.fetch` chuyển `init` qua `this.fetch_` (closure do `initClient()` trả về) rồi tới `fetch(url, normalize(init))`, với `normalize` dùng `Object.assign(Object.assign({}, init), {headers, …})`.
  - Trong `generic`, lời gọi không có method có path không mang dạng API (`/admin/campaigns`, không có `/api/` hay version) bị coi là **route của router**, nên GET biến mất.
  - `optionsAt` không hiểu `Object.assign`, và options đã biết mà không có method vẫn để method trống.

### 40.3. Sửa (tổng quát)
- `generic`: callee giống `fetch` (`fetchLike`: `fetch`, `X.fetch`, `fetchImpl`…), method trống, và không có options nào mang method chưa giải được (`methodUnknown`) thì là **GET**, mặc định của `fetch`. Một hàm điều hướng (`navigate(path, {replace})`) vẫn là route.
- `optionsAt`: `Object.assign(a, b, …)` được đọc như spread lần lượt; đối số sau thắng (duyệt ngược, vì `merge` giữ giá trị đầu).
- `readBound`: options được code thể hiện đầy đủ (`known`), không có `method` và không có biểu thức method thì là GET.
- `TestFetchOptionsWithoutMethodAreGET`:
  - ca dương: list/retrieve ra GET, `Object.assign({method: "GET"}, init, {method: "POST"})` ra POST;
  - ca âm: method tính lúc chạy thì không đoán GET; `navigate` vẫn là route.
  - Trượt 3 điểm với code v27.

### 40.4. Kết quả
- **Medusa (dev): 300 lên 382/420**, ở cả hai chế độ.
  - 79 dòng có method không khớp; 30 dòng mới đều là GET hợp lệ của SDK ngoài Admin spec (`/store/*` 19, `/rbac/*` 8, `/admin/audit-logs*`, `/cloud/auth`).
  - **38 operation còn thiếu:**
    - khoảng 29 **không có trong code dưới path đó**: `gift-cards`, `store-credit-accounts`, `index/*` (0 lần); SDK dùng `location-levels/batch` thay cho `POST location-levels`; các route `order-edits/shipping-method`, `variants/{}/inventory-items`, `tax-rates/{}/rules`, `import/{}/confirm`, `workflows-executions` (`run`/`steps`/`subscribe`) không có.
    - 9 **có dạng template trong SDK**: `/admin/promotions/${id}/${ruleType}/batch` (ground truth: `buy-rules`, `target-rules`, `rules`) và `/auth/${actor}/${method}…` (ground truth: `user`). Giá trị cụ thể nằm ở nơi gọi trong dashboard, một script khác, nên cần **liên kết xuyên script** (đợt riêng).
- **Corpus dev (2.568 file):** giống hệt v27. **Đánh giá dev:** 100%, FP = 0. Kết quả lưu theo commit `f7f6778`: `output/_groundtruth/eval_26f_v28_dev.json`, `keycloak_dev_v28.json`, `medusa_dev_v28.json`. Regress 18/18.
- **Keycloak (dev):** 341/415. Hai dòng trước đây không có method giờ có GET (`/.well-known/openid-configuration`, `/realms/{}/account`), đều đúng nhưng nằm ngoài Admin spec.

### 40.5. Còn lại
- Liên kết xuyên script: giá trị literal ở nơi gọi (dashboard) cho tham số path của method SDK (script khác).
- (a) "Method trả về URL" (mục 38.4).
- Tập kiểm mù #4: đề xuất gói và spec, chờ xác nhận.
- P3 từ review 26D: `pathParams` qua tầng `sub` chưa đi qua hằng cục bộ; `urlOf` chưa dùng `x.object`.

## 41. Đợt 26G: review 26F (method theo thứ tự viết), kiểm mù #4 Directus

### 41.1. Hai lỗi P2 của review 26F (có thật, đã sửa, jsapi v29)
1. **`Object.assign`/spread và `known`:** phần không đọc được bị bỏ qua, nên `Object.assign({}, runtimeInit, {headers})` và `{...runtimeInit, headers}` bị đoán là GET. Thêm vào đó, `Object.assign({method: verb}, {method: "POST"})` mất POST, vì vòng lặp duyệt ngược hạ `known` sau khi đã có POST.
   - **Sửa:** các phần được đặt chồng lên nhau theo thứ tự viết (`overlay`).
     - Method viết sau thay method viết trước.
     - Một phần không đọc được làm method thành "không biết", **trừ khi** đã có method được viết tường minh trước nó. `{method: "POST", body, ...extra}` vẫn là POST: đây là mẫu `bT("POST", body, extra)` của target-c. Phiên bản đầu của bản sửa xoá cả các POST đó, và snapshot đã bắt được.
   - Spread dạng `?:`, `&&`, `||` được đọc theo từng nhánh (`eitherOptions`): method xác định khi hai nhánh cùng một method. Nhờ vậy `...(body ? {body} : {})` của Medusa vẫn cho GET.
2. **`generic` đoán GET khi options không đọc được:** đối số đứng ngay sau URL của một lời gọi kiểu `fetch` là `init` của request. Không đọc được nó thì method là "không biết".
- **Test:** `TestFetchMethodFromOptionsInOrder` (code v28 trượt 5 điểm, gồm cả `cond-method` với hai nhánh khác method) và `TestWrittenMethodSurvivesTrailingSpread`.
- **Không đổi:** corpus dev, đánh giá dev (100%, FP = 0), Keycloak (dev) 341/415, Medusa (dev) 382/420.
- **Regress:** 17/18. `bench` trượt một lần ở `reqcheck` của `angular-ngsw`: request `ngsw.json?ngsw-cache-bust` của service worker không được ghi lại. Đây là giới hạn đã biết của recorder (request đầu của service worker), thuộc tầng Chrome. Chạy riêng thì qua.

### 41.2. Kiểm mù #4: `@directus/app@19.1.0` (người dùng cho phép tải)
- **Ghim:** release Directus `v12.6.1` (commit `b17d2e94ac8dd118f6c3c28b5b04337e97fdd418`) chứa `app/package.json` 19.1.0 và `packages/specs/package.json` 16.0.0, kiểm qua raw file tại tag. SHA-1 của hai tarball khớp registry. Chỉ giải nén `package/dist/openapi.json` của gói specs; tarball app không được mở trước khi chạy.
- **App:** `dist/index.html` cộng các chunk; SPA Vue đã build, mọi dependency đóng gói sẵn.
- **Ground truth:** 136 operation (70 path; GET 46, POST 35, PATCH 30, DELETE 25; không deprecated), SHA-256 `466d2a8b65b5072abad5855e941c3f915f81df2d03a471ddb349a3bccdb084d4`. Spec của Directus chỉ tuyển phần core API.
- **Harness `eval_heldout_directus.py`:**
  - `entries` phục vụ nguyên `dist/` dưới `/admin/` (đường dẫn mặc định của Directus) và crawl từ `index.html` của gói, `-resolve-max` mặc định.
  - `all` dùng `index.html` nạp mọi file JS, `-resolve-max` ≥ 2000.
  - Đếm riêng các nhóm khớp như kiểm mù #3. File đánh dấu ghi trước khi chấm điểm.

### 41.3. Kết quả (một lần, `d59a25b`, working tree sạch; `output/_groundtruth/heldout_directus_v29.json`)

| Chế độ | Khớp | Path đầy đủ | Dòng có method / không khớp | File JS tìm thấy / phục vụ | `b_err` | `endpoints` |
|---|---|---|---|---|---|---|
| `entries` | **89/136 (65,4%)** | 89 | 151 / 60 | 372 / 393 | 0 | 8,3 s, 342 MB |
| `all` | 89/136 | 89 | 151 / 60 | 391 / 393 | 0 | 8,6 s, 368 MB |

- Hai chế độ thiếu đúng cùng 47 operation: khâu tìm chunk không phải nút thắt. `entries` chạm trần `-resolve-max (500)`, có tính cả các request thăm dò.
- **47 operation bị thiếu** (chỉ là quan sát): GET 14, PATCH 14, DELETE 13, POST 6. Nổi bật là `/items/{}/{}` (GET/PATCH/DELETE) và PATCH/DELETE trên `roles`, `permissions`, `operations`, `presets`, `relations`. Chưa chẩn đoán.
- **60 dòng không khớp:** phần lớn là endpoint có thật của Directus ngoài phần core của spec (`dashboards`, `panels`, `shares`, `policies`, `access`, `notifications`, `translations`, `extensions/registry`, `ai/chat`, `graphql`). Vài dòng đáng ngờ: `GET /__open-in-editor` (công cụ dev), `/api/chat/{}/stream`.

### 41.4. Bức tranh sau bốn lần kiểm mù

| Tập | Kiến trúc | Kết quả mù | Sau khi thành dev |
|---|---|---|---|
| Keycloak | class SDK, bundle | 0/415 | 341/415 |
| Appwrite | SDK thuần, service class | 1.070/1.098 | (chưa dùng làm dev) |
| Medusa | bundle UI + class SDK | 300/420 | 382/420 |
| Directus | bundle Vue + axios | 89/136 | |

- Cả bốn tập đều có `b_err = 0`, và recall không phụ thuộc vào khâu tìm chunk. Phần còn thiếu nằm ở trích xuất (cách app dựng URL) và ở phạm vi của ground truth.

## 42. Đợt 26H: Directus chuyển thành tập dev; chẩn đoán dẫn tới liên kết xuyên script

### 42.1. Quyết định phương pháp
- Theo review 26G: **Directus (`@directus/app@19.1.0`) là tập dev** từ đợt này. Kết quả mù cuối cùng là 89/136 (mục 41). Repo **không còn tập kiểm mù UI thật nào chưa mở**. Tập #5 phải đề xuất và chờ xác nhận trước khi tải.
- Kết quả dev lưu theo commit: `eval_26g_v29_dev.json`, `keycloak_dev_v29.json`, `medusa_dev_v29.json` (code `d59a25b`); `directus_dev_v30.json` (`6ba630d`).

### 42.2. Chẩn đoán (đọc code Directus)
- **Nút thắt chính: liên kết xuyên script.** App dựng endpoint bằng `function MT(e){ return e in jT ? jT[e] : NC(e) ? `/${e.substring(9)}` : `/items/${e}` }` (tên collection hệ thống `directus_roles` thành `/roles`, còn lại thành `/items/<collection>`).
  - Hàm này định nghĩa ở một chunk dùng chung (`dist-*.js`). Nơi gọi (`Sf.patch(`${Qi(n.collection)}/${n.primaryKey}`)`) nằm ở chunk khác và import nó (`import{…, ut as Qi, …} from "./dist-….js"`).
  - jsapi phân tích (và cache) từng script độc lập, nên `evalCall` không đọc được thân hàm import.
  - Trong bundle có **44 lời gọi với tên collection literal** (`directus_users`, `directus_roles`, `directus_permissions`…).
  - Trên bản thu nhỏ **cùng một script**, jsapi và catalog đã ra đúng `PATCH/DELETE /items/{}/{}` và `/mcp-oauth/clients/{}`. Phần còn thiếu đúng là phần liên kết.
- Cùng gốc với 9 operation dạng template của Medusa (`/admin/promotions/${id}/${ruleType}/batch`, `/auth/${actor}/…`): giá trị literal nằm ở nơi gọi, trong script khác.
- **Bộ dựng lệnh kiểu SDK** trong bundle (`(e, n) => () => ({path: `/users/${e}`, params: n, method: "GET"})`): chỉ còn vài cái sau tree-shaking, không phải khoảng trống chính.
- **`GET /__open-in-editor`:** devtools của Vue bị đóng gói vào bundle; đây là FP.
- **`PATCH /relations/{}/{}`:** code đúng như API thật của Directus (`/relations/:collection/:field`); spec ghi `/relations/{id}`. Đây là spec lệch, không phải lỗi trích xuất.

### 42.3. Sửa (jsapi v30)
- Endpoint của dev server (`__open-in-editor`, `__vite_ping`, `__webpack_hmr`, `__webpack_dev_server__`, của Next và Nuxt, `__inspect`) bị loại theo **tên đoạn đầu** (`devToolPath`). `/__/auth/handler` và `/api/__meta` được giữ (`TestDevToolEndpointsDropped`).
- **Đã thử rồi bỏ:** cho phép đánh giá hàm có path literal riêng (`/items/${e}`) khi đối số không biết (`ownLiteralPath`). Kết quả: Directus chỉ +1 (`POST /auth/login`), trong khi corpus dev có thêm một FP (`GET /apps/{}/` của target-c, thực ra là route điều hướng) và một route nhiễu (`/node_modules/@types/{}`). FP = 0 là tiêu chí cứng, nên quy tắc này để lại cho đợt xuyên script, khi có ngữ cảnh của export và nơi gọi.

### 42.4. Kết quả
- **Directus (dev): 89/136** (cả hai chế độ), 150 dòng có method (bỏ được `__open-in-editor`).
- Corpus dev, đánh giá dev (100%, FP = 0), Keycloak 341/415, Medusa 382/420: **không đổi**.

### 42.5. Hướng tiếp: liên kết xuyên script (đề xuất thiết kế)
- **jsapi (theo từng script, vẫn cache được):**
  - phát ra **bản tóm tắt export của hàm dựng URL thuần**: tên export, các phương án giá trị trả về theo tham số (ví dụ `/items/{0}`, `/{0:substring(9)}`, `/mcp-oauth/clients` khi `{0}` là `directus_oauth_clients`);
  - tại nơi gọi một hàm import, phát ra một **URL hoãn lại** mang module, tên export và đối số literal hoặc chưa biết.
- **endpoints (đã thấy mọi script):** thay đối số vào bản tóm tắt của đúng module/export (dùng chung `linkModules`, ESM URL hoặc ID bundler), rồi dựng endpoint. Không giải được thì không phát ra gì.
- **Tiêu chí:** FP = 0 trên corpus dev; Directus và Medusa (dev) là thước đo; fixture dev độc lập (hai chunk ESM tự viết).

## 43. Đợt 27A: liên kết xuyên script, chiều "hàm dựng URL được export" (jsapi v31)

### 43.1. Phạm vi (theo review 26H)
- **Hai chiều liên kết khác nhau** (đã kiểm trên code Medusa):
  - **Directus:** request nằm ở nơi gọi (`Sf.patch(`${Qi(c)}/${k}`)`); module khác export một **hàm dựng URL thuần** (`MT`). Đợt này làm chiều này.
  - **Medusa:** request nằm trong **method của class SDK** ở module A (`addRules(id, ruleType)` → `` `/admin/promotions/${id}/${ruleType}/batch` ``, `auth.login(actor, method)`); literal nằm ở nơi gọi trong module B, có khi qua một tầng hook (`usePromotionRules(id, "buy-rules")`) và một singleton import (`sdk.admin.promotion…`). Đây là **cơ chế thứ hai** (method có tham số đoạn path, qua instance được export), để đợt sau. Cơ chế của Directus không giải được Medusa.

### 43.2. Thiết kế
- **jsapi (từng script, vẫn cache theo SHA):**
  - **`Result.Builders`:** hàm export ESM (`export {MT as ut}`, `export function`, `export const`) có 1–4 tham số, không phải request, mà biểu thức trả về **có path literal riêng** (`writesPath`: text có `/` và một từ ≥ 3 chữ cái). `x.exportVars` ghi tên export của mọi binding.
  - **`Result.Deferred`:** chỉ trong `add()` của request (không phải `navigation`/`route`), một lời gọi tới hàm import ở **tầng trên cùng** của URL được thay bằng dấu đánh dấu. Ghi lại `{module, name, đối số}` và URL với `{import}` đúng tại chỗ đó, giữ tiền tố/hậu tố như `/${k}`. Chỉ ghi khi request có method và URL có đúng một dấu.
  - **Bên trong `evalCall` (thân một hàm khác) không đánh dấu.** Một dấu ở đó bị coi là "đối số đã biết", và đã làm lọt `{}/envelope/` của Sentry. Snapshot catalog bắt được.
  - Request vẫn được thêm như trước (chỗ gọi là `{}`): không giải được thì cũng không tệ hơn trước.
- **`jsapi.EvalBuilder(src, name, args)`:** parse script export (hạ cấp nếu cần), chạy các pass định nghĩa (`prepare`, tách khỏi `extractWithMap`), rồi đánh giá hàm **cho từng tổ hợp** đối số (tối đa 16 tổ hợp, 16 giá trị), để điều kiện thấy một giá trị.
  - `condTruth` hiểu thêm: `key in obj` (object literal không spread); lời gọi hàm của app chỉ trả về một điều kiện (`NC(e)`); `?:` lồng; literal thật/giả (`!1`, `true`); `list.includes(x)` với `stringList` (mảng literal, hằng, thuộc tính, `arr.map(e => e.key)` trên mảng object). `substring` dùng chung `sliceString`.
  - **Chốt FP:** khi mọi đối số đã biết mà vẫn ra nhiều hơn một giá trị (điều kiện không quyết định được), tổ hợp đó bị bỏ. Đây đúng là nguồn của FP `/items/directus_permissions` ở bản đầu.
- **endpoints (`linkDeferred`, gọi cuối `linkModules`):**
  - tìm script export bằng chính `targetScripts` (URL ESM, đường dẫn source map), `ReExports` và `Local` của barrel bị tree-shake; nạp source qua `Script.Load` (mỗi script một lần; kết quả nhớ theo script/tên/đối số);
  - thay giá trị vào URL; bỏ giá trị có **origin không biết** (`unknownOrigin`: `{}…`, `//{}…`, `https://{}…`, tương đương `withBase` ở tầng catalog) và URL không có từ (`/{}/{}`);
  - nguồn được ghi `kind: import`.
- `Script.Load` chỉ có khi `Analyze` đọc thư mục output. Các nơi gọi `Build` khác (MCP server) không giải URL hoãn lại, tức là giữ hành vi cũ.

### 43.3. Kết quả
- **Directus (dev): 89 lên 93/136:** thêm `GET/PATCH/DELETE /items/{}/{}`, `POST /items/{}`. Các dòng không khớp mới là `/mcp-oauth/clients*` (bảng `jT` của app; API thật, ngoài phần core của spec).
  - 43 operation còn thiếu (`roles`/`permissions`/`operations`… PATCH/DELETE, `users/me`): tên collection đến từ biến lúc chạy (props, route), không phải literal.
- **Corpus dev:** catalog của **cả 5 target giống hệt HEAD** (so toàn bộ `endpoints.jsonl`, không chỉ ground truth). Đánh giá dev 100%, FP = 0. Keycloak 341/415, Medusa 382/420: không đổi. `perfgate` 8,8 s.
- **Test:**
  - `TestDeferredURLsAcrossChunks`: hai chunk ESM tự viết. Literal → `/roles/{}`; bảng tra → `/auth/tokens/{}`; không biết → `/records/{}/{}`. Ca âm: điều kiện không quyết định được với literal; điều hướng; module không có trong crawl; origin không biết (`//{}/api/…/envelope/`). Tắt `linkDeferred` thì trượt.
  - `TestUnknownOrigin`.

### 43.4. Còn lại
- Cơ chế thứ hai (Medusa): method của class SDK có tham số đoạn path, gọi qua singleton import và hook bọc.
- Builder theo ID bundler (webpack `M.s`); hàm nối kiểu `(base, ...parts)`; lời gọi import nằm trong tham số URL của một helper (chưa đánh dấu trong `bindParams`).
- Vị trí (`Line`/`Col`) của `Deferred` dùng `locateCall`, nên có thể lệch khi nhiều lời gọi giống nhau trên cùng một dòng.

## 44. Đợt 27B: review 27A (hiệu năng của bước liên kết, tiền tố client, test jsapi), jsapi v32

### 44.1. Sửa
- **P2 hiệu năng:** `EvalBuilder` từng parse lại cả chunk export và chạy lại 6 pass chuẩn bị cho **mỗi bộ đối số**.
  - Giờ tách thành `jsapi.PrepareModule(src)` (một lần cho mỗi script) và `(*Module).EvalBuilder(name, args)`; mỗi lần đánh giá chỉ đặt lại binding của tham số và ngân sách gọi hàm (`callBudget`, `rootEvals`, `calls`). `linkDeferred` nhớ `Module` theo script.
  - Đo ở lần chạy ấm trên Directus (dev, 34 `Deferred`): `endpoints` từ 0,55 s xuống 0,45 s. Chênh lệch tăng theo số bộ đối số khác nhau.
- **Tiền tố client bị rơi** khi URL bắt đầu bằng lời gọi import (`prefixed` chỉ nhận `t` bắt đầu bằng `/`). Giờ các tiền tố đi theo request (`Deferred.Pre`), và tầng catalog áp chúng khi giá trị thay vào là path `/…` của origin trang.
- **`condTruth`:** từ chối đối số spread khi gọi hàm điều kiện; thêm `||`/`&&` (short-circuit như JavaScript). Bản đầu của `TestModuleEvalBuilder` lộ ra rằng thiếu `||` thì `isSys(e) = … SYS.includes(e) || LIT.includes(e)` không quyết định được. Chốt "đối số đã biết mà vẫn nhiều giá trị" khi đó cho ra rỗng, không ra FP: chốt hoạt động đúng.
- **Test trực tiếp ở jsapi** (`deferred_test.go`):
  - `TestModuleEvalBuilder`: một `Module` dùng cho nhiều lần đánh giá; `in`, hàm điều kiện, `?:`, `!0`, `includes` trên `map` và trên mảng literal, `||`; điều kiện không quyết định được thì không ra gì.
  - `TestDeferredRecorded`: `Pre`, không đánh dấu trong điều hướng, không đánh dấu bên trong hàm khác.
  - `TestBuildersRecorded`: `withBase` không phải builder; đoạn path một chữ cái không phải path riêng (theo `writesPath`).
- **Ghi nhận, chưa đổi:** chốt `known && len(vals) > 1` không áp cho tổ hợp có một tham số không biết. Với builder nhiều tham số, nhánh phụ thuộc tham số đã biết nhưng không quyết định được vẫn có thể bị gộp. Chỉ xử lý khi gặp mẫu thật.

### 44.2. Kết quả
- Snapshot jsapi và catalog của cả 5 target dev **giống hệt HEAD**. Directus 93/136, Keycloak 341/415, Medusa 382/420. `perfgate` 8,0 s.

### 44.3. Thiết kế đợt sau: cơ chế thứ hai (method của class SDK, Medusa)
- **Mẫu:** module A (js-sdk) có class `Promotion` với `addRules(id, ruleType, payload)` → `this.client.fetch(`/admin/promotions/${id}/${ruleType}/batch`, {method: "POST"})`. Module B (dashboard) gọi `sdk.admin.promotion.addRules(id, "buy-rules", …)`, với `sdk` là singleton import (`new Medusa(…)`), hoặc qua hook `usePromotionRules(id, "buy-rules")`.
- **Ba điểm hạ tầng (review 27A):**
  1. `imported()` chỉ nhận `fn(…)` hoặc `ns.fn(…)`. Cần nhận chuỗi `X.a.b.m(…)` với `X` là binding import, ghi lại **đường thuộc tính** (`admin.promotion`) và tên method.
  2. `ImportArg.Values` chỉ giữ chuỗi giống URL/method. Cần giữ **literal ngắn tuỳ ý** (`"buy-rules"`, `"user"`) cho tham số đoạn path.
  3. `applyLeaf` chỉ thay nguyên URL (`URLArg`). Cần một dạng export mới: **method của instance được export**. Module A ghi bảng `(đường thuộc tính, method) → template với chỉ số tham số` (`/admin/promotions/{0}/{1}/batch`, method, kind), dựng từ instance export (`export const sdk = new Medusa(…)`, hoặc class được export cùng chuỗi field `admin.promotion = new Promotion(client)`). Tầng catalog điền **từng đoạn** bằng literal ở nơi gọi.
- **Hook bọc:** chỉ đi theo literal được truyền **thẳng** qua tham số (một tầng), không lần theo state hay props, để không bùng nổ tổ hợp.
- **Chốt FP:** chỉ điền khi literal là một đoạn path hợp lệ (không có `/`, không rỗng); tham số không biết giữ `{}`; template giữ nguyên endpoint sẵn có (`/admin/promotions/{}/{}/batch`).

## 45. Đợt 27C: review 27B; thiết kế cơ chế Medusa viết lại (chưa code)

### 45.1. Hai biên nhỏ của review 27B (đã sửa, `8c97a41`)
- `linkDeferred` đánh dấu mọi request client là "path chờ base của client", kể cả khi tiền tố của client (`/api`, hoặc URL tuyệt đối) đã ghép vào. Giờ chỉ path **không có tiền tố đứng trước** mới là của client, đúng như `ownPrefix` của jsapi.
  - `TestLinkDeferredClientFlag` đọc trực tiếp cờ này và trượt với code cũ.
  - Ca end-to-end ở tầng `Build` (`TestDeferredClientPrefix`, `/api/records/posts/{}`) không làm lộ được cờ sai, vì gán base cho client còn cần `BaseKeys` khớp. Vì vậy cần test trực tiếp.
- `condTruth`: vế trái của `||`/`&&` không quyết định được thì dừng, không đọc vế phải.
- Catalog dev (cả `bases`/`origin`) và Directus: không đổi.

### 45.2. Mục 44.3 sai ở đâu (review 27B, đã kiểm lại trên code Medusa)
- **Promotion (3 POST `…/{buy-rules|rules|target-rules}/batch`):** không có nơi gọi nào truyền literal vào `addRules`/`updateRules`/`removeRules` hay hook bọc chúng. `ruleType` lấy từ route (`params.ruleType`); literal chỉ có trong các nhánh `ruleType === "buy-rules"`. Đi theo hook một tầng không lấy được. Muốn lấy phải **thu hẹp giá trị theo nhánh so sánh**, một cơ chế khác hẳn.
  - Ví dụ `usePromotionRules(id, "buy-rules")` ở 44.3 gọi `listRules` (GET `/admin/promotions/{}/{}`), vốn đã khớp ground truth. Điền literal ở đây không tăng số khớp, chỉ thêm dòng.
- **Auth (6 operation `/auth/user/*`):** nơi gọi truyền thẳng `"user"` (không qua hook), nằm trong `queryFn`/`mutationFn`. Nhưng `register`/`resetPassword`/`updateProvider` truyền thêm `"emailpass"` cho `{provider}`:
  - điền vào ra `POST /auth/user/emailpass/register`: **request thật**, nhưng ground truth là `/auth/user/{}/register`;
  - `callback` của SDK gửi GET trong khi spec ghi POST (lệch từ chính SDK).
- **Hạ tầng thiếu:**
  1. **Import map:** `htmlscan` đọc import map để crawl nhưng không chuyển bảng `specifier → URL` sang tầng endpoints. `targetScripts` chỉ nhận `./`, `../`, `/`, nên `import Medusa from "@medusajs/js-sdk"` không tìm ra script.
  2. **Chuỗi instance qua 4 module:** singleton `sdk = new Medusa(…)` (dashboard) → `export default Medusa` (một `Var`; `scanESModules` chỉ xét `exported(s.Decl)`) → `this.admin = new Admin(…)` (module khác) → `this.promotion = new Promotion(…)` (module khác). `Auth` gắn method bằng arrow trong constructor (vào `info.fields`, không phải `info.members`) và nhóm object `this.mfa = {…}`.
  3. **`__awaiter(this, …, function* () {…})`:** `nestFinder` coi `function*` là hàm lồng (`nested`), và `exportedFromSummary` bỏ summary `nested`.

### 45.3. Thiết kế sửa đổi (đề xuất)
- **Bỏ khỏi phạm vi:**
  - Promotion batch: cần thu hẹp giá trị theo nhánh so sánh, để thành một cơ chế riêng nếu đáng làm.
  - Hook một tầng: không có ca thật nào cần.
- **Import map: không làm ở tầng endpoints lúc này.** Một bản admin Medusa triển khai thật được `@medusajs/admin-bundler` (Vite) **gói** js-sdk vào các chunk có import tương đối. Bare specifier qua import map là sản phẩm phụ của harness (phục vụ gói npm chưa bundle), hiếm gặp ở production.
  - Thay vào đó, harness dev của Medusa có thêm chế độ **`bundled`**: dùng esbuild (Go API, đã có trong `go.mod`) để bundle `dashboard/dist/*.mjs`, alias `@medusajs/js-sdk` tới dist ESM của nó, các dependency khác để external, `splitting` cùng `minify`. Chế độ này gần với bản triển khai thật hơn.
- **Hạ tầng tổng quát cần làm:**
  1. **Bóc lớp bọc async hạ cấp** của TypeScript/Babel/esbuild: `__awaiter(this, a, b, function* () {…})`, `__async(this, null, function* () {…})`, `_asyncToGenerator(function* () {…})()`. Thân `function*` được đọc như thân của chính hàm, không phải hàm lồng. Áp cho mọi summary, không riêng Medusa.
  2. **Member của class gồm cả:** field hàm gán trong constructor (`this.register = (…) => …`) và nhóm object literal (`this.mfa = {list: …}` → member có đường `mfa.list`).
  3. **Schema export theo từng bước:**
     - `export default <Var>` và export của instance (`export const sdk = new C(…)`, hoặc `var sdk = new C(…)` được export) → `{class: module + tên export}`;
     - field của class trỏ tới class khác (`this.admin = new Admin(…)`, `Admin` import từ module nào);
     - method của class → template theo **chỉ số tham số** (`/admin/promotions/{0}/{1}/batch`, method, kind), dựng từ summary đã bóc lớp `__awaiter`.
     - Tầng catalog đi qua các bước bằng cùng bộ phân giải module (`targetScripts`, `ReExports`, `Local`), độ sâu ≤ 8.
  4. **Nơi gọi:** nhận chuỗi `X.a.b.m(…)` với `X` là binding import (cả khi nằm trong `queryFn`/`mutationFn`); ghi đường `a.b`, method `m`, và giá trị literal **ngắn** của đối số (không có `/`, không rỗng; không giới hạn ở dạng URL).
- **Chính sách literal (cần chốt):** điền literal vào đoạn path cho ra request thật (`/auth/user/emailpass/register`), có giá trị cho recon và fuzzing. Đề xuất:
  - catalog phát **cả** template của SDK (đã có) **lẫn** bản cụ thể;
  - harness dev đếm thêm "khớp theo instance" (một literal lấp một `{}` của ground truth), **tách riêng**, không đổi con số chính.
- **Ước lượng trung thực trên Medusa (dev):**
  - khớp mới theo con số chính: `GET /auth/user/providers` và `POST /auth/user/{}` (`login` với `providerId` không biết): **+2**;
  - khớp theo instance: `register`/`reset-password`/`update` **+3**;
  - `callback` lệch method từ SDK; Promotion batch ngoài phạm vi.
  - Lợi ích chính nằm ở **tính tổng quát** (singleton SDK, `__awaiter`, method dạng field trong constructor là mẫu phổ biến), không ở con số Medusa. Muốn chứng minh cần một tập kiểm mù mới có kiến trúc này.

### 45.4. Lựa chọn cho đợt sau (cần người dùng chốt)
- **(1)** Làm hạ tầng 45.3 (bóc `__awaiter`, member dạng field/nhóm object, schema theo bước, chuỗi gọi qua import) cùng chế độ `bundled` cho harness Medusa.
- **(2)** Gác cơ chế Medusa, chuyển sang (a) "method trả về URL" hoặc kiểm mù #5.
- **(3)** Làm riêng phần rẻ và tổng quát nhất trước: bóc `__awaiter`/`__async` (ảnh hưởng mọi app TypeScript hạ cấp), đo tác động trên các tập dev, rồi mới quyết phần schema theo bước.

## 46. Đợt 27D: method trả về URL (jsapi v33)

### 46.1. Quyết định
- Theo review 27C, chọn **(2)**: làm (a) "method trả về URL", rồi kiểm mù #5. Review cũng nêu bẫy đo lường của (3): `__awaiter` chưa minify gần như chỉ có trong js-sdk của Medusa, nên bóc riêng lớp này sẽ cho delta khoảng 0 trên tập dev, và con số đó không đánh giá được phần schema theo bước.
- **Appwrite từ đây là tập dev cho mẫu này:** đã đọc code SDK để thiết kế. Con số mù 1.070/1.098 ở mục 37 vẫn giữ nguyên.

### 46.2. Mẫu và tín hiệu
- Method gửi request và method trả về URL của SDK dựng URL **giống hệt nhau**: `const uri = new URL(this.client.config.endpoint + apiPath)`. Một bên `return this.client.call("get", uri, …)`, bên kia `return uri.toString()` (cho `<img src>`, link tải, chuyển hướng OAuth2).
- **Tín hiệu (`urlreturn.go`):**
  - Khi đọc một request có method (`add`, và `generic`), ghi lại **biểu thức base** đứng đầu URL (`baseKey`): đi qua hằng cục bộ, `new URL(…)`, vế trái nhất của phép cộng (duyệt vòng lặp, không giới hạn bởi độ sâu), phần đầu của template khi không có chữ đứng trước, `toString()` và `.href`.
  - Base phải là chuỗi thuộc tính **có từ 3 phần trở lên** (`this.client.config.endpoint`). `this.base` hay `cfg.url` quá phổ biến để làm tín hiệu.
  - Một pass chạy sau pass gọi (`urlReturnVisitor`): hàm nào **trả về** một URL dựng trên đúng base đó thì là endpoint `GET`, `kind: "url"`.
- **Ca âm (`TestURLReturningMethods`):** link router (`/settings/files/${id}`); asset trên một base không dùng cho request nào (`this.client.config.cdn`); base hai phần (`this.base`); method gửi request (không bị đếm thêm một lần dưới dạng `url`).

### 46.3. Kết quả
- **Appwrite (dev): 1.070 lên 1.087/1.098**: thêm đủ 17 operation dạng URL (9 `avatars/*`; `download`/`preview`/`view` của file, deployment, invoice), **không có dòng không khớp nào mới**.
  - 11 operation còn lại (`monitors`/`alerts`) xuất hiện 0 lần trong SDK. Như vậy Appwrite đạt **1.087/1.087 phần có trong code**.
- **Không đổi:** snapshot jsapi và toàn bộ catalog của 5 target dev (cả `bases`/`origin`); Directus 93/136, Keycloak 341/415, Medusa 382/420 (không có dòng không khớp mới). `perfgate` 4,9 s.
- Thêm: dọn `split(u)` bị gọi hai lần trong `linkDeferred` (review 27C).

### 46.4. Kiểm mù #5 (đề xuất, chờ xác nhận trước khi đọc metadata hay tải)
- **Tiêu chí:** bundle UI thật (đã build, minify, chia chunk), REST cùng OpenAPI chính thức khớp phiên bản, kiến trúc khác bốn tập trước, và chưa từng mở.
- **Ứng viên:**
  1. **Jellyfin Web** (webpack, minify, chia chunk; client sinh từ OpenAPI `@jellyfin/sdk` cùng `jellyfin-apiclient` cũ), với spec OpenAPI ổn định của Jellyfin server cùng phiên bản. Cần kiểm: bản dist của web có được phát hành như artefact tải được không, và spec ứng với phiên bản nào.
  2. **Unleash** (frontend React), với spec OpenAPI của Unleash server. Cần kiểm: gói frontend đã build có trên npm không, và spec có phải là file tĩnh không (Unleash sinh spec lúc chạy).
- **Quy trình như #3/#4:** ghim phiên bản theo metadata; ground truth từ spec chốt trước; không mở code của app; harness đếm riêng các nhánh khớp, đếm thêm `kind: url`; chế độ `entries`/`all`; file đánh dấu ghi trước khi chấm điểm.

## 47. Đợt 27E: review 27D (ba biên của `urlreturn.go`), jsapi v34; metadata của kiểm mù #5

### 47.1. Sửa theo review
- **Tên biến trùng sau minify:** `memberChain` viết gốc là biến đã khai báo kèm định danh của khai báo (`e#<con trỏ>`). Chỉ biến global (`Decl == NoDecl`) và `this` mới giữ tên trần. Lý do: trong bundle minify, tham số `e` của hai hàm độc lập không phải cùng một base.
- **`x.cursor = 0` trước `urlReturnVisitor`:** giống hai pass sau nó. Thiếu reset thì `locate` tìm tiếp từ chỗ pass gọi dừng, nên vị trí của một URL được trả về rơi vào chỗ cùng các mảnh đó xuất hiện lại phía sau.
- **`.href` trên chính `new URL(…)`**, và **`new URL(path, base)`**: base là đối số thứ hai.
- **Test `TestURLReturningForms`:** gỡ từng sửa thì test trượt đúng ở ca tương ứng.
  - Lưu ý về fixture: các mảnh của một URL được tìm trong khoảng `maxGap` (256 byte). Fixture có dòng ngắn thì ghép nhầm được mảnh nằm ở method bên cạnh, nên fixture phải chèn đệm giữa các method.
- **Chưa làm (ghi lại):**
  - method của lớp cha trả URL dựng trên field của lớp con (`thisStack`/`callInInstances` chưa áp cho `urlReturnVisitor`);
  - `reqBases` tính riêng cho từng script: chunk chỉ có hàm trả URL mà không có request nào thì không bắt được.
- **Kết quả:**
  - Snapshot jsapi và catalog của 5 target dev giống hệt HEAD.
  - Appwrite 1.087/1.098, Directus 93/136, Keycloak 341/415, Medusa 382/420: không đổi.
  - `endpoints-check` và `crosscheck-check` qua; `perfgate` 6,35 s.

### 47.2. Kiểm mù #5: metadata (chỉ đọc, đã được cho phép; chưa tải)
- **Jellyfin thoả cả hai điều kiện của review:**
  - (a) Có bản dist đã build: gói `jellyfin-web_12.4+deb12_all.deb` (32.062.094 byte), chỉ chứa web, không phải build từ source.
    - Chỉ mục APT `bookworm/main/binary-amd64/Packages.gz` (do `InRelease` ký PGP ngày 2026-11-09) ghi SHA256 `0a676b7498b808f3a56282b45c0204e22d1eeb20968b00d1528d8da7143ac0ca`.
    - Hash trong file `.changes` (32.061.596 byte) không phải của file đang phát hành: deb được ký sau khi build.
  - (b) Spec tĩnh đúng phiên bản: `api.jellyfin.org/openapi/stable/jellyfin-openapi-12.4.json` (1.896.214 byte, ngày 2026-10-26, cùng ngày với release web/server 12.4; hai bản phát hành này luôn cùng số).
    - Không có checksum công bố, nên SHA256 sẽ được ghi lúc tải và đưa vào file ground truth.
  - GitHub Releases của `jellyfin-web` không có asset nào. Tarball portable (298 MB) chứa cả server, nên không dùng.
- **Không chọn Unleash:** Jellyfin đã thoả cả hai điều kiện (theo review).

### 47.3. Luật chốt trước của kiểm mù #5 (đề xuất, chờ xác nhận cùng việc tải)
- **Đầu vào:** đúng hai file ở 47.2, kiểm SHA256 của deb theo chỉ mục APT trước khi dùng.
  - Deb được giải bằng Python (`ar` rồi `data.tar.*`) trong thư mục trống riêng; không `dpkg -i`, không chạy script nào của gói.
  - Không đọc code của app trước khi chạy.
- **Ground truth:** mọi operation trong `paths` của spec, mọi method.
  - Path chuẩn: path của spec, `{param}` thành `{}`; không có tiền tố, vì API nằm ở gốc server.
  - So khớp **không phân biệt hoa thường**, vì routing của ASP.NET Core không phân biệt; luật này lấy từ ngữ nghĩa server, không phải từ code.
  - Operation `deprecated` được đếm riêng.
- **Khớp:**
  - Một dòng catalog có method khớp một operation khi method bằng nhau và một path ứng viên (`expand_catalog_row`, path bỏ `{}` đầu, path tương đối thêm `/`) bằng path chuẩn.
  - Không tính dòng `confidence` là `string`/`doc` hay `kind: doc`. Có tính dòng `third_party`, nhưng báo riêng số khớp nhờ chúng.
- **Phục vụ:** cây web của deb phục vụ ở `/web/` trên loopback, giống triển khai thật. Hai chế độ:
  - `entries`: crawl từ `index.html` của chính bản dist;
  - `all`: một trang nạp mọi `.js`.
  - Cả hai dùng `-engine http -depth 1 -archive=false -probe=false`, rồi `endpoints` lạnh, trong `unshare -rn`.
- **Cột `url` (theo review):** `endpoints.jsonl` gộp các dòng cùng METHOD/host/path và giữ `kind` của dòng đến trước, nên phải đếm từ cache `static/<sha>.json` (giữ `kind` theo nguồn). Báo ba con số:
  - số operation có nguồn `kind: url`;
  - số operation **chỉ** có nguồn `kind: url`;
  - số operation khớp trên catalog khi tính và khi bỏ các dòng mà mọi nguồn đều là `url`.
- **Chạy đúng một lần trên commit sạch;** file đánh dấu được ghi trước khi chấm điểm. Sau khi chạy, tập này thành dev.

## 48. Đợt 27F: kiểm mù #5 Jellyfin Web 12.4 (3/364); bộ mô tả request của openapi-generator, runtime webpack chia vendor, jsapi v35

### 48.1. Kiểm mù #5 (chạy một lần, commit sạch `afa5bd3`, jsapi v34)
- **Toàn vẹn đầu vào:**
  - `gpgv` xác nhận chữ ký `InRelease` (khoá `4918AABC486CA052358D778D49023CD01DE21A7B`, lấy từ `repo.jellyfin.org`, tin theo lần đầu).
  - SHA256 của `Packages.gz` khớp với `InRelease`; SHA256 của deb khớp với `Packages`.
  - Spec `02a60649…036e` (1.896.214 byte), `info.version` 12.4.0.
- **Ground truth chốt trước:** 364 operation (186 GET, 130 POST, 30 DELETE, 18 HEAD), 12 deprecated. Khi bỏ phân biệt hoa thường không có hai operation nào thành một khoá.
- **Harness:** `output/_groundtruth/eval_heldout_jellyfin.py`, file đánh dấu `heldout_jellyfin_RUN.json`, kết quả `heldout_jellyfin_v34.json`.

| Chế độ | Script tìm được | Khớp | Dòng không khớp |
|---|---|---|---|
| `entries` (`index.html` thật, `-resolve-max` 500) | 30/986 | **3/364** | 0 |
| `all` (mọi `.js`, `-resolve-max` 2000) | 964/986 | **3/364** | 1 |

- Cột `url`: 0 ở cả hai chế độ (bản Jellyfin này không có hàm nào trả về URL dựng trên base của request).
- Tập này đã dùng, **từ giờ là dev**.

### 48.2. Chẩn đoán (sau khi chạy)
- **SDK là client `typescript-axios` do openapi-generator sinh**, qua Babel và regenerator, rồi minify (`node_modules.@jellyfin.sdk.bundle.js`, 676 KB). Mỗi operation là một ParamCreator:
  - `l = "/Items/{itemId}/Refresh".replace("{".concat("itemId","}"), …)`, `f = new URL(l, DUMMY_BASE_URL)`;
  - `v = h(h({method:"POST"}, baseOptions), options)` (`h` là `_objectSpread2` của Babel);
  - kết quả `{url: toPathString(f), options: v}`. Regenerator viết nó thành đối số của `t.a(2, {...})`, không phải câu `return`.
  - Request thật được gửi ở chỗ khác, bởi một hàm chung cho mọi operation (`createRequestFunction`: `axios.request({...args.options, url: basePath + args.url})`). Vì vậy jsapi không thấy lời gọi nào mang path.
- **Biến hoist của regenerator:** `var s,l,f;` rồi mới gán `l=…, f=…`. `defs` khi đó là `[nil, Y, nil]`, nên `constant` không coi là hằng.
- **Runtime webpack chia vendor:** `s.u=function(e){return 45642===e?"node_modules.@jellyfin.sdk.bundle.js":…:({tên}[e]||e)+"."+{hash}[e]+".chunk.js"}`. Chuỗi ternary đứng trước, và không có chuỗi tiền tố, nên `webpackURe` không khớp và không có chunk nào được tải.
  - Ngân sách 500 bị dùng hết bởi 630 URL đoán sai `./<locale>/_lib/…/index.js`. Đó là key của context map lazy của webpack (`"./te/index.js":[55355,7,[55355]]`), không phải file trên server.
- **Phân loại 62 operation còn thiếu sau khi sửa:**
  - 1 có trong SDK: `GET /Branding/Css.css`, bị cả hai lớp lọc asset bỏ (`.css`). Để nguyên.
  - Khoảng 44 chỉ có qua client cũ: `apiClient.getUrl("Items/"+id+"/ContentType", …)` cùng `apiClient.ajax({type:"POST", url})` / `getJSON(url)`. Lớp `ApiClient` nằm ở một chunk, nơi gọi ở các chunk khác, và receiver lấy từ `ServerConnections.getApiClient(id)`. Xem 48.4.
  - Khoảng 17 không có trong code UI: `*/InstantMix` của album/song/genre, `/Years`, `/Trailers`, `/Items/Suggestions`, `/Startup/FirstUser`, và 9 `RemoteSearch/<loại>` dựng động.

### 48.3. Sửa (jsapi v35, resolver)
- **`descriptor.go`:** object literal ở bất cứ đâu có `url` và `options`, trong đó `options` là options của request (`isOpt`) và có method biết được, được ghi thành request `kind: "descriptor"`.
  - `urlObjectPath`: URL object (`new URL(path, base)`, đứng riêng, đưa vào `toPathString(u)`, hoặc `u.toString()`) cho ra path của nó. Base bị bỏ, vì hàm gửi request đặt base của chính nó trước path, còn base dùng để tạo URL object chỉ là giữ chỗ.
  - `settled`/`assignedOnce`: đi qua hằng cục bộ và qua biến khai báo không giá trị rồi gán đúng một lần. Chỉ dùng cho descriptor; `constant` chung không đổi.
- **`assignLike`:** hàm chỉ trả về tham số đầu (`_objectSpread2`, `_extends` của Babel) được `optionsAt` đọc như `Object.assign`.
- **Resolver:**
  - `webpackURe` chấp nhận chuỗi `N===e?"file":` đứng trước bảng và tiền tố có thể vắng; các file đặt tên riêng thành ứng viên (`webpackNamedRe`).
  - `moduleKeyRe` nhận thêm key của context lazy (`": [số, …"`).
- **Test** (gỡ từng phần thì test trượt):
  - `TestRequestDescriptors`: dạng regenerator và dạng TypeScript; ca âm gồm options điều hướng của router, options không có method, method là tham số.
  - `TestStaticWebpackRuntime` (`split`) và `TestStaticIgnores` (context map).
- **Kết quả:**
  - **Jellyfin (dev): 3 lên 302/364 ở cả hai chế độ** (299/352 không deprecated). Dòng không khớp: 0 (`entries`), 1 (`all`, `GET /` có từ trước).
  - Chế độ `entries` tìm được 468/986 script (trước đó 30); số còn lại bị giới hạn bởi `-resolve-max` mặc định 500 (cùng các 404 của route SPA và map đoán thử).
  - Như vậy SDK đạt 302/303 phần có trong SDK.
  - **Không đổi:** snapshot jsapi và catalog của 5 target dev; Appwrite 1.087/1.098, Directus 93/136, Keycloak 341/415, Medusa 382/420.
  - Regress 18/18 (`-j 3`, 914 s); `perfgate` 8,08 s, RSS 278,7 MB.

### 48.4. Đề xuất: client cũ (`ApiClient.getUrl`), chờ chốt
- **Mẫu:** `n = ServerConnections.getApiClient(id); n.getJSON(n.getUrl("Items/Filters", {...}))`; `n.ajax({url: n.getUrl("Items/"+id+"/ContentType", q), type: "POST"})`.
  - `getUrl(name, params)` là method của lớp `ApiClient`, dựng `serverAddress + "/" + name + query`.
  - Lớp nằm ở một chunk, còn nơi gọi ở các chunk khác, với receiver không xác định được kiểu.
- **Hướng tổng quát:** coi method có thân **dựng URL từ tham số đầu trên một base của instance** là "URL builder theo tên". Nơi gọi `X.<tên>(path, …)` mà kết quả đi vào URL của một request (`getJSON(u)`, `ajax({url: u, type})`) thì path là đối số đầu.
  - Cần liên kết xuyên script theo **tên method** và **dấu hiệu thân hàm**, không theo kiểu của receiver (giống `methodOf` nhưng ở mức catalog).
  - Cần thêm danh sách method gửi request của cùng lớp (`getJSON`, `ajax`, `fetch`), cũng xác định qua thân hàm.
- **Rủi ro precision:** `getUrl` là tên phổ biến. Nên chỉ nhận khi định nghĩa duy nhất trong tập script có thân đúng dấu hiệu, và nơi gọi đưa kết quả vào một request đã nhận diện được.
- **Trần ước tính:** khoảng 44 operation trên Jellyfin. Cần kiểm thêm trên một tập khác trước khi tin là tổng quát.

## 49. Đợt 37 & 37.1: `verify -host-inflight`, root canary, re-judge, gate

- **Khi nào có lợi:** một host, RTT `r`, N = 1 thì trần là `1/r` req/s (đo được 3,6 req/s ở 273 ms). `-host-inflight N` chỉ có lợi khi `-rate` lớn hơn `1/r`. Mặc định giữ 1 (đúng thiết kế 25K: mỗi host một request mỗi lần, verdict và `Sent` giống `-concurrency 1`).
- **Đồng bộ:** singleflight (`ready`) cho canary, sub-canary và root canary; `optOnce` cho OPTIONS của canary; toàn bộ gate nằm dưới `v.mu`.
- **Root canary ở mọi N:** một câu trả lời 2xx-HTML chưa biết, dưới prefix khác `/`, kích hoạt canary gốc của origin (một lần mỗi origin). Canary này không tính vào `-max-prefixes` cho đến khi một draft của prefix `/` dùng nó.
- **Re-judge:** sau mọi probe, các `verified_alive` là 2xx-HTML được judge lại bằng nhánh đầu của `judge` với tập shell **cuối cùng**. Không gửi gì; chỉ hạ verdict; tất định bất kể thứ tự và N. Sửa luôn tính không tất định của shell `*` (2 host trở lên) vốn đã có ở N = 1 khi `-concurrency > 1`.
- **Hạ về 1:** `throttled` (429 hoặc block kiểu rate, một chiều) và `gateSer` (từ ứng viên gate đầu tiên tới khi `g.broken`, tự nhả). Request đang bay lúc đó (tối đa N−1) vẫn báo verdict thật.
