# Đặc tả chi tiết Capture v2

Bổ sung cho `docs/capture-v2-plan.md`. Mỗi bước có 6 phần: mục tiêu, thiết kế (file, API, hành vi), edge case, lỗi có thể gặp, kiểm thử, tiêu chí đạt. Thêm vào đó là danh sách **giả định cùng trạng thái kiểm chứng**.

**Ký hiệu:** [V] là đã kiểm chứng bằng mã nguồn cdproto v0.159 / chromedp v0.21.1 hoặc bằng testbed. [U] là chưa kiểm chứng; mỗi mục [U] có một kiểm thử riêng để xác nhận.

## ⚠ Sửa đổi sau đánh giá độc lập (2026-11-02) — có hiệu lực cao hơn phần bên dưới

Một agent đánh giá độc lập đã đối chiếu đặc tả với mã nguồn chromedp/cdproto và chạy 4 thử nghiệm. Thử nghiệm worker lồng nhau của chính mình cũng cho cùng kết quả. Mỗi mục dưới đây ghi rõ thay đổi.

**Nghiêm trọng**

- **C1 — Phân loại eval/inline (bước 3) sai.**
  - `setTimeout("string")` có URL rỗng và không có stack.
  - Khi bật Debugger muộn, **mọi script được gửi lại đều không có stack**. Điều này xảy ra với mọi worker, iframe và SW.
  - eval có `//# sourceURL=x.js` mang URL `x.js`.
  - Inline script sau `pushState` mang URL của route mới.
  - URL của target worker trùng với URL script chính của nó.
  
  → **Luật mới:**
  - Chỉ bỏ đúng snippet nội bộ `self` của chromedp (nội dung == `self`, chromedp.go:583) và script có `sourceURL=jsharvest-internal`.
  - **Mọi script khác có URL rỗng là `eval`.**
  - `HasSourceURL` → `eval`, lưu tên ở trường riêng.
  - `inline` chỉ áp dụng cho target page/iframe, khi URL thuộc **tập mọi URL document mà frame đó từng có** (`frameNavigated` + `navigatedWithinDocument`).
  - Fixture mới: `eval:timeout` (setTimeout dạng chuỗi), `eval:worker`.

- **C2 — Gắn vào target có thể treo vĩnh viễn (bước 2).**
  - Worker lồng nhau: `Runtime.enable` không bao giờ trả lời, nên `Do` chặn mãi. Target không bị huỷ, nên lệnh huỷ dự kiến không bao giờ chạy. Đã tái hiện độc lập 2 lần.
  - Gọi lệnh trên session đã chết cũng treo, vì chromedp bỏ reply của session không còn trong `b.pages` (browser.go:424-429).
  
  → **Thay đổi:**
  - `Do` chạy trong goroutine, có **watchdog huỷ ctx của session sau 5 giây**. Không bọc ctx truyền cho `Do` bằng `WithTimeout`, vì vòng đời `target.run` gắn với ctx đó.
  - Mọi lệnh sau đó dùng `context.WithTimeout(sessionCtx, 10s)`.
  - Việc lấy slot của semaphore phải `select` theo ctx.
  - **`worker:nested` được hạ xuống thành giới hạn đã biết.** Script của nó vẫn có thể được ghi lại qua Network của worker cha; đây là việc để thử sau.

- **C3 — Thứ tự kết thúc (bước 4).** Không ngừng nhận target mới trước khi đạt idle, nếu không sẽ mất target sinh ra trong lúc chờ. → Vẫn nhận target cho đến khi đạt idle.

**Lớn**

- **M1 — Lọc target.**
  - Context của tab ở chế độ launch có cả SW và background page của **component extension**.
  - `BrowserContextID` của context đầu tiên rỗng.
  - Worker lúc mới tạo có URL rỗng.
  
  → **Thay đổi:**
  - Bắt buộc URL là http(s) và trong scope; URL lấy từ `TargetInfoChanged`.
  - Iframe/worker: chuỗi `ParentID` phải dẫn về TargetID của tab. Cách này **thay cho việc theo dõi cây frame** và xử lý được cả OOPIF lồng nhau.
  - Bỏ script có `executionContextAuxData.isDefault=false` hoặc URL `chrome-extension:` (content script của extension ở chế độ attach).
  - Lấy context id của tab qua `Target.getTargetInfo`.
- **M2.** `EventDetachedFromTarget` chỉ có `SessionID` → khớp theo SessionID và nghe ở cấp browser (`BrowserEvents`).
- **M3.** U1 đúng (gửi lại `Network.enable` có ghi đè buffer), nhưng **fixture `<script src=big.js>` không đo được điều đó**, vì Chrome lấy lại từ memory cache. → `big.js` được **fetch chứ không chạy**; Debugger không thể bắt nó. Buffer 512 MB là cho mỗi session và nằm trong bộ nhớ renderer.
- **M4. Dương tính giả với Cloudflare.**
  - `/cdn-cgi/challenge-platform/scripts/jsd/main.js` được chèn vào cả trang bình thường.
  - Turnstile có trên các form login thông thường.
  
  → **Thay đổi:**
  - Bằng chứng từ script **chỉ dùng để gắn tag**.
  - `blocked` yêu cầu `cf-mitigated`, hoặc status 403/429/503, trên **document chính cuối cùng** (challenge tự giải rồi tải lại).
  - Fixture âm tính `/jsd-ok`.
- **M5. Chờ SW không đủ tin cậy.**
  - Angular mặc định dùng `registerWhenStable:30000`.
  - `CacheStorage.requestCacheNames` + `requestEntries` trả về **cả 11 mục precache** của vite-pwa.
  
  → **Thêm bước quét CacheStorage khi kết thúc.** Bước này không phụ thuộc thời gian, và còn hoạt động khi chạy lại với persistent profile, nơi SW không tải lại nữa.
- **M6. Store: ghi file không atomic, khôi phục file mồ côi chỉ tin vào tên.** → **Đã sửa:** ghi vào tệp tạm rồi rename; khi khôi phục, kiểm tra sha256 khớp tên file, sai thì xoá; dọn `.tmp-*`. Đã có test.
- **M7. Kẽ hở trong test.**
  - `debugger:after` giờ chỉ xuất hiện trong eval chạy **sau** `debugger;`, và phải kèm điều kiện thời gian chạy < `--idle-max`.
  - Tiêu chí bước 3 nâng lên: bước 2 + `inline:html` + `eval:main` + `eval:function` + `eval:timeout`.
  - **Bỏ `Page.getResourceContent`** (U3): không đo được, và cũng không cần.

**Nhỏ**
- Dedupe theo hash: chỉ đánh dấu đã thấy **sau khi** `getScriptSource` thành công, và vẫn ghi lại lần bắt gặp trùng (map hash → sha256) để `targets[]` và `pages[]` được gộp.
- Luật đuôi `.js` của netTracker: bắt buộc status 2xx/304 và MIME khác `text/html`, để không lưu trang 404 hoặc HTML của SPA fallback.
- Idle: khi session bị huỷ thì trừ các request đang mở của nó. WebSocket không phát `requestWillBeSent`.
- `sourcemap_url` dạng `data:` được lưu thành cờ `data:(inline)`. **Đã sửa.**
- `sha1_b32` khớp với digest của Wayback chỉ là **gợi ý**: với bản lưu gzip, digest có thể tính trên payload nén. [U]

**Cắt bớt:** luật cho Akamai/DataDome/PerimeterX (U7), `getResourceContent`, theo dõi cây frame, và nguồn phát hiện (a) trên session iframe (sự kiện attach đầu tiên đến trước khi kịp đăng ký nghe; nguồn (b) đã phủ).

**Sửa tiêu chí bước 2 khi triển khai:** script chính của worker, SW, shared worker và iframe được tải **trước khi** tool gắn vào target, nên Network không thể bắt được chúng. Spike bắt được là nhờ Debugger. Tiêu chí của bước 2 (chỉ Network) vì vậy là:
- **không tụt so với v1:** webpack đạt 3/20;
- **vite-pwa ≥ 9/10** nhờ Network trên session SW (kết quả: 9/10);
- **`big:tail` bắt được** nhờ tăng buffer (kết quả: bắt được);
- `attach_failed` không bị treo.

Những marker dựa vào Debugger được đo ở bước 3.

**Lỗi tìm ra khi triển khai bước 2:**
1. Code dọn dẹp xoá trạng thái của request khi `loadingFinished` đến trước `responseReceived`, nên request không bao giờ được lấy body. → Sửa: chỉ dọn khi kết quả đã chắc chắn. Có unit test chạy **mọi hoán vị thứ tự event**; đã kiểm chứng test bắt được lỗi cũ.
2. Request do tab khởi tạo nhưng target khác hoàn tất (script chính của worker, document của OOPIF, script của shared worker) bị tính là đang mở mãi, nên idle luôn chạm `--idle-max`. → Sửa: request không có event nào trong 5 giây thì không còn tính là đang mở.

**Tiêu chí đạt điều chỉnh** (app `edge-cases`): `eval:function`, `eval:timeout`, `eval:worker`, `worker:nested-parent`, `debugger:after` (kèm điều kiện thời gian), `big:tail`. Được phép trượt: `inline:handler` (cần click), `worker:nested`, `worker:short`.

---

## Bước 1 — Store v2

**Mục tiêu.** Mô hình lưu trữ đáp ứng được chunk resolver, chế độ monitor và dedupe với archive, đồng thời không mất dữ liệu v1.

**Thiết kế** (`internal/store`):

```go
type Record struct {
    Body         []byte
    URL          string            // rỗng với eval
    Kind         string            // file | inline | eval
    Via          string            // network | debugger
    Target       string            // page | iframe | worker | service_worker | shared_worker
    Page         string
    MIME         string
    Headers      map[string]string // chỉ giữ: content-type, etag, last-modified, sourcemap, x-sourcemap
    SourceMapURL string
    IsModule     bool
    Initiator    *Initiator        // {Type, URL, Line, Col}
    Source       string            // live | wayback
}
func (s *Store) Add(r Record) (isNew bool, err error)
```

**Trường trong `index.jsonl`:** `sha256`, `sha1_b32`, `kinds[]`, `urls[]`, `canonical_keys[]`, `via[]`, `targets[]`, `pages[]`, `mime`, `size`, `headers{}`, `sourcemap_url`, `is_module`, `initiators[]`, `source`, `first_seen`, `last_seen`.

**Quy tắc gộp** khi cùng sha256:
- Các trường dạng tập hợp được hợp lại, có giới hạn để không phình vô hạn: `urls` 200, `pages` 50, `initiators` 20.
- `headers` và `sourcemap_url`: giữ giá trị khác rỗng đầu tiên.
- `source`: live cộng wayback thành `both`.

**`sha1_b32`:** SHA-1 mã hoá base32 chuẩn RFC 4648, viết hoa, 20 byte ra đúng 32 ký tự, khớp định dạng `digest` của Wayback CDX. [V theo nghiên cứu; có test vector]

**`canonical_key`** (đã sửa khi triển khai). Gồm host viết thường cộng path; query và fragment bị bỏ. Có 3 quy tắc:
1. **Hash ngắn ngay trước đuôi `.js`/`.mjs`:** `^(.+)-([A-Za-z0-9_-]{8})(\.m?js)$`. Token được coi là hash khi có chữ số, **hoặc** lẫn cả chữ hoa lẫn chữ thường, **hoặc** là base32 viết hoa (`[A-Z2-7]{8}`).
   - Ví dụ: Vite/Rollup `index-tkF5t2Ua`, kể cả hash có dấu `-` như `index-D-eBaYxL`; Angular/esbuild `chunk-LADWWXNY`.
   - Hash của Rollup **có thể chứa `-` và `_`**, nên không tách token theo `-`.
2. **Hex nằm giữa hai dấu phân cách `.`/`-`, dài 6–64, có cả chữ số lẫn chữ cái:** webpack `main.7b54536e.js`, Next `page-e3e3e3122d5a64cf.js`.
   - Điều kiện có chữ cái để giữ nguyên số và ngày như `20240101`.
   - Điều kiện có chữ số để giữ nguyên từ thật như `decade`.
3. **Segment thư mục là id** (16–64 ký tự `[A-Za-z0-9_-]`, có cả chữ số lẫn chữ cái): buildId của Next.

Khi triển khai đã sửa 2 lỗi của bản đặc tả trước: Angular `chunk-LADWWXNY` (toàn chữ hoa, không chữ số) bị bỏ sót, và từ thật như `decade` bị xoá nhầm. Ca dương tính giả còn chấp nhận được: một từ 8 chữ hoa toàn base32 như `-SETTINGS.js`.

Riêng inline và eval:
- inline: `canonical_key = <host><path của trang>#inline`
- eval: không có key

**Flush định kỳ:** mỗi 50 file mới hoặc mỗi 10 giây, cộng một lần khi kết thúc. Mục đích là để khi bị SIGKILL thì mất tối đa một chu kỳ.

**Đối chiếu khi mở store:** file `js/<sha>.js` không có trong index (sinh ra do bị kill giữa chừng) được thêm lại vào index với `kinds:["unknown"]`.

**Edge case:**
- Body lớn hơn `--max-body` (mặc định 50 MB): bỏ qua và ghi cảnh báo.
- Body rỗng: không lưu.
- Cùng nội dung nhưng khác `kind` (một file trùng y hệt một inline script): hợp `kinds`.
- Index v1 không có trường mới: đọc bình thường.

**Lỗi có thể gặp:** đĩa đầy, hoặc lỗi ghi file. Khi đó `Add` trả lỗi, tool đếm vào `run.json` và **không dừng crawl**.

**Kiểm thử (unit, chạy với `-race`):**
- bảng ca cho `canonical_key`: 10 tên file thật lấy từ 5 app testbed, cộng các ca không được xoá (`settings.js`, `vendor-react.js`)
- test vector `sha1_b32`
- nạp index v1 (lấy từ thư mục output thật của lần chạy trước)
- gộp bản ghi
- 100 goroutine cùng gọi `Add`
- đối chiếu file mồ côi

**Tiêu chí đạt:** mọi test qua với `-race`; output v1 cũ nâng cấp không mất bản ghi nào.

---

## Bước 2 — Quản lý target, Session, netTracker

**Mục tiêu.** Bắt JS qua Network trên **mọi** target thuộc tab của mình, lấy body ngay và song song.

**Thiết kế** (`internal/capture/targets.go`, `session.go`, `network.go`):

1. **Nguồn phát hiện target:**
   - (a) `Events(ctx, target.AttachedToTarget)` trên session của tab và của mọi iframe. chromedp chỉ bật auto-attach cho target **không phải** worker. [V chromedp.go:596-608]
   - (b) `CallBrowser(target.SetDiscoverTargets{Discover:true})` cộng `BrowserEvents(target.TargetCreated)`. Nguồn này cần thiết cho **shared worker** và **worker lồng nhau**. [V spike: shared worker; U: worker lồng nhau, có fixture riêng]
2. **Lọc target thuộc phạm vi:**
   - Chế độ launch (browser riêng): nhận mọi target cùng `BrowserContextID` với tab. [V: `target.Info.BrowserContextID` có tồn tại]
   - Chế độ attach (Chrome thật, browser context mặc định dùng chung với các tab khác):
     - `iframe` và `worker`: nhận khi `ParentFrameID` thuộc cây frame của tab. Cây frame lấy từ `Page.getFrameTree`, cập nhật theo `Page.frameAttached`. [V: có trường `ParentFrameID` cho iframe và worker; với worker lồng nhau, đây là frame tổ tiên]
     - `service_worker` và `shared_worker`: nhận khi host của URL nằm trong scope.
   - Loại target được nhận: `iframe`, `worker`, `service_worker`, `shared_worker`. Bỏ qua các loại khác.
3. **Dedupe** theo `TargetID` (map có mutex). Một target có thể được báo qua cả (a) lẫn (b).
4. **Session:**
   - Với tab: dùng chính ctx của tab.
   - Với target khác: `ctx = NewContext(tab, WithTargetID(id), WithDetachOnCancel())`, rồi `Do(ctx)`. Khi khởi tạo, chromedp tự bật Runtime và Network, và với target không phải worker thì bật cả Page, DOM và auto-attach. [V]
   - Sau đó gửi lại `network.Enable{MaxTotalBufferSize: 512MB, MaxResourceBufferSize: 64MB}`. Cả hai cấu hình được. [V: trường có tồn tại; U: gửi lại có ghi đè giá trị cũ không, có fixture `big.js`]
5. **Huỷ session** khi nhận `DetachedFromTarget` hoặc `TargetDestroyed` có `TargetID` tương ứng. [V: hai event có tồn tại]
6. **netTracker** (mỗi session một cái):
   - Giữ state machine theo cờ độc lập như v1, vì event đến không theo thứ tự.
   - Coi là JS khi: `ResourceType == Script` **hoặc** MIME là JS **hoặc** đuôi `.js`/`.mjs` (ca server trả sai MIME).
   - Khi đủ cờ (responded, finished, script) thì lấy body **ngay** trong goroutine, qua **semaphore toàn cục** (mặc định 8).
   - Body rỗng hoặc lỗi trên target page/iframe: thử lại bằng `Page.getResourceContent{FrameID, URL}`. [V: cần FrameID; U: có trả được nội dung không, có test]
   - Bỏ qua URL `data:` và `blob:` ở Network; Debugger sẽ bắt `blob:`.
   - Lỗi lấy body được phân loại `evicted`, `no_resource` hoặc `other`, rồi đếm vào thống kê.
   - Request đã xong và đã lấy body thì xoá chi tiết, chỉ giữ cờ `done`, để map không phình.

**Edge case:**
- Redirect: `requestWillBeSent` lặp lại với cùng ID; URL cuối cùng lấy từ response.
- 304: body lấy từ cache.
- Target biến mất giữa lúc đang lấy body: lỗi được đếm, không crash.
- Mục tiêu có hàng nghìn request: semaphore cộng xoá chi tiết giúp kiểm soát bộ nhớ.
- Cùng một script đến qua tab và qua SW: store dedupe.

**Lỗi có thể gặp:**
- Gắn vào thất bại vì target đã biến mất: ghi DEBUG và đếm `attach_failed`.
- Gắn vào một target mà phiên chromedp tự gắn trước đó đang giữ: spike cho thấy chạy được. [V]

**Fixture mới cho testbed** (trong `webpack-vanilla/extra/`):
- `nested-worker.js`: một worker tạo ra một worker khác (`JSHMARK:worker:nested`).
- `short-worker.js`: worker gọi `self.close()` ngay (`JSHMARK:worker:short`). Đây là ca có thể không bắt được và được **ghi nhận là giới hạn**.
- `big.js`: khoảng 25 MB, có marker ở cuối (`JSHMARK:big:tail`), lớn hơn giới hạn mặc định 20 MB cho mỗi file.

**Kiểm thử:**
- Unit: netTracker nhận chuỗi event giả lập theo mọi hoán vị thứ tự.
- Integration: bench trên webpack-vanilla và vite-pwa.
- Không còn Chrome sót lại sau khi chạy.
- Đếm `runtime.NumGoroutine()` lúc kết thúc ở chế độ debug.

**Tiêu chí đạt:**
- webpack-vanilla: bắt được mọi marker **dạng file** đã bắt được ở spike (entry, home, telemetry, worker ×2, sw ×2, shared, iframe), cộng `worker:nested` và `big:tail`.
- vite-pwa: ≥ 9/10 (mọi file mà SW precache).
- Không có goroutine nào rò rỉ.

---

## Bước 3 — scriptTracker (Debugger)

**Mục tiêu.** Bắt inline, eval, `blob:` và script đã chạy trước khi gắn vào; không lưu nhầm script nội bộ của CDP; không bao giờ làm treo trang.

**Thiết kế** (`internal/capture/scripts.go`):

1. Đăng ký `Events(ctx, debugger.ScriptParsed)` và `Events(ctx, debugger.Paused)` **trước**, rồi mới gọi `debugger.Enable{MaxScriptsCacheSize: 100MB}`, sau đó `SetSkipAllPauses{true}`.
   - Lưới an toàn: khi nhận `Debugger.paused` thì gọi `Debugger.resume` ngay, vì có một khe nhỏ giữa lúc enable và lúc skip có hiệu lực.
   - Với tab: bật trước khi navigate.
2. **Dedupe theo `scriptParsed.hash`** trong một map toàn cục cho mọi session. Đã thấy hash thì không gọi `getScriptSource`. [V: trường `Hash` có tồn tại]
3. **Phân loại** (theo thứ tự ưu tiên):
   - `ScriptLanguage == WebAssembly` → bỏ qua.
   - `URL` rỗng:
     - **không có `StackTrace`** → coi là **script nội bộ của CDP** (do `Runtime.evaluate` của chromedp hoặc của tool tạo ra) → bỏ qua và đếm `cdp_internal`. [U, có test]
     - có `StackTrace` → `kind = eval`; nếu `HasSourceURL` thì vẫn là eval có tên.
   - `URL` trùng URL document của frame/target (inline `<script>` hoặc handler dạng attribute) → `kind = inline`.
   - Còn lại → `kind = file`. Network cũng thường bắt được những file này; store sẽ dedupe.
   - Script nội bộ mà tool tự chèn sau này phải mang `//# sourceURL=jsharvest-internal` → bỏ qua.
4. Gọi `getScriptSource` qua chung semaphore với Network.
5. Giới hạn **20.000 script cho mỗi session**. Vượt quá thì ghi cảnh báo và chỉ còn lấy script có URL (bỏ eval). Mục đích là chặn những trang sinh eval liên tục.

**Edge case:**
- Handler inline dạng `onclick="..."` được biên dịch muộn, có URL của trang nhưng không có stack: được phân là `inline`, đúng ý.
- `new Function(...)` và `setTimeout("string")` có stack nên được phân là eval. [U, fixture]
- Cùng một mã nguồn được parse ở nhiều context (nhiều iframe): dedupe theo hash.
- Mỗi lần điều hướng sang tài liệu mới, Debugger báo lại các script: dedupe theo hash.

**Lỗi có thể gặp:**
- `getScriptSource` lỗi vì script đã bị thu gom (GC) hoặc session đóng: đếm, bỏ qua.
- Trang có `debugger;` chạy liên tục: được skip pauses cộng resume xử lý.

**Fixture mới cho testbed:**
- `extra/debugger.js`: chứa `debugger;` rồi in marker `JSHMARK:debugger:after`, được nạp từ trang chính. Kiểm tra tool không bị treo và vẫn bắt được marker.
- Thêm vào app webpack: `new Function(atob(...))` mang marker `JSHMARK:eval:function`.
- Thêm vào app webpack: `<button onclick="...JSHMARK:inline:handler...">`. Handler chỉ được biên dịch khi click, nên **khi tải thụ động sẽ không bắt được**. Ca này dùng để đo bước khám phá trang về sau.

**Kiểm thử:**
- Bench trên webpack-vanilla: phải bắt được `inline:html`, `eval:main`, `eval:function` và `debugger:after`.
- **Kiểm tra không lưu rác:** sau khi crawl, không có bản ghi `kind=eval` nào có body là `self` hoặc trùng với các snippet nội bộ của chromedp (grep trong output).
- Thời gian crawl không được tăng quá 30% so với bước 2 (ghi lại để so).

**Tiêu chí đạt:** webpack-vanilla ≥ 11/20 trên các marker gốc; không có script nội bộ CDP nào trong output; không bị treo.

---

## Bước 4 — Theo dõi idle đa session, chờ service worker

**Mục tiêu.** Biết khi nào nên dừng một cách hợp lý trên mọi session, và chờ đủ lâu để SW kịp precache.

**Thiết kế** (`internal/capture/activity.go`):
- Mọi tracker báo về một bộ đếm chung: số request đang mở theo session, và thời điểm có hoạt động gần nhất.
- `swSince`: thời điểm session service worker đầu tiên được gắn vào.
- **Điều kiện dừng:**
  - số request đang mở ≤ 2 **và** đã im lặng ít nhất `--idle` (mặc định 1,5 giây)
  - **và**, nếu có SW: đã qua ít nhất `--sw-wait` (mặc định 8 giây) kể từ `swSince`
  - giới hạn trên là `--idle-max` (mặc định 30 giây)
- **Khi hết thời gian:** ghi WARN, liệt kê tối đa 10 request còn mở kèm session của chúng, và đặt `idle.reason="max"` trong `run.json`.
- **Thứ tự kết thúc:**
  1. Ngừng nhận target mới.
  2. Chờ idle.
  3. Chờ các lần lấy body còn dở, tối đa 10 giây.
  4. Flush store.
  5. Ghi `run.json`.
  6. Huỷ các session.
  7. Đóng tab/browser.

**Edge case:**
- Trang poll liên tục, nên không bao giờ đủ im lặng: dừng ở `--idle-max` kèm cảnh báo, kết quả vẫn hợp lệ.
- SW không bao giờ activate: `--sw-wait` vẫn chỉ tính từ lúc gắn vào, nên không treo.
- WebSocket và EventSource: được tính trong ngưỡng "≤ 2 request đang mở".

**Kiểm thử:**
- Unit: logic điều kiện dừng với đồng hồ giả.
- Integration: angular-ngsw. Agent đã quan sát SW precache khoảng 5 giây sau khi tải trang, nhưng nguyên nhân [U].
- Một trang poll mỗi 500 ms (fixture `extra/poll.html`, nạp từ trang chính) phải dừng đúng ở `--idle-max` và có cảnh báo.

**Tiêu chí đạt:** angular-ngsw đạt 7/7; fixture poll dừng đúng hạn và có cảnh báo.

---

## Bước 5 — Phát hiện bị chặn, `run.json`, mã thoát

**Mục tiêu.** Không bao giờ âm thầm báo thành công khi thực ra bị chặn. **Chỉ phát hiện, không vượt qua.**

**Thiết kế** (`internal/detect`):
- **Dữ liệu đầu vào:**
  - response của document chính: event Network có `Type == Document` và frame chính (status, header)
  - `document.title` đọc qua `Runtime.evaluate`; script nội bộ này sẽ bị bước 3 lọc
  - danh sách URL script đã bắt được
- **Bộ luật dạng dữ liệu** (mở rộng được):
  - Cloudflare: header `cf-mitigated: challenge`; **hoặc** status 403/503 + `server: cloudflare` + title chứa "Just a moment"; **hoặc** có script `/cdn-cgi/challenge-platform/` hoặc `challenges.cloudflare.com/turnstile`. [V: script của CF đã quan sát trong lần chạy thật của người dùng; các header là U]
  - Akamai, DataDome, PerimeterX: luật dựa trên header, cookie và tên script. [U, ghi rõ là chưa kiểm chứng]
- **Hành vi khi bị chặn:**
  - ghi WARN, đặt `run.json.blocked = {vendor, evidence[]}`
  - script của challenge được gắn `tags:["challenge"]` trong index
  - **thoát với mã 3**
- **Mã thoát:** 0 là xong, 1 là lỗi, 3 là bị chặn, 130 là bị ngắt.
- **`run.json`** chứa:
  - `version`, `target`, `role`, `mode`, `started`, `ended`, `duration_ms`
  - `targets{type: count}`, `attach_failed`
  - `scripts{seen, new, by_via, by_kind}`, `bodies_lost{evicted, no_resource, other}`, `cdp_internal`
  - `idle{reason, inflight[]}`, `blocked`, `warnings[]`, `exit_code`

**Testbed:** route `/blocked` trả 503, `server: cloudflare`, `cf-mitigated: challenge`, kèm HTML có title "Just a moment...". Đây là fixture giả, không liên quan đến dịch vụ thật.

**Kiểm thử:**
- Unit: bộ luật trên các response mẫu, cả ca dương tính lẫn âm tính (trang 503 thường không được bị coi là bị chặn).
- Integration: `/blocked` phải cho mã thoát 3; cả 5 app phải cho `blocked=false`.

**Tiêu chí đạt:** đúng như trên, và không có dương tính giả nào trên 5 app.

---

## Bước 6 — Đo, tinh chỉnh, dọn dẹp

- Chạy `bench.sh` trên 5 app cộng các fixture mới, và lưu bảng kết quả trước/sau vào `docs/testbed-results-*.md`.
- Chạy một lần crawl với binary build bằng `-race`.
- Kiểm tra không còn Chrome sót lại, và goroutine ổn định.
- Xoá `spike/`.
- Cập nhật CLAUDE.md.
- **Tiêu chí tổng:** ≥ 38/56 trên 5 app gốc; các tiêu chí riêng của từng bước đều đạt; mọi giả định [U] đều đã có kết quả (đúng hoặc sai, kèm cách xử lý).

---

## Tổng hợp giả định chưa kiểm chứng [U] và cách xác nhận

| # | Giả định | Kiểm chứng bằng |
|---|---|---|
| U1 | Gửi lại `Network.enable` với buffer lớn hơn sẽ ghi đè giá trị cũ | fixture `big.js` 25 MB |
| U2 | Phát hiện target ở cấp browser bắt được worker lồng nhau | fixture `nested-worker.js` |
| U3 | `Page.getResourceContent` bù được body rỗng | log so sánh số body được bù |
| U4 | Script nội bộ CDP có URL rỗng và không có `StackTrace`, còn eval của trang thì có | grep output tìm `self`; marker `eval:main`/`eval:function` vẫn bắt được |
| U5 | `new Function`/`setTimeout(string)` có `StackTrace` | fixture `eval:function` |
| U6 | SW của Angular precache trong ≤ 8 giây | bench angular-ngsw cộng log thời điểm |
| U7 | Luật phát hiện cho Akamai, DataDome, PerimeterX | chỉ unit test với mẫu; ghi rõ chưa kiểm chứng ngoài thực tế |
| U8 | Debugger không làm chậm quá 30% | so thời gian giữa bước 2 và bước 3 |

## Các quyết định cần người dùng xác nhận
- Giá trị mặc định: `--sw-wait 8s`, `--idle-max 30s`, semaphore 8, buffer 512/64 MB, `--max-body 50MB`.
- Mã thoát 3 khi bị chặn.
- `short-worker` được chấp nhận là giới hạn đã biết.
