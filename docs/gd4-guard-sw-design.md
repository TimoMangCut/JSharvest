# GĐ4 4.3c — Guard và service worker: thiết kế

## 0. Sửa đổi sau đánh giá độc lập (có hiệu lực cao hơn các mục bên dưới)

Agent đánh giá đã đo bằng CDP thô trên Chrome 156. **Nguyên nhân gốc rộng hơn mục 1:** `Fetch.enable` ở cấp browser chỉ tác động lên các loader **tạo ra sau khi bật**. Document hoặc worker đã tồn tại từ trước chỉ bị chặn khi bật `Fetch` trên **session của chính nó**. Thứ quyết định là thời điểm khởi động, không phải tab.

1. **`watch` gắn vào trang đã tải sẵn thì trang đó không được bảo vệ** (đã kiểm). Một SPA không điều hướng lại nên cả phiên không có guard. Sửa: lúc `Start`, bật `Fetch` trên session riêng của **mọi target đã tồn tại** thuộc phạm vi bảo vệ:
   - session của chính tab;
   - iframe khác site và dedicated worker của tab (theo chuỗi `ParentID`);
   - service worker và shared worker trong scope;
   - service worker và shared worker có origin trùng với một frame đang có trong tab (ví dụ iframe SSO).
   - Target khởi động **sau** `Start` đã được tầng browser chặn, kể cả service worker được đánh thức bởi push, sync hay cập nhật phiên bản (đã kiểm), nên không cần theo dõi target mới để đảm bảo an toàn.
2. **`otherTab` có tác dụng thật** (đã kiểm): tab mới của người dùng mở sau `Start` *có* bị tạm dừng ở tầng browser, và chỉ `otherTab` thả nó qua. Phải giữ nguyên. Nhận định "tab khác vốn an toàn" ở mục 1 bên dưới chỉ đúng với tab đã tải trước `Start`.
3. **Fail-closed thật sự:** không gắn được hoặc không bật được `Fetch` trên một target có sẵn → `Start` trả lỗi và lần chạy dừng (exit 1). Không chỉ cảnh báo.
4. **`Stop`:**
   - (a) chờ cho tới khi không handler nào đang chạy **và** không có `requestPaused` mới trong 400 ms (tối đa 5 s), vì beacon và `keepalive` lúc `pagehide` bị tạm dừng 5–10 ms sau khi đóng tab; dùng bộ đếm, không dùng `WaitGroup.Add` song song với `Wait`;
   - (b) request còn treo được trả lời bằng **response giả**, chỉ fail khi fulfill lỗi (theo M6 của thiết kế guard; fail khiến Workbox BackgroundSync gửi lại sau);
   - (c) `Fetch.disable` rồi detach các session target, **trước** tầng browser: request đang treo ở tầng worker sẽ bị tạm dừng lại ở tầng browser (đã kiểm), nên tầng browser là lưới an toàn;
   - (d) cuối cùng mới tắt tầng browser (chỉ ở chế độ attach).
5. **Điều hướng do service worker proxy** (Workbox NavigationRoute) đến tầng worker với `resourceType=XHR`. Nhận `200 {}` thì tab người dùng hiện ra `{}`. Phản hồi giả là **204** khi `Accept` bắt đầu bằng `text/html`, hoặc có `Upgrade-Insecure-Requests`, hoặc `Sec-Fetch-Mode: navigate`.
6. **Không có cách khắc phục:** jsharvest bị kill (SIGKILL, hết bộ nhớ) khi đang attach thì websocket đóng, và Chrome cho mọi request đang treo đi tiếp. Có ghi trong tài liệu.

Các phương án đã loại:
- `Network.setBypassServiceWorker`: request service worker tự gửi vẫn lọt, và làm thay đổi hành vi của tab người dùng.
- Auto-attach cấp browser với `waitForDebuggerOnStart`: vẫn lọt request đã đánh thức service worker, và tạm dừng cả service worker không liên quan của người dùng.

## 1. Đo được gì (spike ngày 2026-11-03)

`Fetch.enable` ở cấp browser (cách guard đang làm) **chỉ** chặn request của tab mà tool tạo hoặc gắn vào, cùng iframe (kể cả iframe khác site) và dedicated worker của tab đó:

| Nguồn request | Tab của tool | Tab khác của người dùng |
|---|---|---|
| trang, iframe cùng site, iframe khác site, dedicated worker | bị chặn | **không** bị chặn |
| service worker **khởi động sau** khi bật `Fetch` (launch, profile mới) | bị chặn | — |
| service worker **đã chạy từ trước** (attach, `watch`, người dùng đã vào site) | **không bị chặn** | không bị chặn |

Hệ quả:
- **Lỗ hổng.** Với service worker đã chạy sẵn và proxy mọi request (`respondWith(fetch(e.request))`, phổ biến ở PWA và Workbox NetworkFirst), request của trang đi qua service worker và lọt hoàn toàn. Đo trên `guard-cases` ở chế độ `-attach`, sau khi tab người dùng đã đăng ký service worker: 8 request ghi hoặc phá huỷ tới server, guard chỉ chặn 3.
- **Tab khác vốn an toàn:** nhận định trong review code 4.3 rằng guard chặn ghi của tab khác **không đúng**, vì request của tab khác không bao giờ tới guard. Logic `otherTab` chỉ còn là lớp phòng thủ thêm.
- **`Fetch.enable` trên session của chính service worker** chặn được cả request service worker tự gửi lẫn request nó proxy cho trang. Đây là **một tầng chặn riêng**, nằm trước tầng browser và có `RequestID` riêng (`job-15` rồi mới đến `job-17`). Nếu tầng service worker giả lập response thì request không bao giờ tới tầng browser; nếu cho qua thì tầng browser tạm dừng thêm một lần.
- Shared worker: đo ở launch thì bị chặn. Ở attach với shared worker đã chạy từ trước thì chưa đo, nhưng xử lý giống service worker.
- **Lỗi fixture:** `guard-cases` gọi `/csd` (`Clear-Site-Data: "cookies", "storage"`), mà `"storage"` xoá đăng ký service worker, nên ca POST qua service worker chưa bao giờ chạy. Lỗi `attach_failed: timeout` có từ GĐ4.1 cũng là do service worker bị xoá đúng lúc đang gắn vào. Đã sửa: service worker giờ đăng ký sau khi ca CSD xong. Fixture thêm `write-sw-own` (service worker tự gửi) và `write-shared` (shared worker).

## 2. Thiết kế

1. **Guard có session riêng trên từng service worker và shared worker trong scope**, độc lập với capture:
   - Lúc `Start`: `Target.getTargets` lấy các worker đang chạy. Sau đó dùng discovery (`TargetCreated`, `TargetInfoChanged`) cho các worker mới.
   - Điều kiện chọn: kiểu `service_worker` hoặc `shared_worker`, URL http(s), **cùng browser context với tab**, host **trong scope** (thêm `Options.InScope`).
   - Cách gắn: `chromedp.NewContext(base, WithTargetID, WithDetachOnCancel)`, có watchdog 5 s như capture, rồi `Fetch.enable{*, Request}` trên session đó và nghe `requestPaused` **của session đó**.
   - Lý do không dùng session của capture: capture huỷ session ở `finish`, trước khi tab đóng. Detach một session đang có request bị tạm dừng thì Chrome **cho các request đó đi tiếp**, trái với nguyên tắc "không bao giờ continue request đã giữ lại".
2. **Xử lý:** dùng cùng `Rules.Classify`. Trả lời **trên chính session đó** (`chromedp.Call` với ctx của session), không qua `CallBrowser`. Không áp dụng `otherTab`: service worker trong scope luôn được bảo vệ. Request bị chặn được ghi lại như các request khác, kèm `target: service_worker|shared_worker`.
3. **Fail-closed:**
   - Gắn hoặc bật `Fetch` thất bại → `Stats.WorkersUnguarded++`, cảnh báo trong `run.json` và log mức Warn.
   - Khoảng hở còn lại: request mà worker gửi **trước khi** guard kịp gắn vào. Trường hợp này chỉ xảy ra với worker khởi động *trong lúc* chạy ở chế độ attach; ở launch thì tầng browser đã phủ. Có ghi trong tài liệu.
4. **`Stop`:** chờ các handler đang chạy; fail mọi request còn treo **trên đúng session của nó**; `Fetch.disable` trên session worker; rồi mới detach. Ở launch cũng làm vậy, vì service worker sống lâu hơn tab.
5. **Phạm vi:** service worker trong scope dùng chung cho mọi tab cùng origin. Vì vậy ở `watch`, tab khác **cùng target** gửi ghi qua service worker cũng bị chặn. Điều này được chấp nhận, vì vẫn là target đó, và có ghi trong cảnh báo. Service worker của site khác thì không động tới.
6. **Thứ tự khởi động:** guard bật trước capture và trước khi điều hướng (như hiện nay), nên service worker đang chạy được gắn trước khi trang kịp gửi gì.

## 3. Nghiệm thu
- `GATE=1 bench.sh`: `guard-cases` (launch) không có request nào trong `forbidden.txt` (20 path, gồm `write-via-sw`, `write-sw-own`, `write-shared`) tới server; request trong `required.txt` vẫn tới.
- `attach-guard.sh` thêm ca **service worker chạy sẵn**: trước khi chạy jsharvest, tab của người dùng đã mở `guard-cases` (đăng ký service worker và để nó chạy). Kết quả phải là 0/20 request bị cấm lọt; tab của người dùng ở origin khác vẫn ghi được.
- Unit test cho phần chọn worker (scope, browser context, scheme) và thứ tự `Stop`.

## 4. Kết quả (2026-11-03)

**Cài đặt** (`internal/guard/guard.go`):
- `guardExisting` bật tầng chặn trên session riêng của mọi target có sẵn lúc `Start`. Gắn hoặc bật `Fetch` thất bại thì `Start` trả lỗi.
- Request được trả lời trên đúng tầng đã tạm dừng nó.
- Request được xem là điều hướng theo header (`Accept: text/html`, `Upgrade-Insecure-Requests`, `Sec-Fetch-Mode: navigate`) thì nhận `204`.
- `Stop`: chờ yên 400 ms (bộ đếm, không dùng `WaitGroup`); trả lời giả request còn treo; đóng các tầng target trước, tầng browser sau.
- `Clear-Site-Data` được khử trùng theo id của request, vì guard và capture có thể cùng nghe thấy.
- Scope truyền từ engine; với `-urls` là hợp các scope.

**Lỗi fixture đã sửa:**
- `Clear-Site-Data: "storage"` xoá service worker của `guard-cases`, nên ca POST qua service worker chưa từng chạy, và lỗi `attach_failed: timeout` tồn tại từ GĐ4.1. Service worker giờ đăng ký sau ca CSD; lỗi timeout biến mất.
- Thêm ca `write-sw-own`, `write-shared`; `forbidden.txt` có 20 path.

**Kiểm chứng:**

| Kịch bản | Trước khi sửa | Sau khi sửa |
|---|---|---|
| `crawl -attach`, service worker của target đã chạy từ trước | **11** request bị cấm tới server | **0** (guard chặn 17; `targets_guarded: 1`) |
| `watch -tab` trên trang đã tải, ghi mỗi 500 ms (binary 4.3 so với binary mới) | **8** request ghi lọt trong 4 s | **0**; tab vẫn còn |
| `crawl` launch `guard-cases` (gate) | 15 bị chặn; ca service worker không chạy | **19** bị chặn, gồm POST qua service worker, service worker tự gửi, shared worker; 0/20 path bị cấm tới server |
| Tab người dùng ở site khác, ghi mỗi 300 ms | — | vẫn ghi được (48 lần trong lúc chạy) |

`testbed/attach-guard.sh` có 3 pha: `-urls` trong tab của tool; service worker chạy sẵn; `watch` trên trang đã tải.

**Giới hạn còn lại:**
- `Clear-Site-Data` của một response đi qua service worker khởi động *trong lúc* chạy có thể không được báo, vì session của capture gắn vào sau request đó. Đây chỉ là thiếu sót về báo cáo; việc chặn vẫn do tầng browser đảm nhận.
- jsharvest bị kill khi đang attach thì mọi request đang treo sẽ đi tiếp (không có cách khắc phục).
- Service worker *ngoài* scope, không trùng origin với frame nào lúc `Start`, mà sau đó mới điều khiển một iframe của tab, thì không được tầng riêng bảo vệ. Iframe mới thì có tầng browser.
- Chưa đo: navigation preload; shared worker đã chạy từ trước ở chế độ attach (được xử lý giống service worker, nhưng chưa có ca kiểm).
