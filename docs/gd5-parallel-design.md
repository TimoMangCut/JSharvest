# Song song theo tuỳ chọn (`-tabs`, `-concurrency`)

**Yêu cầu của người dùng (2026-11-05):** hệ thống thật dư tải; song song phải **dùng được bằng cờ**, còn bật hay không là do người dùng quyết. **Mặc định giữ nguyên tuần tự** (`-tabs 1`, `-concurrency 1`), nên mọi gate hiện có vẫn giữ nguyên ý nghĩa.

## 1. Những gì đã song song sẵn

- capture: các event của CDP và việc lấy body chạy song song; mỗi target (tab, iframe, worker, service worker) có phiên riêng;
- guard;
- phân tích tĩnh (nhóm worker);
- store và writer của `requests.jsonl` (có khoá).

Phần **gửi request tới target** thì tuần tự: crawl một tab và từng trang; batch từng URL; `authz`, `replay` từng request.

## 2. `-concurrency N` cho `authz`, `replay` (và kiểm live của `archive`)

- `Sender` cho phép N request đang bay cùng lúc (semaphore). `-rate` vẫn là **trần tổng** (`-rate 0` = không giới hạn); `-max`, các điều kiện dừng (429, `cf-mitigated`…) và `sent.jsonl` dùng chung cho mọi luồng.
- `authz`: N mục (endpoint) chạy song song. **Bên trong** một mục giữ nguyên thứ tự (bản thử trước, đối chứng sau, rồi không danh tính), vì đó là điều kiện để phát hiện cache dùng chung. Kiểm phiên (`alive`) và `downgrade` theo role dùng khoá theo role. Thứ tự các mục trong `authz.json` theo `diff.json` (không theo thứ tự xong).
- `replay -flow`: các bước của một cụm phụ thuộc nhau, nên **vẫn tuần tự**; `-concurrency` không áp dụng.
- `archive`: chỉ phần kiểm live tới target; Wayback, OTX và Common Crawl giữ nhịp riêng (bên thứ ba, giới hạn của họ).

## 3. `-tabs N` cho `crawl`

N tab trong **một** trình duyệt, dùng chung guard (guard ở cấp browser nên đã chặn mọi tab).

**3a. Batch `-urls`:** N URL chạy cùng lúc, mỗi URL một tab và một run (như hiện nay), tối đa N tab mở cùng lúc; `-page-rate` là trần tổng.

**3b. Frontier (`-depth`, `-explore`):** N tab lấy trang từ **một hàng đợi chung** (có khoá), thuộc **một run** (một run ID, một `run.json`):
- mỗi tab có capture, explorer, theo dõi popup và xử lý hộp thoại riêng, nên request và thao tác của tab nào được gom theo đúng tab đó;
- `flows.jsonl`: action id có tiền tố theo tab (`t2:a5`), để không trùng;
- keeper giữ phiên: **một** keeper cho cả run; khi một tab thấy mất phiên thì các tab khác dừng nhận trang mới cho tới khi khôi phục xong (khoá);
- dừng chung khi bị chặn, bị 429/503 liên tiếp, hoặc mất phiên;
- kết thúc khi hàng đợi rỗng **và** không tab nào đang bận (một tab đang bận có thể còn thêm trang vào hàng đợi).

**Dữ liệu dùng chung:**
- **Store:** một registry `dir → *Store` có đếm tham chiếu, để hai URL cùng host (batch) không mở hai store trên cùng `index.jsonl`.
- **Writer `requests.jsonl`:** một writer cho mỗi thư mục, id tăng dần chung.
- **Run ID:** thêm hậu tố khi trùng mili-giây (`…Z-2`).
- `pages.jsonl`: ghi qua một encoder có khoá.
- `scripts` của run (`TakeTouched`): theo run, không theo store. Store chung nên phải ghi nhận theo run (tập SHA của từng run).
- Thống kê guard theo run: lọc các bản ghi của guard theo tab.

**Không hỗ trợ:**
- `-tabs` > 1 với `-attach` (Chrome của người dùng): báo lỗi;
- `watch` (một tab do người điều khiển).

## 4. Gate (`testbed/parallel-check.sh`)

1. **frontier-app**, `-tabs 3` so với `-tabs 1`: cùng tập trang đã thăm và cùng các mục bị liệt kê; không request nào vào hai cụm; `flows.jsonl` không trùng action id; `runs.jsonl` có một run.
2. **flows-app**, `crawl -explore -tabs 3`: mọi tính năng vẫn được gom đúng (`flowscore` như `explore-check`).
3. **session-app**, `-role user -tabs 3`: mất phiên ở một tab được khôi phục một lần, các tab khác không bị kết luận sai; không có trang nào bị thăm hai lần.
4. **Batch** `-urls` gồm 6 URL trên 2 host, `-tabs 3`: đủ 6 run, run ID không trùng, `index.jsonl` của mỗi host không hỏng (mọi dòng đọc được, không mất script so với khi chạy tuần tự).
5. **`authz -concurrency 4`** trên authz-app: kết luận giống hệt khi chạy tuần tự; log server khớp `sent.jsonl`.
6. **Nhịp:** `-tabs 3 -page-rate 2` và `-concurrency 4 -rate 2` không vượt 2 request/giây trên log server.
7. Mọi gate cũ (mặc định `-tabs 1`) vẫn đạt.

## 5. Đánh giá độc lập (2026-11-05) — có hiệu lực cao hơn mục 1–4

Kết luận: `-concurrency` và batch `-tabs` làm an toàn được nếu sửa đúng các chỗ được chỉ ra; **frontier `-tabs` phải tách engine** thành trạng thái của run và trạng thái của tab trước, không thể chỉ đấu nối. Ba giai đoạn, mỗi giai đoạn một commit và có gate riêng:

**A. `-concurrency` cho `authz`:**
- `Sender` đặt chỗ theo lịch (`next = max(now, next) + gap`, giữ khoá); kiểm lại `stopped` và ngân sách **sau** khi chờ;
- mỗi role chỉ một lần kiểm phiên tại một thời điểm (single-flight); `dead` và `good` có khoá;
- việc hạ kết luận (`downgrade`) chạy thành một lượt cuối, theo thời điểm: một bản thử `enforced` của role đã chết, được trả lời sau khi lần kiểm phiên tốt cuối cùng bắt đầu, thì thành `unclear`;
- cookie danh tính bị server xoay vòng thì role đó quay về một request tại một thời điểm;
- `stopped` là "không biết", không phải "chết";
- các mục ghi vào `authz.json` theo thứ tự của `diff.json`.

`replay -flow` vẫn tuần tự (các bước phụ thuộc nhau); `archive` chưa song song hoá.

**B. Batch `-tabs`:**
- mỗi URL có **browser context riêng** (`Target.createBrowserContext`): cookie, cache, sessionStorage và service worker tách hẳn;
- guard: bản ghi được nhận theo capture (`Take(claim)`), không lấy hết; `navHeld` theo frame; không còn `SetPage` toàn cục;
- mỗi run một writer; tập script và số script mới tính theo giá trị trả về của `Add`;
- registry store theo đường dẫn tuyệt đối; ghi `endpoints.jsonl`, `run.json`, `blocked.har` bằng file tạm riêng cộng `rename`;
- keeper: `install` một lần cho mỗi browser, dùng chung theo role;
- `idle` chỉ "chạm" với target của mình;
- tab ở nền có thể bị bóp timer: kiểm `visibilityState`.

**C. Frontier `-tabs`:**
- tách engine thành `runState` và `tabState`;
- `flow.Build` biết làn (`Lane` trên Request và Event): cửa sổ thời gian, handler và chu kỳ chỉ khớp trong cùng làn; template và `depends_on` vẫn tính chung;
- một chủ duy nhất cho service worker và shared worker;
- keeper có epoch: trang nào bị thăm trong lúc mất phiên thì thăm lại;
- hàng đợi: hạ độ sâu khi gặp lại URL; giữ quyền thăm `FinalURL` trong khoá; kết thúc bằng điều kiện "hàng đợi rỗng và không tab nào bận"; dừng bằng cờ, không bằng huỷ ctx;
- explore: `seen` và `-explore-total` dùng chung;
- một bộ phân tích script cho cả run.

Gate của C có thêm: kiểm làn nhất quán, thăm cùng tập trang mà không cần `-max-pages`, kiểm `visibilityState`.

**`Tabs` không đưa vào `RunConfig`**, để monitor vẫn so được một run `-tabs 3` với một run `-tabs 1`; ghi ở ngoài `config`.

## 6. Giai đoạn A: XONG (2026-11-05)

- `jsharvest authz -concurrency N` (mặc định 1). `replay -flow` vẫn luôn tuần tự (truyền 1 cho `Sender`).
- `Sender`: semaphore N; đặt chỗ theo lịch dưới khoá; kiểm `stopped` lại sau khi chờ tới lượt.
- `authz`: một nhóm worker trên danh sách mục; kết quả ghi theo chỉ số, nên `authz.json` theo thứ tự của `diff.json`.
- `roleCtx`:
  - `mu` cho việc kiểm phiên (single-flight), `dead`, `goodAt`;
  - `serial` là khoá "một bản thử tại một thời điểm", dùng khi request có liên kết credential (`credentialLink`) hoặc khi `rotates` (server đổi giá trị cookie của role: `updateJar` trả `turned`).
- `alive`: `errStopped`, `ErrBudget`, huỷ thì là "không biết", không đánh dấu chết.
- `Trial.at` (thời điểm có trả lời); `downgrade()` chạy một lượt sau mọi mục.
- Gate `testbed/replay-check.sh`:
  - B2: `-concurrency 4 -rate 0`, kết luận và thứ tự giống hệt B, `authzscore`, log server khớp `sent.jsonl`;
  - B3: `-concurrency 4 -rate 10`, khoảng cách nhỏ nhất giữa hai request ≥ 90 ms.
  - Đo được: B mất 0,8 s (`-rate 50`, tuần tự); B2 mất 17 ms; B3 với 41 request mất 4,0 s.

## 7. Giai đoạn B: XONG (2026-11-05)

- `crawl -urls FILE -tabs N` (mặc định 1, chạy y như cũ). Báo lỗi khi dùng `-tabs > 1` không kèm `-urls` (frontier là giai đoạn C) hoặc dùng với `-attach`.
- **Browser context riêng cho mỗi URL** (`chromedp.WithNewBrowserContext`). Cookie của context gốc (profile) được chép sang (`copyCookies`); IndexedDB, service worker và localStorage của profile thì không. Với `-role`, keeper nạp cookie và storage từ snapshot vào context đó: `Storage.get/setCookies` có `browserContextId`.
  - Đã kiểm bằng Chrome thật (`go test -tags chrome ./internal/guard/`): `Fetch` ở cấp browser chặn được context tạo sau; preference tắt prefetch có hiệu lực trong context mới (có ca đối chứng không guard cho thấy prefetch xảy ra); tab ở trạng thái `visible`.
- **Guard chung, bản ghi nhận theo tab:**
  - `TakeFor(claim)`; `Capture.Owns(networkID, frame, opener)` dựa trên request id và frame mà các session của tab đã thấy, cộng id target của các session đó;
  - `Record.opener` là tab đã mở popup, đi theo chuỗi opener;
  - phần không tab nào nhận được lấy **sau khi guard đã yên** (`g.Stop`) và ghi vào `blocked.jsonl` của URL có scope chứa host đó; số lượng ghi ở `batch-*.json` `unclaimed_held`.
- Thống kê guard của một run khi chạy chung: lấy từ bản ghi đã nhận (`blocked`, `by_reason`), cộng bộ đếm Clear-Site-Data và WebSocket của chính capture, và `passed_login` theo frame (`Guard.PassedLogin`). `answer_errors` và `held_navigations` của browser không tính vào run.
- **Thư mục output dùng chung** (`engine/shared.go`):
  - registry `outDir` theo đường dẫn tuyệt đối (một `Store`, một `AutoFlush`);
  - `dir.mu` bao các lần ghi `flows.jsonl`, `endpoints.jsonl`, `blocked.*`, `run.json` (ghi tạm rồi rename), `runs.jsonl`;
  - `requests.jsonl`: mỗi run một writer, mỗi dòng một lần `write` với `O_APPEND`; bộ đọc đã bỏ qua dòng dở.
- Mỗi run tự đếm script của nó qua `Store.Put` (trả SHA): `scripts`, `new_scripts`. Không còn dùng `Len` trước/sau hay `TakeTouched`.
- Run ID thêm hậu tố `-2`, `-3`… khi trùng mili-giây. `Record.tabs` nằm ngoài `config`, nên monitor vẫn so được với run `-tabs 1`.
- `-urls-rate` là trần cho nhịp **bắt đầu** trang. `-resolve-rate` và việc tải của từng trang tính theo tab, nên một host có thể nhận tới N lần nhịp đó.
- Ctrl-C: producer chọn giữa `next <- i` và `ctx.Done()`, worker bỏ qua khi ctx đã huỷ, nên không URL nào được mở sau khi ngắt.
- **Sửa lỗi có từ trước, phát hiện khi làm B:**
  - `crawl -urls -role R` bỏ qua phiên đã lưu và crawl như khách mà không báo gì. Giờ mỗi URL dùng phiên của host của nó (`Config.Logins`); browser dùng profile của login khi cả danh sách chỉ có một host. `-guard auto` bật guard khi có phiên (bản review bắt được: lần sửa đầu chạy có đăng nhập mà guard tắt).
  - Một URL trong batch bị mất phiên thì batch thoát mã 4 (`session_lost`).
  - Request bị guard giữ đúng lúc capture dừng từng bị ghi hai lần (`incomplete` cộng `held_back`). Giờ dòng `incomplete` được giữ lại tới khi đọc bản ghi của guard và ghi một lần với outcome `held_back`.
- Gate `testbed/parallel-check.sh`:
  1. guard-cases, 6 URL trên 2 host, `-tabs 1` so với `-tabs 3`: từng URL cùng số request, request bị giữ, thống kê guard và trang; cùng script; run ID không trùng; các run chạy chồng nhau; giữ nhịp; server không nhận request bị cấm nào. Đo được 72 s so với 31 s;
  2. session-app `-role user` với `-tabs 1` và `-tabs 3`: có phiên và guard, mọi trang `/members/*` trả 200, không đăng nhập lại, đủ marker storage;
  3. Ctrl-C thì thoát 130 và không mở thêm trang;
  4. các trường hợp báo lỗi.
- Đánh giá độc lập: 2 lỗi đáng kể (guard tắt khi dùng `-urls -role`; một URL vẫn được mở sau Ctrl-C) và 3 lỗi nhỏ (popup không ai nhận; bản ghi sót lấy trước khi guard yên; `passed_login` và mã thoát khi mất phiên). Đã sửa cả 5.

## 8. Giai đoạn C: thiết kế (frontier `-tabs N`), 2026-11-05

### 8.1 Phạm vi

- Lệnh: `crawl -u URL -depth D [-explore] [-role R] -tabs N`. Cả lần crawl là **một run**: một run ID, một writer `requests.jsonl`, một lần ghi `flows.jsonl`, một `pages.jsonl`.
- **Mọi tab dùng chung một browser context** (context gốc, tức profile). Lý do: crawl một site giống một người mở nhiều tab trên cùng một phiên:
  - chỉ một keeper;
  - server xoay vòng cookie phiên thì mọi tab cùng thấy, không có tab nào bị chết phiên riêng.

  Khác với B: ở B mỗi URL là một target riêng, nên mỗi URL một context.
- Không hỗ trợ: `-attach` và `watch` (vẫn báo lỗi như hiện nay).
- `-tabs 1` chạy đúng đường cũ: một engine, một tab.

### 8.2 Tách engine: trạng thái của run và trạng thái của tab

- **`runState`** (dùng chung, nhúng bằng con trỏ vào `engine`, nên các method hiện có giữ nguyên tên field):
  - cfg, `run Record`, store và `outDir`;
  - writer traffic, redactor, `held`, `incomplete`, `summary`, `events`;
  - keeper, guard;
  - trạng thái resolver (`seen`, `parsed`, `pending`, `resolved`);
  - `scripts`, `newScripts`, `mu`.
- **`engine`** (theo tab): `*runState`, `tab`, `harvest`, `world`, `mainID`, `lane` (số thứ tự tab), bộ đếm Clear-Site-Data/WebSocket, explorer, popups, xử lý hộp thoại.
- Mọi chỗ tab ghi vào `run` (Warnings, Idle…) đi qua hàm có khoá (`e.warn`). `Idle` lưu theo tab; run lấy giá trị xấu nhất.
- `finish` chia hai phần:
  1. **theo tab**, các tab chạy song song: `SweepCaches`, `freeze`, `Drain`, `Stop`, kiểm tra trang challenge;
  2. **một lần cho run**: lấy mọi bản ghi của guard (một run nên lấy hết, không cần claim), `recordHeld`, flows, endpoints, `run.json`. Stats của capture được cộng dồn; có tab nào bị chặn thì cả run bị chặn.

### 8.3 Hàng đợi chung, BFS theo tầng

- Bọc `frontier.Queue` bằng khoá và condvar. `Next()` chỉ trả trang ở tầng `d` khi **không tab nào đang làm trang ở tầng nhỏ hơn d** (BFS đồng bộ theo tầng).
  - Kết quả: tập trang được thăm và các URL bị liệt kê (kèm lý do) **giống hệt `-tabs 1`** khi không đặt `-max-pages`.
  - Nếu không đồng bộ, một URL có thể được tìm thấy trước từ trang sâu hơn, nhận độ sâu lớn hơn thật, rồi bị liệt kê `too-deep` sai.
  - Cái giá: các tab chờ nhau ở ranh giới giữa hai tầng.
- **Kết thúc** khi hàng đợi rỗng **và** không tab nào bận. **Dừng** bằng cờ `stop(reason)`: tab đang làm xong trang hiện tại rồi thoát. ctx chỉ bị huỷ khi Ctrl-C.
- `q.Visited(FinalURL)` gọi dưới khoá ngay khi tab biết FinalURL. Hai tab cùng bị chuyển tới một URL thì tab sau ghi `duplicate_of` vào `pages.jsonl` và không phân tích lại.
- `limiter` dùng chung, có khoá. `-page-rate` là trần tổng cho nhịp **bắt đầu** trang.
- 429/503: đếm trên toàn run, 3 trong 3 trang gần nhất thì dừng cả run (thay cho "3 lần liên tiếp" của một tab).
- `pages.jsonl`: một encoder có khoá; thêm trường `tab`.
- `knownFiles` (robots, sitemap): một lần, sau trang seed. `scriptURLs`: một bộ phân tích cho cả run (khoá, map `done` chung).

### 8.4 Phiên: một keeper, có epoch

- `install`: nạp cookie một lần (context chung). Script khôi phục storage cài cho **mỗi tab** (`AddScriptToEvaluateOnNewDocument` theo tab).
- Mỗi tab kiểm sau trang của mình. Bộ đếm Clear-Site-Data **theo tab**: Clear-Site-Data ở tab A không làm tab B cũng đi khôi phục.
- `recover` chạy dưới khoá của keeper, mỗi lần tăng `epoch`:
  - trong lúc khôi phục, các tab khác không lấy trang mới;
  - tab B cũng thấy mất phiên, nhưng epoch đã tăng sau khi nó bắt đầu trang, thì chỉ `verify`, không đăng nhập lại;
  - trang có lúc thăm chồng lên khoảng mất phiên (epoch lúc bắt đầu khác lúc xong) được `Retry` một lần, không tính vào `blamed`;
  - đăng nhập lại chạy trong tab phát hiện, `AllowWrites` theo frame của tab đó.
- Explore mất phiên (`x.lost`) đi qua đúng đường này.

### 8.5 Guard

- `SetPage` toàn cục được thay bằng `SetPageOf(frame, networkID)`: tra tab sở hữu bằng `Capture.Owns`, lấy trang hiện tại của tab đó.
- `navHeld` theo frame: `TakeNavigationsFor(frame)`, popup tính theo frame của opener.
- `StubSockets` cài theo từng tab.

### 8.6 Capture, worker, focus

- Mỗi tab một capture.
- **Service worker và shared worker: chỉ capture của tab 1 gắn vào** (option mới). Lý do: context chung nên các capture đều thấy cùng một worker, gắn hết thì request của worker bị ghi N lần.
  - Giới hạn: request do SW gửi thay cho trang ở tab 2 được ghi vào làn của tab 1 (thành background của tab 1).
- Dedicated worker và iframe: theo tab, vẫn tự gắn từ tab.
- **Focus emulation cho mỗi tab** (`Emulation.setFocusEmulationEnabled`). Spike `go test -tags chrome ./internal/browser/` cho thấy:
  - 3 tab cùng context đều `visible` và timer không bị bóp;
  - nhưng chỉ tab mở sau cùng có focus, trong khi explore cần focus để gõ phím;
  - có focus emulation thì cả 3 tab đều có focus.
- Hộp thoại xử lý theo tab. Tắt download một lần cho browser.

### 8.7 Flows theo làn (tab)

- `Lane` gắn trên `flow.Event`, `flow.Request`, và trên entry của `requests.jsonl` (`tab`, omitempty).
- `flow.Build` **gán request theo từng làn**: gesture, action `load`, `next`, `findTag` (khoá theo làn cộng document), `lastWithType`, `windowOwner`, `periodic` và background bucket đều chỉ xét trong một làn.
- Sau khi gộp: action ID đánh số toàn cục theo thời gian, nên không trùng và không cần tiền tố. Template và `depends_on` tính trên **toàn bộ** request: tab 2 dùng token tab 1 lấy là liên kết thật.
- `Flow.tab` (omitempty). Một làn (lane 0) thì kết quả giống hệt hiện nay; `flows-gate` chặn hồi quy.
- Unit test: Build trên hai làn xen kẽ theo thời gian phải bằng Build từng làn riêng (bỏ qua cách đánh số).

### 8.8 Explore

- Mỗi tab một explorer.
- Dùng chung (có khoá): tập chữ ký `seen` (một control đã dùng ở tab này thì tab khác không lặp lại), và `-explore-total` tính theo **thời gian thực từ đầu run** (người dùng đặt "30 phút" là 30 phút).
- `-explore-actions` và `-explore-time` vẫn tính theo trang. `ExploreStats` theo tab, cộng lại ở cuối.
- Popup đóng theo tab (lọc theo opener).

### 8.9 Resolver

`e.resolve` chạy theo tab sau mỗi trang, nhưng mỗi lúc chỉ một lần cho cả run (khoá), để `-resolve-rate` vẫn là trần tổng. Trạng thái nằm ở run; fetch chạy trong isolated world của tab gọi.

### 8.10 Output

`pages.jsonl` có `tab`, `requests.jsonl` có `tab`, flows có `tab`, `run.json` có `tabs`. `Tabs` không nằm trong `RunConfig`.

### 8.11 Thứ tự làm, mỗi bước một commit

- **C1:** làn trong `flow.Build` (hàm thuần) và unit test. Gate: `flows-gate`.
- **C2:** tách `runState`/`engine`, chưa đổi hành vi. Gate: toàn bộ `regress.sh` (phải giống hệt).
- **C3:** hàng đợi chung, worker, finish theo tab, guard `SetPageOf` và `navHeld` theo frame, owner duy nhất cho service worker, focus emulation.
- **C4:** keeper có epoch.
- **C5:** explore dùng chung `seen` và ngân sách.
- **C6:** gate `testbed/frontier-tabs-check.sh` (mục 8.12), tài liệu, hồi quy toàn bộ.

### 8.12 Gate

1. frontier-app, `-depth` đủ sâu, `-tabs 1` so với `-tabs 3`:
   - cùng tập trang được thăm, cùng tập (URL, lý do) bị liệt kê;
   - một run; không request nào trùng (`reqcheck` đối chiếu log server theo cả hai chiều);
   - action ID không trùng; mọi flow không phải background có toàn bộ request cùng một tab;
   - đo thời gian.
2. explore-app `-explore -tabs 3`: `explorescore` không thấp hơn ngưỡng của `explore-check`; server không nhận request bị cấm nào.
3. flows-app `crawl -explore -tabs 3`: `flowscore` như `explore-check`.
4. session-app `-role user -depth 2 -tabs 3` (có `/account/privacy` và `/account/expire`):
   - đủ marker; phiên được khôi phục;
   - số lần đăng nhập lại ≤ 2 (epoch chặn việc đăng nhập dồn dập); thoát 0.
5. Nhịp: `-page-rate 2 -tabs 3`, khoảng cách giữa các lần tải document trên log server ≥ 0,35 s.
6. Ctrl-C: thoát 130, không thêm trang nào sau khi ngắt.
7. Trước khi chốt: `EXTRA="-tabs 3" testbed/external/run.sh`, số liệu Crawlground và crawl-maze bằng `-tabs 1`.

### 8.13 Giới hạn đã biết

- Request của service worker gán về làn của tab 1.
- Có `-max-pages`: các trang được chọn ở tầng cuối có thể khác `-tabs 1`, vì thứ tự tìm thấy trong cùng tầng khác nhau.
- Explore N tab cùng lúc trên một server có trạng thái thì hiệu ứng của các thao tác đan xen nhau. Đó là bản chất của chạy song song; `flows` vẫn tách theo tab.
- Tải lên target tăng tới N lần. `-page-rate` chỉ giới hạn nhịp bắt đầu trang; click của explore và resolver tính theo tab (resolver có trần chung).

### 8.14 Review độc lập (Đợt 6): đồng ý C1→C6, 6 điểm phải chốt (có hiệu lực cao hơn 8.1–8.13)

- **REV-C-01 (C3), thứ tự `q.Add` theo tầng:**
  - Vấn đề: `seen` chỉ được gán khi URL vào hàng đợi. Nên nếu trang B (chỉ nêu tên `/x`) xong trước trang A (có link `/x`), `/x` bị liệt kê thừa với lý do `listed`.
  - Cách làm: các URL tìm được của các trang tầng `d` được giữ theo trang cha, rồi `Add` ở ranh giới tầng **theo thứ tự `seq` của trang cha**.
  - Vì BFS theo tầng vốn không cho lấy trang tầng `d+1` trước khi tầng `d` xong, việc này không làm chậm thêm. Thứ tự `Add` và `seq` của tầng `d+1` giống hệt `-tabs 1`, kể cả khi có `-max-pages`; giới hạn ở 8.13 về `-max-pages` không còn.
  - Ngoại lệ: trang `Retry` (vì mất phiên) quay lại hàng đợi ngay, ở cùng tầng.
- **REV-C-02 (C3), FinalURL trùng:** `Queue.ClaimFinal(requested, final) (dupOf string)` dựa trên map `visited` (gán khi `Next`). Chỉ xét khi `final` khác `requested`. Nếu trùng: `pages.jsonl` ghi `duplicate_of`, bỏ qua `domURLs`, explore và `scriptURLs`.
- **REV-C-03 (C4), keeper và nhiều tab:**
  - keeper giữ danh sách tab và `scripts map[target.ID]ScriptIdentifier`;
  - sau `install` và sau `relogin`, cài lại `RestoreScript` cho **mọi** tab;
  - `check`, `verify` và `recover` nhận `*engine` của tab gọi, để `AllowWrites(e.mainID)` và kịch bản login chạy đúng tab.
- **REV-C-04 (C3), Owns và SetPageOf:**
  - frame chính của tab đã được ghi vào `frames` ngay khi `Start` (`newSession`, từ giai đoạn B);
  - `SetPageOf`: nếu không tab nào nhận (request của SW, `frame` rỗng) thì dùng trang của tab 1, tab sở hữu SW.
- **REV-C-05 (C1), khoá làn trong `flow.Build`:**
  - `gestures` tách theo (làn, doc), action mang `lane`, kể cả action `load`;
  - `periodic`: khoá bắt đầu bằng làn, `nearAction` chỉ xét action cùng làn. Nếu không, 3 tab gọi `/api/config` theo nhịp `-page-rate` sẽ bị nhận nhầm là timer;
  - background bucket có khoá `làn|page` và mang `Flow.tab`.
- **REV-C-06 (C4/C5), explore trong lúc khôi phục phiên:** đầu mỗi thao tác của `explorer.page`, gọi `keeper.waitReady()` để chờ nếu tab khác đang `recover`.
- **NEW-C1-01 (Đánh giá độc lập Đợt 7), đã sửa:**
  - Lỗi: `gestures` sắp xếp các sự kiện khác tab theo giờ thực, và hàm so sánh không có tính bắc cầu. Sự kiện của tab khác ở cùng thời điểm chen vào giữa một cử chỉ và tách nó ra: test đếm được 8 thao tác thay vì 6 trên tab có cùng mốc thời gian.
  - Sửa: sắp xếp theo (làn, doc, ts), rồi `Build` sắp xếp lại các thao tác theo giờ thực. `TestLanes` giờ đếm cả thao tác không gửi request.
  - Cùng đợt: `testbed drive` chờ tối đa 20 s cho tới khi thấy tab, thay vì liệt kê đúng một lần. Lần `flows-check` đầu tiên của mỗi luồng từng hỏng với lỗi `0 tabs match` khi máy tải nặng.

### 8.15 C2: tách engine (theo checklist ở Đánh giá độc lập Đợt 7)

- `runState`: cfg, run, `recMu` (Warnings, StoreErrors), store/dir, scripts, `shared` (batch), `mu`, resolver (`seen`, `parsed`, `pending`, `resolved`, cộng `resolveMu` để mỗi lúc chỉ một vòng chạy), guard, `guardAt`, traffic, redactor, `held`, `incomplete`, keeper, `analyzing`, events, `heard`, summary.
- `engine` (tab): `*runState` nhúng vào, `tab`, `lane`, `harvest`, `world`, `mainID`, `csdSeen`, `sockSeen`, `passedAt`, `idle`, `blocked`.
- `newRun(cfg, tab, g)` tạo run cộng tab 0. `runState.newTab(tab, lane)` thêm tab (C3).
- **Đánh số làn:** chạy một tab là 0 (bị ẩn khỏi JSON, output y như cũ); `-tabs N` trên frontier đánh 1..N (C3), để dòng nào cũng có `tab`.
- Làn được gắn ở `record` (trước nhánh `incomplete`), `onEvent` và `summarize`. `traffic.Entry.tab` (omitempty).
- `warn` và `storeError` có khoá `recMu`, riêng với `mu` để không tự khoá chết ở những chỗ đang giữ `mu`.
- `finish` = `finishTab` (CacheStorage, freeze, Drain, kiểm tra challenge, Stop) cộng `finishRun(tabs)`:
  - bị chặn nếu tab nào bị chặn; initiator tra trên mọi tab; `Stats` cộng dồn (`addStats`); `Idle` lấy của tab đầu.
- Với một tab, hành vi y như cũ, kể cả `idle` là lần `settle` cuối. Việc không để resolver ghi đè `idle` để sang C3, khi `idle` thành của từng tab.
- **Gesture bị tách khi trang bận (lỗi có từ trước, lộ ra trong `regress.sh`):**
  - Lỗi: `ts` của click tin cậy là lúc trình duyệt nhận input, còn submit mà click gây ra lấy `ts` lúc được tạo. Khi trang bận, khoảng cách giữa hai mốc vượt 5 ms, nên cú bấm "Save profile" thành hai thao tác: click rỗng và submit.
  - Sửa: sự kiện báo cáo trong vòng `nestGap` (2 ms giờ thực) sau sự kiện trước của cùng document thì thuộc cùng cử chỉ. Có `TestNestedLateTimeStamp`.
  - `replay-check` F chọn flow "Save profile" có request ghi.

### 8.16 Đánh giá độc lập Đợt 8: checklist cho C3

- **NEW-C3-02 (đã sửa trước C3, là lỗi có từ trước của frontier):**
  - Lỗi: `resolve()` chạy sau mỗi trang nhưng khởi tạo lại `fetched` (nên `-resolve-max` thành giới hạn theo trang) và xoá `ByMethod`. Thêm một chỗ review chưa nêu: khi đã dừng vì 429 hay challenge, trang sau vẫn chạy resolver tiếp.
  - Sửa: số đếm, trần và trạng thái dừng tính cho cả run; đã dừng thì bỏ phần body đang chờ.
  - Gate: `frontier-check` thêm webpack-vanilla `-depth 1 -resolve-max 3` (tổng `by_method` phải bằng `fetched + failed`; bản cũ ra `{}`).
- **NEW-C3-01 (C3):** entry tạo từ bản ghi của guard (`Source: "guard"`) phải mang `tab` của tab sở hữu (tra bằng `Owns` theo request id, frame, opener; không ai nhận thì tab 1).
- **NEW-C3-03 (C3):** `SetInterceptFileChooserDialog` đã gọi theo tab (ctx của tab của mỗi explorer). Thêm focus emulation cho mỗi tab. `SetDownloadBehavior` ở cấp browser, gọi lặp lại không sao.
- **NEW-C3-04 (C3):** tầng 0 chỉ có trang seed; các tab 2..N chờ ở ranh giới tầng. URL tìm được (gồm `knownFiles`) vào tầng 1 theo đúng thứ tự như `-tabs 1`.
- **NEW-C3-05 (C3):** `capture.Options.NoSharedWorkers` (đặt cho tab 2..N): chỉ tab 1 gắn vào service worker và shared worker.
- Ghi chú: phần tóm tắt C2 trong review nêu vài tên không có trong code (`mapMu`, `SourceMaps`, `console`, `netLog`, `record.json`). Các điểm cho C3 thì đã đối chiếu với code thật.

### 8.17 C3: frontier `-tabs N`

- `crawl -u URL -depth D -tabs N`: N tab trong **context gốc** (một phiên). Tab 1 dùng tab có sẵn, tab 2..N mở bằng `chromedp.NewContext(tab)`. Làn đánh 1..N; `-tabs 1` giữ làn 0. Với nhiều tab, `-explore` và phiên đã lưu bị từ chối cho tới C4 và C5.
- **Hàng đợi** (`crawl` trong `engine/frontier.go`):
  - BFS đồng bộ theo tầng: `next()` chỉ trả trang có `Depth ≤ level`. Khi tầng xong (không trang nào đang bận) thì `commit()` rồi chuyển tầng.
  - Kết quả của mỗi trang (`marks` gồm FinalURL và document tự chuyển tới, `found`, các script của nó) được giữ tới `commit`, rồi áp **theo thứ tự lấy trang**: `Visited` trước, rồi `Add`, rồi ghi dòng `pages.jsonl`. Hàng đợi vì thế thấy đúng chuỗi thao tác như `-tabs 1`.
  - Kiểm bằng gate: cùng tập (URL, depth, from) được thăm và cùng tập (URL, reason, from) bị liệt kê.
- **Script của trang nào thì của trang đó:**
  - Lỗi đã gặp: `scriptURLs` đọc "các script mới của store" nên bị gán nhầm trang. Script inline của `timer.html` (tab 1) bị `jshref.html` (tab 2) đọc, và `timer-target` bị thăm thêm một lần.
  - Giờ mỗi tab ghi SHA mà capture của nó lưu (`pageScripts`, chỉ ở frontier). Việc đọc URL từ script làm lúc `commit`, theo thứ tự lấy trang; trang đầu tiên tới bước này đọc mọi script trong store (như bản tuần tự).
- `duplicate` (REV-C-02, chỉ khi nhiều tab): trang bị chuyển tới một URL mà trang khác đã tải thì ghi `duplicate_of`, không đọc lại.
- 429/503: 3 trang liên tiếp **trên toàn run**. Limiter dùng chung, đặt chỗ dưới khoá (`-page-rate` là trần nhịp bắt đầu trang). `pages.jsonl` có `tab` và `started`.
- Tab: `capture.Options.NoSharedWorkers` cho tab 2..N (NEW-C3-05); focus emulation khi `lane > 0` (NEW-C3-03); `StubSockets` và hộp thoại theo tab; `Guard.SetPageOf` tra tab sở hữu bằng `Owns`, mặc định tab 1 (REV-C-04); entry tạo từ bản ghi guard mang `tab` (`heldTab`, NEW-C3-01).
- `idle`: resolver dùng `quiet()` nên không ghi đè `idle` của lần tải trang.
- `finishTab` chạy song song cho mọi tab, rồi `finishRun(tabs)`. Bản ghi guard lấy hết (một run).
- Gate `testbed/frontier-tabs-check.sh`:
  1. frontier-app `-tabs 1` so với `-tabs 3`: trang thăm và trang liệt kê giống hệt; một run; `reqcheck` đạt; `frontscore` đạt; flow (trừ background) chỉ một tab; action ID không trùng; dùng đủ 3 tab. Đo được 50 s so với 28–32 s.
  2. Nhịp `-page-rate 2`: khoảng cách nhỏ nhất giữa các `started` ≥ 0,3 s (đo được 0,40 s).
  3. Ctrl-C: thoát 130, `stopped: interrupted`.
  4. `-explore` với nhiều tab bị từ chối.

### 8.18 C4: phiên đăng nhập với nhiều tab (Đánh giá độc lập Đợt 9, NEW-C4-01..05)

- **Keeper cho mọi tab** (`newKeeper(tabs, login)`):
  - `epoch` đếm số lần khôi phục đã bắt đầu;
  - `recovering` cộng `wait()`: các tab không bắt đầu trang mới, và explore không làm thao tác mới, trong lúc một tab đang khôi phục (REV-C-06);
  - script khôi phục storage được cài và cài lại cho **mọi** tab, ghi theo `mainID` (REV-C-03);
  - `check`, `verify`, `recover` và `relogin` nhận `*engine` của tab gọi; `AllowWrites(e.mainID)`.
- `recover(ctx, e, ep, cause, page)` chạy dưới `k.mu`:
  - phiên đã mất hẳn thì trả về ngay (NEW-C4-05.3);
  - `epoch` khác `ep`, tức tab khác đã khôi phục sau khi trang bắt đầu: chỉ `alive(e)` (cookie dấu hiệu, `check_url`; không có `check_url` thì tải lại `FinalURL`), không đăng nhập lại (NEW-C4-01);
  - khôi phục thất bại thì keeper tự đặt `Lost`.
- Bộ đếm Clear-Site-Data của keeper theo tab (`e.keeperCSD`), tách khỏi `csdSeen` của guard (NEW-C4-04).
- **Frontier:**
  - ghi `ep` trước khi tải trang. Nếu `check` không thấy gì nhưng `epoch` đã đổi, trang là **nạn nhân** của tab khác (NEW-C4-03) và được thăm lại một lần;
  - trang mất phiên lần đầu, cả nạn nhân lẫn thủ phạm, được thăm lại **một mình** (`solo`: chờ không tab nào bận, trong lúc nó chạy các tab khác chờ) (NEW-C4-02). Thăm một mình mà vẫn mất phiên thì kết luận "this page ends the session". Với `-tabs 1`, `solo` luôn thoả, nên hành vi như cũ.
- Đo được trên session-app `-depth 2`: `-tabs 3` có cùng 4 sự kiện phiên, `relogins: 2`, 2 lần POST đăng nhập, đủ marker, cùng tập trang như `-tabs 1`. `/members/a` và `/members/b` là nạn nhân được thăm lại một mình; `/members/e` thấy mất phiên nhưng chỉ kiểm `alive`.
- Gate `frontier-tabs-check` phần 5 và 6 (không có kịch bản login: đúng một lần khôi phục thất bại, thoát 4).

### 8.19 C5: explore với nhiều tab (Đánh giá độc lập Đợt 10, NEW-C5-01..05)

- **Guard:** `navHeld` theo frame giữ điều hướng; `holder(frame)` là chính frame đó, hoặc với popup thì frame mở ra nó theo chuỗi opener. `TakeNavigations(frame)` chỉ lấy của tab đó (NEW-C5-01).
- **Explore:**
  - mỗi tab một `explorer`, với thống kê riêng (`p.Explored` không lẫn tab khác); khi xong thì gộp bằng `addExploreStats` (NEW-C5-03);
  - dùng chung `exploreShared`: tập chữ ký đã dùng, mốc bắt đầu cho `-explore-total` (giờ thực của cả run), thư mục file upload;
  - mỗi tab có trình xử lý hộp thoại và file chooser riêng.
- Chữ ký được **giữ chỗ trước** khi thao tác (`claim`), và trả lại khi thao tác `covered` hoặc trang treo (NEW-C5-04). Với một tab, trạng thái cuối giống hệt cũ.
- `ep` được ghi ngay sau `k.wait()` ở đầu mỗi thao tác. Nếu `check` không thấy gì mà `epoch` đổi, tức tab khác mất phiên trong lúc thao tác này chạy: phiên mất hẳn thì `x.lost`, còn không thì tải lại trang và chụp lại (NEW-C5-02).
  - Không theo đề xuất đổi `verify` thành `alive` ở nhánh `toLogin`. Không có `check_url` thì `alive` tải lại `FinalURL`, tức đưa tab khỏi trang đang khám phá; `verify` chỉ đọc cookie, document và `check_url`.
- `BringToFront` chỉ gọi khi `lane == 0` (NEW-C5-05).
- `-explore -tabs N` không còn bị từ chối. `-tabs` dùng được với `-urls`, `-depth` hoặc `-explore`.
- Gate `frontier-tabs-check` phần 7–9:
  - explore-app 84 thao tác, precision 1.000;
  - flows-app 20/20, precision 1.000;
  - session-app `-role -explore -tabs 3`: phiên sống, `session_ends ≥ 1`, `relogins ≤ 2`, đủ marker, chỉ đăng nhập mới ghi.
  - Phần 9 phải đăng nhập lại trước khi chạy: server khởi động lại thì phiên trong bộ nhớ của nó mất (lần chạy đầu ra 3 lần đăng nhập lại vì thế).

### 8.20 C6: kiểm chứng ngoài testbed, chốt giai đoạn C (2026-11-06)

`EXTRA=… testbed/external/run.sh`, chạy trên code hiện tại, 4 cấu hình nối tiếp nhau (image có sẵn trong máy, không cần mạng):

| Cấu hình | Crawlground (≥ 50, có explore ≥ 55) | crawl-maze (≥ 51) | crawl-maze, cho phép trang `.html` (js ≥ 19, 0 request ghi) | Cả gate |
|---|---|---|---|---|
| mặc định | 56/59 trong 208 s | 76/84 | 79/84, js 20/20, 0 | 700 s |
| `-tabs 3` | 56/59 trong **94 s** | 76/84 | 79/84, js 20/20, 0 | **345 s** |
| `-explore` | 56/59 trong 507 s | 76/84 | 79/84, js 20/20, 0 | 1603 s |
| `-explore -tabs 3` | 56/59 trong **200 s** | 76/84 | 79/84, js 20/20, 0 | **634 s** |

- Điểm của `-tabs 3` giống hệt `-tabs 1` ở mọi thước đo; thời gian giảm khoảng 2,2–2,5 lần. 56/59 là trần khi guard bật (3 test POST bị giữ có chủ đích). Cả 4 cấu hình trượt cùng 3 mục javascript khi không cho phép trang `.html`; đó là các trang có tên phá huỷ, được liệt kê chứ không bị mở.
- `testbed/regress.sh` (14 gate cộng unit test, 3 luồng): 741 s.
- **Giai đoạn C xong.** `-tabs N` dùng được với `-urls` (B), `-depth` (C3), `-role` (C4) và `-explore` (C5); mặc định `-tabs 1` như cũ. Song song theo cờ A–B–C đã xong.
