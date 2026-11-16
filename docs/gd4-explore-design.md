# GĐ4 4.6 — Explore tương tác tất định

**Mục tiêu** (plan bản 2, mục 4.6; plan bản 1, mục 4.4). Trên mỗi trang mà `crawl` thăm, jsharvest tự thao tác như một người dùng: click, gõ, điền form, chọn, hover, cuộn. Explore không dùng LLM. Mỗi thao tác là một hành động trong `flows.jsonl`, và các request mà thao tác gây ra được gom dưới nó theo chuỗi nhân quả. Những phần cần "hiểu" giao diện (wizard dài, CAPTCHA, dữ liệu nghiệp vụ) vẫn là việc của AI qua MCP cộng với `watch`.

**Phạm vi:** chỉ trong `crawl`. Explore luôn chạy cùng guard. `watch` không có explore, vì tab đó là của người dùng hoặc của AI.

## 1. Cổng nghiệm thu

| # | Kiểm tra | Ngưỡng |
|---|---|---|
| G1 | `flows-app`, `crawl -explore`, guard bật, không có kịch bản | Mỗi tính năng có `expect` trong `flows.truth.json` (17 tính năng) xuất hiện thành **một hành động explore** chứa đủ các request mong đợi (so theo method và path template, vì giá trị gõ vào khác với truth). Precision ≥ 95%: các request gán vào hành động explore phải thuộc đúng tính năng, không lẫn nhiễu nền hay request lúc tải trang |
| G2 | `webpack-vanilla`, `-resolve=false -explore -depth 1` | Có `click:report`, `scroll:comments`, `form:welcome`, tức là đạt bằng tương tác thật, không nhờ resolver |
| G3 | `edge-cases`, `-explore` | Có `inline:handler` |
| G4 | Fixture mới `explore-app` (mục 9) | Đạt mọi ca trong `explore.truth.json`; **0** request nằm trong `forbidden` |
| G5 | Crawlground, `-explore -depth 3` | ≥ 55/59 (hiện đạt 56/59 khi chưa có explore). crawl-maze không thấp hơn 76/84 |
| G6 | An toàn, đo bằng log server testbed | 0 request ghi tới server; 0 lần điều hướng do explore tới server; nút logout không bao giờ được bấm; `session-app` với `-role user -explore` không mất session vĩnh viễn |
| G7 | Không hồi quy | bench (explore tắt mặc định), `flows-gate.sh`, `attach-guard.sh` (vì có sửa guard), `frontier-check.sh`, `session-check.sh`, `endpoints-check.sh` |

## 2. Sự thật về Chrome đã đo (spike trên Chrome 156, trang 5 000 dòng + shadow DOM closed + iframe)

| Câu hỏi | Kết quả | Hệ quả |
|---|---|---|
| `DOMDebugger.getEventListeners(document, depth=-1, pierce=true)` | 3–12 ms, trả về mọi listener của cây kèm `backendNodeId`, **kể cả trong shadow root closed**. Không đi vào iframe | Gọi riêng cho từng document |
| `DOMSnapshot.captureSnapshot` (cursor, visibility, display, pointer-events, paint order, rect) | 110–200 ms cho 10 000 node, **trong một lệnh**: mọi document (gồm iframe cùng tiến trình), shadow DOM closed, layout, style. `isClickable` của Chrome đánh dấu phần tử có listener click, link và control của form | Dùng làm ảnh chụp trạng thái |
| `Accessibility.getFullAXTree` | 520–650 ms cho cùng trang, tức chậm hơn snapshot khoảng 3 lần và chậm hơn listener khoảng 80 lần. Với `div` chỉ có listener (React), role chỉ là `generic` | **Không dùng cây đầy đủ** (lệch khỏi plan, xem mục 10) |
| Trả `204` cho request điều hướng của main frame (`Fetch.fulfillRequest`) | Trang **đứng yên, state JS còn nguyên**, server không nhận gì. Đúng với `location.href = …`, link và form GET | Có khoá điều hướng (mục 6), không cần tải lại trang sau mỗi click |
| `confirm()` khi click bằng `Input.dispatchMouseEvent` | `dispatchMouseEvent` không trả về cho đến khi hộp thoại được xử lý. Xử lý `Page.javascriptDialogOpening` ở goroutine khác thì chạy được, `confirm` trả `true` | Bộ xử lý hộp thoại phải chạy riêng |
| `chromedp.Click(selector)` sau khi tự gọi `DOM.getDocument` | **Treo**: query của chromedp mất node id mà nó đang theo dõi | Explore chỉ dùng CDP thô theo `backendNodeId` và toạ độ |

## 3. Vị trí trong pipeline

Explore chạy trên mỗi trang mà frontier thăm, kể cả khi `-depth 0` (chỉ trang hạt giống):

```
visit → (keeper.check) → domURLs, header, robots → resolver → EXPLORE → scriptURLs → popup → hàng đợi
```

- URL do explore tìm ra đi vào hàng đợi với `how: explore` ở độ sâu `depth+1`. Các nguồn: điều hướng bị khoá, URL đổi do `pushState`/`hash`, link mới xuất hiện trong DOM sau thao tác, và popup.
- Script mà thao tác làm tải về được `scriptURLs` phân tích ngay sau đó.
- `-explore` bật `Actions` (tagger và reporter) cho crawl và **buộc bật guard**. `-explore -guard off` là lỗi. Ai được phép ghi thì dùng `-allow-write`: guard vẫn bật và vẫn chặn các request phá huỷ.

## 4. Trạng thái và ứng viên

**Ảnh chụp trạng thái** (`engine/explore.go`) gồm:
- `captureSnapshot`;
- `getEventListeners` cho mỗi document có trong snapshot, bỏ qua document khác origin (OOPIF không nằm trong snapshot);
- `location.href` của trang.

Phần dữ liệu này được chuyển thành model riêng, rồi đưa vào package hàm thuần **`internal/explore`**, có unit test bằng cây dựng sẵn.

**Ứng viên** là phần tử **hiển thị**: có hộp layout, rộng và cao ≥ 1 px, `visibility` khác `hidden`, `pointer-events` khác `none`, không `disabled` và không nằm trong `fieldset[disabled]`. Phần tử phải thoả ít nhất một nguồn sau:

1. `isClickable` của Chrome.
2. Có listener riêng thuộc các loại: `click`, `mousedown`, `mouseup`, `pointerdown`, `pointerup`, `dblclick`, `contextmenu`, `mouseover`, `mouseenter`, `pointerover`, `pointerenter`, `keydown`, `keyup`, `keypress`, `change`, `input`, `submit`.
3. Có handler `on*` dạng thuộc tính HTML.
4. Có ngữ nghĩa tương tác:
   - các thẻ `button`, `input` (trừ `hidden`), `select`, `textarea`, `summary`;
   - thẻ `a` không có href thật (`#`, `javascript:`);
   - `[role=button|link|tab|menuitem|menuitemcheckbox|menuitemradio|option|switch|checkbox|radio|treeitem|combobox]`;
   - `[contenteditable]`, `[tabindex>=0]`.
5. **Ủy quyền sự kiện (React, Vue, …):** phần tử nằm dưới một ancestor có listener click mà ancestor đó là `html`, `body`, document, hoặc chứa ≥ 3 ứng viên. Khi đó lấy các phần tử có `cursor: pointer` mà cha của chúng không có `cursor: pointer` (vì `cursor` được kế thừa).

**Loại khỏi danh sách:**
- **Container uỷ quyền** (có listener nhưng chứa ứng viên khác): chỉ click vào con của nó.
- **Link có href thật:** frontier đã lấy URL từ DOM, và khoá điều hướng làm click vào link trở nên thừa.
- **Phần tử có tên kết thúc phiên:** nhãn, `id`, `name`, `class`, `href` hoặc `formaction` khớp `logout|log out|log off|sign out|signout|end session|switch account` (regex riêng của explore, hẹp hơn luật phá huỷ của guard; xem mục 12). Lý do: nhiều SPA logout bằng cách **xoá storage phía client** mà không gửi request nào, nên guard không chặn được.
  - "Delete" **vẫn được bấm**, vì request ghi bị guard giữ lại và được ghi lại. Đó chính là thứ cần cho fuzz.

**Chữ ký** để mỗi nhóm lặp lại chỉ thao tác một đại diện: `tag | role | type | id* | class đầu* | nhãn* | ngữ cảnh | loại thao tác`.
- Dấu `*` nghĩa là chữ số được thay bằng `#`.
- **Ngữ cảnh** là `id` của ancestor gần nhất có `id`, hoặc `action` của form chứa nó.
- **Plan đề xuất `(tag, class, tag cha)`; mình thêm nhãn và ngữ cảnh.** Nếu không, một thanh công cụ "Save / Delete / Export" dùng chung `class="btn"` sẽ bị gộp thành một nút. Còn các hàng "Open" trong một danh sách thì vẫn gộp đúng.
- Chữ ký được nhớ **cho cả run**: menu đầu trang chỉ được thử một lần, không thử lại ở mỗi trang.

**Thứ tự:**
1. Điền mọi trường đang trống.
2. Ứng viên **mới xuất hiện sau thao tác trước** (modal mở ra, bước wizard vừa được bật, menu), đi theo kiểu DFS để chuỗi thao tác nhiều bước chạy trong cùng một trạng thái.
3. Phần còn lại, theo thứ tự trong tài liệu.

## 5. Thao tác: input thật, không dùng `el.click()`

Input được gửi qua `Input.dispatch*`, nên event là `isTrusted`. Nhờ vậy tagger và reporter sẵn có ghi lại hành động như với một người thật, và chuỗi nhân quả của 4.3 dùng được nguyên vẹn.

| Loại | Cách làm |
|---|---|
| click | `DOM.scrollIntoViewIfNeeded`, rồi `DOM.getContentQuads` lấy tâm, rồi **kiểm tra trúng đích** bằng `DOM.getNodeForLocation`: phần tử trúng phải là chính nó hoặc con của nó, theo cây cha của snapshot. Sau đó gửi mouseMoved, mousePressed, mouseReleased |
| bị che (cookie banner, overlay) | Đẩy xuống cuối hàng một lần. Nếu vẫn bị che thì dùng `el.click()` trong isolated world, đánh dấu `untrusted` và đếm |
| dblclick, contextmenu | `clickCount: 2`; nút phải |
| hover (chỉ có listener mouseover/enter) | mouseMoved tới tâm. Go tự tạo một hành động `hover` (mục 7) |
| gõ (input, textarea, contenteditable đang trống) | `DOM.focus`, rồi `Input.insertText` (event `input` là trusted). Sau đó kiểm `validity.valid` trong isolated world; nếu chưa hợp lệ thì thử giá trị khác: theo `minlength`/`maxlength`, `min`/`max`/`step`, và vài mẫu cho `pattern` |
| phím Enter (phần tử có listener keydown, keyup hoặc keypress) | `DOM.focus`, rồi `dispatchKeyEvent` Enter |
| select | focus, rồi phím ArrowDown (event `change` trusted). Không được thì đặt giá trị trong isolated world rồi phát event `change` |
| checkbox, radio | click |
| form | điền mọi trường, rồi click nút submit. Không có nút thì Enter trong một trường text. Không được nữa thì `requestSubmit()` (untrusted) |
| file | `DOM.setFileInputFiles` với file vô hại do jsharvest tạo: `.txt`, hoặc PNG 1×1 nếu `accept` là ảnh |
| scroll | Khi bắt đầu trang và sau mỗi lần có trạng thái mới: cuộn xuống cuối cho tới khi `scrollHeight` không đổi 2 lần, tối đa 10 lần, rồi cuộn về đầu. Go tạo hành động `scroll` |

**Hộp thoại:** `alert` → OK; `confirm` → **chấp nhận**, để đi tới request (và guard giữ nó lại); `prompt` → `"test"`; `beforeunload` → **rời trang** (điều hướng của trang đã bị khoá bằng 204; "ở lại" sẽ chặn cả lần tải lại của chính jsharvest, xem mục 12 M4). Bộ xử lý chạy cho cả crawl. Quá 20 hộp thoại trong một thao tác thì dừng trang.

**Tải file:** `Browser.setDownloadBehavior deny` cho Chrome do jsharvest khởi chạy. Ở chế độ attach thì không đặt, vì thiết lập này áp dụng cho cả browser của người dùng.

## 6. Sau mỗi thao tác

1. Chờ ít nhất `-explore-wait` (800 ms), rồi chờ `WaitIdle` (quiet 500 ms, tối đa 5 giây). Request đến muộn hơn vẫn được gán đúng nhờ chuỗi nhân quả, vì trang chưa bị đổi.
2. **Khoá điều hướng** bằng `Guard.HoldNavigations(mainFrame)`. Trong lúc explore thao tác, mọi request **Document của main frame** đều được trả `204` kèm `X-Jsharvest-Guard: explore-navigation`.
   - Lệnh GET được đưa vào frontier. POST vẫn bị coi là ghi như hiện nay (ghi vào `blocked.jsonl`).
   - Khoá được nhả khi explore chủ động tải lại trang.
3. URL đổi mà document không đổi (`pushState`, hash): đưa URL vào frontier.
4. **Khôi phục trạng thái:** nếu URL đã đổi, hoặc hơn một nửa số ứng viên đang chờ đã biến mất (view khác), thì tải lại trang. Tối đa 10 lần mỗi trang.
5. **Session** (khi có `-role`): sau mỗi thao tác kiểm Clear-Site-Data và cookie dấu hiệu.
   - Mất session thì `keeper.recover`, rồi đánh dấu chữ ký vừa bấm là "kết thúc phiên" để không bấm lại, rồi tải lại trang.
   - Không khôi phục được thì dừng crawl với mã thoát 4 như 4.5.
6. Chụp lại trạng thái. Ứng viên có chữ ký mới được đưa lên đầu hàng.

**Ngân sách:**
- `-explore-actions 50` mỗi trang;
- `-explore-time 2m` mỗi trang;
- mỗi chữ ký một lần cho cả run.

Thao tác sinh ra nút mới vô hạn ("More 1", "More 2", …) bị chặn bởi chữ ký (chữ số thành `#`) và ngân sách.

## 7. Hành động trong `flows.jsonl`

- **Click, gõ, Enter, chọn, submit:** hành động được tagger và reporter ghi lại, gán theo chuỗi nhân quả, đúng như 4.3. Không có gì mới.
- **Hover và scroll:** không có event nào được tagger bọc (và không nên bọc, vì trong `watch`, mỗi lần người dùng rê chuột sẽ thành một hành động). Explore lấy `performance.timeOrigin` và `performance.now()` của trang ngay trước thao tác, rồi thêm một `flow.Event` cùng định dạng tag (`<origin>:<ts>:hover`). Request không mang tag (IntersectionObserver, handler hover) rơi vào cửa sổ của hành động đó. Explore chờ yên tĩnh giữa các thao tác, nên cửa sổ thời gian ở đây đáng tin hơn so với `watch`. `kindOf` thêm `hover` và `scroll`.
- **Thao tác không gửi request nào:** không ghi vào `flows.jsonl` của crawl (`flow.Options.DropEmpty`), chỉ đếm trong `run.json`. `watch` giữ nguyên hành vi cũ.
- **Sửa lỗi có từ 4.4:** `MainDocument` loại request có outcome `held_back:*`. Nếu không, một lần điều hướng bị chặn sẽ tạo ra một hành động `load` giả.

## 8. Output

- `run.json.explore`:
  - `pages`, `actions` theo loại, `skipped` theo lý do (`session-end`, `seen`, `budget`, `covered`);
  - `untrusted`, `restores`, `held_navigations`, `new_urls`, `dialogs`, `took_ms`.
- `pages.jsonl`: thêm `explored` (số thao tác trên trang đó).
- `flows.jsonl`: thao tác của explore mang `trusted: true` và `element` như hành động của người.

## 9. Fixture `explore-app` (ca khó, ground truth trong `explore.truth.json`)

Mỗi ca gọi một request `/api/x/<ca>`. Truth ghi request mong đợi cho từng ca, và danh sách `forbidden` (những request không bao giờ được tới server).

1. **Uỷ quyền kiểu React:** listener click ở `#root`, các `div` có `cursor:pointer`, không có listener riêng.
2. **Menu hover:** hover vào `#menu` làm hiện nút "Reports", click nút đó gọi API.
3. **`confirm()`** trước khi `DELETE`.
4. **Nút điều hướng** (`location.href = '/x/nav-target'`): server không được nhận `/x/nav-target` từ explore; URL đó vào frontier và được frontier thăm.
5. **`pushState`** sang route `/x/route`, rồi khôi phục bằng cách tải lại trang.
6. **Logout phía client** (xoá localStorage và cookie, không gửi request): không bao giờ được bấm.
7. **Cuộn vô hạn:** 3 trang `/api/x/feed?page=N`.
8. **Nút "Load more" tự sinh vô hạn:** bị chặn bởi chữ ký hoặc ngân sách; run phải kết thúc.
9. **Tab** (`role=tab`) mở panel có nút riêng.
10. **`details`/`summary`** chứa nút.
11. **Custom element có shadow DOM closed** chứa nút.
12. **Overlay cookie banner** che nút; nút vẫn phải được bấm (sau khi banner được bấm "Accept", hoặc bằng fallback).
13. **100 hàng giống nhau:** chỉ một hàng được bấm (đếm request).
14. **Nút bị `disabled`** cho tới khi ô nhập có giá trị.
15. **Form có ràng buộc** (`required`, `type=email`, `minlength=8`, `pattern=[A-Z]{3}\d{2}`, `number min=5 max=10`, `select` bắt buộc): phải submit hợp lệ.
16. **Ô tìm kiếm có listener keydown Enter** (không nằm trong form).
17. **dblclick** và **contextmenu**.
18. **Upload file** qua `input[type=file]` có listener change.
19. **`window.close()`:** tab crawl không được chết.
20. **`<a download>`:** không có file nào được ghi.
21. **Iframe cùng origin** có nút.
22. **Toolbar** 3 nút cùng class, khác nhãn: cả 3 phải được bấm.

## 10. Lệch so với plan và lý do

- **Không dùng `Accessibility.getFullAXTree`.** Đo được 520–650 ms mỗi lần đọc trên trang 5 000 dòng; explore đọc lại trạng thái sau mỗi thao tác (tối đa 50 lần mỗi trang). Với giao diện viết bằng `div` (React), AX chỉ cho role `generic`, nên không tìm thêm được ứng viên nào. Role và tên lấy từ thuộc tính và văn bản, như reporter đang làm. Nếu sau này cần tên chuẩn, gọi `getPartialAXTree` cho từng ứng viên.
- **Chữ ký có thêm nhãn và ngữ cảnh** (mục 4).
- **Điều hướng được khoá bằng 204, thay vì "quay về" sau mỗi lần điều hướng** (plan bản 1). Cách này nhanh hơn và giữ được state cho wizard.

## 11. Giới hạn đã biết

- Không explore bên trong iframe khác site (OOPIF): phần tử của nó không nằm trong snapshot của tab.
- Không làm: kéo thả, nhấn giữ lâu, cử chỉ chạm, canvas, CAPTCHA, và bước cần dữ liệu đúng nghiệp vụ (mã OTP, số thẻ). Những việc này để cho AI qua MCP.
- Menu chỉ hiện khi đang hover rồi biến mất khi chuột rời đi: chỉ đạt được nếu nút con nằm trong vùng của menu.
- Request GET làm thay đổi dữ liệu (thiết kế sai nhưng vẫn có) đi qua guard, như ở frontier. Người dùng thêm `-guard-deny` nếu biết trước.

## 12. Đánh giá độc lập và quyết định (2026-11-03)

Một agent đọc độc lập thiết kế cùng code (guard, flow, engine, fixture), không được biết trước kết luận của tác giả. Agent tìm ra 6 lỗi phải sửa trước khi code, 13 điểm nên sửa và 22 ca thiếu trong fixture. Mỗi phát hiện đã được kiểm tra lại bằng code hoặc spike trước khi nhận.

| # | Phát hiện | Kiểm tra | Quyết định |
|---|---|---|---|
| M1 | Khoá điều hướng chỉ giữ main frame: popup (`window.open`, `target=_blank`) vẫn tới server | Spike: target popup được tạo **trước** khi request của nó bị dừng, có `openerId` là tab của mình. Không có `Sec-Fetch-Dest` ở bước Request | **Nhận.** Guard luôn theo dõi các tab (cả ở chế độ launch). Khi khoá đang bật, giữ thêm điều hướng của popup có chuỗi opener về frame bị khoá. iframe vẫn được tải như tài nguyên, vì là GET và vẫn đi qua luật của guard |
| — | **Lỗi mới (không có trong review):** khi popup còn mở, input gửi vào tab bị treo; đóng popup thì input được xử lý | Spike `explore2` | Sau mỗi thao tác, đóng mọi tab có opener là tab của mình |
| M1b | Trang do service worker phục vụ từ cache: điều hướng không đi qua mạng nên khoá không thấy | Đúng về nguyên lý | **Sửa khác:** không bỏ qua SW (vì sẽ đổi hành vi app). Khi URL đổi thì phát hiện, rồi tải lại trang. Không có request nào tới server nên không ảnh hưởng an toàn |
| M2 | Khoá chặn cả lần tải lại của keeper và login lại | Đúng (`e.reload`, `session.Run` đi qua main frame) | **Nhận.** Nhả khoá quanh `recover`; thêm gate mất session trong lúc explore |
| M3 | `-explore -allow-write` gửi DELETE thật sau khi chấp nhận `confirm()` | Đúng (`rules.go`, nhánh AllowWrite) | **Nhận.** Khi explore bật: method DELETE và mutation GraphQL có tên phá huỷ luôn bị coi là phá huỷ, kể cả khi có `-allow-write` |
| M4 | Trả lời "ở lại" cho `beforeunload` làm crawl kẹt | Spike: chấp nhận thì điều hướng đi tiếp | **Nhận.** Chấp nhận mọi hộp thoại; bộ xử lý chạy cho cả crawl, không chỉ trong explore |
| M5 | `window.close()` giết tab | Spike: tab **vẫn sống** vì `history.length=2` (chromedp mở `about:blank` trước) | **Không cần stub.** Giữ ca 19 trong fixture để chặn hồi quy. Mọi lệnh Input đều có timeout |
| M6 | Event mà tagger không bọc (mouseenter, scroll, mousedown, keyup…): timer đặt trong đó bị gắn `jsh:none` nên rơi vào background. `periodic` coi 3 request của feed là poll | Đúng (`build.go`, `chainOwner` và `periodic`; `nearAction` chỉ miễn cho request trong khoảng `Quiet` sau một hành động) | **Nhận, sửa gọn hơn đề xuất.** (a) Tagger bọc thêm các loại event này nhưng reporter không báo chúng; tag không khớp event nào thì rơi về cửa sổ thời gian thay vì background. (b) Mỗi lần cuộn là một hành động `scroll` riêng. (c) Phần tử có listener hover được hover như một hành động riêng **trước khi** click |
| S1 | Điều hướng bị khoá bị tính là ghi | Đúng (`isWrite`) | Nhận |
| S2 | Chữ ký quá thô: wizard dùng lại một nút "Next"; bảng có nhãn khác nhau; form SPA không có `action` | Đúng | Nhận: cho bấm lại tối đa 3 lần mỗi trang **khi tập chữ ký của trang đã đổi**; nhóm ≥ 3 anh em cùng cấu trúc thì bỏ nhãn khỏi chữ ký; ngữ cảnh của form là tập tên trường; `id` của gốc app (con trực tiếp của `body`) không dùng làm ngữ cảnh |
| S3 | Link có listener click riêng bị bỏ; container có handler riêng chứa nút bị bỏ | Đúng | Nhận: click link có listener click riêng (khoá điều hướng giữ nó lại); container có listener riêng và chứa dưới 3 phần tử thao tác được cũng được click |
| S4 | Regex logout là của riêng explore, không phải của guard; cần xét cả phần tử con (icon), tiếng Việt, và điều hướng bị khoá tới trang login | Đúng | Nhận (sửa câu trong mục 4). Thêm "đăng xuất", "thoát"; xét `class`/`title` của phần tử con; điều hướng bị khoá tới `login_url` được coi là dấu hiệu mất session |
| S5 | Theo dõi ứng viên biến mất theo `backendNodeId` sai với Vue/Angular | Đúng | Nhận: theo chữ ký. **Hoãn** việc replay đường đi (panel bị ẩn bởi click sau); thứ tự DFS ưu tiên phần tử mới đã giảm phần lớn trường hợp này |
| S6 | Danh sách cuộn trong container | Đúng | Nhận: mỗi bước cuộn cuộn cả tối đa 20 container có `overflow` cuộn được |
| S7 | Chờ yên tĩnh bị poll kéo dài; không có ngân sách cho cả run | Đúng | Nhận: `WaitIdle` (quiet 400 ms, tối đa 3 giây) sau thời gian chờ tối thiểu; thêm `-explore-total` (mặc định 30 phút) |
| S8 | Nút upload tự làm gọi `input.click()` | Đúng | Nhận: `Page.setInterceptFileChooserDialog` |
| S9 | Tải file ở chế độ attach | Đúng | Nhận: attach dùng `eventsEnabled`, rồi huỷ các lần tải của tab mình |
| S10 | IndexedDB của profile có thể giữ mutation chờ gửi | Đúng về nguyên lý | **Hoãn**, ghi vào giới hạn và cảnh báo. Xoá IndexedDB sẽ làm mất session của Firebase, vốn nằm ngoài ảnh chụp |
| S11 | GET có động từ hành động (approve, archive, …) làm đổi dữ liệu | Hợp lý cho một công cụ tự bấm mọi thứ | Nhận: khi explore bật, request XHR/Fetch GET có động từ trong path bị giữ lại với lý do `explore-verb`; `-guard-allow` ghi đè được |
| S12 | Kiểm trúng đích bằng cây snapshot sai với node mới sinh | Đúng | Nhận: thử 3 điểm; node lạ thì chụp lại một lần rồi kiểm lại, trước khi dùng fallback |
| S13 | `-explore` cần recorder; `runPage` không có hook; ca 4 cần `-depth ≥ 1` | Đúng | Nhận: explore luôn chạy qua frontier (kể cả `-depth 0`); `-record off` cùng `-explore` là lỗi |
| Ghi chú | `insertText` không sinh keydown/keyup | Đúng | Nhận: gõ từng ký tự bằng `dispatchKeyEvent` |

**Thêm vào fixture** (từ danh sách ca thiếu):
- popup `window.open`; form GET `target=_blank`; `beforeunload` khi form bẩn;
- wizard dùng lại một nút "Next"; bảng có nhãn khác nhau và `tr` click được; card có handler kèm nút bên trong; link có href và handler click riêng;
- hover-intent bằng `setTimeout`; loader cuộn có debounce; handler `mousedown`; tìm kiếm theo `keyup`; danh sách vô hạn trong container `overflow`; danh sách render lại sau mỗi click;
- modal có "Cancel" đứng trước "Confirm"; nút upload tự làm; 25 hộp thoại `alert`;
- GET có động từ (`/api/x/approve`); form `novalidate` kiểm tra bằng JS; logout tiếng Việt và logout chỉ có icon.

Gate riêng: `-allow-write` cùng DELETE sau `confirm()`; mất session trong lúc explore (`session-app`, `-role`).

**Chưa thêm:**
- **Trang do service worker phục vụ:** đã có `vite-pwa` trong bench.
- **`history.back()` cùng bfcache.**
- **Handler `while(true)`:** chỉ có timeout bảo vệ.
- **Menu chỉ dùng CSS `:hover`:** nút con không hiển thị nên không được hover. Đây là giới hạn đã biết.

## 13. Sửa đổi khi làm (bằng chứng từ gate)

- **Toạ độ của phép kiểm trúng đích.**
  - `DOM.getContentQuads` và `Input.dispatchMouseEvent` dùng toạ độ của **khung nhìn**, còn `DOM.getNodeForLocation` dùng toạ độ của **tài liệu** (khung nhìn cộng độ cuộn). Đã đo bằng spike: tại y=218 ra "No node found", tại y=218+scrollY ra đúng nút.
  - Nếu chưa sửa, mọi phần tử dưới màn hình đầu tiên đều bị coi là bị che: 97 click untrusted trong một run.
  - Cách sửa: cộng `pageX`/`pageY` lấy từ `Page.getLayoutMetrics`. Review độc lập không thấy lỗi này.
- **Event của chromedp phải nghe trên ctx của tab.** Bộ xử lý hộp thoại, bộ chọn file và sự kiện tải file từng nghe trên ctx của run và **im lặng không nhận gì**. Kết quả là `confirm()` làm treo trang.
- **Popup đang mở làm input của tab bị treo** (đã đo). Vì vậy sau mỗi thao tác, explore đóng các tab có opener là tab của mình.
- **Phần tử nằm sát mép dưới bị banner cố định che.** Khi bị che, cuộn phần tử vào giữa màn hình rồi thử lại, trước khi dùng `el.click()`.
- **Chữ ký:**
  - **Đường dẫn trang không phải ngữ cảnh** (đã bỏ cả luật "gốc app"). SPA phục vụ cùng một trang ở mọi route, nên mọi control bị làm lại trên mỗi trang: 52 thao tác cho mỗi route giống hệt nhau.
  - **"Hàng" phải có dạng hàng:** `li`/`tr`/role `row`… hoặc có class. Các `<section>` trần giống nhau đã làm nhãn của mọi nút trong `flows-app` bị gộp thành `*`, khiến `#next2` trùng chữ ký với `#next1` (id chuẩn hoá thành `next#`).
  - **Phải gặp trong ít nhất hai hàng khác nhau.** Card A và card B nằm chung một container nên không phải hàng.
- **Khoá nguyên văn (`Raw`, giữ chữ số)** dùng cho độ mới, cho việc gõ (mỗi trường một lần trên mỗi trang) và cho wizard. Trường `f2` của bước 2 có cùng chữ ký với `f1`, nên nếu chỉ dùng chữ ký, trang "trông như không đổi".
- **Bấm lại control đã bấm** chỉ khi: lần bấm trước làm trang có thêm control, mọi control mới đó đã được làm, và trang đang ở trạng thái chưa từng bấm nó. Luật đầu tiên ("trang đổi là bấm lại") đã bấm "Delete" và tab "Billing" 3 lần.
- **Con trỏ về góc sau mỗi thao tác, trừ hover:** khi trang cuộn, phần tử trượt vào dưới con trỏ đang đứng yên và bị hover ngoài ý muốn; còn sau hover thì menu vừa mở phải còn nguyên để bấm.
- **`flow`:** tag của event con trỏ đi vào hoặc nhấn (`mouseenter`, `mousedown`…) thuộc về cú click đến trong 500 ms sau nó, trước khi xét luật "hành động hover/scroll trong 1 giây". Nếu không, request `mousedown` của một nút rơi vào hành động hover đứng trước.
- **Trước khi submit, `prepare` điền mọi trường trống** (không chỉ trường trình duyệt báo không hợp lệ), vì form `novalidate` tự kiểm bằng JS.
- **Bão hộp thoại** (quá 20 trong một thao tác): tải lại trang rồi làm tiếp, không bỏ dở cả trang.
- **Lỗi có từ 4.4, đã sửa:** document mà guard trả lời giả (204) từng được capture ghi là document chính, và `flows.jsonl` từng tạo hành động `load` cho nó.

## 14. Kết quả (2026-11-04)

| Cổng | Kết quả |
|---|---|
| G1 `flows-app`, không có kịch bản | Mọi tính năng trong `flows.truth.json` đều thành một hành động explore chứa đúng request của nó. Precision 1.000. Các hàng 42/108 được tính là một tính năng, vì explore chỉ dùng một hàng đại diện |
| G2 `webpack-vanilla`, `-resolve=false -depth 1` | 16/20 khi không explore → **19/20** khi explore. Đạt `click:report`, `scroll:comments`, `form:welcome`. Marker thiếu là `auth-server:admin-panel`, cần role admin |
| G3 `edge-cases` | `inline:handler` đạt |
| G4 `explore-app`, `-depth 1` | **56/56 ca**, precision 1.000. 10 trang trong khoảng 2,5 phút. Mỗi trang sau trang đầu chỉ còn vài thao tác, nhờ khử trùng lặp trên cả run |
| G5 Crawlground có `-explore` | **56/59** (trần khi guard bật: 3 test POST bị giữ có chủ đích). crawl-maze 76/84, và 79/84 cùng javascript 20/20 khi cho phép các trang có tên phá huỷ. Thời gian: Crawlground 511 giây khi explore, 212 giây khi không |
| G6 an toàn | 0 ghi, 0 logout (4 kiểu: tiếng Anh, tiếng Việt, icon, `role=button`), 0 điều hướng do explore tới server. `-allow-write`: không có DELETE, GET `approve` hay logout nào. `session-app` với `-role`: nút "Reset view" xoá session ngay phía client; jsharvest phát hiện ngay sau click, khôi phục, rồi crawl tiếp; chỉ `POST /api/login` tới server |
| G7 hồi quy | Unit `-race`, bench, `flows-gate.sh`, `attach-guard.sh`, `frontier-check.sh`, `session-check.sh` (admin 55/56 như 4.5), `endpoints-check.sh`, `external/run.sh` không có `-explore`: **đều đạt** |

**Giới hạn còn lại** (ngoài mục 11):
- Chưa replay đường đi: panel bị một click sau che mất thì các nút trong đó bị bỏ lỡ.
- Menu chỉ dùng CSS `:hover` không được mở.
- IndexedDB của profile có thể còn giữ mutation đang chờ gửi (mục 12, S10).
- Popup ở chế độ attach: guard thả qua tab nào nó đã biết chắc là của người dùng.
- Request phát từ IntersectionObserver không có tag: chúng được gán theo cửa sổ thời gian của hành động scroll.

## 15. Lỗ hổng guard phát hiện ở GĐ5.1 (2026-11-04)

Review thiết kế GĐ5.1 chỉ ra (đã kiểm trên `diff.json` của roles-check) rằng khi admin bấm "Purge cache" trong `crawl -explore`, request `GET /api/ra/rpc?action=purge` **đã tới server**. Có ba lý do:
- `destructiveRe` không có purge, wipe;
- `actionVerb` chỉ xét path, không xét tham số operation;
- với `-allow-write`, mutation `PurgeUsers` lọt vì tên không khớp `destructiveRe`.

Đã sửa trong `internal/guard/rules.go`:
- `destructiveRe` thêm `purge|wipe|truncate|erase`; `Destructive` vốn xét path và query, nên `?action=purge` bị chặn ở mọi chế độ;
- explore xét động từ hành động trong giá trị của `action`, `op`, `cmd`… (`operationVerb`);
- `EffectiveMethod`: method thật tính theo `X-HTTP-Method-Override` (và các header tương tự) hoặc `_method` trong query hay body form; DELETE nguỵ trang luôn bị coi là phá huỷ, kể cả khi có `-allow-write`.

Hệ quả cho fixture: trang `/account/wipe` của session-app (trang xoá dữ liệu phía client, cố ý đặt tên không giống logout) nay bị frontier bỏ qua vì chứa "wipe", nên được đổi tên thành `/account/privacy`. Các gate attach-guard, explore, roles, frontier, flows, session, export và bench đều đạt.
