# GĐ4 — Kế hoạch (bản 2, 2026-11-03)

**Thay đổi so với bản 1:** đoạn chat với người giao việc (2026-11-03) làm rõ mục tiêu cuối:

> "CDP chrome debugger… click vào 1 tính năng nó simulate hết được flows, bắt được cả chùm request, rồi export dạng jsonl… bắt và **fuzz request theo cụm tính năng**", và "pack luôn mớ tools vô container".

Vì vậy **trọng tâm chuyển sang traffic được gom theo tính năng, phục vụ fuzz**. Thu thập JS (đã có, 53/56) trở thành phần hỗ trợ: tìm endpoint, chunk ẩn và tham số.

**Giả định (chưa được người giao việc xác nhận; sửa ở đây nếu khác):**
- **A1.** Traffic theo tính năng là mục tiêu chính; JS là phần hỗ trợ.
- **A2.** Fuzz: trước hết **xuất sang công cụ có sẵn** (Burp, ffuf, nuclei); bộ tự replay để GĐ5, phải bật rõ bằng cờ và chỉ dùng trên target được phép.
- **A3.** Recorder và gom theo hành động làm **trước** frontier.
- **A4.** "Ai điều khiển trình duyệt" là chuyện tách rời: explore tự động, **AI agent hoặc script Playwright**, hay người bấm tay. jsharvest chỉ cần **ghi lại và gom**, nên ý tưởng "cho AI duyệt" dùng chung được với tool CDP.

**Bản 2.1 (2026-11-03), sau 4.3:** việc "AI điều khiển Chrome" là thứ các MCP Chrome (chrome-devtools-mcp, Playwright MCP, Claude in Chrome) đã làm; jsharvest **không làm lại**. Vai trò của jsharvest là tầng bên dưới:
- ghi lại traffic;
- gán request vào thao tác theo chuỗi nhân quả;
- guard chặn ghi và logout;
- xuất dữ liệu cho fuzz;
- thu thập JS.

AI (qua MCP) và jsharvest `watch` gắn vào **cùng một Chrome**. Do đó:
- (a) bỏ `-explore-llm` khỏi 4.6; explore của jsharvest chỉ là loại tất định, không dùng LLM;
- (b) thêm **4.3c**: giới hạn guard theo tab đang được `watch`, vì đây là cấu hình chạy chung với AI. **Kết quả đo khác giả định:** tab khác vốn không bị ảnh hưởng, nhưng guard có lỗ hổng với target đã chạy trước khi nó bật (service worker chạy sẵn, trang đã tải trong `watch`). 4.3c đã sửa lỗ hổng đó (`docs/gd4-guard-sw-design.md`);
- (c) thêm **4.3d**: giao diện MCP chỉ đọc, để AI đang điều khiển hỏi được jsharvest "thao tác vừa rồi gửi gì".

Thứ tự mới: 4.3c ✅ → 4.3d ✅ → 4.3b ✅ → 4.4 ✅ → 4.5 ✅ → 4.6 ✅ → 4.7 ✅ → 4.8 ✅

Đã xong: **4.0 `-urls`** (`8099d27`), **4.1 guard** (`45e7a4f`), **4.2 recorder** (`8aea901`; thiết kế và kết quả: `docs/gd4-recorder-design.md`), sửa 4 bug từ bản đánh giá cập nhật (`docs/review-assessment-2026-11-03.md`; có `testbed/attach-guard.sh` cho chế độ attach), **4.3 hành động, cụm và `watch`** (thiết kế, hai lượt đánh giá độc lập và kết quả: `docs/gd4-flows-design.md`; gate: `testbed/flows-gate.sh`).

## 1. Thứ tự mới và cổng nghiệm thu

| Bước | Nội dung | Cổng nghiệm thu (đo được) |
|---|---|---|
| **4.2** | **Recorder:** mọi request/response vào `requests.jsonl` | Với mọi app testbed: mọi request trong log server đều có trong `requests.jsonl` (đối chiếu từng dòng, **100%**); request bị guard chặn có `held_back`; test che giá trị nhạy cảm (`-redact`); chi phí ≤ 15% thời gian |
| **4.3** | **Hành động và cụm (flows):** gom request theo hành động, ra `flows.jsonl`; chế độ **watch** ghi lại thao tác của người, AI hoặc Playwright | Fixture `flows-app` có 4 tính năng với tập request đã biết, kèm nhiễu (poll nền, analytics): precision và recall của việc gom **≥ 95%**; cùng kết quả khi thao tác bằng script Playwright attach và khi bấm qua CDP |
| **4.3c ✅** | (Đã làm theo hướng khác, xem `docs/gd4-guard-sw-design.md`: bật tầng chặn trên mọi target có sẵn lúc khởi động.) **Guard theo tab trong `watch`:** chỉ chặn request của tab đang được `watch` (cây frame, cùng các target capture đã gắn: worker, iframe khác site, service worker của chính origin), thả qua request của tab khác. Với request không xác định được nguồn gốc: khi chạy `watch` trên profile dùng chung thì thả qua kèm ghi log; khi chạy trên profile riêng thì chặn | `attach-guard.sh` thêm: service worker và iframe của **tab khác** vẫn ghi được; 0/18 request bị cấm lọt từ tab đang `watch` |
| **4.3d ✅** | (Kết quả: `docs/gd4-mcp-design.md`; gate `MCP=1` trong `flows-gate.sh`: 20/20 bước khi guard tắt và khi bật; agent thật 5/5.) **Giao diện MCP chỉ đọc** (`jsharvest mcp`, chạy cùng `watch`). Các tool: `last_action`, `list_flows`, `get_flow`, `get_request`, `blocked`, `endpoints`. Không có tool nào điều khiển trình duyệt hay gửi request | Một agent (Claude với chrome-devtools-mcp) thao tác `flows-app`, rồi qua MCP lấy được đúng cụm request của từng thao tác |
| **4.3b ✅** | (Kết quả: `docs/gd4-static-endpoints-design.md`. Tự viết bằng Go thuần trên parser tdewolff vì jsluice trượt template literal, method và tham số; mỗi endpoint có vòng đời `static → both`. Gate `testbed/endpoints-check.sh` đạt 26/26 ở cả 3 pha; `flows-app` 29/29.) **Endpoint tĩnh từ JS** (`source: static_js`), kể cả chunk chưa chạy | API chỉ có trong chunk admin được liệt kê khi chạy role `anon` |
| **4.4 ✅** | (Kết quả: `docs/gd4-frontier-design.md`. Crawlground 56/59 khi guard bật; crawl-maze 76/84 mặc định, 79/84 với javascript 20/20 khi cho phép các trang tên phá huỷ; gate nội bộ `testbed/frontier-check.sh`; gate ngoài `testbed/external/run.sh`.) **Frontier** đa trang (như bản 1); mỗi lần tải trang là một cụm | Crawlground ≥ 50/59 khi guard bật; crawl-maze ≥ 51/84, nhóm javascript ≥ 19/20 |
| **4.5 ✅** | (Kết quả: `docs/gd4-session-design.md`. Admin 55/56; marker thiếu là trang không có link nào trỏ tới, chỉ tìm được bằng đoán đường dẫn. Mất session được phát hiện, khôi phục hoặc đăng nhập lại, rồi crawl tiếp; không có kịch bản thì dừng với mã thoát 4. Gate `testbed/session-check.sh`.) **Login và session:** profile, bản chụp sessionStorage, phát hiện mất session, **khôi phục sau `Clear-Site-Data`** | Role admin 56/56; fixture mất session được phát hiện và khôi phục, rồi crawl tiếp |
| **4.6 ✅** | (Kết quả: `docs/gd4-explore-design.md`, gồm đánh giá độc lập ở mục 12. `flows-app` tìm đủ mọi tính năng mà không cần kịch bản, precision 1.000; fixture `explore-app` đạt 56/56 ca khó, 0 ghi và 0 logout tới server; webpack tắt resolver đạt `click`, `scroll` và `form`. Không dùng accessibility tree, vì mỗi lần đọc mất 520–650 ms. Gate `testbed/explore-check.sh`.) **Explore tương tác tất định** (accessibility tree + listener thật, không dùng LLM), **mỗi thao tác là một cụm**. Khám phá có AI thì dùng MCP + `watch` (4.3d) | Crawlground ≥ 55/59; `flows-app` tự tìm đủ 4 tính năng mà không cần script |
| **4.7 ✅** | (Kết quả: `docs/gd4-roles-design.md`. Lệnh `jsharvest diff` so 4 tầng là endpoint, tính năng, trang và script; chỉ đọc output, không gửi request. Gate `testbed/roles-check.sh`: `role-app` 27/27 mục đúng lớp và đúng role, không có mục thừa.) **So sánh giữa role** ở mức tính năng và endpoint | Chỉ ra tính năng và endpoint chỉ có ở admin trên testbed |
| **4.8 ✅** | (Kết quả: `docs/gd4-export-design.md`, mục 9 là đánh giá độc lập, mục 10 là kết quả. Lệnh `jsharvest export`; gate `testbed/export-check.sh`: 28/28 request của các bước có file thô, replay giống bản gốc, bản `-redact` bị từ chối, save bị guard giữ replay ra 200.) **Xuất cho fuzz** theo cụm | Mỗi cụm ra được HAR, file request thô (ffuf/Burp), và **danh mục tham số**; replay một request đã xuất trên testbed cho response giống bản gốc |

**GĐ5** (giữ nguyên, thêm vào). **5.1 ✅** replay theo cụm và kiểm thử phân quyền (`jsharvest authz`, `jsharvest replay`; `docs/gd5-replay-design.md`; gate `testbed/replay-check.sh`). **5.2 ✅** container (`docs/gd5-container-design.md`; gate `testbed/docker-check.sh`). **5.3 ✅** archive (`docs/gd5-archive-design.md`; gate `testbed/archive-check.sh`). **5.4 ✅** monitor (`docs/gd5-monitor-design.md`; gate `testbed/monitor-check.sh`). GĐ5 xong.
- bộ tự replay và fuzz theo cụm (`-allow-write`, rate limit, scope);
- archive, analyze, monitor;
- **container chứa cả bộ công cụ**: jsharvest, Chrome, và tuỳ chọn katana/ffuf.

Quy trình cho mỗi bước giữ như cũ: thiết kế, đánh giá độc lập (bắt buộc cho 4.3, 4.3c, 4.6 và 4.8), fixture và test trước, code, gate, commit.

---

## 4.2 Recorder — `requests.jsonl`

**Nguồn dữ liệu:** event Network trên **mọi session capture** (tab, worker, SW, shared worker, OOPIF), cộng các request bị guard chặn (lấy từ guard).

**Một dòng gồm:**
- **Định danh:** `id`, `ts`, `target` (page, worker…), `page`, `frame`, `action_id` (điền ở 4.3).
- **Request:** `method`, `url`, `headers` (dùng `requestWillBeSentExtraInfo` để có header thật, kể cả Cookie), `body` (`postDataEntries`; mặc định tối đa 64 KB), `resource_type`.
- **Response:** `status`, `headers` (qua `responseReceivedExtraInfo`), `mime`, `body` cho XHR/Fetch/Document có dạng JSON hoặc text (mặc định tối đa 64 KB; `-record-bodies all|api|none`), `timing`.
- **Nguồn gốc:** `initiator` (loại, URL, dòng; stack rút gọn khi có).
- **Kết quả:** `outcome`: `ok` | `failed:<lý do>` | `held_back:<lý do>` (từ guard) | `redirect`.

**Không ghi** script, CSS, ảnh, font (script đã nằm trong store JS), trừ khi có `-record-all`.

**Bảo mật:**
- File output có quyền `0600`.
- `-redact` thay giá trị `Authorization`, `Cookie`, `Set-Cookie`, và các tham số hoặc trường JSON có tên kiểu `token|secret|password|session` bằng `«redacted:sha256-8»`. Hash ngắn giúp vẫn ghép được các giá trị giống nhau.
- **Mặc định không che**, vì fuzz cần giá trị thật; khi chia sẻ file thì chạy với `-redact`.

**Fixture và kiểm thử:**
- Đối chiếu từng dòng log của server testbed với `requests.jsonl` trên cả 9 app.
- Unit test cho phần che và giới hạn kích thước.

## 4.3 Hành động và cụm — `flows.jsonl`

**Hành động** là thứ khởi phát traffic:
- `load` (điều hướng);
- `click` / `submit` / `key` / `change` / `hover`, do explore thực hiện, hoặc **ghi lại** khi người, AI hay Playwright thao tác;
- `timer` (traffic nền không gắn với hành động nào).

**Ghi lại thao tác trong chế độ watch:** script chạy trước trang (có tag internal) nghe `click`, `submit`, `keydown Enter`, `change` ở capture phase, rồi báo qua `Runtime.addBinding` → event `bindingCalled`. Mỗi báo cáo gồm thời điểm, phần tử (role, accessible name, text, selector rút gọn), và URL.

**Gom request vào hành động:**
1. **Chuỗi nhân quả trước:** initiator có async stack chạm tới handler của hành động → thuộc hành động đó (`setAsyncCallStackDepth` khi Debugger bật).
2. **Cửa sổ thời gian sau:** từ lúc hành động bắt đầu đến khi mạng yên (1,5 s, tối đa 10 s), loại trừ các **mẫu nền** đã học được (cùng method + path template lặp lại theo chu kỳ khi không có thao tác nào → gắn `timer`).
3. Request do service worker hoặc worker phát ra: ghép theo `networkId`/URL với request của trang.

**Một dòng `flows.jsonl`:** `action_id`, `kind`, `label` (ví dụ "Save profile", "button#export"), `page`, `route`, `started`, `ended`, `request_ids[]`, `writes[]` (gồm cả request bị chặn), `endpoints[]` (method + **path template**: `/api/users/{id}`), `confidence`.

**Chế độ dùng:**
- `jsharvest watch -attach …`: chỉ ghi lại, không tự điều hướng. Phù hợp khi bạn, AI agent hoặc Playwright điều khiển trình duyệt.
- Trong `crawl`: frontier và explore tự tạo hành động.

**Fixture `flows-app`:** 4 tính năng (tìm kiếm GET, lưu form POST, xoá có xác nhận, wizard 2 bước), cộng poll nền mỗi 2 giây và một lần gọi analytics. Đáp án là tập request của từng tính năng. Thêm một **script Playwright mẫu** (chạy trong container Node, giống cách build testbed) thao tác 4 tính năng ở chế độ attach.

### Đầu vào bổ sung từ đánh giá độc lập (2026-11-03; xem `docs/review-assessment-2026-11-03.md`)
- **Khoá tính năng phụ: "first application frame".** Duyệt `initiator.stack` từ trên xuống, bỏ frame thuộc script `third-party` hoặc thư viện/wrapper (vendor, framework, polyfills, axios…), rồi lấy frame ứng dụng đầu tiên kèm `canonical_key` của script đó. Khoá này dùng khi chuỗi nhân quả hành động → request không đủ.
- **Path template có hỗ trợ initiator:** heuristic từng segment (số, UUID/ULID, hex hoặc base64url dài, JWT, email, timestamp) và gộp theo cây prefix. Ngoài ra, hai request có cùng (method, host, frame ứng dụng) và cùng số segment mà khác ở segment thứ k thì segment đó là tham số.
- **`depends_on`:** giá trị vô hướng (chuỗi ≥ 4 ký tự, số khác 0 và 1, mã `REDACTED_`) trong body hoặc header của response trước xuất hiện trong path, query, header hoặc body của request sau trong cùng phiên.
- Fixture `flows-app` thêm hai ca: một wrapper `apiClient()` dùng chung (cả 4 tính năng đi qua nó), và một luồng cần CSRF/id lấy từ response trước.

## 4.3b Endpoint tĩnh từ JS (bước mới)
Trích lời gọi API từ các script trong store, kể cả chunk chưa chạy (ví dụ chunk admin): `fetch`, `axios`, `XMLHttpRequest.open`, template literal. Mỗi endpoint ghi method, path, tên tham số và `source: static_js`, bên cạnh traffic quan sát được. Lọc nhiễu: MIME, đường dẫn tương đối của module, SVG path. Thử nghiệm jsluice (Go, tree-sitter) trước khi tự viết. Cổng nghiệm thu: fixture có API chỉ nằm trong chunk admin được liệt kê khi chạy với role `anon`.

## 4.4 Frontier — như bản 1, mục 4.2
Nguồn URL lấy từ DOM (kể cả shadow DOM, iframe, SVG, `<area>`, `<base>`, `<noscript>`, `<template>`), form GET, URL trích từ JS, redirect, popup. Áp dụng lọc trang và mẫu phá huỷ, giới hạn `-max-pages`/`-depth`/`-page-rate`. Output `pages.jsonl`, `endpoints.jsonl`. **Mỗi lần tải trang là một hành động `load`** trong `flows.jsonl`.

## 4.5 Login và session — như bản 1, mục 4.3, thêm phần khôi phục
Khi guard phát hiện `Clear-Site-Data`, hoặc dấu hiệu đã đăng nhập biến mất: tạm dừng, **khôi phục cookie và storage** từ bản chụp lúc login (`Network.setCookies`, script nạp lại storage), kiểm tra lại dấu hiệu đăng nhập, rồi tiếp tục. Thất bại thì dừng và báo cáo.

## 4.6 Explore tương tác — như bản 1, mục 4.4, thêm các điểm sau
- **Accessibility tree** (`Accessibility.getFullAXTree`) để chọn phần tử tương tác theo role và tên, kết hợp với listener thật.
- Chỉ chọn phần tử có listener thật (`DOMDebugger.getEventListeners`, hoặc hook `addEventListener` trong script chạy trước trang). Dùng chữ ký DOM `(tag, class, tag cha)` để mỗi nhóm phần tử lặp lại chỉ click một đại diện. Sau mỗi thao tác, kiểm tra xem có request, script hay phần tử mới xuất hiện không để quyết định có đi tiếp nhánh đó (theo crawlergo và Crawljax).
- ~~Tuỳ chọn LLM dẫn đường (`-explore-llm`)~~: **bỏ ở bản 2.1.** Với tính năng cần "hiểu" giao diện (form nhiều bước, wizard), dùng một AI agent qua MCP Chrome điều khiển cùng trình duyệt mà jsharvest `watch` đang ghi (4.3d), thay vì nhúng LLM vào jsharvest.

## 4.7 So sánh giữa role — như bản 1, mục 4.5, thêm phần tính năng
So sánh 3 lớp JS **và** danh sách tính năng/endpoint trong `flows.jsonl` giữa các role. Danh sách "chỉ role cao hơn có" là đầu vào cho test phân quyền.

## 4.8 Xuất cho fuzz theo cụm
Với mỗi cụm (hoặc mỗi endpoint template trong cụm), xuất:
- **HAR** của cụm (mở được trong Burp và DevTools);
- **file request thô** (`requests/<flow>/<n>.http`) dùng được cho `ffuf -request`, Burp "Paste from file", sqlmap `-r`;
- **danh mục tham số** `params.jsonl`: endpoint, vị trí (path, query, body JSON, form, header), tên, kiểu suy ra, giá trị mẫu, có xuất hiện trong JS hay không (lấy từ store JS);
- tuỳ chọn: template nuclei theo endpoint (để sau).

**Mặc định không gửi request nào.** Bộ tự replay và fuzz thuộc GĐ5.

---

## 5. Ánh xạ Crawlground (giữ từ bản 1)
Frontier (4.4) phủ các nhóm links, frames, phần lớn dynamic-content, forms GET, navigation, buttons và other, nhờ đọc DOM và trích từ JS. Explore (4.6) phủ js-events, wizard, scroll và các tương tác còn lại bằng thao tác thật. 3 test POST chủ động không đạt khi guard bật (chúng được ghi vào `blocked.jsonl` và `requests.jsonl` với `held_back`). Dự báo sau 4.4: 52–56/59; trần khi bật guard: 56/59.

## 6. Rủi ro mới
| Rủi ro | Biện pháp |
|---|---|
| `requests.jsonl` chứa token, cookie, mật khẩu | Quyền `0600`; `-redact` khi chia sẻ; ghi rõ trong README |
| Gom nhầm cụm khi nhiều hành động chồng nhau | Ưu tiên chuỗi nhân quả, cửa sổ thời gian chỉ là phương án sau; ghi `confidence`; đo precision/recall trên `flows-app` |
| Fuzz gây hại cho target | Xuất trước, chưa gửi gì; bộ fuzz (GĐ5) cần `-allow-write`, rate limit, scope, và chỉ dùng trên target được phép |
| AI điều khiển (qua MCP) click nhầm thao tác phá huỷ, hoặc làm hỏng tab khác | Guard bật khi `watch`; 4.3c giới hạn guard theo tab; dùng profile riêng cho target |
