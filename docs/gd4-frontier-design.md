# GĐ4 4.4 — Frontier đa trang

**Mục tiêu (plan, mục 4.4; bản 1, mục 4.2).** `crawl` tự đi tới các trang của target mà không cần thao tác: theo link, form GET, URL trong JS, header, redirect, popup. Mỗi lần tải trang là một hành động `load` trong `flows.jsonl`.

**Cổng nghiệm thu:**
- Crawlground ≥ 50/59 khi guard bật;
- security-crawl-maze ≥ 51/84, trong đó nhóm javascript ≥ 19/20.

**Mốc xuất phát (GĐ3):** jsharvest chạy từ trang gốc được 0/59 và 0/84. Katana standard được 54/59 và 51/84.

## 1. Quyết định

- **Frontier là tuỳ chọn:** `crawl -u URL -depth N` với N ≥ 1. Mặc định `-depth 0` giữ hành vi cũ (một trang), để bench và các gate hiện có giữ nguyên ý nghĩa. Lý do: trên target thật, đi theo link nghĩa là gửi thêm request, và người dùng phải chủ động chọn điều đó.
- **Một tab, một capture, một run.** Mỗi trang gồm: điều hướng, settle (idle, cộng thời gian dừng tối thiểu `-page-dwell` 1,5 giây để timer khoảng 1 giây kịp chạy: meta refresh, `location` trễ, `requestSubmit`), thu URL, chạy resolver. `finish` chỉ chạy một lần ở cuối. Mọi trang dùng chung `requests.jsonl` và `flows.jsonl`.
- **Chỉ đi theo GET.** URL của form POST, và endpoint mà code gọi bằng method khác GET, chỉ được **ghi lại** chứ không thăm. Endpoint trông giống API (`/api/`, `.json` …) cũng chỉ được ghi lại, trừ khi nó là `href` của một link, vì link thì sinh ra để mở. Guard vẫn bật như mọi lần chạy. Ngoài ra, trước khi thăm, URL còn bị lọc theo mẫu phá huỷ của guard (logout, delete, reset …).

## 2. Nguồn URL và cách xử lý

| Nguồn | Cách lấy | Thăm? |
|---|---|---|
| Link: `a`, `area`, `iframe`, `frame`, `link rel=alternate/next/prev`, `meta refresh` | `DOM.getDocument(depth=-1, pierce)`: shadow root (kể cả closed), iframe cùng tiến trình, `<template>` | có, trừ file tĩnh |
| Form GET | các control của form: text theo kiểu, `select` lấy option đầu, radio và checkbox, `formaction`, `formmethod`, `input type=image` có x/y | có |
| Form POST, `formmethod=post` | như trên | ghi lại |
| Thuộc tính tài nguyên: `src`, `srcset`, `poster`, `data`, `codebase`, `archive`, `cite`, `longdesc`, `lowsrc`, `dynsrc`, `ping`, `background`, `manifest`, `profile`, `xlink:href`, `param value`, `meta content`, doctype | DOM | ghi lại (trình duyệt tự tải những gì cần) |
| `<noscript>`, comment (kể cả conditional) | parse đoạn HTML bằng `x/net/html` | như link |
| Text trong trang | regex URL tuyệt đối và path có đuôi file | ghi lại |
| Handler inline (`onclick=…`), `href="javascript:…"` | `jsapi` trên đoạn code | như JS |
| JS đã thu thập (script mới sau mỗi trang) | `jsapi`: endpoint GET hoặc navigation không trông giống API, route, và **`paths`** (mới: mọi chuỗi trông giống path, kể cả `href="…"` nằm trong chuỗi HTML) | có, nếu có dạng trang |
| Header của document: `Location`, `Refresh`, `Link`, `Content-Location` | entry của recorder | có (`Location`, `Refresh`) / ghi lại |
| Trang tự điều hướng (redirect, meta refresh, `location`, form tự submit) | URL của main frame sau settle | đã được tải: đánh dấu là đã thăm |
| Popup (`window.open`) | `Target.targetCreated` có `openerId` là tab của tool: ghi URL rồi đóng | ghi lại (trình duyệt đã request) |
| `robots.txt`, `sitemap.xml` | fetch qua trang (isolated world, cùng origin, `redirect: manual`) khi bắt đầu | có |

**"Có dạng trang"** nghĩa là: không có đuôi file, hoặc đuôi `.html .htm .php .asp(x) .jsp .do .cgi`, hoặc đuôi lạ (ví dụ `.found`); và không phải file tĩnh (ảnh, css, font, media, js, archive, pdf).

## 3. Hàng đợi

- **Thứ tự:** BFS theo độ sâu. Trong cùng một độ sâu, ưu tiên theo nguồn: link, form, header, redirect, route, robots và sitemap, rồi JS.
- **Chuẩn hoá để dedupe:** bỏ fragment (trừ hash route `#/…`, `#!…`), sắp xếp query, bỏ `:80`/`:443`, thêm `/` cho path rỗng.
- **Lọc:** scope, http(s), mẫu phá huỷ, file tĩnh, đã thăm.
- **Giới hạn:** `-max-pages` (mặc định 200), `-depth`, `-page-rate` (mặc định 2/s). Dừng khi gặp trang challenge hoặc 3 lần liền 429/503.

## 4. Output

- **`pages.jsonl`**, mỗi dòng một URL:
  - đã thăm: `url`, `final_url`, `status`, `depth`, `from`, `how`, `discovered`, `took_ms`;
  - chưa thăm: `visited: false` và `reason` (`asset`, `post`, `api`, `destructive`, `scope`, `limit`, `listed`).

  URL chưa thăm vẫn có ích cho bước sau (fuzz, explore).
- **`flows.jsonl`:** mỗi trang là một hành động `load`, có sẵn nhờ `MainDocument`.
- **`endpoints.jsonl`:** như 4.3b, giờ gồm JS của mọi trang.

## 5. Kiểm thử và gate

- **Unit:** chuẩn hoá và dedupe; lọc; form (từng loại control); header; robots và sitemap; DOM giả (shadow, template, iframe, noscript, comment, doctype); `jsapi.paths`.
- **Fixture `testbed/apps/frontier-app`:** mỗi nguồn ở bảng trên có một trang, kèm `truth`: URL phải được thăm, URL chỉ được ghi lại, và URL **không được** request (`/logout`, POST, file tĩnh).
- **Gate `testbed/frontier-check.sh`:** chạy `crawl -depth 3` với guard bật. Mọi URL phải-thăm đều được thăm; mọi URL chỉ-ghi đều có trong `pages.jsonl`; không URL cấm nào có trong log server.
- **Gate ngoài `testbed/external/run.sh`:** dùng image Docker đã có (`jsh-ext-crawlground`, `jsh-ext-crawlmaze`) để chấm Crawlground (`/set-tool`, `/results.json`) và crawl-maze (log server cộng output đã liệt kê). Gate này không chạy trong mọi commit.
- Bench gate và flows gate không được giảm (chúng chạy `-depth 0`).

## 6. Sửa đổi khi làm

- **`DOM.getDocument(pierce)` không trả `templateContent`**, trái với giả định ở mục 2. DOM giả trong unit test không cho thấy điều này. Phát hiện được khi chạy Crawlground: test `08-template-element` trượt dù trang đã được thăm. Cách sửa: đọc thêm `DOM.getOuterHTML` của document (markup có cả nội dung template) rồi parse bằng `x/net/html`. Đây cũng là bước "đọc HTML thô" mà plan bản 1 đề xuất.
- **`jsapi` coi `.html` là file tĩnh** (quy tắc đặt ra ở 4.3b cho endpoint API). Hệ quả: `location.href='/x.html'`, link `javascript:` và chuỗi path `.html` đều bị loại. Đã bỏ `.html`/`.htm` khỏi danh sách file tĩnh. Chuỗi đứng riêng vẫn phải trông giống API mới được tính là endpoint, nên số nhiễu không tăng. `jsapi.Version` lên 5.
- **`jsapi` có thêm `paths`**: mọi chuỗi trông giống URL mà chưa là endpoint hay route, gồm `href`/`src`/`action` nằm trong chuỗi HTML, và phép nối chuỗi `+` ở ngoài mọi lời gọi hàm (`var full = domain + path`).
- **Header của trang tự chuyển đi bị mất.** Header `Refresh` đưa tab sang trang khác sau 1 giây, nên document cuối cùng không còn là document có header đó. Capture giờ giữ danh sách các document chính của mỗi lần thăm (`TakeMainDocuments`).
- **Lần đo Crawlground đầu tiên không hợp lệ.** Một container từ GĐ3 vẫn chiếm cổng 3456, nên lượt crawl bị tính vào công cụ khác (`katana-std` từ 54 lên 59). Script `run.sh` giờ dùng container và cổng riêng cho mỗi lần chạy.
- **Trang crawl-maze có tên phá huỷ** (`js-delete.html`, `…-remove-button.html`, `…-remove-event-listener.html`) bị luật của guard chặn, cả khi frontier lọc trước lẫn khi guard chặn lúc điều hướng (status 204). Luật này cố ý nghiêng về an toàn ("mất một trang, không mất session"), nên được giữ nguyên. Cho phép thì dùng `-guard-allow`, và luật cho phép này áp dụng cho cả guard lẫn frontier. Flask trả 308 về `….html/`, nên regex phải là `\.html/?$`.

## 7. Kết quả

Gate ngoài `testbed/external/run.sh` (guard bật, chạy từ trang gốc, `-page-rate 10`):

| Testbed | GĐ3: jsharvest chạy từ gốc | katana standard | **4.4** | Cổng |
|---|---|---|---|---|
| Crawlground | 0/59 | 54/59 | **56/59** trong 209 giây; chỉ trượt 3 test POST, và 56 cũng là trần khi guard bật | ≥ 50 ✅ |
| crawl-maze, either (cấu hình mặc định) | 0/84 | 51/84 | **76/84**; request 42, liệt kê 76 | ≥ 51 ✅ |
| crawl-maze, nhóm javascript (cấu hình mặc định) | 0/20 | 1/20 | 17/20; 3 trang tên `delete`/`remove` không được mở | — |
| crawl-maze, có `-guard-allow` cho các trang `.html` đó | — | — | **79/84; javascript 20/20; 0 request ghi tới server** | ≥ 19 ✅ |

5 đáp án crawl-maze còn trượt:
- `css/font-face`: phải phân tích CSS, ngoài phạm vi;
- `frameset/frame/src`: Flask 308 về `…html/` làm hỏng URL tương đối;
- `img/src-data`: URL nằm trong một `data:` URI;
- `head/import`: HTML Imports đã bị gỡ khỏi Chrome;
- `string-known-extension.pdf`: chuỗi `/x.pdf` đứng sau `<base href="/test/html/misc/string">`; đáp án cho rằng nó được nối vào base, trái với cách trình duyệt resolve.

Gate nội bộ `testbed/frontier-check.sh` (`frontier-app`, `-depth 3`, guard bật):
- 33/33 trang phải được thăm, gồm cả shadow root closed, template, comment, `javascript:`, chuỗi trong script, header `Refresh`/`Link`/`Content-Location`, robots, sitemap, hash route;
- 8/8 URL chỉ được nêu tên, mỗi URL đúng lý do (`post`, `listed`, `destructive`, `asset`, `scope`, `depth`);
- **0 request tới các path bị cấm** (POST, `/logout`, trang tên `delete`, file tĩnh, trang vượt độ sâu, `/api/things`);
- 32 hành động `load` trong `flows.jsonl` cho 29 lần thăm (redirect và Refresh tạo thêm hành động `load`).

## 8. Giới hạn

- **Mặc định `-depth 0`.** Muốn đi theo link thì phải bật frontier. `-urls` chưa kết hợp được với `-depth`.
- **Không thao tác:** click, hover, scroll, submit form POST thuộc 4.6. Ba test POST của Crawlground là trần chừng nào guard còn bật.
- **Thời gian dừng tối thiểu 1,5 giây mỗi trang** để timer kịp chạy. Với 150 trang, mất khoảng 4 phút ở `-page-rate 10`; ở mặc định 2/s thì chậm hơn nữa.
- **Popup:** URL được ghi lại và popup bị đóng; frontier không thăm lại URL đó.
- **iframe khác tiến trình (OOPIF)** không có trong cây DOM của tab. Link bên trong nó chỉ được biết qua JS của nó trong store.

## 9. Race ở cuối run (từ GĐ4.2), đã sửa

Bench lại gặp REQCHECK, lần này ở `angular-ngsw-default`: một `/api/ping` gửi đi sau khi capture dừng. Lần đầu lỗi này được ghi nhận là ở `flows-app`, trong `gd4-static-endpoints-design.md` mục 8.

**Cách sửa:** với tab của chính tool (không áp dụng cho attach và watch), trang được đóng băng bằng `Page.setWebLifecycleState frozen` trước `Drain` và trước khi dừng capture. Request đang bay vẫn hoàn tất và được ghi lại; timer của trang không khởi động request mới nữa.

**Bẫy:** trang đã đóng băng thì không trả lời `CacheStorage.requestCacheNames`. Lần thử đầu đóng băng trước `SweepCaches` làm mỗi run chậm thêm 10 giây, nên giờ đóng băng phải đặt **sau** `SweepCaches`.

**Kiểm tra trên trang `/poll`** (ping mỗi 300 ms): sau khi đóng băng, server không nhận thêm ping nào, và run kết thúc trong cùng giây đó. Bench chạy lại toàn bộ: mọi app đều đạt, không còn dòng REQCHECK nào.
