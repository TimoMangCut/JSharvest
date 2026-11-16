# Lịch sử các giai đoạn và các đợt (GĐ1 → Đợt 28–30)

Chuyển **nguyên văn** từ CLAUDE.md ngày 2026-11-15 (plan-28-exec P0.3), không sửa chữ nào. Đây là bản ghi: các bất biến còn hiệu lực đã rút lên mục "Bất biến" của CLAUDE.md; khi mâu thuẫn, CLAUDE.md và đặc tả hiện hành thắng. Đợt mới ghi nối vào cuối file này.

## Lộ trình

1. Lõi CDP chung (launch + attach) — **xong 2026-11-02**: `jsharvest crawl -u URL` (1 trang), dedupe SHA256, index tích luỹ qua nhiều lần chạy, SIGINT/SIGTERM lưu kết quả dở. Còn thiếu: JS trong Worker/Service Worker (cần `Target.setAutoAttach`), inline script, chuẩn hoá URL, crawl nhiều trang.
**Kế hoạch hiện hành: `docs/review-assessment-2026-11-02.md` mục 7.3; GĐ1 XONG (mục 8); GĐ2 XONG: 53/56, `docs/gd2-design.md` mục 6 (kể cả các mục để sau); GĐ3 phần testbed bên ngoài XONG: `docs/gd3-external-results.md` (target thật chờ danh sách domain). **GĐ4 bản 2 (2026-11-03): `docs/gd4-plan.md`.** Mục tiêu cuối theo người giao việc: **traffic gom theo tính năng (flows) để fuzz**, xuất JSONL; thu thập JS là phần hỗ trợ. Đã xong 4.0 `-urls`, 4.1 guard (`internal/guard`, `-guard auto|on|off`, không bao giờ fail, `Clear-Site-Data` chỉ phát hiện được, thứ tự dừng ở `engine.closeBrowser`), 4.2 recorder (`internal/traffic`, `capture/record.go`, `-record api|all|off`, `-record-body`, `-redact`; worker được tạm dừng khi khởi động để không lọt request đầu tiên; giới hạn đã biết: request đầu của service worker và iframe khác site; `docs/gd4-recorder-design.md`). Sửa bug từ đánh giá độc lập bản cập nhật (`docs/review-assessment-2026-11-03.md`): guard lọt hết khi chạy `-urls -attach` (đã sửa bằng `Guard.AddTab`; kiểm tra bằng `testbed/attach-guard.sh`), phát hiện Clear-Site-Data/WebSocket chuyển sang `capture` (mọi session). 4.3 XONG: `jsharvest watch -attach … (-tab RE | -open URL) -guard on|off` ghi `flows.jsonl`. Request được gán vào hành động theo chuỗi nhân quả (tagger bọc handler và timer bằng `console.createTask`, xem `internal/capture/actions.go`), sau đó mới dùng cửa sổ thời gian. Package `internal/flow` là hàm thuần. Gate: `testbed/flows-gate.sh` (28/28 ở cả nhịp thường và nhịp nhanh; bản chỉ dùng cửa sổ thời gian phải trượt). **Bản 2.1:** AI điều khiển Chrome là việc của MCP (chrome-devtools-mcp, Playwright MCP); jsharvest không làm lại, chỉ ghi, gán, guard và xuất, chạy chung một Chrome với AI. Đã bỏ `-explore-llm`. 4.3c XONG (`docs/gd4-guard-sw-design.md`). `Fetch` cấp browser chỉ chặn loader tạo **sau** khi bật, nên guard bật thêm `Fetch` trên session riêng của mọi target có sẵn lúc `Start`: tab đã tải, iframe và worker của tab, service worker và shared worker trong scope. Gắn thất bại thì dừng lần chạy. `otherTab` có tác dụng thật, không được bỏ. 4.3d XONG (`docs/gd4-mcp-design.md`): `jsharvest mcp -o OUT` là MCP server stdio chỉ đọc (SDK `modelcontextprotocol/go-sdk`), gồm 7 tool: `status`, `last_action` (theo con trỏ, chờ ổn định, có `late`), `list_flows`, `get_flow`, `get_request`, `blocked`, `endpoints`. Mặc định che giá trị nhạy cảm; `-reveal` để xem nguyên bản. Nguồn dữ liệu: `watch` ghi `flows.partial.jsonl` mỗi giây khi có thay đổi, và `watch.json` (`updated`, `last_event`, pid). Package `internal/results` đọc output, `internal/mcpserver` là server. Gate: `MCP=1 [GUARD=on] testbed/flows-check.sh` (đã có trong `flows-gate.sh`). Agent thật: `testbed/agent-demo.sh`. 4.3b XONG (`docs/gd4-static-endpoints-design.md`):
- `internal/jsapi` là extractor hàm thuần trên `tdewolff/parse/v2/js`, không dùng CGo. Nhận diện theo hình dạng lời gọi vì sau khi minify không còn tên thư viện. Giải hằng theo scope: tham chiếu trong scope lồng có `Link` trỏ về `Var` đã khai báo; `DotExpr.Y` là `LiteralExpr` dạng giá trị. Có 3 mức chắc chắn `sure`, `call`, `weak`. Khi đổi kết quả thì phải tăng `jsapi.Version`.
- `internal/endpoints` gồm cache `static/<sha>.json` và danh mục `endpoints.jsonl` (0600). Trạng thái là `static` (chỉ có trong code), `both` hoặc `observed`. Base của client được traffic xác nhận. Request loại `Other` chỉ được dùng để khớp với endpoint đã có.
- `crawl` và `watch` ghi danh mục khi kết thúc; `watch` phân tích nền mỗi tick. Lệnh CLI là `jsharvest endpoints -target HOST`. MCP `endpoints` có tham số `status`.
- Resolver hiểu thêm runtime webpack không có bảng chunk (`webpackPlain`).
- Gate: `testbed/endpoints-check.sh` (`crawl` → `watch` + MCP → `both`). `flows-check.sh` kiểm tra mọi endpoint quan sát được đều có trong code.
- Đợt 15 (mục 9 của thiết kế 4.3b):
  - `eval` trả về tối đa 16 giá trị (`?:`, `obj[key động]`, biến gán nhiều lần theo chuỗi `chains`: `+=`, tự gán, builder; hai nhánh if/`?:` là anh em).
  - `.replace`, `this.<prop>` (gồm `data()`), base động lấy từ chuỗi gốc API.
  - `intel.json` (header cứng của client, cloud URL; 0600; log chỉ in tên).
  - `frontier.Vendor` bỏ route/path của bundle thư viện.
  - Kiểm nhiễu: `JSAPI_STATS=list go test -run TestStats ./internal/jsapi`, so với worktree ở HEAD.

4.4 XONG (`docs/gd4-frontier-design.md`):
- `crawl -u URL -depth N` bật frontier (mặc định `-depth 0` là một trang, để bench giữ ý nghĩa cũ). Các cờ đi kèm: `-max-pages`, `-page-rate`, `-page-dwell`.
- `internal/frontier` là hàm thuần: DOM qua `DOM.getDocument(pierce)` cộng `getOuterHTML` (vì cây DOM không có `templateContent`), form, header, robots, sitemap, text, `jsapi.paths`. Hàng đợi BFS ưu tiên theo nguồn.
- Chỉ đi theo GET. URL của POST, API, file tĩnh và URL phá huỷ chỉ được ghi vào `pages.jsonl` kèm `reason`. Luật phá huỷ dùng chung với guard, `-guard-allow` có hiệu lực cho cả hai.
- `engine/frontier.go` chạy một tab, một capture. `Capture.TakeMainDocuments` giữ header của trang tự chuyển đi.
- Gate: `testbed/frontier-check.sh` (mọi commit có đụng frontier); `testbed/external/run.sh` (Crawlground và crawl-maze qua Docker, khoảng 12 phút, không chạy mỗi commit).

4.5 XONG (`docs/gd4-session-design.md`):
- `jsharvest login -u URL -role R` có 3 chế độ: có giao diện (nhấn Enter khi xong), `-steps` (kịch bản JSON, `${ENV}` cho bí mật), `-attach`.
  - Kết quả ghi vào `<profiles>/<host>/<role>/jsharvest-session.json` (0600): cookie, storage theo origin, dấu hiệu (cookie mới, `check_url`), đường dẫn kịch bản.
- `crawl -role R` tự dùng session đó.
  - Bắt đầu: xoá service worker, CacheStorage và HTTP cache, giữ cookie và localStorage. Gọi `Storage.clearDataForOrigin` ở cấp browser sẽ lỗi `-32603`; phải gọi qua tab.
  - Sau đó nạp cookie bằng `Storage.setCookies`, và storage bằng script chạy trước trang (chỉ điền key còn thiếu).
- `engine/session.go` (keeper) kiểm tra sau mỗi trang: `Clear-Site-Data`, cookie dấu hiệu, trang login (trừ khi chủ động đi tới), 401/403.
  - Khi mất session: nạp lại cookie, kiểm tra lại (gồm `check-url` với `cache: no-store`); nếu chưa được thì chạy lại kịch bản, guard cho phép ghi đúng tab đó (`Guard.AllowWrites`).
  - Thất bại thì dừng frontier với mã thoát 4 (`ErrSessionLost`).
- Testbed server có session thật (`/api/me`, `/members/*`, `/account/wipe`, `/account/expire`).
- Gate: `testbed/session-check.sh`.

4.6 XONG (`docs/gd4-explore-design.md`, gồm đánh giá độc lập ở mục 12):
- `crawl -explore` (luôn chạy qua frontier, kể cả `-depth 0`; buộc bật guard và recorder): trên mỗi trang, explore click, gõ, chọn, hover, cuộn và submit bằng input thật của CDP (`isTrusted`). Mỗi thao tác là một hành động trong `flows.jsonl`. Các cờ: `-explore-actions` (50), `-explore-time` (2 phút mỗi trang), `-explore-total` (30 phút), `-explore-wait` (800 ms).
- `internal/explore` là hàm thuần trên `DOMSnapshot.captureSnapshot` cộng `DOMDebugger.getEventListeners(depth=-1, pierce)`. **Không dùng accessibility tree** (520–650 ms mỗi lần đọc). Chữ ký (`Sig`, chữ số thành `#`, ngữ cảnh là form hoặc id gần nhất, không phải đường dẫn trang) dùng cho cả run. Khoá nguyên văn `Raw` dùng cho độ mới, việc gõ và wizard.
- `engine/explore.go` cùng `explorelib.go` (JS chạy trong isolated world):
  - **khoá điều hướng** `Guard.HoldNavigations`: trả 204 cho main frame và cho popup có opener là tab; URL được giao cho frontier với `how: explore`;
  - đóng popup sau mỗi thao tác; trả lời mọi hộp thoại cho cả crawl;
  - với `-role`: tạm nhả khoá quanh `keeper.recover`.
- Luật guard khi `Rules.Explore`: DELETE và mutation GraphQL có tên phá huỷ luôn bị giữ (kể cả khi có `-allow-write`); GET từ script có động từ hành động trong path bị giữ với lý do `explore-verb`.
- Gate: `testbed/explore-check.sh` (`explore-app` 56 ca, `flows-app`, webpack không resolver, `edge-cases`, `-allow-write`, `session-app` với `-role`); `EXTRA=-explore testbed/external/run.sh` (Crawlground ≥ 55).

4.7 XONG (`docs/gd4-roles-design.md`; mục 8 là đánh giá độc lập, có hiệu lực cao hơn mục 2–4):
- `jsharvest diff -target HOST [-roles anon,user,admin] [-all] [-reveal]` chỉ đọc output, không gửi request nào. Kết quả ghi vào `<out>/<host>/diff.json` và `diff.md` (quyền 0600).
- `internal/roles` so 4 tầng: endpoint, tính năng, trang, script.
  - Mỗi mục có ma trận trạng thái theo role: `absent`, `unknown`, `code`, `denied`, `redirected`, `held`, `used`.
  - Lớp tính theo role thấp nhất dùng được mục đó và role **ngay dưới** nó: `client_gated`, `denied_below`, `higher_only`/`server_gated`, `not_covered`, `lower_ok`, `inconsistent`, `shape_differs`, `content_differs`, `unreached`.
- Endpoint được dựng từ **traffic của mọi role gộp lại**, qua cùng `flow.Templates`. Khoá có thêm operation GraphQL hoặc tham số phân biệt (`action=`…). Endpoint chỉ có trong code được ghép một-một bằng khớp template; template chung (ít hơn 2 đoạn cố định) không dùng để ghép.
- **Outcome `ok` của recorder là mọi response, kể cả 401/403.** Trạng thái phải lấy từ mã HTTP: `results.Req.Status`, và `observed.statuses` mới thêm vào `endpoints.jsonl`.
- `run.json` có thêm `config` và `scope`. `diff` cảnh báo khi các role không được crawl tương đương nhau, và khi file có hash trong tên khác nhau giữa các role (có thể đã deploy giữa các lần crawl).
- Gate: `testbed/roles-check.sh` (fixture `role-app`, `roles.truth.json`, `testbed rolescore`).

4.8 XONG (`docs/gd4-export-design.md`; mục 9 là đánh giá độc lập, có hiệu lực cao hơn mục 1–8):
- `jsharvest export -target HOST [-role R] [-run ID|all] [-dest DIR] [-scope] [-third-party] [-redact]` chỉ đọc output. Kết quả ghi vào `<out>/<host>/<role>/export/` (0700/0600; chỉ thay thư mục có `manifest.json` của chính nó):
  - `flows/<action>-<kind>-<endpoint>/` (file `.http` theo thứ tự, `.held.http` cho request bị guard giữ, `flow.har`, `flow.json` có `depends_on` và `prerequisites`);
  - `endpoints/` (một bản đại diện cho mỗi endpoint), `ffuf/` và `ffuf-destructive/` (`FUZZ` ở đúng một chỗ, không có `Content-Length`);
  - `params.jsonl` (`in_js` theo vị trí, `derived_from` + `refresh`, tham số chỉ có trong code `observed:false`; cookie gộp theo host `* host`), `all.har`, `manifest.json`, `README.txt`.
- File thô là HTTP/1.1 CRLF: `Host` đứng đầu, bỏ `Accept-Encoding` (ffuf không giải nén zstd), tính lại `Content-Length`, dòng request lấy từ chuỗi URL gốc (không dùng `RequestURI()`). Mặc định không đánh dấu, vì `FUZZ` của ffuf và `*` của sqlmap hại nhau.
- **Request bị guard giữ, request của worker và request trả từ cache chỉ có header tạm** (không có Cookie): recorder ghi `headers_provisional`, export mượn Cookie của request thật gần nhất tới cùng host (`cookie_from`) và thêm Origin.
- Khoá endpoint gồm `flow.Operation` (GraphQL/RPC), đoạn path lấy từ response trước, và `{}` của catalog.
- Gate: `testbed/export-check.sh` (flows-app hai lần, guard tắt và bật; `bin/testbed exportcheck`, replay tới testbed). Chưa chạy ffuf và sqlmap thật (cần người dùng cho phép).

**GĐ5.1 XONG** (`docs/gd5-replay-design.md`; mục 8 là đánh giá độc lập, có hiệu lực cao hơn mục 1–7). **Hai lệnh đầu tiên tự gửi request**, chỉ dùng trên target được phép:
- `jsharvest authz -target HOST` lấy các nghi vấn trong `diff.json`:
  - mẫu lấy từ role `native`, hoặc role cao nhất có dùng;
  - với mỗi role thấp hơn: đổi danh tính (cookie từ bản chụp phiên; Authorization và header credential từ traffic), làm mới **chỉ credential** (token CSRF lấy từ bước nguồn chạy dưới phiên của role thấp), **gửi bản thử trước**, rồi gửi đối chứng hai lần để biết trường nào thay đổi theo lần gọi;
  - kết luận: `bypass`, `unauthenticated`, `likely`, `needs-review`, `enforced`, `unclear`, `skipped` (`replay.Judge`);
  - kết quả ghi vào `authz/` (`authz.json`, `authz.md`, `sent.jsonl`, `trials/`), quyền 0600.
- `jsharvest replay -flow ACTION` gửi lại một cụm cùng các bước tiên quyết, lấy giá trị mới (`-keep-ids` để chỉ làm mới credential; `-as` để chạy bằng role khác).
- **An toàn** (`replay.Policy`, chặt hơn guard):
  - chỉ đọc theo mặc định; `-allow-write` cho request ghi; `-allow-destructive` chỉ dành cho `replay`;
  - logout, luồng login và endpoint có `Clear-Site-Data` thì không bao giờ gửi;
  - chỉ tới đúng các host của mẫu; gắn IP khi kết nối (chống DNS rebinding);
  - `-rate 2`, `-max 300`; dừng khi gặp `Clear-Site-Data` hoặc cookie danh tính bị xoá; 5 lỗi mạng liên tiếp chỉ làm bỏ host đó (Đợt 25I). Khi CDN/WAF chặn thì xử lý theo `-on-block` (Đợt 25H, mục 27 của `docs/gd6-waf-design.md`): 429/1015 thì chờ rồi hỏi lại; bị chặn thì gửi một request đối chứng và chỉ bỏ host đó;
  - `-dry-run`, `-proxy`.
- **Credential không làm mới được thì bị gỡ, không bao giờ gửi giá trị của role cao** (gate từng bắt được token CSRF của admin trong bản thử của anon). Phiên chết (kiểm bằng request "sống" lấy từ traffic, không dùng `check_url`) dẫn tới `unclear`, không bao giờ thành `enforced`.
- Gate: `testbed/replay-check.sh` (fixture `authz-app`, `authz.truth.json`, `bin/testbed authzscore`; flows-app với `TESTBED_CSRF_TTL`).
- Cùng đợt đã sửa lỗ hổng guard từ 4.6: `?action=purge` tới server. Chi tiết ở `docs/gd4-explore-design.md` mục 15; trang `/account/wipe` của session-app đổi tên thành `/account/privacy`.

**GĐ5.2 XONG** (`docs/gd5-container-design.md`; mục 6 là đánh giá độc lập):
- Gồm `Dockerfile`, `docker/entrypoint.sh`, `docker-compose.yml`.
- **Chrome for Testing** ghim phiên bản và SHA256 (kho `.deb` của Google chỉ giữ bản hiện hành); base image ghim theo digest; chạy bằng uid 1000 (`--user` để đổi); `tini` không có `-g`.
- Entrypoint:
  - tự bật sandbox của Chrome khi container tạo được user namespace (`seccomp=unconfined`, compose làm sẵn), nếu không thì `--no-sandbox` kèm cảnh báo;
  - `login` bằng tay dùng Xvfb (có xauth, `-nolisten local`), x11vnc (chỉ loopback), noVNC (cổng 6080; chỉ `127.0.0.1` khi dùng mạng của host).
- `login` khi stdin đóng sẽ chờ đóng tab, không bao giờ lưu phiên trống.
- **Chrome chạy trong nhóm tiến trình riêng** (`browser/proc_linux.go`), nên Ctrl-C chỉ tới jsharvest. **Thư mục output là 0700.**
- Gate: `testbed/docker-check.sh` (`NO_BUILD=1` để dùng image có sẵn). Kiểm bằng ffuf và sqlmap thật: `testbed/export-tools.sh` (người dùng tự chạy).

**GĐ5.3 XONG** (`docs/gd5-archive-design.md`; mục 7 là đánh giá độc lập):
- `jsharvest archive -target HOST` liệt kê Wayback (CDX không filter, phân trang `resumeKey`, đọc theo luồng), OTX và Common Crawl (chỉ liệt kê), rồi tải JS cũ.
  - Tải: kiểm trên server hiện tại trước, qua `replay.Sender`, chỉ tới các host crawl đã tới, không bao giờ gửi URL mang credential. Sau đó tải `id_` với `Accept-Encoding: identity` (SHA-1 của byte thô khớp digest của CDX, đã kiểm trên Wayback thật).
  - Kết quả ghi vào `<out>/<host>/archive/` (store riêng; `archive` là tên role dành riêng): `historical.jsonl` (`historical`, `version_changed`, `low`); endpoint có trong JS hôm nay thì không bị coi là lịch sử.
  - Có checkpoint (`archive.json`, `done.log`) để chạy tiếp; mã thoát 3 khi archive chặn.
  - Biến môi trường cho gate: `JSHARVEST_WAYBACK_URL`, `JSHARVEST_OTX_URL`, `JSHARVEST_CC_INDEX_URL`, `JSHARVEST_ARCHIVE_SCALE`.
- Store có `sources[]`, `alive`, `live_same`, `archive{}`; **mọi file output là 0600**.
- Đợt 16 (ARC-01 → ARC-10, mục 10 của thiết kế):
  - kiểm live hỏi lại qua https khi bị redirect sang đúng URL đó; host mục tiêu luôn được hỏi;
  - OTX chọn section `domain`, `hostname` hoặc `IPv4`;
  - nội dung chỉ còn revisit thì tải theo revisit;
  - một nguồn lỗi không làm dừng các nguồn khác (`ErrUnavailable`, liệt kê tiếp ở lần sau);
  - `HistLine.Bases`; version thành `v*`; `pathRe` nhận path tương đối ngay sau dấu nháy.
  - `archivecheck` đo precision/recall trên cả dòng (script so theo sha256).
- Đợt 17 (MAX-01 → MAX-07; mục 11 của thiết kế 5.3 và của `docs/gd6-waf-design.md`):
  - archive liệt kê **song song** 4 nguồn mặc định `wayback,otx,commoncrawl,urlscan` (urlscan chỉ tìm, không gửi URL đi quét);
  - Common Crawl thử 3 lần, mỗi collection độc lập, đọc WARC theo range khi Wayback không có (`JSHARVEST_CC_DATA_URL`);
  - archive đọc `.js.map` và manifest cũ; `-max-html` đếm trang đọc được thật;
  - `httpcrawl` chờ 429 hoặc `Retry-After` ≤ 15 s; 3 trang challenge liên tiếp mới dừng; `-resolve-max` không dừng việc thăm trang;
  - `-sourcemap-guess` mặc định bật (không đoán cho bundle thư viện); engine CDP đọc source map qua resolver.
  - Gate dùng archive giả phải đặt cả `JSHARVEST_CC_DATA_URL` và `JSHARVEST_URLSCAN_URL`.
- Gate: `testbed/archive-check.sh` (archive giả `/fake/*` trong testbed, fixture `archive-app`); `LIVE_ARCHIVE=1` để thử Wayback thật.

**GĐ5.4 XONG** (`docs/gd5-monitor-design.md`; mục 7 là đánh giá độc lập):
- `jsharvest monitor -target HOST` chụp các run mới kể từ snapshot trước (chỉ run `launch` hoặc `attach` thoát 0 và có `scripts`; không lấy `watch`), rồi so với mốc của từng role.
- **Snapshot chỉ lưu run ID**; nội dung được dựng lại từ `js/` và `requests.jsonl` bằng code hiện tại.
- **Mỗi run ghi `scripts:[sha]`** (`store.TakeTouched`) vì index tích luỹ không cho biết script của từng run.
- Khoá endpoint qua `ByShape`, placeholder thành `{}`, so khớp bằng `archive.SameEndpoint`.
- "Mới" là không có trong 3 snapshot so được gần nhất; "mất" cần bằng chứng (script vẫn còn mà không gọi nữa); không so được (config khác, tập URL bắt đầu khác, chạm giới hạn, bị chặn, phiên bị mất) thì mọi thứ "mất" chỉ là info và snapshot đó không thành mốc.
- Webhook: URL đọc từ env hoặc file, chỉ https (trừ loopback), không theo redirect, lỗi không lộ URL, mặc định chỉ gửi số lượng, gửi thất bại thì giữ lại cho lần sau. Mã thoát 5 với `-fail-on`.
- Gate: `testbed/monitor-check.sh` (fixture `monitor-app`, `TESTBED_DIST=dist-v2`; server có `/fake-webhook` với `TESTBED_WEBHOOK_LOG`).

**Song song theo cờ (`docs/gd5-parallel-design.md`; mục 5 là đánh giá độc lập):** mặc định vẫn tuần tự, người dùng tự bật.
- **A XONG:** `authz -concurrency N`; `-rate` vẫn là trần chung. Trong một mục vẫn giữ thứ tự (bản thử rồi đối chứng). Kiểm phiên theo role là single-flight. `downgrade` chạy một lượt cuối theo thời điểm (`Trial.at` so với `goodAt`). Role có cookie bị đổi, hoặc request cần credential mới, thì chạy lần lượt. Gate: B2 và B3 trong `replay-check.sh`.
- **B XONG:** `crawl -urls F -tabs N`; mỗi URL có tab và browser context riêng (chép cookie của profile; với `-role` thì keeper nạp vào context đó).
  - Guard dùng chung; bản ghi nhận theo tab: `Guard.TakeFor(claim)` + `Capture.Owns(networkID, frame, opener)`; phần không ai nhận được lấy sau khi guard yên và ghi vào `blocked.jsonl` (`unclaimed_held`).
  - Thư mục output dùng chung qua `engine/shared.go` (registry store, `dir.mu`, ghi tạm rồi rename). Script của từng run đếm qua `Store.Put`. Run ID có hậu tố khi trùng.
  - Sửa kèm: `-urls -role` trước đây bỏ qua phiên đã lưu (giờ mỗi host dùng phiên của nó, `-guard auto` bật guard); request bị giữ lúc capture dừng từng bị ghi hai lần.
  - Gate: `testbed/parallel-check.sh` (khi sửa `engine/batch.go`, `engine/shared.go`, `Guard.TakeFor`/`Capture.Owns`); `go test -tags chrome ./internal/guard/` kiểm guard trên context mới.
- **C (frontier `-tabs N`, mục 8 của thiết kế, review ở đánh giá độc lập Đợt 6–8):**
  - C1: `flow.Build` theo làn (tab), NEW-C1-01; sự kiện lồng trong 2 ms giờ thực thì cùng cử chỉ.
  - C2: `runState` (dùng chung) / `engine` (tab); `finishTab` + `finishRun(tabs)`; `warn`/`storeError` có `recMu`.
  - C3: `crawl -depth D -tabs N`: BFS đồng bộ theo tầng; kết quả của trang áp vào hàng đợi lúc `commit` theo thứ tự lấy trang (giống hệt `-tabs 1`); script đọc theo tab sở hữu; tab 2..N không gắn SW/shared worker; focus emulation. Gate `testbed/frontier-tabs-check.sh` (khi sửa `engine/frontier.go` hoặc phần nhiều tab).
  - C4: một keeper cho mọi tab (`epoch`, `wait()` trong lúc khôi phục, script storage cho mọi tab, `check`/`recover` nhận tab gọi). Thấy mất phiên sau khi tab khác đã khôi phục thì chỉ kiểm `alive`. Trang mất phiên lần đầu (kể cả nạn nhân vì `epoch` đổi) được thăm lại **một mình** (`solo`).
  - C5: `-explore -tabs N`: explorer theo tab (thống kê gộp ở cuối), `exploreShared` (chữ ký giữ chỗ trước khi thao tác, `-explore-total` theo giờ thực của run, thư mục upload); `Guard.TakeNavigations(frame)` theo frame giữ (popup theo opener); `epoch` đổi giữa thao tác thì tải lại trang; `BringToFront` chỉ khi một tab.
  - C6 XONG: `testbed/external/run.sh` với `-tabs 3` cho điểm giống hệt `-tabs 1`. Crawlground 56/59 trong 94 s (một tab 208 s); có explore 200 s (một tab 507 s); crawl-maze 76/84, 79/84, js 20/20, 0 request ghi. Số liệu ở mục 8.20.
- **Song song A–B–C XONG.**
  - Resolver: `-resolve-max`, bộ đếm và trạng thái dừng tính cho cả run (NEW-C3-02; trước đây tính theo trang).

**Đợt 13 (đánh giá độc lập, D1–D5) XONG** (`docs/gd6-waf-design.md`):
- **`crawl -engine auto` (mặc định) = HTTP cho anon**; engine HTTP mặc định `-depth 3` (khi không truyền `-depth`/`-urls`) và `-archive` (crawl xong chạy `archive` với cả wayback, otx và commoncrawl, cũng là mặc định của lệnh `archive`; `-archive=false` để tắt; gate dùng engine HTTP phải đặt cờ này hoặc archive giả) — mục 10 của `docs/gd6-waf-design.md`; `cdp` khi có `-role` khác anon, `-profile`/phiên đã lưu, `-attach`, `-explore`, `-headful` (người dùng chốt 2026-11-08). Gate cũ đặt `JSHARVEST_ENGINE=cdp`; gate mới về Chrome cũng phải đặt.
- `internal/httpcrawl` + `engine.RunHTTP` (`mode: "http"`, `config.engine: "http"`): `htmlscan` (script, modulepreload, import map, inline, `__NEXT_DATA__`), thăm dò robots/sitemap/asset-manifest/ngsw/.vite/sw, `resolve.Static` đệ quy, `-http-rate`, UA Chrome desktop, không giả TLS. Request thăm dò và map: loại `Other` + tag `jsharvest`. Trang đầu là challenge → thoát 3 + `-archive-fallback` (gọi `archiveRun`, gửi tới Wayback/OTX thật).
- Challenge **bị bỏ ở `capture.emit`** (không vào store/resolver/catalog), không đọc source khi URL/initiator là challenge; `detect.IsChallengeScript`, `InfraPath` (`/cdn-cgi/`), `Quarantined` (đọc output cũ). Recorder gắn tag `challenge`; endpoints/flows/roles/export bỏ qua.
- Guard cho `/cdn-cgi/` qua (`cdn-infra`) trước luật phá huỷ, **trừ `/cdn-cgi/access/`** (logout của Cloudflare Access).
- `archive` đọc trang `text/html` cũ (`-max-html` 10, `/` trước), bỏ trang challenge đã lưu, script do trang chỉ ra → live trước rồi memento, `resolve.Static` đệ quy trên body tải được.
- Source map (engine HTTP): `internal/sourcemap`, nguồn của site → store kind `source` tag `sourcemap`; endpoints dùng `jsapi.ExtractLoose` khi parse lỗi (TS/JSX). Engine CDP chưa đọc map.
- Chrome: `--disable-blink-features=AutomationControlled`, UA bỏ `HeadlessChrome` + Sec-CH-UA (`browser.UAOf`, capture áp cho mọi session); `login` lưu `user_agent`, `crawl -role` dùng lại; `-challenge-wait` 6 s.
- `diff`: role mà mọi run là `http` thì không bị cảnh báo `-no-debugger`/`explore`/`resolve` so với role Chrome; thay vào đó có một ghi chú rằng `client_gated` của nó là do không gửi gì (Đợt 14, mục 9).
- Đợt 18 (target-c.example, mục 12 của `docs/gd6-waf-design.md`):
  - `-escalate` (mặc định, chỉ với `-engine auto`): trang bị challenge mà engine HTTP không qua được thì chuyển sang Chrome, một lần chạy cho mỗi host.
    - Dùng `engine.Escalate` + `Config.OutHost`/`PageScope`/`Seeds`; tối đa 5 host.
    - `run.json` có `escalated`; host bị challenge 2 lần mà chưa trang nào qua thì không hỏi tiếp (`challenged-host`).
  - Resolver: `new URL(`…`, ``+import.meta.url)` và `new URL(x, location)`; phương thức yếu nhất `js-string` (`./x.js`, `/x.js`, không lấy `node_modules`).
  - `sourcemap.Guesses`: origin trượt 10 lần mà chưa trúng thì ngừng đoán map.
  - jsapi v8 bỏ qua `instancePath`/`schemaPath` (Ajv).
  - Frontier xếp vào `template` các path có `:x`, `$x`, `[x]`, `*`, `(g)`, `...`, `__root__` hoặc `node_modules`; bỏ ID route layout của TanStack.
  - `shellPrint` bỏ qua script challenge; chữ ký shell và cờ SPA tính theo từng origin (`http.spa_origins`).
  - Capture giữ script của document 403/429/503 sau WAF (`detect.Suspect`) cho tới khi đọc được title (`judge` trong `MainDocument`); "Attention Required!" không có `cf-mitigated`.
- Gate: `testbed/waf-check.sh` (9 phần, gồm 1b); `roles-check.sh` phần D (anon `-engine http`).
- Đợt 19 (CASE-19-01 → CASE-19-10, mục 13 của `docs/gd6-waf-design.md`):
  - jsapi v9:
    - summary qua nhiều tầng hàm bọc: nhiều tham số URL (`ST(a,b,…)`), `optsArg` (kể cả `{...t}`), `paramIn` cho URL;
    - helper dựng `RequestInit` (`bT("POST", data, extra)`, `initCall` gắn tham số qua `x.args`); `opts.isOpt` (khoá cấu hình không thành body);
    - `relAPIRe` cho 1–3 đoạn trước `/v1`; bỏ `cache.put`/store, route kiểu `R(path)({component})`;
    - `locate` khớp mọi mảnh của template theo thứ tự (`inOrder`, bám mảnh dài nhất);
    - `evalCall` giải hàm của app (không tham số, hoặc có ít nhất một đối số đã biết);
    - `isBaseName` (`VITE_*_API_BASE_URL`, `AUTH_API_URL`, `customerProfileBaseUrl`; loại login/app/cdn), giá trị mặc định của biến môi trường (`dT("VITE_…", "/x")`) là base, không phải endpoint;
    - giải config base64 (thuận và đảo ngược) và cặp JSON trong chuỗi (RSC); `Result.Keys` → `intel.json` `keys`;
    - tiền tố theo từng biến client (`clients.go`: `Z = wy("/api")` → `/api/...`; lời gọi factory không phải endpoint);
    - `ExtractOpenAPI` (yaml.v3), chỉ dùng cho script có tag `openapi`.
  - `endpoints.Build`: bases theo origin của script, `PreferInScope` (bỏ base tuyệt đối ngoài scope khi có base trong scope), `baseFor` cắt base trùng đầu path và xếp base tuyệt đối ngắn nhất trước. `SaveIntel(dir, inScope, redact)`.
  - httpcrawl: file đặc tả (`frontier.SpecFile`: `openapi|swagger|api-docs…` `.yaml/.json`) không bị `spa-route`; tài liệu OpenAPI tải được lưu với tag `openapi` (`http.openapi`). Frontier bỏ tên nội bộ của Next/Turbopack (`/_head`, `/_tree`, `/ROOT/`, `/_next/` không có file), `/a/b`, danh sách có `,`/`*`; `vendorRe` thêm `turbopack|webpack`.
  - archive: `samePath` cần ít nhất một đoạn có tên trùng, và phần đuôi sau `{}` không khớp vào placeholder; giải nén `zstd`/`br` (kể cả zstd không có header); live check mỗi URL một lần; memento của URL không có digest: 403 cũng là chưa lưu, tối đa 50 s; `-scope rdn` hỏi OTX và urlscan thêm tối đa 10 host khác mà crawl đã tới (`ExtraHosts`, `state.extra`).
  - resolve: `base + '/x.js'` với `var base = "./dir"` tính theo script; base không biết thì không đoán theo gốc origin.
  - replay `Sender.dial`: thử IPv4 trước rồi lần lượt các địa chỉ khác, kiểm DNS rebinding trên mọi địa chỉ.
  - `archive.CrawlHosts` tính cả host của các base trong scope có trong `intel.json` (để live check và `ExtraHosts`).
- Đợt 20 (COV-01 → COV-06, mục 14 của `docs/gd6-waf-design.md`), jsapi v10:
  - `helpers.go`: `summary` giữ lời gọi lá (fetch, `fetchLike`: `n = e.fetch`, `{fetchFn: i}`, `e.fetchImpl`; method của client thật `isClientObj`) hoặc lời gọi helper khác (`via`/`sub`). Tại nơi gọi, `readCall` gắn tham số (`bindParams`: `x.args` cho fields/options, `x.bind` cho URL) qua mọi tầng; URL là template thì giải theo đối số (`${o}/mcps/${s}/${e}`, `RE(e,t,"remove")`); tham số khác trong URL mà nhận object là query. GET/HEAD không có body (chuyển sang query). Hàm làm URL từ base (`r = e => base + e`) cho endpoint, không cho route.
  - `keys`: spread, `?:`, dấu phẩy, `.map(fn)`, lời gọi hàm của app (`returnedKeys`, kể cả biến cục bộ được gán thêm thuộc tính); hàm kiểm tra nhiều nhánh (>8 return) trả lại object nó nhận. `object()` đọc tham số đã gắn. Khoá `queries`. `URLSearchParams` + `.set/.append` (`qset`); helper chỉ trả query string được giải dù đối số không biết (`queryOnly`).
  - `evalCall`: ngân sách 300 lần cho mỗi biểu thức gốc, 50.000 cho mỗi script.
  - `modules.go`: `Exports` (`M.s(["name",0,fn],id)` → method/URL/body/base theo tham số) và `Imports` (`(0,H.name)(cfg.AUTH_API_URL, {...})`, `H = M.i(id)`); `Settings` (base theo tên setting). `endpoints.linkModules` nối chúng: body từ bên gọi, base theo tên setting (đúng một base).
  - `docs.go`: endpoint trong tài liệu (`kind: "doc"`: bảng Markdown, `METHOD /path`, `curl -X`), không thăm, không gắn base của origin.
  - `prefixesOf`: client trong `?:`. `locate`: mỗi nhánh giá trị dùng literal của chính nó (`litsOf`); URL của helper đọc theo thứ tự source.
  - Header client: `X-…`/`Authorization` qua `.set`, gán chỉ mục, thuộc tính object.
  - `endpoints.Build`: origin đã biết mà không có base thì không mượn base của origin khác; OpenAPI ưu tiên base có `/openapi`.
  - archive: endpoint có trong text của script hôm nay nhưng không có trong catalog thì giữ trong `historical.jsonl` với lớp `in_current_code` (trước đây bị bỏ).
- Đợt 21 (TRU-01 → TRU-05, mục 15 của `docs/gd6-waf-design.md`), jsapi v11:
  - `x.nests` đi qua biến, `?:`, `||`, nhóm. Hàm dựng query từ entry của object thì khoá của object là query (`queryParam`). `url(…)+query(…)` gắn query vào endpoint (`queryTail`).
  - `baseFor`: base mà path bắt đầu bằng nó, hoặc chung đoạn đầu kiểu gateway (`gatewaySeg`), thì chỉ còn origin đó. OpenAPI chỉ giữ base `…/openapi`.
  - `Factory` (hàm trả bảng method client) cùng `Export.Factory`; setting truyền qua export hoặc lời gọi cục bộ `a(cfg.X_URL)` áp cho mọi method (`linkModules`).
  - Khung helper chỉ tạo ở lời gọi trong thân helper, mà mọi nơi gọi đều làm URL đầy đủ hơn, thì bị bỏ (`frame`, `producers`/`inst`). Lời gọi tới hàm dựng client (`summary.nested`) không được tính.
  - `docs.go`: không có base placeholder, host ví dụ, version hay mã mẫu. `endpoints.mergeDocs` gộp dòng `doc` vào endpoint của code và gộp path viết tắt vào bản đầy đủ. Endpoint không method gộp vào bản có `{}` ở đầu.
  - `urlBuilder` chỉ nhận hàm mà URL của request gọi tới (`builderVisitor`), hoặc có base kiểu API.
  - `endpoints.Build` bỏ `navigation` ngoài scope hoặc không giống API (`jsapi.APILike`). `split` coi host `{}` là base chưa biết. Header có giá trị là số hoặc boolean thì bị bỏ.
- Đợt 21B (FIN-01 → FIN-06, mục 16 của `docs/gd6-waf-design.md`), jsapi v13:
  - `docs.go`:
    - đọc lệnh curl (`parseCurl`/`shellWords`; method suy ra khi không có `-X`; query và body lấy từ `-d` JSON, `-F`, `--data-urlencode`);
    - `export VAR=https://…` thành `Endpoint.Base` (bỏ host dev hoặc host ví dụ);
    - giữ query `?k=`;
    - khối code `fetch` được đọc qua `extract(…, nested)`;
    - host ví dụ thì bỏ hẳn.
  - `endpoints`: `docBases` là base của endpoint; lời gọi ví dụ gộp vào template (`instance`).
  - `resolve.Static`: URL `.js` tuyệt đối trong text (`js-url`; policy giữ host trong scope).
  - `keys`: `FormData`/`URLSearchParams` lấy khoá từ `.append`/`.set`, và đi qua mảng.
  - Lời gọi `X.method(…)` dùng hàm duy nhất cùng tên trong script (`methodOf`, camelCase, không phải global). `propKey` đọc tên method viết tắt.
  - Tiền tố client là path của origin trang (`ownPre`, `basedPre`) thì URL là URL đầy đủ (`Client: false`).
  - `archive.weak` thay `generic` khi xếp lớp `low`.
- Đợt 21C (FIN-21C, mục 17 của `docs/gd6-waf-design.md`), jsapi v14:
  - `methodOf`: trước tiên giải chuỗi thuộc tính qua hằng số (`memberValue`/`objectOf`, kể cả namespace `t({x: () => fn})`). Không giải được thì chỉ ghép theo tên khi có nhánh cha `X.P.name`, khớp số đối số (`takes`), và `P` giữ đúng object hoặc class chứa method (`holds`: `P: {…}`, `P: c` với `c` do hàm trả object đó tạo ra, kể cả qua `useMemo`, `new C`). Hai định nghĩa cùng thoả thì bỏ.
  - `$VAR` chưa `export` trong tài liệu: `Endpoint.Base = "$VAR"`; `Result.DocVars`; `endpoints.Build` giải theo các script cùng origin (chỉ khi có đúng một giá trị).
  - `noRoute`: bỏ curl có chú thích ngay phía trên nói route không tồn tại (không dựa vào "404").
  - `bindParams` gắn tham số destructure (`{baseUrl: e, body: n}`); `x.object` giới hạn 16 tầng (tham số trỏ qua lại nhau từng làm tràn stack).
  - Kiểm offline: `jsharvest endpoints -o output -target HOST` dựng lại catalog từ script có sẵn.
- Đợt 22A (QAL-01 → QAL-05, mục 18 của `docs/gd6-waf-design.md`), jsapi v15:
  - `this.x(…)`: method của object hoặc class bao quanh (`fnStack`, `ownerOf`), của component Vue (`methods`), hoặc định nghĩa duy nhất trong các khối `methods` của mixin; được truyền ít đối số hơn số tham số. `fetchLike` không coi method do app định nghĩa là fetch.
  - `fromCallers`/`destructFrom`: `e.apiBase` lấy từ nơi gọi (tối đa 4, phải có path cố định). `builderPath` ghép tiền tố `{}/api/v1` của hàm dựng URL. `calleeFn`/`givenFn` giải method và hàm do nơi gọi truyền vào trong `evalCall` (không tính vào `maxCallDepth`). SSE (`sseParam`, kind `sse`), AI SDK `prepareSendMessagesRequest` (kind `transport`).
  - `NoInheritBase`/`Collector` (Snowplow, GA → `third_party`, không base); `{}/…config….json` bị bỏ.
  - `ParamSpec` (`params.go`: `typeOf`, `keyInfo`, `pathNames`, `by-x/{}`; OpenAPI; tài liệu). `endpoints`: `params`, `origin`, `confidence` (`confirmed > spec > code > string > doc`), `canonicalMerge` (khoá = METHOD + host + path đầy đủ; bản đại diện có base dài nhất), `siblingBases`.
  - Tài liệu: `curl -H`, khối ```` ```http ```` (cả MDX theo chuỗi: `pendingBody`), `` `GET` / `POST /x` ``, tiền tố "dưới `{agentHub}/api/v1`", dấu `<auth-host>` giải bằng `Settings` (`settingFor`), bảng `prd` (`ProdOf`), bỏ route Next của khách (`clientRoute`).
- Đợt 22B (PIP-01 → PIP-04, CASE-22B-01 → CASE-22B-05, mục 19 của `docs/gd6-waf-design.md`):
  - Thư mục output và profile của host ở cổng không mặc định là `host_port` (`scope.TargetDir`; loopback giữ tên trần). `-target` nhận `x_3016`, `x:3016` hoặc URL (`scope.NormalizeTargetArg`/`TargetHost`). `archive` vẫn ghi theo hostname.
  - `internal/tlsutil`: `AIA.DialTLS` hoàn tất chuỗi chứng chỉ thiếu qua `caIssuers` (kiểm hostname theo host của request, không dial tới địa chỉ private). Dùng trong `httpcrawl` và `replay.Sender`. `crawl -insecure`. Seed không có response: cảnh báo `seed request failed`, thử Chrome một lần (`escalatable`), không chạy archive, mã thoát 1.
  - Resolver bỏ id module của bundle (`moduleID`). `run.json` có `page_requests`/`internal_requests`.
  - `intel.json` có `server_hints` và `security_notes` (`endpoints.Infra`, đọc thụ động từ `requests.jsonl`).
  - Explore đưa thư mục upload cho input `webkitdirectory`.
  - `EnrichFromArchive` (trong `Catalog`, nguồn `archive/endpoints.jsonl`, `enriched_from`). Trang JSON của `httpcrawl` được ghi là `Fetch`.
  - Thăm dò đặc tả `frontier.SpecPaths` trên seed origin và tối đa 5 API host, ở cả hai engine (`-probe`). `jsapi.ExtractOIDC`. OpenAPI không có `servers` lấy origin của tài liệu làm base. `canonHost`.
  - `crawl -spa-boot` (`engine.SPABoot`).
  - Gate 17: `testbed/pipeline-check.sh` (fixture `pipe-app`, `bin/testbed pipecheck`); chạy khi sửa `httpcrawl`, `engine/http.go`, `tlsutil`, `endpoints/infra.go|enrich.go` hoặc `scope.TargetDir`.
- Đợt 23-Offline (POL-22B, VER-01 → VER-04, mục 20 của `docs/gd6-waf-design.md`):
  - `internal/verify`: `Drafts` (URL, giá trị mẫu cho `{}`, body JSON lồng nhau, tier `ready`/`parameterized`/`incomplete`; base tương đối giải theo origin của script), `WriteDrafts` (`drafts/` + `index.json`; bỏ dòng `doc` nếu chưa được verify).
  - `Run`: canary theo gateway prefix, `Sig` (skeleton JSON), các verdict `verified_alive`/`resource_404`/`auth_wall_opaque`/`server_error`/`dead_or_fp`.
  - `jsharvest verify` (**gửi request**; chỉ đọc nếu không có `-allow-write`; request ghi được thăm dò bằng GET; `-dry-run` không gửi gì). `export -drafts [-include-docs]` (chạy cả khi không có traffic hay flow).
  - `NormalizeTargetArg("x:443")` cho thư mục `x`; `AIA.Incomplete` khoá theo `host:port`.
  - Gate 18: `testbed/verify-check.sh` (fixture `verify-app`, `bin/testbed verifycheck`); chạy khi sửa `internal/verify`, lệnh `verify` hoặc `export -drafts`.
  - 23B-Polish:
    - Candidate bị policy chặn thì thử candidate tiếp theo.
    - `Draft.SampleHeaders` không được gửi khi không có identity; `-role` lấy thêm header credential từ traffic.
    - `WriteDrafts` dùng URL đã sống (`AliveKeys` → URL).
- Đợt 24 & 24D–24E (`ENH-01` → `ENH-13`, `P0-1..6`, `P1-1..6`, mục 21 của `docs/gd6-waf-design.md`), jsapi v18:
  - Bảo toàn `Host` cross-origin trên dòng `both`/`static` (`ENH-01`); khoá fallback `Intel.Bases` chỉ cho dòng có `Observed` cũ (`P0-4`); nhận diện `{method, baseURL, endpoint}` và context-wrapper `fn(ctx, METHOD, PATH)` mà không sinh base giả từ path endpoint hay lời gọi sự kiện (`ENH-10`, `P0-1`); chỉ lan truyền gốc cổng API thật lên `{}` (`P0-5`).
  - `verify`: `Sig.MethodScoped` nhận cả `405` và `404` theo method của Express HTML / NestJS JSON → `write_unverified`, phân biệt rõ với JSON `404` đồng nhất (`ENH-02`, `P1-1`); canary cha 1 đoạn khi vượt `maxPrefixes` (`ENH-13`); mặc định bỏ qua chuỗi trần không method, có `-include-strings` thì chấm `client_route` trên SPA shell (`ENH-12`).
  - Giá trị mẫu từ traffic lọc qua `SampleValueOK` (chặn tham số nhạy cảm và `REDACTED_*`) + `RedactDrafts` cho `export -redact -drafts` (`ENH-03`, `P0-2`); `-page-scope auto|fqdn|rdn` và miễn `pageScope` cho redirect trang Seed đầu tiên của `httpcrawl` (`ENH-04a`, `P0-3`); nối ESM `import`/`export` đa chunk (`ENH-05`).
  - Explore xuyên lớp phủ `pointer-events:none`, bật `UserGesture:true` cho fallback click mở FileChooser, mồi DICOM `IM000001` và đếm `covered-for-good` vào `skipped` (`ENH-06`, `ENH-07`, `ENH-11`); thay tab treo an toàn đa luồng (`recycleTab` + `tabMu` + `listenCtx`) và tách timeout resolver `8s` TTFB / `25s` body kèm circuit-breaker 3 lỗi (`ENH-04b/c`, `P1-5`, `P1-6`).
  - Giải hằng `btoa` và giữ credential Basic gắn cứng trong khi lọc serializer tổng quát của Axios (`ENH-08`, `P1-2`); trích xuất `Endpoint.Auth` từ OpenAPI `security` (`ENH-09`, `P1-4`); giữ ghép đa host trong `roles` khi `Bases` hỗn hợp (`P1-3`).
  - Gate 19: `testbed/crosscheck-check.sh` (`bin/testbed crossserve` & `crosscheck`).
- Đợt 25 (`Round 25A` → `25C`: Kiến trúc tổng quát hoá TS/SFC & Liên kết module đa tầng, mục 22 của `docs/gd6-waf-design.md`), jsapi v20:
  - **Tiền xử lý TypeScript & SFC bảo toàn số dòng (`internal/jsapi/preprocess.go`, `ExtractSource`):** đường nhanh `Extract` giữ 0 chi phí trên `.js` hợp lệ; chỉ khi lỗi `js.Parse` (hoặc nguồn SFC `.vue`/`.svelte`) mới che vùng ngoài `<script>` bằng khoảng trắng (giữ nguyên mọi `'\n'` để khớp 100% số dòng gốc) và hạ cấp kiểu TS/TSX bằng `github.com/evanw/esbuild/pkg/api.Transform` (Go thuần, không CGo; hỗ trợ `@Injectable`, generics, `namespace`, `enum` IIFE) trước khi rơi về `ExtractLoose`.
  - **Tổng quát hoá `summary` nội cục (`helpers.go`, `jsapi.go`):** `paramIndex` nhận `*js.BindingObject`/`*js.BindingArray`; `paramOrigin` và `argStringAt` (`depth <= 8`) lần qua `x.destructFrom`, `*js.DotExpr`, gán thuộc tính cục bộ `o.data`/`o.params`, và tách template `${ctx.baseUrl}${endpoint}`; hỗ trợ nhánh ternary của tham số tuỳ chọn bị lược bỏ và khởi tạo HOF / hàm curried (`instantiateHOF`, `curriedHelper`).
  - **Một kiểu `jsapi.Export` thống nhất kèm chuỗi bắc cầu `Via` & `ReExport` (`modules.go`, `endpoints.go`):** mở rộng trực tiếp `Export` (`ParamURL`, `ParamMethod`, `Local`, `HasDynBase`, `Via *ExportVia`) cùng `ReExports` (`export * from`, `export { a as b } from`); `endpoints.linkModules` định tuyến trên 3 không gian (Bundler ID, HTTP ESM URL, SourceMap `#<sourcePath>` có giải `@/` và gói monorepo) bằng DFS có `visited` và trần cứng `depth <= 8`.
  - **Phân tách `source_only` cho endpoint bị tree-shake:** `Endpoint.SourceOnly` gắn `true` khi mọi nguồn tĩnh chỉ đến từ `.js.map` và không có `Observed`; `verify` và `export -drafts` mặc định bỏ qua `source_only` (mở bằng `-include-source-only`).
  - **Gate tự động Bất biến #9 & Gate 19 mở rộng:** `bin/testbed perfgate` (trong `testbed/endpoints-check.sh`) kiểm tự động 2.000 script (`.js`/`.ts`/`.vue`) dưới trần cứng `<= 15 s` và RSS đỉnh `<= 500 MB`; kịch bản 8 của `testbed/crosscheck-check.sh` kiểm trọn luồng 3-module `Via`, barrel `export *`, `.ts`/`.vue` sourcemap và `verify -include-source-only`.
- Đợt 25D (Hậu kiểm Precision, Provenance toạ độ `Import`, tối ưu RSS & kiểm định mù Held-Out + Live 5 domain, mục 23 của `docs/gd6-waf-design.md`), jsapi v21:
  - **Khoanh vùng provenance khi kế thừa base (`BaseKeys`) & hằng base liên module (`ExportedConsts`):** giải hằng URL xuất qua ES module (`https://api.n8n.io/api` → `third_party: true`); cắt nhánh rỗng giả của ternary đoạn path tuỳ chọn khi tham số đã được truyền (`x.supplied`); ghi đầy đủ `(Line, Col, Snippet)` cho `Import` (`code_line0 = 0` trên cả 5 target; `target-d.example` đạt `288/288` recall và `100%` dev precision, `FP: 9 -> 0`).
  - **Tối ưu bộ nhớ/tốc độ & `perfgate` `43,1 MB`:** chuyển thẳng `.ts`/`.tsx` và `<script lang="ts">` vào `transformTS`, nén bảng VLQ thành mảng phẳng `[]vlqSeg` (`12 byte`) không qua `json.Unmarshal`, giới hạn đồng thời `2` slot (`heavySem`) cho bundle `>= 512 KB`, và nâng corpus `perfgate` lên `43,1 MB`.
- Đợt 25E (Lối thoát & quan sát lỗi parse bundle, xoá `genericBaseNormWords` bằng đối sánh biểu thức base & chuẩn hoá `groundtruth_v3` / Held-Out, mục 24 của `docs/gd6-waf-design.md`), jsapi v22:
  - **Lối thoát AST `transformJSLower` + fallback `ExtractLoose` cho mọi bundle + `AnalyzeStats`:** khi `tdewolff/parse v2.8.20` (bản mới nhất trên `master`) vấp lỗi `parse: unexpected =>` trên `({ a: b = 1 } = { a: 1 }) => b`, `Extract`/`ExtractSource` hạ cấp hàm mũi tên JS bằng `esbuild` (`LoaderJS`, `Supported: {"arrow": false}`, giữ VLQ line map, `ASTLowered = true`) và `analyzeOne` áp dụng `ExtractLoose` cho cả bundle nếu vẫn lỗi (`LooseFallback = true`, `ParseError`); ghi `static_analysis` (`bundle_parse_errors`, `bundle_ast_lowered`, `source_parse_fallbacks`, `failed_bundles`) vào `run.json`, `slog.Warn`/`run.Warnings`, và `stderr` của `endpoints`.
  - **Xoá `genericBaseNormWords` / `hasPrimaryClientBaseKey`:** đối sánh trực tiếp biểu thức base tại nơi gọi (`BaseKeys`: `prop:<name>`, `exp:...`, `client:...`) với thuộc tính base tĩnh cùng origin (`settingsByProp`, gồm cả base tương đối `/...`) và biểu thức base của các request đã quan sát (`obsBaseByOriginKey`), chặn cả dương tính giả (`ctx.host` analytics) lẫn âm tính giả (`client.authServer`).
  - **Tách bạch `groundtruth_v3` (`dev`) & kiểm mù lại Keycloak (`heldout`):** trên `dev`, đạt `288/288` (`target-d.example`, `b_err=0, low=1`, `5,53 s`, `372,7 MB`), `30/30` (`:3016`), `7/7` (`target-b`), `60/60` (`target-a`), `28/28` (`target-c`); trên `heldout` Keycloak (`21` bundle `b_err=0, low=2` gồm `index-Cqtr7vCN.js` `4,19 MB` + `648` sourcemap, phân tích lạnh `1,77 s`, RSS `198,1 MB`), trích xuất được `{}/.well-known/openid-configuration` và `{}/account` nhưng Admin REST API vẫn là `0/415`, qua đó kiểm chứng thực nghiệm rằng nút thắt còn lại là chuỗi 3 lớp `class extends` (`BH -> za.#e -> UH.#r` + `URL.pathname`).
- Đợt 25F (Kiểm định tối đa công suất chỉ-đọc trên 5 domain & sửa tổng quát hoá 3 lỗi thực chiến của công cụ, mục 25 của `docs/gd6-waf-design.md`):
  - **`archive.Run` / `listCC` (`internal/archive/run.go`):** khởi tạo đầy đủ mọi trường `map` của `state` và `Summary` khi resume `archive.json` (và kiểm tra tách rời `cc.Next` / `cc.Listed`), xoá bỏ lỗi panic `assignment to entry in nil map` khi resume sau lượt Common Crawl trả `504` trên mọi collection.
  - **`archive.classifyCtx` / `compilePath` (`internal/archive/history.go`):** gọt tiền tố placeholder đầu path (`^(/?\{[^}]*\})+`) để tránh wildcard không neo `[^"'`\s]{1,80}?` ở đầu biểu thức chính quy trên các wrapper `{}/api/...`, lọc nhanh bằng `bytes.Contains` trên các mảnh cố định trước `re.Match` (giảm thời gian phân loại `target-c.example` từ `~335 s` xuống `< 10 ms`), và truyền `context.Context` xuyên suốt `r.history(ctx)` / `classifyCtx` để dừng ngay khi nhận `SIGINT`.
  - **`detect` Cloudflare `1xxx` (`internal/detect/detect.go`, `internal/archive/pages.go`):** nhận diện trang chặn IP/WAF/rate-limit `Error 1xxx` của Cloudflare (`Access denied | ... Cloudflare`, `used Cloudflare to restrict access`, `You are being rate limited`, `cloudflare-1xxx-errors`, `id="cf-error-details"`) mà không báo nhầm trang `403` của chính ứng dụng sau Cloudflare; gắn `cdn-infra` cho `performance.radar.cloudflare.com/` và thêm dấu hiệu inline của trang lỗi Cloudflare (`sparrow.cloudflare.com/api/v1/event`, `cf-footer-ip-reveal`, `window._cf_translation`) để cách ly hoàn toàn khỏi `store` và `endpoints.jsonl`.
- Đợt 25G (Dừng `replay.Sender` khi bị WAF chặn, luồng dữ liệu base tĩnh không `requests.jsonl` / không `isBaseName` & chuẩn hoá `groundtruth_v4`, mục 26 của `docs/gd6-waf-design.md`), jsapi v23:
  - **`replay.Sender` / `replay.Judge` / `verify.probe` (`internal/replay/send.go`, `compare.go`, `internal/verify/verify.go`, mục `G` của `testbed/replay-check.sh`):** gọi `detect.Check` (kèm `htmlscan.Scan` title + `64 KB` đầu body) để dừng ngay `verify`, `authz`, `replay` và `archive` live-check khi gặp trang chặn của nhà cung cấp WAF (như Cloudflare `Error 1006` `403` không có `cf-mitigated`) với `verified_alive = 0`, trong khi trang `403` JSON/HTML của chính ứng dụng sau `Server: cloudflare` vẫn tiếp tục bình thường.
  - **Giải base tĩnh không cần `requests.jsonl` và không dựa vào `isBaseName` (`internal/jsapi`, `internal/endpoints`):** bổ sung `Result.PropBases` (`settlePropBases` với `noMarkUsed`), bóc lớp reactive `.value` (`ref`/`computed`) + Pinia setup-store + `window.BASE_PATH` / `import.meta.env.BASE_URL`, tách `(base, path)` bằng `splitPair` không cần `isBaseName`, và gắn `third_party: true` khi mọi base giải ra đều ngoài scope (`allOutOfScopeBases`). Trên `target-d.example` (`n8n`) khi bỏ `requests.jsonl`, số dòng có `/rest` khôi phục từ `1` (`v22`) lên đủ **`295`** (`288/288` active GT, `FP = 0`, `7` route `templatesHost` giữ `bases: []`).
  - **Cho phép dấu nháy/khoảng trắng trong query RSQL (`looksLikePath` khi `lv >= call`) & tách bạch `groundtruth_v4` (`158` route `target-a`):** khôi phục đủ `15` route `v2` bị rơi ở `v3` do trần `60` cùng toàn bộ route literal/`.replace` không cắt trần và thêm `GET /api-gateway/charge-point/v1.0/transactions/admin/report-on-day` (`v22`: `157/158` -> `v23`: `158/158`).
- Đợt 25H (`-on-block`, mục 27 của `docs/gd6-waf-design.md`; thay cho cách dừng toàn cục của 25G):
  - **Mặc định là `host`.** `replay.ClassifyBlock` phân loại trang chặn thành `rate|challenge|client|signature|request` (đọc mã 1xxx của Cloudflare). Request bị chặn thì gửi **một request đối chứng** tới cùng host (request đọc đã từng được trả lời, nếu không có thì `GET /`). Request đối chứng cũng bị chặn thì chỉ bỏ host đó (`ErrHostBlocked`); hết mọi host thì run dừng.
  - Phản hồi `rate` cho request đọc: chờ `Retry-After` (tối đa 60 s) rồi hỏi lại, tối đa 3 lần; request ghi thì không hỏi lại.
  - `skip` chỉ đánh dấu; `stop` giữ hành vi cũ.
  - `verify` có thêm `waf_blocked`/`host_blocked`; `verify.json`, `authz.json` và `summary.json` của `replay` có thêm `hosts_blocked`. `authz` không còn tự dừng khi một trial bị chặn và không coi probe bị chặn là phiên chết. Kiểm live của `archive` bị chặn thì coi là "không biết".
  - Gate: mục G của `testbed/replay-check.sh` (`TESTBED_CF_BLOCK=1006|1006-after:N|1020:RE|1015:N`).
- Đợt 25I (mục 28 của `docs/gd6-waf-design.md`; nghiên cứu: `docs/research-2026-11-13-bot-transport.md`). Nguyên tắc: không tự khai báo là bot, tự động hoá như người dùng trình duyệt thật, không dùng Chrome cho mọi request, **giữ tốc độ quét**.
  - **N0:** tên script chèn vào trang lấy từ `internal/marker` (`Internal`, `Tagger`, `TaggerKey`; vẫn nhận ra tên cũ). Kiểm tra SPA và canary dùng `marker.Slug()`. `Sender` điền UA của trình duyệt (`SenderOptions.UserAgent`, `observedUA`), không bao giờ để rơi về `Go-http-client`. Không còn `--enable-automation`. Socket stub của guard không còn ghi log có chữ jsharvest.
  - **N5:** `detect` nhận ra `error code: 1xxx` dạng text thuần. "Sorry, you have been blocked" là `request`, không phải `challenge`. 1006 không được hiểu là cấm IP khi chỉ dựa vào mã lỗi.
  - **N4 (một phần):** `verify -gate-after 15` cho ra `host_gated`/`hosts_gated` khi mọi probe của host đều trả lời giống canary.
  - Sửa sau review (mục 28.4):
    - `-gate-after` chỉ tính phản hồi trước định tuyến (400/401/403/407/412/426/428) trên ít nhất 3 prefix;
    - canary cha khi vượt `maxPrefixes`;
    - request đối chứng không mang credential;
    - lỗi mạng tính theo host;
    - `sent.jsonl` và `drafts/*.http` có UA;
    - `pickUA` (UA của phiên đăng nhập → role → target);
    - tên task của tagger lấy từ `marker.TaskPrefix`;
    - race ở `results.Dir.Runs()`; `noteCaptured` chỉ giữ body khi resolve.
  - Còn lại:
    - **N1 thu hẹp:** UA và Sec-CH-UA theo bản Chrome thật thay cho `Chrome/141` cứng; `Sender` dùng HTTP/2; cookie CDN chỉ trong bộ nhớ của từng (target, role), không chia sẻ giữa các role.
    - **N2/N3 hoãn:** chưa có bằng chứng (lúc 17:17, TLS của Go với UA Chrome vẫn nhận 200 từ `api.target-c.example`). Giữ "không giả TLS" cho tới khi thí nghiệm cho thấy cần.
- Đợt 25J (mục 29 của `docs/gd6-waf-design.md`):
  - `verify` gửi draft xen kẽ theo gateway prefix (`probeOrder`; `verify.json` giữ thứ tự gốc). Ngưỡng dừng sớm là `min(3, số prefix gửi được)`, tính bằng cùng `preSkip`/`sendPlan` với `probe`.
  - Request đối chứng nhận 429 thì host chờ đúng `Retry-After`.
  - `requests.jsonl` đọc dạng luồng một lần (`scanEntries`, `uaCounts`).
  - **`detect.Classify` là bộ phân loại chặn dùng chung** (`replay` chỉ còn alias):
    - frontier CDP đi tiếp khi một trang dính luật chặn, 3 trang liên tiếp thì dừng;
    - engine HTTP chỉ leo thang sang Chrome cho host có trang mà trình duyệt có thể qua (`browserPassable`, `BlockKind.BrowserMayPass`).
- Đợt 25K (mục 30 của `docs/gd6-waf-design.md`):
  - `internal/uahints`: UA theo bản Chrome trên máy và Sec-CH-UA khớp UA được gửi; dùng chung cho `browser.cleanUA`, engine HTTP (`httpUA`, hints trên HTTPS) và `Sender`.
  - `Sender.prepare` viết lại request trước khi gửi (bỏ hop-by-hop, thêm UA và hints, gộp cookie CDN); `sent.jsonl` ghi đúng bản đó. `Sender` dùng HTTP/2.
  - Cookie CDN (`traffic.CDNCookie`) giữ trong bộ nhớ theo từng role của `Sender`, không cho role khác hay request đối chứng, không ghi ra đĩa. `updateJar` bỏ qua chúng.
  - `verify -concurrency N`: song song giữa các host, mỗi host một request một lúc (`byHost`, `lockHost`).
  - `polite()`/`page()` của engine HTTP dùng `detect.Classify`: luật chặn trên một URL không dừng crawl.
- Đợt 25L (mục 31 của `docs/gd6-waf-design.md`): engine HTTP `pages()`.
  - Trong một tầng, trang vẫn lấy lần lượt, nhưng tải script của tối đa 4 trang chạy gối nhau (`maxPagesInFlight`, chung `-http-rate`).
  - Route, API host và trạng thái SPA của từng trang nằm trong bucket riêng, đưa vào hàng đợi ở cuối tầng theo thứ tự lấy trang, sắp theo script nguồn. Thứ tự trang giống hệt crawl từng trang một (`TestPipelinedPagesAreDeterministic`).
  - Đo tốc độ: `JSH_PIPE_BENCH=1 [JSH_PIPE_RATE=R] go test -run TestPipelineBench ./internal/httpcrawl`. Ở rate 5 vẫn đạt 100% trần; ở rate 20 từ 35 s xuống 13 s.
- Đợt 25M (mục 32 của `docs/gd6-waf-design.md`):
  - Script của một trang được `admit` (kiểm rồi `claim`) ngay lúc lấy trang, theo thứ tự lấy trang, nên script dùng chung thuộc về trang đầu tiên khai báo nó.
  - `setStop` huỷ việc đang chạy, nhưng crawl vẫn trả `ErrStopped`.
  - Challenge gặp trên script, request thăm dò hay kiểm tra SPA thì ghi trang chứa vào `Challenged` (`politeAt`).
  - Leo thang: Chrome dùng `httpUA` và cookie ứng dụng của crawl HTTP (`Result.Cookies` từ `recJar`, không có cookie CDN), nạp trong `RunRecord`, chỉ trong bộ nhớ, không profile.
  - `NewIdentity` bỏ cookie CDN. `Sender` có `ChromePath`/`JSHARVEST_CHROME`, cờ `-chrome`.
- Đợt 25N (mục 33 của `docs/gd6-waf-design.md`):
  - `recJar` xác định phạm vi cookie theo RFC 6265: path mặc định là thư mục của URL, Domain mà host không nằm dưới thì bỏ, Max-Age/Expires; khoá tên + domain/host + path, bản đặt cuối thắng. `spaCheck` ghi challenge theo tầng của trang.
  - Bước 3.1 (bản nhớ cho `frontier.commit()`) đã đo và **bỏ**: Analyze ấm 0,2 s mỗi tầng (`JSH_ANALYZE_DIR=… go test -run TestAnalyzeBench ./internal/endpoints`).
  - `jsapi.go` tách thành `defs`/`eval`/`keys`/`calls`/`strings`/`locate`/`result.go`. `archive/run.go` tách thành `list`/`groups`/`fetch.go`. Cả hai lần tách chỉ di chuyển code.
  - Đợt 25O (mục 34): keeper thấy request của trang bị đẩy về trang login (`OnRedirect` của capture, `isLoginRedirect`) và xác nhận phiên đã mất phía server (`goneOnServer`: `check_url`, hoặc fetch trang đích của login với `redirect: manual`) → nguyên nhân `login-redirect`. Gate `session-check` 1b (`/members/late`). Cookie có Domain là IP thì host-only.
  - Đợt 26A (mục 35, jsapi v24): request đi qua class (`classes.go`): member kế thừa, field gán hàm, `#private`, `super(…)`, instance (`bindInstance`, `x.self`, `madeOnce`), giải lúc đọc (`lazy`), `new URL` + `url.pathname`, `.expand`, `condTruth` chỉ cho biểu thức ổn định. `_this` chưa khai báo trong code hạ cấp là `this`. Fixture dev `classes_test.go` (3 dạng: nguồn, minify, hạ cấp). **Kiểm mù Keycloak vẫn 0/415** (chạy một lần; chưa chẩn đoán).
  - Đợt 26B (mục 36, jsapi v25): **Keycloak là tập dev** (không còn kiểm mù; cần tập kiểm mù mới). `instanceSites` (gồm class con), `callInInstances` (mọi lời gọi dùng `this`; `forwardsPath` bỏ khung helper), `readChain` + `fills` cho `frame`, `usedLog`, `joinCall` (nối path variadic), `#private` theo class khai báo (`privOwner`), field gán lại ngoài constructor (`later`, bỏ giá trị giữ chỗ). Keycloak 341/415 (74 còn thiếu gần như không có trong code UI).
  - Đợt 26C (mục 37, jsapi v26): `classOrder` (không lặp map), `maxInstanceSites` 8, `urlArgs` (chỉ đối số URL cho `forwardsPath`). **Kiểm mù #2 `@appwrite.io/console@21.1.0` (chạy một lần): 1.070/1.098**; harness `output/_groundtruth/eval_heldout_appwrite.py` (có file đánh dấu, không chạy lại). Tập này đã dùng.
  - Đợt 26D (mục 38, jsapi v27): helper có summary thì summary quyết định đối số nào là path (`pathParams`, `forwardVars`), không đoán. Kết quả dev/Keycloak được lưu theo commit (`eval_26d_v27_dev.json`, `keycloak_dev_v27.json`).
  - Đợt 26E (mục 39): **kiểm mù #3 `@medusajs/dashboard@2.22.7` + `@medusajs/js-sdk` (chạy một lần): 300/420**, cả hai chế độ `entries`/`all` (khâu tìm chunk không phải nút thắt); harness `output/_groundtruth/eval_heldout_medusa.py`. Tập này đã dùng.
  - Đợt 26F (mục 40, jsapi v28): **Medusa là tập dev** (kiểm mù #3 đã dùng; tập #4 phải đề xuất và chờ xác nhận trước khi tải). `X.fetch(path, opts)` không có method thì là GET (`generic`, `readBound`); `Object.assign` trong options. Medusa (dev) 382/420; 38 còn thiếu gần như không có trong code, 9 cần liên kết xuyên script.
  - Đợt 26G (mục 41, jsapi v29): method của options đọc theo thứ tự viết (`overlay`, `eitherOptions`), không đoán GET từ phần không đọc được. **Kiểm mù #4 `@directus/app@19.1.0` (chạy một lần): 89/136**; harness `output/_groundtruth/eval_heldout_directus.py`. Tập này đã dùng.
  - Đợt 26H (mục 42, jsapi v30): **Directus là tập dev** (không còn tập kiểm mù UI nào chưa mở). Nút thắt Directus/Medusa là **liên kết xuyên script** (hàm dựng endpoint import từ chunk khác; thiết kế đề xuất ở 42.5). `devToolPath` loại `__open-in-editor` và các endpoint của dev server.
  - Đợt 27A (mục 43, jsapi v31): **liên kết xuyên script, chiều hàm dựng URL được export**: `Result.Builders`/`Deferred` (jsapi, `deferred.go`), `EvalBuilder` (đánh giá với đối số thật, từng tổ hợp, bỏ tổ hợp không quyết định), `linkDeferred` (endpoints, qua `targetScripts`, `Script.Load`, bỏ `unknownOrigin`). Directus (dev) 93/136. Chiều method-class-SDK (Medusa) chưa làm.
  - Đợt 27B (mục 44, jsapi v32): `PrepareModule` + `(*Module).EvalBuilder` (parse một lần cho mỗi script), `Deferred.Pre` (tiền tố client), `||`/`&&` trong `condTruth`; test `deferred_test.go`. Thiết kế cơ chế Medusa ở 44.3.
  - Đợt 27C (mục 45): sửa cờ `client` của URL hoãn lại sau khi ghép tiền tố; **thiết kế Medusa viết lại** (mục 44.3 sai: Promotion cần thu hẹp theo nhánh so sánh, import map là sản phẩm phụ của harness, cần bóc `__awaiter`, member dạng field trong constructor, schema theo từng bước). Chờ chốt phạm vi (45.4).
  - Đợt 27D (mục 46, jsapi v33): **method trả về URL** (`urlreturn.go`): base của request (`baseKey`, chuỗi thuộc tính ≥ 3 phần) cộng hàm trả về URL dựng trên base đó → `GET`, `kind: url`. Appwrite (giờ là dev cho mẫu này) 1.087/1.098, tức đủ 1.087 phần có trong code. Kiểm mù #5: đề xuất ở 46.4, chờ xác nhận.
  - Đợt 27E (mục 47, jsapi v34): review 27D: gốc của `memberChain` là biến kèm định danh khai báo (tham số `e` của hai hàm minify không cùng base), `cursor` reset trước `urlReturnVisitor`, `new URL(…).href` và `new URL(path, base)`. Kiểm mù #5 chọn **Jellyfin Web 12.4** (`jellyfin-web_12.4+deb12_all.deb`, SHA256 theo chỉ mục APT; spec `jellyfin-openapi-12.4.json`); luật chốt trước ở 47.3.
  - Đợt 27F (mục 48, jsapi v35): **kiểm mù #5 Jellyfin Web 12.4: 3/364** (harness `output/_groundtruth/eval_heldout_jellyfin.py`, đã dùng; **Jellyfin từ giờ là dev**). Sửa: **bộ mô tả request** của openapi-generator `typescript-axios` (`descriptor.go`: object `{url, options:{method}}` ở bất cứ đâu, kể cả `t.a(2,{…})` của regenerator; `urlObjectPath` bỏ base giữ chỗ; `assignedOnce`; `assignLike` cho `_objectSpread2`); resolver: runtime webpack có chunk đặt tên trước bảng (`webpackNamedRe`), key của context lazy không phải file. Jellyfin (dev) 302/364; client cũ `ApiClient.getUrl` (khoảng 44) đề xuất ở 48.4.
  - **Đợt 28–30 (2026-11-15 → 16; đặc tả `docs/plan-28.md`, phase và tiến độ `docs/plan-28-exec.md` mục 4; điều phối O + worker S/C/H qua bản chụp `snapshot-tool`).** Bộ kết luận: SFC gộp đủ trường (jsapi v36), mã lỗi dạng số trong body 200 (control lỗi → `unclear`), GraphQL theo lô mỗi operation một khoá. Mạng của Go: `internal/netsafe` (phân giải một lần, kiểm mọi địa chỉ, dial IP; host rules và target nội bộ là ngoại lệ), kiểm IP literal/`localhost` ở tầng request khi có proxy, một nguồn proxy cho mọi client (`-proxy none`, loopback không qua proxy), gate `proxy-check`. Trình duyệt: dọn map capture, ba lớp chống trang public chạm IP private (guard `FailRequest`, LNA deny gồm `loopback-network`, cầu chì `remoteIPAddress`), WebRTC sau proxy bằng **preference của profile** (Chrome 156 bỏ qua cờ `--force-webrtc-ip-handling-policy`), gate `lan-check`, `webrtc-check`. 28B đo trước khi sửa: guard giết 100 % refresh, `-urls -tabs` với context riêng làm server thu hồi phiên, không gán nhầm nhân quả timer, mã trả về 422/403 không giúp app nào và làm Directus tụt coverage → 28C: ngoại lệ refresh (chỉ POST, sau Deny/Destructive, không GraphQL), `-guard-allow` neo origin+path lưu trong session (Deny trước Allow), đồng bộ token xoay vòng vào snapshot, keeper nghe 401 tầng API, `-urls -role` một context mỗi host. **BOLA ngang `authz -peers`** (`docs/gd7-bola-design.md`, fixture `peer-app`, gate `bola-check`, tool MCP `get_authz`); thử lab Jellyfin/Directus (`testbed/lab/`, mạng `internal: true`). Làn phụ: envelope `untrusted` và tool MCP `get_intel`, `get_diff`, `search_scripts`, `read_script`; `export -format openapi`; `flock` giữa các lệnh ghi. 28B(c): hai cơ chế jsapi tổng quát dự kiến thu hồi 0/228 operation bị sót (140 không có trong bundle) → **người dùng bỏ Bước 30**. Mọi review độc lập (P1.R, P2.R, P3.R, P5.2, P5.5) đều tìm ra lỗi thật đã sửa. `DOCKER=1 regress.sh -j 3` xanh (23 gate gồm `docker-check`, cộng unit; 1.203 s). Còn chờ: P5.T (chạy `authz -peers` trên target thật khi có hai tài khoản được cấp phép); container worker (P0.6) để đợt sau.
  - **Đợt 31 (`docs/plan-31.md` — dọn dẹp kho mã & nâng cấp kiến trúc P1–P3, `3bb9b78..b029a67`):** (P0) dọn repo (`4.1 GB -> 494 MB`), bỏ `devtools/worker/`, tài liệu/log cũ, harness 28B và code chết 0-caller, căn chỉnh `CLAUDE.md` (`<= 20 KB`); (P1) `internal/resolve` hỗ trợ Webpack 3/4/5 + `webpackAsyncContext` + liên kết `runtimeChunk` liên script (`httpcrawl` & `engine`), walker AST router phân cấp xuất `routes` trong `intel.json`/MCP kèm lọc tracker analytics (`D1`/`D2`), gói `internal/secretsig` nhận diện khóa theo tiền tố & che qua MCP, `export -format all` vẫn xuất `openapi.json`/`drafts` khi `flows` rỗng; (P2) dò OpenAPI/Swagger 2 pha theo ngữ cảnh + tự hãm `D3` (`crawl -no-spec-probe`), phân tích Cloud Storage + dò ACL an toàn mặc định qua `netsafe` (`verify -no-cloud-probe`), trích xuất thụ động luồng OAuth2/OIDC/SAML/CAS tiền xác thực (`auth_flows`); (P3) trích xuất bề mặt phân quyền client (`client_authz`: CASL, route guard, role/permission dicts), nâng `internal/jsapi` (`Version = 37`) giải chuỗi gán nối tiếp `+=`/`=` kiểu Terser và `.map`/`.forEach` 1–2 chặng (corpus 2568 file: `Endpoints 956 -> 956, lost 0`, `Routes 362 -> 425`, `RouteEntries 316`, `ClientAuthz 25 scripts`; `perfgate` ~5.34–5.55 s, ~255–275 MB RSS).
  - **Khi sửa `internal/jsapi`, so snapshot:** `JSAPI_SNAPSHOT=<file chứa danh sách đường dẫn tuyệt đối> go test -v -run TestSnapshot ./internal/jsapi | grep '^SNAP' | md5sum` (cần `-v`; corpus dev là `output/_live_25e_max/*/anon/js/*.js`, không gồm Keycloak), so với worktree ở HEAD. Output khác chỉ ở chỗ định sửa.
GĐ5 xong (5.1–5.4). Các phần để sau được ghi trong từng tài liệu thiết kế. Các phần để sau của 5.1: thăm dò endpoint chỉ có trong code, guard lấy cookie qua CDP. Giả định A1–A4 (mục đầu của plan) chưa được người giao việc xác nhận. **So sánh với katana luôn phải có cả chế độ standard, và luôn chạy `katana ... < /dev/null`** — GĐ1 ổn định lõi + bộ chặn hồi quy → GĐ2 engine + chunk resolver → GĐ3 kiểm chứng ngoài testbed (cổng quyết định) → GĐ4 guard → login → explore → diff giữa role → GĐ5 archive/analyze/monitor/Docker. Lộ trình gốc bên dưới giữ lại để tham khảo.

**Lộ trình sửa đổi sau nghiên cứu, chi tiết trong `docs/research-2026-11-02.md`:**

0. Testbed có ground truth (security-crawl-maze, ZAP Crawlground, cộng testbed riêng: webpack, Vite, Next Pages+App Router, Angular ngsw, Workbox SW, worker, inline/eval, route không có link, chunk sau auth).
   **Spike thư viện xong 2026-11-02 → GIỮ chromedp**, không cần patch (code thử ở `spike/` đã xoá sau Capture v2; xem trong lịch sử git):
   - Worker: nghe `target.AttachedToTarget` trên tab, rồi `chromedp.NewContext(ctx, WithTargetID(id), WithDetachOnCancel())`; gắn vào trong khoảng 27 ms; `Debugger.enable` gửi lại cả worker main lẫn chunk worker đã import trước khi gắn vào. ✓
   - `Debugger.scriptParsed` + `getScriptSource` trên tab bắt được inline (url = URL trang) và eval (url rỗng). ✓ Riêng Debugger đã đạt 7/16 trên webpack-vanilla.
   - `Fetch.enable` ở cấp browser (`chromedp.CallBrowser` + `chromedp.BrowserEvents(fetch.RequestPaused)`) dừng được POST của cả tab lẫn worker, có `PostDataEntries`; `FulfillRequest` giả tới được cả hai, server không nhận request nào. ✓ Lưu ý: request từ worker có `networkId` **rỗng**, nên initiator phải lấy từ Network trên session của worker.
   - Service worker và iframe khác site (OOPIF, `type=iframe`) được tự gắn vào từ tab (`AttachedToTarget`). ✓ **Shared worker không được tự gắn vào**: phải dùng `CallBrowser(target.SetDiscoverTargets)` + `BrowserEvents(target.TargetCreated)`. ✓ Cả 4 loại đều dùng cùng cách `WithTargetID` + Debugger. Kết quả: 11/20 marker mà chưa cần khám phá trang.
   - Lưu ý: phát hiện target ở cấp browser thấy cả các tab khác. Ở chế độ attach phải lọc theo `browserContextId` hoặc opener.
   **Testbed xong 2026-11-02**: 5 app (webpack-vanilla, vite-vanilla, vite-pwa, next-mixed, angular-ngsw), tổng 56 marker. Chạy `testbed/bench.sh`. Kết quả và bài học: `docs/testbed-results-2026-11-02.md`. Tổng: jsharvest bước 1 đạt 15/56, katana `-hl` đạt 30/56, spike (Debugger + mọi target, tải thụ động) đạt 30/56. Chưa làm: security-crawl-maze, ZAP Crawlground.
1. Capture v2 — **đặc tả chi tiết: `docs/capture-v2-spec.md`** (đọc phần "Sửa đổi sau đánh giá độc lập" trước, phần này có hiệu lực cao hơn phần còn lại). **Capture v2 XONG 2026-11-02** (commit `c1b5bfa`→`af41450`+): 39/56 trên 5 app khi chỉ tải trang (v1 15, katana 30); kết quả và giả định: `docs/testbed-results-capture-v2.md`. Tiếp theo: bước 2 của lộ trình (chunk resolver). Nội dung: Network + `Debugger.scriptParsed` (setSkipAllPauses), lấy body ngay và song song, tăng buffer, worker, phát hiện bị chặn hoặc trang challenge, cảnh báo khi hết thời gian chờ idle; schema store mới (sha1_b32, canonical_key, header, initiator, sourcemap, cạnh của đồ thị chunk).
2. Chunk resolver: chạy runtime bundler trong trang, manifest (Vite, Next kể cả RSC, Workbox, ngsw), thử `.map` cho mọi chunk, đánh giá trong sandbox cho file lấy từ archive.
3. Auth: `login` có giao diện, profile cộng bản chụp sessionStorage, tự suy ra dấu hiệu đã đăng nhập, TOTP, attach đồng ý kiểu Chrome 144.
4. An toàn: Fetch ở cấp browser để chặn và lưu (blocked.jsonl, xuất request thô), parse GraphQL, xử lý Clear-Site-Data, heuristic logout phía client, response giả có header CORS.
5. Khám phá: hook (theo crawlergo/katana), BFS ngẫu nhiên, gộp nhiều lần chạy, đo bằng Profiler.
6. Role: so sánh 3 lớp; privilege simulation (cờ riêng).
7. Archive: Wayback (resumeKey, lọc phía mình, `id_`, dedupe theo digest), URLScan, OTX, Common Crawl; có checkpoint; không dùng VirusTotal public cho dự án trả phí.
8. Chế độ monitor: chuỗi phiên bản, so sánh, lọc thay đổi vặt.
9. Docker: Chrome đầy đủ ghim phiên bản, xvfb và noVNC cho login, user không phải root, seccomp, `--init`.
