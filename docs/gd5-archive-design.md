# GĐ5.3 — Nguồn lịch sử (`jsharvest archive`)

**Mục tiêu** (CLAUDE.md "Wayback"; research mục 2.5 và 5; đánh giá độc lập đợt 3, mục 6, ưu tiên 3). Tìm **API cũ bị bỏ quên**: endpoint từng có trong bundle JS 6 tháng đến 2 năm trước, đã gỡ khỏi giao diện nhưng backend có thể vẫn chưa đóng.
- Lấy danh sách URL lịch sử của target từ archive công khai.
- Tải các file JS cũ vào store (kèm `source`, `alive`).
- Chạy `jsapi` trên các file đó.
- Đối chiếu với catalog của crawl hiện tại để ra danh sách **chỉ có trong lịch sử** (`historical_only`).

**Gửi gì, tới đâu:**
- **Archive** (bên thứ ba; truy vấn về domain, không chạm vào target): nhịp chậm, chờ khi gặp 429.
- **Target**: chỉ khi kiểm file JS cũ còn sống không (`GET` không credential tới đúng URL cũ, trong scope, có nhịp); tắt được bằng `-live=false`.
- **Không thăm dò endpoint lịch sử** trong bước này; danh sách đó là đầu vào cho bước sau (thăm dò endpoint, để sau của 5.1).

## 1. Nguồn

| Nguồn | Liệt kê | Lấy nội dung | Ghi chú |
|---|---|---|---|
| **Wayback** (mặc định) | CDX `url=<host>&matchType=domain&output=json&fl=timestamp,original,mimetype,statuscode,digest,length&showResumeKey=true&limit=N`, **không filter**; phân trang bằng `resumeKey` | `web.archive.org/web/<ts>id_/<url>` (file gốc, không có phần Wayback chèn vào) | ~15 request/phút; 429 → chờ 3 phút (như waymore) rồi thử lại; 503/504 → thử lại với backoff; checkpoint sau mỗi trang |
| **Common Crawl** | `collinfo.json` → N collection gần nhất (mặc định 3); `<index>?url=*.<host>&output=json&page=k`; chỉ hỏi `showNumPages` khi trang 0 đầy (mục 11) | range-GET WARC `data.commoncrawl.org/<filename>`, `offset`/`length` → một gzip member → bản ghi WARC → body HTTP (giải `Transfer-Encoding: chunked` và `Content-Encoding` nếu có) | index hay timeout: tuỳ chọn, lỗi thì bỏ qua và ghi chú |
| **OTX** | `api/v1/indicators/<section>/<host>/url_list?limit=500&page=k`; section là `domain` cho domain đăng ký (eTLD+1), `hostname` cho subdomain, `IPv4`/`IPv6` cho IP (mục 10, ARC-02) | không có: tải qua Wayback `id_` hoặc server hiện tại | không cần key; `OTX_API_KEY` tuỳ chọn |
| **URLScan** | `api/v1/search/?q=domain:<host>` (chỉ tìm, không bao giờ gửi URL đi quét), rồi `api/v1/result/<id>/` của tối đa 10 lần quét trang của target | không tải từ urlscan: URL nó thấy đi qua kiểm live rồi Wayback | không cần key (giới hạn thấp hơn); `URLSCAN_API_KEY` nâng giới hạn (mục 11) |

Không dùng VirusTotal (research mục 5: điều khoản cấm dùng thương mại).

**Lọc phía mình:**
- giữ `statuscode` 200 (Wayback có cả `-` của revisit, bỏ đi);
- file JS: mimetype chứa javascript/ecmascript, **hoặc** đuôi `.js`, `.mjs`, `.cjs`; sourcemap `.js.map` ghi vào danh sách nhưng chưa tải (để sau);
- thuộc scope (`-scope rdn|fqdn`, mặc định `rdn` như crawl);
- **khử trùng theo `digest`** ngay khi liệt kê: một digest chỉ tải một lần, và **không tải** nếu store đã có file cùng `sha1_b32`;
- URL không phải JS (API, trang) ghi vào `urls.jsonl`.

## 2. Lấy nội dung

Với mỗi digest JS mới, theo thứ tự:
1. **Server hiện tại** (`-live`, mặc định bật): `GET` đúng URL cũ, không cookie, `redirect: manual`, trong scope, `-live-rate`.
   - Nếu ra 200 và SHA-1 bằng digest → lấy bản này, `alive: true`.
   - Nếu ra 200 nhưng nội dung khác → vẫn ghi lại bản live (`source: live`, tag `archive-url`), rồi tải bản archive.
   - 404 hoặc lỗi → `alive: false`.
2. **Archive** (`id_`, hoặc range WARC) → kiểm SHA-1 so với digest. Khớp → `source: wayback|commoncrawl`. Không khớp → vẫn lưu, kèm tag `digest-mismatch`.

Store ghi `Source` (`wayback`, `commoncrawl`, hoặc `both` nếu bản live trùng), `tags: archive`, và metadata mới: `archive: {first, last, captures, sources}`, `alive`.

## 3. Output

```
<out>/<host>/archive/        (thư mục riêng; không có runs.jsonl, nên diff không coi nó là một role)
├── js/<sha256>.js  index.jsonl      store như crawl; source, alive, archive{}
├── urls.jsonl                       mọi URL liệt kê được (JS và không JS): url, sources, first, last, captures, mime, status
├── endpoints.jsonl                  catalog của các file JS archive (endpoints.Analyze)
├── historical.jsonl                 endpoint có trong JS archive mà không role nào của crawl hiện tại có (trong code hay traffic)
└── archive.json                     checkpoint (resumeKey, trang CC, digest đã xong) và thống kê; 0600
```

- **`historical_only`**: khoá endpoint (method, host, path template) có trong `archive/endpoints.jsonl` mà không khớp endpoint nào trong `endpoints.jsonl` của các role hiện có (`<out>/<host>/<role>/`). Ghép bằng template, như 4.7. Mỗi dòng ghi: script nguồn, thời điểm có trong archive (first/last), và `alive` của script.
- `jsharvest endpoints -target H -role archive` dùng được ngay, vì đó là một thư mục store.

## 4. CLI

```
jsharvest archive -target HOST [-sources wayback,commoncrawl,otx,urlscan] [-scope rdn|fqdn] [-since 2024-01-01]
  [-live=true] [-live-rate 2] [-max-files 2000] [-cc-collections 3] [-resume=true]
```

Biến môi trường dành cho test: `JSHARVEST_WAYBACK_URL`, `JSHARVEST_CC_INDEX_URL`, `JSHARVEST_CC_DATA_URL`, `JSHARVEST_OTX_URL`, `JSHARVEST_URLSCAN_URL`, để gate trỏ vào archive giả.

## 5. Package

- `internal/archive`:
  - `wayback.go`, `commoncrawl.go`, `otx.go`, `urlscan.go`: các nguồn; mỗi nguồn trả về `Capture{URL, Time, MIME, Status, Digest, Length, Source, Ref}` qua callback, có checkpoint;
  - `warc.go`: đọc một bản ghi WARC; hàm thuần;
  - `fetch.go`: tải live hoặc archive, kiểm digest;
  - `client.go`: HTTP có nhịp, backoff và chờ khi gặp 429, User-Agent rõ ràng;
  - `state.go`: checkpoint;
  - `historical.go`: đối chiếu với catalog; hàm thuần.
- `cmd/jsharvest/archive.go`.

## 6. Fixture và gate (`testbed/archive-check.sh`)

Archive giả trong testbed server (`/fake/cdx`, `/fake/web/<ts>id_/<url>`, `/fake/cc/…`, `/fake/otx/…`). Dữ liệu dựng từ một app có ba bản build:
- bản cũ có endpoint `/api/v1/legacy-export` mà bản hiện tại không còn;
- một file JS cũ **vẫn còn** trên server hiện tại (`alive`);
- một file đã mất (404) nên phải lấy bản `id_`;
- một bản ghi `warc/revisit`;
- một digest trùng file mà crawl đã có (không được tải);
- URL không phải JS (`/api/v1/…`);
- hai trang CDX nối bằng `resumeKey`;
- một lần 503 (phải thử lại), một lần 429 (phải chờ; gate rút ngắn thời gian chờ bằng `JSHARVEST_ARCHIVE_429_WAIT`);
- một file Common Crawl lấy qua range WARC;
- OTX có phân trang.

Gate kiểm:
1. đủ file JS, đúng SHA-256, đúng `source`/`alive`;
2. `historical.jsonl` chứa `/api/v1/legacy-export` và không chứa endpoint mà bản hiện tại vẫn có;
3. digest đã có không bị tải lại; `revisit` bị bỏ;
4. **checkpoint:** dừng giữa chừng (SIGINT) rồi chạy lại → không tải lại cái đã có, kết quả giống lần chạy liền một mạch;
5. log server: kiểm live chỉ là GET tới URL JS trong scope, không có cookie; không có request nào tới host ngoài scope;
6. quyền 0600/0700.

## 7. Đánh giá độc lập (2026-11-05) — có hiệu lực cao hơn mục 1–6

Reviewer đã thử thật một truy vấn CDX và một lần tải `id_` (example.com), và đọc tài liệu của từng dịch vụ. Mình kiểm lại các điểm về code (`store.merge` gán `both` cho mọi cặp nguồn khác nhau; catalog có `Kind: "string"` cho mức `weak`).

**Phạm vi v1:**
- **Wayback:** liệt kê và tải đầy đủ.
- **Common Crawl:** chỉ liệt kê (Common Crawl không render trang nên hiếm JS, và index bị giới hạn nhịp rất chặt). Tải bằng WARC để sau `-cc-fetch`; `warc.go` đã có và đã có test.
- **OTX:** chỉ liệt kê, rồi tải qua Wayback.
- **URLScan:** để sau (cần key, quy trình hai bước search → result → responses, quota theo từng hành động).

**Quyết định:**
1. **Digest và nén:**
   - tải `id_` với `DisableCompression` và `Accept-Encoding: identity`;
   - băm **byte thô** để so với digest của CDX, rồi mới giải nén theo `Content-Encoding` thật (gzip; br và zstd thì giữ nguyên byte, gắn tag);
   - danh tính nội dung là SHA-256 của body đã giải nén; digest của CDX chỉ dùng để khử trùng trước khi tải;
   - không khớp thì vẫn giữ, gắn tag `digest-mismatch`.
   - Common Crawl lưu body đã giải nén và đổi tên header thành `X-Crawler-*`: không giải nén theo các header đó.
2. **`alive`** = 200, body không phải HTML (sniff), content-type giống JS hoặc không có. Thêm trường riêng `live_same` (trùng nội dung bản archive). Gate có ca file JS cũ trả 200 HTML (SPA fallback), phải ra `alive: false`.
3. **Kiểm live:**
   - dùng `replay.Sender` (gắn IP khi kết nối, không theo redirect, có `-proxy`, có log);
   - chỉ tới các host mà crawl hiện tại đã tới (hoặc `-live-hosts`), vì subdomain cũ có thể là CNAME treo trỏ sang S3 hay Heroku của người khác;
   - **URL cũ mang credential** (tên nhạy cảm, `X-Amz-Signature`, `sig`…) **không bao giờ được gửi**; trong `urls.jsonl` thì bị che, và được liệt kê thành phát hiện (`credential_urls`).
4. **Nhịp:**
   - ngân sách riêng cho CDX (1 request mỗi 4 giây) và cho memento (1 request/giây);
   - tôn trọng `Retry-After`, nếu không có thì chờ ít nhất 60 giây;
   - kết nối bị từ chối liên tiếp nghĩa là đã bị chặn: lưu checkpoint rồi thoát với mã 3;
   - timeout dài (120 giây), đọc CDX theo luồng.
   - Common Crawl: tuần tự từng request, backoff ít nhất 10 giây, bỏ nguồn sau 3 lần 503.
5. **Đọc CDX:**
   - dòng 0 là header, sau đó là dữ liệu, rồi `[]`, rồi `["<resumeKey>"]` (chỉ có khi còn trang tiếp);
   - `original` có thể chứa `:80`;
   - `length` là kích thước bản ghi WARC đã nén, không phải kích thước file;
   - domain bị loại khỏi archive (`AdministrativeAccessControlException`) thì báo, không thử lại;
   - `id_` có thể 302 sang timestamp gần nhất: chỉ theo redirect trong `web.archive.org`, rồi kiểm digest lại;
   - đuôi file xét trên path, không xét trên cả URL;
   - mimetype `unk` hay `text/plain` thì sniff xem có phải HTML không.
6. **Revisit** không tải, nhưng được đếm vào `captures` và `last` của digest tương ứng.
7. **OTX:** không có digest hay timestamp, nên khử trùng theo URL. Chỉ tải những URL mà CDX chưa có, bằng `/web/2id_/URL`. Phân trang theo `has_next`.
8. **Store:** thêm `sources[]` (nguồn chính xác), `alive`, `live_same`, `archive{first,last,captures}`. `source` giữ nghĩa cũ: `both` = live cộng archive.
9. **`historical_only`:**
   - template so với template, `{…}` khớp hai chiều; method rỗng khớp mọi method; host rỗng so theo path;
   - template chung chung và `Kind: string` → `confidence: low` (liệt kê riêng);
   - **trước khi kết luận là lịch sử, tìm các đoạn cố định của path trong `js/` hiện tại**: có trong file JS hiện tại thì không phải lịch sử, chỉ là crawl chưa tới;
   - đối chiếu với mọi thư mục host trong scope (`<out>/*/<role>/`); cảnh báo khi không có catalog hiện tại nào;
   - đổi phiên bản (`/v1/` → `/v2/`) → lớp riêng `version_changed`;
   - `archive` là tên role dành riêng.
10. **Quy mô:**
    - gộp theo URL trong lúc đọc luồng (CDX đã sắp xếp theo urlkey);
    - digest đã xong ghi vào một log chỉ nối thêm;
    - checkpoint lưu hash của tham số truy vấn (`resumeKey` chỉ hợp lệ với đúng truy vấn đó);
    - `-since` lọc phía mình;
    - `-max-files` ưu tiên bản mới nhất theo `CanonicalKey`, bỏ thư viện vendor.
11. **Gate:** fake archive có thêm mọi ca review nêu (nén có header hỏng, redirect sang timestamp gần, kết nối bị từ chối, domain bị loại, SPA fallback, URL mang token, chạy tiếp với tham số khác). Thêm **golden fixture** là các response thật cỡ nhỏ của Wayback (example.com), và smoke test thật tuỳ chọn `LIVE_ARCHIVE=1` (example.com, `-live=false`, giới hạn rất nhỏ).

## 8. Kết quả (2026-11-05)

**Lệnh:** `jsharvest archive -target HOST [-sources wayback,otx,commoncrawl] [-scope rdn|fqdn] [-since YYYY-MM-DD] [-live=true] [-live-hosts …] [-live-rate 2] [-max-files 2000] [-max-pages N] [-vendor] [-proxy URL]`. Mặc định `-sources wayback,otx,commoncrawl` (từ 2026-11-09, người dùng muốn chạy đủ mọi nguồn; trước đó là `wayback,otx`). Common Crawl chậm (khoảng một phút cho một host) và gặp 503 thì bỏ qua, không làm hỏng lần chạy; nội dung chỉ Common Crawl có thì tải qua Wayback.

**Package `internal/archive`:**
- `client.go`: ngân sách nhịp; `Accept-Encoding: identity`; chờ khi gặp 429, 503, 504; `ErrBlocked`;
- `wayback.go`: CDX theo `resumeKey`, `Memento`, `ErrExcluded`;
- `otx.go`, `commoncrawl.go`;
- `warc.go`: để dành cho `-cc-fetch`;
- `run.go`: liệt kê có checkpoint, tải, thống kê;
- `history.go`: crawl hiện tại, phân lớp;
- `historical.go`: ghép template;
- `hosts.go`.

**Store:** thêm `sources[]`, `alive`, `live_same`, `archive{first,last,captures}`, `BySHA1`, `Entry`. `source` giữ nghĩa: `both` = live cộng archive.

**Kiểm với dịch vụ thật** (truy vấn nhỏ, không filter):
- CDX của example.com có đúng định dạng thiết kế giả định; câu trả lời được lưu làm golden fixture (`internal/archive/testdata/cdx-example.json`).
- `-max-pages 2` trên Wayback thật: 50 dòng, nối hai trang bằng `resumeKey` thật.
- `jquery-1.4.2.min.js` (72 KB): SHA-1 base32 của bản tải `id_` (gửi `Accept-Encoding: identity`) **khớp đúng** digest của CDX (`MXF76TU5…`).

**Gate `testbed/archive-check.sh`** (archive giả trong testbed: `/fake/wayback`, `/fake/otx`, `/fake/cc`; fixture `archive-app` với `history.json`):

| | Kết quả |
|---|---|
| A. crawl hiện tại (`-explore`), rồi `archive` | đúng 6 dòng `historical.jsonl`: 5 `historical` (gồm endpoint chỉ OTX có và endpoint từ bản bị nén gzip) và 1 `version_changed` (`/api/v1/orders`); không có endpoint hiện tại nào, không có `/api/v2/hidden-report` (vẫn trong code hôm nay); `old-2023.js` có `both`, `alive`, `live_same`; `/legacy/app.js` (200 HTML) `alive: false`, 3 lần chụp tính cả revisit; bản bị nén không lệch digest; nội dung trùng crawl không tải lại (1); vendor bỏ qua; host ngoài scope bỏ qua; URL mang token bị che ở mọi file và không bao giờ được gửi; live check: đúng 5 path, mỗi path một lần, chỉ GET; vượt qua được 503 và 429; quyền 0600/0700 |
| B. SIGINT giữa lúc tải, rồi chạy tiếp | kết quả giống A; không memento nào tải hai lần |
| C. `-live=false` | không có request nào tới target |
| D. `LIVE_ARCHIVE=1` (tuỳ chọn) | Wayback thật, example.com, 2 trang |

**Lỗi bắt được trong lúc làm:**
1. Catalog hiện tại chỉ có template chung chung của hàm bọc (`/api/v2{}`), vì mọi request đều đi qua `'/api/v2' + p`. Endpoint còn đang dùng vì thế bị báo là lịch sử. Giờ "hiện tại" gồm cả các path trong `requests.jsonl`, và template chung chung không được dùng để ghép.
2. File JS, `run.json`, `runs.jsonl`, `external_refs.jsonl` và tệp batch được ghi với quyền **0644**. Giờ là 0600, cùng với thư mục 0700 của 5.2.
3. Đếm trùng sau khi chạy tiếp: phần bị bỏ qua ở mỗi lượt tải được đếm lại từ đầu.
4. `http.Redirect` của Go làm sạch `http://` trong path, nên archive giả phải tự đặt `Location`. Đây là lỗi của fixture, nhưng nó nhắc rằng Wayback thật trả `Location` tuyệt đối.

**Để sau:**
- `-cc-fetch` (WARC, có kiểm `truncated`);
- URLScan;
- `.js.map` cũ;
- thăm dò endpoint lịch sử (đầu vào là `historical.jsonl`).

## 9. Đánh giá độc lập đợt 5 (2026-11-05)

Kiểm lại cả 4 điểm trên code; cả 4 đều có thật và đã sửa:
- **NEW-5.3-01 (Medium):** `docker/entrypoint.sh` thiếu lệnh `archive`, nên `docker run … archive` đi chạy một binary `archive` không tồn tại. Đã thêm `archive` (và `monitor` cho 5.4). `docker-check.sh` nay chạy `<lệnh> -h` cho **mọi** lệnh có trong `jsharvest help`, để entrypoint luôn theo kịp. Bản thân bước kiểm này từng hỏng vì `grep -q` cộng `pipefail` (SIGPIPE khi phần trợ giúp dài).
- **NEW-5.3-02:** nội dung chỉ một archive khác có (Common Crawl) giờ được tải qua Wayback theo URL, tại timestamp của archive đó (Wayback chuyển sang bản chụp gần nhất). Fixture có thêm `cc-only.js` → `/api/v1/cc-only-hook`.
- **NEW-5.3-03:** `inScripts` không còn tìm "đoạn cố định dài nhất, đã cắt dấu `/`" (thường là `api/v1`, có trong mọi bundle của API đó). Giờ tìm **cả template**: các đoạn cố định giữ dấu `/`, theo đúng thứ tự, placeholder là một đoạn ngắn không có dấu nháy hay khoảng trắng; dưới 8 ký tự cố định thì không tìm. Có unit test.
- **NEW-5.3-04:** dừng vì `-max-pages` thì giữ `resumeKey` và không đánh dấu đã liệt kê xong; lần chạy sau liệt kê tiếp. Gate có thêm kịch bản B2. Cũng tách bộ đếm: `already_held` (crawl hôm nay có) và `merged` (một lượt archive trước đã tải dưới URL khác).

Gate: `archive-check` (A, B, B2, C) và `docker-check` (7 bước) đều đạt.

## 10. Đánh giá độc lập đợt 16 (ARC-01 → ARC-10, 2026-11-09)

Người dùng thấy Wayback "chưa hoạt động đúng với những gì nó có thể" và "chưa đo độ chính xác đúng". Reviewer nêu 10 điểm. Đã kiểm từng điểm trên code:

| Điểm | Có thật? | Đã làm |
|---|---|---|
| ARC-01 kiểm live | Có, cả hai ý | `liveCheck`: URL `http://` bị 3xx sang **đúng host, đúng path và query** qua `https`, hoặc cổng 80 không trả lời (URL không ghi cổng), thì hỏi lại bản `https`. Redirect sang chỗ khác (trang login) vẫn là `alive: false`. Bản live ghi theo URL đã trả lời, tag `https-upgrade`. Khi không có `-live-hosts`, **host mục tiêu luôn được hỏi** kể cả chưa crawl: người dùng đã chỉ định nó. Subdomain cũ vẫn chỉ được hỏi khi crawl đã tới (CNAME treo). `LiveHosts` nil giờ là không hỏi ai. |
| ARC-02 OTX | Có | Chọn section theo loại host (như gau). Archive giả nhận cả 3 section, gate kiểm đúng section đã hỏi. |
| ARC-03 revisit | Có (khi dùng `-since`) | `groups()`: nội dung chỉ còn revisit thì tải theo revisit mới nhất. Wayback trả bản gốc tại timestamp của revisit. |
| ARC-04 | Ý 1 có một phần; ý 2 mô tả sai | URL không có digest chỉ bị bỏ khi nhóm digest của nó **thật sự được tải**. Ý 2: `webpackChunks` resolve theo URL của **script**, không theo `pageURL`, nên lỗi `/static/js/static/js/…` mô tả trong review không xảy ra vì tham số này. Tham số này chỉ ảnh hưởng gốc của Vite và worker; vẫn đổi sang gốc của origin. |
| ARC-05 | Có | `Client.Get` thử lại 502. `Wayback.Page` gặp trang HTML với 200 ("Temporarily Offline") thì chờ rồi hỏi lại, tối đa `Tries` lần, sau đó trả `ErrUnavailable`. `list()`: một nguồn lỗi (trừ `ErrBlocked` và ngắt) thì ghi chú, các nguồn khác vẫn chạy, `listed` để `false` để lần sau liệt kê tiếp từ chỗ dừng. |
| ARC-06 | Có | Redirect trong Wayback tối đa 8 bước. `urls` đếm URL **khác nhau** sau khi liệt kê, đọc `urls.jsonl` bằng một tập hash. |
| ARC-07 | Có | `HistLine.Bases`. |
| ARC-08 | Có | `unversioned` thay version bằng `v*` (không có `{`), nên vẫn là một đoạn cố định. Không sửa `generic()`, vì `monitor` dùng nó và `/api/v2{}` của hàm bọc phải vẫn là chung chung. |
| ARC-09 | Có, nhưng mô tả sai | `pathRe` không đòi dấu nháy; nó đòi đúng chuỗi `/system-user/…`, nên path tương đối không khớp. Giờ dấu `/` đầu được thay bằng `/` **hoặc** một dấu nháy ngay trước. Path ghép bằng `+` vẫn không tính (NEW-5.3-03, có trong `TestInScripts`). |
| ARC-10 | Có | Xem dưới. |

**Bộ đo (`testbed archivecheck`):**
- `historical.jsonl` và `archive/endpoints.jsonl` so **cả dòng**: class, method, path, `bases`, query, body, và với historical thêm các script gọi nó. Script được so theo **sha256 nội dung**, vì cùng một nội dung có thể nằm ở hai URL và URL được ghi tuỳ thứ tự tải. In ra precision và recall; cả hai phải bằng 1.
- Kiểm thêm: `in_current_code`, `urls`, `live-checks.jsonl` (khi có log của đúng một lần chạy, vì file được viết mới mỗi lần chạy), sự cố của archive giả (trang offline trả 200, 502, 503, 429), và section của OTX.

**Fixture mới (`archive-app`):**
- Gate liệt kê với `-since 2020-01-01`.
- `revisit-only.js`: chụp 2019, chỉ có revisit từ 2023.
- `gateway-2022.js`: client có `baseURL: '/api-gateway'`, path tương đối. `POST legacy/v1.0/export` giữ `bases` và body. `billing/v1.0/invoices/` vẫn được code hôm nay viết ra trong một template literal ngoài lời gọi, nên tính là `in_current_code`.
- `/v1.0/scooters/{}` cũ so với `/v2.0/scooters/{}` hôm nay: `version_changed`.
- CDX trả trang offline cho truy vấn đầu, 502 một lần ở trang sau.

**Kiểm chứng:** chạy gate mới trên code ở HEAD (worktree tạm):
- bản có ca offline: archive dừng ngay, recall 0;
- bỏ ca offline và 502: precision và recall của historical là 0,8, catalog có recall 0,947. Các lỗi gate bắt được: thiếu revisit (ARC-03), mất `bases` (ARC-07), `/v1.0/scooters/{}` thành `historical` (ARC-08), `billing` thành `historical` và `in_current_code` 1 (ARC-09), OTX hỏi `domain` (ARC-02), đếm 19 URL thay vì 17 (ARC-06).

Code hiện tại đạt cả A, B, B2, C với precision và recall bằng 1. ARC-01 (https) có unit test (`TestLiveUpgrade`) vì testbed chỉ chạy http. Các unit test khác: `TestOTXSection`, `TestWaybackOffline`, `TestListGoesOn`, `TestGroupsRevisitOnly`, `TestClassifyRound16`, `TestInScriptsRelative`.

**Để sau:**
- `.p=""` của webpack (public path tương đối theo trang) vẫn resolve theo script, ở cả crawl lẫn archive. Ít gặp; sửa trong `resolve` sẽ ảnh hưởng mọi engine.
- `live-checks.jsonl` chỉ giữ lần chạy cuối khi chạy tiếp.
- Trên target-a cần chạy lại `archive` để thấy OTX theo `hostname`. Chưa chạy: cần người dùng cho phép.

## 11. Đánh giá độc lập đợt 17 (MAX-01 → MAX-07, 2026-11-09)

Người dùng thấy tool "tự giới hạn bản thân": tự dừng sớm, và không mặc định chạy hết công suất. Phần thuộc `archive`:

| Điểm | Đã làm |
|---|---|
| MAX-01 Common Crawl | Client thử 3 lần, cách 15 s (trước là 1 lần). Bỏ chốt "3 lỗi thì bỏ cả nguồn". Mỗi collection độc lập: lỗi thì ghi chú, collection sau vẫn được hỏi, lần chạy sau chỉ hỏi lại collection lỗi (`state.commoncrawl.next/listed`). Chỉ hỏi `showNumPages` khi trang 0 có từ 3000 dòng trở lên: một host thường chỉ cần **một** request cho mỗi collection. Dòng index giữ `filename/offset/length`. Khi Wayback không có bản, đọc bản ghi bằng range GET tới `data.commoncrawl.org` (`JSHARVEST_CC_DATA_URL`) và `ReadRecord` (`from_warc`). |
| MAX-03 `-max-html` | Đếm số trang **đọc được thật**: trang không phải 200 hoặc là challenge thì nhường lượt cho trang sau. Trang đã đọc ở lần chạy trước vẫn được tính (`read:` trong `done.log`). |
| MAX-04 map và manifest | `take()` giữ thêm `.js.map`, `asset-manifest.json`, `ngsw.json`, `.vite/manifest.json`. Chúng đi cùng đường tải với script (kiểm live, chấp nhận JSON; Wayback; WARC). Map: nguồn của chính app (không lấy `node_modules`) vào store với kind `source`, file map vào `archive/maps/`. Manifest: các script nó chỉ ra được đưa vào danh sách tải (`resolved`). Script cũ có `sourceMappingURL` thì map của nó cũng được đưa vào danh sách tải. Hàm đọc manifest chuyển sang `resolve` (`ManifestScripts`). |
| MAX-05 song song, urlscan | `list()` chạy mọi nguồn cùng lúc; state, summary và file dùng chung nằm dưới `r.mu`. `ErrBlocked` hoặc ngắt thì huỷ cả lượt và giữ chỗ dừng; lỗi khác thì ghi chú và để lần sau. Thêm nguồn `urlscan`, có trong mặc định (`wayback,otx,commoncrawl,urlscan`). Trang urlscan thấy không vào `html.jsonl`, vì không có timestamp để hỏi Wayback. |
| MAX-06 host khác trong scope | Chưa làm. Với `-scope fqdn` (target-a) điểm này không áp dụng; với `rdn`, Wayback đã liệt kê theo `matchType=domain` của host. Ghi vào "Để sau". |

**Sửa thêm do gate bắt được:** khi danh sách mới có một phần (B2: `-max-pages 1`), `app.js` hôm nay đến từ urlscan hoặc Common Crawl dưới dạng URL không có digest, bị tải về và xếp thành lịch sử (`low /api/v2{}`). Giờ nội dung tải về theo URL không có digest mà trùng sha1 với script crawl hôm nay đã có thì không tính là lịch sử (`held_after_fetch`).

**Gate `archive-check`** (archive giả có thêm `/fake/ccdata`, `/fake/urlscan`, 504 một lần ở collection mới nhất): historical 19 dòng, catalog 23 dòng, precision và recall bằng 1 ở cả A, B, B2, C. Bốn ca mới:
- `DELETE /api/v1/map-only-hook/{}` lấy từ nguồn trong map 2022; `/api/v9/vendor-noise` của `node_modules` không xuất hiện;
- `GET /api/v1/manifest-only-hook` từ script chỉ `asset-manifest.json` 2022 chỉ ra;
- `PUT /api/v1/warc-only-hook` từ bản ghi WARC;
- `GET /api/v1/urlscan-only-hook` từ script chỉ một lần quét của urlscan thấy, vẫn còn sống.

Unit test: `TestCommonCrawlCollections`, `TestCommonCrawlFetch`, `TestURLScan`; `TestListGoesOn` chạy với `-race` trên hai nguồn song song.

**Để sau:** MAX-06; tải body từ `urlscan.io/responses/<sha256>/` (cần kiểm điều khoản và khoá); đoán `<script>.map` cho script cũ trong archive (mỗi lần đoán tốn một request tới server và một tới Wayback).


## 12. Đợt 37 & 37.1: hai stage, nhịp CDX, truyền tín hiệu chặn

**Nhịp.** Thư viện `wayback` (theo hướng dẫn của Internet Archive, 2026) đặt mặc định ở 80% giới hạn cứng: CDX/timemap khoảng 30 req/phút, Memento khoảng 600 req/phút. Hai giới hạn **tách biệt**. `wbIndexGap` 2,5 s (24 req/phút), AIMD lên tối đa 10 s khi gặp 429/503 (cooldown dùng chung giữa các worker), giảm dần khi thành công; `Wait` 60 s hoặc theo `Retry-After`. Với domain hàng nghìn shard, liệt kê đầy đủ mất từ 44 phút trở lên. Vì vậy `crawl -archive` đặt trần `-archive-max-pages 150`, duyệt shard theo stride nguyên tố cùng nhau (phủ đều không gian SURT), và các run sau tiếp tục từ `PagesDone`.

**Cô lập lỗi.** `ErrBlocked`/`ErrExcluded` của một nguồn chỉ dừng nguồn đó; chỉ `ctx` bị hủy mới dừng tất cả. Memento bị chặn thì `pages()` bỏ phần Memento và `fetch()` chuyển sang WARC của CC; mục chưa xong không đánh dấu done. `history()` luôn chạy. Mã thoát 3 giữ nguyên, `run.json` giữ `summary` khi có lỗi.

**Hai stage trong crawl (`archive.Mode`).**
- `ModeListOnly`: chỉ index công khai, `Live`/`Sender` bị bỏ ngay tại `Run`. Không gửi request tới target, không prefetch. Chạy khi seed đã sống, chồng lên crawl; với `-scope rdn`, `httpcrawl` stream các subdomain mới phát hiện qua `ExtraHostCh` vào bộ fan-out độc lập cho OTX và URLScan ngay trong lúc crawl đang chạy (Đợt 38, [plan-38.md](plan-38.md)).
- `ModeResume`: chạy sau barrier (Escalate, SPABoot, `writeEndpoints`). Không liệt kê lại; hỏi OTX/URLScan cho delta `ExtraHosts` còn sót (`intel.json`, Escalate/SPABoot); rồi `pages` → `fetch` → `history` (có log timing từng pha và 4 chặng `history`, kèm harness offline `JSH_HISTORY_BENCH`).
- `ModeFull`: khi không có Stage 1 (`-depth 0`, hoặc Stage 1 bị dừng sớm).
- Cả hai stage chạy trên **một** `archiveEnv` (`cmd/jsharvest/archive.go`). Env giữ khoá `archive/` liên tục, giữ client và budget (AIMD của OTX/URLScan được giữ), và được đóng ngay sau mỗi target.
- Cờ được parse bằng `ContinueOnError`, nên không bao giờ `os.Exit` trong tiến trình crawl.

**Truyền tín hiệu CDX → Memento (B5).** Chỉ khi client CDX bị **từ chối kết nối** đến mức latch (IP bị chặn): `Wayback.CarryIndexBlock()` cho client Memento chờ `Wait` rồi latch ngay ở lần từ chối đầu. 429 thuần của CDX không truyền. Không truyền chiều ngược lại (test cách ly `round34_2_test.go`).
