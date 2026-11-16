# GĐ5.4 — Theo dõi thay đổi (`jsharvest monitor`)

**Mục tiêu** (lộ trình gốc mục 8; đánh giá độc lập đợt 5, mục 6). Sau mỗi lần crawl định kỳ của cùng một target, cho biết **cái gì mới, cái gì mất, cái gì đổi**, và xếp mức độ đáng chú ý để người kiểm thử biết nên nhìn vào đâu trước:
- script mới hoặc đã đổi nội dung (đổi hash trong tên chunk không tính là thay đổi);
- endpoint mới, endpoint mất, endpoint đổi tham số;
- status quan sát được thay đổi (một endpoint trước trả 403, nay trả 200);
- lớp trong ma trận phân quyền `diff.json` thay đổi.

**`monitor` không crawl và không gửi gì tới target.** Nó chụp lại trạng thái của thư mục output, so với lần chụp trước, rồi ghi ra thay đổi. Dùng với cron hay CI: `jsharvest crawl … && jsharvest diff … && jsharvest monitor -target H`. Request duy nhất nó gửi là webhook tuỳ chọn, và nội dung webhook không bao giờ chứa cookie, token hay giá trị mẫu.

## 1. Snapshot

`<out>/<host>/monitor/snapshots/<UTC>.json` (0600), một file cho mỗi lần chạy `monitor`. Với mỗi role (thư mục `<out>/<host>/<role>/` có `runs.jsonl`; bỏ `archive` và `monitor`):
- **Lần chạy được lấy:** lần chạy mới nhất trong `runs.jsonl`, kèm `config` (độ sâu, explore, max_pages, resolve, guard) và kết quả (`frontier.stopped`, `session_lost`).
- **Script:** entry của `index.jsonl` có `last_seen` ≥ lúc lần chạy đó bắt đầu, bỏ script third-party và script của jsharvest. Khoá là `CanonicalKey` (hash trong tên chunk → `[h]`); mỗi khoá giữ tập SHA-256.
- **Endpoint:** `endpoints.Build` trên **chính các script đó** (cache `static/<sha>.json`) cộng **request của lần chạy đó**, nên endpoint của bản build cũ không lọt vào. Khoá là `METHOD host template [operation]`, như 4.7 (`flow.EntryTemplates`, `flow.Operation`). Mỗi endpoint giữ:
  - `status` (`static`, `both`, `observed`);
  - tên tham số query, body và header (từ code và từ traffic);
  - operation GraphQL;
  - các status HTTP quan sát được.
- **Phân quyền:** nếu `<out>/<host>/diff.json` có và mới hơn snapshot trước, giữ các mục `endpoint` gồm khoá, lớp và `lowest`.

Giữ tối đa `-keep` snapshot (mặc định 30); lần đầu chạy chỉ tạo mốc (baseline).

## 2. So sánh và mức độ

| Thay đổi | Điều kiện | Mức |
|---|---|---|
| `endpoint_new` | khoá chưa có trong snapshot trước | **high** nếu path có dấu hiệu quản trị hay gỡ lỗi (`admin`, `internal`, `debug`, `staff`, `manage`… như `roles.nativeMarks`), method ghi, hoặc tên phá huỷ hay động từ hành động (`guard.Destructive`, `NamesAction`); còn lại **medium** |
| `endpoint_gone` | khoá không còn | **medium** (đầu vào cho thăm dò: server có thể vẫn trả lời); **info** nếu hai lần chạy không so được (mục 3) |
| `param_new` | endpoint có thêm tên tham số | **high** nếu tên nhạy cảm cho phân quyền hay gỡ lỗi (`role`, `admin`, `is_admin`, `permission`, `scope`, `debug`, `include_deleted`, `internal`, `user_id`, `tenant`…) hoặc `traffic.Sensitive`; còn lại **medium** |
| `param_gone` | mất tên tham số | **low** |
| `status_changed` | cùng endpoint, cùng role, trước chỉ có 401/403 nay có 2xx | **high**; ngược lại (2xx → 401/403) **medium**; các thay đổi status khác **low** |
| `operation_new` | thêm operation GraphQL hay RPC | như `endpoint_new` |
| `authz_changed` | mục trong `diff.json` đổi lớp | **high** nếu lớp mới là `lower_ok`, `client_gated` hoặc `inconsistent`; còn lại **medium** |
| `script_new` | khoá chuẩn của script chưa có | **low** (các endpoint mới của nó đã được báo riêng) |
| `script_changed` | cùng khoá, tập SHA khác | **low**; bỏ qua với khoá chứa `[h]` khi tập endpoint không đổi, vì đó chỉ là build lại |
| `script_gone` | khoá không còn | **info** |

Mỗi thay đổi ghi kèm role, khoá, trước, sau, và các script nguồn (SHA, URL đã che token).

## 3. Chống nhiễu

- **Hai lần chạy không so được:** `config` khác nhau, `session_lost`, hoặc frontier dừng vì giới hạn (`limit`, `time`). Khi đó các thay đổi kiểu "mất" (`endpoint_gone`, `script_gone`, `param_gone`) hạ xuống **info** kèm lý do, vì crawl có thể chỉ chưa tới đó.
- Bỏ host ngoài scope và script third-party.
- Template so qua `flow.ByShape` và placeholder, nên id khác nhau (`/items/41`, `/items/42`) không tạo endpoint mới.
- Endpoint chỉ có trong traffic (`observed`) mà đã có trong lần trước thì không báo lại; chỉ báo khi khoá mới.

## 4. Output và cảnh báo

```
<out>/<host>/monitor/
├── snapshots/<UTC>.json     0600
├── changes.jsonl            nối thêm: mỗi dòng {at, from, to, role, kind, severity, layer, key, before, after, reason}
└── latest.md                tóm tắt của lần so gần nhất, xếp theo mức
```

- `-fail-on high|medium|low`: thoát với mã 5 khi có thay đổi từ mức đó trở lên (cron, CI).
- `-webhook URL`:
  - `POST` JSON `{target, from, to, counts, changes:[{severity, kind, role, key, reason}], text}` (trường `text` để Slack và Mattermost đọc được);
  - chỉ có **khoá endpoint đã template và che token** (`roles.MaskTokens`), không có giá trị mẫu, header hay body;
  - chỉ gửi khi có thay đổi từ `-webhook-min` (mặc định medium) trở lên;
  - timeout 10 giây, không theo redirect, thử lại một lần;
  - URL webhook không được in ra log.
- `-dry-run`: so và in kết quả, không ghi snapshot, không gửi webhook.

## 5. Package

- `internal/monitor`:
  - `snapshot.go`: chụp trạng thái;
  - `compare.go`: so và xếp mức; hàm thuần;
  - `report.go`: `changes.jsonl`, `latest.md`;
  - `webhook.go`.
- `cmd/jsharvest/monitor.go`.

## 6. Fixture và gate (`testbed/monitor-check.sh`)

Fixture `monitor-app` có hai bản build (`dist`, `dist-v2`). Server testbed chọn bản theo `TESTBED_DIST`, và route phía server cũng đổi theo bản. v2 so với v1:
- endpoint quản trị mới `POST /api/admin/export` → **high**;
- endpoint thường mới → **medium**;
- `GET /api/old-feed` biến mất → `endpoint_gone` **medium**;
- `/api/search` có thêm tham số `include_deleted` → **high**, và `page` → **medium**;
- `GET /api/report` trước trả 403, nay trả 200 → `status_changed` **high**;
- chunk `vendor.<hash>.js` đổi hash mà nội dung endpoint không đổi → không báo gì;
- một chunk mới chỉ chứa endpoint đã có → `script_new` **low**.

Gate kiểm:
1. crawl v1 → `monitor` (mốc, không có thay đổi);
2. crawl v2 → `monitor` cho đúng tập thay đổi trong `monitor.truth.json`, không thêm gì;
3. `monitor` lần nữa mà không crawl → 0 thay đổi;
4. crawl v2 với `-max-pages 1` (không so được) → các thay đổi "mất" chỉ là info;
5. `-fail-on high` → mã thoát 5;
6. webhook tới testbed: nhận một lần, nội dung không có cookie, token hay giá trị mẫu nào; `-dry-run` không gửi gì;
7. `monitor` không gửi request nào tới target (log server không tăng, trừ webhook);
8. quyền 0600/0700.

## 7. Đánh giá độc lập (2026-11-05) — có hiệu lực cao hơn mục 1–6

Reviewer đối chiếu với code và output thật; mình kiểm lại trên `runs.jsonl` (có `mode`, `exit_code`, `blocked`, `session.restored`, `frontier.listed`) và thí nghiệm hai bản build của monitor-app. Ở đó catalog tích luỹ giữ lại `/api/old-feed` của v1, `/api/report` mang cả `[200, 403]`, và `/api/items/41` với `/api/items/42` thành hai endpoint. Rủi ro lớn nhất là **báo động giả**.

**Quyết định:**
1. **Mỗi run tự ghi danh sách script của nó** (`scripts:[sha]` trong `run.json`/`runs.jsonl`, qua `store.TakeTouched`), thay cho việc đoán bằng `last_seen`. `RunConfig` có thêm `record`, `page_dwell`, ngân sách explore, `resolve_max`, `allow_write`, `guard_allow`.
2. **Run được dùng:**
   - mode `launch` hoặc `attach` (không lấy `watch`), `exit_code` 0, có trường `scripts`;
   - **mọi** run như vậy mà các snapshot trước chưa lấy (một batch `-urls` có nhiều run);
   - không có run mới thì không làm gì.
3. **Snapshot chỉ lưu run ID và thông tin để quyết định có so được không.** Nội dung (script, endpoint, tham số, status) được **dựng lại lúc so, cho cả hai bên, bằng code hiện tại**, vì `js/` và `requests.jsonl` vẫn còn. Nhờ vậy nâng cấp extractor không làm mọi thứ hiện thành "đã đổi".
4. **Chỉ snapshot so được mới được làm mốc.** Không so được khi:
   - `config` khác nhau, `blocked`, `session.restored` lớn hơn 0 hay `lost`;
   - frontier chạm giới hạn (`listed.limit` hoặc `queued` lớn hơn 0);
   - số trang đã thăm dưới 80% của mốc;
   - resolver dừng.

   Snapshot không so được vẫn được lưu, và vẫn được dùng để báo cái **mới**; mọi thay đổi kiểu "mất" thì chỉ là info.
5. **"Mới" nghĩa là không có trong hợp của 3 snapshot so được gần nhất**, chứ không chỉ so với mốc, để thứ chập chờn do explore không bị báo đi báo lại.
6. **"Mất" cần bằng chứng:** endpoint trong code chỉ được coi là mất khi script của nó **vẫn còn** (cùng khoá, SHA mới) mà không còn gọi endpoint đó. Script mất cả file thì là info. Endpoint chỉ có trong traffic mà mất thì luôn là info, vì explore thay đổi giữa các lần chạy.
7. **Khoá endpoint chuẩn hoá:**
   - host rỗng thì thay bằng host của target;
   - path qua `flow.ByShape`, mọi placeholder thành `{}`;
   - method rỗng khớp mọi method;
   - so khớp bằng hợp nhất template (`archive.SameEndpoint`), không bằng chuỗi.
8. **Tham số:**
   - lấy từ code (`Query`, `Body`, `Headers`) và từ traffic (query, JSON, form; như `roles.paramNames`);
   - tên được chuẩn hoá (chữ số và chỉ số mảng thành `#`); bỏ tham số chống cache (`_`, `t`, `ts`, `v`, `cb`, `utm_*`, `gclid`, `fbclid`);
   - tên chỉ thấy một lần trong traffic thì không tính.
9. **Status theo role:**
   - **high** chỉ khi mọi request trước (ít nhất 2) bị từ chối **và** mọi request lần này thành công;
   - có lẫn cả hai (`mixed`) → low;
   - thành công → bị từ chối → low;
   - run có sự kiện phiên → info.
10. **Thay đổi gộp theo (tầng, khoá)**, kèm `roles:[…]` và mức cao nhất, để một bundle chung cho 3 role không bị báo 3 lần.
11. **Mức độ:**
    - Endpoint mới là **high** khi path có dấu hiệu quản trị hay gỡ lỗi (`admin`, `internal`, `debug`, `staff`, `manage`, `swagger`, `openapi`, `graphiql`, `actuator`, `metrics`, `env`, `trace`, `beta`, `preview`, `test`…), khi nằm trên một **host mới trong scope**, hoặc khi **anon gọi được với 2xx**. Method ghi hay tên phá huỷ → **medium**. Còn lại **medium**.
    - Tham số mới là **high** khi là tham số về phân quyền hay gỡ lỗi (`role`, `admin`, `is_admin`, `permission`, `scope`, `debug`, `include_deleted`, `internal`, `impersonate`, `as_user`, `sudo`, `owner_id`, `account_id`, `org_id`, `user_id`, `tenant`), về redirect, SSRF hay LFI (`url`, `redirect`, `next`, `return_to`, `callback`, `file`, `path`, `template`), về lộ dữ liệu (`fields`, `expand`, `include`), hoặc về giá (`price`, `amount`, `discount`). Tên credential (`traffic.Sensitive`) → **medium**.
12. **Tầng script:** chỉ `kind=file`. Khoá có `[h]` mới hay mất → info. Đổi nội dung → low với khoá không có `[h]`; với khoá có `[h]` thì bỏ qua, vì đó chỉ là build lại.
13. **Tầng phân quyền (`authz_changed`) để sau:** `diff.json` tích luỹ mọi run, nên phải dựng lại phép so role trên đúng các run đã chọn. Tín hiệu quan trọng nhất (403 thành 200) đã có ở mục 9.
14. **Webhook:**
    - mặc định chỉ gửi số lượng, mức và đường dẫn tới `latest.md`; gửi kèm khoá endpoint chỉ khi có `-webhook-detail keys`;
    - URL đọc từ biến `JSHARVEST_WEBHOOK` hoặc từ file (`-webhook-file`), không qua tham số dòng lệnh;
    - chỉ https, trừ loopback; không theo redirect;
    - lỗi được log mà không kèm URL;
    - escape mrkdwn và Markdown; giới hạn kích thước payload; có `id` để chống trùng;
    - gửi thất bại thì giữ lại trong `pending-webhook.json` và gửi lại ở lần chạy sau.
15. **Snapshot** đặt tên theo thời gian kèm hash của tập run; `-keep` không bao giờ xoá mốc hiện hành.
16. **Gate có thêm:**
    - v1 crawl 3 lần với `-explore` → không có thay đổi từ low trở lên;
    - một run `-max-pages 1` xen giữa → không làm dời mốc, và không gây làn sóng "mới";
    - một batch `-urls` → mọi run của batch đều được lấy;
    - webhook: redirect không được theo, URL không xuất hiện trong stderr, nội dung đã escape.

    Các ca khó dựng bằng fixture được kiểm bằng unit test: template lật giữa hai dạng, gộp nhiều role, session bị mất giữa chừng.

## 8. Kết quả (2026-11-05)

**Lệnh:** `jsharvest monitor -target HOST [-keep 30] [-fail-on high|medium|low] [-webhook-file F] [-webhook-min medium] [-webhook-detail counts|keys] [-dry-run]`. URL webhook đọc từ `JSHARVEST_WEBHOOK` hoặc `-webhook-file`. Mã thoát 5 khi có thay đổi từ mức `-fail-on` trở lên.

**Package `internal/monitor`:**
- `runs.go`: chọn run, quyết định có so được không;
- `content.go`: dựng nội dung từ dữ liệu thô;
- `compare.go`: thay đổi và mức; hàm thuần;
- `monitor.go`: snapshot, mốc, `-keep`;
- `report.go`;
- `webhook.go`.

**Engine:** mỗi run ghi `scripts:[sha]` (`store.TakeTouched`); `RunConfig` có thêm `record`, `page_dwell_ms`, ngân sách explore, `resolve_max`, `allow_write`, `guard_allow`. `archive.SameEndpoint` và `archive.Generic` được export để monitor so khớp bằng template.

**Gate `testbed/monitor-check.sh`** (fixture `monitor-app`, hai bản build; server chọn bản qua `TESTBED_DIST`):

| | Kết quả |
|---|---|
| A. v1 crawl 3 lần | mốc, rồi 0 thay đổi từ low trở lên |
| B. v2 | đúng 8 thay đổi của truth: high cho `POST /api/admin/export`, `include_deleted`, `/api/report` 403 → 200; medium cho `/api/news`, `/api/old-feed` mất (script vẫn còn mà không gọi nữa), `page`; low cho `app.js` đổi nội dung, `extra.js` mới. `/api/items/41` → `/42` và `vendor.<hash>.js` đổi hash **không** bị báo. `-fail-on high` → thoát 5 |
| C. `monitor` lại, không crawl | "no new crawl" |
| D. `-max-pages 1` rồi crawl đầy đủ | không so được, không có gì từ low trở lên; sau đó 0 thay đổi (không có làn sóng "mới") |
| D3. batch `-urls` | lấy đủ 2 run; không so với mốc của các lần crawl đơn |
| E. webhook lỗi, rồi chạy được | URL (chứa token giả) không xuất hiện trong output; payload được giữ lại rồi gửi ở lần sau (2 payload); mặc định chỉ có số lượng, không có path |
| F. | không có request nào tới target; quyền 0600/0700 |

Unit test: luật status (từ chối một lần, `mixed`, phiên bị mất), "mất" cần bằng chứng, script có hash, gộp role, `eligible`, `comparable` (batch và crawl đơn), webhook (chỉ https, không theo redirect, lỗi không lộ URL, escape `<!here>` và `@channel`, chế độ chỉ đếm).

**Lỗi bắt được trong lúc làm:**
1. Luật "endpoint mới mà anon gọi được với 2xx là high" (từ review) biến **mọi** endpoint công khai mới thành high trên target chỉ có anon: đã bỏ.
2. **Snapshot của một batch thành mốc**, và từ đó mọi lần crawl đơn đều "không so được" mãi mãi (vì trước đây chỉ so URL target cuối cùng và tổng số trang). Giờ so **tập** URL bắt đầu.

**Để sau:**
- `authz_changed`: so role trên đúng các run đã chọn;
- thăm dò endpoint lịch sử hay chỉ có trong code;
- `-crawl` để monitor tự gọi crawl.
