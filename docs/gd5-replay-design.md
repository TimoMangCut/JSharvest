# GĐ5.1 — Replay theo cụm và kiểm thử phân quyền

**Mục tiêu** (đánh giá độc lập đợt 3, mục 6; plan GĐ5 "bộ tự replay và fuzz theo cụm"). Biến hai đầu ra đã có thành kết luận có kiểm chứng:
- `diff.json` (4.7) nêu nghi vấn: `client_gated`, `higher_only`, `lower_ok`, `denied_below`…;
- `export/` (4.8) có request thô, `flow.json` (`depends_on`, `prerequisites`) và `params.jsonl` (`derived_from`).

Hai lệnh mới:
- `jsharvest replay`: gửi lại một cụm theo thứ tự, **lấy giá trị mới** cho những chỗ có `derived_from` (token CSRF, id vừa tạo) bằng cách chạy lại request nguồn.
- `jsharvest authz`: lấy request của role cao, **đổi danh tính sang role thấp** (cookie, Authorization, token CSRF mới lấy bằng chính phiên của role thấp), gửi cả bản của role cao (đối chứng) lẫn bản của role thấp, rồi kết luận `bypass`, `enforced`, `partial` hoặc `unclear`. Đây là cách Autorize làm, nhưng đầu vào là các nghi vấn đã được `diff` chọn sẵn, và có làm mới giá trị phụ thuộc.

**Đây là bước đầu tiên jsharvest tự gửi request ngoài trình duyệt.** Chỉ dùng trên target được phép. Mọi thứ dưới đây xoay quanh việc đó.

## 1. An toàn (ràng buộc cứng)

1. **Scope:** chỉ gửi tới host thuộc scope của run (`results.ScopeMode`), thu hẹp được bằng `-scope fqdn` hoặc `-hosts a,b`. Request tới host ngoài scope bị bỏ qua và ghi lại, không bao giờ gửi.
2. **Request đọc** (GET, HEAD, OPTIONS, và GraphQL query) được gửi mặc định, **trừ khi** URL hoặc operation mang động từ hành động (`guard.Destructive`, các động từ của explore: purge, approve, invite…). Những request đó được coi là request ghi.
3. **Request ghi** (method khác, GraphQL mutation, GET mang động từ hành động) cần `-allow-write`.
4. **Request phá huỷ** (DELETE; tên phá huỷ theo `guard.Destructive`; mutation GraphQL hay RPC có tên phá huỷ: delete, remove, purge, wipe, destroy, drop, reset) cần thêm `-allow-destructive`. **Logout và các request kết thúc phiên thì không bao giờ gửi**, dù có cờ nào.
5. **Nhịp:** `-rate` (mặc định 2 request/giây), `-max` (mặc định 300 request mỗi lần chạy). Dừng ngay khi gặp 429, `cf-mitigated`, hoặc 5 lỗi kết nối liên tiếp (giống resolver).
6. **Ghi lại mọi thứ đã gửi:** `sent.jsonl` (0600) gồm request, response, lý do gửi, danh tính dùng, và các giá trị đã được làm mới. `-dry-run` in ra kế hoạch mà không gửi gì.
7. **Proxy:** `-proxy http://127.0.0.1:8080` cho mọi request đi qua Burp, Caido hoặc ZAP để người kiểm thử xem lại.
8. **Không theo redirect.** Redirect được ghi lại và dùng làm tín hiệu (bị chuyển tới trang login nghĩa là `enforced`).

## 2. Danh tính (identity)

Danh tính của một role gồm `Cookie`, `Authorization`, và các header credential (`traffic.Sensitive`: `x-csrf-token`, `x-api-key`, `x-auth-token`…).
- **Nguồn, theo thứ tự ưu tiên:**
  - (a) bản chụp phiên `jsharvest-session.json` của role (4.5): cookie còn hạn tới host;
  - (b) request có header thật mới nhất của role đó tới cùng host (`requests.jsonl`);
  - (c) role `anon`: không có danh tính (bỏ hết các header trên).
- **Kiểm phiên trước khi chạy:**
  - với role có bản chụp phiên: gửi `check_url` của bản chụp; nếu nhận 401/403 hoặc bị chuyển tới trang login thì dừng với thông báo "phiên của role X đã hết: chạy `jsharvest login`";
  - với role cao (bản đối chứng): mỗi mục có request đối chứng riêng (mục 4), nên phiên hết hạn thể hiện thành `unclear` chứ không thành `enforced`.
- **Cookie mới từ server** (`Set-Cookie` trong lúc replay) được cập nhật vào jar của danh tính đó, chỉ trong lần chạy (không ghi đè bản chụp phiên).

## 3. `replay`: gửi lại một cụm, làm mới giá trị phụ thuộc

```
jsharvest replay -target HOST -role R -flow a8 [-as R2] [-allow-write] [-dry-run]
```

- **Kế hoạch:**
  1. Đọc `export/flows/<flow>/flow.json`.
  2. Các request tiên quyết (`prerequisites`, nằm ở cụm khác) chạy trước, theo thứ tự thời gian và không trùng lặp.
  3. Sau đó là các request của cụm, theo thứ tự.
  4. Request không có file thô (ví dụ cụm `background`) bị bỏ qua.
- **Làm mới giá trị:** mỗi liên kết `request X tại <at> ← request Y tại <from_at>`:
  1. Sau khi Y được gửi lại, đọc response mới của Y tại `<from_at>` (`flow.ResponseValues`, cùng cách đặt tên vị trí như `depends_on`).
  2. Ghi giá trị mới vào X tại `<at>` bằng vị trí byte của `export.Params`, mã hoá theo vị trí: path → `PathEscape`, query/form → `QueryEscape`, JSON → escape chuỗi JSON, header → nguyên văn (từ chối nếu có CR/LF).
  3. Nếu không đọc được giá trị mới thì giữ giá trị cũ, và ghi `stale` vào `sent.jsonl`.
- **`-as R2`:** chạy cả cụm bằng danh tính của role khác; bước nguồn cũng chạy bằng danh tính đó, nên token CSRF là token của R2.
- **So với bản ghi gốc:** ghi status gốc và status mới cho từng bước. Kết quả nằm ở `replay/<flow>-<time>/` (`sent.jsonl`, `summary.json`).

## 4. `authz`: kiểm thử phân quyền theo `diff.json`

```
jsharvest authz -target HOST [-roles anon,user,admin] [-classes client_gated,higher_only,lower_ok,denied_below,shape_differs,not_covered] [-allow-write] [-allow-destructive]
```

- **Chọn mục:** endpoint trong `diff.json` thuộc các lớp đã chọn. Mặc định là mọi lớp trừ `same` và `unreached`, vì `unreached` không có request nào để dùng làm mẫu.
- **Request mẫu:** bản đại diện của endpoint trong `export/` của **role thấp nhất dùng được** endpoint đó (`lowest`), hoặc của role cao nhất có request mẫu. Lấy kèm `flow.json` để biết các bước nguồn của nó.
- **Với mỗi role R thấp hơn role của mẫu:**
  1. **Đối chứng:** gửi mẫu bằng danh tính của chính role mẫu (các giá trị phụ thuộc được làm mới bằng phiên của role đó).
  2. **Thử:** gửi mẫu bằng danh tính của R. Các bước nguồn (ví dụ `GET /api/csrf`) cũng chạy bằng danh tính của R, để token là token của R. Id và tham số trong path, query, body **giữ nguyên của role cao**, vì đó chính là điều cần thử (truy cập đối tượng của người khác).
  3. **Kết luận:**
     | Kết luận | Điều kiện |
     |---|---|
     | `unclear` | đối chứng không ra 2xx (phiên hết hạn, trạng thái đã đổi), hoặc thử ra 5xx hay lỗi mạng |
     | `enforced` | thử ra 401 hoặc 403, bị chuyển tới trang login, hoặc ra 404 trong khi đối chứng ra 2xx |
     | `bypass` | thử ra 2xx, và body **giống** đối chứng: bằng nhau sau khi bỏ các giá trị thay đổi theo lần gọi, **hoặc** cùng tập khoá JSON (Jaccard ≥ 0.9) và độ dài lệch không quá 2 lần |
     | `partial` | thử ra 2xx nhưng body khác (đã lọc theo quyền, mảng rỗng, chỉ có trường công khai): cần người xem |
     | `skipped` | là request ghi mà không có `-allow-write`, request phá huỷ mà không có `-allow-destructive`, request kết thúc phiên, hoặc ngoài scope |
- **Output:** `<out>/<host>/authz/` gồm:
  - `authz.json` và `authz.md`: mỗi mục có lớp trong diff, role mẫu, kết luận cho từng role thấp hơn, status và kích thước của đối chứng và bản thử, file `.http` của bản thử để tái hiện bằng tay;
  - `sent.jsonl`;
  - quyền 0600/0700.

## 5. Package

- `internal/replay`:
  - `identity.go`: nguồn danh tính, jar, đổi danh tính trên request thô;
  - `patch.go`: ghi giá trị theo vị trí, mã hoá theo vị trí; hàm thuần, dùng `export.Params`;
  - `send.go`: transport, nhịp, dừng, proxy, `sent.jsonl`;
  - `policy.go`: đọc/ghi/phá huỷ/kết thúc phiên; dùng luật của `guard`;
  - `compare.go`: kết luận; hàm thuần;
  - `flow.go`: kế hoạch và chạy một cụm.
- `cmd/jsharvest/replay.go`, `authz.go`.

## 6. Fixture và gate

**Fixture:**
- **flows-app:** token CSRF có **hạn dùng**: nonce mang thời điểm cấp, server từ chối token quá `-csrf-ttl` (mặc định 1 giờ; gate đặt 3 giây). Khi đó replay nguyên file đã ghi ra 403, còn `replay -flow` có làm mới ra 200.
- **role-app:** truth `authz.truth.json`. User so với admin:
  - `admin/summary` → `bypass`;
  - `admin/stats`, `admin/users` → `enforced`;
  - `admin/invite` → `skipped` (không có `-allow-write`), và `enforced` khi có `-allow-write`;
  - `DELETE admin/users/7` và `PurgeUsers` → `skipped` khi chỉ có `-allow-write`; `PurgeUsers` là `bypass` khi có thêm `-allow-destructive`;
  - `rpc?action=purge` → `skipped` khi không có `-allow-write`;
  - anon: `enforced` ở mọi endpoint admin; `me/inbox` bị chuyển tới login → `enforced`.

  Thêm một endpoint `partial`: user nhận danh sách đã lọc.

**Gate `testbed/replay-check.sh`:**
1. flows-app:
   - replay nguyên file sau khi token hết hạn → 403;
   - `replay -flow <save>` → 200, với token mới khác token cũ;
   - `-dry-run` không gửi gì;
   - request ngoài scope không gửi;
   - không có `-allow-write` thì request ghi bị `skipped`.
2. role-app (dùng lại crawl của `roles-check.sh`):
   - `authz` khớp truth ở 3 tổ hợp cờ: mặc định, `-allow-write`, `-allow-write -allow-destructive`;
   - log server chỉ có đúng các request mà `sent.jsonl` ghi, và không có request nào bị `skipped`;
   - không bao giờ có logout.
3. Phiên của role thấp hết hạn (server khởi động lại sẽ mất session) → `authz` dừng với thông báo, không kết luận `enforced`.

## 7. Ngoài phạm vi (để sau)

- Thăm dò endpoint chỉ có trong code (Reviewer 5.1 mục 3).
- Fuzz tự động theo `params.jsonl`.
- Guard lấy cookie bằng CDP lúc giữ request (NEW-4.8-02).
- Gửi qua Chrome (giữ TLS fingerprint): hiện dùng Go `net/http` cùng UA đã ghi; với target có anti-bot thì dùng `-proxy` hoặc làm tay.

## 8. Đánh giá độc lập (2026-11-04) — có hiệu lực cao hơn mục 1–7

Reviewer đọc code, `diff.json` thật của role-app và các route testbed. Mình kiểm lại trên dữ liệu những điểm kiểm được (1, 5, 9, 10): **đều đúng**.

**Lỗ hổng của guard từ 4.6, lộ ra nhờ review này.** Trong crawl `-explore` của roles-check, admin bấm "Purge cache", và `GET /api/ra/rpc?action=purge` **đã tới server** (`diff.json`: `admin: used`, 200). Lý do:
- `destructiveRe` không có purge, wipe;
- `actionVerb` chỉ xét path;
- với `-allow-write`, mutation `PurgeUsers` cũng lọt vì tên không khớp.

Đã sửa trước khi làm 5.1, thành một commit riêng:
- `destructiveRe` thêm `purge|wipe|truncate|erase`; `Destructive` vốn xét cả query, nên `?action=purge` bị chặn ở mọi chế độ;
- explore xét động từ hành động trong giá trị của tham số operation (`action=`, `op=`…);
- method thật lấy từ header ghi đè và `_method` (`guard.EffectiveMethod`); DELETE nguỵ trang luôn bị coi là phá huỷ.

**Quyết định cho 5.1 (thay cho mục 1–6 ở những chỗ khác nhau):**

1. **Bộ phân loại riêng cho replay** (`replay/policy.go`), dựa trên guard nhưng chặt hơn:
   - method thật (`EffectiveMethod`);
   - động từ hành động và động từ phá huỷ được xét trên path, giá trị query, giá trị body form và JSON, `flow.Operation`, **tên root field** của GraphQL, mọi operation trong một batch, và `method`/`action` của JSON-RPC;
   - không đọc được operation (persisted query chỉ có hash, batch không parse được) thì coi là phá huỷ;
   - request bị guard giữ ở bất kỳ role nào thì ít nhất là request ghi;
   - POST chỉ để đọc được cho qua bằng `-read-allow REGEX`.
2. **Không bao giờ gửi các luồng xác thực** (login, signin, token, refresh, oauth, sso, saml, password, mfa, impersonate, switch-account), trừ khi có `-allow-auth REGEX`. Cũng không gửi các endpoint mà response đã ghi có `Clear-Site-Data` hoặc xoá cookie dấu hiệu. Trong lúc chạy, nếu gặp `Clear-Site-Data` hoặc `Set-Cookie` xoá cookie danh tính thì **dừng**, và các kết luận từ đó về sau là `unclear`.
3. **Thứ tự gửi:**
   - **bản thử gửi trước bản đối chứng**, để cache dùng chung (CDN không có `Vary: Cookie`) không bị điền bằng response của admin; bản thử có `Age`, `X-Cache: HIT` hoặc `CF-Cache-Status: HIT` thì kết luận `unclear`;
   - với request ghi: **không gửi đối chứng** (trừ khi có `-control-writes`), và chỉ kết luận qua tín hiệu từ chối;
   - `authz` **không có `-allow-destructive`** ở v1; cờ này chỉ dành cho `replay` một cụm.
4. **Làm mới giá trị trong `authz` chỉ áp dụng cho credential**: tên theo `traffic.Sensitive`, `refresh: likely` có tên dạng credential, và nguồn `cookie:`. Liên kết `unknown` giữ nguyên giá trị của role cao, vì id là thứ cần thử. Trong `replay`: làm mới liên kết `likely` theo mặc định, liên kết `unknown` chỉ khi có `-refresh-all`.
5. **Kiểm phiên bằng request "sống"** lấy từ traffic của chính role đó: GET, ra 2xx, trả JSON, và `diff` cho thấy role thấp hơn bị từ chối (ví dụ `/api/me`). Không dùng `check_url`: của role-app là `/?in=1`, một trang SPA luôn trả 200. Sau mỗi 401, 403 hoặc chuyển tới login ở bản thử, kiểm phiên lại; nếu phiên chết thì dừng, và mọi kết luận kể từ lần kiểm phiên tốt gần nhất chuyển thành `unclear`.
6. **Danh tính gộp theo từng loại** (cookie từ bản chụp phiên, cộng Authorization và header credential từ traffic):
   - request của role cao có loại credential mà role thấp không có → `unclear: no equivalent credential`, không bỏ trống;
   - loại bỏ giá trị `REDACTED_`, header tạm, và JWT đã hết hạn (`exp`);
   - credential của role cao nằm trong query hoặc body (tên nhạy cảm) phải được thay, nếu không thì `unclear`;
   - liệt kê trong báo cáo các header tuỳ biến còn giữ của role cao (`X-User-Id`…).
7. **Lỗi CSRF không được tính là bị từ chối:**
   - liên kết credential nào chưa làm mới được (`stale`), hoặc bước nguồn không ra 2xx → `unclear`;
   - nguồn được phép là `Document` (dựng từ log, không cần file đã xuất);
   - giá trị có nguồn `cookie:` (double-submit `XSRF-TOKEN`) đọc từ jar;
   - bản thử bị 403 hoặc 419 trong khi vẫn mang tham số dạng CSRF của role cao chưa làm mới (ví dụ multipart) → `unclear`.
8. **Kết luận:**
   - gửi đối chứng hai lần để biết trường nào thay đổi theo lần gọi, rồi che các trường đó;
   - `bypass`: bản thử ra 2xx và body (đã che) **bằng** đối chứng;
   - `likely`: chỉ cùng hình dạng (cùng khoá JSON);
   - `needs-review`: body khác (đổi tên từ `partial`);
   - **thử thêm không danh tính** cho mỗi mục: nếu cũng bằng đối chứng thì `unauthenticated`;
   - Content-Type khác đối chứng (HTML 200 cho endpoint JSON, SPA fallback) → `unclear`;
   - 400, 405, 409, 419, 422 → `unclear`; 3xx không về login → `unclear`;
   - 403 có dấu hiệu WAF (`cf-mitigated`, trang chặn) → dừng cả lần chạy;
   - loại OPTIONS.
9. **Mẫu lấy từ role `native`**, hoặc từ role cao nhất có request thật, rồi thử mọi role thấp hơn. Với `shape_differs`, mẫu lấy từ role gửi thêm tham số.
10. **Fixture role-app làm lại cho đúng server:**
    - graphql và rpc có kiểm quyền theo operation;
    - mỗi route admin trả dữ liệu riêng;
    - log server ghi role của từng request.
    - Các bẫy:
      - 200 kèm body lỗi;
      - SPA fallback;
      - dữ liệu công khai giống nhau cho mọi role;
      - danh sách bị lọc nhưng cùng khoá;
      - đối tượng của chính mình (bỏ qua id);
      - trường thay đổi theo lần gọi (timestamp);
      - một request ghi của admin có CSRF;
      - nguồn CSRF bị gate theo role (kỳ vọng `unclear`);
      - 403 kiểu WAF.
11. Gate kiểm thêm: không có cookie, Authorization hay giá trị CSRF nào của role cao trong bất kỳ bản thử nào ở `sent.jsonl`.
12. **Mạng:**
    - mặc định chỉ gửi tới **đúng các host** của mẫu;
    - từ chối file có `Host` khác authority của URL;
    - phân giải tên miền một lần rồi gắn IP khi kết nối; từ chối nếu loại IP (công khai hay nội bộ) khác `remote_ip` đã ghi (chống DNS rebinding); với `-proxy` thì không kiểm được điều này, và có ghi rõ;
    - dùng `cookiejar` với public suffix list.
13. Đường dẫn JSON có chỉ số mảng (`$.items[3].id`): chỉ dùng khi các khoá anh em giống bản ghi, nếu không thì `stale`.
14. `authz` không bao giờ chạy lại một bước nguồn là request ghi (`POST /api/notes`): dùng giá trị đã ghi và đánh dấu. `-dry-run` liệt kê các bước bị bỏ và các liên kết vì thế thành `stale`.
15. **Ngân sách:** `-max` tính cả bước nguồn, đối chứng, kiểm phiên và bản thử; `-dry-run` in tổng. Dừng khi gặp 503 có `Retry-After`, hoặc khi đối chứng thất bại N lần liên tiếp.
16. `authz.md` mặc định che giá trị; file thô 0600.
17. Khoá query lặp lại: chỉ sửa lần xuất hiện đầu tiên, và ghi chú điều đó. Phiên gắn với TLS fingerprint hay DBSC sẽ hiện thành đối chứng thất bại (`unclear`), đúng như mong đợi.

**Nguồn dữ liệu:** replay dùng mô hình của `export` (một API mới `export.Load` trả về các request đã vá header tạm, có template, khoá, liên kết và tham số), không đọc thư mục `export/`. Nhờ đó các bước nguồn không có file thô (`Document`) vẫn chạy được.

**Thứ tự làm:** (a) fixture và truth → (b) `policy`, `identity`, `compare` (hàm thuần, kèm test) → (c) `send`, `flow`, `authz` → (d) gate.

## 9. Kết quả (2026-11-04)

**Lệnh:**
- `jsharvest authz -target HOST [-allow-write] [-control-writes] [-classes …] [-rate 2] [-max 300] [-proxy URL] [-hosts …] [-read-allow RE] [-allow-auth RE] [-dry-run]`;
- `jsharvest replay -target HOST -flow ACTION [-role R] [-as R2] [-allow-write] [-allow-destructive] [-keep-ids] …`.

**Package `internal/replay`:**
- `policy.go`: bộ phân loại (đọc, ghi, phá huỷ, không bao giờ gửi);
- `identity.go`: danh tính, `Apply`;
- `patch.go`;
- `compare.go`: `Judge`;
- `send.go`: `Sender`;
- `authz.go`, `flow.go`, `report.go`.

`export.Load` và `export.Best` mở mô hình của export cho replay.

**Fixture `authz-app`** (route `/api/az/*`, login dùng chung `/api/login`) có 12 endpoint của admin. Mỗi endpoint là một trường hợp server kiểm đúng, kiểm sai, không kiểm, hoặc là một bẫy cho kết luận. Truth `authz.truth.json` ghi kết luận cho user và anon, có và không có `-allow-write`. flows-app có thêm hạn dùng cho token CSRF (`TESTBED_CSRF_TTL`).

**Gate `testbed/replay-check.sh`:**

| | Kết quả |
|---|---|
| B. authz chỉ đọc | 24/24 kết luận đúng (bypass 1, unauthenticated 2, enforced 7, needs-review 6, unclear 2, skipped 6); 22 request của role thấp không mang bí mật nào của admin; log server khớp từng request với `sent.jsonl`; không có request ghi, wipe, login hay logout |
| C. `-allow-write` | 24/24 (`notes` của user là `bypass`, `invite` là `enforced`, anon `unclear` vì nguồn CSRF trả 401); 31 request không rò bí mật; không bao giờ có wipe |
| D. `-dry-run` | log server không đổi; mọi kết luận là `skipped: dry run` |
| E. mọi phiên đã chết | chỉ còn `unclear` (18) và `skipped` (6); có thông báo "session is dead"; chỉ gửi 2 request kiểm phiên |
| F. flows-app, token hạn 3 giây | gửi nguyên request đã ghi → 403; `replay -flow` → GET csrf 200, POST profile 200 với `header:x-csrf-token` mới; không có `-allow-write` thì POST là `skipped`; `-dry-run` không gửi gì |

**Lỗi do gate bắt được** (đã sửa, và gate giờ chặn chúng tái diễn):
1. **Rò credential:** credential không làm mới được (token CSRF của anon, vì nguồn trả 401) vẫn mang giá trị của admin, và bản thử của anon gửi đi **token CSRF của admin**. Giờ credential như vậy bị gỡ (`dropCredential`), không bao giờ giữ giá trị của role cao.
2. Chạy thử báo nhầm phiên đã chết, vì request kiểm phiên được "trả lời" là `dry run`.
3. Phiên của role mẫu đã chết mà vẫn kết luận (endpoint không kiểm quyền vẫn trả 200 cho cookie chết). Giờ mọi bản thử là `unclear` và không gửi gì.
4. Token theo phiên (`GET /api/az/csrf`): hai lần đối chứng khác nhau ở mọi trường, nên che hết thì "bằng nhau", thành `bypass` giả. Giờ khi mọi trường đều thay đổi thì kết luận là `needs-review` ("nothing stable to compare").

**Lỗ hổng guard từ 4.6** (`?action=purge` tới server): sửa trong cùng đợt, ghi ở `docs/gd4-explore-design.md` mục 15.

**Giới hạn:**
- chưa có kiểm thử với WAF thật (mới có unit test cho `cf-mitigated` và trang chặn);
- liên kết có chỉ số mảng chưa kiểm khoá anh em (mục 8.13): nếu không đọc được giá trị thì thành `stale`, còn nếu đọc được ở vị trí đã đổi thì chưa phát hiện;
- endpoint chỉ có trong code chưa được thăm dò;
- guard chưa lấy cookie qua CDP lúc giữ request;
- gửi bằng Go `net/http`, nên TLS fingerprint khác Chrome (dùng `-proxy` khi target có anti-bot).

## 10. Đánh giá độc lập đợt 4 (2026-11-04)

Kiểm lại từng điểm trên code; cả 6 đều đúng và đã sửa:
- **NEW-5.1-01 (Medium):** bản ghi catalog chỉ thấy trong traffic (không có nguồn tĩnh) làm `gatedBy` trả -1, xoá mất `native` lấy từ script riêng của admin. Giờ chỉ bản ghi có nguồn tĩnh mới góp vào `gates`. role-app không có bản ghi `observed` nên gate không bắt được.
- **NEW-5.1-02:** bản thử không danh tính nay gỡ cả credential trong query và body (`strip`).
- **NEW-5.1-03:** `downgrade` chỉ hạ các kết luận từ lần kiểm phiên tốt gần nhất (`roleCtx.good`).
- **NEW-5.1-04:** với `shape_differs`, mẫu lấy từ role cao nhất có dùng, không lấy từ `native`.
- **NEW-5.1-05:** một `Document` cùng cụm, là nguồn của giá trị (token trong `<meta>`), nay được replay.
- **NEW-5.1-06:** `Patch` và `dropCredential` giữ JSON hợp lệ ở ô kiểu số, boolean hay null; `POST /api/profile` của testbed trả 400 khi body không phải JSON.
