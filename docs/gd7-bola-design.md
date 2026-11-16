# GĐ7 (Bước 29) — Kiểm thử BOLA ngang (`authz -peers`)

**Mục tiêu** (`docs/plan-28.md` mục 6 và 4.3). `jsharvest authz` hiện hành (`docs/gd5-replay-design.md`) kiểm phân quyền **dọc** dựa trên `diff.json` (`anon < user < admin`). Với hai tài khoản **ngang quyền** (`userA`, `userB`), cả hai cùng gọi được một tập endpoint nên `diff.json` xếp chúng vào lớp `same` và loại bỏ; ngoài ra `compareBodies` so khớp toàn bộ body, dễ kết luận sai khi server bỏ qua `userId` (trả đối tượng của chính B), phản chiếu lại `id_A` trong thông báo rỗng, hoặc khi B là tài khoản mới chưa có dữ liệu.

Tài liệu này thiết kế chế độ kiểm thử BOLA/IDOR ngang:

```
jsharvest authz -target HOST -peers userA,userB -relation same-org|cross-org [flags]
```

Đọc trực tiếp dữ liệu `export.Load` của hai peer, thử cả hai chiều `userA -> userB` và `userB -> userA`, đối chứng tam giác (`Trial`, `Control`×2, `Self` hoặc `Bogus`), và **chỉ kết luận `bypass` khi response của bản thử chứa giá trị riêng đã kiểm chứng của phía chủ sở hữu**.

---

## 1. An toàn và bất biến (ràng buộc cứng)

Chế độ `-peers` tự gửi request thật lên mục tiêu, nên kế thừa toàn bộ rào chắn của `replay` và các bất biến trong `CLAUDE.md`:

1. **Chính sách gửi (`internal/replay/policy.go`):**
   - Mặc định **chỉ gửi `Read`** (`GET`, `HEAD`, và GraphQL `query` đã đọc được AST). `OPTIONS` bị loại (`Excluded`).
   - Request `Write` (`POST`, `PUT`, `PATCH`, GraphQL `mutation`/`subscription`, request từng bị `guard` giữ ở bất kỳ peer nào, hoặc `GET`/GraphQL `query` mang động từ hành động) chỉ gửi khi có `-allow-write`.
   - **Danh sách động từ hành động riêng của `replay`:** bổ sung regex riêng `replayActionRe = (?i)verify|magic|regenerate|refresh` (kiểm theo ranh giới từ `word()`, ghép OR với `guard.NamesAction` trong hàm `namesReplayAction` của `internal/replay/policy.go`) và áp lên cả `GET`/`HEAD` lẫn GraphQL `query` (xét trên `path`, `query`, `gql.names` gồm tên operation + root fields, và `bodyValues`). Lý do: gửi lại link xác thực email, magic link, hoặc endpoint xoay API key/token sẽ tiêu huỷ token dùng một lần hoặc làm hỏng credential thật của peer. **Tuyệt đối không thêm bốn từ này vào `internal/guard/rules.go`** để không chặn nhầm request đọc hợp lệ trong lúc trình duyệt crawl (`/verify-status`, `/magic-link-info`, `/refresh-preview`).
   - Request `Destructive` (`DELETE`, DELETE nguỵ trang qua `guard.EffectiveMethod`, tên khớp `guard.NamesDestructive`, GraphQL persisted query không đọc được nội dung) **không bao giờ gửi trong `authz`** (`-allow-destructive` chỉ dành cho `replay -flow`).
   - Luồng xác thực (`authFlowRe`), kết thúc phiên (`sessionEndRe`: logout/signout/revoke/expire), hoặc endpoint từng trả `Clear-Site-Data` → `Never`, không bao giờ gửi. Trong lúc chạy, nếu nhận `Clear-Site-Data` hoặc `Set-Cookie` xoá cookie danh tính của bất kỳ peer nào (`updateJar`) thì dừng ngay toàn bộ lượt chạy và hạ các kết luận bị ảnh hưởng về `unclear`.
2. **Cách ly credential giữa hai peer:**
   - Mọi liên kết credential (`credentialLink`: header nhạy cảm, `cookie:`, tham số query/form/body khớp `traffic.Sensitive` trừ tham số chữ ký URL ở mục 4.5) phải được làm mới bằng chính phiên của peer thử; không làm mới được (`stale`) thì gỡ bỏ bằng `dropCredential`, **không bao giờ gửi giá trị credential của peer A dưới danh tính peer B**.
   - Cookie hạ tầng CDN (`traffic.CDNCookie`: `__cf_bm`, `cf_clearance`…) được `Sender` giữ tách biệt trong RAM theo từng tên peer (`Sender.cdn[role]`), không nạp từ snapshot đĩa và không dùng chung giữa `userA`, `userB` và `(none)`.
   - Phiên chết của A hoặc B không bao giờ sinh ra `enforced`: chỉ sinh `unclear`.
3. **Mạng và OpSec (`internal/replay/send.go`, `internal/netsafe`):**
   - Chỉ gửi tới đúng tập `host:port` trong scope xuất hiện ở các request ứng viên, bước nguồn và `probe` của hai peer (`Sender.Allow`), trừ khi người dùng thu hẹp thêm bằng `-hosts`.
   - Đi qua `netsafe.Dialer` + `netsafe.Guard`: phân giải DNS một lần, kiểm mọi IP qua bộ kiểm private dùng chung (gồm CGNAT, unspecified), gắn IP khi nối, giữ SNI là hostname gốc, chống DNS rebinding so với `response.remote_ip` đã ghi; tôn trọng `-host-resolver-rules` và `AllowPrivate` (target nội bộ); kiểm IP literal chuẩn WHATWG và `localhost`/`*.localhost` ở tầng request khi có `-proxy`; dùng chung một nguồn proxy `netsafe.ProxyFrom`.
   - `User-Agent` lấy từ phiên đăng nhập/traffic đã ghi (`observedUA`) hoặc `uahints.LocalChromeUA`, kèm HTTP/2 (`ForceAttemptHTTP2: true`), không bao giờ gửi `Go-http-client` hay `HeadlessChrome`. Không theo redirect (`http.ErrUseLastResponse`).
   - Ngân sách `-max` (mặc định 300) và nhịp `-rate` (mặc định 2 req/s) tính gộp mọi request phát sinh (`probe`, `source`, `trial`, `control`×2, `self`, `bogus`, `no-identity`, và các phép thử `-substitute`). Bị WAF chặn thì xử lý theo `-on-block` (mặc định `host`), phân loại bằng `detect.Classify`.
4. **Dữ liệu đầu vào sạch từ `guard` và `capture`:**
   - Bỏ qua mọi request nội bộ (`q.Internal` / tag `jsharvest`) và trang/script challenge (`q.Challenge` / tag `challenge`).
   - Request từng bị `guard` giữ (`r.Held`, header `X-Jsharvest-Guard`, body giả `200 {}`) chỉ có `headers_provisional`: không bao giờ coi response giả của `guard` là response thật của A (không dùng để đối chiếu `replay_broken` và không đưa vào tập giá trị đã thấy của B).

---

## 2. Đầu vào, danh tính sống và quan hệ khai báo

### 2.1. Nguồn dữ liệu (hai chiều, không qua `diff.json`)

Với `-peers userA,userB` trên `<out>/<targetDir>`:
1. Kiểm tra hai tên peer khác nhau, khớp `roleRe`, không phải `anon` hay `archive`.
2. Đọc mô hình traffic của từng peer trực tiếp bằng `export.Load`:
   ```go
   cat, _ := endpoints.Read(filepath.Join(o.Root, peer))
   m, err := export.Load(export.Options{
       Dir:     filepath.Join(o.Root, peer),
       Run:     "all",
       InScope: o.InScope,
       Catalog: cat,
   })
   ```
   Truyền `Catalog` (từ `endpoints.jsonl` của peer) để `export.Load` điền `{}` cho cả các path segment kiểu slug mà phân tích tĩnh JS đã biết nhưng peer chỉ mới gọi 1–2 giá trị (`flow.EntryTemplates` một mình cần $\ge 3$ giá trị khác nhau).
3. Đọc thêm toàn bộ response đã ghi của `<out>/<targetDir>/anon` (nếu thư mục `anon` tồn tại) qua `results.Open(anonDir)` thay vì `export.Load` — vì `anon` mặc định chạy bằng engine HTTP nên không có `flows.jsonl` (`export.ErrNoFlows`). Nếu không có thư mục `anon`, ghi chú vào `BolaReport.Notes` (`anon_loaded: false`); probe `NoIdentity` trực tiếp lúc chạy vẫn luôn hoạt động.
4. Thực thi đối xứng cả hai chiều: `(owner = userA, as = userB)` và `(owner = userB, as = userA)`.

### 2.2. Danh tính peer và ràng buộc token sống (`plan-28.md` 4.3 ràng buộc 1)

Danh tính mỗi peer `P` được dựng từ `<profiles>/<targetDir>/<P>/jsharvest-session.json` (`session.Load`) kết hợp với danh sách `traffic.Entry` của `P` (theo thứ tự thời gian cũ → mới), tái sử dụng và mở rộng `NewIdentity(role, snap, entries, now)` trong `internal/replay/identity.go`:

1. **Yêu cầu phiên sống (ràng buộc 4.3.1):** trong lúc `crawl -role P` (P4.5), khi trình duyệt xoay vòng cookie hoặc token trong `localStorage`/`sessionStorage` (qua OAuth `grant_type=refresh_token` hoặc refresh BFF trong `-guard-allow`), `keeper` cập nhật `keeper.login.Snapshot` và ghi lại `jsharvest-session.json` ở cuối phiên crawl (**chỉ ghi khi `!session.Lost`**). Nhờ đó `snap` trên đĩa tại thời điểm chạy `authz -peers` mang bộ cookie và storage **còn sống** mới nhất, không phải token đã bị thu hồi lúc đầu phiên. Nếu `run.json` mới nhất của `P` ghi `session.lost == true`, `authz` ghi cảnh báo rõ vào `Notes`.
2. **Cookie (`id.Jar`):** nạp từ `snap.Cookies` còn hạn (bỏ cookie CDN và giá trị `REDACTED_`); chỉ khi không có `snap` mới lùi về header `Cookie` mới nhất theo từng host trong `entries`. `Set-Cookie` mới nhận được trong lúc `authz` chạy được `updateJar` cập nhật vào `id.Jar` trong RAM (nếu cookie danh tính bị xoay vòng giữa chừng, đặt `rc.rotates = true` để tuần tự hoá các request của peer đó qua `rc.serial`, tránh race thu hồi phiên).
3. **Header credential (`id.Creds`) và token trong `snap.Storage`:**
   - Quét ngược `entries` từ mới nhất về cũ nhất để lấy các header `credential(name)` (`Authorization`, `X-Api-Key`, `X-Auth-Token`… không `HeadersProvisional`, không `held_back`, không `REDACTED_`).
   - **Bổ sung đọc `snap.Storage` (`resolveStorageCred`):** nếu giá trị header mới nhất trong `entries` là JWT đã hết hạn (`expiredJWT(v, now)`) — hoặc phiên vừa xoay token vào `localStorage`/`sessionStorage` ngay cuối buổi crawl trước khi kịp phát sinh thêm XHR — hàm `resolveStorageCred(snap, host, hdrName, oldVal, now)` tìm trong `snap.Storage[origin]` (`Local` và `Session`, kể cả chuỗi JSON lồng nhau) token còn hạn cùng định dạng:
     - Với `Bearer <jwt>`: tìm JWT chưa hết hạn có cùng `iss`/`sub` (nếu claim có mặt) và `exp` lớn hơn `oldVal`, thay phần `<jwt>` giữ nguyên tiền tố `Bearer `.
     - Với token mờ (opaque) từng xuất hiện trong `entries` tại một khoá `k` của storage: nếu `snap.Storage[origin]` tại đúng khoá `k` nay giữ giá trị mới khác rỗng và không `REDACTED_`, dùng giá trị mới đó.
     - Không bao giờ tự đoán tên header nếu `entries` chưa từng gửi header đó.
4. **Kiểm phiên sống (`pickPeerProbes` + `alive`):**
   - Vì không có `diff.json`, `pickPeerProbes` chọn cho mỗi peer `P` một request `GET` (`Policy.Classify == Read`, `!Provisional`, `!Held`, trả 2xx JSON), ưu tiên URL khớp `snap.Signs.CheckURL` hoặc đường dẫn định danh phiên (`/me`, `/self`, `/whoami`, `/profile`, `/session`), sau đó đến các `GET` 2xx JSON khác của `P`.
   - Khi khởi động, xác nhận ứng viên `probe` bằng tối đa một lần gửi không danh tính (`stripPeer` → phải bị từ chối 401/403/redirect login) và một lần gửi dưới danh tính `P` (phải trả 2xx và không `bodyErrors`). Nhờ đó không bao giờ chọn nhầm endpoint công khai làm `probe`. Nếu `P` chết ngay đầu phiên, mọi phép thử dùng `P` đều nhận `unclear` và không gửi bản thử vô ích; sau mỗi 401/403/redirect login ở bản thử, gọi lại `alive(ctx, peerB)` và cuối lượt chạy `downgrade()` hạ mọi `enforced` của `peerB` sau mốc `goodAt` gần nhất xuống `unclear`.

### 2.3. Quan hệ khai báo (`-relation same-org|cross-org`)

Khi có `-peers`, cờ `-relation` là **bắt buộc** (`RelSameOrg = "same-org"` hoặc `RelCrossOrg = "cross-org"`):
- **`cross-org`:** hai peer thuộc hai tenant/tổ chức độc lập (hoặc hai người dùng cá nhân tách biệt). Mọi trường hợp peer B đọc được giá trị riêng của peer A (mà `NoIdentity` không đọc được) đều là lỗ hổng phân quyền ngang → **`bypass`**.
- **`same-org`:** hai peer cùng thuộc một tổ chức/workspace. Nhiều ứng dụng cộng tác (dự án chung, tài liệu nhóm, danh bạ nội bộ) cho phép thành viên cùng tổ chức xem tài nguyên của nhau theo thiết kế, kể cả khi peer B tình cờ chưa mở tài nguyên đó lúc crawl. Do đó với request **đọc** khi `Trial(B, id_A)` trả về giá trị riêng của A (và `NoIdentity` bị chặn):
  - Kết luận **`bypass`** chỉ khi có ít nhất một bằng chứng tài nguyên là **riêng tư cấp cá nhân**:
    1. URL hoặc endpoint key khớp cờ `-private REGEX` do người kiểm thử khai báo từ tài liệu/giao diện ứng dụng; **hoặc**
    2. JSON của `Control(A)` mang trường đánh dấu riêng tư tường minh ở đối tượng gốc hoặc `data` (`private: true`, `is_private: true`, `isPrivate: true`, hoặc `visibility`/`access`/`scope` nhận giá trị `"private"`, `"personal"`, `"only_me"`, `"secret"`).
  - Ngược lại, kết luận **`shared`** (`Verdict = "shared"`): ghi đầy đủ bằng chứng (đã che mặc định) và xếp ngay sau `bypass` trong `bola.md` để người kiểm thử rà soát nhanh hoặc chạy lại với `-private`, không làm nhiễu số lượng `bypass`.

---

## 3. Chọn ứng viên và trích xuất định danh (`internal/replay/ids.go`)

### 3.1. Chuẩn hoá khoá endpoint giữa hai peer

Vì `export.Load` giữ nguyên tên placeholder cục bộ (`{id}`, `{uuid}`, `{hash}`, `{param}`, `{}`), hàm `canonEndpointKey(key string) string` đưa mọi `{[^}]*}` trong path template về `{}`, bỏ `/` dư ở cuối (trừ `/`), giữ nguyên `METHOD host/tmpl [op]`. Ngoài ra, `alignPeerTemplates(modelA, modelB)` gom các request cùng `(Method, Host, số segment, frame khởi phát JS)` của cả hai peer khác nhau đúng 1–2 segment dạng slug để đánh dấu thêm `{}` trước khi gom nhóm.

### 3.2. Tập giá trị đã biết của phía đối phương (`SeenSet`)

Với chiều `A -> B`, dựng `SeenOther = BuildSeenSet(entriesOf(B), entriesOf(anon))`:
- Duyệt **mọi** response đã ghi của `B` và của `anon` (status $< 500$, không phải response giả `X-Jsharvest-Guard`, không phải trang challenge).
- Không dùng `flow.ResponseValues` (vốn bỏ mọi chuỗi dài $< 5$ ký tự và cắt ở 200 giá trị mỗi response). Thay vào đó, `BuildSeenSet` duyệt toàn bộ cây JSON (tới độ sâu 30, trần 50.000 lá mỗi response), các thuộc tính `<meta>`/`<input>`/`href` trong HTML và các response header không thuộc `PlainHeader`, ghi nhận:
  - chuỗi nguyên văn của mọi lá scalar (string, số nguyên/thực dạng chuỗi);
  - các path segment trong lá có dạng URL cùng host/in-scope;
  - nếu lá là Relay global ID hợp lệ (`Type:inner`), ghi nhận cả chuỗi base64 gốc (chuẩn hoá không phụ thuộc dấu `=`) lẫn chuỗi giải mã `"Type:inner"` (và `inner` khi `inner` là UUID/ULID/ObjectId/int64).

### 3.3. Phân loại tham số định danh (`ClassifyID`) và loại trừ entropy cao

Từ `r.Params()` của một request `r` thuộc peer A (`r.File == true`, không `Hop > 0`, không `incomplete`/`failed`), xét các vị trí `p.In` thuộc `path`, `query`, `form`, `json`, `multipart` (trừ `.filename`), cộng các custom header định danh không gian làm việc (`header:x-org-id`, `x-tenant-id`, `x-workspace-id`, `x-project-id`, `x-account-id` — tức header không thuộc `PlainHeader` và không phải `credential(name)`):

1. **Loại trừ ngay (`IDNone`):**
   - Path segment ở vị trí hằng số trong `r.Template` (không phải `{...}`, ví dụ `api`, `v1`, `users`, `graphql`), hoặc từ khoá tự thân `isSelfAlias(v)` (`"me"`, `"self"`, `"current"`, `"@me"`, `"~"`).
   - Các lá cú pháp GraphQL: `isQueryName(p.Name)` (`$.query`, `$[n].query`), `$.operationName`, `$[n].operationName`, `$.extensions.*`, `$[n].extensions.*` (ID của GraphQL nằm trong `$.variables.*` hoặc query).
   - Tên tham số điều khiển/phân trang không phải ID (`page`, `per_page`, `pageSize`, `limit`, `offset`, `cursor`, `after`, `before`, `first`, `last`, `sort`, `order`, `order_by`, `dir`, `q`, `search`, `filter`, `fields`, `include`, `expand`, `format`, `locale`, `lang`, `tz`, `version`, `v`) khi giá trị không phải UUID/ULID/Relay.
   - Boolean, `null`, chuỗi rỗng, số thực có phần thập phân, số $\le 0$, ngày giờ ISO-8601 (`dateRe`), hoặc Unix timestamp 10/13 chữ số khi tên tham số chỉ thời gian (`ts`, `time`, `timestamp`, `expires`, `exp`, `iat`, `since`, `until`, `*_at`).
   - **Credential, chữ ký và chuỗi entropy cao:**
     - Tên khớp `traffic.Sensitive(lastName(p.Name))` hoặc `isSignatureParam(name)` (`x-amz-signature`, `x-amz-credential`, `x-amz-security-token`, `x-amz-date`, `x-amz-expires`, `x-amz-signedheaders`, `x-goog-signature`, `x-goog-credential`, `x-ms-sig`, `sig`, `signature`, `hmac`, `mac`, `digest`, `nonce`, `state`, `challenge`, `Policy`, `Key-Pair-Id`).
     - **JWT / JWS:** khớp `^eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*$`.
     - **Chuỗi hex dài $\ge 32$ ký tự** ($\ge 128$ bit: MD5, SHA-1, HMAC-SHA256…) — trong khi ObjectId 24 hex và UUID có gạch nối chuẩn vẫn được nhận diện ở bước dưới.
     - **Chuỗi ngẫu nhiên entropy cao:** độ dài $\ge 24$ ký tự không phải UUID/ULID/Relay/slug có gạch nối chữ thường, có entropy Shannon $H(v) \ge 4{,}0\text{ bit/ký tự}$ và trộn hoa+thường+số (`flow.mixed`).

2. **Giải mã Relay Global ID (`DecodeRelay`):**
   - Thử giải mã base64 chuỗi `v` (độ dài $8..172$) theo 4 biến thể (`StdEncoding`, `RawStdEncoding`, `URLEncoding`, `RawURLEncoding`) sao cho mã hoá ngược lại khớp y hệt `v`.
   - Chuỗi giải mã phải là ASCII in được khớp `^([A-Z][A-Za-z0-9_]{1,63}):([A-Za-z0-9_.-]{1,128})$`, trong đó phần `inner` sau dấu `:` phân loại đệ quy thành một trong các kiểu ID bên dưới (không phải `IDNone`). Khi đó trả về `IDRelay` lưu kèm `RelayType`, `RelayInner`, `InnerKind`, và `B64Variant`.

3. **Các kiểu định danh hợp lệ (`IDKind`):**
   - `IDUUID`: UUID chuẩn `8-4-4-4-12` (ghi nhận nibble phiên bản $1..8$).
   - `IDULID`: Crockford Base32 26 ký tự `^[0-9A-HJKMNP-TV-Z]{26}$`.
   - `IDObjectID`: MongoDB ObjectId 24 ký tự hex `^[0-9a-fA-F]{24}$`.
   - `IDIntSmall`: số nguyên dương `^[1-9]\d{0,9}$` thuộc $[1, 2^{31}-1]$; nếu nằm ở `query`/`form`/`json` mà không có `Derived` và $< 1000$, yêu cầu tên tham số mang nghĩa định danh (`id`, `*_id`, `*Id`, `*ID`, `uid`, `account`, `user`, `org`, `project`, `item`, `order`, `doc`, `wallet`, `voucher`…) để không bắt nhầm cờ số nhỏ.
   - `IDInt64`: số nguyên dương thuộc $[2^{31}, 2^{63}-1]$ (10–19 chữ số, gồm Snowflake ID).
   - `IDRelay`: Relay Global ID `base64("Type:inner")`.
   - `IDSlug`: ID có tiền tố (`usr_...`, `proj-...`, độ dài $< 24$ hoặc phần sau ngắn) hoặc slug chữ thường-số-gạch ngang (`^[a-z0-9]+(?:[-_][a-z0-9]+)*$`, dài $3..64$) nằm ở placeholder `{}` của path, có `Derived` từ response trước của A, hoặc ở tham số có tên kiểu định danh (`slug`, `handle`, `username`, `key`, `project`, `org`, `workspace`).

### 3.4. Điều kiện chọn ứng viên

Một request `r` của peer A là ứng viên theo chiều `A -> B` khi `r` mang **ít nhất một** `ParsedID` mà giá trị của nó **không thuộc `SeenOther`** (`!SeenOther.Has(id)` — kiểm cả giá trị thô lẫn `"Type:inner"` nếu là `IDRelay`, tức không xuất hiện ở **bất kỳ** response nào của B hay `anon`, phép hợp ANY). Gom các ứng viên của A theo `canonEndpointKey(r.Key)` và chọn bản đại diện tốt nhất `export.Best(group)` làm mẫu thử chính cho mỗi endpoint key (nếu một endpoint có nhiều bản mang các tập vị trí ID khác nhau, giữ một mẫu đại diện cho mỗi tập vị trí `at` riêng biệt, tối đa 3 mẫu/endpoint).

---

## 4. Phép thử, đối chứng tam giác, Bogus và bộ kết luận

### 4.1. Phép thử chính và chế độ thay từng tham số (`-substitute`)

1. **Phép thử chính (`mode: "main"`, mặc định):**
   - Lấy nguyên request mẫu `r_A` của A (giữ nguyên toàn bộ path, query, body — với GraphQL lô là mảng một phần tử `[{op}]` mà `export.Load` đã tách theo P1.3 — và giữ nguyên mọi custom/tenant header của A như `X-Org-Id`), chỉ đổi danh tính sang B qua `build(ctx, A, B, r_A, key)`.
   - Các header không thuộc `PlainHeader` và không phải `credential` còn giữ từ A được ghi vào `kept_headers` của báo cáo.
2. **Chế độ thay từng tham số (`-substitute`, tuỳ chọn thêm — mặc định tắt):**
   - Giải quyết bài toán khoá phân cấp ở `cross-org` (ví dụ `GET /orgs/{o}/projects/{p}`: gửi nguyên `/orgs/o_A/projects/p_A` dưới B bị chặn 403 ở tầng kiểm `o_A`, nhưng nếu server quên kiểm quan hệ cha–con `p.org == o`, gửi `/orgs/o_B/projects/p_A` sẽ lộ project `p_A` của A).
   - Khi bật `-substitute`, nếu endpoint `K` có $\ge 2$ vị trí ID, phép thử chính không ra `bypass`/`shared`/`unauthenticated`, và B có request mẫu `Self(B)` trên cùng `K`: với từng vị trí ID chưa thấy của A `at_i` (tối đa 4 vị trí mỗi endpoint), lấy bản thô `Self(B)` của B làm nền (đã mang đúng `o_B` và header tenant của B), gọi `Patch(raw_B, at_i, val_A[at_i])`, gửi dưới danh tính B với `mode: "substitute:" + at_i` và chấm bằng cùng bộ đối chứng tam giác đối với `Control(A, id_A)`.

### 4.2. Trình tự gửi đối chứng tam giác và phát hiện `replay_broken`

Để cache dùng chung (CDN thiếu `Vary: Cookie`/`Authorization`) không bao giờ được điền bằng response của A trước khi B hỏi, thứ tự gửi trên mỗi ứng viên đọc (`Read`, hoặc `Write` khi có `-control-writes`) cố định như sau:

1. **`Trial(B, id_A)`** (`purpose: "trial"`, dưới danh tính B).
2. **`Control_1(A, id_A)`** (`purpose: "control"`, dưới danh tính A):
   - Luôn gửi ít nhất 1 lần đối chứng của A ngay cả khi `Trial(B)` trả 401/403/404, để phân biệt phân quyền thật với request không replay được.
   - **Kiểm `replay_broken`:** nếu `!Control_1.ok()` hoặc `bodyErrors(Control_1.Body, nil) == errAll` (tận dụng bộ phân loại mã lỗi số và mảng gốc của P1.2):
     - Gọi `alive(ctx, peerA)` để kiểm phiên của A. Nếu phiên A đã chết → kết luận **`unclear`** (`"peer A's session is dead"`).
     - Nếu phiên A **vẫn sống** trong khi bản ghi gốc lúc crawl `r_A.Entry.Response` trả 2xx (`!r_A.Held`) và không mang body lỗi → kết luận **`replay_broken`** (`Verdict = "replay_broken"`), nêu rõ mã trả về kèm gợi ý nguyên nhân (request signing/HMAC, anti-replay nonce/timestamp hết hạn, hoặc phiên gắn chặt TLS/DBSC), **không kết luận phân quyền**.
     - Các trường hợp `Control_1` lỗi còn lại → **`unclear`**.
   - Nếu `Trial(B)` không trả 2xx (401, 403, redirect login, 404…): đã đủ dữ kiện kết luận (`enforced` hoặc `unclear`), **dừng sớm**, không tốn thêm request cho `Control_2` và `Self`/`Bogus`.
3. **Khi `Trial(B)` trả 2xx** (cùng `kind` với `Control_1`, không bị cache HIT, không phải `errAll`):
   - Gửi **`Control_2(A, id_A)`** (`purpose: "control"`) để xác định tập đường dẫn JSON thay đổi theo từng lần gọi (`Volatile`: các path `p` mà `flatten(C1)[p] != flatten(C2)[p]`).
   - Tìm request `Self(B, id_B)` trong `matching(peerB.model, K)` (`!Held`, từng trả 2xx, có giá trị ID ở cùng vị trí khác với A). Nếu có, gửi live **`Self(B, id_B)`** (`purpose: "self"`).
   - Nếu không có `Self(B)` (hoặc `Self(B)` gửi live không trả 2xx), dựng và gửi **`Bogus(B, id_giả)`** (`purpose: "bogus"`, mục 4.3).

### 4.3. Quy tắc sinh và kiểm tra `Bogus(B, id_giả)` (`internal/replay/bogus.go`)

Khi peer B không có `Self(B)` trên endpoint `K` (ví dụ B là tài khoản mới trống dữ liệu), lấy `r_A` đổi danh tính sang B và `Patch` các vị trí ID chưa thấy của A bằng giá trị giả sinh từ `crypto/rand` theo đúng kiểu (`BogusID(id, avoidSet)`). Nếu request có khoá phân cấp mà chỉ ID lá chưa thấy (như `orgs/{o}/projects/{p}` ở `same-org`), giữ nguyên `{o}` và chỉ thay ID lá `{p}`; ở `cross-org` có nhiều tầng đều chưa thấy, giữ tầng cha của request đang thử và thay tầng định danh đối tượng lá để thử đúng tầng tra cứu đối tượng.

| Kiểu ID (`IDKind`) | Luật sinh `BogusID` (tuyệt đối **không** dùng `id_A ± k`, không dùng `0`, âm, hay tràn kiểu) |
|---|---|
| `IDUUID` | Sinh 16 byte ngẫu nhiên, gán đúng nibble phiên bản gốc $V \in [1..8]$ (`b[6] = (b[6]&0x0f)\|(V<<4)`) và variant RFC 4122/9562 (`b[8] = (b[8]&0x3f)\|0x80`); riêng UUIDv7 ($V=7$) giữ 48 bit đầu là mốc epoch-ms hợp lệ rồi ngẫu nhiên hoá 74 bit còn lại; giữ nguyên hoa/thường hex. |
| `IDULID` | Giữ tiền tố thời gian 10 ký tự Crockford Base32 hợp lệ (không vượt thời điểm hiện tại) + 16 ký tự Crockford ngẫu nhiên. |
| `IDObjectID` | Giữ 8 ký tự hex timestamp đầu của `id_A` + 16 ký tự hex ngẫu nhiên cùng kiểu chữ hoa/thường. |
| `IDIntSmall` ($1 \le n \le 2^{31}-1$) | Số nguyên dương ngẫu nhiên trong dải cao sát trần `int32`: **`[1_900_000_000, 2_147_483_000]`** (nhỏ hơn `math.MaxInt32 = 2_147_483_647` nên không tràn `INT SIGNED`; nếu bản thân `id_A >= 1_800_000_000` thì lấy trong `[1_400_000_000, 1_700_000_000]` để đảm bảo $\|fake - id_A\| > 10^8$). |
| `IDInt64` ($n > 2^{31}-1$, Snowflake) | Giữ **đúng số chữ số $D = \text{len}(v)$** và giữ 2 chữ số đầu của `id_A` (nên epoch hợp lệ và chắc chắn $\le \text{math.MaxInt64}$, không tràn `BIGINT`), sinh ngẫu nhiên $D-2$ chữ số còn lại sao cho $\|fake - n\| > 10^9$. |
| `IDSlug` | Nếu có tiền tố (`proj_9a8b`, `doc-101`): giữ nguyên tiền tố + dấu nối và sinh ngẫu nhiên phần sau cùng độ dài, cùng lớp ký tự. Nếu là slug thuần (`alpha-roadmap`): sinh `"z-"` + chuỗi `[a-z0-9]` ngẫu nhiên cùng độ dài ($\ge 12$ ký tự). |
| `IDRelay` | Giải mã `Type:inner`, gọi đệ quy `BogusID(inner)`, ghép `"Type:" + fakeInner` rồi mã hoá lại theo **đúng biến thể base64 và dấu đệm `=`** ban đầu. |

**Cầu chì Bogus trả 200 kèm dữ liệu (`bogusHasData`):**
- Nếu `Bogus(B)` trả 2xx, cùng `kind` với `Control_1`, `bodyErrors(Bogus.Body, Control_1.Body) == errNone`, và sau khi loại bỏ các lá `metaKeys`, giá trị rỗng/`null`/`[]`/`{}` cùng chính chuỗi `bogus_id` bị phản chiếu mà vẫn còn dữ liệu thật (`!noData`):
  - Endpoint này trả dữ liệu mặc định/fallback cho mọi ID bất kỳ → **không thể kết luận BOLA**.
  - Gán kết luận **`unclear`** (`"bogus ID answered 200 with data; stopping trials on this endpoint"`), đánh dấu `stopped_endpoints[K]` và **dừng thử mọi ứng viên còn lại của endpoint `K`** trong cả lượt chạy.

### 4.4. Luật kết luận và trích bằng chứng riêng của A (`JudgePeer` trong `internal/replay/compare.go`)

Hàm thuần `JudgePeer(c PeerCase) PeerJudgement` hoạt động tách biệt, **không sửa `Judge(Case)` của RBAC dọc** (đảm bảo `replay-check` giữ nguyên 100% hành vi):

1. **Tập giá trị phản chiếu từ request (`SentSet`):** mọi `p.Value` trong `r_A.Params()` (đã unescape), path/URL thô, và với mọi `IDRelay` trong request thì thêm cả chuỗi base64, `"Type:inner"` lẫn `"inner"` (chống trường hợp GraphQL nhận Relay ID nhưng trả `databaseId: inner` trong body).
2. **Tập giá trị riêng của A trong `Control(A)` (`uniqueEvidence`):**
   - Làm phẳng JSON bằng `flatten` (đã sắp chuẩn tắc phần tử mảng qua `sortedItems`/`canonSig` của P1.2): $M_{C1} = \text{flatten}(C_1)$, $M_{C2} = \text{flatten}(C_2)$, $M_T = \text{flatten}(\text{Trial})$, $M_{\text{ref}} = \text{flatten}(\text{Self hoặc Bogus})$.
   - Xét các cặp $(p, v) \in M_{C1}$ thoả đồng thời:
     - (i) ổn định qua hai lần đối chứng: $p \in M_{C2}$ và $M_{C2}[p] == v$;
     - (ii) không phải giá trị rỗng/cấu trúc/siêu dữ liệu (`""`, `"null"`, `"true"`, `"false"`, `"{}"`, `"[]"`, tên khoá lá $\in \text{metaKeys}$);
     - (iii) **không phản chiếu request:** $v \notin \text{SentSet}$;
     - (iv) **chưa từng lộ cho B hay anon:** $v \notin \text{SeenOther}$ và không xuất hiện ở bất kỳ lá nào của `RefB` (`Self(B)` hoặc `Bogus(B)` live);
     - (v) khác đối chứng phía B tại cùng đường dẫn: $M_{\text{ref}}[p] \ne v$ (gồm cả khi $p \notin M_{\text{ref}}$, ví dụ `Bogus` trả 404/rỗng).
   - **Phân tách giá trị mạnh và giá trị ngắn:**
     - **Giá trị mạnh (`isStrongValue(v)`):** độ dài $\ge 8$ ký tự, hoặc chuỗi chữ/ký hiệu dài $\ge 6$ ký tự không thuần chữ số, hoặc số nguyên dài $\ge 6$ chữ số — **1 cặp $(p, v)$** xuất hiện khớp trong $M_T$ ($M_T[p] == v$, hoặc cùng khoá lá và giá trị khi danh sách bị lọc làm đổi chỉ số mảng) là đủ làm bằng chứng.
     - **Giá trị ngắn (`short: true` — số dư, cấp bậc, mã ngắn dài $1..7$ ký tự hoặc số $1..5$ chữ số):** **không bao giờ khớp đơn lẻ**. Chỉ được chấp nhận khi có **tổ hợp nhiều cặp `(json_path, value)`** cùng khớp chính xác cả `json_path` lẫn `value` trong $M_T$ ($M_T[p_i] == v_i$) và **mỗi cặp đều khác giá trị tại đúng `p_i` của `Self(B)` hoặc `Bogus(B)`** ($M_{\text{ref}}[p_i] \ne v_i$), với ngưỡng tối thiểu:
       - $\ge 2$ cặp nếu có ít nhất một giá trị dài $\ge 3$ ký tự (ví dụ `($.data.balance, "750")` + `($.data.level, "4")`);
       - $\ge 3$ cặp nếu mọi giá trị đều chỉ dài 1–2 ký tự.
   - Với response không phải JSON (`kind == "text"` / `"other"`, ví dụ CSV/file tải về): ổn định giữa `C1` và `C2` (sau `maskText`), `Trial` trùng nội dung đã che của `C1`, khác hẳn `Self`/`Bogus`, và chứa dòng/chuỗi $\ge 8$ ký tự không thuộc `SentSet` hay body thô của `B`/`anon`.

3. **Bảng quyết định của `JudgePeer`:**

| Thứ tự | Điều kiện | Kết luận (`Verdict`) |
|---|---|---|
| 1 | `Policy` chặn (`Never`, `Excluded`, `Destructive`, `Write` thiếu `-allow-write`), ngoài scope, hết `-max`, endpoint đã bị khoá bởi `Bogus`, hoặc `-dry-run` | `skipped` |
| 2 | WAF chặn `Trial` (không phải `BlockRate`) | `blocked` |
| 3 | Lỗi mạng, `BlockRate`, cache dùng chung (`cached(Trial)`), WAF chặn đối chứng, phiên A hoặc B đã chết | `unclear` |
| 4 | `Control_1(A)` thất bại (`!ok()` hoặc `bodyErrors == errAll`): nếu `alive(A)` còn sống và bản ghi lúc crawl là 2xx lành → `replay_broken`; ngược lại (kể cả `Control_1` mang `errorBody` từ đầu hoặc phiên A chết) → `unclear` | `replay_broken` / `unclear` |
| 5 | `Trial(B)` trả 401/403 (không `Stale`/`Kept` và `alive(B)` còn sống), 3xx về trang login (`alive(B)` còn sống), hoặc 404 khi `Control_1` là 2xx | `enforced` |
| 6 | `Trial(B)` trả 401/403 kèm `Stale`/`Kept`, 419, 400/405/409/422, 3xx khác login, 5xx, hoặc khác `kind` với `Control_1` (SPA HTML fallback) | `unclear` |
| 7 | `Bogus(B)` trả 200 kèm dữ liệu (`bogusHasData`) | `unclear` (và dừng endpoint `K`) |
| 8 | `Trial(B)` trả 2xx có `bodyErrors == errAll` (ví dụ `{"code": 40301}` hoặc GraphQL `errors` kèm `data: null`) và `len(evidence) == 0` | `enforced` |
| 9 | `Self(B)` trả 2xx lành và `compareBodies(Trial, [Self]) == same` (hoặc bằng sau khi che các path `Volatile`) — server bỏ qua `id_A`, trả đối tượng của B | `enforced` |
| 10 | `Trial(B)` trả 2xx, **`len(evidence) == 0`**: nếu sau khi bỏ `metaKeys`, `SentSet` (phản chiếu ID) và rỗng/`null`/`[]`/`{}` mà không còn lá dữ liệu nào, hoặc trùng `Bogus(B)` sau khi chuẩn hoá ID phản chiếu → `enforced`; nếu còn lá dữ liệu khác (ví dụ trường công khai hoặc danh sách lọc một phần) → `needs-review` | `enforced` / `needs-review` |
| 11 | `Write` có `-allow-write` nhưng không bật `-control-writes`: `Trial(B)` trả 2xx không lỗi body (không có `Control(A)` nên không chứng minh được giá trị riêng của A) | `needs-review` |
| 12 | `Trial(B)` trả 2xx và **`len(evidence) > 0`**: chạy `NoIdentity` (mục 4.5); nếu `NoIdentity` cũng trả 2xx chứa giá trị riêng của A → `unauthenticated` | `unauthenticated` |
| 13 | `len(evidence) > 0`, `NoIdentity` không lấy được dữ liệu A: nếu `cross-org`, hoặc `same-org` kèm dấu hiệu riêng tư (`-private` / JSON `private: true` / `visibility: "private"`) → `bypass`; ngược lại ở `same-org` → `shared` | `bypass` / `shared` |

### 4.5. Probe `NoIdentity` và xử lý Signed / Capability URL

Khi bước 12 phát hiện `Trial(B)` chứa bằng chứng riêng của A (và request là `Read`), `authz` gửi thêm một probe `NoIdentity` (`purpose: "no-identity"`, `role: "(none)"`) bằng hàm `stripPeer(raw, rawURL, derived, snapA)`:
- Gỡ toàn bộ `Cookie` và mọi header `credential(name)` qua `Apply(raw, NoIdentity(), ...)`.
- Gỡ mọi liên kết `credentialLink` (CSRF, `cookie:`) và gỡ mọi tham số query/form/body mang credential phiên của A (khớp giá trị trong `snapA.Cookies`/`snapA.Storage`, là JWT, hoặc tên nhạy cảm kiểu `access_token`, `api_key`, `session_id`, `csrf`).
- **Giữ nguyên các tham số chữ ký / capability của chính URL (`isURLSignatureParam`):** `X-Amz-Signature`, `X-Amz-Credential`, `X-Amz-Date`, `X-Amz-Expires`, `X-Amz-SignedHeaders`, `X-Amz-Security-Token`, `X-Goog-Signature`, `X-Goog-Credential`, `sig`, `signature`, `hmac`, `expires`, `Policy`, `Key-Pair-Id`, `sv`/`se`/`sp`/`sr`. (Đồng thời trong `build()` của `Trial(B)`, các tham số chữ ký URL này không bị gắn vào `b.kept`, tránh báo nhầm rò credential phiên).
- Hệ quả: với một pre-signed URL `/api/peer/files/doc-a1?expires=...&sig=<hmac>`, `doc-a1` đưa request vào tập ứng viên (còn `sig` bị loại khỏi tập ID nhưng được giữ nguyên trên URL); cả `Trial(B)` lẫn `NoIdentity` đều nhận 200 kèm nội dung của A → kết luận chính xác **`unauthenticated`** thay vì báo nhầm `bypass` cho B.

---

## 5. Package, CLI, định dạng Output và tích hợp MCP

### 5.1. Tổ chức file trong `internal/replay`

- `bola.go`: `Relation`, `BolaOptions`, `BolaReport`, `PeerItem`, `CandidateID`, `EvidencePair`, `RefBrief`, `Bola(ctx, BolaOptions) (*BolaReport, error)`, `peerCtx`, `pickPeerProbes`, `stripPeer`.
- `ids.go`: `IDKind`, `ParsedID`, `ClassifyID`, `DecodeRelay`, `SeenSet`, `BuildSeenSet`, `canonEndpointKey`, `alignPeerTemplates`, `isURLSignatureParam`.
- `bogus.go`: `BogusID`, `bogusHasData`.
- `compare.go`: thêm hằng số `Shared Verdict = "shared"`, `ReplayBroken Verdict = "replay_broken"`, kiểu `PeerCase`, `PeerJudgement`, hàm thuần `JudgePeer` và `uniqueEvidence` (giữ nguyên `Judge` cho `authz.go`).
- `identity.go`: bổ sung `resolveStorageCred` trong `NewIdentity` khi có `snap.Storage`.
- `policy.go`: bổ sung `replayActionRe` (`verify|magic|regenerate|refresh`) vào `namesReplayAction`.
- `report.go`: `(r *BolaReport) Write(dir string) error`, `(r *BolaReport) Markdown() string`, cập nhật `verdictRank` (`unauthenticated` < `bypass` < `shared` < `likely` < `needs-review` < `replay_broken` < `unclear` < `enforced` < `skipped` < `blocked`).

### 5.2. Cờ CLI trong `cmd/jsharvest/authz.go`

Mở rộng `runAuthz` (khi không truyền `-peers`, giữ nguyên luồng `replay.Authz` đọc `diff.json`):
- `-peers string`: hai role ngăn cách dấu phẩy, ví dụ `-peers userA,userB`. Không dùng chung với `-classes`.
- `-relation string`: bắt buộc khi có `-peers` (`same-org` hoặc `cross-org`).
- `-substitute bool`: thử thêm chế độ thay từng tham số định danh trên nền request `Self(B)` (mặc định `false`).
- `-private string`: biểu thức chính quy khớp URL/key các endpoint riêng tư cá nhân khi `-relation same-org` (nâng từ `shared` lên `bypass`).
- `-reveal bool`: ghi nguyên văn giá trị bằng chứng trong `bola.json` và `bola.md` (mặc định `false`: che thành `REDACTED_<8 hex>`).
- Các cờ an toàn/nhịp có sẵn giữ nguyên: `-o`, `-profiles`, `-target`, `-scope`, `-concurrency`, `-allow-write`, `-control-writes`, `-read-allow`, `-allow-auth`, `-rate`, `-max`, `-proxy`, `-insecure`, `-hosts`, `-dry-run`, `-timeout`, `-on-block`, `-chrome`, `-host-resolver-rules`.

### 5.3. Định dạng Output (`<out>/<targetDir>/authz/bola.json`)

Ghi vào `<out>/<targetDir>/authz/` (thư mục `0700`, mọi file `0600`) gồm `bola.json`, `bola.md`, `bola.sent.jsonl` và các file tái hiện `trials/bola.<slug>.<from>-as-<to>.http` — tách tên file với `authz.json` để chạy cả RBAC dọc lẫn BOLA ngang trên cùng một target không ghi đè mất kết quả của nhau:

```go
type BolaReport struct {
    Host             string            `json:"host"`
    Peers            [2]string         `json:"peers"`
    Relation         Relation          `json:"relation"` // "same-org" | "cross-org"
    Substitute       bool              `json:"substitute,omitempty"`
    AnonLoaded       bool              `json:"anon_loaded"`
    Redacted         bool              `json:"redacted"`
    Generated        time.Time         `json:"generated"`
    Sent             int               `json:"sent"`
    Stopped          string            `json:"stopped,omitempty"`
    HostsBlocked     map[string]string `json:"hosts_blocked,omitempty"`
    StoppedEndpoints map[string]string `json:"stopped_endpoints,omitempty"`
    Notes            []string          `json:"notes,omitempty"`
    Summary          map[string]int    `json:"summary"`
    Items            []PeerItem        `json:"items"`
}

type PeerItem struct {
    Key         string         `json:"key"`       // METHOD host/tmpl [op]
    Direction   string         `json:"direction"` // "userA->userB"
    Owner       string         `json:"owner"`
    As          string         `json:"as"`
    Mode        string         `json:"mode"` // "main" | "substitute:<at>"
    Request     Ref            `json:"sample_request"`
    SelfRequest *Ref           `json:"self_request,omitempty"`
    Kind        Kind           `json:"kind"`
    Why         string         `json:"kind_reason,omitempty"`
    IDs         []CandidateID  `json:"ids"`
    Judgement                  // verdict, reason
    Evidence    []EvidencePair `json:"evidence,omitempty"`
    Trial       *Brief         `json:"trial,omitempty"`
    Control     *Brief         `json:"control,omitempty"`
    Reference   *RefBrief      `json:"reference,omitempty"`   // kind: "self"|"bogus", status, size
    NoIdentity  *Brief         `json:"no_identity,omitempty"`
    File        string         `json:"file,omitempty"`
    KeptHeaders []string       `json:"kept_headers,omitempty"`
    Refreshed   []string       `json:"refreshed,omitempty"`
    Stale       []string       `json:"stale,omitempty"`
    Kept        []string       `json:"kept,omitempty"`
    Missing     []string       `json:"missing,omitempty"`
    At          time.Time      `json:"at,omitzero"`
}

type CandidateID struct {
    At        string `json:"at"`                   // "path:3", "query:userId", "body:$.variables.id"
    Kind      IDKind `json:"kind"`                 // "int_small", "int64", "uuid", "ulid", "objectid", "relay", "slug"
    Value     string `json:"value"`
    RelayType string `json:"relay_type,omitempty"`
    RelayID   string `json:"relay_id,omitempty"`
    Bogus     string `json:"bogus,omitempty"`
}

type EvidencePair struct {
    Path   string `json:"path"`                // "$.data.taxId", "$.data.balance"
    Value  string `json:"value"`               // REDACTED_<8 hex> mặc định; nguyên văn khi có -reveal
    RefVal string `json:"ref_value,omitempty"` // giá trị tại Path của Self/Bogus, cùng chế độ che
    Short  bool   `json:"short,omitempty"`
}
```

Khi `!Reveal`, mọi `EvidencePair.Value` và `EvidencePair.RefVal` được băm qua `traffic.Redactor.Value` (`REDACTED_<8 hex>`), trong khi `EvidencePair.Path` và `Short` luôn giữ nguyên để thấy rõ trường nào của A đã bị lộ.

### 5.4. Tích hợp MCP tool `get_authz` (P6.2b, `internal/mcpserver/`)

Đăng ký tool chỉ đọc `get_authz` trong `mcpserver.New` (`ReadOnlyHint: true`, `OpenWorldHint: &closed`, mô tả kèm `untrustedNote`):
- **Đầu vào (`getAuthzIn`):**
  - `mode`: `""` (mặc định: `"peers"` khi có `bola.json`, ngược lại `"roles"`), `"roles"` (chỉ `authz.json`), `"peers"` (chỉ `bola.json`). Không gộp cả hai file trong một lần gọi để tiết kiệm I/O và giữ nhẹ payload MCP dưới trần `maxReply`.
  - `verdict`: lọc theo kết luận (`bypass`, `shared`, `unauthenticated`, `needs-review`, `replay_broken`, `enforced`, `unclear`…).
  - `direction`: lọc chiều peer (ví dụ `"userA->userB"`).
  - `role`: lọc theo `trial.role` (dọc) hoặc `owner`/`as` (ngang).
  - `key_contains`: lọc chuỗi con trên `key`.
  - `limit` (mặc định 100, tối đa 500), `offset` (phân trang để luôn dưới trần `maxReply = 120 KB`).
- **Cơ chế đọc và làm sạch:**
  - Xác định `hostDir := filepath.Dir(d.Path)` từ `s.dir()` (giống `get_diff`), đọc `filepath.Join(hostDir, "authz", "authz.json")` và/hoặc `filepath.Join(hostDir, "authz", "bola.json")`; nếu cả hai đều chưa tồn tại thì báo lỗi hướng dẫn chạy `jsharvest authz`. Không bao giờ mở `sent.jsonl`, `bola.sent.jsonl` hay `trials/*.http`.
  - Khi MCP không bật `-reveal` (`s.red != nil`), ngay cả khi người dùng trước đó từng chạy `authz -reveal`, `get_authz` vẫn đi qua bộ che: gọi `s.red.Value` lên mọi `EvidencePair.Value`/`RefVal` (hàm `mask` của `Redactor` giữ nguyên chuỗi đã có tiền tố `REDACTED_`), gọi `s.text` lên `Reason`, `Notes`, `CandidateID.Value`.
  - Trả kết quả qua `reply(out)` để tự động bọc envelope `{"untrusted": "target", ...}` (P6.1).

---

## 6. Fixture `peer-app`, `peerscore` và gate `bola-check`

### 6.1. Fixture `testbed/apps/peer-app` và các tài khoản thử

Thêm route `/api/peer/*` trong `testbed/cmd/testbed/peer.go` gắn vào `serve()` và SPA `testbed/apps/peer-app/dist/` với 4 tài khoản đăng nhập:
- `alice` và `bob`: cùng thuộc `org-alpha` (**kịch bản `-peers alice,bob -relation same-org`**).
- `charlie`: thuộc `org-beta` (**kịch bản `-peers alice,charlie -relation cross-org`**).
- `dave`: thuộc `org-beta`, tài khoản mới hoàn toàn trống dữ liệu (**kịch bản `-peers alice,dave -relation cross-org`**, ép nhánh thiếu `Self(B)` → sinh `Bogus`).

Mỗi tài khoản có dữ liệu riêng đủ dài để làm bằng chứng mạnh (mã số thuế, ghi chú bí mật) và các trường ngắn (số dư `balance`, cấp bậc `tier`). Server cũng có một endpoint động từ nguy hiểm `GET /api/peer/keys/{id}?action=regenerate` để kiểm `replayActionRe` luôn giữ ở trạng thái `skipped` khi không có `-allow-write`.

### 6.2. Bảng ca kiểm thử bắt buộc trong `peer.truth.json`

| # | Ca kiểm thử | Route / Operation trên `peer-app` | Hành vi server | Kỳ vọng `same-org` (`alice,bob`) | Kỳ vọng `cross-org` (`alice,charlie` / `alice,dave`) |
|---|---|---|---|---|---|
| 1 | `/me` | `GET /api/peer/me` | Trả hồ sơ của chính phiên gọi | **Không là ứng viên** (`excluded`: không mang ID trong request, 0 bản thử gửi đi) | **Không là ứng viên** (`excluded`) |
| 2a | Tài nguyên chung đã thấy | `GET /api/peer/announcements/{id}` (`id` có sẵn trong `GET /api/peer/feed` của mọi role/`anon`) | Ai đăng nhập cũng đọc được | **Không là ứng viên** (`excluded`: `id` đã nằm trong `SeenOther`) | **Không là ứng viên** (`excluded`) |
| 2b | Tài nguyên dùng chung cấp org (B chưa mở lúc crawl) | `GET /api/peer/org-docs/{uuid}` | Kiểm `doc.org == caller.org`; không có cờ `private` | **`shared`** (cùng `org-alpha`, B đọc được dữ liệu riêng của `alice` theo thiết kế) | **`enforced`** (403 cho `charlie`/`dave` ở `org-beta`) |
| 2c | Tài nguyên cá nhân bị quên kiểm quyền | `GET /api/peer/private-notes/{id}` (`id` kiểu `int_small`, JSON có `"visibility":"private"`) | Chỉ kiểm đăng nhập, trả luôn note của `id` | **`bypass`** (có `"visibility":"private"` nên `same-org` vẫn là `bypass`) | **`bypass`** (cả với `charlie` có `Self` lẫn `dave` qua `Bogus`) |
| 3 | Server bỏ qua `userId` | `GET /api/peer/preferences?userId={uuid}` | Bỏ qua `userId`, trả `preferences` của người gọi | **`enforced`** (`Trial` trùng `Self(bob)`) | **`enforced`** (`charlie`: trùng `Self`; `dave`: trả object mặc định rỗng của `dave`, 0 giá trị riêng của `alice`) |
| 4 | Phản chiếu lại ID | `GET /api/peer/lookup?itemId={slug}` | Nếu không phải chủ sở hữu, trả `200 {"itemId": itemId, "items": [], "found": false}` | **`enforced`** (`itemId` nằm trong `SentSet` bị trừ bỏ, không còn dữ liệu riêng của `alice`) | **`enforced`** |
| 5a | B trống dữ liệu (Bogus lành) | `GET /api/peer/orders/{snowflake_int64}` (`dave` không có đơn hàng nào) | Quên kiểm owner; ID không tồn tại trả 404 | `bypass` (`bob` có `Self`) | **`bypass`** ở `alice->dave` (`Bogus` 19 chữ số trả 404, `Trial` lộ đơn của `alice`; không gửi chiều `dave->alice`) |
| 5b | B trống dữ liệu + bẫy Bogus 200 có dữ liệu | `GET /api/peer/featured/{int_small}` (`dave` chưa gọi) | ID không tồn tại vẫn trả `200 {"title":"Default Pack","sku":"DEF-9"}` | `enforced` / `needs-review` | **`unclear`** ở `alice->dave` + ghi `stopped_endpoints`, dừng thử endpoint đó |
| 6 | Khoá phân cấp `orgs/{o}/projects/{p}` | `GET /api/peer/orgs/{o}/projects/{p}` | Kiểm `o == caller.org`, **quên** kiểm `project[p].org == o` | **`shared`** (`o` chung `org-alpha`, lộ project của `alice`; thành `bypass` khi truyền `-private`) | Mặc định: **`enforced`** (403 vì `o_alice != org-beta`); với `-substitute`: **`bypass`** (`orgs/org-beta/projects/p_alice` trả 200 dữ liệu `alice`) |
| 7 | Signed / Capability URL | `GET /api/peer/files/{id}?expires=...&sig=<hmac>` | Chỉ kiểm chữ ký HMAC `sig` + `expires`, không kiểm cookie | **`unauthenticated`** (`NoIdentity` giữ `sig` cũng nhận 200 dữ liệu `alice`) | **`unauthenticated`** |
| 8 | GraphQL theo lô + Relay Global ID | `POST /api/peer/graphql` gửi lô `[{GetViewer}, {GetVaultItem(id: base64("VaultItem:1001"))}]` | `GetViewer` theo phiên; `GetVaultItem` quên kiểm owner | `GetViewer` bị loại; `GetVaultItem` (**`bypass`**, có `private: true`) | `GetVaultItem` → **`bypass`** (tách `[{GetVaultItem}]`, giải mã Relay `VaultItem:1001`) |
| 9a | Mã lỗi/thành công dạng số + giá trị ngắn | `GET /api/peer/wallets/{id}` | Chủ nhận `200 {"code":20000,"data":{"balance":750,"tier":4}}`; người khác nhận `200 {"code":40301,"msg":"cấm"}` (riêng endpoint `/wallets-leaky/{id}` quên kiểm, trả `code:20000` kèm `balance`+`tier` của chủ) | `/wallets/{id}` → **`enforced`**; `/wallets-leaky/{id}` (có `private:true`) → **`bypass`** nhờ tổ hợp 2 cặp ngắn `(balance, tier)` khác `Self`/`Bogus` | `/wallets/{id}` → **`enforced`**; `/wallets-leaky/{id}` → **`bypass`** |
| 9b | Control mang `errorBody` số | `GET /api/peer/quota/{id}` | Token phụ hết hạn sau crawl nên cả `Control(alice)` live trả `200 {"code":2001,"msg":"expired"}` | **`unclear`** (`Control_1` có `bodyErrors == errAll`) | **`unclear`** |
| 10 | Request signing / nonce một lần | `GET /api/peer/signed-transfer-preview/{id}` kèm `X-Req-Nonce` dùng một lần | Lúc crawl trả 200; khi replay lại nonce cũ trả 401 trong khi `/api/peer/me` vẫn 200 | **`replay_broken`** | **`replay_broken`** |
| 11 | Động từ riêng của replay | `GET /api/peer/keys/{id}?action=regenerate` | Xoay secret | **`skipped`** (nhờ `replayActionRe`) | **`skipped`** |

### 6.3. Lệnh chấm `bin/testbed peerscore` và gate `testbed/bola-check.sh`

1. **`bin/testbed peerscore -truth peer.truth.json -bola <dir> -scenario <name> -secrets <file> [-reveal]`:**
   - Đối chiếu 1–1 mọi `(key không chứa host, direction, mode)` trong `bola.json` với kịch bản tương ứng trong `peer.truth.json`; thiếu ứng viên hoặc thừa ứng viên thuộc `excluded` đều fail.
   - Kiểm tra mọi mục `bypass`/`shared` đều có `len(evidence) > 0`; khi không có `-reveal`, mọi `evidence[].value` phải có tiền tố `REDACTED_` và không chuỗi bí mật nào trong `-secrets` xuất hiện trong `bola.json` hay `bola.md`.
   - Quét toàn bộ `bola.sent.jsonl` và `trials/*.http`: không một request nào gửi dưới danh tính `bob`/`charlie`/`dave` hoặc `(none)` được chứa cookie phiên, `Authorization` hay CSRF token của `alice` (và ngược lại).
2. **`testbed/bola-check.sh`** (tuân thủ `${TESTBED_WORK}`, `${TESTBED_LOG}`, `${TESTBED_PID}`, `${TESTBED_NO_BUILD}`, thêm vào `testbed/regress.sh`):
   - **A.** Khởi chạy `peer-app`; `login` cho `alice`, `bob`, `charlie`, `dave`; `crawl -explore` cho `anon` và cả 4 peer.
   - **B.** Chạy `authz -peers alice,bob -relation same-org`, chấm `peerscore`; chạy tiếp với `-private 'orgs/.*/projects'` kiểm `shared` chuyển thành `bypass`; kiểm quyền file `0600`, đối chiếu số dòng server log với `bola.sent.jsonl`, và xác nhận không có request tới `/api/login`, `/api/logout`, hay `?action=regenerate`.
   - **C.** Chạy `authz -peers alice,charlie -relation cross-org` (mặc định và có `-substitute`), chấm `peerscore`.
   - **D.** Chạy `authz -peers alice,dave -relation cross-org` (ca B trống dữ liệu + Bogus + `stopped_endpoints`), chấm `peerscore`; kiểm mọi Bogus ID trong `bola.sent.jsonl` không nằm trong `id_A ± 1000`, không âm, không bằng `0`.
   - **E.** Khởi động lại server (mọi phiên chết) → chạy lại `authz -peers`, xác nhận chỉ còn `unclear` và `skipped`, không có `enforced` hay `replay_broken` giả.
   - **F.** Kiểm `mcpcall` trên tool `get_authz` (cả mặc định che secret lẫn `-reveal`, kiểm envelope `"untrusted": "target"`).
3. **Thử nghiệm bổ sung P5.6:** chạy cùng quy trình với 2 tài khoản local trên Directus và Jellyfin trong mạng Docker cô lập (`*.jsh.test` qua `-host-resolver-rules`, không có kết nối ra ngoài).

---

## 7. Rủi ro, giới hạn và ngoài phạm vi

1. **ID số nguyên rất nhỏ (1 chữ số như `1`, `2`):** vì `SeenOther` lấy hợp của mọi giá trị scalar từng xuất hiện trong bất kỳ response nào của B và `anon` để triệt tiêu dương tính giả, một đối tượng có ID là `1` hoặc `2` có thể trùng với trường phân trang/đếm (`"page": 1`, `"count": 2`) trong response của B và bị bỏ qua ở bước chọn ứng viên. Chấp nhận đánh đổi này để giữ chặt điều kiện ứng viên.
2. **BOLA mù trên request ghi (blind write BOLA):** khi chạy `-allow-write` (không bật `-control-writes` để tránh ghi đúp lên dữ liệu thật của A), các endpoint ghi chỉ trả `200 {"ok": true}` không mang giá trị riêng của A trong body nên chỉ dừng ở `needs-review`, không tự kết luận `bypass`. Kiểm chứng ghi mù (đọc lại đối tượng của A sau khi B ghi) có tác dụng phụ lên dữ liệu của A nên để ngoài phạm vi tự động.
3. **Phiên gắn chặt thiết bị / TLS fingerprint / chữ ký request phía client:** `Sender` gửi bằng Go `net/http` (HTTP/2 + UA khớp Chrome, không giả JA3/JA4 và không chạy lại code ký request trong V8); các mục tiêu ràng buộc chặt phiên với TLS hoặc ký từng request sẽ rơi vào `replay_broken` (hoặc `blocked` nếu WAF chặn) như thiết kế — khi đó cần xem qua `-proxy` hoặc thao tác trong trình duyệt.
4. **Ngoài phạm vi của Bước 29:**
   - Tự động làm mới Bearer JWT hết hạn ngay bên trong `authz` bằng luồng OAuth (hiện dựa vào snapshot sống đã được `crawl` đồng bộ ở cuối phiên theo P4.5; mục 11 của `plan-28.md` hoãn việc tự refresh trong `replay`).
   - Dò tìm/vét cạn (enumeration) ID tuần tự khi cả A lẫn B đều chưa từng thấy đối tượng của người thứ ba.
   - Tổ hợp thay đồng thời nhiều tham số bậc cao ($> 1$ vị trí cùng lúc) ngoài chế độ thay từng vị trí đơn lẻ của `-substitute`.
   - GraphQL persisted query chỉ có mã băm (`sha256Hash`) không có nội dung document: vẫn bị `Policy` xếp vào `Destructive` và bỏ qua để giữ an toàn.

---

## 8. Đánh giá độc lập (P5.2, 2026-11-16) — có hiệu lực cao hơn mục 1–7

Người viết: C (Gemini Carbon). Người review: S (Claude Sonnet), đọc code. O kiểm các nhận định nặng trên code (ví dụ #3: `authz.go` ~503-511 chỉ ghi `b.kept` rồi vẫn gửi). Mọi điểm dưới đây **thay thế** chỗ tương ứng ở mục 1–7.

**Kết luận**
1. **Khoá loại khỏi bằng chứng** là tập riêng, không dùng `metaKeys` của `bodyErrors` (tập đó có `title`, `description`, `path`, `type`, `url`, `date` — dữ liệu thật của một ghi chú). Tập loại: `code`, `status`, `statusCode`, `errcode`, `msg`, `message`, `error`, `errors`, `success`, `ok`, `timestamp`, `trace_id`/`traceId`/`request_id`/`requestId`/`span_id`.
2. **Phản chiếu:** loại mọi lá mà giá trị **chứa** (không phân biệt hoa thường, sau URL-decode) bất kỳ giá trị đã gửi dài ≥ 3 ký tự (`"self":"https://h/api/users/42"`, `"No items for alpha-roadmap"`), không chỉ lá bằng đúng giá trị đã gửi.
3. **Không bao giờ gửi credential của A dưới danh tính B:** `kept ≠ ∅` (credential trong query/body/multipart không làm mới được) → **không gửi** Trial, verdict `unclear` ("credential of A cannot be replaced: …"). Header tuỳ biến mang định danh A (`X-User-Id`…) được ghi chú trong bằng chứng.
4. **Phiên của B còn sống cho mọi `enforced`**: kiểm `alive(B)` sau **mọi** kết luận `enforced` (200 không bằng chứng, 404, `errAll`, 401/403), như authz dọc đã làm; chết → `unclear`. Danh tính B được kiểm **theo từng host** của request: jar không có cookie cho host đó và không có header credential → `unclear` (không gửi ẩn danh rồi ghi `enforced`).
5. **Thứ tự với Bogus:** so Trial với Bogus **trước**: Trial ≡ Bogus (sau khi bỏ phản chiếu và trường thay đổi) → `enforced`; chỉ khi khác mới áp "Bogus 200 có dữ liệu → `unclear`, dừng endpoint".
6. **`IDInt64`** kiểm cận trên `≤ MaxInt64` (id 19 chữ số đầu "92…").
7. **Bằng chứng mạnh**: một cặp chỉ đủ khi giá trị dài ≥ 8 ký tự **và** có chữ số hoặc entropy cao (không phải tên enum, múi giờ, `ROLE_*`); còn lại cần ≥ 2 cặp. Cặp ngắn loại giá trị mặc định (`0`, `1`, `true`, `false`, `null`, mã tiền tệ, `active`/`inactive`…). Nếu tham chiếu (Self/Bogus) không phải 2xx thì cần ≥ 3 cặp.
8. **Cache:** Trial gửi kèm `Cache-Control: no-cache` (và `Pragma: no-cache`); header `HIT` vẫn → `unclear` như cũ.

**Tên và chỗ trong code**
9. `endpoints.Read` không có: dùng `endpoints.Catalog(dir, inScope, false)` (như `cmd/jsharvest/export.go`). `flow.mixed` không export. `Param.At()` của multipart là `""`: multipart không `Patch`/`-substitute` được (ghi `skipped: multipart`). `results.Req` không có body: dùng `Dir.Entry`.
10. `authFlowRe` (`replay/policy.go`) đã có `refresh|token`; `replayActionRe` (`verify|magic|regenerate|refresh` cộng các từ phá huỷ) phải kiểm **trước** nhánh GraphQL query = Read, trên URL, query, body và tên operation; `-read-allow` **không** ghi đè danh sách này ở `-peers`.
11. **Token opaque sau xoay vòng (2.2.3):** không thêm trường vào snapshot; lúc chạy, tìm khoá storage của snapshot (bản lúc crawl của A trong `export`) có **giá trị bằng** header credential đã ghi, rồi lấy giá trị **hiện tại** của chính khoá đó trong snapshot sống (P4.5 giữ nó mới). Không tìm được → như "credential không làm mới được" (gỡ hoặc `unclear`, không gửi giá trị cũ của A). JWT có `exp` ngắn hơn thời lượng dự kiến (`-max / -rate`) → cảnh báo.

**Câu hỏi mở (O quyết)**
- Q1: ghi tách `<out>/<host>/authz/bola.json` (+ `bola.md`, `bola.sent.jsonl`); `get_authz` đọc cả hai.
- Q2: `same-org` nâng `shared` → `bypass` khi `-private REGEX` khớp, khi Control(A) có trường riêng tư tường minh, **hoặc** khi đối tượng có `ownerId`/`userId`/`createdBy`/`owner` bằng định danh của A (không phải của B).
- Q3: thay tham số vẫn chỉ dưới `-substitute`; nhưng request có ≥ 2 vị trí ID mà bị 403/404 ở phép thử chính thì verdict là **`enforced-parent`** (chỉ tầng cha đã được thử), không phải `enforced`, kèm gợi ý `-substitute`.
- Q4: ngưỡng phân bậc như đề xuất, cộng điều 7 ở trên.
- Q5: ghi 2xx không có bằng chứng → `needs-review` với nhãn `blind-write`; với `-allow-write`, cả hai chiều đều ghi vào dữ liệu thật của peer (cảnh báo khi chạy).

**Fixture**
12. Bảng 6.2 dòng 5a `same-org`: kỳ vọng `shared` (không có dấu riêng tư), trừ khi có `ownerId` của A (điều Q2) — `peer.truth.json` theo luật này.

## 9. Kết quả (2026-11-16)

**Gate `bola-check` (fixture `peer-app`)**: xanh trong `regress.sh -j 3` đầy đủ — `same-org` (cả `-reveal`, `-private`), `cross-org` (mặc định và `-substitute`), peer trống dữ liệu (Bogus), mọi phiên chết (chỉ `unclear`/`skipped`), `get_authz` qua MCP (che mặc định, lộ với `-reveal`). Không request nào mang credential của peer này dưới danh tính peer kia; server không thấy request ngoài `bola.sent.jsonl`, không login/logout/`regenerate`.

**Thử trên lab local (P5.6, không có kết nối ra ngoài)**, hai tài khoản cùng quyền, `-relation same-org`:
- **Directus 12.6.1** (`user2`, `user3`, role Editor): quyền đọc `notes` không giới hạn theo chủ (Directus 12.6.1 khoá "custom permission rules": không đặt được luật `user_created = $CURRENT_USER`), nên danh sách của mỗi người đã chứa id ghi chú của người kia → đúng là **không** có ứng viên ở `notes` (B được phép thấy chúng). `activity/{}`: hai mục `shared` (đọc được nhật ký của người kia; không có dấu riêng tư; khoá `user` không thuộc danh sách dấu chủ sở hữu của Q2). Không bypass giả. Crawl của hai peer cần `login -guard-allow '^http://directus\.jsh\.test:8055/auth/refresh(\?|$)'` (refresh BFF, P4.5); có nó thì phiên giữ suốt crawl (`refreshed 38`, `saved true`).
- **Jellyfin 12.4** (`user2`, `user3`, không admin; lab không có media): hai mục `needs-review` ở `GET /Playback/BitrateTest` (byte ngẫu nhiên: không có bằng chứng của A). Id người dùng (`/Users/{hex}`) xuất hiện trong response của người kia nên không là ứng viên (đúng luật đặc tả 6).
- Lỗi tìm thấy và đã sửa nhờ lab: (1) keeper coi 401 của document là mất phiên với phiên giữ token trong storage (frontier mở URL API lấy từ JS như trang) → đã sửa (`ad8b5c3`); (2) token nằm **bên trong** header nhiều tham số (`Authorization: MediaBrowser …, Token="…"`, lưu trong JSON `jellyfin_credentials`) bị bản sửa P5.5 #9 gỡ nhầm → đã sửa (`4f335bc`).

**Giới hạn còn lại**: lab chưa có ca BOLA thật được server thực thi theo chủ (Directus khoá luật tuỳ biến, Jellyfin trống media); kết luận `enforced` trên ứng dụng thật chỉ được gate fixture kiểm. Khoá chủ sở hữu của Q2 nên thêm `user`/`user_created` (Directus) — đề xuất, chưa làm.
