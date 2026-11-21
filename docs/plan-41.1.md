# Đợt 41.1: hậu kiểm và vá kín các đường vòng sau Đợt 41

Nguồn: hậu kiểm đối kháng toàn bộ 116 file thay đổi của Đợt 41 (`4679c70..f079907`) kết hợp đo thực nghiệm trực tiếp trên `esbuild v0.28.2` và tập corpus 2.568 script thực tế (`output/_live_25e_max/*/anon/js/*.js`).

Tài liệu này mô tả thiết kế chi tiết cho **Đợt 41.1** trước khi sửa mã nguồn. Mọi vị trí dòng mã đều đã đối chiếu trực tiếp với `HEAD f079907`.

**Quy ước công sức:** S ≤ 0,5 ngày · M 1–2 ngày (một người, gồm cả unit test và chạy gate).

**Quy tắc chung:**
- Mỗi mục là một commit độc lập, kèm unit test đối kháng thất bại nếu bỏ phần sửa (mutation check).
- Tuyệt đối không chứa tên mục tiêu thật, đường dẫn máy cục bộ hay danh tính cá nhân trong mã, test, fixture hay tài liệu; chỉ dùng `example.test`, `example.net`, `example.com`.
- Giữ nguyên bất biến `jsapi`: so MD5 `TestSnapshot` trên toàn bộ 2.568 script với `HEAD` (`6aaeefd647d4d130c6cb2faa5cd35983`); chỉ tăng `jsapi.Version` nếu output thay đổi có chủ đích.

---

## 0. Kết quả hậu kiểm và số liệu thực nghiệm hiệu chỉnh thiết kế

| Nhóm | Phát hiện cốt lõi khi hậu kiểm `HEAD f079907` | Số liệu thực nghiệm & hướng chốt |
|---|---|---|
| **A1 (vá M7)** | 1) `esbuild v0.28.2` bị `fatal error: stack overflow` (> 1 GB goroutine stack, không `recover()` được) trên **9 cấu trúc đệ quy không cần bất kỳ ngoặc `( [ {` nào**: JSX lồng `<a><a>…</a></a>`, toán tử đơn ngôi `!!!!…1`, toán tử 3 ngôi `a?a?…:2:2`, arrow `a=>a=>…1`, gán phải `a=a=…1`, luỹ thừa `2**2**…2`, chuỗi thuộc tính `a.b.b…` (`visitExprInOut` đệ quy trên `EDot`), `new new …A`, và nhãn câu lệnh `l: l: …a`.<br>2) Lexer trong `internal/jsapi/depth.go` còn 4 điểm lệch trạng thái: `//` tại `:62-66` chỉ tìm `\n` nên `"//\r" + "("*1M` thoát ở byte 2 với `(0, false)` (tương tự `\u2028`/`\u2029`, thiếu `#!` và Annex B `<!--`); `canRegex = c == '}'` (`:116`) và `"of"` (`:200`) hiểu nhầm phép chia trong `({}/(((1M)))/1)` hoặc `of/(((1M)))/1` thành regex literal; JSX text có dấu nháy đơn `<div>Don't</div>` mở nhầm `skipStringLiteral`. | Đo trên toàn bộ **2.568 script** của corpus dev (tới 5 MB/file):<br>• Độ sâu ngoặc thô không lexer (`( [ {` trừ `) ] }`, kẹp `>= 0`) tối đa = **`1.186`** (cao thứ nhì = `321`).<br>• Độ sâu `(ngoặc + chuỗi biểu thức mỗi scope)` có lexer tối đa = **`1.065`**.<br>• Chuỗi toán tử/từ khoá thô **không lexer** giữa các dấu ngắt `; , }` và dấu nháy tối đa = **`7.232`**.<br>→ Chốt **cầu chì 2 lớp trong cùng 1 lượt quét O(N)**: Lớp 1 (có lexer đã vá kín line-terminator/regex) chặn `depth > 400` hoặc `depth + chain > 2.500`; Lớp 2 (thô phi-lexer, **không thể bị đánh lừa trạng thái**) chặn `rawBracketDepth > 4.000` hoặc `rawChain > 16.000` (vẫn thấp hơn ngưỡng tràn stack của `esbuild` từ 15× đến 50×). |
| **A2 (vá L3)** | 1) `mdsafe.InlineText` (`internal/mdsafe/mdsafe.go:68-74`) không escape `\` trước, nên `\[x\](https://evil.example)` thành `\\[x\\](…)` (vẫn là link sống trong CommonMark) và `` \` `` thành code span sống.<br>2) `mdsafe.TableCode` (`:43-45`) thay mọi `|` bằng `\|`: chuỗi có số lẻ `\` trước `|` (vd `a\|b`) bị biến thành số chẵn `\\|` — GFM tách ô bảng **trước** khi xét code span nên `\\` thành một backslash và `|` làm vỡ cột!<br>3) Một số dòng `fmt.Fprintf(os.Stderr, …)` ở `cmd/jsharvest/` vẫn in chuỗi từ target chưa qua `StripControls`. | • Thêm `\` → `\\` đứng đầu `inlineTextEscaper`.<br>• Trong `TableCode`, với mỗi chuỗi `k` dấu `\` đứng ngay trước `|`, nhân đôi thành `2k + 1` dấu `\` rồi tới `|` (`2k + 1` **luôn lẻ** với mọi `k >= 0`, nên `|` luôn được escape khi tách bảng mà không chạm các `\` đứng riêng như `C:\foo`).<br>• Cập nhật hàm kiểm `countUnescapedPipes` trong test theo đúng chẵn-lẻ số `\` liền trước, và bọc `mdsafe.StripControls` cho các dòng `os.Stderr` in dữ liệu từ target. |
| **A3 (vá M12)** | 1) `url.ParseQuery` trả lỗi cho toàn bộ chuỗi hễ gặp `;` hoặc `%ZZ` hỏng, làm `EffectiveMethod` (`guard/rules.go:66`), `BodyActionFields` (`:260`) và `bodyValues` (`replay/policy.go:250`) bỏ trắng toàn bộ form như `note=a;b&action=delete` hay `note=a;b&action=logout`.<br>2) `BodyActionFields` và `bodyValues` chưa bóc `multipart/form-data`.<br>3) `walkActionJSON` (`rules.go:276`) cắt cứng ở `len(*out) >= 64` nên batch JSON-RPC 65 phần tử giấu được `{"method":"user.delete"}` ở phần tử thứ 65.<br>4) `Rules.Classify` (`:114`) kiểm `BodyActionFields` trước `graphQL`, có thể chặn nhầm GraphQL `query` chỉ đọc có biến `variables.filter.action = "delete"`. | • Viết bộ tách form chịu lỗi theo cả `&` lẫn `;`, `QueryUnescape` từng token với fallback giữ nguyên chuỗi gốc.<br>• Đọc `multipart/form-data` bằng `mime.ParseMediaType` + `multipart.NewReader` có trần (tối đa `64` part, `4 KiB`/part text không phải file) kèm fallback quét ranh giới khi body bị cắt.<br>• Thay mảng cắt 64 bằng duyệt trực tiếp có trần nút `maxActionJSONNodes = 10_000`.<br>• Nếu request là GraphQL `query` thuần đọc (`gql && !write`), bỏ qua `BodyActionFields` (còn GraphQL `mutation` hoặc unknown vẫn kiểm cả body lẫn biến). |
| **A4 (vá H2 & M1)** | 1) `Redactor.URL` (`traffic/redact.go:237-244`) dùng `u.User.Password()` (đã giải mã `%`), nên không khớp chuỗi raw khi mật khẩu mã hoá `https://user:p%40ss@host` và bỏ lọt token đứng một mình `https://ghp_xxx@host` (không có `:`).<br>2) `maskLogQuerySeg` (`:385,400`) gọi `Text(v)` thay vì `URL(v)` và bỏ qua base64 chuẩn bắt đầu bằng `/` dù có đệm `=`.<br>3) `verify.Report` còn sót `Results[i].Reason`, `CloudChecks[i].{URL,Error}`, `Stopped`, `HostsGated`; `AuthzReport`/`BolaReport` còn sót `Reason`, `Stopped`, `StoppedEndpoints`, `Notes` khi `-redact` bật.<br>4) `JudgePeer` (`replay/judge_peer.go:502,549`) chưa chặn `if c.Kept` ở nhánh 2xx như `Judge` (`compare.go:131`). | • Cắt trực tiếp lát raw userinfo giữa `://` và `@` của phần authority để che cả `user:pass@` mã hoá `%` lẫn `token@`.<br>• Nâng cấp `maskLogQuerySeg` gọi `URL(v)` khi giá trị là URL lồng nhau và bắt base64 bắt đầu bằng `/` khi có dấu `=` hợp lệ.<br>• Scrub đầy đủ các trường chuỗi còn lại của `verify.Report`, `AuthzReport`, `BolaReport` khi `Redactor != nil`.<br>• Đặt `if c.Kept` ở đầu nhánh 2xx ghi (`:502`) và 2xx đọc (`:549`) của `JudgePeer`. |
| **A5 (vá L10)** | 1) `Sender.DoExternal` (`replay/send.go:792-830`) tăng `s.n++` **trước** khi chờ `s.slots` và `-rate`: nếu `reqCtx` hết hạn trong lúc chờ thì `DoExternal` trả lỗi sớm mà không gọi `s.write(line)`, làm `rep.Sent > số dòng sent.jsonl` và hao hụt ngân sách `-max` cho request chưa gửi.<br>2) `Sender.write` (`:734`) gọi `r.Text(l.Item)` thay vì `r.URL(l.Item)`. | • Kiểm nhanh `s.stopped`/`s.o.Max` trước khi chờ, nhưng **chỉ tăng `s.n++` dưới `s.mu` sau khi đã qua `s.slots` và `turn`**, ngay sát lúc ghi `Sent` và thực thi `client.Do`.<br>• Đổi `l.Item = r.URL(l.Item)` tại `send.go:734`. |
| **41.1B & 41.1C** | 6 cạnh biên/caller phụ (`archive` & `monitor` JSONL append, `SaveMap` fsync, `relogin` redactor/response headers, cảnh báo `watch` `-lan-guard`, neo đầu chuỗi `M8` / profile tạm & `SingletonLock` `M9` / dừng sớm `SourceMap` `M11`, `umask`/`chmod` trong `docker/entrypoint.sh`, nối `o.Resolver` vào `resolve.Policy` của `httpcrawl`) và 4 điểm lệch tài liệu/footer/`.gitleaks.toml`. | Vá trọn gói trong 41.1B (6 commit nhỏ theo vùng) và 41.1C (1–2 commit tài liệu + cấu hình CI). |

---

## 1. Bảng tổng quan

| ID | Gốc | Đợt | Việc | File chính | Gate | Công sức |
|---|---|---|---|---|---|---|
| A1 | M7 | 41.1A | Cầu chì 2 lớp trước `esbuild` (ngoặc + chuỗi biểu thức/JSX + tầng thô phi-lexer; vá line-terminator/regex) | `internal/jsapi/depth.go`, `internal/jsapi/round41_test.go` | endpoints-check, snapshot, stats, perfgate | M |
| A2 | L3 | 41.1A | Vá lệch chẵn-lẻ `\` trong `mdsafe.{InlineText,TableCode}` + lọc C0/C1 cho `os.Stderr` còn sót | `internal/mdsafe/mdsafe.go`, `cmd/jsharvest/*.go` | roles-check, replay-check, bola-check, verify-check, monitor-check | S |
| A3 | M12 | 41.1A | Form parser chịu `;`/`%ZZ`, hỗ trợ `multipart/form-data`, bỏ trần 64 JSON-RPC, tách GraphQL `query` đọc | `internal/guard/rules.go`, `internal/replay/policy.go` | attach-guard, explore-check, replay-check | M |
| A4 | H2, M1 | 41.1A | Che raw userinfo ở `Redactor.URL` + `LogURL`; scrub đủ `Reason`/`Error`/`Notes` của `verify`/`authz`/`bola`; chặn `c.Kept` ở `JudgePeer` 2xx | `internal/traffic/redact.go`, `internal/verify/verify.go`, `internal/replay/{authz,bola,judge_peer}.go` | replay-check, bola-check, verify-check | M |
| A5 | L10 | 41.1A | Tăng `s.n` sau chờ slot/`-rate` trong `Sender.DoExternal`; dùng `r.URL(l.Item)` trong `Sender.write` | `internal/replay/send.go` | verify-check, replay-check | S |
| B1 | L5 | 41.1B | Đổi `archive/run.go` & `monitor/report.go` sang `traffic.AppendOpen`; `tmp.Sync()` trong `SaveMap` | `internal/archive/run.go`, `internal/monitor/report.go`, `internal/store/store.go` | archive-check, monitor-check, pipeline-check | S |
| B2 | M6 | 41.1B | Truyền `e.redactor` vào `capture.RecordOptions` và gọi `r.red.Entry(&e)` cho cửa sổ `relogin` | `internal/capture/record.go`, `internal/engine/engine.go` | session-check | S |
| B3 | M3 | 41.1B | Cảnh báo phạm vi browser của `-lan-guard` trong `watch` khi `-guard off` | `internal/engine/watch.go` | lan-check, attach-guard | S |
| B4 | M8, M9, M11 | 41.1B | Neo `^` cho `promptInjectionRe`; luôn tạo `jsharvest-profile-*` + kiểm hostname `SingletonLock` + `pidAlive` non-Unix; dừng sớm `SourceMap` khi hết ngân sách store | `internal/mcpserver/server.go`, `internal/browser/{browser,proc_other}.go`, `internal/engine/http.go` | flows-gate, webrtc-check, docker-check, pipeline-check | S |
| B5 | L7 | 41.1B | Đặt `umask 077` cho `/tmp/jsharvest-home` & `.Xauthority`; bọc an toàn `chmod 700 "$HOME"` khi bind-mount khác UID | `docker/entrypoint.sh` | docker-check | S |
| B6 | L9 | 41.1B | Nối `o.Resolver` (và `o.HostRules`) vào `resolve.Policy` của `httpcrawl`; gắn `nxResolver` cho 4 file test còn lại | `internal/resolve/policy.go`, `internal/httpcrawl/{crawl,*_test}.go` | pipeline-check, waf-check | S |
| C1 | Docs | 41.1C | Chỉnh chính xác mô tả `M13` và `M10` trong `docs/CURRENT.md` | `docs/CURRENT.md` | — | S |
| C2 | H2 | 41.1C | Cập nhật câu kết `authz.md` và `bola.md` phản ánh đúng trạng thái redact của `trials/*.http` | `internal/replay/{authz,bola,report,bola_report}.go` | replay-check, bola-check | S |
| C3 | L8 | 41.1C | Bỏ allowlist `^docs/` và thu hẹp `^testbed/` trong `.gitleaks.toml` (kiểm chứng bằng `gitleaks v8.24.2`) | `.gitleaks.toml` | gitleaks / CI | S |
| C4 | Docs | 41.1C | Cập nhật `CLAUDE.md` theo cờ và bất biến mới của Đợt 41/41.1 | `CLAUDE.md` | — | S |

Tổng ước lượng: **41.1A ≈ 2–3 ngày**, **41.1B ≈ 1–1,5 ngày**, **41.1C ≈ 0,5 ngày**.

---

## 2. Đợt 41.1A: Vá 5 lỗ hổng bypass & đúng đắn cốt lõi

Thứ tự thực hiện: `A1 → A2 → A3 → A4 → A5`.

### A1. Cầu chì hai lớp trước `esbuild` (vá M7)

**Hiện trạng**
- `internal/jsapi/depth.go:17-204` hiện chỉ đếm ngoặc `(`, `[`, `{` và `${` với một lớp lexer duy nhất.
- **Lỗ hổng 1 — Đệ quy ngoài ngoặc trong `esbuild v0.28.2`:** Kiểm nghiệm trực tiếp bằng subprocess trên `api.Transform` cho thấy cả 9 mẫu sau đều gây `fatal error: stack overflow` (> 1 GB stack) dù `maxNesting` hiện trả `depth = 0` hoặc `1`:
  1. JSX lồng nhau (`LoaderTSX`/`LoaderJSX`): `const x = <a><a>…</a></a>` (~50.000 thẻ).
  2. Toán tử đơn ngôi tiền tố: `const x = !!!!…1;` hoặc `typeof typeof …a;`, `void …`, `delete …`, `+ - ~ !` (~250.000 toán tử).
  3. Toán tử điều kiện 3 ngôi phải-kết-hợp: `const x = a ? a ? … : 2 : 2;`.
  4. Chuỗi hàm mũi tên không ngoặc: `const x = a => a => … => 1;`.
  5. Phép gán phải-kết-hợp: `let a; a = a = … = 1;`.
  6. Phép luỹ thừa phải-kết-hợp: `const x = 2 ** 2 ** … ** 2;`.
  7. Chuỗi truy cập thuộc tính dài: `const x = a.b.b.b…;` (`esbuild` duyệt đệ quy `visitExprInOut` trên cây trái `EDot`).
  8. Chuỗi `new`: `const x = new new … A;`.
  9. Nhãn câu lệnh hoặc nhánh `if … else if …`: `l: l: … a;` / `if(a)x; else if(a)x; …`.
- **Lỗ hổng 2 — Lệch trạng thái lexer trong `depth.go`:**
  1. `depth.go:60-66`: nhánh `//` tìm `bytes.IndexByte(src[i:], '\n')`; nếu file dùng `\r` (CR cổ điển) hoặc `\u2028`/`\u2029` (ECMAScript LineTerminator, UTF-8 `E2 80 A8` / `E2 80 A9`) mà không có `\n`, hàm trả ngay `(maxDepth, false)` tại dòng 65, bỏ qua toàn bộ triệu dấu ngoặc phía sau! Đồng thời chưa nhận `#!` ở đầu file và HTML-like line comment `<!--` / `-->` (Annex B).
  2. `depth.go:116` & `:200`: đặt `canRegex = c == '}'` làm biểu thức đối tượng chia cho biểu thức `({} / (((…1M…))) / 1)` bị hiểu thành regex literal `/(((…1M…)))/` và nhảy qua toàn bộ ngoặc mở; từ khoá ngữ cảnh `"of"` trong `isRegexPrefixKeyword` cũng gây lỗi tương tự với biến tên `of` (`of / (((…))) / 1`).
  3. Trong TSX/JSX, văn bản giữa các thẻ như `<div>Don't</div>; (((…1M…))); <div>'</div>` trên cùng một dòng làm dấu `'` của `Don't` nhảy vào `skipStringLiteral` và nuốt sạch đoạn mã JS ở giữa.

**Thiết kế**
Thay `maxNesting` trong `internal/jsapi/depth.go` bằng bộ kiểm hai lớp chạy trong **cùng một vòng quét tuyến tính O(N)** (không cấp phát lớn, thoát sớm ngay khi vượt ngưỡng):

1. **Lớp 1 — Máy trạng thái có lexer đã vá kín:**
   - **Line comment chuẩn ECMAScript:** viết hàm `skipLineComment(src []byte, i int) int` dừng tại bất kỳ byte `\n`, `\r`, hoặc chuỗi 3 byte `\xe2\x80\xa8` (`U+2028`), `\xe2\x80\xa9` (`U+2029`). Hỗ trợ `#!` tại `i == 0` và `<!--` ở mọi vị trí ngoài chuỗi/comment (cùng `-->` ở đầu dòng sau khoảng trắng).
   - **Sửa nhận diện regex literal:**
     - Sau `}` (không thuộc `${}` của template): đặt `canRegex = false` (nếu sau block là regex hợp lệ thì regex đó không chứa triệu ngoặc mở không đóng trên 1 dòng; ngược lại nếu là phép chia `({}) / (…)` thì bắt buộc không được nuốt biểu thức sau `/`).
     - Bỏ `"of"` khỏi `isRegexPrefixKeyword` (`of` không phải unary prefix keyword trong JS).
     - **Quan trọng:** bên trong `skipRegexLiteral`, vẫn đếm các dấu ngoặc chưa escape `(` / `[` (ngoài character class) vào bộ đếm an toàn hoặc giới hạn độ dài regex trên 1 dòng, chỉ dùng `skipRegexLiteral` để dấu `'`/`"`/`/*` bên trong `/don't/` không làm hỏng trạng thái chuỗi/comment phía sau! Như vậy dù heuristic `canRegex` chọn nhầm `/` là regex hay phép chia thì `({} / (((…1M…))) / 1)` vẫn bị đếm đủ ngoặc và chặn 100%.
   - **Đếm đồng thời độ sâu ngoặc (`depth`) và chuỗi đệ quy trong từng cấp ngoặc (`chain`):**
     - Duy trì ngăn xếp nguyên `chainStack []int` theo cấp ngoặc (khởi tạo `[0]`, push `0` khi gặp `( [ {` hoặc `${`, pop khi gặp `) ] }`).
     - Reset phần tử đỉnh `chainStack[top] = 0` tại các ranh giới câu lệnh/danh sách phẳng mà `esbuild` lặp bằng vòng `for` (không đệ quy): `;` và `,` (cũng như khi đóng `}`).
     - Tăng `chainStack[top]++` khi gặp các toán tử/cấu trúc có thể tạo cây đệ quy trong `esbuild`: `!`, `~`, `?`, `:`, `=` (không đi liền `==`/`===`/`!=`/`!==`/`<=`/`>=`, nhưng **có** tính `=` gán và `=>` arrow), `.` (không phải `...`), `<` (thẻ JSX mở; giảm hoặc không tăng đôi ở `</`), `**`, `+`/`-` đơn ngôi (khi `canRegex == true`, không phải `++`/`--`), và các từ khoá tiền tố/nhánh đệ quy (`new`, `typeof`, `void`, `delete`, `await`, `yield`, `else`).
     - Ngưỡng Lớp 1:
       - `maxEsbuildNesting = 400` cho `depth` ngoặc (giữ nguyên hằng số và thông báo lỗi cũ, corpus tối đa `321` ở p99.96, riêng 1 bundle có ngoặc trong chuỗi/comment đã được lexer lọc sạch).
       - `maxEsbuildChain = 2_500` cho `depth + chainStack[top]` (cao gấp **2,35×** mức tối đa `1.065` trên toàn bộ 2.568 script thực tế).

2. **Lớp 2 — Cầu chì thô phi-lexer (Zero-Lexer Hard Fuse, chạy song song mỗi byte):**
   - Không phụ thuộc vào bất kỳ cờ `inString`, `inComment`, `inTemplate` hay JSX nào — do đó **miễn nhiễm tuyệt đối** với mọi kỹ thuật làm lệch trạng thái lexer (kể cả `<div>Don't</div>` trong JSX hay cú pháp ES mới):
     - `rawDepth`: tăng ở `(`, `[`, `{`; giảm ở `)`, `]`, `}` (nếu `rawDepth > 0`). Trần cứng `maxRawBracketDepth = 4_000` (gấp **3,37×** mức tối đa `1.186` đo trên toàn bộ 2.568 script thực tế, vẫn an toàn hoàn toàn trước tràn stack của `esbuild`).
     - `rawChain`: reset về `0` khi gặp `;`, `,`, `}`, `(`, `[`, `{`, `"`, `'`, `` ` `` hoặc `\n` sau comment; tăng khi gặp `!`, `~`, `?`, `:`, `=`, `.`, `<`, `*`, `+`, `-` hoặc từ khoá đơn ngôi liên tiếp (`new`, `typeof`, `void`, `delete`, `await`, `yield`, `else`). Trần cứng `maxRawExprChain = 16_000` (gấp **2,21×** mức tối đa `7.232` trên toàn bộ 2.568 script thực tế, và thấp hơn 15×–50× ngưỡng gây stack overflow thực tế của `esbuild`).

3. Giữ nguyên chữ ký `transformState.allowDepth(src)` và chuỗi lỗi `nestingSkipError()` (`"parse: nesting over 400, esbuild skipped"`) để `ExtractSource`/`Extract` rơi êm sang `ExtractLoose` mà không phá tương thích.

**File:** `internal/jsapi/depth.go`, `internal/jsapi/round41_test.go`.

**Test** (`internal/jsapi/round41_test.go`)
- `TestRound41EsbuildNonBracketRecursionSubprocess`: chạy trong **subprocess** (`exec.Command(os.Args[0], …)`) đủ 9 vector không ngoặc ở kích thước gây tràn stack (`<a>`×80k, `!`×300k, `a?b:`×100k, `a=>`×100k, `a=`×100k, `2**`×100k, `.b`×200k, `new `×100k, `l:`×100k) qua `ExtractSource` (`.js`, `.ts`, `.tsx`, `.vue`) và `Extract` → tất cả thoát mã `0` dưới 2 s, trả `"esbuild skipped"`.
- `TestRound41MaxNestingLexerDesyncBypass`: kiểm tra trực tiếp `"//\r" + "("*5000`, `"//\u2028" + "("*5000`, `"<!--\n" + "("*5000`, `"({}/" + "("*5000 + "/1)"`, `"of/" + "("*5000 + "/1"`, và `"const x = <div>Don't</div>; " + "("*5000 + "; const y = <div>'</div>"` → tất cả đều trả `over == true`!
- `TestRound41NestingThresholdCorpus`: xác nhận 0/2.568 script trong corpus chạm Lớp 1 hoặc Lớp 2.

**Gate:** `testbed/endpoints-check.sh`; `TestSnapshot` MD5 so với `HEAD`; `JSAPI_STATS=list go test -run TestStats ./internal/jsapi`; `bin/testbed perfgate`.

**Chấp nhận:** MD5 snapshot trùng khít `6aaeefd647d4d130c6cb2faa5cd35983`; toàn bộ subprocess vector thoát 0; `perfgate` ≤ 15 s và ≤ 500 MB.

**`jsapi.Version`:** giữ nguyên `46` (snapshot không đổi). **Công sức:** M.

---

### A2. Vá lệch chẵn-lẻ backslash trong `mdsafe` & lọc C0/C1 trên `os.Stderr` (vá L3)

**Hiện trạng**
- `internal/mdsafe/mdsafe.go:68-74`: `inlineTextEscaper` chưa có cặp `\` → `\\`. Đầu vào `\[click\](https://evil.example)` biến thành `\\[click\\](https://evil.example)` — trong CommonMark `\\` là một dấu backslash hiển thị, còn `[click](…)` trở thành liên kết bấm được! Tương tự `` \`x\` `` mở được code span thật.
- `internal/mdsafe/mdsafe.go:40-45`: `codeSpan(s, true)` gọi `strings.ReplaceAll(s, "|", `\|`)`. Trong GFM, bước tách cột của bảng chạy **trước** bước phân tích code span và đếm số lượng dấu `\` đứng liền trước `|`:
  - Nếu có `k` dấu `\` đứng trước `|`, `ReplaceAll` biến thành `k + 1` dấu `\`. Khi `k` lẻ (vd URL/endpoint chứa `a\|b`, `k = 1`), kết quả là `` `a\\|b` `` (`k + 1 = 2`, chẵn) → GFM hiểu `\\` là backslash đã escape và dùng `|` để **cắt gãy cột bảng**!
  - Đồng thời, hàm trợ giúp `countUnescapedPipes` trong `internal/mdsafe/round41_test.go` chỉ kiểm tra `line[i-1] != '\\'` thay vì đếm chẵn-lẻ chuỗi `\` liền trước, nên đã bỏ lọt đúng ca `\\|`.
- Tại `cmd/jsharvest/`: một số lệnh vẫn in trực tiếp chuỗi có nguồn gốc từ target (header, base URL, đường dẫn endpoint, lý do lỗi host, tên action/label) ra `os.Stderr` chưa qua `mdsafe.StripControls`:
  - `cmd/jsharvest/main.go:1017-1018` (`intel.ClientHeaders`, `intel.Bases`)
  - `cmd/jsharvest/authz.go:179,182,185,200,284,287,290` (`rep.Host`, `n`, `rep.Stopped`, `h`, `m[h]`)
  - `cmd/jsharvest/verify.go:111,114,143,147` (`n`, `rep.Stopped`, `h`, `why`)
  - `cmd/jsharvest/replay.go:77,103,116,118,121,126` (`n`, `res.Action`, `res.Label`, `s.Endpoint`, `s.Refreshed`, `s.Stale`, `res.Stopped`)
  - `cmd/jsharvest/monitor.go:103,108,112` (`*target`, `n`, `ch.String()`)
  - `cmd/jsharvest/archive.go:430,443` (`e.host`, `n`), `diff.go:76` (`w`), `export.go:190` (`w`).

**Thiết kế**
1. Trong `internal/mdsafe/mdsafe.go`:
   - Đặt `\` → `\\` làm cặp **đầu tiên** của `inlineTextEscaper` (giống hệt `tableTextEscaper`).
   - Trong `codeSpan(s, true)`: thay `strings.ReplaceAll(s, "|", `\|`)` bằng hàm `escapeTableCodePipes(s string) string`:
     - Quét `s` một lượt; với mọi dãy `k` ký tự `\` liên tiếp (`k >= 0`), nếu ký tự kế tiếp là `|` thì ghi `2*k + 1` ký tự `\` rồi ghi `|`; nếu ký tự kế tiếp **không** phải `|` thì giữ nguyên đúng `k` ký tự `\` đó!
     - **Tính chất toán học:** trước mọi `|` trong chuỗi kết quả luôn có đúng `2k + 1` dấu `\` (luôn là số lẻ với mọi `k >= 0`) → GFM luôn coi dấu `|` là ký tự thường thuộc cùng một ô bảng, và bên trong code span các dấu `\` đơn lẻ không đứng trước `|` (như `C:\Users\foo` hay `\d+`) giữ nguyên 100%, không bị nhân đôi thừa.
2. Trong `internal/mdsafe/round41_test.go`:
   - Sửa `countUnescapedPipes(line)` đếm số dấu `\` liên tiếp ngay trước `|`: một dấu `|` là unescaped khi và chỉ khi `backslashes % 2 == 0`.
   - Thêm vector kiểm thử `a\|b`, `a\\|b`, `a\\\|b`, `\[evil\](https://example.test)`, và `` \`code\` `` cho cả 5 trình sinh báo cáo `.md`.
3. Thêm helper gọn `cleanStderr` / dùng `mdsafe.StripControls` cho các dòng in dữ liệu nguồn ngoài lên `os.Stderr` tại `cmd/jsharvest/{main,authz,verify,replay,monitor,archive,diff,export}.go`.

**File:** `internal/mdsafe/mdsafe.go`, `internal/mdsafe/round41_test.go`, `cmd/jsharvest/{main,authz,verify,replay,monitor,archive,diff,export}.go`.

**Test:** `TestRound41MarkdownBackslashParityAndLinks` (`internal/mdsafe/round41_test.go`) + test lọc C0/C1 (`\x1b]52;c;…\x07`, `\u009b31m`).

**Gate:** `testbed/{roles,replay,bola,verify,monitor}-check.sh`.

**Chấp nhận:** số cột mọi dòng bảng trong 5 báo cáo `.md` luôn bằng đúng số cột header với mọi tổ hợp `\^k|` (`k = 0..5`); không tạo được link/code-span sống qua `InlineText`; 0 chuỗi điều khiển lọt ra `os.Stderr`. **Công sức:** S.

---

### A3. Gia cố parser body cho `guard.Rules` và `replay.Policy` (vá M12)

**Hiện trạng**
- `internal/guard/rules.go:66` (`EffectiveMethod`), `rules.go:260` (`BodyActionFields`) và `internal/replay/policy.go:250` (`bodyValues`) đều gọi `url.ParseQuery(t)` và bỏ qua toàn bộ kết quả nếu `err != nil`. Trong Go (`net/url`), bất kỳ dấu chấm phẩy `;` nào trong form (vd `comment=a;b&action=delete_account` hoặc `_method=DELETE;foo=1`) hoặc một escape `%ZZ` lỗi ở trường khác đều khiến `url.ParseQuery` trả `err != nil` (hoặc cắt bỏ phần tử chứa `;`), làm vô hiệu hoá hoàn toàn kiểm tra `_method`, `action=delete` và `action=logout`!
- `BodyActionFields` (`rules.go:246-273`) và `bodyValues` (`replay/policy.go:236-257`) chưa phân tích `multipart/form-data`: một `<form method="POST" enctype="multipart/form-data">` gửi trường `action=delete` hoặc `op=logout` sẽ đi lọt qua `BodyActionFields` (khi chạy `-allow-write` hoặc trong cửa sổ `AllowWrites` của `relogin`) và được `replay.Policy` xếp là `Write` thay vì `Never`.
- `walkActionJSON` (`rules.go:275-293`) dừng ngay khi `len(*out) >= 64`: một mảng JSON-RPC batch gồm 64 phần tử `{"method":"ping"}` đi trước `{"method":"account.delete"}` ở phần tử thứ 65 sẽ né sạch kiểm tra phá huỷ. (Tương tự `replay/policy.go:259` `walk` chưa giới hạn tổng số nút duyệt trên JSON lớn).
- `Rules.Classify` (`rules.go:114-118`) chạy `BodyActionFields` **trước** khi xét xem request có phải là GraphQL `query` chỉ đọc hay không: một `POST /graphql` với `{"query":"query Search($f: Filter){ items(filter:$f){id} }","variables":{"f":{"action":"delete"}}}` (chỉ lọc danh sách log có `action == "delete"`) sẽ bị chặn nhầm là `"destructive"` thay vì cho qua `"read"`.

**Thiết kế**
1. **Form parser chịu lỗi (`forEachFormField`):**
   - Tách chuỗi trên cả `&` và `;` bằng vòng lặp chỉ số (không cấp phát slice tạm).
   - Với mỗi đoạn `rawK=rawV`: giải mã `k` bằng `queryUnescapeLenient(rawK)` và `v` bằng `queryUnescapeLenient(rawV)` (nếu `url.QueryUnescape` báo lỗi `%` không hợp lệ thì thay `+` bằng `' '` và giữ nguyên các ký tự còn lại thay vì huỷ bỏ!).
   - Áp dụng đồng nhất cho:
     - `EffectiveMethod` (`guard/rules.go:65-68`) khi tìm `_method`;
     - `BodyActionFields` (`guard/rules.go:259-270`);
     - `operationVerb` (`guard/rules.go:297-309`) trên `u.RawQuery` (để `/rpc?note=%ZZ&action=approve` vẫn bị bắt khi `Explore`);
     - `bodyValues` (`replay/policy.go:249-255`).
2. **Hỗ trợ `multipart/form-data` có trần an toàn:**
   - Khi `strings.Contains(ct, "multipart/")` (hoặc body bắt đầu bằng `--` và chứa `Content-Disposition: form-data`):
     - Nếu `mime.ParseMediaType(contentType)` lấy được `boundary != ""`, đọc bằng `multipart.NewReader(strings.NewReader(t), boundary)` tối đa `maxMultipartParts = 64` part; bỏ qua part có `p.FileName() != ""` (file upload nhị phân); với part text thường, đọc tối đa `4096` byte bằng `io.LimitReader` để lấy `(formName, value)`.
     - **Fallback khi thiếu boundary header hoặc body bị cắt giữa chừng:** quét các đoạn `Content-Disposition: form-data; name="..."` để trích giá trị text ngắn phía sau `\r\n\r\n` (hoặc `\n\n`), tương tự cách `EffectiveMethod` đang bắt `name="_method"` ở `:69`, đồng thời đọc thật giá trị của `_method` (nếu `_method` là `GET`/`HEAD` hợp lệ hoặc `DELETE` trá hình thì phân loại chính xác).
3. **Bỏ trần mù 64 phần tử trong JSON & đặt trần nút duyệt:**
   - Thay giới hạn `len(*out) >= 64` ở `walkActionJSON` (`rules.go:276`) bằng bộ đếm tổng số nút JSON đã thăm `*visited <= maxActionJSONNodes` (`10_000` nút, độ sâu `<= 20`), hoặc thêm hàm trực tiếp `bodyHasDestructiveAction(body, contentType string) bool` trả `true` ngay lập tức khi gặp giá trị đầu tiên khớp `hasWord(destructiveRe, v)`. Batch JSON-RPC hàng trăm phần tử đều được kiểm trọn vẹn dưới vài chục micro-giây.
   - Áp trần nút `10_000` tương tự cho `walk` trong `internal/replay/policy.go:259`.
4. **Thứ tự ưu tiên cho GraphQL `query` chỉ đọc trong `Rules.Classify` (`rules.go:114-125`):**
   - Tính `method := EffectiveMethod(...)` và `gql, gqlWrite, gqlReason := graphQL(method, req)` ngay sau `Destructive(req.URL)`:
   - Nếu `!(gql && !gqlWrite)` (tức **không phải** một GraphQL `query` đã xác minh chỉ đọc), mới chạy kiểm tra `BodyActionFields` phá huỷ!
   - Nếu là GraphQL ghi hoặc không rõ (`gql && gqlWrite`), vẫn kiểm tra cả `hasWord(destructiveRe, req.Body+" "+req.URL)` lẫn `BodyActionFields` để chặn mọi mutation xóa/logout dù `-allow-write` đang bật.

**File:** `internal/guard/rules.go`, `internal/replay/policy.go`, `internal/guard/round41_test.go`, `internal/replay/round41_test.go`.

**Test**
- `TestRound41FormSemicolonAndBadPercent`: `note=a;b&action=delete`, `bad=%ZZ&action=logout`, `_method=DELETE;x=1` → `Guard` chặn `"destructive"`, `replay.Policy` trả `Never`.
- `TestRound41MultipartDestructiveAndLogout`: `multipart/form-data` có part `action=destroy` và part `op=sign_out` (cả đủ boundary lẫn body cụt) → `Guard` chặn `"destructive"` kể cả khi `AllowWrite: true`; `replay.Policy` trả `Never`.
- `TestRound41JSONRPCBatch65thDestructive`: mảng 70 phần tử JSON-RPC với phần tử thứ 68 là `{"jsonrpc":"2.0","method":"user.delete","id":68}` → bị chặn `"destructive"`.
- `TestRound41GraphQLReadQueryWithFilterAction`: `POST /graphql` `query ListAudit($f: Filter){ logs(filter: $f){ id } }` kèm `variables.f.action = "delete"` → được phép qua (`Pass`, `"read"`), trong khi `mutation` cùng biến vẫn bị chặn `"destructive"`.

**Gate:** `testbed/attach-guard.sh`, `testbed/explore-check.sh`, `testbed/replay-check.sh`.

**Chấp nhận:** toàn bộ test mới & 3 gate xanh 100%. **Công sức:** M.

---

### A4. Vá kín `Redactor.URL`/`LogURL`, scrub báo cáo `verify`/`authz`/`bola` & đồng bộ `JudgePeer` (vá H2 & M1)

**Hiện trạng**
1. `internal/traffic/redact.go:237-244` (`Redactor.URL`):
   - Dùng `u.User.Password()` (trả chuỗi đã giải mã `%`) rồi `strings.Replace(raw, ":"+p+"@", …)`: nếu URL chứa ký tự mã hoá phần trăm trong mật khẩu như `https://admin:p%40ssword123@example.test/api`, `p` là `p@ssword123` nên không khớp `":p%40ssword123@"` và mật khẩu còn nguyên trên đĩa!
   - Nếu URL dùng token làm username không có dấu `:` (chuẩn GitHub/GitLab/Basic token: `https://ghp_xxx@example.test/repo` hoặc `https://x-access-token@…`), `u.User.Password()` trả `ok == false` và chỉ những mẫu nằm trong `secretsig` mới được `r.Text` bắt, còn token tuỳ chỉnh độ dài bất kỳ nằm nguyên trước `@`.
2. `internal/traffic/redact.go:385,400` (`maskLogQuerySeg` / `looksLikeLogToken`):
   - Dòng 385 gọi `logQueryRedactor.Text(v)` thay vì `logQueryRedactor.URL(v)`, nên tham số redirect mang URL có userinfo như `?next=https%3A%2F%2Fuser%3Apass%40example.test%2F` không được che userinfo trên log.
   - Dòng 400 từ chối mọi `strings.HasPrefix(trimmed, "/")` để tránh che nhầm đường dẫn `/assets/…`, nhưng một chuỗi base64 chuẩn bắt đầu bằng byte `0xFC..0xFF` (ký tự đầu `/`) và kết thúc bằng đệm `=` hoặc `==` (không bao giờ là đường dẫn URL thông thường) lại bị bỏ lọt.
3. Các trường chuỗi báo cáo còn sót khi `Redactor != nil` (`-redact=true` mặc định cho `authz` và `verify`):
   - `internal/verify/verify.go:275-288`: mới scrub `rep.Results[i].URL` và `rep.Canaries[i].Err`; chưa scrub `rep.Results[i].Reason` (chứa URL `Location` redirect 3xx từ `verify.go:1084` như `302 -> https://sso.example.test/authorize?id_token_hint=eyJ…` hoặc chuỗi lỗi dial), `rep.CloudChecks[i].URL`, `rep.CloudChecks[i].Error`, `rep.Stopped`, và giá trị trong `rep.HostsGated`.
   - `internal/replay/authz.go` & `internal/replay/bola.go`: khi `o.Sender != nil && o.Sender.Redactor() != nil`, các trường `Trial.Reason`, `PeerItem.Reason` (chứa `t.Err`, `c1.Err`, hoặc `302 to <Location>` tại `compare.go:121` / `judge_peer.go:542`), `Stopped`, `StoppedEndpoints` và `Notes` (chứa `rc.dead` / `p.deadWhy()`) chưa đi qua `Redactor`.
4. Đồng bộ `M1` trong `internal/replay/judge_peer.go:502-507` và `:549-555`:
   - Trong `Judge` (`internal/replay/compare.go:131`), Đợt 41A đã thêm chốt chặn `if c.Kept` ngay đầu nhánh `2xx` để không bao giờ kết luận `Bypass`/`Likely`/`NeedsReview` nếu còn sót credential không làm mới được.
   - Trong `JudgePeer` (`judge_peer.go`), `c.Kept` mới chỉ được kiểm ở nhánh `401/403` (`:496` và `:531`), chưa có ở nhánh `2xx` ghi (`:502`) và `2xx` đọc (`:549`). Dù `bola.go` hiện giữ lại khi `len(tr.kept) > 0`, một caller gọi trực tiếp `JudgePeer` hoặc thay đổi luồng sau này sẽ kết luận sai `Bypass`/`NeedsReview` nếu thiếu chốt bảo vệ tương đương tại `JudgePeer`.

**Thiết kế**
1. **Sửa `Redactor.URL` (`internal/traffic/redact.go:237-244`) trên lát authority thô:**
   - Viết helper tách phần authority sau `://` (cho tới ký tự đầu tiên thuộc `/ ? #` hoặc hết chuỗi). Nếu trong authority có dấu `@` cuối cùng tại chỉ số `at`:
     - Phần `userinfo := auth[:at]`:
       - Nếu có dấu `:` (`rawUser, rawPass, ok := strings.Cut(userinfo, ":")`): giải mã nhẹ `decPass` để tính HMAC nhất quán `r.mask(decPass)` (nếu giải mã lỗi thì `r.mask(rawPass)`), đồng thời nếu `Sensitive(rawUser)` hoặc `looksLikeLogToken(rawUser)` thì che cả `rawUser`; ghép lại `maskedUser + ":" + maskedPass + "@" + auth[at+1:]`.
       - Nếu **không** có dấu `:` (`https://token@host`): che toàn bộ `userinfo` thành `r.mask(decUser) + "@" + auth[at+1:]`.
   - Sau đó vẫn truyền qua `r.Text(raw)` để tiếp tục che query/path token như cũ.
2. **Sửa `maskLogQuerySeg` & `looksLikeLogToken` (`redact.go:385,400`):**
   - Tại `:385`: gọi `logQueryRedactor.URL(v) != v` (bao hàm cả `r.Text(v)` lẫn userinfo trong URL lồng nhau).
   - Tại `:400`: chỉ miễn trừ `strings.HasPrefix(trimmed, "/")` khi `pad == 0` (nếu có hậu tố `=`/`==` ở cuối và toàn bộ ký tự thuộc bảng chữ cái base64 chuẩn với đủ chữ hoa + chữ thường + chữ số thì vẫn bắt là token).
3. **Scrub trọn vẹn báo cáo khi `Redactor != nil`:**
   - Trong `internal/verify/verify.go:275-288`: scrub thêm `rep.Results[i].Reason = r.URL(rep.Results[i].Reason)`, `rep.CloudChecks[i].URL = r.URL(...)`, `rep.CloudChecks[i].Error = r.URL(...)`, `rep.Stopped = r.URL(rep.Stopped)`, và từng giá trị `rep.HostsGated[h] = r.URL(v)`.
   - Trong `internal/replay/authz.go` (cuối `Authz` trước khi trả `a.out`) và `internal/replay/bola.go` (cuối `Bola` trước khi trả `b.rep`): nếu `r := o.Sender.Redactor(); r != nil`, chạy `scrubAuthzReport(a.out, r)` / `scrubBolaReport(b.rep, r)` dùng `r.URL` trên `Stopped`, `Notes[i]`, `HostsBlocked[k]`, `StoppedEndpoints[k]`, `Items[i].Trials[j].Reason`, và `Items[i].Reason`.
4. **Đồng bộ `c.Kept` trong `JudgePeer` (`internal/replay/judge_peer.go:502,549`):**
   - Tại `:502` (`case status >= 200 && status < 300:` của write): thêm đầu nhánh `if c.Kept { return out.with(Unclear, fmt.Sprintf("%d, with a foreign credential still on the request", status)) }`.
   - Tại `:549` (`// A success.` của read): thêm ngay dòng đầu `if c.Kept { return out.with(Unclear, fmt.Sprintf("%d, with a foreign credential still on the request", status)) }`.

**File:** `internal/traffic/redact.go`, `internal/verify/verify.go`, `internal/replay/{authz,bola,judge_peer}.go`, cùng các file `round41_test.go` tương ứng.

**Test**
- `TestRound41RedactorURLPercentEncodedAndTokenUserinfo`: kiểm `https://admin:p%40ss%3A1@example.test/p`, `https://custom_pat_token_12345@example.test/p`, và `LogURL("https://example.test/cb?next=https%3A%2F%2Fuser%3Ap%2540ss%40internal.example.test%2F")`.
- `TestRound41VerifyAndAuthzScrubReasonsAndRedirectLocations`: mock server trả `302` với `Location: https://idp.example.test/cb?access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.sigabcdef123456` → xác nhận `verify.json`, `verify.md`, `authz.json`, `authz.md`, `bola.json`, `bola.md` đều đã che `access_token`.
- `TestRound41JudgePeerKeptNeverBypass`: gọi `JudgePeer` với `Kept: true` và response `200` chứa canary riêng của A → trả `Unclear`, không bao giờ trả `Bypass` hay `NeedsReview`.

**Gate:** `testbed/replay-check.sh`, `testbed/bola-check.sh`, `testbed/verify-check.sh`.

**Chấp nhận:** 0 rò rỉ token/password qua userinfo, `Location` 3xx hay chuỗi lỗi mạng trong mọi file `.json`/`.md` khi `-redact=true`; 3 gate xanh. **Công sức:** M.

---

### A5. Sửa thứ tự đếm `s.n` trong `Sender.DoExternal` & che `Sent.Item` bằng `r.URL` (vá L10)

**Hiện trạng**
- `internal/replay/send.go:792-830`: `DoExternal` khoá `s.mu`, kiểm `s.stopped` và `s.o.Max`, rồi lập tức tăng `s.n++` tại dòng 803 **trước** khi lấy `s.slots` (`:808`) và trước khi ngủ chờ `-rate` (`:823`).
  - Hệ quả 1: Nếu `ctx` (như `reqCtx` 10 s của `ProbeCloud` hoặc Ctrl-C) bị huỷ trong lúc đang xếp hàng chờ slot hoặc chờ `-rate`, hàm trả `ctx.Err()` ở dòng 810/825/829 mà **không gọi `s.write(line)`** và **chưa gửi request nào** — làm lệch bất biến `Sender.Count() == số dòng sent.jsonl` và trừ oan hạn mức `-max` (thậm chí kích hoạt `s.stop(ErrBudget.Error())` sớm).
  - Hệ quả 2: Thứ tự `N` ghi vào `sent.jsonl` có thể đảo lộn so với thứ tự thực gửi khi nhiều goroutine cạnh tranh `s.slots`.
- `internal/replay/send.go:733-735`: `Sender.write` gọi `l.Item = r.Text(l.Item)` thay vì `r.URL(l.Item)`, nên nếu `l.Item` là URL chứa `user:pass@host` thì mật khẩu không bị che.

**Thiết kế**
1. Trong `(*Sender).DoExternal` (`internal/replay/send.go:791-840`):
   - **Bước 1 (kiểm nhanh không tăng đếm):** dưới `s.mu`, nếu `s.stopped != ""` trả `errStopped`; nếu `s.o.Max > 0 && s.n >= s.o.Max` gọi `s.stop(ErrBudget.Error())` và trả `ErrBudget`.
   - **Bước 2:** chờ `s.slots` (hoặc `<-ctx.Done()`).
   - **Bước 3:** tính `turn` theo `s.o.Rate` và chờ `time.Until(turn)` (hoặc `<-ctx.Done()`).
   - **Bước 4 (chốt số thứ tự ngay trước khi ghi/gửi):** khoá lại `s.mu`, kiểm lại `s.stopped != ""` và `s.o.Max > 0 && s.n >= s.o.Max`; nếu hợp lệ mới tăng `s.n++`, gán `n := s.n`, mở khoá và đảm bảo **mọi nhánh từ đây trở xuống** (`DryRun`, lỗi `client.Do`, lỗi đọc `hb`, thành công) đều gọi `s.write(line)` đúng 1 lần (giống hệt cấu trúc của `Sender.Send` tại `:595-645`).
2. Trong `(*Sender).write` (`internal/replay/send.go:734`): đổi `l.Item = r.Text(l.Item)` thành `l.Item = r.URL(l.Item)`.

**File:** `internal/replay/send.go`, `internal/verify/round41_test.go`.

**Test:** `TestRound41DoExternalCancelWhileRateLimitedDoesNotCount` — đặt `Rate: 500ms`, `Max: 2`, bắn 1 request thành công rồi bắn request thứ 2 với `ctx` timeout `30ms` (hủy trong lúc chờ rate), sau đó bắn request thứ 3 với `ctx` bình thường → request thứ 3 vẫn được gửi thành công (`Count() == 2`), và `sent.jsonl` có đúng `2` dòng (`N = 1, 2`).

**Gate:** `testbed/verify-check.sh`, `testbed/replay-check.sh`.

**Chấp nhận:** `Sender.Count()` luôn bằng đúng số dòng của `sent.jsonl` kể cả khi timeout/cancel giữa chừng; 2 gate xanh. **Công sức:** S.

---

## 3. Đợt 41.1B: Vá 6 cạnh biên, độ bền file & caller phụ

Các mục trong Đợt 41.1B chạm những vùng độc lập và nhỏ gọn: `B1 → B2 → B3 → B4 → B5 → B6`.

### B1. Mở rộng `traffic.AppendOpen` sang `archive`/`monitor` & `fsync` cho `SaveMap` (vá L5)

**Hiện trạng**
- Đợt 41C (`L5`) đã chuyển `engine`, `results`, `guard` sang `traffic.AppendOpen` (tự phát hiện và chặt bỏ dòng JSONL cụt ở cuối file sau sự cố sập nguồn/SIGKILL trước khi ghi tiếp), nhưng còn sót 2 nơi mở file JSONL bằng `os.OpenFile(..., os.O_APPEND, 0o600)`:
  1. `internal/archive/run.go:571` (`appendFile`, dùng cho `archive.jsonl` và `historical.jsonl`).
  2. `internal/monitor/report.go:25` (`AppendChanges`, dùng cho `monitor/changes.jsonl`).
- `internal/store/store.go:345` (`SaveMap`) gọi `writeFileAtomic(dst, body)` — hàm này hiện ghi file `.tmp` rồi `Close()` + `os.Rename(...)` mà chưa gọi `tmp.Sync()` trước khi đóng (khác với `flushLocked` đã có `f.Sync()`).

**Thiết kế**
1. Thay `os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)` tại `internal/archive/run.go:571` và `internal/monitor/report.go:25` bằng `traffic.AppendOpen(path)`.
2. Thêm `if err := tmp.Sync(); err != nil { ... }` trước `tmp.Close()` trong `writeFileAtomic` (`internal/store/store.go`).

**File:** `internal/archive/run.go`, `internal/monitor/report.go`, `internal/store/store.go`.

**Test:** unit test xác nhận `AppendChanges` và `appendFile` cắt bỏ phần đuôi không có `\n` trước khi nối bản ghi JSONL hợp lệ mới.

**Gate:** `testbed/archive-check.sh`, `testbed/monitor-check.sh`, `testbed/pipeline-check.sh`. **Công sức:** S.

---

### B2. Chia sẻ `Redactor` và che trọn vẹn `Entry` trong cửa sổ `relogin` (vá M6)

**Hiện trạng**
- `internal/capture/record.go:108`: `NewRecorder` tự khởi tạo `red: traffic.NewRedactor()` với khóa HMAC ngẫu nhiên riêng, thay vì dùng `e.redactor` của engine khi `-redact` đang bật — làm hash giả danh `<redacted:xxxxxxxx>` của request trong lúc `relogin` không khớp với hash của cùng token ở các request còn lại trong `requests.jsonl`.
- `internal/capture/record.go:505-509`: khi `x.sensitive` bật, recorder chỉ gọi `r.red.URL(e.URL)`, `r.red.Headers(e.Headers)` và `r.red.Body(e.Body)`, bỏ sót `e.Page` (URL trang OAuth/SSO có thể mang `?code=…` nếu chưa qua `Entry`) và đặc biệt bỏ sót **`e.Response`** (`e.Response.Headers["location"]`, `e.Response.Headers["set-cookie"]`, `e.Response.Body` chứa `access_token`/`refresh_token` trả về từ `POST /login`) khi chạy mặc định không bật `-redact` toàn cục!

**Thiết kế**
1. Thêm trường `Redactor *traffic.Redactor` vào `capture.RecordOptions` (`internal/capture/record.go`); trong `NewRecorder`, nếu `opts.Redactor != nil` thì dùng `opts.Redactor`, ngược lại mới tạo `traffic.NewRedactor()` riêng cho cửa sổ nhạy cảm.
2. Tại `internal/engine/engine.go:1058`, truyền `Redactor: e.redactor` vào `capture.RecordOptions`.
3. Tại `internal/capture/record.go:505-509`, thay 3 dòng che lẻ bằng lời gọi đầy đủ `r.red.Entry(&e)` (hàm `Redactor.Entry` đã che đồng bộ `e.URL`, `e.Page`, `e.Headers`, `e.Body`, `e.Response.Headers` và `e.Response.Body`).

**File:** `internal/capture/record.go`, `internal/engine/engine.go`, `internal/capture/round41_test.go`.

**Test:** `TestRound41SensitiveWindowRedactsResponseAndSharesHMAC` — mô phỏng `POST /auth/login` trả `200 {"access_token":"secret-jwt-value"}` + `Set-Cookie: sid=secret` khi `-redact=false` (chỉ có `SensitiveWindow` bật) và khi truyền chung `Redactor` → cả request lẫn response body/headers đều được che và trùng mã băm HMAC.

**Gate:** `testbed/session-check.sh`. **Công sức:** S.

---

### B3. Cảnh báo phạm vi browser của `-lan-guard` trong `watch` khi `-guard off` (vá M3)

**Hiện trạng**
- `internal/engine/watch.go:107-109` chỉ in cảnh báo cross-tab khi `cfg.Guard == true`. Khi người dùng chạy `jsharvest watch -attach … -guard=false` (mặc định mới của M3 vẫn bật `-lan-guard=true`), `Fetch.enable` cấp browser của `LANOnly` vẫn chặn truy cập tới IP private/loopback của các worker/service worker không gắn được về tab khác trong cùng trình duyệt (ví dụ dev server `127.0.0.1:3000` mở ở tab bên cạnh) mà chưa báo cho người dùng biết cách tắt (`-lan-guard=false`).

**Thiết kế**
- Tại `internal/engine/watch.go:107-109`, thêm nhánh `else if e.guard != nil`:
  `slog.Warn("watch: -lan-guard blocks private/loopback requests of unattributed workers in this browser; use a dedicated browser profile or -lan-guard=false if other tabs use local services")`.

**File:** `internal/engine/watch.go`.

**Test:** kiểm tra log cảnh báo trong unit test cấu hình `watch` hoặc kiểm tra không ảnh hưởng hành vi `lan-check`/`attach-guard`.

**Gate:** `testbed/lan-check.sh`, `testbed/attach-guard.sh`. **Công sức:** S.

---

### B4. Tinh chỉnh 3 cạnh biên của `M8`, `M9` và `M11`

**Hiện trạng**
1. **`M8` (`internal/mcpserver/server.go:95`):** `promptInjectionRe` dùng `[\r\n](?:system|assistant):` nên không bắt chuỗi bắt đầu ngay ở byte 0 bằng `"system: ignore safety..."` hoặc `"assistant: ..."`.
2. **`M9` (`internal/browser/browser.go:90-101, 256-265` & `proc_other.go:9`):**
   - Khi `o.Attach == ""` và `o.ProfileDir == ""`, nếu cả `o.NoPrediction == false` (tức `-guard=false`) lẫn `o.Proxy == ""`, `browser.New` để `profile = ""` nên `chromedp` tự tạo thư mục `/tmp/chromedp-runner*` nằm ngoài `RegisterTempDir` và `sweepStaleProfiles`.
   - Trong `sweepStaleProfiles` (`:257-262`), symlink `SingletonLock` của Chrome có dạng `<hostname>-<pid>`. Hàm hiện lấy `<pid>` mà chưa so `<hostname>` với `os.Hostname()`: nếu `/tmp` được chia sẻ giữa các container hoặc mount chung, một tiến trình Chrome đang chạy ở container khác có PID không tồn tại trong PID namespace hiện tại sẽ bị tưởng nhầm là đã chết sau 24h!
   - Trong `internal/browser/proc_other.go:9` (`//go:build !unix`), `pidAlive` đang trả cứng `false` — nghĩa là trên Windows/플랫폼 khác, mọi profile quá 24h đang chạy thật đều bị coi là chết và bị xoá! Trả `true` an toàn hơn (chỉ dọn các thư mục mồ côi không còn `SingletonLock` hoặc trên Unix nơi kiểm được `kill(pid, 0)`).
3. **`M11` (`internal/engine/http.go:274-313`):** trong callback `SourceMap`, khi `st.SaveMap(m.Body)` trả `store.ErrStoreBudget` (hoặc `put(...)` của một file nguồn chạm trần và bật `storeBudgetHit`), vòng lặp `for _, f := range own` vẫn tiếp tục chạy nốt tới 5.000 file nguồn (mỗi lần lại gọi `put` rồi thất bại và giảm `mapSourcesStored`).

**Thiết kế**
1. **`M8`:** đổi nhánh cuối của `promptInjectionRe` tại `mcpserver/server.go:95` thành `(?:^|[\r\n])\s*(?:system|assistant):`.
2. **`M9`:**
   - Tại `browser/browser.go:90`: khi `o.Attach == ""` và `profile == ""`, **luôn** tạo `os.MkdirTemp("", "jsharvest-profile-")` và đăng ký `RegisterTempDir(dir)` (khi `o.NoPrediction == false` và `o.Proxy == ""`, `webrtcPolicy(dir, false)` chỉ `os.Stat` marker rồi trả `nil` ngay, không tốn I/O ghi `Preferences`, đồng thời mọi phiên Chrome không có `-profile` đều có thư mục `0700` nằm dưới quyền quản lý dọn dẹp thống nhất).
   - Tại `sweepStaleProfiles` (`browser/browser.go:257-262`): tách `host, pidStr` tại dấu `-` cuối cùng của `SingletonLock`; nếu `myHost, err := os.Hostname(); err != nil || host != myHost` thì giữ lại thư mục (`continue`) trừ khi không đọc được host; chỉ xoá khi `host == myHost && !pidAlive(pid)`.
   - Tại `browser/proc_other.go:9`: đổi `func pidAlive(pid int) bool { return true }`.
3. **`M11`:** tại `engine/http.go:274-310`, nếu `storeBudgetHit.Load()` đã bật trước hoặc ngay sau `st.SaveMap` / `put`, đặt `putFailed = true` và `break` ngay khỏi vòng `for _, f := range own` (vẫn gọi `m.NoteStored(storedRefs, false)` ở dòng 318 để cache singleflight không bị lệch).

**File:** `internal/mcpserver/server.go`, `internal/browser/browser.go`, `internal/browser/proc_other.go`, `internal/engine/http.go`, và unit test trong các file `round41_test.go`.

**Test**
- `TestRound41PromptInjectionAtByteZero` (`internal/mcpserver/round41_test.go`).
- `TestRound41StaleProfileForeignHostnameKept` (`internal/browser/round41_test.go`).
- Unit test callback sourcemap dừng ngay khi `MaxRunBytes` đã đầy (`internal/engine/`).

**Gate:** `testbed/flows-gate.sh`, `testbed/webrtc-check.sh`, `testbed/docker-check.sh`, `testbed/pipeline-check.sh`. **Công sức:** S.

---

### B5. Quyền `0700`/`0600` an toàn khi bind-mount `$HOME` trong `docker/entrypoint.sh` (vá L7)

**Hiện trạng**
- `docker/entrypoint.sh:15-18`: khi fallback sang `HOME=/tmp/jsharvest-home`, lệnh `mkdir -p "$HOME"` chạy với `umask` mặc định (`022` → quyền `0755`), và tại `:53` lệnh `touch "$XAUTHORITY"` tạo `.Xauthority` với quyền `0644` nếu chạy `JSHARVEST_VNC_PASSWORD=...` (bỏ qua khối dòng 61-65).
- Ngược lại, tại dòng 63: `(umask 077 && mkdir -p "$HOME" && chmod 700 "$HOME" && ...)` — nếu người dùng chạy container với `--user 1001:1001` và bind-mount một thư mục `$HOME` thuộc sở hữu `root` nhưng cấp quyền nhóm ghi (`0770`), phép kiểm `[ -w "$HOME" ]` ở dòng 15 đúng nên giữ nguyên `$HOME`, rồi `chmod 700 "$HOME"` ở dòng 63 trả `EPERM` và làm cả `entrypoint.sh` thoát lỗi ngay lập tức vì `set -eu`!

**Thiết kế**
1. Tại `docker/entrypoint.sh:15-19`:
   ```sh
   if [ ! -w "${HOME:-/nonexistent}" ]; then
     export HOME=/tmp/jsharvest-home
   fi
   (umask 077 && mkdir -p "$HOME")
   chmod 700 "$HOME" 2>/dev/null || true
   ```
2. Tại `:53`: tạo cookie X11 dưới `umask 077`:
   ```sh
   (umask 077 && : >"$XAUTHORITY")
   ```
3. Tại `:63`: bỏ `chmod 700 "$HOME"` cứng bên trong `&&` (vì bản thân file `"$HOME/vnc-password"` và `"$HOME/.vncpass"` đã được tạo mới dưới `umask 077` → luôn mang quyền `0600` bất kể chủ sở hữu của thư mục cha).

**File:** `docker/entrypoint.sh`.

**Test & Gate:** `testbed/docker-check.sh` (bổ sung kiểm tra quyền `0600` của `.Xauthority` / `vnc-password` và ca thư mục `$HOME` ghi được nhưng không phải chủ sở hữu). **Công sức:** S.

---

### B6. Nối `o.Resolver` vào `resolve.Policy` của `httpcrawl` & khử tra DNS ngoài cho 4 file test còn lại (vá L9)

**Hiện trạng**
- `internal/httpcrawl/crawl.go:443-447` khởi tạo `policy := resolve.NewPolicy(o.Target.Hostname(), o.InScope, o.NoDNS)` và `specPolicy := resolve.NewPolicy(...)`. `resolve.NewPolicy` (`internal/resolve/policy.go:47-54`) luôn gọi `net.DefaultResolver.LookupNetIP` trừ khi `noDNS == true`, **không dùng `o.Resolver` của `httpcrawl.Options`**. Hệ quả: ngay cả khi test đã truyền `Resolver: nxResolver`, `NewPolicy` vẫn gõ DNS thật của hệ điều hành cho `example.com` / `app.example.test` (tốn thời gian hoặc phụ thuộc mạng máy chạy test), và nếu người dùng cấu hình `-host-resolver-rules` trong `httpcrawl` thì `resolve.Policy` cũng không thấy ánh xạ đó.
- Ngoài `pipeline_test.go`, `waf_test.go` và `breaker_test.go` đã gắn `nxResolver` ở Đợt 41A, còn 4 file test trong `internal/httpcrawl/` dựng `Options` với tên miền giả mà chưa gắn `Resolver: nxResolver`: `round33_test.go`, `round37_test.go`, `round40_test.go` và `specprobe_test.go`.

**Thiết kế**
1. Thêm `resolve.NewPolicyWithLookup(target string, inScope scope.Func, noDNS bool, lookupFn func(context.Context, string) ([]netip.Addr, error)) *Policy` trong `internal/resolve/policy.go` (khi `lookupFn != nil && !noDNS` thì dùng `lookupFn`, còn `NewPolicy` cũ giữ nguyên chữ ký gọi sang `NewPolicyWithLookup(..., nil)`).
2. Trong `internal/httpcrawl/crawl.go:443-447`: tạo hàm `policyLookup` đi qua `rules` (`netsafe.ParseHostRules(o.HostRules)`) và `o.Resolver` (khi `o.Resolver != nil`), truyền vào `NewPolicyWithLookup` cho cả `policy` lẫn `specPolicy`.
3. Gắn `Resolver: nxResolver` vào các `Options` dùng host giả trong `round33_test.go`, `round37_test.go`, `round40_test.go` và `specprobe_test.go`.

**File:** `internal/resolve/policy.go`, `internal/httpcrawl/crawl.go`, `internal/httpcrawl/{round33,round37,round40,specprobe}_test.go`.

**Test:** đếm số lượt gọi `o.Resolver` trong unit test của `httpcrawl.Crawl` và xác nhận `0` gói UDP/TCP DNS rò ra ngoài trong toàn bộ `go test ./internal/httpcrawl`.

**Gate:** `testbed/pipeline-check.sh`, `testbed/waf-check.sh`. **Công sức:** S.

---

## 4. Đợt 41.1C: Đồng bộ tài liệu, footer báo cáo & thu hẹp `.gitleaks.toml`

### C1. Chỉnh chính xác mô tả kỹ thuật trong `docs/CURRENT.md`
- `docs/CURRENT.md:18`: sửa chi tiết `M13` từ `"maxEsbuildFallbacks = 4"` thành mô tả đúng mã nguồn (`fallbackBudget(len(src))` từ `2..8` theo kích thước script + tối đa `maxSFCSpans = 4` block `<script>` mỗi SFC, bỏ fallthrough lặp `.ts`) và cập nhật câu mô tả `M7` thành cầu chì 2 lớp của Đợt 41.1.
- `docs/CURRENT.md:30`: sửa chi tiết `M10` từ `"phục hồi .sending"` thành mô tả đúng mã nguồn (`WritePending` ghi nguyên tử `0600`, `ReadPending`/`ClearPending` chỉ xoá sau khi gửi webhook thành công kèm timeout `30 s`).

### C2. Đồng bộ câu kết của `authz.md` và `bola.md` theo trạng thái `-redact`
- `internal/replay/report.go:80` và `internal/replay/bola_report.go:86` hiện luôn in cứng câu `"The trial files (authz/trials/...) hold the ... live credentials."` ngay cả khi mặc định mới `-redact=true` đã che toàn bộ credential trong `trials/*.http`.
- **Thiết kế:**
  - Thêm `Redacted bool \`json:"redacted,omitempty"\`` vào `AuthzReport` (`authz.go:55`), gán `a.out.Redacted = o.Sender != nil && o.Sender.Redactor() != nil`. Trong `report.go:80`: nếu `r.Redacted` in `"Credentials in the trial files (authz/trials/) are redacted (-redact=false keeps live credentials)."`, ngược lại giữ nguyên câu cũ.
  - Thêm `TrialsRedacted bool \`json:"trials_redacted,omitempty"\`` vào `BolaReport` (`bola.go:58`, tách bạch hoàn toàn với `Redacted: !o.Reveal` vốn điều khiển việc ẩn `Evidence.Value`), gán `b.rep.TrialsRedacted = o.Sender != nil && o.Sender.Redactor() != nil`. Trong `bola_report.go:86`: nếu `r.TrialsRedacted` in `"Credentials in the trial files (authz/trials/bola.*.http) are redacted (-redact=false keeps live credentials)."`, ngược lại giữ nguyên câu cũ.

### C3. Thu hẹp allowlist trong `.gitleaks.toml`
- **Hiện trạng:** `.gitleaks.toml:8-12` đang miễn trừ toàn bộ `^testbed/` và `^docs/`. Nếu sau này có tài liệu nháp trong `docs/` hoặc script shell trong `testbed/` vô tình chứa token thật, gitleaks trên CI sẽ bỏ qua.
- **Đối chiếu thực tế trên toàn repo:** toàn bộ `docs/` chỉ có duy nhất một chuỗi ví dụ giả lập `AIzaSyDUMMY000000000000000000000000000` tại `docs/plan-31.md:23`; trong `testbed/`, các khoá giả lập chỉ nằm trong `testbed/apps/`, `testbed/lab/compose.yml` (`lab-test-key-0000…`) và `testbed/cmd/testbed/`.
- **Thiết kế:**
  - Xoá hoàn toàn `'''^docs/'''` khỏi `paths` để mọi tài liệu trong `docs/` luôn được quét secret tự động.
  - Thu hẹp `'''^testbed/'''` xuống chỉ các thư mục fixture tổng hợp `'''^testbed/(?:apps|lab|cmd/testbed)/'''` và `'''_test\.go$'''`, kèm `regexes = ['''AIzaSyDUMMY0+''', '''lab-test-(?:key|secret)-0+''']`.
  - Chạy kiểm chứng trực tiếp container `zricethezav/gitleaks:v8.24.2` (`git --no-banner` + `dir --no-banner`) trên repo để xác nhận `0 leaks found` trước khi commit.

### C4. Cập nhật `CLAUDE.md`
- Cập nhật dòng bảng tra cứu thiết kế (`CLAUDE.md:27`) trỏ tới `docs/CURRENT.md` và Đợt 41/41.1 (`docs/plan-41.md`, `docs/plan-41.1.md`).
- Bổ sung ngắn gọn vào mục **Bất biến** (`CLAUDE.md:36-55`) 4 quy tắc mới của Đợt 41: `-redact=true` mặc định trên `authz`/`verify`, `-lan-guard=on` mặc định trên `crawl`/`watch` kể cả khi `-guard=false`, `-probe-offscope=auto` tự tắt khi có `-proxy`, và ngân sách đĩa `-max-store-mb` mặc định `2048` trên `crawl`/`watch`/`archive`.

---

## 5. Trình tự triển khai & bộ Gate kiểm định chốt mốc

1. **Triển khai Đợt 41.1A (5 commit riêng: `A1`..`A5`):**
   - Chạy `go test -race ./cmd/... ./internal/...` và `go test ./internal/testlint`.
   - Chạy kiểm chứng `jsapi`:
     - `JSAPI_SNAPSHOT=<corpus> go test -v -run TestSnapshot ./internal/jsapi | grep '^SNAP' | md5sum` → bắt buộc khớp `6aaeefd647d4d130c6cb2faa5cd35983`.
     - `bin/testbed perfgate` → `<= 15.0 s`, peak RSS `<= 500.0 MB`.
   - Chạy gate của 41.1A: `endpoints-check`, `roles-check`, `replay-check`, `bola-check`, `verify-check`, `monitor-check`, `attach-guard`, `explore-check`.
2. **Triển khai Đợt 41.1B (6 commit riêng: `B1`..`B6`):**
   - Chạy `go test -race ./cmd/... ./internal/...`.
   - Chạy gate của 41.1B: `archive-check`, `session-check`, `lan-check`, `flows-gate`, `webrtc-check`, `docker-check`, `pipeline-check`, `waf-check`.
3. **Triển khai Đợt 41.1C (commit `C2` + commit tài liệu/CI `C1`+`C3`+`C4`):**
   - Chạy lại `replay-check`, `bola-check`, quét `gitleaks v8.24.2` trên toàn lịch sử & working tree, và kiểm tra hygiene 0 chuỗi nhạy cảm/đường dẫn cục bộ trước khi báo cáo kết quả.
