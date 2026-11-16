# Đợt 28–30: kế hoạch thực thi (phase, giao việc, nghiệm thu)

Hai tài liệu, hai vai trò:
- **`docs/plan-28.md` là đặc tả**: luật, bẫy, gate của từng mục. Số mục (2.1, 3.4, 6…) giữ nguyên để commit và brief trỏ về được.
- **Tài liệu này là cách làm**: chia phase theo ranh giới tin cậy, ai làm việc gì, nghiệm thu ra sao, khi nào dừng hỏi người dùng.

Khi hai tài liệu mâu thuẫn: nội dung kỹ thuật theo `plan-28.md`, thứ tự và quy trình theo tài liệu này.

## 1. Vì sao chia theo ranh giới tin cậy

Mỗi phase làm việc **bên trong một ranh giới**: một chỗ dữ liệu do target kiểm soát đi vào một thành phần mà ta tin. Phase sau dựa vào các bất biến phase trước đã khoá. Ví dụ BOLA (P5) gửi request dưới danh tính khác, nên nó cần:
- bộ kết luận đúng (P1);
- kết nối mạng an toàn (P2);
- phiên đăng nhập ổn định khi có guard (P4).

| Ranh giới | Dữ liệu không tin cậy | Hỏng thì hậu quả là | Phase |
|---|---|---|---|
| **B0. Dữ liệu đã lưu → bộ đọc và bộ kết luận** (offline, không mạng, không trình duyệt) | JS, response, request của target nằm trên đĩa | Kết luận sai (bypass giả, mất endpoint), output sai | P1, P7 |
| **B1. Tiến trình Go → mạng** (socket, DNS, proxy) | Tên miền, bản ghi DNS, URL trong code target | Tool bị dùng để chạm mạng nội bộ của pentester, lộ IP thật, traffic đi ngoài proxy | P2 |
| **B2. Tool ↔ Chrome chạy JS của target** (CDP, guard, capture) | JS của target chạy trong trình duyệt của ta | Trình duyệt quét localhost/LAN, lộ IP qua WebRTC, rò bộ nhớ, guard lọt | P3 |
| **B3. Danh tính ↔ server của target** (phiên, refresh, gửi request thay người khác) | Response, cookie, token do server cấp | Mất phiên, server thu hồi phiên, ghi dữ liệu thật, kết luận phân quyền sai | P4, P5 |
| **B4. Tool → AI agent và dịch vụ ngoài** (MCP, archive, image Docker) | Output đưa cho agent, dữ liệu từ dịch vụ ngoài | Prompt injection gián tiếp, lộ secret cho agent | P6 |

## 2. Các phase

Ký hiệu worker: **S** = Claude Sonnet 5.5, effort medium (Agent tool của phiên, mục 3.4); **C** = Gemini 4 Carbon medium (`agy`); **H** = Gemini 4 Hydrogen medium (`agy`); **O** = orchestrator tự làm. Cột "Gate" là gate **orchestrator tự chạy lại** khi nghiệm thu, không tin số liệu của worker.

### P0. Nền (làm trước mọi thứ)
| ID | Việc | Worker | Gate / tiêu chí |
|---|---|---|---|
| P0.1 | Mốc `regress.sh` tại `f6f0cd4` | O | **Xong** (xanh; `bench` từng fail chập chờn ở SW ngsw) |
| P0.2 | 2.1 `Load` + MCP | O | **Xong** (`847e812`) |
| P0.3 | **Rút gọn CLAUDE.md** (đặc tả 8): lịch sử các đợt sang `docs/rounds-history.md` **nguyên văn**; CLAUDE.md giữ bất biến, bảng gate, bẫy CDP, con trỏ. Làm sớm vì mọi sub-agent Claude nạp CLAUDE.md (~85 KB, khoảng 25k token mỗi lần). **Cắt khối lịch sử bằng script** (không để LLM chép lại 65 KB); chỉ biên tập phần khung còn lại. Không giao Gemini: file có tên domain khách hàng | O | Script kiểm: mọi dòng bị xoá khỏi CLAUDE.md có mặt nguyên văn trong `rounds-history.md`; CLAUDE.md ≤ 20 KB |
| P0.4 | Pilot `agy` + `bwrap` (mục 3.4) trên **một module Go giả khoảng 10 dòng** trong scratchpad, **không có file nào của jsharvest** (chưa gửi dòng nào của repo trước khi người dùng quyết P0.5(c)). Đo: (1) **canary**: file giả đặt trong `output/`, `profiles/` của cây thật, thư mục agent config cục bộ (ví dụ `~/.config/<agent>/`, brain/conversations), `/tmp`; worker được yêu cầu thử đọc, phải không thấy; (2) `go test` chạy được (cache Go riêng, module cache chỉ đọc, `GOPROXY=off`); (3) output JSON đúng schema; (4) **tập file tối thiểu** `agy` cần để đăng nhập (chép vào thư mục trạng thái mới, mục 3.4) | O | Ghi kết quả vào mục 3.4. **Canary đọc được → dừng, không giao Gemini việc nào** cho tới khi sửa xong lớp che (hoặc mọi việc chuyển S) |
| P0.5 | **Điểm dừng gộp** (một lần hỏi thay vì ba): (a) diff CLAUDE.md; (b) digest `@sha256` của image Jellyfin + Directus do O tra sẵn từ registry (chỉ tra, chưa pull); (c) quyết định dữ liệu cho Gemini (mục 3.3: bản chụp làm sạch vẫn còn path và hình dạng code suy ra từ app khách hàng trong test); (d) chấp nhận hay không giới hạn keyring: `agy` cần Secret Service qua D-Bus đã lọc, nên trong sandbox về lý thuyết đọc được các mục đã mở khoá khác của keyring login (mục 3.4, kết quả P0.4) | O | Người dùng duyệt. Sau đó P1 → P4.4 chạy liền tới P4.D |
| P0.6 | **Container worker** (mục 3.4, "Enhance sau"): mọi worker chạy trong Docker, không phụ thuộc máy chính, fail-closed. **Hoãn** sang đợt enhance sau. | O | Image và fail-closed đã dựng; còn lỗi probe (mục 3.4) |
| P0.7 | Đồ nghề cho chế độ hiện hành (ngoài repo, `$SNAP_DIR`): script tạo snapshot sạch & wrapper sandbox `bwrap` có chốt `.sanitized` và tự bật proxy | O | Đã kiểm (mục 3.3, 3.4) |

### P1. B0: bộ đọc và bộ kết luận (offline)
Phụ thuộc: P0. Cả P2 và P5 dùng bộ kết luận này.

| ID | Việc (đặc tả) | Worker | Gate |
|---|---|---|---|
| P1.1 | 2.2 SFC gộp đủ trường, test reflect | S | unit; `crosscheck-check`; snapshot jsapi so với HEAD **do O chạy trong cây chính** (cần `output/_live_25e_max`, worker không được đọc) |
| P1.2 | 2.3 `SigOf` code số; `errorBody` (bảng phân loại, body không mang dữ liệu, root mảng); control lỗi → `Unclear`; `flatten` mảng không thứ tự | S | unit (fixture `0/1/20000/2001/40301`, mảng); `verify-check`, `replay-check` |
| P1.3 | 2.4 GraphQL lô: mỗi operation một khoá (`flow`); `export` tách bản đại diện `[{op1}]` và tính lại `Params`; `replay -flow` giữ lô; draft của `verify` theo operation | S | unit; `flows-gate`, `export-check`, `roles-check`, `monitor-check`, `verify-check` |
| P1.R | Review độc lập diff P1.2 + P1.3 (bộ kết luận là nền của BOLA) | C | Orchestrator kiểm từng nhận định trên code trước khi chấp nhận |

Thoát P1: mọi gate trên xanh; bảng tiến độ cập nhật.

### P2. B1: mạng của tiến trình Go
Phụ thuộc: P0. Chạy được song song với P1 (khác package), nhưng gate chạy tuần tự.

| ID | Việc (đặc tả) | Worker | Gate |
|---|---|---|---|
| P2.1 | 3.1 `internal/netsafe`: phân giải → kiểm → dial IP; host rules tin cậy; `TargetPublic=false` cho phép private; miễn địa chỉ proxy ở cả `DialContext` lẫn `DialTLSContext`; IPv4 trước; SNI giữ hostname. Thay dialer của `httpcrawl`, `replay.Sender`, AIA, kiểm live của `archive` | S | unit (rebinding, DNS lỗi, CGNAT, unspecified, proxy loopback, proxy https, host rules); `waf-check`, `pipeline-check`, `archive-check`, `verify-check`, `replay-check` |
| P2.2 | 3.2 kiểm IP literal ở tầng request khi có proxy (dạng số IPv4 theo WHATWG, `localhost`, `*.localhost`, mapped IPv6) | S | unit bảng ca |
| P2.3 | 3.3 một nguồn proxy cho mọi client (gồm `archive`); host rules không qua proxy; in proxy ra stderr; lý do tắt AIA vào `run.json` | S | unit; **gate mới `proxy-check`** (namespace chỉ có route tới proxy ghi log; `crawl`, `archive`, `verify` với `-proxy`; mọi kết nối đi thẳng là fail). Thêm vào `regress.sh` |
| P2.R | Review độc lập P2 (an toàn mạng) | C | Như P1.R |

### P3. B2: trình duyệt chạy JS của target
Phụ thuộc: P2 (dùng chung hàm private và luật IP literal).

| ID | Việc (đặc tả) | Worker | Gate |
|---|---|---|---|
| P3.1 | 2.5 dọn map capture (`held` từ header guard, chỉ khi responded+finished, `n.reqs`), `Guard.RemoveTab` | S | unit; `parallel-check`, `explore-check`, `flows-gate`, `attach-guard`; đo heap `watch` dài (O) |
| P3.2 | 3.4 lớp 1: guard `FailRequest` cho IP literal private khi origin mốc public (SW lấy origin worker; không mốc thì coi public) | S | unit; fixture origin public giả lập; `attach-guard`, `explore-check` |
| P3.3 | 3.4 lớp 2: LNA deny (`localNetworkAccess` và `localNetwork`), reset ở `-attach`; test trên Chrome 156 | S | fixture `loadingFailed` có `LocalNetworkAccessPermissionDenied`; mọi gate Chrome không gãy |
| P3.4 | 3.4 lớp 3: cầu chì `remoteIPAddress` (đọc được → đóng tab; còn lại → chặn host); tắt khi có proxy; miễn host rules | S | unit; fixture |
| P3.5 | 3.4 WebRTC với `-proxy` | S | fixture ICE candidate; `docker-check` (cần mạng, `DOCKER=1`) |
| P3.R | Review độc lập P3 | C | Như P1.R |

### P4. B2×B3: phiên đăng nhập dưới guard (đo rồi mới sửa)
Phụ thuộc: P3 (cùng file guard/capture). Theo đặc tả 4 và 5.

| ID | Việc (đặc tả) | Worker | Gate / tiêu chí |
|---|---|---|---|
| P4.1 | 28B(b): fixture refresh token xoay vòng (OAuth `grant_type`, BFF cookie body rỗng); đo guard và `-urls -tabs 3 -role`, `crawl -depth 2 -tabs 3 -role` | S | Bảng số liệu (3 lần, trung vị) vào `plan-28.md` |
| P4.2 | 28B(e): fixture `setTimeout` tự hẹn lại và RxJS trong `flows-app`; đo gán nhân quả | S | Bảng số liệu |
| P4.3 | 28B(a) chuẩn bị: compose Jellyfin + Directus (SQLite, ghim `@sha256` đã duyệt ở P0.5, **mạng `internal: true`**, tắt telemetry/update); tài khoản local. Hai app dùng tên `*.jsh.test` qua `-host-resolver-rules` (đặc tả 3.4: host rules là nội bộ ở mọi lớp) | H | Digest đúng bản đã duyệt (khác thì dừng hỏi lại). O kiểm compose không có route ra ngoài |
| P4.4 | 28B(a) đo: guard `200 {}` / `422` / `403` trên `explore-app`, `flows-app`, Crawlground, Jellyfin, Directus | S | Bảng số liệu |
| P4.5 | 28C áp dụng theo số liệu: ngoại lệ refresh (đặt sau `Destructive`), `-guard-allow` lưu trong session (neo origin+path), mã trả về khi guard giữ, đóng overlay nếu 422, `-urls -role` theo mô hình C4 | S | Fixture P4.1 thành gate (thêm vào `session-check`); `explore-check`, `parallel-check` |
| P4.D | Quyết định 28C từ số liệu | O | **Trình người dùng bảng số liệu và lựa chọn trước P4.5** |

### P5. B3: BOLA ngang (trọng tâm)
Phụ thuộc: P1 (bộ kết luận), P2 (gửi request an toàn), P4 (phiên của hai peer ổn định khi crawl).

| ID | Việc (đặc tả 6) | Worker | Gate / tiêu chí |
|---|---|---|---|
| P5.1 | Design doc `docs/gd7-bola-design.md` theo khung `gd5-replay` mục 8, mọi luật của đặc tả 6. C chạy `--mode plan`, trả nội dung trong JSON; **O ghi thành file** | C | O kiểm mọi luật của đặc tả 6 đều có mặt |
| P5.2 | Đánh giá độc lập design doc (khác model với người viết) | S | O đối chiếu với code; chốt bản sửa |
| P5.3 | Fixture `peer-app` + `peer.truth.json` + `bin/testbed peerscore` (`same-org`/`cross-org`; ca: `/me`, dùng chung, bỏ qua `userId`, phản chiếu ID, B trống, khoá phân cấp, signed URL, GraphQL lô, code số) | S | Fixture chạy được, truth đầy đủ |
| P5.4 | Cài đặt `authz -peers` theo design đã chốt | S | unit; **gate mới `bola-check`**; `replay-check` không đổi |
| P5.5 | Review độc lập code P5.4 | C | Như P1.R |
| P5.6 | Thử trên Directus/Jellyfin local với 2 tài khoản | S | Báo cáo; không có request ra ngoài |
| P5.T | Target thật | — | **Chờ người dùng cấp tài khoản và cho phép từng lần chạy** |

### P6. B4: output cho AI agent và dịch vụ ngoài
Việc nhỏ, ít rủi ro: **làn phụ**, xen vào khi làn chính đang chờ (đang review, đang chờ người dùng). Mỗi mục có phụ thuộc riêng (cột 4); chưa đủ phụ thuộc thì không được lấy dù làn chính đang chờ.

| ID | Việc (đặc tả) | Worker | Phụ thuộc | Gate |
|---|---|---|---|---|
| P6.1 | 2.6 envelope `untrusted` cho mọi tool MCP | H | P0 | `flows-gate` (MCP=1) |
| P6.2 | Tool MCP chỉ đọc `get_intel`, `get_diff` | H | P6.1 | `flows-gate` |
| P6.2b | Tool MCP `get_authz` (đủ trường kết quả peer) | H | P6.1, **P5.4** | `flows-gate`, `bola-check` |
| P6.3 | `search_scripts`, `read_script` (chỉ sha256 trong index, phân trang theo byte, che secret) | S | P6.2 | unit (đường dẫn `../`, file 5 MB một dòng); `flows-gate` |
| P6.4 | `export -format openapi` + kiểm schema trong `exportcheck` | S | **P1.3** (cùng `internal/export`; dùng bản đại diện `[{op1}]`) | `export-check` |
| P6.5 | `flock` giữa các lệnh ghi (test hai tiến trình trước). **Chỉ lấy khoá ở tầng lệnh CLI** (`cmd/jsharvest`), không lấy lại trong hàm thư viện (`endpoints.Analyze` do `crawl`/`watch` gọi ở cuối sẽ tự khoá chính mình) | S | **P4** (không làm nhiễu phép đo phiên) | unit hai tiến trình; `parallel-check` |

P6.1 → P6.2 → P6.3 cùng sửa `internal/mcpserver`: chạy **nối đuôi**, không dựng hai bản chụp cùng lúc.

### P7. B0: jsapi, một cơ chế tổng quát
Phụ thuộc: P1.1. Đặt sau P5 theo quyết định trọng tâm. Riêng P7.1 (chỉ đọc) có thể chạy sớm làm làn phụ.

| ID | Việc (đặc tả 7, 28B(c)) | Worker | Gate / tiêu chí |
|---|---|---|---|
| P7.1a | Phân loại endpoint thiếu trên 5 tập dev OpenAPI (Keycloak, Appwrite, Medusa, Directus, Jellyfin: mã nguồn mở). Các tập này nằm trong `output/_groundtruth/` **chung thư mục với ground truth của target khách hàng** (`groundtruth_v*.json`, `eval_suite.py`). O dựng một thư mục riêng trong bản chụp, **chép chọn lọc** đúng: spec/GT của 5 app, bundle, `endpoints.jsonl` của lần chạy dev. Không symlink, không `--add-dir` tới `output/` | C | Bảng nguyên nhân; O kiểm mẫu ngẫu nhiên 10 dòng trên code |
| P7.1b | Tỉ lệ loại bundler trên `output/_live_25e_max` (**dữ liệu target khách hàng: không đưa cho Gemini**) | O hoặc S | Bảng |
| P7.2 | Chọn cơ chế | O | **Trình người dùng** bảng 7.1 và cơ chế chọn |
| P7.3 | Cài đặt cơ chế + bóc `__awaiter` | S | snapshot dev không giảm; `perfgate`; `endpoints-check`, `crosscheck-check` |
| P7.4 | Đề xuất tập kiểm mù | O | **Người dùng xác nhận trước khi tải**; không mở bundle trước |
| P7.5 | Chạy kiểm mù một lần | O | Ghi kết quả; tập chuyển thành dev |

### P8. Hiệu năng và chốt đợt
| ID | Việc | Worker | Gate |
|---|---|---|---|
| P8.1 | Các mục ở đặc tả 9, **chỉ mục có số đo** cho thấy cần | S | `perfgate`, gate liên quan |
| P8.2 | `regress.sh -j 3` toàn bộ (`DOCKER=1`) | O | Xanh |
| P8.3 | Ghi đợt vào `docs/rounds-history.md` và CLAUDE.md (con trỏ) | O | (có tên target khách hàng: không giao Gemini) |

## 3. Điều phối

### 3.1. Vai trò
- **Orchestrator (O):** viết brief, giao việc, **nghiệm thu bằng chứng tự chạy lại**, commit, cập nhật tiến độ, quyết định làm lại hay leo thang. Chỉ tự viết code khi việc nhỏ hơn chi phí một brief, hoặc sau khi leo thang (mục 3.6).
- **Worker** chỉ làm đúng phạm vi brief, **không commit, không push**, không sửa file ngoài danh sách cho phép, không đổi baseline.

### 3.2. Chọn worker
| Loại việc | Worker | Lý do |
|---|---|---|
| Code ở chỗ nhạy cảm: đồng thời, CDP, an toàn mạng, bộ kết luận, BOLA | **S** | Cần chính xác; đọc được CLAUDE.md và bẫy chromedp |
| Thiết kế, phân tích nguyên nhân, review độc lập | **C** | Logic cao; khác model với người viết code nên đỡ thiên kiến |
| Việc cơ học: tool MCP đơn giản, file cấu hình | **H** | Rẻ; mọi kết quả đều qua kiểm của O |
| Việc chạm `output/`, `profiles/` (dữ liệu target khách hàng, phiên đăng nhập), CLAUDE.md, lịch sử đợt, tài liệu có tên target | **S hoặc O, không bao giờ C/H** | Không đưa dữ liệu khách hàng sang dịch vụ của bên thứ ba khác (Google) |

Nếu `agy` không dùng được (lỗi, hết hạn mức, pilot P0.4 thất bại, người dùng chọn không gửi ở P0.5): mọi việc của C/H chuyển sang **S**.

### 3.3. Nơi làm việc

**Bẫy đã kiểm (2026-11-15):** "Worktree không có dữ liệu khách hàng" là **sai**. Tên domain của target khách hàng có trong 24 file được git theo dõi: CLAUDE.md; test có fixture lấy hình dạng từ code khách hàng (`internal/endpoints/round22*_test.go`, `internal/jsapi/round19–21_test.go`, `internal/scope/scope_test.go`, …); code (`scope.go`, `detect.go`, …); `docs/gd6-waf-design.md` (103 chỗ); `docs/session-2026-11-02.jsonl` (transcript thô). Ngoài ra `.git` của worktree trỏ về `.git` của cây chính, nên chỉ cần đọc được `.git` là đọc được toàn bộ lịch sử. Vì vậy hai loại worker làm ở hai nơi khác nhau.

**Chế độ hiện hành (người dùng chốt 2026-11-15):** chạy worker qua lớp cô lập ngoài repo tại `$SNAP_DIR` (bản chụp cô lập, wrapper `bubblewrap`, seed profile rỗng, cache Go riêng, proxy D-Bus và bảng từ khoá làm sạch cục bộ `0600` không track git). Container `devtools/worker/` (P0.6) **hoãn** sang đợt enhance sau.

**Worker S (Claude):** dựng bản chụp làm việc ở `$SNAP_DIR/<ID>`:
- `git archive HEAD`, `git init` làm mốc riêng (danh tính `snap <snap@localhost>`), không trỏ về `.git` của cây chính; không có `output/`, `profiles/`, `bin/`;
- **chép** (`cp -a`, không symlink, không hardlink) 7 `dist` bị gitignore: `angular-ngsw`, `angular-ngsw-default`, `endpoints-app`, `next-mixed`, `vite-pwa`, `vite-vanilla`, `webpack-vanilla` (khoảng 2 MB). Các `dist` khác đã được git theo dõi; symlink hay hardlink thì worker sửa fixture sẽ ghi xuyên vào cây chính.
- Không có `.sanitized`, nên wrapper sandbox từ chối bản chụp này (chặn giao nhầm).
- Brief cấm đọc ngoài bản chụp. **Không bao giờ chép credential phiên** ra nơi khác hay chạy song song bằng bản sao: refresh token xoay vòng sẽ làm văng phiên chính.

**Worker C/H (Gemini):** **mọi lần gọi, kể cả việc chỉ đọc**, chạy trong **bản chụp đã làm sạch**, không bao giờ trong cây chính hay bản chụp của S:
- tạo bản chụp rồi xoá file transcript/nhật ký nội bộ nếu còn;
- thay nhãn domain mục tiêu theo bảng từ khoá cục bộ (cùng độ dài nên hoa/thường được giữ theo từng ký tự và đổi ngược chính xác), **giữ nguyên TLD**;
- **quét lại** cả nội dung (kể cả file nhị phân) lẫn đường dẫn; còn nhãn thật thì xoá bản chụp và thoát 1. Sạch thì ghi `.sanitized` (nằm trong `.git/info/exclude`).
- Kiểm tra `go vet` + `go test ./...` trên bản chụp làm sạch ra **0 test hỏng** do nhãn giả.
- Bài học P0.4: rào chắn là `bwrap` theo kiểu danh sách trắng (mục 3.4), không che theo danh sách đen. Trong `$HOME` có nhiều chỗ chứa trạng thái phiên/lịch sử shell/Go cache; lời dặn trong brief chỉ là lớp phụ.
- Giới hạn đã được chấp nhận (P0.5c): test khi đó vẫn còn hình dạng code mô phỏng trước khi chuẩn hoá hoàn toàn ra public.

**Cả hai loại:** worker trong bản chụp chỉ chạy `go build`/`go vet`/`go test -race`. Mọi gate (`regress.sh`, gate cần Chrome hay namespace lồng) **do O chạy ở cây chính** lúc nghiệm thu.

**Thu bài (cả hai loại):**
1–3. xuất diff đã staging sang `$SNAP_DIR/<ID>.patch`:
   - in `status --porcelain` để O đối chiếu mọi file `??` với danh sách brief cho phép (có file lạ thì trả về);
   - `add -A` + `diff --cached --binary HEAD` ra `$SNAP_DIR/<ID>.patch`. `git diff HEAD` trơn **bỏ qua file mới chưa track** (package mới, design doc, fixture sẽ mất);
   - với bản chụp `.sanitized`: đổi ngược nhãn giả trong patch, còn sót nhãn giả thì thoát 1.
4. Áp vào cây chính:
   - bản chụp của S (blob trùng HEAD): `git apply --3way <ID>.patch`;
   - bản chụp của C/H: patch chạm file **đã đổi nhãn** thì `git apply` **không `--3way`** (blob gốc trong dòng `index` là bản đã đổi nhãn, cây chính không có, nên `--3way` báo thiếu blob). File không đổi nhãn có blob trùng, `--3way` dùng được.

   Sau đó **chạy lại gate trong cây chính**, commit, xoá bản chụp (`<ID>`, `<ID>.patch`, state dir tạm). Không đạt thì cũng xoá, không để rác.

Một lúc chỉ một việc ghi vào cây chính. Việc chỉ đọc chạy song song được, mỗi việc một bản chụp.

### 3.4. Gọi worker
- **S:** Agent tool chạy nền trong `$SNAP_DIR/<ID>` (bản chụp `s`). Brief theo mẫu 3.5.
- **C/H:** chạy nền qua wrapper `bwrap` trong `$SNAP_DIR`:
  ```
  "$SNAP_DIR/<sandbox-wrapper>" <ID> -- agy -p "$BRIEF" --model gemini-4-carbon-medium \
      --output-format json --json-schema "$SCHEMA" --print-timeout 3600s \
      --disable-slash-commands --sandbox --dangerously-skip-permissions < /dev/null > <ID>.out.json
  ```
  - Đổi `gemini-4-carbon-medium` thành `gemini-4-hydrogen-medium` cho H.
  - Kết quả đọc ở trường `structured_output`; trường `response` có thể kèm câu dẫn.
  - **`--mode plan` không có tác dụng khi có `--disable-slash-commands`**. Với việc review, phân tích hay thiết kế: brief cấm sửa file, và O kiểm `git status` của bản chụp phải sạch. Nội dung trả trong JSON, O ghi file.
  - Brief và schema đọc ở máy chính rồi truyền thành tham số; output ghi ra ngoài sandbox.
- **Wrapper `bwrap` tự làm** (đọc trước khi sửa):
  - Chốt đầu: ID rỗng, có `/`, bắt đầu bằng `.`, hoặc không có `$SNAP_DIR/<ID>/.sanitized` thì thoát **2**. Chặn giao nhầm bản chụp của S hay cây chính.
  - Tạo state dir riêng bằng `cp -a` từ seed rỗng; **không** gắn lịch sử hay brain từ `$HOME`. Mỗi việc một bản để hai worker song song không tranh khoá SQLite.
  - Kiểm proxy D-Bus đã lọc (`busctl --user list` qua `$SNAP_DIR/run/bus`). Chết thì xoá socket cũ, bật nền `setsid xdg-dbus-proxy … --filter --talk=org.freedesktop.secrets`, chờ tối đa 5 s.
  - `bwrap` danh sách trắng:
    - `--ro-bind / /`, `--dev /dev`, `--unshare-pid --proc /proc`, `--unshare-ipc`, `--new-session`, `--die-with-parent`;
    - `tmpfs` cho `/tmp`, `/var/tmp`, `/run/user/$UID`, `/run/dbus`;
    - HOME giả thay cho `$HOME` thật; gắn lại chỉ đọc binary worker và module cache Go; `$SNAP_DIR/gocache` làm `~/.cache/go-build`; bản chụp gắn tại `/work`;
    - `--clearenv`, rồi chỉ đặt `HOME USER LANG TERM PATH GOPROXY=off GOFLAGS=-mod=readonly GOTOOLCHAIN=local DBUS_SESSION_BUS_ADDRESS`.
- **Kiểm 2026-11-15:**
  - Pilot P0.4 tìm ra lỗ thoát qua D-Bus của phiên: `systemd-run --user --pipe cat …` có thể đọc xuyên nếu không lọc D-Bus. Đã bịt bằng `tmpfs`, `--clearenv` và proxy lọc. Sau đó `systemd-run` báo `ServiceUnknown`; qua proxy chỉ thấy `org.freedesktop.DBus` và `org.freedesktop.secrets`.
  - Sau khi thêm các cờ khoá `/proc` và `/dev`: chỉ thấy 5 tiến trình, `/dev/pts` và `/dev/shm` rỗng, `/` chỉ đọc; `go test` và `--sandbox` lồng bên trong vẫn chạy.
  - Chốt `.sanitized` chặn được 4 ca: ID rỗng, bản chụp S, pilot chưa đánh dấu, `../jsharvest`; cả bốn thoát 2.
  - Proxy tự bật được khi socket cũ đã chết, và được dùng lại ở lần gọi sau (vẫn 1 tiến trình).
  - Smoke test trên module giả `pilot` trả `OK` trong 8 s.
  - Pilot với file mồi đặt ngoài sandbox: không lộ.
  - Chi phí: việc tự kiểm đơn giản mất 445 s và khoảng 34k token; việc thật cần `--print-timeout` rộng.
- **Giới hạn đã biết:** qua Secret Service, tiến trình trong sandbox về lý thuyết đọc được mọi mục đang mở khoá trong keyring login của máy. Không đọc được file. Chấp nhận trong chế độ hiện hành; container (dưới đây) là cách bỏ hẳn giới hạn này.
- **Enhance sau — container `devtools/worker/` (P0.6, hoãn, đừng gọi):**
  - Đã có: image `jsh-worker:1` từ `golang:1.25.4-bookworm@sha256:e17419604b6d1f9bc245694425f0ec9b1b53685c80850900a376fb10cb0f70cb`; worker CLI cài từ script chính thức; keyring riêng; volume cache; fail-closed mã 20, đã kiểm khi chưa đăng nhập.
  - Lỗi phải sửa trước khi dùng (review 2026-11-15):
    - `entry.sh` `with_keyring`: `gnome-keyring-daemon` in ra stderr (`Could not find daemon to replace…`). Hàm kiểm tra đăng nhập gộp `2>&1`, rồi `tr -d '[:space:].'` xoá cả xuống dòng, nên `grep -qx OK` luôn sai và `check` trả 20 **kể cả khi đã đăng nhập**. Sửa: chuyển hướng `>/dev/null 2>&1` cho daemon; dọn `/h`; thay probe bằng lệnh CLI đòi đăng nhập có `timeout`.
    - `worker.sh`: tách volume cache theo từng tool; mount `/cred:ro` ở `check` và `run`; chỉ nhận `$SNAP_DIR/<ID>` có `.sanitized`.
  - Còn mở: egress allowlist (chỉ domain API của Google/Anthropic, qua proxy trong mạng `internal`); đăng nhập `claude` trong container phải dùng credential riêng, không chép từ máy.

### 3.5. Mẫu brief (bắt buộc đủ các phần)
1. **Mục tiêu**, một câu, kèm ID và mục đặc tả (`plan-28.md` mục X): trích nguyên văn luật và bẫy của mục đó vào brief, không bắt worker tự tìm.
2. **Bối cảnh tối thiểu:** file và hàm liên quan (đường dẫn:dòng), những gì đã biết là sai trong các vòng review (để không lặp lại). Bước nào cần dữ liệu trong `output/` (snapshot jsapi, đo trên tập dev) thì ghi rõ **O chạy**, worker không chạy. Với bản chụp: danh sách test hỏng sẵn do nhãn giả, không được sửa.
3. **Phạm vi:** danh sách file được sửa; điều cấm (không commit/push, không sửa baseline, không chạy với target thật, không truy cập mạng ngoài trừ khi brief cho phép, không đọc `output/`, `profiles/`).
4. **Quy trình bắt buộc:** viết test fail trước → chạy cho thấy fail → sửa → chạy cho thấy qua → `gofmt` chỉ trên phần mình sửa → `go build` + `go vet` + `go test -race` các package đã chạm. **Worker không chạy `regress.sh` hay gate nào**: gate luôn do O chạy ở cây chính lúc nghiệm thu.
5. **Báo cáo trả về** (≤ 300 từ, đúng các mục): file đã sửa; test thêm; **output lúc test fail** (trích); kết quả test và gate; điều chưa chắc hoặc lệch khỏi đặc tả (nêu rõ, không tự quyết); việc phát sinh ngoài phạm vi (chỉ ghi, không làm).

### 3.6. Nghiệm thu (O làm, không bỏ bước)
1. Diff chỉ nằm trong phạm vi brief; không có file lạ.
2. **Tự tái hiện test fail**, theo loại việc:
   - **Sửa hành vi của hàm đã có** (P1.1–P1.3, P3.1, P4.5…): `git stash push --include-untracked -- ':!*_test.go'` (stash trơn cất luôn test vì cả hai đều chưa commit). Test phải **biên dịch được và FAIL ở assertion**; fail vì lỗi biên dịch (`undefined`) không được tính, khi đó brief sau yêu cầu test không phụ thuộc helper mới. `git stash pop`, phải qua.
   - **API, package, cờ mới** (P2.1 `netsafe`, P2.2, P5.4 `-peers`, P6.3, P6.4): không stash được (test không biên dịch). Thay bằng: (a) đối chiếu bộ test với danh sách ca âm tính bắt buộc trong brief (rebinding, DNS lỗi, bogus ID, `../`…); (b) **kiểm đột biến**: O tự gỡ từng kiểm tra then chốt trong code (ví dụ bỏ kiểm IP sau phân giải), test tương ứng phải fail; trả lại.
3. `go build ./...`, `go vet`, `go test -race` các package đã chạm; `gofmt` không tạo diff mới ở phần đã chạm.
4. Gate theo bảng phase **chạy trong cây chính**; với `jsapi`: so snapshot với HEAD.
5. Đọc diff theo đặc tả: mọi luật và bẫy của mục đều được xử lý; nhận định của worker được kiểm trên code (bài học: các LLM đã sai `Params`, `finishTab`, `Sender.dial`).
6. Đạt: commit (một mục một commit, có dòng `Co-Authored-By`), cập nhật bảng tiến độ ở mục 4. Kết quả review độc lập (C) cũng ghi vào phần đánh giá của design doc tương ứng.

### 3.7. Làm lại và leo thang (chống đốt token)
- **Tối đa 2 lần làm lại cho mỗi việc.** Brief làm lại = brief cũ + mục "Lần trước sai": bằng chứng cụ thể (lệnh, output), chỗ phải sửa, điều **không** được đổi. Không gửi lại cả hội thoại.
- Làm lại trong **cùng bản chụp** (giữ phần đúng), trừ khi hướng sai từ gốc thì dựng bản chụp mới.
- Sau 2 lần vẫn không đạt, chọn một trong các cách:
  - (a) tách việc nhỏ hơn;
  - (b) O tự làm phần còn lại;
  - (c) đổi worker (C/H → S);
  - (d) dừng và hỏi người dùng khi nguyên nhân là đặc tả mơ hồ hoặc mâu thuẫn.
- Gate fail vì lý do ngoài phạm vi (chập chờn đã biết, như SW ngsw của `bench`): chạy lại **một lần**. Fail tiếp thì ghi vào tiến độ và báo người dùng, không bắt worker sửa thứ ngoài phạm vi.
- Ghi mọi lần làm lại vào cột "Ghi chú" của mục 4, kèm bài học. Brief sau dùng bài học đó.

### 3.8. Điểm dừng chờ người dùng (không bao giờ tự vượt)
- P0.5 (gộp): diff CLAUDE.md; digest image Docker (O tra sẵn, chưa pull); dữ liệu cho Gemini (mục 3.3).
- Worker CLI qua sandbox wrapper báo chưa đăng nhập hoặc lỗi xác thực: dừng, báo người dùng đăng nhập lại công cụ trên máy; không tự xử lý.
- P0.4 (tự dừng): canary đọc được qua lớp che → không giao Gemini, báo người dùng.
- P4.3 (chỉ khi lệch): digest lúc pull khác bản đã duyệt.
- P4.D: lựa chọn 28C từ số liệu.
- P7.2: cơ chế jsapi được chọn. P7.4: tập kiểm mù trước khi tải.
- P5.T: mọi lần chạy trên target thật (theo memory: hỏi trước mỗi lần).
- Bất kỳ việc nào cần đưa dữ liệu khách hàng ra ngoài, push, hoặc thao tác git không đảo ngược được.

Ngoài các điểm này, O chạy liên tục theo thứ tự phase cho tới hết kế hoạch. Khi phải chờ người dùng ở một điểm dừng, O chuyển sang làn phụ (P6, P7.1) nếu còn việc.

### 3.9. Thứ tự chạy dự kiến
```
P0.3 ─┐
P0.4 ─┴→ P0.5 (dừng gộp) → P1 ──┐
                         P2 ───┴→ P3 → P4 (dừng P4.D) → P5 (dừng P5.T) → P7 (dừng P7.2, P7.4) → P8
làn phụ (khi làn chính chờ, đủ phụ thuộc mới lấy):
  P6.1 → P6.2 → P6.3 (nối đuôi) · P6.4 sau P1.3 · P6.5 sau P4 · P6.2b sau P5.4 · P7.1a, P7.1b
```

## 4. Tiến độ

| ID | Trạng thái | Commit | Ghi chú |
|---|---|---|---|
| P0.1 | xong | — | Mốc xanh tại `f6f0cd4`; `bench` chập chờn (SW ngsw) |
| P0.2 | xong | `847e812` | Do O làm trước khi có kế hoạch này |
| P0.3 | xong | (commit P0) | CLAUDE.md 84,9 KB → 20,6 KB; lịch sử dòng 43–397 sang `docs/rounds-history.md` bằng script, kiểm nguyên văn (chỉ dòng con trỏ kế hoạch được sửa); thêm mục "Lịch sử và tra cứu thiết kế" + "Bất biến"; sau review bổ sung 4 gate (`parallel-check`, `frontier-tabs-check`, `pipeline-check`, `verify-check`), trần `perfgate`, luật không commit file nhạy cảm, bỏ câu mã thoát lặp |
| P0.4 | xong | — | Tìm và đóng lỗ thoát D-Bus (`systemd-run --user`) của `bwrap`; khoá thêm `/proc`, `/dev` theo review |
| P0.5 | xong 2026-11-15 | — | (a) duyệt sau khi bổ sung 3 ý; (b) duyệt `jellyfin/jellyfin:12.4.20261026-211555@sha256:fea863d0cd9ec445985d9c75fc6ed64e38a1d2766cf0c250a33d553f4fc1b771` và `directus/directus:12.6.1@sha256:e1561b5e526e8e7a2ac19b7bb6eab63611dd84a862a8c45b864118768a2baff4` (index đa kiến trúc; `directus` 12.6.1 → `@directus/app` 19.1.0); (c) chấp nhận gửi bản chụp đã làm sạch cho Gemini (theo review đã chuyển); (d) chấp nhận keyring qua proxy lọc trong chế độ hiện hành (container bỏ giới hạn này, hoãn) |
| P0.6 | hoãn | `44f63e6` | Container `devtools/worker/` để đợt enhance sau; lỗi probe và backlog ở mục 3.4. Image `jsh-worker:1` và 3 volume vẫn còn trên máy |
| P0.7 | xong | (commit bàn giao) | `snap` + bảng nhãn `0600` + wrapper `bwrap` chốt `.sanitized`, proxy D-Bus, smoke OK 8 s. **Sẵn sàng P1** |
| P1.1 | xong | `7c31db4` | O tự làm (nhỏ hơn một brief). `Result.mergeSpan` + test reflect; snapshot dev không đổi ngoài số version (v36); `crosscheck-check` xanh |
| P1.2 | xong | `c829130` | S, đạt lần đầu. Sửa theo P1.R ở `49e5776` (làm lại lần 1): khoá siêu dữ liệu RFC 7807, mảng gốc không ghép theo vị trí, `code:0` thắng `status` unknown, chữ ký chuẩn tắc đệ quy |
| P1.3 | xong | `2c5b3f0` | S, làm lại 2 lần. Lần 1: `verify` gửi N request giống hệt cho N operation (O phát hiện) + test loopback gãy sau P2.1. Lần 2 (theo P1.R, `49e5776`): `derived` theo `$[i]`, phần tử ẩn danh, REST mảng có `query`, APQ, `valueType $[n].query`, monitor đọc body `[`, dedup draft trần. Bài học: brief phải nêu người gọi gửi request thật (verify) |
| P1.R | xong | — | C (Carbon): 10 nhận định, O kiểm cả 10 trên code, đều đúng; sửa ở `49e5776` |
| P2.1 | xong | `9455d3e` | S. O bỏ ngoại lệ "host trình duyệt từng gặp ở IP private" (`recordedPrivate`, ngoài đặc tả). Kiểm đột biến: bỏ kiểm private / proxy exempt / dial theo tên khi DNS lỗi → đều fail |
| P2.2 | xong | `48f5dca` | S. Đột biến: bỏ nối Guard, bỏ luật localhost, bỏ octal → fail |
| P2.3 | xong | `615b990` | S, làm lại 1 lần (gate: grep `CONNECT`, scheme của verify qua `intel.json`, archive giả `FAKE_ARCHIVE_REHOST`). O thêm: `ProxyFunc` miễn loopback (như `<-loopback>` của Chrome). Gate mới `proxy-check` |
| P2.R | xong | `f81e602` | C: 8 nhận định, O kiểm; sửa 7 (S): `httpcrawl` suy nội bộ khi **bất kỳ** địa chỉ private, DNS cục bộ khi có proxy, client archive không qua netsafe, lộ credential trong lỗi, RequestURI `a:@host`, zone IPv6/`..`, thiếu NAT64/6to4/240/4…, IDN proxy, webhook. Giữ miễn loopback khỏi proxy; `NO_PROXY` không đọc (giới hạn) |
| P3.1 | xong | `607dac8` | S. O tách `request.response` và thêm test vì đột biến "không bao giờ đặt `held`" không bị bắt. Đo `watch` 150 s, ~57k request: RSS cuối 190 → 164 MB (nhiễu; record guard và summary vẫn tăng, ngoài phạm vi) |
| P3.2 | xong | `fcff21f` | S. Gate mới `lan-check` (TEST-NET trên lo trong netns). O sửa gate: SW không chạy trên http public (bỏ khỏi kỳ vọng, có unit test); Chrome 156 tự chặn trang http public → loopback (`cors:InsecureLocalNetwork`) kể cả host rules. `-guard off` thì lớp 1 không chạy |
| P3.3 | xong | `689ae2f` | S. O: đếm riêng `lna_denied`/`lna_insecure`, `addStats` gộp (lỗi do worker P3.4 phát hiện), `bench` bỏ app không có `truth.txt`. Regress đầy đủ xanh |
| P3.4 | xong | `b703d01` | S. Không gate nào dựng được ca thật (cách map tên duy nhất cho Chrome là host rules, vốn được miễn): unit test + đột biến. Thêm (ngoài đặc tả): tắt lớp 3 khi target nội bộ. Regress đầy đủ xanh |
| P3.5 | xong | `3341a1d` | S, làm lại 1 lần: cờ `--force-webrtc-ip-handling-policy` **bị Chrome 156 bỏ qua** (O đo: candidate `host` UDP vẫn có); preference `webrtc.ip_handling_policy` trong profile thì có tác dụng, cả trong context của `-urls -tabs 2`. Gate mới `webrtc-check` (netns có `dummy0` + default route). `docker-check` (`DOCKER=1`) xanh sau khi sửa hai lỗi cũ của gate (entrypoint thiếu `verify`, đường dẫn `host_port`) |
| P3.R | xong | `24d367b` | C: 13 nhận định, O kiểm; sửa 11 (S): request không bao giờ xong, `url.Parse` lỗi → cho qua, popup `noopener` không bị xét, worker tạo trong run, `g.ours` thiếu tab ở `-tabs`/`recycleTab`, `-attach` lỗi không reset LNA, thiếu `loopback-network`, origin iframe ở lớp 3, redirect 3xx, profile `last_used`/`Local State`. Ghi giới hạn: WebSocket từ worker không qua `Fetch`; mốc ghi trước commit. Regress đầy đủ xanh |
| P4.1 | xong | `ded61a8`, `b231c9b` | S fixture, O đo. Thêm cấu hình G/H (`-tabs 3` khi guard tắt) vì khi guard bật refresh không tới server nên không đo được thu hồi. Bảng ở `plan-28.md` 4.1 |
| P4.2 | xong | `46b913c` | S fixture, O đo trong netns riêng. Bảng ở `plan-28.md` 4.1 |
| P4.3 | xong | `90a095f` | H viết; O sửa khi dựng lần đầu (email `.test` bị Directus từ chối, header `Authorization` của Jellyfin 12, liên kết policy–role, tên project). Image kéo theo digest đã duyệt; `check-isolation.sh` xanh |
| P4.4 | xong | `53fd90e`, `b231c9b` | S công tắc + script; O gỡ đăng nhập lab: Jellyfin Web cần secure context (`crypto.randomUUID`) → lab chạy Jellyfin https 8920 tự ký, thêm `login -insecure`. Đo trong worktree riêng (45 lượt, ~3,5 giờ). Bảng ở `plan-28.md` 4.1 |
| P4.D | xong 2026-11-15 | — | Người dùng duyệt 1–4 và thêm mục 5, với 3 ràng buộc (`plan-28.md` 4.3) |
| P6.1 | xong | `8f5a00d` | H, đạt lần đầu; `flows-gate` (MCP=1) xanh |
| P6.2 | xong | `170c484` | H, đạt lần đầu |
| P6.3 | xong | `0ed3d6e` | S; trần `read_script` 56 KB (thay vì 128 KB) vì `maxReply` 120 KB và JSON escape. Đột biến bỏ kiểm "sha có trong index" bị bắt |
| P6.4 | xong | `0531d00` | S; `export-check` mở rộng (chạy hai lần so byte, redact, `-format all`) |
| P7.1a | xong | — | C hết giờ 2 lần (sandbox lồng của `agy` không chạy được lệnh giải nén); theo 3.7 chuyển S, O giải nén sẵn 5 gói. S: 228 operation, 187 độ tin cậy cao; O kiểm mẫu 10 dòng trên bundle. Bảng ở `plan-28.md` 4.1 (c) |
| P7.1b | xong (thô) | — | O: trên `_live_25e_max` (2.568 file): ESM không dấu bundler 72,5 %, khác 24,9 %, Vite/Rollup 1,2 %, Turbopack 0,9 %, webpack 0,5 % theo số file; theo dung lượng: khác 40 %, ESM 31 %, Vite 22 %, webpack 5 %. Phân loại theo chữ ký thô, làm lại kỹ ở P7 |
| P4.5 | xong | `d10e1b1`, `b414842` | S hai worker. (a) refresh POST, Deny trước Allow, `-guard-allow` neo hoặc từ chối, OR với session. (b) đồng bộ token (O sửa: phiên giữ token trong storage dùng khoá storage làm dấu; làm lại 1 lần: đọc cuối khi script đã dừng qua DOMStorage, snapshot ghi đè khi cài phiên), 401 tầng API, C4. Gate `session-check` + `refresh-app` (thêm `lock=1`: app cẩn thận dùng Web Locks). Sự cố: commit tài liệu `76844a1` cuốn theo bản P4.5b đang stage, O đã tách lại trước khi push (chưa push) |
| P5.1 | xong | `691aa54` | C viết `gd7-bola-design.md` (48 KB), phủ 14 luật đặc tả 6 |
| P5.2 | xong | `1c983ff` | S review: 16 nhận định (ví dụ credential của A vẫn gửi dưới B khi không làm mới được — O kiểm trên code, đúng); O ghi mục 8 với quyết định Q1–Q5 |
| P5.3 | xong | `5a005a4` | S fixture `peer-app` 11 ca, `peerscore`, `bola-check.sh`; O thêm `ownerId` cho orders (luật Q2) |
| P6.5 | xong | `af40e45` | S; test hai tiến trình chứng minh mất mục `index.jsonl` khi không khoá; đột biến khoá chia sẻ bị bắt |
| P5.4 | xong | `e48c37d` | S; làm lại 1 lần (căn template gộp nhầm endpoint vì tên tài nguyên dạng slug). O sửa fixture: GET tên `transfer` bị guard explore giữ; id 19 chữ số bị JS làm tròn; gate đếm `PEERLOG`. Gate `bola-check` vào `regress.sh` |
| P5.5 | xong | `4f335bc` | C review: 14 nhận định, S kiểm cả 14 đúng và sửa (O kiểm `alive()` và `fresh()` trên code). Đột biến: alive "không biết", `NamesAction`, giá trị ngắn theo path → bị bắt |
| P5.6 | xong | `ad8b5c3`, `4f335bc` | O chạy trên lab: Directus (`shared` ở `activity`, không bypass giả), Jellyfin (2 `needs-review`). Hai lỗi tìm ra và đã sửa: 401 của document với phiên token-storage; token bên trong header nhiều tham số. Chi tiết `gd7` mục 9 |
| P6.2b | xong | `5b6558e` | O tự làm (cần cho bước F của `bola-check`) |
| P5.T | đóng tạm (quyết định 2026-11-16) | — | Chưa có tài khoản target thật; chạy khi được cấp. Q2 giữ nguyên (không thêm `user`/`user_created`) |
| P7.1b | xong (thô) | — | Xem dòng P7.1b ở trên |
| P7.2 | xong: bỏ Bước 30 | — | Người dùng quyết 2026-11-16 (`plan-28.md` 4.4): hai cơ chế dự kiến thu hồi 0/228; P7.3–P7.5 không làm |
| P8.1 | xong: không đổi code | — | Không mục nào có số đo chứng minh cần: `perfgate` 3 lần trung vị 5,25 s, RSS đỉnh 254 MB (trần 15 s / 500 MB); `watch` 57k request trong 150 s cho RSS 164 MB (một phiên người dùng cần hàng giờ mới tới) |
| P8 (thêm) | xong | `212c814`, `c4f309b` | Người dùng yêu cầu: `refreshGrant` không cho lọt GraphQL (3 lỗ tái hiện bằng test rồi sửa, hai lớp); `setup.sh` tự tạo `user3` và `notes.user_created` (kiểm bằng dựng lại lab từ đầu, chạy hai lần) |
| P8.2 | xong | — | `DOCKER=1 testbed/regress.sh -j 3`: 23 gate (gồm `docker-check`) và unit xanh, 1.203 s |
| P8.3 | xong | (commit này) | `docs/rounds-history.md` thêm Đợt 28–30; `CLAUDE.md`: con trỏ đợt xong, bất biến mạng/phiên, gate mới |
| Khác | | `b231c9b` | `login -insecure` (lab tự ký). `bench` chỉ chấm app có `truth.txt` (`689ae2f`) |
