# GĐ4 4.3d — Giao diện MCP chỉ đọc (`jsharvest mcp`)

Mục tiêu (plan 2.1): một AI agent điều khiển Chrome qua MCP của nó (chrome-devtools-mcp, Playwright MCP), còn jsharvest `watch` ghi lại trên cùng Chrome đó. Agent cần hỏi được jsharvest: "thao tác vừa rồi đã gửi những request nào?". jsharvest **không** điều khiển trình duyệt và **không** gửi request.

Cổng nghiệm thu (plan): một agent thao tác `flows-app`, sau đó lấy được qua MCP đúng cụm request của từng thao tác.

## 1. Kiến trúc: tiến trình riêng, stdio, chỉ đọc file

```
AI client ──stdio── jsharvest mcp ──đọc── output/<host>/<role>/{watch.json, flows.partial.jsonl, flows.jsonl, requests.jsonl, runs.jsonl}
    └──MCP── chrome-devtools-mcp ──CDP── Chrome ──CDP── jsharvest watch ──ghi──┘
```

Lý do không nhúng server vào `watch`:
- **Không mở cổng mạng.** Một server HTTP trên localhost chứa cookie và token. Trang web chạy trong chính Chrome đó có thể gửi request tới server này, và đọc được response qua DNS rebinding. Với stdio thì client tự khởi chạy tiến trình, nên không có bề mặt tấn công qua mạng.
- **Chỉ một nơi gom cụm.** `flow.Build` chạy trong `watch`, còn MCP chỉ đọc kết quả đã gom.
- **Dùng được cả sau khi chạy xong.** Có thể hỏi về output của `crawl` hoặc của một lần `watch` đã kết thúc.
- **Vòng đời độc lập.** `watch` khởi động lại thì agent không mất kết nối MCP.

Thư viện: `github.com/modelcontextprotocol/go-sdk` v1.8.0 (SDK chính thức, `go 1.25.0`, không nâng `go.mod`).

## 2. Thay đổi phía `watch`

- **Snapshot gần thời gian thực.** Mỗi giây, nếu có request hoặc action mới thì ghi lại `flows.partial.jsonl` (ghi file tạm rồi rename). Chu kỳ ghi không nhỏ hơn 20 lần thời gian gom, để việc gom chiếm tối đa 5% thời gian chạy (giữ quy tắc cũ). Trước đây chu kỳ là 10 giây.
- **`watch.json`** (quyền 0600) được ghi khi bắt đầu, cập nhật mỗi tick và xoá khi kết thúc. Nội dung: `run`, `pid`, `tab`, `started`, `updated`, `guard`, `requests`, `actions`.
  - `updated` cho biết snapshot đã gồm mọi thứ được ghi trước thời điểm đó. MCP dựa vào trường này để biết khi nào có thể trả lời.
  - Nếu tiến trình `watch` chết, `pid` không còn sống, và MCP coi run đó là đã dừng.

## 3. Chọn thư mục và run

- **Thư mục.** `jsharvest mcp -o OUTROOT [-target HOST] [-role ROLE]`. Nếu không chỉ định, server chọn theo thứ tự:
  1. thư mục có `watch` đang sống, mới cập nhật nhất;
  2. nếu không có, thư mục có output mới nhất.

  Mọi câu trả lời đều ghi rõ `dir` và `run` đang đọc.
- **Run.** Mặc định server đọc run đang `watch`; nếu không có thì đọc run mới nhất trong `requests.jsonl`. Tham số `run` dùng để chọn run khác; `"all"` dùng cho `list_flows`, `endpoints` và `blocked`.
- **ID.** Request ID chỉ duy nhất trong một run. Action ID (`a1`, `a2`…, theo thời gian) ổn định với thao tác của người dùng, nhưng `bgN` có thể đổi giữa các snapshot.

## 4. Tool (tất cả đều `readOnlyHint`)

| Tool | Vào | Ra |
|---|---|---|
| `status` | — | Thư mục, target, role; run đang `watch` (tab, guard, số request và action, lần cập nhật cuối); vài run gần nhất; các thư mục khác |
| `last_action` | `wait_ms`, `quiet_ms` | Các thao tác **mới kể từ lần gọi trước**, mỗi thao tác kèm request của nó (id, method, URL, status, outcome, cách gán), endpoint, ghi (write), `depends_on`, nền mà thao tác khởi động |
| `list_flows` | `run`, `kind`, `contains`, `include_background`, `limit`, `offset` | Danh sách cụm dạng gọn |
| `get_flow` | `action`, `run` | Cụm đầy đủ |
| `get_request` | `id`, `run`, `max_body` | Một dòng `requests.jsonl` (header, body bị cắt ở `max_body`), kèm cụm chứa nó |
| `blocked` | `run`, `limit` | Request bị guard chặn (`held_back:*`): lý do, cụm, frame khởi phát |
| `endpoints` | `run`, `method`, `contains`, `limit` | Endpoint template gộp từ các cụm: số request, các thao tác dùng nó, outcome, mẫu |

**`last_action` theo con trỏ.** Agent thường làm theo vòng "thao tác, rồi hỏi thao tác đó gửi gì". Một bước có thể sinh nhiều cử chỉ, ví dụ gõ chữ rồi Enter, nên tool trả về mọi thao tác bắt đầu sau lần gọi trước. Ở lần gọi đầu tiên, tool chỉ trả thao tác mới nhất.
- **Chờ.** Khi đang `watch`, tool chờ tới `wait_ms` (mặc định 5000) cho đến khi có thao tác mới và tập request của các thao tác đó không đổi trong `quiet_ms` (mặc định 1500) qua các snapshot có `updated` sau lúc gọi.
- **Hết giờ.** Tool trả `settled: false` cùng những gì đã có.
- **Thao tác được tính** là cử chỉ thật của người dùng (`trusted`) hoặc `load`/`nav`. Event do trang tự bắn (`el.click()` trong code) không được tính.

**Che giá trị mặc định bật.** Output của MCP đi tới nhà cung cấp LLM. Cookie, Authorization, token và mật khẩu được thay bằng `REDACTED_<hmac>`; mỗi tiến trình có khoá riêng, nên hai chỗ cùng giá trị vẫn khớp nhau. `-reveal` tắt việc che.

**Giới hạn kích thước.** Mỗi câu trả lời tối đa khoảng 60 KB; danh sách có `limit`/`offset`; body bị cắt theo `max_body` (mặc định 4000, tối đa 65536).

## 5. Đọc file

- **`requests.jsonl`.** Đọc nối tiếp theo offset, chỉ xử lý tới dòng hoàn chỉnh cuối cùng (dòng đang ghi dở thì để lần sau). Index nhẹ theo `(run, id)` gồm method, URL, status, outcome, offset. `get_request` đọc lại đúng dòng theo offset. Nếu file nhỏ đi (bị xoá hoặc ghi lại) thì đọc lại từ đầu.
- **`flows.partial.jsonl` và `flows.jsonl`.** Cache theo kích thước và mtime. Run đã có trong `flows.jsonl` thì dùng bản đó. Bản partial của một run đã chết vẫn đọc được, đánh dấu `partial`.

## 6. Kiểm thử và gate

- **Unit.** Reader (dòng ghi dở, nhiều run, file bị cắt, chọn run, partial). Server qua `mcp.NewInMemoryTransports` (mọi tool, che giá trị, con trỏ của `last_action`, chờ cho đến khi ổn định).
- **Gate `MCP=1 testbed/flows-check.sh`.** `testbed drive -mcp "<lệnh>"` mở một MCP client stdio thật. Sau **mỗi** bước, driver gọi `last_action` ngay, như agent sẽ làm, rồi so tập request của các thao tác trả về với `expect` của bước, dùng cùng `expectMatch` với flowscore. Cổng: mọi bước có `expect` đều khớp chính xác, `flowscore` vẫn ≥ 95%, và `get_request` với `blocked` trả về đúng. Chạy thêm với `-guard on` để `blocked` có dữ liệu.
- **Demo với agent thật** (một lần, tuỳ chọn): `claude -p` với chrome-devtools-mcp (chạy trong container node) cùng `jsharvest mcp`, thao tác vài tính năng của `flows-app`, ghi lại câu trả lời.

## 7. Ngoài phạm vi

- Không có tool điều khiển trình duyệt, replay hay fuzz (thuộc 4.8 và GĐ5).
- Không có transport HTTP. Nếu sau này cần (container, `watch` ở máy khác), phải có token và kiểm tra `Host`/`Origin`.
- Không có MCP resource hay notification: agent hỏi chủ động.

## 8. Sửa đổi khi làm

- **Request đến muộn (`late`).** Lần chạy gate đầu đạt 19/20. Bước `#report` gửi request 2,5 giây sau click (qua `setTimeout`). `last_action` trả lời sau 1,5 giây yên lặng, và ở lần hỏi sau con trỏ đã vượt qua thao tác đó, nên agent **không bao giờ thấy** request này.
  - Cách sửa: server nhớ các request đã đưa cho mỗi thao tác. Mỗi câu trả lời có thêm `late`, chứa các thao tác cũ kèm **chỉ** những request mới của chúng.
  - Key của thao tác là `kind@started`, không dùng action ID, vì ID là thứ hạng theo thời gian và có thể dịch.
  - Server theo dõi 200 thao tác gần nhất.
- **Gõ chữ không sinh cụm.** Cụm `input`/`key` không có request bị `flow.Build` bỏ, nên sau một bước gõ, `last_action` chờ hết `wait_ms`.
  - Cách sửa: `watch.json` có thêm `last_event`, là thời điểm `watch` nhận event thật cuối cùng, tính theo đồng hồ của `watch`.
  - Khi không có thao tác mới, câu trả lời ổn định khi snapshot cách mốc muộn hơn giữa lúc gọi và `last_event` ít nhất `quiet_ms`.
  - Điều kiện này đúng với mọi nhịp tick: snapshot có `updated` sau event thì đã chứa event đó, và click luôn sinh cụm, kể cả khi không có request.
- **Lỗi có từ 4.3: nhãn mọi click chỉ là `"click"`.** Một cú click gồm `pointerup`, `mouseup`, `click` có cùng hạng. `gestures` lấy `element` của event đầu tiên, tức `pointerup`, mà event này không mô tả phần tử. Đã sửa: trong cùng một hạng, ưu tiên event có `element`. Có test `TestGestureNamedByDescribedEvent`. Nhãn giờ là `button "Save profile"`, `submit form "Find"`…
- **Gate khi bật guard.** Response giả `{}` không có `id`, nên app gọi `GET /api/notes/undefined`. Vì vậy:
  - với `-mcp-guard`, gate chỉ so các request ghi, và kiểm tra `blocked` gán mỗi request ghi vào đúng thao tác của bước;
  - `flowscore -guard` bỏ qua `depends_on`;
  - `flows-check.sh` kiểm tra mọi request ghi trong truth đều `held_back`.

## 9. Kết quả

| Gate | Kết quả |
|---|---|
| `flows-gate.sh`: nhịp thường, nhịp nhanh | 28/28 precision và recall (không đổi) |
| `MCP=1`: agent hỏi `last_action` sau mỗi bước | **20/20 bước** đúng chính xác tập request và cách gán (`causal`); `get_request`, `endpoints` đúng; `blocked` = 0 |
| Thời gian chờ của `last_action` (gate, 22 lần hỏi) | 1,8 / **3,0** / 5,0 giây (nhỏ nhất / trung vị / lớn nhất): 1,5 giây yên lặng, cộng độ trễ ghi của recorder (≥ 0,5 giây sau khi request kết thúc), cộng nhịp snapshot 1 giây |
| `MCP=1 GUARD=on` | **20/20 bước** (request ghi); `blocked` có 28 request, mỗi request ghi được gán đúng thao tác; flowscore 28/28 |
| Chỉ dùng cửa sổ thời gian | vẫn trượt, như yêu cầu |
| **Agent thật** (`testbed/agent-demo.sh`: Claude Sonnet + chrome-devtools-mcp 1.12.0 + `jsharvest mcp`, guard bật) | 5/5 bước, mỗi bước đúng tập request, khớp với `flows.jsonl`. Agent tự chọn trang, tự thao tác, tự gọi `last_action` sau mỗi bước. `blocked` gán `POST /api/profile` vào a8, `POST /api/notes` vào a10, beacon analytics vào `bg1`. Tốn $0,17, 18 lượt, 40 giây |
| `GATE=1 bench.sh`, `attach-guard.sh` | không đổi; ok |
| Unit test | `results`: đọc nối tiếp, dòng ghi dở, file bị ghi lại, partial và full, `watch.json` sống hoặc chết. `mcpserver`: con trỏ, chờ ổn định, gõ rồi Enter, nền, `late`, che giá trị và `-reveal`, cắt body theo ký tự, `blocked`, `endpoints`, phân trang, lỗi khi chưa có output |

## 10. Cách dùng

```sh
# Chrome riêng cho target (thay bằng chromium nếu distro chỉ cài chromium)
"${JSHARVEST_CHROME:-google-chrome}" --remote-debugging-port=9222 --user-data-dir="$HOME/.jsh-profile" &
jsharvest watch -attach http://127.0.0.1:9222 -open https://target/ -guard on -o out &
# Đăng ký với agent (Claude Code)
claude mcp add chrome -- npx chrome-devtools-mcp@1.12.0 --browser-url=http://127.0.0.1:9222
claude mcp add jsharvest -- /path/bin/jsharvest mcp -o /path/out
```

Mỗi lần agent thao tác bằng tool `chrome`, nó gọi `jsharvest.last_action` để lấy các request mà thao tác đó gây ra. Agent thật được chạy thử bằng `testbed/agent-demo.sh` (không phải gate).

## 11. Giới hạn còn lại

- Request do một thao tác gây ra mà đến sau câu trả lời thì nằm trong `late` của câu trả lời kế tiếp, không nằm trong câu trả lời đầu. Server không biết thao tác còn timer chưa chạy hay request đang bay. Có thể bổ sung tín hiệu này từ tagger (timer đang chờ theo tag) và recorder (request mở theo chuỗi), nếu cần.
- Action ID có thể dịch nếu một thao tác sớm hơn được ghi muộn. `get_flow` theo ID cũ khi đó trỏ sang cụm khác. Trường hợp này hiếm (chỉ xảy ra khi request điều hướng chính hoàn tất sau event).
- Nếu quá 10 thao tác mới trong một lần hỏi, các thao tác cũ hơn chỉ được đếm (`skipped`) và không được theo dõi `late`.
- Server tự chọn thư mục theo `watch` đang chạy. Khi có nhiều `watch` chạy cùng lúc, nên dùng `-target`/`-role` để chọn rõ.
