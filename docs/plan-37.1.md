# Đợt 37.1: Sửa tận gốc các điểm còn lại sau round37 (`d917bd2`)

Ngày: 2026-11-19 · Trạng thái: **đã triển khai** (xem mục "Triển khai" cuối file) · Tiền đề: [research-2026-11-19-speed-plan-review.md](research-2026-11-19-speed-plan-review.md) và bản đánh giá round37.

Mỗi mục gồm: **hiện trạng** (đã trace đến dòng mã), **gốc lỗi**, **giải pháp**, **vì sao không phải chắp vá**, **bất biến / rủi ro**, **kiểm thử và gate**.

### Sửa đổi so với v1 (sau review ngoài, đã kiểm lại từng điểm với mã)

| Điểm review | Kết quả kiểm | Thay đổi trong v2 |
|---|---|---|
| D: `finishFlight` chạy **trước** `cr.o.SourceMap` ([sourcemaps.go:150–160](../internal/httpcrawl/sourcemaps.go)); sighting của host 2 có thể đến trước khi host 1 `Put` body, và `Put` sẽ âm thầm bỏ qua ([store.go:253–256](../internal/store/store.go)) | **Đúng** | D: công bố kết quả cache **sau** callback; cập nhật `round37_test.go:146–152` |
| C: bỏ `ensureRootCanary` sẽ làm fail `TestRound37HostInFlight…` (không draft nào có prefix `/`) | **Đúng** | C: giữ root canary, chạy **thống nhất cho mọi N** |
| C: warm-up làm `Canary.Drafts` bị đếm hai lần; phải kiểm `BlockedHosts`, `Stopped`, `-max`, `GateAfter == 0` | **Đúng**; thêm nữa, `verify_test.go:263` (`Sent != 2`) và `:330` (`Sent > 5+3`) assert số request tuyệt đối | C: **bỏ pha warm-up**, thay bằng re-judge sau cùng, không phát sinh request |
| C: `stepDown` một chiều làm mất `-host-inflight` vĩnh viễn trên gateway hỗn hợp | **Đúng** (`throttled` không bao giờ nhả) | C4: cờ `gateSerializing` riêng, tự nhả khi `g.broken` |
| B: CDX (`wbIndexClient`) và Memento (`wbFilesClient`) là hai client và budget tách biệt, test cách ly `round34_2_test.go` ghim điều này; dùng chung `archiveEnv` **không** tự truyền AIMD từ CDX sang Memento | **Đúng**; câu tương ứng trong v1 sai | B: bỏ khẳng định đó; nêu rõ thiết kế truyền tín hiệu (mục B5) |
| B: `Depth == 0` thì không có Stage 1; nhiều target thì không `defer Close()` trong vòng lặp | **Đúng** | B: thêm vào B1, B2 |
| A3: `hostState` keyed theo hostname, `hs.ok++` chỉ ở `commitPage` | **Đúng** ([crawl.go:712–722](../internal/httpcrawl/crawl.go), [crawl.go:852](../internal/httpcrawl/crawl.go)) | A3: map riêng keyed theo origin, `ok` đặt ở mọi câu trả lời |
| A3: script/spec probe không qua `canDispatch` nên vẫn có thể bắn song song vào origin chưa chứng minh | **Đúng** | A3: gate "lần đầu" giống `breaker.go`, nhả bằng `defer` |
| A1: trang 3xx có body HTML lọt qua `!isHTML || a.Status >= 400` | **Đúng**, và v1 mô tả sai: `http.Redirect` của Go trả body HTML nên trang 302 **được gán print** (stub redirect thành "shell" và kéo theo một `spaCheck`), chứ không phải "không bao giờ ổn định" | A1: ngưỡng `>= 300`; ghi đúng hiện trạng |
| F4: breaker dial trả lỗi chuỗi thường và chạy **sau** limiter ([client.go:173–180](../internal/httpcrawl/client.go)) | **Đúng** | F4: lỗi sentinel cho cả hai breaker, kiểm trước limiter, `commitPage` rẽ nhánh như `givenUp` |
| E: lint phải xét cả `mux.HandleFunc`, loại closure có `.Lock()` | Hợp lý | E: cập nhật |

---

| # | Vùng | Mức | Tóm tắt |
|---|---|---|---|
| A | httpcrawl dispatch | Cao | Origin "chưa ổn định" bị khoá 1 request vĩnh viễn; stub 3xx bị coi là shell; không có breaker theo origin ở tầng response |
| B | archive orchestration | Cao | crawl dùng CLI như API nội bộ: `ExitOnError` trong tiến trình crawl, cờ nội bộ lộ ra, khoá đứt quãng giữa hai stage, trạng thái OTX/URLScan/CC không giữ |
| C | verify | Trung bình | Kiến thức HTML shell phụ thuộc thứ tự; root canary chỉ chạy khi N > 1 (N = 1 có false positive mà N > 1 không có); gate hạ về 1 vĩnh viễn |
| D | sourcemap dedup | Trung bình | `mapCache` giữ nội dung, không có trần |
| E | Test | Trung bình | Bộ đếm trong handler test không đồng bộ |
| F | Nhỏ | Thấp | UA, map đoán, `history()`, breaker ghi `requests.jsonl` |
| G | Docs | Thấp | Round37 chưa vào docs |

---

## A. httpcrawl: ổn định origin và breaker theo origin

### Hiện trạng

- `canDispatch` cho tối đa 1 request tới origin `o` khi `cr.prints[o] == ""` ([crawl.go:1892](../internal/httpcrawl/crawl.go)). `o` là `originOf(nx.URL)`, tức **URL được yêu cầu**.
- `cr.prints[origin]` được gán ở `commitPage` ([crawl.go:901–902](../internal/httpcrawl/crawl.go)) khi trang vượt qua điều kiện `!isHTML || a.Status >= 400` ([crawl.go:896](../internal/httpcrawl/crawl.go)). `origin` ở đây là `originOf(a.URL)`, tức **URL cuối sau redirect**.
- Ba hành vi sai:
  1. **Không bao giờ ổn định:** origin chỉ trả lỗi transport ([crawl.go:802](../internal/httpcrawl/crawl.go)), ≥ 400, không phải HTML, hay 3xx không có body HTML. Đo: 12 link trả 404 chậm 10 s cùng origin mất **125 s** (không đổi sau round37).
  2. **Ổn định sai:** 3xx có body HTML (mặc định của `http.Redirect`, nginx, Apache) vượt qua điều kiện, nên stub redirect bị gán làm print và `spaCheck` gửi thêm một request. Đã tái hiện: link `127.0.0.1/rN` trả 302 HTML, origin được "ổn định" bằng stub.
  3. **Lệch khoá khi redirect được follow:** print gán cho origin cuối, còn khoá đặt ở origin yêu cầu (suy từ mã; trên loopback policy chặn redirect giữa các cổng nên chưa dựng test được).
- Trang challenge (`verdict.Blocked`, [crawl.go:855–874](../internal/httpcrawl/crawl.go)) cố ý không ổn định. Hành vi này giữ nguyên.
- Không có breaker ở tầng response. `hostState` ([crawl.go:225](../internal/httpcrawl/crawl.go)) keyed theo **hostname** (bỏ scheme và port), còn `ok` chỉ tăng ở `commitPage`.

### Gốc lỗi

`prints[o]` đang gánh hai nghĩa: "shell" và "đã ổn định". Thiếu trạng thái "ổn định, không có shell". Khoá và trạng thái đặt ở hai origin khác nhau.

### Giải pháp

**A1. Tách "ổn định" khỏi "shell".** Thêm `cr.settled map[string]settleKind` (`settledShell`, `settledNoShell`), chỉ vòng điều phối ghi, ở bước commit.

| Câu trả lời khi commit | Hành động |
|---|---|
| HTML và `200 ≤ status < 300` | Gán print (như cũ), `settledShell`, chạy `spaCheck` |
| `status ≥ 300` (kể cả 3xx có body HTML), hoặc không phải HTML | `settledNoShell`; **không** gán print, **không** `spaCheck` |
| `verdict.Blocked` (challenge) | Giữ nguyên: không ổn định, `hostChallenged` như cũ |
| Lỗi transport (`a.Status == 0`) hoặc bị breaker giữ | Không ổn định; chuyển sang A3 |

- Đổi điều kiện ở [crawl.go:896](../internal/httpcrawl/crawl.go) từ `a.Status >= 400` thành `a.Status >= 300`. Trang 3xx vẫn được ghi `Page` như các trang không phải shell.
- Gán `settled` cho **cả** `originOf(it.URL)` và `originOf(a.URL)`. Print chỉ gán cho origin cuối. Origin yêu cầu khác origin cuối thì nhận `settledNoShell`.
- `canDispatch`: thay `cr.prints[orig] == ""` bằng `cr.settled[orig] == 0`.
- `settledNoShell` có thể nâng lên `settledShell` khi sau đó origin trả HTML 2xx (gán print, chạy `spaCheck`).

**A2.** Ổn định chỉ xảy ra ở commit (thứ tự heap), nên dispatch vẫn tất định. Không đụng `originInFlight`.

**A3. Breaker theo origin ở tầng response**, tách khỏi `hostState`:

```go
type originHealth struct {
    ok        bool          // đã từng nhận một câu trả lời HTTP (status > 0) từ origin này
    fails     int           // lỗi transport liên tiếp sau khi đã kết nối
    downUntil time.Time
    probing   bool
    probeWait chan struct{}
}
cr.origins map[string]*originHealth // key: originOf(raw) = scheme://host:port
```

- `ok = true` ở **mọi** lần `fetchWithHeaders` nhận `a.Status > 0`, bất kể loại fetch (trang, script, map, spec probe). Một CDN chỉ phục vụ script vẫn được coi là sống, và `https://h:443` sống không ảnh hưởng `https://h:8443`.
- Một "fail" là `a.Status == 0` với timeout hoặc reset **sau khi kết nối**: `net.Error.Timeout()`, TLS handshake timeout, header timeout, `ECONNRESET`, `io.ErrUnexpectedEOF` trước header. Lỗi dial do breaker dial xử lý, không đếm hai lần. `ctx` bị hủy thì không tính.
- Khi `ok == false`, breaker mở sau 3 fail liên tiếp; cooldown 3 phút; half-open 1 request. Khi `ok == true`, breaker không bao giờ mở (một origin đã chứng minh sống không bị khoá vì lỗi thoáng qua).
- **Gate lần đầu** khi `ok == false`: chỉ một request tới origin chưa chứng minh được bay; các request khác (kể cả script worker và spec probe, vốn không qua `canDispatch`) chờ trên `probeWait`, giống mẫu [breaker.go:95–109](../internal/httpcrawl/breaker.go). `probing` được nhả bằng `defer` (kể cả khi `ctx.Done()` hoặc panic). Chi phí với origin khoẻ là 1 RTT cho request đầu.
- Điểm kiểm duy nhất ở **đầu `fetchWithHeaders`, trước limiter** (xem F4).

### Vì sao không phải chắp vá

Sửa mô hình trạng thái (thêm trạng thái còn thiếu, đúng khoá, đúng ngưỡng 3xx) thay vì nới `maxWin` hay tăng worker để bù. Breaker đặt ở tầng có thông tin về câu trả lời, keyed đúng đơn vị (origin), và dùng một điểm chặn chung cho mọi loại fetch.

### Bất biến / rủi ro

- SPA catch-all: trang đầu là 200-HTML, đi nhánh `settledShell` như cũ.
- Origin trả 404 rồi mới phục vụ shell: vài trang có thể chạy song song trước `spaCheck`, nghĩa là thêm request chứ không mất route. Chấp nhận được.
- MAX-02, `hostChallenged`, `politeAt` giữ nguyên.
- Thay đổi output có chủ đích: origin chỉ trả 3xx không còn có `spaCheck`/print (bớt 1 request mỗi origin như vậy).

### Kiểm thử và gate

- Unit (mỗi kịch bản một test, timeout ngắn 1–2 s để test nhanh):
  - 12 link 404 chậm cùng origin;
  - 302 có body HTML (không còn gán print, không `spaCheck`);
  - 9 link dial timeout;
  - TLS handshake treo (listener nhận TCP, không trả lời TLS);
  - CDN chỉ phục vụ script, có 3 timeout xen giữa nhiều request thành công (breaker **không** mở);
  - origin `:8443` chết trong khi `:443` sống (breaker mở cho `:8443`).
- Mục tiêu: 12 link 404 chậm cùng origin còn khoảng 3 × timeout (giới hạn bởi 4 page worker); TLS treo: 3 fail rồi fail ngay.
- `TestParallelPagesDeterministicOrder`, `TestPipelined*`, `go test -race ./internal/httpcrawl/...`.
- Gate: `pipeline-check.sh`, `waf-check.sh`, `frontier-check.sh`, `frontier-tabs-check.sh`, và `bin/testbed reqcheck` (vì F4 đổi cách ghi `requests.jsonl`).

---

## B. archive: tách lớp CLI khỏi lớp chạy

### Hiện trạng

- crawl gọi `archiveRun(ctx, args []string)` hai lần, với `-list-only` và `-stage2` ([main.go:562](../cmd/jsharvest/main.go), [main.go:584](../cmd/jsharvest/main.go)).
- Mỗi lần gọi: parse lại `flag.NewFlagSet("archive", flag.ExitOnError)` ([archive.go:44](../cmd/jsharvest/archive.go)), lấy lại `lockDirs`, mở lại store, dựng mới mọi client và budget.
- Client CDX (`wbIndexClient`, `Wayback.Index`) và Memento (`wbFilesClient`, `Wayback.Files`) **tách biệt có chủ đích**, và `round34_2_test.go` ghim điều này: Memento bị latch thì CDX vẫn liệt kê tiếp.
- Stage 1 chỉ dùng client index của Wayback cùng OTX/CC/URLScan. Stage 2 bỏ qua `listWayback` ([list.go:94–102](../internal/archive/list.go)); `pages()`/`fetch()` chỉ dùng client files.
- Hệ quả thật:
  1. `ExitOnError`: tham số sai do crawl dựng sẽ `os.Exit(2)` cả crawl, bỏ qua `defer`.
  2. Cờ nội bộ hiện trong `jsharvest archive -h`.
  3. Khoá bị nhả giữa Stage 1 và Stage 2, để một `jsharvest archive` khác có thể chen vào.
  4. Budget và latch của **OTX/URLScan** (Stage 2 hỏi delta `ExtraHosts`) bị dựng lại, nên mất AIMD đã học ở Stage 1.
  5. Trạng thái giữa hai stage truyền qua biến đóng gói trong `main.go`.

### Gốc lỗi

crawl dùng **CLI** làm API nội bộ.

### Giải pháp

**B1. Tách lớp** trong `cmd/jsharvest/archive.go`:

```go
type archiveConfig struct { /* giá trị flag đã parse và kiểm */ }
func parseArchiveFlags(args []string) (archiveConfig, error) // flag.ContinueOnError
type archiveEnv struct {
    opts       archive.Options // mọi client + Budget, dựng một lần
    sender     *replay.Sender  // live check, tạo lười (chỉ khi mode cần)
    unlock     func()
    stage1Ran  bool
    stage1Err  error
}
func newArchiveEnv(ctx context.Context, cfg archiveConfig) (*archiveEnv, error)
func (e *archiveEnv) Run(ctx context.Context, mode archive.Mode) (*archive.Summary, error)
func (e *archiveEnv) Close()
```

- `archive.Mode` có ba giá trị: `ModeFull | ModeListOnly | ModeResume`. Nó thay cho ba bool `ListOnly`/`Stage2`/`DisablePrefetch` trong `archive.Options`.
- `jsharvest archive` gọi `parse → newArchiveEnv → Run(ModeFull) → Close`. Hai cờ nội bộ bị **xoá**.
- crawl dựng một `archiveEnv` cho **mỗi target**:
  - Stage 1 gọi `Run(ModeListOnly)` và ghi `stage1Ran`, `stage1Err`.
  - Sau barrier, gọi `Run(ModeResume)` nếu `stage1Ran`, ngược lại gọi `Run(ModeFull)`. Trường hợp thứ hai bao gồm `cfg.Depth == 0`, khi `ArchiveStage1` không chạy ([http.go:176](../internal/engine/http.go)).
  - Cuối cùng `Close()`.

**B2. Khoá và vòng đời.**
- `newArchiveEnv` lấy `lockDirs("archive")` một lần và giữ suốt hai stage.
- Với nhiều target ([main.go:533](../cmd/jsharvest/main.go), `for _, t := range targets`), `Close()` được gọi **ngay khi target xong**, trong một hàm con có `defer` riêng, không `defer` trong thân vòng lặp. Như vậy không giữ chồng khoá.

**B3.** Kết quả Stage 1 nằm trong `archiveEnv`, không còn biến đóng gói ở `main.go`.

**B4.** `ModeListOnly` không dựng sender, nên 0 request tới target (bất biến). `ModeResume` đọc `archive.json` (đã có) và không dựng lại client.

**B5. Truyền tín hiệu từ CDX sang Memento: có chủ đích và một chiều.**
- Dùng chung `archiveEnv` **không** tự truyền AIMD từ CDX sang Memento: hai client tách biệt, và đó là thiết kế đúng. Thư viện `wayback` (theo hướng dẫn của Internet Archive) dùng hai giới hạn riêng: CDX ~30/phút, Memento ~600/phút. Một 429 của CDX không có nghĩa Memento cũng bị giới hạn.
- Chỉ truyền tín hiệu **ở mức IP**: nếu Stage 1 thấy client index bị **từ chối kết nối** (chuỗi `ECONNREFUSED`/`ECONNRESET` làm `recordConnTrouble` latch, tức IP bị chặn chứ không phải giới hạn tốc độ), thì khi vào `ModeResume`:
  - đặt `Wayback.Files.cooldownUntil = max(…, now + Wait)`;
  - đánh dấu client files ở trạng thái "nghi ngờ", để lần từ chối **đầu tiên** của Memento là latch ngay (thay vì phải đủ ngưỡng).
- Không truyền theo chiều ngược lại, và không truyền 429/503 thuần. Test cách ly `round34_2_test.go` giữ nguyên.

### Vì sao không phải chắp vá

Sửa đúng ranh giới lớp: các hệ quả 1–5 biến mất cùng lúc. Việc truyền tín hiệu CDX → Memento là một quy tắc có căn cứ (mức IP so với mức tốc độ), không phải tác dụng phụ của việc dùng chung đối tượng.

### Bất biến / rủi ro

- Stage 1 không gửi request tới target. Mã thoát 3 khi bị chặn giữ nguyên. `archive.json` tương thích ngược.

### Kiểm thử và gate

- Unit: `parseArchiveFlags` với tham số sai trả lỗi, không thoát tiến trình.
- Unit: OTX trả 429 ở Stage 1 làm `curGap` tăng; Stage 2 hỏi delta `ExtraHosts` với `curGap` đã tăng.
- Unit: CDX bị từ chối kết nối ở Stage 1, Stage 2 bắt đầu Memento sau cooldown, latch ngay ở lần từ chối đầu. CDX trả 429 thuần thì Memento **không** bị ảnh hưởng.
- Unit: `Depth == 0` chạy `ModeFull` (có liệt kê Wayback/CC).
- Unit: 2 target liên tiếp, khoá của target 1 được nhả trước khi target 2 bắt đầu.
- `round34_2_test.go`, `TestRound37TwoStage…`, `TestRound37ArchiveStage1Overlaps…` vẫn pass.
- Gate: `archive-check.sh`, `pipeline-check.sh`, `proxy-check.sh`.

---

## C. verify: phán quyết shell tất định, không thêm request

### Hiện trạng

- Phán quyết 200-HTML dựa trên `matchesKnownHTMLShell` (`judge`), đọc `htmlShells`. `htmlShells` được ghi dần khi canary trả lời (`canaryAnswer` → `recordHTMLShell`). Vì vậy kiến thức lúc judge phụ thuộc thứ tự.
- Shell `*` (từ 2 host trở lên) đã không tất định **từ trước round37**, ngay ở N = 1, vì các host chạy song song (`-concurrency 8`).
- `ensureRootCanary` chỉ chạy khi `hostMaxInFlight() > 1`. Nghĩa là với cùng dữ liệu, **N = 1 cho false positive mà N > 1 không cho**: trường hợp 0006 (`/api/v2/missing-route` trả shell SPA gốc) trong `TestRound37HostInFlight…`, test này chỉ chạy với N = 4.
- `ensureRootCanary` gọi `canary()` → `canaryFor`, tăng `perOrigin`, nên có thể đổi khoá fallback khi đặt `MaxPrefixes`.
- `hostSlotPool.stepDown` đặt `throttled = true` vĩnh viễn ([verify.go:341](../internal/verify/verify.go)).
- Các test assert số request tuyệt đối: [verify_test.go:263](../internal/verify/verify_test.go) (`Sent != 2`), [verify_test.go:330](../internal/verify/verify_test.go) (`Sent > 5+3`); [verify_test.go:515](../internal/verify/verify_test.go) so `Sent` giữa N = 1 và N = 3.

### Gốc lỗi

Hai thao tác khác bản chất bị trộn vào một bước judge:
- **Thu thập bằng chứng** (gửi canary, sub-canary, OPTIONS): cần request, và cần thứ tự.
- **Đối chiếu với kiến thức tổng hợp** (shell đã biết của host và `*`): không cần request, nhưng hiện được làm sớm, với kiến thức chưa đủ.

### Giải pháp

**C1. Re-judge sau cùng (thay cho pha warm-up của v1).**
- Sau khi mọi probe xong và **trước** khi ghi `verify.json`/`verify.md`, duyệt kết quả theo thứ tự draft. Với mỗi kết quả `Alive` mà `Answer` là 200-HTML có `Shell`, áp lại đúng nhánh đầu tiên của `judge` cho 200-HTML với `htmlShells` **cuối cùng**:
  - `matchesKnownHTMLShell` khớp và draft là chuỗi trần → `ClientRoute`;
  - khớp nhưng không phải chuỗi trần → `DeadOrFP`;
  - cùng chuỗi lý do như `judge`, thêm hậu tố `(re-judged)` để truy vết.
- Vì sao đúng: trong `judge`, kiểm `matchesKnownHTMLShell` là nhánh **đầu tiên** của 200-HTML. Một kết quả đã `Alive` qua nhánh này chỉ vì lúc đó kiến thức còn thiếu. Áp lại với kiến thức đầy đủ tương đương judge với kiến thức đầy đủ (chỉ khác là sub-canary có thể đã được gửi; verdict không phụ thuộc điều đó).
- Tính chất:
  - (a) **0 request thêm**: không đổi `Sent`, tương thích các test assert số tuyệt đối;
  - (b) **tất định**: tập canary của prefix giống nhau ở mọi N và mọi thứ tự, nên `htmlShells` cuối cùng giống nhau, kể cả shell `*`;
  - (c) **đơn điệu**: chỉ hạ `Alive` xuống `DeadOrFP`/`ClientRoute`, không bao giờ tạo `Alive`;
  - (d) không đụng `Drafts`, `-max`, `BlockedHosts`, `GateAfter`.
- Gate (`noteGate`) dùng verdict tại thời điểm probe, không bị re-judge thay đổi (hành vi gate giữ nguyên).
- `export -drafts` và `AliveKeys` đọc `verify.json`, nên tự nhận verdict đã re-judge.

**C2. Root canary thống nhất cho mọi N** (thay vì xoá):
- Bỏ điều kiện `hostMaxInFlight() > 1`. Khi một probe trả 200-HTML có shell mà chưa khớp shell nào đã biết, và prefix của nó khác `/`, gọi `rootCanary(origin)`. Hàm này singleflight theo `origin + "/"`.
- `rootCanary` **không** đi qua `canaryFor` và **không** tăng `perOrigin`/`Drafts`, nên `MaxPrefixes` không lệch.
- Nếu sau đó một draft có prefix `/` gọi `canaryFor`, nó dùng lại canary đã có (cache hit, `Drafts++` như mọi cache hit), và `perOrigin` **được tăng một lần ở thời điểm này** (đánh dấu `counted` trên `Canary` để không đếm hai lần). Nhờ vậy ngữ nghĩa ngân sách giống hệt trước.
- Trigger là chính câu trả lời của probe đó, nên điều kiện giống nhau ở mọi N. Kết quả: 0006 là `DeadOrFP` ở cả N = 1 và N > 1.
- Chi phí: tối đa 1 request mỗi origin, **chỉ** khi có probe trả 200-HTML chưa biết. Phải chạy lại các test có `Sent` tuyệt đối; dữ liệu của chúng không có 200-HTML nên dự kiến không đổi, cần xác nhận khi triển khai.

**C3.** Thay đổi hành vi ở N = 1 (theo hướng ít false positive hơn), nên phải so verdict trên corpus thật trước khi chốt (bước 5 của lộ trình).

**C4. Gate khi N > 1: tuần tự hoá có điều kiện, tự nhả.**

```go
type hostSlotPool struct {
    mu        sync.Mutex
    limit     int
    inFlight  int
    throttled bool // 429 / BlockRate: một chiều, như hiện nay
    gateSer   bool // đang nghi gate: bật/tắt theo trạng thái gate
    wake      chan struct{}
}
```

- Hiệu lực: `lim = 1` nếu `throttled || gateSer`.
- `noteGate` (đã dưới `v.mu`):
  - ứng viên gate đầu tiên (`asCanary && gateStatus[...]`, `g.first == nil`) → `pool.setGateSerial(true)`;
  - `g.broken = true` (host trả lời khác canary, tức không bị gate toàn cục) → `pool.setGateSerial(false)` và **đánh thức** người chờ (`close(wake)`);
  - `g.why != ""` (gate xác nhận) → giữ, vì host đã dừng gửi.
- Request đang bay khi bật `gateSer` (≤ N−1) vẫn báo verdict thật; ghi chú trong mô tả cờ `-host-inflight`.

### Vì sao không phải chắp vá

Tách đúng hai bản chất: thu thập bằng chứng (giữ lười, singleflight) và đối chiếu kiến thức tổng hợp (làm một lần, ở cuối, với dữ liệu đầy đủ). Heuristic "chỉ N > 1" bị bỏ, thay bằng một quy tắc chung cho mọi N. Gate có trạng thái hai chiều thay vì latch một chiều.

### Kiểm thử và gate

- `TestRound37HostInFlight…` chạy thêm với N = 1: 0006 phải là `DeadOrFP`.
- Unit: shell `*` từ 2 host, 5 lần với `-concurrency 8`, verdict y hệt nhau.
- Unit: gateway hỗn hợp (`/api/v1/*` trả 401, `/public/*` trả 200), N = 4: sau probe 200 đầu tiên, in-flight trở lại 4.
- Unit: re-judge không đổi `Sent`; mọi thay đổi verdict là `Alive` → `DeadOrFP`/`ClientRoute`.
- Ép N = 4 cho toàn bộ test verify: mọi test verdict pass (như đánh giá round37).
- Gate: `verify-check.sh`, `crosscheck-check.sh`, `replay-check.sh`.

---

## D. sourcemap dedup: cache tham chiếu, công bố sau khi lưu

### Hiện trạng

- `mapCache[key]` giữ `ownFiles []sourcemap.File` **có nội dung**, cho mọi map có `sourcesContent` đầy đủ, suốt crawl. Mỗi map tối đa 64 MiB ([sourcemap.go:88](../internal/sourcemap/sourcemap.go)).
- Thứ tự hiện tại ([sourcemaps.go:150–160](../internal/httpcrawl/sourcemaps.go)): `finishFlight(sm, own)` (công bố cache, đóng `ready`) chạy **trước** `cr.o.SourceMap(...)` (engine `put` body vào store).
  - Hiện chưa gây lỗi, vì người dùng lại vẫn nhận nội dung.
  - Nhưng sẽ thành race ngay khi chuyển sang tham chiếu: sighting `Put(Record{SHA256})` đến trước body thì `s.entries[sha] == nil` và `Put` trả `"", false, nil` một cách âm thầm ([store.go:253–256](../internal/store/store.go)). Host 2 mất `urls`, `pages`, `initiator`, `scripts[key]`.

### Gốc lỗi

Cache lưu **dữ liệu** thay vì **tham chiếu**, và công bố trước khi dữ liệu được lưu bền.

### Giải pháp

1. **Thứ tự "lưu rồi mới công bố":** dời `finishFlight(sm, ownRefs)` xuống **sau** `cr.o.SourceMap(...)`. Giữ `defer finishFlight(nil, nil)` cho mọi nhánh thoát sớm hoặc panic: người chờ thấy "không có cache" và tự tải.
2. **Tham chiếu thay vì nội dung:**
   - `mapDedupEntry` giữ `ownRefs []sourcemap.SourceRef{Path, SHA256}`. SHA tính một lần khi trích own files ở lần tải đầu.
   - `SourceMap` thêm `OwnRefs`; khi `Reused` thì chỉ có `OwnRefs` (không có `OwnFiles`).
   - Engine phát lại bằng sighting: `put(store.Record{SHA256: ref.SHA256, URL: where+"#"+ref.Path, Page: m.ScriptURL, Kind: "source", Via: "sourcemap", Target: "http", Tags: …, Source: "live", Initiator: …})`.
3. **Phát hiện sighting hụt thay vì im lặng:** engine kiểm giá trị trả về của `Put`. Sighting trả key rỗng thì tăng `run.StoreErrors["sighting_missing"]` và ghi log cảnh báo. Với thứ tự ở mục 1, điều này chỉ xảy ra khi lần đầu bị `ErrTooLarge`, cùng hành vi như trước.
4. `index.jsonl` giống hệt hiện nay, vì cùng SHA thì `Put` có body cũng chỉ `merge`. Bộ nhớ cache giảm xuống vài chục byte mỗi file.

### Kiểm thử và gate

- Cập nhật `round37_test.go:146–152`: đọc `OwnRefs` khi `m.Reused`.
- Unit: 6 host cùng bundle, `PageWorkers: 4` (song song thật), `-race`: `index.jsonl` có đủ 6 `pages` cho mọi source.
- Unit: lần đầu `ErrTooLarge` thì có `sighting_missing` và host sau tự tải.
- Gate: `pipeline-check.sh`, `endpoints-check.sh`.

---

## E. Test: bộ đếm không đồng bộ trong handler

### Hiện trạng

- `newsHits++` ([round34_test.go:53](../internal/httpcrawl/round34_test.go)) gây race, tái hiện được trên cả `2e5c5fc`.
- Cùng mẫu có 14 chỗ:
  - `endpoints/cloud_test.go:341`
  - `engine/round34_2_test.go:211`
  - `engine/specprobe_test.go:29,43`
  - `httpcrawl/round33_test.go:24`
  - `httpcrawl/round34_test.go:53`
  - `httpcrawl/internal_test.go:14`
  - `httpcrawl/specprobe_test.go:33,166`
  - `tlsutil/aia_test.go:89,92`
  - `verify/cloud_sso_test.go:99`
  - `verify/verify_test.go:304`
  - `mcpserver/server_test.go:458`

### Giải pháp

- Rà từng chỗ. Bộ đếm nào được ghi trong handler HTTP hoặc goroutine thì đổi sang `atomic.Int32/Int64`.
- Test lint `internal/testlint` (chạy trong `go test ./...`):
  - dùng `go/ast` duyệt `*_test.go`;
  - báo lỗi khi `x++`/`x += …`/`x = …` ghi vào biến cục bộ bị capture trong closure truyền cho `http.HandlerFunc(...)`, `mux.HandleFunc(...)`, `http.HandleFunc(...)` hoặc `httptest.NewServer(...)`;
  - bỏ qua closure có gọi `.Lock()` trước phép ghi (đã đồng bộ).

### Gate

- `go test -race -count=20` cho các test đã sửa.
- Bước unit của `regress.sh`.

---

## F. Các điểm nhỏ

1. **Chọn UA** (`CrawlHostsWithUA`, [hosts.go:17–65](../internal/archive/hosts.go)): giữ hành vi mới. Ghi rõ thứ tự ưu tiên trong chú thích hàm:
   1. role;
   2. thư mục target và `target_port`;
   3. UA trình duyệt trước UA engine;
   4. bỏ request có tag `challenge`/`jsharvest`.

   Thêm unit test ghim thứ tự này.
2. **Map đoán trúng cache:** bỏ `cr.guesses.Done(ref.URL, true)` ở nhánh trúng cache ([sourcemaps.go:75–77](../internal/httpcrawl/sourcemaps.go)), vì origin này chưa có quan sát nào.
3. **`history()` khi bị chặn và store rỗng:** luôn chạy `history()`. Hàm đã xử lý store rỗng, và không test/gate nào đòi `historical.jsonl` vắng mặt khi bị chặn.
4. **Request bị breaker giữ** (đi cùng A3):
   - Hai lỗi sentinel: `errDialBreaker` (bọc lỗi ở [breaker.go:72](../internal/httpcrawl/breaker.go)) và `errOriginDown` (A3).
   - Kiểm **trước** limiter: `fetchWithHeaders` hỏi `cr.origins[o]` (A3) và `dialBreaker.IsOpen(hostport)` (hàm truy vấn mới, chỉ đọc) trước `pageLimit.wait`/`limit.wait`. Request bị giữ không tốn hạn mức `-http-rate`.
   - `fetchWithHeaders` không gọi `cr.log` cho lỗi sentinel, nên `requests.jsonl` chỉ có request đã thật sự gửi.
   - `commitPage` rẽ nhánh sớm như `fp.givenUp` ([crawl.go:786–793](../internal/httpcrawl/crawl.go)):
     - không tăng `Visited`/`Stats.Pages`;
     - ghi `Page{Visited: false, Reason: "origin-unreachable"}`;
     - tăng `cr.res.Listed["origin-unreachable"]`.
   - Thêm `Stats.HeldByBreaker`.

---

## G. Docs

- `docs/CURRENT.md`: round37 (cờ `-host-inflight`, `-archive-max-pages`, hai stage, AIMD/stride, WARC fallback, breaker, map dedup) và 37.1.
- `docs/rounds-history.md` và `docs/archive/rounds-history-full.md`: Đợt 37, 37.1.
- `docs/gd5-archive-design.md`: `archiveEnv`/`Mode`, AIMD, stride, giới hạn ~30 req/phút của CDX và ~600 req/phút của Memento (có nguồn), quy tắc truyền tín hiệu B5.
- Mục verify trong `docs/gd6-waf-design.md`: `-host-inflight`, re-judge sau cùng, root canary thống nhất, `gateSer`.
- `CLAUDE.md`:
  - bảng chọn gate: thêm `httpcrawl/breaker.go` và `sourcemaps.go` (gate `pipeline-check` + `waf-check`);
  - bất biến mới: "Stage 1 archive không gửi request tới target"; "`requests.jsonl` chỉ ghi request đã gửi".

---

## Thứ tự thực hiện

| Bước | Nội dung | Lý do thứ tự |
|---|---|---|
| 1 | E | Rẻ; làm `regress.sh` xanh để các bước sau có nền sạch |
| 2 | A + F4 | Lợi lớn nhất cho crawl; F4 đi cùng A3 vì cùng đổi cách ghi `requests.jsonl` |
| 3 | B | Độc lập với A |
| 4 | D + F2 | Cùng vùng sourcemap |
| 5 | C | Đổi hành vi verify ở N = 1 (theo hướng ít FP); so verdict trên corpus thật trước khi chốt |
| 6 | F1, F3, G | Hoàn thiện |

Mỗi bước một commit, chạy đủ gate trong bảng của bước và `go test -race ./internal/...`.

---

## Triển khai (2026-11-19)

Mọi mục A–G đã làm, chưa commit. Phần lệch so với đặc tả, kèm lý do:

| Mục | Lệch | Lý do |
|---|---|---|
| E | Không phải 14 chỗ như liệt kê: phần lớn đã có mutex. Race thật ở 2 test (`newsHits`, `derHits`/`pemHits`), đổi sang atomic. Lint `internal/testlint` tìm thêm 9 chỗ ghi biến capture (`asked`, `rng`, `key`, `hit`, `got`, `hits`, `hitPaths`), sửa bằng mutex riêng mỗi biến | Grep ban đầu đếm thừa; lint dựa trên AST mới chính xác |
| A1 | Trang 3xx **vẫn được trích link** (body, cộng thêm header `Location` dạng `frontier.Redirect`), chỉ không gán print và không `spaCheck`. 3xx không phải HTML cũng trả `Location` | Đổi ngưỡng máy móc thành `>= 300` sẽ làm mất link đích của redirect (trước đây chỉ thu qua body) |
| A3/F4 | `originHealth` nằm trong `httpcrawl/origins.go`; breaker dial có `isOpen` và sentinel `errDialBreaker`; cả hai được kiểm ở đầu `fetchWithHeaders`, trước limiter | Như đặc tả |
| B5 | Logic truyền tín hiệu nằm ở `archive.(*Wayback).CarryIndexBlock()` thay vì ở CLI | Để test được trong gói `archive` (latch của client là trường không xuất) |
| C | Re-judge (`rejudgeShells`) thay cho warm-up; `rootCanary` riêng, có cờ `uncounted` được đếm khi `canaryFor` dùng lần đầu; `gateSer` trong `hostSlotPool` | Như đặc tả v2 |
| D | `SourceMap.OwnRefs` và `SourceRef{Path, SHA256}` nằm trong `httpcrawl` (không trong `sourcemap`); `put` của engine trả key để phát hiện sighting hụt | Giữ gói `sourcemap` thuần |

Test mới: `httpcrawl/round37_1_test.go` (5), `engine/round37_1_test.go` (1), `archive/round37_1_test.go` (1), `archive/hosts371_test.go` (1), `verify/round37_1_test.go` (4), `cmd/jsharvest/round37_1_test.go` (2), `testlint` (1). Ba test đã được kiểm ngược bằng mutation (đảo thứ tự công bố map; tắt re-judge; tắt nhả gate): đều fail khi mã sai.

---

## Tồn đọng nhỏ sau Round 37.1

Theo review sau commit, đã kiểm lại với mã. `T1` và `T3` đã được đóng ở **Đợt 38** ([plan-38.md](plan-38.md)); `T2` giữ defer vì phạm vi cực hiếm.

### T1. `rejudgeShells` không xoá `VerifiedBase` *(Đã đóng ở Đợt 38)*

- **Hiện trạng:** `one()` gán `res.VerifiedBase = candBase` cho kết quả `Alive` của candidate đầu cơ ([verify.go:546–548](../internal/verify/verify.go)). `rejudgeShells` hạ verdict và xoá `VerifiedMethod` nhưng không xoá `VerifiedBase`.
- **Dấu hiệu khi vướng:** `verify.json` có kết quả `dead_or_fp`/`client_route` mà vẫn mang `verified_base`. Tiêu thụ nào tin `verified_base` mà không xét verdict (ví dụ `export -drafts` chọn base, hay MCP liệt kê base đã xác nhận) sẽ nhận một base sai.
- **Xử lý:** trong `rejudgeShells`, khi hạ verdict thì xoá luôn `r.VerifiedBase = ""`. Rà mọi chỗ đọc `VerifiedBase` (`grep -rn VerifiedBase internal cmd`), bảo đảm tất cả đều đi kèm điều kiện verdict.
- **Test:** draft nhiều candidate, base 1 trả 2xx-HTML là shell chỉ học được về sau (shell `*` từ 2 host chậm, như `TestRound371RejudgeWithEveryCanaryKnown`). Kỳ vọng sau re-judge: verdict `dead_or_fp` và `verified_base` rỗng.

### T2. Re-judge không thử lại candidate sau, và không sửa thống kê base đầu cơ

- **Hiện trạng:** trong `one()`, candidate đầu tiên trả `Alive` thì `return` ngay ([verify.go:549–551](../internal/verify/verify.go)); `noteSpecBase(candBase, …, Alive)` đã ghi vào `specBases` ([verify.go:543](../internal/verify/verify.go)). Nếu re-judge hạ kết quả đó:
  - (a) candidate 2 không được thử;
  - (b) `specBases` vẫn coi base 1 là sống, có thể làm lệch việc cắt tỉa base đầu cơ (`specBasePruneAfter`, round36) cho các draft khác trong cùng run.
- **Phạm vi:** hiếm. `rootCanary` đã chạy ngay trong `judge` cho cùng origin, nên chỉ xảy ra khi shell được học **từ host khác** (`*`) sau thời điểm probe.
- **Dấu hiệu khi vướng:** draft có `candidates` ra `dead_or_fp` với lý do có hậu tố `(judged again with every canary known)`, trong khi một base khác của cùng draft thật ra sống (biết được nhờ chạy lại verify).
- **Xử lý (theo thứ tự ưu tiên, chỉ làm khi gặp thực tế):**
  1. **Ghi nhận rõ:** thêm vào `Result` danh sách candidate chưa thử (`untried_candidates`), để người dùng và `export` biết.
  2. **Thử lại có giới hạn:** sau `rejudgeShells`, với mỗi draft bị hạ mà còn candidate chưa thử, chạy lại `one()` **chỉ trên các candidate còn lại** (bỏ candidate đã hạ). Lúc này shell đã đủ, nên phán quyết tất định. Chi phí là thêm request đúng bằng số candidate còn lại của các draft bị hạ (thường bằng 0), tuân theo `-rate`, `-max`, gate và `BlockedHosts`.
  3. **Sửa thống kê:** khi hạ, gọi bản đảo của `noteSpecBase` (trừ một lượt sống của base đó) trước khi chạy lại bước 2, để việc cắt tỉa của lượt thử lại dựa trên số liệu đúng.
- **Test:** draft 2 candidate; base 1 trả shell `*` học muộn; base 2 là route thật. Kỳ vọng sau xử lý: verdict `verified_alive` với `verified_base` = base 2, và `Sent` tăng đúng 1 probe (cộng canary của base 2 nếu chưa có).

### T3. `internal/testlint` tin `RLock()` và chưa bắt ghi vào phần tử map/slice *(Đã đóng ở Đợt 38)*

- **Hiện trạng:** `callsLock` coi `RLock` như khoá ghi ([handler_race_test.go:110](../internal/testlint/handler_race_test.go)). `capturedWrites` chỉ xét `*ast.Ident`, không xét `m[k] = v`, `s[i] = v`, `x.f = v`, `delete(m, k)`, `append` vào trường.
- **Dấu hiệu khi vướng:** một test chỉ fail với `-race` (hoặc chập chờn) trong khi lint vẫn pass, và handler của nó ghi vào map/slice/trường struct bị capture.
- **Xử lý (mở rộng lint, giữ không có false positive):**
  1. Chỉ tin `Lock()`, không tin `RLock()`, cho phép ghi.
  2. Xét thêm LHS dạng `IndexExpr`/`SelectorExpr` có gốc là identifier bị capture; xét thêm lời gọi `delete(<captured>, …)`.
  3. Bỏ qua kiểu đồng bộ sẵn (`sync.Map`, `atomic.*`, `chan` gửi/nhận), vì phép ghi qua method của chúng không phải `AssignStmt`.
  4. Chạy lint mới trên toàn repo, sửa các chỗ nó báo trong cùng commit (như E).
- **Test:** thêm `internal/testlint/testdata` với 4 file mẫu: map ghi không khoá (phải báo), map ghi trong `Lock` (không báo), `RLock` rồi ghi (phải báo), `atomic.Add` (không báo). Lint đọc thư mục mẫu bằng một test con riêng, không quét chung với repo.
