# Đánh giá tổng hợp: Kế hoạch tăng tốc JSharvest (6 giải pháp) và hai bản đánh giá ngoài

Ngày: 2026-11-19 · Mã đối chiếu: `2e5c5fc` (github/main) · Không sửa mã trong đợt này.

Tài liệu gộp: (a) bản kế hoạch "6 giải pháp kiến trúc tăng tốc, bảo toàn 100% output"; (b) Đánh giá 1 và Đánh giá 2 (bản ngoài); (c) đánh giá của phiên này, gồm đối chiếu mã, thí nghiệm cục bộ, dữ liệu output thật trong `output/` và nguồn bên ngoài về giới hạn tải của Internet Archive / Common Crawl. Mọi khẳng định của hai bản ngoài đã được kiểm lại; kết quả ở mục 3–4.

---

## 0. Kết luận nhanh

1. **Chẩn đoán vị trí nút thắt của kế hoạch phần lớn đúng** (I/O, khoá theo host, tuần tự liên pha), nhưng **ba khẳng định cốt lõi sai** khi đối chiếu thực tế:
   - **"0% rủi ro output" cho P1 (verify) là sai, đã chứng minh bằng test:** bỏ tuần tự theo host làm một trang chặn HTML của WAF bị báo `verified_alive` (mục 2.1).
   - **Mục tiêu tổng 10–13,5 phút (kế hoạch) và 12–16 phút (Đánh giá 2) không khả thi khi liệt kê Wayback đầy đủ.** Giới hạn cứng của CDX khoảng 30 req/phút, nên 1.314 shard cần **≥ 44 phút** chỉ riêng phần liệt kê (mục 2.3, 6).
   - **Nút thắt chính của httpcrawl không phải `q.Peek()`.** Nguyên nhân là `activeWorkers` chỉ được trả khi commit `win[0]` theo thứ tự. Thí nghiệm: 12 link chết làm crawl tăng từ 8,3 s lên 122 s; vá riêng điểm này còn 65 s (mục 2.2).
2. **P1 chỉ có lợi khi người dùng nâng `-rate` lên trên khoảng 1/RTT.** Ở mặc định `-rate 2` thì lợi bằng 0: mọi bản verify thật trên máy đều chạy đúng 2,01 req/s.
3. **Việc đáng làm nhất là P3 phần "chạy tiếp khi một nguồn bị chặn"**, đi kèm **hạ nhịp Wayback CDX về ≤ 24 req/phút**. Hiện jsharvest gửi 75 req/phút, gấp khoảng 2,5 lần giới hạn cứng, và đó là nguyên nhân bị 503 sau khoảng 2 phút.
4. Hai bản đánh giá ngoài bổ sung đúng nhiều bẫy race (gate, `subCanary`, `canaryOptions`) và bẫy vòng đời (tắt prefetch ở Stage 1, barrier sau Escalate/SPABoot, hủy khi `seedDead`). Nhưng mỗi bản có vài khẳng định sai so với mã (bảng ở mục 3–4), và **Đánh giá 1 khuyến nghị hạ `Wait` của Wayback từ 60 s xuống 10–15 s, ngược với hướng dẫn của Internet Archive.**

---

## 1. Phương pháp và giới hạn

| Nguồn | Nội dung |
|---|---|
| Mã nguồn | Đối chiếu từng dòng được trích dẫn tại `2e5c5fc` |
| Thí nghiệm cục bộ | Test tạm (`httptest`, latency giả lập), vá thử rồi hoàn tác; cây git sạch sau thí nghiệm |
| Dữ liệu thật | 8 bộ output trong `output/` (target A, target B, target C, target C (cổng phụ), target D, bản `_live_25e_max`), chỉ đọc, không gửi request nào tới target |
| Nguồn ngoài | Blog Internet Archive 2026-09-15, thư viện `wayback` (release notes + mã nguồn), Common Crawl blog/status/mailing list |

**Giới hạn:** dữ liệu phiên quét R35 (1h20m, hai API gateway chính, 783 host) **không có trên máy này**. Các con số đo của kế hoạch (273 ms, 165 s tải map, 10,25 s × 19, 7 phút im lặng ở Wayback) chưa được kiểm trực tiếp; chỉ kiểm được cơ chế gây ra chúng. Số "~30–35 phút hiện tại" của kế hoạch là dự phóng, chưa đo trên `2e5c5fc`.

---

## 2. Kết quả thực nghiệm

### 2.1. verify: thông lượng theo số host, và hệ quả khi bỏ khoá host

Server `httptest` có latency 273 ms; `-rate 10` (`Rate: 100ms`), `-concurrency 8`; 96 draft, 6 prefix.

| Số host | Request | Thời gian | req/s | In-flight đỉnh |
|---|---|---|---|---|
| 1 | 102 | 28,1 s | **3,63** | 1 |
| 2 | 108 | 15,0 s | 7,19 | 2 |
| 8 | 144 | 14,7 s | 9,81 | 8 |

Kết quả xác nhận định luật Little mà kế hoạch nêu: với một host thì trần là 1/RTT. Nhưng nút thắt này **chỉ xuất hiện khi `-rate` > 1/RTT**. Mặc định `-rate 2` (`cmd/jsharvest/authz.go:45`, dùng chung cho verify) nằm dưới 3,6 req/s, nên ở mặc định P1 không có lợi. Dữ liệu thật trên máy: target B 380 request và target D 266 request đều đúng 2,01 req/s (cả hai là dry-run); target C (cổng phụ) 1,99 req/s.

**Vá thử bỏ khoá host** (`lockHost` thành no-op, chia hàng đợi một host cho 4 worker), chạy `go test ./internal/verify` 3 lần, kết quả lặp lại cả 3 lần:

- `TestVerifyConcurrentHosts`: fail, 2–3 request cùng lúc trên một host (đúng như dự kiến).
- `TestVerifyRejectsF5AndSubPathAdminWAFHTMLShells`: **fail**. Endpoint `0003` bị báo `verified_alive` thay vì `dead_or_fp` ([round34_test.go:95](../internal/verify/round34_test.go)). Đây chính là **false positive mà verify được thiết kế để chặn**: một trang chặn HTML của WAF trên `/admin` bị nhận là route sống.

Kết luận: P1 làm đổi verdict nếu thiếu singleflight cho cả canary, sub-canary và OPTIONS của canary, cộng với thứ tự học HTML shell.

### 2.2. httpcrawl: nghẽn đầu cửa sổ (head-of-line)

Seed có 80 link trang (RTT 120 ms, mỗi trang 1 script, `Rate: 20`), cộng thêm N link "chết" (server treo 10 s rồi trả 404). Mặc định `pageWorkers = 4`, `maxWin = 8`.

| Kịch bản | Thời gian |
|---|---|
| 0 link chết | 8,3 s |
| 4 link chết, cùng origin | 47,3 s |
| 12 link chết, cùng origin | 122,0 s |
| 12 link chết, **12 origin khác nhau** | 122,1 s |
| 12 khác origin + **vá: trả `activeWorkers` khi tải xong** (commit vẫn theo thứ tự) | **65,3 s** |
| Như trên + `maxWin` 8 → 32 | 35,5 s |

Diễn giải:

- Mỗi link chết cộng gần đủ 10 s, tức bị **tuần tự hoá hoàn toàn**. Kết quả không đổi khi các link chết nằm ở các origin khác nhau. Vậy nguyên nhân **không phải** khoá theo origin (`prints[orig]`) hay `q.Peek()`.
- Nguyên nhân chính nằm ở `activeWorkers--` ([crawl.go:1838–1846](../internal/httpcrawl/crawl.go)). Bộ đếm này chỉ giảm khi `win[0]` được commit, nên một trang chậm ở đầu cửa sổ giữ toàn bộ slot. Vá điểm này giảm 47%.
- Phần còn lại chủ yếu do giới hạn `maxWin` và 4 page worker: 12 × 10 s / 4 ≈ 30 s.
- Với bản vá thử, các test tính xác định `TestPipelined*`, `TestStopEndsWorkInFlight`, `TestAssetChallengeNamesItsPage` vẫn pass. Chưa chạy `TestParallelPagesDeterministicOrder` (round35) và các gate.

### 2.3. archive: giới hạn tải của Internet Archive và Common Crawl

| Thông số | Giá trị | Nguồn |
|---|---|---|
| Giới hạn cứng Wayback CDX (search/timemap) | ~**30 req/phút** | `wayback` 0.5.1 (2026-06-19): mặc định hạ còn 24/phút "để khớp giới hạn cứng"; mã nguồn ghi IA yêu cầu đặt mặc định ở 80% giới hạn cứng |
| Giới hạn chung Wayback (memento) | ~600 req/phút | Mã nguồn `wayback`, `DEFAULT_MEMENTO_RATE_LIMIT` |
| Xử lý 429 | Chờ 60 s (hoặc theo `Retry-After`); từ 0.5.0 không tự retry 429 để tránh bị chặn IP | `wayback` release notes |
| Chính sách 2026 | IA bổ sung lớp bảo vệ chống lưu lượng tự động khối lượng lớn | Blog IA 2026-09-15 |
| jsharvest `wbIndexGap` | 800 ms = **75 req/phút** (~2,5× giới hạn cứng) | `cmd/jsharvest/archive.go:183` |
| jsharvest `wbFilesGap` | 300 ms = 200 req/phút (dưới 600) | `cmd/jsharvest/archive.go:187` |
| Common Crawl index | Có rate limit "strict", hay trả 5xx; CC khuyến nghị dùng Columnar Index cho tải nặng | Blog + status Common Crawl |
| Dữ liệu thật trên máy | CommonCrawl index trả **504 ở 4/4** run archive | `output/*/archive/archive.json` |

Hệ quả:

- 1.314 shard × 2 s ≈ **43,8 phút** (ở 30/phút), hoặc ≈ **54,8 phút** (ở 24/phút) **chỉ riêng liệt kê Wayback**.
- Hiện tượng "503 sau khoảng 2 phút / 128 shard" khớp với việc vượt giới hạn: khoảng 64 req/phút thực tế so với giới hạn 30.
- `Budget.Gap` đã giãn mọi lượt bắt đầu request ([client.go:39](../internal/archive/client.go)). Vì vậy 16 worker không "bắn liên thanh" như kế hoạch mô tả; vấn đề nằm ở **giá trị gap quá nhỏ**, không phải số worker.

### 2.4. Dữ liệu thật trên máy liên quan P4

- 8 bộ `pages.jsonl` (lớn nhất 2.316 và 2.095 trang): **0** trang lỗi dial timeout.
- 8 bộ `requests.jsonl` (lớn nhất 938 `.map`): **0** file `.map` cùng tên bị tải trên nhiều host.

Vậy lợi ích của P4 phụ thuộc loại target (nhiều subdomain dùng chung CMS, cổng bị firewall chặn). Với các target hiện có, lợi bằng 0.

---

## 3. Kiểm lại Đánh giá 1

| # | Khẳng định | Kết quả | Bằng chứng / ghi chú |
|---|---|---|---|
| 1.1 | Chẩn đoán "khớp 100% từng dòng", mọi nút thắt "chính xác tuyệt đối" | **Sai một phần** | HOL do `activeWorkers`, không phải `q.Peek()` (2.2); P1 không có lợi ở `-rate 2` (2.1); Wayback bị chặn do gap, không phải số worker (2.3) |
| 1.2 | `verify.go:595` `lockHost` + `byHost` 1 goroutine/host | Đúng | `verify.go:595`, `1171–1211` |
| 1.3 | `netsafe.go:170–252` resolve + dial lại "mỗi URL" | Đúng một phần | Resolve/dial theo **kết nối mới**; keep-alive dùng lại kết nối. Với host chết thì không có kết nối để dùng lại, nên thực tế mỗi URL đều dial lại |
| 1.4 | Archive khởi động đọc `requests.jsonl` **4 lần** | **Sai: 3 lần** | `CrawlHosts` ×2 (`archive.go:221`, `232`) + `observedUA` (`archive.go:250`). `loadCurrent` đọc `index.jsonl`, không đọc `requests.jsonl` (`history.go:43–59`). Lưu ý thêm: `CrawlHosts` quét `requests.jsonl` của **mọi host/role trong thư mục output** (`hosts.go:38`) |
| B1 | `noteGate` ghi `g.*`/`g.prefixes` ngoài `v.mu` | Đúng | `verify.go:371–393`; chỉ an toàn nhờ `lockHost` |
| B2 | `subCanary` chèn `v.canaries` rồi ghi `c.Answer` ngoài khoá; `canaryOptions` ghi `c.Options` lười | Đúng | `verify.go:980–1006`, `1032–1043` |
| B3 | Thứ tự học `htmlShells` giữa các prefix | Đúng, **đã tái hiện** | Test round34 fail khi bỏ khoá (2.1) |
| B4 | Phải tắt prefetch ở Stage 1 (live-check vào target, `r.cur` rỗng, tranh memCache) | Đúng | `list.go:172–188`, `fetch.go:27–39`, `fetch.go:461`, `fetch.go:478` (`ExtractCached`) |
| B4b | Barrier Stage 2 sau Escalate và SPABoot | Đúng | `http.go:286–320` (cả hai bước đều `writeEndpoints` lại) |
| B5 | Không chạy Stage 1 khi `seedDead` | Đúng | `http.go:334–337` |
| B6 | `cancel()` chéo giữa các nguồn khi Wayback `ErrBlocked` | Đúng | `list.go:57–63` |
| B6b | AIMD có `cooldownUntil`, trần `maxGap` 10 s | Hướng đúng, **thông số sai** | Gap gốc phải ≥ 2–2,5 s (≤ 24–30/phút); trần 10 s là hợp lý |
| B6c | **Hạ `wbIndexClient.Wait` từ 60 s xuống 10–15 s** | **Sai hướng** | IA/`wayback` dùng 60 s cho 429 và khuyến cáo không retry 429 dồn dập để tránh bị chặn IP. Dòng trích là `archive.go:158`, không phải 150–160 như ghi |
| B7 | Chỉ bỏ tải trước theo `standaloneVendorFileRe` là "an toàn 100%" | **Gần đúng, không phải 100%** | `explicitAppSourcePath` vẫn áp dụng cho cả `libScript` (`sourcemap.go:198`), nên một bản build ckeditor/tinymce tuỳ biến có file ở `resources/js/` hoặc `frontend/src/` sẽ mất. Map thô cũng không còn được lưu `maps/<sha>.map` (`engine/http.go:185–187`) |
| B7b | Singleflight dedup theo (sha256, mapRef), lỗi tạm thời không khoá cứng | Đúng, hợp lý | Cần thêm: replay `store.Add` cho từng `ScriptURL` (xem Đánh giá 2, P4.2) |
| B8 | Đếm lỗi theo lần hoàn tất `dialAll` (A + AAAA = 1 strike); First-Dial Gate | Đúng, hợp lý | `netsafe.go:228–252` thử lần lượt từng IP. Nhưng "treo cả **8** pageWorkers" sai: mặc định `pageWorkers = max(tabs, 4) = 4` (`main.go:515`) |
| B8b | Đặt breaker trong `netsafe.Dialer` | **Không nên** | `netsafe` dùng chung cho `replay.Sender` (đã có pin IP `send.go:311–338` và ngưỡng `hs.errs >= 5` ở `send.go:674`), AIA và archive. Nên đặt ở httpcrawl hoặc opt-in (như Đánh giá 2) |
| B9 | `TakeMatching`: quét `q.h[1..maxScan]` rồi chọn min theo `Less` và `heap.Remove` | **Sai thứ tự** | Trong binary heap, 16 ô mảng đầu chỉ chắc chắn chứa 4 phần tử nhỏ nhất (phần tử nhỏ thứ k nằm ở độ sâu ≤ k−1). Phần tử đủ điều kiện có ưu tiên cao hơn có thể nằm ngoài cửa sổ. Cách đúng là pop/push (Đánh giá 2) |
| B9b | Gom `specProbePhase2` theo `GatewayBase` là "bảo toàn 100%" | Đúng với brake D3 | Nhưng hai `GatewayBase` cùng một host sẽ chạy song song, làm tăng tải lên host đó. Nên gom theo **host** (bên trong tuần tự theo gateway) |
| B9c | `pickUA` ưu tiên UA trình duyệt hơn UA engine | Đúng | `verify.go:194–210` (`uaCounts{browser, engine}`); `run.json` `user_agent` ở `crawl.go:148` |
| R | Đợt A "rủi ro thấp, ăn ~70% độ lợi" gồm P1 với `maxHostInFlight = min(4, Concurrency)` mặc định | **Không đồng ý** | P1 không có lợi ở `-rate` mặc định; per-host song song làm tải lên một gateway tăng ~2,7×, dễ dính WAF; đã thấy false positive (2.1) |

## 4. Kiểm lại Đánh giá 2

| # | Khẳng định | Kết quả | Bằng chứng / ghi chú |
|---|---|---|---|
| 2.0 | Chẩn đoán "đánh trúng 100% nút thắt vật lý" | **Sai một phần** | Như 1.1 |
| 2.0b | Tiết kiệm của P2 và P3 không cộng tuyến tính; chặn dưới bởi `max(T_crawl, T_list) + T_stage2` | Đúng | Khớp 2.3 |
| 2.0c | "Rút xuống ~12–16 phút là hoàn toàn khả thi" | **Sai với target R35** | Riêng liệt kê Wayback đã ≥ 44 phút (2.3), trừ khi chấp nhận liệt kê dở dang qua nhiều run |
| P1 | `ForceAttemptHTTP2`, `MaxIdleConnsPerHost = max(2, Concurrency)`, trần `s.next`/`s.slots` | Đúng | `send.go:170–180`, `596–630` |
| P1 | "Giá trị rất cao, nên làm đầu tiên" | **Không đồng ý** | Chỉ có lợi khi `-rate` > 1/RTT (2.1) |
| P1.1–2 | Race trên gate; thiếu singleflight cho `subCanary`/`canaryOptions` | Đúng | Như B1, B2 |
| P1.3 | Không giữ semaphore host A khi chờ host B (draft nhiều host) | Đúng, hợp lý | Hiện `lockHost` khoá theo từng probe, không lồng (thiết kế 25K) |
| P1.4 | Bắn lố tối đa N−1 request khi gặp 429 hoặc gate; tự hạ về 1 sau 429 đầu tiên | Đúng, hợp lý | |
| P2.1–3 | Tắt prefetch ở Stage 1; barrier sau Escalate/SPABoot/`writeEndpoints`; hủy khi `seedDead`/SIGINT; không chạy khi chỉ có `Fallback` | Đúng | `http.go:286–343`. Archive trong crawl gọi `archiveRun` → `lockDirs("archive")` (`archive.go:105`), nên phải chờ goroutine Stage 1 kết thúc trước khi trả |
| P2.4 | Chồng đỉnh RAM: `seenURLs` + memCache + `frontier.Queue` (500k) | Đúng | `queue.go:114` (`maxQueuedOrSeenPages = 500000`); memCache cấu hình qua `SetMemCacheMB` (`memcache.go:55–63`) |
| P2.5 | Làm P2 sau P3 | Đúng | |
| P3 | `PagesDone map[int]bool`, duyệt stride không cần đổi `stateVersion` | Đúng | `run.go:106` |
| P3.1 | Cô lập `ErrBlocked` theo từng nguồn | Đúng | `list.go:57–63` |
| P3.2 | `main.go` chỉ ghi `error` vào `run.json`, mất summary; test cũ assert `ErrBlocked` | Đúng | `main.go:548–553`; `archive_test.go`, `round34_1_test.go`, `round34_2_test.go` |
| P3.3 | `r.pages()` không idempotent khi resume, cần đánh dấu done | **Sai** | Đã có `isDone`/`markDone` với khoá `html:` và `read:` (`pages.go:226–244`). Điểm **bị bỏ sót**: `pages()` cũng trả `ErrBlocked` khi Memento bị chặn (`pages.go:234`), nên `fetch()` bị bỏ qua. Cũng phải cô lập lỗi ở đây |
| P3.4 | `cooldownUntil` dùng chung; nhân tham số theo `JSHARVEST_ARCHIVE_SCALE` | Đúng | `archive.go:117`; `archive-check.sh:45` |
| P4.1 | Chỉ chặn trước theo `standaloneVendorFileRe`, "không bao giờ bỏ sót app bundle lai" | **Gần đúng** | Như B7: ngoại lệ `explicitAppSourcePath` vẫn áp dụng cho tên file thư viện |
| P4.2 | Dedup map phải replay `store.Add` theo `ScriptURL` của sub2 để không mất quy thuộc origin | Đúng, quan trọng | Callback ghi `Page: m.ScriptURL` (`engine/http.go:195–200`) |
| P4.3 | Breaker/DNS cache opt-in cho httpcrawl, không cache khi `d.Resolver != nil`, kiểm lại `PrivateAddr`; chỉ tính `OpError{Op:"dial"}`; half-open | Đúng, hợp lý | `send.go:311` dùng `Resolver` riêng để pin |
| P5 | Sau 35.1 đã bỏ `sectionKeyOf` | Đúng | `db98e0d` |
| P5.1 | `TakeMatching` pop/push heap, cập nhật `q.taken`, `q.bandFloor` | Đúng | `queue.go:303–322`. Lưu ý: TakeMatching **không** giải quyết nguyên nhân chính (2.2) |
| P5.1b | Cần kiểm `TestParallelPagesDeterministicOrder` | Đúng | `round35_test.go:18` |
| P5.2 | Gom theo `GatewayBase`; budget `MaxPhase2SpecProbes` bị cạnh tranh | Đúng | `crawl.go:1449–1451`. Bổ sung: nên gom theo host (như B9b) |
| P6 | `CrawlHosts` gọi 2 lần + `observedUA` = 3 lượt đọc | Đúng | Như 1.4 |
| P6.1 | `run.json` `user_agent` chỉ có ở mode HTTP; gộp một pass | Đúng | |
| P6.2 | `ClearMemCache()` khi `store.Len() > 1000` trước `classifyCtx` | Đúng | `run.go:419–420` |

---

## 5. Những điểm cả ba bản đánh giá đều bỏ sót hoặc sai

Bao gồm cả bản đánh giá đầu tiên của phiên này (chỉ đọc mã).

1. **Giới hạn cứng ~30 req/phút của Wayback CDX.** Không bản nào nêu. Đây là yếu tố quyết định tổng thời gian archive và làm thay đổi mức ưu tiên:
   - Duyệt shard theo stride / bit-reversal **có giá trị cao hơn** đánh giá ban đầu, vì liệt kê domain lớn là việc kéo qua nhiều run; một lần liệt kê dở dang cần phủ đều không gian SURT.
   - Giảm worker CDX từ 16 xuống 4 không giải quyết được gì nếu gap vẫn 800 ms.
2. **Nguyên nhân thật của HOL trong httpcrawl** là thời điểm trả `activeWorkers`, không phải `q.Peek()` (2.2). `TakeMatching` (P5) chỉ là cải thiện phụ.
3. **`-rate` mặc định = 2** làm P1 không có lợi ở cấu hình mặc định.
4. **`pages()` cũng thoát vì `ErrBlocked`** (P3).
5. **Lợi ích P4 phụ thuộc target**: dữ liệu thật hiện có cho thấy lợi bằng 0.
6. **Common Crawl index thường xuyên 5xx** (4/4 run). Chạy tiếp khi một nguồn lỗi là cần thiết, không chỉ cho Wayback.

---

## 6. Giới hạn dưới thời gian và kỳ vọng thực tế (target R35)

| Pha | Giới hạn dưới | Ghi chú |
|---|---|---|
| Wayback CDX listing | 1.314 × 2–2,5 s ≈ **44–55 phút** | Không thể ẩn sau crawl (~11–13 phút); chỉ ẩn được phần trùng thời gian |
| verify | ~1.900 req ÷ `-rate` | 10 req/s → ~3,2 phút; 2 req/s (mặc định) → ~16 phút bất kể P1 |
| httpcrawl | Phụ thuộc số link chết / chậm | Sửa `activeWorkers` + breaker gỡ phần lớn thời gian treo |

Kỳ vọng hợp lý:

- **crawl + verify** giảm rõ rệt nhờ P5 (đúng nguyên nhân), breaker của P4 và P1 khi người dùng chủ động nâng `-rate`.
- **archive** cho domain có hàng nghìn shard trở thành **việc nền nhiều run**: mỗi run liệt kê một phần (stride), luôn chạy tiếp pages/fetch/history trên phần đã có, resume qua `PagesDone`.
- Con số tổng "10–13,5 phút" hoặc "12–16 phút" chỉ đạt được nếu **không** đòi liệt kê Wayback đầy đủ trong một run.

---

## 7. Đánh giá hợp nhất từng giải pháp

| Giải pháp | Giữ / sửa / bỏ | Thiết kế đã hợp nhất |
|---|---|---|
| **P3** archive | **Giữ, làm đầu tiên** | (a) Cô lập lỗi theo nguồn: chỉ `ctx.Err()` mới hủy toàn bộ. (b) `pages()`/`fetch()` chạy tiếp khi Memento bị chặn, chỉ tắt nhánh Memento, giữ live-check và CC WARC. (c) `wbIndexGap` ≥ 2,5 s (≤ 24/phút), AIMD tăng gap khi gặp 429/503 với `cooldownUntil` dùng chung và trần 10 s; **giữ `Wait` 60 s / theo `Retry-After`**. (d) Tạm dừng prefetch khi index bị throttle. (e) Duyệt shard stride. (f) `main.go` giữ summary khi partial. (g) Cập nhật các test đang assert `ErrBlocked`. (h) Nhân tham số theo `JSHARVEST_ARCHIVE_SCALE` |
| **P5** httpcrawl dispatch | **Sửa trọng tâm** | (a) Trả `activeWorkers` khi tải xong, giữ commit theo thứ tự (đã đo: −47%). (b) Cân nhắc nới `maxWin` có giới hạn bộ nhớ. (c) `TakeMatching` pop/push heap, cùng Depth, là phụ. (d) `specProbePhase2` song song **theo host**, bên trong tuần tự theo `GatewayBase` |
| **P4** map + breaker | **Giữ phần an toàn** | (a) Dedup map singleflight theo (sha256 script, ref tương đối), replay `store.Add` cho mọi `ScriptURL`, chỉ dedup khi lần trước parse thành công. (b) Bỏ tải trước theo `standaloneVendorFileRe` **chỉ khi chấp nhận** mất ngoại lệ `explicitAppSourcePath` và map thô (hoặc làm thành cờ). (c) Breaker ở httpcrawl theo host:port: một strike cho mỗi `dialAll`, chỉ tính `OpError{Op:"dial"}`; ngưỡng 2 cho refused/NXDOMAIN, 3 cho timeout; half-open 3–5 phút; First-Dial Gate; ghi lý do vào `pages.jsonl`. (d) DNS cache nếu có: opt-in, không dùng khi có `Resolver`, luôn kiểm lại `PrivateAddr` |
| **P2** gối đầu archive | **Giữ, sau P3** | Stage 1 chỉ liệt kê index (`prefetchCh = nil`, 0 request tới target); khởi động sau khi seed sống; hủy khi `seedDead`/`ctx`; không chạy khi chỉ có `Fallback`; barrier sau Escalate + SPABoot + `writeEndpoints`; đợi goroutine Stage 1 trước khi nhả khoá; đo RSS đỉnh. Lợi = min(T_crawl, T_list) |
| **P1** verify per-host | **Đổi thành cờ tùy chọn** | `-host-inflight N` mặc định 1. Khi N > 1: singleflight `ready` cho canary, sub-canary và OPTIONS của canary (`sync.Once`); toàn bộ gate dưới `v.mu`; hàng đợi chung theo `probeOrder`; semaphore lấy/trả trong `probe` theo từng target; tự hạ về 1 sau 429 đầu tiên. Bắt buộc pass `TestVerifyRejectsF5AndSubPathAdminWAFHTMLShells` khi N > 1 |
| **P6** I/O | **Phần nhỏ** | Gộp `CrawlHosts` ×2 + `observedUA` thành một pass (3 → 1). Không thay `pickUA` bằng `run.json` trừ khi chỉ có HTTP. memCache chỉ làm fast-path |

---

## 8. Lộ trình khuyến nghị

0. **Đo baseline trên `2e5c5fc`** với target đã được phép (hỏi trước mỗi run trên target thật). Nếu có thể, chép log/output R35 về máy để kiểm các con số 273 ms, 165 s, 10,25 s × 19.
1. **Đợt A: archive reliability (P3).** Gate: `archive-check.sh`, `pipeline-check.sh`, `proxy-check.sh`, `go test -race ./internal/archive/...`.
2. **Đợt B: httpcrawl (P5a + P4 an toàn + P5d).** Gate: `pipeline-check.sh`, `waf-check.sh`, `frontier-check.sh`, `frontier-tabs-check.sh`, `TestParallelPagesDeterministicOrder`, `go test -race ./internal/httpcrawl/...`.
3. **Đợt C: P2 gối đầu archive.** Gate: `archive-check.sh`, `pipeline-check.sh`, đo RSS đỉnh trên domain nhiều shard.
4. **Đợt D: P1 dạng cờ tùy chọn + P6.** Gate: `verify-check.sh`, `crosscheck-check.sh`, `replay-check.sh`, `go test -race ./internal/verify/...`.

Sau mỗi đợt: `go test -race ./internal/...` và `bin/testbed perfgate` (2.000 script ≤ 15 s, RSS ≤ 500 MB).

---

## 9. Phụ lục: tái hiện thí nghiệm

Các test tạm đã được chuyển ra khỏi repo (thư mục scratchpad của phiên). Mô tả để tái hiện:

- **verify** (`internal/verify`, test tạm): `httptest` sleep 273 ms; `replay.NewSender{AllowPrivate, Max: 5000, Concurrency: 8, Rate: 100ms}`; `Run(... Concurrency: 8)`; 96 endpoint chia đều 1/2/8 host.
- **Bỏ khoá host:** trong `byHost` đổi khoá hàng đợi thành `hostOf(t)+"#"+i%4`; `lockHost` trả hàm rỗng; chạy `go test -count=1 ./internal/verify`.
- **HOL** (`internal/httpcrawl`, test tạm): seed 80 link `/pN` + N link tới server treo 10 s; `Crawl(Options{Depth: 1, Rate: 20, MaxPages: 500})`.
- **Vá `activeWorkers`:** kênh `freed` được báo khi `fetchPage` xong; giảm `activeWorkers` khi nhận từ kênh; `originInFlight` vẫn giảm lúc commit.

---

## 10. Nguồn

- [An update on Wayback Machine access, Internet Archive, 2026-09-15](https://blog.archive.org/2026/09/15/an-update-on-wayback-machine-access/)
- [wayback: release history](https://wayback.readthedocs.io/en/latest/release-history.html)
- [wayback: `_client.py`](https://wayback.readthedocs.io/en/latest/_modules/wayback/_client.html)
- [edgi-govdata-archiving/wayback issue #153](https://githubrp.bychv-a.workers.dev/edgi-govdata-archiving/wayback/issues/153)
- [Ciro Santilli: Wayback Machine rate limit](https://cirosantilli.com/wayback-machine-rate-limit)
- [Common Crawl blog: build directly on Common Crawl from the browser](https://commoncrawl.org/blog/you-can-now-build-directly-on-common-crawl-from-the-browser)
- [Common Crawl mailing list: Having problems with the index](https://groups.google.com/g/common-crawl/c/cwtFIB5-7Hc)
- [Common Crawl status](https://status.commoncrawl.org/)
- [Brightdata: Internet Archive vs Common Crawl](https://brightdata.com/blog/ai/internet-archive-vs-common-crawl-vs-web-archive)
