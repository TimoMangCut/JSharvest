# Đợt 38: Đóng tồn đọng 37.1 (`T1`, `T3`) & Tối ưu có đo đạc cho `archive` và `specProbePhase2`

**Ngày:** 2026-11-19 · **Nền mã nguồn:** `a0bd890` (sau Round 37.1) · **Trạng thái:** đã triển khai đầy đủ 6 bước.

**Nguyên tắc bất biến:** Zero Band-Aids — không cắt độ sâu BFS, không giảm độ phủ OpenAPI/OIDC ở origin root, không tăng tải mạng lên target hay vi phạm giới hạn nhịp của Internet Archive, không đổi `stateVersion` của `archive.json`, không mở lỗ hổng SSRF/OpSec/race, không đưa tên mục tiêu thật vào tài liệu/test.

| Hạng mục | Vùng | Mức / Mục tiêu | Tóm tắt |
|---|---|---|---|
| **T1** | `verify` | Nhỏ / Sạch schema | Xoá `r.VerifiedBase = ""` khi `rejudgeShells` hạ verdict từ `Alive` xuống `DeadOrFP`/`ClientRoute` |
| **T3** | `testlint` | Nhỏ / Chống race lọt | Bỏ `RLock()` khỏi `callsLock`; mở rộng `capturedWrites` bắt `*ast.IndexExpr`, `*ast.SelectorExpr`, `*ast.ParenExpr`, `*ast.StarExpr`, `delete()` + fixture `testdata` |
| **B1** | `archive` (đo đạc) | Cao / Nền ra quyết định | Log timing cấp `archive.Run` (`list/pages/fetch/history`) + 4 chặng của `history()` + harness đo offline `JSH_HISTORY_BENCH=<dir>` (0 mạng) |
| **A** | `archive` + `engine` | Cao / Tiết kiệm `~1m 45s – 1m 57s` | Stream subdomain mới từ `httpcrawl` qua channel vào Stage 1 (`ModeListOnly`) cho OTX/URLScan với hàng đợi fan-out độc lập; giữ nguyên delta Stage 2 |
| **C** | `httpcrawl` (`specProbe`) | Trung bình / Cắt probe SPA rác | Auto-brake theo **từng sub-path base** trong `specProbeWithScope` khi trả đúng SPA shell của origin + truyền `spaBraked` sang `plan.Services`; giữ nguyên origin root & bảo vệ OIDC sub-path |
| **B2** | `endpoints` | Tối ưu CPU/RAM | Singleflight theo SHA-256 + khoá trần `extractHeavySem` bên trong `endpoints.ExtractCached` (số đo B1 xác nhận `history()` warm chỉ mất `65–71 ms` trên 635 script nên không cần mở thêm async worker pool trong `archive`) |
| **D** | `docs` | Thấp | Cập nhật `docs/plan-38.md`, `docs/plan-37.1.md`, `docs/CURRENT.md`, `docs/rounds-history.md`, `docs/gd5-archive-design.md` |

> [!NOTE]
> **Các hạng mục cố ý KHÔNG đưa vào đợt này (Defer):**
> - **T2 (thử lại candidate 2 sau `rejudgeShells`):** Cực hiếm (chỉ xảy ra khi shell học muộn từ host khác `*`). Giữ defer theo [plan-37.1.md](plan-37.1.md).
> - **Không chạm `wbFilesGap` (`300ms`) hay `PageWorkers` mặc định:** Nhịp tải Memento chịu điều tiết AIMD của Internet Archive.
> - **Không cắt sớm `SpecPaths` trên origin root (`path == ""` hoặc `"/"`):** Bảo vệ recall trên reverse-proxy SPA.

---

## 1. T1 & T3 — Đóng tồn đọng sau Round 37.1

### T1. `verify`: Xoá `VerifiedBase` khi `rejudgeShells` hạ verdict
- Thêm `r.VerifiedBase = ""` cạnh `r.VerifiedMethod = ""` trong `rejudgeShells()` tại [verify.go](../internal/verify/verify.go).
- Test: `TestRound38RejudgeClearsVerifiedBase` trong [round38_test.go](../internal/verify/round38_test.go).

### T3. `internal/testlint`: Bỏ `RLock()`, mở rộng bắt ghi vào map/slice/struct/pointer
- `callsLock` tại [handler_race_test.go](../internal/testlint/handler_race_test.go) chỉ tin `.Lock()`.
- `rootIdent` lần qua `*ast.IndexExpr`, `*ast.SelectorExpr`, `*ast.ParenExpr`, `*ast.StarExpr` cho `AssignStmt`, `IncDecStmt`, và `delete(m, k)`.
- Bỏ qua thư mục `testdata` khi quét toàn repo; kiểm chứng bằng `TestHandlerLintFixtures` trên 4 mẫu trong `internal/testlint/testdata/`.

---

## 2. B1 — Đo tách chặng `archive` / `history()` & Kết quả thực nghiệm

- Bổ sung log `archive timings: list=%s pages=%s fetch=%s history=%s` và `history timings: scripts=%d endpoints=%d analyze=%s assemble=%s intel=%s classify=%s` tại [run.go](../internal/archive/run.go), cùng harness [history_bench_test.go](../internal/archive/history_bench_test.go) (`JSH_HISTORY_BENCH`).
- **Kết quả đo thực tế trên tập 635 script lịch sử (`254` endpoint):**
  - `COLD` (xoá `static/`, parse lại từ đầu): `1m12.025s` (`analyze=1m11.997s`, `assemble=20ms`, `intel=4ms`, `classify=4ms`).
  - `WARM-DISK` (giữ `static/` trên đĩa, xoá cache RAM): **`71ms`** (`analyze=43ms`).
  - `WARM-MEM` (giữ cả `static/` và `memResultCache` ngay sau `fetch()`): **`65ms`** (`analyze=36ms`).
- **Kết luận kỹ thuật:** `fetchOne` vốn đã gọi `ExtractCached` cho ~94% script ngay trong lúc chờ tải mạng Memento, nên `history()` thực tế chỉ tốn `< 0.1s` (phần đuôi ~88s trước `index.jsonl` thuộc về các capture `not_script`/`not_archived` cuối của `fetch()`). Vì vậy không cần mở thêm async worker pool cho 40 đoạn inline nhỏ ở `archive`, mà chỉ cần khoá chặt **Singleflight theo SHA-256 + `extractHeavySem`** ngay trong `endpoints.ExtractCached` (mục B2).

---

## 3. A — Streaming `ExtraHosts` (OTX/URLScan) ngay trong Stage 1

- Thêm `ArchiveStage1Stream` vào `engine.HTTPOptions` tại [http.go](../internal/engine/http.go): phát subdomain mới trong scope (`e.Response.Status > 0`) dưới khoá `extraMu` (`seenHosts` + `extraClosed`) ngay khi `httpcrawl` chạm tới, đóng kênh ngay sau khi `httpcrawl.Crawl` kết thúc (và trên mọi nhánh dừng sớm / `seedDead`).
- Trong [list.go](../internal/archive/list.go) và [urlscan.go](../internal/archive/urlscan.go): router fan-out đẩy vào hàng đợi độc lập `hostQueue` cho `otx` và `urlscan` (một nguồn chậm hoặc bị `ErrBlocked` gọi `drop()` dừng ngay mà không làm nghẽn nguồn kia hay chặn producer); debounce ghi `archive.json` bằng `saveMaybeLocked()` kèm `save()` cuối pha; giữ đọc `st.Scans` của domain gốc khi subdomain lẻ gặp lỗi thường.
- Stage 2 (`ModeResume`) giữ nguyên `prepare()` và chạy delta cho các host mới từ `intel.json`, `Escalate`, `SPABoot` chưa có trong `r.st.Extra`.
- Test: `TestRound38ExtraHostsStreamingFanoutAndResumeDelta`, `TestRound38ExtraHostsStreamingOTXBlockedMidStream` ([round38_test.go](../internal/archive/round38_test.go)) và `TestRound38HTTPStreamsDiscoveredHostsToStage1AndClosesOnSeedDead` ([round38_test.go](../internal/engine/round38_test.go)).

---

## 4. C — Guarded Sub-Path SPA Brake trong `specProbePhase2`

- Trong `specProbeWithScope` ([crawl.go](../internal/httpcrawl/crawl.go)):
  1. Chỉ bật khi `postPages == true` và `base` có sub-path khác `/` trên origin đã xác nhận `cr.spa[orig] && cr.prints[orig] != ""`; **origin root luôn thử đủ 100% `SpecPaths`**.
  2. Chỉ đếm các request **thực gửi** (`sent == true`, không bị `claim` bỏ qua hay breaker giữ).
  3. Khi 3 probe liên tiếp trả `200` khớp đúng `cr.prints[orig]`, thử nốt `/v3/api-docs` (nếu chưa thử) và bảo vệ `/.well-known/openid-configuration` cho các đường dẫn IdP (`auth`, `realms`, `oauth`, `oauth2`, `oidc`, `sso`, `identity`).
  4. Ghi nhận `spaBraked[base]` trong `specProbePhase2` để nhánh `plan.Services` không bắn bồi lại `/v2/api-docs` và `/service/v3/api-docs` trên cùng prefix vừa phanh.
- Test: 4 kịch bản trong [round38_test.go](../internal/httpcrawl/round38_test.go).

---

## 5. B2 — Singleflight SHA-256 & `extractHeavySem` trong `endpoints.ExtractCached`

- Bổ sung bảng `extractInflight` (singleflight theo SHA-256) và semaphore `extractHeavySem` (`max(2, min(4, GOMAXPROCS/2))`) cho `ExtractCached` tại [endpoints.go](../internal/endpoints/endpoints.go), ngăn parse AST trùng khi nhiều worker chạm cùng một bundle và chặn vọt đỉnh RAM trên các script `>= 320 KiB`.
- Test: `TestRound38ExtractCachedSingleflight` ([round38_test.go](../internal/endpoints/round38_test.go)); `perfgate`: `2000 scripts -> 1.62s, peak RSS 352.1 MB`.
