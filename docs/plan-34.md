# Đợt 34 — Điều khiển Độ lợi Thông tin Biên (`ΔInformation`), Streaming Archive DAG, Bộ nhớ Đệm RAM & Độ chính xác Verify

Tài liệu thiết kế và kết luận kỹ thuật cho **Đợt 34 (`Round 34`)**, tập trung giải quyết triệt để độ trễ trên các hệ thống lớn đa subdomain (CMS/SSR nhiều trang lặp mẫu và kho lịch sử hàng triệu bản ghi) thông qua kiến trúc điều khiển theo độ lợi thông tin, chồng pha luồng dữ liệu, đánh đổi RAM có kiểm soát lấy tốc độ I/O + mạng, lập lịch công bằng đa tầng và hiệu chuẩn sâu `verify`.

---

## 1. Năm Trụ Cột Kiến Trúc & Tối Ưu Tốc Độ / Bộ Nhớ

### 1.1. Marginal Information-Gain Controller (`ΔInformation`)
1. **Tầng HTTP Crawl (`internal/httpcrawl/skeleton.go`, `crawl.go`):**
   - **Prefix Trie có ngưỡng Fan-out (`K = 8`):** chuẩn hoá tức thì các phân đoạn động rõ ràng (số nguyên, UUID, ngày ISO, chuỗi hex/alnum dài `>= 16` ký tự) thành `{id}`; chỉ gộp phân đoạn chữ/slug dưới cùng nút cha thành `{slug}` sau khi quan sát thấy `>= 8` giá trị con khác nhau (bảo vệ tuyệt đối các tab tính năng tĩnh như `/account/billing`, `/account/api-keys`), kết hợp tập khoá query đã sắp xếp (`?page&sort`).
   - **Đo `ΔInformation` đa chiều cho cả SPA lẫn SSR/MPA:** một trang HTML đóng góp thông tin mới khi mang lại ít nhất một script ngoài mới, chữ ký ngữ nghĩa AST inline mới (đã chuẩn hoá skeleton đường dẫn để không bị nhiễu bởi biến trạng thái URL hiện tại của SSR), biểu mẫu `<form>` mới, hoặc khung liên kết con mới. Chỉ các skeleton động/phân trang mới có thể bão hoà (`template-saturated` sau `>= 6` lượt thăm và `5` lượt liên tiếp `ΔInfo == 0`), đồng thời hoàn trả slot `-max-pages` (`Queue.Refund`).
2. **Tầng Archive (`internal/store/canonical.go`, `internal/archive/family.go`):**
   - **`CanonicalKey` v2:** nhận diện thêm các họ bundle CMS/bundler đổi mã băm phổ biến (`js_<hash>.js`, `autoptimize_<hash>.js`, tên tệp thuần hex `16..64` ký tự, `eael-<id>.min.js`, dấu phân tách `_`) trong khi giữ nguyên từ vựng ngữ nghĩa thông thường.
   - **Coarse-Stride (`8` mốc) + Binary Zoom-In theo `SemanticAPISig`:** các họ file nhỏ (`<= 8` phiên bản) luôn tải đầy đủ 100%; các họ lớn (`> 8` phiên bản) lấy mẫu lưới thô `8` mốc theo trục thời gian, trích xuất AST ngay trên RAM để tính chữ ký ngữ nghĩa `SemanticAPISig`. Khoảng giữa hai mốc có cùng `SemanticAPISig` được cắt tỉa ngay (`Skipped["family unchanged"]`), còn khoảng có thay đổi được chia đôi nhị phân đệ quy để bắt trọn cả các endpoint chỉ xuất hiện tạm thời ở giữa lịch sử.

### 1.2. Streaming Archive Pipeline & Đánh Đổi RAM Lấy Tốc Độ (`-mem-cache-mb`)
1. **Xoá bỏ `html.jsonl` bằng `HTMLTop` Bounded Pool trên RAM (`internal/archive/pages.go`, `run.go`):**
   - Thay tệp tạm `html.jsonl` hàng trăm MB và đỉnh RAM nạp lại hàng GB bằng tập ứng viên giới hạn `O(K)` ngay trên luồng đọc CDX (`stateVersion = 3`), lưu gọn `html_top` trong `archive.json` để hỗ trợ tạm dừng / chạy tiếp toàn vẹn.
2. **Chồng pha ZipNum Shard $\rightarrow$ Background Memento Prefetch (`internal/archive/list.go`, `fetch.go`):**
   - Trong chế độ phân mảnh Wayback (`Sharded`), khởi chạy song song các worker tải trước memento + kiểm tra live + trích xuất AST ngay trong lúc các worker CDX đang kéo danh sách shard.
3. **Bộ nhớ đệm RAM có trần (`endpoints.SetMemCacheMB`, mặc định `512 MB` cho `crawl`/`archive`) & Gộp I/O Đĩa:**
   - Lưu kết quả `jsapi.Result` và mã nguồn module xuất hàm (`Builders`/`Exports`) trong bộ nhớ đệm phân mảnh 16-shard (`internal/endpoints/memcache.go`); cắt dung lượng slice (`src[:len(src):len(src)]`) trước `tdewolff/parse` để an toàn tuyệt đối khi đọc song song.
   - Đếm URL độc nhất trực tiếp trên RAM (`map[[16]byte]struct{}`), bọc `urls.jsonl` (`4 MB`) và `js.jsonl` (`1 MB`) bằng `bufio.Writer`, giữ handle `done.log` mở xuyên suốt và gom chu kỳ ghi checkpoint `archive.json`.
   - Ghi nhớ nâng cấp `http -> https` theo host (`httpsUpgrades >= 3` khi cổng mặc định không phục vụ HTTP thuần) để tránh nhân đôi lượt kiểm tra cổng 80.

### 1.3. Lập Lịch Công Bằng Đa Tầng (`Weighted DRR`)
- **`frontier.Queue` (`internal/frontier/queue.go`):** lập lịch theo thời gian ảo có trọng số (`weight 1..4`) giữa các host trong cùng bậc `(Depth, rank[How])`, tăng trọng số khi host sinh thông tin mới (`Feedback(..., true)`) và tự giảm về `1` sau `3` trang rỗng liên tiếp.
- **`archive.fetch` (`internal/archive/family.go`):** hàng đợi vòng xoay 2 tầng (`Origin -> CanonicalFamily`) giúp phân phối worker đồng đều qua mọi subdomain và họ bundle.

### 1.4. Nén Gzip Chỉ Mục, Song Song Hoá Common Crawl & Adaptive Backoff
- Bổ sung `Client.GetIndex` / `GetIndexWith` gửi `Accept-Encoding: gzip` cho mọi truy vấn chỉ mục JSON/NDJSON (Wayback CDX, Common Crawl Index, OTX, URLScan) trong khi giữ nguyên `Accept-Encoding: identity` cho tải Memento & WARC Range nhằm bảo toàn đối chiếu `SHA1B32`.
- Chạy song song các collection của Common Crawl và thay thời gian chờ cố định bằng Adaptive Exponential Backoff có jitter (`adaptiveBackoff`).

### 1.5. Hai Bản Vá Độ Chính Xác Cho `verify` & `detect`
1. **Nhận diện trang chặn WAF F5 BIG-IP ASM & Sub-Canary Phân Đoạn Nhạy Cảm (`internal/detect/classify.go`, `internal/verify/verify.go`):**
   - Nhận diện mẫu chặn `Request Rejected` (`The requested URL was rejected. Please consult with your administrator`) là `BlockRequest` trong `detect.Classify`.
   - Lưu sổ đăng ký các `2xx` HTML shell từng xuất hiện trên canary (`htmlShells`, so khớp tuyệt đối mã băm `Shell` qua `sameHTMLShell`, bỏ `<title>` rỗng và chỉ thăng cấp toàn RDN khi có nhãn WAF hoặc xuất hiện trên `>= 2` host) và tự động hiệu chuẩn **sub-canary** cho các phân đoạn nhạy cảm nằm sâu sau prefix 2-segment (`/admin/`, `/internal/`, `/manage/`, `/management/`, `/console/`, `/actuator/`, ...), triệt tiêu dương tính giả khi reverse-proxy chỉ trả trang HTML chặn riêng trên nhánh `/admin/`.
2. **Chống nhân đôi gốc API có phiên bản trong `join()` (`internal/verify/draft.go`):**
   - Khi `base` (ví dụ `https://host/api/v1/admin/users`) và `path` (`/api/v1/orders`) dùng chung gốc tiền tố API (`/api/v1`, `/v2`, `/api`, `/rest`, `/graphql`), neo thẳng `path` về origin thay vì ghép lặp `/api/v1/admin/users/api/v1/orders`.

### 1.6. Củng Cố Kiến Trúc Đợt 34.1 (`jsapi` v41, Máy Trạng Thái 4 Pha & Dual-Pool Cache)
- **Máy trạng thái 4 pha cho `familyController` & tách `archBody`:** chỉ đóng khoảng khi cả 2 mốc là `memberValid` có mã nguồn lịch sử thật (`ferr == nil && len(archBody) > 0`), nạp sẵn mốc từ `loadCurrent` (`SHA1B32 -> SHA256`) và Prefetch (`|Δt| >= 60d`), tách ngân sách `deadRetries` khỏi `familyMaxZoom`, tự thu gọn `O(1)` cho `drrQueue`.
- **Cô lập `archive.Client` & Nhịp bền bỉ:** tách riêng client cho Wayback/OTX/CC/URLScan kèm ngắt mạch Leaky-Bucket chốt cứng `c.blocked`, đặt mặc định `-concurrency 8`, `-live-rate 5`, `wbIndexGap = 800ms`, `wbFilesGap = 300ms`.
- **Dual-Pool MemCache (`65%` AST / `35%` Body):** trục xuất vòng liên shard không khóa chéo, không để raw body chiếm chỗ AST cache.
- **`jsapi` v41 & Liên kết Hằng Liên Chunk:** bóc ngoặc `(function(){...})` của Terser, hỗ trợ `constOrSingleExpr`, `Object.freeze`, `thisProps` (`*.prototype`, `data()`, `computed`, ngữ cảnh render Vue 2/3), nối `ConstExports` theo origin có clash-guard tại tầng `BuildIntel`/`MergeClientAuthz`, và tinh gọn các bộ lọc byte đầu vào để cắt 4–6 lượt duyệt AST thừa.
