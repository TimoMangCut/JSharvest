# Threat model `jsharvest` (2026-11-20, sau Đợt 40.1)

Đánh giá rủi ro của chính công cụ: an ninh (STRIDE), vận hành, hiệu năng, OpSec. Tài liệu không chứa tên target thật.

**Phương pháp.** Đọc mã toàn repo (~130k dòng Go, 33 package) theo 3 vùng: đầu vào không tin cậy và giới hạn tài nguyên; egress và an toàn request; bí mật, vận hành và OpSec. Không chạy request nào tới mạng. Mỗi mục ghi rõ mức kiểm chứng:

- **Đo**: đã chạy test cục bộ để đo.
- **Mã**: đã đọc lại đúng dòng mã và xác nhận.
- **Báo**: agent đọc mã báo lại, chưa đọc lại từng dòng. Cần kiểm trước khi sửa.

**Trạng thái triển khai (2026-11-21 — Đợt 41 hoàn tất):** Toàn bộ **27/27 hạng mục** (`H1`–`H3`, `M1`–`M13`, `L1`–`L11`) đã được khắc phục triệt để trong Đợt 41A/41B/41C theo thiết kế ở [plan-41.md](plan-41.md), kèm bộ unit test `round41_test.go`, `perfgate` (`10.83 s`, `385.5 MB` RSS) và toàn bộ gate hồi quy `testbed/regress.sh` PASS 100%. (Các hạng mục chủ đích đặt ngoài phạm vi Đợt 41 như xoay vòng `requests.jsonl` và mã hoá tầng ứng dụng được ghi nhận tại [plan-41.md](plan-41.md) Mục 7 và hướng dẫn vận hành phân vùng mã hoá tại [CURRENT.md](CURRENT.md) Mục 3).

**Cập nhật sau khi kiểm lại (xem [plan-41.md](plan-41.md) mục 0).** Toàn bộ các mục **Báo** đã được đối chiếu trực tiếp từng dòng mã nguồn ở `HEAD 4679c70` (gồm cả vòng rà soát chéo v2). Thay đổi:
- **M1, M7, M13 nâng lên mức Cao.**
  - M1: ở nhánh 2xx, `Judge` không xét `Kept`, nên có thể ra false positive `Bypass` (và `3xx`/`404` vẫn phán `Enforced` khi `Stale || Kept`; `dropCredential` không gỡ được `multipart` hay `"json:..."` thô).
  - M7: đã đo, esbuild **crash cả tiến trình** với 1M cấp lồng (2 MB); ngoài đường sau tdewolff còn có nhánh `.ts`/`.tsx` và `.vue`/`.svelte` gọi thẳng `transformTS`, cùng `jsapi/deferred.go:408`.
  - M13: đã đo, 1001 hàm lồng nhau (khoảng 13 KB) qua esbuild mất 6,6 s mỗi lần transform, 2000 cấp mất 45 s; một script có thể gọi esbuild tới 9 lần (chưa tính nhân theo số block `<script>` của SFC).
- **M8:** đề xuất bỏ câu "use your browser tools" là **sai**, vì đó là thiết kế cốt lõi của MCP watch. Chỉ nên gắn metadata fence và đánh dấu nghi vấn mà không phá byte offset của `read_script`.
- **L7:** noVNC nghe `0.0.0.0` trong container là có chủ đích; container chạy UID thường nên file mật khẩu phải đặt trong `$HOME` (không phải `/run`).

ID giữ nguyên để tham chiếu chéo; cột "Kiểm chứng" bên dưới đã được cập nhật.

## 1. Tài sản cần bảo vệ

| # | Tài sản | Vì sao quan trọng |
|---|---|---|
| A1 | Credential của các role (cookie, bearer, refresh token, mật khẩu `login -steps`) | Lộ ra là chiếm tài khoản khách hàng. Gửi nhầm danh tính làm kết quả `authz` sai. |
| A2 | Output (`endpoints.jsonl`, `intel.json`, `requests.jsonl`, `sent.jsonl`, secret tìm thấy trong JS) | Là dữ liệu của khách hàng, đồng thời là phát hiện chưa công bố. |
| A3 | Máy và mạng nội bộ của operator | Target thù địch có thể nhắm tới qua SSRF, crash, làm đầy đĩa. |
| A4 | Tính hợp pháp của run (scope, chỉ đọc) | Gửi request ra ngoài scope hoặc request ghi là rủi ro pháp lý và hợp đồng. |
| A5 | Tính sẵn sàng của target | Quá tải hoặc DoS target là rủi ro pháp lý. |
| A6 | Danh tính và ẩn danh của operator (IP, UA, dấu vân tay công cụ) | Bị WAF chặn, bị lộ công cụ hoặc lộ danh tính. |
| A7 | Tính đúng của kết luận (`verified_alive`, `bypass`/`enforced`) | Báo cáo sai dẫn tới false positive trong report. |

## 2. Tác nhân đe doạ

1. **Target thù địch hoặc bị chiếm.** Kiểm soát mọi byte HTML, JS, sourcemap, manifest, header, redirect và DNS của mình.
2. **Bên thứ ba trên đường đi.** Gồm dịch vụ archive (Wayback, CommonCrawl, OTX, urlscan), CA trong AIA, partner API mà JS của target nhắc tới, proxy.
3. **LLM client qua MCP.** Đọc output do target kiểm soát nên có thể bị prompt injection.
4. **Người dùng khác trên cùng máy hoặc nhóm**, và kho git **public**.
5. **Chính operator cấu hình sai**: `-allow-write`, `-guard off`, quên `-redact`, chạy sai thư mục.
6. **Chuỗi cung ứng**: Chrome, image gốc, module Go.

## 3. Ranh giới tin cậy

```
                    ┌───────────── TB1: Internet (target, bên thứ ba) ─────────────┐
 target HTML/JS ───►│ httpcrawl (netsafe) ─► sourcemap/resolve ─► jsapi/endpoints  │
 target page JS ───►│ Chrome (guard, LNA, capture) ─► recorder                     │
 archive APIs ─────►│ archive client (netsafe)                                     │
                    └──────────────┬───────────────────────────────────────────────┘
                                   ▼ TB2: đĩa (0600/0700, không mã hoá)
                     output/<target>/<role>/*, profiles/, session snapshot
                                   │
         ┌─────────────────────────┼──────────────────────────────┐
         ▼ TB3: lệnh tự gửi        ▼ TB4: MCP stdio → LLM         ▼ TB5: người đọc báo cáo
  replay / authz / verify    read_script, search…           .md report, terminal, webhook
  (credential role, write)   (đánh dấu untrusted)
```

## 4. Rủi ro (xếp theo mức)

### Cao

| ID | Vùng | Rủi ro | Bằng chứng | Kiểm chứng |
|---|---|---|---|---|
| **H1** *(Đã đóng — 41A)* | Hiệu năng / DoS cục bộ | Loose scanner tốn thời gian **bậc hai**. Mỗi match gọi `bytes.Count(src[:off], "\n")`, và số match không có trần. Đường này chạy cho mọi script parse lỗi (≤16 MB) và **mọi** script 16–64 MB (bỏ qua AST). | `internal/jsapi/loose.go:43-47,54,83`; `internal/endpoints/endpoints.go:269-292` | **Đo**: 1 MB `"/a/bN",` (88k match) mất **86 s**. Ngoại suy: 64 MB tốn hàng giờ CPU và giữ một slot `heavySem`. |
| **H2** *(Đã đóng — 41B)* | Bí mật lưu trên đĩa | Credential ghi **dạng rõ** theo mặc định. `-redact=false` cho `requests.jsonl` và `blocked.jsonl`. `sent.jsonl` (cả request, `set-cookie`, 64 KB response body, `Err`), `authz/trials/*.http` và `verify/drafts/*.http` ghi credential/token rõ và chưa có tuỳ chọn redact. Session snapshot là JSON rõ (cookie + local/sessionStorage). Profile Chrome dùng `password-store=basic`. Bảo vệ duy nhất là quyền 0600/0700. | `cmd/jsharvest/main.go:197`; `internal/replay/send.go:642,668,684-690`; `internal/replay/{authz.go:992,bola.go:1140}`; `cmd/jsharvest/verify.go:127`; `internal/session/session.go:88-101` | **Mã** |
| **H3** *(Đã đóng — 41B)* | Tài nguyên đĩa | Sourcemap chỉ có trần **byte** (16 MB mỗi source, 64 MB tổng), không có trần **số file** (cả `Parse` sections, `FilesFor`, `engine` và `archive/fetch.go:385-408`). Mỗi source `own` thành một `js/<sha>.js`, và `index.jsonl` bị ghi lại toàn bộ mỗi 50 entry trong `Put`. Một map dưới 50 MB có thể đẻ ra hàng triệu file nhỏ (cạn inode, I/O bậc hai, tốn hàng trăm MB RAM). | `internal/sourcemap/sourcemap.go:144-157,213-259`; `internal/engine/http.go:262-266`; `internal/archive/fetch.go:396-404`; `internal/store/store.go:246-300` | **Mã** |

### Trung bình

| ID | Vùng | Rủi ro | Bằng chứng | Kiểm chứng |
|---|---|---|---|---|
| **M1** *(Đã đóng — 41A)* | Đúng đắn `authz` / bất biến | Credential ở **query hoặc body** của role cao mà không được làm mới chỉ bị ghi `kept`, nhưng trial **vẫn gửi**. Admin token vì thế đi dưới danh tính user. Phán quyết chỉ bị hạ mức (`compare.go:103`), trái bất biến "không bao giờ gửi giá trị của role cao". `replay -as` không kiểm `kept`. Header không nhận ra là credential (`X-User-Id`, `X-Hasura-Role`) cũng giữ nguyên. | `internal/replay/authz.go:606-617,849`; `internal/replay/flow.go:176-188`; `internal/replay/compare.go:103,124-150` | **Mã**. **Nâng lên Cao:** nhánh 2xx của `Judge` không xét `Kept`, nên có thể ra `Bypass` false positive. |
| **M2** *(Đã đóng — 41B)* | Pháp lý / scope | Spec probe **ra ngoài `-scope`** theo mặc định: `-probe=true`, D2 ở gốc, cộng tối đa 2 base mỗi host do code đặt tên (quy tắc 40.1). Không gửi cookie hay header, nhưng vẫn là request tới host không nằm trong chương trình bug bounty. | `frontier/queue.go:596-620`; `frontier/specprobe.go` (`MaxOutOfScopeSpecBasesPerOrigin`) | **Mã** (quyết định thiết kế Đợt 40) |
| **M3** *(Đã đóng — 41B)* | SSRF trình duyệt | Lớp 1 chặn IP private trong trình duyệt nằm **trong guard**. Run CDP ẩn danh (`-engine cdp`, escalate challenge/SPA, `-headful`, `watch -guard off`) không có guard nên chỉ còn LNA, mà LNA chỉ cảnh báo nếu Chrome từ chối permission. Ngay cả khi có guard, lớp 1 chỉ chặn IP literal. | `internal/guard/lan.go:243`; `internal/engine/engine.go:592`; `internal/browser/lna.go:47-50` | **Mã** |
| **M4** *(Đã đóng — 41B)* | SSRF qua proxy | Khi có `-proxy`, dialer chỉ thấy proxy nên không tra DNS cục bộ (đúng thiết kế). Kết hợp với M2 và follow-up `SwaggerUIURLs`/`SwaggerResources` không lọc `inScope`, một host nội bộ mà JS hoặc trang Swagger nhắc tới (`jenkins.corp…`) sẽ được proxy phân giải và gọi từ mạng của operator. | `internal/netsafe/netsafe.go:176`; `internal/engine/specprobe.go:35,263`; `internal/httpcrawl/crawl.go:425,1681` | **Mã** |
| **M5** *(Đã đóng — 41A)* | Lộ bí mật qua log | `guard: held back` và hơn 25 dòng `slog.Info`/`Warn`/`Error` trong `guard`, `engine`, `capture` log **URL đầy đủ** bất kể `-redact`. URL thường mang `id_token_hint=<JWT>`, `code=…` hoặc `?token=…`, nên token rơi vào stderr, log cron hay log Docker. | `internal/guard/guard.go:390,613`; `internal/engine/{session.go:481,watch.go:116,engine.go:894,1218}` | **Mã** |
| **M6** *(Đã đóng — 41A)* | Phiên | `relogin` shallow-copy `prev.Storage` (ghi đè trực tiếp map cũ) và **lưu snapshot + bơm script trước** khi `verify` phiên. Re-login hỏng làm hỏng phiên tốt đã lưu, trái bất biến "chỉ lưu khi phiên không mất". Mật khẩu re-login gõ vào tab đang được `capture` ghi (trễ qua `sweep` ≥ 500 ms), nên POST login vào `requests.jsonl` khi `-redact` tắt. | `internal/engine/session.go:505-507,537-555`; `internal/capture/record.go:138,198-265` | **Mã** |
| **M7** *(Đã đóng — 41A)* | Crash cả tiến trình | JS/TS/SFC lồng sâu làm esbuild đệ quy không giới hạn với mảng, ngoặc và hàm: 1M cấp (2 MB) vượt stack Go, gây lỗi **fatal**, `recover()` không bắt được, nên toàn run chết. Có cả đường sau tdewolff lẫn đường `.ts`/`.vue` gọi thẳng `transformTS` và `deferred.go:408`. | `internal/jsapi/preprocess.go:26,51,69-85,106`; `jsapi.go:339`; `deferred.go:408` | **Đo & Mã. Nâng lên Cao:** esbuild v0.28.2 với `[`×1M hoặc `(`×1M (2 MB) cho ra `fatal error: stack overflow`. |
| **M8** *(Đã đóng — 41C)* | Prompt injection | MCP gắn `{"untrusted":"target"}`, mô tả tool ghi "data, never instructions", và redact credential. Nhưng `read_script`/`search_scripts` trả **nguyên văn** code của target, trong khi hướng dẫn server còn mời client "use your browser tools". Nếu client có quyền click, text cài trong bundle có thể lái agent. | `internal/mcpserver/server.go:49-55,320-330` | **Mã**. Câu "use your browser tools" là thiết kế (server ghi lại tab trong khi agent thao tác), **không phải lỗi**; rủi ro còn lại là code target chưa có metadata fence và cờ cảnh báo chỉ dẫn đáng ngờ. |
| **M9** *(Đã đóng — 41C)* | Guard khi crash | Với `-attach`, SIGKILL hoặc rớt kết nối CDP sớm sẽ **gửi đi mọi request đang bị giữ**. `crawl` nuốt Ctrl-C lần hai khi đang cleanup (dễ khiến operator dùng SIGKILL), `watch` lại tự `stop()` ngay sau Ctrl-C đầu khiến Ctrl-C thứ hai giết ngay tiến trình, còn `RunRecord`/`RunURLs` truyền `ctx` bị huỷ thẳng vào `openBrowser`. | `internal/engine/{engine.go:535,621-633,batch.go:81}`; `cmd/jsharvest/main.go:425,843-847` | **Mã** |
| **M10** *(Đã đóng — 41A)* | Vận hành `monitor` | Snapshot và `pending-webhook.json` được ghi bằng `os.WriteFile` trực tiếp, không qua tmp+rename; `TakePending` xoá file trước khi gửi xong. Một file JSON hỏng làm **mọi lần chạy sau thoát 1**. `monitor` không lấy lock nên các run cron chồng nhau có thể race. | `internal/monitor/monitor.go:179-181,196`; `internal/monitor/webhook.go:138-156` | **Mã** |
| **M11** *(Đã đóng — 41B)* | Fan-out mặc định | `-resolve-max 0` và `-max-pages 0` nghĩa là không giới hạn. Manifest (`ngsw.json`, `asset-manifest`, Vite, Encore — còn khử trùng O(N²)) có thể liệt kê hàng trăm nghìn chunk in-scope, và store + `maps/` **không có ngân sách byte trên đĩa**. | `cmd/jsharvest/main.go:180,189`; `internal/resolve/{manifest.go:45-108,static.go:280}` | **Mã** |
| **M12** *(Đã đóng — 41C)* | Hành động phá huỷ trong body | Khi có `-allow-write` (hoặc trong cửa sổ `AllowWrites` lúc `relogin`), luật phá huỷ của guard chỉ xét **URL** (và GraphQL chỉ khi `Explore`). `POST /rpc {"method":"user.delete"}` vẫn qua. Logout khai trong body/GraphQL bị `replay` xếp `Destructive` chứ không phải `Never`. | `internal/guard/{rules.go:105,119,138,guard.go:541}`; `internal/replay/policy.go:57-86` | **Mã** |
| **M13** *(Đã đóng — 41A)* | Thời gian mỗi script | Không có deadline wall-clock quanh `extractJS`. Script parse lỗi có thể gọi esbuild tới 9 lần (1 JSLower + 4 TS + 4 arrow-lowered; `.ts` lỗi chạy lặp `transformTS` 2 lần; SFC nhân theo số `<script>`). | `internal/endpoints/endpoints.go:262-297`; `internal/jsapi/preprocess.go:50-127,439-495` | **Đo & Mã. Nâng lên Cao:** hàm lồng nhau qua esbuild mất 6,6 s ở N=1000, 45 s ở N=2000, hơn 60 s ở N=5000; tdewolff từ chối từ N=1001. |

### Thấp

| ID | Vùng | Rủi ro | Bằng chứng | Kiểm chứng |
|---|---|---|---|---|
| **L1** *(Đã đóng — 41A)* | OpSec / bất biến | Request AIA không đặt User-Agent nên đi với `Go-http-client`, tới URL issuer do **cert của target** chọn. | `internal/tlsutil/aia.go:189-198` | **Mã** |
| **L2** *(Đã đóng — 41C)* | OpSec | Marker cố định trong repo public (`rt-4f9c2a.js`, `Symbol.for("pf.8d1e7b")`) giúp target nhận diện công cụ. Client archive tự khai `jsharvest (archive; +github…)` và gửi tên miền target tới 4 dịch vụ bên thứ ba (urlscan gắn với tài khoản API key). | `internal/marker/marker.go:16-27`; `internal/archive/client.go:181` | **Mã** |
| **L3** *(Đã đóng — 41C)* | Injection vào báo cáo | 5 báo cáo Markdown (`roles`, `authz`, `bola`, `verify`, `monitor`) chèn `Key`/`Sample`/`Value`/`URL` chưa escape đủ backtick, `\|` hoặc `\r\n`. Lệnh `archive` in URL thô bằng `fmt.Fprintf` ra stderr, nên có thể chứa escape sequence (C0/C1) của terminal. | `internal/roles/report.go:50,75`; `internal/replay/{report.go:64,bola_report.go:52-75}`; `internal/verify/verify.go:1356-1393`; `internal/monitor/report.go:41-71`; `cmd/jsharvest/archive.go:191` | **Mã** |
| **L4** *(Đã đóng — 41C)* | Crash archive | `Content-Length` của WARC dùng thẳng cho `make([]byte, n)` không kiểm âm hay vượt `max + 1<<20`, và thiếu `zr.Close()`. Nguồn là CommonCrawl, không phải target. | `internal/archive/warc.go:42,66-73` | **Mã** |
| **L5** *(Đã đóng — 41C)* | Toàn vẹn log | Không có `fsync`. JSONL nối thêm không kiểm dòng cuối bị cụt, nên dòng hỏng nối vào bản ghi đầu của run sau và bị bỏ âm thầm. `results.Finished` đọc toàn bộ `runs.jsonl` vào RAM. | `internal/results/results.go:383-392`; `internal/traffic/traffic.go:205` | **Mã** |
| **L6** *(Đã đóng — 41C)* | Khoá | CLAUDE.md nói lệnh ghi `flock` profile, nhưng `crawl` chỉ khoá output (và với `-urls`, profile được phân giải sau `lockDirs`), trong khi keeper của nó ghi snapshot vào profile. | `cmd/jsharvest/main.go:355-391`; `internal/engine/keeper_state.go:334` | **Mã** |
| **L7** *(Đã đóng — 41C)* | Docker | noVNC nghe `0.0.0.0` trong container: nếu `docker run -p 6080:6080` là lộ VNC HTTP với mật khẩu 8 ký tự, mà mật khẩu còn in ra stderr. `seccomp=unconfined`. Gói `chromium` trên non-amd64 không ghim phiên bản. | `docker/entrypoint.sh:61,70-75` | **Mã**. Nghe `0.0.0.0` trong container là có chủ đích (để publish ra `127.0.0.1` của host) và tự về loopback khi dùng mạng host. |
| **L8** *(Đã đóng — 41C)* | Lộ qua git | `.gitignore` thiếu `*.log`, `.env`, `.claude/`. CI hygiene chỉ grep `/home/...`, không quét secret hay ground truth. | `.gitignore`; `.github/workflows/ci.yml` | **Mã** |
| **L9** *(Đã đóng — 41A)* | Test chạm mạng thật | `TestPipelinedPagesAreDeterministic` tra DNS hệ thống cho `apiN.x.test`, kể cả trên CI GitHub, nên flaky. Không test nào trong `httpcrawl` đặt `Resolver`. Bản sửa đang nằm ở một nhánh cục bộ chưa merge. | `internal/httpcrawl/pipeline_test.go:38,66-67` | **Mã** (trượt ở cả base) |
| **L10** *(Đã đóng — 41C)* | Probe bên thứ ba | Cloud-bucket probe của `verify` (S3/GCS/Azure, tối đa 10 target × 2 request) bỏ qua `-rate`, `-max`, `Stopped()` và `sent.jsonl`; `rep.Sent` được gán trước khi `ProbeCloud` chạy. | `internal/endpoints/cloud.go:22,370-388`; `internal/verify/verify.go:225-263` | **Mã** |
| **L11** *(Đã đóng — 41C)* | Phủ dải địa chỉ | `PrivateAddr` thiếu `fec0::/10` (site-local IPv6, đã deprecated). | `internal/netsafe/netsafe.go:31-52` | **Mã** |

## 5. Kiểm soát đã có (điểm mạnh)

- **SSRF phía Go**: mọi client (crawl, replay, spec/cloud probe, archive, AIA) đi qua `netsafe`: phân giải một lần, kiểm mọi IP, dial IP đã kiểm, DNS lỗi thì từ chối. Dải địa chỉ phủ rộng (IPv4-mapped, CGNAT, NAT64, 6to4, Teredo, link-local, metadata). Redirect được kiểm lại. Replay so sánh địa chỉ để chống DNS rebinding.
- **Chỉ đọc theo mặc định**: `-allow-write` tắt; `replay` cần cả hai cờ mới gửi request phá huỷ; `Never` cho logout, luồng login và `Clear-Site-Data`. Không tìm thấy đường nào gửi non-GET khi thiếu cờ. Guard đặt Deny trước Allow, và ngoại lệ refresh chặt (không GraphQL). Guard gắn thất bại thì dừng run.
- **Kích thước đầu vào**: body 50 MB sau giải nén, trần cả với gzip/br/zstd của archive. Bậc kích thước script 16/64 MB. `heavySem` 2–4. `recover()` quanh parse và walk của tdewolff. Độ sâu JSON có trần.
- **Hệ thống file**: tên file là `sha256` hoặc slug `[a-z0-9]` có trần độ dài. `TargetDir` chỉ lấy từ `-u`. Ghi tmp+rename với quyền 0600/0700. MCP chỉ mở `^[0-9a-f]{64}$`, có `Lstat` và chỉ mở regular file.
- **Lịch sự với target**: `-http-rate 5`, `-page-rate 2`, `verify`/`authz -rate 2`. Breaker dial/origin. 503 + Retry-After thì dừng. Không retry request ghi.
- **Bề mặt cục bộ**: MCP chỉ qua stdio. Không bật `--remote-allow-origins`. Xvfb `-nolisten tcp`, x11vnc `-localhost`, compose publish `127.0.0.1:6080`.
- **Chuỗi cung ứng**: Chrome for Testing ghim SHA256 (amd64), image gốc ghim digest, `GOTOOLCHAIN=local`, không `curl|sh`.

## 6. Vận hành

- **Điểm tốt**: mã thoát rõ ràng (0/1/3/4/5/130, cộng 2 khi sai cờ). Keeper khôi phục phiên tối đa 10 lần rồi coi là mất phiên và thoát 4. Watchdog chống treo chromedp. Lock cho thư mục output. Gate hồi quy phủ phần lớn bất biến.
- **Điểm yếu**:
  - Dữ liệu dễ hỏng: M10, L5, L6.
  - Không có ngân sách đĩa hay thời gian tổng (M11, H3).
  - SIGKILL để lại profile tạm và (trên macOS) Chrome mồ côi (M9).
  - Log Info lộ token (M5).
  - Gate chỉ thử Ctrl-C: không thử SIGKILL dưới `-attach`, JSONL bị cụt, đĩa đầy, hay việc `-redact` có phủ stderr không.
- **Khuyến nghị cho người vận hành ngay bây giờ** (không cần sửa mã):
  - Chạy với `-redact` khi output sẽ chia sẻ.
  - Đặt `-max-pages`/`-resolve-max` cho target lạ.
  - Dùng `-scope rdn` hoặc `-probe=false` khi chương trình cấm host ngoài danh sách.
  - Không chạy `-proxy` cùng spec probe trên mạng nội bộ nhạy cảm.
  - Đặt `output/` và `profiles/` trên phân vùng mã hoá.

## 7. Hiệu năng

- **Đường thường**: perfgate 2.000 script ≤ 15 s, RSS ≤ 500 MB (gần nhất ~9–12 s, ~360 MB trên Linux, theo `docs/CURRENT.md`; lần này tôi **không đo lại**).
- **Đường thù địch chưa có gate**:
  - H1: loose scanner bậc hai, **đã đo**.
  - M13: không có deadline mỗi script.
  - M7: độ sâu lồng.
  - H3: sourcemap nhiều file nhỏ.
  - `cr.extracted`/`cr.seen` giữ toàn run không trần.
  - Engine Chrome đọc trọn body rồi mới `.slice` (`engine/resolver.go:314`).

  Đề xuất thêm `perfgate -adversarial` gồm 4 file mẫu: nhiều match loose, lồng sâu, map nhiều source, manifest 100k chunk. Đặt trần thời gian và RSS cho từng file.

## 8. Lộ trình đề xuất

**Đợt ngay** (rẻ, giá trị cao, mỗi mục kèm test):
1. H1: tính bảng offset dòng một lần rồi tra nhị phân; đặt trần số match loose (ví dụ 50k), vượt trần thì ghi `loose_truncated`.
2. M1: credential role cao không làm mới được ở query/body thì **gỡ** hoặc chuyển trial sang `Unclear` **mà không gửi**; áp dụng tương tự cho `replay -as`.
3. M5: log guard chỉ in `scheme://host/path`, bỏ query (hoặc hash).
4. M6: `verify` phiên trước khi `snap.Save`.
5. M10: snapshot `monitor` ghi tmp+rename; file hỏng thì bỏ qua kèm cảnh báo; thêm `lockDirs`.
6. L1: AIA dùng UA của `uahints`.
7. Merge bản sửa L9 (resolver giả cho test pipeline).

**Đợt sau**:
- H3: trần số file cho mỗi map và mỗi run; index chuyển sang append hoặc flush theo thời gian.
- M11: ngân sách byte/đĩa cho mỗi run (`-max-store-mb`).
- M7: tiền kiểm độ sâu ngoặc trước esbuild, hoặc `debug.SetMaxStack` cùng bỏ qua fallback khi lồng quá sâu.
- M13: deadline cho mỗi script.
- M2/M4: cờ `-probe-offscope=on|off` (cân nhắc mặc định `off` khi có `-proxy`).
- M3: chặn IP private lớp 1 cả khi guard tắt (Fetch tối thiểu chỉ cho luật LAN).
- H2: `-redact` cho `sent.jsonl`, `authz/trials/*.http`, `verify/drafts/*.http` và `verify.json`/`verify.md` (bật mặc định cho `authz` và `verify`, giữ tắt cho `replay`).

**Dài hạn**:
- M8: metadata fence có nonce ở envelope MCP và đánh dấu đoạn code trông như chỉ dẫn (giữ nguyên byte offset của `read_script`). Giữ câu "use your browser tools", vì đó là thiết kế.
- M9: handler cho tín hiệu thứ hai (cả `crawl` và `watch`), giữ kết nối CDP qua `context.WithoutCancel`, dọn profile tạm cũ.
- L5: cô lập dòng JSONL cụt (`appendOpen`), đọc `runs.jsonl` bằng `bufio.Scanner`, `fsync` khi đóng run (hoãn xoay vòng `requests.jsonl`).
- L7: không in mật khẩu VNC ra stderr (ghi vào `$HOME/vnc-password` với `umask 077`); giữ bind `0.0.0.0` trong container cho `-p 127.0.0.1:6080:6080`.
- L8: quét secret trong CI.

## 9. Giới hạn của đánh giá

- Đã đọc lại trực tiếp dòng mã ở `HEAD 4679c70` cho toàn bộ mục cộng các phép đo cục bộ (H1, M7, M13). Chưa chạy gate mới, chưa chạy lại perfgate, chưa fuzz.
- Chưa đánh giá: nội dung Chrome for Testing và các CVE của nó; cách ly giữa các tab đa role khi chạy song song (`-tabs N`); module Go phụ thuộc (chưa chạy `govulncheck`).
- Giả định A1–A4 (`docs/gd4-plan.md`) vẫn chưa được xác nhận. Đánh giá này không thay đổi điều đó.
