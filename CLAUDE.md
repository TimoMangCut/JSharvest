# jsharvest

Công cụ thu thập và phân tích JavaScript của web mục tiêu (live + post-auth + archive) phục vụ recon pentest/bug bounty. Viết lại từ đầu bằng Go thuần (không wrap katana).

**Bối cảnh hiện hành:** đọc [docs/CURRENT.md](docs/CURRENT.md) (~5 KB) cùng mục **Bất biến** dưới đây. Lịch sử các đợt xem chỉ mục [docs/rounds-history.md](docs/rounds-history.md) (bản chi tiết: [docs/archive/rounds-history-full.md](docs/archive/rounds-history-full.md)).

## Tổng quan kiến trúc & Anti-Bot

- **Ngôn ngữ & Lõi:** Go 1.25.4 (`CGO_ENABLED=0`, `GOTOOLCHAIN=${GOTOOLCHAIN:-auto}` khi dev; `GOTOOLCHAIN=local` trong Docker build), `chromedp` (`cdproto` Fetch, DOMDebugger, Target auto-attach, Debugger), `tdewolff/parse/v2/js` + `esbuild`, single binary. Lõi nói chuyện với 1 CDP endpoint; auth thay thế được (`launch`, `attach` với `--user-data-dir` riêng từ Chrome 136, `login -steps`).
- **Pre-Auth & Chống bot:** `crawl -engine auto` ưu tiên Pure-Go HTTP/2 + giải mã tĩnh manifest/chunk/sourcemap + Archive để không lộ `HeadlessChrome`; chỉ bật CDP khi cần (`-role`/`-profile`/`-attach`, `-explore`, V8 runtime, trang challenge). Cách ly script/eval/endpoint challenge (`/cdn-cgi/challenge-platform/`...) khỏi `store`/`endpoints.jsonl`; cho `/cdn-cgi/` qua `Guard` (trừ `/cdn-cgi/access/`).
- **Post-Auth & Coverage:** keeper phát hiện mất session → pause, re-auth, resume (khôi phục cookie + storage); chặn logout/signout/revoke và request ghi ở `Fetch.requestPaused` (`blocked.jsonl`, mặc định giả `200 {}` `fake|fail|allow`); đa vai trò `diff` / `authz`; dedupe 2 lớp (URL chuẩn hoá + SHA256) + giải mã bundler (Webpack 3/4/5, `webpackAsyncContext`, `runtimeChunk`, Vite, Next `_buildManifest`, Workbox, `ngsw.json`), router phân cấp và `archive`.

## Cấu trúc Output

```
output/<target>/<role>/
├── js/<sha256>.js   static/
├── index.jsonl      endpoints.jsonl   intel.json
├── requests.jsonl   blocked.jsonl
└── run.json         runs.jsonl
```

## Tra cứu thiết kế chuyên sâu (mở khi sửa vùng tương ứng)

| Chủ đề | Tài liệu (phần kết luận chốt sau review có hiệu lực cao hơn) |
|---|---|
| Hiện hành, cờ mới, backlog | `docs/CURRENT.md` (tổng hợp Đợt 33 `docs/plan-33.md`, Đợt 32 `docs/plan-32.md` & Đợt 31 `docs/plan-31.md`) |
| Đợt 28–30, BOLA ngang | `docs/plan-28.md`, `docs/plan-28-exec.md` (mục 3–4), `docs/gd7-bola-design.md` (mục 8–9) |
| Engine HTTP, WAF, OpSec, `jsapi` 13–27F | `docs/gd6-waf-design.md` mục 10–48 (bảng Đợt → mục: `docs/rounds-history.md`) |
| Replay, Docker, Archive, Monitor, Song song | `docs/gd5-{replay,container,archive,monitor,parallel}-design.md` |
| Guard/SW, Recorder, Flows, MCP, Static, Frontier, Session, Explore, Roles, Export | `docs/gd4-{plan,guard-sw,recorder,flows,mcp,static-endpoints,frontier,session,explore,roles,export}-design.md` |

## Bất biến (không được phá; gate hiện có kiểm phần lớn)

**An toàn khi gửi request.** Chỉ chạy trên target được phép. `authz` (kể cả `-peers`: chỉ `bypass` khi response của B chứa giá trị chỉ A có; không bao giờ gửi credential của A dưới B), `replay`, `verify`, `archive` (kiểm live) là các lệnh **tự gửi request**:
- chỉ đọc theo mặc định (`-allow-write`; `-allow-destructive` chỉ cho `replay`); logout, luồng login, endpoint có `Clear-Site-Data` thì không bao giờ gửi;
- credential không làm mới được thì gỡ, **không bao giờ gửi giá trị của role cao** dưới danh tính role thấp; phiên chết → `unclear`, không bao giờ `enforced`;
- chỉ tới host của mẫu, gắn IP khi kết nối; bị WAF chặn thì xử lý theo `-on-block` (mặc định `host`), phân loại bằng `detect.Classify`.

**Guard.** `Fetch` cấp browser chỉ chặn loader tạo sau khi bật, nên guard gắn thêm `Fetch` trên session của mọi target có sẵn; gắn thất bại thì dừng run; `otherTab` có tác dụng thật, không được bỏ. Luật phá huỷ dùng chung với frontier; `-guard-allow` có hiệu lực cho cả hai. Khi explore: DELETE và mutation GraphQL có tên phá huỷ luôn bị giữ, kể cả với `-allow-write`. `/cdn-cgi/` đi qua (`cdn-infra`) trước luật phá huỷ, **trừ `/cdn-cgi/access/`**.

**Challenge.** Script/eval/endpoint của trang challenge bị bỏ ở `capture.emit` (không vào store, resolver, catalog); recorder gắn tag `challenge` và endpoints/flows/roles/export bỏ qua.

**Engine.** `crawl -engine auto` (mặc định) = HTTP cho anon; `cdp` khi có `-role` khác anon, `-profile`/phiên đã lưu, `-attach`, `-explore`, `-headful`. Gate về Chrome đặt `JSHARVEST_ENGINE=cdp`. Gate dùng engine HTTP phải đặt `-archive=false` hoặc archive giả (`JSHARVEST_WAYBACK_URL`, `_OTX_URL`, `_CC_INDEX_URL`, `_CC_DATA_URL`, `_URLSCAN_URL`).

**Mạng của tiến trình Go & Trình duyệt.** Mọi client (`httpcrawl`, `replay.Sender`, AIA, dịch vụ archive) đi qua `internal/netsafe`: phân giải một lần, kiểm mọi địa chỉ (`PrivateAddr`), dial IP; DNS lỗi là từ chối; host rules và target nội bộ là ngoại lệ duy nhất; có proxy thì không tra DNS cục bộ và kiểm IP literal/`localhost` ở tầng request (`netsafe.Guard`). Một nguồn proxy (`netsafe.ProxyFrom`); loopback không qua proxy. Trình duyệt: guard chặn IP private khi origin mốc public, LNA deny, cầu chì `remoteIPAddress`; WebRTC sau proxy bằng preference của profile (cờ dòng lệnh bị Chrome 156 bỏ qua).

**Phiên và guard (28C).** Ngoại lệ refresh: chỉ POST có mọi `grant_type` là `refresh_token`, sau Deny/Destructive/DELETE trá hình, không bao giờ GraphQL. `-guard-allow` của `login` phải neo `^https?://<host trong scope>/` (không thì từ chối), lưu trong session, OR với của `crawl`; Deny trước Allow. Keeper đồng bộ token xoay vòng vào snapshot và chỉ lưu khi phiên không mất. Lệnh ghi lấy `flock` trên thư mục output/profile; lệnh chỉ đọc không khoá.

**OpSec.** Không tự khai là bot: tên script chèn vào trang lấy từ `internal/marker` (`pf-8d1e7b.js` cho tagger, `rt-4f9c2a.js` cho resolver/internal); UA và `Sec-CH-UA` theo bản Chrome thật (`internal/uahints`), không bao giờ `Go-http-client` hay `HeadlessChrome`; không `--enable-automation`. Không giả TLS khi chưa có bằng chứng cần. Cookie CDN chỉ trong bộ nhớ theo từng `(target, role)`, không ghi ra đĩa.

**Recorder và kết luận.** Outcome `ok` của recorder là **mọi response, kể cả 401/403**: trạng thái lấy từ mã HTTP (`results.Req.Status`, `observed.statuses`). Request bị guard giữ, của worker, hoặc từ cache chỉ có header tạm (`headers_provisional`). Template endpoint phải suy bằng `flow.EntryTemplates` (frame ứng dụng dưới hàm bọc request; dùng frame trên cùng sẽ gộp nhầm thành `/api/{param}`).

**Output.** Mọi file output `0600`, thư mục `0700`. Thư mục host cổng không mặc định là `host_port` (`scope.TargetDir`; loopback giữ tên trần); `archive` ghi theo hostname và là tên role dành riêng. Mỗi run ghi `scripts:[sha]`; số liệu `requests`/`page_requests`/`internal_requests`/`scripts`/`new_scripts` của run HTTP là của riêng nó, còn tổng hợp với các run Chrome follow-up (`Escalated`/`SPABoot`) nằm trong khối `totals` của `run.json` (`unique_scripts = st.Len() + Σ er.NewScripts`); snapshot của `monitor` chỉ lưu run ID. `requests.jsonl` chỉ ghi request **đã gửi**: request bị breaker dial/origin của `httpcrawl` giữ thì không ghi, chỉ ghi `pages.jsonl` `reason: origin-unreachable`. Stage 1 của `crawl -archive` (`archive.ModeListOnly`) không bao giờ gửi request tới target. Mã thoát: `0` xong, `1` lỗi, `3` bị chặn, `4` mất session, `5` `monitor -fail-on`, `130` bị ngắt. Không bao giờ commit `output/`, `profiles/`, `bin/`, file log hay ground truth lấy từ mục tiêu thật.

**jsapi.** Đổi kết quả thì tăng `jsapi.Version` (hiện `46`). Khi sửa `internal/jsapi`, so snapshot với HEAD (output chỉ khác ở chỗ định sửa):
`JSAPI_SNAPSHOT=<file đường dẫn tuyệt đối> go test -v -run TestSnapshot ./internal/jsapi | grep '^SNAP' | md5sum` (cần `-v`; corpus dev `output/_live_25e_max/*/anon/js/*.js`). Kiểm mù chạy **một lần** rồi thành dev (dev hiện có: Keycloak, Appwrite, Medusa, Directus, Jellyfin); tập mới chờ xác nhận trước khi tải. Nhiễu: `JSAPI_STATS=list go test -run TestStats ./internal/jsapi`. Trần cứng: `bin/testbed perfgate` — 2.000 script `≤ 15 s`, RSS đỉnh `≤ 500 MB`.

**Đo và so sánh.** So với katana luôn có cả chế độ standard và luôn chạy `katana ... < /dev/null`. Giả định A1–A4 (`docs/gd4-plan.md`) chưa được xác nhận.

## Đóng gói Docker

`Dockerfile` (Chrome for Testing ghim SHA256 + Xvfb + x11vnc + noVNC + `tini`), `docker-compose.yml` (`seccomp=unconfined`, `cap_drop: [ALL]`, noVNC `127.0.0.1:6080`), `docker/entrypoint.sh` và `testbed/docker-check.sh`: cấu hình qua flag/`JSHARVEST_*`, dùng `--disable-dev-shm-usage`, tự bật Chrome sandbox khi có userns hoặc fallback `--no-sandbox` kèm cảnh báo; `login` (headful) chạy qua Xvfb + noVNC.

## Ghi chú kỹ thuật & Bộ gate kiểm thử

- **Build & Test nhanh:** `go build -o bin/jsharvest ./cmd/jsharvest` · `go test -race ./internal/...` · `GATE=1 TOOLS=jsharvest testbed/bench.sh` (hoặc `go test -tags integration ./testbed/`); ghi baseline tăng có chủ đích: `bin/testbed score -app testbed/apps/<app> -out <dir> -write-baseline`.
- **Hồi quy toàn bộ:** `testbed/regress.sh [-j 3] [gate…]` (`DOCKER=1` thêm `docker-check`), mỗi lane dùng `unshare -rn` + userns lồng (nếu Ubuntu đặt `apparmor_restrict_unprivileged_userns=1` sẽ chạy 1 lane và trượt `lan-check`/`proxy-check`/`webrtc-check`). Gate đọc `TESTBED_LOG`, `TESTBED_PID`, `TESTBED_WORK`, `TESTBED_NO_BUILD`; log ở `bin/regress/<gate>.log`. Testbed: `testbed/build.sh [app]`, `bin/testbed serve`, marker `JSHMARK:<loại>:<tên>` trong `truth.txt`.
- **chromedp v0.21 / cdproto v0.159:** dùng API generic mới (`chromedp.Events`, `chromedp.Call`, `chromedp/remote`; xem `$(go env GOMODCACHE)/github.com/chromedp/chromedp@v0.21.1/docs/API.md`). Event cùng request đến không thứ tự → `capture` dùng cờ độc lập.
  - **8 bẫy chromedp:** (1) worker lồng treo `Runtime.enable` → watchdog, không đặt timeout trên ctx của `Do`; (2) lệnh trên session chết treo → luôn đặt timeout; (3) `chromedp` tự gọi `Runtime.evaluate("self")` tạo `scriptParsed` URL rỗng; (4) `Call`/`Events` phải dùng ctx tab/session; (5) `DOM.getDocument` làm treo `chromedp.Click(sel)` → `explore` chỉ dùng `backendNodeId`/toạ độ; (6) `getNodeForLocation` dùng toạ độ document, `getContentQuads`/`Input.dispatch*` dùng viewport → cộng `pageX`/`pageY`; (7) popup mở làm treo input tab; (8) `Input.dispatchMouseEvent` treo khi mở dialog JS → xử lý dialog ở goroutine khác.
- **Chi tiết cốt lõi:** giữ `go 1.25.x` trong `go.mod` (`x/net` ghim v0.58.0); `requests.jsonl` kiểm đối chiếu hai chiều qua `bin/testbed reqcheck`; response giả của guard mang `X-Jsharvest-Guard`; `fetch()` không đọc body không có `loadingFinished`; binding JSON từ trang phải giải mã dễ dãi; `scope`: `-scope rdn|fqdn` (script ngoài scope gắn `third-party`, tài nguyên ứng dụng nạp vào vẫn `in-scope` trừ tracker), `-host-resolver-rules`; `detect` theo bảng `rules` (`Check` đòi hỏi bằng chứng riêng, `Vendor` → `fronted`/`fronted_by`, `AllChallenge`).

### Bảng chọn Gate khi sửa mã nguồn

| Sửa vùng mã | Gate bắt buộc |
|---|---|
| `guard`, quản lý tab | `testbed/attach-guard.sh` *(chế độ `-attach` không nằm trong gate khác)* |
| `capture/actions.go`, `internal/flow`, recorder | `testbed/flows-gate.sh` (`PLAYWRIGHT=1` cho Playwright Docker) |
| `internal/jsapi`, `internal/endpoints`, resolver | `testbed/endpoints-check.sh` + snapshot/stats/`perfgate` |
| `internal/session`, `engine/session.go`, `login`, refresh/keeper | `testbed/session-check.sh` |
| `internal/roles`, `diff` | `testbed/roles-check.sh` |
| `internal/export`, `export`, CSRF/session `flows-app` | `testbed/export-check.sh` |
| `internal/replay`, `authz`/`replay`, `export.Load`, `authz-app` | `testbed/replay-check.sh` |
| `authz -peers`, `peer-app`, `get_authz` | `testbed/bola-check.sh` (`testbed/lab/` cho lab Jellyfin/Directus) |
| `Dockerfile`, `docker/`, `internal/browser`, WebRTC | `testbed/docker-check.sh` (khi sửa WebRTC chạy cả `webrtc-check.sh`) |
| `internal/archive`, `archive`, `archiveEnv`/`archive.Mode` (crawl `-archive`) | `testbed/archive-check.sh` + `pipeline-check.sh` |
| `internal/monitor`, `monitor`, `runs.jsonl` | `testbed/monitor-check.sh` |
| `internal/explore`, `engine/explore*.go`, guard của explore | `testbed/explore-check.sh` |
| `internal/detect`, `/cdn-cgi/`, `httpcrawl`, `htmlscan`, `sourcemap`, `ua.go` | `testbed/waf-check.sh` |
| `internal/frontier`, `engine/frontier.go` | `testbed/frontier-check.sh` (`testbed/external/run.sh` trước khi chốt bước) |
| `engine/batch.go`, `shared.go`, `Guard.TakeFor`/`Capture.Owns` | `testbed/parallel-check.sh` |
| Đa tab `-tabs N` của `engine/frontier.go` | `testbed/frontier-tabs-check.sh` |
| `httpcrawl`, `engine/http.go`, `tlsutil`, `infra.go`/`enrich.go`, `TargetDir` | `testbed/pipeline-check.sh` |
| `httpcrawl/breaker.go`, `origins.go`, `sourcemaps.go` (breaker, ổn định origin, dedup map) | `testbed/pipeline-check.sh` + `waf-check.sh` + `bin/testbed reqcheck` |
| Test có `httptest` handler | `go test ./internal/testlint` (handler không được ghi biến capture khi không khoá) |
| `internal/verify`, `verify`, `export -drafts` | `testbed/verify-check.sh` |
| `verify`, base cross-origin/ESM, `-page-scope`, `recycleTab`, FileChooser | `testbed/crosscheck-check.sh` |
| `internal/netsafe`, nguồn proxy, client archive | `testbed/proxy-check.sh` |
| Chống IP private lớp 1–3 (`guard/lan.go`, `capture/private.go`, `browser/lna.go`) | `testbed/lan-check.sh` |
| WebRTC / preference profile | `testbed/webrtc-check.sh` + `docker-check.sh` |

## Môi trường

- Go 1.25.4+ (hoặc `GOTOOLCHAIN=auto`), Google Chrome / Chromium (đã kiểm trên Chrome 156); chỉ chạy trên mục tiêu được phép (bug bounty / pentest hợp lệ), có rate-limit.
