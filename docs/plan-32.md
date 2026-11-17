# Kế hoạch Thực thi Đợt 32 (`jsharvest` — Tối ưu Hiệu năng, Đồng bộ An toàn & Mở rộng Giao thức Web Hiện đại)

Tài liệu thiết kế và theo dõi nghiệm thu cho **Đợt 32** (tiếp nối Đợt 31 [plan-31.md](plan-31.md), đối chiếu các bất biến tại [CLAUDE.md](../CLAUDE.md) và [CURRENT.md](CURRENT.md)).

## 1. Phạm vi & Quyết định Kiến trúc

1. **Giữ nguyên mô hình Scope `D2` (`App-Referenced = In-Scope`):** Mọi tài nguyên hoặc API mà ứng dụng trực tiếp nạp hoặc gọi đều được giữ `in-scope`; chỉ lọc thêm các miền SaaS/captcha/embed dùng chung khỏi `nonAPIInfraDomains` (`P1.3`) để tránh chiếm slot Spec Probe.
2. **Không đại phẫu tách `internal/engine` / `internal/jsapi` đơn lẻ & không chuyển JSONL sang SQLite/`bbolt`:** `results.Open` đã có cơ chế chỉ mục byte-offset tăng dần (`57.000` request chiếm `~164 MB` RSS). Toàn bộ phần mở rộng giao thức mới của Phase P3 được cô lập vào các tệp riêng (`internal/flow/rpc.go`, `internal/jsapi/modern_rpc.go`, `internal/jsapi/gql.go`) kèm guard `bytes.Contains` chi phí `0 ns` khi script không dùng giao thức tương ứng.
3. **Tối ưu công suất MCP `get_authz` (`P1.6`):** Giữ `mode` nghiêm ngặt `"peers"` | `"roles"` (mỗi lời gọi đọc tối đa 1 tệp JSON), bổ sung lọc sớm `direction` và `role` trước `Total++` và `maskAuthz`.
4. **Nâng `jsapi.Version` một lần duy nhất (`38 -> 39`) ở `P4.1`:** Gom toàn bộ thay đổi trích xuất tĩnh của Phase P3 vào một mốc nâng phiên bản cache duy nhất.

---

## 2. Bảng Tiến độ, Commit & Bộ Gate Nghiệm thu

| Mã | Commit | Hạng mục | Tệp chạm chính | Gate bắt buộc trên máy Linux | Trạng thái |
|---|---|---|---|---|---|
| **P1.1** | `fc8877a` | Xoá parse AST đúp `httpcrawl` -> `endpoints.Analyze` (`ExtractCached` `0600`) + lọc sớm `Vendor`/`Tracker`/`Infra` ở `Depth == 0` | [crawl.go](../internal/httpcrawl/crawl.go), [endpoints.go](../internal/endpoints/endpoints.go), [http.go](../internal/engine/http.go) | `pipeline-check.sh`, `endpoints-check.sh`, `perfgate` | `[x]` |
| **P1.2** | `a45623f` | Tách Cross-origin Spec Probe qua `netsafe` (tránh CORS preflight trên `client_headers`), vá cầu chì `D3` trên `neterr`, tái sử dụng `resolve.Policy` | [specprobe.go](../internal/engine/specprobe.go), [frontier.go](../internal/engine/frontier.go), [crawl.go](../internal/httpcrawl/crawl.go) | `frontier-check.sh`, `waf-check.sh`, `proxy-check.sh` | `[x]` |
| **P1.3** | `e63ffe2` | Bổ sung SaaS/captcha/embed dùng chung vào `nonAPIInfraDomains` (giữ nguyên serverless `execute-api`, `run.app`, `workers.dev`) | [queue.go](../internal/frontier/queue.go) | `frontier-check.sh`, `pipeline-check.sh` | `[x]` |
| **P1.4** | `c38a7f9` | Thay đệ quy `QueryUnescape` không trần trong `reflector.hit` bằng vòng lặp phẳng tối đa 2 lớp (`len <= 8192`) | [judge_peer.go](../internal/replay/judge_peer.go) | `bola-check.sh`, `replay-check.sh` | `[x]` |
| **P1.5** | `9535a52` | Đồng bộ `resolve.Policy` sang `netsafe.RefuseHost` / `LiteralHost` / `PrivateAddr` (giữ nguyên hành vi `noDNS`) | [policy.go](../internal/resolve/policy.go) | `proxy-check.sh`, `lan-check.sh`, `pipeline-check.sh`, `frontier-check.sh` | `[x]` |
| **P1.6** | `3c69b5f` | MCP `get_authz` lọc sớm (`direction`, `role`) trước `maskAuthz` + bổ sung khoá chủ sở hữu `user` / `user_created` trong `privateMarker` | [authz.go](../internal/mcpserver/authz.go), [judge_peer.go](../internal/replay/judge_peer.go), [gd7-bola-design.md](gd7-bola-design.md) | `bola-check.sh`, `flows-gate.sh` (`MCP=1`) | `[x]` |
| **P1.7** | `8169b6b` | Đồng bộ macOS native (`uahints` đường dẫn Chrome `.app`, `Setpgid` tránh giết sớm Chrome khi `Ctrl+C`, đổi đơn vị `Maxrss` Darwin ở `perfgate`) | [uahints.go](../internal/uahints/uahints.go), [proc_unix.go](../internal/browser/proc_unix.go), [perfgate.go](../testbed/cmd/testbed/perfgate.go) | `go test -race ./internal/uahints/... ./internal/browser/...` | `[x]` |
| **P2.1** | — | Kiểm chứng thực địa `D3` & đóng `P5.T` trên target được phép | Không sửa code (ghi nhận số liệu khi chạy thực địa) | Kiểm thủ công trên target được cấp phép | `[ ]` *(chờ chạy thực địa)* |
| **P3.1** | `c299bba` | Next.js App Router Server Actions (`Next-Action` / `$ACTION_ID_<hex>`) tĩnh & động + giải mã RSC Flight `text/x-component` | [rpc.go](../internal/flow/rpc.go), [modern_rpc.go](../internal/jsapi/modern_rpc.go), [compare.go](../internal/replay/compare.go), [draft.go](../internal/verify/draft.go) | `flows-gate.sh`, `export-check.sh`, `bola-check.sh` | `[x]` |
| **P3.2** | `e4853ec` | tRPC `v10`/`v11` tĩnh (`@trpc/client`, `@trpc/react-query`) & tách lô `?batch=1` (`GET` query JSON leaf spans + `POST`), bảo vệ `/trpc/<proc>` trong `Templates` | [rpc.go](../internal/flow/rpc.go), [parse.go](../internal/export/parse.go), [patch.go](../internal/replay/patch.go), [modern_rpc.go](../internal/jsapi/modern_rpc.go) | `export-check.sh`, `bola-check.sh`, `endpoints-check.sh` | `[x]` |
| **P3.3** | `2c3e036` | Trích xuất `GraphQLDoc` từ `gql` / `graphql()` / `Document` (kèm nội suy fragment tĩnh) + tổng hợp thân JSON cho `verify` (tự skip `mutation`/`subscription` khi thiếu `-allow-write`) | [gql.go](../internal/jsapi/gql.go), [endpoints.go](../internal/endpoints/endpoints.go), [draft.go](../internal/verify/draft.go), [verify.go](../internal/verify/verify.go) | `verify-check.sh`, `export-check.sh`, `endpoints-check.sh` | `[x]` |
| **P3.4** | `89667ae` | ConnectRPC (`@connectrpc/connect`) & `grpc-web` (`MethodDescriptor`) tĩnh + bảo vệ đường dẫn `/<pkg.Service>/<Method>` + chặn hỏng khung nhị phân 5-byte proto | [modern_rpc.go](../internal/jsapi/modern_rpc.go), [rpc.go](../internal/flow/rpc.go), [parse.go](../internal/export/parse.go), [patch.go](../internal/replay/patch.go) | `endpoints-check.sh`, `flows-gate.sh`, `bola-check.sh` | `[x]` |
| **P4.1** | `HEAD` | Nâng `jsapi.Version = 39`, đồng bộ tài liệu & qua toàn bộ unit race tests + `perfgate` + CI hygiene | [jsapi.go](../internal/jsapi/jsapi.go), [CLAUDE.md](../CLAUDE.md), [CURRENT.md](CURRENT.md), [rounds-history.md](rounds-history.md) | `DOCKER=1 testbed/regress.sh -j 3` + `JSAPI_SNAPSHOT` trên máy Linux | `[x]` |

---

## 3. Quy trình Kiểm tra Lại trên Máy Linux (`pull` từ `main`)

Sau khi `git pull origin main` trên máy Linux có Chrome & `unshare -rn`:

```bash
# 1. Mở quyền userns trên Ubuntu 24.04+ (nếu vừa reboot)
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0

# 2. Chạy toàn bộ unit test với race detector + perfgate
go vet ./...
go test -race ./...
go build -o bin/jsharvest ./cmd/jsharvest
go build -o bin/testbed ./testbed/cmd/testbed
./bin/testbed perfgate -bin ./bin/jsharvest

# 3. Chạy toàn bộ 24 gate tích hợp (netns + Chrome + Docker)
DOCKER=1 testbed/regress.sh -j 3
```
