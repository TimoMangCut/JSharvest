# GĐ5.2 — Container

**Mục tiêu** (`CLAUDE.md` "Đóng gói"; đánh giá độc lập đợt 4, mục 5.2). Có một image chạy được mọi lệnh:
- headless: `crawl`, `watch`, `diff`, `export`, `authz`, `replay`, `endpoints`, `mcp`;
- `login` có giao diện, qua Xvfb + noVNC, kể cả khi container chạy trên máy chủ từ xa.

Phiên bản Chrome và Go được ghim. Container chạy bằng user không phải root, và có `tini` làm PID 1.

## 1. Image

- **Build:** `golang:1.25.4-bookworm`, `CGO_ENABLED=0 GOTOOLCHAIN=local go build -trimpath`. Lấy module trước khi copy mã nguồn, để Docker cache được tầng này.
- **Chạy:** `debian:bookworm-slim` cộng:
  - `google-chrome-stable` **ghim đúng phiên bản** đang dùng khi phát triển: `156.0.8078.79-1`, tải từ `dl.google.com/linux/chrome/deb/pool/…`, phiên bản có trong `ARG CHROME_VERSION`;
  - `tini`;
  - `xvfb`, `x11vnc`, `novnc` + `python3-websockify` (cho `login`);
  - font: `fonts-liberation`, `fonts-noto-core`, `fonts-noto-cjk`, `fonts-noto-color-emoji` (trang tiếng Việt, CJK và emoji hiển thị đúng; layout ảnh hưởng tới toạ độ của explore);
  - `ca-certificates`.
- **User** `jsharvest` (uid/gid 1000). `/output` và `/profiles` thuộc user đó, quyền 0700, là `VOLUME`.
- **ENV:**
  - `JSHARVEST_OUTPUT=/output`, `JSHARVEST_PROFILES=/profiles`, `JSHARVEST_CHROME=/usr/bin/google-chrome-stable`;
  - `JSHARVEST_NO_SANDBOX=1`: sandbox namespace của Chrome cần `clone(CLONE_NEWUSER)`, mà seccomp mặc định của Docker chặn. Khi đó chính container là lớp cô lập. Gate kiểm cả hai cách (mục 4); muốn bật sandbox thì xem mục 3.
- **Không có ffuf hay sqlmap** trong bản này: build chúng là chạy mã bên ngoài, và môi trường phát triển chặn việc đó. `ARG WITH_TOOLS` để sau.

## 2. Entrypoint (`docker/entrypoint.sh`, chạy dưới `tini -g`)

- Tham số đầu là một lệnh của jsharvest (`crawl`, `login`…) thì chạy `jsharvest "$@"`; nếu không thì `exec "$@"` (`sh`, `id`…, để gỡ lỗi).
- **Màn hình ảo** được bật khi `JSHARVEST_DISPLAY=1`, hoặc khi lệnh là `login` mà không có `-steps` hay `-attach` (đăng nhập bằng tay):
  - `Xvfb :99 -nolisten tcp`;
  - `x11vnc -localhost` (chỉ loopback trong container), có mật khẩu: `JSHARVEST_VNC_PASSWORD`, hoặc ngẫu nhiên và in ra stderr;
  - `websockify` + noVNC trên cổng 6080 trong container. **Chỉ publish ra loopback của host**: `-p 127.0.0.1:6080:6080`. Muốn dùng từ xa thì qua SSH tunnel; README ghi rõ điều này.
- `tini -g` chuyển tín hiệu tới cả nhóm tiến trình: `docker stop` gửi SIGTERM tới jsharvest (nó lưu kết quả dở) và tới Xvfb, x11vnc; tiến trình mồ côi của Chrome được dọn.

## 3. Chạy

```
docker build -t jsharvest .
docker run --rm -v "$PWD/output:/output" -v "$PWD/profiles:/profiles" jsharvest crawl -u https://target/ -depth 1
docker run --rm -it -p 127.0.0.1:6080:6080 -v "$PWD/profiles:/profiles" jsharvest login -u https://target/login -role user
   # mở http://127.0.0.1:6080/vnc.html, đăng nhập, rồi nhấn Enter trong terminal
docker compose run --rm jsharvest diff -target target
```

`docker-compose.yml` thêm phần siết chặt:
- `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`;
- `/tmp` là tmpfs;
- `shm_size: 1g` (Chrome dùng `/dev/shm` khi bỏ `--disable-dev-shm-usage`);
- cổng 6080 chỉ trên `127.0.0.1`;
- `init: true` không cần vì image đã có tini.

Muốn bật sandbox của Chrome: chạy với một seccomp profile cho phép user namespace và đặt `JSHARVEST_NO_SANDBOX=0`.

## 4. Gate `testbed/docker-check.sh`

1. Build image; image chạy bằng uid 1000; `jsharvest help` chạy được; phiên bản Chrome đúng như đã ghim.
2. Crawl testbed (`--network host`) các app webpack-vanilla và vite-pwa: số marker ≥ baseline của bench (`bin/testbed score`). Ở host, file output thuộc uid 1000, quyền 0600/0700.
3. Chrome **có sandbox** (`JSHARVEST_NO_SANDBOX=0`) với seccomp mặc định: ghi lại là chạy được hay không, để xác nhận lý do của mặc định.
4. `docker stop` giữa lúc crawl: thoát trong vòng 10 giây, `run.json` được ghi (kết quả dở), không còn tiến trình zombie.
5. `login` bằng tay với noVNC:
   - `http://127.0.0.1:6080/vnc.html` trả 200;
   - x11vnc chỉ nghe trên loopback trong container;
   - Chrome chạy **có giao diện** trên `:99`;
   - Enter trên stdin → `login` lưu bản chụp phiên (quyền 0600), thoát 0.

   Việc đăng nhập thật qua noVNC là thao tác tay, ngoài phạm vi gate.
6. `login -steps` (session-app) chạy headless trong container; sau đó `crawl -role user` dùng lại phiên đó.

## 5. Kết quả (2026-11-04)

Gồm `Dockerfile`, `docker/entrypoint.sh`, `docker-compose.yml`, `.dockerignore`. Image `jsharvest` nặng 0,54 GB khi nén (1,87 GB khi giải nén; phần lớn là Chrome và font CJK).

**Gate `testbed/docker-check.sh`** (`NO_BUILD=1` để dùng image có sẵn):

| | Kết quả |
|---|---|
| 1. image | uid 1000; Chrome 156.0.8078.79 đúng như ghim; `help` chạy được |
| 2. crawl (`--network host`) | webpack-vanilla 19/20 và vite-pwa 10/10, bằng baseline của bench; file ở host thuộc uid 1000, quyền 0600 |
| 3. sandbox của Chrome dưới seccomp mặc định | **không khởi động được** (`namespace … Operation not permitted`): xác nhận lý do đặt `JSHARVEST_NO_SANDBOX=1` |
| 4. `docker stop` giữa lúc crawl | thoát sau chưa tới 1 giây, mã 130; `run.json` được ghi; không có zombie |
| 5. login bằng tay qua noVNC | noVNC trả 200 trên `127.0.0.1:6080`; VNC chỉ nghe trên loopback trong container; Chrome chạy có giao diện; Enter → bản chụp phiên 0600. "Người dùng đăng nhập" được giả lập bằng trang testbed `/dev/hand-login` |
| 6. `login -steps` rồi `crawl -role user` | đạt (không mất phiên, tới được trang của thành viên) |

**Hai lỗi của chính gate trong lúc làm:**
- container login chạy trên mạng bridge (để publish noVNC chỉ ra loopback), nên không tới được testbed ở `127.0.0.1` của host. Giờ testbed nghe trên IP gateway của bridge Docker;
- `login` từ chối lưu khi không ai đăng nhập. Đây là hành vi đúng, nên gate dùng thêm trang `/dev/hand-login`.

## 6. Đánh giá độc lập (2026-11-04) — có hiệu lực cao hơn mục 1–5

Reviewer đọc Dockerfile, entrypoint, compose và gate. Mình kiểm lại các điểm kiểm được, và đều đúng.

**Phải sửa:**
1. **`login` không có `-i` lưu phiên mà chưa ai đăng nhập:** `ReadString` trả về ngay khi gặp EOF (`docker run` không có `-i`, chạy với `-d`, CI). Giờ khi gặp EOF, `login` báo rằng không thể có Enter, rồi **chờ người dùng đóng tab**; không lưu gì trong lúc chờ. Gate có thêm kiểm tra này.
2. **Chrome đã ghim sẽ không tải được nữa:** kho `.deb` của Google chỉ giữ bản hiện hành (bản cũ trả 404); gate đạt chỉ vì Docker dùng tầng đã cache. Giờ dùng **Chrome for Testing** (giữ mọi phiên bản): `156.0.8078.79`, có kiểm SHA256, thư viện cài theo `deb.deps`. Base image ghim theo digest. Image được build lại **không dùng cache** trong gate.
3. **Volume khi uid khác 1000:** hỗ trợ `--user "$(id -u):$(id -g)"`; entrypoint dùng `HOME=/tmp/jsharvest-home` nếu thư mục home không ghi được; compose có `JSH_UID`/`JSH_GID`; tài liệu nhắc `mkdir -p output profiles`. Gate chạy thêm với uid 1234.

**Nên sửa (đã làm):**
4. **noVNC và X:**
   - Xvfb có cookie xauth và `-nolisten local`, nên không còn abstract socket (với `--network host`, abstract socket nằm chung namespace mạng với host, và mọi tiến trình của host gõ phím vào được);
   - noVNC chỉ nghe trên `127.0.0.1` khi container dùng mạng của host (nhận ra bằng việc thấy `docker0`); `JSHARVEST_NOVNC_LISTEN` để đổi;
   - mật khẩu VNC đúng 8 ký tự, vì giao thức chỉ kiểm 8 ký tự đầu.
5. Entrypoint kiểm Xvfb, x11vnc và websockify đã sống và đang nghe; nếu không thì in log và thoát (ví dụ khi chạy login thứ hai trên mạng của host).
6. **Sandbox:** đã thử, **sandbox của Chrome chạy được** với `seccomp=unconfined` kèm `no-new-privileges` và `--cap-drop ALL`, kể cả trên host bật `apparmor_restrict_unprivileged_userns=1`.
   - Entrypoint tự phát hiện bằng `unshare -U -r -p -n`: được thì bật sandbox, không thì `--no-sandbox` kèm cảnh báo.
   - Compose bật sẵn cấu hình có sandbox. Lý do: với trang có thể độc hại, sandbox của Chrome (namespace cộng seccomp-bpf riêng cho mỗi renderer) là lớp chắn mạnh hơn seccomp của container.
   - Vẫn nên chỉ mount `/profiles` của target đang làm, và cập nhật Chrome thường xuyên.
7. **Tín hiệu:** bỏ `tini -g`. Chrome chạy trong **nhóm tiến trình riêng** (`Setpgid` qua `chromedp.ModifyCmdFunc`, vẫn giữ `Pdeathsig`), nên Ctrl-C hay `docker stop` chỉ tới jsharvest, và jsharvest đóng Chrome theo thứ tự. Lỗi này **có cả ngoài container**: Ctrl-C trong terminal gửi tín hiệu tới Chrome cùng lúc với jsharvest. Đã thử: SIGINT gửi cho cả nhóm → `stopped=interrupted`, lưu đủ `run.json`, `flows.jsonl`, `endpoints.jsonl`, không còn Chrome nào sót lại.
8. Compose đặt `hostname: jsharvest` cố định, vì khoá của profile Chrome ghi tên host.
9. Compose bỏ `shm_size` (Chrome đã có `--disable-dev-shm-usage`), cho `/tmp` dung lượng cố định (`size=2g`), bỏ `tty`. Gate chạy thử compose (bước 7).
10. **`watch -attach` vào Chrome trên host** cần `--network host`, vì cổng debug của Chrome chỉ nghe trên `127.0.0.1` và từ chối `Host` khác. Khi đó một renderer bị khai thác (nếu chạy `--no-sandbox`) sẽ tới được CDP của Chrome thật trên host. Đây thêm một lý do để bật sandbox.

**Để sau:**
- tài liệu về `-proxy` qua `host.docker.internal`, CA của Burp (cần `libnss3-tools`), `TZ` và `--lang` để khớp với lúc login, DNS nội bộ (`--network host` hoặc `-host-resolver-rules`);
- `ARG WITH_TOOLS` (ffuf, sqlmap).

## 7. Kết quả sau đánh giá (2026-11-04)

Image build lại **không dùng cache**: Chrome for Testing 156.0.8078.79 (kiểm SHA256), base image ghim theo digest, nặng 0,52 GB khi nén.

**Gate `testbed/docker-check.sh`, 7 bước đều đạt:**
1. image: uid 1000, Chrome đúng như ghim, `help` chạy được.
2. crawl: webpack-vanilla 19/20, vite-pwa 10/10; file 0600 và thư mục 0700, thuộc uid 1000; với `--user 1234:1234` thì thư mục thuộc 1234, quyền 0700.
3. seccomp mặc định → `--no-sandbox` kèm cảnh báo; `seccomp=unconfined` + `no-new-privileges` + `--cap-drop ALL` → "Chrome sandbox: on".
4. `docker stop` → thoát ngay, mã 130, `run.json` được ghi, không có zombie.
5. login bằng tay:
   - noVNC trên `127.0.0.1:6080`;
   - VNC chỉ nghe trên loopback (`tcp` và `tcp6`);
   - Xvfb không có abstract socket;
   - Chrome chạy có giao diện;
   - Enter → bản chụp phiên 0600;
   - không có `-i` → báo "stdin is closed", chờ đóng tab, không lưu gì.
6. `login -steps` → `crawl -role user`.
7. `docker compose run`: sandbox của Chrome bật, vite-vanilla 10/10. vite-vanilla được chọn vì compose chạy trên mạng bridge và target ở IP gateway: http trên IP không phải localhost thì không phải secure context, nên service worker không đăng ký được (webpack-vanilla chỉ đạt 16/20 ở đó, do trình duyệt chứ không do container).

**Gate bắt thêm ba lỗi:**
- `apt-get purge --auto-remove curl` gỡ luôn noVNC (qua chuỗi phụ thuộc). Giờ chỉ gỡ `unzip`.
- **Thư mục output là 0755** (jsharvest tạo bằng `MkdirAll(…, 0o755)` ở `batch.go`, `store.go`, `endpoints.go`), dù file bên trong là 0600. Giờ là 0700. Thư mục đã có từ trước giữ nguyên quyền cũ.
- Gate tự kiểm sai thư mục 0700 của uid khác.
