# GĐ4 4.5 — Login, session và khôi phục

**Mục tiêu.** Plan bản 2 mục 4.5, cộng bản 1 mục 4.3: đăng nhập một lần cho mỗi role, crawl bằng session đó, phát hiện khi mất session, khôi phục rồi crawl tiếp. Nếu không khôi phục được thì dừng, giữ kết quả và báo rõ.

**Cổng nghiệm thu:** role admin đạt 56/56 marker trên 5 app gốc; fixture mất session được phát hiện, khôi phục, rồi crawl tiếp.

## 1. Sự thật về Chrome quyết định thiết kế

- **Persistent profile không đủ.** Cookie phiên (không có `Expires`/`Max-Age`) mất khi Chrome đóng, kể cả khi dùng `--user-data-dir`. `sessionStorage` thì không bao giờ được lưu. Vì vậy `login` **chụp lại** cookie và cả hai loại storage, và `crawl` **nạp lại** chúng.
- **Storage được nạp lại bằng script chạy trước mọi script của trang** (`Page.addScriptToEvaluateOnNewDocument`, có tag `jsharvest-internal`). Script này chỉ điền những key còn thiếu và chỉ cho đúng origin của nó. Cùng một cơ chế phục vụ lúc bắt đầu crawl và sau `Clear-Site-Data`: trang kế tiếp có lại storage.
- **Cookie được nạp lại bằng `Storage.setCookies`** ở cấp browser, không cần tải trang nào.

## 2. `jsharvest login`

```
jsharvest login -u URL [-role R] [-profile DIR | -profiles ROOT] [-check-url URL] [-check-text T]
                (mặc định: Chrome có giao diện, người dùng tự đăng nhập rồi nhấn Enter)
                | -steps FILE   (kịch bản: goto/type/click/wait; giá trị ${ENV} lấy từ biến môi trường, không lưu)
                | -attach URL   (chụp từ Chrome người dùng đang mở và đã đăng nhập)
```

**Profile:** mặc định `profiles/<host>/<role>`.

**`jsharvest-session.json`** (quyền 0600) gồm:
- `login_url`: URL mở ra để đăng nhập;
- `final_url`;
- cookie trong scope;
- storage theo origin;
- dấu hiệu đã đăng nhập;
- đường dẫn kịch bản (nếu có), để tự đăng nhập lại. Mật khẩu không được lưu: kịch bản dùng `${ENV}`.

**Dấu hiệu đã đăng nhập** được tự suy ra từ các cookie xuất hiện hoặc thay đổi trong lúc đăng nhập. Có thể thêm `-check-url` (phải trả 2xx), mặc định là URL cuối, và `-check-text`. Ở chế độ có giao diện, ảnh chụp được lấy mỗi 2 giây, nên người dùng đóng cửa sổ trước khi nhấn Enter cũng không mất.

## 3. Crawl bằng session

`crawl -u URL -role R` tự dùng `profiles/<host>/<role>` nếu thư mục đó có `jsharvest-session.json`; cũng có thể chỉ định bằng `-profile DIR`. Guard tự bật. Khi bắt đầu:
1. nạp lại cookie và script storage;
2. **kiểm tra dấu hiệu** (cookie và `check-url`). Nếu không đạt và có kịch bản thì đăng nhập lại; nếu vẫn không được thì dừng ngay với mã thoát 4.

## 4. Phát hiện và khôi phục

**Tín hiệu** (kiểm tra sau mỗi trang):
- capture thấy `Clear-Site-Data`;
- cookie dấu hiệu biến mất;
- document chính quay về `login_url` (theo path), hoặc trả 401/403.

**Khôi phục:**
1. Nạp lại cookie (script storage đã có sẵn).
2. Kiểm tra lại dấu hiệu.
3. Nếu chưa được và có kịch bản: đăng nhập lại trong một tab mới (guard vẫn bật; request POST login được phép **chỉ** cho đúng `login_url` và endpoint mà kịch bản gọi tới, xem mục 6), chụp lại session, thay script storage, rồi kiểm tra lại.
4. Thành công thì **thăm lại** trang đang dở rồi tiếp tục. Thất bại thì dừng frontier và ghi `run.json.session` (mã thoát 4).

**Giới hạn:** tối đa 5 lần khôi phục mỗi run. Trang đã thăm không bị thăm lại, nên một trang làm mất session (`/account/privacy`) không gây vòng lặp.

## 5. Fixture và gate

- **Testbed server có session thật.** Token được lưu phía server, `/api/me` trả 401 khi không có session. Cookie `role` vẫn giữ để các app cũ không đổi.
- **`session-app`:**
  - `/login` (form chạy bằng JS, ghi `localStorage.auth` và `sessionStorage.tab`);
  - các trang `/app/*` do server chặn khi chưa đăng nhập; mỗi trang có marker;
  - `/app/c` chỉ tải chunk khi có `localStorage.auth`; `/app/d` chỉ tải khi có `sessionStorage.tab`;
  - `/account/privacy` gửi `Clear-Site-Data: "cookies","storage"`;
  - `/account/expire` xoá session phía server.
- **Gate `testbed/session-check.sh`:**
  - `login -steps` đạt; `crawl -depth 2` thấy đủ marker sau khi có các sự kiện wipe (khôi phục) và expire (đăng nhập lại);
  - bản không có kịch bản: dừng ở expire với mã thoát 4 và có `session_lost`;
  - **admin 56/56:** đăng nhập admin vào `webpack-vanilla` bằng form của chính nó, rồi `crawl -depth 2` 5 app gốc.

## 6. An toàn

- **Kịch bản login là thao tác ghi duy nhất được phép**, và chỉ trong lúc login hoặc đăng nhập lại. Tool chạy kịch bản đó bằng một guard mở rộng: cho phép POST tới endpoint login mà kịch bản gửi trong lúc chạy, và chỉ trong khoảng thời gian đó.
- **`jsharvest-session.json` chứa cookie thật** nên có quyền 0600. README phải nói rõ điều này.
- **Không khôi phục trong `watch`.** Tab đó là session của người dùng; nếu session mất thì chỉ báo.

## 7. Sửa đổi khi làm

- **Profile giữ cả bộ nhớ đệm của app, không chỉ phiên đăng nhập.** Phát hiện ở phần admin của gate (lần đầu 43/56):
  - service worker được cài ngay ở lần `login`, nên lần crawl sau không thấy `sw.js` được tải;
  - 5 app testbed dùng chung origin, nên HTTP cache trả `index.html` của app trước cho app sau.

  Cách sửa: khi cài session, xoá service worker, CacheStorage (`Storage.clearDataForOrigin`) và HTTP cache (`Network.clearBrowserCache`), nhưng giữ cookie và localStorage. Lý do sản phẩm: một lần crawl phải thấy những gì server đang phục vụ bây giờ, nhất là cho việc theo dõi phiên bản JS sau này.
  - **Bẫy:** gọi `Storage.clearDataForOrigin` ở **cấp browser** trả `Internal error (-32603)`. Phải gọi trên session của tab.
- **Trang login được thăm chủ động.** Frontier đi theo link tới `/login`, và keeper đã coi đó là mất session. Giờ trang login chỉ là dấu hiệu mất session khi ta không định tới nó.
- **Trang cache che mất việc session đã chết.** Sau khi server huỷ session, lần thăm lại đi theo 302 và nhận `/members/home` **từ HTTP cache**, nên trông như vẫn đăng nhập. Hai cách sửa:
  - fixture gửi `Cache-Control: no-store` cho trang đã xác thực, như app thật;
  - phép kiểm `check-url` của jsharvest dùng `fetch(…, {cache: "no-store"})`, để câu trả lời phải đến từ server.
- **Kiểm tra sau khi khôi phục** không chỉ xem cookie còn hay không. Sau khi server huỷ session, cookie cũ vẫn có mặt mà đã vô hiệu, nên trang vừa tải lại cũng không được là trang login và không được trả 401/403.
- **Thăm lại một lần** trang mà sau khi thăm thì mất session, vì session có thể tự hết hạn. Nếu lại mất session ngay sau khi thăm lại, trang đó bị coi là chính nó kết thúc session (như wipe và expire), và không được thăm lại nữa. Tối đa 10 lần khôi phục mỗi run.

## 8. Kết quả

Gate `testbed/session-check.sh`:

| Phần | Kết quả |
|---|---|
| 1. `session-app`, login bằng kịch bản, `crawl -depth 2` | wipe khôi phục 2 lần, expire đăng nhập lại 2 lần, không mất session; mọi marker của thành viên đều có, gồm `storage:local` (sau wipe) và `storage:session` (thứ không profile nào giữ được). Ảnh chụp có quyền 0600 và không chứa mật khẩu |
| 1b. Crawl bắt đầu khi session ở server đã chết (đo bằng tay) | đăng nhập lại ngay trước trang đầu tiên |
| 2. Cùng login nhưng không có kịch bản | dừng ở expire, **mã thoát 4**, `session.lost` có lý do; các trang sau đó không được thăm |
| 3. Request ghi | chỉ `POST /api/login` của các lần login và đăng nhập lại, qua `Guard.AllowWrites` của đúng tab đó |
| 4. Role admin, 5 app gốc, `-depth 2` | **55/56** (webpack 20, vite 10, vite-pwa 10, next 8/9, angular 7). Marker thiếu là `next-mixed route:hidden-app`: không có link, không có trong manifest, chuỗi `vault` chỉ có trong chính trang đó. Chỉ tìm được bằng đoán đường dẫn, nên đây là trần khi chưa có tính năng thăm dò theo wordlist. Cổng 56/56 của plan **chưa đạt** vì lý do này |

## 9. Giới hạn

- **Chế độ có giao diện** (người dùng tự đăng nhập) cần màn hình và chưa được kiểm thử tự động; nó dùng cùng phần chụp session với hai chế độ kia. Trong container sẽ cần Xvfb và noVNC (GĐ5).
- **Không có TOTP hay OTP** trong kịch bản. Nếu cần thì dùng `-attach` vào Chrome đã đăng nhập.
- **`-urls` không dùng session**; `watch` không khôi phục session (đó là session của người dùng).
- **Đăng nhập lại diễn ra trong tab crawl**, nên request login có trong `requests.jsonl` và `flows.jsonl` như một hành động `load`.
- **Session đăng nhập qua IdP bên thứ ba** (SSO khác domain): cookie của IdP nằm ngoài scope nên không được lưu. Khôi phục bằng cookie của app vẫn được; đăng nhập lại thì phụ thuộc vào kịch bản.
