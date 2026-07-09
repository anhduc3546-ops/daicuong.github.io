# Tổng hợp CTF Writeup

---

## Phần 1: Yet another PDF converter (ĐÃ GIẢI XONG)

**Target:** `http://txg.chal2.teagod.tech:8722/`

### Mô tả
Dịch vụ nhận URL, render trang thành PDF. Frontend: form HTML đơn giản, gọi `POST /convert` với body `application/x-www-form-urlencoded` gồm field `url` và (nếu bật) `g-recaptcha-response`. Backend: **Express (Node.js)**, dùng thư viện `html-pdf-node` để convert — bên dưới thư viện này chạy **Chromium headless** (xác nhận qua `Producer: Skia/PDF m149` trong file PDF xuất ra), KHÔNG phải WeasyPrint như đoán ban đầu.

### Quá trình
1. Dò SSRF bằng cách trỏ `url` về server tự host qua tunnel (`localhost.run`) — xác nhận server tự fetch được URL do người dùng nhập.
2. Thử kỹ thuật LFI kiểu WeasyPrint (`<a rel="attachment" href="file://...">`) — **không hoạt động** vì engine thật là Chromium, không phải WeasyPrint (kiểm tra bằng `grep -a "Producer" output.pdf`).
3. Do bị Chromium xử lý, đổi hướng: cho tham số `url` trỏ thẳng `file:///etc/passwd` — Chromium **navigate trực tiếp vào file local** và render nội dung ra PDF. Bypass được regex check phía client (chỉ chặn `^https?://`) bằng cách gọi thẳng `fetch('/convert', ...)` qua DevTools Console thay vì submit form.
4. Đọc được `/etc/passwd`, phát hiện user đặc biệt: `ctf:x:1337:1337::/home/ctf:/bin/sh` và `node:x:1000:1000::/home/node:/bin/bash`.
5. Do captcha bắt buộc và **token dùng một lần**, phải tick captcha lại trước mỗi lần thử path mới (xác nhận qua test: gọi 2 request liên tiếp cùng token → request thứ 2 bị `400`).
6. Dùng oracle: gọi `/convert` với `file://<path>` — **status 200 = file tồn tại và đọc được, status 500 = không tồn tại/lỗi**.
7. Đọc `/proc/self/cwd/package.json` → biết entry point là `server.js`, thư viện `html-pdf-node` nằm local tại `../lib/html-pdf-node`.
8. (Đang dở: chưa đọc được `server.js` hay tìm ra path flag chính xác — captcha 400 do chưa tick lại trước khi gọi.)

### Script khai thác dùng trong DevTools Console
```javascript
async function tryOne(path) {
  const res = await fetch('/convert', {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: new URLSearchParams({ url: 'file://' + path, 'g-recaptcha-response': grecaptcha.getResponse() })
  });
  console.log(path, '->', res.status);
  if (res.status === 200) {
    const blob = await res.blob();
    const u = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = u; a.download = 'FOUND.pdf'; a.click();
  }
}
```
**Lưu ý quan trọng:** phải tick lại captcha (click ô "I'm not a robot", chờ tick xanh) trước MỖI lần gọi `tryOne()`, vì token single-use.

### Trạng thái: cần làm tiếp
- Tick captcha, chạy `tryOne('/proc/self/cwd/server.js')` để đọc source code thật, từ đó xác định chính xác path lưu flag.
- Nếu không đọc được, thử tiếp: `/home/ctf/flag`, `/flag`, `/flag.txt`, `/home/node/flag`, v.v. (mỗi lần 1 tick captcha).

---

## Phần 2: Confused Component (ĐANG GIẢI, CHƯA XONG)

**Target instancer:** `http://chal3.teagod.tech:9000/` → mỗi lần bấm cấp 1 instance riêng (port thay đổi liên tục, ví dụ hiện tại: `http://chal3.teagod.tech:34592/`)

### Mô tả đề bài
> Component Vault moved its authentication logic into a portable component.
> The previewer treats a path as data. The loader treats it as something else.
> Start an instance from the instancer, then find the flag.

Gợi ý cốt lõi: có 2 module xử lý cùng 1 chuỗi input theo 2 cách khác nhau (type confusion) — cần tìm chỗ lệch pha để khai thác.

### Thông tin đã thu thập được

**`/api/info`** trả về:
```json
{
  "auth_engine": "wit-component/v2",
  "component": {"default_name": "auth", "loader": "enabled"},
  "preview_handlers": ["static"],
  "server_time": ...,
  "team": "..."
}
```
- Hệ thống liên quan đến **WebAssembly Component Model** (`wit-component` — công cụ thật của Bytecode Alliance).
- Có 1 "loader" đang bật (`enabled`), component mặc định tên `auth`.
- Chỉ có 1 handler preview được công khai: `static`.

**Server backend:** Python `BaseHTTPServer` viết tay (header `Server: BaseHTTP/0.6 Python/3.12.13`) — route được match thủ công trong code, không phải framework chuẩn (Flask/Express), nên không đoán route theo quy ước thông thường.

**Route đã xác nhận tồn tại:**
- `GET /` — trang chủ tĩnh
- `GET /api/info` — thông tin service
- `GET /preview?file=X;handler=Y` — chỉ hiển thị lại cách nó **tách chuỗi** (không thực thi gì thật): trả về JSON `{"handler": Y, "normalized": X, "requested": "X;handler=Y"}`. Chấp nhận **bất kỳ giá trị handler nào** kể cả không tồn tại (`loader`, `component`, `abc`... đều ra 200), không validate.
- `GET /assets/<file>` — route serve file thật, có "asset not found" nếu sai tên
- `GET /assets/<file>;handler=Y` — có validate handler thật: `handler=static` → 200 (trả nội dung file), handler khác (`loader`, `component`...) → **404 "handler not found"**.

**Route KHÔNG tồn tại (thử và ra "not found"):**
`/load`, `/api/load`, `/component`, `/api/component`, `/loader`, `/api/loader`, `/auth`, `/api/auth`, `/instantiate`, `/api/instantiate`, `/run`, `/api/run`, `/exec`, `/api/exec`, `/wasm`, `/api/wasm`, `/component/auth`, `/components/auth`, `/manifest`, `/status`, `/health`

**Path traversal trên `/assets/`:**
- `../` chuẩn (`/assets/../server.py`) → **"not found"** (không có chữ "asset") — khác với file thường không tồn tại, gợi ý có 1 lớp normalize riêng xử lý `../` trước khi match route, đẩy path ra ngoài phạm vi `/assets` nên không khớp route nào cả.
- `....//`, `%2e%2e%2f`, `..%2f` → **"asset not found"** (có chữ "asset") — nghĩa là các biến thể này VẪN khớp route `/assets/` (không bị chặn bởi lớp normalize kia), nhưng file đích không tồn tại hoặc bị chặn ở lớp khác.
- `//etc/passwd` (double slash) → vẫn "asset not found", chưa rõ do bị HTTP layer tự gộp `//` thành `/` trước khi tới code, hay do bị chặn thật.
- `%2Fetc%2Fpasswd` (encoded slash) → vẫn "asset not found".

**Test cú pháp tên component kiểu WASM (namespace:package@version):**
- `/preview?file=vault:auth;handler=loader`, `auth:auth`, `vault:auth@1.0.0`, `..:..` — tất cả chỉ phản hồi y nguyên, xác nhận `/preview` **không hề xử lý logic thật**, chỉ tách chuỗi tại dấu `;` để lấy `handler`, phần còn lại giữ nguyên làm `normalized`. Đây không phải nơi chứa lỗ hổng thật — chỉ là công cụ debug/hiển thị.

### Hướng suy luận hiện tại (chưa xác nhận)
- "Loader" thật (khác `/preview`, khác handler trong `/assets/`) có thể là 1 cơ chế **hoàn toàn riêng biệt** dùng để nạp component `auth` phục vụ xác thực — có thể được kích hoạt qua 1 route/method/header khác chưa tìm ra.
- Nghi vấn: "auth_engine: wit-component/v2" gợi ý có luồng xác thực (login/verify) riêng dùng chính "loader" để nạp logic từ 1 "component" — cần tìm route xác thực (`/login`, `/api/verify`, v.v. — **đang test dở, chưa có kết quả**).

### Việc cần làm tiếp
1. Chạy các lệnh test route xác thực còn dang dở:
   ```bash
   curl -s -m 5 -w "[%{http_code}]\n" http://chal3.teagod.tech:34592/login
   curl -s -m 5 -w "[%{http_code}]\n" http://chal3.teagod.tech:34592/api/login
   curl -s -m 5 -w "[%{http_code}]\n" http://chal3.teagod.tech:34592/api/verify
   curl -s -m 5 -w "[%{http_code}]\n" http://chal3.teagod.tech:34592/api/auth
   curl -s -m 5 -w "[%{http_code}]\n" http://chal3.teagod.tech:34592/verify
   curl -s -m 5 -w "[%{http_code}]\n" http://chal3.teagod.tech:34592/token
   curl -s -m 5 -w "[%{http_code}]\n" "http://chal3.teagod.tech:34592/api/verify?component=auth"
   ```
2. Nếu vẫn không ra, cân nhắc: thử method `POST` thay vì `GET` trên các route nghi vấn (`/api/verify`, `/api/auth`), vì auth thường dùng POST.
3. Note quan trọng khi thao tác: **instance chết sau một thời gian hoặc sau khi bị gửi dồn dập nhiều request lạ liên tiếp** (từng bị `000`/connection refused 2 lần) — nên giữ khoảng nghỉ (`sleep 1`) giữa các request, và nếu instance chết, quay lại `http://chal3.teagod.tech:9000/` lấy port mới rồi tiếp tục.
4. Đã tìm kiếm web nhưng **không có writeup công khai nào** cho challenge này (là đề mới, thuộc "No Hack No CTF 2026" — sự kiện gần đây, chưa có ai viết bài giải).
