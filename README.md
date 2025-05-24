<h1 align="center">Ứng dụng Truyền File Chữ Ký Số An Toàn (Web-based Secure Digital Signature File Transfer Application) </h1>


##  🌟 Giới thiệu chi tiết 

Ứng dụng "Truyền File Chữ Ký Số An Toàn" là một giải pháp minh họa mạnh mẽ cho quá trình truyền tải dữ liệu qua mạng TCP/IP, được tăng cường bởi tính năng chữ ký số để đảm bảo đồng thời **tính toàn vẹn (Integrity)** của dữ liệu và **tính xác thực (Authenticity)** của người gửi. Được phát triển trên nền tảng Python, ứng dụng này sử dụng framework **Flask** để cung cấp giao diện web thân thiện, kết hợp với thư viện **Flask-SocketIO** cho giao tiếp thời gian thực giữa trình duyệt và server Python, và thư viện **`cryptography`** - một bộ công cụ mã hóa mạnh mẽ của Python - để xử lý các tác vụ mật mã phức tạp như tạo khóa RSA, băm SHA256 và ký/xác minh chữ ký số.

Mục tiêu chính của ứng dụng là mô phỏng một kịch bản truyền file trong đó người gửi (Client) muốn đảm bảo rằng file của mình không bị sửa đổi trên đường truyền và người nhận (Server) có thể xác minh được nguồn gốc đáng tin cậy của file. Thay vì chỉ đơn thuần gửi file, ứng dụng sẽ tạo ra một "chữ ký số" độc đáo cho file đó, đính kèm chữ ký này vào file và gửi đi. Khi server nhận được, nó sẽ kiểm tra chữ ký số để khẳng định rằng file vẫn nguyên vẹn và đúng là do người gửi mong muốn.

Ứng dụng này rất phù hợp cho mục đích giáo dục, thử nghiệm các nguyên lý mật mã học cơ bản trong an toàn thông tin, hoặc làm nền tảng cho các dự án truyền dữ liệu bảo mật nhỏ.


## ⚙️Tính năng chính (Key Features)

Ứng dụng "Truyền File Chữ Ký Số An Toàn" cung cấp các tính năng sau:
- Server TCP/IP Đa Luồng: Khởi động server TCP để nhận file, có khả năng xử lý nhiều kết nối client cùng lúc.
- Client Truyền File Giao Diện Web: Giao diện web trực quan cho phép người dùng chọn và gửi file dễ dàng.
- Chữ Ký Số RSA:
    - Ký số: Băm file bằng SHA256 và ký bằng khóa riêng RSA.
    - Xác minh: Server băm lại file và dùng khóa công khai để xác minh chữ ký, đảm bảo tính toàn vẹn và xác thực của dữ liệu.
- Quản Lý Khóa Tự Động: Tự động tạo hoặc tải cặp khóa RSA (private_key.pem, public_key.pem).
- Giao Diện Web Thời Gian Thực: Hiển thị nhật ký và trạng thái hoạt động của server/client ngay lập tức trên trình duyệt.

##  📂 Cấu trúc dự án (Project Structure)

Dự án được thiết kế để đơn giản tối đa, với hầu hết logic và giao diện người dùng được gói gọn trong một file Python duy nhất:

📦 Project

├── 📂server.py

├──📂received_files/      # Thư mục nơi các file đã nhận và xác minh thành công sẽ được lưu trữ.
│    ├──received_uploaded_test.txt     

├── 📂 keys/  
│    ├── 📂 private_key.pem  # Khóa riêng tư, dùng để ký số.     # Chứa dữ liệu khuôn mặt.

|    ├── 📂 public_key.pem   # Khóa công khai, dùng để xác minh chữ ký.      # Chứa dữ liệu khuôn mặt người lạ

## 🛠️ Cơ chế hoạt động của Chữ Ký Số 

1️⃣ Quản lý Khóa:

- Khi khởi động, ứng dụng kiểm tra/tạo một cặp khóa RSA (khóa riêng tư và khóa công khai) trong thư mục keys/. Khóa riêng tư dùng để ký, khóa công khai dùng để xác minh.

2️⃣ Quá trình Ký Số (Phía gửi):

- File gốc được băm (hash) bằng thuật toán SHA256 để tạo ra một "dấu vân tay" số duy nhất.
- "Dấu vân tay" này sau đó được mã hóa bằng khóa riêng tư của ứng dụng (đây chính là chữ ký số).
- File cùng với chữ ký số được gửi đi qua mạng TCP.

3️⃣ Quá trình Xác Minh (Phía nhận):

- Server nhận file và chữ ký số.
- Server tự băm lại file đã nhận bằng SHA256 để tạo ra "dấu vân tay" mới.
- Server sử dụng khóa công khai của ứng dụng để giải mã chữ ký số đã nhận.
- Nếu "dấu vân tay" giải mã được khớp với "dấu vân tay" mới tạo từ file, chữ ký được coi là HỢP LỆ. Điều này xác nhận file không bị thay đổi và đến từ nguồn đáng tin cậy.
- Nếu không khớp, chữ ký là KHÔNG HỢP LỆ, cho thấy file có thể đã bị sửa đổi hoặc đến từ nguồn không tin cậy.

## 🚀 Yêu cầu cài đặt 

Để chạy ứng dụng, bạn cần Python 3.7+ và các thư viện sau. Mở Terminal/Command Prompt và chạy:
    ```bash
pip install Flask Flask-SocketIO cryptography Werkzeug
    ```

## 🎮 Hướng dẫn sử dụng 

1. ⬇️ Tải server.py: Lưu code vào một file app.py.
2. 📂 Tạo thư mục: Đảm bảo có received_files/ và keys/ cùng cấp với server.py (sẽ tự tạo nếu không có).
3. ▶️ Chạy ứng dụng: Mở Terminal/Command Prompt tại thư mục chứa server.py và chạy:
       ```bash
python server.py  
4. 🌐 Truy cập Web: Mở trình duyệt và vào http://127.0.0.1:5000/. 
5. ⚙️ Sử dụng:
- Server Info: Nhập IP/Port (mặc định 0.0.0.0:8889) và nhấn "Connect" để khởi động server nhận file.
- Client Info: Nhập IP/Port của server đích (mặc định 127.0.0.1:8889), chọn file và nhấn "Send File" để gửi (file sẽ được ký số tự động).
- Log Output: Theo dõi trạng thái và kết quả xác minh chữ ký (VALID/INVALID). 
