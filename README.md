# 🦈 Mini Wireshark — Bộ Phân Tích & Bắt Gói Tin Mạng Thời Gian Thực

Ứng dụng bắt và phân tích gói tin mạng (Network Packet Sniffer & Protocol Analyzer) có giao diện đồ họa trực quan phát triển bằng **Python 3.11**, **PyQt5**, **Scapy** và **PyQtGraph**, mô phỏng chuẩn xác giao diện và quy tắc hoạt động của phần mềm **Wireshark** thực tế.

---

## 🖥️ 1. Tổng quan giao diện (Chuẩn Wireshark)

Giao diện được thiết kế tối giản, phẳng (Flat UI) và chia thành các khu vực trực quan giúp người dùng dễ dàng thao tác ngay từ lần đầu mở máy:

```text
┌──────────────────────────────────────────────────────────────────────────────────────┐
│ [Menu Bar] Tệp tin | Bắt gói | Hiển thị | Thống kê | Kịch bản Demo | Trợ giúp         │
├──────────────────────────────────────────────────────────────────────────────────────┤
│ [Toolbar] Card: [Wi-Fi ▼] [🔄] │ [▶] [⏹] [🔁] [⏸] [🗑] │ [📂] [💾] │ [📊] [🌙] │ [☑ Cuộn] │
├──────────────────────────────────────────────────────────────────────────────────────┤
│ [Filter Bar] [🔖] [ Nhập bộ lọc: tcp, udp, dns, error, ip.src==... ] [➔] [✖] [➕]    │
├──────────────────────────────────────────────────────────────────────────────────────┤
│ [Demo Bar]   🎬 Bản Demo: [ -- Chọn kịch bản Demo để nạp nhanh -- ▼ ] [⚡ Nạp] [🔄]  │
├──────────────────────────────────────────────────────────────────────────────────────┤
│                     KHUNG 1 (TRÊN): BẢNG DANH SÁCH GÓI TIN (PACKET TABLE)            │
│  No. │ Time     │ Source        │ Destination   │ Protocol │ Length │ Info           │
│  1   │ 0.000000 │ 192.168.1.10  │ 8.8.8.8       │ DNS      │ 74     │ Standard Query │
│  2   │ 0.015230 │ 8.8.8.8       │ 192.168.1.10  │ DNS      │ 90     │ Standard Resp  │
├────────────────────────────────────────┬─────────────────────────────────────────────┤
│  KHUNG 2 (DƯỚI TRÁI): CHI TIẾT TẦNG    │   KHUNG 3 (DƯỚI PHẢI): MÃ NHỊ PHÂN (HEX)    │
│  ▼ Frame 1: 74 bytes on wire           │   0000  92 ec ea 12 ...  |....d...|         │
│  ▼ Ethernet II, Src: ..., Dst: ...     │   0010  74 2e 00 28 ...  |t..(....|         │
│  ▼ Internet Protocol Version 4         │   0020  25 99 72 33 ...  |%.r3....|         │
│  ▼ User Datagram Protocol              │                                             │
│  ▼ Domain Name System (Query)          │                                             │
├────────────────────────────────────────┴─────────────────────────────────────────────┤
│ [Status Bar] ● Sẵn sàng             │ NIC: Wi-Fi │ Packets: 100 • Displayed: 100 (100%)│
└──────────────────────────────────────────────────────────────────────────────────────┘
```

### Ý nghĩa 3 khung làm việc chính:
1. **Khung trên (Bảng danh sách gói tin - Packet Table):** Hiển thị toàn bộ các gói tin thu được theo thời gian thực. Mỗi dòng được tô màu nền và màu chữ tự động theo đúng giao thức hoặc trạng thái lỗi.
2. **Khung dưới bên trái (Chi tiết tầng giao thức - Protocol Tree):** Khi bạn bấm vào bất kỳ dòng nào ở bảng trên, khung này sẽ bóc tách chi tiết gói tin đó theo 5 tầng mạng (Vật lý Frame $\rightarrow$ Liên kết dữ liệu Ethernet/ARP $\rightarrow$ Mạng IPv4/IPv6/ICMP $\rightarrow$ Giao vận TCP/UDP $\rightarrow$ Ứng dụng DNS/HTTP/TLS).
3. **Khung dưới bên phải (Dữ liệu nhị phân - Hex & ASCII View):** Hiển thị nội dung byte thô của gói tin ở dạng mã thập lục phân (Hex) kèm ký tự văn bản đọc được (ASCII).

---

## 🎛️ 2. Giải thích các nút bấm trên Thanh công cụ

Bạn có thể rê chuột vào bất kỳ nút nào để xem chú thích (Tooltip), hoặc tra cứu nhanh tại bảng dưới đây:

### A. Thanh công cụ chính (Main Toolbar)
| Biểu tượng | Tên chức năng | Công dụng |
| :---: | :--- | :--- |
| **`Card: [...]`** | Chọn card mạng | Chọn cổng mạng muốn theo dõi (thường chọn **Wi-Fi** hoặc **Ethernet**). |
| **`🔄`** | Làm mới card mạng | Quét lại danh sách card mạng nếu bạn vừa cắm thêm dây mạng hoặc USB Wi-Fi. |
| **`▶`** | Bắt đầu (Start) | Bắt đầu thu thập gói tin mạng trực tiếp theo thời gian thực. |
| **`⏹`** | Dừng lại (Stop) | Dừng phiên bắt gói tin hiện tại. |
| **`🔁`** | Bắt lại (Restart) | Xóa phiên cũ và bắt đầu lại từ gói số 1 ngay lập tức. |
| **`⏸`** | Tạm dừng (Pause) | Tạm ngừng hiển thị gói mới để bạn đọc dữ liệu, bấm lần nữa để tiếp tục. |
| **`🗑`** | Xóa sạch (Clear) | Xóa toàn bộ gói tin trên màn hình để làm sạch bảng. |
| **`📂`** | Mở file PCAP | Mở một tệp gói tin `.pcap` hoặc `.pcapng` có sẵn trên máy tính. |
| **`💾`** | Lưu file PCAP | Lưu toàn bộ các gói tin vừa bắt được ra file `.pcap` (mở được bằng Wireshark thật). |
| **`📊`** | Thống kê & Biểu đồ | Mở cửa sổ thống kê tỷ lệ giao thức kèm **biểu đồ cột trực quan vẽ bằng `PyQtGraph`**. |
| **`🌙` / `☀️`** | Chế độ Tối / Sáng | Chuyển đổi nhanh giữa Giao diện Sáng (Light Mode) và Giao diện Tối (Dark Mode). |
| **`☑ Cuộn`** | Tự động cuộn | Khi bật, bảng sẽ tự động trượt xuống gói tin mới nhất đang chạy. |

### B. Thanh bộ lọc tìm kiếm (Display Filter Bar)
* **`🔖` (Bookmarks):** Bấm vào để chọn nhanh các bộ lọc mẫu chỉ với 1 cú nhấp chuột (như lọc gói lỗi `error`, `tcp`, `udp`, `dns`...).
* **Ô nhập bộ lọc:**
  * Khi bạn gõ cú pháp **đúng**, ô tìm kiếm tự động chuyển sang **màu xanh lá nhạt**.
  * Khi bạn gõ cú pháp **chưa đúng/chưa hoàn chỉnh**, ô tự động báo **màu hồng đỏ**.
* **`➔` (Áp dụng):** Thực hiện lọc danh sách gói tin (hoặc nhấn phím `Enter`).
* **`✖` (Xóa bộ lọc):** Hủy bộ lọc hiện tại để hiển thị lại 100% các gói tin.
* **`➕` (Lưu bộ lọc):** Lưu từ khóa bạn đang gõ vào danh sách `🔖` để dùng lại lần sau.

### C. Thanh chọn kịch bản mẫu (Demo Bar)
* **`🎬 Bản Demo:`** Hộp chọn chứa sẵn **6 kịch bản mạng mẫu**. Bạn chỉ cần chọn 1 mục trong danh sách là dữ liệu mẫu sẽ tự động nạp lên màn hình ngay lập tức.
* **`⚡ Nạp Demo` / `🔄 Tải lại`:** Nạp hoặc làm mới lại kịch bản mẫu đang chọn.

---

## 📖 3. Hướng dẫn sử dụng chi tiết cho người mới

### Cách 1: Xem nhanh 6 kịch bản mẫu (Dễ nhất — Không cần mạng hay quyền Admin)
Ngay trên màn hình chính, tại thanh **`🎬 Bản Demo:`**, bạn chỉ cần bấm vào hộp chọn và chọn 1 trong 6 kịch bản:
1. **Giao thức ICMP:** Xem quá trình lệnh `ping` gửi 4 gói tin kiểm tra kết nối tới máy chủ Google.
2. **Giao thức TCP & HTTP:** Xem quá trình bắt tay 3 bước (`SYN` $\rightarrow$ `SYN, ACK` $\rightarrow$ `ACK`), tải trang web `HTTP GET` và đóng kết nối (`FIN`).
3. **Giao thức UDP & DNS:** Xem máy tính hỏi địa chỉ IP của một tên miền web qua cổng 53.
4. **Sự cố Bad TCP & Retransmission:** Xem hình dạng của các gói tin bị lỗi mạng (tô nền đen chữ đỏ).
5. **Phiên bắt tổng hợp 8 giao thức:** Đầy đủ ARP, DNS, ICMP, TCP, HTTP, TLS, UDP, DHCP.
6. **Mẫu chuẩn giao diện Wireshark thực tế:** Bao gồm cả gói tin IPv6, bảo mật TLS và lỗi truyền lại.

---

### Cách 2: Bắt gói tin mạng thực tế trên máy tính của bạn (Live Capture)
1. **Bước 1:** Ở mục **`Card:`** góc trên bên trái, chọn card mạng bạn đang dùng (ví dụ: `Wi-Fi`).
2. **Bước 2:** Bấm nút tam giác xanh **`▶`** để bắt đầu.
3. **Bước 3:** Mở trình duyệt web (Chrome/Edge) và truy cập thử một trang web bất kỳ — bạn sẽ thấy hàng trăm gói tin chạy liên tục trên bảng.
4. **Bước 4:** Khi muốn dừng lại để quan sát, bấm nút vuông đỏ **`⏹`**.

---

### Cách 3: Cách lọc tìm gói tin và kiểm tra gói tin bị lỗi mạng
Khi bảng có hàng nghìn gói tin, bạn có thể dùng **Thanh bộ lọc** để chỉ giữ lại những gói cần xem:
* **Xem chỉ riêng các gói bị lỗi mạng:**
  * Bấm nút **`🔖`** ở đầu thanh tìm kiếm $\rightarrow$ chọn dòng đầu tiên **`🔍 error`** (hoặc gõ chữ `error` vào ô tìm kiếm rồi nhấn `Enter`).
  * Hệ thống sẽ lọc ra toàn bộ các gói gặp sự cố thực tế: rớt mạng phải gửi lại (`Retransmission`), gói đến sai thứ tự (`Out-Of-Order`), nghẽn mạng (`Dup ACK`, `ZeroWindow`), ngắt kết nối đột ngột (`RST`), tên miền không tồn tại (`DNS Error`), hoặc không tìm thấy đích (`ICMP Unreachable`).
* **Các từ khóa lọc phổ biến khác:**
  * Lọc theo giao thức: `tcp`, `udp`, `dns`, `icmp`, `arp`, `http`, `tls`
  * Lọc theo địa chỉ IP: `ip.addr == 192.168.1.1`, `ip.src == 192.168.1.10`, `ip.dst == 8.8.8.8`
  * Lọc theo cổng dịch vụ: `port == 80`, `tcp.port == 443`, `udp.port == 53`
  * Lọc theo kích thước gói: `len > 100`, `len <= 64`
  * Kết hợp nhiều điều kiện: `tcp and port == 443`, `dns or icmp`, `not udp`

> **💡 Mẹo đọc thanh trạng thái góc dưới bên phải (`Packets` & `Displayed`):**
> * **`Packets`:** Tổng số gói tin phần mềm đã thu được.
> * **`Displayed`:** Số gói tin đang hiện trên màn hình sau khi lọc. Ví dụ: `Packets: 2000 • Displayed: 50 (2.5%)` nghĩa là tổng cộng bắt được 2.000 gói, nhưng chỉ có 50 gói khớp với từ khóa bạn đang tìm (1.950 gói còn lại chỉ tạm ẩn đi, bấm nút **`✖`** trên thanh lọc là sẽ hiện lại đầy đủ).

---

### Cách 4: Xem biểu đồ thống kê (`PyQtGraph`) & Theo dõi hội thoại TCP
1. **Xem biểu đồ phân bố giao thức (`PyQtGraph`):**
   * Sau khi bắt gói tin (hoặc nạp bản Demo), bấm nút biểu đồ **`📊`** trên thanh công cụ (hoặc vào menu **`Thống kê (Statistics)` $\rightarrow$ `📊 Phân bố lưu lượng...`**).
   * Cửa sổ thống kê sẽ hiển thị bảng tổng hợp số lượng, dung lượng (KB), tỷ lệ phần trăm từng giao thức và **biểu đồ cột trực quan (Bar Chart) được dựng bằng thư viện `PyQtGraph`**.
2. **Theo dõi nội dung cuộc hội thoại TCP (`Follow TCP Stream`):**
   * Nhấp **chuột phải** vào một gói tin `TCP` hoặc `HTTP` bất kỳ trong bảng $\rightarrow$ chọn **`📄 Theo dõi luồng TCP (Follow TCP Stream)...`**.
   * Một cửa sổ mới sẽ ghép nối toàn bộ nội dung trao đổi giữa Máy khách (màu đỏ) và Máy chủ (màu xanh dương).

---

## 🎨 4. Bảng quy tắc tô màu chuẩn Wireshark (Coloring Rules)

Bạn có thể bấm vào menu **`Hiển thị (View)` $\rightarrow$ `🎨 Quy tắc phối màu (Coloring Rules)...`** ngay trong phần mềm để tra cứu bảng màu bất cứ lúc nào:

| Loại giao thức / Trạng thái | Màu nền (Light Mode) | Màu chữ | Ý nghĩa nhận biết nhanh |
| :--- | :---: | :---: | :--- |
| **Sự cố / Lỗi mạng (Bad TCP, Error)** | Đen sẫm (`#262626`) | Đỏ tươi (`#FF5555`) | Gói tin bị lỗi, truyền lại (`Retransmission`), ngắt kết nối (`RST`), lỗi DNS/ICMP |
| **ARP** | Vàng kem (`#FAF0D7`) | Đen (`#000000`) | Hỏi địa chỉ phần cứng MAC trong mạng nội bộ LAN |
| **TCP Handshake (`SYN`, `FIN`)** | Xanh mòng két (`#A0C0C0`) | Đen (`#000000`) | Bắt đầu mở kết nối hoặc đóng kết nối TCP |
| **TCP Thông thường (`ACK`, Data)** | Tím oải hương (`#E7E6FF`) | Đen (`#000000`) | Truyền dữ liệu TCP ổn định |
| **HTTP (Web cổng 80)** | Xanh lá mạ (`#E4FFC7`) | Đen (`#000000`) | Dữ liệu web không mã hóa |
| **TLS / HTTPS (Web bảo mật)** | Tím nhạt (`#E8D4F7`) | Đen (`#000000`) | Dữ liệu web đã mã hóa bảo mật (`TLSv1.2`, `TLSv1.3`) |
| **UDP Thông thường** | Xanh da trời (`#DAEEFF`) | Đen (`#000000`) | Truyền dữ liệu nhanh không kết nối |
| **DNS / mDNS / LLMNR** | Xanh Cyan (`#C8E6FC`) | Đen (`#000000`) | Truy vấn phân giải tên miền thành địa chỉ IP |
| **ICMP / Ping** | Hồng phấn (`#FCE0FF`) | Đen (`#000000`) | Lệnh kiểm tra kết nối mạng `ping` / `tracert` |

---

## 🚀 5. Hướng dẫn cài đặt và khởi chạy

### Yêu cầu hệ thống
* Hệ điều hành: Windows 10 / 11 (đã cài đặt driver **Npcap** hoặc Wireshark để bắt gói tin trực tiếp).
* Môi trường: Python 3.11+ (đã cấu hình sẵn trong thư mục `venv`).

### Khởi chạy phần mềm
Mở **PowerShell** hoặc **Command Prompt** tại thư mục dự án và chạy lệnh:

```powershell
.\venv\Scripts\python.exe main.py
```

> **Lưu ý khi bắt mạng trực tiếp (Live Capture):**
> Để thu gói tin trực tiếp từ card Wi-Fi/Ethernet trên Windows, hãy mở PowerShell/Terminal bằng quyền **Administrator** (*Run as Administrator*). Nếu chỉ xem các kịch bản mẫu trên thanh **Bản Demo** hoặc mở file `.pcap` có sẵn thì không cần quyền Administrator.

### Chạy bộ kiểm thử tự động (Unit Tests)
```powershell
.\venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py" -v
```
