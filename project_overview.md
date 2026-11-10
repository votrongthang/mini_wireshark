# Mini Wireshark — Bộ Phân Tích & Bắt Gói Tin Mạng Thời Gian Thực

**Đồ án môn học:** Mạng máy tính & Truyền thông dữ liệu  
**Chuyên ngành:** Kỹ thuật Điện tử — Viễn thông  
**Công nghệ:** Python 3.11 | PyQt5 | Scapy | Npcap  
**Thời gian thực hiện:** 3 tuần  

---

## 1. Giới thiệu tổng quan

Trong chương trình đào tạo ngành Kỹ thuật Điện tử — Viễn thông, việc thấu hiểu cách thức các gói tin dữ liệu được đóng gói, định tuyến và truyền dẫn qua môi trường mạng là kiến thức nền tảng cốt lõi. Dự án **Mini Wireshark** hướng tới xây dựng một ứng dụng giám sát lưu lượng mạng độc lập (Network Sniffer & Protocol Analyzer) với giao diện đồ họa trực quan phát triển bằng **PyQt5**, vận hành trên nền tảng **Python 3.11** và thư viện xử lý gói tin chuyên sâu **Scapy**.

Phần mềm mô phỏng lại các tính năng cốt lõi của công cụ giám sát mạng tiêu chuẩn công nghiệp (Wireshark), cho phép người dùng thu thập các khung dữ liệu thực tế đang lưu thông qua card mạng, bóc tách cấu trúc từng tầng giao thức (Ethernet, ARP, IPv4, ICMP, TCP, UDP, DNS) và đối chiếu trực tiếp giữa cấu trúc trường dữ liệu với luồng byte thô (Hex View).

---

## 2. Mục tiêu kỹ thuật & Học thuật

* **Củng cố lý thuyết mạng phân tầng:** Vận dụng trực tiếp mô hình tham chiếu OSI 7 tầng và kiến trúc TCP/IP vào việc bóc tách từng byte dữ liệu trong tiêu đề (Header) của các giao thức mạng phổ biến.
* **Làm chủ kỹ thuật lập trình đa luồng (Multithreading):** Giải quyết triệt để bài toán đồng bộ hóa giữa luồng thu thập gói tin tốc độ cao (I/O & Socket-bound) và luồng hiển thị giao diện đồ họa (GUI Event Loop), đảm bảo phần mềm hoạt động ổn định, không giật lag hay treo ứng dụng (`Not Responding`).
* **Trực quan hóa dữ liệu nhị phân:** Xây dựng thành phần hiển thị Hex View theo quy chuẩn kỹ thuật (Offset | Hex Bytes | ASCII), giúp người học dễ dàng đối soát từng trường dữ liệu với gói tin gốc.
* **Khả năng tương thích chuẩn công nghiệp:** Hỗ trợ nhập và xuất dữ liệu lưu trữ theo định dạng tiêu chuẩn `.pcap`, cho phép kiểm chứng chéo kết quả với phần mềm Wireshark chính thức.

---

## 3. Các tính năng chính của hệ thống

| Phân hệ chức năng | Mô tả chi tiết | Thành phần kỹ thuật |
| :--- | :--- | :--- |
| **Quản lý Card mạng** | Liệt kê toàn bộ card mạng khả dụng trên máy (Wi-Fi, Ethernet, Loopback) và cho phép người dùng chọn nguồn lắng nghe. | `scapy.all.get_if_list()`, `QComboBox` |
| **Bắt gói tin đa luồng** | Lắng nghe gói tin thời gian thực, điều khiển Bắt đầu (Start), Tạm dừng (Pause), Xóa bộ đệm (Clear) an toàn. | `QThread`, `pyqtSignal`, `scapy.all.sniff()` |
| **Bảng danh sách gói tin** | Hiển thị tóm tắt các gói tin thu được dạng bảng gồm: STT, Thời gian, Địa chỉ nguồn, Địa chỉ đích, Giao thức, Độ dài và Tóm tắt thông điệp. | `QTableWidget` / `QTableView` |
| **Bóc tách tầng giao thức** | Phân cấp gói tin theo dạng cây thư mục (Tree View) chi tiết từng trường dữ liệu (MAC, IP, Port, Flags, TTL, Checksum). | `QTreeWidget`, `QTreeWidgetItem` |
| **Hiển thị mã Hex & ASCII** | Xuất dữ liệu nhị phân của toàn bộ khung truyền hoặc payload ứng dụng theo định dạng 16 bytes/dòng kèm ký tự ASCII đọc được. | Custom `QPlainTextEdit` |
| **Bộ lọc lưu lượng** | Lọc dữ liệu nhanh theo tên giao thức (TCP, UDP, ICMP, DNS) hoặc theo địa chỉ IP nguồn/đích. | Python filter logic / Scapy BPF syntax |
| **Lưu & Đọc tệp PCAP** | Lưu phiên làm việc ra tệp `.pcap` hoặc nạp lại tệp gói tin đã ghi từ trước để phân tích ngoại tuyến. | `scapy.all.wrpcap()`, `scapy.all.rdpcap()` |
| **Thống kê phân bố lưu lượng** | Vẽ biểu đồ trực quan thể hiện tỷ lệ phần trăm giữa các giao thức mạng đang chiếm dụng băng thông. | `pyqtgraph` |

---

## 4. Kiến trúc hệ thống & Thiết kế phần mềm

Ứng dụng được thiết kế theo mô hình kiến trúc phân lớp (Layered Architecture), tách biệt hoàn toàn giữa tầng xử lý mạng lõi và tầng giao diện hiển thị:

```text
┌────────────────────────────────────────────────────────┐
│               TẦNG GIAO DIỆN (UI LAYER)                │
│  MainWindow | PacketTable | ProtocolTree | HexViewer   │
└───────────────────────────▲────────────────────────────┘
                            │ pyqtSignal (Thread-safe)
┌───────────────────────────┴────────────────────────────┐
│             TẦNG ĐIỀU KHIỂN & LUỒNG (WORKER)           │
│   CaptureWorker (QThread) ──► Packet Queue Buffer      │
└───────────────────────────▲────────────────────────────┘
                            │ Raw Packets
┌───────────────────────────┴────────────────────────────┐
│            TẦNG MẠNG LÕI (CORE & PARSER LAYER)         │
│     Packet Sniffer Engine (Scapy) | Protocol Parser    │
└───────────────────────────▲────────────────────────────┘
                            │ Driver Binding
┌───────────────────────────┴────────────────────────────┐
│      HỆ ĐIỀU HÀNH & PHẦN CỨNG (OS / DRIVER LAYER)      │
│          Npcap / libpcap ──► Network Interface Card    │
└────────────────────────────────────────────────────────┘
```

### Cấu trúc cây thư mục dự án

```text
mini_wireshark/
│
├── core/                           # Tầng xử lý logic nghiệp vụ mạng
│   ├── __init__.py
│   ├── sniffer.py                  # QThread chịu trách nhiệm chạy Scapy sniff
│   ├── parser.py                   # Bóc tách cấu trúc Header các tầng giao thức
│   └── pcap_manager.py             # Xử lý đọc và ghi tệp tin chuẩn .pcap
│
├── ui/                             # Tầng giao diện người dùng (PyQt5)
│   ├── __init__.py
│   ├── main_window.py              # Cửa sổ chính, bố cục tổng thể và thanh công cụ
│   ├── packet_table.py             # Widget hiển thị bảng danh sách gói tin
│   ├── protocol_tree.py            # Widget hiển thị cây phân cấp giao thức
│   ├── hex_view.py                 # Widget hiển thị mã Hex và ký tự ASCII
│   ├── stats_dialog.py             # Hộp thoại biểu đồ thống kê lưu lượng
│   └── style.qss                   # Tệp định dạng màu sắc, bố cục hiện đại
│
├── assets/                         # Tài nguyên ứng dụng
│   ├── icons/                      # Icon nút bấm (start, stop, filter, save)
│   └── sample_captures/            # Các tệp .pcap mẫu dùng cho kiểm thử
│
├── tests/                          # Kịch bản kiểm thử tự động
│   └── test_parser.py              # Kiểm tra độ chính xác của bộ bóc tách header
│
├── main.py                         # Điểm khởi chạy chính của chương trình
├── requirements.txt                # Danh sách thư viện và phiên bản chỉ định
└── README.md                       # Tài liệu hướng dẫn sử dụng
```

---

## 5. Môi trường công nghệ & Thư viện phụ thuộc

| Thành phần | Phiên bản | Vai trò trong dự án |
| :--- | :--- | :--- |
| **Ngôn ngữ** | `Python 3.11.x` | Môi trường thông dịch chính, tận dụng các cải tiến hiệu năng về tốc độ thực thi. |
| **Giao diện** | `PyQt5==5.15.10` | Bộ công cụ xây dựng giao diện đồ họa máy tính để bàn chuẩn công nghiệp. |
| **Bắt gói tin** | `scapy==2.5.0` | Thư viện chuyên sâu về phân tích, bóc tách và thao tác với gói tin mạng. |
| **Driver mạng** | `Npcap` (Windows) / `libpcap` (Linux) | Trình điều khiển tầng thấp cho phép bắt gói tin ở chế độ hỗn tạp (Promiscuous mode). |
| **Vẽ đồ thị** | `pyqtgraph==0.13.7` | Thư viện vẽ biểu đồ phân tích lưu lượng tốc độ cao tích hợp mượt mà vào PyQt. |

---

## 6. Kế hoạch triển khai chi tiết 3 tuần

### Tuần 1: Khởi tạo nền tảng, Đa luồng và Bộ khung giao diện
* **Mục tiêu:** Xây dựng thành công luồng bắt gói tin không làm đơ giao diện và hiển thị dữ liệu thô lên bảng.
* **Công việc cụ thể:**
  * Cài đặt môi trường ảo Python 3.11, Npcap và các thư viện trong `requirements.txt`.
  * Viết lớp `CaptureWorker` (`core/sniffer.py`) kế thừa từ `QThread`, truyền gói tin qua `pyqtSignal`.
  * Dựng cửa sổ chính `MainWindow` với thanh chọn card mạng, các nút điều khiển và bảng dữ liệu `PacketTable`.
  * Kiểm thử bắt luồng gói tin thực tế và xử lý cơ chế chống tràn bộ đệm khi lưu lượng mạng cao.

### Tuần 2: Bóc tách gói tin chi tiết, Hex View và Bộ lọc
* **Mục tiêu:** Phân tích hoàn chỉnh cấu trúc các tầng giao thức và hỗ trợ xem mã nhị phân chi tiết.
* **Công việc cụ thể:**
  * Xây dựng bộ giải mã `core/parser.py` bóc tách chi tiết: Ethernet II, ARP, IPv4/IPv6, ICMP, TCP, UDP, DNS.
  * Lập trình widget `ProtocolTree` hiển thị thông tin từng tầng khi người dùng nhấp chọn 1 gói tin.
  * Lập trình widget `HexView` với định dạng 3 cột chuẩn kỹ thuật: `Offset | Hex | ASCII`.
  * Tích hợp thanh tìm kiếm và lọc dữ liệu cơ bản theo giao thức hoặc địa chỉ IP nguồn/đích.

### Tuần 3: Tính năng nâng cao, Tối ưu giao diện, Đóng gói và Kịch bản bảo vệ
* **Mục tiêu:** Hoàn thiện sản phẩm chuyên nghiệp, sẵn sàng trình bày trước hội đồng chấm thi.
* **Công việc cụ thể:**
  * Xây dựng tính năng Lưu / Mở tệp `.pcap` chuẩn (`core/pcap_manager.py`).
  * Xây dựng cửa sổ biểu đồ thống kê lưu lượng theo giao thức (`ui/stats_dialog.py`).
  * Tinh chỉnh giao diện bằng Qt Style Sheets (`ui/style.qss`) với bảng màu Dark Mode chuẩn Wireshark.
  * Chuẩn bị kịch bản demo và viết báo cáo kỹ thuật giải trình trước giảng viên.

---

## 7. Kịch bản kiểm thử & Demo trước Giảng viên

Để gây ấn tượng thuyết phục trước giảng viên chuyên ngành Mạng máy tính, các kịch bản kiểm thử sau được thiết kế để kích hoạt đầy đủ các tầng giao thức:

1. **Kiểm thử giao thức ICMP (Ping Echo):**
   * *Thao tác:* Mở terminal chạy lệnh `ping google.com -n 4`.
   * *Kết quả phân tích:* Hiển thị rõ các gói ICMP Type 8 (Echo Request) và Type 0 (Echo Reply), phân tích trường Sequence Number và TTL (Time to Live).
2. **Kiểm thử giao thức TCP (Bắt tay 3 bước - 3-Way Handshake):**
   * *Thao tác:* Truy cập vào một trang web sử dụng giao thức HTTP/HTTPS.
   * *Kết quả phân tích:* Bóc tách chính xác chuỗi cờ điều khiển `[SYN]`, `[SYN, ACK]`, `[ACK]` và theo dõi sự thay đổi của trường Sequence Number và Acknowledgment Number.
3. **Kiểm thử giao thức UDP & DNS (Phân giải tên miền):**
   * *Thao tác:* Chạy lệnh `nslookup vnexpress.net`.
   * *Kết quả phân tích:* Ghi nhận gói tin UDP cổng 53, bóc tách cấu trúc câu hỏi truy vấn (DNS Query) và danh sách địa chỉ IP trả về (DNS Answers).
4. **Kiểm chứng tính toàn vẹn (Cross-validation với Wireshark):**
   * *Thao tác:* Lưu phiên bắt gói tin thành tệp `capture_demo.pcap` từ ứng dụng Mini Wireshark, sau đó mở tệp này bằng phần mềm Wireshark chính thức để chứng minh tính chuẩn mực của cấu trúc dữ liệu.

---

## 8. Hướng dẫn cài đặt & Khởi chạy nhanh

### Yêu cầu tiên quyết
* Hệ điều hành: Windows 10/11 hoặc Linux (Ubuntu 20.04+).
* Đã cài đặt [Npcap](https://npcap.com/) (chọn chế độ *WinPcap API-compatible Mode*) hoặc `libpcap-dev`.
   
### Các bước cài đặt

```bash
# 1. Khởi tạo môi trường ảo Python 3.11
py -3.11 -m venv venv

# 2. Kích hoạt môi trường ảo
# Trên Windows:
venv\Scripts\activate
# Trên Linux:
source venv/bin/activate

# 3. Nâng cấp pip và cài đặt thư viện
python -m pip install --upgrade pip
pip install -r requirements.txt

# 4. Khởi chạy ứng dụng (Chạy với quyền Administrator để có quyền bắt gói tin)
python main.py
```
