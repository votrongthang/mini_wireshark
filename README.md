# Mini Wireshark — Network Protocol Analyzer

Ứng dụng bắt và phân tích gói tin mạng thời gian thực với giao diện đồ họa trực quan phát triển bằng **PyQt5** và thư viện **Scapy**, mô phỏng chính xác công cụ **Wireshark**.

---

## 📸 Bố cục chuẩn 3 khung (Three-Pane Layout)

Giao diện được thiết kế tương đồng chuẩn Wireshark với 3 khung làm việc:

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        THANH CÔNG CỤ & BỘ LỌC                          │
│  [NIC: Wi-Fi] [▶ Bắt đầu] [⏸ Tạm dừng] [⏹ Dừng] [📂 Mở] [💾 Lưu] [☀️/🌙] │
├────────────────────────────────────────────────────────────────────────┤
│                       KHUNG TRÊN: DANH SÁCH GÓI TIN                     │
│  No. | Time | Source | Destination | Protocol | Length | Info          │
│  1   | 0.00 | 192.168.1.50 | 8.8.8.8 | DNS    | 74     | Query ...     │
├───────────────────────────────────┬────────────────────────────────────┤
│     KHUNG DƯỚI TRÁI: CHI TIẾT     │      KHUNG DƯỚI PHẢI: HEX VIEW     │
│  > Frame 1: 74 bytes on wire      │  0000  92 ec ea 12 ... |....d...|  │
│  > Ethernet II, Src: ..., Dst: ...│  0010  74 2e 00 28 ... |t..(....|  │
│  > Internet Protocol Version 4    │  0020  25 99 72 33 ... |%.r3....|  │
│  > User Datagram Protocol         │  ...                               │
│  > Domain Name System (Query)     │                                    │
└───────────────────────────────────┴────────────────────────────────────┘
```

1. **Khung trên (Top Pane):** Bảng danh sách gói tin (Packet Table) toàn chiều ngang, phân biệt màu sắc theo giao thức (TCP, UDP, DNS, ICMP, ARP, TLS).
2. **Khung dưới bên trái (Bottom-Left Pane):** Cây phân cấp bóc tách từng tầng giao thức (Protocol Tree) theo chuẩn OSI/TCP-IP.
3. **Khung dưới bên phải (Bottom-Right Pane):** Khung xem mã nhị phân (Hex & ASCII View) với định dạng 3 cột chuẩn kỹ thuật: `Offset | Hex | ASCII`.

---

## 🌓 Chế độ Dark Mode & Light Mode

* Hỗ trợ chuyển đổi nhanh ngay trên thanh công cụ bằng nút bấm `🌙 Giao diện Tối` / `☀️ Giao diện Sáng`.
* **Light Mode:** Tông màu sáng nguyên bản giống hệt giao diện chính thức của Wireshark.
* **Dark Mode:** Tông màu tối hiện đại, tương phản cao, dịu mắt khi làm việc ban đêm.

---

## 🔍 Bộ lọc hiển thị (Display Filter)

Hỗ trợ cú pháp lọc tương tự Wireshark:
* Lọc giao thức: `tcp`, `udp`, `icmp`, `dns`, `arp`, `tls`, `http`
* Lọc địa chỉ IP: `ip.addr == 192.168.1.1`, `ip.src == 192.168.1.50`, `ip.dst == 8.8.8.8`
* Lọc cổng: `port == 53`, `tcp.port == 443`, `udp.port == 53`
* Lọc độ dài: `len > 100`, `len <= 64`
* Toán tử logic: `and`, `or`, `&&`, `||`, `not`, `!`

---

## 🚀 Hướng dẫn khởi chạy

### 1. Khởi động môi trường và chạy ứng dụng

```powershell
# Chạy ứng dụng Mini Wireshark
.\venv\Scripts\python.exe main.py
```

> **Lưu ý về quyền bắt gói tin trực tiếp (Live Sniffing):**  
> Do cơ chế bảo mật của Npcap trên Windows, để bắt gói tin trực tiếp từ card mạng (Wi-Fi, Ethernet), vui lòng mở Terminal/PowerShell với quyền **Administrator** (`Run as Administrator`).

### 2. Trải nghiệm ngoại tuyến (Không cần quyền Admin)
1. Khởi chạy ứng dụng `main.py`.
2. Bấm nút **`📂 Mở .pcap`** trên thanh công cụ.
3. Chọn file mẫu có sẵn tại: `assets/sample_captures/demo.pcap` (gồm đầy đủ gói tin ARP, DNS, ICMP Ping, TCP Handshake và TLS).

### 3. Chạy kiểm thử tự động (Unit Tests)

```powershell
.\venv\Scripts\python.exe -m unittest tests/test_parser.py
```
