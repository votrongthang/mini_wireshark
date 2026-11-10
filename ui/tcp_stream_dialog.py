"""
Hộp thoại theo dõi và tái dựng luồng TCP (Follow TCP Stream).
Ghép nối toàn bộ dữ liệu trao đổi giữa Client và Server trong phiên truyền thông.
"""
from typing import List, Tuple
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPlainTextEdit, QPushButton, QComboBox
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QTextCharFormat, QColor, QTextCursor

from scapy.packet import Packet, Raw
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6


class TcpStreamDialog(QDialog):
    """Cửa sổ hiển thị toàn bộ nội dung trao đổi của một phiên TCP."""

    def __init__(self, packets: List[Packet], selected_pkt: Packet, parent=None):
        super().__init__(parent)
        self.packets = packets
        self.selected_pkt = selected_pkt
        self.setWindowTitle("Theo dõi luồng TCP (Follow TCP Stream)")
        self.resize(750, 520)
        self.init_ui()
        self.reconstruct_stream()

    def init_ui(self):
        layout = QVBoxLayout(self)

        # Thông tin hai đầu endpoint
        self.lbl_info = QLabel("Đang phân tích phiên truyền thông TCP...")
        self.lbl_info.setStyleSheet("font-weight: bold; color: #2563eb; font-size: 13px; padding: 4px;")
        layout.addWidget(self.lbl_info)

        # Khung văn bản hiển thị dòng hội thoại
        self.txt_stream = QPlainTextEdit()
        self.txt_stream.setReadOnly(True)
        mono_font = QFont("Consolas", 10)
        self.txt_stream.setFont(mono_font)
        layout.addWidget(self.txt_stream)

        # Thanh điều khiển phía dưới
        bottom_layout = QHBoxLayout()

        self.lbl_stats = QLabel("Dữ liệu: 0 bytes")
        bottom_layout.addWidget(self.lbl_stats)

        bottom_layout.addStretch()

        btn_close = QPushButton("Đóng")
        btn_close.clicked.connect(self.accept)
        bottom_layout.addWidget(btn_close)

        layout.addLayout(bottom_layout)

    def reconstruct_stream(self):
        """Lọc và ghép nối dữ liệu của cả 2 chiều trong kết nối TCP."""
        if not self.selected_pkt.haslayer(TCP):
            self.txt_stream.setPlainText("Gói tin đã chọn không thuộc giao thức TCP.")
            return

        # Xác định bộ 4 thông số của kết nối: (IP1, Port1, IP2, Port2)
        tcp = self.selected_pkt[TCP]
        src_port = tcp.sport
        dst_port = tcp.dport

        if self.selected_pkt.haslayer(IP):
            src_ip = self.selected_pkt[IP].src
            dst_ip = self.selected_pkt[IP].dst
        elif self.selected_pkt.haslayer(IPv6):
            src_ip = self.selected_pkt[IPv6].src
            dst_ip = self.selected_pkt[IPv6].dst
        else:
            self.txt_stream.setPlainText("Không xác định được địa chỉ IP của gói tin.")
            return

        endpoint1 = (src_ip, src_port)
        endpoint2 = (dst_ip, dst_port)

        self.lbl_info.setText(
            f"Luồng TCP giữa: {src_ip}:{src_port} <───► {dst_ip}:{dst_port}"
        )

        cursor = self.txt_stream.textCursor()
        total_bytes = 0
        stream_packet_count = 0

        # Định dạng màu: Chiều gửi đi (Client -> Server: Đỏ sẫm), Chiều trả về (Server -> Client: Xanh lam)
        fmt_client = QTextCharFormat()
        fmt_client.setForeground(QColor("#dc2626"))  # Đỏ

        fmt_server = QTextCharFormat()
        fmt_server.setForeground(QColor("#2563eb"))  # Xanh lam

        for pkt in self.packets:
            if not pkt.haslayer(TCP):
                continue

            p_tcp = pkt[TCP]
            p_src_port = p_tcp.sport
            p_dst_port = p_tcp.dport

            p_src_ip = pkt[IP].src if pkt.haslayer(IP) else (pkt[IPv6].src if pkt.haslayer(IPv6) else "")
            p_dst_ip = pkt[IP].dst if pkt.haslayer(IP) else (pkt[IPv6].dst if pkt.haslayer(IPv6) else "")

            # Kiểm tra xem gói có thuộc cùng kết nối (chiều xuôi hoặc chiều ngược)
            is_forward = (p_src_ip, p_src_port) == endpoint1 and (p_dst_ip, p_dst_port) == endpoint2
            is_backward = (p_src_ip, p_src_port) == endpoint2 and (p_dst_ip, p_dst_port) == endpoint1

            if is_forward or is_backward:
                stream_packet_count += 1
                if pkt.haslayer(Raw):
                    payload = bytes(pkt[Raw])
                    if payload:
                        total_bytes += len(payload)
                        # Chuyển payload sang chuỗi hiển thị an toàn (các byte lạ thành '.')
                        decoded_chars = []
                        for b in payload:
                            if 32 <= b <= 126 or b in (10, 13, 9):  # Ký tự in được hoặc xuống dòng / tab
                                decoded_chars.append(chr(b))
                            else:
                                decoded_chars.append(".")
                        text_data = "".join(decoded_chars)

                        fmt = fmt_client if is_forward else fmt_server
                        cursor.insertText(text_data, fmt)

        if total_bytes == 0:
            cursor.insertText(
                f"[Ghi nhận {stream_packet_count} gói tin điều khiển TCP (SYN, ACK, FIN...), không có dữ liệu Payload ứng dụng]",
                fmt_client
            )

        self.lbl_stats.setText(
            f"Tổng số gói trong luồng: {stream_packet_count} | Dung lượng Payload: {total_bytes:,} bytes"
        )
