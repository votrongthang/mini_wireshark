"""
Hộp thoại hiển thị và giải thích bảng quy tắc phối màu giao thức (Wireshark Coloring Rules).
"""
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QLabel, QTableWidget, QTableWidgetItem, QHeaderView, QPushButton
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QColor, QBrush

from ui.theme_manager import get_packet_color


class ColoringRulesDialog(QDialog):
    """Cửa sổ tra cứu quy tắc phối màu giao thức chuẩn Wireshark."""

    def __init__(self, current_theme: str = "light", parent=None):
        super().__init__(parent)
        self.current_theme = current_theme
        self.setWindowTitle("Quy tắc phối màu giao thức (Wireshark Coloring Rules)")
        self.resize(650, 480)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        lbl_desc = QLabel(
            "<b>Bảng chú giải quy tắc phối màu chuẩn Wireshark:</b><br>"
            "Toàn bộ hàng từ cột No. đến cột Info được tô màu nền và màu chữ tương ứng theo giao thức & trạng thái cờ."
        )
        lbl_desc.setStyleSheet("padding: 4px; font-size: 13px;")
        layout.addWidget(lbl_desc)

        table = QTableWidget()
        table.setColumnCount(3)
        table.setHorizontalHeaderLabels(["Giao thức & Trạng thái", "Mẫu hiển thị (Preview)", "Mô tả"])
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Interactive)
        table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        table.setColumnWidth(1, 180)
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QTableWidget.NoEditTriggers)

        rules = [
            ("ARP", "ARP Request", "Giao thức phân giải địa chỉ IP sang MAC (#FAF0D7)"),
            ("TCP (Handshake)", "50117 -> 443 [SYN]", "Bắt tay 3 bước / Ngắt kết nối TCP [SYN, FIN] (#A0C0C0)"),
            ("TCP (Normal)", "50117 -> 443 [ACK]", "TCP truyền dữ liệu thông thường (#E7E6FF)"),
            ("TLS / HTTPS", "TLSv1.2 App Data", "Dữ liệu mã hóa bảo mật SSL/TLS (#E8D4F7)"),
            ("HTTP", "GET / HTTP/1.1", "Web không mã hóa cổng 80 (#E4FFC7)"),
            ("UDP", "UDP Datagram", "Giao thức truyền dữ liệu người dùng (#DAEEFF)"),
            ("DNS", "Standard Query A", "Phân giải tên miền qua cổng 53 (#C8E6FC)"),
            ("ICMP", "Echo (ping) request", "Thông điệp kiểm tra mạng Ping / Tracert (#FCE0FF)"),
            ("Bad TCP", "[TCP Retransmission] RST", "Sự cố, truyền lại hoặc lỗi cờ RST (#262626 - Chữ đỏ)"),
        ]

        table.setRowCount(len(rules))

        for idx, (label, sample_info, desc_text) in enumerate(rules):
            proto_arg = label.split()[0]
            bg_hex, fg_hex = get_packet_color(proto_arg, sample_info, theme=self.current_theme)

            item_name = QTableWidgetItem(label)
            item_name.setFont(QFont("Segoe UI", 9, QFont.Bold))

            item_preview = QTableWidgetItem(f" {sample_info} ")
            item_preview.setTextAlignment(Qt.AlignCenter)
            item_preview.setBackground(QBrush(QColor(bg_hex)))
            item_preview.setForeground(QBrush(QColor(fg_hex)))
            item_preview.setFont(QFont("Segoe UI", 9, QFont.Bold))

            item_desc = QTableWidgetItem(desc_text)

            table.setItem(idx, 0, item_name)
            table.setItem(idx, 1, item_preview)
            table.setItem(idx, 2, item_desc)

        layout.addWidget(table)

        btn_close = QPushButton("Đóng")
        btn_close.clicked.connect(self.accept)
        layout.addWidget(btn_close, alignment=Qt.AlignRight)
