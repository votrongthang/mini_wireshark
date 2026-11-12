"""
Hộp thoại hiển thị thống kê phân bố lưu lượng theo giao thức (Stats Dialog).
"""
from typing import List, Dict, Any
from collections import Counter
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget,
    QTableWidgetItem, QHeaderView, QPushButton
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QColor, QBrush
from ui.theme_manager import get_packet_color
from ui.packet_table import WiresharkItemDelegate

try:
    import pyqtgraph as pg
    HAS_PYQTGRAPH = True
except ImportError:
    HAS_PYQTGRAPH = False


class StatsDialog(QDialog):
    """Cửa sổ phân tích thống kê lưu lượng gói tin."""

    def __init__(self, packets_summary: List[Dict[str, Any]], parent=None):
        super().__init__(parent)
        self.packets_summary = packets_summary
        self.setWindowTitle("Thống kê phân bố lưu lượng mạng (Network Statistics)")
        self.resize(650, 480)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        # Tổng quan tóm tắt
        total_packets = len(self.packets_summary)
        total_bytes = sum(p.get("length", 0) for p in self.packets_summary)
        
        lbl_summary = QLabel(
            f"<b>Tổng số gói tin:</b> {total_packets:,} | "
            f"<b>Tổng dung lượng:</b> {total_bytes:,} bytes ({total_bytes / 1024:.2f} KB)"
        )
        lbl_summary.setStyleSheet("font-size: 14px; padding: 6px; color: #38bdf8;")
        layout.addWidget(lbl_summary)

        # Đếm phân bố theo giao thức
        proto_counter = Counter(p.get("protocol", "Other") for p in self.packets_summary)

        # Bảng dữ liệu thống kê
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["Giao thức", "Số gói tin", "Tỷ lệ (%)", "Màu chuẩn Wireshark"])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        table.setItemDelegate(WiresharkItemDelegate(table))
        table.setRowCount(len(proto_counter))

        sorted_protos = proto_counter.most_common()
        for idx, (proto, count) in enumerate(sorted_protos):
            pct = (count / total_packets * 100) if total_packets > 0 else 0

            item_proto = QTableWidgetItem(proto)
            item_count = QTableWidgetItem(str(count))
            item_count.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            item_pct = QTableWidgetItem(f"{pct:.2f}%")
            item_pct.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)

            table.setItem(idx, 0, item_proto)
            table.setItem(idx, 1, item_count)
            table.setItem(idx, 2, item_pct)
            
            # Ô hiển thị màu sắc chuẩn Wireshark của giao thức
            bg_hex, fg_hex = get_packet_color(proto, "")
            item_color = QTableWidgetItem(f" {proto} ({bg_hex}) ")
            item_color.setTextAlignment(Qt.AlignCenter)
            item_color.setBackground(QBrush(QColor(bg_hex)))
            item_color.setForeground(QBrush(QColor(fg_hex)))
            item_color.setFont(QFont("Segoe UI", 9, QFont.Bold))
            table.setItem(idx, 3, item_color)

        layout.addWidget(table)

        # Nếu có pyqtgraph, vẽ thêm Bar Chart trực quan
        if HAS_PYQTGRAPH and sorted_protos:
            plot_widget = pg.PlotWidget(title="Biểu đồ số lượng gói tin theo giao thức")
            plot_widget.setBackground("#0b1120")
            
            x_vals = list(range(len(sorted_protos)))
            y_vals = [count for _, count in sorted_protos]
            ticks = [(i, proto) for i, (proto, _) in enumerate(sorted_protos)]

            bar_item = pg.BarGraphItem(x=x_vals, height=y_vals, width=0.6, brush="#38bdf8")
            plot_widget.addItem(bar_item)
            
            ax = plot_widget.getAxis('bottom')
            ax.setTicks([ticks])
            layout.addWidget(plot_widget)

        # Nút đóng
        btn_close = QPushButton("Đóng")
        btn_close.clicked.connect(self.accept)
        layout.addWidget(btn_close, alignment=Qt.AlignRight)
