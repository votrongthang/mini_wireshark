"""
Widget hiển thị danh sách các gói tin dạng bảng (Packet List Table).
Tô màu toàn bộ dòng từ cột No. đến cột Info theo chuẩn Wireshark Coloring Rules.
Hỗ trợ:
- WiresharkItemDelegate: Đảm bảo màu nền của từng ô luôn được vẽ chính xác 100%.
- get_packet_color: Tính toán cặp màu (Nền, Chữ) theo giao thức và cờ (flags).
- Menu chuột phải (Context Menu): Sao chép, lọc nhanh, theo dõi luồng TCP.
"""
from typing import Dict, Any, List, Tuple
from PyQt5.QtWidgets import (
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QMenu, QAction, QApplication, QStyledItemDelegate, QStyle
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor, QBrush, QFont

from ui.theme_manager import get_packet_color


class WiresharkItemDelegate(QStyledItemDelegate):
    """
    Delegate tùy biến để đảm bảo màu nền của từng dòng luôn được vẽ tràn ô,
    không bị stylesheet QSS hay theme mặc định của hệ điều hành ghi đè.
    """
    def paint(self, painter, option, index):
        bg = index.data(Qt.BackgroundRole)
        # Nếu dòng đang không được chọn (not selected), vẽ nền theo màu giao thức
        if bg and not (option.state & QStyle.State_Selected):
            painter.fillRect(option.rect, bg)
        super().paint(painter, option, index)


class PacketTable(QTableWidget):
    """Bảng danh sách gói tin với khả năng tô màu toàn bộ hàng theo chuẩn Wireshark."""
    packet_selected = pyqtSignal(int)
    filter_requested = pyqtSignal(str)       # Yêu cầu áp dụng bộ lọc từ menu chuột phải
    tcp_stream_requested = pyqtSignal(int)   # Yêu cầu mở Follow TCP Stream

    COLUMNS = ["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.auto_scroll = True
        self.current_theme = "light"
        
        # Lưu trữ metadata (proto, info, flags) của từng dòng để đổi theme nhanh
        self.row_metadata: List[Tuple[str, str, Any]] = []
        
        self.init_ui()

    def init_ui(self):
        self.setColumnCount(len(self.COLUMNS))
        self.setHorizontalHeaderLabels(self.COLUMNS)
        
        # Áp dụng Custom Delegate bảo đảm màu nền tô toàn bộ hàng
        self.setItemDelegate(WiresharkItemDelegate(self))

        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setShowGrid(False)
        self.setAlternatingRowColors(False)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(24)

        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents) # No.
        header.setSectionResizeMode(1, QHeaderView.Interactive)       # Time
        header.setSectionResizeMode(2, QHeaderView.Interactive)       # Source
        header.setSectionResizeMode(3, QHeaderView.Interactive)       # Destination
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents) # Protocol
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents) # Length
        header.setSectionResizeMode(6, QHeaderView.Stretch)          # Info
        
        self.setColumnWidth(1, 110)
        self.setColumnWidth(2, 220)
        self.setColumnWidth(3, 220)

        table_font = QFont("Segoe UI", 9)
        self.setFont(table_font)

        self.itemSelectionChanged.connect(self._on_selection_changed)

        # Menu ngữ cảnh khi bấm chuột phải
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._show_context_menu)

    def _show_context_menu(self, pos):
        """Menu chuột phải để sao chép, lọc hoặc xem luồng TCP."""
        row = self.rowAt(pos.y())
        if row < 0 or row >= self.rowCount():
            return

        self.selectRow(row)
        menu = QMenu(self)

        src_ip = self.item(row, 2).text() if self.item(row, 2) else ""
        dst_ip = self.item(row, 3).text() if self.item(row, 3) else ""
        proto = self.item(row, 4).text() if self.item(row, 4) else ""
        info = self.item(row, 6).text() if self.item(row, 6) else ""

        act_copy_summary = QAction("📋 Sao chép tóm tắt dòng này", self)
        act_copy_summary.triggered.connect(lambda: self._copy_to_clipboard(
            f"No: {self.item(row, 0).text()} | Proto: {proto} | Src: {src_ip} -> Dst: {dst_ip} | {info}"
        ))
        menu.addAction(act_copy_summary)

        menu.addSeparator()

        if proto:
            act_filter_proto = QAction(f"🔍 Lọc chỉ xem giao thức '{proto}'", self)
            act_filter_proto.triggered.connect(lambda: self.filter_requested.emit(proto.lower()))
            menu.addAction(act_filter_proto)

        if src_ip and src_ip != "-":
            act_filter_src = QAction(f"🔍 Lọc theo IP nguồn: ip.src == {src_ip}", self)
            act_filter_src.triggered.connect(lambda: self.filter_requested.emit(f"ip.src == {src_ip}"))
            menu.addAction(act_filter_src)

        if dst_ip and dst_ip != "-":
            act_filter_dst = QAction(f"🔍 Lọc theo IP đích: ip.dst == {dst_ip}", self)
            act_filter_dst.triggered.connect(lambda: self.filter_requested.emit(f"ip.dst == {dst_ip}"))
            menu.addAction(act_filter_dst)

        if proto in ("TCP", "HTTP", "TLS", "TLSv1.2", "TLSv1.3", "SSH", "FTP"):
            menu.addSeparator()
            act_tcp_stream = QAction("🌊 Theo dõi luồng TCP (Follow TCP Stream)...", self)
            act_tcp_stream.triggered.connect(lambda: self.tcp_stream_requested.emit(row))
            menu.addAction(act_tcp_stream)

        menu.exec_(self.viewport().mapToGlobal(pos))

    def _copy_to_clipboard(self, text: str):
        clipboard = QApplication.clipboard()
        clipboard.setText(text)

    def set_theme(self, theme_name: str):
        """Thay đổi bảng màu theo Light Mode hoặc Dark Mode."""
        self.current_theme = theme_name

        for row in range(self.rowCount()):
            if row < len(self.row_metadata):
                proto, info, flags = self.row_metadata[row]
            else:
                proto = self.item(row, 4).text() if self.item(row, 4) else "Unknown"
                info = self.item(row, 6).text() if self.item(row, 6) else ""
                flags = None

            bg_hex, fg_hex = get_packet_color(proto, info, flags=flags, theme=theme_name)
            bg = QBrush(QColor(bg_hex))
            fg = QBrush(QColor(fg_hex))

            for col in range(self.columnCount()):
                item = self.item(row, col)
                if item:
                    item.setBackground(bg)
                    item.setForeground(fg)

    def add_packet(self, summary: Dict[str, Any]):
        """Thêm một dòng gói tin đơn lẻ."""
        self.add_packets_batch([summary])

    def add_packets_batch(self, summaries: List[Dict[str, Any]], max_limit: int = None):
        """
        Thêm một lô (Batch) gói tin vào bảng với hiệu năng cao:
        - Tắt render cập nhật đồ họa trong quá trình chèn: setUpdatesEnabled(False)
        - Tắt sắp xếp tạm thời: setSortingEnabled(False)
        - Giữ nguyên vẹn toàn bộ các dòng từ gói số 1 (chỉ xóa nếu max_limit được chỉ định cụ thể)
        - Pre-allocate kích thước bảng một lần duy nhất
        - Bật lại đồ họa: setUpdatesEnabled(True)
        - Gọi scrollToBottom() DUY NHẤT một lần ở cuối hàm (nếu auto_scroll bật)
        """
        if not summaries:
            return

        self.setUpdatesEnabled(False)
        self.setSortingEnabled(False)

        try:
            current_rows = self.rowCount()
            new_count = len(summaries)
            total_after = current_rows + new_count

            # Nếu có cấu hình max_limit thì mới cắt tỉa dòng cũ, mặc định (None) là lưu toàn bộ từ gói 1
            if max_limit is not None and total_after > max_limit:
                overflow = total_after - max_limit
                remove_from_table = min(overflow, current_rows)
                for _ in range(remove_from_table):
                    self.removeRow(0)

                if overflow <= len(self.row_metadata):
                    del self.row_metadata[:overflow]
                else:
                    self.row_metadata.clear()

                current_rows = self.rowCount()

            # Mở rộng số dòng một lần duy nhất (Pre-allocate)
            self.setRowCount(current_rows + new_count)

            proto_font = QFont("Segoe UI", 9, QFont.Bold)
            normal_font = QFont("Segoe UI", 9)

            alignments = [
                Qt.AlignRight | Qt.AlignVCenter,
                Qt.AlignLeft | Qt.AlignVCenter,
                Qt.AlignLeft | Qt.AlignVCenter,
                Qt.AlignLeft | Qt.AlignVCenter,
                Qt.AlignCenter,
                Qt.AlignRight | Qt.AlignVCenter,
                Qt.AlignLeft | Qt.AlignVCenter
            ]

            for i, summary in enumerate(summaries):
                row = current_rows + i

                proto = summary.get("protocol", "Unknown")
                info = summary.get("info", "")
                flags = summary.get("flags", None)

                self.row_metadata.append((proto, info, flags))

                # Tính toán màu sắc Wireshark cho dòng này
                bg_hex, fg_hex = get_packet_color(proto, info, flags=flags, theme=self.current_theme)
                bg_brush = QBrush(QColor(bg_hex))
                fg_brush = QBrush(QColor(fg_hex))

                values = [
                    str(summary.get("no", row + 1)),
                    str(summary.get("time", "")),
                    str(summary.get("src", "")),
                    str(summary.get("dst", "")),
                    str(proto),
                    str(summary.get("length", 0)),
                    str(info)
                ]

                for col, val in enumerate(values):
                    item = QTableWidgetItem(val)
                    item.setTextAlignment(alignments[col])
                    item.setBackground(bg_brush)
                    item.setForeground(fg_brush)

                    if col == 4:
                        item.setFont(proto_font)
                    else:
                        item.setFont(normal_font)

                    self.setItem(row, col, item)

        finally:
            self.setUpdatesEnabled(True)

        # Gọi scrollToBottom() DUY NHẤT một lần ở cuối
        if self.auto_scroll:
            self.scrollToBottom()

    def _on_selection_changed(self):
        selected_rows = self.selectionModel().selectedRows()
        if selected_rows:
            row_idx = selected_rows[0].row()
            self.packet_selected.emit(row_idx)

    def set_auto_scroll(self, enabled: bool):
        self.auto_scroll = enabled

    def clear_all(self):
        self.setRowCount(0)
        self.row_metadata.clear()
