"""
Widget hiển thị cây phân cấp giao thức gói tin (Protocol Tree View).
Tương đương với khung dưới bên trái của Wireshark trong ảnh người dùng cung cấp.
"""
from typing import List, Dict, Any
from PyQt5.QtWidgets import QTreeWidget, QTreeWidgetItem, QHeaderView
from PyQt5.QtGui import QFont, QColor, QBrush
from PyQt5.QtCore import Qt


class ProtocolTree(QTreeWidget):
    """Cây hiển thị chi tiết các tầng giao thức bóc tách từ gói tin."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_theme = "light"
        self.current_layers: List[Dict[str, Any]] = []
        self.init_ui()

    def init_ui(self):
        self.setHeaderLabels(["Cấu trúc tầng giao thức (Packet Details)"])
        self.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.setAnimated(True)
        self.setIndentation(18)
        
        font = QFont("Segoe UI", 9)
        self.setFont(font)

    def set_theme(self, theme_name: str):
        """Cập nhật màu chữ hiển thị khi chuyển đổi giao diện sáng/tối."""
        self.current_theme = theme_name
        if self.current_layers:
            self.display_packet(self.current_layers)

    def display_packet(self, layers: List[Dict[str, Any]]):
        """Nạp danh sách các tầng giao thức và các trường con vào cây."""
        self.clear()
        self.current_layers = layers
        if not layers:
            return

        is_dark = (self.current_theme == "dark")
        header_color = QColor("#f8fafc") if is_dark else QColor("#0f172a")
        field_color = QColor("#94a3b8") if is_dark else QColor("#334155")

        bold_font = QFont("Segoe UI", 9, QFont.Bold)
        normal_font = QFont("Segoe UI", 9)

        for layer in layers:
            title = layer.get("title", "")
            fields = layer.get("fields", [])

            # Node gốc đại diện cho từng Layer
            layer_item = QTreeWidgetItem(self, [title])
            layer_item.setFont(0, bold_font)
            layer_item.setForeground(0, QBrush(header_color))

            # Các node con đại diện cho từng trường Header
            for field in fields:
                field_item = QTreeWidgetItem(layer_item, [str(field)])
                field_item.setFont(0, normal_font)
                field_item.setForeground(0, QBrush(field_color))

            # Mặc định mở rộng để đối soát nhanh
            layer_item.setExpanded(True)

    def clear_tree(self):
        """Xóa trắng cây chi tiết giao thức."""
        self.clear()
        self.current_layers.clear()
