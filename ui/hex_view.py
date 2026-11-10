"""
Widget hiển thị dữ liệu nhị phân dạng Hex và ký tự ASCII (Hex Viewer).
Tương đương với khung dưới bên phải của Wireshark trong ảnh người dùng cung cấp.
"""
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QPlainTextEdit
from PyQt5.QtGui import QFont, QTextOption
from core.parser import format_hex_ascii


class HexView(QWidget):
    """Khung hiển thị mã nhị phân thô của gói tin theo chuẩn: Offset | Hex | ASCII."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_theme = "light"
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)

        # Tiêu đề tóm tắt dung lượng byte
        self.lbl_title = QLabel("Dữ liệu thô (Packet Bytes): 0 bytes")
        self.lbl_title.setStyleSheet("font-weight: bold; padding: 4px;")
        layout.addWidget(self.lbl_title)

        # Vùng hiển thị văn bản Hex
        self.text_edit = QPlainTextEdit()
        self.text_edit.setReadOnly(True)
        self.text_edit.setWordWrapMode(QTextOption.NoWrap)

        mono_font = QFont("Consolas", 9)
        mono_font.setStyleHint(QFont.Monospace)
        self.text_edit.setFont(mono_font)

        layout.addWidget(self.text_edit)
        self.set_theme("light")

    def set_theme(self, theme_name: str):
        """Cập nhật màu sắc hiển thị của Hex View theo theme."""
        self.current_theme = theme_name
        if theme_name == "dark":
            self.lbl_title.setStyleSheet("font-weight: bold; color: #94a3b8; padding: 4px;")
        else:
            self.lbl_title.setStyleSheet("font-weight: bold; color: #475569; padding: 4px;")

    def display_data(self, raw_bytes: bytes):
        """Định dạng và hiển thị chuỗi byte thô lên widget."""
        if not raw_bytes:
            self.lbl_title.setText("Dữ liệu thô (Packet Bytes): 0 bytes")
            self.text_edit.setPlainText("")
            return

        byte_len = len(raw_bytes)
        self.lbl_title.setText(f"Dữ liệu thô (Packet Bytes): {byte_len} bytes ({byte_len * 8} bits)")
        formatted_text = format_hex_ascii(raw_bytes)
        self.text_edit.setPlainText(formatted_text)

    def clear_view(self):
        """Xoá nội dung hiển thị."""
        self.lbl_title.setText("Dữ liệu thô (Packet Bytes): 0 bytes")
        self.text_edit.setPlainText("")
