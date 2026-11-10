"""
Quản lý màu sắc và giao diện (Theme Manager) chuẩn Wireshark.
Thiết kế phẳng (Flat), siêu gọn:
- Toolbar chiều cao tối đa 30px.
- Display Filter Bar chiều cao tối đa 26px.
- Nút bấm dạng icon phẳng 24x22px hoặc 22x22px với hover highlight mượt mà.
- Bảng màu Wireshark Coloring Rules (tô toàn bộ dòng).
"""
from typing import Tuple


def get_packet_color(protocol: str, info: str = "", flags=None, theme: str = "light") -> Tuple[str, str]:
    """
    Xác định mã màu nền (Background) và màu chữ (Foreground) chuẩn Wireshark.
    Trả về: (bg_color_hex, fg_color_hex)
    """
    proto_upper = str(protocol).strip().upper()
    info_lower = str(info).strip().lower()

    flags_list = []
    if flags:
        if isinstance(flags, (list, tuple)):
            flags_list = [str(f).upper() for f in flags]
        else:
            flags_list = [str(flags).upper()]

    # 4. Sự cố & Lỗi TCP (Bad TCP: RST, Retransmission, Spurious Retransmission, Checksum Error)
    is_bad_tcp = (
        "retransmission" in info_lower
        or "[rst" in info_lower
        or "rst" in flags_list
        or "checksum error" in info_lower
        or "bad" in info_lower
    )
    if is_bad_tcp:
        return ("#262626", "#FF5555")

    # 1. Giao thức mạng tầng thấp & Bắt tay TCP
    if "ARP" in proto_upper:
        if theme == "dark":
            return ("#42341c", "#fde68a")
        return ("#FAF0D7", "#000000")

    if "ICMP" in proto_upper:
        if theme == "dark":
            return ("#421d3f", "#f5d0fe")
        return ("#FCE0FF", "#000000")

    if any(k in proto_upper for k in ("DNS", "MDNS", "LLMNR")):
        if theme == "dark":
            return ("#163b4f", "#7dd3fc")
        return ("#C8E6FC", "#000000")

    if any(k in proto_upper for k in ("TLS", "SSL", "HTTPS")):
        if theme == "dark":
            return ("#35204d", "#e9d5ff")
        return ("#E8D4F7", "#000000")

    if proto_upper == "HTTP":
        if theme == "dark":
            return ("#1b3d22", "#a7f3d0")
        return ("#E4FFC7", "#000000")

    if "TCP" in proto_upper:
        is_handshake = (
            "[syn" in info_lower
            or "syn," in info_lower
            or "syn]" in info_lower
            or "[fin" in info_lower
            or "fin," in info_lower
            or "fin]" in info_lower
            or any(f in flags_list for f in ("SYN", "FIN"))
        )
        if is_handshake:
            if theme == "dark":
                return ("#1e3a40", "#99f6e4")
            return ("#A0C0C0", "#000000")
        
        if theme == "dark":
            return ("#2a2754", "#c7d2fe")
        return ("#E7E6FF", "#000000")

    if "UDP" in proto_upper:
        if theme == "dark":
            return ("#15324d", "#93c5fd")
        return ("#DAEEFF", "#000000")

    if "DHCP" in proto_upper:
        return ("#D1FAE5", "#000000") if theme == "light" else ("#133d32", "#6ee7b7")
    if "NTP" in proto_upper:
        return ("#E0E7FF", "#000000") if theme == "light" else ("#252554", "#a5b4fc")
    if "QUIC" in proto_upper:
        return ("#CCFBF1", "#000000") if theme == "light" else ("#133e3d", "#5eead4")

    if theme == "dark":
        return ("#1e293b", "#f8fafc")
    return ("#FFFFFF", "#000000")


LIGHT_QSS = """
/* Wireshark Authentic Light Theme - Compact Header (30px Toolbar + 26px Filter) */
QMainWindow, QWidget {
    background-color: #f1f5f9;
    color: #0f172a;
    font-family: "Segoe UI", -apple-system, BlinkMacSystemFont, "Roboto", sans-serif;
    font-size: 12px;
}

/* Menu Bar mảnh chuẩn Wireshark */
QMenuBar {
    background-color: #f8fafc;
    color: #0f172a;
    border-bottom: 1px solid #cbd5e1;
    padding: 1px 4px;
    height: 22px;
    font-size: 12px;
}

QMenuBar::item {
    background: transparent;
    padding: 2px 6px;
    border-radius: 2px;
}

QMenuBar::item:selected {
    background-color: #e2e8f0;
}

QMenu {
    background-color: #ffffff;
    color: #0f172a;
    border: 1px solid #cbd5e1;
    padding: 3px;
    font-size: 12px;
}

QMenu::item {
    padding: 4px 20px;
    border-radius: 2px;
}

QMenu::item:selected {
    background-color: #2563eb;
    color: #ffffff;
}

/* Toolbar chính: Chiều cao tối đa 30px, các nút phẳng gọn gàng */
QToolBar {
    background-color: #f8fafc;
    border-bottom: 1px solid #cbd5e1;
    spacing: 2px;
    padding: 1px 3px;
    max-height: 28px;
}

/* Phong cách nút bấm phẳng (Flat Button) chuẩn Wireshark */
QPushButton, QToolButton {
    background-color: transparent;
    color: #0f172a;
    border: 1px solid transparent;
    border-radius: 3px;
    padding: 1px 4px;
    height: 22px;
    min-width: 22px;
    font-size: 11px;
    font-weight: 600;
}

QPushButton:hover, QToolButton:hover {
    background-color: #e2e8f0;
    border: 1px solid #cbd5e1;
}

QPushButton:pressed, QToolButton:pressed {
    background-color: #cbd5e1;
}

QPushButton:disabled, QToolButton:disabled {
    color: #94a3b8;
    background-color: transparent;
    border: 1px solid transparent;
}

QPushButton#btn_start {
    color: #16a34a;
    font-weight: bold;
}
QPushButton#btn_start:hover {
    background-color: #dcfce7;
    border: 1px solid #86efac;
}

QPushButton#btn_stop {
    color: #dc2626;
    font-weight: bold;
}
QPushButton#btn_stop:hover {
    background-color: #fee2e2;
    border: 1px solid #fca5a5;
}

QComboBox {
    background-color: #ffffff;
    border: 1px solid #cbd5e1;
    border-radius: 3px;
    padding: 1px 6px;
    color: #0f172a;
    height: 22px;
    max-height: 22px;
    font-size: 11px;
}

QComboBox::drop-down {
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 16px;
    border-left: 1px solid #cbd5e1;
}

QComboBox QAbstractItemView {
    background-color: #ffffff;
    border: 1px solid #cbd5e1;
    selection-background-color: #2563eb;
    selection-color: #ffffff;
    color: #0f172a;
}

/* Khung thanh lọc hiển thị (Display Filter Bar) - Chuẩn Wireshark cao 26px */
QWidget#filter_bar_container {
    background-color: #f8fafc;
    border-bottom: 1px solid #cbd5e1;
    max-height: 26px;
}

QLineEdit#txt_filter {
    background-color: #ffffff;
    border: 1px solid #cbd5e1;
    border-radius: 3px;
    padding: 1px 6px;
    color: #0f172a;
    height: 22px;
    max-height: 22px;
    font-size: 11.5px;
    font-family: "Consolas", "Segoe UI", monospace;
}

QLineEdit#txt_filter:focus {
    border: 1px solid #22c55e;
    background-color: #f0fdf4;
}

QPushButton#btn_filter_apply {
    color: #16a34a;
    font-weight: bold;
    font-size: 12px;
}
QPushButton#btn_filter_apply:hover {
    background-color: #dcfce7;
    border: 1px solid #86efac;
}

QPushButton#btn_filter_clear {
    color: #64748b;
    font-size: 11px;
}
QPushButton#btn_filter_clear:hover {
    background-color: #fee2e2;
    border: 1px solid #fca5a5;
    color: #dc2626;
}

/* Splitter chia khung */
QSplitter::handle {
    background-color: #cbd5e1;
}
QSplitter::handle:horizontal { width: 4px; }
QSplitter::handle:vertical { height: 4px; }
QSplitter::handle:hover { background-color: #2563eb; }

/* Bảng danh sách gói tin: Delegate tự tô màu toàn dòng */
QTableWidget {
    border: 1px solid #cbd5e1;
    gridline-color: #e2e8f0;
    selection-background-color: #71b2e8;
    selection-color: #000000;
}

QHeaderView::section {
    background-color: #f8fafc;
    color: #334155;
    padding: 4px 6px;
    border: none;
    border-right: 1px solid #cbd5e1;
    border-bottom: 1px solid #cbd5e1;
    font-weight: bold;
    font-size: 11.5px;
}

/* Cây phân tầng */
QTreeWidget {
    background-color: #ffffff;
    border: 1px solid #cbd5e1;
    color: #0f172a;
    selection-background-color: #dbeafe;
    selection-color: #1e3a8a;
    font-size: 11.5px;
}

QTreeWidget::item { padding: 1px 0px; }
QTreeWidget::item:hover { background-color: #f1f5f9; }
QTreeWidget::item:selected { background-color: #2563eb; color: #ffffff; }

/* Hex View */
QPlainTextEdit {
    background-color: #f8fafc;
    color: #0f172a;
    border: 1px solid #cbd5e1;
    selection-background-color: #bfdbfe;
    selection-color: #0f172a;
    font-size: 11.5px;
}

/* Status Bar */
QStatusBar {
    background-color: #e2e8f0;
    border-top: 1px solid #cbd5e1;
    color: #334155;
    font-size: 11px;
    max-height: 22px;
}
QStatusBar QLabel { padding: 1px 6px; }
"""


DARK_QSS = """
/* Wireshark Authentic Dark Theme - Compact Header (30px Toolbar + 26px Filter) */
QMainWindow, QWidget {
    background-color: #0f172a;
    color: #e2e8f0;
    font-family: "Segoe UI", -apple-system, BlinkMacSystemFont, "Roboto", sans-serif;
    font-size: 12px;
}

QMenuBar {
    background-color: #1e293b;
    color: #e2e8f0;
    border-bottom: 1px solid #334155;
    padding: 1px 4px;
    height: 22px;
    font-size: 12px;
}

QMenuBar::item {
    background: transparent;
    padding: 2px 6px;
    border-radius: 2px;
}

QMenuBar::item:selected {
    background-color: #334155;
}

QMenu {
    background-color: #1e293b;
    color: #e2e8f0;
    border: 1px solid #334155;
    padding: 3px;
    font-size: 12px;
}

QMenu::item {
    padding: 4px 20px;
    border-radius: 2px;
}

QMenu::item:selected {
    background-color: #2563eb;
    color: #ffffff;
}

QToolBar {
    background-color: #1e293b;
    border-bottom: 1px solid #334155;
    spacing: 2px;
    padding: 1px 3px;
    max-height: 28px;
}

QPushButton, QToolButton {
    background-color: transparent;
    color: #e2e8f0;
    border: 1px solid transparent;
    border-radius: 3px;
    padding: 1px 4px;
    height: 22px;
    min-width: 22px;
    font-size: 11px;
    font-weight: 600;
}

QPushButton:hover, QToolButton:hover {
    background-color: #334155;
    border: 1px solid #475569;
}

QPushButton:pressed, QToolButton:pressed {
    background-color: #1e293b;
}

QPushButton:disabled, QToolButton:disabled {
    color: #64748b;
    background-color: transparent;
    border: 1px solid transparent;
}

QPushButton#btn_start {
    color: #4ade80;
    font-weight: bold;
}
QPushButton#btn_start:hover {
    background-color: #064e3b;
    border: 1px solid #22c55e;
}

QPushButton#btn_stop {
    color: #f87171;
    font-weight: bold;
}
QPushButton#btn_stop:hover {
    background-color: #7f1d1d;
    border: 1px solid #ef4444;
}

QComboBox {
    background-color: #1e293b;
    border: 1px solid #475569;
    border-radius: 3px;
    padding: 1px 6px;
    color: #f8fafc;
    height: 22px;
    max-height: 22px;
    font-size: 11px;
}

QComboBox::drop-down {
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 16px;
    border-left: 1px solid #475569;
}

QComboBox QAbstractItemView {
    background-color: #1e293b;
    border: 1px solid #475569;
    selection-background-color: #2563eb;
    selection-color: #ffffff;
    color: #e2e8f0;
}

QWidget#filter_bar_container {
    background-color: #0f172a;
    border-bottom: 1px solid #334155;
    max-height: 26px;
}

QLineEdit#txt_filter {
    background-color: #0f172a;
    border: 1px solid #475569;
    border-radius: 3px;
    padding: 1px 6px;
    color: #f8fafc;
    height: 22px;
    max-height: 22px;
    font-size: 11.5px;
    font-family: "Consolas", "Segoe UI", monospace;
}

QLineEdit#txt_filter:focus {
    border: 1px solid #38bdf8;
    background-color: #0b1120;
}

QPushButton#btn_filter_apply {
    color: #4ade80;
    font-weight: bold;
    font-size: 12px;
}
QPushButton#btn_filter_apply:hover {
    background-color: #064e3b;
    border: 1px solid #22c55e;
}

QPushButton#btn_filter_clear {
    color: #94a3b8;
    font-size: 11px;
}
QPushButton#btn_filter_clear:hover {
    background-color: #7f1d1d;
    border: 1px solid #ef4444;
    color: #f87171;
}

QSplitter::handle { background-color: #334155; }
QSplitter::handle:horizontal { width: 4px; }
QSplitter::handle:vertical { height: 4px; }
QSplitter::handle:hover { background-color: #38bdf8; }

QTableWidget {
    border: 1px solid #334155;
    gridline-color: #1e293b;
    selection-background-color: #1d4ed8;
    selection-color: #ffffff;
}

QHeaderView::section {
    background-color: #1e293b;
    color: #94a3b8;
    padding: 4px 6px;
    border: none;
    border-right: 1px solid #334155;
    border-bottom: 1px solid #334155;
    font-weight: bold;
    font-size: 11.5px;
}

QTreeWidget {
    background-color: #0b1120;
    border: 1px solid #334155;
    color: #e2e8f0;
    selection-background-color: #1e3a5f;
    selection-color: #ffffff;
    font-size: 11.5px;
}

QTreeWidget::item { padding: 1px 0px; }
QTreeWidget::item:hover { background-color: #1e293b; }
QTreeWidget::item:selected { background-color: #1d4ed8; color: #ffffff; }

QPlainTextEdit {
    background-color: #050811;
    color: #38bdf8;
    border: 1px solid #334155;
    selection-background-color: #1e40af;
    selection-color: #ffffff;
    font-size: 11.5px;
}

QStatusBar {
    background-color: #1e293b;
    border-top: 1px solid #334155;
    color: #94a3b8;
    font-size: 11px;
    max-height: 22px;
}
QStatusBar QLabel { padding: 1px 6px; }
"""
