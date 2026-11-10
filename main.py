"""
Điểm khởi chạy chính của ứng dụng Mini Wireshark.
"""
import sys
import os
import logging

# Vô hiệu hóa cảnh báo scapy runtime tránh nghẽn I/O terminal
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
try:
    from scapy.all import conf
    conf.verb = 0
except Exception:
    pass

from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt

from ui.main_window import MainWindow


def main():
    # Hỗ trợ hiển thị sắc nét trên màn hình độ phân giải cao (High-DPI / 2K / 4K)
    if hasattr(Qt, "AA_EnableHighDpiScaling"):
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    if hasattr(Qt, "AA_UseHighDpiPixmaps"):
        QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName("Mini Wireshark")
    app.setOrganizationName("Telecommunications Network Lab")

    window = MainWindow()
    window.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
