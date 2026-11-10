import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QTextEdit, QVBoxLayout, QWidget
from PyQt5.QtCore import QThread, pyqtSignal
from scapy.all import sniff

# 1. Luồng chạy ngầm để bắt gói tin (không làm đơ giao diện)
class SnifferThread(QThread):
    # Tạo tín hiệu gửi chuỗi tóm tắt gói tin sang giao diện
    packet_captured = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.is_running = True

    def run(self):
        # Hàm callback được gọi mỗi khi Scapy tóm được 1 gói tin
        def handle_packet(packet):
            if self.is_running:
                summary = packet.summary()
                self.packet_captured.emit(summary)

        # Chạy vòng lặp bắt gói tin liên tục
        sniff(prn=handle_packet, stop_filter=lambda x: not self.is_running)

    def stop(self):
        self.is_running = False

# 2. Cửa sổ giao diện chính
class SimpleSnifferWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Mini Wireshark — Bản thử nghiệm đầu tiên")
        self.resize(700, 400)

        # Tạo nút bấm và khung hiển thị văn bản
        self.btn_toggle = QPushButton("Bắt đầu bắt gói tin")
        self.btn_toggle.setFixedHeight(40)
        self.btn_toggle.clicked.connect(self.toggle_sniffing)

        self.text_log = QTextEdit()
        self.text_log.setReadOnly(True)

        # Bố trí các thành phần theo chiều dọc
        layout = QVBoxLayout()
        layout.addWidget(self.btn_toggle)
        layout.addWidget(self.text_log)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.sniffer_thread = None

    def toggle_sniffing(self):
        if self.sniffer_thread is None or not self.sniffer_thread.isRunning():
            # Bắt đầu luồng
            self.sniffer_thread = SnifferThread()
            self.sniffer_thread.packet_captured.connect(self.add_packet_to_ui)
            self.sniffer_thread.start()
            self.btn_toggle.setText("Dừng lại")
            self.btn_toggle.setStyleSheet("background-color: #ff4d4d; color: white; font-weight: bold;")
        else:
            # Dừng luồng
            self.sniffer_thread.stop()
            self.btn_toggle.setText("Bắt đầu bắt gói tin")
            self.btn_toggle.setStyleSheet("")

    def add_packet_to_ui(self, packet_summary):
        # Thêm dòng mới vào khung văn bản
        self.text_log.append(packet_summary)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SimpleSnifferWindow()
    window.show()
    sys.exit(app.exec_())