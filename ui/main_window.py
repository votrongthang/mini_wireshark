"""
Cửa sổ chính của ứng dụng Mini Wireshark (Main Window).
Thiết kế chuẩn Wireshark với:
- Menu Bar đầy đủ: File, Capture, View, Statistics, Help
- Toolbar với nút điều khiển, card mạng, tự động cuộn, chuyển đổi Dark/Light mode
- Bố cục 3 khung chuẩn hình ảnh Wireshark:
  1. Khung trên (Top Pane): Bảng danh sách gói tin (Packet Table)
  2. Khung dưới bên trái (Bottom-Left Pane): Cây phân tích chi tiết các tầng (Protocol Tree)
  3. Khung dưới bên phải (Bottom-Right Pane): Dữ liệu nhị phân thô (Hex & ASCII View)
"""
import os
import sys
import time
import queue
from typing import List, Dict, Any, Optional

from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QToolBar, QComboBox, QLineEdit, QPushButton, QLabel, QCheckBox,
    QFileDialog, QMessageBox, QStatusBar, QApplication, QAction, QMenuBar, QMenu
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont

from scapy.packet import Packet

from core.sniffer import CaptureWorker, get_available_interfaces
from core.parser import parse_packet_summary, parse_packet_layers, reset_tcp_tracker
from core.pcap_manager import save_pcap, load_pcap
from core.filter_engine import match_display_filter
from ui.packet_table import PacketTable
from ui.protocol_tree import ProtocolTree
from ui.hex_view import HexView
from ui.stats_dialog import StatsDialog
from ui.coloring_rules_dialog import ColoringRulesDialog
from ui.tcp_stream_dialog import TcpStreamDialog
from ui.theme_manager import LIGHT_QSS, DARK_QSS, get_packet_color


class MainWindow(QMainWindow):
    """Cửa sổ làm việc chính chuẩn Wireshark."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Mini Wireshark — Bộ Phân Tích & Bắt Gói Tin Mạng Thời Gian Thực")
        self.resize(1280, 820)

        # Trạng thái giao diện: 'light' hoặc 'dark'
        self.current_theme = "light"

        # Bộ đệm lưu trữ dữ liệu phiên làm việc
        self.raw_packets: List[Packet] = []
        self.packet_summaries: List[Dict[str, Any]] = []
        self.displayed_indices: List[int] = []

        # Hàng đợi an toàn đa luồng (thread-safe Queue) chứa gói tin chờ hiển thị
        self.packet_queue: queue.Queue = queue.Queue()
        # Biến đếm số thứ tự gói tin tăng liên tục (Monotonically Increasing), không bao giờ reset khi đạt mốc
        self.packet_count: int = 0

        self.start_timestamp: Optional[float] = None
        self.capture_worker: Optional[CaptureWorker] = None

        # Danh sách các bộ lọc mẫu / đã lưu (Bookmarks)
        self.saved_filters: List[str] = [
            "error",
            "tcp",
            "udp",
            "dns",
            "arp",
            "icmp",
            "http",
            "tls",
            "port == 80 or port == 443",
            "len > 100"
        ]

        # Timer chu kỳ 100ms (10 lần/giây) để xả hàng đợi vào bảng theo lô (Batching)
        self.ui_update_timer = QTimer(self)
        self.ui_update_timer.setInterval(100)
        self.ui_update_timer.timeout.connect(self._flush_pending_packets)
        self.ui_update_timer.start()

        self.init_menu_bar()
        self.init_ui()
        self.load_interfaces()
        self.apply_theme(self.current_theme)

    def init_menu_bar(self):
        """Khởi tạo thanh menu chuẩn (File, Capture, View, Statistics, Help)."""
        menubar = self.menuBar()

        # 1. Menu Tệp tin (File)
        file_menu = menubar.addMenu("&Tệp tin (File)")
        act_open = QAction("📂 Mở tệp tin PCAP...", self)
        act_open.setShortcut("Ctrl+O")
        act_open.triggered.connect(self.open_pcap_file)
        file_menu.addAction(act_open)

        act_save = QAction("💾 Lưu tệp tin PCAP...", self)
        act_save.setShortcut("Ctrl+S")
        act_save.triggered.connect(self.save_pcap_file)
        file_menu.addAction(act_save)

        act_export_csv = QAction("📄 Xuất danh sách gói tin ra CSV...", self)
        act_export_csv.triggered.connect(self.export_to_csv)
        file_menu.addAction(act_export_csv)

        file_menu.addSeparator()

        act_clear = QAction("🗑 Xóa dữ liệu hiện tại", self)
        act_clear.triggered.connect(self.clear_capture_data)
        file_menu.addAction(act_clear)

        file_menu.addSeparator()

        act_exit = QAction("❌ Thoát", self)
        act_exit.setShortcut("Ctrl+Q")
        act_exit.triggered.connect(self.close)
        file_menu.addAction(act_exit)

        # 2. Menu Bắt gói (Capture)
        cap_menu = menubar.addMenu("&Bắt gói (Capture)")
        act_start = QAction("▶ Bắt đầu bắt gói", self)
        act_start.setShortcut("Ctrl+E")
        act_start.triggered.connect(self.start_capture)
        cap_menu.addAction(act_start)

        act_restart = QAction("🔁 Bắt lại từ đầu (Restart)", self)
        act_restart.setShortcut("Ctrl+R")
        act_restart.triggered.connect(self.restart_capture)
        cap_menu.addAction(act_restart)

        act_pause = QAction("⏸ Tạm dừng / Tiếp tục", self)
        act_pause.triggered.connect(self.toggle_pause)
        cap_menu.addAction(act_pause)

        act_stop = QAction("⏹ Dừng lại", self)
        act_stop.triggered.connect(self.stop_capture)
        cap_menu.addAction(act_stop)

        cap_menu.addSeparator()
        act_refresh_nic = QAction("🔄 Làm mới danh sách card mạng", self)
        act_refresh_nic.triggered.connect(self.load_interfaces)
        cap_menu.addAction(act_refresh_nic)

        # 3. Menu Hiển thị (View)
        view_menu = menubar.addMenu("&Hiển thị (View)")
        act_toggle_theme = QAction("🌓 Chuyển đổi Dark / Light Mode", self)
        act_toggle_theme.triggered.connect(self.toggle_theme)
        view_menu.addAction(act_toggle_theme)

        act_coloring_rules = QAction("🎨 Quy tắc phối màu (Coloring Rules)...", self)
        act_coloring_rules.triggered.connect(self.show_coloring_rules)
        view_menu.addAction(act_coloring_rules)

        # 4. Menu Thống kê (Statistics)
        stats_menu = menubar.addMenu("&Thống kê (Statistics)")
        act_stats = QAction("📊 Phân bố lưu lượng (Protocol Hierarchy)...", self)
        act_stats.triggered.connect(self.show_statistics)
        stats_menu.addAction(act_stats)

        # 5. Menu Kịch bản Demo (Demo) phục vụ báo cáo đồ án
        demo_menu = menubar.addMenu("&Kịch bản Demo (Demo)")
        act_d1 = QAction("1. Giao thức ICMP (Ping Echo 4 gói Google)...", self)
        act_d1.triggered.connect(lambda: self.load_sample_capture("scenario1_icmp_ping.pcap"))
        demo_menu.addAction(act_d1)

        act_d2 = QAction("2. Giao thức TCP (Bắt tay 3 bước + HTTP + FIN)...", self)
        act_d2.triggered.connect(lambda: self.load_sample_capture("scenario2_tcp_handshake.pcap"))
        demo_menu.addAction(act_d2)

        act_d3 = QAction("3. Giao thức UDP & DNS (Phân giải tên miền A record)...", self)
        act_d3.triggered.connect(lambda: self.load_sample_capture("scenario3_dns_lookup.pcap"))
        demo_menu.addAction(act_d3)

        act_d4 = QAction("4. Sự cố Bad TCP & Retransmission (Cờ RST, Nền đen chữ đỏ)...", self)
        act_d4.triggered.connect(lambda: self.load_sample_capture("scenario4_bad_tcp.pcap"))
        demo_menu.addAction(act_d4)

        demo_menu.addSeparator()
        act_d5 = QAction("5. Phiên bắt gói tin tổng hợp 8 giao thức (demo.pcap)...", self)
        act_d5.triggered.connect(lambda: self.load_sample_capture("demo.pcap"))
        demo_menu.addAction(act_d5)

        act_d6 = QAction("6. Mẫu chuẩn giao diện Wireshark thực tế (IPv6 UDP, TLS, Bad TCP)...", self)
        act_d6.triggered.connect(lambda: self.load_sample_capture("scenario5_wireshark_sample.pcap"))
        demo_menu.addAction(act_d6)

        # 6. Menu Trợ giúp (Help)
        help_menu = menubar.addMenu("&Trợ giúp (Help)")
        act_about = QAction("ℹ️ Giới thiệu Mini Wireshark", self)
        act_about.triggered.connect(self.show_about_dialog)
        help_menu.addAction(act_about)

    def init_ui(self):
        # 1. Thanh công cụ chính siêu gọn (Toolbar - Chiều cao 28-30px chuẩn Wireshark)
        self.toolbar = QToolBar("Main Toolbar")
        self.toolbar.setMovable(False)
        self.toolbar.setFixedHeight(28)
        self.addToolBar(self.toolbar)

        # Card mạng: Label nhỏ & ComboBox tối đa 220px
        lbl_nic = QLabel(" Card: ")
        lbl_nic.setStyleSheet("font-size: 11px; font-weight: bold;")
        self.toolbar.addWidget(lbl_nic)

        self.combo_nic = QComboBox()
        self.combo_nic.setMaximumWidth(220)
        self.combo_nic.setFixedHeight(22)
        self.combo_nic.currentIndexChanged.connect(self.on_nic_changed)
        self.toolbar.addWidget(self.combo_nic)

        # Nút Làm mới (Icon reload phẳng)
        self.btn_refresh_nic = QPushButton("🔄")
        self.btn_refresh_nic.setFixedSize(24, 22)
        self.btn_refresh_nic.setToolTip("Làm mới danh sách card mạng")
        self.btn_refresh_nic.clicked.connect(self.load_interfaces)
        self.toolbar.addWidget(self.btn_refresh_nic)

        self.toolbar.addSeparator()

        # Nút Bắt đầu (Start) - Icon tam giác xanh
        self.btn_start = QPushButton("▶")
        self.btn_start.setObjectName("btn_start")
        self.btn_start.setFixedSize(24, 22)
        self.btn_start.setToolTip("Bắt đầu bắt gói tin (Start)")
        self.btn_start.clicked.connect(self.start_capture)
        self.toolbar.addWidget(self.btn_start)

        # Nút Dừng lại (Stop) - Icon ô vuông đỏ
        self.btn_stop = QPushButton("⏹")
        self.btn_stop.setObjectName("btn_stop")
        self.btn_stop.setFixedSize(24, 22)
        self.btn_stop.setToolTip("Dừng bắt gói tin (Stop)")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_capture)
        self.toolbar.addWidget(self.btn_stop)

        # Nút Bắt lại từ đầu (Restart)
        self.btn_restart = QPushButton("🔁")
        self.btn_restart.setFixedSize(24, 22)
        self.btn_restart.setToolTip("Bắt lại từ đầu (Restart capture)")
        self.btn_restart.clicked.connect(self.restart_capture)
        self.toolbar.addWidget(self.btn_restart)

        # Nút Tạm dừng / Tiếp tục
        self.btn_pause = QPushButton("⏸")
        self.btn_pause.setFixedSize(24, 22)
        self.btn_pause.setToolTip("Tạm dừng / Tiếp tục bắt gói")
        self.btn_pause.setEnabled(False)
        self.btn_pause.clicked.connect(self.toggle_pause)
        self.toolbar.addWidget(self.btn_pause)

        # Nút Xóa sạch (Clear) - Icon thùng rác
        self.btn_clear = QPushButton("🗑")
        self.btn_clear.setFixedSize(24, 22)
        self.btn_clear.setToolTip("Xóa sạch danh sách gói tin (Clear)")
        self.btn_clear.clicked.connect(self.clear_capture_data)
        self.toolbar.addWidget(self.btn_clear)

        self.toolbar.addSeparator()

        # Nút Mở / Lưu PCAP
        self.btn_open_pcap = QPushButton("📂")
        self.btn_open_pcap.setFixedSize(24, 22)
        self.btn_open_pcap.setToolTip("Mở tệp .pcap để phân tích ngoại tuyến")
        self.btn_open_pcap.clicked.connect(self.open_pcap_file)
        self.toolbar.addWidget(self.btn_open_pcap)

        self.btn_save_pcap = QPushButton("💾")
        self.btn_save_pcap.setFixedSize(24, 22)
        self.btn_save_pcap.setToolTip("Lưu phiên bắt gói tin ra file .pcap")
        self.btn_save_pcap.clicked.connect(self.save_pcap_file)
        self.toolbar.addWidget(self.btn_save_pcap)

        self.toolbar.addSeparator()

        # Nút Thống kê
        self.btn_stats = QPushButton("📊")
        self.btn_stats.setFixedSize(24, 22)
        self.btn_stats.setToolTip("Thống kê phân bố lưu lượng theo giao thức (Protocol Hierarchy)")
        self.btn_stats.clicked.connect(self.show_statistics)
        self.toolbar.addWidget(self.btn_stats)

        # Nút Chuyển đổi Dark / Light Mode
        self.btn_theme_toggle = QPushButton("🌙")
        self.btn_theme_toggle.setObjectName("btn_theme")
        self.btn_theme_toggle.setFixedSize(24, 22)
        self.btn_theme_toggle.setToolTip("Chuyển đổi Giao diện Sáng / Tối")
        self.btn_theme_toggle.clicked.connect(self.toggle_theme)
        self.toolbar.addWidget(self.btn_theme_toggle)

        self.toolbar.addSeparator()

        # Checkbox Tự động cuộn
        self.chk_auto_scroll = QCheckBox("Cuộn")
        self.chk_auto_scroll.setStyleSheet("font-size: 11px;")
        self.chk_auto_scroll.setChecked(True)
        self.chk_auto_scroll.setToolTip("Tự động cuộn xuống gói tin mới nhất")
        self.chk_auto_scroll.toggled.connect(self.on_auto_scroll_toggled)
        self.toolbar.addWidget(self.chk_auto_scroll)

        # 2. Vùng trung tâm & Thanh bộ lọc hiển thị (Display Filter Bar cao 26px chuẩn Wireshark)
        central_widget = QWidget()
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(4, 2, 4, 2)
        main_layout.setSpacing(2)

        # Khung thanh lọc Display Filter Bar
        filter_container = QWidget()
        filter_container.setObjectName("filter_bar_container")
        filter_container.setFixedHeight(26)

        filter_layout = QHBoxLayout(filter_container)
        filter_layout.setContentsMargins(3, 1, 3, 1)
        filter_layout.setSpacing(3)

        self.btn_filter_icon = QPushButton("🔖")
        self.btn_filter_icon.setFixedSize(22, 22)
        self.btn_filter_icon.setToolTip("Danh sách bộ lọc mẫu / đã lưu (Display Filter Bookmarks)")
        self.btn_filter_icon.clicked.connect(self.show_filter_bookmarks_menu)
        filter_layout.addWidget(self.btn_filter_icon)

        self.txt_filter = QLineEdit()
        self.txt_filter.setObjectName("txt_filter")
        self.txt_filter.setFixedHeight(22)
        self.txt_filter.setPlaceholderText("Apply a display filter ... <Ctrl-/> (Ví dụ: tcp, udp, dns, ip.src==192.168.1.1, len > 100)")
        self.txt_filter.returnPressed.connect(self.apply_filter)
        self.txt_filter.textChanged.connect(self.on_filter_text_changed)
        filter_layout.addWidget(self.txt_filter)

        self.btn_apply_filter = QPushButton("➔")
        self.btn_apply_filter.setObjectName("btn_filter_apply")
        self.btn_apply_filter.setFixedSize(22, 22)
        self.btn_apply_filter.setToolTip("Áp dụng bộ lọc (Enter)")
        self.btn_apply_filter.clicked.connect(self.apply_filter)
        filter_layout.addWidget(self.btn_apply_filter)

        self.btn_clear_filter = QPushButton("✖")
        self.btn_clear_filter.setObjectName("btn_filter_clear")
        self.btn_clear_filter.setFixedSize(22, 22)
        self.btn_clear_filter.setToolTip("Xóa bộ lọc")
        self.btn_clear_filter.clicked.connect(self.clear_filter)
        filter_layout.addWidget(self.btn_clear_filter)

        self.btn_add_filter = QPushButton("➕")
        self.btn_add_filter.setObjectName("btn_filter_add")
        self.btn_add_filter.setFixedSize(22, 22)
        self.btn_add_filter.setToolTip("Lưu biểu thức lọc hiện tại vào Bookmarks và áp dụng (+)")
        self.btn_add_filter.clicked.connect(self.save_and_apply_filter)
        filter_layout.addWidget(self.btn_add_filter)

        main_layout.addWidget(filter_container)

        # 3. BỐ CỤC CHUẨN 3 KHUNG (GIỐNG HỆT HÌNH ẢNH WIRESHARK)
        # Splitter chính theo chiều dọc (Tách Khung Trên và Khung Dưới)
        self.main_splitter = QSplitter(Qt.Vertical)

        # Khung 1 (TRÊN CÙNG): Bảng danh sách gói tin (Toàn bộ chiều ngang)
        self.packet_table = PacketTable()
        self.packet_table.packet_selected.connect(self.on_packet_selected)
        self.packet_table.filter_requested.connect(self.on_filter_requested_from_context)
        self.packet_table.tcp_stream_requested.connect(self.open_tcp_stream)
        self.main_splitter.addWidget(self.packet_table)

        # Khung Dưới: Splitter theo chiều ngang (Chia đôi Trái - Phải)
        self.bottom_splitter = QSplitter(Qt.Horizontal)

        # Khung 2 (DƯỚI BÊN TRÁI): Cây phân tích chi tiết các tầng giao thức
        self.protocol_tree = ProtocolTree()
        self.bottom_splitter.addWidget(self.protocol_tree)

        # Khung 3 (DƯỚI BÊN PHẢI): Vùng hiển thị mã Hex & ASCII
        self.hex_view = HexView()
        self.bottom_splitter.addWidget(self.hex_view)

        # Tỷ lệ Khung dưới: 55% Protocol Tree, 45% Hex View (như ảnh Wireshark)
        self.bottom_splitter.setSizes([600, 500])

        # Đưa cụm khung dưới vào Splitter chính
        self.main_splitter.addWidget(self.bottom_splitter)

        # Tỷ lệ Khung Trên vs Khung Dưới: 55% Bảng gói tin, 45% Khung chi tiết bên dưới
        self.main_splitter.setSizes([450, 320])

        main_layout.addWidget(self.main_splitter)
        self.setCentralWidget(central_widget)

        # 4. Thanh trạng thái (Status Bar chuẩn Wireshark)
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

        self.lbl_status = QLabel("● Sẵn sàng")
        self.lbl_current_nic = QLabel("NIC: Chưa chọn")
        self.lbl_packet_count = QLabel("Packets: 0 • Displayed: 0 (0.0%)")
        self.lbl_profile = QLabel("Profile: Default")

        self.status_bar.addWidget(self.lbl_status, 2)
        self.status_bar.addPermanentWidget(self.lbl_current_nic)
        self.status_bar.addPermanentWidget(self.lbl_packet_count)
        self.status_bar.addPermanentWidget(self.lbl_profile)

    def on_auto_scroll_toggled(self, checked: bool):
        self.packet_table.set_auto_scroll(checked)

    def on_filter_requested_from_context(self, filter_expr: str):
        """Áp dụng bộ lọc nhanh từ Menu chuột phải của Packet Table."""
        self.txt_filter.setText(filter_expr)
        self.apply_filter()

    def toggle_theme(self):
        """Chuyển đổi qua lại giữa Light Mode và Dark Mode."""
        if self.current_theme == "light":
            self.apply_theme("dark")
        else:
            self.apply_theme("light")

    def apply_theme(self, theme_name: str):
        """Áp dụng màu sắc toàn diện cho ứng dụng."""
        self.current_theme = theme_name

        if theme_name == "dark":
            self.setStyleSheet(DARK_QSS)
            self.btn_theme_toggle.setText("☀️")
            self.btn_theme_toggle.setToolTip("Chuyển sang Giao diện Sáng (Light Mode)")
        else:
            self.setStyleSheet(LIGHT_QSS)
            self.btn_theme_toggle.setText("🌙")
            self.btn_theme_toggle.setToolTip("Chuyển sang Giao diện Tối (Dark Mode)")

        self.packet_table.set_theme(theme_name)
        self.protocol_tree.set_theme(theme_name)
        self.hex_view.set_theme(theme_name)
        self.on_filter_text_changed(self.txt_filter.text())

    def on_nic_changed(self, index: int):
        """Cập nhật thanh trạng thái ngay khi người dùng chọn card mạng khác."""
        nic_data = self.combo_nic.currentData()
        if nic_data:
            self.lbl_current_nic.setText(f"NIC: {nic_data}")

    def show_filter_bookmarks_menu(self):
        """Hiển thị menu danh sách các biểu thức lọc mẫu / đã lưu khi bấm nút 🔖."""
        menu = QMenu(self)
        for expr in self.saved_filters:
            act = QAction(f"🔍 {expr}", self)
            act.triggered.connect(lambda checked=False, e=expr: self.on_filter_requested_from_context(e))
            menu.addAction(act)

        if self.txt_filter.text().strip():
            menu.addSeparator()
            act_clear = QAction("✖ Xóa bộ lọc hiện tại", self)
            act_clear.triggered.connect(self.clear_filter)
            menu.addAction(act_clear)

        pos = self.btn_filter_icon.mapToGlobal(self.btn_filter_icon.rect().bottomLeft())
        menu.exec_(pos)

    def save_and_apply_filter(self):
        """Lưu biểu thức lọc hiện tại vào danh sách Bookmarks và áp dụng lọc."""
        expr = self.txt_filter.text().strip()
        if expr and expr not in self.saved_filters:
            self.saved_filters.append(expr)
            self.lbl_status.setText(f"● Đã lưu bộ lọc '{expr}' vào Bookmarks")
        self.apply_filter()

    def load_interfaces(self):
        """Tải danh sách các card mạng vào ComboBox."""
        self.combo_nic.clear()
        interfaces = get_available_interfaces()
        
        default_index = 0
        for idx, iface in enumerate(interfaces):
            self.combo_nic.addItem(iface["label"], iface["id"])
            if iface.get("ips") and ("Wi-Fi" in iface["id"] or "Ethernet" in iface["id"]):
                default_index = idx

        if interfaces:
            self.combo_nic.setCurrentIndex(default_index)
            self.lbl_current_nic.setText(f"NIC: {self.combo_nic.currentData()}")

    def start_capture(self):
        """Bắt đầu luồng lắng nghe gói tin."""
        iface_id = self.combo_nic.currentData()
        if not iface_id:
            QMessageBox.warning(self, "Cảnh báo", "Vui lòng chọn card mạng trước khi bắt đầu!")
            return

        # 3. Đảm bảo an toàn: Nếu luồng cũ còn đang chạy thì dừng và chờ kết thúc hoàn toàn
        if self.capture_worker is not None and self.capture_worker.isRunning():
            self.capture_worker.stop()
            self.capture_worker.wait()

        self.setWindowTitle(f"*{iface_id} — Mini Wireshark")
        self.lbl_status.setText(f"● Đang bắt gói tin trên [{iface_id}]...")

        if not self.raw_packets:
            self.start_timestamp = time.time()

        # 1. Khởi tạo luồng bắt gói kết nối trực tiếp với thread-safe queue.Queue()
        self.capture_worker = CaptureWorker(iface=iface_id, packet_queue=self.packet_queue)
        self.capture_worker.capture_error.connect(self.on_capture_error)
        self.capture_worker.capture_stopped.connect(self.on_capture_stopped)
        self.capture_worker.start()

        self.btn_start.setEnabled(False)
        self.btn_pause.setEnabled(True)
        self.btn_pause.setText("⏸")
        self.btn_pause.setToolTip("Tạm dừng bắt gói tin")
        self.btn_stop.setEnabled(True)
        self.combo_nic.setEnabled(False)
        self.btn_refresh_nic.setEnabled(False)

    def restart_capture(self):
        """Khởi động lại phiên bắt gói tin từ đầu (Restart)."""
        self.stop_capture()
        self.clear_capture_data()
        self.start_capture()

    def toggle_pause(self):
        """Tạm dừng hoặc tiếp tục phiên bắt gói."""
        if not self.capture_worker:
            return

        if self.capture_worker.is_paused:
            self.capture_worker.resume()
            self.btn_pause.setText("⏸")
            self.btn_pause.setToolTip("Tạm dừng bắt gói tin")
            self.lbl_status.setText("● Đang bắt gói tin...")
        else:
            self.capture_worker.pause()
            self.btn_pause.setText("▶")
            self.btn_pause.setToolTip("Tiếp tục bắt gói tin")
            self.lbl_status.setText("● Đã tạm dừng")

    def stop_capture(self):
        """Dừng tiến trình bắt gói tin."""
        if self.capture_worker and self.capture_worker.isRunning():
            self.lbl_status.setText("● Đang dừng luồng...")
            self.capture_worker.stop()
            self.capture_worker.wait()

        self.setWindowTitle("Mini Wireshark — Bộ Phân Tích & Bắt Gói Tin Mạng Thời Gian Thực")
        self.btn_start.setEnabled(True)
        self.btn_pause.setEnabled(False)
        self.btn_stop.setEnabled(False)
        self.combo_nic.setEnabled(True)
        self.btn_refresh_nic.setEnabled(True)
        self.lbl_status.setText("● Đã dừng")

    def on_capture_stopped(self):
        self.btn_start.setEnabled(True)
        self.btn_pause.setEnabled(False)
        self.btn_stop.setEnabled(False)
        self.combo_nic.setEnabled(True)
        self.btn_refresh_nic.setEnabled(True)
        self.lbl_status.setText("● Đã dừng")

    def on_capture_error(self, message: str):
        self.stop_capture()
        QMessageBox.critical(self, "Lỗi bắt gói tin", message)

    def _flush_pending_packets(self):
        """
        Kích hoạt định kỳ mỗi 100ms bởi QTimer (10 lần/giây):
        - Rút toàn bộ gói tin từ hàng đợi thread-safe queue.Queue()
        - Đảm bảo gói nào đã rút ra khỏi queue thì không bao giờ bị chèn lại lần thứ hai
        - Quản lý số thứ tự gói tin self.packet_count tăng liên tục đơn điệu (không modulo/reset)
        """
        packets_to_insert = []
        while not self.packet_queue.empty():
            try:
                packets_to_insert.append(self.packet_queue.get_nowait())
            except queue.Empty:
                break

        if not packets_to_insert:
            return

        filter_text = self.txt_filter.text().strip()
        new_summaries = []

        for pkt in packets_to_insert:
            self.packet_count += 1
            pkt_no = self.packet_count

            self.raw_packets.append(pkt)
            summary = parse_packet_summary(pkt, pkt_no, self.start_timestamp)
            self.packet_summaries.append(summary)

            if not filter_text or match_display_filter(filter_text, summary):
                self.displayed_indices.append(len(self.raw_packets) - 1)
                new_summaries.append(summary)

        # Thêm lô gói tin vào bảng (Không giới hạn, lưu trọn vẹn từ gói 1)
        if new_summaries:
            self.packet_table.add_packets_batch(new_summaries, max_limit=None)

        # Cập nhật số đếm trên thanh trạng thái
        self._update_counts()

    def on_packet_selected(self, table_row_idx: int):
        """Callback khi người dùng bấm chuột chọn 1 dòng trên Packet Table."""
        if 0 <= table_row_idx < len(self.displayed_indices):
            raw_pkt_idx = self.displayed_indices[table_row_idx]
            packet = self.raw_packets[raw_pkt_idx]
            pkt_no = self.packet_summaries[raw_pkt_idx].get("no", raw_pkt_idx + 1)

            # 1. Cập nhật cây chi tiết các tầng (Khung dưới bên trái)
            layers = parse_packet_layers(packet, pkt_no)
            self.protocol_tree.display_packet(layers)

            # 2. Cập nhật mã Hex & ASCII (Khung dưới bên phải)
            raw_bytes = bytes(packet)
            self.hex_view.display_data(raw_bytes)

    def on_filter_text_changed(self, text: str):
        """
        Đổi màu nền thanh Display Filter Bar theo thời gian thực chuẩn Wireshark:
        - Xanh lá mạ (#c5ffc5 / #064e3b): Cú pháp hợp lệ
        - Hồng đỏ nhạt (#ffc5c5 / #7f1d1d): Cú pháp chưa hoàn chỉnh hoặc có lỗi
        - Trắng / Mặc định: Thanh tìm kiếm rỗng
        """
        from core.filter_engine import validate_filter_syntax
        val = text.strip()
        if not val:
            self.txt_filter.setStyleSheet("")
            return

        is_valid = validate_filter_syntax(val)
        if is_valid:
            if self.current_theme == "dark":
                self.txt_filter.setStyleSheet(
                    "background-color: #064e3b; color: #a7f3d0; border: 1px solid #10b981;"
                )
            else:
                self.txt_filter.setStyleSheet(
                    "background-color: #c5ffc5; color: #000000; border: 1px solid #22c55e;"
                )
        else:
            if self.current_theme == "dark":
                self.txt_filter.setStyleSheet(
                    "background-color: #7f1d1d; color: #fecaca; border: 1px solid #ef4444;"
                )
            else:
                self.txt_filter.setStyleSheet(
                    "background-color: #ffc5c5; color: #000000; border: 1px solid #f87171;"
                )

    def apply_filter(self):
        """Lọc và cập nhật lại bảng danh sách gói tin (sử dụng Batching)."""
        filter_text = self.txt_filter.text().strip()
        self.packet_table.clear_all()
        self.displayed_indices.clear()

        matched_summaries = []
        for idx, summary in enumerate(self.packet_summaries):
            if not filter_text or match_display_filter(filter_text, summary):
                self.displayed_indices.append(idx)
                matched_summaries.append(summary)

        # Nạp toàn bộ các gói tin khớp bộ lọc mà không cắt tỉa
        self.packet_table.add_packets_batch(matched_summaries, max_limit=None)
        self._update_counts()
        self.protocol_tree.clear_tree()
        self.hex_view.clear_view()

    def clear_filter(self):
        """Bỏ bộ lọc và hiển thị lại toàn bộ gói tin."""
        self.txt_filter.clear()
        self.txt_filter.setStyleSheet("")
        self.apply_filter()

    def clear_capture_data(self):
        """Xóa sạch bộ nhớ tạm, hàng đợi và giao diện."""
        if self.capture_worker and self.capture_worker.isRunning():
            QMessageBox.information(self, "Thông báo", "Vui lòng dừng bắt gói tin trước khi xóa!")
            return

        # Rút sạch hàng đợi an toàn đa luồng
        while not self.packet_queue.empty():
            try:
                self.packet_queue.get_nowait()
            except queue.Empty:
                break

        self.packet_count = 0
        self.raw_packets.clear()
        self.packet_summaries.clear()
        self.displayed_indices.clear()
        self.start_timestamp = None
        reset_tcp_tracker()

        self.packet_table.clear_all()
        self.protocol_tree.clear_tree()
        self.hex_view.clear_view()
        self._update_counts()
        self.lbl_status.setText("● Đã xóa dữ liệu")

    def _update_counts(self):
        total = len(self.raw_packets)
        disp = len(self.displayed_indices)
        pct = (disp / total * 100.0) if total > 0 else 0.0
        self.lbl_packet_count.setText(f"Packets: {total} • Displayed: {disp} ({pct:.1f}%)")

    def open_pcap_file(self):
        """Mở tệp .pcap tiêu chuẩn để xem ngoại tuyến."""
        if self.capture_worker and self.capture_worker.isRunning():
            QMessageBox.warning(self, "Cảnh báo", "Vui lòng dừng tiến trình bắt gói tin hiện tại!")
            return

        filepath, _ = QFileDialog.getOpenFileName(
            self, "Mở tệp tin PCAP", "", "Wireshark PCAP Files (*.pcap *.pcapng);;All Files (*)"
        )
        if not filepath:
            return

        try:
            filename = os.path.basename(filepath)
            self.lbl_status.setText(f"● Đang đọc tệp: {filename}...")
            QApplication.processEvents()
            
            packets = load_pcap(filepath)
            self.clear_capture_data()

            self.start_timestamp = float(packets[0].time) if packets else time.time()
            for pkt in packets:
                self.packet_count += 1
                pkt_no = self.packet_count
                self.raw_packets.append(pkt)
                summary = parse_packet_summary(pkt, pkt_no, self.start_timestamp)
                self.packet_summaries.append(summary)

            self.apply_filter()
            self.setWindowTitle(f"{filename} — Mini Wireshark")
            self.lbl_status.setText(f"● Đã mở tệp: {filename} ({len(packets)} gói)")
            if self.packet_table.rowCount() > 0:
                self.packet_table.selectRow(0)
        except Exception as e:
            QMessageBox.critical(self, "Lỗi mở file", f"Không thể đọc tệp PCAP:\n{str(e)}")
            self.lbl_status.setText("● Lỗi mở file")

    def load_sample_capture(self, sample_filename: str):
        """Tải một file mẫu pcap từ thư mục assets/sample_captures/ phục vụ demo báo cáo."""
        if self.capture_worker and self.capture_worker.isRunning():
            self.stop_capture()

        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        pcap_path = os.path.join(base_dir, "assets", "sample_captures", sample_filename)
        if not os.path.exists(pcap_path):
            QMessageBox.warning(self, "Lỗi", f"Không tìm thấy file mẫu:\n{pcap_path}")
            return

        try:
            self.lbl_status.setText(f"● Đang đọc mẫu demo: {sample_filename}...")
            QApplication.processEvents()

            packets = load_pcap(pcap_path)
            self.clear_capture_data()

            self.start_timestamp = float(packets[0].time) if packets else time.time()
            for pkt in packets:
                self.packet_count += 1
                pkt_no = self.packet_count
                self.raw_packets.append(pkt)
                summary = parse_packet_summary(pkt, pkt_no, self.start_timestamp)
                self.packet_summaries.append(summary)

            self.apply_filter()
            self.setWindowTitle(f"{sample_filename} — Mini Wireshark")
            self.lbl_status.setText(f"● Đã tải mẫu demo: {sample_filename} ({len(packets)} gói)")

            if self.packet_table.rowCount() > 0:
                self.packet_table.selectRow(0)
        except Exception as e:
            QMessageBox.critical(self, "Lỗi đọc file mẫu", f"Không thể tải mẫu demo:\n{str(e)}")
            self.lbl_status.setText("● Lỗi nạp mẫu demo")

    def save_pcap_file(self):
        """Lưu toàn bộ gói tin hiện tại ra tệp .pcap."""
        if not self.raw_packets:
            QMessageBox.information(self, "Thông báo", "Chưa có gói tin nào để lưu!")
            return

        filepath, _ = QFileDialog.getSaveFileName(
            self, "Lưu phiên bắt gói tin", "capture.pcap", "PCAP Files (*.pcap);;All Files (*)"
        )
        if not filepath:
            return

        try:
            save_pcap(filepath, self.raw_packets)
            QMessageBox.information(self, "Thành công", f"Đã lưu thành công {len(self.raw_packets)} gói tin vào:\n{filepath}")
            self.lbl_status.setText(f"Đã lưu tệp: {os.path.basename(filepath)}")
        except Exception as e:
            QMessageBox.critical(self, "Lỗi lưu file", f"Không thể ghi tệp PCAP:\n{str(e)}")

    def show_statistics(self):
        """Hiển thị hộp thoại thống kê phân tích lưu lượng."""
        if not self.packet_summaries:
            QMessageBox.information(self, "Thông báo", "Chưa có dữ liệu gói tin để thống kê!")
            return

        dialog = StatsDialog(self.packet_summaries, self)
        dialog.exec_()

    def open_tcp_stream(self, table_row_idx: int):
        """Mở cửa sổ theo dõi luồng TCP (Follow TCP Stream)."""
        if 0 <= table_row_idx < len(self.displayed_indices):
            raw_pkt_idx = self.displayed_indices[table_row_idx]
            selected_pkt = self.raw_packets[raw_pkt_idx]
            dialog = TcpStreamDialog(self.raw_packets, selected_pkt, self)
            dialog.exec_()

    def show_coloring_rules(self):
        """Hiển thị bảng quy tắc phối màu chuẩn Wireshark."""
        dialog = ColoringRulesDialog(self.current_theme, self)
        dialog.exec_()

    def export_to_csv(self):
        """Xuất danh sách các gói tin đang hiển thị ra tệp CSV."""
        if not self.packet_summaries:
            QMessageBox.information(self, "Thông báo", "Chưa có dữ liệu để xuất file CSV!")
            return

        filepath, _ = QFileDialog.getSaveFileName(
            self, "Xuất dữ liệu CSV", "packets_export.csv", "CSV Files (*.csv);;All Files (*)"
        )
        if not filepath:
            return

        try:
            import csv
            with open(filepath, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)
                writer.writerow(["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"])
                for idx in self.displayed_indices:
                    s = self.packet_summaries[idx]
                    writer.writerow([
                        s.get("no"), s.get("time"), s.get("src"), s.get("dst"),
                        s.get("protocol"), s.get("length"), s.get("info")
                    ])
            QMessageBox.information(self, "Thành công", f"Đã xuất thành công {len(self.displayed_indices)} gói tin ra:\n{filepath}")
        except Exception as e:
            QMessageBox.critical(self, "Lỗi xuất CSV", f"Không thể ghi tệp CSV:\n{str(e)}")

    def show_about_dialog(self):
        """Hiển thị hộp thoại thông tin đồ án."""
        QMessageBox.about(
            self,
            "Về phần mềm Mini Wireshark",
            "<b>Mini Wireshark v1.0</b><br>"
            "<i>Bộ Phân Tích & Bắt Gói Tin Mạng Thời Gian Thực</i><br><br>"
            "<b>Đồ án môn học:</b> Mạng máy tính & Truyền thông dữ liệu<br>"
            "<b>Chuyên ngành:</b> Kỹ thuật Điện tử — Viễn thông<br>"
            "<b>Công nghệ:</b> Python 3.11 | PyQt5 | Scapy | Npcap<br><br>"
            "Hỗ trợ phân tích đa tầng (Ethernet, ARP, IPv4/IPv6, ICMP, TCP, UDP, DNS) "
            "kèm bộ lọc cú pháp Wireshark và xuất mã Hex nhị phân."
        )

    def closeEvent(self, event):
        """Đảm bảo dừng toàn bộ QTimer và luồng bắt gói an toàn trước khi thoát."""
        if self.ui_update_timer.isActive():
            self.ui_update_timer.stop()
        if self.capture_worker is not None and self.capture_worker.isRunning():
            self.capture_worker.stop()
            self.capture_worker.wait()
        event.accept()
