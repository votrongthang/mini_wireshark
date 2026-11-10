"""
Module luồng bắt gói tin thời gian thực kế thừa QThread (CaptureWorker).
Đảm bảo an toàn luồng, không gây đơ giao diện đồ họa (GUI).
"""
import sys
import time
import queue
import logging
from typing import List, Dict, Optional

# Tắt cảnh báo Scapy trên Windows để tối ưu thông lượng bắt gói
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sniff, get_if_list, conf
conf.verb = 0

from PyQt5.QtCore import QThread, pyqtSignal
from scapy.packet import Packet


def get_available_interfaces() -> List[Dict[str, str]]:
    """
    Lấy danh sách các card mạng khả dụng với tên gọi thân thiện với người dùng.
    """
    interfaces = []
    
    # Ưu tiên lấy thông tin chi tiết trên nền tảng Windows
    if sys.platform.startswith("win"):
        try:
            from scapy.arch.windows import get_windows_if_list
            win_ifs = get_windows_if_list()
            # Lọc các interface chính có thông tin IP hoặc mô tả rõ ràng
            for item in win_ifs:
                name = item.get("name", "")
                desc = item.get("description", "")
                ips = item.get("ips", [])
                guid = item.get("guid", "")
                
                # Bỏ qua các miniport ảo phụ nếu không có IP và là filter con
                if "Filter" in desc or "Scheduler" in desc or "LightWeight" in desc:
                    continue

                display_ip = f" ({ips[0]})" if ips else ""
                label = f"{name} - {desc}{display_ip}"
                
                interfaces.append({
                    "id": name,
                    "label": label,
                    "guid": guid,
                    "desc": desc,
                    "ips": ips
                })
        except Exception:
            pass

    # Fallback cho Linux hoặc khi get_windows_if_list không hoạt động
    if not interfaces:
        raw_list = get_if_list()
        for idx, iface in enumerate(raw_list):
            interfaces.append({
                "id": iface,
                "label": f"[{idx}] {iface}",
                "guid": iface,
                "desc": iface,
                "ips": []
            })

    return interfaces


class CaptureWorker(QThread):
    """
    Luồng chạy nền chịu trách nhiệm thực thi scapy.sniff()
    Đẩy gói tin an toàn vào hàng đợi thread-safe queue.Queue() hoặc phát Signal duy nhất.
    Không bao giờ phát kép tín hiệu gây lặp gói tin.
    """
    packet_captured = pyqtSignal(object)   # Phát từng gói tin nếu không dùng queue
    capture_error = pyqtSignal(str)        # Phát chuỗi thông báo lỗi khi có sự cố
    capture_started = pyqtSignal()
    capture_stopped = pyqtSignal()

    def __init__(self, iface: Optional[str] = None, bpf_filter: str = "", packet_queue: Optional[queue.Queue] = None):
        super().__init__()
        self.iface = iface
        self.bpf_filter = bpf_filter.strip()
        self.packet_queue = packet_queue
        self.is_running = False
        self.is_paused = False

    def run(self):
        self.is_running = True
        self.capture_started.emit()

        def handle_packet(packet: Packet):
            if not self.is_running:
                return
            if not self.is_paused:
                if self.packet_queue is not None:
                    # Đẩy an toàn vào thread-safe Queue chuẩn Python
                    self.packet_queue.put(packet)
                else:
                    # Phát 1 tín hiệu duy nhất nếu không dùng Queue
                    self.packet_captured.emit(packet)

        try:
            filter_arg = self.bpf_filter if self.bpf_filter else None
            sniff(
                iface=self.iface,
                filter=filter_arg,
                prn=handle_packet,
                stop_filter=lambda x: not self.is_running,
                store=False
            )
        except OSError as e:
            error_msg = str(e)
            if "permission" in error_msg.lower() or "admin" in error_msg.lower():
                self.capture_error.emit(
                    "Không có đủ quyền hạn bắt gói tin trên thiết bị này!\n"
                    "-> Vui lòng chạy ứng dụng với quyền Administrator (Run as Administrator)\n"
                    "hoặc kiểm tra lại cấu hình Npcap driver."
                )
            else:
                self.capture_error.emit(f"Lỗi Socket/Hệ điều hành: {error_msg}")
        except Exception as e:
            self.capture_error.emit(f"Lỗi bắt gói tin: {str(e)}")
        finally:
            self.is_running = False
            self.capture_stopped.emit()

    def stop(self):
        """Dừng tiến trình bắt gói tin."""
        self.is_running = False

    def pause(self):
        """Tạm dừng nhận gói tin vào UI."""
        self.is_paused = True

    def resume(self):
        """Tiếp tục nhận gói tin."""
        self.is_paused = False
