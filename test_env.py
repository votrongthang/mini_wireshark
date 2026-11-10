import sys
import PyQt5.QtCore
from scapy.all import get_if_list, sniff

print("--- THÔNG TIN MÔI TRƯỜNG ---")
print(f"Phiên bản Python: {sys.version.split()[0]}")
print(f"Phiên bản PyQt5:  {PyQt5.QtCore.PYQT_VERSION_STR}")

print("\n--- DANH SÁCH CARD MẠNG (INTERFACES) ---")
interfaces = get_if_list()
for idx, iface in enumerate(interfaces):
    print(f"[{idx}] {iface}")

print("\n--- BẮT THỬ NGHIỆM 1 GÓI TIN ---")
print("Đang lắng nghe gói tin trên mạng (hãy mở trình duyệt hoặc gõ phím nếu cần)...")
# Bắt thử duy nhất 1 gói tin
packets = sniff(count=1, timeout=5)
if packets:
    print(f"Thành công! Đã bắt được gói: {packets[0].summary()}")
else:
    print("Hết thời gian chờ (5s) chưa có gói nào đi qua, nhưng Scapy đã hoạt động bình thường.")