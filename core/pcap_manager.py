"""
Module quản lý đọc và ghi file định dạng tiêu chuẩn .pcap
"""
from typing import List
from scapy.all import rdpcap, wrpcap
from scapy.packet import Packet


def save_pcap(filepath: str, packets: List[Packet]) -> bool:
    """Lưu danh sách gói tin Scapy vào file .pcap"""
    try:
        wrpcap(filepath, packets)
        return True
    except Exception as e:
        raise RuntimeError(f"Lỗi khi lưu tệp PCAP: {str(e)}")


def load_pcap(filepath: str) -> List[Packet]:
    """Đọc các gói tin từ file .pcap"""
    try:
        packets = rdpcap(filepath)
        return list(packets)
    except Exception as e:
        raise RuntimeError(f"Lỗi khi đọc tệp PCAP: {str(e)}")
