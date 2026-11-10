"""
Bộ kiểm thử tự động (Unit Tests) cho module phân tích gói tin và bộ lọc.
Chạy bằng lệnh: python -m unittest tests/test_parser.py
"""
import unittest
import os
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR, DNSRR

from core.parser import (
    parse_packet_summary, parse_packet_layers,
    format_hex_ascii, get_packet_protocol
)
from core.filter_engine import match_display_filter
from core.pcap_manager import save_pcap, load_pcap


class TestParserAndCore(unittest.TestCase):
    
    def test_arp_parsing(self):
        """Kiểm tra bóc tách gói tin ARP."""
        pkt = Ether(src="aa:bb:cc:dd:ee:01", dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=1, hwsrc="aa:bb:cc:dd:ee:01", psrc="192.168.1.10", pdst="192.168.1.1"
        )
        summary = parse_packet_summary(pkt, 1)
        self.assertEqual(summary["protocol"], "ARP")
        self.assertEqual(summary["src"], "192.168.1.10")
        self.assertEqual(summary["dst"], "192.168.1.1")
        self.assertIn("Who has 192.168.1.1", summary["info"])

        layers = parse_packet_layers(pkt, 1)
        layer_titles = [l["title"] for l in layers]
        self.assertTrue(any("Address Resolution Protocol" in t for t in layer_titles))

    def test_icmp_parsing(self):
        """Kiểm tra bóc tách gói tin ICMP Ping."""
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(type=8, code=0, id=0x4321, seq=5)
        summary = parse_packet_summary(pkt, 2)
        self.assertEqual(summary["protocol"], "ICMP")
        self.assertIn("Echo (ping) request", summary["info"])

        layers = parse_packet_layers(pkt, 2)
        icmp_layer = next((l for l in layers if "Internet Control Message Protocol" in l["title"]), None)
        self.assertIsNotNone(icmp_layer)
        fields_str = " ".join(icmp_layer["fields"])
        self.assertIn("Type: 8", fields_str)
        self.assertIn("Code: 0", fields_str)

    def test_tcp_flags_parsing(self):
        """Kiểm tra bóc tách cờ điều khiển TCP (SYN, ACK)."""
        pkt = Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=50000, dport=80, flags="SA", seq=100, ack=200)
        summary = parse_packet_summary(pkt, 3)
        self.assertIn("[SYN, ACK]", summary["info"])
        self.assertEqual(summary["protocol"], "TCP")

        # Kiểm tra gói có dữ liệu HTTP
        http_pkt = Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=50000, dport=80, flags="PA") / b"GET / HTTP/1.1\r\n\r\n"
        http_summary = parse_packet_summary(http_pkt, 4)
        self.assertEqual(http_summary["protocol"], "HTTP")

        layers = parse_packet_layers(pkt, 3)
        tcp_layer = next((l for l in layers if "Transmission Control Protocol" in l["title"]), None)
        self.assertIsNotNone(tcp_layer)
        fields_str = " ".join(tcp_layer["fields"])
        self.assertIn("Source Port: 50000", fields_str)
        self.assertIn("Destination Port: 80", fields_str)

    def test_dns_parsing(self):
        """Kiểm tra bóc tách gói tin DNS Query và Answer."""
        pkt = Ether() / IP(src="192.168.1.2", dst="8.8.8.8") / UDP(sport=5555, dport=53) / DNS(
            id=0x1234, qr=0, qd=DNSQR(qname="google.com")
        )
        summary = parse_packet_summary(pkt, 4)
        self.assertEqual(summary["protocol"], "DNS")
        self.assertIn("Standard Query 0x1234", summary["info"])
        self.assertIn("google.com", summary["info"])

    def test_hex_ascii_formatting(self):
        """Kiểm tra xuất chuỗi định dạng Hex & ASCII."""
        raw_bytes = b"Hello, Wireshark!"
        formatted = format_hex_ascii(raw_bytes)
        self.assertTrue(formatted.startswith("0000"))
        self.assertIn("Hello, Wireshark", formatted)
        self.assertIn("|!|", formatted)

    def test_filter_engine(self):
        """Kiểm tra các biểu thức lọc hiển thị theo chuẩn Wireshark."""
        pkt = Ether() / IP(src="192.168.1.100", dst="8.8.8.8") / TCP(sport=443, dport=54321, flags="S")
        summary = parse_packet_summary(pkt, 5)

        # 1. Lọc giao thức
        self.assertTrue(match_display_filter("tcp", summary))
        self.assertFalse(match_display_filter("udp", summary))

        # 2. Lọc IP nguồn / đích
        self.assertTrue(match_display_filter("ip.src == 192.168.1.100", summary))
        self.assertFalse(match_display_filter("ip.src == 10.0.0.1", summary))
        self.assertTrue(match_display_filter("ip.addr == 8.8.8.8", summary))

        # 3. Lọc Port
        self.assertTrue(match_display_filter("port == 443", summary))
        self.assertFalse(match_display_filter("port == 80", summary))

        # 4. Lọc kết hợp AND / OR
        self.assertTrue(match_display_filter("tcp and ip.src == 192.168.1.100", summary))
        self.assertTrue(match_display_filter("udp or tcp", summary))
        self.assertFalse(match_display_filter("udp and ip.src == 192.168.1.100", summary))

    def test_pcap_manager(self):
        """Kiểm tra tính năng lưu và nạp tệp .pcap."""
        test_file = "test_temp_capture.pcap"
        pkt = Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / ICMP()
        
        save_pcap(test_file, [pkt])
        self.assertTrue(os.path.exists(test_file))

        loaded = load_pcap(test_file)
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0][IP].src, "1.1.1.1")

        if os.path.exists(test_file):
            os.remove(test_file)


if __name__ == "__main__":
    unittest.main()
