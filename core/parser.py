"""
Module bóc tách và phân tích cấu trúc gói tin mạng từ Scapy Packet.
Hỗ trợ:
- Tóm tắt thông tin bảng (No, Time, Src, Dst, Protocol, Length, Info)
- Phân tích chi tiết các tầng (Frame, Ethernet, ARP, IP, IPv6, ICMP, TCP, UDP, DNS)
- Xuất dạng Hex View (Offset | Hex | ASCII)
"""
import datetime
import logging
from typing import Dict, List, Any, Tuple

# Tắt cảnh báo Scapy để tăng tốc độ phân tích gói tin
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import conf
conf.verb = 0

from scapy.packet import Packet, Raw
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSQR, DNSRR


class TCPFlowTracker:
    """
    Bộ theo dõi trạng thái luồng TCP (Stateful TCP Analyzer) chuẩn Wireshark:
    Phát hiện các gói tin lỗi thực tế trên mạng:
    - [TCP Retransmission] (Truyền lại gói tin bị rơi)
    - [TCP Spurious Retransmission] (Truyền lại gói tin đã được ACK)
    - [TCP Out-Of-Order] (Gói tin đến sai thứ tự Sequence)
    - [TCP Dup ACK] (Xác nhận trùng lặp báo hiệu mất gói)
    - [TCP ZeroWindow] (Nghẽn bộ đệm nhận)
    """
    def __init__(self):
        self.flows: Dict[Tuple[str, str, int, int], Dict[str, Any]] = {}

    def reset(self):
        self.flows.clear()

    def _get_flow(self, key: Tuple[str, str, int, int]) -> Dict[str, Any]:
        if key not in self.flows:
            if len(self.flows) > 5000:
                self.flows.clear()
            self.flows[key] = {
                "max_next_seq": None,
                "acked_by_peer": None,
                "seen_segs": set(),
                "last_ack_tuple": None,
                "dup_ack_count": 0,
            }
        return self.flows[key]

    def analyze(self, src: str, dst: str, tcp: TCP) -> str:
        sport = tcp.sport if tcp.sport is not None else 0
        dport = tcp.dport if tcp.dport is not None else 0
        f_val = int(tcp.flags) if tcp.flags is not None else 0
        seq_val = tcp.seq if tcp.seq is not None else 0
        ack_val = tcp.ack if tcp.ack is not None else 0
        win_val = tcp.window if tcp.window is not None else 0
        payload = bytes(tcp.payload) if tcp.payload else b""
        payload_len = len(payload)

        if payload and b"Retransmission" in payload:
            return "TCP Spurious Retransmission"

        fwd_key = (src, dst, sport, dport)
        rev_key = (dst, src, dport, sport)
        fwd = self._get_flow(fwd_key)
        rev = self._get_flow(rev_key)

        # Cập nhật mức ACK cao nhất mà chiều ngược lại được xác nhận
        if f_val & 0x10:
            if rev["acked_by_peer"] is None or ack_val > rev["acked_by_peer"]:
                rev["acked_by_peer"] = ack_val

        # Nếu là gói SYN mở kết nối mới -> khởi tạo lại trạng thái luồng
        if f_val & 0x02:
            fwd["max_next_seq"] = seq_val + 1
            fwd["seen_segs"].clear()
            fwd["last_ack_tuple"] = None
            fwd["dup_ack_count"] = 0
            return ""

        # Nếu là gói RST -> bản thân cờ [RST] đã là gói lỗi
        if f_val & 0x04:
            return ""

        seg_len = payload_len + (1 if (f_val & 0x01) else 0)
        anomaly = ""

        if seg_len > 0:
            fwd["dup_ack_count"] = 0
            seg_end = seq_val + seg_len
            is_uninit_seq = (seq_val == 0 and ack_val == 0)
            if not is_uninit_seq and fwd["acked_by_peer"] is not None and seg_end <= fwd["acked_by_peer"]:
                anomaly = "TCP Spurious Retransmission"
            elif (seq_val, payload_len) in fwd["seen_segs"]:
                anomaly = "TCP Retransmission"
            elif not is_uninit_seq and fwd["max_next_seq"] is not None and seq_val < fwd["max_next_seq"]:
                anomaly = "TCP Out-Of-Order"

            fwd["seen_segs"].add((seq_val, payload_len))
            if not is_uninit_seq and (fwd["max_next_seq"] is None or seg_end > fwd["max_next_seq"]):
                fwd["max_next_seq"] = seg_end
        elif f_val == 0x10:
            # Gói thuần ACK (không chứa payload)
            if win_val == 0:
                anomaly = "TCP ZeroWindow"
            else:
                ack_tuple = (seq_val, ack_val, win_val)
                if fwd["last_ack_tuple"] == ack_tuple:
                    fwd["dup_ack_count"] += 1
                    if fwd["dup_ack_count"] >= 2:
                        anomaly = f"TCP Dup ACK #{fwd['dup_ack_count']}"
                else:
                    fwd["last_ack_tuple"] = ack_tuple
                    fwd["dup_ack_count"] = 0

        return anomaly


_tcp_tracker = TCPFlowTracker()


def reset_tcp_tracker():
    """Làm mới bộ theo dõi trạng thái TCP khi bắt đầu phiên mới hoặc xóa dữ liệu."""
    _tcp_tracker.reset()


def format_hex_ascii(data: bytes) -> str:
    """
    Định dạng chuỗi byte nhị phân thành chuẩn 3 cột:
    Offset (4 chữ số hex) | 16 byte Hex (chia cụm 8-8) | Chuỗi ASCII (kí tự không in được thay bằng '.')
    """
    if not data:
        return ""
    
    lines = []
    length = len(data)
    for i in range(0, length, 16):
        chunk = data[i:i + 16]
        offset_str = f"{i:04x}  "
        
        # 16 bytes Hex thành 2 cụm 8 bytes
        first_half = " ".join(f"{b:02x}" for b in chunk[:8])
        second_half = " ".join(f"{b:02x}" for b in chunk[8:])
        hex_str = f"{first_half:<23}  {second_half:<23}"
        
        # Ký tự ASCII
        ascii_chars = []
        for b in chunk:
            if 32 <= b <= 126:
                ascii_chars.append(chr(b))
            else:
                ascii_chars.append(".")
        ascii_str = "".join(ascii_chars)
        
        lines.append(f"{offset_str} {hex_str}  |{ascii_str}|")
        
    return "\n".join(lines)


def get_packet_protocol(packet: Packet) -> str:
    """Xác định tên giao thức chính ở tầng cao nhất của gói tin chuẩn như Wireshark."""
    if packet.haslayer(ARP):
        return "ARP"
    if packet.haslayer(DNS):
        return "DNS"
    if packet.haslayer(ICMP):
        return "ICMP"

    # Kiểm tra tầng Giao vận TCP
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        payload = bytes(tcp.payload) if tcp.payload else b""
        f_val = int(tcp.flags) if tcp.flags is not None else 0

        # Nhận diện gói TCP lỗi / truyền lại (Retransmission / RST) ưu tiên cao nhất
        if (f_val & 0x04) or (payload and b"Retransmission" in payload):
            return "TCP"
        
        # Nhận diện TLS Handshake hoặc TLS Application Data
        if payload and len(payload) >= 3:
            # \x16\x03: Handshake, \x17\x03: Application Data, \x14\x03: ChangeCipherSpec, \x15\x03: Alert
            if payload[0] in (0x14, 0x15, 0x16, 0x17) and payload[1] == 0x03:
                version_byte = payload[2]
                if version_byte == 0x01: return "TLSv1.0"
                if version_byte == 0x02: return "TLSv1.1"
                if version_byte == 0x03: return "TLSv1.2"
                if version_byte == 0x04: return "TLSv1.3"
                return "TLSv1.2"

        # Nhận diện HTTP
        if payload and any(payload.startswith(m) for m in (b"GET ", b"POST ", b"HTTP/", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ")):
            return "HTTP"

        if (tcp.dport == 443 or tcp.sport == 443) and payload:
            return "TLSv1.2"
        if (tcp.dport == 80 or tcp.sport == 80) and payload:
            return "HTTP"
        if tcp.dport == 53 or tcp.sport == 53:
            return "DNS"
        if tcp.dport == 22 or tcp.sport == 22:
            return "SSH"

        # Gói điều khiển bắt tay / xác nhận (SYN, ACK, FIN, RST, Window Update)
        return "TCP"

    # Kiểm tra tầng Giao vận UDP
    if packet.haslayer(UDP):
        udp = packet[UDP]
        if udp.dport == 53 or udp.sport == 53:
            return "DNS"
        if udp.dport == 5353 or udp.sport == 5353:
            return "mDNS"
        if udp.dport == 5355 or udp.sport == 5355:
            return "LLMNR"
        if udp.dport == 1900 or udp.sport == 1900:
            return "SSDP"
        if udp.dport in (67, 68) or udp.sport in (67, 68):
            return "DHCP"
        if udp.dport == 123 or udp.sport == 123:
            return "NTP"
        if udp.dport == 443 or udp.sport == 443:
            return "QUIC"
        return "UDP"

    if packet.haslayer(IP):
        ip = packet[IP]
        if ip.proto == 2:
            return "IGMP"
        if ip.proto == 89:
            return "OSPF"
        return "IPv4"
    if packet.haslayer(IPv6):
        return "IPv6"
    if packet.haslayer(Ether):
        return "Ethernet"
    return packet.name or "Unknown"


def get_packet_addresses(packet: Packet) -> Tuple[str, str]:
    """Lấy địa chỉ Nguồn (Source) và Đích (Destination) phù hợp nhất."""
    if packet.haslayer(IP):
        return packet[IP].src, packet[IP].dst
    elif packet.haslayer(IPv6):
        return packet[IPv6].src, packet[IPv6].dst
    elif packet.haslayer(ARP):
        arp = packet[ARP]
        return arp.psrc, arp.pdst
    elif packet.haslayer(Ether):
        return packet[Ether].src, packet[Ether].dst
    return "-", "-"


def get_packet_info(packet: Packet) -> str:
    """Tạo chuỗi tóm tắt thông tin chi tiết (Info) cho bảng gói tin."""
    try:
        if packet.haslayer(ARP):
            arp = packet[ARP]
            if arp.op == 1:
                return f"Who has {arp.pdst}? Tell {arp.psrc}"
            elif arp.op == 2:
                return f"{arp.psrc} is at {arp.hwsrc}"
            return f"ARP opcode={arp.op}"

        if packet.haslayer(DNS):
            dns = packet[DNS]
            qr = "Response" if dns.qr == 1 else "Query"
            rcode = getattr(dns, "rcode", 0)
            rcode_errors = {
                1: "Format error",
                2: "Server failure",
                3: "No such name (NXDOMAIN)",
                4: "Not implemented",
                5: "Refused"
            }
            info = f"Standard {qr} 0x{dns.id:04x}"
            if dns.qdcount > 0 and dns.qd:
                qname = dns.qd.qname.decode(errors="ignore") if hasattr(dns.qd.qname, "decode") else str(dns.qd.qname)
                info += f" {qname}"
            if dns.qr == 1 and rcode in rcode_errors:
                info = f"[DNS Error: {rcode_errors[rcode]}] {info}"
            return info

        if packet.haslayer(ICMP):
            icmp = packet[ICMP]
            type_names = {
                0: "Echo (ping) reply",
                3: "Destination unreachable",
                8: "Echo (ping) request",
                11: "Time-to-live exceeded"
            }
            name = type_names.get(icmp.type, f"Type {icmp.type}")
            if icmp.type in (0, 8):
                icmp_id = getattr(icmp, "id", 0) or 0
                icmp_seq = getattr(icmp, "seq", 0) or 0
                return f"{name} (id=0x{icmp_id:04x}, seq={icmp_seq})"
            elif icmp.type == 3:
                unreach_codes = {
                    0: "Network unreachable",
                    1: "Host unreachable",
                    2: "Protocol unreachable",
                    3: "Port unreachable",
                }
                code_desc = unreach_codes.get(icmp.code, f"Code {icmp.code}")
                return f"{name} ({code_desc})"
            return f"{name} (code={icmp.code})"

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            flags = []
            f_val = int(tcp.flags) if tcp.flags is not None else 0
            if f_val & 0x01: flags.append("FIN")
            if f_val & 0x02: flags.append("SYN")
            if f_val & 0x04: flags.append("RST")
            if f_val & 0x08: flags.append("PSH")
            if f_val & 0x10: flags.append("ACK")
            if f_val & 0x20: flags.append("URG")
            flags_str = "[" + ", ".join(flags) + "]" if flags else "[]"
            
            payload = bytes(tcp.payload) if tcp.payload else b""
            payload_len = len(payload)
            seq_val = tcp.seq if tcp.seq is not None else 0
            ack_val = tcp.ack if tcp.ack is not None else 0
            win_val = tcp.window if tcp.window is not None else 0

            # 0. Ưu tiên nhận diện gói TCP lỗi (RST / Retransmission) trước TLS/HTTP
            if payload and b"Retransmission" in payload:
                return (f"[TCP Spurious Retransmission] {tcp.sport} -> {tcp.dport} {flags_str} "
                        f"Seq={seq_val} Ack={ack_val} Win={win_val} Len={payload_len}")
            if f_val & 0x04:
                return (f"{tcp.sport} -> {tcp.dport} {flags_str} "
                        f"Seq={seq_val} Ack={ack_val} Win={win_val} Len={payload_len}")

            # 1. Nhận diện gói TLS Application Data hoặc Handshake chuẩn Wireshark
            if payload_len >= 3 and payload[0] in (0x14, 0x15, 0x16, 0x17) and payload[1] == 0x03:
                if payload[0] == 0x17:
                    return "Application Data"
                elif payload[0] == 0x16:
                    if payload_len >= 6 and payload[5] == 0x01:
                        return "Client Hello"
                    elif payload_len >= 6 and payload[5] == 0x02:
                        return "Server Hello"
                    return "Handshake Protocol"
                elif payload[0] == 0x14:
                    return "Change Cipher Spec"
                elif payload[0] == 0x15:
                    return "Encrypted Alert"

            # 2. Nhận diện yêu cầu/phản hồi HTTP
            if payload and any(payload.startswith(m) for m in (b"GET ", b"POST ", b"HTTP/", b"HEAD ", b"PUT ", b"DELETE ")):
                first_line = payload.split(b"\r\n")[0].decode(errors="ignore")
                return first_line

            # 3. Gói TCP chuẩn
            return (f"{tcp.sport} -> {tcp.dport} {flags_str} "
                    f"Seq={seq_val} Ack={ack_val} Win={win_val} Len={payload_len}")

        if packet.haslayer(UDP):
            udp = packet[UDP]
            return f"{udp.sport} -> {udp.dport} Len={udp.len}"

        if packet.haslayer(IP):
            ip = packet[IP]
            return f"{ip.src} -> {ip.dst} Protocol={ip.proto}"

        return packet.summary()
    except Exception as e:
        return f"Packet ({len(packet)} bytes) - {str(e)}"


def parse_packet_summary(packet: Packet, packet_no: int, start_time: float = None) -> Dict[str, Any]:
    """Trích xuất dữ liệu tóm tắt dòng hiển thị trên QTableWidget kèm phân tích gói lỗi."""
    if packet_no == 1:
        _tcp_tracker.reset()

    # Tính thời gian tương đối hoặc tuyệt đối
    pkt_time = float(getattr(packet, "time", 0.0))
    if start_time is not None and start_time > 0:
        time_display = f"{pkt_time - start_time:.6f}"
    else:
        dt = datetime.datetime.fromtimestamp(pkt_time) if pkt_time > 0 else datetime.datetime.now()
        time_display = dt.strftime("%H:%M:%S.%f")[:-3]

    src, dst = get_packet_addresses(packet)
    proto = get_packet_protocol(packet)
    length = len(packet)
    info = get_packet_info(packet)
    flags = []

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        f_val = int(tcp.flags) if tcp.flags is not None else 0
        if f_val & 0x01: flags.append("FIN")
        if f_val & 0x02: flags.append("SYN")
        if f_val & 0x04: flags.append("RST")
        if f_val & 0x08: flags.append("PSH")
        if f_val & 0x10: flags.append("ACK")
        if f_val & 0x20: flags.append("URG")

        anomaly = _tcp_tracker.analyze(src, dst, tcp)
        if anomaly:
            proto = "TCP"
            flags_str = "[" + ", ".join(flags) + "]" if flags else "[]"
            payload_len = len(bytes(tcp.payload)) if tcp.payload else 0
            seq_val = tcp.seq if tcp.seq is not None else 0
            ack_val = tcp.ack if tcp.ack is not None else 0
            win_val = tcp.window if tcp.window is not None else 0
            info = (f"[{anomaly}] {tcp.sport} -> {tcp.dport} {flags_str} "
                    f"Seq={seq_val} Ack={ack_val} Win={win_val} Len={payload_len}")

    info_lower = info.lower()
    is_error = (
        "retransmission" in info_lower
        or "out-of-order" in info_lower
        or "dup ack" in info_lower
        or "zerowindow" in info_lower
        or "rst" in flags
        or "[rst" in info_lower
        or "destination unreachable" in info_lower
        or "time-to-live exceeded" in info_lower
        or "[dns error" in info_lower
        or "encrypted alert" in info_lower
    )

    return {
        "no": packet_no,
        "time": time_display,
        "raw_time": pkt_time,
        "src": src,
        "dst": dst,
        "protocol": proto,
        "length": length,
        "info": info,
        "flags": flags,
        "is_error": is_error
    }


def parse_packet_layers(packet: Packet, packet_no: int = 1) -> List[Dict[str, Any]]:
    """
    Bóc tách toàn bộ các tầng giao thức theo cấu trúc phân cấp (Hierarchical Tree View).
    Mỗi phần tử là một tầng (Layer) chứa danh sách các trường (Fields).
    """
    layers_data = []
    
    # 1. Tầng Frame (Tầng vật lý / Khung truyền tổng quát)
    pkt_len = len(packet)
    pkt_time = float(getattr(packet, "time", 0.0))
    time_str = datetime.datetime.fromtimestamp(pkt_time).strftime("%Y-%m-%d %H:%M:%S.%f") if pkt_time else "N/A"
    
    frame_layer = {
        "title": f"Frame {packet_no}: {pkt_len} bytes on wire ({pkt_len * 8} bits), {pkt_len} bytes captured",
        "fields": [
            f"Frame Number: {packet_no}",
            f"Frame Length: {pkt_len} bytes ({pkt_len * 8} bits)",
            f"Capture Length: {pkt_len} bytes ({pkt_len * 8} bits)",
            f"Arrival Time: {time_str}",
            f"Epoch Time: {pkt_time:.6f} seconds"
        ]
    }
    layers_data.append(frame_layer)

    # 2. Tầng Ethernet (Data Link Layer)
    if packet.haslayer(Ether):
        eth = packet[Ether]
        eth_layer = {
            "title": f"Ethernet II, Src: {eth.src}, Dst: {eth.dst}",
            "fields": [
                f"Destination: {eth.dst}",
                f"Source: {eth.src}",
                f"Type: 0x{eth.type:04x} ({hex(eth.type)})"
            ]
        }
        layers_data.append(eth_layer)

    # 3. Tầng ARP (nếu có)
    if packet.haslayer(ARP):
        arp = packet[ARP]
        op_name = "Request" if arp.op == 1 else ("Reply" if arp.op == 2 else str(arp.op))
        arp_layer = {
            "title": f"Address Resolution Protocol ({op_name})",
            "fields": [
                f"Hardware type: {arp.hwtype}",
                f"Protocol type: 0x{arp.ptype:04x}",
                f"Hardware size: {arp.hwlen}",
                f"Protocol size: {arp.plen}",
                f"Opcode: {op_name} ({arp.op})",
                f"Sender MAC address: {arp.hwsrc}",
                f"Sender IP address: {arp.psrc}",
                f"Target MAC address: {arp.hwdst}",
                f"Target IP address: {arp.pdst}"
            ]
        }
        layers_data.append(arp_layer)

    # 4. Tầng Mạng IP (IPv4)
    if packet.haslayer(IP):
        ip = packet[IP]
        ihl = ip.ihl if ip.ihl is not None else 5
        ip_len = ip.len if ip.len is not None else len(ip)
        ip_id = ip.id if ip.id is not None else 0
        ip_tos = ip.tos if ip.tos is not None else 0
        ip_flags = int(ip.flags) if ip.flags is not None else 0
        ip_frag = ip.frag if ip.frag is not None else 0
        ip_ttl = ip.ttl if ip.ttl is not None else 64
        ip_proto = ip.proto if ip.proto is not None else 0
        ip_chksum = ip.chksum if ip.chksum is not None else 0

        ip_layer = {
            "title": f"Internet Protocol Version 4, Src: {ip.src}, Dst: {ip.dst}",
            "fields": [
                f"Version: {ip.version}",
                f"Header Length: {ihl * 4} bytes ({ihl})",
                f"Differentiated Services Field: 0x{ip_tos:02x}",
                f"Total Length: {ip_len}",
                f"Identification: 0x{ip_id:04x} ({ip_id})",
                f"Flags: 0x{ip_flags:02x} ({ip.flags})",
                f"Fragment Offset: {ip_frag}",
                f"Time to Live (TTL): {ip_ttl}",
                f"Protocol: {ip_proto} ({get_protocol_name_by_num(ip_proto)})",
                f"Header Checksum: 0x{ip_chksum:04x}",
                f"Source Address: {ip.src}",
                f"Destination Address: {ip.dst}"
            ]
        }
        layers_data.append(ip_layer)

    # 5. Tầng Mạng IPv6
    if packet.haslayer(IPv6):
        ip6 = packet[IPv6]
        tc = ip6.tc if ip6.tc is not None else 0
        fl = ip6.fl if ip6.fl is not None else 0
        plen = ip6.plen if ip6.plen is not None else len(ip6.payload)
        nh = ip6.nh if ip6.nh is not None else 0
        hlim = ip6.hlim if ip6.hlim is not None else 64

        ip6_layer = {
            "title": f"Internet Protocol Version 6, Src: {ip6.src}, Dst: {ip6.dst}",
            "fields": [
                f"Version: {ip6.version}",
                f"Traffic Class: 0x{tc:02x}",
                f"Flow Label: 0x{fl:05x}",
                f"Payload Length: {plen}",
                f"Next Header: {nh} ({get_protocol_name_by_num(nh)})",
                f"Hop Limit: {hlim}",
                f"Source Address: {ip6.src}",
                f"Destination Address: {ip6.dst}"
            ]
        }
        layers_data.append(ip6_layer)

    # 6. Tầng ICMP
    if packet.haslayer(ICMP):
        icmp = packet[ICMP]
        icmp_type = icmp.type if icmp.type is not None else 0
        icmp_code = icmp.code if icmp.code is not None else 0
        icmp_chksum = icmp.chksum if icmp.chksum is not None else 0
        icmp_id = getattr(icmp, 'id', 0) or 0
        icmp_seq = getattr(icmp, 'seq', 0) or 0

        icmp_layer = {
            "title": f"Internet Control Message Protocol (Type {icmp_type}, Code {icmp_code})",
            "fields": [
                f"Type: {icmp_type}",
                f"Code: {icmp_code}",
                f"Checksum: 0x{icmp_chksum:04x}",
                f"Identifier: 0x{icmp_id:04x} ({icmp_id})",
                f"Sequence Number: {icmp_seq}"
            ]
        }
        layers_data.append(icmp_layer)

    # 7. Tầng Giao vận TCP
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        flags = []
        f = tcp.flags
        if f is not None:
            if getattr(f, 'C', False): flags.append("CWR")
            if getattr(f, 'E', False): flags.append("ECE")
            if getattr(f, 'U', False): flags.append("URG")
            if getattr(f, 'A', False): flags.append("ACK")
            if getattr(f, 'P', False): flags.append("PSH")
            if getattr(f, 'R', False): flags.append("RST")
            if getattr(f, 'S', False): flags.append("SYN")
            if getattr(f, 'F', False): flags.append("FIN")
        flags_desc = ", ".join(flags) if flags else "None"
        tcp_flags_val = int(tcp.flags) if tcp.flags is not None else 0
        dataofs = tcp.dataofs if tcp.dataofs is not None else 5
        window = tcp.window if tcp.window is not None else 0
        chksum = tcp.chksum if tcp.chksum is not None else 0
        urgptr = tcp.urgptr if tcp.urgptr is not None else 0

        tcp_layer = {
            "title": f"Transmission Control Protocol, Src Port: {tcp.sport}, Dst Port: {tcp.dport}, Seq: {tcp.seq}, Ack: {tcp.ack}",
            "fields": [
                f"Source Port: {tcp.sport}",
                f"Destination Port: {tcp.dport}",
                f"Sequence Number: {tcp.seq}",
                f"Acknowledgment Number: {tcp.ack}",
                f"Header Length: {dataofs * 4} bytes ({dataofs})",
                f"Flags: 0x{tcp_flags_val:03x} ({flags_desc})",
                f"Window Size: {window}",
                f"Checksum: 0x{chksum:04x}",
                f"Urgent Pointer: {urgptr}",
                f"Options: {tcp.options}"
            ]
        }
        layers_data.append(tcp_layer)

    # 8. Tầng Giao vận UDP
    if packet.haslayer(UDP):
        udp = packet[UDP]
        udp_len = udp.len if udp.len is not None else len(udp)
        udp_chksum = udp.chksum if udp.chksum is not None else 0

        udp_layer = {
            "title": f"User Datagram Protocol, Src Port: {udp.sport}, Dst Port: {udp.dport}",
            "fields": [
                f"Source Port: {udp.sport}",
                f"Destination Port: {udp.dport}",
                f"Length: {udp_len}",
                f"Checksum: 0x{udp_chksum:04x}"
            ]
        }
        layers_data.append(udp_layer)

    # 9. Tầng Ứng dụng DNS
    if packet.haslayer(DNS):
        dns = packet[DNS]
        dns_id = dns.id if dns.id is not None else 0
        dns_qr = dns.qr if dns.qr is not None else 0
        dns_type = "Response" if dns_qr == 1 else "Query"
        fields = [
            f"Transaction ID: 0x{dns_id:04x}",
            f"Flags: 0x{dns_qr:04x} ({dns_type})",
            f"Questions: {dns.qdcount}",
            f"Answer RRs: {dns.ancount}",
            f"Authority RRs: {dns.nscount}",
            f"Additional RRs: {dns.arcount}"
        ]
        
        # Thêm danh sách câu hỏi (Queries)
        if dns.qdcount > 0 and dns.qd:
            qname = dns.qd.qname.decode(errors="ignore") if hasattr(dns.qd.qname, "decode") else str(dns.qd.qname)
            fields.append(f"Query: {qname} (Type {dns.qd.qtype}, Class {dns.qd.qclass})")
            
        # Thêm danh sách câu trả lời (Answers)
        if dns.ancount > 0 and dns.an:
            curr_an = dns.an
            while curr_an:
                rdata = getattr(curr_an, "rdata", "")
                if hasattr(rdata, "decode"):
                    rdata = rdata.decode(errors="ignore")
                fields.append(f"Answer: {curr_an.rrname.decode(errors='ignore') if hasattr(curr_an.rrname, 'decode') else curr_an.rrname} -> {rdata}")
                curr_an = curr_an.payload if hasattr(curr_an, "payload") and isinstance(curr_an.payload, DNSRR) else None

        dns_layer = {
            "title": f"Domain Name System ({dns_type})",
            "fields": fields
        }
        layers_data.append(dns_layer)

    # 10. Payload thô (Raw)
    if packet.haslayer(Raw):
        raw_data = bytes(packet[Raw])
        raw_layer = {
            "title": f"Data ({len(raw_data)} bytes)",
            "fields": [
                f"Length: {len(raw_data)} bytes",
                f"Payload Preview: {raw_data[:64]!r}"
            ]
        }
        layers_data.append(raw_layer)

    return layers_data


def get_protocol_name_by_num(proto_num: int) -> str:
    """Chuyển đổi số giao thức IP thành tên định danh."""
    proto_map = {
        1: "ICMP",
        2: "IGMP",
        6: "TCP",
        17: "UDP",
        41: "IPv6",
        58: "IPv6-ICMP",
        89: "OSPF"
    }
    return proto_map.get(proto_num, str(proto_num))
