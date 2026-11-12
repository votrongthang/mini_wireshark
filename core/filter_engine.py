"""
Module phân tích và xử lý bộ lọc hiển thị (Display Filter Engine).
Hỗ trợ cú pháp chuẩn Wireshark:
- Tên giao thức: tcp, udp, icmp, dns, arp, http, tls
- Địa chỉ IP: ip.addr == X, ip.src == X, ip.dst == X
- Cổng dịch vụ: port == X, tcp.port == X, udp.port == X
- Độ dài khung: len > X, len >= X, len < X, len == X
- Toán tử logic: and, &&, or, ||, not, !
- Fallback: Tìm kiếm tự do theo từ khóa trong tất cả các cột
"""
import re
from typing import Dict, Any


def evaluate_single_condition(condition_str: str, summary: Dict[str, Any]) -> bool:
    """Đánh giá 1 điều kiện lọc đơn lẻ với thông tin tóm tắt gói tin."""
    cond = condition_str.strip()
    if not cond:
        return True

    # 1. So sánh độ dài: len > 100, len <= 64, v.v.
    len_match = re.match(r"^len\s*(==|!=|>=|<=|>|<)\s*(\d+)$", cond, re.IGNORECASE)
    if len_match:
        op, val_str = len_match.groups()
        target_len = int(val_str)
        pkt_len = summary.get("length", 0)
        if op == "==": return pkt_len == target_len
        if op == "!=": return pkt_len != target_len
        if op == ">": return pkt_len > target_len
        if op == ">=": return pkt_len >= target_len
        if op == "<": return pkt_len < target_len
        if op == "<=": return pkt_len <= target_len

    # 2. So sánh địa chỉ IP nguồn / đích / cả hai
    # ip.src == 192.168.1.1
    ip_src_match = re.match(r"^ip\.src\s*(==|!=)\s*([a-zA-Z0-9\.:]+)$", cond, re.IGNORECASE)
    if ip_src_match:
        op, ip_val = ip_src_match.groups()
        src = str(summary.get("src", "")).lower()
        ip_val = ip_val.lower()
        return (src == ip_val) if op == "==" else (src != ip_val)

    # ip.dst == 192.168.1.1
    ip_dst_match = re.match(r"^ip\.dst\s*(==|!=)\s*([a-zA-Z0-9\.:]+)$", cond, re.IGNORECASE)
    if ip_dst_match:
        op, ip_val = ip_dst_match.groups()
        dst = str(summary.get("dst", "")).lower()
        ip_val = ip_val.lower()
        return (dst == ip_val) if op == "==" else (dst != ip_val)

    # ip.addr == 192.168.1.1
    ip_addr_match = re.match(r"^ip\.addr\s*(==|!=)\s*([a-zA-Z0-9\.:]+)$", cond, re.IGNORECASE)
    if ip_addr_match:
        op, ip_val = ip_addr_match.groups()
        src = str(summary.get("src", "")).lower()
        dst = str(summary.get("dst", "")).lower()
        ip_val = ip_val.lower()
        is_match = (src == ip_val or dst == ip_val)
        return is_match if op == "==" else not is_match

    # 3. So sánh cổng dịch vụ: port == 80, tcp.port == 443, udp.port == 53
    port_match = re.match(r"^(?:tcp\.|udp\.)?port\s*(==|!=)\s*(\d+)$", cond, re.IGNORECASE)
    if port_match:
        op, port_str = port_match.groups()
        info = str(summary.get("info", ""))
        # Kiểm tra sự xuất hiện của cổng trong trường Info (sport -> dport)
        pattern = rf"\b{port_str}\b"
        found = bool(re.search(pattern, info))
        return found if op == "==" else not found

    # 4. Kiểm tra giao thức đơn: tcp, udp, icmp, dns, arp, tls, http
    known_protocols = {
        "tcp": ["tcp", "http", "tls", "tlsv1.0", "tlsv1.1", "tlsv1.2", "tlsv1.3", "tls/https", "ssh", "ftp"],
        "udp": ["udp", "dns", "mdns", "llmnr", "ssdp", "dhcp", "ntp", "quic"],
        "icmp": ["icmp", "icmpv6"],
        "icmpv6": ["icmpv6"],
        "dns": ["dns", "mdns", "llmnr"],
        "mdns": ["mdns"],
        "llmnr": ["llmnr"],
        "arp": ["arp"],
        "http": ["http"],
        "tls": ["tls", "tlsv1.0", "tlsv1.1", "tlsv1.2", "tlsv1.3", "tls/https"],
        "tlsv1.2": ["tlsv1.2"],
        "tlsv1.3": ["tlsv1.3"],
        "ssl": ["tls", "tlsv1.0", "tlsv1.1", "tlsv1.2", "tlsv1.3", "tls/https"],
        "https": ["tls", "tlsv1.0", "tlsv1.1", "tlsv1.2", "tlsv1.3", "tls/https"],
        "quic": ["quic"],
        "dhcp": ["dhcp"],
        "ntp": ["ntp"],
        "ssh": ["ssh"],
        "igmp": ["igmp"],
        "ospf": ["ospf"],
        "ipv4": ["ipv4"],
        "ipv6": ["ipv6"],
        "ethernet": ["ethernet"]
    }

    cond_lower = cond.lower()
    proto = str(summary.get("protocol", "")).lower()
    info = str(summary.get("info", "")).lower()

    # Hỗ trợ lọc nhanh các gói tin bị lỗi mạng bằng từ khóa: error, errors, bad, loi
    if cond_lower in ("error", "errors", "bad", "loi", "tcp.analysis.flags"):
        if summary.get("is_error"):
            return True
        return any(k in info for k in (
            "retransmission", "out-of-order", "dup ack", "zerowindow",
            "[rst", "rst]", "rst,", "checksum error", "destination unreachable",
            "time-to-live exceeded", "[dns error", "encrypted alert", "[bad", "bad tcp"
        ))

    if cond_lower in known_protocols:
        return proto in known_protocols[cond_lower]

    # proto == "TCP"
    proto_eq_match = re.match(r"^(?:proto|protocol)\s*(==|!=)\s*([a-zA-Z0-9/]+)$", cond, re.IGNORECASE)
    if proto_eq_match:
        op, val = proto_eq_match.groups()
        val = val.lower()
        return (val in proto) if op == "==" else (val not in proto)

    # 5. Fallback: Kiểm tra chứa chuỗi tìm kiếm tự do trong tất cả các trường
    src = str(summary.get("src", "")).lower()
    dst = str(summary.get("dst", "")).lower()
    info = str(summary.get("info", "")).lower()
    return (cond_lower in proto or cond_lower in src or cond_lower in dst or cond_lower in info)


def match_display_filter(filter_str: str, summary: Dict[str, Any]) -> bool:
    """
    Hàm chính kiểm tra một gói tin có thỏa mãn biểu thức bộ lọc hay không.
    Hỗ trợ kết hợp bằng toán tử `and` (`&&`) và `or` (`||`).
    """
    raw_filter = filter_str.strip()
    if not raw_filter:
        return True

    # Chuẩn hóa cú pháp toán tử
    normalized = raw_filter.replace("&&", " and ").replace("||", " or ")

    # Tách mệnh đề theo toán tử 'or' (Độ ưu tiên thấp hơn 'and')
    or_clauses = re.split(r"\s+or\s+", normalized, flags=re.IGNORECASE)
    for or_clause in or_clauses:
        # Tách tiếp theo toán tử 'and'
        and_clauses = re.split(r"\s+and\s+", or_clause, flags=re.IGNORECASE)
        # Mọi điều kiện trong and_clauses phải đúng
        and_result = True
        for cond in and_clauses:
            cond = cond.strip()
            if not cond:
                continue
            is_negated = False
            if cond.startswith("not ") or cond.startswith("! "):
                is_negated = True
                cond = cond.split(" ", 1)[1].strip()
            elif cond.startswith("!"):
                is_negated = True
                cond = cond[1:].strip()

            matched = evaluate_single_condition(cond, summary)
            if is_negated:
                matched = not matched

            if not matched:
                and_result = False
                break

        # Nếu một mệnh đề OR đúng -> Kết quả chung là Đúng
        if and_result:
            return True

    return False


def validate_filter_syntax(filter_str: str) -> bool:
    """
    Kiểm tra tính hợp lệ về mặt cú pháp của biểu thức bộ lọc hiển thị.
    Dùng để đổi màu nền thanh Display Filter Bar chuẩn Wireshark:
    - Xanh lá mạ (#c5ffc5): Biểu thức hợp lệ
    - Hồng đỏ nhạt (#ffc5c5): Biểu thức chưa hoàn chỉnh hoặc sai cú pháp
    - Trắng / Mặc định: Trống
    """
    raw = filter_str.strip()
    if not raw:
        return True

    # Biểu thức không được kết thúc bằng toán tử lơ lửng
    if re.search(r"(\band\b|\bor\b|&&|\|\||!|\bnot\b|==|!=|>=|<=|>|<)\s*$", raw, re.IGNORECASE):
        return False

    normalized = raw.replace("&&", " and ").replace("||", " or ")
    clauses = re.split(r"\s+(?:and|or)\s+", normalized, flags=re.IGNORECASE)

    for clause in clauses:
        c = clause.strip()
        if not c:
            return False
        if c.startswith("not ") or c.startswith("! "):
            c = c.split(" ", 1)[1].strip()
        elif c.startswith("!"):
            c = c[1:].strip()

        if not c:
            return False

        # Kiểm tra toán tử so sánh (==, !=, >, <, >=, <=)
        cmp_match = re.search(r"(==|!=|>=|<=|>|<)", c)
        if cmp_match:
            parts = c.split(cmp_match.group(1))
            if len(parts) != 2 or not parts[0].strip() or not parts[1].strip():
                return False

    return True
