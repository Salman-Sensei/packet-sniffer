"""
Unit tests for protocol parsers.
Run with:  pytest tests/ -v
"""

import pytest
import struct

from src.parse.ethernet import EthernetParser
from src.parse.ipv4 import IPv4Parser
from src.parse.tcp import TCPParser
from src.parse.protocols import UDPParser, ICMPParser, DNSParser, ARPParser
from src.utils.helpers import bytes_to_mac, bytes_to_ip, tcp_flags_str, format_bytes


# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════

def make_ethernet(dst="aa:bb:cc:dd:ee:ff", src="11:22:33:44:55:66", eth_type=0x0800, payload=b""):
    dst_b = bytes(int(x, 16) for x in dst.split(":"))
    src_b = bytes(int(x, 16) for x in src.split(":"))
    return struct.pack("!6s6sH", dst_b, src_b, eth_type) + payload


def make_ipv4(src="192.168.1.1", dst="8.8.8.8", proto=6, payload=b""):
    src_b = bytes(int(x) for x in src.split("."))
    dst_b = bytes(int(x) for x in dst.split("."))
    ihl   = 5   # 20 bytes, no options
    ver_ihl = (4 << 4) | ihl
    total_len = 20 + len(payload)
    header = struct.pack("!BBHHHBBH4s4s",
        ver_ihl, 0, total_len, 0, 0,
        64, proto, 0,
        src_b, dst_b
    )
    return header + payload


def make_tcp(src_port=12345, dst_port=80, seq=1000, ack=2000,
             flags=0x002, window=65535, payload=b""):
    data_off = 5   # 20-byte header
    data_off_flags = (data_off << 12) | flags
    header = struct.pack("!HHIIHHHHH",
        src_port, dst_port, seq, ack,
        data_off_flags, window, 0, 0,
        # NOTE: struct "!HHIIHHHHH" packs 9 items
        # Actually TCP is 10 fields — let's keep it simple:
    )
    # Simpler approach:
    header = (
        struct.pack("!HH", src_port, dst_port) +
        struct.pack("!I", seq) +
        struct.pack("!I", ack) +
        struct.pack("!HH", data_off_flags, window) +
        struct.pack("!HH", 0, 0)  # checksum, urg
    )
    return header + payload


def make_udp(src_port=54321, dst_port=53, payload=b""):
    length = 8 + len(payload)
    return struct.pack("!HHHH", src_port, dst_port, length, 0) + payload


# ══════════════════════════════════════════════════════════════════════════════
# Ethernet
# ══════════════════════════════════════════════════════════════════════════════

class TestEthernetParser:
    def test_parse_basic(self):
        raw = make_ethernet()
        result = EthernetParser.parse(raw)
        assert result["dst_mac"] == "aa:bb:cc:dd:ee:ff"
        assert result["src_mac"] == "11:22:33:44:55:66"
        assert result["eth_type_int"] == 0x0800
        assert result["eth_type_str"] == "IPv4"

    def test_parse_arp_type(self):
        raw = make_ethernet(eth_type=0x0806)
        result = EthernetParser.parse(raw)
        assert result["eth_type_str"] == "ARP"

    def test_parse_ipv6_type(self):
        raw = make_ethernet(eth_type=0x86DD)
        result = EthernetParser.parse(raw)
        assert result["eth_type_str"] == "IPv6"

    def test_payload_extracted(self):
        payload = b"\x45\x00\x00\x28"
        raw = make_ethernet(payload=payload)
        result = EthernetParser.parse(raw)
        assert result["payload"] == payload

    def test_too_short_raises(self):
        with pytest.raises(ValueError):
            EthernetParser.parse(b"\x00" * 5)

    def test_unknown_eth_type(self):
        raw = make_ethernet(eth_type=0x9999)
        result = EthernetParser.parse(raw)
        assert "0x9999" in result["eth_type_str"]


# ══════════════════════════════════════════════════════════════════════════════
# IPv4
# ══════════════════════════════════════════════════════════════════════════════

class TestIPv4Parser:
    def test_parse_basic(self):
        raw = make_ipv4(src="192.168.1.100", dst="8.8.8.8", proto=6)
        result = IPv4Parser.parse(raw)
        assert result["src"] == "192.168.1.100"
        assert result["dst"] == "8.8.8.8"
        assert result["proto"] == 6
        assert result["proto_name"] == "TCP"
        assert result["version"] == 4
        assert result["ttl"] == 64

    def test_parse_udp_proto(self):
        raw = make_ipv4(proto=17)
        result = IPv4Parser.parse(raw)
        assert result["proto_name"] == "UDP"

    def test_parse_icmp_proto(self):
        raw = make_ipv4(proto=1)
        result = IPv4Parser.parse(raw)
        assert result["proto_name"] == "ICMP"

    def test_header_length(self):
        raw = make_ipv4()
        result = IPv4Parser.parse(raw)
        assert result["ihl"] == 20

    def test_too_short_raises(self):
        with pytest.raises(ValueError):
            IPv4Parser.parse(b"\x45" * 10)

    def test_payload_correct(self):
        payload = b"TCP_DATA_HERE"
        raw = make_ipv4(payload=payload)
        result = IPv4Parser.parse(raw)
        assert result["payload"] == payload


# ══════════════════════════════════════════════════════════════════════════════
# TCP
# ══════════════════════════════════════════════════════════════════════════════

class TestTCPParser:
    def test_parse_basic(self):
        raw = make_tcp(src_port=54321, dst_port=80)
        result = TCPParser.parse(raw)
        assert result["src_port"] == 54321
        assert result["dst_port"] == 80

    def test_syn_flag(self):
        raw = make_tcp(flags=0x002)  # SYN
        result = TCPParser.parse(raw)
        assert result["flags_dict"]["SYN"] is True
        assert result["flags_dict"]["ACK"] is False

    def test_syn_ack_flag(self):
        raw = make_tcp(flags=0x012)  # SYN + ACK
        result = TCPParser.parse(raw)
        assert result["flags_dict"]["SYN"] is True
        assert result["flags_dict"]["ACK"] is True

    def test_fin_flag(self):
        raw = make_tcp(flags=0x011)  # FIN + ACK
        result = TCPParser.parse(raw)
        assert result["flags_dict"]["FIN"] is True

    def test_flag_summary_syn(self):
        assert TCPParser.flag_summary(0x002) == "SYN"

    def test_flag_summary_syn_ack(self):
        assert TCPParser.flag_summary(0x012) == "SYN-ACK"

    def test_flag_summary_fin(self):
        assert TCPParser.flag_summary(0x001) == "FIN"

    def test_flag_summary_rst(self):
        assert TCPParser.flag_summary(0x004) == "RST"

    def test_flag_summary_ack(self):
        assert TCPParser.flag_summary(0x010) == "ACK"

    def test_seq_ack_numbers(self):
        raw = make_tcp(seq=111111, ack=222222)
        result = TCPParser.parse(raw)
        assert result["seq"] == 111111
        assert result["ack"] == 222222

    def test_dst_service_http(self):
        raw = make_tcp(dst_port=80)
        result = TCPParser.parse(raw)
        assert result["dst_service"] == "HTTP"

    def test_dst_service_https(self):
        raw = make_tcp(dst_port=443)
        result = TCPParser.parse(raw)
        assert result["dst_service"] == "HTTPS"

    def test_too_short_raises(self):
        with pytest.raises(ValueError):
            TCPParser.parse(b"\x00" * 5)


# ══════════════════════════════════════════════════════════════════════════════
# UDP
# ══════════════════════════════════════════════════════════════════════════════

class TestUDPParser:
    def test_parse_basic(self):
        raw = make_udp(src_port=54000, dst_port=53)
        result = UDPParser.parse(raw)
        assert result["src_port"] == 54000
        assert result["dst_port"] == 53
        assert result["dst_service"] == "DNS"

    def test_length_field(self):
        payload = b"A" * 10
        raw = make_udp(payload=payload)
        result = UDPParser.parse(raw)
        assert result["length"] == 18   # 8 header + 10 payload

    def test_too_short_raises(self):
        with pytest.raises(ValueError):
            UDPParser.parse(b"\x00" * 4)

    def test_payload_extracted(self):
        payload = b"DNS_QUERY"
        raw = make_udp(payload=payload)
        result = UDPParser.parse(raw)
        assert result["payload"] == payload


# ══════════════════════════════════════════════════════════════════════════════
# ICMP
# ══════════════════════════════════════════════════════════════════════════════

class TestICMPParser:
    def _make_icmp(self, icmp_type=8, code=0, id=1, seq=1):
        header = struct.pack("!BBH", icmp_type, code, 0)
        if icmp_type in (0, 8):
            header += struct.pack("!HH", id, seq)
        return header

    def test_echo_request(self):
        raw = self._make_icmp(icmp_type=8, id=100, seq=1)
        result = ICMPParser.parse(raw)
        assert result["type"] == 8
        assert result["type_name"] == "Echo Request"
        assert result["id"] == 100
        assert result["seq"] == 1

    def test_echo_reply(self):
        raw = self._make_icmp(icmp_type=0)
        result = ICMPParser.parse(raw)
        assert result["type"] == 0
        assert result["type_name"] == "Echo Reply"

    def test_unreachable(self):
        raw = struct.pack("!BBH", 3, 1, 0) + b"\x00" * 4
        result = ICMPParser.parse(raw)
        assert result["type"] == 3
        assert result["code_name"] == "Host Unreachable"

    def test_too_short_raises(self):
        with pytest.raises(ValueError):
            ICMPParser.parse(b"\x08\x00")


# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════

class TestHelpers:
    def test_bytes_to_mac(self):
        raw = bytes([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        assert bytes_to_mac(raw) == "aa:bb:cc:dd:ee:ff"

    def test_bytes_to_ip(self):
        raw = bytes([192, 168, 1, 1])
        assert bytes_to_ip(raw) == "192.168.1.1"

    def test_tcp_flags_str_syn(self):
        result = tcp_flags_str(0x002)
        assert "SYN" in result

    def test_tcp_flags_str_syn_ack(self):
        result = tcp_flags_str(0x012)
        assert "SYN" in result
        assert "ACK" in result

    def test_format_bytes_bytes(self):
        assert format_bytes(512) == "512.0 B"

    def test_format_bytes_kb(self):
        assert "KB" in format_bytes(2048)

    def test_format_bytes_mb(self):
        assert "MB" in format_bytes(2 * 1024 * 1024)


# ══════════════════════════════════════════════════════════════════════════════
# Filter engine
# ══════════════════════════════════════════════════════════════════════════════

class TestFilterEngine:
    from src.filter.filter_engine import FilterEngine
    from src.parse.parsed_packet import ParsedPacket

    def _pkt(self, **kwargs):
        from src.parse.parsed_packet import ParsedPacket
        defaults = dict(
            protocol="TCP",
            ip_src="192.168.1.1",
            ip_dst="8.8.8.8",
            tcp_src_port=54321,
            tcp_dst_port=80,
            length=100,
        )
        defaults.update(kwargs)
        return ParsedPacket(**defaults)

    def test_empty_filter_matches_all(self):
        from src.filter.filter_engine import FilterEngine
        fe = FilterEngine("")
        assert fe.matches(self._pkt()) is True

    def test_protocol_filter_match(self):
        from src.filter.filter_engine import FilterEngine
        fe = FilterEngine("tcp")
        assert fe.matches(self._pkt(protocol="TCP")) is True

    def test_protocol_filter_no_match(self):
        from src.filter.filter_engine import FilterEngine
        fe = FilterEngine("udp")
        assert fe.matches(self._pkt(protocol="TCP")) is False

    def test_ip_src_filter(self):
        from src.filter.filter_engine import FilterEngine
        fe = FilterEngine("ip.src == 192.168.1.1")
        assert fe.matches(self._pkt(ip_src="192.168.1.1")) is True
        assert fe.matches(self._pkt(ip_src="10.0.0.1")) is False

    def test_port_filter(self):
        from src.filter.filter_engine import FilterEngine
        fe = FilterEngine("port 80")
        assert fe.matches(self._pkt(tcp_dst_port=80)) is True
        assert fe.matches(self._pkt(tcp_dst_port=443)) is False

    def test_and_filter(self):
        from src.filter.filter_engine import FilterEngine
        fe = FilterEngine("tcp and port 80")
        assert fe.matches(self._pkt(protocol="TCP", tcp_dst_port=80)) is True
        assert fe.matches(self._pkt(protocol="UDP", tcp_dst_port=80)) is False

    def test_or_filter(self):
        from src.filter.filter_engine import FilterEngine
        fe = FilterEngine("tcp or udp")
        assert fe.matches(self._pkt(protocol="TCP")) is True
        assert fe.matches(self._pkt(protocol="UDP")) is True
        assert fe.matches(self._pkt(protocol="ICMP")) is False

    def test_not_filter(self):
        from src.filter.filter_engine import FilterEngine
        fe = FilterEngine("not icmp")
        assert fe.matches(self._pkt(protocol="TCP")) is True
        assert fe.matches(self._pkt(protocol="ICMP")) is False

    def test_validate_valid(self):
        from src.filter.filter_engine import FilterEngine
        assert FilterEngine.validate("tcp") is None
        assert FilterEngine.validate("ip.src == 192.168.1.1") is None
        assert FilterEngine.validate("") is None

    def test_dns_filter(self):
        from src.filter.filter_engine import FilterEngine
        fe = FilterEngine("dns")
        assert fe.matches(self._pkt(protocol="DNS")) is True
        assert fe.matches(self._pkt(protocol="TCP")) is False
