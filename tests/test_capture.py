"""
Integration tests for PacketParser (no live capture needed).
Uses manually crafted scapy-like raw bytes.
"""

import pytest
import struct

from src.parse.packet_parser import PacketParser
from src.parse.parsed_packet import ParsedPacket


def build_raw_tcp(
    eth_src="aa:bb:cc:dd:ee:ff", eth_dst="11:22:33:44:55:66",
    ip_src="192.168.1.5",  ip_dst="8.8.8.8",
    tcp_sport=54321, tcp_dport=80,
    tcp_flags=0x002,
):
    """Build a raw Ethernet/IPv4/TCP frame as bytes."""
    # TCP header (20 bytes)
    tcp_data_off_flags = (5 << 12) | tcp_flags
    tcp_hdr = (
        struct.pack("!HH", tcp_sport, tcp_dport) +
        struct.pack("!I", 1000) +   # seq
        struct.pack("!I", 0) +      # ack
        struct.pack("!HH", tcp_data_off_flags, 65535) +
        struct.pack("!HH", 0, 0)    # checksum, urgent
    )

    # IPv4 header (20 bytes)
    ip_src_b = bytes(int(x) for x in ip_src.split("."))
    ip_dst_b = bytes(int(x) for x in ip_dst.split("."))
    total_len = 20 + len(tcp_hdr)
    ip_hdr = (
        struct.pack("!BB", 0x45, 0) +
        struct.pack("!HH", total_len, 0) +
        struct.pack("!HH", 0, 0) +
        struct.pack("!BBH", 64, 6, 0) +  # TTL=64, proto=6 (TCP)
        ip_src_b + ip_dst_b
    )

    # Ethernet header (14 bytes)
    eth_dst_b = bytes(int(x, 16) for x in eth_dst.split(":"))
    eth_src_b = bytes(int(x, 16) for x in eth_src.split(":"))
    eth_hdr = struct.pack("!6s6sH", eth_dst_b, eth_src_b, 0x0800)

    return eth_hdr + ip_hdr + tcp_hdr


def build_raw_udp_dns(ip_src="192.168.1.5", ip_dst="8.8.8.8"):
    """Build Ethernet/IPv4/UDP/DNS query frame."""
    # Minimal DNS query for "google.com"
    dns_payload = (
        struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) +
        b"\x06google\x03com\x00" +
        struct.pack("!HH", 1, 1)  # QTYPE=A, QCLASS=IN
    )

    udp_length = 8 + len(dns_payload)
    udp_hdr = struct.pack("!HHHH", 54321, 53, udp_length, 0)

    ip_src_b = bytes(int(x) for x in ip_src.split("."))
    ip_dst_b = bytes(int(x) for x in ip_dst.split("."))
    total_len = 20 + len(udp_hdr) + len(dns_payload)
    ip_hdr = (
        struct.pack("!BB", 0x45, 0) +
        struct.pack("!HH", total_len, 0) +
        struct.pack("!HH", 0, 0) +
        struct.pack("!BBH", 64, 17, 0) +   # proto=17 (UDP)
        ip_src_b + ip_dst_b
    )
    eth_dst_b = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
    eth_src_b = bytes([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
    eth_hdr = struct.pack("!6s6sH", eth_dst_b, eth_src_b, 0x0800)

    return eth_hdr + ip_hdr + udp_hdr + dns_payload


class FakeScapyPkt:
    """Minimal stand-in for a scapy packet — just wraps raw bytes."""
    def __init__(self, raw: bytes):
        self._raw = raw

    def __bytes__(self):
        return self._raw

    def __len__(self):
        return len(self._raw)


class TestPacketParser:

    def test_parse_tcp_syn(self):
        raw = build_raw_tcp(tcp_sport=54321, tcp_dport=80, tcp_flags=0x002)
        pkt = PacketParser.parse(FakeScapyPkt(raw))

        assert pkt is not None
        assert pkt.ip_src == "192.168.1.5"
        assert pkt.ip_dst == "8.8.8.8"
        assert pkt.tcp_src_port == 54321
        assert pkt.tcp_dst_port == 80
        assert pkt.tcp_flags & 0x002   # SYN set

    def test_parse_https_port(self):
        raw = build_raw_tcp(tcp_dport=443)
        pkt = PacketParser.parse(FakeScapyPkt(raw))
        assert pkt.protocol == "HTTPS"

    def test_parse_http_port(self):
        raw = build_raw_tcp(tcp_dport=80)
        pkt = PacketParser.parse(FakeScapyPkt(raw))
        assert pkt.protocol in ("HTTP", "TCP")   # HTTP if payload has method

    def test_parse_ethernet_fields(self):
        raw = build_raw_tcp(
            eth_src="aa:bb:cc:dd:ee:ff",
            eth_dst="11:22:33:44:55:66"
        )
        pkt = PacketParser.parse(FakeScapyPkt(raw))
        assert pkt.eth_src == "aa:bb:cc:dd:ee:ff"
        assert pkt.eth_dst == "11:22:33:44:55:66"

    def test_parse_ip_ttl(self):
        raw = build_raw_tcp()
        pkt = PacketParser.parse(FakeScapyPkt(raw))
        assert pkt.ip_ttl == 64

    def test_parse_dns(self):
        raw = build_raw_dns = build_raw_udp_dns()
        pkt = PacketParser.parse(FakeScapyPkt(build_raw_dns))
        assert pkt.protocol == "DNS"
        assert pkt.udp_dst_port == 53

    def test_packet_has_id(self):
        raw = build_raw_tcp()
        p1 = PacketParser.parse(FakeScapyPkt(raw))
        p2 = PacketParser.parse(FakeScapyPkt(raw))
        assert p2.packet_id == p1.packet_id + 1

    def test_packet_has_timestamp(self):
        raw = build_raw_tcp()
        pkt = PacketParser.parse(FakeScapyPkt(raw))
        assert pkt.timestamp >= 0.0

    def test_packet_has_raw_bytes(self):
        raw = build_raw_tcp()
        pkt = PacketParser.parse(FakeScapyPkt(raw))
        assert pkt.raw_bytes == raw

    def test_packet_length(self):
        raw = build_raw_tcp()
        pkt = PacketParser.parse(FakeScapyPkt(raw))
        assert pkt.length == len(raw)

    def test_src_dst_properties(self):
        raw = build_raw_tcp(ip_src="10.0.0.1", ip_dst="172.16.0.5")
        pkt = PacketParser.parse(FakeScapyPkt(raw))
        assert pkt.src == "10.0.0.1"
        assert pkt.dst == "172.16.0.5"

    def test_src_port_property(self):
        raw = build_raw_tcp(tcp_sport=9999)
        pkt = PacketParser.parse(FakeScapyPkt(raw))
        assert pkt.src_port == 9999

    def test_dst_port_property(self):
        raw = build_raw_tcp(tcp_dport=3306)
        pkt = PacketParser.parse(FakeScapyPkt(raw))
        assert pkt.dst_port == 3306
