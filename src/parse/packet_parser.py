"""
PacketParser — orchestrates all layer parsers into a single ParsedPacket.
"""

import time
from datetime import datetime
from typing import Optional

from src.parse.parsed_packet import ParsedPacket
from src.parse.ethernet import EthernetParser
from src.parse.ipv4 import IPv4Parser
from src.parse.tcp import TCPParser
from src.parse.protocols import UDPParser, ICMPParser, DNSParser, ARPParser
from src.utils.helpers import port_service, tcp_flags_str

_capture_start: float = time.time()


def reset_timer():
    global _capture_start
    _capture_start = time.time()


class PacketParser:
    """
    Parse a raw scapy packet (or raw bytes via scapy) into a ParsedPacket.
    Falls back gracefully if any layer can't be parsed.
    """

    _counter: int = 0

    @classmethod
    def parse(cls, scapy_pkt) -> Optional[ParsedPacket]:
        """Main entry point. Pass a scapy packet object."""
        cls._counter += 1
        now = time.time()
        rel_time = now - _capture_start

        p = ParsedPacket(
            packet_id = cls._counter,
            timestamp  = rel_time,
            abs_time   = datetime.now().strftime("%H:%M:%S.%f")[:-3],
        )

        try:
            raw = bytes(scapy_pkt)
            p.raw_bytes = raw
            p.length    = len(raw)
        except Exception:
            return None

        # ── Ethernet ─────────────────────────────────────────────────────────
        try:
            eth = EthernetParser.parse(raw)
            p.eth_src    = eth["src_mac"]
            p.eth_dst    = eth["dst_mac"]
            p.eth_type   = eth["eth_type_str"]
            eth_type_int = eth["eth_type_int"]
            payload      = eth["payload"]
        except Exception:
            p.protocol = "RAW"
            p.info = f"Raw frame {p.length} bytes"
            return p

        # ── IPv4 ─────────────────────────────────────────────────────────────
        if eth_type_int == 0x0800:
            try:
                ip = IPv4Parser.parse(payload)
                p.ip_version   = ip["version"]
                p.ip_src       = ip["src"]
                p.ip_dst       = ip["dst"]
                p.ip_ttl       = ip["ttl"]
                p.ip_proto     = ip["proto"]
                p.ip_checksum  = ip["checksum"]
                p.ip_header_len = ip["ihl"]
                p.ip_total_len  = ip["total_len"]
                ip_payload     = ip["payload"]

                proto = ip["proto"]

                # ── TCP ──────────────────────────────────────────────────────
                if proto == 6:
                    cls._parse_tcp(p, ip_payload)

                # ── UDP ──────────────────────────────────────────────────────
                elif proto == 17:
                    cls._parse_udp(p, ip_payload)

                # ── ICMP ─────────────────────────────────────────────────────
                elif proto == 1:
                    cls._parse_icmp(p, ip_payload)

                else:
                    p.protocol = ip["proto_name"]
                    p.info = f"{p.protocol} {p.ip_src} → {p.ip_dst}"

            except Exception as e:
                p.protocol = "IPv4"
                p.info = f"Parse error: {e}"

        # ── ARP ──────────────────────────────────────────────────────────────
        elif eth_type_int == 0x0806:
            try:
                arp = ARPParser.parse(payload)
                p.protocol      = "ARP"
                p.arp_op        = arp["op"]
                p.arp_sender_ip  = arp["sender_ip"]
                p.arp_target_ip  = arp["target_ip"]
                p.arp_sender_mac = arp["sender_mac"]
                if arp["op"] == "request":
                    p.info = f"Who has {arp['target_ip']}? Tell {arp['sender_ip']}"
                else:
                    p.info = f"{arp['sender_ip']} is at {arp['sender_mac']}"
            except Exception:
                p.protocol = "ARP"
                p.info = "ARP packet"

        # ── IPv6 ─────────────────────────────────────────────────────────────
        elif eth_type_int == 0x86DD:
            p.protocol = "IPv6"
            p.info = "IPv6 packet"

        else:
            p.protocol = eth["eth_type_str"]
            p.info = f"EtherType {eth['eth_type_str']}"

        return p

    # ── Layer helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _parse_tcp(p: ParsedPacket, raw: bytes):
        try:
            tcp = TCPParser.parse(raw)
            p.tcp_src_port = tcp["src_port"]
            p.tcp_dst_port = tcp["dst_port"]
            p.tcp_seq      = tcp["seq"]
            p.tcp_ack      = tcp["ack"]
            p.tcp_flags    = tcp["flags_int"]
            p.tcp_flags_str = tcp["flags_str"]
            p.tcp_window   = tcp["window"]
            p.tcp_checksum = tcp["checksum"]

            # Check for HTTP inside TCP payload
            payload = tcp["payload"]
            flag_summary = TCPParser.flag_summary(tcp["flags_int"])

            dst_svc = port_service(tcp["dst_port"])
            src_svc = port_service(tcp["src_port"])

            if tcp["dst_port"] == 80 or tcp["src_port"] == 80:
                PacketParser._try_http(p, payload, tcp)
                if p.protocol not in ("HTTP",):
                    p.protocol = "HTTP"
                    p.info = f"{tcp['src_port']} → {tcp['dst_port']} [{flag_summary}]"
            elif tcp["dst_port"] == 443 or tcp["src_port"] == 443:
                p.protocol = "HTTPS"
                p.info = f"TLS Application Data {tcp['src_port']} → {tcp['dst_port']} [{flag_summary}]"
            else:
                p.protocol = "TCP"
                svc = dst_svc or src_svc
                svc_str = f" ({svc})" if svc else ""
                p.info = f"{tcp['src_port']} → {tcp['dst_port']}{svc_str} [{flag_summary}] Seq={tcp['seq']} Ack={tcp['ack']}"

        except Exception as e:
            p.protocol = "TCP"
            p.info = f"TCP parse error: {e}"

    @staticmethod
    def _try_http(p: ParsedPacket, payload: bytes, tcp: dict):
        try:
            text = payload.decode("utf-8", errors="replace")
            lines = text.split("\r\n")
            if lines:
                first = lines[0]
                if first.startswith(("GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ")):
                    parts = first.split(" ")
                    p.http_method  = parts[0]
                    p.http_uri     = parts[1] if len(parts) > 1 else "/"
                    p.http_version = parts[2] if len(parts) > 2 else "HTTP/1.1"
                    for line in lines[1:]:
                        if line.lower().startswith("host:"):
                            p.http_host = line.split(":", 1)[1].strip()
                    p.protocol = "HTTP"
                    p.info = f"{p.http_method} {p.http_host or ''}{p.http_uri} {p.http_version}"
                elif first.startswith("HTTP/"):
                    parts = first.split(" ", 2)
                    p.http_version = parts[0]
                    p.http_status  = f"{parts[1]} {parts[2]}" if len(parts) > 2 else parts[1]
                    p.protocol = "HTTP"
                    p.info = f"HTTP {p.http_status}"
        except Exception:
            pass

    @staticmethod
    def _parse_udp(p: ParsedPacket, raw: bytes):
        try:
            udp = UDPParser.parse(raw)
            p.udp_src_port = udp["src_port"]
            p.udp_dst_port = udp["dst_port"]
            p.udp_length   = udp["length"]
            p.udp_checksum = udp["checksum"]

            # DNS on port 53
            if udp["src_port"] == 53 or udp["dst_port"] == 53:
                PacketParser._parse_dns(p, udp["payload"])
            else:
                svc = port_service(udp["dst_port"]) or port_service(udp["src_port"])
                svc_str = f" ({svc})" if svc else ""
                p.protocol = "UDP"
                p.info = f"{udp['src_port']} → {udp['dst_port']}{svc_str} Len={udp['length']}"

        except Exception as e:
            p.protocol = "UDP"
            p.info = f"UDP parse error: {e}"

    @staticmethod
    def _parse_dns(p: ParsedPacket, payload: bytes):
        try:
            dns = DNSParser.parse(payload)
            p.dns_id          = dns.get("id")
            p.dns_is_response  = dns.get("is_response", False)
            p.dns_query_name   = dns.get("query_name")
            p.dns_query_type   = dns.get("query_type")
            p.dns_answers      = dns.get("answers", [])
            p.protocol = "DNS"
            direction = "Response" if p.dns_is_response else "Query"
            qname = p.dns_query_name or "?"
            qtype = p.dns_query_type or "A"
            p.info = f"Standard {direction} {qtype} {qname}"
        except Exception:
            p.protocol = "DNS"
            p.info = "DNS packet"

    @staticmethod
    def _parse_icmp(p: ParsedPacket, raw: bytes):
        try:
            icmp = ICMPParser.parse(raw)
            p.icmp_type = icmp["type"]
            p.icmp_code = icmp["code"]
            p.icmp_id   = icmp.get("id")
            p.icmp_seq  = icmp.get("seq")
            p.protocol = "ICMP"
            name = icmp["type_name"]
            if p.icmp_id is not None:
                p.info = f"{name} id=0x{p.icmp_id:04x} seq={p.icmp_seq}"
            else:
                p.info = f"{name} (code {p.icmp_code})"
        except Exception:
            p.protocol = "ICMP"
            p.info = "ICMP packet"
