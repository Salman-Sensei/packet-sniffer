"""
ParsedPacket dataclass — the core data object passed around the whole app.
Every layer's parser fills in the relevant fields.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Any


@dataclass
class ParsedPacket:
    # ── Metadata ────────────────────────────────────────────────────────────
    packet_id:   int      = 0
    timestamp:   float    = 0.0          # seconds since capture start
    abs_time:    str      = ""           # "HH:MM:SS.mmm"
    raw_bytes:   bytes    = b""
    length:      int      = 0
    protocol:    str      = "UNKNOWN"    # top-level protocol label
    info:        str      = ""           # one-line summary for table

    # ── Ethernet ────────────────────────────────────────────────────────────
    eth_src:     Optional[str] = None
    eth_dst:     Optional[str] = None
    eth_type:    Optional[str] = None    # "0x0800"

    # ── IPv4 ────────────────────────────────────────────────────────────────
    ip_version:  Optional[int] = None
    ip_src:      Optional[str] = None
    ip_dst:      Optional[str] = None
    ip_ttl:      Optional[int] = None
    ip_proto:    Optional[int] = None
    ip_checksum: Optional[int] = None
    ip_header_len: Optional[int] = None
    ip_total_len:  Optional[int] = None

    # ── IPv6 ────────────────────────────────────────────────────────────────
    ipv6_src:    Optional[str] = None
    ipv6_dst:    Optional[str] = None

    # ── TCP ─────────────────────────────────────────────────────────────────
    tcp_src_port: Optional[int] = None
    tcp_dst_port: Optional[int] = None
    tcp_seq:      Optional[int] = None
    tcp_ack:      Optional[int] = None
    tcp_flags:    Optional[int] = None
    tcp_flags_str: Optional[str] = None   # "[SYN,ACK]"
    tcp_window:   Optional[int] = None
    tcp_checksum: Optional[int] = None

    # ── UDP ─────────────────────────────────────────────────────────────────
    udp_src_port: Optional[int] = None
    udp_dst_port: Optional[int] = None
    udp_length:   Optional[int] = None
    udp_checksum: Optional[int] = None

    # ── ICMP ────────────────────────────────────────────────────────────────
    icmp_type:  Optional[int] = None
    icmp_code:  Optional[int] = None
    icmp_id:    Optional[int] = None
    icmp_seq:   Optional[int] = None

    # ── DNS ─────────────────────────────────────────────────────────────────
    dns_id:         Optional[int]  = None
    dns_is_response: bool          = False
    dns_query_name: Optional[str]  = None
    dns_query_type: Optional[str]  = None
    dns_answers:    list           = field(default_factory=list)

    # ── HTTP ────────────────────────────────────────────────────────────────
    http_method:  Optional[str] = None
    http_uri:     Optional[str] = None
    http_version: Optional[str] = None
    http_host:    Optional[str] = None
    http_status:  Optional[str] = None

    # ── ARP ─────────────────────────────────────────────────────────────────
    arp_op:       Optional[str] = None   # "request" | "reply"
    arp_sender_ip: Optional[str] = None
    arp_target_ip: Optional[str] = None
    arp_sender_mac: Optional[str] = None

    # ── Convenience properties ───────────────────────────────────────────────
    @property
    def src(self) -> str:
        return self.ip_src or self.ipv6_src or self.arp_sender_ip or self.eth_src or "?"

    @property
    def dst(self) -> str:
        return self.ip_dst or self.ipv6_dst or self.arp_target_ip or self.eth_dst or "?"

    @property
    def src_port(self) -> Optional[int]:
        return self.tcp_src_port or self.udp_src_port

    @property
    def dst_port(self) -> Optional[int]:
        return self.tcp_dst_port or self.udp_dst_port
