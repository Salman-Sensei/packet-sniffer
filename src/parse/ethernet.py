"""
Ethernet frame parser (Layer 2)

Ethernet II frame layout (14 bytes):
  [0:6]  Destination MAC
  [6:12] Source MAC
  [12:14] EtherType
  [14:]  Payload
"""

import struct
from src.utils.helpers import bytes_to_mac

# EtherType → human name
ETHER_TYPES = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
    0x8100: "VLAN",
    0x88CC: "LLDP",
}


class EthernetParser:
    HEADER_LEN = 14

    @staticmethod
    def parse(raw: bytes) -> dict:
        """
        Parse Ethernet frame header.

        Returns dict with keys:
            dst_mac, src_mac, eth_type_int, eth_type_str, payload
        """
        if len(raw) < EthernetParser.HEADER_LEN:
            raise ValueError(f"Packet too short for Ethernet header: {len(raw)} bytes")

        dst_mac_raw, src_mac_raw, eth_type = struct.unpack("!6s6sH", raw[:14])

        return {
            "dst_mac":     bytes_to_mac(dst_mac_raw),
            "src_mac":     bytes_to_mac(src_mac_raw),
            "eth_type_int": eth_type,
            "eth_type_str": ETHER_TYPES.get(eth_type, f"0x{eth_type:04x}"),
            "payload":     raw[14:],
        }
