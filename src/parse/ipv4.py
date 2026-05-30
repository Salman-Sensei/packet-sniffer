"""
IPv4 packet parser (Layer 3)

IPv4 header layout (min 20 bytes):
  [0]    Version(4) | IHL(4)
  [1]    DSCP/ECN
  [2:4]  Total Length
  [4:6]  Identification
  [6:8]  Flags | Fragment Offset
  [8]    TTL
  [9]    Protocol
  [10:12] Header Checksum
  [12:16] Source IP
  [16:20] Destination IP
  [20:]   Options (if IHL > 5) then Payload
"""

import struct
from src.utils.helpers import bytes_to_ip
from src.utils.constants import IP_PROTOCOLS

IP_FLAGS = {0: "", 1: "MF", 2: "DF", 3: "MF+DF"}


class IPv4Parser:
    MIN_HEADER = 20

    @staticmethod
    def parse(raw: bytes) -> dict:
        if len(raw) < IPv4Parser.MIN_HEADER:
            raise ValueError(f"Too short for IPv4 header: {len(raw)}")

        ver_ihl = raw[0]
        version    = ver_ihl >> 4
        ihl        = (ver_ihl & 0x0F) * 4   # bytes
        tos        = raw[1]
        total_len, ident, flags_frag = struct.unpack("!HHH", raw[2:8])
        flags      = (flags_frag >> 13) & 0x7
        frag_off   = flags_frag & 0x1FFF
        ttl        = raw[8]
        proto      = raw[9]
        checksum   = struct.unpack("!H", raw[10:12])[0]
        src_ip     = bytes_to_ip(raw[12:16])
        dst_ip     = bytes_to_ip(raw[16:20])
        payload    = raw[ihl:]

        return {
            "version":    version,
            "ihl":        ihl,
            "tos":        tos,
            "total_len":  total_len,
            "ident":      ident,
            "flags":      IP_FLAGS.get(flags, str(flags)),
            "frag_off":   frag_off,
            "ttl":        ttl,
            "proto":      proto,
            "proto_name": IP_PROTOCOLS.get(proto, f"Unknown({proto})"),
            "checksum":   checksum,
            "src":        src_ip,
            "dst":        dst_ip,
            "payload":    payload,
        }
