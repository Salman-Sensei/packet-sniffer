"""
TCP segment parser (Layer 4)

TCP header layout (min 20 bytes):
  [0:2]  Source Port
  [2:4]  Destination Port
  [4:8]  Sequence Number
  [8:12] Acknowledgment Number
  [12]   Data Offset(4) | Reserved(3) | Flags(9 bits split across [12][13])
  [13]   Flags (lower 6 bits used: URG ACK PSH RST SYN FIN)
  [14:16] Window Size
  [16:18] Checksum
  [18:20] Urgent Pointer
  [20:]  Options then Payload
"""

import struct
from src.utils.helpers import tcp_flags_str, port_service

TCP_FLAG_BITS = {
    "FIN": 0x01,
    "SYN": 0x02,
    "RST": 0x04,
    "PSH": 0x08,
    "ACK": 0x10,
    "URG": 0x20,
}


class TCPParser:
    MIN_HEADER = 20

    @staticmethod
    def parse(raw: bytes) -> dict:
        if len(raw) < TCPParser.MIN_HEADER:
            raise ValueError(f"Too short for TCP header: {len(raw)}")

        src_port, dst_port = struct.unpack("!HH", raw[0:4])
        seq_num  = struct.unpack("!I", raw[4:8])[0]
        ack_num  = struct.unpack("!I", raw[8:12])[0]
        data_off_flags = struct.unpack("!H", raw[12:14])[0]
        data_off = ((data_off_flags >> 12) & 0xF) * 4
        flags    = data_off_flags & 0x01FF   # 9-bit flags
        window   = struct.unpack("!H", raw[14:16])[0]
        checksum = struct.unpack("!H", raw[16:18])[0]
        urg_ptr  = struct.unpack("!H", raw[18:20])[0]
        payload  = raw[data_off:]

        active_flags = {name: bool(flags & bit) for name, bit in TCP_FLAG_BITS.items()}

        return {
            "src_port":     src_port,
            "dst_port":     dst_port,
            "src_service":  port_service(src_port),
            "dst_service":  port_service(dst_port),
            "seq":          seq_num,
            "ack":          ack_num,
            "data_offset":  data_off,
            "flags_int":    flags,
            "flags_str":    tcp_flags_str(flags),
            "flags_dict":   active_flags,
            "window":       window,
            "checksum":     checksum,
            "urg_ptr":      urg_ptr,
            "payload":      payload,
        }

    @staticmethod
    def flag_summary(flags: int) -> str:
        """One-word summary of the dominant flag."""
        if flags & 0x02 and flags & 0x10:   return "SYN-ACK"
        if flags & 0x02:                     return "SYN"
        if flags & 0x01 and flags & 0x10:   return "FIN-ACK"
        if flags & 0x01:                     return "FIN"
        if flags & 0x04:                     return "RST"
        if flags & 0x10:                     return "ACK"
        if flags & 0x08:                     return "PSH"
        return "DATA"
