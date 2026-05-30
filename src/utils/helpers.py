"""
Utility / helper functions for NETSCOPE
"""

import socket
import struct
from datetime import datetime
from typing import Optional
from src.utils.constants import WELL_KNOWN_PORTS, IP_PROTOCOLS


def bytes_to_mac(raw: bytes) -> str:
    """Convert 6 raw bytes to human-readable MAC string."""
    return ":".join(f"{b:02x}" for b in raw)


def bytes_to_ip(raw: bytes) -> str:
    """Convert 4 raw bytes to dotted-decimal IPv4 string."""
    return ".".join(str(b) for b in raw)


def ip_to_int(ip: str) -> int:
    """Convert dotted-decimal IP to integer for comparison."""
    try:
        parts = ip.split(".")
        return sum(int(p) << (24 - 8 * i) for i, p in enumerate(parts))
    except Exception:
        return 0


def port_service(port: int) -> str:
    """Return service name for well-known port, or empty string."""
    return WELL_KNOWN_PORTS.get(port, "")


def protocol_name(proto_num: int) -> str:
    """Convert IP protocol number to string name."""
    return IP_PROTOCOLS.get(proto_num, f"Proto({proto_num})")


def format_bytes(n: int) -> str:
    """Human-readable byte count: 1024 → '1.0 KB'"""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def format_hex(data: bytes, bytes_per_row: int = 16) -> str:
    """Return pretty hex dump string of raw bytes."""
    lines = []
    for i in range(0, len(data), bytes_per_row):
        chunk = data[i: i + bytes_per_row]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        asc_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:04x}  {hex_part:<{bytes_per_row*3}}  {asc_part}")
    return "\n".join(lines)


def hex_dump_rows(data: bytes, bytes_per_row: int = 16):
    """Yield (offset_str, hex_str, ascii_str) tuples for GUI display."""
    for i in range(0, len(data), bytes_per_row):
        chunk = data[i: i + bytes_per_row]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        asc_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        yield f"{i:04x}", hex_part, asc_part


def timestamp_str() -> str:
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def get_local_ip() -> str:
    """Best-effort local IP detection (no network call needed)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def tcp_flags_str(flags: int) -> str:
    """Convert TCP flags int to human-readable string."""
    names = []
    if flags & 0x01: names.append("FIN")
    if flags & 0x02: names.append("SYN")
    if flags & 0x04: names.append("RST")
    if flags & 0x08: names.append("PSH")
    if flags & 0x10: names.append("ACK")
    if flags & 0x20: names.append("URG")
    return "[" + (",".join(names) if names else "NONE") + "]"
