"""
UDP, ICMP, DNS and ARP parsers.
"""

import struct
from src.utils.helpers import port_service, bytes_to_ip, bytes_to_mac


# ══════════════════════════════════════════════════════════════════════════════
# UDP
# ══════════════════════════════════════════════════════════════════════════════

class UDPParser:
    HEADER_LEN = 8

    @staticmethod
    def parse(raw: bytes) -> dict:
        if len(raw) < UDPParser.HEADER_LEN:
            raise ValueError(f"Too short for UDP: {len(raw)}")
        src_port, dst_port, length, checksum = struct.unpack("!HHHH", raw[:8])
        return {
            "src_port":    src_port,
            "dst_port":    dst_port,
            "src_service": port_service(src_port),
            "dst_service": port_service(dst_port),
            "length":      length,
            "checksum":    checksum,
            "payload":     raw[8:],
        }


# ══════════════════════════════════════════════════════════════════════════════
# ICMP
# ══════════════════════════════════════════════════════════════════════════════

ICMP_TYPES = {
    0:  "Echo Reply",
    3:  "Destination Unreachable",
    4:  "Source Quench",
    5:  "Redirect",
    8:  "Echo Request",
    11: "Time Exceeded",
    12: "Parameter Problem",
    13: "Timestamp",
    14: "Timestamp Reply",
    30: "Traceroute",
}

ICMP_CODES_3 = {    # Destination Unreachable codes
    0: "Net Unreachable",
    1: "Host Unreachable",
    2: "Protocol Unreachable",
    3: "Port Unreachable",
    4: "Fragmentation Needed",
    5: "Source Route Failed",
}


class ICMPParser:
    HEADER_LEN = 4

    @staticmethod
    def parse(raw: bytes) -> dict:
        if len(raw) < ICMPParser.HEADER_LEN:
            raise ValueError(f"Too short for ICMP: {len(raw)}")
        icmp_type = raw[0]
        icmp_code = raw[1]
        checksum  = struct.unpack("!H", raw[2:4])[0]
        payload   = raw[4:]

        # Echo request/reply carry id + seq
        icmp_id = icmp_seq = None
        if icmp_type in (0, 8) and len(raw) >= 8:
            icmp_id, icmp_seq = struct.unpack("!HH", raw[4:8])
            payload = raw[8:]

        type_name = ICMP_TYPES.get(icmp_type, f"Type({icmp_type})")
        code_name = ""
        if icmp_type == 3:
            code_name = ICMP_CODES_3.get(icmp_code, f"Code({icmp_code})")

        return {
            "type":      icmp_type,
            "type_name": type_name,
            "code":      icmp_code,
            "code_name": code_name,
            "checksum":  checksum,
            "id":        icmp_id,
            "seq":       icmp_seq,
            "payload":   payload,
        }


# ══════════════════════════════════════════════════════════════════════════════
# DNS  (simplified — enough for display)
# ══════════════════════════════════════════════════════════════════════════════

DNS_QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
              15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}


def _dns_decode_name(data: bytes, offset: int):
    """Decode a DNS name from `data` starting at `offset`. Returns (name, new_offset)."""
    labels = []
    visited = set()
    while offset < len(data):
        if offset in visited:
            break
        visited.add(offset)
        length = data[offset]
        if length == 0:
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:      # pointer
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            offset += 2
            name_part, _ = _dns_decode_name(data, ptr)
            labels.append(name_part)
            break
        else:
            offset += 1
            labels.append(data[offset: offset + length].decode("utf-8", errors="replace"))
            offset += length
    return ".".join(labels), offset


class DNSParser:
    @staticmethod
    def parse(raw: bytes) -> dict:
        if len(raw) < 12:
            return {"error": "too short"}

        dns_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", raw[:12])
        is_response = bool(flags & 0x8000)

        # Parse first question
        query_name = query_type_str = None
        offset = 12
        if qdcount > 0 and offset < len(raw):
            try:
                query_name, offset = _dns_decode_name(raw, offset)
                if offset + 4 <= len(raw):
                    qtype, qclass = struct.unpack("!HH", raw[offset: offset + 4])
                    query_type_str = DNS_QTYPES.get(qtype, str(qtype))
                    offset += 4
            except Exception:
                pass

        # Parse answers (best-effort)
        answers = []
        for _ in range(min(ancount, 10)):
            try:
                name, offset = _dns_decode_name(raw, offset)
                if offset + 10 > len(raw):
                    break
                rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", raw[offset: offset + 10])
                offset += 10
                rdata = raw[offset: offset + rdlen]
                offset += rdlen
                rtype_str = DNS_QTYPES.get(rtype, str(rtype))
                if rtype == 1 and len(rdata) == 4:
                    val = bytes_to_ip(rdata)
                elif rtype == 28 and len(rdata) == 16:
                    val = ":".join(f"{rdata[i]:02x}{rdata[i+1]:02x}" for i in range(0, 16, 2))
                else:
                    val = rdata.decode("utf-8", errors="replace")
                answers.append({"name": name, "type": rtype_str, "ttl": ttl, "value": val})
            except Exception:
                break

        return {
            "id":          dns_id,
            "is_response": is_response,
            "query_name":  query_name,
            "query_type":  query_type_str,
            "answers":     answers,
            "qdcount":     qdcount,
            "ancount":     ancount,
        }


# ══════════════════════════════════════════════════════════════════════════════
# ARP
# ══════════════════════════════════════════════════════════════════════════════

ARP_OPS = {1: "request", 2: "reply"}


class ARPParser:
    @staticmethod
    def parse(raw: bytes) -> dict:
        if len(raw) < 28:
            return {"error": "too short"}
        htype, ptype, hlen, plen, op = struct.unpack("!HHBBH", raw[:8])
        sender_mac = bytes_to_mac(raw[8:14])
        sender_ip  = bytes_to_ip(raw[14:18])
        target_mac = bytes_to_mac(raw[18:24])
        target_ip  = bytes_to_ip(raw[24:28])
        return {
            "op":         ARP_OPS.get(op, str(op)),
            "sender_mac": sender_mac,
            "sender_ip":  sender_ip,
            "target_mac": target_mac,
            "target_ip":  target_ip,
        }
