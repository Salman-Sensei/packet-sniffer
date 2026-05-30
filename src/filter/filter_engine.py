"""
FilterEngine — parses and applies display filters.

Supported syntax examples:
    tcp
    udp
    dns
    icmp
    http
    ip.src == 192.168.1.1
    ip.dst == 8.8.8.8
    port 80
    port == 443
    tcp.port == 80
    udp.port == 53
    ip.src == 192.168.1.1 and port 443
    tcp or udp
    not icmp
"""

import re
from typing import Optional
from src.parse.parsed_packet import ParsedPacket


class FilterError(Exception):
    pass


class FilterEngine:

    def __init__(self, expression: str = ""):
        self.expression = expression.strip()
        self._tokens: list = []
        if self.expression:
            self._tokens = self._tokenize(self.expression)

    # ── Public API ────────────────────────────────────────────────────────────

    def matches(self, pkt: ParsedPacket) -> bool:
        """Return True if packet satisfies the filter expression."""
        if not self.expression:
            return True
        try:
            result, _ = self._eval(self._tokens, 0, pkt)
            return bool(result)
        except Exception:
            return True   # bad filter → show everything

    @staticmethod
    def validate(expression: str) -> Optional[str]:
        """Return error string if expression is invalid, else None."""
        if not expression.strip():
            return None
        try:
            fe = FilterEngine(expression)
            dummy = ParsedPacket(protocol="TCP", ip_src="1.2.3.4", ip_dst="5.6.7.8",
                                 tcp_src_port=1234, tcp_dst_port=80)
            fe.matches(dummy)
            return None
        except FilterError as e:
            return str(e)
        except Exception as e:
            return str(e)

    # ── Tokeniser ─────────────────────────────────────────────────────────────

    def _tokenize(self, expr: str) -> list:
        token_re = re.compile(
            r'\b(and|or|not)\b'
            r'|([!=<>]+)'
            r'|(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'   # IP
            r'|(\d+)'
            r'|([a-zA-Z][a-zA-Z0-9._]*)'
            r'|(\(|\))',
            re.IGNORECASE
        )
        tokens = []
        for m in token_re.finditer(expr):
            tok = m.group(0)
            tokens.append(tok)
        return tokens

    # ── Recursive descent evaluator ───────────────────────────────────────────

    def _eval(self, tokens: list, pos: int, pkt: ParsedPacket):
        """Returns (bool_result, new_pos)."""
        result, pos = self._eval_or(tokens, pos, pkt)
        return result, pos

    def _eval_or(self, tokens, pos, pkt):
        left, pos = self._eval_and(tokens, pos, pkt)
        while pos < len(tokens) and tokens[pos].lower() == "or":
            pos += 1
            right, pos = self._eval_and(tokens, pos, pkt)
            left = left or right
        return left, pos

    def _eval_and(self, tokens, pos, pkt):
        left, pos = self._eval_not(tokens, pos, pkt)
        while pos < len(tokens) and tokens[pos].lower() == "and":
            pos += 1
            right, pos = self._eval_not(tokens, pos, pkt)
            left = left and right
        return left, pos

    def _eval_not(self, tokens, pos, pkt):
        if pos < len(tokens) and tokens[pos].lower() == "not":
            pos += 1
            val, pos = self._eval_primary(tokens, pos, pkt)
            return not val, pos
        return self._eval_primary(tokens, pos, pkt)

    def _eval_primary(self, tokens, pos, pkt):
        if pos >= len(tokens):
            return True, pos

        tok = tokens[pos]

        if tok == "(":
            pos += 1
            val, pos = self._eval_or(tokens, pos, pkt)
            if pos < len(tokens) and tokens[pos] == ")":
                pos += 1
            return val, pos

        # Look-ahead for "field op value" pattern
        if pos + 2 < len(tokens) and tokens[pos + 1] in ("==", "!=", ">", "<", ">=", "<=", "contains"):
            field = tokens[pos]
            op    = tokens[pos + 1]
            value = tokens[pos + 2]
            pos += 3
            return self._compare(pkt, field, op, value), pos

        # Single keyword
        tok_lower = tok.lower()
        pos += 1

        # Protocol keywords
        if tok_lower in ("tcp", "udp", "dns", "icmp", "http", "https", "arp", "tls"):
            return pkt.protocol.upper() == tok_lower.upper(), pos

        # "port <num>" or "port == <num>"
        if tok_lower == "port":
            # optional == or just the number
            op = "=="
            if pos < len(tokens) and tokens[pos] in ("==", "!="):
                op = tokens[pos]
                pos += 1
            if pos < len(tokens) and tokens[pos].isdigit():
                port_val = int(tokens[pos])
                pos += 1
                match = (pkt.src_port == port_val or pkt.dst_port == port_val)
                return (match if op == "==" else not match), pos
            return True, pos

        return True, pos

    def _compare(self, pkt: ParsedPacket, field: str, op: str, value: str) -> bool:
        pkt_val = self._get_field(pkt, field.lower())
        if pkt_val is None:
            return False
        pkt_str = str(pkt_val).lower()
        val_str = value.lower().strip('"\'')

        if op == "==":    return pkt_str == val_str
        if op == "!=":    return pkt_str != val_str
        if op == "contains": return val_str in pkt_str

        # Numeric comparisons
        try:
            pv = float(pkt_val)
            vv = float(value)
            if op == ">":  return pv > vv
            if op == "<":  return pv < vv
            if op == ">=": return pv >= vv
            if op == "<=": return pv <= vv
        except (ValueError, TypeError):
            pass
        return False

    def _get_field(self, pkt: ParsedPacket, field: str):
        mapping = {
            "ip.src":      pkt.ip_src,
            "ip.dst":      pkt.ip_dst,
            "ip.ttl":      pkt.ip_ttl,
            "ip.proto":    pkt.ip_proto,
            "tcp.port":    pkt.tcp_src_port or pkt.tcp_dst_port,
            "tcp.srcport": pkt.tcp_src_port,
            "tcp.dstport": pkt.tcp_dst_port,
            "tcp.seq":     pkt.tcp_seq,
            "tcp.ack":     pkt.tcp_ack,
            "tcp.flags":   pkt.tcp_flags_str,
            "udp.port":    pkt.udp_src_port or pkt.udp_dst_port,
            "udp.srcport": pkt.udp_src_port,
            "udp.dstport": pkt.udp_dst_port,
            "eth.src":     pkt.eth_src,
            "eth.dst":     pkt.eth_dst,
            "dns.qry":     pkt.dns_query_name,
            "dns.query":   pkt.dns_query_name,
            "frame.len":   pkt.length,
            "protocol":    pkt.protocol,
        }
        return mapping.get(field)
