"""
PacketDetailsPane — shows a Wireshark-style protocol tree + hex dump
when the user clicks a packet row.
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QTabWidget,
    QTreeWidget, QTreeWidgetItem, QTextEdit, QLabel
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QFont, QBrush

from src.parse.parsed_packet import ParsedPacket
from src.utils.helpers import format_hex, hex_dump_rows
from src.utils.constants import PROTOCOL_TEXT_COLORS, PROTOCOL_ACCENT_COLORS

MONO = QFont("JetBrains Mono", 11)
MONO.setStyleHint(QFont.Monospace)


class PacketDetailsPane(QWidget):

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._tabs = QTabWidget()
        layout.addWidget(self._tabs)

        # ── Protocol Tree tab ─────────────────────────────────────────────────
        self._tree = QTreeWidget()
        self._tree.setHeaderHidden(True)
        self._tree.setIndentation(14)
        self._tree.setFont(MONO)
        self._tabs.addTab(self._tree, "Details")

        # ── Hex Dump tab ──────────────────────────────────────────────────────
        self._hex = QTextEdit()
        self._hex.setReadOnly(True)
        self._hex.setFont(MONO)
        self._hex.setLineWrapMode(QTextEdit.NoWrap)
        self._tabs.addTab(self._hex, "Hex Dump")

        # ── Raw Bytes tab ─────────────────────────────────────────────────────
        self._raw = QTextEdit()
        self._raw.setReadOnly(True)
        self._raw.setFont(MONO)
        self._raw.setLineWrapMode(QTextEdit.WidgetWidth)
        self._tabs.addTab(self._raw, "Raw Bytes")

        self._placeholder()

    def _placeholder(self):
        self._tree.clear()
        root = QTreeWidgetItem(["Select a packet to inspect..."])
        root.setForeground(0, QBrush(QColor("#334155")))
        self._tree.addTopLevelItem(root)

    # ── Public API ────────────────────────────────────────────────────────────

    def show_packet(self, pkt: ParsedPacket):
        self._build_tree(pkt)
        self._build_hex(pkt)
        self._build_raw(pkt)

    def clear(self):
        self._placeholder()
        self._hex.clear()
        self._raw.clear()

    # ── Tree builder ──────────────────────────────────────────────────────────

    def _build_tree(self, pkt: ParsedPacket):
        self._tree.clear()
        accent = PROTOCOL_ACCENT_COLORS.get(pkt.protocol, "#2b7fff")

        def section(label: str, color: str = "#60a5fa") -> QTreeWidgetItem:
            item = QTreeWidgetItem([label])
            item.setForeground(0, QBrush(QColor(color)))
            item.setExpanded(True)
            return item

        def row(parent: QTreeWidgetItem, label: str, value) -> QTreeWidgetItem:
            s = f"{label}: {value}"
            child = QTreeWidgetItem([s])
            child.setForeground(0, QBrush(QColor("#64748b")))
            parent.addChild(child)
            return child

        # ── Frame ─────────────────────────────────────────────────────────────
        frame_sec = section(f"Frame {pkt.packet_id}: {pkt.length} bytes on wire, {pkt.length} bytes captured", "#475569")
        row(frame_sec, "Arrival Time",    pkt.abs_time)
        row(frame_sec, "Frame Number",    pkt.packet_id)
        row(frame_sec, "Frame Length",    f"{pkt.length} bytes")
        row(frame_sec, "Capture Length",  f"{pkt.length} bytes")
        self._tree.addTopLevelItem(frame_sec)

        # ── Ethernet ──────────────────────────────────────────────────────────
        if pkt.eth_src:
            eth_sec = section(f"Ethernet II, Src: {pkt.eth_src}, Dst: {pkt.eth_dst}", "#94a3b8")
            row(eth_sec, "Destination", pkt.eth_dst)
            row(eth_sec, "Source",      pkt.eth_src)
            row(eth_sec, "Type",        pkt.eth_type or "IPv4")
            self._tree.addTopLevelItem(eth_sec)

        # ── IPv4 ──────────────────────────────────────────────────────────────
        if pkt.ip_src:
            ip_sec = section(
                f"Internet Protocol Version {pkt.ip_version or 4}, "
                f"Src: {pkt.ip_src}, Dst: {pkt.ip_dst}",
                "#94a3b8"
            )
            row(ip_sec, "Version",       pkt.ip_version or 4)
            row(ip_sec, "Header Length", f"{pkt.ip_header_len or 20} bytes")
            row(ip_sec, "Total Length",  pkt.ip_total_len or pkt.length)
            row(ip_sec, "TTL",           pkt.ip_ttl)
            row(ip_sec, "Protocol",      f"{pkt.protocol} ({pkt.ip_proto})")
            row(ip_sec, "Checksum",      f"0x{pkt.ip_checksum:04x}" if pkt.ip_checksum else "N/A")
            row(ip_sec, "Source",        pkt.ip_src)
            row(ip_sec, "Destination",   pkt.ip_dst)
            self._tree.addTopLevelItem(ip_sec)

        # ── TCP ───────────────────────────────────────────────────────────────
        if pkt.tcp_src_port is not None:
            tcp_sec = section(
                f"Transmission Control Protocol, "
                f"Src Port: {pkt.tcp_src_port}, Dst Port: {pkt.tcp_dst_port}",
                PROTOCOL_TEXT_COLORS.get("TCP", "#60a5fa")
            )
            row(tcp_sec, "Source Port",      pkt.tcp_src_port)
            row(tcp_sec, "Destination Port", pkt.tcp_dst_port)
            row(tcp_sec, "Sequence Number",  pkt.tcp_seq)
            row(tcp_sec, "Acknowledgment",   pkt.tcp_ack)
            row(tcp_sec, "Flags",            pkt.tcp_flags_str or "")
            row(tcp_sec, "Window Size",      pkt.tcp_window)
            row(tcp_sec, "Checksum",         f"0x{pkt.tcp_checksum:04x}" if pkt.tcp_checksum else "N/A")
            self._tree.addTopLevelItem(tcp_sec)

        # ── UDP ───────────────────────────────────────────────────────────────
        if pkt.udp_src_port is not None:
            udp_sec = section(
                f"User Datagram Protocol, "
                f"Src Port: {pkt.udp_src_port}, Dst Port: {pkt.udp_dst_port}",
                PROTOCOL_TEXT_COLORS.get("UDP", "#4ade80")
            )
            row(udp_sec, "Source Port",      pkt.udp_src_port)
            row(udp_sec, "Destination Port", pkt.udp_dst_port)
            row(udp_sec, "Length",           pkt.udp_length)
            row(udp_sec, "Checksum",         f"0x{pkt.udp_checksum:04x}" if pkt.udp_checksum else "N/A")
            self._tree.addTopLevelItem(udp_sec)

        # ── ICMP ──────────────────────────────────────────────────────────────
        if pkt.icmp_type is not None:
            icmp_sec = section(
                f"Internet Control Message Protocol",
                PROTOCOL_TEXT_COLORS.get("ICMP", "#facc15")
            )
            row(icmp_sec, "Type", f"{pkt.icmp_type} ({pkt.info})")
            row(icmp_sec, "Code", pkt.icmp_code)
            if pkt.icmp_id  is not None: row(icmp_sec, "Identifier", f"0x{pkt.icmp_id:04x}")
            if pkt.icmp_seq is not None: row(icmp_sec, "Sequence",   pkt.icmp_seq)
            self._tree.addTopLevelItem(icmp_sec)

        # ── DNS ───────────────────────────────────────────────────────────────
        if pkt.dns_query_name:
            dns_sec = section(
                f"Domain Name System ({'Response' if pkt.dns_is_response else 'Query'})",
                PROTOCOL_TEXT_COLORS.get("DNS", "#c084fc")
            )
            row(dns_sec, "Transaction ID", f"0x{pkt.dns_id:04x}" if pkt.dns_id else "?")
            row(dns_sec, "Type",           "Response" if pkt.dns_is_response else "Query")
            row(dns_sec, "Query Name",     pkt.dns_query_name)
            row(dns_sec, "Query Type",     pkt.dns_query_type or "A")
            if pkt.dns_answers:
                ans_parent = QTreeWidgetItem([f"Answers ({len(pkt.dns_answers)})"])
                ans_parent.setForeground(0, QBrush(QColor("#94a3b8")))
                for ans in pkt.dns_answers:
                    row(ans_parent, ans["type"], f"{ans['name']} → {ans['value']} (TTL {ans['ttl']})")
                dns_sec.addChild(ans_parent)
            self._tree.addTopLevelItem(dns_sec)

        # ── ARP ───────────────────────────────────────────────────────────────
        if pkt.arp_op:
            arp_sec = section("Address Resolution Protocol", PROTOCOL_TEXT_COLORS.get("ARP", "#f87171"))
            row(arp_sec, "Operation",   pkt.arp_op)
            row(arp_sec, "Sender MAC",  pkt.arp_sender_mac)
            row(arp_sec, "Sender IP",   pkt.arp_sender_ip)
            row(arp_sec, "Target IP",   pkt.arp_target_ip)
            self._tree.addTopLevelItem(arp_sec)

        # ── HTTP ──────────────────────────────────────────────────────────────
        if pkt.http_method or pkt.http_status:
            http_sec = section("Hypertext Transfer Protocol", PROTOCOL_TEXT_COLORS.get("HTTP", "#a5b4fc"))
            if pkt.http_method:
                row(http_sec, "Method",  pkt.http_method)
                row(http_sec, "URI",     pkt.http_uri or "/")
                row(http_sec, "Version", pkt.http_version or "HTTP/1.1")
                if pkt.http_host:
                    row(http_sec, "Host", pkt.http_host)
            if pkt.http_status:
                row(http_sec, "Status", pkt.http_status)
            self._tree.addTopLevelItem(http_sec)

    # ── Hex dump builder ──────────────────────────────────────────────────────

    def _build_hex(self, pkt: ParsedPacket):
        self._hex.clear()
        if not pkt.raw_bytes:
            self._hex.setText("No raw data available")
            return

        lines = []
        for offset, hex_part, ascii_part in hex_dump_rows(pkt.raw_bytes):
            lines.append(f"{offset}  {hex_part:<48}  {ascii_part}")

        self._hex.setPlainText("\n".join(lines))

    def _build_raw(self, pkt: ParsedPacket):
        self._raw.clear()
        if not pkt.raw_bytes:
            self._raw.setText("No raw data available")
            return
        hex_str = " ".join(f"{b:02x}" for b in pkt.raw_bytes)
        self._raw.setPlainText(hex_str)
