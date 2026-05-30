"""
Global constants for NETSCOPE
"""

from PyQt5.QtGui import QColor

# ── Protocol colour palette ──────────────────────────────────────────────────
PROTOCOL_COLORS = {
    "TCP":   QColor("#0f2942"),
    "UDP":   QColor("#0a2e1a"),
    "DNS":   QColor("#2d1b4e"),
    "ICMP":  QColor("#2d2000"),
    "HTTP":  QColor("#1a1a2e"),
    "HTTPS": QColor("#0f2d2d"),
    "ARP":   QColor("#2d1414"),
    "TLS":   QColor("#1a2d1a"),
    "DHCP":  QColor("#1a1a1a"),
}

PROTOCOL_TEXT_COLORS = {
    "TCP":   "#60a5fa",
    "UDP":   "#4ade80",
    "DNS":   "#c084fc",
    "ICMP":  "#facc15",
    "HTTP":  "#a5b4fc",
    "HTTPS": "#2dd4bf",
    "ARP":   "#f87171",
    "TLS":   "#86efac",
    "DHCP":  "#94a3b8",
}

PROTOCOL_ACCENT_COLORS = {
    "TCP":   "#2b7fff",
    "UDP":   "#16a34a",
    "DNS":   "#9333ea",
    "ICMP":  "#ca8a04",
    "HTTP":  "#6366f1",
    "HTTPS": "#0d9488",
    "ARP":   "#dc2626",
    "TLS":   "#15803d",
    "DHCP":  "#64748b",
}

# IP protocol numbers → name
IP_PROTOCOLS = {
    1:  "ICMP",
    6:  "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    58: "ICMPv6",
}

# Well-known ports
WELL_KNOWN_PORTS = {
    20:   "FTP-DATA",
    21:   "FTP",
    22:   "SSH",
    23:   "TELNET",
    25:   "SMTP",
    53:   "DNS",
    67:   "DHCP",
    68:   "DHCP",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
    27017:"MongoDB",
}

# Table column config
TABLE_COLUMNS = ["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"]
TABLE_WIDTHS  = [60,     90,     140,      140,           80,         60,       400]

# Max packets to keep in memory
MAX_PACKETS = 5000

# Capture buffer size (bytes)
CAPTURE_BUFFER = 65535
