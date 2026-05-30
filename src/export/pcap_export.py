"""
PCAPExporter / PCAPImporter — save and load .pcap files.
Uses scapy under the hood.
"""

from typing import List, Optional
from src.parse.parsed_packet import ParsedPacket
from src.parse.packet_parser import PacketParser


class PCAPExporter:
    @staticmethod
    def export(packets: List[ParsedPacket], filepath: str) -> bool:
        """
        Save a list of ParsedPackets to a .pcap file.
        Returns True on success, raises on failure.
        """
        try:
            from scapy.all import wrpcap, Raw
            scapy_pkts = []
            for p in packets:
                if p.raw_bytes:
                    scapy_pkts.append(Raw(p.raw_bytes))
            wrpcap(filepath, scapy_pkts)
            return True
        except ImportError:
            raise RuntimeError("scapy not installed — cannot export PCAP")
        except Exception as e:
            raise RuntimeError(f"Export failed: {e}")


class PCAPImporter:
    @staticmethod
    def load(filepath: str) -> List[ParsedPacket]:
        """
        Load packets from a .pcap file.
        Returns list of ParsedPackets.
        """
        try:
            from scapy.all import rdpcap
            raw_packets = rdpcap(filepath)
            parsed = []
            for pkt in raw_packets:
                p = PacketParser.parse(pkt)
                if p:
                    parsed.append(p)
            return parsed
        except ImportError:
            raise RuntimeError("scapy not installed — cannot import PCAP")
        except Exception as e:
            raise RuntimeError(f"Import failed: {e}")
