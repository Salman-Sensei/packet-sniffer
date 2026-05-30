"""
PacketCapture — captures live packets using scapy in a background QThread.
Emits parsed ParsedPacket objects to the GUI via Qt signals.
"""

import sys
from typing import Optional, Callable

from PyQt5.QtCore import QThread, pyqtSignal

from src.parse.packet_parser import PacketParser, reset_timer
from src.parse.parsed_packet import ParsedPacket


class CaptureThread(QThread):
    """
    Background thread that runs scapy sniff().
    Emits packet_captured for each packet.
    Emits error_occurred if something goes wrong.
    """
    packet_captured = pyqtSignal(object)   # ParsedPacket
    error_occurred  = pyqtSignal(str)
    stats_updated   = pyqtSignal(int, int)  # total_count, total_bytes

    def __init__(self, interface: str, bpf_filter: str = "", parent=None):
        super().__init__(parent)
        self.interface  = interface
        self.bpf_filter = bpf_filter
        self._stop_flag = False
        self._total     = 0
        self._bytes     = 0

    def run(self):
        """Thread entry point — runs scapy sniff loop."""
        try:
            from scapy.all import sniff
        except ImportError:
            self.error_occurred.emit(
                "scapy is not installed.\nRun:  pip install scapy"
            )
            return

        reset_timer()
        PacketParser._counter = 0

        def handle(pkt):
            if self._stop_flag:
                return
            try:
                parsed = PacketParser.parse(pkt)
                if parsed:
                    self._total += 1
                    self._bytes += parsed.length
                    self.packet_captured.emit(parsed)
                    if self._total % 50 == 0:
                        self.stats_updated.emit(self._total, self._bytes)
            except Exception as e:
                pass   # never crash the capture thread

        try:
            sniff(
                iface=self.interface if self.interface != "any" else None,
                filter=self.bpf_filter or None,
                prn=handle,
                store=False,
                stop_filter=lambda _: self._stop_flag,
            )
        except PermissionError:
            self.error_occurred.emit(
                "Permission denied — run as root/Administrator:\n"
                "  Linux/Mac:  sudo python main.py\n"
                "  Windows:    Run Terminal as Administrator"
            )
        except Exception as e:
            self.error_occurred.emit(f"Capture error: {e}")

    def stop(self):
        self._stop_flag = True


class PacketCapture:
    """
    High-level manager: creates/destroys CaptureThread,
    exposes start/stop/pause API to the GUI.
    """

    def __init__(self):
        self._thread: Optional[CaptureThread] = None
        self._paused = False
        self._pending_packets = []

    def start(
        self,
        interface: str,
        bpf_filter: str,
        on_packet: Callable,
        on_error:  Callable,
        on_stats:  Callable,
    ):
        self.stop()
        self._paused = False
        self._thread = CaptureThread(interface, bpf_filter)
        self._thread.packet_captured.connect(lambda p: on_packet(p) if not self._paused else None)
        self._thread.error_occurred.connect(on_error)
        self._thread.stats_updated.connect(on_stats)
        self._thread.start()

    def pause(self):
        self._paused = True

    def resume(self):
        self._paused = False

    def stop(self):
        if self._thread and self._thread.isRunning():
            self._thread.stop()
            self._thread.wait(3000)
        self._thread = None
        self._paused = False

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.isRunning()

    @property
    def is_paused(self) -> bool:
        return self._paused

    @staticmethod
    def available_interfaces() -> list:
        """Return list of network interfaces available on this machine."""
        try:
            from scapy.all import get_if_list
            ifaces = get_if_list()
            return ["any"] + [i for i in ifaces if i != "any"]
        except ImportError:
            import socket
            return ["eth0", "wlan0", "lo", "en0", "any"]
        except Exception:
            return ["eth0", "wlan0", "lo", "en0", "any"]
