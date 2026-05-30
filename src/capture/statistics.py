"""
TrafficStatistics — collects and computes live network stats.
Thread-safe (all mutations happen on Qt main thread via signals).
"""

import time
from collections import defaultdict, deque
from typing import Dict, List, Tuple
from src.parse.parsed_packet import ParsedPacket


class TrafficStatistics:

    def __init__(self, window_secs: int = 60):
        self._window = window_secs
        self.reset()

    def reset(self):
        self.total_packets:   int = 0
        self.total_bytes:     int = 0
        self.proto_counts:    Dict[str, int] = defaultdict(int)
        self.ip_src_counts:   Dict[str, int] = defaultdict(int)
        self.ip_dst_counts:   Dict[str, int] = defaultdict(int)
        self.port_counts:     Dict[int, int]  = defaultdict(int)
        self._time_series:    deque = deque()   # (timestamp, pkt_count, byte_count)
        self._bucket_start:   float = time.time()
        self._bucket_pkts:    int = 0
        self._bucket_bytes:   int = 0

    def update(self, pkt: ParsedPacket):
        """Update stats with a new packet. Call from GUI thread only."""
        self.total_packets += 1
        self.total_bytes   += pkt.length
        self.proto_counts[pkt.protocol] += 1

        if pkt.ip_src: self.ip_src_counts[pkt.ip_src] += 1
        if pkt.ip_dst: self.ip_dst_counts[pkt.ip_dst] += 1

        for port in (pkt.src_port, pkt.dst_port):
            if port: self.port_counts[port] += 1

        # Rolling 1-second bucket
        now = time.time()
        self._bucket_pkts  += 1
        self._bucket_bytes += pkt.length
        if now - self._bucket_start >= 1.0:
            self._time_series.append((
                self._bucket_start,
                self._bucket_pkts,
                self._bucket_bytes,
            ))
            # Trim old buckets
            cutoff = now - self._window
            while self._time_series and self._time_series[0][0] < cutoff:
                self._time_series.popleft()
            self._bucket_start = now
            self._bucket_pkts  = 0
            self._bucket_bytes = 0

    # ── Derived metrics ───────────────────────────────────────────────────────

    @property
    def packets_per_second(self) -> float:
        recent = [b for b in self._time_series if b[0] >= time.time() - 5]
        if not recent:
            return 0.0
        total = sum(b[1] for b in recent)
        span  = max(len(recent), 1)
        return total / span

    @property
    def bits_per_second(self) -> float:
        recent = [b for b in self._time_series if b[0] >= time.time() - 5]
        if not recent:
            return 0.0
        total = sum(b[2] for b in recent) * 8
        span  = max(len(recent), 1)
        return total / span

    @property
    def top_protocols(self) -> List[Tuple[str, int]]:
        return sorted(self.proto_counts.items(), key=lambda x: x[1], reverse=True)[:8]

    @property
    def top_talkers(self) -> List[Tuple[str, int]]:
        """Top 10 source IPs by packet count."""
        return sorted(self.ip_src_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    @property
    def top_ports(self) -> List[Tuple[int, int]]:
        return sorted(self.port_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    @property
    def time_series_pps(self) -> List[int]:
        """Packets-per-second list for sparkline chart."""
        return [b[1] for b in self._time_series]

    @property
    def time_series_bps(self) -> List[float]:
        """Bits-per-second list for sparkline chart."""
        return [b[2] * 8 / 1024 for b in self._time_series]  # kbps

    def proto_percentage(self, proto: str) -> float:
        if self.total_packets == 0:
            return 0.0
        return (self.proto_counts.get(proto, 0) / self.total_packets) * 100
