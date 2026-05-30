"""
StatisticsPanel — sidebar panel showing live traffic stats:
  • 4 metric cards (total pkts, pps, kbps, dropped)
  • Protocol distribution bars
  • PPS sparkline
  • Top talkers list
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QFrame, QProgressBar, QSizePolicy, QScrollArea
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QColor, QFont, QPainter, QPen, QBrush, QPolygonF
from PyQt5.QtCore import QPointF

from src.capture.statistics import TrafficStatistics
from src.utils.constants import PROTOCOL_TEXT_COLORS, PROTOCOL_ACCENT_COLORS
from src.utils.helpers import format_bytes

MONO = QFont("JetBrains Mono", 10)
MONO.setStyleHint(QFont.Monospace)
SMALL = QFont("JetBrains Mono", 9)
SMALL.setStyleHint(QFont.Monospace)


# ── Sparkline widget ──────────────────────────────────────────────────────────

class SparklineWidget(QWidget):
    def __init__(self, color="#2b7fff", parent=None):
        super().__init__(parent)
        self._data = []
        self._color = QColor(color)
        self.setFixedHeight(40)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

    def set_data(self, data: list):
        self._data = data[-80:]
        self.update()

    def paintEvent(self, event):
        if len(self._data) < 2:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        w, h = self.width(), self.height()
        mx = max(self._data) or 1
        n  = len(self._data)

        pts = [
            QPointF((i / (n - 1)) * w, h - (v / mx) * (h - 4))
            for i, v in enumerate(self._data)
        ]

        # Fill
        fill_color = QColor(self._color)
        fill_color.setAlpha(30)
        fill_pts = [QPointF(0, h)] + pts + [QPointF(w, h)]
        painter.setPen(Qt.NoPen)
        painter.setBrush(QBrush(fill_color))
        painter.drawPolygon(QPolygonF(fill_pts))

        # Line
        painter.setPen(QPen(self._color, 1.5, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
        painter.setBrush(Qt.NoBrush)
        for i in range(len(pts) - 1):
            painter.drawLine(pts[i], pts[i + 1])


# ── Metric card ───────────────────────────────────────────────────────────────

class MetricCard(QFrame):
    def __init__(self, label: str, color: str, parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.NoFrame)
        self.setStyleSheet(f"""
            QFrame {{
                background: #0d1117;
                border: 1px solid #1e2740;
                border-radius: 4px;
            }}
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(4)

        self._label = QLabel(label)
        self._label.setFont(SMALL)
        self._label.setStyleSheet("color: #475569; border: none; background: transparent;")
        layout.addWidget(self._label)

        self._value = QLabel("0")
        self._value.setFont(QFont("JetBrains Mono", 18))
        self._value.setStyleSheet(f"color: {color}; font-weight: bold; border: none; background: transparent;")
        layout.addWidget(self._value)

    def set_value(self, v):
        self._value.setText(str(v))


# ── Proto bar row ─────────────────────────────────────────────────────────────

class ProtoBarRow(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)
        self._name_label  = QLabel()
        self._name_label.setFont(SMALL)
        self._count_label = QLabel()
        self._count_label.setFont(SMALL)
        self._count_label.setStyleSheet("color: #475569;")
        self._bar = QProgressBar()
        self._bar.setFixedHeight(3)
        self._bar.setTextVisible(False)
        self._bar.setRange(0, 100)

        hl = QHBoxLayout()
        hl.setContentsMargins(0, 0, 0, 0)
        hl.addWidget(self._name_label)
        hl.addStretch()
        hl.addWidget(self._count_label)
        layout.addLayout(hl)
        layout.addWidget(self._bar)

    def update_row(self, proto: str, count: int, pct: int):
        color = PROTOCOL_TEXT_COLORS.get(proto, "#94a3b8")
        accent = PROTOCOL_ACCENT_COLORS.get(proto, "#374151")
        self._name_label.setText(proto)
        self._name_label.setStyleSheet(f"color: {color};")
        self._count_label.setText(f"{count} ({pct}%)")
        self._bar.setValue(pct)
        self._bar.setStyleSheet(f"""
            QProgressBar {{ background: #0f1520; border: none; border-radius: 1px; }}
            QProgressBar::chunk {{ background: {accent}; border-radius: 1px; }}
        """)


# ── Main statistics panel ─────────────────────────────────────────────────────

class StatisticsPanel(QWidget):
    def __init__(self, stats: TrafficStatistics, parent=None):
        super().__init__(parent)
        self._stats = stats
        self._proto_rows: dict[str, ProtoBarRow] = {}
        self._build_ui()

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._timer.start(500)

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── Metric cards ──────────────────────────────────────────────────────
        cards_w = QWidget()
        cards_w.setStyleSheet("background: #0a0e1a;")
        cards_l = QHBoxLayout(cards_w)
        cards_l.setContentsMargins(8, 8, 8, 8)
        cards_l.setSpacing(6)

        self._card_total = MetricCard("PACKETS", "#60a5fa")
        self._card_pps   = MetricCard("PKT/S",   "#4ade80")
        cards_l.addWidget(self._card_total)
        cards_l.addWidget(self._card_pps)
        layout.addWidget(cards_w)

        cards_w2 = QWidget()
        cards_w2.setStyleSheet("background: #0a0e1a;")
        cards_l2 = QHBoxLayout(cards_w2)
        cards_l2.setContentsMargins(8, 0, 8, 8)
        cards_l2.setSpacing(6)
        self._card_kbps  = MetricCard("KBPS",    "#c084fc")
        self._card_bytes = MetricCard("BYTES",   "#2dd4bf")
        cards_l2.addWidget(self._card_kbps)
        cards_l2.addWidget(self._card_bytes)
        layout.addWidget(cards_w2)

        # ── Sparkline ─────────────────────────────────────────────────────────
        sep1 = QFrame(); sep1.setFrameShape(QFrame.HLine)
        sep1.setStyleSheet("color: #1e2740; background: #1e2740; border: none; max-height: 1px;")
        layout.addWidget(sep1)

        spark_w = QWidget()
        spark_w.setStyleSheet("background: #0a0e1a;")
        spark_l = QVBoxLayout(spark_w)
        spark_l.setContentsMargins(10, 8, 10, 8)
        spark_l.setSpacing(4)

        lbl = QLabel("TRAFFIC  (pkts/sec)")
        lbl.setFont(SMALL)
        lbl.setStyleSheet("color: #475569; letter-spacing: 1px;")
        spark_l.addWidget(lbl)

        self._spark = SparklineWidget("#2b7fff")
        spark_l.addWidget(self._spark)
        layout.addWidget(spark_w)

        # ── Protocol bars ─────────────────────────────────────────────────────
        sep2 = QFrame(); sep2.setFrameShape(QFrame.HLine)
        sep2.setStyleSheet("color: #1e2740; background: #1e2740; border: none; max-height: 1px;")
        layout.addWidget(sep2)

        proto_w = QWidget()
        proto_w.setStyleSheet("background: #0a0e1a;")
        proto_l = QVBoxLayout(proto_w)
        proto_l.setContentsMargins(10, 8, 10, 8)
        proto_l.setSpacing(6)

        lbl2 = QLabel("PROTOCOL DISTRIBUTION")
        lbl2.setFont(SMALL)
        lbl2.setStyleSheet("color: #475569; letter-spacing: 1px;")
        proto_l.addWidget(lbl2)

        self._proto_container = proto_l
        layout.addWidget(proto_w)

        # ── Top Talkers ───────────────────────────────────────────────────────
        sep3 = QFrame(); sep3.setFrameShape(QFrame.HLine)
        sep3.setStyleSheet("color: #1e2740; background: #1e2740; border: none; max-height: 1px;")
        layout.addWidget(sep3)

        talker_w = QWidget()
        talker_w.setStyleSheet("background: #0a0e1a;")
        talker_l = QVBoxLayout(talker_w)
        talker_l.setContentsMargins(10, 8, 10, 8)
        talker_l.setSpacing(4)

        lbl3 = QLabel("TOP TALKERS")
        lbl3.setFont(SMALL)
        lbl3.setStyleSheet("color: #475569; letter-spacing: 1px;")
        talker_l.addWidget(lbl3)

        self._talkers_container = talker_l
        layout.addWidget(talker_w)

        layout.addStretch()

    def _refresh(self):
        st = self._stats

        self._card_total.set_value(f"{st.total_packets:,}")
        self._card_pps.set_value(f"{st.packets_per_second:.0f}")
        self._card_kbps.set_value(f"{st.bits_per_second/1024:.1f}")
        self._card_bytes.set_value(format_bytes(st.total_bytes))

        self._spark.set_data(st.time_series_pps)

        # Protocol bars
        top = st.top_protocols
        total = st.total_packets or 1
        for proto, count in top:
            pct = int((count / total) * 100)
            if proto not in self._proto_rows:
                row_w = ProtoBarRow()
                self._proto_rows[proto] = row_w
                self._proto_container.addWidget(row_w)
            self._proto_rows[proto].update_row(proto, count, pct)

        # Top talkers
        # Clear and rebuild (simple approach)
        while self._talkers_container.count() > 1:
            item = self._talkers_container.takeAt(1)
            if item.widget():
                item.widget().deleteLater()

        for ip, cnt in st.top_talkers[:6]:
            pct = int((cnt / total) * 100)
            row_l = QHBoxLayout()
            row_l.setContentsMargins(0, 0, 0, 0)
            ip_lbl = QLabel(ip)
            ip_lbl.setFont(SMALL)
            ip_lbl.setStyleSheet("color: #60a5fa;")
            cnt_lbl = QLabel(f"{cnt} ({pct}%)")
            cnt_lbl.setFont(SMALL)
            cnt_lbl.setStyleSheet("color: #475569;")
            cnt_lbl.setAlignment(Qt.AlignRight)
            row_l.addWidget(ip_lbl)
            row_l.addStretch()
            row_l.addWidget(cnt_lbl)
            row_w = QWidget()
            row_w.setStyleSheet("background: transparent;")
            row_w.setLayout(row_l)
            self._talkers_container.addWidget(row_w)

    def reset(self):
        self._proto_rows.clear()
        while self._proto_container.count() > 1:
            item = self._proto_container.takeAt(1)
            if item.widget():
                item.widget().deleteLater()
        while self._talkers_container.count() > 1:
            item = self._talkers_container.takeAt(1)
            if item.widget():
                item.widget().deleteLater()
