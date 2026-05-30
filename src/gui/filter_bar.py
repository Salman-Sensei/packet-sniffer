"""
FilterBar — the green filter bar at the top of the packet list,
exactly like Wireshark's display filter bar.
"""

from PyQt5.QtWidgets import (
    QWidget, QHBoxLayout, QLineEdit,
    QPushButton, QLabel, QFrame
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor, QFont

from src.filter.filter_engine import FilterEngine

QUICK_FILTERS = ["tcp", "udp", "dns", "icmp", "http", "https", "arp"]


class FilterBar(QWidget):
    filter_applied = pyqtSignal(str)   # emits valid filter string
    filter_cleared = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._current_filter = ""
        self._build_ui()

    def _build_ui(self):
        self.setStyleSheet("background: #0d1117; border-bottom: 1px solid #1e2740;")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 5, 8, 5)
        layout.setSpacing(6)

        lbl = QLabel("Filter:")
        lbl.setStyleSheet("color: #475569; font-size: 11px; min-width: 36px;")
        layout.addWidget(lbl)

        self._input = QLineEdit()
        self._input.setPlaceholderText(
            'tcp  ·  ip.src == 192.168.1.1  ·  port 443  ·  dns and ip.dst == 8.8.8.8'
        )
        self._input.setStyleSheet("""
            QLineEdit {
                background: #080c14;
                color: #94a3b8;
                border: 1px solid #1e2740;
                border-radius: 4px;
                padding: 4px 8px;
                font-size: 11px;
                font-family: 'JetBrains Mono', monospace;
            }
            QLineEdit:focus { border-color: #2b7fff; color: #e2e8f0; }
        """)
        self._input.returnPressed.connect(self._apply)
        self._input.textChanged.connect(self._validate_live)
        layout.addWidget(self._input, 1)

        self._apply_btn = QPushButton("Apply")
        self._apply_btn.setStyleSheet("""
            QPushButton {
                background: #0f2542;
                color: #60a5fa;
                border: 1px solid #1e3a60;
                border-radius: 4px;
                padding: 4px 12px;
                font-size: 11px;
            }
            QPushButton:hover { background: #1e3a60; }
        """)
        self._apply_btn.clicked.connect(self._apply)
        layout.addWidget(self._apply_btn)

        clear_btn = QPushButton("✕")
        clear_btn.setFixedWidth(28)
        clear_btn.setStyleSheet("""
            QPushButton {
                background: transparent;
                color: #475569;
                border: 1px solid #1e2740;
                border-radius: 4px;
                padding: 4px;
                font-size: 11px;
            }
            QPushButton:hover { color: #f87171; border-color: #7f1d1d; }
        """)
        clear_btn.clicked.connect(self._clear)
        layout.addWidget(clear_btn)

        # Quick filter tags
        for proto in QUICK_FILTERS:
            tag = QPushButton(proto)
            tag.setCheckable(False)
            tag.setFixedHeight(22)
            tag.setStyleSheet(f"""
                QPushButton {{
                    background: #0a0e1a;
                    color: #475569;
                    border: 1px solid #1e2740;
                    border-radius: 10px;
                    padding: 0px 8px;
                    font-size: 10px;
                    font-family: monospace;
                }}
                QPushButton:hover {{
                    color: #94a3b8;
                    border-color: #2d3a5c;
                }}
            """)
            tag.clicked.connect(lambda checked, p=proto: self._quick_set(p))
            layout.addWidget(tag)

    # ── Slots ─────────────────────────────────────────────────────────────────

    def _apply(self):
        expr = self._input.text().strip()
        err = FilterEngine.validate(expr)
        if err:
            self._input.setStyleSheet(self._input.styleSheet().replace(
                "color: #94a3b8", "color: #f87171"
            ))
            return
        self._current_filter = expr
        self._input.setStyleSheet(
            self._input.styleSheet()
                .replace("color: #f87171", "color: #94a3b8")
        )
        if expr:
            self.filter_applied.emit(expr)
        else:
            self.filter_cleared.emit()

    def _clear(self):
        self._input.clear()
        self._current_filter = ""
        self.filter_cleared.emit()

    def _quick_set(self, proto: str):
        self._input.setText(proto)
        self._apply()

    def _validate_live(self, text: str):
        """Show red tint if expression is invalid (non-empty)."""
        if not text.strip():
            self._set_normal_style()
            return
        err = FilterEngine.validate(text)
        if err:
            self._input.setStyleSheet("""
                QLineEdit {
                    background: #2d0a0a;
                    color: #f87171;
                    border: 1px solid #7f1d1d;
                    border-radius: 4px;
                    padding: 4px 8px;
                    font-size: 11px;
                    font-family: 'JetBrains Mono', monospace;
                }
            """)
        else:
            self._set_normal_style()

    def _set_normal_style(self):
        self._input.setStyleSheet("""
            QLineEdit {
                background: #080c14;
                color: #94a3b8;
                border: 1px solid #1e2740;
                border-radius: 4px;
                padding: 4px 8px;
                font-size: 11px;
                font-family: 'JetBrains Mono', monospace;
            }
            QLineEdit:focus { border-color: #2b7fff; color: #e2e8f0; }
        """)

    @property
    def current_filter(self) -> str:
        return self._current_filter
