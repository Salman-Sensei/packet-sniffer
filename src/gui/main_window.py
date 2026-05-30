"""
PacketSnifferWindow — the main application window.
Orchestrates capture, filter, table, details, and stats panel.
"""

import os
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QSplitter, QToolBar, QPushButton, QComboBox,
    QLabel, QStatusBar, QMessageBox, QFileDialog,
    QAction, QFrame, QSizePolicy
)
from PyQt5.QtCore import Qt, QTimer, pyqtSlot
from PyQt5.QtGui import QFont, QColor, QIcon

from src.capture.packet_capture import PacketCapture
from src.capture.statistics import TrafficStatistics
from src.filter.filter_engine import FilterEngine
from src.parse.parsed_packet import ParsedPacket
from src.export.pcap_export import PCAPExporter, PCAPImporter
from src.gui.packet_table import PacketTableView
from src.gui.packet_details import PacketDetailsPane
from src.gui.statistics_panel import StatisticsPanel
from src.gui.filter_bar import FilterBar
from src.utils.constants import MAX_PACKETS


class PacketSnifferWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self._capture  = PacketCapture()
        self._stats    = TrafficStatistics()
        self._filter   = FilterEngine()
        self._auto_scroll = True
        self._dropped  = 0

        self.setWindowTitle("NETSCOPE (Mini Wireshark)")
        self.setMinimumSize(1200, 750)
        self.resize(1440, 860)

        self._build_menu()
        self._build_toolbar()
        self._build_central()
        self._build_status_bar()

        # Periodic status-bar refresh
        self._status_timer = QTimer(self)
        self._status_timer.timeout.connect(self._refresh_statusbar)
        self._status_timer.start(500)

    # ══════════════════════════════════════════════════════════════════════════
    # UI construction
    # ══════════════════════════════════════════════════════════════════════════

    def _build_menu(self):
        mb = self.menuBar()

        # File
        file_menu = mb.addMenu("File")
        self._act_open  = file_menu.addAction("Open PCAP…")
        self._act_save  = file_menu.addAction("Save As PCAP…")
        file_menu.addSeparator()
        file_menu.addAction("Exit").triggered.connect(self.close)
        self._act_open.triggered.connect(self._open_pcap)
        self._act_save.triggered.connect(self._save_pcap)

        # Edit
        edit_menu = mb.addMenu("Edit")
        edit_menu.addAction("Find Packet…").triggered.connect(self._find_placeholder)
        edit_menu.addAction("Mark All Displayed").triggered.connect(lambda: None)

        # View
        view_menu = mb.addMenu("View")
        self._act_autoscroll = view_menu.addAction("Auto Scroll")
        self._act_autoscroll.setCheckable(True)
        self._act_autoscroll.setChecked(True)
        self._act_autoscroll.toggled.connect(lambda v: setattr(self, "_auto_scroll", v))
        view_menu.addAction("Clear Packets").triggered.connect(self._clear_packets)

        # Capture
        capture_menu = mb.addMenu("Capture")
        capture_menu.addAction("Start  (F5)").triggered.connect(self._start_capture)
        capture_menu.addAction("Pause").triggered.connect(self._pause_capture)
        capture_menu.addAction("Stop   (F6)").triggered.connect(self._stop_capture)
        capture_menu.addAction("Restart").triggered.connect(self._restart_capture)

        # Help
        help_menu = mb.addMenu("Help")
        help_menu.addAction("About NETSCOPE").triggered.connect(self._about)

    def _build_toolbar(self):
        tb = QToolBar("Main")
        tb.setMovable(False)
        tb.setFloatable(False)
        self.addToolBar(tb)

        # Start button
        self._btn_start = QPushButton("▶  Start")
        self._btn_start.setStyleSheet("""
            QPushButton {
                background: #052e16; color: #22c55e;
                border: 1px solid #16653440;
                border-radius: 4px; padding: 4px 14px; font-size: 11px;
            }
            QPushButton:hover { background: #0a4a22; }
            QPushButton:disabled { color: #334155; background: #0a0e1a; border-color: #1e2740; }
        """)
        self._btn_start.clicked.connect(self._start_capture)
        tb.addWidget(self._btn_start)

        # Pause
        self._btn_pause = QPushButton("⏸  Pause")
        self._btn_pause.setEnabled(False)
        self._btn_pause.setStyleSheet("""
            QPushButton {
                background: #451a03; color: #f59e0b;
                border: 1px solid #92400e40;
                border-radius: 4px; padding: 4px 14px; font-size: 11px;
            }
            QPushButton:hover { background: #6b2800; }
            QPushButton:disabled { color: #334155; background: #0a0e1a; border-color: #1e2740; }
        """)
        self._btn_pause.clicked.connect(self._pause_capture)
        tb.addWidget(self._btn_pause)

        # Stop
        self._btn_stop = QPushButton("⏹  Stop")
        self._btn_stop.setEnabled(False)
        self._btn_stop.setStyleSheet("""
            QPushButton {
                background: #2d0a0a; color: #f87171;
                border: 1px solid #7f1d1d40;
                border-radius: 4px; padding: 4px 14px; font-size: 11px;
            }
            QPushButton:hover { background: #450f0f; }
            QPushButton:disabled { color: #334155; background: #0a0e1a; border-color: #1e2740; }
        """)
        self._btn_stop.clicked.connect(self._stop_capture)
        tb.addWidget(self._btn_stop)

        tb.addSeparator()

        # Interface selector
        iface_lbl = QLabel("  Interface: ")
        iface_lbl.setStyleSheet("color: #475569; font-size: 11px;")
        tb.addWidget(iface_lbl)

        self._iface_combo = QComboBox()
        self._iface_combo.setFixedWidth(130)
        for iface in PacketCapture.available_interfaces():
            self._iface_combo.addItem(iface)
        tb.addWidget(self._iface_combo)

        tb.addSeparator()

        # BPF filter label
        bpf_lbl = QLabel("  Capture Filter: ")
        bpf_lbl.setStyleSheet("color: #475569; font-size: 11px;")
        from PyQt5.QtWidgets import QLineEdit
        self._bpf_input = QLineEdit()
        self._bpf_input.setPlaceholderText("tcp or udp or icmp")
        self._bpf_input.setFixedWidth(200)
        tb.addWidget(bpf_lbl)
        tb.addWidget(self._bpf_input)

        tb.addSeparator()

        # Live indicator
        self._live_dot = QLabel("●")
        self._live_dot.setStyleSheet("color: #334155; font-size: 14px; padding: 0 8px;")
        tb.addWidget(self._live_dot)
        self._live_label = QLabel("IDLE")
        self._live_label.setStyleSheet("color: #334155; font-size: 11px; letter-spacing: 1px;")
        tb.addWidget(self._live_label)

    def _build_central(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ── Filter bar (full width) ───────────────────────────────────────────
        self._filter_bar = FilterBar()
        self._filter_bar.filter_applied.connect(self._on_filter_applied)
        self._filter_bar.filter_cleared.connect(self._on_filter_cleared)
        main_layout.addWidget(self._filter_bar)

        # ── Horizontal splitter: [table+details | stats] ──────────────────────
        outer_splitter = QSplitter(Qt.Horizontal)
        outer_splitter.setChildrenCollapsible(False)

        # Left side: vertical splitter [table | details]
        left_splitter = QSplitter(Qt.Vertical)
        left_splitter.setChildrenCollapsible(False)

        self._packet_table = PacketTableView()
        self._packet_table.packet_selected.connect(self._on_packet_selected)
        self._packet_table.setMinimumHeight(200)
        left_splitter.addWidget(self._packet_table)

        self._details_pane = PacketDetailsPane()
        self._details_pane.setMinimumHeight(150)
        left_splitter.addWidget(self._details_pane)

        # Use stretch factors: table gets 65%, details gets 35%
        left_splitter.setStretchFactor(0, 65)
        left_splitter.setStretchFactor(1, 35)

        outer_splitter.addWidget(left_splitter)

        # Right side: stats panel in a scroll area
        from PyQt5.QtWidgets import QScrollArea
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea { border: none; border-left: 1px solid #1e2740; }")

        self._stats_panel = StatisticsPanel(self._stats)
        scroll.setWidget(self._stats_panel)
        scroll.setFixedWidth(280)
        outer_splitter.addWidget(scroll)

        # Outer splitter: left side expands, right side fixed
        outer_splitter.setStretchFactor(0, 1)
        outer_splitter.setStretchFactor(1, 0)

        main_layout.addWidget(outer_splitter, 1)  # stretch=1 so it fills remaining space

    def _build_status_bar(self):
        sb = self.statusBar()

        self._sb_packets  = QLabel("Packets: 0")
        self._sb_shown    = QLabel("Shown: 0")
        self._sb_dropped  = QLabel("Dropped: 0")
        self._sb_iface    = QLabel("Interface: —")
        self._sb_filter   = QLabel("Filter: none")
        self._sb_pps      = QLabel("PPS: 0")

        for lbl in (self._sb_packets, self._sb_shown, self._sb_pps,
                    self._sb_dropped, self._sb_filter, self._sb_iface):
            lbl.setStyleSheet("padding: 0 10px; color: #475569; font-size: 11px;")
            sb.addWidget(lbl)

        sb.addPermanentWidget(QLabel("NETSCOPE v2.4.1  "))

    # ══════════════════════════════════════════════════════════════════════════
    # Capture control
    # ══════════════════════════════════════════════════════════════════════════

    def _start_capture(self):
        if self._capture.is_running:
            if self._capture.is_paused:
                self._capture.resume()
                self._set_live_state(True)
                self._btn_pause.setText("⏸  Pause")
            return

        iface = self._iface_combo.currentText()
        bpf   = self._bpf_input.text().strip()
        self._capture.start(
            interface = iface,
            bpf_filter = bpf,
            on_packet  = self._on_packet_received,
            on_error   = self._on_capture_error,
            on_stats   = self._on_stats_update,
        )
        self._set_live_state(True)
        self._sb_iface.setText(f"Interface: {iface}")

    def _pause_capture(self):
        if self._capture.is_running and not self._capture.is_paused:
            self._capture.pause()
            self._btn_pause.setText("▶  Resume")
            self._set_live_state(False, label="PAUSED")
        elif self._capture.is_paused:
            self._capture.resume()
            self._btn_pause.setText("⏸  Pause")
            self._set_live_state(True)

    def _stop_capture(self):
        self._capture.stop()
        self._set_live_state(False)
        self._btn_pause.setText("⏸  Pause")

    def _restart_capture(self):
        self._stop_capture()
        self._clear_packets()
        self._start_capture()

    def _set_live_state(self, live: bool, label: str = ""):
        if live:
            self._live_dot.setStyleSheet("color: #22c55e; font-size: 14px; padding: 0 8px;")
            self._live_label.setStyleSheet("color: #22c55e; font-size: 11px; letter-spacing: 1px;")
            self._live_label.setText("LIVE")
        else:
            col = "#f59e0b" if label == "PAUSED" else "#334155"
            txt = label or "IDLE"
            self._live_dot.setStyleSheet(f"color: {col}; font-size: 14px; padding: 0 8px;")
            self._live_label.setStyleSheet(f"color: {col}; font-size: 11px; letter-spacing: 1px;")
            self._live_label.setText(txt)

        self._btn_start.setEnabled(not live or self._capture.is_paused)
        self._btn_pause.setEnabled(live)
        self._btn_stop.setEnabled(live)

    # ══════════════════════════════════════════════════════════════════════════
    # Packet slots
    # ══════════════════════════════════════════════════════════════════════════

    @pyqtSlot(object)
    def _on_packet_received(self, pkt: ParsedPacket):
        # Enforce memory limit
        if self._packet_table.total_count >= MAX_PACKETS:
            self._dropped += 1
            return

        self._stats.update(pkt)
        visible = self._filter.matches(pkt)
        self._packet_table.append_packet(pkt, visible)

        if self._auto_scroll and visible:
            self._packet_table.scroll_to_bottom()

    @pyqtSlot(int, int)
    def _on_stats_update(self, total, total_bytes):
        pass   # stats panel refreshes itself via timer

    @pyqtSlot(object)
    def _on_packet_selected(self, pkt: ParsedPacket):
        self._details_pane.show_packet(pkt)

    @pyqtSlot(str)
    def _on_capture_error(self, msg: str):
        self._stop_capture()
        QMessageBox.critical(self, "Capture Error", msg)

    # ══════════════════════════════════════════════════════════════════════════
    # Filter slots
    # ══════════════════════════════════════════════════════════════════════════

    @pyqtSlot(str)
    def _on_filter_applied(self, expr: str):
        self._filter = FilterEngine(expr)
        self._packet_table.apply_filter(self._filter.matches)
        self._sb_filter.setText(f"Filter: {expr[:40]}")

    @pyqtSlot()
    def _on_filter_cleared(self):
        self._filter = FilterEngine()
        self._packet_table.apply_filter(lambda _: True)
        self._sb_filter.setText("Filter: none")

    # ══════════════════════════════════════════════════════════════════════════
    # Status bar refresh
    # ══════════════════════════════════════════════════════════════════════════

    def _refresh_statusbar(self):
        self._sb_packets.setText(f"Packets: {self._packet_table.total_count:,}")
        self._sb_shown.setText(f"Shown: {self._packet_table.visible_count:,}")
        self._sb_dropped.setText(f"Dropped: {self._dropped:,}")
        self._sb_pps.setText(f"PPS: {self._stats.packets_per_second:.0f}")

    # ══════════════════════════════════════════════════════════════════════════
    # PCAP export/import
    # ══════════════════════════════════════════════════════════════════════════

    def _save_pcap(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Capture", "capture.pcap", "PCAP Files (*.pcap);;All Files (*)"
        )
        if not path:
            return
        try:
            packets = self._packet_table.get_all_packets()
            PCAPExporter.export(packets, path)
            self.statusBar().showMessage(f"Saved {len(packets)} packets to {path}", 4000)
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    def _open_pcap(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open PCAP", "", "PCAP Files (*.pcap *.pcapng);;All Files (*)"
        )
        if not path:
            return
        try:
            self._clear_packets()
            packets = PCAPImporter.load(path)
            for pkt in packets:
                self._stats.update(pkt)
                visible = self._filter.matches(pkt)
                self._packet_table.append_packet(pkt, visible)
            self.statusBar().showMessage(f"Loaded {len(packets)} packets from {path}", 4000)
        except Exception as e:
            QMessageBox.critical(self, "Import Error", str(e))

    # ══════════════════════════════════════════════════════════════════════════
    # Misc
    # ══════════════════════════════════════════════════════════════════════════

    def _clear_packets(self):
        self._packet_table.clear()
        self._details_pane.clear()
        self._stats.reset()
        self._stats_panel.reset()
        self._dropped = 0

    def _find_placeholder(self):
        QMessageBox.information(self, "Find", "Packet search coming in v2.5 — use the filter bar for now.")

    def _about(self):
        QMessageBox.about(self, "About NETSCOPE",
            "<b>NETSCOPE v2.4.1</b><br>"
            "Wireshark-inspired Network Packet Analyzer<br><br>"
            "Built with Python + PyQt5 + scapy<br>"
            "© Salman-Sensei"
        )

    def closeEvent(self, event):
        self._capture.stop()
        event.accept()

    # Keyboard shortcuts
    def keyPressEvent(self, event):
        from PyQt5.QtCore import Qt
        if event.key() == Qt.Key_F5:
            self._start_capture()
        elif event.key() == Qt.Key_F6:
            self._stop_capture()
        elif event.key() == Qt.Key_Space:
            self._pause_capture()
        super().keyPressEvent(event)