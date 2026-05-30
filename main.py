#!/usr/bin/env python3
"""
NETSCOPE - Wireshark-like Network Packet Analyzer
Run with:  sudo python main.py   (Linux/Mac)
           python main.py        (Windows - as Administrator)
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPalette, QColor
from src.gui.main_window import PacketSnifferWindow


def apply_dark_theme(app: QApplication):
    app.setStyle("Fusion")
    palette = QPalette()
    palette.setColor(QPalette.Window,          QColor("#0a0e1a"))
    palette.setColor(QPalette.WindowText,      QColor("#e2e8f0"))
    palette.setColor(QPalette.Base,            QColor("#080c14"))
    palette.setColor(QPalette.AlternateBase,   QColor("#0d1117"))
    palette.setColor(QPalette.ToolTipBase,     QColor("#0d1117"))
    palette.setColor(QPalette.ToolTipText,     QColor("#e2e8f0"))
    palette.setColor(QPalette.Text,            QColor("#e2e8f0"))
    palette.setColor(QPalette.Button,          QColor("#0f1520"))
    palette.setColor(QPalette.ButtonText,      QColor("#94a3b8"))
    palette.setColor(QPalette.BrightText,      QColor("#f1f5f9"))
    palette.setColor(QPalette.Link,            QColor("#2b7fff"))
    palette.setColor(QPalette.Highlight,       QColor("#1e3a60"))
    palette.setColor(QPalette.HighlightedText, QColor("#60a5fa"))
    palette.setColor(QPalette.Disabled, QPalette.Text,       QColor("#334155"))
    palette.setColor(QPalette.Disabled, QPalette.ButtonText, QColor("#334155"))
    app.setPalette(palette)
    app.setStyleSheet("""
        QMainWindow, QWidget { background:#0a0e1a; color:#e2e8f0;
            font-family:'JetBrains Mono','Cascadia Code','Fira Code','Consolas',monospace; font-size:12px; }
        QMenuBar { background:#0d1117; color:#64748b; border-bottom:1px solid #1e2740; padding:2px 0; }
        QMenuBar::item:selected { background:#1e2740; color:#94a3b8; }
        QMenu { background:#0d1117; color:#94a3b8; border:1px solid #1e2740; }
        QMenu::item:selected { background:#1e2740; color:#e2e8f0; }
        QToolBar { background:#0f1520; border-bottom:1px solid #1e2740; spacing:4px; padding:4px 8px; }
        QStatusBar { background:#080c14; color:#475569; border-top:1px solid #1e2740; font-size:11px; }
        QSplitter::handle { background:#1e2740; width:1px; height:1px; }
        QScrollBar:vertical { background:transparent; width:6px; }
        QScrollBar::handle:vertical { background:#1e2740; border-radius:3px; min-height:20px; }
        QScrollBar::handle:vertical:hover { background:#2d3a5c; }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height:0px; }
        QScrollBar:horizontal { background:transparent; height:6px; }
        QScrollBar::handle:horizontal { background:#1e2740; border-radius:3px; }
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width:0px; }
        QPushButton { background:#0f1520; color:#94a3b8; border:1px solid #1e2740; border-radius:4px;
            padding:4px 12px; font-family:inherit; font-size:11px; }
        QPushButton:hover { background:#1e2740; color:#e2e8f0; }
        QPushButton:pressed { background:#0d1117; }
        QPushButton:disabled { color:#334155; border-color:#1a2030; }
        QLineEdit { background:#080c14; color:#94a3b8; border:1px solid #1e2740; border-radius:4px;
            padding:4px 8px; font-family:inherit; font-size:11px; selection-background-color:#1e3a60; }
        QLineEdit:focus { border-color:#2b7fff; color:#e2e8f0; }
        QComboBox { background:#0d1117; color:#94a3b8; border:1px solid #1e2740; border-radius:4px;
            padding:4px 8px; font-family:inherit; font-size:11px; }
        QComboBox::drop-down { border:none; width:16px; }
        QComboBox QAbstractItemView { background:#0d1117; color:#94a3b8; border:1px solid #1e2740;
            selection-background-color:#1e2740; }
        QTableView { background:#0a0e1a; color:#94a3b8; gridline-color:#0d1117; border:none;
            selection-background-color:#1e2740; }
        QTableView::item { padding:2px 4px; border-bottom:1px solid #0d1117; }
        QHeaderView::section { background:#080c14; color:#475569; border:none; border-right:1px solid #1e2740;
            border-bottom:1px solid #1e2740; padding:5px 6px; font-size:10px; font-weight:bold; }
        QTreeWidget { background:#080c14; color:#94a3b8; border:none; }
        QTreeWidget::item:hover { background:#0d1117; }
        QTreeWidget::item:selected { background:#1e2740; color:#e2e8f0; }
        QTabWidget::pane { border:none; background:#080c14; }
        QTabBar::tab { background:#080c14; color:#475569; border:none; border-bottom:2px solid transparent;
            padding:6px 14px; font-size:10px; letter-spacing:0.07em; }
        QTabBar::tab:selected { color:#60a5fa; border-bottom:2px solid #2b7fff; }
        QTabBar::tab:hover { color:#94a3b8; background:#0d1117; }
        QGroupBox { color:#475569; border:1px solid #1e2740; border-radius:4px; margin-top:8px;
            padding-top:8px; font-size:10px; }
        QGroupBox::title { color:#475569; subcontrol-origin:margin; left:8px; }
        QLabel { color:#94a3b8; }
        QTextEdit { background:#080c14; color:#94a3b8; border:none;
            font-family:'JetBrains Mono',monospace; font-size:11px; selection-background-color:#1e2740; }
        QProgressBar { background:#0f1520; border:none; border-radius:2px; height:4px; }
        QProgressBar::chunk { background:#2b7fff; border-radius:2px; }
        QToolTip { background:#0d1117; color:#e2e8f0; border:1px solid #1e2740; padding:4px 8px; font-size:11px; }
    """)


def main():
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    app = QApplication(sys.argv)
    app.setApplicationName("NETSCOPE")
    app.setApplicationVersion("2.4.1")
    app.setOrganizationName("Salman-Sensei")
    apply_dark_theme(app)
    window = PacketSnifferWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
