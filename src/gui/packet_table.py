"""
PacketTableModel — Qt table model that holds the list of ParsedPackets.
PacketTableView  — styled QTableView that uses the model.
"""

from PyQt5.QtCore import (
    Qt, QAbstractTableModel, QModelIndex, QVariant, pyqtSignal
)
from PyQt5.QtWidgets import QTableView, QHeaderView, QAbstractItemView
from PyQt5.QtGui import QColor, QFont, QBrush

from src.parse.parsed_packet import ParsedPacket
from src.utils.constants import (
    TABLE_COLUMNS, TABLE_WIDTHS,
    PROTOCOL_COLORS, PROTOCOL_TEXT_COLORS
)

MONO = QFont("JetBrains Mono", 11)
MONO.setStyleHint(QFont.Monospace)


class PacketTableModel(QAbstractTableModel):
    """Holds all captured packets. Supports filtering via a separate list."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._all_packets: list[ParsedPacket] = []
        self._visible:     list[ParsedPacket] = []

    # ── Qt interface ──────────────────────────────────────────────────────────

    def rowCount(self, parent=QModelIndex()) -> int:
        return len(self._visible)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(TABLE_COLUMNS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return TABLE_COLUMNS[section]
        if role == Qt.TextAlignmentRole:
            return Qt.AlignLeft | Qt.AlignVCenter
        return QVariant()

    def data(self, index: QModelIndex, role=Qt.DisplayRole):
        if not index.isValid():
            return QVariant()

        pkt = self._visible[index.row()]
        col = index.column()

        if role == Qt.DisplayRole:
            return self._cell_text(pkt, col)

        if role == Qt.ForegroundRole:
            text_color = PROTOCOL_TEXT_COLORS.get(pkt.protocol, "#94a3b8")
            if col in (2, 3):   # src/dst IPs stand out slightly
                return QBrush(QColor("#cbd5e1"))
            if col == 4:        # protocol badge color
                return QBrush(QColor(text_color))
            return QBrush(QColor("#64748b"))

        if role == Qt.BackgroundRole:
            return QBrush(QColor("#0a0e1a"))

        if role == Qt.FontRole:
            return MONO

        if role == Qt.TextAlignmentRole:
            if col == 5:   # length — right-align
                return Qt.AlignRight | Qt.AlignVCenter
            return Qt.AlignLeft | Qt.AlignVCenter

        if role == Qt.UserRole:
            return pkt   # raw packet object for detail pane

        return QVariant()

    def _cell_text(self, pkt: ParsedPacket, col: int) -> str:
        if col == 0: return str(pkt.packet_id)
        if col == 1: return f"{pkt.timestamp:.6f}"
        if col == 2: return pkt.src or ""
        if col == 3: return pkt.dst or ""
        if col == 4: return pkt.protocol
        if col == 5: return str(pkt.length)
        if col == 6: return pkt.info
        return ""

    # ── Mutation helpers ──────────────────────────────────────────────────────

    def append_packet(self, pkt: ParsedPacket, visible: bool):
        self._all_packets.append(pkt)
        if visible:
            row = len(self._visible)
            self.beginInsertRows(QModelIndex(), row, row)
            self._visible.append(pkt)
            self.endInsertRows()

    def apply_filter(self, filter_fn):
        """Re-filter _visible from _all_packets using filter_fn(pkt)->bool."""
        self.beginResetModel()
        self._visible = [p for p in self._all_packets if filter_fn(p)]
        self.endResetModel()

    def clear(self):
        self.beginResetModel()
        self._all_packets.clear()
        self._visible.clear()
        self.endResetModel()

    def get_packet(self, row: int) -> ParsedPacket:
        return self._visible[row]

    def get_all(self) -> list:
        return list(self._all_packets)

    @property
    def visible_count(self) -> int:
        return len(self._visible)

    @property
    def total_count(self) -> int:
        return len(self._all_packets)


# ── View ──────────────────────────────────────────────────────────────────────

class PacketTableView(QTableView):

    packet_selected = pyqtSignal(object)  # ParsedPacket

    def __init__(self, parent=None):
        super().__init__(parent)
        self._model = PacketTableModel(self)
        self.setModel(self._model)
        self._setup_ui()
        self.selectionModel().selectionChanged.connect(self._on_selection)

    def _setup_ui(self):
        h = self.horizontalHeader()
        for i, w in enumerate(TABLE_WIDTHS):
            self.setColumnWidth(i, w)
        h.setSectionResizeMode(6, QHeaderView.Stretch)     # Info column stretches
        h.setHighlightSections(False)
        h.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)

        v = self.verticalHeader()
        v.setVisible(False)
        v.setDefaultSectionSize(24)

        self.setShowGrid(False)
        self.setAlternatingRowColors(False)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setWordWrap(False)
        self.setSortingEnabled(False)

    def _on_selection(self, selected, deselected):
        indexes = selected.indexes()
        if indexes:
            row = indexes[0].row()
            pkt = self._model.get_packet(row)
            self.packet_selected.emit(pkt)

    # ── Proxy methods ─────────────────────────────────────────────────────────

    def append_packet(self, pkt: ParsedPacket, visible: bool = True):
        self._model.append_packet(pkt, visible)

    def apply_filter(self, fn):
        self._model.apply_filter(fn)

    def clear(self):
        self._model.clear()

    def get_all_packets(self) -> list:
        return self._model.get_all()

    def scroll_to_bottom(self):
        self.scrollToBottom()

    @property
    def visible_count(self):
        return self._model.visible_count

    @property
    def total_count(self):
        return self._model.total_count
