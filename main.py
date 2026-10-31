from __future__ import annotations

import sys
from threading import Event, Lock
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt, QThread, QTimer, Signal
from PySide6.QtGui import QIcon, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableView,
    QVBoxLayout,
    QWidget,
)
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.all import AsyncSniffer, conf
from scapy.utils import PcapNgWriter, PcapReader


MAX_PACKETS = 100_000
MAX_LIVE_PACKETS = 20_000
MAX_LIVE_FLOWS = 20_000
HEADERS = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info")
FLOW_HEADERS = ("No.", "Last seen", "IP address A", "IP address B", "Protocol", "Packets", "Bytes")


def asset_path(name: str) -> Path:
    bundle_dir = getattr(sys, "_MEIPASS", None)
    base_dir = Path(bundle_dir) if bundle_dir else Path(__file__).resolve().parent
    return base_dir / name


@dataclass(frozen=True)
class PacketRecord:
    number: int
    timestamp: str
    source: str
    destination: str
    protocol: str
    length: int
    info: str
    details: str

    def columns(self) -> tuple[str, ...]:
        return (
            str(self.number),
            self.timestamp,
            self.source,
            self.destination,
            self.protocol,
            str(self.length),
            self.info,
        )


@dataclass
class IpFlow:
    key: tuple[str, str, str]
    number: int
    source: str
    destination: str
    protocol: str
    first_seen: str
    last_seen: str
    packet_count: int
    total_bytes: int

    @classmethod
    def from_packet(cls, record: PacketRecord, number: int) -> IpFlow:
        source, destination = sorted((record.source, record.destination))
        key = (record.protocol, source, destination)
        return cls(
            key=key,
            number=number,
            source=source,
            destination=destination,
            protocol=record.protocol,
            first_seen=record.timestamp,
            last_seen=record.timestamp,
            packet_count=1,
            total_bytes=record.length,
        )

    def add_packet(self, record: PacketRecord) -> None:
        self.packet_count += 1
        self.total_bytes += record.length
        self.last_seen = record.timestamp

    def columns(self) -> tuple[str, ...]:
        return (
            str(self.number),
            self.last_seen,
            self.source,
            self.destination,
            self.protocol,
            f"{self.packet_count:,}",
            f"{self.total_bytes:,}",
        )

    @property
    def details(self) -> str:
        return "\n".join(
            [
                f"IP conversation {self.number}",
                f"{self.source} <-> {self.destination}",
                f"Protocol: {self.protocol}",
                f"Packets: {self.packet_count:,}",
                f"Total bytes: {self.total_bytes:,}",
                f"First seen: {self.first_seen}",
                f"Last seen: {self.last_seen}",
            ]
        )


def ip_flow_key(record: PacketRecord) -> tuple[str, str, str] | None:
    if record.source == "-" or record.destination == "-":
        return None
    source, destination = sorted((record.source, record.destination))
    return record.protocol, source, destination


def summarize_ip_flows(records: list[PacketRecord]) -> list[IpFlow]:
    flows: dict[tuple[str, str, str], IpFlow] = {}
    for record in records:
        key = ip_flow_key(record)
        if key is None:
            continue
        flow = flows.get(key)
        if flow is None:
            flows[key] = IpFlow.from_packet(record, len(flows) + 1)
        else:
            flow.add_packet(record)
    return list(flows.values())


def describe_packet(packet, number: int) -> PacketRecord:
    timestamp_value = float(packet.time)
    timestamp = datetime.fromtimestamp(timestamp_value).astimezone().strftime(
        "%Y-%m-%d %H:%M:%S.%f"
    )[:-3]
    source = "-"
    destination = "-"
    protocol = "Other"
    info = ""
    detail_lines = [
        f"Frame {number}",
        f"Time: {timestamp}",
        f"Frame length: {len(packet)} bytes",
    ]

    if packet.haslayer(Ether):
        ethernet = packet[Ether]
        detail_lines.append(f"Ethernet: {ethernet.src} -> {ethernet.dst}")

    if packet.haslayer(IP):
        ip = packet[IP]
        source, destination = ip.src, ip.dst
        detail_lines.extend(
            [
                "",
                "IPv4",
                f"  Source: {ip.src}",
                f"  Destination: {ip.dst}",
                f"  TTL: {ip.ttl}",
                f"  Header length: {ip.ihl * 4 if ip.ihl else '-'} bytes",
            ]
        )
    elif packet.haslayer(IPv6):
        ip = packet[IPv6]
        source, destination = ip.src, ip.dst
        detail_lines.extend(
            [
                "",
                "IPv6",
                f"  Source: {ip.src}",
                f"  Destination: {ip.dst}",
                f"  Hop limit: {ip.hlim}",
            ]
        )

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        protocol = "TCP"
        info = f"{tcp.sport} -> {tcp.dport} [{tcp.flags}]"
        detail_lines.extend(
            [
                "",
                "TCP",
                f"  Source port: {tcp.sport}",
                f"  Destination port: {tcp.dport}",
                f"  Flags: {tcp.flags}",
                f"  Window: {tcp.window}",
            ]
        )
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        protocol = "UDP"
        info = f"{udp.sport} -> {udp.dport}"
        detail_lines.extend(
            [
                "",
                "UDP",
                f"  Source port: {udp.sport}",
                f"  Destination port: {udp.dport}",
                f"  Length: {udp.len if udp.len is not None else '-'}",
            ]
        )
    elif packet.haslayer(ICMP):
        icmp = packet[ICMP]
        protocol = "ICMP"
        info = f"type {icmp.type}, code {icmp.code}"
        detail_lines.extend(["", "ICMP", f"  Type: {icmp.type}", f"  Code: {icmp.code}"])
    elif packet.haslayer(IP):
        protocol = "IPv4"
    elif packet.haslayer(IPv6):
        protocol = "IPv6"

    return PacketRecord(
        number=number,
        timestamp=timestamp,
        source=source,
        destination=destination,
        protocol=protocol,
        length=len(packet),
        info=info,
        details="\n".join(detail_lines),
    )


class CaptureLoader(QThread):
    loaded = Signal(object, str, bool)
    failed = Signal(str)

    def __init__(self, path: Path):
        super().__init__()
        self.path = path

    def run(self) -> None:
        records = []
        truncated = False
        try:
            with PcapReader(str(self.path)) as capture:
                for number, packet in enumerate(capture, start=1):
                    if number > MAX_PACKETS:
                        truncated = True
                        break
                    try:
                        records.append(describe_packet(packet, number))
                    except Exception:
                        continue
            self.loaded.emit(records, str(self.path), truncated)
        except Exception as error:
            self.failed.emit(str(error))


class LiveCaptureWorker(QThread):
    packet_received = Signal(object)
    ready = Signal()
    failed = Signal(str)
    save_failed = Signal(str)

    def __init__(self, interface):
        super().__init__()
        self.interface = interface
        self.stop_requested = Event()
        self.sniffer = None
        self.writer_lock = Lock()
        self.writer = None

    def run(self) -> None:
        try:
            self.sniffer = AsyncSniffer(
                iface=self.interface,
                prn=self.emit_packet,
                store=False,
                promisc=False,
                started_callback=self.ready.emit,
            )
            self.sniffer.start()
            while not self.stop_requested.wait(0.1):
                if not self.sniffer.running:
                    if self.sniffer.exception:
                        raise self.sniffer.exception
                    break
            if self.sniffer.running:
                self.sniffer.stop(join=True)
        except Exception as error:
            self.failed.emit(str(error))
        finally:
            self.stop_saving()

    def stop(self) -> None:
        self.stop_requested.set()

    def start_saving(self, path: Path) -> None:
        with self.writer_lock:
            if self.writer is not None:
                raise RuntimeError("A capture is already being saved.")
            self.writer = PcapNgWriter(str(path))

    def stop_saving(self) -> None:
        with self.writer_lock:
            writer = self.writer
            self.writer = None
            if writer is not None:
                writer.close()

    def emit_packet(self, packet) -> None:
        with self.writer_lock:
            if self.writer is not None:
                try:
                    self.writer.write(packet)
                except Exception as error:
                    writer = self.writer
                    self.writer = None
                    try:
                        writer.close()
                    except Exception:
                        pass
                    self.save_failed.emit(str(error))
        self.packet_received.emit(packet)


class PacketTableModel(QAbstractTableModel):
    def __init__(self):
        super().__init__()
        self.records: list[PacketRecord | IpFlow] = []
        self.headers = HEADERS

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.records)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.headers)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or role != Qt.ItemDataRole.DisplayRole:
            return None
        return self.records[index.row()].columns()[index.column()]

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole):
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal:
            return self.headers[section]
        return str(section + 1)

    def set_records(self, records: list[PacketRecord | IpFlow], headers=HEADERS) -> None:
        self.beginResetModel()
        self.records = records
        self.headers = headers
        self.endResetModel()

    def append_record(self, record: PacketRecord) -> None:
        row = len(self.records)
        self.beginInsertRows(QModelIndex(), row, row)
        self.records.append(record)
        self.endInsertRows()

    def update_record(self, row: int) -> None:
        if 0 <= row < len(self.records):
            self.dataChanged.emit(self.index(row, 0), self.index(row, len(self.headers) - 1))

    def remove_first(self) -> PacketRecord | None:
        if not self.records:
            return None
        self.beginRemoveRows(QModelIndex(), 0, 0)
        record = self.records.pop(0)
        self.endRemoveRows()
        return record


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Net-Tracker")
        self.resize(1220, 780)
        self.loader: CaptureLoader | None = None
        self.capture_worker: LiveCaptureWorker | None = None
        self.all_records: list[PacketRecord] = []
        self.live_packet_count = 0
        self.live_active = False
        self.live_error = ""
        self.stop_requested = False
        self.saving_path: Path | None = None
        self.flow_records: list[IpFlow] = []
        self.flows_by_key: dict[tuple[str, str, str], IpFlow] = {}
        self.flow_row_indexes: dict[tuple[str, str, str], int] = {}
        self.model = PacketTableModel()
        self._build_ui()

        logo_path = asset_path("Network.png")
        if logo_path.exists():
            self.setWindowIcon(QIcon(str(logo_path)))
            self.logo.setPixmap(QPixmap(str(logo_path)).scaled(
                48, 48, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation
            ))

    def _build_ui(self) -> None:
        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setContentsMargins(24, 20, 24, 14)
        layout.setSpacing(14)

        header = QHBoxLayout()
        self.logo = QLabel()
        self.logo.setFixedSize(48, 48)
        header.addWidget(self.logo)

        title_block = QVBoxLayout()
        title = QLabel("Net-Tracker")
        title.setObjectName("title")
        subtitle = QLabel("Live and offline packet inspector")
        subtitle.setObjectName("subtitle")
        title_block.addWidget(title)
        title_block.addWidget(subtitle)
        header.addLayout(title_block)
        header.addStretch(1)

        self.live_button = QPushButton("Start live capture")
        self.live_button.setObjectName("liveButton")
        self.live_button.clicked.connect(self.toggle_live_capture)
        header.addWidget(self.live_button)

        self.open_button = QPushButton("Open capture")
        self.open_button.setObjectName("primaryButton")
        self.open_button.clicked.connect(self.open_capture)
        header.addWidget(self.open_button)
        layout.addLayout(header)

        toolbar = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter packets...")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self.filter_packets)
        toolbar.addWidget(self.search, 1)
        self.group_by_ip = QCheckBox("Group by IP pair")
        self.group_by_ip.setChecked(True)
        self.group_by_ip.toggled.connect(lambda _checked: self.filter_packets(self.search.text()))
        toolbar.addWidget(self.group_by_ip)
        self.file_label = QLabel("No capture file open")
        self.file_label.setObjectName("muted")
        toolbar.addWidget(self.file_label)
        self.save_button = QPushButton("Save capture")
        self.save_button.setEnabled(False)
        self.save_button.clicked.connect(self.toggle_save_capture)
        toolbar.addWidget(self.save_button)
        layout.addLayout(toolbar)

        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(False)
        self.table.verticalHeader().hide()
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setColumnWidth(0, 64)
        self.table.setColumnWidth(1, 190)
        self.table.setColumnWidth(2, 170)
        self.table.setColumnWidth(3, 170)
        self.table.setColumnWidth(4, 100)
        self.table.setColumnWidth(5, 80)
        self.table.selectionModel().currentRowChanged.connect(self.show_packet_details)

        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        self.details.setPlaceholderText("Select a packet to inspect its header metadata.")
        self.details.setMaximumBlockCount(80)
        self.details.setFixedHeight(178)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.table)
        splitter.addWidget(self.details)
        splitter.setStretchFactor(0, 1)
        splitter.setSizes([520, 178])
        layout.addWidget(splitter, 1)

        footer = QHBoxLayout()
        self.status = QLabel("Ready")
        self.status.setObjectName("muted")
        footer.addWidget(self.status)
        footer.addStretch(1)
        credits = QLabel("Credits: Nex12126")
        credits.setObjectName("muted")
        footer.addWidget(credits)
        local_processing = QLabel("| Processed locally")
        local_processing.setObjectName("muted")
        footer.addWidget(local_processing)
        layout.addLayout(footer)

        self.setCentralWidget(root)
        self.setStyleSheet(
            "QMainWindow, QWidget { background: #f4f5f2; color: #202722; }"
            "QLabel#title { font-size: 24px; font-weight: 700; color: #18251e; }"
            "QLabel#subtitle, QLabel#muted { color: #68756c; }"
            "QPushButton { padding: 9px 16px; border: 1px solid #cbd4cc; border-radius: 5px; background: #fff; }"
            "QPushButton:hover { background: #e9eee9; }"
            "QPushButton#primaryButton { color: #fff; background: #176b4a; border-color: #176b4a; font-weight: 600; }"
            "QPushButton#primaryButton:hover { background: #11573c; }"
            "QPushButton#liveButton { color: #fff; background: #b64236; border-color: #b64236; font-weight: 600; }"
            "QPushButton#liveButton:hover { background: #96352c; }"
            "QLineEdit, QPlainTextEdit, QTableView { background: #fff; border: 1px solid #d5ddd6; border-radius: 4px; }"
            "QLineEdit { padding: 9px 10px; }"
            "QPlainTextEdit { padding: 8px; font-family: Consolas, monospace; }"
            "QTableView { gridline-color: #e7ebe7; alternate-background-color: #f7f9f6; selection-background-color: #d7ebe0; selection-color: #17241d; }"
            "QHeaderView::section { background: #e9eee9; color: #3a4b40; padding: 8px; border: 0; border-bottom: 1px solid #d5ddd6; font-weight: 600; }"
        )

    def open_capture(self) -> None:
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Open capture file",
            "",
            "Packet captures (*.pcap *.pcapng *.cap);;All files (*.*)",
        )
        if not filename:
            return
        if self.loader and self.loader.isRunning():
            return
        self.stop_live_capture()
        path = Path(filename)
        self.open_button.setEnabled(False)
        self.status.setText("Reading capture...")
        self.file_label.setText(path.name)
        self.details.clear()
        self.all_records = []
        self.flow_records = []
        self.flows_by_key = {}
        self.flow_row_indexes = {}
        self.model.set_records([])
        self.loader = CaptureLoader(path)
        self.loader.loaded.connect(self.capture_loaded)
        self.loader.failed.connect(self.capture_failed)
        self.loader.finished.connect(lambda: self.open_button.setEnabled(True))
        self.loader.start()

    def toggle_live_capture(self) -> None:
        if self.capture_worker and self.capture_worker.isRunning():
            self.stop_live_capture()
        else:
            self.start_live_capture()

    def start_live_capture(self) -> None:
        if self.capture_worker and self.capture_worker.isRunning():
            return
        self.live_error = ""
        self.live_active = True
        self.stop_requested = False
        self.live_packet_count = 0
        self.all_records = []
        self.flow_records = []
        self.flows_by_key = {}
        self.flow_row_indexes = {}
        self.model.set_records([])
        self.details.clear()
        self.search.clear()
        self.save_button.setEnabled(False)
        interface = conf.iface
        interface_name = getattr(interface, "description", None) or str(interface)
        self.file_label.setText(f"Live: {interface_name}")
        self.status.setText("Starting live capture...")
        self.live_button.setText("Stop live capture")
        self.live_button.setEnabled(True)
        self.capture_worker = LiveCaptureWorker(interface)
        self.capture_worker.packet_received.connect(self.receive_live_packet)
        self.capture_worker.ready.connect(self.live_capture_ready)
        self.capture_worker.failed.connect(self.live_capture_failed)
        self.capture_worker.save_failed.connect(self.capture_save_failed)
        self.capture_worker.finished.connect(self.live_capture_finished)
        self.capture_worker.start()

    def stop_live_capture(self) -> None:
        self.live_active = False
        self.save_button.setEnabled(False)
        self.stop_saving_capture(update_status=False)
        if self.capture_worker and self.capture_worker.isRunning():
            self.stop_requested = True
            self.live_button.setEnabled(False)
            self.status.setText("Stopping live capture...")
            self.capture_worker.stop()

    def live_capture_ready(self) -> None:
        self.status.setText("Live capture active")
        self.save_button.setEnabled(True)

    def live_capture_failed(self, message: str) -> None:
        self.live_active = False
        self.live_error = message
        self.save_button.setEnabled(False)
        self.status.setText(f"Live capture failed: {message}")

    def live_capture_finished(self) -> None:
        self.live_active = False
        saved_path = self.saving_path
        self.saving_path = None
        self.save_button.setEnabled(False)
        self.save_button.setText("Save capture")
        self.live_button.setEnabled(True)
        self.live_button.setText("Start live capture")
        if not self.live_error:
            if saved_path:
                self.status.setText(f"Capture saved: {saved_path.name}")
            elif self.stop_requested:
                self.status.setText("Live capture stopped")
        self.stop_requested = False

    def toggle_save_capture(self) -> None:
        if self.saving_path:
            self.stop_saving_capture()
            return
        if not self.live_active or not self.capture_worker or not self.capture_worker.isRunning():
            self.status.setText("Start live capture before saving packets.")
            return
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Save packet capture",
            "Net-Tracker-capture.pcapng",
            "PCAPNG captures (*.pcapng)",
        )
        if not filename:
            return
        path = Path(filename)
        if path.suffix.casefold() != ".pcapng":
            path = path.with_suffix(".pcapng")
        try:
            self.capture_worker.start_saving(path)
        except Exception as error:
            self.status.setText("Could not start saving capture")
            QMessageBox.critical(self, "Save error", str(error))
            return
        self.saving_path = path
        self.save_button.setText("Stop saving")
        self.status.setText(f"Saving capture locally to {path.name}")

    def stop_saving_capture(self, update_status: bool = True) -> None:
        if not self.saving_path:
            return
        path = self.saving_path
        if self.capture_worker:
            self.capture_worker.stop_saving()
        self.saving_path = None
        self.save_button.setText("Save capture")
        self.save_button.setEnabled(self.live_active)
        if update_status:
            self.status.setText(f"Capture saved: {path.name}")

    def capture_save_failed(self, message: str) -> None:
        self.saving_path = None
        self.save_button.setText("Save capture")
        self.save_button.setEnabled(self.live_active)
        self.status.setText(f"Could not save capture: {message}")

    def receive_live_packet(self, packet) -> None:
        if not self.live_active:
            return
        scroll_bar = self.table.verticalScrollBar()
        was_at_bottom = scroll_bar.value() >= scroll_bar.maximum()
        self.live_packet_count += 1
        try:
            record = describe_packet(packet, self.live_packet_count)
        except Exception:
            return

        dropped = None
        if len(self.all_records) >= MAX_LIVE_PACKETS:
            dropped = self.all_records.pop(0)
        self.all_records.append(record)

        self.update_live_flow(record)
        needle = self.search.text().casefold().strip()
        if self.group_by_ip.isChecked():
            flow = self.flows_by_key.get(ip_flow_key(record))
            if flow:
                row = self.flow_row_indexes.get(flow.key)
                if row is None and self.matches_flow(flow, needle):
                    row = self.model.rowCount()
                    self.model.append_record(flow)
                    self.flow_row_indexes[flow.key] = row
                elif row is not None:
                    self.model.update_record(row)
        else:
            if dropped and (not needle or needle in " ".join(dropped.columns()).casefold()):
                self.model.remove_first()
            if not needle or needle in " ".join(record.columns()).casefold():
                self.model.append_record(record)

        if was_at_bottom:
            self.table.scrollToBottom()
        visible_count = self.model.rowCount()
        item_name = "IP groups" if self.group_by_ip.isChecked() else "packets"
        self.status.setText(
            f"Live capture active | {visible_count:,} {item_name} shown | {self.live_packet_count:,} packets received"
        )

    def update_live_flow(self, record: PacketRecord) -> None:
        key = ip_flow_key(record)
        if key is None:
            return
        flow = self.flows_by_key.get(key)
        if flow:
            flow.add_packet(record)
            return
        if len(self.flow_records) >= MAX_LIVE_FLOWS:
            return
        flow = IpFlow.from_packet(record, len(self.flow_records) + 1)
        self.flow_records.append(flow)
        self.flows_by_key[key] = flow

    @staticmethod
    def matches_flow(flow: IpFlow, needle: str) -> bool:
        return not needle or needle in f"{flow.source} {flow.destination} {flow.protocol}".casefold()

    def capture_loaded(self, records: list[PacketRecord], filename: str, truncated: bool) -> None:
        self.all_records = records
        self.flow_records = summarize_ip_flows(records)
        self.flows_by_key = {flow.key: flow for flow in self.flow_records}
        self.filter_packets(self.search.text())
        count_text = f"{len(records):,}"
        suffix = f" (limit: {MAX_PACKETS:,} packets)" if truncated else ""
        self.status.setText(f"{count_text} packets loaded{suffix}")
        self.file_label.setText(Path(filename).name)
        if records:
            self.table.selectRow(0)
        else:
            self.details.setPlainText("No readable packets found in this file.")

    def capture_failed(self, message: str) -> None:
        self.status.setText("Could not open capture")
        QMessageBox.critical(self, "Capture error", message)

    def filter_packets(self, text: str) -> None:
        needle = text.casefold().strip()
        if self.group_by_ip.isChecked():
            visible_flows = [flow for flow in self.flow_records if self.matches_flow(flow, needle)]
            self.model.set_records(visible_flows, FLOW_HEADERS)
            self.flow_row_indexes = {flow.key: index for index, flow in enumerate(visible_flows)}
            visible_count = len(visible_flows)
            item_name = "IP groups"
        else:
            if not needle:
                visible = self.all_records
            else:
                visible = [
                    record for record in self.all_records
                    if needle in " ".join(record.columns()).casefold()
                ]
            self.model.set_records(list(visible), HEADERS)
            self.flow_row_indexes = {}
            visible_count = len(visible)
            item_name = "packets"
        self.details.clear()
        self.status.setText(f"{visible_count:,} {item_name} shown")

    def show_packet_details(self, current: QModelIndex, _previous: QModelIndex) -> None:
        if current.isValid() and current.row() < len(self.model.records):
            self.details.setPlainText(self.model.records[current.row()].details)

    def closeEvent(self, event) -> None:
        if self.capture_worker and self.capture_worker.isRunning():
            self.capture_worker.stop()
            self.capture_worker.wait()
        if self.loader and self.loader.isRunning():
            self.loader.wait()
        event.accept()


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("Net-Tracker")
    window = MainWindow()
    window.show()
    QTimer.singleShot(400, window.start_live_capture)
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())