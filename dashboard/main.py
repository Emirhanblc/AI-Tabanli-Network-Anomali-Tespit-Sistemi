"""IDS canlı trafik ve tehdit paneli."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from PyQt5.QtCore import QProcess, QTimer, QUrl
from PyQt5.QtGui import QColor
from PyQt5.QtNetwork import QNetworkAccessManager, QNetworkReply, QNetworkRequest
from PyQt5.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

import os

import sys

os.environ['QT_QPA_PLATFORM_PLUGIN_PATH'] = os.path.join(sys.prefix, 'Lib', 'site-packages', 'PyQt5', 'Qt5', 'plugins', 'platforms')


class Dashboard(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.api_url = os.getenv("IDS_API_URL", "http://127.0.0.1:8000").rstrip("/")
        self.network = QNetworkAccessManager(self)
        self._replies: set[QNetworkReply] = set()
        self.sniffer = QProcess(self)
        self.sniffer.setProcessChannelMode(QProcess.MergedChannels)
        self.sniffer.stateChanged.connect(self._process_state_changed)
        self.setWindowTitle("Yapay Zeka Destekli Ağ IDS")
        self.resize(1200, 700)
        self._build_ui()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(1500)
        self.refresh()

    def _build_ui(self) -> None:
        root = QWidget()
        layout = QVBoxLayout(root)
        status = QHBoxLayout()
        self.listener_status = QLabel("Dinleyici: durdu")
        self.api_status = QLabel("Karar motoru: denetleniyor")
        self.interface = QLineEdit(os.getenv("SNIFFER_INTERFACE", ""))
        self.interface.setPlaceholderText("Ağ arayüzü adı")
        self.toggle = QPushButton("Dinleyiciyi başlat")
        self.toggle.clicked.connect(self.toggle_sniffer)
        for widget in (
            self.listener_status,
            self.api_status,
            QLabel("Arayüz:"),
            self.interface,
            self.toggle,
        ):
            status.addWidget(widget)
        layout.addLayout(status)

        tables = QHBoxLayout()
        self.traffic = self._table(
            ["Zaman", "Protokol", "Kaynak", "Hedef", "Hedef port", "Boyut"],
            "#d9f7df",
        )
        self.alerts = self._table(
            ["Zaman", "Sınıf", "Kaynak IP", "Hedef IP", "Hedef port"],
            "#ffd9d9",
        )
        left = QVBoxLayout()
        left.addWidget(QLabel("Güvenli trafik"))
        left.addWidget(self.traffic)
        right = QVBoxLayout()
        right.addWidget(QLabel("Tehditler"))
        right.addWidget(self.alerts)
        tables.addLayout(left, 3)
        tables.addLayout(right, 2)
        layout.addLayout(tables)
        self.message = QLabel("")
        layout.addWidget(self.message)
        self.setCentralWidget(root)

    @staticmethod
    def _table(headers: list[str], color: str) -> QTableWidget:
        table = QTableWidget(1, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        table.setAlternatingRowColors(False)
        table.setStyleSheet(f"QTableWidget::item {{ background: {color}; }}")
        table.setItem(0, 0, QTableWidgetItem("Kayıt yok"))
        return table

    def refresh(self) -> None:
        self._get("/health", self._health_received)
        self._get("/traffic?limit=100&verdict=Temiz", self._traffic_received)
        self._get("/alerts?limit=100", self._alerts_received)

    def _get(self, path: str, callback) -> None:
        reply = self.network.get(QNetworkRequest(QUrl(self.api_url + path)))
        self._replies.add(reply)
        reply.finished.connect(lambda: self._handle_reply(reply, callback))

    def _handle_reply(self, reply: QNetworkReply, callback) -> None:
        self._replies.discard(reply)
        if reply.error() != QNetworkReply.NoError:
            self.api_status.setText("Karar motoru: hazır değil")
            self.message.setText(f"Servis hatası: {reply.errorString()}")
        else:
            try:
                callback(json.loads(bytes(reply.readAll()).decode("utf-8")))
                self.message.setText("")
            except (ValueError, TypeError, KeyError):
                self.message.setText("Servisten geçersiz yanıt alındı; eski veriler korunuyor.")
        reply.deleteLater()

    def _health_received(self, data: dict) -> None:
        status = "çalışıyor" if data.get("ready") else "hazır değil"
        self.api_status.setText(f"Karar motoru: {status}")

    def _traffic_received(self, rows: list[dict]) -> None:
        values = [
            [
                row["captured_at"],
                row["protocol"],
                row["src_ip"],
                row["dst_ip"],
                row["dst_port"],
                row["packet_size"],
            ]
            for row in rows
        ]
        self._fill(self.traffic, values, QColor(217, 247, 223))

    def _alerts_received(self, rows: list[dict]) -> None:
        values = [
            [row["captured_at"], row["label"], row["src_ip"], row["dst_ip"], row["dst_port"]]
            for row in rows
        ]
        self._fill(self.alerts, values, QColor(255, 217, 217))

    @staticmethod
    def _fill(table: QTableWidget, rows: list[list[object]], color: QColor) -> None:
        if not rows:
            table.setRowCount(1)
            table.clearContents()
            table.setItem(0, 0, QTableWidgetItem("Kayıt yok"))
            return
        table.setRowCount(len(rows))
        for row_index, row in enumerate(rows):
            for column, value in enumerate(row):
                item = QTableWidgetItem(str(value))
                item.setBackground(color)
                table.setItem(row_index, column, item)

    def toggle_sniffer(self) -> None:
        if self.sniffer.state() != QProcess.NotRunning:
            self.sniffer.terminate()
            if not self.sniffer.waitForFinished(1500):
                self.sniffer.kill()
            return
        project_root = Path(__file__).resolve().parents[1]
        arguments = [
            str(project_root / "sniffer.py"),
            "--output",
            "http",
            "--api-url",
            self.api_url,
        ]
        if self.interface.text().strip():
            arguments.extend(["--iface", self.interface.text().strip()])
        self.sniffer.setWorkingDirectory(str(project_root))
        self.sniffer.start(sys.executable, arguments)

    def _process_state_changed(self, state: QProcess.ProcessState) -> None:
        running = state == QProcess.Running
        self.listener_status.setText(f"Dinleyici: {'çalışıyor' if running else 'durdu'}")
        self.toggle.setText("Dinleyiciyi durdur" if running else "Dinleyiciyi başlat")
        self.interface.setEnabled(not running)

    def closeEvent(self, event) -> None:
        self.timer.stop()
        for reply in tuple(self._replies):
            reply.disconnect()
            reply.abort()
            reply.deleteLater()
        self._replies.clear()
        if self.sniffer.state() != QProcess.NotRunning:
            self.sniffer.terminate()
            self.sniffer.waitForFinished(1000)
        super().closeEvent(event)


def main() -> None:
    application = QApplication(sys.argv)
    window = Dashboard()
    window.show()
    raise SystemExit(application.exec_())


if __name__ == "__main__":
    main()
