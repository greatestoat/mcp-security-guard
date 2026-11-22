from __future__ import annotations

import argparse
import ipaddress
import json
import os
import queue
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

from PySide6.QtCore import QEvent, QSettings, Qt, QThread, QTimer, Signal
from PySide6.QtGui import QAction, QColor, QFont, QIcon, QPainter, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QStackedWidget,
    QSystemTrayIcon,
    QVBoxLayout,
    QWidget,
)


APP_NAME = "MCP Security Guard"
POLL_INTERVAL_SECONDS = 1.0
HISTORY_INTERVAL_SECONDS = 5.0
CONTROL_TIMEOUT_SECONDS = 4.0

STYLESHEET = """
QWidget {
    background: #0c111b;
    color: #e8edf6;
    font-family: "Segoe UI";
    font-size: 10pt;
}
QFrame#Sidebar { background: #101725; border-right: 1px solid #222d3e; }
QLabel#BrandMark {
    background: #6d5efc; color: white; border-radius: 10px;
    font-size: 15pt; font-weight: 700;
}
QLabel#BrandTitle { color: #f3f5fa; font-size: 12pt; font-weight: 700; }
QLabel#BrandSub { color: #8491a8; font-size: 8pt; }
QPushButton#NavButton {
    text-align: left; padding: 11px 14px; border: 0; border-radius: 8px;
    color: #9da9bd; background: transparent; font-weight: 600;
}
QPushButton#NavButton:hover { background: #192437; color: #f4f6fb; }
QPushButton#NavButton[active="true"] { background: #242248; color: #aaa4ff; }
QLabel#PageTitle { font-size: 23pt; font-weight: 700; color: #f3f5fa; }
QLabel#PageSubtitle { color: #8996ac; font-size: 10pt; }
QFrame#Card, QFrame#RequestCard, QFrame#SettingCard {
    background: #131c2a; border: 1px solid #263348; border-radius: 12px;
}
QLabel#CardLabel { color: #8d9ab0; font-size: 9pt; }
QLabel#CardValue { font-size: 24pt; font-weight: 700; color: #f2f5fb; }
QLabel#Muted { color: #8996ac; }
QLabel#SectionTitle { font-size: 13pt; font-weight: 700; }
QLabel#StatusConnected {
    color: #63e3ac; background: #103327; border: 1px solid #1d5f47;
    border-radius: 12px; padding: 6px 11px; font-weight: 700;
}
QLabel#StatusDisconnected {
    color: #ffc47d; background: #3a2a19; border: 1px solid #72502a;
    border-radius: 12px; padding: 6px 11px; font-weight: 700;
}
QLabel#StatusDemo {
    color: #ffe28a; background: #423616; border: 1px solid #796125;
    border-radius: 12px; padding: 6px 11px; font-weight: 700;
}
QPushButton {
    border: 1px solid #303e54; border-radius: 8px; padding: 9px 14px;
    color: #dce4f2; background: #1a2638; font-weight: 600;
}
QPushButton:hover { background: #25344b; }
QPushButton:disabled { color: #647087; background: #141c28; }
QPushButton#PrimaryButton {
    color: white; border: 1px solid #786cff; background: #6356ed;
}
QPushButton#PrimaryButton:hover { background: #766bff; }
QPushButton#AllowButton {
    color: #d7ffec; border: 1px solid #26865f; background: #126344;
    font-size: 11pt; font-weight: 700; padding: 12px 20px;
}
QPushButton#AllowButton:hover { background: #178153; }
QPushButton#BlockButton {
    color: #ffe3e5; border: 1px solid #a74850; background: #772d38;
    font-size: 11pt; font-weight: 700; padding: 12px 20px;
}
QPushButton#BlockButton:hover { background: #943644; }
QLineEdit, QSpinBox, QPlainTextEdit {
    background: #0d1420; border: 1px solid #2a384d; border-radius: 7px;
    padding: 9px; selection-background-color: #6356ed;
}
QPlainTextEdit#Arguments { font-family: Consolas; font-size: 9pt; }
QScrollArea { border: 0; background: transparent; }
QStatusBar { color: #8d9ab0; background: #101725; }
QToolTip { color: #f3f5fa; background: #172235; border: 1px solid #35445a; }
"""


def _control_request(
    host: str,
    port: int,
    token: str,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    encoded_body = json.dumps(body).encode("utf-8") if body is not None else None
    formatted_host = f"[{host}]" if ":" in host else host
    request = urllib.request.Request(
        f"http://{formatted_host}:{port}{path}",
        data=encoded_body,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(request, timeout=CONTROL_TIMEOUT_SECONDS) as response:
        result = json.loads(response.read())
    if not isinstance(result, dict):
        raise ValueError("Approval control API returned an invalid response")
    return result


class ControlWorker(QThread):
    pending_changed = Signal(list)
    history_changed = Signal(list)
    connection_changed = Signal(bool, str)
    decision_completed = Signal(str, str, bool, str)

    def __init__(self, host: str, port: int, token: str) -> None:
        super().__init__()
        self._host = host
        self._port = port
        self._token = token
        self._actions: queue.Queue[tuple[str, str]] = queue.Queue()
        self._wake = threading.Event()
        self._was_connected = False

    def decide(self, approval_id: str, decision: str) -> None:
        self._actions.put((approval_id, decision))
        self._wake.set()

    def run(self) -> None:
        last_history_at = 0.0
        while not self.isInterruptionRequested():
            self._process_actions()
            try:
                result = _control_request(
                    self._host, self._port, self._token, "GET", "/pending"
                )
                pending = result.get("pending")
                if not isinstance(pending, list):
                    raise ValueError("Approval API returned an invalid pending list")
                self.pending_changed.emit(pending)
                self._set_connection(True, "Connected to the real MCP proxy")
                current = time.monotonic()
                if current - last_history_at >= HISTORY_INTERVAL_SECONDS:
                    history_result = _control_request(
                        self._host, self._port, self._token, "GET", "/audit"
                    )
                    history = history_result.get("recent")
                    if not isinstance(history, list):
                        raise ValueError("Approval API returned an invalid audit history")
                    self.history_changed.emit(history)
                    last_history_at = current
            except (OSError, ValueError, urllib.error.URLError, json.JSONDecodeError) as exc:
                self._set_connection(False, _control_error(exc))
            self._wait_for_action()

    def _process_actions(self) -> None:
        while True:
            try:
                approval_id, decision = self._actions.get_nowait()
            except queue.Empty:
                return
            try:
                result = _control_request(
                    self._host,
                    self._port,
                    self._token,
                    "POST",
                    f"/requests/{approval_id}/decision",
                    {"decision": decision},
                )
                accepted = result.get("status") == decision
                message = (
                    "Decision sent to proxy"
                    if accepted
                    else "Request is no longer pending"
                )
                self.decision_completed.emit(approval_id, decision, accepted, message)
            except (OSError, ValueError, urllib.error.URLError, json.JSONDecodeError) as exc:
                self.decision_completed.emit(
                    approval_id, decision, False, _control_error(exc)
                )

    def _set_connection(self, connected: bool, message: str) -> None:
        if connected != self._was_connected or not connected:
            self.connection_changed.emit(connected, message)
        self._was_connected = connected

    def _wait_for_action(self) -> None:
        self._wake.wait(POLL_INTERVAL_SECONDS)
        self._wake.clear()


def _control_error(exc: Exception) -> str:
    if isinstance(exc, urllib.error.HTTPError):
        if exc.code == 401:
            return "Authentication failed. Check the approval token."
        return f"Approval service returned HTTP {exc.code}."
    if isinstance(exc, urllib.error.URLError):
        return f"Cannot reach the proxy at the configured loopback address: {exc.reason}"
    if isinstance(exc, TimeoutError):
        return "The approval service did not respond before the connection timed out."
    return f"Approval service error: {exc}"


def _make_icon() -> QIcon:
    pixmap = QPixmap(64, 64)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setBrush(QColor("#6d5efc"))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.drawRoundedRect(3, 3, 58, 58, 17, 17)
    painter.setPen(QColor("#ffffff"))
    font = QFont("Segoe UI", 26, QFont.Weight.Bold)
    painter.setFont(font)
    painter.drawText(pixmap.rect(), Qt.AlignmentFlag.AlignCenter, "G")
    painter.end()
    return QIcon(pixmap)


def _format_timestamp(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.astimezone().strftime("%b %d, %Y  %I:%M:%S %p")
    except (ValueError, TypeError):
        return value


def _remaining_seconds(value: str, timeout_seconds: int) -> int:
    try:
        created = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        elapsed = (datetime.now(timezone.utc) - created.astimezone(timezone.utc)).total_seconds()
        return max(0, timeout_seconds - int(elapsed))
    except (ValueError, TypeError):
        return timeout_seconds


class RequestCard(QFrame):
    def __init__(
        self,
        request: dict[str, Any],
        timeout_seconds: int,
        on_decision: Any,
    ) -> None:
        super().__init__()
        self.setObjectName("RequestCard")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        layout = QVBoxLayout(self)
        heading = QHBoxLayout()
        tool = QLabel(str(request.get("tool_name", "Unknown tool")))
        tool.setObjectName("SectionTitle")
        heading.addWidget(tool)
        heading.addStretch(1)
        heading.addWidget(_badge("AWAITING APPROVAL", "#ffe28a", "#423616"))
        layout.addLayout(heading)
        details = QLabel(
            f"{request.get('origin_application', 'Unknown MCP client')}  ·  "
            f"{request.get('server_name', 'Unknown server')}  ·  "
            f"Request ID: {request.get('request_id')}"
        )
        details.setObjectName("Muted")
        details.setWordWrap(True)
        layout.addWidget(details)
        args = QPlainTextEdit(
            json.dumps(request.get("arguments", {}), indent=2, ensure_ascii=False)
        )
        args.setObjectName("Arguments")
        args.setReadOnly(True)
        args.setMaximumHeight(120)
        layout.addWidget(args)
        footer = QHBoxLayout()
        timer = QLabel()
        timer.setObjectName("Muted")
        approval_time = str(request.get("timestamp", ""))
        timer.setText(
            f"Expires in {_remaining_seconds(approval_time, timeout_seconds)} seconds"
        )
        footer.addWidget(timer)
        footer.addStretch(1)
        allow = QPushButton("Allow")
        allow.setObjectName("AllowButton")
        allow.clicked.connect(
            lambda checked=False, approval_id=request["approval_id"]: on_decision(
                approval_id, "approve"
            )
        )
        block = QPushButton("Block")
        block.setObjectName("BlockButton")
        block.clicked.connect(
            lambda checked=False, approval_id=request["approval_id"]: on_decision(
                approval_id, "deny"
            )
        )
        footer.addWidget(allow)
        footer.addWidget(block)
        layout.addLayout(footer)


def _badge(text: str, foreground: str, background: str) -> QLabel:
    label = QLabel(text)
    label.setStyleSheet(
        f"color: {foreground}; background: {background}; border-radius: 10px;"
        "padding: 5px 9px; font-weight: 700; font-size: 8pt;"
    )
    return label


class ApprovalPopup(QWidget):
    def __init__(
        self,
        request: dict[str, Any],
        timeout_seconds: int,
        on_decision: Any,
        index: int,
    ) -> None:
        super().__init__(
            None,
            Qt.WindowType.Tool
            | Qt.WindowType.WindowStaysOnTopHint
            | Qt.WindowType.WindowTitleHint
            | Qt.WindowType.WindowCloseButtonHint,
        )
        self._request = request
        self._timeout_seconds = timeout_seconds
        self._on_decision = on_decision
        self._decision_sent = False
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, False)
        self.setWindowTitle("MCP Security Guard — Approval required")
        self.setWindowIcon(_make_icon())
        self.setFixedWidth(500)
        self.setStyleSheet(
            "QWidget { background: #101725; color: #edf2fb; font-family: 'Segoe UI'; }"
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 18, 22, 20)
        header = QHBoxLayout()
        emblem = QLabel("!")
        emblem.setAlignment(Qt.AlignmentFlag.AlignCenter)
        emblem.setFixedSize(38, 38)
        emblem.setStyleSheet(
            "background: #6459ee; color: white; border-radius: 12px;"
            "font-size: 18pt; font-weight: 800;"
        )
        title_box = QVBoxLayout()
        title = QLabel("Tool call needs your approval")
        title.setStyleSheet("font-size: 13pt; font-weight: 700;")
        subtitle = QLabel("A real MCP request is paused until you decide.")
        subtitle.setStyleSheet("color: #8f9db3; font-size: 9pt;")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        header.addWidget(emblem)
        header.addSpacing(10)
        header.addLayout(title_box)
        header.addStretch(1)
        layout.addLayout(header)
        layout.addSpacing(12)
        for label, field in (
            ("ORIGINATING APPLICATION", request.get("origin_application", "Unknown MCP client")),
            ("MCP SERVER", request.get("server_name", "Unknown server")),
            ("TOOL", request.get("tool_name", "Unknown tool")),
            ("REQUEST ID", request.get("request_id")),
        ):
            layout.addWidget(_detail(label, str(field)))
        layout.addWidget(QLabel("ARGUMENTS"))
        arguments = QPlainTextEdit(
            json.dumps(request.get("arguments", {}), indent=2, ensure_ascii=False)
        )
        arguments.setReadOnly(True)
        arguments.setMaximumHeight(155)
        arguments.setStyleSheet(
            "QPlainTextEdit { background: #0b111c; border: 1px solid #2a384d;"
            "border-radius: 8px; padding: 10px; font-family: Consolas; font-size: 9pt; }"
        )
        layout.addWidget(arguments)
        self._countdown = QLabel()
        self._countdown.setStyleSheet("color: #ffc47d; font-weight: 700;")
        layout.addWidget(self._countdown)
        actions = QHBoxLayout()
        actions.addStretch(1)
        block = QPushButton("Block")
        block.setObjectName("BlockButton")
        block.clicked.connect(lambda: self._submit_decision("deny"))
        allow = QPushButton("Allow")
        allow.setObjectName("AllowButton")
        allow.clicked.connect(lambda: self._submit_decision("approve"))
        actions.addWidget(block)
        actions.addWidget(allow)
        layout.addSpacing(5)
        layout.addLayout(actions)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._update_countdown)
        self._timer.start(500)
        self._update_countdown()
        self.adjustSize()
        screen = QApplication.primaryScreen()
        if screen is not None:
            area = screen.availableGeometry()
            margin = 24
            gap = 12
            columns = max(1, (area.width() - margin * 2) // (self.width() + gap))
            rows = max(1, (area.height() - margin * 2) // (self.height() + gap))
            slot = max(0, index - 1)
            column = slot % columns
            row = (slot // columns) % rows
            x = area.right() - self.width() - margin - column * (self.width() + gap)
            y = area.top() + margin + row * (self.height() + gap)
            self.move(x, y)

    def present(self) -> None:
        self.show()
        self.raise_()
        self.activateWindow()

    def _submit_decision(self, decision: str) -> None:
        if self._decision_sent:
            return
        self._decision_sent = True
        self._timer.stop()
        self._on_decision(self._request["approval_id"], decision)
        self.hide()

    def _update_countdown(self) -> None:
        remaining = _remaining_seconds(
            str(self._request.get("timestamp", "")), self._timeout_seconds
        )
        self._countdown.setText(
            "Proxy timeout in "
            f"{remaining // 60:02d}:{remaining % 60:02d} "
            "— timeout is enforced by the proxy."
        )

    def dismiss(self) -> None:
        self._timer.stop()
        self.hide()
        self.close()

    def closeEvent(self, event: Any) -> None:
        if not self._decision_sent:
            event.ignore()
            self.hide()
            return
        event.accept()


def _detail(label: str, value: str) -> QWidget:
    container = QWidget()
    layout = QVBoxLayout(container)
    layout.setContentsMargins(0, 3, 0, 3)
    title = QLabel(label)
    title.setStyleSheet("color: #8290a6; font-size: 8pt; font-weight: 700;")
    content = QLabel(value)
    content.setWordWrap(True)
    content.setStyleSheet("font-size: 10pt; font-weight: 600;")
    layout.addWidget(title)
    layout.addWidget(content)
    return container


class MainWindow(QMainWindow):
    def __init__(self, *, demo_mode: bool = False) -> None:
        super().__init__()
        self._demo_mode = demo_mode
        self._settings = QSettings("MCP Security Guard", "MCP Security Guard")
        self._worker: ControlWorker | None = None
        self._pending: dict[str, dict[str, Any]] = {}
        self._popups: dict[str, ApprovalPopup] = {}
        self._popup_counter = 0
        self._history: list[dict[str, Any]] = []
        self._allow_popups = True
        self._explicit_exit = False
        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(_make_icon())
        self.resize(1240, 810)
        self.setMinimumSize(980, 650)
        self._build_ui()
        self._build_tray()
        self._load_settings()
        if demo_mode:
            self._show_demo_visual()
        elif os.environ.get("MCP_GUARD_APPROVAL_TOKEN"):
            self.token_input.setText(os.environ["MCP_GUARD_APPROVAL_TOKEN"])
            self._connect_monitoring()

    def _build_ui(self) -> None:
        central = QWidget()
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(238)
        side_layout = QVBoxLayout(sidebar)
        side_layout.setContentsMargins(16, 22, 16, 20)
        brand = QHBoxLayout()
        mark = QLabel("G")
        mark.setObjectName("BrandMark")
        mark.setAlignment(Qt.AlignmentFlag.AlignCenter)
        mark.setFixedSize(38, 38)
        brand_title = QVBoxLayout()
        product = QLabel("MCP Security Guard")
        product.setObjectName("BrandTitle")
        caption = QLabel("Approval control center")
        caption.setObjectName("BrandSub")
        brand_title.addWidget(product)
        brand_title.addWidget(caption)
        brand.addWidget(mark)
        brand.addSpacing(9)
        brand.addLayout(brand_title)
        side_layout.addLayout(brand)
        side_layout.addSpacing(34)
        self._nav_buttons: list[QPushButton] = []
        self._stack = QStackedWidget()
        for index, (name, title) in enumerate(
            (("Dashboard", "Dashboard"), ("Requests", "Requests"), ("History", "History"), ("Settings", "Settings"))
        ):
            button = QPushButton(name)
            button.setObjectName("NavButton")
            button.setProperty("active", index == 0)
            button.clicked.connect(lambda checked=False, page=index: self._navigate(page))
            side_layout.addWidget(button)
            self._nav_buttons.append(button)
        side_layout.addStretch(1)
        side_status = QLabel("●  Local approval channel")
        side_status.setStyleSheet("color: #718099; font-size: 8pt;")
        side_layout.addWidget(side_status)
        root.addWidget(sidebar)

        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(32, 26, 32, 18)
        content_layout.setSpacing(18)
        top = QHBoxLayout()
        heading_box = QVBoxLayout()
        self.page_title = QLabel("Dashboard")
        self.page_title.setObjectName("PageTitle")
        self.page_subtitle = QLabel("Live overview of approval-gated MCP activity")
        self.page_subtitle.setObjectName("PageSubtitle")
        heading_box.addWidget(self.page_title)
        heading_box.addWidget(self.page_subtitle)
        top.addLayout(heading_box)
        top.addStretch(1)
        self.status_badge = QLabel("NOT CONNECTED")
        self.status_badge.setObjectName("StatusDisconnected")
        top.addWidget(self.status_badge, 0, Qt.AlignmentFlag.AlignVCenter)
        self.connect_button = QPushButton("Connect proxy")
        self.connect_button.setObjectName("PrimaryButton")
        self.connect_button.clicked.connect(self._toggle_monitoring)
        top.addWidget(self.connect_button, 0, Qt.AlignmentFlag.AlignVCenter)
        content_layout.addLayout(top)
        self.demo_banner = QLabel()
        self.demo_banner.setVisible(False)
        self.demo_banner.setStyleSheet(
            "color: #ffe28a; background: #423616; border: 1px solid #796125;"
            "border-radius: 8px; padding: 10px; font-weight: 800;"
        )
        content_layout.addWidget(self.demo_banner)

        self.dashboard_page = self._build_dashboard_page()
        self.requests_page = self._build_requests_page()
        self.history_page = self._build_history_page()
        self.settings_page = self._build_settings_page()
        for page in (
            self.dashboard_page,
            self.requests_page,
            self.history_page,
            self.settings_page,
        ):
            self._stack.addWidget(page)
        content_layout.addWidget(self._stack, 1)
        self.setStatusBar(self.statusBar())
        self.statusBar().showMessage("Ready")
        root.addWidget(content, 1)
        self.setCentralWidget(central)

    def _build_dashboard_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        cards = QHBoxLayout()
        self.monitor_value = QLabel("Idle")
        self.pending_value = QLabel("0")
        self.history_value = QLabel("0")
        for title, value, note in (
            ("MONITORING", self.monitor_value, "Connected to local proxy"),
            ("PENDING REQUESTS", self.pending_value, "Awaiting your decision"),
            ("RECENT DECISIONS", self.history_value, "Recorded by the proxy"),
        ):
            card = QFrame()
            card.setObjectName("Card")
            card_layout = QVBoxLayout(card)
            label = QLabel(title)
            label.setObjectName("CardLabel")
            value.setObjectName("CardValue")
            note_label = QLabel(note)
            note_label.setObjectName("Muted")
            card_layout.addWidget(label)
            card_layout.addWidget(value)
            card_layout.addWidget(note_label)
            cards.addWidget(card, 1)
        layout.addLayout(cards)
        self.connection_detail = QLabel(
            "Start the configured MCP host to launch the Guard proxy. Enter the same "
            "MCP_GUARD_APPROVAL_TOKEN in this app and the host configuration."
        )
        self.connection_detail.setWordWrap(True)
        self.connection_detail.setStyleSheet(
            "color: #ffc47d; background: #3a2a19; border: 1px solid #72502a;"
            "border-radius: 8px; padding: 10px;"
        )
        layout.addWidget(self.connection_detail)
        section = QHBoxLayout()
        title = QLabel("Live approval queue")
        title.setObjectName("SectionTitle")
        section.addWidget(title)
        section.addStretch(1)
        view_all = QPushButton("View requests")
        view_all.clicked.connect(lambda: self._navigate(1))
        section.addWidget(view_all)
        layout.addLayout(section)
        self.dashboard_scroll = _scroll_container()
        self.dashboard_requests = self.dashboard_scroll.widget().layout()
        layout.addWidget(self.dashboard_scroll, 1)
        return page

    def _build_requests_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        header = QLabel("Each request remains isolated by its approval ID.")
        header.setObjectName("PageSubtitle")
        layout.addWidget(header)
        self.requests_scroll = _scroll_container()
        self.requests_layout = self.requests_scroll.widget().layout()
        layout.addWidget(self.requests_scroll, 1)
        return page

    def _build_history_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        message = QLabel("Recent decisions and timeout outcomes reported by the proxy.")
        message.setObjectName("PageSubtitle")
        layout.addWidget(message)
        self.history_scroll = _scroll_container()
        self.history_layout = self.history_scroll.widget().layout()
        layout.addWidget(self.history_scroll, 1)
        return page

    def _build_settings_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        intro = QLabel(
            "Connect the desktop approval app to the local MCP proxy."
        )
        intro.setObjectName("PageSubtitle")
        layout.addWidget(intro)
        card = QFrame()
        card.setObjectName("SettingCard")
        form = QVBoxLayout(card)
        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("127.0.0.1")
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(8765)
        self.timeout_input = QSpinBox()
        self.timeout_input.setRange(1, 3600)
        self.timeout_input.setValue(120)
        self.token_input = QLineEdit()
        self.token_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.token_input.setPlaceholderText("MCP_GUARD_APPROVAL_TOKEN")
        form.addWidget(_field("Control host (loopback only)", self.host_input))
        form.addWidget(_field("Control port", self.port_input))
        form.addWidget(_field("Approval timeout shown in popups (seconds)", self.timeout_input))
        form.addWidget(_field("Session approval token (not saved)", self.token_input))
        actions = QHBoxLayout()
        save = QPushButton("Save settings")
        save.clicked.connect(self._save_settings)
        actions.addWidget(save)
        actions.addStretch(1)
        form.addLayout(actions)
        layout.addWidget(card)
        info = QFrame()
        info.setObjectName("SettingCard")
        info_layout = QVBoxLayout(info)
        info_title = QLabel("Connect your MCP host")
        info_title.setObjectName("SectionTitle")
        info_layout.addWidget(info_title)
        info_copy = QLabel(
            "Configure your MCP host to launch the bundled `mcp-security-guard-proxy.exe` "
            "with its real upstream MCP server command. The proxy must use the same "
            "loopback port, bearer token, and timeout configured here. The MCP host "
            "supplies the proxy input and output streams. This desktop app does not "
            "use a browser extension."
        )
        info_copy.setObjectName("Muted")
        info_copy.setWordWrap(True)
        info_layout.addWidget(info_copy)
        layout.addWidget(info)
        layout.addStretch(1)
        return page

    def _build_tray(self) -> None:
        self._tray = QSystemTrayIcon(self.windowIcon(), self)
        self._tray.setToolTip(APP_NAME)
        menu = QMenu(self)
        show_action = QAction("Open MCP Security Guard", self)
        show_action.triggered.connect(self._restore_from_tray)
        menu.addAction(show_action)
        menu.addSeparator()
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self._exit_application)
        menu.addAction(exit_action)
        self._tray.setContextMenu(menu)
        self._tray.activated.connect(self._tray_activated)
        if QSystemTrayIcon.isSystemTrayAvailable():
            self._tray.show()

    def _load_settings(self) -> None:
        self.host_input.setText(str(self._settings.value("control_host", "127.0.0.1")))
        self.port_input.setValue(int(self._settings.value("control_port", 8765)))
        self.timeout_input.setValue(int(self._settings.value("approval_timeout", 120)))

    def _save_settings(self) -> None:
        host = self.host_input.text().strip()
        try:
            if not ipaddress.ip_address(host).is_loopback:
                raise ValueError("Host must be a loopback IP address.")
        except ValueError as exc:
            QMessageBox.warning(
                self,
                "Invalid control host",
                "Use a loopback IP address such as 127.0.0.1 or ::1.",
            )
            return
        self._settings.setValue("control_host", host)
        self._settings.setValue("control_port", self.port_input.value())
        self._settings.setValue("approval_timeout", self.timeout_input.value())
        self.statusBar().showMessage("Settings saved. The token is kept in memory only.", 5000)

    def _connect_monitoring(self) -> None:
        if self._demo_mode:
            return
        host = self.host_input.text().strip()
        try:
            if not ipaddress.ip_address(host).is_loopback:
                raise ValueError("Control host must be loopback.")
        except ValueError:
            QMessageBox.warning(self, "Invalid control host", "Only loopback IPs are allowed.")
            return
        token = self.token_input.text().strip()
        if len(token) < 16:
            QMessageBox.warning(
                self, "Approval token required", "Enter the proxy token (at least 16 characters)."
            )
            self._navigate(3)
            return
        self._save_settings()
        self._worker = ControlWorker(host, self.port_input.value(), token)
        self._worker.pending_changed.connect(self._on_pending_changed)
        self._worker.history_changed.connect(self._on_history_changed)
        self._worker.connection_changed.connect(self._on_connection_changed)
        self._worker.decision_completed.connect(self._on_decision_completed)
        self._worker.start()
        self.connect_button.setText("Disconnect")
        self.statusBar().showMessage("Connecting to the configured MCP proxy…")

    def _disconnect_monitoring(self) -> None:
        worker = self._worker
        self._worker = None
        if worker is not None:
            worker.requestInterruption()
            worker.wait(9000)
            worker.deleteLater()
        for popup in tuple(self._popups.values()):
            popup.dismiss()
        self._popups.clear()
        self._pending.clear()
        self._render_pending()
        self._on_connection_changed(False, "Disconnected by user")
        self.connect_button.setText("Connect proxy")

    def _toggle_monitoring(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._disconnect_monitoring()
        else:
            self._connect_monitoring()

    def _on_connection_changed(self, connected: bool, message: str) -> None:
        self.monitor_value.setText("Live" if connected else "Offline")
        self.status_badge.setText("PROXY CONNECTED" if connected else "NOT CONNECTED")
        self.status_badge.setObjectName(
            "StatusConnected" if connected else "StatusDisconnected"
        )
        self.status_badge.style().unpolish(self.status_badge)
        self.status_badge.style().polish(self.status_badge)
        self.status_badge.setToolTip(message)
        self.statusBar().showMessage(message)
        if connected:
            self.connection_detail.setText("Connected to the MCP approval proxy.")
            self.connection_detail.setStyleSheet(
                "color: #63e3ac; background: #103327; border: 1px solid #1d5f47;"
                "border-radius: 8px; padding: 10px;"
            )
        elif message == "Disconnected by user":
            self.connection_detail.setText("Monitoring stopped. Start monitoring when the proxy is running.")
            self.connection_detail.setStyleSheet(
                "color: #a7b3c7; background: #263348; border: 1px solid #35445a;"
                "border-radius: 8px; padding: 10px;"
            )
        else:
            self.connection_detail.setText(
                f"{message} Start or restart the MCP host configured to launch the "
                "Guard proxy. The token only authenticates the connection; it does "
                "not start the proxy. Check that the app and proxy use the same "
                "loopback host and port."
            )
            self.connection_detail.setStyleSheet(
                "color: #ffc47d; background: #3a2a19; border: 1px solid #72502a;"
                "border-radius: 8px; padding: 10px;"
            )
        if self._worker is not None:
            self.connect_button.setText("Disconnect")

    def _on_pending_changed(self, pending: list[dict[str, Any]]) -> None:
        valid = {
            str(request["approval_id"]): request
            for request in pending
            if isinstance(request, dict) and isinstance(request.get("approval_id"), str)
        }
        for approval_id in set(self._popups) - set(valid):
            self._popups.pop(approval_id).dismiss()
        self._pending = valid
        self._render_pending()
        if self._allow_popups:
            for approval_id, request in valid.items():
                if approval_id not in self._popups:
                    self._popup_counter += 1
                    popup = ApprovalPopup(
                        request,
                        self.timeout_input.value(),
                        self._request_decision,
                        self._popup_counter,
                    )
                    self._popups[approval_id] = popup
                    popup.present()
                    if self._tray.isVisible():
                        self._tray.showMessage(
                            "MCP tool call awaiting approval",
                            f"{request.get('tool_name', 'Unknown tool')} on "
                            f"{request.get('server_name', 'Unknown server')}",
                            QSystemTrayIcon.MessageIcon.Warning,
                            8000,
                        )

    def _render_pending(self) -> None:
        self.pending_value.setText(str(len(self._pending)))
        self._clear_layout(self.dashboard_requests)
        self._clear_layout(self.requests_layout)
        if not self._pending:
            empty = _empty_state("No pending requests", "Real MCP tool calls appear here when the proxy is connected.")
            self.dashboard_requests.addWidget(empty)
            self.requests_layout.addWidget(
                _empty_state("Queue is clear", "The next intercepted tools/call will appear here.")
            )
            return
        timeout = self.timeout_input.value()
        for request in self._pending.values():
            self.dashboard_requests.addWidget(
                RequestCard(request, timeout, self._request_decision)
            )
            self.requests_layout.addWidget(
                RequestCard(request, timeout, self._request_decision)
            )
        self.dashboard_requests.addStretch(1)
        self.requests_layout.addStretch(1)

    def _on_history_changed(self, history: list[dict[str, Any]]) -> None:
        self._history = [entry for entry in history if isinstance(entry, dict)]
        self.history_value.setText(str(len(self._history)))
        self._clear_layout(self.history_layout)
        if not self._history:
            self.history_layout.addWidget(
                _empty_state("No history yet", "Proxy decisions and timeouts are recorded here.")
            )
            return
        for entry in reversed(self._history):
            self.history_layout.addWidget(_history_card(entry))
        self.history_layout.addStretch(1)

    def _request_decision(self, approval_id: str, decision: str) -> None:
        if self._worker is None or not self._worker.isRunning():
            self.statusBar().showMessage("Not connected to an approval service.", 5000)
            return
        self._worker.decide(approval_id, decision)
        popup = self._popups.get(approval_id)
        if popup is not None:
            popup.hide()
        self.statusBar().showMessage(
            f"Sending {'Allow' if decision == 'approve' else 'Block'} for {approval_id[:8]}…"
        )

    def _on_decision_completed(
        self, approval_id: str, decision: str, accepted: bool, message: str
    ) -> None:
        popup = self._popups.pop(approval_id, None)
        if popup is not None:
            popup.dismiss()
        self.statusBar().showMessage(message, 5000)
        if not accepted:
            QMessageBox.warning(self, "Decision not accepted", message)

    def _navigate(self, page: int) -> None:
        self._stack.setCurrentIndex(page)
        titles = (
            ("Dashboard", "Live overview of approval-gated MCP activity"),
            ("Requests", "Review and decide each paused MCP tool call"),
            ("History", "Recent proxy decisions and outcomes"),
            ("Settings", "Configure the local approval connection"),
        )
        title, subtitle = titles[page]
        self.page_title.setText(title)
        self.page_subtitle.setText(subtitle)
        for index, button in enumerate(self._nav_buttons):
            button.setProperty("active", index == page)
            button.style().unpolish(button)
            button.style().polish(button)

    def _restore_from_tray(self) -> None:
        self.showNormal()
        self.show()
        self.raise_()
        self.activateWindow()

    def _tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason in (
            QSystemTrayIcon.ActivationReason.DoubleClick,
            QSystemTrayIcon.ActivationReason.Trigger,
        ):
            self._restore_from_tray()

    def _exit_application(self) -> None:
        if self._pending:
            answer = QMessageBox.question(
                self,
                "Exit MCP Security Guard?",
                f"{len(self._pending)} request(s) are awaiting a decision. "
                "Exiting will leave them to the proxy's approval timeout; none will "
                "be approved automatically. Exit anyway?",
                QMessageBox.StandardButton.Exit | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel,
            )
            if answer != QMessageBox.StandardButton.Exit:
                return
        self._explicit_exit = True
        self._disconnect_monitoring()
        self._tray.hide()
        QApplication.quit()

    def closeEvent(self, event: Any) -> None:
        if self._explicit_exit or not self._tray.isVisible():
            self._disconnect_monitoring()
            event.accept()
            QApplication.quit()
            return
        event.ignore()
        self.hide()
        self._tray.showMessage(
            APP_NAME,
            "Still monitoring the MCP proxy. Select the tray icon to restore.",
            QSystemTrayIcon.MessageIcon.Information,
            3000,
        )

    def changeEvent(self, event: Any) -> None:
        super().changeEvent(event)
        if (
            event.type() == QEvent.Type.WindowStateChange
            and self.isMinimized()
            and getattr(self, "_tray", None) is not None
            and self._tray.isVisible()
        ):
            QTimer.singleShot(0, self.hide)

    def _show_demo_visual(self) -> None:
        self.demo_banner.setText(
            "VISUAL DEMO ONLY — synthetic display data; no proxy connection or tool execution"
        )
        self.demo_banner.setVisible(True)
        self.status_badge.setText("DEMO MODE")
        self.status_badge.setObjectName("StatusDemo")
        self.status_badge.style().unpolish(self.status_badge)
        self.status_badge.style().polish(self.status_badge)
        self.monitor_value.setText("Demo")
        self.connect_button.setEnabled(False)
        self._clear_layout(self.dashboard_requests)
        visual_only = QLabel(
            "VISUAL DEMO — Example: read_file on sample-files. This card is not a request "
            "and its buttons are disabled."
        )
        visual_only.setWordWrap(True)
        visual_only.setStyleSheet(
            "color: #ffe28a; background: #423616; border: 1px solid #796125;"
            "border-radius: 10px; padding: 18px;"
        )
        self.dashboard_requests.addWidget(visual_only)
        self.dashboard_requests.addStretch(1)
        self._clear_layout(self.requests_layout)
        self.requests_layout.addWidget(
            _empty_state(
                "Demo display only",
                "No MCP server is connected. Launch without --demo to monitor real proxy requests.",
            )
        )
        self._clear_layout(self.history_layout)
        self.history_layout.addWidget(
            _empty_state("No real history", "Demo mode never creates audit entries.")
        )
        self.statusBar().showMessage("Visual demo mode — no connection and no tool calls")

    @staticmethod
    def _clear_layout(layout: Any) -> None:
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
            elif item.layout() is not None:
                MainWindow._clear_layout(item.layout())


def _scroll_container() -> QScrollArea:
    scroll = QScrollArea()
    scroll.setWidgetResizable(True)
    container = QWidget()
    layout = QVBoxLayout(container)
    layout.setContentsMargins(1, 1, 8, 1)
    layout.setSpacing(12)
    scroll.setWidget(container)
    return scroll


def _empty_state(title: str, detail: str) -> QWidget:
    card = QFrame()
    card.setObjectName("Card")
    layout = QVBoxLayout(card)
    heading = QLabel(title)
    heading.setObjectName("SectionTitle")
    description = QLabel(detail)
    description.setObjectName("Muted")
    description.setWordWrap(True)
    layout.addWidget(heading)
    layout.addWidget(description)
    return card


def _history_card(entry: dict[str, Any]) -> QWidget:
    card = QFrame()
    card.setObjectName("RequestCard")
    layout = QVBoxLayout(card)
    top = QHBoxLayout()
    tool = QLabel(str(entry.get("tool_name", "Unknown tool")))
    tool.setObjectName("SectionTitle")
    status_text = str(entry.get("status", "unknown")).replace("_", " ").upper()
    colors = {
        "APPROVE": ("#63e3ac", "#103327"),
        "DENY": ("#ff9da5", "#442129"),
        "TIMEOUT": ("#ffc47d", "#3a2a19"),
        "CANCELLED": ("#a7b3c7", "#263348"),
    }
    foreground, background = colors.get(status_text, ("#a7b3c7", "#263348"))
    top.addWidget(tool)
    top.addStretch(1)
    top.addWidget(_badge(status_text, foreground, background))
    layout.addLayout(top)
    layout.addWidget(
        QLabel(
            f"{entry.get('origin_application', 'Unknown MCP client')}  ·  "
            f"{entry.get('server_name', 'Unknown server')}  ·  "
            f"Request ID: {entry.get('request_id')}"
        )
    )
    timestamp = QLabel(_format_timestamp(str(entry.get("timestamp", ""))))
    timestamp.setObjectName("Muted")
    layout.addWidget(timestamp)
    return card


def _field(label: str, editor: QWidget) -> QWidget:
    wrapper = QWidget()
    layout = QVBoxLayout(wrapper)
    layout.setContentsMargins(0, 5, 0, 5)
    heading = QLabel(label)
    heading.setStyleSheet("color: #a9b5c8; font-weight: 600;")
    layout.addWidget(heading)
    layout.addWidget(editor)
    return wrapper


def main() -> None:
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Show clearly labeled visual-only example data; never connects to a proxy.",
    )
    args = parser.parse_args()
    app = QApplication(sys.argv[:1])
    app.setApplicationName(APP_NAME)
    app.setOrganizationName(APP_NAME)
    app.setQuitOnLastWindowClosed(False)
    app.setWindowIcon(_make_icon())
    app.setStyleSheet(STYLESHEET)
    window = MainWindow(demo_mode=args.demo)
    window.show()
    if not QSystemTrayIcon.isSystemTrayAvailable():
        window.statusBar().showMessage(
            "System tray is unavailable; closing the window exits the application."
        )
    raise SystemExit(app.exec())


if __name__ == "__main__":
    main()