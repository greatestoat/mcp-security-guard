import asyncio
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QSettings, Qt
from PySide6.QtWidgets import QApplication, QPushButton

from mcp_security_guard.gui import MainWindow


ROOT = Path(__file__).resolve().parents[1]
TOKEN = "gui-end-to-end-approval-token"


class DesktopApprovalEndToEndTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])
        cls.app.setQuitOnLastWindowClosed(False)

    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.call_log = Path(self.temp_dir.name) / "calls.jsonl"
        env = os.environ.copy()
        env["PYTHONPATH"] = (
            str(ROOT / "src")
            + os.pathsep
            + str(ROOT)
            + os.pathsep
            + env.get("PYTHONPATH", "")
        )
        env["MCP_GUARD_APPROVAL_TOKEN"] = TOKEN
        env["FAKE_MCP_CALL_LOG"] = str(self.call_log)
        self.proxy = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "mcp_security_guard",
            "proxy",
            "--server-name",
            "gui-e2e-server",
            "--approval-timeout",
            "8",
            "--control-port",
            "0",
            "--",
            sys.executable,
            "-m",
            "tests.fake_mcp_server",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        self.addAsyncCleanup(self._cleanup)
        self.port = await self._read_control_port()
        self.window = MainWindow()
        self.window._settings = QSettings(
            str(Path(self.temp_dir.name) / "settings.ini"),
            QSettings.Format.IniFormat,
        )
        self.window.host_input.setText("127.0.0.1")
        self.window.port_input.setValue(self.port)
        self.window.timeout_input.setValue(8)
        self.window.token_input.setText(TOKEN)
        self.window.show()
        self.window._connect_monitoring()
        await self._spin_until(
            lambda: self.window.status_badge.text() == "PROXY CONNECTED", timeout=5
        )
        await self._send(
            {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "E2E Desktop Client", "version": "1.0"},
                },
            }
        )
        self.assertEqual((await self._read_response())["id"], 7)
        await self._send(
            {"jsonrpc": "2.0", "method": "notifications/initialized"}
        )

    async def asyncTearDown(self) -> None:
        if hasattr(self, "window"):
            self.window._disconnect_monitoring()
            self.window._explicit_exit = True
            self.window.close()
            self.window.deleteLater()
        self.temp_dir.cleanup()

    async def _cleanup(self) -> None:
        if self.proxy.returncode is None:
            self.proxy.terminate()
            try:
                await asyncio.wait_for(self.proxy.wait(), timeout=3)
            except TimeoutError:
                self.proxy.kill()
                await self.proxy.wait()

    async def test_popup_buttons_decide_the_matching_real_proxy_requests(self) -> None:
        await self._send_tool_call(101, "allow this one")
        await self._send_tool_call(102, "block this one")
        await self._spin_until(lambda: len(self.window._popups) == 2, timeout=5)

        by_text = {
            request["arguments"]["text"]: approval_id
            for approval_id, request in self.window._pending.items()
        }
        self.assertEqual(set(by_text), {"allow this one", "block this one"})
        self.assertEqual(self.window.pending_value.text(), "2")
        for request in self.window._pending.values():
            self.assertEqual(request["origin_application"], "E2E Desktop Client")
            self.assertEqual(request["server_name"], "gui-e2e-server")

        allow_id = by_text["allow this one"]
        allow_popup = self.window._popups[allow_id]
        self.assertTrue(
            allow_popup.windowFlags() & Qt.WindowType.WindowStaysOnTopHint
        )
        allow_button = next(
            button
            for button in allow_popup.findChildren(QPushButton)
            if button.text() == "Allow"
        )
        allow_button.click()
        allowed = await self._read_response()
        self.assertEqual(allowed["id"], 101)
        self.assertEqual(
            allowed["result"]["content"][0]["text"], "allow this one"
        )

        block_id = by_text["block this one"]
        block_popup = self.window._popups[block_id]
        block_button = next(
            button
            for button in block_popup.findChildren(QPushButton)
            if button.text() == "Block"
        )
        block_button.click()
        blocked = await self._read_response()
        self.assertEqual(blocked["id"], 102)
        self.assertEqual(blocked["error"]["code"], -32001)
        self.assertEqual(
            json.loads(self.call_log.read_text(encoding="utf-8").strip()),
            {"name": "echo", "arguments": {"text": "allow this one"}},
        )

    async def _read_control_port(self) -> int:
        if self.proxy.stderr is None:
            self.fail("Proxy stderr pipe unavailable")
        while True:
            line = await asyncio.wait_for(self.proxy.stderr.readline(), timeout=8)
            if not line:
                self.fail("Proxy exited before publishing the approval endpoint")
            event = json.loads(line)
            if event.get("event") == "approval_control_endpoint":
                return int(event["control_port"])

    async def _send(self, message: dict[str, Any]) -> None:
        if self.proxy.stdin is None:
            self.fail("Proxy stdin pipe unavailable")
        self.proxy.stdin.write(
            (json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8")
        )
        await self.proxy.stdin.drain()

    async def _send_tool_call(self, request_id: int, text: str) -> None:
        await self._send(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "tools/call",
                "params": {"name": "echo", "arguments": {"text": text}},
            }
        )

    async def _read_response(self) -> dict[str, Any]:
        if self.proxy.stdout is None:
            self.fail("Proxy stdout pipe unavailable")
        line = await asyncio.wait_for(self.proxy.stdout.readline(), timeout=5)
        if not line:
            self.fail("Proxy closed stdout without a response")
        return json.loads(line)

    async def _spin_until(self, predicate: Any, *, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.app.processEvents()
            if predicate():
                return
            await asyncio.sleep(0.02)
        self.fail("Timed out waiting for desktop UI state")


class VisualDemoModeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def test_demo_is_labeled_and_never_connects_or_creates_requests(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            window = MainWindow(demo_mode=True)
            window._settings = QSettings(
                str(Path(temp_dir) / "settings.ini"),
                QSettings.Format.IniFormat,
            )
            window.show()
            self.app.processEvents()
            self.assertIn("VISUAL DEMO ONLY", window.demo_banner.text())
            self.assertFalse(window.connect_button.isEnabled())
            self.assertIsNone(window._worker)
            self.assertEqual(window._pending, {})
            window._explicit_exit = True
            window.close()
            window.deleteLater()


if __name__ == "__main__":
    unittest.main()
