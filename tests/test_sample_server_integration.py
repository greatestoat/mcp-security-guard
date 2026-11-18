import asyncio
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

from test_proxy_integration import control_request


ROOT = Path(__file__).resolve().parents[1]
TOKEN = "test-approval-token-123456"


class SampleServerIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.sample_root = Path(self.temp_dir.name)
        (self.sample_root / "hello.txt").write_text("sample content", encoding="utf-8")
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
        env["MCP_GUARD_APPROVAL_TOKEN"] = TOKEN
        self.process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "mcp_security_guard",
            "proxy",
            "--server-name",
            "sdk-sample-filesystem",
            "--approval-timeout",
            "5",
            "--control-port",
            "0",
            "--",
            sys.executable,
            "-m",
            "mcp_security_guard.sample_server",
            "--root",
            str(self.sample_root),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        self.addAsyncCleanup(self._cleanup_process)
        self.control_port = await self._read_control_port()

    async def asyncTearDown(self) -> None:
        await self._cleanup_process()
        self.temp_dir.cleanup()

    async def _cleanup_process(self) -> None:
        if self.process.returncode is None:
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), timeout=3)
            except TimeoutError:
                self.process.kill()
                await self.process.wait()

    async def test_sdk_filesystem_server_is_discovered_and_approved_call_runs(self) -> None:
        await self._send(
            {
                "jsonrpc": "2.0",
                "id": 31,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "sample-test-client", "version": "1.0"},
                },
            }
        )
        initialize = await self._read_response()
        self.assertEqual(initialize["id"], 31)
        self.assertIn("result", initialize)
        await self._send(
            {"jsonrpc": "2.0", "method": "notifications/initialized"}
        )

        await self._send({"jsonrpc": "2.0", "id": 32, "method": "tools/list"})
        discovery = await self._read_response()
        self.assertEqual(discovery["id"], 32)
        names = {tool["name"] for tool in discovery["result"]["tools"]}
        self.assertEqual(names, {"list_files", "read_file"})

        await self._send(
            {
                "jsonrpc": "2.0",
                "id": 33,
                "method": "tools/call",
                "params": {"name": "list_files", "arguments": {"path": "."}},
            }
        )
        pending = await self._wait_for_pending()
        self.assertEqual(pending["tool_name"], "list_files")
        await control_request(
            self.control_port,
            "POST",
            f"/requests/{pending['approval_id']}/decision",
            {"decision": "approve"},
        )
        result = await self._read_response()
        self.assertEqual(result["id"], 33)
        self.assertIn("hello.txt", json.dumps(result))

    async def _read_control_port(self) -> int:
        if self.process.stderr is None:
            raise AssertionError("stderr pipe not available")
        while True:
            line = await asyncio.wait_for(self.process.stderr.readline(), timeout=10)
            if not line:
                raise AssertionError("Proxy exited before starting the control API")
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event") == "approval_control_endpoint":
                return int(event["control_port"])

    async def _send(self, message: dict[str, Any]) -> None:
        if self.process.stdin is None:
            raise AssertionError("stdin pipe not available")
        self.process.stdin.write(
            (json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8")
        )
        await self.process.stdin.drain()

    async def _read_response(self) -> dict[str, Any]:
        if self.process.stdout is None:
            raise AssertionError("stdout pipe not available")
        try:
            line = await asyncio.wait_for(self.process.stdout.readline(), timeout=5)
        except TimeoutError as exc:
            diagnostic = b""
            if self.process.stderr is not None:
                try:
                    diagnostic = await asyncio.wait_for(
                        self.process.stderr.read(4096), timeout=0.2
                    )
                except TimeoutError:
                    pass
            raise AssertionError(
                f"Proxy did not return a response; stderr={diagnostic.decode(errors='replace')}"
            ) from exc
        if not line:
            raise AssertionError("Proxy closed stdout before returning a response")
        return json.loads(line)

    async def _wait_for_pending(self) -> dict[str, Any]:
        for _ in range(100):
            result = await control_request(self.control_port, "GET", "/pending")
            if result["pending"]:
                return result["pending"][0]
            await asyncio.sleep(0.02)
        self.fail("Timed out waiting for the SDK server tool call")


if __name__ == "__main__":
    unittest.main()
