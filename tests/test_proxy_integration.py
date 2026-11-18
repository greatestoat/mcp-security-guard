import asyncio
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TOKEN = "test-approval-token-123456"


async def control_request(
    port: int, method: str, path: str, payload: dict[str, Any] | None = None
) -> dict[str, Any]:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    body = json.dumps(payload).encode("utf-8") if payload is not None else b""
    request = (
        f"{method} {path} HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        f"Authorization: Bearer {TOKEN}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii") + body
    writer.write(request)
    await writer.drain()
    status_line = await reader.readline()
    status = int(status_line.split(b" ")[1])
    headers: dict[str, str] = {}
    while True:
        line = await reader.readline()
        if line in (b"\r\n", b"\n"):
            break
        name, value = line.decode("ascii").split(":", 1)
        headers[name.lower()] = value.strip()
    response = await reader.readexactly(int(headers["content-length"]))
    writer.close()
    await writer.wait_closed()
    if status >= 400:
        raise AssertionError(f"Control API returned {status}: {response!r}")
    return json.loads(response)


class ProxyIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.call_log = Path(self.temp_dir.name) / "calls.jsonl"
        env = os.environ.copy()
        src_path = str(ROOT / "src")
        env["PYTHONPATH"] = src_path + os.pathsep + str(ROOT) + os.pathsep + env.get(
            "PYTHONPATH", ""
        )
        env["MCP_GUARD_APPROVAL_TOKEN"] = TOKEN
        env["FAKE_MCP_CALL_LOG"] = str(self.call_log)
        self.process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "mcp_security_guard",
            "proxy",
            "--server-name",
            "integration-test-server",
            "--approval-timeout",
            "1.0",
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
        self.addAsyncCleanup(self._cleanup_process)
        self.control_port = await self._read_control_port()
        await self._exchange(
            {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "test-client", "version": "1.0"},
                },
            },
            expected_id=7,
        )
        await self._send(
            {"jsonrpc": "2.0", "method": "notifications/initialized"}
        )
        await self._exchange(
            {"jsonrpc": "2.0", "id": 8, "method": "tools/list"},
            expected_id=8,
        )

    async def asyncTearDown(self) -> None:
        self.temp_dir.cleanup()

    async def _cleanup_process(self) -> None:
        if self.process.returncode is None:
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), timeout=3)
            except TimeoutError:
                self.process.kill()
                await self.process.wait()

    async def test_approval_and_denial_are_isolated_and_denied_call_never_runs(self) -> None:
        await self._send_tool_call(11, "approved")
        await self._send_tool_call(12, "denied")

        pending = await self._wait_for_pending(2)
        self.assertEqual({item["request_id"] for item in pending}, {11, 12})
        self.assertEqual(
            {item["tool_name"] for item in pending},
            {"echo"},
        )
        self.assertTrue(all(item["server_name"] == "integration-test-server" for item in pending))
        self.assertTrue(all("timestamp" in item for item in pending))
        self.assertFalse(self.call_log.exists(), "Calls must wait for explicit approval")

        by_text = {item["arguments"]["text"]: item for item in pending}
        await control_request(
            self.control_port,
            "POST",
            f"/requests/{by_text['approved']['approval_id']}/decision",
            {"decision": "approve"},
        )
        await control_request(
            self.control_port,
            "POST",
            f"/requests/{by_text['denied']['approval_id']}/decision",
            {"decision": "deny"},
        )

        responses = {
            response["id"]: response
            for response in (
                await self._read_response(),
                await self._read_response(),
            )
        }
        self.assertEqual(responses[11]["result"]["content"][0]["text"], "approved")
        self.assertEqual(responses[12]["error"]["code"], -32001)
        self.assertEqual(self.call_log.read_text(encoding="utf-8").splitlines(), [
            '{"name": "echo", "arguments": {"text": "approved"}}'
        ])

    async def test_timeout_denies_and_never_forwards_unapproved_call(self) -> None:
        await self._send_tool_call(21, "wait for timeout")
        response = await self._read_response(timeout=3)
        self.assertEqual(response["id"], 21)
        self.assertEqual(response["error"]["code"], -32002)
        self.assertFalse(self.call_log.exists())

    async def test_cancellation_removes_pending_call_without_forwarding(self) -> None:
        await self._send_tool_call(22, "cancel before approval")
        pending = await self._wait_for_pending(1)
        queued = await control_request(self.control_port, "GET", "/next")
        self.assertEqual(queued["request"]["approval_id"], pending[0]["approval_id"])
        await self._send(
            {
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {"requestId": 22, "reason": "client cancelled"},
            }
        )
        response = await self._read_response()
        self.assertEqual(response["id"], 22)
        self.assertEqual(response["error"]["code"], -32800)
        self.assertFalse(self.call_log.exists())
        self.assertEqual(
            (await control_request(self.control_port, "GET", "/pending"))["pending"],
            [],
        )
        self.assertEqual(pending[0]["status"], "pending")

    async def _read_control_port(self) -> int:
        if self.process.stderr is None:
            raise AssertionError("stderr pipe not available")
        while True:
            line = await asyncio.wait_for(self.process.stderr.readline(), timeout=5)
            if not line:
                raise AssertionError("Proxy exited before starting the control API")
            event = json.loads(line)
            if event.get("event") == "approval_control_endpoint":
                self.assertEqual(event["control_host"], "127.0.0.1")
                return int(event["control_port"])

    async def _send(self, message: dict[str, Any]) -> None:
        if self.process.stdin is None:
            raise AssertionError("stdin pipe not available")
        self.process.stdin.write(
            (json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8")
        )
        await self.process.stdin.drain()

    async def _exchange(
        self, message: dict[str, Any], *, expected_id: int
    ) -> dict[str, Any]:
        await self._send(message)
        response = await self._read_response()
        self.assertEqual(response.get("id"), expected_id)
        self.assertNotIn("error", response)
        return response

    async def _send_tool_call(self, request_id: int, text: str) -> None:
        await self._send(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "tools/call",
                "params": {"name": "echo", "arguments": {"text": text}},
            }
        )

    async def _read_response(self, timeout: float = 2) -> dict[str, Any]:
        if self.process.stdout is None:
            raise AssertionError("stdout pipe not available")
        line = await asyncio.wait_for(self.process.stdout.readline(), timeout=timeout)
        if not line:
            raise AssertionError("Proxy closed stdout before returning a response")
        return json.loads(line)

    async def _wait_for_pending(self, expected: int) -> list[dict[str, Any]]:
        for _ in range(50):
            result = await control_request(
                self.control_port, "GET", "/pending"
            )
            pending = result["pending"]
            if len(pending) >= expected:
                return pending
            await asyncio.sleep(0.02)
        self.fail(f"Timed out waiting for {expected} pending requests")


if __name__ == "__main__":
    unittest.main()
