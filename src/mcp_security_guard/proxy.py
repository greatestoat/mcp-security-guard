import asyncio
import json
import logging
import math
import sys
import threading
import uuid
from dataclasses import dataclass
from typing import Any

from .approval import ApprovalQueue, ApprovalQueueFull, ApprovalRequest
from .control import ApprovalControlServer


logger = logging.getLogger(__name__)
_MAX_MESSAGE_BYTES = 4 * 1024 * 1024
_STOP = object()


@dataclass(frozen=True, slots=True)
class ProxyConfig:
    server_name: str
    approval_timeout: float
    control_host: str
    control_port: int
    approval_token: str
    fail_closed: bool
    upstream_command: tuple[str, ...]


class MCPProxy:
    def __init__(self, config: ProxyConfig) -> None:
        self._config = config
        self._approval_queue = ApprovalQueue()
        self._control = ApprovalControlServer(
            self._approval_queue,
            host=config.control_host,
            port=config.control_port,
            token=config.approval_token,
        )
        self._control_available = True
        self._origin_application = "Unknown MCP client"
        self._upstream: asyncio.subprocess.Process | None = None
        self._upstream_write_lock = asyncio.Lock()
        self._host_write_lock = asyncio.Lock()
        self._host_to_upstream: dict[str, dict[str, Any]] = {}
        self._upstream_to_host: dict[str, Any] = {}
        self._host_original_to_wire: dict[str, str] = {}
        self._pending_approval_by_host_id: dict[str, str] = {}
        self._call_tasks: set[asyncio.Task[None]] = set()
        self._host_messages: asyncio.Queue[bytes | object] = asyncio.Queue()
        self._closing = False

    async def run(self) -> None:
        try:
            await self._start_control_server()
            await self._start_upstream()
            self._start_host_reader()
            host_task = asyncio.create_task(self._host_loop(), name="host-stdio-reader")
            upstream_task = asyncio.create_task(
                self._upstream_loop(), name="upstream-stdio-reader"
            )
            done, pending = await asyncio.wait(
                (host_task, upstream_task), return_when=asyncio.FIRST_COMPLETED
            )
            failure: BaseException | None = None
            for task in done:
                if not task.cancelled() and task.exception() is not None:
                    failure = task.exception()
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            if failure is not None:
                raise failure
        finally:
            await self._shutdown()

    async def _start_control_server(self) -> None:
        try:
            port = await self._control.start()
        except OSError as exc:
            if self._config.fail_closed:
                raise RuntimeError("Could not start approval control server") from exc
            self._control_available = False
            logger.error(
                "approval_control_unavailable_calls_will_be_denied",
                extra={
                    "event": "approval_control_unavailable_calls_will_be_denied",
                    "error": str(exc),
                },
            )
            return
        logger.info(
            "approval_control_server_started",
            extra={"event": "approval_control_server_started"},
        )
        logger.info(
            "approval_control_endpoint",
            extra={
                "event": "approval_control_endpoint",
                "control_host": self._config.control_host,
                "control_port": port,
            },
        )

    async def _start_upstream(self) -> None:
        self._upstream = await asyncio.create_subprocess_exec(
            *self._config.upstream_command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=None,
            limit=_MAX_MESSAGE_BYTES + 1,
        )
        logger.info(
            "upstream_started",
            extra={"event": "upstream_started", "server_name": self._config.server_name},
        )

    def _start_host_reader(self) -> None:
        loop = asyncio.get_running_loop()
        queue = self._host_messages
        stream = sys.stdin.buffer

        def enqueue(item: bytes | object) -> None:
            try:
                queue.put_nowait(item)
            except RuntimeError:
                return

        def read_stdin() -> None:
            try:
                while True:
                    line = stream.readline(_MAX_MESSAGE_BYTES + 1)
                    if not line:
                        loop.call_soon_threadsafe(enqueue, _STOP)
                        return
                    if len(line) > _MAX_MESSAGE_BYTES:
                        while line and not line.endswith(b"\n"):
                            line = stream.readline(_MAX_MESSAGE_BYTES + 1)
                        loop.call_soon_threadsafe(enqueue, b"")
                    else:
                        loop.call_soon_threadsafe(enqueue, line)
            except (OSError, ValueError):
                loop.call_soon_threadsafe(enqueue, _STOP)

        threading.Thread(
            target=read_stdin, name="mcp-host-stdin", daemon=True
        ).start()

    async def _host_loop(self) -> None:
        while True:
            raw = await self._host_messages.get()
            if raw is _STOP:
                return
            if raw == b"":
                await self._send_jsonrpc_error(
                    None, -32700, "JSON-RPC message exceeds maximum size"
                )
                continue
            try:
                message = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                await self._send_jsonrpc_error(None, -32700, "Parse error")
                continue
            if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
                await self._send_jsonrpc_error(None, -32600, "Invalid Request")
                continue
            await self._handle_host_message(message)

    async def _handle_host_message(self, message: dict[str, Any]) -> None:
        if "method" not in message:
            await self._route_host_response(message)
            return
        method = message.get("method")
        if not isinstance(method, str):
            await self._send_jsonrpc_error(message.get("id"), -32600, "Invalid Request")
            return
        if "id" in message and not _valid_request_id(message["id"]):
            await self._send_jsonrpc_error(None, -32600, "Invalid Request")
            return
        if method == "notifications/cancelled":
            await self._handle_cancellation(message)
            return
        if method == "initialize":
            params = message.get("params")
            client_info = params.get("clientInfo") if isinstance(params, dict) else None
            client_name = client_info.get("name") if isinstance(client_info, dict) else None
            if isinstance(client_name, str) and client_name.strip():
                self._origin_application = client_name.strip()[:200]
        if method == "tools/call":
            await self._intercept_tool_call(message)
            return
        await self._forward_host_message(message)

    async def _intercept_tool_call(self, message: dict[str, Any]) -> None:
        params = message.get("params")
        if not isinstance(params, dict) or not isinstance(params.get("name"), str):
            if "id" in message:
                await self._send_jsonrpc_error(
                    message["id"], -32602, "tools/call requires a tool name"
                )
            return
        arguments = params.get("arguments", {})
        if not isinstance(arguments, dict):
            if "id" in message:
                await self._send_jsonrpc_error(
                    message["id"], -32602, "tools/call arguments must be an object"
                )
            return
        request_id = message.get("id")
        if "id" in message and not _valid_request_id(request_id):
            await self._send_jsonrpc_error(None, -32600, "Invalid Request")
            return
        try:
            approval = self._approval_queue.enqueue(
                origin_application=self._origin_application,
                server_name=self._config.server_name,
                tool_name=params["name"],
                arguments=dict(arguments),
                request_id=request_id,
            )
        except ApprovalQueueFull:
            if "id" in message:
                await self._send_jsonrpc_error(
                    request_id, -32005, "Approval queue is full"
                )
            return
        original_key = _request_id_key(request_id) if "id" in message else None
        if original_key is not None:
            self._pending_approval_by_host_id[original_key] = approval.approval_id
        task = asyncio.create_task(
            self._await_approval_and_forward(message, approval),
            name=f"approval-{approval.approval_id}",
        )
        self._call_tasks.add(task)
        task.add_done_callback(self._call_tasks.discard)

    async def _await_approval_and_forward(
        self, message: dict[str, Any], approval: ApprovalRequest
    ) -> None:
        request_id = message.get("id")
        original_key = _request_id_key(request_id) if "id" in message else None
        try:
            if not self._control_available:
                self._approval_queue.decide(approval.approval_id, "control_unavailable")
                decision = await self._approval_queue.wait_for_decision(
                    approval, self._config.approval_timeout
                )
            else:
                decision = await self._approval_queue.wait_for_decision(
                    approval, self._config.approval_timeout
                )
            if decision == "approve":
                await self._forward_host_message(message)
            elif "id" in message:
                if decision == "deny":
                    await self._send_jsonrpc_error(
                        request_id, -32001, "Tool call denied by MCP Security Guard"
                    )
                elif decision == "timeout":
                    await self._send_jsonrpc_error(
                        request_id, -32002, "Tool call approval timed out"
                    )
                elif decision == "cancelled":
                    await self._send_jsonrpc_error(
                        request_id, -32800, "Request cancelled"
                    )
                else:
                    await self._send_jsonrpc_error(
                        request_id, -32003, "Approval service unavailable"
                    )
        except asyncio.CancelledError:
            raise
        except (BrokenPipeError, ConnectionError, OSError) as exc:
            logger.error(
                "tool_call_forward_failed",
                extra={
                    "event": "tool_call_forward_failed",
                    "server_name": approval.server_name,
                    "tool_name": approval.tool_name,
                    "request_id": approval.request_id,
                    "error": str(exc),
                },
            )
            if "id" in message:
                await self._send_jsonrpc_error(
                    request_id, -32004, "Could not forward approved tool call"
                )
        finally:
            if original_key is not None:
                self._pending_approval_by_host_id.pop(original_key, None)

    async def _handle_cancellation(self, message: dict[str, Any]) -> None:
        params = message.get("params")
        request_id = params.get("requestId") if isinstance(params, dict) else None
        request_key = _request_id_key(request_id)
        approval_id = self._pending_approval_by_host_id.pop(request_key, None)
        if approval_id is not None:
            self._approval_queue.decide(approval_id, "cancelled")
            return
        wire_id = self._host_original_to_wire.get(request_key)
        forwarded = dict(message)
        if wire_id is not None:
            forwarded_params = dict(params)
            forwarded_params["requestId"] = wire_id
            forwarded["params"] = forwarded_params
        await self._write_upstream(forwarded)

    async def _forward_host_message(self, message: dict[str, Any]) -> None:
        if "id" not in message:
            await self._write_upstream(message)
            return
        original_id = message["id"]
        wire_id = _wire_id()
        forwarded = dict(message)
        forwarded["id"] = wire_id
        self._host_to_upstream[_request_id_key(wire_id)] = {
            "original_id": original_id,
            "original_key": _request_id_key(original_id),
        }
        self._host_original_to_wire[_request_id_key(original_id)] = wire_id
        try:
            await self._write_upstream(forwarded)
        except (BrokenPipeError, ConnectionError, OSError):
            self._host_to_upstream.pop(_request_id_key(wire_id), None)
            self._host_original_to_wire.pop(_request_id_key(original_id), None)
            raise

    async def _route_host_response(self, message: dict[str, Any]) -> None:
        response_id = message.get("id")
        upstream_id = self._upstream_to_host.pop(_request_id_key(response_id), None)
        if upstream_id is None:
            await self._write_upstream(message)
            return
        forwarded = dict(message)
        forwarded["id"] = upstream_id
        await self._write_upstream(forwarded)

    async def _upstream_loop(self) -> None:
        if self._upstream is None or self._upstream.stdout is None:
            raise RuntimeError("Upstream process was not started")
        while True:
            try:
                raw = await self._upstream.stdout.readline()
            except ValueError:
                logger.error(
                    "upstream_message_too_large",
                    extra={"event": "upstream_message_too_large"},
                )
                return
            if not raw:
                logger.info(
                    "upstream_closed",
                    extra={"event": "upstream_closed", "server_name": self._config.server_name},
                )
                return
            if len(raw) > _MAX_MESSAGE_BYTES:
                logger.error(
                    "upstream_message_too_large",
                    extra={"event": "upstream_message_too_large"},
                )
                continue
            try:
                message = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                logger.error(
                    "upstream_invalid_json",
                    extra={"event": "upstream_invalid_json"},
                )
                continue
            if not isinstance(message, dict):
                logger.error(
                    "upstream_invalid_message",
                    extra={"event": "upstream_invalid_message"},
                )
                continue
            await self._handle_upstream_message(message)

    async def _handle_upstream_message(self, message: dict[str, Any]) -> None:
        if "method" in message:
            if "id" not in message:
                await self._write_host(message)
                return
            original_id = message["id"]
            wire_id = _wire_id()
            forwarded = dict(message)
            forwarded["id"] = wire_id
            self._upstream_to_host[_request_id_key(wire_id)] = original_id
            await self._write_host(forwarded)
            return
        response_id = message.get("id")
        entry = self._host_to_upstream.pop(_request_id_key(response_id), None)
        if entry is None:
            await self._write_host(message)
            return
        self._host_original_to_wire.pop(entry["original_key"], None)
        forwarded = dict(message)
        forwarded["id"] = entry["original_id"]
        await self._write_host(forwarded)

    async def _write_upstream(self, message: dict[str, Any]) -> None:
        process = self._upstream
        if process is None or process.stdin is None or process.stdin.is_closing():
            raise BrokenPipeError("Upstream MCP server is not available")
        encoded = json.dumps(message, ensure_ascii=False, separators=(",", ":"))
        async with self._upstream_write_lock:
            process.stdin.write((encoded + "\n").encode("utf-8"))
            await process.stdin.drain()

    async def _write_host(self, message: dict[str, Any]) -> None:
        encoded = json.dumps(message, ensure_ascii=False, separators=(",", ":"))
        async with self._host_write_lock:
            sys.stdout.write(encoded + "\n")
            sys.stdout.flush()

    async def _send_jsonrpc_error(
        self, request_id: Any, code: int, message: str
    ) -> None:
        await self._write_host(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": code, "message": message},
            }
        )

    async def _shutdown(self) -> None:
        if self._closing:
            return
        self._closing = True
        self._approval_queue.cancel_all()
        for task in tuple(self._call_tasks):
            task.cancel()
        if self._call_tasks:
            await asyncio.gather(*self._call_tasks, return_exceptions=True)
        await self._control.close()
        process = self._upstream
        if process is not None:
            if process.stdin is not None and not process.stdin.is_closing():
                process.stdin.close()
            if process.returncode is None:
                try:
                    await asyncio.wait_for(process.wait(), timeout=5)
                except TimeoutError:
                    process.terminate()
                    try:
                        await asyncio.wait_for(process.wait(), timeout=2)
                    except TimeoutError:
                        process.kill()
                        await process.wait()
        logger.info("proxy_shutdown", extra={"event": "proxy_shutdown"})


def _wire_id() -> str:
    return f"mcp-security-guard:{uuid.uuid4().hex}"


def _valid_request_id(request_id: Any) -> bool:
    if isinstance(request_id, float):
        return math.isfinite(request_id)
    return isinstance(request_id, (str, int)) and not isinstance(request_id, bool)


def _request_id_key(request_id: Any) -> str:
    return json.dumps(request_id, ensure_ascii=True, separators=(",", ":"))
