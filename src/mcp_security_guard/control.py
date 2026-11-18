import asyncio
import hmac
import json
import logging
import re
from typing import Any

from .approval import ApprovalQueue


logger = logging.getLogger(__name__)
_DECISION_PATH = re.compile(r"^/requests/([a-f0-9]{32})/decision$")
_MAX_BODY_BYTES = 16_384


class ApprovalControlServer:
    def __init__(
        self,
        queue: ApprovalQueue,
        *,
        host: str,
        port: int,
        token: str,
    ) -> None:
        self._queue = queue
        self._host = host
        self._port = port
        self._token = token.encode("utf-8")
        self._server: asyncio.AbstractServer | None = None

    @property
    def port(self) -> int:
        if self._server is None or not self._server.sockets:
            raise RuntimeError("Approval control server is not running")
        return int(self._server.sockets[0].getsockname()[1])

    async def start(self) -> int:
        self._server = await asyncio.start_server(
            self._handle_connection, self._host, self._port
        )
        return self.port

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=5)
            parts = request_line.decode("ascii").strip().split(" ")
            if len(parts) != 3 or parts[2] not in ("HTTP/1.0", "HTTP/1.1"):
                await self._respond(writer, 400, {"error": "Invalid HTTP request"})
                return

            headers: dict[str, str] = {}
            total_header_bytes = len(request_line)
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=5)
                total_header_bytes += len(line)
                if total_header_bytes > _MAX_BODY_BYTES or not line:
                    await self._respond(writer, 400, {"error": "Invalid HTTP headers"})
                    return
                if line in (b"\r\n", b"\n"):
                    break
                decoded = line.decode("ascii").strip()
                name, separator, value = decoded.partition(":")
                if not separator:
                    await self._respond(writer, 400, {"error": "Invalid HTTP header"})
                    return
                headers[name.lower().strip()] = value.strip()

            authorization = headers.get("authorization", "")
            supplied_token = authorization.removeprefix("Bearer ").encode("utf-8")
            if not hmac.compare_digest(self._token, supplied_token):
                await self._respond(writer, 401, {"error": "Unauthorized"})
                return

            method, path = parts[0], parts[1]
            if method == "GET" and path == "/pending":
                await self._respond(writer, 200, {"pending": self._queue.pending()})
                return
            if method == "GET" and path == "/next":
                request = await self._queue.next_request(timeout_seconds=20)
                await self._respond(
                    writer,
                    200,
                    {"request": request.as_dict() if request is not None else None},
                )
                return
            if method == "GET" and path == "/audit":
                await self._respond(writer, 200, {"recent": self._queue.history()})
                return
            match = _DECISION_PATH.fullmatch(path)
            if method == "POST" and match:
                body = await self._read_body(reader, headers)
                try:
                    payload = json.loads(body)
                except json.JSONDecodeError:
                    await self._respond(writer, 400, {"error": "Invalid JSON body"})
                    return
                decision = payload.get("decision") if isinstance(payload, dict) else None
                if decision not in ("approve", "deny"):
                    await self._respond(
                        writer, 400, {"error": "decision must be 'approve' or 'deny'"}
                    )
                    return
                found = self._queue.decide(match.group(1), decision)
                status = 200 if found else 404
                await self._respond(
                    writer,
                    status,
                    {"status": decision if found else "not_pending"},
                )
                return
            await self._respond(writer, 404, {"error": "Not found"})
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, UnicodeDecodeError, ValueError) as exc:
            logger.warning(
                "invalid_approval_control_request",
                extra={"event": "invalid_approval_control_request", "error": str(exc)},
            )
            await self._respond(writer, 400, {"error": "Invalid request"})
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                logger.debug("approval_control_connection_close_failed")

    async def _read_body(
        self, reader: asyncio.StreamReader, headers: dict[str, str]
    ) -> bytes:
        if "transfer-encoding" in headers:
            raise ValueError("Transfer-Encoding is not supported")
        try:
            content_length = int(headers.get("content-length", "0"))
        except ValueError as exc:
            raise ValueError("Invalid Content-Length") from exc
        if content_length < 0 or content_length > _MAX_BODY_BYTES:
            raise ValueError("Request body is too large")
        return await asyncio.wait_for(reader.readexactly(content_length), timeout=5)

    async def _respond(
        self, writer: asyncio.StreamWriter, status: int, payload: dict[str, Any]
    ) -> None:
        reasons = {200: "OK", 400: "Bad Request", 401: "Unauthorized", 404: "Not Found"}
        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        response = (
            f"HTTP/1.1 {status} {reasons.get(status, 'Error')}\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii") + body
        writer.write(response)
        await writer.drain()
