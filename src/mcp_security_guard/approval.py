import asyncio
import logging
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


logger = logging.getLogger(__name__)
Decision = str
MAX_PENDING_APPROVALS = 256


class ApprovalQueueFull(RuntimeError):
    pass


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(slots=True)
class ApprovalRequest:
    approval_id: str
    origin_application: str
    server_name: str
    tool_name: str
    arguments: dict[str, Any]
    request_id: str | int | float | None
    timestamp: str
    future: asyncio.Future[Decision] = field(repr=False)
    status: str = "pending"

    def as_dict(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "origin_application": self.origin_application,
            "server_name": self.server_name,
            "tool_name": self.tool_name,
            "arguments": self.arguments,
            "request_id": self.request_id,
            "timestamp": self.timestamp,
            "status": self.status,
        }


class ApprovalQueue:
    def __init__(self) -> None:
        self._pending: dict[str, ApprovalRequest] = {}
        self._queue: deque[ApprovalRequest] = deque()
        self._available = asyncio.Event()
        self._history: deque[dict[str, Any]] = deque(maxlen=500)

    def enqueue(
        self,
        *,
        origin_application: str,
        server_name: str,
        tool_name: str,
        arguments: dict[str, Any],
        request_id: str | int | float | None,
    ) -> ApprovalRequest:
        if len(self._pending) >= MAX_PENDING_APPROVALS:
            approval_id = uuid.uuid4().hex
            timestamp = _utc_timestamp()
            self._history.append(
                {
                    "approval_id": approval_id,
                    "origin_application": origin_application,
                    "server_name": server_name,
                    "tool_name": tool_name,
                    "arguments": arguments,
                    "request_id": request_id,
                    "timestamp": timestamp,
                    "status": "queue_full",
                }
            )
            logger.warning(
                "tool_call_rejected_queue_full",
                extra={
                    "event": "tool_call_rejected_queue_full",
                    "origin_application": origin_application,
                    "server_name": server_name,
                    "tool_name": tool_name,
                    "request_id": request_id,
                    "approval_id": approval_id,
                },
            )
            raise ApprovalQueueFull("Approval queue is full")
        loop = asyncio.get_running_loop()
        request = ApprovalRequest(
            approval_id=uuid.uuid4().hex,
            origin_application=origin_application,
            server_name=server_name,
            tool_name=tool_name,
            arguments=arguments,
            request_id=request_id,
            timestamp=_utc_timestamp(),
            future=loop.create_future(),
        )
        self._pending[request.approval_id] = request
        self._queue.append(request)
        self._available.set()
        logger.info(
            "tool_call_awaiting_approval",
            extra={
                "event": "tool_call_awaiting_approval",
                "origin_application": origin_application,
                "server_name": server_name,
                "tool_name": tool_name,
                "request_id": request_id,
                "approval_id": request.approval_id,
            },
        )
        return request

    async def next_request(self, timeout_seconds: float) -> ApprovalRequest | None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout_seconds
        while True:
            while self._queue:
                request = self._queue.popleft()
                if (
                    self._pending.get(request.approval_id) is request
                    and not request.future.done()
                ):
                    return request
            self._available.clear()
            remaining = deadline - loop.time()
            if remaining <= 0:
                return None
            try:
                await asyncio.wait_for(self._available.wait(), remaining)
            except TimeoutError:
                return None

    def pending(self) -> list[dict[str, Any]]:
        return [request.as_dict() for request in self._pending.values()]

    def history(self) -> list[dict[str, Any]]:
        return list(self._history)

    def decide(self, approval_id: str, decision: Decision) -> bool:
        request = self._pending.get(approval_id)
        if request is None or request.future.done():
            return False
        request.future.set_result(decision)
        return True

    async def wait_for_decision(
        self, request: ApprovalRequest, timeout_seconds: float
    ) -> Decision:
        try:
            decision = await asyncio.wait_for(request.future, timeout_seconds)
        except TimeoutError:
            decision = "timeout"
        except asyncio.CancelledError:
            self._finish(request, "cancelled")
            raise
        self._finish(request, decision)
        return decision

    def cancel_all(self) -> None:
        for request in tuple(self._pending.values()):
            self.decide(request.approval_id, "cancelled")

    def _finish(self, request: ApprovalRequest, decision: Decision) -> None:
        self._pending.pop(request.approval_id, None)
        if request in self._queue:
            self._queue.remove(request)
        request.status = decision
        self._history.append(request.as_dict())
