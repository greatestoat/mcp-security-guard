import argparse
import asyncio
import ipaddress
import json
import math
import os
import sys
import urllib.error
import urllib.request

from .logging_config import configure_logging
from .proxy import MCPProxy, ProxyConfig


def _add_control_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--control-host", default="127.0.0.1")
    parser.add_argument(
        "--control-port",
        type=int,
        default=int(os.environ.get("MCP_GUARD_CONTROL_PORT", "8765")),
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mcp-security-guard")
    subparsers = parser.add_subparsers(dest="command", required=True)

    proxy = subparsers.add_parser("proxy", help="Run the approval-gated stdio proxy")
    proxy.add_argument("--server-name", default="upstream-mcp-server")
    proxy.add_argument("--approval-timeout", type=float, default=120.0)
    proxy.add_argument(
        "--fail-closed",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Exit if the approval control server cannot start (default: true)",
    )
    _add_control_options(proxy)
    proxy.add_argument(
        "upstream_command",
        nargs=argparse.REMAINDER,
        help="Upstream MCP server command, preceded by --",
    )

    pending = subparsers.add_parser("pending", help="List pending tool approvals")
    _add_control_options(pending)

    subparsers_next = subparsers.add_parser(
        "next", help="Wait for the next tool approval request"
    )
    _add_control_options(subparsers_next)

    approve = subparsers.add_parser("approve", help="Approve or deny a tool call")
    approve.add_argument("--request-id", required=True, help="Approval ID from pending")
    approve.add_argument("--decision", required=True, choices=("approve", "deny"))
    _add_control_options(approve)
    return parser


def _approval_token() -> str:
    token = os.environ.get("MCP_GUARD_APPROVAL_TOKEN")
    if not token:
        raise SystemExit("Set MCP_GUARD_APPROVAL_TOKEN before running MCP Security Guard.")
    if len(token) < 16:
        raise SystemExit("MCP_GUARD_APPROVAL_TOKEN must contain at least 16 characters.")
    return token


def _validate_control_endpoint(host: str, port: int) -> None:
    try:
        if not ipaddress.ip_address(host).is_loopback:
            raise SystemExit("Approval control host must be a loopback IP address.")
    except ValueError as exc:
        raise SystemExit("Approval control host must be a loopback IP address.") from exc
    if not 0 <= port <= 65535:
        raise SystemExit("Approval control port must be between 0 and 65535.")


def _proxy_config(args: argparse.Namespace) -> ProxyConfig:
    _validate_control_endpoint(args.control_host, args.control_port)
    upstream_command = list(args.upstream_command)
    if upstream_command and upstream_command[0] == "--":
        upstream_command = upstream_command[1:]
    if not upstream_command:
        raise SystemExit("Provide an upstream command after --.")
    if not math.isfinite(args.approval_timeout) or args.approval_timeout <= 0:
        raise SystemExit("--approval-timeout must be greater than zero.")
    return ProxyConfig(
        server_name=args.server_name,
        approval_timeout=args.approval_timeout,
        control_host=args.control_host,
        control_port=args.control_port,
        approval_token=_approval_token(),
        fail_closed=args.fail_closed,
        upstream_command=tuple(upstream_command),
    )


def _control_request(
    host: str,
    port: int,
    token: str,
    method: str,
    path: str,
    body: dict | None = None,
    timeout: float = 5,
) -> dict:
    encoded_body = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(
        f"http://{host}:{port}{path}",
        data=encoded_body,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"Approval control request failed ({exc.code}): {detail}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"Could not reach approval control server: {exc.reason}") from exc


def main() -> None:
    args = _build_parser().parse_args()
    _validate_control_endpoint(args.control_host, args.control_port)
    token = _approval_token()
    if args.command == "proxy":
        config = _proxy_config(args)
        configure_logging()
        try:
            asyncio.run(MCPProxy(config).run())
        except KeyboardInterrupt:
            return
        except (OSError, RuntimeError) as exc:
            print(f"MCP Security Guard: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc
        return
    if args.command == "pending":
        result = _control_request(
            args.control_host, args.control_port, token, "GET", "/pending"
        )
        print(json.dumps(result, indent=2))
        return
    if args.command == "next":
        result = _control_request(
            args.control_host,
            args.control_port,
            token,
            "GET",
            "/next",
            timeout=25,
        )
        print(json.dumps(result, indent=2))
        return
    result = _control_request(
        args.control_host,
        args.control_port,
        token,
        "POST",
        f"/requests/{args.request_id}/decision",
        {"decision": args.decision},
    )
    print(json.dumps(result, indent=2))
