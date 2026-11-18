# MCP Security Guard

MCP Security Guard is a Python 3.11+ stdio proxy for MCP clients such as Claude
Desktop. It starts an upstream stdio MCP server, passes initialization,
capability negotiation, notifications, discovery, and responses through, and
holds every `tools/call` until an operator explicitly approves or denies it.
Only explicitly approved calls are forwarded.

The proxy preserves JSON-RPC correlation by assigning unique internal IDs to
requests in both directions and restoring the original IDs in responses. The
approval channel is a bearer-token-protected HTTP API bound to a loopback IP.
It is separate from MCP stdin/stdout; stdout is reserved for MCP JSON-RPC.

## What this application does

MCP Security Guard sits between an MCP client and an upstream MCP server. It
forwards normal MCP protocol traffic while pausing every tool invocation for an
explicit human decision. An operator can review the request and allow or block
it through the desktop dashboard or the authenticated local control commands.
The proxy fails closed when approval is unavailable or times out, and keeps
MCP protocol traffic separate from the approval interface. The included
read-only filesystem server provides a safe way to try the workflow.

The project includes:

- A Python stdio proxy with JSON-RPC request ID mapping and tool-call approval.
- A loopback HTTP control API protected by a bearer token.
- A PySide6 desktop dashboard with approval prompts, history, settings, and a
  system tray icon.
- Command-line commands for inspecting and deciding pending requests.
- A read-only sample filesystem MCP server and integration tests.
## Project files

- `.gitignore` â€” excludes the local virtual environment, bytecode, and packaging
  artifacts.
- `pyproject.toml` â€” package metadata, Python version requirement, dependency,
  editable-install configuration, and console entry point.
- `requirements.txt` â€” official MCP Python SDK and PySide6 Essentials (Qt
  Widgets/GUI without unused Qt WebEngine and optional modules).
- `src/mcp_security_guard/__init__.py` â€” package marker and version.
- `src/mcp_security_guard/__main__.py` â€” enables `python -m mcp_security_guard`.
- `src/mcp_security_guard/cli.py` â€” proxy, pending-request, and decision commands;
  includes queue consumption with `next`, validates the local control endpoint,
  and requires the shared approval token.
- `src/mcp_security_guard/gui.py` â€” PySide6 dashboard and loopback API client,
  topmost per-request approval windows, history, settings, and system tray.
- `src/mcp_security_guard/proxy.py` â€” bidirectional stdio JSON-RPC proxy,
  request-ID remapping, tool-call interception, timeout/denial handling,
  cancellation, and upstream lifecycle management.
- `src/mcp_security_guard/approval.py` â€” unique approval records, bounded
  asynchronous queue, independent per-request futures, and recent history.
- `src/mcp_security_guard/control.py` â€” authenticated loopback HTTP endpoints
  for listing pending calls, viewing recent audit entries, and deciding calls.
- `src/mcp_security_guard/logging_config.py` â€” JSON structured logs to stderr.
- `src/mcp_security_guard/sample_server.py` â€” read-only example filesystem MCP
  server implemented with the official MCP Python SDK and constrained to a
  configured root directory.
- `tests/fake_mcp_server.py` â€” minimal JSON-RPC MCP test server that implements
  initialize, tool discovery, and one observable tool.
- `tests/test_proxy_integration.py` â€” subprocess-level tests proving protocol
  forwarding, request isolation, explicit approval/denial, and timeout denial.
- `tests/test_sample_server_integration.py` â€” end-to-end test using the official
  MCP SDK sample filesystem server through the proxy.
- `tests/test_gui_e2e.py` â€” offscreen Qt integration test that clicks the real
  Allow and Block buttons against a running proxy and verifies server execution.
- `tests/__init__.py` â€” makes the test server importable by the integration test.

The approval control API retains the most recent 500 decisions in memory.
Arguments are available to the authenticated approval client while a request is
pending and in that bounded recent history. Arguments are intentionally omitted
from routine logs to reduce accidental sensitive-data exposure.

## Install and test (Windows PowerShell)

From the project directory:

```powershell
Set-Location C:\Users\lenovo\Desktop\mcp-security-guard
$python = 'C:\Users\lenovo\AppData\Roaming\uv\python\cpython-3.14.3-windows-x86_64-none\python.exe'
& $python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e .
python -m unittest discover -s tests -v
```

The configured interpreter above is Python 3.14.3. If using another Python
installation, replace `$python` with its executable path; Python 3.11 or newer
is required.

If PowerShell blocks activation, use this session-only policy and activate
again:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

## Run the sample filesystem server through the proxy

In the first PowerShell window, prepare a sample root and start the proxy:

```powershell
Set-Location C:\Users\lenovo\Desktop\mcp-security-guard
.\.venv\Scripts\Activate.ps1
New-Item -ItemType Directory -Force "$HOME\mcp-guard-files" | Out-Null
Set-Content -Path "$HOME\mcp-guard-files\hello.txt" -Value "Hello from the guarded filesystem"
$env:MCP_GUARD_APPROVAL_TOKEN = [guid]::NewGuid().ToString("N")
Write-Host "Copy this token to the approval window: $env:MCP_GUARD_APPROVAL_TOKEN"
python -m mcp_security_guard proxy --server-name sample-files --control-host 127.0.0.1 --control-port 8765 --approval-timeout 120 -- python -m mcp_security_guard.sample_server --root "$HOME\mcp-guard-files"
```

The proxy remains attached to stdin/stdout for its MCP client. It does not open a
GUI. Keep the token secret and use the exact same value in the second window.

In a second PowerShell window, use the same token to list and decide requests:

```powershell
Set-Location C:\Users\lenovo\Desktop\mcp-security-guard
.\.venv\Scripts\Activate.ps1
$env:MCP_GUARD_APPROVAL_TOKEN = "PASTE-THE-TOKEN-FROM-THE-FIRST-WINDOW"
python -m mcp_security_guard pending --control-host 127.0.0.1 --control-port 8765
python -m mcp_security_guard next --control-host 127.0.0.1 --control-port 8765
python -m mcp_security_guard approve --request-id APPROVAL_ID --decision approve --control-host 127.0.0.1 --control-port 8765
```

Use `--decision deny` to block the call. A call that is denied, cancelled before
forwarding, times out, hits the 256-request queue limit, or cannot reach the
approval service is never sent to the upstream MCP server. The default is
fail-closed if the control listener cannot start; `--no-fail-closed` permits
proxy startup in degraded mode, but tool calls still receive an error rather
than being forwarded without approval.

## Run the desktop application

Open the desktop dashboard in its own PowerShell window:

```powershell
Set-Location C:\Users\lenovo\Desktop\mcp-security-guard
.\.venv\Scripts\Activate.ps1
$env:MCP_GUARD_APPROVAL_TOKEN = "THE-SAME-LONG-RANDOM-SECRET-AS-THE-PROXY"
python -m mcp_security_guard.gui
```

In **Settings**, use the same host (`127.0.0.1`), port, approval timeout, and
token configured for the proxy. The token is held only in the current app
session; host, port, and display timeout are saved. The dashboard attaches to
the proxy launched by Claude Desktop; it does not take over Claude's stdio
transport. You can minimize the window to the system tray and restore it from
the tray icon. Closing the window hides it while the tray is available; use the
tray's **Exit** command to stop monitoring. Outstanding calls remain paused and
will fail closed at the proxy timeout if the UI exits.

To configure Claude Desktop, add an MCP server entry like this to its config,
using the absolute paths for your Python installation and the actual upstream
server. Use the same token in both Claude Desktop and the GUI:

```json
{
  "mcpServers": {
    "guarded-filesystem": {
      "command": "C:\\Users\\lenovo\\Desktop\\mcp-security-guard\\.venv\\Scripts\\python.exe",
      "args": [
        "-m", "mcp_security_guard", "proxy",
        "--server-name", "guarded-filesystem",
        "--control-host", "127.0.0.1",
        "--control-port", "8765",
        "--approval-timeout", "120",
        "--",
        "C:\\Users\\lenovo\\Desktop\\mcp-security-guard\\.venv\\Scripts\\python.exe",
        "-m", "mcp_security_guard.sample_server",
        "--root", "C:\\Users\\lenovo\\mcp-guard-files"
      ],
      "env": {
        "MCP_GUARD_APPROVAL_TOKEN": "SET-A-LONG-RANDOM-SECRET-HERE"
      }
    }
  }
}
```

For visual-only testing, run `python -m mcp_security_guard.gui --demo`. The
dashboard is explicitly marked as demo, makes no proxy connection, and creates
no tool calls or audit entries. Normal launch never inserts demo requests.

The approval API listens only on a loopback address and requires the bearer
token; do not expose it on a non-loopback interface.

