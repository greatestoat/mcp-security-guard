import json
import os
import sys


def respond(message: dict) -> None:
    sys.stdout.write(json.dumps(message, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def main() -> None:
    for line in sys.stdin:
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        method = message.get("method")
        if method == "initialize":
            respond(
                {
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "minimal-test-mcp-server", "version": "1.0"},
                    },
                }
            )
        elif method == "tools/list":
            respond(
                {
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": {
                        "tools": [
                            {
                                "name": "echo",
                                "description": "Return the submitted text",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {"text": {"type": "string"}},
                                    "required": ["text"],
                                },
                            }
                        ]
                    },
                }
            )
        elif method == "tools/call":
            log_path = os.environ["FAKE_MCP_CALL_LOG"]
            with open(log_path, "a", encoding="utf-8") as audit_file:
                audit_file.write(json.dumps(message["params"]) + "\n")
            respond(
                {
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": {
                        "content": [
                            {"type": "text", "text": message["params"]["arguments"]["text"]}
                        ]
                    },
                }
            )


if __name__ == "__main__":
    main()
