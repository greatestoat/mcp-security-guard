import argparse
from pathlib import Path

from mcp.server.fastmcp import FastMCP


def _resolve_within_root(root: Path, relative_path: str) -> Path:
    candidate = (root / relative_path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError("Path must stay within the configured sample root") from exc
    return candidate


def build_server(root_path: Path) -> FastMCP:
    root = root_path.resolve()
    if not root.is_dir():
        raise ValueError(f"Sample root is not a directory: {root}")
    server = FastMCP("MCP Security Guard sample filesystem")

    @server.tool()
    def list_files(path: str = ".") -> list[str]:
        """List names in a directory under the configured sample root."""
        target = _resolve_within_root(root, path)
        if not target.is_dir():
            raise ValueError("Requested path is not a directory")
        return sorted(item.name for item in target.iterdir())

    @server.tool()
    def read_file(path: str) -> str:
        """Read a UTF-8 text file under the configured sample root."""
        target = _resolve_within_root(root, path)
        if not target.is_file():
            raise ValueError("Requested path is not a file")
        if target.stat().st_size > 1_000_000:
            raise ValueError("Sample files are limited to 1 MB")
        return target.read_text(encoding="utf-8")

    return server


def main() -> None:
    parser = argparse.ArgumentParser(description="Read-only sample filesystem MCP server")
    parser.add_argument("--root", required=True, type=Path)
    args = parser.parse_args()
    build_server(args.root).run(transport="stdio")


if __name__ == "__main__":
    main()
