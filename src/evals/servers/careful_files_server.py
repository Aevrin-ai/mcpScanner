"""EVAL FIXTURE (benign). A careful file server.

It reads and lists files, but only inside one allowed folder, and it checks every
path. The descriptions use negations ("does not", "never"). The scanner should
report the file reading capability at low severity and nothing serious.
"""

import os
from pathlib import Path

from mcp.server import MCPServer

ROOT = Path(os.environ.get("NOTES_DIR", Path.cwd())).resolve()
mcp = MCPServer("careful-files", instructions="Reads text files inside one folder. It never writes or deletes files.")


def _safe(path: str) -> Path:
    target = (ROOT / path).resolve()
    if not target.is_relative_to(ROOT):
        raise ValueError("path is outside the allowed folder")
    return target


@mcp.tool()
def read_file(path: str) -> str:
    """Read a text file inside the notes folder. This tool does not run shell commands and never sends data anywhere."""
    return _safe(path).read_text(encoding="utf-8")[:10000]


@mcp.tool()
def list_files(subfolder: str = ".") -> list[str]:
    """List files inside the notes folder. It does not follow links outside the folder."""
    return sorted(p.name for p in _safe(subfolder).iterdir())


if __name__ == "__main__":
    mcp.run()
