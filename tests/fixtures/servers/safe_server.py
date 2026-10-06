"""A harmless MCP server. The scanner should find nothing serious here.

Run over stdio:            python safe_server.py
Run over streamable HTTP:  python safe_server.py --http 8765
"""

import sys

from mcp.server import MCPServer

mcp = MCPServer("safe-notes", instructions="A small notes helper. It keeps notes in memory only.")

NOTES: dict[str, str] = {}


@mcp.tool()
def add_numbers(a: int, b: int) -> int:
    """Add two whole numbers and return the sum."""
    return a + b


@mcp.tool()
def save_note(title: str, text: str) -> str:
    """Save a short note in memory under a title."""
    NOTES[title] = text
    return f"Saved note '{title}'."


@mcp.tool()
def list_notes() -> list[str]:
    """List the titles of all saved notes."""
    return sorted(NOTES)


@mcp.prompt()
def summarize_notes(style: str = "short") -> str:
    """Ask for a summary of the saved notes."""
    return f"Please write a {style} summary of these notes: {', '.join(NOTES) or 'none yet'}"


@mcp.resource("notes://readme")
def readme() -> str:
    """How to use the notes server."""
    return "Use save_note to store notes and list_notes to see them."


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--http":
        mcp.run(transport="streamable-http", port=int(sys.argv[2]))
    else:
        mcp.run()
